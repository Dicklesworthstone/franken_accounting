//! Scratch-book replay (plan §15.2, Appendix H R-BR; bead fa-xo0 part 2).
//!
//! Until the substrate ships branches, a draft materialized for review and
//! a scenario are a deterministic replay of trunk into a fresh `open_memory`
//! database. The replay reads the source's committed history from the
//! substrate's delta stream and re-commits it, **one source commit per
//! scratch transaction**, row for row:
//!
//! - identities are preserved: vids and eids are written as the source wrote
//!   them, payload bytes are copied verbatim, so every entry digest, every
//!   proposal digest and every approval that binds one is the same object in
//!   the scratch book (§4.2, §4.9);
//! - property moves replay as compare-and-sets from the source's `before`,
//!   so any divergence aborts instead of being papered over;
//! - **accounting objects only**: rows on `Register` (materialized register
//!   checkpoints), `AccumulatorState` (the notary's checkpoints) and
//!   `RegisterState` (the native register maintainer's cells and cursor)
//!   vertices, and every row on them or their edges — property moves and
//!   removals, label flips, deletes — are maintenance and are dropped, as
//!   are moves of a maintenance property wherever it sits (the notary's
//!   checkpoint head on the book root); a source commit that is only
//!   maintenance yields no scratch commit;
//! - on an accounting object, a removal or a delete (the journal is
//!   append-only), and anywhere a row family fa never writes (valid time,
//!   counters, escrow, sketches, schema, constraints), refuses FA-REF-134,
//!   never a skip.
//!
//! The scratch book's commit sequences are its own: recorded time is never
//! forged. The [`SeqMap`] it returns binds each replayed source commit (its
//! sequence and marker) to the scratch commit that reproduces it, so known-at
//! selectors translate deterministically; binding it into a scenario
//! certificate is fa-we7's (ruling 3236 R3). A scratch book never claims
//! original membership: a promotion that lands on trunk is the only one.

use std::collections::BTreeSet;

use fa_model::Id128;
use fa_model::symbols::{label, property};
pub use fa_palimpsest::{
    SCOPE_ACCOUNTING_OBJECTS_ONLY, SEQ_MAP_DOMAIN, SEQ_MAP_VERSION, SeqPair, encode_seq_map,
    seq_map_digest, seq_pairs_are_monotone, translate_seq,
};
use fgdb::{Database, WriteBatch, WriteMismatchPolicy, WriteTxnError};
use fgdb_delta_types::{
    DeltaRow, ElementId, LabelId, LogicalDeltaBatch, PropertyKeyId, RelationId,
};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, EId, VId};

use crate::refusal::{KernelError, Outcome, Refusal, code, exit};

/// Properties that are maintenance wherever they sit: the notary's
/// checkpoint head on the book root (fa-notary `checkpoint` moves it in the
/// commit that writes an `AccumulatorState`). Their moves are dropped like
/// every row on a maintenance vertex, so a checkpoint commit replays to
/// nothing and a scratch book never points at a checkpoint it lacks.
const MAINTENANCE_PROPERTIES: [PropertyKeyId; 1] = [property::ACCUMULATOR_HEAD];

/// Labels excluded from accounting-object replay: maintenance, checkpoints,
/// and certificates whose native snapshot identities bind the source database.
/// A `TransparencyCheckpoint` signs the source's prefix by its sequence
/// numbers, which a scratch book does not share; it is written in the same
/// commit as the `AccumulatorState` it signs.
/// A scratch report must issue its own certificate; the source's
/// retained artifact remains unchanged in its original book.
const MAINTENANCE: [LabelId; 5] = [
    label::REGISTER,
    label::ACCUMULATOR_STATE,
    label::TRANSPARENCY_CHECKPOINT,
    label::REGISTER_STATE,
    label::CERTIFICATE,
];

/// The map from source `CommitSeq`s to scratch `CommitSeq`s (plan §15.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeqMap {
    pub source_book: Id128,
    /// The source prefix replayed: every accounting commit at or before it.
    pub source_prefix: CommitSeq,
    /// Strictly increasing on both sides.
    pub pairs: Vec<SeqPair>,
}

impl SeqMap {
    /// `u16 version ‖ book[16] ‖ u64 prefix ‖ u8 scope ‖ list(u64 source ‖
    /// marker[32] ‖ u64 scratch)`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        encode_seq_map(self.source_book, self.source_prefix, &self.pairs)
            .map_err(|e| KernelError::Model(e.into()))
    }

    pub fn digest(&self) -> Result<[u8; 32], KernelError> {
        seq_map_digest(self.source_book, self.source_prefix, &self.pairs)
            .map_err(|e| KernelError::Model(e.into()))
    }

    /// Both sides strictly increasing.
    #[must_use]
    pub fn is_monotone(&self) -> bool {
        seq_pairs_are_monotone(&self.pairs)
    }

    /// The scratch coordinate that knows exactly the accounting objects the
    /// source knew at `source_known_at`: the last replayed commit at or
    /// before it. `None` before the first replayed commit (nothing known)
    /// and past `source_prefix`, whose history the scratch book does not
    /// hold: a floor is only lawful inside `[0, source_prefix]`.
    #[must_use]
    pub fn translate(&self, source_known_at: CommitSeq) -> Option<CommitSeq> {
        translate_seq(self.source_prefix, &self.pairs, source_known_at)
    }
}

/// The maintenance objects seen so far in a replay, so their later property
/// moves and incident edges are dropped too.
#[derive(Clone, Debug, Default)]
pub struct Maintenance {
    vertices: BTreeSet<VId>,
    edges: BTreeSet<EId>,
}

impl Maintenance {
    fn holds(&self, elem: &ElementId) -> bool {
        match elem {
            ElementId::Vertex(v) => self.vertices.contains(v),
            ElementId::Edge(e) => self.edges.contains(e),
        }
    }

    // Coordinates are canonical, not causal. An incident edge or its
    // property can precede the coordinate that identifies its endpoint as
    // maintenance. Classify the complete commit before translating any row.
    fn observe_batch(&mut self, batch: &LogicalDeltaBatch) {
        for entry in batch.coordinate_entries() {
            for row in &entry.rows {
                match row {
                    DeltaRow::CreateVertex { vid, labels, .. }
                        if labels.iter().any(|label| MAINTENANCE.contains(label)) =>
                    {
                        self.vertices.insert(*vid);
                    }
                    DeltaRow::LabelMembership { vid, label, .. } if MAINTENANCE.contains(label) => {
                        self.vertices.insert(*vid);
                    }
                    _ => {}
                }
            }
        }
        for entry in batch.coordinate_entries() {
            for row in &entry.rows {
                match row {
                    DeltaRow::CreateEdge { eid, src, dst, .. }
                        if self.vertices.contains(src) || self.vertices.contains(dst) =>
                    {
                        self.edges.insert(*eid);
                    }
                    DeltaRow::DeleteVertex {
                        vid,
                        sorted_retired_incident_edges,
                        ..
                    } if self.vertices.contains(vid) => {
                        self.edges
                            .extend(sorted_retired_incident_edges.iter().copied());
                    }
                    _ => {}
                }
            }
        }
    }
}

fn unsupported(seq: CommitSeq, what: &str) -> Refusal {
    Refusal::new(
        code::REPLAY_UNSUPPORTED,
        exit::FOUNDATION,
        format!(
            "source commit {} carries {what}, which a scratch replay does not reproduce",
            seq.0
        ),
        "plan §15.2 (a scratch book replays accounting objects only), Appendix H R-BR",
        "replay a prefix before that commit, or wait for substrate branches (R-BR) for this history",
    )
}

/// One replayed create, with its coordinate's relation retained separately.
enum Create {
    Vertex(VId, Vec<LabelId>, Vec<(PropertyKeyId, CanonicalScalar)>),
    Edge(EId, VId, VId, Vec<(PropertyKeyId, CanonicalScalar)>),
}

/// The replayable accounting part of one source commit: its rows minus
/// maintenance (empty when the commit was only maintenance), excluding
/// maintenance regardless of coordinate order. The creates come first, in
/// the source's birth order: vertices and edges share a counter, so
/// endpoints precede their edges. The substrate allocates birth ordinals as
/// statements stage, while a delta batch lists rows per coordinate in
/// canonical order, so replaying coordinate by coordinate would allocate the
/// same elements in a different order (the book root, born first, would be
/// born after the genesis unit table). Canonical delta coordinate order is
/// not allocation order. Every other row follows, per relation, in the
/// batch's original order, with all compare-and-set checks intact; each
/// names an element that exists by then.
///
/// Skipped maintenance can leave gaps in source ordinals: the scratch
/// database allocates its own ordinals and sequences, never forged source
/// metadata. The relative creation order of retained objects is preserved.
pub fn replayable(
    batch: &LogicalDeltaBatch,
    maintenance: &mut Maintenance,
) -> Result<Vec<WriteBatch>, Refusal> {
    let seq = batch.commit_seq();
    maintenance.observe_batch(batch);
    let mut creates: Vec<(u64, RelationId, Create)> = Vec::new();
    let mut out = Vec::new();
    for entry in batch.coordinate_entries() {
        let mut w = WriteBatch::new(entry.relation);
        for row in &entry.rows {
            match row {
                DeltaRow::CreateVertex {
                    vid,
                    birth_ordinal,
                    labels,
                    props,
                    valid_time,
                } => {
                    if valid_time.is_some() {
                        return Err(unsupported(seq, "a valid-time vertex"));
                    }
                    if maintenance.vertices.contains(vid) {
                        continue;
                    }
                    creates.push((
                        *birth_ordinal,
                        entry.relation,
                        Create::Vertex(*vid, labels.clone(), props.clone()),
                    ));
                }
                DeltaRow::CreateEdge {
                    eid,
                    birth_ordinal,
                    src,
                    dst,
                    canonical_key,
                    props,
                    valid_time,
                    ..
                } => {
                    if valid_time.is_some() || canonical_key.is_some() {
                        return Err(unsupported(seq, "a keyed or valid-time edge"));
                    }
                    if maintenance.edges.contains(eid) {
                        continue;
                    }
                    creates.push((
                        *birth_ordinal,
                        entry.relation,
                        Create::Edge(*eid, *src, *dst, props.clone()),
                    ));
                }
                DeltaRow::Property {
                    elem,
                    property,
                    before,
                    after,
                } => {
                    if maintenance.holds(elem) || MAINTENANCE_PROPERTIES.contains(property) {
                        continue;
                    }
                    let Some(after) = after else {
                        return Err(unsupported(seq, "a property removal"));
                    };
                    match elem {
                        ElementId::Vertex(v) => {
                            w.compare_and_set_vertex_property(
                                *v,
                                *property,
                                before.clone(),
                                after.clone(),
                                WriteMismatchPolicy::AbortWrite,
                            );
                        }
                        ElementId::Edge(e) => {
                            w.compare_and_set_edge_property(
                                *e,
                                *property,
                                before.clone(),
                                after.clone(),
                                WriteMismatchPolicy::AbortWrite,
                            );
                        }
                    }
                }
                DeltaRow::LabelMembership {
                    vid, label, after, ..
                } => {
                    if MAINTENANCE.contains(label) {
                        maintenance.vertices.insert(*vid);
                    }
                    if maintenance.vertices.contains(vid) {
                        continue;
                    }
                    w.set_vertex_label(*vid, *label, *after);
                }
                DeltaRow::DeleteVertex {
                    vid,
                    sorted_retired_incident_edges,
                    ..
                } => {
                    if maintenance.vertices.contains(vid) {
                        maintenance
                            .edges
                            .extend(sorted_retired_incident_edges.iter().copied());
                        continue;
                    }
                    return Err(unsupported(seq, "a delete (fa's journal is append-only)"));
                }
                DeltaRow::DeleteEdge { eid, .. } => {
                    if maintenance.edges.contains(eid) {
                        continue;
                    }
                    return Err(unsupported(seq, "a delete (fa's journal is append-only)"));
                }
                DeltaRow::ValidTime { .. } => return Err(unsupported(seq, "a valid-time move")),
                DeltaRow::Counter { .. } => return Err(unsupported(seq, "a counter row")),
                DeltaRow::Escrow { .. } => return Err(unsupported(seq, "an escrow row")),
                DeltaRow::Sketch { .. } => return Err(unsupported(seq, "a sketch row")),
                DeltaRow::Schema { .. } => return Err(unsupported(seq, "a schema transition")),
                DeltaRow::Constraint { .. } => return Err(unsupported(seq, "a constraint change")),
            }
        }
        if !w.is_empty() {
            out.push(w);
        }
    }
    creates.sort_by_key(|(ordinal, ..)| *ordinal);
    if creates.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(unsupported(seq, "duplicate creation birth ordinals"));
    }
    let mut staged = Vec::new();
    let mut pending: Option<(RelationId, WriteBatch)> = None;
    for (_, relation, create) in creates {
        let mut w = match pending.take() {
            Some((previous, w)) if previous == relation => w,
            Some((_, done)) => {
                staged.push(done);
                WriteBatch::new(relation)
            }
            None => WriteBatch::new(relation),
        };
        match create {
            Create::Vertex(vid, labels, props) => {
                w.create_vertex(vid, labels, props);
            }
            Create::Edge(eid, src, dst, props) => {
                w.add_edge(eid, src, dst, props);
            }
        }
        pending = Some((relation, w));
    }
    if let Some((_, done)) = pending {
        staged.push(done);
    }
    staged.extend(out);
    Ok(staged)
}

/// Make the source's whole committed history readable (a checkpoint-opened
/// store starts with only its frontier in the window).
pub async fn ensure_history<V: asupersync::fs::Vfs + Clone>(
    source: &mut Database<V>,
    ctx: &PurposeContexts,
) -> Outcome<()> {
    match source
        .ensure_delta_window(&ctx.commit(), CommitSeq(0))
        .await
    {
        Ok(()) => Ok(Ok(())),
        Err(e) => Ok(Err(Refusal::new(
            code::REPLAY_UNSUPPORTED,
            exit::FOUNDATION,
            format!("the source's committed history is not readable from its start: {e:?}"),
            "plan §15.2 (a scratch book replays trunk from genesis)",
            "replay from a store whose history is retained (an un-compacted directory book or an in-memory book)",
        ))),
    }
}

/// The book root's original creating commit in the authenticated delta stream.
/// Call [`ensure_history`] first. A missing current root or a history without
/// its `CreateVertex` has no book genesis.
///
/// A vertex row's `created_at` is the start of that content version, not its
/// original birth. Checkpoint maintenance moves `ACCUMULATOR_HEAD` on the
/// root, so its current row cannot determine the earliest replayable prefix.
pub fn source_genesis<V: asupersync::fs::Vfs + Clone>(
    source: &Database<V>,
) -> Result<Option<CommitSeq>, KernelError> {
    let root = crate::rows::book_root();
    if source.vertex(root)?.is_none() {
        return Ok(None);
    }
    for batch in source.delta_since(CommitSeq(0))? {
        for entry in batch.coordinate_entries() {
            if entry.rows.iter().any(|row| {
                matches!(row, DeltaRow::CreateVertex { vid, labels, .. }
                    if *vid == root && labels.contains(&label::BOOK))
            }) {
                return Ok(Some(batch.commit_seq()));
            }
        }
    }
    Ok(None)
}

/// The source's committed batches through `prefix` (head when `None`), in
/// commit order. Call [`ensure_history`] first.
pub fn source_batches<V: asupersync::fs::Vfs + Clone>(
    source: &Database<V>,
    prefix: Option<CommitSeq>,
) -> Outcome<(CommitSeq, Vec<LogicalDeltaBatch>)> {
    let head = source.frontier()?;
    let prefix = prefix.unwrap_or(head);
    if prefix > head {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "replay prefix {} is beyond the source head {}",
                prefix.0, head.0
            ),
            "plan §15.2",
            format!("replay at or before {}", head.0),
        )));
    }
    // A scratch book starts at the source's genesis: a prefix before the
    // book root's creating commit would replay to a database with no book,
    // which no caller may present as one (WhiteCreek 3500).
    let Some(genesis) = source_genesis(source)? else {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "the source database holds no book",
            "plan §15.2",
            "replay from an opened book",
        )));
    };
    if prefix < genesis {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "replay prefix {} precedes the book's genesis at {}",
                prefix.0, genesis.0
            ),
            "plan §15.2",
            format!("replay at or after {} (the genesis commit)", genesis.0),
        )));
    }
    let batches = source
        .delta_since(CommitSeq(0))?
        .filter(|b| b.commit_seq() <= prefix)
        .cloned()
        .collect();
    Ok(Ok((prefix, batches)))
}

/// Re-commit `batches` into the empty `target`, one scratch transaction per
/// source commit that carries accounting objects, and return the [`SeqMap`].
pub async fn replay_batches<W: asupersync::fs::Vfs + Clone>(
    target: &mut Database<W>,
    ctx: &PurposeContexts,
    source_book: Id128,
    prefix: CommitSeq,
    batches: &[LogicalDeltaBatch],
) -> Outcome<SeqMap> {
    let at = target.frontier()?;
    if !target.vertices_at(at)?.is_empty() {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "the scratch target already holds objects",
            "plan §15.2 (a scratch book is a fresh open_memory database)",
            "replay into a newly opened, empty database",
        )));
    }
    let mut maintenance = Maintenance::default();
    let mut pairs = Vec::new();
    for batch in batches {
        let writes = match replayable(batch, &mut maintenance) {
            Ok(w) => w,
            Err(r) => return Ok(Err(r)),
        };
        if writes.is_empty() {
            continue;
        }
        let diverged = || {
            Refusal::new(
                code::REPLAY_UNSUPPORTED,
                exit::FOUNDATION,
                format!(
                    "replaying source commit {} diverged: a property's prior value differs in the scratch book",
                    batch.commit_seq().0
                ),
                "plan §15.2 (replay preserves every object exactly)",
                "the source history is not reproducible as accounting objects alone; report it with the source commit",
            )
        };
        let txn_cx = ctx.txn();
        let mut txn = target.begin(&txn_cx)?;
        match txn.write_ordered(target, writes) {
            Ok(()) => {}
            Err(WriteTxnError::Write(fgdb::WriteError::CompareAndSetMismatch(_))) => {
                txn.abort();
                return Ok(Err(diverged()));
            }
            Err(e) => return Err(e.into()),
        }
        let seq = match txn.commit(target, &ctx.commit()).await {
            Ok(seq) => seq,
            Err(WriteTxnError::Write(fgdb::WriteError::CompareAndSetMismatch(_))) => {
                return Ok(Err(diverged()));
            }
            Err(e) => return Err(e.into()),
        };
        pairs.push(SeqPair {
            source_seq: batch.commit_seq(),
            source_marker: batch.commit_marker_identity().marker_oid.0,
            scratch_seq: seq,
        });
    }
    Ok(Ok(SeqMap {
        source_book,
        source_prefix: prefix,
        pairs,
    }))
}

/// The whole replay under one runtime: make the source's history readable,
/// read it through `prefix`, and re-commit it into `target`.
pub async fn replay_into<V, W>(
    source: &mut Database<V>,
    target: &mut Database<W>,
    ctx: &PurposeContexts,
    source_book: Id128,
    prefix: Option<CommitSeq>,
) -> Outcome<SeqMap>
where
    V: asupersync::fs::Vfs + Clone,
    W: asupersync::fs::Vfs + Clone,
{
    if let Err(r) = ensure_history(source, ctx).await? {
        return Ok(Err(r));
    }
    let (prefix, batches) = match source_batches(source, prefix)? {
        Ok(read) => read,
        Err(r) => return Ok(Err(r)),
    };
    replay_batches(target, ctx, source_book, prefix, &batches).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(source: u64, scratch: u64) -> SeqPair {
        SeqPair {
            source_seq: CommitSeq(source),
            source_marker: [u8::try_from(source % 256).unwrap(); 32],
            scratch_seq: CommitSeq(scratch),
        }
    }

    #[test]
    fn a_seq_map_translates_by_floor_and_binds_every_pair() {
        let map = SeqMap {
            source_book: Id128([1; 16]),
            source_prefix: CommitSeq(20),
            pairs: vec![pair(3, 1), pair(7, 2), pair(15, 3)],
        };
        assert!(map.is_monotone());
        assert_eq!(map.translate(CommitSeq(2)), None);
        assert_eq!(map.translate(CommitSeq(3)), Some(CommitSeq(1)));
        assert_eq!(map.translate(CommitSeq(9)), Some(CommitSeq(2)));
        assert_eq!(map.translate(CommitSeq(20)), Some(CommitSeq(3)));
        let digest = map.digest().unwrap();
        let mut moved = map.clone();
        moved.pairs[1].scratch_seq = CommitSeq(5);
        assert_ne!(moved.digest().unwrap(), digest);
        assert!(!moved.is_monotone());
        let mut marker = map.clone();
        marker.pairs[0].source_marker = [9; 32];
        assert_ne!(marker.digest().unwrap(), digest);
    }
}
