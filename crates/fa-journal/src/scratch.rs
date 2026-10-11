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

use fa_model::symbols::{label, property};
use fa_model::{Id128, Writer, domain_digest};
use fgdb::{Database, WriteBatch, WriteMismatchPolicy, WriteTxnError};
use fgdb_delta_types::{DeltaRow, ElementId, LabelId, LogicalDeltaBatch, PropertyKeyId};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, EId, VId};

use crate::refusal::{KernelError, Outcome, Refusal, code, exit};

/// `H(domain ‖ canonical SeqMap)`.
pub const SEQ_MAP_DOMAIN: &[u8] = b"fa:seq-map:v1";
pub const SEQ_MAP_VERSION: u16 = 1;
/// The scope a scratch book replays: accounting objects only (§15.2).
pub const SCOPE_ACCOUNTING_OBJECTS_ONLY: u8 = 1;

/// Properties that are maintenance wherever they sit: the notary's
/// checkpoint head on the book root (fa-notary `checkpoint` moves it in the
/// commit that writes an `AccumulatorState`). Their moves are dropped like
/// every row on a maintenance vertex, so a checkpoint commit replays to
/// nothing and a scratch book never points at a checkpoint it lacks.
const MAINTENANCE_PROPERTIES: [PropertyKeyId; 1] = [property::ACCUMULATOR_HEAD];

/// Labels excluded from accounting-object replay: maintenance, checkpoints,
/// and report certificates whose native snapshot identities bind the source
/// database. A scratch report must issue its own certificate; the source's
/// retained artifact remains unchanged in its original book.
const MAINTENANCE: [LabelId; 4] = [
    label::REGISTER,
    label::ACCUMULATOR_STATE,
    label::REGISTER_STATE,
    label::CERTIFICATE,
];

/// One replayed source commit and the scratch commit that reproduces it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeqPair {
    pub source_seq: CommitSeq,
    /// The source commit's marker object id (its place in the source chain).
    pub source_marker: [u8; 32],
    pub scratch_seq: CommitSeq,
}

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
        let mut w = Writer::new();
        w.u16(SEQ_MAP_VERSION)
            .fixed(&self.source_book.0)
            .u64(self.source_prefix.0)
            .u8(SCOPE_ACCOUNTING_OBJECTS_ONLY)
            .list(&self.pairs, |w, p| {
                w.u64(p.source_seq.0)
                    .fixed(&p.source_marker)
                    .u64(p.scratch_seq.0);
            });
        w.finish().map_err(|e| KernelError::Model(e.into()))
    }

    pub fn digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(SEQ_MAP_DOMAIN, &[&self.canonical_bytes()?]))
    }

    /// Both sides strictly increasing.
    #[must_use]
    pub fn is_monotone(&self) -> bool {
        self.pairs
            .windows(2)
            .all(|w| w[0].source_seq < w[1].source_seq && w[0].scratch_seq < w[1].scratch_seq)
    }

    /// The scratch coordinate that knows exactly the accounting objects the
    /// source knew at `source_known_at`: the last replayed commit at or
    /// before it. `None` before the first replayed commit (nothing known)
    /// and past `source_prefix`, whose history the scratch book does not
    /// hold: a floor is only lawful inside `[0, source_prefix]`.
    #[must_use]
    pub fn translate(&self, source_known_at: CommitSeq) -> Option<CommitSeq> {
        if source_known_at > self.source_prefix {
            return None;
        }
        self.pairs
            .iter()
            .take_while(|p| p.source_seq <= source_known_at)
            .last()
            .map(|p| p.scratch_seq)
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

/// The replayable part of one source commit: its rows minus maintenance,
/// as per-relation batches in the source's order (empty when the commit was
/// only maintenance).
pub fn replayable(
    batch: &LogicalDeltaBatch,
    maintenance: &mut Maintenance,
) -> Result<Vec<WriteBatch>, Refusal> {
    let seq = batch.commit_seq();
    let mut out = Vec::new();
    for entry in batch.coordinate_entries() {
        let mut w = WriteBatch::new(entry.relation);
        for row in &entry.rows {
            match row {
                DeltaRow::CreateVertex {
                    vid,
                    labels,
                    props,
                    valid_time,
                    ..
                } => {
                    if valid_time.is_some() {
                        return Err(unsupported(seq, "a valid-time vertex"));
                    }
                    if labels.iter().any(|l| MAINTENANCE.contains(l)) {
                        maintenance.vertices.insert(*vid);
                        continue;
                    }
                    w.create_vertex(*vid, labels.clone(), props.clone());
                }
                DeltaRow::CreateEdge {
                    eid,
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
                    if maintenance.vertices.contains(src) || maintenance.vertices.contains(dst) {
                        maintenance.edges.insert(*eid);
                        continue;
                    }
                    w.add_edge(*eid, *src, *dst, props.clone());
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
    Ok(out)
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
    let Some(root) = source.vertex(crate::rows::book_root())? else {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "the source database holds no book",
            "plan §15.2",
            "replay from an opened book",
        )));
    };
    if prefix < root.created_at {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "replay prefix {} precedes the book's genesis at {}",
                prefix.0, root.created_at.0
            ),
            "plan §15.2",
            format!(
                "replay at or after {} (the genesis commit)",
                root.created_at.0
            ),
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
