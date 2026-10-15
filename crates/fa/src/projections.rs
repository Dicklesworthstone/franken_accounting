//! Settlement-safe leg-projection recovery (plan §4.2, fa-avx).
//!
//! The journal supplies every immutable mirror and topology edge. The existing
//! reversal/migration-aware open-item fold supplies `applied`; a missing mirror
//! is never interpreted as zero. No Entry, document, account, unit, lifecycle,
//! settlement edge, register, limit cell or certificate is rewritten.
//!
//! Recovery is explicit, whole-book and atomic, not an automatic action on open.
//! The pinned substrate cannot resurrect spent vertex/edge identities. Missing
//! never-created projections can be filled; retired identities or a live edge
//! whose immutable endpoints are wrong refuse rather than minting replacement
//! IDs. Repairing payload corruption is outside this API.
//!
//! Preparation first verifies every Entry against its native creation history.
//! Consistent replacement hashes, hidden labels, retired Entries and exact
//! restoration do not make a rewritten source eligible for recovery. Complete
//! history is mandatory even when the projections already appear correct.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_journal::rows::{bytes, edge_id, leg_vid, mantissa_scalar, prop};
use fa_journal::{BookContext, KernelError};
use fa_model::symbols::{label, property, relation};
use fa_model::{Entry, Id128, leg_mirrors, unit_vid};
use fa_policy::{Capability, Intent, Op};
use fgdb::{Database, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, EId, ObjectId, VId};

use crate::{AsyncBook, BookError, Outcome};

/// One atomic repair's changes, not a certificate of the underlying accounting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionRebuild {
    pub basis: CommitSeq,
    pub published_at: CommitSeq,
    pub entries_checked: usize,
    pub legs_checked: usize,
    pub legs_created: usize,
    pub legs_repaired: usize,
    pub edges_created: usize,
    pub edges_repaired: usize,
    pub edges_retired: usize,
    pub wrote: bool,
}

/// An in-process repair prepared against one exact committed snapshot.
/// Fields and batches are private: a caller cannot supply replacement amounts.
/// This is not a portable plan, approval, or permission to publish.
#[derive(Debug)]
pub struct PreparedProjectionRebuild {
    book: Id128,
    basis_root: ObjectId,
    report: ProjectionRebuild,
    batches: Vec<WriteBatch>,
}

impl PreparedProjectionRebuild {
    #[must_use]
    pub fn preview(&self) -> &ProjectionRebuild {
        &self.report
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Recompute a repair without writing. Require current whole-book Read,
    /// Verify and SchemaChange authority, including the no-Agent-on-trunk law.
    /// An empty or already-correct book still requires the same authority.
    /// This synchronous preview needs native history resident from sequence
    /// zero. Use `prepare_projection_rebuild_with_history` after reopening a
    /// checkpoint-backed book; missing history is never an integrity pass.
    pub fn prepare_projection_rebuild(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
    ) -> Outcome<PreparedProjectionRebuild> {
        if let Err(refusal) = authorize(&self.db, cx, self.context(), principal, capability)? {
            return Ok(Err(refusal));
        }
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        query.with_restriction(|| prepare(&self.db, cx, self.context()).map(Ok))
    }

    /// Load the complete retained native history before producing a preview.
    /// Admission precedes history I/O and is rechecked afterward. This does not
    /// repair an Entry or publish a journal record; an unavailable history
    /// returns the existing native-history refusal instead of a partial plan.
    pub async fn prepare_projection_rebuild_with_history(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
    ) -> Outcome<PreparedProjectionRebuild> {
        if let Err(refusal) = authorize(&self.db, cx, self.context(), principal, capability)? {
            return Ok(Err(refusal));
        }
        cx.commit().checkpoint().map_err(BookError::Context)?;
        if let Err(refusal) = fa_journal::scratch::ensure_history(&mut self.db, cx).await? {
            return Ok(Err(refusal));
        }
        self.prepare_projection_rebuild(cx, principal, capability)
    }

    /// Recheck authority and the complete preparation basis, then publish all
    /// mirror/counter/topology changes in one substrate commit. A concurrent
    /// posting, revocation, or even projection-only change invalidates the plan.
    /// A clean result is a true no-op, with no consumed sequence.
    pub async fn publish_projection_rebuild(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        prepared: PreparedProjectionRebuild,
    ) -> Outcome<ProjectionRebuild> {
        if let Err(refusal) = authorize(&self.db, cx, self.context(), principal, capability)? {
            return Ok(Err(refusal));
        }
        cx.commit().checkpoint().map_err(BookError::Context)?;
        if prepared.book != self.context().book_id
            || prepared.report.basis != self.db.frontier().map_err(KernelError::from)?
            || prepared.basis_root != self.db.partition_root().map_err(KernelError::from)?.0
        {
            return Err(fa_registers::RegisterError::StaleFold.into());
        }
        let mut report = prepared.report;
        if !prepared.batches.is_empty() {
            let mut transaction = self.db.begin(&cx.txn()).map_err(KernelError::from)?;
            if let Err(error) = transaction.write_ordered(&mut self.db, prepared.batches) {
                transaction.abort();
                return Err(KernelError::from(error).into());
            }
            report.published_at = transaction.commit(&mut self.db, &cx.commit())
                .await.map_err(KernelError::from)?;
            report.wrote = true;
        }
        // These are the existing independent checkers, not the repair's own
        // expected maps. Never report a successful repair of only one family.
        let query = cx.query();
        let (projection, applications) = query.with_restriction(|| {
            Ok::<_, BookError>((
                fa_journal::verify_projections(&self.db, self.context(), None)?,
                fa_registers::verify_open_items(&self.db, self.context(), None)?,
            ))
        })?;
        if !projection.is_green() || !applications.is_green() {
            return Err(corrupt(format!(
                "projection rebuild at sequence {} did not verify; inspect projections and open items before posting",
                report.published_at.0,
            )));
        }
        Ok(Ok(report))
    }

    /// Explicit recovery from the current journal, with no caller-provided
    /// balances or replacement payloads. Load native history only after
    /// admission, then verify source immutability before deriving any changes.
    /// Call `prepare_projection_rebuild_with_history` and publish separately
    /// for a preview; publication always requires current authority again.
    pub async fn rebuild_projections(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
    ) -> Outcome<ProjectionRebuild> {
        let prepared = match self.prepare_projection_rebuild_with_history(cx, principal, capability).await? {
            Ok(prepared) => prepared,
            Err(refusal) => return Ok(Err(refusal)),
        };
        self.publish_projection_rebuild(cx, principal, capability, prepared).await
    }
}

fn corrupt(message: impl Into<String>) -> BookError {
    KernelError::Corrupt(message.into()).into()
}

fn authorize<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    principal: VId,
    capability: &Capability,
) -> Outcome<()> {
    // All request-only checks precede even frontier observation.
    let admission = fa_policy::admit_read(capability, principal, book.book_id)
        .and_then(|()| fa_policy::require(capability, Op::Verify, "rebuilding leg projections"))
        .and_then(|()| fa_policy::admit(capability, &Intent {
            principal, trunk: true, op: Op::SchemaChange, book: book.book_id, legs: &[],
        }));
    if let Err(denial) = admission {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    let query = cx.query();
    query.checkpoint().map_err(BookError::Context)?;
    query.with_restriction(|| {
        let head = db.frontier().map_err(KernelError::from)?;
        if let Err(denial) = fa_policy::current(capability, head) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        Ok(fa_journal::policy::capability_admitted(db, book, capability)?)
    })
}

// kind indexes the frozen relations below; value is ordinal or dimension_id.
// Storing primitive metadata here avoids introducing another dependency edge
// merely to name the substrate's relation/property IDs.
struct ExpectedEdge {
    kind: usize,
    src: VId,
    dst: VId,
    value: Option<i64>,
}

fn prepare<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
) -> Result<PreparedProjectionRebuild, BookError> {
    let basis = db.frontier().map_err(KernelError::from)?;
    let basis_root = db.partition_root().map_err(KernelError::from)?.0;
    // Never make projections agree with a self-consistently rewritten Entry.
    // Discover the source set from native births, not a possibly damaged live
    // label scan. This gate precedes both the fold and every staged repair.
    fa_journal::verify_entry_history(db, cx, book, Some(basis))?;
    let rows = db.vertices_at(basis).map_err(KernelError::from)?;
    let edges = db.edges_at(basis).map_err(KernelError::from)?;
    let vertices: BTreeMap<_, _> = rows.iter().map(|row| (row.vid, row)).collect();
    let relations = [relation::HAS_LEG, relation::POSTS_TO, relation::IN_UNIT, relation::FOR];
    let keys = [property::FA_EFFECTIVE_DAY, property::SIDE, property::ACCOUNT_REF,
        property::UNIT_ID, property::AMOUNT, property::AMOUNT_BYTES, property::ORDINAL,
        property::APPLIED];
    let mut vertex_changes = WriteBatch::new(relation::HAS_LEG);
    let mut edge_changes: Vec<_> = relations.iter().map(|r| WriteBatch::new(*r)).collect();
    let mut owned_entries = BTreeSet::new();
    let mut expected_legs = BTreeSet::new();
    let mut expected_edges: BTreeMap<EId, ExpectedEdge> = BTreeMap::new();
    let mut report = ProjectionRebuild {
        basis, published_at: basis, entries_checked: 0, legs_checked: 0,
        legs_created: 0, legs_repaired: 0,
        edges_created: 0, edges_repaired: 0, edges_retired: 0, wrote: false,
    };
    // A lost Entry label must not turn its real legs into apparently orphaned
    // projections. Never guess an authoritative label, and never reinterpret
    // another typed object's bytes (for example a certificate chunk) as Entry.
    for row in rows.iter().filter(|row| row.labels.is_empty()) {
        if let Some(CanonicalScalar::Bytes(payload)) = prop(row, property::FA_PAYLOAD)
            && Entry::decode(payload.as_slice()).is_ok()
        {
            return Err(corrupt("an entry payload has lost its Entry label; restore journal integrity before projection recovery"));
        }
    }
    // This fold reads journal payloads, NOT damaged leg rows or HAS_LEG edges.
    // Its migration visibility and iterative reversal parity are reused intact.
    let mut applied = BTreeMap::new();
    for item in fa_registers::open_items(db, book, None, Some(basis))? {
        if item.applied < 0 || item.applied_out < 0 || item.open < 0 {
            return Err(corrupt("cannot rebuild projections from an invalid open-item fold"));
        }
        if applied.insert((item.entry, item.ordinal), item.applied).is_some() {
            return Err(corrupt("duplicate open-item identity in the journal fold"));
        }
    }
    for row in rows.iter().filter(|row| row.labels.contains(&label::ENTRY)) {
        cx.query().checkpoint().map_err(BookError::Context)?;
        let payload = bytes(row, property::FA_PAYLOAD, "entry._fa_payload")?;
        let entry = Entry::decode(&payload).map_err(KernelError::from)?;
        if entry.proposal.book_id != book.book_id || entry.proposal.branch_id != Id128::TRUNK {
            return Err(corrupt("cannot rebuild projections of a foreign journal entry"));
        }
        owned_entries.insert(row.vid);
        report.entries_checked += 1;
        for (index, leg) in entry.proposal.legs.iter().enumerate() {
            let ordinal = u16::try_from(index).map_err(|_| corrupt("more than u16 legs"))?;
            let lvid = leg_vid(row.vid, ordinal);
            if !expected_legs.insert(lvid) {
                return Err(corrupt("duplicate leg identity derived from journal payloads"));
            }
            let unit = book.units.get(leg.amount.unit)
                .ok_or_else(|| corrupt("a projected leg names an unregistered unit"))?;
            let unit = unit_vid(book.book_id, &format!("{}@v{}", unit.code, unit.version));
            if !vertices.get(&leg.account_ref).is_some_and(|row| row.labels.contains(&label::ACCOUNT))
                || !vertices.get(&unit).is_some_and(|row| row.labels.contains(&label::UNIT))
            {
                return Err(corrupt("a projected leg's authoritative account or unit is missing"));
            }
            let mut mirrors = leg_mirrors(leg, ordinal, entry.proposal.effective_date, &book.units)
                .map_err(KernelError::from)?;
            let counter = applied.remove(&(row.vid, ordinal)).unwrap_or(0);
            mirrors.push((property::APPLIED, mantissa_scalar("applied", counter)?));
            report.legs_checked += 1;
            match vertices.get(&lvid) {
                None => {
                    vertex_changes.create_vertex(lvid, vec![label::LEG], mirrors);
                    report.legs_created += 1;
                }
                Some(stored) => {
                    if stored.labels.iter().any(|id| *id != label::LEG)
                        || prop(stored, property::FA_PAYLOAD).is_some()
                    {
                        return Err(corrupt("a required leg identity is occupied by a non-projection object"));
                    }
                    let mut changed = false;
                    if stored.labels != vec![label::LEG] {
                        vertex_changes.set_vertex_label(lvid, label::LEG, true);
                        changed = true;
                    }
                    for key in keys {
                        let expected = mirrors.iter().find(|(id, _)| *id == key).map(|(_, value)| value);
                        if prop(stored, key) != expected {
                            vertex_changes.set_vertex_property(lvid, key, expected.cloned());
                            changed = true;
                        }
                    }
                    report.legs_repaired += usize::from(changed);
                }
            }
            let mut topology = vec![
                ExpectedEdge { kind: 0, src: row.vid, dst: lvid, value: Some(i64::from(ordinal)) },
                ExpectedEdge { kind: 1, src: lvid, dst: leg.account_ref, value: None },
                ExpectedEdge { kind: 2, src: lvid, dst: unit, value: None },
            ];
            for (dimension, value) in &leg.dimension_set {
                if !vertices.get(value).is_some_and(|row| row.labels.contains(&label::DIMENSION_VALUE)) {
                    return Err(corrupt("a projected leg's authoritative dimension value is missing"));
                }
                topology.push(ExpectedEdge {
                    kind: 3, src: lvid, dst: *value, value: Some(i64::from(*dimension)),
                });
            }
            for edge in topology {
                let eid = edge_id(relations[edge.kind], edge.src, edge.dst);
                if expected_edges.insert(eid, edge).is_some() {
                    return Err(corrupt("journal payloads require a duplicate projection edge"));
                }
            }
        }
    }
    if !applied.is_empty() {
        return Err(corrupt("an open-item fold names a leg absent from the journal"));
    }
    // An orphan may be evidence of a lost authoritative Entry, not merely an
    // extra cache row. Do not erase that diagnostic or cascade relationships.
    if rows.iter().any(|row| row.labels.contains(&label::LEG)
        && !expected_legs.contains(&row.vid))
    {
        return Err(corrupt("an orphan leg has no decoded journal owner; no projection repair published"));
    }
    for stored in &edges {
        let eid = stored.entry.eid;
        if let Some(expected) = expected_edges.remove(&eid) {
            if stored.entry.relation != relations[expected.kind]
                || stored.entry.src != expected.src || stored.entry.dst != expected.dst
            {
                return Err(corrupt("a projection edge identity has incompatible immutable endpoints; replacement identities are forbidden"));
            }
            let props = match expected.value {
                Some(value) => vec![(if expected.kind == 0 { property::ORDINAL }
                    else { property::DIMENSION_ID }, CanonicalScalar::Int(value))],
                None => Vec::new(),
            };
            if stored.props != props {
                let batch = &mut edge_changes[expected.kind];
                for (key, _) in &stored.props {
                    if !props.iter().any(|(expected, _)| expected == key) {
                        batch.set_edge_property(eid, *key, None);
                    }
                }
                for (key, value) in props {
                    if !stored.props.iter().any(|(stored_key, stored_value)| *stored_key == key && *stored_value == value) {
                        batch.set_edge_property(eid, key, Some(value));
                    }
                }
                report.edges_repaired += 1;
            }
        } else if let Some(kind) = relations.iter().position(|r| *r == stored.entry.relation) {
            let owned = if kind == 0 {
                owned_entries.contains(&stored.entry.src)
                    && expected_legs.contains(&stored.entry.dst)
            } else {
                expected_legs.contains(&stored.entry.src)
            };
            if !owned {
                return Err(corrupt("an unexpected projection edge has no journal-derived owner; no repair published"));
            }
            edge_changes[kind].delete_edge(eid);
            report.edges_retired += 1;
        }
    }
    for (eid, expected) in expected_edges {
        let props = match expected.value {
            Some(value) => vec![(if expected.kind == 0 { property::ORDINAL }
                else { property::DIMENSION_ID }, CanonicalScalar::Int(value))],
            None => Vec::new(),
        };
        edge_changes[expected.kind].add_edge(eid, expected.src, expected.dst, props);
        report.edges_created += 1;
    }
    let mut batches = vec![vertex_changes];
    batches.extend(edge_changes);
    batches.retain(|batch| !batch.is_empty());
    cx.query().checkpoint().map_err(BookError::Context)?;
    Ok(PreparedProjectionRebuild { book: book.book_id, basis_root, report, batches })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod history_tests;
