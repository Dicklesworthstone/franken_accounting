//! A close prerequisite for a real, current, retained statement issuance.
//!
//! The kernel authenticates native issuance, retained bytes and their typed
//! binding. The facade additionally replays the complete accounting report.

use std::collections::BTreeSet;

use asupersync::fs::Vfs;
use fa_model::symbols::{label, property, relation};
use fa_model::{EntryClass, Id128, Writer, domain_digest, statement_issuance_vid};
use fa_policy::Capability;
use fgdb::{Database, VertexRow, WriteTxn, WriteTxnError};
use fgdb_delta_types::{DeltaRow, ElementId};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::BookContext;
use crate::issuance::IssuanceRecord;
use crate::object::{self, ObjectKind};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};

mod certificate;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementIssuanceCheckpoint {
    issuance: IssuanceRecord,
    known_at: CommitSeq,
    source_digest: [u8; 32],
    retained: Vec<VId>,
}

impl StatementIssuanceCheckpoint {
    pub fn issuance(&self) -> &IssuanceRecord {
        &self.issuance
    }

    pub fn known_at(&self) -> CommitSeq {
        self.known_at
    }

    pub fn source_digest(&self) -> &[u8; 32] {
        &self.source_digest
    }

    pub(super) fn witness<V: Vfs + Clone>(
        &self,
        txn: &WriteTxn,
        db: &Database<V>,
    ) -> Result<(), KernelError> {
        if self.retained.is_empty() || self.known_at != txn.basis() {
            return Err(super::corrupt(
                "statement checkpoint lacks retained native evidence",
            ));
        }
        for vid in self
            .retained
            .iter()
            .copied()
            .chain([self.issuance.vid, self.issuance.control_entry])
        {
            if txn.vertex(db, vid)?.is_none() {
                return Err(super::corrupt("issued statement evidence disappeared"));
            }
        }
        let control = txn
            .vertex(db, self.issuance.control_entry)?
            .ok_or_else(|| super::corrupt("issued statement control disappeared"))?;
        // The control may itself use object storage. Re-reading through the
        // transaction binds every fragment, not only its immutable root.
        let entry = crate::entry_storage::decode_staged(txn, db, &control)?;
        // A legacy control may have no claim. Enlist that absence too, so a
        // concurrent replacement cannot change the authenticated key ancestry.
        txn.vertex(db, crate::outcome::entry_outcome_vid(&entry.proposal))?;
        let membership = crate::rows::edge_id(
            relation::IN_CASE,
            self.issuance.control_entry,
            self.issuance.vid,
        );
        if txn.edge(db, membership)?.is_none() {
            return Err(super::corrupt("issued statement membership disappeared"));
        }
        Ok(())
    }
}

pub(super) fn unavailable(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::PLAN_INVALIDATED,
        exit::CONFLICT,
        message,
        "plan §7.5 / §12.5 (close requires the exact issued statement over the current accounting source)",
        "finish monetary close work, certify and issue the current statement, then review a new close run selecting that issuance ordinal",
    )
}

/// Authenticate retained statement identity and unchanged accounting source.
/// This native check does not claim to replay statement arithmetic. Current
/// whole-book Read admission precedes all source observations.
pub fn verify_statement_issuance_checkpoint<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    period: &str,
    ordinal: u32,
    known_at: Option<CommitSeq>,
) -> Outcome<StatementIssuanceCheckpoint> {
    if let Err(refusal) = super::admit(db, book, capability, None)? {
        return Ok(Err(refusal));
    }
    statement_issuance_checkpoint_at(
        db,
        cx,
        book,
        period,
        ordinal,
        known_at.unwrap_or(db.frontier()?),
    )
}

/// The scratch book excludes Certificate storage. Its caller must first
/// authenticate/replay the original book's retained certificate and compare
/// this source digest. This value cannot stage a live completion receipt.
pub fn statement_issuance_source_checkpoint<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    period: &str,
    ordinal: u32,
    known_at: CommitSeq,
) -> Outcome<StatementIssuanceCheckpoint> {
    if let Err(refusal) = super::admit(db, book, capability, None)? {
        return Ok(Err(refusal));
    }
    source_checkpoint_at(db, cx, book, period, ordinal, known_at)
}

pub(super) fn statement_issuance_checkpoint_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    period: &str,
    ordinal: u32,
    at: CommitSeq,
) -> Outcome<StatementIssuanceCheckpoint> {
    let mut checkpoint = match source_checkpoint_at(db, cx, book, period, ordinal, at)? {
        Ok(checkpoint) => checkpoint,
        Err(refusal) => return Ok(Err(refusal)),
    };
    checkpoint.retained =
        match certificate::verify_retained(db, cx, book, &checkpoint.issuance, at)? {
            Ok(retained) => retained,
            Err(refusal) => return Ok(Err(refusal)),
        };
    Ok(Ok(checkpoint))
}

fn source_checkpoint_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    period: &str,
    ordinal: u32,
    at: CommitSeq,
) -> Outcome<StatementIssuanceCheckpoint> {
    if ordinal == 0 || at.0 == 0 || at > db.frontier()? {
        return Ok(Err(unavailable(
            "the statement check selects an unavailable issuance or prefix",
        )));
    }
    let Some(issuance) = crate::issuance::record_of_at(
        db,
        book,
        statement_issuance_vid(book.book_id, period, ordinal),
        at,
    )?
    else {
        return Ok(Err(unavailable(
            "the selected period has no such native statement issuance",
        )));
    };
    let source = &issuance.issuance;
    if source.period != period
        || source.ordinal != ordinal
        || source.certified_at.0 == 0
        || source.certified_at >= issuance.recorded_at
        || issuance.recorded_at > at
    {
        return Err(super::corrupt(
            "issued statement has inconsistent source coordinates",
        ));
    }
    let mut changed = BTreeSet::new();
    let mut changed_edges = BTreeSet::new();
    let mut covered = source.certified_at;
    for batch in db.delta_since(source.certified_at)? {
        let seq = batch.commit_seq();
        if seq > at {
            break;
        }
        if covered.0.checked_add(1) != Some(seq.0) {
            return Ok(Err(unavailable(
                "the complete native history since statement certification is unavailable",
            )));
        }
        cx.query()
            .checkpoint()
            .map_err(WriteTxnError::Interrupted)?;
        for coordinate in batch.coordinate_entries() {
            for delta in &coordinate.rows {
                let vid = match delta {
                    DeltaRow::CreateVertex {
                        vid, valid_time, ..
                    } => {
                        if valid_time.is_some() {
                            return Ok(Err(unavailable(
                                "statement source acquired unsupported valid-time history",
                            )));
                        }
                        Some(*vid)
                    }
                    DeltaRow::LabelMembership { vid, .. } => Some(*vid),
                    DeltaRow::DeleteVertex {
                        vid,
                        sorted_retired_incident_edges,
                        ..
                    } => {
                        changed_edges
                            .extend(sorted_retired_incident_edges.iter().map(|eid| (seq, *eid)));
                        Some(*vid)
                    }
                    DeltaRow::Property {
                        elem: ElementId::Vertex(vid),
                        property: key,
                        ..
                    } => {
                        // Period state and accumulator maintenance do not alter
                        // statement amounts or the period's canonical bounds.
                        if *key == property::STATE
                            && db
                                .vertex_at(*vid, seq)?
                                .is_some_and(|r| r.labels.contains(&label::PERIOD))
                        {
                            continue;
                        }
                        if *vid == crate::rows::book_root()
                            && ![
                                property::FA_PAYLOAD,
                                property::BOOK_ID,
                                property::BASE_UNIT,
                                property::SYMBOLS_DIGEST,
                                property::UNIT_TABLE_DIGEST,
                            ]
                            .contains(key)
                        {
                            continue;
                        }
                        Some(*vid)
                    }
                    DeltaRow::CreateEdge {
                        eid,
                        valid_time,
                        canonical_key,
                        ..
                    } => {
                        if valid_time.is_some() || canonical_key.is_some() {
                            return Ok(Err(unavailable(
                                "statement source acquired an unsupported keyed or valid-time edge",
                            )));
                        }
                        changed_edges.insert((seq, *eid));
                        None
                    }
                    DeltaRow::Property {
                        elem: ElementId::Edge(eid),
                        ..
                    }
                    | DeltaRow::DeleteEdge { eid, .. } => {
                        changed_edges.insert((seq, *eid));
                        None
                    }
                    DeltaRow::ValidTime { .. }
                    | DeltaRow::Counter { .. }
                    | DeltaRow::Escrow { .. }
                    | DeltaRow::Sketch { .. }
                    | DeltaRow::Schema { .. }
                    | DeltaRow::Constraint { .. } => {
                        return Ok(Err(unavailable(
                            "statement source contains an unsupported native input change",
                        )));
                    }
                };
                if let Some(vid) = vid {
                    changed.insert((seq, vid));
                }
            }
        }
        covered = seq;
    }
    if covered != at {
        return Ok(Err(unavailable(
            "the complete native history since statement certification is unavailable",
        )));
    }
    let mut controls = BTreeSet::new();
    let mut control_fragments = BTreeSet::new();
    let mut changed_fragments = BTreeSet::new();
    for (seq, vid) in changed {
        cx.query()
            .checkpoint()
            .map_err(WriteTxnError::Interrupted)?;
        let before = db.vertex_at(vid, CommitSeq(seq.0 - 1))?;
        let after = db.vertex_at(vid, seq)?;
        if before
            .as_ref()
            .is_some_and(|row| row.labels.contains(&label::ENTRY))
        {
            return Ok(Err(unavailable(
                "journal history changed after the issued statement was certified",
            )));
        }
        if let Some(row) = after
            .as_ref()
            .filter(|row| row.labels.contains(&label::ENTRY))
        {
            let entry = crate::entry_storage::decode_at(db, row, seq)?;
            if row.created_at != seq
                || entry.proposal.book_id != book.book_id
                || entry.proposal.branch_id != Id128::TRUNK
                || !crate::entry_storage::mirrors_match(row, &entry)?
            {
                return Err(super::corrupt(
                    "statement source contains an inauthentic journal entry",
                ));
            }
            if !entry.proposal.legs.is_empty()
                || !matches!(
                    entry.proposal.class,
                    EntryClass::CLOSE_CONTROL
                        | EntryClass::PERIOD_CONTROL
                        | EntryClass::ISSUANCE_CONTROL
                        | EntryClass::DRAFT_CONTROL
                        | EntryClass::SCENARIO_CONTROL
                        | EntryClass::TIME_CONTROL
                )
            {
                return Ok(Err(unavailable(
                    "accounting source changed after the issued statement was certified",
                )));
            }
            controls.insert((seq, vid));
            let encoded = entry.encode()?;
            if encoded.len() > object::CHUNK_BYTES {
                let identity = object::identity(ObjectKind::Entry, &encoded);
                control_fragments.extend((0..encoded.len().div_ceil(object::CHUNK_BYTES)).map(
                    |index| {
                        (
                            seq,
                            object::fragment_vid(book.book_id, vid, identity, index),
                        )
                    },
                ));
            }
            continue;
        }
        if before
            .iter()
            .chain(after.iter())
            .any(|row| row.labels.contains(&label::ENTRY_FRAGMENT))
        {
            if before.is_some() {
                return Ok(Err(unavailable(
                    "journal storage changed after statement certification",
                )));
            }
            changed_fragments.insert((seq, vid));
            continue;
        }
        if before.iter().chain(after.iter()).any(statement_input) {
            return Ok(Err(unavailable(
                "statement inputs changed after certification",
            )));
        }
    }
    if !changed_fragments.is_subset(&control_fragments) {
        return Ok(Err(unavailable(
            "new journal storage is not part of unchanged close or issuance metadata",
        )));
    }
    for (seq, eid) in changed_edges {
        cx.query()
            .checkpoint()
            .map_err(WriteTxnError::Interrupted)?;
        let before_at = CommitSeq(seq.0 - 1);
        let before = db.edge_at(eid, before_at)?;
        let after = db.edge_at(eid, seq)?;
        // A new metadata membership may point into the book or into the
        // transitioned period. Existing accounting topology is immutable.
        if before.is_none()
            && let Some(edge) = &after
        {
            let e = &edge.entry;
            let control = controls.contains(&(seq, e.src));
            let allowed_period = control && e.relation == relation::IN_PERIOD;
            let allowed_book = e.relation == relation::IN_BOOK;
            let mut metadata = true;
            for vid in [e.src, e.dst] {
                let Some(row) = db.vertex_at(vid, seq)? else {
                    metadata = false;
                    break;
                };
                if controls.contains(&(seq, vid))
                    || (allowed_period && row.labels.as_slice() == [label::PERIOD])
                    || (allowed_book && vid == crate::rows::book_root())
                {
                    continue;
                }
                metadata &= !statement_input(&row);
            }
            if metadata {
                continue;
            }
        }
        for (edge, prefix) in before
            .iter()
            .map(|e| (e, before_at))
            .chain(after.iter().map(|e| (e, seq)))
        {
            for vid in [edge.entry.src, edge.entry.dst] {
                if db
                    .vertex_at(vid, prefix)?
                    .as_ref()
                    .is_some_and(statement_input)
                {
                    return Ok(Err(unavailable(
                        "statement input relationships changed after certification",
                    )));
                }
            }
        }
    }
    let mut source = Writer::new();
    source
        .bytes(&issuance.issuance.canonical_bytes()?)
        .u128(issuance.control_entry.0)
        .u64(issuance.recorded_at.0);
    let source_digest = domain_digest(b"fa:close-issued-statement:v1", &[&source.finish()?]);
    Ok(Ok(StatementIssuanceCheckpoint {
        issuance,
        known_at: at,
        source_digest,
        retained: Vec::new(),
    }))
}

fn statement_input(row: &VertexRow) -> bool {
    row.labels.iter().any(|label| {
        [
            label::BOOK,
            label::ACCOUNT,
            label::UNIT,
            label::FISCAL_CALENDAR,
            label::PERIOD,
            label::ENTRY,
            label::LEG,
            label::ENTRY_FRAGMENT,
            label::MIGRATION_RUN,
            label::MIGRATION_RUN_FRAGMENT,
            label::MIGRATION_SOURCE,
            label::MIGRATION_SOURCE_FRAGMENT,
            label::STATEMENT_DEFINITION,
        ]
        .contains(label)
    }) || (row.labels.contains(&label::DOCUMENT)
        && matches!(crate::rows::prop(row, property::CODE), Some(CanonicalScalar::Text(code)) if code.as_bytes() == b"Rate"))
}
