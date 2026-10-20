//! Immutable correction lineage and metadata-only bank decision history.
//!
//! The active claims are a fold of native confirmation and Unmatch births.
//! Every former row and edge remains immutable. Metadata history authenticates
//! those recorded decisions without fetching original BankStatement/manifest
//! bytes; the existing full-source reader continues to verify that separate
//! evidence scope.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::symbols::{label, property, relation};
use fa_model::{Id128, Oid, Reader, Writer, domain_digest};
use fa_policy::{Capability, Observes, Op, Profile, Reach};
use fgdb::{Database, VertexRow, WriteBatch, WriteTxn, WriteTxnError};
use fgdb_delta_types::{DeltaRow, ElementId, LabelId, PropertyKeyId};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use super::{
    BankDecisionRef, BankMatchLineage, BankMatchRecorded, checkpoint, conflict, drift, invalid,
    short_id, verify,
};
use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal};
use crate::rows::{book_root, edge_id, scalar_bytes, scalar_text};

pub const UNMATCH_SCHEMA_REGISTRY: &str =
    include_str!("../../../../registries/object_schemas/bank_unmatch.toml");

const UNMATCH_MAGIC: &[u8; 15] = b"FA-BANK-UNMATCH";
const UNMATCH_DOMAIN: &[u8] = b"fa:bank-unmatch-record:v1";
const UNMATCH_BYTES: usize = 140;
const UNMATCH_METHOD: &str = "explicit-unmatch";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankUnmatchRequest {
    pub target: BankDecisionRef,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankUnmatch {
    pub book_id: Id128,
    pub target: BankDecisionRef,
    pub unmatched_by: VId,
    pub unmatching_profile: Profile,
    pub capability_commitment: [u8; 32],
    pub security_policy_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankUnmatchRecorded {
    pub unmatch_vid: VId,
    pub unmatch_digest: [u8; 32],
    pub recorded_at: CommitSeq,
    pub already_recorded: bool,
    pub unmatch: BankUnmatch,
}

/// Immutable native decision facts, their explicit corrections, and the active
/// subset at one prefix. This is not a statement-balance reconciliation, a
/// complete outstanding-item inventory, or a reconciled-through lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankMatchHistory {
    pub known_at: CommitSeq,
    pub confirmations: Vec<BankMatchRecorded>,
    pub unmatches: Vec<BankUnmatchRecorded>,
    pub active: Vec<BankMatchRecorded>,
}

fn corrupt(error: impl core::fmt::Display) -> KernelError {
    KernelError::Corrupt(format!("bank correction: {error}"))
}

impl BankUnmatch {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::new();
        w.fixed(UNMATCH_MAGIC)
            .u16(1)
            .u16(0)
            .fixed(&self.book_id.0)
            .u128(self.target.vid.0)
            .fixed(&self.target.digest)
            .u128(self.unmatched_by.0)
            .u8(self.unmatching_profile.tag())
            .fixed(&self.capability_commitment)
            .u64(self.security_policy_epoch);
        w.finish().map_err(corrupt)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        if bytes.len() != UNMATCH_BYTES {
            return Err(corrupt("invalid exact Unmatch record length"));
        }
        let mut r = Reader::new(bytes);
        if r.fixed::<15>("bank_unmatch.magic").map_err(corrupt)? != *UNMATCH_MAGIC
            || r.u16("bank_unmatch.major").map_err(corrupt)? != 1
            || r.u16("bank_unmatch.minor").map_err(corrupt)? != 0
        {
            return Err(corrupt("unknown Unmatch record version"));
        }
        let result = Self {
            book_id: Id128(r.fixed("bank_unmatch.book").map_err(corrupt)?),
            target: BankDecisionRef {
                vid: VId(r.u128("bank_unmatch.target").map_err(corrupt)?),
                digest: r.fixed("bank_unmatch.target_digest").map_err(corrupt)?,
            },
            unmatched_by: VId(r.u128("bank_unmatch.principal").map_err(corrupt)?),
            unmatching_profile: Profile::from_tag(r.u8("bank_unmatch.profile").map_err(corrupt)?)
                .ok_or_else(|| corrupt("unknown Unmatch principal profile"))?,
            capability_commitment: r.fixed("bank_unmatch.capability").map_err(corrupt)?,
            security_policy_epoch: r.u64("bank_unmatch.policy_epoch").map_err(corrupt)?,
        };
        r.finish().map_err(corrupt)?;
        if result.unmatching_profile != Profile::Human || result.canonical_bytes()? != bytes {
            return Err(corrupt("Unmatch lacks a canonical Human attribution"));
        }
        Ok(result)
    }

    pub fn digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(UNMATCH_DOMAIN, &[&self.canonical_bytes()?]))
    }

    #[must_use]
    pub fn vid(&self) -> VId {
        unmatch_vid(self.book_id, self.target)
    }

    fn recorded(
        &self,
        at: CommitSeq,
        already_recorded: bool,
    ) -> Result<BankUnmatchRecorded, KernelError> {
        Ok(BankUnmatchRecorded {
            unmatch_vid: self.vid(),
            unmatch_digest: self.digest()?,
            recorded_at: at,
            already_recorded,
            unmatch: self.clone(),
        })
    }
}

fn unmatch_vid(book: Id128, target: BankDecisionRef) -> VId {
    short_id(domain_digest(
        b"fa:vid:bank-unmatch:v1",
        &[&book.0, &target.vid.0.to_le_bytes(), &target.digest],
    ))
}

fn unmatch_props(
    value: &BankUnmatch,
) -> Result<Vec<(PropertyKeyId, CanonicalScalar)>, KernelError> {
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("bank_unmatch.payload", value.canonical_bytes()?)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("bank_unmatch.digest", value.digest()?.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("bank_unmatch.book", value.book_id.0.to_vec())?,
        ),
        (
            property::CODE,
            scalar_text("bank_unmatch.method", UNMATCH_METHOD)?,
        ),
    ];
    props.sort_by_key(|(key, _)| key.0);
    Ok(props)
}

fn read_unmatch(row: &VertexRow, book: Id128) -> Outcome<BankUnmatchRecorded> {
    let value = match BankUnmatch::decode(verify::payload(row)?) {
        Ok(value) => value,
        Err(error) => return Ok(Err(drift(error.to_string()))),
    };
    if row.labels.as_slice() != [label::BANK_UNMATCH]
        || value.book_id != book
        || value.vid() != row.vid
        || row.props != unmatch_props(&value)?
    {
        return Ok(Err(drift(
            "the Unmatch identity, book or canonical mirrors disagree",
        )));
    }
    Ok(Ok(value.recorded(row.created_at, false)?))
}

/// Admit a metadata history prefix without hydrating or observing that history.
/// CLI and facade opening paths use this before stamping read metadata.
pub fn admit_bank_match_history<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
    known_at: Option<CommitSeq>,
) -> Outcome<CommitSeq> {
    if let Err(denial) = fa_policy::admit_read(capability, capability.holder(), book.book_id)
        .and_then(|()| {
            fa_policy::require(capability, Op::Reconcile, "reading bank decision history")
        })
    {
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    // A historical prefix never restores revoked or expired current authority.
    if let Err(refusal) = crate::policy::current_at(db, book, capability)? {
        return Ok(Err(refusal));
    }
    let mut reach = Reach::whole_book(true);
    reach.observes = known_at.map_or(Observes::Head, Observes::At);
    if let Err(denial) = fa_policy::reach(capability, &reach, None) {
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    let frontier = db.frontier()?;
    let selected = known_at.unwrap_or(frontier);
    if selected > frontier {
        return Ok(Err(invalid(
            "bank decision history cannot select a future native prefix",
        )));
    }
    Ok(Ok(selected))
}

/// Metadata-only authenticated history. Current Read and Reconcile admission
/// precedes hydration or observation. External manifests need no fetching.
/// The optional statement OID filters output after the complete claim fold.
pub async fn bank_match_history<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    known_at: Option<CommitSeq>,
    statement_oid: Option<Oid>,
) -> Outcome<BankMatchHistory> {
    if let Err(refusal) = admit_bank_match_history(db, book, capability, known_at)? {
        return Ok(Err(refusal));
    }
    checkpoint(cx)?;
    if let Err(refusal) = crate::scratch::ensure_history(db, cx).await? {
        return Ok(Err(refusal));
    }
    let at = match admit_bank_match_history(db, book, capability, known_at)? {
        Ok(at) => at,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let mut result = match history_at(db, cx, book, at)? {
        Ok(result) => result,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Some(statement) = statement_oid {
        result
            .confirmations
            .retain(|recorded| recorded.confirmation.statement_oid == statement);
        let kept: BTreeSet<_> = result
            .confirmations
            .iter()
            .map(|recorded| recorded.match_vid)
            .collect();
        result
            .unmatches
            .retain(|recorded| kept.contains(&recorded.unmatch.target.vid));
        result
            .active
            .retain(|recorded| recorded.confirmation.statement_oid == statement);
    }
    Ok(Ok(result))
}

/// Native history is the authority, including births hidden by deletion or
/// relabeling. A rewrite followed by exact restoration remains a rewrite.
/// The same law is used by metadata history, publication and exact retries.
fn births<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    at: CommitSeq,
) -> Outcome<BTreeMap<VId, (LabelId, CommitSeq)>> {
    let families = [
        label::BANK_MATCH,
        label::BANK_MATCHED_LEG,
        label::BANK_UNMATCH,
    ];
    let mut births = BTreeMap::new();
    let mut through = 0_u64;
    for batch in db.delta_since(CommitSeq(0))? {
        let seq = batch.commit_seq();
        if seq > at {
            break;
        }
        checkpoint(cx)?;
        if through.checked_add(1) != Some(seq.0) {
            return Ok(Err(drift(
                "bank decision integrity requires complete native history from sequence zero",
            )));
        }
        // Coordinates sort canonically, not causally; discover all births first.
        for coordinate in batch.coordinate_entries() {
            for row in &coordinate.rows {
                checkpoint(cx)?;
                if let DeltaRow::CreateVertex { vid, labels, .. } = row
                    && let Some(kind) = labels.iter().find(|kind| families.contains(kind))
                    && (labels.as_slice() != [*kind] || births.insert(*vid, (*kind, seq)).is_some())
                {
                    return Ok(Err(drift(
                        "a bank decision or claim has an invalid or repeated native birth",
                    )));
                }
            }
        }
        for coordinate in batch.coordinate_entries() {
            for row in &coordinate.rows {
                checkpoint(cx)?;
                if let DeltaRow::LabelMembership {
                    vid,
                    label: changed,
                    after: true,
                    ..
                } = row
                    && families.contains(changed)
                    && births.get(vid).is_none_or(|(kind, _)| kind != changed)
                {
                    return Ok(Err(drift(
                        "a later label cannot manufacture bank decision or claim history",
                    )));
                }
                let touched = match row {
                    DeltaRow::Property {
                        elem: ElementId::Vertex(vid),
                        ..
                    }
                    | DeltaRow::LabelMembership { vid, .. }
                    | DeltaRow::DeleteVertex { vid, .. } => Some(vid),
                    _ => None,
                };
                if let Some(vid) = touched
                    && births.get(vid).is_some_and(|(_, born)| *born < seq)
                {
                    return Ok(Err(drift(format!(
                        "bank decision or claim {:032x} was modified at {}; restoration cannot erase that mutation",
                        vid.0, seq.0,
                    ))));
                }
            }
        }
        through = seq.0;
    }
    if through != at.0 {
        return Ok(Err(drift(
            "bank decision history ends before the selected native prefix",
        )));
    }
    for row in db.vertices_at(at)? {
        checkpoint(cx)?;
        if row.labels.iter().any(|kind| families.contains(kind)) && !births.contains_key(&row.vid) {
            return Ok(Err(drift(
                "a visible bank decision or claim lacks a native birth",
            )));
        }
    }
    for (&vid, &(kind, born)) in &births {
        checkpoint(cx)?;
        let Some(row) = db.vertex_at(vid, at)?.map(|row| row.seen_at(at)) else {
            return Ok(Err(drift(
                "an immutable bank birth is absent; deletion cannot release or revive a claim",
            )));
        };
        let Some(original) = db.vertex_at(vid, born)?.map(|row| row.seen_at(born)) else {
            return Ok(Err(drift(
                "a bank decision creating snapshot is unavailable",
            )));
        };
        if row.created_at != born
            || row.retired_at.is_some()
            || row.labels.as_slice() != [kind]
            || original.created_at != born
            || original.birth_ordinal != row.birth_ordinal
            || original.labels != row.labels
            || original.props != row.props
        {
            return Ok(Err(drift(
                "a bank decision or claim differs from its immutable creating row",
            )));
        }
        if let Err(refusal) = verify::native_birth(db, cx, &row, kind)? {
            return Ok(Err(refusal));
        }
    }
    Ok(Ok(births))
}

pub(super) fn history_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    at: CommitSeq,
) -> Outcome<BankMatchHistory> {
    checkpoint(cx)?;
    if at > db.frontier()? {
        return Ok(Err(invalid(
            "bank decision history cannot select a future native prefix",
        )));
    }
    let query = cx.query();
    query.with_restriction(|| {
        let births = match births(db, cx, at)? {
            Ok(births) => births,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let mut confirmations = Vec::new();
        let mut unmatches = Vec::new();
        let mut claims = BTreeSet::new();
        for (&vid, &(kind, _)) in &births {
            checkpoint(cx)?;
            let Some(row) = db.vertex_at(vid, at)?.map(|row| row.seen_at(at)) else {
                return Ok(Err(drift("an authenticated bank birth disappeared")));
            };
            if kind == label::BANK_MATCH {
                match verify::read_metadata_record(db, cx, book, &row, at)? {
                    Ok(recorded) => confirmations.push(recorded),
                    Err(refusal) => return Ok(Err(refusal)),
                }
            } else if kind == label::BANK_UNMATCH {
                match read_unmatch(&row, book.book_id)? {
                    Ok(recorded) => unmatches.push(recorded),
                    Err(refusal) => return Ok(Err(refusal)),
                }
            } else {
                claims.insert(vid);
            }
        }
        confirmations.sort_by_key(|recorded| (recorded.recorded_at, recorded.match_vid));
        unmatches.sort_by_key(|recorded| (recorded.recorded_at, recorded.unmatch_vid));
        let expected_claims: BTreeSet<_> = confirmations
            .iter()
            .map(|recorded| recorded.confirmation.leg_claim_vid())
            .collect();
        if claims != expected_claims || expected_claims.len() != confirmations.len() {
            return Ok(Err(drift(
                "the immutable bank claim population does not match its confirmations",
            )));
        }
        let active = match fold(db, cx, book, at, &confirmations, &unmatches)? {
            Ok(active) => active,
            Err(refusal) => return Ok(Err(refusal)),
        };
        Ok(Ok(BankMatchHistory {
            known_at: at,
            confirmations,
            unmatches,
            active,
        }))
    })
}

fn preceding(
    latest: Option<&BankMatchRecorded>,
    released: &BTreeMap<VId, &BankUnmatchRecorded>,
    leg: bool,
) -> Result<(u64, Option<BankDecisionRef>, CommitSeq), Refusal> {
    let Some(latest) = latest else {
        return Ok((0, None, CommitSeq(0)));
    };
    let Some(release) = released.get(&latest.match_vid) else {
        return Err(drift(
            "one bank line or cash leg has competing active confirmation generations",
        ));
    };
    let generation = if leg {
        latest.confirmation.leg_generation()
    } else {
        latest.confirmation.line_generation()
    }
    .checked_add(1)
    .ok_or_else(|| drift("bank confirmation generation overflow"))?;
    Ok((
        generation,
        Some(BankDecisionRef {
            vid: release.unmatch_vid,
            digest: release.unmatch_digest,
        }),
        release.recorded_at,
    ))
}

fn fold<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    at: CommitSeq,
    confirmations: &[BankMatchRecorded],
    unmatches: &[BankUnmatchRecorded],
) -> Outcome<Vec<BankMatchRecorded>> {
    let by_id: BTreeMap<_, _> = confirmations
        .iter()
        .map(|recorded| (recorded.match_vid, recorded))
        .collect();
    let mut events: Vec<_> = confirmations
        .iter()
        .enumerate()
        .map(|(index, recorded)| (recorded.recorded_at, recorded.match_vid, false, index))
        .collect();
    events.extend(
        unmatches
            .iter()
            .enumerate()
            .map(|(index, recorded)| (recorded.recorded_at, recorded.unmatch_vid, true, index)),
    );
    events.sort_by_key(|event| (event.0, event.1));
    let mut lines = BTreeMap::new();
    let mut cash = BTreeMap::new();
    let mut released = BTreeMap::new();
    let mut active = BTreeSet::new();
    for (_, _, is_unmatch, index) in events {
        checkpoint(cx)?;
        if is_unmatch {
            let correction = &unmatches[index];
            let target = correction.unmatch.target;
            let Some(prior) = by_id.get(&target.vid).copied() else {
                return Ok(Err(drift(
                    "an Unmatch does not target a native confirmation",
                )));
            };
            if target.digest != prior.match_digest
                || prior.recorded_at >= correction.recorded_at
                || !active.remove(&target.vid)
                || released.insert(target.vid, correction).is_some()
            {
                return Ok(Err(drift(
                    "an Unmatch repeats or differs from an active earlier confirmation",
                )));
            }
            for (kind, destination) in [
                (relation::SUPERSEDES, target.vid),
                (relation::CITES, prior.confirmation.leg_claim_vid()),
                (relation::IN_BOOK, book_root()),
            ] {
                if let Err(refusal) = verify::edge(
                    db,
                    cx,
                    kind,
                    correction.unmatch_vid,
                    destination,
                    &[],
                    correction.recorded_at,
                    at,
                    edge_id(kind, correction.unmatch_vid, destination),
                )? {
                    return Ok(Err(refusal));
                }
            }
        } else {
            let recorded = &confirmations[index];
            let value = &recorded.confirmation;
            let line = (value.statement_oid, value.line_ordinal);
            let leg = (value.entry_ref.vid, value.leg_ordinal);
            let (line_generation, previous_line_unmatch, line_at) =
                match preceding(lines.get(&line).copied(), &released, false) {
                    Ok(value) => value,
                    Err(refusal) => return Ok(Err(refusal)),
                };
            let (leg_generation, previous_leg_unmatch, leg_at) =
                match preceding(cash.get(&leg).copied(), &released, true) {
                    Ok(value) => value,
                    Err(refusal) => return Ok(Err(refusal)),
                };
            let expected = BankMatchLineage {
                line_generation,
                leg_generation,
                previous_line_unmatch,
                previous_leg_unmatch,
            };
            let actual = value.lineage.clone().unwrap_or(BankMatchLineage {
                line_generation: 0,
                leg_generation: 0,
                previous_line_unmatch: None,
                previous_leg_unmatch: None,
            });
            if actual != expected
                || value.source_known_at < line_at
                || value.source_known_at < leg_at
                || value.book_id != book.book_id
            {
                return Ok(Err(drift(
                    "bank confirmation lineage skips a generation or reviews a prefix before its explicit releases",
                )));
            }
            lines.insert(line, recorded);
            cash.insert(leg, recorded);
            active.insert(recorded.match_vid);
        }
    }
    Ok(Ok(confirmations
        .iter()
        .filter(|recorded| active.contains(&recorded.match_vid))
        .cloned()
        .collect()))
}

/// Compute the next independent resources from complete authenticated history.
/// An exact retry is looked up before this occupancy/fresh-review check.
pub(super) fn next_lineage(
    history: &BankMatchHistory,
    statement: Oid,
    line_ordinal: u32,
    entry: VId,
    leg_ordinal: u16,
    source_known_at: CommitSeq,
) -> Result<BankMatchLineage, Refusal> {
    if history.active.iter().any(|recorded| {
        let value = &recorded.confirmation;
        (value.statement_oid == statement && value.line_ordinal == line_ordinal)
            || (value.entry_ref.vid == entry && value.leg_ordinal == leg_ordinal)
    }) {
        return Err(conflict(
            "the bank line or exact cash leg already has an active confirmation",
        ));
    }
    let released: BTreeMap<_, _> = history
        .unmatches
        .iter()
        .map(|recorded| (recorded.unmatch.target.vid, recorded))
        .collect();
    let line = history.confirmations.iter().rev().find(|recorded| {
        recorded.confirmation.statement_oid == statement
            && recorded.confirmation.line_ordinal == line_ordinal
    });
    let leg = history.confirmations.iter().rev().find(|recorded| {
        recorded.confirmation.entry_ref.vid == entry
            && recorded.confirmation.leg_ordinal == leg_ordinal
    });
    let (line_generation, previous_line_unmatch, line_at) = preceding(line, &released, false)?;
    let (leg_generation, previous_leg_unmatch, leg_at) = preceding(leg, &released, true)?;
    if source_known_at < line_at || source_known_at < leg_at {
        return Err(invalid(
            "a new confirmation must review a source prefix that includes every release permitting reuse",
        ));
    }
    Ok(BankMatchLineage {
        line_generation,
        leg_generation,
        previous_line_unmatch,
        previous_leg_unmatch,
    })
}

pub(super) fn witness_lineage<V: Vfs + Clone>(
    db: &Database<V>,
    txn: &WriteTxn,
    lineage: &BankMatchLineage,
) -> Outcome<()> {
    let references: BTreeSet<_> = [lineage.previous_line_unmatch, lineage.previous_leg_unmatch]
        .into_iter()
        .flatten()
        .collect();
    for reference in references {
        let Some(row) = txn.vertex(db, reference.vid)? else {
            return Ok(Err(drift(
                "a required bank release disappeared before reconfirmation",
            )));
        };
        let value = match BankUnmatch::decode(verify::payload(&row)?) {
            Ok(value) => value,
            Err(error) => return Ok(Err(drift(error.to_string()))),
        };
        if value.vid() != reference.vid
            || value.digest()? != reference.digest
            || row.props != unmatch_props(&value)?
            || row.labels.as_slice() != [label::BANK_UNMATCH]
        {
            return Ok(Err(drift(
                "a required bank release changed before reconfirmation",
            )));
        }
    }
    Ok(Ok(()))
}

/// Append one explicit correction of an active confirmation. Human Read and
/// Reconcile authority is current and witnessed; original source bytes are not
/// needed to correct a recorded decision. Same-target retries return the first
/// actual correcting principal and publication, even after a later rematch.
pub async fn unmatch_bank_match<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    request: BankUnmatchRequest,
) -> Outcome<BankUnmatchRecorded> {
    if let Err(refusal) = admit_bank_match_history(db, book, capability, None)? {
        return Ok(Err(refusal));
    }
    if capability.profile() != Profile::Human {
        return Ok(Err(crate::policy::refusal(
            &fa_policy::Denial::ApproverProfile {
                rule: "bank_match_corrector".into(),
                approver: capability.holder(),
                profile: capability.profile(),
                allowed: vec!["Human".into()],
            },
        )));
    }
    checkpoint(cx)?;
    if let Err(refusal) = crate::scratch::ensure_history(db, cx).await? {
        return Ok(Err(refusal));
    }
    if let Err(refusal) = admit_bank_match_history(db, book, capability, None)? {
        return Ok(Err(refusal));
    }
    let head = db.frontier()?;
    let state = match history_at(db, cx, book, head)? {
        Ok(state) => state,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let vid = unmatch_vid(book.book_id, request.target);
    if let Some(previous) = state
        .unmatches
        .iter()
        .find(|recorded| recorded.unmatch_vid == vid)
    {
        let mut previous = previous.clone();
        previous.already_recorded = true;
        return Ok(Ok(previous));
    }
    let Some(target) = state.active.iter().find(|recorded| {
        recorded.match_vid == request.target.vid && recorded.match_digest == request.target.digest
    }) else {
        return Ok(Err(invalid(
            "Unmatch requires the exact digest of an active native confirmation",
        )));
    };
    let mut txn = db.begin(&cx.txn())?;
    if let Err(refusal) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let epoch = crate::policy::epoch_witness(&txn, db)?;
    for source in [
        target.match_vid,
        target.confirmation.leg_claim_vid(),
        book_root(),
    ] {
        if txn.vertex(db, source)?.is_none() {
            txn.abort();
            return Ok(Err(drift(
                "an Unmatch target or original claim disappeared before publication",
            )));
        }
    }
    if txn.vertex(db, vid)?.is_some() {
        txn.abort();
        return Ok(Err(drift("an unexplained Unmatch identity already exists")));
    }
    let value = BankUnmatch {
        book_id: book.book_id,
        target: request.target,
        unmatched_by: capability.holder(),
        unmatching_profile: capability.profile(),
        capability_commitment: capability.commitment().map_err(corrupt)?,
        security_policy_epoch: epoch,
    };
    // This fixed canonical record has no decision-card or source-text growth.
    if BankUnmatch::decode(&value.canonical_bytes()?)? != value {
        return Err(corrupt("the new Unmatch does not round-trip"));
    }
    let mut correction = WriteBatch::new(relation::SUPERSEDES);
    correction.create_vertex(vid, vec![label::BANK_UNMATCH], unmatch_props(&value)?);
    correction.add_edge(
        edge_id(relation::SUPERSEDES, vid, target.match_vid),
        vid,
        target.match_vid,
        vec![],
    );
    let claim = target.confirmation.leg_claim_vid();
    let mut sources = WriteBatch::new(relation::CITES);
    sources.add_edge(edge_id(relation::CITES, vid, claim), vid, claim, vec![]);
    let mut membership = WriteBatch::new(relation::IN_BOOK);
    membership.add_edge(
        edge_id(relation::IN_BOOK, vid, book_root()),
        vid,
        book_root(),
        vec![],
    );
    txn.write_ordered(db, vec![correction, sources, membership])?;
    match txn.commit(db, &cx.commit()).await {
        Ok(recorded_at) => Ok(Ok(value.recorded(recorded_at, false)?)),
        Err(WriteTxnError::Write(
            fgdb::WriteError::FirstCommitterWins { .. }
            | fgdb::WriteError::AlreadyLive { .. }
            | fgdb::WriteError::IdentitySpent { .. }
            | fgdb::WriteError::CompareAndSetMismatch(_),
        )) => Ok(Err(conflict(
            "a bank correction publication witness changed; retry the exact target under current authority",
        ))),
        Err(error) => Err(error.into()),
    }
}
