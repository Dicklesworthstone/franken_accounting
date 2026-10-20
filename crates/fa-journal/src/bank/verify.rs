use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    AccountType, ControlPayload, Entry, EntryClass, EntryRef, Id128, Oid, entry_mirrors,
    leg_mirrors,
};
use fa_money::{Amount, Side, UnitKind};
use fa_policy::{BenefitInterval, DecisionCandidate, DecisionFeature};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteTxn};
use fgdb_delta_types::{DeltaRow, LabelId, PropertyKeyId, RelationId};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, EId, VId};

use super::wire::{
    BankLine, claim_props, match_edge_props, match_props, proposal_digest, validate_card,
};
use super::{
    BankMatchConfirmation, BankMatchHistory, BankMatchRecorded, BankMatchRequest, checkpoint,
    drift, invalid,
};
use crate::evidence::{Document, DocumentRecord, Storage, doc_commit, document_vid, verify_row};
use crate::genesis::{BookContext, UnitPolicy};
use crate::import::bank::{BANK_LINE_MIME, BANK_MANIFEST_MIME};
use crate::import::{BankImportManifest, BankImportWitness, RunReceipt};
use crate::refusal::{KernelError, Outcome};
use crate::rows::{AccountRow, book_root, edge_id, leg_vid, prop};

fn policy() -> Result<EvidencePolicy, KernelError> {
    EvidencePolicy::embedded().map_err(|error| KernelError::Corrupt(error.to_string()))
}

fn kind(policy: &EvidencePolicy, name: &str) -> Result<u8, KernelError> {
    policy
        .kind_by_name(name)
        .map(|kind| kind.tag)
        .ok_or_else(|| {
            KernelError::Corrupt(format!("bank confirmation lacks document kind {name}"))
        })
}

pub(super) fn payload(row: &VertexRow) -> Result<&[u8], KernelError> {
    match prop(row, property::FA_PAYLOAD) {
        Some(CanonicalScalar::Bytes(bytes)) => Ok(bytes.as_slice()),
        _ => Err(KernelError::Corrupt(
            "bank confirmation source lacks its canonical payload".into(),
        )),
    }
}

/// A content version's `created_at` is not itself a birth proof. Bind it to
/// the actual CreateVertex record, including labels, ordinal and properties.
pub(super) fn native_birth<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    row: &VertexRow,
    expected_label: LabelId,
) -> Outcome<()> {
    let Some(before) = row.created_at.0.checked_sub(1) else {
        return Ok(Err(drift("bank match source predates native genesis")));
    };
    if row.retired_at.is_some() || !row.labels.contains(&expected_label) {
        return Ok(Err(drift(
            "bank match source has been retired or relabelled",
        )));
    }
    let Some(batch) = db.delta_since(CommitSeq(before))?.next() else {
        return Ok(Err(drift(
            "bank match source has no retained creating commit",
        )));
    };
    if batch.commit_seq() != row.created_at {
        return Ok(Err(drift(
            "bank match source creation history is incomplete",
        )));
    }
    let mut births = 0_u8;
    for coordinate in batch.coordinate_entries() {
        for delta in &coordinate.rows {
            checkpoint(cx)?;
            if let DeltaRow::CreateVertex {
                vid,
                birth_ordinal,
                labels,
                props,
                ..
            } = delta
                && *vid == row.vid
            {
                if *birth_ordinal != row.birth_ordinal
                    || labels != &row.labels
                    || props != &row.props
                {
                    return Ok(Err(drift(
                        "bank match source differs from its original native birth",
                    )));
                }
                births = births.saturating_add(1);
            }
        }
    }
    if births != 1 {
        return Ok(Err(drift(
            "bank match source version is not an original native birth",
        )));
    }
    Ok(Ok(()))
}

pub(super) fn was_created<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    vid: VId,
    at: CommitSeq,
) -> Result<bool, KernelError> {
    for batch in db.delta_since(CommitSeq(0))? {
        if batch.commit_seq() > at {
            break;
        }
        for coordinate in batch.coordinate_entries() {
            for row in &coordinate.rows {
                checkpoint(cx)?;
                if matches!(row, DeltaRow::CreateVertex { vid: created, .. } if *created == vid) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

pub(super) struct SourceEntry {
    pub entry: Entry,
    pub row: VertexRow,
}

pub(super) fn source_entry<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    reference: EntryRef,
    at: CommitSeq,
) -> Outcome<SourceEntry> {
    let Some(row) = db.vertex_at(reference.vid, at)? else {
        return Ok(Err(invalid(
            "the selected cash Entry did not exist at the proposal's source sequence",
        )));
    };
    if let Err(refusal) = native_birth(db, cx, &row, label::ENTRY)? {
        return Ok(Err(refusal));
    }
    let entry = match Entry::decode(payload(&row)?) {
        Ok(entry) => entry,
        Err(error) => return Ok(Err(drift(format!("cash Entry no longer decodes: {error}")))),
    };
    if entry.proposal.book_id != book.book_id
        || entry.proposal.branch_id != Id128::TRUNK
        || entry.entry_ref(row.vid) != reference
        || entry.proposal.class == EntryClass::PENDING
        || entry_mirrors(&entry)?
            .iter()
            .any(|(key, value)| prop(&row, *key) != Some(value))
    {
        return Ok(Err(invalid(
            "the selected reference is not this book's unchanged posted cash Entry",
        )));
    }
    if !crate::migration::visible_at(db, &entry, at, &mut BTreeMap::new())? {
        return Ok(Err(invalid(
            "an unpublished or excluded migration leg cannot be bank-confirmed",
        )));
    }
    Ok(Ok(SourceEntry { entry, row }))
}

pub(super) fn current_entry<V: Vfs + Clone>(
    db: &Database<V>,
    txn: &WriteTxn,
    book: &BookContext,
    source: &SourceEntry,
    request: &BankMatchRequest,
) -> Outcome<()> {
    let Some(current) = txn.vertex(db, source.row.vid)? else {
        return Ok(Err(drift(
            "the selected cash Entry disappeared before confirmation",
        )));
    };
    if current != source.row {
        return Ok(Err(drift(
            "the selected cash Entry changed after the proposal's source coordinate",
        )));
    }
    if let Err(refusal) = crate::migration::witness_open_item(
        txn,
        db,
        source.row.vid,
        &source.entry,
        usize::from(request.leg_ordinal),
    )? {
        return Ok(Err(refusal));
    }
    let Some(leg) = source
        .entry
        .proposal
        .legs
        .get(usize::from(request.leg_ordinal))
    else {
        return Ok(Err(invalid(
            "the selected actual cash-leg ordinal does not exist",
        )));
    };
    let Some(row) = txn.vertex(db, leg_vid(source.row.vid, request.leg_ordinal))? else {
        return Ok(Err(drift(
            "the selected native cash-leg projection is absent",
        )));
    };
    if !row.labels.contains(&label::LEG)
        || leg_mirrors(
            leg,
            request.leg_ordinal,
            source.entry.proposal.effective_date,
            &book.units,
        )?
        .iter()
        .any(|(key, value)| prop(&row, *key) != Some(value))
    {
        return Ok(Err(drift(
            "the selected native cash leg differs from its immutable Entry",
        )));
    }
    let Some(account_row) = txn.vertex(db, request.import.manifest().account)? else {
        return Ok(Err(invalid(
            "the bank manifest's cash account does not exist",
        )));
    };
    if !account_row.labels.contains(&label::ACCOUNT) {
        return Ok(Err(invalid("the bank mapping no longer names an Account")));
    }
    let account = AccountRow::decode(&account_row)?;
    if !account.is_leaf
        || account.normal_balance != 0
        || account.account_type != AccountType::ASSET.0
        || !book
            .units
            .get(leg.amount.unit)
            .is_some_and(|unit| matches!(unit.kind, UnitKind::Currency { .. }))
        || matches!(account.unit_policy, UnitPolicy::Single(unit) if unit != leg.amount.unit)
    {
        return Ok(Err(invalid(
            "bank confirmation requires a debit-normal Asset leaf in the statement's exact currency",
        )));
    }
    Ok(Ok(()))
}

pub(super) fn exact_cash_leg(
    book: &BookContext,
    source: &SourceEntry,
    request: &BankMatchRequest,
    line: &BankLine,
) -> Outcome<()> {
    let Some(leg) = source
        .entry
        .proposal
        .legs
        .get(usize::from(request.leg_ordinal))
    else {
        return Ok(Err(invalid(
            "the selected actual cash-leg ordinal does not exist",
        )));
    };
    let days = (i64::from(source.entry.proposal.effective_date.0) - i64::from(line.booking_date.0))
        .unsigned_abs();
    let reference = match &leg.memo {
        Some(memo) => memo
            .open(&book.seal_key, fa_model::limits::MAX_MEMO_BYTES)
            .map_err(|error| {
                KernelError::Corrupt(format!(
                    "cannot open the retained cash-leg reference: {error}"
                ))
            })?,
        None => String::new(),
    };
    let bank_reference = line.reference.trim().to_ascii_lowercase();
    if leg.account_ref != request.import.manifest().account
        || leg.amount != line.amount
        || leg.amount.mantissa <= 0
        || leg.side == line.side
        || days > u64::from(request.date_window_days)
        || (!bank_reference.is_empty() && bank_reference != reference.trim().to_ascii_lowercase())
    {
        return Ok(Err(invalid(
            "the selected retained bank line and cash leg fail the exact amount, currency, direction, date-window or reference law",
        )));
    }
    Ok(Ok(()))
}

struct Candidate {
    entry_ref: EntryRef,
    ordinal: u16,
    effective: DateDay,
    amount: Amount,
    side: Side,
    reference: String,
}

fn eligible(line: &BankLine, candidate: &Candidate, window: u32) -> bool {
    let reference = line.reference.trim().to_ascii_lowercase();
    line.amount == candidate.amount
        && line.side != candidate.side
        && (i64::from(line.booking_date.0) - i64::from(candidate.effective.0)).unsigned_abs()
            <= u64::from(window)
        && (reference.is_empty() || reference == candidate.reference.trim().to_ascii_lowercase())
}

/// Reconstruct the exact cash-candidate coordinate and bidirectional
/// uniqueness independently of the caller's advisory DecisionCard. The
/// complete native Entry history prevents a deleted candidate from making an
/// originally ambiguous proposal appear unique.
pub(super) fn unique_selection<V: Vfs + Clone>(
    db: &Database<V>,
    txn: &WriteTxn,
    cx: &PurposeContexts,
    book: &BookContext,
    request: &BankMatchRequest,
    selected_line: &BankLine,
    availability: &BankMatchHistory,
) -> Outcome<()> {
    let manifest = request.import.manifest();
    if request.lines.len() != manifest.line_oids.len()
        || request.lines.len() > crate::import::bank::MAX_BANK_LINES
    {
        return Ok(Err(invalid(
            "confirmation requires every committed bank line in original manifest order",
        )));
    }
    let mut lines = Vec::with_capacity(request.lines.len());
    for (index, document) in request.lines.iter().enumerate() {
        checkpoint(cx)?;
        if manifest.line_oids.get(index) != Some(&document.oid()) {
            return Ok(Err(invalid(
                "the supplied bank lines omit, reorder or replace the retained manifest closure",
            )));
        }
        if let Err(refusal) = line_document(db, txn, book, document)? {
            return Ok(Err(refusal));
        }
        let line = match BankLine::decode(&document.bytes) {
            Ok(line) => line,
            Err(error) => return Ok(Err(invalid(error.to_string()))),
        };
        if usize::try_from(line.line_ordinal).ok() != index.checked_add(1)
            || line.statement_oid != manifest.statement_oid
            || line.statement_seq != manifest.sequence_number
            || line.amount.unit != manifest.unit
        {
            return Ok(Err(invalid(
                "the committed bank lines have incompatible source, unit or ordinal coordinates",
            )));
        }
        lines.push(line);
    }
    let Some(first) = lines.iter().map(|line| line.booking_date.0).min() else {
        return Ok(Err(invalid(
            "an empty bank statement has no confirmable line",
        )));
    };
    let window = i32::try_from(request.date_window_days)
        .map_err(|_| KernelError::Corrupt("bank date window was not bounded".into()))?;
    let from = DateDay(first.saturating_sub(window));
    let through = DateDay(manifest.statement_date.0.saturating_add(window));
    if let Err(error) =
        crate::entry_history::verify_entry_history(db, cx, book, Some(request.source_known_at))
    {
        return Ok(Err(drift(format!(
            "bank candidate history cannot be verified: {error}"
        ))));
    }
    if let Err(refusal) = verify_active_entries(db, cx, book, availability)? {
        return Ok(Err(refusal));
    }
    let mut entries = db.vertices_at(request.source_known_at)?;
    entries.retain(|row| row.labels.contains(&label::ENTRY));
    entries.sort_by_key(|row| (row.created_at, row.vid.0));
    let mut candidates = Vec::new();
    let mut migrations = BTreeMap::new();
    for row in entries {
        checkpoint(cx)?;
        let entry = Entry::decode(payload(&row)?)?;
        let day = entry.proposal.effective_date;
        if entry.proposal.class == EntryClass::PENDING
            || day < from
            || day > through
            || !crate::migration::visible_at(db, &entry, request.source_known_at, &mut migrations)?
        {
            continue;
        }
        for (ordinal, leg) in entry.proposal.legs.iter().enumerate() {
            checkpoint(cx)?;
            if leg.account_ref != manifest.account || leg.amount.unit != manifest.unit {
                continue;
            }
            let reference = match &leg.memo {
                Some(memo) => memo
                    .open(&book.seal_key, fa_model::limits::MAX_MEMO_BYTES)
                    .map_err(|error| {
                        KernelError::Corrupt(format!(
                            "cannot open a retained bank candidate reference: {error}"
                        ))
                    })?,
                None => String::new(),
            };
            candidates.push(Candidate {
                entry_ref: entry.entry_ref(row.vid),
                ordinal: u16::try_from(ordinal).map_err(|_| {
                    KernelError::Corrupt("native cash leg ordinal exceeds Entry schema".into())
                })?,
                effective: day,
                amount: leg.amount,
                side: leg.side,
                reference,
            });
        }
    }
    // Only already recorded active claims at the reviewed prefix remove a
    // resource. Earlier greedy proposals in this report cannot create
    // uniqueness; the complete candidate vector and ordinals stay unchanged.
    let claimed_cash: BTreeSet<_> = availability
        .active
        .iter()
        .map(|recorded| {
            (
                recorded.confirmation.entry_ref.vid,
                recorded.confirmation.leg_ordinal,
            )
        })
        .collect();
    let claimed_lines: BTreeSet<_> = availability
        .active
        .iter()
        .map(|recorded| {
            (
                recorded.confirmation.statement_oid,
                recorded.confirmation.line_ordinal,
            )
        })
        .collect();
    // Fresh reports retain the complete original coordinate. Previously
    // published available-index proposals remain admissible only when the
    // pinned index also binds their explicit immutable Entry and actual leg.
    let binds = |candidate: &&Candidate| {
        candidate.entry_ref == request.entry_ref && candidate.ordinal == request.leg_ordinal
    };
    let Some(selected) = usize::try_from(request.candidate_ordinal)
        .ok()
        .and_then(|ordinal| candidates.get(ordinal))
        .filter(binds)
        .or_else(|| {
            usize::try_from(request.candidate_ordinal)
                .ok()
                .and_then(|ordinal| {
                    candidates
                        .iter()
                        .filter(|candidate| {
                            !claimed_cash.contains(&(candidate.entry_ref.vid, candidate.ordinal))
                        })
                        .nth(ordinal)
                        .filter(binds)
                })
        })
    else {
        return Ok(Err(invalid(
            "neither the original nor saved available candidate index binds this exact Entry and cash leg",
        )));
    };
    if claimed_cash.contains(&(selected.entry_ref.vid, selected.ordinal))
        || claimed_lines.contains(&(selected_line.statement_oid, selected_line.line_ordinal))
    {
        return Ok(Err(invalid(
            "the selected line or cash leg was already active at the reviewed prefix",
        )));
    }
    let candidate_count = candidates
        .iter()
        .filter(|candidate| {
            !claimed_cash.contains(&(candidate.entry_ref.vid, candidate.ordinal))
                && eligible(selected_line, candidate, request.date_window_days)
        })
        .count();
    let line_count = lines
        .iter()
        .filter(|line| {
            !claimed_lines.contains(&(line.statement_oid, line.line_ordinal))
                && eligible(line, selected, request.date_window_days)
        })
        .count();
    if candidate_count != 1 || line_count != 1 {
        return Ok(Err(invalid(
            "the complete retained proposal is ambiguous: exact confirmation requires one eligible cash leg and one eligible bank line before candidate consumption",
        )));
    }
    let days =
        (i64::from(selected_line.booking_date.0) - i64::from(selected.effective.0)).unsigned_abs();
    let reference = selected_line.reference.trim().to_ascii_lowercase();
    let exact_reference =
        !reference.is_empty() && reference == selected.reference.trim().to_ascii_lowercase();
    let analytic_score = 1_000 - i128::from(days) * 10 + if exact_reference { 500 } else { 0 };
    let ordinal = request.candidate_ordinal;
    let expected = fa_policy::decide_bank_match(
        None,
        [0; 32],
        selected_line.oid.0,
        vec![DecisionCandidate {
            action: "match_entry_ordinal".into(),
            parameter: i128::from(ordinal),
            analytic_score: (analytic_score
                .saturating_mul(1_000_000)
                .saturating_sub(i128::from(ordinal)))
            .max(1),
        }],
        vec![
            DecisionFeature {
                name: format!("cand.{ordinal}.date_delta_days"),
                value: i128::from(days),
                advisory: false,
            },
            DecisionFeature {
                name: format!("cand.{ordinal}.ref_exact"),
                value: i128::from(u8::from(exact_reference)),
                advisory: false,
            },
            DecisionFeature {
                name: format!("cand.{ordinal}.cp_exact"),
                value: 0,
                advisory: false,
            },
        ],
        BenefitInterval {
            lower_bps: 0,
            upper_bps: 2_000,
        },
    );
    if request.decision_card != expected {
        return Ok(Err(invalid(
            "the supplied DecisionCard differs from the native replay of the unique exact bank proposal",
        )));
    }
    Ok(Ok(()))
}

pub(super) fn line_document<V: Vfs + Clone>(
    db: &Database<V>,
    txn: &WriteTxn,
    book: &BookContext,
    document: &Document,
) -> Outcome<()> {
    let policy = policy()?;
    let Some(row) = txn.vertex(db, document_vid(&document.oid()))? else {
        return Ok(Err(drift(
            "the selected retained BankLine document disappeared",
        )));
    };
    let record = match verify_row(&row, &policy) {
        Ok(record) => record,
        Err(error) => return Ok(Err(drift(error))),
    };
    if record.book_id != book.book_id
        || record.kind != kind(&policy, "Other")?
        || record.mime != BANK_LINE_MIME
        || document.book_id != book.book_id
        || document.kind != record.kind
        || document.mime != record.mime
        || record.with_bytes(document.bytes.clone()).is_none()
    {
        return Ok(Err(drift(
            "the supplied bank line is not the complete committed document bytes",
        )));
    }
    Ok(Ok(()))
}

pub(super) fn import_birth<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    witness: &BankImportWitness,
) -> Outcome<()> {
    let Some(row) = db.vertex(witness.receipt().run)? else {
        return Ok(Err(drift("the retained bank ImportRun disappeared")));
    };
    if row.created_at != witness.receipt().recorded_at {
        return Ok(Err(drift(
            "the bank ImportRun has a different publication coordinate",
        )));
    }
    if let Err(refusal) = native_birth(db, cx, &row, label::ENTRY)? {
        return Ok(Err(refusal));
    }
    let entry = Entry::decode(payload(&row)?)?;
    if entry.proposal.book_id != book.book_id || entry.proposal.branch_id != Id128::TRUNK {
        return Ok(Err(drift(
            "the bank ImportRun belongs to another book or branch",
        )));
    }
    Ok(Ok(()))
}

fn document_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    oid: Oid,
    at: CommitSeq,
    policy: &EvidencePolicy,
) -> Outcome<DocumentRecord> {
    let Some(row) = db.vertex_at(document_vid(&oid), at)? else {
        return Ok(Err(drift(
            "a confirmed match's retained source document is absent",
        )));
    };
    let record = match verify_row(&row, policy) {
        Ok(record) => record,
        Err(error) => return Ok(Err(drift(error))),
    };
    if record.book_id != book.book_id || record.oid() != oid {
        return Ok(Err(drift(
            "a confirmed match's source document identity changed",
        )));
    }
    Ok(Ok(record))
}

fn sources<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    value: &BankMatchConfirmation,
    at: CommitSeq,
    manifest: &BankImportManifest,
) -> Outcome<()> {
    let policy = policy()?;
    let manifest_bytes = manifest
        .canonical_bytes()
        .map_err(|error| KernelError::Model(error.into()))?;
    if manifest.book_id != book.book_id
        || manifest.document_oid()? != value.manifest_oid
        || doc_commit(kind(&policy, "Workpaper")?, &manifest_bytes) != value.manifest_commit
        || manifest.account != value.account
        || manifest.statement_oid != value.statement_oid
        || manifest.statement_commit != value.statement_commit
        || value
            .line_ordinal
            .checked_sub(1)
            .and_then(|ordinal| usize::try_from(ordinal).ok())
            .and_then(|ordinal| manifest.line_oids.get(ordinal))
            != Some(&value.line_document_oid)
    {
        return Ok(Err(drift(
            "the confirmation differs from its retained bank import interpretation",
        )));
    }
    let mut byte_count = 0_u64;
    for oid in manifest.closure(value.manifest_oid) {
        checkpoint(cx)?;
        let record = match document_at(db, book, oid, at, &policy)? {
            Ok(record) => record,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let valid = if oid == value.manifest_oid {
            record.kind == kind(&policy, "Workpaper")?
                && record.mime == BANK_MANIFEST_MIME
                && record.doc_commit == value.manifest_commit
        } else if oid == value.statement_oid {
            record.kind == kind(&policy, "BankStatement")?
                && record.doc_commit == value.statement_commit
        } else {
            record.kind == kind(&policy, "Other")? && record.mime == BANK_LINE_MIME
        };
        if !valid {
            return Ok(Err(drift(
                "a confirmed match's bank source changed its kind, MIME or commitment",
            )));
        }
        byte_count = byte_count
            .checked_add(record.size)
            .ok_or_else(|| KernelError::Corrupt("bank import byte count overflow".into()))?;
        if oid == value.line_document_oid
            && let Storage::Inline(bytes) = &record.storage
        {
            let line = match BankLine::decode(bytes) {
                Ok(line) => line,
                Err(error) => return Ok(Err(drift(error.to_string()))),
            };
            if line.oid != value.bank_line_oid
                || line.line_ordinal != value.line_ordinal
                || line.statement_oid != value.statement_oid
                || line.statement_seq != manifest.sequence_number
                || line.amount.unit != manifest.unit
            {
                return Ok(Err(drift(
                    "the confirmed line differs from its committed source bytes",
                )));
            }
        }
    }
    let Some(row) = db.vertex_at(value.import_run, at)? else {
        return Ok(Err(drift(
            "the confirmed match's native ImportRun is absent",
        )));
    };
    if let Err(refusal) = native_birth(db, cx, &row, label::ENTRY)? {
        return Ok(Err(refusal));
    }
    let entry = Entry::decode(payload(&row)?)?;
    let Some(ControlPayload::ImportRun {
        source,
        document_count,
        byte_count: recorded_bytes,
        oids_root,
        receipt_hash,
    }) = &entry.proposal.control
    else {
        return Ok(Err(drift(
            "the confirmed match no longer cites an ImportRun",
        )));
    };
    if entry.proposal.book_id != book.book_id
        || entry.proposal.branch_id != Id128::TRUNK
        || entry.proposal.class != EntryClass::IMPORT_CONTROL
        || row.created_at != value.import_recorded_at
        || *receipt_hash != value.import_receipt_hash
        || byte_count != *recorded_bytes
        || entry_mirrors(&entry)?
            .iter()
            .any(|(key, value)| prop(&row, *key) != Some(value))
    {
        return Ok(Err(drift(
            "the confirmed match's ImportRun content or publication coordinate differs",
        )));
    }
    let receipt = RunReceipt {
        run: value.import_run,
        source: source.clone(),
        document_count: *document_count,
        byte_count,
        oids_root: *oids_root,
        receipt_hash: *receipt_hash,
        recorded_at: row.created_at,
    };
    if let Err(refusal) = crate::import::verify_receipt(
        &receipt,
        book.book_id,
        &manifest.closure(value.manifest_oid),
    ) {
        return Ok(Err(drift(refusal.message)));
    }
    let source = match confirmed_entry(db, cx, book, value, at)? {
        Ok(source) => source,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if source.entry.proposal.legs[usize::from(value.leg_ordinal)]
        .amount
        .unit
        != manifest.unit
    {
        return Ok(Err(drift(
            "the confirmed cash leg differs from its retained statement unit",
        )));
    }
    Ok(Ok(()))
}

/// The native occupied cash leg can be verified without fetching an external
/// manifest. The complete source closure is verified by read_record once its
/// caller supplies that original retained interpretation.
fn confirmed_entry<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    value: &BankMatchConfirmation,
    at: CommitSeq,
) -> Outcome<SourceEntry> {
    let source = match source_entry(db, cx, book, value.entry_ref, value.source_known_at)? {
        Ok(source) => source,
        Err(refusal) => return Ok(Err(drift(refusal.message))),
    };
    if db.vertex_at(value.entry_ref.vid, at)?.as_ref() != Some(&source.row) {
        return Ok(Err(drift(
            "the confirmed cash Entry changed or disappeared",
        )));
    }
    // An unchanged Migration Entry is part of the posting universe only
    // while its run remains visible at this selected prefix. The original
    // proposal's visibility, checked above, cannot stand in for that fact.
    match crate::migration::visible_at(db, &source.entry, at, &mut BTreeMap::new()) {
        Ok(true) => {}
        Ok(false) => {
            return Ok(Err(drift(
                "the confirmed migration cash leg is no longer visible at the selected prefix",
            )));
        }
        Err(KernelError::Corrupt(message)) => {
            return Ok(Err(drift(format!(
                "the confirmed migration cash leg's selected run projection cannot be verified: {message}"
            ))));
        }
        Err(error) => return Err(error),
    }
    let Some(leg) = source
        .entry
        .proposal
        .legs
        .get(usize::from(value.leg_ordinal))
    else {
        return Ok(Err(drift(
            "the confirmation names a nonexistent actual cash-leg ordinal",
        )));
    };
    let Some(row) = db.vertex_at(leg_vid(value.entry_ref.vid, value.leg_ordinal), at)? else {
        return Ok(Err(drift("the confirmed cash-leg projection is absent")));
    };
    if leg.account_ref != value.account
        || !row.labels.contains(&label::LEG)
        || leg_mirrors(
            leg,
            value.leg_ordinal,
            source.entry.proposal.effective_date,
            &book.units,
        )?
        .iter()
        .any(|(key, expected)| prop(&row, *key) != Some(expected))
    {
        return Ok(Err(drift(
            "the confirmed cash leg differs from its retained Entry",
        )));
    }
    Ok(Ok(source))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn edge<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    relation: RelationId,
    src: VId,
    dst: VId,
    expected_props: &[(PropertyKeyId, CanonicalScalar)],
    born: CommitSeq,
    at: CommitSeq,
    eid: EId,
) -> Outcome<()> {
    let Some(edge) = db.edge_at(eid, at)? else {
        return Ok(Err(drift(
            "a confirmed match's strong source edge is absent",
        )));
    };
    if edge.entry.src != src
        || edge.entry.dst != dst
        || edge.entry.relation != relation
        || edge.entry.created_at != born
        || edge.entry.retired_at.is_some_and(|retired| retired <= at)
        || edge.props != expected_props
    {
        return Ok(Err(drift(
            "a confirmed match's edge was changed or published separately",
        )));
    }
    let Some(before) = born.0.checked_sub(1) else {
        return Ok(Err(drift("a bank edge predates genesis")));
    };
    let Some(batch) = db.delta_since(CommitSeq(before))?.next() else {
        return Ok(Err(drift("bank edge creation history is absent")));
    };
    if batch.commit_seq() != born {
        return Ok(Err(drift("bank edge creation history is incomplete")));
    }
    for coordinate in batch.coordinate_entries() {
        for row in &coordinate.rows {
            checkpoint(cx)?;
            if let DeltaRow::CreateEdge {
                eid: id,
                src: from,
                dst: to,
                relation: kind,
                props,
                ..
            } = row
                && *id == eid
                && *from == src
                && *to == dst
                && *kind == relation
                && props == expected_props
            {
                return Ok(Ok(()));
            }
        }
    }
    Ok(Err(drift(
        "a bank edge has no native birth beside its confirmation",
    )))
}

/// Authenticate recorded native facts and their same-publication claim/edges.
/// This intentionally does not fetch or replay the original statement bytes.
pub(super) fn read_metadata_record<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    row: &VertexRow,
    at: CommitSeq,
) -> Outcome<BankMatchRecorded> {
    let visible = row.clone().seen_at(at);
    let row = &visible;
    if let Err(refusal) = native_birth(db, cx, row, label::BANK_MATCH)? {
        return Ok(Err(refusal));
    }
    let value = match BankMatchConfirmation::decode(payload(row)?) {
        Ok(value) => value,
        Err(error) => return Ok(Err(drift(error.to_string()))),
    };
    if value.book_id != book.book_id
        || value.vid() != row.vid
        || row.props != match_props(&value)?
        || value.source_known_at >= row.created_at
        || value.proposal_digest
            != proposal_digest(
                value.bank_line_oid,
                value.entry_ref,
                value.candidate_ordinal,
                value.proposer,
                &value.decision_card,
            )?
    {
        return Ok(Err(drift(
            "the confirmed match identity, proposal or coordinates disagree",
        )));
    }
    if let Err(error) = validate_card(&value.decision_card, value.bank_line_oid) {
        return Ok(Err(drift(error.to_string())));
    }
    let claim = value.leg_claim_vid();
    let Some(claim_row) = db.vertex_at(claim, at)?.map(|row| row.seen_at(at)) else {
        return Ok(Err(drift(
            "the confirmed match's unique cash-leg claim is absent",
        )));
    };
    if claim_row.props != claim_props(&value)? || claim_row.created_at != row.created_at {
        return Ok(Err(drift(
            "the confirmed match and cash-leg claim were changed or published separately",
        )));
    }
    if let Err(refusal) = native_birth(db, cx, &claim_row, label::BANK_MATCHED_LEG)? {
        return Ok(Err(refusal));
    }
    let mut edges = vec![(
        relation::MATCHES,
        document_vid(&value.line_document_oid),
        leg_vid(value.entry_ref.vid, value.leg_ordinal),
        match_edge_props(&value)?,
    )];
    for target in value.source_vertices() {
        edges.push((relation::CITES, value.vid(), target, vec![]));
    }
    edges.push((relation::CITES, claim, value.vid(), vec![]));
    edges.push((relation::IN_BOOK, claim, book_root(), vec![]));
    edges.push((relation::IN_BOOK, value.vid(), book_root(), vec![]));
    for (relation, src, dst, props) in edges {
        let eid = if relation == relation::MATCHES {
            value.match_edge_id()
        } else {
            edge_id(relation, src, dst)
        };
        if let Err(refusal) = edge(db, cx, relation, src, dst, &props, row.created_at, at, eid)? {
            return Ok(Err(refusal));
        }
    }
    Ok(Ok(value.recorded(row.created_at, false)?))
}

/// Existing full source verification remains separate from metadata history.
pub(super) fn read_record<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    row: &VertexRow,
    at: CommitSeq,
    manifest: Option<&BankImportManifest>,
) -> Outcome<BankMatchRecorded> {
    let recorded = match read_metadata_record(db, cx, book, row, at)? {
        Ok(recorded) => recorded,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let value = &recorded.confirmation;
    let policy = policy()?;
    let document = match document_at(db, book, value.manifest_oid, at, &policy)? {
        Ok(document) => document,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let decoded;
    let manifest = match manifest {
        Some(manifest) => manifest,
        None => {
            let Storage::Inline(bytes) = &document.storage else {
                return Ok(Err(invalid(
                    "reading this confirmation requires the fetched canonical external bank manifest; pass its retained interpretation to the native reader",
                )));
            };
            decoded = BankImportManifest::decode(bytes)
                .map_err(|error| KernelError::Model(error.into()))?;
            &decoded
        }
    };
    if manifest.document_oid()? != value.manifest_oid {
        return Ok(Err(super::conflict(format!(
            "this source line was confirmed under manifest {}; provide that original retained interpretation",
            crate::evidence::hex(&value.manifest_oid.0)
        ))));
    }
    let bytes = manifest
        .canonical_bytes()
        .map_err(|error| KernelError::Model(error.into()))?;
    if document.kind != kind(&policy, "Workpaper")?
        || document.mime != BANK_MANIFEST_MIME
        || document.doc_commit != value.manifest_commit
        || document.with_bytes(bytes).is_none()
    {
        return Ok(Err(drift(
            "the supplied bank manifest does not reproduce the original committed document",
        )));
    }
    if let Err(refusal) = sources(db, cx, book, value, at, manifest)? {
        return Ok(Err(refusal));
    }
    Ok(Ok(recorded))
}

/// Preserve the source-bound occupied-pair reader while explicit corrections
/// determine which immutable generations currently claim resources. Metadata
/// history is a separate scope and intentionally does not reopen source bytes.
pub(super) fn claims_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    at: CommitSeq,
) -> Outcome<Vec<BankMatchRecorded>> {
    let history = match super::lifecycle::history_at(db, cx, book, at)? {
        Ok(history) => history,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Err(refusal) = verify_active_entries(db, cx, book, &history)? {
        return Ok(Err(refusal));
    }
    Ok(Ok(history.active))
}

pub(super) fn verify_active_entries<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    history: &BankMatchHistory,
) -> Outcome<()> {
    for recorded in &history.active {
        checkpoint(cx)?;
        if let Err(refusal) =
            confirmed_entry(db, cx, book, &recorded.confirmation, history.known_at)?
        {
            return Ok(Err(refusal));
        }
    }
    Ok(Ok(()))
}
