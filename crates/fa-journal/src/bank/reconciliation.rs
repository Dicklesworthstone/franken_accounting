//! Exact statement closes in the native Attestation family. A close binds the
//! original prefix; later cash changes and match corrections are reported as
//! drift and never rewrite that historical fact. Outstanding-adjusted closing
//! is deliberately outside this exact profile.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    AccountType, ControlPayload, Entry, EntryClass, EntryRef, Id128, Oid, Writer, domain_digest,
};
use fa_money::{Side, UnitId, UnitKind};
use fa_policy::Capability;
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::DateDay;
use fgdb::{Database, WriteBatch, WriteTxn, WriteTxnError};
use fgdb_delta_types::{DeltaRow, ElementId, PropertyKeyId, RelationId};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, EId, MarkerRef, VId};

use super::{
    BankDecisionRef, BankMatchRecorded, admit_confirmation, checkpoint, lifecycle, verify,
};
use crate::attestation::{
    Attestation, AttestationClaim, CapabilityBinding, ReconciledClaim, Subject, reconciled_vid,
    verify_attestation_row,
};
use crate::evidence::{document_vid, verify_row};
use crate::genesis::{BookContext, UnitPolicy};
use crate::import::bank::{
    BANK_LINE_MIME, BANK_MANIFEST_MIME, BankStatementLink, bank_statement_link_vid,
};
use crate::import::{BankImportManifest, BankImportWitness, RunReceipt};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{AccountRow, book_root, edge_id, marker_at, scalar_bytes, scalar_text};

const CASH_FOLD_DOMAIN: &[u8] = b"fa:bank-reconciled-cash-fold:v1";

/// The complete native source witnesses are the only inputs to the close.
/// Monetary amounts, matches and cash contributions are evaluated internally.
#[derive(Clone, Debug)]
pub struct BankReconciliationRequest {
    pub import: BankImportWitness,
    pub predecessors: Vec<BankImportWitness>,
    pub evaluated_known_at: CommitSeq,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankReconciliationRecorded {
    pub attestation_vid: VId,
    pub attestation_digest: [u8; 32],
    pub recorded_at: CommitSeq,
    pub already_recorded: bool,
    pub principal: VId,
    pub claim: ReconciledClaim,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankReconciliationState {
    pub recorded: BankReconciliationRecorded,
    pub cash_balance: i128,
    pub cash_fold_digest: [u8; 32],
    pub active_matches: Vec<BankDecisionRef>,
    pub balance_drift: bool,
    /// The contribution set changed, including exact net-zero later changes.
    pub cash_drift: bool,
    pub match_drift: bool,
    pub changed_entries: Vec<EntryRef>,
    /// Durable native CITES edges made by authorized late postings/activation.
    pub citing_entries: Vec<EntryRef>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankReconciliationStatus {
    pub manifest_oid: Oid,
    pub known_at: CommitSeq,
    /// The protection remains in force after drift; a correction cannot erase
    /// the need for reconciliation authority on the already-attested history.
    pub reconciled_through: Option<DateDay>,
    pub reconciliations: Vec<BankReconciliationState>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankReconciliationLock {
    pub attestation: BankDecisionRef,
    pub account: VId,
    pub unit: UnitId,
    pub reconciled_through: DateDay,
    pub evaluated_known_at: CommitSeq,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::BANK_MATCH,
        exit::REFUSAL,
        message,
        "plan §5.7 / §9.4 (an exact close binds complete confirmed statement lines and cumulative posted cash)",
        "confirm every retained statement line, post any genuine difference under its accounting law, then review the current native prefix; outstanding-adjusted reconciliation is not supported by this exact close",
    )
}

fn drift(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::ATTESTATION_DRIFT,
        exit::VERIFICATION,
        message,
        "FA-INV-02; FA-INV-04; plan §9.4 (the immutable close and original native prefix must verify)",
        "preserve the store and investigate its original reconciliation attestation, source receipt, cash entries and confirmation history",
    )
}

fn conflict(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::CONFLICT,
        exit::CONFLICT,
        message,
        "FG-LAW-FCW-01; plan §9.4 (the reviewed closing prefix is exact)",
        "review the new native prefix and submit a new exact close, or retry the exact originally recorded prefix",
    )
}

#[derive(Clone)]
struct CashFold {
    balance: i128,
    digest: [u8; 32],
    entries: BTreeSet<EntryRef>,
}

fn cash_fold<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    manifest: &BankImportManifest,
    at: CommitSeq,
) -> Outcome<CashFold> {
    if let Err(error) = crate::entry_history::verify_entry_history(db, cx, book, Some(at)) {
        return match error {
            KernelError::Corrupt(message) => Ok(Err(drift(message))),
            error => Err(error),
        };
    }
    let Some(account_row) = db.vertex_at(manifest.account, at)? else {
        return Ok(Err(invalid(
            "the statement cash account does not exist at the evaluated prefix",
        )));
    };
    let account = AccountRow::decode(&account_row)?;
    if !account_row.labels.contains(&label::ACCOUNT)
        || !account.is_leaf
        || account.normal_balance != 0
        || account.account_type != AccountType::ASSET.0
        || !book
            .units
            .get(manifest.unit)
            .is_some_and(|unit| matches!(unit.kind, UnitKind::Currency { .. }))
        || matches!(account.unit_policy, UnitPolicy::Single(unit) if unit != manifest.unit)
    {
        return Ok(Err(invalid(
            "exact bank closing requires a debit-normal Asset leaf in the statement currency",
        )));
    }
    let mut rows = db.vertices_at(at)?;
    rows.sort_by_key(|row| (row.created_at, row.vid));
    let mut amount = 0_i128;
    let mut digest = domain_digest(
        CASH_FOLD_DOMAIN,
        &[
            &book.book_id.0,
            &manifest.account.0.to_le_bytes(),
            &manifest.unit.0.to_le_bytes(),
            &manifest.statement_date.0.to_le_bytes(),
        ],
    );
    let mut entries = BTreeSet::new();
    let mut visibility = BTreeMap::new();
    for row in rows {
        checkpoint(cx)?;
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = Entry::decode(verify::payload(&row)?)?;
        if entry.proposal.class == EntryClass::PENDING
            || entry.proposal.effective_date > manifest.statement_date
            || !crate::migration::visible_at(db, &entry, at, &mut visibility)?
        {
            continue;
        }
        for (ordinal, leg) in entry.proposal.legs.iter().enumerate() {
            if leg.account_ref != manifest.account || leg.amount.unit != manifest.unit {
                continue;
            }
            amount = match leg.side {
                Side::Debit => amount.checked_add(leg.amount.mantissa),
                Side::Credit => amount.checked_sub(leg.amount.mantissa),
            }
            .ok_or_else(|| {
                KernelError::Corrupt("cumulative reconciled cash overflows i128".into())
            })?;
            let mut contribution = Writer::new();
            contribution
                .fixed(&digest)
                .u128(row.vid.0)
                .fixed(&entry.entry_digest)
                .u64(row.created_at.0)
                .u16(u16::try_from(ordinal).map_err(|_| {
                    KernelError::Corrupt("cash leg ordinal exceeds its native bound".into())
                })?)
                .i32(entry.proposal.effective_date.0)
                .u8(match leg.side {
                    Side::Debit => 0,
                    Side::Credit => 1,
                })
                .i128(leg.amount.mantissa);
            digest = domain_digest(CASH_FOLD_DOMAIN, &[&contribution.finish()?]);
            entries.insert(entry.entry_ref(row.vid));
        }
    }
    Ok(Ok(CashFold {
        balance: amount,
        digest,
        entries,
    }))
}

fn selected_matches<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    manifest: &BankImportManifest,
    manifest_oid: Oid,
    at: CommitSeq,
    require_complete: bool,
) -> Outcome<Vec<BankDecisionRef>> {
    let active = match verify::claims_at(db, cx, book, at)? {
        Ok(active) => active,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let selected: Vec<&BankMatchRecorded> = active
        .iter()
        .filter(|recorded| {
            let c = &recorded.confirmation;
            c.manifest_oid == manifest_oid
                && c.account == manifest.account
                && c.statement_oid == manifest.statement_oid
        })
        .collect();
    let mut ordinals = BTreeSet::new();
    let mut references = Vec::with_capacity(selected.len());
    for recorded in selected {
        checkpoint(cx)?;
        let c = &recorded.confirmation;
        let Some(row) = db.vertex_at(recorded.match_vid, at)? else {
            return Ok(Err(drift("an active statement confirmation is absent")));
        };
        if let Err(refusal) = verify::read_record(db, cx, book, &row, at, Some(manifest))? {
            return Ok(Err(refusal));
        }
        let source = match verify::source_entry(db, cx, book, c.entry_ref, at)? {
            Ok(source) => source,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let Some(leg) = source.entry.proposal.legs.get(usize::from(c.leg_ordinal)) else {
            return Ok(Err(drift(
                "a statement confirmation has no actual cash leg",
            )));
        };
        if leg.amount.unit != manifest.unit || !ordinals.insert(c.line_ordinal) {
            return Ok(Err(drift(
                "the statement's active confirmations repeat a line or change its currency",
            )));
        }
        if require_complete && source.entry.proposal.effective_date > manifest.statement_date {
            return Ok(Err(invalid(
                "a confirmed cash leg is effective after the statement close date",
            )));
        }
        references.push(BankDecisionRef {
            vid: recorded.match_vid,
            digest: recorded.match_digest,
        });
    }
    if require_complete
        && (ordinals.len() != manifest.line_oids.len()
            || (1..=manifest.line_oids.len()).any(|ordinal| !ordinals.contains(&(ordinal as u32))))
    {
        return Ok(Err(invalid(
            "every retained statement line must have an active confirmation under this exact manifest before closing",
        )));
    }
    references.sort();
    Ok(Ok(references))
}

/// Verify retained source metadata and the complete original receipt at one
/// prefix. The canonical manifest is retained in the claim, so external source
/// storage never turns native protection into an optional network operation.
#[allow(clippy::too_many_arguments)]
fn verify_import_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    manifest: &BankImportManifest,
    manifest_oid: Oid,
    import_run: VId,
    receipt_hash: [u8; 32],
    import_at: CommitSeq,
    at: CommitSeq,
) -> Outcome<()> {
    if manifest.book_id != book.book_id
        || manifest.document_oid()? != manifest_oid
        || import_at.0 == 0
        || import_at > at
    {
        return Ok(Err(drift(
            "a reconciled statement's source identity or publication coordinate differs",
        )));
    }
    let policy =
        EvidencePolicy::embedded().map_err(|error| KernelError::Corrupt(error.to_string()))?;
    let kind = |name: &str| {
        policy
            .kind_by_name(name)
            .map(|kind| kind.tag)
            .ok_or_else(|| KernelError::Corrupt(format!("missing bank document kind {name}")))
    };
    let mut byte_count = 0_u64;
    for oid in manifest.closure(manifest_oid) {
        checkpoint(cx)?;
        let Some(row) = db.vertex_at(document_vid(&oid), at)? else {
            return Ok(Err(drift(
                "a reconciled statement's retained source closure is incomplete",
            )));
        };
        let record = match verify_row(&row, &policy) {
            Ok(record) => record,
            Err(message) => return Ok(Err(drift(message))),
        };
        let valid = if oid == manifest_oid {
            record.kind == kind("Workpaper")?
                && record.mime == BANK_MANIFEST_MIME
                && record.doc_commit == manifest.document_commit()?
        } else if oid == manifest.statement_oid {
            record.kind == kind("BankStatement")? && record.doc_commit == manifest.statement_commit
        } else {
            record.kind == kind("Other")? && record.mime == BANK_LINE_MIME
        };
        if !valid || record.book_id != book.book_id || record.oid() != oid {
            return Ok(Err(drift(
                "a reconciled statement's source commitment, kind or identity differs",
            )));
        }
        byte_count = byte_count.checked_add(record.size).ok_or_else(|| {
            KernelError::Corrupt("reconciliation import byte count overflow".into())
        })?;
    }
    let Some(row) = db.vertex_at(import_run, at)? else {
        return Ok(Err(drift(
            "a reconciled statement's native ImportRun is absent",
        )));
    };
    let entry = Entry::decode(verify::payload(&row)?)?;
    let Some(ControlPayload::ImportRun {
        source,
        document_count,
        byte_count: original_bytes,
        oids_root,
        receipt_hash: original_hash,
    }) = &entry.proposal.control
    else {
        return Ok(Err(drift(
            "the reconciliation source does not name a native ImportRun",
        )));
    };
    if row.created_at != import_at
        || entry.proposal.class != EntryClass::IMPORT_CONTROL
        || entry.proposal.book_id != book.book_id
        || entry.proposal.branch_id != Id128::TRUNK
        || *original_hash != receipt_hash
        || *original_bytes != byte_count
    {
        return Ok(Err(drift(
            "the reconciliation source receipt or publication coordinate differs",
        )));
    }
    let receipt = RunReceipt {
        run: import_run,
        source: source.clone(),
        document_count: *document_count,
        byte_count,
        oids_root: *oids_root,
        receipt_hash,
        recorded_at: import_at,
    };
    if let Err(refusal) =
        crate::import::verify_receipt(&receipt, book.book_id, &manifest.closure(manifest_oid))
    {
        return Ok(Err(drift(refusal.message)));
    }
    if manifest.predecessor.is_some() || manifest.csv_layout.is_some() {
        let vid = bank_statement_link_vid(book.book_id, manifest.account, manifest.statement_oid);
        let Some(row) = db.vertex_at(vid, at)?.map(|row| row.seen_at(at)) else {
            return Ok(Err(drift(
                "a reconciled predecessor interpretation lacks its atomic native link",
            )));
        };
        let expected = BankStatementLink {
            manifest_oid,
            manifest: manifest.clone(),
            receipt,
        };
        if row.created_at != import_at || !expected.matches_row(&row)? {
            return Ok(Err(drift(
                "a reconciled predecessor link differs from its actual source import",
            )));
        }
        if let Err(refusal) = verify::native_birth(db, cx, &row, label::BANK_STATEMENT_LINK)? {
            return Ok(Err(drift(refusal.message)));
        }
    }
    Ok(Ok(()))
}

fn verify_sources<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    claim: &ReconciledClaim,
) -> Outcome<()> {
    verify_sources_at(db, cx, book, claim, claim.evaluated_known_at)
}

fn verify_sources_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    claim: &ReconciledClaim,
    at: CommitSeq,
) -> Outcome<()> {
    let mut manifest = &claim.manifest;
    let mut manifest_oid = claim.manifest_oid;
    let mut run = claim.import_run;
    let mut receipt = claim.import_receipt_hash;
    let mut imported = claim.import_recorded_at;
    let mut seen = BTreeSet::new();
    for previous in claim
        .predecessors
        .iter()
        .map(Some)
        .chain(core::iter::once(None))
    {
        if !seen.insert(manifest.statement_oid) {
            return Ok(Err(drift(
                "a reconciled predecessor chain repeats its source",
            )));
        }
        if let Err(refusal) = verify_import_at(
            db,
            cx,
            book,
            manifest,
            manifest_oid,
            run,
            receipt,
            imported,
            at,
        )? {
            return Ok(Err(refusal));
        }
        match (previous, &manifest.predecessor) {
            (Some(old), Some(binding)) => {
                if old.book_id != book.book_id
                    || old.account != manifest.account
                    || old.unit != manifest.unit
                    || old.document_oid()? != binding.manifest_oid
                    || old.document_commit()? != binding.manifest_commit
                    || old.statement_oid != binding.statement_oid
                    || old.statement_commit != binding.statement_commit
                    || old.sequence_number != binding.sequence_number
                    || old.statement_date != binding.statement_date
                    || old.closing_balance != binding.closing_balance
                    || old.closing_balance != manifest.opening_balance
                    || old.sequence_number.checked_add(1) != Some(manifest.sequence_number)
                    || old.statement_date > manifest.statement_date
                    || binding.recorded_at >= imported
                {
                    return Ok(Err(drift(
                        "the reconciled predecessor closure differs from its retained binding",
                    )));
                }
                manifest_oid = binding.manifest_oid;
                run = binding.import_run;
                receipt = binding.receipt_hash;
                imported = binding.recorded_at;
                manifest = old;
            }
            (None, None) => {}
            _ => {
                return Ok(Err(drift(
                    "the reconciled predecessor closure is incomplete or contains extra interpretations",
                )));
            }
        }
    }
    Ok(Ok(()))
}

fn strong_edges(recorded: &BankReconciliationRecorded) -> Vec<(RelationId, VId)> {
    let claim = &recorded.claim;
    let mut edges = BTreeSet::from([
        (relation::ATTESTS, claim.manifest.account),
        (relation::IN_BOOK, book_root()),
        (relation::CITES, document_vid(&claim.manifest_oid)),
        (relation::CITES, document_vid(&claim.manifest.statement_oid)),
        (relation::CITES, claim.import_run),
    ]);
    for matched in &claim.matches {
        edges.insert((relation::CITES, matched.vid));
    }
    let mut manifest = &claim.manifest;
    if manifest.predecessor.is_some() || manifest.csv_layout.is_some() {
        edges.insert((
            relation::CITES,
            bank_statement_link_vid(manifest.book_id, manifest.account, manifest.statement_oid),
        ));
    }
    for previous in &claim.predecessors {
        if let Some(binding) = &manifest.predecessor {
            edges.insert((relation::CITES, document_vid(&binding.manifest_oid)));
            edges.insert((relation::CITES, document_vid(&binding.statement_oid)));
            edges.insert((relation::CITES, binding.import_run));
        }
        if previous.predecessor.is_some() || previous.csv_layout.is_some() {
            edges.insert((
                relation::CITES,
                bank_statement_link_vid(previous.book_id, previous.account, previous.statement_oid),
            ));
        }
        manifest = previous;
    }
    edges.into_iter().collect()
}

/// The native v1 Attestation header is u16 version, Id128 book, then its
/// reserved claim tag. Classification uses the original CreateVertex bytes,
/// never the mutable code mirror or a current live-label scan. Full decoding
/// follows for every protected birth, including malformed payloads with tag 3.
fn is_reconciled_payload(props: &[(PropertyKeyId, CanonicalScalar)]) -> bool {
    props.iter().any(|(key, value)| {
        *key == property::FA_PAYLOAD
            && matches!(value, CanonicalScalar::Bytes(bytes)
                if bytes.as_slice().get(18) == Some(&crate::attestation::claim::RECONCILED))
    })
}

/// Enumerate actual native Attestation births before examining live rows.
/// Missing/relabelled records, and rewrite followed by restoration, cannot
/// erase an earlier closing lock. Every returned claim is refolded at its own
/// immutable prefix; later ordinary postings need not preserve its old value.
fn history_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    at: CommitSeq,
) -> Outcome<Vec<BankReconciliationRecorded>> {
    let mut births = BTreeMap::new();
    let mut through = 0_u64;
    for batch in db.delta_since(CommitSeq(0))? {
        let seq = batch.commit_seq();
        if seq > at {
            break;
        }
        if through.checked_add(1) != Some(seq.0) {
            return Ok(Err(drift(
                "reconciliation protection requires complete native history from sequence zero",
            )));
        }
        for coordinate in batch.coordinate_entries() {
            for delta in &coordinate.rows {
                checkpoint(cx)?;
                if let DeltaRow::CreateVertex {
                    vid, labels, props, ..
                } = delta
                    && labels.contains(&label::ATTESTATION)
                    && is_reconciled_payload(props)
                    && (labels.as_slice() != [label::ATTESTATION]
                        || births.insert(*vid, seq).is_some())
                {
                    return Ok(Err(drift(
                        "an attestation has an invalid or repeated native birth",
                    )));
                }
            }
        }
        for coordinate in batch.coordinate_entries() {
            for delta in &coordinate.rows {
                checkpoint(cx)?;
                let touched = match delta {
                    DeltaRow::Property {
                        elem: ElementId::Vertex(vid),
                        ..
                    }
                    | DeltaRow::LabelMembership { vid, .. }
                    | DeltaRow::DeleteVertex { vid, .. } => Some(vid),
                    _ => None,
                };
                if let Some(vid) = touched
                    && births.get(vid).is_some_and(|born| *born <= seq)
                {
                    return Ok(Err(drift(format!(
                        "attestation {:032x} was modified at {}; restoration cannot erase that history",
                        vid.0, seq.0
                    ))));
                }
            }
        }
        through = seq.0;
    }
    if through != at.0 {
        return Ok(Err(drift(
            "native reconciliation history ends before the selected prefix",
        )));
    }
    for row in db.vertices_at(at)? {
        if row.labels.contains(&label::ATTESTATION)
            && is_reconciled_payload(&row.props)
            && !births.contains_key(&row.vid)
        {
            return Ok(Err(drift(
                "a later label or payload rewrite cannot manufacture a reconciled attestation birth",
            )));
        }
    }
    let mut result = Vec::new();
    let mut protected_edges: BTreeMap<EId, CommitSeq> = BTreeMap::new();
    for (vid, born) in births {
        let Some(row) = db.vertex_at(vid, at)?.map(|row| row.seen_at(at)) else {
            return Ok(Err(drift(
                "an immutable attestation birth is absent at the selected prefix",
            )));
        };
        let Some(original) = db.vertex_at(vid, born)?.map(|row| row.seen_at(born)) else {
            return Ok(Err(drift(
                "an attestation creating snapshot is unavailable",
            )));
        };
        if row.created_at != born
            || row.retired_at.is_some()
            || row.labels.as_slice() != [label::ATTESTATION]
            || original.birth_ordinal != row.birth_ordinal
            || original.labels != row.labels
            || original.props != row.props
        {
            return Ok(Err(drift(
                "an attestation differs from its immutable native creating row",
            )));
        }
        if let Err(refusal) = verify::native_birth(db, cx, &row, label::ATTESTATION)? {
            return Ok(Err(drift(refusal.message)));
        }
        let stored = match verify_attestation_row(&row) {
            Ok(stored) => stored,
            Err(message) => return Ok(Err(drift(message))),
        };
        let AttestationClaim::Reconciled(claim) = stored.attestation.claim else {
            continue;
        };
        let claim = *claim;
        if stored.attestation.book_id != book.book_id
            || claim.evaluated_known_at.0.checked_add(1) != Some(born.0)
        {
            return Ok(Err(drift(
                "a reconciliation attestation has invalid book or evaluated coordinates",
            )));
        }
        if let Err(refusal) = verify_sources(db, cx, book, &claim)? {
            return Ok(Err(refusal));
        }
        let cash = match cash_fold(db, cx, book, &claim.manifest, claim.evaluated_known_at)? {
            Ok(cash) => cash,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let matches = match selected_matches(
            db,
            cx,
            book,
            &claim.manifest,
            claim.manifest_oid,
            claim.evaluated_known_at,
            true,
        )? {
            Ok(matches) => matches,
            Err(refusal) => return Ok(Err(drift(refusal.message))),
        };
        if cash.balance != claim.cash_balance
            || cash.digest != claim.cash_fold_digest
            || matches != claim.matches
        {
            return Ok(Err(drift(
                "a reconciliation attestation does not equal its original cumulative cash and active-confirmation fold",
            )));
        }
        let recorded = BankReconciliationRecorded {
            attestation_vid: vid,
            attestation_digest: stored.signed_digest,
            recorded_at: born,
            already_recorded: false,
            principal: stored.attestation.principal,
            claim,
        };
        for (relation, target) in strong_edges(&recorded) {
            let eid = edge_id(relation, vid, target);
            if let Err(refusal) = verify::edge(db, cx, relation, vid, target, &[], born, at, eid)? {
                return Ok(Err(drift(refusal.message)));
            }
            protected_edges.insert(eid, born);
        }
        result.push(recorded);
    }
    // A restored edge must not hide a missing account anchor at any point in
    // native history. These are same-publication immutable source edges.
    for batch in db.delta_since(CommitSeq(0))? {
        let seq = batch.commit_seq();
        if seq > at {
            break;
        }
        for coordinate in batch.coordinate_entries() {
            for delta in &coordinate.rows {
                checkpoint(cx)?;
                let touched = match delta {
                    DeltaRow::Property {
                        elem: ElementId::Edge(eid),
                        ..
                    }
                    | DeltaRow::DeleteEdge { eid, .. } => Some(eid),
                    _ => None,
                };
                if let Some(eid) = touched
                    && protected_edges.get(eid).is_some_and(|born| *born <= seq)
                {
                    return Ok(Err(drift(
                        "an immutable reconciliation source/account edge was modified after publication",
                    )));
                }
            }
        }
    }
    result.sort_by_key(|recorded| (recorded.recorded_at, recorded.attestation_vid));
    Ok(Ok(result))
}

/// Current authority precedes any source/history observation. The ordinary
/// async entrypoint hydrates retained history before preparing one atomic close.
pub async fn reconcile_bank_statement<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    request: BankReconciliationRequest,
) -> Outcome<BankReconciliationRecorded> {
    if let Err(refusal) = admit_confirmation(db, book, capability)? {
        return Ok(Err(refusal));
    }
    if let Err(refusal) = crate::scratch::ensure_history(db, cx).await? {
        return Ok(Err(refusal));
    }
    match prepare_bank_reconciliation(db, cx, book, capability, request)? {
        Err(refusal) => Ok(Err(refusal)),
        Ok(BankReconciliationPreparation::AlreadyRecorded(recorded)) => Ok(Ok(*recorded)),
        Ok(BankReconciliationPreparation::Ready(prepared)) => prepared.commit(db, cx).await,
    }
}

pub enum BankReconciliationPreparation {
    AlreadyRecorded(Box<BankReconciliationRecorded>),
    Ready(Box<PreparedBankReconciliation>),
}

pub struct PreparedBankReconciliation {
    txn: WriteTxn,
    recorded: BankReconciliationRecorded,
    capability: Capability,
}

impl PreparedBankReconciliation {
    pub async fn commit<V: Vfs + Clone>(
        self: Box<Self>,
        db: &mut Database<V>,
        cx: &PurposeContexts,
    ) -> Outcome<BankReconciliationRecorded> {
        let Self {
            mut txn,
            mut recorded,
            capability,
        } = *self;
        if let Err(denial) = fa_policy::current(&capability, db.frontier()?) {
            txn.abort();
            return Ok(Err(crate::policy::refusal(&denial)));
        }
        // Even a maintenance commit without changed vertices moves the exact
        // reviewed coordinate. Refuse before publication rather than create a
        // record which its historical verifier would immediately reject.
        if db.frontier()? != recorded.claim.evaluated_known_at {
            txn.abort();
            return Ok(Err(conflict(
                "the reviewed closing prefix changed before publication",
            )));
        }
        match txn.commit(db, &cx.commit()).await {
            Ok(at) => {
                recorded.recorded_at = at;
                Ok(Ok(recorded))
            }
            Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
                Ok(Err(conflict(format!(
                    "a closing cash/source/authority witness changed before publication: {detail}"
                ))))
            }
            Err(error) => Err(error.into()),
        }
    }
}

/// Resident-history preparation for native FCW and batch/planning callers.
pub fn prepare_bank_reconciliation<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    request: BankReconciliationRequest,
) -> Outcome<BankReconciliationPreparation> {
    if let Err(refusal) = admit_confirmation(db, book, capability)? {
        return Ok(Err(refusal));
    }
    let head = db.frontier()?;
    if request.evaluated_known_at > head
        || request.import.manifest().book_id != book.book_id
        || request.import.receipt().recorded_at > request.evaluated_known_at
        || request.predecessors.len() > fa_model::limits::MAX_BANK_PREDECESSOR_DEPTH
    {
        return Ok(Err(invalid(
            "the exact closing source or evaluated prefix is outside this book's retained bounds",
        )));
    }
    let mut txn = db.begin(&cx.txn())?;
    if let Err(refusal) = crate::policy::capability_witness(&txn, db, book, capability)? {
        return Ok(Err(refusal));
    }
    crate::policy::epoch_witness(&txn, db)?;
    let identity = reconciled_vid(
        book.book_id,
        request.import.manifest_oid(),
        request.evaluated_known_at,
        capability.holder(),
    );
    let history = match history_at(db, cx, book, head)? {
        Ok(history) => history,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Some(mut original) = history
        .into_iter()
        .find(|recorded| recorded.attestation_vid == identity)
    {
        if original.claim.manifest != *request.import.manifest()
            || original.claim.import_run != request.import.receipt().run
            || original.claim.import_receipt_hash != request.import.receipt().receipt_hash
            || original.claim.import_recorded_at != request.import.receipt().recorded_at
            || original.claim.predecessors
                != request
                    .predecessors
                    .iter()
                    .map(|w| w.manifest().clone())
                    .collect::<Vec<_>>()
        {
            return Ok(Err(conflict(
                "a retained reconciliation identity binds different source witnesses",
            )));
        }
        txn.abort();
        original.already_recorded = true;
        return Ok(Ok(BankReconciliationPreparation::AlreadyRecorded(
            Box::new(original),
        )));
    }
    // A new contributing Entry, match correction, migration activation, or
    // source mutation invalidates this infrequent complete closing fold.
    txn.vertices(db)?;
    if let Err(refusal) = request.import.retain(&txn, db, book.book_id)? {
        return Ok(Err(refusal));
    }
    if let Err(refusal) = verify::import_birth(db, cx, book, &request.import)? {
        return Ok(Err(refusal));
    }
    let mut previous = request.import.manifest();
    let mut previous_imported = request.import.receipt().recorded_at;
    let mut seen = BTreeSet::from([request.import.manifest_oid()]);
    for witness in &request.predecessors {
        checkpoint(cx)?;
        if !seen.insert(witness.manifest_oid())
            || witness.receipt().recorded_at >= previous_imported
        {
            return Ok(Err(invalid(
                "a closing predecessor repeats or was not published before its successor",
            )));
        }
        if let Err(refusal) = previous.verify_predecessor(witness) {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = witness.retain(&txn, db, book.book_id)? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = verify::import_birth(db, cx, book, witness)? {
            return Ok(Err(refusal));
        }
        previous = witness.manifest();
        previous_imported = witness.receipt().recorded_at;
    }
    if previous.predecessor.is_some() {
        return Ok(Err(invalid(
            "the complete closing predecessor chain is required",
        )));
    }
    if request.evaluated_known_at != head {
        return Ok(Err(conflict(
            "a new exact statement close must name the current reviewed native prefix",
        )));
    }
    let manifest = request.import.manifest();
    let cash = match cash_fold(db, cx, book, manifest, head)? {
        Ok(cash) => cash,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let matches = match selected_matches(
        db,
        cx,
        book,
        manifest,
        request.import.manifest_oid(),
        head,
        true,
    )? {
        Ok(matches) => matches,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if cash.balance != manifest.closing_balance {
        return Ok(Err(invalid(format!(
            "cumulative posted cash {} differs from statement closing {}; outstanding-adjusted closing is not this exact profile",
            cash.balance, manifest.closing_balance
        ))));
    }
    let claim = ReconciledClaim {
        manifest_oid: request.import.manifest_oid(),
        manifest: manifest.clone(),
        predecessors: request
            .predecessors
            .iter()
            .map(|w| w.manifest().clone())
            .collect(),
        import_run: request.import.receipt().run,
        import_receipt_hash: request.import.receipt().receipt_hash,
        import_recorded_at: request.import.receipt().recorded_at,
        evaluated_known_at: head,
        cash_balance: cash.balance,
        cash_fold_digest: cash.digest,
        matches,
    };
    if let Err(refusal) = verify_sources(db, cx, book, &claim)? {
        return Ok(Err(refusal));
    }
    let mut evidence_refs = vec![claim.manifest_oid, claim.manifest.statement_oid];
    evidence_refs.sort();
    let attestation = Attestation {
        book_id: book.book_id,
        subject: Subject::Document(claim.manifest_oid),
        principal: capability.holder(),
        evidence_refs,
        claim: AttestationClaim::Reconciled(Box::new(claim.clone())),
    };
    let binding = CapabilityBinding {
        profile: capability.profile(),
        capability_commitment: capability
            .commitment()
            .map_err(|error| KernelError::Corrupt(format!("reconciliation capability: {error}")))?,
    };
    let payload = attestation.canonical_bytes(&binding)?;
    if payload.len() > fa_model::limits::MAX_ENTRY_BYTES {
        return Ok(Err(invalid(
            "the complete statement-close attestation exceeds its native payload bound; no predecessor or match may be omitted",
        )));
    }
    // Decode before publication, enforcing every reader's exact bounds and shape.
    crate::attestation::StoredAttestation::decode(&payload)?;
    let recorded = BankReconciliationRecorded {
        attestation_vid: identity,
        attestation_digest: attestation.signed_digest()?,
        recorded_at: CommitSeq(0),
        already_recorded: false,
        principal: capability.holder(),
        claim,
    };
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("reconciled.payload", payload)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("reconciled.digest", recorded.attestation_digest.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("reconciled.book", book.book_id.0.to_vec())?,
        ),
        (
            property::CODE,
            scalar_text("reconciled.claim", "Reconciled")?,
        ),
    ];
    props.sort_by_key(|(key, _)| key.0);
    let mut attests = WriteBatch::new(relation::ATTESTS);
    attests.create_vertex(identity, vec![label::ATTESTATION], props);
    let mut cites = WriteBatch::new(relation::CITES);
    let mut membership = WriteBatch::new(relation::IN_BOOK);
    for (kind, target) in strong_edges(&recorded) {
        let batch = if kind == relation::ATTESTS {
            &mut attests
        } else if kind == relation::CITES {
            &mut cites
        } else {
            &mut membership
        };
        batch.add_edge(edge_id(kind, identity, target), identity, target, vec![]);
    }
    txn.write_ordered(db, vec![attests, cites, membership])?;
    Ok(Ok(BankReconciliationPreparation::Ready(Box::new(
        PreparedBankReconciliation {
            txn,
            recorded,
            capability: capability.clone(),
        },
    ))))
}

/// The verified reconciliation history at one committed prefix. It reads
/// only committed rows at `at`, never a transaction's overlay, so every
/// member of one batch (one transaction, one basis) shares it (fa-rcw1).
#[derive(Clone, Debug)]
pub struct ReconciliationHistory {
    at: CommitSeq,
    /// The Chronicle marker of the commit at `at`. Markers chain to their
    /// predecessor, so an equal marker means the same committed prefix: a
    /// history is only carried forward on the database it was verified on.
    marker: Option<MarkerRef>,
    recorded: Vec<BankReconciliationRecorded>,
}

impl ReconciliationHistory {
    /// The committed prefix this history was verified at.
    #[must_use]
    pub fn verified_at(&self) -> CommitSeq {
        self.at
    }
}

/// `history` carried forward to `at` without a replay from sequence zero, or
/// `None` when a commit after its prefix could change any part of the
/// verdict [`history_at`] would reach at `at`; the caller then verifies the
/// full history there (fa-rcw1).
///
/// Every check in `history_at` is either over attestation births, over the
/// rows of born attestations and their strong edges, over the label and
/// payload of every vertex, or at a claim's own immutable
/// `evaluated_known_at`. A commit can change the first three only through an
/// attestation birth, a delta naming a born attestation or one of its strong
/// edges, a vertex retirement (whose cascade retires edges), an ATTESTATION
/// label flip, or a payload write on a vertex labelled ATTESTATION at `at`.
/// Any such delta, any delta kind not listed here, a gap in the sequence, or
/// a prefix behind `history`, or a database whose commit at the history's
/// prefix is not the one it was verified on (another Chronicle marker)
/// refuses the shortcut; the full verification then decides, exactly as
/// before. The substrate's delta rows are the complete net effect of each
/// commit, as the register maintainer relies on.
#[doc(hidden)]
pub fn extend_reconciliation_history<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    history: &ReconciliationHistory,
    at: CommitSeq,
) -> Result<Option<ReconciliationHistory>, KernelError> {
    if history.at > at || history.marker.is_none() || marker_at(db, history.at)? != history.marker {
        return Ok(None);
    }
    let born: BTreeSet<VId> = history.recorded.iter().map(|r| r.attestation_vid).collect();
    let protected: BTreeSet<EId> = history
        .recorded
        .iter()
        .flat_map(|recorded| {
            strong_edges(recorded)
                .into_iter()
                .map(|(relation, target)| edge_id(relation, recorded.attestation_vid, target))
        })
        .collect();
    let mut through = history.at.0;
    for batch in db.delta_since(history.at)? {
        let seq = batch.commit_seq();
        if seq > at {
            break;
        }
        if through.checked_add(1) != Some(seq.0) {
            return Ok(None);
        }
        for coordinate in batch.coordinate_entries() {
            for delta in &coordinate.rows {
                checkpoint(cx)?;
                let unchanged = match delta {
                    DeltaRow::CreateVertex { labels, .. } => !labels.contains(&label::ATTESTATION),
                    DeltaRow::CreateEdge { .. } => true,
                    DeltaRow::LabelMembership {
                        vid,
                        label: flipped,
                        ..
                    } => *flipped != label::ATTESTATION && !born.contains(vid),
                    DeltaRow::Property {
                        elem: ElementId::Vertex(vid),
                        property: key,
                        ..
                    } => {
                        !born.contains(vid)
                            && (*key != property::FA_PAYLOAD
                                || !db
                                    .vertex_at(*vid, at)?
                                    .is_some_and(|row| row.labels.contains(&label::ATTESTATION)))
                    }
                    DeltaRow::Property {
                        elem: ElementId::Edge(eid),
                        ..
                    }
                    | DeltaRow::DeleteEdge { eid, .. } => !protected.contains(eid),
                    _ => false,
                };
                if !unchanged {
                    return Ok(None);
                }
            }
        }
        through = seq.0;
    }
    if through != at.0 {
        return Ok(None);
    }
    Ok(Some(ReconciliationHistory {
        at,
        marker: marker_at(db, at)?,
        recorded: history.recorded.clone(),
    }))
}

/// Witness each affected account even when there is no close. New close
/// publication adds an ATTESTS edge to that account; FGDB's adjacency endpoint
/// conflict check invalidates a prepared post without serializing disjoint
/// accounts through a global vertex-population scan.
///
/// `history` is reused when it was verified at this transaction's basis,
/// carried forward when [`extend_reconciliation_history`] proves no later
/// commit can change it, and verified in full otherwise; the account and
/// attestation witnesses are still read through `txn` on every call.
pub fn witness_reconciliation_locks<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    txn: &WriteTxn,
    accounts: &[VId],
    history: &mut Option<ReconciliationHistory>,
) -> Outcome<Vec<BankReconciliationLock>> {
    let accounts: BTreeSet<_> = accounts.iter().copied().collect();
    if accounts.is_empty() {
        return Ok(Ok(Vec::new()));
    }
    for account in &accounts {
        txn.vertex(db, *account)?;
    }
    let at = txn.basis();
    let carried = match history.take() {
        Some(verified) => extend_reconciliation_history(db, cx, &verified, at)?,
        None => None,
    };
    let verified = match carried {
        Some(verified) => verified,
        None => match history_at(db, cx, book, at)? {
            Ok(recorded) => ReconciliationHistory {
                at,
                marker: marker_at(db, at)?,
                recorded,
            },
            Err(refusal) => return Ok(Err(refusal)),
        },
    };
    let locks = locks_for(db, txn, &accounts, &verified.recorded);
    *history = Some(verified);
    locks
}

fn locks_for<V: Vfs + Clone>(
    db: &Database<V>,
    txn: &WriteTxn,
    accounts: &BTreeSet<VId>,
    history: &[BankReconciliationRecorded],
) -> Outcome<Vec<BankReconciliationLock>> {
    let mut locks = Vec::new();
    for recorded in history {
        if !accounts.contains(&recorded.claim.manifest.account) {
            continue;
        }
        let Some(row) = txn.vertex(db, recorded.attestation_vid)? else {
            return Ok(Err(drift(
                "a reconciliation attestation disappeared before posting preparation",
            )));
        };
        let stored = match verify_attestation_row(&row) {
            Ok(stored) => stored,
            Err(message) => return Ok(Err(drift(message))),
        };
        if stored.signed_digest != recorded.attestation_digest {
            return Ok(Err(drift(
                "the posting transaction sees a different reconciliation attestation",
            )));
        }
        locks.push(BankReconciliationLock {
            attestation: BankDecisionRef {
                vid: recorded.attestation_vid,
                digest: recorded.attestation_digest,
            },
            account: recorded.claim.manifest.account,
            unit: recorded.claim.manifest.unit,
            reconciled_through: recorded.claim.manifest.statement_date,
            evaluated_known_at: recorded.claim.evaluated_known_at,
        });
    }
    Ok(Ok(locks))
}

fn citing_entries_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    recorded: &BankReconciliationRecorded,
    at: CommitSeq,
) -> Outcome<Vec<EntryRef>> {
    let mut births = BTreeMap::new();
    for batch in db.delta_since(recorded.recorded_at)? {
        let seq = batch.commit_seq();
        if seq > at {
            break;
        }
        for coordinate in batch.coordinate_entries() {
            for delta in &coordinate.rows {
                checkpoint(cx)?;
                if let DeltaRow::CreateEdge {
                    eid,
                    relation: kind,
                    src,
                    dst,
                    props,
                    ..
                } = delta
                    && *kind == relation::CITES
                    && *dst == recorded.attestation_vid
                {
                    let Some(row) = db.vertex_at(*src, seq)? else {
                        return Ok(Err(drift(
                            "a reconciliation citation lacks its native source",
                        )));
                    };
                    if !row.labels.contains(&label::ENTRY) {
                        continue;
                    }
                    if row.created_at != seq
                        || !props.is_empty()
                        || *eid != edge_id(relation::CITES, *src, *dst)
                        || births.insert(*eid, (*src, seq)).is_some()
                    {
                        return Ok(Err(drift(
                            "a late reconciliation citation was not born with its exact source Entry",
                        )));
                    }
                }
            }
        }
        for coordinate in batch.coordinate_entries() {
            for delta in &coordinate.rows {
                let touched = match delta {
                    DeltaRow::Property {
                        elem: ElementId::Edge(eid),
                        ..
                    }
                    | DeltaRow::DeleteEdge { eid, .. } => Some(eid),
                    _ => None,
                };
                if let Some(eid) = touched
                    && births.get(eid).is_some_and(|(_, born)| *born <= seq)
                {
                    return Ok(Err(drift(
                        "a durable late-posting reconciliation citation was modified or deleted",
                    )));
                }
            }
        }
    }
    let mut references = BTreeSet::new();
    for (eid, (source, born)) in births {
        if let Err(refusal) = verify::edge(
            db,
            cx,
            relation::CITES,
            source,
            recorded.attestation_vid,
            &[],
            born,
            at,
            eid,
        )? {
            return Ok(Err(drift(refusal.message)));
        }
        let Some(row) = db.vertex_at(source, at)? else {
            return Ok(Err(drift(
                "a durable reconciliation citation's Entry is absent",
            )));
        };
        references.insert(Entry::decode(verify::payload(&row)?)?.entry_ref(source));
    }
    Ok(Ok(references.into_iter().collect()))
}

fn states_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    manifest_oid: Option<Oid>,
    at: CommitSeq,
) -> Outcome<Vec<BankReconciliationState>> {
    let history = match history_at(db, cx, book, at)? {
        Ok(history) => history,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let mut reconciliations = Vec::new();
    for recorded in history
        .into_iter()
        .filter(|recorded| manifest_oid.is_none_or(|oid| recorded.claim.manifest_oid == oid))
    {
        let claim = &recorded.claim;
        let current = match cash_fold(db, cx, book, &claim.manifest, at)? {
            Ok(cash) => cash,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let original = match cash_fold(db, cx, book, &claim.manifest, claim.evaluated_known_at)? {
            Ok(cash) => cash,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let active_matches =
            match selected_matches(db, cx, book, &claim.manifest, claim.manifest_oid, at, false)? {
                Ok(matches) => matches,
                Err(refusal) => return Ok(Err(refusal)),
            };
        let changed_entries = current
            .entries
            .symmetric_difference(&original.entries)
            .copied()
            .collect();
        let citing_entries = match citing_entries_at(db, cx, &recorded, at)? {
            Ok(entries) => entries,
            Err(refusal) => return Ok(Err(refusal)),
        };
        reconciliations.push(BankReconciliationState {
            balance_drift: current.balance != claim.cash_balance,
            cash_drift: current.digest != claim.cash_fold_digest,
            match_drift: active_matches != claim.matches,
            recorded,
            cash_balance: current.balance,
            cash_fold_digest: current.digest,
            active_matches,
            changed_entries,
            citing_entries,
        });
    }
    Ok(Ok(reconciliations))
}

/// Verify every native statement close and evaluate its drift at one prefix.
/// This synchronous reader requires resident complete native history; callers
/// that open a checkpointed book must hydrate through `scratch::ensure_history`
/// only after current admission. No source bytes or Privileged grant are needed.
/// Both standalone metadata views and certified Lantern procedures use this
/// exact native calculation instead of accepting caller-supplied balances.
pub fn read_bank_reconciliation_states<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    known_at: Option<CommitSeq>,
) -> Outcome<Vec<BankReconciliationState>> {
    let at = match lifecycle::admit_bank_match_history(db, book, capability, known_at)? {
        Ok(at) => at,
        Err(refusal) => return Ok(Err(refusal)),
    };
    states_at(db, cx, book, None, at)
}

/// Verify immutable reconciliation history through a retained prefix without
/// making a historical output depend on later cash amounts. Every original
/// claim is still refolded at its own evaluated prefix; this additionally
/// authenticates current Entry/decision history, retained source metadata and
/// durable late-posting citations. Legitimate document custody changes do not
/// change a source's content commitment. Requires the same current whole-book
/// Read/Reconcile admission and resident history as the states reader.
pub fn verify_bank_reconciliation_history<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    known_at: Option<CommitSeq>,
) -> Outcome<()> {
    let at = match lifecycle::admit_bank_match_history(db, book, capability, known_at)? {
        Ok(at) => at,
        Err(refusal) => return Ok(Err(refusal)),
    };
    verify_history_at(db, cx, book, at)
}

/// Native integrity primitive shared by admitted readers and scratch replay.
/// Replay validates the original source before omitting maintenance rows, so
/// a source mutation cannot disappear through maintenance classification.
/// This does not admit a principal or disclose reconciliation state; public
/// readers retain their own current authority checks before calling it.
pub(crate) fn verify_history_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    at: CommitSeq,
) -> Outcome<()> {
    if let Err(error) = crate::entry_history::verify_entry_history(db, cx, book, Some(at)) {
        return match error {
            KernelError::Corrupt(message) => Ok(Err(drift(message))),
            error => Err(error),
        };
    }
    if let Err(refusal) = lifecycle::history_at(db, cx, book, at)? {
        return Ok(Err(refusal));
    }
    let history = match history_at(db, cx, book, at)? {
        Ok(history) => history,
        Err(refusal) => return Ok(Err(refusal)),
    };
    for recorded in history {
        if let Err(refusal) = verify_sources_at(db, cx, book, &recorded.claim, at)? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = citing_entries_at(db, cx, &recorded, at)? {
            return Ok(Err(refusal));
        }
    }
    Ok(Ok(()))
}

/// Metadata-only current-authority view: original claims are verified at their
/// pinned prefixes, while drift is evaluated at the caller's selected prefix.
pub async fn bank_reconciliation_status<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    manifest_oid: Oid,
    known_at: Option<CommitSeq>,
) -> Outcome<BankReconciliationStatus> {
    if let Err(refusal) = lifecycle::admit_bank_match_history(db, book, capability, known_at)? {
        return Ok(Err(refusal));
    }
    if let Err(refusal) = crate::scratch::ensure_history(db, cx).await? {
        return Ok(Err(refusal));
    }
    let at = match lifecycle::admit_bank_match_history(db, book, capability, known_at)? {
        Ok(at) => at,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let reconciliations = match states_at(db, cx, book, Some(manifest_oid), at)? {
        Ok(states) => states,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let reconciled_through = reconciliations
        .iter()
        .map(|state| state.recorded.claim.manifest.statement_date)
        .max();
    Ok(Ok(BankReconciliationStatus {
        manifest_oid,
        known_at: at,
        reconciled_through,
        reconciliations,
    }))
}
