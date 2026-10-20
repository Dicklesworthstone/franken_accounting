//! Bank statement intake and reproducible reconciliation proposals (§5.7 / §9.5).
//!
//! An intake is one ordinary, atomic Docket import: the original statement,
//! canonical BankLine documents, and a versioned manifest binding the parser
//! and the selected cash account. Matching reopens that retained closure and
//! verifies it against a fresh parse before reading the immutable journal.
//! Teller's pinned deterministic fallback produces reproducible proposals.
//! Exact confirmations retain the original source and actual cash-leg identity
//! under current authority. They do not post money or establish a period lock.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_formats::bank::BankStatementExtract;
use fa_journal::custody::CustodyBody;
use fa_journal::evidence::Document;
use fa_journal::refusal::{Refusal, code, exit};
use fa_journal::{DocumentRead, ImportRecorded, KernelError, RunReceipt, UnitPolicy};
use fa_model::{AccountType, EntryClass, IntakeSource, Oid, domain_digest};
use fa_money::{Side, UnitId};
use fa_policy::{Capability, Op, Profile, Reach};
use fa_registers::reconciliation::{
    BankStatementLine, BookCandidateEntry, MatcherConfig, ReconciliationMatch, match_bank_lines,
};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::DateDay;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, BookError, IntakeAction, Outcome};

use fa_journal::import::BankImportWitness;
use fa_journal::import::bank::{BANK_LINE_MIME as LINE_MIME, BANK_MANIFEST_MIME as MANIFEST_MIME};
pub use fa_journal::import::{BankFormat, BankImportManifest, BankImportPredecessor};

mod confirmation;
mod reconciliation;
pub use confirmation::{BankConfirmationRequest, BankConfirmationStatus, BankStatusRequest};
pub use fa_journal::bank::{
    BankDecisionRef, BankMatchConfirmation, BankMatchHistory, BankMatchLineage, BankMatchRecorded,
    BankReconciliationRecorded, BankReconciliationState, BankReconciliationStatus,
    BankUnmatchRecorded, BankUnmatchRequest,
};
pub use reconciliation::BankReconciliationRequest;

const PARSER_REVISION: u16 = 1;

/// A statement and its manifest occupy the two remaining slots of the
/// registered atomic Docket import bound. No partial statement is admitted.
pub const MAX_BANK_LINES: usize = fa_model::limits::MAX_IMPORT_DOCUMENTS - 2;

/// Bytes are the exact original upload. No source grade or party identity
/// supplied by the caller can override the authenticated import session.
#[derive(Clone, Debug)]
pub struct BankImportRequest {
    pub account: VId,
    pub format: BankFormat,
    pub bytes: Vec<u8>,
    /// Explicit prior retained import. None preserves the original unlinked
    /// v1 interpretation; it does not claim a complete statement history.
    pub previous_manifest: Option<Oid>,
}

#[derive(Clone, Debug)]
pub struct BankImportRecorded {
    pub manifest_oid: Oid,
    pub manifest: BankImportManifest,
    pub receipt: ImportRecorded,
    /// Replayed predecessor links, ending at an explicitly unlinked manifest.
    pub verified_predecessors: usize,
}

#[derive(Clone, Debug)]
pub struct BankMatchRequest {
    pub manifest_oid: Oid,
    pub known_at: Option<CommitSeq>,
    pub date_window_days: u32,
}

/// The original leg ordinal accompanies the matcher's stable candidate
/// ordinal, so multiple cash legs of one entry stay distinguishable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankMatchCandidate {
    pub candidate: BookCandidateEntry,
    pub leg_ordinal: u16,
    pub recorded_at: CommitSeq,
}

/// Gross cash movements in the retained statement's unit. Inflows and
/// outflows stay separate so offsetting unresolved lines cannot disappear.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BankCashAmounts {
    pub inflow: i128,
    pub outflow: i128,
}

impl BankCashAmounts {
    fn add(&mut self, mantissa: i128, inflow: bool) -> Result<(), BookError> {
        let total = if inflow {
            &mut self.inflow
        } else {
            &mut self.outflow
        };
        *total = total
            .checked_add(mantissa)
            .ok_or_else(|| corrupt("cash direction total exceeds the exact integer range"))?;
        Ok(())
    }

    fn add_line(&mut self, line: &BankStatementLine) -> Result<(), BookError> {
        self.add(line.amount.mantissa, line.side == Side::Credit)
    }
}

/// Active reconciliation progress at one fixed prefix. `remaining` includes
/// occupied lines under other interpretations as well as proposed and
/// unmatched lines. `outstanding` covers only the candidate search window.
/// Matching every line and equal closing balances are separate observations;
/// neither observation publishes an attestation or creates a posting lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankReconciliationProgress {
    pub confirmed: BankCashAmounts,
    pub occupied: BankCashAmounts,
    pub remaining: BankCashAmounts,
    pub proposed: BankCashAmounts,
    pub unmatched: BankCashAmounts,
    pub outstanding: BankCashAmounts,
    pub all_statement_lines_confirmed: bool,
    pub closing_balances_equal: bool,
}

#[derive(Clone, Debug)]
pub struct BankMatchReport {
    pub manifest_oid: Oid,
    pub manifest: BankImportManifest,
    pub known_at: CommitSeq,
    pub account_code: String,
    pub date_window_days: u32,
    /// Inclusive candidate search bounds, clipped to the representable civil
    /// day domain. Both are absent when the statement contains no lines.
    /// The source adapters do not establish a complete statement start date.
    pub candidate_from: Option<DateDay>,
    pub candidate_through: Option<DateDay>,
    /// Unmatched book legs describe only the candidate search, not a complete
    /// inventory of outstanding items across this account's history.
    pub outstanding_scope: &'static str,
    pub outstanding_complete: bool,
    pub decision_epoch: [u8; 32],
    pub lines: Vec<BankStatementLine>,
    pub candidates: Vec<BankMatchCandidate>,
    /// Active immutable confirmations for this exact retained interpretation.
    /// Their original proposal and attribution remain in the native record.
    pub confirmed_matches: Vec<BankMatchRecorded>,
    /// Every active cash-leg claim in the book at `known_at`, including claims
    /// from other statements. Candidate ordinals still index the full vector.
    pub consumed_cash_legs: Vec<(VId, u16)>,
    /// Every active source-line claim at `known_at`, independent of parser or
    /// account remapping. Keys are original statement identities and ordinals.
    pub occupied_bank_lines: Vec<(Oid, u32)>,
    pub proposals: Vec<ReconciliationMatch>,
    pub book_closing_balance: i128,
    /// Statement closing less posted book closing, in the bound unit.
    pub closing_difference: i128,
    pub progress: BankReconciliationProgress,
    pub verified_predecessors: usize,
}

fn reconciliation_progress(
    lines: &[BankStatementLine],
    proposals: &[ReconciliationMatch],
    candidates: &[BankMatchCandidate],
    confirmed_matches: &[BankMatchRecorded],
    occupied_bank_lines: &BTreeSet<(Oid, u32)>,
    consumed_cash_legs: &BTreeSet<(VId, u16)>,
    closing_difference: i128,
) -> Result<BankReconciliationProgress, BookError> {
    if lines.len() != proposals.len() {
        return Err(corrupt(
            "reconciliation progress needs one proposal per source line",
        ));
    }
    let confirmed_lines: BTreeSet<_> = confirmed_matches
        .iter()
        .map(|recorded| {
            (
                recorded.confirmation.statement_oid,
                recorded.confirmation.line_ordinal,
            )
        })
        .collect();
    let source_lines: BTreeSet<_> = lines
        .iter()
        .map(|line| (line.statement_oid, line.line_ordinal))
        .collect();
    if confirmed_lines.len() != confirmed_matches.len()
        || source_lines.len() != lines.len()
        || !confirmed_lines.is_subset(&source_lines)
        || !confirmed_lines.is_subset(occupied_bank_lines)
    {
        return Err(corrupt(
            "reconciliation progress has inconsistent source-line claims",
        ));
    }
    let mut progress = BankReconciliationProgress {
        confirmed: BankCashAmounts::default(),
        occupied: BankCashAmounts::default(),
        remaining: BankCashAmounts::default(),
        proposed: BankCashAmounts::default(),
        unmatched: BankCashAmounts::default(),
        outstanding: BankCashAmounts::default(),
        all_statement_lines_confirmed: confirmed_lines.len() == lines.len(),
        closing_balances_equal: closing_difference == 0,
    };
    let mut selected_ordinals = BTreeSet::new();
    for (line, proposal) in lines.iter().zip(proposals) {
        let line_oid = line.oid().map_err(|e| corrupt(e.to_string()))?;
        if proposal.bank_line_ids.as_slice() != [line_oid] {
            return Err(corrupt(
                "a progress proposal does not identify its source line",
            ));
        }
        let key = (line.statement_oid, line.line_ordinal);
        if confirmed_lines.contains(&key) {
            progress.confirmed.add_line(line)?;
            continue;
        }
        progress.remaining.add_line(line)?;
        if occupied_bank_lines.contains(&key) {
            progress.occupied.add_line(line)?;
        } else if let Some(ordinal) = proposal.matched_entry_ordinal {
            let candidate = candidates
                .get(
                    usize::try_from(ordinal)
                        .map_err(|_| corrupt("invalid progress candidate ordinal"))?,
                )
                .ok_or_else(|| corrupt("missing progress candidate"))?;
            if candidate.candidate.entry_ordinal != ordinal
                || consumed_cash_legs
                    .contains(&(candidate.candidate.entry_ref.vid, candidate.leg_ordinal))
                || !selected_ordinals.insert(ordinal)
            {
                return Err(corrupt(
                    "a progress proposal reuses or misidentifies a cash leg",
                ));
            }
            progress.proposed.add_line(line)?;
        } else {
            progress.unmatched.add_line(line)?;
        }
    }
    for candidate in candidates {
        if selected_ordinals.contains(&candidate.candidate.entry_ordinal)
            || consumed_cash_legs
                .contains(&(candidate.candidate.entry_ref.vid, candidate.leg_ordinal))
        {
            continue;
        }
        progress.outstanding.add(
            candidate.candidate.amount.mantissa,
            candidate.candidate.side == Side::Debit,
        )?;
    }
    Ok(progress)
}

fn intake_error(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::DOCUMENT_INTAKE,
        exit::USAGE,
        message,
        "plan §9.5; exact bank statement parsing and opening + activity = closing",
        "provide one internally balanced statement in the declared --bank-format; use exact fixed-scale decimal amounts, never scientific notation",
    )
}

fn corrupt(message: impl Into<String>) -> BookError {
    KernelError::Corrupt(format!("bank import closure: {}", message.into())).into()
}

fn closure_drift(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::DOCUMENT_DRIFT,
        exit::VERIFICATION,
        format!("bank import closure: {}", message.into()),
        "FA-INV-04; FA-INV-05; plan §9.5 (the retained source and interpretation verify)",
        "preserve the store and investigate the retained bank statement, manifest and import receipt before relying on a match",
    )
}

fn policy_kind(policy: &EvidencePolicy, name: &str) -> Result<u8, BookError> {
    policy
        .kind_by_name(name)
        .map(|row| row.tag)
        .ok_or_else(|| corrupt(format!("missing registered document kind {name}")))
}

fn parsed(format: BankFormat, bytes: &[u8]) -> Result<BankStatementExtract, Refusal> {
    let text = core::str::from_utf8(bytes)
        .map_err(|_| intake_error("the bank statement must be valid UTF-8"))?;
    let units = fa_formats::UnitCatalog::embedded().map_err(|e| intake_error(e.to_string()))?;
    let parse = match format {
        BankFormat::Camt053 => fa_formats::bank::parse_camt053,
        BankFormat::Camt052 => fa_formats::bank::parse_camt052,
        BankFormat::Bai2 => fa_formats::bank::parse_bai2,
        BankFormat::Ofx => fa_formats::bank::parse_ofx_qbo,
        BankFormat::Mt940 => fa_formats::bank::parse_mt940,
        BankFormat::Csv => fa_formats::bank::parse_bank_csv,
    };
    let extract = parse(text, &units).map_err(|e| intake_error(e.to_string()))?;
    if extract.lines.len() > MAX_BANK_LINES {
        return Err(intake_error(format!(
            "this statement has {} lines; max_import_documents={} permits at most {MAX_BANK_LINES} lines plus the source and manifest in one atomic import; request a smaller statement from the source",
            extract.lines.len(),
            fa_model::limits::MAX_IMPORT_DOCUMENTS,
        )));
    }
    for line in &extract.lines {
        if line.amount.mantissa <= 0
            || line.counterparty.len() > fa_model::limits::MAX_MEMO_BYTES
            || line.reference.len() > fa_model::limits::MAX_MEMO_BYTES
        {
            return Err(intake_error(format!(
                "bank line {} needs a positive exact amount and counterparty/reference of at most {} UTF-8 bytes",
                line.line_ordinal,
                fa_model::limits::MAX_MEMO_BYTES,
            )));
        }
        if line.booking_date > extract.statement_date {
            return Err(intake_error(format!(
                "bank line {} books after the statement closing date",
                line.line_ordinal,
            )));
        }
    }
    extract
        .verify_internal_balance()
        .map_err(|e| intake_error(e.to_string()))?;
    Ok(extract)
}

fn bank_lines(extract: &BankStatementExtract, statement_oid: Oid) -> Vec<BankStatementLine> {
    extract
        .lines
        .iter()
        .map(|line| BankStatementLine {
            statement_oid,
            statement_seq: extract.sequence_number,
            line_ordinal: line.line_ordinal,
            booking_date: line.booking_date,
            value_date: line.value_date,
            side: line.side,
            amount: line.amount,
            counterparty: line.counterparty.clone(),
            reference: line.reference.clone(),
        })
        .collect()
}

struct VerifiedBankImport {
    manifest: BankImportManifest,
    extract: BankStatementExtract,
    lines: Vec<BankStatementLine>,
    witness: BankImportWitness,
}

fn predecessor_error(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::BANK_CONTINUITY,
        exit::REFUSAL,
        message,
        "plan §9.5 (explicit predecessor continuity is checked against the retained source)",
        "select the immediately preceding --previous-import for this bank account; correct source gaps or import without a predecessor as explicitly unlinked evidence",
    )
}

fn same_bank_source(
    current: &BankStatementExtract,
    previous: &BankStatementExtract,
) -> Result<(), Refusal> {
    if current.instrument_account_id.trim().is_empty()
        || previous.instrument_account_id.trim().is_empty()
        || current.instrument_account_id != previous.instrument_account_id
        || current.currency != previous.currency
    {
        return Err(predecessor_error(
            "the retained predecessor identifies a different bank account or currency, or its bank identity is absent",
        ));
    }
    Ok(())
}

fn chain_bound() -> Refusal {
    predecessor_error(format!(
        "bank predecessor history exceeds max_bank_predecessor_depth={}; no prefix was accepted as the complete checked chain",
        fa_model::limits::MAX_BANK_PREDECESSOR_DEPTH,
    ))
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    fn authorize_bank(&self, cx: &PurposeContexts, cap: &Capability) -> Outcome<()> {
        if let Err(denial) = fa_policy::admit_read(cap, cap.holder(), self.context().book_id)
            .and_then(|()| fa_policy::require(cap, Op::Reconcile, "working with bank statements"))
            .and_then(|()| fa_policy::reach(cap, &Reach::whole_book(true), None))
        {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        self.query(cx, |db, book| {
            Ok(fa_journal::policy::current_at(db, book, cap)?.map(|_| ()))
        })
    }

    fn bank_account(
        &self,
        cx: &PurposeContexts,
        account: VId,
        unit: UnitId,
        known_at: CommitSeq,
    ) -> Outcome<fa_journal::rows::AccountRow> {
        self.query(cx, |db, book| {
            let Some(row) = db.vertex_at(account, known_at).map_err(KernelError::from)? else {
                return Ok(Err(Refusal::new(code::UNKNOWN_ACCOUNT, exit::REFUSAL,
                    format!("bank account {:032x} does not exist at the selected coordinate", account.0),
                    "plan §9.5 (an explicit bank-to-GL account mapping)",
                    "use a debit-normal asset leaf from fa chart list --json")));
            };
            if !row.labels.contains(&fa_model::symbols::label::ACCOUNT) {
                return Ok(Err(intake_error("the bank mapping does not name an Account")));
            }
            let account = fa_journal::rows::AccountRow::decode(&row)?;
            if !account.is_leaf || account.normal_balance != 0 || account.account_type != AccountType::ASSET.0 {
                return Ok(Err(intake_error("bank matching currently requires a debit-normal Asset leaf (cash); liability and credit-card account sign policies are not admitted")));
            }
            if !book.units.get(unit).is_some_and(|unit| matches!(unit.kind, fa_money::UnitKind::Currency { .. })) {
                return Ok(Err(intake_error("the statement must use a registered currency unit")));
            }
            match account.unit_policy {
                UnitPolicy::Single(fixed) if fixed != unit => {
                    return Ok(Err(Refusal::new(code::UNIT_POLICY, exit::REFUSAL,
                        "the bank statement currency differs from the mapped account's fixed unit",
                        "plan §5.2; §9.5 (no implicit bank-statement FX conversion)",
                        "select the cash account for this statement's currency")));
                }
                _ => {}
            }
            Ok(Ok(account))
        })
    }

    /// One atomic intake. Linked v2 imports replay their explicit predecessor
    /// chain and publish one native, immutable choice for this account/source.
    /// Exact re-imports return the original receipt across authorized uploaders.
    pub async fn import_bank_statement(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        request: BankImportRequest,
    ) -> Outcome<BankImportRecorded> {
        if let Err(refusal) = self.preflight_intake(cx, capability, IntakeAction::BankImport)? {
            return Ok(Err(refusal));
        }
        let policy = EvidencePolicy::embedded()?;
        if u64::try_from(request.bytes.len()).map_or(true, |size| size > policy.max_document_bytes)
        {
            return Ok(Err(intake_error(format!(
                "bank statement exceeds max_document_bytes={}",
                policy.max_document_bytes,
            ))));
        }
        let extract = match parsed(request.format, &request.bytes) {
            Ok(extract) => extract,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let Some(unit) = self.context().units.lookup(&extract.currency) else {
            return Ok(Err(intake_error(
                "the statement currency is not registered in this book",
            )));
        };
        if extract.lines.iter().any(|line| line.amount.unit != unit) {
            return Ok(Err(intake_error(
                "parsed line units differ from the statement's registered book currency",
            )));
        }
        let known_at = self.head(cx)?;
        let account = match self.bank_account(cx, request.account, unit, known_at)? {
            Ok(account) => account,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let source = Document {
            book_id: self.context().book_id,
            kind: policy_kind(&policy, "BankStatement")?,
            mime: request.format.mime().into(),
            grade: fa_journal::upload::upload_grade(&policy, capability.sod_profile())?,
            retrieved_by: capability.holder(),
            bytes: request.bytes,
        };
        let predecessors = if let Some(previous_oid) = request.previous_manifest {
            let previous = match self
                .load_bank_import(cx, capability, previous_oid, known_at)
                .await?
            {
                Ok(previous) => previous,
                Err(refusal) => return Ok(Err(refusal)),
            };
            if let Err(refusal) = same_bank_source(&extract, &previous.extract) {
                return Ok(Err(refusal));
            }
            let witnesses = match self
                .verify_bank_predecessors(cx, capability, &previous, known_at)
                .await?
            {
                Ok(witnesses) => witnesses,
                Err(refusal) => return Ok(Err(refusal)),
            };
            if witnesses.len() > fa_model::limits::MAX_BANK_PREDECESSOR_DEPTH {
                return Ok(Err(chain_bound()));
            }
            if witnesses
                .iter()
                .any(|previous| previous.manifest().statement_oid == source.oid())
            {
                return Ok(Err(predecessor_error(
                    "the selected predecessor history already contains this source statement",
                )));
            }
            witnesses
        } else {
            Vec::new()
        };
        let lines = bank_lines(&extract, source.oid());
        let mut documents = Vec::with_capacity(lines.len() + 2);
        let derived_grade = fa_journal::upload::upload_grade(&policy, Profile::Agent)?;
        let line_kind = policy_kind(&policy, "Other")?;
        let mut line_oids = Vec::with_capacity(lines.len());
        for line in lines {
            let bytes = line.canonical_bytes().map_err(|e| corrupt(e.to_string()))?;
            BankStatementLine::decode(&bytes).map_err(|e| corrupt(e.to_string()))?;
            let document = Document {
                book_id: self.context().book_id,
                kind: line_kind,
                mime: LINE_MIME.into(),
                grade: derived_grade,
                retrieved_by: capability.holder(),
                bytes,
            };
            line_oids.push(document.oid());
            documents.push(document);
        }
        let manifest = BankImportManifest {
            book_id: self.context().book_id,
            account: request.account,
            format: request.format,
            statement_oid: source.oid(),
            statement_commit: source.doc_commit(),
            unit,
            sequence_number: extract.sequence_number,
            statement_date: extract.statement_date,
            opening_balance: extract.opening_balance,
            closing_balance: extract.closing_balance,
            line_oids,
            predecessor: predecessors.first().map(BankImportWitness::predecessor),
        };
        if let Some(previous) = predecessors.first()
            && let Err(refusal) = manifest.verify_predecessor(previous)
        {
            return Ok(Err(refusal));
        }
        let mut derivations = documents.clone();
        documents.push(source);
        let manifest_document = Document {
            book_id: manifest.book_id,
            kind: policy_kind(&policy, "Workpaper")?,
            mime: MANIFEST_MIME.into(),
            grade: derived_grade,
            retrieved_by: capability.holder(),
            bytes: manifest
                .canonical_bytes()
                .map_err(|e| corrupt(e.to_string()))?,
        };
        let manifest_oid = manifest_document.oid();
        derivations.push(manifest_document.clone());
        documents.push(manifest_document);
        let previous_receipt = match self.bank_import_receipt(cx, &manifest, manifest_oid)? {
            Ok(receipt) => receipt,
            Err(refusal) => return Ok(Err(refusal)),
        };
        // An unlinked import recorded before this statement gained predecessor
        // linkage stays an exact repeat: it returns its original receipt. Only
        // a new unlinked manifest meets the recorded link below.
        let linked_receipt_recorded = match previous_receipt {
            Some(receipt) if manifest.predecessor.is_none() => {
                return Ok(Ok(BankImportRecorded {
                    manifest_oid,
                    manifest: manifest.clone(),
                    receipt: ImportRecorded {
                        receipt,
                        recorded: Vec::new(),
                        already_held: manifest.closure(manifest_oid),
                        already_recorded: true,
                    },
                    verified_predecessors: 0,
                }));
            }
            other => other.is_some(),
        };
        let existing_link = match self.query(cx, |db, book| {
            Ok(fa_journal::import::read_bank_statement_link(
                db,
                book.book_id,
                manifest.account,
                manifest.statement_oid,
            )?)
        })? {
            Ok(link) => link,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if let Some(existing) = existing_link {
            if existing.manifest != manifest || existing.manifest_oid != manifest_oid {
                return Ok(Err(Refusal::new(
                    code::IDEMPOTENCY_CONFLICT,
                    exit::CONFLICT,
                    format!(
                        "this account's statement already has predecessor linkage in manifest {}",
                        fa_journal::evidence::hex(&existing.manifest_oid.0),
                    ),
                    "plan §4.9; §9.5 (one immutable predecessor choice per account/source statement)",
                    "repeat the original statement, parser, account and --previous-import; another uploader or import key cannot replace the recorded link",
                )));
            }
            let retry_at = self.head(cx)?;
            let verified = match self
                .load_bank_import(cx, capability, manifest_oid, retry_at)
                .await?
            {
                Ok(verified) => verified,
                Err(refusal) => return Ok(Err(refusal)),
            };
            return Ok(Ok(BankImportRecorded {
                manifest_oid,
                receipt: ImportRecorded {
                    receipt: verified.witness.receipt().clone(),
                    recorded: Vec::new(),
                    already_held: manifest.closure(manifest_oid),
                    already_recorded: true,
                },
                manifest,
                verified_predecessors: predecessors.len(),
            }));
        }
        if linked_receipt_recorded {
            return Ok(Err(closure_drift(
                "a linked manifest was imported without its atomic native predecessor record",
            )));
        }
        let key = fa_journal::evidence::hex(&manifest_oid.0);
        let import_request = fa_journal::ImportRequest {
            principal: capability.holder(),
            source: IntakeSource::Upload {
                principal: capability.holder(),
            },
            idempotency_key: key.into_bytes(),
            effective_date: extract.statement_date,
            description: self.seal_text(cx, "Bank statement and canonical parsed lines")?,
            documents,
        };
        let context = self.context().clone();
        let preparation = match fa_journal::import::prepare_import_in_store(
            &mut self.db,
            cx,
            &context,
            capability,
            &self.blobs,
            import_request,
        )
        .await?
        {
            Ok(preparation) => preparation,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let receipt = match preparation {
            fa_journal::import::ImportPreparation::AlreadyRecorded(receipt) => receipt,
            fa_journal::import::ImportPreparation::Ready(mut prepared) => {
                if let Err(refusal) = prepared.witness_account(&self.db, &account)? {
                    prepared.abort();
                    return Ok(Err(refusal));
                }
                for previous in &predecessors {
                    if let Err(refusal) = prepared.witness_bank_import(&self.db, previous)? {
                        prepared.abort();
                        return Ok(Err(refusal));
                    }
                }
                match prepared.bind_bank_statement(&mut self.db, &manifest, predecessors.first())? {
                    Err(refusal) => {
                        prepared.abort();
                        return Ok(Err(refusal));
                    }
                    Ok(Some(recorded)) => {
                        prepared.abort();
                        return Ok(Ok(BankImportRecorded {
                            manifest_oid,
                            manifest,
                            receipt: recorded,
                            verified_predecessors: predecessors.len(),
                        }));
                    }
                    Ok(None) => {}
                }
                let prepared =
                    match prepared.with_document_derivations(&mut self.db, cx, &derivations)? {
                        Ok(prepared) => prepared,
                        Err(refusal) => return Ok(Err(refusal)),
                    };
                match prepared.commit(&mut self.db, cx).await? {
                    Ok(receipt) => receipt,
                    Err(refusal) => return Ok(Err(refusal)),
                }
            }
        };
        if receipt.already_recorded && manifest.predecessor.is_some() {
            let retry_at = self.head(cx)?;
            if let Err(refusal) = self
                .load_bank_import(cx, capability, manifest_oid, retry_at)
                .await?
            {
                return Ok(Err(refusal));
            }
        }
        Ok(Ok(BankImportRecorded {
            manifest_oid,
            manifest,
            receipt,
            verified_predecessors: predecessors.len(),
        }))
    }

    fn bank_import_receipt(
        &self,
        cx: &PurposeContexts,
        manifest: &BankImportManifest,
        manifest_oid: Oid,
    ) -> Outcome<Option<RunReceipt>> {
        self.query(cx, |db, book| {
            let Some(_) = fa_journal::evidence::document_record(db, &manifest_oid)? else {
                return Ok(Ok(None));
            };
            let chain = fa_journal::custody::custody_chain(db, &manifest_oid)?;
            let Some((event, _)) = chain.first() else {
                return Ok(Err(closure_drift("manifest has no import receipt")));
            };
            let CustodyBody::Receipt {
                run_ref: Some(run), ..
            } = &event.body
            else {
                return Ok(Err(closure_drift(
                    "manifest was not recorded in an atomic bank import",
                )));
            };
            let Some(receipt) = fa_journal::import::read_run(db, *run)? else {
                return Ok(Err(closure_drift("manifest import run is missing")));
            };
            Ok(fa_journal::import::verify_receipt_in(
                db,
                book.book_id,
                &receipt,
                &manifest.closure(manifest_oid),
            )?
            .map(|()| Some(receipt)))
        })
    }

    async fn full_bank_document(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        oid: Oid,
    ) -> Outcome<Document> {
        const FULL_SOURCE_AUTHORITY: &str = "bank continuity and matching must replay the complete original BankStatement; a redacted view cannot supply those bytes. Use an authorized capability allowing full source disclosure. On the embedded-owner CLI, pass --grant privileged explicitly; launch-bound MCP templates cannot add or hold that operation";
        Ok(match self.read_document_for(cx, capability, &oid).await? {
            Err(mut refusal) if refusal.code == code::REDACTED_VIEW_ABSENT => {
                refusal.fix = FULL_SOURCE_AUTHORITY.into();
                Err(refusal)
            }
            Err(refusal) => Err(refusal),
            Ok(DocumentRead::Full(document)) => Ok(document),
            Ok(DocumentRead::Redacted(_)) => Err(Refusal::new(
                code::CAPABILITY,
                exit::SAFETY,
                "the bank import's retained evidence is redacted under this capability",
                "plan §9.5–§9.6 (bank continuity and matching require the exact statement and parsed closure)",
                FULL_SOURCE_AUTHORITY,
            )),
        })
    }

    /// Capture native publication witnesses before replaying the complete
    /// governed source and every canonical line. This is shared by matching
    /// and explicit continuity; no caller-supplied prior balance is accepted.
    async fn load_bank_import(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        manifest_oid: Oid,
        seq: CommitSeq,
    ) -> Outcome<VerifiedBankImport> {
        let document = match self
            .full_bank_document(cx, capability, manifest_oid)
            .await?
        {
            Ok(doc) => doc,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let policy = EvidencePolicy::embedded()?;
        if document.kind != policy_kind(&policy, "Workpaper")? || document.mime != MANIFEST_MIME {
            return Ok(Err(Refusal::new(
                code::DOCUMENT_INTAKE,
                exit::USAGE,
                "the oid names a document that is not a bank import manifest",
                "plan §9.5 (a bank import is identified by the manifest_oid its import returned)",
                "pass the manifest_oid that `fa bank import` printed: --import for `fa bank match`, --previous-import for `fa bank import`",
            )));
        }
        let manifest = match BankImportManifest::decode(&document.bytes) {
            Ok(manifest) => manifest,
            Err(error) => return Ok(Err(closure_drift(error.to_string()))),
        };
        if manifest.book_id != self.context().book_id {
            return Ok(Err(closure_drift("manifest belongs to another book")));
        }
        let receipt = match self.bank_import_receipt(cx, &manifest, manifest_oid)? {
            Ok(Some(receipt)) => receipt,
            Ok(None) => return Ok(Err(closure_drift("manifest has no retained receipt"))),
            Err(refusal) => return Ok(Err(refusal)),
        };
        if receipt.recorded_at > seq {
            return Ok(Err(Refusal::new(
                code::COORDINATE,
                exit::USAGE,
                "the bank import did not yet exist at the selected known-at sequence",
                "plan §7.1 (evidence cannot contribute before its recorded sequence)",
                format!("select --as-known-at {} or later", receipt.recorded_at.0),
            )));
        }
        let witness = match self.query(cx, |db, book| {
            Ok(BankImportWitness::capture(
                db,
                book.book_id,
                &document,
                &receipt,
            )?)
        })? {
            Ok(witness) => witness,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let source = match self
            .full_bank_document(cx, capability, manifest.statement_oid)
            .await?
        {
            Ok(doc) => doc,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if source.kind != policy_kind(&policy, "BankStatement")?
            || source.doc_commit() != manifest.statement_commit
        {
            return Ok(Err(closure_drift(
                "manifest source commitment or document kind differs",
            )));
        }
        let extract = match parsed(manifest.format, &source.bytes) {
            Ok(extract) => extract,
            Err(error) => return Ok(Err(closure_drift(error.to_string()))),
        };
        let Some(unit) = self.context().units.lookup(&extract.currency) else {
            return Ok(Err(closure_drift(
                "source currency is not registered in this book",
            )));
        };
        if manifest.unit != unit
            || manifest.sequence_number != extract.sequence_number
            || manifest.statement_date != extract.statement_date
            || manifest.opening_balance != extract.opening_balance
            || manifest.closing_balance != extract.closing_balance
            || manifest.line_oids.len() != extract.lines.len()
        {
            return Ok(Err(closure_drift(
                "manifest interpretation differs from the retained source",
            )));
        }
        let lines = bank_lines(&extract, manifest.statement_oid);
        for (oid, line) in manifest.line_oids.iter().zip(&lines) {
            let doc = match self.full_bank_document(cx, capability, *oid).await? {
                Ok(doc) => doc,
                Err(refusal) => return Ok(Err(refusal)),
            };
            if doc.kind != policy_kind(&policy, "Other")?
                || doc.mime != LINE_MIME
                || doc.bytes != line.canonical_bytes().map_err(|e| corrupt(e.to_string()))?
            {
                return Ok(Err(closure_drift(
                    "a retained BankLine differs from its source parse",
                )));
            }
        }
        Ok(Ok(VerifiedBankImport {
            manifest,
            extract,
            lines,
            witness,
        }))
    }

    async fn verify_bank_predecessors(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        first: &VerifiedBankImport,
        known_at: CommitSeq,
    ) -> Outcome<Vec<BankImportWitness>> {
        let mut witnesses = vec![first.witness.clone()];
        let mut seen_manifests = BTreeSet::from([first.witness.manifest_oid()]);
        let mut seen_sources = BTreeSet::from([first.manifest.statement_oid]);
        let mut current = first.manifest.clone();
        let mut bank_identity = first.extract.instrument_account_id.clone();
        let mut currency = first.extract.currency.clone();
        while let Some(binding) = current.predecessor.clone() {
            if witnesses.len() > fa_model::limits::MAX_BANK_PREDECESSOR_DEPTH {
                return Ok(Err(chain_bound()));
            }
            if !seen_manifests.insert(binding.manifest_oid)
                || !seen_sources.insert(binding.statement_oid)
            {
                return Ok(Err(closure_drift(
                    "the predecessor history repeats a manifest or source statement",
                )));
            }
            let previous = match self
                .load_bank_import(cx, capability, binding.manifest_oid, known_at)
                .await?
            {
                Ok(previous) => previous,
                Err(refusal) => return Ok(Err(refusal)),
            };
            if let Err(refusal) = current.verify_predecessor(&previous.witness) {
                return Ok(Err(refusal));
            }
            if bank_identity.trim().is_empty()
                || previous.extract.instrument_account_id.trim().is_empty()
                || bank_identity != previous.extract.instrument_account_id
                || currency != previous.extract.currency
            {
                return Ok(Err(closure_drift(
                    "the predecessor chain changes its bank account identity or currency",
                )));
            }
            bank_identity = previous.extract.instrument_account_id;
            currency = previous.extract.currency;
            current = previous.manifest;
            witnesses.push(previous.witness);
        }
        Ok(Ok(witnesses))
    }

    /// Recreate deterministic exact-amount/date/reference proposals from a
    /// verified intake and one journal prefix. The source and every parsed
    /// line remain evidence; neither candidate scores nor proposals confirm a
    /// match, change an amount, or lock a reconciled period.
    pub async fn match_bank_statement(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        request: BankMatchRequest,
    ) -> Outcome<BankMatchReport> {
        self.match_bank_statement_for(cx, capability, request, capability.holder())
            .await
    }

    /// Replaying a proposal preserves its selected principal while admission
    /// and every source read remain bound to the current caller.
    async fn match_bank_statement_for(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        request: BankMatchRequest,
        proposer: VId,
    ) -> Outcome<BankMatchReport> {
        if let Err(refusal) = self.authorize_bank(cx, capability)? {
            return Ok(Err(refusal));
        }
        let Ok(window) = i32::try_from(request.date_window_days) else {
            return Ok(Err(intake_error(
                "the matching date window exceeds the civil-date domain",
            )));
        };
        let seq = self.query(cx, |db, _| {
            Ok(fa_registers::resolve_known_at(db, request.known_at)?)
        })?;
        let verified = match self
            .load_bank_import(cx, capability, request.manifest_oid, seq)
            .await?
        {
            Ok(verified) => verified,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let predecessors = match self
            .verify_bank_predecessors(cx, capability, &verified, seq)
            .await?
        {
            Ok(witnesses) => witnesses,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let verified_predecessors = predecessors.len().saturating_sub(1);
        let manifest = verified.manifest;
        let lines = verified.lines;
        let context = self.context().clone();
        let active_claims = match fa_journal::bank::read_bank_match_claims(
            &mut self.db,
            cx,
            &context,
            capability,
            Some(seq),
        )
        .await?
        {
            Ok(claims) => claims,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let consumed_cash_legs: BTreeSet<_> = active_claims
            .iter()
            .map(|recorded| {
                (
                    recorded.confirmation.entry_ref.vid,
                    recorded.confirmation.leg_ordinal,
                )
            })
            .collect();
        let occupied_bank_lines: BTreeSet<_> = active_claims
            .iter()
            .map(|recorded| {
                (
                    recorded.confirmation.statement_oid,
                    recorded.confirmation.line_ordinal,
                )
            })
            .collect();
        let mut confirmed_matches = Vec::new();
        for recorded in &active_claims {
            let confirmation = &recorded.confirmation;
            if confirmation.statement_oid != manifest.statement_oid
                || confirmation.manifest_oid != request.manifest_oid
            {
                continue;
            }
            let Some(index) = lines
                .iter()
                .position(|line| line.line_ordinal == confirmation.line_ordinal)
            else {
                return Ok(Err(closure_drift(
                    "an active confirmation names a line absent from its retained statement",
                )));
            };
            if confirmation.account != manifest.account
                || confirmation.line_document_oid != manifest.line_oids[index]
            {
                return Ok(Err(closure_drift(
                    "an active confirmation disagrees with its retained manifest's account or line document",
                )));
            }
            confirmed_matches.push(recorded.clone());
        }
        let unit = manifest.unit;
        let account = match self.bank_account(cx, manifest.account, unit, seq)? {
            Ok(account) => account,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let first_day = lines.iter().map(|line| line.booking_date.0).min();
        let candidate_from = first_day.map(|first| DateDay(first.saturating_sub(window)));
        let candidate_through =
            first_day.map(|_| DateDay(manifest.statement_date.0.saturating_add(window)));
        if let Err(refusal) = fa_journal::scratch::ensure_history(&mut self.db, cx).await? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = self.authorize_bank(cx, capability)? {
            return Ok(Err(refusal));
        }
        let (candidates, book_closing_balance, epoch) = self.query(cx, |db, book| {
            fa_journal::entry_history::verify_entry_history(db, cx, book, Some(seq))?;
            let entries = fa_registers::entries_at(db, book, seq)?;
            let mut candidates = Vec::new();
            let mut balance = 0_i128;
            for (vid, entry, recorded_at) in entries {
                if entry.proposal.class == EntryClass::PENDING {
                    continue;
                }
                let day = entry.proposal.effective_date;
                for (ordinal, leg) in entry.proposal.legs.iter().enumerate() {
                    if leg.account_ref != manifest.account || leg.amount.unit != unit {
                        continue;
                    }
                    if day <= manifest.statement_date {
                        balance = match leg.side {
                            Side::Debit => balance.checked_add(leg.amount.mantissa),
                            Side::Credit => balance.checked_sub(leg.amount.mantissa),
                        }
                        .ok_or_else(|| corrupt("cash balance exceeds the exact integer range"))?;
                    }
                    let within_range = candidate_from
                        .zip(candidate_through)
                        .is_some_and(|(from, through)| from <= day && day <= through);
                    if !within_range {
                        continue;
                    }
                    let reference = match &leg.memo {
                        Some(memo) => memo
                            .open(&book.seal_key, fa_model::limits::MAX_MEMO_BYTES)
                            .map_err(|e| corrupt(format!("cannot open cash-leg reference: {e}")))?,
                        None => String::new(),
                    };
                    candidates.push(BankMatchCandidate {
                        candidate: BookCandidateEntry {
                            entry_ref: entry.entry_ref(vid),
                            entry_ordinal: u64::try_from(candidates.len())
                                .map_err(|_| corrupt("too many cash candidates"))?,
                            effective_date: day,
                            side: leg.side,
                            amount: leg.amount,
                            counterparty: String::new(),
                            reference,
                        },
                        leg_ordinal: u16::try_from(ordinal)
                            .map_err(|_| corrupt("cash leg ordinal exceeds the Entry schema"))?,
                        recorded_at,
                    });
                }
            }
            let epoch = fa_journal::policy::security_policy_epoch(db)?;
            Ok((candidates, balance, epoch))
        })?;
        if let Err(refusal) = self
            .verify_bank_match_claim_sources(
                cx,
                capability,
                (request.manifest_oid, &manifest),
                &candidates,
                &active_claims,
                seq,
            )
            .await?
        {
            return Ok(Err(refusal));
        }
        let decision_epoch = domain_digest(
            b"fa:bank-match-policy:v1",
            &[
                &manifest.book_id.0,
                &epoch.to_le_bytes(),
                &PARSER_REVISION.to_le_bytes(),
            ],
        );
        let native: Vec<_> = candidates
            .iter()
            .filter(|candidate| {
                !consumed_cash_legs
                    .contains(&(candidate.candidate.entry_ref.vid, candidate.leg_ordinal))
            })
            .map(|candidate| candidate.candidate.clone())
            .collect();
        let config = MatcherConfig {
            policy_epoch: None,
            enforced_policy_epoch: decision_epoch,
            max_date_window_days: window,
            pinned_fallback_only: true,
            advisory_learned_scores_bps: BTreeMap::new(),
        };
        let available_lines: Vec<_> = lines
            .iter()
            .filter(|line| !occupied_bank_lines.contains(&(line.statement_oid, line.line_ordinal)))
            .cloned()
            .collect();
        let mut available_proposals =
            match_bank_lines(&available_lines, &native, &config, proposer)
                .map_err(|e| corrupt(e.to_string()))?
                .into_iter();
        let mut proposals = Vec::with_capacity(lines.len());
        for line in &lines {
            let proposal = if occupied_bank_lines.contains(&(line.statement_oid, line.line_ordinal))
            {
                // Preserve one position per source line. Consumers display
                // the retained fact in `confirmed_matches` for these rows.
                match_bank_lines(core::slice::from_ref(line), &[], &config, proposer)
                    .map_err(|e| corrupt(e.to_string()))?
                    .pop()
                    .ok_or_else(|| corrupt("the matcher omitted an occupied source line"))?
            } else {
                available_proposals
                    .next()
                    .ok_or_else(|| corrupt("the matcher omitted an available source line"))?
            };
            proposals.push(proposal);
        }
        if available_proposals.next().is_some() {
            return Err(corrupt(
                "the matcher produced an extra source-line proposal",
            ));
        }
        let bank_by_id = lines
            .iter()
            .map(|line| {
                line.oid()
                    .map(|id| (id, line.clone()))
                    .map_err(|e| corrupt(e.to_string()))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        for proposal in &proposals {
            let card = proposal
                .decision_card
                .canonical_bytes()
                .map_err(|e| corrupt(e.to_string()))?;
            if fa_policy::DecisionCard::decode(&card).is_err() {
                return Ok(Err(Refusal::new(
                    code::DOCUMENT_INTAKE,
                    exit::USAGE,
                    "the complete candidate decision card exceeds its registered wire bounds",
                    "plan §5.7 (a bank proposal retains a complete, replayable decision card)",
                    "narrow --date-window, or supply specific references on cash-leg memos and statement lines; no candidates were discarded",
                )));
            }
            // Validate against the selected leg, not a map that overwrites
            // earlier cash legs sharing the same EntryRef.
            let mut selected = BTreeMap::new();
            if let Some(ordinal) = proposal.matched_entry_ordinal {
                let candidate = candidates
                    .get(
                        usize::try_from(ordinal)
                            .map_err(|_| corrupt("invalid candidate ordinal"))?,
                    )
                    .ok_or_else(|| corrupt("missing selected candidate"))?;
                selected.insert(candidate.candidate.entry_ref, candidate.candidate.clone());
            }
            proposal
                .validate(decision_epoch, &bank_by_id, &selected)
                .map_err(|e| corrupt(e.to_string()))?;
        }
        let closing_difference = manifest
            .closing_balance
            .checked_sub(book_closing_balance)
            .ok_or_else(|| corrupt("closing-balance difference exceeds the exact integer range"))?;
        let progress = reconciliation_progress(
            &lines,
            &proposals,
            &candidates,
            &confirmed_matches,
            &occupied_bank_lines,
            &consumed_cash_legs,
            closing_difference,
        )?;
        Ok(Ok(BankMatchReport {
            manifest_oid: request.manifest_oid,
            manifest,
            known_at: seq,
            account_code: account.code,
            date_window_days: request.date_window_days,
            candidate_from,
            candidate_through,
            outstanding_scope: "unmatched_cash_legs_in_candidate_window",
            outstanding_complete: false,
            decision_epoch,
            lines,
            candidates,
            confirmed_matches,
            consumed_cash_legs: consumed_cash_legs.into_iter().collect(),
            occupied_bank_lines: occupied_bank_lines.into_iter().collect(),
            proposals,
            book_closing_balance,
            closing_difference,
            progress,
            verified_predecessors,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_model::Id128;

    fn manifest() -> BankImportManifest {
        BankImportManifest {
            book_id: Id128([3; 16]),
            account: VId(4),
            format: BankFormat::Camt053,
            statement_oid: Oid([5; 32]),
            statement_commit: [6; 32],
            unit: UnitId(1),
            sequence_number: 9,
            statement_date: DateDay(20_000),
            opening_balance: 100,
            closing_balance: 125,
            line_oids: vec![Oid([7; 32])],
            predecessor: None,
        }
    }

    #[test]
    fn bank_manifest_wire_binds_mapping_parser_source_and_order() {
        let expected = manifest();
        let bytes = expected.canonical_bytes().unwrap();
        assert_eq!(BankImportManifest::decode(&bytes).unwrap(), expected);
        assert!(bytes.starts_with(b"FA-BANK-IMPORT\x01\0\0\0"));
        for count in 0..bytes.len() {
            assert!(BankImportManifest::decode(&bytes[..count]).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(BankImportManifest::decode(&extra).is_err());
        let mut duplicate = expected.clone();
        duplicate.line_oids.push(duplicate.line_oids[0]);
        assert!(BankImportManifest::decode(&duplicate.canonical_bytes().unwrap()).is_err());
        let mut changed = expected.clone();
        changed.account = VId(10);
        assert_ne!(changed.canonical_bytes().unwrap(), bytes);
        changed = expected;
        changed.format = BankFormat::Csv;
        assert_ne!(changed.canonical_bytes().unwrap(), bytes);
    }

    #[test]
    fn progress_preserves_gross_directions_occupied_sources_and_exact_overflow() {
        let config = MatcherConfig {
            policy_epoch: None,
            enforced_policy_epoch: [11; 32],
            max_date_window_days: 3,
            pinned_fallback_only: true,
            advisory_learned_scores_bps: BTreeMap::new(),
        };
        let line = BankStatementLine {
            statement_oid: Oid([9; 32]),
            statement_seq: 1,
            line_ordinal: 1,
            booking_date: DateDay(20_000),
            value_date: DateDay(20_000),
            side: Side::Credit,
            amount: fa_money::Amount::new(UnitId(1), 1000),
            counterparty: String::new(),
            reference: String::new(),
        };
        let mut debit = line.clone();
        debit.line_ordinal = 2;
        debit.side = Side::Debit;
        let lines = vec![line, debit];
        let proposals = match_bank_lines(&lines, &[], &config, VId(12)).unwrap();
        let empty = BTreeSet::new();
        let progress =
            reconciliation_progress(&lines, &proposals, &[], &[], &empty, &BTreeSet::new(), 0)
                .unwrap();
        assert_eq!(
            progress.remaining,
            BankCashAmounts {
                inflow: 1000,
                outflow: 1000
            }
        );
        assert_eq!(progress.unmatched, progress.remaining);
        assert!(progress.closing_balances_equal);
        assert!(!progress.all_statement_lines_confirmed);

        let occupied = BTreeSet::from([(lines[0].statement_oid, lines[0].line_ordinal)]);
        let remapped =
            reconciliation_progress(&lines, &proposals, &[], &[], &occupied, &BTreeSet::new(), 0)
                .unwrap();
        assert_eq!(
            remapped.occupied,
            BankCashAmounts {
                inflow: 1000,
                outflow: 0
            }
        );
        assert_eq!(
            remapped.unmatched,
            BankCashAmounts {
                inflow: 0,
                outflow: 1000
            }
        );
        assert_eq!(remapped.remaining, progress.remaining);
        assert!(!remapped.all_statement_lines_confirmed);

        let mut overflowing = lines;
        overflowing[0].amount.mantissa = i128::MAX;
        overflowing[1].amount.mantissa = 1;
        overflowing[1].side = Side::Credit;
        let proposals = match_bank_lines(&overflowing, &[], &config, VId(12)).unwrap();
        assert!(
            reconciliation_progress(
                &overflowing,
                &proposals,
                &[],
                &[],
                &empty,
                &BTreeSet::new(),
                0,
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod provenance_tests;
