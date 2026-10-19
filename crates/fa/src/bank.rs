//! Bank statement intake and reproducible reconciliation proposals (§5.7 / §9.5).
//!
//! An intake is one ordinary, atomic Docket import: the original statement,
//! canonical BankLine documents, and a versioned manifest binding the parser
//! and the selected cash account. Matching reopens that retained closure and
//! verifies it against a fresh parse before reading the immutable journal.
//! Every result is a proposal under Teller's pinned deterministic fallback.
//! No match confirmation, reconciliation soft lock, or monetary entry is made.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_formats::bank::BankStatementExtract;
use fa_journal::custody::CustodyBody;
use fa_journal::evidence::Document;
use fa_journal::refusal::{Refusal, code, exit};
use fa_journal::{DocumentRead, ImportRecorded, KernelError, RunReceipt, UnitPolicy};
use fa_model::{AccountType, EntryClass, Id128, IntakeSource, Oid, Reader, Writer, domain_digest};
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

const IMPORT_MAGIC: &[u8; 14] = b"FA-BANK-IMPORT";
const IMPORT_MAJOR: u16 = 1;
const IMPORT_MINOR: u16 = 0;
const PARSER_REVISION: u16 = 1;
const MANIFEST_MIME: &str = "application/vnd.frankenaccounting.bank-import";
const LINE_MIME: &str = "application/vnd.frankenaccounting.bank-line";

/// A statement and its manifest occupy the two remaining slots of the
/// registered atomic Docket import bound. No partial statement is admitted.
pub const MAX_BANK_LINES: usize = fa_model::limits::MAX_IMPORT_DOCUMENTS - 2;

/// An explicitly selected parser. Its tag and revision are retained so a
/// later match never asks the caller to reinterpret the original evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BankFormat {
    Camt053,
    Camt052,
    Bai2,
    Ofx,
    Mt940,
    Csv,
}

impl BankFormat {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Camt053 => "camt053",
            Self::Camt052 => "camt052",
            Self::Bai2 => "bai2",
            Self::Ofx => "ofx",
            Self::Mt940 => "mt940",
            Self::Csv => "csv",
        }
    }

    #[must_use]
    pub fn parse_name(name: &str) -> Option<Self> {
        match name {
            "camt053" => Some(Self::Camt053),
            "camt052" => Some(Self::Camt052),
            "bai2" => Some(Self::Bai2),
            "ofx" => Some(Self::Ofx),
            "mt940" => Some(Self::Mt940),
            "csv" => Some(Self::Csv),
            _ => None,
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Camt053 => 1,
            Self::Camt052 => 2,
            Self::Bai2 => 3,
            Self::Ofx => 4,
            Self::Mt940 => 5,
            Self::Csv => 6,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Camt053),
            2 => Some(Self::Camt052),
            3 => Some(Self::Bai2),
            4 => Some(Self::Ofx),
            5 => Some(Self::Mt940),
            6 => Some(Self::Csv),
            _ => None,
        }
    }

    const fn mime(self) -> &'static str {
        match self {
            Self::Camt053 | Self::Camt052 => "application/xml",
            Self::Csv => "text/csv",
            Self::Ofx => "application/x-ofx",
            Self::Bai2 | Self::Mt940 => "text/plain",
        }
    }
}

/// The immutable, content-addressed interpretation of one source statement.
/// The account is the importer's explicit mapping, not a parser guess.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankImportManifest {
    pub book_id: Id128,
    pub account: VId,
    pub format: BankFormat,
    pub statement_oid: Oid,
    pub statement_commit: [u8; 32],
    pub unit: UnitId,
    pub sequence_number: u64,
    pub statement_date: DateDay,
    pub opening_balance: i128,
    pub closing_balance: i128,
    /// Document OIDs in statement order, distinct from BankStatementLine::oid.
    pub line_oids: Vec<Oid>,
}

impl BankImportManifest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut w = Writer::new();
        w.fixed(IMPORT_MAGIC)
            .u16(IMPORT_MAJOR)
            .u16(IMPORT_MINOR)
            .fixed(&self.book_id.0)
            .u128(self.account.0)
            .u8(self.format.tag())
            .u16(PARSER_REVISION)
            .fixed(&self.statement_oid.0)
            .fixed(&self.statement_commit)
            .u32(self.unit.0)
            .u64(self.sequence_number)
            .i32(self.statement_date.0)
            .i128(self.opening_balance)
            .i128(self.closing_balance)
            .list(&self.line_oids, |w, oid| {
                w.fixed(&oid.0);
            });
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, fa_model::DecodeError> {
        let mut r = Reader::new(bytes);
        if r.fixed::<14>("bank_import.magic")? != *IMPORT_MAGIC
            || r.u16("bank_import.major")? != IMPORT_MAJOR
            || r.u16("bank_import.minor")? != IMPORT_MINOR
        {
            return Err(r.invalid("bank_import.version"));
        }
        let book_id = Id128(r.fixed("bank_import.book")?);
        let account = VId(r.u128("bank_import.account")?);
        let format = BankFormat::from_tag(r.u8("bank_import.parser")?)
            .ok_or_else(|| r.invalid("bank_import.parser"))?;
        if r.u16("bank_import.parser_revision")? != PARSER_REVISION {
            return Err(r.invalid("bank_import.parser_revision"));
        }
        let result = Self {
            book_id,
            account,
            format,
            statement_oid: Oid(r.fixed("bank_import.statement_oid")?),
            statement_commit: r.fixed("bank_import.statement_commit")?,
            unit: UnitId(r.u32("bank_import.unit")?),
            sequence_number: r.u64("bank_import.sequence")?,
            statement_date: DateDay(r.i32("bank_import.statement_date")?),
            opening_balance: r.i128("bank_import.opening")?,
            closing_balance: r.i128("bank_import.closing")?,
            line_oids: r.list(MAX_BANK_LINES, "bank_import.lines", |r| {
                r.fixed("bank_import.line_oid").map(Oid)
            })?,
        };
        if result.line_oids.iter().collect::<BTreeSet<_>>().len() != result.line_oids.len() {
            return Err(r.invalid("bank_import.duplicate_line"));
        }
        r.finish()?;
        Ok(result)
    }

    fn closure(&self, manifest_oid: Oid) -> Vec<Oid> {
        let mut closure = self.line_oids.clone();
        closure.extend([self.statement_oid, manifest_oid]);
        closure.sort();
        closure
    }
}

/// Bytes are the exact original upload. No source grade or party identity
/// supplied by the caller can override the authenticated import session.
#[derive(Clone, Debug)]
pub struct BankImportRequest {
    pub account: VId,
    pub format: BankFormat,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct BankImportRecorded {
    pub manifest_oid: Oid,
    pub manifest: BankImportManifest,
    pub receipt: ImportRecorded,
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
    pub proposals: Vec<ReconciliationMatch>,
    pub book_closing_balance: i128,
    /// Statement closing less posted book closing, in the bound unit.
    pub closing_difference: i128,
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

    /// One atomic intake; exact re-imports return the original receipt even
    /// from a different authorized uploader. Parser output is conservatively
    /// AgentUpload evidence; it never upgrades the retained source's grade.
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
                policy.max_document_bytes
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
        let account = match self.bank_account(cx, request.account, unit, self.head(cx)?)? {
            Ok(account) => account,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let source = Document {
            book_id: self.context().book_id,
            kind: policy_kind(&policy, "BankStatement")?,
            mime: request.format.mime().into(),
            grade: fa_journal::upload::upload_grade(&policy, capability.profile())?,
            retrieved_by: capability.holder(),
            bytes: request.bytes,
        };
        let lines = bank_lines(&extract, source.oid());
        let mut documents = Vec::with_capacity(lines.len() + 2);
        let derived_grade = fa_journal::upload::upload_grade(&policy, Profile::Agent)?;
        let line_kind = policy_kind(&policy, "Other")?;
        let mut line_oids = Vec::with_capacity(lines.len());
        for line in lines {
            let bytes = line.canonical_bytes().map_err(|e| corrupt(e.to_string()))?;
            // The wire must be consumable by the retained BankLine decoder,
            // including all string and positive-mantissa bounds.
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
        };
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
        if let Some(receipt) = previous_receipt {
            return Ok(Ok(BankImportRecorded {
                manifest_oid,
                manifest: manifest.clone(),
                receipt: ImportRecorded {
                    receipt,
                    recorded: Vec::new(),
                    already_held: manifest.closure(manifest_oid),
                    already_recorded: true,
                },
            }));
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
                let prepared = match prepared.with_document_derivations(
                    &mut self.db,
                    cx,
                    &derivations,
                )? {
                    Ok(prepared) => prepared,
                    Err(refusal) => return Ok(Err(refusal)),
                };
                match prepared.commit(&mut self.db, cx).await? {
                    Ok(receipt) => receipt,
                    Err(refusal) => return Ok(Err(refusal)),
                }
            }
        };
        Ok(Ok(BankImportRecorded {
            manifest_oid,
            manifest,
            receipt,
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
            Ok(fa_journal::import::verify_receipt(
                &receipt,
                book.book_id,
                &manifest.closure(manifest_oid),
            )
            .map(|()| Some(receipt)))
        })
    }

    async fn full_bank_document(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        oid: Oid,
    ) -> Outcome<Document> {
        const FULL_SOURCE_AUTHORITY: &str = "matching must replay the complete original BankStatement; a redacted view cannot supply those bytes. Use an authorized capability allowing full source disclosure. On the embedded-owner CLI, pass --grant privileged explicitly; launch-bound MCP templates cannot add or hold that operation";
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
                "plan §9.5–§9.6 (matching requires the exact statement and parsed closure)",
                FULL_SOURCE_AUTHORITY,
            )),
        })
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
        let document = match self
            .full_bank_document(cx, capability, request.manifest_oid)
            .await?
        {
            Ok(doc) => doc,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let policy = EvidencePolicy::embedded()?;
        if document.kind != policy_kind(&policy, "Workpaper")? || document.mime != MANIFEST_MIME {
            return Ok(Err(intake_error(
                "--import must name the manifest_oid returned by fa bank import",
            )));
        }
        let manifest = match BankImportManifest::decode(&document.bytes) {
            Ok(manifest) => manifest,
            Err(error) => return Ok(Err(closure_drift(error.to_string()))),
        };
        if manifest.book_id != self.context().book_id {
            return Ok(Err(closure_drift("manifest belongs to another book")));
        }
        let receipt = match self.bank_import_receipt(cx, &manifest, request.manifest_oid)? {
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
        let account = match self.bank_account(cx, manifest.account, unit, seq)? {
            Ok(account) => account,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let first_day = lines.iter().map(|line| line.booking_date.0).min();
        let candidate_from = first_day.map(|first| DateDay(first.saturating_sub(window)));
        let candidate_through =
            first_day.map(|_| DateDay(manifest.statement_date.0.saturating_add(window)));
        let (candidates, book_closing_balance, epoch) = self.query(cx, |db, book| {
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
            .map(|candidate| candidate.candidate.clone())
            .collect();
        let config = MatcherConfig {
            policy_epoch: None,
            enforced_policy_epoch: decision_epoch,
            max_date_window_days: window,
            pinned_fallback_only: true,
            advisory_learned_scores_bps: BTreeMap::new(),
        };
        let proposals = match_bank_lines(&lines, &native, &config, capability.holder())
            .map_err(|e| corrupt(e.to_string()))?;
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
            proposals,
            book_closing_balance,
            closing_difference,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

#[cfg(test)]
mod provenance_tests;
