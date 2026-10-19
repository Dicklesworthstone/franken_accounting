//! Native bank import identities and explicit predecessor continuity.
//!
//! Unlinked manifests retain their original v1 bytes. A linked v2 manifest
//! binds the previous source, interpretation and actual journal receipt.
//! Its BankStatementLink is derived from the same ImportRun transaction:
//! one identity per (book, cash account, statement) prevents conflicting links.
//! This records continuity only; it neither confirms matches nor soft-locks cash.

use std::collections::BTreeSet;

use asupersync::fs::Vfs;
use fa_model::symbols::{label, property, relation};
use fa_model::{Id128, Oid, Reader, Writer, domain_digest, entry_mirrors, entry_vid};
use fa_money::UnitId;
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteTxn};
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use super::{ImportRecorded, RunReceipt, receipt_of, stored_entry, verify_receipt_in};
use crate::evidence::{Document, doc_commit, document_oid, document_vid, verify_row};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{edge_id, prop, scalar_bytes};

const IMPORT_MAGIC: &[u8; 14] = b"FA-BANK-IMPORT";
const IMPORT_MINOR: u16 = 0;
const PARSER_REVISION: u16 = 1;
const LINK_MAGIC: &[u8; 12] = b"FA-BANK-LINK";
const LINK_DOMAIN: &[u8] = b"fa:bank-statement-link:v1";
pub const BANK_MANIFEST_MIME: &str = "application/vnd.frankenaccounting.bank-import";
pub const BANK_LINE_MIME: &str = "application/vnd.frankenaccounting.bank-line";
/// A source and manifest take the other two slots in one atomic import.
pub const MAX_BANK_LINES: usize = fa_model::limits::MAX_IMPORT_DOCUMENTS - 2;

fn policy() -> Result<EvidencePolicy, KernelError> {
    EvidencePolicy::embedded().map_err(|error| KernelError::Corrupt(error.to_string()))
}

fn kind(policy: &EvidencePolicy, name: &str) -> Result<u8, KernelError> {
    policy.kind_by_name(name).map(|row| row.tag).ok_or_else(|| {
        KernelError::Corrupt(format!("bank import lacks registered document kind {name}"))
    })
}

fn drift(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::DOCUMENT_DRIFT,
        exit::VERIFICATION,
        format!("bank predecessor: {}", message.into()),
        "FA-INV-04; FA-INV-05; plan §9.5 (retained statements and native receipts bind continuity)",
        "preserve the store and verify the referenced source, manifest and original ImportRun before relying on continuity",
    )
}

pub(super) fn conflict(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::CONFLICT,
        exit::CONFLICT,
        message,
        "FG-LAW-FCW-01 (bank predecessor and publication witnesses remain current)",
        "retry the complete bank import with the same --previous-import under current authority",
    )
}

fn continuity(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::BANK_CONTINUITY,
        exit::REFUSAL,
        message,
        "plan §9.5 (same-book/account/unit, contiguous sequence, ordered dates and previous closing = opening)",
        "select the actual immediately preceding --previous-import; correct the statement or explicitly import it without a predecessor as unlinked evidence",
    )
}

fn fork(existing: &BankStatementLink) -> Refusal {
    Refusal::new(
        code::IDEMPOTENCY_CONFLICT,
        exit::CONFLICT,
        format!(
            "this account's statement already has predecessor linkage in manifest {}",
            crate::evidence::hex(&existing.manifest_oid.0),
        ),
        "plan §4.9; §9.5 (one immutable predecessor choice per book, account and source statement)",
        "repeat the original statement, account, parser and --previous-import exactly; a new idempotency key or uploader cannot replace a recorded link",
    )
}

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

    #[must_use]
    pub const fn mime(self) -> &'static str {
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
    /// Authenticated prior import; absence deliberately remains unlinked v1.
    pub predecessor: Option<BankImportPredecessor>,
}

impl BankImportManifest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut w = Writer::new();
        w.fixed(IMPORT_MAGIC)
            .u16(if self.predecessor.is_some() { 2 } else { 1 })
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
        if let Some(predecessor) = &self.predecessor {
            predecessor.encode(&mut w);
        }
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, fa_model::DecodeError> {
        let mut r = Reader::new(bytes);
        if r.fixed::<14>("bank_import.magic")? != *IMPORT_MAGIC {
            return Err(r.invalid("bank_import.version"));
        }
        let major = r.u16("bank_import.major")?;
        if !matches!(major, 1 | 2) || r.u16("bank_import.minor")? != IMPORT_MINOR {
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
            predecessor: if major == 2 {
                Some(BankImportPredecessor::decode(&mut r)?)
            } else {
                None
            },
        };
        if let Some(previous) = &result.predecessor
            && (previous.statement_oid == result.statement_oid
                || previous.sequence_number.checked_add(1) != Some(result.sequence_number)
                || previous.statement_date > result.statement_date
                || previous.closing_balance != result.opening_balance)
        {
            return Err(r.invalid("bank_import.predecessor_continuity"));
        }
        if result.line_oids.iter().collect::<BTreeSet<_>>().len() != result.line_oids.len() {
            return Err(r.invalid("bank_import.duplicate_line"));
        }
        r.finish()?;
        Ok(result)
    }

    #[must_use]
    pub fn closure(&self, manifest_oid: Oid) -> Vec<Oid> {
        let mut closure = self.line_oids.clone();
        closure.extend([self.statement_oid, manifest_oid]);
        closure.sort();
        closure
    }
}

/// The previous import's actual source and native publication coordinate.
/// No bank-account identifier or free-form source text is copied into this
/// public binding. Those are checked by replaying the governed source bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankImportPredecessor {
    pub manifest_oid: Oid,
    pub manifest_commit: [u8; 32],
    pub statement_oid: Oid,
    pub statement_commit: [u8; 32],
    pub import_run: VId,
    pub receipt_hash: [u8; 32],
    pub recorded_at: CommitSeq,
    pub sequence_number: u64,
    pub statement_date: DateDay,
    pub closing_balance: i128,
}

impl BankImportPredecessor {
    fn encode(&self, w: &mut Writer) {
        w.fixed(&self.manifest_oid.0)
            .fixed(&self.manifest_commit)
            .fixed(&self.statement_oid.0)
            .fixed(&self.statement_commit)
            .u128(self.import_run.0)
            .fixed(&self.receipt_hash)
            .u64(self.recorded_at.0)
            .u64(self.sequence_number)
            .i32(self.statement_date.0)
            .i128(self.closing_balance);
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, fa_model::DecodeError> {
        Ok(Self {
            manifest_oid: Oid(r.fixed("bank_predecessor.manifest_oid")?),
            manifest_commit: r.fixed("bank_predecessor.manifest_commit")?,
            statement_oid: Oid(r.fixed("bank_predecessor.statement_oid")?),
            statement_commit: r.fixed("bank_predecessor.statement_commit")?,
            import_run: VId(r.u128("bank_predecessor.import_run")?),
            receipt_hash: r.fixed("bank_predecessor.receipt_hash")?,
            recorded_at: CommitSeq(r.u64("bank_predecessor.recorded_at")?),
            sequence_number: r.u64("bank_predecessor.sequence")?,
            statement_date: DateDay(r.i32("bank_predecessor.date")?),
            closing_balance: r.i128("bank_predecessor.closing")?,
        })
    }
}

impl BankImportManifest {
    pub fn document_commit(&self) -> Result<[u8; 32], KernelError> {
        let bytes = self
            .canonical_bytes()
            .map_err(|error| KernelError::Model(error.into()))?;
        Ok(doc_commit(kind(&policy()?, "Workpaper")?, &bytes))
    }

    pub fn document_oid(&self) -> Result<Oid, KernelError> {
        Ok(document_oid(self.book_id, &self.document_commit()?))
    }

    /// Verify the immediate predecessor against a captured, actual import.
    /// The facade separately replays both source statements' bank identity.
    pub fn verify_predecessor(&self, previous: &BankImportWitness) -> Result<(), Refusal> {
        let old = previous.manifest();
        if self.book_id != old.book_id || self.account != old.account || self.unit != old.unit {
            return Err(continuity(
                "the previous bank import has a different book, cash account or currency unit",
            ));
        }
        if self.statement_oid == old.statement_oid {
            return Err(continuity("a bank statement cannot be its own predecessor"));
        }
        if old.sequence_number.checked_add(1) != Some(self.sequence_number) {
            return Err(continuity(
                "bank statement sequence numbers are not consecutive (including sequence overflow)",
            ));
        }
        if old.statement_date > self.statement_date {
            return Err(continuity(
                "the bank statement closes before its predecessor's closing date",
            ));
        }
        if old.closing_balance != self.opening_balance {
            return Err(continuity(
                "the bank statement opening balance differs from its predecessor's closing balance",
            ));
        }
        if self.predecessor.as_ref() != Some(&previous.predecessor()) {
            return Err(drift(
                "the predecessor binding differs from the actual retained manifest, source or import receipt",
            ));
        }
        Ok(())
    }
}

/// A current native publication; its canonical payload binds the complete
/// manifest and run. recorded_at is read from the original ImportRun row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankStatementLink {
    pub manifest_oid: Oid,
    pub manifest: BankImportManifest,
    pub receipt: RunReceipt,
}

impl BankStatementLink {
    fn payload(&self) -> Result<Vec<u8>, KernelError> {
        let manifest = self
            .manifest
            .canonical_bytes()
            .map_err(|error| KernelError::Model(error.into()))?;
        let mut w = Writer::new();
        w.fixed(LINK_MAGIC)
            .u16(1)
            .u16(0)
            .bytes(&manifest)
            .u128(self.receipt.run.0)
            .fixed(&self.receipt.receipt_hash);
        w.finish().map_err(|error| KernelError::Model(error.into()))
    }
}

/// A single point identity, independent of the uploader and import key.
#[must_use]
pub fn bank_statement_link_vid(book: Id128, account: VId, statement: Oid) -> VId {
    let digest = domain_digest(
        b"fa:vid:bank-statement-link:v1",
        &[&book.0, &account.0.to_le_bytes(), &statement.0],
    );
    let mut short = [0_u8; 16];
    short.copy_from_slice(&digest[..16]);
    VId(u128::from_le_bytes(short))
}

fn payload(row: &VertexRow) -> Result<&[u8], KernelError> {
    match prop(row, property::FA_PAYLOAD) {
        Some(CanonicalScalar::Bytes(bytes)) => Ok(bytes.as_slice()),
        _ => Err(KernelError::Corrupt(
            "bank witness lacks its canonical payload".into(),
        )),
    }
}

fn verify_run_row(row: &VertexRow, book: Id128, expected: &RunReceipt) -> Outcome<()> {
    let entry = stored_entry(row)?;
    let actual_id = entry_vid(
        book,
        &entry.proposal.principal_ref.0.to_le_bytes(),
        &entry.proposal.idempotency_key,
    );
    if !row.labels.contains(&label::ENTRY)
        || entry.proposal.book_id != book
        || entry.proposal.branch_id != Id128::TRUNK
        || actual_id != row.vid
        || receipt_of(&entry, row.vid, row.created_at).as_ref() != Some(expected)
        || entry_mirrors(&entry)?
            .iter()
            .any(|(key, value)| prop(row, *key) != Some(value))
    {
        return Ok(Err(drift(
            "the native import row differs from the captured receipt",
        )));
    }
    Ok(Ok(()))
}

fn link_from_row<V: Vfs + Clone>(
    db: &Database<V>,
    book: Id128,
    row: &VertexRow,
) -> Outcome<BankStatementLink> {
    let bytes = payload(row)?;
    let mut r = Reader::new(bytes);
    let decoded = (|| -> Result<_, fa_model::DecodeError> {
        if r.fixed::<12>("bank_link.magic")? != *LINK_MAGIC
            || r.u16("bank_link.major")? != 1
            || r.u16("bank_link.minor")? != 0
        {
            return Err(r.invalid("bank_link.version"));
        }
        let manifest = BankImportManifest::decode(
            r.bytes(fa_model::limits::MAX_ENTRY_BYTES, "bank_link.manifest")?,
        )?;
        let run = VId(r.u128("bank_link.run")?);
        let hash = r.fixed::<32>("bank_link.receipt")?;
        r.finish()?;
        Ok((manifest, run, hash))
    })();
    let (manifest, run, hash) = match decoded {
        Ok(value) => value,
        Err(error) => return Ok(Err(drift(format!("invalid native link: {error}")))),
    };
    let digest = domain_digest(LINK_DOMAIN, &[bytes]);
    if !row.labels.contains(&label::BANK_STATEMENT_LINK)
        || manifest.book_id != book
        || manifest.predecessor.is_none()
        || row.vid != bank_statement_link_vid(book, manifest.account, manifest.statement_oid)
        || !matches!(prop(row, property::FA_DIGEST), Some(CanonicalScalar::Bytes(value)) if value.as_slice() == digest.as_slice())
        || !matches!(prop(row, property::BOOK_ID), Some(CanonicalScalar::Bytes(value)) if value.as_slice() == book.0.as_slice())
    {
        return Ok(Err(drift(
            "native link identity, label or payload mirrors differ",
        )));
    }
    let Some(run_row) = db.vertex(run)? else {
        return Ok(Err(drift("native link's import run is absent")));
    };
    let entry = stored_entry(&run_row)?;
    let Some(receipt) = receipt_of(&entry, run, run_row.created_at) else {
        return Ok(Err(drift("native link does not name an ImportRun")));
    };
    if hash != receipt.receipt_hash || row.created_at != receipt.recorded_at {
        return Ok(Err(drift(
            "native link and import were not published together",
        )));
    }
    if let Err(refusal) = verify_run_row(&run_row, book, &receipt)? {
        return Ok(Err(refusal));
    }
    let manifest_oid = manifest.document_oid()?;
    if let Err(refusal) = verify_receipt_in(db, book, &receipt, &manifest.closure(manifest_oid))? {
        return Ok(Err(refusal));
    }
    Ok(Ok(BankStatementLink {
        manifest_oid,
        manifest,
        receipt,
    }))
}

/// Read an authenticated native link. Callers must admit source/metadata
/// observation first, as for the other raw kernel import readers.
pub fn read_bank_statement_link<V: Vfs + Clone>(
    db: &Database<V>,
    book: Id128,
    account: VId,
    statement: Oid,
) -> Outcome<Option<BankStatementLink>> {
    let Some(row) = db.vertex(bank_statement_link_vid(book, account, statement))? else {
        return Ok(Ok(None));
    };
    Ok(link_from_row(db, book, &row)?.map(Some))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RowWitness {
    vid: VId,
    recorded_at: CommitSeq,
    payload_digest: [u8; 32],
}

impl RowWitness {
    fn capture(row: &VertexRow) -> Result<Self, KernelError> {
        Ok(Self {
            vid: row.vid,
            recorded_at: row.created_at,
            payload_digest: domain_digest(b"fa:import:row-witness:v1", &[payload(row)?]),
        })
    }

    fn unchanged(&self, row: &VertexRow) -> Result<bool, KernelError> {
        Ok(*self == Self::capture(row)?)
    }
}

/// A native receipt and its entire retained document closure, captured before
/// source interpretation. Private fields prevent a caller from manufacturing
/// publication coordinates or exchanging a different predecessor afterward.
#[derive(Clone, Debug)]
pub struct BankImportWitness {
    manifest: BankImportManifest,
    manifest_oid: Oid,
    manifest_commit: [u8; 32],
    receipt: RunReceipt,
    documents: Vec<RowWitness>,
    link: Option<RowWitness>,
}

impl BankImportWitness {
    /// Call only after admitting the governed read of manifest/source metadata.
    /// Full source parsing follows capture, and publication retains these exact
    /// witnesses in the original import transaction.
    pub fn capture<V: Vfs + Clone>(
        db: &Database<V>,
        book: Id128,
        document: &Document,
        receipt: &RunReceipt,
    ) -> Outcome<Self> {
        let policy = policy()?;
        if document.book_id != book
            || document.kind != kind(&policy, "Workpaper")?
            || document.mime != BANK_MANIFEST_MIME
        {
            return Ok(Err(drift(
                "the selected document is not this book's bank import manifest",
            )));
        }
        let manifest = match BankImportManifest::decode(&document.bytes) {
            Ok(manifest) => manifest,
            Err(error) => return Ok(Err(drift(format!("invalid bank manifest: {error}")))),
        };
        let manifest_oid = document.oid();
        if manifest.book_id != book
            || manifest.document_oid()? != manifest_oid
            || document_oid(book, &manifest.statement_commit) != manifest.statement_oid
        {
            return Ok(Err(drift(
                "manifest or source identity belongs to different content or book",
            )));
        }
        let oids = manifest.closure(manifest_oid);
        if let Err(refusal) = verify_receipt_in(db, book, receipt, &oids)? {
            return Ok(Err(refusal));
        }
        let Some(run_row) = db.vertex(receipt.run)? else {
            return Ok(Err(drift("the manifest import run disappeared")));
        };
        if let Err(refusal) = verify_run_row(&run_row, book, receipt)? {
            return Ok(Err(refusal));
        }
        let mut documents = Vec::with_capacity(oids.len());
        let mut byte_count = 0_u64;
        for oid in oids {
            let Some(row) = db.vertex(document_vid(&oid))? else {
                return Ok(Err(drift("an import closure document is absent")));
            };
            let record = match verify_row(&row, &policy) {
                Ok(record) => record,
                Err(error) => return Ok(Err(drift(error))),
            };
            if record.book_id != book || record.oid() != oid {
                return Ok(Err(drift(
                    "a closure document's native identity or publication sequence differs",
                )));
            }
            let valid = if oid == manifest_oid {
                record.kind == kind(&policy, "Workpaper")?
                    && record.mime == BANK_MANIFEST_MIME
                    && record.doc_commit == document.doc_commit()
            } else if oid == manifest.statement_oid {
                record.kind == kind(&policy, "BankStatement")?
                    && record.doc_commit == manifest.statement_commit
            } else {
                record.kind == kind(&policy, "Other")? && record.mime == BANK_LINE_MIME
            };
            if !valid {
                return Ok(Err(drift(
                    "a closure document's registered kind, commitment or MIME differs",
                )));
            }
            byte_count = match byte_count.checked_add(record.size) {
                Some(count) => count,
                None => return Ok(Err(drift("import byte count overflows"))),
            };
            documents.push(RowWitness::capture(&row)?);
        }
        if byte_count != receipt.byte_count {
            return Ok(Err(drift(
                "the native import byte count differs from its actual document closure",
            )));
        }
        let link = if let Some(previous) = &manifest.predecessor {
            if previous.recorded_at >= receipt.recorded_at {
                return Ok(Err(drift(
                    "a predecessor must have been published before the linked import",
                )));
            }
            let Some(row) = db.vertex(bank_statement_link_vid(
                book,
                manifest.account,
                manifest.statement_oid,
            ))?
            else {
                return Ok(Err(drift(
                    "a linked manifest has no atomic native predecessor record",
                )));
            };
            let recorded = match link_from_row(db, book, &row)? {
                Ok(recorded) => recorded,
                Err(refusal) => return Ok(Err(refusal)),
            };
            if recorded.manifest != manifest
                || recorded.manifest_oid != manifest_oid
                || recorded.receipt != *receipt
            {
                return Ok(Err(drift(
                    "the native predecessor record differs from this manifest or receipt",
                )));
            }
            Some(RowWitness::capture(&row)?)
        } else {
            None
        };
        Ok(Ok(Self {
            manifest,
            manifest_oid,
            manifest_commit: document.doc_commit(),
            receipt: receipt.clone(),
            documents,
            link,
        }))
    }

    #[must_use]
    pub fn manifest(&self) -> &BankImportManifest {
        &self.manifest
    }

    #[must_use]
    pub fn manifest_oid(&self) -> Oid {
        self.manifest_oid
    }

    #[must_use]
    pub fn receipt(&self) -> &RunReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn predecessor(&self) -> BankImportPredecessor {
        BankImportPredecessor {
            manifest_oid: self.manifest_oid,
            manifest_commit: self.manifest_commit,
            statement_oid: self.manifest.statement_oid,
            statement_commit: self.manifest.statement_commit,
            import_run: self.receipt.run,
            receipt_hash: self.receipt.receipt_hash,
            recorded_at: self.receipt.recorded_at,
            sequence_number: self.manifest.sequence_number,
            statement_date: self.manifest.statement_date,
            closing_balance: self.manifest.closing_balance,
        }
    }

    pub(crate) fn retain<V: Vfs + Clone>(
        &self,
        txn: &WriteTxn,
        db: &Database<V>,
        book: Id128,
    ) -> Outcome<()> {
        if self.manifest.book_id != book {
            return Ok(Err(conflict(
                "the bank predecessor witness belongs to another book",
            )));
        }
        let Some(run_row) = txn.vertex(db, self.receipt.run)? else {
            return Ok(Err(conflict(
                "the predecessor import run disappeared before preparation",
            )));
        };
        if verify_run_row(&run_row, book, &self.receipt)?.is_err() {
            return Ok(Err(conflict(
                "the predecessor import receipt changed before preparation",
            )));
        }
        let policy = policy()?;
        for expected in &self.documents {
            let Some(row) = txn.vertex(db, expected.vid)? else {
                return Ok(Err(conflict(
                    "a predecessor document disappeared before preparation",
                )));
            };
            if verify_row(&row, &policy).is_err() || !expected.unchanged(&row)? {
                return Ok(Err(conflict(
                    "a predecessor document changed before preparation",
                )));
            }
        }
        if let Some(expected) = &self.link {
            let Some(row) = txn.vertex(db, expected.vid)? else {
                return Ok(Err(conflict(
                    "a predecessor's native continuity record disappeared",
                )));
            };
            if !expected.unchanged(&row)? || !row.labels.contains(&label::BANK_STATEMENT_LINK) {
                return Ok(Err(conflict(
                    "a predecessor's native continuity record changed",
                )));
            }
            if link_from_row(db, book, &row)?.is_err() {
                return Ok(Err(conflict(
                    "a predecessor's native continuity record no longer verifies",
                )));
            }
        }
        Ok(Ok(()))
    }
}

/// Prepare the one native predecessor choice. The caller already owns the
/// original import transaction; no new transaction or authority is substituted.
/// Unlinked imports retain an absence witness without claiming continuity.
pub(super) fn bind_statement<V: Vfs + Clone>(
    txn: &mut WriteTxn,
    db: &mut Database<V>,
    book: Id128,
    manifest: &BankImportManifest,
    receipt: RunReceipt,
    documents: &[(Oid, u8)],
    previous: Option<&BankImportWitness>,
) -> Outcome<Option<ImportRecorded>> {
    let manifest_oid = manifest.document_oid()?;
    let policy = policy()?;
    let mut oids: Vec<_> = documents.iter().map(|(oid, _)| *oid).collect();
    oids.sort();
    if manifest.book_id != book
        || document_oid(book, &manifest.statement_commit) != manifest.statement_oid
        || manifest.closure(manifest_oid) != oids
        || !documents.contains(&(manifest_oid, kind(&policy, "Workpaper")?))
        || !documents.contains(&(manifest.statement_oid, kind(&policy, "BankStatement")?))
    {
        return Ok(Err(drift(
            "the prepared import does not contain exactly this bank manifest, source and line closure",
        )));
    }
    if let Err(refusal) = super::verify_receipt(&receipt, book, &oids) {
        return Ok(Err(refusal));
    }
    // Canonical decode rejects malformed/duplicate line lists and malformed
    // predecessor bounds even when a native caller constructed the struct.
    let bytes = manifest
        .canonical_bytes()
        .map_err(|error| KernelError::Model(error.into()))?;
    if !matches!(BankImportManifest::decode(&bytes), Ok(decoded) if decoded == *manifest) {
        return Ok(Err(drift(
            "the proposed bank manifest violates its canonical wire contract",
        )));
    }
    match (manifest.predecessor.as_ref(), previous) {
        (Some(_), Some(previous)) => {
            if let Err(refusal) = manifest.verify_predecessor(previous) {
                return Ok(Err(refusal));
            }
            if let Err(refusal) = previous.retain(txn, db, book)? {
                return Ok(Err(refusal));
            }
        }
        (None, None) => {}
        _ => {
            return Ok(Err(drift(
                "the prepared manifest and authenticated predecessor witness disagree",
            )));
        }
    }
    let vid = bank_statement_link_vid(book, manifest.account, manifest.statement_oid);
    if let Some(row) = txn.vertex(db, vid)? {
        let existing = match link_from_row(db, book, &row)? {
            Ok(existing) => existing,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if existing.manifest != *manifest || existing.manifest_oid != manifest_oid {
            return Ok(Err(fork(&existing)));
        }
        return Ok(Ok(Some(ImportRecorded {
            receipt: existing.receipt,
            recorded: Vec::new(),
            already_held: oids,
            already_recorded: true,
        })));
    }
    if manifest.predecessor.is_none() {
        return Ok(Ok(None));
    }
    let link = BankStatementLink {
        manifest_oid,
        manifest: manifest.clone(),
        receipt,
    };
    let bytes = link.payload()?;
    let digest = domain_digest(LINK_DOMAIN, &[&bytes]);
    let mut props = vec![
        (property::FA_PAYLOAD, scalar_bytes("_fa_payload", bytes)?),
        (
            property::FA_DIGEST,
            scalar_bytes("_fa_digest", digest.to_vec())?,
        ),
        (property::BOOK_ID, scalar_bytes("book_id", book.0.to_vec())?),
    ];
    props.sort_by_key(|(key, _)| key.0);
    let mut batch = WriteBatch::new(relation::DERIVED_FROM);
    batch.create_vertex(vid, vec![label::BANK_STATEMENT_LINK], props);
    batch.add_edge(
        edge_id(relation::DERIVED_FROM, vid, link.receipt.run),
        vid,
        link.receipt.run,
        vec![],
    );
    let current_document = document_vid(&manifest_oid);
    batch.add_edge(
        edge_id(relation::DERIVED_FROM, vid, current_document),
        vid,
        current_document,
        vec![],
    );
    if let Some(previous) = &manifest.predecessor {
        batch.add_edge(
            edge_id(relation::DERIVED_FROM, vid, previous.import_run),
            vid,
            previous.import_run,
            vec![],
        );
        let prior_document = document_vid(&previous.manifest_oid);
        batch.add_edge(
            edge_id(relation::DERIVED_FROM, vid, prior_document),
            vid,
            prior_document,
            vec![],
        );
    }
    txn.write_ordered(db, vec![batch])?;
    Ok(Ok(None))
}
