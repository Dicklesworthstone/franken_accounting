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
use crate::evidence::{Document, Storage, doc_commit, document_oid, document_vid, verify_row};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{edge_id, prop, scalar_bytes};

const IMPORT_MAGIC: &[u8; 14] = b"FA-BANK-IMPORT";
const IMPORT_MINOR: u16 = 0;
const PARSER_REVISION: u16 = 1;
const LINK_MAGIC: &[u8; 12] = b"FA-BANK-LINK";
const LINK_DOMAIN: &[u8] = b"fa:bank-statement-link:v1";
const COMPACT_LINK_DOMAIN: &[u8] = b"fa:bank-statement-link:v2";
/// Fixed v2 binding size, independent of the statement's lines and CSV layout.
/// The complete manifest remains in its content-addressed Document/blob.
pub const BANK_STATEMENT_LINK_PAYLOAD_BYTES: usize = 192;
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

fn fork(manifest_oid: Oid) -> Refusal {
    Refusal::new(
        code::IDEMPOTENCY_CONFLICT,
        exit::CONFLICT,
        format!(
            "this account's statement already has an immutable interpretation in manifest {}",
            crate::evidence::hex(&manifest_oid.0),
        ),
        "plan §4.9; §9.5 (one immutable native interpretation per book, account and source statement)",
        "repeat the original statement, account, parser, layout and --previous-import exactly; a new idempotency key or uploader cannot replace a recorded binding",
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
    /// A saved `fwc` Plaid `transactions_sync` robot payload (`fa_formats::fwc`,
    /// plan §9.5): the connector's output, retained and parsed like a statement.
    PlaidSync,
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
            Self::PlaidSync => "plaid-sync",
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
            "plaid-sync" => Some(Self::PlaidSync),
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
            Self::PlaidSync => 7,
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
            7 => Some(Self::PlaidSync),
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
            Self::PlaidSync => "application/json",
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
    /// Declared CSV interpretation, authenticated alongside the original bytes.
    /// Its presence selects manifest v3; v1/v2 bytes remain unchanged.
    pub csv_layout: Option<fa_model::bank_csv::BankCsvLayout>,
    /// Authenticated prior import; absence deliberately remains unlinked.
    pub predecessor: Option<BankImportPredecessor>,
}

impl BankImportManifest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut w = Writer::new();
        w.fixed(IMPORT_MAGIC)
            .u16(if self.csv_layout.is_some() {
                3
            } else if self.predecessor.is_some() {
                2
            } else {
                1
            })
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
        if let Some(layout) = &self.csv_layout {
            w.bytes(&layout.canonical_bytes()?)
                .bool(self.predecessor.is_some());
        }
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
        if !matches!(major, 1..=3) || r.u16("bank_import.minor")? != IMPORT_MINOR {
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
            csv_layout: if major == 3 {
                if format != BankFormat::Csv {
                    return Err(r.invalid("bank_import.csv_layout_parser"));
                }
                Some(fa_model::bank_csv::BankCsvLayout::decode(r.bytes(
                    fa_model::bank_csv::MAX_LAYOUT_BYTES,
                    "bank_import.csv_layout",
                )?)?)
            } else {
                None
            },
            predecessor: if major == 2 || (major == 3 && r.bool("bank_import.predecessor")?) {
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
        if result.csv_layout.as_ref().is_some_and(|layout| {
            layout.sequence_number != result.sequence_number
                || layout.statement_date != result.statement_date
        }) {
            return Err(r.invalid("bank_import.csv_layout_metadata"));
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

/// A current native publication. Its fixed-size v2 payload commits to the
/// retained manifest and run; v1 payloads embedded the complete manifest.
/// recorded_at is read from the original ImportRun row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankStatementLink {
    pub manifest_oid: Oid,
    pub manifest: BankImportManifest,
    pub receipt: RunReceipt,
}

impl BankStatementLink {
    pub(crate) fn payload(&self) -> Result<Vec<u8>, KernelError> {
        self.payload_version(2)
    }

    fn payload_version(&self, major: u16) -> Result<Vec<u8>, KernelError> {
        let manifest = self
            .manifest
            .canonical_bytes()
            .map_err(|error| KernelError::Model(error.into()))?;
        let commit = doc_commit(kind(&policy()?, "Workpaper")?, &manifest);
        if self.manifest_oid != document_oid(self.manifest.book_id, &commit) {
            return Err(KernelError::Corrupt(
                "bank binding's manifest identity differs from its canonical bytes".into(),
            ));
        }
        let mut w = Writer::new();
        w.fixed(LINK_MAGIC).u16(major).u16(0);
        match major {
            1 => {
                w.bytes(&manifest);
            }
            2 => {
                w.fixed(&self.manifest.book_id.0)
                    .u128(self.manifest.account.0)
                    .fixed(&self.manifest.statement_oid.0)
                    .fixed(&self.manifest_oid.0)
                    .fixed(&commit);
            }
            _ => {
                return Err(KernelError::Corrupt(
                    "unsupported bank binding payload version".into(),
                ));
            }
        }
        w.u128(self.receipt.run.0).fixed(&self.receipt.receipt_hash);
        w.finish().map_err(|error| KernelError::Model(error.into()))
    }

    /// Historical verification accepts exactly the original v1 or compact v2
    /// encoding. It never rewrites an old binding or its digest domain.
    pub(crate) fn matches_row(&self, row: &VertexRow) -> Result<bool, KernelError> {
        let actual = payload(row)?;
        let mut reader = Reader::new(actual);
        let major = match link_version(&mut reader) {
            Ok(major) => major,
            Err(_) => return Ok(false),
        };
        let expected = self.payload_version(major)?;
        Ok(row.labels.as_slice() == [label::BANK_STATEMENT_LINK]
            && row.props == link_properties(self.manifest.book_id, major, expected)?)
    }
}

fn link_version(r: &mut Reader<'_>) -> Result<u16, fa_model::DecodeError> {
    if r.fixed::<12>("bank_link.magic")? != *LINK_MAGIC {
        return Err(r.invalid("bank_link.version"));
    }
    let major = r.u16("bank_link.major")?;
    if !matches!(major, 1 | 2) || r.u16("bank_link.minor")? != 0 {
        return Err(r.invalid("bank_link.version"));
    }
    Ok(major)
}

fn link_domain(major: u16) -> &'static [u8] {
    if major == 2 {
        COMPACT_LINK_DOMAIN
    } else {
        LINK_DOMAIN
    }
}

fn link_properties(
    book: Id128,
    major: u16,
    bytes: Vec<u8>,
) -> Result<Vec<(fgdb_delta_types::PropertyKeyId, CanonicalScalar)>, KernelError> {
    let digest = domain_digest(link_domain(major), &[&bytes]);
    let mut props = vec![
        (property::FA_PAYLOAD, scalar_bytes("_fa_payload", bytes)?),
        (
            property::FA_DIGEST,
            scalar_bytes("_fa_digest", digest.to_vec())?,
        ),
        (property::BOOK_ID, scalar_bytes("book_id", book.0.to_vec())?),
    ];
    props.sort_by_key(|(key, _)| key.0);
    Ok(props)
}

#[derive(Debug, PartialEq, Eq)]
enum LinkManifest {
    Legacy(Box<BankImportManifest>),
    Retained {
        book_id: Id128,
        account: VId,
        statement_oid: Oid,
        manifest_oid: Oid,
        manifest_commit: [u8; 32],
    },
}

fn decode_link(bytes: &[u8]) -> Result<(u16, LinkManifest, VId, [u8; 32]), fa_model::DecodeError> {
    let mut r = Reader::new(bytes);
    let major = link_version(&mut r)?;
    let manifest = if major == 1 {
        LinkManifest::Legacy(Box::new(BankImportManifest::decode(
            r.bytes(fa_model::limits::MAX_ENTRY_BYTES, "bank_link.manifest")?,
        )?))
    } else {
        LinkManifest::Retained {
            book_id: Id128(r.fixed("bank_link.book")?),
            account: VId(r.u128("bank_link.account")?),
            statement_oid: Oid(r.fixed("bank_link.statement")?),
            manifest_oid: Oid(r.fixed("bank_link.manifest_oid")?),
            manifest_commit: r.fixed("bank_link.manifest_commit")?,
        }
    };
    let run = VId(r.u128("bank_link.run")?);
    let hash = r.fixed::<32>("bank_link.receipt")?;
    r.finish()?;
    Ok((major, manifest, run, hash))
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
    supplied_manifest: Option<&BankImportManifest>,
) -> Outcome<BankStatementLink> {
    let bytes = payload(row)?;
    let (major, binding, run, hash) = match decode_link(bytes) {
        Ok(value) => value,
        Err(error) => return Ok(Err(drift(format!("invalid native link: {error}")))),
    };
    let (bound_book, account, statement, manifest_oid, manifest_commit) = match &binding {
        LinkManifest::Legacy(manifest) => (
            manifest.book_id,
            manifest.account,
            manifest.statement_oid,
            manifest.document_oid()?,
            manifest.document_commit()?,
        ),
        LinkManifest::Retained {
            book_id,
            account,
            statement_oid,
            manifest_oid,
            manifest_commit,
        } => (
            *book_id,
            *account,
            *statement_oid,
            *manifest_oid,
            *manifest_commit,
        ),
    };
    let digest = domain_digest(link_domain(major), &[bytes]);
    if !row.labels.contains(&label::BANK_STATEMENT_LINK)
        || bound_book != book
        || row.vid != bank_statement_link_vid(book, account, statement)
        || document_oid(book, &manifest_commit) != manifest_oid
        || !matches!(prop(row, property::FA_DIGEST), Some(CanonicalScalar::Bytes(value)) if value.as_slice() == digest.as_slice())
        || !matches!(prop(row, property::BOOK_ID), Some(CanonicalScalar::Bytes(value)) if value.as_slice() == book.0.as_slice())
    {
        return Ok(Err(drift(
            "native link identity, label or payload mirrors differ",
        )));
    }
    // Authenticate the retained document's identity and commitment before
    // using caller-supplied bytes or reporting an interpretation conflict.
    // External manifests need no blob access on this synchronous path.
    let Some(document_row) = db.vertex(document_vid(&manifest_oid))? else {
        return Ok(Err(drift("native link's retained manifest is absent")));
    };
    let policy = policy()?;
    let document = match verify_row(&document_row, &policy) {
        Ok(document) => document,
        Err(error) => return Ok(Err(drift(error))),
    };
    if document.book_id != book
        || document.oid() != manifest_oid
        || document.kind != kind(&policy, "Workpaper")?
        || document.mime != BANK_MANIFEST_MIME
        || document.doc_commit != manifest_commit
    {
        return Ok(Err(drift(
            "native link differs from its retained manifest document",
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
    if let Some(supplied) = supplied_manifest
        && supplied.document_oid()? != manifest_oid
    {
        return Ok(Err(fork(manifest_oid)));
    }
    let manifest = match binding {
        LinkManifest::Legacy(manifest) => *manifest,
        LinkManifest::Retained { .. } => match supplied_manifest {
            Some(manifest) => manifest.clone(),
            None => match &document.storage {
                Storage::Inline(bytes) => match BankImportManifest::decode(bytes) {
                    Ok(manifest) => manifest,
                    Err(error) => {
                        return Ok(Err(drift(format!("invalid retained manifest: {error}"))));
                    }
                },
                Storage::External { .. } => {
                    return Ok(Err(Refusal::new(
                        code::BLOB_MISSING,
                        exit::FOUNDATION,
                        "this bank binding refers to an external manifest; its canonical bytes are required to verify the complete import closure",
                        "FA-INV-04; FA-INV-05 (the retained manifest authenticates the statement interpretation)",
                        "fetch the retained manifest under the caller's document authority and use read_bank_statement_link_with_manifest; exact import retries may supply the manifest reconstructed from their own original bytes",
                    )));
                }
            },
        },
    };
    let canonical = manifest
        .canonical_bytes()
        .map_err(|error| KernelError::Model(error.into()))?;
    if manifest.book_id != book
        || manifest.account != account
        || manifest.statement_oid != statement
        || document_oid(book, &manifest.statement_commit) != statement
        || (manifest.predecessor.is_none() && manifest.csv_layout.is_none())
        || !matches!(BankImportManifest::decode(&canonical), Ok(decoded) if decoded == manifest)
        || document.with_bytes(canonical).is_none()
    {
        return Ok(Err(drift(
            "native link's interpretation does not reproduce the retained manifest",
        )));
    }
    if let Err(refusal) = verify_receipt_in(db, book, &receipt, &manifest.closure(manifest_oid))? {
        return Ok(Err(refusal));
    }
    Ok(Ok(BankStatementLink {
        manifest_oid,
        manifest,
        receipt,
    }))
}

/// Read an authenticated native link whose manifest is inline, or carried in
/// a legacy v1 binding. For an external v2 binding, use
/// [`read_bank_statement_link_with_manifest`] with authenticated retained or
/// caller-reconstructed bytes. Callers must admit source/metadata observation
/// first, as for the other raw kernel import readers.
pub fn read_bank_statement_link<V: Vfs + Clone>(
    db: &Database<V>,
    book: Id128,
    account: VId,
    statement: Oid,
) -> Outcome<Option<BankStatementLink>> {
    let Some(row) = db.vertex(bank_statement_link_vid(book, account, statement))? else {
        return Ok(Ok(None));
    };
    Ok(link_from_row(db, book, &row, None)?.map(Some))
}

/// Resolve a binding using the exact canonical interpretation supplied by the
/// caller. Its bytes must reproduce the retained document commitment, and its
/// complete closure must verify against the original native import receipt.
/// No blob is fetched and no source-disclosure authority is substituted.
pub fn read_bank_statement_link_with_manifest<V: Vfs + Clone>(
    db: &Database<V>,
    book: Id128,
    manifest: &BankImportManifest,
) -> Outcome<Option<BankStatementLink>> {
    let Some(row) = db.vertex(bank_statement_link_vid(
        book,
        manifest.account,
        manifest.statement_oid,
    ))?
    else {
        return Ok(Ok(None));
    };
    Ok(link_from_row(db, book, &row, Some(manifest))?.map(Some))
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
        if manifest
            .predecessor
            .as_ref()
            .is_some_and(|previous| previous.recorded_at >= receipt.recorded_at)
        {
            return Ok(Err(drift(
                "a predecessor must have been published before the linked import",
            )));
        }
        let link = if manifest.predecessor.is_some() || manifest.csv_layout.is_some() {
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
            let recorded = match link_from_row(db, book, &row, Some(&manifest))? {
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
            if link_from_row(db, book, &row, Some(&self.manifest))?.is_err() {
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
        let existing = match link_from_row(db, book, &row, Some(manifest))? {
            Ok(existing) => existing,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if existing.manifest != *manifest || existing.manifest_oid != manifest_oid {
            return Ok(Err(fork(existing.manifest_oid)));
        }
        return Ok(Ok(Some(ImportRecorded {
            receipt: existing.receipt,
            recorded: Vec::new(),
            already_held: oids,
            already_recorded: true,
        })));
    }
    if manifest.predecessor.is_none() && manifest.csv_layout.is_none() {
        return Ok(Ok(None));
    }
    let link = BankStatementLink {
        manifest_oid,
        manifest: manifest.clone(),
        receipt,
    };
    let bytes = link.payload()?;
    let props = link_properties(book, 2, bytes)?;
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

/// Verify bank import manifest, bank-line document, and `BankStatementLink`
/// `DERIVED_FROM` projections at `at` (`fa-d22b`).
pub(crate) fn verify_all_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &crate::genesis::BookContext,
    at: CommitSeq,
) -> Result<Vec<String>, KernelError> {
    let rows = db.vertices_at(at)?;
    let stored_edges = db.edges_at(at)?;
    let vertices: std::collections::BTreeMap<_, _> =
        rows.iter().map(|row| (row.vid, row)).collect();
    let derived_edges: BTreeSet<(VId, VId)> = stored_edges
        .iter()
        .filter(|edge| {
            edge.entry.relation == relation::DERIVED_FROM
                && edge.entry.eid == edge_id(relation::DERIVED_FROM, edge.entry.src, edge.entry.dst)
                && edge.props.is_empty()
        })
        .map(|edge| (edge.entry.src, edge.entry.dst))
        .collect();
    let policy = policy()?;
    let workpaper_kind = kind(&policy, "Workpaper")?;
    let statement_kind = kind(&policy, "BankStatement")?;
    let line_kind = kind(&policy, "Other")?;
    let mut receipts = Vec::new();
    for row in rows.iter().filter(|row| row.labels.contains(&label::ENTRY)) {
        if let Ok(entry) = stored_entry(row)
            && entry.proposal.book_id == book.book_id
            && entry.proposal.branch_id == Id128::TRUNK
            && let Some(receipt) = receipt_of(&entry, row.vid, row.created_at)
        {
            receipts.push(receipt);
        }
    }
    let mut drift = Vec::new();
    let mut expected_links = BTreeSet::new();
    for row in rows
        .iter()
        .filter(|row| row.labels.contains(&label::DOCUMENT))
    {
        let Ok(record) = verify_row(row, &policy) else {
            continue;
        };
        if record.book_id != book.book_id
            || record.kind != workpaper_kind
            || record.mime != BANK_MANIFEST_MIME
        {
            continue;
        }
        let Storage::Inline(bytes) = &record.storage else {
            continue;
        };
        let manifest_oid = record.oid();
        let manifest = match BankImportManifest::decode(bytes) {
            Ok(manifest) => manifest,
            Err(error) => {
                drift.push(format!(
                    "bank manifest {:032x}: invalid payload: {error}",
                    row.vid.0
                ));
                continue;
            }
        };
        if manifest.book_id != book.book_id || manifest.document_oid()? != manifest_oid {
            drift.push(format!(
                "bank manifest {:032x}: book or document identity mismatch",
                row.vid.0
            ));
            continue;
        }
        let closure = manifest.closure(manifest_oid);
        let Some(receipt) = receipts
            .iter()
            .find(|receipt| super::verify_receipt(receipt, book.book_id, &closure).is_ok())
        else {
            continue;
        };
        let statement_vid = document_vid(&manifest.statement_oid);
        match vertices.get(&statement_vid) {
            Some(stmt_row)
                if verify_row(stmt_row, &policy).is_ok_and(|stmt| {
                    stmt.book_id == book.book_id
                        && stmt.oid() == manifest.statement_oid
                        && stmt.kind == statement_kind
                        && stmt.doc_commit == manifest.statement_commit
                }) => {}
            _ => drift.push(format!(
                "bank manifest {:032x}: missing or mismatched BankStatement vertex {:032x}",
                row.vid.0, statement_vid.0
            )),
        }
        if !derived_edges.contains(&(row.vid, statement_vid)) {
            drift.push(format!(
                "bank manifest {:032x}: missing DERIVED_FROM edge to statement {:032x}",
                row.vid.0, statement_vid.0
            ));
        }
        for line_oid in &manifest.line_oids {
            let line_vid = document_vid(line_oid);
            match vertices.get(&line_vid) {
                Some(line_row)
                    if verify_row(line_row, &policy).is_ok_and(|line_rec| {
                        line_rec.book_id == book.book_id
                            && line_rec.oid() == *line_oid
                            && line_rec.kind == line_kind
                            && line_rec.mime == BANK_LINE_MIME
                    }) => {}
                _ => drift.push(format!(
                    "bank manifest {:032x}: missing or mismatched BankLine document {:032x}",
                    row.vid.0, line_vid.0
                )),
            }
            if !derived_edges.contains(&(line_vid, statement_vid)) {
                drift.push(format!(
                    "bank line {:032x}: missing DERIVED_FROM edge to statement {:032x}",
                    line_vid.0, statement_vid.0
                ));
            }
            if !derived_edges.contains(&(row.vid, line_vid)) {
                drift.push(format!(
                    "bank manifest {:032x}: missing DERIVED_FROM edge to bank line {:032x}",
                    row.vid.0, line_vid.0
                ));
            }
        }
        if manifest.predecessor.is_some() || manifest.csv_layout.is_some() {
            let link_vid =
                bank_statement_link_vid(book.book_id, manifest.account, manifest.statement_oid);
            expected_links.insert(link_vid);
            let expected_link = BankStatementLink {
                manifest_oid,
                manifest: manifest.clone(),
                receipt: receipt.clone(),
            };
            match vertices.get(&link_vid) {
                Some(link_row) if expected_link.matches_row(link_row)? => {}
                _ => drift.push(format!(
                    "bank manifest {:032x}: missing or mismatched BankStatementLink {:032x}",
                    row.vid.0, link_vid.0
                )),
            }
            for target in [receipt.run, row.vid] {
                if !derived_edges.contains(&(link_vid, target)) {
                    drift.push(format!(
                        "bank link {:032x}: missing DERIVED_FROM edge to {:032x}",
                        link_vid.0, target.0
                    ));
                }
            }
            if let Some(previous) = &manifest.predecessor {
                for target in [previous.import_run, document_vid(&previous.manifest_oid)] {
                    if !derived_edges.contains(&(link_vid, target)) {
                        drift.push(format!(
                            "bank link {:032x}: missing predecessor DERIVED_FROM edge to {:032x}",
                            link_vid.0, target.0
                        ));
                    }
                }
            }
        }
    }
    for row in rows
        .iter()
        .filter(|row| row.labels.contains(&label::BANK_STATEMENT_LINK))
    {
        if !expected_links.contains(&row.vid) {
            if let Ok(bytes) = payload(row)
                && let Ok((_, LinkManifest::Retained { manifest_oid, .. }, run, _)) =
                    decode_link(bytes)
                && vertices
                    .get(&document_vid(&manifest_oid))
                    .and_then(|doc_row| verify_row(doc_row, &policy).ok())
                    .is_some_and(|rec| matches!(rec.storage, Storage::External { .. }))
                && derived_edges.contains(&(row.vid, run))
                && derived_edges.contains(&(row.vid, document_vid(&manifest_oid)))
            {
                continue;
            }
            drift.push(format!(
                "orphan or invalid BankStatementLink {:032x}",
                row.vid.0
            ));
        }
    }
    Ok(drift)
}

/// Count bank statement lines across all retained `BankImportManifest`s at `at`
/// that have no active confirmation, returning `(unmatched_lines, first_unmatched_manifest)`
/// (`fa-g8em`).
pub fn unmatched_bank_lines_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: Id128,
    at: CommitSeq,
) -> Result<(usize, Option<Oid>), KernelError> {
    let policy = policy()?;
    let workpaper_kind = kind(&policy, "Workpaper")?;
    let rows = db.vertices_at(at)?;
    let mut receipts = Vec::new();
    for row in rows.iter().filter(|row| row.labels.contains(&label::ENTRY)) {
        if let Ok(entry) = stored_entry(row)
            && entry.proposal.book_id == book
            && entry.proposal.branch_id == Id128::TRUNK
            && let Some(receipt) = receipt_of(&entry, row.vid, row.created_at)
        {
            receipts.push(receipt);
        }
    }
    let mut manifests = Vec::new();
    let mut confirmations = Vec::new();
    let mut unmatched_vids = BTreeSet::new();
    for row in &rows {
        if row.labels.as_slice() == [label::DOCUMENT] {
            let Ok(record) = verify_row(row, &policy) else {
                continue;
            };
            if record.book_id != book
                || record.kind != workpaper_kind
                || record.mime != BANK_MANIFEST_MIME
            {
                continue;
            }
            let Storage::Inline(bytes) = &record.storage else {
                continue;
            };
            let Ok(manifest) = BankImportManifest::decode(bytes) else {
                continue;
            };
            let manifest_oid = record.oid();
            if manifest.book_id != book || manifest.document_oid().ok() != Some(manifest_oid) {
                continue;
            }
            let closure = manifest.closure(manifest_oid);
            if receipts
                .iter()
                .any(|receipt| super::verify_receipt(receipt, book, &closure).is_ok())
            {
                manifests.push((row.created_at, manifest_oid, manifest));
            }
        } else if row.labels.as_slice() == [label::BANK_MATCH] {
            if let Ok(bytes) = payload(row)
                && let Ok(confirmation) = crate::bank::BankMatchConfirmation::decode(bytes)
                && confirmation.book_id == book
            {
                confirmations.push((row.vid, confirmation));
            }
        } else if row.labels.as_slice() == [label::BANK_UNMATCH]
            && let Ok(bytes) = payload(row)
            && let Ok(unmatch) = crate::bank::BankUnmatch::decode(bytes)
            && unmatch.book_id == book
        {
            unmatched_vids.insert(unmatch.target.vid);
        }
    }
    manifests.sort_by_key(|(created_at, oid, _)| (*created_at, *oid));
    let mut total_unmatched = 0_usize;
    let mut first_unmatched_manifest = None;
    for (_, manifest_oid, manifest) in manifests {
        let confirmed: BTreeSet<u32> = confirmations
            .iter()
            .filter(|(vid, c)| {
                !unmatched_vids.contains(vid)
                    && c.manifest_oid == manifest_oid
                    && c.statement_oid == manifest.statement_oid
                    && c.account == manifest.account
            })
            .map(|(_, c)| c.line_ordinal)
            .collect();
        let unmatched = manifest.line_oids.len().saturating_sub(confirmed.len());
        total_unmatched += unmatched;
        if unmatched > 0 && first_unmatched_manifest.is_none() {
            first_unmatched_manifest = Some(manifest_oid);
        }
    }
    Ok((total_unmatched, first_unmatched_manifest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_model::IntakeSource;
    use fa_model::bank_csv::{BankCsvAmounts, BankCsvDateFormat, BankCsvLayout};

    fn binding(line_count: usize, declared_layout: bool) -> BankStatementLink {
        let book_id = Id128([11; 16]);
        let statement_commit = [12; 32];
        let date = DateDay::from_ymd(2026, 3, 31).unwrap();
        let manifest = BankImportManifest {
            book_id,
            account: VId(13),
            format: BankFormat::Csv,
            statement_oid: document_oid(book_id, &statement_commit),
            statement_commit,
            unit: UnitId(1),
            sequence_number: 2,
            statement_date: date,
            opening_balance: 0,
            closing_balance: 0,
            line_oids: (0..line_count)
                .map(|index| {
                    Oid(domain_digest(
                        b"bank-link-test-line",
                        &[&index.to_le_bytes()],
                    ))
                })
                .collect(),
            csv_layout: declared_layout.then(|| BankCsvLayout {
                name: "binding-test".into(),
                headers: vec!["Date".into(), "Amount".into()],
                delimiter: b',',
                decimal_separator: b'.',
                date_format: BankCsvDateFormat::Iso,
                booking_date: "Date".into(),
                value_date: None,
                counterparty: None,
                reference: None,
                amounts: BankCsvAmounts::Signed {
                    column: "Amount".into(),
                    positive_is_credit: true,
                },
                instrument_id: "BANK-TEST".into(),
                sequence_number: 2,
                currency: "USD".into(),
                statement_date: date,
                opening_balance: "0.00".into(),
                closing_balance: "0.00".into(),
            }),
            predecessor: Some(BankImportPredecessor {
                manifest_oid: Oid([14; 32]),
                manifest_commit: [15; 32],
                statement_oid: Oid([16; 32]),
                statement_commit: [17; 32],
                import_run: VId(18),
                receipt_hash: [19; 32],
                recorded_at: CommitSeq(20),
                sequence_number: 1,
                statement_date: date,
                closing_balance: 0,
            }),
        };
        BankStatementLink {
            manifest_oid: manifest.document_oid().unwrap(),
            manifest,
            receipt: RunReceipt {
                run: VId(21),
                source: IntakeSource::Upload { principal: VId(22) },
                document_count: u32::try_from(line_count + 2).unwrap(),
                byte_count: 0,
                oids_root: [23; 32],
                receipt_hash: [24; 32],
                recorded_at: CommitSeq(25),
            },
        }
    }

    #[test]
    fn legacy_v1_binding_decodes_the_original_v2_manifest_without_reencoding_it() {
        let link = binding(2, false);
        let original_manifest = link.manifest.canonical_bytes().unwrap();
        assert_eq!(&original_manifest[14..18], &[2, 0, 0, 0]);
        // The pre-compact wire contract, assembled independently of the new
        // writer: full manifest bytes, then native run and receipt hash.
        let mut old = Writer::new();
        old.fixed(b"FA-BANK-LINK")
            .u16(1)
            .u16(0)
            .bytes(&original_manifest)
            .u128(link.receipt.run.0)
            .fixed(&link.receipt.receipt_hash);
        let bytes = old.finish().unwrap();
        assert_eq!(
            decode_link(&bytes).unwrap(),
            (
                1,
                LinkManifest::Legacy(Box::new(link.manifest.clone())),
                link.receipt.run,
                link.receipt.receipt_hash,
            )
        );
        assert_eq!(link.payload_version(1).unwrap(), bytes);
        assert_eq!(link_domain(1), b"fa:bank-statement-link:v1");
        for length in 0..bytes.len() {
            assert!(decode_link(&bytes[..length]).is_err());
        }
    }

    #[test]
    fn compact_binding_stays_192_bytes_at_the_full_statement_limit() {
        for (line_count, declared_layout) in
            [(0, false), (MAX_BANK_LINES, false), (MAX_BANK_LINES, true)]
        {
            let link = binding(line_count, declared_layout);
            let bytes = link.payload().unwrap();
            assert_eq!(bytes.len(), BANK_STATEMENT_LINK_PAYLOAD_BYTES);
            assert_eq!(bytes.len(), 192);
            if line_count == MAX_BANK_LINES {
                assert!(link.manifest.canonical_bytes().unwrap().len() > 16 * 1024);
            }
            assert_eq!(
                decode_link(&bytes).unwrap(),
                (
                    2,
                    LinkManifest::Retained {
                        book_id: link.manifest.book_id,
                        account: link.manifest.account,
                        statement_oid: link.manifest.statement_oid,
                        manifest_oid: link.manifest_oid,
                        manifest_commit: link.manifest.document_commit().unwrap(),
                    },
                    link.receipt.run,
                    link.receipt.receipt_hash,
                )
            );
            assert_eq!(link_domain(2), b"fa:bank-statement-link:v2");
            for length in 0..bytes.len() {
                assert!(decode_link(&bytes[..length]).is_err());
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(decode_link(&trailing).is_err());
            for (offset, value) in [(0, b'X'), (12, 0), (12, 3), (14, 1)] {
                let mut invalid = bytes.clone();
                invalid[offset] = value;
                assert!(decode_link(&invalid).is_err());
            }
        }
    }
}
