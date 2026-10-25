//! Docket intake and the evidence law (plan §9.1–§9.3, FA-INV-05 clause
//! `evidence-minimum`).
//!
//! A `Document` is immutable and content-addressed. Its public commitment is
//! `doc_commit = BLAKE3("fa:doc:v1" ‖ kind ‖ length ‖ chunk_root)`, where
//! `chunk_root` is a Merkle root over fixed 4 KiB chunks of the canonical
//! bytes, so a verifier recomputes it from the bytes alone and a redacted
//! production can disclose a subset of chunks with their paths. Every
//! `EvidenceRef` carries `doc_commit` beside the locator; the posting kernel
//! refuses a citation whose commitment does not match the document it names.
//!
//! The evidence minimum is a registry (`evidence_policy.toml`), total over the
//! entry classes, checked inside the posting transaction with each cited
//! document read as a point witness. An entry below its class's minimum is
//! refused; the kernel never infers, fabricates, or auto-attaches evidence.
//!
//! Interim postures, stated rather than hidden (the pinned substrate has no
//! object store, Appendix H):
//! - the canonical bytes ride inline in the Document's `fa:document:v1`
//!   payload up to [`inline_document_bound`] (what one substrate row holds);
//!   past it they live in the book's blob store behind the inline commitment
//!   (`blob`,
//!   `document_stores.toml`). Custody and import runs (`custody`, `import`),
//!   legal holds (`legal_hold`) and redacted views (`redaction`) are their
//!   own modules; parsed projections are a later slice;
//! - `document_oid = H("fa:oid:document:v1" ‖ book_id ‖ doc_commit)` is a
//!   book-scoped locator, because the substrate's keyed `ObjectId` (`K_oid`)
//!   is not exposed through the embedded handle;
//! - the provenance grade is recorded at intake from the uploader's declared
//!   posture (`HumanUpload` | `AgentUpload`); grades derived from a receipt
//!   chain are refused. A self-sourced document (`AgentUpload`, `Generated`)
//!   counts toward a minimum only once a principal other than its uploader
//!   has recorded a `Reviewed` attestation over it (plan §9.3; the
//!   attestation module), read as a witness of the posting transaction; the
//!   Agent-profile draft gate needs drafts, which do not exist yet, so an
//!   unreviewed one is refused (FA-REF-086), never exempted;
//! - the preparer's `ManualAssertion` (plan §9.2) satisfies the minimum in
//!   place of a document only where the class's row says
//!   `manual_assertion = true`, and only with a registered reason; it too is
//!   read as a witness, and the entry gains `ATTESTS` from it.

use fa_model::symbols::{label, property, relation};
use fa_model::{
    DecodeError, EntryPayload, EntryRef, EvidenceRef, Id128, IntakeSource, Oid, Reader, Writer,
    domain_digest,
};
use fa_registry::evidence_policy::{EvidencePolicy, Requirement};
use fa_registry::reason_codes::ReasonCodes;
use fgdb::{Database, VertexRow, WriteBatch, WriteTxn};
use fgdb_crypto::Hasher;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::attestation::{
    Assertion, MANUAL_ASSERTION_SCOPE, Review, reason_refusal, self_review_refusal,
    witness_manual_assertion, witness_review,
};
use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{edge_id, prop, scalar_bytes, scalar_text};

/// The fixed chunk size of the commitment's Merkle tree (plan §9.1).
pub const CHUNK_BYTES: usize = 4096;

/// The decoder's bound on inline bytes: the substrate's scalar ceiling, so a
/// later, larger registry bound never makes a stored document unreadable.
const MAX_DECODED_DOCUMENT_BYTES: usize = 64 * 1024 * 1024;
const MAX_DECODED_MIME_BYTES: usize = 1024;

/// The bytes a Document carries inline. The pinned substrate refuses a
/// vertex row above 16384 encoded bytes (`RowExceedsStorageLimit`); the
/// payload is one byte scalar stored as 8-byte memcomparable groups (about
/// 9/8 of its length) beside the digest, book and kind mirrors and a MIME of
/// up to `max_mime_bytes`. 12 KiB leaves that headroom, as for retained
/// certificates (`fa` certificate_store). A larger document lives in the
/// book's blob store behind its inline commitment.
pub const MAX_INLINE_DOCUMENT_BYTES: u64 = 12 * 1024;

/// The inline intake bound: the policy's document bound, capped by what one
/// substrate row holds ([`MAX_INLINE_DOCUMENT_BYTES`]). Every intake path
/// routes or refuses on this bound, never on the policy bound alone.
#[must_use]
pub fn inline_document_bound(policy: &EvidencePolicy) -> u64 {
    policy.max_document_bytes.min(MAX_INLINE_DOCUMENT_BYTES)
}

/// Storage tags of `fa:document:v1`.
const STORAGE_INLINE: u8 = 0;
const STORAGE_EXTERNAL: u8 = 1;
/// Bound on an external locator (Appendix A `locator: String(≤2048)`).
const MAX_LOCATOR_BYTES: usize = 2048;

fn finalize(h: Hasher) -> [u8; 32] {
    h.finalize().0
}

/// The Merkle root over fixed 4 KiB chunks: leaf `i` is
/// `H("fa:doc:leaf:v1" ‖ u64 i ‖ u64 len ‖ chunk)`, an interior node is
/// `H("fa:doc:node:v1" ‖ left ‖ right)`, and an unpaired node is promoted
/// unchanged. Empty input is one empty leaf, so the function is total.
#[must_use]
pub fn chunk_root(bytes: &[u8]) -> [u8; 32] {
    let level: Vec<[u8; 32]> = if bytes.is_empty() {
        vec![leaf(0, &[])]
    } else {
        bytes
            .chunks(CHUNK_BYTES)
            .enumerate()
            .map(|(i, c)| leaf(i, c))
            .collect()
    };
    tree_root(level)
}

/// The root over `leaves` in order (one or more), as [`chunk_root`] builds
/// it; a redacted view rebuilds the tree from disclosed and withheld leaves.
pub(crate) fn tree_root(mut level: Vec<[u8; 32]>) -> [u8; 32] {
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [l, r] => node(l, r),
                // `chunks(2)` yields a lone last element only.
                _ => pair[0],
            })
            .collect();
    }
    level.first().copied().unwrap_or_else(|| leaf(0, &[]))
}

fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"fa:doc:node:v1");
    h.update(left);
    h.update(right);
    finalize(h)
}

pub(crate) fn leaf(index: usize, chunk: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"fa:doc:leaf:v1");
    h.update(&len_u64(index).to_le_bytes());
    h.update(&len_u64(chunk.len()).to_le_bytes());
    h.update(chunk);
    finalize(h)
}

/// A length as the commitment encodes it (`usize` never exceeds `u64` on a
/// supported target; saturating keeps the transcript total).
fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// `doc_commit = BLAKE3("fa:doc:v1" ‖ kind ‖ length ‖ chunk_root)` — the
/// public commitment every evidence list, bundle and certificate references.
#[must_use]
pub fn doc_commit(kind: u8, bytes: &[u8]) -> [u8; 32] {
    commitment(kind, len_u64(bytes.len()), &chunk_root(bytes))
}

/// The commitment from its parts: what a redacted view recomputes without
/// the withheld bytes.
pub(crate) fn commitment(kind: u8, size: u64, root: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"fa:doc:v1");
    h.update(&[kind]);
    h.update(&size.to_le_bytes());
    h.update(root);
    finalize(h)
}

/// The book-scoped locator of a document (interim for the keyed substrate
/// `ObjectId`): `H("fa:oid:document:v1" ‖ book_id ‖ doc_commit)`.
#[must_use]
pub fn document_oid(book: Id128, doc_commit: &[u8; 32]) -> Oid {
    Oid(domain_digest(b"fa:oid:document:v1", &[&book.0, doc_commit]))
}

/// `vid(Document) = H("fa:vid:document:v1" ‖ document_oid)`: the same bytes
/// of the same kind are the same vertex, so intake is idempotent by identity.
#[must_use]
pub fn document_vid(oid: &Oid) -> VId {
    let d = domain_digest(b"fa:vid:document:v1", &[&oid.0]);
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d[..16]);
    VId(u128::from_le_bytes(lo))
}

/// A Document as journaled (`fa:document:v1`, inline storage).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Document {
    pub book_id: Id128,
    /// A registered kind tag (`evidence_policy.toml [[kind]]`).
    pub kind: u8,
    pub mime: String,
    /// A registered provenance grade tag (`evidence_policy.toml [[grade]]`).
    pub grade: u8,
    /// The principal that brought the bytes into the book.
    pub retrieved_by: VId,
    /// The canonical bytes.
    pub bytes: Vec<u8>,
}

impl Document {
    #[must_use]
    pub fn doc_commit(&self) -> [u8; 32] {
        doc_commit(self.kind, &self.bytes)
    }

    #[must_use]
    pub fn oid(&self) -> Oid {
        document_oid(self.book_id, &self.doc_commit())
    }

    /// The citation an entry carries for this document in `role`.
    #[must_use]
    pub fn evidence_ref(&self, role: u8) -> EvidenceRef {
        EvidenceRef {
            document_oid: self.oid(),
            doc_commit: self.doc_commit(),
            role,
        }
    }

    fn prefix(&self, w: &mut Writer) {
        w.u16(1)
            .fixed(&self.book_id.0)
            .u8(self.kind)
            .str(&self.mime)
            .u64(len_u64(self.bytes.len()))
            .fixed(&self.doc_commit())
            .u8(self.grade)
            .u128(self.retrieved_by.0);
    }

    /// The inline payload: the bytes ride in the journal.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::with_capacity(self.bytes.len() + 128);
        self.prefix(&mut w);
        w.u8(STORAGE_INLINE).bytes(&self.bytes);
        w.finish().map_err(|e| KernelError::Model(e.into()))
    }

    /// The external payload: size and commitment inline, the bytes in
    /// registered store `store` under `locator`.
    pub fn canonical_bytes_external(
        &self,
        store: u16,
        locator: &str,
    ) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::with_capacity(256);
        self.prefix(&mut w);
        w.u8(STORAGE_EXTERNAL).u16(store).str(locator);
        w.finish().map_err(|e| KernelError::Model(e.into()))
    }

    /// Decode an inline payload and verify it (an external payload carries
    /// no bytes: decode it as a [`DocumentRecord`]).
    pub fn decode(payload: &[u8]) -> Result<Self, KernelError> {
        let record = DocumentRecord::decode(payload)?;
        match record.storage {
            Storage::Inline(ref bytes) => Ok(Self {
                book_id: record.book_id,
                kind: record.kind,
                mime: record.mime.clone(),
                grade: record.grade,
                retrieved_by: record.retrieved_by,
                bytes: bytes.clone(),
            }),
            Storage::External { .. } => Err(KernelError::Corrupt(format!(
                "document {}: an external payload carries no bytes",
                hex(&record.doc_commit)
            ))),
        }
    }
}

/// Where a recorded document's bytes are (plan §9.1 `storage`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Storage {
    /// In the journal, in the payload itself.
    Inline(Vec<u8>),
    /// In registered store `store` (document_stores.toml) under `locator`.
    External { store: u16, locator: String },
}

/// A Document row's payload, decoded: what every reader of the evidence law
/// needs — kind, grade, uploader, size, commitment — and where the bytes
/// are. An inline payload is verified against its bytes at decode; an
/// external one when its bytes are fetched ([`fetch_document`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentRecord {
    pub book_id: Id128,
    pub kind: u8,
    pub mime: String,
    pub size: u64,
    pub doc_commit: [u8; 32],
    pub grade: u8,
    pub retrieved_by: VId,
    pub storage: Storage,
}

impl DocumentRecord {
    #[must_use]
    pub fn oid(&self) -> Oid {
        document_oid(self.book_id, &self.doc_commit)
    }

    /// The citation an entry carries for this document in `role`.
    #[must_use]
    pub fn evidence_ref(&self, role: u8) -> EvidenceRef {
        EvidenceRef {
            document_oid: self.oid(),
            doc_commit: self.doc_commit,
            role,
        }
    }

    /// The document `bytes` are, if they are this record's: the size and the
    /// commitment recomputed from them must be the recorded ones.
    #[must_use]
    pub fn with_bytes(&self, bytes: Vec<u8>) -> Option<Document> {
        if len_u64(bytes.len()) != self.size || doc_commit(self.kind, &bytes) != self.doc_commit {
            return None;
        }
        Some(Document {
            book_id: self.book_id,
            kind: self.kind,
            mime: self.mime.clone(),
            grade: self.grade,
            retrieved_by: self.retrieved_by,
            bytes,
        })
    }

    /// Decode a `fa:document:v1` payload; an inline one must reproduce its
    /// stored size and commitment, or the row is corrupt.
    pub fn decode(payload: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(payload);
        let record = (|| -> Result<Self, DecodeError> {
            if r.u16("document.version")? != 1 {
                return Err(r.invalid("document.version"));
            }
            let book_id = Id128(r.fixed("document.book_id")?);
            let kind = r.u8("document.kind")?;
            let mime = r.str(MAX_DECODED_MIME_BYTES, "document.mime")?.to_string();
            let size = r.u64("document.size")?;
            let doc_commit: [u8; 32] = r.fixed("document.doc_commit")?;
            let grade = r.u8("document.grade")?;
            let retrieved_by = VId(r.u128("document.retrieved_by")?);
            let storage = match r.u8("document.storage")? {
                STORAGE_INLINE => Storage::Inline(
                    r.bytes(MAX_DECODED_DOCUMENT_BYTES, "document.bytes")?
                        .to_vec(),
                ),
                STORAGE_EXTERNAL => {
                    let store = r.u16("document.store")?;
                    let locator = r.str(MAX_LOCATOR_BYTES, "document.locator")?.to_string();
                    if store == 0 || locator.is_empty() {
                        return Err(r.invalid("document.external"));
                    }
                    Storage::External { store, locator }
                }
                t => return Err(r.bad_tag("document.storage", t)),
            };
            r.finish()?;
            Ok(Self {
                book_id,
                kind,
                mime,
                size,
                doc_commit,
                grade,
                retrieved_by,
                storage,
            })
        })()
        .map_err(|e| KernelError::Model(e.into()))?;
        let verifies = match &record.storage {
            Storage::Inline(bytes) => {
                record.size == len_u64(bytes.len())
                    && record.doc_commit == doc_commit(record.kind, bytes)
            }
            Storage::External { .. } => {
                usize::try_from(record.size).is_ok_and(|n| n <= MAX_DECODED_DOCUMENT_BYTES)
            }
        };
        if !verifies {
            return Err(KernelError::Corrupt(format!(
                "document {}: stored size/commitment do not match its bytes",
                hex(&record.doc_commit)
            )));
        }
        Ok(record)
    }
}

/// The outcome of intake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentAdded {
    pub oid: Oid,
    pub doc_commit: [u8; 32],
    pub vid: VId,
    pub kind: u8,
    /// The grade the book holds: on a repeat intake, the first intake's.
    pub grade: u8,
    pub size: u64,
    pub recorded_at: CommitSeq,
    /// The same bytes of the same kind were already in the book; nothing was written.
    pub already_recorded: bool,
}

#[must_use]
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn intake_refusal(message: impl Into<String>, fix: impl Into<String>) -> Refusal {
    Refusal::new(
        code::DOCUMENT_INTAKE,
        exit::USAGE,
        message,
        "registries/evidence_policy.toml; plan §9.1 Document",
        fix,
    )
}

/// Check a stored Document row against itself: the payload decodes and its
/// bytes reproduce the stored size and commitment, the vertex is the one the
/// payload's identity derives, and every mirror the kernel or a query might
/// read (`_fa_digest`, `code`, `book_id`, the label) equals what the payload
/// says. The payload is the authority; a mirror is never more authoritative
/// than it (FA-INV-04), so any disagreement is drift, named here.
pub fn verify_row(row: &VertexRow, policy: &EvidencePolicy) -> Result<DocumentRecord, String> {
    if !row.labels.contains(&label::DOCUMENT) {
        return Err("the vertex is not labeled Document".into());
    }
    let Some(CanonicalScalar::Bytes(payload)) = prop(row, property::FA_PAYLOAD) else {
        return Err("the vertex carries no document payload".into());
    };
    let doc = DocumentRecord::decode(payload.as_slice())
        .map_err(|e| format!("the payload does not verify: {e}"))?;
    if document_vid(&doc.oid()) != row.vid {
        return Err("the payload is not the document this vertex's identity names".into());
    }
    if let Storage::External { store, locator } = &doc.storage {
        let stores =
            fa_registry::document_stores::DocumentStores::embedded().map_err(|e| e.to_string())?;
        let Some(registered) = stores.get(*store) else {
            return Err(format!(
                "its bytes are in store {store}, which is not registered"
            ));
        };
        if doc.size > registered.max_document_bytes {
            return Err(format!(
                "it is {} bytes, past store {store}'s bound of {}",
                doc.size, registered.max_document_bytes
            ));
        }
        if *locator != crate::blob::locator_of(&doc.doc_commit) {
            return Err(
                "its locator is not its commitment (the store is content-addressed)".into(),
            );
        }
    }
    let commit = doc.doc_commit;
    match prop(row, property::FA_DIGEST) {
        Some(CanonicalScalar::Bytes(b)) if b.as_slice() == commit.as_slice() => {}
        _ => return Err("the commitment mirror differs from the payload's commitment".into()),
    }
    let kind = policy
        .kind_by_tag(doc.kind)
        .ok_or_else(|| format!("the payload's kind {} is not registered", doc.kind))?;
    if policy.grade_by_tag(doc.grade).is_none() {
        return Err(format!(
            "the payload's grade {} is not registered",
            doc.grade
        ));
    }
    match prop(row, property::CODE) {
        Some(CanonicalScalar::Text(t)) if t.as_bytes() == kind.name.as_bytes() => {}
        _ => {
            return Err(format!(
                "the kind mirror differs from the payload's kind `{}`",
                kind.name
            ));
        }
    }
    match prop(row, property::BOOK_ID) {
        Some(CanonicalScalar::Bytes(b)) if b.as_slice() == doc.book_id.0.as_slice() => {}
        _ => return Err("the book_id mirror differs from the payload's book".into()),
    }
    Ok(doc)
}

/// A held document's public metadata (plan §9.6: kind, size and commitment
/// stay visible to any reader; the bytes never travel here).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentSummary {
    pub oid: Oid,
    pub kind: u8,
    pub mime: String,
    pub grade: u8,
    pub size: u64,
    pub doc_commit: [u8; 32],
    pub recorded_at: CommitSeq,
}

/// Every document the book holds at `seq`, in `(recorded_at, oid)` order,
/// as public metadata. Each row verifies against itself first; a row that
/// does not is drift (exit 8, as for `fa document read`), never skipped.
///
/// `recorded_at` is the document's intake: the commit of its custody event
/// 0, the `ImportReceipt` written with it and never changed. The Document
/// row's own `created_at` starts its current version, which a custody
/// transfer moves.
pub fn list_documents<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    seq: CommitSeq,
) -> Outcome<Vec<DocumentSummary>> {
    let policy = EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let mut out = Vec::new();
    for row in db.vertices_at(seq)? {
        if !row.labels.contains(&label::DOCUMENT) {
            continue;
        }
        let doc = match verify_row(&row, &policy) {
            Ok(doc) => doc,
            Err(why) => {
                return Ok(Err(Refusal::new(
                    code::DOCUMENT_DRIFT,
                    exit::VERIFICATION,
                    format!("document vertex {:032x}: {why}", row.vid.0),
                    "FA-INV-04 (a mirror is never more authoritative than the payload), FA-INV-05 (the closure verifies)",
                    "preserve the store and report the drift; nothing that cites this document is admitted until it is explained",
                )));
            }
        };
        let oid = doc.oid();
        let receipt = crate::custody::custody_vid(doc.book_id, &oid, 0);
        let Some(intake) = db.vertex_at(receipt, seq)? else {
            return Ok(Err(drift(&oid, "its custody receipt (event 0) is missing")));
        };
        out.push(DocumentSummary {
            oid,
            kind: doc.kind,
            mime: doc.mime,
            grade: doc.grade,
            size: doc.size,
            doc_commit: doc.doc_commit,
            recorded_at: intake.created_at,
        });
    }
    out.sort_by_key(|d| (d.recorded_at, d.oid));
    Ok(Ok(out))
}

/// The refusal for a Document whose stored row does not verify (exit 8).
pub(crate) fn drift(oid: &Oid, why: &str) -> Refusal {
    Refusal::new(
        code::DOCUMENT_DRIFT,
        exit::VERIFICATION,
        format!("document {}: {why}", hex(&oid.0)),
        "FA-INV-04 (a mirror is never more authoritative than the payload), FA-INV-05 (the closure verifies)",
        "preserve the store and report the drift; nothing that cites this document is admitted until it is explained",
    )
}

/// The intake outcome a stored row reports, after it verifies (a repeat
/// intake never vouches for a drifted row).
fn added_from_row(
    row: &VertexRow,
    policy: &EvidencePolicy,
    oid: &Oid,
    already_recorded: bool,
) -> Outcome<DocumentAdded> {
    let doc = match verify_row(row, policy) {
        Ok(doc) => doc,
        Err(why) => return Ok(Err(drift(oid, &why))),
    };
    Ok(Ok(DocumentAdded {
        oid: doc.oid(),
        doc_commit: doc.doc_commit,
        vid: row.vid,
        kind: doc.kind,
        grade: doc.grade,
        size: doc.size,
        recorded_at: row.created_at,
        already_recorded,
    }))
}

/// The intake laws every document meets before it is written (plan §9.1):
/// this book's, non-empty, inline-bounded, a printable mime, a registered
/// kind, and a grade the uploader may declare. Returns the kind's name.
pub(crate) fn intake_check(
    policy: &EvidencePolicy,
    book: &BookContext,
    doc: &Document,
    max_bytes: u64,
) -> Result<String, Refusal> {
    if doc.book_id != book.book_id {
        return Err(Refusal::new(
            code::COORDINATE,
            exit::USAGE,
            format!(
                "the document names book {} but this book is {}",
                doc.book_id.to_hex(),
                book.book_id.to_hex()
            ),
            "plan §2.2 (an object belongs to exactly one book)",
            "set book_id to this book's id (fa book info --json)",
        ));
    }
    if doc.bytes.is_empty() {
        return Err(intake_refusal(
            "the document is empty; zero bytes are not evidence",
            "add the file that records the transaction",
        ));
    }
    if len_u64(doc.bytes.len()) > max_bytes {
        let fix = if max_bytes == inline_document_bound(policy) {
            "record it in the book's blob store: `fa document add` routes a document past the inline bound there (library: add_document_external with a registered store)"
        } else {
            "split the document: it is past every registered store's bound (document_stores.toml)"
        };
        return Err(intake_refusal(
            format!(
                "the document is {} bytes; this intake is bounded at {max_bytes}",
                doc.bytes.len()
            ),
            fix,
        ));
    }
    let mime_ok = !doc.mime.is_empty()
        && doc.mime.len() <= policy.max_mime_bytes
        && doc.mime.bytes().all(|b| b.is_ascii_graphic());
    if !mime_ok {
        return Err(intake_refusal(
            format!(
                "mime `{}` must be 1..={} printable ASCII bytes with no spaces",
                doc.mime, policy.max_mime_bytes
            ),
            "pass --mime type/subtype, e.g. application/pdf",
        ));
    }
    let Some(kind) = policy.kind_by_tag(doc.kind) else {
        return Err(intake_refusal(
            format!("document kind {} is not registered", doc.kind),
            format!(
                "use a registered kind: {}",
                policy
                    .kinds
                    .iter()
                    .map(|k| k.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    };
    let Some(grade) = policy.grade_by_tag(doc.grade) else {
        return Err(intake_refusal(
            format!("provenance grade {} is not registered", doc.grade),
            "declare HumanUpload or AgentUpload",
        ));
    };
    if !grade.intake {
        return Err(Refusal::new(
            code::GRADE_UNVERIFIED,
            exit::REFUSAL,
            format!(
                "grade `{}` is derived from a receipt chain (signature, connector transcript, rule run) this book cannot verify at intake",
                grade.name
            ),
            format!(
                "registries/evidence_policy.toml [[grade]] name = \"{}\" (intake = false); plan §9.3",
                grade.name
            ),
            "declare the upload honestly: HumanUpload when a person supplied the bytes, AgentUpload when an agent did",
        ));
    }
    Ok(kind.name.clone())
}

/// Stage a new Document vertex with its payload, mirrors and `custody_len`
/// of 1 (its receipt is staged beside it).
pub(crate) fn stage_document(
    batch: &mut WriteBatch,
    book: &BookContext,
    doc: &Document,
    kind_name: &str,
) -> Result<(), KernelError> {
    stage_document_payload(batch, book, doc, kind_name, doc.canonical_bytes()?)
}

fn stage_document_payload(
    batch: &mut WriteBatch,
    book: &BookContext,
    doc: &Document,
    kind_name: &str,
    payload: Vec<u8>,
) -> Result<(), KernelError> {
    let commit = doc.doc_commit();
    let mut props = vec![
        (property::FA_PAYLOAD, scalar_bytes("_fa_payload", payload)?),
        (
            property::FA_DIGEST,
            scalar_bytes("_fa_digest", commit.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("book_id", book.book_id.0.to_vec())?,
        ),
        (property::CODE, scalar_text("code", kind_name)?),
        (property::CUSTODY_LEN, CanonicalScalar::Int(1)),
    ];
    props.sort_by_key(|(k, _)| k.0);
    batch.create_vertex(document_vid(&doc.oid()), vec![label::DOCUMENT], props);
    Ok(())
}

/// The sources of `doc` (oid `oid`) that are this book's documents, for its
/// `DERIVED_FROM` lineage, read through `read`; empty when `doc` is no
/// derivation. Derived text is governed as its source is (plan §9.6): a
/// derivation of a document a redaction contract governs is refused
/// (FA-REF-083) unless the same contract governs the derivation's kind, so a
/// reader without the revealing op never reads a governed source's withheld
/// bytes through text derived from them.
pub(crate) fn derivation_sources(
    doc: &Document,
    oid: &Oid,
    policy: &EvidencePolicy,
    book: &BookContext,
    mut read: impl FnMut(VId) -> Result<Option<VertexRow>, KernelError>,
) -> Result<Result<Vec<Oid>, Refusal>, KernelError> {
    let Ok((sources, _)) = crate::import::decode_derivation(&doc.bytes) else {
        return Ok(Ok(Vec::new()));
    };
    let contracts = crate::redaction::contracts()?;
    let governs = contracts.for_kind(doc.kind).map(|contract| contract.id);
    let mut parents = Vec::new();
    for parent in sources {
        if parent == *oid {
            continue;
        }
        let Some(row) = read(document_vid(&parent))? else {
            continue;
        };
        let Ok(record) = verify_row(&row, policy) else {
            continue;
        };
        if record.book_id != book.book_id {
            continue;
        }
        if let Some(contract) = contracts.for_kind(record.kind)
            && governs != Some(contract.id)
        {
            return Ok(Err(Refusal::new(
                code::DOCUMENT_INTAKE,
                exit::USAGE,
                format!(
                    "document {} is governed by redaction contract {} (`{}`), which does not govern the kind of a document derived from it",
                    hex(&parent.0),
                    contract.id,
                    contract.name
                ),
                "plan §9.6 (derived text is governed as its source is); registries/redaction_contracts.toml",
                "record the derivation under its source's kind (omit --kind), or another kind the same redaction contract governs",
            )));
        }
        parents.push(parent);
    }
    Ok(Ok(parents))
}

/// Record a document in the book (plan §9.1, §9.3): one `Document` vertex
/// carrying the canonical payload and its mirrors (`_fa_digest` =
/// `doc_commit`, `code` = the kind's registered name, `book_id`,
/// `custody_len`), and its `ImportReceipt` — custody event 0, source
/// `Upload(retrieved_by)` — in one commit. The same bytes of the same kind
/// are the recorded outcome, never a second vertex or a second receipt.
pub async fn add_document<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    doc: &Document,
) -> Outcome<DocumentAdded> {
    let policy = EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let kind_name = match intake_check(&policy, book, doc, inline_document_bound(&policy)) {
        Ok(name) => name,
        Err(r) => return Ok(Err(r)),
    };
    let source = IntakeSource::Upload {
        principal: doc.retrieved_by,
    };
    if let Err(r) = crate::custody::admit_source(&source) {
        return Ok(Err(r));
    }
    let commit = doc.doc_commit();
    let oid = document_oid(book.book_id, &commit);
    let vid = document_vid(&oid);
    if let Some(row) = db.vertex(vid)? {
        return added_from_row(&row, &policy, &oid, true);
    }
    let mut batch = WriteBatch::new(relation::CUSTODY_OF);
    stage_document(&mut batch, book, doc, &kind_name)?;
    crate::custody::stage_receipt(&mut batch, book, doc, source, doc.retrieved_by, None)?;

    let derived_parents =
        match derivation_sources(doc, &oid, &policy, book, |pvid| Ok(db.vertex(pvid)?))? {
            Ok(parents) => parents,
            Err(refusal) => return Ok(Err(refusal)),
        };

    if derived_parents.is_empty() {
        match db.write(&ctx.commit(), batch).await {
            Ok(seq) => Ok(Ok(DocumentAdded {
                oid,
                doc_commit: commit,
                vid,
                kind: doc.kind,
                grade: doc.grade,
                size: len_u64(doc.bytes.len()),
                recorded_at: seq,
                already_recorded: false,
            })),
            // A concurrent intake of the same bytes won: that is the outcome.
            Err(fgdb::WriteError::AlreadyLive { .. }) => match db.vertex(vid)? {
                Some(row) => added_from_row(&row, &policy, &oid, true),
                None => Err(KernelError::Corrupt(format!(
                    "document {} reported live but is absent",
                    hex(&commit)
                ))),
            },
            Err(e) => Err(e.into()),
        }
    } else {
        let txn_cx = ctx.txn();
        let mut txn = db.begin(&txn_cx)?;
        let mut derived_batch = WriteBatch::new(relation::DERIVED_FROM);
        for parent_oid in &derived_parents {
            let target = document_vid(parent_oid);
            derived_batch.add_edge(
                edge_id(relation::DERIVED_FROM, vid, target),
                vid,
                target,
                vec![],
            );
        }
        if let Err(e) = txn.write_ordered(db, vec![batch, derived_batch]) {
            txn.abort();
            return Err(e.into());
        }
        match txn.commit(db, &ctx.commit()).await {
            Ok(seq) => Ok(Ok(DocumentAdded {
                oid,
                doc_commit: commit,
                vid,
                kind: doc.kind,
                grade: doc.grade,
                size: len_u64(doc.bytes.len()),
                recorded_at: seq,
                already_recorded: false,
            })),
            Err(fgdb::WriteTxnError::Write(fgdb::WriteError::AlreadyLive { .. })) => {
                match db.vertex(vid)? {
                    Some(row) => added_from_row(&row, &policy, &oid, true),
                    None => Err(KernelError::Corrupt(format!(
                        "document {} reported live but is absent",
                        hex(&commit)
                    ))),
                }
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// The record at `oid` — metadata and where the bytes are — verified
/// against its own payload and mirrors, or `None` when the book does not
/// hold it. No bytes are fetched; a drifted row is an error naming
/// FA-REF-085.
pub fn document_record<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    oid: &Oid,
) -> Result<Option<DocumentRecord>, KernelError> {
    let Some(row) = db.vertex(document_vid(oid))? else {
        return Ok(None);
    };
    let policy = EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    match verify_row(&row, &policy) {
        Ok(doc) if doc.oid() == *oid => Ok(Some(doc)),
        Ok(_) => Err(KernelError::Corrupt(format!(
            "{} document {}: the vertex holds another document",
            code::DOCUMENT_DRIFT,
            hex(&oid.0)
        ))),
        Err(why) => Err(KernelError::Corrupt(format!(
            "{} document {}: {why}",
            code::DOCUMENT_DRIFT,
            hex(&oid.0)
        ))),
    }
}

fn record_or_drift<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    oid: &Oid,
) -> Outcome<Option<DocumentRecord>> {
    let Some(row) = db.vertex(document_vid(oid))? else {
        return Ok(Ok(None));
    };
    let policy = EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    match verify_row(&row, &policy) {
        Ok(doc) if doc.oid() == *oid => Ok(Ok(Some(doc))),
        Ok(_) => Ok(Err(drift(oid, "the vertex holds another document"))),
        Err(why) => Ok(Err(drift(oid, &why))),
    }
}

/// The refusal for bytes a store cannot produce (exit 5: the environment
/// failed to supply them; never a silent null).
fn blob_missing(oid: &Oid, why: &str) -> Refusal {
    Refusal::new(
        code::BLOB_MISSING,
        exit::FOUNDATION,
        format!("document {}: {why}", hex(&oid.0)),
        "plan §9.1 (a document's bytes are produced on request and verified against its public commitment); registries/document_stores.toml",
        "restore the blob from the book's backup into its store; the commitment names exactly the bytes expected, and nothing substitutes for them",
    )
}

/// The document at `oid` with its bytes, from its payload: an inline
/// document, verified; an external one is FA-REF-116 here (its bytes are in
/// a store: [`fetch_document`]); a drifted row is FA-REF-085.
pub fn read_document<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    oid: &Oid,
) -> Outcome<Option<Document>> {
    let record = match record_or_drift(db, oid)? {
        Ok(Some(record)) => record,
        Ok(None) => return Ok(Ok(None)),
        Err(r) => return Ok(Err(r)),
    };
    match &record.storage {
        Storage::Inline(bytes) => Ok(record
            .with_bytes(bytes.clone())
            .map(Some)
            .ok_or_else(|| drift(oid, "the inline bytes do not reproduce the commitment"))),
        Storage::External { store, .. } => Ok(Err(blob_missing(
            oid,
            &format!("its bytes are in store {store}; read it with fetch_document and that store"),
        ))),
    }
}

/// The document at `oid` with its bytes, wherever they are, verified on
/// every read: an inline document from its payload; an external one from
/// `store`, whose bytes must reproduce the recorded size and commitment
/// (else FA-REF-085, exit 8). A missing blob, a store that cannot be read,
/// or a document held in another store is FA-REF-116 (exit 5).
pub async fn fetch_document<V, W>(
    db: &Database<V>,
    ctx: &PurposeContexts,
    store: &crate::blob::BlobStore<W>,
    oid: &Oid,
) -> Outcome<Option<Document>>
where
    V: asupersync::fs::Vfs + Clone,
    W: asupersync::fs::Vfs + Clone,
{
    fetch_document_with(db, ctx, store, oid, |_| Ok(())).await
}

/// Like [`fetch_document`], admitting the verified [`DocumentRecord`]
/// through `before_fetch` before reading any external blob bytes.
pub async fn fetch_document_with<V, W, F>(
    db: &Database<V>,
    ctx: &PurposeContexts,
    store: &crate::blob::BlobStore<W>,
    oid: &Oid,
    before_fetch: F,
) -> Outcome<Option<Document>>
where
    V: asupersync::fs::Vfs + Clone,
    W: asupersync::fs::Vfs + Clone,
    F: FnOnce(&DocumentRecord) -> Result<(), Refusal>,
{
    let record = match record_or_drift(db, oid)? {
        Ok(Some(record)) => record,
        Ok(None) => return Ok(Ok(None)),
        Err(r) => return Ok(Err(r)),
    };
    if let Err(r) = before_fetch(&record) {
        return Ok(Err(r));
    }
    let bytes = match &record.storage {
        Storage::Inline(bytes) => bytes.clone(),
        Storage::External { store: id, locator } => {
            if *id != store.id() {
                return Ok(Err(blob_missing(
                    oid,
                    &format!("its bytes are in store {id}, not store {}", store.id()),
                )));
            }
            match store.get(&ctx.query(), locator, record.size).await {
                Ok(Some(bytes)) => bytes,
                Ok(None) => {
                    return Ok(Err(blob_missing(
                        oid,
                        &format!("store {id} holds no blob {locator}"),
                    )));
                }
                Err(e) => {
                    return Ok(Err(blob_missing(
                        oid,
                        &format!("store {id} could not be read: {e}"),
                    )));
                }
            }
        }
    };
    Ok(record.with_bytes(bytes).map(Some).ok_or_else(|| {
        drift(
            oid,
            "the stored bytes do not reproduce the recorded size and commitment",
        )
    }))
}

/// Record a document whose bytes live in `store` (plan §9.1 `External`):
/// the intake laws bounded by the store's limit, the upload's source, then
/// the bytes written under the commitment's locator, then — in one commit —
/// the Document vertex (size and commitment inline, the payload naming the
/// store and locator) and its ImportReceipt. The same bytes of the same
/// kind are the recorded outcome, however they were first stored.
pub async fn add_document_external<V, W>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    store: &crate::blob::BlobStore<W>,
    doc: &Document,
) -> Outcome<DocumentAdded>
where
    V: asupersync::fs::Vfs + Clone,
    W: asupersync::fs::Vfs + Clone,
{
    let policy = EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let kind_name = match intake_check(&policy, book, doc, store.max_document_bytes()) {
        Ok(name) => name,
        Err(r) => return Ok(Err(r)),
    };
    let source = IntakeSource::Upload {
        principal: doc.retrieved_by,
    };
    if let Err(r) = crate::custody::admit_source(&source) {
        return Ok(Err(r));
    }
    let commit = doc.doc_commit();
    let oid = document_oid(book.book_id, &commit);
    let vid = document_vid(&oid);
    if let Some(row) = db.vertex(vid)? {
        return added_from_row(&row, &policy, &oid, true);
    }
    let locator = crate::blob::locator_of(&commit);
    if let Err(e) = store.put(&ctx.commit(), &locator, &doc.bytes).await {
        return Ok(Err(blob_missing(
            &oid,
            &format!("store {} could not be written: {e}", store.id()),
        )));
    }
    let mut batch = WriteBatch::new(relation::CUSTODY_OF);
    stage_document_payload(
        &mut batch,
        book,
        doc,
        &kind_name,
        doc.canonical_bytes_external(store.id(), &locator)?,
    )?;
    crate::custody::stage_receipt(&mut batch, book, doc, source, doc.retrieved_by, None)?;
    match db.write(&ctx.commit(), batch).await {
        Ok(seq) => Ok(Ok(DocumentAdded {
            oid,
            doc_commit: commit,
            vid,
            kind: doc.kind,
            grade: doc.grade,
            size: len_u64(doc.bytes.len()),
            recorded_at: seq,
            already_recorded: false,
        })),
        Err(fgdb::WriteError::AlreadyLive { .. }) => match db.vertex(vid)? {
            Some(row) => added_from_row(&row, &policy, &oid, true),
            None => Err(KernelError::Corrupt(format!(
                "document {} reported live but is absent",
                hex(&commit)
            ))),
        },
        Err(e) => Err(e.into()),
    }
}

/// The class's evidence minimum over the distinct cited documents (pure; the
/// posting transaction supplies them, verified, each admissible self-sourced
/// one with the Reviewed attestation it read, and `manual` with the reason
/// of the preparer's ManualAssertion when it read one).
///
/// In order: a document of an admissible kind counts when it is not
/// self-sourced, or when it is (`AgentUpload`, `Generated`: plan §9.3) and a
/// principal other than its uploader reviewed it; a review by the uploader
/// is refused (FA-REF-111). If the documents fall short and the class's row
/// admits a ManualAssertion, the preparer's assertion with a registered
/// reason meets the minimum (an unregistered one: FA-REF-112). Otherwise the
/// refusal is FA-REF-086 when unreviewed self-sourced documents would have
/// met it, else FA-REF-080.
pub fn check_minimum(
    policy: &EvidencePolicy,
    reasons: &ReasonCodes,
    class_name: &str,
    cited: &[CitedDocument],
    manual: Option<u16>,
) -> Result<(), Refusal> {
    let Some(min) = policy.minimum(class_name) else {
        // The registry is total over the classes; a gap is unsupported, never exempt.
        return Err(Refusal::new(
            code::EVIDENCE_MINIMUM,
            exit::REFUSAL,
            format!("class `{class_name}` has no registered evidence minimum"),
            "registries/evidence_policy.toml (total over entry_classes.toml)",
            "register the class's minimum before posting it",
        ));
    };
    if min.requirement != Requirement::Documents {
        return Ok(());
    }
    let needed = usize::from(min.min_documents);
    let admissible: Vec<&CitedDocument> =
        cited.iter().filter(|c| min.kinds.admits(c.kind)).collect();
    let mut counted = 0usize;
    for c in &admissible {
        if !self_sourced(policy, c.grade) {
            counted += 1;
            continue;
        }
        match c.review {
            Some(r) if r.reviewer == c.uploader => {
                return Err(self_review_refusal(&c.oid, r.reviewer));
            }
            Some(_) => counted += 1,
            None => {}
        }
    }
    if counted >= needed {
        return Ok(());
    }
    if min.manual_assertion
        && let Some(reason) = manual
    {
        return match reasons.get(MANUAL_ASSERTION_SCOPE, reason) {
            Some(_) => Ok(()),
            None => Err(reason_refusal(reasons, reason)),
        };
    }
    if admissible.len() >= needed {
        return Err(Refusal::new(
            code::SELF_SOURCED,
            exit::REFUSAL,
            format!(
                "`{class_name}` requires at least {needed} document(s); {} of the entry's {} admissible document(s) are self-sourced and unreviewed, and a self-sourced document counts only once a principal other than its uploader reviews it",
                admissible.len() - counted,
                admissible.len()
            ),
            "plan §9.3 (self-sourced evidence: AgentUpload, Generated; it counts once an approver other than the uploader records a Reviewed attestation)",
            "have a principal other than the uploader, holding `approve`, record a Reviewed attestation over each such document (`fa document attest review --document <oid> --as <reviewer> --grant approve --json` or the attestation library's record_review), then post again; or cite a document a person or third party supplied, recorded with `fa document add <file> --grade HumanUpload --json` by that person; never re-declare an agent's upload as a person's",
        ));
    }
    let kinds = policy.kind_names(&min.kinds).join(", ");
    let admissible = admissible.len();
    let message = if cited.is_empty() {
        format!(
            "`{class_name}` requires at least {} document(s) ({kinds}); the entry cites none",
            min.min_documents
        )
    } else {
        format!(
            "`{class_name}` requires at least {} document(s) of kind {kinds}; the entry cites {} document(s), {admissible} admissible",
            min.min_documents,
            cited.len()
        )
    };
    let fix = if min.manual_assertion {
        "record the source document with `fa document add <file> --kind <Kind> --json` and cite the printed `evidence` object in the intent's `evidence`; or, when no document exists, the preparer records a ManualAssertion over this proposal with a reason from reason_codes.toml (the attestation library's record_manual_assertion) before posting it — never fabricate a document"
    } else {
        "record the source document with `fa document add <file> --kind <Kind> --json` and cite the printed `evidence` object in the intent's `evidence`; this class admits no ManualAssertion in place of a document — never fabricate one"
    };
    Err(Refusal::new(
        code::EVIDENCE_MINIMUM,
        exit::REFUSAL,
        message,
        format!(
            "registries/evidence_policy.toml [[minimum]] class = \"{class_name}\" (FA-INV-05 evidence-minimum)"
        ),
        fix,
    ))
}

/// One distinct cited document, as its verified payload states it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CitedDocument {
    pub vid: VId,
    pub oid: Oid,
    pub kind: u8,
    pub grade: u8,
    /// The principal that brought the bytes into the book.
    pub uploader: VId,
    /// The Reviewed attestation over it, when the posting kernel read one
    /// (it reads one for each admissible self-sourced document).
    pub review: Option<Review>,
}

/// Resolve `citations` — strictly ascending by `(oid, commit, role)`, as
/// every payload that carries them is — inside `txn`: each names a
/// registered role and a document this book holds, read as a witness and
/// verified against its own payload, under exactly the cited commitment.
/// Returns the distinct documents in citation order.
pub fn resolve_documents<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    policy: &EvidencePolicy,
    citations: &[EvidenceRef],
) -> Outcome<Vec<CitedDocument>> {
    for (i, e) in citations.iter().enumerate() {
        if policy.role_by_tag(e.role).is_none() {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!("evidence[{i}] has unregistered role {}", e.role),
                "registries/evidence_policy.toml [[role]]",
                format!(
                    "use a registered role tag: {}",
                    policy
                        .roles
                        .iter()
                        .map(|r| format!("{} {}", r.tag, r.name))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )));
        }
    }
    let mut cited: Vec<CitedDocument> = Vec::new();
    // `evidence` is strictly ascending by (oid, commit, role): citations of
    // one document are adjacent. The document is read once and counts once;
    // every citation's commitment is still checked against it.
    let mut last: Option<(Oid, [u8; 32])> = None;
    for (i, e) in citations.iter().enumerate() {
        let cached = match &last {
            Some((oid, commit)) if *oid == e.document_oid => Some(*commit),
            _ => None,
        };
        let repeat = cached.is_some();
        let dvid = document_vid(&e.document_oid);
        // The whole row is the witness: the kind and commitment the law
        // reads come from the verified payload, never from a mirror alone.
        let (stored, resolved) = match cached {
            Some(commit) => (commit, None),
            None => match txn.vertex(db, dvid)? {
                None => {
                    return Ok(Err(Refusal::new(
                        code::EVIDENCE_UNKNOWN,
                        exit::REFUSAL,
                        format!(
                            "evidence[{i}] names document {} which this book does not hold",
                            hex(&e.document_oid.0)
                        ),
                        "FA-INV-05 (an entry whose evidence references an unknown object is refused)",
                        "record it first with `fa document add <file> --json` and cite the oid it prints",
                    )));
                }
                Some(row) => match verify_row(&row, policy) {
                    Ok(doc) if doc.oid() == e.document_oid => (
                        doc.doc_commit,
                        Some(CitedDocument {
                            vid: dvid,
                            oid: e.document_oid,
                            kind: doc.kind,
                            grade: doc.grade,
                            uploader: doc.retrieved_by,
                            review: None,
                        }),
                    ),
                    Ok(_) => {
                        return Ok(Err(drift(
                            &e.document_oid,
                            "the vertex holds another document",
                        )));
                    }
                    Err(why) => return Ok(Err(drift(&e.document_oid, &why))),
                },
            },
        };
        if stored.as_slice() != e.doc_commit.as_slice() {
            return Ok(Err(Refusal::new(
                code::EVIDENCE_COMMIT,
                exit::REFUSAL,
                format!(
                    "evidence[{i}] cites doc_commit {} but document {} commits to {}",
                    hex(&e.doc_commit),
                    hex(&e.document_oid.0),
                    hex(&stored)
                ),
                "plan §9.1 (every citation carries the public commitment)",
                "cite the doc_commit `fa document add` printed for this document",
            )));
        }
        let (false, Some(doc)) = (repeat, resolved) else {
            continue;
        };
        if let Err(r) = crate::custody::witness_custody(txn, db, policy, &e.document_oid)? {
            return Ok(Err(r));
        }
        last = Some((e.document_oid, stored));
        cited.push(doc);
    }
    Ok(Ok(cited))
}

/// What step 5b resolved: the edges the entry gains.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedEvidence {
    /// The distinct cited documents' vertices, ascending (`EVIDENCED_BY`).
    pub documents: Vec<VId>,
    /// The preparer's ManualAssertion the minimum rests on (`ATTESTS`).
    pub manual_assertion: Option<VId>,
}

/// Step 5b of `post`: every citation resolves ([`resolve_documents`]); the
/// Reviewed attestation over each admissible self-sourced document is read
/// as a witness; if the documents fall short of the class's minimum and its
/// row admits one, the preparer's ManualAssertion over this proposal is read
/// as a witness; then [`check_minimum`] decides.
pub fn resolve_evidence<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    policy: &EvidencePolicy,
    proposal: &EntryPayload,
) -> Outcome<ResolvedEvidence> {
    let reasons = ReasonCodes::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let class_name = proposal.class.name().unwrap_or("?");
    let mut cited = match resolve_documents(txn, db, policy, &proposal.evidence)? {
        Ok(cited) => cited,
        Err(r) => return Ok(Err(r)),
    };
    let row = policy
        .minimum(class_name)
        .filter(|m| m.requirement == Requirement::Documents);
    if let Some(min) = row {
        for c in &mut cited {
            if min.kinds.admits(c.kind) && self_sourced(policy, c.grade) {
                c.review = match witness_review(txn, db, proposal.book_id, &c.oid)? {
                    Ok(review) => review,
                    Err(r) => return Ok(Err(r)),
                };
            }
        }
    }
    let mut manual_assertion = None;
    let mut verdict = check_minimum(policy, &reasons, class_name, &cited, None);
    if verdict.is_err() && row.is_some_and(|m| m.manual_assertion) {
        let digest = proposal.proposal_digest()?;
        match witness_manual_assertion(txn, db, proposal, &digest)? {
            Ok(Some(Assertion {
                attestation,
                reason_code,
            })) => {
                verdict = check_minimum(policy, &reasons, class_name, &cited, Some(reason_code));
                manual_assertion = Some(attestation);
            }
            Ok(None) => {}
            Err(r) => return Ok(Err(r)),
        }
    }
    if let Err(r) = verdict {
        return Ok(Err(r));
    }
    let mut documents: Vec<VId> = cited.iter().map(|c| c.vid).collect();
    documents.sort_unstable();
    documents.dedup();
    Ok(Ok(ResolvedEvidence {
        documents,
        manual_assertion,
    }))
}

/// The batches step 5b adds to the posting transaction: `EVIDENCED_BY`
/// `Entry → Document` for the cited documents and `ATTESTS`
/// `ManualAssertion → Entry` when the minimum rests on one.
#[must_use]
pub fn evidence_edges(entry: VId, resolved: &ResolvedEvidence) -> Vec<WriteBatch> {
    let mut batches: Vec<WriteBatch> = evidenced_by(entry, &resolved.documents)
        .into_iter()
        .collect();
    if let Some(a) = resolved.manual_assertion {
        let mut attests = WriteBatch::new(relation::ATTESTS);
        attests.add_edge(edge_id(relation::ATTESTS, a, entry), a, entry, vec![]);
        batches.push(attests);
    }
    batches
}

/// The `EVIDENCED_BY` edges `Entry → Document` for the resolved documents.
#[must_use]
pub fn evidenced_by(entry: VId, documents: &[VId]) -> Option<WriteBatch> {
    if documents.is_empty() {
        return None;
    }
    let mut batch = WriteBatch::new(relation::EVIDENCED_BY);
    for d in documents {
        batch.add_edge(
            edge_id(relation::EVIDENCED_BY, entry, *d),
            entry,
            *d,
            vec![],
        );
    }
    Some(batch)
}

/// Whether the document's grade is self-sourced (plan §9.3): it counts
/// toward a minimum only once reviewed by a principal other than its uploader.
#[must_use]
pub fn self_sourced(policy: &EvidencePolicy, grade: u8) -> bool {
    policy.grade_by_tag(grade).is_some_and(|g| g.self_sourced)
}

// ---------------------------------------------------------------------------
// Supplemental evidence (plan §9.2: evidence attached after commit is a new
// object; Appendix A `SupplementalEvidence`)
// ---------------------------------------------------------------------------

/// Domain of a supplement's `body_digest`.
pub const SUPPLEMENTAL_DOMAIN: &[u8] = b"fa:supplemental-evidence:v1";

/// Documents attached to a committed entry after its commit: an immutable,
/// content-addressed payload object. The entry's own evidence list never
/// changes; the recorded sequence of a supplement is the commit that created
/// it, so a certificate can name the closure it used (original only, or
/// original plus the supplements known at its known-at).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupplementalEvidence {
    pub book_id: Id128,
    /// The committed entry the documents support.
    pub entry_ref: EntryRef,
    /// Strictly ascending by `(document_oid, doc_commit, role)`.
    pub documents: Vec<EvidenceRef>,
    /// The principal that attached them.
    pub attached_by: VId,
}

impl SupplementalEvidence {
    fn body(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::new();
        w.u16(1).fixed(&self.book_id.0);
        self.entry_ref.encode(&mut w);
        w.list(&self.documents, |w, e| {
            w.fixed(&e.document_oid.0).fixed(&e.doc_commit).u8(e.role);
        })
        .u128(self.attached_by.0);
        w.finish().map_err(|e| KernelError::Model(e.into()))
    }

    /// `BLAKE3("fa:supplemental-evidence:v1" ‖ body)`.
    pub fn body_digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(SUPPLEMENTAL_DOMAIN, &[&self.body()?]))
    }

    /// `body ‖ body_digest`: the stored payload.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut bytes = self.body()?;
        bytes.extend_from_slice(&self.body_digest()?);
        Ok(bytes)
    }

    /// Decode and verify: the trailing digest is the body's.
    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(bytes);
        let s = (|| -> Result<(Self, [u8; 32]), DecodeError> {
            if r.u16("supplement.version")? != 1 {
                return Err(r.invalid("supplement.version"));
            }
            let book_id = Id128(r.fixed("supplement.book_id")?);
            let entry_ref = EntryRef::decode(&mut r)?;
            let documents = r.list(
                fa_model::limits::MAX_EVIDENCE_PER_ENTRY,
                "supplement.documents",
                |r| {
                    Ok(EvidenceRef {
                        document_oid: Oid(r.fixed("supplement.document_oid")?),
                        doc_commit: r.fixed("supplement.doc_commit")?,
                        role: r.u8("supplement.role")?,
                    })
                },
            )?;
            let attached_by = VId(r.u128("supplement.attached_by")?);
            let digest: [u8; 32] = r.fixed("supplement.body_digest")?;
            r.finish()?;
            Ok((
                Self {
                    book_id,
                    entry_ref,
                    documents,
                    attached_by,
                },
                digest,
            ))
        })()
        .map_err(|e| KernelError::Model(e.into()))?;
        let (supplement, digest) = s;
        if supplement.body_digest()? != digest {
            return Err(KernelError::Corrupt(
                "a supplemental evidence payload does not hash to its body_digest".into(),
            ));
        }
        Ok(supplement)
    }
}

/// `vid(SupplementalEvidence) = H("fa:vid:supplemental:v1" ‖ book ‖
/// body_digest)`: the same attachment is the same vertex.
#[must_use]
pub fn supplemental_vid(book: Id128, body_digest: &[u8; 32]) -> VId {
    let d = domain_digest(b"fa:vid:supplemental:v1", &[&book.0, body_digest]);
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d[..16]);
    VId(u128::from_le_bytes(lo))
}

/// The outcome of an attachment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceAttached {
    pub vid: VId,
    pub body_digest: [u8; 32],
    pub recorded_at: CommitSeq,
    /// The same attachment was already recorded; nothing was written.
    pub already_recorded: bool,
}

fn supplement_target(message: String) -> Refusal {
    Refusal::new(
        code::SUPPLEMENT_TARGET,
        exit::REFUSAL,
        message,
        "plan §9.2 (evidence attached after commit supports a committed entry, named by its EntryRef)",
        "name the entry by the vid and entry_digest `fa post --json` printed",
    )
}

/// `AttachEvidence` (plan Appendix B): record `supplement` — after checking
/// its structure, its coordinate, the `post` capability (before any read),
/// the target entry (a witnessed, committed `Entry` with exactly that
/// digest), and every document ([`resolve_documents`]) — as one
/// `SupplementalEvidence` vertex with `SUPPLEMENTS → Entry` and
/// `EVIDENCED_BY → Document` edges, in one transaction. The target entry
/// and its own evidence list are never modified.
pub async fn attach_evidence<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &crate::post::Capability,
    supplement: &SupplementalEvidence,
) -> Outcome<EvidenceAttached> {
    let policy = EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let docs = &supplement.documents;
    if docs.is_empty()
        || docs.len() > fa_model::limits::MAX_EVIDENCE_PER_ENTRY
        || !docs.windows(2).all(|w| w[0] < w[1])
    {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "a supplement attaches 1..=max_evidence_per_entry documents, strictly ascending by (oid, commit, role)",
            "Appendix A SupplementalEvidence.documents",
            "list each citation once, sorted",
        )));
    }
    if supplement.book_id != book.book_id {
        return Ok(Err(Refusal::new(
            code::COORDINATE,
            exit::USAGE,
            format!(
                "the supplement names book {} but this book is {}",
                supplement.book_id.to_hex(),
                book.book_id.to_hex()
            ),
            "plan §2.2 (an object belongs to exactly one book)",
            "set book_id to this book's id (fa book info --json)",
        )));
    }
    // Authorization precedes observation (doctrine 8): the admission a post
    // gets — the capability is the attacher's own, an Agent never writes
    // trunk, `post` is held — decided from the request alone.
    if let Err(d) = fa_policy::admit(
        capability,
        &fa_policy::Intent {
            principal: supplement.attached_by,
            trunk: true,
            op: fa_policy::Op::Post,
            book: book.book_id,
            legs: &[],
        },
    ) {
        return Ok(Err(crate::policy::refusal(&d)));
    }
    let body_digest = supplement.body_digest()?;
    let svid = supplemental_vid(book.book_id, &body_digest);
    let payload = supplement.canonical_bytes()?;
    // The capability is current at the admission point (plan §14.2).
    if let Err(d) = fa_policy::current(capability, db.frontier()?) {
        return Ok(Err(crate::policy::refusal(&d)));
    }

    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    // Not revoked (plan §14.2): the first read, before the identity.
    if let Err(r) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    if let Some(row) = txn.vertex(db, svid)? {
        txn.abort();
        return recorded_supplement(&row, svid, &body_digest).map(Ok);
    }
    let target = supplement.entry_ref;
    let Some(row) = txn.vertex(db, target.vid)? else {
        txn.abort();
        return Ok(Err(supplement_target(format!(
            "entry {:032x} is not in this book",
            target.vid.0
        ))));
    };
    if !row.labels.contains(&label::ENTRY) {
        txn.abort();
        return Ok(Err(supplement_target(format!(
            "vertex {:032x} is not an entry",
            target.vid.0
        ))));
    }
    let Some(CanonicalScalar::Bytes(entry_bytes)) = prop(&row, property::FA_PAYLOAD) else {
        txn.abort();
        return Err(KernelError::Corrupt(format!(
            "entry {:032x} carries no payload",
            target.vid.0
        )));
    };
    let entry = fa_model::Entry::decode(entry_bytes.as_slice())?;
    if entry.entry_digest != target.entry_digest || entry.proposal.book_id != book.book_id {
        txn.abort();
        return Ok(Err(supplement_target(format!(
            "entry {:032x} has digest {}, not the {} the supplement names",
            target.vid.0,
            hex(&entry.entry_digest),
            hex(&target.entry_digest)
        ))));
    }
    let cited = match resolve_documents(&txn, db, &policy, docs)? {
        Ok(cited) => cited,
        Err(r) => {
            txn.abort();
            return Ok(Err(r));
        }
    };
    let mut documents: Vec<VId> = cited.iter().map(|c| c.vid).collect();
    documents.sort_unstable();
    documents.dedup();

    let mut props = vec![
        (property::FA_PAYLOAD, scalar_bytes("_fa_payload", payload)?),
        (
            property::FA_DIGEST,
            scalar_bytes("_fa_digest", body_digest.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("book_id", book.book_id.0.to_vec())?,
        ),
    ];
    props.sort_by_key(|(k, _)| k.0);
    let mut supplements = WriteBatch::new(relation::SUPPLEMENTS);
    supplements.create_vertex(svid, vec![label::SUPPLEMENTAL_EVIDENCE], props);
    supplements.add_edge(
        edge_id(relation::SUPPLEMENTS, svid, target.vid),
        svid,
        target.vid,
        vec![],
    );
    let mut batches = vec![supplements];
    if let Some(edges) = evidenced_by(svid, &documents) {
        batches.push(edges);
    }
    if let Err(e) = txn.write_ordered(db, batches) {
        txn.abort();
        return Err(e.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(EvidenceAttached {
            vid: svid,
            body_digest,
            recorded_at: seq,
            already_recorded: false,
        })),
        Err(fgdb::WriteTxnError::Write(fgdb::WriteError::AlreadyLive { .. })) => {
            match db.vertex(svid)? {
                Some(row) => recorded_supplement(&row, svid, &body_digest).map(Ok),
                None => Err(KernelError::Corrupt(
                    "a supplement reported live is absent".into(),
                )),
            }
        }
        Err(fgdb::WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins {
            detail, ..
        })) => Ok(Err(Refusal::new(
            code::CONFLICT,
            exit::CONFLICT,
            format!("a concurrent commit invalidated a witness this attachment read: {detail}"),
            "FG-LAW-FCW-01 (first committer wins)",
            "retry the attachment",
        ))),
        Err(e) => Err(e.into()),
    }
}

/// A stored supplement row, verified: label, payload digest, identity.
pub fn stored_supplement(
    row: &VertexRow,
    book: Option<Id128>,
) -> Result<SupplementalEvidence, KernelError> {
    if !row.labels.contains(&label::SUPPLEMENTAL_EVIDENCE) {
        return Err(KernelError::Corrupt(format!(
            "vertex {:032x} is not a SupplementalEvidence",
            row.vid.0
        )));
    }
    let Some(CanonicalScalar::Bytes(payload)) = prop(row, property::FA_PAYLOAD) else {
        return Err(KernelError::Corrupt(format!(
            "supplement {:032x} carries no payload",
            row.vid.0
        )));
    };
    let s = SupplementalEvidence::decode(payload.as_slice())?;
    let digest = s.body_digest()?;
    if supplemental_vid(s.book_id, &digest) != row.vid || book.is_some_and(|b| b != s.book_id) {
        return Err(KernelError::Corrupt(format!(
            "supplement {:032x} is not the object its identity names",
            row.vid.0
        )));
    }
    Ok(s)
}

fn recorded_supplement(
    row: &VertexRow,
    svid: VId,
    body_digest: &[u8; 32],
) -> Result<EvidenceAttached, KernelError> {
    let s = stored_supplement(row, None)?;
    if s.body_digest()? != *body_digest {
        return Err(KernelError::Corrupt(format!(
            "supplement {:032x} holds another body",
            svid.0
        )));
    }
    Ok(EvidenceAttached {
        vid: svid,
        body_digest: *body_digest,
        recorded_at: row.created_at,
        already_recorded: true,
    })
}

/// Every supplement attached to the entry `entry`, verified, oldest first,
/// with the sequence that recorded it. A certificate selects its closure by
/// keeping those recorded at or before its known-at.
pub fn supplements_of<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    entry: VId,
) -> Result<Vec<(SupplementalEvidence, CommitSeq)>, KernelError> {
    let mut out = Vec::new();
    for svid in db.in_neighbours(entry, relation::SUPPLEMENTS)? {
        let Some(row) = db.vertex(svid)? else {
            continue;
        };
        let s = stored_supplement(&row, Some(book.book_id))?;
        if s.entry_ref.vid != entry {
            return Err(KernelError::Corrupt(format!(
                "supplement {:032x} is linked to entry {:032x} but names {:032x}",
                svid.0, entry.0, s.entry_ref.vid.0
            )));
        }
        out.push((s, row.created_at));
    }
    out.sort_by_key(|(s, seq)| (*seq, s.documents.clone()));
    Ok(out)
}

// ---------------------------------------------------------------------------
// Erasure (plan §8.5): a registered absence in this build
// ---------------------------------------------------------------------------

/// `ErasureCut`, a lawful erasure request for `subject`'s data: not available
/// in this build, so every request is refused and nothing is written. The
/// substrate's erasure tombstones are not live (Appendix H R-ERASE), so an
/// append-only store cannot crypto-erase, and a FrankenAccounting-level
/// tombstone that left the plaintext reachable would be a prohibited
/// shortcut (§8.5). Per-Party subject keys are bead fa-v74; until then every
/// erasable field is sealed under the book key. What an erasure must
/// preserve — it never changes an amount, date, account, unit, or lineage —
/// is proven on the real substrate today by fa-registers' `tests/erasure.rs`.
///
/// The order is the one the live mechanism will keep: the `erase` op is
/// admitted before any read (doctrine 8); a revoked capability is refused
/// at the head before the subject is read (FA-REF-023, plan §14.2); then a
/// legal hold active on the subject refuses it (FA-REF-117, §14.6); then an
/// active retention policy floor covering the subject refuses it (FA-REF-199,
/// §8.5); only then is the absence itself the answer (FA-REF-088).
pub fn erasure_cut<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &fa_policy::Capability,
    subject: VId,
) -> Result<Refusal, KernelError> {
    if let Err(d) = fa_policy::admit(
        capability,
        &fa_policy::Intent {
            principal: capability.holder(),
            trunk: true,
            op: fa_policy::Op::Erase,
            book: book.book_id,
            legs: &[],
        },
    ) {
        return Ok(crate::policy::refusal(&d));
    }
    if let Err(d) = fa_policy::current(capability, db.frontier()?) {
        return Ok(crate::policy::refusal(&d));
    }
    if let Err(r) = crate::policy::capability_admitted(db, book, capability)? {
        return Ok(r);
    }
    if let Some(held) = crate::legal_hold::pinned(
        db,
        book.book_id,
        subject,
        crate::legal_hold::Pinned::Erasure,
    )? {
        return Ok(held);
    }
    if let Some(floor) = crate::retention::check_erasure_retention_floor(db, book, subject)? {
        return Ok(floor);
    }
    Ok(Refusal::new(
        code::ERASURE_ABSENT,
        exit::REFUSAL,
        format!(
            "erasure of subject {:032x} is not available in this build",
            subject.0
        ),
        "plan §8.5; Appendix H R-ERASE (the substrate's erasure tombstones are not live); per-Party subject keys: bead fa-v74",
        "nothing to run: erasure is not available in this build; every erasable field is sealed under the book key and stays unopenable to anyone without it",
    ))
}

/// Metadata summary of a `Reviewed` attestation on a cited document (`fa explain evidence`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewedSummary {
    pub attestation_vid: VId,
    pub reviewer: VId,
    pub recorded_at: CommitSeq,
    pub against: Vec<Oid>,
}

/// Summary of an extraction step recorded in a derived document's envelope
/// (`fa:derived-extraction:v1`, plan §9.1–9.3, bead `fa-646`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedExtractionInfo {
    pub method: String,
    pub tool_name: String,
    pub tool_version: String,
    pub model_artifact_hash: Option<[u8; 32]>,
    pub command_line: Vec<String>,
    pub replayable: bool,
    pub extracted_text_bytes: u64,
}

/// Metadata summary of an ancestor source document in a cited document's
/// `DERIVED_FROM` lineage (`fa explain evidence`, bead `fa-646`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedFromDocumentSummary {
    pub document_oid: Oid,
    pub doc_commit: [u8; 32],
    pub kind: u8,
    pub mime: String,
    pub grade: u8,
    pub size: u64,
    pub retrieved_by: VId,
    pub recorded_at: CommitSeq,
    pub edge_recorded: bool,
    pub extraction: Option<DerivedExtractionInfo>,
    pub derived_from: Vec<Oid>,
}

/// Metadata summary of one cited document on an entry (`fa explain evidence`).
/// Never carries raw document bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentEvidenceSummary {
    pub document_oid: Oid,
    pub doc_commit: [u8; 32],
    pub role: u8,
    pub kind: u8,
    pub mime: String,
    pub grade: u8,
    pub size: u64,
    pub retrieved_by: VId,
    pub recorded_at: CommitSeq,
    pub custody_events: usize,
    pub review: Option<ReviewedSummary>,
    pub extraction: Option<DerivedExtractionInfo>,
    pub derived_from: Vec<DerivedFromDocumentSummary>,
}

fn extraction_info_from_record(rec: &DocumentRecord) -> Option<DerivedExtractionInfo> {
    let Storage::Inline(bytes) = &rec.storage else {
        return None;
    };
    let (_, meta) = crate::import::decode_extraction_derivation(bytes).ok()?;
    Some(DerivedExtractionInfo {
        method: meta.method.name().to_string(),
        tool_name: meta.tool_name,
        tool_version: meta.tool_version,
        model_artifact_hash: meta.model_artifact_hash,
        command_line: meta.command_line,
        replayable: meta.replayable,
        extracted_text_bytes: len_u64(meta.extracted_text.len()),
    })
}

fn content_bound_sources(rec: &DocumentRecord) -> Vec<Oid> {
    let Storage::Inline(bytes) = &rec.storage else {
        return Vec::new();
    };
    crate::import::decode_derivation(bytes)
        .map(|(sources, _)| sources)
        .unwrap_or_default()
}

fn walk_derived_from<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    policy: &EvidencePolicy,
    derived_edges: &std::collections::BTreeSet<(VId, VId)>,
    root_vid: VId,
    root_rec: &DocumentRecord,
) -> Result<Vec<DerivedFromDocumentSummary>, KernelError> {
    let mut visited = std::collections::BTreeSet::new();
    visited.insert(root_rec.oid());
    let mut queue = std::collections::VecDeque::new();

    let enqueue_parents =
        |cur_vid: VId,
         cur_rec: &DocumentRecord,
         q: &mut std::collections::VecDeque<(Oid, bool)>| {
            for parent_oid in content_bound_sources(cur_rec) {
                let pvid = document_vid(&parent_oid);
                q.push_back((parent_oid, derived_edges.contains(&(cur_vid, pvid))));
            }
        };

    enqueue_parents(root_vid, root_rec, &mut queue);

    let mut out = Vec::new();
    while let Some((parent_oid, edge_recorded)) = queue.pop_front() {
        if !visited.insert(parent_oid) {
            continue;
        }
        let pvid = document_vid(&parent_oid);
        let Some(prow) = db.vertex(pvid)? else {
            continue;
        };
        let prec = match verify_row(&prow, policy) {
            Ok(prec) => prec,
            Err(why) => {
                return Err(KernelError::Corrupt(format!(
                    "derived-from document {}: {why}",
                    hex(&parent_oid.0)
                )));
            }
        };
        if prec.book_id != book.book_id {
            continue;
        }
        let grand_parents = content_bound_sources(&prec);
        enqueue_parents(pvid, &prec, &mut queue);
        out.push(DerivedFromDocumentSummary {
            document_oid: parent_oid,
            doc_commit: prec.doc_commit,
            kind: prec.kind,
            mime: prec.mime.clone(),
            grade: prec.grade,
            size: prec.size,
            retrieved_by: prec.retrieved_by,
            recorded_at: prow.created_at,
            edge_recorded,
            extraction: extraction_info_from_record(&prec),
            derived_from: grand_parents,
        });
    }
    Ok(out)
}

/// Metadata summary of one `SupplementalEvidence` attached to an entry (`fa explain evidence`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupplementSummary {
    pub vid: VId,
    pub body_digest: [u8; 32],
    pub attached_by: VId,
    pub recorded_at: CommitSeq,
    pub documents: Vec<EvidenceRef>,
}

/// Metadata summary of a `ManualAssertion` over an entry's proposal (`fa explain evidence`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManualAssertionSummary {
    pub attestation_vid: VId,
    pub principal: VId,
    pub reason_code: u16,
    pub recorded_at: CommitSeq,
}

/// What a provenance-closure member is (plan §9.2, bead fa-ge0y). The
/// declaration order is the canonical order, and [`ClosureKind::tag`] is
/// part of the closure digest: both are durable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClosureKind {
    /// A document the entry cites; the role is the citation's.
    Document,
    /// The Reviewed attestation of a cited document.
    Review,
    /// A document a cited one was derived from (`DERIVED_FROM`).
    Derivation,
    /// The ManualAssertion over the entry's proposal.
    ManualAssertion,
    /// An approval in the entry's envelope.
    Approval,
    /// The REA event the entry cites.
    Event,
    /// An entry this one supersedes or resolves.
    Supersedes,
    /// The principal the entry was posted for: a reference, not a vertex.
    Principal,
    /// The session it was posted in: a reference.
    Session,
    /// What produced it: the intent, the migration run and batch, the
    /// control spec, the sweep's tick evidence, the schedule, or a rule
    /// version and its inputs.
    Origin,
    /// The dry-run plan certificate it was committed under.
    PlanCertificate,
    /// A supplement attached after the entry.
    Supplement,
    /// A document a supplement cites.
    SupplementDocument,
}

impl ClosureKind {
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::Document => 1,
            Self::Review => 2,
            Self::Derivation => 3,
            Self::ManualAssertion => 4,
            Self::Approval => 5,
            Self::Event => 6,
            Self::Supersedes => 7,
            Self::Principal => 8,
            Self::Session => 9,
            Self::Origin => 10,
            Self::PlanCertificate => 11,
            Self::Supplement => 12,
            Self::SupplementDocument => 13,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::Review => "review",
            Self::Derivation => "derivation",
            Self::ManualAssertion => "manual_assertion",
            Self::Approval => "approval",
            Self::Event => "event",
            Self::Supersedes => "supersedes",
            Self::Principal => "principal",
            Self::Session => "session",
            Self::Origin => "origin",
            Self::PlanCertificate => "plan_certificate",
            Self::Supplement => "supplement",
            Self::SupplementDocument => "supplement_document",
        }
    }

    /// Members that join the closure after posting, whatever their own
    /// sequence: a supplement and every document it cites.
    fn supplementary(self) -> bool {
        matches!(self, Self::Supplement | Self::SupplementDocument)
    }
}

/// One member of an entry's provenance closure.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ClosureMember {
    pub kind: ClosureKind,
    /// Its vertex, when it has one.
    pub vid: Option<VId>,
    /// Its content identity: a document oid, an approval's, event's or
    /// superseded entry's digest, an origin's oid or digest.
    pub digest: Option<[u8; 32]>,
    /// A citation's role.
    pub role: Option<u8>,
    /// The sequence that recorded it; none for a bare reference.
    pub recorded_at: Option<CommitSeq>,
}

/// An entry's provenance closure (plan §9.2): every member, in canonical
/// order, and two digests under `fa:closure:v1`. `original_digest` covers
/// the members the entry had as posted: recorded no later than it, and not
/// supplementary. `digest` covers every member, later reviews and
/// supplements included.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenanceClosure {
    pub members: Vec<ClosureMember>,
    pub original_digest: [u8; 32],
    pub digest: [u8; 32],
}

/// The closure digest's domain.
pub const CLOSURE_DOMAIN: &[u8] = b"fa:closure:v1";

impl ProvenanceClosure {
    /// The closure of the entry `entry_vid` (`entry_digest`, recorded at
    /// `recorded_at`) over `members`, in canonical order without
    /// duplicates.
    pub fn new(
        entry_vid: VId,
        entry_digest: [u8; 32],
        recorded_at: CommitSeq,
        mut members: Vec<ClosureMember>,
    ) -> Result<Self, KernelError> {
        members.sort();
        members.dedup();
        let digest = |list: &[&ClosureMember]| -> Result<[u8; 32], KernelError> {
            let mut w = Writer::new();
            w.u128(entry_vid.0)
                .fixed(&entry_digest)
                .u64(recorded_at.0)
                .list(list, |w, member| {
                    w.u8(member.kind.tag())
                        .opt(member.vid.as_ref(), |w, vid| {
                            w.u128(vid.0);
                        })
                        .opt(member.digest.as_ref(), |w, digest| {
                            w.fixed(digest);
                        })
                        .opt(member.role.as_ref(), |w, role| {
                            w.u8(*role);
                        })
                        .opt(member.recorded_at.as_ref(), |w, seq| {
                            w.u64(seq.0);
                        });
                });
            let bytes = w
                .finish()
                .map_err(|e| KernelError::Corrupt(format!("provenance closure: {e}")))?;
            Ok(domain_digest(CLOSURE_DOMAIN, &[&bytes]))
        };
        let all: Vec<&ClosureMember> = members.iter().collect();
        let original: Vec<&ClosureMember> = members
            .iter()
            .filter(|m| {
                !m.kind.supplementary() && m.recorded_at.is_none_or(|seq| seq <= recorded_at)
            })
            .collect();
        Ok(Self {
            original_digest: digest(&original)?,
            digest: digest(&all)?,
            members,
        })
    }
}

/// The members of `entry`'s closure beyond what `explain_entry_evidence`
/// already read: its documents, reviews, derivations, manual assertion and
/// supplements are passed in.
fn closure_of<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    entry: &fa_model::Entry,
    entry_vid: VId,
    recorded_at: CommitSeq,
    documents: &[DocumentEvidenceSummary],
    supplements: &[SupplementSummary],
    manual_assertion: Option<&ManualAssertionSummary>,
) -> Result<ProvenanceClosure, KernelError> {
    let member = |kind, vid, digest, role, recorded_at| ClosureMember {
        kind,
        vid,
        digest,
        role,
        recorded_at,
    };
    let missing = |what: &str, vid: VId| {
        KernelError::Corrupt(format!(
            "entry {:032x} cites a missing {what} {:032x}",
            entry_vid.0, vid.0
        ))
    };
    let created = |vid: VId, what: &str| -> Result<CommitSeq, KernelError> {
        Ok(db
            .vertex(vid)?
            .ok_or_else(|| missing(what, vid))?
            .created_at)
    };
    let mut members = Vec::new();
    for document in documents {
        members.push(member(
            ClosureKind::Document,
            Some(document_vid(&document.document_oid)),
            Some(document.document_oid.0),
            Some(document.role),
            Some(document.recorded_at),
        ));
        if let Some(review) = &document.review {
            members.push(member(
                ClosureKind::Review,
                Some(review.attestation_vid),
                None,
                None,
                Some(review.recorded_at),
            ));
        }
        for source in &document.derived_from {
            members.push(member(
                ClosureKind::Derivation,
                Some(document_vid(&source.document_oid)),
                Some(source.document_oid.0),
                None,
                Some(source.recorded_at),
            ));
        }
    }
    if let Some(assertion) = manual_assertion {
        members.push(member(
            ClosureKind::ManualAssertion,
            Some(assertion.attestation_vid),
            None,
            None,
            Some(assertion.recorded_at),
        ));
    }
    for approval in &entry.approvals {
        let row = db
            .vertex(approval.approval_vid)?
            .ok_or_else(|| missing("approval", approval.approval_vid))?;
        let digest: [u8; 32] =
            crate::rows::bytes(&row, property::FA_DIGEST, "approval._fa_digest")?
                .try_into()
                .map_err(|_| KernelError::Corrupt("approval._fa_digest is not 32 bytes".into()))?;
        members.push(member(
            ClosureKind::Approval,
            Some(approval.approval_vid),
            Some(digest),
            None,
            Some(row.created_at),
        ));
    }
    if let Some((event, digest)) = entry.proposal.cited_event() {
        members.push(member(
            ClosureKind::Event,
            Some(event),
            digest,
            None,
            Some(created(event, "event")?),
        ));
    }
    for supersession in &entry.proposal.supersession {
        let target = supersession.target.vid;
        let (_, seq) =
            crate::post::read_entry(db, target)?.ok_or_else(|| missing("entry", target))?;
        members.push(member(
            ClosureKind::Supersedes,
            Some(target),
            Some(supersession.target.entry_digest),
            None,
            Some(seq),
        ));
    }
    members.push(member(
        ClosureKind::Principal,
        Some(entry.proposal.principal_ref),
        None,
        None,
        None,
    ));
    if let Some(session) = entry.proposal.session_ref {
        members.push(member(
            ClosureKind::Session,
            Some(session),
            None,
            None,
            None,
        ));
    }
    match &entry.proposal.origin {
        fa_model::EntryOrigin::Intent { intent_oid, .. } => {
            members.push(member(
                ClosureKind::Origin,
                None,
                Some(intent_oid.0),
                None,
                None,
            ));
        }
        fa_model::EntryOrigin::Rule {
            rule_version_oid,
            inputs_digest,
            ..
        } => {
            // Its event is the cited event above.
            for digest in [rule_version_oid.0, *inputs_digest] {
                members.push(member(ClosureKind::Origin, None, Some(digest), None, None));
            }
        }
        fa_model::EntryOrigin::Migration {
            run_ref, batch_oid, ..
        } => {
            members.push(member(
                ClosureKind::Origin,
                Some(*run_ref),
                Some(batch_oid.0),
                None,
                Some(created(*run_ref, "migration run")?),
            ));
        }
        fa_model::EntryOrigin::Control {
            spec_body_digest, ..
        } => {
            members.push(member(
                ClosureKind::Origin,
                None,
                Some(*spec_body_digest),
                None,
                None,
            ));
        }
        fa_model::EntryOrigin::Sweep {
            tick_evidence_oid, ..
        } => {
            members.push(member(
                ClosureKind::Origin,
                None,
                Some(tick_evidence_oid.0),
                None,
                None,
            ));
        }
        fa_model::EntryOrigin::Schedule { schedule_ref, .. } => {
            members.push(member(
                ClosureKind::Origin,
                Some(*schedule_ref),
                None,
                None,
                Some(created(*schedule_ref, "schedule")?),
            ));
        }
    }
    if let Some(plan) = &entry.plan_certificate {
        members.push(member(
            ClosureKind::PlanCertificate,
            None,
            Some(plan.0),
            None,
            None,
        ));
    }
    for supplement in supplements {
        members.push(member(
            ClosureKind::Supplement,
            Some(supplement.vid),
            Some(supplement.body_digest),
            None,
            Some(supplement.recorded_at),
        ));
        for cited in &supplement.documents {
            let vid = document_vid(&cited.document_oid);
            members.push(member(
                ClosureKind::SupplementDocument,
                Some(vid),
                Some(cited.document_oid.0),
                Some(cited.role),
                Some(created(vid, "document")?),
            ));
        }
    }
    ProvenanceClosure::new(entry_vid, entry.entry_digest, recorded_at, members)
}

/// Metadata-only explanation of a committed entry's evidence closure (`fa explain evidence`,
/// bead `fa-rbo0`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceExplanation {
    pub entry_vid: VId,
    pub entry_digest: [u8; 32],
    pub proposal_digest: [u8; 32],
    pub class: String,
    pub recorded_at: CommitSeq,
    pub requirement: String,
    pub min_documents: u16,
    pub manual_assertion_allowed: bool,
    pub minimum_satisfied: bool,
    pub documents: Vec<DocumentEvidenceSummary>,
    pub supplements: Vec<SupplementSummary>,
    pub manual_assertion: Option<ManualAssertionSummary>,
    /// Every member of the entry's provenance closure, with its digests.
    pub closure: ProvenanceClosure,
}

/// Explain the evidence closure of `entry_vid` from verified metadata without
/// returning raw document bytes.
pub fn explain_entry_evidence<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    entry_vid: VId,
) -> Result<Option<EvidenceExplanation>, KernelError> {
    let Some((entry, recorded_at)) = crate::post::read_entry(db, entry_vid)? else {
        return Ok(None);
    };
    if entry.proposal.book_id != book.book_id {
        return Ok(None);
    }
    let policy = EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let reasons = ReasonCodes::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let class_name = entry.proposal.class.name().unwrap_or("?").to_string();
    let min_row = policy.minimum(&class_name);
    let (requirement, min_documents, manual_assertion_allowed) = match min_row {
        Some(m) => (
            match m.requirement {
                Requirement::Documents => "documents".to_string(),
                Requirement::ControlRecord => "control_record".to_string(),
                Requirement::Target => "target".to_string(),
            },
            m.min_documents,
            m.manual_assertion,
        ),
        None => ("unregistered".to_string(), 0, false),
    };

    let mut documents = Vec::with_capacity(entry.proposal.evidence.len());
    let mut cited = Vec::new();
    let mut seen_oids = std::collections::BTreeSet::new();
    let derived_edges: std::collections::BTreeSet<(VId, VId)> = db
        .edges_at(db.frontier()?)?
        .into_iter()
        .filter(|e| e.entry.relation == relation::DERIVED_FROM)
        .map(|e| (e.entry.src, e.entry.dst))
        .collect();

    for ev in &entry.proposal.evidence {
        let dvid = document_vid(&ev.document_oid);
        let doc_row = db.vertex(dvid)?.ok_or_else(|| {
            KernelError::Corrupt(format!(
                "entry {:032x} cites missing document {}",
                entry_vid.0,
                hex(&ev.document_oid.0)
            ))
        })?;
        let rec = match verify_row(&doc_row, &policy) {
            Ok(rec) => rec,
            Err(why) => {
                return Err(KernelError::Corrupt(format!(
                    "document {}: {why}",
                    hex(&ev.document_oid.0)
                )));
            }
        };
        let rvid = crate::attestation::review_vid(book.book_id, &ev.document_oid);
        let review = match crate::attestation::read_attestation(db, rvid)? {
            Some((stored, rev_seq)) => match stored.attestation.claim {
                crate::attestation::AttestationClaim::Reviewed { against } => {
                    Some(ReviewedSummary {
                        attestation_vid: rvid,
                        reviewer: stored.attestation.principal,
                        recorded_at: rev_seq,
                        against,
                    })
                }
                _ => None,
            },
            None => None,
        };
        let custody_events = crate::custody::custody_chain(db, &ev.document_oid)?.len();
        if seen_oids.insert(ev.document_oid) {
            cited.push(CitedDocument {
                vid: dvid,
                oid: ev.document_oid,
                kind: rec.kind,
                grade: rec.grade,
                uploader: rec.retrieved_by,
                review: review.as_ref().map(|r| Review {
                    attestation: r.attestation_vid,
                    reviewer: r.reviewer,
                }),
            });
        }
        let extraction = extraction_info_from_record(&rec);
        let derived_from = walk_derived_from(db, book, &policy, &derived_edges, dvid, &rec)?;
        documents.push(DocumentEvidenceSummary {
            document_oid: ev.document_oid,
            doc_commit: ev.doc_commit,
            role: ev.role,
            kind: rec.kind,
            mime: rec.mime,
            grade: rec.grade,
            size: rec.size,
            retrieved_by: rec.retrieved_by,
            recorded_at: doc_row.created_at,
            custody_events,
            review,
            extraction,
            derived_from,
        });
    }

    let mut supplements = Vec::new();
    for (sup, sup_seq) in supplements_of(db, book, entry_vid)? {
        let body_digest = sup.body_digest()?;
        let svid = supplemental_vid(book.book_id, &body_digest);
        supplements.push(SupplementSummary {
            vid: svid,
            body_digest,
            attached_by: sup.attached_by,
            recorded_at: sup_seq,
            documents: sup.documents,
        });
    }

    let mvid = crate::attestation::manual_assertion_vid(book.book_id, &entry.proposal_digest);
    let manual_assertion = match crate::attestation::read_attestation(db, mvid)? {
        Some((stored, ma_seq)) => match stored.attestation.claim {
            crate::attestation::AttestationClaim::ManualAssertion { reason_code, .. } => {
                Some(ManualAssertionSummary {
                    attestation_vid: mvid,
                    principal: stored.attestation.principal,
                    reason_code,
                    recorded_at: ma_seq,
                })
            }
            _ => None,
        },
        None => None,
    };

    let minimum_satisfied = check_minimum(
        &policy,
        &reasons,
        &class_name,
        &cited,
        manual_assertion.as_ref().map(|m| m.reason_code),
    )
    .is_ok();
    let closure = closure_of(
        db,
        &entry,
        entry_vid,
        recorded_at,
        &documents,
        &supplements,
        manual_assertion.as_ref(),
    )?;

    Ok(Some(EvidenceExplanation {
        entry_vid,
        entry_digest: entry.entry_digest,
        proposal_digest: entry.proposal_digest,
        class: class_name,
        recorded_at,
        requirement,
        min_documents,
        manual_assertion_allowed,
        minimum_satisfied,
        documents,
        supplements,
        manual_assertion,
        closure,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// fa-ge0y: the closure is canonical (order, duplicates), the original
    /// digest is the closure as posted, and every member field is bound.
    #[test]
    fn closure_enumerates_all_members() {
        let entry = VId(0xe);
        let digest = [7; 32];
        let at = CommitSeq(10);
        let m = |kind, vid: u128, digest: Option<u8>, role, seq: Option<u64>| ClosureMember {
            kind,
            vid: Some(VId(vid)),
            digest: digest.map(|b| [b; 32]),
            role,
            recorded_at: seq.map(CommitSeq),
        };
        let posted = vec![
            m(ClosureKind::Approval, 5, Some(5), None, Some(9)),
            m(ClosureKind::Document, 2, Some(2), Some(3), Some(4)),
            m(ClosureKind::Principal, 1, None, None, None),
            m(ClosureKind::Document, 3, Some(3), Some(1), Some(3)),
            m(ClosureKind::Document, 2, Some(2), Some(3), Some(4)),
        ];
        let closure = ProvenanceClosure::new(entry, digest, at, posted.clone()).expect("closure");
        let kinds: Vec<_> = closure.members.iter().map(|m| (m.kind, m.vid)).collect();
        assert_eq!(
            kinds,
            [
                (ClosureKind::Document, Some(VId(2))),
                (ClosureKind::Document, Some(VId(3))),
                (ClosureKind::Approval, Some(VId(5))),
                (ClosureKind::Principal, Some(VId(1))),
            ],
            "canonical order, one copy of a member"
        );
        assert_eq!(closure.original_digest, closure.digest);
        let mut reordered = posted.clone();
        reordered.reverse();
        assert_eq!(
            ProvenanceClosure::new(entry, digest, at, reordered).expect("closure"),
            closure
        );
        // A supplement, and a document it cites that was recorded before the
        // entry, join the closure but not the closure as posted; so does a
        // review recorded after the entry.
        for later in [
            m(ClosureKind::Supplement, 8, Some(8), None, Some(12)),
            m(
                ClosureKind::SupplementDocument,
                4,
                Some(4),
                Some(1),
                Some(2),
            ),
            m(ClosureKind::Review, 6, None, None, Some(11)),
        ] {
            let mut grown = posted.clone();
            grown.push(later.clone());
            let grown = ProvenanceClosure::new(entry, digest, at, grown).expect("closure");
            assert_eq!(grown.original_digest, closure.original_digest, "{later:?}");
            assert_ne!(grown.digest, closure.digest, "{later:?}");
            assert_eq!(grown.members.len(), 5);
        }
        // Every field of a member, and the entry itself, is bound.
        let changed = [
            m(ClosureKind::Review, 2, Some(2), Some(3), Some(4)),
            m(ClosureKind::Document, 9, Some(2), Some(3), Some(4)),
            m(ClosureKind::Document, 2, Some(9), Some(3), Some(4)),
            m(ClosureKind::Document, 2, None, Some(3), Some(4)),
            m(ClosureKind::Document, 2, Some(2), Some(1), Some(4)),
            m(ClosureKind::Document, 2, Some(2), Some(3), Some(5)),
        ];
        for other in changed {
            let mut members = posted.clone();
            members[1] = other.clone();
            members[4] = other.clone();
            let moved = ProvenanceClosure::new(entry, digest, at, members).expect("closure");
            assert_ne!(moved.original_digest, closure.original_digest, "{other:?}");
        }
        for (vid, entry_digest, seq) in [
            (VId(0xf), digest, at),
            (entry, [8; 32], at),
            (entry, digest, CommitSeq(11)),
        ] {
            let moved =
                ProvenanceClosure::new(vid, entry_digest, seq, posted.clone()).expect("closure");
            assert_ne!(moved.digest, closure.digest);
        }
        let tags: std::collections::BTreeSet<u8> = [
            ClosureKind::Document,
            ClosureKind::Review,
            ClosureKind::Derivation,
            ClosureKind::ManualAssertion,
            ClosureKind::Approval,
            ClosureKind::Event,
            ClosureKind::Supersedes,
            ClosureKind::Principal,
            ClosureKind::Session,
            ClosureKind::Origin,
            ClosureKind::PlanCertificate,
            ClosureKind::Supplement,
            ClosureKind::SupplementDocument,
        ]
        .into_iter()
        .map(ClosureKind::tag)
        .collect();
        assert_eq!(tags.len(), 13, "every kind has its own tag");
    }

    #[test]
    fn commitment_binds_kind_length_and_every_chunk() {
        let a = vec![7u8; CHUNK_BYTES * 3 + 5];
        let base = doc_commit(1, &a);
        assert_eq!(base, doc_commit(1, &a), "deterministic");
        assert_ne!(base, doc_commit(2, &a), "kind is bound");
        for i in [0, CHUNK_BYTES, CHUNK_BYTES * 3 + 4] {
            let mut b = a.clone();
            b[i] ^= 1;
            assert_ne!(base, doc_commit(1, &b), "byte {i} is bound");
        }
        let mut longer = a.clone();
        longer.push(7);
        assert_ne!(base, doc_commit(1, &longer), "length is bound");
        assert_ne!(chunk_root(&[]), chunk_root(&[0]));
    }

    #[test]
    fn chunk_root_matches_a_literal_tree() {
        // Five chunks: ((l0 l1) (l2 l3)) l4 — the unpaired leaf is promoted.
        let data: Vec<u8> = (0..CHUNK_BYTES * 4 + 10).map(|i| (i % 251) as u8).collect();
        let l: Vec<[u8; 32]> = data
            .chunks(CHUNK_BYTES)
            .enumerate()
            .map(|(i, c)| leaf(i, c))
            .collect();
        let expected = node(&node(&node(&l[0], &l[1]), &node(&l[2], &l[3])), &l[4]);
        assert_eq!(chunk_root(&data), expected);
    }

    #[test]
    fn document_round_trips_and_detects_tampering() {
        let doc = Document {
            book_id: Id128([3; 16]),
            kind: 1,
            mime: "application/pdf".into(),
            grade: 4,
            retrieved_by: VId(9),
            bytes: b"INVOICE 42: rent, March, 1500.00 USD".to_vec(),
        };
        let bytes = doc.canonical_bytes().unwrap();
        assert_eq!(Document::decode(&bytes).unwrap(), doc);
        // Flip one content byte: the stored commitment no longer matches.
        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x20;
        assert!(matches!(
            Document::decode(&tampered),
            Err(KernelError::Corrupt(_))
        ));
        assert!(Document::decode(&bytes[..bytes.len() - 1]).is_err());
        assert_ne!(doc.oid(), document_oid(Id128([4; 16]), &doc.doc_commit()));
    }

    #[test]
    fn a_supplement_round_trips_and_its_digest_binds_every_field() {
        let s = SupplementalEvidence {
            book_id: Id128([5; 16]),
            entry_ref: EntryRef {
                vid: VId(77),
                entry_digest: [9; 32],
            },
            documents: vec![EvidenceRef {
                document_oid: Oid([1; 32]),
                doc_commit: [2; 32],
                role: 2,
            }],
            attached_by: VId(3),
        };
        let bytes = s.canonical_bytes().unwrap();
        assert_eq!(SupplementalEvidence::decode(&bytes).unwrap(), s);
        // Any byte of the body changed: the trailing digest no longer binds it.
        for i in 0..bytes.len() - 32 {
            let mut t = bytes.clone();
            t[i] ^= 0x01;
            assert!(SupplementalEvidence::decode(&t).is_err(), "byte {i}");
        }
        let mut other = s.clone();
        other.attached_by = VId(4);
        assert_ne!(
            supplemental_vid(s.book_id, &s.body_digest().unwrap()),
            supplemental_vid(other.book_id, &other.body_digest().unwrap())
        );
    }

    #[test]
    fn minimum_counts_admissible_kinds_and_names_the_row() {
        let p = EvidencePolicy::embedded().unwrap();
        let reasons = ReasonCodes::embedded().unwrap();
        let check_minimum = |p: &EvidencePolicy, class: &str, cited: &[CitedDocument]| {
            super::check_minimum(p, &reasons, class, cited, None)
        };
        let human = p.grade_by_name("HumanUpload").unwrap().tag;
        let agent = p.grade_by_name("AgentUpload").unwrap().tag;
        let doc = |kind: &str, grade: u8| CitedDocument {
            vid: VId(1),
            oid: Oid([1; 32]),
            kind: p.kind_by_name(kind).unwrap().tag,
            grade,
            uploader: VId(7),
            review: None,
        };
        let invoice = doc("Invoice", human);
        let rate = doc("Rate", human);
        assert!(check_minimum(&p, "Original", &[invoice]).is_ok());
        let none = check_minimum(&p, "Original", &[]).unwrap_err();
        assert_eq!(none.code, code::EVIDENCE_MINIMUM);
        assert_eq!(none.exit, exit::REFUSAL);
        assert!(none.cite.contains("class = \"Original\""), "{}", none.cite);
        assert!(none.fix.contains("fa document add"), "{}", none.fix);
        // Revaluation admits only rate documents.
        let wrong = check_minimum(&p, "Revaluation", &[invoice]).unwrap_err();
        assert!(wrong.message.contains("0 admissible"), "{}", wrong.message);
        assert!(check_minimum(&p, "Revaluation", &[invoice, rate]).is_ok());
        // Target-derived classes need no document of their own.
        assert!(check_minimum(&p, "Reversal", &[]).is_ok());
        assert!(check_minimum(&p, "Resolution", &[]).is_ok());
        assert!(check_minimum(&p, "Pending", &[]).is_err());
        assert!(check_minimum(&p, "NoSuchClass", &[invoice]).is_err());
        // An unreviewed self-sourced document does not count; a person's does.
        let agents = check_minimum(&p, "Original", &[doc("Invoice", agent)]).unwrap_err();
        assert_eq!(
            (agents.code, agents.exit),
            (code::SELF_SOURCED, exit::REFUSAL)
        );
        assert!(agents.cite.contains("Reviewed"), "{}", agents.cite);
        assert!(agents.fix.contains("record_review"), "{}", agents.fix);
        assert!(check_minimum(&p, "Original", &[doc("Invoice", agent), invoice]).is_ok());
        // Self-sourced but inadmissible is the plain minimum refusal.
        let wrong_kind =
            check_minimum(&p, "Revaluation", &[doc("Rate", agent), invoice]).unwrap_err();
        assert_eq!(wrong_kind.code, code::SELF_SOURCED);
        assert_eq!(
            check_minimum(&p, "Revaluation", &[doc("Invoice", agent)])
                .unwrap_err()
                .code,
            code::EVIDENCE_MINIMUM
        );
        // Target classes rest on their target, whatever they cite.
        assert!(check_minimum(&p, "Reversal", &[doc("Memo", agent)]).is_ok());
    }

    #[test]
    fn reviews_and_manual_assertions_meet_the_minimum_only_as_registered() {
        let p = EvidencePolicy::embedded().unwrap();
        let reasons = ReasonCodes::embedded().unwrap();
        let agent = p.grade_by_name("AgentUpload").unwrap().tag;
        let invoice = p.kind_by_name("Invoice").unwrap().tag;
        let reviewed_by = |reviewer: u128| CitedDocument {
            vid: VId(1),
            oid: Oid([1; 32]),
            kind: invoice,
            grade: agent,
            uploader: VId(7),
            review: Some(Review {
                attestation: VId(99),
                reviewer: VId(reviewer),
            }),
        };
        // Reviewed by another principal: it counts.
        assert!(check_minimum(&p, &reasons, "Original", &[reviewed_by(8)], None).is_ok());
        // Reviewed by its uploader: refused, SoD (exit 7), naming the document.
        let own = check_minimum(&p, &reasons, "Original", &[reviewed_by(7)], None).unwrap_err();
        assert_eq!((own.code, own.exit), (code::SELF_REVIEW, exit::SAFETY));
        assert!(own.message.contains(&hex(&[1; 32])), "{}", own.message);
        // A manual assertion stands in for a document where the row admits it.
        for class in ["Original", "Reclassification", "Adjusting"] {
            assert!(
                check_minimum(&p, &reasons, class, &[], Some(1)).is_ok(),
                "{class}"
            );
            let r = check_minimum(&p, &reasons, class, &[], Some(999)).unwrap_err();
            assert_eq!(
                (r.code, r.exit),
                (code::REASON_CODE, exit::USAGE),
                "{class}"
            );
            assert!(r.fix.contains("1 NoDocumentIssued"), "{}", r.fix);
        }
        // Nowhere else: the row decides, and the fix says so.
        let pending = check_minimum(&p, &reasons, "Pending", &[], Some(1)).unwrap_err();
        assert_eq!(pending.code, code::EVIDENCE_MINIMUM);
        assert!(
            pending.fix.contains("admits no ManualAssertion"),
            "{}",
            pending.fix
        );
        let original = check_minimum(&p, &reasons, "Original", &[], None).unwrap_err();
        assert!(
            original.fix.contains("record_manual_assertion"),
            "{}",
            original.fix
        );
        assert!(check_minimum(&p, &reasons, "Revaluation", &[], Some(1)).is_err());
        // An assertion beside unreviewed agent uploads still meets it.
        let unreviewed = CitedDocument {
            review: None,
            ..reviewed_by(8)
        };
        assert!(check_minimum(&p, &reasons, "Original", &[unreviewed], Some(4)).is_ok());
        assert_eq!(
            check_minimum(&p, &reasons, "Original", &[unreviewed], None)
                .unwrap_err()
                .code,
            code::SELF_SOURCED
        );
    }
}
