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
//!   payload, bounded by `max_document_bytes`; `External` storage, parsed
//!   projections, redaction contracts and the `ImportReceipt` chain are later
//!   slices;
//! - `document_oid = H("fa:oid:document:v1" ‖ book_id ‖ doc_commit)` is a
//!   book-scoped locator, because the substrate's keyed `ObjectId` (`K_oid`)
//!   is not exposed through the embedded handle;
//! - the provenance grade is recorded at intake from the uploader's declared
//!   posture (`HumanUpload` | `AgentUpload`); grades derived from a receipt
//!   chain are refused. `self_sourced` is reported, not enforced: the
//!   Agent-profile draft gate and the reviewer's `Reviewed` attestation need
//!   drafts and Attestation objects, which do not exist yet;
//! - the plan's `ManualAssertion` attestation in place of a document needs
//!   Attestation objects too, so it is not admitted: such an entry is refused,
//!   never exempted.

use fa_model::symbols::{label, property, relation};
use fa_model::{
    DecodeError, EntryPayload, EntryRef, EvidenceRef, Id128, Oid, Reader, Writer, domain_digest,
};
use fa_registry::evidence_policy::{EvidencePolicy, Requirement};
use fgdb::{Database, VertexRow, WriteBatch, WriteTxn};
use fgdb_crypto::Hasher;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{edge_id, prop, scalar_bytes, scalar_text};

/// The fixed chunk size of the commitment's Merkle tree (plan §9.1).
pub const CHUNK_BYTES: usize = 4096;

/// The decoder's bound on inline bytes: the substrate's scalar ceiling, so a
/// later, larger registry bound never makes a stored document unreadable.
const MAX_DECODED_DOCUMENT_BYTES: usize = 64 * 1024 * 1024;
const MAX_DECODED_MIME_BYTES: usize = 1024;

/// Storage tags of `fa:document:v1`.
const STORAGE_INLINE: u8 = 0;

fn finalize(h: Hasher) -> [u8; 32] {
    h.finalize().0
}

/// The Merkle root over fixed 4 KiB chunks: leaf `i` is
/// `H("fa:doc:leaf:v1" ‖ u64 i ‖ u64 len ‖ chunk)`, an interior node is
/// `H("fa:doc:node:v1" ‖ left ‖ right)`, and an unpaired node is promoted
/// unchanged. Empty input is one empty leaf, so the function is total.
#[must_use]
pub fn chunk_root(bytes: &[u8]) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = if bytes.is_empty() {
        vec![leaf(0, &[])]
    } else {
        bytes
            .chunks(CHUNK_BYTES)
            .enumerate()
            .map(|(i, c)| leaf(i, c))
            .collect()
    };
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
    level[0]
}

fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"fa:doc:node:v1");
    h.update(left);
    h.update(right);
    finalize(h)
}

fn leaf(index: usize, chunk: &[u8]) -> [u8; 32] {
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
    let mut h = Hasher::new();
    h.update(b"fa:doc:v1");
    h.update(&[kind]);
    h.update(&len_u64(bytes.len()).to_le_bytes());
    h.update(&chunk_root(bytes));
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

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::with_capacity(self.bytes.len() + 128);
        w.u16(1)
            .fixed(&self.book_id.0)
            .u8(self.kind)
            .str(&self.mime)
            .u64(len_u64(self.bytes.len()))
            .fixed(&self.doc_commit())
            .u8(self.grade)
            .u128(self.retrieved_by.0)
            .u8(STORAGE_INLINE)
            .bytes(&self.bytes);
        w.finish().map_err(|e| KernelError::Model(e.into()))
    }

    /// Decode and verify: the stored size and commitment must be the ones
    /// the bytes produce, or the row is corrupt.
    pub fn decode(payload: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(payload);
        let (doc, size, commit) = (|| -> Result<(Self, u64, [u8; 32]), DecodeError> {
            if r.u16("document.version")? != 1 {
                return Err(r.invalid("document.version"));
            }
            let book_id = Id128(r.fixed("document.book_id")?);
            let kind = r.u8("document.kind")?;
            let mime = r.str(MAX_DECODED_MIME_BYTES, "document.mime")?.to_string();
            let size = r.u64("document.size")?;
            let commit: [u8; 32] = r.fixed("document.doc_commit")?;
            let grade = r.u8("document.grade")?;
            let retrieved_by = VId(r.u128("document.retrieved_by")?);
            let storage = r.u8("document.storage")?;
            if storage != STORAGE_INLINE {
                return Err(r.bad_tag("document.storage", storage));
            }
            let bytes = r
                .bytes(MAX_DECODED_DOCUMENT_BYTES, "document.bytes")?
                .to_vec();
            r.finish()?;
            Ok((
                Self {
                    book_id,
                    kind,
                    mime,
                    grade,
                    retrieved_by,
                    bytes,
                },
                size,
                commit,
            ))
        })()
        .map_err(|e| KernelError::Model(e.into()))?;
        if size != len_u64(doc.bytes.len()) || commit != doc.doc_commit() {
            return Err(KernelError::Corrupt(format!(
                "document {}: stored size/commitment do not match its bytes",
                hex(&commit)
            )));
        }
        Ok(doc)
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
fn verify_row(row: &VertexRow, policy: &EvidencePolicy) -> Result<Document, String> {
    if !row.labels.contains(&label::DOCUMENT) {
        return Err("the vertex is not labeled Document".into());
    }
    let Some(CanonicalScalar::Bytes(payload)) = prop(row, property::FA_PAYLOAD) else {
        return Err("the vertex carries no document payload".into());
    };
    let doc = Document::decode(payload.as_slice())
        .map_err(|e| format!("the payload does not verify: {e}"))?;
    if document_vid(&doc.oid()) != row.vid {
        return Err("the payload is not the document this vertex's identity names".into());
    }
    let commit = doc.doc_commit();
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

/// The refusal for a Document whose stored row does not verify (exit 8).
fn drift(oid: &Oid, why: &str) -> Refusal {
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
        doc_commit: doc.doc_commit(),
        vid: row.vid,
        kind: doc.kind,
        grade: doc.grade,
        size: len_u64(doc.bytes.len()),
        recorded_at: row.created_at,
        already_recorded,
    }))
}

/// Record a document in the book: one `Document` vertex carrying the
/// canonical payload and its mirrors (`_fa_digest` = `doc_commit`, `code` =
/// the kind's registered name, `book_id`), in one commit. The same bytes of
/// the same kind are the recorded outcome, never a second vertex.
pub async fn add_document<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    doc: &Document,
) -> Outcome<DocumentAdded> {
    let policy = EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    if doc.book_id != book.book_id {
        return Ok(Err(Refusal::new(
            code::COORDINATE,
            exit::USAGE,
            format!(
                "the document names book {} but this book is {}",
                doc.book_id.to_hex(),
                book.book_id.to_hex()
            ),
            "plan §2.2 (an object belongs to exactly one book)",
            "set book_id to this book's id (fa book info --json)",
        )));
    }
    if doc.bytes.is_empty() {
        return Ok(Err(intake_refusal(
            "the document is empty; zero bytes are not evidence",
            "add the file that records the transaction",
        )));
    }
    if len_u64(doc.bytes.len()) > policy.max_document_bytes {
        return Ok(Err(intake_refusal(
            format!(
                "the document is {} bytes; inline documents are bounded at {}",
                doc.bytes.len(),
                policy.max_document_bytes
            ),
            "split the document, or wait for External storage (plan §9.1)",
        )));
    }
    let mime_ok = !doc.mime.is_empty()
        && doc.mime.len() <= policy.max_mime_bytes
        && doc.mime.bytes().all(|b| b.is_ascii_graphic());
    if !mime_ok {
        return Ok(Err(intake_refusal(
            format!(
                "mime `{}` must be 1..={} printable ASCII bytes with no spaces",
                doc.mime, policy.max_mime_bytes
            ),
            "pass --mime type/subtype, e.g. application/pdf",
        )));
    }
    let Some(kind) = policy.kind_by_tag(doc.kind) else {
        return Ok(Err(intake_refusal(
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
        )));
    };
    let Some(grade) = policy.grade_by_tag(doc.grade) else {
        return Ok(Err(intake_refusal(
            format!("provenance grade {} is not registered", doc.grade),
            "declare HumanUpload or AgentUpload",
        )));
    };
    if !grade.intake {
        return Ok(Err(Refusal::new(
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
        )));
    }

    let commit = doc.doc_commit();
    let oid = document_oid(book.book_id, &commit);
    let vid = document_vid(&oid);
    if let Some(row) = db.vertex(vid)? {
        return added_from_row(&row, &policy, &oid, true);
    }
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("_fa_payload", doc.canonical_bytes()?)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("_fa_digest", commit.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("book_id", book.book_id.0.to_vec())?,
        ),
        (property::CODE, scalar_text("code", &kind.name)?),
    ];
    props.sort_by_key(|(k, _)| k.0);
    let mut batch = WriteBatch::new(relation::EVIDENCED_BY);
    batch.create_vertex(vid, vec![label::DOCUMENT], props);
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
}

/// The document at `oid`, decoded and verified against its commitment, or
/// `None` when the book does not hold it.
pub fn read_document<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    oid: &Oid,
) -> Result<Option<Document>, KernelError> {
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

/// The class's evidence minimum over the distinct cited documents (pure; the
/// posting transaction supplies them, verified). A self-sourced document
/// (`AgentUpload`, `Generated`: plan §9.3) does not count toward the minimum:
/// the plan admits it only once a reviewer attests it (`Reviewed`, bead
/// fa-g21), and that attestation does not exist yet, so an entry that meets
/// its minimum only by counting self-sourced documents is refused with
/// FA-REF-086 — stricter than the plan, never an exemption.
pub fn check_minimum(
    policy: &EvidencePolicy,
    class_name: &str,
    cited: &[CitedDocument],
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
    let counted = admissible
        .iter()
        .filter(|c| !self_sourced(policy, c.grade))
        .count();
    if counted >= needed {
        return Ok(());
    }
    if admissible.len() >= needed {
        return Err(Refusal::new(
            code::SELF_SOURCED,
            exit::REFUSAL,
            format!(
                "`{class_name}` requires at least {needed} document(s); the entry's admissible documents are self-sourced ({} of {}), and a self-sourced document counts only once a reviewer attests it",
                admissible.len() - counted,
                admissible.len()
            ),
            "plan §9.3 (self-sourced evidence: AgentUpload, Generated); bead fa-g21 (the Reviewed attestation, not yet implemented)",
            "cite a document a person or third party supplied, recorded with `fa document add <file> --grade HumanUpload --json` by the person who supplied it; never re-declare an agent's upload as a person's",
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
    Err(Refusal::new(
        code::EVIDENCE_MINIMUM,
        exit::REFUSAL,
        message,
        format!(
            "registries/evidence_policy.toml [[minimum]] class = \"{class_name}\" (FA-INV-05 evidence-minimum)"
        ),
        "record the source document with `fa document add <file> --kind <Kind> --json` and cite the printed `evidence` object in the intent's `evidence`; a ManualAssertion attestation in place of a document is not admitted until the attestation slice lands — never fabricate a document",
    ))
}

/// One distinct cited document, as its verified payload states it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CitedDocument {
    pub vid: VId,
    pub kind: u8,
    pub grade: u8,
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
                        doc.doc_commit(),
                        Some(CitedDocument {
                            vid: dvid,
                            kind: doc.kind,
                            grade: doc.grade,
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
        last = Some((e.document_oid, stored));
        cited.push(doc);
    }
    Ok(Ok(cited))
}

/// Step 5b of `post`: every citation resolves ([`resolve_documents`]) and
/// the distinct documents meet the class's minimum. Returns the distinct
/// documents' vertices, ascending, for `EVIDENCED_BY`.
pub fn resolve_evidence<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    policy: &EvidencePolicy,
    proposal: &EntryPayload,
) -> Outcome<Vec<VId>> {
    let class_name = proposal.class.name().unwrap_or("?");
    let cited = match resolve_documents(txn, db, policy, &proposal.evidence)? {
        Ok(cited) => cited,
        Err(r) => return Ok(Err(r)),
    };
    if let Err(r) = check_minimum(policy, class_name, &cited) {
        return Ok(Err(r));
    }
    let mut documents: Vec<VId> = cited.iter().map(|c| c.vid).collect();
    documents.sort_unstable();
    documents.dedup();
    Ok(Ok(documents))
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

/// Whether the document's grade is self-sourced (plan §9.3); reported at
/// intake and on reads, not yet enforced (no drafts or attestations).
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
fn stored_supplement(
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
/// in this build, and refused before any read or write. The substrate's
/// erasure tombstones are not live (Appendix H R-ERASE), so an append-only
/// store cannot crypto-erase, and a FrankenAccounting-level tombstone that
/// left the plaintext reachable would be a prohibited shortcut (§8.5).
/// Per-Party subject keys are bead fa-v74; until then every erasable field is
/// sealed under the book key. What an erasure must preserve — it never
/// changes an amount, date, account, unit, or lineage — is proven on the real
/// substrate today by fa-registers' `tests/erasure.rs`.
#[must_use]
pub fn erasure_cut(subject: VId) -> Refusal {
    Refusal::new(
        code::ERASURE_ABSENT,
        exit::REFUSAL,
        format!(
            "erasure of subject {:032x} is not available in this build",
            subject.0
        ),
        "plan §8.5; Appendix H R-ERASE (the substrate's erasure tombstones are not live); per-Party subject keys: bead fa-v74",
        "nothing to run: erasure is not available in this build; every erasable field is sealed under the book key and stays unopenable to anyone without it",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let human = p.grade_by_name("HumanUpload").unwrap().tag;
        let agent = p.grade_by_name("AgentUpload").unwrap().tag;
        let doc = |kind: &str, grade: u8| CitedDocument {
            vid: VId(1),
            kind: p.kind_by_name(kind).unwrap().tag,
            grade,
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
        // A self-sourced document does not count (fa-g21); a person's does.
        let agents = check_minimum(&p, "Original", &[doc("Invoice", agent)]).unwrap_err();
        assert_eq!(
            (agents.code, agents.exit),
            (code::SELF_SOURCED, exit::REFUSAL)
        );
        assert!(agents.cite.contains("fa-g21"), "{}", agents.cite);
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
}
