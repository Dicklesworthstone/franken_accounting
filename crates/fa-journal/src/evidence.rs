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
use fa_model::{DecodeError, EntryPayload, EvidenceRef, Id128, Oid, Reader, Writer, domain_digest};
use fa_registry::evidence_policy::{EvidencePolicy, Requirement};
use fgdb::{Database, VertexRow, WriteBatch, WriteTxn};
use fgdb_crypto::Hasher;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{bytes, edge_id, scalar_bytes, scalar_text};

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

fn added_from_row(row: &VertexRow, already_recorded: bool) -> Result<DocumentAdded, KernelError> {
    let doc = Document::decode(&bytes(row, property::FA_PAYLOAD, "document._fa_payload")?)?;
    Ok(DocumentAdded {
        oid: doc.oid(),
        doc_commit: doc.doc_commit(),
        vid: row.vid,
        kind: doc.kind,
        grade: doc.grade,
        size: len_u64(doc.bytes.len()),
        recorded_at: row.created_at,
        already_recorded,
    })
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
        return added_from_row(&row, true).map(Ok);
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
            Some(row) => added_from_row(&row, true).map(Ok),
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
    let doc = Document::decode(&bytes(&row, property::FA_PAYLOAD, "document._fa_payload")?)?;
    let mirror = bytes(&row, property::FA_DIGEST, "document._fa_digest")?;
    if mirror.as_slice() != doc.doc_commit().as_slice() || doc.oid() != *oid {
        return Err(KernelError::Corrupt(format!(
            "document {}: mirrors disagree with the payload",
            hex(&oid.0)
        )));
    }
    Ok(Some(doc))
}

/// The class's evidence minimum over the distinct cited documents' kinds
/// (pure; the posting transaction supplies the witnessed kinds).
pub fn check_minimum(
    policy: &EvidencePolicy,
    class_name: &str,
    cited_kinds: &[u8],
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
    let admissible = cited_kinds.iter().filter(|k| min.kinds.admits(**k)).count();
    if admissible >= usize::from(min.min_documents) {
        return Ok(());
    }
    let kinds = policy.kind_names(&min.kinds).join(", ");
    let message = if cited_kinds.is_empty() {
        format!(
            "`{class_name}` requires at least {} document(s) ({kinds}); the entry cites none",
            min.min_documents
        )
    } else {
        format!(
            "`{class_name}` requires at least {} document(s) of kind {kinds}; the entry cites {} document(s), {admissible} admissible",
            min.min_documents,
            cited_kinds.len()
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

/// Step 5b of `post`: every citation names a registered role and a document
/// this book holds under exactly the cited commitment — each read as a point
/// witness of `txn` — and the distinct documents meet the class's minimum.
/// Returns the distinct documents' vertices, ascending, for `EVIDENCED_BY`.
pub fn resolve_evidence<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    policy: &EvidencePolicy,
    proposal: &EntryPayload,
) -> Outcome<Vec<VId>> {
    let class_name = proposal.class.name().unwrap_or("?");
    for (i, e) in proposal.evidence.iter().enumerate() {
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
    let mut documents: Vec<VId> = Vec::new();
    let mut kinds: Vec<u8> = Vec::new();
    // `evidence` is strictly ascending by (oid, commit, role): citations of
    // one document are adjacent. The document is read once and counts once;
    // every citation's commitment is still checked against it.
    let mut last: Option<(Oid, Vec<u8>)> = None;
    for (i, e) in proposal.evidence.iter().enumerate() {
        let cached = match &last {
            Some((oid, commit)) if *oid == e.document_oid => Some(commit.clone()),
            _ => None,
        };
        let repeat = cached.is_some();
        let dvid = document_vid(&e.document_oid);
        let stored = match cached {
            Some(commit) => commit,
            None => match txn.vertex_property(db, dvid, property::FA_DIGEST)? {
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
                Some(CanonicalScalar::Bytes(b)) => b.as_slice().to_vec(),
                Some(other) => {
                    return Err(KernelError::Corrupt(format!(
                        "document {} commitment mirror: {other:?}",
                        hex(&e.document_oid.0)
                    )));
                }
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
        if repeat {
            continue;
        }
        last = Some((e.document_oid, stored));
        let kind = match txn.vertex_property(db, dvid, property::CODE)? {
            Some(CanonicalScalar::Text(t)) => core::str::from_utf8(t.as_bytes())
                .ok()
                .and_then(|name| policy.kind_by_name(name))
                .map(|k| k.tag),
            _ => None,
        }
        .ok_or_else(|| {
            KernelError::Corrupt(format!(
                "document {} kind mirror is missing or unregistered",
                hex(&e.document_oid.0)
            ))
        })?;
        documents.push(dvid);
        kinds.push(kind);
    }
    if let Err(r) = check_minimum(policy, class_name, &kinds) {
        return Ok(Err(r));
    }
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
    fn minimum_counts_admissible_kinds_and_names_the_row() {
        let p = EvidencePolicy::embedded().unwrap();
        let invoice = p.kind_by_name("Invoice").unwrap().tag;
        let rate = p.kind_by_name("Rate").unwrap().tag;
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
    }
}
