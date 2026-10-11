//! Redacted views of documents (plan §9.6; fa-txf part C2).
//!
//! A view discloses some of a document's 4 KiB chunks and withholds the
//! others as their leaf hashes. Anyone holding the view alone recomputes the
//! original's public commitment — kind, size and the chunk tree's root — so
//! a view proves it is a projection of exactly the document an entry cites,
//! without the privileged bytes. A chunk that any privileged range touches
//! is withheld whole: the commitment hashes whole chunks, so a partly
//! disclosed chunk could not be proven.
//!
//! The view's own identity is its commitment,
//! `view_commit = H("fa:redacted-view:v1" ‖ canonical bytes)`; its lineage
//! to the original is the `original` oid and `doc_commit` it carries.
//!
//! No-claim boundary: a view proves which bytes it discloses belong to the
//! committed document at their offsets, and nothing about what the withheld
//! chunks say. Amounts, dates, accounts and lineage are never in a
//! document's bytes' redaction scope: a view changes no entry.

use std::sync::OnceLock;

use fa_model::symbols::{label, property, relation};
use fa_model::{DecodeError, Id128, Oid, Reader, Writer, domain_digest};
use fa_policy::{Capability, Intent, Op};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_registry::redaction_contracts::{Contract, RedactionContracts};
use fgdb::{Database, VertexRow, WriteBatch, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::blob::BlobStore;
use crate::evidence::{
    CHUNK_BYTES, Document, commitment, document_oid, document_vid, fetch_document, hex, leaf,
    tree_root,
};
use crate::genesis::BookContext;
use crate::policy::{capability_admitted, capability_witness, refusal};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{edge_id, prop, scalar_bytes};

/// Domain of `view_commit`.
pub const VIEW_DOMAIN: &[u8] = b"fa:redacted-view:v1";
const VIEW_VERSION: u16 = 1;
const DISCLOSED: u8 = 0;
const WITHHELD: u8 = 1;
/// The decoder's bound on a view's chunk count: the document decoder's
/// 64 MiB ceiling in 4 KiB chunks.
const MAX_VIEW_CHUNKS: usize = 64 * 1024 * 1024 / CHUNK_BYTES;

/// One chunk of a view, in the original's chunk order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViewChunk {
    /// The chunk's bytes, disclosed.
    Disclosed(Vec<u8>),
    /// The chunk's leaf hash: the bytes are withheld.
    Withheld([u8; 32]),
}

/// A redacted view of one document under one redaction contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactedView {
    /// The document the view projects.
    pub original: Oid,
    /// The redaction contract that chose what to withhold.
    pub contract: u16,
    /// The original's kind and size, both inside its commitment.
    pub kind: u8,
    pub size: u64,
    /// The original's public commitment, which the view reproduces.
    pub doc_commit: [u8; 32],
    pub chunks: Vec<ViewChunk>,
}

/// The number of chunks a document of `size` bytes commits to (an empty
/// document is one empty chunk).
fn chunk_count(size: u64) -> u64 {
    let chunk = CHUNK_BYTES as u64;
    size.div_ceil(chunk).max(1)
}

/// Whether any of the `privileged` byte ranges `(offset, length)` touches
/// chunk `index`: such a chunk is withheld whole.
fn privileged_chunk(index: u64, privileged: &[(u64, u64)]) -> bool {
    let chunk = CHUNK_BYTES as u64;
    let start = index.saturating_mul(chunk);
    let end = start.saturating_add(chunk);
    privileged.iter().any(|(offset, length)| {
        *length > 0 && *offset < end && offset.saturating_add(*length) > start
    })
}

/// The length of chunk `index` of a `size`-byte document.
fn chunk_len(size: u64, index: u64) -> u64 {
    let chunk = CHUNK_BYTES as u64;
    size.saturating_sub(index.saturating_mul(chunk)).min(chunk)
}

impl RedactedView {
    /// The view of `doc` under `contract` that withholds every chunk any of
    /// the `privileged` byte ranges `(offset, length)` touches. A range past
    /// the end touches nothing beyond it; a zero-length range touches
    /// nothing.
    #[must_use]
    pub fn derive(doc: &Document, contract: u16, privileged: &[(u64, u64)]) -> Self {
        let touched = |index: u64| privileged_chunk(index, privileged);
        let chunks = if doc.bytes.is_empty() {
            vec![if touched(0) {
                ViewChunk::Withheld(leaf(0, &[]))
            } else {
                ViewChunk::Disclosed(Vec::new())
            }]
        } else {
            doc.bytes
                .chunks(CHUNK_BYTES)
                .enumerate()
                .map(|(i, bytes)| {
                    if touched(i as u64) {
                        ViewChunk::Withheld(leaf(i, bytes))
                    } else {
                        ViewChunk::Disclosed(bytes.to_vec())
                    }
                })
                .collect()
        };
        Self {
            original: doc.oid(),
            contract,
            kind: doc.kind,
            size: doc.bytes.len() as u64,
            doc_commit: doc.doc_commit(),
            chunks,
        }
    }

    /// `u16 version ‖ oid ‖ u16 contract ‖ u8 kind ‖ u64 size ‖ doc_commit ‖
    /// list(0u8 ‖ bytes | 1u8 ‖ leaf hash)`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::new();
        w.u16(VIEW_VERSION)
            .fixed(&self.original.0)
            .u16(self.contract)
            .u8(self.kind)
            .u64(self.size)
            .fixed(&self.doc_commit)
            .list(&self.chunks, |w, c| match c {
                ViewChunk::Disclosed(bytes) => {
                    w.u8(DISCLOSED).bytes(bytes);
                }
                ViewChunk::Withheld(hash) => {
                    w.u8(WITHHELD).fixed(hash);
                }
            });
        w.finish().map_err(|e| KernelError::Model(e.into()))
    }

    /// Decode a view's bytes (structure only; [`RedactedView::verify`] is
    /// the proof).
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.u16("view.version")? != VIEW_VERSION {
            return Err(r.invalid("view.version"));
        }
        let view = Self {
            original: Oid(r.fixed("view.original")?),
            contract: r.u16("view.contract")?,
            kind: r.u8("view.kind")?,
            size: r.u64("view.size")?,
            doc_commit: r.fixed("view.doc_commit")?,
            chunks: r.list(MAX_VIEW_CHUNKS, "view.chunks", |r| {
                Ok(match r.u8("view.chunk")? {
                    DISCLOSED => {
                        ViewChunk::Disclosed(r.bytes(CHUNK_BYTES, "view.chunk.bytes")?.to_vec())
                    }
                    WITHHELD => ViewChunk::Withheld(r.fixed("view.chunk.leaf")?),
                    t => return Err(r.bad_tag("view.chunk", t)),
                })
            })?,
        };
        r.finish()?;
        Ok(view)
    }

    /// `H("fa:redacted-view:v1" ‖ canonical bytes)`: the view's own identity.
    pub fn view_commit(&self) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(VIEW_DOMAIN, &[&self.canonical_bytes()?]))
    }

    /// The proof: the view has the original's chunk shape, and its disclosed
    /// chunks and withheld leaves rebuild the original's commitment.
    /// Otherwise names what disagrees.
    pub fn verify(&self) -> Result<(), String> {
        let count = chunk_count(self.size);
        if self.chunks.len() as u64 != count {
            return Err(format!(
                "a {}-byte document has {count} chunks; the view carries {}",
                self.size,
                self.chunks.len()
            ));
        }
        let mut leaves = Vec::with_capacity(self.chunks.len());
        for (i, c) in self.chunks.iter().enumerate() {
            leaves.push(match c {
                ViewChunk::Disclosed(bytes) => {
                    let want = chunk_len(self.size, i as u64);
                    if bytes.len() as u64 != want {
                        return Err(format!(
                            "disclosed chunk {i} is {} bytes; the document's is {want}",
                            bytes.len()
                        ));
                    }
                    leaf(i, bytes)
                }
                ViewChunk::Withheld(hash) => *hash,
            });
        }
        let rebuilt = commitment(self.kind, self.size, &tree_root(leaves));
        if rebuilt != self.doc_commit {
            return Err(format!(
                "the view rebuilds commitment {}, not the original's {}",
                crate::evidence::hex(&rebuilt),
                crate::evidence::hex(&self.doc_commit)
            ));
        }
        Ok(())
    }

    /// The disclosed bytes with their offsets in the original.
    pub fn disclosed(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.chunks.iter().enumerate().filter_map(|(i, c)| match c {
            ViewChunk::Disclosed(bytes) => Some((i as u64 * CHUNK_BYTES as u64, bytes.as_slice())),
            ViewChunk::Withheld(_) => None,
        })
    }
}

// ---------------------------------------------------------------------------
// Views in the book: derivation by a privileged holder, reads by capability
// ---------------------------------------------------------------------------

/// `vid(view) = H("fa:vid:redacted-view:v1" ‖ book ‖ original ‖ u16
/// contract)`: one view per document per contract.
#[must_use]
pub fn redacted_view_vid(book: Id128, original: &Oid, contract: u16) -> VId {
    let d = domain_digest(
        b"fa:vid:redacted-view:v1",
        &[&book.0, &original.0, &contract.to_le_bytes()],
    );
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d[..16]);
    VId(u128::from_le_bytes(lo))
}

/// The embedded contracts, parsed once per process.
fn contracts() -> Result<&'static RedactionContracts, KernelError> {
    static CONTRACTS: OnceLock<Result<RedactionContracts, String>> = OnceLock::new();
    CONTRACTS
        .get_or_init(|| RedactionContracts::embedded().map_err(|e| e.to_string()))
        .as_ref()
        .map_err(|e| KernelError::Corrupt(format!("redaction_contracts.toml: {e}")))
}

/// The outcome of a derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewDerived {
    pub view: VId,
    pub view_commit: [u8; 32],
    pub contract: u16,
    pub recorded_at: CommitSeq,
    /// The same view was already recorded; nothing was written.
    pub already_recorded: bool,
}

/// What a capability may read of a document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DocumentRead {
    /// The verified bytes: the capability reveals them, or nothing in the
    /// document is privileged.
    Full(Document),
    /// The document's redacted view, verified against its commitment.
    Redacted(RedactedView),
}

fn unknown_document(oid: &Oid) -> Refusal {
    Refusal::new(
        code::EVIDENCE_UNKNOWN,
        exit::REFUSAL,
        format!("document {} is not in this book", hex(&oid.0)),
        "plan §9.6 (a redacted view projects a document the book holds)",
        "name the oid `fa document add` printed for a document of this book",
    )
}

fn proof_failed(view: VId, why: &str) -> Refusal {
    Refusal::new(
        code::REDACTION_PROOF,
        exit::VERIFICATION,
        format!("redacted view {:032x}: {why}", view.0),
        "plan §9.6 (a redacted view proves it projects the document an entry cites); FA-INV-14 public-commitment",
        "treat the stored view as untrusted: a view that does not rebuild its document's commitment is not that document's; a privileged principal re-derives it from the verified bytes",
    )
}

/// The view stored at `row`, checked against what the book records without
/// reading the document's bytes (WhiteCreek 3428): it names `oid` and the
/// contract; it proves `document_commit`, the commitment the book recorded
/// for `oid` (which binds its kind and size too); it rebuilds that
/// commitment; and it withholds exactly the chunks the contract's privileged
/// ranges touch — never a privileged chunk disclosed, however consistent its
/// hashes. Otherwise why not.
fn stored_view(
    row: &VertexRow,
    book: Id128,
    oid: &Oid,
    contract: &Contract,
    document_commit: &[u8; 32],
) -> Result<RedactedView, String> {
    let Some(CanonicalScalar::Bytes(b)) = prop(row, property::FA_PAYLOAD) else {
        return Err("carries no view payload".into());
    };
    let view = RedactedView::decode(b.as_slice()).map_err(|e| format!("does not decode: {e}"))?;
    if view.original != *oid || view.contract != contract.id {
        return Err("is another document's or another contract's view".into());
    }
    // The oid is H(book ‖ doc_commit) (WhiteCreek 3435): the view's
    // commitment must be the one the requested oid names, and the one the
    // book recorded for it.
    if document_oid(book, &view.doc_commit) != *oid || view.doc_commit != *document_commit {
        return Err(format!(
            "proves commitment {}, not the {} the book recorded for the document",
            hex(&view.doc_commit),
            hex(document_commit)
        ));
    }
    view.verify()?;
    for (i, c) in view.chunks.iter().enumerate() {
        match (privileged_chunk(i as u64, &contract.privileged), c) {
            (true, ViewChunk::Disclosed(_)) => {
                return Err(format!(
                    "discloses chunk {i}, which contract {} withholds",
                    contract.id
                ));
            }
            (false, ViewChunk::Withheld(_)) => {
                return Err(format!(
                    "withholds chunk {i}, which contract {} discloses",
                    contract.id
                ));
            }
            _ => {}
        }
    }
    let commit = view.view_commit().map_err(|e| e.to_string())?;
    match prop(row, property::FA_DIGEST) {
        Some(CanonicalScalar::Bytes(d)) if d.as_slice() == commit => Ok(view),
        _ => Err("its digest mirror is not its view commitment".into()),
    }
}

/// Derive and record the redacted view of document `oid` under the contract
/// governing its kind (plan §9.6). Authority first, before any read: the
/// capability is its holder's, holds `privileged` (the contracts' revealing
/// op), is current and is not revoked. Then the verified bytes (from the book or `store`;
/// 116/085 as for any read), the governing contract (none: FA-REF-100,
/// nothing in the document is privileged), the view, and in one transaction
/// the revocation witness, the view's identity (the same view again is its
/// recorded outcome) and the view with a `REDACTS` edge to its document.
pub async fn derive_redacted_view<V, B>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    store: &BlobStore<B>,
    oid: Oid,
) -> Outcome<ViewDerived>
where
    V: asupersync::fs::Vfs + Clone,
    B: asupersync::fs::Vfs + Clone,
{
    if let Err(d) = fa_policy::admit(
        capability,
        &Intent {
            principal: capability.holder(),
            trunk: true,
            op: Op::Privileged,
            book: book.book_id,
            legs: &[],
        },
    ) {
        return Ok(Err(refusal(&d)));
    }
    if let Err(d) = fa_policy::current(capability, db.frontier()?) {
        return Ok(Err(refusal(&d)));
    }
    // Not revoked (plan §14.2): a head check before any other read
    // (fa-bcd); a derivation's commit witnesses it again in its transaction.
    if let Err(r) = capability_admitted(db, book, capability)? {
        return Ok(Err(r));
    }
    let doc = match fetch_document(db, ctx, store, &oid).await? {
        Ok(Some(doc)) => doc,
        Ok(None) => return Ok(Err(unknown_document(&oid))),
        Err(r) => return Ok(Err(r)),
    };
    let Some(contract) = contracts()?.for_kind(doc.kind) else {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "document {} is of a kind no redaction contract governs: nothing in it is privileged",
                hex(&oid.0)
            ),
            "plan §9.6; registries/redaction_contracts.toml",
            "read the document itself; a view exists only for kinds a contract governs",
        )));
    };
    let view = RedactedView::derive(&doc, contract.id, &contract.privileged);
    view.verify().map_err(|why| {
        KernelError::Corrupt(format!(
            "a derived view does not rebuild its commitment: {why}"
        ))
    })?;
    let view_commit = view.view_commit()?;
    let vid = redacted_view_vid(book.book_id, &oid, contract.id);
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    if let Some(row) = txn.vertex(db, vid)? {
        txn.abort();
        return recorded(
            &row,
            book.book_id,
            &oid,
            contract,
            &view.doc_commit,
            view_commit,
        );
    }
    let mut batch = WriteBatch::new(relation::REDACTS);
    batch.create_vertex(
        vid,
        vec![label::REDACTED_VIEW],
        vec![
            (
                property::FA_PAYLOAD,
                scalar_bytes("_fa_payload", view.canonical_bytes()?)?,
            ),
            (
                property::FA_DIGEST,
                scalar_bytes("_fa_digest", view_commit.to_vec())?,
            ),
        ],
    );
    let dvid = document_vid(&oid);
    batch.add_edge(edge_id(relation::REDACTS, vid, dvid), vid, dvid, vec![]);
    if let Err(e) = txn.write(db, batch) {
        txn.abort();
        return Err(e.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(ViewDerived {
            view: vid,
            view_commit,
            contract: contract.id,
            recorded_at: seq,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => match db.vertex(vid)? {
            Some(row) => recorded(
                &row,
                book.book_id,
                &oid,
                contract,
                &view.doc_commit,
                view_commit,
            ),
            None => Err(KernelError::Corrupt(
                "redacted view identity spent but no live row".into(),
            )),
        },
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("a concurrent commit invalidated a witness this derivation read: {detail}"),
                "FG-LAW-FCW-01 (first committer wins)",
                "retry; if the view was recorded meanwhile the retry returns it",
            )))
        }
        Err(e) => Err(e.into()),
    }
}

fn recorded(
    row: &VertexRow,
    book: Id128,
    oid: &Oid,
    contract: &Contract,
    document_commit: &[u8; 32],
    view_commit: [u8; 32],
) -> Outcome<ViewDerived> {
    match stored_view(row, book, oid, contract, document_commit) {
        Ok(stored) if stored.view_commit()? == view_commit => Ok(Ok(ViewDerived {
            view: row.vid,
            view_commit,
            contract: contract.id,
            recorded_at: row.created_at,
            already_recorded: true,
        })),
        Ok(_) => Ok(Err(proof_failed(
            row.vid,
            "differs from the view the contract derives from the document's verified bytes",
        ))),
        Err(why) => Ok(Err(proof_failed(row.vid, &why))),
    }
}

/// Read document `oid` as `capability` may see it (plan §9.6; R-RED interim,
/// decided before any read of its bytes, never as a result filter). The
/// capability is its holder's, holds `read`, admits this book, is current
/// and is not revoked. One that also holds `privileged` reads the verified
/// bytes. For
/// any other, the document's kind (public metadata, one point read of its
/// mirror) selects the governing contract: none, and the verified bytes are
/// read, because nothing in them is privileged; one, and only the view
/// vertex is read — FA-REF-142 when no view has been derived, FA-REF-143
/// when the stored view does not rebuild the document's commitment.
pub async fn read_document_for<V, B>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    store: &BlobStore<B>,
    oid: Oid,
) -> Outcome<DocumentRead>
where
    V: asupersync::fs::Vfs + Clone,
    B: asupersync::fs::Vfs + Clone,
{
    if let Err(d) = fa_policy::admit_read(capability, capability.holder(), book.book_id) {
        return Ok(Err(refusal(&d)));
    }
    if let Err(d) = fa_policy::current(capability, db.frontier()?) {
        return Ok(Err(refusal(&d)));
    }
    // Not revoked (plan §14.2): a head check before any other read
    // (fa-bcd); a derivation's commit witnesses it again in its transaction.
    if let Err(r) = capability_admitted(db, book, capability)? {
        return Ok(Err(r));
    }
    let full = |r: Result<Option<Document>, Refusal>| match r {
        Ok(Some(doc)) => Ok(DocumentRead::Full(doc)),
        Ok(None) => Err(unknown_document(&oid)),
        Err(r) => Err(r),
    };
    if capability.holds(Op::Privileged) {
        return Ok(full(fetch_document(db, ctx, store, &oid).await?));
    }
    let policy = EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let txn_cx = ctx.txn();
    let txn = db.begin(&txn_cx)?;
    // Public metadata only (plan §9.6: kind, size and digest stay visible):
    // the kind mirror and the recorded commitment, never the payload.
    let dvid = document_vid(&oid);
    let kind = match txn.vertex_property(db, dvid, property::CODE)? {
        Some(CanonicalScalar::Text(t)) => policy
            .kinds
            .iter()
            .find(|k| k.name.as_bytes() == t.as_bytes())
            .map(|k| k.tag),
        _ => None,
    };
    let recorded_commit = match txn.vertex_property(db, dvid, property::FA_DIGEST)? {
        Some(CanonicalScalar::Bytes(b)) => <[u8; 32]>::try_from(b.as_slice()).ok(),
        _ => None,
    };
    let (Some(kind), Some(recorded_commit)) = (kind, recorded_commit) else {
        txn.abort();
        return Ok(Err(unknown_document(&oid)));
    };
    let Some(contract) = contracts()?.for_kind(kind) else {
        txn.abort();
        return Ok(full(fetch_document(db, ctx, store, &oid).await?));
    };
    let vid = redacted_view_vid(book.book_id, &oid, contract.id);
    let row = txn.vertex(db, vid)?;
    txn.abort();
    let Some(row) = row else {
        return Ok(Err(Refusal::new(
            code::REDACTED_VIEW_ABSENT,
            exit::REFUSAL,
            format!(
                "document {} is governed by redaction contract {} (`{}`) and has no derived view",
                hex(&oid.0),
                contract.id,
                contract.name
            ),
            "plan §9.6 (a reader without the revealing op sees a governed document only through its redacted view); registries/redaction_contracts.toml",
            "have a principal holding privileged derive the document's redacted view first; the bytes themselves are never served to this capability",
        )));
    };
    Ok(
        match stored_view(&row, book.book_id, &oid, contract, &recorded_commit) {
            Ok(view) => Ok(DocumentRead::Redacted(view)),
            Err(why) => Err(proof_failed(vid, &why)),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::DurableDirectory;
    use crate::evidence::doc_commit;
    use crate::genesis::{BookSpec, create_book};
    use asupersync::runtime::{Runtime, RuntimeBuilder};
    use fa_model::{Erasable, Id128, SealKey, SymbolTable};
    use fa_money::UnitRegistry;
    use fa_policy::Profile;
    use fa_time::{DateDay, FiscalCalendar};
    use fgdb::{DatabaseKeys, MemVfs};
    use fgdb_types::VId;
    use fgdb_types::ids::DatabaseSecurityNamespaceId;
    use std::path::Path;

    fn doc(size: usize) -> Document {
        Document {
            book_id: Id128([5; 16]),
            kind: 5,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: VId(7),
            bytes: (0..size).map(|i| (i % 251) as u8).collect(),
        }
    }

    const C: u64 = CHUNK_BYTES as u64;

    struct ReadFixture {
        runtime: Runtime,
        contexts: PurposeContexts,
        db: Database<MemVfs>,
        book: BookContext,
        store: BlobStore<MemVfs>,
    }

    impl ReadFixture {
        fn new() -> Self {
            let runtime = RuntimeBuilder::new().build().unwrap();
            let root = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
            let contexts = PurposeContexts::narrow_runtime_root(&root);
            let keys = DatabaseKeys::new(
                [0x5a; 32],
                DatabaseSecurityNamespaceId([0x5b; 32]),
                [0x5c; 32],
            );
            let mut db = runtime
                .block_on(Database::open_memory(&contexts.commit(), keys))
                .unwrap();
            let units = UnitRegistry::with_defaults();
            let calendar = FiscalCalendar::monthly("read-policy", 1, 1).unwrap();
            let spec = BookSpec {
                book_id: Id128([5; 16]),
                name: "Read admission".into(),
                base_unit: units.lookup("USD").unwrap(),
                calendar: calendar.clone(),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            };
            let symbols = SymbolTable::compiled();
            runtime
                .block_on(create_book(&mut db, &contexts, &spec, &units, &symbols))
                .unwrap();
            let book = BookContext {
                book_id: spec.book_id,
                calendar,
                units,
                seal_key: SealKey([0x11; 32]),
                symbols,
            };
            let vfs = contexts.commit().with_restriction(MemVfs::new).unwrap();
            let directory = runtime
                .block_on(DurableDirectory::create(
                    &contexts.commit(),
                    vfs,
                    Path::new("read-blobs"),
                ))
                .unwrap();
            let store = BlobStore::open(1, directory).unwrap();
            Self {
                runtime,
                contexts,
                db,
                book,
                store,
            }
        }

        fn add(&mut self, document: &Document) {
            self.runtime
                .block_on(crate::evidence::add_document(
                    &mut self.db,
                    &self.contexts,
                    &self.book,
                    document,
                ))
                .unwrap()
                .unwrap();
        }

        fn read(&mut self, capability: &Capability, oid: Oid) -> Result<DocumentRead, Refusal> {
            self.runtime
                .block_on(
                    self.contexts
                        .query()
                        .with_restriction_async(read_document_for(
                            &mut self.db,
                            &self.contexts,
                            &self.book,
                            capability,
                            &self.store,
                            oid,
                        )),
                )
                .unwrap()
        }

        fn reader(&self) -> Capability {
            Capability::new(VId(31), Profile::Agent, &[Op::Read], VId(1))
                .unwrap()
                .for_books(&[self.book.book_id])
                .unwrap()
        }
    }

    #[test]
    fn an_agent_reads_public_documents_and_only_the_governed_redacted_view() {
        let mut f = ReadFixture::new();
        let reader = f.reader();
        let invoice = Document { kind: 1, ..doc(19) };
        f.add(&invoice);
        let head = f.db.frontier().unwrap();
        assert_eq!(
            f.read(&reader, invoice.oid()).unwrap(),
            DocumentRead::Full(invoice)
        );
        assert_eq!(f.db.frontier().unwrap(), head, "a read records no write");

        let statement = doc(CHUNK_BYTES + 19);
        f.add(&statement);
        assert_eq!(
            f.read(&reader, statement.oid()).unwrap_err().code,
            code::REDACTED_VIEW_ABSENT
        );
        let privileged = Capability::embedded(VId(7), &["privileged"]).unwrap();
        f.runtime
            .block_on(derive_redacted_view(
                &mut f.db,
                &f.contexts,
                &f.book,
                &privileged,
                &f.store,
                statement.oid(),
            ))
            .unwrap()
            .unwrap();
        let head = f.db.frontier().unwrap();
        let DocumentRead::Redacted(view) = f.read(&reader, statement.oid()).unwrap() else {
            panic!("an Agent without privileged must not receive the full statement");
        };
        assert_eq!(view.verify(), Ok(()));
        assert_eq!(view.doc_commit, statement.doc_commit());
        assert_eq!(view.chunks.len(), 2);
        assert!(matches!(view.chunks[0], ViewChunk::Withheld(_)));
        assert_eq!(
            view.disclosed().collect::<Vec<_>>(),
            vec![(C, &statement.bytes[CHUNK_BYTES..])]
        );
        assert_eq!(f.db.frontier().unwrap(), head);
    }

    #[test]
    fn excluded_missing_and_expired_read_authority_refuses_before_payload_inspection() {
        let mut f = ReadFixture::new();
        let invoice = Document { kind: 1, ..doc(23) };
        f.add(&invoice);
        let reader = f.reader();
        let mut poison = WriteBatch::new(relation::CUSTODY_OF);
        poison.set_vertex_property(
            document_vid(&invoice.oid()),
            property::FA_PAYLOAD,
            scalar_bytes("_fa_payload", vec![0xff]).unwrap(),
        );
        f.runtime
            .block_on(f.db.write(&f.contexts.commit(), poison))
            .unwrap();
        let head = f.db.frontier().unwrap();
        let excluded = Capability::new(VId(31), Profile::Agent, &[Op::Read], VId(1))
            .unwrap()
            .for_books(&[Id128([6; 16])])
            .unwrap();
        let missing = Capability::new(VId(31), Profile::Agent, &[Op::Post], VId(1)).unwrap();
        let expired = reader.clone().expiring_at(head);
        for (capability, expected) in [
            (excluded, "FA-REF-011"),
            (missing, "FA-REF-011"),
            (expired, "FA-REF-014"),
        ] {
            assert_eq!(
                f.read(&capability, invoice.oid()).unwrap_err().code,
                expected
            );
            assert_eq!(f.db.frontier().unwrap(), head);
        }
        assert_eq!(
            f.read(&reader, invoice.oid()).unwrap_err().code,
            code::DOCUMENT_DRIFT,
            "the malformed payload is observable only after admission"
        );
    }

    #[test]
    fn a_read_uses_current_expiry_and_revocation_even_for_an_older_document() {
        let mut f = ReadFixture::new();
        let invoice = Document { kind: 1, ..doc(29) };
        f.add(&invoice);
        let reader = f.reader();
        let head = f.db.frontier().unwrap();
        let expiring = reader.clone().expiring_at(CommitSeq(head.0 + 1));
        assert!(f.read(&expiring, invoice.oid()).is_ok());
        f.add(&Document { kind: 1, ..doc(31) });
        assert_eq!(
            f.read(&expiring, invoice.oid()).unwrap_err().code,
            "FA-REF-014"
        );
        assert!(f.read(&reader, invoice.oid()).is_ok());
        let request = crate::policy::RevocationRequest {
            capability: Capability::embedded(VId(7), &["issue_capability"]).unwrap(),
            revoked: reader.commitment().unwrap(),
            effective_date: DateDay::from_ymd(2026, 1, 1).unwrap(),
            idempotency_key: b"revoke-reader".to_vec(),
            description: Erasable::seal(
                &"revoke document access".to_string(),
                None,
                &f.book.seal_key,
                [0x12; 32],
                [0x13; 24],
            ),
        };
        f.runtime
            .block_on(crate::policy::revoke_capability(
                &mut f.db,
                &f.contexts,
                &f.book,
                request,
            ))
            .unwrap()
            .unwrap();
        let head = f.db.frontier().unwrap();
        assert_eq!(
            f.read(&reader, invoice.oid()).unwrap_err().code,
            "FA-REF-023"
        );
        assert_eq!(f.db.frontier().unwrap(), head);
    }

    #[test]
    fn a_view_rebuilds_the_commitment_and_discloses_only_untouched_chunks() {
        let ranges: [&[(u64, u64)]; 6] = [
            &[],
            &[(0, 1)],
            &[(C + 10, 5)],
            &[(C - 1, 2)],
            &[(0, 10 * C)],
            &[(3 * C, 0), (9 * C, 7)],
        ];
        for size in [0, 1, CHUNK_BYTES, CHUNK_BYTES + 1, 3 * CHUNK_BYTES + 5] {
            let d = doc(size);
            for privileged in ranges {
                let v = RedactedView::derive(&d, 2, privileged);
                assert_eq!(v.verify(), Ok(()), "size {size}, ranges {privileged:?}");
                assert_eq!(v.doc_commit, doc_commit(d.kind, &d.bytes));
                assert_eq!(v.chunks.len() as u64, chunk_count(size as u64));
                for (offset, bytes) in v.disclosed() {
                    let o = usize::try_from(offset).unwrap();
                    assert_eq!(&d.bytes[o..o + bytes.len()], bytes, "disclosed at {offset}");
                    assert!(
                        privileged
                            .iter()
                            .all(|(p, l)| *l == 0 || p + l <= offset || *p >= offset + C),
                        "a touched chunk was disclosed at {offset}"
                    );
                }
            }
        }
        // A range straddling a chunk boundary withholds both chunks.
        let v = RedactedView::derive(&doc(3 * CHUNK_BYTES), 2, &[(C - 1, 2)]);
        let withheld: Vec<usize> = v
            .chunks
            .iter()
            .enumerate()
            .filter(|(_, c)| matches!(c, ViewChunk::Withheld(_)))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(withheld, [0, 1]);
    }

    #[test]
    fn a_tampered_view_does_not_rebuild_the_commitment() {
        let d = doc(3 * CHUNK_BYTES + 5);
        let v = RedactedView::derive(&d, 2, &[(C + 3, 1)]);
        let mut byte = v.clone();
        if let ViewChunk::Disclosed(b) = &mut byte.chunks[0] {
            b[0] ^= 1;
        }
        let mut hash = v.clone();
        if let ViewChunk::Withheld(h) = &mut hash.chunks[1] {
            h[0] ^= 1;
        }
        let mut short = v.clone();
        short.chunks.pop();
        let mut size = v.clone();
        size.size += 1;
        let mut kind = v.clone();
        kind.kind ^= 1;
        let mut truncated = v.clone();
        if let ViewChunk::Disclosed(b) = &mut truncated.chunks[3] {
            b.pop();
        }
        let mut swapped = v.clone();
        swapped.chunks.swap(0, 2);
        for (what, t) in [
            ("a disclosed byte", byte),
            ("a withheld leaf", hash),
            ("a dropped chunk", short),
            ("the size", size),
            ("the kind", kind),
            ("a short last chunk", truncated),
            ("two chunks swapped", swapped),
        ] {
            assert!(t.verify().is_err(), "{what}");
        }
    }

    #[test]
    fn views_round_trip_and_their_commitment_binds_every_byte() {
        let v = RedactedView::derive(&doc(2 * CHUNK_BYTES + 9), 3, &[(0, 1)]);
        let bytes = v.canonical_bytes().unwrap();
        assert_eq!(RedactedView::decode(&bytes).unwrap(), v);
        let commit = v.view_commit().unwrap();
        for i in (0..bytes.len()).step_by(97) {
            let mut x = bytes.clone();
            x[i] ^= 0x01;
            if let Ok(back) = RedactedView::decode(&x) {
                assert_ne!(back.view_commit().unwrap(), commit, "byte {i}");
            }
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(RedactedView::decode(&trailing).is_err());
        // Another contract over the same document is another view.
        let other = RedactedView::derive(&doc(2 * CHUNK_BYTES + 9), 4, &[(0, 1)]);
        assert_ne!(other.view_commit().unwrap(), commit);
    }
}
