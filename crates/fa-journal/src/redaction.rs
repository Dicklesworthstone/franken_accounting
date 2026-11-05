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
        for (i, c) in self.chunks.iter().enumerate() {
            if let ViewChunk::Disclosed(bytes) = c {
                let want = chunk_len(self.size, i as u64);
                if bytes.len() as u64 != want {
                    return Err(format!(
                        "disclosed chunk {i} is {} bytes; the document's is {want}",
                        bytes.len()
                    ));
                }
            }
        }
        let rebuilt = commitment(self.kind, self.size, &self.chunk_root());
        if rebuilt != self.doc_commit {
            return Err(format!(
                "the view rebuilds commitment {}, not the original's {}",
                crate::evidence::hex(&rebuilt),
                crate::evidence::hex(&self.doc_commit)
            ));
        }
        Ok(())
    }

    /// The original's chunk root, rebuilt from the disclosed chunks and the
    /// withheld leaves: with the kind and size, what the commitment commits,
    /// so a bundle stub can carry it without the bytes. Meaningful only once
    /// [`Self::verify`] passes; a view of the wrong shape rebuilds some other
    /// root.
    #[must_use]
    pub fn chunk_root(&self) -> [u8; 32] {
        tree_root(
            self.chunks
                .iter()
                .enumerate()
                .map(|(i, c)| match c {
                    ViewChunk::Disclosed(bytes) => leaf(i, bytes),
                    ViewChunk::Withheld(hash) => *hash,
                })
                .collect(),
        )
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
pub(crate) fn contracts() -> Result<&'static RedactionContracts, KernelError> {
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
    if let Some(contract) = capability.redaction() {
        return Ok(Err(refusal(&fa_policy::Denial::OutOfScope {
            caveat: "redaction",
            value: format!(
                "deriving a redacted view from unredacted bytes (the token is confined to contract {contract}'s views)"
            ),
        })));
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
/// capability is its holder's, holds `read`, admits this book, carries no
/// scope caveat (plan §14.2: which documents a scoped reader may see is
/// whole-entry visibility, not yet enforced, so it is refused), is current
/// and is not revoked. One that also holds `privileged` and is not confined
/// by a `redaction = <contract>` caveat for the governing contract reads the
/// verified bytes (fa-kuu). For any other, the document's kind (public
/// metadata, one point read of its mirror) selects the governing contract:
/// none, and the verified bytes are read, because nothing in them is
/// privileged; one, and only the view vertex is read — FA-REF-142 when no
/// view has been derived, FA-REF-143 when the stored view does not rebuild
/// the document's commitment.
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
    let reach = fa_policy::Reach::whole_book(true);
    read_document_for_with(db, ctx, book, capability, &reach, store, oid, |_| Ok(())).await
}

/// Like [`read_document_for`], judging the scope caveats against `reach`
/// (what the caller's act discloses; a bundle's cited documents reach what
/// the bundle does) instead of the whole book at its head, and running
/// `before_fetch` on the verified [`crate::DocumentRecord`] after capability
/// and redaction-contract admission and before reading any external blob
/// bytes.
#[allow(clippy::too_many_arguments)]
pub async fn read_document_for_with<V, B, F>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    reach: &fa_policy::Reach<'_>,
    store: &BlobStore<B>,
    oid: Oid,
    before_fetch: F,
) -> Outcome<DocumentRead>
where
    V: asupersync::fs::Vfs + Clone,
    B: asupersync::fs::Vfs + Clone,
    F: FnOnce(&crate::DocumentRecord) -> Result<(), Refusal>,
{
    if let Err(d) = fa_policy::admit_read(capability, capability.holder(), book.book_id) {
        return Ok(Err(refusal(&d)));
    }
    // Judged before its currency or revocation is read: a plain document
    // read reaches the whole book at its head, so a token with any scope
    // caveat is refused there.
    if let Err(d) = fa_policy::reach(capability, reach, None) {
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
    read_document_after_admission(db, ctx, book, capability, store, oid, before_fetch).await
}

/// The closed document families that source-derived draft preparation may
/// observe. A caller cannot turn a draft's Post authority into an arbitrary
/// document read by choosing its own kind or media type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DraftSourceKind {
    FxRate,
    ExternalSubledgerDetail,
}

impl DraftSourceKind {
    const fn kind(self) -> u8 {
        match self {
            Self::FxRate => crate::fx::RATE_DOCUMENT_KIND,
            Self::ExternalSubledgerDetail => {
                crate::external_subledger::EXTERNAL_SUBLEDGER_DOCUMENT_KIND
            }
        }
    }

    const fn mime(self) -> &'static str {
        match self {
            Self::FxRate => "application/vnd.franken.fx-rate.v1",
            Self::ExternalSubledgerDetail => crate::external_subledger::EXTERNAL_SUBLEDGER_MIME,
        }
    }

    fn refusal(self) -> Refusal {
        Refusal::new(
            code::CAPABILITY,
            exit::SAFETY,
            "the selected document is not admitted for this draft source operation",
            "FA-INV-10 (authorization before observation); plan §15.2 / fa-txgy.7 (typed source derivation)",
            match self {
                Self::FxRate => "name a canonical Rate document retained by this book",
                Self::ExternalSubledgerDetail => {
                    "name a canonical external-subledger detail Workpaper retained by this book"
                }
            },
        )
    }
}

/// Validate public identity and kind before the document payload is decoded.
/// Wrong-purpose sources get the same refusal even when their private payload
/// is corrupt, unavailable or governed by a redaction contract.
fn admit_draft_source_document<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    oid: Oid,
    source: DraftSourceKind,
) -> Outcome<[u8; 32]> {
    let policy = EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let expected = policy.kind_by_tag(source.kind()).ok_or_else(|| {
        KernelError::Corrupt("a typed draft source has no registered document kind".into())
    })?;
    let txn_cx = ctx.txn();
    let txn = db.begin(&txn_cx)?;
    let vid = document_vid(&oid);
    let is_document = txn.vertex_has_label(db, vid, label::DOCUMENT)?;
    let kind = txn.vertex_property(db, vid, property::CODE)?;
    let identity = txn.vertex_property(db, vid, property::BOOK_ID)?;
    let digest = txn.vertex_property(db, vid, property::FA_DIGEST)?;
    txn.abort();
    if is_document != Some(true)
        || !matches!(kind, Some(CanonicalScalar::Text(value))
            if value.as_bytes() == expected.name.as_bytes())
        || !matches!(identity, Some(CanonicalScalar::Bytes(value))
            if value.as_slice() == book.book_id.0)
    {
        return Ok(Err(source.refusal()));
    }
    let Some(CanonicalScalar::Bytes(bytes)) = digest else {
        return Ok(Err(source.refusal()));
    };
    let Ok(commit) = <[u8; 32]>::try_from(bytes.as_slice()) else {
        return Ok(Err(source.refusal()));
    };
    if document_oid(book.book_id, &commit) != oid {
        return Ok(Err(source.refusal()));
    }
    Ok(Ok(commit))
}

/// Resolve a source for a typed owned-draft derivation, under the original
/// planner's document disclosure restrictions. This is a database-level
/// operation: facades may expose only the resulting monetary proposal, never
/// a general document read through the draft admission.
///
/// Ownership, open state and current authority are checked before source
/// metadata and again after potentially suspended blob I/O. The expected
/// registered kind and identity must match public mirrors before payload
/// decoding. The verified record's kind, media type and identity are checked
/// again before any external blob bytes are fetched. Governing redaction
/// contracts still apply, including to capabilities holding Privileged.
pub async fn read_document_for_draft_source<V, B>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    admission: &crate::draft::DraftSourceAdmission,
    store: &BlobStore<B>,
    oid: Oid,
    source: DraftSourceKind,
) -> Outcome<DocumentRead>
where
    V: asupersync::fs::Vfs + Clone,
    B: asupersync::fs::Vfs + Clone,
{
    ctx.query()
        .checkpoint()
        .map_err(WriteTxnError::Interrupted)?;
    if let Err(refusal) = admission.recheck(db, book)? {
        return Ok(Err(refusal));
    }
    let commit = match admit_draft_source_document(db, ctx, book, oid, source)? {
        Ok(commit) => commit,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let result = read_document_after_admission(
        db,
        ctx,
        book,
        admission.capability(),
        store,
        oid,
        |record| {
            if record.book_id != book.book_id
                || record.kind != source.kind()
                || record.mime != source.mime()
                || record.doc_commit != commit
                || record.oid() != oid
            {
                return Err(source.refusal());
            }
            Ok(())
        },
    )
    .await?;
    ctx.query()
        .checkpoint()
        .map_err(WriteTxnError::Interrupted)?;
    if let Err(refusal) = admission.recheck(db, book)? {
        return Ok(Err(refusal));
    }
    Ok(result)
}

/// Shared document disclosure law after the caller has established either
/// ordinary Read authority or an owned-draft source derivation admission.
async fn read_document_after_admission<V, B, F>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    store: &BlobStore<B>,
    oid: Oid,
    before_fetch: F,
) -> Outcome<DocumentRead>
where
    V: asupersync::fs::Vfs + Clone,
    B: asupersync::fs::Vfs + Clone,
    F: FnOnce(&crate::DocumentRecord) -> Result<(), Refusal>,
{
    let full = |r: Result<Option<Document>, Refusal>| match r {
        Ok(Some(doc)) => Ok(DocumentRead::Full(doc)),
        Ok(None) => Err(unknown_document(&oid)),
        Err(r) => Err(r),
    };
    if capability.holds(Op::Privileged) && capability.redaction().is_none() {
        return Ok(full(
            crate::evidence::fetch_document_with(db, ctx, store, &oid, before_fetch).await?,
        ));
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
        return Ok(full(
            crate::evidence::fetch_document_with(db, ctx, store, &oid, before_fetch).await?,
        ));
    };
    if capability.reveals_contract(contract.id) {
        txn.abort();
        return Ok(full(
            crate::evidence::fetch_document_with(db, ctx, store, &oid, before_fetch).await?,
        ));
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

        fn draft_request(&self, capability: &Capability) -> crate::draft::DraftRequest {
            crate::draft::DraftRequest {
                capability: capability.clone(),
                effective_date: DateDay::from_ymd(2026, 3, 1).unwrap(),
                description: Erasable::seal(
                    &"source disclosure review".to_string(),
                    None,
                    &self.book.seal_key,
                    [0x14; 32],
                    [0x15; 24],
                ),
            }
        }

        fn draft_source(
            &mut self,
            admission: &crate::draft::DraftSourceAdmission,
            oid: Oid,
            source: DraftSourceKind,
        ) -> Result<DocumentRead, Refusal> {
            self.runtime
                .block_on(self.contexts.query().with_restriction_async(
                    read_document_for_draft_source(
                        &mut self.db,
                        &self.contexts,
                        &self.book,
                        admission,
                        &self.store,
                        oid,
                        source,
                    ),
                ))
                .unwrap()
        }
    }

    fn source_draft(
        f: &mut ReadFixture,
        name: &str,
    ) -> (Capability, crate::draft::DraftSourceAdmission) {
        let planner = Capability::new(VId(31), Profile::Agent, &[Op::Post], VId(1))
            .unwrap()
            .for_books(&[f.book.book_id])
            .unwrap()
            .on_branch(fa_model::draft_branch(f.book.book_id, name))
            .unwrap();
        let request = f.draft_request(&planner);
        f.runtime
            .block_on(crate::draft::open_draft(
                &mut f.db,
                &f.contexts,
                &f.book,
                name,
                request,
            ))
            .unwrap()
            .unwrap();
        let admission = crate::draft::admit_sources(&f.db, &f.book, &planner, name)
            .unwrap()
            .unwrap();
        (planner, admission)
    }

    fn typed_source(f: &ReadFixture, source: DraftSourceKind) -> Document {
        let day = DateDay::from_ymd(2026, 3, 1).unwrap();
        let usd = f.book.units.lookup("USD").unwrap();
        match source {
            DraftSourceKind::FxRate => {
                let rate = crate::fx::FxRateDocument::new(
                    crate::fx::FxRateTerms {
                        base_unit: usd,
                        quote_unit: f.book.units.lookup("EUR").unwrap(),
                        rate_num: 11,
                        rate_den: 10,
                        rounding: fa_money::RoundingLaw::HalfEven,
                    },
                    day,
                    1,
                    crate::fx::FxRatePurpose::SpotClose,
                    "Declared Rate source",
                )
                .unwrap();
                Document {
                    kind: crate::fx::RATE_DOCUMENT_KIND,
                    mime: "application/vnd.franken.fx-rate.v1".into(),
                    bytes: rate.canonical_bytes().unwrap(),
                    ..doc(0)
                }
            }
            DraftSourceKind::ExternalSubledgerDetail => {
                let batch = crate::external_subledger::ExternalSubledgerBatch {
                    book_id: f.book.book_id,
                    feed: "typed-source".into(),
                    batch_key: "complete-detail".into(),
                    effective_date: day,
                    rows: [
                        (1, VId(100), fa_money::Side::Debit),
                        (2, VId(200), fa_money::Side::Credit),
                    ]
                    .into_iter()
                    .map(
                        |(id, account, side)| crate::external_subledger::ExternalSubledgerDetail {
                            source_digest: [id; 32],
                            account,
                            side,
                            amount: fa_money::Amount::new(usd, 100),
                            dimensions: Vec::new(),
                        },
                    )
                    .collect(),
                };
                Document {
                    kind: crate::external_subledger::EXTERNAL_SUBLEDGER_DOCUMENT_KIND,
                    mime: crate::external_subledger::EXTERNAL_SUBLEDGER_MIME.into(),
                    bytes: batch.canonical_bytes().unwrap(),
                    ..doc(0)
                }
            }
        }
    }

    #[test]
    fn draft_sources_admit_only_the_declared_family_before_private_payloads() {
        let mut f = ReadFixture::new();
        let name = "source-review";
        let (planner, admission) = source_draft(&mut f, name);
        for source in [
            DraftSourceKind::FxRate,
            DraftSourceKind::ExternalSubledgerDetail,
        ] {
            let document = typed_source(&f, source);
            f.add(&document);
            let head = f.db.frontier().unwrap();
            assert_eq!(
                f.draft_source(&admission, document.oid(), source).unwrap(),
                DocumentRead::Full(document.clone())
            );
            let other = match source {
                DraftSourceKind::FxRate => DraftSourceKind::ExternalSubledgerDetail,
                DraftSourceKind::ExternalSubledgerDetail => DraftSourceKind::FxRate,
            };
            assert_eq!(
                f.draft_source(&admission, document.oid(), other)
                    .unwrap_err()
                    .code,
                code::CAPABILITY
            );
            assert_eq!(
                f.read(&planner, document.oid()).unwrap_err().code,
                code::CAPABILITY,
                "source preparation never adds a general Read operation"
            );
            assert_eq!(f.db.frontier().unwrap(), head);
        }
        let invoice = Document { kind: 1, ..doc(19) };
        let statement = doc(CHUNK_BYTES + 19);
        f.add(&invoice);
        f.add(&statement);

        let privileged = Capability::embedded(planner.holder(), &["post", "privileged"])
            .unwrap()
            .for_books(&[f.book.book_id])
            .unwrap()
            .on_branch(fa_model::draft_branch(f.book.book_id, name))
            .unwrap();
        let privileged_source = crate::draft::admit_sources(&f.db, &f.book, &privileged, name)
            .unwrap()
            .unwrap();
        let caveated = privileged.with_redaction(1).unwrap();
        let caveated_source = crate::draft::admit_sources(&f.db, &f.book, &caveated, name)
            .unwrap()
            .unwrap();

        let revealer = Capability::embedded(VId(7), &["privileged"]).unwrap();
        f.runtime
            .block_on(derive_redacted_view(
                &mut f.db,
                &f.contexts,
                &f.book,
                &revealer,
                &f.store,
                statement.oid(),
            ))
            .unwrap()
            .unwrap();
        let refused_before = f
            .draft_source(&admission, invoice.oid(), DraftSourceKind::FxRate)
            .unwrap_err();
        let mut poison = WriteBatch::new(relation::CUSTODY_OF);
        for document in [&invoice, &statement] {
            poison.set_vertex_property(
                document_vid(&document.oid()),
                property::FA_PAYLOAD,
                Some(scalar_bytes("_fa_payload", vec![0xff]).unwrap()),
            );
        }
        f.runtime
            .block_on(f.db.write(&f.contexts.commit(), poison))
            .unwrap();
        let head = f.db.frontier().unwrap();
        for token in [&admission, &privileged_source, &caveated_source] {
            for source in [
                DraftSourceKind::FxRate,
                DraftSourceKind::ExternalSubledgerDetail,
            ] {
                for document in [&invoice, &statement] {
                    let refused = f.draft_source(token, document.oid(), source).unwrap_err();
                    assert_eq!(refused.code, code::CAPABILITY);
                    assert_eq!(refused.message, refused_before.message);
                }
            }
        }
        let reader = f.reader();
        assert_eq!(
            f.read(&reader, invoice.oid()).unwrap_err().code,
            code::DOCUMENT_DRIFT,
            "an admitted ordinary read reaches the same poisoned payload"
        );
        let DocumentRead::Redacted(view) = f.read(&reader, statement.oid()).unwrap() else {
            panic!("ordinary governed reads must preserve the redacted view");
        };
        assert_eq!(view.verify(), Ok(()));
        let privileged_reader = Capability::embedded(VId(7), &["read", "privileged"]).unwrap();
        assert_eq!(
            f.read(&privileged_reader, statement.oid())
                .unwrap_err()
                .code,
            code::DOCUMENT_DRIFT
        );
        assert_eq!(f.db.frontier().unwrap(), head);

        let request = f.draft_request(&planner);
        f.runtime
            .block_on(crate::draft::discard_draft(
                &mut f.db,
                &f.contexts,
                &f.book,
                name,
                request,
            ))
            .unwrap()
            .unwrap();
        let head = f.db.frontier().unwrap();
        assert_eq!(
            f.draft_source(&privileged_source, statement.oid(), DraftSourceKind::FxRate)
                .unwrap_err()
                .code,
            code::DRAFT_NOT_OPEN,
            "a closed draft refuses before even the public source metadata"
        );
        assert_eq!(f.db.frontier().unwrap(), head);
    }

    #[test]
    fn draft_source_identity_guards_precede_payload_decoding() {
        for corruption in ["label", "book", "commitment"] {
            let mut f = ReadFixture::new();
            let (_, admission) = source_draft(&mut f, "source-identity");
            let document = typed_source(&f, DraftSourceKind::FxRate);
            f.add(&document);
            let vid = document_vid(&document.oid());
            let mut poison = WriteBatch::new(relation::CUSTODY_OF);
            poison.set_vertex_property(
                vid,
                property::FA_PAYLOAD,
                Some(scalar_bytes("_fa_payload", vec![0xff]).unwrap()),
            );
            match corruption {
                "label" => {
                    poison.set_vertex_label(vid, label::DOCUMENT, false);
                }
                "book" => {
                    poison.set_vertex_property(
                        vid,
                        property::BOOK_ID,
                        Some(scalar_bytes("book_id", vec![0xa5; 16]).unwrap()),
                    );
                }
                _ => {
                    poison.set_vertex_property(
                        vid,
                        property::FA_DIGEST,
                        Some(scalar_bytes("_fa_digest", vec![0; 32]).unwrap()),
                    );
                }
            }
            f.runtime
                .block_on(f.db.write(&f.contexts.commit(), poison))
                .unwrap();
            let head = f.db.frontier().unwrap();
            assert_eq!(
                f.draft_source(&admission, document.oid(), DraftSourceKind::FxRate)
                    .unwrap_err()
                    .code,
                code::CAPABILITY,
                "{corruption}: reject the source identity before its private payload"
            );
            assert_eq!(f.db.frontier().unwrap(), head);
        }
    }

    #[test]
    fn draft_source_media_type_is_checked_before_external_blob_io() {
        for source in [
            DraftSourceKind::FxRate,
            DraftSourceKind::ExternalSubledgerDetail,
        ] {
            let mut f = ReadFixture::new();
            let (_, admission) = source_draft(&mut f, "source-media-type");
            let mut document = typed_source(&f, source);
            document.mime = "text/plain".into();
            f.add(&document);
            // Retain a valid external record without creating its blob. A
            // body fetch would expose BLOB_MISSING instead of the type refusal.
            let mut external = WriteBatch::new(relation::CUSTODY_OF);
            external.set_vertex_property(
                document_vid(&document.oid()),
                property::FA_PAYLOAD,
                Some(
                    scalar_bytes(
                        "_fa_payload",
                        document
                            .canonical_bytes_external(
                                f.store.id(),
                                &crate::blob::locator_of(&document.doc_commit()),
                            )
                            .unwrap(),
                    )
                    .unwrap(),
                ),
            );
            f.runtime
                .block_on(f.db.write(&f.contexts.commit(), external))
                .unwrap();
            let head = f.db.frontier().unwrap();
            assert_eq!(
                f.draft_source(&admission, document.oid(), source)
                    .unwrap_err()
                    .code,
                code::CAPABILITY,
                "a wrong media type must not request source bytes"
            );
            let reader = f.reader();
            assert_eq!(
                f.read(&reader, document.oid()).unwrap_err().code,
                code::BLOB_MISSING,
                "the ordinary reader proves the missing-blob trap is live"
            );
            assert_eq!(f.db.frontier().unwrap(), head);
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
        let view = match f.read(&reader, statement.oid()).unwrap() {
            DocumentRead::Redacted(view) => Some(view),
            DocumentRead::Full(_) => None,
        }
        .expect("an Agent without privileged must not receive the full statement");
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
    fn a_redaction_caveat_is_conjunctive_with_privileged_and_decided_before_payload_inspection() {
        let mut f = ReadFixture::new();
        let unredacted_priv = Capability::embedded(VId(7), &["read", "privileged"])
            .unwrap()
            .for_books(&[f.book.book_id])
            .unwrap();
        let caveated_priv = unredacted_priv.clone().with_redaction(1).unwrap();

        let invoice = Document { kind: 1, ..doc(19) };
        let statement = doc(CHUNK_BYTES + 19);
        f.add(&invoice);
        f.add(&statement);

        // Ungoverned documents are read in full by both capabilities.
        assert_eq!(
            f.read(&unredacted_priv, invoice.oid()).unwrap(),
            DocumentRead::Full(invoice.clone())
        );
        assert_eq!(
            f.read(&caveated_priv, invoice.oid()).unwrap(),
            DocumentRead::Full(invoice)
        );

        // Before the view is derived, the un-caveated privileged capability reads
        // the full BankStatement, while the redaction-caveated privileged capability
        // is refused REDACTED_VIEW_ABSENT and cannot derive the view itself.
        assert_eq!(
            f.read(&unredacted_priv, statement.oid()).unwrap(),
            DocumentRead::Full(statement.clone())
        );
        assert_eq!(
            f.read(&caveated_priv, statement.oid()).unwrap_err().code,
            code::REDACTED_VIEW_ABSENT
        );
        let head_before = f.db.frontier().unwrap();
        let derive_refusal = f
            .runtime
            .block_on(derive_redacted_view(
                &mut f.db,
                &f.contexts,
                &f.book,
                &caveated_priv,
                &f.store,
                statement.oid(),
            ))
            .unwrap()
            .unwrap_err();
        assert_eq!(derive_refusal.code, "FA-REF-011");
        assert!(
            derive_refusal
                .message
                .starts_with("the capability's `redaction` caveat"),
            "{}",
            derive_refusal.message
        );
        assert_eq!(f.db.frontier().unwrap(), head_before);

        // Derive the view with un-caveated privileged authority.
        f.runtime
            .block_on(derive_redacted_view(
                &mut f.db,
                &f.contexts,
                &f.book,
                &unredacted_priv,
                &f.store,
                statement.oid(),
            ))
            .unwrap()
            .unwrap();

        // Poison the BankStatement's raw payload bytes: the redaction-caveated
        // privileged capability never touches the raw payload and reads only the
        // verified RedactedView, whereas the un-caveated privileged capability
        // inspects the raw payload and observes DOCUMENT_DRIFT.
        let mut poison = WriteBatch::new(relation::CUSTODY_OF);
        poison.set_vertex_property(
            document_vid(&statement.oid()),
            property::FA_PAYLOAD,
            Some(scalar_bytes("_fa_payload", vec![0xff]).unwrap()),
        );
        f.runtime
            .block_on(f.db.write(&f.contexts.commit(), poison))
            .unwrap();
        let head = f.db.frontier().unwrap();

        let view = match f.read(&caveated_priv, statement.oid()).unwrap() {
            DocumentRead::Redacted(view) => Some(view),
            DocumentRead::Full(_) => None,
        }
        .expect("a redaction-caveated privileged capability must receive only the RedactedView");
        assert_eq!(view.verify(), Ok(()));
        assert_eq!(view.contract, 1);
        assert_eq!(view.doc_commit, statement.doc_commit());
        assert_eq!(
            f.read(&unredacted_priv, statement.oid()).unwrap_err().code,
            code::DOCUMENT_DRIFT
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
            Some(scalar_bytes("_fa_payload", vec![0xff]).unwrap()),
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

    /// fa-llx: a token carrying `read` and any scope caveat (tags 3-7) is
    /// refused before its currency, its revocation or any document is read,
    /// and never receives bytes or a view.
    #[test]
    fn a_scoped_reader_is_refused_before_currency_revocation_or_any_read() {
        let mut f = ReadFixture::new();
        let invoice = Document { kind: 1, ..doc(29) };
        f.add(&invoice);
        let mut poison = WriteBatch::new(relation::CUSTODY_OF);
        poison.set_vertex_property(
            document_vid(&invoice.oid()),
            property::FA_PAYLOAD,
            Some(scalar_bytes("_fa_payload", vec![0xff]).unwrap()),
        );
        f.runtime
            .block_on(f.db.write(&f.contexts.commit(), poison))
            .unwrap();
        let head = f.db.frontier().unwrap();
        let reader = f.reader();
        let day = DateDay::from_ymd(2026, 3, 31).unwrap();
        for (capability, caveat) in [
            (reader.clone().for_accounts(&["1000"]).unwrap(), "accounts"),
            (
                reader.clone().for_periods(&["FY2026-P03"]).unwrap(),
                "periods",
            ),
            (reader.clone().effective_through(day), "effective"),
            (reader.clone().known_at_most(head), "known_at"),
            (reader.clone().on_branch(Id128([9; 16])).unwrap(), "branch"),
            // Expired too: the scope refusal comes first.
            (
                reader
                    .clone()
                    .expiring_at(head)
                    .for_periods(&["FY2026-P03"])
                    .unwrap(),
                "periods",
            ),
        ] {
            let refused = f.read(&capability, invoice.oid()).unwrap_err();
            assert_eq!(refused.code, "FA-REF-011", "{caveat}");
            assert!(
                refused
                    .message
                    .starts_with(&format!("the capability's `{caveat}` caveat")),
                "{caveat}: {}",
                refused.message
            );
            assert_eq!(f.db.frontier().unwrap(), head);
        }
        assert_eq!(
            f.read(&reader, invoice.oid()).unwrap_err().code,
            code::DOCUMENT_DRIFT,
            "the same token without a scope caveat reaches the payload"
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
                assert_eq!(
                    v.chunk_root(),
                    crate::evidence::chunk_root(&d.bytes),
                    "size {size}, ranges {privileged:?}"
                );
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
        let d = doc(3 * CHUNK_BYTES);
        let v = RedactedView::derive(&d, 2, &[(C - 1, 2)]);
        let withheld: Vec<usize> = v
            .chunks
            .iter()
            .enumerate()
            .filter(|(_, c)| matches!(c, ViewChunk::Withheld(_)))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(withheld, [0, 1]);
        // Its withheld leaves and its disclosed chunk 2 rebuild the
        // commitment through chunk_root alone (what a bundle stub carries).
        assert_eq!(
            commitment(d.kind, d.bytes.len() as u64, &v.chunk_root()),
            doc_commit(d.kind, &d.bytes)
        );
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
