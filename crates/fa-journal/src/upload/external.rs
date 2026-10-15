//! Durable external bytes behind the same session-bound intake law.
//!
//! A prepared transaction holds the original revocation, policy and identity
//! witnesses while its content-addressed bytes are written and fenced. Only
//! then can its Document and ImportReceipt become visible. Failures may leave
//! orphan bytes for recovery; they never authorize a partial graph publication.

use asupersync::fs::Vfs;
use fa_model::Oid;
use fa_model::symbols::{label, property, relation};
use fa_policy::Capability;
use fa_registry::evidence_policy::EvidencePolicy;
use fgdb::{Database, WriteBatch, WriteTxnError};
use fgdb_types::CanonicalScalar;
use fgdb_types::context::PurposeContexts;

use crate::blob::{BlobStore, locator_of};
use crate::evidence::{Document, DocumentAdded, document_vid};
use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{scalar_bytes, scalar_text};

use super::{UploadAdmission, UploadPreparation, UploadRequest, admit_upload};

/// Shared physical representation for individually uploaded and batch-imported
/// documents. Callers supply identities cached by their admission step. This
/// stages no receipt and grants no authority; the enclosing transaction owns
/// those checks and must make external bytes durable before publication.
pub(crate) fn stage_external_document(
    batch: &mut WriteBatch,
    document: &Document,
    kind: &str,
    store: u16,
    locator: &str,
    oid: Oid,
    digest: &[u8; 32],
) -> Result<(), KernelError> {
    let payload = document.canonical_bytes_external(store, locator)?;
    let mut props = vec![
        (property::FA_PAYLOAD, scalar_bytes("_fa_payload", payload)?),
        (
            property::FA_DIGEST,
            scalar_bytes("_fa_digest", digest.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("book_id", document.book_id.0.to_vec())?,
        ),
        (property::CODE, scalar_text("code", kind)?),
        (property::CUSTODY_LEN, CanonicalScalar::Int(1)),
    ];
    props.sort_by_key(|(key, _)| key.0);
    batch.create_vertex(document_vid(&oid), vec![label::DOCUMENT], props);
    Ok(())
}

/// Admit and durably store external bytes, retaining an unpublished graph
/// transaction. Dropping/aborting the returned preparation keeps the journal
/// unchanged. A duplicate neither writes a blob nor changes its first receipt.
pub async fn prepare_external_upload<V: Vfs + Clone, B: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    store: &BlobStore<B>,
    request: UploadRequest,
) -> Outcome<UploadPreparation> {
    let admitted = match admit_upload(
        db,
        cx,
        book,
        capability,
        request,
        store.max_document_bytes(),
    )? {
        Err(refusal) => return Ok(Err(refusal)),
        Ok(UploadAdmission::AlreadyRecorded(added)) => {
            return Ok(Ok(UploadPreparation::AlreadyRecorded(added)));
        }
        Ok(UploadAdmission::New(admitted)) => admitted,
    };
    let locator = locator_of(&admitted.summary.doc_commit);
    let mut batch = WriteBatch::new(relation::CUSTODY_OF);
    stage_external_document(
        &mut batch,
        &admitted.document,
        &admitted.kind,
        store.id(),
        &locator,
        admitted.summary.oid,
        &admitted.summary.doc_commit,
    )?;
    crate::custody::stage_receipt(
        &mut batch,
        book,
        &admitted.document,
        admitted.source.clone(),
        capability.holder(),
        None,
    )?;
    // Admission's transaction stays alive across every await. Do not call the
    // legacy external intake here: that would publish without these witnesses.
    let commit = cx.commit();
    commit.checkpoint().map_err(WriteTxnError::Interrupted)?;
    if let Err(error) = store.put(&commit, &locator, &admitted.document.bytes).await {
        admitted.txn.abort();
        return Ok(Err(Refusal::new(
            code::BLOB_MISSING,
            exit::FOUNDATION,
            format!(
                "document {locator}: store {} could not durably write its bytes: {error}",
                store.id()
            ),
            "plan §9.1; FA-INV-05 (bytes durable before document and receipt publication)",
            "restore the blob store's writable capacity and retry under current authority; no document or receipt was committed",
        )));
    }
    commit.checkpoint().map_err(WriteTxnError::Interrupted)?;
    Ok(Ok(UploadPreparation::Ready(admitted.stage(db, batch)?)))
}

/// Publish a session upload with external bytes. The supplied store must be
/// the embedding book's configured store; store selection is a host input,
/// never a caller-controlled path. No inline size limit is silently relaxed.
pub async fn upload_external_document<V: Vfs + Clone, B: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    store: &BlobStore<B>,
    request: UploadRequest,
) -> Outcome<DocumentAdded> {
    match prepare_external_upload(db, cx, book, capability, store, request).await? {
        Err(refusal) => Ok(Err(refusal)),
        Ok(UploadPreparation::AlreadyRecorded(added)) => Ok(Ok(added)),
        Ok(UploadPreparation::Ready(prepared)) => prepared.commit(db, cx).await,
    }
}

/// Route a session upload by the registered inline bound, without changing
/// its authorization, provenance, identity or receipt semantics.
pub async fn upload_document_in_store<V: Vfs + Clone, B: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    store: &BlobStore<B>,
    request: UploadRequest,
) -> Outcome<DocumentAdded> {
    let policy =
        EvidencePolicy::embedded().map_err(|error| KernelError::Corrupt(error.to_string()))?;
    let size = u64::try_from(request.bytes.len())
        .map_err(|_| KernelError::Corrupt("document size exceeds u64".into()))?;
    if size <= crate::evidence::inline_document_bound(&policy) {
        super::upload_document(db, cx, book, capability, request).await
    } else {
        upload_external_document(db, cx, book, capability, store, request).await
    }
}
