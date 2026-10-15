//! Mixed inline/external import runs, with one witnessed graph publication.
//!
//! Store selection belongs to the host. Nothing is published by individual
//! upload APIs during an import: all documents, receipts, links and the run
//! control record are staged in the same native transaction.

use asupersync::fs::Vfs;
use fa_policy::Capability;
use fa_registry::evidence_policy::EvidencePolicy;
use fgdb::{Database, WriteTxnError};
use fgdb_types::context::PurposeContexts;

use crate::blob::{BlobStore, locator_of};
use crate::evidence::{inline_document_bound, stage_document};
use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::upload::external::stage_external_document;

use super::prepared::{Admission, admit};
use super::{ImportPreparation, ImportRecorded, ImportRequest};

/// Prepare all documents under one original policy/revocation/identity
/// snapshot. Larger bytes are fenced in the configured store before return;
/// abort/drop leaves no graph effects. Already-held documents are neither
/// rewritten nor assigned a second first-intake receipt.
pub async fn prepare_import_in_store<V: Vfs + Clone, B: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    store: &BlobStore<B>,
    req: ImportRequest,
) -> Outcome<ImportPreparation> {
    let policy =
        EvidencePolicy::embedded().map_err(|error| KernelError::Corrupt(error.to_string()))?;
    let inline_bound = inline_document_bound(&policy);
    let admitted = match admit(
        db,
        cx,
        book,
        capability,
        req,
        Some(store.max_document_bytes().max(inline_bound)),
    )? {
        Err(refused) => return Ok(Err(refused)),
        Ok(Admission::AlreadyRecorded(recorded)) => {
            return Ok(Ok(ImportPreparation::AlreadyRecorded(recorded)));
        }
        Ok(Admission::New(admitted)) => admitted,
    };
    // Encode and validate every graph effect before the first external write.
    // A late malformed document cannot produce a partial import.
    let batches = match admitted.batches_with(cx, |batch, doc| {
        if doc.size <= inline_bound {
            stage_document(batch, &admitted.book, &doc.document, &doc.kind)
        } else {
            stage_external_document(
                batch,
                &doc.document,
                &doc.kind,
                store.id(),
                &locator_of(&doc.doc_commit),
                doc.oid,
                &doc.doc_commit,
            )
        }
    }) {
        Ok(batches) => batches,
        Err(error) => {
            admitted.txn.abort();
            return Err(error);
        }
    };
    let commit = cx.commit();
    for doc in &admitted.documents {
        if let Err(error) = commit.checkpoint() {
            admitted.txn.abort();
            return Err(WriteTxnError::Interrupted(error).into());
        }
        if doc.size <= inline_bound {
            continue;
        }
        let locator = locator_of(&doc.doc_commit);
        if let Err(error) = store.put(&commit, &locator, &doc.document.bytes).await {
            admitted.txn.abort();
            return Ok(Err(Refusal::new(
                code::BLOB_MISSING,
                exit::FOUNDATION,
                format!(
                    "import document {locator}: store {} could not durably write its bytes: {error}",
                    store.id(),
                ),
                "plan §9.1 / §9.3; FA-INV-05 (the entire import is published only after its external bytes are durable)",
                "restore the configured store and retry the complete import under current authority; no document, custody receipt or import run was committed",
            )));
        }
    }
    if let Err(error) = commit.checkpoint() {
        admitted.txn.abort();
        return Err(WriteTxnError::Interrupted(error).into());
    }
    Ok(Ok(ImportPreparation::Ready(admitted.stage(db, batches)?)))
}

/// Atomically record a batch using the same law as inline `import_run`.
/// A failure can leave unreferenced blob bytes, but never some of the run's
/// documents or a run receipt describing documents that did not publish.
pub async fn import_run_in_store<V: Vfs + Clone, B: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    store: &BlobStore<B>,
    req: ImportRequest,
) -> Outcome<ImportRecorded> {
    match prepare_import_in_store(db, cx, book, capability, store, req).await? {
        Err(refused) => Ok(Err(refused)),
        Ok(ImportPreparation::AlreadyRecorded(recorded)) => Ok(Ok(recorded)),
        Ok(ImportPreparation::Ready(prepared)) => prepared.commit(db, cx).await,
    }
}
