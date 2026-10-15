//! Session-bound evidence intake for an embedding host (fa-vwf).
//!
//! Transport authentication remains the host's responsibility. This API derives
//! the uploader and provenance grade, checks current authority and revocation,
//! and publishes the document and custody receipt in one witnessed transaction.
//! Large documents use the book's configured blob store, with byte durability
//! preceding graph publication. No caller-supplied storage location is accepted.

use asupersync::fs::Vfs;
use fa_journal::{Capability, DocumentAdded, UploadRequest};
use fgdb_types::context::PurposeContexts;

use crate::{AsyncBook, Outcome};

pub mod batch_source;
pub mod source;
pub use batch_source::{SourceDocument, SourceImportRequest};
pub use source::SourceUploadRequest;

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Supply evidence as the session holder, never as a caller-named uploader.
    /// Agent/System bytes remain self-sourced even after a Human re-uploads
    /// the same content. The earlier immutable receipt remains authoritative.
    ///
    /// The registered inline bound selects storage, not authority: larger
    /// documents use this book's private blob store under the same capability
    /// witnesses. Bytes are durable before the document and receipt publish.
    /// A failed or cancelled upload may leave unreferenced bytes, not a
    /// partially committed document. A duplicate neither moves its storage
    /// nor changes its original grade, uploader, receipt or recorded sequence.
    ///
    /// ```no_run
    /// # async fn example(book: &mut fa::AsyncBook<fgdb::MemVfs>,
    /// #     cx: &fgdb_types::context::PurposeContexts,
    /// #     session: &fa::Capability, invoice_bytes: Vec<u8>) -> fa::Outcome<()> {
    /// let evidence = match book.upload_document(cx, session, fa::UploadRequest {
    ///     kind: 1, // Registered Invoice kind.
    ///     mime: "application/pdf".into(),
    ///     bytes: invoice_bytes,
    ///     asserted_grade: None,
    /// }).await? {
    ///     Ok(evidence) => evidence,
    ///     Err(refusal) => return Ok(Err(refusal)),
    /// };
    /// // Cite evidence.oid and evidence.doc_commit in a posting proposal.
    /// # let _ = evidence;
    /// # Ok(Ok(()))
    /// # }
    /// ```
    pub async fn upload_document(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        request: UploadRequest,
    ) -> Outcome<DocumentAdded> {
        self.upload_in_configured_store(cx, capability, request)
            .await
    }
}
