//! Session-bound inline evidence intake for an embedding host (fa-vwf).
//!
//! Transport authentication remains the host's responsibility. Unlike the
//! legacy embedded-owner intake method, this API derives the uploader and
//! provenance grade, checks current authority and revocation, and publishes
//! the document and its custody receipt in one witnessed transaction.

use asupersync::fs::Vfs;
use fa_journal::{Capability, DocumentAdded, UploadRequest};
use fgdb_types::context::PurposeContexts;

use crate::{AsyncBook, Outcome};

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Supply evidence as the session holder, never as a caller-named uploader.
    /// Agent/System bytes remain self-sourced even after a Human re-uploads
    /// the same content. The earlier immutable receipt remains authoritative.
    /// This slice enforces the inline size bound; it does not silently route
    /// a larger upload through the legacy, owner-only external-byte method.
    pub async fn upload_document(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        request: UploadRequest,
    ) -> Outcome<DocumentAdded> {
        let book = self.context().clone();
        Ok(fa_journal::upload_document(&mut self.db, cx, &book, capability, request).await?)
    }
}
