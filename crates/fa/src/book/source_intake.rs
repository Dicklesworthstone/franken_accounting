//! Blocking source intake is an adapter, not a second admission or storage law.

use std::path::Path;

use asupersync::fs::{UnixVfs, Vfs};
use asupersync::io::AsyncRead;
use fa_journal::{Capability, DocumentAdded, ImportRecorded};

use super::{Book, Outcome, Store};
use crate::IntakeAction;
use crate::upload::{SourceImportRequest, SourceUploadRequest};

impl Book {
    /// Check current authority before a host consumes evidence input.
    /// Success is not a reservation: publication repeats the kernel's checks.
    /// This does not require or grant permission to read existing documents.
    pub fn preflight_intake(
        &self,
        capability: &Capability,
        action: IntakeAction,
    ) -> Outcome<()> {
        with_store!(&self.store, core => core.preflight_intake(
            &self.purposes(), capability, action,
        ))
    }

    /// Consume a bounded asynchronous reader on this book's production runtime.
    /// Authority and metadata are checked before the first read. The caller
    /// remains responsible for any opening or authentication already performed.
    pub fn upload_document_from_reader<R: AsyncRead + Unpin>(
        &mut self,
        capability: &Capability,
        reader: &mut R,
        request: SourceUploadRequest,
    ) -> Outcome<DocumentAdded> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(
            core.upload_document_from_reader(&purposes, capability, reader, request)
        ))
    }

    /// Read from the supplied source filesystem only after intake admission.
    /// The source filesystem is independent of the book's destination store;
    /// no host-path fallback or path-confinement claim is introduced here.
    pub fn upload_document_from_vfs<S: Vfs>(
        &mut self,
        capability: &Capability,
        source: &S,
        path: &Path,
        request: SourceUploadRequest,
    ) -> Outcome<DocumentAdded> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(
            core.upload_document_from_vfs(&purposes, capability, source, path, request)
        ))
    }

    /// Read an explicitly supplied local path after checking current authority.
    /// The path is not opened or canonicalized before the async core admits it.
    /// Use the VFS variant when the source namespace must be confined.
    pub fn upload_document_from_path(
        &mut self,
        capability: &Capability,
        path: &Path,
        request: SourceUploadRequest,
    ) -> Outcome<DocumentAdded> {
        self.upload_document_from_vfs(capability, &UnixVfs, path, request)
    }

    /// Acquire a whole bounded source batch and publish one atomic import run.
    /// All inputs must succeed before publication starts. The async kernel owns
    /// provenance, custody, exact retries and mixed inline/external durability.
    /// An Agent's upload permission does not authorize an ImportControl on trunk.
    pub fn import_uploads_from_vfs<S: Vfs>(
        &mut self,
        capability: &Capability,
        source: &S,
        request: SourceImportRequest,
    ) -> Outcome<ImportRecorded> {
        let purposes = self.purposes();
        with_store!(&mut self.store, core => self.runtime.block_on(
            core.import_uploads_from_vfs(&purposes, capability, source, request)
        ))
    }

    /// Import local source paths under explicit per-document and combined limits.
    /// Source identity is always the session holder, not a caller-claimed connector.
    pub fn import_uploads_from_paths(
        &mut self,
        capability: &Capability,
        request: SourceImportRequest,
    ) -> Outcome<ImportRecorded> {
        self.import_uploads_from_vfs(capability, &UnixVfs, request)
    }
}

#[cfg(test)]
mod tests;
