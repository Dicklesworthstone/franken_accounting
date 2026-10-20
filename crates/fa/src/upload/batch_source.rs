//! Bounded source acquisition followed by one atomic evidence import.
//!
//! The whole request's authority, count, budgets and metadata are checked
//! before any file is opened. Source bytes are accumulated under one combined
//! payload budget; no destination blob or journal write starts until every
//! source has reached EOF successfully. The existing import kernel then owns
//! atomic publication, exact retries, original custody and conflict handling.

use std::collections::BTreeSet;
use std::path::PathBuf;

use asupersync::fs::{OpenOptions, Vfs};
use fa_journal::{Capability, Document, ImportRecorded, KernelError};
use fa_model::IntakeSource;
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::DateDay;
use fgdb_types::context::PurposeContexts;

use super::source::{
    SourceUploadRequest, check_request, document_limit, input_refusal, read_bounded,
};
use crate::{AsyncBook, BookError, IntakeAction, Outcome};

/// A path in the caller-supplied source VFS, not a destination blob locator.
#[derive(Clone, Debug)]
pub struct SourceDocument {
    pub path: PathBuf,
    pub upload: SourceUploadRequest,
}

/// One atomic run of uploaded evidence. The source is always the capability's
/// holder; a pathname or caller's label cannot claim Connector provenance.
#[derive(Clone, Debug)]
pub struct SourceImportRequest {
    pub idempotency_key: Vec<u8>,
    pub effective_date: DateDay,
    pub description: String,
    pub documents: Vec<SourceDocument>,
    /// Combined source payload limit, also bounded by the registered document
    /// store limit. This does not promise that total process RSS equals the
    /// payload count: buffer capacity and kernel encodings have overhead.
    /// A larger run must be explicitly divided by its caller, never silently.
    pub max_total_bytes: u64,
}

fn check_batch(capability: &Capability, request: &SourceImportRequest) -> Outcome<()> {
    let maximum = document_limit()?;
    let count = request.documents.len();
    if count == 0 || count > fa_model::limits::MAX_IMPORT_DOCUMENTS {
        return Ok(Err(input_refusal(format!(
            "source import needs 1..={} documents, got {count}",
            fa_model::limits::MAX_IMPORT_DOCUMENTS,
        ))));
    }
    if request.max_total_bytes == 0 || request.max_total_bytes > maximum {
        return Ok(Err(input_refusal(format!(
            "combined source payload budget must be 1..={maximum} bytes",
        ))));
    }
    let mut paths = BTreeSet::new();
    for document in &request.documents {
        if document.path.as_os_str().is_empty()
            || !paths.insert((&document.path, document.upload.kind))
        {
            return Ok(Err(input_refusal(
                "source import contains an empty path or repeats a path with the same document kind",
            )));
        }
        if let Err(refused) = check_request(capability, &document.upload)? {
            return Ok(Err(refused));
        }
    }
    Ok(Ok(()))
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Acquire all files under bounded input, then publish exactly one run.
    ///
    /// Unlike an ordinary upload this journals an ImportControl on trunk;
    /// an Agent cannot use it to acquire trunk control authority. Every file
    /// uses the session-derived upload grade. Already-held evidence retains
    /// its original grade and custody, even when this importer is a Human.
    ///
    /// The source VFS/path confinement is supplied by the host. No atomic
    /// snapshot of mutable source files is claimed; the receipt commits the
    /// exact bytes that were read. A read error/overflow/empty document leaves
    /// no import or destination blobs. A later kernel failure may leave
    /// unreferenced durable blobs, but never a partially recorded import.
    pub async fn import_uploads_from_vfs<S: Vfs>(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        source: &S,
        request: SourceImportRequest,
    ) -> Outcome<ImportRecorded> {
        if let Err(refused) = self.preflight_intake(cx, capability, IntakeAction::ImportRun)? {
            return Ok(Err(refused));
        }
        if let Err(refused) = check_batch(capability, &request)? {
            return Ok(Err(refused));
        }
        let policy =
            EvidencePolicy::embedded().map_err(|error| KernelError::Corrupt(error.to_string()))?;
        let grade = fa_journal::upload::upload_grade(&policy, capability.sod_profile())?;
        let book_id = self.context().book_id;
        let SourceImportRequest {
            idempotency_key,
            effective_date,
            description,
            documents: sources,
            max_total_bytes,
        } = request;
        let query = cx.query();
        let documents = match query.with_restriction_async(async {
            let mut remaining = max_total_bytes;
            let mut documents = Vec::new();
            documents.try_reserve_exact(sources.len()).map_err(|error| {
                BookError::Io(PathBuf::from("<source import>"), std::io::Error::other(error))
            })?;
            for document in sources {
                query.checkpoint().map_err(BookError::Context)?;
                if remaining == 0 {
                    return Ok(Err(input_refusal("source import exhausted its combined payload budget before the next document")));
                }
                let mut reader = source.open(&document.path, &OpenOptions::new().read(true))
                    .await.map_err(|error| BookError::Io(document.path.clone(), error))?;
                let bytes = match read_bounded(
                    &query, &mut reader, remaining.min(document.upload.max_bytes), &document.path,
                ).await? {
                    Ok(bytes) => bytes,
                    Err(refused) => return Ok(Err(refused)),
                };
                if bytes.is_empty() {
                    return Ok(Err(input_refusal(format!(
                        "source document {} is empty", document.path.display(),
                    ))));
                }
                let size = u64::try_from(bytes.len())
                    .map_err(|_| KernelError::Corrupt("source byte count exceeds u64".into()))?;
                remaining = remaining.checked_sub(size)
                    .ok_or_else(|| KernelError::Corrupt("source exceeded its admitted batch budget".into()))?;
                documents.push(Document {
                    book_id,
                    kind: document.upload.kind,
                    mime: document.upload.mime,
                    grade,
                    retrieved_by: capability.holder(),
                    bytes,
                });
            }
            Ok::<_, BookError>(Ok(documents))
        }).await? {
            Ok(documents) => documents,
            Err(refused) => return Ok(Err(refused)),
        };
        self.import_run(
            cx,
            capability,
            IntakeSource::Upload {
                principal: capability.holder(),
            },
            &idempotency_key,
            effective_date,
            &description,
            documents,
        )
        .await
    }
}

#[cfg(test)]
mod tests;
