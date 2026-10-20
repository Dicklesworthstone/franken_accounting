//! Bounded evidence intake from a caller-owned asynchronous source.
//!
//! The VFS route checks current session authority before opening the source;
//! the reader route checks it before the first read. Both require EOF within
//! the explicit input budget and delegate publication to the normal upload
//! kernel. An admitted prefix is never substituted for an oversized document.
//! Source path containment and transport authentication belong to the host.

use std::io;
use std::path::Path;

use asupersync::fs::{OpenOptions, Vfs};
use asupersync::io::{AsyncRead, AsyncReadExt};
use fa_journal::refusal::{Refusal, code, exit};
use fa_journal::{Capability, DocumentAdded, KernelError, UploadRequest};
use fa_registry::document_stores::DocumentStores;
use fa_registry::evidence_policy::EvidencePolicy;
use fgdb_types::context::{PurposeContexts, QueryCx};

use crate::{AsyncBook, BookError, IntakeAction, Outcome};

const BUFFER_BYTES: usize = 8192;

/// Metadata and an explicit byte budget for a source that has not been read.
/// `max_bytes` must be nonzero and cannot exceed the registered book store's
/// document limit. It may be smaller; exceeding it is a refusal, not truncation.
#[derive(Clone, Debug)]
pub struct SourceUploadRequest {
    pub kind: u8,
    pub mime: String,
    pub asserted_grade: Option<u8>,
    pub max_bytes: u64,
}

pub(super) fn input_refusal(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::DOCUMENT_INTAKE,
        exit::USAGE,
        message,
        "plan §9.1–§9.3; bounded evidence input; document_stores.toml",
        "supply complete evidence within the admitted input budget; split larger input into explicit separate documents or runs; nothing was published",
    )
}

pub(super) fn document_limit() -> Result<u64, BookError> {
    let stores =
        DocumentStores::embedded().map_err(|error| KernelError::Corrupt(error.to_string()))?;
    stores
        .get(crate::async_book::BOOK_BLOB_STORE)
        .map(|store| store.max_document_bytes)
        .ok_or_else(|| {
            KernelError::Corrupt("the book's document store is not registered".into()).into()
        })
}

/// Validate public metadata before touching a source. Publication repeats the
/// complete evidence law; this check grants no authority or provenance upgrade.
pub(super) fn check_request(capability: &Capability, request: &SourceUploadRequest) -> Outcome<()> {
    let maximum = document_limit()?;
    if request.max_bytes == 0 || request.max_bytes > maximum {
        return Ok(Err(input_refusal(format!(
            "source input budget must be 1..={maximum} bytes, got {}",
            request.max_bytes,
        ))));
    }
    let policy =
        EvidencePolicy::embedded().map_err(|error| KernelError::Corrupt(error.to_string()))?;
    if policy.kind_by_tag(request.kind).is_none()
        || request.mime.is_empty()
        || request.mime.len() > policy.max_mime_bytes
    {
        return Ok(Err(input_refusal(
            "source metadata needs a registered kind and a bounded, nonempty MIME type",
        )));
    }
    let grade = fa_journal::upload::upload_grade(&policy, capability.sod_profile())?;
    if request
        .asserted_grade
        .is_some_and(|asserted| asserted != grade)
    {
        return Ok(Err(Refusal::new(
            code::GRADE_UNVERIFIED,
            exit::REFUSAL,
            "source provenance assertion differs from the session's upload grade",
            "plan §9.3; FA-INV-05; fa-vwf",
            "omit the grade assertion; independent review is an attestation, not an intake relabel",
        )));
    }
    Ok(Ok(()))
}

fn append(bytes: &mut Vec<u8>, chunk: &[u8], limit: usize) -> io::Result<()> {
    let needed = bytes
        .len()
        .checked_add(chunk.len())
        .ok_or_else(|| io::Error::other("source byte count overflow"))?;
    if needed > limit {
        return Err(io::Error::other(
            "source append exceeds its admitted budget",
        ));
    }
    if needed > bytes.capacity() {
        let capacity = bytes.capacity().saturating_mul(2).max(needed).min(limit);
        bytes
            .try_reserve_exact(capacity - bytes.len())
            .map_err(io::Error::other)?;
    }
    bytes.extend_from_slice(chunk);
    Ok(())
}

/// Every iteration is metered, including Interrupted retries. At the exact
/// limit read only a one-byte sentinel without appending or allocating it.
/// No file metadata or caller-provided length controls allocation.
pub(super) async fn read_bounded<R: AsyncRead + Unpin>(
    cx: &QueryCx,
    reader: &mut R,
    limit: u64,
    source: &Path,
) -> Outcome<Vec<u8>> {
    let limit = usize::try_from(limit).map_err(|_| {
        BookError::Kernel(KernelError::Corrupt(
            "source input budget is not addressable on this host".into(),
        ))
    })?;
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; BUFFER_BYTES];
    loop {
        cx.checkpoint().map_err(BookError::Context)?;
        let remaining = limit - bytes.len();
        let available = remaining.min(buffer.len()).max(1);
        let count = match reader.read(&mut buffer[..available]).await {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(BookError::Io(source.to_path_buf(), error)),
        };
        cx.checkpoint().map_err(BookError::Context)?;
        if count == 0 {
            return Ok(Ok(bytes));
        }
        if count > remaining {
            return Ok(Err(input_refusal(format!(
                "source {} exceeds its input budget of {limit} bytes",
                source.display(),
            ))));
        }
        append(&mut bytes, &buffer[..count], limit)
            .map_err(|error| BookError::Io(source.to_path_buf(), error))?;
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Read one complete asynchronous stream, then publish its evidence.
    ///
    /// The reader is untouched on authority/metadata refusal. If the caller
    /// already opened it, that opening remains the caller's responsibility;
    /// use `upload_document_from_vfs` to admit before opening as well. Failed
    /// or cancelled reads consume no journal identity. The actual upload
    /// repeats current authority checks and preserves existing provenance.
    pub async fn upload_document_from_reader<R: AsyncRead + Unpin>(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        reader: &mut R,
        request: SourceUploadRequest,
    ) -> Outcome<DocumentAdded> {
        if let Err(refused) = self.preflight_intake(cx, capability, IntakeAction::Upload)? {
            return Ok(Err(refused));
        }
        if let Err(refused) = check_request(capability, &request)? {
            return Ok(Err(refused));
        }
        let query = cx.query();
        let bytes = match query
            .with_restriction_async(read_bounded(
                &query,
                reader,
                request.max_bytes,
                Path::new("<evidence stream>"),
            ))
            .await?
        {
            Ok(bytes) => bytes,
            Err(refused) => return Ok(Err(refused)),
        };
        self.upload_document(
            cx,
            capability,
            UploadRequest {
                kind: request.kind,
                mime: request.mime,
                asserted_grade: request.asserted_grade,
                bytes,
            },
        )
        .await
    }

    /// Open a source through the host-supplied VFS only after admission.
    ///
    /// No host `std::fs` fallback is used. The source namespace is distinct
    /// from this book's destination blob store. The host must supply an
    /// appropriately confined VFS/path; this API does not claim path sandboxing
    /// or an atomic snapshot of a concurrently modified source file.
    pub async fn upload_document_from_vfs<S: Vfs>(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        source: &S,
        path: &Path,
        request: SourceUploadRequest,
    ) -> Outcome<DocumentAdded> {
        if let Err(refused) = self.preflight_intake(cx, capability, IntakeAction::Upload)? {
            return Ok(Err(refused));
        }
        if let Err(refused) = check_request(capability, &request)? {
            return Ok(Err(refused));
        }
        let query = cx.query();
        let bytes = match query
            .with_restriction_async(async {
                query.checkpoint().map_err(BookError::Context)?;
                let mut reader = source
                    .open(path, &OpenOptions::new().read(true))
                    .await
                    .map_err(|error| BookError::Io(path.to_path_buf(), error))?;
                read_bounded(&query, &mut reader, request.max_bytes, path).await
            })
            .await?
        {
            Ok(bytes) => bytes,
            Err(refused) => return Ok(Err(refused)),
        };
        self.upload_document(
            cx,
            capability,
            UploadRequest {
                kind: request.kind,
                mime: request.mime,
                asserted_grade: request.asserted_grade,
                bytes,
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests;
