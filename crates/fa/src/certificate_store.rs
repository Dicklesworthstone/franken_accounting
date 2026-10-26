//! Immutable, lazily retained report certificates in the book's sole store.
//!
//! Small artifacts retain their original inline representation. Larger ones
//! use a bounded manifest and ordered fragments, all published in the SAME
//! native transaction. This is an artifact encoding over FrankenGraphDB, not
//! another storage engine or a mutable cache. Exported certificate bytes and
//! public read APIs are unchanged. See `report_certificate_storage.toml`.
//!
//! The root's public digest commits to the reassembled canonical certificate.
//! Fragment identities bind book, full certificate digest and ordinal. Every
//! read pins one native snapshot and requires every fragment's original birth
//! to coincide with the root, before validating the full content digest. A
//! missing, rewritten, reordered or substituted fragment never yields a
//! partial certificate. Retention creates no journal Entry.
//!
//! Certificates already published as `fa:certificate-external:v1` records
//! still verify: the read fetches the named blob and checks it against the
//! public digest. New retention does not write that external form. Above the
//! inline row, a new certificate is the manifest plus ordered fragments in
//! one native transaction. [`MAX_INLINE_CERTIFICATE_BYTES`] is that inline
//! threshold, equal to one fragment.

use asupersync::fs::Vfs;
use fa_journal::BlobStore;
use fa_journal::genesis::BookContext;
use fa_journal::refusal::{KernelError, Refusal, exit};
use fa_journal::rows::{prop, scalar_bytes};
use fa_model::symbols::{label, property, relation};
use fa_model::{Id128, Reader, domain_digest};
use fgdb::{Database, VertexRow, WriteBatch, WriteError, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, QueryCx, VId};

use crate::certificate::{MAX_CERTIFICATE_BYTES, ReportCertificate};
use crate::report_artifact::ValidatedArtifact;
use crate::{BookError, Outcome, ReportArtifact, ReportArtifactFamily};

mod chunks;

/// Inline vertex-row threshold. One fragment is the same size, so a
/// historical test can still recognize a certificate that no longer fits
/// inline. New writes above this size use native fragments, not a blob.
pub const MAX_INLINE_CERTIFICATE_BYTES: usize = chunks::CHUNK_BYTES;

/// Vertex payload of a certificate retained in the book's blob store before
/// fragment manifests existed: this tag, the store id (u16) and the byte
/// size (u64). The locator is the certificate digest's lowercase hex.
const EXTERNAL_FORMAT: &[u8; 26] = b"fa:certificate-external:v1";

/// A successful storage acknowledgment. An exact retry returns the original
/// creating sequence; it does not assert that the report has just replayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedCertificate {
    pub digest: [u8; 32],
    pub recorded_at: CommitSeq,
}

/// The report-certificate locator is scoped to its book and public digest
/// (`fa_model::report_certificate_vid`, which the kernel also reads).
pub(crate) use fa_model::report_certificate_vid as certificate_vid;

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §13.6 / FA-INV-02 / FA-INV-11 (retained certificate bytes, identity and book binding are immutable)",
        "use the complete public certificate digest in its original book; preserve any corrupt or retired record and its exported bytes instead of replacing it",
    )
}

/// The certificate's record is intact but its external bytes cannot be
/// produced from the named store. That is a foundation failure rather than
/// a verification verdict, because no certificate bytes were examined.
fn unavailable(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::BLOB_MISSING,
        exit::FOUNDATION,
        message,
        "plan §13.6 / §9.1 (a retained certificate's bytes are produced on request and verified against its public digest); registries/document_stores.toml",
        "restore the blob from the book's backup into its store; the certificate digest names exactly the bytes expected, and nothing substitutes for them",
    )
}

fn canonical(certificate: &ReportArtifact) -> Result<Vec<u8>, Refusal> {
    if certificate.output().len() > MAX_CERTIFICATE_BYTES {
        return Err(invalid(
            "report certificate exceeds the 64 MiB format limit",
        ));
    }
    let bytes = certificate
        .canonical_bytes()
        .map_err(|error| invalid(format!("cannot encode report certificate: {error}")))?;
    if bytes.len() > MAX_CERTIFICATE_BYTES {
        return Err(invalid(
            "report certificate exceeds the 64 MiB format limit",
        ));
    }
    // Public fields can be hand-constructed. Decode independently verifies the
    // format, complete native closure and full content digest before storage.
    ReportArtifact::decode(&bytes)?;
    Ok(bytes)
}

/// The blob locator of an externally retained certificate.
fn locator(digest: &[u8; 32]) -> String {
    fa_journal::blob::locator_of(digest)
}

/// Encode the external record for a certificate of `size` bytes in `store`.
#[cfg(test)]
pub(crate) fn external_record(store: u16, size: u64) -> Result<Vec<u8>, Refusal> {
    let mut w = fa_model::Writer::new();
    w.fixed(EXTERNAL_FORMAT).u16(store).u64(size);
    w.finish().map_err(|error| {
        invalid(format!(
            "cannot encode the external certificate record: {error}"
        ))
    })
}

/// Decode an external record, or `None` when the payload is not one.
pub(crate) fn decode_external(payload: &[u8]) -> Result<Option<(u16, u64)>, Refusal> {
    if !payload.starts_with(EXTERNAL_FORMAT) {
        return Ok(None);
    }
    let mut r = Reader::new(payload);
    let bad = |error| invalid(format!("malformed external certificate record: {error}"));
    r.fixed::<26>("certificate.external.format").map_err(bad)?;
    let store = r.u16("certificate.external.store").map_err(bad)?;
    let size = r.u64("certificate.external.size").map_err(bad)?;
    r.finish().map_err(bad)?;
    if size == 0 || size > MAX_CERTIFICATE_BYTES as u64 {
        return Err(invalid(format!(
            "external certificate record names an impossible size {size}"
        )));
    }
    Ok(Some((store, size)))
}

/// Fetch and verify an externally retained certificate's bytes.
async fn fetched<W: Vfs + Clone>(
    cx: &QueryCx,
    blobs: &BlobStore<W>,
    book: &BookContext,
    digest: &[u8; 32],
    created_at: CommitSeq,
    store: u16,
    size: u64,
) -> Outcome<ReportArtifact> {
    if store != blobs.id() {
        return Ok(Err(unavailable(format!(
            "the retained certificate's bytes are in store {store}, not store {}",
            blobs.id()
        ))));
    }
    let locator = locator(digest);
    let bytes = match blobs.get(cx, &locator, size).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return Ok(Err(unavailable(format!(
                "store {store} holds no blob {locator} for the retained certificate"
            ))));
        }
        Err(error) => {
            return Ok(Err(unavailable(format!(
                "store {store} could not be read for the retained certificate's blob {locator}: {error}"
            ))));
        }
    };
    if bytes.len() as u64 != size {
        return Ok(Err(invalid(format!(
            "the retained certificate's external bytes are {} long, but its record names {size}",
            bytes.len()
        ))));
    }
    Ok(verified_bytes(&bytes, book, digest, created_at))
}

/// Common shape/identity checks for the root and its physical fragments.
/// Fragment vertices use a separate identity domain and tagged payload; they
/// are Certificate storage records, never independently addressable reports.
fn record_payload<'a>(
    row: &'a VertexRow,
    book: &BookContext,
    digest: &[u8; 32],
    expected_vid: VId,
) -> Result<&'a [u8], Refusal> {
    if row.vid != expected_vid
        || row.labels.as_slice() != [label::CERTIFICATE]
        || row.retired_at.is_some()
        || row.props.len() != 3
    {
        return Err(invalid(format!(
            "vertex {:032x} is not an intact retained certificate storage record",
            row.vid.0
        )));
    }
    if !matches!(prop(row, property::FA_DIGEST), Some(CanonicalScalar::Bytes(value)) if value.as_slice() == digest)
    {
        return Err(invalid(
            "the retained certificate's full digest differs from its locator",
        ));
    }
    if !matches!(prop(row, property::BOOK_ID), Some(CanonicalScalar::Bytes(value)) if value.as_slice() == book.book_id.0)
    {
        return Err(invalid(
            "the retained certificate's book mirror names a different book",
        ));
    }
    let Some(CanonicalScalar::Bytes(payload)) = prop(row, property::FA_PAYLOAD) else {
        return Err(invalid(
            "the retained certificate has no canonical byte payload",
        ));
    };
    Ok(payload.as_slice())
}

fn verified_bytes(
    bytes: &[u8],
    book: &BookContext,
    digest: &[u8; 32],
    recorded_at: CommitSeq,
) -> Result<ReportArtifact, Refusal> {
    let certificate = ReportArtifact::decode(bytes)?;
    if certificate.digest() != digest || certificate.book_id() != book.book_id {
        return Err(invalid(
            "the retained certificate payload does not match its full digest and book",
        ));
    }
    if recorded_at <= certificate.known_at() {
        return Err(invalid(
            "a retained certificate must be recorded after the report's fixed known-at sequence",
        ));
    }
    let encoded = certificate
        .canonical_bytes()
        .map_err(|error| invalid(format!("cannot encode retained certificate: {error}")))?;
    if encoded != bytes {
        return Err(invalid(
            "the retained certificate payload is not its canonical encoding",
        ));
    }
    Ok(certificate)
}

/// Native created_at is a version start, not a birth timestamp. Checking the
/// preceding snapshot detects even an exact restoration following a rewrite.
fn original_record<V: Vfs + Clone>(db: &Database<V>, cx: &QueryCx, row: &VertexRow) -> Outcome<()> {
    cx.checkpoint().map_err(BookError::Context)?;
    let Some(before_creation) = row.created_at.0.checked_sub(1) else {
        return Ok(Err(invalid(
            "a retained certificate cannot have creating sequence zero",
        )));
    };
    if db
        .vertex_at(row.vid, CommitSeq(before_creation))
        .map_err(KernelError::from)?
        .is_some()
    {
        return Ok(Err(invalid(format!(
            "retained certificate {:032x} existed before its current version at sequence {}; its immutable record was rewritten or rebound",
            row.vid.0, row.created_at.0
        ))));
    }
    let Some(original) = db
        .vertex_at(row.vid, row.created_at)
        .map_err(KernelError::from)?
    else {
        return Ok(Err(invalid(
            "the retained certificate's creating record is unavailable",
        )));
    };
    if original.vid != row.vid
        || original.created_at != row.created_at
        || original.birth_ordinal != row.birth_ordinal
        || original.labels != row.labels
        || original.props != row.props
    {
        return Ok(Err(invalid(format!(
            "retained certificate {:032x} was rewritten or rebound after its creating sequence {}",
            row.vid.0, row.created_at.0
        ))));
    }
    Ok(Ok(()))
}

async fn unchanged_row<V: Vfs + Clone, W: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    blobs: &BlobStore<W>,
    digest: &[u8; 32],
    row: &VertexRow,
    at: CommitSeq,
) -> Outcome<ReportArtifact> {
    let payload = match record_payload(row, book, digest, certificate_vid(book.book_id, digest)) {
        Ok(payload) => payload,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Err(refusal) = original_record(db, cx, row)? {
        return Ok(Err(refusal));
    }
    match chunks::Manifest::decode(payload) {
        Ok(Some(manifest)) => {
            let bytes = match chunks::read(db, cx, book, digest, row, at, manifest)? {
                Ok(bytes) => bytes,
                Err(refusal) => return Ok(Err(refusal)),
            };
            Ok(verified_bytes(&bytes, book, digest, row.created_at))
        }
        Ok(None) => match decode_external(payload) {
            Ok(Some((store, size))) => {
                fetched(cx, blobs, book, digest, row.created_at, store, size).await
            }
            Ok(None) => Ok(verified_bytes(payload, book, digest, row.created_at)),
            Err(refusal) => Ok(Err(refusal)),
        },
        Err(refusal) => Ok(Err(refusal)),
    }
}

/// Read the exact retained artifact at one snapshot, independently of whether
/// its historical report currently replays. Storage never returns partial data.
pub(crate) async fn read<V: Vfs + Clone, W: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    blobs: &BlobStore<W>,
    digest: &[u8; 32],
) -> Outcome<ReportCertificate> {
    match read_artifact(db, cx, book, blobs, digest).await? {
        Ok(artifact) if artifact.family() == ReportArtifactFamily::Native => {
            Ok(Ok(artifact.source_certificate().clone()))
        }
        Ok(_) => Ok(Err(invalid(
            "the retained artifact is not a native report certificate; use read_report_artifact to preserve its outer selector and output",
        ))),
        Err(refusal) => Ok(Err(refusal)),
    }
}

/// Decode the original family rather than silently returning a nested source.
/// The facade must authorize whole-book reads before entering this storage path.
pub(crate) async fn read_artifact<V: Vfs + Clone, W: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    blobs: &BlobStore<W>,
    digest: &[u8; 32],
) -> Outcome<ReportArtifact> {
    cx.checkpoint().map_err(BookError::Context)?;
    let at = db.frontier().map_err(KernelError::from)?;
    let vid = certificate_vid(book.book_id, digest);
    let Some(row) = db.vertex_at(vid, at).map_err(KernelError::from)? else {
        return Ok(Err(invalid(format!(
            "report certificate {:032x} is not retained in this book or its record was retired",
            vid.0
        ))));
    };
    unchanged_row(db, cx, book, blobs, digest, &row, at).await
}

fn refused_write(error: WriteTxnError) -> Outcome<RetainedCertificate> {
    match error {
        WriteTxnError::Write(WriteError::AlreadyLive { .. } | WriteError::IdentitySpent { .. }) => {
            Ok(Err(invalid(
                "the certificate locator was already used; a retained or retired identity is never overwritten or recreated",
            )))
        }
        WriteTxnError::Write(WriteError::FirstCommitterWins { detail, .. }) => {
            Ok(Err(Refusal::new(
                fa_journal::refusal::code::CONFLICT,
                exit::CONFLICT,
                format!("a concurrent commit changed the certificate storage witness: {detail}"),
                "FG-LAW-FCW-01 (first committer wins over the retained certificate's point witness)",
                "retry retaining the same certificate; an exact stored outcome returns its original sequence",
            )))
        }
        error => Err(KernelError::from(error).into()),
    }
}

fn stage_record(
    batch: &mut WriteBatch,
    book: &BookContext,
    digest: &[u8; 32],
    vid: VId,
    payload: Vec<u8>,
) -> Result<(), KernelError> {
    let mut properties = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("certificate payload", payload)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("certificate digest", digest.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("certificate book", book.book_id.0.to_vec())?,
        ),
    ];
    properties.sort_by_key(|(key, _)| key.0);
    batch.create_vertex(vid, vec![label::CERTIFICATE], properties);
    Ok(())
}

/// First retention replays the report, then publishes one root plus any
/// required fragments in one native transaction. No partial/chunk commits or
/// second storage backend. Exact retries inspect the original complete artifact
/// and acknowledge its original sequence without writes or a fresh replay.
pub(crate) async fn retain<V: Vfs + Clone, W: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    blobs: &BlobStore<W>,
    certificate: &ReportCertificate,
) -> Outcome<RetainedCertificate> {
    if certificate.output.len() > MAX_CERTIFICATE_BYTES {
        return Ok(Err(invalid(
            "report certificate exceeds the 64 MiB format limit",
        )));
    }
    let artifact = match ReportArtifact::try_from(certificate) {
        Ok(artifact) => artifact,
        Err(refusal) => return Ok(Err(refusal)),
    };
    retain_inner(db, cx, book, blobs, &artifact, None).await
}

/// Only the facade's private successful-replay witness can admit other families.
/// It also pins the head at which authority and the complete replay were checked.
pub(crate) async fn retain_validated<V: Vfs + Clone, W: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    blobs: &BlobStore<W>,
    validated: &ValidatedArtifact,
) -> Outcome<RetainedCertificate> {
    retain_inner(db, cx, book, blobs, validated.artifact(), Some(validated)).await
}

async fn retain_inner<V: Vfs + Clone, W: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    blobs: &BlobStore<W>,
    certificate: &ReportArtifact,
    validated: Option<&ValidatedArtifact>,
) -> Outcome<RetainedCertificate> {
    let query_cx = cx.query();
    query_cx.checkpoint().map_err(BookError::Context)?;
    if certificate.book_id() != book.book_id {
        return Ok(Err(invalid("the certificate belongs to a different book")));
    }
    let payload = match canonical(certificate) {
        Ok(payload) => payload,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let digest = certificate.digest();
    let vid = certificate_vid(book.book_id, digest);
    let txn_cx = cx.txn();
    let mut txn = db.begin(&txn_cx).map_err(KernelError::from)?;
    if validated.is_some_and(|v| v.verified_at() != txn.basis()) {
        txn.abort();
        return Ok(Err(Refusal::new(
            fa_journal::refusal::code::CONFLICT,
            exit::CONFLICT,
            "the book changed after artifact replay and authority validation",
            "FA-INV-10 / FA-INV-11 (retention binds the current authorization and replay basis)",
            "retry retention with the same artifact and independently selected expectations",
        )));
    }
    if let Some(row) = txn.vertex(db, vid).map_err(KernelError::from)? {
        let stored = unchanged_row(db, &query_cx, book, blobs, digest, &row, txn.basis()).await;
        txn.abort();
        let stored = match stored? {
            Ok(stored) => stored,
            Err(refusal) => return Ok(Err(refusal)),
        };
        // Both representations were decoded and re-encoded canonically.
        // Compare reconstructed bytes, not the manifest to the exported body.
        let stored_bytes = match canonical(&stored) {
            Ok(bytes) => bytes,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if stored != *certificate || stored_bytes != payload {
            return Ok(Err(invalid(
                "the retained certificate locator contains different canonical bytes",
            )));
        }
        return Ok(Ok(RetainedCertificate {
            digest: *digest,
            recorded_at: row.created_at,
        }));
    }
    if validated.is_none() {
        if certificate.family() != ReportArtifactFamily::Native {
            txn.abort();
            return Ok(Err(invalid(
                "non-native retention requires a full family replay",
            )));
        }
        if let Err(refusal) =
            crate::certificate::replay_report(db, cx, book, certificate.source_certificate())?
        {
            txn.abort();
            return Ok(Err(refusal));
        }
    }
    query_cx.checkpoint().map_err(BookError::Context)?;
    let mut batch = match chunks::stage(&query_cx, book, digest, vid, payload)? {
        Ok(batch) => batch,
        Err(refusal) => {
            txn.abort();
            return Ok(Err(refusal));
        }
    };
    if let Err(refusal) = crate::certificate::registry_epoch::stage(
        db,
        &query_cx,
        book,
        certificate.source_certificate(),
        &mut txn,
        &mut batch,
    )? {
        txn.abort();
        return Ok(Err(refusal));
    }
    if let Err(error) = txn.write(db, batch) {
        txn.abort();
        return refused_write(error);
    }
    cx.commit().checkpoint().map_err(BookError::Context)?;
    match txn.commit(db, &cx.commit()).await {
        Ok(recorded_at) => Ok(Ok(RetainedCertificate {
            digest: *digest,
            recorded_at,
        })),
        Err(error) => refused_write(error),
    }
}

#[cfg(test)]
mod external_record_codec {
    use super::*;

    #[test]
    fn the_external_record_round_trips_and_refuses_what_is_not_one() {
        let record = external_record(1, 17_205).expect("encode");
        assert!(record.len() < 64, "the record is small: {}", record.len());
        assert_eq!(decode_external(&record).expect("decode"), Some((1, 17_205)));
        assert_eq!(
            decode_external(crate::certificate::STATEMENT_CERTIFICATE_FORMAT)
                .expect("not external"),
            None
        );
        assert!(decode_external(&record[..record.len() - 1]).is_err());
        let mut long = record.clone();
        long.push(0);
        assert!(decode_external(&long).is_err());
        assert!(decode_external(&external_record(1, 0).expect("encode")).is_err());
        assert!(
            decode_external(&external_record(1, MAX_CERTIFICATE_BYTES as u64 + 1).expect("encode"))
                .is_err()
        );
    }
}

#[cfg(test)]
pub(crate) mod tests;
