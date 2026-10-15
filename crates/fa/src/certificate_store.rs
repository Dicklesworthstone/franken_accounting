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

use asupersync::fs::Vfs;
use fa_journal::genesis::BookContext;
use fa_journal::refusal::{KernelError, Refusal, exit};
use fa_journal::rows::{prop, scalar_bytes};
use fa_model::symbols::{label, property, relation};
use fa_model::{Id128, domain_digest};
use fgdb::{Database, VertexRow, WriteBatch, WriteError, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, QueryCx, VId};

use crate::certificate::{MAX_CERTIFICATE_BYTES, ReportCertificate};
use crate::{BookError, Outcome};

mod chunks;

/// A successful storage acknowledgment. An exact retry returns the original
/// creating sequence; it does not assert that the report has just replayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedCertificate {
    pub digest: [u8; 32],
    pub recorded_at: CommitSeq,
}

/// The report-certificate locator is scoped to its book and public digest.
/// The complete digest remains mandatory when reading the located vertex.
pub(crate) fn certificate_vid(book_id: Id128, digest: &[u8; 32]) -> VId {
    let hash = domain_digest(b"fa:vid:report-certificate:v1", &[&book_id.0, digest]);
    let mut low = [0_u8; 16];
    low.copy_from_slice(&hash[..16]);
    VId(u128::from_le_bytes(low))
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §13.6 / FA-INV-02 / FA-INV-11 (retained certificate bytes, identity and book binding are immutable)",
        "use the complete public certificate digest in its original book; preserve any corrupt or retired record and its exported bytes instead of replacing it",
    )
}

fn canonical(certificate: &ReportCertificate) -> Result<Vec<u8>, Refusal> {
    if certificate.output.len() > MAX_CERTIFICATE_BYTES {
        return Err(invalid("report certificate exceeds the 64 MiB format limit"));
    }
    let bytes = certificate
        .canonical_bytes()
        .map_err(|error| invalid(format!("cannot encode report certificate: {error}")))?;
    if bytes.len() > MAX_CERTIFICATE_BYTES {
        return Err(invalid("report certificate exceeds the 64 MiB format limit"));
    }
    // Public fields can be hand-constructed. Decode independently verifies the
    // format, complete native closure and full content digest before storage.
    ReportCertificate::decode(&bytes)?;
    Ok(bytes)
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
        return Err(invalid("the retained certificate's full digest differs from its locator"));
    }
    if !matches!(prop(row, property::BOOK_ID), Some(CanonicalScalar::Bytes(value)) if value.as_slice() == book.book_id.0)
    {
        return Err(invalid("the retained certificate's book mirror names a different book"));
    }
    let Some(CanonicalScalar::Bytes(payload)) = prop(row, property::FA_PAYLOAD) else {
        return Err(invalid("the retained certificate has no canonical byte payload"));
    };
    Ok(payload.as_slice())
}

fn verified_bytes(
    bytes: &[u8],
    book: &BookContext,
    digest: &[u8; 32],
    recorded_at: CommitSeq,
) -> Result<ReportCertificate, Refusal> {
    let certificate = ReportCertificate::decode(bytes)?;
    if certificate.digest != *digest || certificate.book_id != book.book_id {
        return Err(invalid("the retained certificate payload does not match its full digest and book"));
    }
    if recorded_at <= certificate.known_at {
        return Err(invalid("a retained certificate must be recorded after the report's fixed known-at sequence"));
    }
    let encoded = certificate.canonical_bytes()
        .map_err(|error| invalid(format!("cannot encode retained certificate: {error}")))?;
    if encoded != bytes {
        return Err(invalid("the retained certificate payload is not its canonical encoding"));
    }
    Ok(certificate)
}

/// Native created_at is a version start, not a birth timestamp. Checking the
/// preceding snapshot detects even an exact restoration following a rewrite.
fn original_record<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    row: &VertexRow,
) -> Outcome<()> {
    cx.checkpoint().map_err(BookError::Context)?;
    let Some(before_creation) = row.created_at.0.checked_sub(1) else {
        return Ok(Err(invalid("a retained certificate cannot have creating sequence zero")));
    };
    if db.vertex_at(row.vid, CommitSeq(before_creation)).map_err(KernelError::from)?.is_some() {
        return Ok(Err(invalid(format!(
            "retained certificate {:032x} existed before its current version at sequence {}; its immutable record was rewritten or rebound",
            row.vid.0, row.created_at.0
        ))));
    }
    let Some(original) = db.vertex_at(row.vid, row.created_at).map_err(KernelError::from)? else {
        return Ok(Err(invalid("the retained certificate's creating record is unavailable")));
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

fn unchanged_row<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    digest: &[u8; 32],
    row: &VertexRow,
    at: CommitSeq,
) -> Outcome<ReportCertificate> {
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
        Ok(None) => Ok(verified_bytes(payload, book, digest, row.created_at)),
        Err(refusal) => Ok(Err(refusal)),
    }
}

/// Read the exact retained artifact at one snapshot, independently of whether
/// its historical report currently replays. Storage never returns partial data.
pub(crate) fn read<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    digest: &[u8; 32],
) -> Outcome<ReportCertificate> {
    cx.checkpoint().map_err(BookError::Context)?;
    let at = db.frontier().map_err(KernelError::from)?;
    let vid = certificate_vid(book.book_id, digest);
    let Some(row) = db.vertex_at(vid, at).map_err(KernelError::from)? else {
        return Ok(Err(invalid(format!(
            "report certificate {:032x} is not retained in this book or its record was retired",
            vid.0
        ))));
    };
    unchanged_row(db, cx, book, digest, &row, at)
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
        (property::FA_PAYLOAD, scalar_bytes("certificate payload", payload)?),
        (property::FA_DIGEST, scalar_bytes("certificate digest", digest.to_vec())?),
        (property::BOOK_ID, scalar_bytes("certificate book", book.book_id.0.to_vec())?),
    ];
    properties.sort_by_key(|(key, _)| key.0);
    batch.create_vertex(vid, vec![label::CERTIFICATE], properties);
    Ok(())
}

/// First retention replays the report, then publishes one root plus any
/// required fragments in one native transaction. No partial/chunk commits or
/// second storage backend. Exact retries inspect the original complete artifact
/// and acknowledge its original sequence without writes or a fresh replay.
pub(crate) async fn retain<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    certificate: &ReportCertificate,
) -> Outcome<RetainedCertificate> {
    let query_cx = cx.query();
    query_cx.checkpoint().map_err(BookError::Context)?;
    if certificate.book_id != book.book_id {
        return Ok(Err(invalid("the certificate belongs to a different book")));
    }
    let payload = match canonical(certificate) {
        Ok(payload) => payload,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let vid = certificate_vid(book.book_id, &certificate.digest);
    let txn_cx = cx.txn();
    let mut txn = db.begin(&txn_cx).map_err(KernelError::from)?;
    if let Some(row) = txn.vertex(db, vid).map_err(KernelError::from)? {
        let stored = unchanged_row(db, &query_cx, book, &certificate.digest, &row, txn.basis());
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
            return Ok(Err(invalid("the retained certificate locator contains different canonical bytes")));
        }
        return Ok(Ok(RetainedCertificate { digest: certificate.digest, recorded_at: row.created_at }));
    }
    if let Err(refusal) = crate::certificate::replay_report(db, &query_cx, book, certificate)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    query_cx.checkpoint().map_err(BookError::Context)?;
    let batch = match chunks::stage(&query_cx, book, &certificate.digest, vid, payload)? {
        Ok(batch) => batch,
        Err(refusal) => {
            txn.abort();
            return Ok(Err(refusal));
        }
    };
    if let Err(error) = txn.write(db, batch) {
        txn.abort();
        return refused_write(error);
    }
    cx.commit().checkpoint().map_err(BookError::Context)?;
    match txn.commit(db, &cx.commit()).await {
        Ok(recorded_at) => Ok(Ok(RetainedCertificate { digest: certificate.digest, recorded_at })),
        Err(error) => refused_write(error),
    }
}

#[cfg(test)]
mod tests;
