//! Immutable, lazily retained report certificates in the book's sole store.
//!
//! A certificate's public content digest is a locator and commitment to its
//! canonical bytes. It is not the substrate's keyed native `ObjectId`. The
//! derived vertex keeps the complete digest and book identity, so truncating
//! the locator to 128 bits never makes a collision an accepted certificate.
//! Retention has its own substrate sequence and creates no journal `Entry`.

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
        return Err(invalid(
            "report certificate exceeds the 64 MiB format limit",
        ));
    }
    let bytes = certificate
        .canonical_bytes()
        .map_err(|error| invalid(format!("cannot encode report certificate: {error}")))?;
    // Public fields can be hand-constructed. Decode independently verifies the
    // format, complete native closure and full content digest before storage.
    ReportCertificate::decode(&bytes)?;
    Ok(bytes)
}

fn decoded_row(
    row: &VertexRow,
    book: &BookContext,
    digest: &[u8; 32],
) -> Result<ReportCertificate, Refusal> {
    if row.vid != certificate_vid(book.book_id, digest)
        || row.labels.as_slice() != [label::CERTIFICATE]
        || row.retired_at.is_some()
        || row.props.len() != 3
    {
        return Err(invalid(format!(
            "vertex {:032x} is not an intact retained report certificate",
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
    let certificate = ReportCertificate::decode(payload.as_slice())?;
    if certificate.digest != *digest || certificate.book_id != book.book_id {
        return Err(invalid(
            "the retained certificate payload does not match its full digest and book",
        ));
    }
    if row.created_at <= certificate.known_at {
        return Err(invalid(
            "a retained certificate must be recorded after the report's fixed known-at sequence",
        ));
    }
    let encoded = certificate
        .canonical_bytes()
        .map_err(|error| invalid(format!("cannot encode retained certificate: {error}")))?;
    if encoded != payload.as_slice() {
        return Err(invalid(
            "the retained certificate payload is not its canonical encoding",
        ));
    }
    Ok(certificate)
}

/// Compare with the creating snapshot as well as validating the current bytes.
/// A raw write cannot turn a colliding or unrelated earlier row into an exact
/// retry merely by replacing its payload and digest with valid new bytes.
fn unchanged_row<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    digest: &[u8; 32],
    row: &VertexRow,
) -> Outcome<ReportCertificate> {
    let certificate = match decoded_row(row, book, digest) {
        Ok(certificate) => certificate,
        Err(refusal) => return Ok(Err(refusal)),
    };
    cx.checkpoint().map_err(BookError::Context)?;
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
    Ok(Ok(certificate))
}

/// Read the exact retained artifact, independently of whether its historical
/// report currently replays. The caller can inspect or export the artifact and
/// invoke report replay separately; corrupted storage never returns an artifact.
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
    unchanged_row(db, cx, book, digest, &row)
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
                fa_journal::code::CONFLICT,
                exit::CONFLICT,
                format!("a concurrent commit changed the certificate storage witness: {detail}"),
                "FG-LAW-FCW-01 (first committer wins over the retained certificate's point witness)",
                "retry retaining the same certificate; an exact stored outcome returns its original sequence",
            )))
        }
        error => Err(KernelError::from(error).into()),
    }
}

/// Persist a replayed certificate once. Existing exact bytes acknowledge the
/// original retention without replaying or issuing another commit. A first
/// retention verifies the report, witnesses the absent locator in the native
/// transaction and creates one immutable Certificate vertex, never an Entry.
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
        let stored = unchanged_row(db, &query_cx, book, &certificate.digest, &row);
        txn.abort();
        let stored = match stored? {
            Ok(stored) => stored,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let same_bytes = matches!(prop(&row, property::FA_PAYLOAD), Some(CanonicalScalar::Bytes(value)) if value.as_slice() == payload);
        if stored != *certificate || !same_bytes {
            return Ok(Err(invalid(
                "the retained certificate locator contains different canonical bytes",
            )));
        }
        return Ok(Ok(RetainedCertificate {
            digest: certificate.digest,
            recorded_at: row.created_at,
        }));
    }
    if let Err(refusal) = crate::certificate::replay_report(db, &query_cx, book, certificate)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    query_cx.checkpoint().map_err(BookError::Context)?;
    let mut properties = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("certificate payload", payload)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("certificate digest", certificate.digest.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("certificate book", book.book_id.0.to_vec())?,
        ),
    ];
    properties.sort_by_key(|(key, _)| key.0);
    let mut batch = WriteBatch::new(relation::DERIVED_FROM);
    batch.create_vertex(vid, vec![label::CERTIFICATE], properties);
    if let Err(error) = txn.write(db, batch) {
        txn.abort();
        return refused_write(error);
    }
    match txn.commit(db, &cx.commit()).await {
        Ok(recorded_at) => Ok(Ok(RetainedCertificate {
            digest: certificate.digest,
            recorded_at,
        })),
        Err(error) => refused_write(error),
    }
}
