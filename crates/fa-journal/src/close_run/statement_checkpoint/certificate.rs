//! Typed binding of retained statement bytes, without duplicating report folds.
//! The formats are the existing native report and certificate-storage contracts.

use asupersync::fs::Vfs;
use fa_model::symbols::{label, property};
use fa_model::{Id128, Reader, domain_digest, report_certificate_vid};
use fgdb::{Database, VertexRow, WriteTxnError};
use fgdb_crypto::Hasher;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::BookContext;
use crate::issuance::IssuanceRecord;
use crate::refusal::{KernelError, Outcome, Refusal};
use crate::rows::prop;

const MAX_BYTES: usize = 64 * 1024 * 1024;
const CHUNK_BYTES: usize = 12 * 1024;
const MANIFEST: &[u8] = b"fa:certificate-chunks:v1";
const FRAGMENT: &[u8] = b"fa:certificate-fragment:v1";
const CUSTOM_DEFINITION: &[u8] = b"fa:custom-statement-def:v1";

fn malformed(error: impl std::fmt::Display) -> KernelError {
    super::super::corrupt(format!("issued statement certificate: {error}"))
}

fn payload<'a, V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    row: &'a VertexRow,
    digest: &[u8; 32],
    at: CommitSeq,
) -> Result<&'a [u8], KernelError> {
    if row.labels.as_slice() != [label::CERTIFICATE]
        || row.props.len() != 3
        || row.created_at.0 == 0
        || row.created_at > at
        || row.retired_at.is_some_and(|seq| seq <= at)
        || !matches!(prop(row, property::BOOK_ID), Some(CanonicalScalar::Bytes(b)) if b.as_slice() == book.book_id.0)
        || !matches!(prop(row, property::FA_DIGEST), Some(CanonicalScalar::Bytes(b)) if b.as_slice() == digest)
        || db
            .vertex_at(row.vid, CommitSeq(row.created_at.0 - 1))?
            .is_some()
        || db
            .vertex_at(row.vid, row.created_at)?
            .map(|r| r.seen_at(at))
            != Some(row.clone().seen_at(at))
    {
        return Err(malformed(
            "retained storage differs from its immutable birth or identity",
        ));
    }
    match prop(row, property::FA_PAYLOAD) {
        Some(CanonicalScalar::Bytes(bytes)) => Ok(bytes.as_slice()),
        _ => Err(malformed("retained storage has no payload")),
    }
}

pub(super) fn verify_retained<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    issuance: &IssuanceRecord,
    at: CommitSeq,
) -> Outcome<Vec<VId>> {
    let source = &issuance.issuance;
    let root = report_certificate_vid(book.book_id, &source.certificate);
    let Some(row) = db.vertex_at(root, at)? else {
        return Ok(Err(super::unavailable(
            "the issued statement certificate is no longer retained",
        )));
    };
    if row.created_at <= source.certified_at || row.created_at > issuance.recorded_at {
        return Ok(Err(super::unavailable(
            "the issued certificate was not retained before issuance",
        )));
    }
    let stored = payload(db, book, &row, &source.certificate, at)?;
    let mut retained = vec![root];
    let bytes = if stored.starts_with(MANIFEST) {
        let mut r = Reader::new(stored);
        r.fixed::<{ MANIFEST.len() }>("certificate manifest")
            .map_err(malformed)?;
        let size =
            usize::try_from(r.u64("certificate size").map_err(malformed)?).map_err(malformed)?;
        let width = r.u32("certificate chunk size").map_err(malformed)?;
        let count = r.u32("certificate chunk count").map_err(malformed)?;
        r.finish().map_err(malformed)?;
        if !(CHUNK_BYTES + 1..=MAX_BYTES).contains(&size)
            || width as usize != CHUNK_BYTES
            || count as usize != size.div_ceil(CHUNK_BYTES)
        {
            return Err(malformed("invalid bounded fragment manifest"));
        }
        let mut bytes = Vec::with_capacity(size);
        for index in 0..count {
            cx.query()
                .checkpoint()
                .map_err(WriteTxnError::Interrupted)?;
            let hash = domain_digest(
                b"fa:vid:report-certificate-fragment:v1",
                &[&book.book_id.0, &source.certificate, &index.to_le_bytes()],
            );
            let mut low = [0; 16];
            low.copy_from_slice(&hash[..16]);
            let vid = VId(u128::from_le_bytes(low));
            let Some(part) = db.vertex_at(vid, at)? else {
                return Ok(Err(super::unavailable(
                    "an issued statement certificate fragment is missing",
                )));
            };
            if part.created_at != row.created_at {
                return Err(malformed(
                    "certificate fragments were not published atomically",
                ));
            }
            let mut r = Reader::new(payload(db, book, &part, &source.certificate, at)?);
            if r.fixed::<{ FRAGMENT.len() }>("certificate fragment")
                .map_err(malformed)?
                .as_slice()
                != FRAGMENT
                || r.u32("certificate fragment ordinal").map_err(malformed)? != index
            {
                return Err(malformed("certificate fragment identity differs"));
            }
            let part = r
                .bytes(CHUNK_BYTES, "certificate fragment bytes")
                .map_err(malformed)?;
            r.finish().map_err(malformed)?;
            if part.len() != (size - bytes.len()).min(CHUNK_BYTES) {
                return Err(malformed("certificate fragment length differs"));
            }
            bytes.extend_from_slice(part);
            retained.push(vid);
        }
        bytes
    } else if stored.starts_with(b"fa:certificate-external:v1") {
        return Ok(Err(super::unavailable(
            "this issuance uses legacy external-only certificate storage; certify and issue a current native statement",
        )));
    } else {
        stored.to_vec()
    };
    if let Err(refusal) = verify_binding(&bytes, issuance) {
        return Ok(Err(refusal));
    }
    Ok(Ok(retained))
}

/// Hash the complete certificate and check its bounded statement framing.
/// Native input and output frames stay opaque here; their authenticated
/// interpretation and mathematical replay are the facade's responsibility.
fn verify_binding(bytes: &[u8], issuance: &IssuanceRecord) -> Result<(), Refusal> {
    let bad = |error: fa_model::DecodeError| {
        super::unavailable(format!("invalid issued statement binding: {error}"))
    };
    let invalid = || {
        super::unavailable(
            "the retained statement does not match its issued book, period, definition or certified prefix",
        )
    };
    if !(32..=MAX_BYTES).contains(&bytes.len()) {
        return Err(invalid());
    }
    let (format, selector, output, custom): (&[u8], u8, &str, bool) =
        if bytes.starts_with(b"fa:report-certificate:v11") {
            (
                b"fa:report-certificate:v11",
                9,
                "fa:custom-statement-report:v1",
                true,
            )
        } else if bytes.starts_with(b"fa:report-certificate:v12") {
            (
                b"fa:report-certificate:v12",
                10,
                "fa:functional-custom-statement:v1",
                true,
            )
        } else if bytes.starts_with(b"fa:report-certificate:v4") {
            (b"fa:report-certificate:v4", 2, "fa:statement:v1", false)
        } else if bytes.starts_with(b"fa:report-certificate:v5") {
            (
                b"fa:report-certificate:v5",
                3,
                "fa:functional-statement:v1",
                false,
            )
        } else {
            return Err(invalid());
        };
    let source = &issuance.issuance;
    let split = bytes.len() - 32;
    if split < format.len() {
        return Err(invalid());
    }
    let mut hash = Hasher::new();
    hash.update(format);
    hash.update(&bytes[..split]);
    if hash.finalize().0 != source.certificate || bytes[split..] != source.certificate {
        return Err(invalid());
    }
    let mut r = Reader::new(&bytes[format.len()..split]);
    if r.str(64, "statement replay scope").map_err(bad)? != "fa-fold-over-prefix"
        || r.str(64, "statement authority").map_err(bad)? != "embedded-owner"
        || r.str(64, "statement output").map_err(bad)? != output
        || r.fixed::<16>("statement book").map_err(bad)? != source.book_id.0
        || r.fixed::<16>("statement branch").map_err(bad)? != Id128::TRUNK.0
        || r.u64("statement prefix").map_err(bad)? != source.certified_at.0
        || r.u8("statement selector").map_err(bad)? != selector
    {
        return Err(invalid());
    }
    let definition = r.bytes(64 * 1024, "statement definition").map_err(bad)?;
    let mut d = Reader::new(definition);
    let domain = if custom {
        if d.fixed::<{ CUSTOM_DEFINITION.len() }>("custom definition")
            .map_err(bad)?
            .as_slice()
            != CUSTOM_DEFINITION
        {
            return Err(invalid());
        }
        r.u128("statement activation").map_err(bad)?;
        let activated = r.u64("statement activation prefix").map_err(bad)?;
        if activated == 0 || activated > source.certified_at.0 {
            return Err(invalid());
        }
        CUSTOM_DEFINITION
    } else {
        if d.fixed::<17>("statement definition").map_err(bad)? != *b"FA-STATEMENT-DEF\0"
            || d.u16("definition major").map_err(bad)? != 1
            || d.u16("definition minor").map_err(bad)? != 0
        {
            return Err(invalid());
        }
        b"fa:statement-definition:v1"
    };
    let name = d.str(64, "definition name").map_err(bad)?;
    d.str(256, "definition title").map_err(bad)?;
    if name != source.definition_name
        || d.u32("definition version").map_err(bad)? != source.definition_version
        || domain_digest(domain, &[definition]) != source.definition_digest
    {
        return Err(invalid());
    }
    let count = r.count(65_536, "statement primary periods").map_err(bad)?;
    let mut selected = false;
    let mut previous = "";
    for _ in 0..count {
        let period = r.str(128, "statement primary period").map_err(bad)?;
        if period.is_empty() || period <= previous {
            return Err(invalid());
        }
        selected |= period == source.period;
        previous = period;
    }
    if !selected {
        return Err(invalid());
    }
    let count = r
        .count(65_536, "statement comparative periods")
        .map_err(bad)?;
    let mut previous = "";
    for _ in 0..count {
        let period = r.str(128, "statement comparative period").map_err(bad)?;
        if period.is_empty() || period <= previous {
            return Err(invalid());
        }
        previous = period;
    }
    if custom {
        r.opt("statement presentation", |r| {
            r.bytes(1024, "presentation spec")
        })
        .map_err(bad)?;
    }
    r.fixed::<32>("statement registry closure").map_err(bad)?;
    r.fixed::<32>("statement journal root").map_err(bad)?;
    r.u64("statement journal leaves").map_err(bad)?;
    let required_inputs =
        7 + usize::from(selector == 3 || selector == 10) + 5 * usize::from(custom);
    let count = r
        .count(required_inputs + 4, "statement native inputs")
        .map_err(bad)?;
    if count < required_inputs {
        return Err(invalid());
    }
    for _ in 0..count {
        if r.bytes(1024 * 1024, "statement native certificate")
            .map_err(bad)?
            .is_empty()
        {
            return Err(invalid());
        }
    }
    let output = r.bytes(MAX_BYTES, "statement output bytes").map_err(bad)?;
    let mut hash = Hasher::new();
    hash.update(b"fa:report-output:v1");
    hash.update(output);
    if r.fixed::<32>("statement output digest").map_err(bad)? != hash.finalize().0 {
        return Err(invalid());
    }
    if let Some(time) = r
        .opt("statement TimeEvidence", read_time_selection)
        .map_err(bad)?
        && (!time.is_canonical() || time.resolution.resolved_seq != source.certified_at.0)
    {
        return Err(invalid());
    }
    r.finish().map_err(bad)?;
    Ok(())
}

fn read_observation(r: &mut Reader<'_>) -> Result<fa_time::TimeObservation, fa_model::DecodeError> {
    Ok(fa_time::TimeObservation {
        recorded_at: r.u64("tick sequence")?,
        observed_utc_ns: r.u64("tick observed UTC nanoseconds")?,
        source: r.u8("tick source")?,
        monotonic_ok: r.bool("tick monotonic corroboration")?,
    })
}

fn read_time_selection(
    r: &mut Reader<'_>,
) -> Result<crate::InstantSelection, fa_model::DecodeError> {
    Ok(crate::InstantSelection {
        resolution: fa_time::InstantResolution {
            requested_utc_ns: r.u64("requested UTC nanoseconds")?,
            frontier: r.u64("TimeEvidence frontier")?,
            resolved_seq: r.u64("resolved known-at")?,
            lower: read_observation(r)?,
            upper: r.opt("upper tick", read_observation)?,
        },
        lower_entry: VId(r.u128("lower tick entry")?),
        upper_entry: r.opt("upper tick entry", |r| Ok(VId(r.u128("upper tick entry")?)))?,
    })
}
