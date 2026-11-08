//! Exact native identities for supplemental monetary-entry targets. This is
//! independent of the producer's model and never trusts the claimed VID.

use crate::codec::Reader;
use crate::envelope::{MAX_ENVELOPE_LIST, proposal_after_legs, skip_erasable, skip_origin};
use crate::evidence::{EvidenceError, visit_citations};
use crate::proof::production::derivation::LeafRecord;

use super::super::EvidenceProductionError;
use super::super::prefix::framed_proposal;

fn framed_identity(domain: &[u8], parts: &[&[u8]]) -> u128 {
    let mut raw = Vec::new();
    for part in parts {
        raw.extend_from_slice(&(part.len() as u32).to_le_bytes());
        raw.extend_from_slice(part);
    }
    low_identity(crate::blake3::hash_parts(domain, &[&raw]))
}

fn low_identity(digest: [u8; 32]) -> u128 {
    let mut low = [0; 16];
    low.copy_from_slice(&digest[..16]);
    u128::from_le_bytes(low)
}

fn target_identity(domain: &[u8], target: u128) -> u128 {
    low_identity(crate::blake3::hash_parts(domain, &[&target.to_le_bytes()]))
}

pub(super) fn entry_identity(
    record: &LeafRecord<'_>,
    leaf_index: u64,
) -> Result<u128, EvidenceProductionError> {
    let at_leaf = |error| EvidenceProductionError::Evidence { leaf_index, error };
    let proposal = framed_proposal(record.payload, record.split).map_err(at_leaf)?;
    let mut header = Reader::new(proposal);
    header
        .u16("entry.major")
        .map_err(EvidenceError::from)
        .map_err(at_leaf)?;
    let minor = header
        .u16("entry.minor")
        .map_err(EvidenceError::from)
        .map_err(at_leaf)?;
    let class = record.envelope.class;
    // Replacement has both historical key-derived and modern target-derived
    // identities with no distinguishing immutable marker. Control identities
    // are separately registered and must not fall through to the posting law.
    // Minors 9/10 add application/FX terms (extensions 41/42) without changing
    // entry identities. Posting semantics remain outside this citation proof;
    // future minors still refuse rather than assume their identity rules.
    if minor > 10 || !(1..=15).contains(&class) || class == 5 {
        return Err(EvidenceProductionError::UnsupportedTargetIdentity { leaf_index, class });
    }
    // Complete frame and citation checks apply to referenced targets even if
    // the recipient excludes them. A target's framing is not an accounting-law
    // replay. Full-prefix authentication has already checked both entry hashes.
    visit_citations(proposal, |citation| {
        if citation.document_oid
            != crate::evidence::document_oid(&record.envelope.book_id, &citation.doc_commit)
        {
            return Err(EvidenceError::DocumentIdentity);
        }
        Ok(())
    })
    .map_err(at_leaf)?;
    read_identity(proposal, minor, class, &record.envelope.book_id).map_err(at_leaf)
}

fn read_identity(
    proposal: &[u8],
    minor: u16,
    class: u16,
    book: &[u8; 16],
) -> Result<u128, EvidenceError> {
    let invalid = EvidenceError::Request;
    let mut r = proposal_after_legs(proposal)?;
    if r.present("entry.control")? {
        return Err(invalid(
            "monetary supplement target contains a control payload",
        ));
    }
    let n = r.count(MAX_ENVELOPE_LIST, 36, "entry.unit_totals")?;
    for _ in 0..n {
        r.fixed::<36>("unit_total")?;
    }
    if r.present("entry.base_totals")? {
        r.fixed::<68>("base_totals")?;
        let n = r.count(64, 32, "base_totals.rates")?;
        for _ in 0..n {
            r.fixed::<32>("rate")?;
        }
        if r.present("base_totals.residual")? {
            r.fixed::<22>("residual")?;
        }
    }
    let key = r.bytes(64, "entry.idempotency_key")?;
    if key.is_empty() {
        return Err(invalid(
            "supplement target identity requires a nonempty key",
        ));
    }
    let mut origin_reader = Reader::new(&proposal[proposal.len() - r.remaining()..]);
    let origin = origin_reader.u8("origin.tag")?;
    let migration = if origin == 2 {
        Some(origin_reader.u128("origin.run")?)
    } else {
        None
    };
    let schedule = if origin == 5 {
        Some((
            origin_reader.u128("origin.schedule")?,
            origin_reader.u8("origin.trigger")?,
            origin_reader.u128("origin.trigger_ref")?,
        ))
    } else {
        None
    };
    skip_origin(&mut r)?;
    let principal = r.u128("entry.principal")?;
    if r.present("entry.session")? {
        r.u128("entry.session")?;
    }
    let n = r.count(1024, 65, "entry.evidence")?;
    for _ in 0..n {
        r.fixed::<65>("entry.citation")?;
    }
    let n = r.count(1024, 51, "entry.supersession")?;
    let mut reversal = None;
    for _ in 0..n {
        let target = r.u128("supersession.target")?;
        r.fixed::<32>("supersession.digest")?;
        let kind = r.u8("supersession.kind")?;
        r.u16("supersession.reason")?;
        if class == 4 && n == 1 && kind == 1 {
            reversal = Some(target);
        }
    }
    let mut resolution = None;
    if r.present("entry.pending")? {
        if r.present("pending.timeout")? {
            r.u64("pending.timeout")?;
        }
        if r.present("pending.resolution")? {
            resolution = Some(r.u128("pending.target")?);
            r.fixed::<32>("pending.digest")?;
        }
        if r.present("pending.disposition")? {
            match r.u8("pending.disposition")? {
                1 => {}
                2 => {
                    r.u64("pending.expiry")?;
                }
                3 => {
                    let n = r.count(MAX_ENVELOPE_LIST, 2, "pending.posted_ordinals")?;
                    for _ in 0..n {
                        r.u16("pending.ordinal")?;
                    }
                }
                _ => return Err(invalid("unsupported pending disposition")),
            }
        }
    }
    for (field, bound) in [("entry.external_ids", 256), ("entry.tags", 32)] {
        let n = r.count(bound, 65, field)?;
        for _ in 0..n {
            r.bytes(64, "entry.key")?;
            skip_erasable(&mut r, "entry.value")?;
        }
    }
    let mut recurring = None;
    if minor >= 1 {
        let n = r.count(64, 6, "entry.extensions")?;
        for _ in 0..n {
            let tag = r.u16("extension.tag")?;
            let bytes = r.bytes(64 * 1024, "extension.body")?;
            if tag == 31 {
                let mut marker = Reader::new(bytes);
                if marker.u16("recurring.version")? != 1 {
                    return Err(invalid("unsupported recurring occurrence version"));
                }
                let source = marker.u128("recurring.schedule")?;
                let index = marker.u64("recurring.index")?;
                let tick = marker.u128("recurring.tick")?;
                marker.finish("recurring occurrence")?;
                if class != 1 || schedule != Some((source, 0, tick)) {
                    return Err(invalid("recurring identity marker differs from its origin"));
                }
                recurring = Some(framed_identity(
                    b"fa:vid:recurring:v1",
                    &[&source.to_le_bytes(), &index.to_le_bytes()],
                ));
            }
        }
    }
    r.finish("supplement target identity")?;
    if (class == 12) != migration.is_some() {
        return Err(invalid("migration target class and origin disagree"));
    }
    if let Some(recurring) = recurring {
        return Ok(recurring);
    }
    match class {
        4 => reversal
            .map(|target| target_identity(b"fa:vid:reversal:v1", target))
            .ok_or_else(|| invalid("reversal target requires exactly one Reverses reference")),
        3 => resolution
            .map(|target| target_identity(b"fa:vid:resolution:v1", target))
            .ok_or_else(|| invalid("resolution target requires its pending reference")),
        12 => Ok(framed_identity(
            b"fa:vid:migration-entry:v1",
            &[
                book,
                &migration
                    .ok_or_else(|| invalid("missing migration run"))?
                    .to_le_bytes(),
                key,
            ],
        )),
        _ if matches!(origin, 0 | 1) => Ok(framed_identity(
            b"fa:vid:entry:v1",
            &[book, &principal.to_le_bytes(), key],
        )),
        _ => Err(invalid(
            "supplement target origin has no supported identity derivation",
        )),
    }
}
