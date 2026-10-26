//! Allocation-specific proposal interpretation, after cryptographic inclusion.

use super::basis::{debit, read_dimensions};
use super::{AllocationBasis, AllocationError, basis_digest, law_digest};
use crate::codec::Reader;
use crate::document::doc_commit;
use crate::envelope::skip_erasable;
use crate::evidence::{EvidenceCitation, MAX_EVIDENCE_PER_ENTRY};
use crate::proof::Checkpoint;

pub(super) fn verify(
    proposal: &[u8],
    checkpoint: &Checkpoint,
    expected_bytes: &[u8],
    basis: &AllocationBasis,
    shares: &[i128],
) -> Result<EvidenceCitation, AllocationError> {
    let mut r = Reader::new(proposal);
    if r.u16("entry.major")? != 1
        || r.u16("entry.minor")? != 1
        || r.fixed::<16>("entry.book")? != checkpoint.book_id
        || r.fixed::<16>("entry.branch")? != checkpoint.branch_id
        || checkpoint.branch_id != [0; 16]
        || r.u16("entry.class")? != 9
    {
        return Err(invalid("expected a minor-1 trunk Allocation entry"));
    }
    r.i32("entry.effective_day")?;
    if r.present("entry.document_day")? {
        r.i32("entry.document_day")?;
    }
    skip_erasable(&mut r, "entry.description")?;
    if r.present("entry.period")? {
        r.bytes(32, "entry.period.calendar")?;
        r.bytes(32, "entry.period.code")?;
    }
    let expected_count = 1 + shares.iter().filter(|share| **share != 0).count();
    if r.count(4096, 47, "entry.legs")? != expected_count {
        return Err(invalid(
            "allocation leg count differs from recomputed nonzero vector",
        ));
    }
    let expected = core::iter::once((basis.source, basis.total, basis.source_debit)).chain(
        basis
            .targets
            .iter()
            .zip(shares)
            .filter(|(_, share)| **share != 0)
            .map(|(target, share)| {
                (
                    target.account,
                    *share,
                    if *share < 0 {
                        basis.source_debit
                    } else {
                        !basis.source_debit
                    },
                )
            }),
    );
    for (ordinal, (account, amount, side)) in expected.enumerate() {
        let actual_side = debit(r.u8("leg.side")?)?;
        let actual_account = r.u128("leg.account")?;
        let unit = r.u32("leg.unit")?;
        let mantissa = r.i128("leg.mantissa")?;
        if actual_side != side
            || actual_account != account
            || unit != basis.unit
            || u128::try_from(mantissa).ok() != Some(amount.unsigned_abs())
        {
            return Err(AllocationError::LegMismatch { ordinal });
        }
        if r.present("leg.base_amount")? {
            return Err(invalid("allocation cannot carry FX valuation"));
        }
        if read_dimensions(&mut r)? != basis.dimensions
            || r.present("leg.memo")?
            || r.u32("leg.settles")? != 0
        {
            return Err(AllocationError::LegMismatch { ordinal });
        }
    }
    if r.present("entry.control")?
        || r.u32("entry.unit_totals")? != 1
        || r.u32("entry.total.unit")? != basis.unit
    {
        return Err(invalid(
            "allocation requires one native total and no control payload",
        ));
    }
    let debits = r.i128("entry.debits")?;
    let credits = r.i128("entry.credits")?;
    let turnover = shares
        .iter()
        .filter(|share| **share > 0)
        .try_fold(0i128, |sum, share| sum.checked_add(*share))
        .ok_or(AllocationError::Arithmetic)?;
    if debits != turnover || credits != turnover || r.present("entry.base_totals")? {
        return Err(invalid(
            "allocation totals do not equal the recomputed native turnover",
        ));
    }
    if r.bytes(64, "entry.idempotency_key")?.is_empty() || r.u8("entry.origin")? != 0 {
        return Err(invalid(
            "allocation requires an Intent origin and a nonempty key",
        ));
    }
    r.fixed::<32>("entry.intent_oid")?;
    r.u16("entry.intent_kind")?;
    r.u128("entry.principal")?;
    if r.present("entry.session")? {
        r.u128("entry.session")?;
    }
    let commitment = doc_commit(21, expected_bytes);
    let expected_citation = EvidenceCitation {
        document_oid: super::super::document_oid(&checkpoint.book_id, &commitment),
        doc_commit: commitment,
        role: 1,
    };
    let mut found = false;
    let mut previous = None;
    let count = r.count(MAX_EVIDENCE_PER_ENTRY, 65, "entry.evidence")?;
    for _ in 0..count {
        let citation = EvidenceCitation {
            document_oid: r.fixed("evidence.oid")?,
            doc_commit: r.fixed("evidence.commitment")?,
            role: r.u8("evidence.role")?,
        };
        if previous.is_some_and(|last| last >= citation) {
            return Err(invalid("entry citations are not strictly ordered"));
        }
        if super::super::document_oid(&checkpoint.book_id, &citation.doc_commit)
            != citation.document_oid
        {
            return Err(invalid(
                "an evidence citation has an invalid book-scoped identity",
            ));
        }
        previous = Some(citation);
        found |= citation == expected_citation;
    }
    if !found {
        return Err(AllocationError::DriverMissing);
    }
    if r.u32("entry.supersession")? != 0 || r.present("entry.pending")? {
        return Err(invalid("an Allocation cannot carry lifecycle effects"));
    }
    let count = r.count(256, 65, "entry.external_ids")?;
    for _ in 0..count {
        r.bytes(64, "entry.external_system")?;
        skip_erasable(&mut r, "entry.external_id")?;
    }
    let count = r.count(32, 65, "entry.tags")?;
    for _ in 0..count {
        r.bytes(64, "entry.tag_key")?;
        skip_erasable(&mut r, "entry.tag_value")?;
    }
    if r.u32("entry.extensions")? != 1 || r.u16("extension.tag")? != 5 {
        return Err(invalid(
            "Allocation requires exactly its computation extension",
        ));
    }
    let record = r.bytes(64 * 1024, "allocation.record")?;
    r.finish("allocation entry")?;
    let mut r = Reader::new(record);
    if r.fixed::<14>("allocation.record.magic")? != *b"FA-ALLOC-POST\0"
        || r.u16("allocation.record.version")? != 1
        || r.bytes(super::MAX_BASIS_BYTES, "allocation.record.basis")? != expected_bytes
        || r.fixed::<32>("allocation.record.law_digest")? != law_digest(basis.law)
        || r.fixed::<32>("allocation.record.basis_digest")? != basis_digest(expected_bytes)
    {
        return Err(AllocationError::BasisMismatch);
    }
    r.finish("allocation computation record")?;
    Ok(expected_citation)
}

fn invalid(why: &'static str) -> AllocationError {
    AllocationError::Invalid(why)
}
