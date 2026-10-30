//! The authenticated source closure for portable functional reports.
//!
//! The facade replays its original native certificate before calling these
//! helpers. The independent verifier reproduces the valuation and report;
//! these checks prevent exporting an incomplete or unsupported closure.

use std::collections::BTreeMap;

use fa_journal::custody::CustodyBody;
use fa_journal::evidence::Document;
use fa_journal::genesis::BookSpec;
use fa_journal::refusal::Outcome;
use fa_journal::{FxLawId, FxRateDocument};
use fa_model::{EntryOrigin, Oid, Reader};
use fgdb_types::{CommitSeq, VId};

use crate::{Journal, Record};

use super::refused;

pub const MAX_FUNCTIONAL_RATES: usize = 4096;
pub const MAX_FUNCTIONAL_RATE_BYTES: usize = 4096;
pub const MAX_FUNCTIONAL_BOOK_BYTES: usize = 1024 * 1024;

type RateClaims = BTreeMap<Oid, ([u8; 32], VId)>;

/// Every retained valuation is checked, including entries outside the selected
/// effective period and reversal ancestors. Import receipts must be present in
/// the signed prefix before their first use. An entries-only legacy prefix
/// cannot authenticate this closure and is refused.
fn claims(journal: &Journal, known_at: CommitSeq) -> Outcome<RateClaims> {
    if journal.branch_id != fa_model::Id128::TRUNK || known_at > journal.through_seq {
        return Ok(Err(refused(
            "functional report requires a complete trunk checkpoint prefix",
        )));
    }
    let mut needed: BTreeMap<Oid, ([u8; 32], CommitSeq)> = BTreeMap::new();
    let mut receipts = BTreeMap::new();
    for leaf in &journal.leaves {
        if leaf.envelope.commit_seq > known_at {
            continue;
        }
        let Some(record) = leaf.authenticated_record()? else {
            return Ok(Err(refused(
                "functional source record does not match its checkpoint",
            )));
        };
        match record {
            Record::Entry(entry) => {
                let proposal = &entry.proposal;
                if let Some((_, raw)) = proposal
                    .extensions
                    .iter()
                    .find(|(tag, _)| *tag == fa_model::entry::FX_REVALUATION_EXTENSION)
                {
                    let basis = fa_model::FxRevaluationBasis::decode(raw)
                        .map_err(|e| fa_journal::KernelError::Model(e.into()))?;
                    if basis.item_allocation.is_some()
                        || proposal.class != fa_model::EntryClass::REVALUATION
                        || proposal.base_totals.as_ref().is_none_or(|base| {
                            FxLawId::from_oid(&base.fx_law_oid)
                                != Some(FxLawId::PeriodEndRevaluation)
                        })
                    {
                        return Ok(Err(refused(
                            "portable functional revaluation supports only source-bound aggregate PeriodEndRevaluation v1",
                        )));
                    }
                }
                let Some(base) = &proposal.base_totals else {
                    continue;
                };
                if FxLawId::from_oid(&base.fx_law_oid) == Some(FxLawId::PeriodEndRevaluation)
                    && proposal.class != fa_model::EntryClass::REVERSAL
                    && !proposal
                        .extensions
                        .iter()
                        .any(|(tag, _)| *tag == fa_model::entry::FX_REVALUATION_EXTENSION)
                {
                    return Ok(Err(refused(
                        "portable PeriodEndRevaluation requires its retained cumulative source basis",
                    )));
                }
                if matches!(proposal.origin, EntryOrigin::Migration { .. })
                    && FxLawId::from_oid(&base.fx_law_oid) != Some(FxLawId::SpotClose)
                {
                    return Ok(Err(refused(
                        "portable Migration valuations require the registered SpotClose law",
                    )));
                }
                if !matches!(
                    FxLawId::from_oid(&base.fx_law_oid),
                    Some(
                        FxLawId::SpotClose
                            | FxLawId::PeriodEndRevaluation
                            | FxLawId::PeriodAverage
                            | FxLawId::SettlementCarryingBasis
                    )
                ) {
                    return Ok(Err(refused(
                        "portable functional reports support SpotClose, aggregate PeriodEndRevaluation, PeriodAverage, source-bound SettlementCarryingBasis and their exact inherited reversals",
                    )));
                }
                for oid in &base.rate_doc_oids {
                    let mut citations = proposal
                        .evidence
                        .iter()
                        .filter(|evidence| evidence.document_oid == *oid && evidence.role == 3);
                    let Some(citation) = citations.next() else {
                        return Ok(Err(refused(
                            "a functional rate has no original role-3 citation",
                        )));
                    };
                    if citations.next().is_some() {
                        return Ok(Err(refused("a functional rate has ambiguous commitments")));
                    }
                    if let Some((commitment, first_use)) = needed.get_mut(oid) {
                        if *commitment != citation.doc_commit {
                            return Ok(Err(refused(
                                "a functional rate changes its original commitment",
                            )));
                        }
                        *first_use = (*first_use).min(leaf.envelope.commit_seq);
                    } else {
                        needed.insert(*oid, (citation.doc_commit, leaf.envelope.commit_seq));
                    }
                    if needed.len() > MAX_FUNCTIONAL_RATES {
                        return Ok(Err(refused(
                            "functional rate closure exceeds 4096 documents",
                        )));
                    }
                }
            }
            Record::Custody(event) => {
                if let CustodyBody::Receipt {
                    digest_at_receipt,
                    received_by,
                    ..
                } = event.body
                    && (event.book_id != journal.book_id
                        || event.index != 0
                        || event.prev_digest != [0; 32]
                        || receipts
                            .insert(
                                event.document_oid,
                                (digest_at_receipt, leaf.envelope.commit_seq, received_by),
                            )
                            .is_some())
                {
                    return Ok(Err(refused(
                        "functional source contains an invalid import receipt",
                    )));
                }
            }
            _ => {}
        }
    }
    let mut authenticated = BTreeMap::new();
    for (oid, (commitment, first_use)) in needed {
        let Some((imported, at, received_by)) = receipts.get(&oid) else {
            return Ok(Err(refused(
                "a functional rate lacks an authenticated import receipt at or before its first use",
            )));
        };
        if *imported != commitment || *at > first_use {
            return Ok(Err(refused(
                "a functional rate lacks an authenticated import receipt at or before its first use",
            )));
        }
        authenticated.insert(oid, (commitment, *received_by));
    }
    Ok(Ok(authenticated))
}

/// Return the exact sorted Rate OID closure without reading any Rate body.
/// The caller must authorize and govern each document read before assembly.
pub fn rate_oids(journal: &Journal, known_at: CommitSeq) -> Outcome<Vec<Oid>> {
    Ok(claims(journal, known_at)?.map(|claims| claims.into_keys().collect()))
}

/// Bounded format routing; neither this check nor the carried BookSpec claims
/// to authenticate genesis outside the checkpoint's journal. The recipient's
/// expected certificate and the signed bundle bind the declared book basis.
pub(super) fn certificate(certificate: &[u8], journal: &Journal, known_at: CommitSeq) -> bool {
    let check = || -> Result<bool, fa_model::DecodeError> {
        let mut reader = Reader::new(certificate);
        let (output, selector) = if certificate.starts_with(b"fa:report-certificate:v10") {
            reader.fixed::<{ b"fa:report-certificate:v10".len() }>("functional certificate")?;
            ("fa:functional-trial-balance:v1", 8)
        } else if certificate.starts_with(b"fa:report-certificate:v5") {
            reader.fixed::<{ b"fa:report-certificate:v5".len() }>("functional certificate")?;
            ("fa:functional-statement:v1", 3)
        } else {
            return Ok(false);
        };
        if reader.str(64, "scope")? != "fa-fold-over-prefix" {
            return Ok(false);
        }
        reader.str(64, "authority")?;
        Ok(reader.str(64, "output")? == output
            && reader.fixed::<16>("book")? == journal.book_id.0
            && reader.fixed::<16>("branch")? == [0; 16]
            && reader.u64("known-at")? == known_at.0
            && reader.u8("selector")? == selector)
    };
    check().unwrap_or(false)
}

pub(super) fn validate(
    journal: &Journal,
    known_at: CommitSeq,
    book_spec: &[u8],
    rates: &[(Oid, Vec<u8>)],
) -> Outcome<()> {
    if book_spec.len() > MAX_FUNCTIONAL_BOOK_BYTES
        || !book_spec.starts_with(&2u16.to_le_bytes())
        || rates.len() > MAX_FUNCTIONAL_RATES
        || rates
            .iter()
            .any(|(_, bytes)| bytes.len() > MAX_FUNCTIONAL_RATE_BYTES)
    {
        return Ok(Err(refused(
            "functional source exceeds its canonical v3 format bounds",
        )));
    }
    let spec = BookSpec::decode(book_spec)?;
    if spec.book_id != journal.book_id || spec.canonical_bytes()? != book_spec {
        return Ok(Err(refused(
            "functional source requires the exact canonical version-2 BookSpec",
        )));
    }
    // An unvalued foreign entry outside the report's selected dates may be
    // harmless to a local fold, but this portable profile validates the entire
    // retained valuation prefix. Refuse it before emitting unverifiable bytes.
    for leaf in &journal.leaves {
        if leaf.envelope.is_entry() && leaf.envelope.commit_seq <= known_at {
            let entry = fa_model::Entry::decode(&leaf.payload)?;
            if entry.proposal.base_totals.is_none()
                && entry
                    .proposal
                    .legs
                    .iter()
                    .any(|leg| leg.amount.unit != spec.base_unit)
            {
                return Ok(Err(refused(
                    "portable functional source contains an unvalued foreign entry",
                )));
            }
        }
    }
    let needed = match claims(journal, known_at)? {
        Ok(needed) => needed,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if rates.iter().map(|(oid, _)| oid).ne(needed.keys()) {
        return Ok(Err(refused(
            "functional source must contain exactly its sorted original Rate documents",
        )));
    }
    for (oid, payload) in rates {
        let document = Document::decode(payload)?;
        let (commitment, received_by) = needed[oid];
        if document.book_id != journal.book_id
            || document.kind != 11
            || document.oid() != *oid
            || document.doc_commit() != commitment
            || document.retrieved_by != received_by
            || document.canonical_bytes()? != *payload
        {
            return Ok(Err(refused(
                "functional Rate payload does not reproduce its authenticated commitment",
            )));
        }
        let rate = match FxRateDocument::decode(&document.bytes) {
            Ok(rate) => rate,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if rate.base_unit != spec.base_unit {
            return Ok(Err(refused(
                "functional Rate base unit differs from the book basis",
            )));
        }
    }
    Ok(Ok(()))
}
