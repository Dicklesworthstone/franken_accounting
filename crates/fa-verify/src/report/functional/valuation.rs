//! Rate closure, custody visibility and independent direct/carrying calculations.

mod closing;
mod revaluation;
mod settlement;

use super::super::{ReportError, failed, metadata, registry, text};
use super::{BookParameters, add, framed_hash};
use crate::codec::Reader;
use crate::envelope::{
    KIND_IMPORT_RECEIPT, LeafEnvelope, Leg, LegDetails, MAX_ENVELOPE_LIST, proposal_after_legs,
    proposal_leg_details, skip_control,
};
use std::collections::{BTreeMap, BTreeSet};

pub(in crate::report) const MAX_RATES: usize = 4096;
pub(in crate::report) const MAX_RATE_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
struct BaseTotals {
    unit: u32,
    debits: i128,
    credits: i128,
    law: [u8; 32],
    rates: Vec<[u8; 32]>,
    residual: Option<(u16, u32, i128)>,
}
fn base_totals(proposal: &[u8]) -> Result<Option<BaseTotals>, ReportError> {
    let mut r = proposal_after_legs(proposal)?;
    if r.present("entry.control")? {
        skip_control(&mut r)?;
    }
    let n = r.count(MAX_ENVELOPE_LIST, 36, "entry.unit_totals")?;
    for _ in 0..n {
        r.fixed::<36>("entry.unit_total")?;
    }
    if !r.present("entry.base_totals")? {
        return Ok(None);
    }
    let unit = r.u32("base_totals.unit")?;
    let debits = r.i128("base_totals.debits")?;
    let credits = r.i128("base_totals.credits")?;
    let law = r.fixed("base_totals.law")?;
    let n = r.count(MAX_RATES, 32, "base_totals.rates")?;
    let mut rates = Vec::with_capacity(n);
    for _ in 0..n {
        rates.push(r.fixed("base_totals.rate")?);
    }
    if !rates.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(failed(
            "functional_rates",
            "Rate references must be strictly ordered",
        ));
    }
    let residual = if r.present("base_totals.residual")? {
        Some((
            r.u16("residual.ordinal")?,
            r.u32("residual.unit")?,
            r.i128("residual.amount")?,
        ))
    } else {
        None
    };
    Ok(Some(BaseTotals {
        unit,
        debits,
        credits,
        law,
        rates,
        residual,
    }))
}
pub(super) fn law_oid(id: u16) -> [u8; 32] {
    framed_hash(b"fa:fx-law:v1", &[&id.to_le_bytes(), &1u16.to_le_bytes()])
}
#[derive(Clone, Debug)]
struct Rate {
    commitment: [u8; 32],
    received_by: u128,
    base: u32,
    quote: u32,
    numerator: u128,
    denominator: u128,
    date: i32,
    purpose: u8,
    canonical_mime: bool,
}
fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a
}
fn rate(
    oid: [u8; 32],
    bytes: &[u8],
    book: &[u8; 16],
    base: u32,
    registry: &registry::FunctionalRegistry,
) -> Result<Rate, ReportError> {
    let mut r = Reader::new(bytes);
    if r.u16("document.version")? != 1
        || r.fixed::<16>("document.book")? != *book
        || r.u8("document.kind")? != 11
    {
        return Err(failed(
            "functional_rates",
            "Rate document version, book or kind differs",
        ));
    }
    let canonical_mime =
        text(&mut r, 1024, "document.mime")? == "application/vnd.franken.fx-rate.v1";
    let size = r.u64("document.size")?;
    let commitment = r.fixed("document.commitment")?;
    r.u8("document.grade")?;
    let received_by = r.u128("document.received_by")?;
    if r.u8("document.storage")? != 0 {
        return Err(failed(
            "supported_report",
            "functional Rate documents must be inline",
        ));
    }
    let content = r.bytes(MAX_RATE_BYTES, "document.content")?;
    r.finish("functional Rate document")?;
    if size != content.len() as u64
        || crate::document::doc_commit(11, content) != commitment
        || framed_hash(b"fa:oid:document:v1", &[book, &commitment]) != oid
    {
        return Err(failed(
            "functional_rates",
            "Rate bytes differ from their content address",
        ));
    }
    let mut r = Reader::new(content);
    if r.fixed::<11>("rate.magic")? != *b"FA-FX-RATE\0" || r.u16("rate.version")? != 1 {
        return Err(failed(
            "functional_rates",
            "unsupported canonical Rate version",
        ));
    }
    let rate_base = r.u32("rate.base")?;
    let quote = r.u32("rate.quote")?;
    let numerator = r.u128("rate.numerator")?;
    let denominator = r.u128("rate.denominator")?;
    let rounding = r.u16("rate.rounding")?;
    let date = r.i32("rate.date")?;
    r.u64("rate.retrieved_at")?;
    let purpose = r.u8("rate.purpose")?;
    let source = text(&mut r, 128, "rate.source")?;
    r.finish("Rate terms")?;
    if rate_base != base
        || quote == base
        || !registry.units.get(&quote).is_some_and(|unit| unit.currency)
        || numerator == 0
        || denominator == 0
        || gcd(numerator, denominator) != 1
        || rounding != 3
        || !matches!(purpose, 1..=4)
        || source.trim().is_empty()
    {
        return Err(failed(
            "functional_rates",
            "Rate must use distinct registered currencies, reduced positive terms and supported HalfEven purpose",
        ));
    }
    Ok(Rate {
        commitment,
        received_by,
        base,
        quote,
        numerator,
        denominator,
        date,
        purpose,
        canonical_mime,
    })
}

/// The envelope decoder has already authenticated the complete custody body.
fn receipt(payload: &[u8], len: usize) -> Result<([u8; 32], [u8; 32], u128), ReportError> {
    let mut r = Reader::new(&payload[..len]);
    r.u16("receipt.version")?;
    r.fixed::<16>("receipt.book")?;
    let oid = r.fixed("receipt.document")?;
    r.u32("receipt.index")?;
    r.fixed::<32>("receipt.previous")?;
    r.u8("receipt.body")?;
    match r.u8("receipt.source")? {
        1 => {
            r.u128("receipt.source_principal")?;
        }
        2 => {
            text(&mut r, 256, "receipt.source_name")?;
            text(&mut r, 256, "receipt.source_version")?;
        }
        3 | 4 => {
            text(&mut r, 256, "receipt.source_identifier")?;
        }
        _ => {
            return Err(failed(
                "functional_rate_visibility",
                "unsupported receipt source",
            ));
        }
    }
    let received_by = r.u128("receipt.received_by")?;
    let commitment = r.fixed("receipt.commitment")?;
    Ok((oid, commitment, received_by))
}
struct ParsedEntry {
    details: Vec<LegDetails>,
    base: Option<BaseTotals>,
    entities: Vec<Option<String>>,
    amounts: Vec<i128>,
}
pub(super) struct CheckedEntry {
    pub entities: Vec<Option<String>>,
    pub amounts: Vec<i128>,
}
fn parsed_entry(
    proposal: &[u8],
    legs: &[Leg],
    spec: &BookParameters,
    registry: &registry::FunctionalRegistry,
) -> Result<ParsedEntry, ReportError> {
    let details = proposal_leg_details(proposal)?;
    let base = base_totals(proposal)?;
    if details.len() != legs.len() {
        return Err(failed("functional_valuation", "leg detail count disagrees"));
    }
    if legs.is_empty() {
        if base.is_some() {
            return Err(failed(
                "functional_valuation",
                "empty entry carries an FX claim",
            ));
        }
        return Ok(ParsedEntry {
            details,
            base,
            entities: Vec::new(),
            amounts: Vec::new(),
        });
    }
    let mut entities = Vec::with_capacity(legs.len());
    let mut amounts = Vec::with_capacity(legs.len());
    let mut native: BTreeMap<(Option<String>, u32), (i128, i128)> = BTreeMap::new();
    let mut functional: BTreeMap<Option<String>, (i128, i128)> = BTreeMap::new();
    let mut totals = (0i128, 0i128);
    for (leg, detail) in legs.iter().zip(&details) {
        if leg.mantissa <= 0 || !registry.units.contains_key(&leg.unit) {
            return Err(failed(
                "functional_valuation",
                "native amount must be positive and registered",
            ));
        }
        let entity = spec.entity(&detail.dimensions)?;
        let value = match (&base, detail.base_amount) {
            (None, None) if leg.unit == spec.base => leg.mantissa,
            (Some(_), Some((unit, amount)))
                if unit == spec.base
                    && (amount > 0
                        || amount == 0
                            && base.as_ref().is_some_and(|claim| {
                                [law_oid(4), law_oid(8), law_oid(11)].contains(&claim.law)
                            })
                            && leg.unit != spec.base)
                    && (leg.unit != spec.base || amount == leg.mantissa) =>
            {
                amount
            }
            _ => {
                return Err(failed(
                    "functional_valuation",
                    "foreign legs require a complete claim; only carrying relief/closing may be zero and base-unit legs stay at par",
                ));
            }
        };
        let native_sum = native.entry((entity.clone(), leg.unit)).or_default();
        let base_sum = functional.entry(entity.clone()).or_default();
        if leg.debit {
            native_sum.0 = add(native_sum.0, leg.mantissa)?;
            base_sum.0 = add(base_sum.0, value)?;
            totals.0 = add(totals.0, value)?;
        } else {
            native_sum.1 = add(native_sum.1, leg.mantissa)?;
            base_sum.1 = add(base_sum.1, value)?;
            totals.1 = add(totals.1, value)?;
        }
        entities.push(entity);
        amounts.push(value);
    }
    if native.values().any(|(debits, credits)| debits != credits)
        || functional
            .values()
            .any(|(debits, credits)| debits != credits)
    {
        return Err(failed(
            "functional_footing",
            "native and functional amounts must balance within every legal entity and native unit",
        ));
    }
    if let Some(base) = &base
        && (base.unit != spec.base || (base.debits, base.credits) != totals)
    {
        return Err(failed(
            "functional_valuation",
            "BaseTotals disagree with leg amounts or base unit",
        ));
    }
    Ok(ParsedEntry {
        details,
        base,
        entities,
        amounts,
    })
}
fn compute(
    legs: &[Leg],
    entry: &ParsedEntry,
    rates: &BTreeMap<[u8; 32], Rate>,
    effective: i32,
    period_end: i32,
    base_unit: u32,
    registry: &registry::FunctionalRegistry,
) -> Result<(), ReportError> {
    let claim = entry
        .base
        .as_ref()
        .ok_or_else(|| failed("functional_valuation", "missing claim"))?;
    let law = if claim.law == law_oid(1) {
        1
    } else if claim.law == law_oid(11) {
        11
    } else {
        3
    };
    let mut by_quote = BTreeMap::new();
    for oid in &claim.rates {
        let rate = rates
            .get(oid)
            .ok_or_else(|| failed("functional_rates", "missing cited Rate"))?;
        if rate.base != base_unit
            || rate.purpose
                != if law == 1 {
                    1
                } else if law == 11 {
                    4
                } else {
                    3
                }
            || rate.date != if law == 3 { period_end } else { effective }
            || by_quote.insert(rate.quote, rate).is_some()
        {
            return Err(failed(
                "functional_valuation",
                "Rate purpose, date, base or unique quote unit differs from the original direct law",
            ));
        }
    }
    let base_scale = registry.units[&base_unit].scale;
    if law == 11 && (!registry.spot_carrying || claim.residual.is_some()) {
        return Err(failed(
            "functional_valuation",
            "SettlementSpotCarrying requires its registered v1 law and no residual absorption",
        ));
    }
    let mut groups: BTreeMap<(Option<String>, u32), Vec<usize>> = BTreeMap::new();
    let mut expected = Vec::with_capacity(legs.len());
    for (ordinal, (leg, entity)) in legs.iter().zip(&entry.entities).enumerate() {
        if leg.unit == base_unit {
            expected.push(leg.mantissa);
        } else {
            let rate = by_quote
                .get(&leg.unit)
                .ok_or_else(|| failed("functional_rates", "a foreign unit has no cited Rate"))?;
            let unit = registry
                .units
                .get(&leg.unit)
                .filter(|unit| unit.currency)
                .ok_or_else(|| {
                    failed("functional_rates", "FX quote is not a registered currency")
                })?;
            expected.push(super::arithmetic::convert(
                leg.mantissa,
                unit.scale,
                base_scale,
                rate.numerator,
                rate.denominator,
            )?);
            groups
                .entry((entity.clone(), leg.unit))
                .or_default()
                .push(ordinal);
        }
    }
    let mut residual = None;
    for indices in groups.values() {
        let mut sums = (0i128, 0i128);
        for &index in indices {
            if legs[index].debit {
                sums.0 = add(sums.0, expected[index])?;
            } else {
                sums.1 = add(sums.1, expected[index])?;
            }
        }
        if sums.0 == sums.1 {
            continue;
        }
        let deficient_debit = sums.0 < sums.1;
        let difference = if deficient_debit {
            sums.1 - sums.0
        } else {
            sums.0 - sums.1
        };
        if difference > (indices.len() / 2) as i128 || residual.is_some() {
            return Err(failed(
                "functional_residual",
                "HalfEven residual exceeds its exact bound or more than one partition needs a residual",
            ));
        }
        let mut target = None;
        for &index in indices {
            if legs[index].debit == deficient_debit
                && target.is_none_or(|before| expected[index] > expected[before])
            {
                target = Some(index);
            }
        }
        let target = target
            .ok_or_else(|| failed("functional_residual", "deficient side has no converted leg"))?;
        expected[target] = add(expected[target], difference)?;
        residual = Some((target as u16, base_unit, difference));
    }
    if expected != entry.amounts || residual != claim.residual {
        return Err(failed(
            "functional_valuation",
            "recorded base amounts or designated residual differ from exact independent conversion",
        ));
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub(super) fn verify_history(
    known_at: u64,
    spec: &BookParameters,
    registry: &registry::FunctionalRegistry,
    documents: &[([u8; 32], &[u8])],
    schema: &metadata::Schema,
    envelopes: &[LeafEnvelope],
    records: &[(usize, &[u8])],
    legs: &[Vec<Leg>],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    migration_activations: &BTreeMap<u64, u64>,
) -> Result<BTreeMap<usize, CheckedEntry>, ReportError> {
    if documents.len() > MAX_RATES || !documents.windows(2).all(|pair| pair[0].0 < pair[1].0) {
        return Err(failed(
            "functional_rates",
            "Rate closure is oversized, duplicate or unordered",
        ));
    }
    let mut rates = BTreeMap::new();
    for (oid, bytes) in documents {
        if bytes.len() > MAX_RATE_BYTES {
            return Err(failed(
                "bounded_input",
                "Rate DocumentRecord exceeds 4096 bytes",
            ));
        }
        rates.insert(*oid, rate(*oid, bytes, &spec.book, spec.base, registry)?);
    }
    let mut parsed = BTreeMap::new();
    let mut first_use: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    let mut settlement_use: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    let mut by_digest = BTreeMap::new();
    for (&index, info) in infos {
        if info.fx_revaluation_basis.is_some()
            && base_totals(&records[index].1[..records[index].0])?
                .is_none_or(|base| base.law != law_oid(2))
        {
            return Err(failed(
                "supported_report",
                "source-bound revaluation requires the registered aggregate PeriodEndRevaluation law",
            ));
        }
        let envelope = &envelopes[index];
        let entry = parsed_entry(
            &records[index].1[..records[index].0],
            &legs[index],
            spec,
            registry,
        )?;
        if let Some(claim) = &entry.base {
            if envelope.class == 12 && claim.law != law_oid(1) {
                return Err(failed(
                    "functional_valuation",
                    "Migration valuations require the registered SpotClose law",
                ));
            }
            if ![
                law_oid(1),
                law_oid(2),
                law_oid(3),
                law_oid(4),
                law_oid(8),
                law_oid(11),
            ]
            .contains(&claim.law)
                || claim.law == law_oid(11) && !registry.spot_carrying
            {
                return Err(failed(
                    "supported_report",
                    "functional replay supports SpotClose, aggregate PeriodEndRevaluation, PeriodAverage, source-bound SettlementCarryingBasis v1 and YearEndCloseCarrying; translation and item-allocation laws require their own source proofs",
                ));
            }
            if claim.rates.is_empty() && claim.law != law_oid(8) {
                return Err(failed("functional_rates", "FX claim has no Rate evidence"));
            }
            for oid in &claim.rates {
                let rate = rates
                    .get(oid)
                    .ok_or_else(|| failed("functional_rates", "incomplete Rate closure"))?;
                let citations: Vec<_> = info
                    .evidence
                    .iter()
                    .filter(|(document, _, role)| document == oid && *role == 3)
                    .collect();
                if citations.is_empty()
                    || citations
                        .iter()
                        .any(|(_, commitment, _)| *commitment != rate.commitment)
                {
                    return Err(failed(
                        "functional_rates",
                        "Rate citation is absent or has another commitment",
                    ));
                }
                first_use
                    .entry(*oid)
                    .and_modify(|at| *at = (*at).min(envelope.commit_seq))
                    .or_insert(envelope.commit_seq);
                if [law_oid(4), law_oid(11)].contains(&claim.law) && envelope.class != 4 {
                    settlement_use
                        .entry(*oid)
                        .and_modify(|at| *at = (*at).min(envelope.commit_seq))
                        .or_insert(envelope.commit_seq);
                }
            }
        }
        by_digest.insert(envelope.record_digest, index);
        parsed.insert(index, entry);
    }
    if rates.keys().ne(first_use.keys()) {
        return Err(failed(
            "functional_rates",
            "Rate closure must be the exact referenced set",
        ));
    }
    let mut receipts = BTreeSet::new();
    for (envelope, &(len, payload)) in envelopes.iter().zip(records) {
        if envelope.kind != KIND_IMPORT_RECEIPT || envelope.commit_seq > known_at {
            continue;
        }
        let (oid, commitment, received_by) = receipt(payload, len)?;
        if let Some(rate) = rates.get(&oid)
            && (envelope.book_id != spec.book
                || commitment != rate.commitment
                || received_by != rate.received_by
                || envelope.commit_seq > first_use[&oid]
                || settlement_use
                    .get(&oid)
                    .is_some_and(|at| envelope.commit_seq >= *at)
                || !receipts.insert(oid))
        {
            return Err(failed(
                "functional_rate_visibility",
                "Rate receipt is duplicate, belongs to another intake, or is later than first use",
            ));
        }
    }
    if receipts.iter().ne(rates.keys()) {
        return Err(failed(
            "functional_rate_visibility",
            "complete prefix lacks a signed ImportReceipt for a cited Rate before first use",
        ));
    }
    let mut parents = BTreeMap::new();
    for (&index, entry) in &parsed {
        let envelope = &envelopes[index];
        if legs[index].is_empty() {
            continue;
        }
        let effective = envelope
            .effective_day
            .ok_or_else(|| failed("functional_valuation", "monetary entry lacks a date"))?;
        let period = schema.entry_period(&infos[&index], effective)?;
        if envelope.class == 4 {
            let [(identity, digest, 1)] = infos[&index].supersession.as_slice() else {
                return Err(failed(
                    "functional_reversal",
                    "reversal requires exactly one original target",
                ));
            };
            let target = *by_digest
                .get(digest)
                .ok_or_else(|| failed("functional_reversal", "reversal target is absent"))?;
            let original = &parsed[&target];
            if !infos[&target].matches_identity(*identity)
                || envelopes[target].commit_seq > envelope.commit_seq
                || envelopes[target].class == 12
                    && migration_activations
                        .get(&(target as u64))
                        .is_none_or(|activated| *activated >= envelope.commit_seq)
                || envelopes[target].book_id != envelope.book_id
                || envelopes[target].branch_id != envelope.branch_id
                || legs[target].is_empty()
                || legs[index].len() != legs[target].len()
                || entry.base != original.base
            {
                return Err(failed(
                    "functional_reversal",
                    "reversal does not preserve its original identity and valuation",
                ));
            }
            for ordinal in 0..legs[index].len() {
                let current = &legs[index][ordinal];
                let prior = &legs[target][ordinal];
                if current.debit == prior.debit
                    || current.account != prior.account
                    || current.unit != prior.unit
                    || current.mantissa != prior.mantissa
                    || entry.details[ordinal].base_amount != original.details[ordinal].base_amount
                    || entry.details[ordinal].dimensions != original.details[ordinal].dimensions
                {
                    return Err(failed(
                        "functional_reversal",
                        "reversal is not an exact ordered side-swap",
                    ));
                }
            }
            if let Some(claim) = &original.base {
                for evidence in &infos[&target].evidence {
                    if claim.rates.contains(&evidence.0)
                        && !infos[&index].evidence.contains(evidence)
                    {
                        return Err(failed(
                            "functional_reversal",
                            "reversal dropped original Rate evidence",
                        ));
                    }
                }
            }
            parents.insert(index, target);
        } else if entry
            .base
            .as_ref()
            .is_some_and(|claim| ![law_oid(4), law_oid(2), law_oid(8)].contains(&claim.law))
        {
            let (_, period_end) = schema.bounds(std::slice::from_ref(&period))?;
            compute(
                &legs[index],
                entry,
                &rates,
                effective,
                period_end,
                spec.base,
                registry,
            )?;
        }
    }
    let mut complete = BTreeSet::new();
    for &index in parents.keys() {
        let mut path = BTreeSet::new();
        let mut cursor = index;
        while !complete.contains(&cursor) {
            if !path.insert(cursor) {
                return Err(failed("functional_reversal", "cyclic reversal ancestry"));
            }
            match parents.get(&cursor) {
                Some(parent) => cursor = *parent,
                None => break,
            }
        }
        complete.extend(path);
    }
    revaluation::verify(
        spec,
        registry,
        &rates,
        envelopes,
        records,
        infos,
        legs,
        &parsed,
        migration_activations,
    )?;
    settlement::verify(
        spec,
        registry,
        &rates,
        envelopes,
        infos,
        legs,
        &parsed,
        &parents,
        migration_activations,
    )?;
    closing::verify(
        spec,
        registry,
        envelopes,
        records,
        infos,
        legs,
        &parsed,
        migration_activations,
    )?;
    Ok(parsed
        .into_iter()
        .map(|(index, entry)| {
            (
                index,
                CheckedEntry {
                    entities: entry.entities,
                    amounts: entry.amounts,
                },
            )
        })
        .collect())
}
