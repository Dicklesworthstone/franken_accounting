//! Independent allocated-carrying settlement releases (FX law 10).
//!
//! The immutable release is an assertion: historical relief, total relief,
//! route and source digest must all match the checked pre-publication item.

use super::*;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Release {
    ordinal: u16,
    source_digest: [u8; 32],
    historical: i128,
    total: i128,
    valuation: i128,
    route: AllocationRoute,
}

fn read(raw: &[u8], base: u32) -> Result<Vec<Release>, ReportError> {
    if raw.len() > 64 * 1024 {
        return Err(failed(
            "bounded_input",
            "FX allocated release exceeds its 64 KiB native extension bound",
        ));
    }
    let mut r = Reader::new(raw);
    if r.fixed::<13>("fx_relief.magic")? != *b"FA-FX-RELIEF\0" || r.u16("fx_relief.version")? != 1 {
        return Err(invalid("unsupported allocated settlement release format"));
    }
    let count = r.count(1024, 174, "fx_relief.items")?;
    if count == 0 {
        return Err(invalid(
            "allocated settlement requires a nonempty release basis",
        ));
    }
    let mut releases = Vec::with_capacity(count);
    let mut previous = None;
    for _ in 0..count {
        let ordinal = r.u16("fx_relief.ordinal")?;
        let source_digest = r.fixed("fx_relief.source_digest")?;
        let historical_unit = r.u32("fx_relief.historical.unit")?;
        let historical = r.i128("fx_relief.historical.amount")?;
        let total_unit = r.u32("fx_relief.total.unit")?;
        let total = r.i128("fx_relief.total.amount")?;
        let valuation_unit = r.u32("fx_relief.valuation.unit")?;
        let valuation = r.i128("fx_relief.valuation.amount")?;
        let route = AllocationRoute {
            entry: r.u128("fx_relief.routes_entry")?,
            digest: r.fixed("fx_relief.routes_digest")?,
            valuation: r.u128("fx_relief.valuation_account")?,
            unrealized: r.u128("fx_relief.unrealized_account")?,
        };
        if previous.is_some_and(|last| last >= ordinal)
            || ordinal >= 4096
            || historical_unit != base
            || total_unit != base
            || valuation_unit != base
            || historical < 0
            || total < 0
            || historical.checked_add(valuation) != Some(total)
            || route.valuation == route.unrealized
        {
            return Err(invalid(
                "allocated release ordinals, units, route or carrying components differ",
            ));
        }
        previous = Some(ordinal);
        releases.push(Release {
            ordinal,
            source_digest,
            historical,
            total,
            valuation,
            route,
        });
    }
    r.finish("allocated carrying release")?;
    Ok(releases)
}

pub(super) fn read_history(
    spec: &BookParameters,
    registry: &registry::FunctionalRegistry,
    envelopes: &[LeafEnvelope],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    parsed: &BTreeMap<usize, ParsedEntry>,
    parents: &BTreeMap<usize, usize>,
) -> Result<BTreeMap<usize, Vec<Release>>, ReportError> {
    let mut declarations = BTreeMap::new();
    for (&index, entry) in parsed {
        let allocated = entry
            .base
            .as_ref()
            .is_some_and(|claim| claim.law == law_oid(10));
        let raw = infos[&index].fx_settlement_basis;
        if raw.is_some() != allocated {
            return Err(invalid(
                "allocated release provenance requires exactly its registered carrying law",
            ));
        }
        if allocated {
            if !registry.allocated_carrying || !matches!(envelopes[index].class, 1 | 4 | 7) {
                return Err(failed(
                    "supported_report",
                    "allocated settlement requires its registered law and eligible class",
                ));
            }
            declarations.insert(index, read(raw.expect("presence checked"), spec.base)?);
        }
    }
    for (&index, &parent) in parents {
        if declarations.contains_key(&index) && envelopes[parent].class == 4 {
            return Err(failed(
                "supported_report",
                "allocated settlement cannot inherit a fresh reapplication by reversing an undo",
            ));
        }
        if declarations.contains_key(&index)
            && (declarations.get(&index) != declarations.get(&parent)
                || infos[&index].fx_settlement_basis != infos[&parent].fx_settlement_basis)
        {
            return Err(invalid(
                "an exact allocated-settlement undo must retain its original release basis",
            ));
        }
    }
    Ok(declarations)
}

pub(super) fn check_ranges(
    releases: &[Release],
    ranges: &[std::ops::Range<usize>],
) -> Result<(), ReportError> {
    if releases.len() != ranges.len()
        || releases
            .iter()
            .zip(ranges)
            .any(|(release, range)| usize::from(release.ordinal) != range.start)
    {
        return Err(invalid(
            "allocated release ordinals must cover every ordered settlement component exactly once",
        ));
    }
    Ok(())
}

pub(super) fn component(
    history: &History<'_>,
    index: usize,
    range: std::ops::Range<usize>,
    target: Target,
    state: &Carrying,
    source_digest: [u8; 32],
) -> Result<Effect, ReportError> {
    let releases = &history.releases[&index];
    let position = releases
        .binary_search_by_key(&(range.start as u16), |release| release.ordinal)
        .map_err(|_| invalid("allocated component has no retained release"))?;
    let release = &releases[position];
    let route = state.allocated.ok_or_else(|| {
        invalid("allocated settlement target has no authenticated prior allocation")
    })?;
    let tail = usize::from(release.valuation != 0) * 2;
    let core_end = range
        .end
        .checked_sub(tail)
        .filter(|end| *end > range.start)
        .ok_or_else(|| invalid("allocated settlement release tail is incomplete"))?;
    // The ordinary historical-cost component is checked independently,
    // including exact remaining historical relief and current Rate cash.
    let mut effect = history.component(index, range.start..core_end, target, state)?;
    let carrying = state
        .base
        .checked_add(state.valuation)
        .ok_or_else(|| invalid("allocated carrying total exceeds i128"))?;
    let total_relief = if effect.native == state.native {
        carrying
    } else {
        super::super::super::arithmetic::convert(
            carrying,
            0,
            0,
            effect.native as u128,
            state.native as u128,
        )?
    };
    let valuation_relief = sub(total_relief, effect.base)?;
    if release.source_digest != source_digest
        || source_digest != state.source_hash.finalize()
        || release.historical != effect.base
        || release.total != total_relief
        || release.valuation != valuation_relief
        || release.route != route
    {
        return Err(invalid(
            "allocated relief, route or carrying source digest differs from its checked prefix",
        ));
    }
    if history.legs[index][range.start..core_end]
        .iter()
        .any(|leg| [route.valuation, route.unrealized].contains(&leg.account))
    {
        return Err(invalid(
            "allocated valuation and unrealized accounts must be distinct from every settlement core account",
        ));
    }
    if valuation_relief != 0 {
        let magnitude = valuation_relief
            .checked_abs()
            .ok_or_else(|| invalid("allocated release magnitude overflow"))?;
        let applying = &history.legs[index][range.start];
        let debit = if valuation_relief > 0 {
            applying.debit
        } else {
            !applying.debit
        };
        let dimensions = &history.parsed[&index].details[range.start].dimensions;
        for (ordinal, account, debit) in [
            (core_end, route.valuation, debit),
            (core_end + 1, route.unrealized, !debit),
        ] {
            let leg = &history.legs[index][ordinal];
            let detail = &history.parsed[&index].details[ordinal];
            if leg.account != account
                || leg.debit != debit
                || leg.unit != history.spec.base
                || leg.mantissa != magnitude
                || detail.base_amount != Some((history.spec.base, magnitude))
                || &detail.dimensions != dimensions
                || !detail.settlements.is_empty()
            {
                return Err(invalid(
                    "allocated release must preserve the exact signed route pair and source dimensions",
                ));
            }
        }
    }
    effect.valuation = valuation_relief;
    Ok(effect)
}

pub(super) fn coverage(
    index: usize,
    releases: &[Release],
    components: &[(std::ops::Range<usize>, Target)],
    legs: &[Vec<Leg>],
) -> Vec<ReleaseCoverage> {
    releases
        .iter()
        .zip(components)
        .map(|(release, (range, _))| ReleaseCoverage {
            source: legs[index][range.start].account,
            route: release.route,
            valuation_ordinal: (release.valuation != 0).then_some(range.end - 2),
        })
        .collect()
}
