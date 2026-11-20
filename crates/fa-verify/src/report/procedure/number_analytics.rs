//! Independent relative-size and threshold-splitting audit calculations.
//!
//! The original leg order, unit and party dimensions come from authenticated
//! journal payloads. Native population witnesses never supply these facts.
//! Relative-size groups retain their two largest observations directly; split
//! groups use wide prefix totals and binary-searched date windows. Neither
//! calculation imports the producer's implementation or trusts its findings.

use std::collections::BTreeMap;

use super::{
    Entry, MAX_CITES, MAX_FINDINGS, Reader, Registry, ReportError, VerifiedProcedureFinding,
    VerifiedProcedureParameters, VerifiedProcedureStatistic, failed, text,
};

pub(super) const RSF_DEFAULTS: [(&str, u32); 2] = [("min_rsf_bps", 50_000), ("min_subset_size", 3)];
pub(super) const SPLIT_DEFAULTS: [(&str, u32); 5] = [
    ("currency_iso4217", 840),
    ("floor", 250_000),
    ("min_count", 2),
    ("threshold", 1_000_000),
    ("window_days", 5),
];

fn invalid(message: &str) -> ReportError {
    failed("procedure_profile", message)
}

fn overflow() -> ReportError {
    failed(
        "procedure_arithmetic",
        "numeric audit arithmetic exceeds its exact domain",
    )
}

pub(super) fn decode(
    reader: &mut Reader<'_>,
    splitting: bool,
) -> Result<VerifiedProcedureParameters, ReportError> {
    let defaults = if splitting {
        &SPLIT_DEFAULTS[..]
    } else {
        &RSF_DEFAULTS[..]
    };
    if reader.count(defaults.len(), 20, "procedure.parameters")? != defaults.len() {
        return Err(invalid(
            "numeric audit requires its complete explicit parameter inventory",
        ));
    }
    let mut values = Vec::with_capacity(defaults.len());
    for (name, _) in defaults {
        if text(reader, 64, "procedure.parameter")? != *name {
            return Err(invalid(
                "numeric audit parameters must be unique and lexically ordered",
            ));
        }
        values.push(reader.i128("procedure.parameter_value")?);
    }
    let unsigned = |index: usize| {
        u32::try_from(values[index])
            .map_err(|_| invalid("numeric audit count, currency and window parameters require u32"))
    };
    if splitting {
        let currency_iso4217 = unsigned(0)?;
        let min_count = unsigned(2)?;
        if !(1..=999).contains(&currency_iso4217)
            || values[1] <= 0
            || values[1] >= values[3]
            || min_count < 2
        {
            return Err(invalid(
                "threshold splitting requires a currency, 0 < floor < threshold and at least two postings",
            ));
        }
        Ok(VerifiedProcedureParameters::ThresholdSplitting {
            currency_iso4217,
            floor: values[1],
            min_count,
            threshold: values[3],
            window_days: unsigned(4)?,
        })
    } else {
        let min_subset_size = unsigned(1)?;
        if min_subset_size < 2 {
            return Err(invalid(
                "relative-size subsets require at least two observations",
            ));
        }
        Ok(VerifiedProcedureParameters::RelativeSizeFactor {
            min_rsf_bps: unsigned(0)?,
            min_subset_size,
        })
    }
}

fn parties<'a>(entry: &Entry, registry: &'a Registry) -> Result<&'a [Option<u128>], ReportError> {
    registry
        .leg_parties
        .get(&entry.identity)
        .filter(|parties| {
            parties.len() == entry.legs.len() && entry.leg_accounts.len() == entry.legs.len()
        })
        .map(Vec::as_slice)
        .ok_or_else(|| invalid("numeric audit lacks authenticated per-leg party identities"))
}

fn push(
    findings: &mut Vec<VerifiedProcedureFinding>,
    finding: VerifiedProcedureFinding,
) -> Result<(), ReportError> {
    if findings.len() >= MAX_FINDINGS {
        return Err(failed(
            "bounded_input",
            "numeric audit findings exceed the certificate bound",
        ));
    }
    findings.push(finding);
    Ok(())
}

/// floor(numerator * 10_000 / denominator), without a narrow product. The
/// fractional remainder is scaled by binary long division in fourteen steps;
/// each intermediate is below twice a positive i128 denominator and fits u128.
fn ratio_bps(numerator: i128, denominator: i128) -> Result<i128, ReportError> {
    if numerator <= 0 || denominator <= 0 {
        return Err(invalid("relative-size observations must be positive"));
    }
    let (numerator, denominator) = (numerator as u128, denominator as u128);
    let whole = (numerator / denominator)
        .checked_mul(10_000)
        .ok_or_else(overflow)?;
    let fraction = numerator % denominator;
    let (mut quotient, mut remainder) = (0u128, 0u128);
    for bit in (0..14).rev() {
        quotient *= 2;
        remainder *= 2;
        if remainder >= denominator {
            remainder -= denominator;
            quotient += 1;
        }
        if (10_000u32 >> bit) & 1 != 0 {
            remainder += fraction;
            if remainder >= denominator {
                remainder -= denominator;
                quotient += 1;
            }
        }
    }
    whole
        .checked_add(quotient)
        .and_then(|value| i128::try_from(value).ok())
        .ok_or_else(overflow)
}

#[derive(Default)]
struct Largest {
    count: u64,
    first: Option<(i128, u128)>,
    second: Option<(i128, u128)>,
}

impl Largest {
    fn add(&mut self, amount: i128, identity: u128) -> Result<(), ReportError> {
        self.count = self.count.checked_add(1).ok_or_else(overflow)?;
        let item = (amount, identity);
        let precedes =
            |other: (i128, u128)| amount > other.0 || (amount == other.0 && identity < other.1);
        if self.first.is_none_or(precedes) {
            self.second = self.first.replace(item);
        } else if self.second.is_none_or(precedes) {
            self.second = Some(item);
        }
        Ok(())
    }
}

fn relative_size(
    live: &[&Entry],
    registry: &Registry,
    min_rsf_bps: u32,
    min_subset_size: u32,
) -> Result<(Vec<VerifiedProcedureFinding>, u64, u64), ReportError> {
    if min_subset_size < 2 {
        return Err(invalid(
            "relative-size subsets require at least two observations",
        ));
    }
    let mut groups: BTreeMap<(bool, u128, u32), Largest> = BTreeMap::new();
    let (mut legs, mut population) = (0u64, 0u64);
    for entry in live {
        let parties = parties(entry, registry)?;
        legs = legs
            .checked_add(entry.legs.len() as u64)
            .ok_or_else(overflow)?;
        for (index, &(unit, amount)) in entry.legs.iter().enumerate() {
            let (account, debit) = entry.leg_accounts[index];
            if debit && amount > 0 {
                population = population.checked_add(1).ok_or_else(overflow)?;
                let party = parties[index];
                groups
                    .entry((party.is_some(), party.unwrap_or(account), unit))
                    .or_default()
                    .add(amount, entry.identity)?;
            }
        }
    }
    let mut findings = Vec::new();
    for ((by_party, identity, _unit), values) in groups {
        if values.count < u64::from(min_subset_size) {
            continue;
        }
        let (largest, second) = values
            .first
            .zip(values.second)
            .ok_or_else(|| invalid("relative-size group lacks its two observations"))?;
        let basis_points = ratio_bps(largest.0, second.0)?;
        if basis_points < i128::from(min_rsf_bps) {
            continue;
        }
        push(
            &mut findings,
            VerifiedProcedureFinding {
                entry: Some(largest.1),
                severity: if basis_points >= i128::from(min_rsf_bps) * 2 {
                    3
                } else {
                    2
                },
                statistic: VerifiedProcedureStatistic::RelativeSizeFactor {
                    basis_points,
                    largest_entry: largest.1,
                    second_entry: second.1,
                    account: (!by_party && registry.account_types.contains_key(&identity))
                        .then_some(identity),
                },
                population,
                narrative: format!(
                    "largest debit {} vs second-largest {} across {} postings yields RSF {basis_points} bps (min_rsf_bps {min_rsf_bps})",
                    largest.0, second.0, values.count
                ),
            },
        )?;
    }
    // Native work charges every positive debit once when visiting its group,
    // even when that group has too few observations to produce a finding.
    Ok((findings, legs, population))
}

/// A prefix may exceed i128 even when every disjoint window fits. Preserve the
/// complete positive prefix in two limbs, then range-check the selected delta.
#[derive(Clone, Copy, Default)]
struct Total {
    high: u128,
    low: u128,
}

impl Total {
    fn add(self, value: i128) -> Result<Self, ReportError> {
        let value = u128::try_from(value).map_err(|_| overflow())?;
        let (low, carry) = self.low.overflowing_add(value);
        Ok(Self {
            high: self
                .high
                .checked_add(u128::from(carry))
                .ok_or_else(overflow)?,
            low,
        })
    }

    fn since(self, earlier: Self) -> Result<i128, ReportError> {
        let (low, borrow) = self.low.overflowing_sub(earlier.low);
        let high = self
            .high
            .checked_sub(earlier.high)
            .and_then(|value| value.checked_sub(u128::from(borrow)))
            .ok_or_else(overflow)?;
        if high != 0 {
            return Err(overflow());
        }
        i128::try_from(low).map_err(|_| overflow())
    }
}

fn splitting(
    live: &[&Entry],
    registry: &Registry,
    profile: VerifiedProcedureParameters,
) -> Result<(Vec<VerifiedProcedureFinding>, u64, u64), ReportError> {
    let VerifiedProcedureParameters::ThresholdSplitting {
        currency_iso4217,
        floor,
        min_count,
        threshold,
        window_days,
    } = profile
    else {
        return Err(invalid("expected threshold splitting"));
    };
    if !(1..=999).contains(&currency_iso4217) || floor <= 0 || floor >= threshold || min_count < 2 {
        return Err(invalid("invalid threshold-splitting domain"));
    }
    type Key = (bool, u128, u128, u8);
    type Item = (i32, u128, i128);
    let mut groups: BTreeMap<Key, Vec<Item>> = BTreeMap::new();
    let mut legs = 0u64;
    for entry in live {
        let parties = parties(entry, registry)?;
        legs = legs
            .checked_add(entry.legs.len() as u64)
            .ok_or_else(overflow)?;
        let (mut debit_total, mut scale, mut party) = (0i128, 2u8, None);
        let (mut first, mut last) = (None, None);
        for (index, &(unit, amount)) in entry.legs.iter().enumerate() {
            if registry.unit_currencies.get(&unit).copied().map(u32::from) != Some(currency_iso4217)
            {
                continue;
            }
            scale = *registry
                .unit_scales
                .get(&unit)
                .ok_or_else(|| invalid("selected currency has no authenticated scale"))?;
            let (account, debit) = entry.leg_accounts[index];
            if parties[index].is_some() {
                party = parties[index];
            }
            first = Some(first.map_or(account, |value: u128| value.min(account)));
            last = Some(last.map_or(account, |value: u128| value.max(account)));
            if debit {
                debit_total = debit_total.checked_add(amount).ok_or_else(overflow)?;
            }
        }
        if (floor..threshold).contains(&debit_total) {
            let day = entry
                .effective
                .ok_or_else(|| invalid("a split candidate has no effective date"))?;
            let key = match party {
                Some(party) => (true, party, 0, scale),
                None => (false, first.unwrap_or(0), last.unwrap_or(0), scale),
            };
            groups
                .entry(key)
                .or_default()
                .push((day, entry.identity, debit_total));
        }
    }
    let mut findings = Vec::new();
    let mut comparisons = 0u64;
    for ((_, _, _, scale), mut items) in groups {
        comparisons = comparisons
            .checked_add(items.len() as u64)
            .ok_or_else(overflow)?;
        if (items.len() as u64) < u64::from(min_count) {
            continue;
        }
        items.sort_unstable_by_key(|&(day, entry, _)| (day, entry));
        let mut prefix = Vec::with_capacity(items.len() + 1);
        prefix.push(Total::default());
        let mut total = Total::default();
        for &(_, _, amount) in &items {
            total = total.add(amount)?;
            prefix.push(total);
        }
        let mut start = 0;
        while start < items.len() {
            let last_day = i64::from(items[start].0) + i64::from(window_days);
            let end = items.partition_point(|&(day, _, _)| i64::from(day) <= last_day);
            let sum = prefix[end].since(prefix[start])?;
            if (end - start) as u64 >= u64::from(min_count) && sum >= threshold {
                if end - start > MAX_CITES {
                    return Err(failed(
                        "bounded_input",
                        "split group exceeds the complete citation bound",
                    ));
                }
                let mut entries: Vec<_> = items[start..end]
                    .iter()
                    .map(|&(_, identity, _)| identity)
                    .collect();
                entries.sort_unstable();
                entries.dedup();
                let narrative = format!(
                    "{} sub-threshold postings in [{floor}, {threshold}) within {window_days} day(s) sum to {sum} (>= threshold {threshold}; 31 CFR 1010.311 CTR / threshold rule)",
                    entries.len()
                );
                push(
                    &mut findings,
                    VerifiedProcedureFinding {
                        entry: entries.first().copied(),
                        severity: 3,
                        statistic: VerifiedProcedureStatistic::SplitTotal {
                            mantissa: sum,
                            scale,
                            entries,
                        },
                        population: live.len() as u64,
                        narrative,
                    },
                )?;
                start = end;
            } else {
                start += 1;
            }
        }
    }
    Ok((findings, legs, comparisons))
}

pub(super) fn replay(
    profile: VerifiedProcedureParameters,
    live: &[&Entry],
    registry: &Registry,
) -> Result<(Vec<VerifiedProcedureFinding>, u64, u64), ReportError> {
    match profile {
        VerifiedProcedureParameters::RelativeSizeFactor {
            min_rsf_bps,
            min_subset_size,
        } => relative_size(live, registry, min_rsf_bps, min_subset_size),
        VerifiedProcedureParameters::ThresholdSplitting { .. } => {
            splitting(live, registry, profile)
        }
        _ => Err(invalid("expected numeric audit profile")),
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "relative_size.rs"]
mod relative_size_regressions;
