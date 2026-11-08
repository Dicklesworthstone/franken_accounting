//! First-digit Benford v2, independently folded from authenticated live legs.
//! The fixed probabilities and integer truncations are part of this semantic
//! version. No producer arithmetic, claimed histogram, or native query result
//! contributes to the independently computed counts.

use super::{
    Entry, Reader, Registry, ReportError, VerifiedProcedureFinding, VerifiedProcedureParameters,
    VerifiedProcedureStatistic, failed, text,
};

pub(super) const DEFAULTS: [(&str, u32); 7] = [
    ("account_type", 0),
    ("currency_iso4217", 840),
    ("mad_acceptable", 12),
    ("mad_close", 6),
    ("mad_marginal", 15),
    ("min_population", 500),
    ("side", 0),
];

const SCALE: u128 = 1_000_000_000;
const CHI_POPULATION_LIMIT: u64 = 1_000_000;
// Rounded log10(1 + 1/d), d=1..=9, with the last cell reduced by one
// part per billion so the registered v2 table sums to exactly one.
const PROBABILITIES: [u128; 9] = [
    301_029_996,
    176_091_259,
    124_938_737,
    96_910_013,
    79_181_246,
    66_946_790,
    57_991_947,
    51_152_522,
    45_757_490,
];

fn arithmetic() -> ReportError {
    failed(
        "procedure_arithmetic",
        "Benford exact arithmetic exceeds its bounds",
    )
}

pub(super) fn decode(reader: &mut Reader<'_>) -> Result<VerifiedProcedureParameters, ReportError> {
    if reader.count(DEFAULTS.len(), 20, "procedure.parameters")? != DEFAULTS.len() {
        return Err(failed(
            "procedure_profile",
            "first-digit Benford v2 requires all seven explicit parameters",
        ));
    }
    let mut values = [0u32; 7];
    for (index, (name, _)) in DEFAULTS.iter().enumerate() {
        if text(reader, 64, "procedure.parameter")? != *name {
            return Err(failed(
                "procedure_profile",
                "Benford parameter names must be complete, unique and lexically ordered",
            ));
        }
        values[index] =
            u32::try_from(reader.i128("procedure.parameter_value")?).map_err(|_| {
                failed(
                    "procedure_profile",
                    "Benford parameters must be unsigned 32-bit integers",
                )
            })?;
    }
    if values[0] > 8 || !(1..=999).contains(&values[1]) || values[6] > 1 {
        return Err(failed(
            "procedure_profile",
            "Benford requires account_type 0..=8, currency_iso4217 1..=999 and side 0 or 1",
        ));
    }
    Ok(VerifiedProcedureParameters::FirstDigit {
        account_type: values[0],
        currency_iso4217: values[1],
        mad_acceptable: values[2],
        mad_close: values[3],
        mad_marginal: values[4],
        min_population: values[5],
        side: values[6],
    })
}

fn population(counts: &[u64; 9]) -> Result<u64, ReportError> {
    counts.iter().try_fold(0u64, |total, &count| {
        total.checked_add(count).ok_or_else(arithmetic)
    })
}

/// MAD and KS at 1e9, and the sum of per-cell Pearson terms truncated at
/// 1e6. The version's chi-square bound is retained even when wider arithmetic
/// could admit a larger population; above it the output explicitly omits chi.
fn statistics(counts: &[u64; 9]) -> Result<(u64, u64, Option<u64>), ReportError> {
    let total = population(counts)?;
    if total == 0 {
        return Ok((0, 0, Some(0)));
    }
    let n = u128::from(total);
    let mut deviation = 0u128;
    let mut observed_cumulative = 0u128;
    let mut expected_cumulative = 0u128;
    let mut largest_distance = 0u128;
    let mut chi = (total <= CHI_POPULATION_LIMIT).then_some(0u128);
    for (&count, probability) in counts.iter().zip(PROBABILITIES) {
        let observed = u128::from(count)
            .checked_mul(SCALE)
            .ok_or_else(arithmetic)?;
        let expected = n.checked_mul(probability).ok_or_else(arithmetic)?;
        let distance = observed.abs_diff(expected);
        deviation = deviation.checked_add(distance).ok_or_else(arithmetic)?;
        observed_cumulative = observed_cumulative
            .checked_add(observed)
            .ok_or_else(arithmetic)?;
        expected_cumulative = expected_cumulative
            .checked_add(expected)
            .ok_or_else(arithmetic)?;
        largest_distance =
            largest_distance.max(observed_cumulative.abs_diff(expected_cumulative));
        if let Some(sum) = chi.as_mut() {
            let numerator = distance
                .checked_mul(distance)
                .and_then(|square| square.checked_mul(1_000_000))
                .ok_or_else(arithmetic)?;
            let denominator = expected.checked_mul(SCALE).ok_or_else(arithmetic)?;
            *sum = sum
                .checked_add(numerator / denominator)
                .ok_or_else(arithmetic)?;
        }
    }
    let mad = u64::try_from(deviation / (n * 9)).map_err(|_| arithmetic())?;
    let ks = u64::try_from(largest_distance / n).map_err(|_| arithmetic())?;
    let chi = chi.map(u64::try_from).transpose().map_err(|_| arithmetic())?;
    Ok((mad, ks, chi))
}

pub(super) fn replay(
    parameters: VerifiedProcedureParameters,
    entries: &[&Entry],
    registry: &Registry,
) -> Result<(VerifiedProcedureFinding, u64), ReportError> {
    let VerifiedProcedureParameters::FirstDigit {
        account_type,
        currency_iso4217,
        side,
        ..
    } = parameters
    else {
        return Err(failed(
            "procedure_profile",
            "expected first-digit Benford parameters",
        ));
    };
    let mut counts = [0u64; 9];
    let mut work_legs = 0u64;
    for entry in entries {
        if entry.legs.len() != entry.leg_accounts.len() {
            return Err(failed(
                "procedure_profile",
                "Benford leg identities are incomplete",
            ));
        }
        work_legs = work_legs
            .checked_add(entry.legs.len() as u64)
            .ok_or_else(arithmetic)?;
        for (&(unit, amount), &(account, debit)) in entry.legs.iter().zip(&entry.leg_accounts) {
            let scale = registry.unit_scales.get(&unit).ok_or_else(|| {
                failed(
                    "procedure_units",
                    "Benford posting uses an unregistered unit",
                )
            })?;
            if u32::from(u8::from(!debit)) != side
                || registry
                    .unit_currencies
                    .get(&unit)
                    .copied()
                    .map(u32::from)
                    != Some(currency_iso4217)
            {
                continue;
            }
            if account_type != 0 {
                let actual = registry.account_types.get(&account).ok_or_else(|| {
                    failed(
                        "account_metadata",
                        "Benford posting has no authenticated account type",
                    )
                })?;
                if u32::from(*actual) != account_type {
                    continue;
                }
            }
            let one = 10u128
                .checked_pow(u32::from(*scale))
                .ok_or_else(arithmetic)?;
            let mut magnitude = amount.unsigned_abs();
            if magnitude < one {
                continue;
            }
            while magnitude >= 10 {
                magnitude /= 10;
            }
            let bucket = usize::try_from(magnitude - 1).map_err(|_| arithmetic())?;
            counts[bucket] = counts[bucket].checked_add(1).ok_or_else(arithmetic)?;
        }
    }
    Ok((finish(parameters, counts)?, work_legs))
}

fn finish(
    parameters: VerifiedProcedureParameters,
    counts: [u64; 9],
) -> Result<VerifiedProcedureFinding, ReportError> {
    let VerifiedProcedureParameters::FirstDigit {
        mad_acceptable,
        mad_close,
        mad_marginal,
        min_population,
        ..
    } = parameters
    else {
        return Err(failed(
            "procedure_profile",
            "expected first-digit Benford parameters",
        ));
    };
    let population = population(&counts)?;
    if population < u64::from(min_population) {
        return Ok(VerifiedProcedureFinding {
            entry: None,
            severity: 0,
            statistic: VerifiedProcedureStatistic::FirstDigitPopulation { counts },
            population,
            narrative: format!(
                "population {population} is below the registered minimum {min_population}; no conformity is claimed"
            ),
        });
    }
    let (mad, ks, chi_square_1e6) = statistics(&counts)?;
    let close = u64::from(mad_close) * 1_000_000;
    let acceptable = u64::from(mad_acceptable) * 1_000_000;
    let marginal = u64::from(mad_marginal) * 1_000_000;
    let severity = if mad <= close {
        0
    } else if mad <= acceptable {
        1
    } else if mad <= marginal {
        2
    } else {
        3
    };
    let chi = match chi_square_1e6 {
        Some(value) => format!("chi-square {value}e-6 with 8 degrees of freedom, KS {ks}e-9"),
        None => format!(
            "chi-square not computed above {CHI_POPULATION_LIMIT} legs (its exact arithmetic bound); KS {ks}e-9; MAD is the scored statistic"
        ),
    };
    Ok(VerifiedProcedureFinding {
        entry: None,
        severity,
        statistic: VerifiedProcedureStatistic::FirstDigitMad {
            counts,
            mad_1e9: mad,
            ks_1e9: ks,
            chi_square_1e6,
        },
        population,
        narrative: format!(
            "first-digit counts {counts:?} over {population} legs; MAD {mad}e-9 (close ≤ {close}e-9, acceptable ≤ {acceptable}e-9, marginal ≤ {marginal}e-9); {chi}"
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parameters(min_population: u32) -> VerifiedProcedureParameters {
        VerifiedProcedureParameters::FirstDigit {
            account_type: 0,
            currency_iso4217: 840,
            mad_acceptable: 12,
            mad_close: 6,
            mad_marginal: 15,
            min_population,
            side: 0,
        }
    }

    #[test]
    fn fixed_point_statistics_and_all_four_conformity_bands_have_literal_witnesses() {
        for (counts, expected, severity) in [
            (
                [301, 176, 125, 97, 79, 67, 58, 51, 46],
                (101_116, 242_510, 2_358),
                0,
            ),
            (
                [271, 206, 125, 97, 79, 67, 58, 51, 46],
                (6_747_503, 30_029_996, 8_077_963),
                1,
            ),
            (
                [241, 236, 125, 97, 79, 67, 58, 51, 46],
                (13_414_169, 60_029_996, 32_355_012),
                2,
            ),
            (
                [201, 276, 125, 97, 79, 67, 58, 51, 46],
                (22_303_058, 100_029_996, 89_926_654),
                3,
            ),
            ([1; 9], (59_717_035, 268_726_658, 3_615_281), 3),
        ] {
            assert_eq!(
                statistics(&counts).unwrap(),
                (expected.0, expected.1, Some(expected.2))
            );
            let result = finish(parameters(1), counts).unwrap();
            assert_eq!(result.entry, None);
            assert_eq!(result.severity, severity);
            assert_eq!(result.statistic.name(), "mad");
            assert_eq!(result.statistic.scale(), 9);
            assert_eq!(result.statistic.value(), expected.0);
            assert_eq!(result.population, counts.iter().sum::<u64>());
        }
        assert_eq!(statistics(&[0; 9]).unwrap(), (0, 0, Some(0)));
        assert!(
            statistics(&[u64::MAX; 9]).is_err(),
            "a histogram cannot wrap its population"
        );
    }

    #[test]
    fn minimum_population_and_chi_square_limit_keep_their_distinct_claim_boundaries() {
        let below = finish(parameters(500), [499, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(below.severity, 0);
        assert_eq!(below.statistic.name(), "population");
        assert_eq!(below.statistic.scale(), 0);
        assert_eq!(below.statistic.value(), 499);
        assert_eq!(
            below.narrative,
            "population 499 is below the registered minimum 500; no conformity is claimed"
        );
        let at = finish(parameters(500), [500, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(at.severity, 3);
        assert_eq!(
            at.statistic,
            VerifiedProcedureStatistic::FirstDigitMad {
                counts: [500, 0, 0, 0, 0, 0, 0, 0, 0],
                mad_1e9: 155_326_667,
                ks_1e9: 698_970_004,
                chi_square_1e6: Some(1_160_964_043),
            }
        );
        assert!(
            statistics(&[1_000_000, 0, 0, 0, 0, 0, 0, 0, 0])
                .unwrap()
                .2
                .is_some()
        );
        let above =
            finish(parameters(500), [1_000_001, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            above.statistic,
            VerifiedProcedureStatistic::FirstDigitMad {
                counts: [1_000_001, 0, 0, 0, 0, 0, 0, 0, 0],
                mad_1e9: 155_326_667,
                ks_1e9: 698_970_004,
                chi_square_1e6: None,
            }
        );
        assert!(
            above
                .narrative
                .contains("chi-square not computed above 1000000 legs")
        );
        assert!(above.narrative.ends_with("MAD is the scored statistic"));
        let zero = finish(parameters(0), [0; 9]).unwrap();
        assert_eq!(zero.statistic.name(), "mad");
        assert_eq!(zero.statistic.value(), 0);
        assert_eq!(zero.severity, 0);
    }
}
