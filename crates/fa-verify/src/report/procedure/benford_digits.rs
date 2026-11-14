//! Independent second-digit and first-two-digits Benford v2 replay.
//! These fixed tables and integer rounding boundaries are versioned semantics;
//! producer histograms, native REA witnesses and claimed scores are not inputs.

use super::benford::{
    CHI_POPULATION_LIMIT, SCALE, arithmetic, decode_values, population, statistics_for,
};
use super::{
    Entry, Reader, Registry, ReportError, VerifiedProcedureFinding, VerifiedProcedureParameters,
    VerifiedProcedureStatistic, failed,
};

pub(super) const SECOND_DEFAULTS: [(&str, u32); 7] = [
    ("account_type", 0),
    ("currency_iso4217", 840),
    ("mad_acceptable", 10),
    ("mad_close", 8),
    ("mad_marginal", 12),
    ("min_population", 500),
    ("side", 0),
];

pub(super) const FIRST_TWO_DEFAULTS: [(&str, u32); 7] = [
    ("account_type", 0),
    ("currency_iso4217", 840),
    ("mad_acceptable", 18),
    ("mad_close", 12),
    ("mad_marginal", 22),
    ("min_population", 500),
    ("side", 0),
];

// Exact registered v2 probabilities, in parts per billion. The 90-cell
// table's column marginals are the ten second-digit probabilities.
const SECOND: [u128; 10] = [
    119_679_269,
    113_890_104,
    108_821_499,
    104_329_561,
    100_308_203,
    96_677_237,
    93_374_735,
    90_351_990,
    87_570_054,
    84_997_348,
];
const FIRST_TWO: [u128; 90] = [
    41_392_685, 37_788_561, 34_762_106, 32_184_683, 29_963_223, 28_028_724, 26_328_939, 24_823_584,
    23_481_096, 22_276_395, 21_189_299, 20_203_386, 19_305_155, 18_483_406, 17_728_767, 17_033_339,
    16_390_416, 15_794_267, 15_239_967, 14_723_257, 14_240_439, 13_788_284, 13_363_962, 12_964_977,
    12_589_127, 12_234_456, 11_899_223, 11_581_873, 11_281_010, 10_995_386, 10_723_865, 10_465_434,
    10_219_165, 9_984_221, 9_759_837, 9_545_318, 9_340_026, 9_143_379, 8_954_843, 8_773_925,
    8_600_172, 8_433_168, 8_272_526, 8_117_890, 7_968_930, 7_825_338, 7_686_829, 7_553_138,
    7_424_018, 7_299_237, 7_178_585, 7_061_854, 6_948_860, 6_839_425, 6_733_383, 6_630_579,
    6_530_867, 6_434_110, 6_340_178, 6_248_949, 6_160_309, 6_074_148, 5_990_364, 5_908_860,
    5_829_544, 5_752_329, 5_677_133, 5_603_878, 5_532_489, 5_462_893, 5_395_032, 5_328_834,
    5_264_240, 5_201_194, 5_139_640, 5_079_526, 5_020_801, 4_963_420, 4_907_334, 4_852_501,
    4_798_883, 4_746_435, 4_695_121, 4_644_905, 4_595_752, 4_547_628, 4_500_501, 4_454_341,
    4_409_119, 4_364_805,
];

pub(super) fn decode(
    reader: &mut Reader<'_>,
    first_two: bool,
) -> Result<VerifiedProcedureParameters, ReportError> {
    let [
        account_type,
        currency_iso4217,
        mad_acceptable,
        mad_close,
        mad_marginal,
        min_population,
        side,
    ] = decode_values(reader)?;
    Ok(if first_two {
        VerifiedProcedureParameters::FirstTwoDigits {
            account_type,
            currency_iso4217,
            mad_acceptable,
            mad_close,
            mad_marginal,
            min_population,
            side,
        }
    } else {
        VerifiedProcedureParameters::SecondDigit {
            account_type,
            currency_iso4217,
            mad_acceptable,
            mad_close,
            mad_marginal,
            min_population,
            side,
        }
    })
}

#[derive(Clone, Copy)]
struct Settings {
    first_two: bool,
    account_type: u32,
    currency: u32,
    side: u32,
    close: u64,
    acceptable: u64,
    marginal: u64,
    minimum: u64,
}

fn settings(profile: VerifiedProcedureParameters) -> Result<Settings, ReportError> {
    let first_two = matches!(profile, VerifiedProcedureParameters::FirstTwoDigits { .. });
    let (VerifiedProcedureParameters::SecondDigit {
        account_type,
        currency_iso4217,
        mad_acceptable,
        mad_close,
        mad_marginal,
        min_population,
        side,
    }
    | VerifiedProcedureParameters::FirstTwoDigits {
        account_type,
        currency_iso4217,
        mad_acceptable,
        mad_close,
        mad_marginal,
        min_population,
        side,
    }) = profile
    else {
        return Err(failed(
            "procedure_profile",
            "expected second-digit or first-two-digits Benford parameters",
        ));
    };
    // First-two-digits bands are in ten-thousandths; second-digit bands
    // are in thousandths. Both become exact parts per billion here.
    let scale = if first_two { 100_000 } else { 1_000_000 };
    Ok(Settings {
        first_two,
        account_type,
        currency: currency_iso4217,
        side,
        close: u64::from(mad_close) * scale,
        acceptable: u64::from(mad_acceptable) * scale,
        marginal: u64::from(mad_marginal) * scale,
        minimum: u64::from(min_population),
    })
}

pub(super) fn replay(
    parameters: VerifiedProcedureParameters,
    entries: &[&Entry],
    registry: &Registry,
) -> Result<(VerifiedProcedureFinding, u64), ReportError> {
    let settings = settings(parameters)?;
    if settings.first_two {
        replay_digits(settings, entries, registry, &FIRST_TWO)
    } else {
        replay_digits(settings, entries, registry, &SECOND)
    }
}

fn replay_digits<const N: usize>(
    settings: Settings,
    entries: &[&Entry],
    registry: &Registry,
    probabilities: &[u128; N],
) -> Result<(VerifiedProcedureFinding, u64), ReportError> {
    let mut counts = [0u64; N];
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
            if u32::from(u8::from(!debit)) != settings.side
                || registry.unit_currencies.get(&unit).copied().map(u32::from)
                    != Some(settings.currency)
            {
                continue;
            }
            if settings.account_type != 0 {
                let actual = registry.account_types.get(&account).ok_or_else(|| {
                    failed(
                        "account_metadata",
                        "Benford posting has no authenticated account type",
                    )
                })?;
                if u32::from(*actual) != settings.account_type {
                    continue;
                }
            }
            let one = 10u128
                .checked_pow(u32::from(*scale))
                .ok_or_else(arithmetic)?;
            let Some(minimum) = one.checked_mul(10) else {
                continue;
            };
            let mut magnitude = amount.unsigned_abs();
            if magnitude < minimum.max(10) {
                continue;
            }
            while magnitude >= 100 {
                magnitude /= 10;
            }
            let index = if settings.first_two {
                magnitude - 10
            } else {
                magnitude % 10
            };
            let index = usize::try_from(index).map_err(|_| arithmetic())?;
            let count = counts.get_mut(index).ok_or_else(arithmetic)?;
            *count = count.checked_add(1).ok_or_else(arithmetic)?;
        }
    }
    Ok((finish(settings, counts, probabilities)?, work_legs))
}

/// Continuity-corrected Z: floor(1000 * max(|O - E| - 1/2, 0)
/// / sqrt(n*p*(1-p))), retaining the native integer-square-root boundary.
fn max_z<const N: usize>(counts: &[u64; N], probabilities: &[u128; N]) -> Result<u64, ReportError> {
    let total = u128::from(population(counts)?);
    if total == 0 {
        return Ok(0);
    }
    let mut maximum = 0u128;
    for (&count, &probability) in counts.iter().zip(probabilities) {
        let observed = u128::from(count)
            .checked_mul(SCALE)
            .ok_or_else(arithmetic)?;
        let expected = total.checked_mul(probability).ok_or_else(arithmetic)?;
        // This deliberate floor belongs to a statistic, never a money balance.
        #[allow(clippy::manual_saturating_arithmetic)]
        let corrected = observed
            .abs_diff(expected)
            .checked_sub(SCALE / 2)
            .unwrap_or(0);
        let variance = SCALE
            .checked_sub(probability)
            .and_then(|complement| expected.checked_mul(complement))
            .ok_or_else(arithmetic)?;
        let score = corrected.checked_mul(1_000).ok_or_else(arithmetic)? / variance.isqrt().max(1);
        maximum = maximum.max(score);
    }
    u64::try_from(maximum).map_err(|_| arithmetic())
}

fn finish<const N: usize>(
    settings: Settings,
    counts: [u64; N],
    probabilities: &[u128; N],
) -> Result<VerifiedProcedureFinding, ReportError> {
    let population = population(&counts)?;
    if population < settings.minimum {
        return Ok(VerifiedProcedureFinding {
            entry: None,
            severity: 0,
            statistic: VerifiedProcedureStatistic::DigitPopulation {
                counts: counts.to_vec(),
            },
            population,
            narrative: format!(
                "population {population} is below the registered minimum {}; no conformity is claimed",
                settings.minimum
            ),
        });
    }
    let (mad, ks, chi_square_1e6) = statistics_for(&counts, probabilities)?;
    let max_z_milli = max_z(&counts, probabilities)?;
    let degrees = N - 1;
    let chi = if let Some(value) = chi_square_1e6 {
        format!(
            "chi-square {value}e-6 with {degrees} degrees of freedom, KS {ks}e-9, max Z {max_z_milli}e-3"
        )
    } else {
        format!(
            "chi-square not computed above {CHI_POPULATION_LIMIT} legs; KS {ks}e-9; max Z {max_z_milli}e-3; MAD is the scored statistic"
        )
    };
    let distribution = if settings.first_two {
        format!("first-two-digits over {population} legs")
    } else {
        format!("second-digit counts {counts:?} over {population} legs")
    };
    let Settings {
        close,
        acceptable,
        marginal,
        ..
    } = settings;
    Ok(VerifiedProcedureFinding {
        entry: None,
        severity: if mad <= close {
            0
        } else if mad <= acceptable {
            1
        } else if mad <= marginal {
            2
        } else {
            3
        },
        statistic: VerifiedProcedureStatistic::DigitMad {
            counts: counts.to_vec(),
            mad_1e9: mad,
            ks_1e9: ks,
            chi_square_1e6,
            max_z_milli,
        },
        population,
        narrative: format!(
            "{distribution}; MAD {mad}e-9 (close ≤ {close}e-9, acceptable ≤ {acceptable}e-9, marginal ≤ {marginal}e-9); {chi}"
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn profile(
        first_two: bool,
        minimum: u32,
        account_type: u32,
        currency: u32,
        side: u32,
    ) -> VerifiedProcedureParameters {
        if first_two {
            VerifiedProcedureParameters::FirstTwoDigits {
                account_type,
                currency_iso4217: currency,
                side,
                min_population: minimum,
                mad_close: 12,
                mad_acceptable: 18,
                mad_marginal: 22,
            }
        } else {
            VerifiedProcedureParameters::SecondDigit {
                account_type,
                currency_iso4217: currency,
                side,
                min_population: minimum,
                mad_close: 8,
                mad_acceptable: 10,
                mad_marginal: 12,
            }
        }
    }

    #[test]
    fn digit_tables_and_exact_statistics_have_independent_literal_witnesses() {
        assert_eq!(SECOND.iter().sum::<u128>(), SCALE);
        assert_eq!(FIRST_TWO.iter().sum::<u128>(), SCALE);
        for (digit, expected) in SECOND.iter().enumerate() {
            assert_eq!(
                (0..9)
                    .map(|first| FIRST_TWO[first * 10 + digit])
                    .sum::<u128>(),
                *expected
            );
        }
        assert_eq!(
            statistics_for(&[1; 10], &SECOND).unwrap(),
            (9_405_727, 47_028_636, Some(118_522))
        );
        assert_eq!(
            max_z(&[1; 10], &SECOND).unwrap(),
            0,
            "continuity correction floors each cell at zero"
        );
        assert_eq!(
            statistics_for(&[1; 90], &FIRST_TWO).unwrap(),
            (5_974_275, 268_842_383, Some(36_637_231))
        );
        assert_eq!(max_z(&[1; 90], &FIRST_TWO).unwrap(), 1_177);
        let second = finish(
            settings(profile(false, 0, 0, 840, 0)).unwrap(),
            [1; 10],
            &SECOND,
        )
        .unwrap();
        assert_eq!(second.severity, 1);
        let pair = finish(
            settings(profile(true, 0, 0, 840, 0)).unwrap(),
            [1; 90],
            &FIRST_TWO,
        )
        .unwrap();
        assert_eq!(
            pair.severity, 3,
            "first-two-digits thresholds use ten-thousandths"
        );
        assert!(pair.narrative.starts_with("first-two-digits over 90 legs;"));
        assert!(pair.narrative.ends_with("max Z 1177e-3"));
        for first_two in [false, true] {
            let mut settings = settings(profile(first_two, 0, 0, 840, 0)).unwrap();
            settings.close = 0;
            settings.acceptable = 0;
            settings.marginal = 10_000_000;
            let finding = if first_two {
                finish(settings, [1; 90], &FIRST_TWO)
            } else {
                finish(settings, [1; 10], &SECOND)
            }
            .unwrap();
            assert_eq!(finding.severity, 2);
            settings.close = 10_000_000;
            let finding = if first_two {
                finish(settings, [1; 90], &FIRST_TWO)
            } else {
                finish(settings, [1; 10], &SECOND)
            }
            .unwrap();
            assert_eq!(finding.severity, 0);
        }
    }

    #[test]
    fn digit_population_and_chi_square_bounds_do_not_change_the_claim() {
        let config = settings(profile(false, 500, 0, 840, 0)).unwrap();
        let mut counts = [0; 10];
        counts[0] = 499;
        let below = finish(config, counts, &SECOND).unwrap();
        assert_eq!(below.statistic.name(), "population");
        assert_eq!(below.severity, 0);
        assert!(below.narrative.ends_with("no conformity is claimed"));
        counts[0] = 1_000;
        let scored = finish(config, counts, &SECOND).unwrap();
        assert_eq!(
            scored.statistic,
            VerifiedProcedureStatistic::DigitMad {
                counts: counts.to_vec(),
                mad_1e9: 176_064_146,
                ks_1e9: 880_320_731,
                chi_square_1e6: Some(7_355_666_009),
                max_z_milli: 85_716,
            }
        );
        counts[0] = 1_000_000;
        assert!(statistics_for(&counts, &SECOND).unwrap().2.is_some());
        counts[0] += 1;
        let large = finish(config, counts, &SECOND).unwrap();
        assert!(matches!(
            large.statistic,
            VerifiedProcedureStatistic::DigitMad {
                chi_square_1e6: None,
                ..
            }
        ));
        assert!(
            large
                .narrative
                .contains("chi-square not computed above 1000000 legs;")
        );
        assert!(large.narrative.ends_with("MAD is the scored statistic"));
        let mut pair = [0; 90];
        pair[0] = 1_000;
        assert_eq!(
            statistics_for(&pair, &FIRST_TWO).unwrap(),
            (21_302_384, 958_607_315, Some(23_158_858_020))
        );
        assert_eq!(max_z(&pair, &FIRST_TWO).unwrap(), 152_100);
        assert!(statistics_for(&[u64::MAX; 90], &FIRST_TWO).is_err());
        assert!(max_z(&[u64::MAX; 10], &SECOND).is_err());
        assert_eq!(
            statistics_for(&[0; 90], &FIRST_TWO).unwrap(),
            (0, 0, Some(0))
        );
        assert_eq!(max_z(&[0; 90], &FIRST_TWO).unwrap(), 0);
    }

    #[test]
    fn digit_replay_selects_exact_ten_unit_magnitudes_currency_side_and_account_type() {
        let registry = Registry {
            unit_scales: BTreeMap::from([(1, 2), (2, 0), (3, 0), (4, 38)]),
            unit_currencies: BTreeMap::from([(1, 840), (2, 392), (4, 840)]),
            account_types: BTreeMap::from([(10, 5), (20, 1)]),
            trace: None,
            policy_oid: [0; 32],
        };
        let mut entry = Entry {
            identity: 1,
            digest: [1; 32],
            recorded_at: 1,
            effective: Some(1),
            class: 1,
            legs: vec![
                (1, 999),
                (1, 1_000),
                (1, 4_299),
                (1, -987_654),
                (1, i128::MIN),
                (1, 3_100),
                (1, 5_600),
                (2, 17),
                (3, 9_900),
                (4, i128::MAX),
            ],
            leg_accounts: vec![
                (10, true),
                (10, true),
                (10, true),
                (10, true),
                (10, true),
                (10, false),
                (20, true),
                (10, true),
                (10, true),
                (10, true),
            ],
            supersession: Vec::new(),
            settlements: Vec::new(),
            period: None,
            transition: None,
        };
        for first_two in [false, true] {
            for (currency, side, selected) in [
                (840, 0, vec![10, 42, 98, 17]),
                (840, 1, vec![31]),
                (392, 0, vec![17]),
            ] {
                let (finding, work) = replay(
                    profile(first_two, 1, 5, currency, side),
                    &[&entry],
                    &registry,
                )
                .unwrap();
                assert_eq!(
                    work, 10,
                    "work includes every visited leg, including exclusions"
                );
                let mut expected = vec![0; if first_two { 90 } else { 10 }];
                for digit in selected {
                    let index = if first_two { digit - 10 } else { digit % 10 };
                    expected[index] += 1;
                }
                let VerifiedProcedureStatistic::DigitMad { counts, .. } = finding.statistic else {
                    panic!("scored population");
                };
                assert_eq!(counts, expected);
            }
        }
        entry.leg_accounts.pop();
        assert_eq!(
            replay(profile(false, 1, 5, 840, 0), &[&entry], &registry)
                .unwrap_err()
                .predicate,
            "procedure_profile"
        );
    }

    fn frame(profile: VerifiedProcedureParameters, extended: bool, witnesses: usize) -> Vec<u8> {
        use crate::codec::Writer;
        let mut output = Writer::default();
        output
            .bytes(super::super::OUTPUT_FORMAT)
            .bytes(profile.id().as_bytes())
            .u16(2)
            .u8(0)
            .bytes(profile.evidence().as_bytes())
            .fixed(&[1; 16])
            .u64(1)
            .u8(0);
        super::super::parameters(&mut output, profile);
        output.count(0);
        let mut certificate = Writer::default();
        certificate
            .bytes(if extended {
                super::super::EXTENDED_FORMAT
            } else {
                super::super::FORMAT
            })
            .bytes(&[])
            .bytes(&[]);
        if extended {
            certificate.count(witnesses);
            for _ in 0..witnesses {
                certificate.bytes(&[]);
            }
        }
        certificate
            .fixed(&[0; 32])
            .u128(0)
            .fixed(&[0; 32])
            .bytes(&output.buf);
        let digest = super::super::framed_hash(super::super::DIGEST_DOMAIN, &certificate.buf);
        certificate.fixed(&digest);
        certificate.buf
    }

    #[test]
    fn extended_digit_frames_are_bounded_and_profile_specific() {
        for first_two in [false, true] {
            let profile = profile(first_two, 500, 5, 840, 0);
            let bytes = frame(profile, true, 6);
            assert!(super::super::recognizes(&bytes));
            assert_eq!(super::super::decode(&bytes).unwrap().parameters, profile);
            for count in [0, 5, 7] {
                assert!(super::super::decode(&frame(profile, true, count)).is_err());
            }
            assert!(
                super::super::decode(&frame(profile, false, 0)).is_err(),
                "do not downgrade a v2 native closure to v1"
            );
        }
        assert!(
            super::super::decode(&frame(
                VerifiedProcedureParameters::RoundAmounts { round_power: 3 },
                true,
                6
            ))
            .is_err(),
            "v2 framing does not admit unrelated profiles"
        );
    }
}
