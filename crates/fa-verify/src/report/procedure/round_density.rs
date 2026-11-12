//! Account round-amount density v1, refolded from authenticated live postings.
//!
//! Counts pool nonzero legs across both sides and all units. Each unit's scale
//! determines roundness; the baseline includes the account being tested. Only
//! citations are capped: neither the statistic nor its population is truncated.

use std::collections::BTreeMap;

use super::{
    Entry, MAX_CITES, MAX_FINDINGS, Reader, Registry, ReportError, VerifiedProcedureFinding,
    VerifiedProcedureParameters, VerifiedProcedureStatistic, failed, text,
};

pub(super) const DEFAULTS: [(&str, u32); 3] =
    [("min_legs", 20), ("round_power", 2), ("z_squared", 9)];

fn arithmetic() -> ReportError {
    failed(
        "procedure_arithmetic",
        "round-amount density exceeds its exact arithmetic bounds",
    )
}

pub(super) fn decode(reader: &mut Reader<'_>) -> Result<VerifiedProcedureParameters, ReportError> {
    if reader.count(DEFAULTS.len(), 20, "procedure.parameters")? != DEFAULTS.len() {
        return Err(failed(
            "procedure_profile",
            "round-amount density requires all three explicit parameters",
        ));
    }
    let mut values = [0u32; 3];
    for (index, (name, _)) in DEFAULTS.iter().enumerate() {
        if text(reader, 64, "procedure.parameter")? != *name {
            return Err(failed(
                "procedure_profile",
                "density parameter names must be complete, unique and lexically ordered",
            ));
        }
        values[index] = u32::try_from(reader.i128("procedure.parameter_value")?).map_err(|_| {
            failed(
                "procedure_profile",
                "density parameters must be unsigned 32-bit integers",
            )
        })?;
    }
    if values[1] > 30 || values[2] == 0 {
        return Err(failed(
            "procedure_profile",
            "density requires round_power at most 30 and z_squared at least 1",
        ));
    }
    Ok(VerifiedProcedureParameters::RoundAmountDensity {
        min_legs: values[0],
        round_power: values[1],
        z_squared: values[2],
    })
}

/// Compare the squared excess with its exact binomial variance. The v1
/// threshold is inclusive. Overflow of the optional fourfold High threshold
/// leaves a Medium finding; overflow in the actual test refuses the report.
fn severity(
    account_round: u64,
    account_total: u64,
    book_round: u64,
    book_total: u64,
    z_squared: u32,
) -> Result<Option<u8>, ReportError> {
    let observed = u128::from(account_round)
        .checked_mul(u128::from(book_total))
        .ok_or_else(arithmetic)?;
    let expected = u128::from(account_total)
        .checked_mul(u128::from(book_round))
        .ok_or_else(arithmetic)?;
    if book_round == 0 || book_round == book_total || observed <= expected {
        return Ok(None);
    }
    let excess = observed.checked_sub(expected).ok_or_else(arithmetic)?;
    let squared = excess.checked_mul(excess).ok_or_else(arithmetic)?;
    let nonround = book_total.checked_sub(book_round).ok_or_else(arithmetic)?;
    let variance = expected
        .checked_mul(u128::from(nonround))
        .ok_or_else(arithmetic)?;
    let threshold = variance
        .checked_mul(u128::from(z_squared))
        .ok_or_else(arithmetic)?;
    if squared < threshold {
        return Ok(None);
    }
    Ok(Some(
        if threshold.checked_mul(4).is_some_and(|high| squared >= high) {
            3
        } else {
            2
        },
    ))
}

#[derive(Default)]
struct Account {
    round: u64,
    nonzero: u64,
    citations: Vec<(u128, u16)>,
}

pub(super) fn replay(
    profile: VerifiedProcedureParameters,
    live: &[&Entry],
    registry: &Registry,
) -> Result<(Vec<VerifiedProcedureFinding>, u64, u64), ReportError> {
    let VerifiedProcedureParameters::RoundAmountDensity {
        min_legs,
        round_power,
        z_squared,
    } = profile
    else {
        return Err(failed("procedure_profile", "expected round-amount density"));
    };
    if round_power > 30 || z_squared == 0 {
        return Err(failed(
            "procedure_profile",
            "density requires round_power at most 30 and z_squared at least 1",
        ));
    }
    let factor = 10i128.checked_pow(round_power).ok_or_else(arithmetic)?;
    let mut ordered = live.to_vec();
    ordered.sort_unstable_by_key(|entry| (entry.recorded_at, entry.identity));
    let mut accounts: BTreeMap<u128, Account> = BTreeMap::new();
    let mut legs_visited = 0u64;
    for entry in ordered {
        if entry.legs.len() != entry.leg_accounts.len() {
            return Err(failed(
                "procedure_profile",
                "density leg account identities are incomplete",
            ));
        }
        legs_visited = legs_visited
            .checked_add(entry.legs.len() as u64)
            .ok_or_else(arithmetic)?;
        for (ordinal, (&(unit, amount), &(account, _))) in
            entry.legs.iter().zip(&entry.leg_accounts).enumerate()
        {
            // Zero legs still contribute work, but neither an account bucket
            // nor a unit-scale multiplication belongs to their v1 semantics.
            if amount == 0 {
                continue;
            }
            let scale = registry.unit_scales.get(&unit).ok_or_else(|| {
                failed("procedure_units", "density leg uses an unregistered unit")
            })?;
            let base = 10i128
                .checked_pow(u32::from(*scale))
                .and_then(|one| one.checked_mul(factor))
                .ok_or_else(arithmetic)?;
            let counts = accounts.entry(account).or_default();
            counts.nonzero = counts.nonzero.checked_add(1).ok_or_else(arithmetic)?;
            // Do not take abs(): negative multiples, including i128::MIN
            // when the base divides it, follow the same exact remainder law.
            if amount.checked_rem(base) == Some(0) {
                counts.round = counts.round.checked_add(1).ok_or_else(arithmetic)?;
                if counts.citations.len() < MAX_CITES - 1 {
                    counts.citations.push((
                        entry.identity,
                        u16::try_from(ordinal).map_err(|_| {
                            failed("bounded_input", "density leg ordinal exceeds u16")
                        })?,
                    ));
                }
            }
        }
    }
    let (book_round, book_total) = accounts.values().try_fold(
        (0u64, 0u64),
        |(round, total), account| -> Result<_, ReportError> {
            Ok((
                round.checked_add(account.round).ok_or_else(arithmetic)?,
                total.checked_add(account.nonzero).ok_or_else(arithmetic)?,
            ))
        },
    )?;
    // The native contract charges every nonempty account once, even if the
    // account has too few legs or no excess. Sort and arithmetic add no charge.
    let comparisons = accounts.len() as u64;
    let mut findings = Vec::new();
    for (account, counts) in accounts {
        if counts.nonzero < u64::from(min_legs) {
            continue;
        }
        let Some(severity) = severity(
            counts.round,
            counts.nonzero,
            book_round,
            book_total,
            z_squared,
        )?
        else {
            continue;
        };
        if findings.len() >= MAX_FINDINGS {
            return Err(failed(
                "bounded_input",
                "density findings exceed the certificate bound",
            ));
        }
        let (round, total) = (counts.round, counts.nonzero);
        findings.push(VerifiedProcedureFinding {
            entry: None,
            severity,
            statistic: VerifiedProcedureStatistic::AccountRoundLegs {
                account,
                count: round,
                legs: counts.citations,
            },
            population: total,
            narrative: format!(
                "{round} of {total} legs on this account are whole multiples of 10^{round_power} units, against {book_round} of {book_total} across the book (z^2 >= {z_squared})"
            ),
        });
    }
    Ok((findings, legs_visited, comparisons))
}

#[cfg(test)]
mod tests {
    use super::super::{
        Certificate, VerifiedProcedure, decode as decode_certificate, framed_hash,
        recompute_version, replay as replay_certificate,
    };
    use super::*;
    use crate::blake3::hash_parts;
    use crate::codec::Writer;

    const PROFILE: VerifiedProcedureParameters = VerifiedProcedureParameters::RoundAmountDensity {
        min_legs: 4,
        round_power: 2,
        z_squared: 4,
    };

    fn registry() -> Registry {
        Registry {
            unit_scales: BTreeMap::from([(1, 2), (2, 0), (3, 38)]),
            unit_currencies: BTreeMap::new(),
            account_types: BTreeMap::new(),
            trace: None,
            policy_oid: [7; 32],
        }
    }

    fn entry(id: u128, recorded_at: u64, amount: i128, accounts: (u128, u128)) -> Entry {
        Entry {
            identity: id,
            digest: hash_parts(b"density-test", &[&id.to_le_bytes()]),
            recorded_at,
            // Effective order deliberately differs from recording order.
            effective: Some((id % 20) as i32),
            class: 1,
            legs: vec![(1, amount), (1, amount)],
            leg_accounts: vec![(accounts.0, true), (accounts.1, false)],
            supersession: Vec::new(),
            settlements: Vec::new(),
            period: None,
            transition: None,
        }
    }

    fn population() -> Vec<Entry> {
        let mut entries = vec![
            entry(900, 2, 10_000, (1, 256)),
            entry(2, 1, 10_000, (1, 256)),
            entry(257, 1, 10_000, (1, 256)),
            entry(7, 4, 10_000, (1, 256)),
        ];
        for index in 0..4 {
            entries.push(entry(1000 + index, 10 + index as u64, 123, (2, 3)));
        }
        // Multiplying this unit's scale by the round factor would overflow;
        // zero legs must bypass that multiplication and every account count.
        let mut zero = entry(2000, 20, 0, (99, 100));
        zero.legs = vec![(3, 0), (3, 0)];
        entries.push(zero);
        entries
    }

    fn run(
        profile: VerifiedProcedureParameters,
        entries: Vec<Entry>,
    ) -> (VerifiedProcedure, Vec<u8>) {
        recompute_version([1; 16], 100_000, 1, None, profile, entries, &registry()).unwrap()
    }

    #[test]
    fn round_density_preserves_account_population_threshold_and_citation_order() {
        let entries = population();
        let (report, output) = run(PROFILE, entries.clone());
        assert_eq!(report.findings.len(), 2);
        assert_eq!(
            (
                report.population,
                report.live_entries,
                report.live_legs,
                report.comparisons
            ),
            (9, 9, 18, 4)
        );
        // Each selected account is 4/4 round against the book's 8/16:
        // (4*16 - 4*8)^2 / (4*8*(16-8)) = 4, exactly the threshold.
        // Canonical account bytes put 256 before 1; chronological ties put
        // numeric entry 2 before 257, preserving each entry's leg ordinal.
        for (finding, (expected_account, ordinal)) in report.findings.iter().zip([(256, 1), (1, 0)])
        {
            let VerifiedProcedureStatistic::AccountRoundLegs {
                account,
                count,
                legs,
            } = &finding.statistic
            else {
                panic!("account density statistic");
            };
            assert_eq!((*account, *count), (expected_account, 4));
            assert_eq!(finding.entry, None);
            assert_eq!(finding.population, 4);
            assert_eq!(finding.severity, 2);
            assert_eq!(
                legs,
                &vec![(2, ordinal), (257, ordinal), (900, ordinal), (7, ordinal)]
            );
            assert_eq!(
                finding.narrative,
                "4 of 4 legs on this account are whole multiples of 10^2 units, against 8 of 16 across the book (z^2 >= 4)"
            );
        }
        for (minimum, threshold, expected_count, expected_severity) in
            [(4, 1, 2, 3), (4, 5, 0, 0), (5, 4, 0, 0)]
        {
            let (variant, _) = run(
                VerifiedProcedureParameters::RoundAmountDensity {
                    min_legs: minimum,
                    round_power: 2,
                    z_squared: threshold,
                },
                entries.clone(),
            );
            assert_eq!(variant.findings.len(), expected_count);
            assert_eq!(variant.comparisons, 4);
            assert!(
                variant
                    .findings
                    .iter()
                    .all(|finding| finding.severity == expected_severity)
            );
        }
        let mut reversed_order = entries;
        reversed_order.reverse();
        assert_eq!(run(PROFILE, reversed_order).1, output);
    }

    #[test]
    fn round_density_pools_sides_and_units_using_each_units_scale() {
        let (expected, _) = run(PROFILE, population());
        let mut entries = population();
        entries[0].legs = vec![(1, -10_000), (1, -10_000)];
        entries[1].legs = vec![(2, 100), (2, 100)];
        entries[2].leg_accounts = vec![(1, false), (256, true)];
        entries[3].legs = vec![(2, -100), (2, -100)];
        let (mixed, _) = run(PROFILE, entries.clone());
        assert_eq!(mixed.findings, expected.findings);
        assert_eq!(mixed.live_legs, 18);
        assert_eq!(mixed.comparisons, 4);

        // 100 mantissa is round at scale 0, but is only 1.00 at scale 2.
        // After this change each target is 3/4 against 6/16: z^2 = 2.4.
        entries[1].legs = vec![(1, 100), (1, 100)];
        assert!(run(PROFILE, entries).0.findings.is_empty());

        let mut minimum = entry(1, 1, 1, (1, 256));
        minimum.legs = vec![(2, i128::MIN), (2, i128::MIN)];
        let (minimum, _) = run(
            VerifiedProcedureParameters::RoundAmountDensity {
                min_legs: 1,
                round_power: 0,
                z_squared: 1,
            },
            vec![minimum, entry(2, 2, 123, (2, 3))],
        );
        assert_eq!(minimum.findings.len(), 2, "no absolute-value overflow");
        assert!(
            minimum
                .findings
                .iter()
                .all(|finding| finding.population == 1)
        );
    }

    #[test]
    fn round_density_excludes_pending_reversals_and_rejects_changed_uncited_baseline() {
        let (expected, _) = run(PROFILE, population());
        let mut entries = population();
        let mut pending = entry(5000, 50, 10_000, (1, 256));
        pending.class = 2;
        let original = entry(5001, 60, 10_000, (2, 3));
        let mut reversal = entry(5002, 61, 10_000, (3, 2));
        reversal.class = 4;
        reversal
            .supersession
            .push((original.identity, original.digest, 1));
        entries.extend([pending, original, reversal]);
        let (report, output) = run(PROFILE, entries.clone());
        assert_eq!(report.findings, expected.findings);
        assert_eq!(
            (
                report.population,
                report.live_entries,
                report.live_legs,
                report.comparisons
            ),
            (12, 9, 18, 4)
        );
        let request = Certificate {
            source: &[],
            registry_digest: [0; 32],
            output: &output,
            digest: [0; 32],
            parameters: PROFILE,
            version: 1,
            book: [1; 16],
            known_at: 100_000,
            effective_through: None,
        };
        assert_eq!(
            replay_certificate(&request, [1; 16], 100_000, entries.clone(), &registry())
                .unwrap()
                .0,
            report
        );
        let mut missing = entries.clone();
        missing.retain(|entry| entry.identity != 1000);
        let mut changed = entries;
        changed
            .iter_mut()
            .find(|entry| entry.identity == 1000)
            .unwrap()
            .legs = vec![(1, 10_000), (1, 10_000)];
        for inputs in [missing, changed] {
            assert!(run(PROFILE, inputs.clone()).0.findings.is_empty());
            assert_eq!(
                replay_certificate(&request, [1; 16], 100_000, inputs, &registry())
                    .unwrap_err()
                    .predicate,
                "procedure_recomputation"
            );
        }
    }

    #[test]
    fn round_density_caps_citations_without_truncating_counts_or_work() {
        let mut entries = Vec::new();
        for index in 0..MAX_CITES {
            entries.push(entry(index as u128 + 1, index as u64 + 1, 10_000, (1, 256)));
            entries.push(entry(
                20_000 + index as u128,
                20_000 + index as u64,
                123,
                (2, 3),
            ));
        }
        let (report, _) = run(PROFILE, entries);
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.live_entries, (MAX_CITES * 2) as u64);
        assert_eq!(report.live_legs, (MAX_CITES * 4) as u64);
        assert_eq!(report.comparisons, 4);
        for finding in report.findings {
            let VerifiedProcedureStatistic::AccountRoundLegs { count, legs, .. } =
                finding.statistic
            else {
                panic!("account density statistic");
            };
            assert_eq!(count, MAX_CITES as u64);
            assert_eq!(finding.population, MAX_CITES as u64);
            assert_eq!(finding.severity, 3);
            assert_eq!(legs.len(), MAX_CITES - 1);
            assert_eq!(legs.first().unwrap().0, 1);
            assert_eq!(legs.last().unwrap().0, (MAX_CITES - 1) as u128);
        }
    }

    #[test]
    fn round_density_exact_arithmetic_handles_empty_baselines_and_overflow() {
        // A hand-computed z^2 of 11.25 is below 12 and above 11.
        assert_eq!(severity(10, 20, 24, 120, 9).unwrap(), Some(2));
        assert_eq!(severity(10, 20, 24, 120, 11).unwrap(), Some(2));
        assert_eq!(severity(10, 20, 24, 120, 12).unwrap(), None);
        assert_eq!(severity(10, 20, 24, 120, 2).unwrap(), Some(3));
        for (x, n, round, total) in [(0, 4, 0, 8), (4, 4, 8, 8), (2, 4, 4, 8), (1, 4, 4, 8)] {
            assert_eq!(severity(x, n, round, total, 1).unwrap(), None);
        }
        let large = 1u64 << 31;
        assert_eq!(
            severity(large, large, large, large * 4, u32::MAX).unwrap(),
            Some(2),
            "overflow of the optional fourfold High threshold retains Medium"
        );
        assert_eq!(
            severity(large * 2, large * 2, large * 2, large * 8, 1)
                .unwrap_err()
                .predicate,
            "procedure_arithmetic"
        );
        assert_eq!(
            severity(large + 1, large * 2, large * 4, large * 8, u32::MAX)
                .unwrap_err()
                .predicate,
            "procedure_arithmetic",
            "overflow of the actual threshold refuses"
        );
        assert!(run(PROFILE, Vec::new()).0.findings.is_empty());
        let mut too_large = entry(1, 1, 1, (1, 256));
        too_large.legs = vec![(3, 1), (3, 1)];
        assert_eq!(
            replay(PROFILE, &[&too_large], &registry())
                .unwrap_err()
                .predicate,
            "procedure_arithmetic"
        );
    }

    fn encoded(output: &[u8]) -> Vec<u8> {
        let mut certificate = Writer::default();
        certificate
            .bytes(super::super::FORMAT)
            .bytes(&[])
            .bytes(&[])
            .fixed(&[0; 32])
            .u128(1)
            .fixed(&[0; 32])
            .bytes(output);
        let digest = framed_hash(super::super::DIGEST_DOMAIN, &certificate.buf);
        certificate.fixed(&digest);
        certificate.buf
    }

    fn parameter_bytes(parameters: &[(&str, i128)]) -> Vec<u8> {
        let mut bytes = Writer::default();
        bytes.count(parameters.len());
        for &(name, amount) in parameters {
            bytes.bytes(name.as_bytes()).i128(amount);
        }
        bytes.buf
    }

    #[test]
    fn round_density_profile_refuses_wrong_versions_cutoffs_and_parameters() {
        let entries = population();
        let (_, output) = run(PROFILE, entries.clone());
        assert_eq!(
            decode_certificate(&encoded(&output)).unwrap().parameters,
            PROFILE
        );
        for (version, cutoff) in [(2, None), (1, Some(0))] {
            let (_, output) = recompute_version(
                [1; 16],
                100_000,
                version,
                cutoff,
                PROFILE,
                entries.clone(),
                &registry(),
            )
            .unwrap();
            assert_eq!(
                decode_certificate(&encoded(&output))
                    .err()
                    .expect("unsupported density profile")
                    .predicate,
                "procedure_profile"
            );
        }
        let valid = [("min_legs", 20), ("round_power", 2), ("z_squared", 9)];
        assert_eq!(
            decode(&mut Reader::new(&parameter_bytes(&valid)))
                .unwrap()
                .parameters(),
            DEFAULTS.to_vec()
        );
        for (index, value) in [
            (0, -1),
            (0, i128::from(u32::MAX) + 1),
            (1, 31),
            (2, 0),
            (2, i128::from(u32::MAX) + 1),
        ] {
            let mut invalid = valid;
            invalid[index].1 = value;
            assert!(decode(&mut Reader::new(&parameter_bytes(&invalid))).is_err());
        }
        for invalid in [
            valid[..2].to_vec(),
            vec![valid[1], valid[0], valid[2]],
            vec![valid[0], valid[0], valid[2]],
            vec![valid[0], valid[1], valid[2], ("extra", 1)],
        ] {
            assert!(decode(&mut Reader::new(&parameter_bytes(&invalid))).is_err());
        }
    }
}
