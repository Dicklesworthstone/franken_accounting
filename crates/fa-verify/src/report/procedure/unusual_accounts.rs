//! Independent unusual-account-pair replay under the registered v2 law.
//!
//! Each entry contributes a set of undirected pairs, formed from its distinct
//! debit and credit accounts in the authenticated historical chart. Counting
//! these sets independently avoids the producer's last-entry sentinel and
//! proves that split legs and both directions count only once. Amounts, account
//! types and narrative text do not decide pair membership.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    Entry, MAX_FINDINGS, Reader, Registry, ReportError, VerifiedProcedureFinding,
    VerifiedProcedureParameters, VerifiedProcedureStatistic, failed, text,
};

pub(super) const DEFAULTS: [(&str, u32); 2] = [("max_pair_count", 1), ("min_population", 5)];

type Pair = (u128, u128);

// Account pairs can expand quadratically from a small source. Refuse before
// expansion once their raw identities alone would exceed the report's 64 MiB
// input budget. No pair or contributing entry is dropped to fit this bound.
const MAX_PAIR_CANDIDATES: u64 =
    (super::MAX_REPORT_BUNDLE_BYTES / std::mem::size_of::<Pair>()) as u64;

fn arithmetic() -> ReportError {
    failed("procedure_arithmetic", "account-pair count overflows")
}

fn pair_budget(current: u64, additional: u64) -> Result<u64, ReportError> {
    current
        .checked_add(additional)
        .filter(|total| *total <= MAX_PAIR_CANDIDATES)
        .ok_or_else(|| {
            failed(
                "bounded_input",
                "account-pair expansion exceeds the independent replay budget; no pairs were omitted",
            )
        })
}

pub(super) fn decode(reader: &mut Reader<'_>) -> Result<VerifiedProcedureParameters, ReportError> {
    if reader.count(DEFAULTS.len(), 20, "procedure.parameters")? != DEFAULTS.len() {
        return Err(failed(
            "procedure_profile",
            "unusual accounts requires both explicit parameters",
        ));
    }
    let mut values = [0u32; 2];
    for (index, (name, _)) in DEFAULTS.iter().enumerate() {
        if text(reader, 64, "procedure.parameter")? != *name {
            return Err(failed(
                "procedure_profile",
                "account-pair parameter names must be complete, unique and lexically ordered",
            ));
        }
        values[index] = u32::try_from(reader.i128("procedure.parameter_value")?).map_err(|_| {
            failed(
                "procedure_profile",
                "account-pair parameters must be unsigned 32-bit integers",
            )
        })?;
    }
    Ok(VerifiedProcedureParameters::UnusualAccounts {
        max_pair_count: values[0],
        min_population: values[1],
    })
}

pub(super) fn replay(
    profile: VerifiedProcedureParameters,
    live: &[&Entry],
    registry: &Registry,
) -> Result<(Vec<VerifiedProcedureFinding>, u64, u64, u64), ReportError> {
    let VerifiedProcedureParameters::UnusualAccounts {
        max_pair_count,
        min_population,
    } = profile
    else {
        return Err(failed("procedure_profile", "expected unusual accounts"));
    };
    let population = live.len() as u64;
    if population < u64::from(min_population) {
        // The native law exits before visiting or charging any entry or leg.
        return Ok((Vec::new(), 0, 0, 0));
    }
    let mut occurrences: BTreeMap<Pair, u64> = BTreeMap::new();
    let mut entries = Vec::with_capacity(live.len());
    let mut legs = 0u64;
    let mut candidates = 0u64;
    for entry in live {
        if entry.legs.len() != entry.leg_accounts.len() {
            return Err(failed(
                "procedure_profile",
                "account-pair leg account identities are incomplete",
            ));
        }
        legs = legs
            .checked_add(entry.legs.len() as u64)
            .ok_or_else(arithmetic)?;
        let mut debits = BTreeSet::new();
        let mut credits = BTreeSet::new();
        for &(account, debit) in &entry.leg_accounts {
            if registry.account_types.contains_key(&account) {
                if debit {
                    debits.insert(account);
                } else {
                    credits.insert(account);
                }
            }
        }
        let expanded = (debits.len() as u64)
            .checked_mul(credits.len() as u64)
            .ok_or_else(arithmetic)?;
        candidates = pair_budget(candidates, expanded)?;
        let mut pairs = BTreeSet::new();
        for debit in debits {
            for &credit in &credits {
                pairs.insert((debit.min(credit), debit.max(credit)));
            }
        }
        for &pair in &pairs {
            let count = occurrences.entry(pair).or_default();
            *count = count.checked_add(1).ok_or_else(arithmetic)?;
        }
        entries.push((entry.identity, pairs));
    }
    // Reconstruct the native witness from authenticated side cardinalities:
    // every directed candidate is charged in each of its two passes, and each
    // entry is charged once more when its rarest pair is selected. The oracle
    // itself operates on the per-entry undirected sets above.
    let comparisons = candidates
        .checked_mul(2)
        .and_then(|value| value.checked_add(population))
        .ok_or_else(arithmetic)?;
    let mut findings = Vec::new();
    for (identity, pairs) in entries {
        let mut rarest: Option<(u64, Pair)> = None;
        for pair in pairs {
            let count = occurrences.get(&pair).ok_or_else(|| {
                failed(
                    "procedure_recomputation",
                    "account-pair frequency is absent",
                )
            })?;
            let candidate = (*count, pair);
            rarest = Some(rarest.map_or(candidate, |prior| prior.min(candidate)));
        }
        let Some((count, (first_account, second_account))) = rarest else {
            continue;
        };
        if count > u64::from(max_pair_count) {
            continue;
        }
        if findings.len() >= MAX_FINDINGS {
            return Err(failed(
                "bounded_input",
                "account-pair findings exceed the certificate bound",
            ));
        }
        findings.push(VerifiedProcedureFinding {
            entry: Some(identity),
            severity: 1,
            statistic: VerifiedProcedureStatistic::AccountPairOccurrences {
                first_account,
                second_account,
                count,
            },
            population,
            narrative: format!(
                "debit/credit account pair ({first_account:032x}, {second_account:032x}) occurs {count} time(s) in {population} live postings (max_pair_count {max_pair_count})"
            ),
        });
    }
    Ok((findings, population, legs, comparisons))
}

#[cfg(test)]
mod tests {
    use super::super::{VerifiedProcedure, recompute_version};
    use super::*;
    use crate::blake3::hash_parts;
    use crate::codec::Writer;

    const PROFILE: VerifiedProcedureParameters = VerifiedProcedureParameters::UnusualAccounts {
        max_pair_count: 1,
        min_population: 4,
    };

    fn registry() -> Registry {
        Registry {
            unit_scales: BTreeMap::from([(1, 2)]),
            unit_currencies: BTreeMap::from([(1, 840)]),
            account_types: BTreeMap::from([(10, 1), (20, 1), (30, 3)]),
            leg_parties: BTreeMap::new(),
            trace: None,
            open_items: None,
            policy_oid: [7; 32],
        }
    }

    fn entry(identity: u128, sides: &[(u128, bool)]) -> Entry {
        Entry {
            identity,
            digest: hash_parts(b"pair-test", &[&identity.to_le_bytes()]),
            recorded_at: identity as u64,
            effective: Some(1),
            class: 1,
            legs: vec![(1, 100); sides.len()],
            leg_accounts: sides.to_vec(),
            supersession: Vec::new(),
            settlements: Vec::new(),
            period: None,
            transition: None,
        }
    }

    fn population() -> Vec<Entry> {
        vec![
            entry(
                1,
                &[
                    (10, true),
                    (10, true),
                    (20, true),
                    (10, false),
                    (20, false),
                    (20, false),
                ],
            ),
            entry(2, &[(10, true), (20, false)]),
            entry(3, &[(20, true), (10, false)]),
            entry(4, &[(10, true), (30, false)]),
        ]
    }

    fn run(
        profile: VerifiedProcedureParameters,
        entries: Vec<Entry>,
    ) -> (VerifiedProcedure, Vec<u8>) {
        recompute_version([1; 16], 100, 2, None, profile, entries, &registry()).unwrap()
    }

    #[test]
    fn account_pairs_count_split_and_reciprocal_legs_once_and_choose_the_rarest_pair() {
        let entries = population();
        let (report, bytes) = run(PROFILE, entries.clone());
        assert_eq!(
            (
                report.population,
                report.live_entries,
                report.live_legs,
                report.comparisons
            ),
            (4, 4, 12, 18)
        );
        assert_eq!(report.findings.len(), 2);
        for (finding, (identity, pair)) in
            report.findings.iter().zip([(1, (10, 10)), (4, (10, 30))])
        {
            assert_eq!(finding.entry, Some(identity));
            assert_eq!(finding.severity, 1);
            assert_eq!(finding.population, 4);
            assert_eq!(
                finding.statistic,
                VerifiedProcedureStatistic::AccountPairOccurrences {
                    first_account: pair.0,
                    second_account: pair.1,
                    count: 1,
                }
            );
        }
        let mut reordered = entries;
        reordered.reverse();
        for entry in &mut reordered {
            entry.legs.reverse();
            entry.leg_accounts.reverse();
        }
        assert_eq!(run(PROFILE, reordered).1, bytes);
        let (all, _) = run(
            VerifiedProcedureParameters::UnusualAccounts {
                max_pair_count: 3,
                min_population: 4,
            },
            population(),
        );
        assert_eq!(all.findings.len(), 4);
        assert!(
            all.findings
                .iter()
                .filter(|finding| matches!(finding.entry, Some(2 | 3)))
                .all(|finding| {
                    finding.statistic
                        == VerifiedProcedureStatistic::AccountPairOccurrences {
                            first_account: 10,
                            second_account: 20,
                            count: 3,
                        }
                })
        );
    }

    #[test]
    fn account_pair_minimum_precedes_work_and_zero_threshold_never_reports() {
        for minimum in [0, 4, 5, u32::MAX] {
            let (report, _) = run(
                VerifiedProcedureParameters::UnusualAccounts {
                    max_pair_count: 1,
                    min_population: minimum,
                },
                population(),
            );
            assert_eq!(report.population, 4);
            assert_eq!(report.findings.len(), if minimum <= 4 { 2 } else { 0 });
            assert_eq!(
                (report.live_entries, report.live_legs, report.comparisons),
                if minimum <= 4 { (4, 12, 18) } else { (0, 0, 0) }
            );
        }
        let (report, _) = run(
            VerifiedProcedureParameters::UnusualAccounts {
                max_pair_count: 0,
                min_population: 0,
            },
            population(),
        );
        assert!(report.findings.is_empty());
        assert_eq!(
            (report.live_entries, report.live_legs, report.comparisons),
            (4, 12, 18)
        );
    }

    #[test]
    fn account_pairs_use_authenticated_chart_membership_and_preserve_zero_legs() {
        let mut entries = population();
        entries[3].legs.fill((1, 0));
        let refs: Vec<_> = entries.iter().collect();
        let before = replay(PROFILE, &refs, &registry()).unwrap();
        assert_eq!(
            before.0.len(),
            2,
            "amounts do not change the account-pair law"
        );
        let mut declared = registry();
        declared.account_types.remove(&30);
        let after = replay(PROFILE, &refs, &declared).unwrap();
        assert_eq!((after.0.len(), after.1, after.2, after.3), (1, 4, 12, 16));
        declared.account_types.clear();
        let none = replay(PROFILE, &refs, &declared).unwrap();
        assert_eq!((none.0.len(), none.1, none.2, none.3), (0, 4, 12, 4));
        entries[0].leg_accounts.pop();
        assert_eq!(
            replay(PROFILE, &entries.iter().collect::<Vec<_>>(), &registry())
                .unwrap_err()
                .predicate,
            "procedure_profile"
        );
    }

    #[test]
    fn account_pair_history_nets_reversals_without_counting_controls_or_pending() {
        let mut entries = population();
        let mut undo = entry(5, &[(10, false), (30, true)]);
        undo.class = 4;
        undo.supersession = vec![(4, entries[3].digest, 1)];
        entries.push(undo);
        let mut control = entry(6, &[]);
        control.class = 100;
        entries.push(control);
        let mut pending = entry(7, &[(10, true), (30, false)]);
        pending.class = 2;
        entries.push(pending);
        let profile = VerifiedProcedureParameters::UnusualAccounts {
            max_pair_count: 1,
            min_population: 0,
        };
        let (reversed, _) = run(profile, entries.clone());
        assert_eq!(
            (
                reversed.population,
                reversed.live_entries,
                reversed.live_legs,
                reversed.comparisons
            ),
            (7, 3, 10, 15)
        );
        assert_eq!(reversed.findings.len(), 1);
        assert_eq!(reversed.findings[0].entry, Some(1));
        let mut restore = entry(8, &[(10, true), (30, false)]);
        restore.class = 4;
        restore.supersession = vec![(5, entries[4].digest, 1)];
        entries.push(restore);
        let (restored, _) = run(profile, entries);
        assert_eq!(restored.findings, run(profile, population()).0.findings);
        assert_eq!(
            (
                restored.population,
                restored.live_entries,
                restored.comparisons
            ),
            (8, 4, 18)
        );
    }

    #[test]
    fn account_pair_budget_refuses_dense_expansion_before_allocating_the_pairs() {
        for total in [MAX_PAIR_CANDIDATES - 1, MAX_PAIR_CANDIDATES] {
            assert_eq!(pair_budget(total - 1, 1).unwrap(), total);
        }
        for (used, more) in [(MAX_PAIR_CANDIDATES, 1), (u64::MAX, 1)] {
            assert_eq!(
                pair_budget(used, more).unwrap_err().predicate,
                "bounded_input"
            );
        }
        let sides: Vec<_> = (0..4096).map(|account| (account, account < 2048)).collect();
        let dense = entry(1, &sides);
        let mut registry = registry();
        registry.account_types = (0..4096).map(|account| (account, 1)).collect();
        assert_eq!(
            replay(
                VerifiedProcedureParameters::UnusualAccounts {
                    max_pair_count: 1,
                    min_population: 1,
                },
                &[&dense],
                &registry
            )
            .unwrap_err()
            .predicate,
            "bounded_input"
        );
    }

    #[test]
    fn account_pair_parameters_require_complete_ordered_unsigned_values() {
        for value in [0, i128::from(u32::MAX)] {
            let mut bytes = Writer::default();
            bytes
                .count(2)
                .bytes(b"max_pair_count")
                .i128(value)
                .bytes(b"min_population")
                .i128(value);
            assert_eq!(
                decode(&mut Reader::new(&bytes.buf)).unwrap(),
                VerifiedProcedureParameters::UnusualAccounts {
                    max_pair_count: value as u32,
                    min_population: value as u32,
                }
            );
        }
        for (first, value, second) in [
            ("max_pair_count", -1, "min_population"),
            ("max_pair_count", i128::from(u32::MAX) + 1, "min_population"),
            ("min_population", 1, "max_pair_count"),
            ("max_pair_count", 1, "max_pair_count"),
        ] {
            let mut bytes = Writer::default();
            bytes
                .count(2)
                .bytes(first.as_bytes())
                .i128(value)
                .bytes(second.as_bytes())
                .i128(5);
            assert!(decode(&mut Reader::new(&bytes.buf)).is_err());
        }
        let mut missing = Writer::default();
        missing.count(1).bytes(b"max_pair_count").i128(1);
        assert!(decode(&mut Reader::new(&missing.buf)).is_err());
    }
}
