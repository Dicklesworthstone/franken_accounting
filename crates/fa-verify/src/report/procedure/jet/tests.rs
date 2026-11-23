use super::super::{EntryFacts, EntryPeriod, VerifiedProcedure, recompute_version};
use super::*;
use crate::blake3::hash_parts;
use crate::codec::Writer;

struct Fixture {
    entries: Vec<Entry>,
    registry: Registry,
}

impl Fixture {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            registry: Registry {
                unit_scales: BTreeMap::from([(1, 2), (2, 0), (3, 38)]),
                unit_currencies: BTreeMap::new(),
                account_types: BTreeMap::from([(10, 1), (20, 3), (30, 5)]),
                account_codes: BTreeMap::new(),
                account_roles: BTreeMap::new(),
                leg_parties: BTreeMap::new(),
                entry_facts: BTreeMap::new(),
                trace: None,
                open_items: None,
                policy_oid: [7; 32],
            },
        }
    }

    fn add(&mut self, identity: u128, principal: u128, origin: u8, accounts: &[u128]) {
        self.entries.push(Entry {
            identity,
            digest: hash_parts(b"jet-input", &[&identity.to_le_bytes()]),
            recorded_at: identity as u64,
            effective: Some(1),
            class: 1,
            legs: vec![(1, 100_000); accounts.len()],
            leg_accounts: accounts
                .iter()
                .map(|&account| (account, account == 10))
                .collect(),
            supersession: Vec::new(),
            settlements: Vec::new(),
            period: Some(EntryPeriod {
                code: "P1".into(),
                effective: 1,
                end: 31,
                document: None,
            }),
            transition: None,
        });
        self.registry
            .entry_facts
            .insert(identity, EntryFacts { principal, origin });
    }

    fn reverse(&mut self, identity: u128, target: u128, day: i32, period: &str) {
        let target = self
            .entries
            .iter()
            .find(|entry| entry.identity == target)
            .unwrap()
            .clone();
        let mut reversal = target.clone();
        reversal.identity = identity;
        reversal.digest = hash_parts(b"jet-reversal", &[&identity.to_le_bytes()]);
        reversal.recorded_at = identity as u64;
        reversal.effective = Some(day);
        reversal.class = 4;
        reversal.period = Some(EntryPeriod {
            code: period.into(),
            effective: day,
            end: day + 30,
            document: None,
        });
        reversal.supersession = vec![(target.identity, target.digest, 1)];
        self.entries.push(reversal);
    }

    fn run(&self, profile: VerifiedProcedureParameters) -> (VerifiedProcedure, Vec<u8>) {
        recompute_version(
            [3; 16],
            100,
            1,
            None,
            profile,
            self.entries.clone(),
            &self.registry,
        )
        .unwrap()
    }
}

#[test]
fn preparer_rarity_counts_entries_once_and_preserves_reversal_parity() {
    let mut f = Fixture::new();
    f.add(1, 80, 0, &[10, 20]);
    f.add(2, 80, 0, &[10, 20]);
    f.add(3, 90, 0, &[20, 10, 10]);
    let profile = VerifiedProcedureParameters::UnusualPreparers {
        max_preparer_count: 1,
        min_account_entries: 3,
    };
    let (original, encoded) = f.run(profile);
    assert_eq!(
        (
            original.population,
            original.live_entries,
            original.live_legs,
            original.comparisons
        ),
        (3, 3, 7, 3)
    );
    assert_eq!(original.findings.len(), 1);
    assert_eq!(original.findings[0].entry, Some(3));
    assert_eq!(original.findings[0].population, 3);
    assert_eq!(
        original.findings[0].statistic,
        VerifiedProcedureStatistic::PreparerAccountPostings {
            account: 10,
            count: 1
        }
    );
    f.entries.reverse();
    assert_eq!(
        f.run(profile).1,
        encoded,
        "input order cannot change the populations or tie break"
    );
    f.reverse(4, 3, 2, "P1");
    assert!(f.run(profile).0.findings.is_empty());
    f.reverse(5, 4, 3, "P1");
    assert_eq!(f.run(profile).0.findings, original.findings);
    f.registry.entry_facts.get_mut(&3).unwrap().principal = 80;
    assert!(
        f.run(profile).0.findings.is_empty(),
        "one preparer is never unusual against itself"
    );
    f.registry.entry_facts.remove(&3);
    assert_eq!(
        recompute_version([3; 16], 100, 1, None, profile, f.entries, &f.registry)
            .unwrap_err()
            .predicate,
        "procedure_profile"
    );
}

#[test]
fn manual_source_share_is_exact_and_other_origins_are_not_manual() {
    let mut f = Fixture::new();
    f.add(1, 80, 1, &[10, 20]);
    f.add(2, 80, 1, &[10, 20]);
    f.add(3, 90, 0, &[20, 10, 10]);
    let profile = VerifiedProcedureParameters::ManualVsRule {
        min_account_entries: 3,
        min_rule_share_bps: 6666,
    };
    let (report, _) = f.run(profile);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(
        (report.live_entries, report.live_legs, report.comparisons),
        (3, 7, 1)
    );
    assert_eq!(
        report.findings[0].statistic,
        VerifiedProcedureStatistic::RuleShare {
            account: 10,
            basis_points: 6666
        }
    );
    assert_eq!(report.findings[0].population, 3);
    assert!(
        f.run(VerifiedProcedureParameters::ManualVsRule {
            min_account_entries: 3,
            min_rule_share_bps: 6667
        })
        .0
        .findings
        .is_empty()
    );
    assert!(
        f.run(VerifiedProcedureParameters::ManualVsRule {
            min_account_entries: 0,
            min_rule_share_bps: u32::MAX
        })
        .0
        .findings
        .is_empty()
    );
    f.add(4, 90, 5, &[10, 20]);
    let (with_schedule, _) = f.run(VerifiedProcedureParameters::ManualVsRule {
        min_account_entries: 0,
        min_rule_share_bps: 5000,
    });
    assert_eq!(with_schedule.findings.len(), 1);
    assert_eq!(with_schedule.findings[0].entry, Some(3));
    assert_eq!(with_schedule.findings[0].population, 4);
    assert_eq!(
        with_schedule.comparisons, 1,
        "schedule-origin entries affect the denominator but are not manual"
    );
    f.reverse(5, 1, 2, "P1");
    assert!(
        f.run(profile).0.findings.is_empty(),
        "reversed rule postings leave the live denominator and numerator"
    );
}

#[test]
fn round_reversals_keep_all_history_and_use_whole_units_and_inclusive_windows() {
    let mut f = Fixture::new();
    f.add(1, 80, 0, &[10, 20]);
    f.entries[0].effective = Some(30);
    f.entries[0].period.as_mut().unwrap().effective = 30;
    f.reverse(2, 1, 31, "P2");
    f.reverse(3, 2, 61, "P3");
    let profile = VerifiedProcedureParameters::LargeRoundReversals {
        round_power: 3,
        window_days: 30,
    };
    let (report, bytes) = f.run(profile);
    assert_eq!(
        (
            report.population,
            report.live_entries,
            report.live_legs,
            report.comparisons
        ),
        (3, 3, 4, 2)
    );
    assert_eq!(report.findings.len(), 2);
    assert_eq!(
        report.findings[0].statistic,
        VerifiedProcedureStatistic::DaysToReversal {
            original: 2,
            reversal: 3,
            days: 30
        }
    );
    assert_eq!(
        report.findings[1].statistic,
        VerifiedProcedureStatistic::DaysToReversal {
            original: 1,
            reversal: 2,
            days: 1
        }
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.population == 3)
    );
    f.entries.reverse();
    assert_eq!(f.run(profile).1, bytes);
    assert_eq!(
        f.run(VerifiedProcedureParameters::LargeRoundReversals {
            round_power: 3,
            window_days: 29
        })
        .0
        .findings
        .len(),
        1
    );
    assert!(
        f.run(VerifiedProcedureParameters::LargeRoundReversals {
            round_power: 3,
            window_days: 0
        })
        .0
        .findings
        .is_empty()
    );
    for entry in &mut f.entries {
        for leg in &mut entry.legs {
            leg.1 = 1000;
        }
    }
    assert!(
        f.run(profile).0.findings.is_empty(),
        "USD 10 is not a thousand whole units"
    );
    for entry in &mut f.entries {
        for leg in &mut entry.legs {
            leg.0 = 2;
        }
    }
    assert_eq!(
        f.run(profile).0.findings.len(),
        2,
        "JPY 1000 is a thousand whole units"
    );
}

#[test]
fn reversal_days_widen_before_subtraction_and_round_base_overflow_refuses() {
    let mut f = Fixture::new();
    f.add(1, 80, 0, &[10, 20]);
    f.entries[0].effective = Some(i32::MIN);
    f.entries[0].period.as_mut().unwrap().effective = i32::MIN;
    f.reverse(2, 1, i32::MAX - 30, "P2");
    f.entries[1].effective = Some(i32::MAX);
    f.entries[1].period.as_mut().unwrap().effective = i32::MAX;
    let profile = VerifiedProcedureParameters::LargeRoundReversals {
        round_power: 3,
        window_days: u32::MAX,
    };
    assert_eq!(
        f.run(profile).0.findings[0].statistic,
        VerifiedProcedureStatistic::DaysToReversal {
            original: 1,
            reversal: 2,
            days: u32::MAX
        }
    );
    assert!(
        f.run(VerifiedProcedureParameters::LargeRoundReversals {
            round_power: 3,
            window_days: u32::MAX - 1
        })
        .0
        .findings
        .is_empty()
    );
    f.entries[0].legs[0].0 = 3;
    assert_eq!(
        recompute_version([3; 16], 100, 1, None, profile, f.entries, &f.registry)
            .unwrap_err()
            .predicate,
        "procedure_arithmetic"
    );
}

#[test]
fn jet_parameter_decode_rejects_incomplete_reordered_negative_and_unbounded_values() {
    for (id, names) in [
        (
            "jet.unusual_preparers",
            ["max_preparer_count", "min_account_entries"],
        ),
        (
            "jet.manual_vs_rule",
            ["min_account_entries", "min_rule_share_bps"],
        ),
        ("jet.large_round_reversals", ["round_power", "window_days"]),
    ] {
        for values in [[0, 0], [1, i128::from(u32::MAX)]] {
            let mut w = Writer::default();
            w.count(2);
            for (name, value) in names.iter().zip(values) {
                w.bytes(name.as_bytes()).i128(value);
            }
            assert!(decode(&mut Reader::new(&w.buf), id).is_ok());
        }
        for (first, second, values) in [
            (names[1], names[0], [1, 1]),
            (names[0], names[0], [1, 1]),
            (names[0], names[1], [-1, 1]),
            (names[0], names[1], [1, i128::from(u32::MAX) + 1]),
        ] {
            let mut w = Writer::default();
            w.count(2)
                .bytes(first.as_bytes())
                .i128(values[0])
                .bytes(second.as_bytes())
                .i128(values[1]);
            assert_eq!(
                decode(&mut Reader::new(&w.buf), id).unwrap_err().predicate,
                "procedure_profile"
            );
        }
    }
    let mut w = Writer::default();
    w.count(2)
        .bytes(b"round_power")
        .i128(31)
        .bytes(b"window_days")
        .i128(1);
    assert_eq!(
        decode(&mut Reader::new(&w.buf), "jet.large_round_reversals")
            .unwrap_err()
            .predicate,
        "procedure_profile"
    );
}
