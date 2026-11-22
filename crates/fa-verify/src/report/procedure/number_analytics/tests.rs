use super::super::{
    DIGEST_DOMAIN, EXTENDED_FORMAT, FORMAT, VerifiedProcedure, decode as decode_certificate,
    framed_hash, recompute_version,
};
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
                unit_scales: BTreeMap::from([(1, 2), (2, 0), (3, 2), (4, 2)]),
                unit_currencies: BTreeMap::from([(1, 840), (2, 392), (3, 978), (4, 840)]),
                account_types: BTreeMap::from([(10, 1), (20, 5), (30, 5), (99, 3)]),
                leg_parties: BTreeMap::new(),
                entry_facts: BTreeMap::new(),
                trace: None,
                open_items: None,
                policy_oid: [7; 32],
            },
        }
    }

    fn legs(&mut self, identity: u128, day: i32, legs: &[(u128, bool, u32, i128, Option<u128>)]) {
        self.registry.leg_parties.insert(
            identity,
            legs.iter().map(|(_, _, _, _, party)| *party).collect(),
        );
        self.entries.push(Entry {
            identity,
            digest: hash_parts(b"numeric-audit-test", &[&identity.to_le_bytes()]),
            recorded_at: u64::try_from(identity).unwrap(),
            effective: Some(day),
            class: 1,
            legs: legs
                .iter()
                .map(|(_, _, unit, amount, _)| (*unit, *amount))
                .collect(),
            leg_accounts: legs
                .iter()
                .map(|(account, debit, _, _, _)| (*account, *debit))
                .collect(),
            supersession: Vec::new(),
            settlements: Vec::new(),
            period: None,
            transition: None,
        });
    }

    fn post(
        &mut self,
        identity: u128,
        day: i32,
        account: u128,
        unit: u32,
        amount: i128,
        party: Option<u128>,
    ) {
        self.legs(
            identity,
            day,
            &[
                (account, true, unit, amount, party),
                (99, false, unit, amount, party),
            ],
        );
    }

    fn reverse(&mut self, identity: u128, target: u128) {
        let original = self
            .entries
            .iter()
            .find(|entry| entry.identity == target)
            .unwrap();
        let mut reversal = original.clone();
        reversal.identity = identity;
        reversal.digest = hash_parts(b"numeric-audit-test", &[&identity.to_le_bytes()]);
        reversal.recorded_at = u64::try_from(identity).unwrap();
        reversal.class = 4;
        reversal.supersession = vec![(target, original.digest, 1)];
        for (_, debit) in &mut reversal.leg_accounts {
            *debit = !*debit;
        }
        self.registry.leg_parties.insert(
            identity,
            self.registry.leg_parties.get(&target).unwrap().clone(),
        );
        self.entries.push(reversal);
    }

    fn run(
        &self,
        profile: VerifiedProcedureParameters,
    ) -> Result<(VerifiedProcedure, Vec<u8>), ReportError> {
        recompute_version(
            [1; 16],
            10_000,
            1,
            None,
            profile,
            self.entries.clone(),
            &self.registry,
        )
    }
}

fn rsf() -> VerifiedProcedureParameters {
    VerifiedProcedureParameters::RelativeSizeFactor {
        min_rsf_bps: 50_000,
        min_subset_size: 3,
    }
}

fn split(window_days: u32) -> VerifiedProcedureParameters {
    VerifiedProcedureParameters::ThresholdSplitting {
        currency_iso4217: 840,
        floor: 200,
        min_count: 2,
        threshold: 1_000,
        window_days,
    }
}

#[test]
fn exact_relative_size_ratio_covers_small_and_full_width_values() {
    for numerator in 1..=257i128 {
        for denominator in 1..=257i128 {
            assert_eq!(
                ratio_bps(numerator, denominator).unwrap(),
                numerator * 10_000 / denominator,
                "{numerator}/{denominator}"
            );
        }
    }
    assert_eq!(ratio_bps(i128::MAX, i128::MAX).unwrap(), 10_000);
    assert_eq!(ratio_bps(i128::MAX - 1, i128::MAX).unwrap(), 9_999);
    assert_eq!(ratio_bps(i128::MAX, i128::MAX / 2).unwrap(), 20_000);
    assert_eq!(ratio_bps(1, i128::MAX).unwrap(), 0);
    assert!(ratio_bps(i128::MAX, 1).is_err());
    assert!(ratio_bps(0, 1).is_err());
    assert!(ratio_bps(1, 0).is_err());
    assert!(ratio_bps(-1, 1).is_err());
}

#[test]
fn relative_size_groups_preserve_party_unit_side_and_complete_population() {
    let mut f = Fixture::new();
    for (id, amount) in [(1, 100), (2, 100), (3, 1_000)] {
        f.post(id, 0, 10, 1, amount, None);
    }
    for (id, account, amount) in [(4, 20, 50), (5, 30, 80), (6, 20, 400)] {
        f.post(id, 0, account, 1, amount, Some(77));
    }
    for (id, amount) in [(7, 9), (8, 10), (9, 12)] {
        f.post(id, 0, 20, 1, amount, Some(78));
    }
    for (id, amount) in [(10, 10), (11, 100), (12, 1_000)] {
        f.post(id, 0, 10, 2, amount, None);
    }
    f.post(13, 0, 10, 1, 0, None);
    f.post(14, 0, 10, 1, -20_000, None);
    let (report, _) = f.run(rsf()).unwrap();
    assert_eq!(
        (report.population, report.live_entries, report.live_legs),
        (14, 14, 28)
    );
    assert_eq!(report.comparisons, 12);
    assert_eq!(report.findings.len(), 3);
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.population == 12)
    );
    assert_eq!(
        report
            .findings
            .iter()
            .map(|finding| finding.severity)
            .collect::<Vec<_>>(),
        vec![3, 3, 2]
    );
    let party = report
        .findings
        .iter()
        .find(|finding| {
            matches!(
                finding.statistic,
                VerifiedProcedureStatistic::RelativeSizeFactor { account: None, .. }
            )
        })
        .unwrap();
    assert!(matches!(
        party.statistic,
        VerifiedProcedureStatistic::RelativeSizeFactor {
            basis_points: 50_000,
            largest_entry: 6,
            second_entry: 5,
            account: None,
        }
    ));
    // Removing this leg from its prior party leaves that group below the
    // minimum. Its new party does not acquire the other party's observations.
    f.registry.leg_parties.get_mut(&6).unwrap()[0] = Some(79);
    assert_eq!(f.run(rsf()).unwrap().0.findings.len(), 2);
}

#[test]
fn relative_size_canonical_ties_use_every_citation_and_numeric_entry_identity() {
    let mut f = Fixture::new();
    f.legs(
        500,
        0,
        &[
            (10, true, 1, 90, None),
            (20, true, 1, 90, None),
            (99, false, 1, 180, None),
        ],
    );
    f.post(1, 0, 10, 1, 10, None);
    f.post(256, 0, 20, 1, 10, None);
    let profile = VerifiedProcedureParameters::RelativeSizeFactor {
        min_rsf_bps: 10_000,
        min_subset_size: 2,
    };
    let (report, bytes) = f.run(profile).unwrap();
    assert_eq!(report.findings.len(), 2);
    let second_entries: Vec<_> = report
        .findings
        .iter()
        .map(|finding| match finding.statistic {
            VerifiedProcedureStatistic::RelativeSizeFactor { second_entry, .. } => second_entry,
            ref other => panic!("unexpected statistic {other:?}"),
        })
        .collect();
    assert_eq!(
        second_entries,
        vec![256, 1],
        "canonical identities compare little-endian bytes"
    );
    f.entries.reverse();
    assert_eq!(
        f.run(profile).unwrap().1,
        bytes,
        "source order cannot change ranking"
    );

    let mut equal = Fixture::new();
    equal.post(300, 0, 10, 1, 70, None);
    equal.post(7, 0, 10, 1, 70, None);
    let (report, _) = equal.run(profile).unwrap();
    assert!(matches!(
        report.findings[0].statistic,
        VerifiedProcedureStatistic::RelativeSizeFactor {
            largest_entry: 7,
            second_entry: 300,
            basis_points: 10_000,
            ..
        }
    ));
}

#[test]
fn numeric_audits_recompute_reversal_parity_and_keep_original_source_commitments() {
    let mut f = Fixture::new();
    f.post(1, 0, 10, 1, 800, None);
    f.post(2, 0, 10, 1, 100, None);
    f.post(3, 0, 10, 1, 100, None);
    let profiles = [
        rsf(),
        VerifiedProcedureParameters::ThresholdSplitting {
            currency_iso4217: 840,
            floor: 50,
            min_count: 2,
            threshold: 1_000,
            window_days: 0,
        },
    ];
    let original: Vec<_> = profiles
        .iter()
        .map(|&profile| f.run(profile).unwrap().0)
        .collect();
    assert!(original.iter().all(|report| report.findings.len() == 1));
    f.reverse(4, 1);
    for profile in profiles {
        let report = f.run(profile).unwrap().0;
        assert!(report.findings.is_empty());
        assert_eq!((report.population, report.live_entries), (4, 2));
    }
    f.reverse(5, 4);
    for (profile, before) in profiles.into_iter().zip(original) {
        let after = f.run(profile).unwrap().0;
        assert_eq!(after.findings, before.findings);
        assert_ne!(after.inputs_digest, before.inputs_digest);
        assert_eq!((after.population, after.live_entries), (5, 3));
    }
}

#[test]
fn split_windows_are_complete_greedy_and_support_the_full_civil_day_range() {
    let mut f = Fixture::new();
    for (id, day, amount) in [
        (1, 0, 300),
        (2, 6, 350),
        (3, 7, 350),
        (4, 8, 350),
        (5, 20, 600),
        (6, 21, 500),
    ] {
        f.post(id, day, 10, 1, amount, None);
    }
    let (report, _) = f.run(split(2)).unwrap();
    assert_eq!(report.comparisons, 6);
    assert_eq!(report.findings.len(), 2);
    assert!(matches!(
        &report.findings[0].statistic,
        VerifiedProcedureStatistic::SplitTotal {
            mantissa: 1_100,
            entries,
            ..
        }
            if entries == &[5, 6]
    ));
    assert!(matches!(
        &report.findings[1].statistic,
        VerifiedProcedureStatistic::SplitTotal {
            mantissa: 1_050,
            entries,
            ..
        }
            if entries == &[2, 3, 4]
    ));
    assert!(f.run(split(0)).unwrap().0.findings.is_empty());

    // An earlier window reaches the amount threshold but fails min_count;
    // its last observations must remain available to the next anchor.
    let mut overlap = Fixture::new();
    for (id, day, amount) in [
        (1, 0, 800),
        (2, 4, 300),
        (3, 5, 300),
        (4, 6, 300),
        (5, 7, 300),
    ] {
        overlap.post(id, day, 10, 1, amount, None);
    }
    let profile = VerifiedProcedureParameters::ThresholdSplitting {
        currency_iso4217: 840,
        floor: 200,
        min_count: 4,
        threshold: 1_000,
        window_days: 5,
    };
    let report = overlap.run(profile).unwrap().0;
    assert_eq!(report.findings.len(), 1);
    assert!(matches!(
        &report.findings[0].statistic,
        VerifiedProcedureStatistic::SplitTotal {
            mantissa: 1_200,
            entries,
            ..
        }
            if entries == &[2, 3, 4, 5]
    ));

    let mut extremes = Fixture::new();
    extremes.post(1, i32::MIN, 10, 1, 600, None);
    extremes.post(2, i32::MAX, 10, 1, 500, None);
    assert!(
        extremes
            .run(split(u32::MAX - 1))
            .unwrap()
            .0
            .findings
            .is_empty()
    );
    assert_eq!(extremes.run(split(u32::MAX)).unwrap().0.findings.len(), 1);
}

#[test]
fn split_wide_prefix_preserves_disjoint_windows_and_refuses_overflow() {
    let mut f = Fixture::new();
    let threshold = i128::MAX / 2;
    let amount = threshold - 1;
    for (id, day) in [(1, 0), (2, 0), (3, 10), (4, 10), (5, 20), (6, 20)] {
        f.post(id, day, 10, 1, amount, None);
    }
    let profile = VerifiedProcedureParameters::ThresholdSplitting {
        currency_iso4217: 840,
        floor: 1,
        min_count: 2,
        threshold,
        window_days: 0,
    };
    let (report, _) = f.run(profile).unwrap();
    assert_eq!(report.findings.len(), 3);
    for finding in report.findings {
        assert!(matches!(
            finding.statistic,
            VerifiedProcedureStatistic::SplitTotal { mantissa, .. }
                if mantissa == i128::MAX - 3
        ));
    }
    let wide = VerifiedProcedureParameters::ThresholdSplitting {
        currency_iso4217: 840,
        floor: 1,
        min_count: 2,
        threshold,
        window_days: 20,
    };
    assert_eq!(f.run(wide).unwrap_err().predicate, "procedure_arithmetic");

    let mut sum = Total::default();
    let zero = sum;
    sum = sum.add(i128::MAX).unwrap().add(i128::MAX).unwrap();
    let before = sum;
    sum = sum.add(123).unwrap();
    assert_eq!(sum.high, 1);
    assert_eq!(sum.since(before).unwrap(), 123);
    assert!(sum.since(zero).is_err());
}

#[test]
fn split_groups_follow_original_currency_and_party_leg_order() {
    let mut f = Fixture::new();
    f.legs(
        1,
        0,
        &[
            (10, true, 1, 600, Some(70)),
            (99, false, 1, 600, Some(71)),
            (20, true, 2, 100, Some(72)),
            (99, false, 2, 100, Some(72)),
        ],
    );
    f.post(2, 1, 30, 1, 500, Some(71));
    f.post(3, 1, 30, 1, 900, Some(70));
    f.post(4, 1, 30, 3, 500, Some(71));
    f.post(5, 1, 30, 4, 400, Some(71));
    let (report, _) = f.run(split(5)).unwrap();
    assert_eq!((report.live_legs, report.comparisons), (12, 4));
    assert_eq!(report.findings.len(), 1);
    assert!(matches!(
        &report.findings[0].statistic,
        VerifiedProcedureStatistic::SplitTotal {
            mantissa: 1_500,
            scale: 2,
            entries,
        }
            if entries == &[1, 2, 5]
    ));
}

fn parameter_bytes(parameters: &[(&str, i128)]) -> Vec<u8> {
    let mut w = Writer::default();
    w.count(parameters.len());
    for &(name, value) in parameters {
        w.bytes(name.as_bytes()).i128(value);
    }
    w.buf
}

fn frame(output: &[u8], extended: bool, count: usize) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(if extended { EXTENDED_FORMAT } else { FORMAT })
        .bytes(b"native source")
        .bytes(b"native approvals");
    if extended {
        w.count(count);
        for _ in 0..count {
            w.bytes(b"native population");
        }
    }
    w.fixed(&[3; 32]).u128(1).fixed(&[4; 32]).bytes(output);
    let digest = framed_hash(DIGEST_DOMAIN, &w.buf);
    w.fixed(&digest);
    w.buf
}

#[test]
fn numeric_audit_profiles_bind_exact_parameters_and_extended_framing() {
    let full = [
        ("currency_iso4217", 840),
        ("floor", 1i128 << 100),
        ("min_count", 2),
        ("threshold", i128::MAX),
        ("window_days", i128::from(u32::MAX)),
    ];
    let bytes = parameter_bytes(&full);
    let profile = decode(&mut Reader::new(&bytes), true).unwrap();
    assert_eq!(profile.parameters(), full);
    for (index, value) in [
        (0, 0),
        (0, 1_000),
        (1, 0),
        (1, i128::MAX),
        (2, 1),
        (2, i128::from(u32::MAX) + 1),
        (3, 1),
        (4, -1),
        (4, i128::from(u32::MAX) + 1),
    ] {
        let mut parameters = full;
        parameters[index].1 = value;
        assert!(decode(&mut Reader::new(&parameter_bytes(&parameters)), true).is_err());
    }
    let relative = [("min_rsf_bps", 50_000), ("min_subset_size", 3)];
    for parameters in [
        vec![],
        vec![("min_rsf_bps", 50_000)],
        vec![("min_rsf_bps", -1), ("min_subset_size", 3)],
        vec![("min_rsf_bps", 0), ("min_subset_size", 1)],
        vec![("min_subset_size", 3), ("min_rsf_bps", 50_000)],
        vec![("min_rsf_bps", 0), ("min_rsf_bps", 3)],
    ] {
        assert!(decode(&mut Reader::new(&parameter_bytes(&parameters)), false).is_err());
    }
    assert_eq!(
        decode(&mut Reader::new(&parameter_bytes(&relative)), false).unwrap(),
        rsf()
    );

    let mut f = Fixture::new();
    f.post(1, 0, 10, 1, 800, None);
    f.post(2, 0, 10, 1, 200, None);
    f.post(3, 0, 10, 1, 100, None);
    for profile in [rsf(), split(0)] {
        let (_, output) = f.run(profile).unwrap();
        let valid = frame(&output, true, 6);
        let decoded = decode_certificate(&valid).unwrap();
        assert_eq!(decoded.parameters, profile);
        for bytes in [
            frame(&output, false, 0),
            frame(&output, true, 5),
            frame(&output, true, 7),
        ] {
            assert!(decode_certificate(&bytes).is_err());
        }
        for (version, cutoff) in [(2, None), (1, Some(0))] {
            let (_, changed) = recompute_version(
                [1; 16],
                10_000,
                version,
                cutoff,
                profile,
                f.entries.clone(),
                &f.registry,
            )
            .unwrap();
            assert!(decode_certificate(&frame(&changed, true, 6)).is_err());
        }
    }
}

#[test]
fn numeric_audits_refuse_missing_facts_and_excessive_citations() {
    let mut f = Fixture::new();
    f.post(1, 0, 10, 1, 600, None);
    f.post(2, 0, 10, 1, 500, None);
    f.registry.leg_parties.remove(&1);
    assert_eq!(f.run(split(0)).unwrap_err().predicate, "procedure_profile");
    f.registry.leg_parties.insert(1, vec![None]);
    assert_eq!(f.run(split(0)).unwrap_err().predicate, "procedure_profile");
    let mut many = Fixture::new();
    for index in 0..=MAX_CITES {
        many.post(index as u128 + 1, 0, 10, 1, 500, None);
    }
    assert_eq!(many.run(split(0)).unwrap_err().predicate, "bounded_input");
}
