use super::*;
use crate::blake3::hash_parts;
use crate::codec::Writer;
use crate::report::procedure::{
    Certificate, VerifiedProcedure, decode as decode_certificate, finding, framed_hash,
};

const BOOK: [u8; 16] = [1; 16];
const FRONTIER: u64 = 1_000;
const PROFILE: VerifiedProcedureParameters = VerifiedProcedureParameters::RelativeSizeFactor {
    min_rsf_bps: 50_000,
    min_subset_size: 3,
};

type Leg = (u128, bool, u32, i128, Option<u128>);

/// Keep source facts together in tests, then supply them through production's
/// authenticated per-entry party map at the replay boundary.
#[derive(Clone)]
struct SourceEntry {
    entry: Entry,
    leg_parties: Vec<Option<u128>>,
}

impl std::ops::Deref for SourceEntry {
    type Target = Entry;

    fn deref(&self) -> &Entry {
        &self.entry
    }
}

impl std::ops::DerefMut for SourceEntry {
    fn deref_mut(&mut self) -> &mut Entry {
        &mut self.entry
    }
}

fn bound_registry<'a>(
    entries: impl IntoIterator<Item = &'a SourceEntry>,
    registry: &Registry,
) -> Registry {
    let mut leg_parties = registry.leg_parties.clone();
    for entry in entries {
        leg_parties.insert(entry.identity, entry.leg_parties.clone());
    }
    Registry {
        unit_scales: registry.unit_scales.clone(),
        unit_currencies: registry.unit_currencies.clone(),
        account_types: registry.account_types.clone(),
        leg_parties,
        trace: registry.trace.clone(),
        open_items: registry.open_items.clone(),
        policy_oid: registry.policy_oid,
    }
}

fn recompute_version(
    book: [u8; 16],
    known_at: u64,
    version: u16,
    effective_through: Option<i32>,
    profile: VerifiedProcedureParameters,
    entries: Vec<SourceEntry>,
    registry: &Registry,
) -> Result<(VerifiedProcedure, Vec<u8>), ReportError> {
    let registry = bound_registry(&entries, registry);
    crate::report::procedure::recompute_version(
        book,
        known_at,
        version,
        effective_through,
        profile,
        entries.into_iter().map(|entry| entry.entry).collect(),
        &registry,
    )
}

fn replay_certificate(
    request: &Certificate<'_>,
    book: [u8; 16],
    known_at: u64,
    entries: Vec<SourceEntry>,
    registry: &Registry,
) -> Result<(VerifiedProcedure, Vec<u8>), ReportError> {
    let registry = bound_registry(&entries, registry);
    crate::report::procedure::replay(
        request,
        book,
        known_at,
        entries.into_iter().map(|entry| entry.entry).collect(),
        &registry,
    )
}

fn replay(
    profile: VerifiedProcedureParameters,
    entries: &[&SourceEntry],
    registry: &Registry,
) -> Result<(Vec<VerifiedProcedureFinding>, u64, u64), ReportError> {
    let registry = bound_registry(entries.iter().copied(), registry);
    let entries: Vec<_> = entries.iter().map(|entry| &entry.entry).collect();
    super::super::replay(profile, &entries, &registry)
}

fn registry() -> Registry {
    Registry {
        unit_scales: BTreeMap::from([(1, 2), (2, 0)]),
        unit_currencies: BTreeMap::from([(1, 840), (2, 392)]),
        account_types: [10, 20, 30, 40, 77].into_iter().map(|id| (id, 1)).collect(),
        leg_parties: BTreeMap::new(),
        trace: None,
        open_items: None,
        policy_oid: [7; 32],
    }
}

fn entry(identity: u128, facts: &[Leg]) -> SourceEntry {
    SourceEntry {
        entry: Entry {
            identity,
            digest: hash_parts(b"relative-size-test", &[&identity.to_le_bytes()]),
            recorded_at: identity as u64,
            effective: Some(1),
            class: 1,
            legs: facts
                .iter()
                .map(|&(_, _, unit, amount, _)| (unit, amount))
                .collect(),
            leg_accounts: facts
                .iter()
                .map(|&(account, debit, _, _, _)| (account, debit))
                .collect(),
            supersession: Vec::new(),
            settlements: Vec::new(),
            period: None,
            transition: None,
        },
        leg_parties: facts.iter().map(|&(_, _, _, _, party)| party).collect(),
    }
}

fn population() -> Vec<SourceEntry> {
    vec![
        entry(
            1,
            &[
                (10, true, 1, 5_000, None),
                (20, true, 1, 2_000, Some(77)),
                (30, true, 2, 9_000, Some(77)),
                (20, false, 1, i128::MAX, Some(77)),
                (20, true, 1, 0, Some(77)),
                (20, true, 1, -999, Some(77)),
            ],
        ),
        entry(
            256,
            &[
                (10, true, 1, 1_000, None),
                (30, true, 1, 200, Some(77)),
                (10, true, 2, 3_000, Some(77)),
            ],
        ),
        entry(
            2,
            &[
                (10, true, 1, 500, None),
                (10, true, 1, 100, Some(77)),
                (20, true, 2, 1_000, Some(77)),
            ],
        ),
        entry(3, &[(77, true, 1, 100, None)]),
        entry(4, &[(77, true, 1, 10, None)]),
        entry(5, &[(77, true, 1, 5, None)]),
    ]
}

fn run(
    profile: VerifiedProcedureParameters,
    entries: Vec<SourceEntry>,
) -> (VerifiedProcedure, Vec<u8>) {
    recompute_version(BOOK, FRONTIER, 1, None, profile, entries, &registry()).unwrap()
}

fn encoded(output: &[u8], extended: bool) -> Vec<u8> {
    let mut certificate = Writer::default();
    certificate
        .bytes(if extended {
            b"fa:procedure-certificate:v2"
        } else {
            b"fa:procedure-certificate:v1"
        })
        .bytes(&[])
        .bytes(&[]);
    if extended {
        certificate.count(6);
        for _ in 0..6 {
            certificate.bytes(&[]);
        }
    }
    certificate
        .fixed(&[0; 32])
        .u128(1)
        .fixed(&[0; 32])
        .bytes(output);
    let digest = framed_hash(b"fa:procedure-certificate-digest:v1", &certificate.buf);
    certificate.fixed(&digest);
    certificate.buf
}

#[test]
fn relative_size_separates_parties_accounts_and_native_units_and_counts_every_eligible_leg() {
    let entries = population();
    let (report, output) = run(PROFILE, entries.clone());
    assert_eq!(
        (
            report.population,
            report.live_entries,
            report.live_legs,
            report.comparisons
        ),
        (6, 6, 15, 12)
    );
    assert_eq!(report.findings.len(), 3);
    for (actual, (entry, severity, bps, second_entry, account)) in report.findings.iter().zip([
        (1, 3, 100_000, 256, None),
        (3, 3, 100_000, 4, Some(77)),
        (1, 2, 50_000, 256, Some(10)),
    ]) {
        assert_eq!(actual.entry, Some(entry));
        assert_eq!(actual.severity, severity);
        assert_eq!(actual.population, 12);
        assert_eq!(
            actual.statistic,
            VerifiedProcedureStatistic::RelativeSizeFactor {
                basis_points: bps,
                largest_entry: entry,
                second_entry,
                account,
            }
        );
    }
    assert_eq!(
        report.findings[0].narrative,
        "largest debit 2000 vs second-largest 200 across 3 postings yields RSF 100000 bps (min_rsf_bps 50000)"
    );
    assert_eq!(
        report.findings[2].narrative,
        "largest debit 5000 vs second-largest 1000 across 3 postings yields RSF 50000 bps (min_rsf_bps 50000)"
    );
    let mut permuted = entries;
    permuted.reverse();
    for entry in &mut permuted {
        entry.legs.reverse();
        entry.leg_accounts.reverse();
        entry.leg_parties.reverse();
    }
    assert_eq!(run(PROFILE, permuted).1, output);
}

#[test]
fn relative_size_uses_numeric_maximum_ties_but_complete_canonical_citation_order() {
    let entries = vec![
        entry(
            1,
            &[
                (10, true, 1, 100, None),
                (20, true, 1, 10, None),
                (30, true, 1, 100, None),
                (40, true, 1, 100, None),
                (40, true, 1, 100, None),
            ],
        ),
        entry(2, &[(10, true, 1, 100, None), (30, true, 1, 100, None)]),
        entry(256, &[(20, true, 1, 10, None)]),
    ];
    let profile = VerifiedProcedureParameters::RelativeSizeFactor {
        min_rsf_bps: 10_000,
        min_subset_size: 2,
    };
    let (report, _) = run(profile, entries);
    assert_eq!(report.findings.len(), 4);
    let accounts: Vec<_> = report
        .findings
        .iter()
        .map(|finding| {
            assert_eq!(
                finding.entry,
                Some(1),
                "equal maxima use numeric entry order"
            );
            assert_eq!(finding.statistic.value(), 10_000);
            let VerifiedProcedureStatistic::RelativeSizeFactor { account, .. } = finding.statistic
            else {
                unreachable!()
            };
            account.unwrap()
        })
        .collect();
    assert_eq!(
        accounts,
        [20, 10, 30, 40],
        "second entry 256 sorts before 2 in canonical little-endian bytes"
    );
    let repeated = report.findings.last().unwrap();
    let mut bytes = Writer::default();
    finding(&mut bytes, repeated, profile, 1).unwrap();
    let mut reader = Reader::new(&bytes.buf);
    reader.bytes(128, "id").unwrap();
    reader.u16("version").unwrap();
    reader.u8("severity").unwrap();
    reader.bytes(128, "statistic").unwrap();
    reader.i128("value").unwrap();
    reader.u8("scale").unwrap();
    reader.u64("population").unwrap();
    assert_eq!(reader.count(3, 17, "citations").unwrap(), 2);
    assert_eq!(
        (reader.u8("tag").unwrap(), reader.u128("entry").unwrap()),
        (1, 1)
    );
    assert_eq!(
        (reader.u8("tag").unwrap(), reader.u128("account").unwrap()),
        (3, 40)
    );
}

#[test]
fn relative_size_ratios_remain_exact_across_i128_product_overflow_and_refuse_true_overflow() {
    for (largest, second, expected) in [
        (i128::MAX, i128::MAX, 10_000),
        (i128::MAX, i128::MAX - 1, 10_000),
        (i128::MAX, i128::MAX / 2, 20_000),
        (i128::MAX, 10_000, i128::MAX),
        (19, 3, 63_333),
        (10_001, 10_000, 10_001),
    ] {
        assert_eq!(basis_points(largest, second).unwrap(), expected);
        assert_eq!(super::super::ratio_bps(largest, second).unwrap(), expected);
    }
    for (largest, second) in [(i128::MAX, 9_999), (i128::MAX, 1), (1, 0), (0, 1), (-1, 1)] {
        assert_eq!(
            basis_points(largest, second).unwrap_err().predicate,
            "procedure_arithmetic"
        );
    }
    for largest in 1..=257 {
        for second in 1..=127 {
            assert_eq!(
                basis_points(largest, second).unwrap(),
                largest * 10_000 / second
            );
            assert_eq!(
                super::super::ratio_bps(largest, second).unwrap(),
                largest * 10_000 / second
            );
        }
    }
    // Compare production's binary construction with the independent decimal
    // oracle where no narrow multiplied reference value can be formed.
    for largest in [
        1,
        9_999,
        10_001,
        1i128 << 100,
        i128::MAX / 2,
        i128::MAX - 1,
        i128::MAX,
    ] {
        for second in [
            1,
            3,
            9_999,
            10_000,
            10_001,
            1i128 << 99,
            i128::MAX / 2,
            i128::MAX,
        ] {
            assert_eq!(
                super::super::ratio_bps(largest, second).ok(),
                basis_points(largest, second).ok(),
                "independent exact ratio {largest}/{second}"
            );
        }
    }
    let entries = vec![
        entry(1, &[(10, true, 1, i128::MAX, None)]),
        entry(2, &[(10, true, 1, 10_000, None)]),
    ];
    let profile = VerifiedProcedureParameters::RelativeSizeFactor {
        min_rsf_bps: 0,
        min_subset_size: 2,
    };
    assert_eq!(
        run(profile, entries.clone()).0.findings[0]
            .statistic
            .value(),
        i128::MAX
    );
    let mut unrepresentable = entries;
    unrepresentable[1].legs[0].1 = 9_999;
    assert_eq!(
        recompute_version(
            BOOK,
            FRONTIER,
            1,
            None,
            profile,
            unrepresentable,
            &registry()
        )
        .unwrap_err()
        .predicate,
        "procedure_arithmetic"
    );
}

#[test]
fn relative_size_honors_subset_and_threshold_boundaries_without_dropping_work() {
    let entries = vec![
        entry(1, &[(10, true, 1, 19, None)]),
        entry(2, &[(10, true, 1, 3, None)]),
    ];
    for (minimum, threshold, expected, severity) in [
        (2, 63_333, 1, 2),
        (2, 63_334, 0, 0),
        (3, 0, 0, 0),
        (2, 0, 1, 3),
    ] {
        let profile = VerifiedProcedureParameters::RelativeSizeFactor {
            min_rsf_bps: threshold,
            min_subset_size: minimum,
        };
        let (report, _) = run(profile, entries.clone());
        assert_eq!(
            (report.live_entries, report.live_legs, report.comparisons),
            (2, 2, 2)
        );
        assert_eq!(report.findings.len(), expected);
        if let Some(finding) = report.findings.first() {
            assert_eq!(finding.severity, severity);
        }
    }
    let mut unknown_chart = registry();
    unknown_chart.account_types.clear();
    let profile = VerifiedProcedureParameters::RelativeSizeFactor {
        min_rsf_bps: 0,
        min_subset_size: 2,
    };
    let (without_cite, _, _) =
        replay(profile, &entries.iter().collect::<Vec<_>>(), &unknown_chart).unwrap();
    assert!(matches!(
        without_cite[0].statistic,
        VerifiedProcedureStatistic::RelativeSizeFactor { account: None, .. }
    ));
    assert!(run(PROFILE, Vec::new()).0.findings.is_empty());
    for field in ["accounts", "parties"] {
        let mut incomplete = entries.clone();
        if field == "accounts" {
            incomplete[0].leg_accounts.clear();
        } else {
            incomplete[0].leg_parties.clear();
        }
        assert_eq!(
            recompute_version(BOOK, FRONTIER, 1, None, profile, incomplete, &registry())
                .unwrap_err()
                .predicate,
            "procedure_profile"
        );
    }
}

#[test]
fn relative_size_uses_reversal_parity_and_excludes_pending_controls_and_reversal_legs() {
    let profile = VerifiedProcedureParameters::RelativeSizeFactor {
        min_rsf_bps: 50_000,
        min_subset_size: 2,
    };
    let mut entries = vec![
        entry(1, &[(10, true, 1, 1_000, None)]),
        entry(2, &[(10, true, 1, 100, None)]),
        entry(3, &[(10, true, 1, 10, None)]),
    ];
    let before = run(profile, entries.clone()).0;
    let mut reversal = entry(4, &[(10, false, 1, 1_000, None)]);
    reversal.class = 4;
    reversal.supersession.push((1, entries[0].digest, 1));
    let mut pending = entry(5, &[(10, true, 1, i128::MAX, None)]);
    pending.class = 2;
    let mut control = entry(6, &[]);
    control.class = 16;
    entries.extend([reversal, pending, control]);
    let reversed = run(profile, entries.clone()).0;
    assert_eq!(
        (
            reversed.population,
            reversed.live_entries,
            reversed.live_legs,
            reversed.comparisons
        ),
        (6, 2, 2, 2)
    );
    assert_eq!(reversed.findings[0].entry, Some(2));
    let mut restore = entry(7, &[(10, true, 1, 1_000, None)]);
    restore.class = 4;
    restore.supersession.push((4, entries[3].digest, 1));
    entries.push(restore);
    let restored = run(profile, entries).0;
    assert_eq!(restored.findings, before.findings);
    assert_eq!(
        (
            restored.population,
            restored.live_entries,
            restored.live_legs,
            restored.comparisons
        ),
        (7, 3, 3, 3)
    );
}

#[test]
fn relative_size_rejects_forged_grouping_citations_work_and_policy_after_rehashing() {
    let original = population();
    let (expected, output) = run(PROFILE, original.clone());
    let certificate = encoded(&output, true);
    let request = decode_certificate(&certificate).unwrap();
    assert_eq!(
        replay_certificate(&request, BOOK, FRONTIER, original.clone(), &registry())
            .unwrap()
            .0,
        expected
    );
    for change in [
        "party",
        "account",
        "unit",
        "side",
        "amount",
        "entry",
        "work",
        "omitted population",
        "policy",
    ] {
        let mut claimed_source = original.clone();
        let mut claimed_registry = registry();
        match change {
            "party" => claimed_source[0].leg_parties[1] = None,
            "account" => claimed_source[0].leg_accounts[0].0 = 20,
            "unit" => claimed_source[0].legs[1].0 = 2,
            "side" => claimed_source[0].leg_accounts[1].1 = false,
            "amount" => claimed_source[0].legs[1].1 = 2_001,
            "entry" => claimed_source[0].identity = 9,
            "work" => {
                claimed_source[0].legs.push((1, 0));
                claimed_source[0].leg_accounts.push((10, false));
                claimed_source[0].leg_parties.push(None);
            }
            "omitted population" => {
                claimed_source.pop();
            }
            "policy" => claimed_registry.policy_oid = [8; 32],
            _ => unreachable!(),
        }
        let (_, forged_output) = recompute_version(
            BOOK,
            FRONTIER,
            1,
            None,
            PROFILE,
            claimed_source,
            &claimed_registry,
        )
        .unwrap();
        assert_ne!(
            forged_output, output,
            "{change} must actually change the claim"
        );
        // Recompute every public output commitment and the outer digest.
        // Original authenticated facts still decide the only valid result.
        let forged_certificate = encoded(&forged_output, true);
        let forged = decode_certificate(&forged_certificate).unwrap();
        assert_eq!(
            replay_certificate(&forged, BOOK, FRONTIER, original.clone(), &registry())
                .unwrap_err()
                .predicate,
            "procedure_recomputation",
            "{change}"
        );
    }
    for (book, frontier) in [([2; 16], FRONTIER), (BOOK, FRONTIER - 1)] {
        assert_eq!(
            replay_certificate(&request, book, frontier, original.clone(), &registry())
                .unwrap_err()
                .predicate,
            "procedure_selection"
        );
    }
}

fn parameter_bytes(values: &[(&str, i128)]) -> Vec<u8> {
    let mut bytes = Writer::default();
    bytes.count(values.len());
    for &(name, value) in values {
        bytes.bytes(name.as_bytes()).i128(value);
    }
    bytes.buf
}

#[test]
fn relative_size_profile_requires_extended_v1_complete_unsigned_parameters_and_no_cutoff() {
    let (_, output) = run(PROFILE, population());
    assert_eq!(
        decode_certificate(&encoded(&output, true))
            .unwrap()
            .parameters,
        PROFILE
    );
    assert_eq!(
        decode_certificate(&encoded(&output, false))
            .err()
            .unwrap()
            .predicate,
        "procedure_profile"
    );
    for (version, cutoff) in [(2, None), (1, Some(1))] {
        let (_, unsupported) = recompute_version(
            BOOK,
            FRONTIER,
            version,
            cutoff,
            PROFILE,
            population(),
            &registry(),
        )
        .unwrap();
        assert_eq!(
            decode_certificate(&encoded(&unsupported, true))
                .err()
                .unwrap()
                .predicate,
            "procedure_profile"
        );
    }
    for (threshold, minimum) in [(0, 2), (u32::MAX, u32::MAX)] {
        let values = [
            ("min_rsf_bps", i128::from(threshold)),
            ("min_subset_size", i128::from(minimum)),
        ];
        assert_eq!(
            decode(&mut Reader::new(&parameter_bytes(&values))).unwrap(),
            VerifiedProcedureParameters::RelativeSizeFactor {
                min_rsf_bps: threshold,
                min_subset_size: minimum,
            }
        );
    }
    let defaults = [("min_rsf_bps", 50_000), ("min_subset_size", 3)];
    assert_eq!(
        decode(&mut Reader::new(&parameter_bytes(&defaults)))
            .unwrap()
            .parameters(),
        DEFAULTS.map(|(name, value)| (name, i128::from(value)))
    );
    for (index, value) in [
        (0, -1),
        (0, i128::from(u32::MAX) + 1),
        (1, -1),
        (1, 0),
        (1, 1),
        (1, i128::from(u32::MAX) + 1),
    ] {
        let mut invalid = defaults;
        invalid[index].1 = value;
        assert!(decode(&mut Reader::new(&parameter_bytes(&invalid))).is_err());
    }
    for invalid in [
        vec![defaults[0]],
        vec![defaults[1], defaults[0]],
        vec![defaults[0], defaults[0]],
        vec![defaults[0], defaults[1], ("extra", 1)],
    ] {
        assert!(decode(&mut Reader::new(&parameter_bytes(&invalid))).is_err());
    }
}
