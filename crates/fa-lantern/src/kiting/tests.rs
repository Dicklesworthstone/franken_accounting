//! Arithmetic/search fixtures only. Native receipts and match authentication
//! are exercised by the facade's integration tests, not asserted by these ids.

use super::*;
use search::{Group, Transfer};

fn cycles(
    edges: &[Transfer<'_>],
    max_hops: usize,
    window: u32,
    max_steps: u64,
    through: Option<i32>,
    work: &mut Meter<'_>,
) -> Result<Vec<search::Cycle>, LanternError> {
    search::cycles(edges, max_hops, window, max_steps, through, work).map(|search| search.cycles)
}

#[test]
fn hard_capacity_limits_match_their_registry_contract() {
    let limits = fa_registry::limits_embedded().unwrap();
    for (name, value) in [
        ("max_kiting_transfers", MAX_KITING_TRANSFERS),
        ("max_kiting_findings", MAX_KITING_FINDINGS),
        ("max_kiting_finding_bytes", MAX_KITING_FINDING_BYTES),
        ("max_kiting_instrument_bytes", MAX_INSTRUMENT_BYTES),
    ] {
        assert_eq!(limits[name], value as u64, "{name}");
    }
}

#[test]
fn cgse_witness_records_complete_deterministic_temporal_dfs() {
    let sources = [source(10, 1, 2, 1, 5), source(11, 2, 1, 2, 6)];
    let edges = edges(&sources);
    let search = || {
        search::cycles(
            &edges,
            3,
            7,
            100,
            None,
            &mut Meter::new(Kiting::ID, None, None),
        )
        .unwrap()
    };
    let first = search();
    let repeated = search();
    assert_eq!(first.witness.n, 2);
    assert_eq!(first.witness.m, 2);
    assert_eq!(first.witness.observed_count, 3);
    assert_eq!(first.witness.policy, fnx_cgse::TieBreakPolicy::DfsPreorder);
    assert_eq!(first.witness.dominant_term, "bounded_temporal_dfs_complete");
    assert_eq!(
        first.witness.decision_path_blake3,
        repeated.witness.decision_path_blake3
    );
    assert_eq!(first.cycles, repeated.cycles);
}

fn source(id: u128, from: u128, to: u128, available: i32, clears: i32) -> BankTransfer {
    let oid = |tag: u8| {
        let mut bytes = [tag; 32];
        bytes[..16].copy_from_slice(&id.to_le_bytes());
        Oid(bytes)
    };
    BankTransfer {
        entry: EntryRef {
            vid: VId(id),
            entry_digest: oid(9).0,
        },
        source_ordinal: 1,
        destination_ordinal: 0,
        source: MatchedBankLine {
            manifest_oid: oid(1),
            line_oid: oid(2),
            account: VId(from),
            instrument: format!("BANK-{from}"),
            booking_date: DateDay(available),
            value_date: DateDay(clears),
        },
        destination: MatchedBankLine {
            manifest_oid: oid(3),
            line_oid: oid(4),
            account: VId(to),
            instrument: format!("BANK-{to}"),
            booking_date: DateDay(available),
            value_date: DateDay(available),
        },
    }
}

fn edges(sources: &[BankTransfer]) -> Vec<Transfer<'_>> {
    sources
        .iter()
        .map(|source| Transfer {
            source,
            group: Group {
                unit: 1,
                entity: None,
                amount: 50_000,
            },
            start: source
                .destination
                .booking_date
                .0
                .max(source.destination.value_date.0),
            end: source.source.value_date.0,
            earliest: source
                .source
                .booking_date
                .0
                .min(source.destination.booking_date.0),
            latest: source
                .source
                .value_date
                .0
                .max(source.destination.value_date.0),
        })
        .collect()
}

fn run(edges: &[Transfer<'_>]) -> Result<Vec<search::Cycle>, LanternError> {
    cycles(
        edges,
        3,
        7,
        100_000,
        None,
        &mut Meter::new(Kiting::ID, None, None),
    )
}

#[test]
fn detects_planted_three_instrument_kite_once_with_exact_common_interval() {
    let sources = [
        source(10, 1, 2, 1, 5),
        source(11, 2, 3, 2, 6),
        source(12, 3, 1, 3, 7),
    ];
    let edges = edges(&sources);
    let found = run(&edges).unwrap();
    assert_eq!(
        found,
        vec![search::Cycle {
            transfers: vec![0, 1, 2],
            start: 3,
            end: 5
        }]
    );
    assert!(
        cycles(
            &edges,
            2,
            7,
            100_000,
            None,
            &mut Meter::new(Kiting::ID, None, None)
        )
        .unwrap()
        .is_empty()
    );
    assert!(
        cycles(
            &edges,
            3,
            7,
            100_000,
            Some(2),
            &mut Meter::new(Kiting::ID, None, None)
        )
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        cycles(
            &edges,
            3,
            7,
            100_000,
            Some(3),
            &mut Meter::new(Kiting::ID, None, None)
        )
        .unwrap(),
        found
    );
}

#[test]
fn same_day_reverse_date_disjoint_float_and_outside_window_are_not_kites() {
    for pairs in [
        [(1, 1), (1, 5), (1, 5)],    // no same-day positive float
        [(2, 1), (1, 5), (1, 5)],    // reversed interval
        [(1, 3), (3, 5), (2, 4)],    // half-open endpoints only touch
        [(1, 4), (2, 5), (5, 8)],    // individually positive, no common day
        [(1, 10), (2, 11), (3, 12)], // common day but more than seven-day span
    ] {
        let sources = [
            source(10, 1, 2, pairs[0].0, pairs[0].1),
            source(11, 2, 3, pairs[1].0, pairs[1].1),
            source(12, 3, 1, pairs[2].0, pairs[2].1),
        ];
        assert!(run(&edges(&sources)).unwrap().is_empty(), "{pairs:?}");
    }
}

#[test]
fn exact_amount_unit_and_entity_partitions_never_join() {
    let sources = [
        source(10, 1, 2, 1, 5),
        source(11, 2, 3, 2, 6),
        source(12, 3, 1, 3, 7),
    ];
    for changed in [
        Group {
            unit: 2,
            entity: None,
            amount: 50_000,
        },
        Group {
            unit: 1,
            entity: Some(VId(99)),
            amount: 50_000,
        },
        Group {
            unit: 1,
            entity: None,
            amount: 50_001,
        },
    ] {
        let mut edges = edges(&sources);
        edges[1].group = changed;
        assert!(run(&edges).unwrap().is_empty());
    }
}

#[test]
fn repeated_accounts_or_instruments_cannot_form_a_longer_cycle() {
    let mut sources = [
        source(10, 1, 2, 1, 5),
        source(11, 2, 3, 2, 6),
        source(12, 3, 1, 3, 7),
    ];
    sources[1].destination.instrument = "BANK-1".into();
    sources[2].source.instrument = "BANK-1".into();
    assert!(run(&edges(&sources)).unwrap().is_empty());
    sources[1].destination.instrument = "BANK-3".into();
    sources[2].source.instrument = "BANK-3".into();
    sources[1].destination.account = VId(1);
    sources[2].source.account = VId(1);
    assert!(run(&edges(&sources)).unwrap().is_empty());
}

#[test]
fn disjoint_chains_and_one_sided_transfers_are_clean() {
    let sources = [
        source(10, 1, 2, 1, 5),
        source(11, 2, 3, 2, 6),
        source(12, 3, 4, 3, 7),
    ];
    assert!(run(&edges(&sources)).unwrap().is_empty());
    assert!(run(&[]).unwrap().is_empty());
}

#[test]
fn parallel_transfers_are_distinct_but_rotations_are_not() {
    let sources = [
        source(10, 1, 2, 1, 5),
        source(11, 1, 2, 2, 6),
        source(12, 2, 1, 3, 7),
    ];
    let found = run(&edges(&sources)).unwrap();
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].transfers, vec![0, 2]);
    assert_eq!(found[1].transfers, vec![1, 2]);
}

#[test]
fn exhaustive_search_and_output_caps_refuse_without_partial_success() {
    let sources = [source(10, 1, 2, 1, 5), source(11, 2, 1, 2, 6)];
    assert!(matches!(
        cycles(
            &edges(&sources),
            3,
            7,
            2,
            None,
            &mut Meter::new(Kiting::ID, None, None)
        ),
        Err(LanternError::BudgetExhausted { budget: 2, .. })
    ));
    assert!(matches!(
        cycles(
            &edges(&sources),
            3,
            7,
            100,
            None,
            &mut Meter::new(Kiting::ID, Some(1), None)
        ),
        Err(LanternError::BudgetExhausted { budget: 1, .. })
    ));
    let mut many = Vec::new();
    for index in 0..101 {
        many.push(source(1000 + index, 1, 2, 1, 5));
        many.push(source(2000 + index, 2, 1, 1, 5));
    }
    let err = run(&edges(&many)).unwrap_err();
    assert!(
        matches!(err, LanternError::Parameter { message, .. } if message.contains("10000 findings"))
    );
}

#[test]
fn cancellation_is_observed_before_network_allocation() {
    struct Cancelled;
    impl crate::Cancellation for Cancelled {
        fn cancelled(&self) -> bool {
            true
        }
    }
    let sources = [source(10, 1, 2, 1, 5), source(11, 2, 1, 2, 6)];
    assert!(matches!(
        cycles(
            &edges(&sources),
            3,
            7,
            100,
            None,
            &mut Meter::new(Kiting::ID, None, Some(&Cancelled))
        ),
        Err(LanternError::Cancelled { .. })
    ));
}

#[test]
fn civil_day_span_is_widened_before_subtraction() {
    let sources = [
        source(10, 1, 2, i32::MIN, i32::MAX),
        source(11, 2, 1, i32::MIN + 1, i32::MAX),
    ];
    assert!(run(&edges(&sources)).unwrap().is_empty());
    for boundary in [i32::MIN, i32::MAX - 5] {
        let sources = [
            source(10, 1, 2, boundary, boundary + 5),
            source(11, 2, 1, boundary + 1, boundary + 4),
        ];
        let found = run(&edges(&sources)).unwrap();
        assert_eq!((found[0].start, found[0].end), (boundary + 1, boundary + 4));
    }
}
