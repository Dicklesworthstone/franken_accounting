use super::*;
use crate::report::open_items::VerifiedOpenItem;

const PROFILE: VerifiedProcedureParameters = VerifiedProcedureParameters::OpenItemsAging {
    edges: [10, 20, 30],
};

fn item(entry: u128, day: i32, amount: i128) -> VerifiedOpenItem {
    VerifiedOpenItem {
        entry,
        ordinal: 0,
        account: 10,
        unit_id: 1,
        debit: true,
        effective_date: day,
        recorded_at: 1,
        original: amount,
        applied: 0,
        applied_out: 0,
        open: amount,
        applications: Vec::new(),
    }
}

fn registry(items: Vec<VerifiedOpenItem>) -> Registry {
    Registry {
        unit_scales: BTreeMap::from([(1, 2), (2, 0)]),
        unit_currencies: BTreeMap::new(),
        account_types: BTreeMap::new(),
        leg_parties: BTreeMap::new(),
        entry_facts: BTreeMap::new(),
        trace: None,
        open_items: Some(items),
        policy_oid: [7; 32],
    }
}

#[test]
fn independent_aging_uses_residuals_inclusive_edges_and_separate_sides_and_units() {
    let mut partial = item(1, 0, 100);
    partial.applied = 60;
    partial.open = 40;
    let mut credit = item(2, 0, 40);
    credit.debit = false;
    let mut other_unit = item(3, 0, 9_007_199_254_740_993);
    other_unit.unit_id = 2;
    let mut paid = item(4, 0, 80);
    paid.applied_out = 80;
    paid.open = 0;
    let mut sources = vec![
        partial,
        credit,
        other_unit,
        paid,
        item(5, 31, 11), // inclusive day 10
        item(6, 21, 12), // inclusive day 20
        item(7, 11, 13), // inclusive day 30
    ];
    let (findings, visits) = replay(PROFILE, Some(41), &registry(sources.clone())).unwrap();
    assert_eq!(visits, 6);
    assert_eq!(findings.len(), 3);
    assert_eq!(findings[0].severity, 3);
    assert_eq!(findings[0].population, 6);
    assert_eq!(
        findings[0].statistic,
        VerifiedProcedureStatistic::AgedOpenAmount {
            name: "open_past_30_days".into(),
            account: 10,
            unit: 1,
            debit: true,
            totals: [11, 12, 13, 40],
            items: 4,
            scale: 2,
            legs: vec![(1, 0)],
        }
    );
    assert_eq!(
        findings[1].statistic.value(),
        40,
        "credit never nets against debit"
    );
    assert_eq!(findings[2].statistic.value(), 9_007_199_254_740_993);
    assert_eq!(findings[2].statistic.scale(), 0);
    sources.reverse();
    assert_eq!(
        replay(PROFILE, Some(41), &registry(sources)).unwrap().0,
        findings
    );
}

#[test]
fn independent_aging_caps_only_citations_and_keeps_the_full_oldest_amount() {
    let mut sources: Vec<_> = (0..MAX_CITES + 4)
        .map(|index| item(index as u128 + 1, index as i32, 1))
        .collect();
    // Chronology decides the capped population; numeric identity decides
    // its final presentation order. A late high amount must still be counted.
    sources[0].entry = 100_000;
    sources[MAX_CITES + 3].open = 100;
    sources[MAX_CITES + 3].original = 100;
    let (findings, visits) = replay(PROFILE, Some(20_000), &registry(sources)).unwrap();
    assert_eq!(visits, (MAX_CITES + 4) as u64);
    let VerifiedProcedureStatistic::AgedOpenAmount {
        totals,
        legs,
        items,
        ..
    } = &findings[0].statistic
    else {
        panic!("aging statistic");
    };
    assert_eq!(*totals, [0, 0, 0, (MAX_CITES + 103) as i128]);
    assert_eq!(*items, visits);
    assert_eq!(legs.len(), MAX_CITES - 1);
    assert_eq!(legs.last(), Some(&(100_000, 0)));
    assert!(!legs.contains(&((MAX_CITES + 4) as u128, 0)));
}

#[test]
fn independent_aging_checks_dates_inputs_and_exact_arithmetic() {
    let empty = registry(Vec::new());
    assert!(replay(PROFILE, None, &empty).is_err());
    let mut missing = registry(Vec::new());
    missing.open_items = None;
    assert!(replay(PROFILE, Some(0), &missing).is_err());
    assert!(replay(PROFILE, Some(0), &registry(vec![item(1, 1, 1)])).is_err());
    let mut damaged = item(1, 0, 1);
    damaged.applied = 1;
    assert!(replay(PROFILE, Some(40), &registry(vec![damaged])).is_err());
    let mut unknown = item(1, 0, 1);
    unknown.unit_id = 99;
    assert!(replay(PROFILE, Some(40), &registry(vec![unknown])).is_err());
    assert!(
        replay(
            PROFILE,
            Some(40),
            &registry(vec![item(1, 0, i128::MAX), item(2, 0, 1)])
        )
        .is_err()
    );
    assert_eq!(replay(PROFILE, Some(40), &empty).unwrap(), (Vec::new(), 0));
    let extreme = VerifiedProcedureParameters::OpenItemsAging {
        edges: [0, u32::MAX - 1, u32::MAX],
    };
    let (findings, _) = replay(
        extreme,
        Some(i32::MAX),
        &registry(vec![item(1, i32::MIN, i128::MAX)]),
    )
    .unwrap();
    assert_eq!(findings[0].severity, 0);
    let VerifiedProcedureStatistic::AgedOpenAmount { totals, .. } = findings[0].statistic else {
        panic!("aging statistic");
    };
    assert_eq!(totals, [0, 0, i128::MAX, 0]);
}

#[test]
fn independent_aging_decoder_requires_exact_ordered_unsigned_edges() {
    use crate::codec::Writer;
    for edges in [
        [0, 1, u32::MAX as i128],
        [30, 60, 90],
        [-1, 2, 3],
        [1, 1, 3],
        [2, 1, 3],
        [0, 1, u32::MAX as i128 + 1],
    ] {
        let mut encoded = Writer::default();
        encoded.count(3);
        for (index, (name, _)) in DEFAULTS.iter().enumerate() {
            encoded.bytes(name.as_bytes()).i128(edges[index]);
        }
        let valid = edges[0] >= 0
            && edges[0] < edges[1]
            && edges[1] < edges[2]
            && edges[2] <= u32::MAX as i128;
        assert_eq!(
            decode(&mut Reader::new(&encoded.buf)).is_ok(),
            valid,
            "{edges:?}"
        );
    }
    let mut duplicated = Writer::default();
    duplicated
        .count(3)
        .bytes(b"bucket_1")
        .i128(1)
        .bytes(b"bucket_1")
        .i128(2)
        .bytes(b"bucket_3")
        .i128(3);
    assert!(decode(&mut Reader::new(&duplicated.buf)).is_err());
}
