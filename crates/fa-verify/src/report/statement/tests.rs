use super::*;
use crate::envelope::KIND_ENTRY;

fn envelope(index: u8, class: u16, at: u64) -> LeafEnvelope {
    LeafEnvelope {
        kind: KIND_ENTRY,
        book_id: [0; 16],
        branch_id: [0; 16],
        commit_seq: at,
        within_commit_ordinal: 0,
        record_digest: [index; 32],
        class,
        effective_day: Some(40),
        account_vids: Vec::new(),
        unit_ids: Vec::new(),
    }
}
fn info(identity: u128, target: Option<(u128, [u8; 32], u8)>) -> metadata::EntryInfo<'static> {
    metadata::EntryInfo {
        time_tick: None,
        schema: None,
        period: None,
        resolution: None,
        identity,
        legacy_identity: None,
        supersession: target.into_iter().collect(),
        supersession_reasons: target.map(|_| 1).into_iter().collect(),
        rule_version_oid: None,
        has_fx_revaluation_basis: false,
        obligation_maturity: None,
        evidence: Vec::new(),
    }
}
#[test]
fn lineage_rejects_missing_mismatched_later_ambiguous_and_cyclic_targets() {
    for case in 0..6 {
        let mut envelopes = vec![envelope(1, 8, 1), envelope(2, 4, 2)];
        let mut infos = BTreeMap::from([(0, info(1, None)), (1, info(2, Some((1, [1; 32], 1))))]);
        match case {
            0 => infos.get_mut(&1).unwrap().supersession[0].0 = 999,
            1 => infos.get_mut(&1).unwrap().supersession[0].1 = [9; 32],
            2 => envelopes[0].commit_seq = 3,
            3 => infos.get_mut(&1).unwrap().supersession[0].2 = 2,
            4 => infos
                .get_mut(&1)
                .unwrap()
                .supersession
                .push((1, [1; 32], 1)),
            5 => {
                envelopes[0].class = 4;
                envelopes[0].commit_seq = 2;
                infos
                    .get_mut(&0)
                    .unwrap()
                    .supersession
                    .push((2, [2; 32], 1));
            }
            _ => unreachable!(),
        }
        let error = origin(
            1,
            &envelopes,
            &infos,
            &BTreeMap::from([(1, 0), (2, 1)]),
            &mut Lineage::default(),
        )
        .unwrap_err();
        assert_eq!(error.predicate, "entry_lineage");
    }
}
#[test]
fn same_commit_reversals_resolve_and_repeated_lineage_uses_the_original_class() {
    let envelopes = vec![envelope(1, 8, 1), envelope(2, 4, 1), envelope(3, 4, 2)];
    let infos = BTreeMap::from([
        (0, info(1, None)),
        (1, info(2, Some((1, [1; 32], 1)))),
        (2, info(3, Some((2, [2; 32], 1)))),
    ]);
    let mut cache = Lineage::default();
    assert_eq!(
        origin(
            2,
            &envelopes,
            &infos,
            &BTreeMap::from([(1, 0), (2, 1), (3, 2)]),
            &mut cache
        )
        .unwrap(),
        0
    );
    assert_eq!(cache.origins.get(&1), Some(&0));
    assert_eq!(cache.origins.get(&2), Some(&0));
}
fn income() -> Selection {
    let raw: Vec<_> = include_str!("../tests/income-statement.hex")
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let bytes: Vec<_> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect();
    Selection::new(&bytes, vec!["C1".into()], vec![]).unwrap()
}
fn schema() -> metadata::Schema {
    let mut chart = Writer::default();
    chart.count(2);
    for (code, typ) in [("cash", 1), ("revenue", 4)] {
        chart
            .bytes(code.as_bytes())
            .bytes(code.as_bytes())
            .u8(typ)
            .u8(u8::from(typ == 4))
            .u8(1)
            .fixed(&0i64.to_le_bytes())
            .u8(0);
    }
    let mut periods = Writer::default();
    periods
        .fixed(b"fa:period-creation:v1")
        .bytes(b"cy")
        .i32(2026)
        .count(1)
        .bytes(b"C1")
        .i32(2026)
        .u16(1)
        .u8(3)
        .i32(31)
        .i32(59)
        .u8(0);
    let mut schema = metadata::Schema::default();
    schema.apply(1, &chart.buf, &[0; 16], 1).unwrap();
    schema.apply(13, &periods.buf, &[0; 16], 2).unwrap();
    schema
}
#[test]
fn closing_period_migration_ancestry_is_refused_but_operating_adjustments_are_income() {
    let legs = vec![vec![
        Leg {
            debit: true,
            account: crate::ads::account_vid(&[0; 16], "cash"),
            unit: 0,
            mantissa: 50,
        },
        Leg {
            debit: false,
            account: crate::ads::account_vid(&[0; 16], "revenue"),
            unit: 0,
            mantissa: 50,
        },
    ]];
    for class in [7, 12] {
        let envelopes = vec![envelope(1, class, 1)];
        let mut entry = info(1, None);
        entry.period = Some(("cy", "C1"));
        let infos = BTreeMap::from([(0, entry)]);
        let result = replay(
            &income(),
            &[0; 16],
            &[0; 16],
            1,
            &[0],
            &schema(),
            &envelopes,
            &infos,
            &legs,
            &BTreeSet::from([0]),
            &BTreeSet::new(),
        );
        if class == 12 {
            assert_eq!(result.unwrap_err().predicate, "entry_lineage");
        } else {
            let statement = result.unwrap().0;
            assert_eq!(
                statement
                    .lines
                    .iter()
                    .find(|line| line.code == "revenue")
                    .unwrap()
                    .amounts,
                [50]
            );
        }
    }
    let envelopes = vec![envelope(1, 12, 1), envelope(2, 4, 2)];
    let mut migration = info(1, None);
    migration.period = Some(("cy", "C1"));
    let mut reversal = info(2, Some((1, [1; 32], 1)));
    reversal.period = Some(("cy", "C1"));
    let error = replay(
        &income(),
        &[0; 16],
        &[0; 16],
        2,
        &[0],
        &schema(),
        &envelopes,
        &BTreeMap::from([(0, migration), (1, reversal)]),
        &[vec![], legs[0].clone()],
        &BTreeSet::from([0]),
        &BTreeSet::new(),
    )
    .unwrap_err();
    assert_eq!(error.predicate, "entry_lineage");
}
#[test]
fn zero_gross_source_cannot_smuggle_an_unregistered_unit() {
    let mut entry = info(1, None);
    entry.period = Some(("cy", "C1"));
    let error = replay(
        &income(),
        &[0; 16],
        &[0; 16],
        1,
        &[0],
        &schema(),
        &[envelope(1, 1, 1)],
        &BTreeMap::from([(0, entry)]),
        &[vec![Leg {
            debit: true,
            account: crate::ads::account_vid(&[0; 16], "cash"),
            unit: 99,
            mantissa: 0,
        }]],
        &BTreeSet::new(),
        &BTreeSet::new(),
    )
    .unwrap_err();
    assert_eq!(error.predicate, "registry_closure");
}
#[test]
fn definitions_refuse_forward_cycles_repeated_operands_and_unknown_signs() {
    for case in 0..4 {
        let mut w = Writer::default();
        w.fixed(b"FA-STATEMENT-DEF\0")
            .u16(1)
            .u16(0)
            .bytes(b"test")
            .bytes(b"Test")
            .u32(1)
            .u8(1)
            .count(2)
            .bytes(b"revenue")
            .bytes(b"Revenue")
            .u8(0)
            .count(1)
            .u8(4)
            .u8(if case == 3 { 2 } else { 1 })
            .bytes(b"result")
            .bytes(b"Result")
            .u8(1)
            .count(1)
            .bytes(if case == 0 {
                b"result"
            } else if case == 1 {
                b"unknown"
            } else {
                b"revenue"
            });
        if case == 2 {
            w.count(1).bytes(b"revenue");
        } else {
            w.count(0);
        }
        w.count(0);
        assert_eq!(
            Definition::decode(&w.buf).unwrap_err().predicate,
            "statement_definition"
        );
    }
}

#[test]
fn wide_statement_sum_cancels_before_narrowing_and_detects_real_overflow() {
    let mut sum = Sum::default();
    for _ in 0..4096 {
        sum.add(i128::MAX, false).unwrap();
    }
    assert!(sum.value().is_none());
    for _ in 0..4095 {
        sum.add(i128::MAX, true).unwrap();
    }
    assert_eq!(sum.value().unwrap(), i128::MAX);
    sum.add(i128::MAX, true).unwrap();
    sum.add(i128::MIN, false).unwrap();
    assert_eq!(sum.value().unwrap(), i128::MIN);
    sum.add(-1, false).unwrap();
    assert!(sum.value().is_none());
    sum.add(1, false).unwrap();
    assert_eq!(sum.value().unwrap(), i128::MIN);
    sum.add(i128::MIN, true).unwrap();
    assert_eq!(sum.value().unwrap(), 0);
}

fn lineage_record(
    ordinal: u64,
    target: Option<(u128, [u8; 32])>,
) -> (Vec<u8>, usize, LeafEnvelope, u128) {
    let mut w = Writer::default();
    w.u16(1)
        .u16(0)
        .fixed(&[3; 16])
        .fixed(&[0; 16])
        .u16(if target.is_some() { 4 } else { 1 })
        .i32(0)
        .u8(0);
    w.fixed(&[0; 32]).u8(0).fixed(&[0; 24]).bytes(&[]);
    w.u8(0).count(2);
    for (account, side) in [(1, 0), (2, 1)] {
        w.u8(side ^ ((ordinal & 1) as u8))
            .u128(account)
            .u32(1)
            .i128(10)
            .u8(0)
            .count(0)
            .u8(0)
            .count(0);
    }
    w.u8(0)
        .count(1)
        .u32(1)
        .i128(10)
        .i128(10)
        .u8(0)
        .bytes(&ordinal.to_le_bytes())
        .u8(0)
        .fixed(&[0; 32])
        .u16(1)
        .u128(99)
        .u8(0)
        .count(0)
        .count(usize::from(target.is_some()));
    if let Some((identity, digest)) = target {
        w.u128(identity).fixed(&digest).u8(1).u16(1);
    }
    w.u8(0).count(0).count(0);
    let length = w.buf.len();
    let proposal = hash_parts(crate::envelope::PROPOSAL_DIGEST_DOMAIN, &[&w.buf]);
    let digest = hash_parts(crate::envelope::ENTRY_DIGEST_DOMAIN, &[&proposal, &[]]);
    w.fixed(&proposal).fixed(&digest);
    let envelope = crate::envelope::envelope_of_entry(&w.buf, length, ordinal + 1, 0).unwrap();
    let identity = metadata::entry_info(&w.buf[..length], &envelope)
        .unwrap()
        .identity;
    (w.buf, length, envelope, identity)
}

#[test]
fn long_reversal_ancestry_is_inspected_once_and_cached_edges_still_authenticate() {
    const COUNT: usize = 4096;
    let mut records = Vec::with_capacity(COUNT + 1);
    let mut target = None;
    for index in 0..COUNT {
        let record = lineage_record(index as u64, target);
        target = Some((record.3, record.2.record_digest));
        records.push(record);
    }
    // A new branch reaches a cached, genuine payload with the wrong
    // identity. Memoization must not make that edge authoritative.
    records.push(lineage_record(
        COUNT as u64,
        Some((records[0].3 ^ 1, records[0].2.record_digest)),
    ));
    let envelopes: Vec<_> = records.iter().map(|record| record.2.clone()).collect();
    let infos = records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            (
                index,
                metadata::entry_info(&record.0[..record.1], &record.2).unwrap(),
            )
        })
        .collect();
    let by_identity = records
        .iter()
        .enumerate()
        .map(|(index, record)| (record.3, index))
        .collect();
    let mut lineage = Lineage::default();
    assert_eq!(
        origin(COUNT - 1, &envelopes, &infos, &by_identity, &mut lineage).unwrap(),
        0,
    );
    // Revisit the entire source population in both orders, as comparative
    // columns do, while observing actual ancestry inspections rather than
    // timing or merely counting cache entries.
    for index in (0..COUNT).chain((0..COUNT).rev()) {
        assert_eq!(
            origin(index, &envelopes, &infos, &by_identity, &mut lineage).unwrap(),
            0
        );
    }
    let mut inspected = lineage.inspected.clone();
    inspected.sort_unstable();
    assert_eq!(inspected, (0..COUNT).collect::<Vec<_>>());
    assert_eq!(
        origin(COUNT, &envelopes, &infos, &by_identity, &mut lineage)
            .unwrap_err()
            .predicate,
        "entry_lineage"
    );
    assert!(!lineage.origins.contains_key(&COUNT));
    assert_eq!(lineage.inspected.len(), COUNT + 1);
}
