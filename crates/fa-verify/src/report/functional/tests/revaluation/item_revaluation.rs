//! Law 9 vectors are encoded independently of the native producer and verifier.
use super::*;

#[derive(Clone)]
struct Item {
    source: Record,
    native: i128,
    historical: i128,
    prior: i128,
    target: i128,
}

fn item_registries() -> Vec<(String, Vec<u8>)> {
    let mut docs = registries();
    docs[4].1 = registry::item_law_fixture(&docs[4].1);
    docs
}

fn item_definitions() -> registry::FunctionalRegistry {
    let docs = item_registries();
    let inputs: Vec<_> = docs
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    let definitions = registry::verify_functional(&inputs, &closure(&docs)).unwrap();
    assert!(definitions.item_revaluation);
    definitions
}

fn replay_items(
    records: &[Record],
    rates: &[RateFixture],
) -> Result<(VerifiedFunctionalTrialBalance, Vec<u8>), ReportError> {
    replay_registry_fixture(
        records,
        Selection::AsOf(30),
        records.last().unwrap().envelope.commit_seq,
        &book(&[]),
        rates,
        &[],
        &item_definitions(),
    )
}

fn source_commitment(
    route: &Record,
    rate: &RateFixture,
    contributions: &[(&Record, usize)],
) -> [u8; 32] {
    let mut w = Writer::default();
    w.fixed(&BOOK)
        .bytes(b"cy")
        .bytes(b"P1")
        .i32(0)
        .i32(31)
        .u8(1)
        .u128(id("1000"))
        .u8(0)
        .u32(1)
        .u32(0)
        .u128(handle(route).0)
        .fixed(&framed_hash(
            b"fa:fx-revaluation-routes:v1",
            &[&BOOK, &route_body()],
        ))
        .fixed(&rate.oid)
        .fixed(&rate.commitment);
    for code in ["1000", "1290", "4700"] {
        let (_, kind, unit) = chart()
            .into_iter()
            .find(|(name, _, _)| *name == code)
            .unwrap();
        w.u128(id(code))
            .bytes(code.as_bytes())
            .bytes(code.as_bytes())
            .u8(kind)
            .u8(u8::from(matches!(kind, 2..=4)))
            .u8(1)
            .u64(1)
            .u8(0)
            .u32(unit)
            .bytes(&[]);
    }
    // This explicit list is the fixture's assertion, not discovered by replay.
    let mut contributions = contributions.to_vec();
    contributions
        .sort_by_key(|(record, ordinal)| (record.envelope.commit_seq, handle(record).0, *ordinal));
    for (record, ordinal) in contributions {
        w.u64(record.envelope.commit_seq)
            .u128(handle(record).0)
            .fixed(&record.envelope.record_digest)
            .u64(ordinal as u64);
    }
    hash_parts(b"fa:fx-revaluation-source:v1", &[&w.buf])
}

#[allow(clippy::too_many_arguments)]
fn item_adjustment(
    seq: u64,
    observed: u64,
    key: &[u8],
    debit: bool,
    route: &Record,
    rate: &RateFixture,
    contributions: &[(&Record, usize)],
    items: &[Item],
) -> Record {
    let mut basis = Writer::default();
    basis
        .fixed(b"FA-FX-REVALUE\0")
        .u16(2)
        .bytes(b"P1")
        .i32(30)
        .u64(observed)
        .u128(id("1000"))
        .u8(0)
        .u128(handle(route).0)
        .fixed(&framed_hash(
            b"fa:fx-revaluation-routes:v1",
            &[&BOOK, &route_body()],
        ))
        .fixed(&rate.oid)
        .fixed(&rate.commitment)
        .fixed(&source_commitment(route, rate, contributions))
        .u16(1)
        .u16(1)
        .count(items.len());
    let mut legs = Vec::new();
    for item in items {
        let (identity, digest) = handle(&item.source);
        basis.u128(identity).fixed(&digest).u16(0);
        for (unit, value) in [
            (1, item.native),
            (0, item.historical),
            (0, item.prior),
            (0, item.target),
        ] {
            basis.u32(unit).i128(value);
        }
        let delta = item.target - item.historical - item.prior;
        if delta == 0 {
            continue;
        }
        for (ordinal, code) in ["1290", "4700"].into_iter().enumerate() {
            legs.push(TestLeg {
                code,
                debit: (ordinal == 0) == (debit == (delta > 0)),
                unit: 0,
                native: delta.abs(),
                base: Some(delta.abs()),
                entity: None,
            });
        }
    }
    let original = entry(seq, 10, 30, key, &legs, Some((9, rate, None)), None, None);
    let mut header = prefix(10, 30);
    let header_len = header.buf.len();
    header.buf[2..4].copy_from_slice(&4u16.to_le_bytes());
    *header.buf.last_mut().unwrap() = 1;
    header
        .bytes(b"cy")
        .bytes(b"P1")
        .fixed(&original.bytes[header_len..original.len])
        .count(1)
        .u16(16)
        .bytes(&basis.buf);
    finish(header, seq)
}

fn initial(
    amounts: &[i128],
    debit: bool,
    closing: (u128, u128),
) -> (Vec<Record>, Vec<RateFixture>, Vec<Item>) {
    let spot = rate_fixture(1, 1, 1, 10);
    let close = close_rate(closing.0, closing.1);
    let mut records = declarations();
    records.push(intake(&spot, 5));
    let mut items = Vec::new();
    for (index, amount) in amounts.iter().copied().enumerate() {
        let mut legs = pair(amount, amount);
        if !debit {
            for leg in &mut legs {
                leg.debit = !leg.debit;
            }
        }
        let source = entry(
            6 + index as u64,
            1,
            10,
            format!("item-{index}").as_bytes(),
            &legs,
            Some((1, &spot, None)),
            None,
            None,
        );
        items.push(Item {
            source: source.clone(),
            native: amount,
            historical: amount,
            prior: 0,
            target: amount,
        });
        records.push(source);
    }
    records.push(intake(&close, 6 + amounts.len() as u64));
    items.sort_by_key(|item| handle(&item.source).0);
    (records, vec![spot, close], items)
}

fn append_first(records: &mut Vec<Record>, rates: &[RateFixture], items: &[Item], debit: bool) {
    let observed = records.last().unwrap().envelope.commit_seq;
    let contributions: Vec<_> = items.iter().map(|item| (&item.source, 0)).collect();
    records.push(item_adjustment(
        observed + 1,
        observed,
        b"item-close",
        debit,
        &records[3],
        &rates[1],
        &contributions,
        items,
    ));
}

#[test]
fn item_revaluation_ties_use_target_identity_and_replay_both_source_orientations() {
    for debit in [true, false] {
        let (mut records, rates, mut items) = initial(&[1, 1, 1], debit, (4, 3));
        // The exact target is four; three equal weights tie, so only the first
        // canonical (VID, ordinal) receives the one residual minor unit.
        items[0].target = 2;
        append_first(&mut records, &rates, &items, debit);
        let (report, _) = replay_items(&records, &rates).unwrap();
        let sign = if debit { 1 } else { -1 };
        assert_eq!(net(&report, "1000"), sign * 3);
        assert_eq!(net(&report, "1290"), sign);
        assert_eq!(net(&report, "4700"), -sign);
        let mut false_tie = items.clone();
        false_tie[0].target = 1;
        false_tie[1].target = 2;
        records.pop();
        append_first(&mut records, &rates, &false_tie, debit);
        assert!(
            replay_items(&records, &rates).is_err(),
            "identical balanced posting legs cannot authenticate a false item allocation"
        );
    }
}

#[test]
fn item_revaluation_repeats_only_the_incremental_complete_item_deltas() {
    let (mut records, mut rates, mut items) = initial(&[1, 2, 3], true, (4, 3));
    for item in &mut items {
        item.target = match item.native {
            1 => 1,
            2 => 3,
            3 => 4,
            _ => unreachable!(),
        };
    }
    append_first(&mut records, &rates, &items, true);
    let first = records.last().unwrap().clone();
    assert_eq!(net(&replay_items(&records, &rates).unwrap().0, "1290"), 2);
    let next = close_rate(5, 3);
    records.push(intake(&next, first.envelope.commit_seq + 1));
    let mut contributions: Vec<_> = items.iter().map(|item| (&item.source, 0)).collect();
    contributions.extend([(&first, 0), (&first, 2)]);
    let mut next_items = items.clone();
    for item in &mut next_items {
        item.prior = item.target - item.historical;
        item.target = match item.native {
            1 => 2,
            2 => 3,
            3 => 5,
            _ => unreachable!(),
        };
    }
    records.push(item_adjustment(
        first.envelope.commit_seq + 2,
        first.envelope.commit_seq + 1,
        b"item-reclose",
        true,
        &records[3],
        &next,
        &contributions,
        &next_items,
    ));
    rates.push(next);
    let (report, _) = replay_items(&records, &rates).unwrap();
    assert_eq!(net(&report, "1290"), 4);
    assert_eq!(net(&report, "4700"), -4);
    let (historic, _) = replay_registry_fixture(
        &records,
        Selection::AsOf(30),
        first.envelope.commit_seq,
        &book(&[]),
        &rates[..2],
        &[],
        &item_definitions(),
    )
    .unwrap();
    assert_eq!(net(&historic, "1290"), 2);
}

#[test]
fn item_revaluation_preserves_opposite_item_deltas_when_the_aggregate_delta_is_zero() {
    let high = rate_fixture(3, 1, 1, 10);
    let low = rate_fixture(1, 1, 1, 10);
    let close = close_rate(2, 1);
    let mut records = declarations();
    let mut items = Vec::new();
    for (index, (rate, historical)) in [(&high, 3), (&low, 1)].into_iter().enumerate() {
        let seq = 5 + index as u64 * 2;
        records.push(intake(rate, seq));
        let source = entry(
            seq + 1,
            1,
            10,
            format!("mixed-{index}").as_bytes(),
            &pair(1, historical),
            Some((1, rate, None)),
            None,
            None,
        );
        items.push(Item {
            source: source.clone(),
            native: 1,
            historical,
            prior: 0,
            target: 2,
        });
        records.push(source);
    }
    items.sort_by_key(|item| handle(&item.source).0);
    records.push(intake(&close, 9));
    let contributions: Vec<_> = items.iter().map(|item| (&item.source, 0)).collect();
    records.push(item_adjustment(
        10,
        9,
        b"zero-net",
        true,
        &records[3],
        &close,
        &contributions,
        &items,
    ));
    let (report, _) = replay_items(&records, &[high, low, close]).unwrap();
    for code in ["1290", "4700"] {
        let cell = report
            .cells
            .iter()
            .find(|cell| cell.account == id(code))
            .unwrap();
        assert_eq!((cell.debits, cell.credits), (1, 1));
    }
}

#[test]
fn item_revaluation_refuses_forged_incomplete_and_noncanonical_population_assertions() {
    let (mut records, rates, mut items) = initial(&[1, 1, 1], true, (4, 3));
    items[0].target = 2;
    append_first(&mut records, &rates, &items, true);
    let index = records.len() - 1;
    let original = records[index].clone();
    // Version, allocation law/version, target handle/digest/ordinal, and each
    // typed monetary field must be reproduced, not trusted as balanced inputs.
    for offset in [
        14, 195, 197, 203, 219, 251, 253, 257, 273, 277, 293, 297, 313, 317,
    ] {
        records[index] = mutate_basis(&original, |raw| raw[offset] ^= 1);
        assert!(
            replay_items(&records, &rates).is_err(),
            "basis byte {offset}"
        );
    }
    records[index] = mutate_basis(&original, |raw| {
        raw.truncate(raw.len() - 130);
        raw[199..203].copy_from_slice(&2u32.to_le_bytes());
    });
    assert!(
        replay_items(&records, &rates).is_err(),
        "a zero-delta item is still part of the complete population"
    );
    records[index] = mutate_basis(&original, |raw| {
        let first = raw[203..333].to_vec();
        raw[333..463].copy_from_slice(&first);
    });
    assert!(replay_items(&records, &rates).is_err(), "duplicate target");
    records[index] = mutate_basis(&original, |raw| {
        let first = raw[203..333].to_vec();
        let second = raw[333..463].to_vec();
        raw[203..333].copy_from_slice(&second);
        raw[333..463].copy_from_slice(&first);
    });
    assert!(replay_items(&records, &rates).is_err(), "unordered targets");
    records[index] = mutate_basis(&original, |raw| raw.resize(64 * 1024 + 1, 0));
    assert_eq!(
        replay_items(&records, &rates).unwrap_err().predicate,
        "bounded_input",
        "item basis cannot exceed the native 64 KiB extension frame"
    );
    let mut legacy_minor = Writer::default();
    let mut raw = original.bytes[..original.len].to_vec();
    raw[2..4].copy_from_slice(&1u16.to_le_bytes());
    legacy_minor.fixed(&raw);
    records[index] = finish(legacy_minor, original.envelope.commit_seq);
    assert!(
        replay_items(&records, &rates).is_err(),
        "item basis requires schema minor 4"
    );
    let mut delayed = Writer::default();
    delayed.fixed(&original.bytes[..original.len]);
    records[index] = finish(delayed, 11);
    let extra = entry(
        10,
        1,
        10,
        b"unreviewed-item",
        &pair(1, 1),
        Some((1, &rates[0], None)),
        None,
        None,
    );
    records.insert(index, extra);
    assert!(
        replay_items(&records, &rates).is_err(),
        "a source arriving between review and publication invalidates the complete population"
    );
}

#[test]
fn source_undo_after_item_allocation_cannot_leave_orphaned_valuation() {
    let (mut records, rates, mut items) = initial(&[2], true, (3, 2));
    items[0].target = 3;
    append_first(&mut records, &rates, &items, true);
    let mut legs = pair(2, 2);
    for leg in &mut legs {
        leg.debit = !leg.debit;
    }
    records.push(entry(
        9,
        4,
        30,
        b"undo-valued-item",
        &legs,
        Some((1, &rates[0], None)),
        Some(&items[0].source),
        None,
    ));
    assert!(
        replay_items(&records, &rates).is_err(),
        "source reversal must not strand a nonzero item valuation even without a later close"
    );
}

#[test]
fn portable_item_revaluation_bundle_recomputes_and_refuses_resealed_false_output() {
    let (mut records, rates, mut items) = initial(&[1, 1, 1], true, (4, 3));
    items[0].target = 2;
    append_first(&mut records, &rates, &items, true);
    let (expected, output) = replay_items(&records, &rates).unwrap();
    let selected = Selection::AsOf(30);
    let known = records.last().unwrap().envelope.commit_seq;
    let docs = item_registries();
    let (bundle, signed, pin) = pack_with_registries(
        &records,
        &selected,
        known,
        &book(&[]),
        &rates,
        &output,
        &docs,
    );
    let verified = verify_report_with_inputs(&bundle, &[], None, None, Some(&pin), None, |_, _| {
        Ok(signed.clone())
    })
    .unwrap();
    assert_eq!(verified.functional_trial_balance, Some(expected));
    let mut forged = output;
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let (bundle, signed, pin) = pack_with_registries(
        &records,
        &selected,
        known,
        &book(&[]),
        &rates,
        &forged,
        &docs,
    );
    assert_eq!(
        verify_report_with_inputs(&bundle, &[], None, None, Some(&pin), None, |_, _| {
            Ok(signed.clone())
        })
        .unwrap_err()
        .predicate,
        "report_recomputation"
    );
}

#[test]
fn item_profile_does_not_authorize_allocated_settlement_or_revaluation_reversal() {
    let (mut records, rates, mut items) = initial(&[2], true, (3, 2));
    items[0].target = 3;
    append_first(&mut records, &rates, &items, true);
    let adjustment = records.last().unwrap().clone();
    let mut legs = vec![
        TestLeg {
            code: "1290",
            debit: false,
            unit: 0,
            native: 1,
            base: Some(1),
            entity: None,
        },
        TestLeg {
            code: "4700",
            debit: true,
            unit: 0,
            native: 1,
            base: Some(1),
            entity: None,
        },
    ];
    records.push(entry(
        9,
        4,
        30,
        b"undo-item-close",
        &legs,
        Some((9, &rates[1], None)),
        Some(&adjustment),
        None,
    ));
    assert!(
        replay_items(&records, &rates).is_err(),
        "law 9 admits only Revaluation"
    );
    records.pop();
    for leg in &mut legs {
        leg.debit = !leg.debit;
    }
    records.push(entry(
        9,
        1,
        30,
        b"unproved-allocated-settlement",
        &legs,
        Some((10, &rates[1], None)),
        None,
        None,
    ));
    assert_eq!(
        replay_items(&records, &rates).unwrap_err().predicate,
        "supported_report"
    );
}

fn settlement_declarations() -> Vec<Record> {
    let mut records = declarations();
    let mut body = Writer::default();
    body.count(7);
    for (code, kind, unit) in [
        ("1000", 1, 1i64),
        ("1010", 1, 0),
        ("1290", 1, 0),
        ("1900", 1, -1),
        ("3000", 3, 1),
        ("4700", 4, 0),
        ("7000", 4, 0),
    ] {
        body.bytes(code.as_bytes())
            .bytes(code.as_bytes())
            .u8(kind)
            .u8(u8::from(matches!(kind, 2..=4)))
            .u8(1)
            .fixed(&unit.to_le_bytes())
            .u8(0);
    }
    records[0] = schema_record(1, 1, &body.buf);
    records
}

fn item_spot_definitions() -> registry::FunctionalRegistry {
    let mut docs = item_registries();
    docs[4].1 = registry::spot_law_fixture(&docs[4].1);
    let inputs: Vec<_> = docs
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    registry::verify_functional(&inputs, &closure(&docs)).unwrap()
}

#[test]
fn item_revaluation_replays_partial_carrying_settlements_and_their_exact_undos() {
    use super::super::settlement::{Application, application_entry, leg, swapped};
    for law in [4, 11] {
        for undo_before in [false, true] {
            let spot = rate_fixture(1, 1, 1, 10);
            let settlement = rate_fixture(1, 1, 4, 20);
            let close = close_rate(3, 2);
            let mut records = settlement_declarations();
            records.push(intake(&spot, 5));
            let source = entry(
                6,
                1,
                10,
                b"partly-applied",
                &pair(10, 10),
                Some((1, &spot, None)),
                None,
                None,
            );
            records.push(source.clone());
            records.push(intake(&settlement, 7));
            let mut legs = if law == 4 {
                vec![
                    leg("1000", false, 1, 4, 4),
                    leg("1900", true, 1, 4, 4),
                    leg("1900", false, 0, 4, 4),
                    leg("1010", true, 0, 4, 4),
                ]
            } else {
                vec![leg("1000", false, 1, 4, 4), leg("3000", true, 1, 4, 4)]
            };
            let (identity, digest) = handle(&source);
            legs[0].applications.push(Application {
                identity,
                digest,
                ordinal: 0,
                unit: 1,
                amount: 4,
            });
            let payment =
                application_entry(8, 1, 20, b"partial", &legs, (law, &settlement, None), None);
            records.push(payment.clone());
            let undo = undo_before.then(|| {
                application_entry(
                    9,
                    4,
                    25,
                    b"undo-partial-before-close",
                    &swapped(&legs),
                    (law, &settlement, None),
                    Some(&payment),
                )
            });
            if let Some(undo) = &undo {
                records.push(undo.clone());
            }
            let observed = records.last().unwrap().envelope.commit_seq + 1;
            records.push(intake(&close, observed));
            let mut contributions = vec![(&source, 0), (&payment, 0)];
            if let Some(undo) = &undo {
                contributions.push((undo, 0));
            }
            let remaining = if undo_before { 10 } else { 6 };
            let mut item = Item {
                source: source.clone(),
                native: remaining,
                historical: remaining,
                prior: 0,
                target: if undo_before { 15 } else { 9 },
            };
            let adjustment = item_adjustment(
                observed + 1,
                observed,
                b"after-partial",
                true,
                &records[3],
                &close,
                &contributions,
                std::slice::from_ref(&item),
            );
            records.push(adjustment.clone());
            let rates = vec![spot, settlement.clone(), close.clone()];
            let definitions = item_spot_definitions();
            let (report, _) = replay_registry_fixture(
                &records,
                Selection::AsOf(30),
                observed + 1,
                &book(&[]),
                &rates,
                &[],
                &definitions,
            )
            .unwrap();
            assert_eq!(
                net(&report, "1000"),
                remaining,
                "law {law}, undo {undo_before}"
            );
            assert_eq!(net(&report, "1290"), item.target - remaining);
            if !undo_before {
                // An exact old application undo after allocation restores its
                // recorded historical relief without erasing the allocated +3.
                let after = application_entry(
                    observed + 2,
                    4,
                    30,
                    b"undo-partial-after-close",
                    &swapped(&legs),
                    (law, &settlement, None),
                    Some(&payment),
                );
                records.push(after.clone());
                let (restored, _) = replay_registry_fixture(
                    &records,
                    Selection::AsOf(30),
                    observed + 2,
                    &book(&[]),
                    &rates,
                    &[],
                    &definitions,
                )
                .unwrap();
                assert_eq!(net(&restored, "1000"), 10);
                assert_eq!(net(&restored, "1290"), 3);
                contributions.extend([(&adjustment, 0), (&after, 0)]);
                item.native = 10;
                item.historical = 10;
                item.prior = 3;
                item.target = 15;
                records.push(item_adjustment(
                    observed + 3,
                    observed + 2,
                    b"reclose-after-undo",
                    true,
                    &records[3],
                    &close,
                    &contributions,
                    &[item],
                ));
                let (reclosed, _) = replay_registry_fixture(
                    &records,
                    Selection::AsOf(30),
                    observed + 3,
                    &book(&[]),
                    &rates,
                    &[],
                    &definitions,
                )
                .unwrap();
                assert_eq!(
                    net(&reclosed, "1290"),
                    5,
                    "only the additional +2 is posted"
                );
            }
        }
    }
}

fn with_dimensions(record: &Record, dimensions: &[(u32, u128)]) -> Record {
    let raw = &record.bytes[..record.len];
    let details = crate::envelope::proposal_leg_details(raw).unwrap();
    assert!(
        details
            .iter()
            .all(|leg| leg.dimensions.is_empty() && leg.settlements.is_empty())
    );
    let after = crate::envelope::proposal_after_legs(raw).unwrap();
    let end = raw.len() - after.remaining();
    // These independently encoded fixture legs all have a present base amount,
    // no dimensions, no memo and no applications: 67 bytes each.
    let begin = end - details.len() * 67;
    let mut w = Writer::default();
    w.fixed(&raw[..begin]);
    for leg in raw[begin..end].chunks_exact(67) {
        assert_eq!(&leg[58..62], &[0; 4]);
        w.fixed(&leg[..58]).count(dimensions.len());
        for (kind, value) in dimensions {
            w.u32(*kind).u128(*value);
        }
        w.fixed(&leg[62..]);
    }
    w.fixed(&raw[end..]);
    finish(w, record.envelope.commit_seq)
}

#[test]
fn item_revaluation_preserves_full_fund_and_party_dimensions_on_each_adjustment_pair() {
    let (mut records, rates, mut items) = initial(&[2], true, (3, 2));
    let dimensions = [(7, 901), (12, 902)];
    let source = with_dimensions(&items[0].source, &dimensions);
    records[5] = source.clone();
    items[0].source = source;
    items[0].target = 3;
    append_first(&mut records, &rates, &items, true);
    let index = records.len() - 1;
    let unqualified = records[index].clone();
    records[index] = with_dimensions(&unqualified, &dimensions);
    let (report, _) = replay_items(&records, &rates).unwrap();
    assert_eq!(net(&report, "1290"), 1);
    records[index] = with_dimensions(&unqualified, &[(7, 901), (12, 903)]);
    assert!(
        replay_items(&records, &rates).is_err(),
        "another party is a different item cell"
    );
    records[index] = unqualified;
    assert!(
        replay_items(&records, &rates).is_err(),
        "an item allocation cannot drop its fund or party"
    );
}

#[test]
fn later_settlement_of_a_future_effective_unallocated_item_remains_supported() {
    use super::super::settlement::{Application, application_entry, leg};
    for law in [4, 11] {
        let spot = rate_fixture(1, 1, 1, 10);
        let future_spot = rate_fixture(1, 1, 1, 40);
        let close = close_rate(3, 2);
        let settlement = rate_fixture(1, 1, 4, 45);
        let mut records = settlement_declarations();
        records.push(intake(&spot, 5));
        let source = entry(
            6,
            1,
            10,
            b"current-period-item",
            &pair(10, 10),
            Some((1, &spot, None)),
            None,
            None,
        );
        records.push(source.clone());
        records.push(intake(&future_spot, 7));
        let future = entry(
            8,
            1,
            40,
            b"next-period-item",
            &pair(10, 10),
            Some((1, &future_spot, None)),
            None,
            None,
        );
        records.push(future.clone());
        records.push(intake(&close, 9));
        let item = Item {
            source: source.clone(),
            native: 10,
            historical: 10,
            prior: 0,
            target: 15,
        };
        records.push(item_adjustment(
            10,
            9,
            b"current-period-close",
            true,
            &records[3],
            &close,
            &[(&source, 0)],
            &[item],
        ));
        records.push(intake(&settlement, 11));
        let mut legs = if law == 4 {
            vec![
                leg("1000", false, 1, 4, 4),
                leg("1900", true, 1, 4, 4),
                leg("1900", false, 0, 4, 4),
                leg("1010", true, 0, 4, 4),
            ]
        } else {
            vec![leg("1000", false, 1, 4, 4), leg("3000", true, 1, 4, 4)]
        };
        let (identity, digest) = handle(&future);
        legs[0].applications.push(Application {
            identity,
            digest,
            ordinal: 0,
            unit: 1,
            amount: 4,
        });
        records.push(application_entry(
            12,
            1,
            45,
            b"future-item-payment",
            &legs,
            (law, &settlement, None),
            None,
        ));
        let rates = vec![spot, future_spot, close, settlement.clone()];
        let (report, _) = replay_registry_fixture(
            &records,
            Selection::AsOf(58),
            12,
            &book(&[]),
            &rates,
            &[],
            &item_spot_definitions(),
        )
        .unwrap();
        assert_eq!(net(&report, "1000"), 16);
        assert_eq!(net(&report, "1290"), 5);
        // The same ordinary carrying profile remains forbidden for a target
        // that actually received an item allocation in the earlier closing.
        let (identity, digest) = handle(&source);
        legs[0].applications[0].identity = identity;
        legs[0].applications[0].digest = digest;
        *records.last_mut().unwrap() = application_entry(
            12,
            1,
            45,
            b"allocated-item-payment",
            &legs,
            (law, &settlement, None),
            None,
        );
        assert!(
            replay_registry_fixture(
                &records,
                Selection::AsOf(58),
                12,
                &book(&[]),
                &rates,
                &[],
                &item_spot_definitions(),
            )
            .is_err(),
            "an actually allocated target still requires the separate allocated-settlement law"
        );
    }
}
