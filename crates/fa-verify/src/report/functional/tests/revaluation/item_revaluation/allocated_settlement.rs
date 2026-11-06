//! Allocated-carrying settlement vectors, with independently encoded source
//! chains and hand-calculated historical, total and valuation relief.
use super::super::super::settlement::{Application, AppliedLeg, application_entry, leg, swapped};
use super::*;

#[derive(Clone)]
struct Component {
    legs: Vec<AppliedLeg>,
    source_digest: [u8; 32],
    historical: i128,
    total: i128,
    route_entry: u128,
    route_digest: [u8; 32],
}

#[derive(Clone)]
struct Payment {
    record: Record,
    legs: Vec<AppliedLeg>,
    basis: Vec<u8>,
}

fn allocated_registries() -> Vec<(String, Vec<u8>)> {
    let mut docs = item_registries();
    docs[4].1 = registry::allocated_law_fixture(&docs[4].1);
    docs
}

fn allocated_definitions() -> registry::FunctionalRegistry {
    let docs = allocated_registries();
    let inputs: Vec<_> = docs
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    let result = registry::verify_functional(&inputs, &closure(&docs)).unwrap();
    assert!(result.item_revaluation && result.allocated_carrying);
    result
}

fn replay_allocated(
    records: &[Record],
    rates: &[RateFixture],
) -> Result<(VerifiedFunctionalTrialBalance, Vec<u8>), ReportError> {
    replay_registry_fixture(
        records,
        Selection::AsOf(58),
        records.last().unwrap().envelope.commit_seq,
        &book(&[]),
        rates,
        &[],
        &allocated_definitions(),
    )
}

fn allocated_history(
    native: i128,
    historical: i128,
    target: i128,
    spot: (u128, u128),
    closing: (u128, u128),
    debit: bool,
) -> (Vec<Record>, Vec<RateFixture>, Record, Record) {
    let spot = rate_fixture(spot.0, spot.1, 1, 10);
    let close = close_rate(closing.0, closing.1);
    let mut records = settlement_declarations();
    records.push(intake(&spot, 5));
    let mut legs = pair(native, historical);
    if !debit {
        for leg in &mut legs {
            leg.debit = !leg.debit;
        }
    }
    let source = entry(
        6,
        1,
        10,
        b"allocated-original",
        &legs,
        Some((1, &spot, None)),
        None,
        None,
    );
    records.push(source.clone());
    records.push(intake(&close, 7));
    let item = Item {
        source: source.clone(),
        native,
        historical,
        prior: 0,
        target,
    };
    let allocation = item_adjustment(
        8,
        7,
        b"allocated-close",
        debit,
        &records[3],
        &close,
        &[(&source, 0)],
        &[item],
    );
    records.push(allocation.clone());
    (records, vec![spot, close], source, allocation)
}

fn carrying_digest(source: &Record, ordinal: u16, effects: &[&Record]) -> [u8; 32] {
    let (identity, digest) = handle(source);
    let mut w = Writer::default();
    w.u128(identity).fixed(&digest).u16(ordinal);
    for effect in effects {
        w.u64(effect.envelope.commit_seq)
            .u128(handle(effect).0)
            .fixed(&effect.envelope.record_digest);
    }
    hash_parts(b"fa:allocated-carrying-source:v1", &[&w.buf])
}

#[allow(clippy::too_many_arguments)]
fn component(
    source: &Record,
    debit: bool,
    native: i128,
    historical: i128,
    total: i128,
    cash: i128,
    route: &Record,
    effects: &[&Record],
) -> Component {
    let applying = !debit;
    let mut legs = vec![
        leg("1000", applying, 1, native, historical),
        leg("1900", !applying, 1, native, historical),
    ];
    if historical != 0 {
        legs.push(leg("1900", applying, 0, historical, historical));
    }
    legs.push(leg("1010", !applying, 0, cash, cash));
    let realized = cash - historical;
    if realized != 0 {
        legs.push(leg(
            "7000",
            if realized > 0 { applying } else { !applying },
            0,
            realized.abs(),
            realized.abs(),
        ));
    }
    let valuation = total - historical;
    if valuation != 0 {
        let side = if valuation > 0 { applying } else { !applying };
        legs.push(leg("1290", side, 0, valuation.abs(), valuation.abs()));
        legs.push(leg("4700", !side, 0, valuation.abs(), valuation.abs()));
    }
    let (identity, digest) = handle(source);
    legs[0].applications.push(Application {
        identity,
        digest,
        ordinal: 0,
        unit: 1,
        amount: native,
    });
    Component {
        legs,
        source_digest: carrying_digest(source, 0, effects),
        historical,
        total,
        route_entry: handle(route).0,
        route_digest: framed_hash(b"fa:fx-revaluation-routes:v1", &[&BOOK, &route_body()]),
    }
}

#[allow(clippy::too_many_arguments)]
fn with_release(
    seq: u64,
    class: u16,
    day: i32,
    key: &[u8],
    legs: &[AppliedLeg],
    rate: &RateFixture,
    basis: &[u8],
    reverses: Option<&Record>,
) -> Record {
    let original = application_entry(seq, class, day, key, legs, (10, rate, None), reverses);
    let mut raw = original.bytes[..original.len].to_vec();
    raw[2..4].copy_from_slice(&4u16.to_le_bytes());
    let mut w = Writer::default();
    w.fixed(&raw).count(1).u16(37).bytes(basis);
    finish(w, seq)
}

fn payment(
    seq: u64,
    day: i32,
    key: &[u8],
    rate: &RateFixture,
    components: &[Component],
) -> Payment {
    let mut basis = Writer::default();
    basis
        .fixed(b"FA-FX-RELIEF\0")
        .u16(1)
        .count(components.len());
    let mut legs = Vec::new();
    for component in components {
        basis.u16(legs.len() as u16).fixed(&component.source_digest);
        for value in [
            component.historical,
            component.total,
            component.total - component.historical,
        ] {
            basis.u32(0).i128(value);
        }
        basis
            .u128(component.route_entry)
            .fixed(&component.route_digest)
            .u128(id("1290"))
            .u128(id("4700"));
        legs.extend(component.legs.iter().cloned());
    }
    let record = with_release(seq, 1, day, key, &legs, rate, &basis.buf, None);
    Payment {
        record,
        legs,
        basis: basis.buf,
    }
}

fn undo(seq: u64, key: &[u8], target: &Payment, rate: &RateFixture) -> Payment {
    let legs = swapped(&target.legs);
    Payment {
        record: with_release(
            seq,
            4,
            30,
            key,
            &legs,
            rate,
            &target.basis,
            Some(&target.record),
        ),
        legs,
        basis: target.basis.clone(),
    }
}

fn mutate_release(record: &Record, change: impl FnOnce(&mut Vec<u8>)) -> Record {
    let info = metadata::entry_info(&record.bytes[..record.len], &record.envelope).unwrap();
    let raw = info.fx_settlement_basis.unwrap();
    let mut changed = raw.to_vec();
    change(&mut changed);
    let mut w = Writer::default();
    w.fixed(&record.bytes[..record.len - raw.len() - 4])
        .bytes(&changed);
    finish(w, record.envelope.commit_seq)
}

#[test]
fn allocated_settlement_relieves_positive_and_negative_carrying_and_takes_the_final_remainder() {
    for (target, close, first_total) in [(15, (3, 2), 4), (5, (1, 2), 2)] {
        for debit in [true, false] {
            let (mut records, mut rates, source, allocation) =
                allocated_history(10, 10, target, (1, 1), close, debit);
            let quote = rate_fixture(2, 1, 4, 30);
            records.push(intake(&quote, 9));
            let first_native = if target == 15 { 3 } else { 5 };
            let first = payment(
                10,
                30,
                b"allocated-partial",
                &quote,
                &[component(
                    &source,
                    debit,
                    first_native,
                    first_native,
                    first_total,
                    first_native * 2,
                    &records[3],
                    &[&allocation],
                )],
            );
            records.push(first.record.clone());
            rates.push(quote.clone());
            let (partial, _) = replay_allocated(&records, &rates).unwrap();
            let sign = if debit { 1 } else { -1 };
            assert_eq!(net(&partial, "1000"), sign * (10 - first_native));
            assert_eq!(
                net(&partial, "1290"),
                sign * (target - 10 - first_total + first_native)
            );
            let remaining = 10 - first_native;
            let final_payment = payment(
                11,
                30,
                b"allocated-final",
                &quote,
                &[component(
                    &source,
                    debit,
                    remaining,
                    remaining,
                    target - first_total,
                    remaining * 2,
                    &records[3],
                    &[&allocation, &first.record],
                )],
            );
            records.push(final_payment.record.clone());
            let (closed, _) = replay_allocated(&records, &rates).unwrap();
            assert_eq!(net(&closed, "1000"), 0);
            assert_eq!(net(&closed, "1290"), 0);
            assert_eq!(net(&closed, "4700"), 0);
            assert_eq!(net(&closed, "1010"), sign * 20);
            assert_eq!(net(&closed, "7000"), -sign * 10);
            let reversed = undo(12, b"undo-final", &final_payment, &quote);
            records.push(reversed.record.clone());
            let (restored, _) = replay_allocated(&records, &rates).unwrap();
            assert_eq!(net(&restored, "1000"), sign * remaining);
            assert_eq!(
                net(&restored, "1290"),
                sign * (target - first_total - remaining)
            );
            let reinstated = undo(13, b"reinstate-final", &reversed, &quote);
            records.push(reinstated.record);
            assert!(
                replay_allocated(&records, &rates).is_err(),
                "native allocated-carrying does not admit a reversal of its application undo"
            );
        }
    }
}

#[test]
fn allocated_settlement_then_revaluation_uses_each_remaining_carrying_component() {
    let (mut records, mut rates, source, allocation) =
        allocated_history(10, 10, 15, (1, 1), (3, 2), true);
    let quote = rate_fixture(2, 1, 4, 30);
    records.push(intake(&quote, 9));
    let partial = payment(
        10,
        30,
        b"partial-before-reclose",
        &quote,
        &[component(
            &source,
            true,
            4,
            4,
            6,
            8,
            &records[3],
            &[&allocation],
        )],
    );
    records.push(partial.record.clone());
    let next_rate = close_rate(2, 1);
    records.push(intake(&next_rate, 11));
    let item = Item {
        source: source.clone(),
        native: 6,
        historical: 6,
        prior: 3,
        target: 12,
    };
    let reclose = item_adjustment(
        12,
        11,
        b"reclose-after-release",
        true,
        &records[3],
        &next_rate,
        &[
            (&source, 0),
            (&allocation, 0),
            (&partial.record, 0),
            (&partial.record, 5),
        ],
        &[item],
    );
    records.push(reclose.clone());
    rates.extend([quote.clone(), next_rate.clone()]);
    let (report, _) = replay_allocated(&records, &rates).unwrap();
    assert_eq!(net(&report, "1000"), 6);
    assert_eq!(net(&report, "1290"), 6);
    assert_eq!(net(&report, "4700"), -6);
    records.push(with_release(
        13,
        4,
        29,
        b"backdated-undo-after-reclose",
        &swapped(&partial.legs),
        &quote,
        &partial.basis,
        Some(&partial.record),
    ));
    assert!(
        replay_allocated(&records, &rates).is_err(),
        "an exact allocated-payment undo cannot predate the item's latest closing"
    );
    records.pop();
    let restored = undo(13, b"undo-after-reclose", &partial, &quote);
    records.push(restored.record.clone());
    let (after_undo, _) = replay_allocated(&records, &rates).unwrap();
    assert_eq!(net(&after_undo, "1000"), 10);
    assert_eq!(
        net(&after_undo, "1290"),
        8,
        "undo restores the recorded +2 release, not a current proportion"
    );
    let reclosed = item_adjustment(
        14,
        13,
        b"reclose-after-exact-undo",
        true,
        &records[3],
        &next_rate,
        &[
            (&source, 0),
            (&allocation, 0),
            (&partial.record, 0),
            (&partial.record, 5),
            (&reclose, 0),
            (&restored.record, 0),
            (&restored.record, 5),
        ],
        &[Item {
            source: source.clone(),
            native: 10,
            historical: 10,
            prior: 8,
            target: 20,
        }],
    );
    records.push(reclosed.clone());
    let (after_reclose, _) = replay_allocated(&records, &rates).unwrap();
    assert_eq!(
        net(&after_reclose, "1290"),
        10,
        "only +2 is required after the undo"
    );
    let final_payment = payment(
        15,
        30,
        b"final-after-reclose",
        &quote,
        &[component(
            &source,
            true,
            10,
            10,
            20,
            20,
            &records[3],
            &[
                &allocation,
                &partial.record,
                &reclose,
                &restored.record,
                &reclosed,
            ],
        )],
    );
    records.push(final_payment.record);
    let (closed, _) = replay_allocated(&records, &rates).unwrap();
    assert_eq!(net(&closed, "1000"), 0);
    assert_eq!(net(&closed, "1290"), 0);
    assert_eq!(net(&closed, "4700"), 0);
}

#[test]
fn allocated_settlement_preserves_zero_relief_and_restores_it_without_repricing() {
    let (mut records, mut rates, source, allocation) =
        allocated_history(100, 1, 2, (1, 100), (1, 50), true);
    let quote = rate_fixture(1, 1, 4, 30);
    records.push(intake(&quote, 9));
    let zero = payment(
        10,
        30,
        b"zero-relief",
        &quote,
        &[component(
            &source,
            true,
            1,
            0,
            0,
            1,
            &records[3],
            &[&allocation],
        )],
    );
    assert_eq!(
        zero.legs.len(),
        4,
        "zero historical/valuation relief has no artificial zero legs"
    );
    records.push(zero.record.clone());
    rates.push(quote.clone());
    let (partial, _) = replay_allocated(&records, &rates).unwrap();
    assert_eq!(net(&partial, "1000"), 1);
    assert_eq!(net(&partial, "1290"), 1);
    records.push(undo(11, b"undo-zero-relief", &zero, &quote).record);
    let (restored, _) = replay_allocated(&records, &rates).unwrap();
    assert_eq!(net(&restored, "1000"), 1);
    assert_eq!(net(&restored, "1290"), 1);
    assert_eq!(net(&restored, "1010"), 0);
}

#[test]
fn allocated_settlement_authenticates_balanced_relief_quote_route_and_tail_claims() {
    let (mut records, mut rates, source, allocation) =
        allocated_history(10, 10, 15, (1, 1), (3, 2), true);
    let quote = rate_fixture(2, 1, 4, 30);
    records.push(intake(&quote, 9));
    let honest = payment(
        10,
        30,
        b"honest-release",
        &quote,
        &[component(
            &source,
            true,
            4,
            4,
            6,
            8,
            &records[3],
            &[&allocation],
        )],
    );
    records.push(honest.record.clone());
    rates.push(quote.clone());
    replay_allocated(&records, &rates).unwrap();
    let index = records.len() - 1;
    // Every malformed case is resealed, so rejection is accounting evidence,
    // canonical shape or source authentication, never a stale entry digest.
    for offset in [13, 19, 21, 53, 57, 73, 77, 93, 97, 113, 129, 161, 177] {
        records[index] = mutate_release(&honest.record, |raw| raw[offset] ^= 1);
        assert!(
            replay_allocated(&records, &rates).is_err(),
            "release byte {offset}"
        );
    }
    records[index] = mutate_release(&honest.record, |raw| raw.resize(64 * 1024 + 1, 0));
    assert!(
        replay_allocated(&records, &rates).is_err(),
        "oversized release frame"
    );
    for (historical, total, cash) in [(5, 6, 8), (4, 5, 8), (4, 6, 9)] {
        records[index] = payment(
            10,
            30,
            b"balanced-false-relief",
            &quote,
            &[component(
                &source,
                true,
                4,
                historical,
                total,
                cash,
                &records[3],
                &[&allocation],
            )],
        )
        .record;
        assert!(
            replay_allocated(&records, &rates).is_err(),
            "false relief {historical}/{total}/{cash}"
        );
    }
    let mut wrong = component(&source, true, 4, 4, 6, 8, &records[3], &[&allocation]);
    let tail = wrong.legs.len() - 2;
    wrong.legs[tail].leg.code = "1010";
    records[index] = payment(10, 30, b"rerouted-release", &quote, &[wrong]).record;
    assert!(
        replay_allocated(&records, &rates).is_err(),
        "valuation cannot be released to cash"
    );
    let mut wrong = component(&source, true, 4, 4, 6, 8, &records[3], &[&allocation]);
    let last = wrong.legs.len() - 1;
    wrong.legs.swap(last - 1, last);
    records[index] = payment(10, 30, b"unordered-tail", &quote, &[wrong]).record;
    assert!(
        replay_allocated(&records, &rates).is_err(),
        "the retained tail order is intrinsic"
    );
    let mut wrong = component(&source, true, 4, 4, 6, 8, &records[3], &[&allocation]);
    wrong
        .legs
        .extend([leg("1010", true, 0, 1, 1), leg("7000", false, 0, 1, 1)]);
    records[index] = payment(10, 30, b"extra-effects", &quote, &[wrong]).record;
    assert!(
        replay_allocated(&records, &rates).is_err(),
        "balanced unrelated legs are not a settlement"
    );
    let mut no_basis = Writer::default();
    no_basis
        .fixed(&honest.record.bytes[..honest.record.len - honest.basis.len() - 10])
        .count(0);
    records[index] = finish(no_basis, 10);
    assert!(
        replay_allocated(&records, &rates).is_err(),
        "law 10 requires its retained release basis"
    );
    let mut stale = component(&source, true, 4, 4, 6, 8, &records[3], &[]);
    records[index] = payment(10, 30, b"omitted-allocation", &quote, &[stale.clone()]).record;
    assert!(
        replay_allocated(&records, &rates).is_err(),
        "source chain must include its allocation"
    );
    stale.source_digest = honest.basis[21..53].try_into().unwrap();
    records[index] = payment(10, 29, b"retroactive-release", &quote, &[stale]).record;
    assert!(
        replay_allocated(&records, &rates).is_err(),
        "a settlement cannot predate the allocation"
    );
}

#[test]
fn allocated_settlement_undo_retains_exact_provenance_and_uses_no_new_rate() {
    let (mut records, mut rates, source, allocation) =
        allocated_history(10, 10, 15, (1, 1), (3, 2), true);
    let quote = rate_fixture(2, 1, 4, 30);
    records.push(intake(&quote, 9));
    let partial = payment(
        10,
        30,
        b"release",
        &quote,
        &[component(
            &source,
            true,
            4,
            4,
            6,
            8,
            &records[3],
            &[&allocation],
        )],
    );
    records.push(partial.record.clone());
    let reverse = undo(11, b"undo-release", &partial, &quote);
    records.push(reverse.record.clone());
    rates.push(quote.clone());
    let (report, _) = replay_allocated(&records, &rates).unwrap();
    assert_eq!(net(&report, "1000"), 10);
    assert_eq!(net(&report, "1290"), 5);
    *records.last_mut().unwrap() = mutate_release(&reverse.record, |raw| raw[21] ^= 1);
    assert!(
        replay_allocated(&records, &rates).is_err(),
        "an undo cannot replace the original source proof"
    );
    *records.last_mut().unwrap() = reverse.record;
    let fresh = rate_fixture(3, 1, 4, 30);
    records.insert(records.len() - 1, intake(&fresh, 10));
    let changed = with_release(
        11,
        4,
        30,
        b"repriced-undo",
        &swapped(&partial.legs),
        &fresh,
        &partial.basis,
        Some(&partial.record),
    );
    *records.last_mut().unwrap() = changed;
    rates.push(fresh);
    assert!(
        replay_allocated(&records, &rates).is_err(),
        "a current quote cannot reprice a recorded undo"
    );
}

#[test]
fn allocated_settlement_bundle_replays_complete_carrying_and_rejects_false_certified_output() {
    let (mut records, mut rates, source, allocation) =
        allocated_history(10, 10, 15, (1, 1), (3, 2), true);
    let quote = rate_fixture(2, 1, 4, 30);
    records.push(intake(&quote, 9));
    records.push(
        payment(
            10,
            30,
            b"bundle-release",
            &quote,
            &[component(
                &source,
                true,
                4,
                4,
                6,
                8,
                &records[3],
                &[&allocation],
            )],
        )
        .record,
    );
    rates.push(quote);
    let (expected, output) = replay_allocated(&records, &rates).unwrap();
    let selected = Selection::AsOf(58);
    let docs = allocated_registries();
    let (bundle, signed, pin) =
        pack_with_registries(&records, &selected, 10, &book(&[]), &rates, &output, &docs);
    let verified = verify_report_with_inputs(&bundle, &[], None, None, Some(&pin), None, |_, _| {
        Ok(signed.clone())
    })
    .unwrap();
    assert_eq!(verified.functional_trial_balance, Some(expected));
    let mut false_output = output;
    let last = false_output.len() - 1;
    false_output[last] ^= 1;
    let (bundle, signed, pin) = pack_with_registries(
        &records,
        &selected,
        10,
        &book(&[]),
        &rates,
        &false_output,
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
fn allocated_settlement_groups_distinct_items_including_a_zero_valuation_item() {
    let (mut records, mut rates, mut items) = initial(&[1, 1], true, (3, 2));
    records[0] = settlement_declarations()[0].clone();
    items[0].target = 2;
    append_first(&mut records, &rates, &items, true);
    let allocation = records.last().unwrap().clone();
    let quote = rate_fixture(2, 1, 4, 30);
    records.push(intake(&quote, 10));
    // Group execution order is independently retained; it need not match the
    // closing population's canonical target order.
    let components = [
        component(
            &items[1].source,
            true,
            1,
            1,
            1,
            2,
            &records[3],
            &[&allocation],
        ),
        component(
            &items[0].source,
            true,
            1,
            1,
            2,
            2,
            &records[3],
            &[&allocation],
        ),
    ];
    assert_eq!(
        components[0].legs.len(),
        5,
        "a zero valuation release adds no tail"
    );
    assert_eq!(components[1].legs.len(), 7);
    let group = payment(11, 30, b"two-item-group", &quote, &components);
    records.push(group.record.clone());
    rates.push(quote.clone());
    let (report, _) = replay_allocated(&records, &rates).unwrap();
    assert_eq!(net(&report, "1000"), 0);
    assert_eq!(net(&report, "1290"), 0);
    assert_eq!(net(&report, "4700"), 0);
    assert_eq!(net(&report, "1010"), 4);
    assert_eq!(net(&report, "7000"), -2);
    let index = records.len() - 1;
    records[index] = payment(
        11,
        30,
        b"duplicate-item-group",
        &quote,
        &[components[0].clone(), components[0].clone()],
    )
    .record;
    assert!(
        replay_allocated(&records, &rates).is_err(),
        "a grouped publication cannot spend one item twice"
    );
    records[index] = mutate_release(&group.record, |raw| {
        raw.truncate(raw.len() - 174);
        raw[15..19].copy_from_slice(&1u32.to_le_bytes());
    });
    assert!(
        replay_allocated(&records, &rates).is_err(),
        "every component needs exactly one release row"
    );
    records[index] = mutate_release(&group.record, |raw| raw[193] ^= 1);
    assert!(
        replay_allocated(&records, &rates).is_err(),
        "release ordinals must match complete component starts"
    );
}

#[test]
fn ordinary_functional_reversal_keeps_its_same_publication_compatibility() {
    let spot = rate_fixture(1, 1, 1, 10);
    let mut records = declarations();
    records.push(intake(&spot, 5));
    let source = entry(
        6,
        1,
        10,
        b"ordinary-source",
        &pair(10, 10),
        Some((1, &spot, None)),
        None,
        None,
    );
    let mut reversed = pair(10, 10);
    for leg in &mut reversed {
        leg.debit = !leg.debit;
    }
    let reversal = entry(
        6,
        4,
        10,
        b"same-publication-reversal",
        &reversed,
        Some((1, &spot, None)),
        Some(&source),
        None,
    );
    records.extend([source, reversal]);
    let (report, _) = replay_allocated(&records, &[spot]).unwrap();
    assert_eq!(net(&report, "1000"), 0);
    assert_eq!(net(&report, "3000"), 0);
}

fn add_secondary_route_accounts(records: &mut [Record]) {
    let mut chart = Writer::default();
    chart.count(10);
    for (code, kind, unit) in [
        ("1000", 1, 1i64),
        ("1010", 1, 0),
        ("1100", 1, 1),
        ("1290", 1, 0),
        ("1390", 1, 0),
        ("1900", 1, -1),
        ("3000", 3, 1),
        ("4700", 4, 0),
        ("4800", 4, 0),
        ("7000", 4, 0),
    ] {
        chart
            .bytes(code.as_bytes())
            .bytes(code.as_bytes())
            .u8(kind)
            .u8(u8::from(matches!(kind, 2..=4)))
            .u8(1)
            .fixed(&unit.to_le_bytes())
            .u8(0);
    }
    records[0] = schema_record(1, 1, &chart.buf);
}

#[test]
fn allocated_settlement_cannot_use_another_sources_dedicated_valuation_as_cash() {
    let (mut records, mut rates, source, allocation) =
        allocated_history(10, 10, 15, (1, 1), (3, 2), true);
    add_secondary_route_accounts(&mut records);
    let mut rows = vec![
        (id("1000"), id("1290"), id("4700")),
        (id("1100"), id("1390"), id("4800")),
    ];
    rows.sort_unstable();
    let mut route_map = Writer::default();
    route_map
        .fixed(b"FA-FX-ROUTES\0")
        .u16(1)
        .i32(0)
        .u32(0)
        .count(rows.len());
    for (source, valuation, unrealized) in rows {
        route_map.u128(source).u128(valuation).u128(unrealized);
    }
    records.push(control(
        9,
        1,
        14,
        &route_map.buf,
        b"additional-dedicated-route",
    ));
    let quote = rate_fixture(2, 1, 4, 30);
    records.push(intake(&quote, 10));
    let legitimate = component(&source, true, 4, 4, 6, 8, &records[3], &[&allocation]);
    let honest = payment(
        11,
        30,
        b"ordinary-cash-account",
        &quote,
        &[legitimate.clone()],
    );
    records.push(honest.record);
    rates.push(quote.clone());
    replay_allocated(&records, &rates).unwrap();
    let mut polluted = legitimate;
    polluted
        .legs
        .iter_mut()
        .find(|leg| leg.leg.code == "1010")
        .unwrap()
        .leg
        .code = "1390";
    *records.last_mut().unwrap() =
        payment(11, 30, b"polluted-other-valuation", &quote, &[polluted]).record;
    assert!(
        replay_allocated(&records, &rates).is_err(),
        "a final settlement cannot pollute another source's dedicated valuation account even without a later revaluation"
    );
}

#[test]
fn allocated_settlement_rejects_a_later_route_dedication_of_used_cash() {
    let (mut records, mut rates, source, allocation) =
        allocated_history(10, 10, 15, (1, 1), (3, 2), true);
    add_secondary_route_accounts(&mut records);
    let quote = rate_fixture(2, 1, 4, 30);
    records.push(intake(&quote, 9));
    let settled = payment(
        10,
        30,
        b"cash-before-new-route",
        &quote,
        &[component(
            &source,
            true,
            4,
            4,
            6,
            8,
            &records[3],
            &[&allocation],
        )],
    );
    records.push(settled.record);
    rates.push(quote);
    let declare = |valuation: &str| {
        let mut rows = vec![
            (id("1000"), id("1290"), id("4700")),
            (id("1100"), id(valuation), id("4800")),
        ];
        rows.sort_unstable();
        let mut map = Writer::default();
        map.fixed(b"FA-FX-ROUTES\0")
            .u16(1)
            .i32(0)
            .u32(0)
            .count(rows.len());
        for (source, valuation, unrealized) in rows {
            map.u128(source).u128(valuation).u128(unrealized);
        }
        control(11, 1, 14, &map.buf, b"route-after-cash-payment")
    };
    records.push(declare("1390"));
    replay_allocated(&records, &rates).unwrap();
    *records.last_mut().unwrap() = declare("1010");
    assert!(
        replay_allocated(&records, &rates).is_err(),
        "a final route declaration cannot dedicate a leaf with any earlier cash posting, even without a later closing"
    );
}
