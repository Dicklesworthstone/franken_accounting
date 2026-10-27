//! Independently encoded settlement histories. Expected carrying relief is
//! calculated in each test, without calling native planners or the verifier's
//! settlement arithmetic. Malformed histories are rehashed by the fixture so
//! rejection must come from their accounting meaning, not a broken digest.

use super::*;

#[derive(Clone)]
struct Application {
    identity: u128,
    digest: [u8; 32],
    ordinal: u16,
    unit: u32,
    amount: i128,
}

#[derive(Clone)]
struct AppliedLeg {
    leg: TestLeg,
    applications: Vec<Application>,
}

fn leg(code: &'static str, debit: bool, unit: u32, native: i128, base: i128) -> AppliedLeg {
    AppliedLeg {
        leg: TestLeg {
            code,
            debit,
            unit,
            native,
            base: Some(base),
            entity: None,
        },
        applications: Vec::new(),
    }
}

// The source-bound law has no extension carrying a caller-selected balance.
// Its sources are the authenticated target handle, prior applications, their
// exact reversals, and the retained Settlement Rate document.
#[allow(clippy::too_many_arguments)]
fn application_entry(
    seq: u64,
    class: u16,
    day: i32,
    key: &[u8],
    legs: &[AppliedLeg],
    claim: ValuationClaim<'_>,
    reverses: Option<&Record>,
) -> Record {
    let mut w = prefix(class, day);
    w.count(legs.len());
    let mut native: BTreeMap<u32, (i128, i128)> = BTreeMap::new();
    let mut base = (0, 0);
    for applied in legs {
        let leg = &applied.leg;
        w.u8(u8::from(!leg.debit))
            .u128(id(leg.code))
            .u32(leg.unit)
            .i128(leg.native)
            .u8(u8::from(leg.base.is_some()));
        if let Some(amount) = leg.base {
            w.u32(0).i128(amount);
            if leg.debit {
                base.0 += amount;
            } else {
                base.1 += amount;
            }
        }
        w.count(usize::from(leg.entity.is_some()));
        if let Some(entity) = leg.entity {
            let digest = framed_hash(
                b"fa:vid:dimension-value:v1",
                &[&BOOK, b"legal_entity", entity.as_bytes()],
            );
            w.u32(1)
                .u128(u128::from_le_bytes(digest[..16].try_into().unwrap()));
        }
        w.u8(0).count(applied.applications.len());
        for application in &applied.applications {
            w.u128(application.identity)
                .fixed(&application.digest)
                .u16(application.ordinal)
                .u32(application.unit)
                .i128(application.amount);
        }
        let sum = native.entry(leg.unit).or_default();
        if leg.debit {
            sum.0 += leg.native;
        } else {
            sum.1 += leg.native;
        }
    }
    w.u8(0).count(native.len());
    for (unit, (debits, credits)) in native {
        w.u32(unit).i128(debits).i128(credits);
    }
    let (law, rate, residual) = claim;
    w.u8(1)
        .u32(0)
        .i128(base.0)
        .i128(base.1)
        .fixed(&valuation::law_oid(law))
        .count(1)
        .fixed(&rate.oid)
        .u8(u8::from(residual.is_some()));
    if let Some((ordinal, amount)) = residual {
        w.u16(ordinal).u32(0).i128(amount);
    }
    w.bytes(key)
        .u8(0)
        .fixed(&[0; 32])
        .u16(1)
        .u128(PRINCIPAL)
        .u8(0)
        .count(1)
        .fixed(&rate.oid)
        .fixed(&rate.commitment)
        .u8(3)
        .count(usize::from(reverses.is_some()));
    if let Some(target) = reverses {
        let (identity, digest) = handle(target);
        w.u128(identity).fixed(&digest).u8(1).u16(0);
    }
    w.u8(0).count(0).count(0);
    finish(w, seq)
}

fn settlement_schema() -> Vec<Record> {
    let mut chart = Writer::default();
    chart.count(7);
    for (code, name, typ, normal) in [
        ("1000", "Cash", 1, 0),
        ("1100", "Receivables", 1, 0),
        ("1900", "FX conversion", 1, 0),
        ("2000", "Payables", 2, 1),
        ("4000", "Revenue", 4, 1),
        ("5000", "Expense", 5, 0),
        ("7000", "Realized FX", 4, 1),
    ] {
        chart
            .bytes(code.as_bytes())
            .bytes(name.as_bytes())
            .u8(typ)
            .u8(normal)
            .u8(1)
            .fixed(&(-1i64).to_le_bytes())
            .u8(0);
    }
    let mut records = schema();
    records[0] = schema_record(1, 1, &chart.buf);
    records
}

fn invoice(seq: u64, key: &[u8], native: i128, base: i128, rate: &RateFixture) -> Record {
    let mut legs = pair(native, base);
    legs[0].code = "1100";
    legs[1].code = "4000";
    entry(seq, 1, 10, key, &legs, Some((1, rate, None)), None, None)
}

fn history(
    native: i128,
    base: i128,
    spot: (u128, u128),
    settlement: (u128, u128),
) -> (Vec<Record>, Vec<RateFixture>, Record) {
    let spot = rate_fixture(spot.0, spot.1, 1, 10);
    let settlement = rate_fixture(settlement.0, settlement.1, 4, 20);
    let source = invoice(4, b"invoice", native, base, &spot);
    let mut records = settlement_schema();
    records.extend([intake(&spot, 3), source.clone(), intake(&settlement, 5)]);
    (records, vec![spot, settlement], source)
}

#[allow(clippy::too_many_arguments)]
fn component(
    source: &Record,
    ordinal: u16,
    account: &'static str,
    source_debit: bool,
    native: i128,
    relief: i128,
    cash: i128,
) -> Vec<AppliedLeg> {
    let side = !source_debit;
    let mut legs = vec![
        leg(account, side, 1, native, relief),
        leg("1900", !side, 1, native, relief),
    ];
    if relief != 0 {
        legs.push(leg("1900", side, 0, relief, relief));
    }
    legs.push(leg("1000", !side, 0, cash, cash));
    let difference = cash - relief;
    if difference != 0 {
        legs.push(leg(
            "7000",
            if difference > 0 { side } else { !side },
            0,
            difference.abs(),
            difference.abs(),
        ));
    }
    let (identity, digest) = handle(source);
    legs[0].applications.push(Application {
        identity,
        digest,
        ordinal,
        unit: 1,
        amount: native,
    });
    legs
}

fn payment(seq: u64, day: i32, key: &[u8], legs: &[AppliedLeg], rate: &RateFixture) -> Record {
    application_entry(seq, 1, day, key, legs, (4, rate, None), None)
}

fn swapped(legs: &[AppliedLeg]) -> Vec<AppliedLeg> {
    legs.iter()
        .cloned()
        .map(|mut applied| {
            applied.leg.debit = !applied.leg.debit;
            applied.applications.clear();
            applied
        })
        .collect()
}

fn replay_settlements(
    records: &[Record],
    rates: &[RateFixture],
) -> Result<VerifiedFunctionalTrialBalance, ReportError> {
    replay_fixture(
        records,
        Selection::AsOf(58),
        records.iter().map(|r| r.envelope.commit_seq).max().unwrap(),
        &book(&[]),
        rates,
    )
    .map(|(report, _)| report)
}

fn totals(report: &VerifiedFunctionalTrialBalance, code: &str) -> (i128, i128) {
    report
        .cells
        .iter()
        .filter(|cell| cell.account == id(code))
        .fold((0, 0), |sum, cell| {
            (sum.0 + cell.debits, sum.1 + cell.credits)
        })
}

#[test]
fn partial_zero_and_final_relief_recompute_remaining_native_and_base() {
    let (mut records, rates, source) = history(3, 2, (2, 3), (1, 1));
    // 2/3 rounds to 1; the remaining 1/2 ties to even zero; the final
    // native unit takes the entire one-unit base remainder.
    for (seq, relief) in [(6, 1), (7, 0), (8, 1)] {
        records.push(payment(
            seq,
            20 + (seq - 6) as i32,
            &seq.to_le_bytes(),
            &component(&source, 0, "1100", true, 1, relief, 1),
            &rates[1],
        ));
    }
    let report = replay_settlements(&records, &rates).unwrap();
    assert_eq!(totals(&report, "1100"), (2, 2));
    assert_eq!(totals(&report, "1000"), (3, 0));
    assert_eq!(totals(&report, "1900"), (2, 2));
    assert_eq!(totals(&report, "7000"), (0, 1));
    assert_eq!(totals(&report, "4000"), (0, 2));
    assert_eq!(report.entries, 4);
}

#[test]
fn half_even_rounds_both_tie_directions_and_final_application_takes_the_remainder() {
    for (base, first, final_relief) in [(5, 2, 3), (7, 4, 3)] {
        let (mut records, rates, source) = history(4, base, (base as u128, 4), (1, 1));
        records.push(payment(
            6,
            20,
            b"half",
            &component(&source, 0, "1100", true, 2, first, 2),
            &rates[1],
        ));
        records.push(payment(
            7,
            21,
            b"final",
            &component(&source, 0, "1100", true, 2, final_relief, 2),
            &rates[1],
        ));
        assert_eq!(
            totals(&replay_settlements(&records, &rates).unwrap(), "1100"),
            (base, base)
        );
        // Reassigning one base unit preserves all entry-level and final
        // source totals, but violates the first application's exact law.
        records[5] = payment(
            6,
            20,
            b"half",
            &component(&source, 0, "1100", true, 2, first + 1, 2),
            &rates[1],
        );
        records[6] = payment(
            7,
            21,
            b"final",
            &component(&source, 0, "1100", true, 2, final_relief - 1, 2),
            &rates[1],
        );
        assert!(replay_settlements(&records, &rates).is_err());
    }
}

#[test]
fn grouped_receivable_and_payable_applications_balance_separately() {
    let (mut records, rates, source) = history(100, 110, (11, 10), (3, 2));
    let payable_legs = vec![
        TestLeg {
            code: "5000",
            debit: true,
            unit: 1,
            native: 80,
            base: Some(88),
            entity: None,
        },
        TestLeg {
            code: "2000",
            debit: false,
            unit: 1,
            native: 80,
            base: Some(88),
            entity: None,
        },
    ];
    let payable = entry(
        6,
        1,
        10,
        b"payable",
        &payable_legs,
        Some((1, &rates[0], None)),
        None,
        None,
    );
    records.push(payable.clone());
    let mut effects = component(&source, 0, "1100", true, 100, 110, 150);
    effects.extend(component(&payable, 1, "2000", false, 80, 88, 120));
    records.push(payment(7, 20, b"group", &effects, &rates[1]));
    let report = replay_settlements(&records, &rates).unwrap();
    assert_eq!(totals(&report, "1100"), (110, 110));
    assert_eq!(totals(&report, "2000"), (88, 88));
    assert_eq!(totals(&report, "1000"), (150, 120));
    assert_eq!(totals(&report, "1900"), (198, 198));
    assert_eq!(totals(&report, "7000"), (32, 40));
}

#[test]
fn reversal_and_reversal_of_reversal_restore_exact_recorded_relief() {
    let (mut records, rates, source) = history(10, 15, (3, 2), (2, 1));
    let effects = component(&source, 0, "1100", true, 4, 6, 8);
    let first = payment(6, 20, b"first", &effects, &rates[1]);
    let undo_effects = swapped(&effects);
    let undo = application_entry(
        7,
        4,
        21,
        b"undo",
        &undo_effects,
        (4, &rates[1], None),
        Some(&first),
    );
    let second = payment(8, 22, b"second", &effects, &rates[1]);
    let restore = application_entry(
        9,
        4,
        23,
        b"restore",
        &swapped(&undo_effects),
        (4, &rates[1], None),
        Some(&undo),
    );
    records.extend([first, undo, second, restore]);
    records.push(payment(
        10,
        24,
        b"final",
        &component(&source, 0, "1100", true, 2, 3, 4),
        &rates[1],
    ));
    let report = replay_settlements(&records, &rates).unwrap();
    assert_eq!(totals(&report, "1100"), (21, 21));
    assert_eq!(totals(&report, "1000"), (28, 8));
    assert_eq!(totals(&report, "7000"), (2, 7));
    // Every payment and exact undo posts both sides of the conversion
    // account: 6 + 6 + 6 + 6 + 3 = 27 on each side, with no net balance.
    assert_eq!(totals(&report, "1900"), (27, 27));
}

#[test]
fn zero_recorded_relief_is_restored_without_repricing() {
    let (mut records, rates, source) = history(3, 2, (2, 3), (1, 1));
    let first_effects = component(&source, 0, "1100", true, 1, 1, 1);
    let second_effects = component(&source, 0, "1100", true, 1, 0, 1);
    let first = payment(6, 20, b"first", &first_effects, &rates[1]);
    let second = payment(7, 21, b"second", &second_effects, &rates[1]);
    let undo_second = application_entry(
        8,
        4,
        22,
        b"undo-zero",
        &swapped(&second_effects),
        (4, &rates[1], None),
        Some(&second),
    );
    records.extend([first, second, undo_second]);
    records.push(payment(
        9,
        23,
        b"final",
        &component(&source, 0, "1100", true, 2, 1, 2),
        &rates[1],
    ));
    let report = replay_settlements(&records, &rates).unwrap();
    assert_eq!(totals(&report, "1100"), (2, 2));
    assert_eq!(totals(&report, "1000"), (4, 1));
    assert_eq!(totals(&report, "7000"), (1, 2));
}

#[test]
fn authenticated_target_identity_digest_ordinal_and_full_allocation_are_required() {
    let (records, rates, source) = history(10, 15, (3, 2), (2, 1));
    let valid = component(&source, 0, "1100", true, 4, 6, 8);
    for variant in 0..7 {
        let mut effects = valid.clone();
        let application = &mut effects[0].applications[0];
        match variant {
            0 => application.identity ^= 1,
            1 => application.digest[0] ^= 1,
            2 => application.ordinal = 99,
            3 => application.unit = 0,
            4 => application.amount = 3,
            5 => effects[0].applications.clear(),
            6 => {
                let duplicate = effects[0].applications[0].clone();
                effects[0].applications.push(duplicate);
            }
            _ => unreachable!(),
        }
        let mut changed = records.clone();
        changed.push(payment(6, 20, b"payment", &effects, &rates[1]));
        assert!(
            replay_settlements(&changed, &rates).is_err(),
            "target variant {variant}"
        );
    }
}

#[test]
fn balanced_but_wrong_carrying_cash_and_component_shapes_refuse() {
    let (records, rates, source) = history(10, 15, (3, 2), (2, 1));
    let variants = [
        component(&source, 0, "1100", true, 4, 7, 8),
        component(&source, 0, "1100", true, 4, 6, 9),
        component(&source, 0, "2000", true, 4, 6, 8),
        component(&source, 0, "1100", false, 4, 6, 8),
    ];
    for (variant, effects) in variants.iter().enumerate() {
        let mut changed = records.clone();
        changed.push(payment(6, 20, b"payment", effects, &rates[1]));
        assert!(
            replay_settlements(&changed, &rates).is_err(),
            "balanced variant {variant}"
        );
    }
    for variant in 0..4 {
        let mut effects = component(&source, 0, "1100", true, 4, 6, 8);
        match variant {
            0 => effects.swap(0, 1),
            1 => {
                effects.push(leg("1000", true, 0, 1, 1));
                effects.push(leg("7000", false, 0, 1, 1));
            }
            2 => effects[2].leg.code = "5000",
            3 => effects[4].leg.code = "1000",
            _ => unreachable!(),
        }
        let mut changed = records.clone();
        changed.push(payment(6, 20, b"payment", &effects, &rates[1]));
        assert!(
            replay_settlements(&changed, &rates).is_err(),
            "shape variant {variant}"
        );
    }
    let mut changed = records;
    changed.push(application_entry(
        6,
        1,
        20,
        b"residual",
        &component(&source, 0, "1100", true, 4, 6, 8),
        (4, &rates[1], Some((0, 1))),
        None,
    ));
    assert!(replay_settlements(&changed, &rates).is_err());
}

#[test]
fn native_capacity_is_enforced_even_when_remaining_base_is_zero() {
    let (mut records, rates, source) = history(3, 1, (1, 3), (1, 1));
    records.push(payment(
        6,
        20,
        b"first",
        &component(&source, 0, "1100", true, 2, 1, 2),
        &rates[1],
    ));
    records.push(payment(
        7,
        21,
        b"over",
        &component(&source, 0, "1100", true, 2, 0, 2),
        &rates[1],
    ));
    assert!(replay_settlements(&records, &rates).is_err());
}

#[test]
fn late_undo_cannot_conceal_prior_overapplication_or_duplicate_reversal_lineage() {
    let (mut records, rates, source) = history(10, 15, (3, 2), (2, 1));
    let effects = component(&source, 0, "1100", true, 6, 9, 12);
    let first = payment(6, 20, b"first", &effects, &rates[1]);
    let second = payment(7, 21, b"second", &effects, &rates[1]);
    let undo = application_entry(
        8,
        4,
        22,
        b"undo",
        &swapped(&effects),
        (4, &rates[1], None),
        Some(&first),
    );
    records.extend([first, second, undo]);
    assert!(replay_settlements(&records, &rates).is_err());

    let (mut records, rates, source) = history(10, 10, (1, 1), (2, 1));
    let effects = component(&source, 0, "1100", true, 2, 2, 4);
    let first = payment(6, 20, b"first", &effects, &rates[1]);
    let second = payment(7, 21, b"second", &effects, &rates[1]);
    let undo = application_entry(
        8,
        4,
        22,
        b"undo",
        &swapped(&effects),
        (4, &rates[1], None),
        Some(&first),
    );
    let duplicate = application_entry(
        9,
        4,
        23,
        b"duplicate-undo",
        &swapped(&effects),
        (4, &rates[1], None),
        Some(&first),
    );
    records.extend([first, second, undo, duplicate]);
    // Aggregate capacity is still within the original 10. It does not prove
    // that the same immutable application may be restored twice.
    assert!(replay_settlements(&records, &rates).is_err());
}

#[test]
fn carrying_source_must_preexist_the_publication_and_remain_live() {
    let (records, rates, source) = history(10, 15, (3, 2), (2, 1));
    let effects = component(&source, 0, "1100", true, 4, 6, 8);
    let mut same_commit = records.clone();
    same_commit[3].envelope.commit_seq = 6;
    same_commit.sort_by_key(|record| record.envelope.commit_seq);
    same_commit.push(payment(6, 20, b"same-commit", &effects, &rates[1]));
    assert!(replay_settlements(&same_commit, &rates).is_err());

    let mut reversed = records;
    let reversed_source = vec![
        TestLeg {
            code: "1100",
            debit: false,
            unit: 1,
            native: 10,
            base: Some(15),
            entity: None,
        },
        TestLeg {
            code: "4000",
            debit: true,
            unit: 1,
            native: 10,
            base: Some(15),
            entity: None,
        },
    ];
    reversed.push(entry(
        6,
        4,
        20,
        b"reverse-source",
        &reversed_source,
        Some((1, &rates[0], None)),
        Some(&source),
        None,
    ));
    reversed.push(payment(7, 21, b"after-reversal", &effects, &rates[1]));
    assert!(replay_settlements(&reversed, &rates).is_err());
}

#[test]
fn separate_targets_may_share_a_commit_but_same_target_effects_need_order() {
    let (mut records, rates, source) = history(3, 2, (2, 3), (1, 1));
    let another = invoice(6, b"another-invoice", 3, 2, &rates[0]);
    records.push(another.clone());
    records.push(payment(
        7,
        20,
        b"one",
        &component(&source, 0, "1100", true, 1, 1, 1),
        &rates[1],
    ));
    let mut second = payment(
        7,
        20,
        b"two",
        &component(&another, 0, "1100", true, 1, 1, 1),
        &rates[1],
    );
    second.envelope.within_commit_ordinal = 1;
    records.push(second);
    assert_eq!(
        totals(&replay_settlements(&records, &rates).unwrap(), "1100"),
        (4, 2)
    );
    records[7] = payment(
        7,
        20,
        b"two",
        &component(&source, 0, "1100", true, 1, 0, 1),
        &rates[1],
    );
    records[7].envelope.within_commit_ordinal = 1;
    assert!(replay_settlements(&records, &rates).is_err());
}

#[test]
fn same_commit_recorded_undos_commute_but_undo_and_new_relief_do_not() {
    let (mut records, rates, source) = history(3, 2, (2, 3), (1, 1));
    let first_effects = component(&source, 0, "1100", true, 1, 1, 1);
    let second_effects = component(&source, 0, "1100", true, 1, 0, 1);
    let first = payment(6, 20, b"first", &first_effects, &rates[1]);
    let second = payment(7, 21, b"second", &second_effects, &rates[1]);
    let undo_first = application_entry(
        8,
        4,
        22,
        b"undo-first",
        &swapped(&first_effects),
        (4, &rates[1], None),
        Some(&first),
    );
    let mut undo_second = application_entry(
        8,
        4,
        22,
        b"undo-second",
        &swapped(&second_effects),
        (4, &rates[1], None),
        Some(&second),
    );
    undo_second.envelope.within_commit_ordinal = 1;
    records.extend([first, second, undo_first, undo_second]);
    records.push(payment(
        9,
        23,
        b"final",
        &component(&source, 0, "1100", true, 3, 2, 3),
        &rates[1],
    ));
    assert_eq!(
        totals(&replay_settlements(&records, &rates).unwrap(), "1100"),
        (3, 3)
    );
    records[8] = payment(
        8,
        22,
        b"unordered-new",
        &component(&source, 0, "1100", true, 1, 1, 1),
        &rates[1],
    );
    records[8].envelope.within_commit_ordinal = 1;
    assert!(replay_settlements(&records[..9], &rates).is_err());
}

#[test]
fn duplicate_group_targets_and_backdated_relief_are_refused() {
    let (records, rates, source) = history(10, 15, (3, 2), (2, 1));
    let component = component(&source, 0, "1100", true, 2, 3, 4);
    let mut group = component.clone();
    group.extend(component.clone());
    let mut duplicate = records.clone();
    duplicate.push(payment(6, 20, b"duplicate-group", &group, &rates[1]));
    assert!(replay_settlements(&duplicate, &rates).is_err());
    let mut backdated = records;
    backdated.push(payment(6, 25, b"first", &component, &rates[1]));
    backdated.push(payment(7, 24, b"backdated", &component, &rates[1]));
    assert!(replay_settlements(&backdated, &rates).is_err());
}

#[test]
fn settlement_quote_purpose_date_and_prior_custody_are_authenticated() {
    for (purpose, date) in [(1, 20), (3, 20), (4, 21)] {
        let (mut records, mut rates, source) = history(10, 15, (3, 2), (2, 1));
        rates[1] = rate_fixture(2, 1, purpose, date);
        records[4] = intake(&rates[1], 5);
        records.push(payment(
            6,
            20,
            b"payment",
            &component(&source, 0, "1100", true, 4, 6, 8),
            &rates[1],
        ));
        assert!(
            replay_settlements(&records, &rates).is_err(),
            "purpose {purpose}, date {date}"
        );
    }
    for receipt_at in [6, 7] {
        let (mut records, rates, source) = history(10, 15, (3, 2), (2, 1));
        records[4] = intake(&rates[1], receipt_at);
        records.push(payment(
            6,
            20,
            b"payment",
            &component(&source, 0, "1100", true, 4, 6, 8),
            &rates[1],
        ));
        records.sort_by_key(|record| record.envelope.commit_seq);
        assert!(
            replay_settlements(&records, &rates).is_err(),
            "receipt at {receipt_at}"
        );
    }
    let (mut records, mut rates, source) = history(10, 15, (3, 2), (2, 1));
    let mut reader = Reader::new(&rates[1].document);
    reader.u16("version").unwrap();
    reader.fixed::<16>("book").unwrap();
    reader.u8("kind").unwrap();
    reader.bytes(1024, "mime").unwrap();
    reader.u64("size").unwrap();
    reader.fixed::<32>("commitment").unwrap();
    reader.u8("grade").unwrap();
    let at = rates[1].document.len() - reader.remaining();
    rates[1].document[at..at + 16].copy_from_slice(&999u128.to_le_bytes());
    records.push(payment(
        6,
        20,
        b"payment",
        &component(&source, 0, "1100", true, 4, 6, 8),
        &rates[1],
    ));
    assert!(replay_settlements(&records, &rates).is_err());
}

#[test]
fn source_and_component_must_preserve_exact_legal_entity_dimensions() {
    let (mut records, rates, _) = history(10, 15, (3, 2), (2, 1));
    let mut invoice_legs = pair(10, 15);
    invoice_legs[0].code = "1100";
    invoice_legs[1].code = "4000";
    for leg in &mut invoice_legs {
        leg.entity = Some("alpha");
    }
    let source = entry(
        4,
        1,
        10,
        b"invoice",
        &invoice_legs,
        Some((1, &rates[0], None)),
        None,
        None,
    );
    records[3] = source.clone();
    let mut effects = component(&source, 0, "1100", true, 4, 6, 8);
    for applied in &mut effects {
        applied.leg.entity = Some("alpha");
    }
    records.push(payment(6, 20, b"payment", &effects, &rates[1]));
    let spec = book(&["alpha", "beta"]);
    assert!(replay_fixture(&records, Selection::AsOf(58), 6, &spec, &rates).is_ok());
    for applied in &mut effects {
        applied.leg.entity = Some("beta");
    }
    records[5] = payment(6, 20, b"payment", &effects, &rates[1]);
    // Both sides still balance within beta. They cannot relieve alpha's item.
    assert!(replay_fixture(&records, Selection::AsOf(58), 6, &spec, &rates).is_err());
}

#[test]
fn historic_prefix_ignores_future_applications_but_checks_all_known_valuation_claims() {
    let (mut records, rates, source) = history(10, 15, (3, 2), (2, 1));
    records.push(payment(
        6,
        20,
        b"valid",
        &component(&source, 0, "1100", true, 4, 6, 8),
        &rates[1],
    ));
    // Wrong relief is recorded after the trusted historical selection and
    // effective outside P1. Neither fact hides it when it becomes known.
    records.push(payment(
        7,
        40,
        b"bad-future",
        &component(&source, 0, "1100", true, 4, 7, 8),
        &rates[1],
    ));
    assert!(
        replay_fixture(
            &records,
            Selection::Periods(vec!["P1".into()]),
            6,
            &book(&[]),
            &rates
        )
        .is_ok()
    );
    assert!(
        replay_fixture(
            &records,
            Selection::Periods(vec!["P1".into()]),
            7,
            &book(&[]),
            &rates
        )
        .is_err()
    );
}

#[test]
fn full_portable_settlement_bundle_recomputes_and_rejects_a_resealed_wrong_result() {
    let (mut records, rates, source) = history(100, 110, (11, 10), (3, 2));
    records.push(payment(
        6,
        20,
        b"payment",
        &component(&source, 0, "1100", true, 100, 110, 150),
        &rates[1],
    ));
    let selected = Selection::AsOf(58);
    let spec = book(&[]);
    let (expected, output) = replay_fixture(&records, selected.clone(), 6, &spec, &rates).unwrap();
    assert_eq!(totals(&expected, "1100"), (110, 110));
    assert_eq!(totals(&expected, "1000"), (150, 0));
    assert_eq!(totals(&expected, "7000"), (0, 40));
    let (bundle, signed, pin) = pack(&records, &selected, 6, &spec, &rates, &output);
    let verified = verify_report_with_inputs(&bundle, &[], None, None, Some(&pin), None, |_, _| {
        Ok(signed.clone())
    })
    .unwrap();
    assert_eq!(verified.functional_trial_balance, Some(expected));
    let mut forged = output;
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let (bundle, signed, pin) = pack(&records, &selected, 6, &spec, &rates, &forged);
    assert_eq!(
        verify_report_with_inputs(&bundle, &[], None, None, Some(&pin), None, |_, _| Ok(
            signed.clone()
        ))
        .unwrap_err()
        .predicate,
        "report_recomputation"
    );
}

#[test]
fn a_prior_settlement_quote_and_period_average_source_are_supported() {
    let (mut records, mut rates, _) = history(10, 15, (3, 2), (2, 1));
    rates[0] = rate_fixture(3, 2, 3, 30);
    rates[1] = rate_fixture(2, 1, 4, 10);
    records[2] = intake(&rates[0], 3);
    let mut source_legs = pair(10, 15);
    source_legs[0].code = "1100";
    source_legs[1].code = "4000";
    let source = entry(
        4,
        1,
        10,
        b"average-invoice",
        &source_legs,
        Some((3, &rates[0], None)),
        None,
        None,
    );
    records[3] = source.clone();
    records[4] = intake(&rates[1], 5);
    records.push(payment(
        6,
        20,
        b"payment",
        &component(&source, 0, "1100", true, 10, 15, 20),
        &rates[1],
    ));
    let report = replay_settlements(&records, &rates).unwrap();
    assert_eq!(totals(&report, "1100"), (15, 15));
    assert_eq!(totals(&report, "1000"), (20, 0));
    assert_eq!(totals(&report, "7000"), (0, 5));
}

#[test]
fn a_pending_reservation_is_not_a_carrying_open_item() {
    let (mut records, rates, _) = history(10, 15, (3, 2), (2, 1));
    let mut source_legs = pair(10, 15);
    source_legs[0].code = "1100";
    source_legs[1].code = "4000";
    let pending = entry(
        4,
        2,
        10,
        b"pending",
        &source_legs,
        Some((1, &rates[0], None)),
        None,
        None,
    );
    records[3] = pending.clone();
    records.push(payment(
        6,
        20,
        b"payment",
        &component(&pending, 0, "1100", true, 4, 6, 8),
        &rates[1],
    ));
    assert!(replay_settlements(&records, &rates).is_err());
}

#[test]
fn reinstating_an_undone_payment_cannot_spend_capacity_used_by_another_payment() {
    let (mut records, rates, source) = history(10, 15, (3, 2), (2, 1));
    let effects = component(&source, 0, "1100", true, 4, 6, 8);
    let first = payment(6, 20, b"first", &effects, &rates[1]);
    let undo_effects = swapped(&effects);
    let undo = application_entry(
        7,
        4,
        21,
        b"undo",
        &undo_effects,
        (4, &rates[1], None),
        Some(&first),
    );
    records.extend([first, undo.clone()]);
    records.push(payment(
        8,
        22,
        b"all",
        &component(&source, 0, "1100", true, 10, 15, 20),
        &rates[1],
    ));
    records.push(application_entry(
        9,
        4,
        23,
        b"restore",
        &swapped(&undo_effects),
        (4, &rates[1], None),
        Some(&undo),
    ));
    assert!(replay_settlements(&records, &rates).is_err());
}

fn route_record(seq: u64) -> Record {
    let mut body = Writer::default();
    body.fixed(b"FA-FX-ROUTES\0")
        .u16(1)
        .i32(0)
        .u32(0)
        .count(1)
        .u128(id("1100"))
        .u128(id("1110"))
        .u128(id("7001"));
    let mut w = prefix(17, 0);
    w.count(0)
        .u8(1)
        .u8(1)
        .u16(14)
        .bytes(&body.buf)
        .count(0)
        .u8(0)
        .bytes(b"fx-routes")
        .u8(3)
        .u16(1)
        .fixed(&[0; 32])
        .u128(PRINCIPAL)
        .u8(0)
        .count(0)
        .count(0)
        .u8(0)
        .count(0)
        .count(0);
    finish(w, seq)
}

fn route_chart() -> Record {
    let mut chart = Writer::default();
    chart.count(9);
    for (code, typ, unit) in [
        ("1000", 1, 0i64),
        ("1100", 1, 1),
        ("1110", 1, 0),
        ("1900", 1, -1),
        ("2000", 2, 1),
        ("4000", 4, -1),
        ("5000", 5, -1),
        ("7000", 4, 0),
        ("7001", 4, 0),
    ] {
        chart
            .bytes(code.as_bytes())
            .bytes(code.as_bytes())
            .u8(typ)
            .u8(u8::from(matches!(typ, 2..=4)))
            .u8(1)
            .fixed(&unit.to_le_bytes())
            .u8(0);
    }
    schema_record(1, 1, &chart.buf)
}

fn base_adjustment(seq: u64) -> (Record, Vec<TestLeg>) {
    let legs = vec![
        TestLeg {
            code: "1110",
            debit: true,
            unit: 0,
            native: 1,
            base: None,
            entity: None,
        },
        TestLeg {
            code: "7001",
            debit: false,
            unit: 0,
            native: 1,
            base: None,
            entity: None,
        },
    ];
    (
        entry(seq, 7, 20, b"aggregate-adjustment", &legs, None, None, None),
        legs,
    )
}

#[test]
fn dormant_routes_do_not_block_settlement_but_live_aggregate_adjustments_do() {
    let (mut records, rates, source) = history(10, 15, (3, 2), (2, 1));
    records[0] = route_chart();
    records.push(route_record(6));
    let paid = payment(
        7,
        21,
        b"payment",
        &component(&source, 0, "1100", true, 4, 6, 8),
        &rates[1],
    );
    let mut dormant = records.clone();
    dormant.push(paid);
    assert!(replay_settlements(&dormant, &rates).is_ok());
    let (adjustment, legs) = base_adjustment(7);
    records.push(adjustment.clone());
    let paid = payment(
        8,
        21,
        b"payment",
        &component(&source, 0, "1100", true, 4, 6, 8),
        &rates[1],
    );
    let mut live = records.clone();
    live.push(paid);
    assert_eq!(
        replay_settlements(&live, &rates).unwrap_err().predicate,
        "supported_report"
    );
    let reversed: Vec<_> = legs
        .into_iter()
        .map(|mut leg| {
            leg.debit = !leg.debit;
            leg
        })
        .collect();
    records.push(entry(
        8,
        4,
        21,
        b"undo-aggregate",
        &reversed,
        None,
        Some(&adjustment),
        None,
    ));
    records.push(payment(
        9,
        22,
        b"payment",
        &component(&source, 0, "1100", true, 4, 6, 8),
        &rates[1],
    ));
    // A fully undone adjustment restores the source's admissible carrying
    // basis. Its old accounting legs remain in the complete report prefix.
    assert!(replay_settlements(&records, &rates).is_ok());
}

fn with_revaluation_basis(record: &Record, rate: &RateFixture) -> Record {
    let mut basis = Writer::default();
    basis
        .fixed(b"FA-FX-REVALUE\0")
        .u16(1)
        .bytes(b"P1")
        .i32(30)
        .u64(5)
        .u128(id("1100"))
        .u8(0)
        .u128(123)
        .fixed(&[4; 32])
        .fixed(&rate.oid)
        .fixed(&rate.commitment)
        .fixed(&[5; 32]);
    let mut proposal = record.bytes[..record.len].to_vec();
    proposal[2..4].copy_from_slice(&1u16.to_le_bytes());
    let mut w = Writer::default();
    w.fixed(&proposal).count(1).u16(16).bytes(&basis.buf);
    finish(w, record.envelope.commit_seq)
}

#[test]
fn tagged_revaluation_cannot_hide_in_an_at_par_claim_without_declared_routes() {
    let (mut records, rates, source) = history(10, 15, (3, 2), (2, 1));
    records[0] = route_chart();
    let (adjustment, _) = base_adjustment(6);
    let tagged = with_revaluation_basis(&adjustment, &rates[1]);
    records.push(tagged);
    records.push(payment(
        7,
        21,
        b"payment",
        &component(&source, 0, "1100", true, 4, 6, 8),
        &rates[1],
    ));
    // All native and functional totals balance and no route declaration or
    // law2 BaseTotals is present. The authenticated source-basis extension
    // still requires the separate revaluation proof that this format refuses.
    assert_eq!(
        replay_settlements(&records, &rates).unwrap_err().predicate,
        "supported_report"
    );
}
