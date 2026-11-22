//! A quoted Original and its one dependent carrying application may share
//! one publication. These fixtures independently encode and rehash both
//! records; envelope VID order is deliberately not treated as execution order.

use super::*;

fn atomic_history(key: &[u8]) -> (Vec<Record>, Vec<RateFixture>, Record) {
    let (mut records, rates, _) = history(10, 15, (3, 2), (2, 1));
    let source = invoice(6, key, 10, 15, &rates[0]);
    records[3] = source.clone();
    (records, rates, source)
}

fn order_publications(records: &mut [Record]) {
    records.sort_by_key(|record| {
        (
            record.envelope.commit_seq,
            if record.envelope.kind == KIND_ENTRY {
                handle(record).0
            } else {
                0
            },
        )
    });
    let mut previous = None;
    let mut ordinal = 0;
    for record in records {
        if previous == Some(record.envelope.commit_seq) {
            ordinal += 1;
        } else {
            ordinal = 0;
            previous = Some(record.envelope.commit_seq);
        }
        record.envelope.within_commit_ordinal = ordinal;
    }
}

fn refused(mut records: Vec<Record>, rates: &[RateFixture]) {
    order_publications(&mut records);
    assert!(replay_settlements(&records, rates).is_err());
}

#[test]
fn fresh_invoice_partial_application_and_final_remainder_verify_in_a_portable_bundle() {
    let (mut records, rates, source) = atomic_history(b"atomic-invoice");
    records.push(payment(
        6,
        20,
        b"atomic-partial",
        &component(&source, 0, "1100", true, 4, 6, 8),
        &rates[1],
    ));
    records.push(payment(
        7,
        21,
        b"remaining-payment",
        &component(&source, 0, "1100", true, 6, 9, 12),
        &rates[1],
    ));
    order_publications(&mut records);
    let selected = Selection::AsOf(58);
    let spec = book(&[]);
    let (prefix, _) = replay_fixture(&records, selected.clone(), 6, &spec, &rates).unwrap();
    assert_eq!(totals(&prefix, "1100"), (15, 6));
    assert_eq!(totals(&prefix, "1000"), (8, 0));

    let (expected, output) = replay_fixture(&records, selected.clone(), 7, &spec, &rates).unwrap();
    assert_eq!(totals(&expected, "1100"), (15, 15));
    assert_eq!(totals(&expected, "1000"), (20, 0));
    assert_eq!(totals(&expected, "7000"), (0, 5));
    let (bundle, signed, pin) = pack(&records, &selected, 7, &spec, &rates, &output);
    let verified = verify_report_with_inputs(&bundle, &[], None, None, Some(&pin), None, |_, _| {
        Ok(signed.clone())
    })
    .unwrap();
    assert_eq!(verified.functional_trial_balance, Some(expected));

    let mut forged = output;
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let (bundle, signed, pin) = pack(&records, &selected, 7, &spec, &rates, &forged);
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
fn the_fresh_dependency_is_independent_of_the_signed_vid_rank() {
    let mut covered = [false; 2];
    for nonce in 0..64 {
        let source_key = format!("ranked-invoice-{nonce}");
        let payment_key = format!("ranked-payment-{nonce}");
        let (mut records, rates, source) = atomic_history(source_key.as_bytes());
        let paid = payment(
            6,
            20,
            payment_key.as_bytes(),
            &component(&source, 0, "1100", true, 4, 6, 8),
            &rates[1],
        );
        let source_first = handle(&source).0 < handle(&paid).0;
        let slot = usize::from(source_first);
        if covered[slot] {
            continue;
        }
        records.push(paid);
        order_publications(&mut records);
        assert_eq!(
            totals(&replay_settlements(&records, &rates).unwrap(), "1100"),
            (15, 6)
        );
        covered[slot] = true;
        if covered == [true; 2] {
            break;
        }
    }
    assert_eq!(covered, [true; 2]);
}

#[test]
fn fresh_period_average_sources_keep_their_independently_checked_quote() {
    let (mut records, mut rates, _) = atomic_history(b"unused");
    rates[0] = rate_fixture(3, 2, 3, 30);
    records[2] = intake(&rates[0], 3);
    let mut source_legs = pair(10, 15);
    source_legs[0].code = "1100";
    source_legs[1].code = "4000";
    let source = entry(
        6,
        1,
        10,
        b"atomic-average",
        &source_legs,
        Some((3, &rates[0], None)),
        None,
        None,
    );
    records[3] = source.clone();
    records.push(payment(
        6,
        20,
        b"average-payment",
        &component(&source, 0, "1100", true, 10, 15, 20),
        &rates[1],
    ));
    order_publications(&mut records);
    assert_eq!(
        totals(&replay_settlements(&records, &rates).unwrap(), "1100"),
        (15, 15)
    );
}

#[test]
fn fresh_sources_require_the_exact_handle_eligible_class_and_publication() {
    let (records, rates, source) = atomic_history(b"exact-atomic-source");
    let effects = component(&source, 0, "1100", true, 4, 6, 8);
    let mut wrong_digest = effects.clone();
    wrong_digest[0].applications[0].digest[0] ^= 1;
    let mut wrong_ordinal = effects.clone();
    wrong_ordinal[0].applications[0].ordinal = 1;
    for rejected in [wrong_digest, wrong_ordinal] {
        let mut forged = records.clone();
        forged.push(payment(6, 20, b"forged-target", &rejected, &rates[1]));
        refused(forged, &rates);
    }

    let mut future = records.clone();
    future[3].envelope.commit_seq = 7;
    future.push(payment(6, 20, b"future-source", &effects, &rates[1]));
    refused(future, &rates);

    let mut source_legs = pair(10, 15);
    source_legs[0].code = "1100";
    source_legs[1].code = "4000";
    for class in [2, 7] {
        let target = entry(
            6,
            class,
            10,
            b"wrong-source-class",
            &source_legs,
            Some((1, &rates[0], None)),
            None,
            None,
        );
        let mut forged = records.clone();
        forged[3] = target.clone();
        forged.push(payment(
            6,
            20,
            b"wrong-class-payment",
            &component(&target, 0, "1100", true, 4, 6, 8),
            &rates[1],
        ));
        refused(forged, &rates);
    }
}

#[test]
fn fresh_relief_cannot_reprice_exceed_capacity_or_run_backwards() {
    let (records, rates, source) = atomic_history(b"bounded-fresh-source");
    for (native, relief, cash, date) in [(4, 7, 8, 20), (11, 17, 22, 20), (4, 6, 8, 9)] {
        let mut forged = records.clone();
        forged.push(payment(
            6,
            date,
            b"invalid-relief",
            &component(&source, 0, "1100", true, native, relief, cash),
            &rates[1],
        ));
        refused(forged, &rates);
    }

    let mut duplicate = records.clone();
    for key in [b"first-relief".as_slice(), b"second-relief".as_slice()] {
        duplicate.push(payment(
            6,
            20,
            key,
            &component(&source, 0, "1100", true, 4, 6, 8),
            &rates[1],
        ));
    }
    // Total relief remains inside 10/15, so capacity alone cannot reject
    // these two independently rounded effects on one same-publication target.
    refused(duplicate, &rates);
}

#[test]
fn fresh_sources_have_no_extensions_or_outgoing_application_dependencies() {
    let (records, rates, source) = atomic_history(b"plain-fresh-source");
    let mut proposal = source.bytes[..source.len].to_vec();
    proposal[2..4].copy_from_slice(&1u16.to_le_bytes());
    let mut w = Writer::default();
    w.fixed(&proposal).count(1).u16(6).bytes(&[0; 48]);
    let extended = finish(w, 6);
    let mut with_extension = records.clone();
    with_extension[3] = extended.clone();
    with_extension.push(payment(
        6,
        20,
        b"extended-source-payment",
        &component(&extended, 0, "1100", true, 4, 6, 8),
        &rates[1],
    ));
    refused(with_extension, &rates);

    let mut applying_source = vec![leg("1100", true, 1, 10, 15), leg("4000", false, 1, 10, 15)];
    applying_source[0].applications.push(Application {
        identity: handle(&source).0,
        digest: source.envelope.record_digest,
        ordinal: 0,
        unit: 1,
        amount: 10,
    });
    let chained = application_entry(
        6,
        1,
        10,
        b"applying-source",
        &applying_source,
        (1, &rates[0], None),
        None,
    );
    let mut with_dependency = records;
    with_dependency[3] = chained.clone();
    with_dependency.push(payment(
        6,
        20,
        b"chained-payment",
        &component(&chained, 0, "1100", true, 4, 6, 8),
        &rates[1],
    ));
    refused(with_dependency, &rates);
}

#[test]
fn only_the_exact_fresh_source_leg_may_touch_a_carried_account() {
    let (mut records, rates, source) = atomic_history(b"isolated-fresh-source");
    records.push(payment(
        6,
        20,
        b"isolated-payment",
        &component(&source, 0, "1100", true, 4, 6, 8),
        &rates[1],
    ));
    let mut poisoned = records.clone();
    poisoned.push(invoice(6, b"unrelated-invoice", 2, 3, &rates[0]));
    refused(poisoned, &rates);

    let ordinary = vec![
        TestLeg {
            code: "5000",
            debit: true,
            unit: 0,
            native: 3,
            base: None,
            entity: None,
        },
        TestLeg {
            code: "1000",
            debit: false,
            unit: 0,
            native: 3,
            base: None,
            entity: None,
        },
    ];
    records.push(entry(
        6,
        1,
        20,
        b"ordinary-companion",
        &ordinary,
        None,
        None,
        None,
    ));
    order_publications(&mut records);
    assert_eq!(
        totals(&replay_settlements(&records, &rates).unwrap(), "1000"),
        (8, 3)
    );

    let (mut valuation, rates, source) = atomic_history(b"valuation-isolation");
    valuation[0] = route_chart();
    valuation[2].envelope.commit_seq = 4;
    valuation.push(route_record(3));
    valuation.push(payment(
        6,
        20,
        b"valuation-payment",
        &component(&source, 0, "1100", true, 4, 6, 8),
        &rates[1],
    ));
    let (_, legs) = base_adjustment(6);
    valuation.push(entry(
        6,
        1,
        20,
        b"valuation-poison",
        &legs,
        None,
        None,
        None,
    ));
    refused(valuation, &rates);
}

#[test]
fn a_later_exact_undo_restores_the_fresh_sources_original_capacity() {
    let (mut records, rates, source) = atomic_history(b"undo-fresh-source");
    let effects = component(&source, 0, "1100", true, 4, 6, 8);
    let first = payment(6, 20, b"first-payment", &effects, &rates[1]);
    let undo = application_entry(
        7,
        4,
        21,
        b"undo-first-payment",
        &swapped(&effects),
        (4, &rates[1], None),
        Some(&first),
    );
    records.extend([first, undo]);
    records.push(payment(
        8,
        22,
        b"final-payment",
        &component(&source, 0, "1100", true, 10, 15, 20),
        &rates[1],
    ));
    order_publications(&mut records);
    let report = replay_settlements(&records, &rates).unwrap();
    assert_eq!(totals(&report, "1100"), (21, 21));
    assert_eq!(totals(&report, "1000"), (28, 8));
}
