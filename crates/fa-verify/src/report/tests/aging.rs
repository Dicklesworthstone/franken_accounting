//! Hand-calculated historical aging fixtures over independently encoded native
//! OpenItems sources. The fixture encoder is separate from the replay encoder.
use super::*;
use crate::report::{
    VerifiedAgedOpenItem, VerifiedAging, VerifiedAgingAmounts, VerifiedAgingBand,
    VerifiedAgingCell, VerifiedAgingTotal,
};

const BOUNDS: &[u32] = &[0, 30, 60, 90];

fn dated((mut record, identity): (Record, u128), day: i32) -> (Record, u128) {
    record.bytes[38..42].copy_from_slice(&day.to_le_bytes());
    let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&record.bytes[..record.len]]);
    let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal_digest, &[]]);
    record.bytes[record.len..record.len + 32].copy_from_slice(&proposal_digest);
    record.bytes[record.len + 32..].copy_from_slice(&digest);
    record.envelope =
        envelope_of_entry(&record.bytes, record.len, record.envelope.commit_seq, 0).unwrap();
    (record, identity)
}

fn sample(known_at: u64) -> (Vec<Record>, VerifiedOpenItems, u128, u128) {
    let mut records = schema();
    let invoice_legs = [leg("1000", true, 100), leg("3000", false, 100)];
    let (invoice, invoice_id) = dated(
        posting(1, 3, b"aging-invoice", &invoice_legs, None, None),
        10,
    );
    let mut receipt_legs = [leg("1000", false, 40), leg("3000", true, 40)];
    receipt_legs[0]
        .settles
        .push(application(&invoice, invoice_id, 0, 40));
    let (receipt, receipt_id) = dated(
        posting(1, 4, b"aging-receipt", &receipt_legs, None, None),
        40,
    );
    let (undo, _) = dated(
        reverse(&receipt, receipt_id, 5, b"aging-undo", &receipt_legs),
        70,
    );
    records.extend([invoice, receipt, undo]);
    let history = if known_at < 4 {
        vec![]
    } else {
        vec![VerifiedApplication {
            entry: receipt_id,
            ordinal: 0,
            amount: 40,
            recorded_at: 4,
            live: known_at < 5,
        }]
    };
    let applied = if known_at == 4 { 40 } else { 0 };
    let mut items = vec![item(
        invoice_id,
        0,
        "1000",
        true,
        3,
        100,
        applied,
        0,
        100 - applied,
        history,
    )];
    if known_at == 4 {
        let mut payment = item(receipt_id, 0, "1000", false, 4, 40, 0, 40, 0, vec![]);
        payment.effective_date = 40;
        items.push(payment);
    }
    (
        records,
        report(Some(account_id("1000")), items),
        invoice_id,
        receipt_id,
    )
}

fn conventional_bands() -> Vec<VerifiedAgingBand> {
    [
        (0, Some(0)),
        (1, Some(30)),
        (31, Some(60)),
        (61, Some(90)),
        (91, None),
    ]
    .into_iter()
    .map(|(lower_inclusive, upper_inclusive)| VerifiedAgingBand {
        lower_inclusive,
        upper_inclusive,
    })
    .collect()
}

fn expected_one(known_at: u64, cutoff: i32, aged: VerifiedAgedOpenItem) -> VerifiedAging {
    let amounts = VerifiedAgingAmounts {
        debits: aged.item.open,
        credits: 0,
        item_count: 1,
    };
    VerifiedAging {
        book_id: BOOK,
        known_at,
        effective_through: cutoff,
        account_filter: Some(account_id("1000")),
        source_certificate_digest: [0; 32],
        bands: conventional_bands(),
        cells: vec![VerifiedAgingCell {
            account: account_id("1000"),
            unit_id: 1,
            bucket: aged.bucket,
            amounts: amounts.clone(),
        }],
        totals: vec![VerifiedAgingTotal {
            account: account_id("1000"),
            unit_id: 1,
            amounts,
        }],
        items: vec![aged],
    }
}

fn expected_bytes(report: &VerifiedAging) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(b"fa:effective-date-aging:v1")
        .fixed(&report.book_id)
        .u64(report.known_at)
        .i32(report.effective_through)
        .u8(u8::from(report.account_filter.is_some()));
    if let Some(account) = report.account_filter {
        w.u128(account);
    }
    w.count(report.bands.len());
    for band in &report.bands {
        w.u64(band.lower_inclusive)
            .u8(u8::from(band.upper_inclusive.is_some()));
        if let Some(upper) = band.upper_inclusive {
            w.u64(upper);
        }
    }
    w.count(report.items.len());
    for row in &report.items {
        let i = &row.item;
        w.u128(i.entry)
            .u16(i.ordinal)
            .u128(i.account)
            .u32(i.unit_id)
            .u8(u8::from(!i.debit))
            .i32(i.effective_date)
            .u64(i.recorded_at)
            .i128(i.original)
            .i128(i.applied)
            .i128(i.applied_out)
            .i128(i.open)
            .count(i.applications.len());
        for a in &i.applications {
            w.u128(a.entry)
                .u16(a.ordinal)
                .i128(a.amount)
                .u64(a.recorded_at)
                .u8(u8::from(a.live));
        }
        w.u64(row.age_days).u32(row.bucket as u32);
    }
    w.count(report.cells.len());
    for c in &report.cells {
        w.u128(c.account)
            .u32(c.unit_id)
            .u32(c.bucket as u32)
            .i128(c.amounts.debits)
            .i128(c.amounts.credits)
            .u64(c.amounts.item_count);
    }
    w.count(report.totals.len());
    for t in &report.totals {
        w.u128(t.account)
            .u32(t.unit_id)
            .i128(t.amounts.debits)
            .i128(t.amounts.credits)
            .u64(t.amounts.item_count);
    }
    w.buf
}

fn wrap(native: &[u8], cutoff: i32, bounds: &[u32], output: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let mut r = Reader::new(native);
    assert_eq!(r.bytes(64, "format").unwrap(), REPORT_BUNDLE_FORMAT);
    assert_eq!(r.u16("major").unwrap(), 2);
    assert_eq!(r.u16("minor").unwrap(), 0);
    let source = r.bytes(MAX_REPORT_BUNDLE_BYTES, "source").unwrap();
    let rest = &native[native.len() - r.remaining()..];
    let mut outer = Writer::default();
    outer
        .bytes(b"fa:aging-certificate:v1")
        .u128(PRINCIPAL)
        .fixed(&[9; 32])
        .bytes(source)
        .i32(cutoff)
        .count(bounds.len());
    for bound in bounds {
        outer.u32(*bound);
    }
    outer.bytes(output);
    // fa_model::domain_digest frames each part; native ReportCertificate does not.
    let body_len = (outer.buf.len() as u32).to_le_bytes();
    let pin = hash_parts(b"fa:aging-certificate-digest:v1", &[&body_len, &outer.buf]);
    outer.fixed(&pin);
    let mut bundle = Writer::default();
    bundle
        .bytes(REPORT_BUNDLE_FORMAT)
        .u16(2)
        .u16(0)
        .bytes(&outer.buf)
        .fixed(rest);
    (bundle.buf, pin)
}

fn verify_aging(
    records: &[Record],
    known_at: u64,
    source: &VerifiedOpenItems,
    cutoff: i32,
    bounds: &[u32],
    expected: &VerifiedAging,
) -> Result<VerifiedReport, ReportError> {
    let (native, anchor, _) = pack(records, known_at, source);
    let (bundle, pin) = wrap(&native, cutoff, bounds, &expected_bytes(expected));
    verify_report_with(&bundle, &[], None, None, Some(&pin), |_, _| Ok(anchor))
}

#[test]
fn effective_cutoff_precedes_settlement_and_reversal_netting_at_each_known_at() {
    for (known_at, cutoff, open, bucket, application_live) in [
        (3, 30, 100, 1, None),
        (4, 30, 100, 1, None),
        (5, 30, 100, 1, None),
        (4, 45, 60, 2, Some(true)),
        (5, 45, 60, 2, Some(true)),
        (5, 90, 100, 3, Some(false)),
    ] {
        let (records, source, invoice, receipt) = sample(known_at);
        let applications = application_live
            .map(|live| VerifiedApplication {
                entry: receipt,
                ordinal: 0,
                amount: 40,
                recorded_at: 4,
                live,
            })
            .into_iter()
            .collect();
        let aged = VerifiedAgedOpenItem {
            item: item(
                invoice,
                0,
                "1000",
                true,
                3,
                100,
                100 - open,
                0,
                open,
                applications,
            ),
            age_days: (cutoff - 10) as u64,
            bucket,
        };
        let mut expected = expected_one(known_at, cutoff, aged);
        let (_, _, source_pin) = pack(&records, known_at, &source);
        expected.source_certificate_digest = source_pin;
        let actual = verify_aging(&records, known_at, &source, cutoff, BOUNDS, &expected)
            .unwrap_or_else(|e| panic!("known_at={known_at}, cutoff={cutoff}: {e}"));
        assert_eq!(actual.aging.as_ref(), Some(&expected));
        assert_eq!(actual.output, expected_bytes(&expected));
        assert_eq!(actual.effective_through, Some(cutoff));
        assert!(
            actual.open_items.is_none() && actual.statement.is_none() && actual.rows.is_empty()
        );
    }
}

#[test]
fn aging_pin_authenticates_the_outer_question_and_never_only_its_native_source() {
    let (records, source, invoice, _) = sample(5);
    let expected = expected_one(
        5,
        30,
        VerifiedAgedOpenItem {
            item: item(invoice, 0, "1000", true, 3, 100, 0, 0, 100, vec![]),
            age_days: 20,
            bucket: 1,
        },
    );
    let (native, anchor, source_pin) = pack(&records, 5, &source);
    let (bundle, outer_pin) = wrap(&native, 30, BOUNDS, &expected_bytes(&expected));
    assert_ne!(source_pin, outer_pin);
    let verified = verify_report_with(&bundle, &[], None, None, Some(&outer_pin), |_, _| {
        Ok(anchor.clone())
    })
    .unwrap();
    assert_eq!(verified.certificate_digest, outer_pin);
    assert_eq!(
        verified.aging.unwrap().source_certificate_digest,
        source_pin
    );
    for (pin, predicate) in [
        (Some(&source_pin), "recipient_certificate"),
        (None, "report_input_authority"),
    ] {
        assert_eq!(
            verify_report_with(&bundle, &[], None, None, pin, |_, _| Ok(anchor.clone()),)
                .unwrap_err()
                .predicate,
            predicate
        );
    }
    let (changed_cutoff, _) = wrap(&native, 31, BOUNDS, &expected_bytes(&expected));
    let (changed_buckets, _) = wrap(&native, 30, &[0, 20, 60, 90], &expected_bytes(&expected));
    for tampered in [changed_cutoff, changed_buckets] {
        assert_eq!(
            verify_report_with(&tampered, &[], None, None, Some(&outer_pin), |_, _| Ok(
                anchor.clone()
            ),)
            .unwrap_err()
            .predicate,
            "recipient_certificate"
        );
    }
}

#[test]
fn resealed_aging_item_history_bucket_cell_total_and_omission_never_verify() {
    let (records, source, invoice, receipt) = sample(5);
    let expected = expected_one(
        5,
        90,
        VerifiedAgedOpenItem {
            item: item(
                invoice,
                0,
                "1000",
                true,
                3,
                100,
                0,
                0,
                100,
                vec![VerifiedApplication {
                    entry: receipt,
                    ordinal: 0,
                    amount: 40,
                    recorded_at: 4,
                    live: false,
                }],
            ),
            age_days: 80,
            bucket: 3,
        },
    );
    for mutation in 0..10 {
        let mut changed = expected.clone();
        match mutation {
            0 => changed.items[0].item.open = 99,
            1 => changed.items[0].age_days = 79,
            2 => changed.items[0].bucket = 2,
            3 => changed.items[0].item.applications[0].live = true,
            4 => changed.cells[0].amounts.debits = 99,
            5 => changed.totals[0].amounts.item_count = 2,
            6 => changed.items.clear(),
            7 => changed.bands[3].upper_inclusive = Some(89),
            8 => changed.items[0].item.recorded_at = 4,
            9 => changed.items.push(changed.items[0].clone()),
            _ => unreachable!(),
        }
        assert_eq!(
            verify_aging(&records, 5, &source, 90, BOUNDS, &changed,)
                .unwrap_err()
                .predicate,
            "report_recomputation",
            "mutation {mutation}"
        );
    }
}

#[test]
fn aging_never_ignores_a_false_nested_source_or_tampered_excluded_payload() {
    let (mut records, mut source, invoice, _) = sample(5);
    let expected = expected_one(
        5,
        30,
        VerifiedAgedOpenItem {
            item: item(invoice, 0, "1000", true, 3, 100, 0, 0, 100, vec![]),
            age_days: 20,
            bucket: 1,
        },
    );
    source.items[0].open = 99;
    assert_eq!(
        verify_aging(&records, 5, &source, 30, BOUNDS, &expected)
            .unwrap_err()
            .predicate,
        "report_recomputation"
    );
    source.items[0].open = 100;
    records.last_mut().unwrap().bytes[38] ^= 1;
    assert_eq!(
        verify_aging(&records, 5, &source, 30, BOUNDS, &expected)
            .unwrap_err()
            .predicate,
        "record_derivation"
    );
}

#[test]
fn aging_empty_filters_zero_open_items_and_empty_bucket_bounds_are_exact() {
    let records = schema();
    let source = report(Some(account_id("1000")), vec![]);
    let expected = VerifiedAging {
        book_id: BOOK,
        known_at: 2,
        effective_through: -1,
        account_filter: Some(account_id("1000")),
        source_certificate_digest: [0; 32],
        bands: vec![VerifiedAgingBand {
            lower_inclusive: 0,
            upper_inclusive: None,
        }],
        items: vec![],
        cells: vec![],
        totals: vec![],
    };
    let actual = verify_aging(&records, 2, &source, -1, &[], &expected).unwrap();
    assert!(actual.aging.unwrap().items.is_empty());
    assert_eq!(actual.output, expected_bytes(&expected));
    for bounds in [vec![30, 30], vec![30, 0], vec![0; 129]] {
        let error = verify_aging(&records, 2, &source, -1, &bounds, &expected).unwrap_err();
        assert!(matches!(
            error.predicate,
            "aging_buckets" | "canonical_encoding"
        ));
    }
}

fn empty_expected(known_at: u64, cutoff: i32) -> VerifiedAging {
    VerifiedAging {
        book_id: BOOK,
        known_at,
        effective_through: cutoff,
        account_filter: Some(account_id("1000")),
        source_certificate_digest: [0; 32],
        bands: conventional_bands(),
        items: vec![],
        cells: vec![],
        totals: vec![],
    }
}

#[test]
fn selected_backdated_settlements_and_reversals_cannot_cross_the_effective_cutoff() {
    for reversal in [false, true] {
        let mut records = schema();
        let target_legs = [leg("1000", true, 100), leg("3000", false, 100)];
        let (target, target_id) = dated(
            posting(1, 3, b"future-target", &target_legs, None, None),
            40,
        );
        let (next, next_id) = if reversal {
            dated(
                reverse(&target, target_id, 4, b"backdated-reversal", &target_legs),
                10,
            )
        } else {
            let mut legs = [leg("1000", false, 40), leg("3000", true, 40)];
            legs[0].settles.push(application(&target, target_id, 0, 40));
            dated(
                posting(1, 4, b"backdated-settlement", &legs, None, None),
                10,
            )
        };
        records.extend([target, next]);
        let items = if reversal {
            vec![]
        } else {
            let mut target_item = item(
                target_id,
                0,
                "1000",
                true,
                3,
                100,
                40,
                0,
                60,
                vec![VerifiedApplication {
                    entry: next_id,
                    ordinal: 0,
                    amount: 40,
                    recorded_at: 4,
                    live: true,
                }],
            );
            target_item.effective_date = 40;
            vec![
                target_item,
                item(next_id, 0, "1000", false, 4, 40, 0, 40, 0, vec![]),
            ]
        };
        let source = report(Some(account_id("1000")), items);
        assert_eq!(
            verify_aging(&records, 4, &source, 30, BOUNDS, &empty_expected(4, 30),)
                .unwrap_err()
                .predicate,
            "aging_effective_selection",
            "reversal={reversal}"
        );
    }
}

#[test]
fn account_filtered_aging_does_not_reject_an_unrelated_cross_cutoff_application() {
    let mut records = schema();
    let (future, future_id) = dated(
        posting(
            1,
            3,
            b"other-account-future",
            &[leg("1000", true, 100), leg("3000", false, 100)],
            None,
            None,
        ),
        40,
    );
    let mut payment_legs = [leg("1000", false, 40), leg("3000", true, 40)];
    payment_legs[1]
        .settles
        .push(application(&future, future_id, 1, 40));
    let (payment, payment_id) = dated(
        posting(1, 4, b"other-account-backdated", &payment_legs, None, None),
        10,
    );
    records.extend([future, payment]);
    let mut future_item = item(future_id, 0, "1000", true, 3, 100, 0, 0, 100, vec![]);
    future_item.effective_date = 40;
    let payment_item = item(payment_id, 0, "1000", false, 4, 40, 0, 0, 40, vec![]);
    let source = report(
        Some(account_id("1000")),
        vec![future_item, payment_item.clone()],
    );
    let mut expected = expected_one(
        4,
        30,
        VerifiedAgedOpenItem {
            item: payment_item,
            age_days: 20,
            bucket: 1,
        },
    );
    for amounts in [
        &mut expected.cells[0].amounts,
        &mut expected.totals[0].amounts,
    ] {
        amounts.debits = 0;
        amounts.credits = 40;
    }
    let actual = verify_aging(&records, 4, &source, 30, BOUNDS, &expected).unwrap();
    assert_eq!(actual.output, expected_bytes(&expected));
}

#[test]
fn a_historical_projection_is_not_mistaken_for_an_admitted_commit_prefix() {
    let mut records = schema();
    let invoice_legs = [leg("1000", true, 100), leg("3000", false, 100)];
    let (invoice, invoice_id) = dated(
        posting(1, 3, b"capacity-invoice", &invoice_legs, None, None),
        10,
    );
    let mut a_legs = [leg("1000", false, 70), leg("3000", true, 70)];
    a_legs[0]
        .settles
        .push(application(&invoice, invoice_id, 0, 70));
    let (a, a_id) = dated(posting(1, 4, b"payment-a", &a_legs, None, None), 10);
    let (undo_a, _) = dated(reverse(&a, a_id, 5, b"undo-a-future", &a_legs), 40);
    let mut b_legs = [leg("1000", false, 80), leg("3000", true, 80)];
    b_legs[0]
        .settles
        .push(application(&invoice, invoice_id, 0, 80));
    let (b, b_id) = dated(posting(1, 6, b"payment-b", &b_legs, None, None), 10);
    let (undo_b, _) = dated(reverse(&b, b_id, 7, b"undo-b-backdated", &b_legs), 10);
    records.extend([invoice, a, undo_a, b, undo_b]);
    let source = report(
        Some(account_id("1000")),
        vec![item(
            invoice_id,
            0,
            "1000",
            true,
            3,
            100,
            0,
            0,
            100,
            vec![
                VerifiedApplication {
                    entry: a_id,
                    ordinal: 0,
                    amount: 70,
                    recorded_at: 4,
                    live: false,
                },
                VerifiedApplication {
                    entry: b_id,
                    ordinal: 0,
                    amount: 80,
                    recorded_at: 6,
                    live: false,
                },
            ],
        )],
    );
    let expected = expected_one(
        7,
        30,
        VerifiedAgedOpenItem {
            item: item(
                invoice_id,
                0,
                "1000",
                true,
                3,
                100,
                70,
                0,
                30,
                vec![
                    VerifiedApplication {
                        entry: a_id,
                        ordinal: 0,
                        amount: 70,
                        recorded_at: 4,
                        live: true,
                    },
                    VerifiedApplication {
                        entry: b_id,
                        ordinal: 0,
                        amount: 80,
                        recorded_at: 6,
                        live: false,
                    },
                ],
            ),
            age_days: 20,
            bucket: 1,
        },
    );
    // The actual history never over-applies. Removing the future-effective
    // undo-a makes the subset appear to hold 150 at seq6, but seq7 undoes b.
    // Its final historical balance is 30 and native aging accepts that view.
    let actual = verify_aging(&records, 7, &source, 30, BOUNDS, &expected).unwrap();
    assert_eq!(actual.output, expected_bytes(&expected));
}

#[test]
fn aging_never_loses_a_live_credit_stranded_on_a_reversed_target() {
    let mut records = schema();
    let invoice_legs = [leg("1000", true, 100), leg("3000", false, 100)];
    let (invoice, invoice_id) = dated(
        posting(1, 3, b"stranded-invoice", &invoice_legs, None, None),
        10,
    );
    let mut payment_legs = [leg("1000", false, 40), leg("3000", true, 40)];
    payment_legs[0]
        .settles
        .push(application(&invoice, invoice_id, 0, 40));
    let (payment, payment_id) = dated(
        posting(1, 4, b"stranded-payment", &payment_legs, None, None),
        10,
    );
    let (undo_payment, _) = dated(
        reverse(
            &payment,
            payment_id,
            5,
            b"future-payment-undo",
            &payment_legs,
        ),
        40,
    );
    let (undo_invoice, _) = dated(
        reverse(
            &invoice,
            invoice_id,
            6,
            b"backdated-invoice-undo",
            &invoice_legs,
        ),
        20,
    );
    records.extend([invoice, payment, undo_payment, undo_invoice]);
    // Actual commit history is valid: the payment is undone before its target.
    // At this effective cutoff the payment is still live, so accepting an empty
    // schedule would lose its credit after discarding the reversed target.
    let source = report(Some(account_id("1000")), vec![]);
    assert!(verify(&records, 6, &source).is_ok());
    assert_eq!(
        verify_aging(&records, 6, &source, 30, BOUNDS, &empty_expected(6, 30),)
            .unwrap_err()
            .predicate,
        "aging_effective_selection"
    );
}

#[test]
fn aging_preserves_native_units_debit_credit_columns_and_inclusive_bucket_edges() {
    let mut chart = Writer::default();
    chart.count(2);
    for (code, name, typ, normal) in [("1000", "Cash", 1, 0), ("3000", "Equity", 3, 1)] {
        chart
            .bytes(code.as_bytes())
            .bytes(name.as_bytes())
            .u8(typ)
            .u8(normal)
            .u8(1)
            .fixed(&(-2i64).to_le_bytes())
            .u8(0);
    }
    let mut records = vec![record(
        17,
        1,
        0,
        b"aging-any-unit",
        0,
        Some((1, &chart.buf)),
        None,
        None,
    )];
    records.push(schema().pop().unwrap());
    let mut source_items = Vec::new();
    let mut aged_items = Vec::new();
    for (offset, (effective, debit, unit, amount, age_days, bucket)) in [
        (10, true, 1, 100, 30, 1),
        (9, true, 1, 50, 31, 2),
        (40, false, 1, 25, 0, 0),
        (10, true, 2, 1000, 30, 1),
        (10, false, 2, 1000, 30, 1),
    ]
    .into_iter()
    .enumerate()
    {
        let seq = offset as u64 + 3;
        let mut legs = [leg("1000", debit, amount), leg("3000", !debit, amount)];
        for leg in &mut legs {
            leg.unit = unit;
        }
        let (entry, id) = dated(
            posting(1, seq, &[b'a', offset as u8], &legs, None, None),
            effective,
        );
        records.push(entry);
        let mut row = item(id, 0, "1000", debit, seq, amount, 0, 0, amount, vec![]);
        row.effective_date = effective;
        row.unit_id = unit;
        source_items.push(row.clone());
        aged_items.push(VerifiedAgedOpenItem {
            item: row,
            age_days,
            bucket,
        });
    }
    let mut source = report(Some(account_id("1000")), source_items);
    source
        .accounts
        .get_mut(&account_id("1000"))
        .unwrap()
        .unit_policy = OpenItemUnitPolicy::AnyUnit;
    aged_items.sort_by_key(|row| {
        (
            row.item.account,
            row.item.unit_id,
            row.bucket,
            row.item.effective_date,
            row.item.recorded_at,
            row.item.entry,
            row.item.ordinal,
        )
    });
    let account = account_id("1000");
    let amounts = |debits, credits, item_count| VerifiedAgingAmounts {
        debits,
        credits,
        item_count,
    };
    let expected = VerifiedAging {
        book_id: BOOK,
        known_at: 7,
        effective_through: 40,
        account_filter: Some(account),
        source_certificate_digest: [0; 32],
        bands: conventional_bands(),
        items: aged_items,
        cells: vec![
            VerifiedAgingCell {
                account,
                unit_id: 1,
                bucket: 0,
                amounts: amounts(0, 25, 1),
            },
            VerifiedAgingCell {
                account,
                unit_id: 1,
                bucket: 1,
                amounts: amounts(100, 0, 1),
            },
            VerifiedAgingCell {
                account,
                unit_id: 1,
                bucket: 2,
                amounts: amounts(50, 0, 1),
            },
            VerifiedAgingCell {
                account,
                unit_id: 2,
                bucket: 1,
                amounts: amounts(1000, 1000, 2),
            },
        ],
        totals: vec![
            VerifiedAgingTotal {
                account,
                unit_id: 1,
                amounts: amounts(150, 25, 3),
            },
            VerifiedAgingTotal {
                account,
                unit_id: 2,
                amounts: amounts(1000, 1000, 2),
            },
        ],
    };
    let actual = verify_aging(&records, 7, &source, 40, BOUNDS, &expected).unwrap();
    assert_eq!(actual.output, expected_bytes(&expected));
    assert_eq!(actual.aging.unwrap().totals, expected.totals);
}

#[test]
fn aging_aggregate_overflow_is_refused_without_wrapping_or_truncating_items() {
    let mut records = schema();
    let mut items = Vec::new();
    for (seq, amount) in [(3, i128::MAX), (4, 1)] {
        let (entry, id) = posting(
            1,
            seq,
            &[seq as u8],
            &[leg("1000", true, amount), leg("3000", false, amount)],
            None,
            None,
        );
        records.push(entry);
        items.push(item(id, 0, "1000", true, seq, amount, 0, 0, amount, vec![]));
    }
    let source = report(Some(account_id("1000")), items);
    assert_eq!(
        verify_aging(&records, 4, &source, 30, BOUNDS, &empty_expected(4, 30))
            .unwrap_err()
            .predicate,
        "exact_arithmetic"
    );
}

#[test]
fn aging_uses_wide_civil_day_differences_and_preserves_the_u32_max_bucket_tail() {
    let mut records = schema();
    let (entry, id) = dated(
        posting(
            1,
            3,
            b"minimum-effective-day",
            &[leg("1000", true, 5), leg("3000", false, 5)],
            None,
            None,
        ),
        i32::MIN,
    );
    records.push(entry);
    let mut source_item = item(id, 0, "1000", true, 3, 5, 0, 0, 5, vec![]);
    source_item.effective_date = i32::MIN;
    let source = report(Some(account_id("1000")), vec![source_item.clone()]);
    for (cutoff, bound, age) in [(i32::MIN, 0, 0), (i32::MAX, u32::MAX, u64::from(u32::MAX))] {
        let mut expected = expected_one(
            3,
            cutoff,
            VerifiedAgedOpenItem {
                item: source_item.clone(),
                age_days: age,
                bucket: 0,
            },
        );
        expected.bands = vec![
            VerifiedAgingBand {
                lower_inclusive: 0,
                upper_inclusive: Some(u64::from(bound)),
            },
            VerifiedAgingBand {
                lower_inclusive: u64::from(bound) + 1,
                upper_inclusive: None,
            },
        ];
        let actual = verify_aging(&records, 3, &source, cutoff, &[bound], &expected).unwrap();
        assert_eq!(actual.output, expected_bytes(&expected));
        let aging = actual.aging.unwrap();
        assert_eq!(aging.items[0].age_days, age);
        assert_eq!(aging.bands[1].lower_inclusive, u64::from(bound) + 1);
    }
}

fn migration_bodies(native: &[u8], bodies: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut r = Reader::new(native);
    r.bytes(64, "format").unwrap();
    r.u16("major").unwrap();
    r.u16("minor").unwrap();
    r.bytes(MAX_REPORT_BUNDLE_BYTES, "certificate").unwrap();
    r.bytes(MAX_REPORT_BUNDLE_BYTES, "checkpoint").unwrap();
    r.bytes(MAX_REPORT_BUNDLE_BYTES, "prefix").unwrap();
    let n = r.count(MAX_ROWS, 8, "records").unwrap();
    for _ in 0..n {
        r.u32("proposal length").unwrap();
        r.bytes(MAX_RECORD_BYTES, "payload").unwrap();
    }
    let before = &native[..native.len() - r.remaining()];
    assert_eq!(r.count(0, 12, "migration bodies").unwrap(), 0);
    let after = &native[native.len() - r.remaining()..];
    let mut w = Writer::default();
    w.fixed(before).count(bodies.len());
    for (index, body) in bodies {
        w.u64(*index).bytes(body);
    }
    w.fixed(after);
    w.buf
}

#[test]
fn aging_migration_visibility_uses_finalize_without_rewriting_age_or_recorded_time() {
    use super::super::explain::{migration_body, migration_id, migration_record};
    use crate::envelope::Leg;
    for (mode, sole, day, terminal, counts) in [
        (0, false, 9, 1, true),
        (1, false, 9, 1, true),
        (2, false, 9, 1, false),
        (2, true, 9, 1, true),
        (2, false, 10, 1, true),
        (0, false, 9, 2, false),
    ] {
        let (run, body, digest) = migration_body(mode, sole);
        let id = migration_id(run, 4);
        let legs = [
            Leg {
                account: account_id("1000"),
                unit: 1,
                debit: true,
                mantissa: 35,
            },
            Leg {
                account: account_id("3000"),
                unit: 1,
                debit: false,
                mantissa: 35,
            },
        ];
        let mut records = schema();
        records.extend([
            migration_record(run, digest, Some(0), 3, 10, &[]),
            migration_record(run, digest, None, 4, day, &legs),
            migration_record(run, digest, Some(terminal), 6, 10, &[]),
        ]);
        for known_at in [4, 6] {
            let visible = counts && known_at == 6;
            let mut row = item(id, 0, "1000", true, 4, 35, 0, 0, 35, vec![]);
            row.effective_date = day;
            let source = report(
                Some(account_id("1000")),
                if visible { vec![row.clone()] } else { vec![] },
            );
            let expected = if visible {
                expected_one(
                    known_at,
                    30,
                    VerifiedAgedOpenItem {
                        item: row,
                        age_days: (30 - day) as u64,
                        bucket: 1,
                    },
                )
            } else {
                empty_expected(known_at, 30)
            };
            let (native, anchor, _) = pack(&records, known_at, &source);
            let native = migration_bodies(&native, &[(2, body.clone())]);
            let (bundle, pin) = wrap(&native, 30, BOUNDS, &expected_bytes(&expected));
            let actual = verify_report_with(
                &bundle, &[], None, None, Some(&pin), |_, _| Ok(anchor),
            ).unwrap_or_else(|e| panic!(
                "mode={mode}, sole={sole}, day={day}, terminal={terminal}, known_at={known_at}: {e}"
            ));
            assert_eq!(actual.output, expected_bytes(&expected));
            if visible {
                let aging = actual.aging.unwrap();
                assert_eq!(aging.items[0].item.recorded_at, 4);
                assert_eq!(aging.items[0].age_days, (30 - day) as u64);
            }
        }
    }
}
