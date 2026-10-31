//! Independently encoded obligations and hand-calculated due-date schedules.
//! No producer crate, maturity decoder or production output encoder is used.
use super::*;
use crate::report::{
    VerifiedAgingAmounts, VerifiedAgingBand, VerifiedAgingCell, VerifiedAgingTotal,
    VerifiedDueDateAgedItem, VerifiedDueDateAging, VerifiedUnscheduled, VerifiedUnscheduledItem,
};

const BOUNDS: &[u32] = &[0, 30, 60, 90];

#[path = "due_date_reconciliation.rs"]
mod reconciliation_tests;

fn terms(ordinal: u16, status: u8, reason: u16, installments: &[(i32, i128)]) -> Vec<u8> {
    let mut w = Writer::default();
    w.u16(1).count(1).u16(ordinal).u8(status);
    if status == 2 {
        w.u16(reason);
    }
    w.count(installments.len());
    for &(day, amount) in installments {
        w.i32(day).i128(amount);
    }
    w.buf
}

fn extend((mut record, identity): (Record, u128), terms: &[u8]) -> (Record, u128) {
    let mut w = Writer {
        buf: record.bytes[..record.len].to_vec(),
    };
    w.buf[2..4].copy_from_slice(&1_u16.to_le_bytes());
    w.count(1).u16(33).bytes(terms);
    record.len = w.buf.len();
    let proposal = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&w.buf]);
    let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal, &[]]);
    w.fixed(&proposal).fixed(&digest);
    record.bytes = w.buf;
    record.envelope =
        envelope_of_entry(&record.bytes, record.len, record.envelope.commit_seq, 0).unwrap();
    (record, identity)
}

fn dated((mut record, identity): (Record, u128), day: i32) -> (Record, u128) {
    record.bytes[38..42].copy_from_slice(&day.to_le_bytes());
    let proposal = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&record.bytes[..record.len]]);
    let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal, &[]]);
    record.bytes[record.len..record.len + 32].copy_from_slice(&proposal);
    record.bytes[record.len + 32..].copy_from_slice(&digest);
    record.envelope =
        envelope_of_entry(&record.bytes, record.len, record.envelope.commit_seq, 0).unwrap();
    (record, identity)
}

struct Fixture {
    records: Vec<Record>,
    invoice: u128,
    payment: u128,
    unknown: [(u128, i128); 3],
}

fn fixture() -> Fixture {
    let mut records = schema();
    let invoice_legs = [leg("1000", true, 100), leg("3000", false, 100)];
    let (invoice, invoice_id) = extend(
        posting(1, 3, b"due-invoice", &invoice_legs, None, None),
        &terms(1, 1, 0, &[(30, 30), (60, 70)]),
    );
    let mut payment_legs = [leg("3000", true, 40), leg("1000", false, 40)];
    payment_legs[0]
        .settles
        .push(application(&invoice, invoice_id, 1, 40));
    let (payment, payment_id) = dated(posting(1, 4, b"due-payment", &payment_legs, None, None), 40);
    let (undo, _) = dated(
        reverse(&payment, payment_id, 5, b"due-undo", &payment_legs),
        70,
    );
    records.extend([invoice, payment, undo]);
    let mut unknown = [(0, 50), (0, 20), (0, 7)];
    for (index, key) in [b"missing".as_slice(), b"disputed", b"no-terms"]
        .into_iter()
        .enumerate()
    {
        let seq = 6 + index as u64;
        let amount = unknown[index].1;
        let legs = [leg("1000", true, amount), leg("3000", false, amount)];
        let pair = dated(posting(1, seq, key, &legs, None, None), 15 + index as i32);
        let (record, id) = match index {
            0 => extend(pair, &terms(1, 3, 0, &[])),
            1 => extend(pair, &terms(1, 2, 9, &[])),
            _ => pair,
        };
        unknown[index].0 = id;
        records.push(record);
    }
    Fixture {
        records,
        invoice: invoice_id,
        payment: payment_id,
        unknown,
    }
}

fn invoice_item(f: &Fixture, applied: bool, history: Option<bool>) -> VerifiedOpenItem {
    item(
        f.invoice,
        1,
        "3000",
        false,
        3,
        100,
        if applied { 40 } else { 0 },
        0,
        if applied { 60 } else { 100 },
        history
            .map(|live| VerifiedApplication {
                entry: f.payment,
                ordinal: 0,
                amount: 40,
                recorded_at: 4,
                live,
            })
            .into_iter()
            .collect(),
    )
}

fn unknown_item(f: &Fixture, index: usize) -> VerifiedOpenItem {
    let (id, amount) = f.unknown[index];
    let mut row = item(
        id,
        1,
        "3000",
        false,
        6 + index as u64,
        amount,
        0,
        0,
        amount,
        vec![],
    );
    row.effective_date = 15 + index as i32;
    row
}

fn source(f: &Fixture, known_at: u64) -> VerifiedOpenItems {
    let mut items = vec![invoice_item(
        f,
        known_at == 4,
        (known_at >= 4).then_some(known_at == 4),
    )];
    if known_at == 4 {
        let mut payment = item(f.payment, 0, "3000", true, 4, 40, 0, 40, 0, vec![]);
        payment.effective_date = 40;
        items.push(payment);
    }
    for index in 0..3 {
        if known_at >= 6 + index as u64 {
            items.push(unknown_item(f, index));
        }
    }
    report(Some(account_id("3000")), items)
}

fn bands() -> Vec<VerifiedAgingBand> {
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

fn expected(
    f: &Fixture,
    known_at: u64,
    cutoff: i32,
    invoice: VerifiedOpenItem,
    installments: &[(i32, i128, u64, usize)],
    include_unknown: bool,
) -> VerifiedDueDateAging {
    let items = installments
        .iter()
        .map(
            |&(due_date, open, days_past_due, bucket)| VerifiedDueDateAgedItem {
                item: invoice.clone(),
                due_date,
                open,
                days_past_due,
                bucket,
            },
        )
        .collect();
    let mut cells = BTreeMap::new();
    for &(_, amount, _, bucket) in installments {
        let value = cells
            .entry(bucket)
            .or_insert(VerifiedAgingAmounts::default());
        value.credits += amount;
        value.item_count += 1;
    }
    let cells = cells
        .into_iter()
        .map(|(bucket, amounts)| VerifiedAgingCell {
            account: account_id("3000"),
            unit_id: 1,
            bucket,
            amounts,
        })
        .collect();
    let totals = vec![VerifiedAgingTotal {
        account: account_id("3000"),
        unit_id: 1,
        amounts: VerifiedAgingAmounts {
            debits: 0,
            credits: invoice.open,
            item_count: installments.len() as u64,
        },
    }];
    let mut unscheduled = Vec::new();
    let mut unscheduled_totals = Vec::new();
    if include_unknown {
        for (index, reason) in [
            VerifiedUnscheduled::MissingMaturity,
            VerifiedUnscheduled::Disputed { reason_code: 9 },
            VerifiedUnscheduled::NoTerms,
        ]
        .into_iter()
        .enumerate()
        {
            unscheduled.push(VerifiedUnscheduledItem {
                item: unknown_item(f, index),
                reason,
            });
        }
        unscheduled_totals.push(VerifiedAgingTotal {
            account: account_id("3000"),
            unit_id: 1,
            amounts: VerifiedAgingAmounts {
                debits: 0,
                credits: 77,
                item_count: 3,
            },
        });
    }
    VerifiedDueDateAging {
        book_id: BOOK,
        known_at,
        effective_through: cutoff,
        account_filter: Some(account_id("3000")),
        source_certificate_digest: [0; 32],
        bands: bands(),
        items,
        cells,
        totals,
        unscheduled,
        unscheduled_totals,
    }
}

fn expected_item(w: &mut Writer, item: &VerifiedOpenItem) {
    w.u128(item.entry)
        .u16(item.ordinal)
        .u128(item.account)
        .u32(item.unit_id)
        .u8(u8::from(!item.debit))
        .i32(item.effective_date)
        .u64(item.recorded_at)
        .i128(item.original)
        .i128(item.applied)
        .i128(item.applied_out)
        .i128(item.open)
        .count(item.applications.len());
    for a in &item.applications {
        w.u128(a.entry)
            .u16(a.ordinal)
            .i128(a.amount)
            .u64(a.recorded_at)
            .u8(u8::from(a.live));
    }
}

fn expected_totals(w: &mut Writer, totals: &[VerifiedAgingTotal]) {
    w.count(totals.len());
    for t in totals {
        w.u128(t.account)
            .u32(t.unit_id)
            .i128(t.amounts.debits)
            .i128(t.amounts.credits)
            .u64(t.amounts.item_count);
    }
}

fn output(expected: &VerifiedDueDateAging) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(b"fa:due-date-aging:v1")
        .fixed(&expected.book_id)
        .u64(expected.known_at)
        .i32(expected.effective_through)
        .u8(u8::from(expected.account_filter.is_some()));
    if let Some(account) = expected.account_filter {
        w.u128(account);
    }
    w.count(expected.bands.len());
    for band in &expected.bands {
        w.u64(band.lower_inclusive)
            .u8(u8::from(band.upper_inclusive.is_some()));
        if let Some(upper) = band.upper_inclusive {
            w.u64(upper);
        }
    }
    w.count(expected.items.len());
    for row in &expected.items {
        expected_item(&mut w, &row.item);
        w.i32(row.due_date)
            .i128(row.open)
            .u64(row.days_past_due)
            .u32(row.bucket as u32);
    }
    w.count(expected.cells.len());
    for cell in &expected.cells {
        w.u128(cell.account)
            .u32(cell.unit_id)
            .u32(cell.bucket as u32)
            .i128(cell.amounts.debits)
            .i128(cell.amounts.credits)
            .u64(cell.amounts.item_count);
    }
    expected_totals(&mut w, &expected.totals);
    w.count(expected.unscheduled.len());
    for row in &expected.unscheduled {
        expected_item(&mut w, &row.item);
        match row.reason {
            VerifiedUnscheduled::NoTerms => {
                w.u8(0);
            }
            VerifiedUnscheduled::MissingMaturity => {
                w.u8(1);
            }
            VerifiedUnscheduled::Disputed { reason_code } => {
                w.u8(2).u32(u32::from(reason_code));
            }
        }
    }
    expected_totals(&mut w, &expected.unscheduled_totals);
    w.buf
}

fn wrap(native: &[u8], cutoff: i32, bounds: &[u32], output: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let mut r = Reader::new(native);
    assert_eq!(r.bytes(64, "format").unwrap(), REPORT_BUNDLE_FORMAT);
    assert_eq!((r.u16("major").unwrap(), r.u16("minor").unwrap()), (2, 0));
    let source = r.bytes(MAX_REPORT_BUNDLE_BYTES, "source").unwrap();
    let rest = &native[native.len() - r.remaining()..];
    let mut certificate = Writer::default();
    certificate
        .bytes(b"fa:due-date-aging-certificate:v1")
        .u128(PRINCIPAL)
        .fixed(&[9; 32])
        .bytes(source)
        .i32(cutoff)
        .count(bounds.len());
    for bound in bounds {
        certificate.u32(*bound);
    }
    certificate.bytes(output);
    let pin = hash_parts(
        b"fa:due-date-aging-certificate-digest:v1",
        &[
            &(certificate.buf.len() as u32).to_le_bytes(),
            &certificate.buf,
        ],
    );
    certificate.fixed(&pin);
    let mut bundle = Writer::default();
    bundle
        .bytes(REPORT_BUNDLE_FORMAT)
        .u16(2)
        .u16(0)
        .bytes(&certificate.buf)
        .fixed(rest);
    (bundle.buf, pin)
}

fn verify_pinned(
    bundle: &[u8],
    anchor: SignedCheckpoint,
    pin: Option<&[u8; 32]>,
) -> Result<VerifiedReport, ReportError> {
    // One authentication closure type keeps the large verifier from being
    // instantiated again for each independent negative fixture.
    verify_report_with(bundle, &[], None, None, pin, |_, _| Ok(anchor))
}

fn verify(
    f: &Fixture,
    known_at: u64,
    expected: &VerifiedDueDateAging,
) -> Result<VerifiedReport, ReportError> {
    let (native, anchor, _) = pack(&f.records, known_at, &source(f, known_at));
    let (bundle, pin) = wrap(
        &native,
        expected.effective_through,
        BOUNDS,
        &output(expected),
    );
    verify_pinned(&bundle, anchor, Some(&pin))
}

#[test]
fn receivable_v2_replays_debit_installments_and_rejects_removed_or_retyped_terms() {
    let invoice_legs = [leg("1000", true, 100), leg("3000", false, 100)];
    let mut maturity = terms(0, 1, 0, &[(30, 100)]);
    maturity[..2].copy_from_slice(&2_u16.to_le_bytes());
    let (invoice, invoice_id) = extend(
        posting(1, 3, b"receivable-due", &invoice_legs, None, None),
        &maturity,
    );
    let mut records = schema();
    records.push(invoice);
    let original = item(invoice_id, 0, "1000", true, 3, 100, 0, 0, 100, vec![]);
    for (cutoff, days_past_due, bucket) in [(30, 0, 0), (31, 1, 1)] {
        let amounts = VerifiedAgingAmounts {
            debits: 100,
            credits: 0,
            item_count: 1,
        };
        let expected = VerifiedDueDateAging {
            book_id: BOOK,
            known_at: 3,
            effective_through: cutoff,
            account_filter: Some(account_id("1000")),
            source_certificate_digest: [0; 32],
            bands: bands(),
            items: vec![VerifiedDueDateAgedItem {
                item: original.clone(),
                due_date: 30,
                open: 100,
                days_past_due,
                bucket,
            }],
            cells: vec![VerifiedAgingCell {
                account: account_id("1000"),
                unit_id: 1,
                bucket,
                amounts: amounts.clone(),
            }],
            totals: vec![VerifiedAgingTotal {
                account: account_id("1000"),
                unit_id: 1,
                amounts,
            }],
            unscheduled: vec![],
            unscheduled_totals: vec![],
        };
        let source = report(Some(account_id("1000")), vec![original.clone()]);
        let (native, anchor, _) = pack(&records, 3, &source);
        let (bundle, pin) = wrap(&native, cutoff, BOUNDS, &output(&expected));
        let verified = verify_pinned(&bundle, anchor, Some(&pin)).unwrap();
        assert_eq!(verified.output, output(&expected));
        let actual = verified.due_date_aging.unwrap();
        assert_eq!(actual.items, expected.items);
        assert_eq!(actual.totals, expected.totals);

        // Repair every outer/source binding after removing the original
        // maturity. The same claimed scheduled output must still fail.
        let mut removed = records.clone();
        removed[2] = posting(1, 3, b"receivable-due", &invoice_legs, None, None).0;
        let (native, anchor, _) = pack(&removed, 3, &source);
        let (bundle, pin) = wrap(&native, cutoff, BOUNDS, &output(&expected));
        assert_eq!(
            verify_pinned(&bundle, anchor, Some(&pin))
                .unwrap_err()
                .predicate,
            "report_recomputation"
        );

        // Reinterpreting the debit terms as historical v1 is not admitted,
        // even under a freshly trusted prefix and repaired output digest.
        let mut wrong_side = maturity.clone();
        wrong_side[..2].copy_from_slice(&1_u16.to_le_bytes());
        let mut retyped = records.clone();
        retyped[2] = extend(
            posting(1, 3, b"receivable-due", &invoice_legs, None, None),
            &wrong_side,
        )
        .0;
        let (native, anchor, _) = pack(&retyped, 3, &source);
        let (bundle, pin) = wrap(&native, cutoff, BOUNDS, &output(&expected));
        assert_eq!(
            verify_pinned(&bundle, anchor, Some(&pin))
                .unwrap_err()
                .predicate,
            "obligation_terms"
        );
    }
}

#[test]
fn due_date_aging_independently_replays_installments_partial_settlements_and_reversals() {
    let f = fixture();
    for (known_at, cutoff, applied, history, installments) in [
        (3, 30, false, None, vec![(30, 30, 0, 0), (60, 70, 0, 0)]),
        (3, 31, false, None, vec![(60, 70, 0, 0), (30, 30, 1, 1)]),
        (4, 45, true, Some(true), vec![(60, 60, 0, 0)]),
        (5, 45, true, Some(true), vec![(60, 60, 0, 0)]),
        (
            5,
            90,
            false,
            Some(false),
            vec![(60, 70, 30, 1), (30, 30, 60, 2)],
        ),
    ] {
        let expected = expected(
            &f,
            known_at,
            cutoff,
            invoice_item(&f, applied, history),
            &installments,
            false,
        );
        let actual = verify(&f, known_at, &expected)
            .unwrap_or_else(|error| panic!("known-at {known_at}, cutoff {cutoff}: {error}"));
        assert!(actual.aging.is_none());
        assert_eq!(actual.output, output(&expected));
        let report = actual.due_date_aging.unwrap();
        assert_eq!(report.items, expected.items);
        assert_eq!(report.totals, expected.totals);
        assert_ne!(report.source_certificate_digest, [0; 32]);
    }
}

#[test]
fn due_date_aging_preserves_missing_disputed_and_unrecorded_terms_without_guessing() {
    let f = fixture();
    let expected = expected(
        &f,
        8,
        45,
        invoice_item(&f, true, Some(true)),
        &[(60, 60, 0, 0)],
        true,
    );
    let actual = verify(&f, 8, &expected).unwrap().due_date_aging.unwrap();
    assert_eq!(actual.unscheduled, expected.unscheduled);
    assert_eq!(actual.unscheduled_totals[0].amounts.credits, 77);
    assert_eq!(actual.totals[0].amounts.credits, 60);
    // All later records are still present in the authenticated checkpoint,
    // but none can change the selected historical prefix.
    let old = self::expected(
        &f,
        3,
        31,
        invoice_item(&f, false, None),
        &[(60, 70, 0, 0), (30, 30, 1, 1)],
        false,
    );
    assert!(
        verify(&f, 3, &old)
            .unwrap()
            .due_date_aging
            .unwrap()
            .unscheduled
            .is_empty()
    );
}

#[test]
fn due_date_aging_whole_book_preserves_unscheduled_debits_and_scheduled_credits() {
    let f = fixture();
    let invoice = invoice_item(&f, false, None);
    let debit = item(f.invoice, 0, "1000", true, 3, 100, 0, 0, 100, vec![]);
    let source = report(None, vec![invoice.clone(), debit.clone()]);
    let mut expected = expected(&f, 3, 30, invoice, &[(30, 30, 0, 0), (60, 70, 0, 0)], false);
    expected.account_filter = None;
    expected.unscheduled.push(VerifiedUnscheduledItem {
        item: debit,
        reason: VerifiedUnscheduled::NoTerms,
    });
    expected.unscheduled_totals.push(VerifiedAgingTotal {
        account: account_id("1000"),
        unit_id: 1,
        amounts: VerifiedAgingAmounts {
            debits: 100,
            credits: 0,
            item_count: 1,
        },
    });
    let (native, anchor, _) = pack(&f.records, 3, &source);
    let (bundle, pin) = wrap(&native, 30, BOUNDS, &output(&expected));
    let actual = verify_pinned(&bundle, anchor, Some(&pin))
        .unwrap()
        .due_date_aging
        .unwrap();
    assert_eq!(actual.items, expected.items);
    assert_eq!(actual.unscheduled, expected.unscheduled);
    assert_eq!(actual.totals[0].amounts.credits, 100);
    assert_eq!(actual.unscheduled_totals[0].amounts.debits, 100);
}

#[test]
fn due_date_certificate_decoder_enforces_bounds_canonicality_and_recipient_pins() {
    let f = fixture();
    let expected = expected(
        &f,
        3,
        30,
        invoice_item(&f, false, None),
        &[(30, 30, 0, 0), (60, 70, 0, 0)],
        false,
    );
    let (native, anchor, _) = pack(&f.records, 3, &source(&f, 3));
    let (bundle, pin) = wrap(&native, 30, BOUNDS, &output(&expected));
    let mut r = Reader::new(&bundle);
    r.bytes(64, "format").unwrap();
    r.u16("major").unwrap();
    r.u16("minor").unwrap();
    let certificate = r.bytes(MAX_REPORT_BUNDLE_BYTES, "certificate").unwrap();
    assert!(crate::report::due_date::decode(certificate).is_ok());
    for end in 0..certificate.len() {
        assert!(
            crate::report::due_date::decode(&certificate[..end]).is_err(),
            "prefix {end}"
        );
    }
    let mut trailing = certificate.to_vec();
    trailing.push(0);
    assert!(crate::report::due_date::decode(&trailing).is_err());
    let mut corrupt = certificate.to_vec();
    *corrupt.last_mut().unwrap() ^= 1;
    assert_eq!(
        crate::report::due_date::decode(&corrupt)
            .err()
            .unwrap()
            .predicate,
        "certificate_digest"
    );
    for bounds in [vec![30, 30], vec![30, 0], (0..129).collect()] {
        let (invalid, pin) = wrap(&native, 30, &bounds, &output(&expected));
        assert!(verify_pinned(&invalid, anchor.clone(), Some(&pin)).is_err());
    }
    assert_eq!(
        verify_pinned(&bundle, anchor.clone(), None)
            .unwrap_err()
            .predicate,
        "report_input_authority"
    );
    let mut other_pin = pin;
    other_pin[0] ^= 1;
    assert_eq!(
        verify_pinned(&bundle, anchor, Some(&other_pin))
            .unwrap_err()
            .predicate,
        "recipient_certificate"
    );
}

#[test]
fn due_date_output_tampering_cannot_be_hidden_by_repairing_the_outer_digest() {
    let f = fixture();
    let expected = expected(
        &f,
        8,
        45,
        invoice_item(&f, true, Some(true)),
        &[(60, 60, 0, 0)],
        true,
    );
    for mutation in 0..6 {
        let mut forged = expected.clone();
        match mutation {
            0 => forged.items[0].due_date = 59,
            1 => forged.items[0].open = 59,
            2 => forged.items[0].days_past_due = 1,
            3 => {
                forged.unscheduled.remove(0);
            }
            4 => forged.unscheduled[1].reason = VerifiedUnscheduled::NoTerms,
            5 => forged.totals[0].amounts.credits = 61,
            _ => unreachable!(),
        }
        assert_eq!(
            verify(&f, 8, &forged).unwrap_err().predicate,
            "report_recomputation",
            "mutation {mutation}"
        );
    }
}

#[test]
fn due_date_terms_are_authenticated_and_cannot_be_removed_from_a_valid_bundle() {
    let f = fixture();
    let expected = expected(
        &f,
        3,
        30,
        invoice_item(&f, false, None),
        &[(30, 30, 0, 0), (60, 70, 0, 0)],
        false,
    );
    let (native, anchor, _) = pack(&f.records, 3, &source(&f, 3));
    let (mut bundle, pin) = wrap(&native, 30, BOUNDS, &output(&expected));
    let raw_terms = terms(1, 1, 0, &[(30, 30), (60, 70)]);
    let position = bundle
        .windows(raw_terms.len())
        .position(|bytes| bytes == raw_terms)
        .unwrap();
    bundle[position + 13] ^= 1;
    assert_eq!(
        verify_pinned(&bundle, anchor, Some(&pin))
            .unwrap_err()
            .predicate,
        "record_derivation"
    );
    // Even if an attacker rebuilds the prefix, native source and outer digest,
    // the claimed contractual schedule cannot survive removing its terms.
    let mut f = fixture();
    f.records[2] = posting(
        1,
        3,
        b"due-invoice",
        &[leg("1000", true, 100), leg("3000", false, 100)],
        None,
        None,
    )
    .0;
    assert_eq!(
        verify(&f, 3, &expected).unwrap_err().predicate,
        "report_recomputation"
    );
}

#[test]
fn due_date_malformed_maturity_records_fail_closed_even_with_a_trusted_prefix() {
    for (name, bytes) in [
        ("debit", terms(0, 1, 0, &[(30, 100)])),
        ("missing leg", terms(2, 1, 0, &[(30, 100)])),
        ("wrong sum", terms(1, 1, 0, &[(30, 99)])),
        ("zero amount", terms(1, 1, 0, &[(30, 0), (60, 100)])),
        ("negative amount", terms(1, 1, 0, &[(30, -1), (60, 101)])),
        ("duplicate due day", terms(1, 1, 0, &[(30, 30), (30, 70)])),
        ("unordered days", terms(1, 1, 0, &[(60, 30), (30, 70)])),
        ("unknown status", terms(1, 4, 0, &[])),
        ("missing schedule", terms(1, 1, 0, &[])),
        ("missing status with schedule", terms(1, 3, 0, &[(30, 100)])),
        ("disputed wrong sum", terms(1, 2, 9, &[(30, 99)])),
    ] {
        let mut f = fixture();
        f.records[2] = extend(
            posting(
                1,
                3,
                b"due-invoice",
                &[leg("1000", true, 100), leg("3000", false, 100)],
                None,
                None,
            ),
            &bytes,
        )
        .0;
        let expected = expected(
            &f,
            3,
            30,
            invoice_item(&f, false, None),
            &[(30, 30, 0, 0), (60, 70, 0, 0)],
            false,
        );
        assert_eq!(
            verify(&f, 3, &expected).unwrap_err().predicate,
            "obligation_terms",
            "{name}"
        );
    }
}
