//! Independently encoded complete-prefix workpapers. Expected monetary values
//! are hand-calculated from the fixture, not obtained from either producer or
//! verifier comparison code.
use super::*;
use crate::report::{VerifiedAgingReconciliationRow, VerifiedDueDateAgingReconciliation};

struct ComparisonFixture {
    bundle: Vec<u8>,
    anchor: SignedCheckpoint,
    pin: [u8; 32],
    expected: VerifiedDueDateAgingReconciliation,
    aging_bundle: Vec<u8>,
    control: Vec<u8>,
}

fn native_source(bundle: &[u8]) -> &[u8] {
    let mut r = Reader::new(bundle);
    r.bytes(64, "format").unwrap();
    r.u16("major").unwrap();
    r.u16("minor").unwrap();
    r.bytes(MAX_REPORT_BUNDLE_BYTES, "certificate").unwrap()
}

fn stock_output(at: u64, cutoff: i32, rows: &[ReportRow]) -> Vec<u8> {
    let mut w = Writer::default();
    let periods: &[&str] = if cutoff < 31 { &["P1"] } else { &["P1", "P2"] };
    w.fixed(b"fa:trial-balance:v1").count(periods.len());
    for period in periods {
        w.bytes(period.as_bytes());
    }
    w.u64(at).u8(1).i32(cutoff).u8(0).count(rows.len());
    let mut totals = [0_i128; 4];
    for row in rows {
        w.u128(row.account)
            .bytes(row.code.as_bytes())
            .bytes(row.name.as_bytes())
            .u8(row.account_type)
            .u32(row.unit)
            .i128(row.debits)
            .i128(row.credits)
            .i128(row.debits_pending)
            .i128(row.credits_pending);
        for (index, amount) in [
            row.debits,
            row.credits,
            row.debits_pending,
            row.credits_pending,
        ]
        .into_iter()
        .enumerate()
        {
            totals[index] += amount;
        }
    }
    for offset in [0, 2] {
        w.count(1)
            .u32(1)
            .i128(totals[offset])
            .i128(totals[offset + 1]);
    }
    w.buf
}

fn control(source: &crate::report::Certificate<'_>, cutoff: i32, rows: &[ReportRow]) -> Vec<u8> {
    let output = stock_output(source.known_at, cutoff, rows);
    let mut w = Writer::default();
    w.fixed(crate::report::CERTIFICATE_FORMAT)
        .bytes(b"fa-fold-over-prefix")
        .bytes(b"embedded-owner")
        .bytes(b"fa:trial-balance:v1")
        .fixed(&source.book)
        .fixed(&source.branch)
        .u64(source.known_at)
        .u8(1)
        .i32(cutoff)
        .fixed(&source.registry_digest)
        .fixed(&source.journal_root)
        .u64(source.leaves)
        .count(7);
    for _ in 0..7 {
        w.bytes(b"opaque native control read");
    }
    w.bytes(&output)
        .fixed(&hash_parts(b"fa:report-output:v1", &[&output]));
    let pin = hash_parts(crate::report::CERTIFICATE_FORMAT, &[&w.buf]);
    w.fixed(&pin);
    w.buf
}

fn comparison_output(report: &VerifiedDueDateAgingReconciliation) -> Vec<u8> {
    let a = &report.account;
    let mut w = Writer::default();
    w.bytes(b"fa:due-date-aging-control-reconciliation:v1")
        .fixed(&report.book_id)
        .u64(report.known_at)
        .i32(report.effective_through)
        .u128(a.account)
        .bytes(a.code.as_bytes())
        .bytes(a.name.as_bytes())
        .u8(a.account_type)
        .u8(a.normal_balance)
        .u8(u8::from(a.is_leaf))
        .u64(a.created_at)
        .count(report.rows.len());
    for row in &report.rows {
        w.u32(row.unit_id)
            .i128(row.posted_debits)
            .i128(row.posted_credits)
            .i128(row.pending_debits)
            .i128(row.pending_credits)
            .i128(row.open_debits)
            .i128(row.open_credits)
            .u64(row.open_item_count)
            .i128(row.posted_net)
            .i128(row.open_net)
            .i128(row.difference);
    }
    w.u8(u8::from(report.rows.iter().all(|row| row.difference == 0)));
    w.buf
}

fn wrap_comparison(aging_bundle: &[u8], control: &[u8], output: &[u8]) -> (Vec<u8>, [u8; 32]) {
    wrap_comparison_format(
        aging_bundle,
        control,
        output,
        b"fa:due-date-aging-reconciliation-certificate:v1",
        b"fa:due-date-aging-reconciliation-digest:v1",
    )
}

fn wrap_comparison_format(
    aging_bundle: &[u8],
    control: &[u8],
    output: &[u8],
    format: &[u8],
    domain: &[u8],
) -> (Vec<u8>, [u8; 32]) {
    let mut r = Reader::new(aging_bundle);
    r.bytes(64, "format").unwrap();
    assert_eq!((r.u16("major").unwrap(), r.u16("minor").unwrap()), (2, 0));
    let aging = r.bytes(MAX_REPORT_BUNDLE_BYTES, "aging").unwrap();
    let rest = &aging_bundle[aging_bundle.len() - r.remaining()..];
    let mut cert = Writer::default();
    cert.bytes(format)
        .u128(PRINCIPAL)
        .fixed(&[8; 32])
        .bytes(aging)
        .bytes(control)
        .bytes(output);
    let pin = hash_parts(domain, &[&(cert.buf.len() as u32).to_le_bytes(), &cert.buf]);
    cert.fixed(&pin);
    let mut bundle = Writer::default();
    bundle
        .bytes(REPORT_BUNDLE_FORMAT)
        .u16(2)
        .u16(0)
        .bytes(&cert.buf)
        .fixed(rest);
    (bundle.buf, pin)
}

fn comparison_fixture(known_at: u64, cutoff: i32, pending: bool) -> ComparisonFixture {
    let mut f = fixture();
    if pending {
        f.records
            .push(record(2, 9, 0, b"due-hold", 25, None, None, Some("P1")));
    }
    // Invoice = 100; payment = 40; reversal at day 70; three unscheduled
    // obligations = 50 + 20 + 7. The hold is pending and never an open item.
    let (applied, history, parts, debits, credits, open, count) = match (known_at, cutoff) {
        (3, 30) => (
            false,
            None,
            vec![(30, 30, 0, 0), (60, 70, 0, 0)],
            100,
            0,
            100,
            1,
        ),
        (4, 45) => (true, Some(true), vec![(60, 60, 0, 0)], 100, 40, 60, 1),
        (8, 45) => (true, Some(true), vec![(60, 60, 0, 0)], 177, 40, 137, 4),
        (8 | 9, 90) => (
            false,
            Some(false),
            vec![(60, 70, 30, 1), (30, 30, 60, 2)],
            217,
            40,
            177,
            4,
        ),
        _ => panic!("unregistered fixture coordinate"),
    };
    let mut aging = expected(
        &f,
        known_at,
        cutoff,
        invoice_item(&f, applied, history),
        &parts,
        known_at >= 8,
    );
    let (native, anchor, source_pin) = pack(&f.records, known_at, &source(&f, known_at));
    aging.source_certificate_digest = source_pin;
    let (aging_bundle, aging_pin) = wrap(&native, cutoff, BOUNDS, &output(&aging));
    let mut controls = crate::report::tests::rows(0, if pending { 25 } else { 0 });
    controls[0].debits = debits;
    controls[0].credits = credits;
    controls[1].debits = credits;
    controls[1].credits = debits;
    let native_certificate = certificate(native_source(&native)).unwrap();
    let control = control(&native_certificate, cutoff, &controls);
    let selected = controls
        .iter()
        .find(|row| row.account == account_id("3000"))
        .unwrap();
    let expected = VerifiedDueDateAgingReconciliation {
        book_id: BOOK,
        known_at,
        effective_through: cutoff,
        account: displayed("3000"),
        aging,
        control_rows: vec![selected.clone()],
        rows: vec![VerifiedAgingReconciliationRow {
            unit_id: 1,
            posted_debits: credits,
            posted_credits: debits,
            pending_debits: 0,
            pending_credits: if pending { 25 } else { 0 },
            open_debits: 0,
            open_credits: open,
            open_item_count: count,
            posted_net: credits - debits,
            open_net: -open,
            difference: 0,
        }],
        aging_certificate_digest: aging_pin,
        control_certificate_digest: certificate(&control).unwrap().digest,
    };
    let (bundle, pin) = wrap_comparison(&aging_bundle, &control, &comparison_output(&expected));
    ComparisonFixture {
        bundle,
        anchor,
        pin,
        expected,
        aging_bundle,
        control,
    }
}

#[test]
fn due_reconciliation_independently_replays_installments_unscheduled_and_pending() {
    for (known_at, cutoff, pending) in [
        (3, 30, false),
        (4, 45, false),
        (8, 45, false),
        (8, 90, false),
        (9, 90, true),
    ] {
        let f = comparison_fixture(known_at, cutoff, pending);
        let verified = verify_pinned(&f.bundle, f.anchor, Some(&f.pin))
            .unwrap_or_else(|e| panic!("known-at {known_at}, cutoff {cutoff}: {e}"));
        assert!(verified.aging_reconciliation.is_none());
        assert!(verified.due_date_aging.is_none());
        assert_eq!(verified.output, comparison_output(&f.expected));
        assert_eq!(verified.due_date_aging_reconciliation, Some(f.expected));
    }
}

#[test]
fn due_reconciliation_requires_the_independently_selected_outer_pin() {
    let f = comparison_fixture(8, 90, false);
    assert_eq!(
        verify_pinned(&f.bundle, f.anchor.clone(), None)
            .unwrap_err()
            .predicate,
        "report_input_authority"
    );
    for inner in [
        f.expected.aging_certificate_digest,
        f.expected.control_certificate_digest,
        f.expected.aging.source_certificate_digest,
    ] {
        assert_eq!(
            verify_pinned(&f.bundle, f.anchor.clone(), Some(&inner))
                .unwrap_err()
                .predicate,
            "recipient_certificate"
        );
    }
}

#[test]
fn due_reconciliation_refuses_omitted_unscheduled_amounts_and_installment_item_counts() {
    let f = comparison_fixture(8, 90, false);
    for mutation in 0..3 {
        let mut expected = f.expected.clone();
        match mutation {
            0 => {
                expected.rows[0].open_credits = 100;
                expected.rows[0].open_net = -100;
                expected.rows[0].difference = -77;
            }
            1 => expected.rows[0].open_item_count = 5,
            _ => expected.account.name.push_str(" forged"),
        }
        let (bundle, pin) =
            wrap_comparison(&f.aging_bundle, &f.control, &comparison_output(&expected));
        assert_eq!(
            verify_pinned(&bundle, f.anchor.clone(), Some(&pin))
                .unwrap_err()
                .predicate,
            "report_recomputation"
        );
    }
}

#[test]
fn due_reconciliation_binds_both_sources_to_one_prefix_cutoff_and_registry() {
    let f = comparison_fixture(8, 90, false);
    let output = comparison_output(&f.expected);
    for mutation in 0..6 {
        let mut source = certificate(&f.control).unwrap();
        let mut cutoff = 90;
        match mutation {
            0 => source.book[0] ^= 1,
            1 => source.known_at -= 1,
            2 => source.journal_root[0] ^= 1,
            3 => source.leaves -= 1,
            4 => cutoff -= 1,
            _ => source.registry_digest[0] ^= 1,
        }
        let other = control(&source, cutoff, &f.expected.control_rows);
        let (bundle, pin) = wrap_comparison(&f.aging_bundle, &other, &output);
        let expected = if mutation == 5 {
            "registry_closure"
        } else {
            "reconciliation_selection"
        };
        assert_eq!(
            verify_pinned(&bundle, f.anchor.clone(), Some(&pin))
                .unwrap_err()
                .predicate,
            expected
        );
    }
}

#[test]
fn due_reconciliation_refuses_nested_unscheduled_omission_even_with_both_digests_repaired() {
    let f = comparison_fixture(8, 90, false);
    let nested = crate::report::due_date::decode(native_source(&f.aging_bundle)).unwrap();
    let mut r = Reader::new(&f.aging_bundle);
    r.bytes(64, "format").unwrap();
    r.u16("major").unwrap();
    r.u16("minor").unwrap();
    r.bytes(MAX_REPORT_BUNDLE_BYTES, "aging").unwrap();
    let rest = &f.aging_bundle[f.aging_bundle.len() - r.remaining()..];
    let mut native = Writer::default();
    native
        .bytes(REPORT_BUNDLE_FORMAT)
        .u16(2)
        .u16(0)
        .bytes(nested.source)
        .fixed(rest);
    let mut expected = f.expected.clone();
    expected.aging.unscheduled.clear();
    expected.aging.unscheduled_totals.clear();
    expected.rows[0].open_credits = 100;
    expected.rows[0].open_net = -100;
    expected.rows[0].difference = -77;
    expected.rows[0].open_item_count = 1;
    let (forged_aging, _) = wrap(&native.buf, 90, BOUNDS, &output(&expected.aging));
    let (bundle, pin) = wrap_comparison(&forged_aging, &f.control, &comparison_output(&expected));
    assert_eq!(
        verify_pinned(&bundle, f.anchor, Some(&pin))
            .unwrap_err()
            .predicate,
        "report_recomputation"
    );
}

#[test]
fn due_reconciliation_cannot_be_relabelled_as_effective_date_reconciliation() {
    let f = comparison_fixture(8, 90, false);
    let (bundle, pin) = wrap_comparison_format(
        &f.aging_bundle,
        &f.control,
        &comparison_output(&f.expected),
        b"fa:aging-reconciliation-certificate:v1",
        b"fa:aging-reconciliation-digest:v1",
    );
    assert_eq!(
        verify_pinned(&bundle, f.anchor, Some(&pin))
            .unwrap_err()
            .predicate,
        "supported_report"
    );
}
