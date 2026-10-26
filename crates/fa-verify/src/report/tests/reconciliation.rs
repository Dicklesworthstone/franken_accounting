//! Complete-prefix fixtures for the portable reconciliation wrapper. Both
//! native source certificates and comparison bytes are encoded separately from
//! the verifier. Signature primitives have their own tests; these fixtures
//! supply the already authenticated checkpoint at the replay boundary.
use super::*;
use crate::report::{
    VerifiedAgingReconciliation, VerifiedAgingReconciliationRow,
    reconciliation as comparison,
};

fn stock_rows(debits: i128, credits: i128, pending: i128) -> Vec<ReportRow> {
    let mut rows = crate::report::tests::rows(0, pending);
    rows[0].debits = debits;
    rows[0].credits = credits;
    rows[1].debits = credits;
    rows[1].credits = debits;
    rows
}

fn stock_output(known_at: u64, cutoff: i32, rows: &[ReportRow]) -> Vec<u8> {
    let mut w = Writer::default();
    let periods: &[&str] = if known_at == 1 {
        // This fixture's chart is born at 1, and its first periods at 2.
        &[]
    } else if cutoff < 31 {
        &["P1"]
    } else {
        &["P1", "P2"]
    };
    w.fixed(b"fa:trial-balance:v1").count(periods.len());
    for period in periods {
        w.bytes(period.as_bytes());
    }
    w.u64(known_at).u8(1).i32(cutoff).u8(0).count(rows.len());
    let mut totals: BTreeMap<u32, [i128; 4]> = BTreeMap::new();
    for row in rows {
        w.u128(row.account).bytes(row.code.as_bytes()).bytes(row.name.as_bytes())
            .u8(row.account_type).u32(row.unit).i128(row.debits).i128(row.credits)
            .i128(row.debits_pending).i128(row.credits_pending);
        let total = totals.entry(row.unit).or_insert([0; 4]);
        for (index, amount) in [
            row.debits, row.credits, row.debits_pending, row.credits_pending,
        ].into_iter().enumerate() {
            total[index] = total[index].checked_add(amount).unwrap();
        }
    }
    for offset in [0, 2] {
        w.count(totals.len());
        for (unit, total) in &totals {
            w.u32(*unit).i128(total[offset]).i128(total[offset + 1]);
        }
    }
    w.buf
}

fn control(source: &crate::report::Certificate<'_>, cutoff: i32, rows: &[ReportRow]) -> Vec<u8> {
    let output = stock_output(source.known_at, cutoff, rows);
    let mut w = Writer::default();
    w.fixed(crate::report::CERTIFICATE_FORMAT)
        .bytes(b"fa-fold-over-prefix").bytes(b"embedded-owner")
        .bytes(b"fa:trial-balance:v1")
        .fixed(&source.book).fixed(&source.branch).u64(source.known_at)
        .u8(1).i32(cutoff).fixed(&source.registry_digest)
        .fixed(&source.journal_root).u64(source.leaves).count(7);
    for _ in 0..7 {
        w.bytes(b"opaque native control read");
    }
    w.bytes(&output).fixed(&hash_parts(b"fa:report-output:v1", &[&output]));
    let digest = hash_parts(crate::report::CERTIFICATE_FORMAT, &[&w.buf]);
    w.fixed(&digest);
    w.buf
}

fn native_source(bundle: &[u8]) -> &[u8] {
    let mut r = Reader::new(bundle);
    r.bytes(64, "format").unwrap();
    r.u16("major").unwrap();
    r.u16("minor").unwrap();
    r.bytes(MAX_REPORT_BUNDLE_BYTES, "certificate").unwrap()
}

fn comparison_output(report: &VerifiedAgingReconciliation) -> Vec<u8> {
    // Independent fixture encoder, including every exact native output field.
    let a = &report.account;
    let mut w = Writer::default();
    w.bytes(b"fa:aging-control-reconciliation:v1").fixed(&report.book_id)
        .u64(report.known_at).i32(report.effective_through).u128(a.account)
        .bytes(a.code.as_bytes()).bytes(a.name.as_bytes()).u8(a.account_type)
        .u8(a.normal_balance).u8(u8::from(a.is_leaf)).u64(a.created_at)
        .count(report.rows.len());
    for row in &report.rows {
        w.u32(row.unit_id).i128(row.posted_debits).i128(row.posted_credits)
            .i128(row.pending_debits).i128(row.pending_credits)
            .i128(row.open_debits).i128(row.open_credits).u64(row.open_item_count)
            .i128(row.posted_net).i128(row.open_net).i128(row.difference);
    }
    w.u8(u8::from(report.rows.iter().all(|row| row.difference == 0)));
    w.buf
}

fn comparison_report(
    aging: VerifiedAging,
    controls: &[ReportRow],
) -> VerifiedAgingReconciliation {
    let account = displayed("1000");
    let selected: Vec<_> = controls.iter().filter(|row| row.account == account.account)
        .cloned().collect();
    let mut report = VerifiedAgingReconciliation {
        book_id: BOOK,
        known_at: aging.known_at,
        effective_through: aging.effective_through,
        account,
        aging,
        control_rows: selected,
        rows: Vec::new(),
        aging_certificate_digest: [0; 32],
        control_certificate_digest: [0; 32],
    };
    let units: BTreeSet<_> = report.control_rows.iter().map(|row| row.unit)
        .chain(report.aging.totals.iter().map(|row| row.unit_id)).collect();
    for unit_id in units {
        let control = report.control_rows.iter().find(|row| row.unit == unit_id);
        let open = report.aging.totals.iter().find(|row| row.unit_id == unit_id);
        let posted_debits = control.map_or(0, |row| row.debits);
        let posted_credits = control.map_or(0, |row| row.credits);
        let open_debits = open.map_or(0, |row| row.amounts.debits);
        let open_credits = open.map_or(0, |row| row.amounts.credits);
        report.rows.push(VerifiedAgingReconciliationRow {
            unit_id, posted_debits, posted_credits,
            pending_debits: control.map_or(0, |row| row.debits_pending),
            pending_credits: control.map_or(0, |row| row.credits_pending),
            open_debits, open_credits,
            open_item_count: open.map_or(0, |row| row.amounts.item_count),
            posted_net: posted_debits - posted_credits,
            open_net: open_debits - open_credits,
            difference: (posted_debits - posted_credits) - (open_debits - open_credits),
        });
    }
    report
}

fn wrap_comparison(aging_bundle: &[u8], control: &[u8], output: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let mut r = Reader::new(aging_bundle);
    r.bytes(64, "format").unwrap();
    assert_eq!(r.u16("major").unwrap(), 2);
    r.u16("minor").unwrap();
    let aging = r.bytes(MAX_REPORT_BUNDLE_BYTES, "aging").unwrap();
    let rest = &aging_bundle[aging_bundle.len() - r.remaining()..];
    let mut body = Writer::default();
    body.bytes(b"fa:aging-reconciliation-certificate:v1").u128(PRINCIPAL)
        .fixed(&[8; 32]).bytes(aging).bytes(control).bytes(output);
    let length = (body.buf.len() as u32).to_le_bytes();
    let pin = hash_parts(b"fa:aging-reconciliation-digest:v1", &[&length, &body.buf]);
    body.fixed(&pin);
    let mut bundle = Writer::default();
    bundle.bytes(REPORT_BUNDLE_FORMAT).u16(2).u16(0).bytes(&body.buf).fixed(rest);
    (bundle.buf, pin)
}

fn fixture(
    records: &[Record],
    source: &VerifiedOpenItems,
    mut expected: VerifiedAgingReconciliation,
    controls: &[ReportRow],
) -> (Vec<u8>, SignedCheckpoint, [u8; 32], VerifiedAgingReconciliation) {
    let (native, anchor, source_pin) = pack(records, expected.known_at, source);
    let native_certificate = certificate(native_source(&native)).unwrap();
    let control = control(&native_certificate, expected.effective_through, controls);
    expected.aging.source_certificate_digest = source_pin;
    let (aging, aging_pin) = wrap(
        &native, expected.effective_through, BOUNDS, &expected_bytes(&expected.aging),
    );
    expected.aging_certificate_digest = aging_pin;
    expected.control_certificate_digest = certificate(&control).unwrap().digest;
    let (bundle, pin) = wrap_comparison(&aging, &control, &comparison_output(&expected));
    (bundle, anchor, pin, expected)
}

fn verify_comparison(
    bundle: &[u8],
    anchor: SignedCheckpoint,
    pin: &[u8; 32],
) -> Result<VerifiedReport, ReportError> {
    verify_report_with(bundle, &[], None, None, Some(pin), |_, _| Ok(anchor))
}

fn historical_fixture(
    known_at: u64, cutoff: i32, open: i128, bucket: usize, live: Option<bool>,
) -> (Vec<u8>, SignedCheckpoint, [u8; 32], VerifiedAgingReconciliation) {
    let (records, source, invoice, receipt) = sample(known_at);
    let applications = live.map(|live| VerifiedApplication {
        entry: receipt, ordinal: 0, amount: 40, recorded_at: 4, live,
    }).into_iter().collect();
    let aging = expected_one(known_at, cutoff, VerifiedAgedOpenItem {
        item: item(invoice, 0, "1000", true, 3, 100, 100 - open, 0, open, applications),
        age_days: (cutoff - 10) as u64, bucket,
    });
    let receipt_visible = known_at >= 4 && cutoff >= 40;
    let reversal_visible = known_at >= 5 && cutoff >= 70;
    let controls = stock_rows(
        100 + if reversal_visible { 40 } else { 0 },
        if receipt_visible { 40 } else { 0 }, 0,
    );
    let expected = comparison_report(aging, &controls);
    fixture(&records, &source, expected, &controls)
}

#[test]
fn both_complete_sources_replay_at_the_same_historical_cutoff() {
    for (at, cutoff, open, bucket, live) in [
        (3, 30, 100, 1, None), (4, 30, 100, 1, None),
        (5, 30, 100, 1, None), (4, 45, 60, 2, Some(true)),
        (5, 45, 60, 2, Some(true)), (5, 90, 100, 3, Some(false)),
    ] {
        let (bytes, anchor, pin, expected) = historical_fixture(at, cutoff, open, bucket, live);
        let verified = verify_comparison(&bytes, anchor, &pin)
            .unwrap_or_else(|error| panic!("at={at}, cutoff={cutoff}: {error}"));
        assert_eq!(verified.certificate_digest, pin);
        assert_eq!(verified.output, comparison_output(&expected));
        assert_eq!(verified.aging_reconciliation, Some(expected));
        assert!(verified.rows.is_empty() && verified.aging.is_none());
        assert_eq!(verified.checked_records, 5);
    }
}

fn empty_aging(at: u64, cutoff: i32) -> VerifiedAging {
    VerifiedAging {
        book_id: BOOK, known_at: at, effective_through: cutoff,
        account_filter: Some(account_id("1000")), source_certificate_digest: [0; 32],
        bands: conventional_bands(), items: vec![], cells: vec![], totals: vec![],
    }
}

#[test]
fn an_empty_account_has_authenticated_metadata_without_invented_unit_rows() {
    let records = schema();
    let source = report(Some(account_id("1000")), vec![]);
    let expected = comparison_report(empty_aging(2, 30), &[]);
    let (bytes, anchor, pin, expected) = fixture(&records, &source, expected, &[]);
    let verified = verify_comparison(&bytes, anchor, &pin).unwrap();
    let actual = verified.aging_reconciliation.unwrap();
    assert_eq!(actual, expected);
    assert!(actual.rows.is_empty() && actual.is_reconciled());
    assert_eq!(actual.account.code, "1000");
}

#[test]
fn chart_only_history_reconciles_before_any_fiscal_period_is_declared() {
    let mut records = schema();
    records.truncate(1);
    let source = report(Some(account_id("1000")), vec![]);
    let expected = comparison_report(empty_aging(1, 30), &[]);
    let (bytes, anchor, pin, expected) = fixture(&records, &source, expected, &[]);
    let verified = verify_comparison(&bytes, anchor, &pin).unwrap();
    assert_eq!(verified.checked_records, 1);
    assert_eq!(verified.known_at, 1);
    assert!(verified.periods.is_empty());
    let actual = verified.aging_reconciliation.unwrap();
    assert_eq!(actual, expected);
    assert!(actual.control_rows.is_empty() && actual.rows.is_empty());
    assert!(actual.is_reconciled());
    assert_eq!(actual.account.created_at, 1);
}

#[test]
fn pending_columns_are_separate_and_later_legless_release_is_historical() {
    let mut records = schema();
    let pending_legs = [leg("1000", true, 75), leg("3000", false, 75)];
    let (hold, identity) = posting(2, 3, b"reconciliation-hold", &pending_legs, None, None);
    let (release, _) = dated(
        posting(3, 4, b"reconciliation-release", &[], None,
            Some((identity, hold.envelope.record_digest))),
        40,
    );
    records.extend([hold, release]);
    let source = report(Some(account_id("1000")), vec![]);
    for at in [3, 4] {
        let controls = if at == 3 { stock_rows(0, 0, 75) } else { vec![] };
        let expected = comparison_report(empty_aging(at, 30), &controls);
        let (bytes, anchor, pin, expected) = fixture(&records, &source, expected, &controls);
        let actual = verify_comparison(&bytes, anchor, &pin).unwrap()
            .aging_reconciliation.unwrap();
        assert_eq!(actual, expected);
        assert!(actual.is_reconciled());
        if at == 3 {
            assert_eq!((actual.rows[0].posted_net, actual.rows[0].pending_debits), (0, 75));
        } else {
            assert!(actual.rows.is_empty());
        }
    }
}

#[test]
fn only_the_outer_recipient_pin_authenticates_the_complete_question() {
    let (bytes, anchor, pin, expected) = historical_fixture(5, 45, 60, 2, Some(true));
    for wrong in [
        expected.aging.source_certificate_digest,
        expected.aging_certificate_digest,
        expected.control_certificate_digest,
        [77; 32],
    ] {
        assert_ne!(pin, wrong);
        assert_eq!(
            verify_comparison(&bytes, anchor.clone(), &wrong).unwrap_err().predicate,
            "recipient_certificate",
        );
    }
    assert_eq!(
        verify_report_with(&bytes, &[], None, None, None, |_, _| Ok(anchor.clone()))
            .unwrap_err().predicate,
        "report_input_authority",
    );
    let mut legacy = bytes.clone();
    let major = 4 + REPORT_BUNDLE_FORMAT.len();
    legacy[major..major + 2].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(
        verify_comparison(&legacy, anchor, &pin).unwrap_err().predicate,
        "registry_closure",
    );
}

fn split(bundle: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let outer = comparison::decode(native_source(bundle)).unwrap();
    let mut r = Reader::new(bundle);
    r.bytes(64, "format").unwrap();
    r.u16("major").unwrap();
    r.u16("minor").unwrap();
    r.bytes(MAX_REPORT_BUNDLE_BYTES, "certificate").unwrap();
    let mut aging_bundle = Writer::default();
    aging_bundle.bytes(REPORT_BUNDLE_FORMAT).u16(2).u16(0).bytes(outer.aging)
        .fixed(&bundle[bundle.len() - r.remaining()..]);
    (aging_bundle.buf, outer.control.to_vec(), outer.output.to_vec())
}

#[test]
fn recomputed_outer_digests_cannot_launder_different_source_questions() {
    let (bytes, anchor, _, _) = historical_fixture(5, 45, 60, 2, Some(true));
    let (aging_bundle, _, output) = split(&bytes);
    let aging = crate::report::aging::decode(native_source(&aging_bundle)).unwrap();
    for forged_field in 0..6 {
        let mut source = certificate(aging.source).unwrap();
        let mut cutoff = 45;
        match forged_field {
            0 => source.book[0] ^= 1,
            1 => source.known_at -= 1,
            2 => source.journal_root[0] ^= 1,
            3 => source.leaves -= 1,
            4 => cutoff += 1,
            5 => source.registry_digest[0] ^= 1,
            _ => unreachable!(),
        }
        let control = control(&source, cutoff, &stock_rows(100, 40, 0));
        let (forged, pin) = wrap_comparison(&aging_bundle, &control, &output);
        assert_eq!(
            verify_comparison(&forged, anchor.clone(), &pin).unwrap_err().predicate,
            if forged_field == 5 { "registry_closure" } else { "reconciliation_selection" },
        );
    }
}

#[test]
fn both_control_output_and_comparison_output_are_recomputed_not_trusted() {
    let (bytes, anchor, _, expected) = historical_fixture(5, 45, 60, 2, Some(true));
    let (aging_bundle, control_bytes, output) = split(&bytes);
    let aging = crate::report::aging::decode(native_source(&aging_bundle)).unwrap();
    let source = certificate(aging.source).unwrap();
    // A perfectly balanced, self-consistent control lie still differs from
    // the authenticated prefix, even if the comparison is altered to match.
    let forged_rows = stock_rows(101, 40, 0);
    let forged_control = control(&source, 45, &forged_rows);
    let forged_expected = comparison_report(expected.aging.clone(), &forged_rows);
    let (forged, pin) = wrap_comparison(
        &aging_bundle, &forged_control, &comparison_output(&forged_expected),
    );
    assert_eq!(
        verify_comparison(&forged, anchor.clone(), &pin).unwrap_err().predicate,
        "report_recomputation",
    );
    let mut forged_output = output;
    let last = forged_output.len() - 1;
    forged_output[last] = 0; // Original comparison reconciles.
    let (forged, pin) = wrap_comparison(&aging_bundle, &control_bytes, &forged_output);
    assert_eq!(
        verify_comparison(&forged, anchor, &pin).unwrap_err().predicate,
        "report_recomputation",
    );
}

#[test]
fn forged_account_metadata_and_missing_record_bytes_are_rejected() {
    let (bytes, anchor, _, mut expected) = historical_fixture(5, 30, 100, 1, None);
    let (aging_bundle, control, _) = split(&bytes);
    expected.account.name = "Forged historical name".into();
    let (forged, pin) = wrap_comparison(&aging_bundle, &control, &comparison_output(&expected));
    assert_eq!(
        verify_comparison(&forged, anchor.clone(), &pin).unwrap_err().predicate,
        "report_recomputation",
    );
    let mut missing = bytes.clone();
    let mut r = Reader::new(&bytes);
    r.bytes(64, "format").unwrap();
    r.u16("major").unwrap();
    r.u16("minor").unwrap();
    r.bytes(MAX_REPORT_BUNDLE_BYTES, "certificate").unwrap();
    r.bytes(MAX_REPORT_BUNDLE_BYTES, "checkpoint").unwrap();
    r.bytes(MAX_REPORT_BUNDLE_BYTES, "prefix").unwrap();
    r.u32("record count").unwrap();
    r.u32("proposal length").unwrap();
    let payload_frame = bytes.len() - r.remaining();
    // Keep the authenticated checkpoint and prefix while withholding a payload.
    missing[payload_frame..payload_frame + 4].copy_from_slice(&0u32.to_le_bytes());
    let outer = comparison::decode(native_source(&bytes)).unwrap();
    assert_eq!(
        verify_comparison(&missing, anchor, &outer.digest).unwrap_err().predicate,
        "record_derivation",
    );
}

#[test]
fn discrepancy_is_data_and_native_units_never_offset_each_other() {
    // Pure comparison fixtures intentionally supply disagreeing folds. They
    // do not claim such sources have passed complete-prefix authentication.
    let mut aging = empty_aging(5, 45);
    aging.totals = vec![
        VerifiedAgingTotal { account: account_id("1000"), unit_id: 1,
            amounts: VerifiedAgingAmounts { debits: 60, credits: 0, item_count: 1 } },
        VerifiedAgingTotal { account: account_id("1000"), unit_id: 7,
            amounts: VerifiedAgingAmounts { debits: 80, credits: 0, item_count: 1 } },
    ];
    let mut controls = vec![stock_rows(100, 0, 9).remove(0), stock_rows(40, 0, 0).remove(0)];
    controls[1].unit = 7;
    let expected = comparison_report(aging.clone(), &controls);
    assert_eq!(expected.rows.iter().map(|r| r.difference).collect::<Vec<_>>(), [40, -40]);
    let output = comparison_output(&expected);
    let certificate = comparison::Certificate { aging: &[], control: &[], output: &output, digest: [0; 32] };
    let (actual, actual_bytes) = comparison::replay(
        &certificate, [0; 32], [0; 32], displayed("1000"), aging, controls, &[1, 7],
    ).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(actual_bytes, output);
    assert!(!actual.is_reconciled());
    assert_eq!(actual.rows[0].pending_debits, 9);
}

#[test]
fn comparison_difference_overflow_is_a_typed_failure() {
    let mut aging = empty_aging(5, 45);
    aging.totals = vec![VerifiedAgingTotal {
        account: account_id("1000"), unit_id: 1,
        amounts: VerifiedAgingAmounts { debits: 0, credits: i128::MAX, item_count: 1 },
    }];
    let control = stock_rows(i128::MAX, 0, 0).remove(0);
    let certificate = comparison::Certificate { aging: &[], control: &[], output: &[], digest: [0; 32] };
    assert_eq!(comparison::replay(
        &certificate, [0; 32], [0; 32], displayed("1000"), aging, vec![control], &[1],
    ).unwrap_err().predicate, "exact_arithmetic");
}
