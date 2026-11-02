//! Detail uses the original authenticated roll-forward. Expected cells and
//! balances are hand calculated; canonical bytes use the separate fixture
//! encoder shared with the cash-flow differential tests.

use super::*;

fn backdated_fixture() -> (Vec<u8>, SignedCheckpoint, VerifiedRollForward) {
    let mut records = schema();
    for (seq, day, debit, amount) in [
        (3, 9, true, 100),
        (4, 20, true, 40),
        (5, 10, false, 15),
        (6, 10, true, 7),
        (7, 20, false, 7),
        // A newer covering checkpoint cannot introduce a later backdate into
        // the recipient's explicitly selected historical prefix.
        (8, 8, true, 999),
    ] {
        records.push(
            dated(
                posting(
                    1,
                    seq,
                    &seq.to_le_bytes(),
                    &[leg("1000", debit, amount), leg("3000", !debit, amount)],
                    None,
                    None,
                ),
                day,
            )
            .0,
        );
    }
    let mut expected = schedule(7, 10, 20, &["1000", "3000"], &[0, 1]);
    let bucket = classification(1, "", None);
    expected.buckets = vec![bucket.clone()];
    for row in &mut expected.rows {
        let sign = if row.account_id == account_id("1000") {
            1
        } else {
            -1
        };
        row.activity = vec![if row.unit_id == 1 { 25 * sign } else { 0 }];
        if row.unit_id == 1 {
            row.opening = 100 * sign;
            row.net_change = 25 * sign;
            row.closing = 125 * sign;
        }
    }
    for (index, debit, amount) in [(3, true, 40), (4, false, 15), (5, true, 7), (6, false, 7)] {
        expected.movements.extend([
            movement(&records[index], 0, "1000", debit, amount, &bucket),
            movement(&records[index], 1, "3000", !debit, amount, &bucket),
        ]);
    }
    let (native, anchor, _) = source_bundle(&records, 7, 20, &stock(147, 22), &[]);
    (native, anchor, expected)
}

#[test]
fn general_ledger_detail_reproduces_exact_bytes_zero_cells_and_effective_running_order() {
    let (native, anchor, expected) = backdated_fixture();
    let source = verify(&native, anchor, &expected).unwrap();
    let detail = source.general_ledger_detail().unwrap();
    assert_eq!(detail, source.general_ledger_detail().unwrap());
    assert_eq!(detail.output, cash_flow::ledger_bytes(&expected));
    assert_ne!(detail.output, source.output);
    assert_eq!(detail.source_certificate_digest, source.certificate_digest);
    assert_eq!(detail.source_output_digest, source.output_digest);
    assert_eq!(
        detail.output_digest,
        hash_parts(b"fa:report-output:v1", &[&detail.output])
    );
    assert_ne!(detail.output_digest, source.output_digest);
    assert_eq!(source.output, expected_bytes(&expected));
    assert_eq!(detail.ledger.known_at, 7);
    assert_eq!(source.checkpoint.checkpoint.through_seq, 8);
    assert_eq!(detail.ledger.units, [0, 1]);
    assert_eq!(detail.ledger.cells.len(), 4);
    assert_eq!(detail.ledger.lines.len(), 8);
    let cash = &detail.ledger.cells[1];
    assert_eq!(
        (
            cash.opening,
            cash.debits,
            cash.credits,
            cash.net_change,
            cash.closing
        ),
        (100, 47, 22, 25, 125)
    );
    assert_eq!((cash.line_start, cash.line_end), (0, 4));
    let equity = &detail.ledger.cells[3];
    assert_eq!(
        (
            equity.opening,
            equity.debits,
            equity.credits,
            equity.net_change,
            equity.closing
        ),
        (-100, 22, 47, -25, -125)
    );
    assert_eq!((equity.line_start, equity.line_end), (4, 8));
    for (index, position) in [(0, 0), (2, 4)] {
        let cell = &detail.ledger.cells[index];
        assert_eq!(cell.unit_id, 0);
        assert_eq!(
            (
                cell.opening,
                cell.debits,
                cell.credits,
                cell.net_change,
                cell.closing
            ),
            (0, 0, 0, 0, 0)
        );
        assert_eq!((cell.line_start, cell.line_end), (position, position));
    }
    assert_eq!(
        detail.ledger.lines[..4]
            .iter()
            .map(|line| (line.effective_day, line.recorded_seq, line.running_balance))
            .collect::<Vec<_>>(),
        [(10, 5, 85), (10, 6, 92), (20, 4, 132), (20, 7, 125)]
    );
    assert_eq!(
        detail.ledger.lines[4..]
            .iter()
            .map(|line| line.running_balance)
            .collect::<Vec<_>>(),
        [-85, -92, -132, -125]
    );
    assert!(
        detail
            .ledger
            .lines
            .iter()
            .all(|line| line.recorded_seq <= 7)
    );
}

#[test]
fn general_ledger_detail_retains_zero_net_original_and_reversal_and_rejects_omission() {
    let (records, expected) = offsetting(40);
    let (native, anchor, _) = source_bundle(&records, 4, 20, &stock(40, 40), &[]);
    let source = verify(&native, anchor.clone(), &expected).unwrap();
    let detail = source.general_ledger_detail().unwrap();
    let cell = &detail.ledger.cells[0];
    assert_eq!(
        (
            cell.opening,
            cell.debits,
            cell.credits,
            cell.net_change,
            cell.closing
        ),
        (0, 40, 40, 0, 0)
    );
    assert_eq!(
        detail
            .ledger
            .lines
            .iter()
            .map(|line| line.running_balance)
            .collect::<Vec<_>>(),
        [40, 0]
    );
    assert_eq!(detail.ledger.lines[1].bucket_index, 1);
    assert_eq!(detail.ledger.buckets[1].reason_code, "supersession:1");
    let mut omitted = expected;
    omitted.movements.clear();
    // wrap() regenerates the outer certificate digest, so this refusal checks
    // complete source recomputation, not an accidental stale checksum.
    assert!(
        verify(&native, anchor, &omitted)
            .and_then(|source| source.general_ledger_detail())
            .is_err()
    );
}

#[test]
fn general_ledger_detail_keeps_empty_complete_scope_and_refuses_other_families() {
    let records = schema();
    let expected = schedule(2, -1, 20, &["1000", "3000"], &[0, 1]);
    let (native, anchor, _) = source_bundle(&records, 2, 20, &[], &[]);
    let detail = verify(&native, anchor.clone(), &expected)
        .unwrap()
        .general_ledger_detail()
        .unwrap();
    assert_eq!(detail.ledger.cells.len(), 4);
    assert!(detail.ledger.lines.is_empty());
    assert!(
        detail
            .ledger
            .cells
            .iter()
            .all(|cell| cell.line_start == 0 && cell.line_end == 0)
    );
    assert_eq!(detail.output, cash_flow::ledger_bytes(&expected));
    // The bare trial-balance receiver uses its supported v1 transport; the
    // registry-bearing v2 native source above is admitted through its wrapper.
    let (trial_bytes, trial_anchor) = bundle(&records, 2, Selection::AsOf(20), &[]);
    let trial_balance =
        verify_report_with(&trial_bytes, &[], None, None, None, |_, _| Ok(trial_anchor)).unwrap();
    assert_eq!(
        trial_balance.general_ledger_detail().unwrap_err().predicate,
        "report_view"
    );
}

#[test]
fn general_ledger_detail_requires_original_outer_pin_and_complete_source() {
    let (records, expected) = offsetting(40);
    let (native, anchor, inner_pin) = source_bundle(&records, 4, 20, &stock(40, 40), &[]);
    let (bundle, outer_pin) = wrap(&native, &expected);
    let project = |bytes: &[u8], pin: Option<&[u8; 32]>| {
        verify_report_with(bytes, &[], None, None, pin, |_, _| Ok(anchor.clone()))
            .and_then(|source| source.general_ledger_detail())
    };
    let detail = project(&bundle, Some(&outer_pin)).unwrap();
    assert_eq!(detail.source_certificate_digest, outer_pin);
    assert!(project(&bundle, None).is_err());
    assert!(project(&bundle, Some(&inner_pin)).is_err());
    assert!(project(&bundle, Some(&detail.output_digest)).is_err());
    let (wrong_native, _, _) = source_bundle(&records, 4, 20, &stock(39, 39), &[]);
    let (wrong_bundle, wrong_pin) = wrap(&wrong_native, &expected);
    assert_eq!(
        project(&wrong_bundle, Some(&wrong_pin))
            .unwrap_err()
            .predicate,
        "report_recomputation"
    );
}

#[test]
fn general_ledger_detail_bounds_before_projection_and_refuses_intermediate_overflow() {
    let (records, expected) = offsetting(40);
    let (native, anchor, _) = source_bundle(&records, 4, 20, &stock(40, 40), &[]);
    let source = verify(&native, anchor, &expected).unwrap();
    // These deliberate public-struct mutations exercise the projector's
    // resource/arithmetic guards, not proof authentication. The API requires
    // an unmodified verifier result for its source-authentication claim.
    let mut too_many_cells = source.clone();
    let schedule = too_many_cells.roll_forward.as_mut().unwrap();
    schedule.rows.resize(65_537, schedule.rows[0].clone());
    assert_eq!(
        too_many_cells
            .general_ledger_detail()
            .unwrap_err()
            .predicate,
        "bounded_input"
    );
    let mut too_many_lines = source.clone();
    let schedule = too_many_lines.roll_forward.as_mut().unwrap();
    schedule
        .movements
        .resize(250_001, schedule.movements[0].clone());
    assert_eq!(
        too_many_lines
            .general_ledger_detail()
            .unwrap_err()
            .predicate,
        "bounded_input"
    );
    let mut running_overflow = source.clone();
    let schedule = running_overflow.roll_forward.as_mut().unwrap();
    schedule.rows[0].opening = i128::MAX;
    schedule.rows[0].closing = i128::MAX;
    // Opening + closing net fits; the first positive leg does not.
    assert_eq!(
        running_overflow
            .general_ledger_detail()
            .unwrap_err()
            .predicate,
        "exact_arithmetic"
    );
    let mut gross_overflow = source;
    let schedule = gross_overflow.roll_forward.as_mut().unwrap();
    schedule.movements[0].debits = i128::MAX;
    schedule.movements[1].credits = i128::MAX;
    let mut extra_debit = schedule.movements[0].clone();
    extra_debit.entry_digest = [255; 32];
    extra_debit.recorded_seq = 4;
    extra_debit.effective_day = 20;
    extra_debit.debits = 1;
    let mut extra_credit = extra_debit.clone();
    extra_credit.leg_index = 1;
    extra_credit.debits = 0;
    extra_credit.credits = 1;
    schedule.movements.extend([extra_debit, extra_credit]);
    assert_eq!(
        gross_overflow
            .general_ledger_detail()
            .unwrap_err()
            .predicate,
        "exact_arithmetic"
    );
}
