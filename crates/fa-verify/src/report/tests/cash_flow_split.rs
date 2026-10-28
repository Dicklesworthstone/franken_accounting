//! Separate wire encoders and literal expectations for original-leg partitions.
//! Repaired hashes never substitute for replaying authenticated source detail.
use super::*;

type Split = ([u8; 32], u32, String, Vec<(u8, i128)>);

#[derive(Clone)]
struct SplitDefinition {
    name: String,
    accounts: Vec<u128>,
    splits: Vec<Split>,
}

fn definition(f: &Fixture) -> SplitDefinition {
    SplitDefinition {
        name: "Original cash partitions".into(),
        accounts: f.definition.accounts.clone(),
        splits: f
            .definition
            .assignments
            .iter()
            .map(|&(digest, index, activity)| {
                let movement = f
                    .roll
                    .movements
                    .iter()
                    .find(|m| m.entry_digest == digest && m.leg_index == index)
                    .unwrap();
                (
                    digest,
                    index,
                    "Documented classification".into(),
                    vec![(activity, movement.debits.max(movement.credits))],
                )
            })
            .collect(),
    }
}

fn definition_bytes(d: &SplitDefinition) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(b"fa:cash-flow-split-definition:v1")
        .bytes(d.name.as_bytes())
        .count(d.accounts.len());
    for account in &d.accounts {
        w.u128(*account);
    }
    w.count(d.splits.len());
    for (digest, leg, reason, portions) in &d.splits {
        w.fixed(digest)
            .u32(*leg)
            .bytes(reason.as_bytes())
            .count(portions.len());
        for (activity, amount) in portions {
            w.u8(*activity).i128(*amount);
        }
    }
    w.buf
}

fn split_output(ledger: &[u8], d: &SplitDefinition, units: &[Unit]) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(b"fa:cash-flow-split:v1")
        .bytes(ledger)
        .bytes(&definition_bytes(d))
        .count(units.len());
    for (unit, opening, sections, change, closing) in units {
        w.u32(*unit).i128(*opening);
        for section in sections {
            for amount in section {
                w.i128(*amount);
            }
        }
        w.i128(*change).i128(*closing);
    }
    w.buf
}

fn split_certificate(source: &[u8], definition: &[u8], output: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let mut w = Writer::default();
    w.bytes(b"fa:cash-flow-split-certificate:v1")
        .bytes(source)
        .bytes(definition)
        .bytes(output);
    sealed(w, b"fa:cash-flow-split-certificate-digest:v1")
}

fn split_bundle(
    f: &Fixture,
    d: &SplitDefinition,
    units: &[Unit],
) -> (Vec<u8>, [u8; 32], Vec<u8>, [u8; 32]) {
    let (roll_bundle, roll_pin) = wrap(&f.native, &f.roll);
    let output = split_output(&ledger_bytes(&f.roll), d, units);
    let (outer, pin) = split_certificate(certificate(&roll_bundle), &definition_bytes(d), &output);
    (
        replace_certificate(&roll_bundle, &outer),
        pin,
        output,
        roll_pin,
    )
}

#[test]
fn split_loan_and_partial_internal_transfer_replay_original_legs_above_float_precision() {
    let k = (1i128 << 55) + 1;
    let f = single_entry(
        &[
            leg("1000", false, 110 * k),
            leg("1100", true, 50 * k),
            leg("3000", true, 50 * k),
            leg("7000", true, 10 * k),
        ],
        &["1000", "1100"],
        &[(0, 0), (1, 4)],
    );
    let mut d = definition(&f);
    let cash = d.splits.iter_mut().find(|split| split.1 == 0).unwrap();
    cash.2 = "Interest, principal and internal transfer".into();
    cash.3 = vec![(0, 10 * k), (2, 50 * k), (4, 50 * k)];
    let units = vec![
        (0, 0, [[0; 3]; 4], 0, 0),
        (
            1,
            0,
            [[0, 10 * k, -10 * k], [0; 3], [0, 50 * k, -50 * k], [0; 3]],
            -60 * k,
            -60 * k,
        ),
    ];
    let (bundle, pin, expected, roll_pin) = split_bundle(&f, &d, &units);
    let actual = check(&f, &bundle, &pin).unwrap();
    assert_eq!(actual.output, expected);
    assert_eq!(actual.certificate_digest, pin);
    assert_eq!(actual.unit_universe_source, "authenticated-registry");
    assert!(actual.cash_flow.is_none());
    let split = actual.split_cash_flow.unwrap();
    assert_eq!(split.source_certificate_digest, roll_pin);
    assert_eq!(
        split.ledger.lines.len(),
        2,
        "portions never become synthetic journal legs"
    );
    assert_eq!(split.definition.splits.len(), 2);
    assert_eq!(
        split
            .definition
            .splits
            .iter()
            .map(|s| s.portions.len())
            .sum::<usize>(),
        4
    );
    assert_eq!(
        (
            split.units[1].operating.outflows,
            split.units[1].financing.outflows
        ),
        (10 * k, 50 * k)
    );
    assert_eq!(split.units[1].closing, -60 * k);
    assert_eq!(split.units[0].closing, 0);
    assert!(check(&f, &bundle, &roll_pin).is_err());
    assert!(check(&f, &bundle, &f.roll.source_certificate_digest).is_err());
}

#[test]
fn split_history_keeps_gross_sections_overdraft_and_historical_zero_cells() {
    for (known_at, opening) in [(12, 80), (13, 89)] {
        let f = fixture(known_at, 10, 20, false);
        let d = definition(&f);
        let (bundle, pin, expected, _) = split_bundle(&f, &d, &expected_units(opening));
        let actual = check(&f, &bundle, &pin).unwrap();
        assert_eq!(actual.output, expected);
        let split = actual.split_cash_flow.unwrap();
        assert_eq!(split.ledger.lines.len(), 8);
        assert_eq!(split.ledger.cells.len(), 6);
        assert_eq!(split.units.len(), 2);
        assert_eq!(
            (split.units[1].opening, split.units[1].closing),
            (opening, opening + 43)
        );
        assert_eq!(
            (
                split.units[1].operating.inflows,
                split.units[1].operating.outflows
            ),
            (40, 10)
        );
        assert!(
            split
                .ledger
                .lines
                .iter()
                .all(|l| (10..=20).contains(&l.effective_day) && l.recorded_seq <= 10)
        );
    }
    let f = fixture(12, 21, 30, false);
    let (bundle, pin, expected, _) = split_bundle(&f, &definition(&f), &zero_units(123));
    let actual = check(&f, &bundle, &pin).unwrap();
    assert_eq!(actual.output, expected);
    let split = actual.split_cash_flow.unwrap();
    assert!(split.ledger.lines.is_empty());
    assert!(split.definition.splits.is_empty());
    assert_eq!((split.units[1].opening, split.units[1].closing), (123, 123));
}

#[test]
fn split_repaired_hashes_cannot_hide_changed_stock_ledger_reasons_or_partitions() {
    let f = fixture(12, 10, 20, false);
    let d = definition(&f);
    let (bundle, _, output, _) = split_bundle(&f, &d, &expected_units(80));
    let (roll_bundle, _) = wrap(&f.native, &f.roll);
    let source = certificate(&roll_bundle);
    for case in 0..5 {
        let mut forged_output = output.clone();
        let mut forged_definition = d.clone();
        match case {
            0 => *forged_output.last_mut().unwrap() ^= 1,
            1 => {
                let mut ledger = ledger_bytes(&f.roll);
                *ledger.last_mut().unwrap() ^= 1;
                forged_output = split_output(&ledger, &d, &expected_units(80));
            }
            2 => {
                forged_definition.splits[0].3[0].1 += 1;
                forged_output = split_output(
                    &ledger_bytes(&f.roll),
                    &forged_definition,
                    &expected_units(80),
                );
            }
            3 => forged_definition.splits[0].2 = "A changed judgment".into(),
            4 => {
                let mut units = expected_units(80);
                units[1].2[0][0] += 1;
                units[1].2[0][1] += 1;
                forged_output = split_output(&ledger_bytes(&f.roll), &d, &units);
            }
            _ => unreachable!(),
        }
        let (outer, pin) = split_certificate(
            source,
            &definition_bytes(&forged_definition),
            &forged_output,
        );
        assert!(
            check(&f, &replace_certificate(&bundle, &outer), &pin).is_err(),
            "forgery {case}"
        );
    }
    // A self-consistent change of professional judgment needs the recipient's
    // new outer pin. The proof does not pretend to judge economic treatment.
    let mut changed = d;
    changed.splits[0].2 = "Different approved documentation".into();
    let (old, old_pin, _, _) = split_bundle(&f, &definition(&f), &expected_units(80));
    let (new, new_pin, _, _) = split_bundle(&f, &changed, &expected_units(80));
    check(&f, &new, &new_pin).unwrap();
    assert!(check(&f, &new, &old_pin).is_err());
    assert_ne!(old, new);
}

#[test]
fn split_coverage_positive_portions_and_canonical_order_are_required() {
    let f = fixture(12, 10, 20, false);
    for case in 0..15 {
        let mut d = definition(&f);
        match case {
            0 => {
                d.accounts.pop();
            }
            1 => {
                d.accounts.push(account_id("4000"));
                d.accounts.sort_unstable();
            }
            2 => d.accounts.reverse(),
            3 => d.accounts[1] = d.accounts[0],
            4 => {
                d.splits.pop();
            }
            5 => d.splits[1] = d.splits[0].clone(),
            6 => d.splits.reverse(),
            7 => {
                d.splits[0].1 = 999;
                d.splits.sort_by_key(|s| (s.0, s.1));
            }
            8 => d.name = " \t".into(),
            9 => d.splits[0].2 = " \t".into(),
            10 => d.splits[0].3.clear(),
            11 => d.splits[0].3[0].1 = 0,
            12 => d.splits[0].3[0].1 = -1,
            13 => d.splits[0].3[0].0 = 5,
            14 => {
                let duplicate = d.splits[0].3[0];
                d.splits[0].3.push(duplicate);
            }
            _ => unreachable!(),
        }
        let (bundle, pin, _, _) = split_bundle(&f, &d, &expected_units(80));
        assert!(
            check(&f, &bundle, &pin).is_err(),
            "malformed partition {case}"
        );
    }
    let f = single_entry(
        &[leg("1000", true, 10), leg("4000", false, 10)],
        &["1000"],
        &[(0, 0)],
    );
    let mut d = definition(&f);
    d.splits[0].3 = vec![(2, 5), (0, 5)];
    let units = vec![
        (0, 0, [[0; 3]; 4], 0, 0),
        (1, 0, [[5, 0, 5], [0; 3], [5, 0, 5], [0; 3]], 10, 10),
    ];
    let (bundle, pin, _, _) = split_bundle(&f, &d, &units);
    assert!(check(&f, &bundle, &pin).is_err());
}

#[test]
fn split_transfer_portions_require_distinct_accounts_same_entry_and_same_native_unit() {
    let f = single_entry(
        &[leg("1000", true, 10), leg("1000", false, 10)],
        &["1000"],
        &[(0, 0), (1, 0)],
    );
    let mut d = definition(&f);
    let (bundle, pin, _, _) = split_bundle(&f, &d, &zero_units(0));
    check(&f, &bundle, &pin).unwrap();
    for split in &mut d.splits {
        split.3[0].0 = 4;
    }
    let (bundle, pin, _, _) = split_bundle(&f, &d, &zero_units(0));
    assert!(check(&f, &bundle, &pin).is_err());

    let mut other_cash = leg("1100", false, 10);
    other_cash.unit = 0;
    let mut other_counterpart = leg("4000", true, 10);
    other_counterpart.unit = 0;
    let f = single_entry(
        &[
            leg("1000", true, 10),
            leg("4000", false, 10),
            other_cash,
            other_counterpart,
        ],
        &["1000", "1100"],
        &[(0, 0), (2, 0)],
    );
    let mut d = definition(&f);
    let units = vec![
        (0, 0, [[0, 10, -10], [0; 3], [0; 3], [0; 3]], -10, -10),
        (1, 0, [[10, 0, 10], [0; 3], [0; 3], [0; 3]], 10, 10),
    ];
    let (bundle, pin, _, _) = split_bundle(&f, &d, &units);
    check(&f, &bundle, &pin).unwrap();
    for split in &mut d.splits {
        split.3[0].0 = 4;
    }
    let (bundle, pin, _, _) = split_bundle(&f, &d, &units);
    assert!(check(&f, &bundle, &pin).is_err());

    let f = fixture(12, 10, 20, false);
    let mut d = definition(&f);
    // A receipt in one original entry cannot cancel a transfer in another.
    for split in &mut d.splits {
        split.3[0].0 = 4;
    }
    let (bundle, pin, _, _) = split_bundle(&f, &d, &expected_units(80));
    assert!(check(&f, &bundle, &pin).is_err());
}

#[test]
fn split_framing_bounds_and_source_composition_fail_closed() {
    let f = fixture(12, 10, 20, false);
    let d = definition(&f);
    let (bundle, pin, output, _) = split_bundle(&f, &d, &expected_units(80));
    let outer = certificate(&bundle);
    for cut in [0, 1, 4, 32, outer.len() / 2, outer.len() - 1] {
        assert!(check(&f, &replace_certificate(&bundle, &outer[..cut]), &pin).is_err());
    }
    let (roll_bundle, _) = wrap(&f.native, &f.roll);
    for case in 0..3 {
        let mut w = Writer::default();
        w.bytes(b"fa:cash-flow-split-definition:v1")
            .bytes(b"Bounded");
        if case > 0 {
            w.count(1).u128(account_id("1000"));
        }
        if case > 1 {
            w.count(1).fixed(&[1; 32]).u32(0).bytes(b"Reason");
        }
        w.u32(u32::MAX);
        let (bad, pin) = split_certificate(certificate(&roll_bundle), &w.buf, &output);
        assert!(check(&f, &replace_certificate(&bundle, &bad), &pin).is_err());
    }
    let mut trailing = Writer::default();
    trailing.fixed(&outer[..outer.len() - 32]).u8(0);
    let (bad, pin) = sealed(trailing, b"fa:cash-flow-split-certificate-digest:v1");
    assert!(check(&f, &replace_certificate(&bundle, &bad), &pin).is_err());
    let (direct_bundle, _, _, _) = direct(&f, &f.definition, &expected_units(80));
    for source in [certificate(&f.native), certificate(&direct_bundle), outer] {
        let (bad, pin) = split_certificate(source, &definition_bytes(&d), &output);
        assert!(check(&f, &replace_certificate(&bundle, &bad), &pin).is_err());
    }
}
