//! Migration lifecycle and hostile complete-prefix vectors, independently encoded.
use super::*;

pub(super) fn run() -> u128 {
    let hash = framed_hash(b"fa:vid:migration-run:v1", &[&BOOK, b"functional-import"]);
    u128::from_le_bytes(hash[..16].try_into().unwrap())
}
pub(super) fn body(mode: u8, sole: bool) -> Vec<u8> {
    let mut w = Writer::default();
    w.u16(1)
        .fixed(&BOOK)
        .bytes(b"functional-import")
        .bytes(b"legacy")
        .u8(mode)
        .fixed(&[0; 32])
        .i32(10)
        .count(0);
    if mode != 0 {
        w.count(0);
    }
    if mode == 2 {
        w.count(0).u8(u8::from(sole));
    }
    w.buf
}
pub(super) fn control(seq: u64, kind: u8, run: u128, body: &[u8]) -> Record {
    let digest = framed_hash(b"fa:migration-run-body:v1", &[body]);
    let mut w = prefix(22, 10);
    w.count(0)
        .u8(1)
        .u8(10)
        .u128(run)
        .u8(kind)
        .fixed(if kind == 0 { &digest } else { &[9; 32] })
        .count(0)
        .u8(0)
        .bytes(&seq.to_le_bytes())
        .u8(3)
        .u16(9)
        .fixed(&digest)
        .u128(PRINCIPAL)
        .u8(0)
        .count(0)
        .count(0)
        .u8(0)
        .count(0)
        .count(0);
    finish(w, seq)
}
fn base_legs(amount: i128) -> Vec<TestLeg> {
    pair(amount, amount)
        .into_iter()
        .map(|mut leg| {
            leg.unit = 0;
            leg.base = None;
            leg
        })
        .collect()
}
fn history(mode: u8, sole: bool, effective: i32) -> (Vec<Record>, Vec<u8>) {
    let body = body(mode, sole);
    let mut records = schema();
    records.push(control(3, 0, run(), &body));
    records.push(entry_with_migration(
        4,
        12,
        effective,
        b"imported-capital",
        &base_legs(42),
        None,
        None,
        None,
        Some(run()),
    ));
    records.push(control(5, 1, run(), &body));
    (records, body)
}
pub(super) fn verify_packed(
    records: &[Record],
    known_at: u64,
    rates: &[RateFixture],
    output: &[u8],
    bodies: &[(u64, &[u8])],
) -> Result<crate::report::VerifiedReport, ReportError> {
    let mut selector = Writer::default();
    selector.u8(8).u8(1).i32(30);
    let (bundle, signed, pin) = pack_profile_with_migrations(
        records,
        known_at,
        &book(&[]),
        rates,
        output,
        CertificateProfile {
            format: FUNCTIONAL_CERTIFICATE_FORMAT,
            output_format: OUTPUT_FORMAT,
            selector: &selector.buf,
        },
        &registries(),
        bodies,
    );
    verify_report_with_inputs(&bundle, &[], None, None, Some(&pin), None, |_, _| {
        Ok(signed.clone())
    })
}

fn assert_capital_cells(report: &VerifiedFunctionalTrialBalance, amount: Option<i128>) {
    let expected = if let Some(amount) = amount {
        BTreeMap::from([
            (id("1000"), (0, None, amount, 0, 1)),
            (id("3000"), (0, None, 0, amount, 1)),
        ])
    } else {
        BTreeMap::new()
    };
    let actual: BTreeMap<_, _> = report
        .cells
        .iter()
        .map(|cell| {
            (
                cell.account,
                (
                    cell.unit_id,
                    cell.entity.as_deref(),
                    cell.debits,
                    cell.credits,
                    cell.entry_count,
                ),
            )
        })
        .collect();
    assert_eq!(actual, expected);
    assert_eq!(report.base_unit, 0);
    assert!(report.pending.is_empty());
}

#[test]
fn migration_modes_activate_functional_stock_and_activity_at_finalize_only() {
    for (mode, sole, effective, counted) in [
        (0, false, 10, true),
        (1, false, 10, true),
        (2, false, 9, false),
        (2, false, 10, true),
        (2, true, 9, true),
    ] {
        let (records, body) = history(mode, sole, effective);
        let bodies = [(2, body.as_slice())];
        for selection in [Selection::AsOf(30), Selection::Activity(vec!["P1".into()])] {
            for known_at in [4, 5] {
                let (report, output) = replay_migration_fixture(
                    &records,
                    selection.clone(),
                    known_at,
                    &book(&[]),
                    &[],
                    &bodies,
                )
                .unwrap();
                let visible = counted && known_at == 5;
                assert_eq!(report.entries, u64::from(visible));
                assert_eq!(report.watermark, visible.then_some(5));
                assert_capital_cells(&report, visible.then_some(42));
                assert_eq!(
                    report.cells.iter().map(|cell| cell.debits).sum::<i128>(),
                    if visible { 42 } else { 0 }
                );
                assert_eq!(
                    report.cells.iter().map(|cell| cell.credits).sum::<i128>(),
                    if visible { 42 } else { 0 }
                );
                if selection == Selection::AsOf(30) {
                    let verified =
                        verify_packed(&records, known_at, &[], &output, &bodies).unwrap();
                    assert_eq!(verified.functional_trial_balance, Some(report));
                }
            }
        }
    }
}

#[test]
fn activation_source_digest_changes_without_rewriting_the_import_birth() {
    let (records, body) = history(0, false, 10);
    let bodies = [(2, body.as_slice())];
    let (_, original) =
        replay_migration_fixture(&records, Selection::AsOf(30), 5, &book(&[]), &[], &bodies)
            .unwrap();
    let mut later = records.clone();
    later[4] = control(6, 1, run(), &body);
    let (report, changed) =
        replay_migration_fixture(&later, Selection::AsOf(30), 6, &book(&[]), &[], &bodies).unwrap();
    assert_eq!(later[3].envelope, records[3].envelope);
    assert_eq!(report.watermark, Some(6));
    assert_ne!(original, changed);
    assert!(verify_packed(&later, 6, &[], &original, &bodies).is_err());
    assert!(verify_packed(&later, 6, &[], &changed, &bodies).is_ok());
}

#[test]
fn missing_forged_future_abandoned_and_reordered_controls_cannot_supply_functional_amounts() {
    let (records, body) = history(0, false, 10);
    let bodies = [(2, body.as_slice())];
    let (_, output) =
        replay_migration_fixture(&records, Selection::AsOf(30), 5, &book(&[]), &[], &bodies)
            .unwrap();
    assert!(verify_packed(&records, 5, &[], &output, &[]).is_err());
    assert!(verify_packed(&records, 5, &[], &output, &[(3, &body)]).is_err());
    assert!(verify_packed(&records, 5, &[], &output, &[(2, &body), (2, &body)]).is_err());
    let substituted = self::body(2, true);
    assert!(verify_packed(&records, 5, &[], &output, &[(2, &substituted)]).is_err());
    for kind in 0..6 {
        let mut altered = records.clone();
        match kind {
            0 => {
                altered.remove(4);
            }
            1 => {
                altered[4] = control(5, 2, run(), &body);
            }
            2 => {
                altered[4] = control(6, 1, run(), &body);
            }
            3 => {
                altered[4] = control(5, 1, run() + 1, &body);
            }
            4 => {
                altered.swap(3, 4);
            }
            _ => {
                altered.remove(2);
            }
        }
        assert!(
            verify_packed(&altered, 5, &[], &output, &bodies).is_err(),
            "mutation {kind}"
        );
    }
    let mut after_terminal = records.clone();
    after_terminal.push(entry_with_migration(
        6,
        12,
        10,
        b"after-finalize",
        &base_legs(1),
        None,
        None,
        None,
        Some(run()),
    ));
    assert!(verify_packed(&after_terminal, 6, &[], &output, &bodies).is_err());
    let mut forged_output = output.clone();
    *forged_output.last_mut().unwrap() ^= 1;
    assert!(verify_packed(&records, 5, &[], &forged_output, &bodies).is_err());
}

#[test]
fn spot_valued_imports_are_independently_repriced_and_hidden_before_activation() {
    let body = body(0, false);
    let rate = rate_fixture(11, 10, 1, 10);
    let mut records = schema();
    records.push(intake(&rate, 3));
    records.push(control(4, 0, run(), &body));
    records.push(entry_with_migration(
        5,
        12,
        10,
        b"foreign-opening",
        &pair(100, 110),
        Some((1, &rate, None)),
        None,
        None,
        Some(run()),
    ));
    records.push(control(6, 1, run(), &body));
    let rates = [rate.clone()];
    let bodies = [(3, body.as_slice())];
    for known_at in [5, 6] {
        let (report, output) = replay_migration_fixture(
            &records,
            Selection::AsOf(30),
            known_at,
            &book(&[]),
            &rates,
            &bodies,
        )
        .unwrap();
        assert_eq!(
            report.cells.iter().map(|cell| cell.debits).sum::<i128>(),
            if known_at == 6 { 110 } else { 0 }
        );
        assert_eq!(report.watermark, (known_at == 6).then_some(6));
        assert_capital_cells(&report, (known_at == 6).then_some(110));
        assert!(verify_packed(&records, known_at, &rates, &output, &bodies).is_ok());
    }
    records[4] = entry_with_migration(
        5,
        12,
        10,
        b"foreign-opening",
        &pair(100, 111),
        Some((1, &rate, None)),
        None,
        None,
        Some(run()),
    );
    for known_at in [5, 6] {
        assert!(
            replay_migration_fixture(
                &records,
                Selection::AsOf(30),
                known_at,
                &book(&[]),
                &rates,
                &bodies,
            )
            .is_err(),
            "hidden imports must not bypass valuation checks"
        );
    }
}

#[test]
fn an_exact_reversal_cannot_make_an_unactivated_import_spendable() {
    let (mut records, body) = history(0, false, 10);
    let target = records[3].clone();
    let mut reversed = base_legs(42);
    for leg in &mut reversed {
        leg.debit = !leg.debit;
    }
    records.push(entry(
        6,
        4,
        10,
        b"reverse-import",
        &reversed,
        None,
        Some(&target),
        None,
    ));
    let bodies = [(2, body.as_slice())];
    assert!(
        replay_migration_fixture(&records, Selection::AsOf(30), 6, &book(&[]), &[], &bodies)
            .is_ok()
    );
    for kind in [0, 2] {
        let mut altered = records.clone();
        if kind == 0 {
            altered.remove(4);
        } else {
            altered[4] = control(5, kind, run(), &body);
        }
        assert!(
            replay_migration_fixture(&altered, Selection::AsOf(30), 6, &book(&[]), &[], &bodies)
                .is_err()
        );
    }
}
