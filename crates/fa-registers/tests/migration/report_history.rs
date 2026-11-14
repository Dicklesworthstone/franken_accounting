use super::*;

#[test]
fn resident_report_population_rebuilds_when_migration_visibility_changes() {
    let (mut k, _) = setup();
    let spec = RunSpec {
        key: "report-visible-run".into(),
        opening_date: opening_date(),
        lines: vec![
            ("1000".into(), usd().0, 100),
            ("2000".into(), usd().0, -100),
        ],
        periods: Vec::new(),
        full_detail: None,
    };
    let run = kernel_open(&mut k, &spec, "report-open", &["post", "migrate"])
        .unwrap()
        .run;
    post_chunk(
        &mut k,
        run,
        "report-chunk",
        vec![
            leg(fa_reference::Side::Debit, "1000", 100),
            leg(fa_reference::Side::Credit, "2000", 100),
        ],
    );
    let periods = vec![OPENING.to_string()];
    let cx = k.ctx();
    let before = k.db.frontier().unwrap();
    let mut memo = fa_registers::ReportHistoryMemo::default();
    let (hidden, _) = fa_registers::trial_balance_served_at_carried(
        &k.db,
        &cx.query(),
        &k.book,
        &periods,
        Some(before),
        &mut memo,
    )
    .unwrap();
    assert!(hidden.unit_totals.is_empty());
    assert_eq!(memo.read_work().population_scans, 1);
    let proposal = kernel_plan(&k, run, kind::FINALIZE, "report-finalize").unwrap();
    kernel_transition(&mut k, proposal, true).unwrap();
    let after = k.db.frontier().unwrap();
    let literal = fa_registers::trial_balance_served_at_with_context(
        &k.db,
        &cx.query(),
        &k.book,
        &periods,
        Some(after),
    )
    .unwrap();
    let carried = fa_registers::trial_balance_served_at_carried(
        &k.db,
        &cx.query(),
        &k.book,
        &periods,
        Some(after),
        &mut memo,
    )
    .unwrap();
    assert_eq!(carried, literal);
    assert_eq!(carried.0.unit_totals.get(&usd().0), Some(&(100, 100)));
    assert!(matches!(carried.1, fa_registers::Served::Literal(_)));
    assert_eq!(memo.read_work().metadata_scans, 1);
    assert_eq!(memo.read_work().population_scans, 1);
    let historical = fa_registers::trial_balance_served_at_carried(
        &k.db,
        &cx.query(),
        &k.book,
        &periods,
        Some(before),
        &mut memo,
    )
    .unwrap();
    assert_eq!(historical.0, hidden);
    assert_eq!(memo.known_at(), Some(after));
    assert_eq!(k.db.frontier().unwrap(), after);
}
