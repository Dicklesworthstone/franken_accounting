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
    // January's final day covers both P01 and Opening in the cumulative report.
    let periods = [P01.to_string()];
    let cx = k.ctx();
    let before = k.db.frontier().unwrap();
    let mut memo = fa_registers::ReportHistoryMemo::default();
    let (hidden, served) = fa_registers::trial_balance_served_at_carried(
        &k.db,
        &cx.query(),
        &k.book,
        &periods,
        Some(before),
        &mut memo,
    )
    .unwrap();
    assert!(hidden.unit_totals.is_empty());
    assert!(matches!(served, fa_registers::Served::Maintained(_)));
    assert_eq!(memo.read_work().population_scans, 1);
    let repeated = fa_registers::trial_balance_served_at_carried(
        &k.db,
        &cx.query(),
        &k.book,
        &periods,
        Some(before),
        &mut memo,
    )
    .unwrap();
    assert_eq!(repeated, (hidden.clone(), served));
    assert_eq!(memo.read_work().population_scans, 0);
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

    // Opening alone ends inside P01. That date cut requires a literal fold
    // even when the migration has populated the overlapping Opening period.
    let mut opening_memo = fa_registers::ReportHistoryMemo::default();
    for (at, totals) in [(before, None), (after, Some((100, 100)))] {
        let (opening, served) = fa_registers::trial_balance_served_at_carried(
            &k.db,
            &cx.query(),
            &k.book,
            &[OPENING.to_string()],
            Some(at),
            &mut opening_memo,
        )
        .unwrap();
        assert_eq!(opening.unit_totals.get(&usd().0).copied(), totals);
        assert_eq!(
            served,
            fa_registers::Served::Literal(format!("period `{P01}` straddles 2026-01-01"))
        );
        assert_eq!(opening_memo.read_work().population_scans, 0);
    }
    assert_eq!(k.db.frontier().unwrap(), after);
}

#[test]
fn resident_open_items_rebuild_for_migration_activation_and_reopened_history() {
    use fa_registers::open_items::{OpenItemMemo, open_items_report, open_items_report_carried};

    let (mut k, _) = setup();
    let spec = RunSpec {
        key: "open-item-visible-run".into(),
        opening_date: opening_date(),
        lines: vec![
            ("1000".into(), usd().0, 100),
            ("2000".into(), usd().0, -100),
        ],
        periods: Vec::new(),
        full_detail: None,
    };
    let run = kernel_open(&mut k, &spec, "open-item-open", &["post", "migrate"])
        .unwrap()
        .run;
    post_chunk(
        &mut k,
        run,
        "open-item-chunk",
        vec![
            leg(fa_reference::Side::Debit, "1000", 100),
            leg(fa_reference::Side::Credit, "2000", 100),
        ],
    );
    let before = k.db.frontier().unwrap();
    let account = Some(account_vid(k.book.book_id, "1000"));
    let mut memo = OpenItemMemo::default();
    let read = |k: &Kernel, memo: &mut OpenItemMemo, at| {
        let literal = open_items_report(&k.db, &k.book, account, at).unwrap();
        let carried =
            open_items_report_carried(&k.db, &k.ctx().query(), &k.book, account, at, memo).unwrap();
        assert_eq!(literal, carried);
        carried
    };
    let hidden = read(&k, &mut memo, None);
    assert!(hidden.items.is_empty());
    let proposal = kernel_plan(&k, run, kind::FINALIZE, "open-item-finalize").unwrap();
    kernel_transition(&mut k, proposal, true).unwrap();
    let after = k.db.frontier().unwrap();
    let visible = read(&k, &mut memo, None);
    assert_eq!(visible.items.len(), 1);
    assert_eq!(visible.items[0].open, 100);
    assert_eq!(memo.read_work().snapshot_reads, 1);
    assert_eq!(read(&k, &mut memo, Some(before)), hidden);
    assert_eq!(memo.known_at(), Some(after));
    assert_eq!(read(&k, &mut memo, None), visible);
    assert_eq!(memo.read_work().snapshot_reads, 0);

    k = crash_and_reopen(k);
    assert_eq!(read(&k, &mut memo, None), visible);
    assert_eq!(
        memo.read_work().snapshot_reads,
        1,
        "a retired resident delta window is not reusable"
    );
    let cx = k.ctx();
    k.runtime
        .block_on(fa_journal::scratch::ensure_history(&mut k.db, &cx))
        .unwrap()
        .unwrap();
    assert_eq!(read(&k, &mut memo, None), visible);
    assert_eq!(read(&k, &mut memo, None), visible);
    assert_eq!(memo.read_work().snapshot_reads, 0);
    assert_eq!(k.db.frontier().unwrap(), after);
}
