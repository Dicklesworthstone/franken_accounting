//! The public authorized facade must reach the resident source memo only
//! after admitting its complete selected coordinate.

use super::*;
use crate::ReportSelection;
use fa_registers::{ReportHistoryWork, Served};

fn work(book: &Book) -> (Option<CommitSeq>, ReportHistoryWork) {
    with_store!(&book.store, core => {
        let memo = core.report_history.lock().unwrap();
        (memo.known_at(), memo.read_work())
    })
}

#[test]
fn resident_authorized_reports_share_history_and_keep_scoped_reads_literal() {
    let (mut book, usd, _, _) = certified_fixture();
    let principal = VId(1);
    let periods = vec!["FY2026-P03".to_string()];
    book.advance_registers(principal, &maintenance_capability(principal), &periods[0])
        .unwrap()
        .unwrap();
    assert_eq!(work(&book), (None, ReportHistoryWork::default()));
    let reader = Capability::embedded(principal, &["read"]).unwrap();
    let scoped = reader.clone().for_periods(&[&periods[0]]).unwrap();
    let restricted = book.read_scope(principal, &scoped).unwrap().unwrap();
    let (activity, served) = restricted
        .period_activity_served(&periods)
        .unwrap()
        .unwrap();
    assert_eq!(activity.unit_totals[&usd.0], (150_000, 150_000));
    assert!(matches!(served, Served::Literal(_)));
    assert_eq!(work(&book), (None, ReportHistoryWork::default()));

    let selected = book.head().unwrap();
    let whole = book.read_scope(principal, &reader).unwrap().unwrap();
    let (stock, served) = whole.trial_balance_served(&periods).unwrap().unwrap();
    assert!(matches!(served, Served::Maintained(_)));
    assert_eq!(stock.unit_totals[&usd.0], (150_000, 150_000));
    let (at, cold) = work(&book);
    assert_eq!(at, Some(selected));
    assert_eq!((cold.metadata_scans, cold.population_scans), (1, 1));
    assert_eq!(
        whole.period_activity_served(&periods).unwrap().unwrap().0,
        activity
    );
    assert_eq!(work(&book), (Some(selected), ReportHistoryWork::default()));

    // Scoped success and scoped refusal both leave the whole-book memo alone.
    assert_eq!(
        restricted
            .period_activity_served(&periods)
            .unwrap()
            .unwrap()
            .0,
        activity
    );
    assert!(restricted.trial_balance_served(&periods).unwrap().is_err());
    assert!(
        restricted
            .period_activity_served(&["FY2026-P04".into()])
            .unwrap()
            .is_err()
    );
    assert_eq!(work(&book), (Some(selected), ReportHistoryWork::default()));
    assert_eq!(book.head().unwrap(), selected);
}

#[test]
fn resident_report_memo_contention_keeps_the_exact_nonblocking_read() {
    let (mut book, _, _, _) = certified_fixture();
    let principal = VId(1);
    let periods = vec!["FY2026-P03".to_string()];
    book.advance_registers(principal, &maintenance_capability(principal), &periods[0])
        .unwrap()
        .unwrap();
    let reader = Capability::embedded(principal, &["read"]).unwrap();
    let scope = book.read_scope(principal, &reader).unwrap().unwrap();
    let expected = scope.trial_balance_served(&periods).unwrap().unwrap();
    let held = with_store!(&book.store, core => core.report_history.lock().unwrap());
    assert_eq!(
        scope.trial_balance_served(&periods).unwrap().unwrap(),
        expected
    );
    let activity = scope.period_activity_served(&periods).unwrap().unwrap();
    assert_eq!(activity.0.unit_totals, expected.0.unit_totals);
    drop(held);
    assert_eq!(
        scope.trial_balance_served(&periods).unwrap().unwrap(),
        expected
    );
    assert_eq!(work(&book).1, ReportHistoryWork::default());
}

#[test]
fn civil_date_convenience_reads_reuse_history_and_keep_exact_frontiers() {
    let (mut book, usd, day, _) = certified_fixture();
    let principal = VId(1);
    let through = DateDay::from_ymd(2026, 3, 31).unwrap();
    book.advance_registers(principal, &maintenance_capability(principal), "FY2026-P03")
        .unwrap()
        .unwrap();
    let selected = book.head().unwrap();
    let purposes = book.purposes();
    let expected = with_store!(&book.store, core => core.query(&purposes, |db, context| {
        Ok(fa_registers::balance_as_of(db, context, through, Some(selected))?)
    }))
    .unwrap();
    assert_eq!(book.balance_as_of(through, None).unwrap(), expected);
    let (at, cold) = work(&book);
    assert_eq!(at, Some(selected));
    assert_eq!((cold.metadata_scans, cold.population_scans), (1, 1));

    let reader = Capability::embedded(principal, &["read"]).unwrap();
    let scope = book.read_scope(principal, &reader).unwrap().unwrap();
    assert_eq!(scope.balance_as_of(through, None).unwrap().unwrap(), expected);
    assert_eq!(work(&book), (Some(selected), ReportHistoryWork::default()));

    // Both convenience routes remain exact without waiting for another
    // reader's optional memo, just like the explicit served API.
    let held = with_store!(&book.store, core => core.report_history.lock().unwrap());
    assert_eq!(book.balance_as_of(through, None).unwrap(), expected);
    assert_eq!(scope.balance_as_of(through, None).unwrap().unwrap(), expected);
    drop(held);

    post_rent(&mut book, usd, principal, day, b"convenience-as-of-tail", 150_000)
        .unwrap()
        .unwrap();
    let head = book.head().unwrap();
    let current = book.balance_as_of(through, None).unwrap();
    assert_eq!(current.known_at, head);
    assert_eq!(current.unit_totals[&usd.0], (300_000, 300_000));
    let (at, suffix) = work(&book);
    assert_eq!(at, Some(head));
    assert_eq!((suffix.metadata_scans, suffix.population_scans, suffix.snapshot_rows), (0, 0, 0));
    assert_eq!(suffix.entries_decoded, 1);
    assert!(suffix.delta_rows > 0);

    assert_eq!(book.balance_as_of(through, Some(selected)).unwrap(), expected);
    assert_eq!(work(&book).0, Some(head), "historical reads do not evict the newer memo");
    assert_eq!(book.head().unwrap(), head, "reads never publish or repair");
}

#[test]
fn civil_date_convenience_caveats_precede_any_register_history_access() {
    let (mut book, usd, _, _) = certified_fixture();
    let principal = VId(1);
    let through = DateDay::from_ymd(2026, 3, 31).unwrap();
    book.advance_registers(principal, &maintenance_capability(principal), "FY2026-P03")
        .unwrap()
        .unwrap();
    let reader = Capability::embedded(principal, &["read"]).unwrap();
    let limited = reader.clone().effective_through(through);
    let restricted = book.read_scope(principal, &limited).unwrap().unwrap();
    let allowed = restricted.balance_as_of(through, None).unwrap().unwrap();
    assert_eq!(allowed.unit_totals[&usd.0], (150_000, 150_000));
    assert_eq!(work(&book), (None, ReportHistoryWork::default()));
    let refusal = restricted
        .balance_as_of(DateDay::from_ymd(2026, 4, 1).unwrap(), None)
        .unwrap()
        .unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-011", 7));
    assert_eq!(work(&book), (None, ReportHistoryWork::default()));

    // A later whole-book reader can populate the memo; the admitted narrow
    // convenience read must still leave even its work counters untouched.
    assert_eq!(book.balance_as_of(through, None).unwrap(), allowed);
    let warmed = work(&book);
    assert_eq!(warmed.1.metadata_scans, 1);
    assert_eq!(restricted.balance_as_of(through, None).unwrap().unwrap(), allowed);
    assert_eq!(work(&book), warmed);
    let per_period = reader.for_periods(&["FY2026-P03"]).unwrap();
    assert!(book
        .read_scope(principal, &per_period)
        .unwrap()
        .unwrap()
        .balance_as_of(through, None)
        .unwrap()
        .is_err());
    assert_eq!(work(&book), warmed);
}

fn open_item_work(
    book: &Book,
) -> (
    Option<CommitSeq>,
    fa_registers::open_items::OpenItemReadWork,
) {
    with_store!(&book.store, core => {
        let memo = core.open_item_history.lock().unwrap();
        (memo.known_at(), memo.read_work())
    })
}

#[test]
fn resident_open_item_facade_preserves_admission_and_does_not_wait_for_its_memo() {
    let (book, _, _, _) = certified_fixture();
    let principal = VId(1);
    let reader = Capability::embedded(principal, &["read"]).unwrap();
    let scoped = reader.clone().for_periods(&["FY2026-P03"]).unwrap();
    let selection = ReportSelection::OpenItems { account: None };
    assert!(
        book.read_scope(principal, &scoped)
            .unwrap()
            .unwrap()
            .admit_report(&selection, None)
            .unwrap()
            .is_err()
    );
    assert_eq!(
        open_item_work(&book).0,
        None,
        "refused scoped reads cannot populate a whole-book memo"
    );

    let at = book
        .read_scope(principal, &reader)
        .unwrap()
        .unwrap()
        .admit_report(&selection, None)
        .unwrap()
        .unwrap();
    let expected = book.open_items_report(None, Some(at)).unwrap();
    assert_eq!(open_item_work(&book).0, Some(at));
    assert_eq!(open_item_work(&book).1.snapshot_reads, 1);
    assert_eq!(book.open_items(None, Some(at)).unwrap(), expected.items);
    assert_eq!(open_item_work(&book).1.snapshot_reads, 0);
    assert_eq!(open_item_work(&book).1.entries_decoded, 0);

    let held = with_store!(&book.store, core => core.open_item_history.lock().unwrap());
    assert_eq!(book.open_items_report(None, Some(at)).unwrap(), expected);
    assert_eq!(book.open_items(None, Some(at)).unwrap(), expected.items);
    drop(held);
    assert_eq!(book.open_items_report(None, Some(at)).unwrap(), expected);
    assert_eq!(open_item_work(&book).1.snapshot_reads, 0);
    assert_eq!(book.head().unwrap(), at);
}

#[test]
fn resident_effective_open_item_facade_shares_aging_and_keeps_nonblocking_fallback() {
    let (book, _, _, _) = certified_fixture();
    let through = DateDay::from_ymd(2026, 3, 31).unwrap();
    let at = book.head().unwrap();
    let buckets = crate::AgingBuckets::thirty_day();
    let snapshot = book.open_items_as_of(None, through, Some(at)).unwrap();
    assert_eq!(open_item_work(&book).0, Some(at));
    assert_eq!(open_item_work(&book).1.snapshot_reads, 1);
    let literal = with_store!(&book.store, core => {
        fa_registers::open_items::aging::effective_date_aging(
            &core.db,
            core.context(),
            None,
            through,
            Some(at),
            &buckets,
        ).unwrap()
    });
    let aged = book
        .effective_date_aging(None, through, Some(at), &buckets)
        .unwrap();
    assert_eq!(aged, literal);
    assert_eq!(open_item_work(&book).1.snapshot_reads, 0);
    assert_eq!(open_item_work(&book).1.entries_decoded, 0);

    // A resident optimization may neither wait on another reader nor change
    // the observed amounts when its disposable memo is unavailable.
    let held = with_store!(&book.store, core => core.open_item_history.lock().unwrap());
    assert_eq!(
        book.open_items_as_of(None, through, Some(at)).unwrap(),
        snapshot
    );
    assert_eq!(
        book.effective_date_aging(None, through, Some(at), &buckets)
            .unwrap(),
        aged
    );
    drop(held);
    assert_eq!(
        book.effective_date_aging(None, through, Some(at), &buckets)
            .unwrap(),
        aged
    );
    assert_eq!(open_item_work(&book).1.snapshot_reads, 0);
    assert_eq!(book.head().unwrap(), at);
}
