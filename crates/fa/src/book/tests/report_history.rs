//! The public authorized facade must reach the resident source memo only
//! after admitting its complete selected coordinate.

use super::*;
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
