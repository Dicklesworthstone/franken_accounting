use super::test_support::*;
use super::*;

#[test]
fn whole_portfolio_equals_single_account_reads_and_includes_empty_leaves() {
    let mut h = Harness::new();
    let invoice = h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    h.post(
        "payment",
        "2026-03-15",
        h.usd,
        ("cash", "ar"),
        40,
        Some(invoice),
    );
    h.post(
        "eur",
        "2026-03-01",
        h.eur,
        ("ar", "sales"),
        (1_i128 << 90) + 7,
        None,
    );
    h.post("bill", "2026-03-02", h.usd, ("expense", "ap"), 19, None);
    let at = h.head();
    let report = h.report(&h.request());
    assert_eq!(report.request().known_at, Some(at));
    assert_eq!(report.accounts().len(), 6);
    assert!(report.is_complete_and_reconciled());
    assert!(!report.has_pending_reservations());
    assert!(report.uncovered_accounts().is_empty());
    assert!(
        report
            .accounts()
            .windows(2)
            .all(|pair| pair[0].account().code < pair[1].account().code)
    );
    for account in report.accounts() {
        let single = h
            .book
            .reconcile_effective_date_aging(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &AgingReconciliationRequest {
                    account: account.account().vid,
                    effective_through: report.request().effective_through,
                    known_at: Some(at),
                    buckets: report.request().buckets.clone(),
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(*account, single);
    }
    let idle = report
        .accounts()
        .iter()
        .find(|a| a.account().code == "idle")
        .unwrap();
    assert!(idle.rows().is_empty());
    assert!(idle.is_reconciled());
    assert_eq!(
        h.head(),
        at,
        "the portfolio is a read, not a journal publication"
    );
    assert_eq!(
        report.canonical_bytes().unwrap(),
        h.report(&h.request()).canonical_bytes().unwrap()
    );
}

#[test]
fn selection_order_is_canonical_and_balanced_subsets_never_claim_whole_book_coverage() {
    let h = Harness::new();
    let mut request = h.request();
    request.scope = AgingAccountScope::Selected(vec![h.id("sales"), h.id("ar")]);
    let one = h.report(&request);
    request.scope = AgingAccountScope::Selected(vec![h.id("ar"), h.id("sales")]);
    let two = h.report(&request);
    assert_eq!(one, two);
    assert_eq!(
        one.canonical_bytes().unwrap(),
        two.canonical_bytes().unwrap()
    );
    assert!(one.is_reconciled());
    assert!(!one.is_complete_and_reconciled());
    assert_eq!(one.uncovered_accounts().len(), 4);
    request.scope = AgingAccountScope::Selected(Vec::new());
    let none = h.report(&request);
    assert!(none.accounts().is_empty());
    assert!(none.is_reconciled());
    assert!(!none.is_complete());
    assert_eq!(none.uncovered_accounts().len(), 6);
}

#[test]
fn both_time_coordinates_and_chart_coverage_survive_later_publications_and_reopen() {
    let mut h = Harness::new();
    let invoice = h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    let mut request = h.request();
    request.known_at = Some(h.head());
    let original = h.report(&request);
    h.post(
        "later-payment",
        "2026-03-20",
        h.usd,
        ("cash", "ar"),
        40,
        Some(invoice),
    );
    h.add_leaf("new-leaf");
    let h = h.reopen();
    assert_eq!(h.report(&request), original);
    let mut early = h.request();
    early.effective_through = day("2026-03-10");
    let early = h.report(&early);
    let late = h.report(&h.request());
    assert_eq!(early.accounts().len(), 7);
    let ar_net = |p: &AgingPortfolio| {
        p.accounts()
            .iter()
            .find(|a| a.account().code == "ar")
            .unwrap()
            .rows()[0]
            .open_net
    };
    assert_eq!(ar_net(&early), 100);
    assert_eq!(ar_net(&late), 60);
    assert!(early.is_complete_and_reconciled());
    assert!(late.is_complete_and_reconciled());
}

#[test]
fn invalid_selection_and_absent_authority_refuse_without_publication() {
    let h = Harness::new();
    let at = h.head();
    for scope in [
        AgingAccountScope::Selected(vec![h.id("ar"), h.id("ar")]),
        AgingAccountScope::Selected(vec![VId(999)]),
        AgingAccountScope::Selected(vec![h.id("summary")]),
        AgingAccountScope::Selected(vec![VId(1); MAX_AGING_PORTFOLIO_ACCOUNTS + 1]),
    ] {
        let request = AgingPortfolioRequest {
            scope,
            ..h.request()
        };
        assert!(
            h.book
                .reconcile_aging_portfolio(&h.cx(), PRINCIPAL, &cap(&["read"]), &request)
                .unwrap()
                .is_err()
        );
    }
    let request = AgingPortfolioRequest {
        known_at: Some(CommitSeq(at.0 + 1)),
        ..h.request()
    };
    assert!(
        h.book
            .reconcile_aging_portfolio(&h.cx(), PRINCIPAL, &cap(&["read"]), &request)
            .unwrap()
            .is_err()
    );
    let request = AgingPortfolioRequest {
        buckets: AgingBuckets::new((0..129).collect()).unwrap(),
        ..h.request()
    };
    assert!(
        h.book
            .reconcile_aging_portfolio(&h.cx(), PRINCIPAL, &cap(&["read"]), &request)
            .unwrap()
            .is_err()
    );
    assert!(
        h.book
            .reconcile_aging_portfolio(&h.cx(), PRINCIPAL, &cap(&["post"]), &h.request())
            .unwrap()
            .is_err()
    );
    assert!(
        h.book
            .reconcile_aging_portfolio(&h.cx(), VId(99), &cap(&["read"]), &h.request())
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), at);
}

#[test]
fn offsetting_account_discrepancies_are_not_cancelled_and_pending_is_separate() {
    let mut h = Harness::new();
    h.post("ar", "2026-03-01", h.usd, ("ar", "sales"), 10, None);
    h.post("cash", "2026-03-01", h.usd, ("cash", "sales"), 10, None);
    let (chart, aging, mut control) = h.sources();
    control
        .rows
        .iter_mut()
        .find(|r| r.account == h.id("ar"))
        .unwrap()
        .debits += 1;
    let cash = control
        .rows
        .iter_mut()
        .find(|r| r.account == h.id("cash"))
        .unwrap();
    cash.debits -= 1;
    cash.debits_pending = 4;
    cash.credits_pending = 4;
    let request = normalize(&h.request(), h.head()).unwrap();
    let ids = selected(&chart, &request.scope).unwrap();
    let report = partition(
        h.book.context().book_id,
        request,
        chart.accounts(),
        &ids,
        aging,
        control,
        &h.book.context().units,
    )
    .unwrap()
    .unwrap();
    let differences: Vec<_> = report
        .accounts()
        .iter()
        .flat_map(|a| a.rows())
        .map(|r| r.difference)
        .collect();
    assert_eq!(differences.iter().sum::<i128>(), 0);
    assert_eq!(differences.iter().filter(|n| **n != 0).count(), 2);
    assert!(report.is_complete());
    assert!(!report.is_reconciled());
    assert!(!report.is_complete_and_reconciled());
    assert!(
        report.has_pending_reservations(),
        "opposite reservations must not be netted away"
    );
}

#[test]
fn invalid_rows_in_omitted_accounts_fail_closed() {
    let mut h = Harness::new();
    h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 100, None);
    let (chart, aging, control) = h.sources();
    let request = normalize(
        &AgingPortfolioRequest {
            scope: AgingAccountScope::Selected(vec![h.id("idle")]),
            ..h.request()
        },
        h.head(),
    )
    .unwrap();
    let ids = selected(&chart, &request.scope).unwrap();
    let mut duplicate = control.clone();
    duplicate.rows.push(duplicate.rows[0].clone());
    let mut negative = control.clone();
    negative.rows[0].debits = -1;
    let mut unknown = control.clone();
    unknown.rows[0].unit_id = u32::MAX;
    for bad in [duplicate, negative, unknown] {
        assert!(
            partition(
                h.book.context().book_id,
                request.clone(),
                chart.accounts(),
                &ids,
                aging.clone(),
                bad,
                &h.book.context().units
            )
            .is_err()
        );
    }
    let mut bad = aging;
    bad.totals.push(bad.totals[0].clone());
    assert!(
        partition(
            h.book.context().book_id,
            request,
            chart.accounts(),
            &ids,
            bad,
            control,
            &h.book.context().units
        )
        .is_err()
    );
}

#[test]
fn per_cell_difference_overflow_is_refused_not_wrapped() {
    let mut h = Harness::new();
    h.post("invoice", "2026-03-01", h.usd, ("ar", "sales"), 1, None);
    let (chart, mut aging, mut control) = h.sources();
    let row = control
        .rows
        .iter_mut()
        .find(|r| r.account == h.id("ar"))
        .unwrap();
    row.debits = i128::MAX;
    row.credits = 0;
    let total = aging
        .totals
        .iter_mut()
        .find(|r| r.account == h.id("ar"))
        .unwrap();
    total.amounts.debits = 0;
    total.amounts.credits = i128::MAX;
    let request = normalize(&h.request(), h.head()).unwrap();
    let ids = selected(&chart, &request.scope).unwrap();
    assert!(matches!(
        partition(
            h.book.context().book_id,
            request,
            chart.accounts(),
            &ids,
            aging,
            control,
            &h.book.context().units
        ),
        Err(BookError::Registers(RegisterError::Overflow))
    ));
}
