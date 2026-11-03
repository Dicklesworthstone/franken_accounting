//! Retained legacy sources may target real bank and credit-line accounts
//! without stripping their bounds. Native activation, not invisible staging,
//! is the point at which imported money affects availability.

use super::*;

const LIVE_PERIOD: &str = "FY2026-P07";

fn fixture(bounds: &str) -> Fixture {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = loop {
        let path = std::env::temp_dir().join(format!(
            "fa-limited-legacy-migration-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => break path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create retained fixture {}: {error}", path.display()),
        }
    };
    let book = dir.join("book");
    ok(
        &book,
        &[
            "book",
            "create",
            "--name",
            "Limited legacy bank",
            "--base-unit",
            "USD",
            "--opening-date",
            "2026-07-01",
        ],
    );
    let mut fixture = Fixture {
        dir,
        book,
        unit: "USD".into(),
        source: String::new(),
        trial_balance: String::new(),
        run_vid: String::new(),
        format: "quickbooks-csv".into(),
        opening_entries: None,
        entry_periods: None,
        period_trial_balances: Vec::new(),
    };
    let chart = fixture.file(
        "chart.json",
        &format!(
            r#"{{"accounts":[{{"code":"1000","name":"Bounded bank","type":"Asset","unit":"USD",{bounds}}},{{"code":"3000","name":"Opening equity","type":"Equity","unit":"USD"}}]}}"#
        ),
    );
    ok(&fixture.book, &["chart", "import", &chart]);
    ok(
        &fixture.book,
        &["period", "create", "--fiscal-year", "2026"],
    );
    ok(&fixture.book, &["period", "open", LIVE_PERIOD]);
    fixture.source = fixture.document("original-bank-source.csv", QB, "Spreadsheet");
    fixture.trial_balance = fixture.document(
        "independent-bank-trial-balance.csv",
        &tb_document(OPENING, &[("1000", "125.50"), ("3000", "-125.50")]),
        "Spreadsheet",
    );
    fixture.run_vid = fixture.open_run("limited-bank-import", "125.50");
    fixture
}

fn assert_availability(fixture: &Fixture, net: &str, generation: i128) -> Json {
    let result = ok(&fixture.book, &["verify", "availability"]);
    assert_eq!(integer(data(&result), "accounts_checked"), 1);
    assert!(rows(data(&result), "drift").is_empty());
    let accounts = rows(data(&result), "accounts");
    assert_eq!(accounts.len(), 1);
    let cash = &accounts[0];
    assert_eq!(text(cash, "account"), "1000");
    assert_eq!(cash.get("period"), Some(&Json::Null));
    assert_eq!(text(cash, "net"), net);
    assert_eq!(text(cash, "pending_in"), "0.00 USD");
    assert_eq!(text(cash, "pending_out"), "0.00 USD");
    assert_eq!(integer(cash, "generation"), generation);
    cash.clone()
}

fn stage_source(fixture: &Fixture) -> (String, Vec<(String, String)>) {
    let prepared = fixture.prepare();
    let package = text(data(&prepared), "package_oid").to_string();
    let chunks = rows(data(&prepared), "chunks");
    assert_eq!(chunks.len(), 2, "both original journal entries survive");
    let mut approvals = Vec::new();
    for (index, chunk) in chunks.iter().enumerate() {
        let digest = text(chunk, "proposal_digest");
        let first = fixture.approve(digest, "bank-source-reviewer-one");
        let second = fixture.approve(digest, "bank-source-reviewer-two");
        let staged = fixture.stage(&package, index, &[&first, &second]);
        assert_eq!(
            integer(data(&staged), "recorded_count"),
            (index + 1) as i128
        );
        assert_eq!(fixture.cash(None), "0.00 USD");
        assert_availability(fixture, "0.00 USD", 0);
        approvals.push((first, second));
    }
    let shown = fixture.show(&package);
    assert_eq!(data(&shown).get("ties_out"), Some(&Json::Bool(true)));
    assert_eq!(text(data(&shown), "run_state"), "Open");
    (package, approvals)
}

fn finalize_plan(fixture: &Fixture) -> (String, String, String) {
    let path = fixture.dir.join("activate.plan").display().to_string();
    let planned = ok(
        &fixture.book,
        &["migrate", "finalize", &fixture.run_vid, "--plan-out", &path],
    );
    let digest = text(data(&planned), "proposal_digest");
    let first = fixture.approve(digest, "bank-activation-reviewer-one");
    let second = fixture.approve(digest, "bank-activation-reviewer-two");
    (path, first, second)
}

fn activate(fixture: &Fixture, plan: &(String, String, String)) -> (i32, Json) {
    run(
        &fixture.book,
        &[
            "migrate",
            "finalize",
            &fixture.run_vid,
            "--plan",
            &plan.0,
            "--approval",
            &plan.1,
            "--approval",
            &plan.2,
        ],
    )
}

fn withdrawal(fixture: &Fixture, name: &str, amount: &str) -> String {
    fixture.file(
        &format!("{name}.json"),
        &format!(
            r#"{{"effective_date":"2026-07-10","idempotency_key":"{name}","legs":[{{"side":"debit","account":"3000","amount":"{amount} USD"}},{{"side":"credit","account":"1000","amount":"{amount} USD"}}]}}"#
        ),
    )
}

fn post(fixture: &Fixture, path: &str) -> (i32, Json) {
    run(
        &fixture.book,
        &["post", "--intent", path, "--evidence", &fixture.source],
    )
}

fn assert_refused_without_publication(
    fixture: &Fixture,
    before: i128,
    result: (i32, Json),
    refusal: &str,
) {
    assert_eq!(result.0, 3, "{}", result.1.render());
    assert_eq!(text(data(&result.1), "refusal_id"), refusal);
    assert_eq!(head(&fixture.book), before, "{}", result.1.render());
}

#[test]
fn limited_account_import_activates_once_and_preserves_posting_bounds() {
    let fixture = fixture(r#""lower_bound":"0.00""#);
    let (package, approvals) = stage_source(&fixture);
    let one_cent = withdrawal(&fixture, "spend-one-cent", "0.01");
    // Durable imported chunks are not yet available to spend.
    let before = head(&fixture.book);
    assert_refused_without_publication(&fixture, before, post(&fixture, &one_cent), "FA-REF-090");
    let plan = finalize_plan(&fixture);
    let before_finalize = head(&fixture.book);
    let (status, finalized) = activate(&fixture, &plan);
    assert_eq!(status, 0, "{}", finalized.render());
    assert_eq!(text(data(&finalized), "to"), "Finalized");
    assert_eq!(fixture.cash(None), "125.50 USD");
    assert_eq!(fixture.cash(Some(before_finalize)), "0.00 USD");
    let cash = assert_availability(&fixture, "125.50 USD", 1);
    assert_eq!(text(&cash, "lower_bound"), "0.00 USD");
    assert_eq!(cash.get("upper_bound"), Some(&Json::Null));

    // Both activation and source-chunk retries preserve the one movement.
    let activated = head(&fixture.book);
    let (status, retried) = activate(&fixture, &plan);
    assert_eq!(status, 0, "{}", retried.render());
    assert_eq!(
        data(&retried).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    let retried_chunk = fixture.stage(&package, 0, &[&approvals[0].0, &approvals[0].1]);
    assert_eq!(
        data(&retried_chunk).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(head(&fixture.book), activated);
    assert_availability(&fixture, "125.50 USD", 1);

    let spend = withdrawal(&fixture, "spend-imported-cash", "125.50");
    let (status, posted) = post(&fixture, &spend);
    assert_eq!(status, 0, "{}", posted.render());
    assert_eq!(fixture.cash_at(LIVE_PERIOD, None), "0.00 USD");
    assert_availability(&fixture, "0.00 USD", 2);
    let spent = head(&fixture.book);
    let (status, repeated) = post(&fixture, &spend);
    assert_eq!(status, 0, "{}", repeated.render());
    assert_eq!(text(&repeated, "event"), "recorded");
    assert_eq!(head(&fixture.book), spent);
    assert_refused_without_publication(&fixture, spent, post(&fixture, &one_cent), "FA-REF-090");
    assert_availability(&fixture, "0.00 USD", 2);
    for period in [OPENING, LIVE_PERIOD] {
        ok(&fixture.book, &["registers", "advance", "--period", period]);
        ok(&fixture.book, &["verify", "registers", "--period", period]);
    }
}

#[test]
fn limited_account_import_checks_current_upper_bound_at_atomic_finalization() {
    // An upper-only bank exposure ceiling permits a negative balance. The
    // retained opening source is 125.50, above that ceiling in isolation.
    let fixture = fixture(r#""upper_bound":"100.00""#);
    let (package, _) = stage_source(&fixture);
    let plan = finalize_plan(&fixture);
    let before_finalize = head(&fixture.book);
    for _ in 0..2 {
        assert_refused_without_publication(
            &fixture,
            before_finalize,
            activate(&fixture, &plan),
            "FA-REF-091",
        );
        assert_eq!(text(data(&fixture.show(&package)), "run_state"), "Open");
        assert_eq!(fixture.cash(None), "0.00 USD");
        assert_availability(&fixture, "0.00 USD", 0);
    }

    // A separately evidenced live withdrawal changes current availability.
    // Retrying the exact approved run now fits: -25.50 + 125.50 = 100.00.
    // Nothing edits the source, trial balance, limit, proposal or approvals.
    let spend = withdrawal(&fixture, "live-withdrawal-before-activation", "25.50");
    let (status, posted) = post(&fixture, &spend);
    assert_eq!(status, 0, "{}", posted.render());
    assert_availability(&fixture, "-25.50 USD", 1);
    let before_retry = head(&fixture.book);
    let (status, finalized) = activate(&fixture, &plan);
    assert_eq!(status, 0, "{}", finalized.render());
    assert_eq!(text(data(&finalized), "to"), "Finalized");
    assert_eq!(fixture.cash(None), "125.50 USD");
    assert_eq!(fixture.cash_at(LIVE_PERIOD, None), "100.00 USD");
    assert_eq!(fixture.cash(Some(before_retry)), "0.00 USD");
    let cash = assert_availability(&fixture, "100.00 USD", 2);
    assert_eq!(text(&cash, "upper_bound"), "100.00 USD");
    assert_eq!(cash.get("lower_bound"), Some(&Json::Null));
    let activated = head(&fixture.book);
    let (status, repeated) = activate(&fixture, &plan);
    assert_eq!(status, 0, "{}", repeated.render());
    assert_eq!(
        data(&repeated).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(head(&fixture.book), activated);
    assert_availability(&fixture, "100.00 USD", 2);
    let over = fixture.file(
        "exposure-over-limit.json",
        r#"{"effective_date":"2026-07-10","idempotency_key":"exposure-over-limit","legs":[{"side":"debit","account":"1000","amount":"0.01 USD"},{"side":"credit","account":"3000","amount":"0.01 USD"}]}"#,
    );
    assert_refused_without_publication(&fixture, activated, post(&fixture, &over), "FA-REF-091");
    assert_availability(&fixture, "100.00 USD", 2);
}
