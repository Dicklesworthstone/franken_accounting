//! Real binary bank intake/reconciliation: retained source and parser closure,
//! atomicity, exact signs, stable repeats, and refusal before source consumption.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::authority::{LaunchAuthority, LaunchProfile};
use fa_cli::cli::{Files, Stdin};
use fa_cli::entry::fa_with_authority;
use fa_cli::json::{self, Json};

fn data(value: &Json) -> &Json {
    value.get("data").expect("robot data")
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value.get(key).and_then(Json::as_str).expect(key)
}

fn integer(value: &Json, key: &str) -> i128 {
    match value.get(key).expect(key) {
        Json::Int(value) => *value,
        other => panic!("{key} is not an integer: {other:?}"),
    }
}

fn rows<'a>(value: &'a Json, key: &str) -> &'a [Json] {
    match value.get(key).expect(key) {
        Json::Arr(rows) => rows,
        other => panic!("{key} is not an array: {other:?}"),
    }
}

fn assert_progress(
    output: &Json,
    expected: [(&str, &str); 6],
    remaining_count: i128,
    all_statement_lines_confirmed: bool,
    closing_balances_equal: bool,
) {
    let report = data(output);
    let progress = report.get("progress").expect("reconciliation progress");
    for (name, (inflow, outflow)) in [
        "confirmed",
        "occupied",
        "remaining",
        "proposed",
        "unmatched",
        "outstanding",
    ]
    .into_iter()
    .zip(expected)
    {
        let flow = progress.get(name).expect(name);
        assert_eq!(
            text(flow, "inflow"),
            format!("{inflow} USD"),
            "{name} inflow"
        );
        assert_eq!(
            text(flow, "outflow"),
            format!("{outflow} USD"),
            "{name} outflow"
        );
    }
    assert_eq!(integer(report, "remaining_count"), remaining_count);
    assert_eq!(
        progress.get("all_statement_lines_confirmed"),
        Some(&Json::Bool(all_statement_lines_confirmed))
    );
    assert_eq!(
        progress.get("closing_balances_equal"),
        Some(&Json::Bool(closing_balances_equal))
    );
}

fn run(book: &Path, args: &[&str]) -> (i32, Json) {
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{args:?}: {stdout}\n{stderr}");
    fa_cli::verbs::registry()
        .unwrap()
        .check_line(lines[0])
        .unwrap_or_else(|error| panic!("{args:?}: {error}\n{stdout}\n{stderr}"));
    (
        output.status.code().unwrap(),
        json::parse(lines[0]).unwrap(),
    )
}

fn ok(book: &Path, args: &[&str]) -> Json {
    let (status, output) = run(book, args);
    assert_eq!(status, 0, "{args:?}: {}", output.render());
    output
}

fn certified_events(book: &Path, args: &[&str]) -> Vec<Json> {
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{args:?}: {stdout}\n{stderr}");
    stdout
        .lines()
        .map(|line| {
            fa_cli::verbs::registry()
                .unwrap()
                .check_line(line)
                .unwrap_or_else(|error| panic!("{args:?}: {error}\n{stdout}"));
            json::parse(line).unwrap()
        })
        .collect()
}

// Replaying the original governed BankStatement is an explicit owner choice;
// the ordinary reader and every launch-bound template retain their ceilings.
fn run_privileged(book: &Path, args: &[&str]) -> (i32, Json) {
    let mut granted = args.to_vec();
    granted.extend(["--grant", "privileged"]);
    run(book, &granted)
}

fn ok_privileged(book: &Path, args: &[&str]) -> Json {
    let (status, output) = run_privileged(book, args);
    assert_eq!(status, 0, "{args:?}: {}", output.render());
    output
}

fn head(book: &Path) -> i128 {
    let output = ok(book, &["book", "info"]);
    integer(output.get("coordinate").unwrap(), "known_at")
}

/// AccessEvents recorded after `since` (fa-7dw): a read-only token's command
/// records one before it observes the book, refused or not.
fn access_events_since(book: &Path, since: i128) -> i128 {
    let log = ok(book, &["access", "log", "--since", &since.to_string()]);
    integer(log.get("data").unwrap(), "count")
}

struct Fixture {
    dir: PathBuf,
    book: PathBuf,
    evidence: String,
}

impl Fixture {
    fn new() -> Self {
        Self::with_chart(
            r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"},{"code":"6000","name":"Expenses","type":"Expense","unit":"USD"}]}"#,
        )
    }

    fn with_chart(chart_json: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = loop {
            let dir = std::env::temp_dir().join(format!(
                "fa-bank-cli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&dir) {
                Ok(()) => break dir,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create retained fixture {}: {error}", dir.display()),
            }
        };
        let book = dir.join("book");
        ok(&book, &["book", "create", "--name", "Bank intake"]);
        let chart = dir.join("chart.json");
        std::fs::write(&chart, chart_json).unwrap();
        ok(&book, &["chart", "import", chart.to_str().unwrap()]);
        ok(&book, &["period", "create", "--fiscal-year", "2026"]);
        ok(&book, &["period", "open", "FY2026-P03"]);
        let source = dir.join("source.txt");
        std::fs::write(
            &source,
            "Bank workflow source receipt for posted transactions.",
        )
        .unwrap();
        let document = ok(
            &book,
            &[
                "document",
                "add",
                source.to_str().unwrap(),
                "--kind",
                "Receipt",
                "--grade",
                "HumanUpload",
            ],
        );
        Self {
            dir,
            book,
            evidence: text(data(&document), "oid").into(),
        }
    }

    fn file(&self, name: &str, content: &str) -> String {
        let path = self.dir.join(name);
        std::fs::write(&path, content).unwrap();
        path.display().to_string()
    }

    fn post(&self, key: &str, date: &str, side: &str, amount: &str, reference: &str) -> Json {
        let (other_side, other_account) = if side == "debit" {
            ("credit", "4000")
        } else {
            ("debit", "6000")
        };
        let path = self.file(&format!("{key}.json"), &format!(
            r#"{{"effective_date":"{date}","idempotency_key":"{key}","legs":[{{"side":"{side}","account":"1000","amount":"{amount} USD","memo":"{reference}"}},{{"side":"{other_side}","account":"{other_account}","amount":"{amount} USD"}}]}}"#));
        ok(
            &self.book,
            &["post", "--intent", &path, "--evidence", &self.evidence],
        )
    }

    fn import(&self, name: &str, format: &str, contents: &str) -> Json {
        let path = self.file(name, contents);
        ok(
            &self.book,
            &[
                "bank",
                "import",
                &path,
                "--bank-format",
                format,
                "--account",
                "1000",
            ],
        )
    }
}

const CSV_HEADER: &str = "sequence_number,instrument_id,currency,statement_date,opening_balance,closing_balance,booking_date,value_date,side,amount,counterparty,reference\n";

fn statement_csv(closing: &str) -> String {
    format!(
        "{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,{closing},2026-03-05,2026-03-05,CRDT,150.00,Customer,SALE-1\n1,BANK-123,USD,2026-03-31,0.00,{closing},2026-03-06,2026-03-06,DBIT,50.00,Vendor,BILL-1\n1,BANK-123,USD,2026-03-31,0.00,{closing},2026-03-07,2026-03-07,DBIT,5.00,Bank,FEE-1\n"
    )
}

fn confirmation_args(matched: &Json, index: usize, confirmer: &str) -> Vec<String> {
    let report = data(matched);
    let proposal = &rows(report, "proposals")[index];
    let mut args = vec![
        "bank".into(),
        "confirm".into(),
        "--import".into(),
        text(report, "manifest_oid").into(),
        "--line-ordinal".into(),
        integer(proposal, "line_ordinal").to_string(),
        "--proposal-digest".into(),
        text(proposal, "proposal_digest").into(),
        "--source-known-at".into(),
        integer(report, "known_at").to_string(),
        "--proposer".into(),
        text(proposal, "proposer").into(),
        "--as".into(),
        confirmer.into(),
    ];
    // Omit the default deliberately: a three-day proposal must be usable with
    // the CLI default, while a narrower selection carries its original window.
    let window = integer(report, "date_window");
    if window != 3 {
        args.extend(["--date-window".into(), window.to_string()]);
    }
    args
}

fn confirm_selection(book: &Path, args: &[String]) -> Json {
    ok_privileged(book, &args.iter().map(String::as_str).collect::<Vec<_>>())
}

fn reconciliation_args(manifest: &str, reviewed: i128) -> Vec<String> {
    vec![
        "bank".into(),
        "reconcile".into(),
        "--import".into(),
        manifest.into(),
        "--source-known-at".into(),
        reviewed.to_string(),
        "--as".into(),
        "statement-reviewer".into(),
        "--yes".into(),
    ]
}

fn reconcile_selection(book: &Path, args: &[String]) -> Json {
    ok_privileged(book, &args.iter().map(String::as_str).collect::<Vec<_>>())
}

fn reconciliation_state(status: &Json) -> &Json {
    let states = rows(data(status), "reconciliations");
    assert_eq!(states.len(), 1, "one immutable statement close: {status:?}");
    &states[0]
}

#[test]
fn exact_bank_reconciliation_carries_opening_cash_and_survives_reopen_retry_and_drift() {
    let f = Fixture::new();
    ok(&f.book, &["period", "open", "FY2026-P02"]);
    f.post("opening-cash", "2026-02-28", "debit", "500.00", "OPENING");
    f.post(
        "statement-sale",
        "2026-03-10",
        "debit",
        "100.00",
        "MIDMONTH",
    );
    // Already recorded activity after the statement date must be excluded
    // even though it belongs to the same accounting period.
    f.post("after-statement", "2026-03-25", "debit", "25.00", "LATER");
    let imported = f.import("midmonth.csv", "csv", &format!(
        "{CSV_HEADER}1,BANK-MIDMONTH,USD,2026-03-15,500.00,600.00,2026-03-10,2026-03-10,CRDT,100.00,Private customer,MIDMONTH\n"
    ));
    let manifest = text(data(&imported), "manifest_oid");
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    let confirmed = confirm_selection(&f.book, &confirmation_args(&matched, 0, "cash-reviewer"));
    let reviewed = head(&f.book);
    let args = reconciliation_args(manifest, reviewed);
    let argv: Vec<_> = args.iter().map(String::as_str).collect();
    let before_tb = ok(&f.book, &["tb", "--as-of", "2026-03-15"]);

    let without_yes: Vec<_> = argv.iter().copied().filter(|arg| *arg != "--yes").collect();
    let (exit, refused) = run_privileged(&f.book, &without_yes);
    assert_eq!(exit, 7, "{refused:?}");
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-007");
    assert_eq!(head(&f.book), reviewed);
    for selector in [None, Some("HEAD"), Some("2026-03-15T00:00:00Z")] {
        let mut invalid = vec!["bank", "reconcile", "--import", manifest, "--yes"];
        if let Some(selector) = selector {
            invalid.extend(["--source-known-at", selector]);
        }
        let (exit, refused) = run_privileged(&f.book, &invalid);
        assert_eq!(exit, 2, "{selector:?}: {refused:?}");
        assert_eq!(head(&f.book), reviewed);
    }
    let (exit, refused) = run(&f.book, &argv);
    assert_eq!(
        exit, 3,
        "governed source is not implicitly disclosed: {refused:?}"
    );
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-142");
    assert_eq!(head(&f.book), reviewed);

    let closed = reconcile_selection(&f.book, &args);
    assert_eq!(text(&closed, "event"), "bank_reconciled");
    let original = data(&closed).get("reconciliation").unwrap();
    assert_eq!(text(original, "scope"), "exact_statement_close");
    assert_eq!(text(original, "statement_date"), "2026-03-15");
    assert_eq!(text(original, "cash_balance"), "600.00 USD");
    assert_eq!(integer(original, "evaluated_known_at"), reviewed);
    assert_eq!(integer(original, "recorded_at"), reviewed + 1);
    assert_eq!(original.get("already_recorded"), Some(&Json::Bool(false)));
    assert_eq!(rows(original, "matches").len(), 1);
    assert_eq!(
        rows(original, "matches")[0].get("vid"),
        data(&confirmed).get("match_vid")
    );
    let closed_at = head(&f.book);
    let after_tb = ok(&f.book, &["tb", "--as-of", "2026-03-15"]);
    assert_eq!(data(&after_tb).get("rows"), data(&before_tb).get("rows"));

    // Every command opens a fresh process. This metadata read requires no
    // privileged source access and must independently verify the old claim.
    let status = ok(&f.book, &["bank", "reconciliation", "--import", manifest]);
    assert_eq!(text(&status, "event"), "bank_reconciliation_status");
    assert_eq!(text(data(&status), "reconciled_through"), "2026-03-15");
    assert_eq!(integer(data(&status), "drifted_count"), 0);
    let clean = reconciliation_state(&status);
    for (field, expected) in [
        ("historical_claim_verified", true),
        ("balance_drift", false),
        ("cash_drift", false),
        ("match_drift", false),
    ] {
        assert_eq!(
            clean.get(field),
            Some(&Json::Bool(expected)),
            "{field}: {status:?}"
        );
    }
    assert!(rows(clean, "changed_entries").is_empty());
    assert!(rows(clean, "citing_entries").is_empty());
    assert!(!status.render().contains("Private customer"));
    let retry = reconcile_selection(&f.book, &args);
    let retry = data(&retry).get("reconciliation").unwrap();
    assert_eq!(retry.get("already_recorded"), Some(&Json::Bool(true)));
    for field in [
        "attestation_vid",
        "attestation_digest",
        "recorded_at",
        "cash_fold_digest",
        "matches",
    ] {
        assert_eq!(
            retry.get(field),
            original.get(field),
            "retry preserves {field}"
        );
    }
    assert_eq!(head(&f.book), closed_at);

    // Unprotected later dates remain ordinary postings and do not create
    // drift in the statement's earlier cash prefix.
    f.post("future-cash", "2026-03-20", "debit", "7.00", "FUTURE");
    let future = ok(&f.book, &["bank", "reconciliation", "--import", manifest]);
    assert_eq!(integer(data(&future), "drifted_count"), 0);

    let late = f.file("late-cash.json", r#"{"effective_date":"2026-03-12","idempotency_key":"late-cash","legs":[{"side":"debit","account":"1000","amount":"1.00 USD"},{"side":"credit","account":"4000","amount":"1.00 USD"}]}"#);
    let before = head(&f.book);
    let (exit, refused) = run(
        &f.book,
        &["post", "--intent", &late, "--evidence", &f.evidence],
    );
    assert_eq!(exit, 7, "{refused:?}");
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-011");
    assert!(text(data(&refused), "message").contains("reconcile"));
    assert_eq!(head(&f.book), before);
    let posted = ok(
        &f.book,
        &[
            "post",
            "--intent",
            &late,
            "--evidence",
            &f.evidence,
            "--grant",
            "reconcile",
        ],
    );
    let drifted = ok(&f.book, &["bank", "reconciliation", "--import", manifest]);
    let state = reconciliation_state(&drifted);
    assert_eq!(text(state, "cash_balance"), "601.00 USD");
    assert_eq!(
        state.get("historical_claim_verified"),
        Some(&Json::Bool(true))
    );
    assert_eq!(state.get("balance_drift"), Some(&Json::Bool(true)));
    assert_eq!(state.get("cash_drift"), Some(&Json::Bool(true)));
    assert_eq!(state.get("match_drift"), Some(&Json::Bool(false)));
    assert_eq!(
        rows(state, "changed_entries")[0].get("vid"),
        data(&posted).get("vid")
    );
    assert_eq!(
        rows(state, "citing_entries")[0].get("vid"),
        data(&posted).get("vid")
    );

    // Returning to the same amount does not erase changed contributions.
    let offset = f.file("late-offset.json", r#"{"effective_date":"2026-03-12","idempotency_key":"late-offset","legs":[{"side":"credit","account":"1000","amount":"1.00 USD"},{"side":"debit","account":"6000","amount":"1.00 USD"}]}"#);
    ok(
        &f.book,
        &[
            "post",
            "--intent",
            &offset,
            "--evidence",
            &f.evidence,
            "--grant",
            "reconcile",
        ],
    );
    let offset_status = ok(&f.book, &["bank", "reconciliation", "--import", manifest]);
    let state = reconciliation_state(&offset_status);
    assert_eq!(text(state, "cash_balance"), "600.00 USD");
    assert_eq!(state.get("balance_drift"), Some(&Json::Bool(false)));
    assert_eq!(state.get("cash_drift"), Some(&Json::Bool(true)));
    assert_eq!(rows(state, "changed_entries").len(), 2);
    assert_eq!(rows(state, "citing_entries").len(), 2);

    let mut release = unmatch_args(&confirmed);
    release.push("--yes".into());
    ok(
        &f.book,
        &release.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    let released = ok(&f.book, &["bank", "reconciliation", "--import", manifest]);
    assert_eq!(
        reconciliation_state(&released).get("match_drift"),
        Some(&Json::Bool(true))
    );
    assert_eq!(text(data(&released), "reconciled_through"), "2026-03-15");
    let historical = ok(
        &f.book,
        &[
            "bank",
            "reconciliation",
            "--import",
            manifest,
            "--as-known-at",
            &closed_at.to_string(),
        ],
    );
    assert_eq!(data(&historical), data(&status));
    assert_eq!(
        integer(historical.get("coordinate").unwrap(), "known_at"),
        closed_at
    );
    let before = head(&f.book);
    let retry = reconcile_selection(&f.book, &args);
    assert_eq!(
        data(&retry)
            .get("reconciliation")
            .unwrap()
            .get("attestation_digest"),
        original.get("attestation_digest")
    );
    assert_eq!(
        head(&f.book),
        before,
        "retry never reactivates released matches or rewrites the close"
    );
}

#[test]
fn reconciled_cash_scenarios_preserve_native_coordinates_and_planner_authority() {
    let f = Fixture::new();
    f.post("scenario-source", "2026-03-10", "debit", "100.00", "SOURCE");

    // Retained certificates and checkpoints are omitted accounting objects,
    // but their real source sequences precede the import, confirmations and
    // close. A compressed replay would invalidate the immutable native claim.
    let retained = certified_events(&f.book, &["tb", "--as-of", "2026-03-15", "--certify"]);
    assert_eq!(retained.len(), 2);
    assert_eq!(text(&retained[1], "event"), "report_certificate");
    let retained_locator = format!("C:{}", text(data(&retained[1]), "oid"));
    let retained_at = head(&f.book);
    ok(&f.book, &["checkpoint", "create", "--grant", "witness"]);
    assert!(head(&f.book) > retained_at);
    let imported = f.import("scenario-statement.csv", "csv", &format!(
        "{CSV_HEADER}1,BANK-SCENARIO,USD,2026-03-15,0.00,100.00,2026-03-10,2026-03-10,CRDT,100.00,Customer,SOURCE\n"
    ));
    let manifest = text(data(&imported), "manifest_oid");
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    confirm_selection(
        &f.book,
        &confirmation_args(&matched, 0, "scenario-reviewer"),
    );
    // The evaluated prefix itself may be maintenance. It must exist as an
    // actual native scratch sequence even though SeqMap floors to equivalent
    // accounting state and never pairs the source checkpoint as accounting.
    ok(&f.book, &["checkpoint", "create", "--grant", "witness"]);
    let reviewed = head(&f.book);
    let close_args = reconciliation_args(manifest, reviewed);
    let closed = reconcile_selection(&f.book, &close_args);
    let original = data(&closed).get("reconciliation").unwrap();
    assert_eq!(integer(original, "evaluated_known_at"), reviewed);
    assert_eq!(integer(original, "recorded_at"), reviewed + 1);
    let before_tb = ok(&f.book, &["tb", "--as-of", "2026-03-15"]);
    let forked = ok(
        &f.book,
        &[
            "scenario",
            "fork",
            "protected-cash",
            "--from",
            "2026-03-01",
            "--evidence",
            &f.evidence,
        ],
    );
    let fork_at = integer(data(&forked), "fork_at");
    let intent = f.file("scenario-late.json", r#"{"effective_date":"2026-03-12","idempotency_key":"scenario-late","legs":[{"side":"debit","account":"1000","amount":"1.00 USD"},{"side":"credit","account":"4000","amount":"1.00 USD"}]}"#);
    let before = head(&f.book);
    let (exit, denied) = run(
        &f.book,
        &[
            "scenario",
            "run",
            "protected-cash",
            "--intent",
            &intent,
            "--evidence",
            &f.evidence,
        ],
    );
    assert_eq!(exit, 7, "{denied:?}");
    assert_eq!(text(data(&denied), "refusal_id"), "FA-REF-011");
    assert!(text(data(&denied), "message").contains("reconcile"));
    assert_eq!(head(&f.book), before, "a refused rehearsal records nothing");

    let authorized = [
        "scenario",
        "run",
        "protected-cash",
        "--intent",
        &intent,
        "--evidence",
        &f.evidence,
        "--grant",
        "reconcile",
    ];
    let planned = ok(&f.book, &authorized);
    assert_eq!(data(&planned).get("rehearsed"), Some(&Json::Bool(true)));
    assert_eq!(integer(data(&planned), "ordinal"), 1);
    assert_eq!(
        head(&f.book),
        before + 1,
        "only the scenario record publishes"
    );
    let retried = ok(&f.book, &authorized);
    assert_eq!(
        data(&retried).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(head(&f.book), before + 1);

    // Each command cold-opens the book. A read-only diff uses the authority
    // retained with the planner's intent, not authority invented for a reader.
    let diff = ok(
        &f.book,
        &[
            "scenario",
            "diff",
            "protected-cash",
            "--period",
            "FY2026-P03",
        ],
    );
    assert_eq!(integer(data(&diff), "fork_at"), fork_at);
    assert_eq!(integer(data(&diff), "scenario_known_at"), fork_at + 1);
    let deltas: Vec<_> = rows(data(&diff), "rows")
        .iter()
        .map(|row| (text(row, "code"), text(row, "delta")))
        .collect();
    assert_eq!(deltas, [("1000", "1.00 USD"), ("4000", "-1.00 USD")]);
    let certified = certified_events(
        &f.book,
        &[
            "scenario",
            "diff",
            "protected-cash",
            "--period",
            "FY2026-P03",
            "--certify",
        ],
    );
    assert_eq!(certified.len(), 2);
    assert_eq!(data(&certified[0]), data(&diff));
    let encoded = text(data(&certified[1]), "bytes");
    let bytes: Vec<u8> = (0..encoded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).unwrap())
        .collect();
    let mut reader = fa_model::Reader::new(&bytes);
    assert_eq!(
        reader.bytes(64, "scenario certificate format").unwrap(),
        b"fa:scenario-diff-certificate:v2"
    );
    assert_eq!(
        text(data(&certified[1]), "output_format"),
        "fa:scenario-diff:v1"
    );
    let locator = format!("C:{}", text(data(&certified[1]), "oid"));
    let before_replay = head(&f.book);
    let replayed = ok(&f.book, &["replay", &locator]);
    assert_eq!(data(&replayed), data(&diff));
    assert_eq!(head(&f.book), before_replay);
    let original_report = ok(&f.book, &["replay", &retained_locator]);
    assert_eq!(
        data(&original_report).get("rows"),
        data(&retained[0]).get("rows")
    );

    let after_tb = ok(&f.book, &["tb", "--as-of", "2026-03-15"]);
    assert_eq!(data(&after_tb).get("rows"), data(&before_tb).get("rows"));
    let status = ok(&f.book, &["bank", "reconciliation", "--import", manifest]);
    assert_eq!(integer(data(&status), "drifted_count"), 0);
    let state = reconciliation_state(&status);
    assert_eq!(
        state.get("historical_claim_verified"),
        Some(&Json::Bool(true))
    );
    assert!(rows(state, "changed_entries").is_empty());
    assert!(rows(state, "citing_entries").is_empty());
    let retry = reconcile_selection(&f.book, &close_args);
    let retry = data(&retry).get("reconciliation").unwrap();
    for field in [
        "attestation_vid",
        "attestation_digest",
        "cash_fold_digest",
        "evaluated_known_at",
        "recorded_at",
        "matches",
    ] {
        assert_eq!(retry.get(field), original.get(field), "immutable {field}");
    }
}

#[test]
fn soft_closed_scenarios_preserve_only_granted_posting_authority_on_cold_replay() {
    let f = Fixture::new();
    f.post("soft-source", "2026-03-10", "debit", "100.00", "SOURCE");
    ok(&f.book, &["period", "soft-close", "FY2026-P03"]);
    let trunk = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    ok(&f.book, &["scenario", "fork", "soft-review"]);
    let original = f.file("soft-original.json", r#"{"effective_date":"2026-03-12","idempotency_key":"soft-original","legs":[{"side":"debit","account":"1000","amount":"1.00 USD"},{"side":"credit","account":"4000","amount":"1.00 USD"}]}"#);
    let before = head(&f.book);
    for grants in [
        Vec::new(),
        vec![
            "--grant",
            "post_closed",
            "--grant",
            "close",
            "--grant",
            "restate",
        ],
    ] {
        let mut args = vec![
            "scenario",
            "run",
            "soft-review",
            "--intent",
            &original,
            "--evidence",
            &f.evidence,
        ];
        args.extend(grants);
        let (exit, denied) = run(&f.book, &args);
        assert_eq!(exit, 7, "{denied:?}");
        assert_eq!(text(data(&denied), "refusal_id"), "FA-REF-011");
        assert!(text(data(&denied), "message").contains("post_softclosed"));
        assert_eq!(head(&f.book), before, "missing authority records nothing");
    }
    let planned = ok(
        &f.book,
        &[
            "scenario",
            "run",
            "soft-review",
            "--intent",
            &original,
            "--evidence",
            &f.evidence,
            "--grant",
            "post_softclosed",
        ],
    );
    assert_eq!(data(&planned).get("rehearsed"), Some(&Json::Bool(true)));
    assert_eq!(integer(data(&planned), "ordinal"), 1);
    assert_eq!(head(&f.book), before + 1);

    // Adjusting is already admissible in SoftClosed with Post alone. The
    // scratch capability must preserve exceptions, not require new ones.
    let adjustment = f.file("soft-adjustment.json", r#"{"class":"Adjusting","effective_date":"2026-03-12","idempotency_key":"soft-adjustment","legs":[{"side":"debit","account":"1000","amount":"2.00 USD"},{"side":"credit","account":"4000","amount":"2.00 USD"}]}"#);
    let planned = ok(
        &f.book,
        &[
            "scenario",
            "run",
            "soft-review",
            "--intent",
            &adjustment,
            "--evidence",
            &f.evidence,
        ],
    );
    assert_eq!(integer(data(&planned), "ordinal"), 2);
    assert_eq!(head(&f.book), before + 2, "only scenario records publish");
    let diff = ok(
        &f.book,
        &["scenario", "diff", "soft-review", "--period", "FY2026-P03"],
    );
    let deltas: Vec<_> = rows(data(&diff), "rows")
        .iter()
        .map(|row| (text(row, "code"), text(row, "delta")))
        .collect();
    assert_eq!(deltas, [("1000", "3.00 USD"), ("4000", "-3.00 USD")]);
    let certified = certified_events(
        &f.book,
        &[
            "scenario",
            "diff",
            "soft-review",
            "--period",
            "FY2026-P03",
            "--certify",
        ],
    );
    assert_eq!(certified.len(), 2);
    assert_eq!(data(&certified[0]), data(&diff));
    let locator = format!("C:{}", text(data(&certified[1]), "oid"));

    // A later real period close does not change the scenario's historical
    // fork. Every command cold-opens the directory book, including replay.
    ok(
        &f.book,
        &[
            "period",
            "close",
            "FY2026-P03",
            "--reason",
            "Scheduled",
            "--yes",
        ],
    );
    ok(&f.book, &["checkpoint", "create", "--grant", "witness"]);
    let before_replay = head(&f.book);
    let replayed = ok(&f.book, &["replay", &locator]);
    assert_eq!(data(&replayed), data(&diff));
    assert_eq!(head(&f.book), before_replay);
    let after = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    assert_eq!(data(&after).get("rows"), data(&trunk).get("rows"));
}

#[test]
fn closed_adjustment_scenarios_keep_post_closed_and_independent_approvals() {
    let f = Fixture::new();
    f.post("closed-source", "2026-03-10", "debit", "100.00", "SOURCE");
    let adjustment = f.file("closed-adjustment.json", r#"{"class":"Adjusting","effective_date":"2026-03-12","idempotency_key":"closed-adjustment","legs":[{"side":"debit","account":"1000","amount":"1.00 USD"},{"side":"credit","account":"4000","amount":"1.00 USD"}]}"#);
    let plan_path = f.dir.join("closed-adjustment.plan");
    let before_plan = head(&f.book);
    let planned = ok(
        &f.book,
        &[
            "post",
            "--intent",
            &adjustment,
            "--evidence",
            &f.evidence,
            "--dry-run",
            "--plan-out",
            plan_path.to_str().unwrap(),
        ],
    );
    assert_eq!(head(&f.book), before_plan);
    let plan = fa::PostPlan::decode(&std::fs::read(&plan_path).unwrap()).unwrap();
    let approval = ok(
        &f.book,
        &[
            "approve",
            "--proposal",
            text(data(&planned), "proposal_digest"),
            "--as",
            "independent-close-reviewer",
        ],
    );
    let approval_ref = fa_model::ApprovalRef {
        approval_vid: fgdb_types::VId(
            u128::from_str_radix(text(data(&approval), "approval_vid"), 16).unwrap(),
        ),
        approved_digest: plan.certificate().proposal_digest,
    };
    ok(&f.book, &["period", "soft-close", "FY2026-P03"]);
    ok(
        &f.book,
        &[
            "period",
            "close",
            "FY2026-P03",
            "--reason",
            "Scheduled",
            "--yes",
        ],
    );
    let forked = ok(&f.book, &["scenario", "fork", "closed-review"]);
    assert!(integer(data(&approval), "recorded_at") < integer(data(&forked), "fork_at"));
    let trunk = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    let before = head(&f.book);
    {
        // Preserve the exact sealed proposal prepared by the real CLI. A
        // JSON reconstruction would reseal it and invalidate the approval.
        // The old PostPlan is never committed: the scenario reruns the intent
        // under the now-Closed period and retains its own planning record.
        let keys = fa::BookKeys::load(&f.book.join("book.keys")).unwrap();
        let mut book = fa::Book::open_dir(&f.book, keys, fa::Entropy::production()).unwrap();
        let principal = fa_model::principal_vid("operator");
        let intent =
            fa::PostIntent::new(plan.intent().proposal().clone(), vec![approval_ref]).unwrap();
        let missing_op =
            fa::Capability::embedded(principal, &["post", "close", "restate"]).unwrap();
        let refusal = book
            .run_in_scenario(missing_op, "closed-review", intent.clone())
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, "FA-REF-011");
        assert!(refusal.message.contains("post_closed"));
        assert_eq!(i128::from(book.head().unwrap().0), before);
        let granted = fa::Capability::embedded(principal, &["post", "post_closed"]).unwrap();
        let refusal = book
            .run_in_scenario(granted.clone(), "closed-review", plan.intent().clone())
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, "FA-REF-012", "{refusal:?}");
        assert_eq!(i128::from(book.head().unwrap().0), before);
        let rehearsed = book
            .run_in_scenario(granted.clone(), "closed-review", intent.clone())
            .unwrap()
            .unwrap();
        assert!(rehearsed.rehearsed.is_some());
        assert_eq!(rehearsed.ordinal, 1);
        assert_eq!(i128::from(book.head().unwrap().0), before + 1);
        let retry = book
            .run_in_scenario(granted, "closed-review", intent)
            .unwrap()
            .unwrap();
        assert!(retry.recorded.already_recorded);
        assert_eq!(i128::from(book.head().unwrap().0), before + 1);
    }

    let diff = ok(
        &f.book,
        &[
            "scenario",
            "diff",
            "closed-review",
            "--period",
            "FY2026-P03",
        ],
    );
    let deltas: Vec<_> = rows(data(&diff), "rows")
        .iter()
        .map(|row| (text(row, "code"), text(row, "delta")))
        .collect();
    assert_eq!(deltas, [("1000", "1.00 USD"), ("4000", "-1.00 USD")]);
    let certified = certified_events(
        &f.book,
        &[
            "scenario",
            "diff",
            "closed-review",
            "--period",
            "FY2026-P03",
            "--certify",
        ],
    );
    assert_eq!(certified.len(), 2);
    assert_eq!(data(&certified[0]), data(&diff));
    let locator = format!("C:{}", text(data(&certified[1]), "oid"));
    ok(&f.book, &["checkpoint", "create", "--grant", "witness"]);
    let before_replay = head(&f.book);
    let replayed = ok(&f.book, &["replay", &locator]);
    assert_eq!(data(&replayed), data(&diff));
    assert_eq!(head(&f.book), before_replay);
    let after = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    assert_eq!(data(&after).get("rows"), data(&trunk).get("rows"));
}

#[test]
fn bank_drift_becomes_typed_recorded_findings_with_replayable_original_workpapers() {
    const PROCEDURE: &str = "recon.bank_statement_drift";
    let f = Fixture::new();
    let before = head(&f.book);
    let (exit, refused) = run(&f.book, &["finding", "record", PROCEDURE]);
    assert_eq!(
        exit, 7,
        "missing reconcile refuses even an empty bank population: {refused:?}"
    );
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-011");
    assert_eq!(head(&f.book), before);

    f.post(
        "finding-source-cash",
        "2026-03-10",
        "debit",
        "100.00",
        "SOURCE",
    );
    let imported = f.import("finding-statement.csv", "csv", &format!(
        "{CSV_HEADER}1,BANK-FINDING,USD,2026-03-15,0.00,100.00,2026-03-10,2026-03-10,CRDT,100.00,Private bank customer,SOURCE\n"
    ));
    let manifest = text(data(&imported), "manifest_oid");
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    let confirmed = confirm_selection(
        &f.book,
        &confirmation_args(&matched, 0, "finding-cash-reviewer"),
    );
    let closed = reconcile_selection(&f.book, &reconciliation_args(manifest, head(&f.book)));
    let close = data(&closed).get("reconciliation").unwrap();
    let attestation = text(close, "attestation_vid");
    let closed_at = head(&f.book).to_string();
    let clean = ok(
        &f.book,
        &[
            "finding",
            "record",
            PROCEDURE,
            "--known-at",
            &closed_at,
            "--grant",
            "reconcile",
        ],
    );
    assert_eq!(integer(data(&clean), "finding_count"), 0);
    assert_eq!(
        integer(data(&clean), "source_known_at").to_string(),
        closed_at
    );

    let late = f.file("finding-late.json", r#"{"effective_date":"2026-03-12","idempotency_key":"finding-late","legs":[{"side":"debit","account":"1000","amount":"1.00 USD"},{"side":"credit","account":"4000","amount":"1.00 USD"}]}"#);
    let posted = ok(
        &f.book,
        &[
            "post",
            "--intent",
            &late,
            "--evidence",
            &f.evidence,
            "--grant",
            "reconcile",
        ],
    );
    let late_entry = text(data(&posted), "vid");
    let late_at = head(&f.book).to_string();
    let balance_run = ok(
        &f.book,
        &[
            "finding",
            "record",
            PROCEDURE,
            "--known-at",
            &late_at,
            "--grant",
            "reconcile",
        ],
    );
    assert_eq!(text(&balance_run, "event"), "findings_recorded");
    assert_eq!(integer(data(&balance_run), "finding_count"), 1);
    let certificate = text(data(&balance_run), "certificate");
    let published_at = integer(data(&balance_run), "recorded_at");

    let (exit, refused) = run(&f.book, &["finding", "list", "--certificate", certificate]);
    assert_eq!(
        exit, 7,
        "saved certificate grants no bank observation authority: {refused:?}"
    );
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-011");
    let listed = ok(
        &f.book,
        &[
            "finding",
            "list",
            "--certificate",
            certificate,
            "--grant",
            "reconcile",
        ],
    );
    let findings = rows(data(&listed), "findings");
    assert_eq!(findings.len(), 1);
    let finding_id = text(&findings[0], "finding_vid");
    let original_finding = findings[0].get("finding").unwrap();
    let statistic = original_finding.get("statistic").unwrap();
    assert_eq!(text(statistic, "name"), "bank_statement_balance_drift");
    assert_eq!(integer(statistic, "value"), 100);
    assert_eq!(integer(statistic, "scale"), 2);
    let citations = rows(original_finding, "cites");
    assert!(
        citations.iter().any(|cite| {
            text(cite, "kind") == "attestation"
                && cite.get("attestation") == Some(&Json::Str(attestation.into()))
                && cite.get("entry") == Some(&Json::Null)
        }),
        "the native close is a typed attestation, never a fabricated Entry"
    );
    assert!(citations.iter().any(|cite| {
        text(cite, "kind") == "entry" && cite.get("entry") == Some(&Json::Str(late_entry.into()))
    }));
    let selected = ok(
        &f.book,
        &["finding", "show", finding_id, "--grant", "reconcile"],
    );
    assert_eq!(
        data(&selected).get("row").unwrap().get("finding"),
        Some(original_finding)
    );
    assert!(!listed.render().contains("Private bank customer"));

    // An unrecorded observation is a read: a bound investigator needs
    // Reconcile, but neither Produce nor a monetary posting capability.
    let observer = LaunchAuthority::new(
        f.book.clone(),
        None,
        "bank-drift-observer",
        LaunchProfile::Preparer,
        &["read", "reconcile"],
    )
    .unwrap();
    let args = [
        "procedure",
        "run",
        PROCEDURE,
        "--known-at",
        &late_at,
        "--json",
    ]
    .map(str::to_string);
    let (exit, output) = fa_with_authority(
        &args,
        Files {
            cwd: Some(f.dir.clone()),
            stdin: Stdin::Missing,
        },
        &observer,
        true,
    );
    assert_eq!(
        exit, 0,
        "an unrecorded observation requires no Produce: {output:?}"
    );
    let observed = json::parse(output.stdout.lines().last().unwrap()).unwrap();
    assert_eq!(
        rows(data(&observed), "findings"),
        std::slice::from_ref(original_finding)
    );

    let review = ok(
        &f.book,
        &[
            "finding",
            "review",
            finding_id,
            "--action",
            "acknowledge",
            "--note",
            "The retained close predates this admitted cash correction.",
            "--as",
            "bank-drift-reviewer",
            "--grant",
            "reconcile",
            "--yes",
        ],
    );
    assert_eq!(
        text(data(&review).get("review").unwrap(), "action"),
        "acknowledge"
    );
    let reviewed_at = head(&f.book).to_string();
    let selected = ok(
        &f.book,
        &["finding", "show", finding_id, "--grant", "reconcile"],
    );
    let row = data(&selected).get("row").unwrap();
    assert_eq!(text(row, "status"), "Reviewed");
    assert_eq!(row.get("finding"), Some(original_finding));

    let reviewed_path = f.dir.join("bank-drift-review.fawp");
    ok(
        &f.book,
        &[
            "finding",
            "export",
            "--certificate",
            certificate,
            "--grant",
            "reconcile",
            "--include-reviews",
            "--known-at",
            &reviewed_at,
            "--export-format",
            "canonical",
            "--out",
            reviewed_path.to_str().unwrap(),
        ],
    );

    let packet_path = f.dir.join("bank-drift.fawp");
    let exported = ok(
        &f.book,
        &[
            "finding",
            "export",
            "--certificate",
            certificate,
            "--grant",
            "reconcile",
            "--export-format",
            "canonical",
            "--out",
            packet_path.to_str().unwrap(),
        ],
    );
    let packet_bytes = std::fs::read(&packet_path).unwrap();
    let packet = fa::findings::FindingWorkpaper::decode(&packet_bytes).unwrap();
    assert_eq!(packet.id(), text(data(&exported), "workpaper"));
    assert_eq!(i128::from(packet.recorded_at().0), published_at);
    assert!(
        packet
            .markdown()
            .contains(&format!("Attestation {attestation}"))
    );
    assert!(packet.jsonl().contains(&format!(
        "\"kind\":\"attestation\",\"vid\":\"{attestation}\""
    )));
    assert!(!packet.markdown().contains("Private bank customer"));
    let source = fa::ProcedureCertificate::decode(packet.certificate_bytes()).unwrap();
    assert_eq!(source.known_at().0.to_string(), late_at);
    assert_eq!(source.report().findings.len(), 1);
    let native_attestation = fgdb_types::VId(u128::from_str_radix(attestation, 16).unwrap());
    assert!(
        source.report().findings[0]
            .cites
            .contains(&fa_lantern::Cite::Attestation(native_attestation))
    );
    let artifact_path = f.dir.join("bank-drift-procedure.fac");
    std::fs::write(&artifact_path, packet.certificate_bytes()).unwrap();

    // Returning the cash amount to its original value does not erase the
    // changed contribution set. Releasing a match is a separate exact drift.
    let offset = f.file("finding-offset.json", r#"{"effective_date":"2026-03-12","idempotency_key":"finding-offset","legs":[{"side":"credit","account":"1000","amount":"1.00 USD"},{"side":"debit","account":"6000","amount":"1.00 USD"}]}"#);
    let offset_posted = ok(
        &f.book,
        &[
            "post",
            "--intent",
            &offset,
            "--evidence",
            &f.evidence,
            "--grant",
            "reconcile",
        ],
    );
    let mut release = unmatch_args(&confirmed);
    release.push("--yes".into());
    ok(
        &f.book,
        &release.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    let changed_at = head(&f.book).to_string();
    let changed = ok(
        &f.book,
        &[
            "finding",
            "record",
            PROCEDURE,
            "--known-at",
            &changed_at,
            "--grant",
            "reconcile",
        ],
    );
    assert_eq!(integer(data(&changed), "finding_count"), 2);
    let changed_certificate = text(data(&changed), "certificate");
    let changes = ok(
        &f.book,
        &[
            "finding",
            "list",
            "--certificate",
            changed_certificate,
            "--grant",
            "reconcile",
        ],
    );
    let changes = rows(data(&changes), "findings");
    let changed_value = |name: &str| {
        changes
            .iter()
            .map(|row| row.get("finding").unwrap())
            .find(|finding| text(finding.get("statistic").unwrap(), "name") == name)
            .expect(name)
    };
    let contribution = changed_value("bank_statement_contribution_drift");
    assert_eq!(integer(contribution.get("statistic").unwrap(), "value"), 2);
    for entry in [late_entry, text(data(&offset_posted), "vid")] {
        assert!(rows(contribution, "cites").iter().any(|cite| {
            text(cite, "kind") == "entry" && cite.get("entry") == Some(&Json::Str(entry.into()))
        }));
    }
    let match_drift = changed_value("bank_statement_match_drift");
    assert_eq!(integer(match_drift.get("statistic").unwrap(), "value"), 1);
    for finding in [contribution, match_drift] {
        assert!(rows(finding, "cites").iter().any(|cite| {
            text(cite, "kind") == "attestation"
                && cite.get("attestation") == Some(&Json::Str(attestation.into()))
        }));
    }
    assert!(changes.iter().all(|row| {
        text(
            row.get("finding").unwrap().get("statistic").unwrap(),
            "name",
        ) != "bank_statement_balance_drift"
    }));
    let net_packet_path = f.dir.join("bank-net-zero-drift.fawp");
    ok(
        &f.book,
        &[
            "finding",
            "export",
            "--certificate",
            changed_certificate,
            "--grant",
            "reconcile",
            "--export-format",
            "canonical",
            "--out",
            net_packet_path.to_str().unwrap(),
        ],
    );

    // A further lawful cash change cannot rewrite either original observation.
    let later = f.file("finding-later.json", r#"{"effective_date":"2026-03-14","idempotency_key":"finding-later","legs":[{"side":"debit","account":"1000","amount":"2.00 USD"},{"side":"credit","account":"4000","amount":"2.00 USD"}]}"#);
    ok(
        &f.book,
        &[
            "post",
            "--intent",
            &later,
            "--evidence",
            &f.evidence,
            "--grant",
            "reconcile",
        ],
    );
    let frontier = head(&f.book);
    let (exit, refused) = run(&f.book, &["finding", "runs"]);
    assert_eq!(
        exit, 7,
        "inventory returns no partial bank page: {refused:?}"
    );
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-011");
    let inventory = ok(&f.book, &["finding", "runs", "--grant", "reconcile"]);
    assert_eq!(integer(data(&inventory), "total_recorded_runs"), 3);
    assert_eq!(integer(data(&inventory), "page_count"), 3);
    assert!(
        rows(data(&inventory), "runs")
            .iter()
            .all(|run| text(run, "procedure") == PROCEDURE)
    );
    let (exit, refused) = run(
        &f.book,
        &["finding", "replay", packet_path.to_str().unwrap()],
    );
    assert_eq!(
        exit, 7,
        "portable bytes do not confer bank authority: {refused:?}"
    );
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-011");
    for (path, expected_count, expected_at) in [
        (&packet_path, 1, late_at.as_str()),
        (&net_packet_path, 2, changed_at.as_str()),
    ] {
        let replayed = ok(
            &f.book,
            &[
                "finding",
                "replay",
                path.to_str().unwrap(),
                "--grant",
                "reconcile",
            ],
        );
        assert_eq!(text(&replayed, "event"), "finding_replayed");
        assert_eq!(integer(data(&replayed), "finding_count"), expected_count);
        assert_eq!(
            integer(data(&replayed), "source_known_at").to_string(),
            expected_at
        );
    }
    let reviewed = ok(
        &f.book,
        &[
            "finding",
            "replay",
            reviewed_path.to_str().unwrap(),
            "--grant",
            "reconcile",
            "--certificate",
            certificate,
            "--known-at",
            &reviewed_at,
        ],
    );
    assert_eq!(integer(data(&reviewed), "finding_count"), 1);
    assert_eq!(
        integer(data(&reviewed), "source_known_at").to_string(),
        late_at
    );
    assert_eq!(
        integer(data(&reviewed), "review_known_at").to_string(),
        reviewed_at
    );
    assert_eq!(
        data(&reviewed).get("includes_reviews"),
        Some(&Json::Bool(true))
    );
    let analytic = ok(
        &f.book,
        &[
            "replay",
            artifact_path.to_str().unwrap(),
            "--grant",
            "reconcile",
        ],
    );
    assert_eq!(text(&analytic, "event"), "procedure_run");
    assert_eq!(integer(data(&analytic), "known_at").to_string(), late_at);
    assert_eq!(
        rows(data(&analytic), "findings"),
        std::slice::from_ref(original_finding)
    );
    let retry = ok(
        &f.book,
        &[
            "finding",
            "record",
            "--certificate",
            certificate,
            "--grant",
            "reconcile",
        ],
    );
    assert_eq!(
        data(&retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(integer(data(&retry), "recorded_at"), published_at);
    let second_path = f.dir.join("bank-drift-again.fawp");
    ok(
        &f.book,
        &[
            "finding",
            "export",
            "--certificate",
            certificate,
            "--grant",
            "reconcile",
            "--export-format",
            "canonical",
            "--out",
            second_path.to_str().unwrap(),
        ],
    );
    assert_eq!(std::fs::read(second_path).unwrap(), packet_bytes);
    assert_eq!(
        head(&f.book),
        frontier,
        "read, replay, export and exact retry publish no new history"
    );
}

#[test]
fn bank_drift_admission_precedes_open_and_read_only_procedures_keep_their_authority() {
    const PROCEDURE: &str = "recon.bank_statement_drift";
    let f = Fixture::new();
    let missing = f.dir.join("bank-procedure-no-book");
    let producer_without_reconcile = LaunchAuthority::new(
        missing.clone(),
        None,
        "bank-drift-denied",
        LaunchProfile::Preparer,
        &["read", "produce"],
    )
    .unwrap();
    for args in [
        ["procedure", "run", PROCEDURE, "--json"],
        ["finding", "record", PROCEDURE, "--json"],
    ] {
        let (exit, output) = fa_with_authority(
            &args.map(str::to_string),
            Files {
                cwd: Some(f.dir.clone()),
                stdin: Stdin::Missing,
            },
            &producer_without_reconcile,
            true,
        );
        assert_eq!(
            exit, 7,
            "missing Reconcile must precede a cold open: {output:?}"
        );
        let refused = json::parse(output.stdout.lines().last().unwrap()).unwrap();
        assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-011");
        assert_eq!(refused.get("book"), Some(&Json::Null));
    }
    assert!(!missing.exists());

    let before = head(&f.book);
    let reader = LaunchAuthority::new(
        f.book.clone(),
        None,
        "ordinary-procedure-reader",
        LaunchProfile::Preparer,
        &["read"],
    )
    .unwrap();
    let args = ["procedure", "run", "jet.weekend", "--json"].map(str::to_string);
    let (exit, output) = fa_with_authority(
        &args,
        Files {
            cwd: Some(f.dir.clone()),
            stdin: Stdin::Missing,
        },
        &reader,
        true,
    );
    assert_eq!(
        exit, 0,
        "ordinary procedures do not gain a Reconcile requirement: {output:?}"
    );
    let observed = json::parse(output.stdout.lines().last().unwrap()).unwrap();
    assert_eq!(integer(data(&observed), "finding_count"), 0);
    assert_eq!(
        head(&f.book),
        before + access_events_since(&f.book, before),
        "only the token session's AccessEvents were written"
    );
}

#[test]
fn bank_reconciliation_refuses_unmatched_stale_unbalanced_and_postdated_closes() {
    let f = Fixture::new();
    f.post("unclosed-sale", "2026-03-10", "debit", "100.00", "UNCLOSED");
    let imported = f.import("unclosed.csv", "csv", &format!(
        "{CSV_HEADER}1,BANK-UNCLOSED,USD,2026-03-15,0.00,100.00,2026-03-10,2026-03-10,CRDT,100.00,Customer,UNCLOSED\n"
    ));
    let manifest = text(data(&imported), "manifest_oid");
    let before = head(&f.book);
    let args = reconciliation_args(manifest, before);
    let (exit, refused) = run_privileged(
        &f.book,
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_eq!(exit, 3, "{refused:?}");
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-168");
    assert!(text(data(&refused), "message").contains("active confirmation"));
    assert_eq!(head(&f.book), before);
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    confirm_selection(
        &f.book,
        &confirmation_args(&matched, 0, "statement-confirmer"),
    );
    let (exit, refused) = run_privileged(
        &f.book,
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_eq!(
        exit, 6,
        "a new close cannot borrow an old reviewed prefix: {refused:?}"
    );
    f.post(
        "unreported-cash",
        "2026-03-11",
        "debit",
        "1.00",
        "DIFFERENCE",
    );
    let before = head(&f.book);
    let args = reconciliation_args(manifest, before);
    let (exit, refused) = run_privileged(
        &f.book,
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_eq!(exit, 3, "{refused:?}");
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-168");
    assert!(text(data(&refused), "message").contains("cumulative posted cash"));
    assert_eq!(head(&f.book), before);
    let status = ok(&f.book, &["bank", "reconciliation", "--import", manifest]);
    assert_eq!(integer(data(&status), "reconciliation_count"), 0);
    assert_eq!(data(&status).get("reconciled_through"), Some(&Json::Null));

    // The cumulative amount happens to tie, but the matched leg itself is
    // effective after the close. A matching date window cannot authorize it.
    let f = Fixture::new();
    f.post("earlier-cash", "2026-03-01", "debit", "100.00", "EARLIER");
    f.post(
        "postdated-cash",
        "2026-03-16",
        "debit",
        "100.00",
        "POSTDATED",
    );
    let imported = f.import("postdated.csv", "csv", &format!(
        "{CSV_HEADER}1,BANK-POSTDATED,USD,2026-03-15,0.00,100.00,2026-03-15,2026-03-15,CRDT,100.00,Customer,POSTDATED\n"
    ));
    let manifest = text(data(&imported), "manifest_oid");
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    confirm_selection(
        &f.book,
        &confirmation_args(&matched, 0, "postdate-confirmer"),
    );
    let before = head(&f.book);
    let args = reconciliation_args(manifest, before);
    let (exit, refused) = run_privileged(
        &f.book,
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_eq!(exit, 3, "{refused:?}");
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-168");
    assert!(text(data(&refused), "message").contains("after the statement close date"));
    assert_eq!(head(&f.book), before);
}

#[test]
fn exact_confirmations_reopen_and_retry_without_changing_cash_or_reconciliation_state() {
    let f = Fixture::new();
    f.post("confirmed-sale", "2026-03-05", "debit", "150.00", "SALE-1");
    f.post("confirmed-bill", "2026-03-06", "credit", "50.00", "BILL-1");
    let imported = f.import("confirmation.csv", "csv", &statement_csv("95.00"));
    let manifest = text(data(&imported), "manifest_oid");
    let before_tb = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    let matched = ok_privileged(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            manifest,
            "--as",
            "bank-preparer",
        ],
    );
    let proposals = rows(data(&matched), "proposals");
    let proposer = format!("{:032x}", fa_model::principal_vid("bank-preparer").0);
    for proposal in &proposals[..2] {
        assert_eq!(text(proposal, "proposer"), proposer);
        let command = text(proposal, "confirmation_command");
        assert!(command.contains("bank confirm"));
        assert!(command.contains(text(proposal, "proposal_digest")));
        assert!(command.contains(&proposer));
    }
    assert_eq!(proposals[2].get("confirmation_command"), Some(&Json::Null));
    let source_known_at = integer(data(&matched), "known_at");
    let before = head(&f.book);
    let args = confirmation_args(&matched, 0, "bank-reviewer");
    let confirmed = confirm_selection(&f.book, &args);
    assert_eq!(text(&confirmed, "event"), "bank_match_confirmed");
    let receipt = data(&confirmed);
    assert_eq!(receipt.get("already_recorded"), Some(&Json::Bool(false)));
    assert_eq!(integer(receipt, "recorded_at"), before + 1);
    assert_eq!(head(&f.book), before + 1);
    assert_eq!(text(receipt, "manifest_oid"), manifest);
    assert_eq!(
        integer(receipt, "line_ordinal"),
        integer(&proposals[0], "line_ordinal")
    );
    assert_eq!(
        text(receipt, "bank_line_oid"),
        text(&proposals[0], "bank_line_id")
    );
    assert_eq!(
        text(receipt, "line_document_oid"),
        text(&proposals[0], "line_document_oid")
    );
    assert_eq!(receipt.get("entry_ref"), proposals[0].get("entry_ref"));
    assert_eq!(receipt.get("leg_ordinal"), proposals[0].get("leg_ordinal"));
    assert_eq!(integer(receipt, "source_known_at"), source_known_at);
    assert_eq!(
        text(receipt, "proposal_digest"),
        text(&proposals[0], "proposal_digest")
    );
    assert_eq!(text(receipt, "proposer"), proposer);
    assert_eq!(
        text(receipt, "confirmed_by"),
        format!("{:032x}", fa_model::principal_vid("bank-reviewer").0)
    );
    assert_eq!(text(receipt, "match_vid").len(), 32);
    assert_eq!(text(receipt, "match_digest").len(), 64);
    assert_eq!(
        text(confirmed.get("authority").unwrap(), "principal"),
        "bank-reviewer"
    );

    // Every helper starts a fresh process. A different authorized caller must
    // recover the original decision and attribution after reopening the book.
    let after = head(&f.book);
    let retry = confirm_selection(
        &f.book,
        &confirmation_args(&matched, 0, "bank-retry-operator"),
    );
    assert_eq!(
        data(&retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    for key in [
        "match_vid",
        "match_digest",
        "recorded_at",
        "manifest_oid",
        "line_ordinal",
        "line_document_oid",
        "bank_line_oid",
        "entry_ref",
        "leg_ordinal",
        "proposer",
        "confirmed_by",
        "source_known_at",
        "proposal_digest",
    ] {
        assert_eq!(data(&retry).get(key), receipt.get(key), "retained {key}");
    }
    assert_eq!(
        text(retry.get("authority").unwrap(), "principal"),
        "bank-retry-operator"
    );
    assert_eq!(head(&f.book), after);

    let status = ok_privileged(&f.book, &["bank", "status", "--import", manifest]);
    assert_eq!(text(&status, "event"), "bank_confirmation_status");
    let inventory = data(&status);
    assert_eq!(text(inventory, "scope"), "recorded_confirmations");
    assert_eq!(integer(inventory, "line_count"), 3);
    assert_eq!(integer(inventory, "confirmed_lines"), 1);
    assert_eq!(integer(inventory, "remaining_lines"), 2);
    assert_eq!(inventory.get("reconciled_through"), Some(&Json::Null));
    let saved = rows(inventory, "confirmations");
    assert_eq!(saved.len(), 1);
    for key in [
        "match_vid",
        "match_digest",
        "recorded_at",
        "confirmed_by",
        "entry_ref",
        "leg_ordinal",
    ] {
        assert_eq!(saved[0].get(key), receipt.get(key), "inventory {key}");
    }
    let historical = ok_privileged(
        &f.book,
        &[
            "bank",
            "status",
            "--import",
            manifest,
            "--as-known-at",
            &source_known_at.to_string(),
        ],
    );
    assert_eq!(integer(data(&historical), "known_at"), source_known_at);
    assert_eq!(
        integer(historical.get("coordinate").unwrap(), "known_at"),
        source_known_at
    );
    assert_eq!(integer(data(&historical), "confirmed_lines"), 0);
    assert_eq!(integer(data(&historical), "remaining_lines"), 3);
    assert!(rows(data(&historical), "confirmations").is_empty());
    assert_eq!(head(&f.book), after);

    // The original report also authorizes its distinct outflow selection. Its
    // unmatched bank fee remains a missing posting, never an automatic entry.
    let bill = confirm_selection(&f.book, &confirmation_args(&matched, 1, "bank-reviewer"));
    assert_eq!(data(&bill).get("entry_ref"), proposals[1].get("entry_ref"));
    let status = ok_privileged(&f.book, &["bank", "status", "--import", manifest]);
    assert_eq!(integer(data(&status), "confirmed_lines"), 2);
    assert_eq!(integer(data(&status), "remaining_lines"), 1);
    assert_eq!(data(&status).get("reconciled_through"), Some(&Json::Null));
    let after_tb = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    for key in ["rows", "unit_totals", "pending_unit_totals", "balanced"] {
        assert_eq!(
            data(&after_tb).get(key),
            data(&before_tb).get(key),
            "unchanged {key}"
        );
    }
}

#[test]
fn confirmation_identity_preserves_two_cash_leg_ordinals_in_one_entry() {
    let f = Fixture::new();
    let intent = f.file(
        "two-confirmable-legs.json",
        r#"{"effective_date":"2026-03-05","idempotency_key":"two-confirmable-legs","legs":[{"side":"debit","account":"1000","amount":"60.00 USD","memo":"A"},{"side":"debit","account":"1000","amount":"40.00 USD","memo":"B"},{"side":"credit","account":"4000","amount":"100.00 USD"}]}"#,
    );
    ok(
        &f.book,
        &["post", "--intent", &intent, "--evidence", &f.evidence],
    );
    let raw = format!(
        "{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,100.00,2026-03-05,2026-03-05,CRDT,40.00,Customer,B\n1,BANK-123,USD,2026-03-31,0.00,100.00,2026-03-05,2026-03-05,CRDT,60.00,Customer,A\n"
    );
    let imported = f.import("two-confirmable-legs.csv", "csv", &raw);
    let manifest = text(data(&imported), "manifest_oid");
    let before_tb = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    let matched = ok_privileged(
        &f.book,
        &["bank", "match", "--import", manifest, "--date-window", "0"],
    );
    let proposals = rows(data(&matched), "proposals");
    assert_eq!(proposals[0].get("entry_ref"), proposals[1].get("entry_ref"));
    assert_eq!(integer(&proposals[0], "leg_ordinal"), 1);
    assert_eq!(integer(&proposals[1], "leg_ordinal"), 0);
    let first = confirm_selection(&f.book, &confirmation_args(&matched, 0, "bank-reviewer"));
    let second = confirm_selection(&f.book, &confirmation_args(&matched, 1, "bank-reviewer"));
    assert_eq!(
        data(&first).get("entry_ref"),
        data(&second).get("entry_ref")
    );
    assert_eq!(integer(data(&first), "leg_ordinal"), 1);
    assert_eq!(integer(data(&second), "leg_ordinal"), 0);
    assert_ne!(
        text(data(&first), "match_vid"),
        text(data(&second), "match_vid")
    );
    assert_ne!(
        text(data(&first), "match_digest"),
        text(data(&second), "match_digest")
    );
    let status = ok_privileged(&f.book, &["bank", "status", "--import", manifest]);
    assert_eq!(integer(data(&status), "confirmed_lines"), 2);
    assert_eq!(integer(data(&status), "remaining_lines"), 0);
    assert_eq!(data(&status).get("reconciled_through"), Some(&Json::Null));
    let mut ordinals: Vec<_> = rows(data(&status), "confirmations")
        .iter()
        .map(|row| integer(row, "leg_ordinal"))
        .collect();
    ordinals.sort_unstable();
    assert_eq!(ordinals, [0, 1]);
    let after_tb = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    assert_eq!(data(&after_tb).get("rows"), data(&before_tb).get("rows"));
}

#[test]
fn different_statements_cannot_confirm_the_same_cash_leg_twice() {
    let f = Fixture::new();
    f.post("single-claimed-leg", "2026-03-05", "debit", "100.00", "ONE");
    let raw = format!(
        "{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,100.00,2026-03-05,2026-03-05,CRDT,100.00,Customer,ONE\n"
    );
    let first = f.import("first-claim.csv", "csv", &raw);
    let second = f.import(
        "second-claim.csv",
        "csv",
        &raw.replace("\n1,BANK-123", "\n2,BANK-123"),
    );
    let first_manifest = text(data(&first), "manifest_oid");
    let second_manifest = text(data(&second), "manifest_oid");
    assert_ne!(first_manifest, second_manifest);
    let first_match = ok_privileged(&f.book, &["bank", "match", "--import", first_manifest]);
    let second_match = ok_privileged(&f.book, &["bank", "match", "--import", second_manifest]);
    let first_proposal = &rows(data(&first_match), "proposals")[0];
    let second_proposal = &rows(data(&second_match), "proposals")[0];
    assert_eq!(
        first_proposal.get("entry_ref"),
        second_proposal.get("entry_ref")
    );
    assert_eq!(
        first_proposal.get("leg_ordinal"),
        second_proposal.get("leg_ordinal")
    );
    assert_eq!(integer(first_proposal, "eligible_candidate_count"), 1);
    assert_eq!(integer(second_proposal, "eligible_candidate_count"), 1);
    let recorded = confirm_selection(
        &f.book,
        &confirmation_args(&first_match, 0, "first-reviewer"),
    );
    let before = head(&f.book);
    let conflicting = confirmation_args(&second_match, 0, "second-reviewer");
    let (status, refusal) = run_privileged(
        &f.book,
        &conflicting.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_eq!(status, 6, "{}", refusal.render());
    assert_eq!(
        text(data(&refusal), "refusal_id"),
        fa_journal::refusal::code::IDEMPOTENCY_CONFLICT
    );
    assert_eq!(head(&f.book), before);
    let first_status = ok_privileged(&f.book, &["bank", "status", "--import", first_manifest]);
    assert_eq!(integer(data(&first_status), "confirmed_lines"), 1);
    assert_eq!(
        rows(data(&first_status), "confirmations")[0].get("match_digest"),
        data(&recorded).get("match_digest")
    );
    let second_status = ok_privileged(&f.book, &["bank", "status", "--import", second_manifest]);
    assert_eq!(integer(data(&second_status), "confirmed_lines"), 0);
    assert_eq!(integer(data(&second_status), "remaining_lines"), 1);
    assert!(rows(data(&second_status), "confirmations").is_empty());
    assert_eq!(head(&f.book), before);
}

#[test]
fn confirmation_refuses_unprivileged_forged_and_historically_unavailable_selections() {
    let f = Fixture::new();
    let raw = format!(
        "{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,25.00,2026-03-05,2026-03-05,CRDT,25.00,Customer,PAY-25\n"
    );
    let imported = f.import("selection-boundary.csv", "csv", &raw);
    let imported_at = head(&f.book);
    f.post("later-known-cash", "2026-03-04", "debit", "25.00", "PAY-25");
    let manifest = text(data(&imported), "manifest_oid");
    let matched = ok_privileged(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            manifest,
            "--as",
            "bank-preparer",
        ],
    );
    assert_eq!(integer(data(&matched), "proposed_count"), 1);
    let args = confirmation_args(&matched, 0, "bank-reviewer");
    let before = head(&f.book);
    let (status, refusal) = run(
        &f.book,
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_eq!(status, 3, "{}", refusal.render());
    assert_eq!(text(data(&refusal), "refusal_id"), "FA-REF-142");
    assert!(!refusal.render().contains("PAY-25"));
    assert_eq!(head(&f.book), before);

    let digest = text(&rows(data(&matched), "proposals")[0], "proposal_digest");
    let forged_digest = format!(
        "{}{}",
        if digest.starts_with('0') { '1' } else { '0' },
        &digest[1..]
    );
    for (flag, value) in [
        ("--proposal-digest", forged_digest),
        ("--source-known-at", imported_at.to_string()),
        ("--date-window", "0".into()),
    ] {
        let mut forged = args.clone();
        if let Some(position) = forged.iter().position(|arg| arg == flag) {
            forged[position + 1] = value;
        } else {
            forged.extend([flag.into(), value]);
        }
        let (status, refusal) = run_privileged(
            &f.book,
            &forged.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        assert_eq!(status, 3, "{flag}: {}", refusal.render());
        assert_eq!(text(data(&refusal), "refusal_id"), "FA-REF-168", "{flag}");
        assert_eq!(
            head(&f.book),
            before,
            "{flag} must claim neither line nor leg"
        );
    }
    let recorded = confirm_selection(&f.book, &args);
    assert_eq!(
        data(&recorded).get("already_recorded"),
        Some(&Json::Bool(false))
    );
    assert_eq!(integer(data(&recorded), "recorded_at"), before + 1);
}

#[test]
fn import_is_atomic_keeps_source_and_line_closure_and_is_content_idempotent() {
    let f = Fixture::new();
    let raw = statement_csv("95.00");
    let before = head(&f.book);
    let imported = f.import("statement.csv", "csv", &raw);
    assert_eq!(text(&imported, "event"), "bank_imported");
    let result = data(&imported);
    assert_eq!(integer(result, "line_count"), 3);
    assert_eq!(text(result, "closing_balance"), "95.00 USD");
    assert_eq!(
        head(&f.book),
        before + 1,
        "source, lines and manifest are one commit"
    );
    let source = ok_privileged(
        &f.book,
        &["document", "read", text(result, "statement_oid")],
    );
    assert_eq!(text(data(&source), "kind"), "BankStatement");
    assert_eq!(
        text(data(&source).get("text").unwrap(), "untrusted_content"),
        raw
    );
    for oid in rows(result, "line_oids") {
        let line = ok(&f.book, &["document", "read", oid.as_str().unwrap()]);
        assert_eq!(
            text(data(&line), "grade"),
            "AgentUpload",
            "derived text never upgrades provenance"
        );
        assert_eq!(
            text(data(&line), "mime"),
            "application/vnd.frankenaccounting.bank-line"
        );
    }
    let after = head(&f.book);
    let repeated = f.import("repeat.csv", "csv", &raw);
    assert_eq!(
        data(&repeated).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        text(data(&repeated), "manifest_oid"),
        text(result, "manifest_oid")
    );
    assert_eq!(
        text(data(&repeated), "receipt_hash"),
        text(result, "receipt_hash")
    );
    assert_eq!(head(&f.book), after);
    let other_path = f.file("other-uploader.csv", &raw);
    let other = ok(
        &f.book,
        &[
            "bank",
            "import",
            &other_path,
            "--bank-format",
            "csv",
            "--account",
            "1000",
            "--as",
            "second-uploader",
        ],
    );
    assert_eq!(
        data(&other).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        head(&f.book),
        after,
        "another authorized uploader does not duplicate an import"
    );
    ok(&f.book, &["verify", "registers", "--fiscal-year", "2026"]);
}

#[test]
fn exact_matches_reopen_with_bound_account_and_parser_and_never_confirm_or_post_fees() {
    let f = Fixture::new();
    f.post("sale", "2026-03-05", "debit", "150.00", "SALE-1");
    f.post("bill", "2026-03-06", "credit", "50.00", "BILL-1");
    f.post("in-transit", "2026-03-10", "debit", "20.00", "NEXT-STMT");
    let before_import = head(&f.book);
    let imported = f.import("match.csv", "csv", &statement_csv("95.00"));
    let manifest = text(data(&imported), "manifest_oid");
    let before = head(&f.book);
    let (status, unavailable) = run_privileged(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            manifest,
            "--as-known-at",
            &before_import.to_string(),
        ],
    );
    assert_eq!(status, 2, "{}", unavailable.render());
    assert_eq!(text(data(&unavailable), "refusal_id"), "FA-REF-103");
    assert_eq!(head(&f.book), before);
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    let result = data(&matched);
    assert_eq!(text(&matched, "event"), "bank_matches_proposed");
    assert_eq!(result.get("confirmed"), Some(&Json::Bool(false)));
    assert_eq!(integer(result, "proposed_count"), 2);
    assert_eq!(integer(result, "unmatched_count"), 1);
    assert_eq!(integer(result, "outstanding_count"), 1);
    assert_eq!(text(result, "candidate_from"), "2026-03-02");
    assert_eq!(text(result, "candidate_through"), "2026-04-03");
    assert_eq!(
        text(result, "outstanding_scope"),
        "unmatched_cash_legs_in_candidate_window"
    );
    assert_eq!(result.get("outstanding_complete"), Some(&Json::Bool(false)));
    assert_eq!(text(result, "book_closing_balance"), "120.00 USD");
    assert_eq!(text(result, "closing_difference"), "-25.00 USD");
    assert_progress(
        &matched,
        [
            ("0.00", "0.00"),
            ("0.00", "0.00"),
            ("150.00", "55.00"),
            ("150.00", "50.00"),
            ("0.00", "5.00"),
            ("20.00", "0.00"),
        ],
        3,
        false,
        false,
    );
    let proposals = rows(result, "proposals");
    assert_eq!(text(&proposals[0], "direction"), "inflow");
    assert_eq!(text(&proposals[1], "direction"), "outflow");
    assert_eq!(text(&proposals[2], "status"), "unmatched");
    for row in &proposals[..2] {
        assert_eq!(text(row, "status"), "proposed");
        assert!(
            row.get("entry_ref")
                .is_some_and(|value| value != &Json::Null)
        );
        assert_eq!(text(row, "decision_card_digest").len(), 64);
        assert!(!text(row, "decision_card").is_empty());
    }
    assert_eq!(head(&f.book), before);
    let replay = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    assert_eq!(
        matched, replay,
        "same retained inputs and prefix yield identical proposals"
    );
    f.post("late-booking", "2026-03-07", "credit", "5.00", "FEE-1");
    let original = ok_privileged(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            manifest,
            "--as-known-at",
            &before.to_string(),
        ],
    );
    assert_eq!(integer(data(&original), "proposed_count"), 2);
    assert_eq!(
        integer(original.get("coordinate").unwrap(), "known_at"),
        before
    );
    let current = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    assert_eq!(integer(data(&current), "proposed_count"), 3);
    assert_eq!(integer(data(&current), "unmatched_count"), 0);
}

#[test]
fn invalid_balances_float_syntax_and_wrong_account_unit_publish_nothing() {
    let f = Fixture::new();
    let cases = [
        ("unbalanced.csv", statement_csv("96.00"), "1000"),
        (
            "float.csv",
            statement_csv("95.00").replace("150.00", "1.5e2"),
            "1000",
        ),
        (
            "currency.csv",
            statement_csv("95.00").replace("USD", "EUR"),
            "1000",
        ),
        ("revenue.csv", statement_csv("95.00"), "4000"),
    ];
    let before = head(&f.book);
    for (name, raw, account) in cases {
        let path = f.file(name, &raw);
        let (status, output) = run(
            &f.book,
            &[
                "bank",
                "import",
                &path,
                "--bank-format",
                "csv",
                "--account",
                account,
            ],
        );
        assert!(status == 2 || status == 3, "{name}: {}", output.render());
        assert_eq!(text(&output, "event"), "error");
        assert_eq!(
            head(&f.book),
            before,
            "{name}: a refused statement leaves no document or import receipt"
        );
    }
}

#[test]
fn missing_authority_and_agent_import_refuse_before_reading_missing_input() {
    let f = Fixture::new();
    let before = head(&f.book);
    for (profile, ops, expected) in [
        (LaunchProfile::Preparer, &["post"][..], "FA-REF-011"),
        (
            LaunchProfile::Agent,
            &["read", "post", "reconcile"][..],
            "FA-REF-013",
        ),
    ] {
        let authority =
            LaunchAuthority::new(f.book.clone(), None, "bank-bound-agent", profile, ops).unwrap();
        let args = [
            "bank",
            "import",
            "-",
            "--bank-format",
            "csv",
            "--account",
            "1000",
            "--json",
        ]
        .map(str::to_string);
        let (code, captured) = fa_with_authority(
            &args,
            Files {
                cwd: Some(f.dir.clone()),
                stdin: Stdin::Missing,
            },
            &authority,
            true,
        );
        assert_eq!(code, 7, "{captured:?}");
        let output = json::parse(captured.stdout.lines().last().unwrap()).unwrap();
        assert_eq!(text(data(&output), "refusal_id"), expected);
        assert!(!captured.stdout.contains("no input reached the daemon"));
        assert_eq!(head(&f.book), before);
    }
}

#[test]
fn governed_sources_need_explicit_privilege_and_redacted_views_never_enable_matching() {
    let f = Fixture::new();
    let raw = statement_csv("95.00");
    let imported = f.import("governed.csv", "csv", &raw);
    let source = text(data(&imported), "statement_oid");
    let manifest = text(data(&imported), "manifest_oid");
    let before = head(&f.book);
    for args in [
        vec!["document", "read", source],
        vec!["bank", "match", "--import", manifest],
    ] {
        let (status, refused) = run(&f.book, &args);
        assert_eq!(status, 3, "{}", refused.render());
        assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-142");
        assert!(!refused.render().contains("BANK-123"));
        assert!(!refused.render().contains("SALE-1"));
        if args[0] == "bank" {
            assert!(text(data(&refused), "fix").contains("--grant privileged"));
        }
        assert_eq!(head(&f.book), before);
    }

    ok(&f.book, &["document", "redact", source]);
    let after_view = head(&f.book);
    let redacted = ok(&f.book, &["document", "read", source]);
    assert_eq!(text(data(&redacted), "view"), "redacted");
    assert_eq!(data(&redacted).get("bytes_hex"), Some(&Json::Null));
    assert_eq!(data(&redacted).get("text"), Some(&Json::Null));
    let (status, refused) = run(&f.book, &["bank", "match", "--import", manifest]);
    assert_eq!(status, 7, "{}", refused.render());
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-011");
    assert!(text(data(&refused), "fix").contains("--grant privileged"));

    for profile in [LaunchProfile::Agent, LaunchProfile::Preparer] {
        assert!(
            LaunchAuthority::new(
                f.book.clone(),
                None,
                "bank-template",
                profile,
                &["read", "reconcile", "privileged"],
            )
            .is_err(),
            "matching must not broaden a launch template's privilege ceiling"
        );
        let authority = LaunchAuthority::new(
            f.book.clone(),
            None,
            "bank-template",
            profile,
            &["read", "reconcile"],
        )
        .unwrap();
        let args = ["bank", "match", "--import", manifest, "--json"].map(str::to_string);
        let (status, captured) = fa_with_authority(
            &args,
            Files {
                cwd: Some(f.dir.clone()),
                stdin: Stdin::Missing,
            },
            &authority,
            true,
        );
        assert_eq!(status, 7, "{captured:?}");
        let refused = json::parse(captured.stdout.lines().last().unwrap()).unwrap();
        assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-011");
        assert!(!captured.stdout.contains("SALE-1"));
        assert_eq!(head(&f.book), after_view);

        // The same session reads the governed source through its derived
        // view (fa-0x0): a document read is read admission, never the
        // trunk-write rule an Agent's posts meet.
        let args = ["document", "read", source, "--json"].map(str::to_string);
        let (status, captured) = fa_with_authority(
            &args,
            Files {
                cwd: Some(f.dir.clone()),
                stdin: Stdin::Missing,
            },
            &authority,
            true,
        );
        assert_eq!(status, 0, "{profile:?}: {captured:?}");
        let read = json::parse(captured.stdout.lines().last().unwrap()).unwrap();
        assert_eq!(text(data(&read), "view"), "redacted", "{profile:?}");
        assert_eq!(data(&read).get("text"), Some(&Json::Null));
        assert!(!captured.stdout.contains("BANK-123"));
        assert_eq!(head(&f.book), after_view);
    }

    let full = ok_privileged(&f.book, &["document", "read", source]);
    assert_eq!(text(data(&full), "view"), "full");
    assert_eq!(
        text(data(&full).get("text").unwrap(), "untrusted_content"),
        raw
    );
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    assert_eq!(integer(data(&matched), "line_count"), 3);
    assert_eq!(data(&matched).get("confirmed"), Some(&Json::Bool(false)));
    assert_eq!(head(&f.book), after_view);
}

#[test]
fn one_entry_with_multiple_cash_legs_preserves_each_selected_ordinal() {
    let f = Fixture::new();
    let intent = f.file("two-cash-legs.json", r#"{"effective_date":"2026-03-05","idempotency_key":"two-cash","legs":[{"side":"debit","account":"1000","amount":"60.00 USD","memo":"A"},{"side":"debit","account":"1000","amount":"40.00 USD","memo":"B"},{"side":"credit","account":"4000","amount":"100.00 USD"}]}"#);
    ok(
        &f.book,
        &["post", "--intent", &intent, "--evidence", &f.evidence],
    );
    let raw = format!(
        "{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,100.00,2026-03-05,2026-03-05,CRDT,40.00,Customer,B\n1,BANK-123,USD,2026-03-31,0.00,100.00,2026-03-05,2026-03-05,CRDT,60.00,Customer,A\n"
    );
    let imported = f.import("split.csv", "csv", &raw);
    let matched = ok_privileged(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            text(data(&imported), "manifest_oid"),
        ],
    );
    assert_eq!(integer(data(&matched), "proposed_count"), 2);
    let proposals = rows(data(&matched), "proposals");
    assert_eq!(integer(&proposals[0], "leg_ordinal"), 1);
    assert_eq!(integer(&proposals[1], "leg_ordinal"), 0);
    assert_eq!(proposals[0].get("entry_ref"), proposals[1].get("entry_ref"));
}

/// fa-d22b: one statement, a 125.00 USD wire credited on 2026-03-05, imports
/// through the real binary in every registered bank format and profile and
/// matches the one posted cash leg it records: csv, camt053, camt052, bai2
/// (the standard bank profile and the ISO profile), ofx, and mt940 (the
/// SWIFT profile and the pipe profile).
#[test]
fn every_format_imports_via_cli() {
    let f = Fixture::new();
    f.post("wire-sale", "2026-03-05", "debit", "125.00", "WIRE-125");
    let camt = r#"<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt.053.001.08">
  <BkToCstmrStmt><Stmt><Id>March</Id><ElctrncSeqNb>1</ElctrncSeqNb>
    <Acct><Id><IBAN>GB29NWBK60161331926819</IBAN></Id><Ccy>USD</Ccy></Acct>
    <Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy="USD">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><Dt>2026-03-01</Dt></Dt></Bal>
    <Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy="USD">125.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><Dt>2026-03-31</Dt></Dt></Bal>
    <Ntry><Amt Ccy="USD">125.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Sts><Cd>BOOK</Cd></Sts>
      <BookgDt><Dt>2026-03-05</Dt></BookgDt><ValDt><Dt>2026-03-05</Dt></ValDt><AcctSvcrRef>WIRE-125</AcctSvcrRef>
    </Ntry>
  </Stmt></BkToCstmrStmt>
</Document>"#;
    let camt052 = camt
        .replace("camt.053", "camt.052")
        .replace("BkToCstmrStmt", "BkToCstmrAcctRpt")
        .replace("<Stmt>", "<Rpt>")
        .replace("</Stmt>", "</Rpt>")
        .replace("CLBD", "ITBD");
    let csv = format!(
        "{CSV_HEADER}1,GB29NWBK60161331926819,USD,2026-03-31,0.00,125.00,2026-03-05,2026-03-05,CRDT,125.00,Customer,WIRE-125\n"
    );
    // A bank's BAI2 file: account control 0 + 12500 + 12500 (03) + 12500
    // (16) = 37500 over 3 records; group 5 records; file 7.
    let bai2 = "01,BANKID,CUSTID,260305,0600,1,,,2/\n\
02,CUSTID,BANKID,1,260305,2359,USD,2/\n\
03,GB29NWBK60161331926819,USD,010,0,,,015,12500,,,100,12500,1,Z/\n\
16,195,12500,V,260305,,WIRE-125,,Customer/\n\
49,37500,3/\n\
98,37500,1,5/\n\
99,37500,1,7/\n";
    let bai2_iso = "02,OWNER,BANK,1,2026-03-05,2359,USD,1/\n\
03,GB29NWBK60161331926819,USD,010,0,015,12500/\n\
16,195,12500,2026-03-05,WIRE-125,Customer/\n";
    let ofx = "<OFX><TRNUID>1</TRNUID><CURDEF>USD</CURDEF><ACCTID>GB29NWBK60161331926819</ACCTID>\
<OPENBAL>0.00</OPENBAL>\
<STMTTRN><DTPOSTED>2026-03-05</DTPOSTED><TRNAMT>125.00</TRNAMT><FITID>WIRE-125</FITID><NAME>Customer</NAME></STMTTRN>\
<LEDGERBAL><BALAMT>125.00</BALAMT><DTASOF>2026-03-31</DTASOF></LEDGERBAL></OFX>";
    let mt940 = ":20:MARCH\n:25:GB29NWBK60161331926819\n:28C:1\n\
:60F:C260301USD0,\n\
:61:2603050305C125,NTRFWIRE-125\n\
:86:Customer\n\
:62F:C260331USD125,\n";
    let mt940_pipe = ":20:MARCH\n:25:GB29NWBK60161331926819\n:28C:1/1\n\
:60F:C|2026-03-01|USD|0.00\n\
:61:2026-03-05|C|125.00|WIRE-125|Customer\n\
:62F:C|2026-03-31|USD|125.00\n";
    for (name, format, raw) in [
        ("statement.csv", "csv", csv.as_str()),
        ("statement.camt053.xml", "camt053", camt),
        ("statement.camt052.xml", "camt052", camt052.as_str()),
        ("statement.bai2", "bai2", bai2),
        ("statement-iso.bai2", "bai2", bai2_iso),
        ("statement.ofx", "ofx", ofx),
        ("statement.mt940", "mt940", mt940),
        ("statement-pipe.mt940", "mt940", mt940_pipe),
    ] {
        let imported = f.import(name, format, raw);
        println!("import {name} {format}: {}", imported.render());
        assert_eq!(text(data(&imported), "bank_format"), format, "{name}");
        let before = head(&f.book);
        let matched = ok_privileged(
            &f.book,
            &[
                "bank",
                "match",
                "--import",
                text(data(&imported), "manifest_oid"),
                "--date-window",
                "0",
            ],
        );
        let report = data(&matched);
        assert_eq!(
            integer(report, "proposed_count"),
            1,
            "{name}: {}",
            matched.render()
        );
        assert_eq!(integer(report, "unmatched_count"), 0, "{name}");
        assert_eq!(text(report, "closing_difference"), "0.00 USD", "{name}");
        let row = &rows(report, "proposals")[0];
        assert_eq!(text(row, "booking_date"), "2026-03-05", "{name}");
        assert_eq!(text(row, "value_date"), "2026-03-05", "{name}");
        assert_eq!(head(&f.book), before, "{name}: matching writes nothing");
    }
    let declared_csv = "Date;Description;Amount\r\n05/03/2026;WIRE-125;125,00\r\n";
    let declared_layout = r#"{"version":1,"name":"wire-125-v1","headers":["Date","Description","Amount"],"delimiter":";","decimal_separator":",","date_format":"DD/MM/YYYY","booking_date":"Date","reference":"Description","amount":{"column":"Amount","positive":"credit"},"statement":{"instrument_id":"GB29NWBK60161331926819","sequence_number":1,"currency":"USD","statement_date":"2026-03-31","opening_balance":"0,00","closing_balance":"125,00"}}"#;
    let declared_source = f.file("declared.csv", declared_csv);
    let declared_imported = ok(
        &f.book,
        &[
            "bank",
            "import",
            &declared_source,
            "--bank-format",
            "csv",
            "--account",
            "1000",
            "--layout",
            declared_layout,
        ],
    );
    assert_eq!(text(data(&declared_imported), "layout_name"), "wire-125-v1");
    let projections = ok(&f.book, &["verify", "projections"]);
    assert!(
        rows(data(&projections), "drift").is_empty(),
        "{projections:?}"
    );
}

#[test]
fn real_camt_date_choices_and_currency_attributes_import_and_match() {
    let f = Fixture::new();
    // These unresolved cash legs precede the first bank line and cancel in
    // the closing balance. A zero candidate count cannot attest that they
    // have been reconciled or that the outstanding inventory is complete.
    f.post("earlier-inflow", "2026-03-01", "debit", "20.00", "EARLY-IN");
    f.post(
        "earlier-outflow",
        "2026-03-01",
        "credit",
        "20.00",
        "EARLY-OUT",
    );
    f.post("camt-sale", "2026-03-05", "debit", "125.00", "WIRE-125");
    let statement = r#"<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt.053.001.08">
  <BkToCstmrStmt><Stmt><Id>March bank statement</Id><ElctrncSeqNb>1</ElctrncSeqNb>
    <Acct><Id><IBAN>GB29NWBK60161331926819</IBAN></Id><Ccy>USD</Ccy></Acct>
    <Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy="USD">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><Dt>2026-03-01</Dt></Dt></Bal>
    <Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy="USD">125.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><Dt>2026-03-31</Dt></Dt></Bal>
    <Ntry><Amt Ccy="USD">125.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Sts><Cd>BOOK</Cd></Sts>
      <BookgDt><Dt>2026-03-05</Dt></BookgDt><ValDt><Dt>2026-03-05</Dt></ValDt><AcctSvcrRef>WIRE-125</AcctSvcrRef>
      <NtryDtls><TxDtls><RltdPties><Dbtr><Pty><Nm>Customer &amp; Co</Nm></Pty></Dbtr></RltdPties></TxDtls></NtryDtls>
    </Ntry>
  </Stmt></BkToCstmrStmt>
</Document>"#;
    let intraday = statement
        .replace("camt.053", "camt.052")
        .replace("BkToCstmrStmt", "BkToCstmrAcctRpt")
        .replace("<Stmt>", "<Rpt>")
        .replace("</Stmt>", "</Rpt>")
        .replace("CLBD", "ITBD");
    for (format, raw) in [("camt053", statement), ("camt052", intraday.as_str())] {
        let imported = f.import(&format!("{format}.xml"), format, raw);
        assert_eq!(text(data(&imported), "bank_format"), format);
        let after_import = head(&f.book);
        let matched = ok_privileged(
            &f.book,
            &[
                "bank",
                "match",
                "--import",
                text(data(&imported), "manifest_oid"),
                "--date-window",
                "0",
            ],
        );
        let report = data(&matched);
        assert_eq!(integer(report, "proposed_count"), 1);
        assert_eq!(integer(report, "unmatched_count"), 0);
        assert_eq!(integer(report, "outstanding_count"), 0);
        assert_eq!(text(report, "candidate_from"), "2026-03-05");
        assert_eq!(text(report, "candidate_through"), "2026-03-31");
        assert_eq!(
            text(report, "outstanding_scope"),
            "unmatched_cash_legs_in_candidate_window"
        );
        assert_eq!(report.get("outstanding_complete"), Some(&Json::Bool(false)));
        assert_eq!(report.get("confirmed"), Some(&Json::Bool(false)));
        assert_eq!(text(report, "closing_difference"), "0.00 USD");
        assert_eq!(head(&f.book), after_import);
        let row = &rows(report, "proposals")[0];
        assert_eq!(text(row, "booking_date"), "2026-03-05");
        assert_eq!(text(row, "value_date"), "2026-03-05");
    }
    let entry_start = statement.find("<Ntry>").unwrap();
    let entry_end = statement.find("</Ntry>").unwrap() + "</Ntry>".len();
    let empty = format!("{}{}", &statement[..entry_start], &statement[entry_end..]).replace(
        "<Amt Ccy=\"USD\">0.00</Amt>",
        "<Amt Ccy=\"USD\">125.00</Amt>",
    );
    let imported = f.import("empty-camt053.xml", "camt053", &empty);
    let after_import = head(&f.book);
    let matched = ok_privileged(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            text(data(&imported), "manifest_oid"),
        ],
    );
    let report = data(&matched);
    assert_eq!(integer(report, "line_count"), 0);
    assert_eq!(integer(report, "proposed_count"), 0);
    assert_eq!(integer(report, "outstanding_count"), 0);
    assert_eq!(report.get("candidate_from"), Some(&Json::Null));
    assert_eq!(report.get("candidate_through"), Some(&Json::Null));
    assert_eq!(
        text(report, "outstanding_scope"),
        "unmatched_cash_legs_in_candidate_window"
    );
    assert_eq!(report.get("outstanding_complete"), Some(&Json::Bool(false)));
    assert_eq!(report.get("confirmed"), Some(&Json::Bool(false)));
    assert_eq!(text(report, "closing_difference"), "0.00 USD");
    assert_eq!(head(&f.book), after_import);
}

#[test]
fn an_ambiguous_candidate_set_cannot_emit_an_undecodable_decision_card() {
    let f = Fixture::new();
    let mut legs = vec![r#"{"side":"debit","account":"1000","amount":"1.00 USD"}"#; 43];
    legs.push(r#"{"side":"credit","account":"4000","amount":"43.00 USD"}"#);
    let intent = f.file(
        "many-candidates.json",
        &format!(
            r#"{{"effective_date":"2026-03-05","idempotency_key":"many-candidates","legs":[{}]}}"#,
            legs.join(",")
        ),
    );
    ok(
        &f.book,
        &["post", "--intent", &intent, "--evidence", &f.evidence],
    );
    let raw = format!(
        "{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,1.00,2026-03-05,2026-03-05,CRDT,1.00,Customer,\n"
    );
    let imported = f.import("ambiguous.csv", "csv", &raw);
    let before = head(&f.book);
    let (code, output) = run_privileged(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            text(data(&imported), "manifest_oid"),
        ],
    );
    assert_eq!(code, 2, "{}", output.render());
    assert_eq!(text(data(&output), "refusal_id"), "FA-REF-083");
    assert!(output.render().contains("decision card"));
    assert_eq!(head(&f.book), before);
}

#[test]
fn missing_bank_descriptions_remain_valid_robot_data_and_present_text_cites_its_document() {
    let f = Fixture::new();
    let raw = format!(
        "{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,1.00,2026-03-05,2026-03-05,CRDT,1.00,,\n"
    );
    let imported = f.import("no-descriptions.csv", "csv", &raw);
    let before = head(&f.book);
    let matched = ok_privileged(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            text(data(&imported), "manifest_oid"),
        ],
    );
    let proposal = &rows(data(&matched), "proposals")[0];
    assert_eq!(proposal.get("counterparty"), Some(&Json::Null));
    assert_eq!(proposal.get("reference"), Some(&Json::Null));
    assert_eq!(head(&f.book), before);

    let imported = f.import("described.csv", "csv", &statement_csv("95.00"));
    let matched = ok_privileged(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            text(data(&imported), "manifest_oid"),
        ],
    );
    for proposal in rows(data(&matched), "proposals") {
        let expected_source = format!("D:{}", text(proposal, "line_document_oid"));
        for field in ["counterparty", "reference"] {
            assert_eq!(
                text(proposal.get(field).unwrap(), "source"),
                expected_source
            );
        }
    }
}

#[test]
fn bank_ties_are_explicit_and_reference_selection_can_resolve_them() {
    let f = Fixture::new();
    f.post("same-one", "2026-03-05", "debit", "100.00", "ONE");
    f.post("same-two", "2026-03-05", "debit", "100.00", "TWO");
    let raw = format!(
        "{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,100.00,2026-03-05,2026-03-05,CRDT,100.00,,\n"
    );
    let imported = f.import("tie.csv", "csv", &raw);
    let before = head(&f.book);
    let matched = ok_privileged(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            text(data(&imported), "manifest_oid"),
            "--date-window",
            "0",
        ],
    );
    let report = data(&matched);
    assert_eq!(integer(report, "ambiguous_count"), 1);
    assert_eq!(integer(report, "proposed_count"), 1);
    assert_eq!(report.get("confirmed"), Some(&Json::Bool(false)));
    let row = &rows(report, "proposals")[0];
    assert_eq!(integer(row, "eligible_candidate_count"), 2);
    assert_eq!(row.get("ambiguous"), Some(&Json::Bool(true)));
    assert_eq!(row.get("competing_bank_lines"), Some(&Json::Bool(false)));
    assert_eq!(row.get("counterparty"), Some(&Json::Null));
    assert_eq!(row.get("reference"), Some(&Json::Null));
    assert_eq!(row.get("confirmation_command"), Some(&Json::Null));
    let selection = confirmation_args(&matched, 0, "tie-reviewer");
    let (status, refused) = run_privileged(
        &f.book,
        &selection.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_eq!(status, 3, "{}", refused.render());
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-168");
    assert_eq!(
        head(&f.book),
        before,
        "diagnostics and an ambiguous confirmation do not write"
    );

    let selective = raw.replace("100.00,,\n", "100.00,,one\n");
    let imported = f.import("specific-reference.csv", "csv", &selective);
    let matched = ok_privileged(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            text(data(&imported), "manifest_oid"),
            "--date-window",
            "0",
        ],
    );
    let row = &rows(data(&matched), "proposals")[0];
    assert_eq!(integer(data(&matched), "ambiguous_count"), 0);
    assert_eq!(integer(row, "eligible_candidate_count"), 1);
    assert_eq!(row.get("ambiguous"), Some(&Json::Bool(false)));
    assert!(text(row, "confirmation_command").contains("bank confirm"));
}

#[test]
fn a_consumed_cash_leg_does_not_hide_competition_between_statement_lines() {
    let f = Fixture::new();
    f.post("one-cash-leg", "2026-03-05", "debit", "100.00", "ONE");
    let raw = format!(
        "{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,200.00,2026-03-05,2026-03-05,CRDT,100.00,,\n1,BANK-123,USD,2026-03-31,0.00,200.00,2026-03-05,2026-03-05,CRDT,100.00,,\n"
    );
    let imported = f.import("competing-lines.csv", "csv", &raw);
    let before = head(&f.book);
    let matched = ok_privileged(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            text(data(&imported), "manifest_oid"),
            "--date-window",
            "0",
        ],
    );
    let report = data(&matched);
    assert_eq!(integer(report, "ambiguous_count"), 2);
    assert_eq!(integer(report, "proposed_count"), 1);
    assert_eq!(integer(report, "unmatched_count"), 1);
    assert_eq!(text(report, "closing_difference"), "100.00 USD");
    let proposals = rows(report, "proposals");
    assert_eq!(text(&proposals[0], "status"), "proposed");
    assert_eq!(text(&proposals[1], "status"), "unmatched");
    for row in proposals {
        assert_eq!(integer(row, "eligible_candidate_count"), 1);
        assert_eq!(row.get("ambiguous"), Some(&Json::Bool(true)));
        assert_eq!(row.get("competing_bank_lines"), Some(&Json::Bool(true)));
        assert_eq!(row.get("confirmation_command"), Some(&Json::Null));
    }
    let selection = confirmation_args(&matched, 0, "competition-reviewer");
    let (status, refused) = run_privileged(
        &f.book,
        &selection.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_eq!(status, 3, "{}", refused.render());
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-168");
    assert_eq!(head(&f.book), before);
}

#[test]
fn quoted_csv_descriptions_survive_retention_reopen_and_exact_matching() {
    let f = Fixture::new();
    f.post("quoted-reference", "2026-03-05", "debit", "1.00", "SALE,1");
    let raw = format!(
        "{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,1.00,2026-03-05,2026-03-05,CRDT,1.00,\"Acme,\n\"\"Ltd\"\"\",\"SALE,1\"\n"
    );
    let imported = f.import("quoted-fields.csv", "csv", &raw);
    let manifest = text(data(&imported), "manifest_oid");
    assert_eq!(integer(data(&imported), "line_count"), 1);
    let after_import = head(&f.book);
    let source = ok_privileged(
        &f.book,
        &["document", "read", text(data(&imported), "statement_oid")],
    );
    assert_eq!(
        text(data(&source).get("text").unwrap(), "untrusted_content"),
        raw,
    );
    let matched = ok_privileged(
        &f.book,
        &["bank", "match", "--import", manifest, "--date-window", "0"],
    );
    assert_eq!(integer(data(&matched), "proposed_count"), 1);
    assert_eq!(integer(data(&matched), "ambiguous_count"), 0);
    assert_eq!(text(data(&matched), "closing_difference"), "0.00 USD");
    let row = &rows(data(&matched), "proposals")[0];
    assert_eq!(
        text(row.get("counterparty").unwrap(), "untrusted_content"),
        "Acme,\n\"Ltd\"",
    );
    assert_eq!(
        text(row.get("reference").unwrap(), "untrusted_content"),
        "SALE,1",
    );
    let source = format!("D:{}", text(row, "line_document_oid"));
    assert_eq!(text(row.get("counterparty").unwrap(), "source"), source);
    assert_eq!(text(row.get("reference").unwrap(), "source"), source);
    assert_eq!(head(&f.book), after_import);
    let repeated = f.import("quoted-fields-again.csv", "csv", &raw);
    assert_eq!(text(data(&repeated), "manifest_oid"), manifest);
    assert_eq!(
        data(&repeated).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(head(&f.book), after_import);
}

fn continuity_csv(
    sequence: u64,
    bank: &str,
    date: &str,
    opening: &str,
    closing: &str,
    reference: &str,
) -> String {
    format!(
        "{CSV_HEADER}{sequence},{bank},USD,{date},{opening},{closing},{date},{date},CRDT,25.00,Customer,{reference}\n"
    )
}

fn linked_import(f: &Fixture, name: &str, raw: &str, previous: &str) -> Json {
    let path = f.file(name, raw);
    ok_privileged(
        &f.book,
        &[
            "bank",
            "import",
            &path,
            "--bank-format",
            "csv",
            "--account",
            "1000",
            "--previous-import",
            previous,
        ],
    )
}

#[test]
fn explicit_predecessors_bind_original_receipts_and_replay_the_retained_chain() {
    let f = Fixture::new();
    let first = f.import(
        "chain-first.csv",
        "csv",
        &continuity_csv(10, "BANK-CHAIN", "2026-03-31", "0.00", "25.00", "FIRST"),
    );
    let first_data = data(&first);
    let first_oid = text(first_data, "manifest_oid");
    assert_eq!(text(first_data, "continuity"), "unlinked");
    assert_eq!(integer(first_data, "verified_predecessors"), 0);
    assert_eq!(first_data.get("predecessor"), Some(&Json::Null));

    let second_raw = continuity_csv(11, "BANK-CHAIN", "2026-04-30", "25.00", "50.00", "SECOND");
    let before = head(&f.book);
    let path = f.file("second-unprivileged.csv", &second_raw);
    let (status, refusal) = run(
        &f.book,
        &[
            "bank",
            "import",
            &path,
            "--bank-format",
            "csv",
            "--account",
            "1000",
            "--previous-import",
            first_oid,
        ],
    );
    assert_ne!(
        status, 0,
        "replaying retained source requires explicit disclosure authority"
    );
    assert!(refusal.render().contains("privileged"));
    assert_eq!(head(&f.book), before);

    let second = linked_import(&f, "chain-second.csv", &second_raw, first_oid);
    let second_data = data(&second);
    assert_eq!(
        head(&f.book),
        before + 1,
        "link, documents, native provenance and import publish together"
    );
    assert_eq!(text(second_data, "continuity"), "verified_predecessor");
    assert_eq!(integer(second_data, "verified_predecessors"), 1);
    let predecessor = second_data.get("predecessor").unwrap();
    assert_eq!(text(predecessor, "manifest_oid"), first_oid);
    assert_eq!(
        text(predecessor, "statement_oid"),
        text(first_data, "statement_oid")
    );
    assert_eq!(
        text(predecessor, "statement_commit"),
        text(first_data, "statement_commit")
    );
    assert_eq!(
        text(predecessor, "receipt_hash"),
        text(first_data, "receipt_hash")
    );
    assert_eq!(
        integer(predecessor, "recorded_at"),
        integer(first_data, "recorded_at")
    );
    assert_eq!(integer(predecessor, "sequence_number"), 10);
    assert_eq!(text(predecessor, "closing_balance"), "25.00 USD");

    let after = head(&f.book);
    let other_path = f.file("chain-second-retry.csv", &second_raw);
    let repeated = ok_privileged(
        &f.book,
        &[
            "bank",
            "import",
            &other_path,
            "--bank-format",
            "csv",
            "--account",
            "1000",
            "--previous-import",
            first_oid,
            "--as",
            "another-authorized-uploader",
        ],
    );
    assert_eq!(
        data(&repeated).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        text(data(&repeated), "manifest_oid"),
        text(second_data, "manifest_oid")
    );
    assert_eq!(
        text(data(&repeated), "receipt_hash"),
        text(second_data, "receipt_hash")
    );
    assert_eq!(
        data(&repeated).get("predecessor"),
        second_data.get("predecessor")
    );
    assert_eq!(head(&f.book), after);

    let third = linked_import(
        &f,
        "chain-third.csv",
        &continuity_csv(12, "BANK-CHAIN", "2026-05-31", "50.00", "75.00", "THIRD"),
        text(second_data, "manifest_oid"),
    );
    assert_eq!(integer(data(&third), "verified_predecessors"), 2);
    let before_match = head(&f.book);
    let matched = ok_privileged(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            text(data(&third), "manifest_oid"),
        ],
    );
    assert_eq!(integer(data(&matched), "verified_predecessors"), 2);
    assert_eq!(text(data(&matched), "continuity"), "verified_predecessor");
    assert_eq!(data(&matched).get("confirmed"), Some(&Json::Bool(false)));
    assert_eq!(
        head(&f.book),
        before_match,
        "continuity replay does not confirm reconciliation"
    );
    let original = ok_privileged(&f.book, &["bank", "match", "--import", first_oid]);
    assert_eq!(
        text(data(&original), "continuity"),
        "unlinked",
        "v1 remains explicitly readable"
    );
    assert_eq!(integer(data(&original), "verified_predecessors"), 0);
}

#[test]
fn predecessor_mismatches_refuse_without_publishing_any_new_import() {
    let f = Fixture::new();
    let first_raw = continuity_csv(20, "BANK-STRICT", "2026-03-31", "0.00", "25.00", "FIRST");
    let first = f.import("strict-first.csv", "csv", &first_raw);
    let previous = text(data(&first), "manifest_oid");
    let before = head(&f.book);
    for (name, raw) in [
        (
            "gap",
            continuity_csv(22, "BANK-STRICT", "2026-04-30", "25.00", "50.00", "NEXT"),
        ),
        (
            "opening",
            continuity_csv(21, "BANK-STRICT", "2026-04-30", "20.00", "45.00", "NEXT"),
        ),
        (
            "date",
            continuity_csv(21, "BANK-STRICT", "2026-03-20", "25.00", "50.00", "NEXT"),
        ),
        (
            "bank",
            continuity_csv(21, "DIFFERENT-BANK", "2026-04-30", "25.00", "50.00", "NEXT"),
        ),
        ("self", first_raw),
    ] {
        let path = f.file(&format!("strict-{name}.csv"), &raw);
        let (status, refusal) = run_privileged(
            &f.book,
            &[
                "bank",
                "import",
                &path,
                "--bank-format",
                "csv",
                "--account",
                "1000",
                "--previous-import",
                previous,
            ],
        );
        assert_eq!(status, 3, "{name}: {}", refusal.render());
        assert_eq!(
            text(data(&refusal), "refusal_id"),
            "FA-REF-165",
            "{name}: a continuity failure is an accounting refusal, not a malformed upload"
        );
        assert_eq!(
            head(&f.book),
            before,
            "{name} must not record its source, manifest or run"
        );
    }
    let overflow = f.import(
        "overflow-first.csv",
        "csv",
        &continuity_csv(
            u64::MAX,
            "BANK-OVERFLOW",
            "2026-03-31",
            "0.00",
            "25.00",
            "LAST",
        ),
    );
    let overflow_head = head(&f.book);
    let path = f.file(
        "overflow-next.csv",
        &continuity_csv(
            0,
            "BANK-OVERFLOW",
            "2026-04-30",
            "25.00",
            "50.00",
            "WRAPPED",
        ),
    );
    let (status, refusal) = run_privileged(
        &f.book,
        &[
            "bank",
            "import",
            &path,
            "--bank-format",
            "csv",
            "--account",
            "1000",
            "--previous-import",
            text(data(&overflow), "manifest_oid"),
        ],
    );
    assert_eq!(
        status,
        3,
        "sequence addition must not wrap: {}",
        refusal.render()
    );
    assert_eq!(text(data(&refusal), "refusal_id"), "FA-REF-165");
    assert_eq!(head(&f.book), overflow_head);
}

#[test]
fn a_valid_alternative_predecessor_cannot_fork_an_already_linked_statement() {
    let f = Fixture::new();
    let left = f.import(
        "fork-left.csv",
        "csv",
        &continuity_csv(1, "BANK-FORK", "2026-03-31", "0.00", "25.00", "LEFT"),
    );
    let right = f.import(
        "fork-right.csv",
        "csv",
        &continuity_csv(1, "BANK-FORK", "2026-03-31", "0.00", "25.00", "RIGHT"),
    );
    let raw = continuity_csv(2, "BANK-FORK", "2026-04-30", "25.00", "50.00", "NEXT");
    let selected = linked_import(&f, "fork-next.csv", &raw, text(data(&left), "manifest_oid"));
    let before = head(&f.book);
    let path = f.file("fork-conflict.csv", &raw);
    let (status, refusal) = run_privileged(
        &f.book,
        &[
            "bank",
            "import",
            &path,
            "--bank-format",
            "csv",
            "--account",
            "1000",
            "--previous-import",
            text(data(&right), "manifest_oid"),
            "--as",
            "different-uploader",
        ],
    );
    assert_ne!(status, 0);
    assert_eq!(
        text(data(&refusal), "refusal_id"),
        fa_journal::refusal::code::IDEMPOTENCY_CONFLICT
    );
    assert!(
        refusal
            .render()
            .contains(text(data(&selected), "manifest_oid"))
    );
    assert_eq!(head(&f.book), before);

    let (status, refusal) = run(
        &f.book,
        &[
            "bank",
            "import",
            &path,
            "--bank-format",
            "csv",
            "--account",
            "1000",
        ],
    );
    assert_ne!(
        status, 0,
        "omitting the predecessor cannot replace a recorded choice"
    );
    assert_eq!(
        text(data(&refusal), "refusal_id"),
        fa_journal::refusal::code::IDEMPOTENCY_CONFLICT
    );
    assert_eq!(head(&f.book), before);
}

#[test]
fn an_unlinked_import_recorded_before_its_statement_was_linked_retries_to_its_receipt() {
    // Import unlinked first and link later (the continuity refusal's fix
    // offers exactly that). An exact repeat of the original unlinked import
    // is still the recorded import, not a competing choice: it returns the
    // original receipt and publishes nothing. A new unlinked import of a
    // linked statement stays refused (the fork test above).
    let f = Fixture::new();
    let first = f.import(
        "retry-first.csv",
        "csv",
        &continuity_csv(30, "BANK-RETRY", "2026-03-31", "0.00", "25.00", "FIRST"),
    );
    let raw = continuity_csv(31, "BANK-RETRY", "2026-04-30", "25.00", "50.00", "NEXT");
    let unlinked = f.import("retry-next.csv", "csv", &raw);
    assert_eq!(text(data(&unlinked), "continuity"), "unlinked");
    let linked = linked_import(
        &f,
        "retry-next-linked.csv",
        &raw,
        text(data(&first), "manifest_oid"),
    );
    assert_eq!(text(data(&linked), "continuity"), "verified_predecessor");
    assert_ne!(
        text(data(&linked), "manifest_oid"),
        text(data(&unlinked), "manifest_oid")
    );
    let after = head(&f.book);
    let repeated = f.import("retry-next-again.csv", "csv", &raw);
    assert_eq!(
        data(&repeated).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        text(data(&repeated), "manifest_oid"),
        text(data(&unlinked), "manifest_oid")
    );
    assert_eq!(
        text(data(&repeated), "receipt_hash"),
        text(data(&unlinked), "receipt_hash")
    );
    assert_eq!(text(data(&repeated), "continuity"), "unlinked");
    assert_eq!(head(&f.book), after);
}

fn unmatch_args(confirmed: &Json) -> Vec<String> {
    let recorded = data(confirmed);
    vec![
        "bank".into(),
        "unmatch".into(),
        "--match".into(),
        text(recorded, "match_vid").into(),
        "--digest".into(),
        text(recorded, "match_digest").into(),
    ]
}

#[test]
fn explicit_unmatch_retains_history_retries_and_allows_a_fresh_confirmation() {
    let f = Fixture::new();
    f.post("release-sale", "2026-03-05", "debit", "100.00", "RELEASE");
    let source = format!(
        "{CSV_HEADER}1,BANK-RELEASE,USD,2026-03-31,0.00,100.00,2026-03-05,2026-03-05,CRDT,100.00,Customer,RELEASE\n"
    );
    let imported = f.import("release.csv", "csv", &source);
    let manifest = text(data(&imported), "manifest_oid");
    let money_before = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    let available_progress = [
        ("0.00", "0.00"),
        ("0.00", "0.00"),
        ("100.00", "0.00"),
        ("100.00", "0.00"),
        ("0.00", "0.00"),
        ("0.00", "0.00"),
    ];
    let confirmed_progress = [
        ("100.00", "0.00"),
        ("0.00", "0.00"),
        ("0.00", "0.00"),
        ("0.00", "0.00"),
        ("0.00", "0.00"),
        ("0.00", "0.00"),
    ];
    assert_progress(&matched, available_progress, 1, false, true);
    let initial_proposal = &rows(data(&matched), "proposals")[0];
    let original_args = confirmation_args(&matched, 0, "release-reviewer");
    let first = confirm_selection(&f.book, &original_args);
    let first_at = integer(data(&first), "recorded_at");
    let before = head(&f.book);

    // History is an authorized metadata fold; full source status keeps its
    // separate governed disclosure requirement.
    let history = ok(&f.book, &["bank", "history", "--import", manifest]);
    assert_eq!(text(&history, "event"), "bank_match_history");
    assert_eq!(text(data(&history), "scope"), "match_history");
    assert_eq!(integer(data(&history), "confirmation_count"), 1);
    assert_eq!(integer(data(&history), "unmatch_count"), 0);
    assert_eq!(integer(data(&history), "active_count"), 1);
    assert_eq!(
        rows(data(&history), "active")[0].get("match_vid"),
        data(&first).get("match_vid")
    );
    let (status, _) = run(&f.book, &["bank", "status", "--import", manifest]);
    assert_ne!(
        status, 0,
        "full-source status still requires governed disclosure"
    );
    assert_eq!(head(&f.book), before);

    let claimed = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    assert_eq!(integer(data(&claimed), "confirmed_count"), 1);
    assert_eq!(integer(data(&claimed), "unmatched_count"), 0);
    assert_eq!(integer(data(&claimed), "outstanding_count"), 0);
    assert_progress(&claimed, confirmed_progress, 0, true, true);
    let retained = &rows(data(&claimed), "proposals")[0];
    assert_eq!(text(retained, "status"), "confirmed");
    assert_eq!(retained.get("confirmation_command"), Some(&Json::Null));
    for key in [
        "entry_ref",
        "leg_ordinal",
        "candidate_ordinal",
        "decision_card",
        "decision_card_digest",
        "proposal_digest",
        "proposer",
    ] {
        assert_eq!(
            retained.get(key),
            initial_proposal.get(key),
            "original {key}"
        );
    }
    assert_eq!(
        retained.get("confirmed_match").unwrap().get("match_vid"),
        data(&first).get("match_vid")
    );

    let args = unmatch_args(&first);
    let argv: Vec<_> = args.iter().map(String::as_str).collect();
    let (status, refusal) = run(&f.book, &argv);
    assert_ne!(status, 0, "unmatch must be explicitly acknowledged");
    assert!(refusal.render().contains("--yes"));
    assert_eq!(head(&f.book), before);
    let wrong_digest = "ab".repeat(32);
    let (status, _) = run(
        &f.book,
        &[
            "bank",
            "unmatch",
            "--match",
            text(data(&first), "match_vid"),
            "--digest",
            &wrong_digest,
            "--yes",
        ],
    );
    assert_ne!(
        status, 0,
        "a release must bind the exact original match digest"
    );
    assert_eq!(head(&f.book), before);

    let mut release_args = args.clone();
    release_args.push("--yes".into());
    let release_argv: Vec<_> = release_args.iter().map(String::as_str).collect();
    let release = ok(&f.book, &release_argv);
    assert_eq!(text(&release, "event"), "bank_match_unmatched");
    let released = data(&release);
    assert_eq!(integer(released, "recorded_at"), before + 1);
    assert_eq!(released.get("already_recorded"), Some(&Json::Bool(false)));
    assert_eq!(
        released.get("target").unwrap().get("vid"),
        data(&first).get("match_vid")
    );
    assert_eq!(
        released.get("target").unwrap().get("digest"),
        data(&first).get("match_digest")
    );
    let released_at = head(&f.book);
    let retry = ok(&f.book, &release_argv);
    assert_eq!(
        data(&retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    for key in [
        "unmatch_vid",
        "unmatch_digest",
        "recorded_at",
        "target",
        "unmatched_by",
    ] {
        assert_eq!(
            data(&retry).get(key),
            released.get(key),
            "release retry {key}"
        );
    }
    assert_eq!(head(&f.book), released_at);

    let original_retry = confirm_selection(&f.book, &original_args);
    assert_eq!(
        data(&original_retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        data(&original_retry).get("match_vid"),
        data(&first).get("match_vid")
    );
    assert_eq!(head(&f.book), released_at);
    let released_history = ok(&f.book, &["bank", "history", "--import", manifest]);
    assert_eq!(integer(data(&released_history), "confirmation_count"), 1);
    assert_eq!(integer(data(&released_history), "unmatch_count"), 1);
    assert_eq!(integer(data(&released_history), "active_count"), 0);
    let historical = ok(
        &f.book,
        &[
            "bank",
            "history",
            "--import",
            manifest,
            "--as-known-at",
            &first_at.to_string(),
        ],
    );
    assert_eq!(integer(data(&historical), "known_at"), first_at);
    assert_eq!(
        integer(historical.get("coordinate").unwrap(), "known_at"),
        first_at
    );
    assert_eq!(integer(data(&historical), "active_count"), 1);
    assert_eq!(integer(data(&historical), "unmatch_count"), 0);
    let historical_match = ok_privileged(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            manifest,
            "--as-known-at",
            &first_at.to_string(),
        ],
    );
    assert_progress(&historical_match, confirmed_progress, 0, true, true);

    let fresh = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    assert_progress(&fresh, available_progress, 1, false, true);
    assert_eq!(integer(data(&fresh), "confirmed_count"), 0);
    assert_eq!(
        text(&rows(data(&fresh), "proposals")[0], "status"),
        "proposed"
    );
    let second = confirm_selection(&f.book, &confirmation_args(&fresh, 0, "fresh-reviewer"));
    assert_ne!(
        data(&second).get("match_vid"),
        data(&first).get("match_vid")
    );
    assert!(integer(data(&second), "source_known_at") >= released_at);
    let history = ok(&f.book, &["bank", "history", "--import", manifest]);
    assert_eq!(integer(data(&history), "confirmation_count"), 2);
    assert_eq!(integer(data(&history), "unmatch_count"), 1);
    assert_eq!(integer(data(&history), "active_count"), 1);
    assert_eq!(
        rows(data(&history), "active")[0].get("match_vid"),
        data(&second).get("match_vid")
    );
    let rematched = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    assert_progress(&rematched, confirmed_progress, 0, true, true);
    let historical_release = ok_privileged(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            manifest,
            "--as-known-at",
            &released_at.to_string(),
        ],
    );
    assert_progress(&historical_release, available_progress, 1, false, true);

    let current_head = head(&f.book);
    let retry_old_release = ok(&f.book, &release_argv);
    assert_eq!(
        data(&retry_old_release).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(head(&f.book), current_head);
    let source_status = ok_privileged(&f.book, &["bank", "status", "--import", manifest]);
    assert_eq!(
        text(data(&source_status), "scope"),
        "recorded_confirmations"
    );
    assert_eq!(integer(data(&source_status), "line_count"), 1);
    assert_eq!(integer(data(&source_status), "confirmed_lines"), 1);
    assert_eq!(integer(data(&source_status), "remaining_lines"), 0);
    assert_eq!(rows(data(&source_status), "confirmations").len(), 2);
    assert_eq!(
        data(&source_status).get("reconciled_through"),
        Some(&Json::Null)
    );
    let money_after = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    for key in ["rows", "unit_totals", "pending_unit_totals", "balanced"] {
        assert_eq!(
            data(&money_after).get(key),
            data(&money_before).get(key),
            "unchanged {key}"
        );
    }
}

#[test]
fn reports_exclude_other_statements_cash_claims_until_an_explicit_release() {
    let f = Fixture::new();
    f.post("global-cash", "2026-03-05", "debit", "50.00", "GLOBAL");
    let source = |sequence| {
        format!(
            "{CSV_HEADER}{sequence},BANK-GLOBAL,USD,2026-03-31,0.00,50.00,2026-03-05,2026-03-05,CRDT,50.00,Customer,GLOBAL\n"
        )
    };
    let first_import = f.import("global-first.csv", "csv", &source(1));
    let second_import = f.import("global-second.csv", "csv", &source(2));
    let first_manifest = text(data(&first_import), "manifest_oid");
    let second_manifest = text(data(&second_import), "manifest_oid");
    let first_report = ok_privileged(&f.book, &["bank", "match", "--import", first_manifest]);
    let second_report = ok_privileged(&f.book, &["bank", "match", "--import", second_manifest]);
    let stale_args = confirmation_args(&second_report, 0, "other-reviewer");
    let first = confirm_selection(
        &f.book,
        &confirmation_args(&first_report, 0, "first-reviewer"),
    );

    let occupied = ok_privileged(&f.book, &["bank", "match", "--import", second_manifest]);
    let row = &rows(data(&occupied), "proposals")[0];
    assert_eq!(text(row, "status"), "unmatched");
    assert_eq!(integer(row, "eligible_candidate_count"), 0);
    assert_eq!(row.get("confirmation_command"), Some(&Json::Null));
    assert_eq!(integer(data(&occupied), "confirmed_count"), 0);
    assert_eq!(integer(data(&occupied), "outstanding_count"), 0);
    // A cash leg used by another statement makes this line unmatched. It
    // does not confirm or occupy this distinct retained source identity.
    assert_progress(
        &occupied,
        [
            ("0.00", "0.00"),
            ("0.00", "0.00"),
            ("50.00", "0.00"),
            ("0.00", "0.00"),
            ("50.00", "0.00"),
            ("0.00", "0.00"),
        ],
        1,
        false,
        true,
    );
    let mut release_args = unmatch_args(&first);
    release_args.push("--yes".into());
    ok(
        &f.book,
        &release_args.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    let before = head(&f.book);
    let (status, _) = run_privileged(
        &f.book,
        &stale_args.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_ne!(
        status, 0,
        "the new cash generation requires a post-release review"
    );
    assert_eq!(head(&f.book), before);

    let fresh = ok_privileged(&f.book, &["bank", "match", "--import", second_manifest]);
    assert_progress(
        &fresh,
        [
            ("0.00", "0.00"),
            ("0.00", "0.00"),
            ("50.00", "0.00"),
            ("50.00", "0.00"),
            ("0.00", "0.00"),
            ("0.00", "0.00"),
        ],
        1,
        false,
        true,
    );
    assert_eq!(
        integer(
            &rows(data(&fresh), "proposals")[0],
            "eligible_candidate_count"
        ),
        1
    );
    let second = confirm_selection(&f.book, &confirmation_args(&fresh, 0, "other-reviewer"));
    assert_eq!(
        data(&second).get("entry_ref"),
        data(&first).get("entry_ref")
    );
    assert_eq!(
        data(&second).get("leg_ordinal"),
        data(&first).get("leg_ordinal")
    );
    let first_history = ok(&f.book, &["bank", "history", "--import", first_manifest]);
    assert_eq!(integer(data(&first_history), "confirmation_count"), 1);
    assert_eq!(integer(data(&first_history), "unmatch_count"), 1);
    assert_eq!(integer(data(&first_history), "active_count"), 0);
    let second_history = ok(&f.book, &["bank", "history", "--import", second_manifest]);
    assert_eq!(integer(data(&second_history), "confirmation_count"), 1);
    assert_eq!(integer(data(&second_history), "unmatch_count"), 0);
    assert_eq!(integer(data(&second_history), "active_count"), 1);
    let all_history = ok(&f.book, &["bank", "history", "--account", "1000"]);
    assert_eq!(text(data(&all_history), "account"), "1000");
    assert_eq!(integer(data(&all_history), "confirmation_count"), 2);
    assert_eq!(integer(data(&all_history), "unmatch_count"), 1);
    assert_eq!(integer(data(&all_history), "active_count"), 1);
}

#[test]
fn equal_closing_balances_do_not_clear_offsetting_unconfirmed_flows() {
    let f = Fixture::new();
    f.post("offset-in", "2026-03-05", "debit", "10.00", "OFFSET-IN");
    f.post("offset-out", "2026-03-06", "credit", "10.00", "OFFSET-OUT");
    let source = format!(
        "{CSV_HEADER}1,BANK-OFFSET,USD,2026-03-31,0.00,0.00,2026-03-05,2026-03-05,CRDT,10.00,Customer,OFFSET-IN\n1,BANK-OFFSET,USD,2026-03-31,0.00,0.00,2026-03-06,2026-03-06,DBIT,10.00,Vendor,OFFSET-OUT\n"
    );
    let imported = f.import("offset.csv", "csv", &source);
    let manifest = text(data(&imported), "manifest_oid");
    let money_before = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    let before_confirmation = integer(data(&matched), "known_at");
    assert_eq!(
        text(data(&matched), "statement_closing_balance"),
        "0.00 USD"
    );
    assert_eq!(text(data(&matched), "book_closing_balance"), "0.00 USD");
    assert_eq!(text(data(&matched), "closing_difference"), "0.00 USD");
    assert_progress(
        &matched,
        [
            ("0.00", "0.00"),
            ("0.00", "0.00"),
            ("10.00", "10.00"),
            ("10.00", "10.00"),
            ("0.00", "0.00"),
            ("0.00", "0.00"),
        ],
        2,
        false,
        true,
    );

    confirm_selection(&f.book, &confirmation_args(&matched, 0, "inflow-reviewer"));
    let partial = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    assert_progress(
        &partial,
        [
            ("10.00", "0.00"),
            ("0.00", "0.00"),
            ("0.00", "10.00"),
            ("0.00", "10.00"),
            ("0.00", "0.00"),
            ("0.00", "0.00"),
        ],
        1,
        false,
        true,
    );
    confirm_selection(&f.book, &confirmation_args(&partial, 1, "outflow-reviewer"));
    let complete = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    assert_progress(
        &complete,
        [
            ("10.00", "10.00"),
            ("0.00", "0.00"),
            ("0.00", "0.00"),
            ("0.00", "0.00"),
            ("0.00", "0.00"),
            ("0.00", "0.00"),
        ],
        0,
        true,
        true,
    );
    let historical = ok_privileged(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            manifest,
            "--as-known-at",
            &before_confirmation.to_string(),
        ],
    );
    assert_eq!(
        data(&historical).get("progress"),
        data(&matched).get("progress")
    );
    assert_eq!(integer(data(&historical), "remaining_count"), 2);
    let money_after = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    for key in ["rows", "unit_totals", "pending_unit_totals", "balanced"] {
        assert_eq!(data(&money_after).get(key), data(&money_before).get(key));
    }
}

#[test]
fn the_same_statement_under_another_cash_mapping_remains_occupied_until_release() {
    let f = Fixture::with_chart(
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"1010","name":"Alternate cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"},{"code":"6000","name":"Expenses","type":"Expense","unit":"USD"}]}"#,
    );
    f.post("mapped-cash", "2026-03-05", "debit", "40.00", "MAPPED");
    let alternate = f.file(
        "alternate-cash.json",
        r#"{"effective_date":"2026-03-05","idempotency_key":"alternate-cash","legs":[{"side":"debit","account":"1010","amount":"40.00 USD","memo":"MAPPED"},{"side":"credit","account":"4000","amount":"40.00 USD"}]}"#,
    );
    ok(
        &f.book,
        &["post", "--intent", &alternate, "--evidence", &f.evidence],
    );
    let source = format!(
        "{CSV_HEADER}1,BANK-MAPPED,USD,2026-03-31,0.00,40.00,2026-03-05,2026-03-05,CRDT,40.00,Customer,MAPPED\n"
    );
    let original_import = f.import("original-mapping.csv", "csv", &source);
    let alternate_source = f.file("alternate-mapping.csv", &source);
    let alternate_import = ok(
        &f.book,
        &[
            "bank",
            "import",
            &alternate_source,
            "--bank-format",
            "csv",
            "--account",
            "1010",
        ],
    );
    let original_manifest = text(data(&original_import), "manifest_oid");
    let alternate_manifest = text(data(&alternate_import), "manifest_oid");
    assert_ne!(original_manifest, alternate_manifest);
    assert_eq!(
        text(data(&original_import), "statement_oid"),
        text(data(&alternate_import), "statement_oid")
    );
    let money_before = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    let original = ok_privileged(&f.book, &["bank", "match", "--import", original_manifest]);
    let alternate = ok_privileged(&f.book, &["bank", "match", "--import", alternate_manifest]);
    let available_progress = [
        ("0.00", "0.00"),
        ("0.00", "0.00"),
        ("40.00", "0.00"),
        ("40.00", "0.00"),
        ("0.00", "0.00"),
        ("0.00", "0.00"),
    ];
    let occupied_progress = [
        ("0.00", "0.00"),
        ("40.00", "0.00"),
        ("40.00", "0.00"),
        ("0.00", "0.00"),
        ("0.00", "0.00"),
        ("40.00", "0.00"),
    ];
    assert_progress(&alternate, available_progress, 1, false, true);
    let original_at = integer(data(&alternate), "known_at");
    let first = confirm_selection(
        &f.book,
        &confirmation_args(&original, 0, "original-reviewer"),
    );
    let occupied = ok_privileged(&f.book, &["bank", "match", "--import", alternate_manifest]);
    assert_eq!(text(data(&occupied), "account"), "1010");
    assert_eq!(integer(data(&occupied), "confirmed_count"), 0);
    assert_eq!(integer(data(&occupied), "occupied_count"), 1);
    assert_eq!(integer(data(&occupied), "proposed_count"), 0);
    assert_eq!(integer(data(&occupied), "unmatched_count"), 0);
    assert_eq!(integer(data(&occupied), "outstanding_count"), 1);
    let row = &rows(data(&occupied), "proposals")[0];
    assert_eq!(text(row, "status"), "occupied");
    assert_eq!(row.get("confirmation_command"), Some(&Json::Null));
    assert_progress(&occupied, occupied_progress, 1, false, true);
    let historical = ok_privileged(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            alternate_manifest,
            "--as-known-at",
            &original_at.to_string(),
        ],
    );
    assert_progress(&historical, available_progress, 1, false, true);

    let mut release_args = unmatch_args(&first);
    release_args.push("--yes".into());
    ok(
        &f.book,
        &release_args.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    let available = ok_privileged(&f.book, &["bank", "match", "--import", alternate_manifest]);
    assert_progress(&available, available_progress, 1, false, true);
    let second = confirm_selection(
        &f.book,
        &confirmation_args(&available, 0, "alternate-reviewer"),
    );
    assert_ne!(
        data(&first).get("entry_ref"),
        data(&second).get("entry_ref")
    );
    let occupied_original =
        ok_privileged(&f.book, &["bank", "match", "--import", original_manifest]);
    assert_progress(&occupied_original, occupied_progress, 1, false, true);
    let money_after = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    for key in ["rows", "unit_totals", "pending_unit_totals", "balanced"] {
        assert_eq!(data(&money_after).get(key), data(&money_before).get(key));
    }
}

/// fa-lzrn: a saved `fwc plaid transactions_sync` robot payload imports with
/// `--bank-format plaid-sync`. It is retained as the BankStatement, its two
/// lines parse with exact amounts, an exact repeat returns the original
/// receipt, and its lines propose exact matches against posted cash like any
/// statement's. A payload whose activity does not reach its closing balance,
/// or that another connector produced, is refused with nothing written.
#[test]
fn a_plaid_transactions_sync_payload_imports_and_matches_like_a_statement() {
    const PLAID: &str =
        include_str!("../../fa-formats/corpora/fwc_plaid_transactions_sync_fixture.json");
    let f = Fixture::new();
    f.post("plaid-sale", "2026-03-10", "debit", "500.00", "INV-100");
    f.post("plaid-bill", "2026-03-15", "credit", "250.00", "BILL-200");
    let before = head(&f.book);
    for (name, payload) in [
        (
            "unbalanced.json",
            PLAID.replace(
                "\"closing_balance\": \"1250.00\"",
                "\"closing_balance\": \"1300.00\"",
            ),
        ),
        (
            "other-connector.json",
            PLAID.replace("\"connector\": \"plaid\"", "\"connector\": \"stripe\""),
        ),
    ] {
        assert_ne!(payload, PLAID, "{name}: the planted change applies");
        let path = f.file(name, &payload);
        let (exit, refused) = run(
            &f.book,
            &[
                "bank",
                "import",
                &path,
                "--bank-format",
                "plaid-sync",
                "--account",
                "1000",
            ],
        );
        assert_eq!(exit, 2, "{name}: {}", refused.render());
        assert_eq!(head(&f.book), before, "{name}: nothing is written");
    }
    let imported = f.import("plaid.json", "plaid-sync", PLAID);
    let report = data(&imported);
    assert_eq!(text(report, "bank_format"), "plaid-sync");
    assert_eq!(integer(report, "line_count"), 2);
    assert_eq!(text(report, "opening_balance"), "1000.00 USD");
    assert_eq!(text(report, "closing_balance"), "1250.00 USD");
    assert_eq!(text(report, "statement_date"), "2026-03-31");
    assert_eq!(report.get("already_recorded"), Some(&Json::Bool(false)));
    let manifest = text(report, "manifest_oid").to_string();
    let again = f.import("plaid-again.json", "plaid-sync", PLAID);
    assert_eq!(
        data(&again).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(text(data(&again), "manifest_oid"), manifest);
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", &manifest]);
    assert_eq!(
        rows(data(&matched), "proposals").len(),
        2,
        "{}",
        matched.render()
    );
}

/// fa-lzrn: `fa bank fetch --connector plaid` runs the host's `fwc` (here a
/// stand-in on a private PATH that checks its exact argv) after admission,
/// and retains its payload as a plaid-sync statement. Importing the same
/// payload from a file afterwards is the recorded receipt, so the fetched
/// bytes are what was retained. Planted: with no `fwc` on PATH, or an `fwc`
/// that fails, the fetch did not run (exit 4) and nothing is written; a
/// connector without a bank feed parser is a usage error.
#[cfg(unix)]
#[test]
fn bank_fetch_runs_the_hosts_fwc_and_retains_its_payload() {
    use std::os::unix::fs::PermissionsExt;
    const PLAID: &str =
        include_str!("../../fa-formats/corpora/fwc_plaid_transactions_sync_fixture.json");
    let f = Fixture::new();
    let payload = f.file("plaid-payload.json", PLAID);
    let bin = f.dir.join("bin");
    let empty = f.dir.join("empty");
    std::fs::create_dir(&bin).unwrap();
    std::fs::create_dir(&empty).unwrap();
    let fake = |dir: &Path, body: &str| {
        let path = dir.join("fwc");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    fake(
        &bin,
        &format!(
            "#!/bin/sh\nPATH=/usr/bin:/bin\n[ \"$*\" = 'robot invoke --connector plaid --operation transactions_sync --account plaid-acct-chk-1010 --since 2026-03-01' ] || exit 9\ncat '{payload}'\n"
        ),
    );
    let failing = f.dir.join("failing");
    std::fs::create_dir(&failing).unwrap();
    fake(
        &failing,
        "#!/bin/sh\necho 'plaid: item login required' >&2\nexit 3\n",
    );
    let fetch = |path: &Path, connector: &str| -> (i32, Json) {
        let output = Command::new(env!("CARGO_BIN_EXE_fa"))
            .arg("--book")
            .arg(&f.book)
            .args([
                "bank",
                "fetch",
                "--connector",
                connector,
                "--connector-account",
                "plaid-acct-chk-1010",
                "--since",
                "2026-03-01",
                "--account",
                "1000",
                "--json",
            ])
            .env_remove("FA_BOOK")
            .env_remove("FA_TOKEN")
            .env("PATH", path)
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let line = stdout.lines().last().unwrap_or_default();
        fa_cli::verbs::registry()
            .unwrap()
            .check_line(line)
            .unwrap_or_else(|error| panic!("{error}\n{stdout}"));
        (output.status.code().unwrap(), json::parse(line).unwrap())
    };
    let before = head(&f.book);
    for (path, connector, exit) in [
        (&empty, "plaid", 4),
        (&failing, "plaid", 4),
        (&bin, "stripe", 2),
    ] {
        let (code, refused) = fetch(path, connector);
        assert_eq!(code, exit, "{}: {}", path.display(), refused.render());
        assert_eq!(head(&f.book), before, "nothing is written");
    }
    let (code, fetched) = fetch(&bin, "plaid");
    assert_eq!(code, 0, "{}", fetched.render());
    let report = data(&fetched);
    assert_eq!(text(report, "bank_format"), "plaid-sync");
    assert_eq!(integer(report, "line_count"), 2);
    assert_eq!(text(report, "closing_balance"), "1250.00 USD");
    assert_eq!(report.get("already_recorded"), Some(&Json::Bool(false)));
    let imported = f.import("plaid-again.json", "plaid-sync", PLAID);
    assert_eq!(
        data(&imported).get("already_recorded"),
        Some(&Json::Bool(true)),
        "the fetched bytes are the payload"
    );
    assert_eq!(
        text(data(&imported), "manifest_oid"),
        text(report, "manifest_oid")
    );
}

/// fa-lzrn: `fa export warehouse` runs the host's `fwc` (`fwc robot export`)
/// after admission and report-certificate verification, writes the canonical
/// `WarehouseExportReceipt` control record, and `fa verify export warehouse`
/// re-reads and verifies it against the book. Planted: missing or failing
/// `fwc` (exit 4), unknown or mismatched connector (exit 2), unverified
/// certificate (exit 8), and tampered receipt file (exit 8).
#[cfg(unix)]
#[test]
fn warehouse_export_runs_the_hosts_fwc_and_verifies_its_receipt() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let tb_events = certified_events(&f.book, &["tb", "--period", "FY2026-P03", "--certify"]);
    let tb = &tb_events[0];
    let cert_oid = text(tb, "certificate").to_string();
    let receipt_hash = "ab".repeat(32);

    let bin = f.dir.join("wh-bin");
    let empty = f.dir.join("wh-empty");
    let failing = f.dir.join("wh-failing");
    let mismatch = f.dir.join("wh-mismatch");
    for d in [&bin, &empty, &failing, &mismatch] {
        std::fs::create_dir(d).unwrap();
    }
    let fake = |dir: &Path, body: &str| {
        let path = dir.join("fwc");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    fake(
        &bin,
        &format!(
            "#!/bin/sh\nPATH=/usr/bin:/bin\n[ \"$*\" = 'robot export --connector snowflake --destination analytics.gl.tb --certificate {cert_oid}' ] || exit 9\nprintf '{{\"robot_schema_version\":\"fwc.robot.v1\",\"connector\":\"snowflake\",\"receipt_hash\":\"{receipt_hash}\"}}\\n'\n"
        ),
    );
    fake(
        &failing,
        "#!/bin/sh\necho 'snowflake: warehouse suspended' >&2\nexit 3\n",
    );
    fake(
        &mismatch,
        &format!(
            "#!/bin/sh\nprintf '{{\"robot_schema_version\":\"fwc.robot.v1\",\"connector\":\"bigquery\",\"receipt_hash\":\"{receipt_hash}\"}}\\n'\n"
        ),
    );

    let run_wh = |path: &Path, args: &[&str]| -> (i32, Json) {
        let output = Command::new(env!("CARGO_BIN_EXE_fa"))
            .arg("--book")
            .arg(&f.book)
            .args(args)
            .arg("--json")
            .env_remove("FA_BOOK")
            .env_remove("FA_TOKEN")
            .env("PATH", path)
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let line = stdout.lines().last().unwrap_or_default();
        fa_cli::verbs::registry()
            .unwrap()
            .check_line(line)
            .unwrap_or_else(|error| panic!("{error}\n{stdout}"));
        (output.status.code().unwrap(), json::parse(line).unwrap())
    };

    let refused_out = f.dir.join("refused-receipt.toml");
    let refused_out_str = refused_out.to_str().unwrap();
    let zero_cert = format!("C:{}", "00".repeat(32));
    for (path, connector, cert, expected_exit) in [
        (&empty, "snowflake", cert_oid.as_str(), 4),
        (&failing, "snowflake", cert_oid.as_str(), 4),
        (&bin, "postgres", cert_oid.as_str(), 2),
        (&mismatch, "snowflake", cert_oid.as_str(), 2),
        (&bin, "snowflake", zero_cert.as_str(), 8),
    ] {
        let (code, refused) = run_wh(
            path,
            &[
                "export",
                "warehouse",
                "--connector",
                connector,
                "--destination",
                "analytics.gl.tb",
                "--report",
                cert,
                "--out",
                refused_out_str,
            ],
        );
        assert_eq!(code, expected_exit, "{}", refused.render());
        assert!(!refused_out.exists(), "refused export must not create --out");
    }

    let receipt_path = f.dir.join("warehouse-receipt.toml");
    let receipt_path_str = receipt_path.to_str().unwrap();
    let (code, exported) = run_wh(
        &bin,
        &[
            "export",
            "warehouse",
            "--connector",
            "snowflake",
            "--destination",
            "analytics.gl.tb",
            "--report",
            &cert_oid,
            "--out",
            receipt_path_str,
        ],
    );
    assert_eq!(code, 0, "{}", exported.render());
    let exp_data = data(&exported);
    assert_eq!(text(exp_data, "format"), "warehouse");
    assert_eq!(text(exp_data, "certificate_digest"), cert_oid);
    let control_oid = text(exp_data, "content_digest").to_string();
    assert!(receipt_path.exists());

    let (v_code, verified) = run_wh(&bin, &["verify", "export", "warehouse", receipt_path_str]);
    assert_eq!(v_code, 0, "{}", verified.render());
    let ver_data = data(&verified);
    assert_eq!(text(ver_data, "format"), "warehouse");
    assert_eq!(text(ver_data, "reread"), "receipt");
    assert_eq!(text(ver_data, "certificate_digest"), cert_oid);
    assert_eq!(text(ver_data, "content_digest"), control_oid);

    let mut tampered = std::fs::read_to_string(&receipt_path).unwrap();
    tampered = tampered.replacen("analytics.gl.tb", "analytics.gl.tx", 1);
    let tampered_path = f.dir.join("warehouse-receipt-tampered.toml");
    let tampered_str = tampered_path.to_str().unwrap();
    std::fs::write(&tampered_path, tampered).unwrap();
    let (t_code, t_out) = run_wh(&bin, &["verify", "export", "warehouse", tampered_str]);
    assert_eq!(t_code, 8, "{}", t_out.render());
}

#[path = "bank/csv_layout.rs"]
mod csv_layout;
