//! fa-7dw: AccessEvent (who read what) through real binary and bound-host
//! commands. Bound reads commit one AccessEvent before observing the book,
//! including Agent and writing sessions. Owner reads remain unrecorded.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::authority::{LaunchAuthority, LaunchProfile};
use fa_cli::cli::{Files, Stdin};
use fa_cli::entry::fa_with_authority;
use fa_cli::json::{self, Json};

fn temporary() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("fa-access-log-{}-{n}", std::process::id()));
        match std::fs::create_dir(&d) {
            Ok(()) => return d,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => panic!("create {}: {e}", d.display()),
        }
    }
}

fn data(event: &Json) -> &Json {
    event.get("data").expect("data")
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("{key} in {value:?}"))
}

fn number(value: &Json, key: &str) -> i128 {
    match value.get(key) {
        Some(Json::Int(n)) => *n,
        other => panic!("{key}: {other:?}"),
    }
}

struct Fixture {
    dir: PathBuf,
    evidence: String,
}

impl Fixture {
    fn new() -> Self {
        let mut f = Self {
            dir: temporary(),
            evidence: String::new(),
        };
        f.ok(&["book", "create", "--name", "Access log"]);
        std::fs::write(
            f.dir.join("chart.json"),
            r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","leaf":true,"unit":"USD"}]}"#,
        )
        .unwrap();
        f.ok(&["chart", "import", "chart.json"]);
        f.ok(&["period", "create", "--fiscal-year", "2026"]);
        f.ok(&["period", "open", "FY2026-P03"]);
        std::fs::write(f.dir.join("receipt.txt"), b"March receipt").unwrap();
        let document = f.ok(&[
            "document",
            "add",
            "receipt.txt",
            "--kind",
            "Receipt",
            "--grade",
            "HumanUpload",
        ]);
        let evidence = text(data(&document), "oid").to_string();
        f.evidence = evidence.clone();
        std::fs::write(
            f.dir.join("sale.json"),
            r#"{"idempotency_key":"sale","effective_date":"2026-03-10","legs":[{"side":"debit","account":"1000","amount":"5.00 USD"},{"side":"credit","account":"4000","amount":"5.00 USD"}]}"#,
        )
        .unwrap();
        f.ok(&["post", "--intent", "sale.json", "--evidence", &evidence]);
        f
    }

    fn run(&self, args: &[&str]) -> (i32, Json) {
        let output = Command::new(env!("CARGO_BIN_EXE_fa"))
            .current_dir(&self.dir)
            .args(["--book", "book"])
            .args(args)
            .arg("--json")
            .env_remove("FA_BOOK")
            .env_remove("FA_TOKEN")
            .output()
            .expect("run fa");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let lines: Vec<&str> = stdout.lines().collect();
        assert_eq!(lines.len(), 1, "args={args:?}\n{stdout}");
        fa_cli::verbs::registry()
            .unwrap()
            .check_line(lines[0])
            .unwrap_or_else(|error| panic!("robot schema: {error}\n{stdout}"));
        (
            output.status.code().unwrap_or(-1),
            json::parse(lines[0]).unwrap(),
        )
    }

    fn ok(&self, args: &[&str]) -> Json {
        let (exit, event) = self.run(args);
        assert_eq!(exit, 0, "args={args:?}\n{event:?}");
        event
    }

    /// A Human token for `holder` holding `ops`; returns the token file and
    /// its commitment.
    fn issue(&self, holder: &str, ops: &[&str]) -> (String, String) {
        let token = format!("{holder}.token");
        let mut args = vec![
            "capability",
            "issue",
            "--holder",
            holder,
            "--profile",
            "human",
            "--out",
            &token,
            "--grant",
            "issue_capability",
        ];
        for op in ops {
            args.extend(["--op", *op, "--grant", *op]);
        }
        let issued = self.ok(&args);
        (token, text(data(&issued), "commitment").to_string())
    }

    fn log(&self, extra: &[&str]) -> Json {
        let mut args = vec!["access", "log"];
        args.extend_from_slice(extra);
        data(&self.ok(&args)).clone()
    }

    fn head(&self) -> i128 {
        number(
            self.ok(&["book", "info"]).get("coordinate").unwrap(),
            "known_at",
        )
    }

    fn bound(&self, authority: &LaunchAuthority, args: &[&str], input: Option<&str>) -> (u8, Json) {
        let mut argv = args
            .iter()
            .map(|arg| (*arg).to_string())
            .collect::<Vec<_>>();
        argv.push("--json".to_string());
        let (exit, captured) = fa_with_authority(
            &argv,
            Files {
                cwd: Some(self.dir.clone()),
                stdin: input.map_or(Stdin::Missing, |bytes| {
                    Stdin::Forwarded(bytes.as_bytes().to_vec())
                }),
            },
            authority,
            true,
        );
        let lines = captured.stdout.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1, "{args:?}: {captured:?}");
        fa_cli::verbs::registry()
            .unwrap()
            .check_line(lines[0])
            .unwrap_or_else(|error| panic!("robot schema: {error}\n{captured:?}"));
        let event = json::parse(lines[0]).unwrap();
        assert_eq!(event.get("authority"), Some(&authority.envelope_json()));
        (exit, event)
    }
}

#[test]
fn recorded_token_reads_are_counted_in_signed_checkpoint_coverage() {
    let f = Fixture::new();
    let (token, _) = f.issue("checkpoint-auditor", &["read"]);
    let before = f.ok(&["checkpoint", "create", "--grant", "witness"]);
    let before = data(&before);
    assert_eq!(number(before, "access_after_seq"), 1);
    assert_eq!(
        number(before.get("leaf_kinds").unwrap(), "access_events"),
        0
    );

    f.ok(&["--token", &token, "tb", "--period", "FY2026-P03"]);
    let log = f.log(&[]);
    assert_eq!(number(&log, "count"), 1);
    let access = &log.get("events").and_then(Json::as_arr).unwrap()[0];
    let after = f.ok(&["checkpoint", "create", "--grant", "witness"]);
    let after = data(&after);
    assert_eq!(text(after, "signatures"), "ed25519");
    assert_eq!(text(after, "prev_state_oid"), text(before, "oid"));
    assert_ne!(text(after, "root"), text(before, "root"));
    assert_eq!(
        number(after, "leaf_count"),
        number(before, "leaf_count") + 1
    );
    assert_eq!(number(after, "access_after_seq"), 1);
    assert_eq!(number(after.get("leaf_kinds").unwrap(), "access_events"), 1);
    assert!(number(after, "through_seq") >= number(access, "recorded_at"));

    let verified = f.ok(&["verify", "accumulator"]);
    assert_eq!(text(data(&verified), "status"), "verified");
    let states = data(&verified)
        .get("states")
        .and_then(Json::as_arr)
        .unwrap();
    assert_eq!(states.len(), 2);
    for (state, expected) in states.iter().zip([1, 0]) {
        assert_eq!(number(state, "access_after_seq"), 1);
        assert_eq!(
            number(state.get("leaf_kinds").unwrap(), "access_events"),
            expected
        );
    }
    let listed = f.ok(&["checkpoint", "list"]);
    let states = data(&listed)
        .get("checkpoints")
        .and_then(Json::as_arr)
        .unwrap();
    assert_eq!(states.len(), 2);
    assert!(
        states
            .iter()
            .all(|state| number(state, "access_after_seq") == 1)
    );
    assert_eq!(
        number(&f.log(&[]), "count"),
        1,
        "owner verification records no extra access"
    );
}

#[test]
fn token_reads_are_recorded_before_observation_even_when_the_holder_can_write() {
    let f = Fixture::new();
    let (auditor, commitment) = f.issue("auditor-1", &["read"]);
    let (preparer, preparer_commitment) = f.issue("preparer-1", &["read", "post"]);

    // Owner reads are not recorded.
    f.ok(&["tb", "--period", "FY2026-P03"]);
    assert_eq!(number(&f.log(&[]), "count"), 0);

    // A read-only token's trial balance: one event, recorded before the read
    // (the report's frontier is the event's own sequence).
    let tb = f.ok(&["--token", &auditor, "tb", "--period", "FY2026-P03"]);
    let tb_known_at = number(tb.get("coordinate").unwrap(), "known_at");
    let log = f.log(&[]);
    assert_eq!(number(&log, "count"), 1, "{log:?}");
    let event = &log.get("events").and_then(Json::as_arr).unwrap()[0];
    assert_eq!(text(event, "principal_name"), "auditor-1");
    assert_eq!(text(event, "command"), "tb");
    assert_eq!(text(event, "capability"), commitment);
    assert_eq!(
        event.get("ops"),
        Some(&Json::Arr(vec![json::s("read")])),
        "{event:?}"
    );
    let recorded_at = number(event, "recorded_at");
    assert!(number(event, "observed_at") < recorded_at, "{event:?}");
    assert_eq!(
        tb_known_at, recorded_at,
        "the read observed the book only after its record was committed"
    );

    // Write authority never exempts a read from audit. The writing token's
    // report, too, sees the already committed AccessEvent.
    let tb = f.ok(&["--token", &preparer, "tb", "--period", "FY2026-P03"]);
    let log = f.log(&[]);
    assert_eq!(number(&log, "count"), 2);
    let writer = &log.get("events").and_then(Json::as_arr).unwrap()[1];
    assert_eq!(text(writer, "principal_name"), "preparer-1");
    assert_eq!(text(writer, "capability"), preparer_commitment);
    assert_eq!(
        number(tb.get("coordinate").unwrap(), "known_at"),
        number(writer, "recorded_at")
    );

    // The same read again is a second, distinct event; another command and
    // a refused command are recorded too (the record precedes the outcome).
    f.ok(&["--token", &auditor, "tb", "--period", "FY2026-P03"]);
    f.ok(&["--token", &auditor, "explain", "period", "FY2026-P03"]);
    let log = f.log(&[]);
    let events = log.get("events").and_then(Json::as_arr).unwrap();
    assert_eq!(events.len(), 4, "{log:?}");
    assert_ne!(text(&events[0], "vid"), text(&events[2], "vid"));
    assert_eq!(
        text(&events[0], "request_digest"),
        text(&events[2], "request_digest"),
        "the same arguments digest alike"
    );
    assert_eq!(text(&events[3], "command"), "explain period");
    assert_ne!(
        text(&events[0], "request_digest"),
        text(&events[3], "request_digest")
    );

    // Filters: by principal and by a reproducible recorded interval.
    assert_eq!(number(&f.log(&["--reader", "preparer-1"]), "count"), 1);
    assert_eq!(number(&f.log(&["--reader", "auditor-1"]), "count"), 3);
    let first = number(&events[0], "recorded_at").to_string();
    let through = number(&events[2], "recorded_at").to_string();
    let after = through.clone();
    assert_eq!(number(&f.log(&["--since", &after]), "count"), 1);
    let bounded = f.log(&["--since", &first, "--through", &through]);
    assert_eq!(number(&bounded, "count"), 2, "{bounded:?}");
    assert_eq!(number(&bounded, "since"), number(&events[0], "recorded_at"));
    assert_eq!(
        number(&bounded, "through"),
        number(&events[2], "recorded_at")
    );
    let exact = f.log(&["--through", &through]);
    assert_eq!(number(&exact, "count"), 3, "{exact:?}");
    assert_eq!(
        exact.get("through"),
        Some(&Json::Int(number(&events[2], "recorded_at")))
    );

    // Reading the log under the read-only token records that read too, and
    // the answer includes it.
    let own = f.ok(&["--token", &auditor, "access", "log"]);
    let own = data(&own);
    assert_eq!(number(own, "count"), 5, "{own:?}");
    let last = own
        .get("events")
        .and_then(Json::as_arr)
        .unwrap()
        .last()
        .unwrap();
    assert_eq!(text(last, "command"), "access log");

    // Planted negatives: malformed and inverted bounds are usage errors and
    // are rejected before a book read can be recorded.
    let (code, _) = f.run(&["access", "log", "--since", "soon"]);
    assert_eq!(code, 2);
    let (code, _) = f.run(&["access", "log", "--through", "later"]);
    assert_eq!(code, 2);
    let (code, _) = f.run(&["access", "log", "--since", "10", "--through", "9"]);
    assert_eq!(code, 2);
    assert_eq!(number(&f.log(&[]), "count"), 5);
}

#[test]
fn witness_and_hold_authority_do_not_suppress_a_readers_access_history() {
    let f = Fixture::new();
    for (principal, extra_op) in [
        ("auditor-witness", "witness"),
        ("investigator-hold", "hold"),
    ] {
        let (token, commitment) = f.issue(principal, &["read", extra_op]);
        let before = f.head();
        let read = f.ok(&["--token", &token, "document", "read", &f.evidence]);
        let log = f.log(&["--since", &before.to_string()]);
        assert_eq!(number(&log, "count"), 1, "{log:?}");
        let access = &log.get("events").and_then(Json::as_arr).unwrap()[0];
        assert_eq!(text(access, "principal_name"), principal);
        assert_eq!(text(access, "capability"), commitment);
        assert_eq!(text(access, "command"), "document read");
        assert_eq!(number(access, "observed_at"), before);
        assert_eq!(number(access, "recorded_at"), before + 1);
        assert_eq!(
            number(read.get("coordinate").unwrap(), "known_at"),
            before + 1
        );
        assert_eq!(
            text(data(&read).get("text").unwrap(), "untrusted_content"),
            "March receipt"
        );
    }
}

#[test]
fn bound_agent_and_preparer_reads_audit_documents_findings_and_streams_once() {
    let f = Fixture::new();
    std::fs::write(f.dir.join("bank.txt"), b"Account BANK-123, March statement").unwrap();
    let source = f.ok(&[
        "document",
        "add",
        "bank.txt",
        "--kind",
        "BankStatement",
        "--grade",
        "HumanUpload",
    ]);
    let source = text(data(&source), "oid");
    f.ok(&["document", "redact", source]);
    std::fs::write(
        f.dir.join("weekend.json"),
        r#"{"idempotency_key":"weekend","effective_date":"2026-03-14","legs":[{"side":"debit","account":"1000","amount":"7.00 USD"},{"side":"credit","account":"4000","amount":"7.00 USD"}]}"#,
    )
    .unwrap();
    f.ok(&[
        "post",
        "--intent",
        "weekend.json",
        "--evidence",
        &f.evidence,
    ]);
    let findings = f.ok(&["finding", "record", "jet.weekend"]);
    assert_eq!(number(data(&findings), "finding_count"), 1);
    let finding = data(&findings)
        .get("finding_ids")
        .and_then(Json::as_arr)
        .unwrap()[0]
        .as_str()
        .unwrap();

    for (principal, profile) in [
        ("agent-reader", LaunchProfile::Agent),
        ("preparer-reader", LaunchProfile::Preparer),
    ] {
        let authority = LaunchAuthority::new(
            f.dir.join("book"),
            None,
            principal,
            profile,
            &["read", "post", "produce"],
        )
        .unwrap();
        let start = f.head();
        for args in [
            vec!["document", "read", source],
            vec!["finding", "show", finding],
            vec!["export", "ndjson", "--period", "FY2026-P03"],
            vec!["query", "CALL fa.access_log"],
        ] {
            let before = f.head();
            let (exit, result) = f.bound(&authority, &args, None);
            assert_eq!(exit, 0, "{principal}: {args:?}: {result:?}");
            let log = f.log(&["--since", &before.to_string()]);
            assert_eq!(
                number(&log, "count"),
                1,
                "one receipt for the entire response: {log:?}"
            );
            let access = &log.get("events").and_then(Json::as_arr).unwrap()[0];
            assert_eq!(text(access, "principal_name"), principal);
            assert_eq!(number(access, "observed_at"), before);
            assert_eq!(number(access, "recorded_at"), before + 1);
            assert_eq!(f.head(), before + 1, "the read only publishes its receipt");
            assert_eq!(
                number(result.get("coordinate").unwrap(), "known_at"),
                number(access, "recorded_at"),
                "{principal}: {args:?}: the read cannot disclose an observation made before its receipt commits"
            );
            match args[0] {
                "document" => {
                    assert_eq!(text(data(&result), "view"), "redacted");
                    assert_eq!(data(&result).get("text"), Some(&Json::Null));
                    assert_eq!(data(&result).get("bytes_hex"), Some(&Json::Null));
                    assert!(!result.render().contains("BANK-123"));
                }
                "export" => {
                    let files = data(&result).get("files").and_then(Json::as_arr).unwrap();
                    let stream = files
                        .iter()
                        .find(|file| text(file, "name") == "gl.ndjson")
                        .unwrap();
                    let content = text(stream, "content");
                    assert_eq!(
                        fa_formats::csv_gl::verify_ndjson_gl_stream(content).unwrap(),
                        4
                    );
                    let header = json::parse(content.lines().next().unwrap()).unwrap();
                    assert_eq!(
                        number(&header, "known_at_seq"),
                        number(access, "recorded_at")
                    );
                }
                "query" => {
                    let rows = data(&result).get("events").and_then(Json::as_arr).unwrap();
                    assert_eq!(text(rows.last().unwrap(), "command"), "query");
                    assert_eq!(text(rows.last().unwrap(), "vid"), text(access, "vid"));
                }
                _ => {}
            }
        }
        assert_eq!(number(&f.log(&["--since", &start.to_string()]), "count"), 4);
    }
}

#[test]
fn a_bound_plan_audits_before_its_basis_and_commit_does_not_invalidate_the_plan() {
    let f = Fixture::new();
    let authority = LaunchAuthority::new(
        f.dir.join("book"),
        None,
        "preparer-planner",
        LaunchProfile::Preparer,
        &["read", "post"],
    )
    .unwrap();
    let intent = r#"{"idempotency_key":"planned-sale","effective_date":"2026-03-10","legs":[{"side":"debit","account":"1000","amount":"3.00 USD"},{"side":"credit","account":"4000","amount":"3.00 USD"}]}"#;
    let before = f.head();
    let (exit, planned) = f.bound(
        &authority,
        &[
            "post",
            "--intent",
            "-",
            "--evidence",
            &f.evidence,
            "--dry-run",
        ],
        Some(intent),
    );
    assert_eq!(exit, 0, "{planned:?}");
    assert_eq!(text(&planned, "event"), "plan");
    let log = f.log(&["--since", &before.to_string()]);
    assert_eq!(number(&log, "count"), 1);
    let access = &log.get("events").and_then(Json::as_arr).unwrap()[0];
    assert_eq!(text(access, "command"), "post");
    assert_eq!(number(access, "observed_at"), before);
    assert_eq!(number(access, "recorded_at"), before + 1);
    assert_eq!(
        f.head(),
        before + 1,
        "rehearsal publishes its access record, no entry"
    );

    let bytes = text(data(&planned), "bytes");
    let (exit, committed) = f.bound(&authority, &["commit", "--plan", "-"], Some(bytes));
    assert_eq!(
        exit, 0,
        "the access receipt must precede acquisition of the guarded basis: {committed:?}"
    );
    assert_eq!(text(&committed, "event"), "plan_committed");
    assert_eq!(
        data(&committed).get("already_recorded"),
        Some(&Json::Bool(false))
    );
    assert_eq!(f.head(), before + 2);
    assert_eq!(
        number(&f.log(&[]), "count"),
        1,
        "commit must not self-invalidate by recording another read"
    );
    let (exit, repeated) = f.bound(&authority, &["commit", "--plan", "-"], Some(bytes));
    assert_eq!(exit, 0, "{repeated:?}");
    assert_eq!(
        data(&repeated).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(text(data(&repeated), "vid"), text(data(&committed), "vid"));
    assert_eq!(f.head(), before + 2);
}

/// fa-1nx under fa-7dw: another session's read between a plan and its
/// commit publishes only its access receipt, which changes nothing the plan
/// reviewed, so the plan still commits. An accounting post in between still
/// invalidates the plan (the negative control).
#[test]
fn another_sessions_access_receipt_does_not_invalidate_a_plan() {
    let f = Fixture::new();
    let book = f.dir.join("book");
    let planner = LaunchAuthority::new(
        book.clone(),
        None,
        "preparer-planner",
        LaunchProfile::Preparer,
        &["read", "post"],
    )
    .unwrap();
    let reader =
        LaunchAuthority::new(book, None, "agent-reader", LaunchProfile::Agent, &["read"]).unwrap();
    let intent = |key: &str| {
        format!(
            r#"{{"idempotency_key":"{key}","effective_date":"2026-03-10","legs":[{{"side":"debit","account":"1000","amount":"3.00 USD"}},{{"side":"credit","account":"4000","amount":"3.00 USD"}}]}}"#
        )
    };
    let plan = |key: &str| {
        let (exit, planned) = f.bound(
            &planner,
            &[
                "post",
                "--intent",
                "-",
                "--evidence",
                &f.evidence,
                "--dry-run",
            ],
            Some(intent(key).as_str()),
        );
        assert_eq!(exit, 0, "{planned:?}");
        assert_eq!(text(&planned, "event"), "plan");
        text(data(&planned), "bytes").to_string()
    };

    let planned = plan("receipt-tolerant");
    let snapshot = f.head();
    let (exit, read) = f.bound(&reader, &["tb", "--period", "FY2026-P03"], None);
    assert_eq!(exit, 0, "{read:?}");
    let log = f.log(&["--since", &snapshot.to_string()]);
    assert_eq!(number(&log, "count"), 1);
    let access = &log.get("events").and_then(Json::as_arr).unwrap()[0];
    assert_eq!(text(access, "principal_name"), "agent-reader");
    assert_eq!(text(access, "command"), "tb");
    assert_eq!(
        f.head(),
        snapshot + 1,
        "the read published only its receipt"
    );
    let (exit, committed) = f.bound(&planner, &["commit", "--plan", "-"], Some(planned.as_str()));
    assert_eq!(
        exit, 0,
        "another session's access receipt must not invalidate the plan: {committed:?}"
    );
    assert_eq!(text(&committed, "event"), "plan_committed");
    assert_eq!(
        data(&committed).get("already_recorded"),
        Some(&Json::Bool(false))
    );

    let invalidated = plan("receipt-control");
    std::fs::write(
        f.dir.join("between.json"),
        r#"{"idempotency_key":"between-sale","effective_date":"2026-03-11","legs":[{"side":"debit","account":"1000","amount":"7.00 USD"},{"side":"credit","account":"4000","amount":"7.00 USD"}]}"#,
    )
    .unwrap();
    f.ok(&[
        "post",
        "--intent",
        "between.json",
        "--evidence",
        &f.evidence,
    ]);
    let before = f.head();
    let (exit, refused) = f.bound(
        &planner,
        &["commit", "--plan", "-"],
        Some(invalidated.as_str()),
    );
    assert_eq!(
        exit, 6,
        "an accounting post still invalidates the plan: {refused:?}"
    );
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-034");
    assert_eq!(f.head(), before);
}

#[test]
fn a_historical_export_keeps_its_prefix_after_recording_current_access() {
    let f = Fixture::new();
    let authority = LaunchAuthority::new(
        f.dir.join("book"),
        None,
        "historical-export-reader",
        LaunchProfile::Preparer,
        &["read", "produce"],
    )
    .unwrap();
    let selected = f.head();
    std::fs::write(
        f.dir.join("later.json"),
        r#"{"idempotency_key":"later-sale","effective_date":"2026-03-11","legs":[{"side":"debit","account":"1000","amount":"7.00 USD"},{"side":"credit","account":"4000","amount":"7.00 USD"}]}"#,
    )
    .unwrap();
    f.ok(&["post", "--intent", "later.json", "--evidence", &f.evidence]);
    let before = f.head();
    assert!(before > selected);
    let prefix = selected.to_string();
    let (exit, result) = f.bound(
        &authority,
        &[
            "export",
            "ndjson",
            "--period",
            "FY2026-P03",
            "--as-known-at",
            &prefix,
        ],
        None,
    );
    assert_eq!(exit, 0, "{result:?}");
    assert_eq!(
        number(result.get("coordinate").unwrap(), "known_at"),
        selected
    );
    assert_eq!(number(data(&result), "entries"), 1);
    let files = data(&result).get("files").and_then(Json::as_arr).unwrap();
    let stream = files
        .iter()
        .find(|file| text(file, "name") == "gl.ndjson")
        .unwrap();
    let content = text(stream, "content");
    assert_eq!(
        fa_formats::csv_gl::verify_ndjson_gl_stream(content).unwrap(),
        2
    );
    let header = json::parse(content.lines().next().unwrap()).unwrap();
    assert_eq!(number(&header, "known_at_seq"), selected);
    let log = f.log(&["--since", &before.to_string()]);
    assert_eq!(number(&log, "count"), 1);
    let access = &log.get("events").and_then(Json::as_arr).unwrap()[0];
    assert_eq!(number(access, "observed_at"), before);
    assert_eq!(number(access, "recorded_at"), before + 1);
    assert_eq!(f.head(), before + 1);
}

#[test]
fn unauthorized_and_revoked_readers_disclose_nothing_and_publish_no_access_event() {
    let f = Fixture::new();
    let writer = LaunchAuthority::new(
        f.dir.join("book"),
        None,
        "writer-without-read",
        LaunchProfile::Agent,
        &["post"],
    )
    .unwrap();
    let (token, commitment) = f.issue("revoked-reader", &["read", "post", "produce"]);
    f.ok(&[
        "capability",
        "revoke",
        "--commitment",
        &commitment,
        "--grant",
        "issue_capability",
        "--yes",
    ]);
    let before = f.head();
    for args in [
        vec!["document", "read", &f.evidence],
        // A syntactically valid certificate selector must never be looked up
        // for a caller without current authority. Omitting it is only usage.
        vec![
            "finding",
            "list",
            "--certificate",
            "C:0000000000000000000000000000000000000000000000000000000000000000",
        ],
        vec!["export", "ndjson", "--period", "FY2026-P03"],
    ] {
        let (exit, refused) = f.bound(&writer, &args, None);
        assert_eq!(exit, 7, "{args:?}: {refused:?}");
        assert_eq!(refused.get("coordinate"), Some(&Json::Null));
        assert_eq!(refused.get("book"), Some(&Json::Null));
        assert!(!refused.render().contains("March receipt"));
        assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-011");

        let mut revoked_args = vec!["--token", token.as_str()];
        revoked_args.extend_from_slice(&args);
        let (exit, refused) = f.run(&revoked_args);
        assert_eq!(exit, 7, "{revoked_args:?}: {refused:?}");
        assert_eq!(refused.get("coordinate"), Some(&Json::Null));
        assert_eq!(refused.get("book"), Some(&Json::Null));
        assert!(!refused.render().contains("March receipt"));
        assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-023");
        assert_eq!(f.head(), before);
        assert_eq!(number(&f.log(&[]), "count"), 0);
    }
}

/// fa-5c1, the runtime graph queried: `fa query "CALL fa.access_log"` is the
/// access log itself, so a read-only token session's query lists that
/// session's own read, which was recorded (command `query`) before the query
/// observed the book. One reader's events, and the coordinates the log
/// cannot honour, are refused rather than ignored.
#[test]
fn a_query_over_the_runtime_graph_lists_the_callers_own_session() {
    let f = Fixture::new();
    let (auditor, commitment) = f.issue("auditor-7", &["read"]);
    let (other, _) = f.issue("auditor-8", &["read"]);
    f.ok(&["--token", &other, "tb", "--period", "FY2026-P03"]);

    let queried = f.ok(&["--token", &auditor, "query", "CALL fa.access_log"]);
    assert_eq!(text(&queried, "event"), "access_log", "{queried:?}");
    let events = data(&queried).get("events").and_then(Json::as_arr).unwrap();
    assert_eq!(events.len(), 2, "{queried:?}");
    let own = events.last().unwrap();
    assert_eq!(text(own, "principal_name"), "auditor-7");
    assert_eq!(text(own, "capability"), commitment);
    assert_eq!(text(own, "command"), "query");
    // The same read through the CLI verb answers the same events, its own
    // read added.
    let direct = f.log(&[]);
    assert_eq!(number(&direct, "count"), 2, "{direct:?}");

    // One reader's: the other auditor's trial balance alone.
    let theirs = f.ok(&["query", "CALL fa.access_log('auditor-8')"]);
    let theirs = data(&theirs).get("events").and_then(Json::as_arr).unwrap();
    assert_eq!(theirs.len(), 1, "{theirs:?}");
    assert_eq!(text(&theirs[0], "command"), "tb");

    // Planted: certification, a known-at and a branch are refused by the
    // profile before the book opens, so nothing more is recorded.
    for statement in [
        "EXPLAIN (CERTIFICATE) CALL fa.access_log",
        "CALL fa.access_log AS KNOWN AT 3",
        "CALL fa.access_log AT BRANCH 'scenario:x'",
    ] {
        let (code, refused) = f.run(&["--token", &auditor, "query", statement]);
        assert_ne!(code, 0, "{statement}: {refused:?}");
        assert!(
            refused.render().contains("fa.access_log"),
            "{statement}: {refused:?}"
        );
    }
    assert_eq!(number(&f.log(&["--reader", "auditor-7"]), "count"), 1);
}
