//! fa-7dw: AccessEvent (who read what) on the real binary. A read-only token
//! session's command commits one AccessEvent before it observes the book;
//! `fa access log` lists them. Embedded-owner reads and sessions that can
//! write are not recorded by this slice.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

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
}

impl Fixture {
    fn new() -> Self {
        let f = Self { dir: temporary() };
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
}

#[test]
fn a_read_only_token_read_is_recorded_before_it_observes_the_book() {
    let f = Fixture::new();
    let (auditor, commitment) = f.issue("auditor-1", &["read"]);
    let (preparer, _) = f.issue("preparer-1", &["read", "post"]);

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

    // A token that can write is not recorded by this slice.
    f.ok(&["--token", &preparer, "tb", "--period", "FY2026-P03"]);
    assert_eq!(number(&f.log(&[]), "count"), 1);

    // The same read again is a second, distinct event; another command and
    // a refused command are recorded too (the record precedes the outcome).
    f.ok(&["--token", &auditor, "tb", "--period", "FY2026-P03"]);
    f.ok(&["--token", &auditor, "explain", "period", "FY2026-P03"]);
    let log = f.log(&[]);
    let events = log.get("events").and_then(Json::as_arr).unwrap();
    assert_eq!(events.len(), 3, "{log:?}");
    assert_ne!(text(&events[0], "vid"), text(&events[1], "vid"));
    assert_eq!(
        text(&events[0], "request_digest"),
        text(&events[1], "request_digest"),
        "the same arguments digest alike"
    );
    assert_eq!(text(&events[2], "command"), "explain period");
    assert_ne!(
        text(&events[0], "request_digest"),
        text(&events[2], "request_digest")
    );

    // Filters: by principal, and after a sequence.
    assert_eq!(number(&f.log(&["--reader", "preparer-1"]), "count"), 0);
    assert_eq!(number(&f.log(&["--reader", "auditor-1"]), "count"), 3);
    let after = number(&events[1], "recorded_at").to_string();
    assert_eq!(number(&f.log(&["--since", &after]), "count"), 1);

    // Reading the log under the read-only token records that read too, and
    // the answer includes it.
    let own = f.ok(&["--token", &auditor, "access", "log"]);
    let own = data(&own);
    assert_eq!(number(own, "count"), 4, "{own:?}");
    let last = own
        .get("events")
        .and_then(Json::as_arr)
        .unwrap()
        .last()
        .unwrap();
    assert_eq!(text(last, "command"), "access log");

    // Planted negative: a bad --since is usage and records nothing.
    let (code, _) = f.run(&["access", "log", "--since", "soon"]);
    assert_eq!(code, 2);
    assert_eq!(number(&f.log(&[]), "count"), 4);
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
