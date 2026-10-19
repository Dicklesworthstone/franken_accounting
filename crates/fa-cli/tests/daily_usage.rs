//! Daily spending limits through persisted books and actual CLI token sessions.
//! Delegation uses the native operator API; MCP/preparer launch ceilings stay
//! unchanged while the resulting Human children spend through `fa --token`.

#![forbid(unsafe_code)]

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use asupersync::Budget;
use asupersync::runtime::RuntimeBuilder;
use fa_cli::json::{self, Json};
use fa_policy::{Capability, CapabilityToken, Op, Profile, possession_digest};

const DAY_ONE_NS: u64 = 1_773_576_000_000_000_000; // 2026-03-15T12:00:00Z
const DAY_TWO_NS: u64 = DAY_ONE_NS + 86_400_000_000_000;

fn temporary() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "fa-daily-usage-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create {}: {error}", path.display()),
        }
    }
}

fn data(event: &Json) -> &Json {
    event.get("data").expect("event data")
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("missing string {key}: {value:?}"))
}

fn number(value: &Json, key: &str) -> i128 {
    match value.get(key) {
        Some(Json::Int(value)) => *value,
        _ => panic!("missing integer {key}: {value:?}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Fixture {
    dir: PathBuf,
    book: PathBuf,
    evidence: String,
}

impl Fixture {
    fn new(with_tick: bool) -> Self {
        let dir = temporary();
        let mut fixture = Self {
            book: dir.join("book"),
            dir,
            evidence: String::new(),
        };
        fixture.ok(&[
            "book",
            "create",
            "--name",
            "Daily spending",
            "--time-zone",
            "UTC",
        ]);
        std::fs::write(
            fixture.dir.join("chart.json"),
            r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"USD"},{"code":"6000","name":"Expenses","type":"Expense","leaf":true,"unit":"USD"}]}"#,
        )
        .unwrap();
        fixture.ok(&["chart", "import", "chart.json"]);
        fixture.ok(&["period", "create", "--fiscal-year", "2026"]);
        fixture.ok(&["period", "open", "FY2026-P03"]);
        std::fs::write(
            fixture.dir.join("invoice.txt"),
            b"Authorized operating costs",
        )
        .unwrap();
        let document = fixture.ok(&[
            "document",
            "add",
            "invoice.txt",
            "--kind",
            "Invoice",
            "--grade",
            "HumanUpload",
        ]);
        fixture.evidence = text(data(&document), "oid").to_string();
        if with_tick {
            fixture.tick(DAY_ONE_NS);
        }
        fixture
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
        let stderr = String::from_utf8_lossy(&output.stderr);
        let lines: Vec<&str> = stdout.lines().collect();
        assert_eq!(lines.len(), 1, "args={args:?}\n{stdout}\n{stderr}");
        fa_cli::verbs::registry()
            .unwrap()
            .check_line(lines[0])
            .unwrap_or_else(|error| panic!("robot schema: {error}\n{stdout}\n{stderr}"));
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

    fn head(&self) -> i128 {
        let event = self.ok(&["book", "info"]);
        number(event.get("coordinate").unwrap(), "known_at")
    }

    fn open(&self) -> fa::Book {
        let keys = fa::BookKeys::load(&self.book.join("book.keys")).unwrap();
        fa::Book::open_dir(&self.book, keys, fa::Entropy::deterministic(165)).unwrap()
    }

    fn tick(&self, observed_utc_ns: u64) {
        let mut book = self.open();
        let runtime = RuntimeBuilder::new().build().unwrap();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let witness =
            Capability::embedded(fa_model::principal_vid("budget-clock"), &["witness"]).unwrap();
        runtime
            .block_on(book.record_tick(&cx, observed_utc_ns, true, &witness))
            .unwrap()
            .unwrap();
    }

    fn issue_root(&self, delegates: bool) -> CapabilityToken {
        let mut args = vec![
            "capability",
            "issue",
            "--holder",
            "daily-root",
            "--profile",
            "human",
            "--op",
            "read",
            "--op",
            "post",
            "--op",
            "verify",
            "--daily-total",
            "1000.00 USD",
            "--daily-total",
            "1200.00 USD",
            "--out",
            "root.token",
            "--grant",
            "issue_capability",
            "--grant",
            "read",
            "--grant",
            "post",
            "--grant",
            "verify",
        ];
        if delegates {
            args.extend(["--op", "issue_capability"]);
        }
        let issued = self.ok(&args);
        assert_eq!(text(&issued, "event"), "capability_issued");
        let token =
            CapabilityToken::decode(&std::fs::read(self.dir.join("root.token")).unwrap()).unwrap();
        assert_eq!(
            text(data(&issued), "commitment"),
            hex(&token.capability().commitment().unwrap())
        );
        assert_eq!(token.capability().daily_root(), None);
        assert_eq!(token.capability().daily_totals().len(), 1);
        assert_eq!(
            token.capability().daily_totals().values().next(),
            Some(&100_000),
            "a repeated higher ceiling must not widen the first one"
        );
        let detail = self.ok(&[
            "capability",
            "show",
            "--commitment",
            text(data(&issued), "commitment"),
        ]);
        let cap = data(&detail).get("capability").unwrap();
        assert_eq!(cap.get("daily_root"), Some(&Json::Null));
        let Some(Json::Arr(totals)) = cap.get("daily_totals") else {
            panic!("missing daily totals: {detail:?}");
        };
        assert_eq!(totals.len(), 1);
        assert_eq!(number(&totals[0], "max_mantissa"), 100_000);
        token
    }

    fn intent(&self, key: &str, amount: &str) -> String {
        let name = format!("{key}.json");
        std::fs::write(
            self.dir.join(&name),
            format!(
                r#"{{"idempotency_key":"{key}","effective_date":"2026-03-15","evidence":["{}"],"legs":[{{"side":"debit","account":"6000","amount":"{amount} USD"}},{{"side":"credit","account":"1000","amount":"{amount} USD"}}]}}"#,
                self.evidence
            ),
        )
        .unwrap();
        name
    }

    fn post(&self, token: &str, intent: &str) -> Json {
        let event = self.ok(&["--token", token, "post", "--intent", intent]);
        assert_eq!(
            text(event.get("authority").unwrap(), "posture"),
            "issued-token"
        );
        event
    }

    fn refuse_post(&self, token: &str, intent: &str, expected_exit: i32, code: &str) {
        let before = self.head();
        let (exit, event) = self.run(&["--token", token, "post", "--intent", intent]);
        assert_eq!(exit, expected_exit, "{event:?}");
        assert_eq!(text(&event, "event"), "error");
        assert_eq!(text(data(&event), "refusal_id"), code, "{event:?}");
        assert_eq!(self.head(), before, "a refused post must write nothing");
    }

    fn usage(&self, token: &str, charges: i128, cells: i128) {
        let before = self.head();
        let event = self.ok(&["--token", token, "verify", "usage"]);
        assert_eq!(text(&event, "event"), "usage_verified");
        assert_eq!(number(data(&event), "known_at"), before);
        assert_eq!(number(data(&event), "charges_checked"), charges);
        assert_eq!(number(data(&event), "cells_checked"), cells);
        assert_eq!(data(&event).get("drift"), Some(&Json::Arr(Vec::new())));
        assert_eq!(self.head(), before, "verification must be read only");
    }
}

#[test]
fn cli_root_issue_enforces_cumulative_gross_debits_and_retries_do_not_recharge() {
    let fixture = Fixture::new(true);
    fixture.issue_root(false);
    let first = fixture.intent("first", "600.00");
    let posted = fixture.post("root.token", &first);
    assert_eq!(text(&posted, "event"), "posted");
    fixture.usage("root.token", 1, 1);
    let before = fixture.head();
    let retried = fixture.post("root.token", &first);
    assert_eq!(text(&retried, "event"), "recorded");
    for field in ["vid", "entry_digest"] {
        assert_eq!(text(data(&retried), field), text(data(&posted), field));
    }
    assert_eq!(
        number(data(&retried), "recorded_at"),
        number(data(&posted), "recorded_at")
    );
    assert_eq!(fixture.head(), before);
    let too_much = fixture.intent("second-over", "500.00");
    fixture.refuse_post("root.token", &too_much, 7, "FA-REF-166");
    let remainder = fixture.intent("remainder", "400.00");
    fixture.post("root.token", &remainder);
    let penny = fixture.intent("one-cent-over", "0.01");
    fixture.refuse_post("root.token", &penny, 7, "FA-REF-166");
    fixture.usage("root.token", 2, 1);
    let current = fixture.head();
    let first_prefix = number(data(&posted), "recorded_at");
    let historical = fixture.ok(&[
        "--token",
        "root.token",
        "verify",
        "usage",
        "--as-known-at",
        &first_prefix.to_string(),
    ]);
    assert_eq!(text(&historical, "event"), "usage_verified");
    assert_eq!(number(data(&historical), "known_at"), first_prefix);
    assert_eq!(number(data(&historical), "charges_checked"), 1);
    assert_eq!(number(data(&historical), "cells_checked"), 1);
    assert_eq!(data(&historical).get("drift"), Some(&Json::Arr(Vec::new())));
    assert_eq!(
        number(historical.get("coordinate").unwrap(), "known_at"),
        first_prefix,
        "the verification result and envelope bind the same retained prefix"
    );
    assert_eq!(
        fixture.head(),
        current,
        "historical verification cannot rewrite the live usage cell"
    );
}

#[test]
fn native_operator_delegation_keeps_cli_children_on_the_same_daily_quota() {
    let fixture = Fixture::new(true);
    let root = fixture.issue_root(true);
    let root_cap = root.capability();
    let root_commitment = root_cap.commitment().unwrap();
    let mut book = fixture.open();
    let mut children = Vec::new();
    for (principal, secret) in [("child-one", [1; 32]), ("child-two", [2; 32])] {
        let mut child = Capability::new(
            fa_model::principal_vid(principal),
            Profile::Human,
            &[Op::Read, Op::Post, Op::Verify],
            root_cap.holder(),
        )
        .unwrap()
        .holder_bound(possession_digest(&secret));
        for (unit, limit) in root_cap.daily_totals() {
            child = child.with_daily_total(*unit, *limit).unwrap();
        }
        child = child.with_daily_root(root_commitment).unwrap();
        book.issue_capability(
            root_cap.clone(),
            child.clone(),
            fa_time::DateDay::from_ymd(2026, 3, 15).unwrap(),
            principal.as_bytes(),
            "Delegate the root's shared daily spending limit",
        )
        .unwrap()
        .unwrap();
        let token = CapabilityToken::new(principal, child, secret).unwrap();
        children.push((principal, hex(&token.capability().commitment().unwrap())));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(fixture.dir.join(format!("{principal}.token")))
            .unwrap()
            .write_all(&token.canonical_bytes().unwrap())
            .unwrap();
    }
    drop(book);
    for (principal, commitment) in children {
        let token_name = format!("{principal}.token");
        let detail = fixture.ok(&[
            "--token",
            &token_name,
            "capability",
            "show",
            "--commitment",
            &commitment,
        ]);
        assert_eq!(
            text(data(&detail).get("capability").unwrap(), "daily_root"),
            hex(&root_commitment)
        );
    }
    let first = fixture.intent("child-first", "600.00");
    fixture.post("child-one.token", &first);
    let second = fixture.intent("child-second-over", "500.00");
    fixture.refuse_post("child-two.token", &second, 7, "FA-REF-166");
    let remainder = fixture.intent("child-remainder", "400.00");
    fixture.post("child-two.token", &remainder);
    fixture.usage("child-one.token", 2, 1);
    fixture.usage("child-two.token", 2, 1);
}

#[test]
fn cli_daily_spending_without_retained_time_refuses_then_succeeds_under_a_tick() {
    let fixture = Fixture::new(false);
    fixture.issue_root(false);
    let intent = fixture.intent("wait-for-clock", "10.00");
    fixture.refuse_post(
        "root.token",
        &intent,
        i32::from(fa_journal::exit::REFUSAL),
        "FA-REF-095",
    );
    fixture.usage("root.token", 0, 0);
    fixture.tick(DAY_ONE_NS);
    fixture.post("root.token", &intent);
    fixture.usage("root.token", 1, 1);
}

#[test]
fn a_retained_day_boundary_resets_allowance_without_recharging_an_old_retry() {
    let fixture = Fixture::new(true);
    fixture.issue_root(false);
    let first = fixture.intent("day-one", "1000.00");
    let posted = fixture.post("root.token", &first);
    let second = fixture.intent("day-two-backdated", "1000.00");
    fixture.refuse_post("root.token", &second, 7, "FA-REF-166");
    fixture.tick(DAY_TWO_NS);
    let before_retry = fixture.head();
    let retried = fixture.post("root.token", &first);
    assert_eq!(text(&retried, "event"), "recorded");
    assert_eq!(text(data(&retried), "vid"), text(data(&posted), "vid"));
    assert_eq!(fixture.head(), before_retry);
    fixture.usage("root.token", 1, 1);
    // Both intents have effective_date March 15. The retained March 16 tick
    // selects the second quota day; the accounting date cannot select it.
    fixture.post("root.token", &second);
    fixture.usage("root.token", 2, 2);
    let extra = fixture.intent("day-two-over", "0.01");
    fixture.refuse_post("root.token", &extra, 7, "FA-REF-166");
}
