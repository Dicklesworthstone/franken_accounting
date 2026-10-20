//! Daily spending limits through persisted books and actual CLI token sessions.
//! Delegation covers the native operator API and the CLI issuer-token route;
//! MCP/preparer launch ceilings stay unchanged while lower Human descendants
//! spend through `fa --token`.

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
fn cli_issuer_tokens_preserve_a_shared_budget_across_children_and_grandchildren() {
    let fixture = Fixture::new(true);
    let root = fixture.issue_root(true);
    let root_commitment = root.capability().commitment().unwrap();
    let root_hex = hex(&root_commitment);
    let root_unit = *root.capability().daily_totals().keys().next().unwrap();

    // Issuers retain IssueCapability and are used only by the operator route.
    // The actual spending tokens are lower Human grants within the unchanged
    // Preparer launch ceiling, including one grandchild of the original root.
    for (issuer, holder, output, limit, delegates, maximum, expected_issuer) in [
        (
            "root.token",
            "daily-child-issuer",
            "child-issuer.token",
            Some("800.00 USD"),
            true,
            80_000,
            "daily-root",
        ),
        (
            "child-issuer.token",
            "daily-grandchild",
            "grandchild.token",
            Some("600.00 USD"),
            false,
            60_000,
            "daily-child-issuer",
        ),
        (
            "root.token",
            "daily-root-leaf",
            "root-leaf.token",
            None,
            false,
            100_000,
            "daily-root",
        ),
    ] {
        let mut args = vec![
            "capability",
            "issue",
            "--issuer-token",
            issuer,
            "--holder",
            holder,
            "--profile",
            "human",
            "--op",
            "read",
            "--op",
            "post",
            "--op",
            "verify",
            "--out",
            output,
        ];
        if let Some(limit) = limit {
            args.extend(["--daily-total", limit]);
        }
        if delegates {
            args.extend(["--op", "issue_capability"]);
        }
        let issuer_token =
            CapabilityToken::decode(&std::fs::read(fixture.dir.join(issuer)).unwrap()).unwrap();
        let issued = fixture.ok(&args);
        assert_eq!(text(&issued, "event"), "capability_issued");
        let authority = issued.get("authority").unwrap();
        assert_eq!(text(authority, "posture"), "issued-token");
        assert_eq!(
            text(authority, "principal"),
            expected_issuer,
            "the envelope must identify the retained token issuer"
        );
        assert_eq!(
            text(authority, "profile"),
            issuer_token.capability().profile().name()
        );
        assert_eq!(
            authority.get("ops"),
            Some(&Json::Arr(
                issuer_token
                    .capability()
                    .ops()
                    .iter()
                    .map(|op| Json::Str(op.name().to_string()))
                    .collect()
            )),
            "disclosure must name the actual issuer operations without reconstructing a grant"
        );
        assert_eq!(text(data(&issued), "token"), output);
        assert_eq!(
            data(&issued).get("already_recorded"),
            Some(&Json::Bool(false))
        );
        let token =
            CapabilityToken::decode(&std::fs::read(fixture.dir.join(output)).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(fixture.dir.join(output))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600,
                "the issued holder secret must stay private"
            );
        }
        let cap = token.capability();
        assert_eq!(cap.profile(), Profile::Human);
        assert_eq!(cap.ops().contains(&Op::IssueCapability), delegates);
        assert_eq!(cap.holder(), fa_model::principal_vid(holder));
        assert_eq!(cap.issuer(), fa_model::principal_vid(expected_issuer));
        assert_eq!(cap.daily_root(), Some(root_commitment));
        assert_eq!(cap.daily_totals().len(), 1);
        assert_eq!(cap.daily_totals().get(&root_unit), Some(&maximum));
        assert_eq!(
            text(data(&issued), "commitment"),
            hex(&cap.commitment().unwrap())
        );
        let detail = fixture.ok(&[
            "capability",
            "show",
            "--commitment",
            text(data(&issued), "commitment"),
        ]);
        let retained = data(&detail).get("capability").unwrap();
        assert_eq!(text(retained, "daily_root"), root_hex);
        assert_eq!(
            text(retained, "issuer"),
            format!("{:032x}", fa_model::principal_vid(expected_issuer).0)
        );
        let Some(Json::Arr(totals)) = retained.get("daily_totals") else {
            panic!("missing inherited daily totals: {detail:?}");
        };
        assert_eq!(totals.len(), 1);
        assert_eq!(number(&totals[0], "unit_id"), i128::from(root_unit.0));
        assert_eq!(number(&totals[0], "max_mantissa"), maximum);
    }

    // A valid issuer token cannot be combined with a different principal or
    // an embedded grant. Neither refusal may journal an issuance or leave a
    // usable token behind.
    for (flag, value, output) in [
        ("--as", "different-issuer", "spoofed-issuer.token"),
        ("--grant", "privileged", "widened-issuer.token"),
    ] {
        let before = fixture.head();
        let (status, refusal) = fixture.run(&[
            "capability",
            "issue",
            "--issuer-token",
            "root.token",
            "--holder",
            "must-not-be-issued",
            "--profile",
            "human",
            "--op",
            "read",
            "--out",
            output,
            flag,
            value,
        ]);
        assert_eq!(status, 2, "{flag}: {refusal:?}");
        assert_eq!(text(&refusal, "event"), "error");
        assert_eq!(text(data(&refusal), "class"), "usage");
        assert_eq!(fixture.head(), before);
        assert!(!fixture.dir.join(output).exists(), "{flag} created a token");
    }

    let sibling_spend = fixture.intent("cli-root-leaf-first", "400.00");
    fixture.post("root-leaf.token", &sibling_spend);
    let grandchild_spend = fixture.intent("cli-grandchild-first", "200.00");
    fixture.post("grandchild.token", &grandchild_spend);
    let too_much = fixture.intent("cli-grandchild-over-shared-total", "0.01");
    fixture.refuse_post("grandchild.token", &too_much, 7, "FA-REF-166");
    let remaining = fixture.intent("cli-root-leaf-remainder", "400.00");
    fixture.post("root-leaf.token", &remaining);
    let exhausted = fixture.intent("cli-original-root-exhausted", "0.01");
    fixture.refuse_post("root-leaf.token", &exhausted, 7, "FA-REF-166");
    fixture.usage("root-leaf.token", 3, 1);
    fixture.usage("grandchild.token", 3, 1);

    let revoked = fixture.ok(&[
        "capability",
        "revoke",
        "--commitment",
        &root_hex,
        "--grant",
        "issue_capability",
        "--grant",
        "read",
        "--yes",
    ]);
    assert_eq!(text(&revoked, "event"), "capability_revoked");
    let before = fixture.head();
    let (status, refusal) = fixture.run(&[
        "capability",
        "issue",
        "--issuer-token",
        "child-issuer.token",
        "--holder",
        "revoked-root-descendant",
        "--profile",
        "human",
        "--op",
        "read",
        "--op",
        "post",
        "--out",
        "revoked-root-descendant.token",
    ]);
    assert_eq!(status, 7, "{refusal:?}");
    assert_eq!(text(data(&refusal), "refusal_id"), "FA-REF-023");
    assert_eq!(fixture.head(), before);
    assert!(!fixture.dir.join("revoked-root-descendant.token").exists());
    fixture.refuse_post(
        "grandchild.token",
        "missing-after-root-revocation.json",
        7,
        "FA-REF-023",
    );
}

#[test]
fn cli_issuer_credentials_are_bounded_explicit_and_issue_only() {
    let fixture = Fixture::new(false);
    fixture.issue_root(true);
    std::fs::write(
        fixture.dir.join("malformed-issuer.token"),
        b"this is not a canonical capability token",
    )
    .unwrap();
    std::fs::write(
        fixture.dir.join("oversized-issuer.token"),
        vec![0_u8; fa_policy::capability::MAX_TOKEN_BYTES + 1],
    )
    .unwrap();
    let cases: [(&str, &[&str], &str); 5] = [
        (
            "malformed",
            &["--issuer-token", "malformed-issuer.token"],
            "--issuer-token malformed-issuer.token",
        ),
        (
            "oversized",
            &["--issuer-token", "oversized-issuer.token"],
            "64 KiB token limit",
        ),
        ("stdin", &["--issuer-token", "-"], "stdin is not accepted"),
        (
            "empty",
            &["--issuer-token", ""],
            "exactly one nonempty token file",
        ),
        (
            "duplicate",
            &[
                "--issuer-token",
                "root.token",
                "--issuer-token",
                "root.token",
            ],
            "exactly one nonempty token file",
        ),
    ];
    for (name, flags, expected_message) in cases {
        let output = format!("rejected-{name}.token");
        let mut args = vec![
            "capability",
            "issue",
            "--holder",
            "rejected-credential-child",
            "--profile",
            "human",
            "--op",
            "read",
            "--out",
            &output,
        ];
        args.extend_from_slice(flags);
        let before = fixture.head();
        let (status, refusal) = fixture.run(&args);
        assert_eq!(status, 2, "{name}: {refusal:?}");
        assert_eq!(text(&refusal, "event"), "error");
        assert_eq!(text(data(&refusal), "class"), "usage");
        assert_eq!(data(&refusal).get("refusal_id"), Some(&Json::Null));
        assert!(
            text(data(&refusal), "message").contains(expected_message),
            "{name}: {refusal:?}"
        );
        assert_eq!(fixture.head(), before, "{name} journaled an issuance");
        assert!(
            !fixture.dir.join(&output).exists(),
            "{name} created a token"
        );
    }
    let before = fixture.head();
    let (status, refusal) = fixture.run(&["capability", "list", "--issuer-token", "root.token"]);
    assert_eq!(status, 2, "{refusal:?}");
    assert_eq!(text(&refusal, "event"), "error");
    assert_eq!(text(data(&refusal), "class"), "usage");
    assert!(
        text(data(&refusal), "message").contains("capability issue"),
        "{refusal:?}"
    );
    assert_eq!(fixture.head(), before);
}

#[test]
fn daemon_issuer_credentials_stay_inside_the_configured_files_root() {
    let fixture = Fixture::new(false);
    fixture.issue_root(true);
    let allowed = fixture.dir.join("allowed");
    std::fs::create_dir(&allowed).unwrap();
    // fad canonicalizes its --files-root at launch; so does this test, so a
    // temp dir reached through a symlink (macOS /var -> /private/var) is
    // the root the daemon would hold.
    let allowed = fa_cli::authority::validate_files_root(allowed).unwrap();
    let issuer = fixture.dir.join("root.token");
    let output = allowed.join("must-not-be-issued.token");
    assert!(issuer.is_absolute());
    let before = fixture.head();
    let mut book = fixture.open();
    let args = [
        "capability",
        "issue",
        "--issuer-token",
        issuer.to_str().unwrap(),
        "--holder",
        "outside-issuer-child",
        "--profile",
        "human",
        "--op",
        "read",
        "--out",
        output.to_str().unwrap(),
        "--json",
    ]
    .map(String::from);
    let (status, captured) = fa_cli::cli::run_for_daemon(
        &args,
        &mut book,
        fixture.book.clone(),
        Some(allowed),
        None,
        fa_cli::cli::Stdin::Missing,
        true,
    );
    assert_eq!(status, 2, "{captured:?}");
    let lines: Vec<_> = captured.stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{captured:?}");
    fa_cli::verbs::registry()
        .unwrap()
        .check_line(lines[0])
        .unwrap();
    let refusal = json::parse(lines[0]).unwrap();
    assert_eq!(text(&refusal, "event"), "error");
    assert_eq!(text(data(&refusal), "class"), "usage");
    assert_eq!(data(&refusal).get("refusal_id"), Some(&Json::Null));
    let message = text(data(&refusal), "message");
    assert!(message.contains("--issuer-token path"), "{refusal:?}");
    assert!(
        message.contains("outside the daemon --files-root"),
        "{refusal:?}"
    );
    assert!(!output.exists());
    assert_eq!(i128::from(book.head().unwrap().0), before);
    drop(book);
    assert_eq!(fixture.head(), before);
}

#[test]
fn token_bound_cli_cannot_replace_its_authority_with_an_issuer_token() {
    let fixture = Fixture::new(false);
    let token = fixture.issue_root(false);
    assert!(!token.capability().ops().contains(&Op::IssueCapability));
    let before = fixture.head();
    let (status, refusal) = fixture.run(&[
        "--token",
        "root.token",
        "capability",
        "issue",
        "--issuer-token",
        "root.token",
        "--holder",
        "launch-override-child",
        "--op",
        "read",
        "--out",
        "launch-override-child.token",
    ]);
    assert_eq!(status, 2, "{refusal:?}");
    assert_eq!(text(&refusal, "event"), "error");
    assert_eq!(text(data(&refusal), "class"), "usage");
    assert_eq!(data(&refusal).get("refusal_id"), Some(&Json::Null));
    assert!(
        text(data(&refusal), "message")
            .contains("--issuer-token cannot override launch-bound authority"),
        "{refusal:?}"
    );
    assert_eq!(fixture.head(), before);
    assert!(!fixture.dir.join("launch-override-child.token").exists());
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
