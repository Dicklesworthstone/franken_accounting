//! Issued Human authority through the ordinary CLI, with unchanged MCP ceilings.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa::{Book, BookKeys, Entropy};
use fa_cli::authority::LaunchAuthority;
use fa_cli::cli::{Books, Captured, Files, Stdin, preflight_for_daemon, run, run_with_authority};
use fa_cli::json::{self, Json};
use fa_journal::BookSpec;
use fa_model::{Id128, principal_vid};
use fa_money::UnitRegistry;
use fa_policy::{Capability, CapabilityToken, Op, Profile, possession_digest};
use fa_time::{DateDay, FiscalCalendar};
use fgdb_types::CommitSeq;

const PERIOD: &str = "FY2026-P03";
const ISSUER: &str = "operator-token-issuer";

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let index = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("fa-operator-tokens-{}-{index}", std::process::id()));
        match std::fs::create_dir(&dir) {
            Ok(()) => return dir,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create {}: {error}", dir.display()),
        }
    }
}

fn args(words: &[&str]) -> Vec<String> {
    words
        .iter()
        .copied()
        .chain(["--json"])
        .map(str::to_string)
        .collect()
}

fn event(out: &Captured) -> Json {
    let lines: Vec<_> = out.stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{out:?}");
    fa_cli::verbs::registry()
        .unwrap()
        .check_line(lines[0])
        .unwrap_or_else(|error| panic!("{error}: {out:?}"));
    json::parse(lines[0]).unwrap()
}

fn field<'a>(value: &'a Json, key: &str) -> &'a Json {
    value
        .get("data")
        .and_then(|data| data.get(key))
        .or_else(|| value.get(key))
        .unwrap_or_else(|| panic!("missing {key}: {}", value.render()))
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    field(value, key).as_str().unwrap()
}

fn token(holder: &str, ops: &[Op], seed: u8) -> CapabilityToken {
    let secret = [seed; 32];
    let capability = Capability::new(
        principal_vid(holder),
        Profile::Human,
        ops,
        principal_vid(ISSUER),
    )
    .unwrap()
    .holder_bound(possession_digest(&secret));
    CapabilityToken::new(holder, capability, secret).unwrap()
}

struct Fixture {
    dir: PathBuf,
    book: Book,
    issuer: Capability,
}

impl Fixture {
    fn new(seed: u8) -> Self {
        let units = UnitRegistry::embedded().unwrap();
        let mut book = Book::create_memory(
            BookKeys::for_development(seed),
            BookSpec {
                book_id: Id128([seed; 16]),
                name: "Issued Human operators".into(),
                base_unit: units.lookup("USD").unwrap(),
                calendar: FiscalCalendar::monthly("operator-tokens", 1, 1).unwrap(),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            },
            Entropy::deterministic(u64::from(seed)),
        )
        .unwrap();
        let schema = Capability::embedded(principal_vid(ISSUER), &["schema_change"]).unwrap();
        book.create_periods(2026, schema.holder(), &schema)
            .unwrap()
            .unwrap();
        let mut fixture = Self {
            dir: directory(),
            book,
            issuer: Capability::embedded(
                principal_vid(ISSUER),
                &[
                    "issue_capability",
                    "read",
                    "post",
                    "close",
                    "reopen",
                    "approve",
                    "witness",
                ],
            )
            .unwrap(),
        };
        fixture.owner(&["period", "open", PERIOD]);
        fixture
    }

    fn owner(&mut self, words: &[&str]) -> Json {
        let (exit, out) = run(
            &args(words),
            Books::Held {
                book: &mut self.book,
                dir: self.dir.join("book"),
            },
            Files {
                cwd: Some(self.dir.clone()),
                stdin: Stdin::Missing,
            },
            true,
        );
        assert_eq!(exit, 0, "owner {words:?}: {out:?}");
        event(&out)
    }

    fn issue(&mut self, token: &CapabilityToken) -> LaunchAuthority {
        let key = format!(
            "issue-{}-{}",
            token.principal(),
            self.book.head().unwrap().0
        );
        self.book
            .issue_capability(
                self.issuer.clone(),
                token.capability().clone(),
                DateDay::parse("2026-03-15").unwrap(),
                key.as_bytes(),
                "operator-token test issuance",
            )
            .unwrap()
            .unwrap();
        self.authority(token)
    }

    fn authority(&self, token: &CapabilityToken) -> LaunchAuthority {
        LaunchAuthority::from_operator_token(self.dir.join("book"), None, token)
            .unwrap()
            .with_files(Some(self.dir.clone()))
            .unwrap()
    }

    fn run(
        &mut self,
        authority: &LaunchAuthority,
        words: &[&str],
        input: Option<&str>,
    ) -> (u8, Json) {
        let (exit, out) = run_with_authority(
            &args(words),
            Books::Held {
                book: &mut self.book,
                dir: self.dir.join("book"),
            },
            Files {
                cwd: None,
                stdin: input.map_or(Stdin::Missing, |value| {
                    Stdin::Forwarded(value.as_bytes().to_vec())
                }),
            },
            authority,
            true,
        );
        let event = event(&out);
        assert_eq!(event.get("authority"), Some(&authority.envelope_json()));
        (exit, event)
    }

    fn ok(&mut self, authority: &LaunchAuthority, words: &[&str], input: Option<&str>) -> Json {
        let (exit, event) = self.run(authority, words, input);
        assert_eq!(exit, 0, "{words:?}: {}", event.render());
        event
    }

    fn refused(&mut self, authority: &LaunchAuthority, words: &[&str], code: &str) -> Json {
        let before = self.book.head().unwrap();
        let (exit, event) = self.run(authority, words, None);
        assert_eq!(exit, 7, "{words:?}: {}", event.render());
        assert_eq!(text(&event, "refusal_id"), code, "{}", event.render());
        assert_eq!(self.book.head().unwrap(), before);
        event
    }
}

fn operator_action(event: &Json, book: &Path) {
    let actions = field(event, "next_actions").as_arr().unwrap();
    let action = actions
        .last()
        .expect("an operator can commit the reviewed plan");
    let command = action.get("command").and_then(Json::as_str).unwrap();
    assert!(
        command.starts_with("fa --token '<same-token-file>' "),
        "{command}"
    );
    assert!(command.contains(&book.display().to_string()), "{command}");
    assert!(
        !command.contains("--as") && !command.contains("--grant"),
        "{command}"
    );
    assert!(!command.contains("fa_post_commit_plan"), "{command}");
    assert!(
        action
            .get("why")
            .and_then(Json::as_str)
            .unwrap()
            .contains("original token file")
    );
}

#[test]
fn human_tokens_close_and_approve_exact_plans_without_inheriting_rights() {
    let mut f = Fixture::new(0xb1);
    let controller = f.issue(&token("controller", &[Op::Read, Op::Close, Op::Approve], 1));
    let reviewer = f.issue(&token("reviewer", &[Op::Approve], 2));
    let witness = f.issue(&token("witness", &[Op::Witness], 3));
    let refused = f.refused(
        &controller,
        &["period", "close", PERIOD, "--reason", "Scheduled"],
        "FA-REF-007",
    );
    let rerun = field(&refused, "refusal")
        .get("fix")
        .unwrap()
        .get("rerun_with")
        .unwrap();
    assert_eq!(rerun, &Json::Arr(vec![Json::Str("--yes".into())]));
    let closed = f.ok(
        &controller,
        &["period", "close", PERIOD, "--reason", "Scheduled", "--yes"],
        None,
    );
    assert_eq!(text(&closed, "to"), "Closed");
    assert_eq!(
        field(&closed, "authority")
            .get("profile")
            .and_then(Json::as_str),
        Some("Human")
    );

    let plan = f.ok(
        &controller,
        &[
            "period",
            "lock",
            PERIOD,
            "--reason",
            "AuditComplete",
            "--dry-run",
        ],
        None,
    );
    operator_action(&plan, &f.dir.join("book"));
    let bytes = text(&plan, "bytes").to_string();
    let digest = text(&plan, "proposal_digest").to_string();
    let before = f.book.head().unwrap();
    let (exit, missing) = f.run(
        &controller,
        &["period", "lock", PERIOD, "--plan", "-"],
        Some(&bytes),
    );
    assert_eq!(exit, 7, "{}", missing.render());
    assert_eq!(text(&missing, "refusal_id"), "FA-REF-012");
    assert_eq!(f.book.head().unwrap(), before);

    let self_approval = f.ok(&controller, &["approve", "--proposal", &digest], None);
    let before = f.book.head().unwrap();
    let (exit, refused) = f.run(
        &controller,
        &[
            "period",
            "lock",
            PERIOD,
            "--plan",
            "-",
            "--approval",
            text(&self_approval, "approval_vid"),
        ],
        Some(&bytes),
    );
    assert_eq!(exit, 7, "{}", refused.render());
    assert_eq!(text(&refused, "refusal_id"), "FA-REF-008");
    assert_eq!(f.book.head().unwrap(), before);
    let approval = f.ok(&reviewer, &["approve", "--proposal", &digest], None);
    let locked = f.ok(
        &controller,
        &[
            "period",
            "lock",
            PERIOD,
            "--plan",
            "-",
            "--approval",
            text(&approval, "approval_vid"),
        ],
        Some(&bytes),
    );
    assert_eq!(text(&locked, "to"), "Locked");
    f.ok(&witness, &["checkpoint", "create"], None);
    f.refused(&witness, &["period", "soft-close", PERIOD], "FA-REF-011");
    f.refused(&controller, &["checkpoint", "create"], "FA-REF-011");
    f.refused(
        &controller,
        &[
            "period",
            "reopen",
            PERIOD,
            "--reason",
            "LateTransactions",
            "--yes",
        ],
        "FA-REF-011",
    );
}

#[test]
fn schema_only_human_tokens_record_account_controls_without_inheriting_other_rights() {
    let mut f = Fixture::new(0xb6);
    let witness = f.issue(&token("schema-test-witness", &[Op::Witness], 31));
    f.issuer = Capability::embedded(
        principal_vid(ISSUER),
        &["issue_capability", "schema_change"],
    )
    .unwrap();
    let schema_token = token("schema-manager", &[Op::SchemaChange], 32);
    assert!(LaunchAuthority::from_token(f.dir.join("book"), None, &schema_token).is_err());
    let schema = f.issue(&schema_token);
    assert!(schema.can_confirm());
    assert_eq!(schema.capability(), schema_token.capability());
    let never = f.authority(&token("unissued-schema", &[Op::SchemaChange], 33));
    let open = [
        "chart",
        "open",
        "-",
        "--opened",
        "2026-03-01",
        "--key",
        "human-schema-open",
    ];
    let account = r#"{"code":"6100","name":"Office supplies","type":"Expense","unit":"USD"}"#;

    // Correct posture supplies neither a missing operation nor issuance.
    f.refused(&witness, &open, "FA-REF-011");
    f.refused(&never, &open, "FA-REF-156");
    assert!(f.book.accounts().unwrap().is_empty());

    let before = f.book.head().unwrap();
    let opened = f.ok(&schema, &open, Some(account));
    assert_eq!(text(&opened, "action"), "open");
    assert_eq!(text(&opened, "code"), "6100");
    assert_eq!(field(&opened, "already_recorded"), &Json::Bool(false));
    assert!(f.book.head().unwrap() > before);
    let accounts = f.book.accounts().unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].code, "6100");

    let head = f.book.head().unwrap();
    let retry = f.ok(&schema, &open, Some(account));
    assert_eq!(field(&retry, "already_recorded"), &Json::Bool(true));
    assert_eq!(
        field(&retry, "control_entry"),
        field(&opened, "control_entry")
    );
    assert_eq!(f.book.head().unwrap(), head);

    let closed = f.ok(
        &schema,
        &["chart", "close", "6100", "--on", "2026-03-20"],
        None,
    );
    assert_eq!(text(&closed, "action"), "close");
    assert_eq!(text(&closed, "code"), "6100");
    assert_ne!(
        field(&closed, "control_entry"),
        field(&opened, "control_entry")
    );
    f.refused(&schema, &["checkpoint", "create"], "FA-REF-011");
}

#[test]
fn operator_preflight_keeps_issuance_expiry_revocation_and_scope_admission() {
    let mut f = Fixture::new(0xb2);
    let valid_token = token("valid-witness", &[Op::Witness], 10);
    let expires_at = CommitSeq(f.book.head().unwrap().0 + 1_000);
    let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
    let valid_token = CapabilityToken::new(
        valid_token.principal(),
        valid_token
            .capability()
            .clone()
            .expiring_at(expires_at)
            .with_ceiling(usd, 50_000)
            .unwrap(),
        [10; 32],
    )
    .unwrap();
    let valid = f.issue(&valid_token);
    let discovery = f.ok(&valid, &["capabilities"], None);
    let binding = field(&discovery, "capability").get("binding").unwrap();
    assert_eq!(
        binding.get("expires_at"),
        Some(&Json::Int(i128::from(expires_at.0)))
    );
    assert_eq!(
        binding.get("ceilings"),
        Some(&Json::Arr(vec![Json::Str(format!(
            "unit_id={}, max_mantissa=50000",
            usd.0
        ))]))
    );
    assert_eq!(
        binding.get("posture").and_then(Json::as_str),
        Some("issued-token")
    );
    let never = f.authority(&token("never-issued", &[Op::Witness], 11));
    let expiring = token("expired-witness", &[Op::Witness], 12);
    let expiring = CapabilityToken::new(
        expiring.principal(),
        expiring
            .capability()
            .clone()
            .expiring_at(CommitSeq(f.book.head().unwrap().0 + 1)),
        [12; 32],
    )
    .unwrap();
    let expired = f.issue(&expiring);
    let revoked_token = token("revoked-witness", &[Op::Witness], 13);
    let revoked = f.issue(&revoked_token);
    f.book
        .revoke_capability(
            f.issuer.clone(),
            revoked_token.capability().commitment().unwrap(),
            DateDay::parse("2026-03-15").unwrap(),
            b"revoke-operator-witness",
            "operator-token test revocation",
        )
        .unwrap()
        .unwrap();
    let scoped_token = token("scoped-witness", &[Op::Witness], 14);
    let scoped_token = CapabilityToken::new(
        scoped_token.principal(),
        scoped_token
            .capability()
            .clone()
            .for_periods(&[PERIOD])
            .unwrap(),
        [14; 32],
    )
    .unwrap();
    let scoped = f.issue(&scoped_token);
    let mut other = Fixture::new(0xb3);
    let foreign_token = token("foreign-witness", &[Op::Witness], 15);
    other.issue(&foreign_token);
    let foreign = f.authority(&foreign_token);
    let close_only = f.issue(&token("close-only", &[Op::Close], 16));

    let before = f.book.head().unwrap();
    assert_eq!(
        preflight_for_daemon(
            &args(&["checkpoint", "create"]),
            &mut f.book,
            f.dir.join("book"),
            Some(f.dir.clone()),
            None,
            Some(&valid),
        ),
        Ok(true)
    );
    assert_eq!(f.book.head().unwrap(), before);
    for (authority, code) in [
        (&never, "FA-REF-156"),
        (&expired, "FA-REF-014"),
        (&revoked, "FA-REF-023"),
        (&foreign, "FA-REF-156"),
        (&scoped, "FA-REF-011"),
        (&close_only, "FA-REF-011"),
    ] {
        let before = f.book.head().unwrap();
        let (exit, out) = preflight_for_daemon(
            &args(&["checkpoint", "create"]),
            &mut f.book,
            f.dir.join("book"),
            Some(f.dir.clone()),
            None,
            Some(authority),
        )
        .expect_err("inadmissible authority cannot request a fresh command tick");
        assert_eq!(exit, 7, "{out:?}");
        assert_eq!(text(&event(&out), "refusal_id"), code, "{out:?}");
        assert_eq!(f.book.head().unwrap(), before);
        f.refused(authority, &["checkpoint", "create"], code);
    }
}

#[test]
fn operator_confirmation_preserves_identity_paths_and_exact_void_plan_capability() {
    let mut f = Fixture::new(0xb4);
    std::fs::write(f.dir.join("chart.json"), r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#).unwrap();
    f.owner(&["chart", "import", "chart.json"]);
    std::fs::write(f.dir.join("receipt.txt"), "Evidence for held amount").unwrap();
    let document = f.owner(&[
        "document",
        "add",
        "receipt.txt",
        "--kind",
        "Receipt",
        "--grade",
        "HumanUpload",
    ]);
    let evidence = text(&document, "oid").to_string();
    let operator = f.issue(&token("operator-a", &[Op::Read, Op::Post, Op::Witness], 20));
    // Another issued secret for the same principal still has a distinct
    // capability commitment and cannot replay the original token's plan.
    let other = f.issue(&token("operator-a", &[Op::Read, Op::Post, Op::Witness], 21));
    let preparer = f.issue(&token("restricted-preparer", &[Op::Read, Op::Post], 22));
    for (flag, value) in [
        ("--as", "other"),
        ("--grant", "close"),
        ("--book", "/other"),
        ("--keys", "/other"),
        ("--via", "direct"),
        ("--token", "other.token"),
        ("--issuer-token", "other.token"),
    ] {
        let before = f.book.head().unwrap();
        let (exit, _) = f.run(&operator, &["checkpoint", "create", flag, value], None);
        assert_eq!(exit, 2, "{flag} never overrides bound authority");
        assert_eq!(f.book.head().unwrap(), before);
    }
    for path in ["../escape.plan", "/outside.plan"] {
        let before = f.book.head().unwrap();
        let (exit, error) = f.run(&operator, &["commit", "--plan", path], None);
        assert_eq!(exit, 2, "{}", error.render());
        assert!(text(&error, "message").contains("outside"));
        assert_eq!(f.book.head().unwrap(), before);
    }
    let (exit, _) = f.run(&preparer, &["commit", "--plan", "-", "--yes"], None);
    assert_eq!(
        exit, 2,
        "a Human Preparer token has no confirmation posture"
    );

    for batch in [false, true] {
        let key = if batch { "batch" } else { "single" };
        let pending = format!(
            r#"{{"effective_date":"2026-03-15","idempotency_key":"hold-{key}","legs":[{{"side":"debit","account":"1000","amount":"5.00 USD"}},{{"side":"credit","account":"4000","amount":"5.00 USD"}}]}}"#
        );
        let held = f.ok(
            &operator,
            &["reserve", "--intent", "-", "--evidence", &evidence],
            Some(&pending),
        );
        let void = format!(
            r#"{{"class":"Resolution","effective_date":"2026-03-15","idempotency_key":"void-{key}","resolves":"{}","disposition":"voids"}}"#,
            text(&held, "vid")
        );
        let intent = if batch {
            format!(r#"{{"idempotency_key":"release-batch","intents":[{void}]}}"#)
        } else {
            void
        };
        let verb = if batch { "post" } else { "resolve" };
        let before = f.book.head().unwrap();
        let plan = f.ok(
            &operator,
            &[verb, "--intent", "-", "--dry-run"],
            Some(&intent),
        );
        let access = f.book.access_log(before).unwrap();
        assert_eq!(access.len(), 1);
        assert_eq!(access[0].record.command, verb);
        assert_eq!(access[0].record.principal_name, "operator-a");
        assert_eq!(access[0].observed_at, before);
        assert_eq!(access[0].recorded_at.0, before.0 + 1);
        let prepared_at = f.book.head().unwrap();
        assert_eq!(
            prepared_at, access[0].recorded_at,
            "plan delivery publishes only its audit receipt"
        );
        assert_eq!(text(&plan, "authority"), "issued-token");
        operator_action(&plan, &f.dir.join("book"));
        let bytes = text(&plan, "bytes");
        let (exit, wrong) = f.run(&other, &["commit", "--plan", "-"], Some(bytes));
        assert_eq!(exit, 6, "{}", wrong.render());
        assert_eq!(text(&wrong, "refusal_id"), "FA-REF-034");
        assert_eq!(f.book.head().unwrap(), prepared_at);
        let (exit, refused) = f.run(&preparer, &["commit", "--plan", "-"], Some(bytes));
        assert_eq!(exit, 7, "{}", refused.render());
        assert_eq!(text(&refused, "refusal_id"), "FA-REF-007");
        assert_eq!(f.book.head().unwrap(), prepared_at);
        let committed = f.ok(&operator, &["commit", "--plan", "-"], Some(bytes));
        assert_eq!(
            text(&committed, "event"),
            if batch {
                "batch_plan_committed"
            } else {
                "plan_committed"
            }
        );
        let recorded = f.book.head().unwrap();
        f.ok(&operator, &["commit", "--plan", "-"], Some(bytes));
        assert_eq!(
            f.book.head().unwrap(),
            recorded,
            "exact retry does not release twice"
        );
    }
}

#[test]
fn ordinary_cli_binds_human_operator_tokens_and_keeps_confirmation_explicit() {
    let dir = directory();
    let invoke = |words: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fa"))
            .current_dir(&dir)
            .args(["--book", "book", "--json"])
            .args(words)
            .env_remove("FA_BOOK")
            .env_remove("FA_TOKEN")
            .output()
            .unwrap();
        let captured = Captured {
            stdout: String::from_utf8(output.stdout).unwrap(),
            stderr: String::from_utf8(output.stderr).unwrap(),
        };
        (output.status.code().unwrap_or(-1), event(&captured))
    };
    for words in [
        vec!["book", "create", "--name", "Human token CLI"],
        vec!["period", "create", "--fiscal-year", "2026"],
        vec!["period", "open", PERIOD],
        vec![
            "capability",
            "issue",
            "--holder",
            "human-witness",
            "--profile",
            "human",
            "--op",
            "witness",
            "--out",
            "witness.token",
            "--grant",
            "issue_capability",
            "--grant",
            "witness",
        ],
        vec![
            "capability",
            "issue",
            "--holder",
            "human-controller",
            "--profile",
            "human",
            "--op",
            "close",
            "--out",
            "controller.token",
            "--grant",
            "issue_capability",
            "--grant",
            "close",
        ],
        vec![
            "capability",
            "issue",
            "--holder",
            "human-schema",
            "--profile",
            "human",
            "--op",
            "schema_change",
            "--out",
            "schema.token",
            "--grant",
            "issue_capability",
            "--grant",
            "schema_change",
        ],
    ] {
        let (exit, event) = invoke(&words);
        assert_eq!(exit, 0, "{words:?}: {}", event.render());
    }
    std::fs::write(
        dir.join("account.json"),
        r#"{"code":"6100","name":"Office supplies","type":"Expense","unit":"USD"}"#,
    )
    .unwrap();
    let (exit, refused) = invoke(&[
        "--token",
        "witness.token",
        "chart",
        "open",
        "account.json",
        "--opened",
        "2026-03-01",
    ]);
    assert_eq!(exit, 7, "{}", refused.render());
    assert_eq!(text(&refused, "refusal_id"), "FA-REF-011");
    let (exit, opened) = invoke(&[
        "--token",
        "schema.token",
        "chart",
        "open",
        "account.json",
        "--opened",
        "2026-03-01",
    ]);
    assert_eq!(exit, 0, "{}", opened.render());
    assert_eq!(text(&opened, "action"), "open");
    assert_eq!(text(&opened, "code"), "6100");
    assert_eq!(
        field(&opened, "authority")
            .get("profile")
            .and_then(Json::as_str),
        Some("Human")
    );
    let (exit, checkpoint) = invoke(&["--token", "witness.token", "checkpoint", "create"]);
    assert_eq!(exit, 0, "{}", checkpoint.render());
    assert_eq!(
        field(&checkpoint, "authority")
            .get("profile")
            .and_then(Json::as_str),
        Some("Human")
    );
    let (exit, refused) = invoke(&[
        "--token",
        "controller.token",
        "period",
        "close",
        PERIOD,
        "--reason",
        "Scheduled",
    ]);
    assert_eq!(exit, 7, "{}", refused.render());
    assert_eq!(text(&refused, "refusal_id"), "FA-REF-007");
    let (exit, closed) = invoke(&[
        "--token",
        "controller.token",
        "period",
        "close",
        PERIOD,
        "--reason",
        "Scheduled",
        "--yes",
    ]);
    assert_eq!(exit, 0, "{}", closed.render());
    assert_eq!(text(&closed, "to"), "Closed");
}
