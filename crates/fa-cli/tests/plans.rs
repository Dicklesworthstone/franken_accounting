//! Portable posting plans through separate real CLI processes (fa-we7).
//! The observations use reopened books, not the preparer's staged view.

#![forbid(unsafe_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::authority::{LaunchAuthority, LaunchProfile};
use fa_cli::cli::{Files, Stdin};
use fa_cli::entry::fa_with_authority;
use fa_cli::json::{self, Json};

fn run(book: &Path, args: &[&str], input: Option<&[u8]>) -> (i32, Json) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run fa");
    if let Some(input) = input {
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(input)
            .expect("write plan input");
    }
    let result = child.wait_with_output().expect("wait for fa");
    let code = result.status.code().unwrap_or(-1);
    let stdout = String::from_utf8(result.stdout).expect("UTF-8 stdout");
    let stderr = String::from_utf8_lossy(&result.stderr);
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "args={args:?}\n{stdout}\n{stderr}");
    fa_cli::verbs::registry()
        .expect("registry")
        .check_line(lines[0])
        .unwrap_or_else(|e| panic!("args={args:?}: {e}\n{stdout}\n{stderr}"));
    let line = json::parse(lines[0]).expect("one robot line");
    assert_eq!(
        text(&line, "event") == "error",
        code != 0,
        "{stdout}\n{stderr}"
    );
    (code, line)
}

fn ok(book: &Path, args: &[&str]) -> Json {
    let (code, line) = run(book, args, None);
    assert_eq!(code, 0, "args={args:?}: {}", line.render());
    line
}

fn commit_bound(authority: &LaunchAuthority, plan: &str) -> (u8, Json) {
    let argv = ["commit", "--plan", "-", "--json"].map(str::to_string);
    let (code, out) = fa_with_authority(
        &argv,
        Files {
            cwd: None,
            stdin: Stdin::Forwarded(plan.as_bytes().to_vec()),
        },
        authority,
        true,
    );
    let lines: Vec<_> = out.stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{out:?}");
    fa_cli::verbs::registry()
        .expect("registry")
        .check_line(lines[0])
        .unwrap_or_else(|error| panic!("{error}\n{out:?}"));
    let line = json::parse(lines[0]).expect("bound robot line");
    assert_eq!(line.get("authority"), Some(&authority.envelope_json()));
    (code, line)
}

fn get<'a>(value: &'a Json, key: &str) -> &'a Json {
    value
        .get("data")
        .and_then(|data| data.get(key))
        .or_else(|| value.get(key))
        .expect(key)
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    get(value, key).as_str().expect(key)
}

fn integer(value: &Json, key: &str) -> i128 {
    match get(value, key) {
        Json::Int(value) => *value,
        value => panic!("{key} must be an integer: {value:?}"),
    }
}

fn head(book: &Path) -> i128 {
    integer(get(&ok(book, &["book", "info"]), "coordinate"), "known_at")
}

fn write(dir: &Path, name: &str, contents: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write retained fixture");
    path.display().to_string()
}

struct Fixture {
    dir: PathBuf,
    book: PathBuf,
    evidence: String,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = loop {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!("fa-plans-cli-{}-{n}", std::process::id()));
            match std::fs::create_dir(&dir) {
                Ok(()) => break dir,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create {}: {error}", dir.display()),
            }
        };
        let book = dir.join("book");
        ok(&book, &["book", "create", "--name", "Plans Co"]);
        let chart = write(
            &dir,
            "chart.json",
            r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
        );
        ok(&book, &["chart", "import", &chart]);
        ok(&book, &["period", "create", "--fiscal-year", "2026"]);
        ok(&book, &["period", "open", "FY2026-P03"]);
        let source = write(
            &dir,
            "receipt.txt",
            "Receipt for exact posting-plan fixture.",
        );
        let document = ok(
            &book,
            &[
                "document",
                "add",
                &source,
                "--kind",
                "Receipt",
                "--grade",
                "HumanUpload",
            ],
        );
        Self {
            dir,
            book,
            evidence: text(&document, "oid").to_string(),
        }
    }

    fn intent(&self, key: &str, amount: &str) -> String {
        write(
            &self.dir,
            &format!("{key}.json"),
            &format!(
                r#"{{"effective_date":"2026-03-10","description":"Retain this randomized seal","idempotency_key":"{key}","legs":[{{"side":"debit","account":"1000","amount":"{amount} USD"}},{{"side":"credit","account":"4000","amount":"{amount} USD"}}]}}"#
            ),
        )
    }

    fn plan(&self, intent: &str) -> Json {
        ok(
            &self.book,
            &[
                "post",
                "--intent",
                intent,
                "--evidence",
                &self.evidence,
                "--dry-run",
            ],
        )
    }
}

#[test]
fn binary_plan_survives_reopen_preserves_seals_and_exact_retries() {
    let f = Fixture::new();
    let intent = f.intent("sale", "12.34");
    let output = f.dir.join("sale.plan");
    let before = head(&f.book);
    let planned = ok(
        &f.book,
        &[
            "post",
            "--intent",
            &intent,
            "--evidence",
            &f.evidence,
            "--dry-run",
            "--plan-out",
            &output.display().to_string(),
        ],
    );
    assert_eq!(text(&planned, "event"), "plan");
    assert_eq!(text(&planned, "scope"), "same-snapshot-post");
    assert_eq!(text(&planned, "authority"), "embedded-owner");
    assert_eq!(get(&planned, "certificate"), &Json::Null);
    assert_eq!(integer(&planned, "snapshot_seq"), before);
    assert_eq!(
        head(&f.book),
        before,
        "planning must not publish metadata or journal data"
    );
    let bytes = std::fs::read(&output).expect("saved binary plan");
    let plan = fa::PostPlan::decode(&bytes).expect("canonical portable plan");
    assert_eq!(plan.proposal().effective_date.render(), "2026-03-10");
    assert_eq!(plan.proposal().legs[0].amount.mantissa, 1234);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let committed = ok(
        &f.book,
        &["commit", "--plan", &output.display().to_string()],
    );
    assert_eq!(text(&committed, "event"), "plan_committed");
    assert_eq!(get(&committed, "already_recorded"), &Json::Bool(false));
    for field in ["plan_digest", "certificate_digest"] {
        assert_eq!(text(&committed, field), text(&planned, field));
    }
    let entry = ok(&f.book, &["entry", "show", text(&committed, "vid")]);
    // The digest binds the exact randomized sealed description and every
    // proposal field. A newly sealed equivalent plaintext would differ.
    assert_eq!(
        text(&entry, "proposal_digest"),
        text(&planned, "proposal_digest")
    );
    let committed_head = head(&f.book);
    assert!(committed_head > before);
    let retry = ok(
        &f.book,
        &["commit", "--plan", &output.display().to_string()],
    );
    assert_eq!(get(&retry, "already_recorded"), &Json::Bool(true));
    assert_eq!(get(&retry, "period"), &Json::Null);
    for field in ["vid", "entry_digest", "plan_digest", "certificate_digest"] {
        assert_eq!(text(&retry, field), text(&committed, field));
    }
    assert_eq!(
        integer(&retry, "recorded_at"),
        integer(&committed, "recorded_at")
    );
    assert_eq!(head(&f.book), committed_head);
    let ordinary_retry = ok(
        &f.book,
        &["post", "--intent", &intent, "--evidence", &f.evidence],
    );
    assert_eq!(text(&ordinary_retry, "event"), "recorded");
    assert_eq!(text(&ordinary_retry, "vid"), text(&committed, "vid"));
    assert_eq!(head(&f.book), committed_head);
    let reversal = ok(
        &f.book,
        &[
            "reverse",
            text(&committed, "vid"),
            "--reason",
            "WrongAmount",
            "--dry-run",
        ],
    );
    assert_eq!(text(&reversal, "class"), "Reversal");
    assert_eq!(text(&reversal, "effective_date"), "2026-03-10");
    let legs = get(&reversal, "legs").as_arr().unwrap();
    assert_eq!(text(&legs[0], "side"), "credit");
    assert_eq!(text(&legs[0], "amount"), "12.34 USD");
    let lineage = get(&reversal, "supersedes").as_arr().unwrap();
    assert_eq!(text(&lineage[0], "entry"), text(&committed, "vid"));
    assert_eq!(text(&lineage[0], "reason"), "WrongAmount");
    assert_eq!(head(&f.book), committed_head);
    let (code, reversed) = run(
        &f.book,
        &["commit", "--plan", "-"],
        Some(text(&reversal, "bytes").as_bytes()),
    );
    assert_eq!(code, 0, "{}", reversed.render());
    assert_eq!(get(&reversed, "already_recorded"), &Json::Bool(false));
}

#[test]
fn tampered_wrong_caller_and_stale_plans_cannot_publish_or_consume_the_key() {
    let f = Fixture::new();
    let intent = f.intent("replan", "7.25");
    let planned = f.plan(&intent);
    let before = head(&f.book);
    let encoded = text(&planned, "bytes");
    let (code, error) = run(
        &f.book,
        &["commit", "--plan", "-", "--as", "another-preparer"],
        Some(encoded.as_bytes()),
    );
    assert_eq!(code, 7, "{}", error.render());
    assert_eq!(text(&error, "refusal_id"), "FA-REF-011");
    assert_eq!(head(&f.book), before);
    // A lawful capability held by the original principal still has to
    // match the exact capability reviewed and authenticated by the plan.
    let (code, error) = run(
        &f.book,
        &["commit", "--plan", "-", "--grant", "read"],
        Some(encoded.as_bytes()),
    );
    assert_eq!(code, 6, "{}", error.render());
    assert_eq!(text(&error, "refusal_id"), "FA-REF-034");
    assert_eq!(head(&f.book), before);
    // Authentication is the final fixed field. A bit change remains a
    // decodable artifact, then must fail the book's authentic issuance check.
    let mut tampered = encoded.as_bytes().to_vec();
    let last = tampered.last_mut().expect("non-empty plan hex");
    *last = if *last == b'0' { b'1' } else { b'0' };
    let (code, error) = run(&f.book, &["commit", "--plan", "-"], Some(&tampered));
    assert_eq!(code, 6, "{}", error.render());
    assert_eq!(text(&error, "refusal_id"), "FA-REF-034");
    assert_eq!(head(&f.book), before);
    // A metadata-only publication is enough to invalidate the first-slice
    // same-snapshot contract; it need not change this entry's account balances.
    let later = write(&f.dir, "later.txt", "A later independent source document.");
    ok(
        &f.book,
        &[
            "document",
            "add",
            &later,
            "--kind",
            "Receipt",
            "--grade",
            "HumanUpload",
        ],
    );
    let advanced = head(&f.book);
    assert!(advanced > before);
    let (code, error) = run(
        &f.book,
        &["commit", "--plan", "-"],
        Some(encoded.as_bytes()),
    );
    assert_eq!(code, 6, "{}", error.render());
    assert_eq!(text(&error, "refusal_id"), "FA-REF-034");
    assert_eq!(head(&f.book), advanced);
    let fresh = f.plan(&intent);
    assert_eq!(integer(&fresh, "snapshot_seq"), advanced);
    let (code, committed) = run(
        &f.book,
        &["commit", "--plan", "-"],
        Some(text(&fresh, "bytes").as_bytes()),
    );
    assert_eq!(code, 0, "{}", committed.render());
    assert_eq!(get(&committed, "already_recorded"), &Json::Bool(false));
}

#[test]
fn law_refusals_and_artifact_output_failures_do_not_emit_a_plan_or_write() {
    let f = Fixture::new();
    let good = f.intent("good", "5.00");
    let bad = write(
        &f.dir,
        "unbalanced.json",
        r#"{"effective_date":"2026-03-10","idempotency_key":"bad","legs":[{"side":"debit","account":"1000","amount":"5.00 USD"},{"side":"credit","account":"4000","amount":"4.99 USD"}]}"#,
    );
    let before = head(&f.book);
    let output = f.dir.join("refused.plan");
    let (code, error) = run(
        &f.book,
        &[
            "post",
            "--intent",
            &bad,
            "--evidence",
            &f.evidence,
            "--dry-run",
            "--plan-out",
            &output.display().to_string(),
        ],
        None,
    );
    assert_eq!(code, 3, "{}", error.render());
    assert_eq!(text(&error, "refusal_id"), "FA-REF-001");
    assert!(!output.exists());
    assert_eq!(head(&f.book), before);
    let existing = write(&f.dir, "existing.plan", "KEEP THIS ARTIFACT");
    for extra in [
        vec!["--plan-out", existing.as_str()],
        vec!["--dry-run", "--plan-out", existing.as_str()],
        vec!["--dry-run", "--plan-out", "-"],
        vec!["--dry-run", "--balancing", "0"],
    ] {
        let mut args = vec!["post", "--intent", &good, "--evidence", &f.evidence];
        args.extend(extra);
        let (code, error) = run(&f.book, &args, None);
        assert_eq!(code, 2, "{}", error.render());
        assert_eq!(head(&f.book), before);
        assert_eq!(
            std::fs::read_to_string(&existing).unwrap(),
            "KEEP THIS ARTIFACT"
        );
    }
    for bytes in [
        b"not a plan".as_slice(),
        b"FA-POST-PLAN\0\x01".as_slice(),
        b"00ff".as_slice(),
    ] {
        let (code, error) = run(&f.book, &["commit", "--plan", "-"], Some(bytes));
        assert_eq!(code, 2, "{}", error.render());
        assert_eq!(head(&f.book), before);
    }
}

#[test]
fn void_dry_run_keeps_the_hold_until_the_exact_plan_is_committed() {
    let f = Fixture::new();
    let hold = f.intent("hold", "5.00");
    let held = ok(
        &f.book,
        &["reserve", "--intent", &hold, "--evidence", &f.evidence],
    );
    let void = write(
        &f.dir,
        "void.json",
        &format!(
            r#"{{"effective_date":"2026-03-10","idempotency_key":"void","resolves":"{}","disposition":"voids"}}"#,
            text(&held, "vid"),
        ),
    );
    let before = head(&f.book);
    let before_tb = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    let (code, error) = run(&f.book, &["resolve", "--intent", &void], None);
    assert_eq!(code, 7);
    assert_eq!(text(&error, "refusal_id"), "FA-REF-007");
    let planned = ok(&f.book, &["resolve", "--intent", &void, "--dry-run"]);
    assert_eq!(text(&planned, "disposition"), "voids");
    assert_eq!(get(&planned, "legs"), &Json::Arr(Vec::new()));
    assert_eq!(text(&planned, "resolves"), text(&held, "vid"));
    assert_eq!(head(&f.book), before);
    assert_eq!(ok(&f.book, &["tb", "--period", "FY2026-P03"]), before_tb);
    // This launch has the exact same holder, Human profile and operation
    // set as the owner who made the plan. Capability mismatch must not hide
    // a missing independent-confirmation check on the bound entrypoint.
    let authority = LaunchAuthority::new(
        f.book.clone(),
        None,
        "operator",
        LaunchProfile::Preparer,
        &["post"],
    )
    .expect("matching launch authority");
    let commitment: String = authority
        .capability()
        .commitment()
        .expect("capability commitment")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(text(&planned, "capability_commitment"), commitment);
    assert_eq!(
        text(&planned, "principal"),
        format!("{:032x}", authority.principal_vid().0),
    );
    let (code, refused) = commit_bound(&authority, text(&planned, "bytes"));
    assert_eq!(code, 7, "{}", refused.render());
    assert_eq!(text(&refused, "refusal_id"), "FA-REF-007");
    assert_eq!(get(&refused, "book"), &Json::Null);
    assert_eq!(head(&f.book), before);
    assert_eq!(ok(&f.book, &["tb", "--period", "FY2026-P03"]), before_tb);
    let (code, committed) = run(
        &f.book,
        &["commit", "--plan", "-"],
        Some(text(&planned, "bytes").as_bytes()),
    );
    assert_eq!(code, 0, "{}", committed.render());
    assert_eq!(get(&committed, "already_recorded"), &Json::Bool(false));
    let after_tb = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    assert!(before_tb.render().contains("5.00 USD"));
    assert!(
        !after_tb.render().contains("5.00 USD"),
        "{}",
        after_tb.render()
    );
    let committed_head = head(&f.book);
    let (code, refused_retry) = commit_bound(&authority, text(&planned, "bytes"));
    assert_eq!(code, 7, "{}", refused_retry.render());
    assert_eq!(text(&refused_retry, "refusal_id"), "FA-REF-007");
    assert_eq!(get(&refused_retry, "book"), &Json::Null);
    assert_eq!(head(&f.book), committed_head);
}

#[test]
fn inline_period_plan_survives_independent_approval_and_exact_stdin_commit() {
    let f = Fixture::new();
    ok(&f.book, &["period", "close", "FY2026-P03", "--yes"]);
    let before = head(&f.book);
    let planned = ok(&f.book, &["period", "lock", "FY2026-P03", "--dry-run"]);
    assert_eq!(text(&planned, "event"), "period_plan");
    assert_eq!(text(&planned, "scope"), "period-transition-proposal");
    assert_eq!(text(&planned, "from"), "Closed");
    assert_eq!(text(&planned, "to"), "Locked");
    assert_eq!(get(&planned, "certificate"), &Json::Null);
    assert_eq!(head(&f.book), before);
    let encoded = text(&planned, "bytes");
    let bytes: Vec<u8> = encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let decoded =
        fa_journal::TransitionPlan::decode(&bytes).expect("existing canonical period format");
    assert_eq!(decoded.encode().unwrap(), bytes);
    assert_eq!(decoded.period_code, "FY2026-P03");
    let approval = ok(
        &f.book,
        &[
            "approve",
            "--proposal",
            text(&planned, "proposal_digest"),
            "--as",
            "controller",
        ],
    );
    let (code, committed) = run(
        &f.book,
        &[
            "period",
            "lock",
            "FY2026-P03",
            "--plan",
            "-",
            "--approval",
            text(&approval, "approval_vid"),
        ],
        Some(encoded.as_bytes()),
    );
    assert_eq!(code, 0, "{}", committed.render());
    assert_eq!(text(&committed, "event"), "period_transitioned");
    assert_eq!(text(&committed, "to"), "Locked");
    let stored = ok(
        &f.book,
        &["entry", "show", text(&committed, "control_entry")],
    );
    assert_eq!(
        text(&stored, "proposal_digest"),
        text(&planned, "proposal_digest")
    );
}
