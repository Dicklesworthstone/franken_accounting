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
fn large_post_and_replacement_plans_commit_atomically_and_retry_after_reopen() {
    let f = Fixture::new();
    let legs = |amount: &str| {
        (0..40)
        .map(|i| {
            let (side, account) = if i % 2 == 0 {
                ("debit", "1000")
            } else {
                ("credit", "4000")
            };
            format!(
                r#"{{"side":"{side}","account":"{account}","amount":"{amount} USD","memo":"{}"}}"#,
                "supporting detail ".repeat(8),
            )
        })
        .collect::<Vec<_>>()
        .join(",")
    };
    let intent = write(
        &f.dir,
        "large.json",
        &format!(
            r#"{{"effective_date":"2026-03-10","idempotency_key":"large-plan","legs":[{legs}]}}"#,
            legs = legs("1.00"),
        ),
    );
    let output = f.dir.join("large.plan");
    let before = head(&f.book);
    ok(
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
    let bytes = std::fs::read(&output).unwrap();
    assert!(bytes.len() > 16_384, "must cross the old native row limit");
    let plan = fa::PostPlan::decode(&bytes).unwrap();
    assert_eq!(plan.proposal().legs.len(), 40);
    assert_eq!(head(&f.book), before);
    let committed = ok(
        &f.book,
        &["commit", "--plan", &output.display().to_string()],
    );
    assert_eq!(
        head(&f.book),
        before + 1,
        "root, fragments and entry are atomic"
    );
    let retry = ok(
        &f.book,
        &["commit", "--plan", &output.display().to_string()],
    );
    assert_eq!(get(&retry, "already_recorded"), &Json::Bool(true));
    assert_eq!(head(&f.book), before + 1);
    let correction = f.dir.join("large-correction.plan");
    let replacement = write(
        &f.dir,
        "large-replacement.json",
        &format!(
            r#"{{"effective_date":"2026-03-10","idempotency_key":"large-replacement","legs":[{legs}]}}"#,
            legs = legs("2.00"),
        ),
    );
    ok(
        &f.book,
        &[
            "reverse",
            text(&committed, "vid"),
            "--reason",
            "WrongAmount",
            "--replace-with",
            &replacement,
            "--evidence",
            &f.evidence,
            "--dry-run",
            "--plan-out",
            &correction.display().to_string(),
        ],
    );
    let bytes = std::fs::read(&correction).unwrap();
    assert!(bytes.len() > 16_384);
    let correction_head = head(&f.book);
    assert_eq!(
        correction_head,
        before + 1,
        "correction planning cannot publish"
    );
    ok(
        &f.book,
        &["commit", "--plan", &correction.display().to_string()],
    );
    assert_eq!(head(&f.book), correction_head + 1);
    let retry = ok(
        &f.book,
        &["commit", "--plan", &correction.display().to_string()],
    );
    assert_eq!(get(&retry, "already_recorded"), &Json::Bool(true));
    assert_eq!(head(&f.book), correction_head + 1);
    ok(&f.book, &["verify", "projections"]);
}

#[test]
fn binary_replacement_plan_survives_reopen_and_commits_both_reviewed_members() {
    let f = Fixture::new();
    let original = ok(
        &f.book,
        &[
            "post",
            "--intent",
            &f.intent("correction-original", "10.00"),
            "--evidence",
            &f.evidence,
        ],
    );
    let replacement = f.intent("corrected-sale", "12.34");
    let output = f.dir.join("correction.plan");
    let before = head(&f.book);
    let planned = ok(
        &f.book,
        &[
            "reverse",
            text(&original, "vid"),
            "--reason",
            "WrongAmount",
            "--replace-with",
            &replacement,
            "--evidence",
            &f.evidence,
            "--dry-run",
            "--plan-out",
            &output.display().to_string(),
        ],
    );
    assert_eq!(text(&planned, "event"), "replacement_plan");
    assert_eq!(text(&planned, "intent_kind"), "Replace");
    assert_eq!(text(&planned, "scope"), "same-snapshot-replacement");
    assert_eq!(text(&planned, "target"), text(&original, "vid"));
    assert_eq!(integer(&planned, "snapshot_seq"), before);
    assert_eq!(head(&f.book), before);
    let members = get(&planned, "members").as_arr().unwrap();
    assert_eq!(members.len(), 2);
    assert_eq!(text(&members[0], "class"), "Reversal");
    assert_eq!(text(&members[1], "class"), "Replacement");
    let bytes = std::fs::read(&output).unwrap();
    let plan = fa::ReplacementPlan::decode(&bytes).unwrap();
    assert_eq!(plan.reversal().proposal().legs[0].amount.mantissa, 1000);
    assert_eq!(plan.replacement().proposal().legs[0].amount.mantissa, 1234);
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
    assert_eq!(text(&committed, "event"), "replacement_plan_committed");
    assert_eq!(get(&committed, "already_recorded"), &Json::Bool(false));
    for field in ["plan_digest", "certificate_digest"] {
        assert_eq!(text(&planned, field), text(&committed, field));
    }
    for (field, member) in [("reversal", &members[0]), ("replacement", &members[1])] {
        let entry = ok(&f.book, &["entry", "show", text(&committed, field)]);
        assert_eq!(
            text(&entry, "proposal_digest"),
            text(member, "proposal_digest")
        );
        assert_eq!(text(&entry, "entry_digest"), text(member, "entry_digest"));
        assert_eq!(
            integer(&entry, "recorded_at"),
            integer(&committed, "recorded_at")
        );
    }
    let committed_head = head(&f.book);
    assert_eq!(committed_head, before + 1);
    // Retry through a different transport and another process returns the
    // same two immutable identities without resealing either description.
    let (code, retry) = run(
        &f.book,
        &["commit", "--plan", "-"],
        Some(text(&planned, "bytes").as_bytes()),
    );
    assert_eq!(code, 0, "{}", retry.render());
    assert_eq!(get(&retry, "already_recorded"), &Json::Bool(true));
    for field in [
        "reversal",
        "replacement",
        "reversal_digest",
        "replacement_digest",
        "plan_digest",
        "certificate_digest",
    ] {
        assert_eq!(text(&retry, field), text(&committed, field));
    }
    assert_eq!(
        integer(&retry, "recorded_at"),
        integer(&committed, "recorded_at")
    );
    assert_eq!(get(&retry, "reversal_period"), &Json::Null);
    assert_eq!(get(&retry, "replacement_period"), &Json::Null);
    assert_eq!(head(&f.book), committed_head);
}

#[test]
fn replacement_plan_rejects_changed_authority_stale_basis_and_invalid_second_member() {
    let f = Fixture::new();
    let original = ok(
        &f.book,
        &[
            "post",
            "--intent",
            &f.intent("pair-errors-original", "10.00"),
            "--evidence",
            &f.evidence,
        ],
    );
    let corrected = f.intent("pair-errors-corrected", "12.00");
    let planned = ok(
        &f.book,
        &[
            "reverse",
            text(&original, "vid"),
            "--reason",
            "WrongAmount",
            "--replace-with",
            &corrected,
            "--evidence",
            &f.evidence,
            "--dry-run",
        ],
    );
    let before = head(&f.book);
    let encoded = text(&planned, "bytes").as_bytes();
    let (code, error) = run(
        &f.book,
        &["commit", "--plan", "-", "--as", "99"],
        Some(encoded),
    );
    assert_eq!(code, 7, "{}", error.render());
    assert_eq!(head(&f.book), before);
    let unbalanced = write(
        &f.dir,
        "pair-unbalanced.json",
        r#"{"legs":[{"side":"debit","account":"1000","amount":"12.00 USD"},{"side":"credit","account":"4000","amount":"11.99 USD"}]}"#,
    );
    let refused_output = f.dir.join("refused-correction.plan");
    let (code, error) = run(
        &f.book,
        &[
            "reverse",
            text(&original, "vid"),
            "--reason",
            "WrongAmount",
            "--replace-with",
            &unbalanced,
            "--evidence",
            &f.evidence,
            "--dry-run",
            "--plan-out",
            &refused_output.display().to_string(),
        ],
        None,
    );
    assert_eq!(code, 3, "{}", error.render());
    assert_eq!(text(&error, "refusal_id"), "FA-REF-001");
    assert!(!refused_output.exists());
    assert_eq!(head(&f.book), before);
    // A second legitimate transaction makes the accounting basis stale;
    // committing the older pair cannot leave its reversal behind.
    ok(
        &f.book,
        &[
            "post",
            "--intent",
            &f.intent("pair-errors-later", "1.00"),
            "--evidence",
            &f.evidence,
        ],
    );
    let advanced = head(&f.book);
    let (code, error) = run(&f.book, &["commit", "--plan", "-"], Some(encoded));
    assert_eq!(code, 6, "{}", error.render());
    assert_eq!(text(&error, "refusal_id"), "FA-REF-034");
    assert_eq!(head(&f.book), advanced);
    let fresh = ok(
        &f.book,
        &[
            "reverse",
            text(&original, "vid"),
            "--reason",
            "WrongAmount",
            "--replace-with",
            &corrected,
            "--evidence",
            &f.evidence,
            "--dry-run",
        ],
    );
    let (code, committed) = run(
        &f.book,
        &["commit", "--plan", "-"],
        Some(text(&fresh, "bytes").as_bytes()),
    );
    assert_eq!(code, 0, "{}", committed.render());
    assert_eq!(text(&committed, "event"), "replacement_plan_committed");
    assert_eq!(head(&f.book), advanced + 1);
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

/// fa-we7: a stale correction (Reversal and Replacement) or atomic batch
/// plan is refused the same way, with its fresh plan, which commits.
#[test]
fn stale_correction_and_batch_plans_carry_their_fresh_plans() {
    let f = Fixture::new();
    let mut documents = 0;
    let mut publish = || {
        documents += 1;
        let source = write(
            &f.dir,
            &format!("between-{documents}.txt"),
            &format!("Independent source document {documents}."),
        );
        ok(
            &f.book,
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
        head(&f.book)
    };
    let stale_then_fresh = |stale: &str, advanced: i128, expected: &[&str]| {
        let (code, error) = run(&f.book, &["commit", "--plan", "-"], Some(stale.as_bytes()));
        assert_eq!(code, 6, "{}", error.render());
        assert_eq!(text(&error, "refusal_id"), "FA-REF-034");
        assert_eq!(
            head(&f.book),
            advanced,
            "nothing is committed for the caller"
        );
        let detail = get(&error, "detail");
        assert_eq!(names(get(detail, "changed")), expected);
        let fresh = get(detail, "fresh_plan");
        assert_eq!(integer(fresh, "snapshot_seq"), advanced);
        assert_eq!(get(fresh, "period"), &Json::Null);
        let (code, committed) = run(
            &f.book,
            &["commit", "--plan", "-"],
            Some(text(fresh, "bytes").as_bytes()),
        );
        assert_eq!(code, 0, "{}", committed.render());
        assert_eq!(text(&committed, "plan_digest"), text(fresh, "plan_digest"));
        committed
    };

    let original = ok(
        &f.book,
        &[
            "post",
            "--intent",
            &f.intent("stale-original", "10.00"),
            "--evidence",
            &f.evidence,
        ],
    );
    let corrected = f.intent("stale-corrected", "12.00");
    let planned = ok(
        &f.book,
        &[
            "reverse",
            text(&original, "vid"),
            "--reason",
            "WrongAmount",
            "--replace-with",
            &corrected,
            "--evidence",
            &f.evidence,
            "--dry-run",
        ],
    );
    assert_eq!(text(&planned, "event"), "replacement_plan");
    let stale = text(&planned, "bytes").to_string();
    let advanced = publish();
    let committed = stale_then_fresh(&stale, advanced, &["basis"]);
    assert_eq!(text(&committed, "event"), "replacement_plan_committed");

    let batch = write(
        &f.dir,
        "stale-batch.json",
        &format!(
            r#"{{"idempotency_key":"stale-batch","intents":[{{"effective_date":"2026-03-12","idempotency_key":"stale-batch-1","evidence":["{ev}"],"legs":[{{"side":"debit","account":"1000","amount":"1.00 USD"}},{{"side":"credit","account":"4000","amount":"1.00 USD"}}]}},{{"effective_date":"2026-03-13","idempotency_key":"stale-batch-2","evidence":["{ev}"],"legs":[{{"side":"debit","account":"1000","amount":"2.00 USD"}},{{"side":"credit","account":"4000","amount":"2.00 USD"}}]}}]}}"#,
            ev = f.evidence
        ),
    );
    let planned = ok(&f.book, &["post", "--intent", &batch, "--dry-run"]);
    assert_eq!(text(&planned, "event"), "batch_plan");
    let stale = text(&planned, "bytes").to_string();
    let advanced = publish();
    let committed = stale_then_fresh(&stale, advanced, &["basis", "effects"]);
    assert_eq!(text(&committed, "event"), "batch_plan_committed");
}

fn names(value: &Json) -> Vec<&str> {
    match value {
        Json::Arr(items) => items.iter().map(|i| i.as_str().expect("name")).collect(),
        other => panic!("changed must be a list: {other:?}"),
    }
}

/// fa-we7, plan §10.4: a stale plan is refused with PlanInvalidated naming
/// what changed and carrying a fresh plan of the same intent at the current
/// head, never committed for the caller; the fresh plan commits as
/// reviewed. A different acting capability is named the same way. An
/// intent that can no longer be planned carries that refusal instead.
#[test]
fn a_stale_plan_refusal_carries_a_fresh_plan_and_names_what_changed() {
    let f = Fixture::new();
    let intent = f.intent("fresh", "4.50");
    let stale = text(&f.plan(&intent), "bytes").to_string();
    let later = write(&f.dir, "later.txt", "Another independent source document.");
    let add = [
        "document",
        "add",
        later.as_str(),
        "--kind",
        "Receipt",
        "--grade",
        "HumanUpload",
    ];
    ok(&f.book, &add);
    let advanced = head(&f.book);
    let (code, error) = run(&f.book, &["commit", "--plan", "-"], Some(stale.as_bytes()));
    assert_eq!(code, 6, "{}", error.render());
    assert_eq!(text(&error, "refusal_id"), "FA-REF-034");
    assert_eq!(
        head(&f.book),
        advanced,
        "nothing is committed for the caller"
    );
    let detail = get(&error, "detail");
    let changed = names(get(detail, "changed"));
    assert!(changed.contains(&"basis"), "{changed:?}");
    for same in [
        "capability",
        "entry",
        "period",
        "security_policy_epoch",
        "effects",
    ] {
        assert!(!changed.contains(&same), "{same}: {changed:?}");
    }
    assert_eq!(get(detail, "replan_refusal"), &Json::Null);
    let fresh = get(detail, "fresh_plan");
    assert_eq!(integer(fresh, "snapshot_seq"), advanced);
    assert_eq!(text(fresh, "period"), "FY2026-P03");
    assert!(text(&error, "fix").contains("fa commit --plan -"));
    let (code, committed) = run(
        &f.book,
        &["commit", "--plan", "-"],
        Some(text(fresh, "bytes").as_bytes()),
    );
    assert_eq!(code, 0, "{}", committed.render());
    assert_eq!(text(&committed, "plan_digest"), text(fresh, "plan_digest"));
    assert_eq!(get(&committed, "already_recorded"), &Json::Bool(false));

    // Another acting capability: named, and the fresh plan binds the caller's.
    let other = text(&f.plan(&f.intent("other", "1.25")), "bytes").to_string();
    let wider = ["commit", "--plan", "-", "--grant", "read"];
    let (code, error) = run(&f.book, &wider, Some(other.as_bytes()));
    assert_eq!(code, 6, "{}", error.render());
    let detail = get(&error, "detail");
    let changed = names(get(detail, "changed"));
    assert!(changed.contains(&"capability"), "{changed:?}");
    assert!(!changed.contains(&"basis"), "{changed:?}");
    let fresh = text(get(detail, "fresh_plan"), "bytes").to_string();
    let (code, committed) = run(&f.book, &wider, Some(fresh.as_bytes()));
    assert_eq!(code, 0, "{}", committed.render());

    // A launch-bound session (MCP) gets the same fresh plan, and the fix
    // names its commit tool; the fresh plan commits through it.
    let authority = LaunchAuthority::new(
        f.book.clone(),
        None,
        "operator",
        LaunchProfile::Preparer,
        &["post"],
    )
    .expect("launch authority");
    let bound = text(&f.plan(&f.intent("bound", "3.00")), "bytes").to_string();
    let moved = write(
        &f.dir,
        "moved.txt",
        "A source document between plan and commit.",
    );
    ok(
        &f.book,
        &[
            "document",
            "add",
            &moved,
            "--kind",
            "Receipt",
            "--grade",
            "HumanUpload",
        ],
    );
    let (code, error) = commit_bound(&authority, &bound);
    assert_eq!(code, 6, "{}", error.render());
    assert!(
        text(&error, "fix").contains("fa_post_commit_plan"),
        "{}",
        error.render()
    );
    let detail = get(&error, "detail");
    assert_eq!(names(get(detail, "changed")), vec!["basis"]);
    let (code, committed) = commit_bound(&authority, text(get(detail, "fresh_plan"), "bytes"));
    assert_eq!(code, 0, "{}", committed.render());

    // Recorded meanwhile from a later plan: the stale one cannot be planned
    // again, and its refusal says so.
    let twice = f.intent("twice", "2.00");
    let first = text(&f.plan(&twice), "bytes").to_string();
    let again = write(&f.dir, "again.txt", "A third independent source document.");
    ok(
        &f.book,
        &[
            "document",
            "add",
            &again,
            "--kind",
            "Receipt",
            "--grade",
            "HumanUpload",
        ],
    );
    let second = text(&f.plan(&twice), "bytes").to_string();
    let (code, committed) = run(&f.book, &["commit", "--plan", "-"], Some(second.as_bytes()));
    assert_eq!(code, 0, "{}", committed.render());
    let recorded = head(&f.book);
    let (code, error) = run(&f.book, &["commit", "--plan", "-"], Some(first.as_bytes()));
    assert_eq!(code, 6, "{}", error.render());
    assert_eq!(head(&f.book), recorded);
    let detail = get(&error, "detail");
    assert_eq!(get(detail, "fresh_plan"), &Json::Null);
    assert_eq!(get(detail, "changed"), &Json::Null);
    let replan = get(detail, "replan_refusal");
    assert_eq!(text(replan, "refusal_id"), "FA-REF-034");
    assert!(
        text(replan, "message").contains("already recorded"),
        "{replan:?}"
    );
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

/// fa-87r: the period dates its control, never the caller. `--date` is not
/// a flag of `fa period` (exit 2 before the book is touched), and the
/// journaled controls carry the period law's dates: March opens on its
/// first day and soft-closes and closes on its last.
#[test]
fn period_controls_are_dated_by_their_period_never_by_the_caller() {
    let f = Fixture::new();
    let before = head(&f.book);
    for transition in ["soft-close", "close"] {
        let (code, refused) = run(
            &f.book,
            &[
                "period",
                transition,
                "FY2026-P03",
                "--date",
                "2026-04-15",
                "--yes",
            ],
            None,
        );
        assert_eq!(code, 2, "{}", refused.render());
        assert_eq!(text(&refused, "class"), "usage", "{}", refused.render());
        assert!(
            text(&refused, "message").contains("--date"),
            "{}",
            refused.render()
        );
        assert_eq!(head(&f.book), before, "{transition}: nothing written");
    }
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
    let explained = ok(&f.book, &["explain", "period", "FY2026-P03"]);
    let dated: Vec<(&str, &str)> = get(&explained, "transitions")
        .as_arr()
        .expect("transitions")
        .iter()
        .map(|row| (text(row, "to"), text(row, "effective_date")))
        .collect();
    assert_eq!(
        dated,
        vec![
            ("Open", "2026-03-01"),
            ("SoftClosed", "2026-03-31"),
            ("Closed", "2026-03-31"),
        ],
        "{}",
        explained.render()
    );
}

/// fa-cvg: every transition journals a registered reason. A close without
/// `--reason` and an unknown reason name are usage errors (exit 2) naming
/// the registered reasons; an unregistered code reaches the kernel and is
/// refused FA-REF-041 (exit 3); `--reason` with `--plan` is refused because
/// the plan carries the reason its approvals bind. Nothing is written by
/// any refusal, and `explain period` names each recorded reason.
#[test]
fn period_transitions_journal_a_registered_reason() {
    let f = Fixture::new();
    let before = head(&f.book);
    let (code, missing) = run(&f.book, &["period", "close", "FY2026-P03", "--yes"], None);
    assert_eq!(code, 2, "{}", missing.render());
    assert!(
        text(&missing, "fix").contains("Scheduled"),
        "{}",
        missing.render()
    );
    let (code, unknown) = run(
        &f.book,
        &[
            "period",
            "close",
            "FY2026-P03",
            "--reason",
            "Vibes",
            "--yes",
        ],
        None,
    );
    assert_eq!(code, 2, "{}", unknown.render());
    assert!(
        text(&unknown, "message").contains("Vibes"),
        "{}",
        unknown.render()
    );
    for unregistered in ["0", "4", "99"] {
        let (code, refused) = run(
            &f.book,
            &[
                "period",
                "soft-close",
                "FY2026-P03",
                "--reason",
                unregistered,
            ],
            None,
        );
        assert_eq!(code, 3, "{unregistered}: {}", refused.render());
        assert_eq!(text(&refused, "refusal_id"), "FA-REF-041");
    }
    let (code, both) = run(
        &f.book,
        &[
            "period",
            "lock",
            "FY2026-P03",
            "--plan",
            "unused.plan",
            "--reason",
            "Scheduled",
        ],
        None,
    );
    assert_eq!(code, 2, "{}", both.render());
    assert_eq!(head(&f.book), before, "no refusal wrote anything");

    ok(&f.book, &["period", "soft-close", "FY2026-P03"]);
    // A SoftClosed reopen needs an independent approval of its plan, and the
    // plan carries the reason: the commit gives none.
    let planned = ok(
        &f.book,
        &[
            "period",
            "reopen",
            "FY2026-P03",
            "--to",
            "open",
            "--reason",
            "ErrorCorrection",
            "--dry-run",
        ],
    );
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
    let (code, reopened) = run(
        &f.book,
        &[
            "period",
            "reopen",
            "FY2026-P03",
            "--to",
            "open",
            "--plan",
            "-",
            "--approval",
            text(&approval, "approval_vid"),
        ],
        Some(text(&planned, "bytes").as_bytes()),
    );
    assert_eq!(code, 0, "{}", reopened.render());
    // The second soft close of the same Open state needs its own key.
    ok(
        &f.book,
        &[
            "period",
            "soft-close",
            "FY2026-P03",
            "--reason",
            "Reclose",
            "--key",
            "soft-close-after-reopen",
        ],
    );
    let explained = ok(&f.book, &["explain", "period", "FY2026-P03"]);
    let reasons: Vec<(&str, &str)> = get(&explained, "transitions")
        .as_arr()
        .expect("transitions")
        .iter()
        .map(|row| (text(row, "to"), text(row, "reason")))
        .collect();
    assert_eq!(
        reasons,
        vec![
            ("Open", "Scheduled"),
            ("SoftClosed", "Scheduled"),
            ("Open", "ErrorCorrection"),
            ("SoftClosed", "Reclose"),
        ],
        "{}",
        explained.render()
    );
}

/// fa-cvg parts 1 and 2 at the CLI: a zero leg moves nothing and is never
/// a journaled fact (FA-REF-100, a structure defect, exit 2), and a manual
/// reversal cannot cite ScheduledAccrualReversal, the kernel's own scheduled
/// reason (FA-REF-054, exit 3). Neither writes anything.
#[test]
fn zero_legs_and_a_manual_scheduled_reversal_reason_are_refused() {
    let f = Fixture::new();
    let before = head(&f.book);
    let (code, zero) = run(
        &f.book,
        &[
            "post",
            "--intent",
            &f.intent("zero-legs", "0.00"),
            "--evidence",
            &f.evidence,
        ],
        None,
    );
    assert_eq!(code, 2, "{}", zero.render());
    assert_eq!(text(&zero, "refusal_id"), "FA-REF-100", "{}", zero.render());
    assert!(
        text(&zero, "message").contains("positive"),
        "{}",
        zero.render()
    );
    assert_eq!(head(&f.book), before, "a zero leg writes nothing");

    let original = ok(
        &f.book,
        &[
            "post",
            "--intent",
            &f.intent("scheduled-reason-target", "10.00"),
            "--evidence",
            &f.evidence,
        ],
    );
    let posted = head(&f.book);
    let (code, refused) = run(
        &f.book,
        &[
            "reverse",
            text(&original, "vid"),
            "--reason",
            "ScheduledAccrualReversal",
        ],
        None,
    );
    assert_eq!(code, 3, "{}", refused.render());
    assert_eq!(
        text(&refused, "refusal_id"),
        "FA-REF-054",
        "{}",
        refused.render()
    );
    assert_eq!(head(&f.book), posted, "the refused reversal writes nothing");
}

#[test]
fn inline_period_plan_survives_independent_approval_and_exact_stdin_commit() {
    let f = Fixture::new();
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
    let before = head(&f.book);
    let planned = ok(
        &f.book,
        &[
            "period",
            "lock",
            "FY2026-P03",
            "--reason",
            "Scheduled",
            "--dry-run",
        ],
    );
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

#[test]
fn certification_does_not_invalidate_plans_while_accounting_writes_do_and_read_op_is_required() {
    let f = Fixture::new();
    let intent_a = f.intent("plan-across-certify", "15.00");
    let before = head(&f.book);
    let planned_a = f.plan(&intent_a);
    assert_eq!(integer(&planned_a, "snapshot_seq"), before);

    // Certifying a trial balance retains a ReportCertificate and advances raw
    // known_at, but leaves the accounting frontier unchanged (fa-1nx).
    let (code, certified_tb) = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(&f.book)
        .args(["tb", "--period", "FY2026-P03", "--certify", "--json"])
        .env_remove("FA_BOOK")
        .output()
        .map(|o| {
            (
                o.status.code().unwrap_or(-1),
                String::from_utf8(o.stdout).unwrap(),
            )
        })
        .unwrap();
    assert_eq!(code, 0, "{certified_tb}");
    assert_eq!(certified_tb.lines().count(), 2, "{certified_tb}");
    let after_cert = head(&f.book);
    assert_eq!(after_cert, before + 1);

    // Retaining a certificate without `read` is refused (FA-REF-011, exit 7).
    let no_read_authority = LaunchAuthority::new(
        f.book.clone(),
        None,
        "operator",
        LaunchProfile::Preparer,
        &["post"],
    )
    .expect("post-only launch authority");
    let certify_argv = ["tb", "--period", "FY2026-P03", "--certify", "--json"].map(str::to_string);
    let (code, certify_out) = fa_with_authority(
        &certify_argv,
        Files {
            cwd: None,
            stdin: Stdin::Process,
        },
        &no_read_authority,
        true,
    );
    assert_eq!(code, 7, "{certify_out:?}");
    let refused_cert = json::parse(certify_out.stdout.trim()).expect("refusal json");
    assert_eq!(text(&refused_cert, "refusal_id"), "FA-REF-011");
    assert_eq!(head(&f.book), after_cert);

    // The outstanding plan still commits and its exact retry succeeds.
    let (code, committed) = run(
        &f.book,
        &["commit", "--plan", "-"],
        Some(text(&planned_a, "bytes").as_bytes()),
    );
    assert_eq!(code, 0, "{}", committed.render());
    assert_eq!(get(&committed, "already_recorded"), &Json::Bool(false));
    assert_eq!(integer(&committed, "recorded_at"), after_cert + 1);

    let (code, retried) = run(
        &f.book,
        &["commit", "--plan", "-"],
        Some(text(&planned_a, "bytes").as_bytes()),
    );
    assert_eq!(code, 0, "{}", retried.render());
    assert_eq!(get(&retried, "already_recorded"), &Json::Bool(true));
    assert_eq!(integer(&retried, "recorded_at"), after_cert + 1);

    // An actual accounting posting between plan and commit still invalidates (FA-REF-034).
    let intent_b = f.intent("plan-stale-after-post", "20.00");
    let planned_b = f.plan(&intent_b);
    let intent_other = f.intent("intervening-post", "3.00");
    ok(
        &f.book,
        &["post", "--intent", &intent_other, "--evidence", &f.evidence],
    );
    let (code, refused) = run(
        &f.book,
        &["commit", "--plan", "-"],
        Some(text(&planned_b, "bytes").as_bytes()),
    );
    assert_eq!(code, 6, "{}", refused.render());
    assert_eq!(text(&refused, "refusal_id"), "FA-REF-034");
}

#[test]
fn period_plan_out_never_overwrites_existing_files_or_book_keys() {
    let f = Fixture::new();
    let before = head(&f.book);
    let book_keys = f.book.join("book.keys");
    let keys_before = std::fs::read(&book_keys).expect("read book.keys before");
    let keys_digest_before = fa_model::domain_digest(b"fa:test:file", &[&keys_before]);

    let existing_path = write(&f.dir, "existing-period.plan", "DO NOT TRUNCATE ME");
    let existing_before = std::fs::read(&existing_path).expect("read existing file");
    let existing_digest_before = fa_model::domain_digest(b"fa:test:file", &[&existing_before]);

    for target in [
        book_keys.display().to_string(),
        existing_path.clone(),
        "-".to_string(),
    ] {
        let (code, error) = run(
            &f.book,
            &[
                "period",
                "close",
                "FY2026-P03",
                "--reason",
                "Scheduled",
                "--plan-out",
                &target,
            ],
            None,
        );
        assert_eq!(code, 2, "target={target}: {}", error.render());
        assert_eq!(get(&error, "refusal_id"), &Json::Null);
        assert_eq!(text(&error, "class"), "usage");
        if target != "-" {
            assert!(
                text(&error, "message").contains(&target),
                "message must name {target}: {}",
                error.render()
            );
        }
        assert_eq!(head(&f.book), before);
    }

    let keys_after = std::fs::read(&book_keys).expect("read book.keys after");
    assert_eq!(
        fa_model::domain_digest(b"fa:test:file", &[&keys_after]),
        keys_digest_before,
        "book.keys must remain byte-identical"
    );
    let existing_after = std::fs::read(&existing_path).expect("read existing after");
    assert_eq!(
        fa_model::domain_digest(b"fa:test:file", &[&existing_after]),
        existing_digest_before,
        "existing artifact must remain byte-identical"
    );

    // Writing to a genuinely new path succeeds with mode 0600, and a second call refuses.
    let fresh = f.dir.join("fresh-period.plan");
    let fresh_str = fresh.display().to_string();
    let planned = ok(
        &f.book,
        &[
            "period",
            "close",
            "FY2026-P03",
            "--reason",
            "Scheduled",
            "--plan-out",
            &fresh_str,
        ],
    );
    assert_eq!(text(&planned, "event"), "period_planned");
    let fresh_bytes = std::fs::read(&fresh).expect("read fresh period plan");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let (code, error) = run(
        &f.book,
        &[
            "period",
            "close",
            "FY2026-P03",
            "--reason",
            "Scheduled",
            "--plan-out",
            &fresh_str,
        ],
        None,
    );
    assert_eq!(code, 2, "{}", error.render());
    assert_eq!(
        std::fs::read(&fresh).expect("fresh plan preserved"),
        fresh_bytes
    );
}

/// The kinds of a plan's dry-run warnings, in order.
fn warning_kinds(plan: &Json) -> Vec<&str> {
    get(plan, "warnings")
        .as_arr()
        .expect("warnings")
        .iter()
        .map(|warning| text(warning, "kind"))
        .collect()
}

/// The envelope's warnings beside the data.
fn envelope_warnings(line: &Json) -> Vec<&str> {
    line.get("warnings")
        .and_then(Json::as_arr)
        .expect("envelope warnings")
        .iter()
        .map(|warning| warning.as_str().expect("warning text"))
        .collect()
}

/// Dry-run warnings (plan §5.1, fa-d5un) name what journal-entry testing
/// would flag about the planned entry, read at the plan's snapshot. They are
/// data: they never refuse, and a warned plan commits.
#[test]
fn dry_run_warnings_name_what_journal_entry_testing_would_flag() {
    let f = Fixture::new();
    let legs = |amount: &str| {
        format!(
            r#"[{{"side":"debit","account":"1000","amount":"{amount} USD"}},{{"side":"credit","account":"4000","amount":"{amount} USD"}}]"#
        )
    };
    // A plain amount draws no warning, and every check ran.
    let plain = f.plan(&f.intent("plain", "125.37"));
    assert!(warning_kinds(&plain).is_empty(), "{}", plain.render());
    assert_eq!(get(&plain, "unchecked"), &Json::Arr(Vec::new()));
    assert!(envelope_warnings(&plain).is_empty(), "{}", plain.render());

    // RoundAmount: both legs are whole multiples of 1,000.00 USD
    // (jet.round_amounts' registered round_power 3).
    let round = f.plan(&f.intent("round", "2000.00"));
    assert_eq!(warning_kinds(&round), ["RoundAmount"]);
    let warning = &get(&round, "warnings").as_arr().unwrap()[0];
    assert_eq!(
        get(warning, "legs"),
        &Json::Arr(vec![Json::Int(0), Json::Int(1)])
    );
    assert!(text(warning, "message").contains("jet.round_amounts"));
    assert!(
        envelope_warnings(&round)
            .iter()
            .any(|w| w.starts_with("RoundAmount: ")),
        "{}",
        round.render()
    );
    // A warning never refuses: the warned plan commits.
    let (code, committed) = run(
        &f.book,
        &["commit", "--plan", "-"],
        Some(text(&round, "bytes").as_bytes()),
    );
    assert_eq!(code, 0, "{}", committed.render());
    // A derived entry is not judged: reversing the round entry draws none.
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
    assert!(warning_kinds(&reversal).is_empty(), "{}", reversal.render());

    // PossibleDuplicate: the same legs, recorded under another key.
    let first = ok(
        &f.book,
        &[
            "post",
            "--intent",
            &f.intent("first", "125.37"),
            "--evidence",
            &f.evidence,
        ],
    );
    let first_vid = text(&first, "vid").to_string();
    let again = f.plan(&f.intent("again", "125.37"));
    assert_eq!(warning_kinds(&again), ["PossibleDuplicate"]);
    let warning = &get(&again, "warnings").as_arr().unwrap()[0];
    assert_eq!(
        get(warning, "entries"),
        &Json::Arr(vec![Json::Str(first_vid.clone())])
    );
    assert!(text(warning, "message").contains(&first_vid));
    // A session whose token does not read the book is never shown the
    // earlier entry, and the plan says the check did not run. (The embedded
    // posture's operator reads as the owner.)
    let token = f.dir.join("post-only.token").display().to_string();
    ok(
        &f.book,
        &[
            "capability",
            "issue",
            "--holder",
            "post-only-planner",
            "--profile",
            "human",
            "--op",
            "post",
            "--grant",
            "issue_capability",
            "--grant",
            "post",
            "--out",
            &token,
        ],
    );
    // A token-bound session reads no host path outside a launch files root,
    // so the intent travels on stdin.
    let narrow_intent = std::fs::read(f.intent("narrow", "125.37")).expect("narrow intent");
    let (code, narrow) = run(
        &f.book,
        &[
            "--token",
            &token,
            "post",
            "--intent",
            "-",
            "--evidence",
            &f.evidence,
            "--dry-run",
        ],
        Some(&narrow_intent),
    );
    assert_eq!(code, 0, "{}", narrow.render());
    assert!(warning_kinds(&narrow).is_empty(), "{}", narrow.render());
    let unchecked = get(&narrow, "unchecked").as_arr().unwrap();
    assert_eq!(unchecked.len(), 1, "{}", narrow.render());
    assert_eq!(text(&unchecked[0], "kind"), "PossibleDuplicate");
    assert!(
        envelope_warnings(&narrow)
            .iter()
            .any(|w| w.starts_with("PossibleDuplicate not checked: ")),
        "{}",
        narrow.render()
    );
    // Planted: another amount is no duplicate.
    assert!(warning_kinds(&f.plan(&f.intent("other", "125.38"))).is_empty());
    // The registered 30-day window holds across a period boundary: 30 days
    // after the first is a duplicate, 31 days is not.
    ok(&f.book, &["period", "open", "FY2026-P04"]);
    let dated = |key: &str, date: &str| {
        write(
            &f.dir,
            &format!("{key}.json"),
            &format!(
                r#"{{"effective_date":"{date}","idempotency_key":"{key}","legs":{}}}"#,
                legs("125.37")
            ),
        )
    };
    assert_eq!(
        warning_kinds(&f.plan(&dated("edge", "2026-04-09"))),
        ["PossibleDuplicate"]
    );
    assert!(warning_kinds(&f.plan(&dated("beyond", "2026-04-10"))).is_empty());
    // A reversed entry is no longer a duplicate.
    let reversal = ok(&f.book, &["reverse", &first_vid, "--reason", "Duplicate"]);
    assert!(warning_kinds(&f.plan(&f.intent("again", "125.37"))).is_empty());
    // Reversing that reversal reinstates the first entry, and the warning.
    ok(
        &f.book,
        &[
            "reverse",
            text(&reversal, "vid"),
            "--reason",
            "DataEntryError",
        ],
    );
    let reinstated = f.plan(&f.intent("again", "125.37"));
    assert_eq!(warning_kinds(&reinstated), ["PossibleDuplicate"]);
    assert_eq!(
        get(
            &get(&reinstated, "warnings").as_arr().unwrap()[0],
            "entries"
        ),
        &Json::Arr(vec![Json::Str(first_vid.clone())])
    );

    // CutoffDrift: the document date lies outside the entry's period.
    let documented = |key: &str, date: &str| {
        write(
            &f.dir,
            &format!("{key}.json"),
            &format!(
                r#"{{"effective_date":"2026-03-12","document_date":"{date}","idempotency_key":"{key}","legs":{}}}"#,
                legs("77.10")
            ),
        )
    };
    let drift = f.plan(&documented("drift", "2026-02-27"));
    assert_eq!(warning_kinds(&drift), ["CutoffDrift"]);
    let message = text(&get(&drift, "warnings").as_arr().unwrap()[0], "message");
    assert!(
        message.contains("2026-02-27") && message.contains("FY2026-P03"),
        "{message}"
    );
    assert!(warning_kinds(&f.plan(&documented("in-period", "2026-03-01"))).is_empty());
    // The entry records its document date, and fa entry show reads it back.
    let (code, recorded) = run(
        &f.book,
        &["commit", "--plan", "-"],
        Some(text(&drift, "bytes").as_bytes()),
    );
    assert_eq!(code, 0, "{}", recorded.render());
    let shown = ok(&f.book, &["entry", "show", text(&recorded, "vid")]);
    assert_eq!(text(&shown, "document_date"), "2026-02-27");
    let undated = ok(&f.book, &["entry", "show", &first_vid]);
    assert_eq!(get(&undated, "document_date"), &Json::Null);
    // A document date is a YYYY-MM-DD string: anything else is a usage error
    // before any plan.
    let malformed = write(
        &f.dir,
        "malformed.json",
        &format!(
            r#"{{"effective_date":"2026-03-12","document_date":20260227,"idempotency_key":"malformed","legs":{}}}"#,
            legs("77.10")
        ),
    );
    let (code, error) = run(
        &f.book,
        &[
            "post",
            "--intent",
            &malformed,
            "--evidence",
            &f.evidence,
            "--dry-run",
        ],
        None,
    );
    assert_eq!(code, 2, "{}", error.render());

    // SoftClosedPeriod: an Adjusting entry after the period's soft close.
    ok(&f.book, &["period", "soft-close", "FY2026-P03"]);
    let adjusting = write(
        &f.dir,
        "adjusting.json",
        &format!(
            r#"{{"class":"Adjusting","effective_date":"2026-03-20","idempotency_key":"late","legs":{}}}"#,
            legs("33.33")
        ),
    );
    assert_eq!(warning_kinds(&f.plan(&adjusting)), ["SoftClosedPeriod"]);
}

fn scan_truncating_writes(source: &str) -> Vec<(usize, String)> {
    let non_test = source.split("#[cfg(test)]").next().unwrap_or(source);
    let mut hits = Vec::new();
    for (idx, line) in non_test.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        if trimmed.contains("fs::write(")
            || trimmed.contains("File::create(")
            || trimmed.contains(".truncate(true)")
        {
            hits.push((idx + 1, trimmed.to_string()));
        }
    }
    hits
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).expect("read src dir");
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs")
            && path.file_name().and_then(|s| s.to_str()) != Some("tests.rs")
        {
            out.push(path);
        }
    }
}

#[test]
fn no_truncating_output_writes_in_surface_or_facade_crates() {
    // Prove the scanner catches the historical bug from fa-n8wm.
    let planted = "let target = ctx.files.resolve(path);\nstd::fs::write(&target, bytes).map_err(|e| BookError::Io(target.clone(), e))?;";
    assert_eq!(
        scan_truncating_writes(planted).len(),
        1,
        "tripwire must detect std::fs::write"
    );

    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root");
    let mut files = Vec::new();
    for rel in [
        "crates/fa-cli/src",
        "crates/fad/src",
        "crates/fa-mcp/src",
        "crates/fa/src",
    ] {
        collect_rs_files(&root.join(rel), &mut files);
    }
    files.sort();
    assert!(!files.is_empty());
    let mut violations = Vec::new();
    for file in files {
        let content = std::fs::read_to_string(&file).expect("read source file");
        for (line, text) in scan_truncating_writes(&content) {
            violations.push(format!("{}:{line}: {text}", file.display()));
        }
    }
    assert!(
        violations.is_empty(),
        "truncating file writes found in surface/facade crates:\n{}",
        violations.join("\n")
    );
}
