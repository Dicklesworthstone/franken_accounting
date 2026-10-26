//! Sealed approval reviews of the actual capped movement, across real processes.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};

fn run(book: &Path, args: &[&str]) -> (i32, Json) {
    let result = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .output()
        .expect("run real fa process");
    let stdout = String::from_utf8(result.stdout).expect("UTF-8 robot output");
    let stderr = String::from_utf8_lossy(&result.stderr);
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "args={args:?}\n{stdout}\n{stderr}");
    fa_cli::verbs::registry()
        .unwrap()
        .check_line(lines[0])
        .unwrap_or_else(|error| panic!("args={args:?}: {error}\n{stdout}\n{stderr}"));
    let line = json::parse(lines[0]).unwrap();
    let code = result.status.code().unwrap_or(-1);
    assert_eq!(text(&line, "event") == "error", code != 0, "{stdout}");
    (code, line)
}

fn ok(book: &Path, args: &[&str]) -> Json {
    let (code, line) = run(book, args);
    assert_eq!(code, 0, "args={args:?}: {}", line.render());
    line
}

fn get<'a>(value: &'a Json, key: &str) -> &'a Json {
    value
        .get("data")
        .and_then(|data| data.get(key))
        .or_else(|| value.get(key))
        .unwrap_or_else(|| panic!("missing {key}: {}", value.render()))
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    get(value, key).as_str().expect(key)
}

fn write(dir: &Path, name: &str, text: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
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
            let next = NEXT.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir()
                .join(format!("fa-balancing-review-{}-{next}", std::process::id()));
            match std::fs::create_dir(&dir) {
                Ok(()) => break dir,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create retained fixture: {error}"),
            }
        };
        let book = dir.join("book");
        ok(&book, &["book", "create", "--name", "Capped Review Co"]);
        let chart = write(
            &dir,
            "chart.json",
            r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD","upper_bound":"100.00"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
        );
        ok(&book, &["chart", "import", &chart]);
        ok(&book, &["period", "create", "--fiscal-year", "2026"]);
        ok(&book, &["period", "open", "FY2026-P03"]);
        let source = write(&dir, "source.txt", "Synthetic capped posting evidence.");
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
        let fixture = Self {
            dir,
            book,
            evidence: text(&document, "oid").to_string(),
        };
        fixture.post("seed", "Original", "80.00");
        fixture
    }

    fn head(&self) -> i128 {
        let info = ok(&self.book, &["book", "info"]);
        match get(get(&info, "coordinate"), "known_at") {
            Json::Int(seq) => *seq,
            other => panic!("invalid head: {other:?}"),
        }
    }

    fn intent(&self, key: &str, class: &str, amount: &str) -> String {
        write(
            &self.dir,
            &format!("{key}.json"),
            &format!(
                r#"{{"class":"{class}","effective_date":"2026-03-10","description":"Keep this randomized description seal","idempotency_key":"{key}","legs":[{{"side":"debit","account":"1000","amount":"{amount} USD"}},{{"side":"credit","account":"4000","amount":"{amount} USD"}}]}}"#
            ),
        )
    }

    fn post(&self, key: &str, class: &str, amount: &str) -> Json {
        ok(
            &self.book,
            &[
                "post",
                "--intent",
                &self.intent(key, class, amount),
                "--evidence",
                &self.evidence,
            ],
        )
    }

    fn review(&self, key: &str, class: &str, amount: &str) -> (String, Json) {
        let path = self.dir.join(format!("{key}.review")).display().to_string();
        let before = self.head();
        let reviewed = ok(
            &self.book,
            &[
                "post",
                "--intent",
                &self.intent(key, class, amount),
                "--evidence",
                &self.evidence,
                "--balancing",
                "0",
                "--review-out",
                &path,
            ],
        );
        assert_eq!(self.head(), before, "review must publish nothing");
        assert_eq!(text(&reviewed, "event"), "post_reviewed");
        (path, reviewed)
    }

    fn approve(&self, digest: &str, principal: &str) -> String {
        text(
            &ok(
                &self.book,
                &["approve", "--proposal", digest, "--as", principal],
            ),
            "approval_vid",
        )
        .to_string()
    }
}

#[test]
fn capped_adjustment_review_preserves_the_request_and_approves_actual_movement() {
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
    let (path, reviewed) = f.review("approved-capped", "Adjusting", "50.00");
    assert_eq!(text(&reviewed, "requested"), "50.00 USD");
    assert_eq!(text(&reviewed, "moved"), "20.00 USD");
    let retained = fa::PostIntent::decode(&std::fs::read(&path).unwrap()).unwrap();
    assert!(retained.approvals().is_empty());
    assert!(
        retained
            .proposal()
            .legs
            .iter()
            .all(|leg| leg.amount.mantissa == 2000)
    );
    assert_eq!(
        fa_journal::limit::balancing_request(retained.proposal()).unwrap(),
        Some((0, 5000))
    );
    let digest = text(&reviewed, "review_digest");
    let before = f.head();
    let (code, missing) = run(
        &f.book,
        &[
            "post",
            "--review",
            &path,
            "--digest",
            digest,
            "--grant",
            "post_closed",
            "--yes",
        ],
    );
    assert_eq!(code, 7, "{}", missing.render());
    assert_eq!(text(&missing, "refusal_id"), "FA-REF-012");
    assert_eq!(f.head(), before);

    let own = f.approve(text(&reviewed, "proposal_digest"), "operator");
    let before = f.head();
    let (code, refused) = run(
        &f.book,
        &[
            "post",
            "--review",
            &path,
            "--digest",
            digest,
            "--approval",
            &own,
            "--grant",
            "post_closed",
            "--yes",
        ],
    );
    assert_eq!(code, 7, "{}", refused.render());
    assert_eq!(text(&refused, "refusal_id"), "FA-REF-008");
    assert_eq!(f.head(), before);

    let request_digest = fa_journal::limit::request_form(retained.proposal())
        .unwrap()
        .unwrap()
        .proposal_digest()
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let wrong_amount = f.approve(&request_digest, "requested-amount-reviewer");
    let before = f.head();
    let (code, refused) = run(
        &f.book,
        &[
            "post",
            "--review",
            &path,
            "--digest",
            digest,
            "--approval",
            &wrong_amount,
            "--grant",
            "post_closed",
            "--yes",
        ],
    );
    assert_eq!(code, 7, "{}", refused.render());
    assert_eq!(text(&refused, "refusal_id"), "FA-REF-016");
    assert_eq!(f.head(), before);

    let approval = f.approve(text(&reviewed, "proposal_digest"), "independent-reviewer");
    let plan_path = f.dir.join("capped.plan").display().to_string();
    let before = f.head();
    let planned = ok(
        &f.book,
        &[
            "post",
            "--review",
            &path,
            "--digest",
            digest,
            "--approval",
            &approval,
            "--grant",
            "post_closed",
            "--dry-run",
            "--plan-out",
            &plan_path,
        ],
    );
    assert_eq!(f.head(), before);
    assert_eq!(
        text(&planned, "proposal_digest"),
        text(&reviewed, "proposal_digest")
    );
    assert_eq!(text(&planned, "requested"), "50.00 USD");
    assert_eq!(text(&planned, "moved"), "20.00 USD");
    let plan = fa::PostPlan::decode(&std::fs::read(&plan_path).unwrap()).unwrap();
    assert!(
        plan.intent()
            .proposal()
            .legs
            .iter()
            .all(|leg| leg.amount.mantissa == 5000)
    );
    assert!(
        plan.proposal()
            .legs
            .iter()
            .all(|leg| leg.amount.mantissa == 2000)
    );
    assert_eq!(
        plan.intent().approvals()[0].approved_digest,
        plan.certificate().proposal_digest
    );
    let committed = ok(
        &f.book,
        &["commit", "--plan", &plan_path, "--grant", "post_closed"],
    );
    assert_eq!(f.head(), before + 1);
    let shown = ok(&f.book, &["entry", "show", text(&committed, "vid")]);
    assert_eq!(
        text(&shown, "proposal_digest"),
        text(&reviewed, "proposal_digest")
    );
    let retried = ok(
        &f.book,
        &["commit", "--plan", &plan_path, "--grant", "post_closed"],
    );
    assert_eq!(get(&retried, "already_recorded"), &Json::Bool(true));
    assert_eq!(text(&retried, "vid"), text(&committed, "vid"));
    assert_eq!(f.head(), before + 1);
    ok(&f.book, &["verify", "availability"]);
}

#[test]
fn capped_review_refuses_changed_movement_even_without_required_approvals() {
    let f = Fixture::new();
    let (path, reviewed) = f.review("drifting-capped", "Original", "50.00");
    f.post("intervening", "Original", "5.00");
    let before = f.head();
    let tb = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    let rejected_plan = f.dir.join("rejected.plan").display().to_string();
    for extra in [
        vec![],
        vec!["--dry-run", "--plan-out", rejected_plan.as_str()],
    ] {
        let mut args = vec![
            "post",
            "--review",
            &path,
            "--digest",
            text(&reviewed, "review_digest"),
        ];
        args.extend(extra);
        let (code, refused) = run(&f.book, &args);
        assert_eq!(code, 6, "{}", refused.render());
        assert_eq!(text(&refused, "refusal_id"), "FA-REF-034");
        assert_eq!(f.head(), before);
        assert_eq!(ok(&f.book, &["tb", "--period", "FY2026-P03"]), tb);
        assert!(!Path::new(&rejected_plan).exists());
    }
    let (fresh_path, fresh) = f.review("fresh-capped", "Original", "50.00");
    assert_eq!(text(&fresh, "requested"), "50.00 USD");
    assert_eq!(text(&fresh, "moved"), "15.00 USD");
    let posted = ok(
        &f.book,
        &[
            "post",
            "--review",
            &fresh_path,
            "--digest",
            text(&fresh, "review_digest"),
        ],
    );
    assert_eq!(text(&posted, "moved"), "15.00 USD");
    assert_eq!(text(&posted, "requested"), "50.00 USD");
    assert_eq!(f.head(), before + 1);
}

#[test]
fn capped_review_respects_pending_reservations_and_never_invents_a_zero_entry() {
    let f = Fixture::new();
    f.post("earlier-hold", "Pending", "5.00");
    let (path, reviewed) = f.review("capped-hold", "Pending", "50.00");
    assert_eq!(text(&reviewed, "moved"), "15.00 USD");
    let before = f.head();
    let posted = ok(
        &f.book,
        &[
            "post",
            "--review",
            &path,
            "--digest",
            text(&reviewed, "review_digest"),
        ],
    );
    assert_eq!(text(&posted, "moved"), "15.00 USD");
    assert_eq!(f.head(), before + 1);
    ok(&f.book, &["verify", "availability"]);
    let before = f.head();
    let output = f.dir.join("zero.review").display().to_string();
    let (code, refused) = run(
        &f.book,
        &[
            "post",
            "--intent",
            &f.intent("zero-room", "Original", "1.00"),
            "--evidence",
            &f.evidence,
            "--balancing",
            "0",
            "--review-out",
            &output,
        ],
    );
    assert_eq!(code, 3, "{}", refused.render());
    assert_eq!(f.head(), before);
    assert!(!Path::new(&output).exists());
}

#[test]
fn balancing_review_checks_current_posting_authority_before_account_observation() {
    let f = Fixture::new();
    let (path, reviewed) = f.review("authority", "Original", "50.00");
    let before = f.head();
    let (code, wrong) = run(
        &f.book,
        &["post", "--review", &path, "--digest", &"00".repeat(32)],
    );
    assert_eq!(code, 2, "{}", wrong.render());
    assert_eq!(f.head(), before);
    let (code, other) = run(
        &f.book,
        &[
            "post",
            "--review",
            &path,
            "--digest",
            text(&reviewed, "review_digest"),
            "--as",
            "another-preparer",
        ],
    );
    assert_eq!(code, 7, "{}", other.render());
    assert_eq!(f.head(), before);
    let retained = fa::PostIntent::decode(&std::fs::read(&path).unwrap()).unwrap();
    let mut proposal = fa_journal::limit::request_form(retained.proposal())
        .unwrap()
        .unwrap();
    proposal.legs[0].account_ref = fgdb_types::VId(u128::MAX);
    let capability = fa_journal::Capability::embedded(proposal.principal_ref, &["read"]).unwrap();
    let keys = fa::BookKeys::load(&f.book.join("book.keys")).unwrap();
    let mut book = fa::Book::open_dir(&f.book, keys, fa::Entropy::production()).unwrap();
    let denied = book
        .review_balancing(proposal, &capability)
        .unwrap()
        .unwrap_err();
    assert_eq!(denied.code, "FA-REF-011");
    assert_eq!(book.head().unwrap().0, u64::try_from(before).unwrap());
}
