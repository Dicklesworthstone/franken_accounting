//! A Locked-period reclose passes through an exact scenario, two independent
//! approvals and the existing atomic Case Post; foreign carrying amounts and
//! complete source revalidation survive process boundaries and portable proof.

use super::*;

const OWNER: &str = "reclose-analyst";
const SCENARIO: &str = "reviewed-reclose";
const PERIOD: &str = "FY2026-CLOSE";

#[test]
fn locked_case_modes_require_operator_restate_without_expanding_launch_ceilings() {
    use fa_cli::authority::{LaunchAuthority, LaunchProfile};

    let registry = fa_cli::verbs::registry().unwrap();
    for flags in [
        vec!["--case-review", "--review-only"],
        vec!["--review", "aa", "--digest", "bb", "--scenario", "reclose"],
    ] {
        let argv: Vec<String> = ["close", "year-end"]
            .into_iter()
            .chain(flags)
            .map(str::to_string)
            .collect();
        let args =
            fa_cli::args::parse(&argv, &registry.value_flags(), &registry.switches()).unwrap();
        let ops = fa_cli::cli::bound_command_ops("close", &args).unwrap();
        assert_eq!(
            ops.iter().map(|op| op.name()).collect::<Vec<_>>(),
            ["read", "post", "restate"],
        );
        for profile in [LaunchProfile::Agent, LaunchProfile::Preparer] {
            let authority = LaunchAuthority::new(
                PathBuf::from("unopened-locked-reclose-book"),
                None,
                "reclose-preparer",
                profile,
                &["read", "post"],
            )
            .unwrap();
            let refusal =
                fa_cli::cli::bound_command_admissible(registry, "close", &args, &authority)
                    .unwrap_err();
            assert!(refusal.contains("restate"), "{argv:?}: {refusal}");
            assert!(!profile.ceiling().contains(&fa::Op::Restate));
        }
    }
}

fn many(book: &Path, args: &[&str]) -> (i32, Vec<Json>) {
    let result = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8(result.stdout).unwrap();
    let registry = fa_cli::verbs::registry().unwrap();
    let lines = stdout
        .lines()
        .map(|line| {
            registry.check_line(line).unwrap();
            json::parse(line).unwrap()
        })
        .collect();
    assert!(
        !stdout.is_empty(),
        "args={args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    (result.status.code().unwrap_or(-1), lines)
}

fn locked_fixture() -> Fixture {
    let f = Fixture::with_chart(
        true,
        r#"{"accounts":[
            {"code":"1000","name":"Cash","type":"Asset","unit":"any-currency"},
            {"code":"3000","name":"Retained earnings","type":"Equity","unit":"any-currency"},
            {"code":"4000","name":"Revenue","type":"Revenue","unit":"any-currency"},
            {"code":"6000","name":"Expense","type":"Expense","unit":"any-currency"}
        ]}"#,
    );
    f.post("case-original-sale", "1000", "4000", "100.00");
    f.post("case-original-expense", "6000", "1000", "20.00");
    f.close_now("case-first-close");
    let rate_file = write(
        &f.dir,
        "late-rate.json",
        r#"{"base_unit":"USD","quote_unit":"EUR","rate_num":"11","rate_den":"10","rounding":"HalfEven","as_of":"2026-12-30","retrieved_at_ns":1767571200000000000,"purpose":"spot_close","source":"late-reviewed-sale"}"#,
    );
    let rate = ok(&f.book, &["fx", "rate", "add", "--from-json", &rate_file]);
    let sale = write(
        &f.dir,
        "late-sale.json",
        &format!(
            r#"{{"effective_date":"2026-12-30","idempotency_key":"case-late-sale","fx":{{"law":"SpotClose","rates":["D:{}"]}},"legs":[{{"side":"debit","account":"1000","amount":"30.00 EUR"}},{{"side":"credit","account":"4000","amount":"30.00 EUR"}}]}}"#,
            text(&rate, "oid")
        ),
    );
    ok(
        &f.book,
        &["post", "--intent", &sale, "--evidence", &f.evidence],
    );
    ok(
        &f.book,
        &["period", "close", PERIOD, "--reason", "Scheduled", "--yes"],
    );
    let lock_path = f.dir.join("close.lock").display().to_string();
    let lock = ok(
        &f.book,
        &[
            "period",
            "lock",
            PERIOD,
            "--reason",
            "Scheduled",
            "--plan-out",
            &lock_path,
        ],
    );
    let approval = ok(
        &f.book,
        &[
            "approve",
            "--proposal",
            text(&lock, "proposal_digest"),
            "--as",
            "lock-controller",
        ],
    );
    ok(
        &f.book,
        &[
            "period",
            "lock",
            PERIOD,
            "--plan",
            &lock_path,
            "--approval",
            text(&approval, "approval_vid"),
            "--yes",
        ],
    );
    f
}

fn review(f: &Fixture) -> (String, Json) {
    let path = f.dir.join("case-close.review").display().to_string();
    let before = head(&f.book);
    let reviewed = ok(
        &f.book,
        &[
            "close",
            "year-end",
            "--fiscal-year",
            "2026",
            "--period",
            PERIOD,
            "--key",
            "case-reclose",
            "--evidence",
            &f.evidence,
            "--case-review",
            "--review-out",
            &path,
            "--as",
            OWNER,
        ],
    );
    assert_eq!(head(&f.book), before, "case preparation publishes nothing");
    assert_eq!(
        leg_nets(&reviewed),
        BTreeMap::from([("3000".into(), -3_000), ("4000".into(), 3_000),])
    );
    (path, reviewed)
}

fn approve(f: &Fixture, path: &str, reviewed: &Json) {
    ok(&f.book, &["scenario", "fork", SCENARIO, "--as", OWNER]);
    let append = [
        "close",
        "year-end",
        "--review",
        path,
        "--digest",
        text(reviewed, "review_digest"),
        "--scenario",
        SCENARIO,
        "--as",
        OWNER,
    ];
    let appended = ok(&f.book, &append);
    assert_eq!(text(&appended, "event"), "scenario_run");
    assert_eq!(get(&appended, "rehearsed"), &Json::Bool(true));
    let before = head(&f.book);
    let repeated = ok(&f.book, &append);
    assert_eq!(get(&repeated, "already_recorded"), &Json::Bool(true));
    assert_eq!(head(&f.book), before);

    // A second reviewed close cannot turn this into a dependent aggregate batch.
    let other = write(
        &f.dir,
        "mixed.json",
        r#"{"effective_date":"2026-12-30","idempotency_key":"mixed-source","legs":[{"side":"debit","account":"1000","amount":"1.00 USD"},{"side":"credit","account":"4000","amount":"1.00 USD"}]}"#,
    );
    let (code, error) = run(
        &f.book,
        &[
            "scenario",
            "run",
            SCENARIO,
            "--intent",
            &other,
            "--evidence",
            &f.evidence,
            "--as",
            OWNER,
        ],
    );
    assert_eq!(code, 3, "{}", error.render());
    assert_eq!(text(&error, "refusal_id"), "FA-REF-102");
    assert_eq!(head(&f.book), before);

    ok(
        &f.book,
        &[
            "case",
            "open",
            "--kind",
            "Restatement",
            "--periods",
            PERIOD,
            "--determined-on",
            "2027-01-02",
            "--authority",
            &f.evidence,
        ],
    );
    let certificate = f.dir.join("case-close.cert").display().to_string();
    let (code, output) = many(
        &f.book,
        &[
            "scenario",
            "diff",
            SCENARIO,
            "--period",
            PERIOD,
            "--certificate-out",
            &certificate,
        ],
    );
    assert_eq!(code, 0, "{output:?}");
    ok(
        &f.book,
        &["case", "rehearse", "1", "--certificate", &certificate],
    );
    let manifest = ok(&f.book, &["case", "approve", "1", "--dry-run"]);
    assert_eq!(get(&manifest, "entries").as_arr().unwrap().len(), 1);
    let digest = text(&manifest, "digest");
    let first = ok(
        &f.book,
        &["approve", "--proposal", digest, "--as", "case-controller"],
    );
    let second = ok(
        &f.book,
        &["approve", "--proposal", digest, "--as", "case-auditor"],
    );
    let own = ok(&f.book, &["approve", "--proposal", digest, "--as", OWNER]);
    let before = head(&f.book);
    for approvals in [
        vec![text(&first, "approval_vid")],
        vec![text(&first, "approval_vid"), text(&own, "approval_vid")],
    ] {
        let mut args = vec!["case", "approve", "1"];
        for approval in approvals {
            args.extend(["--approval", approval]);
        }
        let (code, error) = run(&f.book, &args);
        assert_eq!(code, 7, "{}", error.render());
        assert_eq!(head(&f.book), before);
    }
    ok(
        &f.book,
        &[
            "case",
            "approve",
            "1",
            "--approval",
            text(&first, "approval_vid"),
            "--approval",
            text(&second, "approval_vid"),
        ],
    );
}

#[test]
fn locked_case_reclose_posts_once_under_dual_control_and_exports_functional_proof() {
    let f = locked_fixture();
    let (path, reviewed) = review(&f);
    let before = head(&f.book);
    let (code, error) = run(
        &f.book,
        &[
            "close",
            "year-end",
            "--review",
            &path,
            "--digest",
            text(&reviewed, "review_digest"),
            "--dry-run",
            "--as",
            OWNER,
        ],
    );
    assert_eq!(
        code,
        3,
        "standalone Closing must refuse Locked: {}",
        error.render()
    );
    assert_eq!(text(&error, "refusal_id"), "FA-REF-102");
    assert_eq!(head(&f.book), before);
    approve(&f, &path, &reviewed);

    let before = head(&f.book);
    let (code, error) = run(&f.book, &["case", "post", "1", "--as", "case-controller"]);
    assert_eq!(
        code,
        7,
        "an approver cannot be the posting preparer: {}",
        error.render()
    );
    assert_eq!(head(&f.book), before);
    let posted = ok(&f.book, &["case", "post", "1"]);
    assert_eq!(
        integer(&posted, "recorded_at"),
        before + 1,
        "Closing and Case Post share one publication"
    );
    assert_eq!(text(get(&posted, "case"), "state"), "Posted");
    assert_eq!(
        get(get(&posted, "case"), "posted").as_arr().unwrap().len(),
        1
    );
    let post_head = head(&f.book);
    let repeated = ok(&f.book, &["case", "post", "1"]);
    assert_eq!(get(&repeated, "already_recorded"), &Json::Bool(true));
    assert_eq!(head(&f.book), post_head);
    let verified = ok(&f.book, &["verify", "close", "FY2026"]);
    assert_eq!(get(&verified, "needs_reclose"), &Json::Bool(false));

    let mut book = fa::Book::open_dir(
        &f.book,
        fa::BookKeys::load(&f.book.join("book.keys")).unwrap(),
        fa::Entropy::deterministic(174),
    )
    .unwrap();
    let case = book.case(1).unwrap().unwrap();
    let (entry, recorded_at) = book.read_entry(case.posted[0].entry).unwrap().unwrap();
    assert_eq!(recorded_at.0 as i128, post_head);
    assert_eq!(entry.proposal.class, fa_model::EntryClass::CLOSING);
    assert_eq!(
        entry
            .proposal
            .extensions
            .iter()
            .map(|(tag, _)| *tag)
            .collect::<Vec<_>>(),
        [12, 23]
    );
    assert_eq!(entry.proposal.base_totals.as_ref().unwrap().debits, 3_300);
    assert_eq!(entry.proposal.base_totals.as_ref().unwrap().credits, 3_300);
    let principal = fgdb_types::VId(174);
    let producer = fa::Capability::embedded(principal, &["read", "produce", "witness"]).unwrap();
    let certificate = book
        .certify_functional_trial_balance(
            &producer,
            fa::TrialBalanceSelection::AsOf(fa_time::DateDay::from_ymd(2026, 12, 31).unwrap()),
            None,
        )
        .unwrap()
        .unwrap()
        .certificate;
    let state = book
        .checkpoint(principal, &producer)
        .unwrap()
        .unwrap()
        .checkpoint
        .checkpoint
        .body
        .state_oid;
    let produced = book
        .produce_report_bundle(principal, &producer, Some(state), &certificate)
        .unwrap()
        .unwrap()
        .unwrap();
    let independent = fa_verify::report::verify_report_expected(
        &produced.bundle.bytes,
        &[book.checkpoint_public_key()],
        None,
        Some(&produced.receipt),
        Some(&certificate.digest),
    )
    .unwrap();
    assert_eq!(independent.output, certificate.output);
    let tb = independent.functional_trial_balance.unwrap();
    for (account, expected) in [
        ("1000", 11_300),
        ("3000", -11_300),
        ("4000", 0),
        ("6000", 0),
    ] {
        let vid = fa_model::account_vid(book.context().book_id, account).0;
        let actual: i128 = tb
            .cells
            .iter()
            .filter(|cell| cell.account == vid)
            .map(|cell| cell.debits - cell.credits)
            .sum();
        assert_eq!(actual, expected, "{account}");
    }
}

#[test]
fn approved_reclose_refuses_even_same_net_new_sources_without_partial_publication() {
    let f = locked_fixture();
    let (path, reviewed) = review(&f);
    approve(&f, &path, &reviewed);
    f.post("case-after-review-sale", "1000", "4000", "5.00");
    f.post("case-after-review-refund", "4000", "1000", "5.00");
    let before = head(&f.book);
    let (code, error) = run(&f.book, &["case", "post", "1"]);
    assert_eq!(
        code,
        6,
        "a balanced but changed source must invalidate the exact review: {}",
        error.render()
    );
    assert_eq!(text(&error, "refusal_id"), "FA-REF-034");
    assert_eq!(head(&f.book), before);
    let case = ok(&f.book, &["case", "show", "1"]);
    assert_eq!(text(get(&case, "case"), "state"), "Approved");
    assert!(
        get(get(&case, "case"), "posted")
            .as_arr()
            .unwrap()
            .is_empty()
    );
    assert_eq!(run(&f.book, &["verify", "close", "FY2026"]).0, 8);
}
