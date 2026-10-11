//! Binary-level tests for evidence (bead fa-lp6, plan §9.1–§9.2): `fa document
//! add` records a content-addressed document and prints its citation; an
//! entry whose class requires a document is refused without one (exit 3,
//! FA-REF-080) and posts with one; a citation of an unknown document or under
//! a wrong commitment is refused; a grade only a receipt chain may confer is
//! refused at intake. Every `--json` line is checked against its event schema
//! in `registries/verbs.toml`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::verbs::registry;

fn fa(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(dir)
        .args(args)
        .env_remove("FA_BOOK")
        .output()
        .expect("run fa");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if args.contains(&"--json") {
        let reg = registry().expect("verbs.toml");
        for line in stdout.lines() {
            let checked = reg.check_line(line);
            assert!(checked.is_ok(), "args={args:?}: {checked:?}\n{line}");
        }
    }
    (
        out.status.code().unwrap_or(-1),
        stdout,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn tmp(name: &str) -> std::io::Result<PathBuf> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("fa-doc-{}-{name}-{n}", std::process::id()));
        match std::fs::create_dir(&d) {
            Ok(()) => return Ok(d),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> String {
    let p = dir.join(name);
    std::fs::write(&p, bytes).unwrap();
    p.display().to_string()
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\":");
    let i = line.find(&pat)? + pat.len();
    let rest = &line[i..];
    if let Some(r) = rest.strip_prefix('"') {
        r.split('"').next()
    } else {
        rest.split([',', '}']).next()
    }
}

fn ok(book: &Path, args: &[&str]) -> String {
    let (code, out, err) = fa(book, args);
    assert_eq!(code, 0, "args={args:?}\nstdout={out}\nstderr={err}");
    out
}

fn refused(book: &Path, args: &[&str], code: &str, exit: i32) -> String {
    let (got, out, err) = fa(book, args);
    assert_eq!(got, exit, "args={args:?}\nstdout={out}\nstderr={err}");
    assert_eq!(field(&out, "event"), Some("error"), "{out}");
    assert_eq!(field(&out, "refusal_id"), Some(code), "{out}");
    out
}

const RENT: &str = r#""effective_date":"2026-03-15","description":"March rent","legs":[{"side":"debit","account":"6000","amount":"1500.00 USD"},{"side":"credit","account":"1000","amount":"1500.00 USD"}]"#;

#[test]
fn documents_are_recorded_once_and_entries_must_cite_them() -> std::io::Result<()> {
    let dir = tmp("evidence")?;
    let book = dir.join("book");
    ok(
        &book,
        &["book", "create", "--name", "Evidence Co", "--json"],
    );
    let chart = write(
        &dir,
        "chart.json",
        br#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&book, &["chart", "import", &chart, "--json"]);
    ok(
        &book,
        &["period", "create", "--fiscal-year", "2026", "--json"],
    );
    ok(&book, &["period", "open", "FY2026-P03", "--json"]);

    // Intake: content-addressed, the citation printed ready to use.
    let invoice = write(
        &dir,
        "invoice.txt",
        b"INVOICE 1001 Landlord LLC: March rent 1,500.00 USD",
    );
    let out = ok(
        &book,
        &[
            "document",
            "add",
            &invoice,
            "--kind",
            "Invoice",
            "--grade",
            "HumanUpload",
            "--json",
        ],
    );
    assert_eq!(field(&out, "event"), Some("document"), "{out}");
    assert_eq!(field(&out, "kind"), Some("Invoice"), "{out}");
    assert_eq!(field(&out, "grade"), Some("HumanUpload"), "{out}");
    assert_eq!(field(&out, "self_sourced"), Some("false"), "{out}");
    assert_eq!(field(&out, "already_recorded"), Some("false"), "{out}");
    let oid = field(&out, "oid").unwrap().to_string();
    let commit = field(&out, "doc_commit").unwrap().to_string();
    assert_eq!(oid.len(), 64, "{out}");
    assert_eq!(commit.len(), 64, "{out}");
    assert!(
        out.contains(&format!("\"document_oid\":\"{oid}\"")),
        "{out}"
    );

    // The same bytes again: the recorded outcome, and the book's grade stands.
    let out = ok(
        &book,
        &[
            "document",
            "add",
            &invoice,
            "--kind",
            "Invoice",
            "--grade",
            "AgentUpload",
            "--json",
        ],
    );
    assert_eq!(field(&out, "already_recorded"), Some("true"), "{out}");
    assert_eq!(field(&out, "oid"), Some(oid.as_str()), "{out}");
    assert_eq!(field(&out, "grade"), Some("HumanUpload"), "{out}");

    // Undeclared grade defaults to the self-sourced AgentUpload.
    let memo = write(&dir, "memo.txt", b"MEMO: rent accrual workpaper");
    let out = ok(
        &book,
        &["document", "add", &memo, "--kind", "Memo", "--json"],
    );
    assert_eq!(field(&out, "grade"), Some("AgentUpload"), "{out}");
    assert_eq!(field(&out, "self_sourced"), Some("true"), "{out}");
    let memo_oid = field(&out, "oid").unwrap().to_string();

    // A grade only a verified receipt chain confers is refused at intake.
    refused(
        &book,
        &[
            "document",
            "add",
            &invoice,
            "--grade",
            "ThirdPartySigned",
            "--json",
        ],
        "FA-REF-084",
        3,
    );
    // An empty file is not evidence.
    let empty = write(&dir, "empty.txt", b"");
    refused(
        &book,
        &["document", "add", &empty, "--json"],
        "FA-REF-083",
        2,
    );
    // A misspelled kind is a usage error that names the nearest kind.
    let (code, out, _) = fa(
        &book,
        &["document", "add", &invoice, "--kind", "Invoce", "--json"],
    );
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("Invoice"), "{out}");

    // An Original without evidence is refused, citing the registry row.
    let bare = write(
        &dir,
        "bare.json",
        format!(r#"{{"idempotency_key":"rent-0",{RENT}}}"#).as_bytes(),
    );
    let out = refused(
        &book,
        &["post", "--intent", &bare, "--json"],
        "FA-REF-080",
        3,
    );
    assert!(out.contains("evidence_policy.toml"), "{out}");
    assert!(out.contains("fa document add"), "{out}");
    // An agent's own upload does not meet the minimum until a principal other
    // than its uploader reviews it (fa-g21); the refusal names that remedy.
    let out = refused(
        &book,
        &["post", "--intent", &bare, "--evidence", &memo_oid, "--json"],
        "FA-REF-086",
        3,
    );
    assert!(out.contains("Reviewed attestation"), "{out}");
    assert!(out.contains("fa attest review"), "{out}");
    // A citation of a document the book does not hold.
    let unknown = "ab".repeat(32);
    refused(
        &book,
        &["post", "--intent", &bare, "--evidence", &unknown, "--json"],
        "FA-REF-081",
        3,
    );
    // A citation under a commitment that is not the document's.
    let wrong = write(
        &dir,
        "wrong.json",
        format!(
            r#"{{"idempotency_key":"rent-0","evidence":[{{"document_oid":"{oid}","doc_commit":"{}"}}],{RENT}}}"#,
            "00".repeat(32)
        )
        .as_bytes(),
    );
    refused(
        &book,
        &["post", "--intent", &wrong, "--json"],
        "FA-REF-082",
        3,
    );

    // Cited by flag: posted.
    let out = ok(
        &book,
        &["post", "--intent", &bare, "--evidence", &oid, "--json"],
    );
    assert_eq!(field(&out, "event"), Some("posted"), "{out}");
    // Cited in the intent (bare oid form, role Source): posted.
    let cited = write(
        &dir,
        "cited.json",
        format!(r#"{{"idempotency_key":"rent-1","evidence":["{oid}"],{RENT}}}"#).as_bytes(),
    );
    let out = ok(&book, &["post", "--intent", &cited, "--json"]);
    assert_eq!(field(&out, "event"), Some("posted"), "{out}");

    // A role is a registered name or its integer tag — the form `fa explain`
    // prints — and survives into the entry (review D3); anything else is a
    // usage error, never a silent `Source`.
    let with_role = |key: &str, extra: &str| {
        write(
            &dir,
            &format!("{key}.json"),
            format!(
                r#"{{"idempotency_key":"{key}","evidence":[{{"document_oid":"{oid}"{extra}}}],{RENT}}}"#
            )
            .as_bytes(),
        )
    };
    for (key, extra) in [
        ("bad-role-name", r#","role":"Rat""#),
        ("bad-role-type", r#","role":true"#),
        ("bad-role-tag", r#","role":99"#),
        ("bad-commit-type", r#","doc_commit":5"#),
    ] {
        let (code, out, _) = fa(
            &book,
            &["post", "--intent", &with_role(key, extra), "--json"],
        );
        assert_eq!(code, 2, "{key}: {out}");
        assert_eq!(field(&out, "event"), Some("error"), "{key}: {out}");
        assert_eq!(field(&out, "class"), Some("usage"), "{key}: {out}");
    }
    let (_, out, _) = fa(
        &book,
        &[
            "post",
            "--intent",
            &with_role("bad-role-name", r#","role":"Rat""#),
            "--json",
        ],
    );
    assert!(out.contains("Rate"), "the nearest role is named: {out}");
    let out = ok(
        &book,
        &[
            "post",
            "--intent",
            &with_role("rent-rate-role", r#","role":3"#),
            "--json",
        ],
    );
    assert_eq!(field(&out, "event"), Some("posted"), "{out}");
    let out = ok(
        &book,
        &[
            "explain",
            "balance",
            "6000",
            "--period",
            "FY2026-P03",
            "--json",
        ],
    );
    assert!(
        out.contains(r#""role":3"#),
        "the Rate role (3) survives: {out}"
    );
    assert!(
        out.contains(r#""role":1"#),
        "the Source citations remain: {out}"
    );
    Ok(())
}

/// `fa attest review` (plan §9.3, beads fa-g21/fa-12x): an agent's own upload
/// does not meet the minimum; a principal other than its uploader reviews it
/// under an explicit `--grant approve`, and the same entry then posts. The
/// uploader never reviews its own upload (FA-REF-111, exit 7); without the
/// grant the review is refused before the book is opened; an unknown
/// document is FA-REF-110; a repeat review records nothing new.
#[test]
fn a_reviewer_other_than_the_uploader_promotes_a_self_sourced_document() -> std::io::Result<()> {
    let dir = tmp("attest")?;
    let book = dir.join("book");
    ok(&book, &["book", "create", "--name", "Review Co", "--json"]);
    let chart = write(
        &dir,
        "chart.json",
        br#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&book, &["chart", "import", &chart, "--json"]);
    ok(
        &book,
        &["period", "create", "--fiscal-year", "2026", "--json"],
    );
    ok(&book, &["period", "open", "FY2026-P03", "--json"]);

    // The agent (the default principal) uploads its own workpaper.
    let memo = write(&dir, "memo.txt", b"MEMO: rent accrual workpaper");
    let out = ok(
        &book,
        &["document", "add", &memo, "--kind", "Memo", "--json"],
    );
    assert_eq!(field(&out, "self_sourced"), Some("true"), "{out}");
    let memo_oid = field(&out, "oid").unwrap_or_default().to_string();
    let entry = write(
        &dir,
        "rent.json",
        format!(r#"{{"idempotency_key":"rent-1",{RENT}}}"#).as_bytes(),
    );
    let posting = [
        "post",
        "--intent",
        &entry,
        "--evidence",
        &memo_oid,
        "--json",
    ];
    refused(&book, &posting, "FA-REF-086", 3);

    // No grant: refused before the book is opened, naming the grant.
    let out = refused(
        &book,
        &[
            "attest",
            "review",
            &memo_oid,
            "--as",
            "controller",
            "--json",
        ],
        "FA-REF-011",
        7,
    );
    assert!(out.contains("approve"), "{out}");
    // The uploader reviewing its own upload: segregation of duties.
    refused(
        &book,
        &[
            "attest", "review", &memo_oid, "--grant", "approve", "--json",
        ],
        "FA-REF-111",
        7,
    );
    // A document the book does not hold.
    let unknown = "ab".repeat(32);
    refused(
        &book,
        &[
            "attest",
            "review",
            &unknown,
            "--grant",
            "approve",
            "--as",
            "controller",
            "--json",
        ],
        "FA-REF-110",
        3,
    );
    // A malformed oid is a usage error.
    let (code, out, _) = fa(
        &book,
        &["attest", "review", "xyz", "--grant", "approve", "--json"],
    );
    assert_eq!(code, 2, "{out}");

    // The controller reviews it; the entry now posts.
    let out = ok(
        &book,
        &[
            "attest",
            "review",
            &memo_oid,
            "--grant",
            "approve",
            "--as",
            "controller",
            "--json",
        ],
    );
    assert_eq!(field(&out, "event"), Some("attested"), "{out}");
    assert_eq!(field(&out, "kind"), Some("Reviewed"), "{out}");
    assert_eq!(field(&out, "subject"), Some(memo_oid.as_str()), "{out}");
    assert_eq!(field(&out, "already_recorded"), Some("false"), "{out}");
    let vid = field(&out, "vid").unwrap_or_default().to_string();
    assert!(out.contains("fa post --intent"), "next_actions: {out}");
    let out = ok(&book, &posting);
    assert_eq!(field(&out, "event"), Some("posted"), "{out}");

    // A repeat review is the recorded attestation; nothing new is written.
    let out = ok(
        &book,
        &[
            "attest",
            "review",
            &memo_oid,
            "--grant",
            "approve",
            "--as",
            "controller",
            "--json",
        ],
    );
    assert_eq!(field(&out, "already_recorded"), Some("true"), "{out}");
    assert_eq!(field(&out, "vid"), Some(vid.as_str()), "{out}");
    Ok(())
}

/// fa-12x slice 2 (plan §9.2): where no document exists, the preparer plans
/// the entry (`--plan-out` seals its proposal once), asserts why under a
/// registered reason (`fa attest manual --plan`), and posts exactly that
/// proposal (`fa post --plan`). The plan is the only route: a proposal
/// rebuilt from the intent seals afresh and is a different proposal.
#[test]
fn a_manual_assertion_over_a_planned_proposal_lets_exactly_that_proposal_post()
-> std::io::Result<()> {
    let dir = tmp("manual")?;
    let book = dir.join("book");
    ok(&book, &["book", "create", "--name", "Manual Co", "--json"]);
    let chart = write(
        &dir,
        "chart.json",
        br#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&book, &["chart", "import", &chart, "--json"]);
    ok(
        &book,
        &["period", "create", "--fiscal-year", "2026", "--json"],
    );
    ok(&book, &["period", "open", "FY2026-P03", "--json"]);
    let entry = write(
        &dir,
        "fee.json",
        format!(r#"{{"idempotency_key":"fee-1",{RENT}}}"#).as_bytes(),
    );
    let plan = dir.join("fee.plan").display().to_string();

    // Planning commits nothing and names the assertion as the next step.
    let out = ok(
        &book,
        &["post", "--intent", &entry, "--plan-out", &plan, "--json"],
    );
    assert_eq!(field(&out, "event"), Some("entry_planned"), "{out}");
    assert_eq!(field(&out, "class"), Some("Original"), "{out}");
    let digest = field(&out, "proposal_digest")
        .unwrap_or_default()
        .to_string();
    assert_eq!(digest.len(), 64, "{out}");
    assert!(
        out.contains("fa attest manual --plan"),
        "next_actions: {out}"
    );
    let out = ok(&book, &["tb", "--period", "FY2026-P03", "--json"]);
    assert!(!out.contains("1500.00"), "nothing was committed: {out}");

    // Without the assertion the plan is below the minimum.
    refused(&book, &["post", "--plan", &plan, "--json"], "FA-REF-080", 3);

    // Refusals before the assertion is recorded.
    let manual = |reason: &str, statement: &str, who: Option<&str>| {
        let mut argv = vec![
            "attest",
            "manual",
            "--plan",
            plan.as_str(),
            "--reason",
            reason,
            "--statement",
            statement,
            "--json",
        ];
        if let Some(w) = who {
            argv.extend(["--as", w]);
        }
        fa(&book, &argv)
    };
    let why = "the bank shows this fee only as a statement line";
    // An unknown reason name is a usage error that lists the names.
    let (code, out, _) = manual("NoDocumentIsued", why, None);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("NoDocumentIssued"), "{out}");
    // An unregistered code reaches the kernel, which refuses it.
    let (code, out, _) = manual("999", why, None);
    assert_eq!(
        (code, field(&out, "refusal_id")),
        (2, Some("FA-REF-112")),
        "{out}"
    );
    // A blank statement carries no particulars.
    let (code, out, _) = manual("NoDocumentIssued", "   ", None);
    assert_eq!(
        (code, field(&out, "refusal_id")),
        (2, Some("FA-REF-100")),
        "{out}"
    );
    // The assertion is the preparer's: another principal is refused.
    let (code, out, _) = manual("NoDocumentIssued", why, Some("controller"));
    assert_eq!(
        (code, field(&out, "refusal_id")),
        (7, Some("FA-REF-011")),
        "{out}"
    );
    // A file that is not a plan, and a truncated plan.
    let (code, out, _) = fa(
        &book,
        &[
            "attest",
            "manual",
            "--plan",
            &entry,
            "--reason",
            "1",
            "--statement",
            why,
            "--json",
        ],
    );
    assert_eq!(code, 2, "{out}");
    let bytes = std::fs::read(&plan)?;
    let cut = write(&dir, "cut.plan", &bytes[..bytes.len() - 1]);
    let (code, out, _) = fa(&book, &["post", "--plan", &cut, "--json"]);
    assert_eq!(code, 2, "{out}");

    // The preparer asserts; the attestation's subject is the plan's digest.
    let (code, out, err) = manual("NoDocumentIssued", why, None);
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(field(&out, "event"), Some("attested"), "{out}");
    assert_eq!(field(&out, "kind"), Some("ManualAssertion"), "{out}");
    assert_eq!(field(&out, "subject"), Some(digest.as_str()), "{out}");
    assert!(out.contains("fa post --plan"), "next_actions: {out}");

    // The same intent posted directly is a fresh proposal (its description
    // sealed anew), which the assertion does not cover.
    refused(
        &book,
        &["post", "--intent", &entry, "--json"],
        "FA-REF-080",
        3,
    );
    // Flags that would change the planned proposal, or plan anew, are refused.
    let (code, out, _) = fa(
        &book,
        &["post", "--plan", &plan, "--intent", &entry, "--json"],
    );
    assert_eq!(code, 2, "{out}");
    let (code, out, _) = fa(&book, &["reserve", "--plan", &plan, "--json"]);
    assert_eq!(code, 2, "{out}");
    // An approval binds a planned proposal's digest, never a fresh intent.
    let zero = "0".repeat(32);
    let (code, out, _) = fa(
        &book,
        &["post", "--intent", &entry, "--approval", &zero, "--json"],
    );
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("--plan-out"), "{out}");

    // Exactly the planned proposal posts; a repeat is the recorded outcome.
    let out = ok(&book, &["post", "--plan", &plan, "--json"]);
    assert_eq!(field(&out, "event"), Some("posted"), "{out}");
    let vid = field(&out, "vid").unwrap_or_default().to_string();
    let out = ok(&book, &["post", "--plan", &plan, "--json"]);
    assert_eq!(field(&out, "event"), Some("recorded"), "{out}");
    assert_eq!(field(&out, "vid"), Some(vid.as_str()), "{out}");
    Ok(())
}
