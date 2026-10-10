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
    assert_eq!(field(&out, "event"), Some("refusal"), "{out}");
    assert_eq!(field(&out, "code"), Some(code), "{out}");
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
    assert!(out.contains("record_review"), "{out}");
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
        assert_eq!(field(&out, "event"), Some("usage_error"), "{key}: {out}");
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
