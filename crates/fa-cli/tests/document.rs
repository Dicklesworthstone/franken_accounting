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

/// fa-81lu (plan §9.2 AttachEvidence): `fa document attach` records the
/// documents that support a committed entry as one SupplementalEvidence. The
/// entry keeps its own evidence; `fa explain evidence` lists the supplement
/// with its documents; the same attachment again is the recorded one; an
/// unknown entry, an unknown document and a missing --evidence are refused.
#[test]
fn attach_creates_supplemental_evidence() -> std::io::Result<()> {
    let dir = tmp("attach")?;
    let book = dir.join("book");
    ok(&book, &["book", "create", "--name", "Attach Co", "--json"]);
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
    let add = |name: &str, bytes: &[u8], kind: &str| -> String {
        let path = write(&dir, name, bytes);
        let out = ok(
            &book,
            &[
                "document",
                "add",
                &path,
                "--kind",
                kind,
                "--grade",
                "HumanUpload",
                "--json",
            ],
        );
        field(&out, "oid").unwrap().to_string()
    };
    let invoice = add(
        "invoice.txt",
        b"INVOICE 1001 Landlord LLC: March rent",
        "Invoice",
    );
    let lease = add("lease.txt", b"LEASE: 12 months at 1,500.00 USD", "Contract");
    let intent = write(
        &dir,
        "rent.json",
        format!(r#"{{"idempotency_key":"rent","evidence":["{invoice}"],{RENT}}}"#).as_bytes(),
    );
    let posted = ok(&book, &["post", "--intent", &intent, "--json"]);
    let entry = field(&posted, "vid").unwrap().to_string();

    let lease_cited = format!("{lease}:Contract");
    let attach = [
        "document",
        "attach",
        entry.as_str(),
        "--evidence",
        lease_cited.as_str(),
        "--json",
    ];
    let out = ok(&book, &attach);
    assert_eq!(field(&out, "event"), Some("evidence_attached"), "{out}");
    assert_eq!(field(&out, "entry"), Some(entry.as_str()), "{out}");
    assert_eq!(field(&out, "already_recorded"), Some("false"), "{out}");
    assert!(
        out.contains(&format!("\"document_oid\":\"{lease}\"")),
        "{out}"
    );
    assert!(out.contains("\"role\":\"Contract\""), "{out}");
    let supplement = field(&out, "supplement_vid").unwrap().to_string();
    let recorded_at = field(&out, "recorded_at").unwrap().to_string();

    // The same attachment again is the recorded one; nothing new is written.
    let again = ok(&book, &attach);
    assert_eq!(field(&again, "already_recorded"), Some("true"), "{again}");
    assert_eq!(field(&again, "supplement_vid"), Some(supplement.as_str()));
    assert_eq!(field(&again, "recorded_at"), Some(recorded_at.as_str()));

    // explain evidence: the entry still cites only the invoice, and the
    // supplement is listed with the lease.
    let explained = ok(&book, &["explain", "evidence", &entry, "--json"]);
    assert_eq!(field(&explained, "event"), Some("evidence_explained"));
    let cited = explained.matches("\"counts_toward_minimum\"").count();
    assert_eq!(
        cited, 1,
        "the entry's own evidence is unchanged: {explained}"
    );
    let listed = explained
        .split("\"supplements\":[{")
        .last()
        .unwrap_or_default();
    assert!(
        listed.contains(&format!("\"supplement_vid\":\"{supplement}\""))
            && listed.contains(&format!("\"document_oid\":\"{lease}\"")),
        "{explained}"
    );
    // fa-ge0y: the provenance closure names the invoice the entry was
    // posted with and its principal; the supplement and the lease joined
    // it later, so the closure as posted has its own digest.
    let line = fa_cli::json::parse(explained.trim()).expect("one robot line");
    let closure = line
        .get("data")
        .and_then(|data| data.get("closure"))
        .expect("a closure");
    let members: Vec<(String, String, String)> = closure
        .get("members")
        .and_then(fa_cli::json::Json::as_arr)
        .unwrap_or_default()
        .iter()
        .map(|m| {
            let text = |key: &str| {
                m.get(key)
                    .and_then(fa_cli::json::Json::as_str)
                    .unwrap_or_default()
                    .to_string()
            };
            (text("kind"), text("vid"), text("digest"))
        })
        .collect();
    let has = |kind: &str, check: &dyn Fn(&(String, String, String)) -> bool| {
        members.iter().any(|m| m.0 == kind && check(m))
    };
    assert!(has("document", &|m| m.2 == invoice), "{explained}");
    assert!(has("principal", &|_| true), "{explained}");
    assert!(has("origin", &|_| true), "{explained}");
    assert!(has("supplement", &|m| m.1 == supplement), "{explained}");
    assert!(has("supplement_document", &|m| m.2 == lease), "{explained}");
    let digest = |key: &str| {
        closure
            .get(key)
            .and_then(fa_cli::json::Json::as_str)
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(digest("digest").len(), 64, "{explained}");
    assert_ne!(digest("original_digest"), digest("digest"), "{explained}");

    // An unknown document is the kernel's refusal; nothing is written.
    let unknown = "ab".repeat(32);
    refused(
        &book,
        &[
            "document",
            "attach",
            &entry,
            "--evidence",
            &unknown,
            "--json",
        ],
        "FA-REF-081",
        3,
    );
    // An entry the book does not hold, and an attachment naming nothing,
    // are usage errors.
    let (code, out, _) = fa(
        &book,
        &[
            "document",
            "attach",
            &"cd".repeat(16),
            "--evidence",
            &lease,
            "--json",
        ],
    );
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("no entry"), "{out}");
    let (code, out, _) = fa(&book, &["document", "attach", &entry, "--json"]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("--evidence"), "{out}");
    Ok(())
}
