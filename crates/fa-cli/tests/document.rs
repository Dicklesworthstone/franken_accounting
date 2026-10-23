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
/// `fa assert-balance` (plan §9.4, Appendix B AssertBalance): an
/// assertion equal to the cell's net (debits minus credits) records a
/// RegisterEquals attestation that holds (asserting again later is a new
/// assertion at the later sequence); a false one is refused FA-REF-140,
/// exit 3, naming both amounts and the difference, and records nothing.
#[test]
fn assert_balance_records_a_true_assertion_and_refuses_a_false_one() -> std::io::Result<()> {
    let dir = tmp("assert-balance")?;
    let book = dir.join("book");
    ok(&book, &["book", "create", "--name", "Assert Co", "--json"]);
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
    let statement = write(
        &dir,
        "statement.txt",
        b"Bank statement: March closing balance",
    );
    let out = ok(
        &book,
        &[
            "document",
            "add",
            &statement,
            "--kind",
            "Invoice",
            "--grade",
            "HumanUpload",
            "--json",
        ],
    );
    let oid = field(&out, "oid").expect("oid").to_string();
    let rent = write(
        &dir,
        "rent.json",
        format!("{{\"idempotency_key\":\"rent\",{RENT}}}").as_bytes(),
    );
    ok(
        &book,
        &["post", "--intent", &rent, "--evidence", &oid, "--json"],
    );

    // Cash was credited 1500.00: its net is negative. Rent's is positive.
    let assert = |account: &str, balance: &str| -> Vec<String> {
        [
            "assert-balance",
            "--account",
            account,
            "--period",
            "FY2026-P03",
            "--balance",
            balance,
            "--evidence",
            &oid,
            "--json",
        ]
        .iter()
        .map(|a| (*a).to_string())
        .collect()
    };
    fn args(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }
    let cash = ok(&book, &args(&assert("1000", "-1500.00 USD")));
    assert_eq!(
        field(&cash, "event"),
        Some("attestation_recorded"),
        "{cash}"
    );
    assert_eq!(field(&cash, "claim"), Some("RegisterEquals"), "{cash}");
    assert_eq!(field(&cash, "holds"), Some("true"), "{cash}");
    assert_eq!(field(&cash, "already_recorded"), Some("false"), "{cash}");
    // Asserting again later is a new assertion at the later sequence (the
    // claim binds the sequence it was evaluated at); it holds too.
    let again = ok(&book, &args(&assert("1000", "-1500.00 USD")));
    assert_eq!(field(&again, "holds"), Some("true"), "{again}");
    assert_eq!(field(&again, "already_recorded"), Some("false"), "{again}");
    assert_ne!(
        field(&again, "attestation_vid"),
        field(&cash, "attestation_vid")
    );
    let rent_holds = ok(&book, &args(&assert("6000", "1500.00 USD")));
    assert_eq!(field(&rent_holds, "holds"), Some("true"), "{rent_holds}");
    let checked = ok(
        &book,
        &[
            "document",
            "attest",
            "register-equals",
            field(&cash, "attestation_vid").unwrap(),
            "--json",
        ],
    );
    assert_eq!(field(&checked, "holds"), Some("true"), "{checked}");

    // Planted: the wrong sign, and a wrong amount. Each is refused and
    // records nothing.
    let head = |out: &str| field(out, "known_at").map(str::to_string);
    let before = ok(&book, &["book", "info", "--json"]);
    assert!(head(&before).is_some(), "{before}");
    let wrong_sign = refused(
        &book,
        &args(&assert("1000", "1500.00 USD")),
        "FA-REF-140",
        3,
    );
    assert!(
        wrong_sign.contains("-1500.00 USD") && wrong_sign.contains("off by 3000.00 USD"),
        "{wrong_sign}"
    );
    refused(
        &book,
        &args(&assert("6000", "1499.99 USD")),
        "FA-REF-140",
        3,
    );
    let after = ok(&book, &["book", "info", "--json"]);
    assert_eq!(head(&after), head(&before), "a false assertion wrote");
    let (code, _, _) = fa(&book, &["assert-balance", "--account", "1000", "--json"]);
    assert_eq!(code, 2);

    // Authority precedes observation: an Agent token holding reconcile
    // passes the bound route, and the balance-assertion law refuses it on
    // trunk before the cell is read, so an existing and a nonexistent period
    // get the same refusal and the book learns nothing.
    let token = dir.join("agent.token").display().to_string();
    ok(
        &book,
        &[
            "capability",
            "issue",
            "--holder",
            "assert-agent",
            "--profile",
            "agent",
            "--op",
            "read",
            "--op",
            "reconcile",
            "--grant",
            "issue_capability",
            "--grant",
            "read",
            "--grant",
            "reconcile",
            "--out",
            &token,
            "--json",
        ],
    );
    let mut refusals = Vec::new();
    for period in ["FY2026-P03", "FY2099-P01"] {
        let (code, out, err) = fa(
            &book,
            &[
                "--token",
                &token,
                "assert-balance",
                "--account",
                "1000",
                "--period",
                period,
                "--balance",
                "-1500.00 USD",
                "--json",
            ],
        );
        assert_eq!(code, 7, "{period}: {out}\n{err}");
        refusals.push(field(&out, "refusal_id").map(str::to_string));
    }
    assert!(refusals[0].is_some(), "{refusals:?}");
    assert_eq!(refusals[0], refusals[1], "the period was observed first");
    Ok(())
}

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

/// fa-lzrn (plan §9.1, fa-646's pipeline): `fa document extract` records a
/// PDF's text layer as a derived text document. Its bytes bind the source,
/// `fa document read` shows the text and its lineage, the same extraction
/// again is the recorded document, `--kind` names a different one, and it is
/// graded by who ran it, never the source's HumanUpload. A source that is not
/// a PDF is refused with FA-REF-193 and nothing is written; an unknown oid
/// is refused.
#[test]
fn extract_records_a_pdf_text_layer_as_a_derived_document() -> std::io::Result<()> {
    let dir = tmp("extract")?;
    let book = dir.join("book");
    ok(&book, &["book", "create", "--name", "Extract Co", "--json"]);
    let stream = b"BT /F1 12 Tf (ACME SUPPLIES INC.) Tj T* (TOTAL DUE: 1,234.56 USD) Tj ET";
    let mut pdf = format!(
        "%PDF-1.7\n1 0 obj\n<< /Length {} >>\nstream\n",
        stream.len()
    )
    .into_bytes();
    pdf.extend_from_slice(stream);
    pdf.extend_from_slice(b"\nendstream\nendobj\n%%EOF\n");
    let add = |name: &str, bytes: &[u8], kind: &str, mime: &str| -> String {
        let path = write(&dir, name, bytes);
        let out = ok(
            &book,
            &[
                "document",
                "add",
                &path,
                "--kind",
                kind,
                "--mime",
                mime,
                "--grade",
                "HumanUpload",
                "--json",
            ],
        );
        field(&out, "oid").unwrap().to_string()
    };
    let invoice = add("invoice.pdf", &pdf, "Invoice", "application/pdf");
    let text = "ACME SUPPLIES INC.\\nTOTAL DUE: 1,234.56 USD";

    let extract = ["document", "extract", invoice.as_str(), "--json"];
    let out = ok(&book, &extract);
    assert_eq!(field(&out, "event"), Some("document_extracted"), "{out}");
    assert_eq!(field(&out, "source_oid"), Some(invoice.as_str()), "{out}");
    assert_eq!(field(&out, "kind"), Some("Invoice"), "{out}");
    assert_eq!(field(&out, "grade"), Some("AgentUpload"), "{out}");
    assert_eq!(field(&out, "self_sourced"), Some("true"), "{out}");
    assert_eq!(field(&out, "already_recorded"), Some("false"), "{out}");
    assert_eq!(field(&out, "method"), Some("pdf_text_layer"), "{out}");
    assert_eq!(field(&out, "replayable"), Some("true"), "{out}");
    assert!(
        out.contains(&format!("\"sources\":[\"{invoice}\"]")),
        "{out}"
    );
    assert!(out.contains(text), "{out}");
    let derived = field(&out, "oid").unwrap().to_string();
    assert_ne!(derived, invoice);
    assert!(
        out.contains(&format!("\"source\":\"D:{derived}\"")),
        "the text's handle is the derived document: {out}"
    );

    // Deterministic: the same source again is the recorded document.
    let again = ok(&book, &extract);
    assert_eq!(field(&again, "already_recorded"), Some("true"), "{again}");
    assert_eq!(field(&again, "oid"), Some(derived.as_str()), "{again}");

    // fa document read shows the derived text and its lineage; the source
    // itself is no derivation.
    let read = ok(&book, &["document", "read", &derived, "--json"]);
    assert_eq!(field(&read, "event"), Some("document_read"), "{read}");
    assert!(
        read.contains("\"text\":null"),
        "the envelope is never text: {read}"
    );
    assert_eq!(field(&read, "method"), Some("pdf_text_layer"), "{read}");
    assert!(read.contains(text), "{read}");
    assert!(
        read.contains(&format!("\"sources\":[\"{invoice}\"]")),
        "{read}"
    );
    let source = ok(&book, &["document", "read", &invoice, "--json"]);
    assert!(source.contains("\"extraction\":null"), "{source}");

    // The kind is part of the document's identity.
    let workpaper = ok(
        &book,
        &[
            "document",
            "extract",
            &invoice,
            "--kind",
            "Workpaper",
            "--json",
        ],
    );
    assert_eq!(field(&workpaper, "kind"), Some("Workpaper"), "{workpaper}");
    assert_ne!(
        field(&workpaper, "oid"),
        Some(derived.as_str()),
        "{workpaper}"
    );

    // fa explain evidence names the derivation and its lineage when an entry
    // cites the derived text beside its source; the unreviewed AgentUpload
    // derivation does not count toward the minimum, the invoice does.
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
    let intent = write(
        &dir,
        "rent.json",
        format!(
            r#"{{"idempotency_key":"rent","evidence":["{invoice}",{{"document_oid":"{derived}","role":"Support"}}],{RENT}}}"#
        )
        .as_bytes(),
    );
    let posted = ok(&book, &["post", "--intent", &intent, "--json"]);
    let entry = field(&posted, "vid").unwrap().to_string();
    let explained = ok(&book, &["explain", "evidence", &entry, "--json"]);
    let line = fa_cli::json::parse(explained.trim()).expect("one robot line");
    let documents = line
        .get("data")
        .and_then(|data| data.get("documents"))
        .and_then(fa_cli::json::Json::as_arr)
        .unwrap_or_default();
    let text = |v: &fa_cli::json::Json, key: &str| {
        v.get(key)
            .and_then(fa_cli::json::Json::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let cited = |oid: &str| {
        documents
            .iter()
            .find(|d| text(d, "document_oid") == oid)
            .unwrap_or_else(|| panic!("{oid} is cited: {explained}"))
    };
    let derived_doc = cited(&derived);
    let extraction = derived_doc.get("extraction").expect("extraction");
    assert_eq!(text(extraction, "method"), "pdf_text_layer", "{explained}");
    assert_eq!(
        extraction
            .get("replayable")
            .and_then(fa_cli::json::Json::as_bool),
        Some(true)
    );
    let lineage = derived_doc
        .get("derived_from")
        .and_then(fa_cli::json::Json::as_arr)
        .unwrap_or_default();
    assert_eq!(lineage.len(), 1, "{explained}");
    assert_eq!(text(&lineage[0], "document_oid"), invoice, "{explained}");
    assert_eq!(text(&lineage[0], "grade"), "HumanUpload", "{explained}");
    assert_eq!(
        derived_doc
            .get("counts_toward_minimum")
            .and_then(fa_cli::json::Json::as_bool),
        Some(false),
        "{explained}"
    );
    let source_doc = cited(&invoice);
    assert_eq!(
        source_doc.get("extraction"),
        Some(&fa_cli::json::Json::Null),
        "{explained}"
    );
    assert_eq!(
        source_doc
            .get("derived_from")
            .and_then(fa_cli::json::Json::as_arr)
            .map(<[fa_cli::json::Json]>::len),
        Some(0),
        "{explained}"
    );
    assert_eq!(
        source_doc
            .get("counts_toward_minimum")
            .and_then(fa_cli::json::Json::as_bool),
        Some(true),
        "{explained}"
    );

    // Planted: a source with no PDF text layer is refused, and nothing is
    // recorded; an unknown oid and a missing oid are refused.
    let note = add("note.txt", b"not a pdf", "Other", "text/plain");
    let before = ok(&book, &["document", "list", "--json"]);
    let refusal = refused(
        &book,
        &["document", "extract", &note, "--json"],
        "FA-REF-193",
        3,
    );
    assert!(refusal.contains("invalid_header"), "{refusal}");
    let after = ok(&book, &["document", "list", "--json"]);
    assert_eq!(
        before.matches("\"oid\"").count(),
        after.matches("\"oid\"").count(),
        "a refused extraction records nothing"
    );
    // Derived text is governed as its source is (plan §9.6): a bank
    // statement's text may only be recorded under a kind its redaction
    // contract governs, so `--kind Invoice` is refused with nothing written.
    let statement = add("statement.pdf", &pdf, "BankStatement", "application/pdf");
    let before = ok(&book, &["document", "list", "--json"]);
    let refusal = refused(
        &book,
        &[
            "document",
            "extract",
            &statement,
            "--kind",
            "Invoice",
            "--grant",
            "privileged",
            "--json",
        ],
        "FA-REF-083",
        2,
    );
    assert!(refusal.contains("statement-account-block"), "{refusal}");
    let after = ok(&book, &["document", "list", "--json"]);
    assert_eq!(
        before.matches("\"oid\"").count(),
        after.matches("\"oid\"").count(),
        "a derivation outside its source's contract records nothing"
    );
    let out = ok(
        &book,
        &[
            "document",
            "extract",
            &statement,
            "--grant",
            "privileged",
            "--json",
        ],
    );
    assert_eq!(field(&out, "kind"), Some("BankStatement"), "{out}");
    refused(
        &book,
        &["document", "extract", &"ab".repeat(32), "--json"],
        "FA-REF-081",
        3,
    );
    let (code, out, _) = fa(&book, &["document", "extract", "--json"]);
    assert_eq!(code, 2, "{out}");
    Ok(())
}

/// fa-qip: `fa search` indexes documents beside entries, in one index. A text
/// document is found by its own bytes; a PDF only through the text `fa
/// document extract` derives from it, never its raw bytes (ASCII here, so
/// they would decode). `--kind` keeps one kind of hit. A document recorded
/// after a frontier is not found at it; an unknown kind is usage.
#[test]
fn search_finds_documents_by_their_own_or_extracted_text() -> std::io::Result<()> {
    let dir = tmp("search-docs")?;
    let book = dir.join("book");
    ok(&book, &["book", "create", "--name", "Search Co", "--json"]);
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
    let add = |name: &str, bytes: &[u8], mime: &str| -> String {
        let path = write(&dir, name, bytes);
        let out = ok(
            &book,
            &[
                "document",
                "add",
                &path,
                "--kind",
                "Invoice",
                "--mime",
                mime,
                "--grade",
                "HumanUpload",
                "--json",
            ],
        );
        field(&out, "oid").unwrap().to_string()
    };
    let memo = add(
        "memo.txt",
        b"Harbor Street lease renewal memo",
        "text/plain",
    );
    let intent = write(
        &dir,
        "rent.json",
        br#"{"idempotency_key":"rent","effective_date":"2026-03-10","description":"Office rent for March","legs":[{"side":"debit","account":"6000","amount":"9.00 USD","memo":"Harbor Street lease"},{"side":"credit","account":"1000","amount":"9.00 USD"}]}"#,
    );
    let out = ok(
        &book,
        &["post", "--intent", &intent, "--evidence", &memo, "--json"],
    );
    let rent = field(&out, "vid").unwrap().to_string();
    let search = |args: &[&str]| -> String {
        let mut argv = vec!["search"];
        argv.extend_from_slice(args);
        argv.push("--json");
        let out = ok(&book, &argv);
        assert_eq!(field(&out, "event"), Some("search_results"), "{out}");
        out
    };
    let hit = |out: &str, id: &str| out.contains(&format!("\"id\":\"{id}\""));

    // One query finds the document by its bytes and the entry by its memo;
    // --kind searches one kind only, and `all` is the default's index.
    let both = search(&["harbor"]);
    assert!(hit(&both, &memo) && hit(&both, &rent), "{both}");
    let documents = search(&["harbor", "--kind", "document"]);
    assert!(
        hit(&documents, &memo) && !hit(&documents, &rent),
        "{documents}"
    );
    let entries = search(&["harbor", "--kind", "entry"]);
    assert!(hit(&entries, &rent) && !hit(&entries, &memo), "{entries}");
    assert_eq!(field(&documents, "records"), Some("1"), "{documents}");
    let all = search(&["harbor", "--kind", "all"]);
    assert_eq!(field(&all, "index_digest"), field(&both, "index_digest"));
    assert_eq!(field(&all, "total"), field(&both, "total"), "{all}");
    let frontier = field(&both, "known_at").unwrap().to_string();

    // A PDF's raw bytes are never indexed; the text extracted from it is.
    let stream = b"BT /F1 12 Tf (ACME SUPPLIES INC.) Tj T* (TOTAL DUE: 1,234.56 USD) Tj ET";
    let mut pdf = format!(
        "%PDF-1.7\n1 0 obj\n<< /Length {} >>\nstream\n",
        stream.len()
    )
    .into_bytes();
    pdf.extend_from_slice(stream);
    pdf.extend_from_slice(b"\nendstream\nendobj\n%%EOF\n");
    let invoice = add("invoice.pdf", &pdf, "application/pdf");
    let unextracted = search(&["acme"]);
    assert_eq!(field(&unextracted, "total"), Some("0"), "{unextracted}");
    let out = ok(&book, &["document", "extract", &invoice, "--json"]);
    let derived = field(&out, "oid").unwrap().to_string();
    let found = search(&["acme", "--kind", "document"]);
    assert!(hit(&found, &derived) && !hit(&found, &invoice), "{found}");
    assert!(
        found.contains("[ACME] SUPPLIES"),
        "the snippet is the extracted text: {found}"
    );

    // At the earlier frontier the derived document is not there to be found.
    let early = search(&["acme", "--as-known-at", &frontier]);
    assert_eq!(field(&early, "total"), Some("0"), "{early}");
    let (code, out, _) = fa(&book, &["search", "harbor", "--kind", "invoice", "--json"]);
    assert_eq!(code, 2, "{out}");
    Ok(())
}

/// fa-lzrn (plan §9.1, fa-646's subprocess graders): `fa document extract
/// --tool focr` OCRs an image through the owner's `focr`, resolved in PATH,
/// over a private copy of the source that is removed afterwards. The derived
/// document records `franken_ocr`, the tool's version and `replayable =
/// false`. Planted: with no focr in PATH the tool did not run (exit 4, an
/// environment failure, never invented text); a focr that fails is
/// FA-REF-193; an unknown tool is a usage error naming the three.
#[cfg(unix)]
#[test]
fn extract_runs_the_owner_ocr_tool_and_refuses_when_it_is_absent() -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp("ocr")?;
    let book = dir.join("book");
    ok(&book, &["book", "create", "--name", "Ocr Co", "--json"]);
    let scan = write(
        &dir,
        "receipt.png",
        b"\x89PNG\r\n\x1a\nscanned-receipt-pixels",
    );
    let added = ok(
        &book,
        &[
            "document",
            "add",
            &scan,
            "--kind",
            "Receipt",
            "--mime",
            "image/png",
            "--grade",
            "HumanUpload",
            "--json",
        ],
    );
    let receipt = field(&added, "oid").unwrap().to_string();

    // A stand-in focr: it checks its argv and that it was handed the
    // source's bytes, then prints robot JSON as `focr ocr --json` does.
    let bin = dir.join("bin");
    std::fs::create_dir(&bin)?;
    let fake = |name: &str, body: &str| -> std::io::Result<()> {
        let path = bin.join(name);
        std::fs::write(&path, body)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
    };
    fake(
        "focr",
        "#!/bin/sh\nPATH=/usr/bin:/bin\nif [ \"$1\" = \"--version\" ]; then echo 'focr 0.3.0-test'; exit 0; fi\n[ \"$1\" = ocr ] && [ \"$2\" = --json ] && [ -f \"$3\" ] || exit 9\ngrep -q scanned-receipt-pixels \"$3\" || exit 8\n# printf, not echo: dash's echo would turn the JSON's \\\\n into a newline.\nprintf '%s\\n' '{\"markdown\":\"CORNER CAFE RECEIPT\\nTOTAL 42.00 USD\",\"tool_version\":\"0.3.0-test\"}'\n",
    )?;
    let run = |path: &str, args: &[&str]| -> (i32, String) {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_fa"))
            .arg("--book")
            .arg(&book)
            .args(args)
            .env_remove("FA_BOOK")
            .env("PATH", path)
            .output()
            .expect("run fa");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let reg = registry().expect("verbs.toml");
        for line in stdout.lines() {
            let checked = reg.check_line(line);
            assert!(checked.is_ok(), "args={args:?}: {checked:?}\n{line}");
        }
        (out.status.code().unwrap_or(-1), stdout)
    };
    let with_focr = bin.display().to_string();
    let extract = [
        "document",
        "extract",
        receipt.as_str(),
        "--tool",
        "focr",
        "--json",
    ];
    let (code, out) = run(&with_focr, &extract);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "event"), Some("document_extracted"), "{out}");
    assert_eq!(field(&out, "source_oid"), Some(receipt.as_str()), "{out}");
    assert_eq!(field(&out, "kind"), Some("Receipt"), "{out}");
    assert_eq!(field(&out, "method"), Some("franken_ocr"), "{out}");
    assert_eq!(field(&out, "tool_name"), Some("focr"), "{out}");
    assert_eq!(field(&out, "tool_version"), Some("0.3.0-test"), "{out}");
    assert_eq!(field(&out, "replayable"), Some("false"), "{out}");
    assert!(
        out.contains("CORNER CAFE RECEIPT\\nTOTAL 42.00 USD"),
        "{out}"
    );
    // Provenance names the source by its handle, never the temporary path.
    assert!(
        out.contains(&format!(
            "\"command_line\":[\"focr\",\"ocr\",\"--json\",\"D:{receipt}\"]"
        )),
        "{out}"
    );
    assert!(!out.contains("fa-extract-"), "{out}");
    // The private copy of the source is gone.
    let leftover: Vec<_> = std::fs::read_dir(std::env::temp_dir())?
        .filter_map(Result::ok)
        .filter(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.starts_with("fa-extract-") && name.contains(&receipt)
        })
        .collect();
    assert!(leftover.is_empty(), "{leftover:?}");

    // No focr in PATH: the tool did not run.
    let empty = dir.join("empty");
    std::fs::create_dir(&empty)?;
    let (code, out) = run(&empty.display().to_string(), &extract);
    assert_eq!(code, 4, "{out}");
    assert_eq!(field(&out, "event"), Some("error"), "{out}");
    assert!(out.contains("did not run"), "{out}");
    // A focr that fails is the extraction refusal.
    fake(
        "focr",
        "#!/bin/sh\necho 'focr: unreadable image' >&2\nexit 2\n",
    )?;
    let (code, out) = run(&with_focr, &extract);
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-193"), "{out}");
    // An unknown tool is a usage error.
    let (code, out) = run(
        &with_focr,
        &[
            "document",
            "extract",
            &receipt,
            "--tool",
            "tesseract",
            "--json",
        ],
    );
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("pdf-text"), "{out}");
    Ok(())
}

/// The receiver takes over (plan §15.6, scoreboard WF-TRT-02, fa-k07b): `fa book
/// fork receivership` on the appointing order holds everything recorded
/// through the appointment and opens the estate's branch there; a document
/// recorded after it is not held, and the fork is one per book.
#[test]
fn a_receivership_fork_holds_the_pre_appointment_trunk_and_opens_the_estate_branch()
-> std::io::Result<()> {
    let dir = tmp("receivership")?;
    let book = dir.join("book");
    ok(&book, &["book", "create", "--name", "Estate Co", "--json"]);
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
    let add = |name: &str, bytes: &[u8], kind: &str| -> (String, i64) {
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
        let oid = field(&out, "oid").expect("oid").to_string();
        let at = field(&out, "recorded_at").expect("recorded_at");
        (oid, at.parse().expect("a sequence"))
    };
    let (invoice, _) = add("invoice.txt", b"INVOICE 7001 March rent", "Invoice");
    let rent = write(
        &dir,
        "rent.json",
        format!(r#"{{"idempotency_key":"rent-pre",{RENT}}}"#).as_bytes(),
    );
    ok(
        &book,
        &["post", "--intent", &rent, "--evidence", &invoice, "--json"],
    );
    let (order, appointment) = add(
        "order.txt",
        b"ORDER APPOINTING RECEIVER, Case 26-cv-0042",
        "CourtOrder",
    );

    // Usage: the branch is `receivership`, and it rests on an order.
    let (code, out, _) = fa(&book, &["book", "fork", "receivership", "--json"]);
    assert_eq!(code, 2, "no --authority: {out}");
    assert!(out.contains("--authority"), "{out}");
    let (code, out, _) = fa(
        &book,
        &["book", "fork", "estate", "--authority", &order, "--json"],
    );
    assert_eq!(code, 2, "not a receivership: {out}");
    assert!(out.contains("fa scenario fork"), "{out}");

    // The fork at the head: the hold pins everything through the order's
    // own recording, and the branch forks there on the order.
    let out = ok(
        &book,
        &[
            "book",
            "fork",
            "receivership",
            "--authority",
            &order,
            "--json",
        ],
    );
    eprintln!("k07b receivership: {out}");
    assert_eq!(field(&out, "event"), Some("receivership_forked"), "{out}");
    assert_eq!(
        field(&out, "appointment"),
        Some(appointment.to_string().as_str()),
        "{out}"
    );
    // The envelope's coordinate also names a `branch` (trunk): match the
    // event's own field exactly.
    assert!(out.contains(r#""branch":"receivership""#), "{out}");
    assert_eq!(field(&out, "already_recorded"), Some("false"), "{out}");
    let hold = field(&out, "hold_vid").expect("hold_vid").to_string();
    let out = ok(&book, &["document", "hold", "show", &hold, "--json"]);
    assert_eq!(
        field(&out, "through"),
        Some(appointment.to_string().as_str()),
        "{out}"
    );
    assert_eq!(field(&out, "active"), Some("true"), "{out}");
    for held in [&invoice, &order] {
        let out = ok(
            &book,
            &["document", "hold", "list", "--subject", held, "--json"],
        );
        assert!(out.contains(&hold), "{held} is held: {out}");
    }
    let out = refused(
        &book,
        &["document", "erase", &invoice, "--grant", "erase", "--json"],
        "FA-REF-117",
        7,
    );
    assert!(out.contains(&hold), "{out}");

    // The same fork again is its recorded outcome; another appointment is
    // refused (one receivership per book).
    let out = ok(
        &book,
        &[
            "book",
            "fork",
            "receivership",
            "--authority",
            &order,
            "--json",
        ],
    );
    assert_eq!(field(&out, "already_recorded"), Some("true"), "{out}");
    assert_eq!(field(&out, "hold_vid"), Some(hold.as_str()), "{out}");
    let other = (appointment - 1).to_string();
    let out = refused(
        &book,
        &[
            "book",
            "fork",
            "receivership",
            "--authority",
            &order,
            "--at",
            &other,
            "--json",
        ],
        "FA-REF-032",
        6,
    );
    assert!(out.contains("fa scenario show receivership"), "{out}");

    // After the appointment: the estate posts on its branch, and what trunk
    // records now is not under the hold.
    let estate = write(
        &dir,
        "estate.json",
        format!(r#"{{"idempotency_key":"estate-rent",{RENT}}}"#).as_bytes(),
    );
    let out = ok(
        &book,
        &[
            "post",
            "--intent",
            &estate,
            "--evidence",
            &invoice,
            "--scenario",
            "receivership",
            "--json",
        ],
    );
    assert_eq!(field(&out, "ordinal"), Some("1"), "{out}");
    let out = ok(&book, &["scenario", "show", "receivership", "--json"]);
    assert_eq!(
        field(&out, "fork_at"),
        Some(appointment.to_string().as_str()),
        "{out}"
    );
    assert!(out.contains(&order), "the order is its assumption: {out}");
    let (later, _) = add("later.txt", b"INVOICE 7002 April rent", "Invoice");
    let out = ok(
        &book,
        &["document", "hold", "list", "--subject", &later, "--json"],
    );
    assert!(!out.contains(&hold), "{out}");
    refused(
        &book,
        &["document", "erase", &later, "--grant", "erase", "--json"],
        "FA-REF-088",
        3,
    );

    // A book-scope hold by itself: --through names the sequence, and it
    // cannot also name subjects.
    let out = ok(
        &book,
        &[
            "document",
            "hold",
            "place",
            "--authority",
            &order,
            "--through",
            "HEAD",
            "--json",
        ],
    );
    assert_eq!(field(&out, "event"), Some("legal_hold_placed"), "{out}");
    assert_eq!(field(&out, "subjects"), Some("[]"), "{out}");
    let through: i64 = field(&out, "through")
        .expect("through")
        .parse()
        .expect("a sequence");
    assert!(through > appointment, "{out}");
    let (code, out, _) = fa(
        &book,
        &[
            "document",
            "hold",
            "place",
            "--authority",
            &order,
            "--through",
            "HEAD",
            "--subject",
            &invoice,
            "--json",
        ],
    );
    assert_eq!(code, 2, "{out}");
    refused(
        &book,
        &[
            "document",
            "hold",
            "place",
            "--authority",
            &order,
            "--through",
            "0",
            "--key",
            "zero",
            "--json",
        ],
        "FA-REF-100",
        2,
    );
    Ok(())
}
