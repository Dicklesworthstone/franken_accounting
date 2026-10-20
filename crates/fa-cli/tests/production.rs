//! Real-binary litigation productions (fa-6l9, plan §13.2): journaled Bates
//! numbering per matter, the volume a production writes (Concordance DAT,
//! Opticon OPT, natives), redacted listings for governed sources, exact
//! re-runs, and refusals that journal nothing and create no directory.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};

fn data(value: &Json) -> &Json {
    value.get("data").expect("robot data")
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value.get(key).and_then(Json::as_str).expect(key)
}

fn rows<'a>(value: &'a Json, key: &str) -> &'a [Json] {
    value
        .get(key)
        .and_then(|v| match v {
            Json::Arr(rows) => Some(rows.as_slice()),
            _ => None,
        })
        .expect(key)
}

fn flag(value: &Json, key: &str) -> bool {
    matches!(value.get(key), Some(Json::Bool(true)))
}

fn run(book: &Path, args: &[&str]) -> (i32, Json) {
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .output()
        .expect("run fa");
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{args:?}: {stdout}\n{stderr}");
    let checked = fa_cli::verbs::registry()
        .expect("registry")
        .check_line(lines[0]);
    assert!(checked.is_ok(), "{args:?}: {checked:?}\n{stdout}\n{stderr}");
    (
        output.status.code().expect("exit code"),
        json::parse(lines[0]).expect("robot line"),
    )
}

fn ok(book: &Path, args: &[&str]) -> Json {
    let (status, output) = run(book, args);
    assert_eq!(status, 0, "{args:?}: {}", output.render());
    output
}

fn refused(book: &Path, args: &[&str], exit: i32, id: &str) -> Json {
    let (status, output) = run(book, args);
    assert_eq!(status, exit, "{args:?}: {}", output.render());
    assert_eq!(text(data(&output), "refusal_id"), id, "{}", output.render());
    output
}

fn head(book: &Path) -> String {
    ok(book, &["book", "info"])
        .get("coordinate")
        .and_then(|c| c.get("known_at"))
        .map(Json::render)
        .expect("known_at")
}

struct Fixture {
    dir: PathBuf,
    book: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = loop {
            let dir = std::env::temp_dir().join(format!(
                "fa-production-cli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&dir) {
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                created => {
                    created.expect("create the fixture directory");
                    break dir;
                }
            }
        };
        let book = dir.join("book");
        ok(&book, &["book", "create", "--name", "Production"]);
        Self { dir, book }
    }

    fn path(&self, name: &str) -> String {
        self.dir.join(name).display().to_string()
    }

    fn document(&self, name: &str, body: &str, kind: &str) -> String {
        let mime = if name.ends_with(".csv") {
            "text/csv"
        } else {
            "text/plain"
        };
        let path = self.dir.join(name);
        std::fs::write(&path, body).expect("write source");
        let added = ok(
            &self.book,
            &[
                "document",
                "add",
                path.to_str().expect("utf-8 path"),
                "--kind",
                kind,
                "--mime",
                mime,
                "--grade",
                "HumanUpload",
            ],
        );
        text(data(&added), "oid").to_string()
    }
}

/// `(document, beg, end, assigned)` per produced range.
fn spans(output: &Json) -> Vec<(String, String, String, bool)> {
    rows(data(output), "ranges")
        .iter()
        .map(|r| {
            (
                text(r, "document").to_string(),
                text(r, "beg_bates").to_string(),
                text(r, "end_bates").to_string(),
                flag(r, "assigned"),
            )
        })
        .collect()
}

#[test]
fn a_production_journals_continuing_bates_numbers_and_writes_its_volume() {
    let f = Fixture::new();
    let invoice = f.document("invoice.txt", "INVOICE 1001 for Acme", "Invoice");
    let contract = f.document("contract.txt", "MASTER SERVICES AGREEMENT", "Invoice");
    let order = f.document("order.txt", "STIPULATED PROTECTIVE ORDER", "Invoice");
    let opened = ok(
        &f.book,
        &[
            "production",
            "open",
            "SEC-v-Acme",
            "--bates-prefix",
            "ACME-SEC",
            "--protective-order",
            &order,
        ],
    );
    assert_eq!(text(&opened, "event"), "production_opened");
    let summary = data(&opened).get("production").expect("summary");
    assert_eq!(text(summary, "protective_order"), order);
    assert_eq!(text(summary, "load_file"), "dat");

    let out = f.path("vol-1");
    let first = ok(
        &f.book,
        &[
            "produce",
            "--matter",
            "SEC-v-Acme",
            "--document",
            &format!("{invoice}:3:confidential"),
            "--document",
            &contract,
            "--out",
            &out,
        ],
    );
    assert_eq!(text(&first, "event"), "production_recorded");
    assert_eq!(
        spans(&first),
        vec![
            (
                invoice.clone(),
                "ACME-SEC-00000001".into(),
                "ACME-SEC-00000003".into(),
                true
            ),
            (
                contract.clone(),
                "ACME-SEC-00000004".into(),
                "ACME-SEC-00000004".into(),
                true
            ),
        ]
    );
    assert_eq!(text(data(&first), "next_bates"), "ACME-SEC-00000005");
    let dat = std::fs::read_to_string(format!("{out}/VOL001.dat")).expect("dat");
    assert!(dat.contains("ACME-SEC-00000001"), "{dat}");
    assert!(dat.contains("CONFIDENTIAL"), "{dat}");
    assert!(dat.contains(&invoice), "{dat}");
    let opt = std::fs::read_to_string(format!("{out}/VOL001.opt")).expect("opt");
    assert!(opt.contains("ACME-SEC-00000004"), "{opt}");
    assert_eq!(
        std::fs::read(format!("{out}/NATIVES/ACME-SEC-00000001.txt")).expect("native"),
        b"INVOICE 1001 for Acme"
    );
    let files: Vec<&str> = rows(data(&first), "files")
        .iter()
        .map(|f| text(f, "name"))
        .collect();
    assert_eq!(
        files,
        vec![
            "VOL001.dat",
            "VOL001.opt",
            "PRIVILEGE_LOG.md",
            "NATIVES/ACME-SEC-00000001.txt",
            "NATIVES/ACME-SEC-00000004.txt"
        ]
    );

    // The identical command is the recorded production: same numbers, same
    // volume bytes, nothing journaled.
    let before = head(&f.book);
    let again_out = f.path("vol-1-again");
    let again = ok(
        &f.book,
        &[
            "produce",
            "--matter",
            "SEC-v-Acme",
            "--document",
            &format!("{invoice}:3:confidential"),
            "--document",
            &contract,
            "--out",
            &again_out,
        ],
    );
    assert!(flag(data(&again), "already_recorded"));
    assert_eq!(spans(&again), spans(&first));
    assert_eq!(
        std::fs::read(format!("{again_out}/VOL001.dat")).expect("dat"),
        dat.as_bytes()
    );
    assert_eq!(head(&f.book), before);

    // A new document continues the numbering; the produced one keeps its range.
    let later = f.document("later.txt", "LATER EMAIL", "Invoice");
    let second = ok(
        &f.book,
        &[
            "produce",
            "--matter",
            "SEC-v-Acme",
            "--document",
            &contract,
            "--document",
            &format!("{later}:2"),
            "--out",
            &f.path("vol-2"),
            "--volume",
            "VOL002",
        ],
    );
    assert_eq!(
        spans(&second),
        vec![
            (
                contract.clone(),
                "ACME-SEC-00000004".into(),
                "ACME-SEC-00000004".into(),
                false
            ),
            (
                later.clone(),
                "ACME-SEC-00000005".into(),
                "ACME-SEC-00000006".into(),
                true
            ),
        ]
    );
    assert!(Path::new(&f.path("vol-2")).join("VOL002.opt").exists());

    // A second matter numbers the same document from its own start.
    ok(
        &f.book,
        &[
            "production",
            "open",
            "Doe-v-Acme",
            "--bates-prefix",
            "DOE",
            "--start",
            "500",
        ],
    );
    let doe = ok(
        &f.book,
        &[
            "produce",
            "--matter",
            "Doe-v-Acme",
            "--document",
            &format!("{invoice}::aeo"),
            "--out",
            &f.path("doe-1"),
        ],
    );
    assert_eq!(
        spans(&doe),
        vec![(
            invoice.clone(),
            "DOE-00000500".into(),
            "DOE-00000500".into(),
            true
        )]
    );

    let shown = ok(&f.book, &["production", "show", "SEC-v-Acme"]);
    let listed: Vec<(&str, &str)> = rows(data(&shown), "ranges")
        .iter()
        .map(|r| (text(r, "beg_bates"), text(r, "designation")))
        .collect();
    assert_eq!(
        listed,
        vec![
            ("ACME-SEC-00000001", "confidential"),
            ("ACME-SEC-00000004", "none"),
            ("ACME-SEC-00000005", "none"),
        ]
    );
    let all = ok(&f.book, &["production", "list"]);
    let matters: Vec<&str> = rows(data(&all), "productions")
        .iter()
        .map(|p| text(p, "matter"))
        .collect();
    assert_eq!(matters, vec!["SEC-v-Acme", "Doe-v-Acme"]);
    let ranges = ok(&f.book, &["production", "document", &invoice]);
    let per_matter: Vec<(&str, &str)> = rows(data(&ranges), "ranges")
        .iter()
        .map(|r| (text(r, "matter"), text(r, "beg_bates")))
        .collect();
    assert_eq!(
        per_matter,
        vec![
            ("Doe-v-Acme", "DOE-00000500"),
            ("SEC-v-Acme", "ACME-SEC-00000001")
        ]
    );
    let none = ok(&f.book, &["production", "document", &order]);
    assert!(rows(data(&none), "ranges").is_empty());
}

#[test]
fn a_governed_source_is_listed_redacted_unless_the_producer_reveals_it() {
    let f = Fixture::new();
    let statement = f.document(
        "statement.csv",
        "date,amount,reference\n2026-03-02,100.00,BANK-123\n",
        "BankStatement",
    );
    ok(
        &f.book,
        &["production", "open", "M-1", "--bates-prefix", "M1"],
    );
    // Without a derived view the document cannot be delivered to this
    // reader: refused before any number is journaled.
    let before = head(&f.book);
    let early = f.path("no-view");
    refused(
        &f.book,
        &[
            "produce",
            "--matter",
            "M-1",
            "--document",
            &statement,
            "--out",
            &early,
        ],
        3,
        "FA-REF-142",
    );
    assert_eq!(head(&f.book), before);
    assert!(!Path::new(&early).exists());
    let shown = ok(&f.book, &["production", "show", "M-1"]);
    assert!(rows(data(&shown), "ranges").is_empty());

    ok(
        &f.book,
        &["document", "redact", &statement, "--grant", "privileged"],
    );
    let out = f.path("redacted");
    let produced = ok(
        &f.book,
        &[
            "produce",
            "--matter",
            "M-1",
            "--document",
            &statement,
            "--out",
            &out,
        ],
    );
    let range = &rows(data(&produced), "ranges")[0];
    assert!(flag(range, "redacted"), "{}", produced.render());
    assert_eq!(range.get("native"), Some(&Json::Null));
    assert!(!Path::new(&out).join("NATIVES").exists());
    let dat = std::fs::read_to_string(format!("{out}/VOL001.dat")).expect("dat");
    assert!(dat.contains("statement-account-block"), "{dat}");
    assert!(!dat.contains("BANK-123"), "{dat}");
    // The redaction is logged; no claim states its date, so none is shown.
    let logged = rows(data(&produced), "privilege_log");
    assert_eq!(logged.len(), 1, "{}", produced.render());
    assert_eq!(logged[0].get("date"), Some(&Json::Null));
    assert_eq!(text(&logged[0], "bates"), "M1-00000001..=M1-00000001");
    assert!(text(&logged[0], "treatment").starts_with("REDACTED_IN_PART(contract=1"));
    let log = std::fs::read_to_string(format!("{out}/PRIVILEGE_LOG.md")).expect("log");
    assert!(log.contains("| UNSPECIFIED |"), "{log}");
    assert!(!log.contains("1970-01-01"), "{log}");

    // The owner who holds privileged produces the same range with its native.
    let revealed_out = f.path("revealed");
    let revealed = ok(
        &f.book,
        &[
            "produce",
            "--matter",
            "M-1",
            "--document",
            &statement,
            "--out",
            &revealed_out,
            "--grant",
            "privileged",
        ],
    );
    // The identical request is the recorded production, rendered for a
    // reader who sees the bytes: the same range, now with its native.
    assert!(flag(data(&revealed), "already_recorded"));
    let range = &rows(data(&revealed), "ranges")[0];
    assert!(!flag(range, "redacted"));
    assert_eq!(text(range, "beg_bates"), "M1-00000001");
    assert!(
        std::fs::read_to_string(format!("{revealed_out}/{}", text(range, "native")))
            .expect("native")
            .contains("BANK-123")
    );
}

#[test]
fn refused_productions_journal_nothing_and_create_no_volume() {
    let f = Fixture::new();
    let invoice = f.document("invoice.txt", "INVOICE", "Invoice");
    ok(
        &f.book,
        &["production", "open", "M-1", "--bates-prefix", "M1"],
    );
    ok(
        &f.book,
        &[
            "produce",
            "--matter",
            "M-1",
            "--document",
            &format!("{invoice}:2"),
            "--out",
            &f.path("v1"),
        ],
    );
    let before = head(&f.book);

    // An existing directory is refused before anything is journaled.
    let taken = f.path("taken");
    std::fs::create_dir(&taken).expect("taken dir");
    let later = f.document("later.txt", "LATER", "Invoice");
    let before_later = head(&f.book);
    let (status, output) = run(
        &f.book,
        &[
            "produce",
            "--matter",
            "M-1",
            "--document",
            &later,
            "--out",
            &taken,
        ],
    );
    assert_eq!(status, 2, "{}", output.render());
    assert_eq!(head(&f.book), before_later);
    let shown = ok(&f.book, &["production", "show", "M-1"]);
    assert_eq!(rows(data(&shown), "ranges").len(), 1);

    let cases: Vec<(Vec<String>, i32, &str)> = vec![
        (
            vec![
                "produce".into(),
                "--matter".into(),
                "M-9".into(),
                "--document".into(),
                invoice.clone(),
                "--out".into(),
                f.path("x1"),
            ],
            3,
            "FA-REF-170",
        ),
        (
            vec![
                "produce".into(),
                "--matter".into(),
                "M-1".into(),
                "--document".into(),
                format!("{invoice}:5"),
                "--out".into(),
                f.path("x2"),
            ],
            3,
            "FA-REF-171",
        ),
        (
            vec![
                "produce".into(),
                "--matter".into(),
                "M-1".into(),
                "--document".into(),
                format!("{invoice}::aeo"),
                "--out".into(),
                f.path("x3"),
            ],
            3,
            "FA-REF-171",
        ),
        (
            vec![
                "produce".into(),
                "--matter".into(),
                "M-1".into(),
                "--document".into(),
                "ab".repeat(32),
                "--out".into(),
                f.path("x4"),
            ],
            3,
            "FA-REF-081",
        ),
        (
            vec![
                "production".into(),
                "open".into(),
                "M-1".into(),
                "--bates-prefix".into(),
                "OTHER".into(),
            ],
            6,
            "FA-REF-032",
        ),
        (
            vec!["production".into(), "show".into(), "M-9".into()],
            3,
            "FA-REF-170",
        ),
    ];
    for (args, exit, id) in &cases {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        refused(&f.book, &args, *exit, id);
    }
    for path in ["x1", "x2", "x3", "x4"] {
        assert!(!Path::new(&f.path(path)).exists(), "{path}");
    }
    for args in [
        vec![
            "production",
            "open",
            "M-2",
            "--bates-prefix",
            "M2",
            "--load-file",
            "edrm",
        ],
        vec!["production", "open", "M-2", "--bates-prefix", "M 2"],
        vec![
            "produce",
            "--matter",
            "M-1",
            "--document",
            "nope",
            "--out",
            "unused",
        ],
    ] {
        let (status, output) = run(&f.book, &args);
        assert_eq!(status, 2, "{args:?}: {}", output.render());
    }
    assert_eq!(head(&f.book), before_later);
    assert_ne!(before, before_later, "the later document was recorded");
}

#[test]
fn withheld_documents_and_claims_fill_the_privilege_log_and_are_checked_before_journaling() {
    let f = Fixture::new();
    let invoice = f.document("invoice.txt", "INVOICE 7", "Invoice");
    let memo = f.document("memo.txt", "PRIVILEGED LEGAL MEMO", "Invoice");
    let statement = f.document(
        "statement.csv",
        "date,amount,reference\n2026-03-02,100.00,BANK-9\n",
        "BankStatement",
    );
    ok(
        &f.book,
        &["document", "redact", &statement, "--grant", "privileged"],
    );
    ok(
        &f.book,
        &["production", "open", "M-1", "--bates-prefix", "M1"],
    );
    let claims = f.dir.join("claims.json");
    std::fs::write(
        &claims,
        format!(
            r#"[{{"document": "{memo}", "date": "2026-02-01", "author": "Outside Counsel", "recipients": ["CFO", "GC"], "description": "Legal advice on the March accrual", "basis": "Attorney-client privilege"}},
{{"document": "{statement}", "date": "2026-03-05", "author": "First Bank", "description": "Account statement", "basis": "Account numbers redacted under the protective order"}}]"#
        ),
    )
    .expect("claims");
    let claims = claims.display().to_string();
    let out = f.path("vol");
    let produced = ok(
        &f.book,
        &[
            "produce",
            "--matter",
            "M-1",
            "--document",
            &invoice,
            "--document",
            &statement,
            "--withhold",
            &memo,
            "--privilege",
            &claims,
            "--out",
            &out,
        ],
    );
    // The withheld memo is numbered by no range and never produced.
    assert_eq!(
        spans(&produced),
        vec![
            (
                invoice.clone(),
                "M1-00000001".into(),
                "M1-00000001".into(),
                true
            ),
            (
                statement.clone(),
                "M1-00000002".into(),
                "M1-00000002".into(),
                true
            ),
        ]
    );
    let logged = rows(data(&produced), "privilege_log");
    assert_eq!(logged.len(), 2, "{}", produced.render());
    let row = |oid: &str| {
        logged
            .iter()
            .find(|r| text(r, "document") == oid)
            .expect("a privilege row for the document")
    };
    assert_eq!(row(&memo).get("bates"), Some(&Json::Null));
    assert_eq!(text(row(&memo), "treatment"), "WITHHELD_IN_FULL");
    assert_eq!(text(row(&memo), "date"), "2026-02-01");
    assert_eq!(text(row(&statement), "bates"), "M1-00000002..=M1-00000002");
    assert!(text(row(&statement), "treatment").starts_with("REDACTED_IN_PART(contract=1"));
    assert_eq!(text(row(&statement), "author"), "First Bank");
    let log = std::fs::read_to_string(format!("{out}/PRIVILEGE_LOG.md")).expect("log");
    assert!(log.contains("| WITHHELD |"), "{log}");
    assert!(log.contains("Attorney-client privilege"), "{log}");
    assert!(log.contains("CFO; GC"), "{log}");
    assert!(log.contains("2026-03-05"), "{log}");
    let dat = std::fs::read_to_string(format!("{out}/VOL001.dat")).expect("dat");
    assert!(
        !dat.contains(&memo),
        "a withheld document is not in the load file"
    );
    let natives: Vec<String> = std::fs::read_dir(Path::new(&out).join("NATIVES"))
        .expect("natives")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        natives,
        vec!["M1-00000001.txt".to_string()],
        "only the invoice ships bytes"
    );

    // Every bad claim is refused before anything is journaled.
    let before = head(&f.book);
    let unclaimed = f.dir.join("unclaimed.json");
    std::fs::write(&unclaimed, "[]").expect("empty claims");
    let full = f.dir.join("full.json");
    std::fs::write(
        &full,
        format!(
            r#"[{{"document": "{invoice}", "date": "2026-02-01", "author": "A", "description": "D", "basis": "B"}}]"#
        ),
    )
    .expect("claim on a full document");
    let typo = f.dir.join("typo.json");
    std::fs::write(
        &typo,
        format!(
            r#"[{{"document": "{memo}", "date": "2026-02-01", "author": "A", "descripton": "D", "basis": "B"}}]"#
        ),
    )
    .expect("typo claim");
    let later = f.document("later.txt", "LATER", "Invoice");
    let before_later = head(&f.book);
    assert_ne!(before, before_later);
    let refusals: Vec<(Vec<String>, i32)> = vec![
        // withheld without a claim
        (
            vec![
                "--withhold".into(),
                memo.clone(),
                "--privilege".into(),
                unclaimed.display().to_string(),
            ],
            2,
        ),
        // a claim on a document produced in full
        (vec!["--privilege".into(), full.display().to_string()], 2),
        // produced and withheld at once
        (
            vec![
                "--withhold".into(),
                later.clone(),
                "--privilege".into(),
                claims.clone(),
            ],
            2,
        ),
        // an unknown field
        (
            vec![
                "--withhold".into(),
                memo.clone(),
                "--privilege".into(),
                typo.display().to_string(),
            ],
            2,
        ),
    ];
    for (i, (extra, exit)) in refusals.into_iter().enumerate() {
        let out = f.path(&format!("refused-{i}"));
        let mut args = vec![
            "produce".to_string(),
            "--matter".into(),
            "M-1".into(),
            "--document".into(),
            later.clone(),
            "--out".into(),
            out.clone(),
        ];
        args.extend(extra);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let (status, output) = run(&f.book, &args);
        assert_eq!(status, exit, "case {i}: {}", output.render());
        assert!(!Path::new(&out).exists(), "case {i}");
    }
    refused(
        &f.book,
        &[
            "produce",
            "--matter",
            "M-1",
            "--document",
            &later,
            "--withhold",
            &"cd".repeat(32),
            "--privilege",
            &claims,
            "--out",
            &f.path("refused-unknown"),
        ],
        3,
        "FA-REF-081",
    );
    assert_eq!(
        head(&f.book),
        before_later,
        "no refused production journaled"
    );
    let shown = ok(&f.book, &["production", "show", "M-1"]);
    assert_eq!(rows(data(&shown), "ranges").len(), 2);
}
