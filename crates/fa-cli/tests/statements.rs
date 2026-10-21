//! Financial statements through the real CLI: exact native-unit columns,
//! shared historical coordinates, retained replay, and selector refusals.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};

fn temporary() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let dir = std::env::temp_dir().join(format!(
            "fa-statements-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        match std::fs::create_dir(&dir) {
            Ok(()) => return dir,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create {}: {error}", dir.display()),
        }
    }
}

fn run(book: &Path, args: &[&str]) -> (i32, Vec<Json>, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .output()
        .expect("run fa");
    let text = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    let registry = fa_cli::verbs::registry().expect("verb registry");
    let events = text
        .lines()
        .map(|line| {
            registry
                .check_line(line)
                .unwrap_or_else(|error| panic!("args={args:?}: schema: {error:?}\n{line}"));
            json::parse(line).expect("robot JSON")
        })
        .collect();
    (
        output.status.code().unwrap_or(-1),
        events,
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn ok(book: &Path, args: &[&str]) -> Vec<Json> {
    let (exit, events, stderr) = run(book, args);
    assert_eq!(exit, 0, "args={args:?}\n{events:?}\n{stderr}");
    events
}

fn data(event: &Json) -> &Json {
    event.get("data").expect("data")
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("{key}: {value:?}"))
}

fn array<'a>(value: &'a Json, key: &str) -> &'a [Json] {
    value
        .get(key)
        .and_then(Json::as_arr)
        .unwrap_or_else(|| panic!("{key}: {value:?}"))
}

fn line<'a>(statement: &'a Json, code: &str, unit: &str) -> &'a [Json] {
    let row = array(statement, "lines")
        .iter()
        .find(|row| text(row, "code") == code && text(row, "unit") == unit)
        .unwrap_or_else(|| panic!("missing {code}/{unit}: {statement:?}"));
    array(row, "amounts")
}

struct Fixture {
    dir: PathBuf,
    book: PathBuf,
    evidence: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = temporary();
        let book = dir.join("book");
        ok(&book, &["book", "create", "--name", "Statement fixture"]);
        let chart = dir.join("chart.json");
        std::fs::write(&chart, r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"3000","name":"Capital","type":"Equity","unit":"USD"},{"code":"4000","name":"Sales","type":"Revenue","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"},{"code":"1100","name":"Yen cash","type":"Asset","unit":"JPY"},{"code":"4100","name":"Yen sales","type":"Revenue","unit":"JPY"},{"code":"6100","name":"Yen expense","type":"Expense","unit":"JPY"}]}"#).unwrap();
        ok(&book, &["chart", "import", chart.to_str().unwrap()]);
        ok(&book, &["period", "create", "--fiscal-year", "2026"]);
        for period in ["FY2026-P02", "FY2026-P03"] {
            ok(&book, &["period", "open", period]);
        }
        let source = dir.join("source.txt");
        std::fs::write(&source, b"Statement test source: capital, sales and rent").unwrap();
        let doc = ok(
            &book,
            &[
                "document",
                "add",
                source.to_str().unwrap(),
                "--kind",
                "Invoice",
                "--grade",
                "HumanUpload",
            ],
        );
        let fixture = Self {
            dir,
            book,
            evidence: text(data(&doc[0]), "oid").into(),
        };
        for (key, day, debit, credit, amount) in [
            ("capital", "2026-02-01", "1000", "3000", "200.00 USD"),
            ("feb-sale", "2026-02-10", "1000", "4000", "100.00 USD"),
            ("feb-rent", "2026-02-11", "6000", "1000", "25.00 USD"),
            ("mar-sale", "2026-03-10", "1000", "4000", "90.00 USD"),
            ("mar-rent", "2026-03-11", "6000", "1000", "10.00 USD"),
            ("yen-sale", "2026-03-10", "1100", "4100", "111 JPY"),
            ("yen-expense", "2026-03-11", "6100", "1100", "22 JPY"),
        ] {
            fixture.post(key, day, debit, credit, amount);
        }
        fixture
    }

    fn post(&self, key: &str, day: &str, debit: &str, credit: &str, amount: &str) {
        let path = self.dir.join(format!("{key}.json"));
        std::fs::write(&path, format!(r#"{{"idempotency_key":"{key}","effective_date":"{day}","legs":[{{"side":"debit","account":"{debit}","amount":"{amount}"}},{{"side":"credit","account":"{credit}","amount":"{amount}"}}]}}"#)).unwrap();
        ok(
            &self.book,
            &[
                "post",
                "--intent",
                path.to_str().unwrap(),
                "--evidence",
                &self.evidence,
            ],
        );
    }
}

#[test]
fn statements_carry_opening_history_and_separate_exact_comparative_units() {
    let fixture = Fixture::new();
    let bs = ok(
        &fixture.book,
        &[
            "statement",
            "balance-sheet",
            "--for",
            "FY2026-P03",
            "--compare",
            "FY2026-P02",
        ],
    );
    assert_eq!(text(&bs[0], "event"), "statement");
    let report = data(&bs[0]);
    assert_eq!(
        line(report, "assets", "USD"),
        &[
            Json::Str("355.00 USD".into()),
            Json::Str("275.00 USD".into())
        ]
    );
    assert_eq!(
        line(report, "balance_check", "USD"),
        &[Json::Str("0.00 USD".into()), Json::Str("0.00 USD".into())]
    );
    assert_eq!(
        line(report, "assets", "JPY"),
        &[Json::Str("89 JPY".into()), Json::Str("0 JPY".into())]
    );
    assert_eq!(array(report, "columns").len(), 2);
    assert_eq!(text(&array(report, "columns")[0], "mode"), "stock");
    assert_eq!(array(report, "mappings").len(), 7);

    let income = ok(
        &fixture.book,
        &[
            "statement",
            "income-statement",
            "--for",
            "FY2026-P03",
            "--compare",
            "FY2026-P02",
        ],
    );
    let report = data(&income[0]);
    assert_eq!(
        line(report, "net_income", "USD"),
        &[Json::Str("80.00 USD".into()), Json::Str("75.00 USD".into())]
    );
    assert_eq!(
        line(report, "net_income", "JPY"),
        &[Json::Str("89 JPY".into()), Json::Str("0 JPY".into())]
    );
    assert_eq!(text(&array(report, "columns")[0], "mode"), "activity");
    assert_eq!(array(report, "mappings").len(), 4);
    assert_eq!(bs[0].get("certificate"), Some(&Json::Null));
    assert_eq!(income[0].get("certificate"), Some(&Json::Null));
}

#[test]
fn retained_statement_replay_preserves_both_columns_after_later_postings() {
    let fixture = Fixture::new();
    let original = ok(
        &fixture.book,
        &[
            "statement",
            "income-statement",
            "--for",
            "FY2026-P03",
            "--compare",
            "FY2026-P02",
            "--certify",
        ],
    );
    assert_eq!(original.len(), 2);
    assert_eq!(text(&original[1], "event"), "report_certificate");
    let oid = text(data(&original[1]), "oid");
    let replay = ok(&fixture.book, &["replay", &format!("C:{oid}")]);
    assert_eq!(
        original[0], replay[0],
        "same original and replay robot envelope"
    );
    fixture.post("later-sale", "2026-03-20", "1000", "4000", "20.00 USD");
    assert_eq!(
        ok(&fixture.book, &["replay", &format!("C:{oid}")])[0],
        original[0]
    );
    let now = ok(
        &fixture.book,
        &[
            "statement",
            "income-statement",
            "--for",
            "FY2026-P03",
            "--compare",
            "FY2026-P02",
        ],
    );
    assert_eq!(
        line(data(&now[0]), "net_income", "USD"),
        &[
            Json::Str("100.00 USD".into()),
            Json::Str("75.00 USD".into())
        ]
    );
    let known_at = data(&original[0]).get("known_at").unwrap().render();
    let historical = ok(
        &fixture.book,
        &[
            "statement",
            "income-statement",
            "--for",
            "FY2026-P03",
            "--compare",
            "FY2026-P02",
            "--known-at",
            &known_at,
        ],
    );
    assert_eq!(data(&historical[0]), data(&original[0]));
    let alias = ok(
        &fixture.book,
        &[
            "statement",
            "income-statement",
            "--for",
            "FY2026-P03",
            "--compare",
            "FY2026-P02",
            "--as-known-at",
            &known_at,
        ],
    );
    assert_eq!(historical, alias);
}

#[test]
fn statement_selectors_are_explicit_and_output_files_are_never_replaced() {
    let fixture = Fixture::new();
    for args in [
        vec!["statement", "balance-sheet"],
        vec!["statement", "cash-flow", "--for", "FY2026-P03"],
        vec![
            "statement",
            "balance-sheet",
            "--for",
            "FY2026-P03",
            "--for",
            "FY2026-P02",
        ],
        vec![
            "statement",
            "balance-sheet",
            "--for",
            "FY2026-P03",
            "--known-at",
            "HEAD",
            "--as-known-at",
            "HEAD",
        ],
        vec![
            "statement",
            "balance-sheet",
            "--for",
            "FY2026-P03",
            "--known-at",
            "18446744073709551616",
        ],
    ] {
        let (exit, events, _) = run(&fixture.book, &args);
        assert_eq!(exit, 2, "{args:?}: {events:?}");
        assert_eq!(events.len(), 1);
        assert_eq!(text(&events[0], "event"), "error");
    }
    let path = fixture.dir.join("statement.cert");
    let args = [
        "statement",
        "balance-sheet",
        "--for",
        "FY2026-P03",
        "--certificate-out",
        path.to_str().unwrap(),
    ];
    let certified = ok(&fixture.book, &args);
    assert_eq!(certified.len(), 2);
    let bytes = std::fs::read(&path).unwrap();
    let (exit, events, _) = run(&fixture.book, &args);
    assert_ne!(exit, 0);
    assert!(events.iter().all(|event| text(event, "event") == "error"));
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert_eq!(
        ok(&fixture.book, &["replay", path.to_str().unwrap()])[0],
        certified[0]
    );
}

#[test]
fn certified_comparisons_and_traces_retain_the_complete_family_across_processes() {
    let fixture = Fixture::new();
    let snapshot = ok(
        &fixture.book,
        &["statement", "income-statement", "--for", "FY2026-P03"],
    );
    let before = data(&snapshot[0]).get("known_at").unwrap().render();
    fixture.post("bridge-sale", "2026-03-14", "1000", "4000", "17.00 USD");
    let snapshot = ok(
        &fixture.book,
        &["statement", "income-statement", "--for", "FY2026-P03"],
    );
    let after = data(&snapshot[0]).get("known_at").unwrap().render();
    let mut originals = Vec::new();
    for mode in ["diff", "trace"] {
        let path = fixture.dir.join(format!("{mode}.cert"));
        let args = [
            "statement",
            mode,
            "--definition",
            "income-statement",
            "--for",
            "FY2026-P03",
            "--before",
            &before,
            "--after",
            &after,
            "--certify",
            "--certificate-out",
            path.to_str().unwrap(),
        ];
        let original = ok(&fixture.book, &args);
        assert_eq!(original.len(), 2, "{mode}: {original:?}");
        assert_eq!(text(&original[0], "event"), format!("statement_{mode}"));
        assert_eq!(text(&original[1], "event"), "report_certificate");
        let oid = text(data(&original[1]), "oid").to_string();
        assert_eq!(text(&original[0], "certificate"), oid);
        let bytes = std::fs::read(&path).unwrap();
        let artifact = fa::ReportArtifact::decode(&bytes).unwrap();
        assert_eq!(artifact.family().name(), format!("statement-{mode}"));
        assert_eq!(artifact.known_at().0.to_string(), after);
        let handle = format!("C:{oid}");
        assert_eq!(
            ok(&fixture.book, &["replay", &handle]),
            vec![original[0].clone()],
        );
        assert_eq!(
            ok(&fixture.book, &["replay", path.to_str().unwrap()]),
            vec![original[0].clone()],
        );
        let output_path = fixture.dir.join(format!("{mode}.report"));
        let replay = ok(
            &fixture.book,
            &["replay", &handle, "--output", output_path.to_str().unwrap()],
        );
        assert_eq!(replay.len(), 2);
        assert_eq!(replay[0], original[0]);
        assert_eq!(text(&replay[1], "event"), "report_replayed");
        assert_eq!(text(data(&replay[1]), "family"), artifact.family().name());
        assert_eq!(std::fs::read(&output_path).unwrap(), artifact.output());
        assert_eq!(
            data(&replay[1]).get("output_bytes"),
            Some(&Json::Int(artifact.output().len() as i128)),
        );
        assert_eq!(
            data(&replay[1]).get("output_digest"),
            data(&original[1]).get("output_digest"),
        );
        // Fixed endpoints produce the same certificate after retention
        // advances the metadata frontier. Exact retry publishes nothing.
        let retry = ok(
            &fixture.book,
            &[
                "statement",
                mode,
                "--definition",
                "income-statement",
                "--for",
                "FY2026-P03",
                "--before",
                &before,
                "--after",
                &after,
                "--certify",
            ],
        );
        assert_eq!(text(data(&retry[1]), "oid"), oid);
        assert_eq!(
            data(&retry[1]).get("recorded_at"),
            data(&original[1]).get("recorded_at"),
        );
        let status = ok(&fixture.book, &["certificate", "status", &handle]);
        assert_eq!(text(data(&status[0]), "status"), "Current");
        assert_eq!(text(data(&status[0]), "oid"), oid);
        assert_eq!(data(&status[0]).get("known_at").unwrap().render(), after);

        // Forge the derived output and recompute its unsigned content hash.
        // The container still decodes, so refusal must come from full source
        // replay and reconstruction of the bridge or publication attribution.
        let mut forged = bytes.clone();
        let body_end = forged.len() - 32;
        forged[body_end - 1] ^= 1;
        let domain: &[u8] = if mode == "diff" {
            b"fa:statement-diff-certificate-digest:v1"
        } else {
            b"fa:statement-trace-certificate-digest:v1"
        };
        let digest = fa_model::domain_digest(domain, &[&forged[..body_end]]);
        forged[body_end..].copy_from_slice(&digest);
        fa::ReportArtifact::decode(&forged)
            .expect("an intact unsigned container is not a replay proof");
        let forged_path = fixture.dir.join(format!("{mode}-forged.cert"));
        std::fs::write(&forged_path, forged).unwrap();
        let refused_output = fixture.dir.join(format!("{mode}-must-not-exist.report"));
        for command in [
            vec![
                "replay",
                forged_path.to_str().unwrap(),
                "--output",
                refused_output.to_str().unwrap(),
            ],
            vec!["certificate", "status", forged_path.to_str().unwrap()],
        ] {
            let (exit, events, _) = run(&fixture.book, &command);
            assert_eq!(exit, 8, "{command:?}: {events:?}");
            assert_eq!(events.len(), 1);
            assert_eq!(text(&events[0], "event"), "error");
            assert!(!refused_output.exists());
        }
        let (exit, events, _) = run(
            &fixture.book,
            &["replay", &handle, "--output", output_path.to_str().unwrap()],
        );
        assert_eq!(exit, 2);
        assert_eq!(events.len(), 1);
        assert_eq!(text(&events[0], "event"), "error");
        assert_eq!(std::fs::read(output_path).unwrap(), artifact.output());
        originals.push((handle, original[0].clone()));
    }
    // A late February entry does not affect this March activity selector.
    // A backdated March entry does, without changing the historical bytes.
    fixture.post(
        "unrelated-late-sale",
        "2026-02-14",
        "1000",
        "4000",
        "23.00 USD",
    );
    for (handle, _) in &originals {
        let status = ok(&fixture.book, &["certificate", "status", handle]);
        assert_eq!(text(data(&status[0]), "status"), "Current");
    }
    fixture.post("backdated-sale", "2026-03-12", "1000", "4000", "29.00 USD");
    for (handle, original) in &originals {
        let status = ok(&fixture.book, &["certificate", "status", handle]);
        assert_eq!(text(data(&status[0]), "status"), "SupersededBy");
        assert!(!array(data(&status[0]), "later_entries").is_empty());
        assert_eq!(
            ok(&fixture.book, &["replay", handle]),
            vec![original.clone()],
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn retained_statement_certificates_bridge_and_trace_without_reselecting_head() {
    let fixture = Fixture::new();
    let income = ["statement", "income-statement", "--for", "FY2026-P03"];
    let head = || {
        data(&ok(&fixture.book, &income)[0])
            .get("known_at")
            .unwrap()
            .render()
    };
    let first = ok(&fixture.book, &[&income[..], &["--certify"][..]].concat());
    let before_oid = text(data(&first[1]), "oid").to_string();
    let before = data(&first[0]).get("known_at").unwrap().render();
    fixture.post("bridge-sale", "2026-03-14", "1000", "4000", "17.00 USD");
    let after_path = fixture.dir.join("after.cert");
    let second = ok(
        &fixture.book,
        &[
            &income[..],
            &[
                "--certify",
                "--certificate-out",
                after_path.to_str().unwrap(),
            ][..],
        ]
        .concat(),
    );
    let after_oid = text(data(&second[1]), "oid").to_string();
    let after = data(&second[0]).get("known_at").unwrap().render();
    let balance = ok(
        &fixture.book,
        &[
            "statement",
            "balance-sheet",
            "--for",
            "FY2026-P03",
            "--certify",
        ],
    );
    let balance_oid = format!("C:{}", text(data(&balance[1]), "oid"));
    // The certificates fix the frontiers, so a later HEAD cannot leak in.
    fixture.post("later-sale", "2026-03-20", "1000", "4000", "20.00 USD");
    let (b, a) = (format!("C:{before_oid}"), format!("C:{after_oid}"));
    let sequence = |mode: &str| {
        ok(
            &fixture.book,
            &[
                "statement",
                mode,
                "--definition",
                "income-statement",
                "--for",
                "FY2026-P03",
                "--before",
                &before,
                "--after",
                &after,
            ],
        )
    };
    let by_sequence = sequence("diff");
    let at = head();
    let bridged = ok(
        &fixture.book,
        &[
            "statement",
            "diff",
            "--before-certificate",
            &b,
            "--after-certificate",
            &a,
        ],
    );
    assert_eq!(bridged, by_sequence);
    assert_eq!(bridged[0].get("certificate"), Some(&Json::Null));
    assert_eq!(
        data(&bridged[0]).get("after_known_at").unwrap().render(),
        after
    );
    // A bare digest and the saved file name the same certificates.
    assert_eq!(
        ok(
            &fixture.book,
            &[
                "statement",
                "diff",
                "--before-certificate",
                &before_oid,
                "--after-certificate",
                after_path.to_str().unwrap(),
            ],
        ),
        by_sequence
    );
    // Stating the statement one means is checked against the certificates.
    assert_eq!(
        ok(
            &fixture.book,
            &[
                "statement",
                "diff",
                "--before-certificate",
                &b,
                "--after-certificate",
                &a,
                "--for",
                "FY2026-P03",
                "--definition",
                "income-statement",
            ],
        ),
        by_sequence
    );
    assert_eq!(head(), at, "an uncertified bridge writes nothing");

    let certified = ok(
        &fixture.book,
        &[
            "statement",
            "diff",
            "--before-certificate",
            &b,
            "--after-certificate",
            &a,
            "--certify",
        ],
    );
    assert_eq!(certified.len(), 2);
    assert_eq!(data(&certified[0]), data(&by_sequence[0]));
    let diff_oid = text(data(&certified[1]), "oid").to_string();
    assert_eq!(text(&certified[0], "certificate"), diff_oid);
    let comparison =
        fa::StatementDiffCertificate::decode(&unhex(text(data(&certified[1]), "bytes"))).unwrap();
    let (old, new) = comparison.sources();
    assert_eq!(hex(&old.digest), before_oid);
    assert_eq!(hex(&new.digest), after_oid);
    assert_eq!(
        new.canonical_bytes().unwrap(),
        std::fs::read(&after_path).unwrap(),
        "the comparison keeps the exact retained source, not a re-certification"
    );
    let diff_handle = format!("C:{diff_oid}");
    assert_eq!(
        ok(&fixture.book, &["replay", &diff_handle]),
        vec![certified[0].clone()]
    );

    let trace = ok(
        &fixture.book,
        &[
            "statement",
            "trace",
            "--from-diff",
            &diff_handle,
            "--for",
            "FY2026-P03",
            "--certify",
        ],
    );
    assert_eq!(trace.len(), 2);
    assert_eq!(text(&trace[0], "event"), "statement_trace");
    assert_eq!(data(&trace[0]), data(&sequence("trace")[0]));
    let attributed =
        fa::StatementTraceCertificate::decode(&unhex(text(data(&trace[1]), "bytes"))).unwrap();
    let sources = attributed.sources();
    assert_eq!(hex(&sources.first().unwrap().digest), before_oid);
    assert_eq!(hex(&sources.last().unwrap().digest), after_oid);
    let trace_handle = format!("C:{}", text(data(&trace[1]), "oid"));
    assert_eq!(
        ok(&fixture.book, &["replay", &trace_handle]),
        vec![trace[0].clone()]
    );

    // The comparison and its trace export the library's own workpapers, to a
    // new file or inline, and exporting is a read.
    let at = head();
    let diff_path = fixture.dir.join("bridge.jsonl");
    let trace_path = fixture.dir.join("trace.jsonl");
    for (handle, path, family) in [
        (&diff_handle, &diff_path, "statement-diff"),
        (&trace_handle, &trace_path, "statement-trace"),
    ] {
        let events = ok(
            &fixture.book,
            &["replay", handle, "--workpaper-out", path.to_str().unwrap()],
        );
        let exported = events.last().unwrap();
        assert_eq!(text(exported, "event"), "workpaper_exported");
        assert_eq!(text(data(exported), "family"), family);
        let written = std::fs::read_to_string(path).unwrap();
        assert!(written.lines().count() > 1, "{family}: {written}");
        let inline = ok(&fixture.book, &["replay", handle, "--workpaper"]);
        assert_eq!(
            text(data(inline.last().unwrap()), "text"),
            written,
            "{family}: the inline text is the file's text"
        );
    }
    {
        let keys = fa::BookKeys::load(&fixture.book.join("book.keys")).unwrap();
        let book =
            fa::Book::open_dir(&fixture.book, keys, fa::Entropy::deterministic(119)).unwrap();
        let reviewer = fa_model::principal_vid("statement-reviewer");
        let capability = fa::Capability::embedded(reviewer, &["read", "produce"]).unwrap();
        let package = book
            .statement_diff_workpaper(reviewer, &capability, &comparison)
            .unwrap()
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&diff_path).unwrap(),
            package.jsonl()
        );
        let trace_jsonl = book
            .statement_trace_jsonl(reviewer, &capability, &attributed)
            .unwrap()
            .unwrap();
        assert_eq!(std::fs::read_to_string(&trace_path).unwrap(), trace_jsonl);
    }
    assert_eq!(head(), at, "workpaper exports publish nothing");
    let refused = fixture.dir.join("bridge-again.jsonl");
    std::fs::copy(&diff_path, &refused).unwrap();
    let (exit, _, _) = run(
        &fixture.book,
        &[
            "replay",
            &diff_handle,
            "--workpaper-out",
            refused.to_str().unwrap(),
        ],
    );
    assert_eq!(exit, 2, "an existing workpaper file is never replaced");

    let at = head();
    for (args, exit, needle) in [
        (
            vec!["diff", "--before-certificate", &b],
            2,
            "needs both --before-certificate and --after-certificate",
        ),
        (
            vec![
                "diff",
                "--before-certificate",
                &b,
                "--after-certificate",
                &a,
                "--before",
                "1",
            ],
            2,
            "--before selects a frontier",
        ),
        (
            vec![
                "diff",
                "--before-certificate",
                &b,
                "--after-certificate",
                &a,
                "--branch",
                "scenario:what-if",
            ],
            2,
            "--branch selects a frontier",
        ),
        (
            vec![
                "diff",
                "--before-certificate",
                &b,
                "--after-certificate",
                &a,
                "--compare",
                "FY2026-P02",
            ],
            2,
            "--compare names the comparative column",
        ),
        (
            vec![
                "diff",
                "--before-certificate",
                &b,
                "--after-certificate",
                &a,
                "--for",
                "FY2026-P02",
            ],
            8,
            "the certificates answer income-statement for FY2026-P03 with no comparative",
        ),
        (
            vec![
                "diff",
                "--before-certificate",
                &b,
                "--after-certificate",
                &a,
                "--for",
                "FY2026-P03",
                "--compare",
                "FY2026-P02",
            ],
            8,
            "not the statement --for/--compare/--definition name",
        ),
        (
            vec![
                "diff",
                "--before-certificate",
                &b,
                "--after-certificate",
                &a,
                "--definition",
                "balance-sheet",
            ],
            8,
            "the certificates answer income-statement",
        ),
        (
            vec![
                "trace",
                "--from-diff",
                &diff_handle,
                "--for",
                "FY2026-P02",
                "--certify",
            ],
            8,
            "the certificates answer income-statement for FY2026-P03",
        ),
        (
            vec![
                "diff",
                "--before-certificate",
                &b,
                "--after-certificate",
                &a,
                "--max-publications",
                "2",
            ],
            2,
            "start a statement trace",
        ),
        (
            vec!["income-statement", "--before-certificate", &b],
            2,
            "not statement income-statement",
        ),
        (
            vec!["trace", "--from-diff", &diff_handle],
            2,
            "add --certify",
        ),
        (
            vec![
                "trace",
                "--from-diff",
                &diff_handle,
                "--before-certificate",
                &b,
                "--certify",
            ],
            2,
            "one saved comparison",
        ),
        (
            vec![
                "diff",
                "--before-certificate",
                &a,
                "--after-certificate",
                &b,
            ],
            8,
            "ordered frontiers",
        ),
        (
            vec![
                "diff",
                "--before-certificate",
                &balance_oid,
                "--after-certificate",
                &a,
            ],
            8,
            "same sequence-selected trunk statement",
        ),
        (
            vec![
                "diff",
                "--before-certificate",
                &diff_handle,
                "--after-certificate",
                &a,
            ],
            8,
            "--before-certificate",
        ),
        (
            vec!["trace", "--from-diff", &a, "--certify"],
            8,
            "--from-diff",
        ),
    ] {
        let args = [&["statement"][..], &args[..]].concat();
        let (code, events, _) = run(&fixture.book, &args);
        assert_eq!(code, exit, "{args:?}: {events:?}");
        assert_eq!(events.len(), 1, "{args:?}: {events:?}");
        assert_eq!(text(&events[0], "event"), "error");
        assert!(events[0].render().contains(needle), "{args:?}: {events:?}");
    }
    assert_eq!(head(), at, "refusals publish nothing");

    // A launch-bound reader bridges retained certificates by digest, but
    // cannot name a host file for one or certify without produce.
    let authority = fa_cli::authority::LaunchAuthority::new(
        fixture.book.clone(),
        None,
        "report-reader",
        fa_cli::authority::LaunchProfile::Agent,
        &["read"],
    )
    .unwrap();
    let bound = |args: &[&str]| {
        let argv: Vec<String> = args
            .iter()
            .chain(&["--json"])
            .map(|arg| (*arg).to_string())
            .collect();
        fa_cli::entry::fa_with_authority(&argv, fa_cli::cli::Files::default(), &authority, true)
    };
    let pair = [
        "statement",
        "diff",
        "--before-certificate",
        &b,
        "--after-certificate",
        &a,
    ];
    let (code, captured) = bound(&pair);
    assert_eq!(code, 0, "{}{}", captured.stdout, captured.stderr);
    let event = json::parse(captured.stdout.lines().next().unwrap()).unwrap();
    assert_eq!(data(&event), data(&by_sequence[0]));
    let (code, captured) = bound(&[
        "statement",
        "diff",
        "--before-certificate",
        &b,
        "--after-certificate",
        after_path.to_str().unwrap(),
    ]);
    assert_eq!(code, 2, "{}{}", captured.stdout, captured.stderr);
    assert!(
        captured
            .stdout
            .contains("--after-certificate cannot name a host filesystem path"),
        "{}",
        captured.stdout
    );
    let (code, captured) = bound(&[&pair[..], &["--certify"][..]].concat());
    assert_eq!(code, 7, "{}{}", captured.stdout, captured.stderr);
    assert!(captured.stdout.contains("produce"), "{}", captured.stdout);
    assert_eq!(head(), at);
}

#[test]
fn comparison_scope_and_certification_authority_are_never_silently_ignored() {
    let fixture = Fixture::new();
    for extra in [
        vec!["--known-at", "HEAD"],
        vec!["--as-known-at", "HEAD"],
        vec!["--max-publications", "1"],
    ] {
        let mut args = vec![
            "statement",
            "diff",
            "--definition",
            "income-statement",
            "--for",
            "FY2026-P03",
            "--before",
            "1",
        ];
        args.extend(extra);
        let (exit, events, _) = run(&fixture.book, &args);
        assert_eq!(exit, 2, "{args:?}: {events:?}");
        assert_eq!(events.len(), 1);
        assert_eq!(text(&events[0], "event"), "error");
    }
    let authority = fa_cli::authority::LaunchAuthority::new(
        fixture.book.clone(),
        None,
        "report-reader",
        fa_cli::authority::LaunchProfile::Agent,
        &["read"],
    )
    .unwrap();
    let args = [
        "statement",
        "diff",
        "--definition",
        "income-statement",
        "--for",
        "FY2026-P03",
        "--before",
        "1",
        "--certify",
        "--json",
    ]
    .map(String::from);
    let (exit, captured) =
        fa_cli::entry::fa_with_authority(&args, fa_cli::cli::Files::default(), &authority, true);
    assert_eq!(exit, 7, "{}{}", captured.stdout, captured.stderr);
    let events: Vec<_> = captured
        .stdout
        .lines()
        .map(|line| json::parse(line).unwrap())
        .collect();
    assert_eq!(events.len(), 1);
    assert_eq!(text(&events[0], "event"), "error");
    assert!(captured.stdout.contains("produce"));
}

#[test]
fn generic_aging_artifacts_replay_by_digest_and_export_through_the_held_dispatcher() {
    let fixture = Fixture::new();
    let keys = fa::BookKeys::load(&fixture.book.join("book.keys")).unwrap();
    let mut book =
        fa::Book::open_dir(&fixture.book, keys.clone(), fa::Entropy::deterministic(117)).unwrap();
    let principal = fa_model::principal_vid("aging-producer");
    let capability = fa::Capability::embedded(principal, &["read", "produce"]).unwrap();
    let certified = book
        .certify_effective_date_aging(
            principal,
            &capability,
            &fa::AgingRequest {
                account: None,
                effective_through: fa_time::DateDay::parse("2026-03-31").unwrap(),
                known_at: None,
                buckets: fa::AgingBuckets::thirty_day(),
            },
        )
        .unwrap()
        .unwrap();
    let artifact = fa::ReportArtifact::try_from(&certified.certificate).unwrap();
    let bytes = artifact.canonical_bytes().unwrap();
    let retained = book
        .retain_report_artifact(principal, &capability, &bytes, Some(artifact.digest()))
        .unwrap()
        .unwrap();
    assert_eq!(&retained.digest, artifact.digest());
    let handle = format!(
        "C:{}",
        artifact
            .digest()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    );
    drop(book);
    let output = fixture.dir.join("aging.report");
    let replay = ok(
        &fixture.book,
        &["replay", &handle, "--output", output.to_str().unwrap()],
    );
    assert_eq!(replay.len(), 2);
    assert_eq!(text(&replay[0], "event"), "aging");
    assert_eq!(text(&replay[1], "event"), "report_replayed");
    assert_eq!(text(data(&replay[1]), "family"), "effective-date-aging");
    assert_eq!(std::fs::read(output).unwrap(), artifact.output());
    // Aging has a freshness law (9f30e90): nothing in its selector was
    // recorded after the certificate, so the retained artifact is Current.
    let (exit, events, _) = run(&fixture.book, &["certificate", "status", &handle]);
    assert_eq!(exit, 0, "{events:?}");
    assert_eq!(events.len(), 1);
    assert_eq!(text(&events[0], "event"), "certificate_status");
    assert_eq!(text(data(&events[0]), "status"), "Current");
    assert_eq!(
        data(&events[0]).get("later_entries"),
        Some(&Json::Arr(Vec::new()))
    );

    let mut book =
        fa::Book::open_dir(&fixture.book, keys, fa::Entropy::deterministic(118)).unwrap();
    let original_head = book.head().unwrap();
    let args = ["replay".to_string(), handle.clone(), "--json".into()];
    let (exit, captured) = fa_cli::cli::run_for_daemon(
        &args,
        &mut book,
        fixture.book.clone(),
        None,
        None,
        fa_cli::cli::Stdin::Missing,
        true,
    );
    assert_eq!(exit, 0, "{}{}", captured.stdout, captured.stderr);
    let events: Vec<_> = captured
        .stdout
        .lines()
        .map(|line| {
            fa_cli::verbs::registry().unwrap().check_line(line).unwrap();
            json::parse(line).unwrap()
        })
        .collect();
    assert_eq!(events.len(), 2);
    assert_eq!(text(&events[0], "event"), "aging");
    assert_eq!(data(&events[0]), data(&replay[0]));
    assert_eq!(text(data(&events[1]), "family"), "effective-date-aging");
    assert_eq!(
        data(&events[1]).get("output_digest"),
        data(&replay[1]).get("output_digest")
    );
    assert_eq!(book.head().unwrap(), original_head);

    // The new output flag follows the same daemon file-containment admission
    // as every other output path, before the replay handler can create a file.
    let escaped = fixture.dir.join("daemon-must-not-create.report");
    let args = [
        "replay".to_string(),
        handle,
        "--output".into(),
        escaped.to_str().unwrap().into(),
        "--json".into(),
    ];
    let (exit, captured) = fa_cli::cli::run_for_daemon(
        &args,
        &mut book,
        fixture.book.clone(),
        None,
        None,
        fa_cli::cli::Stdin::Missing,
        true,
    );
    assert_eq!(exit, 2, "{}{}", captured.stdout, captured.stderr);
    assert_eq!(captured.stdout.lines().count(), 1);
    assert!(!escaped.exists());
    assert_eq!(book.head().unwrap(), original_head);
}

/// `fa statement lint` (plan §12.1, FA-INV-04): a definition partitions the
/// chart a statement folds, or names the leaves it does not. The built-in
/// balance sheet maps whole account types; the small-company preset maps code
/// prefixes, so a liability numbered in the cash range is mapped twice.
#[test]
fn statement_lint_reports_the_mapping_partition_of_the_chart() {
    let f = Fixture::new();
    let lint = |book: &Path, args: &[&str]| -> Json {
        let mut argv = vec!["statement", "lint"];
        argv.extend_from_slice(args);
        let events = ok(book, &argv);
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(text(&events[0], "event"), "statement_lint");
        data(&events[0]).clone()
    };
    let strings = |value: &Json, key: &str| -> Vec<String> {
        array(value, key)
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    };
    let int = |value: &Json, key: &str| match value.get(key) {
        Some(Json::Int(n)) => *n,
        other => panic!("{key}: {other:?}"),
    };

    let builtin = lint(&f.book, &["--definition", "balance-sheet"]);
    assert_eq!(builtin.get("clean"), Some(&Json::Bool(true)));
    assert_eq!(
        (
            int(&builtin, "covered_leaves"),
            int(&builtin, "mapped_leaves")
        ),
        (7, 7)
    );
    assert!(
        array(&builtin, "mappings")
            .iter()
            .any(|m| text(m, "account") == "1000" && text(m, "line") == "assets")
    );

    let preset = lint(
        &f.book,
        &["--definition", "us_gaap_small_company_balance_sheet"],
    );
    assert_eq!(preset.get("clean"), Some(&Json::Bool(true)));
    assert_eq!(int(&preset, "mapped_leaves"), 7);
    assert_eq!(
        strings(&preset, "empty_lines"),
        [
            "inventory",
            "ppe_net",
            "accounts_payable",
            "accrued_liabilities",
            "long_term_debt"
        ]
    );

    // A book whose chart numbers a liability in the cash range.
    let dir = temporary();
    let book = dir.join("book");
    ok(&book, &["book", "create", "--name", "Lint fixture"]);
    let created = ok(&book, &["book", "info"]);
    let before_chart = int(created[0].get("coordinate").unwrap(), "known_at").to_string();
    let chart = dir.join("chart.json");
    std::fs::write(&chart, r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"1050","name":"Customer deposits","type":"Liability","unit":"USD"},{"code":"3000","name":"Capital","type":"Equity","unit":"USD"}]}"#).unwrap();
    ok(&book, &["chart", "import", chart.to_str().unwrap()]);
    let found = lint(
        &book,
        &["--definition", "us_gaap_small_company_balance_sheet"],
    );
    assert_eq!(found.get("clean"), Some(&Json::Bool(false)));
    let overlaps = array(&found, "multiply_mapped_leaves");
    assert_eq!(overlaps.len(), 1, "{found:?}");
    assert_eq!(text(&overlaps[0], "account"), "1050");
    assert_eq!(strings(&overlaps[0], "lines"), ["cash", "long_term_debt"]);
    assert_eq!(int(&found, "mapped_leaves"), 2);
    // The built-in definition still partitions this chart by type.
    let typed = lint(&book, &["--definition", "balance-sheet"]);
    assert_eq!(typed.get("clean"), Some(&Json::Bool(true)));
    // Before the chart existed, nothing was covered.
    let empty = lint(
        &book,
        &[
            "--definition",
            "us_gaap_small_company_balance_sheet",
            "--as-known-at",
            &before_chart,
        ],
    );
    assert_eq!(int(&empty, "covered_leaves"), 0);
    assert_eq!(empty.get("clean"), Some(&Json::Bool(true)));

    // An unknown definition is refused; report flags are usage errors.
    let (exit, events, _) = run(&book, &["statement", "lint", "--definition", "cash-flow"]);
    assert_eq!(exit, 3, "{events:?}");
    assert!(text(data(&events[0]), "message").contains("us_gaap_small_company_balance_sheet"));
    let (exit, _, _) = run(
        &book,
        &[
            "statement",
            "lint",
            "--definition",
            "balance-sheet",
            "--for",
            "FY2026-P03",
        ],
    );
    assert_eq!(exit, 2);
    let (exit, _, _) = run(&book, &["statement", "lint"]);
    assert_eq!(exit, 2);
}

/// Plan §12.1 presentation rounding on the CLI: `--present-in units` adds a
/// statement_presented event after the exact statement. Unclosed revenue
/// 190.60 USD and expenses 35.40 USD present as 191 and 35 (HalfEven), while
/// their difference, 155.20 USD, presents as 155: an explicit -1
/// Presentation rounding line sits right before unclosed earnings, so the
/// presented column foots. Under Floor the parts sum to the total and no
/// residual line appears. JPY (scale 0) presents unchanged.
#[test]
fn statement_presented_in_units_foots_with_an_explicit_residual_line() {
    let f = Fixture::new();
    f.post("cents-sale", "2026-03-12", "1000", "4000", "0.60 USD");
    f.post("cents-rent", "2026-03-13", "6000", "1000", "0.40 USD");
    let present = |extra: &[&str]| -> (Json, Json) {
        let mut argv = vec!["statement", "balance-sheet", "--for", "FY2026-P03"];
        argv.extend_from_slice(extra);
        let events = ok(&f.book, &argv);
        let names: Vec<&str> = events.iter().map(|e| text(e, "event")).collect();
        assert_eq!(names, ["statement", "statement_presented"], "{events:?}");
        (events[0].clone(), data(&events[1]).clone())
    };
    let block = |presented: &Json, unit: &str| -> Json {
        array(presented, "units")
            .iter()
            .find(|u| text(u, "unit") == unit)
            .unwrap_or_else(|| panic!("no {unit} block"))
            .clone()
    };
    let ints = |line: &Json| -> Vec<i128> {
        array(line, "presented")
            .iter()
            .map(|v| match v {
                Json::Int(n) => *n,
                other => panic!("{other:?}"),
            })
            .collect()
    };
    let int = |value: &Json, key: &str| match value.get(key) {
        Some(Json::Int(n)) => *n,
        other => panic!("{key}: {other:?}"),
    };

    let (exact, presented) = present(&["--present-in", "units"]);
    assert_eq!(text(&presented, "present_in"), "units");
    assert_eq!(text(&presented, "rounding_law"), "HalfEven");
    assert_eq!(text(&presented, "definition"), "balance-sheet");
    let usd = block(&presented, "USD");
    assert_eq!(int(&usd, "divisor"), 100);
    let lines = array(&usd, "lines");
    let at = |code: &str| {
        lines
            .iter()
            .position(|l| text(l, "code") == code)
            .unwrap_or_else(|| panic!("no line {code}"))
    };
    let revenue = &lines[at("unclosed_revenue")];
    let expense = &lines[at("unclosed_expense")];
    let earnings = at("unclosed_earnings");
    let residual = at("unclosed_earnings_presentation_rounding");
    assert_eq!(ints(revenue), [191]);
    assert_eq!(ints(expense), [35]);
    assert_eq!(ints(&lines[earnings]), [155]);
    assert_eq!(
        residual + 1,
        earnings,
        "the residual line precedes its total"
    );
    assert_eq!(lines[residual].get("residual"), Some(&Json::Bool(true)));
    assert_eq!(ints(&lines[residual]), [-1]);
    assert_eq!(
        ints(revenue)[0] - ints(expense)[0] + ints(&lines[residual])[0],
        ints(&lines[earnings])[0],
        "the presented column foots"
    );
    assert_eq!(
        array(revenue, "rounding_error")[0].as_str(),
        Some("0.40 USD"),
        "191 presented against 190.60 exact"
    );
    assert!(
        lines
            .iter()
            .filter(|l| l.get("residual") == Some(&Json::Bool(true)))
            .count()
            == 1,
        "only the one total whose parts disagree gets a residual line"
    );
    let jpy = block(&presented, "JPY");
    assert_eq!(int(&jpy, "divisor"), 1);
    assert!(
        array(&jpy, "lines")
            .iter()
            .all(|l| l.get("residual") == Some(&Json::Bool(false)))
    );
    // The exact statement is the same with or without the presentation.
    let plain = ok(
        &f.book,
        &["statement", "balance-sheet", "--for", "FY2026-P03"],
    );
    assert_eq!(plain.len(), 1, "no presentation unless asked: {plain:?}");
    assert_eq!(data(&plain[0]), data(&exact));

    // Floor presents 190 and 35, whose difference is the presented 155.
    let (_, floor) = present(&["--present-in", "units", "--rounding", "Floor"]);
    assert_eq!(text(&floor, "rounding_law"), "Floor");
    assert!(
        array(&block(&floor, "USD"), "lines")
            .iter()
            .all(|l| l.get("residual") == Some(&Json::Bool(false)))
    );

    // Planted refusals publish nothing: usage, exit 2.
    for planted in [
        vec!["--rounding", "Floor"],
        vec!["--present-in", "dozens"],
        vec!["--present-in", "units", "--rounding", "Sideways"],
        vec!["--present-in", "units", "--render", "md"],
    ] {
        let mut argv = vec!["statement", "balance-sheet", "--for", "FY2026-P03"];
        argv.extend_from_slice(&planted);
        let (code, events, _) = run(&f.book, &argv);
        assert_eq!(code, 2, "{planted:?}: {events:?}");
        assert_eq!(events.len(), 1, "{planted:?}: {events:?}");
        assert_eq!(text(&events[0], "event"), "error");
    }
}
