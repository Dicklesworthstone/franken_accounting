//! fa-cet: `fa tb` and `fa statement` render their report as a document
//! with `--render md|html|svg|pdf|pdfa`. Markdown carries no date and
//! always renders; HTML, SVG and PDF are dated by the latest corroborated
//! TimeEvidence tick known at the report's frontier (never the wall clock),
//! so the same report renders to the same bytes whenever it is rendered, and
//! a frontier with no such tick refuses before anything is written.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};

/// 2026-03-15T12:00:00Z and ten seconds later, as nanoseconds.
const FIRST_NS: u64 = 1_773_576_000_000_000_000;
const LATEST_NS: u64 = 1_773_576_010_000_000_000;

fn temporary() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "fa-rendered-reports-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create {}: {error}", path.display()),
        }
    }
}

fn run(book: &Path, args: &[&str]) -> (i32, Vec<Json>) {
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .output()
        .expect("run fa");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let registry = fa_cli::verbs::registry().unwrap();
    let events = stdout
        .lines()
        .map(|line| {
            registry
                .check_line(line)
                .unwrap_or_else(|error| panic!("robot schema: {error}\n{line}"));
            json::parse(line).unwrap()
        })
        .collect();
    (output.status.code().unwrap_or(-1), events)
}

fn ok(book: &Path, args: &[&str]) -> Vec<Json> {
    let (exit, events) = run(book, args);
    assert_eq!(exit, 0, "args={args:?}\n{events:?}");
    events
}

/// Refused with `exit`, as one error event.
fn refused(book: &Path, args: &[&str], exit: i32) -> Json {
    let (code, events) = run(book, args);
    assert_eq!(code, exit, "args={args:?}\n{events:?}");
    assert_eq!(events.len(), 1, "args={args:?}\n{events:?}");
    assert_eq!(text(&events[0], "event"), "error", "{events:?}");
    events.into_iter().next().unwrap()
}

fn data(value: &Json) -> &Json {
    value.get("data").expect("data")
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("{key}: {value:?}"))
}

fn number(value: &Json, key: &str) -> i128 {
    match value.get(key) {
        Some(Json::Int(number)) => *number,
        _ => panic!("{key}: {value:?}"),
    }
}

fn head(book: &Path) -> i128 {
    number(
        ok(book, &["book", "info"])[0].get("coordinate").unwrap(),
        "known_at",
    )
}

/// The `rendered` event that follows a report.
fn rendered(events: &[Json]) -> &Json {
    let last = events.last().expect("events");
    assert_eq!(text(last, "event"), "rendered", "{events:?}");
    data(last)
}

/// A book with Cash, Capital and Sales, March open, one capital receipt
/// and one sale.
fn book(dir: &Path) -> PathBuf {
    let book = dir.join("book");
    ok(&book, &["book", "create", "--name", "Rendered reports"]);
    let chart = dir.join("chart.json");
    std::fs::write(
        &chart,
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"3000","name":"Capital","type":"Equity","unit":"USD"},{"code":"4000","name":"Sales","type":"Revenue","unit":"USD"}]}"#,
    )
    .unwrap();
    ok(&book, &["chart", "import", chart.to_str().unwrap()]);
    ok(&book, &["period", "create", "--fiscal-year", "2026"]);
    ok(&book, &["period", "open", "FY2026-P03"]);
    let source = dir.join("source.txt");
    std::fs::write(&source, b"Capital and sales evidence").unwrap();
    let document = ok(
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
    let evidence = text(data(&document[0]), "oid").to_string();
    for (key, credit, amount) in [("capital", "3000", "100.00"), ("sale", "4000", "25.50")] {
        let intent = dir.join(format!("{key}.json"));
        std::fs::write(
            &intent,
            format!(
                r#"{{"idempotency_key":"{key}","effective_date":"2026-03-10","legs":[{{"side":"debit","account":"1000","amount":"{amount} USD"}},{{"side":"credit","account":"{credit}","amount":"{amount} USD"}}]}}"#
            ),
        )
        .unwrap();
        ok(
            &book,
            &[
                "post",
                "--intent",
                intent.to_str().unwrap(),
                "--evidence",
                &evidence,
            ],
        );
    }
    book
}

/// Journal two corroborated TimeEvidence ticks through the library, as
/// fad's timed work would.
fn record_ticks(book: &Path) {
    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;

    let keys = fa::BookKeys::load(&book.join("book.keys")).unwrap();
    let mut opened = fa::Book::open_dir(book, keys, fa::Entropy::deterministic(170)).unwrap();
    let runtime = RuntimeBuilder::new().build().unwrap();
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    let witness =
        fa::Capability::embedded(fa_model::principal_vid("time-witness"), &["witness"]).unwrap();
    for ns in [FIRST_NS, LATEST_NS] {
        runtime
            .block_on(opened.record_tick(&cx, ns, true, &witness))
            .unwrap()
            .unwrap();
    }
}

#[test]
fn markdown_renders_inline_without_a_tick_and_dated_formats_wait_for_one() {
    let dir = temporary();
    let book = book(&dir);
    let tb = ["tb", "--period", "FY2026-P03"];

    // Markdown carries no date: it renders on a book with no clock tick,
    // inline after the report, and the same report renders the same way.
    let mut md = tb.to_vec();
    md.extend(["--render", "md"]);
    let first = ok(&book, &md);
    assert_eq!(first.len(), 2, "{first:?}");
    assert_eq!(text(&first[0], "event"), "trial_balance");
    let document = rendered(&first);
    assert_eq!(text(document, "format"), "md");
    let markdown = text(document, "markdown");
    for expected in ["1000", "Cash", "100.00", "25.50", "3000", "4000"] {
        assert!(markdown.contains(expected), "{expected}: {markdown}");
    }
    for key in ["out", "created", "tick", "pdfa_valid"] {
        assert_eq!(document.get(key), Some(&Json::Null), "{key}: {document:?}");
    }
    let again = ok(&book, &md);
    for key in ["ir_digest", "digest", "markdown"] {
        assert_eq!(text(document, key), text(rendered(&again), key), "{key}");
    }

    // Markdown to a new file: the file holds exactly the inline text, and an
    // existing file is never overwritten.
    let md_file = dir.join("tb.md");
    let mut to_file = md.clone();
    to_file.extend(["--out", md_file.to_str().unwrap()]);
    let written = ok(&book, &to_file);
    assert_eq!(
        std::fs::read_to_string(&md_file).unwrap(),
        markdown,
        "the file is the rendered Markdown"
    );
    assert_eq!(rendered(&written).get("markdown"), Some(&Json::Null));
    assert_eq!(text(rendered(&written), "out"), md_file.to_str().unwrap());
    refused(&book, &to_file, 2);

    // A dated format needs a corroborated tick known at the report's
    // frontier. None is retained, so the read is refused before anything
    // is written, a certified read retains no certificate, and no file
    // appears.
    let pdf = dir.join("tb.pdf");
    let before = head(&book);
    for certify in [false, true] {
        let mut dated = tb.to_vec();
        dated.extend(["--render", "pdf", "--out", pdf.to_str().unwrap()]);
        if certify {
            dated.push("--certify");
        }
        let error = refused(&book, &dated, 4);
        assert!(
            text(data(&error), "message").contains("corroborated clock tick"),
            "{error:?}"
        );
        assert!(!pdf.exists());
        assert_eq!(head(&book), before, "nothing is retained");
    }

    // Requests that cannot render are usage errors, before the book is read.
    let out = dir.join("never.pdf");
    let out = out.to_str().unwrap();
    for bad in [
        vec!["tb", "--period", "FY2026-P03", "--render", "pdf"],
        vec!["tb", "--period", "FY2026-P03", "--out", out],
        vec!["tb", "--period", "FY2026-P03", "--render", "docx"],
        vec![
            "tb",
            "--period",
            "FY2026-P03",
            "--summary",
            "--render",
            "md",
        ],
        vec!["statement", "issuances", "--render", "md"],
        vec![
            "statement",
            "diff",
            "--definition",
            "balance-sheet",
            "--for",
            "FY2026-P03",
            "--before",
            "1",
            "--render",
            "md",
        ],
    ] {
        refused(&book, &bad, 2);
    }
    assert!(!Path::new(out).exists());
}

#[test]
fn dated_documents_are_dated_by_the_tick_known_at_their_frontier_and_render_identically() {
    let dir = temporary();
    let book = book(&dir);
    let untimed = head(&book).to_string();
    record_ticks(&book);
    let tb = ["tb", "--period", "FY2026-P03"];
    let render = |format: &str, name: &str, extra: &[&str]| -> (Json, Vec<u8>) {
        let path = dir.join(name);
        let mut args = tb.to_vec();
        args.extend(extra);
        args.extend(["--render", format, "--out", path.to_str().unwrap()]);
        let events = ok(&book, &args);
        let document = rendered(&events).clone();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(number(&document, "bytes"), bytes.len() as i128);
        assert_eq!(
            text(&document, "digest"),
            fa_model::domain_digest(b"fa:rendering-file:v1", &[&bytes])
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "the event's digest commits the file"
        );
        (document, bytes)
    };

    // Dated by the latest corroborated tick, not by when it was rendered:
    // the same report renders to the same bytes twice.
    let (pdf, first) = render("pdf", "a.pdf", &[]);
    assert!(first.starts_with(b"%PDF-"));
    assert!(String::from_utf8_lossy(&first).contains("FrankenAccounting Statement"));
    assert!(
        !String::from_utf8_lossy(&first).contains("Certified Statement"),
        "ordinary rendering does not itself issue an accounting certificate"
    );
    assert_eq!(text(&pdf, "created"), "2026-03-15T12:00:10Z");
    assert_eq!(text(&pdf, "tick").len(), 32);
    assert_eq!(pdf.get("pdfa_valid"), Some(&Json::Null));
    let (_, second) = render("pdf", "b.pdf", &[]);
    assert_eq!(first, second, "identical report, identical document");

    // PDF/A-2b passes its validator before it is written.
    let (pdfa, bytes) = render("pdfa", "c.pdf", &[]);
    assert_eq!(pdfa.get("pdfa_valid"), Some(&Json::Bool(true)));
    fa::validate_pdfa2b(&bytes).expect("a valid PDF/A-2b");
    assert_eq!(text(&pdfa, "ir_digest"), text(&pdf, "ir_digest"));

    let (_, html) = render("html", "tb.html", &[]);
    let html = String::from_utf8(html).unwrap();
    assert!(html.contains("<html") && html.contains("100.00"), "{html}");
    let (_, svg) = render("svg", "tb.svg", &[]);
    assert!(String::from_utf8(svg).unwrap().contains("<svg"));

    // A frontier recorded before any tick has no date to give: the read at
    // that frontier is refused, never dated by a later tick.
    let early = dir.join("early.pdf");
    let error = refused(
        &book,
        &[
            "tb",
            "--period",
            "FY2026-P03",
            "--as-known-at",
            &untimed,
            "--render",
            "pdf",
            "--out",
            early.to_str().unwrap(),
        ],
        4,
    );
    assert!(text(data(&error), "message").contains(&format!("known at {untimed}")));
    assert!(!early.exists());

    // A statement renders the same way.
    let statement = dir.join("balance-sheet.html");
    let events = ok(
        &book,
        &[
            "statement",
            "balance-sheet",
            "--for",
            "FY2026-P03",
            "--render",
            "html",
            "--out",
            statement.to_str().unwrap(),
        ],
    );
    assert_eq!(text(&events[0], "event"), "statement");
    assert_eq!(text(rendered(&events), "created"), "2026-03-15T12:00:10Z");
    let html = std::fs::read_to_string(&statement).unwrap();
    assert!(html.contains("125.50"), "total assets: {html}");
    let md = ok(
        &book,
        &[
            "statement",
            "income-statement",
            "--for",
            "FY2026-P03",
            "--render",
            "md",
        ],
    );
    assert!(text(rendered(&md), "markdown").contains("25.50"));
}

#[test]
fn rounded_statements_render_all_formats_and_preserve_clock_and_output_guards() {
    let dir = temporary();
    let book = book(&dir);
    let args = [
        "statement",
        "balance-sheet",
        "--for",
        "FY2026-P03",
        "--present-in",
        "units",
    ];
    let before = head(&book);
    let untimed = dir.join("untimed.pdf");
    let mut missing_tick = args.to_vec();
    missing_tick.extend([
        "--certify",
        "--render",
        "pdf",
        "--out",
        untimed.to_str().unwrap(),
    ]);
    let error = refused(&book, &missing_tick, 4);
    assert!(text(data(&error), "message").contains("corroborated clock tick"));
    assert!(!untimed.exists());
    assert_eq!(
        head(&book),
        before,
        "failed rendering retains no accounting certificate"
    );

    record_ticks(&book);
    let at = head(&book).to_string();
    let mut digest = None;
    for format in ["md", "html", "svg", "pdf", "pdfa"] {
        let mut previous = None;
        for repeat in 0..2 {
            let path = dir.join(format!("rounded-{format}-{repeat}"));
            let mut request = args.to_vec();
            request.extend([
                "--as-known-at",
                &at,
                "--render",
                format,
                "--out",
                path.to_str().unwrap(),
            ]);
            let events = ok(&book, &request);
            assert_eq!(
                events.iter().map(|e| text(e, "event")).collect::<Vec<_>>(),
                ["statement", "statement_presented", "rendered"]
            );
            let document = rendered(&events);
            let bytes = std::fs::read(&path).unwrap();
            let ir = text(document, "ir_digest").to_string();
            if let Some(expected) = &digest {
                assert_eq!(&ir, expected);
            } else {
                digest = Some(ir);
            }
            if let Some(previous) = previous {
                assert_eq!(bytes, previous, "{format}");
            }
            previous = Some(bytes.clone());
            assert_eq!(
                head(&book).to_string(),
                at,
                "document-only rendering never writes the journal"
            );
            let body = String::from_utf8_lossy(&bytes);
            assert!(
                body.contains("Display only; cert exact"),
                "{format}: the scope notice must be in actual document content"
            );
            assert!(
                !body.contains("Certified Statement"),
                "{format}: rounded display does not certify rounded amounts"
            );
            assert!(
                body.contains("USD units; HalfEven"),
                "{format}: missing display basis"
            );
            if format == "md" {
                let assets = body
                    .lines()
                    .find(|row| {
                        row.starts_with('|')
                            && row
                                .split('|')
                                .nth(1)
                                .is_some_and(|code| code.trim() == "assets")
                    })
                    .unwrap();
                assert_eq!(
                    assets
                        .split('|')
                        .nth(3)
                        .unwrap()
                        .trim()
                        .trim_matches(['_', '=']),
                    "126"
                );
            } else {
                let amount = match format {
                    "html" => ">126</td>",
                    "svg" => ">126</text>",
                    "pdf" | "pdfa" => "(126) Tj",
                    _ => unreachable!(),
                };
                assert!(
                    body.contains(amount),
                    "{format}: rounded amount is absent from document content"
                );
            }
            assert!(
                !body.contains("125.50"),
                "{format}: exact amounts must not masquerade as the rounded document"
            );
            if format == "pdfa" {
                fa::validate_pdfa2b(&bytes).unwrap();
            }
            refused(&book, &request, 2);
            assert_eq!(
                std::fs::read(&path).unwrap(),
                bytes,
                "existing output is never overwritten"
            );
        }
    }
    for scale in ["thousands", "millions"] {
        let mut scaled = args.to_vec();
        scaled[5] = scale;
        scaled.extend(["--render", "md"]);
        let events = ok(&book, &scaled);
        assert!(text(rendered(&events), "markdown").contains(&format!("USD {scale}; HalfEven")));
        let scaled_digest = text(rendered(&events), "ir_digest").to_string();
        assert_ne!(Some(&scaled_digest), digest.as_ref());
        digest = Some(scaled_digest);
    }

    let functional = ok(
        &book,
        &[
            "statement",
            "balance-sheet",
            "--for",
            "FY2026-P03",
            "--functional",
            "--as-known-at",
            &at,
            "--present-in",
            "units",
            "--render",
            "md",
        ],
    );
    assert_eq!(
        data(&functional[0]).get("functional"),
        Some(&Json::Bool(true))
    );
    assert_eq!(text(data(&functional[0]), "base_unit"), "USD");
    let functional_md = text(rendered(&functional), "markdown");
    assert!(functional_md.contains("USD units; HalfEven"));
    assert!(functional_md.contains("Valuation basis: functional currency USD"));
    assert!(functional_md.contains("Display only; cert exact"));
    let assets = functional_md
        .lines()
        .find(|row| {
            row.starts_with('|')
                && row
                    .split('|')
                    .nth(1)
                    .is_some_and(|code| code.trim() == "assets")
        })
        .unwrap();
    assert_eq!(
        assets
            .split('|')
            .nth(3)
            .unwrap()
            .trim()
            .trim_matches(['_', '=']),
        "126"
    );

    for mode in ["diff", "trace"] {
        refused(
            &book,
            &[
                "statement",
                mode,
                "--definition",
                "balance-sheet",
                "--for",
                "FY2026-P03",
                "--before",
                &at,
                "--present-in",
                "units",
                "--render",
                "md",
            ],
            2,
        );
    }
}

#[test]
fn large_comparative_pdfa_keeps_exact_values_on_a_wide_page() {
    let dir = temporary();
    let book = book(&dir);
    ok(&book, &["period", "open", "FY2026-P02"]);
    let source = dir.join("wide-source.txt");
    std::fs::write(
        &source,
        b"Synthetic wide-comparative capital evidence; test fixture",
    )
    .unwrap();
    let document = ok(
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
    let evidence = text(data(&document[0]), "oid").to_string();
    let capital = 1_000_000_000_000_000_000_000_000_000_000_i128;
    let intent = dir.join("wide-capital.json");
    std::fs::write(
        &intent,
        format!(r#"{{"idempotency_key":"wide-capital","effective_date":"2026-03-10","legs":[{{"side":"debit","account":"1000","amount":"{capital}.00 USD"}},{{"side":"credit","account":"3000","amount":"{capital}.00 USD"}}]}}"#),
    ).unwrap();
    ok(
        &book,
        &[
            "post",
            "--intent",
            intent.to_str().unwrap(),
            "--evidence",
            &evidence,
        ],
    );
    record_ticks(&book);
    let before = head(&book);
    let at = before.to_string();
    let cash = format!("{}.50", capital.checked_add(125).unwrap());
    let mut previous = None;
    for repeat in 0..2 {
        let path = dir.join(format!("wide-comparative-pdfa-{repeat}"));
        let request = [
            "statement",
            "balance-sheet",
            "--for",
            "FY2026-P03",
            "--compare",
            "FY2026-P02",
            "--as-known-at",
            &at,
            "--render",
            "pdfa",
            "--out",
            path.to_str().unwrap(),
        ];
        let events = ok(&book, &request);
        assert_eq!(
            events
                .iter()
                .map(|event| text(event, "event"))
                .collect::<Vec<_>>(),
            ["statement", "rendered"]
        );
        let bytes = std::fs::read(&path).unwrap();
        let body = String::from_utf8_lossy(&bytes);
        let width: u32 = body
            .split_once("/MediaBox [0 0 ")
            .unwrap()
            .1
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(width > 612 && width <= 14_400);
        assert!(body.contains(&format!("({cash}) Tj")));
        assert!(body.contains(r"(current \(FY2026-P03\)) Tj"));
        assert!(body.contains(r"(comparative \(FY2026-P02\)) Tj"));
        assert_eq!(
            text(events[0].get("coordinate").unwrap(), "effective"),
            "periods:FY2026-P03,FY2026-P02"
        );
        fa::validate_pdfa2b(&bytes).unwrap();
        refused(&book, &request, 2);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            bytes,
            "existing wide output is never overwritten"
        );
        let ir_digest = text(rendered(&events), "ir_digest").to_string();
        if let Some((prior_bytes, prior_ir)) = previous {
            assert_eq!(bytes, prior_bytes);
            assert_eq!(ir_digest, prior_ir);
        }
        previous = Some((bytes, ir_digest));
        assert_eq!(head(&book), before, "rendering does not write the journal");
    }
}
