//! A portable analytic certificate survives a process boundary and later posts.
//! The certificate comes from AsyncBook; the separate real fa binary reopens
//! the persisted book and proves native reads before emitting procedure_run.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use asupersync::Budget;
use asupersync::fs::UnixVfs;
use asupersync::runtime::RuntimeBuilder;
use fa::procedure_certificate::{ProcedureCertificate, ProcedureRequest};
use fa::{AsyncBook, Book, BookKeys, Capability, Entropy};
use fa_cli::json::{self, Json};
use fa_lantern::catalog::Inputs;
use fa_model::account_vid;
use fa_time::DateDay;
use fgdb_types::VId;
use fgdb_types::context::PurposeContexts;

fn temp() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "fa-procedure-replay-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => panic!("{}: {e}", path.display()),
        }
    }
}

fn call(book: &Path, args: &[&str], input: Option<&[u8]>) -> (i32, String, Vec<Json>) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fa"));
    command
        .arg("--book")
        .arg(book)
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK");
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn().expect("spawn fa");
    if let Some(input) = input {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input)
            .expect("forward artifact stdin");
    }
    let result = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(result.stdout).unwrap();
    let registry = fa_cli::verbs::registry().unwrap();
    let events = stdout
        .lines()
        .map(|line| {
            registry
                .check_line(line)
                .unwrap_or_else(|error| panic!("{args:?}: {error:?}\n{line}"));
            json::parse(line).unwrap()
        })
        .collect();
    let exit = result.status.code().unwrap_or(-1);
    if exit == 0 {
        assert!(
            result.stderr.is_empty(),
            "{args:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    (exit, stdout, events)
}

fn ok(book: &Path, args: &[&str]) -> Vec<Json> {
    let (exit, stdout, events) = call(book, args, None);
    assert_eq!(exit, 0, "{args:?}\n{stdout}");
    events
}
fn data(value: &Json) -> &Json {
    value.get("data").unwrap()
}
fn text<'a>(value: &'a Json, name: &str) -> &'a str {
    value.get(name).and_then(Json::as_str).unwrap()
}
fn number(value: &Json, name: &str) -> i128 {
    match value.get(name) {
        Some(Json::Int(n)) => *n,
        _ => panic!("{value:?}: {name}"),
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[allow(clippy::too_many_arguments)]
fn post(
    book: &Path,
    dir: &Path,
    evidence: &str,
    key: &str,
    date: u8,
    from: &str,
    to: &str,
    amount: &str,
) -> VId {
    let path = dir.join(format!("{key}.json"));
    std::fs::write(&path, format!(r#"{{"idempotency_key":"{key}","effective_date":"2026-01-{date:02}","legs":[{{"side":"credit","account":"{from}","amount":"{amount}"}},{{"side":"debit","account":"{to}","amount":"{amount}"}}]}}"#)).unwrap();
    let result = ok(
        book,
        &[
            "post",
            "--intent",
            path.to_str().unwrap(),
            "--evidence",
            evidence,
        ],
    );
    VId(u128::from_str_radix(text(data(&result[0]), "vid"), 16).unwrap())
}

#[test]
fn analytic_artifacts_replay_after_reopen_with_no_partial_output_or_new_authority() {
    let dir = temp();
    let path = dir.join("book");
    ok(
        &path,
        &["book", "create", "--name", "Portable analytic evidence"],
    );
    let chart = dir.join("chart.json");
    std::fs::write(&chart, r#"{"accounts":[{"code":"1000","name":"Cash A","type":"Asset","unit":"USD"},{"code":"1010","name":"Cash B","type":"Asset","unit":"USD"},{"code":"1020","name":"Cash C","type":"Asset","unit":"USD"},{"code":"3000","name":"Capital","type":"Equity","unit":"USD"},{"code":"6000","name":"Expense","type":"Expense","unit":"USD"}]}"#).unwrap();
    ok(&path, &["chart", "import", chart.to_str().unwrap()]);
    ok(&path, &["period", "create", "--fiscal-year", "2026"]);
    ok(&path, &["period", "open", "FY2026-P01"]);
    let doc = dir.join("source.txt");
    std::fs::write(&doc, "Actual source document for process-boundary replay").unwrap();
    let evidence = ok(
        &path,
        &[
            "document",
            "add",
            doc.to_str().unwrap(),
            "--kind",
            "Invoice",
            "--grade",
            "HumanUpload",
        ],
    );
    let evidence = text(data(&evidence[0]), "oid");
    let source = post(
        &path,
        &dir,
        evidence,
        "source",
        1,
        "3000",
        "1000",
        "100.00 USD",
    );
    post(
        &path,
        &dir,
        evidence,
        "hop2",
        2,
        "1000",
        "1010",
        "80.00 USD",
    );
    post(
        &path,
        &dir,
        evidence,
        "hop3",
        3,
        "1010",
        "1020",
        "60.00 USD",
    );
    post(
        &path,
        &dir,
        evidence,
        "spent",
        4,
        "1020",
        "6000",
        "10.00 USD",
    );

    let keys = BookKeys::load(&path.join("book.keys")).unwrap();
    let head = || {
        Book::open_dir(&path, keys.clone(), Entropy::production())
            .unwrap()
            .head()
            .unwrap()
    };
    let before = head();
    let certificates: Vec<ProcedureCertificate> = {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let vfs = cx.commit().with_restriction(UnixVfs::new);
        let book = runtime
            .block_on(AsyncBook::open_with_vfs(
                &cx,
                vfs,
                &path,
                keys.clone(),
                Entropy::production(),
            ))
            .unwrap();
        let principal = VId(73);
        let capability = Capability::embedded(principal, &["read", "produce"]).unwrap();
        [
            "trace.network_fifo",
            "trace.network_lifo",
            "trace.network_libr",
            "trace.network_pro_rata",
        ]
        .into_iter()
        .map(|id| {
            let mut request = ProcedureRequest::new(
                id,
                Inputs {
                    account: Some(account_vid(book.context().book_id, "1000")),
                    source: Some(source),
                },
            )
            .unwrap();
            request.known_at = Some(before);
            request.effective_through = Some(DateDay::from_ymd(2026, 1, 31).unwrap());
            let result = book
                .certify_procedure(&cx, principal, &capability, &request)
                .unwrap()
                .unwrap();
            assert_eq!(book.head(&cx).unwrap(), before);
            result.certificate
        })
        .collect()
    }; // close the AsyncBook before independent CLI processes take the lease.
    assert_eq!(head(), before);
    post(
        &path,
        &dir,
        evidence,
        "later-backdated",
        1,
        "3000",
        "1000",
        "900.00 USD",
    );
    let after = head();
    assert!(after > before);

    for (i, certificate) in certificates.iter().enumerate() {
        let bytes = certificate.canonical_bytes().unwrap();
        let file = dir.join(format!("procedure-{i}.cert"));
        std::fs::write(&file, &bytes).unwrap();
        let args = ["replay", file.to_str().unwrap()];
        let (exit, stdout, events) = call(&path, &args, None);
        assert_eq!(exit, 0, "{stdout}");
        assert_eq!(events.len(), 1);
        assert_eq!(text(&events[0], "event"), "procedure_run");
        assert_eq!(text(&events[0], "certificate"), hex(certificate.digest()));
        let result = data(&events[0]);
        assert_eq!(text(result, "procedure"), certificate.report().procedure);
        assert_eq!(
            text(result, "findings_digest"),
            hex(&certificate.report().findings_digest)
        );
        assert_eq!(number(result, "known_at"), i128::from(before.0));
        let findings = result.get("findings").and_then(Json::as_arr).unwrap();
        assert_eq!(
            findings
                .iter()
                .map(|f| number(f.get("statistic").unwrap(), "value"))
                .sum::<i128>(),
            10_000
        );
        let spent = findings
            .iter()
            .find(|f| text(f.get("statistic").unwrap(), "name") == "spent_mantissa")
            .unwrap();
        assert_eq!(number(spent.get("statistic").unwrap(), "value"), 1_000);
        assert_eq!(spent.get("cites").and_then(Json::as_arr).unwrap().len(), 14);
        assert_eq!(call(&path, &args, None).1, stdout);
        let (stdin_exit, stdin_output, _) = call(&path, &["replay", "-"], Some(&bytes));
        assert_eq!(stdin_exit, 0, "{stdin_output}");
        assert_eq!(stdin_output, stdout);
        let encoded = dir.join(format!("procedure-{i}.hex"));
        std::fs::write(&encoded, hex(&bytes)).unwrap();
        let (hex_exit, hex_output, _) = call(&path, &["replay", encoded.to_str().unwrap()], None);
        assert_eq!(hex_exit, 0, "{hex_output}");
        assert_eq!(hex_output, stdout);
        assert_eq!(
            head(),
            after,
            "replay must not journal output or move its basis"
        );

        let mut damaged = bytes.clone();
        *damaged.last_mut().unwrap() ^= 1;
        for bad in [&damaged[..], &bytes[..bytes.len() / 2]] {
            let (exit, error_output, events) = call(&path, &["replay", "-"], Some(bad));
            assert_eq!(exit, 8, "{error_output}");
            assert_eq!(
                events.len(),
                1,
                "no partial results on failure: {error_output}"
            );
            assert_eq!(text(&events[0], "event"), "error");
        }
    }
}

#[test]
fn circular_flow_budget_refuses_inside_search_without_partial_output_or_head_change() {
    let dir = temp();
    let path = dir.join("book");
    ok(
        &path,
        &["book", "create", "--name", "Bounded circular search"],
    );
    let chart = dir.join("chart.json");
    std::fs::write(&chart, r#"{"accounts":[{"code":"1000","name":"Cash A","type":"Asset","unit":"USD"},{"code":"1010","name":"Cash B","type":"Asset","unit":"USD"},{"code":"1020","name":"Cash C","type":"Asset","unit":"USD"}]}"#).unwrap();
    ok(&path, &["chart", "import", chart.to_str().unwrap()]);
    ok(&path, &["period", "create", "--fiscal-year", "2026"]);
    ok(&path, &["period", "open", "FY2026-P01"]);
    let doc = dir.join("source.txt");
    std::fs::write(&doc, "Synthetic three-transfer circular-flow source").unwrap();
    let evidence = ok(
        &path,
        &[
            "document",
            "add",
            doc.to_str().unwrap(),
            "--kind",
            "Invoice",
            "--grade",
            "HumanUpload",
        ],
    );
    let evidence = text(data(&evidence[0]), "oid");
    for (key, date, from, to) in [
        ("hop1", 5, "1000", "1010"),
        ("hop2", 6, "1010", "1020"),
        ("hop3", 7, "1020", "1000"),
    ] {
        post(&path, &dir, evidence, key, date, from, to, "1.00 USD");
    }
    let keys = BookKeys::load(&path.join("book.keys")).unwrap();
    let head = || {
        Book::open_dir(&path, keys.clone(), Entropy::production())
            .unwrap()
            .head()
            .unwrap()
    };
    let before = head();
    let args = [
        "procedure",
        "run",
        "graph.round_trips",
        "--param",
        "max_hops=3",
    ];
    let complete = ok(&path, &args);
    assert_eq!(complete.len(), 1);
    assert_eq!(text(&complete[0], "event"), "procedure_run");
    let result = data(&complete[0]);
    assert_eq!(
        result.get("findings").and_then(Json::as_arr).unwrap().len(),
        1
    );
    let work = result.get("work").unwrap();
    assert_eq!(number(work, "legs"), 3);
    assert_eq!(number(work, "comparisons"), 8);

    let mut bounded = args.to_vec();
    bounded.extend(["--budget", "7"]);
    let (exit, output, events) = call(&path, &bounded, None);
    assert_eq!(exit, 3, "{output}");
    assert_eq!(events.len(), 1, "{output}");
    assert_eq!(text(&events[0], "event"), "error");
    assert!(output.contains("8 > 7 work units"), "{output}");
    assert!(!output.contains("\"findings\""), "{output}");
    assert_eq!(head(), before);

    bounded.pop();
    bounded.push("11");
    let sufficient = ok(&path, &bounded);
    assert_eq!(
        text(data(&sufficient[0]), "findings_digest"),
        text(result, "findings_digest")
    );
    assert_eq!(
        data(&sufficient[0]).get("work").unwrap(),
        result.get("work").unwrap()
    );
    assert_eq!(head(), before);
}

#[path = "procedure_replay/extended.rs"]
mod extended;
