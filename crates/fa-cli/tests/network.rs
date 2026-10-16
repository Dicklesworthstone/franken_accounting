//! Source tracing through the real fa binary and its existing robot contract.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};

const IDS: [&str; 4] = ["trace.network_fifo", "trace.network_lifo", "trace.network_libr", "trace.network_pro_rata"];

fn temp() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!("fa-network-cli-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
            Err(e) => panic!("fixture {}: {e}", path.display()),
        }
    }
}

fn run(book: &Path, args: &[&str]) -> (i32, Vec<Json>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_fa")).arg("--book").arg(book).args(args).arg("--json").env_remove("FA_BOOK").output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let registry = fa_cli::verbs::registry().unwrap();
    let events = stdout.lines().map(|line| {
        registry.check_line(line).unwrap_or_else(|e| panic!("{args:?}: {e:?}\n{line}"));
        json::parse(line).unwrap()
    }).collect();
    (out.status.code().unwrap_or(-1), events, String::from_utf8_lossy(&out.stderr).into_owned())
}

fn ok(book: &Path, args: &[&str]) -> Vec<Json> {
    let (exit, events, err) = run(book, args);
    assert_eq!(exit, 0, "{args:?}\n{events:?}\n{err}");
    events
}

fn data(event: &Json) -> &Json { event.get("data").unwrap() }
fn text<'a>(value: &'a Json, key: &str) -> &'a str { value.get(key).and_then(Json::as_str).unwrap() }
fn array<'a>(value: &'a Json, key: &str) -> &'a [Json] { value.get(key).and_then(Json::as_arr).unwrap() }
fn number(value: &Json, key: &str) -> i128 { match value.get(key) { Some(Json::Int(n)) => *n, other => panic!("{key}: {other:?}") } }

#[test]
fn network_laws_are_discoverable_and_trace_real_postings_with_ordered_path_citations() {
    let dir = temp();
    let book = dir.join("book");
    ok(&book, &["book", "create", "--name", "Trace integration"]);
    let chart = dir.join("chart.json");
    std::fs::write(&chart, r#"{"accounts":[{"code":"1000","name":"Cash A","type":"Asset","unit":"USD"},{"code":"1010","name":"Cash B","type":"Asset","unit":"USD"},{"code":"1020","name":"Cash C","type":"Asset","unit":"USD"},{"code":"3000","name":"Capital","type":"Equity","unit":"USD"},{"code":"6000","name":"Expense","type":"Expense","unit":"USD"}]}"#).unwrap();
    ok(&book, &["chart", "import", chart.to_str().unwrap()]);
    ok(&book, &["period", "create", "--fiscal-year", "2026"]);
    ok(&book, &["period", "open", "FY2026-P01"]);
    let evidence_file = dir.join("invoice.txt");
    std::fs::write(&evidence_file, "Source evidence for transfer tracing").unwrap();
    let added = ok(&book, &["document", "add", evidence_file.to_str().unwrap(), "--kind", "Invoice", "--grade", "HumanUpload"]);
    let evidence = text(data(&added[0]), "oid");
    let mut entries = Vec::new();
    let mut prefix = String::new();
    for (day, from, to, amount) in [(1, "3000", "1000", "100.00 USD"), (2, "1000", "1010", "80.00 USD"), (3, "1010", "1020", "60.00 USD"), (4, "1020", "6000", "10.00 USD")] {
        let path = dir.join(format!("entry-{day}.json"));
        std::fs::write(&path, format!(r#"{{"idempotency_key":"network-{day}","effective_date":"2026-01-{day:02}","legs":[{{"side":"credit","account":"{from}","amount":"{amount}"}},{{"side":"debit","account":"{to}","amount":"{amount}"}}]}}"#)).unwrap();
        let posted = ok(&book, &["post", "--intent", path.to_str().unwrap(), "--evidence", evidence]);
        let posting = data(&posted[0]);
        entries.push(text(posting, "vid").to_string());
        if day == 1 { prefix = number(posting, "recorded_at").to_string(); }
    }
    let listing = ok(&book, &["procedure", "list"]);
    for id in IDS {
        assert!(array(data(&listing[0]), "procedures").iter().any(|p| text(p, "id") == id));
        let args = ["procedure", "run", id, "--account", "1000", "--source", &entries[0], "--effective-through", "2026-01-31"];
        let output = ok(&book, &args);
        assert_eq!(text(&output[0], "event"), "procedure_run");
        let report = data(&output[0]);
        assert_eq!(text(report, "procedure"), id);
        let findings = array(report, "findings");
        assert_eq!(findings.iter().map(|f| number(f.get("statistic").unwrap(), "value")).sum::<i128>(), 10000);
        let spent = findings.iter().find(|f| text(f.get("statistic").unwrap(), "name") == "spent_mantissa").unwrap();
        assert_eq!(number(spent.get("statistic").unwrap(), "value"), 1000);
        let cites = array(spent, "cites");
        assert_eq!(cites.len(), 2 + 3 * entries.len());
        for (hop, entry) in cites[2..].chunks_exact(3).zip(&entries) {
            assert_eq!(text(&hop[0], "kind"), "entry");
            assert_eq!(text(&hop[0], "entry"), entry);
            assert_eq!(text(&hop[1], "kind"), "account");
            assert_eq!(text(&hop[2], "kind"), "account");
        }
        let repeat = ok(&book, &args);
        assert_eq!(text(report, "findings_digest"), text(data(&repeat[0]), "findings_digest"));
        let mut historical = args.to_vec(); historical.extend(["--as-known-at", &prefix]);
        let old = ok(&book, &historical);
        let old_findings = array(data(&old[0]), "findings");
        assert_eq!(old_findings.len(), 1);
        assert_eq!(number(old_findings[0].get("statistic").unwrap(), "value"), 10000);
        let mut bounded = args.to_vec(); bounded.extend(["--param", "max_hops=2"]);
        let (exit, failed, _) = run(&book, &bounded);
        assert_ne!(exit, 0);
        assert_eq!(failed.len(), 1, "no partial findings: {failed:?}");
        assert_eq!(text(&failed[0], "event"), "error");
        assert!(format!("{failed:?}").contains("max_hops"));
    }
}
