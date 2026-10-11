//! Certified trial balances and `fa replay` on real persisted books
//! (plan §13.6, FA-INV-11, bead fa-cqk).
//!
//! Every step logs what it ran and what it saw, so a failure names the
//! command, its exit, and the line that disagreed.

#![forbid(unsafe_code)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use fa::ReportCertificate;
use fa_cli::json::{self, Json};
use fa_cli::verbs::registry;

const CHART: &str = r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#;

fn run_with(book: &Path, args: &[&str], stdin: Option<&str>) -> (i32, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fa"));
    command
        .arg("--book")
        .arg(book)
        .args(args)
        .env_remove("FA_BOOK")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let mut child = command.spawn().expect("spawn fa");
    if let Some(text) = stdin {
        child
            .stdin
            .take()
            .expect("stdin pipe")
            .write_all(text.as_bytes())
            .expect("write stdin");
    }
    let result = child.wait_with_output().expect("run fa");
    let code = result.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&result.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&result.stderr).into_owned();
    eprintln!(
        "[replay-test] fa --book {} {} → exit {code}\n  stdout: {}\n  stderr: {}",
        book.display(),
        args.join(" "),
        stdout.trim(),
        stderr.trim()
    );
    if args.contains(&"--json") {
        let lines: Vec<_> = stdout.lines().collect();
        assert_eq!(lines.len(), 1, "args={args:?}: {stdout}\n{stderr}");
        let checked = registry().expect("verb registry").check_line(lines[0]);
        assert!(checked.is_ok(), "args={args:?}: {checked:?}\n{stdout}");
    }
    (code, stdout, stderr)
}

fn run(book: &Path, args: &[&str]) -> (i32, String, String) {
    run_with(book, args, None)
}

fn ok(book: &Path, args: &[&str]) -> String {
    let (code, stdout, stderr) = run(book, args);
    assert_eq!(code, 0, "args={args:?}\n{stdout}\n{stderr}");
    stdout
}

fn parsed(text: &str) -> Json {
    json::parse(text.trim()).expect("one JSON object")
}

fn get<'a>(value: &'a Json, key: &str) -> Option<&'a Json> {
    value
        .get("data")
        .and_then(|data| data.get(key))
        .or_else(|| value.get(key))
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    get(value, key).and_then(Json::as_str).expect(key)
}

fn integer(value: &Json, key: &str) -> i128 {
    let found = get(value, key);
    let n = match found {
        Some(Json::Int(n)) => Some(*n),
        _ => None,
    };
    assert!(n.is_some(), "{key}: expected an integer, got {found:?}");
    n.unwrap_or_default()
}

fn array<'a>(value: &'a Json, key: &str) -> &'a [Json] {
    get(value, key).and_then(Json::as_arr).expect(key)
}

fn fixture() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("fa-replay-cli-{}-{id}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) => assert_eq!(
                error.kind(),
                std::io::ErrorKind::AlreadyExists,
                "create retained fixture {}: {error}",
                path.display()
            ),
        }
    }
}

fn write(dir: &Path, name: &str, contents: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write fixture");
    path.display().to_string()
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("create copy");
    for entry in std::fs::read_dir(from).expect("read book dir") {
        let entry = entry.expect("dir entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy book file");
        }
    }
}

/// A book with a chart and FY2026's March and April open.
fn book(dir: &Path, name: &str) -> PathBuf {
    let book = dir.join(name);
    ok(&book, &["book", "create", "--name", "Replay Co", "--json"]);
    let chart = write(dir, &format!("{name}-chart.json"), CHART);
    ok(&book, &["chart", "import", &chart, "--json"]);
    ok(
        &book,
        &["period", "create", "--fiscal-year", "2026", "--json"],
    );
    ok(&book, &["period", "open", "FY2026-P03", "--json"]);
    ok(&book, &["period", "open", "FY2026-P04", "--json"]);
    book
}

/// Post a two-leg cash sale with a recorded receipt.
fn sale(dir: &Path, book: &Path, key: &str, date: &str, amount: &str) -> Json {
    let source = write(
        dir,
        &format!("{key}.txt"),
        &format!("Fixture receipt {key}: {amount} USD received on {date}."),
    );
    let document = parsed(&ok(
        book,
        &[
            "document",
            "add",
            &source,
            "--kind",
            "Receipt",
            "--grade",
            "HumanUpload",
            "--json",
        ],
    ));
    let intent = write(
        dir,
        &format!("{key}.json"),
        &format!(
            r#"{{"effective_date":"{date}","idempotency_key":"{key}","legs":[{{"side":"debit","account":"1000","amount":"{amount} USD"}},{{"side":"credit","account":"4000","amount":"{amount} USD"}}]}}"#
        ),
    );
    parsed(&ok(
        book,
        &[
            "post",
            "--intent",
            &intent,
            "--evidence",
            text(&document, "oid"),
            "--json",
        ],
    ))
}

/// The certificate a `fa tb --json` line carries, checked against its
/// envelope; returns the line and the certificate's hex.
fn certified(line: &str) -> (Json, String) {
    let tb = parsed(line);
    assert_eq!(text(&tb, "event"), "trial_balance");
    let certificate = get(&tb, "certificate").expect("data.certificate");
    let id = text(certificate, "id");
    assert_eq!(id.len(), 64, "the id is a 32-byte digest in hex: {id}");
    assert_eq!(
        tb.get("certificate").and_then(Json::as_str),
        Some(id),
        "the envelope's certificate is data.certificate.id"
    );
    let known_at = integer(&tb, "known_at");
    assert_eq!(integer(certificate, "known_at"), known_at);
    let names: Vec<&str> = array(certificate, "inputs")
        .iter()
        .map(|input| text(input, "name"))
        .collect();
    assert_eq!(names, ["entries", "accounts", "periods"]);
    for input in array(certificate, "inputs") {
        assert_eq!(
            integer(input, "snapshot_seq"),
            known_at,
            "every certified read runs at the report's known-at"
        );
    }
    assert_eq!(
        integer(certificate, "rows"),
        array(&tb, "rows").len() as i128
    );
    assert_eq!(text(certificate, "replay_scope"), "native-inputs+fold");
    let bytes = text(certificate, "bytes").to_string();
    let decoded = ReportCertificate::from_text(&bytes).expect("decode the certificate");
    assert_eq!(decoded.id_text().expect("id"), id);
    (tb, bytes)
}

fn refusal_of(stdout: &str) -> (String, String) {
    let line = parsed(stdout);
    assert_eq!(text(&line, "event"), "error");
    (
        text(&line, "refusal_id").to_string(),
        text(&line, "message").to_string(),
    )
}

#[test]
fn a_certified_trial_balance_replays_byte_for_byte_after_reopen_and_on_a_copy() {
    let dir = fixture();
    let book = book(&dir, "book");
    sale(&dir, &book, "sale-1", "2026-03-10", "12.34");

    let first_line = ok(&book, &["tb", "--period", "FY2026-P03", "--json"]);
    let (first, hex) = certified(&first_line);
    assert_eq!(
        text(get(&first, "certificate").expect("cert"), "definition"),
        "fa.tb.stock"
    );
    assert_eq!(
        ok(&book, &["tb", "--period", "FY2026-P03", "--json"]),
        first_line,
        "the same closure certifies to byte-identical output"
    );
    let file = write(&dir, "tb.cert", &hex);

    let replayed = parsed(&ok(&book, &["replay", &file, "--json"]));
    assert_eq!(text(&replayed, "event"), "certificate_replayed");
    assert_eq!(text(&replayed, "status"), "reproduced");
    assert_eq!(text(&replayed, "certificate"), text(&first, "certificate"));
    assert_eq!(
        replayed.get("certificate"),
        first.get("certificate"),
        "the replay's envelope names the same certificate"
    );
    assert_eq!(array(&replayed, "inputs_replayed").len(), 3);
    assert_eq!(
        integer(&replayed, "rows"),
        array(&first, "rows").len() as i128
    );
    assert_eq!(integer(&replayed, "known_at"), integer(&first, "known_at"));

    // The same bytes on stdin, and in human mode.
    let (code, stdout, stderr) = run_with(&book, &["replay", "-", "--json"], Some(&hex));
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let human = ok(&book, &["replay", &file]);
    assert!(human.contains("reproduced byte-for-byte"), "{human}");

    let current = parsed(&ok(&book, &["certificate", "status", &file, "--json"]));
    assert_eq!(text(&current, "event"), "certificate_status");
    assert_eq!(text(&current, "status"), "Current");
    assert!(array(&current, "later_entries").is_empty());
    assert_eq!(
        current.get("data").and_then(|d| d.get("figures_changed")),
        Some(&Json::Bool(false))
    );

    // An April sale is outside the March stock selector: still Current.
    sale(&dir, &book, "sale-april", "2026-04-05", "1.00");
    let after_april = parsed(&ok(&book, &["certificate", "status", &file, "--json"]));
    assert_eq!(text(&after_april, "status"), "Current", "{after_april:?}");
    assert!(integer(&after_april, "head") > integer(&first, "known_at"));

    // A backdated March sale supersedes it; the certificate still replays.
    let backdated = sale(&dir, &book, "sale-2", "2026-03-20", "5.00");
    let superseded = parsed(&ok(&book, &["certificate", "status", &file, "--json"]));
    assert_eq!(text(&superseded, "status"), "SupersededBy");
    let later = array(&superseded, "later_entries");
    assert_eq!(later.len(), 1, "{superseded:?}");
    assert_eq!(text(&later[0], "effective_date"), "2026-03-20");
    assert_eq!(
        integer(&later[0], "recorded_at"),
        integer(&backdated, "recorded_at")
    );
    assert_eq!(
        superseded
            .get("data")
            .and_then(|d| d.get("figures_changed")),
        Some(&Json::Bool(true))
    );
    ok(&book, &["replay", &file, "--json"]);

    // A later certificate at the first one's known-at is the same certificate.
    let known_at = integer(&first, "known_at").to_string();
    let (again, _) = certified(&ok(
        &book,
        &[
            "tb",
            "--period",
            "FY2026-P03",
            "--as-known-at",
            &known_at,
            "--json",
        ],
    ));
    assert_eq!(again.get("certificate"), first.get("certificate"));
    assert_eq!(get(&again, "certificate"), get(&first, "certificate"));

    // The other modes certify and replay under their own definitions.
    for (args, definition) in [
        (vec!["tb", "--as-of", "2026-03-31", "--json"], "fa.tb.as_of"),
        (
            vec!["tb", "--period", "FY2026-P03", "--activity", "--json"],
            "fa.tb.activity",
        ),
        (vec!["tb", "--fiscal-year", "2026", "--json"], "fa.tb.stock"),
    ] {
        let (line, hex) = certified(&ok(&book, &args));
        assert_eq!(
            text(get(&line, "certificate").expect("cert"), "definition"),
            definition
        );
        let file = write(&dir, &format!("{definition}.cert"), &hex);
        let replayed = parsed(&ok(&book, &["replay", &file, "--json"]));
        assert_eq!(text(&replayed, "definition"), definition);
    }

    // A copied book (same keys, same history, another path) replays it too.
    let copy = dir.join("copy");
    copy_dir(&book, &copy);
    let on_copy = parsed(&ok(&copy, &["replay", &file, "--json"]));
    assert_eq!(text(&on_copy, "status"), "reproduced");
}

#[test]
fn an_altered_certificate_or_another_history_does_not_reproduce() {
    let dir = fixture();
    let book = book(&dir, "book");
    // Same keys and history up to here: the fork diverges below.
    let fork = dir.join("fork");
    copy_dir(&book, &fork);
    sale(&dir, &book, "sale-1", "2026-03-10", "12.34");
    let (tb, hex) = certified(&ok(&book, &["tb", "--period", "FY2026-P03", "--json"]));
    let original = ReportCertificate::from_text(&hex).expect("decode");
    let known_at = original.known_at;

    let refused =
        |book: &Path, certificate: &ReportCertificate, name: &str| -> (i32, String, String) {
            let file = write(&dir, name, &certificate.to_hex().expect("encode"));
            let (code, stdout, _) = run(book, &["replay", &file, "--json"]);
            let (code_id, message) = refusal_of(&stdout);
            (code, code_id, message)
        };

    let mut output = original.clone();
    output.output_digest[0] ^= 1;
    let (code, id, message) = refused(&book, &output, "output.cert");
    assert_eq!((code, id.as_str()), (8, "FA-REF-162"), "{message}");
    assert!(message.contains("totals differ"), "{message}");

    let mut row = original.clone();
    row.row_digests[0][0] ^= 1;
    let (code, id, message) = refused(&book, &row, "row.cert");
    assert_eq!((code, id.as_str()), (8, "FA-REF-162"), "{message}");
    assert!(message.contains("row 0"), "{message}");

    let mut parameters = original.clone();
    parameters.request = fa::TrialBalanceRequest::Stock {
        periods: vec!["FY2026-P04".into()],
    };
    let (code, id, message) = refused(&book, &parameters, "parameters.cert");
    assert_eq!((code, id.as_str()), (8, "FA-REF-162"), "{message}");

    let mut earlier = original.clone();
    earlier.known_at = fgdb_types::CommitSeq(known_at.0 - 1);
    let (code, id, message) = refused(&book, &earlier, "known-at.cert");
    assert_eq!((code, id.as_str()), (8, "FA-REF-162"), "{message}");
    assert!(
        message.contains("not the certificate's known-at"),
        "{message}"
    );

    let mut input = original.clone();
    input.inputs[0].certificate.result_digest.0[0] ^= 1;
    let (code, id, message) = refused(&book, &input, "input.cert");
    assert_eq!((code, id.as_str()), (8, "FA-REF-162"), "{message}");
    assert!(message.contains("input `entries`"), "{message}");

    let mut dropped = original.clone();
    dropped.inputs.pop();
    let (code, id, message) = refused(&book, &dropped, "dropped.cert");
    assert_eq!((code, id.as_str()), (8, "FA-REF-162"), "{message}");

    let mut units = original.clone();
    units.units_digest[0] ^= 1;
    let (code, id, message) = refused(&book, &units, "units.cert");
    assert_eq!((code, id.as_str()), (8, "FA-REF-162"), "{message}");
    assert!(message.contains("unit table"), "{message}");

    // Malformed text is a usage error and never opens the book.
    for (name, text_) in [
        ("truncated.cert", hex[..hex.len() - 2].to_string()),
        ("upper.cert", hex.to_uppercase()),
        ("empty.cert", String::new()),
    ] {
        let file = write(&dir, name, &text_);
        let (code, stdout, _) = run(&book, &["replay", &file, "--json"]);
        let (id, message) = refusal_of(&stdout);
        assert_eq!((code, id.as_str()), (2, "FA-REF-160"), "{name}: {message}");
    }

    // The fork has the same keys but has not reached the known-at yet.
    let file = write(&dir, "tb.cert", &hex);
    let (code, stdout, _) = run(&fork, &["replay", &file, "--json"]);
    let (id, message) = refusal_of(&stdout);
    assert_eq!((code, id.as_str()), (8, "FA-REF-162"), "{message}");
    assert!(message.contains("beyond this book's frontier"), "{message}");

    // Once the fork records another sale at the same sequence, its history
    // at the known-at differs: the substrate refuses the chain commitment.
    sale(&dir, &fork, "sale-1", "2026-03-10", "99.99");
    let (code, stdout, _) = run(&fork, &["replay", &file, "--json"]);
    let (id, message) = refusal_of(&stdout);
    assert_eq!((code, id.as_str()), (8, "FA-REF-162"), "{message}");
    assert!(message.contains("not the certified history"), "{message}");

    // Another book refuses by name.
    let other = book_other(&dir);
    let (code, stdout, _) = run(&other, &["replay", &file, "--json"]);
    let (id, message) = refusal_of(&stdout);
    assert_eq!((code, id.as_str()), (8, "FA-REF-161"), "{message}");
    let (code, stdout, _) = run(&other, &["certificate", "status", &file, "--json"]);
    let (id, _) = refusal_of(&stdout);
    assert_eq!((code, id.as_str()), (8, "FA-REF-161"));

    // The untouched certificate still reproduces on its own book.
    let replayed = parsed(&ok(&book, &["replay", &file, "--json"]));
    assert_eq!(replayed.get("certificate"), tb.get("certificate"));
}

fn book_other(dir: &Path) -> PathBuf {
    let other = dir.join("other");
    ok(&other, &["book", "create", "--name", "Other Co", "--json"]);
    other
}
