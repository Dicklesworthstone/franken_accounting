//! Real-binary finding publication, independent human decisions and portable
//! workpaper delivery. Every command reopens the persisted book; retained
//! observations and review cutoffs must survive those process boundaries.

#![forbid(unsafe_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use fa::{Book, BookKeys, Entropy};
use fa_cli::authority::{LaunchAuthority, LaunchProfile};
use fa_cli::cli::{Books, Files, Stdin, run_with_authority};
use fa_cli::json::{self, Json};

fn temporary() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "fa-finding-surface-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("{}: {error}", path.display()),
        }
    }
}

fn events(stdout: &str) -> Vec<Json> {
    let registry = fa_cli::verbs::registry().unwrap();
    stdout
        .lines()
        .map(|line| {
            registry
                .check_line(line)
                .unwrap_or_else(|error| panic!("{error}\n{line}"));
            json::parse(line).unwrap()
        })
        .collect()
}

fn call(book: &Path, args: &[&str], input: Option<&[u8]>) -> (i32, Vec<Json>) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fa"));
    command
        .arg("--book")
        .arg(book)
        .args(["--via", "direct", "--json", "--no-color"])
        .args(args)
        .env_remove("FA_BOOK")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn().unwrap();
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let exit = output.status.code().unwrap_or(-1);
    let parsed = events(&stdout);
    if exit == 0 {
        assert!(
            output.stderr.is_empty(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    } else {
        assert_eq!(
            parsed.len(),
            1,
            "failed command emitted partial findings: {args:?}\n{stdout}"
        );
        assert_eq!(text(&parsed[0], "event"), "error", "{args:?}\n{stdout}");
        assert_eq!(number(data(&parsed[0]), "exit"), i128::from(exit));
    }
    (exit, parsed)
}

fn ok(book: &Path, args: &[&str]) -> Json {
    let (exit, result) = call(book, args, None);
    assert_eq!(exit, 0, "{args:?}: {result:?}");
    assert_eq!(result.len(), 1, "{args:?}: {result:?}");
    result.into_iter().next().unwrap()
}

fn data(value: &Json) -> &Json {
    value.get("data").unwrap()
}
fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value.get(key).and_then(Json::as_str).unwrap()
}
fn number(value: &Json, key: &str) -> i128 {
    match value.get(key) {
        Some(Json::Int(value)) => *value,
        _ => panic!("{key}: {value:?}"),
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Fixture {
    root: PathBuf,
    book: PathBuf,
    evidence: String,
}

impl Fixture {
    fn new() -> Self {
        let root = temporary();
        let book = root.join("book");
        ok(&book, &["book", "create", "--name", "Recorded findings"]);
        let chart = root.join("chart.json");
        std::fs::write(&chart, r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"3000","name":"Capital","type":"Equity","unit":"USD"}]}"#).unwrap();
        ok(&book, &["chart", "import", chart.to_str().unwrap()]);
        ok(&book, &["period", "create", "--fiscal-year", "2026"]);
        ok(&book, &["period", "open", "FY2026-P01"]);
        let source = root.join("actual-source.txt");
        std::fs::write(&source, "Retained actual supporting document for the Saturday entry and its later human explanation.").unwrap();
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
        let evidence = text(data(&document), "oid").to_string();
        let fixture = Self {
            root,
            book,
            evidence,
        };
        fixture.post("saturday", "2026-01-10", "100.00 USD");
        fixture
    }

    fn post(&self, key: &str, day: &str, amount: &str) {
        let path = self.root.join(format!("{key}.json"));
        std::fs::write(&path, format!(r#"{{"idempotency_key":"{key}","effective_date":"{day}","legs":[{{"side":"debit","account":"1000","amount":"{amount}"}},{{"side":"credit","account":"3000","amount":"{amount}"}}]}}"#)).unwrap();
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

    fn head(&self) -> u64 {
        let keys = BookKeys::load(&self.book.join("book.keys")).unwrap();
        Book::open_dir(&self.book, keys, Entropy::production())
            .unwrap()
            .head()
            .unwrap()
            .0
    }

    fn export(
        &self,
        certificate: &str,
        name: &str,
        reviews: bool,
        at: Option<&str>,
    ) -> (Json, Vec<u8>) {
        let path = self.root.join(name);
        let mut args = vec![
            "finding",
            "export",
            "--certificate",
            certificate,
            "--export-format",
            "canonical",
            "--out",
            path.to_str().unwrap(),
        ];
        if reviews {
            args.push("--include-reviews");
        }
        if let Some(at) = at {
            args.extend(["--known-at", at]);
        }
        let event = ok(&self.book, &args);
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(number(data(&event), "bytes"), bytes.len() as i128);
        assert_eq!(
            text(data(&event), "content_digest"),
            hex(&fa_model::domain_digest(b"fa:finding-export:v1", &[&bytes]))
        );
        (event, bytes)
    }
}

#[test]
fn findings_remain_citable_and_review_history_survives_process_boundaries() {
    let f = Fixture::new();
    let basis = f.head().to_string();
    let recorded = ok(
        &f.book,
        &[
            "finding",
            "record",
            "jet.weekend",
            "--as",
            "investigator",
            "--known-at",
            &basis,
        ],
    );
    assert_eq!(text(&recorded, "event"), "findings_recorded");
    let record = data(&recorded);
    let certificate = text(record, "certificate").to_string();
    assert_eq!(
        recorded.get("certificate"),
        Some(&Json::Str(certificate.clone()))
    );
    assert_eq!(number(record, "finding_count"), 1, "{record:?}");
    assert_eq!(number(record, "source_known_at").to_string(), basis);
    let finding = record.get("finding_ids").and_then(Json::as_arr).unwrap()[0]
        .as_str()
        .unwrap()
        .to_string();
    let selected = format!("F:{finding}");
    let published = number(record, "recorded_at").to_string();
    let before = f.head();
    let retry = ok(
        &f.book,
        &[
            "finding",
            "record",
            "--certificate",
            &certificate,
            "--as",
            "investigator",
        ],
    );
    assert_eq!(
        data(&retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        number(data(&retry), "recorded_at"),
        number(record, "recorded_at")
    );
    assert_eq!(f.head(), before, "exact source retries publish nothing");
    let recertified = ok(
        &f.book,
        &[
            "finding",
            "record",
            "jet.weekend",
            "--as",
            "investigator",
            "--known-at",
            &basis,
        ],
    );
    assert_eq!(text(data(&recertified), "certificate"), certificate);
    assert_eq!(
        f.head(),
        before,
        "same producer/parameters/coordinate retain the same complete run"
    );
    let listed = ok(&f.book, &["finding", "list", "--certificate", &certificate]);
    assert_eq!(text(data(&listed), "scope"), "certified-run");
    let rows = data(&listed)
        .get("findings")
        .and_then(Json::as_arr)
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(text(&rows[0], "finding_vid"), finding);
    assert_eq!(text(&rows[0], "status"), "Open");
    let original_value = rows[0].get("finding").unwrap().clone();
    assert!(
        !original_value
            .get("cites")
            .and_then(Json::as_arr)
            .unwrap()
            .is_empty()
    );
    let (_, original) = f.export(&certificate, "original.fawp", false, None);
    let (_, open_review) = f.export(&certificate, "open-review.fawp", true, Some(&published));
    assert_eq!(
        f.head(),
        before,
        "reads and workpaper production do not renumber findings"
    );

    let (exit, refusal) = call(
        &f.book,
        &[
            "finding",
            "review",
            &selected,
            "--action",
            "acknowledge",
            "--note",
            "Self review attempt",
            "--as",
            "investigator",
        ],
        None,
    );
    assert_eq!(exit, 7, "{refusal:?}");
    assert_eq!(text(data(&refusal[0]), "refusal_id"), "FA-REF-008");
    assert_eq!(f.head(), before, "self-review must publish nothing");

    let acknowledgement = [
        "finding",
        "review",
        &selected,
        "--action",
        "acknowledge",
        "--note",
        "Reviewed source with the preparer",
        "--as",
        "reviewer",
    ];
    let acknowledged = ok(&f.book, &acknowledgement);
    let first = data(&acknowledged).get("review").unwrap();
    let previous = format!("R:{}", text(first, "review_vid"));
    let acknowledged_at = number(first, "recorded_at").to_string();
    let after_ack = f.head();
    let exact_ack = ok(&f.book, &acknowledgement);
    assert_eq!(
        data(&exact_ack).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(f.head(), after_ack);
    let (exit, stale) = call(
        &f.book,
        &[
            "finding",
            "review",
            &selected,
            "--action",
            "acknowledge",
            "--note",
            "A competing decision without its predecessor",
            "--as",
            "second-reviewer",
        ],
        None,
    );
    assert_eq!(exit, 6, "{stale:?}");
    assert_eq!(f.head(), after_ack);

    let (exit, missing) = call(
        &f.book,
        &[
            "finding",
            "review",
            &selected,
            "--action",
            "dismiss",
            "--dismissal-reason",
            "explained",
            "--previous",
            &previous,
            "--note",
            "Evidence was not actually supplied",
            "--as",
            "reviewer",
        ],
        None,
    );
    assert_eq!(exit, 2, "{missing:?}");
    assert_eq!(f.head(), after_ack);
    let dismissal = ok(
        &f.book,
        &[
            "finding",
            "review",
            &selected,
            "--action",
            "dismiss",
            "--dismissal-reason",
            "explained",
            "--previous",
            &previous,
            "--note",
            "Source document explains the approved weekend posting",
            "--evidence",
            &f.evidence,
            "--as",
            "reviewer",
        ],
    );
    let decision = data(&dismissal).get("review").unwrap();
    let dismissed_at = number(decision, "recorded_at").to_string();
    let dismissed_previous = format!("R:{}", text(decision, "review_vid"));
    assert_eq!(text(decision, "reason"), "explained");

    let shown = ok(&f.book, &["finding", "show", &selected]);
    let current = data(&shown).get("row").unwrap();
    assert_eq!(text(current, "status"), "Dismissed");
    assert_eq!(current.get("finding"), Some(&original_value));
    assert_eq!(
        current.get("reviews").and_then(Json::as_arr).unwrap().len(),
        2
    );
    let prior = ok(
        &f.book,
        &["finding", "show", &selected, "--known-at", &acknowledged_at],
    );
    assert_eq!(text(data(&prior).get("row").unwrap(), "status"), "Reviewed");
    let first_view = ok(
        &f.book,
        &[
            "finding",
            "list",
            "--certificate",
            &certificate,
            "--known-at",
            &published,
        ],
    );
    assert_eq!(
        text(
            &data(&first_view)
                .get("findings")
                .and_then(Json::as_arr)
                .unwrap()[0],
            "status"
        ),
        "Open"
    );

    let (_, reviewed) = f.export(
        &certificate,
        "dismissed-review.fawp",
        true,
        Some(&dismissed_at),
    );
    let review_text = ok(
        &f.book,
        &[
            "finding",
            "export",
            "--certificate",
            &certificate,
            "--include-reviews",
            "--known-at",
            &dismissed_at,
            "--export-format",
            "jsonl",
        ],
    );
    let content = text(data(&review_text), "content");
    assert!(
        content.contains("\"event\":\"finding\""),
        "original observations must be in a review export"
    );
    assert!(content.contains("Source document explains"), "{content}");
    let (_, unchanged) = f.export(&certificate, "original-after-review.fawp", false, None);
    assert_eq!(
        original, unchanged,
        "review appendices never rewrite the original workpaper"
    );

    ok(
        &f.book,
        &[
            "finding",
            "review",
            &selected,
            "--action",
            "reopen",
            "--previous",
            &dismissed_previous,
            "--note",
            "Additional evidence warrants reopening",
            "--as",
            "second-reviewer",
        ],
    );
    f.post("later", "2026-01-12", "23.00 USD");
    let after = f.head();
    let (exit, replayed) = call(
        &f.book,
        &[
            "finding",
            "replay",
            "-",
            "--certificate",
            &certificate,
            "--known-at",
            &dismissed_at,
        ],
        Some(&reviewed),
    );
    assert_eq!(exit, 0, "{replayed:?}");
    assert_eq!(text(data(&replayed[0]), "scope"), "recipient-bound");
    assert_eq!(
        number(data(&replayed[0]), "review_known_at").to_string(),
        dismissed_at
    );
    let (exit, old_delivery) = call(
        &f.book,
        &[
            "finding",
            "replay",
            "-",
            "--certificate",
            &certificate,
            "--known-at",
            &dismissed_at,
        ],
        Some(&open_review),
    );
    assert_eq!(
        exit, 8,
        "a genuine older packet must not satisfy a later request: {old_delivery:?}"
    );
    let (exit, historical) = call(&f.book, &["finding", "replay", "-"], Some(&open_review));
    assert_eq!(exit, 0, "{historical:?}");
    assert_eq!(text(data(&historical[0]), "scope"), "as-supplied");
    let (exit, missing_reviews) = call(
        &f.book,
        &[
            "finding",
            "replay",
            "-",
            "--certificate",
            &certificate,
            "--known-at",
            &dismissed_at,
        ],
        Some(&original),
    );
    assert_eq!(exit, 8, "{missing_reviews:?}");
    assert_eq!(
        f.head(),
        after,
        "replay neither writes nor replaces current decisions"
    );
    let shown = ok(&f.book, &["finding", "show", &selected]);
    assert_eq!(text(data(&shown).get("row").unwrap(), "status"), "Open");
}

#[test]
fn replay_refuses_rehashed_false_text_and_exports_never_overwrite_files() {
    let f = Fixture::new();
    let recorded = ok(
        &f.book,
        &["finding", "record", "jet.weekend", "--as", "investigator"],
    );
    let certificate = text(data(&recorded), "certificate");
    let (_, bytes) = f.export(certificate, "canonical.fawp", false, None);
    let original_path = f.root.join("canonical.fawp");
    let before = f.head();
    let (exit, unchanged) = call(
        &f.book,
        &[
            "finding",
            "export",
            "--certificate",
            certificate,
            "--export-format",
            "canonical",
            "--out",
            original_path.to_str().unwrap(),
        ],
        None,
    );
    assert_ne!(exit, 0, "{unchanged:?}");
    assert_eq!(std::fs::read(&original_path).unwrap(), bytes);
    let (exit, good) = call(
        &f.book,
        &["finding", "replay", "-"],
        Some(hex(&bytes).as_bytes()),
    );
    assert_eq!(exit, 0, "{good:?}");
    let mut forged = bytes.clone();
    let needle = b"# Finding workpaper";
    let position = forged
        .windows(needle.len())
        .position(|window| window == needle)
        .unwrap();
    forged[position + 2] = b'X';
    let end = forged.len() - 32;
    let public_checksum =
        fa_model::domain_digest(b"fa:finding-workpaper-digest:v1", &[&forged[..end]]);
    forged[end..].copy_from_slice(&public_checksum);
    assert!(
        fa::findings::FindingWorkpaper::decode(&forged).is_ok(),
        "the planted defect must reach native replay rather than fail framing"
    );
    let (exit, false_text) = call(&f.book, &["finding", "replay", "-"], Some(&forged));
    assert_eq!(exit, 8, "{false_text:?}");
    assert_eq!(false_text.len(), 1);
    let (exit, wrong_format) = call(
        &f.book,
        &["finding", "replay", "-"],
        Some(b"# A Markdown presentation alone"),
    );
    assert_eq!(exit, 8, "{wrong_format:?}");
    let (exit, floating) = call(
        &f.book,
        &[
            "finding",
            "record",
            "jet.round_amounts",
            "--param",
            "round_power=2.5",
        ],
        None,
    );
    assert_eq!(exit, 2, "{floating:?}");
    let (exit, duplicate) = call(
        &f.book,
        &[
            "finding",
            "record",
            "jet.round_amounts",
            "--param",
            "round_power=2",
            "--param",
            "round_power=3",
        ],
        None,
    );
    assert_eq!(exit, 2, "{duplicate:?}");
    assert_eq!(
        f.head(),
        before,
        "malformed input and failed replay must publish nothing"
    );
}

#[test]
fn empty_certified_runs_are_recorded_and_replayed_as_complete_empty_results() {
    let f = Fixture::new();
    let recorded = ok(
        &f.book,
        &[
            "finding",
            "record",
            "jet.weekend",
            "--effective-through",
            "2026-01-09",
        ],
    );
    let certificate = text(data(&recorded), "certificate");
    assert_eq!(number(data(&recorded), "finding_count"), 0);
    assert!(
        data(&recorded)
            .get("finding_ids")
            .and_then(Json::as_arr)
            .unwrap()
            .is_empty()
    );
    let before = f.head();
    let listed = ok(&f.book, &["finding", "list", "--certificate", certificate]);
    assert_eq!(number(data(&listed), "finding_count"), 0);
    assert!(
        data(&listed)
            .get("findings")
            .and_then(Json::as_arr)
            .unwrap()
            .is_empty()
    );
    let (_, packet) = f.export(certificate, "empty.fawp", true, None);
    let (exit, replayed) = call(&f.book, &["finding", "replay", "-"], Some(&packet));
    assert_eq!(exit, 0, "{replayed:?}");
    assert_eq!(number(data(&replayed[0]), "finding_count"), 0);
    assert_eq!(f.head(), before);
}

#[test]
fn bound_finding_operations_require_current_explicit_ops_before_any_observation() {
    let missing = temporary().join("not-a-book");
    let reader = LaunchAuthority::new(
        missing.clone(),
        None,
        "bound-reader",
        LaunchProfile::Agent,
        &["read"],
    )
    .unwrap();
    for argv in [
        vec!["finding", "record", "jet.weekend", "--json"],
        vec![
            "finding",
            "export",
            "--certificate",
            "not-even-parsed",
            "--json",
        ],
        vec![
            "finding",
            "review",
            "not-even-parsed",
            "--action",
            "dismiss",
            "--json",
        ],
    ] {
        let argv: Vec<String> = argv.into_iter().map(str::to_string).collect();
        let (exit, out) = run_with_authority(
            &argv,
            Books::Dir,
            Files {
                cwd: None,
                stdin: Stdin::Missing,
            },
            &reader,
            true,
        );
        assert_eq!(exit, 7, "{out:?}");
        let lines = events(&out.stdout);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].get("book"), Some(&Json::Null));
        assert_eq!(lines[0].get("authority"), Some(&reader.envelope_json()));
        assert_eq!(text(data(&lines[0]), "refusal_id"), "FA-REF-011");
    }
    assert!(!missing.exists());
    let f = Fixture::new();
    let producer = LaunchAuthority::new(
        f.book.clone(),
        None,
        "bound-investigator",
        LaunchProfile::Agent,
        &["read", "produce"],
    )
    .unwrap();
    let argv = ["finding", "record", "jet.weekend", "--json"].map(str::to_string);
    let (exit, out) = run_with_authority(
        &argv,
        Books::Dir,
        Files {
            cwd: None,
            stdin: Stdin::Missing,
        },
        &producer,
        true,
    );
    assert_eq!(
        exit, 0,
        "recording evidence with explicit read+produce does not require monetary trunk authority: {out:?}"
    );
    let lines = events(&out.stdout);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].get("authority"), Some(&producer.envelope_json()));
    assert_eq!(
        text(data(&lines[0]), "producer"),
        format!("{:032x}", producer.principal_vid().0)
    );
    assert_eq!(number(data(&lines[0]), "finding_count"), 1);
}
