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
    before_first_post: u64,
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
        let before_first_post =
            u64::try_from(number(document.get("coordinate").unwrap(), "known_at")).unwrap();
        let fixture = Self {
            root,
            book,
            evidence,
            before_first_post,
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
fn recorded_run_discovery_pages_a_fixed_inventory_across_processes_and_new_publications() {
    let f = Fixture::new();
    let before = f.head();
    let empty = ok(&f.book, &["finding", "runs"]);
    assert_eq!(text(&empty, "event"), "finding_runs");
    assert_eq!(text(data(&empty), "scope"), "recorded-runs");
    assert_eq!(number(data(&empty), "total_recorded_runs"), 0);
    assert_eq!(number(data(&empty), "page_count"), 0);
    assert_eq!(data(&empty).get("next_cursor"), Some(&Json::Null));
    assert_eq!(f.head(), before, "an empty inventory is a read");

    let record = |extra: &[&str]| {
        let mut args = vec![
            "finding",
            "record",
            "jet.weekend",
            "--as",
            "run-investigator",
        ];
        args.extend_from_slice(extra);
        ok(&f.book, &args)
    };
    // Weekend v1 scans live postings at known-at and takes no effective date
    // (fa-9pjp refuses one; a dated recorded run is in
    // an_effective_date_is_refused_where_a_procedure_would_ignore_it).
    let before_first_post = f.before_first_post.to_string();
    let empty_run = record(&["--known-at", &before_first_post]);
    assert_eq!(
        number(data(&empty_run), "source_known_at"),
        i128::from(f.before_first_post),
    );
    let populated = record(&[]);
    f.post("second-saturday", "2026-01-17", "25.00 USD");
    let third = record(&[]);
    let records = [empty_run, populated, third];
    let frontier = f.head();
    let cutoff = frontier.to_string();
    let all = ok(&f.book, &["finding", "runs"]);
    let all_data = data(&all);
    let all_rows = all_data.get("runs").and_then(Json::as_arr).unwrap();
    assert_eq!(number(all_data, "total_recorded_runs"), 3);
    assert_eq!(number(all_data, "page_count"), 3);
    assert_eq!(number(all_data, "known_at"), i128::from(frontier));
    assert_eq!(number(all_data, "checked_through"), i128::from(frontier));
    assert_eq!(all_data.get("next_cursor"), Some(&Json::Null));
    for (row, recorded) in all_rows.iter().zip(&records) {
        for field in [
            "run_vid",
            "certificate",
            "recorded_at",
            "producer",
            "source_known_at",
            "effective_through",
            "procedure",
            "version",
            "finding_count",
            "findings_digest",
        ] {
            assert_eq!(
                row.get(field),
                data(recorded).get(field),
                "{field}: {row:?}"
            );
        }
        assert!(
            row.get("status").is_none(),
            "run inventory does not infer review status"
        );
    }
    assert_eq!(number(&all_rows[0], "finding_count"), 0);
    assert_eq!(number(&all_rows[1], "finding_count"), 1);
    assert_eq!(number(&all_rows[2], "finding_count"), 2);

    let first = ok(&f.book, &["finding", "runs", "--page-size", "1"]);
    let first_data = data(&first);
    assert_eq!(
        first_data.get("runs").and_then(Json::as_arr).unwrap(),
        &all_rows[..1]
    );
    assert_eq!(
        first_data.get("inventory_digest"),
        all_data.get("inventory_digest")
    );
    let cursor = text(first_data, "next_cursor").to_string();
    assert_eq!(cursor.len(), 192, "complete native cursor, not its digest");
    assert!(cursor.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(f.head(), frontier, "inventory discovery publishes nothing");

    // Both a new analytic publication and a human review arrive between pages.
    // Continuation keeps the original inventory while checking current history.
    f.post("later-sunday", "2026-01-18", "50.00 USD");
    let fourth = record(&[]);
    let finding = data(&records[1])
        .get("finding_ids")
        .and_then(Json::as_arr)
        .unwrap()[0]
        .as_str()
        .unwrap();
    ok(
        &f.book,
        &[
            "finding",
            "review",
            finding,
            "--action",
            "acknowledge",
            "--note",
            "Reviewed the original source after inventory selection",
            "--as",
            "run-reviewer",
        ],
    );
    let after = f.head();
    let middle = ok(
        &f.book,
        &[
            "finding",
            "runs",
            "--page-size",
            "1",
            "--cursor",
            &cursor,
            "--known-at",
            "HEAD",
        ],
    );
    let middle_data = data(&middle);
    assert_eq!(
        middle_data.get("runs").and_then(Json::as_arr).unwrap(),
        &all_rows[1..2]
    );
    assert_eq!(number(middle_data, "known_at"), i128::from(frontier));
    assert_eq!(number(middle_data, "checked_through"), i128::from(after));
    assert_eq!(number(middle_data, "total_recorded_runs"), 3);
    assert_eq!(
        middle_data.get("inventory_digest"),
        first_data.get("inventory_digest")
    );
    assert_eq!(
        number(middle.get("coordinate").unwrap(), "known_at"),
        i128::from(frontier)
    );
    let repeated = ok(
        &f.book,
        &["finding", "runs", "--page-size", "1", "--cursor", &cursor],
    );
    assert_eq!(
        data(&repeated),
        middle_data,
        "the same continuation reopens reproducibly"
    );

    let last = ok(
        &f.book,
        &[
            "finding",
            "runs",
            "--page-size",
            "2",
            "--cursor",
            text(middle_data, "next_cursor"),
            "--known-at",
            &cutoff,
        ],
    );
    assert_eq!(
        data(&last).get("runs").and_then(Json::as_arr).unwrap(),
        &all_rows[2..]
    );
    assert_eq!(data(&last).get("next_cursor"), Some(&Json::Null));
    assert_eq!(number(data(&last), "page_count"), 1);
    assert_eq!(
        data(&last).get("inventory_digest"),
        first_data.get("inventory_digest")
    );
    let fresh = ok(&f.book, &["finding", "runs", "--page-size", "32"]);
    assert_eq!(number(data(&fresh), "total_recorded_runs"), 4);
    assert_eq!(
        data(&fresh)
            .get("runs")
            .and_then(Json::as_arr)
            .unwrap()
            .last()
            .unwrap()
            .get("certificate"),
        data(&fourth).get("certificate"),
    );
    assert_ne!(
        data(&fresh).get("inventory_digest"),
        first_data.get("inventory_digest")
    );

    let mut changed = cursor.clone();
    let tail = changed.pop().unwrap();
    changed.push(if tail == '0' { '1' } else { '0' });
    let moved_cutoff = after.to_string();
    for args in [
        vec!["finding", "runs", "--cursor", changed.as_str()],
        vec![
            "finding",
            "runs",
            "--cursor",
            &cursor,
            "--known-at",
            &moved_cutoff,
        ],
    ] {
        let (exit, rejected) = call(&f.book, &args, None);
        assert_eq!(exit, 8, "{args:?}: {rejected:?}");
        assert_eq!(text(data(&rejected[0]), "refusal_id"), "FA-REF-150");
    }
    for args in [
        vec!["finding", "runs", "--cursor", ""],
        vec!["finding", "runs", "--page-size", "0"],
        vec!["finding", "runs", "--page-size", "33"],
    ] {
        let (exit, rejected) = call(&f.book, &args, None);
        assert_eq!(exit, 2, "{args:?}: {rejected:?}");
    }
    assert_eq!(
        f.head(),
        after,
        "pages, retries and invalid continuations are reads"
    );
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
    let before_first_post = f.before_first_post.to_string();
    let recorded = ok(
        &f.book,
        &[
            "finding",
            "record",
            "jet.weekend",
            "--known-at",
            &before_first_post,
        ],
    );
    let certificate = text(data(&recorded), "certificate");
    assert_eq!(
        number(data(&recorded), "source_known_at"),
        i128::from(f.before_first_post),
    );
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

#[test]
fn a_run_review_decides_several_findings_in_one_transaction_or_none() {
    let f = Fixture::new();
    // A second weekend entry: jet.weekend now reports two findings.
    f.post("sunday", "2026-01-11", "40.00 USD");
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
    let record = data(&recorded);
    let certificate = text(record, "certificate").to_string();
    let findings: Vec<String> = record
        .get("finding_ids")
        .and_then(Json::as_arr)
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap().to_string())
        .collect();
    assert_eq!(findings.len(), 2, "{record:?}");
    let reviews = f.root.join("reviews.json");
    let review_run = |file: &str| {
        call(
            &f.book,
            &[
                "finding",
                "review",
                "--certificate",
                &certificate,
                "--file",
                file,
                "--as",
                "reviewer",
            ],
            None,
        )
    };
    let before = f.head();

    // One refused decision refuses the whole set: nothing is published.
    std::fs::write(
        &reviews,
        format!(
            r#"[{{"finding":"F:{}","action":"acknowledge","note":"Reviewed the Saturday entry"}},{{"finding":"F:{}","action":"dismiss","dismissal_reason":"explained","note":"No document attached"}}]"#,
            findings[0], findings[1]
        ),
    )
    .unwrap();
    let (exit, refused) = review_run(reviews.to_str().unwrap());
    assert_eq!(exit, 2, "{refused:?}");
    assert!(
        text(data(&refused[0]), "message")
            .contains("reviews[1]: dismissing a finding requires retained evidence"),
        "{refused:?}"
    );
    // Its fix names the file's field, never a flag the run review refuses.
    let fix = text(data(&refused[0]), "fix");
    assert!(
        fix.contains(r#""evidence":["D:"#) && !fix.contains("--evidence"),
        "{refused:?}"
    );
    assert_eq!(f.head(), before, "a refused run review publishes nothing");
    // A run review that forgets --file is told so.
    let (exit, refused) = call(
        &f.book,
        &[
            "finding",
            "review",
            "--certificate",
            &certificate,
            "--as",
            "reviewer",
        ],
        None,
    );
    assert_eq!(exit, 2, "{refused:?}");
    let message = text(data(&refused[0]), "message");
    assert!(
        message.contains("--file") && !message.contains("names no F:"),
        "{refused:?}"
    );

    for (body, why) in [
        (
            format!(
                r#"[{{"finding":"F:{}","action":"acknowledge","note":"x","reviewer":"me"}}]"#,
                findings[0]
            ),
            "an unknown field",
        ),
        ("[]".to_string(), "an empty selection"),
        (
            format!(r#"{{"finding":"F:{}"}}"#, findings[0]),
            "an object instead of an array",
        ),
    ] {
        std::fs::write(&reviews, body).unwrap();
        let (exit, refused) = review_run(reviews.to_str().unwrap());
        assert_eq!(exit, 2, "{why}: {refused:?}");
        assert_eq!(f.head(), before, "{why}");
    }
    let (exit, refused) = call(
        &f.book,
        &[
            "finding",
            "review",
            "--certificate",
            &certificate,
            "--file",
            reviews.to_str().unwrap(),
            "--note",
            "a single-review flag",
            "--as",
            "reviewer",
        ],
        None,
    );
    assert_eq!(exit, 2, "single-review flags never mix in: {refused:?}");

    // Both decisions in one native transaction: one publication, certified order.
    std::fs::write(
        &reviews,
        format!(
            r#"[{{"finding":"F:{}","action":"dismiss","dismissal_reason":"explained","note":"Supported by the retained invoice","evidence":["D:{}"]}},{{"finding":"F:{}","action":"acknowledge","note":"Reviewed the Saturday entry"}}]"#,
            findings[1], f.evidence, findings[0]
        ),
    )
    .unwrap();
    let (exit, decided) = review_run(reviews.to_str().unwrap());
    assert_eq!(exit, 0, "{decided:?}");
    assert_eq!(decided.len(), 2, "{decided:?}");
    let reviewed: Vec<&Json> = decided
        .iter()
        .map(|event| {
            assert_eq!(text(event, "event"), "finding_reviewed");
            data(event).get("review").unwrap()
        })
        .collect();
    assert_eq!(
        reviewed[0].get("recorded_at"),
        reviewed[1].get("recorded_at"),
        "one native transaction"
    );
    assert_eq!(
        [
            text(reviewed[0], "finding_vid"),
            text(reviewed[1], "finding_vid")
        ],
        [findings[0].as_str(), findings[1].as_str()],
        "certified occurrence order, not request order"
    );
    assert_eq!(text(reviewed[0], "action"), "acknowledge");
    assert_eq!(text(reviewed[1], "action"), "dismiss");
    assert!(f.head() > before);
}

/// fa-nwgf end to end (plan §9.4 BalanceAssertionDrift): January cash is
/// attested at 100.00 USD; a January entry recorded afterwards moves the cell
/// by 25.00 USD while a February entry does not. `recon.assertion_drift`
/// reports exactly one finding citing the attestation and the later January
/// entry; a rerun is identical, and the certified run records once.
#[test]
fn a_later_entry_into_an_attested_month_is_one_assertion_drift_finding() {
    let f = Fixture::new();
    let post = |key: &str, day: &str, amount: &str| -> String {
        let path = f.root.join(format!("{key}.json"));
        std::fs::write(&path, format!(r#"{{"idempotency_key":"{key}","effective_date":"{day}","legs":[{{"side":"debit","account":"1000","amount":"{amount}"}},{{"side":"credit","account":"3000","amount":"{amount}"}}]}}"#)).unwrap();
        let posted = ok(
            &f.book,
            &[
                "post",
                "--intent",
                path.to_str().unwrap(),
                "--evidence",
                &f.evidence,
            ],
        );
        text(data(&posted), "vid").to_string()
    };
    let attested = ok(
        &f.book,
        &[
            "attest",
            "register-equals",
            "--account",
            "1000",
            "--period",
            "FY2026-P01",
            "--grant",
            "reconcile",
        ],
    );
    let attestation = text(data(&attested), "attestation_vid").to_string();
    let drift = |f: &Fixture| -> Json {
        let run = ok(&f.book, &["procedure", "run", "recon.assertion_drift"]);
        data(&run).clone()
    };
    let before = drift(&f);
    assert_eq!(number(&before, "finding_count"), 0, "{before:?}");

    let late = post("late-january", "2026-01-20", "25.00 USD");
    ok(&f.book, &["period", "open", "FY2026-P02"]);
    let february = post("february", "2026-02-02", "7.00 USD");
    let after = drift(&f);
    assert_eq!(number(&after, "finding_count"), 1, "{after:?}");
    assert_eq!(text(&after, "claim"), "invariant");
    let finding = &after.get("findings").and_then(Json::as_arr).unwrap()[0];
    assert_eq!(text(finding, "severity"), "Critical");
    let statistic = finding.get("statistic").unwrap();
    assert_eq!(text(statistic, "name"), "assertion_drift");
    assert_eq!(number(statistic, "value"), 2_500);
    let cites = finding.get("cites").and_then(Json::as_arr).unwrap();
    let of = |kind: &str, field: &str| -> Vec<String> {
        cites
            .iter()
            .filter(|c| text(c, "kind") == kind)
            .map(|c| text(c, field).to_string())
            .collect()
    };
    assert_eq!(of("attestation", "attestation"), vec![attestation]);
    assert_eq!(of("entry", "entry"), [late], "only the later January entry");
    assert!(!of("entry", "entry").contains(&february));
    assert_eq!(of("period", "period"), ["FY2026-P01"]);
    let narrative = text(finding, "narrative");
    assert!(
        narrative.contains("attested 100.00 USD") && narrative.contains("drift 25.00 USD"),
        "{narrative}"
    );

    // Deterministic: the same findings at the same head.
    let again = drift(&f);
    assert_eq!(
        text(&again, "findings_digest"),
        text(&after, "findings_digest")
    );

    // The certified run records its finding; its retry command returns the
    // same recorded run.
    let (code, recorded) = call(
        &f.book,
        &["finding", "record", "recon.assertion_drift"],
        None,
    );
    assert_eq!(code, 0, "{recorded:?}");
    let recorded = recorded
        .into_iter()
        .find(|e| text(e, "event") == "findings_recorded")
        .expect("findings_recorded");
    let recorded = data(&recorded);
    assert_eq!(number(recorded, "finding_count"), 1);
    assert_eq!(recorded.get("already_recorded"), Some(&Json::Bool(false)));
    let retry: Vec<String> = text(recorded, "retry_command")
        .split_whitespace()
        .skip(1)
        .filter(|w| *w != "--json")
        .map(str::to_string)
        .collect();
    let retry: Vec<&str> = retry.iter().map(String::as_str).collect();
    let (code, again) = call(&f.book, &retry, None);
    assert_eq!(code, 0, "{retry:?}: {again:?}");
    let again = again
        .into_iter()
        .find(|e| text(e, "event") == "findings_recorded")
        .expect("findings_recorded");
    assert_eq!(
        data(&again).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(text(data(&again), "run_vid"), text(recorded, "run_vid"));
}

/// A procedure whose total leaves the 128-bit range refuses through the real
/// binary with exit 3 and the accumulator named, never a wrapped, clamped or
/// panicking number (FA-INV-06; fa-4aym). Each posting is within range: only
/// the concentration procedure's unit volume overflows.
#[test]
fn a_procedure_total_beyond_i128_is_a_typed_refusal() {
    let root = temporary();
    let book = root.join("book");
    ok(&book, &["book", "create", "--name", "Wide totals"]);
    let chart = root.join("chart.json");
    std::fs::write(&chart, r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"1010","name":"Bank","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"},{"code":"6000","name":"Expense","type":"Expense","unit":"USD"}]}"#).unwrap();
    ok(&book, &["chart", "import", chart.to_str().unwrap()]);
    ok(&book, &["period", "create", "--fiscal-year", "2026"]);
    ok(&book, &["period", "open", "FY2026-P01"]);
    let source = root.join("source.txt");
    std::fs::write(&source, "Supporting document for the wide-total entries.").unwrap();
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
    // i128::MAX cents, then one more cent on other accounts.
    let mut known_at = Vec::new();
    for (key, day, debit, credit, amount) in [
        (
            "max",
            "2026-01-05",
            "1010",
            "1000",
            "1701411834604692317316873037158841057.27 USD",
        ),
        ("cent", "2026-01-06", "6000", "4000", "0.01 USD"),
    ] {
        let path = root.join(format!("{key}.json"));
        std::fs::write(&path, format!(r#"{{"idempotency_key":"{key}","effective_date":"{day}","legs":[{{"side":"debit","account":"{debit}","amount":"{amount}"}},{{"side":"credit","account":"{credit}","amount":"{amount}"}}]}}"#)).unwrap();
        let posted = ok(
            &book,
            &[
                "post",
                "--intent",
                path.to_str().unwrap(),
                "--evidence",
                &evidence,
            ],
        );
        known_at.push(number(posted.get("coordinate").unwrap(), "known_at"));
    }
    let (exit, events) = call(&book, &["procedure", "run", "graph.concentration"], None);
    assert_eq!(exit, 3, "{events:?}");
    let error = data(&events[0]);
    assert_eq!(text(error, "class"), "refusal");
    assert!(
        text(error, "message").contains("graph.concentration unit volume"),
        "{error:?}"
    );
    // The fix names the narrowing every procedure honors: at the sequence
    // that recorded only the first entry, the same procedure runs.
    assert!(text(error, "fix").contains("--known-at"), "{error:?}");
    let first = known_at[0].to_string();
    let narrowed = ok(
        &book,
        &[
            "procedure",
            "run",
            "graph.concentration",
            "--known-at",
            &first,
        ],
    );
    assert_eq!(text(&narrowed, "event"), "procedure_run");
}

/// A date reaches only procedures that use one (fa-9pjp): one given to a
/// procedure that folds every posting regardless of effective date is a
/// usage error on run and on record, never silently ignored, and the
/// registry's effective_through for each procedure is visible in the list.
#[test]
fn an_effective_date_is_refused_where_a_procedure_would_ignore_it() {
    let f = Fixture::new();
    for argv in [
        &[
            "procedure",
            "run",
            "jet.round_amounts",
            "--effective-through",
            "2026-01-31",
        ][..],
        &[
            "finding",
            "record",
            "jet.round_amounts",
            "--effective-through",
            "2026-01-31",
        ][..],
    ] {
        let before = f.head();
        let (exit, events) = call(&f.book, argv, None);
        assert_eq!(exit, 2, "{argv:?}: {events:?}");
        assert!(
            text(data(&events[0]), "message").contains("does not take --effective-through"),
            "{events:?}"
        );
        assert!(
            text(data(&events[0]), "fix").contains("--known-at"),
            "{events:?}"
        );
        assert_eq!(f.head(), before, "{argv:?} wrote nothing");
    }
    let run = ok(
        &f.book,
        &[
            "procedure",
            "run",
            "lookback.preferences",
            "--effective-through",
            "2026-01-31",
        ],
    );
    assert_eq!(text(&run, "event"), "procedure_run");
    // A recorded run keeps the date it was given; the inventory reports it.
    let recorded = ok(
        &f.book,
        &[
            "finding",
            "record",
            "lookback.preferences",
            "--effective-through",
            "2026-01-31",
        ],
    );
    let runs = ok(&f.book, &["finding", "runs"]);
    let row = data(&runs)
        .get("runs")
        .and_then(Json::as_arr)
        .unwrap()
        .iter()
        .find(|r| r.get("run_vid") == data(&recorded).get("run_vid"))
        .expect("the recorded run is listed");
    assert_eq!(text(row, "effective_through"), "2026-01-31");
    let list = ok(&f.book, &["procedure", "list"]);
    let rows = data(&list)
        .get("procedures")
        .and_then(Json::as_arr)
        .unwrap();
    let declared = |id: &str| {
        let row = rows.iter().find(|r| text(r, "id") == id).expect(id);
        text(row, "effective_through").to_string()
    };
    assert_eq!(declared("jet.round_amounts"), "not_taken");
    assert_eq!(declared("lookback.preferences"), "optional");
    assert_eq!(declared("aging.open_items"), "required");
}
