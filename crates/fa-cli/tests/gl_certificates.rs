//! Native GL workpapers become durable, replayable operator artifacts without
//! changing their selected accounting values or granting saved authority.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};

fn temporary() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "fa-gl-certificates-{}-{}",
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

fn events(stdout: &str) -> Vec<Json> {
    let registry = fa_cli::verbs::registry().unwrap();
    stdout
        .lines()
        .map(|line| {
            registry
                .check_line(line)
                .unwrap_or_else(|error| panic!("robot schema: {error}\n{line}"));
            json::parse(line).unwrap()
        })
        .collect()
}

fn run(book: &Path, args: &[&str]) -> (i32, Vec<Json>, String) {
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
    (
        output.status.code().unwrap_or(-1),
        events(&stdout),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn ok(book: &Path, args: &[&str]) -> Vec<Json> {
    let (exit, events, stderr) = run(book, args);
    assert_eq!(exit, 0, "args={args:?}\n{events:?}\n{stderr}");
    events
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
    let info = ok(book, &["book", "info"]);
    number(info[0].get("coordinate").unwrap(), "known_at")
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
        ok(&book, &["book", "create", "--name", "Certified GL"]);
        let chart = dir.join("chart.json");
        std::fs::write(&chart, r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"3000","name":"Capital","type":"Equity","unit":"USD"},{"code":"4000","name":"Sales","type":"Revenue","unit":"USD"}]}"#).unwrap();
        ok(&book, &["chart", "import", chart.to_str().unwrap()]);
        ok(&book, &["period", "create", "--fiscal-year", "2026"]);
        for period in ["FY2026-P02", "FY2026-P03"] {
            ok(&book, &["period", "open", period]);
        }
        let source = dir.join("source.txt");
        std::fs::write(
            &source,
            b"Capital and sales evidence for retained GL reports",
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
        let fixture = Self {
            dir,
            book,
            evidence: text(data(&document[0]), "oid").into(),
        };
        fixture.post("opening", "2026-02-10", "3000", "100.00 USD");
        fixture.post("sale", "2026-03-15", "4000", "25.00 USD");
        fixture
    }

    fn post(&self, key: &str, day: &str, credit: &str, amount: &str) {
        let path = self.dir.join(format!("{key}.json"));
        std::fs::write(&path, format!(r#"{{"idempotency_key":"{key}","effective_date":"{day}","legs":[{{"side":"debit","account":"1000","amount":"{amount}"}},{{"side":"credit","account":"{credit}","amount":"{amount}"}}]}}"#)).unwrap();
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
fn detail_roll_forward_and_aging_retain_their_complete_sources_and_replay_after_corrections() {
    let fixture = Fixture::new();
    let selected = head(&fixture.book).to_string();
    let mut saved = Vec::new();
    for (sub, event, family, output_format) in [
        (
            "detail",
            "general_ledger",
            "roll-forward",
            "fa:roll-forward:v1",
        ),
        (
            "roll-forward",
            "roll_forward",
            "roll-forward",
            "fa:roll-forward:v1",
        ),
        (
            "aging",
            "aging",
            "effective-date-aging",
            "fa:effective-date-aging:v1",
        ),
    ] {
        let mut args = vec!["gl", sub, "--account", "1000", "--as-known-at", &selected];
        if sub == "aging" {
            args.extend(["--as-of", "2026-03-31", "--bucket", "0,30,60"]);
        } else {
            args.extend(["--from", "2026-03-01", "--to", "2026-03-31"]);
        }
        let before = head(&fixture.book);
        let plain = ok(&fixture.book, &args);
        assert_eq!(
            head(&fixture.book),
            before,
            "uncertified {sub} must be read-only"
        );
        assert_eq!(text(&plain[0], "event"), event);

        let path = fixture.dir.join(format!("{sub}.certificate"));
        args.extend(["--certificate-out", path.to_str().unwrap()]);
        let certified = ok(&fixture.book, &args);
        assert_eq!(certified.len(), 2, "{certified:?}");
        assert_eq!(data(&certified[0]), data(&plain[0]));
        assert_eq!(text(&certified[0], "event"), event);
        assert_eq!(text(&certified[1], "event"), "report_certificate");
        let certificate = data(&certified[1]);
        let oid = text(certificate, "oid").to_string();
        assert_eq!(text(&certified[0], "certificate"), oid);
        assert_eq!(text(certificate, "output_format"), output_format);
        assert_eq!(number(certificate, "known_at").to_string(), selected);
        assert!(number(certificate, "recorded_at") > number(certificate, "known_at"));
        let bytes = std::fs::read(&path).unwrap();
        let artifact = fa::ReportArtifact::decode(&bytes).unwrap();
        assert_eq!(artifact.family().name(), family);
        assert_eq!(artifact.canonical_bytes().unwrap(), bytes);

        // The same selected prefix returns the same artifact and original
        // retention sequence, even though its first retention moved HEAD.
        args.truncate(args.len() - 2);
        args.push("--certify");
        let retained_head = head(&fixture.book);
        let retry = ok(&fixture.book, &args);
        assert_eq!(data(&retry[1]).get("oid"), certificate.get("oid"));
        assert_eq!(
            data(&retry[1]).get("recorded_at"),
            certificate.get("recorded_at")
        );
        assert_eq!(head(&fixture.book), retained_head);
        saved.push((sub, oid, artifact, certified[0].clone()));
    }

    fixture.post("later-correction", "2026-03-12", "4000", "9.00 USD");
    for (sub, oid, artifact, original_report) in saved {
        let output = fixture.dir.join(format!("{sub}.replayed"));
        let selected = format!("C:{oid}");
        let replay = ok(
            &fixture.book,
            &["replay", &selected, "--output", output.to_str().unwrap()],
        );
        assert_eq!(replay.len(), 2);
        let report_event = if sub == "aging" {
            "aging"
        } else {
            "roll_forward"
        };
        assert_eq!(text(&replay[0], "event"), report_event);
        assert_eq!(
            number(data(&replay[0]), "known_at"),
            i128::from(artifact.known_at().0),
        );
        assert_eq!(text(&replay[0], "certificate"), oid);
        if sub != "detail" {
            assert_eq!(data(&replay[0]), data(&original_report));
        }
        assert_eq!(text(&replay[1], "event"), "report_replayed");
        assert_eq!(text(data(&replay[1]), "family"), artifact.family().name());
        assert_eq!(std::fs::read(output).unwrap(), artifact.output());
        assert_eq!(text(&replay[1], "certificate"), oid);

        let mut damaged = artifact.canonical_bytes().unwrap();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        let damaged_path = fixture.dir.join(format!("{sub}.damaged"));
        std::fs::write(&damaged_path, damaged).unwrap();
        let (exit, refused, _) = run(&fixture.book, &["replay", damaged_path.to_str().unwrap()]);
        assert_eq!(exit, 8, "{refused:?}");
        assert_eq!(refused.len(), 1);
        assert_eq!(text(&refused[0], "event"), "error");
        assert_eq!(refused[0].get("certificate"), Some(&Json::Null));
    }
}

#[test]
fn certification_refuses_unsupported_modes_and_existing_output_without_writes() {
    let fixture = Fixture::new();
    let before = head(&fixture.book);
    let existing = fixture.dir.join("keep.certificate");
    std::fs::write(&existing, b"preserve this existing file").unwrap();
    for args in [
        vec!["gl", "cash-flow", "--certify"],
        vec!["gl", "lots", "--certify"],
        vec![
            "gl",
            "aging",
            "--as-of",
            "2026-03-31",
            "--reconcile",
            "--certify",
        ],
        vec![
            "gl",
            "detail",
            "--account",
            "1000",
            "--from",
            "2026-03-01",
            "--to",
            "2026-03-31",
            "--certificate-out",
            "-",
        ],
        vec![
            "gl",
            "detail",
            "--account",
            "1000",
            "--from",
            "2026-03-01",
            "--to",
            "2026-03-31",
            "--certificate-out",
            existing.to_str().unwrap(),
        ],
        vec![
            "gl",
            "aging",
            "--as-of",
            "2026-03-31",
            "--certificate-out",
            "first",
            "--certificate-out",
            "second",
        ],
    ] {
        let (exit, refused, _) = run(&fixture.book, &args);
        assert_eq!(exit, 2, "args={args:?}\n{refused:?}");
        assert_eq!(refused.len(), 1);
        assert_eq!(text(&refused[0], "event"), "error");
        assert_eq!(head(&fixture.book), before);
    }
    assert_eq!(
        std::fs::read(existing).unwrap(),
        b"preserve this existing file"
    );

    // Missing produce authority is diagnosed before opening even an absent
    // book; the caller cannot gain it by asking for a certificate output.
    let missing = fixture.dir.join("missing-book");
    let authority = fa_cli::authority::LaunchAuthority::new(
        missing.clone(),
        None,
        "reader",
        fa_cli::authority::LaunchProfile::Agent,
        &["read"],
    )
    .unwrap();
    let args = [
        "gl",
        "aging",
        "--as-of",
        "2026-03-31",
        "--certify",
        "--json",
    ]
    .map(String::from);
    let (exit, captured) =
        fa_cli::entry::fa_with_authority(&args, fa_cli::cli::Files::default(), &authority, true);
    assert_eq!(exit, 7, "{captured:?}");
    let denied = events(&captured.stdout);
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0].get("book"), Some(&Json::Null));
    assert!(captured.stdout.contains("produce"));
    assert!(!missing.exists());
}

#[test]
fn detail_replay_binds_the_independent_request_before_rendering_or_writing() {
    let fixture = Fixture::new();
    let selected = head(&fixture.book).to_string();
    let next_sequence = (selected.parse::<u64>().unwrap() + 1).to_string();
    let label = "March owner's detail";
    let scope = vec![
        "--account",
        "1000",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
        "--label",
        label,
    ];
    let certificate_path = fixture.dir.join("detail-scope.certificate");
    let certified = ok(
        &fixture.book,
        &[
            vec!["gl", "detail"],
            scope.clone(),
            vec!["--certificate-out", certificate_path.to_str().unwrap()],
        ]
        .concat(),
    );
    assert_eq!(certified.len(), 2);
    let certificate = data(&certified[1]);
    let handle = format!("C:{}", text(certificate, "oid"));
    assert_eq!(
        text(certificate, "replay_command"),
        format!(
            "fa replay {handle} --view detail --account '1000' --unit 'USD' --from 2026-03-01 --to 2026-03-31 --label 'March owner'\\''s detail' --as-known-at {selected} --book '{}' --json",
            fixture.book.display(),
        ),
        "the default unit and HEAD resolution must become explicit, safely quoted expectations",
    );
    let source_bytes = std::fs::read(&certificate_path).unwrap();
    let artifact = fa::ReportArtifact::decode(&source_bytes).unwrap();
    assert_eq!(artifact.family().name(), "roll-forward");

    fixture.post("detail-later-correction", "2026-03-12", "4000", "9.00 USD");
    let after_correction = head(&fixture.book);
    let replay_args = [
        vec![
            "replay",
            &handle,
            "--view",
            "detail",
            "--unit",
            "USD",
            "--as-known-at",
            &selected,
        ],
        scope,
    ]
    .concat();
    for input in [handle.as_str(), certificate_path.to_str().unwrap()] {
        let mut args = replay_args.clone();
        args[1] = input;
        let replay = ok(&fixture.book, &args);
        assert_eq!(replay.len(), 2);
        assert_eq!(
            replay[0], certified[0],
            "original detailed lines and coordinate"
        );
        assert_eq!(text(&replay[1], "event"), "report_replayed");
        assert_eq!(text(data(&replay[1]), "family"), "roll-forward");
        assert_eq!(
            data(&replay[1]).get("output_digest"),
            certificate.get("output_digest"),
        );
    }

    // Detail remains a view of the complete existing source. Canonical file
    // exports keep that source's original format and digest.
    let output = fixture.dir.join("detail-source.report");
    let mut with_output = replay_args.clone();
    with_output.extend(["--output", output.to_str().unwrap()]);
    let replay = ok(&fixture.book, &with_output);
    assert_eq!(replay[0], certified[0]);
    assert_eq!(std::fs::read(output).unwrap(), artifact.output());

    let refused_output = fixture.dir.join("detail-refusal-must-not-write.report");
    for (flag, replacement, expected_exit) in [
        ("--account", "4000", 8),
        ("--unit", "EUR", 8),
        ("--from", "2026-02-01", 8),
        ("--to", "2026-03-30", 8),
        ("--label", "A different request", 8),
        ("--as-known-at", next_sequence.as_str(), 8),
        ("--unit", " , ", 2),
        ("--as-known-at", "HEAD", 2),
    ] {
        let mut changed = replay_args.clone();
        let index = changed.iter().position(|value| *value == flag).unwrap();
        changed[index + 1] = replacement;
        changed.extend(["--output", refused_output.to_str().unwrap()]);
        let (exit, refused, _) = run(&fixture.book, &changed);
        assert_eq!(exit, expected_exit, "{flag}={replacement}: {refused:?}");
        assert_eq!(refused.len(), 1);
        assert_eq!(text(&refused[0], "event"), "error");
        assert_eq!(refused[0].get("certificate"), Some(&Json::Null));
        assert!(!refused_output.exists(), "a changed request must not write");
    }
    // Both independent request formats must never compete; the conflict is
    // refused even when the certificate path cannot be opened.
    let absent_source = fixture.dir.join("must-not-read.certificate");
    let mut conflicting = replay_args.clone();
    conflicting[1] = absent_source.to_str().unwrap();
    conflicting.extend(["--expect", "{}", "--output", refused_output.to_str().unwrap()]);
    let (exit, refused, _) = run(&fixture.book, &conflicting);
    assert_eq!(exit, 2, "{refused:?}");
    assert_eq!(refused.len(), 1);
    assert!(text(data(&refused[0]), "message").contains("separate request formats"));
    assert!(!refused_output.exists());

    for missing in [
        "--view",
        "--account",
        "--unit",
        "--from",
        "--to",
        "--label",
        "--as-known-at",
    ] {
        let mut changed = replay_args.clone();
        let index = changed.iter().position(|value| *value == missing).unwrap();
        drop(changed.drain(index..index + 2));
        changed.extend(["--output", refused_output.to_str().unwrap()]);
        let (exit, refused, _) = run(&fixture.book, &changed);
        assert_eq!(exit, 2, "missing {missing}: {refused:?}");
        assert_eq!(refused.len(), 1);
        assert!(!refused_output.exists());
    }
    let mut damaged = source_bytes;
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    let damaged_path = fixture.dir.join("detail-scope.damaged");
    std::fs::write(&damaged_path, damaged).unwrap();
    let mut damaged_args = replay_args;
    damaged_args[1] = damaged_path.to_str().unwrap();
    damaged_args.extend(["--output", refused_output.to_str().unwrap()]);
    let (exit, refused, _) = run(&fixture.book, &damaged_args);
    assert_eq!(exit, 8, "{refused:?}");
    assert_eq!(refused.len(), 1);
    assert!(!refused_output.exists());
    assert_eq!(head(&fixture.book), after_correction, "all replays are reads");
}

#[test]
fn instant_reads_keep_their_brackets_and_certification_requires_an_explicit_sequence() {
    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;

    const LOWER_NS: u64 = 1_773_576_000_000_000_000;
    const UPPER_NS: u64 = 1_773_576_010_000_000_000;
    const INSTANT: &str = "2026-03-15T12:00:05Z";
    let fixture = Fixture::new();
    let keys = fa::BookKeys::load(&fixture.book.join("book.keys")).unwrap();
    let mut book =
        fa::Book::open_dir(&fixture.book, keys, fa::Entropy::deterministic(120)).unwrap();
    let runtime = RuntimeBuilder::new().build().unwrap();
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    let witness =
        fa::Capability::embedded(fa_model::principal_vid("time-witness"), &["witness"]).unwrap();
    let lower = runtime
        .block_on(book.record_tick(&cx, LOWER_NS, true, &witness))
        .unwrap()
        .unwrap();
    let upper = runtime
        .block_on(book.record_tick(&cx, UPPER_NS, true, &witness))
        .unwrap()
        .unwrap();
    let selected = lower.recorded_at.0.to_string();
    drop(book);

    for sub in ["detail", "roll-forward", "aging"] {
        let mut base = vec!["gl", sub, "--account", "1000"];
        if sub == "aging" {
            base.extend(["--as-of", "2026-03-31"]);
        } else {
            base.extend(["--from", "2026-03-01", "--to", "2026-03-31"]);
        }
        let mut instant = base.clone();
        instant.extend(["--as-known-at", INSTANT]);
        let before = head(&fixture.book);
        let ordinary = ok(&fixture.book, &instant);
        assert_eq!(ordinary.len(), 1);
        let coordinate = ordinary[0].get("coordinate").unwrap();
        assert_eq!(
            number(coordinate, "known_at"),
            i128::from(lower.recorded_at.0),
        );
        let time = coordinate.get("time_evidence").unwrap();
        for (name, tick) in [("lower", &lower), ("upper", &upper)] {
            assert_eq!(
                time.get(name).and_then(|tick| tick.get("recorded_at")),
                Some(&Json::Int(i128::from(tick.recorded_at.0))),
            );
        }
        assert_eq!(head(&fixture.book), before, "ordinary {sub} is read-only");

        // A live instant query is valid, but these certificate formats cannot
        // retain its requested instant and both resolution ticks. Refuse before
        // publishing a sequence-only artifact or creating an external file.
        let path = fixture.dir.join(format!("instant-{sub}.certificate"));
        for mode in [
            vec!["--certify"],
            vec!["--certificate-out", path.to_str().unwrap()],
        ] {
            let mut args = instant.clone();
            args.extend(mode);
            let (exit, refused, stderr) = run(&fixture.book, &args);
            assert_eq!(exit, 2, "args={args:?}\n{refused:?}\n{stderr}");
            assert_eq!(refused.len(), 1);
            assert_eq!(text(&refused[0], "event"), "error");
            assert_eq!(data(&refused[0]).get("refusal_id"), Some(&Json::Null));
            assert_eq!(text(data(&refused[0]), "class"), "usage");
            assert!(text(data(&refused[0]), "message").contains("instant-resolution evidence"));
            assert!(text(data(&refused[0]), "fix").contains(&format!("--as-known-at {selected}")));
            let denied_coordinate = refused[0].get("coordinate").unwrap();
            assert_eq!(
                number(denied_coordinate, "known_at"),
                i128::from(lower.recorded_at.0),
            );
            assert_eq!(denied_coordinate.get("time_evidence"), Some(time));
            assert_eq!(head(&fixture.book), before);
            assert!(!path.exists());
        }

        // The explicitly selected recorded prefix still certifies the same
        // accounting values. Its selector no longer asserts an instant proof.
        let mut sequence = base;
        sequence.extend(["--as-known-at", &selected, "--certify"]);
        let certified = ok(&fixture.book, &sequence);
        assert_eq!(certified.len(), 2);
        assert_eq!(data(&certified[0]), data(&ordinary[0]));
        assert_eq!(text(&certified[1], "event"), "report_certificate");
        assert_eq!(
            number(data(&certified[1]), "known_at"),
            i128::from(lower.recorded_at.0),
        );
    }
}

#[test]
fn held_daemon_dispatcher_certifies_and_replays_without_an_external_path() {
    let fixture = Fixture::new();
    let keys = fa::BookKeys::load(&fixture.book.join("book.keys")).unwrap();
    let mut book =
        fa::Book::open_dir(&fixture.book, keys, fa::Entropy::deterministic(119)).unwrap();
    let args = [
        "gl",
        "roll-forward",
        "--account",
        "1000",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
        "--certify",
        "--json",
    ]
    .map(String::from);
    let (exit, captured) = fa_cli::cli::run_for_daemon(
        &args,
        &mut book,
        fixture.book.clone(),
        None,
        None,
        fa_cli::cli::Stdin::Missing,
        true,
    );
    assert_eq!(exit, 0, "{captured:?}");
    let certified = events(&captured.stdout);
    assert_eq!(certified.len(), 2);
    let oid = text(data(&certified[1]), "oid");
    let after_retention = book.head().unwrap();
    let args = ["replay".into(), format!("C:{oid}"), "--json".into()];
    let (exit, captured) = fa_cli::cli::run_for_daemon(
        &args,
        &mut book,
        fixture.book.clone(),
        None,
        None,
        fa_cli::cli::Stdin::Missing,
        true,
    );
    assert_eq!(exit, 0, "{captured:?}");
    let replay = events(&captured.stdout);
    assert_eq!(replay.len(), 2);
    assert_eq!(text(&replay[0], "event"), "roll_forward");
    assert_eq!(data(&replay[0]), data(&certified[0]));
    assert_eq!(text(&replay[1], "event"), "report_replayed");
    assert_eq!(text(data(&replay[1]), "family"), "roll-forward");
    assert_eq!(book.head().unwrap(), after_retention);
}
