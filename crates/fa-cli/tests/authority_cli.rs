//! Launch-bound CLI admission is checked before input files or the book are
//! observed. A plan-output argument does not confer commit authority.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::authority::{LaunchAuthority, LaunchProfile};
use fa_cli::cli::{Books, Captured, Files, Stdin, run_with_authority};
use fa_cli::json::{self, Json};
use fa_cli::verbs::registry;

fn fixture() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("fa-authority-cli-{}-{id}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create retained fixture {}: {error}", path.display()),
        }
    }
}

fn authority(profile: LaunchProfile, grants: &[&str]) -> LaunchAuthority {
    LaunchAuthority::new(
        fixture().join("missing-book"),
        None,
        "bound-7",
        profile,
        grants,
    )
    .expect("launch authority")
}

fn run(authority: &LaunchAuthority, argv: &[&str]) -> (u8, Captured) {
    let argv: Vec<String> = argv.iter().map(|value| (*value).to_string()).collect();
    run_with_authority(
        &argv,
        Books::Dir,
        Files {
            cwd: None,
            stdin: Stdin::Missing,
        },
        authority,
        true,
    )
}

fn event(authority: &LaunchAuthority, out: &Captured) -> Json {
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{out:?}");
    registry()
        .expect("verbs.toml")
        .check_line(lines[0])
        .unwrap_or_else(|error| panic!("{error}\n{out:?}"));
    let event = json::parse(lines[0]).expect("robot JSON");
    assert_eq!(
        event.get("authority"),
        Some(&authority.envelope_json()),
        "{out:?}"
    );
    event
}

fn refused_before_open(authority: &LaunchAuthority, argv: &[&str], refusal: &str) {
    let (exit, out) = run(authority, argv);
    assert_eq!(exit, 7, "argv={argv:?}\n{out:?}");
    let event = event(authority, &out);
    assert_eq!(event.get("event").and_then(Json::as_str), Some("error"));
    assert_eq!(event.get("book"), Some(&Json::Null), "{out:?}");
    assert_eq!(event.get("coordinate"), Some(&Json::Null), "{out:?}");
    assert_eq!(
        event
            .get("data")
            .and_then(|data| data.get("refusal_id"))
            .and_then(Json::as_str),
        Some(refusal),
        "argv={argv:?}\n{out:?}"
    );
    assert!(
        !authority.book().exists(),
        "preflight must not create a book"
    );
}

#[test]
fn owner_mutations_are_refused_before_input_files_or_book_creation() {
    let authority = authority(LaunchProfile::Preparer, &[]);
    for argv in [
        vec!["book", "create", "--name", "Forged book", "--json"],
        vec!["chart", "import", "unread-chart.json", "--json"],
        vec!["period", "create", "--fiscal-year", "2026", "--json"],
        vec![
            "period",
            "create",
            "--fiscal-year",
            "2026",
            "--plan-out",
            "true",
            "--json",
        ],
        vec!["period", "open", "FY2026-P03", "--json"],
        vec!["period", "soft-close", "FY2026-P03", "--json"],
        vec![
            "document",
            "add",
            "unread-evidence.pdf",
            "--grade",
            "HumanUpload",
            "--json",
        ],
    ] {
        refused_before_open(&authority, &argv, "FA-REF-011");
    }
}

#[test]
fn handlers_cannot_add_operations_omitted_from_the_launch_grant() {
    let reader = authority(LaunchProfile::Preparer, &["read"]);
    for argv in [
        vec!["post", "--intent", "-", "--json"],
        vec!["reserve", "--intent", "-", "--json"],
        vec!["resolve", "--intent", "-", "--json"],
        vec![
            "reverse",
            "not-yet-parsed",
            "--reason",
            "WrongAccount",
            "--json",
        ],
        vec!["approve", "--proposal", "not-yet-parsed", "--json"],
        vec!["checkpoint", "create", "--json"],
        vec!["verify", "registers", "--period", "FY2026-P03", "--json"],
        vec!["registers", "advance", "--period", "FY2026-P03", "--json"],
        vec![
            "registers",
            "materialize",
            "--period",
            "FY2026-P03",
            "--json",
        ],
    ] {
        refused_before_open(&reader, &argv, "FA-REF-011");
    }
    let verifier = authority(LaunchProfile::Agent, &["verify"]);
    for argv in [
        vec!["book", "info", "--json"],
        vec!["chart", "list", "--json"],
        vec!["period", "list", "--json"],
        vec!["tb", "--period", "FY2026-P03", "--json"],
        vec!["verify", "registers", "--period", "FY2026-P03", "--json"],
    ] {
        refused_before_open(&verifier, &argv, "FA-REF-011");
    }
}

#[test]
fn derived_report_certification_requires_produce_before_any_book_or_output_observation() {
    let reader = authority(LaunchProfile::Agent, &["read"]);
    for argv in [
        vec![
            "tb",
            "--summary",
            "--period",
            "FY2026-P03",
            "--certify",
            "--json",
        ],
        vec![
            "tb",
            "--summary",
            "--period",
            "FY2026-P03",
            "--certificate-out",
            "unwritten.cert",
            "--json",
        ],
        vec![
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
        ],
        vec![
            "gl",
            "aging",
            "--as-of",
            "2026-03-31",
            "--certify",
            "--json",
        ],
    ] {
        refused_before_open(&reader, &argv, "FA-REF-011");
    }
}

#[test]
fn revoked_report_and_evidence_authority_cannot_disclose_book_or_instant_metadata() {
    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;
    use fa::{Book, BookKeys, Entropy};
    use fa_journal::BookSpec;
    use fa_model::{Id128, principal_vid};
    use fa_money::UnitRegistry;
    use fa_policy::{Capability, CapabilityToken, Op, Profile, possession_digest};
    use fa_time::{DateDay, FiscalCalendar};

    // Real retained ticks bracket an earlier report coordinate. The same
    // holder-bound token is first issued, admitted, and then revoked at HEAD.
    const LOWER_NS: u64 = 1_773_576_000_000_000_000;
    const UPPER_NS: u64 = 1_773_576_010_000_000_000;
    const INSTANT: &str = "2026-03-15T12:00:05Z";
    const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    let dir = fixture();
    let book_dir = dir.join("held-book");
    // File containment is admitted before the book. An existing in-root
    // malformed artifact lets these cases reach the current native read check.
    std::fs::write(dir.join("supplied.cert"), b"not a certificate").unwrap();
    let day = DateDay::parse("2026-03-15").unwrap();
    let units = UnitRegistry::embedded().unwrap();
    let mut book = Book::create_memory(
        BookKeys::for_development(0x3a),
        BookSpec {
            book_id: Id128([0x3b; 16]),
            name: "Current report authority".into(),
            base_unit: units.lookup("USD").unwrap(),
            calendar: FiscalCalendar::monthly("report-authority", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(58),
    )
    .unwrap();
    book.create_periods(2026).unwrap();
    let issuer = Capability::embedded(
        principal_vid("report-issuer"),
        &["issue_capability", "read", "produce", "post", "reconcile"],
    )
    .unwrap();
    let secret = [0x39; 32];
    let issued = Capability::new(
        principal_vid("report-preparer"),
        Profile::Human,
        &[Op::Read, Op::Produce, Op::Post, Op::Reconcile],
        issuer.holder(),
    )
    .unwrap()
    .holder_bound(possession_digest(&secret));
    book.issue_capability(
        issuer.clone(),
        issued.clone(),
        day,
        b"issue-report-preparer",
        "Read and retain reports and evidence",
    )
    .unwrap()
    .unwrap();
    let token = CapabilityToken::new("report-preparer", issued.clone(), secret).unwrap();
    let authority = LaunchAuthority::from_token(book_dir.clone(), None, &token)
        .unwrap()
        .with_files(Some(dir.clone()))
        .unwrap();
    let runtime = RuntimeBuilder::new().build().unwrap();
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    let witness = Capability::embedded(issuer.holder(), &["witness"]).unwrap();
    let lower = runtime
        .block_on(book.record_tick(&cx, LOWER_NS, true, &witness))
        .unwrap()
        .unwrap();
    let upper = runtime
        .block_on(book.record_tick(&cx, UPPER_NS, true, &witness))
        .unwrap()
        .unwrap();
    let held = |book: &mut Book, argv: &[&str]| {
        let argv: Vec<String> = argv.iter().map(|arg| (*arg).to_string()).collect();
        run_with_authority(
            &argv,
            Books::Held {
                book,
                dir: book_dir.clone(),
            },
            Files {
                cwd: None,
                stdin: Stdin::Missing,
            },
            &authority,
            true,
        )
    };

    // An admitted caller gets the explicit unsupported-format refusal and
    // real resolution evidence. After revocation even that evidence is hidden.
    let before = book.head().unwrap();
    let (exit, allowed) = held(
        &mut book,
        &[
            "tb",
            "--summary",
            "--as-of",
            "2026-03-31",
            "--as-known-at",
            INSTANT,
            "--certify",
            "--json",
        ],
    );
    assert_eq!(exit, 2, "{allowed:?}");
    let allowed = event(&authority, &allowed);
    let coordinate = allowed.get("coordinate").unwrap();
    assert_eq!(
        coordinate.get("known_at"),
        Some(&Json::Int(i128::from(lower.recorded_at.0))),
        "{allowed:?}",
    );
    let time = coordinate.get("time_evidence").unwrap();
    for (name, tick) in [("lower", &lower), ("upper", &upper)] {
        assert_eq!(
            time.get(name).and_then(|tick| tick.get("recorded_at")),
            Some(&Json::Int(i128::from(tick.recorded_at.0))),
        );
    }
    assert_eq!(book.head().unwrap(), before);

    // With live authority the same contained file reaches certificate
    // decoding; after revocation its malformed contents must remain unread.
    for argv in [
        vec!["replay", "supplied.cert", "--json"],
        vec!["certificate", "status", "supplied.cert", "--json"],
    ] {
        let (exit, allowed) = held(&mut book, &argv);
        assert_eq!(exit, 8, "argv={argv:?}\n{allowed:?}");
        let allowed = event(&authority, &allowed);
        assert_ne!(allowed.get("book"), Some(&Json::Null));
        assert_eq!(
            allowed
                .get("data")
                .and_then(|data| data.get("refusal_id"))
                .and_then(Json::as_str),
            Some("FA-REF-150"),
        );
        assert_eq!(book.head().unwrap(), before);
    }

    book.revoke_capability(
        issuer,
        issued.commitment().unwrap(),
        day,
        b"revoke-report-preparer",
        "Withdraw report and evidence access",
    )
    .unwrap()
    .unwrap();
    let revoked_head = book.head().unwrap();
    let historical = lower.recorded_at.0.to_string();
    let mut commands = Vec::new();
    for mode in [
        vec![],
        vec!["--certify"],
        vec!["--certificate-out", "unwritten.cert"],
    ] {
        for selector in [
            vec!["--as-of", "2026-03-31", "--as-known-at", INSTANT],
            vec![
                "--as-of",
                "2026-03-31",
                "--as-known-at",
                historical.as_str(),
            ],
            vec!["--fiscal-year", "2099"],
            vec!["--period", "NEVER_REPORTED", "--as-originally-reported"],
        ] {
            let mut command = vec!["tb", "--summary"];
            command.extend(selector);
            command.extend(mode.iter().copied());
            commands.push(command);
        }
        for sub in ["detail", "roll-forward", "aging"] {
            let mut command = vec!["gl", sub, "--account", "1000", "--as-known-at", INSTANT];
            if sub == "aging" {
                command.extend(["--as-of", "2026-03-31"]);
            } else {
                command.extend(["--from", "2026-03-01", "--to", "2026-03-31"]);
            }
            command.extend(mode.iter().copied());
            commands.push(command);
        }
    }
    commands.extend([
        vec![
            "bank",
            "match",
            "--import",
            ZERO_DIGEST,
            "--as-known-at",
            INSTANT,
        ],
        vec![
            "bank",
            "import",
            "-",
            "--bank-format",
            "camt053",
            "--account",
            "1000",
        ],
        vec!["finding", "list", "--certificate", ZERO_DIGEST],
        vec!["finding", "runs", "--cursor", "invalid"],
        vec!["finding", "export", "--certificate", ZERO_DIGEST],
        vec!["finding", "replay", "-"],
        vec!["party", "list"],
        vec!["instrument", "list"],
        vec!["entity", "list"],
        vec!["document", "list"],
        vec!["document", "list", "--kind", "BankStatement"],
        vec!["replay", "-"],
        vec!["replay", ZERO_DIGEST],
        vec!["replay", "supplied.cert", "--output", "unwritten.cert"],
        vec!["certificate", "status", "-"],
        vec!["certificate", "status", ZERO_DIGEST],
        vec!["certificate", "status", "supplied.cert"],
    ]);
    for mut argv in commands {
        argv.push("--json");
        let (exit, denied) = held(&mut book, &argv);
        assert_eq!(exit, 7, "argv={argv:?}\n{denied:?}");
        let denied = event(&authority, &denied);
        assert_eq!(denied.get("event").and_then(Json::as_str), Some("error"));
        assert_eq!(denied.get("book"), Some(&Json::Null), "argv={argv:?}");
        assert_eq!(denied.get("coordinate"), Some(&Json::Null), "argv={argv:?}");
        assert_eq!(
            denied
                .get("data")
                .and_then(|data| data.get("refusal_id"))
                .and_then(Json::as_str),
            Some("FA-REF-023"),
            "argv={argv:?}\n{denied:?}",
        );
        assert_eq!(book.head().unwrap(), revoked_head);
        assert!(!dir.join("unwritten.cert").exists());
    }
}

#[test]
fn plan_files_and_plan_output_flags_cannot_confirm_a_dangerous_commit() {
    let authority = authority(LaunchProfile::Preparer, &[]);
    for transition in ["close", "lock", "reopen"] {
        for extra in [
            vec![],
            vec!["--plan", "false"],
            vec!["--plan-out", "true", "--plan", "false"],
            vec!["--plan-out=true", "--plan=false"],
            vec!["--plan-out", "true", "--approval", ""],
        ] {
            let mut argv = vec!["period", transition, "FY2026-P03"];
            argv.extend(extra);
            argv.push("--json");
            refused_before_open(&authority, &argv, "FA-REF-007");
        }
    }
}

#[test]
fn only_an_actual_read_authorized_inline_period_plan_can_reach_the_book() {
    let reader = authority(LaunchProfile::Agent, &["read"]);
    let plan = reader
        .book()
        .parent()
        .expect("fixture parent")
        .join("review.plan");
    let argv = ["period", "lock", "FY2026-P03", "--dry-run", "--json"];
    let (exit, out) = run(&reader, &argv);
    assert_eq!(
        exit, 4,
        "a permitted plan reaches the missing book: {out:?}"
    );
    let event = event(&reader, &out);
    assert_eq!(
        event.get("data").and_then(|data| data.get("refusal_id")),
        Some(&Json::Null),
        "the failure is opening the fixture, not fabricated commit authority: {out:?}"
    );
    assert!(!plan.exists(), "no plan may be fabricated without a book");
    let poster = authority(LaunchProfile::Preparer, &["post"]);
    refused_before_open(&poster, &argv, "FA-REF-011");
}

#[test]
fn bound_handlers_refuse_file_paths_before_observing_the_book() {
    let authority = authority(LaunchProfile::Preparer, &[]);
    let target = authority.book().parent().unwrap().join("preserve.txt");
    std::fs::write(&target, "preserve this host file").unwrap();
    let path = target.to_str().unwrap();
    for argv in [
        vec![
            "period",
            "close",
            "FY2026-P03",
            "--plan-out",
            path,
            "--json",
        ],
        vec!["post", "--intent", path, "--dry-run", "--json"],
        vec!["commit", "--plan", path, "--json"],
        vec!["replay", path, "--json"],
        vec!["certificate", "status", path, "--json"],
        vec!["tb", "--certificate-out", path, "--json"],
    ] {
        let (exit, out) = run(&authority, &argv);
        assert_eq!(exit, 2, "argv={argv:?}\n{out:?}");
        let event = event(&authority, &out);
        assert_eq!(event.get("book"), Some(&Json::Null));
        assert!(
            event
                .get("data")
                .and_then(|data| data.get("message"))
                .and_then(Json::as_str)
                .unwrap()
                .contains("filesystem")
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "preserve this host file"
        );
        assert!(!authority.book().exists());
    }
}

#[test]
fn positional_flag_text_and_file_cwd_cannot_rebind_the_configured_book() {
    let authority = authority(LaunchProfile::Agent, &["read"]);
    let other = fixture();
    let argv: Vec<String> = ["book", "info", "--json", "--", "--book", "another-book"]
        .iter()
        .map(|value| (*value).to_string())
        .collect();
    let (exit, out) = run_with_authority(
        &argv,
        Books::Dir,
        Files {
            cwd: Some(other.clone()),
            stdin: Stdin::Missing,
        },
        &authority,
        true,
    );
    assert_eq!(exit, 4, "{out:?}");
    let event = event(&authority, &out);
    let message = event
        .get("data")
        .and_then(|data| data.get("message"))
        .and_then(Json::as_str)
        .expect("open failure");
    assert!(
        message.contains(&authority.book().display().to_string()),
        "{out:?}"
    );
    assert!(!message.contains(&other.display().to_string()), "{out:?}");
    assert!(!authority.book().exists());
    assert!(!other.join("another-book").exists());
}
