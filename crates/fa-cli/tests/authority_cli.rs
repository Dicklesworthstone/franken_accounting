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

/// The typed documents post through fa post's own path, so an Agent launch
/// may rehearse them (--dry-run), plan them into a draft or run them in a
/// scenario, but never post them to trunk: the MCP surface refuses that
/// before any argument file or the book is read.
#[test]
fn an_agent_launch_rehearses_typed_documents_but_never_posts_them_to_trunk() {
    let reg = registry().expect("verbs.toml");
    let agent = authority(LaunchProfile::Agent, &["read", "post"]);
    let preparer = authority(LaunchProfile::Preparer, &["read", "post"]);
    let parse = |argv: &[&str]| {
        let argv: Vec<String> = argv.iter().map(|a| (*a).to_string()).collect();
        fa_cli::args::parse(&argv, &reg.value_flags(), &reg.switches()).expect("parses")
    };
    for verb in ["invoice", "bill", "receipt", "payment"] {
        let trunk = parse(&[verb, "--party", "C-17", "--number", "1"]);
        let refused = fa_cli::cli::bound_command_admissible(reg, verb, &trunk, &agent)
            .expect_err("an Agent never posts a typed document to trunk");
        assert!(refused.contains("FA-REF-013"), "{verb}: {refused}");
        assert!(
            fa_cli::cli::bound_command_admissible(reg, verb, &trunk, &preparer).is_ok(),
            "{verb}: a Preparer launch posts to trunk"
        );
        for planning in [
            &["--dry-run"][..],
            &["--draft", "close-03"][..],
            &["--scenario", "but-for"][..],
        ] {
            let mut argv = vec![verb, "--party", "C-17", "--number", "1"];
            argv.extend_from_slice(planning);
            assert!(
                fa_cli::cli::bound_command_admissible(reg, verb, &parse(&argv), &agent).is_ok(),
                "{verb} {planning:?}: an Agent may rehearse, draft or run in a scenario"
            );
        }
    }
    // A reclassification moves an amount on trunk too (fa-i7e): refused the
    // same way before anything is read, and rehearsable the same way.
    let reclass = [
        "reclass",
        "E:00000000000000000000000000000001",
        "--from",
        "6100",
        "--to",
        "6200",
        "--amount",
        "1.00 USD",
        "--reason",
        "WrongAccount",
    ];
    let refused = fa_cli::cli::bound_command_admissible(reg, "reclass", &parse(&reclass), &agent)
        .expect_err("an Agent never reclassifies on trunk");
    assert!(refused.contains("FA-REF-013"), "reclass: {refused}");
    assert!(
        fa_cli::cli::bound_command_admissible(reg, "reclass", &parse(&reclass), &preparer).is_ok(),
        "reclass: a Preparer launch posts to trunk"
    );
    for planning in [&["--dry-run"][..], &["--draft", "close-03"][..]] {
        let mut argv = reclass.to_vec();
        argv.extend_from_slice(planning);
        assert!(
            fa_cli::cli::bound_command_admissible(reg, "reclass", &parse(&argv), &agent).is_ok(),
            "reclass {planning:?}: an Agent may rehearse or draft a reclassification"
        );
    }
}

/// A bank-detail change is the business-email-compromise vector (plan
/// §14.4): no launch-bound session changes a party's identifiers, whatever
/// it holds. No launch ceiling includes schema_change today, so the other
/// REA changes are refused by the op check; identifiers has no launch
/// mapping at all, so a wider future ceiling cannot reach it.
#[test]
fn no_launch_session_changes_a_partys_bank_details() {
    let ceiling: Vec<&str> = LaunchProfile::Preparer
        .ceiling()
        .iter()
        .map(|op| op.name())
        .collect();
    let holder = authority(LaunchProfile::Preparer, &ceiling);
    refused_before_open(
        &holder,
        &[
            "party",
            "identifiers",
            "V-17",
            "--identifier",
            "bank_account=000123",
            "--key",
            "chg-1",
            "--json",
        ],
        "FA-REF-011",
    );
    let reg = registry().expect("verbs.toml");
    let parse = |argv: &[&str]| {
        let argv: Vec<String> = argv.iter().map(|a| (*a).to_string()).collect();
        fa_cli::args::parse(&argv, &reg.value_flags(), &reg.switches()).expect("parses")
    };
    let identifiers = parse(&[
        "party",
        "identifiers",
        "V-17",
        "--identifier",
        "bank_account=000123",
        "--key",
        "chg-1",
    ]);
    assert_eq!(
        fa_cli::cli::bound_command_ops("party", &identifiers),
        None,
        "no grant reaches a bank-detail change"
    );
    assert_eq!(
        fa_cli::cli::bound_command_ops(
            "party",
            &parse(&["party", "bind", "V-17", "--external-id", "qbo:55"])
        ),
        Some(&[fa_policy::Op::SchemaChange][..]),
        "binding another system's id stays a schema_change"
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
        vec!["verify", "periods", "--json"],
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
        vec!["verify", "periods", "--json"],
    ] {
        refused_before_open(&verifier, &argv, "FA-REF-011");
    }
}

#[test]
fn report_certification_requires_produce_before_any_book_or_output_observation() {
    let reader = authority(LaunchProfile::Agent, &["read"]);
    for argv in [
        vec!["tb", "--period", "FY2026-P03", "--certify", "--json"],
        vec![
            "tb",
            "--period",
            "FY2026-P03",
            "--dimension",
            "cost_center=not-created",
            "--certificate-out",
            "unwritten.cert",
            "--json",
        ],
        vec![
            "statement",
            "balance-sheet",
            "--for",
            "FY2026-P03",
            "--certify",
            "--json",
        ],
        vec![
            "statement",
            "income-statement",
            "--for",
            "FY2026-P03",
            "--certificate-out",
            "unwritten.cert",
            "--json",
        ],
        vec![
            "explain",
            "balance",
            "1000",
            "--period",
            "FY2026-P03",
            "--certify",
            "--json",
        ],
        vec![
            "open-items",
            "--account",
            "1200",
            "--certificate-out",
            "unwritten.cert",
            "--json",
        ],
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
    // A well-formed intent, so a scenario run reaches the authority check.
    std::fs::write(
        dir.join("scenario-intent.json"),
        br#"{"effective_date":"2026-03-15","idempotency_key":"what-if","legs":[{"side":"debit","account":"1000","amount":"1.00 USD"},{"side":"credit","account":"4000","amount":"1.00 USD"}]}"#,
    )
    .unwrap();
    // A well-formed explicit allocation: without admission before the book
    // opens, its basis document would be written before the kernel refused.
    std::fs::write(
        dir.join("allocation-intent.json"),
        br#"{"source":"6000","source_side":"credit","total":"1.00 USD","effective_date":"2026-03-15","idempotency_key":"alloc-revoked","method":"largest_remainder","targets":[{"account":"1000","weight":1}]}"#,
    )
    .unwrap();
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
    let schema = Capability::embedded(principal_vid("report-issuer"), &["schema_change"]).unwrap();
    book.create_periods(2026, schema.holder(), &schema)
        .unwrap()
        .unwrap();
    let issuer = Capability::embedded(
        principal_vid("report-issuer"),
        &[
            "issue_capability",
            "read",
            "verify",
            "produce",
            "post",
            "reconcile",
            "maintain",
        ],
    )
    .unwrap();
    let secret = [0x39; 32];
    let issued = Capability::new(
        principal_vid("report-preparer"),
        Profile::Human,
        &[
            Op::Read,
            Op::Verify,
            Op::Produce,
            Op::Post,
            Op::Reconcile,
            Op::Maintain,
        ],
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
    let access = book.access_log(before).unwrap();
    assert_eq!(access.len(), 1);
    assert_eq!(access[0].record.command, "tb");
    assert_eq!(access[0].record.principal_name, "report-preparer");
    assert_eq!(access[0].observed_at, before);
    assert_eq!(access[0].recorded_at.0, before.0 + 1);
    assert_eq!(book.head().unwrap(), access[0].recorded_at);

    // With live authority the same contained file reaches certificate
    // decoding; after revocation its malformed contents must remain unread.
    for argv in [
        vec!["replay", "supplied.cert", "--json"],
        vec!["certificate", "status", "supplied.cert", "--json"],
    ] {
        let before_attempt = book.head().unwrap();
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
        let access = book.access_log(before_attempt).unwrap();
        assert_eq!(
            access.len(),
            1,
            "an admitted attempt is audited before decoding"
        );
        assert_eq!(access[0].record.principal_name, "report-preparer");
        assert_eq!(access[0].observed_at, before_attempt);
        assert_eq!(access[0].recorded_at.0, before_attempt.0 + 1);
        assert_eq!(book.head().unwrap(), access[0].recorded_at);
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
        for sub in ["detail", "roll-forward", "aging", "cash-flow"] {
            let mut command = vec!["gl", sub, "--account", "1000", "--as-known-at", INSTANT];
            if sub == "aging" {
                command.extend(["--as-of", "2026-03-31"]);
            } else {
                command.extend(["--from", "2026-03-01", "--to", "2026-03-31"]);
            }
            if sub == "cash-flow" {
                command.extend(["--policy", "-"]);
            }
            command.extend(mode.iter().copied());
            if sub == "aging" {
                let mut reconciliation = command.clone();
                reconciliation.push("--reconcile");
                commands.push(reconciliation);
            }
            commands.push(command);
        }
    }
    commands.extend([
        vec!["gl", "lots", "--account", "1000", "--as-known-at", INSTANT],
        vec!["replay", "supplied.cert", "--expect", "{"],
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
        vec![
            "scenario",
            "run",
            "nope",
            "--intent",
            "scenario-intent.json",
        ],
        vec![
            "post",
            "--intent",
            "scenario-intent.json",
            "--scenario",
            "nope",
        ],
        vec!["allocate", "--intent", "allocation-intent.json"],
        vec!["registers", "advance", "--period", "FY2026-P03"],
        vec!["registers", "materialize", "--period", "FY2026-P03"],
        vec!["verify", "registers", "--period", "FY2026-P03"],
        // Handlers that open the book without their own admission: the
        // bound session's token is admitted as current at the open itself.
        vec!["tb", "--period", "FY2026-P03"],
        vec!["entry", "show", "00000000000000000000000000000001"],
        vec!["explain", "period", "FY2026-P03"],
        vec!["triage"],
        vec!["verify", "accumulator"],
        vec!["verify", "projections"],
        vec!["verify", "replay"],
        vec!["scenario", "list"],
        vec!["scenario", "show", "nope"],
        vec!["scenario", "diff", "nope", "--period", "FY2026-P03"],
        vec!["party", "list"],
        vec!["instrument", "list"],
        vec!["entity", "list"],
        vec!["document", "list"],
        vec!["document", "list", "--kind", "BankStatement"],
        vec!["verify", "periods", "--as-known-at", INSTANT],
        vec!["verify", "periods", "--as-known-at", historical.as_str()],
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
    let argv = [
        "period",
        "lock",
        "FY2026-P03",
        "--reason",
        "Scheduled",
        "--dry-run",
        "--json",
    ];
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
    let authority = authority(
        LaunchProfile::Preparer,
        &["read", "post", "verify", "produce"],
    );
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
        vec![
            "reverse",
            "00000000000000000000000000000001",
            "--reason",
            "WrongAmount",
            "--replace-with",
            path,
            "--json",
        ],
        vec!["commit", "--plan", path, "--json"],
        vec!["replay", path, "--json"],
        vec!["certificate", "status", path, "--json"],
        vec!["tb", "--certificate-out", path, "--json"],
    ] {
        for leased in [false, true] {
            let books = if leased {
                Books::LeasedOnOpen {
                    lease: registry().unwrap().daemon.lease.clone(),
                    note: "forbidden path must not acquire a lease".to_string(),
                    held: None,
                }
            } else {
                Books::Dir
            };
            let args: Vec<String> = argv.iter().map(|value| (*value).to_string()).collect();
            let (exit, out) = run_with_authority(
                &args,
                books,
                Files {
                    cwd: None,
                    stdin: Stdin::Missing,
                },
                &authority,
                true,
            );
            assert_eq!(exit, 2, "leased={leased}, argv={argv:?}\n{out:?}");
            let event = event(&authority, &out);
            assert_eq!(event.get("book"), Some(&Json::Null));
            assert_eq!(event.get("coordinate"), Some(&Json::Null));
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

mod source_draft_tests {
    use super::*;
    use fa::{Book, BookKeys, Entropy};
    use fa_journal::BookSpec;
    use fa_model::{Id128, draft_branch, principal_vid};
    use fa_money::UnitRegistry;
    use fa_policy::{Capability, CapabilityToken, Op, Profile, possession_digest};
    use fa_time::{DateDay, FiscalCalendar};
    use fgdb_types::VId;

    const DATE: &str = "2026-03-15";

    fn field<'a>(value: &'a Json, key: &str) -> &'a Json {
        value
            .get(key)
            .unwrap_or_else(|| panic!("missing {key}: {value:?}"))
    }

    fn text<'a>(value: &'a Json, key: &str) -> &'a str {
        field(value, key)
            .as_str()
            .unwrap_or_else(|| panic!("{key}: {value:?}"))
    }

    fn result_event(out: &Captured) -> Json {
        let lines: Vec<_> = out.stdout.lines().collect();
        assert_eq!(lines.len(), 1, "{out:?}");
        registry()
            .unwrap()
            .check_line(lines[0])
            .unwrap_or_else(|e| panic!("{e}: {out:?}"));
        json::parse(lines[0]).unwrap()
    }

    struct Fixture {
        book: Book,
        dir: PathBuf,
        evidence: String,
        rate: String,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = fixture().join("source-draft-book");
            let units = UnitRegistry::embedded().unwrap();
            let book = Book::create_memory(
                BookKeys::for_development(0x6a),
                BookSpec {
                    book_id: Id128([0x6b; 16]),
                    name: "Confined source-derived drafts".into(),
                    base_unit: units.lookup("USD").unwrap(),
                    calendar: FiscalCalendar::monthly("source-drafts", 1, 1).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(106),
            )
            .unwrap();
            let mut f = Self {
                book,
                dir,
                evidence: String::new(),
                rate: String::new(),
            };
            f.owner(&["chart", "import", "-"], Some(r#"{"accounts":[{"code":"1000","name":"USD Cash","type":"Asset","unit":"USD"},{"code":"2000","name":"USD Payables","type":"Liability","unit":"USD"},{"code":"2100","name":"EUR Payables","type":"Liability","unit":"EUR"},{"code":"6000","name":"USD Expense","type":"Expense","unit":"USD"},{"code":"6100","name":"EUR Purchases","type":"Expense","unit":"EUR"}]}"#));
            f.owner(&["period", "create", "--fiscal-year", "2026"], None);
            f.owner(&["period", "open", "FY2026-P03"], None);
            let evidence = f.owner(
                &[
                    "document",
                    "add",
                    "-",
                    "--kind",
                    "Receipt",
                    "--grade",
                    "HumanUpload",
                ],
                Some("Independent vendor invoice for the confined draft."),
            );
            f.evidence = text(field(&evidence, "data"), "oid").into();
            let oid = f.evidence.clone();
            f.owner(
                &["attest", "review", &oid, "--as", "independent-reviewer"],
                None,
            );
            let rate = f.owner(&["fx", "rate", "add", "--from-json", "-"], Some(r#"{"base_unit":"USD","quote_unit":"EUR","rate_num":"11","rate_den":"10","rounding":"HalfEven","as_of":"2026-03-15","retrieved_at_ns":1772712000000000000,"purpose":"spot_close","source":"independently retained quote"}"#));
            f.rate = text(field(&rate, "data"), "oid").into();
            f
        }

        fn owner(&mut self, args: &[&str], input: Option<&str>) -> Json {
            let mut argv: Vec<String> =
                vec!["--book".into(), self.dir.to_string_lossy().into_owned()];
            argv.extend(args.iter().map(|arg| (*arg).to_string()));
            argv.push("--json".into());
            let (exit, out) = fa_cli::cli::run(
                &argv,
                Books::Held {
                    book: &mut self.book,
                    dir: self.dir.clone(),
                },
                Files {
                    cwd: None,
                    stdin: input
                        .map_or(Stdin::Missing, |s| Stdin::Forwarded(s.as_bytes().to_vec())),
                },
                true,
            );
            assert_eq!(exit, 0, "owner argv={argv:?}\n{out:?}");
            result_event(&out)
        }

        fn agent(&mut self, holder: &str, draft: Option<&str>) -> (Capability, LaunchAuthority) {
            self.scoped_agent(holder, draft, |cap| cap)
        }

        fn scoped_agent(
            &mut self,
            holder: &str,
            draft: Option<&str>,
            attenuate: impl FnOnce(Capability) -> Capability,
        ) -> (Capability, LaunchAuthority) {
            let issuer =
                Capability::embedded(principal_vid("draft-issuer"), &["issue_capability", "post"])
                    .unwrap();
            let secret = [0x6c; 32];
            let mut cap = Capability::new(
                principal_vid(holder),
                Profile::Agent,
                &[Op::Post],
                issuer.holder(),
            )
            .unwrap()
            .for_books(&[self.book.context().book_id])
            .unwrap()
            .holder_bound(possession_digest(&secret));
            if let Some(name) = draft {
                cap = cap
                    .on_branch(draft_branch(self.book.context().book_id, name))
                    .unwrap();
            }
            cap = attenuate(cap);
            self.book
                .issue_capability(
                    issuer,
                    cap.clone(),
                    DateDay::parse(DATE).unwrap(),
                    format!("issue-{holder}-{}", draft.unwrap_or("unconfined")).as_bytes(),
                    "Only prepare postings within the named draft",
                )
                .unwrap()
                .unwrap();
            let token = CapabilityToken::new(holder, cap.clone(), secret).unwrap();
            let authority = LaunchAuthority::from_token(self.dir.clone(), None, &token).unwrap();
            assert!(!cap.holds(Op::Read));
            (cap, authority)
        }

        fn bound(
            &mut self,
            authority: &LaunchAuthority,
            args: &[&str],
            input: Option<&str>,
        ) -> (u8, Json) {
            let (exit, mut events) = self.bound_events(authority, args, input);
            assert_eq!(events.len(), 1, "argv={args:?}: {events:?}");
            (exit, events.remove(0))
        }

        fn bound_events(
            &mut self,
            authority: &LaunchAuthority,
            args: &[&str],
            input: Option<&str>,
        ) -> (u8, Vec<Json>) {
            let mut argv: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
            argv.push("--json".into());
            let (exit, out) = run_with_authority(
                &argv,
                Books::Held {
                    book: &mut self.book,
                    dir: self.dir.clone(),
                },
                Files {
                    cwd: None,
                    stdin: input
                        .map_or(Stdin::Missing, |s| Stdin::Forwarded(s.as_bytes().to_vec())),
                },
                authority,
                true,
            );
            let events: Vec<_> = out
                .stdout
                .lines()
                .map(|line| {
                    registry()
                        .unwrap()
                        .check_line(line)
                        .unwrap_or_else(|error| panic!("{error}: {out:?}"));
                    let value = json::parse(line).unwrap();
                    assert_eq!(
                        value.get("authority"),
                        Some(&authority.envelope_json()),
                        "{out:?}"
                    );
                    value
                })
                .collect();
            assert!(!events.is_empty(), "argv={argv:?}: {out:?}");
            eprintln!(
                "source-draft argv={argv:?} exit={exit}\nstdout={}\nstderr={}",
                out.stdout, out.stderr
            );
            (exit, events)
        }

        fn open(&mut self, authority: &LaunchAuthority, name: &str) {
            let (exit, result) =
                self.bound(authority, &["draft", "new", name, "--date", DATE], None);
            assert_eq!(exit, 0, "{result:?}");
            assert_eq!(text(&result, "event"), "draft_opened");
        }

        fn fx_intent(&self, key: &str) -> String {
            format!(
                r#"{{"effective_date":"{DATE}","idempotency_key":"{key}","evidence":["{}"],"legs":[{{"side":"debit","account":"6100","amount":"100.00 EUR"}},{{"side":"credit","account":"2100","amount":"100.00 EUR"}}],"fx":{{"law":"SpotClose","rates":["D:{}"]}}}}"#,
                self.evidence, self.rate
            )
        }

        fn external_source(&mut self) -> String {
            self.external_source_with_mime(fa::EXTERNAL_SUBLEDGER_MIME)
        }

        fn external_source_with_mime(&mut self, mime: &str) -> String {
            let input = format!(
                r#"{{"feed":"vendor-ap","batch_key":"march-confined","effective_date":"{DATE}","rows":[{{"source_digest":"{}","account":"6000","side":"debit","amount":"100.00 USD"}},{{"source_digest":"{}","account":"2000","side":"credit","amount":"100.00 USD"}}]}}"#,
                "01".repeat(32),
                "02".repeat(32)
            );
            let path = self
                .dir
                .parent()
                .unwrap()
                .join("retained-external-detail.bin");
            self.owner(
                &[
                    "subledger",
                    "detail",
                    "--input",
                    "-",
                    "--out",
                    path.to_str().unwrap(),
                ],
                Some(&input),
            );
            let retained = self.owner(
                &[
                    "document",
                    "add",
                    path.to_str().unwrap(),
                    "--kind",
                    "Workpaper",
                    "--mime",
                    mime,
                    "--grade",
                    "HumanUpload",
                ],
                None,
            );
            text(field(&retained, "data"), "oid").into()
        }

        fn journal(&self) -> fa::QueryRows {
            let fa::QuerySelection::Native(query) =
                fa::compile_query("MATCH (e:Entry) RETURN e,e._fa_payload AS payload ORDER BY e")
                    .unwrap()
                    .selection
            else {
                panic!("journal population must use a native query");
            };
            self.book
                .query_native(&query, self.book.head().unwrap(), None)
                .unwrap()
                .unwrap()
        }

        fn assert_access_only(
            &self,
            before: fgdb_types::CommitSeq,
            journal: &fa::QueryRows,
            authority: &LaunchAuthority,
            argv: &[&str],
            command: &str,
        ) {
            let records = self.book.access_log(before).unwrap();
            assert_eq!(records.len(), 1, "exactly one bound-command audit receipt");
            let access = &records[0];
            assert_eq!(access.record.command, command);
            assert_eq!(access.record.principal, authority.capability().holder());
            assert_eq!(
                access.record.capability_commitment,
                authority.capability().commitment().unwrap()
            );
            let mut requested: Vec<String> = argv.iter().map(|arg| (*arg).to_string()).collect();
            requested.push("--json".into());
            assert_eq!(
                access.record.request_digest,
                fa::access_log::request_digest(&requested)
            );
            assert_eq!(access.observed_at, before);
            assert_eq!(access.recorded_at.0, before.0 + 1);
            assert_eq!(self.book.head().unwrap(), access.recorded_at);
            assert_eq!(
                self.journal().rows,
                journal.rows,
                "no accounting journal payload changed"
            );
        }

        fn promote_exact(&mut self, cap: &Capability, name: &str, expected_count: usize) {
            let reviewed = self.book.draft_entries(cap, name).unwrap().unwrap();
            assert_eq!(reviewed.len(), expected_count);
            let promoted = self.owner(
                &[
                    "draft",
                    "promote",
                    name,
                    "--date",
                    DATE,
                    "--as",
                    "independent-controller",
                    "--yes",
                ],
                None,
            );
            assert_eq!(text(&promoted, "event"), "draft_promoted");
            let entries = field(field(&promoted, "data"), "entries").as_arr().unwrap();
            assert_eq!(entries.len(), reviewed.len());
            for (id, expected) in entries.iter().zip(reviewed) {
                let vid = VId(u128::from_str_radix(id.as_str().unwrap(), 16).unwrap());
                let (posted, _) = self.book.read_entry(vid).unwrap().unwrap();
                assert_eq!(posted.proposal, expected.proposal);
                assert_eq!(posted.entry_digest, expected.entry_digest);
                assert_eq!(posted.proposal.principal_ref, cap.holder());
                assert_eq!(posted.proposal.branch_id, Id128::TRUNK);
            }
        }
    }

    #[test]
    fn post_only_draft_capability_plans_an_fx_purchase_from_its_named_rate() {
        let mut f = Fixture::new();
        let name = "fx-purchases";
        let (cap, authority) = f.agent("purchase-agent", Some(name));
        f.open(&authority, name);
        let before = f.owner(&["tb", "--period", "FY2026-P03"], None);
        let intent = f.fx_intent("confined-purchase");
        let (exit, result) = f.bound(
            &authority,
            &["post", "--intent", "-", "--draft", name],
            Some(&intent),
        );
        assert_eq!(exit, 0, "{result:?}");
        assert_eq!(text(&result, "event"), "draft_planned");
        let planned = text(field(&result, "data"), "entry");
        let vid = VId(u128::from_str_radix(planned, 16).unwrap());
        assert!(
            f.book.read_entry(vid).unwrap().is_none(),
            "draft planning never posts its entry"
        );
        let reviewed = f.book.draft_entries(&cap, name).unwrap().unwrap();
        assert_eq!(reviewed.len(), 1);
        assert!(
            reviewed[0]
                .proposal
                .legs
                .iter()
                .all(|leg| leg.base_amount.is_some())
        );

        // This second append resolves a named entry retained only in this
        // draft. It must use the admitted draft's prefix, not a trunk read or
        // another draft's private members.
        let reversal = format!(
            r#"{{"class":"Reversal","effective_date":"{DATE}","idempotency_key":"confined-reversal","reverses":"{planned}","reason":"WrongAmount"}}"#
        );
        let (exit, reversed) = f.bound(
            &authority,
            &["post", "--intent", "-", "--draft", name],
            Some(&reversal),
        );
        assert_eq!(exit, 0, "{reversed:?}");
        assert_eq!(text(&reversed, "event"), "draft_planned");
        let after = f.owner(&["tb", "--period", "FY2026-P03"], None);
        assert_eq!(
            field(field(&before, "data"), "rows"),
            field(field(&after, "data"), "rows")
        );
        f.promote_exact(&cap, name, 2);
    }

    #[test]
    fn post_only_draft_capability_prepares_and_appends_a_disposal_review() {
        for law in ["FIFO", "SpecificId"] {
            let mut f = Fixture::new();
            f.owner(&["chart", "import", "-"], Some(r#"{"accounts":[{"code":"1400","name":"Inventory","type":"Asset","unit":"any"},{"code":"1499","name":"Quantity offset","type":"Equity","unit":"SHARE"},{"code":"5100","name":"Cost of goods sold","type":"Expense","unit":"USD"}]}"#));
            f.owner(
                &[
                    "chart",
                    "lot-policy",
                    "set",
                    "--account",
                    "1400",
                    "--law",
                    law,
                    "--regime",
                    "US-GAAP",
                    "--date",
                    DATE,
                    "--key",
                    "governed-lots",
                ],
                None,
            );
            let evidence = f.evidence.clone();
            let acquisition = format!(
                r#"{{"effective_date":"{DATE}","idempotency_key":"selected-acquisition","legs":[{{"side":"debit","account":"1400","amount":"10.000000 SHARE"}},{{"side":"credit","account":"1499","amount":"10.000000 SHARE"}},{{"side":"debit","account":"1400","amount":"100.00 USD"}},{{"side":"credit","account":"1000","amount":"100.00 USD"}}]}}"#
            );
            let acquired = f.owner(
                &["post", "--intent", "-", "--evidence", &evidence],
                Some(&acquisition),
            );
            let acquisition_id = text(field(&acquired, "data"), "vid").to_string();
            let name = "selected-disposal";
            let (cap, authority) = f.agent("lot-agent", Some(name));
            for subcommand in ["new", "discard"] {
                let before = f.book.head().unwrap();
                let (exit, refused) = f.bound(
                    &authority,
                    &["draft", subcommand, "another-draft", "--date", "not-a-date"],
                    None,
                );
                assert_eq!(
                    exit, 7,
                    "branch admission precedes default-date observation/parsing: {refused:?}"
                );
                assert_eq!(text(field(&refused, "data"), "refusal_id"), "FA-REF-011");
                assert_eq!(field(&refused, "coordinate"), &Json::Null);
                assert_eq!(f.book.head().unwrap(), before);
            }
            f.open(&authority, name);
            let target = format!("{acquisition_id}:0");
            let mut args = vec![
                "dispose",
                "--account",
                "1400",
                "--quantity",
                "3.000000 SHARE",
                "--quantity-offset",
                "1499",
                "--cost-offset",
                "5100",
                "--date",
                DATE,
                "--key",
                "selected-disposal",
                "--evidence",
                &evidence,
                "--review-only",
            ];
            if law == "SpecificId" {
                args.extend(["--target", &target]);
            }
            let reg = registry().unwrap();
            let parsed = fa_cli::args::parse(
                &args
                    .iter()
                    .map(|arg| (*arg).to_string())
                    .collect::<Vec<_>>(),
                &reg.value_flags(),
                &reg.switches(),
            )
            .unwrap();
            assert_eq!(
                fa_cli::cli::bound_command_admissible(reg, "dispose", &parsed, &authority).unwrap(),
                &[Op::Post]
            );
            let before = f.book.head().unwrap();
            let journal = f.journal();
            let (exit, reviewed) = f.bound(&authority, &args, None);
            assert_eq!(exit, 0, "{law}: {reviewed:?}");
            assert_eq!(text(&reviewed, "event"), "lot_disposal_review");
            f.assert_access_only(before, &journal, &authority, &args, "dispose");
            assert!(
                f.book
                    .draft_entries(&cap, name)
                    .unwrap()
                    .unwrap()
                    .is_empty()
            );
            let data = field(&reviewed, "data");
            let batch = format!(
                r#"{{"idempotency_key":"selected-review-batch","intents":[{{"review":"{}","review_digest":"{}"}}]}}"#,
                text(data, "bytes"),
                text(data, "review_digest")
            );
            let (exit, planned) = f.bound(
                &authority,
                &["batch", "--intent", "-", "--draft", name],
                Some(&batch),
            );
            assert_eq!(exit, 0, "{law}: {planned:?}");
            assert_eq!(text(&planned, "event"), "draft_planned");
            let entries = f.book.draft_entries(&cap, name).unwrap().unwrap();
            assert_eq!(entries.len(), 1);
            let proposal = &entries[0].proposal;
            assert_eq!(proposal.legs.len(), 4);
            assert_eq!(proposal.legs[0].amount.mantissa, 3_000_000);
            assert_eq!(proposal.legs[2].amount.mantissa, 3_000);
            let basis = proposal.lot_disposal_basis().unwrap().unwrap();
            assert_eq!(basis.specific_ids.len(), usize::from(law == "SpecificId"));
            let vid = VId(u128::from_str_radix(&acquisition_id, 16).unwrap());
            if law == "SpecificId" {
                let (entry, _) = f.book.read_entry(vid).unwrap().unwrap();
                assert_eq!(basis.specific_ids, vec![(entry.entry_ref(vid), 0)]);
            }
            let (exit, denied) = f.bound(&authority, &["entry", "show", &acquisition_id], None);
            assert_eq!(exit, 7, "{denied:?}");
            assert_eq!(text(field(&denied, "data"), "refusal_id"), "FA-REF-011");
            f.promote_exact(&cap, name, 1);
        }
    }

    #[test]
    fn post_only_draft_capability_prepares_an_external_subledger_summary() {
        let mut f = Fixture::new();
        let source = f.external_source();
        let name = "external-summary";
        let (cap, authority) = f.agent("summary-agent", Some(name));
        f.open(&authority, name);
        let intent = format!(
            r#"{{"effective_date":"{DATE}","idempotency_key":"confined-summary","external_subledger":"D:{source}"}}"#
        );
        let before = f.book.head().unwrap();
        let journal = f.journal();
        let argv = ["draft", "plan", name, "--intent", "-"];
        let (exit, refused) = f.bound(&authority, &argv, Some(&intent));
        assert_eq!(exit, 3, "unreviewed detail: {refused:?}");
        assert_eq!(text(field(&refused, "data"), "refusal_id"), "FA-REF-192");
        f.assert_access_only(before, &journal, &authority, &argv, "draft plan");
        assert!(
            f.book
                .draft_entries(&cap, name)
                .unwrap()
                .unwrap()
                .is_empty()
        );
        f.owner(
            &["attest", "review", &source, "--as", "independent-reviewer"],
            None,
        );
        let (exit, planned) = f.bound(
            &authority,
            &["draft", "plan", name, "--intent", "-"],
            Some(&intent),
        );
        assert_eq!(exit, 0, "{planned:?}");
        assert_eq!(text(&planned, "event"), "draft_planned");
        let vid = VId(u128::from_str_radix(text(field(&planned, "data"), "entry"), 16).unwrap());
        assert!(f.book.read_entry(vid).unwrap().is_none());
        let reviewed = f.book.draft_entries(&cap, name).unwrap().unwrap();
        assert_eq!(reviewed[0].proposal.legs.len(), 2);
        assert!(
            reviewed[0]
                .proposal
                .legs
                .iter()
                .all(|leg| leg.amount.mantissa == 10_000)
        );
        f.promote_exact(&cap, name, 1);
    }

    #[test]
    fn source_derived_refusal_discloses_no_other_account_balance() {
        let mut f = Fixture::new();
        let private = format!(
            r#"{{"effective_date":"{DATE}","idempotency_key":"private-opening","legs":[{{"side":"debit","account":"6000","amount":"987654.32 USD"}},{{"side":"credit","account":"2000","amount":"987654.32 USD"}}]}}"#
        );
        let evidence = f.evidence.clone();
        f.owner(
            &["post", "--intent", "-", "--evidence", &evidence],
            Some(&private),
        );
        // The bytes are canonical detail, but this generic document has not
        // been retained under the declared external-subledger media contract.
        let source = f.external_source_with_mime("application/octet-stream");
        let name = "wrong-purpose-detail";
        let (_, authority) = f.agent("wrong-purpose-agent", Some(name));
        f.open(&authority, name);
        let intent = format!(
            r#"{{"effective_date":"{DATE}","idempotency_key":"wrong-purpose-summary","external_subledger":"D:{source}"}}"#
        );
        let argv = ["draft", "plan", name, "--intent", "-"];
        let before = f.book.head().unwrap();
        let journal = f.journal();
        let (exit, refused) = f.bound(&authority, &argv, Some(&intent));
        assert_eq!(exit, 7, "{refused:?}");
        assert_eq!(text(field(&refused, "data"), "refusal_id"), "FA-REF-011");
        assert!(!format!("{refused:?}").contains("987654.32"));
        assert!(!format!("{refused:?}").contains("98765432"));
        f.assert_access_only(before, &journal, &authority, &argv, "draft plan");
    }

    #[test]
    fn unbranched_draft_writers_refuse_other_scope_caveats_before_observation() {
        let mut f = Fixture::new();
        for scope in ["accounts", "periods", "classes"] {
            let (_, authority) =
                f.scoped_agent(&format!("literal-{scope}"), None, |cap| match scope {
                    "accounts" => cap.for_accounts(&["1000"]).unwrap(),
                    "periods" => cap.for_periods(&["FY2026-P03"]).unwrap(),
                    "classes" => cap.for_classes(&[fa_model::EntryClass::ORIGINAL]).unwrap(),
                    _ => unreachable!(),
                });
            let literal = format!(
                r#"{{"effective_date":"{DATE}","idempotency_key":"literal-scoped","evidence":["{}"],"legs":[{{"side":"debit","account":"6000","amount":"1.00 USD"}},{{"side":"credit","account":"1000","amount":"1.00 USD"}}]}}"#,
                f.evidence
            );
            let batch =
                format!(r#"{{"idempotency_key":"literal-scoped-batch","intents":[{literal}]}}"#);
            for (argv, input) in [
                (
                    vec!["post", "--draft", "unobserved-draft", "--intent", "-"],
                    &literal,
                ),
                (
                    vec!["batch", "--draft", "unobserved-draft", "--intent", "-"],
                    &batch,
                ),
                (
                    vec!["draft", "plan", "unobserved-draft", "--intent", "-"],
                    &literal,
                ),
            ] {
                let before = f.book.head().unwrap();
                let (exit, refused) = f.bound(&authority, &argv, Some(input));
                assert_eq!(exit, 7, "{scope} {argv:?}: {refused:?}");
                assert_eq!(text(field(&refused, "data"), "refusal_id"), "FA-REF-011");
                assert_eq!(field(&refused, "coordinate"), &Json::Null);
                assert_eq!(f.book.head().unwrap(), before);
            }
        }
    }

    #[test]
    fn post_only_draft_capability_still_refuses_balance_entry_and_document_reads() {
        let mut f = Fixture::new();
        let name = "bounded-source";
        let (cap, authority) = f.agent("bounded-agent", Some(name));
        f.open(&authority, name);
        let first = f.fx_intent("batch-purchase-1");
        let second = f.fx_intent("batch-purchase-2");
        let batch =
            format!(r#"{{"idempotency_key":"confined-batch","intents":[{first},{second}]}}"#);
        let (exit, planned) = f.bound_events(
            &authority,
            &["batch", "--intent", "-", "--draft", name],
            Some(&batch),
        );
        assert_eq!(exit, 0, "{planned:?}");
        assert_eq!(planned.len(), 2);
        for member in &planned {
            assert_eq!(text(member, "event"), "draft_planned");
            let vid = VId(u128::from_str_radix(text(field(member, "data"), "entry"), 16).unwrap());
            assert!(f.book.read_entry(vid).unwrap().is_none());
        }
        assert_eq!(f.book.draft_entries(&cap, name).unwrap().unwrap().len(), 2);
        let (_, other_authority) = f.agent("other-draft-owner", Some("another-draft"));
        f.open(&other_authority, "another-draft");
        let evidence = f.evidence.clone();
        let rate = f.rate.clone();
        for argv in [
            vec!["tb", "--period", "FY2026-P03"],
            vec!["draft", "list"],
            vec!["draft", "show", name],
            vec!["entry", "show", "E:00000000000000000000000000000001"],
            vec!["document", "read", &evidence],
            vec!["document", "read", &rate],
        ] {
            let before = f.book.head().unwrap();
            let (exit, refused) = f.bound(&authority, &argv, None);
            assert_eq!(exit, 7, "argv={argv:?}: {refused:?}");
            assert_eq!(text(field(&refused, "data"), "refusal_id"), "FA-REF-011");
            assert_eq!(field(&refused, "book"), &Json::Null);
            assert_eq!(field(&refused, "coordinate"), &Json::Null);
            assert_eq!(f.book.head().unwrap(), before);
        }
        let reversal = format!(
            r#"{{"class":"Reversal","effective_date":"{DATE}","idempotency_key":"wrong-draft-reversal","reverses":"{}","reason":"WrongAmount"}}"#,
            text(field(&planned[0], "data"), "entry")
        );
        for other in ["another-draft", "not-created"] {
            for intent in [&first, &reversal] {
                let before = f.book.head().unwrap();
                let (exit, refused) = f.bound(
                    &authority,
                    &["post", "--intent", "-", "--draft", other],
                    Some(intent),
                );
                assert_eq!(exit, 7, "{refused:?}");
                assert!(text(field(&refused, "data"), "message").contains("branch"));
                assert_eq!(field(&refused, "coordinate"), &Json::Null);
                assert_eq!(f.book.head().unwrap(), before);
            }
        }
        let (_, unconfined) = f.agent("unconfined-agent", None);
        let before = f.book.head().unwrap();
        let (exit, refused) = f.bound(
            &unconfined,
            &["post", "--intent", "-", "--draft", name],
            Some(&first),
        );
        assert_eq!(
            exit, 7,
            "an absent branch grants no source read: {refused:?}"
        );
        assert_eq!(text(field(&refused, "data"), "refusal_id"), "FA-REF-011");
        assert_eq!(field(&refused, "coordinate"), &Json::Null);
        assert_eq!(f.book.head().unwrap(), before);
        let (exit, refused) = f.bound(&authority, &["post", "--intent", "-"], Some(&first));
        assert_eq!(exit, 7, "direct Agent trunk post: {refused:?}");
        assert_eq!(f.book.head().unwrap(), before);
    }
}
