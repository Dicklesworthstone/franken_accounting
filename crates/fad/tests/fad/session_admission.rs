//! A valid token envelope cannot authorize work when its journaled issuance
//! is corrupt or unreadable. Exercise both daemon entry points on real books.

use super::*;
use asupersync::Budget;
use asupersync::fs::UnixVfs;
use asupersync::runtime::RuntimeBuilder;
use fa::{Book, BookKeys, Capability, Entropy, Op as CapabilityOp, Profile};
use fa_cli::authority::{CapabilityToken, LaunchAuthority};
use fa_journal::BookSpec;
use fa_model::symbols::{property, relation};
use fa_model::{Id128, principal_vid};
use fa_money::UnitRegistry;
use fa_time::{DateDay, FiscalCalendar};
use fgdb::{Database, DatabaseKeys, WriteBatch};
use fgdb_types::CanonicalScalar;
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;

fn damaged_session_book(damage: &str) -> (PathBuf, [CapabilityToken; 2]) {
    let dir = tmp(&format!("admission-{damage}")).join("book");
    let keys = BookKeys::for_development(186);
    let mut book = Book::create_dir(
        &dir,
        keys.clone(),
        BookSpec {
            book_id: Id128([186; 16]),
            name: "Daemon admission corruption".into(),
            base_unit: UnitRegistry::embedded().unwrap().lookup("USD").unwrap(),
            calendar: FiscalCalendar::monthly("admission", 1, 1).unwrap(),
            time_zone_policy: Some(fa_journal::TimeZonePolicy::Utc),
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(186),
    )
    .unwrap();
    keys.save(&dir.join("book.keys")).unwrap();
    let issuer = Capability::embedded(
        principal_vid("issuer"),
        &["issue_capability", "read", "witness"],
    )
    .unwrap();
    let token = |name, profile, ops: &[CapabilityOp]| {
        let secret = [186; 32];
        CapabilityToken::new(
            name,
            Capability::new(principal_vid(name), profile, ops, issuer.holder())
                .unwrap()
                .holder_bound(fa_model::domain_digest(
                    b"fa:capability-possession:v1",
                    &[&secret],
                )),
            secret,
        )
        .unwrap()
    };
    let tokens = [
        token(
            "daemon-operator",
            Profile::Human,
            &[CapabilityOp::Read, CapabilityOp::Witness],
        ),
        token("hosted-agent", Profile::Agent, &[CapabilityOp::Read]),
    ];
    for token in &tokens {
        book.issue_capability(
            issuer.clone(),
            token.capability().clone(),
            DateDay::from_ymd(2026, 3, 15).unwrap(),
            token.principal().as_bytes(),
            "Daemon admission fixture",
        )
        .unwrap()
        .unwrap();
        book.admit_current(token.capability()).unwrap().unwrap();
    }
    drop(book);

    // Damage only issuance rows while the facade is closed. Genesis and the
    // frontier stay readable, so any later publication is the daemon's own.
    let runtime = RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let cx = PurposeContexts::narrow_runtime_root(&root);
    let mut db = runtime
        .block_on(Database::open_with_vfs(
            &cx.commit(),
            UnixVfs::new(),
            dir.join("store"),
            DatabaseKeys::new([186; 32], DatabaseSecurityNamespaceId([187; 32]), [188; 32]),
        ))
        .unwrap();
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    for token in &tokens {
        let vid =
            fa_journal::issuance_vid(Id128([186; 16]), &token.capability().commitment().unwrap());
        match damage {
            "payload" => {
                batch.set_vertex_property(
                    vid,
                    property::FA_PAYLOAD,
                    Some(CanonicalScalar::bytes(vec![0xff; 8]).unwrap()),
                );
            }
            "issuer" => {
                let (entry, _) = fa_journal::post::read_entry(&db, vid).unwrap().unwrap();
                let mut proposal = entry.proposal;
                proposal.principal_ref = principal_vid("not-the-issuer");
                let malformed = proposal.seal(Vec::new(), None).unwrap();
                for (key, value) in fa_model::entry_mirrors(&malformed).unwrap() {
                    batch.set_vertex_property(vid, key, Some(value));
                }
            }
            _ => panic!("unknown issuance damage: {damage}"),
        }
    }
    runtime.block_on(db.write(&cx.commit(), batch)).unwrap();
    drop(db);
    (dir, tokens)
}

#[test]
fn admission_errors_refuse_before_dispatch_access_receipts_and_command_ticks() {
    for damage in ["payload", "issuer"] {
        let (dir, [token, _]) = damaged_session_book(damage);
        let mut book = Book::open_dir(
            &dir,
            BookKeys::for_development(186),
            Entropy::deterministic(186),
        )
        .unwrap();
        assert!(book.admit_current(token.capability()).is_err());
        let before = book.head().unwrap();
        let runtime = RuntimeBuilder::new().build().unwrap();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let authority = LaunchAuthority::from_operator_token(dir.clone(), None, &token).unwrap();
        for timed in [false, true] {
            let work = timed.then(|| {
                fad::timed::TimedWork::bootstrap(
                    &cx,
                    &book,
                    fad::timed::Policy {
                        tick_ns: 3_600_000_000_000,
                        sweep_batch: 1,
                        clock_drift_ns: 1_000_000_000,
                    },
                )
                .unwrap()
            });
            let mut server = fad::Server {
                book: &mut book,
                dir: dir.clone(),
                socket: dir.join("fad.sock"),
                files_root: None,
                requests: 0,
                timed: work,
                daemon_uid: None,
                timings: Vec::new(),
            };
            for args in [
                vec!["--help", "--json"],
                vec!["tb", "--json"],
                vec!["checkpoint", "create", "--json"],
            ] {
                let argv: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
                let error = server.book.admit_current(token.capability()).unwrap_err();
                let (exit, expected) =
                    fa_cli::cli::book_error_with_authority(&argv, error, &authority, true);
                let (response, next) = runtime.block_on(server.handle(
                    &cx,
                    Request {
                        op: Op::Run,
                        argv,
                        cwd: None,
                        stdin: None,
                        token: Some(token.canonical_bytes().unwrap()),
                    },
                ));
                assert_eq!(response.exit, 5, "{damage}, timed={timed}, {args:?}");
                assert_eq!(response.exit, exit);
                assert_eq!(response.stdout, expected.stdout);
                assert_eq!(response.stderr, expected.stderr);
                assert!(matches!(next, fad::Next::Continue));
                checked(&response.stdout);
                assert_eq!(field(&response.stdout, "posture"), Some("issued-token"));
                assert_eq!(
                    field(&response.stdout, "principal"),
                    Some(token.principal())
                );
                assert_eq!(server.book.head().unwrap(), before);
                assert!(server.book.latest_tick().unwrap().is_none());
                assert!(server.book.checkpoints().unwrap().is_empty());
            }
            assert_eq!(server.requests, 3, "each failed request is counted once");
        }
    }
}

#[test]
fn hosted_mcp_admission_errors_stop_before_socket_time_evidence_or_spawn() {
    for damage in ["payload", "issuer"] {
        let (dir, [_, token]) = damaged_session_book(damage);
        let token_file = dir.parent().unwrap().join("session.token");
        std::fs::write(&token_file, token.canonical_bytes().unwrap()).unwrap();
        let book = Book::open_dir(
            &dir,
            BookKeys::for_development(186),
            Entropy::deterministic(186),
        )
        .unwrap();
        let before = book.head().unwrap();
        let error = book.admit_current(token.capability()).unwrap_err();
        let authority = LaunchAuthority::from_token(dir.clone(), None, &token).unwrap();
        let args = vec![
            "serve".to_owned(),
            "--book".to_owned(),
            dir.display().to_string(),
            "--mcp".to_owned(),
            "stdio".to_owned(),
            "--token".to_owned(),
            token_file.display().to_string(),
            "--bootstrap-system".to_owned(),
            "--json".to_owned(),
        ];
        let (exit, expected) =
            fa_cli::cli::book_error_with_authority(&args, error, &authority, true);
        drop(book);
        // A regression cannot block on a real MCP child. This absent program
        // instead produces a distinguishable spawn error if admission leaks.
        let output = Command::new(env!("CARGO_BIN_EXE_fad"))
            .args(&args)
            .env_remove("FA_BOOK")
            .env_remove("FA_TOKEN")
            .env("FA_MCP_BIN", dir.join("absent-mcp"))
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(i32::from(exit)),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(stdout, expected.stdout);
        assert_eq!(stderr, expected.stderr);
        checked(&stdout);
        assert!(!dir.join("fad.sock").exists());
        let book = Book::open_dir(
            &dir,
            BookKeys::for_development(186),
            Entropy::deterministic(186),
        )
        .unwrap();
        assert_eq!(book.head().unwrap(), before);
        assert!(book.latest_tick().unwrap().is_none());
        assert!(book.checkpoints().unwrap().is_empty());
    }
}

#[test]
fn historical_query_tokens_keep_the_same_authority_over_the_real_daemon_socket() {
    use fa_cli::json::{self, Json};

    let dir = tmp("historical-query");
    let (book_dir, _) = book(&dir);
    let b = book_dir.display().to_string();
    let current_head = || {
        let info = json::parse(&ok(&["book", "info", "--book", &b, "--json"])).unwrap();
        match info.get("coordinate").unwrap().get("known_at").unwrap() {
            Json::Int(seq) => u64::try_from(*seq).unwrap(),
            other => panic!("known_at: {other:?}"),
        }
    };
    let pin = current_head();
    let statement = format!("MATCH (p:Period) RETURN COUNT(*) AS periods AS KNOWN AT {pin}");
    let token = dir.join("history-reader.token").display().to_string();
    let issued = json::parse(&ok(&[
        "capability",
        "issue",
        "--book",
        &b,
        "--holder",
        "history-reader",
        "--profile",
        "agent",
        "--op",
        "read",
        "--known-at-most",
        &pin.to_string(),
        "--out",
        &token,
        "--grant",
        "issue_capability",
        "--grant",
        "read",
        "--json",
    ]))
    .unwrap();
    ok(&[
        "period",
        "create",
        "--fiscal-year",
        "2027",
        "--book",
        &b,
        "--json",
    ]);
    let expected = json::parse(&ok(&[
        "query", &statement, "--token", &token, "--book", &b, "--via", "direct", "--json",
    ]))
    .unwrap();
    let mut daemon = start(&book_dir);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let before = current_head();
        let served = json::parse(&ok(&[
            "query", &statement, "--token", &token, "--book", &b, "--via", "fad", "--json",
        ]))
        .unwrap();
        assert_eq!(served.get("data"), expected.get("data"));
        assert_eq!(served.get("coordinate"), expected.get("coordinate"));
        assert_eq!(served.get("authority"), expected.get("authority"));
        assert_eq!(
            current_head(),
            before + 1,
            "exactly one admitted access receipt"
        );
        for denied_statement in [
            "MATCH (p:Period) RETURN COUNT(*) AS periods".to_string(),
            format!(
                "MATCH (p:Period) RETURN COUNT(*) AS periods AS KNOWN AT {}",
                pin + 1
            ),
            "MATCH (p:Period) RETURN COUNT(*) AS periods AT BRANCH 'draft:unreadable'".to_string(),
        ] {
            let (exit, stdout, stderr) = fa(&[
                "query",
                &denied_statement,
                "--token",
                &token,
                "--book",
                &b,
                "--via",
                "fad",
                "--json",
            ]);
            assert_eq!(exit, 7, "{stdout}{stderr}");
            let denied = json::parse(stdout.trim()).unwrap();
            assert_eq!(
                denied
                    .get("data")
                    .unwrap()
                    .get("refusal_id")
                    .and_then(Json::as_str),
                Some("FA-REF-011")
            );
            assert_eq!(denied.get("book"), Some(&Json::Null));
            assert_eq!(denied.get("coordinate"), Some(&Json::Null));
            assert_eq!(
                current_head(),
                before + 1,
                "a refused read is never published"
            );
        }
        ok(&[
            "capability",
            "revoke",
            "--book",
            &b,
            "--commitment",
            issued
                .get("data")
                .unwrap()
                .get("commitment")
                .unwrap()
                .as_str()
                .unwrap(),
            "--grant",
            "issue_capability",
            "--yes",
            "--via",
            "fad",
            "--json",
        ]);
        let revoked_head = current_head();
        let (exit, stdout, stderr) = fa(&[
            "query", &statement, "--token", &token, "--book", &b, "--via", "fad", "--json",
        ]);
        assert_eq!(exit, 7, "{stdout}{stderr}");
        let denied = json::parse(stdout.trim()).unwrap();
        assert_eq!(
            denied
                .get("data")
                .unwrap()
                .get("refusal_id")
                .and_then(Json::as_str),
            Some("FA-REF-023")
        );
        assert_eq!(denied.get("book"), Some(&Json::Null));
        assert_eq!(denied.get("coordinate"), Some(&Json::Null));
        assert_eq!(current_head(), revoked_head);
    }));
    let (exit, stdout, stderr) = fad(&["stop", "--book", &b, "--json"]);
    if exit != 0 && daemon.child.try_wait().ok().flatten().is_none() {
        let _ = daemon.child.kill();
    }
    let (daemon_exit, rest) = daemon.finish();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
    assert_eq!(exit, 0, "{stdout}{stderr}");
    assert_eq!(daemon_exit, 0, "{rest}");
}
