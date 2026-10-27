//! The connection loop under asupersync's lab runtime (deterministic
//! scheduling, seeded; chaos on for the second half), over a virtual stream
//! pair. Real Unix sockets do not run under the lab reactor, so the socket
//! itself, the lease, and crash recovery are tested with real processes in
//! `tests/fad.rs`; everything the loop decides is tested here.

use super::*;
use asupersync::LabConfig;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::lab::{run_async_under_lab, run_async_under_lab_with_config};
use asupersync::net::tcp::VirtualTcpStream;
use fa_cli::wire::{Decoder, encode};

const MAX: usize = 4096;
const LIMITS: Limits = Limits {
    protocol: 1,
    max_frame_bytes: MAX,
    idle: None,
};

fn addr(port: u16) -> std::net::SocketAddr {
    ([127, 0, 0, 1], port).into()
}

fn request(op: Op, n: usize) -> Request {
    Request {
        op,
        argv: vec!["tb".into(), format!("--n={n}"), "--json".into()],
        cwd: None,
        stdin: None,
        token: None,
    }
}

fn frame(r: &Request) -> Vec<u8> {
    let payload = r.to_json(1).render();
    encode(payload.as_bytes(), MAX).unwrap_or_default()
}

/// What the server saw, how it ended, and the frames the client got back.
type Run = (Vec<Vec<String>>, Ended, Vec<Vec<u8>>);

/// The book directory the lab connections serve.
const BOOK: &str = "/books/lab";

/// Real holder-bound tokens: only journaled issuance makes these grants usable.
fn operator_token(
    principal: &str,
    capability: fa::Capability,
) -> fa_cli::authority::CapabilityToken {
    let secret = [185; 32];
    fa_cli::authority::CapabilityToken::new(
        principal,
        capability.holder_bound(fa_model::domain_digest(
            b"fa:capability-possession:v1",
            &[&secret],
        )),
        secret,
    )
    .unwrap()
}

fn issue_operator_token(
    book: &mut Book,
    issuer: &fa::Capability,
    token: &fa_cli::authority::CapabilityToken,
) {
    book.issue_capability(
        issuer.clone(),
        token.capability().clone(),
        fa_time::DateDay::from_ymd(2026, 3, 15).unwrap(),
        format!("issue-{}", token.principal()).as_bytes(),
        "Operator session test grant",
    )
    .unwrap()
    .unwrap();
}

#[test]
fn issued_operator_sessions_admit_before_ticking_and_recheck_after_the_tick() {
    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;
    use fa::{BookKeys, Capability, Entropy, Op as CapabilityOp, Profile};
    use fa_journal::BookSpec;
    use fa_model::{ControlPayload, Id128, principal_vid};
    use fa_money::UnitRegistry;
    use fa_time::{DateDay, FiscalCalendar};
    use fgdb_types::CommitSeq;

    let mut book = Book::create_memory(
        BookKeys::for_development(185),
        BookSpec {
            book_id: Id128([185; 16]),
            name: "Issued daemon operator".into(),
            base_unit: UnitRegistry::embedded().unwrap().lookup("USD").unwrap(),
            calendar: FiscalCalendar::monthly("operator-clock", 1, 1).unwrap(),
            time_zone_policy: Some(fa_journal::TimeZonePolicy::Utc),
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(185),
    )
    .unwrap();
    let issuer = Capability::embedded(
        principal_vid("operator-issuer"),
        &[
            "issue_capability",
            "witness",
            "close",
            "read",
            "post",
            "verify",
        ],
    )
    .unwrap();
    let capability = |principal, profile, ops: &[CapabilityOp]| {
        Capability::new(principal_vid(principal), profile, ops, issuer.holder()).unwrap()
    };
    let witness = operator_token(
        "witness",
        capability("witness", Profile::Human, &[CapabilityOp::Witness]),
    );
    let revoked = operator_token(
        "revoked",
        capability("revoked", Profile::Human, &[CapabilityOp::Witness]),
    );
    let wrong_book = operator_token(
        "wrong-book",
        capability("wrong-book", Profile::Human, &[CapabilityOp::Witness])
            .for_books(&[Id128([186; 16])])
            .unwrap(),
    );
    let expired = operator_token(
        "expired",
        capability("expired", Profile::Human, &[CapabilityOp::Witness]).expiring_at(CommitSeq(0)),
    );
    let no_witness = operator_token(
        "controller-without-witness",
        capability(
            "controller-without-witness",
            Profile::Human,
            &[CapabilityOp::Close],
        ),
    );
    let agent = operator_token(
        "raw-agent",
        capability(
            "raw-agent",
            Profile::Agent,
            &[CapabilityOp::Read, CapabilityOp::Post],
        ),
    );
    let preparer = operator_token(
        "raw-preparer",
        capability(
            "raw-preparer",
            Profile::Human,
            &[CapabilityOp::Read, CapabilityOp::Post],
        ),
    );
    let never_issued = operator_token(
        "never-issued",
        capability("never-issued", Profile::Human, &[CapabilityOp::Witness]),
    );
    for token in [
        &witness,
        &revoked,
        &wrong_book,
        &expired,
        &no_witness,
        &agent,
        &preparer,
    ] {
        issue_operator_token(&mut book, &issuer, token);
    }
    book.revoke_capability(
        issuer.clone(),
        revoked.capability().commitment().unwrap(),
        DateDay::from_ymd(2026, 3, 15).unwrap(),
        b"revoke-before-session",
        "Withdraw witness",
    )
    .unwrap()
    .unwrap();

    let runtime = RuntimeBuilder::new().build().unwrap();
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    let work = timed::TimedWork::bootstrap(
        &cx,
        &book,
        timed::Policy {
            tick_ns: 3_600_000_000_000,
            sweep_batch: 1,
            clock_drift_ns: 1_000_000_000,
        },
    )
    .unwrap();
    let mut server = Server {
        book: &mut book,
        dir: PathBuf::from(BOOK),
        socket: PathBuf::from(BOOK).join("fad.sock"),
        files_root: None,
        requests: 0,
        timed: Some(work),
        daemon_uid: None,
        timings: Vec::new(),
    };
    let request = |argv: &[&str], bytes: Vec<u8>| Request {
        op: Op::Run,
        argv: argv.iter().map(|s| (*s).to_owned()).collect(),
        cwd: None,
        stdin: None,
        token: Some(bytes),
    };
    let checkpoint = |token: &fa_cli::authority::CapabilityToken| {
        request(
            &["checkpoint", "create", "--json"],
            token.canonical_bytes().unwrap(),
        )
    };
    let before = server.book.head().unwrap();
    for token in [&never_issued, &revoked, &wrong_book, &expired, &no_witness] {
        let (response, _) = runtime.block_on(server.handle(&cx, checkpoint(token)));
        assert_eq!(
            response.exit,
            7,
            "{}: {}{}",
            token.principal(),
            response.stdout,
            response.stderr
        );
        assert_eq!(server.book.head().unwrap(), before, "{}", token.principal());
        assert!(server.book.latest_tick().unwrap().is_none());
        assert!(server.book.checkpoints().unwrap().is_empty());
    }
    let mut forged = witness.canonical_bytes().unwrap();
    *forged.last_mut().unwrap() ^= 1;
    let (response, _) =
        runtime.block_on(server.handle(&cx, request(&["checkpoint", "create", "--json"], forged)));
    assert_eq!(response.exit, 2, "{}{}", response.stdout, response.stderr);
    assert_eq!(server.book.head().unwrap(), before);
    for token in [&agent, &preparer] {
        let bytes = token.canonical_bytes().unwrap();
        assert!(!server.session(&bytes).unwrap().can_confirm());
        for argv in [
            vec!["checkpoint", "create", "--yes", "--json"],
            vec!["period", "close", "FY2026-P03", "--yes", "--json"],
            vec!["period", "close", "FY2026-P03", "--plan", "false", "--json"],
            vec![
                "period",
                "close",
                "FY2026-P03",
                "--plan-out=true",
                "--plan=false",
                "--json",
            ],
        ] {
            let (response, _) = runtime.block_on(server.handle(&cx, request(&argv, bytes.clone())));
            let exit = if argv.contains(&"--yes") { 2 } else { 7 };
            assert_eq!(
                response.exit, exit,
                "{argv:?}: {}{}",
                response.stdout, response.stderr
            );
            assert_eq!(server.book.head().unwrap(), before, "{argv:?}");
            assert!(server.book.latest_tick().unwrap().is_none());
        }
    }
    // A separating Human grant does not release principal or operation binding.
    for argv in [
        vec!["checkpoint", "create", "--as", "operator-issuer", "--json"],
        vec!["checkpoint", "create", "--grant", "witness", "--json"],
    ] {
        let (response, _) = runtime
            .block_on(server.handle(&cx, request(&argv, witness.canonical_bytes().unwrap())));
        assert_eq!(response.exit, 2, "{}{}", response.stdout, response.stderr);
        assert_eq!(server.book.head().unwrap(), before);
    }
    assert!(
        server
            .session(&witness.canonical_bytes().unwrap())
            .unwrap()
            .can_confirm()
    );
    let (startup, _) = runtime.block_on(server.handle(&cx, checkpoint(&witness)));
    assert_eq!(startup.exit, 3, "{}{}", startup.stdout, startup.stderr);
    assert!(startup.stdout.contains("FA-REF-144"));
    let first = server.book.latest_tick().unwrap().unwrap();
    assert!(server.book.checkpoints().unwrap().is_empty());

    let (created, _) = runtime.block_on(server.handle(&cx, checkpoint(&witness)));
    assert_eq!(created.exit, 0, "{}{}", created.stdout, created.stderr);
    assert!(created.stdout.contains("\"checkpoint_created\""));
    let second = server.book.latest_tick().unwrap().unwrap();
    assert!(second.observed_utc_ns > first.observed_utc_ns);
    let (entry, tick_seq) = server.book.read_entry(second.entry).unwrap().unwrap();
    assert!(matches!(
        entry.proposal.control,
        Some(ControlPayload::TimeTick {
            monotonic_ok: true,
            ..
        })
    ));
    let checkpoints = server.book.checkpoints().unwrap();
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].state.through_seq, tick_seq);
    assert!(checkpoints[0].recorded_at > tick_seq);
    assert!(server.book.verify_accumulator().unwrap().is_green());

    // Existing capability expiry is a sequence bound. This token is valid
    // before the command tick, then expires exactly at that publication.
    let expiry = CommitSeq(server.book.head().unwrap().0 + 2);
    let on_tick = operator_token(
        "expires-on-tick",
        capability("expires-on-tick", Profile::Human, &[CapabilityOp::Witness]).expiring_at(expiry),
    );
    issue_operator_token(server.book, &issuer, &on_tick);
    assert!(
        server
            .book
            .admit_current(on_tick.capability())
            .unwrap()
            .is_ok()
    );
    let (refused, _) = runtime.block_on(server.handle(&cx, checkpoint(&on_tick)));
    assert_eq!(refused.exit, 7, "{}{}", refused.stdout, refused.stderr);
    assert_eq!(server.book.head().unwrap(), expiry);
    assert_eq!(server.book.checkpoints().unwrap().len(), 1);
    assert_ne!(server.book.latest_tick().unwrap(), Some(second));
    let after_expiry = server.book.head().unwrap();
    let latest = server.book.latest_tick().unwrap();
    let (again, _) = runtime.block_on(server.handle(&cx, checkpoint(&on_tick)));
    assert_eq!(again.exit, 7, "{}{}", again.stdout, again.stderr);
    assert_eq!(server.book.head().unwrap(), after_expiry);
    assert_eq!(server.book.latest_tick().unwrap(), latest);

    server
        .book
        .revoke_capability(
            issuer,
            witness.capability().commitment().unwrap(),
            DateDay::from_ymd(2026, 3, 15).unwrap(),
            b"revoke-active-session",
            "Withdraw the active witness",
        )
        .unwrap()
        .unwrap();
    let revoked_at = server.book.head().unwrap();
    let (revoked, _) = runtime.block_on(server.handle(&cx, checkpoint(&witness)));
    assert_eq!(revoked.exit, 7, "{}{}", revoked.stdout, revoked.stderr);
    assert_eq!(server.book.head().unwrap(), revoked_at);
    assert_eq!(server.book.latest_tick().unwrap(), latest);
    assert_eq!(server.book.checkpoints().unwrap().len(), 1);
}

#[test]
fn critical_requests_admit_before_observation_and_preserve_preview_frontiers() {
    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;
    use fa::{BookKeys, Entropy};
    use fa_journal::BookSpec;
    use fa_model::Id128;
    use fa_money::UnitRegistry;
    use fa_time::{FiscalCalendar, PeriodState};

    let mut book = Book::create_memory(
        BookKeys::for_development(184),
        BookSpec {
            book_id: Id128([184; 16]),
            name: "Command time evidence".into(),
            base_unit: UnitRegistry::embedded().unwrap().lookup("USD").unwrap(),
            calendar: FiscalCalendar::monthly("command-clock", 1, 1).unwrap(),
            time_zone_policy: Some(fa_journal::TimeZonePolicy::Utc),
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(184),
    )
    .unwrap();
    let runtime = RuntimeBuilder::new().build().unwrap();
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    let work = timed::TimedWork::bootstrap(
        &cx,
        &book,
        timed::Policy {
            tick_ns: 3_600_000_000_000,
            sweep_batch: 1,
            clock_drift_ns: 1_000_000_000,
        },
    )
    .unwrap();
    let mut server = Server {
        book: &mut book,
        dir: PathBuf::from(BOOK),
        socket: PathBuf::from(BOOK).join("fad.sock"),
        files_root: None,
        requests: 0,
        timed: Some(work),
        daemon_uid: None,
        timings: Vec::new(),
    };
    let request = |argv: &[&str]| Request {
        op: Op::Run,
        argv: argv.iter().map(|s| (*s).to_owned()).collect(),
        cwd: None,
        stdin: None,
        token: None,
    };
    for argv in [
        vec!["period", "create", "--fiscal-year", "2026", "--json"],
        vec!["period", "open", "FY2026-P03", "--json"],
    ] {
        let (response, _) = runtime.block_on(server.handle(&cx, request(&argv)));
        assert_eq!(response.exit, 0, "{}{}", response.stdout, response.stderr);
    }
    assert!(server.book.latest_tick().unwrap().is_none());
    let before = server.book.head().unwrap();
    for (argv, exit) in [
        (
            vec!["period", "soft-close", "FY2026-P03", "--dry-run", "--json"],
            0,
        ),
        (vec!["period", "close", "--help", "--json"], 0),
        (vec!["period", "close", "FY2026-P03", "--json"], 7),
        (vec!["checkpoint", "create", "--json"], 7),
        (
            vec!["checkpoint", "create", "--grant", "witness", "--json"],
            7,
        ),
        (
            vec![
                "period",
                "close",
                "FY2026-P03",
                "--dry-run",
                "--plan",
                "-",
                "--json",
            ],
            2,
        ),
        (vec!["sweep", "now", "--dry-run", "--json"], 2),
    ] {
        let (response, _) = runtime.block_on(server.handle(&cx, request(&argv)));
        assert_eq!(
            response.exit, exit,
            "{argv:?}: {}{}",
            response.stdout, response.stderr
        );
        assert_eq!(server.book.head().unwrap(), before, "{argv:?}");
        assert!(server.book.latest_tick().unwrap().is_none(), "{argv:?}");
    }
    let mut forged = request(&["period", "soft-close", "FY2026-P03", "--json"]);
    forged.token = Some(vec![0; 32]);
    let (refused, _) = runtime.block_on(server.handle(&cx, forged));
    assert_eq!(refused.exit, 2);
    assert_eq!(server.book.head().unwrap(), before);

    // The first actual command records the startup observation honestly, and
    // is refused until a later independent sample corroborates the clock.
    let close = request(&["period", "soft-close", "FY2026-P03", "--json"]);
    let (startup, _) = runtime.block_on(server.handle(&cx, close.clone()));
    assert_eq!(startup.exit, 3, "{}{}", startup.stdout, startup.stderr);
    assert!(startup.stdout.contains("FA-REF-144"));
    assert_eq!(
        server
            .book
            .periods()
            .unwrap()
            .into_iter()
            .find(|p| p.code == "FY2026-P03")
            .unwrap()
            .state,
        PeriodState::Open
    );
    let first = server.book.latest_tick().unwrap().unwrap();
    let (closed, _) = runtime.block_on(server.handle(&cx, close));
    assert_eq!(closed.exit, 0, "{}{}", closed.stdout, closed.stderr);
    assert_eq!(
        server
            .book
            .periods()
            .unwrap()
            .into_iter()
            .find(|p| p.code == "FY2026-P03")
            .unwrap()
            .state,
        PeriodState::SoftClosed
    );
    let second = server.book.latest_tick().unwrap().unwrap();
    assert!(second.observed_utc_ns > first.observed_utc_ns);
    assert_eq!(
        server.status_data().get("timed_cycles"),
        Some(&Json::Int(0))
    );

    // `fa explain period` shows the tick the daemon journaled before the
    // soft close (fa-7uhr). The open ran before any tick, so it names none;
    // the startup observation was never corroborated, so nothing names it.
    let (explained, _) = runtime
        .block_on(server.handle(&cx, request(&["explain", "period", "FY2026-P03", "--json"])));
    assert_eq!(
        explained.exit, 0,
        "{}{}",
        explained.stdout, explained.stderr
    );
    let line = fa_cli::json::parse(explained.stdout.lines().last().unwrap()).unwrap();
    let transitions = line
        .get("data")
        .and_then(|data| data.get("transitions"))
        .and_then(Json::as_arr)
        .unwrap();
    assert_eq!(transitions.len(), 2, "{}", explained.stdout);
    assert_eq!(transitions[0].get("to"), Some(&Json::Str("Open".into())));
    assert_eq!(transitions[0].get("recorded_after"), Some(&Json::Null));
    let soft_close = &transitions[1];
    assert_eq!(soft_close.get("to"), Some(&Json::Str("SoftClosed".into())));
    let after = soft_close.get("recorded_after").unwrap();
    let (_, tick_seq) = server.book.read_entry(second.entry).unwrap().unwrap();
    assert_eq!(
        after.get("entry"),
        Some(&Json::Str(format!("{:032x}", second.entry.0)))
    );
    assert_eq!(
        after.get("observed_utc_ns"),
        Some(&Json::Int(i128::from(second.observed_utc_ns)))
    );
    assert_eq!(after.get("monotonic_ok"), Some(&Json::Bool(true)));
    assert_eq!(
        after.get("recorded_at"),
        Some(&Json::Int(i128::from(tick_seq.0)))
    );
    let Some(Json::Int(closed_at)) = soft_close.get("recorded_at") else {
        panic!("{}", explained.stdout);
    };
    assert!(i128::from(tick_seq.0) < *closed_at);
    assert_ne!(
        after.get("entry"),
        Some(&Json::Str(format!("{:032x}", first.entry.0)))
    );

    // The public alias and its canonical command both request fresh time.
    for argv in [
        vec!["sweep", "now", "--json"],
        vec!["schedule", "sweep", "--json"],
    ] {
        let previous = server.book.latest_tick().unwrap().unwrap();
        let (response, _) = runtime.block_on(server.handle(&cx, request(&argv)));
        assert_eq!(
            response.exit, 0,
            "{argv:?}: {}{}",
            response.stdout, response.stderr
        );
        assert!(
            server.book.latest_tick().unwrap().unwrap().observed_utc_ns > previous.observed_utc_ns
        );
    }
}

/// Real dispatcher and memory book, with a long timer so the commit hook
/// itself must make maintenance ready. No virtual handler stands in for it.
#[test]
fn fiscal_year_cohort_picks_up_later_period_creation_without_widening_to_another_year() {
    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;
    use fa::{BookKeys, Entropy};
    use fa_journal::BookSpec;
    use fa_model::Id128;
    use fa_money::UnitRegistry;
    use fa_time::{CustomYear, DateDay, FiscalCalendar};

    let date = |year| DateDay::from_ymd(year, 1, 1).unwrap();
    let calendar = FiscalCalendar::custom(
        "cohort",
        vec![
            CustomYear {
                fiscal_year: 2026,
                bounds: vec![date(2026), date(2027)],
            },
            CustomYear {
                fiscal_year: 2027,
                bounds: vec![date(2027), date(2028)],
            },
        ],
        0,
    )
    .unwrap();
    let mut book = Book::create_memory(
        BookKeys::for_development(164),
        BookSpec {
            book_id: Id128([164; 16]),
            name: "Future period cohort".into(),
            base_unit: UnitRegistry::embedded().unwrap().lookup("USD").unwrap(),
            calendar: calendar.clone(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(164),
    )
    .unwrap();
    assert!(book.periods().unwrap().is_empty());
    let periods = timed::registers::fiscal_year_periods(&calendar, 2026).unwrap();
    assert_eq!(periods, ["FY2026-P01", "FY2026-OPEN", "FY2026-CLOSE"]);
    let runtime = RuntimeBuilder::new().build().unwrap();
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    let work = timed::TimedWork::maintenance_only(
        &cx,
        timed::Policy {
            tick_ns: 3_600_000_000_000,
            sweep_batch: 1,
            clock_drift_ns: 0,
        },
        periods,
    )
    .unwrap();
    let scheduled = work.deadline();
    let mut server = Server {
        book: &mut book,
        dir: PathBuf::from(BOOK),
        socket: PathBuf::from(BOOK).join("fad.sock"),
        files_root: None,
        requests: 0,
        timed: Some(work),
        daemon_uid: None,
        timings: Vec::new(),
    };
    for (index, args) in [
        vec!["period", "create", "--fiscal-year", "2027", "--json"],
        vec!["period", "create", "--fiscal-year", "2026", "--json"],
        vec!["period", "open", "FY2026-P01", "--json"],
        vec!["period", "open", "FY2027-P01", "--json"],
    ]
    .into_iter()
    .enumerate()
    {
        let (response, _) = server.handle(Request {
            op: Op::Run,
            argv: args.iter().map(|arg| (*arg).to_owned()).collect(),
            cwd: None,
            stdin: None,
            token: None,
        });
        assert_eq!(
            response.exit, 0,
            "{args:?}: {}{}",
            response.stdout, response.stderr
        );
        let committed = server.book.head().unwrap();
        runtime.block_on(server.tick(&cx));
        let work = server.timed.as_ref().unwrap();
        assert!(!work.timing_enabled());
        assert_eq!(work.deadline(), scheduled);
        let registers = work.register_maintenance().unwrap();
        assert_eq!(registers.attempts(), (index + 1) as u64);
        assert!(
            registers
                .periods()
                .iter()
                .all(|period| period.period.starts_with("FY2026-"))
        );
        if index == 0 {
            assert!(registers.periods()[0].error.is_some());
            assert!(registers.periods()[0].last_success.is_none());
            assert_eq!(server.book.head().unwrap(), committed);
        } else {
            assert_eq!(
                registers.periods()[index % 3]
                    .last_success
                    .as_ref()
                    .unwrap()
                    .through,
                committed.0
            );
        }
    }
    let work = server
        .timed
        .as_ref()
        .unwrap()
        .register_maintenance()
        .unwrap();
    assert!(
        work.periods()
            .iter()
            .all(|period| period.error.is_none() && period.last_success.is_some())
    );
    let maintained = server.book.verify_registers("FY2026-P01").unwrap();
    assert!(maintained.is_green(), "{maintained:?}");
    assert!(maintained.verified_through.is_some());
    let unselected = server.book.verify_registers("FY2027-P01").unwrap();
    assert_eq!(unselected.verified_through, None);
}

#[test]
fn server_wakes_configured_registers_only_when_a_request_commits() {
    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;
    use fa::{BookKeys, Entropy};
    use fa_journal::BookSpec;
    use fa_model::Id128;
    use fa_money::UnitRegistry;
    use fa_time::FiscalCalendar;

    let mut book = Book::create_memory(
        BookKeys::for_development(163),
        BookSpec {
            book_id: Id128([163; 16]),
            name: "Commit-woken maintenance".into(),
            base_unit: UnitRegistry::embedded().unwrap().lookup("USD").unwrap(),
            calendar: FiscalCalendar::monthly("wake", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(163),
    )
    .unwrap();
    let runtime = RuntimeBuilder::new().build().unwrap();
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    let policy = timed::Policy {
        tick_ns: 3_600_000_000_000,
        sweep_batch: 1,
        clock_drift_ns: 0,
    };
    let work = timed::TimedWork::maintenance_only(&cx, policy, vec!["FY2026-P03".into()]).unwrap();
    let scheduled = work.deadline();
    let mut server = Server {
        book: &mut book,
        dir: PathBuf::from(BOOK),
        socket: PathBuf::from(BOOK).join("fad.sock"),
        files_root: None,
        requests: 0,
        timed: Some(work),
        daemon_uid: None,
        timings: Vec::new(),
    };
    let run = |argv: &[&str]| Request {
        op: Op::Run,
        argv: argv.iter().map(|s| (*s).to_owned()).collect(),
        cwd: None,
        stdin: None,
        token: None,
    };
    let before = server.book.head().unwrap();
    let (read, _) = runtime.block_on(server.handle(&cx, run(&["book", "info", "--json"])));
    assert_eq!(read.exit, 0, "{}{}", read.stdout, read.stderr);
    assert_eq!(server.book.head().unwrap(), before);
    assert_eq!(server.deadline(), scheduled);
    let (bad, _) = runtime.block_on(server.handle(
        &cx,
        run(&["period", "create", "--fiscal-year", "bad", "--json"]),
    ));
    assert_ne!(bad.exit, 0);
    assert_eq!(server.book.head().unwrap(), before);
    assert_eq!(server.deadline(), scheduled);

    let create = run(&["period", "create", "--fiscal-year", "2026", "--json"]);
    let (created, _) = runtime.block_on(server.handle(&cx, create.clone()));
    assert_eq!(created.exit, 0, "{}{}", created.stdout, created.stderr);
    let committed = server.book.head().unwrap();
    assert!(committed > before);
    assert_eq!(server.deadline(), Some(Time::from_nanos(0)));
    runtime.block_on(server.tick(&cx));
    let work = server.timed.as_ref().unwrap();
    assert_eq!(work.deadline(), scheduled);
    assert!(!work.timing_enabled());
    let registers = work.register_maintenance().unwrap();
    assert_eq!(registers.attempts(), 1);
    assert_eq!(
        registers.periods()[0]
            .last_success
            .as_ref()
            .unwrap()
            .through,
        committed.0
    );
    assert!(
        server
            .book
            .verify_registers("FY2026-P03")
            .unwrap()
            .is_green()
    );
    let maintained = server.book.head().unwrap();
    let (retry, _) = runtime.block_on(server.handle(&cx, create));
    assert_eq!(retry.exit, 0, "{}{}", retry.stdout, retry.stderr);
    assert_eq!(server.book.head().unwrap(), maintained);
    assert_eq!(
        server.deadline(),
        scheduled,
        "an idempotent retry never wakes itself"
    );

    // Exercise the actual framing/timer arbitration too. No test calls
    // tick here, and the regular timer is an hour away. A request which
    // commits must wake maintenance before the following status/Stop.
    let mut status = run(&["--json"]);
    status.op = Op::Status;
    let mut stop = run(&["--json"]);
    stop.op = Op::Stop;
    stop.stdin = Some(server.book.owner_token().to_vec());
    let requests = [
        run(&["period", "create", "--fiscal-year", "2027", "--json"]),
        status,
        stop,
    ];
    let bytes: Vec<u8> = requests.iter().flat_map(frame).collect();
    let (mut stream, mut client) = VirtualTcpStream::pair(addr(163), addr(164));
    let received = runtime.block_on(async {
        client.write_all(&bytes).await.unwrap();
        assert_eq!(
            serve_connection_with(&cx, &mut stream, LIMITS, Path::new(BOOK), &mut server).await,
            Ended::Stop
        );
        drop(stream);
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        received
    });
    let mut decoder = Decoder::new(MAX);
    decoder.push(&received);
    let mut frames = Vec::new();
    while let Some(frame) = decoder.next_frame().unwrap() {
        frames.push(frame);
    }
    schema_checked(&frames);
    let replies = responses(&frames);
    assert_eq!(
        replies.len(),
        3,
        "every request receives its whole response"
    );
    for reply in &replies {
        assert_eq!(reply.exit, 0, "{}{}", reply.stdout, reply.stderr);
    }
    let status = fa_cli::wire::canonical(replies[1].stdout.trim().as_bytes()).unwrap();
    let maintenance = status
        .get("data")
        .unwrap()
        .get("register_maintenance")
        .unwrap();
    assert_eq!(maintenance.get("attempts"), Some(&Json::Int(2)));
    let work = server.timed.as_ref().unwrap();
    assert_eq!(work.register_maintenance().unwrap().attempts(), 2);
    assert_eq!(work.deadline(), scheduled);
    assert!(!work.timing_enabled());
    assert!(server.book.latest_tick().unwrap().is_none());
}

/// Feed `bytes` to a fresh connection, serve it with an echo handler, and
/// collect everything the client receives.
async fn exchange(cx: Cx, bytes: Vec<u8>) -> Run {
    exchange_answering(cx, bytes, |r| r.argv.join(" ")).await
}

/// As [`exchange`], with a handler whose stdout is `answer(request)`.
async fn exchange_answering(cx: Cx, bytes: Vec<u8>, answer: fn(&Request) -> String) -> Run {
    let (mut server, mut client) = VirtualTcpStream::pair(addr(1), addr(2));
    let _ = client.write_all(&bytes).await;
    let _ = AsyncWriteExt::shutdown(&mut client).await;
    let mut seen: Vec<Vec<String>> = Vec::new();
    let mut handle = |r: Request| {
        seen.push(r.argv.clone());
        let next = if r.op == Op::Stop {
            Next::Stop
        } else {
            Next::Continue
        };
        (
            Response {
                op: r.op,
                exit: 0,
                stdout: answer(&r),
                stderr: String::new(),
            },
            next,
        )
    };
    let dir = std::path::Path::new(BOOK);
    let ended = serve_connection(&cx, &mut server, LIMITS, dir, &mut handle).await;
    drop(server);
    let mut received = Vec::new();
    let _ = client.read_to_end(&mut received).await;
    let mut decoder = Decoder::new(MAX);
    decoder.push(&received);
    let mut frames = Vec::new();
    while let Ok(Some(f)) = decoder.next_frame() {
        frames.push(f);
    }
    (seen, ended, frames)
}

fn responses(frames: &[Vec<u8>]) -> Vec<Response> {
    frames
        .iter()
        .map(|f| {
            let v = fa_cli::wire::canonical(f);
            assert!(v.is_ok(), "the daemon only writes canonical frames");
            let r = v.and_then(|v| Response::from_json(&v, 1));
            assert!(r.is_ok(), "{r:?}");
            r.unwrap_or(Response {
                op: Op::Run,
                exit: 255,
                stdout: String::new(),
                stderr: String::new(),
            })
        })
        .collect()
}

/// Every frame either side writes is a declared robot-schema event.
fn schema_checked(frames: &[Vec<u8>]) {
    let reg = fa_cli::verbs::registry().expect("verbs.toml");
    for f in frames {
        let text = String::from_utf8_lossy(f);
        assert_eq!(reg.check_line(&text), Ok("fad_response"), "{text}");
    }
}

#[test]
fn requests_are_answered_one_for_one_in_order() {
    for seed in 0..8 {
        let sent: Vec<Request> = (0..3).map(|n| request(Op::Run, n)).collect();
        let reg = fa_cli::verbs::registry().expect("verbs.toml");
        for r in &sent {
            assert_eq!(reg.check_line(&r.to_json(1).render()), Ok("fad_request"));
        }
        let bytes: Vec<u8> = sent.iter().flat_map(frame).collect();
        let ((seen, ended, frames), _) = run_async_under_lab(seed, move |cx| exchange(cx, bytes));
        assert_eq!(ended, Ended::Closed, "seed {seed}");
        assert_eq!(
            seen,
            sent.iter().map(|r| r.argv.clone()).collect::<Vec<_>>()
        );
        schema_checked(&frames);
        let got: Vec<String> = responses(&frames).into_iter().map(|r| r.stdout).collect();
        assert_eq!(
            got,
            sent.iter().map(|r| r.argv.join(" ")).collect::<Vec<_>>(),
            "seed {seed}"
        );
    }
}

#[test]
fn a_stop_is_answered_and_nothing_after_it_is_read() {
    let bytes: Vec<u8> = [
        request(Op::Run, 0),
        request(Op::Stop, 1),
        request(Op::Run, 2),
    ]
    .iter()
    .flat_map(frame)
    .collect();
    let ((seen, ended, frames), _) = run_async_under_lab(7, move |cx| exchange(cx, bytes));
    assert_eq!(ended, Ended::Stop);
    assert_eq!(seen.len(), 2, "the request after stop is never handled");
    assert_eq!(responses(&frames).len(), 2);
}

#[test]
fn a_frame_cut_short_ends_the_connection_without_reaching_the_handler() {
    let whole = frame(&request(Op::Run, 0));
    let second = frame(&request(Op::Run, 1));
    let half = second.len() / 2;
    assert!(half > 4, "the cut falls inside the payload");
    let mut bytes = whole;
    bytes.extend_from_slice(&second[..half]);
    let ((seen, ended, frames), _) = run_async_under_lab(3, move |cx| exchange(cx, bytes));
    assert_eq!(seen.len(), 1);
    assert_eq!(responses(&frames).len(), 1);
    assert_eq!(
        ended,
        Ended::Fault(FrameError::Truncated {
            got: half,
            expected: second.len()
        })
    );
}

#[test]
fn oversized_and_non_canonical_frames_get_a_structured_refusal_and_close() {
    let mut oversized = u32::try_from(MAX + 1)
        .unwrap_or(u32::MAX)
        .to_be_bytes()
        .to_vec();
    oversized.extend_from_slice(b"never read");
    let spaced = br#"{ "event":"fad_request","v":1}"#;
    let mut non_canonical = u32::try_from(spaced.len())
        .unwrap_or(0)
        .to_be_bytes()
        .to_vec();
    non_canonical.extend_from_slice(spaced);
    let mut wrong_protocol = Vec::new();
    let v2 = request(Op::Run, 0).to_json(2).render();
    wrong_protocol.extend(encode(v2.as_bytes(), MAX).unwrap_or_default());
    for (what, bytes) in [
        ("oversized", oversized),
        ("non-canonical", non_canonical),
        ("wrong protocol", wrong_protocol),
    ] {
        let ((seen, ended, frames), _) = run_async_under_lab(11, move |cx| exchange(cx, bytes));
        assert!(
            seen.is_empty(),
            "{what}: the handler never sees a bad frame"
        );
        assert!(matches!(ended, Ended::Fault(_)), "{what}: {ended:?}");
        schema_checked(&frames);
        let replies = responses(&frames);
        assert_eq!(replies.len(), 1, "{what}");
        assert_eq!(replies[0].exit, 2, "{what}");
        let reg = fa_cli::verbs::registry().expect("verbs.toml");
        let line = replies[0].stdout.trim_end();
        assert_eq!(reg.check_line(line), Ok("error"), "{what}: {line}");
        assert!(line.contains(r#""class":"usage""#), "{what}: {line}");
        assert!(line.contains("fad refused the frame"), "{what}: {line}");
    }
}

/// An answer too large for one frame is refused whole, never cut, and the
/// refusal's advice works while this daemon holds the writer lease: narrow
/// the command, or stop the daemon first (a direct run would be FA-REF-018).
#[test]
fn an_oversized_answer_is_refused_whole_with_advice_that_works() {
    let bytes = frame(&request(Op::Run, 0));
    let ((seen, ended, frames), _) = run_async_under_lab(13, move |cx| {
        exchange_answering(cx, bytes, |_| "x".repeat(MAX))
    });
    assert_eq!(seen.len(), 1, "the handler ran the request");
    assert_eq!(ended, Ended::Closed, "the connection stays usable");
    schema_checked(&frames);
    let replies = responses(&frames);
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].exit, 5);
    let line = replies[0].stdout.trim_end();
    assert!(!line.contains("xxxx"), "never a cut answer: {line}");
    let reg = fa_cli::verbs::registry().expect("verbs.toml");
    assert_eq!(reg.check_line(line), Ok("error"), "{line}");
    assert!(line.contains(r#""class":"foundation""#), "{line}");
    let advice = format!(
        "narrow the command, or stop the daemon with `fad stop --book {BOOK}` and run it directly"
    );
    assert!(line.contains(&advice), "{line}");
    assert!(
        !line.contains("narrow the command or run it directly"),
        "the unfollowable advice is gone: {line}"
    );
}

/// With the lab's light chaos (injected cancellation, delays, wake storms):
/// whatever happens, the handler only ever sees whole frames, in order, each
/// answered at most once, and the loop always returns.
#[test]
fn under_chaos_only_whole_frames_reach_the_handler() {
    for seed in 0..16 {
        let sent: Vec<Request> = (0..4).map(|n| request(Op::Run, n)).collect();
        let bytes: Vec<u8> = sent.iter().flat_map(frame).collect();
        let config = LabConfig::new(seed).with_light_chaos();
        let ((seen, ended, frames), _) =
            run_async_under_lab_with_config(config, move |cx| exchange(cx, bytes));
        let expected: Vec<Vec<String>> = sent.iter().map(|r| r.argv.clone()).collect();
        assert!(expected.starts_with(&seen), "seed {seed}: handled {seen:?}");
        let replies = responses(&frames);
        assert!(replies.len() <= seen.len(), "seed {seed}");
        if ended == Ended::Closed {
            assert_eq!(
                seen, expected,
                "seed {seed}: a clean close handled everything"
            );
        }
    }
}

#[test]
fn slow_client_sending_a_frame_every_29s_does_not_starve_other_clients_and_unauthorized_stop_is_refused()
 {
    use asupersync::Budget;
    use asupersync::lab::{AutoAdvanceTermination, LabRuntime};
    use asupersync::net::tcp::VirtualTcpListener;
    use std::sync::Arc;

    const DAEMON_UID: u32 = 1000;
    const FOREIGN_UID: u32 = 2000;
    const OWNER_TOKEN: [u8; 32] = [0xAB; 32];
    const SEC: u64 = 1_000_000_000;

    async fn sleep_ns(cx: &Cx, nanos: u64) {
        let at = clock::deadline_after(clock::timer(cx).unwrap().now(), nanos).unwrap();
        clock::Deadline::new(cx, at).unwrap().await.unwrap();
    }

    let mut lab = LabRuntime::new(LabConfig::new(42).with_auto_advance());
    let root = lab.state.create_root_region(Budget::INFINITE);
    let listener = Arc::new(VirtualTcpListener::new(addr(9000)));
    let listener_for_client = Arc::clone(&listener);

    let (server_task, mut server_handle) = lab
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().expect("lab server cx");
            let limits = Limits {
                protocol: 1,
                max_frame_bytes: MAX,
                idle: Some(Duration::from_secs(30)),
            };
            let mut seen: Vec<Vec<String>> = Vec::new();
            let mut handle = |r: Request| {
                seen.push(r.argv.clone());
                let next = if r.op == Op::Stop {
                    Next::Stop
                } else {
                    Next::Continue
                };
                (
                    Response {
                        op: r.op,
                        exit: 0,
                        stdout: r.argv.join(" "),
                        stderr: String::new(),
                    },
                    next,
                )
            };
            let timings = serve_listener(
                &cx,
                &*listener,
                limits,
                Path::new(BOOK),
                Some(DAEMON_UID),
                Some(OWNER_TOKEN),
                &mut handle,
            )
            .await
            .expect("serve_listener");
            (seen, timings)
        })
        .unwrap();

    let (client_task, mut client_handle) = lab
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().expect("lab client cx");
            let now_ns = || clock::timer(&cx).unwrap().now().as_nanos();

            // Client A connects at t = 0 s and sends only half of its first frame,
            // then dribbles/sends one frame every 29 s (under the 30 s idle timeout).
            let (server_a, mut client_a) = VirtualTcpStream::pair(addr(9000), addr(DAEMON_UID as u16));
            listener_for_client.inject_connection(server_a, addr(DAEMON_UID as u16));
            let frame_a1 = frame(&request(Op::Run, 10));
            let half = frame_a1.len() / 2;
            client_a.write_all(&frame_a1[..half]).await.unwrap();

            // At t = 1 s, Client B connects and sends a full request while Client A is mid-frame.
            sleep_ns(&cx, SEC).await;
            let b_start = now_ns();
            let (server_b, mut client_b) = VirtualTcpStream::pair(addr(9000), addr(DAEMON_UID as u16));
            listener_for_client.inject_connection(server_b, addr(DAEMON_UID as u16));
            client_b.write_all(&frame(&request(Op::Run, 20))).await.unwrap();
            let _ = AsyncWriteExt::shutdown(&mut client_b).await;
            let reply_b = read_frame(&cx, &mut client_b, MAX)
                .await
                .unwrap()
                .expect("client B reply");
            let resp_b = Response::from_json(&canonical(&reply_b).unwrap(), 1).unwrap();
            assert_eq!(resp_b.exit, 0);
            assert_eq!(resp_b.stdout, "tb --n=20 --json");
            let b_elapsed = now_ns() - b_start;
            assert!(
                b_elapsed < 5 * SEC,
                "Client B must complete within its 5 s deadline, not wait 29 s for Client A (elapsed={b_elapsed} ns)"
            );

            // At t = 2 s, a foreign-UID peer (uid 2000 != 1000) connects and sends unparseable
            // bytes; it must be refused with FA-REF-011 before any frame reading or parsing (fa-udti).
            sleep_ns(&cx, SEC).await;
            let (server_foreign, mut client_foreign) =
                VirtualTcpStream::pair(addr(9000), addr(FOREIGN_UID as u16));
            listener_for_client.inject_connection(server_foreign, addr(FOREIGN_UID as u16));
            client_foreign
                .write_all(b"\x00\x00\x00\x07NOTJSON")
                .await
                .unwrap();
            let reply_foreign = read_frame(&cx, &mut client_foreign, MAX)
                .await
                .unwrap()
                .expect("foreign peer refusal");
            let resp_foreign =
                Response::from_json(&canonical(&reply_foreign).unwrap(), 1).unwrap();
            assert_eq!(resp_foreign.exit, 7, "{resp_foreign:?}");
            assert!(
                resp_foreign.stdout.contains("\"refusal_id\":\"FA-REF-011\""),
                "{}",
                resp_foreign.stdout
            );
            assert!(
                resp_foreign.stdout.contains("peer uid 2000"),
                "{}",
                resp_foreign.stdout
            );

            // At t = 3 s, a same-UID peer without the owner token attempts Op::Stop.
            sleep_ns(&cx, SEC).await;
            let (server_unauth, mut client_unauth) =
                VirtualTcpStream::pair(addr(9000), addr(DAEMON_UID as u16));
            listener_for_client.inject_connection(server_unauth, addr(DAEMON_UID as u16));
            client_unauth
                .write_all(&frame(&request(Op::Stop, 98)))
                .await
                .unwrap();
            let _ = AsyncWriteExt::shutdown(&mut client_unauth).await;
            let reply_unauth = read_frame(&cx, &mut client_unauth, MAX)
                .await
                .unwrap()
                .expect("unauthorized stop refusal");
            let resp_unauth =
                Response::from_json(&canonical(&reply_unauth).unwrap(), 1).unwrap();
            assert_eq!(resp_unauth.exit, 7, "{resp_unauth:?}");
            assert!(
                resp_unauth.stdout.contains("\"refusal_id\":\"FA-REF-011\""),
                "{}",
                resp_unauth.stdout
            );
            assert!(
                resp_unauth
                    .stdout
                    .contains("stopping the daemon requires owner authority"),
                "{}",
                resp_unauth.stdout
            );

            // At t = 29 s (26 s later), Client A finishes its first frame and gets its answer.
            sleep_ns(&cx, 26 * SEC).await;
            assert_eq!(now_ns(), 29 * SEC);
            client_a.write_all(&frame_a1[half..]).await.unwrap();
            let reply_a1 = read_frame(&cx, &mut client_a, MAX)
                .await
                .unwrap()
                .expect("client A first reply");
            let resp_a1 = Response::from_json(&canonical(&reply_a1).unwrap(), 1).unwrap();
            assert_eq!(resp_a1.stdout, "tb --n=10 --json");

            // Client A stays open for another 29 s (until t = 58 s). Meanwhile at t = 40 s,
            // Client C connects and is served immediately while Client A sits idle.
            sleep_ns(&cx, 11 * SEC).await;
            let c_start = now_ns();
            let (server_c, mut client_c) = VirtualTcpStream::pair(addr(9000), addr(DAEMON_UID as u16));
            listener_for_client.inject_connection(server_c, addr(DAEMON_UID as u16));
            client_c.write_all(&frame(&request(Op::Run, 30))).await.unwrap();
            let _ = AsyncWriteExt::shutdown(&mut client_c).await;
            let reply_c = read_frame(&cx, &mut client_c, MAX)
                .await
                .unwrap()
                .expect("client C reply");
            let resp_c = Response::from_json(&canonical(&reply_c).unwrap(), 1).unwrap();
            assert_eq!(resp_c.stdout, "tb --n=30 --json");
            assert_eq!(now_ns() - c_start, 0);

            // At t = 58 s (18 s later, 29 s after Client A's first frame), Client A sends a second frame.
            sleep_ns(&cx, 18 * SEC).await;
            assert_eq!(now_ns(), 58 * SEC);
            client_a.write_all(&frame(&request(Op::Run, 11))).await.unwrap();
            let _ = AsyncWriteExt::shutdown(&mut client_a).await;
            let reply_a2 = read_frame(&cx, &mut client_a, MAX)
                .await
                .unwrap()
                .expect("client A second reply");
            let resp_a2 = Response::from_json(&canonical(&reply_a2).unwrap(), 1).unwrap();
            assert_eq!(resp_a2.stdout, "tb --n=11 --json");

            // At t = 59 s, an authorized owner sends Op::Stop with the owner token.
            sleep_ns(&cx, SEC).await;
            let (server_stop, mut client_stop) =
                VirtualTcpStream::pair(addr(9000), addr(DAEMON_UID as u16));
            listener_for_client.inject_connection(server_stop, addr(DAEMON_UID as u16));
            let auth_stop = Request {
                op: Op::Stop,
                argv: vec!["--json".into()],
                cwd: None,
                stdin: Some(OWNER_TOKEN.to_vec()),
                token: None,
            };
            client_stop.write_all(&frame(&auth_stop)).await.unwrap();
            let reply_stop = read_frame(&cx, &mut client_stop, MAX)
                .await
                .unwrap()
                .expect("authorized stop reply");
            let resp_stop = Response::from_json(&canonical(&reply_stop).unwrap(), 1).unwrap();
            assert_eq!(resp_stop.exit, 0);
        })
        .unwrap();

    {
        let mut sched = lab.scheduler.lock();
        sched.schedule(server_task, Budget::INFINITE.priority);
        sched.schedule(client_task, Budget::INFINITE.priority);
    }
    let advanced = lab.run_with_auto_advance();
    assert!(
        matches!(advanced.termination, AutoAdvanceTermination::Quiescent),
        "{advanced:?}"
    );
    assert!(lab.report().lab_test_passed(), "{:?}", lab.report());
    client_handle.try_join().unwrap().expect("client task");
    let (seen, timings) = server_handle.try_join().unwrap().expect("server task");
    assert_eq!(
        seen.len(),
        5,
        "B, A1, C, A2, and authorized Stop reached handler: {seen:?}"
    );
    assert_eq!(
        timings.len(),
        6,
        "6 connections recorded in timings: {timings:?}"
    );
    assert!(
        timings.iter().any(|t| matches!(
            t.ended,
            Ended::UnauthorizedPeer {
                peer_uid: FOREIGN_UID,
                daemon_uid: DAEMON_UID
            }
        )),
        "foreign peer refusal recorded in timings: {timings:?}"
    );
    assert!(
        timings
            .iter()
            .any(|t| t.conn_id == 1 && t.requests == 2 && t.elapsed_ns == 58 * SEC),
        "slow client A timing recorded: {timings:?}"
    );
}

#[test]
fn connection_session_token_is_bound_for_lifetime_and_refuses_mid_connection_switch_under_chaos() {
    fn req_with_token(n: usize, token: Option<&[u8]>) -> Request {
        Request {
            op: Op::Run,
            argv: vec!["tb".into(), format!("--n={n}"), "--json".into()],
            cwd: None,
            stdin: None,
            token: token.map(<[u8]>::to_vec),
        }
    }

    for seed in 0..8 {
        // 1. Token-bound connection: frame 0 binds token-a, frame 1 omits token (inherits token-a),
        //    frame 2 tries to switch to token-b (refused FA-REF-011), frame 3 omits token (still token-a).
        let sent_bound = [
            req_with_token(0, Some(b"token-a")),
            req_with_token(1, None),
            req_with_token(2, Some(b"token-b")),
            req_with_token(3, None),
        ];
        let bytes_bound: Vec<u8> = sent_bound.iter().flat_map(frame).collect();
        let config = LabConfig::new(seed).with_light_chaos();
        let ((seen_tokens, ended, frames), _) =
            run_async_under_lab_with_config(config, move |cx| async move {
                let (mut server, mut client) = VirtualTcpStream::pair(addr(1), addr(2));
                let _ = client.write_all(&bytes_bound).await;
                let _ = AsyncWriteExt::shutdown(&mut client).await;
                let mut seen: Vec<(Vec<String>, Option<Vec<u8>>)> = Vec::new();
                let mut handle = |r: Request| {
                    seen.push((r.argv.clone(), r.token.clone()));
                    (
                        Response {
                            op: r.op,
                            exit: 0,
                            stdout: r.argv.join(" "),
                            stderr: String::new(),
                        },
                        Next::Continue,
                    )
                };
                let dir = std::path::Path::new(BOOK);
                let ended = serve_connection(&cx, &mut server, LIMITS, dir, &mut handle).await;
                drop(server);
                let mut received = Vec::new();
                let _ = client.read_to_end(&mut received).await;
                let mut decoder = Decoder::new(MAX);
                decoder.push(&received);
                let mut frames = Vec::new();
                while let Ok(Some(f)) = decoder.next_frame() {
                    frames.push(f);
                }
                (seen, ended, frames)
            });

        schema_checked(&frames);
        if ended == Ended::Closed {
            assert_eq!(
                seen_tokens.len(),
                3,
                "seed {seed}: frame 2 (token switch) must not reach handler"
            );
            for (argv, tok) in &seen_tokens {
                assert_eq!(
                    tok.as_deref(),
                    Some(&b"token-a"[..]),
                    "seed {seed}: {argv:?} must carry bound token-a"
                );
            }
            let replies = responses(&frames);
            assert_eq!(replies.len(), 4, "seed {seed}");
            assert_eq!(replies[0].exit, 0);
            assert_eq!(replies[1].exit, 0);
            assert_eq!(replies[2].exit, 7, "seed {seed}: {}", replies[2].stdout);
            assert!(
                replies[2].stdout.contains("FA-REF-011")
                    && replies[2]
                        .stdout
                        .contains("already bound to a different capability token"),
                "seed {seed}: {}",
                replies[2].stdout
            );
            assert_eq!(replies[3].exit, 0);
        }

        // 2. Unbound connection: frame 0 has no token, frame 1 tries to bind token-a mid-connection (refused FA-REF-011).
        let sent_unbound = [
            req_with_token(10, None),
            req_with_token(11, Some(b"token-a")),
        ];
        let bytes_unbound: Vec<u8> = sent_unbound.iter().flat_map(frame).collect();
        let ((seen, ended_u, frames_u), _) =
            run_async_under_lab(seed, move |cx| exchange(cx, bytes_unbound));
        assert_eq!(ended_u, Ended::Closed, "seed {seed}");
        assert_eq!(
            seen.len(),
            1,
            "seed {seed}: mid-connection bind refused before handler"
        );
        schema_checked(&frames_u);
        let replies_u = responses(&frames_u);
        assert_eq!(replies_u.len(), 2, "seed {seed}");
        assert_eq!(replies_u[0].exit, 0);
        assert_eq!(replies_u[1].exit, 7, "seed {seed}: {}", replies_u[1].stdout);
        assert!(
            replies_u[1].stdout.contains("FA-REF-011")
                && replies_u[1]
                    .stdout
                    .contains("cannot bind a capability token mid-connection"),
            "seed {seed}: {}",
            replies_u[1].stdout
        );
    }
}
