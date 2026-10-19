//! Real AsyncBook effects and the real framing loop on the lab runtime.
//! These are bounded scenarios, not the full fa-ffo crash/DPOR campaign.

use super::*;
use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use asupersync::Budget;
use asupersync::cx::cap::CapMask;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::lab::{AutoAdvanceTermination, LabConfig, LabRuntime};
use asupersync::net::tcp::VirtualTcpStream;
use asupersync::types::CancelKind;
use fa::{BookKeys, Entropy};
use fa_cli::wire::{Op as WireOp, Request, Response, encode};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, TimeZonePolicy, UnitPolicy};
use fa_model::{EntryClass, EntryOrigin, EntryPayload, LegPayload, Oid, Pending, account_vid};
use fa_money::{Amount, Side, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;
use fgdb_types::VId;

const POLICY: Policy = Policy {
    tick_ns: 10,
    sweep_batch: 1,
    clock_drift_ns: 0,
};

fn lab<T, F>(
    seed: u64,
    test: impl FnOnce(Cx) -> F + Send + 'static,
) -> Result<Option<T>, asupersync::runtime::JoinError>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let mut lab = LabRuntime::new(LabConfig::new(seed).with_auto_advance());
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task, mut handle) = lab
        .state
        .create_task(root, Budget::INFINITE, async move {
            test(Cx::current().expect("lab task context")).await
        })
        .unwrap();
    lab.scheduler
        .lock()
        .schedule(task, Budget::INFINITE.priority);
    let advanced = lab.run_with_auto_advance();
    assert!(
        matches!(advanced.termination, AutoAdvanceTermination::Quiescent),
        "{advanced:?}"
    );
    assert!(lab.report().lab_test_passed(), "{:?}", lab.report());
    handle.try_join()
}

struct Fixture {
    book: AsyncBook<MemVfs>,
    request: PostRequest,
}

async fn fixture(root: &Cx, seed: u8) -> Fixture {
    let cx = PurposeContexts::narrow_runtime_root(root);
    let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
    let book_id = Id128([seed; 16]);
    let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
    let spec = BookSpec {
        book_id,
        name: "Daemon timed-work lab book".into(),
        base_unit: usd,
        calendar: FiscalCalendar::monthly("timed-calendar", 1, 1).unwrap(),
        time_zone_policy: Some(TimeZonePolicy::Utc),
        entities: Vec::new(),
        opening_date: None,
    };
    let mut book = AsyncBook::create_with_vfs(
        &cx,
        vfs,
        Path::new("timed-book"),
        BookKeys::for_development(seed),
        spec,
        Entropy::deterministic(u64::from(seed)),
    )
    .await
    .unwrap();
    let principal = VId(1);
    let day = DateDay::from_ymd(2026, 3, 15).unwrap();
    let chart = [("1000", "Cash", 1), ("6000", "Rent", 5)].map(|(code, name, kind)| AccountSpec {
        code: code.into(),
        name: name.into(),
        account_type: kind,
        normal_balance: 0,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(usd),
        parent_code: None,
        limit: None,
    });
    book.install_chart(
        &cx,
        &chart,
        principal,
        day,
        b"chart",
        &Capability::embedded(principal, &["schema_change"]).unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    book.create_periods(
        &cx,
        2026,
        principal,
        &Capability::embedded(principal, &["schema_change"]).unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let controller = Capability::embedded(principal, &["close"]).unwrap();
    for period in ["FY2026-P03", "FY2026-P04"] {
        book.transition_period(
            &cx,
            period,
            PeriodTransition::Open,
            principal,
            1,
            day,
            period.as_bytes(),
            &controller,
        )
        .await
        .unwrap()
        .unwrap();
    }
    let document = Document {
        book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: principal,
        bytes: b"Invoice supporting timed lab postings".to_vec(),
    };
    book.add_document(&cx, &document).await.unwrap().unwrap();
    let legs = vec![
        LegPayload::simple(
            Side::Debit,
            account_vid(book_id, "6000"),
            Amount::new(usd, 1_000),
        ),
        LegPayload::simple(
            Side::Credit,
            account_vid(book_id, "1000"),
            Amount::new(usd, 1_000),
        ),
    ];
    let proposal = EntryPayload {
        schema_minor: 0,
        book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: day,
        document_date: None,
        description: book.seal_text(&cx, "timed work fixture").unwrap(),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: b"fixture".to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([1; 32]),
            intent_kind: 1,
        },
        principal_ref: principal,
        session_ref: None,
        evidence: vec![document.evidence_ref(1)],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    Fixture {
        book,
        request: PostRequest {
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(principal, &["post"]).unwrap(),
        },
    }
}

fn observation(cx: &Cx, utc_ns: u64) -> Observation {
    let at = clock::timer(cx).unwrap().now().as_nanos();
    Observation {
        utc_ns,
        before_ns: at,
        after_ns: at,
    }
}

async fn advance(cx: &Cx, nanos: u64) {
    let deadline = clock::deadline_after(clock::timer(cx).unwrap().now(), nanos).unwrap();
    clock::Deadline::new(cx, deadline).unwrap().await.unwrap();
}

async fn hold(fixture: &mut Fixture, cx: &PurposeContexts, key: &[u8], timeout: u64) {
    let mut request = fixture.request.clone();
    request.proposal.class = EntryClass::PENDING;
    request.proposal.idempotency_key = key.to_vec();
    request.proposal.pending = Some(Pending {
        timeout_ns: Some(timeout),
        resolution_of: None,
        disposition: None,
    });
    fixture.book.post(cx, request).await.unwrap().unwrap();
}

#[test]
fn daemon_cycle_records_real_ticks_and_bounds_both_kinds_of_effects() {
    lab(71, |root| async move {
        let mut fixture = fixture(&root, 71).await;
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let mut work =
            TimedWork::bootstrap_for_book(&root, fixture.book.context().book_id, POLICY).unwrap();
        let april = DateDay::from_ymd(2026, 4, 1).unwrap();
        let midnight = u64::try_from(april.0).unwrap() * 86_400_000_000_000;
        let start = midnight - 100;
        let first = work
            .run_observation(&root, &mut fixture.book, Ok(observation(&root, start)))
            .await
            .unwrap();
        assert!(!first.corroborated);
        for key in [b"hold-a", b"hold-b", b"hold-c"] {
            hold(&mut fixture, &cx, key, 5).await;
        }
        for key in [b"reverse-a", b"reverse-b"] {
            let mut request = fixture.request.clone();
            request.proposal.class = EntryClass::ADJUSTING;
            request.proposal.idempotency_key = key.to_vec();
            request.proposal = fa_journal::with_auto_reverse(request.proposal, april);
            fixture.book.post(&cx, request).await.unwrap().unwrap();
        }
        advance(&root, 100).await;
        let first_due = work
            .run_observation(&root, &mut fixture.book, Ok(observation(&root, midnight)))
            .await
            .unwrap();
        assert_eq!(
            (
                first_due.corroborated,
                first_due.expired,
                first_due.reversed
            ),
            (true, 1, 1)
        );
        assert_eq!(fixture.book.due_holds(&cx).unwrap().len(), 2);
        assert_eq!(fixture.book.due_reversals(&cx).unwrap().len(), 1);
        assert_eq!(
            work.deadline().unwrap().as_nanos(),
            clock::timer(&root).unwrap().now().as_nanos() + 10
        );
        advance(&root, 10).await;
        let second = work
            .run_observation(
                &root,
                &mut fixture.book,
                Ok(observation(&root, midnight + 10)),
            )
            .await
            .unwrap();
        assert_eq!((second.expired, second.reversed), (1, 1));
        assert_eq!(fixture.book.due_holds(&cx).unwrap().len(), 1);
        assert!(fixture.book.due_reversals(&cx).unwrap().is_empty());
        advance(&root, 10).await;
        assert_eq!(
            work.run_observation(
                &root,
                &mut fixture.book,
                Ok(observation(&root, midnight + 20))
            )
            .await
            .unwrap()
            .expired,
            1
        );
        assert!(fixture.book.due_holds(&cx).unwrap().is_empty());
        assert!(
            fixture
                .book
                .verify_projections(&cx, None)
                .unwrap()
                .is_green()
        );
    })
    .unwrap()
    .expect("lab completed");
}

#[test]
fn forward_jump_rollback_and_old_true_tick_retry_do_not_sweep() {
    lab(73, |root| async move {
        let mut fixture = fixture(&root, 73).await;
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let mut work =
            TimedWork::bootstrap_for_book(&root, fixture.book.context().book_id, POLICY).unwrap();
        work.run_observation(&root, &mut fixture.book, Ok(observation(&root, 1_000)))
            .await
            .unwrap();
        hold(&mut fixture, &cx, b"still-pending", 100).await;
        advance(&root, 10).await;
        assert!(
            work.run_observation(&root, &mut fixture.book, Ok(observation(&root, 1_010)))
                .await
                .unwrap()
                .corroborated
        );
        let old_tick = fixture.book.latest_tick(&cx).unwrap().unwrap();
        advance(&root, 10).await;
        let jump = work
            .run_observation(&root, &mut fixture.book, Ok(observation(&root, 2_000)))
            .await
            .unwrap();
        assert!(!jump.corroborated);
        assert_eq!(jump.expired, 0);
        assert_eq!(fixture.book.due_holds(&cx).unwrap().len(), 1);
        let newest = fixture.book.latest_tick(&cx).unwrap().unwrap();
        assert_ne!(newest, old_tick);
        let unchanged = fixture.book.head(&cx).unwrap();
        // Establish a second process baseline whose elapsed reading could
        // repeat the old true tick. The adapter's idempotent return must
        // not become permission to sweep under the newer false tick.
        let mut retry =
            TimedWork::bootstrap_for_book(&root, fixture.book.context().book_id, POLICY).unwrap();
        assert!(matches!(
            retry
                .run_observation(&root, &mut fixture.book, Ok(observation(&root, 1_000)))
                .await,
            Err(TimedError::StaleTick)
        ));
        advance(&root, 10).await;
        let error = retry
            .run_observation(&root, &mut fixture.book, Ok(observation(&root, 1_010)))
            .await
            .unwrap_err();
        assert!(matches!(error, TimedError::StaleTick), "{error:?}");
        assert_eq!(fixture.book.head(&cx).unwrap(), unchanged);
        assert_eq!(fixture.book.latest_tick(&cx).unwrap(), Some(newest));
        advance(&root, 10).await;
        assert!(
            work.run_observation(&root, &mut fixture.book, Ok(observation(&root, 900)))
                .await
                .is_err()
        );
        assert_eq!(fixture.book.head(&cx).unwrap(), unchanged);
        assert_eq!(fixture.book.due_holds(&cx).unwrap().len(), 1);
        assert!(work.error.as_deref().unwrap().contains("FA-REF-094"));
    })
    .unwrap()
    .expect("lab completed");
}

#[test]
fn far_future_wall_jump_does_not_brick_subsequent_honest_ticks_or_sweeps() {
    lab(77, |root| async move {
        let mut fixture = fixture(&root, 77).await;
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let mut work =
            TimedWork::bootstrap_for_book(&root, fixture.book.context().book_id, POLICY).unwrap();
        let april = DateDay::from_ymd(2026, 4, 1).unwrap();
        let midnight = u64::try_from(april.0).unwrap() * 86_400_000_000_000;
        let start = midnight - 100;
        let first = work
            .run_observation(&root, &mut fixture.book, Ok(observation(&root, start)))
            .await
            .unwrap();
        assert!(!first.corroborated);

        advance(&root, 10).await;
        let baseline = work
            .run_observation(&root, &mut fixture.book, Ok(observation(&root, start + 10)))
            .await
            .unwrap();
        assert!(baseline.corroborated);

        hold(&mut fixture, &cx, b"hold-survives-jump", 50).await;
        let mut rev = fixture.request.clone();
        rev.proposal.class = EntryClass::ADJUSTING;
        rev.proposal.idempotency_key = b"rev-survives-jump".to_vec();
        rev.proposal = fa_journal::with_auto_reverse(rev.proposal, april);
        fixture.book.post(&cx, rev).await.unwrap().unwrap();

        // u64::MAX is out of representable InstantUtc range and refused with FA-REF-100.
        advance(&root, 10).await;
        let overflow = work
            .run_observation(&root, &mut fixture.book, Ok(observation(&root, u64::MAX)))
            .await
            .unwrap_err();
        assert!(matches!(overflow, TimedError::Refused(ref r) if r.code == "FA-REF-100"));

        // A representable far-future jump (~year 2262) is journaled as uncorroborated
        // without firing expiry or scheduled-reversal sweeps.
        let far_future = fa_model::limits::MAX_TICK_UTC_NS;
        let jumped = work
            .run_observation(&root, &mut fixture.book, Ok(observation(&root, far_future)))
            .await
            .unwrap();
        assert!(!jumped.corroborated);
        assert_eq!((jumped.expired, jumped.reversed), (0, 0));

        // When the wall clock returns to its honest trajectory at midnight (start + 100),
        // the daemon records a corroborated tick and sweeps the due hold and reversal.
        advance(&root, 80).await;
        let recovered = work
            .run_observation(&root, &mut fixture.book, Ok(observation(&root, midnight)))
            .await
            .unwrap();
        assert_eq!(
            (
                recovered.corroborated,
                recovered.expired,
                recovered.reversed
            ),
            (true, 1, 1)
        );
        assert!(fixture.book.due_holds(&cx).unwrap().is_empty());
        assert!(fixture.book.due_reversals(&cx).unwrap().is_empty());
    })
    .unwrap()
    .expect("lab completed");
}

#[test]
fn missing_clock_and_human_system_substitution_are_refused() {
    lab(79, |root| async move {
        let stripped = {
            let _guard = Cx::push_restriction(CapMask::none());
            Cx::current().unwrap()
        };
        assert!(matches!(
            TimedWork::bootstrap_for_book(&stripped, Id128([79; 16]), POLICY),
            Err(TimedError::Clock(ClockError::MissingTimeCapability))
        ));
        let mut fixture = fixture(&root, 79).await;
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let mut work =
            TimedWork::bootstrap_for_book(&root, fixture.book.context().book_id, POLICY).unwrap();
        let cap = work.capability.as_ref().expect("bootstrap capability");
        assert_eq!(cap.books().unwrap().len(), 1);
        assert!(!cap.admits_book(Id128([80; 16])));
        assert!(!cap.holds(Op::Approve));
        assert!(!cap.holds(Op::IssueCapability));
        work.capability = Some(Capability::embedded(VId(1), &["witness", "post"]).unwrap());
        work.run_observation(&root, &mut fixture.book, Ok(observation(&root, 100)))
            .await
            .unwrap();
        hold(&mut fixture, &cx, b"human-cannot-expire", 5).await;
        advance(&root, 10).await;
        let error = work
            .run_observation(&root, &mut fixture.book, Ok(observation(&root, 110)))
            .await
            .unwrap_err();
        assert!(matches!(error, TimedError::Refused(ref r) if r.code == "FA-REF-011"));
        assert_eq!(fixture.book.due_holds(&cx).unwrap().len(), 1);
    })
    .unwrap()
    .expect("lab completed");
}

#[test]
fn cancellation_finishes_the_driver_without_recording_another_tick() {
    let completed = Arc::new(AtomicBool::new(false));
    let done = completed.clone();
    let result = lab(83, move |root| async move {
        let mut fixture = fixture(&root, 83).await;
        let mut work =
            TimedWork::bootstrap_for_book(&root, fixture.book.context().book_id, POLICY).unwrap();
        work.run_observation(&root, &mut fixture.book, Ok(observation(&root, 100)))
            .await
            .unwrap();
        let sample = observation(&root, 110);
        root.cancel_with(CancelKind::User, Some("stop timed work"));
        assert!(matches!(
            work.run_observation(&root, &mut fixture.book, Ok(sample))
                .await,
            Err(TimedError::Clock(ClockError::Cancelled))
        ));
        assert_eq!(work.last_tick_utc_ns, Some(100));
        assert_eq!(work.deadline(), None);
        done.store(true, Ordering::Release);
    });
    assert!(
        completed.load(Ordering::Acquire),
        "cancellation assertions completed"
    );
    assert!(
        matches!(result, Err(asupersync::runtime::JoinError::Cancelled(_))),
        "{result:?}"
    );
}

struct Fragmented {
    client: VirtualTcpStream,
    frame: Vec<u8>,
    release: bool,
    seen: Vec<String>,
    book: AsyncBook<MemVfs>,
    work: TimedWork,
    started: u64,
}

impl crate::Service for Fragmented {
    fn handle(&mut self, request: Request) -> (Response, crate::Next) {
        self.seen = request.argv;
        assert_eq!(request.op, WireOp::Stop);
        (
            Response {
                op: WireOp::Stop,
                exit: 0,
                stdout: "stopped".into(),
                stderr: String::new(),
            },
            crate::Next::Stop,
        )
    }

    fn deadline(&self) -> Option<Time> {
        self.work.deadline()
    }

    async fn tick(&mut self, cx: &Cx) {
        let elapsed = clock::timer(cx).unwrap().now().as_nanos() - self.started;
        self.work
            .run_observation(cx, &mut self.book, Ok(observation(cx, 1_000 + elapsed)))
            .await
            .unwrap();
        if self.release {
            let middle = self.frame.len() / 2;
            match self.work.cycles {
                2 => self.client.write_all(&self.frame[2..middle]).await.unwrap(),
                3 => self.client.write_all(&self.frame[middle..]).await.unwrap(),
                _ => (),
            }
        }
    }
}

#[test]
fn partial_prefix_and_payload_survive_multiple_real_timed_cycles_and_idle_is_bounded() {
    for (seed, release) in [(89, true), (97, false)] {
        lab(seed, move |root| async move {
            let fixture = fixture(&root, seed as u8).await;
            let (mut stream, mut client) =
                VirtualTcpStream::pair(([127, 0, 0, 1], 1).into(), ([127, 0, 0, 1], 2).into());
            let request = Request {
                op: WireOp::Stop,
                argv: vec!["--json".into()],
                cwd: None,
                stdin: None,
                token: None,
            };
            let frame = encode(request.to_json(1).render().as_bytes(), 4096).unwrap();
            client.write_all(&frame[..2]).await.unwrap();
            let work = TimedWork::bootstrap_for_book(&root, fixture.book.context().book_id, POLICY)
                .unwrap();
            let mut service = Fragmented {
                client,
                frame,
                release,
                seen: Vec::new(),
                book: fixture.book,
                work,
                started: clock::timer(&root).unwrap().now().as_nanos(),
            };
            let limits = crate::Limits {
                protocol: 1,
                max_frame_bytes: 4096,
                idle: Some(Duration::from_nanos(25)),
            };
            let ended = crate::serve_connection_with(
                &root,
                &mut stream,
                limits,
                Path::new("timed-book"),
                &mut service,
            )
            .await;
            assert_eq!(service.work.cycles, 3);
            assert_eq!(service.work.last_tick_utc_ns, Some(1_020));
            if release {
                assert_eq!(ended, crate::Ended::Stop);
                assert_eq!(service.seen, vec!["--json"]);
                drop(stream);
                let mut reply = Vec::new();
                service.client.read_to_end(&mut reply).await.unwrap();
                assert!(!reply.is_empty());
            } else {
                assert_eq!(ended, crate::Ended::Idle);
                assert!(
                    service.seen.is_empty(),
                    "a partial frame never reaches the handler"
                );
            }
        })
        .unwrap()
        .expect("lab completed");
    }
}

#[test]
fn register_maintenance_alone_never_bootstraps_timed_authority() {
    lab(139, |root| async move {
        let work =
            TimedWork::maintenance_only(&root, POLICY, vec!["FY2026-P03".to_string()]).unwrap();
        assert!(!work.timing_enabled());
        assert!(work.capability.is_none());
        assert_eq!(work.cycles, 0);
        assert_eq!(work.last_tick_utc_ns, None);
        assert_eq!(work.last_tick_monotonic_ok, None);
        assert!(work.register_maintenance().is_some());

        let fields = status_fields(Some(&work));
        let status = fa_cli::json::obj(fields);
        assert_eq!(status.get("timed_work_enabled"), Some(&Json::Bool(false)));
        assert_eq!(status.get("timed_authority"), Some(&Json::Null));
        assert_eq!(status.get("tick_ns"), Some(&Json::Null));
        assert_eq!(status.get("sweep_batch"), Some(&Json::Null));
        assert_eq!(status.get("clock_drift_ns"), Some(&Json::Null));
        assert!(
            status
                .get("register_maintenance")
                .is_some_and(|value| value != &Json::Null)
        );
        assert!(status_text(Some(&work)).contains("no System authority was bootstrapped"));
    })
    .unwrap()
    .expect("lab completed");
}
