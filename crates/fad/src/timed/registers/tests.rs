use super::*;
use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use asupersync::Budget;
use asupersync::lab::{AutoAdvanceTermination, LabConfig, LabRuntime};
use asupersync::types::CancelKind;

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

struct Scripted {
    calls: Vec<String>,
    results: VecDeque<Result<Publication, String>>,
}

impl RegisterBook for Scripted {
    fn book_id(&self) -> Id128 {
        Id128([0x5a; 16])
    }

    async fn advance(
        &mut self,
        _cx: &Cx,
        capability: &Capability,
        period: &str,
    ) -> Result<Publication, String> {
        assert_eq!(
            capability.ops(),
            &BTreeSet::from([Op::Read, Op::Verify, Op::Maintain])
        );
        assert_eq!(capability.books(), Some(&BTreeSet::from([self.book_id()])));
        self.calls.push(period.to_owned());
        self.results
            .pop_front()
            .expect("one result per scripted call")
    }
}

#[test]
fn maintenance_service_authority_is_narrow_and_pinned_to_the_first_real_book() {
    use std::path::Path;

    use fa::{BookKeys, Entropy};
    use fa_journal::BookSpec;
    use fa_money::UnitRegistry;
    use fa_time::FiscalCalendar;
    use fgdb::MemVfs;
    use fgdb_types::VId;

    async fn book(root: &Cx, seed: u8) -> AsyncBook<MemVfs> {
        let cx = PurposeContexts::narrow_runtime_root(root);
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let mut book = AsyncBook::create_with_vfs(
            &cx,
            vfs,
            Path::new("register-service-authority"),
            BookKeys::for_development(seed),
            BookSpec {
                book_id: Id128([seed; 16]),
                name: "Register service authority".into(),
                base_unit: UnitRegistry::embedded().unwrap().lookup("USD").unwrap(),
                calendar: FiscalCalendar::monthly("service-calendar", 1, 1).unwrap(),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            },
            Entropy::deterministic(u64::from(seed)),
        )
        .await
        .unwrap();
        let principal = VId(1);
        book.create_periods(
            &cx,
            2026,
            principal,
            &Capability::embedded(principal, &["schema_change"]).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        book
    }

    lab(181, |root| async move {
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let mut first = book(&root, 181).await;
        let mut other = book(&root, 182).await;
        let mut work = RegisterWork::new(vec!["FY2026-P03".into()]).unwrap();
        assert!(work.authority.is_none());
        let before = first.head(&cx).unwrap();
        work.run_cycle(&root, &mut first).await;
        let publication = work.periods()[0].last_success.clone().unwrap();
        assert!(publication.wrote);
        assert!(first.head(&cx).unwrap() > before);
        assert!(work.periods()[0].error.is_none());
        assert!(
            first
                .verify_registers(&cx, "FY2026-P03")
                .unwrap()
                .is_green()
        );

        let authority = work.authority.as_ref().unwrap().as_ref().unwrap().clone();
        assert_eq!(authority.profile(), Profile::System);
        assert_eq!(
            authority.holder(),
            fa_journal::rows::system_principal(first.context().book_id)
        );
        assert_eq!(
            authority.ops(),
            &BTreeSet::from([Op::Read, Op::Verify, Op::Maintain])
        );
        assert_eq!(
            authority.books(),
            Some(&BTreeSet::from([first.context().book_id]))
        );
        let other_before = other.head(&cx).unwrap();
        let refusal = other
            .advance_registers(&cx, authority.holder(), &authority, "FY2026-P03")
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, 7);
        work.run_cycle(&root, &mut other).await;
        assert_eq!(other.head(&cx).unwrap(), other_before);
        assert_eq!(work.periods()[0].last_success, Some(publication));
        assert_eq!(work.periods()[0].error, Some(refusal.to_string()));
        assert_eq!(
            work.authority.as_ref().unwrap().as_ref().unwrap().books(),
            authority.books(),
            "a different book never causes a new implicit service grant"
        );
        assert!(first.latest_tick(&cx).unwrap().is_none());
        assert!(other.latest_tick(&cx).unwrap().is_none());
    })
    .unwrap()
    .expect("lab completed");
}

fn publication(through: u64) -> Publication {
    Publication {
        through,
        published_at: through + 1,
        entries_decoded: 1,
        rebuilt: false,
        wrote: true,
    }
}

#[test]
fn fiscal_year_selection_uses_custom_boundaries_and_preserves_the_scheduling_bound() {
    use fa_time::{CustomYear, DateDay, FiscalCalendar};
    let start = DateDay::from_ymd(2026, 1, 1).unwrap();
    let calendar = FiscalCalendar::custom(
        "short",
        vec![CustomYear {
            fiscal_year: 2026,
            bounds: vec![
                start,
                start.add_days(10).unwrap(),
                start.add_days(30).unwrap(),
            ],
        }],
        2,
    )
    .unwrap();
    assert_eq!(
        fiscal_year_periods(&calendar, 2026).unwrap(),
        [
            "FY2026-P01",
            "FY2026-P02",
            "FY2026-OPEN",
            "FY2026-A1",
            "FY2026-A2",
            "FY2026-CLOSE",
        ]
    );
    assert!(fiscal_year_periods(&calendar, 2027).is_err());
    let largest = FiscalCalendar::custom(
        "largest",
        vec![CustomYear {
            fiscal_year: 2026,
            bounds: (0..=fa_time::calendar::MAX_CUSTOM_PERIODS)
                .map(|n| start.add_days(n as i32).unwrap())
                .collect(),
        }],
        fa_time::calendar::MAX_ADJUSTMENT_PERIODS,
    )
    .unwrap();
    let selected = fiscal_year_periods(&largest, 2026).unwrap();
    assert_eq!(selected.len(), 59);
    assert!(selected.len() <= MAX_PERIODS);
    assert!(
        fiscal_year_periods(&FiscalCalendar::monthly("monthly", 1, 0).unwrap(), i32::MAX).is_err()
    );
}

#[test]
fn configuration_is_bounded_exact_and_never_silently_repaired() {
    for periods in [
        vec![],
        vec![String::new()],
        vec!["--json".into()],
        vec!["FY2026-P03 ".into()],
        vec!["FY2026-\nP03".into()],
        vec!["x".repeat(MAX_PERIOD_CODE_BYTES + 1)],
        vec!["FY2026-P03".into(), "FY2026-P03".into()],
        (0..=MAX_PERIODS).map(|i| format!("period-{i}")).collect(),
    ] {
        assert!(RegisterWork::new(periods).is_err());
    }
    let periods = vec!["FY2026-P04".into(), "FY2026-P03".into()];
    let work = RegisterWork::new(periods.clone()).unwrap();
    assert_eq!(
        work.periods()
            .iter()
            .map(|p| p.period.clone())
            .collect::<Vec<_>>(),
        periods
    );
    assert_eq!(work.attempts(), 0);
    assert!(RegisterWork::new((0..MAX_PERIODS).map(|i| format!("period-{i}")).collect()).is_ok());
    assert!(RegisterWork::new(vec!["x".repeat(MAX_PERIOD_CODE_BYTES)]).is_ok());
}

#[test]
fn unattempted_periods_never_claim_a_consumed_or_certified_prefix() {
    let work = RegisterWork::new(vec!["FY2026-P03".into()]).unwrap();
    let status = work.status();
    assert_eq!(status.get("certified"), Some(&Json::Bool(false)));
    assert_eq!(status.get("periods_per_cycle"), Some(&Json::Int(1)));
    let period = &status.get("periods").unwrap().as_arr().unwrap()[0];
    for name in [
        "through",
        "published_at",
        "wrote",
        "rebuilt",
        "entries_decoded",
        "error",
    ] {
        assert_eq!(period.get(name), Some(&Json::Null), "{name}");
    }
}

#[test]
fn one_attempt_per_cycle_errors_are_per_period_and_rotation_is_fair() {
    lab(107, |root| async move {
        let mut work = RegisterWork::new(vec!["A".into(), "B".into()]).unwrap();
        let mut book = Scripted {
            calls: vec![],
            results: VecDeque::from([
                Ok(publication(1)),
                Ok(publication(2)),
                Err("projection drift".into()),
                Ok(publication(4)),
                Ok(publication(5)),
            ]),
        };
        for count in 1..=4 {
            work.run_cycle(&root, &mut book).await;
            assert_eq!(book.calls.len(), count);
        }
        assert_eq!(book.calls, ["A", "B", "A", "B"]);
        assert_eq!(work.periods()[0].last_success, Some(publication(1)));
        assert_eq!(work.periods()[0].error.as_deref(), Some("projection drift"));
        assert!(work.periods()[1].error.is_none());
        // Another period's success cannot erase this period's failure.
        let status = work.status();
        let a = &status.get("periods").unwrap().as_arr().unwrap()[0];
        assert_eq!(a.get("through"), Some(&Json::Int(1)));
        assert_eq!(a.get("error").unwrap().as_str(), Some("projection drift"));
        work.run_cycle(&root, &mut book).await;
        assert_eq!(work.periods()[0].last_success, Some(publication(5)));
        assert!(work.periods()[0].error.is_none());
        assert_eq!(work.attempts(), 5);
        assert!(book.results.is_empty());
    })
    .unwrap()
    .expect("lab completed");
}

#[test]
fn a_native_noop_is_success_without_a_claimed_publication_sequence() {
    lab(108, |root| async move {
        let mut work = RegisterWork::new(vec!["A".into()]).unwrap();
        let mut book = Scripted {
            calls: vec![],
            results: VecDeque::from([
                Err("retryable failure".into()),
                Ok(Publication {
                    through: 9,
                    published_at: 9,
                    entries_decoded: 0,
                    rebuilt: false,
                    wrote: false,
                }),
            ]),
        };
        work.run_cycle(&root, &mut book).await;
        work.run_cycle(&root, &mut book).await;
        let status = work.status();
        let a = &status.get("periods").unwrap().as_arr().unwrap()[0];
        assert_eq!(a.get("through"), Some(&Json::Int(9)));
        assert_eq!(a.get("published_at"), Some(&Json::Null));
        assert_eq!(a.get("wrote"), Some(&Json::Bool(false)));
        assert_eq!(a.get("error"), Some(&Json::Null));
    })
    .unwrap()
    .expect("lab completed");
}

#[test]
fn cancellation_before_admission_does_not_touch_a_period_or_rotate() {
    let completed = Arc::new(AtomicBool::new(false));
    let done = completed.clone();
    let result = lab(131, move |root| async move {
        let mut work = RegisterWork::new(vec!["A".into(), "B".into()]).unwrap();
        let mut book = Scripted {
            calls: vec![],
            results: VecDeque::new(),
        };
        root.cancel_with(CancelKind::User, Some("stop maintenance"));
        work.run_cycle(&root, &mut book).await;
        assert!(book.calls.is_empty());
        assert_eq!(work.attempts(), 0);
        assert_eq!(
            work.status().get("next_period").unwrap().as_str(),
            Some("A")
        );
        done.store(true, Ordering::Release);
    });
    assert!(completed.load(Ordering::Acquire));
    assert!(matches!(
        result,
        Err(asupersync::runtime::JoinError::Cancelled(_))
    ));
}

#[test]
fn long_unicode_diagnostics_are_bounded_without_corrupting_status_json() {
    lab(137, |root| async move {
        let mut work = RegisterWork::new(vec!["A".into()]).unwrap();
        let mut book = Scripted {
            calls: vec![],
            results: VecDeque::from([Err("€".repeat(1000))]),
        };
        work.run_cycle(&root, &mut book).await;
        let error = work.periods()[0].error.as_ref().unwrap();
        assert!(error.len() <= 1040);
        assert!(error.ends_with(" [truncated]"));
        assert!(work.status().render().contains("[truncated]"));
    })
    .unwrap()
    .expect("lab completed");
}
