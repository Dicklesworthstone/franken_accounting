//! Complete fiscal periods drive charges, including retail and custom years.

use super::*;
use fa_time::{CustomYear, WeekPattern, Weekday, YearEndRule};

fn retail_end() -> YearEndRule {
    // FY2026 contains 53 weeks under this rule, so its last period is longer.
    YearEndRule::LastWeekdayOfMonth {
        weekday: Weekday::Thursday,
        month: 12,
    }
}

fn custom_calendar() -> FiscalCalendar {
    let day = |month, day| DateDay::from_ymd(2026, month, day).unwrap();
    FiscalCalendar::custom(
        "custom-assets",
        vec![
            CustomYear {
                fiscal_year: 2026,
                bounds: (1..=6).map(|month| day(month, 1)).collect(),
            },
            CustomYear {
                fiscal_year: 2027,
                bounds: vec![day(6, 1), day(6, 11), day(7, 1)],
            },
        ],
        1,
    )
    .unwrap()
}

fn fixture(calendar: FiscalCalendar, kind: AssetCostKind, life: u32) -> Fixture {
    Fixture::from_harness(
        harness_with_calendar(Vec::new(), None, None, true, calendar),
        kind,
        10_007,
        7,
        life,
        Vec::new(),
    )
}

fn install_year(f: &mut Fixture, year: i32) {
    let cx = f.h.ctx();
    let description = f.source.description.clone();
    f.h.runtime
        .block_on(create_periods(
            &mut f.h.db,
            &cx,
            &f.h.book,
            year,
            PRINCIPAL,
            description,
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
}

fn open_period(f: &mut Fixture, code: &str) {
    f.h.transition(
        code,
        PeriodTransition::Open,
        format!("open-{code}").as_bytes(),
    )
    .unwrap();
}

fn template(f: &Fixture, code: &str, key: &[u8]) -> EntryPayload {
    let definition = fa_journal::policy::calendar_period(&f.h.book, code).unwrap();
    let mut proposal = f.h.proposal(vec![], key, EntryClass::ADJUSTING);
    proposal.effective_date = definition.end.pred().unwrap();
    proposal.effective_period = Some(PeriodRef {
        calendar: f.h.book.calendar.id.clone(),
        code: code.into(),
    });
    proposal
}

fn prepare(f: &Fixture, code: &str, key: &[u8]) -> Result<PreparedAssetCharge, Refusal> {
    let proposal = template(f, code, key);
    prepare_asset_charge(
        &f.h.db,
        &f.h.ctx(),
        &f.h.book,
        &cap(),
        &AssetChargeRequest {
            schedule: f.schedule.entry,
            through_period: proposal.effective_period.clone().unwrap(),
            kind: f.schedule.spec.kind,
        },
        &proposal,
    )
    .unwrap()
}

#[test]
fn retail_charges_count_twelve_or_thirteen_periods_and_cross_fifty_three_week_years() {
    let mut calendars: Vec<_> = [WeekPattern::W445, WeekPattern::W454, WeekPattern::W544]
        .into_iter()
        .map(|pattern| {
            (
                FiscalCalendar::weeks("retail-assets", pattern, retail_end(), 1).unwrap(),
                12,
            )
        })
        .collect();
    calendars.push((
        FiscalCalendar::week_52_53("thirteen-assets", retail_end(), 1).unwrap(),
        13,
    ));
    for (calendar, life) in calendars {
        let (start, end) = calendar.year_bounds(2026).unwrap();
        assert_eq!(end.0 - start.0 + 1, 53 * 7);
        for kind in [AssetCostKind::Depreciation, AssetCostKind::Amortization] {
            let mut f = fixture(calendar.clone(), kind, life);
            install_year(&mut f, 2027);
            let last = format!("FY2026-P{life:02}");
            for period in [last.as_str(), "FY2027-P01", "FY2027-P02"] {
                open_period(&mut f, period);
            }
            let targets = if life == 13 {
                [769, 8462, 9231, 10_000]
            } else {
                [833, 8333, 9167, 10_000]
            };
            let mut recognized = 0;
            for (period, target) in ["FY2026-P03", last.as_str(), "FY2027-P01", "FY2027-P02"]
                .into_iter()
                .zip(targets)
            {
                let key = format!("charge-{period}");
                let before = f.h.db.frontier().unwrap();
                let prepared = prepare(&f, period, key.as_bytes()).unwrap();
                assert_eq!(prepared.target().mantissa, target);
                assert_eq!(prepared.delta().mantissa, target - recognized);
                assert_eq!(f.h.db.frontier().unwrap(), before);
                let proposal = prepared
                    .proposal(template(&f, period, key.as_bytes()))
                    .unwrap();
                f.h.post(posting(proposal)).unwrap();
                recognized = target;
            }
            let at = f.h.db.frontier().unwrap();
            let register = asset_register(&f.h.db, &f.h.ctx(), &f.h.book, &cap(), at)
                .unwrap()
                .unwrap();
            assert_eq!(register.rows[0].recognized.mantissa, 10_000);
            assert_eq!(register.rows[0].carrying_amount.mantissa, 7);
            assert_eq!(register.rows[0].remaining_depreciable.mantissa, 0);
            assert_eq!(
                register.rows[0].covered_through.as_ref().unwrap().code,
                "FY2027-P02"
            );
            assert!(prepare(&f, "FY2027-P02", b"finished").unwrap().is_noop());
            let verified = verify_asset_schedules(&f.h.db, &f.h.ctx(), &f.h.book).unwrap();
            assert!(verified.is_green());
            assert_eq!(verified.executed, 4);
        }
    }
}

#[test]
fn custom_variable_years_preserve_catchup_reversals_high_water_and_exact_salvage() {
    let mut f = fixture(custom_calendar(), AssetCostKind::Amortization, 5);
    install_year(&mut f, 2027);
    open_period(&mut f, "FY2027-P01");
    open_period(&mut f, "FY2027-P02");
    let first = prepare(&f, "FY2026-P03", b"custom-first")
        .unwrap()
        .proposal(template(&f, "FY2026-P03", b"custom-first"))
        .unwrap();
    assert_eq!(first.legs[0].amount.mantissa, 2000);
    let first_ref = f.h.post(posting(first.clone())).unwrap().entry_ref();
    let first_at = f.h.db.frontier().unwrap();
    let catchup = prepare(&f, "FY2027-P01", b"custom-catchup")
        .unwrap()
        .proposal(template(&f, "FY2027-P01", b"custom-catchup"))
        .unwrap();
    // The ten-day period in the second custom year is still exactly one
    // scheduled period, following three complete periods in the stub year.
    assert_eq!(catchup.legs[0].amount.mantissa, 6000);
    let caught_up = f.h.post(posting(catchup.clone())).unwrap().entry_ref();
    f.h.post(posting(undo(&catchup, caught_up, b"custom-undo")))
        .unwrap();
    let before = f.h.db.frontier().unwrap();
    assert!(prepare(&f, "FY2026-P05", b"custom-backwards").is_err());
    assert_eq!(f.h.db.frontier().unwrap(), before);
    let repair = prepare(&f, "FY2027-P01", b"custom-repair").unwrap();
    assert_eq!(repair.delta().mantissa, 6000);
    f.h.post(posting(
        repair
            .proposal(template(&f, "FY2027-P01", b"custom-repair"))
            .unwrap(),
    ))
    .unwrap();
    let final_charge = prepare(&f, "FY2027-P02", b"custom-final").unwrap();
    assert_eq!(final_charge.delta().mantissa, 2000);
    f.h.post(posting(
        final_charge
            .proposal(template(&f, "FY2027-P02", b"custom-final"))
            .unwrap(),
    ))
    .unwrap();
    assert_eq!(f.h.post(posting(first)).unwrap().entry_ref(), first_ref);
    for (at, expected) in [(first_at, 2000), (f.h.db.frontier().unwrap(), 10_000)] {
        let register = asset_register(&f.h.db, &f.h.ctx(), &f.h.book, &cap(), at)
            .unwrap()
            .unwrap();
        assert_eq!(register.rows[0].recognized.mantissa, expected);
        assert_eq!(register.rows[0].carrying_amount.mantissa, 10_007 - expected);
    }
    assert!(
        verify_asset_schedules(&f.h.db, &f.h.ctx(), &f.h.book)
            .unwrap()
            .is_green()
    );
}

#[test]
fn custom_schedule_life_must_fit_declared_calendar_before_any_control_is_written() {
    let mut f = fixture(custom_calendar(), AssetCostKind::Depreciation, 5);
    let mut source = f.source.clone();
    source.idempotency_key = b"too-long-source".to_vec();
    let acquisition = f.h.post(posting(source)).unwrap().entry_ref();
    let mut spec = f.schedule.spec.clone();
    spec.name = "outlives-calendar".into();
    spec.acquisition = acquisition;
    spec.useful_life_periods = 6;
    let request = AssetScheduleRequest {
        principal: PRINCIPAL,
        spec,
        effective_date: f.h.day(),
        idempotency_key: b"too-long-schedule".to_vec(),
        description: f.source.description.clone(),
        approvals: vec![],
    };
    let frontier = f.h.db.frontier().unwrap();
    let vertices = f.h.db.vertices().unwrap();
    let refusal = register_schedule(&mut f.h, &request).unwrap_err();
    assert!(
        refusal.message.contains("declared normal periods"),
        "{refusal:?}"
    );
    assert_eq!(f.h.db.frontier().unwrap(), frontier);
    assert_eq!(f.h.db.vertices().unwrap(), vertices);
}

#[test]
fn retail_special_periods_and_noncanonical_period_rows_cannot_charge() {
    let calendar = FiscalCalendar::week_52_53("retail-negative", retail_end(), 1).unwrap();
    let mut f = fixture(calendar, AssetCostKind::Depreciation, 3);
    let before = f.h.db.frontier().unwrap();
    for period in ["FY2026-OPEN", "FY2026-A1", "FY2026-CLOSE", "FY2026-P02"] {
        assert!(prepare(&f, period, b"not-a-scheduled-period").is_err());
    }
    assert_eq!(f.h.db.frontier().unwrap(), before);

    let proposal = template(&f, "FY2026-P04", b"forged-period");
    let selected = proposal.effective_period.clone().unwrap();
    let vid = fa_model::period_vid(&selected.calendar, &selected.code);
    let row = f.h.db.vertex(vid).unwrap().unwrap();
    let start = fa_journal::rows::PeriodRow::decode(&row).unwrap().start;
    let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
    damage.compare_and_set_vertex_property(
        vid,
        property::PERIOD_START,
        fa_journal::rows::prop(&row, property::PERIOD_START).cloned(),
        CanonicalScalar::Int(i64::from(start.0) + 1),
        fgdb::WriteMismatchPolicy::AbortWrite,
    );
    f.h.write_raw(damage);
    let at = f.h.db.frontier().unwrap();
    assert!(
        prepare_asset_charge(
            &f.h.db,
            &f.h.ctx(),
            &f.h.book,
            &cap(),
            &AssetChargeRequest {
                schedule: f.schedule.entry,
                through_period: selected,
                kind: AssetCostKind::Depreciation,
            },
            &proposal,
        )
        .is_err()
    );
    assert_eq!(f.h.db.frontier().unwrap(), at);
}
