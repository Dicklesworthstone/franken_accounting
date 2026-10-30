//! Source-bound finite asset costs through real native plan/commit and undo.

use super::*;
use fa_journal::asset_cost::{
    AssetChargeRequest, AssetCostKind, AssetScheduleRecorded, AssetScheduleRequest,
    AssetScheduleSpec, PreparedAssetCharge, asset_register, asset_schedules, create_asset_schedule,
    prepare_asset_charge, verify_asset_schedules,
};
use fa_model::PeriodRef;
use fa_money::RoundingLaw;

struct Fixture {
    h: Harness,
    acquisition: EntryRef,
    source: EntryPayload,
    schedule: AssetScheduleRecorded,
}

fn cap() -> Capability {
    Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap()
}

fn posting(proposal: EntryPayload) -> PostRequest {
    PostRequest {
        proposal,
        approvals: vec![],
        plan_certificate: None,
        capability: cap(),
    }
}

fn undo(proposal: &EntryPayload, target: EntryRef, key: &[u8]) -> EntryPayload {
    let mut reversed = proposal.clone();
    reversed.class = EntryClass::REVERSAL;
    reversed.idempotency_key = key.to_vec();
    reversed.supersession = vec![Supersession {
        kind: SupersessionKind::Reverses,
        target,
        reason_code: 1,
    }];
    for leg in &mut reversed.legs {
        leg.side = leg.side.flipped();
    }
    reversed.unit_totals = EntryPayload::fold_unit_totals(&reversed.legs).unwrap();
    reversed
}

impl Fixture {
    fn new(kind: AssetCostKind, cost: i128, salvage: i128, periods: u32) -> Self {
        let mut h = harness();
        let accounts = [("1500", 0), ("1590", 1)].map(|(code, normal)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type: fa_model::AccountType::ASSET.0,
            normal_balance: normal,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(h.usd),
            parent_code: None,
            limit: None,
        });
        let cx = h.ctx();
        let description = h
            .proposal(vec![], b"asset-chart", EntryClass::ORIGINAL)
            .description;
        let schema = Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap();
        let day = h.day();
        h.runtime
            .block_on(install_chart(
                &mut h.db,
                &cx,
                &h.book,
                &accounts,
                PRINCIPAL,
                day,
                b"asset-chart",
                description,
                &schema,
            ))
            .unwrap()
            .unwrap();
        h.transition("FY2026-P05", PeriodTransition::Open, b"open-asset-may")
            .unwrap();
        let source = h.proposal(
            vec![
                LegPayload::simple(
                    Side::Debit,
                    account_vid(h.book.book_id, "1500"),
                    Amount::new(h.usd, cost),
                ),
                LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, cost)),
            ],
            b"asset-acquisition",
            EntryClass::ORIGINAL,
        );
        let acquisition = h.post(posting(source.clone())).unwrap().entry_ref();
        let spec = AssetScheduleSpec {
            name: "press".into(),
            kind,
            acquisition,
            acquisition_ordinal: 0,
            first_period: PeriodRef {
                calendar: h.book.calendar.id.clone(),
                code: h.march.clone(),
            },
            useful_life_periods: periods,
            salvage: Amount::new(h.usd, salvage),
            expense_account: h.rent,
            accumulated_account: account_vid(h.book.book_id, "1590"),
            rounding_law: RoundingLaw::HalfEven,
        };
        let request = AssetScheduleRequest {
            principal: PRINCIPAL,
            spec,
            effective_date: day,
            idempotency_key: b"asset-schedule".to_vec(),
            description: source.description.clone(),
            approvals: vec![],
        };
        let schedule = h
            .runtime
            .block_on(create_asset_schedule(
                &mut h.db, &cx, &h.book, &schema, request,
            ))
            .unwrap()
            .unwrap();
        Self {
            h,
            acquisition,
            source,
            schedule,
        }
    }

    fn template(&self, month: u8, key: &[u8]) -> EntryPayload {
        let code = format!("FY2026-P{month:02}");
        let definition = fa_journal::policy::calendar_period(&self.h.book, &code).unwrap();
        let mut template = self.h.proposal(vec![], key, EntryClass::ADJUSTING);
        template.effective_date = definition.end.pred().unwrap();
        template.effective_period = Some(PeriodRef {
            calendar: self.h.book.calendar.id.clone(),
            code,
        });
        template
    }

    fn prepare(&self, month: u8, key: &[u8]) -> Result<PreparedAssetCharge, Refusal> {
        let template = self.template(month, key);
        prepare_asset_charge(
            &self.h.db,
            &self.h.ctx(),
            &self.h.book,
            &cap(),
            &AssetChargeRequest {
                schedule: self.schedule.entry,
                through_period: template.effective_period.clone().unwrap(),
                kind: self.schedule.spec.kind,
            },
            &template,
        )
        .unwrap()
    }

    fn proposal(&self, month: u8, key: &[u8]) -> EntryPayload {
        self.prepare(month, key)
            .unwrap()
            .proposal(self.template(month, key))
            .unwrap()
    }
}

#[test]
fn native_depreciation_and_amortization_round_cumulative_targets_and_finish_exactly() {
    for kind in [AssetCostKind::Depreciation, AssetCostKind::Amortization] {
        let mut f = Fixture::new(kind, 10_007, 7, 3);
        let mut recognized = 0;
        for (month, charge) in [(3, 3333), (4, 3334), (5, 3333)] {
            let key = format!("asset-{month}");
            let before = f.h.db.frontier().unwrap();
            let prepared = f.prepare(month, key.as_bytes()).unwrap();
            assert_eq!(prepared.cost().mantissa, 10_007);
            assert_eq!(prepared.recognized().mantissa, recognized);
            assert_eq!(prepared.delta().mantissa, charge);
            assert_eq!(f.h.db.frontier().unwrap(), before);
            let proposal = prepared
                .proposal(f.template(month, key.as_bytes()))
                .unwrap();
            let plan = f.h.post_plan(posting(proposal)).unwrap();
            assert!(matches!(
                f.h.publish_plan(plan.clone(), &cap()).unwrap(),
                Posted::Committed { .. }
            ));
            assert!(matches!(
                f.h.publish_plan(plan, &cap()).unwrap(),
                Posted::AlreadyRecorded { .. }
            ));
            recognized += charge;
            let before_noop = f.h.db.frontier().unwrap();
            assert!(
                f.prepare(month, format!("noop-{month}").as_bytes())
                    .unwrap()
                    .is_noop()
            );
            assert_eq!(f.h.db.frontier().unwrap(), before_noop);
        }
        assert_eq!(recognized, 10_000);
        let verified = verify_asset_schedules(&f.h.db, &f.h.ctx(), &f.h.book).unwrap();
        assert_eq!(verified.schedules_checked, 1);
        assert_eq!(verified.executed, 3);
        assert!(verified.is_green());
    }
}

#[test]
fn catchup_reversal_rerecognition_and_exact_original_retry_are_consistent() {
    let mut f = Fixture::new(AssetCostKind::Depreciation, 100, 0, 3);
    let original = f.proposal(3, b"first");
    let first = f.h.post(posting(original.clone())).unwrap().entry_ref();
    let catchup = f.proposal(5, b"catchup");
    assert_eq!(catchup.legs[0].amount.mantissa, 67);
    let catchup_ref = f.h.post(posting(catchup.clone())).unwrap().entry_ref();
    let reversed = undo(&catchup, catchup_ref, b"undo-catchup");
    let reversed_ref = f.h.post(posting(reversed.clone())).unwrap().entry_ref();
    assert!(f.prepare(4, b"retrograde").is_err());
    assert_eq!(f.prepare(5, b"repair").unwrap().delta().mantissa, 67);
    let repair = f.proposal(5, b"repair");
    f.h.post(posting(repair)).unwrap();
    assert_eq!(f.proposal(3, b"first"), original);
    assert_eq!(f.h.post(posting(original)).unwrap().entry_ref(), first);
    assert!(
        f.h.post(posting(undo(
            &reversed,
            reversed_ref,
            b"double-recognition"
        )))
        .is_err()
    );
    assert!(
        verify_asset_schedules(&f.h.db, &f.h.ctx(), &f.h.book)
            .unwrap()
            .is_green()
    );
}

#[test]
fn monetary_forgery_stale_state_and_two_prepared_racers_cannot_charge_twice() {
    let mut f = Fixture::new(AssetCostKind::Depreciation, 100, 10, 3);
    let proposal = f.proposal(3, b"tampered");
    let before = f.h.db.frontier().unwrap();
    let mut tampered = proposal.clone();
    for leg in &mut tampered.legs {
        leg.amount.mantissa += 1;
    }
    tampered.unit_totals = EntryPayload::fold_unit_totals(&tampered.legs).unwrap();
    assert!(f.h.post(posting(tampered)).is_err());
    assert_eq!(f.h.db.frontier().unwrap(), before);
    let first = f.proposal(3, b"race-one");
    let second = f.proposal(3, b"race-two");
    let cx = f.h.ctx();
    let PostPreparation::Ready(one) = prepare_post(&mut f.h.db, &cx, &f.h.book, posting(first))
        .unwrap()
        .unwrap()
    else {
        panic!("fresh plan");
    };
    let PostPreparation::Ready(two) =
        prepare_post(&mut f.h.db, &cx, &f.h.book, posting(second.clone()))
            .unwrap()
            .unwrap()
    else {
        panic!("fresh plan");
    };
    f.h.runtime
        .block_on(one.commit(&mut f.h.db, &cx))
        .unwrap()
        .unwrap();
    assert_eq!(
        f.h.runtime
            .block_on(two.commit(&mut f.h.db, &cx))
            .unwrap()
            .unwrap_err()
            .exit,
        6
    );
    assert_eq!(f.h.post(posting(second)).unwrap_err().exit, 6);
    assert!(f.prepare(3, b"after-race").unwrap().is_noop());
}

#[test]
fn reversing_an_undo_cannot_recognize_future_periods_already_caught_up() {
    let mut f = Fixture::new(AssetCostKind::Depreciation, 100, 0, 3);
    let first = f.proposal(3, b"early-charge");
    let first_ref = f.h.post(posting(first.clone())).unwrap().entry_ref();
    let reversed = undo(&first, first_ref, b"early-charge-undo");
    let reversed_ref = f.h.post(posting(reversed.clone())).unwrap().entry_ref();
    let catchup = f.proposal(4, b"middle-catchup");
    assert_eq!(catchup.legs[0].amount.mantissa, 67);
    f.h.post(posting(catchup)).unwrap();
    let before = f.h.db.frontier().unwrap();
    let refusal =
        f.h.post(posting(undo(
            &reversed,
            reversed_ref,
            b"reinstate-earlier-charge",
        )))
        .unwrap_err();
    assert!(refusal.message.contains("duplicate"));
    assert_eq!(f.h.db.frontier().unwrap(), before);
    assert_eq!(
        f.prepare(5, b"remaining-life").unwrap().delta().mantissa,
        33
    );
    assert!(
        verify_asset_schedules(&f.h.db, &f.h.ctx(), &f.h.book)
            .unwrap()
            .is_green()
    );
}

#[test]
fn an_independent_approval_preserves_the_exact_reviewed_charge_bytes() {
    let mut f = Fixture::new(AssetCostKind::Amortization, 100, 0, 3);
    let reviewed = f.proposal(3, b"review-then-approval");
    let approval = f.h.approve_transition(reviewed.proposal_digest().unwrap());
    let mut request = posting(reviewed.clone());
    request.approvals = vec![approval];
    let plan = f.h.post_plan(request).unwrap();
    f.h.publish_plan(plan, &cap()).unwrap();
    assert_eq!(f.proposal(3, b"review-then-approval"), reviewed);
    assert!(
        verify_asset_schedules(&f.h.db, &f.h.ctx(), &f.h.book)
            .unwrap()
            .is_green()
    );
}

#[test]
fn nested_acquisition_reversal_cannot_strand_a_restored_asset_charge() {
    let mut f = Fixture::new(AssetCostKind::Depreciation, 100, 0, 3);
    let charge = f.proposal(3, b"original-charge");
    let charge_ref = f.h.post(posting(charge.clone())).unwrap().entry_ref();
    let source_reverse = undo(&f.source, f.acquisition, b"source-undo");
    assert!(f.h.post(posting(source_reverse.clone())).is_err());
    f.h.post(posting(undo(&charge, charge_ref, b"charge-undo")))
        .unwrap();
    let source_reverse_ref =
        f.h.post(posting(source_reverse.clone()))
            .unwrap()
            .entry_ref();
    assert!(f.prepare(3, b"inactive-source").is_err());
    let source_restore = undo(&source_reverse, source_reverse_ref, b"source-restore");
    let source_restore_ref =
        f.h.post(posting(source_restore.clone()))
            .unwrap()
            .entry_ref();
    let charge = f.proposal(3, b"restored-charge");
    f.h.post(posting(charge)).unwrap();
    let before = f.h.db.frontier().unwrap();
    assert!(
        f.h.post(posting(undo(
            &source_restore,
            source_restore_ref,
            b"nested-source-undo"
        )))
        .is_err()
    );
    assert_eq!(f.h.db.frontier().unwrap(), before);
    assert!(
        verify_asset_schedules(&f.h.db, &f.h.ctx(), &f.h.book)
            .unwrap()
            .is_green()
    );
}

#[test]
fn schedule_registration_conflicts_with_an_already_prepared_source_reversal() {
    let mut f = Fixture::new(AssetCostKind::Depreciation, 100, 0, 3);
    let mut another = f.source.clone();
    another.idempotency_key = b"other-acquisition".to_vec();
    let another_ref = f.h.post(posting(another.clone())).unwrap().entry_ref();
    let cx = f.h.ctx();
    let PostPreparation::Ready(undo_source) = prepare_post(
        &mut f.h.db,
        &cx,
        &f.h.book,
        posting(undo(&another, another_ref, b"other-source-reverse")),
    )
    .unwrap()
    .unwrap() else {
        panic!("fresh source reversal");
    };
    let mut spec = f.schedule.spec.clone();
    spec.name = "other-asset".into();
    spec.acquisition = another_ref;
    let request = AssetScheduleRequest {
        principal: PRINCIPAL,
        spec,
        effective_date: f.h.day(),
        idempotency_key: b"other-schedule".to_vec(),
        description: another.description,
        approvals: vec![],
    };
    let schema = Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap();
    f.h.runtime
        .block_on(create_asset_schedule(
            &mut f.h.db,
            &cx,
            &f.h.book,
            &schema,
            request,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(
        f.h.runtime
            .block_on(undo_source.commit(&mut f.h.db, &cx))
            .unwrap()
            .unwrap_err()
            .exit,
        6
    );
}

#[test]
fn a_new_charge_conflicts_with_a_prepared_zero_recognition_source_reversal() {
    let mut f = Fixture::new(AssetCostKind::Depreciation, 100, 0, 3);
    let cx = f.h.ctx();
    let proposal = undo(&f.source, f.acquisition, b"source-before-charge");
    let PostPreparation::Ready(source_undo) =
        prepare_post(&mut f.h.db, &cx, &f.h.book, posting(proposal))
            .unwrap()
            .unwrap()
    else {
        panic!("fresh source reversal");
    };
    let charge = f.proposal(3, b"charge-before-source-undo");
    f.h.post(posting(charge)).unwrap();
    assert_eq!(
        f.h.runtime
            .block_on(source_undo.commit(&mut f.h.db, &cx))
            .unwrap()
            .unwrap_err()
            .exit,
        6
    );
    assert!(
        verify_asset_schedules(&f.h.db, &f.h.ctx(), &f.h.book)
            .unwrap()
            .is_green()
    );
}

#[test]
fn zero_depreciable_basis_and_zero_installments_publish_nothing() {
    let f = Fixture::new(AssetCostKind::Depreciation, 10, 10, 3);
    let before = f.h.db.frontier().unwrap();
    for month in 3..=5 {
        assert!(f.prepare(month, b"zero-basis").unwrap().is_noop());
    }
    assert_eq!(f.h.db.frontier().unwrap(), before);
    let mut f = Fixture::new(AssetCostKind::Depreciation, 1, 0, 3);
    assert!(f.prepare(3, b"rounds-to-zero").unwrap().is_noop());
    let terminal = f.proposal(5, b"last-residual");
    assert_eq!(terminal.legs[0].amount.mantissa, 1);
    f.h.post(posting(terminal)).unwrap();
    assert!(f.prepare(5, b"terminal-noop").unwrap().is_noop());
}

#[test]
fn missed_final_period_can_catch_up_later_without_extending_depreciable_cost() {
    let mut f = Fixture::new(AssetCostKind::Depreciation, 100, 10, 3);
    f.h.transition(
        "FY2026-P06",
        PeriodTransition::Open,
        b"open-late-asset-period",
    )
    .unwrap();
    let first = f.proposal(3, b"first-before-gap");
    f.h.post(posting(first)).unwrap();
    let late = f.prepare(6, b"catch-up-after-life").unwrap();
    assert_eq!(late.target().mantissa, 90);
    assert_eq!(late.delta().mantissa, 60);
    let proposal = late
        .proposal(f.template(6, b"catch-up-after-life"))
        .unwrap();
    f.h.post(posting(proposal)).unwrap();
    assert!(f.prepare(6, b"late-complete-noop").unwrap().is_noop());
    assert!(f.prepare(7, b"later-complete-noop").unwrap().is_noop());
    assert!(
        verify_asset_schedules(&f.h.db, &f.h.ctx(), &f.h.book)
            .unwrap()
            .is_green()
    );
}

#[test]
fn source_applications_are_refused_before_and_after_asset_schedule_registration() {
    let mut f = Fixture::new(AssetCostKind::Depreciation, 100, 0, 3);
    let application = |source: &EntryPayload, target: EntryRef, key: &[u8]| {
        let mut proposal = source.clone();
        proposal.idempotency_key = key.to_vec();
        for leg in &mut proposal.legs {
            leg.side = leg.side.flipped();
            leg.amount.mantissa = 10;
        }
        proposal.legs[0].settles = vec![Settlement {
            target,
            ordinal: 0,
            amount: Amount::new(source.legs[0].amount.unit, 10),
        }];
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        proposal
    };
    let before = f.h.db.frontier().unwrap();
    assert!(
        f.h.post(posting(application(
            &f.source,
            f.acquisition,
            b"governed-source-application"
        )))
        .is_err()
    );
    assert_eq!(f.h.db.frontier().unwrap(), before);
    let mut source = f.source.clone();
    source.idempotency_key = b"applied-before-schedule-source".to_vec();
    let reference = f.h.post(posting(source.clone())).unwrap().entry_ref();
    f.h.post(posting(application(
        &source,
        reference,
        b"earlier-application",
    )))
    .unwrap();
    let mut spec = f.schedule.spec.clone();
    spec.name = "already-applied".into();
    spec.acquisition = reference;
    let request = AssetScheduleRequest {
        principal: PRINCIPAL,
        spec,
        effective_date: f.h.day(),
        idempotency_key: b"applied-source-schedule".to_vec(),
        description: source.description,
        approvals: vec![],
    };
    let cx = f.h.ctx();
    let schema = Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap();
    assert!(
        f.h.runtime
            .block_on(create_asset_schedule(
                &mut f.h.db,
                &cx,
                &f.h.book,
                &schema,
                request
            ))
            .unwrap()
            .is_err()
    );
}

#[test]
fn a_missing_source_projection_is_corruption_not_an_unguarded_asset() {
    let mut f = Fixture::new(AssetCostKind::Depreciation, 100, 0, 3);
    let guard =
        f.h.db
            .vertices()
            .unwrap()
            .into_iter()
            .find(|row| {
                row.labels
                    .contains(&fa_model::symbols::label::ASSET_SCHEDULE)
            })
            .unwrap()
            .vid;
    let cx = f.h.ctx();
    let mut txn = f.h.db.begin(&cx.txn()).unwrap();
    let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
    damage.delete_vertex(guard);
    txn.write(&mut f.h.db, damage).unwrap();
    f.h.runtime
        .block_on(txn.commit(&mut f.h.db, &cx.commit()))
        .unwrap();
    assert!(verify_asset_schedules(&f.h.db, &cx, &f.h.book).is_err());
    assert!(fa_journal::chart::read_at(&f.h.db, &f.h.book, f.h.db.frontier().unwrap()).is_err());
}

#[test]
fn duplicate_immutable_terms_wrong_kind_wrong_digest_and_unauthorized_reads_refuse() {
    let mut f = Fixture::new(AssetCostKind::Depreciation, 100, 0, 3);
    let cx = f.h.ctx();
    let before = f.h.db.frontier().unwrap();
    let mut spec = f.schedule.spec.clone();
    spec.name = "renamed-same-acquisition".into();
    let schema = Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap();
    let request = AssetScheduleRequest {
        principal: PRINCIPAL,
        spec,
        effective_date: f.h.day(),
        idempotency_key: b"duplicate-schedule".to_vec(),
        description: f.source.description.clone(),
        approvals: vec![],
    };
    assert!(
        f.h.runtime
            .block_on(create_asset_schedule(
                &mut f.h.db,
                &cx,
                &f.h.book,
                &schema,
                request
            ))
            .unwrap()
            .is_err()
    );
    let template = f.template(3, b"wrong-kind");
    let mut request = AssetChargeRequest {
        schedule: f.schedule.entry,
        through_period: template.effective_period.clone().unwrap(),
        kind: AssetCostKind::Amortization,
    };
    assert!(
        prepare_asset_charge(&f.h.db, &cx, &f.h.book, &cap(), &request, &template)
            .unwrap()
            .is_err()
    );
    request.kind = AssetCostKind::Depreciation;
    request.schedule.entry_digest[0] ^= 1;
    assert!(
        prepare_asset_charge(&f.h.db, &cx, &f.h.book, &cap(), &request, &template)
            .unwrap()
            .is_err()
    );
    assert!(
        asset_schedules(
            &f.h.db,
            &cx,
            &f.h.book,
            &Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
            before
        )
        .unwrap()
        .is_err()
    );
    assert_eq!(f.h.db.frontier().unwrap(), before);
}

#[test]
fn read_only_asset_register_reports_cost_salvage_and_all_recorded_recognition() {
    let mut f = Fixture::new(AssetCostKind::Depreciation, 107, 7, 3);
    let read = Capability::embedded(PRINCIPAL, &["read"]).unwrap();
    let registered_at = f.h.db.frontier().unwrap();
    let initial = asset_register(&f.h.db, &f.h.ctx(), &f.h.book, &read, registered_at)
        .unwrap()
        .unwrap();
    assert_eq!(initial.known_at, registered_at);
    assert_eq!(initial.rows.len(), 1);
    let row = &initial.rows[0];
    assert_eq!(row.schedule.entry, f.schedule.entry);
    assert_eq!(row.original_cost, Amount::new(f.h.usd, 107));
    assert!(row.source_live);
    assert_eq!(row.recognized.mantissa, 0);
    assert_eq!(row.carrying_amount.mantissa, 107);
    assert_eq!(row.remaining_depreciable.mantissa, 100);
    assert_eq!(row.covered_through, None);
    assert_eq!(f.h.db.frontier().unwrap(), registered_at);

    let first = f.proposal(3, b"register-march-charge");
    f.h.post(posting(first)).unwrap();
    let first_at = f.h.db.frontier().unwrap();
    let partial = asset_register(&f.h.db, &f.h.ctx(), &f.h.book, &read, first_at)
        .unwrap()
        .unwrap();
    let row = &partial.rows[0];
    assert_eq!(row.recognized.mantissa, 33);
    assert_eq!(row.carrying_amount.mantissa, 74);
    assert_eq!(row.remaining_depreciable.mantissa, 67);
    assert_eq!(row.covered_through.as_ref().unwrap().code, "FY2026-P03");

    // Recording the May catch-up changes HEAD regardless of its effective
    // date. The explicit older recorded prefix retains the March numbers.
    let complete = f.proposal(5, b"register-may-catchup");
    f.h.post(posting(complete)).unwrap();
    let completed_at = f.h.db.frontier().unwrap();
    let completed = asset_register(&f.h.db, &f.h.ctx(), &f.h.book, &read, completed_at)
        .unwrap()
        .unwrap();
    let row = &completed.rows[0];
    assert!(row.source_live);
    assert_eq!(row.recognized.mantissa, 100);
    assert_eq!(row.carrying_amount.mantissa, 7);
    assert_eq!(row.remaining_depreciable.mantissa, 0);
    assert_eq!(row.covered_through.as_ref().unwrap().code, "FY2026-P05");
    assert_eq!(
        asset_register(&f.h.db, &f.h.ctx(), &f.h.book, &read, first_at)
            .unwrap()
            .unwrap(),
        partial
    );
    assert_eq!(
        asset_register(&f.h.db, &f.h.ctx(), &f.h.book, &read, registered_at)
            .unwrap()
            .unwrap(),
        initial
    );
    assert_eq!(f.h.db.frontier().unwrap(), completed_at);
}

#[test]
fn asset_register_preserves_cost_and_coverage_when_acquisition_is_reversed() {
    let mut f = Fixture::new(AssetCostKind::Amortization, 107, 7, 3);
    let read = Capability::embedded(PRINCIPAL, &["read"]).unwrap();
    let charge = f.proposal(4, b"register-charge-before-undo");
    let target = f.h.post(posting(charge.clone())).unwrap().entry_ref();
    let charged_at = f.h.db.frontier().unwrap();
    let charged = asset_register(&f.h.db, &f.h.ctx(), &f.h.book, &read, charged_at)
        .unwrap()
        .unwrap();
    assert_eq!(charged.rows[0].recognized.mantissa, 67);
    assert_eq!(charged.rows[0].carrying_amount.mantissa, 40);
    assert_eq!(charged.rows[0].remaining_depreciable.mantissa, 33);
    f.h.post(posting(undo(&charge, target, b"register-undo-charge")))
        .unwrap();
    let restored_at = f.h.db.frontier().unwrap();
    let restored = asset_register(&f.h.db, &f.h.ctx(), &f.h.book, &read, restored_at)
        .unwrap()
        .unwrap();
    assert!(restored.rows[0].source_live);
    assert_eq!(restored.rows[0].recognized.mantissa, 0);
    assert_eq!(restored.rows[0].carrying_amount.mantissa, 107);
    assert_eq!(restored.rows[0].remaining_depreciable.mantissa, 100);
    assert_eq!(
        restored.rows[0].covered_through.as_ref().unwrap().code,
        "FY2026-P04"
    );

    f.h.post(posting(undo(
        &f.source,
        f.acquisition,
        b"register-undo-source",
    )))
    .unwrap();
    let removed_at = f.h.db.frontier().unwrap();
    let removed = asset_register(&f.h.db, &f.h.ctx(), &f.h.book, &read, removed_at)
        .unwrap()
        .unwrap();
    let row = &removed.rows[0];
    assert!(!row.source_live);
    assert_eq!(row.original_cost.mantissa, 107);
    assert_eq!(row.recognized.mantissa, 0);
    assert_eq!(row.carrying_amount, Amount::new(f.h.usd, 0));
    assert_eq!(row.remaining_depreciable, Amount::new(f.h.usd, 0));
    assert_eq!(row.covered_through.as_ref().unwrap().code, "FY2026-P04");
    assert_eq!(
        asset_register(&f.h.db, &f.h.ctx(), &f.h.book, &read, charged_at)
            .unwrap()
            .unwrap(),
        charged
    );
    assert_eq!(f.h.db.frontier().unwrap(), removed_at);
}

#[test]
fn historical_asset_register_requires_current_read_authority_and_respects_pins() {
    let mut f = Fixture::new(AssetCostKind::Depreciation, 100, 0, 3);
    let pin = f.h.db.frontier().unwrap();
    let read = Capability::embedded(PRINCIPAL, &["read"]).unwrap();
    let pinned = read.clone().known_at_most(pin);
    let expected = asset_register(&f.h.db, &f.h.ctx(), &f.h.book, &pinned, pin)
        .unwrap()
        .unwrap();
    let charge = f.proposal(3, b"register-after-reader-pin");
    f.h.post(posting(charge)).unwrap();
    let head = f.h.db.frontier().unwrap();
    assert_eq!(
        asset_register(&f.h.db, &f.h.ctx(), &f.h.book, &pinned, pin)
            .unwrap()
            .unwrap(),
        expected
    );
    assert_eq!(
        asset_register(&f.h.db, &f.h.ctx(), &f.h.book, &pinned, head)
            .unwrap()
            .unwrap_err()
            .exit,
        7
    );
    let expired = read.clone().expiring_at(pin);
    assert_eq!(
        asset_register(&f.h.db, &f.h.ctx(), &f.h.book, &expired, pin)
            .unwrap()
            .unwrap_err()
            .exit,
        7
    );
    let no_read = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    assert_eq!(
        asset_register(&f.h.db, &f.h.ctx(), &f.h.book, &no_read, pin)
            .unwrap()
            .unwrap_err()
            .exit,
        7
    );
    assert!(
        asset_register(
            &f.h.db,
            &f.h.ctx(),
            &f.h.book,
            &read,
            fgdb_types::CommitSeq(head.0 + 1)
        )
        .unwrap()
        .is_err()
    );
    assert_eq!(f.h.db.frontier().unwrap(), head);
}

#[test]
fn asset_register_has_stable_name_order_and_does_not_leak_future_schedules() {
    let mut f = Fixture::new(AssetCostKind::Depreciation, 100, 0, 3);
    let pin = f.h.db.frontier().unwrap();
    let mut source = f.source.clone();
    source.idempotency_key = b"register-second-source".to_vec();
    let acquisition = f.h.post(posting(source.clone())).unwrap().entry_ref();
    let mut spec = f.schedule.spec.clone();
    spec.name = "alpha-intangible".into();
    spec.kind = AssetCostKind::Amortization;
    spec.acquisition = acquisition;
    let request = AssetScheduleRequest {
        principal: PRINCIPAL,
        spec,
        effective_date: f.h.day(),
        idempotency_key: b"register-second-schedule".to_vec(),
        description: source.description,
        approvals: vec![],
    };
    let schema = Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap();
    let cx = f.h.ctx();
    f.h.runtime
        .block_on(create_asset_schedule(
            &mut f.h.db,
            &cx,
            &f.h.book,
            &schema,
            request,
        ))
        .unwrap()
        .unwrap();
    let read = Capability::embedded(PRINCIPAL, &["read"]).unwrap();
    let head = f.h.db.frontier().unwrap();
    let register = asset_register(&f.h.db, &cx, &f.h.book, &read, head)
        .unwrap()
        .unwrap();
    assert_eq!(
        register
            .rows
            .iter()
            .map(|row| row.schedule.spec.name.as_str())
            .collect::<Vec<_>>(),
        ["alpha-intangible", "press"]
    );
    let historical = asset_register(&f.h.db, &cx, &f.h.book, &read, pin)
        .unwrap()
        .unwrap();
    assert_eq!(historical.rows.len(), 1);
    assert_eq!(historical.rows[0].schedule.spec.name, "press");
    assert_eq!(f.h.db.frontier().unwrap(), head);
}
