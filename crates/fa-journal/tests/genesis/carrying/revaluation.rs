//! Independently allocated carrying values must close both the original source
//! and its valuation leaf, including rounded applications and exact undos.

use super::*;
use fa_journal::chart::{
    FxRevaluationRoute, FxRevaluationRoutesRequest, set_fx_revaluation_routes,
};
use fa_journal::revaluation::{FxRevaluationRequest, prepare_fx_revaluation};
use fa_reference::fx::{
    OracleRevaluedCarrying, allocate_revalued_carrying, remaining_revalued_carrying_relief,
};
use fgdb_types::CommitSeq;

#[path = "revaluation/audits.rs"]
mod audits;
#[path = "revaluation/differences.rs"]
mod differences;
#[path = "revaluation/scaling.rs"]
mod scaling;

#[test]
fn post_only_draft_allocated_group_admits_generated_valuation_releases() {
    let mut f = RevaluedFixture::new(Side::Debit, &[(3, 3), (3, 3)]);
    let allocation = f.revaluation(13, 3, 3, true).unwrap();
    f.post_revaluation(allocation, b"draft-allocated-source");
    let name = "draft-allocated-settlement";
    let base_capability = Capability::new(
        AGENT,
        fa_policy::Profile::Agent,
        &[fa_policy::Op::Post],
        PRINCIPAL,
    )
    .unwrap()
    .on_branch(fa_model::draft_branch(f.f.h.book.book_id, name))
    .unwrap()
    .with_ceiling(f.f.foreign, 1)
    .unwrap();
    let limited = base_capability.clone().with_ceiling(f.f.h.usd, 2).unwrap();
    let permitted = base_capability.with_ceiling(f.f.h.usd, 3).unwrap();
    f.f.h.open_draft(limited.clone(), name).unwrap();
    let inputs = f
        .targets
        .iter()
        .map(|target| f.f.fx_request(*target, 1))
        .collect::<Vec<_>>();
    let mut template =
        f.f.h
            .proposal(vec![], b"draft-allocated-group", EntryClass::ORIGINAL);
    template.effective_date = day(4, 15);
    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
    let mut expected = fa_journal::carrying::prepare_fx_settlement_group(
        &f.f.h.db,
        &f.f.h.ctx(),
        &f.f.h.book,
        &Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
        &inputs,
        template.clone(),
        &mut budget,
    )
    .unwrap()
    .unwrap()
    .into_proposal();
    template.principal_ref = AGENT;
    expected.principal_ref = AGENT;
    assert_eq!(
        expected.base_totals.as_ref().unwrap().fx_law_oid,
        FxLawId::SettlementAllocatedCarrying.oid()
    );
    assert!(
        expected
            .legs
            .iter()
            .any(|leg| leg.account_ref == f.valuation && leg.amount.mantissa == 3)
    );
    let admission = fa_journal::draft::admit_sources(&f.f.h.db, &f.f.h.book, &limited, name)
        .unwrap()
        .unwrap();
    let cx = f.f.h.ctx();
    fa_journal::carrying::admit_draft_settlement_requests(
        &mut f.f.h.db,
        &cx,
        &f.f.h.book,
        &admission,
        &inputs,
        &template,
    )
    .unwrap()
    .expect("the declared 1 EUR / 2 USD effects fit before generated valuation releases");
    let prepare = |f: &mut RevaluedFixture, admission: &fa_journal::draft::DraftSourceAdmission| {
        let stripped = Cx::detached_cancel_context();
        let mut budget =
            ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
        let cx = f.f.h.ctx();
        fa_journal::carrying::prepare_fx_settlement_group_in_draft(
            &mut f.f.h.db,
            &cx,
            &f.f.h.book,
            admission,
            &inputs,
            template.clone(),
            &mut budget,
        )
        .unwrap()
    };
    let before = f.f.h.db.frontier().unwrap();
    let refused = prepare(&mut f, &admission).unwrap_err();
    assert_eq!(refused.exit, exit::SAFETY);
    assert!(refused.message.contains("ceiling"), "{refused}");
    assert_eq!(f.f.h.db.frontier().unwrap(), before);
    assert!(f.f.h.draft(name).intents.is_empty());
    let admission = fa_journal::draft::admit_sources(&f.f.h.db, &f.f.h.book, &permitted, name)
        .unwrap()
        .unwrap();
    let proposal = prepare(&mut f, &admission).unwrap();
    assert_eq!(proposal, expected);
    assert_eq!(f.functional_net(f.valuation), 20);
    assert_eq!(f.f.h.db.frontier().unwrap(), before);
    f.f.h.plan_draft(permitted, name, proposal).unwrap();
    assert_eq!(f.functional_net(f.valuation), 20);
    f.f.h.promote(f.f.h.approver_capability(), name).unwrap();
    assert_eq!(f.functional_net(f.valuation), 14);
    for target in &f.targets {
        assert_eq!(
            f.position(*target, None),
            OracleRevaluedCarrying {
                native: 2,
                historical_base: 2,
                carrying_base: 9
            }
        );
    }
    f.f.verify();
}

#[test]
fn post_only_draft_carrying_preserves_allocated_valuation_relief_and_revalidation() {
    for change_source in [false, true] {
        let mut f = RevaluedFixture::new(Side::Debit, &[(3, 10), (3, 10)]);
        let allocation = f.revaluation(13, 3, 3, true).unwrap();
        f.post_revaluation(allocation, b"confined-allocated-basis");
        let name = "confined-allocated-relief";
        let planner = Capability::new(
            AGENT,
            fa_policy::Profile::Agent,
            &[fa_policy::Op::Post],
            PRINCIPAL,
        )
        .unwrap()
        .on_branch(fa_model::draft_branch(f.f.h.book.book_id, name))
        .unwrap()
        .with_ceiling(f.f.foreign, 3)
        .unwrap()
        .with_ceiling(f.f.h.usd, 13)
        .unwrap();
        f.f.h.open_draft(planner.clone(), name).unwrap();
        let source = fa_journal::draft::admit_sources(&f.f.h.db, &f.f.h.book, &planner, name)
            .unwrap()
            .unwrap();
        let inputs = [
            f.f.fx_request(f.targets[0], 1),
            f.f.fx_request(f.targets[1], 3),
        ];
        let key = b"confined-allocated-group";
        let mut template = f.f.h.proposal(vec![], key, EntryClass::ORIGINAL);
        template.principal_ref = AGENT;
        template.effective_date = day(4, 15);
        let cx = f.f.h.ctx();
        let stripped = Cx::detached_cancel_context();
        let mut budget =
            ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
        let expected = prepare_fx_settlement_group(
            &f.f.h.db,
            &cx,
            &f.f.h.book,
            &Capability::embedded(AGENT, &["read", "post"]).unwrap(),
            &inputs,
            template.clone(),
            &mut budget,
        )
        .unwrap()
        .unwrap()
        .into_proposal();
        let head = f.f.h.db.frontier().unwrap();
        let proposal = fa_journal::carrying::prepare_fx_settlement_group_in_draft(
            &mut f.f.h.db,
            &cx,
            &f.f.h.book,
            &source,
            &inputs,
            template,
            &mut budget,
        )
        .unwrap()
        .unwrap();
        assert_eq!(proposal, expected);
        assert_eq!(
            proposal.base_totals.as_ref().unwrap().fx_law_oid,
            FxLawId::SettlementAllocatedCarrying.oid()
        );
        let (_, raw) = proposal
            .extensions
            .iter()
            .find(|(tag, _)| *tag == fa_model::entry::FX_SETTLEMENT_VALUATION_EXTENSION)
            .unwrap();
        let basis = fa_model::FxSettlementValuationBasis::decode(raw).unwrap();
        assert_eq!(basis.items.len(), 2);
        assert_eq!(basis.items[0].total_relief.mantissa, 4);
        assert_eq!(basis.items[1].total_relief.mantissa, 13);
        assert_eq!(f.f.h.db.frontier().unwrap(), head);
        let planned =
            f.f.h
                .plan_draft(planner.clone(), name, proposal.clone())
                .unwrap();
        let reviewed = planned.plan.unwrap().members()[0].entry.clone();
        if change_source {
            let changed = f.revaluation(5, 1, 3, true).unwrap();
            f.post_revaluation(changed, b"new-basis-before-confined-promotion");
            let head = f.f.h.db.frontier().unwrap();
            let rows = f.f.h.db.vertices().unwrap();
            assert!(f.f.h.promote(f.f.h.approver_capability(), name).is_err());
            assert_eq!(f.f.h.db.frontier().unwrap(), head);
            assert_eq!(f.f.h.db.vertices().unwrap(), rows);
            assert_eq!(f.f.h.draft(name).state, DraftState::Open);
        } else {
            let promoted = f.f.h.promote(f.f.h.approver_capability(), name).unwrap();
            assert_eq!(promoted.entries.len(), 1);
            assert_eq!(promoted.entries[0].entry_digest, reviewed.entry_digest);
            assert_eq!(
                read_entry(&f.f.h.db, promoted.entries[0].vid)
                    .unwrap()
                    .unwrap()
                    .0,
                reviewed
            );
            assert_eq!(
                f.position(f.targets[0], None),
                OracleRevaluedCarrying {
                    native: 2,
                    historical_base: 7,
                    carrying_base: 9,
                }
            );
            assert_eq!(f.position(f.targets[1], None).native, 0);
            assert_eq!(f.position(f.targets[1], None).carrying_base, 0);
            f.f.verify();
        }
    }
}

#[test]
fn mixed_fx_batches_protect_declared_valuation_leaves_before_any_revaluation() {
    for (fx_first, route_month) in [(false, 3), (true, 3), (false, 4), (true, 4)] {
        let mut f = RevaluedFixture::with_routes_from(Side::Debit, &[(3, 10)], day(route_month, 1));
        let target = f.targets[0];
        let fx = f
            .prepare(target, 1, day(3, 15), b"mixed-routed-fx")
            .unwrap()
            .into_proposal();
        assert!(fx.legs.iter().all(|leg| leg.account_ref != f.valuation));
        let mut legs = f.f.h.rent_legs(1);
        legs[0].account_ref = f.valuation;
        let plain =
            f.f.h
                .proposal(legs, b"mixed-valuation-leg", EntryClass::ORIGINAL);
        let members = if fx_first {
            vec![fx.clone(), plain]
        } else {
            vec![plain, fx.clone()]
        };
        let batch = f.f.h.batch(b"mixed-valuation-dependency", members);
        let before = f.f.h.db.frontier().unwrap();
        let rows = f.f.h.db.vertices().unwrap();
        let refusal = f.f.post_fx_batch(batch).unwrap_err();
        assert_eq!(refusal.code, "FA-REF-071");
        assert!(refusal.message.contains("source or valuation account"));
        assert_eq!(f.f.h.db.frontier().unwrap(), before);
        assert_eq!(f.f.h.db.vertices().unwrap(), rows);
        assert_eq!(f.position(target, None).carrying_base, 10);

        // The same native amount on an independent expense account is
        // admissible; sharing the settlement's cash account is safe.
        let plain = f.f.h.proposal(
            f.f.h.rent_legs(1),
            b"mixed-valuation-leg",
            EntryClass::ORIGINAL,
        );
        let members = if fx_first {
            vec![fx, plain]
        } else {
            vec![plain, fx]
        };
        let batch = f.f.h.batch(b"mixed-valuation-dependency", members);
        let posted = f.f.post_fx_batch(batch).unwrap();
        assert_eq!(posted.recorded_at.0, before.0 + 1);
        assert_eq!(f.position(target, None).carrying_base, 7);
        f.f.verify();
    }
}

#[test]
fn fx_batch_offsets_cannot_post_into_another_members_dedicated_valuation_leaf() {
    for offset_first in [false, true] {
        let mut f = RevaluedFixture::new(Side::Debit, &[(3, 10)]);
        let target = f.targets[0];
        let mut offset_request = f.f.fx_request(f.f.target, 1);
        offset_request.settlement_account = f.valuation;
        let stripped = Cx::detached_cancel_context();
        let mut budget =
            ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
        let offset = prepare_fx_settlement(
            &f.f.h.db,
            &f.f.h.ctx(),
            &f.f.h.book,
            &Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
            &offset_request,
            f.f.h
                .proposal(vec![], b"valuation-offset-fx", EntryClass::ORIGINAL),
            &mut budget,
        )
        .unwrap()
        .unwrap()
        .into_proposal();
        let other = f
            .prepare(target, 1, day(3, 15), b"protected-routed-fx")
            .unwrap()
            .into_proposal();
        assert_ne!(
            offset.legs[0].settles[0].target,
            other.legs[0].settles[0].target
        );
        let members = if offset_first {
            vec![offset, other.clone()]
        } else {
            vec![other.clone(), offset]
        };
        let batch = f.f.h.batch(b"cross-source-valuation-offset", members);
        let before = f.f.h.db.frontier().unwrap();
        let rows = f.f.h.db.vertices().unwrap();
        let refusal = f.f.post_fx_batch(batch).unwrap_err();
        assert_eq!(refusal.code, "FA-REF-071");
        assert!(refusal.message.contains("source or valuation account"));
        assert_eq!(f.f.h.db.frontier().unwrap(), before);
        assert_eq!(f.f.h.db.vertices().unwrap(), rows);
        assert_eq!(f.position(target, None).carrying_base, 10);
        assert_eq!(f.f.carrying().open_base.mantissa, 1);

        let independent = f.f.prepare(1, b"valuation-offset-fx").into_proposal();
        let members = if offset_first {
            vec![independent, other]
        } else {
            vec![other, independent]
        };
        let batch = f.f.h.batch(b"cross-source-valuation-offset", members);
        let posted = f.f.post_fx_batch(batch).unwrap();
        assert_eq!(posted.recorded_at.0, before.0 + 1);
        assert_eq!(f.position(target, None).carrying_base, 7);
        assert_eq!(f.f.carrying().open_base.mantissa, 0);
        f.f.verify();
    }
}

#[test]
fn mixed_fx_batches_preserve_exact_allocated_releases_for_shared_valuation_leaves() {
    for include_native in [false, true] {
        let mut f = RevaluedFixture::new(Side::Debit, &[(3, 10), (3, 10)]);
        let allocation = f.revaluation(13, 3, 3, true).unwrap();
        f.post_revaluation(allocation, b"batch-allocated-revaluation");
        let first = f
            .prepare(f.targets[0], 1, day(4, 15), b"batch-first-allocated-fx")
            .unwrap()
            .into_proposal();
        let second = f
            .prepare(f.targets[1], 1, day(4, 15), b"batch-second-allocated-fx")
            .unwrap()
            .into_proposal();
        assert!(first.legs.iter().any(|leg| leg.account_ref == f.valuation));
        assert!(second.legs.iter().any(|leg| leg.account_ref == f.valuation));
        let mut members = vec![first];
        if include_native {
            let mut plain = f.f.h.proposal(
                f.f.h.rent_legs(1),
                b"batch-independent-allocated-companion",
                EntryClass::ORIGINAL,
            );
            plain.effective_date = day(4, 15);
            members.push(plain);
        }
        members.push(second);
        let batch = f.f.h.batch(b"batch-shared-allocated-valuation", members);
        let before = f.f.h.db.frontier().unwrap();
        assert_eq!(f.functional_net(f.valuation), 6);
        let posted = f.f.post_fx_batch(batch.clone()).unwrap();
        assert_eq!(posted.recorded_at.0, before.0 + 1);
        assert_eq!(posted.entries.len(), if include_native { 3 } else { 2 });
        for target in &f.targets {
            assert_eq!(
                f.position(*target, None),
                OracleRevaluedCarrying {
                    native: 2,
                    historical_base: 7,
                    carrying_base: 9,
                }
            );
        }
        assert_eq!(f.functional_net(f.valuation), 4);
        f.f.verify();
        let rows = f.f.h.db.vertices().unwrap();
        let retried = f.f.post_fx_batch(batch).unwrap();
        assert_eq!(retried.entries, posted.entries);
        assert_eq!(retried.recorded_at, posted.recorded_at);
        assert_eq!(f.f.h.db.frontier().unwrap(), posted.recorded_at);
        assert_eq!(f.f.h.db.vertices().unwrap(), rows);
    }
}

fn day(month: u8, value: u8) -> DateDay {
    DateDay::from_ymd(2026, month, value).unwrap()
}

struct RevaluedFixture {
    f: Fixture,
    source: VId,
    valuation: VId,
    unrealized: VId,
    targets: Vec<EntryRef>,
}

impl RevaluedFixture {
    fn new(side: Side, items: &[(i128, i128)]) -> Self {
        Self::with_routes_from(side, items, day(3, 1))
    }

    fn with_routes_from(side: Side, items: &[(i128, i128)], routes_from: DateDay) -> Self {
        // The existing fixture's unrelated invoice exercises isolation: the
        // allocated population is the declared Single(EUR) source below.
        let mut f = fixture(1, 1);
        let kind = if side == Side::Debit {
            fa_model::AccountType::ASSET
        } else {
            fa_model::AccountType::LIABILITY
        };
        let accounts = [
            ("1212", "Allocated foreign source", kind, f.foreign),
            ("1292", "Allocated valuation", kind, f.h.usd),
            (
                "7092",
                "Allocated unrealized FX",
                fa_model::AccountType::REVENUE,
                f.h.usd,
            ),
        ]
        .into_iter()
        .map(|(code, name, kind, unit)| AccountSpec {
            code: code.into(),
            name: name.into(),
            account_type: kind.0,
            normal_balance: u8::from(matches!(
                kind,
                fa_model::AccountType::LIABILITY | fa_model::AccountType::REVENUE
            )),
            is_leaf: true,
            unit_policy: UnitPolicy::Single(unit),
            parent_code: None,
            limit: None,
        })
        .collect::<Vec<_>>();
        let cx = f.h.ctx();
        let description =
            f.h.proposal(vec![], b"allocated-chart", EntryClass::ORIGINAL)
                .description;
        f.h.runtime
            .block_on(install_chart(
                &mut f.h.db,
                &cx,
                &f.h.book,
                &accounts,
                PRINCIPAL,
                day(3, 1),
                b"allocated-chart",
                description.clone(),
                &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        let source = account_vid(f.h.book.book_id, "1212");
        let valuation = account_vid(f.h.book.book_id, "1292");
        let unrealized = account_vid(f.h.book.book_id, "7092");
        f.h.runtime
            .block_on(set_fx_revaluation_routes(
                &mut f.h.db,
                &cx,
                &f.h.book,
                &Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap(),
                FxRevaluationRoutesRequest {
                    principal: PRINCIPAL,
                    effective_from: routes_from,
                    routes: [(
                        source,
                        FxRevaluationRoute {
                            valuation_account: valuation,
                            unrealized_account: unrealized,
                        },
                    )]
                    .into(),
                    idempotency_key: b"allocated-routes".to_vec(),
                    description,
                },
            ))
            .unwrap()
            .unwrap();
        let april = f.h.april.clone();
        f.h.transition(&april, PeriodTransition::Open, b"allocated-open-april")
            .unwrap();
        f.h.transition("FY2026-P05", PeriodTransition::Open, b"allocated-open-may")
            .unwrap();
        let mut fixture = Self {
            f,
            source,
            valuation,
            unrealized,
            targets: Vec::new(),
        };
        for (index, &(native, base)) in items.iter().enumerate() {
            let target = fixture.invoice(
                native,
                base,
                side,
                format!("allocated-invoice-{index}").as_bytes(),
            );
            fixture.targets.push(target);
        }
        fixture
    }

    fn rate(
        &mut self,
        numerator: u128,
        denominator: u128,
        date: DateDay,
        purpose: FxRatePurpose,
    ) -> FxRateDocument {
        let rate = FxRateDocument::new(
            FxRateTerms {
                base_unit: self.f.h.usd,
                quote_unit: self.f.foreign,
                rate_num: numerator,
                rate_den: denominator,
                rounding: RoundingLaw::HalfEven,
            },
            date,
            1_700_000_000_000_000_100,
            purpose,
            "Independent carrying fixture quote",
        )
        .unwrap();
        self.f
            .h
            .add_document(
                &rate
                    .document(self.f.h.book.book_id, PRINCIPAL, HUMAN_UPLOAD)
                    .unwrap(),
            )
            .unwrap();
        rate
    }

    fn invoice(&mut self, native: i128, base: i128, side: Side, key: &[u8]) -> EntryRef {
        let (numerator, denominator) = if base == 0 {
            (1, native.checked_mul(4).unwrap())
        } else {
            (base, native)
        };
        let rate = self.rate(
            u128::try_from(numerator).unwrap(),
            u128::try_from(denominator).unwrap(),
            day(3, 15),
            FxRatePurpose::SpotClose,
        );
        let counterpart = account_vid(self.f.h.book.book_id, "4011");
        let proposal = self.f.h.proposal(
            vec![
                LegPayload::simple(side, self.source, Amount::new(self.f.foreign, native)),
                LegPayload::simple(
                    side.flipped(),
                    counterpart,
                    Amount::new(self.f.foreign, native),
                ),
            ],
            key,
            EntryClass::ORIGINAL,
        );
        let stripped = Cx::detached_cancel_context();
        let mut budget =
            ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
        let spec = fa_journal::genesis::read_book_spec(&self.f.h.db)
            .unwrap()
            .unwrap();
        let proposal = value_proposal(
            &mut budget,
            proposal,
            &spec,
            &self.f.h.book.units,
            FxLawId::SpotClose,
            &[rate],
        )
        .unwrap();
        self.f.h.post(request(proposal)).unwrap().entry_ref()
    }

    fn revaluation(
        &mut self,
        numerator: u128,
        denominator: u128,
        month: u8,
        allocated: bool,
    ) -> Result<PreparedFxRevaluation, Refusal> {
        let (date, period) = if month == 3 {
            (day(3, 31), self.f.h.march.clone())
        } else {
            (day(4, 30), self.f.h.april.clone())
        };
        let rate = self.rate(numerator, denominator, date, FxRatePurpose::PeriodClose);
        let request = FxRevaluationRequest {
            period,
            source_account: self.source,
            rate_document: rate
                .evidence_ref(self.f.h.book.book_id)
                .unwrap()
                .document_oid,
            entity: None,
            item_allocation: allocated,
        };
        let stripped = Cx::detached_cancel_context();
        let mut budget =
            ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
        prepare_fx_revaluation(
            &self.f.h.db,
            &self.f.h.ctx(),
            &self.f.h.book,
            &Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
            &request,
            &mut budget,
        )
        .unwrap()
    }

    fn post_revaluation(&mut self, prepared: PreparedFxRevaluation, key: &[u8]) -> Posted {
        let mut template = self.f.h.proposal(vec![], key, EntryClass::REVALUATION);
        template.effective_date = prepared.closing_date();
        template.effective_period = Some(fa_model::PeriodRef {
            calendar: self.f.h.book.calendar.id.clone(),
            code: prepared.request().period.clone(),
        });
        let proposal = prepared.proposal(template).unwrap();
        self.f.h.post(request(proposal)).unwrap()
    }

    fn prepare(
        &self,
        target: EntryRef,
        native: i128,
        date: DateDay,
        key: &[u8],
    ) -> Result<PreparedFxSettlement, Refusal> {
        let request = self.f.fx_request(target, native);
        let mut template = self.f.h.proposal(vec![], key, EntryClass::ORIGINAL);
        template.effective_date = date;
        let stripped = Cx::detached_cancel_context();
        let mut budget =
            ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
        prepare_fx_settlement(
            &self.f.h.db,
            &self.f.h.ctx(),
            &self.f.h.book,
            &Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
            &request,
            template,
            &mut budget,
        )
        .unwrap()
    }

    fn position(&self, target: EntryRef, at: Option<CommitSeq>) -> OracleRevaluedCarrying {
        let item = open_item_carrying_at(
            &self.f.h.db,
            &self.f.h.ctx(),
            &self.f.h.book,
            target,
            0,
            at.unwrap_or_else(|| self.f.h.db.frontier().unwrap()),
        )
        .unwrap()
        .unwrap();
        OracleRevaluedCarrying {
            native: item.open_native.mantissa,
            historical_base: item.historical_open_base.mantissa,
            carrying_base: item.open_base.mantissa,
        }
    }

    fn functional_net(&self, account: VId) -> i128 {
        let mut sum = fa_reference::Int::zero();
        for row in self.f.h.db.vertices().unwrap() {
            if !row.labels.contains(&fa_model::symbols::label::ENTRY) {
                continue;
            }
            let (entry, _) = read_entry(&self.f.h.db, row.vid).unwrap().unwrap();
            for leg in entry
                .proposal
                .legs
                .iter()
                .filter(|leg| leg.account_ref == account)
            {
                let amount =
                    fa_reference::Int::from_i128(leg.base_amount.unwrap_or(leg.amount).mantissa);
                sum = if leg.side == Side::Debit {
                    sum.add(&amount)
                } else {
                    sum.sub(&amount)
                };
            }
        }
        sum.to_i128().unwrap()
    }
}

#[test]
fn allocated_revaluation_and_settlement_match_independent_rounding_and_close_every_account() {
    for side in [Side::Debit, Side::Credit] {
        for (native, historical, target) in
            [(3, 10, 13), (3, 10, 1), (2, 1, 3), (2, 3, 1), (2, 1, 0)]
        {
            let mut f = RevaluedFixture::new(side, &[(native, historical)]);
            let item = f.targets[0];
            let original_at = f.f.h.db.frontier().unwrap();
            let (numerator, denominator) = if target == 0 {
                (1, native.checked_mul(4).unwrap())
            } else {
                (target, native)
            };
            let revaluation = f
                .revaluation(
                    u128::try_from(numerator).unwrap(),
                    u128::try_from(denominator).unwrap(),
                    3,
                    true,
                )
                .unwrap();
            assert!(!revaluation.is_noop());
            f.post_revaluation(revaluation, b"allocate-for-settlement");
            let mut expected =
                allocate_revalued_carrying(target, &[(native, historical)]).unwrap()[0];
            assert_eq!(f.position(item, None), expected);
            for ordinal in 0..native {
                let key = format!("allocated-application-{ordinal}");
                let predicted = remaining_revalued_carrying_relief(expected, 1).unwrap();
                let prepared = f.prepare(item, 1, day(4, 15), key.as_bytes()).unwrap();
                assert_eq!(prepared.base_relief().mantissa, predicted.carrying_base);
                assert_eq!(
                    prepared.historical_base_relief().mantissa,
                    predicted.historical_base
                );
                let proposal = prepared.into_proposal();
                assert_eq!(
                    proposal.legs[0].base_amount.unwrap().mantissa,
                    predicted.historical_base
                );
                f.f.h.post(request(proposal.clone())).unwrap();
                expected.native = expected.native.checked_sub(predicted.native).unwrap();
                expected.historical_base = expected
                    .historical_base
                    .checked_sub(predicted.historical_base)
                    .unwrap();
                expected.carrying_base = expected
                    .carrying_base
                    .checked_sub(predicted.carrying_base)
                    .unwrap();
                assert_eq!(f.position(item, None), expected);
                assert!(matches!(
                    f.f.h.post(request(proposal)).unwrap(),
                    Posted::AlreadyRecorded { .. }
                ));
            }
            assert_eq!(
                expected,
                OracleRevaluedCarrying {
                    native: 0,
                    historical_base: 0,
                    carrying_base: 0
                }
            );
            for account in [f.source, f.valuation, f.unrealized, f.f.conversion] {
                assert_eq!(
                    f.functional_net(account),
                    0,
                    "source/valuation/unrealized/conversion must each clear"
                );
            }
            let gain = native
                .checked_mul(2)
                .unwrap()
                .checked_sub(historical)
                .unwrap();
            assert_eq!(
                f.functional_net(f.f.realized),
                if side == Side::Debit {
                    gain.checked_neg().unwrap()
                } else {
                    gain
                }
            );
            assert_eq!(
                f.position(item, Some(original_at)),
                OracleRevaluedCarrying {
                    native,
                    historical_base: historical,
                    carrying_base: historical
                }
            );
            f.f.verify();
        }
    }
}

#[test]
fn item_allocation_preserves_rounding_ties_and_posts_zero_net_redistribution() {
    let mut f = RevaluedFixture::new(Side::Debit, &[(1, 1), (1, 1), (1, 1)]);
    let prepared = f.revaluation(2, 3, 3, true).unwrap();
    let allocation = prepared.basis().item_allocation.as_ref().unwrap();
    assert!(
        allocation
            .items
            .windows(2)
            .all(|pair| (pair[0].target.vid, pair[0].ordinal)
                < (pair[1].target.vid, pair[1].ordinal))
    );
    let expected = allocate_revalued_carrying(2, &[(1, 1), (1, 1), (1, 1)]).unwrap();
    assert_eq!(
        allocation
            .items
            .iter()
            .map(|item| item.target_base.mantissa)
            .collect::<Vec<_>>(),
        expected
            .iter()
            .map(|item| item.carrying_base)
            .collect::<Vec<_>>()
    );
    f.post_revaluation(prepared, b"ties-allocated");
    let mut targets = f.targets.clone();
    targets.sort_by_key(|target| target.vid);
    for (target, expected) in targets.into_iter().zip(expected) {
        assert_eq!(f.position(target, None), expected);
    }

    let mut zero = RevaluedFixture::new(Side::Debit, &[(1, 1), (1, 3)]);
    let prepared = zero.revaluation(2, 1, 3, true).unwrap();
    assert_eq!(prepared.delta().mantissa, 0);
    assert!(
        !prepared.is_noop(),
        "opposing item changes require real journal evidence"
    );
    assert_eq!(prepared.legs().len(), 4);
    let head = zero.f.h.db.frontier().unwrap();
    let recorded = zero.post_revaluation(prepared, b"zero-net-allocation");
    assert_eq!(recorded.recorded_at().0, head.0.checked_add(1).unwrap());
    for target in &zero.targets {
        assert_eq!(zero.position(*target, None).carrying_base, 2);
    }
    assert_eq!(zero.functional_net(zero.valuation), 0);
    let repeated = zero.revaluation(2, 1, 3, true).unwrap();
    assert!(repeated.is_noop());
    zero.f.verify();
}

#[test]
fn allocated_application_undo_restores_recorded_values_after_later_revaluation() {
    let mut f = RevaluedFixture::new(Side::Debit, &[(3, 10)]);
    let target = f.targets[0];
    let first = f.revaluation(13, 3, 3, true).unwrap();
    f.post_revaluation(first, b"first-item-valuation");
    let initial = f.position(target, None);
    let relief = remaining_revalued_carrying_relief(initial, 1).unwrap();
    let applied = f
        .prepare(target, 1, day(4, 15), b"allocated-before-rerevaluation")
        .unwrap()
        .into_proposal();
    let posted = f.f.h.post(request(applied.clone())).unwrap();
    let second = f.revaluation(3, 1, 4, true).unwrap();
    f.post_revaluation(second, b"second-item-valuation");
    let before_undo = f.position(target, None);
    assert_eq!(
        before_undo,
        OracleRevaluedCarrying {
            native: 2,
            historical_base: 7,
            carrying_base: 6
        }
    );
    assert_ne!(
        remaining_revalued_carrying_relief(before_undo, 1).unwrap(),
        relief
    );
    let mut reversed = undo(&applied, posted.entry_ref(), b"allocated-undo");
    reversed.effective_date = day(5, 1);
    f.f.h.post(request(reversed)).unwrap();
    assert_eq!(
        f.position(target, None),
        OracleRevaluedCarrying {
            native: 3,
            historical_base: 10,
            carrying_base: 10
        }
    );
    let final_application = f
        .prepare(target, 3, day(5, 2), b"allocated-after-undo")
        .unwrap()
        .into_proposal();
    f.f.h.post(request(final_application)).unwrap();
    for account in [f.source, f.valuation, f.unrealized, f.f.conversion] {
        assert_eq!(f.functional_net(account), 0);
    }
    f.f.verify();
}

#[test]
fn zero_historical_relief_remains_in_the_next_period_revaluation_source() {
    let mut f = RevaluedFixture::new(Side::Debit, &[(2, 1)]);
    let target = f.targets[0];
    let first = f.revaluation(3, 2, 3, true).unwrap();
    f.post_revaluation(first, b"round-zero-historical-first");
    let prepared = f
        .prepare(target, 1, day(4, 15), b"zero-historical-application")
        .unwrap();
    assert_eq!(prepared.historical_base_relief().mantissa, 0);
    assert_eq!(prepared.base_relief().mantissa, 2);
    f.f.h.post(request(prepared.into_proposal())).unwrap();
    assert_eq!(
        f.position(target, None),
        OracleRevaluedCarrying {
            native: 1,
            historical_base: 1,
            carrying_base: 1,
        }
    );
    let second = f.revaluation(2, 1, 4, true).unwrap();
    assert_eq!(second.source_base_net().mantissa, 1);
    f.post_revaluation(second, b"round-zero-historical-second");
    assert_eq!(
        f.position(target, None),
        OracleRevaluedCarrying {
            native: 1,
            historical_base: 1,
            carrying_base: 2,
        }
    );
    let final_application = f
        .prepare(target, 1, day(5, 2), b"zero-historical-final")
        .unwrap();
    f.f.h
        .post(request(final_application.into_proposal()))
        .unwrap();
    for account in [f.source, f.valuation, f.unrealized, f.f.conversion] {
        assert_eq!(f.functional_net(account), 0);
    }
    f.f.verify();
}

#[test]
fn balanced_false_valuation_release_and_stale_allocations_publish_nothing() {
    let mut f = RevaluedFixture::new(Side::Debit, &[(3, 10)]);
    let target = f.targets[0];
    let first = f.revaluation(13, 3, 3, true).unwrap();
    f.post_revaluation(first, b"tamper-item-valuation");
    let proposal = f
        .prepare(target, 1, day(4, 15), b"tampered-allocated-relief")
        .unwrap()
        .into_proposal();
    let release_tag = fa_model::entry::FX_SETTLEMENT_VALUATION_EXTENSION;
    let mut false_release = proposal.clone();
    let (_, raw) = false_release
        .extensions
        .iter_mut()
        .find(|(tag, _)| *tag == release_tag)
        .unwrap();
    let mut basis = fa_model::FxSettlementValuationBasis::decode(raw).unwrap();
    basis.items[0].total_relief.mantissa =
        basis.items[0].total_relief.mantissa.checked_add(1).unwrap();
    basis.items[0].valuation_relief.mantissa = basis.items[0]
        .valuation_relief
        .mantissa
        .checked_add(1)
        .unwrap();
    *raw = basis.canonical_bytes().unwrap();
    for leg in &mut false_release.legs {
        if leg.account_ref == f.valuation || leg.account_ref == f.unrealized {
            leg.amount.mantissa = leg.amount.mantissa.checked_add(1).unwrap();
            leg.base_amount = Some(leg.amount);
        }
    }
    false_release.unit_totals = EntryPayload::fold_unit_totals(&false_release.legs).unwrap();
    let totals = false_release.base_totals.as_mut().unwrap();
    totals.debits = totals.debits.checked_add(1).unwrap();
    totals.credits = totals.credits.checked_add(1).unwrap();
    false_release.validate().unwrap();
    let head = f.f.h.db.frontier().unwrap();
    let rows = f.f.h.db.vertices().unwrap();
    assert!(f.f.h.post(request(false_release)).is_err());
    assert_eq!(f.f.h.db.frontier().unwrap(), head);
    assert_eq!(f.f.h.db.vertices().unwrap(), rows);

    let mut false_source = proposal.clone();
    let (_, raw) = false_source
        .extensions
        .iter_mut()
        .find(|(tag, _)| *tag == release_tag)
        .unwrap();
    let mut basis = fa_model::FxSettlementValuationBasis::decode(raw).unwrap();
    basis.items[0].source_digest[0] ^= 1;
    *raw = basis.canonical_bytes().unwrap();
    assert!(f.f.h.post(request(false_source)).is_err());
    assert_eq!(f.f.h.db.frontier().unwrap(), head);
    assert_eq!(f.f.h.db.vertices().unwrap(), rows);

    // Changing the real source valuation invalidates the prepared application
    // even though its native amount and all of its account names still match.
    let second = f.revaluation(5, 1, 3, true).unwrap();
    f.post_revaluation(second, b"new-valuation-before-settlement");
    let head = f.f.h.db.frontier().unwrap();
    assert!(f.f.h.post(request(proposal)).is_err());
    assert_eq!(f.f.h.db.frontier().unwrap(), head);
    let fresh = f
        .prepare(target, 1, day(4, 15), b"tampered-allocated-relief")
        .unwrap();
    assert_eq!(fresh.base_relief().mantissa, 5);
    f.f.h.post(request(fresh.into_proposal())).unwrap();
    f.f.verify();
}

#[test]
fn allocated_markers_cannot_smuggle_unverified_ordinary_or_unbased_fx_entries() {
    let mut f = RevaluedFixture::new(Side::Debit, &[(3, 10)]);
    let target = f.targets[0];
    let prepared = f.revaluation(13, 3, 3, true).unwrap();
    let mut unbased =
        f.f.h
            .proposal(vec![], b"allocated-without-basis", EntryClass::REVALUATION);
    unbased.effective_date = prepared.closing_date();
    unbased.effective_period = Some(fa_model::PeriodRef {
        calendar: f.f.h.book.calendar.id.clone(),
        code: prepared.request().period.clone(),
    });
    let mut unbased = prepared.proposal(unbased).unwrap();
    let mut legacy_basis = unbased.clone();
    let raw = &mut legacy_basis
        .extensions
        .iter_mut()
        .find(|(tag, _)| *tag == fa_model::entry::FX_REVALUATION_EXTENSION)
        .unwrap()
        .1;
    let mut basis = fa_model::FxRevaluationBasis::decode(raw).unwrap();
    basis.item_allocation = None;
    *raw = basis.canonical_bytes().unwrap();
    let mut legacy_law = unbased.clone();
    legacy_law.base_totals.as_mut().unwrap().fx_law_oid = FxLawId::PeriodEndRevaluation.oid();
    unbased.extensions.clear();
    let head = f.f.h.db.frontier().unwrap();
    let rows = f.f.h.db.vertices().unwrap();
    for mismatched in [legacy_basis, legacy_law] {
        let refused = f.f.h.post(request(mismatched)).unwrap_err();
        assert!(
            refused
                .message
                .contains("item-allocation basis are required together")
        );
        assert_eq!(f.f.h.db.frontier().unwrap(), head);
        assert_eq!(f.f.h.db.vertices().unwrap(), rows);
    }
    assert!(f.f.h.post(request(unbased)).is_err());
    assert_eq!(f.f.h.db.frontier().unwrap(), head);
    assert_eq!(f.f.h.db.vertices().unwrap(), rows);

    f.post_revaluation(prepared, b"marker-bound-item-valuation");
    let settlement = f
        .prepare(target, 1, day(4, 15), b"marker-source")
        .unwrap()
        .into_proposal();
    let marker = settlement
        .extensions
        .iter()
        .find(|(tag, _)| *tag == fa_model::entry::FX_SETTLEMENT_VALUATION_EXTENSION)
        .unwrap()
        .clone();
    let (original, _) = read_entry(&f.f.h.db, target.vid).unwrap().unwrap();
    let mut ordinary = original.proposal;
    ordinary.idempotency_key = b"spot-close-with-release-marker".to_vec();
    ordinary.schema_minor = settlement.schema_minor;
    ordinary.extensions.push(marker.clone());
    let mut no_fx = f.f.h.proposal(
        f.f.h.rent_legs(1),
        b"native-with-release-marker",
        EntryClass::ORIGINAL,
    );
    no_fx.schema_minor = settlement.schema_minor;
    no_fx.extensions.push(marker);
    let mut wrong_law = settlement;
    wrong_law.idempotency_key = b"old-settlement-with-release-marker".to_vec();
    wrong_law.base_totals.as_mut().unwrap().fx_law_oid = FxLawId::SettlementCarryingBasis.oid();
    let head = f.f.h.db.frontier().unwrap();
    let rows = f.f.h.db.vertices().unwrap();
    for proposal in [ordinary, no_fx, wrong_law] {
        assert!(f.f.h.post(request(proposal)).is_err());
        assert_eq!(f.f.h.db.frontier().unwrap(), head);
        assert_eq!(f.f.h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn retained_self_consistent_item_allocation_must_reproduce_the_complete_source() {
    let mut f = RevaluedFixture::new(Side::Debit, &[(3, 10)]);
    let target = f.targets[0];
    let prepared = f.revaluation(13, 3, 3, true).unwrap();
    let mut template = f.f.h.proposal(
        vec![],
        b"forged-retained-allocation",
        EntryClass::REVALUATION,
    );
    template.effective_date = prepared.closing_date();
    template.effective_period = Some(fa_model::PeriodRef {
        calendar: f.f.h.book.calendar.id.clone(),
        code: prepared.request().period.clone(),
    });
    let mut proposal = prepared.proposal(template).unwrap();
    let raw = &mut proposal
        .extensions
        .iter_mut()
        .find(|(tag, _)| *tag == fa_model::entry::FX_REVALUATION_EXTENSION)
        .unwrap()
        .1;
    let mut basis = fa_model::FxRevaluationBasis::decode(raw).unwrap();
    basis.item_allocation.as_mut().unwrap().items[0]
        .target_base
        .mantissa = 14;
    *raw = basis.canonical_bytes().unwrap();
    for leg in &mut proposal.legs {
        leg.amount.mantissa = 4;
        leg.base_amount = Some(leg.amount);
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    let totals = proposal.base_totals.as_mut().unwrap();
    totals.debits = 4;
    totals.credits = 4;
    proposal.validate().unwrap();
    let entry = proposal.seal(vec![], None).unwrap();
    let vid = entry_vid(
        f.f.h.book.book_id,
        &PRINCIPAL.0.to_le_bytes(),
        b"forged-retained-allocation",
    );
    let before = f.f.h.db.frontier().unwrap();
    // Test-only substrate corruption creates a false but internally balanced,
    // canonically sealed record at its real native birth. It is neither a
    // digest bit flip nor a later edit detectable solely by immutability.
    let mut birth = fgdb::WriteBatch::new(relation::IN_BOOK);
    birth.create_vertex(
        vid,
        vec![fa_model::symbols::label::ENTRY],
        fa_model::entry_mirrors(&entry).unwrap(),
    );
    f.f.h.write_raw(birth);
    let head = f.f.h.db.frontier().unwrap();
    let rows = f.f.h.db.vertices().unwrap();
    fa_journal::entry_history::verify_entry_history(
        &f.f.h.db,
        &f.f.h.ctx(),
        &f.f.h.book,
        Some(head),
    )
    .unwrap();
    let denied = open_item_carrying_at(&f.f.h.db, &f.f.h.ctx(), &f.f.h.book, target, 0, head)
        .unwrap()
        .unwrap_err();
    assert!(denied.message.contains("does not reproduce"), "{denied:?}");
    assert!(
        f.prepare(target, 1, day(4, 15), b"cannot-use-forged-allocation")
            .is_err()
    );
    assert_eq!(f.f.h.db.frontier().unwrap(), head);
    assert_eq!(f.f.h.db.vertices().unwrap(), rows);
    assert_eq!(
        f.position(target, Some(before)),
        OracleRevaluedCarrying {
            native: 3,
            historical_base: 10,
            carrying_base: 10,
        }
    );
}

#[test]
fn allocated_population_refuses_mixed_sides_legacy_basis_and_orphaning_reversal() {
    let mut mixed = RevaluedFixture::new(Side::Debit, &[(3, 10)]);
    mixed.invoice(1, 2, Side::Credit, b"opposite-item");
    assert!(mixed.revaluation(2, 1, 3, true).is_err());

    let mut legacy = RevaluedFixture::new(Side::Debit, &[(3, 10)]);
    let revaluation = legacy.revaluation(13, 3, 3, false).unwrap();
    assert!(revaluation.basis().item_allocation.is_none());
    legacy.post_revaluation(revaluation, b"legacy-account-level-valuation");
    let head = legacy.f.h.db.frontier().unwrap();
    assert!(
        legacy
            .prepare(
                legacy.targets[0],
                1,
                day(4, 15),
                b"unsafe-legacy-application"
            )
            .is_err()
    );
    assert_eq!(legacy.f.h.db.frontier().unwrap(), head);

    let mut allocated = RevaluedFixture::new(Side::Debit, &[(3, 10)]);
    let target = allocated.targets[0];
    let revaluation = allocated.revaluation(13, 3, 3, true).unwrap();
    allocated.post_revaluation(revaluation, b"outstanding-item-valuation");
    let (original, _) = read_entry(&allocated.f.h.db, target.vid).unwrap().unwrap();
    let mut reversed = undo(&original.proposal, target, b"orphan-valuation");
    reversed.effective_date = day(4, 15);
    let head = allocated.f.h.db.frontier().unwrap();
    let rows = allocated.f.h.db.vertices().unwrap();
    assert!(allocated.f.h.post(request(reversed)).is_err());
    assert_eq!(allocated.f.h.db.frontier().unwrap(), head);
    assert_eq!(allocated.f.h.db.vertices().unwrap(), rows);
    assert_eq!(
        allocated.position(target, None),
        OracleRevaluedCarrying {
            native: 3,
            historical_base: 10,
            carrying_base: 13,
        }
    );
}

#[test]
fn disjoint_allocated_group_has_one_recorded_prefix_and_one_exact_undo() {
    let mut f = RevaluedFixture::new(Side::Debit, &[(3, 10), (3, 1)]);
    let first = f.revaluation(2, 1, 3, true).unwrap();
    f.post_revaluation(first, b"group-item-valuation");
    let positions = f
        .targets
        .iter()
        .map(|target| f.position(*target, None))
        .collect::<Vec<_>>();
    let inputs = f
        .targets
        .iter()
        .map(|target| f.f.fx_request(*target, 1))
        .collect::<Vec<_>>();
    let mut template =
        f.f.h
            .proposal(vec![], b"allocated-group", EntryClass::ORIGINAL);
    template.effective_date = day(4, 15);
    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
    let prepared = prepare_fx_settlement_group(
        &f.f.h.db,
        &f.f.h.ctx(),
        &f.f.h.book,
        &Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
        &inputs,
        template,
        &mut budget,
    )
    .unwrap()
    .unwrap();
    let expected = positions
        .iter()
        .map(|position| remaining_revalued_carrying_relief(*position, 1).unwrap())
        .collect::<Vec<_>>();
    for (item, expected) in prepared.items().iter().zip(&expected) {
        assert_eq!(item.base_relief.mantissa, expected.carrying_base);
    }
    let proposal = prepared.into_proposal();
    let raw = &proposal
        .extensions
        .iter()
        .find(|(tag, _)| *tag == fa_model::entry::FX_SETTLEMENT_VALUATION_EXTENSION)
        .unwrap()
        .1;
    let basis = fa_model::FxSettlementValuationBasis::decode(raw).unwrap();
    assert_eq!(basis.items.len(), 2);
    assert!(basis.items[0].applying_ordinal < basis.items[1].applying_ordinal);
    // Equal and opposite per-item errors preserve the aggregate release,
    // source balances and conversion neutrality. Each item still must prove
    // its own remaining-value calculation.
    assert_eq!(basis.items[0].valuation_relief.mantissa, -1);
    assert_eq!(basis.items[1].valuation_relief.mantissa, 2);
    let mut false_group = proposal.clone();
    let mut wrong_basis = basis.clone();
    for (item, delta) in wrong_basis.items.iter_mut().zip([-1, 1]) {
        item.total_relief.mantissa = item.total_relief.mantissa.checked_add(delta).unwrap();
        item.valuation_relief.mantissa = item.valuation_relief.mantissa.checked_add(delta).unwrap();
    }
    for leg in &mut false_group.legs {
        if leg.account_ref == f.valuation || leg.account_ref == f.unrealized {
            leg.amount.mantissa = leg.amount.mantissa.checked_add(1).unwrap();
            leg.base_amount = Some(leg.amount);
        }
    }
    let raw = &mut false_group
        .extensions
        .iter_mut()
        .find(|(tag, _)| *tag == fa_model::entry::FX_SETTLEMENT_VALUATION_EXTENSION)
        .unwrap()
        .1;
    *raw = wrong_basis.canonical_bytes().unwrap();
    false_group.unit_totals = EntryPayload::fold_unit_totals(&false_group.legs).unwrap();
    let totals = false_group.base_totals.as_mut().unwrap();
    totals.debits = totals.debits.checked_add(2).unwrap();
    totals.credits = totals.credits.checked_add(2).unwrap();
    false_group.validate().unwrap();
    let head = f.f.h.db.frontier().unwrap();
    let rows = f.f.h.db.vertices().unwrap();
    assert!(f.f.h.post(request(false_group)).is_err());
    assert_eq!(f.f.h.db.frontier().unwrap(), head);
    assert_eq!(f.f.h.db.vertices().unwrap(), rows);
    let posted = f.f.h.post(request(proposal.clone())).unwrap();
    assert_eq!(posted.recorded_at().0, head.0.checked_add(1).unwrap());
    for ((target, initial), release) in f.targets.iter().zip(&positions).zip(&expected) {
        assert_eq!(
            f.position(*target, None),
            OracleRevaluedCarrying {
                native: initial.native.checked_sub(release.native).unwrap(),
                historical_base: initial
                    .historical_base
                    .checked_sub(release.historical_base)
                    .unwrap(),
                carrying_base: initial
                    .carrying_base
                    .checked_sub(release.carrying_base)
                    .unwrap(),
            }
        );
    }
    let reversed = undo(&proposal, posted.entry_ref(), b"allocated-group-undo");
    let reversed_ref = f.f.h.post(request(reversed.clone())).unwrap().entry_ref();
    for (target, initial) in f.targets.iter().zip(&positions) {
        assert_eq!(f.position(*target, None), *initial);
    }
    // Reapply both original releases, including their opposite valuation
    // signs, as one authenticated ancestor rather than a newly priced group.
    let reapplied = undo(&reversed, reversed_ref, b"allocated-group-reapply");
    f.f.h.post(request(reapplied)).unwrap();
    for ((target, initial), release) in f.targets.iter().zip(&positions).zip(&expected) {
        assert_eq!(
            f.position(*target, None),
            OracleRevaluedCarrying {
                native: initial.native.checked_sub(release.native).unwrap(),
                historical_base: initial
                    .historical_base
                    .checked_sub(release.historical_base)
                    .unwrap(),
                carrying_base: initial
                    .carrying_base
                    .checked_sub(release.carrying_base)
                    .unwrap(),
            }
        );
    }
    assert_leg_projections(&f.f.h);
    f.f.verify();
}

#[test]
fn allocated_settlement_cannot_use_another_sources_valuation_leaf() {
    let mut f = RevaluedFixture::new(Side::Debit, &[(3, 10)]);
    let allocation = f.revaluation(13, 3, 3, true).unwrap();
    f.post_revaluation(allocation, b"cross-source-allocation");
    let accounts = [
        ("1213", fa_model::AccountType::ASSET, f.f.foreign),
        ("1293", fa_model::AccountType::ASSET, f.f.h.usd),
        ("7093", fa_model::AccountType::REVENUE, f.f.h.usd),
    ]
    .into_iter()
    .map(|(code, kind, unit)| AccountSpec {
        code: code.into(),
        name: code.into(),
        account_type: kind.0,
        normal_balance: u8::from(kind == fa_model::AccountType::REVENUE),
        is_leaf: true,
        unit_policy: UnitPolicy::Single(unit),
        parent_code: None,
        limit: None,
    })
    .collect::<Vec<_>>();
    let cx = f.f.h.ctx();
    let description =
        f.f.h
            .proposal(vec![], b"second-source-route", EntryClass::ORIGINAL)
            .description;
    f.f.h
        .runtime
        .block_on(install_chart(
            &mut f.f.h.db,
            &cx,
            &f.f.h.book,
            &accounts,
            PRINCIPAL,
            day(4, 1),
            b"second-source-chart",
            description.clone(),
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let second_source = account_vid(f.f.h.book.book_id, "1213");
    let second_valuation = account_vid(f.f.h.book.book_id, "1293");
    let second_unrealized = account_vid(f.f.h.book.book_id, "7093");
    let routes = [
        (
            f.source,
            FxRevaluationRoute {
                valuation_account: f.valuation,
                unrealized_account: f.unrealized,
            },
        ),
        (
            second_source,
            FxRevaluationRoute {
                valuation_account: second_valuation,
                unrealized_account: second_unrealized,
            },
        ),
    ]
    .into();
    f.f.h
        .runtime
        .block_on(set_fx_revaluation_routes(
            &mut f.f.h.db,
            &cx,
            &f.f.h.book,
            &Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap(),
            FxRevaluationRoutesRequest {
                principal: PRINCIPAL,
                effective_from: day(4, 1),
                routes,
                idempotency_key: b"second-source-routes".to_vec(),
                description,
            },
        ))
        .unwrap()
        .unwrap();
    let target = f.targets[0];
    for destination in ["cash", "conversion", "realized"] {
        let mut input = f.f.fx_request(target, 1);
        match destination {
            "cash" => input.settlement_account = second_valuation,
            "conversion" => input.conversion_account = second_valuation,
            "realized" => input.realized_fx_account = second_valuation,
            _ => unreachable!(),
        }
        let mut template = f.f.h.proposal(
            vec![],
            format!("cross-source-{destination}").as_bytes(),
            EntryClass::ORIGINAL,
        );
        template.effective_date = day(4, 15);
        let stripped = Cx::detached_cancel_context();
        let mut budget =
            ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
        let head = f.f.h.db.frontier().unwrap();
        let rows = f.f.h.db.vertices().unwrap();
        let prepared = prepare_fx_settlement(
            &f.f.h.db,
            &f.f.h.ctx(),
            &f.f.h.book,
            &Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
            &input,
            template,
            &mut budget,
        )
        .unwrap();
        if let Ok(prepared) = prepared {
            assert!(f.f.h.post(request(prepared.into_proposal())).is_err());
        }
        assert_eq!(f.f.h.db.frontier().unwrap(), head);
        assert_eq!(f.f.h.db.vertices().unwrap(), rows);
        assert_eq!(f.functional_net(second_valuation), 0);
    }
}

#[test]
fn allocated_reapplication_preserves_recorded_components_after_later_revaluation() {
    for side in [Side::Debit, Side::Credit] {
        for first_target in [6, 13] {
            let mut f = RevaluedFixture::new(side, &[(3, 10)]);
            let target = f.targets[0];
            let first = f.revaluation(first_target, 3, 3, true).unwrap();
            f.post_revaluation(first, b"reapplication-first-valuation");
            let original_position = f.position(target, None);
            let relief = remaining_revalued_carrying_relief(original_position, 1).unwrap();
            let original = f
                .prepare(target, 1, day(4, 15), b"allocated-reapplication-original")
                .unwrap()
                .into_proposal();
            let applied = f.f.h.post(request(original.clone())).unwrap().entry_ref();
            let next = f.revaluation(3, 1, 4, true).unwrap();
            f.post_revaluation(next, b"reapplication-later-valuation");
            let before_undo = f.position(target, None);
            assert_eq!(
                before_undo,
                OracleRevaluedCarrying {
                    native: 2,
                    historical_base: 7,
                    carrying_base: 6,
                }
            );
            let mut reversal = undo(&original, applied, b"allocated-reapplication-undo");
            reversal.effective_date = day(5, 1);
            let reversed = f.f.h.post(request(reversal.clone())).unwrap().entry_ref();
            let at_undo = f.f.h.db.frontier().unwrap();
            let undone = OracleRevaluedCarrying {
                native: before_undo.native.checked_add(relief.native).unwrap(),
                historical_base: before_undo
                    .historical_base
                    .checked_add(relief.historical_base)
                    .unwrap(),
                carrying_base: before_undo
                    .carrying_base
                    .checked_add(relief.carrying_base)
                    .unwrap(),
            };
            assert_eq!(f.position(target, None), undone);
            assert_ne!(
                remaining_revalued_carrying_relief(undone, 1).unwrap(),
                relief,
                "a fresh application would use a different carrying ratio"
            );

            let reapplied = undo(&reversal, reversed, b"allocated-reapplication-redo");
            let reapplied_ref = f.f.h.post(request(reapplied.clone())).unwrap().entry_ref();
            let at_redo = f.f.h.db.frontier().unwrap();
            assert_eq!(f.position(target, None), before_undo);
            let undone_again = undo(
                &reapplied,
                reapplied_ref,
                b"allocated-reapplication-second-undo",
            );
            f.f.h.post(request(undone_again)).unwrap();
            assert_eq!(f.position(target, None), undone);
            let head = f.f.h.db.frontier().unwrap();
            for recorded in [original, reversal, reapplied] {
                assert!(matches!(
                    f.f.h.post(request(recorded)).unwrap(),
                    Posted::AlreadyRecorded { .. }
                ));
                assert_eq!(f.f.h.db.frontier().unwrap(), head);
                assert_eq!(f.position(target, None), undone);
            }
            assert_eq!(f.position(target, Some(at_undo)), undone);
            assert_eq!(f.position(target, Some(at_redo)), before_undo);

            let final_payment = f
                .prepare(target, 3, day(5, 2), b"allocated-reapplication-final")
                .unwrap()
                .into_proposal();
            let final_ref = f.f.h.post(request(final_payment.clone())).unwrap().entry_ref();
            let full_undo = undo(
                &final_payment,
                final_ref,
                b"allocated-reapplication-full-undo",
            );
            let full_undo_ref = f.f.h.post(request(full_undo.clone())).unwrap().entry_ref();
            assert_eq!(f.position(target, None), undone);
            let full_redo = undo(
                &full_undo,
                full_undo_ref,
                b"allocated-reapplication-full-redo",
            );
            f.f.h.post(request(full_redo)).unwrap();
            assert_eq!(
                f.position(target, None),
                OracleRevaluedCarrying {
                    native: 0,
                    historical_base: 0,
                    carrying_base: 0,
                }
            );
            for account in [f.source, f.valuation, f.unrealized, f.f.conversion] {
                assert_eq!(f.functional_net(account), 0);
            }
            assert_leg_projections(&f.f.h);
            f.f.verify();
        }
    }
}

#[test]
fn allocated_reapplication_cannot_strand_offsetting_components_or_negative_carrying() {
    for failure in ["total", "historical", "stranded"] {
        let mut f = match failure {
            "stranded" => RevaluedFixture::new(Side::Debit, &[(2, 1)]),
            "historical" => RevaluedFixture::new(Side::Debit, &[(2, 3)]),
            _ => RevaluedFixture::new(Side::Debit, &[(3, 10)]),
        };
        let target = f.targets[0];
        let first = if failure == "stranded" {
            // Two native units retain one historical unit and minus one
            // valuation unit. Each partial application rounds both reliefs
            // to zero; consuming the last native unit that way would strand
            // opposite components even though their total is zero.
            f.revaluation(1, 8, 3, true).unwrap()
        } else if failure == "historical" {
            f.revaluation(1, 2, 3, true).unwrap()
        } else {
            f.revaluation(13, 3, 3, true).unwrap()
        };
        f.post_revaluation(first, b"blocked-reapplication-first-valuation");
        let original = f
            .prepare(target, 1, day(4, 15), b"blocked-allocated-original")
            .unwrap()
            .into_proposal();
        let applied = f.f.h.post(request(original.clone())).unwrap().entry_ref();
        let mut reversal = undo(&original, applied, b"blocked-allocated-undo");
        reversal.effective_date = day(4, 16);
        let reversed = f.f.h.post(request(reversal.clone())).unwrap().entry_ref();
        if failure != "total" {
            let competing = f
                .prepare(target, 1, day(4, 17), b"blocked-allocated-competitor")
                .unwrap()
                .into_proposal();
            f.f.h.post(request(competing)).unwrap();
        } else {
            let lower = f.revaluation(1, 1, 4, true).unwrap();
            f.post_revaluation(lower, b"blocked-reapplication-lower-valuation");
        }
        let position = f.position(target, None);
        assert_eq!(
            position,
            if failure != "total" {
                OracleRevaluedCarrying {
                    native: 1,
                    historical_base: 1,
                    carrying_base: i128::from(failure == "historical"),
                }
            } else {
                OracleRevaluedCarrying {
                    native: 3,
                    historical_base: 10,
                    carrying_base: 3,
                }
            }
        );
        let mut reapplied = undo(&reversal, reversed, b"blocked-allocated-redo");
        reapplied.effective_date = day(5, 1);
        let head = f.f.h.db.frontier().unwrap();
        let rows = f.f.h.db.vertices().unwrap();
        let refused = f.f.h.post(request(reapplied)).unwrap_err();
        assert_eq!(refused.code, fa_journal::refusal::code::SETTLE_SHAPE);
        assert_eq!(f.f.h.db.frontier().unwrap(), head);
        assert_eq!(f.f.h.db.vertices().unwrap(), rows);
        assert_eq!(f.position(target, None), position);
        assert_leg_projections(&f.f.h);
        f.f.verify();
    }
}

#[test]
fn allocated_reapplication_retains_authority_and_complete_prefix_guards() {
    let mut f = RevaluedFixture::new(Side::Debit, &[(3, 10)]);
    let target = f.targets[0];
    let first = f.revaluation(13, 3, 3, true).unwrap();
    f.post_revaluation(first, b"guarded-allocated-valuation");
    let original = f
        .prepare(target, 1, day(4, 15), b"guarded-allocated-original")
        .unwrap()
        .into_proposal();
    let applied = f.f.h.post(request(original.clone())).unwrap().entry_ref();
    let reversal = undo(&original, applied, b"guarded-allocated-undo");
    let reversed = f.f.h.post(request(reversal.clone())).unwrap().entry_ref();
    let reapplied = undo(&reversal, reversed, b"guarded-allocated-redo");
    let head = f.f.h.db.frontier().unwrap();
    let rows = f.f.h.db.vertices().unwrap();
    let mut without_read = request(reapplied.clone());
    without_read.capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let refused = f.f.h.post(without_read).unwrap_err();
    assert_eq!(refused.code, fa_journal::refusal::code::CAPABILITY);
    assert_eq!(f.f.h.db.frontier().unwrap(), head);
    assert_eq!(f.f.h.db.vertices().unwrap(), rows);

    let cx = f.f.h.ctx();
    let prepared = prepare_post(&mut f.f.h.db, &cx, &f.f.h.book, request(reapplied.clone()))
        .unwrap()
        .unwrap();
    let PostPreparation::Ready(prepared) = prepared else {
        panic!("a new allocated reapplication is prepared");
    };
    let unrelated = f.f.h.document(
        INVOICE,
        HUMAN_UPLOAD,
        b"new evidence after allocated reapplication was prepared",
    );
    f.f.h.add_document(&unrelated).unwrap();
    let head = f.f.h.db.frontier().unwrap();
    let rows = f.f.h.db.vertices().unwrap();
    let refused = f.f.h.runtime
        .block_on(prepared.commit(&mut f.f.h.db, &cx))
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, fa_journal::refusal::code::PLAN_INVALIDATED);
    assert_eq!(f.f.h.db.frontier().unwrap(), head);
    assert_eq!(f.f.h.db.vertices().unwrap(), rows);
    f.f.h.post(request(reapplied)).unwrap();
    assert_eq!(
        f.position(target, None),
        OracleRevaluedCarrying {
            native: 2,
            historical_base: 7,
            carrying_base: 9,
        }
    );
    assert_leg_projections(&f.f.h);
    f.f.verify();
}

#[test]
fn allocated_reapplication_does_not_enable_compound_publication() {
    for member_position in 0..3 {
        let mut f = RevaluedFixture::new(Side::Debit, &[(3, 10)]);
        let target = f.targets[0];
        let first = f.revaluation(13, 3, 3, true).unwrap();
        f.post_revaluation(first, b"compound-allocated-valuation");
        let original = f
            .prepare(target, 1, day(4, 15), b"compound-allocated-original")
            .unwrap()
            .into_proposal();
        let applied = f.f.h.post(request(original.clone())).unwrap().entry_ref();
        let reversal = undo(&original, applied, b"compound-allocated-undo");
        let reversed = f.f.h.post(request(reversal.clone())).unwrap().entry_ref();
        let reapplied = undo(&reversal, reversed, b"compound-allocated-redo");
        let ordinary = f.f.h.proposal(
            f.f.h.rent_legs(1),
            b"compound-allocated-companion",
            EntryClass::ORIGINAL,
        );
        let members = match member_position {
            0 => vec![reapplied.clone(), ordinary],
            1 => vec![ordinary, reapplied.clone()],
            _ => vec![reapplied.clone()],
        };
        let batch = f.f.h.batch(b"compound-allocated-batch", members);
        let capability = Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap();
        let head = f.f.h.db.frontier().unwrap();
        let rows = f.f.h.db.vertices().unwrap();
        let direct = f.f.post_fx_batch(batch.clone()).unwrap_err();
        assert_eq!(direct.code, fa_journal::refusal::code::CLASS_NOT_IMPLEMENTED);
        let planned = f.f.h.planned_batch(batch, &capability).unwrap_err();
        assert_eq!(planned.code, fa_journal::refusal::code::CLASS_NOT_IMPLEMENTED);
        assert_eq!(f.f.h.db.frontier().unwrap(), head);
        assert_eq!(f.f.h.db.vertices().unwrap(), rows);
        f.f.h.post(request(reapplied)).unwrap();
        assert_eq!(
            f.position(target, None),
            OracleRevaluedCarrying {
                native: 2,
                historical_base: 7,
                carrying_base: 9,
            }
        );
        assert_leg_projections(&f.f.h);
        f.f.verify();
    }
}

#[test]
fn allocated_reapplication_rechecks_native_capacity_and_latest_effective_date() {
    for consume_capacity in [false, true] {
        let mut f = RevaluedFixture::new(Side::Debit, &[(3, 10)]);
        let target = f.targets[0];
        let first = f.revaluation(13, 3, 3, true).unwrap();
        f.post_revaluation(first, b"limited-allocated-valuation");
        let original = f
            .prepare(target, 1, day(4, 15), b"limited-allocated-original")
            .unwrap()
            .into_proposal();
        let applied = f.f.h.post(request(original.clone())).unwrap().entry_ref();
        let mut reversal = undo(&original, applied, b"limited-allocated-undo");
        reversal.effective_date = day(4, 16);
        let reversed = f.f.h.post(request(reversal.clone())).unwrap().entry_ref();
        let mut reapplied = undo(&reversal, reversed, b"limited-allocated-redo");
        let expected = if consume_capacity {
            let competing = f
                .prepare(target, 3, day(4, 17), b"limited-allocated-consumed")
                .unwrap()
                .into_proposal();
            f.f.h.post(request(competing)).unwrap();
            reapplied.effective_date = day(4, 17);
            fa_journal::refusal::code::OVER_APPLICATION
        } else {
            reapplied.effective_date = day(4, 15);
            fa_journal::refusal::code::SETTLE_SHAPE
        };
        let position = f.position(target, None);
        let head = f.f.h.db.frontier().unwrap();
        let rows = f.f.h.db.vertices().unwrap();
        let refused = f.f.h.post(request(reapplied)).unwrap_err();
        assert_eq!(refused.code, expected, "{refused}");
        assert_eq!(f.f.h.db.frontier().unwrap(), head);
        assert_eq!(f.f.h.db.vertices().unwrap(), rows);
        assert_eq!(f.position(target, None), position);
        assert_leg_projections(&f.f.h);
        f.f.verify();
    }
}
