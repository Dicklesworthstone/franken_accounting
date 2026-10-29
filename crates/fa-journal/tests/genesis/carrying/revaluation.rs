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
                    effective_from: day(3, 1),
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
    f.f.h.post(request(reversed)).unwrap();
    for (target, initial) in f.targets.iter().zip(positions) {
        assert_eq!(f.position(*target, None), initial);
    }
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
