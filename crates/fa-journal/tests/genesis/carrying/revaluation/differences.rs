//! Allocated original-cost relief and valuation release survive net cash fees.

use super::*;
use fa_journal::carrying::{
    FxSettlementDifference, FxSettlementWithDifferencesRequest,
    prepare_fx_settlement_group_with_differences,
};

#[test]
fn allocated_net_cash_groups_preserve_source_relief_release_routes_and_future_replay() {
    for side in [Side::Debit, Side::Credit] {
        let mut f = RevaluedFixture::new(side, &[(3, 10), (3, 10)]);
        let revaluation = f.revaluation(13, 3, 3, true).unwrap();
        f.post_revaluation(revaluation, b"allocated-difference-source");
        let inputs = f
            .targets
            .iter()
            .map(|target| {
                let mut settlement = f.f.fx_request(*target, 1);
                // Receipt 2 = cash1 + fee1; payment 2 = cash3 - fee1.
                settlement.settlement_amount.mantissa = if side == Side::Debit { 1 } else { 3 };
                FxSettlementWithDifferencesRequest {
                    settlement,
                    differences: vec![FxSettlementDifference {
                        kind: fa_model::ApplicationDifferenceKind::BankCharge,
                        account: f.f.h.rent,
                        amount: Amount::new(f.f.h.usd, 1),
                    }],
                }
            })
            .collect::<Vec<_>>();
        let prepare = |f: &RevaluedFixture, inputs: &[FxSettlementWithDifferencesRequest]| {
            let stripped = Cx::detached_cancel_context();
            let mut budget =
                ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
            let mut template =
                f.f.h
                    .proposal(vec![], b"allocated-net-cash", EntryClass::ORIGINAL);
            template.effective_date = day(4, 15);
            prepare_fx_settlement_group_with_differences(
                &f.f.h.db,
                &f.f.h.ctx(),
                &f.f.h.book,
                &Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
                inputs,
                template,
                &mut budget,
            )
            .unwrap()
        };
        let prepared = prepare(&f, &inputs).unwrap();
        assert!(
            prepared
                .items()
                .iter()
                .all(|item| item.base_relief.mantissa == 4)
        );
        let proposal = prepared.into_proposal();
        assert_eq!(proposal.legs.len(), 20);
        assert_eq!(
            proposal.base_totals.as_ref().unwrap().fx_law_oid,
            FxLawId::SettlementAllocatedCarrying.oid()
        );
        let terms = proposal.fx_settlement_terms().unwrap().unwrap();
        assert_eq!(
            terms
                .components
                .iter()
                .map(|value| value.applying_ordinal)
                .collect::<Vec<_>>(),
            [0, 10]
        );
        assert_eq!(
            terms
                .components
                .iter()
                .map(|value| value.differences[0].leg_ordinal)
                .collect::<Vec<_>>(),
            [6, 16]
        );
        let raw = &proposal
            .extensions
            .iter()
            .find(|(tag, _)| *tag == fa_model::entry::FX_SETTLEMENT_VALUATION_EXTENSION)
            .unwrap()
            .1;
        let releases = fa_model::FxSettlementValuationBasis::decode(raw).unwrap();
        assert_eq!(releases.items.len(), 2);
        for release in &releases.items {
            assert_eq!(release.historical_relief.mantissa, 3);
            assert_eq!(release.total_relief.mantissa, 4);
            assert_eq!(release.valuation_relief.mantissa, 1);
        }
        for account in [f.valuation, f.unrealized] {
            let mut invalid = inputs.clone();
            invalid[1].differences[0].account = account;
            assert!(prepare(&f, &invalid).is_err());
        }
        let head = f.f.h.db.frontier().unwrap();
        let posted = f.f.h.post(request(proposal.clone())).unwrap();
        assert_eq!(posted.recorded_at().0, head.0 + 1);
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
        assert_eq!(prepare(&f, &inputs).unwrap().into_proposal(), proposal);
        f.f.verify();
        // A subsequent valuation must recognize both retained source-bound
        // settlements, not merely accept their first atomic publication.
        let next = f.revaluation(5, 1, 4, true).unwrap();
        assert!(!next.is_noop());
        let reversed = undo(&proposal, posted.entry_ref(), b"allocated-net-cash-undo");
        f.f.h.post(request(reversed)).unwrap();
        for target in &f.targets {
            assert_eq!(
                f.position(*target, None),
                OracleRevaluedCarrying {
                    native: 3,
                    historical_base: 10,
                    carrying_base: 13,
                }
            );
        }
        f.f.verify();
    }
}
