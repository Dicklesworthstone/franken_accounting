//! Net cash and declared economic differences preserve gross-quote FX relief.

use super::*;
use fa_journal::carrying::{
    FxSettlementDifference, FxSettlementWithDifferencesRequest,
    prepare_fx_settlement_group_with_differences, prepare_fx_settlement_with_differences,
};
use fa_model::ApplicationDifferenceKind::{BankCharge, Discount, Writeoff};
use fa_model::entry::FX_SETTLEMENT_TERMS_EXTENSION;

fn fee_request(
    f: &Fixture,
    target: EntryRef,
    native: i128,
    cash: i128,
    fee: i128,
) -> FxSettlementWithDifferencesRequest {
    let mut settlement = f.fx_request(target, native);
    settlement.settlement_amount = Amount::new(f.h.usd, cash);
    FxSettlementWithDifferencesRequest {
        settlement,
        differences: vec![FxSettlementDifference {
            kind: BankCharge,
            account: f.h.rent,
            amount: Amount::new(f.h.usd, fee),
        }],
    }
}

fn prepare(
    f: &Fixture,
    input: &FxSettlementWithDifferencesRequest,
    key: &[u8],
) -> Result<PreparedFxSettlement, Refusal> {
    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
    prepare_fx_settlement_with_differences(
        &f.h.db,
        &f.h.ctx(),
        &f.h.book,
        &Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
        input,
        f.h.proposal(vec![], key, EntryClass::ORIGINAL),
        &mut budget,
    )
    .unwrap()
}

fn group(
    f: &Fixture,
    inputs: &[FxSettlementWithDifferencesRequest],
    key: &[u8],
) -> Result<PreparedFxSettlementGroup, Refusal> {
    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
    prepare_fx_settlement_group_with_differences(
        &f.h.db,
        &f.h.ctx(),
        &f.h.book,
        &Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
        inputs,
        f.h.proposal(vec![], key, EntryClass::ORIGINAL),
        &mut budget,
    )
    .unwrap()
}

fn refold(proposal: &mut EntryPayload) {
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    if let Some(totals) = &mut proposal.base_totals {
        totals.debits = proposal
            .legs
            .iter()
            .filter(|leg| leg.side == Side::Debit)
            .map(|leg| leg.base_amount.unwrap().mantissa)
            .sum();
        totals.credits = proposal
            .legs
            .iter()
            .filter(|leg| leg.side == Side::Credit)
            .map(|leg| leg.base_amount.unwrap().mantissa)
            .sum();
    }
}

#[test]
fn typed_foreign_receipt_and_payment_separate_cash_reductions_fees_and_realized_fx() {
    for payment in [false, true] {
        let mut f = fixture(100, 105);
        if payment {
            let (entry, _) = read_entry(&f.h.db, f.target.vid).unwrap().unwrap();
            let mut payable = entry.proposal;
            payable.idempotency_key = b"foreign-payable".to_vec();
            for leg in &mut payable.legs {
                leg.side = leg.side.flipped();
            }
            payable.unit_totals = EntryPayload::fold_unit_totals(&payable.legs).unwrap();
            f.target = f.h.post(request(payable)).unwrap().entry_ref();
        }
        // Q=200, H=105. Receipt: 192+5+1+2=200.
        // Payment: 196+5+1-2=200. Both retain realized magnitude 95.
        let mut input = fee_request(&f, f.target, 100, if payment { 196 } else { 192 }, 2);
        input.differences.insert(
            0,
            FxSettlementDifference {
                kind: Discount,
                account: f.h.revenue,
                amount: Amount::new(f.h.usd, 5),
            },
        );
        input.differences.insert(
            1,
            FxSettlementDifference {
                kind: Writeoff,
                account: f.h.receivable,
                amount: Amount::new(f.h.usd, 1),
            },
        );
        let before = f.h.db.frontier().unwrap();
        let prepared = prepare(&f, &input, b"net-cash-settlement").unwrap();
        assert_eq!(prepared.historical_base_relief().mantissa, 105);
        assert_eq!(prepared.base_relief().mantissa, 105);
        let proposal = prepared.into_proposal();
        assert_eq!(
            f.h.db.frontier().unwrap(),
            before,
            "preparation is read-only"
        );
        assert_eq!(proposal.legs.len(), 12);
        assert_eq!(proposal.legs[2].amount, input.settlement.settlement_amount);
        assert_eq!(proposal.legs[4].account_ref, f.realized);
        assert_eq!(proposal.legs[4].amount.mantissa, 95);
        assert_eq!(
            proposal.legs[4].side,
            if payment { Side::Debit } else { Side::Credit }
        );
        assert_eq!(
            proposal.legs[6].side,
            if payment { Side::Credit } else { Side::Debit }
        );
        assert_eq!(proposal.legs[8].side, proposal.legs[6].side);
        assert_eq!(proposal.legs[10].side, Side::Debit);
        let terms = proposal.fx_settlement_terms().unwrap().unwrap();
        assert_eq!(terms.components.len(), 1);
        assert_eq!(
            terms.components[0]
                .differences
                .iter()
                .map(|value| value.leg_ordinal)
                .collect::<Vec<_>>(),
            [6, 8, 10]
        );
        let functional_conversion: i128 = proposal
            .legs
            .iter()
            .filter(|leg| leg.account_ref == f.conversion)
            .map(|leg| {
                if leg.side == Side::Debit {
                    leg.base_amount.unwrap().mantissa
                } else {
                    -leg.base_amount.unwrap().mantissa
                }
            })
            .sum();
        assert_eq!(functional_conversion, 0);
        let posted = f.h.post(request(proposal.clone())).unwrap();
        assert_eq!(f.carrying().open_native.mantissa, 0);
        assert_eq!(f.carrying().open_base.mantissa, 0);
        f.verify();

        let retry = prepare(&f, &input, b"net-cash-settlement")
            .unwrap()
            .into_proposal();
        assert_eq!(
            retry, proposal,
            "reconstruction uses the original pre-publication source"
        );
        assert!(matches!(
            f.h.post(request(retry)).unwrap(),
            Posted::AlreadyRecorded { .. }
        ));
        let mut different_reason = input.clone();
        different_reason.differences[0].kind = Writeoff;
        let changed = prepare(&f, &different_reason, b"net-cash-settlement")
            .unwrap()
            .into_proposal();
        assert_eq!(f.h.post(request(changed)).unwrap_err().exit, 6);

        let reversed = undo(&proposal, posted.entry_ref(), b"net-cash-undo");
        let head = f.h.db.frontier().unwrap();
        for strip in [false, true] {
            let mut forged = reversed.clone();
            if strip {
                forged
                    .extensions
                    .retain(|(tag, _)| *tag != FX_SETTLEMENT_TERMS_EXTENSION);
            } else {
                let mut terms = forged.fx_settlement_terms().unwrap().unwrap();
                terms.components[0].differences[0].kind = Writeoff;
                forged.set_fx_settlement_terms(&terms).unwrap();
            }
            assert_eq!(
                f.h.post(request(forged)).unwrap_err().code,
                fa_journal::refusal::code::REVERSAL_SHAPE
            );
            assert_eq!(f.h.db.frontier().unwrap(), head);
        }
        let reversal = f.h.post(request(reversed.clone())).unwrap();
        assert_eq!(f.carrying().open_native.mantissa, 100);
        assert_eq!(f.carrying().open_base.mantissa, 105);
        let restored = undo(&reversed, reversal.entry_ref(), b"net-cash-undo-undo");
        f.h.post(request(restored)).unwrap();
        assert_eq!(f.carrying().open_native.mantissa, 0);
        assert_eq!(f.carrying().open_base.mantissa, 0);
        f.verify();
    }
}

#[test]
fn explicit_fx_difference_zero_relief_final_remainder_and_no_gain_are_exact() {
    for (native, historical) in [(2, 1), (2, 4)] {
        let mut f = fixture(native, historical);
        for index in 0..native {
            let input = fee_request(&f, f.target, 1, 1, 1);
            let prepared = prepare(&f, &input, format!("partial-fee-{index}").as_bytes()).unwrap();
            let expected = if historical == 1 { index } else { 2 };
            assert_eq!(prepared.historical_base_relief().mantissa, expected);
            let proposal = prepared.into_proposal();
            let terms = proposal.fx_settlement_terms().unwrap().unwrap();
            assert_eq!(proposal.legs.len(), if expected == 2 { 6 } else { 8 });
            assert_eq!(
                terms.components[0].differences[0].leg_ordinal,
                if expected == 2 { 4 } else { 6 }
            );
            assert!(proposal.legs.iter().all(|leg| leg.amount.mantissa > 0));
            f.h.post(request(proposal)).unwrap();
            assert_eq!(f.carrying().open_native.mantissa, native - index - 1);
            f.verify();
        }
        assert_eq!(f.carrying().open_base.mantissa, 0);
    }
}

#[test]
fn mixed_fx_groups_rebase_explicit_pairs_and_preserve_empty_request_bytes() {
    for marked_first in [false, true] {
        let mut f = fixture(3, 10);
        let second = f.another_target();
        let legacy = [f.fx_request(f.target, 1), f.fx_request(second, 1)];
        let mut inputs = legacy
            .iter()
            .cloned()
            .map(|settlement| FxSettlementWithDifferencesRequest {
                settlement,
                differences: vec![],
            })
            .collect::<Vec<_>>();
        let old = f
            .prepare_group(&legacy, b"no-difference-parity")
            .unwrap()
            .into_proposal();
        let new = group(&f, &inputs, b"no-difference-parity")
            .unwrap()
            .into_proposal();
        assert_eq!(old, new);
        assert_eq!(
            old.canonical_bytes().unwrap(),
            new.canonical_bytes().unwrap()
        );
        assert_eq!(
            f.prepare(1, b"single-parity").proposal(),
            prepare(&f, &inputs[0], b"single-parity")
                .unwrap()
                .proposal()
        );

        let marked = usize::from(!marked_first);
        inputs[marked] = fee_request(&f, inputs[marked].settlement.target, 1, 1, 1);
        let prepared = group(&f, &inputs, b"mixed-profile-group").unwrap();
        let start = prepared.items()[marked].leg_range.start;
        let proposal = prepared.into_proposal();
        let terms = proposal.fx_settlement_terms().unwrap().unwrap();
        assert_eq!(
            terms.components[0].applying_ordinal,
            u16::try_from(start).unwrap()
        );
        assert_eq!(
            terms.components[0].differences[0].leg_ordinal,
            u16::try_from(start + 6).unwrap()
        );
        let mut bad = proposal.clone();
        // Each changed pair stays individually balanced. Only the immutable
        // Settlement quote exposes the extra unit of alleged actual cash.
        for ordinal in [start + 2, start + 3] {
            bad.legs[ordinal].amount.mantissa += 1;
            bad.legs[ordinal].base_amount.as_mut().unwrap().mantissa += 1;
        }
        refold(&mut bad);
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        assert!(f.h.post(request(bad)).is_err());
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert_eq!(f.carrying_for(f.target).open_native.mantissa, 3);
        assert_eq!(f.carrying_for(second).open_native.mantissa, 3);
        let posted = f.h.post(request(proposal.clone())).unwrap();
        assert_eq!(posted.recorded_at().0, head.0 + 1);
        assert_eq!(f.carrying_for(f.target).open_base.mantissa, 7);
        assert_eq!(f.carrying_for(second).open_base.mantissa, 7);
        f.verify();
        assert_eq!(
            group(&f, &inputs, b"mixed-profile-group")
                .unwrap()
                .into_proposal(),
            proposal
        );
        let mut duplicate = inputs.clone();
        duplicate[1].settlement.target = duplicate[0].settlement.target;
        assert!(group(&f, &duplicate, b"duplicate-target-differences").is_err());
    }
}

#[test]
fn difference_admission_refuses_unexplained_cash_forged_layout_and_stale_sources() {
    let mut f = fixture(100, 105);
    let input = fee_request(&f, f.target, 100, 197, 3);
    let proposal = prepare(&f, &input, b"strict-differences")
        .unwrap()
        .into_proposal();
    let head = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    let mut invalid_inputs = Vec::new();
    let mut bad = input.clone();
    bad.settlement.settlement_amount.mantissa += 1;
    invalid_inputs.push(bad);
    let mut bad = input.clone();
    bad.differences[0].amount.unit = f.foreign;
    invalid_inputs.push(bad);
    let mut bad = input.clone();
    bad.differences[0].amount.mantissa = 0;
    invalid_inputs.push(bad);
    for account in [
        f.h.cash,
        f.conversion,
        f.realized,
        account_vid(f.h.book.book_id, "1211"),
    ] {
        let mut bad = input.clone();
        bad.differences[0].account = account;
        invalid_inputs.push(bad);
    }
    for bad in invalid_inputs {
        assert!(prepare(&f, &bad, b"invalid-differences").is_err());
    }

    let mut candidates = Vec::new();
    let mut bad = proposal.clone();
    bad.extensions
        .retain(|(tag, _)| *tag != FX_SETTLEMENT_TERMS_EXTENSION);
    candidates.push(bad);
    let mut bad = proposal.clone();
    for ordinal in [0, 1] {
        bad.legs[ordinal].base_amount.as_mut().unwrap().mantissa += 1;
    }
    refold(&mut bad);
    candidates.push(bad);
    let mut bad = proposal.clone();
    bad.legs[7].account_ref = f.h.revenue;
    candidates.push(bad);
    let mut bad = proposal.clone();
    bad.legs.extend_from_within(6..8);
    refold(&mut bad);
    candidates.push(bad);
    let mut bad = proposal.clone();
    bad.legs[6].dimension_set = vec![(fa_model::PARTY_DIMENSION, VId(999))];
    candidates.push(bad);
    let mut bad = proposal.clone();
    bad.base_totals = None;
    for leg in &mut bad.legs {
        leg.base_amount = None;
    }
    candidates.push(bad);
    for bad in candidates {
        assert!(f.h.post(request(bad)).is_err());
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
    }

    let advance = f
        .prepare(1, b"concurrent-source-application")
        .into_proposal();
    f.h.post(request(advance)).unwrap();
    let after = f.h.db.frontier().unwrap();
    assert!(f.h.post(request(proposal)).is_err());
    assert_eq!(f.h.db.frontier().unwrap(), after);
    assert_eq!(f.carrying().open_native.mantissa, 99);
    f.verify();
}

#[test]
fn confined_fx_differences_admit_every_declared_route_before_source_reads_and_promote_exactly() {
    for stale in [false, true] {
        let mut f = fixture(3, 10);
        let name = "confined-net-cash";
        let base = Capability::new(
            AGENT,
            fa_policy::Profile::Agent,
            &[fa_policy::Op::Post],
            PRINCIPAL,
        )
        .unwrap()
        .on_branch(fa_model::draft_branch(f.h.book.book_id, name))
        .unwrap();
        let limited = base
            .clone()
            .for_accounts(&["1211", "4011", "1000", "2991", "7091"])
            .unwrap();
        let permitted = base
            .for_accounts(&["1211", "4011", "1000", "2991", "7091", "6000"])
            .unwrap();
        f.h.open_draft(limited.clone(), name).unwrap();
        let input = fee_request(&f, f.target, 1, 1, 1);
        let mut template =
            f.h.proposal(vec![], b"confined-difference-member", EntryClass::ORIGINAL);
        template.principal_ref = AGENT;
        let stripped = Cx::detached_cancel_context();
        let mut budget =
            ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
        let admission = fa_journal::draft::admit_sources(&f.h.db, &f.h.book, &limited, name)
            .unwrap()
            .unwrap();
        let mut unavailable = input.clone();
        unavailable.settlement.target.vid = VId(999);
        unavailable.settlement.rate_document = Oid([99; 32]);
        let head = f.h.db.frontier().unwrap();
        let cx = f.h.ctx();
        let refused = fa_journal::carrying::prepare_fx_settlement_with_differences_in_draft(
            &mut f.h.db,
            &cx,
            &f.h.book,
            &admission,
            &unavailable,
            template.clone(),
            &mut budget,
        )
        .unwrap()
        .unwrap_err();
        assert_eq!(
            refused.exit,
            exit::SAFETY,
            "the fee account is denied before either absent private source: {refused}"
        );
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert!(f.h.draft(name).intents.is_empty());

        let admission = fa_journal::draft::admit_sources(&f.h.db, &f.h.book, &permitted, name)
            .unwrap()
            .unwrap();
        let proposal = fa_journal::carrying::prepare_fx_settlement_with_differences_in_draft(
            &mut f.h.db,
            &cx,
            &f.h.book,
            &admission,
            &input,
            template,
            &mut budget,
        )
        .unwrap()
        .unwrap();
        assert_eq!(proposal.legs[2].amount.mantissa, 1);
        assert!(proposal.fx_settlement_terms().unwrap().is_some());
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert!(fa_policy::admit_read(&permitted, AGENT, f.h.book.book_id).is_err());
        f.h.plan_draft(permitted, name, proposal.clone()).unwrap();
        if stale {
            let changed = f
                .prepare(3, b"source-closed-before-difference-promotion")
                .into_proposal();
            f.h.post(request(changed)).unwrap();
            let head = f.h.db.frontier().unwrap();
            let rows = f.h.db.vertices().unwrap();
            assert!(f.h.promote(f.h.approver_capability(), name).is_err());
            assert_eq!(f.h.db.frontier().unwrap(), head);
            assert_eq!(f.h.db.vertices().unwrap(), rows);
        } else {
            let promoted = f.h.promote(f.h.approver_capability(), name).unwrap();
            assert_eq!(promoted.entries.len(), 1);
            let (recorded, _) = read_entry(&f.h.db, promoted.entries[0].vid)
                .unwrap()
                .unwrap();
            assert_eq!(recorded.proposal, proposal);
            assert_eq!(f.carrying().open_native.mantissa, 2);
            assert_eq!(f.carrying().open_base.mantissa, 7);
            f.verify();
        }
    }
}
