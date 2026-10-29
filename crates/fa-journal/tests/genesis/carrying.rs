use super::*;
use fa_journal::carrying::{
    FxSettlementRequest, PreparedFxSettlementGroup, open_item_carrying_at, prepare_fx_settlement,
    prepare_fx_settlement_group,
};
use fa_money::RoundingLaw;
use fa_money::rate::{ArithmeticBudget, BudgetLimits};

#[path = "carrying/drafts.rs"]
mod drafts;
#[path = "carrying/revaluation.rs"]
mod revaluation;

struct Fixture {
    h: Harness,
    target: EntryRef,
    foreign: UnitId,
    conversion: VId,
    realized: VId,
    rate: Oid,
}

fn request(proposal: EntryPayload) -> PostRequest {
    PostRequest {
        proposal,
        approvals: vec![],
        plan_certificate: None,
        capability: Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
    }
}

fn fixture(native: i128, base: i128) -> Fixture {
    let mut h = harness();
    let foreign = h.book.units.lookup("EUR").unwrap();
    let accounts = [
        (
            "1211",
            "Foreign receivables",
            fa_model::AccountType::ASSET,
            0,
        ),
        ("4011", "Foreign revenue", fa_model::AccountType::REVENUE, 1),
        ("2991", "FX conversion", fa_model::AccountType::LIABILITY, 1),
        ("7091", "Realized FX", fa_model::AccountType::REVENUE, 1),
    ]
    .into_iter()
    .map(|(code, name, kind, normal)| AccountSpec {
        code: code.into(),
        name: name.into(),
        account_type: kind.0,
        normal_balance: normal,
        is_leaf: true,
        unit_policy: UnitPolicy::AnyCurrency,
        parent_code: None,
        limit: None,
    })
    .collect::<Vec<_>>();
    let cx = h.ctx();
    let day = h.day();
    let description = h
        .proposal(vec![], b"chart", EntryClass::ORIGINAL)
        .description;
    h.runtime
        .block_on(install_chart(
            &mut h.db,
            &cx,
            &h.book,
            &accounts,
            PRINCIPAL,
            day,
            b"carrying-chart",
            description,
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let spot = FxRateDocument::new(
        FxRateTerms {
            base_unit: h.usd,
            quote_unit: foreign,
            rate_num: u128::try_from(base).unwrap(),
            rate_den: u128::try_from(native).unwrap(),
            rounding: RoundingLaw::HalfEven,
        },
        day,
        1_700_000_000_000_000_000,
        FxRatePurpose::SpotClose,
        "explicit fixture rate",
    )
    .unwrap();
    h.add_document(
        &spot
            .document(h.book.book_id, PRINCIPAL, HUMAN_UPLOAD)
            .unwrap(),
    )
    .unwrap();
    let settle = FxRateDocument::new(
        FxRateTerms {
            base_unit: h.usd,
            quote_unit: foreign,
            rate_num: 2,
            rate_den: 1,
            rounding: RoundingLaw::HalfEven,
        },
        day,
        1_700_000_000_000_000_001,
        FxRatePurpose::Settlement,
        "explicit settlement rate",
    )
    .unwrap();
    h.add_document(
        &settle
            .document(h.book.book_id, PRINCIPAL, HUMAN_UPLOAD)
            .unwrap(),
    )
    .unwrap();
    let receivable = account_vid(h.book.book_id, "1211");
    let revenue = account_vid(h.book.book_id, "4011");
    let invoice = h.proposal(
        vec![
            LegPayload::simple(Side::Debit, receivable, Amount::new(foreign, native)),
            LegPayload::simple(Side::Credit, revenue, Amount::new(foreign, native)),
        ],
        b"foreign-invoice",
        EntryClass::ORIGINAL,
    );
    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
    let spec = fa_journal::genesis::read_book_spec(&h.db).unwrap().unwrap();
    let invoice = value_proposal(
        &mut budget,
        invoice,
        &spec,
        &h.book.units,
        FxLawId::SpotClose,
        &[spot],
    )
    .unwrap();
    let target = h.post(request(invoice)).unwrap().entry_ref();
    let conversion = account_vid(h.book.book_id, "2991");
    let realized = account_vid(h.book.book_id, "7091");
    let rate = settle.evidence_ref(h.book.book_id).unwrap().document_oid;
    Fixture {
        h,
        target,
        foreign,
        conversion,
        realized,
        rate,
    }
}

impl Fixture {
    fn prepare(&self, amount: i128, key: &[u8]) -> PreparedFxSettlement {
        self.prepare_for(self.target, amount, key)
    }

    fn prepare_for(&self, target: EntryRef, amount: i128, key: &[u8]) -> PreparedFxSettlement {
        let stripped = Cx::detached_cancel_context();
        let mut budget =
            ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
        let req = self.fx_request(target, amount);
        prepare_fx_settlement(
            &self.h.db,
            &self.h.ctx(),
            &self.h.book,
            &Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
            &req,
            self.h.proposal(vec![], key, EntryClass::ORIGINAL),
            &mut budget,
        )
        .unwrap()
        .unwrap()
    }

    fn fx_request(&self, target: EntryRef, amount: i128) -> FxSettlementRequest {
        FxSettlementRequest {
            target,
            target_ordinal: 0,
            amount: Amount::new(self.foreign, amount),
            settlement_amount: Amount::new(self.h.usd, amount.checked_mul(2).unwrap()),
            settlement_account: self.h.cash,
            conversion_account: self.conversion,
            realized_fx_account: self.realized,
            rate_document: self.rate,
        }
    }

    fn prepare_group(
        &self,
        requests: &[FxSettlementRequest],
        key: &[u8],
    ) -> Result<PreparedFxSettlementGroup, Refusal> {
        let stripped = Cx::detached_cancel_context();
        let mut budget =
            ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
        prepare_fx_settlement_group(
            &self.h.db,
            &self.h.ctx(),
            &self.h.book,
            &Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
            requests,
            self.h.proposal(vec![], key, EntryClass::ORIGINAL),
            &mut budget,
        )
        .unwrap()
    }

    fn carrying(&self) -> CarryingOpenItem {
        self.carrying_for(self.target)
    }

    fn carrying_for(&self, target: EntryRef) -> CarryingOpenItem {
        open_item_carrying_at(
            &self.h.db,
            &self.h.ctx(),
            &self.h.book,
            target,
            0,
            self.h.db.frontier().unwrap(),
        )
        .unwrap()
        .unwrap()
    }

    fn another_target(&mut self) -> EntryRef {
        let (entry, _) = read_entry(&self.h.db, self.target.vid).unwrap().unwrap();
        let mut proposal = entry.proposal;
        proposal.idempotency_key = b"second-foreign-invoice".to_vec();
        self.h.post(request(proposal)).unwrap().entry_ref()
    }

    fn post_fx_batch(&mut self, batch: PostBatch) -> Result<BatchPosted, Refusal> {
        let cx = self.h.ctx();
        self.h
            .runtime
            .block_on(fa_journal::post_batch(
                &mut self.h.db,
                &cx,
                &self.h.book,
                Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
                batch,
            ))
            .unwrap()
    }

    fn verify(&self) {
        let cx = self.h.ctx();
        let verification = cx
            .query()
            .with_restriction(|| {
                verify_fx_conversions(&self.h.db, &cx, &self.h.book, self.h.db.frontier().unwrap())
            })
            .unwrap();
        assert!(verification.is_green(), "{:?}", verification.drift);
    }
}

#[test]
fn independent_fx_group_is_one_entry_with_exact_partial_final_zero_and_single_undo() {
    for (base, second_amount, relief, remainder) in [
        (10, 3, (3, 10), ((2, 7), (0, 0))),
        (1, 1, (0, 0), ((2, 1), (2, 1))),
        (6, 3, (2, 6), ((2, 4), (0, 0))),
    ] {
        let mut f = fixture(3, base);
        let second = f.another_target();
        let inputs = [
            f.fx_request(f.target, 1),
            f.fx_request(second, second_amount),
        ];
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let group = f.prepare_group(&inputs, b"single-fx-group").unwrap();
        assert_eq!(group.items().len(), 2);
        assert_eq!(
            (
                group.items()[0].base_relief.mantissa,
                group.items()[1].base_relief.mantissa
            ),
            relief
        );
        assert!(
            group
                .items()
                .iter()
                .all(|item| item.carrying.known_at == head)
        );
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        let proposal = group.into_proposal();
        assert_eq!(
            proposal
                .legs
                .iter()
                .filter(|leg| !leg.settles.is_empty())
                .count(),
            2
        );
        let posted = f.h.post(request(proposal.clone())).unwrap();
        assert_eq!(posted.recorded_at().0, head.0 + 1);
        for (target, expected) in [(f.target, remainder.0), (second, remainder.1)] {
            let item = f.carrying_for(target);
            assert_eq!(
                (item.open_native.mantissa, item.open_base.mantissa),
                expected
            );
        }
        f.verify();
        let rows = f.h.db.vertices().unwrap();
        assert_eq!(
            f.prepare_group(&inputs, b"single-fx-group")
                .unwrap()
                .into_proposal(),
            proposal
        );
        let retry = f.h.post(request(proposal.clone())).unwrap();
        assert!(matches!(&retry, Posted::AlreadyRecorded { .. }));
        assert_eq!(retry.entry_ref(), posted.entry_ref());
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert_eq!(f.h.db.frontier().unwrap(), posted.recorded_at());
        let reversed = undo(&proposal, posted.entry_ref(), b"undo-entire-fx-group");
        let undone = f.h.post(request(reversed)).unwrap();
        assert_eq!(undone.recorded_at().0, posted.recorded_at().0 + 1);
        for target in [f.target, second] {
            let item = f.carrying_for(target);
            assert_eq!(
                (item.open_native.mantissa, item.open_base.mantissa),
                (3, base)
            );
        }
        f.verify();
    }
}

#[test]
fn fx_group_overlap_bad_later_input_and_post_only_authority_publish_nothing() {
    let mut f = fixture(3, 10);
    let second = f.another_target();
    let inputs = [f.fx_request(f.target, 1), f.fx_request(second, 1)];
    let head = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    let mut cases = Vec::new();
    let mut duplicate = inputs.clone();
    duplicate[1].target = duplicate[0].target;
    cases.push(duplicate);
    let mut forged = inputs.clone();
    forged[1].target = forged[0].target;
    forged[1].target.entry_digest[0] ^= 1;
    cases.push(forged);
    let mut bad_cash = inputs.clone();
    bad_cash[1].settlement_amount.mantissa += 1;
    cases.push(bad_cash);
    let mut another_rate = inputs.clone();
    another_rate[1].rate_document = Oid([7; 32]);
    cases.push(another_rate);
    for inputs in cases {
        assert_eq!(
            f.prepare_group(&inputs, b"invalid-fx-group")
                .unwrap_err()
                .code,
            "FA-REF-071"
        );
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
    }
    let group = f
        .prepare_group(&inputs, b"post-only-fx-group")
        .unwrap()
        .into_proposal();
    let mut denied = request(group);
    denied.capability = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    assert_eq!(f.h.post(denied).unwrap_err().exit, 7);
    assert_eq!(f.h.db.frontier().unwrap(), head);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
}

#[test]
fn balanced_false_later_fx_component_and_group_in_batch_refuse_without_partial_effects() {
    let mut f = fixture(3, 10);
    let second = f.another_target();
    let inputs = [f.fx_request(f.target, 1), f.fx_request(second, 1)];
    let group = f.prepare_group(&inputs, b"false-later-fx-group").unwrap();
    let second_start = group.items()[1].leg_range.start;
    let mut proposal = group.into_proposal();
    // Preserve both native and functional balance, and conversion neutrality.
    // Only the second item's claimed carrying relief is wrong.
    for ordinal in [second_start, second_start + 1, second_start + 2] {
        proposal.legs[ordinal]
            .base_amount
            .as_mut()
            .unwrap()
            .mantissa += 1;
    }
    proposal.legs[second_start + 2].amount.mantissa += 1;
    proposal.legs[second_start + 4].amount.mantissa += 1;
    proposal.legs[second_start + 4]
        .base_amount
        .as_mut()
        .unwrap()
        .mantissa += 1;
    // Cash is2 while carrying is3, so the loss grows from1 to2.
    let totals = proposal.base_totals.as_mut().unwrap();
    totals.debits += 2;
    totals.credits += 2;
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    let head = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    let refusal = f.h.post(request(proposal)).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-071");
    assert!(refusal.message.contains("disagrees with journal-derived"));
    assert_eq!(f.h.db.frontier().unwrap(), head);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
    let valid = f
        .prepare_group(&inputs, b"group-not-batch-member")
        .unwrap()
        .into_proposal();
    let batch = f.h.batch(b"unsupported-fx-group-batch", vec![valid]);
    assert_eq!(f.post_fx_batch(batch).unwrap_err().code, "FA-REF-071");
    assert_eq!(f.h.db.frontier().unwrap(), head);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
}

#[test]
fn portable_fx_group_refuses_stale_source_and_unrelated_heads_then_retries_one_entry() {
    for source_change in [false, true] {
        let mut f = fixture(3, 10);
        let second = f.another_target();
        let inputs = [f.fx_request(f.target, 1), f.fx_request(second, 1)];
        let proposal = f
            .prepare_group(&inputs, b"portable-fx-group")
            .unwrap()
            .into_proposal();
        let cap = Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap();
        let plan = f.h.post_plan(request(proposal)).unwrap();
        let bytes = plan.canonical_bytes().unwrap();
        if source_change {
            let earlier = f.prepare(1, b"competing-group-application").into_proposal();
            f.h.post(request(earlier)).unwrap();
        } else {
            let doc =
                f.h.document(INVOICE, HUMAN_UPLOAD, b"new independent group evidence");
            f.h.add_document(&doc).unwrap();
        }
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        assert_eq!(
            f.h.publish_plan(fa_intents::PostPlan::decode(&bytes).unwrap(), &cap)
                .unwrap_err()
                .code,
            fa_journal::refusal::code::PLAN_INVALIDATED
        );
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        let fresh = f
            .prepare_group(&inputs, b"portable-fx-group")
            .unwrap()
            .into_proposal();
        let plan = f.h.post_plan(request(fresh)).unwrap();
        let posted = f.h.publish_plan(plan.clone(), &cap).unwrap();
        assert_eq!(posted.recorded_at().0, head.0 + 1);
        let item = f.carrying();
        assert_eq!(
            (item.open_native.mantissa, item.open_base.mantissa),
            if source_change { (1, 3) } else { (2, 7) }
        );
        assert_eq!(f.carrying_for(second).open_base.mantissa, 7);
        let retry = f.h.publish_plan(plan, &cap).unwrap();
        assert!(matches!(&retry, Posted::AlreadyRecorded { .. }));
        assert_eq!(retry.entry_ref(), posted.entry_ref());
        assert_eq!(f.h.db.frontier().unwrap(), posted.recorded_at());
        f.verify();
    }
}

#[test]
fn independent_fx_batch_publishes_exact_partial_final_and_zero_relief_at_one_prefix() {
    for (base, second_amount, relief, remaining_first, remaining_second) in [
        (10, 3, (3, 10), (2, 7), (0, 0)),
        (1, 1, (0, 0), (2, 1), (2, 1)),
    ] {
        let mut f = fixture(3, base);
        let second = f.another_target();
        let first = f.prepare(1, b"atomic-first");
        let later = f.prepare_for(second, second_amount, b"atomic-second");
        assert_eq!(
            (first.base_relief().mantissa, later.base_relief().mantissa),
            relief
        );
        let batch = f.h.batch(
            b"atomic-fx",
            vec![first.into_proposal(), later.into_proposal()],
        );
        let head = f.h.db.frontier().unwrap();
        let posted = f.post_fx_batch(batch.clone()).unwrap();
        assert!(!posted.already_recorded);
        assert_eq!(posted.entries.len(), 2);
        assert_eq!(posted.recorded_at.0, head.0 + 1);
        for entry in &posted.entries {
            assert_eq!(
                read_entry(&f.h.db, entry.vid).unwrap().unwrap().1,
                posted.recorded_at
            );
        }
        for (target, expected) in [(f.target, remaining_first), (second, remaining_second)] {
            let item = f.carrying_for(target);
            assert_eq!(
                (item.open_native.mantissa, item.open_base.mantissa),
                expected
            );
        }
        f.verify();
        let rows = f.h.db.vertices().unwrap();
        let retry = f.post_fx_batch(batch).unwrap();
        assert!(retry.already_recorded);
        assert_eq!(retry.entries, posted.entries);
        assert_eq!(retry.recorded_at, posted.recorded_at);
        assert_eq!(f.h.db.frontier().unwrap(), posted.recorded_at);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        let reversals = posted
            .entries
            .iter()
            .enumerate()
            .map(|(index, target)| {
                let (entry, _) = read_entry(&f.h.db, target.vid).unwrap().unwrap();
                undo(
                    &entry.proposal,
                    *target,
                    format!("undo-independent-{index}").as_bytes(),
                )
            })
            .collect();
        let undo_batch = f.h.batch(b"undo-independent-fx", reversals);
        let undone = f.h.post_batch(undo_batch).unwrap();
        assert_eq!(undone.recorded_at.0, posted.recorded_at.0 + 1);
        for target in [f.target, second] {
            let item = f.carrying_for(target);
            assert_eq!(
                (item.open_native.mantissa, item.open_base.mantissa),
                (3, base)
            );
        }
        f.verify();
    }
}

#[test]
fn overlapping_fx_batch_targets_refuse_even_when_the_second_digest_is_forged() {
    for forged in [false, true] {
        let mut f = fixture(3, 10);
        let first = f.prepare(1, b"overlap-first").into_proposal();
        let mut second = f.prepare(1, b"overlap-second").into_proposal();
        if forged {
            second.legs[0].settles[0].target.entry_digest[0] ^= 1;
        }
        let batch = f.h.batch(b"overlap-fx", vec![first, second]);
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let refusal = f.post_fx_batch(batch).unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-071", 3));
        assert!(refusal.message.contains("distinct existing target legs"));
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert_eq!(f.carrying().open_base.mantissa, 10);
    }
}

#[test]
fn mixed_fx_batches_and_post_only_authority_cannot_publish_any_member() {
    for fx_first in [false, true] {
        let mut f = fixture(3, 10);
        let fx = f.prepare(1, b"mixed-fx").into_proposal();
        let plain =
            f.h.proposal(f.h.rent_legs(1), b"mixed-plain", EntryClass::ORIGINAL);
        let members = if fx_first {
            vec![fx, plain]
        } else {
            vec![plain, fx]
        };
        let batch = f.h.batch(b"mixed", members);
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let refusal = f.post_fx_batch(batch).unwrap_err();
        assert_eq!(
            refusal.code,
            fa_journal::refusal::code::CLASS_NOT_IMPLEMENTED
        );
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
    }
    let mut f = fixture(3, 10);
    let other = f.another_target();
    let batch = f.h.batch(
        b"post-only-fx",
        vec![
            f.prepare(1, b"post-only-first").into_proposal(),
            f.prepare_for(other, 1, b"post-only-second").into_proposal(),
        ],
    );
    let head = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    let refusal = f.h.post_batch(batch).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-011", 7));
    assert_eq!(f.h.db.frontier().unwrap(), head);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
}

#[test]
fn an_invalid_later_fx_member_or_staged_target_rolls_back_the_complete_batch() {
    for staged_target in [false, true] {
        let mut f = fixture(3, 10);
        let other = f.another_target();
        let first = f.prepare(1, b"rollback-first").into_proposal();
        let mut second = f.prepare_for(other, 1, b"rollback-second").into_proposal();
        if staged_target {
            second.legs[0].settles[0].target = f.h.member_ref(&first);
        } else {
            for leg in &mut second.legs[..2] {
                leg.base_amount.as_mut().unwrap().mantissa += 1;
            }
            let totals = second.base_totals.as_mut().unwrap();
            totals.debits += 1;
            totals.credits += 1;
        }
        let batch = f.h.batch(b"rollback-fx", vec![first, second]);
        let outcome = fa_journal::batch::outcome_vid(&f.h.book, &batch);
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let refusal = f.post_fx_batch(batch).unwrap_err();
        assert_eq!(
            (refusal.code, refusal.exit),
            ("FA-REF-071", 3),
            "{refusal:?}"
        );
        assert!(refusal.message.contains("member 1"));
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert!(f.h.db.vertex(outcome).unwrap().is_none());
        assert_eq!(f.carrying().open_base.mantissa, 10);
        assert_eq!(f.carrying_for(other).open_base.mantissa, 10);
    }
}

#[test]
fn portable_independent_fx_batch_refuses_stale_basis_then_replans_and_retries_exactly() {
    for source_change in [false, true] {
        let mut f = fixture(3, 10);
        let other = f.another_target();
        let batch = f.h.batch(
            b"portable-fx",
            vec![
                f.prepare(1, b"portable-first").into_proposal(),
                f.prepare_for(other, 1, b"portable-second").into_proposal(),
            ],
        );
        let capability = Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap();
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let plan = f.h.planned_batch(batch.clone(), &capability).unwrap();
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        let portable = plan.canonical_bytes().unwrap();
        if source_change {
            f.h.post(request(
                f.prepare(1, b"intervening-application").into_proposal(),
            ))
            .unwrap();
        } else {
            let doc =
                f.h.document(INVOICE, HUMAN_UPLOAD, b"unrelated retained evidence");
            f.h.add_document(&doc).unwrap();
        }
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let refusal =
            f.h.publish_batch_plan(
                fa_intents::BatchPlan::decode(&portable).unwrap(),
                &capability,
            )
            .unwrap_err();
        assert_eq!(
            (refusal.code, refusal.exit),
            (fa_journal::refusal::code::PLAN_INVALIDATED, 6)
        );
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        let current = f.h.batch(
            b"portable-fx",
            vec![
                f.prepare(1, b"portable-first").into_proposal(),
                f.prepare_for(other, 1, b"portable-second").into_proposal(),
            ],
        );
        let fresh = f.h.planned_batch(current, &capability).unwrap();
        let posted = f.h.publish_batch_plan(fresh.clone(), &capability).unwrap();
        assert_eq!(posted.recorded_at.0, head.0 + 1);
        let first = f.carrying();
        assert_eq!(
            (first.open_native.mantissa, first.open_base.mantissa),
            if source_change { (1, 3) } else { (2, 7) }
        );
        let second = f.carrying_for(other);
        assert_eq!(
            (second.open_native.mantissa, second.open_base.mantissa),
            (2, 7)
        );
        f.verify();
        let retry = f.h.publish_batch_plan(fresh, &capability).unwrap();
        assert!(retry.already_recorded);
        assert_eq!(retry.entries, posted.entries);
        assert_eq!(f.h.db.frontier().unwrap(), posted.recorded_at);
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
        leg.settles.clear();
    }
    reversed.unit_totals = EntryPayload::fold_unit_totals(&reversed.legs).unwrap();
    reversed
}

#[test]
fn remaining_carrying_relief_matches_independent_limb_oracle() {
    let native_unit = UnitId(2);
    let base_unit = UnitId(1);
    let stripped = Cx::detached_cancel_context();
    let mut comparisons = 0;
    for native in 1..=31 {
        for base in 0..=31 {
            for application in 1..=native {
                let mut budget =
                    ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
                let actual = fa_journal::carrying::remaining_carrying_relief(
                    &mut budget,
                    Amount::new(native_unit, native),
                    Amount::new(base_unit, base),
                    Amount::new(native_unit, application),
                )
                .unwrap();
                assert_eq!(
                    actual,
                    Amount::new(
                        base_unit,
                        fa_reference::fx::remaining_carrying_relief(native, base, application)
                            .unwrap(),
                    ),
                    "native={native}, base={base}, application={application}",
                );
                comparisons += 1;
            }
        }
    }
    assert_eq!(comparisons, 15_872);
    for (native, base, application) in [
        (i128::MAX, i128::MAX, i128::MAX - 1),
        (i128::MAX, i128::MAX - 1, i128::MAX - 2),
        (2, i128::MAX, 1),
        (1, i128::MAX, 1),
    ] {
        let mut budget =
            ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
        assert_eq!(
            fa_journal::carrying::remaining_carrying_relief(
                &mut budget,
                Amount::new(native_unit, native),
                Amount::new(base_unit, base),
                Amount::new(native_unit, application),
            )
            .unwrap()
            .mantissa,
            fa_reference::fx::remaining_carrying_relief(native, base, application).unwrap(),
        );
    }
}

#[test]
fn application_relief_agrees_with_reference_over_reversals_and_remainders() {
    let mut saw_recorded_relief_differ_from_current_proportion = false;
    for (native, base, applications) in [
        (3, 10, vec![1, 1, 1]),
        (2, 1, vec![1, 1]),
        (3, 2, vec![1, 1, 1]),
        (3, 1, vec![2, 1]),
        (7, 5, vec![2, 3, 2]),
        (8, 3, vec![4, 1, 3]),
        (1_000, 1_050, vec![400, 100, 500]),
    ] {
        let mut f = fixture(native, base);
        let mut expected_native = native;
        let mut expected_base = base;
        let mut snapshots = vec![(f.h.db.frontier().unwrap(), native, base)];
        let mut recorded = Vec::new();
        for (index, application) in applications.into_iter().enumerate() {
            let relief = fa_reference::fx::remaining_carrying_relief(
                expected_native,
                expected_base,
                application,
            )
            .unwrap();
            let before = f.h.db.frontier().unwrap();
            let prepared = f.prepare(application, format!("oracle-apply-{index}").as_bytes());
            assert_eq!(f.h.db.frontier().unwrap(), before);
            assert_eq!(prepared.carrying().open_native.mantissa, expected_native);
            assert_eq!(prepared.carrying().open_base.mantissa, expected_base);
            assert_eq!(prepared.base_relief(), Amount::new(f.h.usd, relief));
            let proposal = prepared.into_proposal();
            let posted = f.h.post(request(proposal.clone())).unwrap();
            recorded.push((proposal, posted.entry_ref(), application, relief));
            expected_native = expected_native.checked_sub(application).unwrap();
            expected_base = expected_base.checked_sub(relief).unwrap();
            let current = f.carrying();
            assert_eq!(current.open_native.mantissa, expected_native);
            assert_eq!(current.open_base.mantissa, expected_base);
            assert_eq!(current.applied_native.mantissa, native - expected_native);
            assert_eq!(current.applied_base.mantissa, base - expected_base);
            snapshots.push((f.h.db.frontier().unwrap(), expected_native, expected_base));
            f.verify();
        }
        assert_eq!((expected_native, expected_base), (0, 0));
        for (index, (proposal, target, application, relief)) in recorded.iter().enumerate() {
            if let Ok(recomputed) = fa_reference::fx::remaining_carrying_relief(
                expected_native,
                expected_base,
                *application,
            ) {
                saw_recorded_relief_differ_from_current_proportion |= recomputed != *relief;
            }
            f.h.post(request(undo(
                proposal,
                *target,
                format!("oracle-undo-{index}").as_bytes(),
            )))
            .unwrap();
            expected_native = expected_native.checked_add(*application).unwrap();
            expected_base = expected_base.checked_add(*relief).unwrap();
            assert_eq!(f.carrying().open_native.mantissa, expected_native);
            assert_eq!(f.carrying().open_base.mantissa, expected_base);
            snapshots.push((f.h.db.frontier().unwrap(), expected_native, expected_base));
            f.verify();
        }
        assert_eq!((expected_native, expected_base), (native, base));
        for (at, expected_native, expected_base) in snapshots {
            let historical = open_item_carrying_at(&f.h.db, &f.h.ctx(), &f.h.book, f.target, 0, at)
                .unwrap()
                .unwrap();
            assert_eq!(historical.open_native.mantissa, expected_native);
            assert_eq!(historical.open_base.mantissa, expected_base);
        }
    }
    assert!(saw_recorded_relief_differ_from_current_proportion);
}

#[test]
fn historical_fx_and_carrying_ignore_later_book_spec_damage() {
    let mut f = fixture(3, 10);
    let settlement = f.prepare(1, b"historical-settlement").into_proposal();
    f.h.post(request(settlement)).unwrap();
    let at = f.h.db.frontier().unwrap();
    let expected_carrying = f.carrying();
    let cx = f.h.ctx();
    let expected_verification = cx
        .query()
        .with_restriction(|| verify_fx_conversions(&f.h.db, &cx, &f.h.book, at))
        .unwrap();
    assert!(expected_verification.is_green());
    assert_eq!(
        expected_verification.checked.get("SettlementCarryingBasis"),
        Some(&1),
    );

    // Corrupt only a later root. Both the outer FX fold and its nested
    // source-bound carrying check must retain their selected BookSpec.
    let mut spec = fa_journal::genesis::read_book_spec(&f.h.db)
        .unwrap()
        .unwrap();
    spec.base_unit = f.foreign;
    let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
    damage.set_vertex_property(
        book_root(),
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(spec.canonical_bytes().unwrap()).unwrap()),
    );
    f.h.write_raw(damage);

    assert_eq!(
        open_item_carrying_at(&f.h.db, &cx, &f.h.book, f.target, 0, at)
            .unwrap()
            .unwrap(),
        expected_carrying,
    );
    assert_eq!(
        cx.query()
            .with_restriction(|| verify_fx_conversions(&f.h.db, &cx, &f.h.book, at))
            .unwrap(),
        expected_verification,
    );
    let head = f.h.db.frontier().unwrap();
    assert!(
        open_item_carrying_at(&f.h.db, &cx, &f.h.book, f.target, 0, head)
            .unwrap()
            .is_err(),
    );
    assert!(
        !cx.query()
            .with_restriction(|| verify_fx_conversions(&f.h.db, &cx, &f.h.book, head))
            .unwrap()
            .is_green(),
    );
}

#[test]
fn historical_fx_and_carrying_reject_selected_book_context_mismatches() {
    let mut f = fixture(3, 10);
    let original = fa_journal::genesis::read_book_spec(&f.h.db)
        .unwrap()
        .unwrap();
    for mismatch in ["book", "calendar"] {
        let mut changed = original.clone();
        match mismatch {
            "book" => changed.book_id = Id128([0xbb; 16]),
            "calendar" => changed.calendar.id.push_str("-changed"),
            _ => unreachable!(),
        }
        let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
        damage.set_vertex_property(
            book_root(),
            property::FA_PAYLOAD,
            Some(CanonicalScalar::bytes(changed.canonical_bytes().unwrap()).unwrap()),
        );
        f.h.write_raw(damage);
        let at = f.h.db.frontier().unwrap();
        let mut restore = fgdb::WriteBatch::new(relation::IN_BOOK);
        restore.set_vertex_property(
            book_root(),
            property::FA_PAYLOAD,
            Some(CanonicalScalar::bytes(original.canonical_bytes().unwrap()).unwrap()),
        );
        f.h.write_raw(restore);

        let cx = f.h.ctx();
        let carrying = open_item_carrying_at(&f.h.db, &cx, &f.h.book, f.target, 0, at).unwrap_err();
        assert!(
            matches!(carrying, KernelError::Corrupt(ref reason) if reason.contains("selected root")),
            "{mismatch}: {carrying}",
        );
        let verification = cx
            .query()
            .with_restriction(|| verify_fx_conversions(&f.h.db, &cx, &f.h.book, at))
            .unwrap_err();
        assert!(
            matches!(verification, KernelError::Corrupt(ref reason) if reason.contains("selected root")),
            "{mismatch}: {verification}",
        );
        f.verify();
        assert_eq!(f.carrying().open_base.mantissa, 10);
    }
}

#[test]
fn foreign_partial_final_and_reversed_applications_restore_recorded_base() {
    let mut f = fixture(3, 10);
    let first = f.prepare(1, b"first");
    assert_eq!(first.base_relief().mantissa, 3);
    let proposal = first.into_proposal();
    let posted = f.h.post(request(proposal.clone())).unwrap();
    assert_eq!(
        (
            f.carrying().open_native.mantissa,
            f.carrying().open_base.mantissa
        ),
        (2, 7)
    );
    // The same typed request reconstructs its original prefix, even though
    // the target is now partly closed. No new amount is computed on retry.
    let retry = f.prepare(1, b"first").into_proposal();
    assert_eq!(retry, proposal);
    let before = f.h.db.frontier().unwrap();
    assert_eq!(
        f.h.post(request(retry)).unwrap().entry_ref(),
        posted.entry_ref()
    );
    assert_eq!(f.h.db.frontier().unwrap(), before);

    let mut reverse = proposal;
    reverse.class = EntryClass::REVERSAL;
    reverse.idempotency_key = b"undo-first".to_vec();
    reverse.supersession = vec![Supersession {
        kind: SupersessionKind::Reverses,
        target: posted.entry_ref(),
        reason_code: 1,
    }];
    for leg in &mut reverse.legs {
        leg.side = leg.side.flipped();
        leg.settles.clear();
    }
    reverse.unit_totals = EntryPayload::fold_unit_totals(&reverse.legs).unwrap();
    f.h.post(request(reverse)).unwrap();
    assert_eq!(
        (
            f.carrying().open_native.mantissa,
            f.carrying().open_base.mantissa
        ),
        (3, 10)
    );

    for (key, expected) in [
        (b"again".as_slice(), 3),
        (b"second".as_slice(), 4),
        (b"final".as_slice(), 3),
    ] {
        let plan = f.prepare(1, key);
        assert_eq!(plan.base_relief().mantissa, expected);
        f.h.post(request(plan.into_proposal())).unwrap();
    }
    let closed = f.carrying();
    assert_eq!(
        (closed.open_native.mantissa, closed.open_base.mantissa),
        (0, 0)
    );
    assert_eq!(
        (closed.applied_native.mantissa, closed.applied_base.mantissa),
        (3, 10)
    );
    f.verify();
}

#[test]
fn zero_rounded_relief_and_final_base_remainder_post_without_a_plug() {
    let mut f = fixture(2, 1);
    let first = f.prepare(1, b"zero-relief");
    assert_eq!(first.base_relief().mantissa, 0);
    let proposal = first.into_proposal();
    assert_eq!(proposal.legs.len(), 4);
    assert!(proposal.legs.iter().all(|leg| leg.amount.mantissa > 0));
    let posted = f.h.post(request(proposal.clone())).unwrap();
    f.verify();
    f.h.post(request(undo(&proposal, posted.entry_ref(), b"undo-zero")))
        .unwrap();
    assert_eq!(
        (
            f.carrying().open_native.mantissa,
            f.carrying().open_base.mantissa
        ),
        (2, 1),
    );
    f.verify();
    let repeated = f.prepare(1, b"zero-again").into_proposal();
    f.h.post(request(repeated)).unwrap();
    let last = f.prepare(1, b"remainder");
    assert_eq!(last.base_relief().mantissa, 1);
    f.h.post(request(last.into_proposal())).unwrap();
    assert_eq!(f.carrying().open_base.mantissa, 0);
    f.verify();
}

#[test]
fn a_batch_of_exact_undos_restores_both_recorded_reliefs_at_one_prefix() {
    let mut f = fixture(3, 10);
    let first = f.prepare(1, b"batch-first").into_proposal();
    let first_ref = f.h.post(request(first.clone())).unwrap().entry_ref();
    let second = f.prepare(1, b"batch-second").into_proposal();
    let second_ref = f.h.post(request(second.clone())).unwrap().entry_ref();
    assert_eq!(
        (
            f.carrying().open_native.mantissa,
            f.carrying().open_base.mantissa
        ),
        (1, 3)
    );
    let before = f.h.db.frontier().unwrap();
    let batch = f.h.batch(
        b"undo-both",
        vec![
            undo(&second, second_ref, b"undo-batch-second"),
            undo(&first, first_ref, b"undo-batch-first"),
        ],
    );
    f.h.post_batch(batch).unwrap();
    assert_eq!(f.h.db.frontier().unwrap().0, before.0 + 1);
    assert_eq!(
        (
            f.carrying().open_native.mantissa,
            f.carrying().open_base.mantissa
        ),
        (3, 10)
    );
    assert_eq!(f.prepare(1, b"after-both-undos").base_relief().mantissa, 3);
    f.verify();
}

#[test]
fn unvalued_foreign_application_cannot_bypass_the_carrying_law() {
    let mut f = fixture(3, 10);
    let amount = Amount::new(f.foreign, 1);
    let mut applying =
        LegPayload::simple(Side::Credit, account_vid(f.h.book.book_id, "1211"), amount);
    applying.settles = vec![fa_model::Settlement {
        target: f.target,
        ordinal: 0,
        amount,
    }];
    let proposal = f.h.proposal(
        vec![
            LegPayload::simple(Side::Debit, account_vid(f.h.book.book_id, "4011"), amount),
            applying,
        ],
        b"unvalued-foreign-application",
        EntryClass::ORIGINAL,
    );
    let before = f.h.db.frontier().unwrap();
    let refusal = f.h.post(request(proposal)).unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::SETTLE_SHAPE);
    assert!(refusal.message.contains("RemainingCarryingValue"));
    assert_eq!(f.h.db.frontier().unwrap(), before);
    let item = f.carrying();
    assert_eq!(
        (item.open_native.mantissa, item.open_base.mantissa),
        (3, 10)
    );
}

#[test]
fn malformed_conversion_or_extra_foreign_effects_are_refused_atomically() {
    let mut f = fixture(3, 10);
    let valid = f.prepare(1, b"malformed-conversion").into_proposal();
    let mut malformed = valid.clone();
    malformed.legs[1].account_ref = malformed.legs[0].account_ref;
    let before = f.h.db.frontier().unwrap();
    let refusal = f.h.post(request(malformed)).unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::SETTLE_SHAPE);
    let mut extra = valid;
    let mut foreign = extra.legs[0].clone();
    foreign.settles.clear();
    extra.legs.push(foreign.clone());
    foreign.side = foreign.side.flipped();
    extra.legs.push(foreign);
    extra.unit_totals = EntryPayload::fold_unit_totals(&extra.legs).unwrap();
    let totals = extra.base_totals.as_mut().unwrap();
    totals.debits += 3;
    totals.credits += 3;
    let refusal = f.h.post(request(extra)).unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::SETTLE_SHAPE);
    assert_eq!(f.h.db.frontier().unwrap(), before);
}

#[test]
fn caller_supplied_balanced_false_carrying_basis_is_refused_atomically() {
    let mut f = fixture(3, 10);
    let mut proposal = f.prepare(1, b"false-basis").into_proposal();
    // Rebuild a fully balanced FX proposal using the old low-level helper,
    // with a fabricated historical basis. Shape and rate checks alone pass.
    let raw = f.h.db.vertex(document_vid(&f.rate)).unwrap().unwrap();
    let record = fa_journal::evidence::DocumentRecord::decode(
        &fa_journal::rows::bytes(&raw, property::FA_PAYLOAD, "rate").unwrap(),
    )
    .unwrap();
    let Storage::Inline(bytes) = record.storage else {
        panic!("fixture rate must be inline")
    };
    let rate = FxRateDocument::decode(&bytes).unwrap();
    let template = f.h.proposal(vec![], b"false-basis", EntryClass::ORIGINAL);
    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
    let applications = proposal.legs[0].settles.clone();
    proposal = plan_realized_fx_settlement(
        &mut budget,
        template,
        proposal.legs[0].account_ref,
        Side::Credit,
        Amount::new(f.foreign, 1),
        Amount::new(f.h.usd, 9),
        f.h.cash,
        f.conversion,
        f.realized,
        &rate,
        vec![],
        &f.h.book.units,
    )
    .unwrap();
    proposal.legs[0].settles = applications;
    let before = f.h.db.frontier().unwrap();
    let refused = f.h.post(request(proposal)).unwrap_err();
    assert_eq!(refused.code, fa_journal::refusal::code::SETTLE_SHAPE);
    assert!(refused.message.contains("journal-derived"));
    assert_eq!(f.h.db.frontier().unwrap(), before);
    assert_eq!(f.carrying().open_base.mantissa, 10);
}

#[test]
fn an_intervening_post_invalidates_the_foreign_settlement_aggregate() {
    let mut f = fixture(3, 10);
    let proposal = f.prepare(1, b"racing-settlement").into_proposal();
    let ctx = f.h.ctx();
    let staged = prepare_post(&mut f.h.db, &ctx, &f.h.book, request(proposal))
        .unwrap()
        .unwrap();
    let PostPreparation::Ready(prepared) = staged else {
        panic!("new plan")
    };
    let unrelated =
        f.h.proposal(f.h.rent_legs(1), b"unrelated", EntryClass::ORIGINAL);
    f.h.post(request(unrelated)).unwrap();
    let before = f.h.db.frontier().unwrap();
    let refusal =
        f.h.runtime
            .block_on(prepared.commit(&mut f.h.db, &ctx))
            .unwrap()
            .unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::PLAN_INVALIDATED);
    assert_eq!(f.h.db.frontier().unwrap(), before);
    assert_eq!(f.carrying().open_base.mantissa, 10);
}
