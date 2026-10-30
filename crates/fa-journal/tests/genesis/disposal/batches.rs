//! Atomic composition retains each lot account's independent source law.

use super::*;
use fa_journal::refusal::code;

fn capability() -> Capability {
    Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap()
}

impl Fixture {
    fn another_inventory(&mut self, law: LotLaw) -> (VId, [EntryRef; 2]) {
        let h = &mut self.h;
        let cx = h.ctx();
        let day = h.day();
        let account = AccountSpec {
            code: "1410".into(),
            name: "Second inventory".into(),
            account_type: fa_model::AccountType::ASSET.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyUnit,
            parent_code: None,
            limit: None,
        };
        let description = h
            .proposal(vec![], b"second-lot-chart", EntryClass::ORIGINAL)
            .description;
        h.runtime
            .block_on(install_chart(
                &mut h.db,
                &cx,
                &h.book,
                &[account],
                PRINCIPAL,
                day,
                b"second-lot-chart",
                description,
                &Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        let inventory = account_vid(h.book.book_id, "1410");
        let request = LotPolicyRequest {
            principal: PRINCIPAL,
            policy: LotPolicy {
                account: inventory,
                law,
                regime: AccountingRegime::UsGaap,
                rounding_law: RoundingLaw::HalfEven,
            },
            effective_date: day,
            idempotency_key: b"second-lot-policy".to_vec(),
            description: h
                .proposal(vec![], b"second-lot-policy", EntryClass::ORIGINAL)
                .description,
            approvals: vec![],
        };
        h.runtime
            .block_on(set_lot_policy(
                &mut h.db,
                &cx,
                &h.book,
                &Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap(),
                request,
            ))
            .unwrap()
            .unwrap();
        let acquisitions = [
            (b"other-lot-one".as_slice(), 70),
            (b"other-lot-two".as_slice(), 30),
        ]
        .map(|(key, cost)| {
            let proposal = h.proposal(
                vec![
                    LegPayload::simple(Side::Debit, inventory, Amount::new(self.share, 10)),
                    LegPayload::simple(
                        Side::Credit,
                        self.quantity_offset,
                        Amount::new(self.share, 10),
                    ),
                    LegPayload::simple(Side::Debit, inventory, Amount::new(h.usd, cost)),
                    LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, cost)),
                ],
                key,
                EntryClass::ORIGINAL,
            );
            h.post(posting(proposal)).unwrap().entry_ref()
        });
        (inventory, acquisitions)
    }

    fn disposal_pair(&self, other: VId, key: &str) -> fa_intents::PostBatch {
        let first = self.prepare(12, format!("{key}-first").as_bytes()).unwrap();
        let mut request = self.request(12);
        request.account = other;
        let second = self
            .prepare_request(&request, format!("{key}-second").as_bytes())
            .unwrap();
        self.h.batch(
            key.as_bytes(),
            vec![first.into_proposal(), second.into_proposal()],
        )
    }

    fn post_disposals(
        &mut self,
        batch: fa_intents::PostBatch,
        capability: &Capability,
    ) -> Result<BatchPosted, Refusal> {
        let cx = self.h.ctx();
        self.h
            .runtime
            .block_on(fa_journal::post_batch(
                &mut self.h.db,
                &cx,
                &self.h.book,
                capability.clone(),
                batch,
            ))
            .expect("disposal batch kernel")
    }
}

fn applied_totals(h: &Harness, acquisitions: &[EntryRef; 2]) -> (i128, i128) {
    let total = |ordinal| {
        h.applied_to(acquisitions[0].vid, ordinal)
            .checked_add(h.applied_to(acquisitions[1].vid, ordinal))
            .unwrap()
    };
    (total(0), total(2))
}

#[test]
fn independent_lot_disposals_share_one_publication_and_external_offsets() {
    for (law, expected) in [
        (LotLaw::Fifo, (104, 76)),
        (LotLaw::Lifo, (40, 44)),
        (LotLaw::WeightedAverage, (72, 60)),
        (LotLaw::SpecificId, (40, 44)),
    ] {
        let mut f = Fixture::new(law);
        let (other, acquisitions) = f.another_inventory(law);
        let mut first_request = f.request(12);
        let mut second_request = f.request(12);
        second_request.account = other;
        if law == LotLaw::SpecificId {
            first_request.specific_ids = vec![(f.acquisitions[1], 0), (f.acquisitions[0], 0)];
            second_request.specific_ids = vec![(acquisitions[1], 0), (acquisitions[0], 0)];
        }
        let first = f
            .prepare_request(&first_request, b"atomic-lot-first")
            .unwrap();
        let second = f
            .prepare_request(&second_request, b"atomic-lot-second")
            .unwrap();
        assert_eq!(
            (
                first.outcome().total_relieved_cost,
                second.outcome().total_relieved_cost
            ),
            expected
        );
        let batch = f.h.batch(
            b"atomic-lots",
            vec![first.into_proposal(), second.into_proposal()],
        );
        let before = f.h.db.frontier().unwrap();
        let posted = f.post_disposals(batch.clone(), &capability()).unwrap();
        assert!(!posted.already_recorded);
        assert_eq!(posted.entries.len(), 2);
        assert_eq!(posted.recorded_at.0, before.0 + 1);
        for reference in &posted.entries {
            assert_eq!(
                read_entry(&f.h.db, reference.vid).unwrap().unwrap().1,
                posted.recorded_at
            );
        }
        assert_eq!(applied_totals(&f.h, &f.acquisitions), (12, expected.0));
        assert_eq!(applied_totals(&f.h, &acquisitions), (12, expected.1));
        let rows = f.h.db.vertices().unwrap();
        let retry = f.post_disposals(batch, &capability()).unwrap();
        assert!(retry.already_recorded);
        assert_eq!(retry.entries, posted.entries);
        assert_eq!(retry.recorded_at, posted.recorded_at);
        assert_eq!(f.h.db.frontier().unwrap(), posted.recorded_at);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn a_false_later_lot_relief_rolls_back_every_member_and_application() {
    for staged_target in [false, true] {
        let mut f = Fixture::new(LotLaw::Fifo);
        let (other, acquisitions) = f.another_inventory(LotLaw::Fifo);
        let first = f
            .prepare(12, b"rollback-lot-first")
            .unwrap()
            .into_proposal();
        let mut request = f.request(12);
        request.account = other;
        let mut second = f
            .prepare_request(&request, b"rollback-lot-second")
            .unwrap()
            .into_proposal();
        if staged_target {
            second.legs[0].settles[0].target = f.h.member_ref(&first);
        } else {
            // Keep the entry balanced; the source law must reject the cost plug.
            second.legs[2].amount.mantissa += 1;
            second.legs[3].amount.mantissa += 1;
            second.unit_totals = EntryPayload::fold_unit_totals(&second.legs).unwrap();
        }
        let batch = f.h.batch(b"rollback-lots", vec![first, second]);
        let outcome = fa_journal::batch::outcome_vid(&f.h.book, &batch);
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let refusal = f.post_disposals(batch, &capability()).unwrap_err();
        assert_eq!(
            (refusal.code, refusal.exit),
            (code::SETTLE_SHAPE, 3),
            "{refusal}"
        );
        assert!(refusal.message.contains("member 1"), "{refusal}");
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert!(f.h.db.vertex(outcome).unwrap().is_none());
        assert_eq!(applied_totals(&f.h, &f.acquisitions), (0, 0));
        assert_eq!(applied_totals(&f.h, &acquisitions), (0, 0));
    }
}

#[test]
fn same_account_lot_batches_refuse_even_with_distinct_policy_handles() {
    for forged in [false, true] {
        let mut f = Fixture::new(LotLaw::Fifo);
        let first = f.prepare(12, b"same-lot-first").unwrap().into_proposal();
        let mut second = f.prepare(12, b"same-lot-second").unwrap().into_proposal();
        if forged {
            let mut basis = second.lot_disposal_basis().unwrap().unwrap();
            basis.policy.entry_digest[0] ^= 1;
            second.set_lot_disposal_basis(&basis).unwrap();
        }
        let batch = f.h.batch(b"same-lot-account", vec![first, second]);
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let refusal = f.post_disposals(batch, &capability()).unwrap_err();
        assert_eq!(refusal.code, code::SETTLE_SHAPE);
        assert!(
            refusal
                .message
                .contains("distinct governed source accounts"),
            "{refusal}"
        );
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn cross_source_lot_offsets_and_mixed_batches_refuse_in_either_order() {
    for offset in [None, Some(false), Some(true)] {
        for reverse in [false, true] {
            let mut f = Fixture::new(LotLaw::Fifo);
            let (other, _) = f.another_inventory(LotLaw::Fifo);
            let mut first_request = f.request(12);
            if let Some(quantity) = offset {
                if quantity {
                    first_request.quantity_offset_account = other;
                } else {
                    first_request.cost_offset_account = other;
                }
            }
            let first = f
                .prepare_request(&first_request, b"coupled-lot-first")
                .unwrap()
                .into_proposal();
            let second = if offset.is_some() {
                let mut request = f.request(12);
                request.account = other;
                f.prepare_request(&request, b"coupled-lot-second")
                    .unwrap()
                    .into_proposal()
            } else {
                f.h.proposal(f.h.rent_legs(1), b"mixed-ordinary", EntryClass::ORIGINAL)
            };
            let mut members = vec![first, second];
            if reverse {
                members.reverse();
            }
            let batch = f.h.batch(b"coupled-lots", members);
            let head = f.h.db.frontier().unwrap();
            let rows = f.h.db.vertices().unwrap();
            let refusal = f.post_disposals(batch, &capability()).unwrap_err();
            assert_eq!(
                refusal.code,
                if offset.is_some() {
                    code::SETTLE_SHAPE
                } else {
                    code::CLASS_NOT_IMPLEMENTED
                }
            );
            assert_eq!(f.h.db.frontier().unwrap(), head);
            assert_eq!(f.h.db.vertices().unwrap(), rows);
        }
    }
}

#[test]
fn disposal_batches_require_current_whole_book_read_and_post_authority() {
    let mut f = Fixture::new(LotLaw::Fifo);
    let (other, _) = f.another_inventory(LotLaw::Fifo);
    let batch = f.disposal_pair(other, "lot-authority");
    for denied in [
        Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        capability()
            .for_accounts(&["1400", "1410", "1499", "5100"])
            .unwrap(),
    ] {
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        assert_eq!(
            f.post_disposals(batch.clone(), &denied).unwrap_err().exit,
            7
        );
        assert_eq!(
            f.h.planned_batch(batch.clone(), &denied).unwrap_err().exit,
            7
        );
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
    }
    let cap = capability();
    let plan = f.h.planned_batch(batch.clone(), &cap).unwrap();
    let posted = f.h.publish_batch_plan(plan.clone(), &cap).unwrap();
    f.h.revoke(&cap, 206);
    let head = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    for refusal in [
        f.post_disposals(batch, &cap).unwrap_err(),
        f.h.publish_batch_plan(plan, &cap).unwrap_err(),
    ] {
        assert_eq!(refusal.exit, 7);
        assert!(refusal.message.contains("revoked"), "{refusal}");
    }
    assert!(head > posted.recorded_at);
    assert_eq!(f.h.db.frontier().unwrap(), head);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
}

#[test]
fn portable_lot_batch_replans_after_any_publication_and_retries_after_later_activity() {
    for source_change in [false, true] {
        let mut f = Fixture::new(LotLaw::Fifo);
        let (other, acquisitions) = f.another_inventory(LotLaw::Fifo);
        let cap = capability().with_requires_dry_run();
        let batch = f.disposal_pair(other, "portable-lots");
        let before = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let refusal = f.post_disposals(batch.clone(), &cap).unwrap_err();
        assert!(refusal.message.contains("requires_dry_run"), "{refusal}");
        let plan = f.h.planned_batch(batch.clone(), &cap).unwrap();
        assert_eq!(f.h.db.frontier().unwrap(), before);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        let portable = plan.canonical_bytes().unwrap();
        if source_change {
            f.buy(b"between-lot-plan-and-commit", 10, 1);
        } else {
            let document =
                f.h.document(INVOICE, HUMAN_UPLOAD, b"unrelated lot batch evidence");
            f.h.add_document(&document).unwrap();
        }
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let refusal =
            f.h.publish_batch_plan(fa_intents::BatchPlan::decode(&portable).unwrap(), &cap)
                .unwrap_err();
        assert_eq!((refusal.code, refusal.exit), (code::PLAN_INVALIDATED, 6));
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        // The stale proposals cannot bypass the portable plan through direct posting.
        let refusal = f.post_disposals(batch, &capability()).unwrap_err();
        assert_eq!(refusal.code, code::PLAN_INVALIDATED);
        let fresh = f.disposal_pair(other, "portable-lots");
        let plan = f.h.planned_batch(fresh, &cap).unwrap();
        let posted = f.h.publish_batch_plan(plan.clone(), &cap).unwrap();
        assert_eq!(posted.recorded_at.0, head.0 + 1);
        assert_eq!(applied_totals(&f.h, &f.acquisitions), (12, 104));
        assert_eq!(applied_totals(&f.h, &acquisitions), (12, 76));
        f.buy(b"after-lot-batch", 1, 1);
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let retry = f.h.publish_batch_plan(plan, &cap).unwrap();
        assert!(retry.already_recorded);
        assert_eq!(retry.entries, posted.entries);
        assert_eq!(retry.recorded_at, posted.recorded_at);
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
    }
}
