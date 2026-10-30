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

impl Fixture {
    fn agent_disposal(&self, request: &LotDisposalRequest, key: &[u8]) -> EntryPayload {
        let mut template = self.h.proposal(vec![], key, EntryClass::ORIGINAL);
        template.principal_ref = AGENT;
        prepare_lot_disposal(
            &self.h.db,
            &self.h.ctx(),
            &self.h.book,
            &self.h.agent_capability(),
            request,
            template,
        )
        .unwrap()
        .unwrap()
        .into_proposal()
    }

    fn plan_lot_pair(
        &mut self,
        name: &str,
        other: VId,
        other_acquisitions: [EntryRef; 2],
        law: LotLaw,
    ) -> Vec<EntryRef> {
        let agent = self.h.agent_capability();
        self.h.open_draft(agent.clone(), name).unwrap();
        let mut first = self.request(12);
        let mut second = self.request(12);
        second.account = other;
        if law == LotLaw::SpecificId {
            first.specific_ids = vec![(self.acquisitions[1], 0), (self.acquisitions[0], 0)];
            second.specific_ids = vec![(other_acquisitions[1], 0), (other_acquisitions[0], 0)];
        }
        let first = self.agent_disposal(&first, b"draft-lot-first");
        let first_basis = first.lot_disposal_basis().unwrap().unwrap().known_at;
        self.h.plan_draft(agent.clone(), name, first).unwrap();
        let second = self.agent_disposal(&second, b"draft-lot-second");
        assert!(second.lot_disposal_basis().unwrap().unwrap().known_at > first_basis);
        let planned = self.h.plan_draft(agent, name, second).unwrap();
        planned
            .plan
            .unwrap()
            .members()
            .iter()
            .map(|member| {
                member.entry.entry_ref(entry_vid(
                    self.h.book.book_id,
                    &AGENT.0.to_le_bytes(),
                    &member.entry.proposal.idempotency_key,
                ))
            })
            .collect()
    }
}

fn assert_lot_draft_unpublished(f: &Fixture, name: &str, entries: &[EntryRef]) {
    assert_eq!(f.h.draft(name).state, DraftState::Open);
    for reference in entries {
        assert!(read_entry(&f.h.db, reference.vid).unwrap().is_none());
    }
}

#[test]
fn agent_lot_drafts_revalidate_unchanged_sources_and_promote_exactly_once() {
    for (law, costs) in [
        (LotLaw::Fifo, (104, 76)),
        (LotLaw::Lifo, (40, 44)),
        (LotLaw::SpecificId, (40, 44)),
        (LotLaw::WeightedAverage, (72, 60)),
    ] {
        let mut f = Fixture::new(law);
        let (other, acquisitions) = f.another_inventory(law);
        let name = "reviewed-lot-disposals";
        let entries = f.plan_lot_pair(name, other, acquisitions, law);
        assert_lot_draft_unpublished(&f, name, &entries);
        assert_eq!(applied_totals(&f.h, &f.acquisitions), (0, 0));
        assert_eq!(applied_totals(&f.h, &acquisitions), (0, 0));
        let retained = f.h.draft(name).intents;

        // Unrelated economic activity and another draft control do not change
        // either complete lot source, and must not require resealing reviews.
        let unrelated =
            f.h.proposal(f.h.rent_legs(1), b"unrelated-rent", EntryClass::ORIGINAL);
        f.h.post(posting(unrelated)).unwrap();
        f.h.open_draft(f.h.agent_capability(), "another-review")
            .unwrap();
        let before = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();

        let direct = PostRequest {
            proposal: retained[0].intent.proposal().clone(),
            approvals: vec![],
            capability: f.h.agent_capability(),
            plan_certificate: None,
        };
        assert_eq!(f.h.post(direct).unwrap_err().exit, 7);
        let owner = Capability::embedded(AGENT, &["read", "approve"]).unwrap();
        assert_eq!(f.h.promote(owner, name).unwrap_err().code, "FA-REF-008");
        assert_eq!(f.h.db.frontier().unwrap(), before);
        assert_eq!(f.h.db.vertices().unwrap(), rows);

        let promoted = f.h.promote(f.h.approver_capability(), name).unwrap();
        assert_eq!(promoted.entries, entries);
        assert_eq!(promoted.recorded_at, CommitSeq(before.0 + 1));
        assert_eq!(applied_totals(&f.h, &f.acquisitions), (12, costs.0));
        assert_eq!(applied_totals(&f.h, &acquisitions), (12, costs.1));
        for (reference, retained) in promoted.entries.iter().zip(&retained) {
            let (entry, at) = read_entry(&f.h.db, reference.vid).unwrap().unwrap();
            assert_eq!(entry.proposal, *retained.intent.proposal());
            assert_eq!(entry.entry_digest, reference.entry_digest);
            assert_eq!(at, promoted.recorded_at);
        }
        assert_eq!(f.h.draft(name).state, DraftState::Promoted);
        let rows = f.h.db.vertices().unwrap();
        let retry = f.h.promote(f.h.approver_capability(), name).unwrap();
        assert!(retry.already_recorded);
        assert_eq!(retry.entries, promoted.entries);
        assert_eq!(retry.recorded_at, promoted.recorded_at);
        assert_eq!(f.h.db.frontier().unwrap(), promoted.recorded_at);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn changed_lot_history_refuses_a_whole_draft_even_after_equal_balance_restoration() {
    for change in [
        "acquisition",
        "later-application",
        "application-and-undo",
        "acquisition-and-undo",
    ] {
        let mut f = Fixture::new(LotLaw::Fifo);
        let (other, acquisitions) = f.another_inventory(LotLaw::Fifo);
        let name = "stale-lot-review";
        let entries = f.plan_lot_pair(name, other, acquisitions, LotLaw::Fifo);
        match change {
            "acquisition" | "acquisition-and-undo" => {
                let added = f.buy(b"new-source-layer", 1, 1);
                if change == "acquisition-and-undo" {
                    let reverse = f.h.reversal_of_entry(added, b"undo-new-source-layer");
                    f.h.post(posting(reverse)).unwrap();
                }
            }
            _ => {
                let mut request = f.request(1);
                request.account = other;
                let proposal = f
                    .prepare_request(&request, b"competing-later-lot-application")
                    .unwrap()
                    .into_proposal();
                let posted = f.h.post(posting(proposal.clone())).unwrap();
                if change == "application-and-undo" {
                    f.h.post(posting(undo(
                        &proposal,
                        posted.entry_ref(),
                        b"undo-competing-lot-application",
                    )))
                    .unwrap();
                }
            }
        }
        let before = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let prior_applications = applied_totals(&f.h, &acquisitions);
        let refusal = f.h.promote(f.h.approver_capability(), name).unwrap_err();
        assert_eq!(
            (refusal.code, refusal.exit),
            (code::PLAN_INVALIDATED, 6),
            "{change}: {refusal}"
        );
        assert!(
            refusal.message.contains("lot source changed"),
            "{change}: {refusal}"
        );
        if change.starts_with("application") || change == "later-application" {
            assert!(refusal.message.contains("batch member 1"), "{refusal}");
        }
        assert_eq!(f.h.db.frontier().unwrap(), before);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert_eq!(applied_totals(&f.h, &f.acquisitions), (0, 0));
        assert_eq!(applied_totals(&f.h, &acquisitions), prior_applications);
        assert_lot_draft_unpublished(&f, name, &entries);
    }
}

#[test]
fn revoked_lot_draft_planner_is_not_replaced_by_promoter_authority() {
    let mut f = Fixture::new(LotLaw::Fifo);
    let (other, acquisitions) = f.another_inventory(LotLaw::Fifo);
    let name = "revoked-lot-planner";
    let entries = f.plan_lot_pair(name, other, acquisitions, LotLaw::Fifo);
    f.h.revoke(&f.h.agent_capability(), 218);
    let before = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    let refusal = f.h.promote(f.h.approver_capability(), name).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-023", 7));
    assert_eq!(f.h.db.frontier().unwrap(), before);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
    assert_lot_draft_unpublished(&f, name, &entries);
    assert_eq!(applied_totals(&f.h, &f.acquisitions), (0, 0));
    assert_eq!(applied_totals(&f.h, &acquisitions), (0, 0));
}

#[test]
fn lot_drafts_refuse_mixed_dependent_and_forged_later_members_without_a_plan_record() {
    for variant in [
        "same-source",
        "forged-policy",
        "cross-source",
        "mixed",
        "cost-plug",
    ] {
        let mut f = Fixture::new(LotLaw::Fifo);
        let (other, _) = f.another_inventory(LotLaw::Fifo);
        let agent = f.h.agent_capability();
        f.h.open_draft(agent.clone(), variant).unwrap();
        let first = f.agent_disposal(&f.request(12), b"first-draft-disposal");
        f.h.plan_draft(agent.clone(), variant, first).unwrap();
        let mut request = f.request(1);
        if matches!(variant, "cross-source" | "cost-plug") {
            request.account = other;
        }
        let mut later = if variant == "mixed" {
            f.h.agent_rent(1, b"mixed-native-post")
        } else {
            f.agent_disposal(&request, b"later-draft-disposal")
        };
        if variant == "forged-policy" {
            let mut basis = later.lot_disposal_basis().unwrap().unwrap();
            basis.policy.entry_digest[0] ^= 1;
            later.set_lot_disposal_basis(&basis).unwrap();
        }
        if variant == "cross-source" {
            let mut basis = later.lot_disposal_basis().unwrap().unwrap();
            basis.quantity_offset_account = f.inventory;
            later.set_lot_disposal_basis(&basis).unwrap();
        }
        if variant == "cost-plug" {
            later.legs[2].amount.mantissa += 1;
            later.legs[3].amount.mantissa += 1;
            later.unit_totals = EntryPayload::fold_unit_totals(&later.legs).unwrap();
        }
        let before = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let view = f.h.draft(variant);
        let refusal = f.h.plan_draft(agent, variant, later).unwrap_err();
        assert_eq!(
            refusal.code,
            if variant == "mixed" {
                code::CLASS_NOT_IMPLEMENTED
            } else {
                code::SETTLE_SHAPE
            },
            "{variant}: {refusal}"
        );
        assert_eq!(f.h.db.frontier().unwrap(), before);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert_eq!(f.h.draft(variant), view);
    }
}

#[test]
fn lot_draft_rehearsal_preserves_source_sequences_vids_and_retained_reviews() {
    use fa_journal::draft::{DraftRehearsalRequest, rehearse_draft_into};

    let mut f = Fixture::new(LotLaw::WeightedAverage);
    let (other, acquisitions) = f.another_inventory(LotLaw::WeightedAverage);
    let name = "lot-rehearsal";
    let entries = f.plan_lot_pair(name, other, acquisitions, LotLaw::WeightedAverage);
    let at = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    let view = f.h.draft(name);
    let cx = f.h.ctx();
    let target =
        f.h.runtime
            .block_on(Database::open_memory(
                &cx.commit(),
                DatabaseKeys::new([221; 32], DatabaseSecurityNamespaceId([222; 32]), [223; 32]),
            ))
            .unwrap();
    let reader = Capability::embedded(VId(224), &["read"]).unwrap();
    let (scratch, rehearsal) =
        f.h.runtime
            .block_on(rehearse_draft_into(
                &mut f.h.db,
                target,
                &cx,
                &f.h.book,
                &reader,
                DraftRehearsalRequest {
                    name: name.into(),
                    known_at: at,
                },
            ))
            .unwrap()
            .unwrap();
    assert_eq!(rehearsal.batch.entries, entries);
    assert_eq!(rehearsal.batch.recorded_at, CommitSeq(at.0 + 1));
    assert_eq!(rehearsal.view, view);
    assert!(
        rehearsal
            .seq_map
            .pairs
            .iter()
            .all(|pair| pair.source_seq == pair.scratch_seq)
    );
    for acquisition in f.acquisitions.into_iter().chain(acquisitions) {
        assert_eq!(
            fa_journal::post::read_entry_at(&scratch, acquisition.vid, at).unwrap(),
            read_entry(&f.h.db, acquisition.vid).unwrap(),
        );
    }
    for (entry, planned) in entries.iter().zip(&view.intents) {
        let (observed, seq) = read_entry(&scratch, entry.vid).unwrap().unwrap();
        assert_eq!(observed.proposal, *planned.intent.proposal());
        assert_eq!(observed.entry_digest, entry.entry_digest);
        assert_eq!(seq, rehearsal.batch.recorded_at);
    }
    assert_eq!(f.h.db.frontier().unwrap(), at);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
    assert_lot_draft_unpublished(&f, name, &entries);
    let promoted = f.h.promote(f.h.approver_capability(), name).unwrap();
    assert_eq!(promoted.entries, rehearsal.batch.entries);
    assert_eq!(applied_totals(&f.h, &f.acquisitions), (12, 72));
    assert_eq!(applied_totals(&f.h, &acquisitions), (12, 60));
}
