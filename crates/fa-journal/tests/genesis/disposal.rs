//! Governed lots reach the real admission pipeline, including prepared races.

use super::*;
use fa_journal::chart::lots::{
    LotPolicy, LotPolicyRequest, lot_policy_proposal, policy_at, set_lot_policy,
    set_lot_policy_proposal,
};
use fa_journal::disposal::{LotDisposalRequest, PreparedLotDisposal, prepare_lot_disposal};
use fa_money::{AccountingRegime, LotLaw, RoundingLaw};
use fa_reference::lots::{RefLot, RefRounding, relieve_lots_oracle};

mod batches;

struct Fixture {
    h: Harness,
    inventory: VId,
    quantity_offset: VId,
    cost_offset: VId,
    share: UnitId,
    acquisitions: [EntryRef; 2],
}

fn posting(proposal: EntryPayload) -> PostRequest {
    PostRequest {
        proposal,
        approvals: vec![],
        plan_certificate: None,
        capability: Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
    }
}

impl Fixture {
    fn new(law: LotLaw) -> Self {
        let mut h = harness();
        let share = h.book.units.lookup("SHARE").unwrap();
        let accounts = [
            ("1400", fa_model::AccountType::ASSET, 0, UnitPolicy::AnyUnit),
            (
                "1499",
                fa_model::AccountType::ASSET,
                1,
                UnitPolicy::Single(share),
            ),
            (
                "5100",
                fa_model::AccountType::EXPENSE,
                0,
                UnitPolicy::Single(h.usd),
            ),
        ]
        .into_iter()
        .map(|(code, kind, normal, unit_policy)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type: kind.0,
            normal_balance: normal,
            is_leaf: true,
            unit_policy,
            parent_code: None,
            limit: None,
        })
        .collect::<Vec<_>>();
        let cx = h.ctx();
        let day = h.day();
        let description = h
            .proposal(vec![], b"lot-chart", EntryClass::ORIGINAL)
            .description;
        h.runtime
            .block_on(install_chart(
                &mut h.db,
                &cx,
                &h.book,
                &accounts,
                PRINCIPAL,
                day,
                b"lot-chart",
                description,
                &Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        let inventory = account_vid(h.book.book_id, "1400");
        let quantity_offset = account_vid(h.book.book_id, "1499");
        let cost_offset = account_vid(h.book.book_id, "5100");
        let policy = LotPolicy {
            account: inventory,
            law,
            regime: AccountingRegime::UsGaap,
            rounding_law: RoundingLaw::HalfEven,
        };
        let policy_request = LotPolicyRequest {
            principal: PRINCIPAL,
            policy,
            effective_date: day,
            idempotency_key: b"lot-policy".to_vec(),
            description: h
                .proposal(vec![], b"lot-policy", EntryClass::ORIGINAL)
                .description,
            approvals: vec![],
        };
        h.runtime
            .block_on(set_lot_policy(
                &mut h.db,
                &cx,
                &h.book,
                &Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap(),
                policy_request,
            ))
            .unwrap()
            .unwrap();
        let acquisitions =
            [(b"lot-one".as_slice(), 100), (b"lot-two".as_slice(), 20)].map(|(key, cost)| {
                let proposal = h.proposal(
                    vec![
                        LegPayload::simple(Side::Debit, inventory, Amount::new(share, 10)),
                        LegPayload::simple(Side::Credit, quantity_offset, Amount::new(share, 10)),
                        LegPayload::simple(Side::Debit, inventory, Amount::new(h.usd, cost)),
                        LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, cost)),
                    ],
                    key,
                    EntryClass::ORIGINAL,
                );
                h.post(posting(proposal)).unwrap().entry_ref()
            });
        Self {
            h,
            inventory,
            quantity_offset,
            cost_offset,
            share,
            acquisitions,
        }
    }

    fn request(&self, quantity: i128) -> LotDisposalRequest {
        LotDisposalRequest {
            account: self.inventory,
            quantity: Amount::new(self.share, quantity),
            quantity_offset_account: self.quantity_offset,
            cost_offset_account: self.cost_offset,
            specific_ids: vec![],
        }
    }

    fn prepare(&self, quantity: i128, key: &[u8]) -> Result<PreparedLotDisposal, Refusal> {
        self.prepare_request(&self.request(quantity), key)
    }

    fn prepare_request(
        &self,
        request: &LotDisposalRequest,
        key: &[u8],
    ) -> Result<PreparedLotDisposal, Refusal> {
        prepare_lot_disposal(
            &self.h.db,
            &self.h.ctx(),
            &self.h.book,
            &Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
            request,
            self.h.proposal(vec![], key, EntryClass::ORIGINAL),
        )
        .unwrap()
    }

    fn buy(&mut self, key: &[u8], quantity: i128, cost: i128) -> EntryRef {
        let proposal = self.h.proposal(
            vec![
                LegPayload::simple(
                    Side::Debit,
                    self.inventory,
                    Amount::new(self.share, quantity),
                ),
                LegPayload::simple(
                    Side::Credit,
                    self.quantity_offset,
                    Amount::new(self.share, quantity),
                ),
                LegPayload::simple(Side::Debit, self.inventory, Amount::new(self.h.usd, cost)),
                LegPayload::simple(Side::Credit, self.h.cash, Amount::new(self.h.usd, cost)),
            ],
            key,
            EntryClass::ORIGINAL,
        );
        self.h.post(posting(proposal)).unwrap().entry_ref()
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
fn fifo_disposal_derives_relief_from_the_oldest_layer() {
    for (law, expected_cost) in [
        (LotLaw::Fifo, 104),
        (LotLaw::Lifo, 40),
        (LotLaw::WeightedAverage, 72),
        (LotLaw::SpecificId, 40),
    ] {
        let mut f = Fixture::new(law);
        let mut request = f.request(12);
        if law == LotLaw::SpecificId {
            request.specific_ids = vec![(f.acquisitions[1], 0), (f.acquisitions[0], 0)];
        }
        let before = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let prepared = f.prepare_request(&request, b"dispose-12").unwrap();
        assert_eq!(prepared.outcome().total_relieved_cost, expected_cost);
        assert_eq!(f.h.db.frontier().unwrap(), before);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        let reference = f
            .acquisitions
            .iter()
            .zip([100, 20])
            .map(|(entry, cost)| {
                let (_, at) = fa_journal::post::read_entry_at(&f.h.db, entry.vid, before)
                    .unwrap()
                    .unwrap();
                RefLot {
                    entry_id: entry.vid.0,
                    ordinal: 0,
                    effective_day: f.h.day().0,
                    recorded_seq: at.0,
                    quantity_unit: f.share.0,
                    open_quantity: 10,
                    cost_unit: f.h.usd.0,
                    open_cost: cost,
                }
            })
            .collect::<Vec<_>>();
        let explicit = request
            .specific_ids
            .iter()
            .map(|(entry, ordinal)| (entry.vid.0, *ordinal))
            .collect::<Vec<_>>();
        let oracle = relieve_lots_oracle(
            &reference,
            f.share.0,
            12,
            law.name(),
            Some("US-GAAP"),
            RefRounding::HalfEven,
            &explicit,
        )
        .unwrap();
        assert_eq!(prepared.outcome().total_relieved_cost, oracle.total_cost);
        let posted = f.h.post(posting(prepared.into_proposal())).unwrap();
        assert!(matches!(posted, Posted::Committed { .. }));
        assert_eq!(
            f.h.applied_to(f.acquisitions[0].vid, 0)
                .checked_add(f.h.applied_to(f.acquisitions[1].vid, 0))
                .unwrap(),
            12
        );
        assert_eq!(
            f.h.applied_to(f.acquisitions[0].vid, 2)
                .checked_add(f.h.applied_to(f.acquisitions[1].vid, 2))
                .unwrap(),
            expected_cost
        );
    }
}

#[test]
fn hand_typed_relief_that_differs_from_the_lot_law_is_refused() {
    let mut f = Fixture::new(LotLaw::Fifo);
    let valid = f.prepare(12, b"tampered-disposal").unwrap().into_proposal();
    let mut wrong_cost = valid.clone();
    for leg in wrong_cost
        .legs
        .iter_mut()
        .filter(|leg| leg.amount.unit == f.h.usd)
    {
        leg.amount.mantissa = leg.amount.mantissa.checked_sub(1).unwrap();
        if let Some(settlement) = leg.settles.first_mut() {
            settlement.amount.mantissa = settlement.amount.mantissa.checked_sub(1).unwrap();
        }
    }
    wrong_cost.unit_totals = EntryPayload::fold_unit_totals(&wrong_cost.legs).unwrap();
    let mut unbound = valid.clone();
    unbound.extensions.clear();
    let mut hidden = unbound.clone();
    for leg in &mut hidden.legs {
        leg.settles.clear();
    }
    let before = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    for proposal in [wrong_cost, unbound, hidden] {
        let refusal = f.h.post(posting(proposal)).unwrap_err();
        assert_eq!(refusal.code, "FA-REF-071");
        assert_eq!(f.h.db.frontier().unwrap(), before);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
    }
    f.h.post(posting(valid)).unwrap();
}

#[test]
fn weighted_average_cost_only_layers_survive_posting_reversal_and_final_relief() {
    let mut f = Fixture::new(LotLaw::WeightedAverage);
    let first = f.prepare(10, b"first-wac").unwrap();
    assert_eq!(first.outcome().total_relieved_cost, 60);
    let first_proposal = first.into_proposal();
    let first_posted = f.h.post(posting(first_proposal.clone())).unwrap();
    assert_eq!(f.h.applied_to(f.acquisitions[0].vid, 0), 10);
    assert_eq!(f.h.applied_to(f.acquisitions[0].vid, 2), 60);
    let last = f.prepare(10, b"last-wac").unwrap();
    assert_eq!(last.outcome().total_relieved_cost, 60);
    assert!(
        last.outcome()
            .slices
            .iter()
            .any(|slice| slice.relieved_quantity == 0 && slice.relieved_cost == 40)
    );
    let last_proposal = last.into_proposal();
    let last_posted = f.h.post(posting(last_proposal.clone())).unwrap();
    for (entry, cost) in f.acquisitions.iter().zip([100, 20]) {
        assert_eq!(f.h.applied_to(entry.vid, 0), 10);
        assert_eq!(f.h.applied_to(entry.vid, 2), cost);
    }
    f.h.post(posting(undo(
        &last_proposal,
        last_posted.entry_ref(),
        b"undo-last-wac",
    )))
    .unwrap();
    let redone = f.prepare(10, b"redo-last-wac").unwrap();
    assert_eq!(redone.outcome().total_relieved_cost, 60);
    f.h.post(posting(undo(
        &first_proposal,
        first_posted.entry_ref(),
        b"undo-first-wac",
    )))
    .unwrap();
    for entry in f.acquisitions {
        assert_eq!(f.h.applied_to(entry.vid, 0), 0);
        assert_eq!(f.h.applied_to(entry.vid, 2), 0);
    }
}

#[test]
fn concurrent_prepared_disposals_cannot_relieve_the_same_inventory_twice() {
    let mut f = Fixture::new(LotLaw::Fifo);
    let first = f.prepare(15, b"first-racer").unwrap().into_proposal();
    let second = f.prepare(15, b"second-racer").unwrap().into_proposal();
    let cx = f.h.ctx();
    let PostPreparation::Ready(first) = prepare_post(&mut f.h.db, &cx, &f.h.book, posting(first))
        .unwrap()
        .unwrap()
    else {
        panic!("first plan");
    };
    let PostPreparation::Ready(second) = prepare_post(&mut f.h.db, &cx, &f.h.book, posting(second))
        .unwrap()
        .unwrap()
    else {
        panic!("second plan");
    };
    f.h.runtime
        .block_on(first.commit(&mut f.h.db, &cx))
        .unwrap()
        .unwrap();
    let after_first = f.h.db.frontier().unwrap();
    let refusal =
        f.h.runtime
            .block_on(second.commit(&mut f.h.db, &cx))
            .unwrap()
            .unwrap_err();
    assert_eq!(refusal.exit, 6);
    assert_eq!(f.h.db.frontier().unwrap(), after_first);
    assert_eq!(
        f.h.applied_to(f.acquisitions[0].vid, 0)
            .checked_add(f.h.applied_to(f.acquisitions[1].vid, 0))
            .unwrap(),
        15
    );
}

#[test]
fn intervening_acquisition_invalidates_a_reviewed_disposal_but_exact_retry_is_stable() {
    let mut f = Fixture::new(LotLaw::Fifo);
    let stale = f.prepare(12, b"stale-lot-basis").unwrap().into_proposal();
    f.buy(b"new-acquisition", 10, 1);
    let before = f.h.db.frontier().unwrap();
    let refusal = f.h.post(posting(stale)).unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::PLAN_INVALIDATED);
    assert_eq!(f.h.db.frontier().unwrap(), before);
    let original = f.prepare(12, b"stable-disposal").unwrap().into_proposal();
    let posted = f.h.post(posting(original.clone())).unwrap();
    f.buy(b"later-acquisition", 1, 1);
    let retry = f.prepare(12, b"stable-disposal").unwrap().into_proposal();
    assert_eq!(retry, original);
    let before_retry = f.h.db.frontier().unwrap();
    let repeated = f.h.post(posting(retry)).unwrap();
    assert!(matches!(repeated, Posted::AlreadyRecorded { .. }));
    assert_eq!(repeated.entry_ref(), posted.entry_ref());
    assert_eq!(f.h.db.frontier().unwrap(), before_retry);
}

#[test]
fn specific_id_requires_real_digest_bound_targets_and_current_read_authority() {
    let f = Fixture::new(LotLaw::SpecificId);
    let mut request = f.request(5);
    let before = f.h.db.frontier().unwrap();
    for target in [
        EntryRef {
            vid: VId(9999),
            entry_digest: [1; 32],
        },
        EntryRef {
            vid: f.acquisitions[0].vid,
            entry_digest: [0; 32],
        },
    ] {
        request.specific_ids = vec![(target, 0)];
        assert_eq!(
            f.prepare_request(&request, b"bad-specific-id")
                .unwrap_err()
                .code,
            "FA-REF-071"
        );
    }
    request.specific_ids = vec![(f.acquisitions[0], 0)];
    let denied = prepare_lot_disposal(
        &f.h.db,
        &f.h.ctx(),
        &f.h.book,
        &Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        &request,
        f.h.proposal(vec![], b"no-read-authority", EntryClass::ORIGINAL),
    )
    .unwrap()
    .unwrap_err();
    assert_eq!(denied.exit, 7);
    assert_eq!(f.h.db.frontier().unwrap(), before);
    assert_eq!(
        f.prepare_request(&request, b"good-specific-id")
            .unwrap()
            .outcome()
            .total_relieved_cost,
        50
    );
}

#[test]
fn changing_lot_policy_requires_dual_control_and_backdating_cannot_restore_the_old_law() {
    let mut f = Fixture::new(LotLaw::Fifo);
    let old_at = f.h.db.frontier().unwrap();
    let old_policy = policy_at(&f.h.db, &f.h.book, f.inventory, old_at)
        .unwrap()
        .unwrap();
    let mut new_policy = old_policy.policy.clone();
    new_policy.law = LotLaw::Lifo;
    let proposal = lot_policy_proposal(
        &f.h.book,
        PRINCIPAL,
        &new_policy,
        f.h.day(),
        b"change-lot-law",
        f.h.proposal(vec![], b"policy-description", EntryClass::ORIGINAL)
            .description,
    )
    .unwrap();
    let cx = f.h.ctx();
    let capability = Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap();
    let refusal =
        f.h.runtime
            .block_on(set_lot_policy_proposal(
                &mut f.h.db,
                &cx,
                &f.h.book,
                &capability,
                proposal.clone(),
                vec![],
            ))
            .unwrap()
            .unwrap_err();
    assert_eq!(refusal.exit, 7);
    assert_eq!(f.h.db.frontier().unwrap(), old_at);
    let digest = proposal.proposal_digest().unwrap();
    let approvals = vec![
        f.h.approve_digest(VId(70), digest).unwrap(),
        f.h.approve_digest(VId(71), digest).unwrap(),
    ];
    f.h.runtime
        .block_on(set_lot_policy_proposal(
            &mut f.h.db,
            &cx,
            &f.h.book,
            &capability,
            proposal,
            approvals,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(
        policy_at(&f.h.db, &f.h.book, f.inventory, old_at)
            .unwrap()
            .unwrap(),
        old_policy
    );
    // The new disposal has the acquisitions' old effective date, but is
    // governed by the latest recorded policy, not a caller-selected old law.
    let next = f.prepare(12, b"dispose-under-current-law").unwrap();
    assert_eq!(next.basis().law, LotLaw::Lifo);
    assert_eq!(next.outcome().total_relieved_cost, 40);
}

#[test]
fn governed_inventory_rejects_unpaired_cost_adjustments() {
    let mut f = Fixture::new(LotLaw::Fifo);
    let proposal = f.h.proposal(
        vec![
            LegPayload::simple(Side::Debit, f.cost_offset, Amount::new(f.h.usd, 1)),
            LegPayload::simple(Side::Credit, f.inventory, Amount::new(f.h.usd, 1)),
        ],
        b"arbitrary-cost-plug",
        EntryClass::ORIGINAL,
    );
    let before = f.h.db.frontier().unwrap();
    assert_eq!(f.h.post(posting(proposal)).unwrap_err().code, "FA-REF-071");
    assert_eq!(f.h.db.frontier().unwrap(), before);
}

#[test]
fn missing_policy_projection_cannot_turn_a_governed_account_into_an_unrestricted_one() {
    let mut f = Fixture::new(LotLaw::Fifo);
    let mut fault = fgdb::WriteBatch::new(relation::IN_BOOK);
    fault.delete_vertex(fa_journal::chart::lots::policy_vid(
        f.h.book.book_id,
        f.inventory,
    ));
    f.h.write_raw(fault);
    let proposal = f.h.proposal(
        vec![
            LegPayload::simple(Side::Debit, f.cost_offset, Amount::new(f.h.usd, 1)),
            LegPayload::simple(Side::Credit, f.inventory, Amount::new(f.h.usd, 1)),
        ],
        b"damaged-policy-bypass",
        EntryClass::ORIGINAL,
    );
    let before = f.h.db.frontier().unwrap();
    let cx = f.h.ctx();
    let result = prepare_post(&mut f.h.db, &cx, &f.h.book, posting(proposal));
    assert!(matches!(result, Err(KernelError::Corrupt(_))));
    assert_eq!(f.h.db.frontier().unwrap(), before);
}
