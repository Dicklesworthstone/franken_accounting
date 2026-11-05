//! A draft-confined writer derives only its requested, fully admitted relief.

use super::*;
use fa_journal::disposal::{prepare_lot_disposal_in_draft, prepare_lot_disposal_targets_in_draft};
use fa_journal::draft::{DraftSourceAdmission, admit_sources};
use fa_journal::refusal::code;

impl Fixture {
    fn confined_disposal_planner(&self, name: &str, quantity: i128, cost: i128) -> Capability {
        Capability::new(
            AGENT,
            fa_policy::Profile::Agent,
            &[fa_policy::Op::Post],
            PRINCIPAL,
        )
        .unwrap()
        .on_branch(fa_model::draft_branch(self.h.book.book_id, name))
        .unwrap()
        .with_ceiling(self.share, quantity)
        .unwrap()
        .with_ceiling(self.h.usd, cost)
        .unwrap()
    }

    fn draft_disposal_template(&self, key: &[u8]) -> EntryPayload {
        let mut template = self.h.proposal(vec![], key, EntryClass::ORIGINAL);
        template.principal_ref = AGENT;
        template
    }

    fn draft_disposal_source(&self, capability: &Capability, name: &str) -> DraftSourceAdmission {
        admit_sources(&self.h.db, &self.h.book, capability, name)
            .unwrap()
            .unwrap()
    }

    fn prepare_confined_disposal(
        &self,
        source: &DraftSourceAdmission,
        request: &LotDisposalRequest,
        key: &[u8],
    ) -> Result<PreparedLotDisposal, Refusal> {
        prepare_lot_disposal_in_draft(
            &self.h.db,
            &self.h.ctx(),
            &self.h.book,
            source,
            request,
            self.draft_disposal_template(key),
        )
        .unwrap()
    }
}

#[test]
fn post_only_draft_disposal_matches_literal_relief_and_promotes_exact_effects() {
    for (law, expected_cost) in [(LotLaw::Fifo, 104), (LotLaw::SpecificId, 40)] {
        let mut f = Fixture::new(law);
        let name = "confined-lot-review";
        let planner = f.confined_disposal_planner(name, 12, 104);
        f.h.open_draft(planner.clone(), name).unwrap();
        let source = f.draft_disposal_source(&planner, name);
        let mut request = f.request(12);
        if law == LotLaw::SpecificId {
            request.specific_ids = vec![(f.acquisitions[1], 0), (f.acquisitions[0], 0)];
        }
        let key = b"confined-disposal";
        let literal = prepare_lot_disposal(
            &f.h.db,
            &f.h.ctx(),
            &f.h.book,
            &Capability::embedded(AGENT, &["read", "post"]).unwrap(),
            &request,
            f.draft_disposal_template(key),
        )
        .unwrap()
        .unwrap();
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let prepared = f.prepare_confined_disposal(&source, &request, key).unwrap();
        let targets: Vec<_> = request
            .specific_ids
            .iter()
            .map(|(entry, ordinal)| (entry.vid, *ordinal))
            .collect();
        let selected = prepare_lot_disposal_targets_in_draft(
            &f.h.db,
            &f.h.ctx(),
            &f.h.book,
            &source,
            &f.request(12),
            &targets,
            f.draft_disposal_template(key),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            selected, literal,
            "resolving raw selectors preserves the exact digest-bound law result"
        );
        assert_eq!(
            prepared, literal,
            "the source admission cannot change lot arithmetic"
        );
        assert_eq!(prepared.outcome().total_relieved_cost, expected_cost);
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert!(
            fa_journal::policy::admit_reads(&f.h.db, &f.h.book, AGENT, &planner)
                .unwrap()
                .is_err()
        );

        let proposal = prepared.into_proposal();
        let mut direct = posting(proposal.clone());
        direct.capability = planner.clone();
        assert_eq!(f.h.post(direct).unwrap_err().exit, 7);
        assert_eq!(f.h.db.frontier().unwrap(), head);
        let planned =
            f.h.plan_draft(planner.clone(), name, proposal.clone())
                .unwrap();
        let reviewed = &planned.plan.as_ref().unwrap().members()[0].entry;
        assert_eq!(reviewed.proposal, proposal);
        let entry = reviewed.entry_ref(entry_vid(f.h.book.book_id, &AGENT.0.to_le_bytes(), key));
        assert!(read_entry(&f.h.db, entry.vid).unwrap().is_none());
        for acquisition in f.acquisitions {
            assert_eq!(f.h.applied_to(acquisition.vid, 0), 0);
            assert_eq!(f.h.applied_to(acquisition.vid, 2), 0);
        }

        let unrelated = f.h.proposal(
            f.h.rent_legs(1),
            b"unrelated-to-confined-lots",
            EntryClass::ORIGINAL,
        );
        f.h.post(posting(unrelated)).unwrap();
        let promoted = f.h.promote(f.h.approver_capability(), name).unwrap();
        assert_eq!(promoted.entries, vec![entry]);
        let (posted, _) = read_entry(&f.h.db, entry.vid).unwrap().unwrap();
        assert_eq!(posted, *reviewed);
        assert_eq!(
            f.acquisitions
                .iter()
                .map(|entry| f.h.applied_to(entry.vid, 0))
                .sum::<i128>(),
            12
        );
        assert_eq!(
            f.acquisitions
                .iter()
                .map(|entry| f.h.applied_to(entry.vid, 2))
                .sum::<i128>(),
            expected_cost
        );
        let head = f.h.db.frontier().unwrap();
        assert_eq!(
            f.prepare_confined_disposal(&source, &request, key)
                .unwrap_err()
                .code,
            code::DRAFT_NOT_OPEN
        );
        assert_eq!(f.h.db.frontier().unwrap(), head);
    }
}

#[test]
fn post_only_draft_disposal_resolves_only_usable_quantity_targets_after_authority() {
    let mut f = Fixture::new(LotLaw::SpecificId);
    let name = "selected-lots";
    let planner = f.confined_disposal_planner(name, 12, 104);
    f.h.open_draft(planner.clone(), name).unwrap();
    let source = f.draft_disposal_source(&planner, name);
    let head = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    for target in [
        (VId(u128::MAX), 0),
        (f.acquisitions[0].vid, 2),
        (f.acquisitions[0].vid, 1),
    ] {
        let denied = prepare_lot_disposal_targets_in_draft(
            &f.h.db,
            &f.h.ctx(),
            &f.h.book,
            &source,
            &f.request(1),
            &[target],
            f.draft_disposal_template(b"invalid-selector"),
        )
        .unwrap()
        .unwrap_err();
        assert_eq!(denied.exit, 3);
        assert_eq!(
            denied.message,
            "SpecificId acquisition target is unavailable"
        );
    }
    let denied = prepare_lot_disposal_targets_in_draft(
        &f.h.db,
        &f.h.ctx(),
        &f.h.book,
        &source,
        &f.request(13),
        &[(VId(u128::MAX), 0)],
        f.draft_disposal_template(b"quantity-before-selector"),
    )
    .unwrap()
    .unwrap_err();
    assert_eq!(denied.exit, 7);
    assert!(denied.message.contains("ceiling"));
    assert_eq!(f.h.db.frontier().unwrap(), head);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
    assert!(
        fa_journal::policy::admit_reads(&f.h.db, &f.h.book, AGENT, &planner)
            .unwrap()
            .is_err()
    );
}

#[test]
fn post_only_draft_disposal_checks_declared_quantity_and_derived_cost_ceilings() {
    let mut f = Fixture::new(LotLaw::Fifo);
    let name = "bounded-lot-review";
    let quantity_bound = f.confined_disposal_planner(name, 11, 104);
    f.h.open_draft(quantity_bound.clone(), name).unwrap();
    let source = f.draft_disposal_source(&quantity_bound, name);
    let head = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    let mut unknown = f.request(12);
    unknown.account = VId(u128::MAX);
    let denied = f
        .prepare_confined_disposal(&source, &unknown, b"quantity-before-source")
        .unwrap_err();
    assert_eq!(denied.exit, 7);
    assert!(
        denied.message.contains("ceiling"),
        "quantity authority precedes even an absent source: {denied}"
    );

    let cost_bound = f.confined_disposal_planner(name, 12, 103);
    let source = f.draft_disposal_source(&cost_bound, name);
    let denied = f
        .prepare_confined_disposal(&source, &f.request(12), b"derived-cost-ceiling")
        .unwrap_err();
    assert_eq!(denied.exit, 7);
    assert!(
        denied.message.contains("ceiling"),
        "the generated 104 cost is independently admitted: {denied}"
    );
    assert_eq!(denied.code, fa_policy::denial::code::CEILING);
    assert_eq!(
        denied.message,
        "generated posting effects exceed the capability's permitted scope or amount ceiling"
    );
    assert!(
        denied.detail.is_none(),
        "denied cost must not leak: {denied:?}"
    );
    let denied = prepare_lot_disposal(
        &f.h.db,
        &f.h.ctx(),
        &f.h.book,
        &cost_bound,
        &f.request(12),
        f.draft_disposal_template(b"ordinary-read-still-required"),
    )
    .unwrap()
    .unwrap_err();
    assert_eq!(
        denied.code,
        code::CAPABILITY,
        "ordinary preparation keeps its Read contract"
    );
    assert_eq!(f.h.db.frontier().unwrap(), head);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
}

#[test]
fn post_only_draft_disposal_promotion_rechecks_source_policy_and_planner() {
    for change in ["acquisition", "policy", "revocation"] {
        let mut f = Fixture::new(LotLaw::Fifo);
        let name = "changed-confined-lots";
        let planner = f.confined_disposal_planner(name, 12, 104);
        f.h.open_draft(planner.clone(), name).unwrap();
        let source = f.draft_disposal_source(&planner, name);
        let proposal = f
            .prepare_confined_disposal(&source, &f.request(12), b"retained-confined-disposal")
            .unwrap()
            .into_proposal();
        let planned = f.h.plan_draft(planner.clone(), name, proposal).unwrap();
        let reviewed = &planned.plan.as_ref().unwrap().members()[0].entry;
        let entry = entry_vid(
            f.h.book.book_id,
            &AGENT.0.to_le_bytes(),
            &reviewed.proposal.idempotency_key,
        );
        match change {
            "acquisition" => {
                f.buy(b"new-confined-source-layer", 1, 1);
            }
            "policy" => {
                let at = f.h.db.frontier().unwrap();
                let mut policy = policy_at(&f.h.db, &f.h.book, f.inventory, at)
                    .unwrap()
                    .unwrap()
                    .policy;
                policy.law = LotLaw::Lifo;
                let proposal = lot_policy_proposal(
                    &f.h.book,
                    PRINCIPAL,
                    &policy,
                    f.h.day(),
                    b"change-confined-lot-policy",
                    f.h.proposal(vec![], b"policy-description", EntryClass::ORIGINAL)
                        .description,
                )
                .unwrap();
                let digest = proposal.proposal_digest().unwrap();
                let approvals = vec![
                    f.h.approve_digest(VId(70), digest).unwrap(),
                    f.h.approve_digest(VId(71), digest).unwrap(),
                ];
                let cx = f.h.ctx();
                f.h.runtime
                    .block_on(set_lot_policy_proposal(
                        &mut f.h.db,
                        &cx,
                        &f.h.book,
                        &Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap(),
                        proposal,
                        approvals,
                    ))
                    .unwrap()
                    .unwrap();
            }
            "revocation" => {
                f.h.revoke(&planner, 231);
            }
            _ => unreachable!(),
        }
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let denied = f.h.promote(f.h.approver_capability(), name).unwrap_err();
        assert_eq!(
            denied.code,
            match change {
                "acquisition" => code::PLAN_INVALIDATED,
                "policy" => code::SETTLE_SHAPE,
                "revocation" => "FA-REF-023",
                _ => unreachable!(),
            },
            "{change}: {denied}"
        );
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert!(read_entry(&f.h.db, entry).unwrap().is_none());
        for acquisition in f.acquisitions {
            assert_eq!(f.h.applied_to(acquisition.vid, 0), 0);
            assert_eq!(f.h.applied_to(acquisition.vid, 2), 0);
        }
    }
}
