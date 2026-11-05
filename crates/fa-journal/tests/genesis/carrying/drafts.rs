//! Native drafts retain the reviewed foreign relief and promote independent
//! existing items through the same guarded atomic carrying-value batch law.

use super::*;

fn confined_planner(f: &Fixture, name: &str, native: i128, base: i128) -> Capability {
    Capability::new(
        AGENT,
        fa_policy::Profile::Agent,
        &[fa_policy::Op::Post],
        PRINCIPAL,
    )
    .unwrap()
    .on_branch(fa_model::draft_branch(f.h.book.book_id, name))
    .unwrap()
    .with_ceiling(f.foreign, native)
    .unwrap()
    .with_ceiling(f.h.usd, base)
    .unwrap()
}

fn prepare_confined_group(
    f: &mut Fixture,
    capability: &Capability,
    name: &str,
    requests: &[FxSettlementRequest],
    key: &[u8],
) -> fa_journal::refusal::Outcome<EntryPayload> {
    let admission = match fa_journal::draft::admit_sources(&f.h.db, &f.h.book, capability, name)? {
        Ok(admission) => admission,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let mut template = f.h.proposal(vec![], key, EntryClass::ORIGINAL);
    template.principal_ref = AGENT;
    let cx = f.h.ctx();
    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
    fa_journal::carrying::prepare_fx_settlement_group_in_draft(
        &mut f.h.db,
        &cx,
        &f.h.book,
        &admission,
        requests,
        template,
        &mut budget,
    )
}

#[test]
fn post_only_draft_carrying_matches_native_effects_and_promotes_exactly() {
    for base in [1, 6, 10] {
        let mut f = fixture(3, base);
        let second = f.another_target();
        let name = "confined-foreign-carrying";
        let planner = confined_planner(&f, name, 3, 10);
        f.h.open_draft(planner.clone(), name).unwrap();
        let requests = [f.fx_request(f.target, 1), f.fx_request(second, 3)];
        let key = b"confined-foreign-effects";
        let mut expected = f.prepare_group(&requests, key).unwrap().into_proposal();
        expected.principal_ref = AGENT;
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let proposal = prepare_confined_group(&mut f, &planner, name, &requests, key)
            .unwrap()
            .unwrap();
        assert_eq!(proposal, expected);
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert_eq!(f.carrying().open_native.mantissa, 3);
        assert_eq!(f.carrying().open_base.mantissa, base);
        assert!(
            fa_journal::policy::admit_reads(&f.h.db, &f.h.book, AGENT, &planner)
                .unwrap()
                .is_err()
        );
        let mut direct = request(proposal.clone());
        direct.capability = planner.clone();
        assert_eq!(f.h.post(direct).unwrap_err().exit, exit::SAFETY);
        let planned =
            f.h.plan_draft(planner.clone(), name, proposal.clone())
                .unwrap();
        let reviewed = planned.plan.unwrap().members()[0].entry.clone();
        assert_eq!(reviewed.proposal, proposal);
        let promoted = f.h.promote(f.h.approver_capability(), name).unwrap();
        assert_eq!(promoted.entries.len(), 1);
        assert_eq!(promoted.entries[0].entry_digest, reviewed.entry_digest);
        let (posted, _) = read_entry(&f.h.db, promoted.entries[0].vid)
            .unwrap()
            .unwrap();
        assert_eq!(posted, reviewed);
        assert_eq!(f.carrying().open_native.mantissa, 2);
        assert_eq!(f.carrying_for(second).open_native.mantissa, 0);
        f.verify();
        let head = f.h.db.frontier().unwrap();
        assert_eq!(
            prepare_confined_group(&mut f, &planner, name, &requests, key)
                .unwrap()
                .unwrap_err()
                .code,
            fa_journal::refusal::code::DRAFT_NOT_OPEN
        );
        assert_eq!(f.h.db.frontier().unwrap(), head);
    }
}

#[test]
fn confined_carrying_checks_declared_and_generated_ceilings_without_source_balances() {
    let mut f = fixture(3, 10);
    let name = "bounded-foreign-carrying";
    let planner = confined_planner(&f, name, 3, 10);
    f.h.open_draft(planner.clone(), name).unwrap();
    let input = f.fx_request(f.target, 1);
    let head = f.h.db.frontier().unwrap();
    for (native_limit, cash_limit, amount) in [(1, 10, 2), (3, 1, 1)] {
        let restricted = confined_planner(&f, name, native_limit, cash_limit);
        let mut absent = f.fx_request(f.target, amount);
        absent.target.vid = VId(0xdead);
        absent.rate_document = Oid([0xee; 32]);
        let denied = prepare_confined_group(
            &mut f,
            &restricted,
            name,
            &[absent],
            b"declared-ceiling-before-source",
        )
        .unwrap()
        .unwrap_err();
        assert_eq!(denied.code, fa_policy::denial::code::CEILING);
        assert!(denied.message.contains("ceiling"), "{denied}");
        assert_eq!(f.h.db.frontier().unwrap(), head);
    }
    // Requested cash is 2, but one third of the retained basis relieves 3.
    // The larger generated USD conversion effect must also fit the token.
    let generated_limit = confined_planner(&f, name, 3, 2);
    let denied = prepare_confined_group(
        &mut f,
        &generated_limit,
        name,
        std::slice::from_ref(&input),
        b"generated-ceiling",
    )
    .unwrap()
    .unwrap_err();
    assert_eq!(denied.code, fa_policy::denial::code::CEILING);
    assert_eq!(
        denied.message,
        "generated posting effects exceed the capability's permitted scope or amount ceiling"
    );
    assert!(denied.detail.is_none(), "{denied:?}");
    assert_eq!(f.h.db.frontier().unwrap(), head);
    assert_eq!(f.carrying().open_base.mantissa, 10);
}

#[test]
fn confined_carrying_handles_are_scoped_and_source_authority_is_rechecked() {
    for revoke in [false, true] {
        let mut f = fixture(3, 10);
        let name = "current-foreign-source-authority";
        let planner = confined_planner(&f, name, 3, 10);
        f.h.open_draft(planner.clone(), name).unwrap();
        let source = fa_journal::draft::admit_sources(&f.h.db, &f.h.book, &planner, name)
            .unwrap()
            .unwrap();
        let cx = f.h.ctx();
        assert_eq!(
            fa_journal::carrying::draft_source_entry_ref(
                &mut f.h.db,
                &cx,
                &f.h.book,
                &source,
                f.target.vid,
            )
            .unwrap()
            .unwrap(),
            Some(f.target)
        );
        assert_eq!(
            fa_journal::carrying::draft_source_entry_ref(
                &mut f.h.db,
                &cx,
                &f.h.book,
                &source,
                VId(0xdead),
            )
            .unwrap()
            .unwrap(),
            None
        );
        let input = f.fx_request(f.target, 1);
        let proposal = prepare_confined_group(
            &mut f,
            &planner,
            name,
            std::slice::from_ref(&input),
            b"source-authority-recheck",
        )
        .unwrap()
        .unwrap();
        f.h.plan_draft(planner.clone(), name, proposal).unwrap();
        let expected = if revoke {
            f.h.revoke(&planner, 182);
            "FA-REF-023"
        } else {
            f.h.discard(planner.clone(), name).unwrap();
            fa_journal::refusal::code::DRAFT_NOT_OPEN
        };
        let head = f.h.db.frontier().unwrap();
        let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
        damage.set_vertex_property(
            f.target.vid,
            property::FA_PAYLOAD,
            Some(CanonicalScalar::bytes(vec![0xff]).unwrap()),
        );
        f.h.write_raw(damage);
        let denied = fa_journal::carrying::draft_source_entry_ref(
            &mut f.h.db,
            &cx,
            &f.h.book,
            &source,
            f.target.vid,
        )
        .unwrap()
        .unwrap_err();
        assert_eq!(
            denied.code, expected,
            "authority must precede the poisoned source"
        );
        assert_eq!(f.h.db.frontier().unwrap().0, head.0 + 1);
    }
}

#[test]
fn confined_source_handles_reject_foreign_books_and_non_item_classes_before_decode() {
    for wrong_book in [false, true] {
        let mut f = fixture(3, 10);
        let name = "typed-open-item-handles";
        let planner = confined_planner(&f, name, 3, 10);
        f.h.open_draft(planner.clone(), name).unwrap();
        let source = fa_journal::draft::admit_sources(&f.h.db, &f.h.book, &planner, name)
            .unwrap()
            .unwrap();
        let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
        damage.set_vertex_property(
            f.target.vid,
            property::FA_PAYLOAD,
            Some(CanonicalScalar::bytes(vec![0xff]).unwrap()),
        );
        if wrong_book {
            damage.set_vertex_property(
                f.target.vid,
                property::BOOK_ID,
                Some(CanonicalScalar::bytes(vec![0xee; 16]).unwrap()),
            );
        } else {
            damage.set_vertex_property(
                f.target.vid,
                property::CLASS,
                Some(CanonicalScalar::Int(i64::from(EntryClass::DRAFT_CONTROL.0))),
            );
        }
        f.h.write_raw(damage);
        let cx = f.h.ctx();
        let head = f.h.db.frontier().unwrap();
        for vid in [f.target.vid, VId(0xdead)] {
            assert_eq!(
                fa_journal::carrying::draft_source_entry_ref(
                    &mut f.h.db,
                    &cx,
                    &f.h.book,
                    &source,
                    vid,
                )
                .unwrap()
                .unwrap(),
                None,
                "unavailable source metadata must prevent poisoned payload decoding"
            );
        }
        assert_eq!(f.h.db.frontier().unwrap(), head);
    }
}

fn agent_proposal(prepared: PreparedFxSettlement) -> EntryPayload {
    let mut proposal = prepared.into_proposal();
    proposal.principal_ref = AGENT;
    proposal
}

fn planned_pair(f: &mut Fixture, name: &str, second_amount: i128) -> (EntryRef, Vec<EntryRef>) {
    let second = f.another_target();
    let agent = f.h.agent_capability();
    f.h.open_draft(agent.clone(), name).unwrap();
    let first = agent_proposal(f.prepare(1, b"draft-fx-first"));
    let later = agent_proposal(f.prepare_for(second, second_amount, b"draft-fx-second"));
    f.h.plan_draft(agent.clone(), name, first).unwrap();
    let planned = f.h.plan_draft(agent, name, later).unwrap();
    let entries = planned
        .plan
        .unwrap()
        .members()
        .iter()
        .map(|member| {
            member.entry.entry_ref(entry_vid(
                f.h.book.book_id,
                &AGENT.0.to_le_bytes(),
                &member.entry.proposal.idempotency_key,
            ))
        })
        .collect();
    (second, entries)
}

fn assert_unpublished(f: &Fixture, name: &str, entries: &[EntryRef]) {
    assert_eq!(f.h.draft(name).state, DraftState::Open);
    for entry in entries {
        assert!(read_entry(&f.h.db, entry.vid).unwrap().is_none());
    }
}

#[test]
fn an_agent_drafts_foreign_relief_and_an_independent_human_promotes_exactly_once() {
    for (base, second_amount, expected) in [(10, 3, [(2, 7), (0, 0)]), (1, 1, [(2, 1), (2, 1)])] {
        let mut f = fixture(3, base);
        let name = "foreign-collections";
        let (second, entries) = planned_pair(&mut f, name, second_amount);
        assert_unpublished(&f, name, &entries);
        for target in [f.target, second] {
            let item = f.carrying_for(target);
            assert_eq!(
                (item.open_native.mantissa, item.open_base.mantissa),
                (3, base)
            );
        }

        // Planning does not give the Agent a direct trunk capability, and
        // the owner cannot impersonate an independent promoter.
        let before = f.h.db.frontier().unwrap();
        let mut direct = request(agent_proposal(f.prepare(1, b"agent-cannot-publish")));
        direct.capability = f.h.agent_capability();
        assert_eq!(f.h.post(direct).unwrap_err().exit, exit::SAFETY);
        let owner = Capability::embedded(AGENT, &["read", "approve"]).unwrap();
        let refusal = f.h.promote(owner, name).unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-008", exit::SAFETY));
        assert_eq!(f.h.db.frontier().unwrap(), before);

        let promoted = f.h.promote(f.h.approver_capability(), name).unwrap();
        assert_eq!(promoted.recorded_at.0, before.0 + 1);
        assert_eq!(promoted.entries, entries);
        assert!(!promoted.already_recorded);
        for target in &promoted.entries {
            let (entry, recorded_at) = read_entry(&f.h.db, target.vid).unwrap().unwrap();
            assert_eq!(entry.entry_digest, target.entry_digest);
            assert_eq!(recorded_at, promoted.recorded_at);
            assert_eq!(entry.proposal.principal_ref, AGENT);
        }
        for (target, expected) in [f.target, second].into_iter().zip(expected) {
            let item = f.carrying_for(target);
            assert_eq!(
                (item.open_native.mantissa, item.open_base.mantissa),
                expected
            );
        }
        assert_eq!(f.h.draft(name).state, DraftState::Promoted);
        f.verify();
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
fn changed_later_foreign_relief_refuses_the_entire_draft_without_repricing_it() {
    let mut f = fixture(3, 10);
    let name = "foreign-carrying-drift";
    let (second, entries) = planned_pair(&mut f, name, 1);
    // Both reviewed applications relieved 3. A competing application to
    // the later target leaves 2 native / 7 base, whose next 1 relieves 4.
    let competing = f
        .prepare_for(second, 1, b"competing-foreign-receipt")
        .into_proposal();
    f.h.post(request(competing)).unwrap();
    let before = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    let refusal = f.h.promote(f.h.approver_capability(), name).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-071", "{refusal}");
    assert!(refusal.message.contains("batch member 1"), "{refusal}");
    assert_eq!(f.h.db.frontier().unwrap(), before);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
    assert_unpublished(&f, name, &entries);
    let first = f.carrying();
    let later = f.carrying_for(second);
    assert_eq!(
        (first.open_native.mantissa, first.open_base.mantissa),
        (3, 10)
    );
    assert_eq!(
        (later.open_native.mantissa, later.open_base.mantissa),
        (2, 7)
    );
    f.verify();
}

#[test]
fn revoked_foreign_draft_planner_cannot_be_replaced_by_the_promoters_authority() {
    let mut f = fixture(3, 10);
    let name = "revoked-foreign-planner";
    let (second, entries) = planned_pair(&mut f, name, 1);
    let agent = f.h.agent_capability();
    f.h.revoke(&agent, 181);
    let before = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    let refusal = f.h.promote(f.h.approver_capability(), name).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-023", exit::SAFETY));
    assert_eq!(f.h.db.frontier().unwrap(), before);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
    assert_unpublished(&f, name, &entries);
    for target in [f.target, second] {
        let item = f.carrying_for(target);
        assert_eq!(
            (item.open_native.mantissa, item.open_base.mantissa),
            (3, 10)
        );
    }
}

#[test]
fn an_agent_drafts_independent_native_and_foreign_members_in_either_order() {
    for fx_first in [false, true] {
        let mut f = fixture(3, 10);
        let name = "mixed-foreign-collections";
        let agent = f.h.agent_capability();
        f.h.open_draft(agent.clone(), name).unwrap();
        let fx = agent_proposal(f.prepare(1, b"draft-mixed-fx"));
        let plain = f.h.agent_rent(1, b"draft-mixed-native");
        let members = if fx_first {
            vec![fx, plain]
        } else {
            vec![plain, fx]
        };
        f.h.plan_draft(agent.clone(), name, members[0].clone())
            .unwrap();
        let planned = f.h.plan_draft(agent, name, members[1].clone()).unwrap();
        let entries: Vec<_> = planned
            .plan
            .unwrap()
            .members()
            .iter()
            .map(|member| {
                member.entry.entry_ref(entry_vid(
                    f.h.book.book_id,
                    &AGENT.0.to_le_bytes(),
                    &member.entry.proposal.idempotency_key,
                ))
            })
            .collect();
        assert_unpublished(&f, name, &entries);
        assert_eq!(f.carrying().open_base.mantissa, 10);
        let before = f.h.db.frontier().unwrap();
        let promoted = f.h.promote(f.h.approver_capability(), name).unwrap();
        assert_eq!(promoted.recorded_at.0, before.0 + 1);
        assert_eq!(promoted.entries, entries);
        assert!(!promoted.already_recorded);
        for (entry_ref, proposed) in promoted.entries.iter().zip(&members) {
            let (entry, recorded_at) = read_entry(&f.h.db, entry_ref.vid).unwrap().unwrap();
            assert_eq!(recorded_at, promoted.recorded_at);
            assert_eq!(entry.proposal.principal_ref, AGENT);
            assert_eq!(entry.proposal.idempotency_key, proposed.idempotency_key);
            assert_eq!(entry.proposal.legs, proposed.legs);
        }
        let carrying = f.carrying();
        assert_eq!(
            (carrying.open_native.mantissa, carrying.open_base.mantissa),
            (2, 7)
        );
        assert_eq!(f.h.draft(name).state, DraftState::Promoted);
        f.verify();
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
fn foreign_drafts_still_refuse_overlapping_sources_mixed_members_and_groups() {
    for variant in ["overlap", "forged-overlap", "mixed", "group"] {
        let mut f = fixture(3, 10);
        let second = f.another_target();
        let agent = f.h.agent_capability();
        f.h.open_draft(agent.clone(), variant).unwrap();
        let first = agent_proposal(f.prepare(1, b"first-foreign-member"));
        f.h.plan_draft(agent.clone(), variant, first).unwrap();
        let mut later = match variant {
            "mixed" => {
                let mut proposal = f.h.agent_rent(1, b"dependent-native-member");
                proposal.legs[0].account_ref = account_vid(f.h.book.book_id, "1211");
                proposal
            }
            "group" => {
                let mut proposal = f
                    .prepare_group(
                        &[f.fx_request(f.target, 1), f.fx_request(second, 1)],
                        b"multiple-targets-in-one-member",
                    )
                    .unwrap()
                    .into_proposal();
                proposal.principal_ref = AGENT;
                proposal
            }
            _ => agent_proposal(f.prepare(1, b"same-foreign-source")),
        };
        if variant == "forged-overlap" {
            let applying = later
                .legs
                .iter_mut()
                .find(|leg| !leg.settles.is_empty())
                .unwrap();
            applying.settles[0].target.entry_digest[0] ^= 1;
        }
        let before = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let planned = f.h.draft(variant);
        let refusal = f.h.plan_draft(agent, variant, later).unwrap_err();
        assert_eq!(refusal.code, "FA-REF-071", "{variant}: {refusal}");
        assert_eq!(f.h.db.frontier().unwrap(), before);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert_eq!(f.h.draft(variant), planned);
    }
}
