//! Native drafts retain the reviewed foreign relief and promote independent
//! existing items through the same guarded atomic carrying-value batch law.

use super::*;
use fgdb::WriteBatch;

fn quoted_original(f: &mut Fixture, law: FxLawId, key: &[u8]) -> EntryPayload {
    let (as_of, purpose) = match law {
        FxLawId::SpotClose => (f.h.day(), FxRatePurpose::SpotClose),
        FxLawId::PeriodAverage => (
            DateDay::from_ymd(2026, 3, 31).unwrap(),
            FxRatePurpose::PeriodAverage,
        ),
        _ => panic!("a quoted original requires SpotClose or PeriodAverage"),
    };
    let rate = FxRateDocument::new(
        FxRateTerms {
            base_unit: f.h.usd,
            quote_unit: f.foreign,
            rate_num: 1,
            rate_den: 3,
            rounding: RoundingLaw::HalfEven,
        },
        as_of,
        1,
        purpose,
        "immutable quotation for an atomic original and reversal",
    )
    .unwrap();
    f.h.add_document(
        &rate
            .document(f.h.book.book_id, PRINCIPAL, HUMAN_UPLOAD)
            .unwrap(),
    )
    .unwrap();
    let receivable = account_vid(f.h.book.book_id, "1211");
    let revenue = account_vid(f.h.book.book_id, "4011");
    let original = f.h.proposal(
        vec![
            LegPayload::simple(Side::Debit, receivable, Amount::new(f.foreign, 8)),
            LegPayload::simple(Side::Credit, revenue, Amount::new(f.foreign, 4)),
            LegPayload::simple(Side::Credit, revenue, Amount::new(f.foreign, 4)),
        ],
        key,
        EntryClass::ORIGINAL,
    );
    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(100_000, 0), 4096);
    let spec = fa_journal::genesis::read_book_spec(&f.h.db)
        .unwrap()
        .unwrap();
    let valued =
        value_proposal(&mut budget, original, &spec, &f.h.book.units, law, &[rate]).unwrap();
    assert_eq!(
        valued
            .legs
            .iter()
            .map(|leg| leg.base_amount.unwrap().mantissa)
            .collect::<Vec<_>>(),
        [3, 2, 1],
        "the exact undo must retain the original's rounding residual"
    );
    valued
}

#[test]
fn recorded_fx_reversals_compose_with_staged_originals_and_confined_drafts() {
    for law in [FxLawId::SpotClose, FxLawId::PeriodAverage] {
        for draft in [false, true] {
            let mut f = fixture(3, 10);
            let mut original = quoted_original(&mut f, law, b"atomic-quoted-original");
            if draft {
                original.principal_ref = AGENT;
            }
            let target = f.h.member_ref(&original);
            let reversal = undo(&original, target, b"atomic-quoted-reversal");
            let expected = [original.clone(), reversal.clone()];
            let (entries, recorded_at) = if draft {
                let name = "quoted-original-and-undo";
                let planner = confined_source_capability(&f, name);
                f.h.open_draft(planner.clone(), name).unwrap();
                f.h.plan_draft(planner.clone(), name, original).unwrap();
                let planned = f.h.plan_draft(planner.clone(), name, reversal).unwrap();
                let preview = planned.plan.unwrap();
                assert_eq!(preview.members().len(), 2);
                for (member, proposal) in preview.members().iter().zip(&expected) {
                    assert_eq!(&member.entry.proposal, proposal);
                }
                assert!(read_entry(&f.h.db, target.vid).unwrap().is_none());
                assert!(
                    read_entry(&f.h.db, reversal_vid(target.vid))
                        .unwrap()
                        .is_none()
                );
                assert!(fa_policy::admit_read(&planner, AGENT, f.h.book.book_id).is_err());
                let before = f.h.db.frontier().unwrap();
                let promoted = f.h.promote(f.h.approver_capability(), name).unwrap();
                assert_eq!(promoted.recorded_at.0, before.0 + 1);
                for (reference, member) in promoted.entries.iter().zip(preview.members()) {
                    assert_eq!(reference.entry_digest, member.entry.entry_digest);
                }
                (promoted.entries, promoted.recorded_at)
            } else {
                let batch = f.h.batch(b"atomic-quoted-batch", vec![original, reversal]);
                let before = f.h.db.frontier().unwrap();
                let posted = f.post_fx_batch(batch.clone()).unwrap();
                assert_eq!(posted.recorded_at.0, before.0 + 1);
                let retry = f.post_fx_batch(batch).unwrap();
                assert!(retry.already_recorded);
                assert_eq!(retry.entries, posted.entries);
                assert_eq!(retry.recorded_at, posted.recorded_at);
                assert_eq!(f.h.db.frontier().unwrap(), posted.recorded_at);
                (posted.entries, posted.recorded_at)
            };
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0], target);
            assert_eq!(entries[1].vid, reversal_vid(target.vid));
            for (reference, proposal) in entries.iter().zip(&expected) {
                let (entry, sequence) = read_entry(&f.h.db, reference.vid).unwrap().unwrap();
                assert_eq!(&entry.proposal, proposal);
                assert_eq!(sequence, recorded_at);
            }
            assert_eq!(f.carrying().open_native.mantissa, 3);
            assert_eq!(f.carrying().open_base.mantissa, 10);
            f.verify();
        }
    }
}

#[test]
fn recorded_fx_reversal_batches_reject_forged_handles_and_side_swaps_atomically() {
    for law in [FxLawId::SpotClose, FxLawId::PeriodAverage] {
        for forged_handle in [false, true] {
            let mut f = fixture(3, 10);
            let original = quoted_original(&mut f, law, b"forged-quoted-original");
            let target = f.h.member_ref(&original);
            let mut reversal = undo(&original, target, b"forged-quoted-reversal");
            let expected_code = if forged_handle {
                reversal.supersession[0].target.entry_digest[0] ^= 1;
                fa_journal::refusal::code::REVERSAL_TARGET
            } else {
                // Still balanced and validly valued, but no longer the
                // original's exact account-by-account side swap.
                reversal.legs[1].account_ref = f.conversion;
                fa_journal::refusal::code::REVERSAL_SHAPE
            };
            let batch = f.h.batch(b"forged-quoted-batch", vec![original, reversal]);
            let outcome = fa_journal::batch::outcome_vid(&f.h.book, &batch);
            let before = f.h.db.frontier().unwrap();
            let rows = f.h.db.vertices().unwrap();
            let refused = f.post_fx_batch(batch).unwrap_err();
            assert_eq!(refused.code, expected_code, "{law:?}: {refused}");
            assert!(refused.message.contains("member 1"), "{refused}");
            assert_eq!(f.h.db.frontier().unwrap(), before);
            assert_eq!(f.h.db.vertices().unwrap(), rows);
            assert!(f.h.db.vertex(outcome).unwrap().is_none());
            assert!(read_entry(&f.h.db, target.vid).unwrap().is_none());
            assert!(
                read_entry(&f.h.db, reversal_vid(target.vid))
                    .unwrap()
                    .is_none()
            );
            f.verify();
        }
    }
}

#[test]
fn recorded_fx_reversal_batch_plans_keep_the_complete_prefix_guard() {
    for law in [FxLawId::SpotClose, FxLawId::PeriodAverage] {
        let mut f = fixture(3, 10);
        let original = quoted_original(&mut f, law, b"guarded-quoted-original");
        let target = f.h.member_ref(&original);
        let reversal = undo(&original, target, b"guarded-quoted-reversal");
        let batch = f.h.batch(b"guarded-quoted-batch", vec![original, reversal]);
        let capability = Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap();
        let before = f.h.db.frontier().unwrap();
        let plan = f.h.planned_batch(batch.clone(), &capability).unwrap();
        assert_eq!(f.h.db.frontier().unwrap(), before);
        let document =
            f.h.document(INVOICE, HUMAN_UPLOAD, b"unrelated later evidence");
        f.h.add_document(&document).unwrap();
        let before = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let refused = f.h.publish_batch_plan(plan, &capability).unwrap_err();
        assert_eq!(refused.code, fa_journal::refusal::code::PLAN_INVALIDATED);
        assert_eq!(f.h.db.frontier().unwrap(), before);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert!(read_entry(&f.h.db, target.vid).unwrap().is_none());
        let fresh = f.h.planned_batch(batch, &capability).unwrap();
        let posted = f.h.publish_batch_plan(fresh, &capability).unwrap();
        assert_eq!(posted.recorded_at.0, before.0 + 1);
        assert_eq!(posted.entries.len(), 2);
        f.verify();
    }
}

fn confined_source_capability(f: &Fixture, name: &str) -> Capability {
    Capability::new(
        AGENT,
        fa_policy::Profile::Agent,
        &[fa_policy::Op::Post],
        PRINCIPAL,
    )
    .unwrap()
    .on_branch(fa_model::draft_branch(f.h.book.book_id, name))
    .unwrap()
}

fn source_template(f: &Fixture, key: &[u8]) -> EntryPayload {
    let mut template = f.h.proposal(vec![], key, EntryClass::ORIGINAL);
    template.principal_ref = AGENT;
    template
}

fn prepare_confined(
    f: &mut Fixture,
    admission: &fa_journal::draft::DraftSourceAdmission,
    requests: &[FxSettlementRequest],
    template: EntryPayload,
) -> Result<EntryPayload, Refusal> {
    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
    let cx = f.h.ctx();
    fa_journal::carrying::prepare_fx_settlement_group_in_draft(
        &mut f.h.db,
        &cx,
        &f.h.book,
        admission,
        requests,
        template,
        &mut budget,
    )
    .unwrap()
}

#[test]
fn post_only_draft_settlement_factories_preserve_single_group_and_exact_promotion() {
    for group in [false, true] {
        let mut f = fixture(3, 10);
        let second = f.another_target();
        let name = "confined-carrying";
        let capability = confined_source_capability(&f, name);
        f.h.open_draft(capability.clone(), name).unwrap();
        let admission = fa_journal::draft::admit_sources(&f.h.db, &f.h.book, &capability, name)
            .unwrap()
            .unwrap();
        let mut inputs = vec![f.fx_request(f.target, 1)];
        if group {
            inputs.push(f.fx_request(second, 3));
        }
        let key = b"source-only-fx";
        let mut expected = f.prepare_group(&inputs, key).unwrap().into_proposal();
        expected.principal_ref = AGENT;
        let template = source_template(&f, key);
        let head = f.h.db.frontier().unwrap();
        let proposal = if group {
            prepare_confined(&mut f, &admission, &inputs, template).unwrap()
        } else {
            let stripped = Cx::detached_cancel_context();
            let mut budget =
                ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
            let cx = f.h.ctx();
            fa_journal::carrying::prepare_fx_settlement_in_draft(
                &mut f.h.db,
                &cx,
                &f.h.book,
                &admission,
                &inputs[0],
                template,
                &mut budget,
            )
            .unwrap()
            .unwrap()
        };
        assert_eq!(proposal, expected);
        assert_eq!(proposal.legs[0].base_amount.unwrap().mantissa, 3);
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert!(fa_policy::admit_read(&capability, AGENT, f.h.book.book_id).is_err());
        let planned = f.h.plan_draft(capability, name, proposal.clone()).unwrap();
        assert_eq!(planned.plan.unwrap().members()[0].entry.proposal, proposal);
        assert_eq!(f.carrying().open_native.mantissa, 3);
        let promoted = f.h.promote(f.h.approver_capability(), name).unwrap();
        assert_eq!(promoted.entries.len(), 1);
        assert_eq!(f.carrying().open_native.mantissa, 2);
        assert_eq!(f.carrying().open_base.mantissa, 7);
        assert_eq!(
            f.carrying_for(second).open_native.mantissa,
            if group { 0 } else { 3 }
        );
        f.verify();
        let before = f.h.db.frontier().unwrap();
        let mut unknown_source = inputs;
        unknown_source[0].rate_document = Oid([0xee; 32]);
        let template = source_template(&f, b"closed-source-token");
        let refused = prepare_confined(&mut f, &admission, &unknown_source, template).unwrap_err();
        assert_eq!(refused.code, fa_journal::refusal::code::DRAFT_NOT_OPEN);
        assert_eq!(f.h.db.frontier().unwrap(), before);
    }
}

#[test]
fn draft_settlement_rechecks_declared_and_generated_ceilings_and_revocation() {
    let mut f = fixture(3, 10);
    let name = "confined-carrying-ceilings";
    let capability = confined_source_capability(&f, name)
        .with_ceiling(f.foreign, 1)
        .unwrap()
        .with_ceiling(f.h.usd, 2)
        .unwrap();
    f.h.open_draft(capability.clone(), name).unwrap();
    let admission = fa_journal::draft::admit_sources(&f.h.db, &f.h.book, &capability, name)
        .unwrap()
        .unwrap();
    let inputs = [f.fx_request(f.target, 1)];
    let template = source_template(&f, b"generated-carrying-ceiling");
    let cx = f.h.ctx();
    assert!(
        fa_journal::carrying::admit_draft_settlement_requests(
            &mut f.h.db,
            &cx,
            &f.h.book,
            &admission,
            &inputs,
            &template,
        )
        .unwrap()
        .is_ok(),
        "the declared 1 EUR / 2 USD effects are within their ceilings"
    );
    let head = f.h.db.frontier().unwrap();
    let refused = prepare_confined(&mut f, &admission, &inputs, template.clone()).unwrap_err();
    assert_eq!(refused.exit, exit::SAFETY);
    assert!(refused.message.contains("ceiling"), "{refused}");
    assert_eq!(f.h.db.frontier().unwrap(), head);
    assert!(f.h.draft(name).intents.is_empty());

    let mut invalid = inputs;
    invalid[0].amount.mantissa = 2;
    invalid[0].rate_document = Oid([0xee; 32]);
    let refused = prepare_confined(&mut f, &admission, &invalid, template.clone()).unwrap_err();
    assert!(
        refused.message.contains("ceiling"),
        "declared excess precedes source lookup: {refused}"
    );
    let unconfined = Capability::new(
        AGENT,
        fa_policy::Profile::Agent,
        &[fa_policy::Op::Post],
        PRINCIPAL,
    )
    .unwrap();
    let wrong_owner = Capability::new(
        VId(0xbad),
        fa_policy::Profile::Agent,
        &[fa_policy::Op::Post],
        PRINCIPAL,
    )
    .unwrap()
    .on_branch(fa_model::draft_branch(f.h.book.book_id, name))
    .unwrap();
    for denied in [
        unconfined,
        wrong_owner,
        capability.clone().expiring_at(head),
    ] {
        assert!(
            fa_journal::draft::admit_sources(&f.h.db, &f.h.book, &denied, name)
                .unwrap()
                .is_err()
        );
    }
    f.h.revoke(&capability, 192);
    let revoked_at = f.h.db.frontier().unwrap();
    let refused = prepare_confined(&mut f, &admission, &invalid, template).unwrap_err();
    assert_eq!(refused.code, "FA-REF-023");
    assert_eq!(f.h.db.frontier().unwrap(), revoked_at);
}

#[test]
fn draft_settlement_refuses_poisoned_unrelated_documents_before_rate_payload_decode() {
    let mut f = fixture(3, 10);
    let name = "typed-carrying-source";
    let capability = confined_source_capability(&f, name);
    f.h.open_draft(capability.clone(), name).unwrap();
    let admission = fa_journal::draft::admit_sources(&f.h.db, &f.h.book, &capability, name)
        .unwrap()
        .unwrap();
    let input = f.fx_request(f.target, 1);
    let template = source_template(&f, b"poisoned-rate-kind");
    let mut poison = WriteBatch::new(fa_model::symbols::relation::CUSTODY_OF);
    let vid = fa_journal::evidence::document_vid(&input.rate_document);
    poison.set_vertex_property(
        vid,
        fa_model::symbols::property::CODE,
        Some(fa_journal::rows::scalar_text("kind", "Invoice").unwrap()),
    );
    poison.set_vertex_property(
        vid,
        fa_model::symbols::property::FA_PAYLOAD,
        Some(fa_journal::rows::scalar_bytes("payload", vec![0xff]).unwrap()),
    );
    let cx = f.h.ctx();
    f.h.runtime
        .block_on(f.h.db.write(&cx.commit(), poison))
        .unwrap();
    let head = f.h.db.frontier().unwrap();
    let refused = prepare_confined(&mut f, &admission, &[input.clone()], template).unwrap_err();
    assert_eq!(refused.code, fa_journal::refusal::code::CAPABILITY);
    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
    assert!(
        prepare_fx_settlement(
            &f.h.db,
            &cx,
            &f.h.book,
            &Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
            &input,
            f.h.proposal(vec![], b"ordinary-poisoned-source", EntryClass::ORIGINAL),
            &mut budget,
        )
        .is_err(),
        "the ordinary reader proves that the payload trap is live"
    );
    assert_eq!(f.h.db.frontier().unwrap(), head);
}

#[test]
fn draft_settlement_keeps_same_target_partials_outside_the_independent_source_batch_law() {
    let mut f = fixture(99, 50);
    let name = "confined-repeated-carrying";
    let capability = confined_source_capability(&f, name);
    f.h.open_draft(capability.clone(), name).unwrap();
    let admission = fa_journal::draft::admit_sources(&f.h.db, &f.h.book, &capability, name)
        .unwrap()
        .unwrap();
    let input = f.fx_request(f.target, 33);
    let first = source_template(&f, b"first-confined-partial");
    let proposal = prepare_confined(&mut f, &admission, &[input.clone()], first).unwrap();
    assert_eq!(proposal.legs[0].base_amount.unwrap().mantissa, 17);
    f.h.plan_draft(capability.clone(), name, proposal).unwrap();
    let later = source_template(&f, b"second-confined-partial");
    let proposal = prepare_confined(&mut f, &admission, &[input], later).unwrap();
    let before = f.h.db.frontier().unwrap();
    let refused = f.h.plan_draft(capability, name, proposal).unwrap_err();
    assert_eq!(refused.exit, exit::REFUSAL);
    assert_eq!(f.h.db.frontier().unwrap(), before);
    assert_eq!(f.h.draft(name).intents.len(), 1);
    assert_eq!(
        (
            f.carrying().open_native.mantissa,
            f.carrying().open_base.mantissa
        ),
        (99, 50)
    );
}

#[test]
fn hand_built_draft_settlements_admit_rate_kind_before_hydrating_sources() {
    for law in [
        FxLawId::SettlementCarryingBasis,
        FxLawId::SettlementAllocatedCarrying,
        FxLawId::SettlementSpotCarrying,
    ] {
        let mut f = fixture(3, 10);
        let name = "native-carrying-source";
        let capability = confined_source_capability(&f, name);
        f.h.open_draft(capability.clone(), name).unwrap();
        // Submit retained native proposal bytes directly, without invoking
        // the draft preparation factory that separately admits its sources.
        let mut proposal = f.prepare(1, b"native-untrusted-rate").into_proposal();
        proposal.principal_ref = AGENT;
        proposal.base_totals.as_mut().unwrap().fx_law_oid = law.oid();
        let oid = proposal.base_totals.as_ref().unwrap().rate_doc_oids[0];
        let vid = fa_journal::evidence::document_vid(&oid);
        let mut poison = WriteBatch::new(fa_model::symbols::relation::CUSTODY_OF);
        poison.set_vertex_property(
            vid,
            fa_model::symbols::property::CODE,
            Some(fa_journal::rows::scalar_text("kind", "Invoice").unwrap()),
        );
        poison.set_vertex_property(
            vid,
            fa_model::symbols::property::FA_PAYLOAD,
            Some(fa_journal::rows::scalar_bytes("payload", vec![0xff]).unwrap()),
        );
        let cx = f.h.ctx();
        f.h.runtime
            .block_on(f.h.db.write(&cx.commit(), poison))
            .unwrap();
        let before = f.h.db.frontier().unwrap();
        let refusal = f.h.plan_draft(capability, name, proposal).unwrap_err();
        assert_eq!(
            refusal.code,
            fa_journal::refusal::code::CAPABILITY,
            "{law:?} must not decode the poisoned unrelated payload: {refusal}"
        );
        assert_eq!(f.h.db.frontier().unwrap(), before);
        assert!(f.h.draft(name).intents.is_empty());
    }
}

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

#[test]
fn draft_settlement_validates_selected_leg_before_carrying_history() {
    let mut f = fixture(3, 10);
    let unrelated = f.another_target();
    let name = "selected-foreign-source";
    let capability = confined_source_capability(&f, name);
    f.h.open_draft(capability.clone(), name).unwrap();
    let admission = fa_journal::draft::admit_sources(&f.h.db, &f.h.book, &capability, name)
        .unwrap()
        .unwrap();
    let valid = f.fx_request(f.target, 1);
    let mut poison = WriteBatch::new(fa_model::symbols::relation::CUSTODY_OF);
    poison.set_vertex_property(
        unrelated.vid,
        fa_model::symbols::property::FA_PAYLOAD,
        Some(fa_journal::rows::scalar_bytes("payload", vec![0xff]).unwrap()),
    );
    f.h.write_raw(poison);
    let before = f.h.db.frontier().unwrap();
    for variant in ["ordinal", "native unit", "base unit"] {
        let mut input = valid.clone();
        match variant {
            "ordinal" => input.target_ordinal = u16::MAX,
            "native unit" => input.amount.unit = f.h.usd,
            "base unit" => input.settlement_amount.unit = f.foreign,
            _ => unreachable!(),
        }
        let template = source_template(&f, b"selected-leg-before-history");
        let refusal = prepare_confined(&mut f, &admission, &[input], template).unwrap_err();
        assert_eq!(
            refusal.code,
            fa_journal::refusal::code::SETTLE_SHAPE,
            "{variant}: {refusal}"
        );
        assert_eq!(f.h.db.frontier().unwrap(), before);
    }
    let stripped = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
    assert!(
        prepare_fx_settlement(
            &f.h.db,
            &f.h.ctx(),
            &f.h.book,
            &Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap(),
            &valid,
            f.h.proposal(vec![], b"live-history-trap", EntryClass::ORIGINAL),
            &mut budget,
        )
        .is_err(),
        "an admitted valid target reaches the poisoned history trap"
    );
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
        let unconfined = Capability::new(
            AGENT,
            fa_policy::Profile::Agent,
            &[fa_policy::Op::Post],
            PRINCIPAL,
        )
        .unwrap();
        let denied =
            f.h.plan_draft(unconfined, name, proposal.clone())
                .unwrap_err();
        assert_eq!(denied.code, fa_journal::refusal::code::CAPABILITY);
        assert!(denied.message.contains("requires capability op `read`"));
        assert_eq!(f.h.db.frontier().unwrap(), head);
        let mut overlapping = proposal.clone();
        for application in overlapping
            .legs
            .iter_mut()
            .flat_map(|leg| &mut leg.settles)
            .skip(1)
        {
            application.target = f.target;
        }
        let denied =
            f.h.plan_draft(planner.clone(), name, overlapping)
                .unwrap_err();
        assert_eq!(denied.code, fa_journal::refusal::code::SETTLE_SHAPE);
        assert!(denied.message.contains("distinct existing target legs"));
        assert_eq!(f.h.db.frontier().unwrap(), head);
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
fn confined_carrying_plan_does_not_disclose_withheld_relief_for_a_forged_proposal() {
    let mut f = fixture(3, 10);
    let name = "withheld-foreign-relief";
    let planner = confined_planner(&f, name, 3, 2);
    f.h.open_draft(planner.clone(), name).unwrap();
    // The real historical relief is 3, which this capability cannot disclose.
    // A caller can still author a balanced proposal claiming relief of 2.
    let mut forged = f.prepare(1, b"understated-foreign-relief").into_proposal();
    forged.principal_ref = AGENT;
    forged.legs.retain(|leg| leg.account_ref != f.realized);
    assert_eq!(forged.legs.len(), 4);
    for leg in &mut forged.legs {
        leg.base_amount = Some(Amount::new(f.h.usd, 2));
        if leg.amount.unit == f.h.usd {
            leg.amount.mantissa = 2;
        }
    }
    forged.unit_totals = EntryPayload::fold_unit_totals(&forged.legs).unwrap();
    let totals = forged.base_totals.as_mut().unwrap();
    totals.debits = 4;
    totals.credits = 4;
    forged.validate().unwrap();
    let head = f.h.db.frontier().unwrap();
    let denied = f.h.plan_draft(planner, name, forged).unwrap_err();
    assert_eq!(denied.code, fa_journal::refusal::code::SETTLE_SHAPE);
    assert_eq!(
        denied.message,
        "batch member 0: the proposed foreign settlement does not reproduce its admitted source effects; nothing in the batch was recorded"
    );
    assert_eq!(f.h.db.frontier().unwrap(), head);
    assert!(f.h.draft(name).intents.is_empty());
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
