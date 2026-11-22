use super::*;

fn plan_invoice(f: &mut Fixture, name: &str, law: FxLawId) -> (Capability, EntryRef, EntryPayload) {
    let mut invoice = quoted_original(f, law, b"fresh-draft-fx-invoice");
    invoice.principal_ref = AGENT;
    let capability = confined_source_capability(f, name);
    f.h.open_draft(capability.clone(), name).unwrap();
    let planned =
        f.h.plan_draft(capability.clone(), name, invoice.clone())
            .unwrap();
    let preview = planned.plan.unwrap();
    let vid = entry_vid(
        f.h.book.book_id,
        &AGENT.0.to_le_bytes(),
        &invoice.idempotency_key,
    );
    let target = preview.members()[0].entry.entry_ref(vid);
    assert!(read_entry(&f.h.db, vid).unwrap().is_none());
    (capability, target, invoice)
}

fn prepare_application(
    f: &mut Fixture,
    capability: &Capability,
    name: &str,
    target: EntryRef,
    amount: i128,
    key: &[u8],
) -> EntryPayload {
    let admission = fa_journal::draft::admit_sources(&f.h.db, &f.h.book, capability, name)
        .unwrap()
        .unwrap();
    let request = f.fx_request(target, amount);
    let template = source_template(f, key);
    prepare_confined(f, &admission, &[request], template).unwrap()
}

#[test]
fn post_only_draft_settles_its_reviewed_fx_invoice_and_rehearses_and_promotes_exactly() {
    for law in [FxLawId::SpotClose, FxLawId::PeriodAverage] {
        for amount in [3, 8] {
            let mut f = fixture(3, 10);
            let name = "new-foreign-invoice-and-application";
            let (capability, target, _) = plan_invoice(&mut f, name, law);
            let admission = fa_journal::draft::admit_sources(&f.h.db, &f.h.book, &capability, name)
                .unwrap()
                .unwrap();
            let cx = f.h.ctx();
            assert_eq!(
                fa_journal::carrying::draft_source_entry_ref(
                    &mut f.h.db,
                    &cx,
                    &f.h.book,
                    &admission,
                    target.vid,
                )
                .unwrap()
                .unwrap(),
                Some(target),
            );
            assert!(fa_policy::admit_read(&capability, AGENT, f.h.book.book_id).is_err());
            let before = f.h.db.frontier().unwrap();
            let proposal = prepare_application(
                &mut f,
                &capability,
                name,
                target,
                amount,
                b"fresh-fx-application",
            );
            assert_eq!(f.h.db.frontier().unwrap(), before);
            let relief = if amount == 8 { 3 } else { 1 };
            assert_eq!(proposal.legs[0].base_amount.unwrap().mantissa, relief);
            assert_eq!(proposal.legs[0].settles[0].target, target);
            let planned =
                f.h.plan_draft(capability.clone(), name, proposal.clone())
                    .unwrap();
            let retained_at = planned.recorded.recorded_at;
            let preview = planned.plan.unwrap();
            assert_eq!(preview.members().len(), 2);
            let expected: Vec<_> = preview
                .members()
                .iter()
                .map(|member| {
                    let entry = &member.entry;
                    entry.entry_ref(entry_vid(
                        f.h.book.book_id,
                        &AGENT.0.to_le_bytes(),
                        &entry.proposal.idempotency_key,
                    ))
                })
                .collect();
            assert_eq!(expected[0], target);
            assert_unpublished(&f, name, &expected);
            assert_eq!(
                f.carrying().open_native.mantissa,
                3,
                "existing trunk item is untouched"
            );

            let known_at = f.h.db.frontier().unwrap();
            let rows = f.h.db.vertices().unwrap();
            let scratch = f
                .h
                .runtime
                .block_on(Database::open_memory(
                    &cx.commit(),
                    DatabaseKeys::new([191; 32], DatabaseSecurityNamespaceId([192; 32]), [193; 32]),
                ))
                .unwrap();
            let (scratch, rehearsal) =
                f.h.runtime
                    .block_on(fa_journal::draft::rehearse_draft_into(
                        &mut f.h.db,
                        scratch,
                        &cx,
                        &f.h.book,
                        &Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
                        fa_journal::draft::DraftRehearsalRequest {
                            name: name.into(),
                            known_at,
                        },
                    ))
                    .unwrap()
                    .unwrap();
            assert_eq!(rehearsal.batch.entries, expected);
            let scratch_item = open_item_carrying_at(
                &scratch,
                &cx,
                &f.h.book,
                target,
                0,
                scratch.frontier().unwrap(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                (
                    scratch_item.open_native.mantissa,
                    scratch_item.open_base.mantissa
                ),
                (8 - amount, 3 - relief)
            );
            let verified = cx
                .query()
                .with_restriction(|| {
                    verify_fx_conversions(&scratch, &cx, &f.h.book, scratch.frontier().unwrap())
                })
                .unwrap();
            assert!(verified.is_green(), "{:?}", verified.drift);
            assert_eq!(f.h.db.frontier().unwrap(), known_at);
            assert_eq!(f.h.db.vertices().unwrap(), rows);

            let promoted = f.h.promote(f.h.approver_capability(), name).unwrap();
            assert_eq!(promoted.recorded_at.0, known_at.0 + 1);
            assert_eq!(promoted.entries, expected);
            for reference in &expected {
                assert_eq!(
                    read_entry(&f.h.db, reference.vid).unwrap().unwrap().1,
                    promoted.recorded_at
                );
            }
            let carrying = f.carrying_for(target);
            assert_eq!(
                (carrying.open_native.mantissa, carrying.open_base.mantissa),
                (8 - amount, 3 - relief)
            );
            f.verify();
            let rows = f.h.db.vertices().unwrap();
            let retry = f.h.plan_draft(capability, name, proposal).unwrap();
            assert!(retry.recorded.already_recorded);
            assert_eq!(retry.recorded.recorded_at, retained_at);
            let retry = f.h.promote(f.h.approver_capability(), name).unwrap();
            assert!(retry.already_recorded);
            assert_eq!(retry.entries, expected);
            assert_eq!(f.h.db.frontier().unwrap(), promoted.recorded_at);
            assert_eq!(f.h.db.vertices().unwrap(), rows);
        }
    }
}

#[test]
fn fresh_draft_fx_sources_cannot_escape_into_direct_or_portable_batches_or_forward_order() {
    let mut f = fixture(3, 10);
    let name = "fresh-source-admission";
    let (capability, target, invoice) = plan_invoice(&mut f, name, FxLawId::SpotClose);
    let proposal = prepare_application(
        &mut f,
        &capability,
        name,
        target,
        3,
        b"fresh-source-payment",
    );
    let batch = f.h.batch(
        b"fresh-source-native-batch",
        vec![invoice.clone(), proposal.clone()],
    );
    let human = Capability::embedded(AGENT, &["read", "post"]).unwrap();
    let before = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    let refusal = f.h.planned_batch(batch.clone(), &human).unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::SETTLE_SHAPE);
    let cx = f.h.ctx();
    let refusal =
        f.h.runtime
            .block_on(fa_journal::post_batch(
                &mut f.h.db,
                &cx,
                &f.h.book,
                human.clone(),
                batch.clone(),
            ))
            .unwrap()
            .unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::SETTLE_SHAPE);
    assert_eq!(f.h.db.frontier().unwrap(), before);
    assert_eq!(f.h.db.vertices().unwrap(), rows);

    // Even a harness-authenticated portable transcript cannot acquire the
    // private draft dependency proof. The real planner refuses to issue one.
    let entries = batch
        .members()
        .iter()
        .map(|member| member.proposal().clone().seal(Vec::new(), None).unwrap())
        .collect::<Vec<_>>();
    let periods = vec![f.h.march.clone(); entries.len()];
    let mut certificate = fa_intents::BatchPlanCertificate {
        book_id: batch.book_id(),
        branch_id: batch.branch_id(),
        principal: batch.principal(),
        capability_commitment: human.commitment().unwrap(),
        intent_digest: batch.digest().unwrap(),
        prepared_digest: fa_intents::BatchPlan::prepared_digest(&entries, &periods).unwrap(),
        effects_digest: [0; 32],
        snapshot_seq: before,
        security_policy_epoch: 0,
        expires_at: None,
        authentication: [0; 32],
    };
    let key = fgdb_crypto::derive_key("fa:batch-plan-authentication-key:v1", &f.h.book.seal_key.0);
    certificate.authentication =
        fgdb_crypto::keyed_hash(&key, &certificate.authentication_bytes().unwrap()).0;
    let portable = fa_intents::BatchPlan::new(batch, entries, periods, certificate).unwrap();
    let portable = fa_intents::BatchPlan::decode(&portable.canonical_bytes().unwrap()).unwrap();
    let refusal = f.h.publish_batch_plan(portable, &human).unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::PLAN_INVALIDATED);
    assert!(
        refusal.message.contains("earlier quoted Original"),
        "{refusal}"
    );
    assert_eq!(f.h.db.frontier().unwrap(), before);
    assert_eq!(f.h.db.vertices().unwrap(), rows);

    let forward_name = "forward-foreign-source";
    let forward_capability = confined_source_capability(&f, forward_name);
    f.h.open_draft(forward_capability.clone(), forward_name)
        .unwrap();
    let forward = f.h.batch(b"forward-foreign-batch", vec![proposal, invoice]);
    let request = f.h.draft_request(forward_capability);
    let before = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    let refusal =
        f.h.runtime
            .block_on(fa_journal::draft::plan_batch_into_draft(
                &mut f.h.db,
                &cx,
                &f.h.book,
                forward_name,
                forward,
                request,
            ))
            .unwrap()
            .unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::SETTLE_SHAPE);
    assert_eq!(f.h.db.frontier().unwrap(), before);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
    assert!(f.h.draft(forward_name).intents.is_empty());
}

#[test]
fn fresh_draft_fx_refuses_forged_handles_relief_repeated_targets_and_unrelated_source_legs() {
    for variant in ["digest", "relief", "duplicate", "companion"] {
        let mut f = fixture(3, 10);
        let (capability, target, _) = plan_invoice(&mut f, variant, FxLawId::SpotClose);
        let mut proposal = prepare_application(
            &mut f,
            &capability,
            variant,
            target,
            3,
            b"reviewed-new-payment",
        );
        match variant {
            "digest" => proposal.legs[0].settles[0].target.entry_digest[0] ^= 1,
            "relief" => {
                // This validly balanced settlement was derived from an existing
                // 3-native/10-base item, not this new 8-native/3-base invoice.
                proposal = agent_proposal(f.prepare(1, b"forged-fresh-relief"));
                proposal.legs[0].settles[0].target = target;
            }
            "duplicate" => {
                f.h.plan_draft(capability.clone(), variant, proposal.clone())
                    .unwrap();
                proposal.idempotency_key = b"second-fresh-application".to_vec();
            }
            "companion" => {
                f.h.plan_draft(capability.clone(), variant, proposal)
                    .unwrap();
                proposal = f.h.agent_rent(1, b"unrelated-source-account-effect");
                proposal.legs[0].account_ref = account_vid(f.h.book.book_id, "1211");
            }
            _ => unreachable!(),
        }
        let before = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let view = f.h.draft(variant);
        let refusal = f.h.plan_draft(capability, variant, proposal).unwrap_err();
        assert_eq!(
            refusal.code,
            fa_journal::refusal::code::SETTLE_SHAPE,
            "{variant}: {refusal}"
        );
        assert_eq!(f.h.db.frontier().unwrap(), before);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert_eq!(f.h.draft(variant), view);
        assert!(read_entry(&f.h.db, target.vid).unwrap().is_none());
    }
}

#[test]
fn fresh_draft_fx_source_is_owned_and_original_planner_authority_is_rechecked() {
    let mut f = fixture(3, 10);
    let name = "owned-new-source";
    let (capability, target, _) = plan_invoice(&mut f, name, FxLawId::SpotClose);
    let other_name = "different-owned-draft";
    let other = confined_source_capability(&f, other_name);
    f.h.open_draft(other.clone(), other_name).unwrap();
    let admission = fa_journal::draft::admit_sources(&f.h.db, &f.h.book, &other, other_name)
        .unwrap()
        .unwrap();
    let cx = f.h.ctx();
    assert_eq!(
        fa_journal::carrying::draft_source_entry_ref(
            &mut f.h.db,
            &cx,
            &f.h.book,
            &admission,
            target.vid,
        )
        .unwrap()
        .unwrap(),
        None
    );
    let proposal = prepare_application(
        &mut f,
        &capability,
        name,
        target,
        3,
        b"owned-source-payment",
    );
    f.h.plan_draft(capability.clone(), name, proposal).unwrap();
    f.h.revoke(&capability, 194);
    let before = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    let view = f.h.draft(name);
    let refusal = f.h.promote(f.h.approver_capability(), name).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-023");
    assert_eq!(f.h.db.frontier().unwrap(), before);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
    assert_eq!(f.h.draft(name), view);
    assert!(read_entry(&f.h.db, target.vid).unwrap().is_none());
}
