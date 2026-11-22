//! The explicit-rule draft profile grants no direct or portable publication
//! route, and automatic selections never lose their complete-set binding.

use super::*;

fn synthetic_rule(h: &Harness, key: &[u8]) -> fa_intents::PostIntent {
    let mut p = h.proposal(h.rent_legs(100), key, EntryClass::ORIGINAL);
    let inputs = vec![0; 4];
    p.schema_minor = fa_model::entry::EXTENSIONS_MINOR;
    p.origin = EntryOrigin::Rule {
        rule_version_oid: Oid([91; 32]),
        event_ref: VId(92),
        inputs_digest: fa_model::domain_digest(b"fa:canon-inputs:v1", &[&inputs]),
    };
    p.extensions = vec![(fa_model::entry::RULE_INPUTS_EXTENSION, inputs)];
    fa_intents::PostIntent::rule_derived(p, Vec::new()).unwrap()
}

fn draft_only_refusal(refusal: Refusal) {
    assert_eq!(
        (refusal.code, refusal.exit),
        (refusal::code::STRUCTURE, refusal::exit::USAGE),
        "{refusal}"
    );
    assert!(
        refusal.to_string().contains("native draft lifecycle"),
        "{refusal}"
    );
}

#[test]
fn decoded_explicit_rule_draft_profile_cannot_post_plan_or_confirm_on_trunk() {
    let mut h = harness();
    let capability = Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap();
    let batch = fa_intents::PostBatch::for_draft(
        b"draft-profile".to_vec(),
        vec![synthetic_rule(&h, b"draft-profile-member")],
    )
    .unwrap();
    let decoded = fa_intents::PostBatch::decode(&batch.canonical_bytes().unwrap()).unwrap();

    // Neither the referenced rule nor event exists. The profile must be
    // refused before observing them, even under unrestricted Human authority.
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    draft_only_refusal(h.post_batch(decoded.clone()).unwrap_err());
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    draft_only_refusal(h.planned_batch(decoded.clone(), &capability).unwrap_err());
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);

    // Format-valid bytes confer no authority. First prove unauthenticated
    // transcripts fail; then authenticate a test-only hostile profile to
    // exercise the independent native admission guard during plan confirm.
    let entries = decoded
        .members()
        .iter()
        .map(|member| {
            member
                .proposal()
                .clone()
                .seal(member.approvals().to_vec(), None)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let periods = vec![h.march.clone()];
    let mut certificate = fa_intents::BatchPlanCertificate {
        book_id: decoded.book_id(),
        branch_id: decoded.branch_id(),
        principal: decoded.principal(),
        capability_commitment: capability.commitment().unwrap(),
        intent_digest: decoded.digest().unwrap(),
        prepared_digest: fa_intents::BatchPlan::prepared_digest(&entries, &periods).unwrap(),
        effects_digest: [0; 32],
        snapshot_seq: head,
        security_policy_epoch: 0,
        expires_at: None,
        authentication: [0; 32],
    };
    let unauthenticated = fa_intents::BatchPlan::new(
        decoded.clone(),
        entries.clone(),
        periods.clone(),
        certificate.clone(),
    )
    .unwrap();
    let refusal = h
        .publish_batch_plan(unauthenticated, &capability)
        .unwrap_err();
    assert_eq!(refusal.code, refusal::code::PLAN_INVALIDATED, "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);

    // Harness-only access to the book's authentication key: no public caller
    // can cause native planning to issue a certificate for this profile.
    let authentication_key =
        fgdb_crypto::derive_key("fa:batch-plan-authentication-key:v1", &h.book.seal_key.0);
    certificate.authentication = fgdb_crypto::keyed_hash(
        &authentication_key,
        &certificate.authentication_bytes().unwrap(),
    )
    .0;
    let portable = fa_intents::BatchPlan::new(decoded, entries, periods, certificate).unwrap();
    let portable = fa_intents::BatchPlan::decode(&portable.canonical_bytes().unwrap()).unwrap();
    draft_only_refusal(h.publish_batch_plan(portable, &capability).unwrap_err());
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
}

#[test]
fn automatic_rule_group_refuses_unrecorded_sources_without_appending() {
    let mut h = harness();
    let capability = Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap();
    h.open_draft(capability.clone(), "unrecorded-automatic-sources")
        .unwrap();
    let batch = fa_intents::PostBatch::automatic_rules(
        VId(92),
        b"automatic-draft-attempt".to_vec(),
        vec![synthetic_rule(&h, b"automatic-draft-member")],
    )
    .unwrap();
    let request = h.draft_request(capability);
    let ctx = h.ctx();
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let refusal = h
        .runtime
        .block_on(fa_journal::plan_batch_into_draft(
            &mut h.db,
            &ctx,
            &h.book,
            "unrecorded-automatic-sources",
            batch,
            request,
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(
        (refusal.code, refusal.exit),
        (refusal::code::CANON_RULE, refusal::exit::REFUSAL),
        "{refusal}"
    );
    assert!(refusal.to_string().contains("batch member 0"), "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    assert!(h.draft("unrecorded-automatic-sources").intents.is_empty());
}
