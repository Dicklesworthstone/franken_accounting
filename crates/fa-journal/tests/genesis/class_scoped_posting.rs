//! fa-3vg1: naming a class narrows posting and portable-plan authority
//! without turning legitimate same-class writes or exact retries into
//! whole-book refusals.

use super::*;

fn original_only() -> Capability {
    Capability::embedded(PRINCIPAL, &["post"])
        .unwrap()
        .for_classes(&[EntryClass::ORIGINAL])
        .unwrap()
}

#[test]
fn matching_posting_and_retry_succeed_while_another_class_changes_nothing() {
    let mut h = harness();
    let cap = original_only();
    let proposal = h.proposal(h.rent_legs(125), b"class-post", EntryClass::ORIGINAL);
    let request = PostRequest {
        proposal,
        capability: cap.clone(),
        approvals: Vec::new(),
        plan_certificate: None,
    };
    let posted = h.post(request.clone()).unwrap();
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let retry = h.post(request).unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);

    let other = PostRequest {
        proposal: h.proposal(h.rent_legs(75), b"class-adjusting", EntryClass::ADJUSTING),
        capability: cap,
        approvals: Vec::new(),
        plan_certificate: None,
    };
    let refusal = h.post(other.clone()).unwrap_err();
    assert!(refusal.message.contains("`classes`"), "{refusal}");
    assert!(refusal.message.contains("Adjusting"), "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    h.post(PostRequest {
        capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        ..other
    })
    .expect("the same Adjusting is admissible under unscoped authority");
}

#[test]
fn class_scoped_rehearsal_and_publication_preserve_the_required_plan_gate() {
    let mut h = harness();
    let cap = original_only().with_requires_dry_run();
    let request = PostRequest {
        proposal: h.proposal(h.rent_legs(250), b"class-plan", EntryClass::ORIGINAL),
        capability: cap.clone(),
        approvals: Vec::new(),
        plan_certificate: None,
    };
    let basis = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let refusal = h.post(request.clone()).unwrap_err();
    assert!(refusal.message.contains("requires_dry_run"), "{refusal}");
    let plan = h.post_plan(request.clone()).unwrap();
    assert_eq!(h.post_plan(request).unwrap(), plan);
    assert_eq!(h.db.frontier().unwrap(), basis);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    let posted = h.publish_plan(plan.clone(), &cap).unwrap();
    let retry = h.publish_plan(plan, &cap).unwrap();
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(retry.recorded_at(), posted.recorded_at());
    assert_eq!(h.db.frontier().unwrap(), posted.recorded_at());
}

#[test]
fn class_mismatch_refuses_both_portable_planning_entrypoints_before_publication() {
    let mut h = harness();
    let request = PostRequest {
        proposal: h.proposal(
            h.rent_legs(300),
            b"class-plan-denied",
            EntryClass::ADJUSTING,
        ),
        capability: original_only(),
        approvals: Vec::new(),
        plan_certificate: None,
    };
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let refusal = h.post_plan(request.clone()).unwrap_err();
    assert!(refusal.message.contains("`classes`"), "{refusal}");
    let ctx = h.ctx();
    let intent = fa_intents::PostIntent::new(request.proposal, request.approvals).unwrap();
    let refusal = h
        .runtime
        .block_on(plan_post_with_history(
            &mut h.db,
            &ctx,
            &h.book,
            request.capability,
            intent,
        ))
        .unwrap()
        .unwrap_err();
    assert!(refusal.message.contains("`classes`"), "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
}
