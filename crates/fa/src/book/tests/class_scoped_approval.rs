//! Payload-bound approval wrappers preserve scope and real principal signatures.

use super::*;
use fa_journal::refusal::code;
use fa_policy::{Approval, Op, Profile, possession_digest};

fn retained_signed_approval(
    book: &Book,
    approved: &fa_journal::Approved,
    capability: &Capability,
    proposal: &EntryPayload,
    public_key: &[u8; 32],
) {
    let vid = approved.approval().approval_vid;
    let query = book.purposes().query();
    query.checkpoint().unwrap();
    let records = query.with_restriction(
        || with_store!(&book.store, core => fa_journal::policy::approval_records(&core.db, &[vid])),
    );
    let records = records.unwrap();
    let (approval, signature) = Approval::decode_record(records.get(&vid).unwrap()).unwrap();
    assert_eq!(approval.principal, capability.holder());
    assert_eq!(
        approval.capability_commitment,
        capability.commitment().unwrap()
    );
    assert_eq!(
        approval.approved_proposal_digest,
        proposal.proposal_digest().unwrap()
    );
    let signature = signature.expect("the façade retained its real Ed25519 signature");
    signature
        .check(
            &approval.digest().unwrap(),
            0,
            public_key,
            &PRINCIPAL_SIGNATURES,
        )
        .unwrap();
}

#[test]
fn payload_approvals_use_real_registered_keys_and_preserve_class_scope() {
    let (mut book, _, day, source) = certified_fixture();
    let principal = VId(201);
    let key = fa_notary::SigningKey::from_seed(&[201; 32]);
    let public_key = key.public_key();
    let unrestricted = Capability::embedded(principal, &["approve"]).unwrap();
    book.register_principal_key(
        unrestricted,
        &key,
        None,
        day,
        b"scoped-approval-key",
        "Register the scoped approver's signing key",
    )
    .unwrap()
    .unwrap();
    let capability = Capability::new(principal, Profile::Human, &[Op::Approve], VId(1))
        .unwrap()
        .holder_bound(possession_digest(&[202; 32]))
        .for_classes(&[EntryClass::ORIGINAL])
        .unwrap();
    book.issue_capability(
        Capability::embedded(VId(1), &["issue_capability", "approve"]).unwrap(),
        capability.clone(),
        day,
        b"scoped-approver",
        "Approve Original entries only",
    )
    .unwrap()
    .unwrap();
    let mut proposal = book.read_entry(source).unwrap().unwrap().0.proposal;
    proposal.idempotency_key = b"explicit-signed-scoped-post".to_vec();
    let mut wrong_class = proposal.clone();
    wrong_class.class = EntryClass::ADJUSTING;
    wrong_class.idempotency_key = b"outside-signed-scope".to_vec();
    let unrelated_key = fa_notary::SigningKey::from_seed(&[203; 32]);
    let before = book.head().unwrap();

    // Wrong-class admission must win even when the supplied signing key is
    // also wrong; an opaque digest supplies no class at all.
    let refused = book
        .approve_entry_signed(capability.clone(), &wrong_class, &unrelated_key)
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, code::CAPABILITY);
    assert!(refused.message.contains("classes"), "{refused}");
    let refused = book
        .approve_signed(
            capability.clone(),
            proposal.proposal_digest().unwrap(),
            &key,
        )
        .unwrap()
        .unwrap_err();
    assert!(refused.message.contains("classes"), "{refused}");
    let refused = book
        .approve_entry_signed(
            Capability::embedded(principal, &["read"]).unwrap(),
            &proposal,
            &unrelated_key,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, code::CAPABILITY);
    assert!(refused.message.contains("approve"), "{refused}");
    let refused = book
        .approve_entry_signed(
            capability.clone().with_requires_dry_run(),
            &proposal,
            &unrelated_key,
        )
        .unwrap()
        .unwrap_err();
    assert!(refused.message.contains("requires_dry_run"), "{refused}");
    assert_eq!(book.head().unwrap(), before);

    let approved = book
        .approve_entry_signed(capability.clone(), &proposal, &key)
        .unwrap()
        .unwrap();
    retained_signed_approval(&book, &approved, &capability, &proposal, &public_key);
    let approved_at = book.head().unwrap();
    let retry = book
        .approve_entry_signed(capability.clone(), &proposal, &key)
        .unwrap()
        .unwrap();
    assert!(matches!(
        retry,
        fa_journal::Approved::AlreadyRecorded { .. }
    ));
    assert_eq!(retry.approval(), approved.approval());
    assert_eq!(book.head().unwrap(), approved_at);
    book.post(PostRequest {
        proposal: proposal.clone(),
        approvals: vec![approved.approval()],
        plan_certificate: None,
        capability: Capability::embedded(proposal.principal_ref, &["post"]).unwrap(),
    })
    .unwrap()
    .unwrap();

    // Configured signing takes the same route. A refusal must restore the
    // handle's key so the next admitted payload remains signed.
    book.sign_with_principal_key(key);
    let before = book.head().unwrap();
    let refused = book
        .approve_entry(capability.clone(), &wrong_class)
        .unwrap()
        .unwrap_err();
    assert!(refused.message.contains("classes"), "{refused}");
    assert_eq!(book.head().unwrap(), before);
    proposal.idempotency_key = b"configured-signed-scoped-post".to_vec();
    let approved = book
        .approve_entry(capability.clone(), &proposal)
        .unwrap()
        .unwrap();
    retained_signed_approval(&book, &approved, &capability, &proposal, &public_key);
    book.post(PostRequest {
        capability: Capability::embedded(proposal.principal_ref, &["post"]).unwrap(),
        proposal,
        approvals: vec![approved.approval()],
        plan_certificate: None,
    })
    .unwrap()
    .unwrap();
}
