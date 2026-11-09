//! Payload-bound approval wrappers preserve scope and real principal signatures.

use super::*;
use fa_journal::refusal::code;
use fa_policy::{Approval, Op, Profile, possession_digest};

fn retained_signed_approval(
    book: &Book,
    approved: &fa_journal::Approved,
    capability: &Capability,
    proposal: &EntryPayload,
    generation: u32,
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
            generation,
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
    retained_signed_approval(&book, &approved, &capability, &proposal, 0, &public_key);
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
    retained_signed_approval(&book, &approved, &capability, &proposal, 0, &public_key);
    book.post(PostRequest {
        capability: Capability::embedded(proposal.principal_ref, &["post"]).unwrap(),
        proposal,
        approvals: vec![approved.approval()],
        plan_certificate: None,
    })
    .unwrap()
    .unwrap();
}

#[test]
fn scoped_entry_preflight_and_signed_approval_share_complete_payload_admission() {
    let (mut book, usd, day, source) = certified_fixture();
    let principal = VId(220);
    let key = fa_notary::SigningKey::from_seed(&[220; 32]);
    let unrelated_key = fa_notary::SigningKey::from_seed(&[221; 32]);
    book.register_principal_key(
        Capability::embedded(principal, &["approve"]).unwrap(),
        &key,
        None,
        day,
        b"departmental-signing-key",
        "Register the departmental approver's key",
    )
    .unwrap()
    .unwrap();
    let capability = Capability::new(principal, Profile::Human, &[Op::Approve], VId(1))
        .unwrap()
        .holder_bound(possession_digest(&[220; 32]))
        .for_classes(&[EntryClass::ORIGINAL])
        .unwrap()
        .for_accounts(&["1000", "6000"])
        .unwrap()
        .for_periods(&["FY2026-P03"])
        .unwrap()
        .effective_through(DateDay::from_ymd(2026, 3, 31).unwrap())
        .with_ceiling(usd, 150_000)
        .unwrap();
    book.issue_capability(
        Capability::embedded(VId(1), &["issue_capability", "approve"]).unwrap(),
        capability.clone(),
        day,
        b"departmental-approval-authority",
        "Approve bounded March rent and cash postings",
    )
    .unwrap()
    .unwrap();
    let mut proposal = book.read_entry(source).unwrap().unwrap().0.proposal;
    proposal.idempotency_key = b"departmental-signed-post".to_vec();
    let before = book.head().unwrap();
    book.admit_entry_approval(&capability, &proposal)
        .unwrap()
        .unwrap();
    assert_eq!(book.head().unwrap(), before);

    let mut excessive = proposal.clone();
    for leg in &mut excessive.legs {
        leg.amount.mantissa += 1;
    }
    excessive.unit_totals = EntryPayload::fold_unit_totals(&excessive.legs).unwrap();
    let preflight = book
        .admit_entry_approval(&capability, &excessive)
        .unwrap()
        .unwrap_err();
    let signed = book
        .approve_entry_signed(capability.clone(), &excessive, &unrelated_key)
        .unwrap()
        .unwrap_err();
    assert_eq!(preflight.code, fa_policy::denial::code::CEILING);
    assert_eq!(
        signed, preflight,
        "scope is decided before signing-key validation"
    );

    let mut outside = proposal.clone();
    outside.legs[0].account_ref = fa_model::account_vid(outside.book_id, "9999");
    let refused = book
        .approve_entry_signed(capability.clone(), &outside, &unrelated_key)
        .unwrap()
        .unwrap_err();
    assert!(refused.message.contains("accounts"), "{refused}");
    let mut foreign = proposal.clone();
    foreign.book_id = Id128([221; 16]);
    let preflight = book
        .admit_entry_approval(&capability, &foreign)
        .unwrap()
        .unwrap_err();
    let signed = book
        .approve_entry_signed(capability.clone(), &foreign, &unrelated_key)
        .unwrap()
        .unwrap_err();
    assert_eq!(preflight.code, code::COORDINATE);
    assert_eq!(signed.code, preflight.code);
    assert_eq!(book.head().unwrap(), before);

    let approved = book
        .approve_entry_signed(capability.clone(), &proposal, &key)
        .unwrap()
        .unwrap();
    retained_signed_approval(
        &book,
        &approved,
        &capability,
        &proposal,
        0,
        &key.public_key(),
    );
    assert!(matches!(
        book.post(PostRequest {
            capability: Capability::embedded(proposal.principal_ref, &["post"]).unwrap(),
            proposal,
            approvals: vec![approved.approval()],
            plan_certificate: None,
        })
        .unwrap()
        .unwrap(),
        Posted::Committed { .. }
    ));
}

#[test]
fn independently_valid_ed25519_signatures_do_not_make_a_shared_key_independent() {
    for rotate_alias in [false, true] {
        let (mut book, _, day, source) = certified_fixture();
        let alice = VId(211);
        let bob = VId(212);
        let carol = VId(213);
        let shared = fa_notary::SigningKey::from_seed(&[211; 32]);
        let previous = fa_notary::SigningKey::from_seed(&[212; 32]);
        let independent = fa_notary::SigningKey::from_seed(&[213; 32]);
        let bob_initial = if rotate_alias { &previous } else { &shared };
        for (principal, key) in [(alice, &shared), (bob, bob_initial), (carol, &independent)] {
            book.register_principal_key(
                Capability::embedded(principal, &["approve"]).unwrap(),
                key,
                None,
                day,
                format!("signer-key-{}", principal.0).as_bytes(),
                "Register the approval's signing key",
            )
            .unwrap()
            .unwrap();
        }
        if rotate_alias {
            let rotated = book
                .register_principal_key(
                    Capability::embedded(bob, &["approve"]).unwrap(),
                    &shared,
                    Some(&previous),
                    day,
                    b"rotate-alias-to-shared-key",
                    "Rotate the alias to the shared signing key",
                )
                .unwrap()
                .unwrap();
            assert_eq!(rotated.generation, 1);
        }
        let mut proposal = book.read_entry(source).unwrap().unwrap().0.proposal;
        proposal.idempotency_key = b"independent-ed25519-approvals".to_vec();
        let mut approvals = Vec::new();
        for (principal, key, generation) in [
            (alice, &shared, 0),
            (bob, &shared, u32::from(rotate_alias)),
            (carol, &independent, 0),
        ] {
            let capability = Capability::embedded(principal, &["approve"]).unwrap();
            let approved = book
                .approve_entry_signed(capability.clone(), &proposal, key)
                .unwrap()
                .unwrap();
            // Each signature verifies over its own principal's approval
            // body. The shared-key failure is not an invalid-signature test.
            retained_signed_approval(
                &book,
                &approved,
                &capability,
                &proposal,
                generation,
                &key.public_key(),
            );
            approvals.push(approved.approval());
        }
        let before = book.head().unwrap();
        let capability = Capability::embedded(proposal.principal_ref, &["post"]).unwrap();
        let refused = book
            .post(PostRequest {
                proposal: proposal.clone(),
                approvals: vec![approvals[0], approvals[1]],
                plan_certificate: None,
                capability: capability.clone(),
            })
            .unwrap()
            .unwrap_err();
        assert_eq!((refused.code, refused.exit), ("FA-REF-008", 7));
        assert!(refused.message.contains("same signing key"), "{refused}");
        assert_eq!(book.head().unwrap(), before);

        let posted = book
            .post(PostRequest {
                proposal,
                approvals: vec![approvals[0], approvals[2]],
                plan_certificate: None,
                capability,
            })
            .unwrap()
            .unwrap();
        assert!(matches!(posted, Posted::Committed { .. }));
        assert_eq!(book.head().unwrap().0, before.0 + 1);
    }
}
