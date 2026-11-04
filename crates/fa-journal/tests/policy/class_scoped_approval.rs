//! An approval's admitted class follows its actual proposal through native
//! consumption, including signed records retained by an earlier writer.

use super::*;
use fa_journal::refusal::code;
use fa_policy::principal_key::{SCHEME_ED25519, approval_message, key_id};
use fa_policy::{Approval, PrincipalSignature, SignatureVerifier};

fn scoped_approver(holder: VId, class: EntryClass, salt: u8) -> Capability {
    Capability::new(holder, Profile::Human, &[Op::Approve], PREPARER)
        .unwrap()
        .for_classes(&[class])
        .unwrap()
        .holder_bound(possession_digest(&[salt; 32]))
}

fn issue_approver(h: &mut Harness, capability: &Capability, key: &[u8]) {
    h.issue(
        &human(PREPARER, &["issue_capability", "approve"]),
        capability,
        key,
    )
    .unwrap();
}

fn approve_payload(
    h: &mut Harness,
    capability: Capability,
    proposal: &EntryPayload,
) -> Result<Approved, Refusal> {
    let ctx = h.ctx();
    h.runtime
        .block_on(fa_journal::policy::record_approval_for(
            &mut h.db, &ctx, &h.book, capability, proposal, 0,
        ))
        .unwrap()
}

fn assert_classes(refusal: &Refusal) {
    assert_eq!(
        (refusal.code, refusal.exit),
        (code::CAPABILITY, exit::SAFETY)
    );
    assert!(refusal.message.contains("classes"), "{refusal}");
}

#[test]
fn issued_scoped_approval_requires_the_matching_payload_and_posts_with_it() {
    let mut h = harness();
    let capability = scoped_approver(ALICE, EntryClass::ORIGINAL, 171);
    issue_approver(&mut h, &capability, b"approve-original-issued");
    let proposal = h.proposal(PREPARER, 500, b"approved-original", EntryClass::ORIGINAL);
    let wrong = h.proposal(PREPARER, 500, b"outside-class", EntryClass::ADJUSTING);
    let before = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();

    let refused = approve_payload(&mut h, capability.clone(), &wrong).unwrap_err();
    assert_classes(&refused);
    // Even a digest of the matching class supplies no evidence of that class.
    let refused = h
        .approve_with(capability.clone(), proposal.proposal_digest().unwrap())
        .unwrap_err();
    assert_classes(&refused);
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(h.db.vertices().unwrap(), rows);

    let approved = approve_payload(&mut h, capability.clone(), &proposal).unwrap();
    assert!(matches!(approved, Approved::Recorded { .. }));
    assert_eq!(
        approved.approval().approved_digest,
        proposal.proposal_digest().unwrap()
    );
    let approved_at = h.db.frontier().unwrap();
    let retry = approve_payload(&mut h, capability, &proposal).unwrap();
    assert!(matches!(retry, Approved::AlreadyRecorded { .. }));
    assert_eq!(retry.approval(), approved.approval());
    assert_eq!(h.db.frontier().unwrap(), approved_at);
    h.post(
        proposal,
        human(PREPARER, &["post"]),
        vec![approved.approval()],
    )
    .expect("the matching scoped approval is consumed by the native posting path");
}

#[test]
fn unissued_scoped_approval_refuses_but_legacy_embedded_approval_remains_usable() {
    let mut h = harness();
    let proposal = h.proposal(PREPARER, 500, b"embedded-approval", EntryClass::ORIGINAL);
    // No possession caveat: this is the otherwise-valid embedded authority
    // path whose class body would disappear after retaining only a digest.
    let scoped = human(ALICE, &["approve"])
        .for_classes(&[EntryClass::ORIGINAL])
        .unwrap();
    assert!(
        read_issued(&h.db, &h.book, &scoped.commitment().unwrap())
            .unwrap()
            .is_none()
    );
    let before = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    assert_classes(&approve_payload(&mut h, scoped, &proposal).unwrap_err());
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(h.db.vertices().unwrap(), rows);

    let embedded = human(ALICE, &["approve"]);
    assert!(
        read_issued(&h.db, &h.book, &embedded.commitment().unwrap())
            .unwrap()
            .is_none()
    );
    // An existing unissued, unscoped record remains the exact retry through
    // the new payload API, and the normal consumer still honors it.
    let legacy = h
        .approve_with(embedded.clone(), proposal.proposal_digest().unwrap())
        .unwrap();
    let retry = approve_payload(&mut h, embedded, &proposal).unwrap();
    assert!(matches!(retry, Approved::AlreadyRecorded { .. }));
    assert_eq!(retry.approval(), legacy.approval());
    h.post(
        proposal,
        human(PREPARER, &["post"]),
        vec![legacy.approval()],
    )
    .expect("historical embedded approval compatibility");
}

#[test]
fn payload_bound_approval_cannot_bypass_the_requires_dry_run_caveat() {
    let mut h = harness();
    let capability = scoped_approver(ALICE, EntryClass::ORIGINAL, 172).with_requires_dry_run();
    issue_approver(&mut h, &capability, b"rehearsal-approver-issued");
    let proposal = h.proposal(PREPARER, 500, b"rehearsal-approval", EntryClass::ORIGINAL);
    let before = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let refusal = approve_payload(&mut h, capability, &proposal).unwrap_err();
    assert_eq!(
        (refusal.code, refusal.exit),
        (code::CAPABILITY, exit::SAFETY)
    );
    assert!(refusal.message.contains("requires_dry_run"), "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

// The laws-layer test verifier binds both message and key, avoiding a new
// cryptographic dependency. These fixtures model already-retained signed
// approval records; the native consumer must still recheck their class.
#[derive(Debug)]
struct FixtureVerifier;

fn fixture_signature(key: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let mut signature = [0; 64];
    signature[..32].copy_from_slice(&fa_model::domain_digest(
        b"class-approval-signature-a",
        &[key, message],
    ));
    signature[32..].copy_from_slice(&fa_model::domain_digest(
        b"class-approval-signature-b",
        &[key, message],
    ));
    signature
}

impl SignatureVerifier for FixtureVerifier {
    fn verify_ed25519(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        *signature == fixture_signature(public_key, message)
    }
}

fn import_signed_approval(
    h: &mut Harness,
    capability: &Capability,
    proposal: &EntryPayload,
) -> ApprovalRef {
    let digest = proposal.proposal_digest().unwrap();
    let epoch = security_policy_epoch(&h.db).unwrap();
    let approval = Approval::by(capability, Op::Approve, h.book.book_id, digest, epoch, 0)
        .unwrap()
        .unwrap();
    let approval_digest = approval.digest().unwrap();
    let public_key = [173; 32];
    let signature = PrincipalSignature {
        scheme: SCHEME_ED25519,
        generation: 1,
        key_id: key_id(&public_key),
        bytes: fixture_signature(&public_key, &approval_message(&approval_digest)),
    };
    signature
        .check(&approval_digest, 1, &public_key, &FixtureVerifier)
        .unwrap();
    let bytes = approval.record_bytes(Some(&signature)).unwrap();
    assert_eq!(
        Approval::decode_record(&bytes).unwrap(),
        (approval, Some(signature))
    );
    let vid = approval_vid(h.book.book_id, capability.holder(), &digest, epoch);
    let mut props = vec![
        (property::FA_PAYLOAD, CanonicalScalar::bytes(bytes).unwrap()),
        (
            property::FA_DIGEST,
            CanonicalScalar::bytes(approval_digest.to_vec()).unwrap(),
        ),
    ];
    props.sort_by_key(|(key, _)| key.0);
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(vid, vec![label::APPROVAL], props);
    let ctx = h.ctx();
    h.runtime
        .block_on(h.db.write(&ctx.commit(), batch))
        .unwrap();
    ApprovalRef {
        approval_vid: vid,
        approved_digest: digest,
    }
}

#[test]
fn legacy_signed_approvals_cannot_cross_classes_at_posting_or_control_consumption() {
    for target in [EntryClass::ORIGINAL, EntryClass::PERIOD_CONTROL] {
        let mut h = harness();
        let wrong_cap = scoped_approver(ALICE, EntryClass::ADJUSTING, 174);
        let matching_cap = scoped_approver(BOB, target, 175);
        issue_approver(&mut h, &wrong_cap, b"legacy-wrong-class-issued");
        issue_approver(&mut h, &matching_cap, b"legacy-matching-class-issued");
        let key = b"legacy-signed-target";
        let proposal = if target == EntryClass::ORIGINAL {
            h.proposal(PREPARER, 500, key, target)
        } else {
            h.period_proposal(PeriodState::Open, PeriodState::SoftClosed, key)
        };
        // Reproduce the prior writer's signed envelopes without using the
        // fixed creation path: otherwise its refusal would mask a consumer bug.
        let wrong = import_signed_approval(&mut h, &wrong_cap, &proposal);
        let matching = import_signed_approval(&mut h, &matching_cap, &proposal);
        let before = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let refusal = if target == EntryClass::ORIGINAL {
            h.post(proposal.clone(), human(PREPARER, &["post"]), vec![wrong])
                .unwrap_err()
        } else {
            h.transition_with(PeriodTransition::SoftClose, key, &period_cap(), &[wrong])
                .unwrap_err()
        };
        assert_classes(&refusal);
        assert_eq!(h.db.frontier().unwrap(), before);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert_eq!(h.march_state(), PeriodState::Open);

        // The signed format remains consumable under its retained matching
        // authority; the refused attempt consumed neither state nor key.
        if target == EntryClass::ORIGINAL {
            h.post(proposal, human(PREPARER, &["post"]), vec![matching])
                .unwrap();
        } else {
            h.transition_with(PeriodTransition::SoftClose, key, &period_cap(), &[matching])
                .unwrap();
            assert_eq!(h.march_state(), PeriodState::SoftClosed);
        }
        assert_eq!(h.db.frontier().unwrap().0, before.0 + 1);
    }
}
