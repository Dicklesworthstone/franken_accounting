//! An approval's admitted class follows its actual proposal through native
//! consumption, including signed records retained by an earlier writer.

use super::*;
use fa_journal::principal_key::{PrincipalKeyRequest, read_principal_keys, register_principal_key};
use fa_journal::refusal::code;
use fa_policy::principal_key::{SCHEME_ED25519, approval_message, key_id};
use fa_policy::{Approval, PrincipalKey, PrincipalSignature, SignatureVerifier};

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

/// Register through the native key protocol; the fixture verifier checks
/// possession and rotation endorsement as well as approval messages.
fn register_fixture_key(h: &mut Harness, principal: VId, public_key: [u8; 32]) -> u32 {
    let chain = read_principal_keys(&h.db, &h.book, principal).unwrap();
    let generation = u32::try_from(chain.len()).unwrap();
    let mut key = PrincipalKey {
        book_id: h.book.book_id,
        principal,
        generation,
        public_key,
        possession: [0; 64],
        endorsement: None,
    };
    let message = key.message();
    key.possession = fixture_signature(&public_key, &message);
    key.endorsement = chain
        .last()
        .map(|previous| fixture_signature(&previous.key.public_key, &message));
    let ctx = h.ctx();
    let description = h.period_description();
    let registered = h
        .runtime
        .block_on(register_principal_key(
            &mut h.db,
            &ctx,
            &h.book,
            PrincipalKeyRequest {
                capability: human(principal, &["approve"]),
                key,
                effective_date: DateDay::from_ymd(2026, 3, 1).unwrap(),
                idempotency_key: format!("key-{}-{generation}", principal.0).into_bytes(),
                description,
                verifier: &FixtureVerifier,
            },
        ))
        .unwrap()
        .unwrap();
    assert_eq!(registered.generation, generation);
    generation
}

fn signature_for(
    h: &Harness,
    capability: &Capability,
    proposal: &EntryPayload,
) -> PrincipalSignature {
    let chain = read_principal_keys(&h.db, &h.book, capability.holder()).unwrap();
    let current = &chain.last().expect("registered fixture key").key;
    let approval = Approval::by(
        capability,
        Op::Approve,
        h.book.book_id,
        proposal.proposal_digest().unwrap(),
        security_policy_epoch(&h.db).unwrap(),
        0,
    )
    .unwrap()
    .unwrap();
    PrincipalSignature {
        scheme: SCHEME_ED25519,
        generation: current.generation,
        key_id: current.key_id(),
        bytes: fixture_signature(
            &current.public_key,
            &approval_message(&approval.digest().unwrap()),
        ),
    }
}

fn record_fixture_signature(
    h: &mut Harness,
    capability: Capability,
    proposal: &EntryPayload,
    signature: PrincipalSignature,
) -> Result<Approved, Refusal> {
    let ctx = h.ctx();
    h.runtime
        .block_on(fa_journal::policy::record_signed_approval_for(
            &mut h.db,
            &ctx,
            &h.book,
            capability,
            proposal,
            0,
            Some(fa_journal::policy::SignedBy {
                signature,
                verifier: &FixtureVerifier,
            }),
        ))
        .unwrap()
}

fn signed_approval(h: &mut Harness, principal: VId, proposal: &EntryPayload) -> ApprovalRef {
    let capability = human(principal, &["approve"]);
    let signature = signature_for(h, &capability, proposal);
    record_fixture_signature(h, capability, proposal, signature)
        .unwrap()
        .approval()
}

fn import_signed_approval(
    h: &mut Harness,
    capability: &Capability,
    proposal: &EntryPayload,
) -> ApprovalRef {
    let public_key = [173; 32];
    let generation = register_fixture_key(h, capability.holder(), public_key);
    let digest = proposal.proposal_digest().unwrap();
    let epoch = security_policy_epoch(&h.db).unwrap();
    let approval = Approval::by(capability, Op::Approve, h.book.book_id, digest, epoch, 0)
        .unwrap()
        .unwrap();
    let approval_digest = approval.digest().unwrap();
    let signature = PrincipalSignature {
        scheme: SCHEME_ED25519,
        generation,
        key_id: key_id(&public_key),
        bytes: fixture_signature(&public_key, &approval_message(&approval_digest)),
    };
    signature
        .check(&approval_digest, generation, &public_key, &FixtureVerifier)
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

#[test]
fn signed_dual_control_counts_keys_instead_of_aliases_or_generations() {
    for rotate_alias in [false, true] {
        let mut h = harness();
        let shared = [181; 32];
        register_fixture_key(&mut h, ALICE, shared);
        if rotate_alias {
            register_fixture_key(&mut h, BOB, [182; 32]);
        }
        let bob_generation = register_fixture_key(&mut h, BOB, shared);
        assert_eq!(bob_generation, u32::from(rotate_alias));
        register_fixture_key(&mut h, CAROL, [183; 32]);
        let proposal = h.activation(PREPARER, b"signed-dual-control");
        let alice = signed_approval(&mut h, ALICE, &proposal);
        let bob = signed_approval(&mut h, BOB, &proposal);
        let carol = signed_approval(&mut h, CAROL, &proposal);
        let before = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();

        let refused = h
            .activate(proposal.clone(), controller(), vec![alice, bob])
            .unwrap_err();
        assert_eq!((refused.code, refused.exit), ("FA-REF-008", exit::SAFETY));
        assert_eq!(refused.cite, "sod_policy.toml#policy-activate");
        assert!(refused.message.contains("same signing key"), "{refused}");
        assert!(refused.fix.contains("independent principal"), "{refused}");
        assert_eq!(h.db.frontier().unwrap(), before);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert_eq!(security_policy_epoch(&h.db).unwrap(), 0);

        // The refused alias consumed neither the proposal nor its key.
        // Two independently registered keys satisfy the exact same policy.
        let done = h
            .activate(proposal, controller(), vec![alice, carol])
            .unwrap();
        assert_eq!((done.from_epoch, done.to_epoch), (0, 1));
        assert_eq!(h.db.frontier().unwrap().0, before.0 + 1);
    }
}

#[test]
fn a_preparer_key_cannot_approve_under_an_alias_even_after_rotation() {
    let mut h = harness();
    h.close_march();
    let shared = [184; 32];
    register_fixture_key(&mut h, PREPARER, shared);
    register_fixture_key(&mut h, ALICE, shared);
    register_fixture_key(&mut h, BOB, [185; 32]);
    let proposal = h.proposal(
        PREPARER,
        500,
        b"signed-self-approval",
        EntryClass::ADJUSTING,
    );
    let alias = signed_approval(&mut h, ALICE, &proposal);
    let independent = signed_approval(&mut h, BOB, &proposal);
    // Key rotation cannot undo evidence that the preparer held this key.
    register_fixture_key(&mut h, PREPARER, [186; 32]);
    let before = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let capability = human(PREPARER, &["post", "post_closed"]);
    let refused = h
        .post(proposal.clone(), capability.clone(), vec![alias])
        .unwrap_err();
    assert_eq!((refused.code, refused.exit), ("FA-REF-008", exit::SAFETY));
    assert_eq!(refused.cite, "sod_policy.toml#adjusting-closed");
    assert!(refused.message.contains("same signing key"), "{refused}");
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(h.db.vertices().unwrap(), rows);
    assert!(matches!(
        h.post(proposal, capability, vec![independent]).unwrap(),
        Posted::Committed { .. }
    ));
}

#[test]
fn approval_consumption_uses_the_key_at_recording_and_preserves_legacy_unsigned() {
    let mut h = harness();
    let proposal = h.proposal(PREPARER, 500, b"historical-signers", EntryClass::ORIGINAL);
    // Legacy capability-only approval predates its principal's first key.
    let legacy = h
        .approve(ALICE, proposal.proposal_digest().unwrap())
        .unwrap()
        .approval();
    register_fixture_key(&mut h, ALICE, [187; 32]);
    register_fixture_key(&mut h, BOB, [188; 32]);
    let signed = signed_approval(&mut h, BOB, &proposal);
    register_fixture_key(&mut h, BOB, [189; 32]);
    let before = h.db.frontier().unwrap();
    // Neither a later first registration nor rotation rewrites authority
    // already admitted at the approval's own recorded coordinate.
    h.post(proposal, human(PREPARER, &["post"]), vec![legacy, signed])
        .unwrap();
    assert_eq!(h.db.frontier().unwrap().0, before.0 + 1);
}

#[test]
fn a_changed_approval_signature_is_refused_before_recording() {
    let mut h = harness();
    register_fixture_key(&mut h, ALICE, [190; 32]);
    let proposal = h.proposal(PREPARER, 500, b"tampered-signature", EntryClass::ORIGINAL);
    let capability = human(ALICE, &["approve"]);
    let good = signature_for(&h, &capability, &proposal);
    let mut changed = good;
    changed.bytes[0] ^= 1;
    let before = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let refused =
        record_fixture_signature(&mut h, capability.clone(), &proposal, changed).unwrap_err();
    assert_eq!(
        (refused.code, refused.exit),
        (code::APPROVAL_SIGNATURE, exit::SAFETY)
    );
    assert!(refused.message.contains("signature"), "{refused}");
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(h.db.vertices().unwrap(), rows);
    let approved = record_fixture_signature(&mut h, capability, &proposal, good)
        .unwrap()
        .approval();
    h.post(proposal, human(PREPARER, &["post"]), vec![approved])
        .unwrap();
}

#[test]
fn retained_approval_signature_metadata_must_match_its_recorded_key() {
    for field in ["scheme", "generation", "key", "unsigned"] {
        let mut h = harness();
        register_fixture_key(&mut h, ALICE, [191; 32]);
        let proposal = h.proposal(PREPARER, 500, field.as_bytes(), EntryClass::ORIGINAL);
        let approval = signed_approval(&mut h, ALICE, &proposal);
        let row = h.db.vertex(approval.approval_vid).unwrap().unwrap();
        let Some(CanonicalScalar::Bytes(bytes)) = row
            .props
            .iter()
            .find(|(key, _)| *key == property::FA_PAYLOAD)
            .map(|(_, value)| value)
        else {
            panic!("fixture approval payload");
        };
        let (body, signature) = Approval::decode_record(bytes.as_slice()).unwrap();
        let mut changed = signature.unwrap();
        // A later real key gives the planted generation/key alias a valid
        // current registration; it was not valid at this approval's birth.
        register_fixture_key(&mut h, ALICE, [192; 32]);
        match field {
            "scheme" => changed.scheme = 99,
            "generation" => {
                changed.generation = 1;
                changed.key_id = key_id(&[192; 32]);
                changed.bytes =
                    fixture_signature(&[192; 32], &approval_message(&body.digest().unwrap()));
            }
            "key" => changed.key_id = key_id(&[193; 32]),
            "unsigned" => {}
            _ => unreachable!(),
        }
        let rewritten = body
            .record_bytes((field != "unsigned").then_some(&changed))
            .unwrap();
        let mut corruption = WriteBatch::new(relation::IN_BOOK);
        corruption.set_vertex_property(
            approval.approval_vid,
            property::FA_PAYLOAD,
            CanonicalScalar::bytes(rewritten).unwrap(),
        );
        let ctx = h.ctx();
        h.runtime
            .block_on(h.db.write(&ctx.commit(), corruption))
            .unwrap();
        let before = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let refused = h
            .post(proposal, human(PREPARER, &["post"]), vec![approval])
            .unwrap_err();
        assert_eq!(
            (refused.code, refused.exit),
            (code::APPROVAL_SIGNATURE, exit::SAFETY),
            "{field}: {refused}"
        );
        assert_eq!(h.db.frontier().unwrap(), before, "{field}");
        assert_eq!(h.db.vertices().unwrap(), rows, "{field}");
    }
}
