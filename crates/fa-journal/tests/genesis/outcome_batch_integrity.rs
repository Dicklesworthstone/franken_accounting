//! Batch retry admission covers the entire original membership before
//! decoding its outcome, and a retained outcome must be its original atomic
//! publication rather than a later claim over already-recorded entries.

use super::*;

fn post_batch_as(
    h: &mut Harness,
    batch: PostBatch,
    capability: Capability,
) -> Result<Result<BatchPosted, Refusal>, KernelError> {
    let ctx = h.ctx();
    h.runtime.block_on(fa_journal::post_batch(
        &mut h.db, &ctx, &h.book, capability, batch,
    ))
}

#[test]
fn scoped_batch_retry_proves_complete_membership_before_decoding_a_poisoned_outcome() {
    let mut h = harness();
    let reachable = h.proposal(h.rent_legs(100), b"scope-first", EntryClass::ORIGINAL);
    let hidden = h.invoice(200, b"scope-hidden");
    let batch = h.batch(b"scope-batch", vec![reachable.clone(), hidden.clone()]);
    let posted = h.post_batch(batch.clone()).unwrap();

    // A genuinely complete scoped retry remains usable. The narrower token
    // below reaches the first member but neither account of the second.
    let complete = Capability::embedded(PRINCIPAL, &["post"])
        .unwrap()
        .for_accounts(&["1000", "1200", "4000", "6000"])
        .unwrap();
    let head = h.db.frontier().unwrap();
    let retry = post_batch_as(&mut h, batch, complete).unwrap().unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, posted.entries);
    assert_eq!(retry.recorded_at, posted.recorded_at);
    assert_eq!(h.db.frontier().unwrap(), head);

    let substitute = h.proposal(h.rent_legs(300), b"scope-substitute", EntryClass::ORIGINAL);
    h.post(h.request(substitute.clone(), &["post"])).unwrap();
    let narrowed = Capability::embedded(PRINCIPAL, &["post"])
        .unwrap()
        .for_accounts(&["1000", "6000"])
        .unwrap();

    // These bytes deliberately fail decoding. A retry must still return the
    // ordinary key conflict, not observe either inaccessible payload. Keep
    // all account mirrors and original IN_BATCH membership intact.
    let mut poison = fgdb::WriteBatch::new(relation::IN_BATCH);
    for vid in [posted.outcome, posted.entries[1].vid] {
        poison.set_vertex_property(
            vid,
            property::FA_PAYLOAD,
            Some(CanonicalScalar::bytes(vec![0; 11]).unwrap()),
        );
    }
    h.write_raw(poison);
    assert!(read_outcome(&h.db, &h.ctx().query(), posted.outcome).is_err());
    assert!(read_entry(&h.db, posted.entries[1].vid).is_err());

    let changed_hidden = h.proposal(
        h.rent_legs(200),
        &hidden.idempotency_key,
        EntryClass::ORIGINAL,
    );
    let fresh = h.proposal(h.rent_legs(400), b"scope-fresh", EntryClass::ORIGINAL);
    let fresh_vid = h.member_ref(&fresh).vid;
    let attempts = [
        ("omitted original member", vec![reachable.clone()]),
        (
            "substituted already-recorded member",
            vec![reachable.clone(), substitute],
        ),
        (
            "changed payload at the hidden member's key",
            vec![reachable.clone(), changed_hidden],
        ),
        ("fresh replacement member", vec![reachable, fresh]),
    ];
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    for (case, members) in attempts {
        let attempt = h.batch(b"scope-batch", members);
        let refusal = post_batch_as(&mut h, attempt, narrowed.clone())
            .expect("a refused scope never decodes the poisoned entry or outcome")
            .unwrap_err();
        assert_eq!(
            (refusal.code, refusal.exit),
            ("FA-REF-032", exit::CONFLICT),
            "{case}: {refusal}"
        );
        assert_eq!(h.db.frontier().unwrap(), head, "{case}");
        assert_eq!(h.db.vertices().unwrap(), vertices, "{case}");
        assert!(h.db.vertex(fresh_vid).unwrap().is_none(), "{case}");
    }
}

#[test]
fn ordinary_batch_retry_rejects_a_later_forged_root_and_a_rebound_original_body() {
    let mut h = harness();
    let standalone = h.proposal(h.rent_legs(100), b"forged-member", EntryClass::ORIGINAL);
    let member = h.post(h.request(standalone.clone(), &["post"])).unwrap();
    let forged = h.batch(b"forged-batch", vec![standalone]);
    let forged_vid = outcome_vid(&h.book, &forged);
    let forged_body = OutcomeBody {
        request_digest: request_digest(forged.idempotency_key(), &[member.entry_ref().vid]),
        entries: vec![member.entry_ref()],
    };

    // The request digest, EntryRef and adjacency all agree. Only native
    // publication provenance distinguishes this later raw claim from a batch
    // that actually created its members atomically.
    let mut planted = fgdb::WriteBatch::new(relation::IN_BATCH);
    planted.create_vertex(
        forged_vid,
        vec![fa_model::symbols::label::INTENT_OUTCOME],
        vec![(
            property::FA_PAYLOAD,
            CanonicalScalar::bytes(forged_body.canonical_bytes().unwrap()).unwrap(),
        )],
    );
    planted.add_edge(
        edge_id(relation::IN_BATCH, member.entry_ref().vid, forged_vid),
        member.entry_ref().vid,
        forged_vid,
        vec![],
    );
    h.write_raw(planted);
    let head = h.db.frontier().unwrap();
    assert!(head > member.recorded_at());
    assert_eq!(
        read_outcome(&h.db, &h.ctx().query(), forged_vid).unwrap(),
        Some((forged_body, head))
    );
    assert_eq!(
        h.db.in_neighbours(forged_vid, relation::IN_BATCH).unwrap(),
        vec![member.entry_ref().vid]
    );
    let vertices = h.db.vertices().unwrap();
    let refusal = h.post_batch(forged).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);

    let first = h.proposal(h.rent_legs(200), b"rebound-first", EntryClass::ORIGINAL);
    let second = h.proposal(h.rent_legs(300), b"rebound-second", EntryClass::ORIGINAL);
    let batch = h.batch(b"rebound-batch", vec![first.clone(), second.clone()]);
    let posted = h.post_batch(batch.clone()).unwrap();
    let retry = h.post_batch(batch).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, posted.entries);
    assert_eq!(retry.recorded_at, posted.recorded_at);
    assert_eq!(h.db.frontier().unwrap(), posted.recorded_at);

    // Rebinding the original root to the opposite order preserves complete
    // membership and member co-birth. Its current self-consistent body still
    // cannot replace the immutable outcome originally published at that key.
    let reordered = h.batch(b"rebound-batch", vec![second, first]);
    let rebound_body = OutcomeBody {
        request_digest: request_digest(
            reordered.idempotency_key(),
            &[posted.entries[1].vid, posted.entries[0].vid],
        ),
        entries: vec![posted.entries[1], posted.entries[0]],
    };
    let mut rebound = fgdb::WriteBatch::new(relation::IN_BATCH);
    rebound.set_vertex_property(
        posted.outcome,
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(rebound_body.canonical_bytes().unwrap()).unwrap()),
    );
    h.write_raw(rebound);
    assert_eq!(
        read_outcome(&h.db, &h.ctx().query(), posted.outcome)
            .unwrap()
            .unwrap()
            .0,
        rebound_body
    );
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let refusal = h.post_batch(reordered).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
}
