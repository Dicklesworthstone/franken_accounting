//! TimeEvidence must not consume a scoped key already owned by another
//! accounting effect, even when that effect has a target-derived identity.

use super::*;

const TICK_NS: u64 = 1_773_532_800_000_000_000;

fn request(h: &Harness, key: &[u8]) -> TickRequest {
    TickRequest {
        observed_utc_ns: TICK_NS,
        source: fa_journal::sweep::SOURCE_DAEMON_CLOCK,
        monotonic_ok: true,
        principal_ref: PRINCIPAL,
        capability: Capability::embedded(PRINCIPAL, &["witness"]).unwrap(),
        idempotency_key: key.to_vec(),
        description: h.statement("time outcome", 151),
    }
}

fn tick(h: &mut Harness, request: TickRequest) -> Result<Ticked, Refusal> {
    let ctx = h.ctx();
    h.runtime
        .block_on(record_tick(&mut h.db, &ctx, &h.book, request))
        .expect("tick kernel")
}

fn key_vid(h: &Harness, key: &[u8]) -> VId {
    fa_model::intent_outcome_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), key)
}

#[test]
fn ticks_refuse_keys_owned_by_target_derived_postings_and_outer_batches() {
    let mut h = harness();
    let source = h.proposal(
        h.rent_legs(100),
        b"tick-reverse-source",
        EntryClass::ORIGINAL,
    );
    let original = h.post(h.request(source, &["post"])).unwrap().entry_ref();
    let reversal = h.reversal_of_entry(original, b"reversal-before-tick");
    h.post(h.request(reversal, &["post"])).unwrap();
    let pending = h.pending(h.rent_legs(200), b"tick-resolution-source");
    let held = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
    let resolution = h.resolution_posts(
        held,
        h.rent_legs(150),
        vec![0, 1],
        b"resolution-before-tick",
    );
    h.post(h.request(resolution, &["post"])).unwrap();
    let member = h.proposal(h.rent_legs(300), b"tick-batch-member", EntryClass::ORIGINAL);
    h.post_batch(h.batch(b"batch-before-tick", vec![member]))
        .unwrap();

    let before = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    for key in [
        b"reversal-before-tick".as_slice(),
        b"resolution-before-tick".as_slice(),
        b"batch-before-tick".as_slice(),
    ] {
        let req = request(&h, key);
        let refusal = tick(&mut h, req).unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
        assert_eq!(h.db.frontier().unwrap(), before);
        assert_eq!(h.db.vertices().unwrap(), vertices);
        assert!(
            h.db.vertex(entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), key))
                .unwrap()
                .is_none(),
            "the refused tick must not acquire another Entry identity"
        );
    }
    assert!(fa_journal::latest_tick(&h.db).unwrap().is_none());
}

#[test]
fn a_tick_reserves_its_key_atomically_and_only_exact_retries_return_it() {
    let mut h = harness();
    let req = request(&h, b"tick-owned-key");
    let first = tick(&mut h, req.clone()).unwrap();
    let before = h.db.frontier().unwrap();
    let entry = h.db.vertex(first.entry_ref.vid).unwrap().unwrap();
    let claim =
        h.db.vertex(key_vid(&h, b"tick-owned-key"))
            .unwrap()
            .unwrap();
    assert_eq!(claim.created_at, entry.created_at);
    assert_eq!(claim.created_at, first.recorded_at);
    assert_eq!(
        fa_journal::rows::prop(&claim, property::TARGET_REF),
        Some(&CanonicalScalar::bytes(first.entry_ref.vid.0.to_le_bytes().to_vec()).unwrap())
    );
    let retry = tick(&mut h, req.clone()).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entry_ref, first.entry_ref);
    assert_eq!(retry.recorded_at, first.recorded_at);
    assert_eq!(h.db.frontier().unwrap(), before);

    let mut changed_time = req.clone();
    changed_time.observed_utc_ns += 1;
    let mut changed_description = req.clone();
    changed_description.description = h.statement("a different observation", 152);
    let mut changed_corroboration = req;
    changed_corroboration.monotonic_ok = false;
    for changed in [changed_time, changed_description, changed_corroboration] {
        let refusal = tick(&mut h, changed).unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
        assert_eq!(h.db.frontier().unwrap(), before);
    }

    let original = h.proposal(h.rent_legs(100), b"tick-owned-key", EntryClass::ORIGINAL);
    assert_eq!(
        h.post(h.request(original, &["post"])).unwrap_err().code,
        "FA-REF-032"
    );
    let member = h.proposal(
        h.rent_legs(100),
        b"tick-blocked-member",
        EntryClass::ORIGINAL,
    );
    assert_eq!(
        h.post_batch(h.batch(b"tick-owned-key", vec![member]))
            .unwrap_err()
            .code,
        "FA-REF-032"
    );
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn a_tick_winner_invalidates_an_already_prepared_target_derived_posting() {
    let mut h = harness();
    let source = h.proposal(h.rent_legs(100), b"tick-race-source", EntryClass::ORIGINAL);
    let original = h.post(h.request(source, &["post"])).unwrap().entry_ref();
    let reversal = h.reversal_of_entry(original, b"tick-race-key");
    let req = h.request(reversal, &["post"]);
    let ctx = h.ctx();
    let PostPreparation::Ready(prepared) = prepare_post(&mut h.db, &ctx, &h.book, req)
        .unwrap()
        .unwrap()
    else {
        panic!("a fresh reversal must prepare");
    };
    let tick_request = request(&h, b"tick-race-key");
    let first = tick(&mut h, tick_request).unwrap();
    let before = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let refusal = h
        .runtime
        .block_on(prepared.commit(&mut h.db, &ctx))
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.exit, exit::CONFLICT);
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    assert!(h.db.vertex(reversal_vid(original.vid)).unwrap().is_none());
    assert_eq!(fa_journal::latest_tick(&h.db).unwrap(), Some(first.tick));
}

#[test]
fn tick_key_lookup_never_supplies_authority_and_keys_are_principal_scoped() {
    let mut h = harness();
    let req = request(&h, b"scoped-tick-key");
    let first = tick(&mut h, req.clone()).unwrap();
    let before = h.db.frontier().unwrap();
    let mut unauthorized = req.clone();
    unauthorized.capability = Capability::embedded(PRINCIPAL, &["read"]).unwrap();
    assert_eq!(tick(&mut h, unauthorized).unwrap_err().exit, exit::SAFETY);
    assert_eq!(h.db.frontier().unwrap(), before);

    let mut other = req;
    other.principal_ref = VId(99);
    other.capability = Capability::embedded(VId(99), &["witness"]).unwrap();
    other.observed_utc_ns += 1;
    let independent = tick(&mut h, other).unwrap();
    assert_ne!(first.entry_ref.vid, independent.entry_ref.vid);
    assert_eq!(independent.recorded_at.0, before.0 + 1);
}

#[test]
fn a_legacy_tick_retries_without_claim_backfill_but_new_ticks_need_verified_coverage() {
    let mut h = harness_legacy();
    let req = request(&h, b"legacy-time-key");
    let proposal = fa_journal::sweep::tick_proposal(&h.book, &req);
    let entry = proposal.seal(Vec::new(), None).unwrap();
    let vid = entry_vid(
        h.book.book_id,
        &PRINCIPAL.0.to_le_bytes(),
        &req.idempotency_key,
    );
    let mut batch = fgdb::WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(
        vid,
        vec![fa_model::symbols::label::ENTRY],
        fa_model::entry_mirrors(&entry).unwrap(),
    );
    let mut latest = req.observed_utc_ns.to_le_bytes().to_vec();
    latest.extend_from_slice(&vid.0.to_le_bytes());
    batch.set_vertex_property(
        book_root(),
        property::LATEST_TICK,
        CanonicalScalar::bytes(latest).unwrap(),
    );
    let ctx = h.ctx();
    let recorded_at = h
        .runtime
        .block_on(h.db.write(&ctx.commit(), batch))
        .unwrap();
    assert!(
        h.db.vertex(key_vid(&h, b"legacy-time-key"))
            .unwrap()
            .is_none()
    );
    let before = h.db.frontier().unwrap();
    let retry = tick(&mut h, req.clone()).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entry_ref, entry.entry_ref(vid));
    assert_eq!(retry.recorded_at, recorded_at);
    assert_eq!(h.db.frontier().unwrap(), before);

    let mut new_request = req;
    new_request.idempotency_key = b"legacy-new-time-key".to_vec();
    new_request.observed_utc_ns += 1;
    let refusal = tick(&mut h, new_request).unwrap_err();
    assert_eq!(refusal.exit, exit::CONFLICT);
    assert!(refusal.fix.contains("fa recover outcomes"));
    assert_eq!(h.db.frontier().unwrap(), before);
}
