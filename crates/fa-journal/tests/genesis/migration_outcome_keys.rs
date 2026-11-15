//! A lifecycle control and a monetary effect must never consume the same
//! principal-scoped request key, even when their Entry identities differ.

use super::*;
use fa_journal::refusal::code;
use fa_model::symbols::label;
use fgdb::WriteBatch;

fn opening_request(h: &Harness, run_key: &str, key: &[u8]) -> (RunBody, RunControlRequest) {
    let body = RunBody {
        book_id: h.book.book_id,
        run_key: run_key.into(),
        source_system: "legacy-limits".into(),
        mode: RunMode::OpeningOnly,
        trial_balance: h.evidence[0].document_oid,
        opening_date: DateDay::from_ymd(2026, 1, 1).unwrap(),
        lines: [("1000", 100), ("4000", -100)]
            .into_iter()
            .map(|(account, mantissa)| migration::TrialBalanceLine {
                account_code: account.into(),
                unit: h.usd,
                mantissa,
            })
            .collect(),
        periods: Vec::new(),
        detail_base: Vec::new(),
        sole_opening_source: false,
    };
    let proposal = migration::open_proposal(
        &h.book,
        PRINCIPAL,
        &body,
        h.evidence.clone(),
        key,
        h.statement("open a retained migration", 143),
    )
    .unwrap();
    (
        body,
        RunControlRequest {
            proposal,
            capability: Capability::embedded(PRINCIPAL, &["migrate"]).unwrap(),
            approvals: Vec::new(),
        },
    )
}

fn start(
    h: &mut Harness,
    body: &RunBody,
    request: RunControlRequest,
) -> Result<RunControlled, Refusal> {
    let ctx = h.ctx();
    h.runtime
        .block_on(migration::open_run(&mut h.db, &ctx, &h.book, body, request))
        .expect("migration Open kernel")
}

fn outcome(h: &Harness, key: &[u8]) -> VId {
    fa_model::intent_outcome_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), key)
}

fn assert_atomic_claim(h: &Harness, request: &RunControlRequest, done: &RunControlled) {
    let claim =
        h.db.vertex(outcome(h, &request.proposal.idempotency_key))
            .unwrap()
            .expect("each lifecycle success reserves the common key");
    let entry = h.db.vertex(done.control_entry).unwrap().unwrap();
    assert_eq!(claim.labels, [label::INTENT_OUTCOME]);
    assert_eq!(claim.created_at, done.recorded_at);
    assert_eq!(claim.created_at, entry.created_at);
    assert_eq!(
        fa_journal::rows::prop(&claim, property::TARGET_REF),
        Some(&CanonicalScalar::bytes(done.control_entry.0.to_le_bytes().to_vec()).unwrap())
    );
}

#[test]
fn lifecycle_claims_are_atomic_and_exact_retries_retain_the_original_population() {
    for kind in [migration::kind::FINALIZE, migration::kind::ABANDON] {
        let mut h = lock_opening(harness());
        let (body, request) = opening_request(&h, "complete-outcome", b"open-outcome");
        let opened = start(&mut h, &body, request.clone()).unwrap();
        assert_atomic_claim(&h, &request, &opened);
        // Chunks retain their intentional run-scoped namespace. Sharing a
        // control's raw key does not consume that control's principal key.
        let proposal = chunk(&h, opened.run, cash_legs(&h, 100), b"open-outcome");
        let imported = stage(&mut h, proposal).unwrap().entry_ref();
        let close = control(&mut h, opened.run, kind, b"finish-outcome");
        let closed = transition(&mut h, close.clone()).unwrap();
        assert_atomic_claim(&h, &close, &closed);
        assert_eq!(closed.chunks.len(), 1);
        assert_eq!(closed.chunks[0].vid, imported.vid);
        let before = h.db.frontier().unwrap();
        let vertices = h.db.vertices().unwrap();
        assert_eq!(
            start(&mut h, &body, request).unwrap(),
            RunControlled {
                already_recorded: true,
                ..opened
            }
        );
        assert_eq!(
            transition(&mut h, close.clone()).unwrap(),
            RunControlled {
                already_recorded: true,
                ..closed
            }
        );
        let mut changed = close;
        if changed.approvals.is_empty() {
            changed.approvals = read_entry(&h.db, imported.vid)
                .unwrap()
                .unwrap()
                .0
                .approvals;
        } else {
            changed.approvals.reverse();
        }
        assert_eq!(
            transition(&mut h, changed).unwrap_err().code,
            code::IDEMPOTENCY_CONFLICT
        );
        assert_eq!(h.db.frontier().unwrap(), before);
        assert_eq!(h.db.vertices().unwrap(), vertices);
    }
}

#[test]
fn occupied_reversal_resolution_and_batch_keys_cannot_open_or_transition_a_run() {
    let mut h = lock_opening(harness());
    let original = h.proposal(
        h.rent_legs(100),
        b"migration-key-target",
        EntryClass::ORIGINAL,
    );
    let target = h.post(h.request(original, &["post"])).unwrap().entry_ref();
    let reversal = h.reversal_of_entry(target, b"reversal-before-open");
    h.post(h.request(reversal, &["post"])).unwrap();
    let hold = h.pending(h.rent_legs(200), b"migration-key-hold");
    let held = h.post(h.request(hold, &["post"])).unwrap().entry_ref();
    let resolve = h.resolution_posts(
        held,
        h.rent_legs(150),
        vec![0, 1],
        b"resolution-before-finalize",
    );
    h.post(h.request(resolve, &["post"])).unwrap();
    let member = h.proposal(
        h.rent_legs(300),
        b"migration-batch-member",
        EntryClass::ORIGINAL,
    );
    h.post_batch(h.batch(b"batch-before-abandon", vec![member]))
        .unwrap();
    let run = open(
        &mut h,
        "occupied-controls",
        &[("1000", 100), ("4000", -100)],
    );
    let imported = chunk(&h, run, cash_legs(&h, 100), b"occupied-controls-chunk");
    stage(&mut h, imported).unwrap();
    let finalize = control(
        &mut h,
        run,
        migration::kind::FINALIZE,
        b"resolution-before-finalize",
    );
    let abandon = control(
        &mut h,
        run,
        migration::kind::ABANDON,
        b"batch-before-abandon",
    );
    let (body, opening) = opening_request(&h, "occupied-open", b"reversal-before-open");
    let before = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    assert_eq!(
        start(&mut h, &body, opening).unwrap_err().code,
        code::IDEMPOTENCY_CONFLICT
    );
    for request in [finalize, abandon] {
        assert_eq!(
            transition(&mut h, request).unwrap_err().code,
            code::IDEMPOTENCY_CONFLICT
        );
    }
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    assert!(
        migration::read_run(&h.db, body.vid(), None)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        migration::read_run(&h.db, run, None)
            .unwrap()
            .unwrap()
            .state,
        RunState::Open
    );
}

#[test]
fn migration_winners_block_later_postings_batches_and_prepared_target_derived_writes() {
    let mut h = harness();
    let original = h.proposal(
        h.rent_legs(100),
        b"migration-race-target",
        EntryClass::ORIGINAL,
    );
    let target = h.post(h.request(original, &["post"])).unwrap().entry_ref();
    let reversal = h.reversal_of_entry(target, b"migration-race-key");
    let request = h.request(reversal, &["post"]);
    let ctx = h.ctx();
    let PostPreparation::Ready(prepared) = prepare_post(&mut h.db, &ctx, &h.book, request)
        .unwrap()
        .unwrap()
    else {
        panic!("a fresh reversal must prepare");
    };
    let (body, request) = opening_request(&h, "migration-race", b"migration-race-key");
    let winner = start(&mut h, &body, request.clone()).unwrap();
    assert_atomic_claim(&h, &request, &winner);
    let before = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let refusal = h
        .runtime
        .block_on(prepared.commit(&mut h.db, &ctx))
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.exit, exit::CONFLICT);
    let posting = h.proposal(
        h.rent_legs(100),
        b"migration-race-key",
        EntryClass::ORIGINAL,
    );
    assert_eq!(
        h.post(h.request(posting, &["post"])).unwrap_err().code,
        code::IDEMPOTENCY_CONFLICT
    );
    let member = h.proposal(
        h.rent_legs(100),
        b"migration-late-member",
        EntryClass::ORIGINAL,
    );
    assert_eq!(
        h.post_batch(h.batch(b"migration-race-key", vec![member]))
            .unwrap_err()
            .code,
        code::IDEMPOTENCY_CONFLICT
    );
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
}

#[test]
fn deleted_claims_and_restored_control_or_claim_bytes_never_gain_the_legacy_exception() {
    for damage in [0, 1, 2] {
        let mut h = harness();
        let (body, request) = opening_request(&h, "damaged-outcome", b"damaged-control-key");
        let done = start(&mut h, &body, request.clone()).unwrap();
        let claim = outcome(&h, &request.proposal.idempotency_key);
        let mut change = WriteBatch::new(relation::IN_MIGRATION_RUN);
        if damage == 0 {
            change.delete_vertex(claim);
            h.write_raw(change);
        } else {
            let target = if damage == 1 {
                claim
            } else {
                done.control_entry
            };
            let original = fa_journal::rows::prop(
                &h.db.vertex(target).unwrap().unwrap(),
                property::FA_PAYLOAD,
            )
            .unwrap()
            .clone();
            change.set_vertex_property(
                target,
                property::FA_PAYLOAD,
                Some(CanonicalScalar::bytes(vec![0xff; 8]).unwrap()),
            );
            h.write_raw(change);
            let mut restore = WriteBatch::new(relation::IN_MIGRATION_RUN);
            restore.set_vertex_property(target, property::FA_PAYLOAD, Some(original));
            h.write_raw(restore);
        }
        let before = h.db.frontier().unwrap();
        let vertices = h.db.vertices().unwrap();
        assert_eq!(
            start(&mut h, &body, request).unwrap_err().code,
            code::IDEMPOTENCY_CONFLICT
        );
        assert_eq!(h.db.frontier().unwrap(), before);
        assert_eq!(h.db.vertices().unwrap(), vertices);
    }
}

#[test]
fn current_authority_is_required_before_observing_even_a_malformed_control_claim() {
    let mut h = harness();
    let (body, request) = opening_request(&h, "unread-outcome", b"unread-control-key");
    start(&mut h, &body, request.clone()).unwrap();
    let mut damage = WriteBatch::new(relation::IN_MIGRATION_RUN);
    damage.set_vertex_property(
        outcome(&h, &request.proposal.idempotency_key),
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(b"FA-ENTRY-OUTCOME\0".to_vec()).unwrap()),
    );
    h.write_raw(damage);
    let revoked = Capability::embedded(PRINCIPAL, &["migrate"]).unwrap();
    h.revoke(&revoked, 144);
    let before = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    for capability in [Capability::embedded(PRINCIPAL, &["read"]).unwrap(), revoked] {
        let mut unauthorized = request.clone();
        unauthorized.capability = capability;
        assert_eq!(
            start(&mut h, &body, unauthorized).unwrap_err().exit,
            exit::SAFETY
        );
    }
    let mut admitted = request;
    admitted.capability = Capability::embedded(PRINCIPAL, &["migrate", "read"]).unwrap();
    let ctx = h.ctx();
    assert!(
        h.runtime
            .block_on(migration::open_run(
                &mut h.db, &ctx, &h.book, &body, admitted
            ))
            .is_err()
    );
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(h.db.vertices().unwrap(), vertices);
}

/// Reproduce the old writer's native Open publication in a separate legacy
/// book. Copy only its original Entry/run bytes, never its modern key claim.
fn write_legacy_open(
    h: &mut Harness,
    body: &RunBody,
    request: &RunControlRequest,
) -> RunControlled {
    let mut producer = harness();
    let done = start(&mut producer, body, request.clone()).unwrap();
    let mut batch = WriteBatch::new(relation::IN_MIGRATION_RUN);
    for row in producer.db.vertices_at(done.recorded_at).unwrap() {
        if row.created_at == done.recorded_at && row.labels != [label::INTENT_OUTCOME] {
            batch.create_vertex(row.vid, row.labels, row.props);
        }
    }
    batch.add_edge(
        edge_id(relation::IN_MIGRATION_RUN, done.control_entry, done.run),
        done.control_entry,
        done.run,
        vec![],
    );
    let mut evidence = WriteBatch::new(relation::EVIDENCED_BY);
    for cite in &request.proposal.evidence {
        let doc = document_vid(&cite.document_oid);
        evidence.add_edge(
            edge_id(relation::EVIDENCED_BY, done.control_entry, doc),
            done.control_entry,
            doc,
            vec![],
        );
    }
    let ctx = h.ctx();
    let mut txn = h.db.begin(&ctx.txn()).unwrap();
    txn.write_ordered(&mut h.db, vec![batch, evidence]).unwrap();
    let recorded_at = h
        .runtime
        .block_on(txn.commit(&mut h.db, &ctx.commit()))
        .unwrap();
    RunControlled {
        recorded_at,
        ..done
    }
}

#[test]
fn authentic_legacy_open_retries_survive_recovery_and_reopen_without_backfill() {
    let mut h = harness_legacy();
    let original = h.proposal(
        h.rent_legs(100),
        b"migration-old-target",
        EntryClass::ORIGINAL,
    );
    let target = outcome_recovery_tests::write_legacy(&mut h, original);
    let reversal = h.reversal_of_entry(target, b"migration-old-reversal");
    outcome_recovery_tests::write_legacy(&mut h, reversal);
    let (body, request) = opening_request(&h, "legacy-run", b"legacy-open-key");
    let done = write_legacy_open(&mut h, &body, &request);
    let original_row = h.db.vertex(done.control_entry).unwrap().unwrap();
    let expected = RunControlled {
        already_recorded: true,
        ..done
    };
    let before = h.db.frontier().unwrap();
    assert_eq!(start(&mut h, &body, request.clone()).unwrap(), expected);
    assert_eq!(h.db.frontier().unwrap(), before);
    assert!(
        h.db.vertex(outcome(&h, &request.proposal.idempotency_key))
            .unwrap()
            .is_none()
    );
    let (fresh_body, fresh) = opening_request(&h, "after-recovery", b"fresh-migration-key");
    let refusal = start(&mut h, &fresh_body, fresh.clone()).unwrap_err();
    assert_eq!(refusal.code, code::PLAN_INVALIDATED);
    assert!(refusal.fix.contains("recover outcomes"));
    assert_eq!(h.db.frontier().unwrap(), before);
    let ctx = h.ctx();
    let prepared = h
        .runtime
        .block_on(prepare_outcome_rebuild(
            &mut h.db,
            &ctx,
            &h.book,
            Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    h.runtime
        .block_on(publish_outcome_rebuild(&mut h.db, &ctx, &h.book, prepared))
        .unwrap()
        .unwrap();
    let (vfs, keys) = h.legacy_storage.clone().unwrap();
    let empty = h
        .runtime
        .block_on(Database::open_memory(&ctx.commit(), keys.clone()))
        .unwrap();
    drop(std::mem::replace(&mut h.db, empty));
    h.db = h
        .runtime
        .block_on(Database::open_with_vfs(
            &ctx.commit(),
            vfs.clone(),
            vfs.database_dir(),
            keys,
        ))
        .unwrap();
    let before = h.db.frontier().unwrap();
    assert_eq!(start(&mut h, &body, request.clone()).unwrap(), expected);
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(
        h.db.vertex(expected.control_entry).unwrap().unwrap(),
        original_row
    );
    assert!(
        h.db.vertex(outcome(&h, &request.proposal.idempotency_key))
            .unwrap()
            .is_none()
    );
    let (conflicting_body, conflicting) =
        opening_request(&h, "old-key-collision", b"migration-old-reversal");
    assert_eq!(
        start(&mut h, &conflicting_body, conflicting)
            .unwrap_err()
            .code,
        code::IDEMPOTENCY_CONFLICT
    );
    assert_eq!(h.db.frontier().unwrap(), before);
    let new = start(&mut h, &fresh_body, fresh.clone()).unwrap();
    assert_atomic_claim(&h, &fresh, &new);
    let abandon = control(
        &mut h,
        body.vid(),
        migration::kind::ABANDON,
        b"legacy-run-abandoned",
    );
    transition(&mut h, abandon).unwrap();
    let before = h.db.frontier().unwrap();
    assert_eq!(start(&mut h, &body, request).unwrap(), expected);
    assert_eq!(h.db.frontier().unwrap(), before);
}
