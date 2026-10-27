//! Authenticate the retained capability event before acknowledging a retry.

use super::*;

#[derive(Clone, Copy, Debug)]
enum Kind {
    Issue,
    Revoke,
}

#[derive(Clone)]
struct Request {
    kind: Kind,
    capability: Capability,
    target: Capability,
    day: DateDay,
    key: Vec<u8>,
    description: Erasable<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Recorded {
    vid: VId,
    at: CommitSeq,
    already: bool,
}

fn text(h: &Harness, value: &str, salt: u8) -> Erasable<String> {
    Erasable::seal(
        &value.to_owned(),
        None,
        &h.book.seal_key,
        [salt; 32],
        [salt; 24],
    )
}

fn request(h: &Harness, kind: Kind) -> Request {
    Request {
        kind,
        capability: human(PREPARER, &["issue_capability", "post", "read"]),
        target: Capability::new(ALICE, Profile::Human, &[Op::Post], PREPARER)
            .unwrap()
            .holder_bound(possession_digest(&[120; 32])),
        day: DateDay::from_ymd(2026, 3, 1).unwrap(),
        key: b"capability-original-key".to_vec(),
        description: text(h, "capability event", 121),
    }
}

fn execute(h: &mut Harness, request: &Request) -> Result<Result<Recorded, Refusal>, KernelError> {
    let ctx = h.ctx();
    match request.kind {
        Kind::Issue => h
            .runtime
            .block_on(issue_capability(
                &mut h.db,
                &ctx,
                &h.book,
                IssuanceRequest {
                    capability: request.capability.clone(),
                    issued: request.target.clone(),
                    effective_date: request.day,
                    idempotency_key: request.key.clone(),
                    description: request.description.clone(),
                },
            ))
            .map(|result| {
                result.map(|outcome| Recorded {
                    vid: outcome.control_entry,
                    at: outcome.recorded_at,
                    already: outcome.already_recorded,
                })
            }),
        Kind::Revoke => h
            .runtime
            .block_on(revoke_capability(
                &mut h.db,
                &ctx,
                &h.book,
                RevocationRequest {
                    capability: request.capability.clone(),
                    revoked: request.target.commitment().unwrap(),
                    effective_date: request.day,
                    idempotency_key: request.key.clone(),
                    description: request.description.clone(),
                },
            ))
            .map(|result| {
                result.map(|outcome| Recorded {
                    vid: outcome.control_entry,
                    at: outcome.recorded_at,
                    already: outcome.already_recorded,
                })
            }),
    }
}

fn write(h: &mut Harness, batch: WriteBatch) {
    let ctx = h.ctx();
    h.runtime
        .block_on(h.db.write(&ctx.commit(), batch))
        .unwrap();
}

fn assert_conflict(h: &mut Harness, request: &Request) {
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let refusal = execute(h, request).unwrap().unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

fn outcome(h: &Harness, request: &Request) -> VId {
    fa_model::intent_outcome_vid(
        h.book.book_id,
        &request.capability.holder().0.to_le_bytes(),
        &request.key,
    )
}

#[test]
fn original_capability_keys_bind_semantics_and_resealed_retries_return_the_original_result() {
    for kind in [Kind::Issue, Kind::Revoke] {
        let mut h = harness();
        let original = request(&h, kind);
        let before = h.db.frontier().unwrap();
        let count = h.db.vertices().unwrap().len();
        let first = execute(&mut h, &original).unwrap().unwrap();
        assert_eq!(first.at.0, before.0 + 1);
        assert!(!first.already);
        assert_eq!(h.db.vertices().unwrap().len(), count + 2);
        let claim = h.db.vertex(outcome(&h, &original)).unwrap().unwrap();
        assert_eq!(claim.labels, vec![label::INTENT_OUTCOME]);
        assert_eq!(claim.created_at, first.at);
        assert_eq!(
            fa_journal::rows::prop(&claim, property::TARGET_REF),
            Some(&CanonicalScalar::bytes(first.vid.0.to_le_bytes().to_vec()).unwrap()),
        );
        let expected = Recorded {
            already: true,
            ..first
        };
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        assert_eq!(execute(&mut h, &original).unwrap().unwrap(), expected);
        let mut changed = original.clone();
        changed.description = text(&h, "a different request", 122);
        assert_conflict(&mut h, &changed);
        let mut changed = original.clone();
        changed.day = DateDay::from_ymd(2026, 3, 2).unwrap();
        assert_conflict(&mut h, &changed);
        let mut resealed = original;
        resealed.description = text(&h, "capability event", 123);
        assert_eq!(execute(&mut h, &resealed).unwrap().unwrap(), expected);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn capability_events_reserve_the_common_key_against_posting_batches_and_other_targets() {
    for kind in [Kind::Issue, Kind::Revoke] {
        let mut h = harness();
        let original = request(&h, kind);
        let first = execute(&mut h, &original).unwrap().unwrap();
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();

        let post = h.proposal(PREPARER, 100, &original.key, EntryClass::ORIGINAL);
        let refusal = h
            .post(post, human(PREPARER, &["post"]), Vec::new())
            .unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));

        let mut other_target = original.clone();
        other_target.target = other_target
            .target
            .clone()
            .holder_bound(possession_digest(&[137; 32]));
        assert_conflict(&mut h, &other_target);
        let mut other_kind = original.clone();
        other_kind.kind = match kind {
            Kind::Issue => Kind::Revoke,
            Kind::Revoke => Kind::Issue,
        };
        assert_conflict(&mut h, &other_kind);

        let member = h.proposal(
            PREPARER,
            200,
            b"unpublished-capability-key-batch-member",
            EntryClass::ORIGINAL,
        );
        let batch = PostBatch::new(
            original.key.clone(),
            vec![PostIntent::new(member, Vec::new()).unwrap()],
        )
        .unwrap();
        let ctx = h.ctx();
        let refused = h
            .runtime
            .block_on(post_batch(
                &mut h.db,
                &ctx,
                &h.book,
                human(PREPARER, &["post"]),
                batch,
            ))
            .unwrap()
            .unwrap_err();
        assert_eq!((refused.code, refused.exit), ("FA-REF-032", exit::CONFLICT));
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert_eq!(
            execute(&mut h, &original).unwrap().unwrap(),
            Recorded {
                already: true,
                ..first
            },
        );
        let other_principal = h.proposal(BOB, 300, &original.key, EntryClass::ORIGINAL);
        h.post(other_principal, human(BOB, &["post"]), Vec::new())
            .expect("the same bytes are a different key in another principal's scope");
    }
}

#[test]
fn posting_and_batch_keys_cannot_issue_revoke_or_observe_an_existing_capability() {
    for kind in [Kind::Issue, Kind::Revoke] {
        for batch_key in [false, true] {
            let mut h = harness();
            let original = request(&h, kind);
            execute(&mut h, &original).unwrap().unwrap();
            let occupied = b"occupied-capability-request";
            if batch_key {
                let member = h.proposal(
                    PREPARER,
                    100,
                    b"capability-collision-batch-member",
                    EntryClass::ORIGINAL,
                );
                let batch = PostBatch::new(
                    occupied.to_vec(),
                    vec![PostIntent::new(member, Vec::new()).unwrap()],
                )
                .unwrap();
                let ctx = h.ctx();
                h.runtime
                    .block_on(post_batch(
                        &mut h.db,
                        &ctx,
                        &h.book,
                        human(PREPARER, &["post"]),
                        batch,
                    ))
                    .unwrap()
                    .unwrap();
            } else {
                let post = h.proposal(PREPARER, 100, occupied, EntryClass::ORIGINAL);
                h.post(post, human(PREPARER, &["post"]), Vec::new())
                    .unwrap();
            }
            let mut occupied_request = original;
            occupied_request.key = occupied.to_vec();
            // Neither an existing target nor a fresh target bypasses the
            // scoped key already owned by a different successful intent.
            assert_conflict(&mut h, &occupied_request);
            occupied_request.target = occupied_request
                .target
                .holder_bound(possession_digest(&[138; 32]));
            assert_conflict(&mut h, &occupied_request);
        }
    }
}

#[test]
fn a_prepared_post_loses_to_a_capability_event_reserving_the_same_key() {
    for kind in [Kind::Issue, Kind::Revoke] {
        let mut h = harness();
        let original = request(&h, kind);
        let proposal = h.proposal(PREPARER, 100, &original.key, EntryClass::ORIGINAL);
        let post_vid =
            fa_model::entry_vid(h.book.book_id, &PREPARER.0.to_le_bytes(), &original.key);
        let ctx = h.ctx();
        let PostPreparation::Ready(prepared) = prepare_post(
            &mut h.db,
            &ctx,
            &h.book,
            PostRequest {
                proposal,
                capability: human(PREPARER, &["post"]),
                approvals: Vec::new(),
                plan_certificate: None,
            },
        )
        .unwrap()
        .unwrap() else {
            panic!("fresh posting")
        };
        let recorded = execute(&mut h, &original).unwrap().unwrap();
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let refused = h
            .runtime
            .block_on(prepared.commit(&mut h.db, &ctx))
            .unwrap()
            .unwrap_err();
        assert_eq!(refused.exit, exit::CONFLICT);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert!(h.db.vertex(post_vid).unwrap().is_none());
        assert_eq!(
            h.db.vertex(outcome(&h, &original))
                .unwrap()
                .unwrap()
                .created_at,
            recorded.at,
        );
    }
}

#[test]
fn a_missing_or_rewritten_capability_claim_cannot_be_treated_as_a_legacy_event() {
    for kind in [Kind::Issue, Kind::Revoke] {
        for deleted in [false, true] {
            let mut h = harness();
            let original = request(&h, kind);
            let recorded = execute(&mut h, &original).unwrap().unwrap();
            let claim = outcome(&h, &original);
            assert!(h.db.vertex_at(claim, recorded.at).unwrap().is_some());
            let mut damage = WriteBatch::new(relation::IN_BOOK);
            if deleted {
                damage.delete_vertex(claim);
            } else {
                damage.set_vertex_property(
                    claim,
                    property::TARGET_REF,
                    Some(CanonicalScalar::bytes(VId(139).0.to_le_bytes().to_vec()).unwrap()),
                );
            }
            write(&mut h, damage);
            assert_conflict(&mut h, &original);
        }
    }
}

#[test]
fn a_new_key_observes_the_authenticated_existing_capability_target_without_republishing() {
    for kind in [Kind::Issue, Kind::Revoke] {
        let mut h = harness();
        let mut next = request(&h, kind);
        let first = execute(&mut h, &next).unwrap().unwrap();
        next.key = b"another-request-key".to_vec();
        next.day = DateDay::from_ymd(2026, 3, 2).unwrap();
        next.description = text(&h, "observe the existing target", 124);
        if matches!(kind, Kind::Revoke) {
            next.capability = human(BOB, &["issue_capability"]);
        }
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        assert_eq!(
            execute(&mut h, &next).unwrap().unwrap(),
            Recorded {
                already: true,
                ..first
            },
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn an_original_issuance_key_cannot_switch_its_recorded_issuer_capability() {
    let mut h = harness();
    let mut next = request(&h, Kind::Issue);
    execute(&mut h, &next).unwrap().unwrap();
    next.capability = human(PREPARER, &["issue_capability", "post"]);
    assert_conflict(&mut h, &next);
}

#[test]
fn a_modern_issuance_claim_authenticates_a_target_for_a_new_issuer_request() {
    let mut h = harness();
    let original = request(&h, Kind::Issue);
    let first = execute(&mut h, &original).unwrap().unwrap();
    let mut next = original;
    next.key = b"observe-issued-target-under-current-authority".to_vec();
    next.capability = human(PREPARER, &["issue_capability", "post"]);
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    assert_eq!(
        execute(&mut h, &next).unwrap().unwrap(),
        Recorded {
            already: true,
            ..first
        },
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

#[test]
fn a_target_identity_requires_the_right_control_and_its_empty_acceptance_envelope() {
    for kind in [Kind::Issue, Kind::Revoke] {
        let mut producer = harness();
        let original = request(&producer, kind);
        let first = execute(&mut producer, &original).unwrap().unwrap();
        let (entry, _) = read_entry(&producer.db, first.vid).unwrap().unwrap();
        for damage in [
            "kind",
            "commitment",
            "caveats",
            "origin",
            "book",
            "branch",
            "label",
            "mirror",
            "approvals",
            "plan",
        ] {
            let mut h = harness();
            let mut altered = entry.proposal.clone();
            let mut approvals = Vec::new();
            let mut plan = None;
            match damage {
                "kind" => {
                    let Some(ControlPayload::CapabilityEvent { kind, .. }) = &mut altered.control
                    else {
                        panic!("capability event")
                    };
                    *kind = 2;
                }
                "commitment" => {
                    let Some(ControlPayload::CapabilityEvent { commitment, .. }) =
                        &mut altered.control
                    else {
                        panic!("capability event")
                    };
                    *commitment = [125; 32];
                }
                "caveats" => {
                    let Some(ControlPayload::CapabilityEvent { caveats_digest, .. }) =
                        &mut altered.control
                    else {
                        panic!("capability event")
                    };
                    *caveats_digest = [126; 32];
                }
                "origin" => {
                    let EntryOrigin::Control {
                        spec_body_digest, ..
                    } = &mut altered.origin
                    else {
                        panic!("capability control origin")
                    };
                    // Keep the class-compatible kind so sealing reaches the
                    // retained-origin authentication this fixture exercises.
                    *spec_body_digest = [127; 32];
                }
                "book" => altered.book_id = Id128([128; 16]),
                "branch" => altered.branch_id = Id128([129; 16]),
                "approvals" => {
                    approvals.push(h.approve(BOB, entry.proposal_digest).unwrap().approval())
                }
                "plan" => plan = Some(Oid([130; 32])),
                _ => (),
            }
            let altered = altered.seal(approvals, plan).unwrap();
            let mut props = fa_model::entry_mirrors(&altered).unwrap();
            if damage == "mirror" {
                props
                    .iter_mut()
                    .find(|(key, _)| *key == property::CLASS)
                    .unwrap()
                    .1 = CanonicalScalar::Int(255);
            }
            let mut batch = WriteBatch::new(relation::IN_BOOK);
            batch.create_vertex(
                first.vid,
                vec![if damage == "label" {
                    label::ACCOUNT
                } else {
                    label::ENTRY
                }],
                props,
            );
            write(&mut h, batch);
            assert_conflict(&mut h, &original);
            let mut another_key = original.clone();
            another_key.key = b"different-key-cannot-bless-bad-row".to_vec();
            assert_conflict(&mut h, &another_key);
        }
    }
}

#[test]
fn an_issuance_result_binds_its_canonical_body_and_recorded_issuer() {
    let mut producer = harness();
    let original = request(&producer, Kind::Issue);
    let first = execute(&mut producer, &original).unwrap().unwrap();
    let (entry, _) = read_entry(&producer.db, first.vid).unwrap().unwrap();
    for damage in ["body", "issuer"] {
        let mut h = harness();
        let mut altered = entry.proposal.clone();
        if damage == "body" {
            altered.extensions[0].1 = original
                .target
                .clone()
                .expiring_at(CommitSeq(500))
                .canonical_bytes()
                .unwrap();
        } else {
            altered.principal_ref = BOB;
        }
        let altered = altered.seal(Vec::new(), None).unwrap();
        let mut batch = WriteBatch::new(relation::IN_BOOK);
        batch.create_vertex(
            first.vid,
            vec![label::ENTRY],
            fa_model::entry_mirrors(&altered).unwrap(),
        );
        write(&mut h, batch);
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let result = execute(&mut h, &original);
        if damage == "body" {
            assert!(matches!(result, Err(KernelError::Corrupt(_))));
        } else {
            assert_eq!(result.unwrap().unwrap_err().code, "FA-REF-032");
        }
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn a_rewritten_capability_entry_cannot_supply_a_new_original_outcome() {
    for kind in [Kind::Issue, Kind::Revoke] {
        let mut h = harness();
        let mut next = request(&h, kind);
        let first = execute(&mut h, &next).unwrap().unwrap();
        let (entry, _) = read_entry(&h.db, first.vid).unwrap().unwrap();
        next.description = text(&h, "rewritten capability event", 131);
        let mut altered = entry.proposal;
        altered.description = next.description.clone();
        let altered = altered.seal(Vec::new(), None).unwrap();
        let mut batch = WriteBatch::new(relation::IN_BOOK);
        for (key, value) in fa_model::entry_mirrors(&altered).unwrap() {
            batch.set_vertex_property(first.vid, key, Some(value));
        }
        write(&mut h, batch);
        assert_conflict(&mut h, &next);
        next.key = b"a-new-key-does-not-legitimize-rewriting".to_vec();
        assert_conflict(&mut h, &next);
    }
}

#[test]
fn capability_retry_admission_precedes_observing_a_malformed_target() {
    for kind in [Kind::Issue, Kind::Revoke] {
        let mut h = harness();
        let original = request(&h, kind);
        let commitment = original.target.commitment().unwrap();
        let vid = match kind {
            Kind::Issue => issuance_vid(h.book.book_id, &commitment),
            Kind::Revoke => revocation_vid(h.book.book_id, &commitment),
        };
        let mut batch = WriteBatch::new(relation::IN_BOOK);
        batch.create_vertex(
            vid,
            vec![label::ENTRY],
            vec![(
                property::FA_PAYLOAD,
                CanonicalScalar::bytes(vec![0xff; 8]).unwrap(),
            )],
        );
        write(&mut h, batch);
        h.revoke(
            &human(CAROL, &["issue_capability"]),
            &original.capability,
            b"revoke-retry-observer",
        )
        .unwrap();
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        for (capability, code) in [
            (human(PREPARER, &["read"]), "FA-REF-011"),
            (
                original
                    .capability
                    .clone()
                    .for_books(&[Id128([132; 16])])
                    .unwrap(),
                "FA-REF-011",
            ),
            (original.capability.clone().expiring_at(head), "FA-REF-014"),
            (original.capability.clone(), "FA-REF-023"),
        ] {
            let mut denied = original.clone();
            denied.capability = capability;
            let refusal = execute(&mut h, &denied).unwrap().unwrap_err();
            assert_eq!((refusal.code, refusal.exit), (code, exit::SAFETY));
        }
        let mut admitted = original;
        admitted.capability = human(PREPARER, &["issue_capability", "post"]);
        assert!(
            execute(&mut h, &admitted).is_err(),
            "an admitted observer reaches the malformed target"
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn capability_results_retain_their_original_coordinates_after_durable_reopen() {
    for kind in [Kind::Issue, Kind::Revoke] {
        let mut h = harness();
        let ctx = h.ctx();
        let keys = DatabaseKeys::new([133; 32], DatabaseSecurityNamespaceId([134; 32]), [135; 32]);
        let vfs = ctx.commit().with_restriction(MemVfs::new).unwrap();
        h.db = h
            .runtime
            .block_on(Database::create_with_vfs(
                &ctx.commit(),
                vfs.clone(),
                vfs.database_dir(),
                keys.clone(),
            ))
            .unwrap();
        let spec = BookSpec {
            book_id: h.book.book_id,
            name: "Durable capability retry".into(),
            base_unit: h.usd,
            calendar: h.book.calendar.clone(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        h.runtime
            .block_on(create_book(
                &mut h.db,
                &ctx,
                &spec,
                &h.book.units,
                &h.book.symbols,
            ))
            .unwrap();
        let original = request(&h, kind);
        let first = execute(&mut h, &original).unwrap().unwrap();
        let original_row = h.db.vertex(first.vid).unwrap().unwrap();
        let original_claim = h.db.vertex(outcome(&h, &original)).unwrap().unwrap();
        let mut unrelated = WriteBatch::new(relation::IN_BOOK);
        unrelated.create_vertex(VId(136), vec![label::DOCUMENT], vec![]);
        write(&mut h, unrelated);
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
        assert!(matches!(
            h.db.delta_since(CommitSeq(0)),
            Err(fgdb::ReadError::DeltaCursorRetired { .. })
        ));
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        assert_eq!(
            execute(&mut h, &original).unwrap().unwrap(),
            Recorded {
                already: true,
                ..first
            }
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert_eq!(h.db.vertex(first.vid).unwrap().unwrap(), original_row);
        assert_eq!(
            h.db.vertex(outcome(&h, &original)).unwrap().unwrap(),
            original_claim,
        );
    }
}

#[test]
fn original_legacy_capability_events_remain_read_only_retry_anchors() {
    for kind in [Kind::Issue, Kind::Revoke] {
        let mut producer = harness();
        let original = request(&producer, kind);
        let produced = execute(&mut producer, &original).unwrap().unwrap();
        let (entry, _) = read_entry(&producer.db, produced.vid).unwrap().unwrap();

        // Reproduce an old writer's publication directly, without creating
        // and deleting a modern claim to manufacture a legacy fixture.
        let mut h = harness();
        let mut legacy = WriteBatch::new(relation::IN_BOOK);
        legacy.create_vertex(
            produced.vid,
            vec![label::ENTRY],
            fa_model::entry_mirrors(&entry).unwrap(),
        );
        write(&mut h, legacy);
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let expected = Recorded {
            vid: produced.vid,
            at: head,
            already: true,
        };
        assert_eq!(execute(&mut h, &original).unwrap().unwrap(), expected);
        let mut resealed = original.clone();
        resealed.description = text(&h, "capability event", 140);
        assert_eq!(execute(&mut h, &resealed).unwrap().unwrap(), expected);
        let mut changed = original.clone();
        changed.description = text(&h, "changed legacy request", 141);
        assert_conflict(&mut h, &changed);
        let mut new_key = original.clone();
        new_key.key = b"observe-authentic-legacy-capability-target".to_vec();
        assert_eq!(execute(&mut h, &new_key).unwrap().unwrap(), expected);
        if matches!(kind, Kind::Issue) {
            new_key.capability = human(PREPARER, &["issue_capability", "post"]);
            assert_conflict(&mut h, &new_key);
        }
        assert!(h.db.vertex(outcome(&h, &original)).unwrap().is_none());
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}
