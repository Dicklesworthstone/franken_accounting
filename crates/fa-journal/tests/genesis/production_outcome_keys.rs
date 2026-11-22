//! Production records share their canonical principal/key reservation with
//! monetary batches; retries and views require the original atomic claim.

use super::*;
use fa_journal::refusal::{Outcome, code};
use fa_model::symbols::label;
use fgdb::WriteBatch;
use fgdb_types::CommitSeq;

const MATTER: &str = "production-outcome";

fn profile(h: &Harness) -> ProductionProfile {
    ProductionProfile {
        book_id: h.book.book_id,
        matter: MATTER.into(),
        bates_prefix: "OUTCOME".into(),
        first_bates: 1,
        load_file_format: 1,
        protective_order: None,
    }
}

fn request(h: &Harness, key: &[u8]) -> ProductionRequest {
    ProductionRequest {
        capability: Capability::embedded(PRINCIPAL, &["produce"]).unwrap(),
        effective_date: h.day(),
        description: h.statement("production outcome", 201),
        idempotency_key: key.to_vec(),
    }
}

fn produced_document(document: Oid) -> ProducedDocument {
    ProducedDocument {
        document,
        pages: Some(2),
        designation: None,
    }
}

fn execute(
    h: &mut Harness,
    producing: bool,
    document: Oid,
    request: ProductionRequest,
) -> Outcome<(VId, CommitSeq)> {
    let ctx = h.ctx();
    if producing {
        h.runtime
            .block_on(produce(
                &mut h.db,
                &ctx,
                &h.book,
                MATTER,
                vec![produced_document(document)],
                request,
            ))
            .map(|result| {
                result.map(|produced| produced.record.expect("this request assigned a range"))
            })
    } else {
        let profile = profile(h);
        h.runtime
            .block_on(open_production(&mut h.db, &ctx, &h.book, profile, request))
            .map(|result| result.map(|opened| (opened.control_entry, opened.recorded_at)))
    }
}

fn fixture(producing: bool) -> (Harness, Oid) {
    let mut h = harness();
    let document = h.document(INVOICE, HUMAN_UPLOAD, b"production outcome source");
    h.add_document(&document).unwrap();
    let oid = document.oid();
    if producing {
        let opening = request(&h, b"fixture-open");
        execute(&mut h, false, oid, opening).unwrap().unwrap();
    }
    (h, oid)
}

/// The wire identity is the canonical ProductionControl key, not its raw
/// caller key. A batch deliberately reserves that same principal/key pair.
fn key(h: &Harness, producing: bool, raw: &[u8]) -> Vec<u8> {
    fa_model::domain_digest(
        b"fa:production-record-key:v1",
        &[
            &[u8::from(producing)],
            &fa_model::production_profile_vid(h.book.book_id, MATTER)
                .0
                .to_le_bytes(),
            raw,
        ],
    )
    .to_vec()
}

fn outcome(h: &Harness, key: &[u8]) -> VId {
    fa_model::intent_outcome_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), key)
}

#[test]
fn a_batch_key_blocks_open_and_produce_before_any_production_effect() {
    for producing in [false, true] {
        let (mut h, document) = fixture(producing);
        let raw = b"batch-reserved-production";
        let canonical = key(&h, producing, raw);
        let target = entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), &canonical);
        let member = h.proposal(
            h.rent_legs(100),
            b"production-batch-member",
            EntryClass::ORIGINAL,
        );
        let batch = h.batch(&canonical, vec![member]);
        let posted = h.post_batch(batch).unwrap();
        assert_eq!(posted.outcome, outcome(&h, &canonical));
        assert!(h.db.vertex(target).unwrap().is_none());

        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let edges = h.db.edges_at(head).unwrap();
        let attempted = request(&h, raw);
        let refusal = execute(&mut h, producing, document, attempted)
            .unwrap()
            .unwrap_err();
        assert_eq!(
            (refusal.code, refusal.exit),
            (code::IDEMPOTENCY_CONFLICT, exit::CONFLICT),
            "producing={producing}: {refusal}"
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert_eq!(h.db.edges_at(head).unwrap(), edges);
        assert!(h.db.vertex(target).unwrap().is_none());

        let view = read_production(&h.db, &h.book, MATTER).unwrap();
        if producing {
            let view = view.unwrap();
            assert_eq!(view.next_bates, 1);
            assert!(view.ranges.is_empty());
        } else {
            assert!(view.is_none());
        }
    }
}

#[test]
fn open_and_produce_publish_atomic_claims_that_block_a_batch_key() {
    for producing in [false, true] {
        let (mut h, document) = fixture(producing);
        let raw = b"production-reserved-batch";
        let canonical = key(&h, producing, raw);
        let attempted = request(&h, raw);
        let (target, recorded_at) = execute(&mut h, producing, document, attempted)
            .unwrap()
            .unwrap();
        let (entry, entry_at) = read_entry(&h.db, target).unwrap().unwrap();
        assert_eq!(entry.proposal.class, EntryClass::PRODUCTION_CONTROL);
        assert_eq!(entry.proposal.idempotency_key, canonical);
        assert_eq!(entry_at, recorded_at);
        let claim = h.db.vertex(outcome(&h, &canonical)).unwrap().unwrap();
        assert_eq!(claim.labels, vec![label::INTENT_OUTCOME]);
        assert_eq!(claim.created_at, recorded_at);
        assert_eq!(
            fa_journal::rows::prop(&claim, property::TARGET_REF),
            Some(&CanonicalScalar::bytes(target.0.to_le_bytes().to_vec()).unwrap())
        );

        let member = h.proposal(
            h.rent_legs(200),
            b"unpublished-production-batch-member",
            EntryClass::ORIGINAL,
        );
        let member_vid = h.member_ref(&member).vid;
        let batch = h.batch(&canonical, vec![member]);
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let edges = h.db.edges_at(head).unwrap();
        let refusal = h.post_batch(batch).unwrap_err();
        assert_eq!(
            (refusal.code, refusal.exit),
            (code::IDEMPOTENCY_CONFLICT, exit::CONFLICT),
            "producing={producing}: {refusal}"
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert_eq!(h.db.edges_at(head).unwrap(), edges);
        assert!(h.db.vertex(member_vid).unwrap().is_none());
    }
}

#[test]
fn production_retries_and_views_reject_deleted_retargeted_and_restored_claims() {
    for producing in [false, true] {
        for attack in ["deleted", "retargeted", "rewritten and restored"] {
            let (mut h, document) = fixture(producing);
            let raw = b"production-claim-integrity";
            let canonical = key(&h, producing, raw);
            let attempted = request(&h, raw);
            execute(&mut h, producing, document, attempted)
                .unwrap()
                .unwrap();
            let claim_vid = outcome(&h, &canonical);
            let original = h.db.vertex(claim_vid).unwrap().unwrap();
            let mut change = WriteBatch::new(relation::IN_CASE);
            match attack {
                "deleted" => {
                    change.delete_vertex(claim_vid);
                }
                "retargeted" => {
                    change.set_vertex_property(
                        claim_vid,
                        property::TARGET_REF,
                        Some(CanonicalScalar::bytes(VId(202).0.to_le_bytes().to_vec()).unwrap()),
                    );
                }
                "rewritten and restored" => {
                    change.set_vertex_property(
                        claim_vid,
                        property::FA_PAYLOAD,
                        Some(CanonicalScalar::bytes(vec![0x56; 32]).unwrap()),
                    );
                }
                _ => unreachable!(),
            }
            h.write_raw(change);
            if attack == "rewritten and restored" {
                let mut restore = WriteBatch::new(relation::IN_CASE);
                restore.set_vertex_property(
                    claim_vid,
                    property::FA_PAYLOAD,
                    Some(
                        fa_journal::rows::prop(&original, property::FA_PAYLOAD)
                            .unwrap()
                            .clone(),
                    ),
                );
                h.write_raw(restore);
                assert_eq!(
                    h.db.vertex(claim_vid).unwrap().unwrap().props,
                    original.props
                );
            }

            let head = h.db.frontier().unwrap();
            let rows = h.db.vertices().unwrap();
            let edges = h.db.edges_at(head).unwrap();
            assert!(
                read_production(&h.db, &h.book, MATTER).is_err(),
                "producing={producing}, attack={attack}"
            );
            assert!(
                list_productions(&h.db, &h.book).is_err(),
                "producing={producing}, attack={attack}"
            );
            let attempted = request(&h, raw);
            match execute(&mut h, producing, document, attempted) {
                Ok(Err(refusal)) => assert_eq!(refusal.code, code::IDEMPOTENCY_CONFLICT),
                Err(KernelError::Corrupt(_)) => {}
                other => panic!(
                    "damaged production was accepted: producing={producing}, \
                     attack={attack}, result={other:?}"
                ),
            }
            assert_eq!(h.db.frontier().unwrap(), head);
            assert_eq!(h.db.vertices().unwrap(), rows);
            assert_eq!(h.db.edges_at(head).unwrap(), edges);
        }
    }
}

#[test]
fn a_noop_production_claims_nothing_but_still_respects_an_occupied_key() {
    let (mut h, document) = fixture(true);
    let first_request = request(&h, b"first-production");
    execute(&mut h, true, document, first_request)
        .unwrap()
        .unwrap();
    let raw = b"already-produced-noop";
    let canonical = key(&h, true, raw);
    let target = entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), &canonical);
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let ctx = h.ctx();
    let no_op_request = request(&h, raw);
    let no_op = h
        .runtime
        .block_on(produce(
            &mut h.db,
            &ctx,
            &h.book,
            MATTER,
            vec![produced_document(document)],
            no_op_request,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(no_op.record, None);
    assert_eq!(no_op.next_bates, 3);
    assert!(!no_op.ranges[0].assigned);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
    assert!(h.db.vertex(target).unwrap().is_none());
    assert!(h.db.vertex(outcome(&h, &canonical)).unwrap().is_none());

    let member = h.proposal(
        h.rent_legs(300),
        b"noop-production-batch-member",
        EntryClass::ORIGINAL,
    );
    let batch = h.batch(&canonical, vec![member]);
    h.post_batch(batch).unwrap();
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let ctx = h.ctx();
    let no_op_request = request(&h, raw);
    let refusal = h
        .runtime
        .block_on(produce(
            &mut h.db,
            &ctx,
            &h.book,
            MATTER,
            vec![produced_document(document)],
            no_op_request,
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(
        (refusal.code, refusal.exit),
        (code::IDEMPOTENCY_CONFLICT, exit::CONFLICT)
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
    let view = read_production(&h.db, &h.book, MATTER).unwrap().unwrap();
    assert_eq!(view.next_bates, 3);
    assert_eq!(view.ranges.len(), 1);
}
