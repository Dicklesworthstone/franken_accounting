//! Access receipts recorded by the public facade are protected by the same
//! signed checkpoints and independent proof verifier as journal entries.

use fa::access_log::{AccessRecord, request_digest};
use fa::{Book, BookKeys, Capability, Entropy, ProofKind, ProofRequest, SuffixRequest};
use fa_journal::BookSpec;
use fa_model::Id128;
use fa_money::UnitRegistry;
use fa_time::FiscalCalendar;
use fgdb_types::{CommitSeq, VId};

const PRINCIPAL: VId = VId(7);

fn book() -> Book {
    let units = UnitRegistry::embedded().unwrap();
    Book::create_memory(
        BookKeys::for_development(71),
        BookSpec {
            book_id: Id128([71; 16]),
            name: "Access checkpoint fixture".into(),
            base_unit: units.lookup("USD").unwrap(),
            calendar: FiscalCalendar::monthly("access-monthly", 1, 0).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(71),
    )
    .unwrap()
}

fn access(command: &str, capability: &Capability) -> AccessRecord {
    AccessRecord {
        principal: PRINCIPAL,
        principal_name: "examiner".into(),
        capability_commitment: capability.commitment().unwrap(),
        ops: vec!["produce".into(), "read".into()],
        command: command.into(),
        request_digest: request_digest(&[command.into(), "--json".into()]),
    }
}

#[test]
fn recorded_access_events_reach_signed_checkpoints_and_complete_offline_proofs() {
    let mut book = book();
    let producer = Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap();
    let witness = Capability::embedded(PRINCIPAL, &["witness"]).unwrap();
    let first_head = book.head().unwrap();
    let first_record = access("statement", &producer);
    let first = book.record_access(&first_record).unwrap().unwrap();
    assert_eq!(first.observed_at, first_head);
    assert!(first.recorded_at > first.observed_at);
    let old = book.checkpoint(PRINCIPAL, &witness).unwrap().unwrap();
    assert_eq!(old.stored.state.access_after, Some(CommitSeq(1)));

    let trusted_old = fa_verify::verify_state(&old.stored.bytes)
        .expect("the independent state decoder accepts access coverage")
        .checkpoint;
    let signed = book
        .export_proof(
            PRINCIPAL,
            &producer,
            ProofRequest {
                state: Some(old.stored.oid),
                kind: ProofKind::SignedCheckpoint,
            },
        )
        .unwrap()
        .unwrap();
    let signed_anchor =
        fa_verify::verify_checkpoint(&signed.bytes, &[book.checkpoint_public_key()])
            .expect("the checkpoint carrying access leaves has a valid book signature");
    assert_eq!(signed_anchor.checkpoint, trusted_old);
    assert_eq!(signed_anchor.state_oid, old.stored.oid.0);
    let inclusion = book
        .export_proof(
            PRINCIPAL,
            &producer,
            ProofRequest {
                state: Some(old.stored.oid),
                kind: ProofKind::Inclusion {
                    entry: first.vid,
                    with_record: true,
                },
            },
        )
        .unwrap()
        .unwrap();
    let verified = fa_verify::verify_inclusion(&inclusion.bytes, &trusted_old).unwrap();
    assert_eq!(verified.record, fa_verify::RecordCheck::Recomputed);
    assert_eq!(verified.envelope.kind, 6);
    assert_eq!(verified.envelope.commit_seq, first.recorded_at.0);
    assert_eq!(verified.envelope.record_digest, first.digest);
    assert!(verified.envelope.account_vids.is_empty());
    assert!(verified.envelope.unit_ids.is_empty());

    // An access-log read has its own receipt, and neither checkpoint is itself
    // an accounting or access leaf. The new root must extend the saved one by
    // exactly the newly recorded access event.
    let second_record = access("access log", &producer);
    let second = book.record_access(&second_record).unwrap().unwrap();
    let new = book.checkpoint(PRINCIPAL, &witness).unwrap().unwrap();
    assert_eq!(new.stored.state.access_after, old.stored.state.access_after);
    assert_eq!(new.stored.state.leaf_count, old.stored.state.leaf_count + 1);
    let trusted_new = fa_verify::verify_state(&new.stored.bytes)
        .unwrap()
        .checkpoint;
    let suffix = book
        .export_suffix(
            PRINCIPAL,
            &producer,
            SuffixRequest {
                state: old.stored.oid,
                next_state: Some(new.stored.oid),
            },
        )
        .unwrap()
        .unwrap();
    fa_verify::verify_consistency(&suffix.consistency, &trusted_old, &trusted_new).unwrap();
    assert_eq!(suffix.records.len(), 1);
    let appended = fa_verify::verify_inclusion(&suffix.records[0], &trusted_new).unwrap();
    assert_eq!(appended.record, fa_verify::RecordCheck::Recomputed);
    assert_eq!(appended.envelope.kind, 6);
    assert_eq!(appended.envelope.record_digest, second.digest);

    let complete = book
        .export_proof(
            PRINCIPAL,
            &producer,
            ProofRequest {
                state: Some(new.stored.oid),
                kind: ProofKind::PrefixWithRecords,
            },
        )
        .unwrap()
        .unwrap();
    let prefix = fa_verify::proof::production::derivation::verify_prefix_with_records(
        &complete.bytes,
        &trusted_new,
    )
    .unwrap();
    let access_leaves: Vec<_> = prefix
        .envelopes
        .iter()
        .filter(|leaf| leaf.kind == 6)
        .collect();
    assert_eq!(access_leaves.len(), 2);
    assert_eq!(access_leaves[0].record_digest, first.digest);
    assert_eq!(access_leaves[1].record_digest, second.digest);
    assert_eq!(book.access_log(CommitSeq(0)).unwrap(), vec![first, second]);

    // These exports and the direct log read do not invent additional records;
    // the session layer, not proof construction, owns access-attempt recording.
    assert_eq!(book.head().unwrap(), new.stored.recorded_at);
    fa_verify::verify_inclusion(&inclusion.bytes, &trusted_old)
        .expect("later reads and checkpoints preserve the earlier proof");
}
