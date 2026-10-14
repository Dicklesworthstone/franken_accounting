//! Actual producer encodings through the complete independent evidence chain.
//! Synthetic journals are constructed below the storage boundary, as in golden.rs;
//! these tests do not claim posting admission, signatures or export authorization.

use fa_journal::{Document, RedactedView, ViewChunk};
use fa_model::{
    ApprovalRef, Entry, EntryClass, EntryOrigin, EntryPayload, Erasable, EvidenceRef, Id128,
    LegPayload, Oid, SealKey,
};
use fa_money::{Amount, Side, UnitId};
use fa_notary::Journal;
use fa_time::DateDay;
use fa_verify::{
    Checkpoint, EvidenceError, EvidenceExpectation, RecordCheck, verify_evidence_view_for,
};
use fgdb_types::{CommitSeq, VId};

const BOOK: Id128 = Id128([0x42; 16]);
const KEY: SealKey = SealKey([0x33; 32]);

fn document(length: usize) -> Document {
    Document {
        book_id: BOOK,
        kind: 1,
        mime: "application/octet-stream".into(),
        grade: 2,
        retrieved_by: VId(7),
        bytes: (0..length).map(|i| (i % 251) as u8).collect(),
    }
}

fn entry(doc: &Document, key: &[u8], minor: u16) -> Entry {
    let legs = vec![
        LegPayload::simple(Side::Debit, VId(10), Amount::new(UnitId(1), 123)),
        LegPayload::simple(Side::Credit, VId(20), Amount::new(UnitId(1), 123)),
    ];
    let proposal = EntryPayload {
        schema_minor: minor,
        book_id: BOOK,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: DateDay(20_527),
        document_date: Some(DateDay(20_526)),
        description: Erasable::seal(&"evidence".to_string(), None, &KEY, [1; 32], [2; 24]),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: key.to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([4; 32]),
            intent_kind: 1,
        },
        principal_ref: VId(7),
        session_ref: Some(VId(8)),
        evidence: vec![EvidenceRef {
            document_oid: doc.oid(),
            doc_commit: doc.doc_commit(),
            role: 3,
        }],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    let digest = proposal.proposal_digest().unwrap();
    // Nonempty envelope fields ensure the verifier checks the actual framing,
    // not a test-only assumption that the proposal is followed by five zeros.
    proposal
        .seal(
            vec![ApprovalRef {
                approval_vid: VId(9),
                approved_digest: digest,
            }],
            Some(Oid([5; 32])),
        )
        .unwrap()
}

fn checkpoint(journal: &Journal) -> Checkpoint {
    Checkpoint {
        book_id: BOOK.0,
        branch_id: Id128::TRUNK.0,
        through_seq: 20,
        leaf_count: journal.len(),
        root: journal.root(),
    }
}

#[test]
fn producer_journal_entry_and_redacted_view_agree_with_independent_verification() {
    for minor in [0, 1] {
        for length in [0, 1, 4096, 4097, 8193, 5 * 4096 + 3] {
            let doc = document(length);
            let record = entry(&doc, b"cited", minor);
            let expected = EvidenceExpectation {
                entry_digest: record.entry_digest,
                document_oid: doc.oid().0,
                role: 3,
            };
            let journal = Journal::from_records(
                BOOK,
                CommitSeq(20),
                vec![
                    (
                        VId(100),
                        entry(&document(19), b"unrelated", minor),
                        CommitSeq(2),
                    ),
                    (VId(101), record, CommitSeq(7)),
                    (
                        VId(102),
                        entry(&document(23), b"another", minor),
                        CommitSeq(11),
                    ),
                ],
            )
            .unwrap();
            let proof = journal.inclusion_proof(VId(101), true).unwrap().unwrap();
            let view = RedactedView::derive(&doc, 7, &[(4096, 4096)]);
            let shown: Vec<_> = view
                .chunks
                .iter()
                .enumerate()
                .filter_map(|(index, chunk)| {
                    matches!(chunk, ViewChunk::Disclosed(_)).then_some(index as u64)
                })
                .collect();
            let bytes = view.canonical_bytes().unwrap();
            let verified =
                verify_evidence_view_for(&proof, &bytes, &checkpoint(&journal), &expected, &shown)
                    .unwrap();
            assert_eq!(verified.inclusion.record, RecordCheck::Recomputed);
            assert_eq!(verified.inclusion.leaf_index, 1);
            assert_eq!(verified.inclusion.envelope.commit_seq, 7);
            assert_eq!(verified.citation.doc_commit, doc.doc_commit());
            assert_eq!(verified.citation.document_oid, doc.oid().0);
            assert_eq!(verified.view_commit, view.view_commit().unwrap());
            assert_eq!(verified.disclosure_scope, "membership_only");
            for chunk in verified.disclosed {
                let start = chunk.index as usize * 4096;
                assert_eq!(chunk.bytes, &doc.bytes[start..(start + 4096).min(length)]);
            }
        }
    }
}

#[test]
fn genuine_producer_outputs_cannot_be_mixed_into_an_uncited_disclosure() {
    let doc = document(8193);
    let record = entry(&doc, b"cited", 1);
    let expected = EvidenceExpectation {
        entry_digest: record.entry_digest,
        document_oid: doc.oid().0,
        role: 3,
    };
    let journal =
        Journal::from_records(BOOK, CommitSeq(20), vec![(VId(101), record, CommitSeq(7))]).unwrap();
    let checkpoint = checkpoint(&journal);
    let proof = journal.inclusion_proof(VId(101), true).unwrap().unwrap();
    let good = RedactedView::derive(&doc, 7, &[(4096, 4096)])
        .canonical_bytes()
        .unwrap();
    let unrelated = RedactedView::derive(&document(8194), 7, &[(4096, 4096)])
        .canonical_bytes()
        .unwrap();
    assert!(verify_evidence_view_for(&proof, &unrelated, &checkpoint, &expected, &[0, 2]).is_err());
    let envelope_only = journal.inclusion_proof(VId(101), false).unwrap().unwrap();
    assert_eq!(
        verify_evidence_view_for(&envelope_only, &good, &checkpoint, &expected, &[0, 2]),
        Err(EvidenceError::RecordRequired)
    );
    let mut wrong_role = expected;
    wrong_role.role = 4;
    assert_eq!(
        verify_evidence_view_for(&proof, &good, &checkpoint, &wrong_role, &[0, 2]),
        Err(EvidenceError::CitationMissing)
    );
    let mut relabeled = good;
    relabeled[2] ^= 1;
    assert_eq!(
        verify_evidence_view_for(&proof, &relabeled, &checkpoint, &expected, &[0, 2]),
        Err(EvidenceError::ViewLocator)
    );
}

#[test]
fn compact_export_of_only_requested_readable_chunks_has_the_same_authenticated_chain() {
    use fa_notary::disclosure::disclosure_from_view;
    use fa_verify::evidence::verify_evidence_disclosure_for;

    let doc = document(8193);
    let record = entry(&doc, b"compact", 1);
    let expected = EvidenceExpectation {
        entry_digest: record.entry_digest,
        document_oid: doc.oid().0,
        role: 3,
    };
    let journal =
        Journal::from_records(BOOK, CommitSeq(20), vec![(VId(101), record, CommitSeq(7))]).unwrap();
    let checkpoint = checkpoint(&journal);
    let proof = journal.inclusion_proof(VId(101), true).unwrap().unwrap();
    let view = RedactedView::derive(&doc, 7, &[(4096, 4096)]);
    // The authorized view permits 0 and 2, but the recipient asks only for 2.
    // Export the subset, not the other readable chunk or withheld chunk 1.
    let compact = disclosure_from_view(&view, &[2], &doc.doc_commit()).unwrap();
    assert!(compact.len() < view.canonical_bytes().unwrap().len());
    let verified =
        verify_evidence_disclosure_for(&proof, &compact, &checkpoint, &expected, &[2]).unwrap();
    assert_eq!(verified.citation.doc_commit, doc.doc_commit());
    assert_eq!(verified.disclosure.scope, "membership_only");
    assert_eq!(verified.disclosure.chunks.len(), 1);
    assert_eq!(verified.disclosure.chunks[0].index, 2);
    assert_eq!(verified.disclosure.chunks[0].byte_length, 1);
    assert!(
        verify_evidence_disclosure_for(&proof, &compact, &checkpoint, &expected, &[0, 2],).is_err()
    );
    assert!(disclosure_from_view(&view, &[1], &doc.doc_commit()).is_err());
    let envelope_only = journal.inclusion_proof(VId(101), false).unwrap().unwrap();
    assert_eq!(
        verify_evidence_disclosure_for(&envelope_only, &compact, &checkpoint, &expected, &[2],),
        Err(EvidenceError::RecordRequired)
    );
    let other = document(8194);
    let other_view = RedactedView::derive(&other, 7, &[(4096, 4096)]);
    let other_compact = disclosure_from_view(&other_view, &[2], &other.doc_commit()).unwrap();
    assert!(
        verify_evidence_disclosure_for(&proof, &other_compact, &checkpoint, &expected, &[2],)
            .is_err()
    );
}
