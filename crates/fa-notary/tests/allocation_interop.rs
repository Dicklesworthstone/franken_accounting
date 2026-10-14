//! Producer codecs/proofs against the independent offline allocation checker.
//!
//! These synthetic records exercise actual producer APIs, not a live book's
//! authority or account admission. The fixed test checkpoint is trusted only
//! for this fixture; verification never learns its question from a proof.

use fa_journal::allocation::AllocationPosting;
use fa_model::{Entry, EntryClass, EntryOrigin, EntryPayload, Erasable, Id128, Oid, SealKey};
use fa_money::allocation::{AllocationMethod, AllocationRequest, AllocationTarget};
use fa_money::{Amount, RoundingLaw, Side, UnitId};
use fa_notary::Journal;
use fa_time::DateDay;
use fa_verify::evidence::inventory::allocation::{
    AllocationBasis, AllocationError, VerifiedAllocation, verify_allocation_for,
};
use fa_verify::{Checkpoint, RecordCheck};
use fgdb_types::{CommitSeq, VId};

const BOOK: Id128 = Id128([0x6a; 16]);
const ENTRY: VId = VId(0x1234);

fn posting(total: i128, method: AllocationMethod, weights: &[u128]) -> AllocationPosting {
    AllocationPosting {
        source: VId(10),
        source_side: Side::Credit,
        dimensions: vec![(1, VId(55)), (9, VId(99))],
        request: AllocationRequest {
            total: Amount::new(UnitId(7), total),
            method,
            targets: weights
                .iter()
                .enumerate()
                .map(|(index, basis)| AllocationTarget {
                    id: 20 + index as u128,
                    basis: *basis,
                })
                .collect(),
        },
    }
}

fn template(posting: &AllocationPosting) -> EntryPayload {
    EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: BOOK,
        branch_id: Id128::TRUNK,
        class: EntryClass::ALLOCATION,
        effective_date: DateDay(20_527),
        document_date: None,
        description: Erasable::seal(
            &"allocation interoperability".to_string(),
            None,
            &SealKey([0x33; 32]),
            [1; 32],
            [2; 24],
        ),
        effective_period: None,
        unit_totals: Vec::new(),
        legs: Vec::new(),
        control: None,
        base_totals: None,
        idempotency_key: b"allocation-interop".to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([4; 32]),
            intent_kind: 1,
        },
        principal_ref: VId(7),
        session_ref: None,
        evidence: vec![posting.driver_evidence(BOOK).unwrap()],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    }
}

fn proof(entry: Entry) -> (Vec<u8>, Checkpoint, [u8; 32]) {
    let digest = entry.entry_digest;
    let journal =
        Journal::from_records(BOOK, CommitSeq(9), vec![(ENTRY, entry, CommitSeq(7))]).unwrap();
    let statement = journal.statement();
    let checkpoint = Checkpoint {
        book_id: statement.book_id.0,
        branch_id: statement.branch_id.0,
        through_seq: statement.through_seq.0,
        leaf_count: statement.leaf_count,
        root: statement.root,
    };
    (
        journal.inclusion_proof(ENTRY, true).unwrap().unwrap(),
        checkpoint,
        digest,
    )
}

fn compare(posting: &AllocationPosting) -> VerifiedAllocation {
    let bytes = posting.basis_bytes().unwrap();
    let expected = posting.request.execute().unwrap();
    let proposal = posting.proposal(template(posting)).unwrap();
    let (proof, checkpoint, digest) = proof(proposal.seal(Vec::new(), None).unwrap());
    let verified = verify_allocation_for(&proof, &checkpoint, &digest, &bytes).unwrap();
    assert_eq!(
        verified.shares,
        expected
            .shares()
            .iter()
            .map(|share| share.mantissa)
            .collect::<Vec<_>>()
    );
    assert_eq!(verified.basis.source, posting.source.0);
    assert_eq!(
        verified.basis.source_debit,
        posting.source_side == Side::Debit
    );
    assert_eq!(verified.basis.unit, posting.request.total.unit.0);
    assert_eq!(
        verified.basis.dimensions,
        posting
            .dimensions
            .iter()
            .map(|(id, value)| (*id, value.0))
            .collect::<Vec<_>>()
    );
    assert_eq!(verified.law_digest, posting.law_digest());
    assert_eq!(verified.basis_digest, posting.basis_digest().unwrap());
    let citation = posting.driver_evidence(BOOK).unwrap();
    assert_eq!(verified.driver.document_oid, citation.document_oid.0);
    assert_eq!(verified.driver.doc_commit, citation.doc_commit);
    assert_eq!(verified.driver.role, citation.role);
    assert_eq!(verified.inclusion.record, RecordCheck::Recomputed);
    verified
}

#[test]
fn actual_producer_entries_and_proofs_verify_for_all_laws_sides_and_rounding_modes() {
    let mut examples = vec![
        posting(10_000, AllocationMethod::LargestRemainder, &[1; 3]),
        posting(
            7,
            AllocationMethod::LargestRemainder,
            &[u128::MAX, u128::MAX],
        ),
        posting(10, AllocationMethod::Waterfall, &[4, 0, 9]),
        posting(2, AllocationMethod::EqualSplitResidualFirst, &[1; 5]),
        posting(i128::MAX, AllocationMethod::LargestRemainder, &[1; 2]),
    ];
    for rounding in RoundingLaw::ALL {
        for recipient in [20, 21, 22] {
            examples.push(posting(
                1,
                AllocationMethod::ProRataResidualToNamed {
                    rounding,
                    recipient,
                },
                &[1; 3],
            ));
        }
    }
    for mut example in examples {
        for side in [Side::Debit, Side::Credit] {
            example.source_side = side;
            compare(&example);
        }
    }
}

#[test]
fn maximum_driver_crosses_document_chunks_without_losing_dimensions_or_targets() {
    let mut example = posting(
        i128::MAX,
        AllocationMethod::LargestRemainder,
        &vec![u128::MAX; 1024],
    );
    example.dimensions = (0..64).map(|id| (id, VId(u128::from(id) + 55))).collect();
    assert!(example.basis_bytes().unwrap().len() > 4096);
    let verified = compare(&example);
    assert_eq!(verified.basis.targets.len(), 1024);
    assert_eq!(verified.basis.dimensions.len(), 64);
    assert_eq!(verified.shares.iter().sum::<i128>(), i128::MAX);
}

#[test]
fn producer_resealing_does_not_hide_wrong_shares_or_a_removed_driver() {
    let example = posting(10_000, AllocationMethod::LargestRemainder, &[1; 3]);
    let bytes = example.basis_bytes().unwrap();
    let original = example.proposal(template(&example)).unwrap();
    let mut wrong = original.clone();
    wrong.legs[1].amount.mantissa -= 1;
    wrong.legs[2].amount.mantissa += 1;
    wrong.unit_totals = EntryPayload::fold_unit_totals(&wrong.legs).unwrap();
    let (proof_bytes, checkpoint, digest) = proof(wrong.seal(Vec::new(), None).unwrap());
    assert_eq!(
        verify_allocation_for(&proof_bytes, &checkpoint, &digest, &bytes),
        Err(AllocationError::LegMismatch { ordinal: 1 })
    );
    let mut missing = original;
    missing.evidence.clear();
    let (proof_bytes, checkpoint, digest) = proof(missing.seal(Vec::new(), None).unwrap());
    assert_eq!(
        verify_allocation_for(&proof_bytes, &checkpoint, &digest, &bytes),
        Err(AllocationError::DriverMissing)
    );
}

#[test]
fn conserving_arithmetic_that_cannot_be_journaled_is_rejected_by_both_posting_sides() {
    let example = posting(
        i128::MAX,
        AllocationMethod::ProRataResidualToNamed {
            rounding: RoundingLaw::Ceiling,
            recipient: 20,
        },
        &[0, 1, 1],
    );
    let arithmetic = example.request.execute().unwrap();
    assert_eq!(arithmetic.shares()[0].mantissa, -1);
    assert!(example.proposal(template(&example)).is_err());
    let decoded = AllocationBasis::decode(&example.basis_bytes().unwrap()).unwrap();
    assert_eq!(decoded.shares(), Err(AllocationError::Arithmetic));
}
