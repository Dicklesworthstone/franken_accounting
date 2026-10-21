//! Actual Notary assembly, checkpoint signatures and detached receipts checked
//! under an independent recipient quorum. No storage/authorization claim.

use fa_model::{Id128, Oid};
use fa_notary::bundle::{BundleRequest, BundleScope, ProductionReceipt, ReceiptBody, assemble};
use fa_notary::checkpoint::{CheckpointBody, TransparencyCheckpoint};
use fa_notary::{Journal, ScopeIndex, SigningKey, StoredCheckpoint};
use fa_verify::checkpoint::witness::bundle::{BundleExpectation, verify_witnessed_bundle_for};
use fa_verify::checkpoint::witness::{RecipientWitnessPolicy, verify_witnessed_checkpoint};
use fgdb_types::{CommitSeq, VId};
use std::collections::BTreeMap;

fn fixture() -> (
    Journal,
    StoredCheckpoint,
    SigningKey,
    SigningKey,
    SigningKey,
) {
    let publisher = SigningKey::from_seed(&[0x11; 32]);
    let a = SigningKey::from_seed(&[0x12; 32]);
    let b = SigningKey::from_seed(&[0x13; 32]);
    let journal = Journal::from_records(Id128([0x11; 16]), CommitSeq(0), vec![]).unwrap();
    let checkpoint = TransparencyCheckpoint::sign(
        CheckpointBody {
            statement: journal.statement(),
            state_oid: Oid([0x22; 32]),
            scope_index_root: ScopeIndex::of(&journal).root(),
            substrate_chain_commitment: [0x44; 32],
            witness_policy_oid: Some(Oid([0x55; 32])),
            time_evidence_oid: None,
        },
        &[&publisher, &a, &b],
    )
    .unwrap();
    let stored = StoredCheckpoint {
        oid: checkpoint.oid().unwrap(),
        vid: VId(1),
        bytes: checkpoint.canonical_bytes().unwrap(),
        checkpoint,
    };
    (journal, stored, publisher, a, b)
}

#[test]
fn real_publisher_receipt_and_quorum_anchor_authenticate_the_produced_bundle() {
    let (journal, stored, publisher, a, b) = fixture();
    let policy = RecipientWitnessPolicy::new(
        [0x11; 16],
        [0; 16],
        [0x55; 32],
        publisher.public_key(),
        &[a.public_key(), b.public_key()],
        2,
    )
    .unwrap();
    let pin = verify_witnessed_checkpoint(&stored.bytes, &policy).unwrap();
    let bundle = assemble(
        &journal,
        &stored,
        &BundleRequest {
            scope: BundleScope::Prefix,
            balances: vec![],
            inline_documents: true,
        },
        &BTreeMap::new(),
    )
    .unwrap()
    .unwrap();
    let receipt = ProductionReceipt::sign(
        ReceiptBody {
            bundle_digest: bundle.digest,
            producer_principal: VId(7),
            produced_at_seq: CommitSeq(1),
            capability_commitment: [0x66; 32],
            time_evidence_oid: None,
        },
        &publisher,
    )
    .unwrap()
    .canonical_bytes()
    .unwrap();
    let expected = BundleExpectation {
        scope: fa_verify::BundleScope::Prefix,
        inline_documents: true,
        publisher_receipt: true,
    };
    let report =
        verify_witnessed_bundle_for(&bundle.bytes, &pin, &expected, Some(&receipt)).unwrap();
    assert!(report.verified(), "{:?}", report.checks);
    assert_eq!(report.digest, bundle.digest);
    assert_eq!(report.receipt.unwrap().producer_principal, 7);
}

#[test]
fn a_witness_can_not_gain_production_receipt_authority_from_its_checkpoint_role() {
    let (journal, stored, publisher, a, b) = fixture();
    let policy = RecipientWitnessPolicy::new(
        [0x11; 16],
        [0; 16],
        [0x55; 32],
        publisher.public_key(),
        &[a.public_key(), b.public_key()],
        2,
    )
    .unwrap();
    let pin = verify_witnessed_checkpoint(&stored.bytes, &policy).unwrap();
    let bundle = assemble(
        &journal,
        &stored,
        &BundleRequest {
            scope: BundleScope::Prefix,
            balances: vec![],
            inline_documents: true,
        },
        &BTreeMap::new(),
    )
    .unwrap()
    .unwrap();
    let receipt = ProductionReceipt::sign(
        ReceiptBody {
            bundle_digest: bundle.digest,
            producer_principal: VId(7),
            produced_at_seq: CommitSeq(1),
            capability_commitment: [0x66; 32],
            time_evidence_oid: None,
        },
        &a,
    )
    .unwrap()
    .canonical_bytes()
    .unwrap();
    // A broad trusted-key list admits this genuine witness-signed receipt.
    assert!(
        fa_verify::verify_bundle(
            &bundle.bytes,
            &[publisher.public_key(), a.public_key(), b.public_key()],
            Some(&receipt)
        )
        .unwrap()
        .verified()
    );
    let expected = BundleExpectation {
        scope: fa_verify::BundleScope::Prefix,
        inline_documents: true,
        publisher_receipt: true,
    };
    let report =
        verify_witnessed_bundle_for(&bundle.bytes, &pin, &expected, Some(&receipt)).unwrap();
    assert!(!report.verified());
    assert!(report.receipt.is_none());
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.check == "production_receipt"
                && matches!(check.grade, fa_verify::Grade::Fail(_)))
    );
}

#[test]
fn two_genuine_producer_scopes_are_not_interchangeable() {
    let (journal, stored, publisher, a, b) = fixture();
    let policy = RecipientWitnessPolicy::new(
        [0x11; 16],
        [0; 16],
        [0x55; 32],
        publisher.public_key(),
        &[a.public_key(), b.public_key()],
        2,
    )
    .unwrap();
    let pin = verify_witnessed_checkpoint(&stored.bytes, &policy).unwrap();
    let expected = BundleExpectation {
        scope: fa_verify::BundleScope::Prefix,
        inline_documents: true,
        publisher_receipt: false,
    };
    for (scope, accepted) in [
        (BundleScope::Prefix, true),
        (BundleScope::Entries(vec![]), false),
    ] {
        let bundle = assemble(
            &journal,
            &stored,
            &BundleRequest {
                scope,
                balances: vec![],
                inline_documents: true,
            },
            &BTreeMap::new(),
        )
        .unwrap()
        .unwrap();
        assert!(
            fa_verify::verify_bundle(&bundle.bytes, &[publisher.public_key()], None)
                .unwrap()
                .verified()
        );
        let report = verify_witnessed_bundle_for(&bundle.bytes, &pin, &expected, None).unwrap();
        assert_eq!(report.verified(), accepted);
    }
}

#[test]
fn requested_inline_documents_cannot_be_replaced_by_valid_commitment_only_stubs() {
    use fa_journal::{Document, DocumentRead};
    use fa_model::{
        EntryClass, EntryOrigin, EntryPayload, Erasable, EvidenceRef, LegPayload, SealKey,
    };
    use fa_money::{Amount, Side, UnitId};
    use fa_time::DateDay;

    let (_, _, publisher, a, b) = fixture();
    let book = Id128([0x11; 16]);
    let doc = Document {
        book_id: book,
        kind: 1,
        mime: "text/plain".into(),
        grade: 2,
        retrieved_by: VId(7),
        bytes: b"private original invoice".to_vec(),
    };
    let legs = vec![
        LegPayload::simple(Side::Debit, VId(10), Amount::new(UnitId(1), 123)),
        LegPayload::simple(Side::Credit, VId(20), Amount::new(UnitId(1), 123)),
    ];
    let proposal = EntryPayload {
        schema_minor: 1,
        book_id: book,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: DateDay(20_527),
        document_date: None,
        description: Erasable::seal(
            &"invoice".to_string(),
            None,
            &SealKey([3; 32]),
            [1; 32],
            [2; 24],
        ),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: b"witnessed-bundle".to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([4; 32]),
            intent_kind: 1,
        },
        principal_ref: VId(7),
        session_ref: None,
        evidence: vec![EvidenceRef {
            document_oid: doc.oid(),
            doc_commit: doc.doc_commit(),
            role: 3,
        }],
        supersession: vec![],
        pending: None,
        external_ids: vec![],
        extensions: vec![],
        tags: vec![],
    };
    let record = proposal.seal(vec![], None).unwrap();
    let journal =
        Journal::from_records(book, CommitSeq(7), vec![(VId(100), record, CommitSeq(7))]).unwrap();
    let checkpoint = TransparencyCheckpoint::sign(
        CheckpointBody {
            statement: journal.statement(),
            state_oid: Oid([2; 32]),
            scope_index_root: ScopeIndex::of(&journal).root(),
            substrate_chain_commitment: [4; 32],
            witness_policy_oid: Some(Oid([0x55; 32])),
            time_evidence_oid: None,
        },
        &[&publisher, &a, &b],
    )
    .unwrap();
    let stored = StoredCheckpoint {
        oid: checkpoint.oid().unwrap(),
        vid: VId(1),
        bytes: checkpoint.canonical_bytes().unwrap(),
        checkpoint,
    };
    let policy = RecipientWitnessPolicy::new(
        book.0,
        [0; 16],
        [0x55; 32],
        publisher.public_key(),
        &[a.public_key(), b.public_key()],
        2,
    )
    .unwrap();
    let pin = verify_witnessed_checkpoint(&stored.bytes, &policy).unwrap();
    let mut documents = BTreeMap::new();
    documents.insert(doc.oid(), DocumentRead::Full(doc));
    for inline in [false, true] {
        let bundle = assemble(
            &journal,
            &stored,
            &BundleRequest {
                scope: BundleScope::Prefix,
                balances: vec![],
                inline_documents: inline,
            },
            &documents,
        )
        .unwrap()
        .unwrap();
        assert!(
            fa_verify::verify_bundle(&bundle.bytes, &[publisher.public_key()], None)
                .unwrap()
                .verified()
        );
        let mut expected = BundleExpectation {
            scope: fa_verify::BundleScope::Prefix,
            inline_documents: true,
            publisher_receipt: false,
        };
        let report = verify_witnessed_bundle_for(&bundle.bytes, &pin, &expected, None).unwrap();
        assert_eq!(report.verified(), inline, "{:?}", report.checks);
        assert_eq!(report.summary.documents, 1);
        assert_eq!(report.summary.inline, u64::from(inline));
        expected.inline_documents = false;
        assert!(
            verify_witnessed_bundle_for(&bundle.bytes, &pin, &expected, None)
                .unwrap()
                .verified()
        );
    }
}
