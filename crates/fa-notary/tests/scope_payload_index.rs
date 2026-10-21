//! Actual producer v3 proofs and signed scope roots through the independent
//! verifier. This is not a posting-admission or export-authorization test.

use fa_model::{
    Entry, EntryClass, EntryOrigin, EntryPayload, Erasable, Id128, LegPayload, Oid, SealKey,
};
use fa_money::{Amount, Side, UnitId};
use fa_notary::checkpoint::{CheckpointBody, TransparencyCheckpoint};
use fa_notary::{Journal, ScopeIndex, SigningKey};
use fa_time::DateDay;
use fa_verify::checkpoint::witness::{
    RecipientWitnessPolicy, WitnessedCheckpoint, verify_witnessed_checkpoint,
};
use fa_verify::scope::payloads::{
    PayloadIndexError, verify_payload_index, verify_scope_with_payload_index,
};
use fa_verify::{IndexDerivation, ScopeClaim};
use fgdb_types::{CommitSeq, VId};

const BOOK: Id128 = Id128([0x42; 16]);

fn record(key: &str, day: i32) -> Entry {
    let legs = vec![
        LegPayload::simple(Side::Debit, VId(10), Amount::new(UnitId(1), 123)),
        LegPayload::simple(Side::Credit, VId(20), Amount::new(UnitId(1), 123)),
    ];
    EntryPayload {
        schema_minor: 1,
        book_id: BOOK,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: DateDay(day),
        document_date: None,
        description: Erasable::seal(
            &"private source".to_string(),
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
        idempotency_key: key.as_bytes().to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([4; 32]),
            intent_kind: 1,
        },
        principal_ref: VId(7),
        session_ref: None,
        evidence: vec![],
        supersession: vec![],
        pending: None,
        external_ids: vec![],
        extensions: vec![],
        tags: vec![],
    }
    .seal(vec![], None)
    .unwrap()
}

fn journal() -> Journal {
    Journal::from_records(
        BOOK,
        CommitSeq(30),
        vec![
            (VId(100), record("earlier", 100), CommitSeq(7)),
            (VId(101), record("late-effective", -10), CommitSeq(30)),
        ],
    )
    .unwrap()
}

fn checkpoint(
    journal: &Journal,
    root: [u8; 32],
) -> (WitnessedCheckpoint, fa_notary::StoredCheckpoint) {
    let publisher = SigningKey::from_seed(&[0x11; 32]);
    let a = SigningKey::from_seed(&[0x12; 32]);
    let b = SigningKey::from_seed(&[0x13; 32]);
    let checkpoint = TransparencyCheckpoint::sign(
        CheckpointBody {
            statement: journal.statement(),
            state_oid: Oid([0x22; 32]),
            scope_index_root: root,
            substrate_chain_commitment: [0x44; 32],
            witness_policy_oid: Some(Oid([0x55; 32])),
            time_evidence_oid: None,
        },
        &[&publisher, &a, &b],
    )
    .unwrap();
    let policy = RecipientWitnessPolicy::new(
        BOOK.0,
        [0; 16],
        [0x55; 32],
        publisher.public_key(),
        &[a.public_key(), b.public_key()],
        2,
    )
    .unwrap();
    let stored = fa_notary::StoredCheckpoint {
        oid: checkpoint.oid().unwrap(),
        vid: VId(1),
        bytes: checkpoint.canonical_bytes().unwrap(),
        checkpoint,
    };
    (
        verify_witnessed_checkpoint(&stored.bytes, &policy).unwrap(),
        stored,
    )
}

fn anchor(journal: &Journal, root: [u8; 32]) -> WitnessedCheckpoint {
    checkpoint(journal, root).0
}

#[test]
fn native_v3_export_reconstructs_the_producer_index_and_authenticates_empty_boundaries() {
    let journal = journal();
    let index = ScopeIndex::of(&journal);
    let pin = anchor(&journal, index.root());
    let complete = journal
        .balance_proof_complete(VId(10), 1, None, &[])
        .unwrap()
        .unwrap();
    let derived = verify_payload_index(&complete, pin.signed_checkpoint()).unwrap();
    assert_eq!(derived.tuple_count(), index.tuples().len());
    assert_eq!(*derived.root(), index.root());
    for (account, from, to, expected) in [
        (10, -10, 100, 2),
        (20, -10, -10, 1),
        (99, i32::MIN, i32::MAX, 0),
        (10, 0, 99, 0),
    ] {
        let proof = index.proof(&journal, account, from, to).unwrap();
        let report = verify_scope_with_payload_index(
            &proof,
            pin.signed_checkpoint(),
            &ScopeClaim { account, from, to },
            &derived,
        )
        .unwrap();
        assert_eq!(report.index_derivation, IndexDerivation::Recomputed);
        assert_eq!(report.leaves.len(), expected);
    }
    assert!(
        verify_payload_index(&journal.prefix_proof().unwrap(), pin.signed_checkpoint()).is_err()
    );
}

#[test]
fn genuine_publisher_and_witness_signatures_cannot_validate_an_omitted_account_index() {
    let journal = journal();
    let mut omitted = journal.clone();
    for leaf in &mut omitted.leaves {
        leaf.envelope
            .account_vids
            .retain(|account| *account != VId(20));
    }
    // Signing an inconsistent index is possible; the verifier must detect it.
    let false_root = ScopeIndex::of(&omitted).root();
    assert_ne!(false_root, ScopeIndex::of(&journal).root());
    let pin = anchor(&journal, false_root);
    let complete = journal
        .balance_proof_complete(VId(10), 1, None, &[])
        .unwrap()
        .unwrap();
    assert_eq!(
        verify_payload_index(&complete, pin.signed_checkpoint()),
        Err(PayloadIndexError::Root)
    );
}

#[test]
fn using_a_native_balance_as_index_evidence_does_not_skip_its_fold_verification() {
    let journal = journal();
    let pin = anchor(&journal, ScopeIndex::of(&journal).root());
    let mut complete = journal
        .balance_proof_complete(VId(10), 1, None, &[])
        .unwrap()
        .unwrap();
    assert!(verify_payload_index(&complete, pin.signed_checkpoint()).is_ok());
    let format_len = u32::from_le_bytes(complete[..4].try_into().unwrap()) as usize;
    // bytes(format), checkpoint, account, unit, absent-cutoff tag, debits.
    let debit = 4 + format_len + fa_verify::Checkpoint::ENCODED_LEN + 16 + 4 + 1;
    complete[debit] ^= 1;
    assert!(matches!(
        verify_payload_index(&complete, pin.signed_checkpoint()),
        Err(PayloadIndexError::Proof(_))
    ));
}

use fa_notary::bundle::{BalanceRequest, BundleRequest, BundleScope, assemble};
use fa_notary::scope::ScopeRequest;
use fa_verify::checkpoint::witness::bundle::{
    BundleExpectation, MAX_WITNESSED_BUNDLE_BYTES, WitnessBundleError,
};
use fa_verify::scope::payloads::bundle::verify_witnessed_indexed_bundle_for;

fn expected() -> BundleExpectation {
    BundleExpectation {
        scope: fa_verify::BundleScope::Account(ScopeClaim {
            account: 10,
            from: 0,
            to: 100,
        }),
        inline_documents: true,
        publisher_receipt: false,
    }
}

fn bundle(
    journal: &Journal,
    stored: &fa_notary::StoredCheckpoint,
    balances: Vec<BalanceRequest>,
) -> Vec<u8> {
    assemble(
        journal,
        stored,
        &BundleRequest {
            scope: BundleScope::Index(ScopeRequest::Account {
                account: VId(10),
                from: 0,
                to: 100,
            }),
            balances,
            inline_documents: true,
        },
        &std::collections::BTreeMap::new(),
    )
    .unwrap()
    .unwrap()
    .bytes
}

#[test]
fn produced_account_bundle_retains_range_checks_and_replaces_only_the_signed_index_premise() {
    let journal = journal();
    let (pin, stored) = checkpoint(&journal, ScopeIndex::of(&journal).root());
    let prefix = journal
        .balance_proof_complete(VId(10), 1, None, &[])
        .unwrap()
        .unwrap();
    let index = verify_payload_index(&prefix, pin.signed_checkpoint()).unwrap();
    let retained = index.clone();
    let report = verify_witnessed_indexed_bundle_for(
        &bundle(&journal, &stored, vec![]),
        &pin,
        &expected(),
        None,
        &index,
        Some(&[]),
    )
    .unwrap();
    assert!(report.verified(), "{:?}", report.checks);
    assert_eq!(report.summary.entries, 1); // late-effective excluded record still checked
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.check == "payload_scope_index_derivation"
                && matches!(check.grade, fa_verify::Grade::Pass))
    );
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.check == "completeness"
                && check.subject.contains("independently payload-derived"))
    );
    assert_eq!(index, retained);
}

#[test]
fn independently_derived_index_never_rescues_wrong_scope_missing_receipt_or_balance_requests() {
    let journal = journal();
    let (pin, stored) = checkpoint(&journal, ScopeIndex::of(&journal).root());
    let prefix = journal
        .balance_proof_complete(VId(10), 1, None, &[])
        .unwrap()
        .unwrap();
    let index = verify_payload_index(&prefix, pin.signed_checkpoint()).unwrap();
    let bytes = bundle(&journal, &stored, vec![]);
    {
        let mut request = expected();
        request.publisher_receipt = true;
        let report =
            verify_witnessed_indexed_bundle_for(&bytes, &pin, &request, None, &index, None)
                .unwrap();
        assert!(!report.verified());
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.check == "payload_scope_index_derivation"
                    && matches!(check.grade, fa_verify::Grade::Unrun(_)))
        );
        request.publisher_receipt = false;
        request.scope = fa_verify::BundleScope::Account(ScopeClaim {
            account: 20,
            from: 0,
            to: 100,
        });
        assert!(
            !verify_witnessed_indexed_bundle_for(&bytes, &pin, &request, None, &index, None)
                .unwrap()
                .verified()
        );
    }
    let wanted = [fa_verify::BalanceExpectation {
        scope: fa_verify::BalanceScope {
            account: 10,
            unit: 1,
            effective_through: None,
        },
        amounts: None,
    }];
    assert!(
        !verify_witnessed_indexed_bundle_for(
            &bytes,
            &pin,
            &expected(),
            None,
            &index,
            Some(&wanted)
        )
        .unwrap()
        .verified()
    );
}

#[test]
fn index_reuse_cannot_cross_known_at_coordinates_or_bypass_aggregate_input_limits() {
    let journal = journal();
    let (pin, _) = checkpoint(&journal, ScopeIndex::of(&journal).root());
    let prefix = journal
        .balance_proof_complete(VId(10), 1, None, &[])
        .unwrap()
        .unwrap();
    let index = verify_payload_index(&prefix, pin.signed_checkpoint()).unwrap();
    let mut later = journal.clone();
    later.through_seq = CommitSeq(31);
    let later_pin = anchor(&later, ScopeIndex::of(&later).root());
    let later_prefix = later
        .balance_proof_complete(VId(10), 1, None, &[])
        .unwrap()
        .unwrap();
    let later_index = verify_payload_index(&later_prefix, later_pin.signed_checkpoint()).unwrap();
    assert!(matches!(
        verify_witnessed_indexed_bundle_for(b"bad", &pin, &expected(), None, &later_index, None),
        Err(WitnessBundleError::Request(_))
    ));
    let oversized_total = vec![0; MAX_WITNESSED_BUNDLE_BYTES];
    assert!(matches!(
        verify_witnessed_indexed_bundle_for(
            &oversized_total,
            &pin,
            &expected(),
            None,
            &index,
            None
        ),
        Err(WitnessBundleError::InputLimit(_))
    ));
    let mut wrong_scope = expected();
    wrong_scope.scope = fa_verify::BundleScope::Prefix;
    assert!(matches!(
        verify_witnessed_indexed_bundle_for(b"bad", &pin, &wrong_scope, None, &index, None),
        Err(WitnessBundleError::Request(_))
    ));
}

#[test]
fn derived_index_and_exact_nonzero_stock_amounts_are_independent_obligations() {
    let journal = journal();
    let (pin, stored) = checkpoint(&journal, ScopeIndex::of(&journal).root());
    let prefix = journal
        .balance_proof_complete(VId(10), 1, None, &[])
        .unwrap()
        .unwrap();
    let index = verify_payload_index(&prefix, pin.signed_checkpoint()).unwrap();
    let bytes = bundle(
        &journal,
        &stored,
        vec![BalanceRequest {
            account: VId(10),
            unit: 1,
            effective_through: None,
        }],
    );
    let mut wanted = [fa_verify::BalanceExpectation {
        scope: fa_verify::BalanceScope {
            account: 10,
            unit: 1,
            effective_through: None,
        },
        amounts: Some(fa_verify::BalanceAmounts {
            debits: 246,
            credits: 0,
        }),
    }];
    assert!(
        verify_witnessed_indexed_bundle_for(&bytes, &pin, &expected(), None, &index, Some(&wanted))
            .unwrap()
            .verified()
    );
    wanted[0].amounts = Some(fa_verify::BalanceAmounts {
        debits: 247,
        credits: 1,
    });
    let report =
        verify_witnessed_indexed_bundle_for(&bytes, &pin, &expected(), None, &index, Some(&wanted))
            .unwrap();
    assert!(!report.verified());
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.check == "requested_balance_amounts"
                && matches!(check.grade, fa_verify::Grade::Fail(_)))
    );
}
