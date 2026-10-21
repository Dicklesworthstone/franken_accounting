//! Real Notary encoders/signers exercise recorded-boundary continuity.
//! These fixtures are constructed below posting admission. A genuine signature
//! does not make a deliberately false known-at statement semantically correct.

use fa_model::{
    Entry, EntryClass, EntryOrigin, EntryPayload, Erasable, Id128, LegPayload, Oid, SealKey,
};
use fa_money::{Amount, Side, UnitId};
use fa_notary::checkpoint::{CheckpointBody, TransparencyCheckpoint};
use fa_notary::{Journal, ScopeIndex, SigningKey};
use fa_time::DateDay;
use fa_verify::checkpoint::witness::recorded::{
    RecordedAdvanceError, verify_recorded_checkpoint_advance,
};
use fa_verify::checkpoint::witness::{
    AdvanceStatus, RecipientWitnessPolicy, WitnessedCheckpoint, verify_checkpoint_advance,
    verify_witnessed_checkpoint,
};
use fgdb_types::{CommitSeq, VId};

const BOOK: Id128 = Id128([0x42; 16]);

fn entry(key: &str, day: i32) -> Entry {
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
            &"private recorded-history fixture".to_string(),
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

fn journal(through: u64, rows: &[(u64, i32)]) -> Journal {
    Journal::from_records(
        BOOK,
        CommitSeq(through),
        rows.iter()
            .enumerate()
            .map(|(index, (sequence, day))| {
                (
                    VId(100 + index as u128),
                    entry(&format!("record-{index}"), *day),
                    CommitSeq(*sequence),
                )
            })
            .collect(),
    )
    .unwrap()
}

fn policy() -> RecipientWitnessPolicy {
    RecipientWitnessPolicy::new(
        BOOK.0,
        [0; 16],
        [0x55; 32],
        SigningKey::from_seed(&[0x11; 32]).public_key(),
        &[
            SigningKey::from_seed(&[0x12; 32]).public_key(),
            SigningKey::from_seed(&[0x13; 32]).public_key(),
        ],
        2,
    )
    .unwrap()
}

fn signed(journal: &Journal, witnessed: bool) -> Vec<u8> {
    let publisher = SigningKey::from_seed(&[0x11; 32]);
    let a = SigningKey::from_seed(&[0x12; 32]);
    let b = SigningKey::from_seed(&[0x13; 32]);
    let body = CheckpointBody {
        statement: journal.statement(),
        state_oid: Oid([0x22; 32]),
        scope_index_root: ScopeIndex::of(journal).root(),
        substrate_chain_commitment: [0x44; 32],
        witness_policy_oid: Some(Oid([0x55; 32])),
        time_evidence_oid: None,
    };
    let signed = if witnessed {
        TransparencyCheckpoint::sign(body, &[&publisher, &a, &b])
    } else {
        TransparencyCheckpoint::sign(body, &[&publisher])
    };
    signed.unwrap().canonical_bytes().unwrap()
}

fn retained(journal: &Journal) -> WitnessedCheckpoint {
    verify_witnessed_checkpoint(&signed(journal, true), &policy()).unwrap()
}

fn complete(journal: &Journal) -> Vec<u8> {
    journal.prefix_proof_with_records().unwrap().unwrap()
}

#[test]
fn valid_recorded_extension_keeps_late_effective_entries_and_releases_no_payloads() {
    let old = journal(10, &[(7, 100)]);
    let new = journal(20, &[(7, 100), (11, i32::MIN), (11, -5)]);
    let pin = retained(&old);
    let before = pin.clone();
    let proof = new.consistency_proof(&old.statement()).unwrap().unwrap();
    let result =
        verify_recorded_checkpoint_advance(&pin, &signed(&new, true), &proof, &complete(&new))
            .unwrap();
    assert_eq!(pin, before);
    assert_eq!(result.status(), AdvanceStatus::Advanced);
    assert_eq!(result.appended_records(), 2);
    assert_eq!(result.previous(), &pin.signed_checkpoint().checkpoint);
    assert_eq!(
        result
            .checkpoint()
            .signed_checkpoint()
            .checkpoint
            .through_seq,
        20
    );
    assert_eq!(
        result.clone().into_checkpoint(),
        result.checkpoint().clone()
    );
    assert!(!format!("{result:?}").contains("private recorded-history fixture"));
}

#[test]
fn genuine_consistent_signed_extensions_cannot_insert_at_or_before_a_retained_sequence() {
    for (old_sequence, inserted_sequence) in [(7, 7), (10, 7), (10, 8), (10, 10)] {
        let old = journal(old_sequence, &[(7, 100)]);
        let new = journal(20, &[(7, 100), (inserted_sequence, 200)]);
        let pin = retained(&old);
        let before = pin.clone();
        let candidate = signed(&new, true);
        let proof = new.consistency_proof(&old.statement()).unwrap().unwrap();

        // This is genuinely a cryptographic tree extension. The original API
        // deliberately makes no assertion about the new leaves' recorded time.
        assert!(verify_checkpoint_advance(&pin, &candidate, &proof).is_ok());
        assert_eq!(
            verify_recorded_checkpoint_advance(&pin, &candidate, &proof, &complete(&new)),
            Err(RecordedAdvanceError::RecordedBoundary {
                retained_leaf_count: 1,
                reconstructed_leaf_count: 2,
            })
        );
        assert_eq!(pin, before);
    }
}

#[test]
fn an_empty_tree_at_a_nonzero_horizon_still_excludes_earlier_insertions() {
    let old = journal(10, &[]);
    let pin = retained(&old);
    for (sequence, succeeds) in [(5, false), (10, false), (11, true)] {
        let new = journal(20, &[(sequence, -100)]);
        let candidate = signed(&new, true);
        let proof = new.consistency_proof(&old.statement()).unwrap().unwrap();
        assert!(verify_checkpoint_advance(&pin, &candidate, &proof).is_ok());
        let result = verify_recorded_checkpoint_advance(&pin, &candidate, &proof, &complete(&new));
        if succeeds {
            assert_eq!(result.unwrap().appended_records(), 1);
        } else {
            assert_eq!(
                result,
                Err(RecordedAdvanceError::RecordedBoundary {
                    retained_leaf_count: 0,
                    reconstructed_leaf_count: 1,
                })
            );
        }
    }
}

#[test]
fn unchanged_or_later_empty_advancements_still_need_complete_witnesses() {
    for rows in [vec![], vec![(7, 100)]] {
        let old = journal(10, &rows);
        let pin = retained(&old);
        for (through, status) in [
            (10, AdvanceStatus::Unchanged),
            (20, AdvanceStatus::Advanced),
        ] {
            let new = journal(through, &rows);
            let candidate = signed(&new, true);
            let proof = new.consistency_proof(&old.statement()).unwrap().unwrap();
            let result =
                verify_recorded_checkpoint_advance(&pin, &candidate, &proof, &complete(&new))
                    .unwrap();
            assert_eq!(result.status(), status);
            assert_eq!(result.appended_records(), 0);
            assert!(matches!(
                verify_recorded_checkpoint_advance(&pin, &candidate, &proof, &[]),
                Err(RecordedAdvanceError::Prefix(_))
            ));
        }
    }
}

#[test]
fn a_signed_retained_boundary_cannot_hide_its_own_future_record() {
    let genuine = journal(11, &[(11, 100)]);
    let mut false_old = genuine.clone();
    false_old.through_seq = CommitSeq(10); // deliberate false signed statement
    let pin = retained(&false_old);
    let new = journal(20, &[(11, 100)]);
    let proof = new
        .consistency_proof(&false_old.statement())
        .unwrap()
        .unwrap();
    let candidate = signed(&new, true);
    assert!(verify_checkpoint_advance(&pin, &candidate, &proof).is_ok());
    assert_eq!(
        verify_recorded_checkpoint_advance(&pin, &candidate, &proof, &complete(&new)),
        Err(RecordedAdvanceError::RecordedBoundary {
            retained_leaf_count: 1,
            reconstructed_leaf_count: 0,
        })
    );
}

#[test]
fn envelope_only_corrupted_truncated_and_foreign_prefixes_never_satisfy_the_stronger_api() {
    let old = journal(10, &[(7, 100)]);
    let new = journal(20, &[(7, 100), (11, -10)]);
    let pin = retained(&old);
    let candidate = signed(&new, true);
    let proof = new.consistency_proof(&old.statement()).unwrap().unwrap();
    let good = complete(&new);
    assert!(verify_recorded_checkpoint_advance(&pin, &candidate, &proof, &good).is_ok());
    let mut corrupted = good.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    let mut trailing = good.clone();
    trailing.push(0);
    let foreign = journal(21, &[(7, 100), (11, -10)]);
    for invalid in [
        new.prefix_proof().unwrap(),
        corrupted,
        good[..good.len() - 1].to_vec(),
        trailing,
        complete(&foreign),
    ] {
        assert!(matches!(
            verify_recorded_checkpoint_advance(&pin, &candidate, &proof, &invalid),
            Err(RecordedAdvanceError::Prefix(_))
        ));
    }
}

#[test]
fn quorum_and_consistency_obligations_cannot_be_replaced_by_a_complete_prefix() {
    let old = journal(10, &[(7, 100)]);
    let new = journal(20, &[(7, 100), (11, -10)]);
    let pin = retained(&old);
    let proof = new.consistency_proof(&old.statement()).unwrap().unwrap();
    let prefix = complete(&new);
    let candidate = signed(&new, true);
    assert!(verify_recorded_checkpoint_advance(&pin, &candidate, &proof, &prefix).is_ok());
    assert!(matches!(
        verify_recorded_checkpoint_advance(&pin, &signed(&new, false), &proof, &prefix),
        Err(RecordedAdvanceError::Advance(_))
    ));
    assert!(matches!(
        verify_recorded_checkpoint_advance(&pin, &candidate, &[], &prefix),
        Err(RecordedAdvanceError::Advance(_))
    ));
    let replay = old.consistency_proof(&old.statement()).unwrap().unwrap();
    assert!(matches!(
        verify_recorded_checkpoint_advance(&pin, &candidate, &replay, &prefix),
        Err(RecordedAdvanceError::Advance(_))
    ));
}

#[test]
fn native_balance_witnesses_retain_their_full_fold_obligation() {
    let old = journal(10, &[(7, 100)]);
    let new = journal(20, &[(7, 100), (11, -10)]);
    let pin = retained(&old);
    let candidate = signed(&new, true);
    let proof = new.consistency_proof(&old.statement()).unwrap().unwrap();
    let mut balance = new
        .balance_proof_complete(VId(10), 1, None, &[])
        .unwrap()
        .unwrap();
    assert!(verify_recorded_checkpoint_advance(&pin, &candidate, &proof, &balance).is_ok());
    let format_length = u32::from_le_bytes(balance[..4].try_into().unwrap()) as usize;
    let debit = 4 + format_length + fa_verify::Checkpoint::ENCODED_LEN + 16 + 4 + 1;
    balance[debit] ^= 1;
    assert!(matches!(
        verify_recorded_checkpoint_advance(&pin, &candidate, &proof, &balance),
        Err(RecordedAdvanceError::Prefix(_))
    ));
}
