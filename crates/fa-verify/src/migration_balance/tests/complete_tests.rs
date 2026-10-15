//! Adversarial scope-derivation vectors (fa-n6fh / fa-fqi).
//!
//! Checkpoints below deliberately commit the producer's forged envelopes.
//! Rejecting a stale root would not test this attack. These independent wire
//! fixtures test the offline proof contract, not kernel admission or economics.

use super::*;
use crate::balance::CLASS_PENDING;
use crate::envelope::RecordError;

fn complete(
    records: &[Record],
    bodies: &[(u64, Vec<u8>)],
    debits: i128,
    through: Option<i32>,
) -> (Vec<u8>, Checkpoint) {
    proof_format(records, bodies, debits, through, None, BALANCE_FORMAT_V3)
}

fn reseal(record: &mut Record) {
    let end = record.payload.len();
    let proposal = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&record.payload[..record.len]]);
    let digest = hash_parts(
        ENTRY_DIGEST_DOMAIN,
        &[&proposal, &record.payload[record.len..end - 64]],
    );
    record.payload[end - 64..end - 32].copy_from_slice(&proposal);
    record.payload[end - 32..].copy_from_slice(&digest);
    record.envelope = envelope_of_entry(
        &record.payload,
        record.len,
        record.envelope.commit_seq,
        record.envelope.within_commit_ordinal,
    )
    .unwrap();
}

#[test]
fn committed_selector_forgery_is_rejected_even_when_the_root_is_trusted() {
    // Eight deterministic histories, with independent honest controls. The
    // forged zero balances were formerly accepted as `recomputation`.
    for seed in 0..8 {
        let day = 100 + seed;
        let honest = [record(Kind::Ordinary, 1, day)];
        let (bytes, anchor) = complete(&honest, &[], 5000, Some(day));
        let report = crate::verify_balance(&bytes, &anchor).unwrap();
        assert_eq!(report.scope, SCOPE_RECOMPUTATION);
        assert_eq!(report.claim.debits, 5000);

        for selector in 0..5 {
            let mut forged = [record(Kind::Ordinary, 1, day)];
            match selector {
                0 => forged[0].envelope.class = CLASS_PENDING,
                1 => forged[0].envelope.account_vids = vec![20],
                2 => forged[0].envelope.unit_ids = vec![2],
                3 => forged[0].envelope.effective_day = Some(day + 1),
                _ => forged[0].envelope.effective_day = None,
            }
            let context = format!("seed={seed}, selector={selector}");
            // Legacy wire remains readable, but cannot upgrade an unverified
            // indexing premise to an independently recomputed balance.
            let (legacy, anchor) = proof(&forged, &[], 0, Some(day), None);
            let weak = crate::verify_balance(&legacy, &anchor).unwrap();
            assert_eq!(weak.scope, SCOPE_MEMBERSHIP_ONLY, "{context}");

            let (full, anchor) = complete(&forged, &[], 0, Some(day));
            assert_eq!(
                crate::verify_balance(&full, &anchor),
                Err(VerifyError::Record(RecordError::Envelope)),
                "{context}"
            );
            let (omitted, anchor) = proof_format(
                &forged, &[], 0, Some(day), Some(0), BALANCE_FORMAT_V3,
            );
            assert_eq!(
                crate::verify_balance(&omitted, &anchor),
                Err(VerifyError::RecordSet { index: 0 }),
                "missing payload: {context}"
            );
        }
    }
}

#[test]
fn a_finalize_control_cannot_be_hidden_by_a_committed_noncontrol_tag() {
    let body = body(0, false);
    let witnesses = [(0, body.clone())];
    let mut records = history(&body, 100, Some(1));
    let (honest, anchor) = complete(&records, &witnesses, 5000, None);
    assert_eq!(crate::verify_balance(&honest, &anchor).unwrap().contributing, vec![1]);

    records[2].envelope.class = CLASS_PENDING;
    let (legacy, anchor) = proof(&records, &witnesses, 0, None, None);
    assert_eq!(
        crate::verify_balance(&legacy, &anchor).unwrap().scope,
        SCOPE_MEMBERSHIP_ONLY
    );
    let (forged, anchor) = complete(&records, &witnesses, 0, None);
    assert_eq!(
        crate::verify_balance(&forged, &anchor),
        Err(VerifyError::Record(RecordError::Envelope))
    );
    let (omitted, anchor) = proof_format(
        &records, &witnesses, 0, None, Some(2), BALANCE_FORMAT_V3,
    );
    assert_eq!(
        crate::verify_balance(&omitted, &anchor),
        Err(VerifyError::RecordSet { index: 2 })
    );
}

#[test]
fn authentic_pending_future_and_unrelated_control_payloads_are_checked_not_counted() {
    let mut pending = record(Kind::Ordinary, 2, 100);
    pending.payload[36..38].copy_from_slice(&CLASS_PENDING.to_le_bytes());
    reseal(&mut pending);
    // An authenticated undated control outside the balance predicate must
    // not be interpreted as a migration lifecycle transition. Its remaining
    // control fields are digest-covered, not economic/admission assertions.
    let mut unrelated_control = record(Kind::Control(RUN, 0, [7; 32]), 4, 100);
    unrelated_control.payload[36..38].copy_from_slice(&18u16.to_le_bytes());
    reseal(&mut unrelated_control);
    let mut records = vec![
        record(Kind::Ordinary, 1, 100),
        pending,
        record(Kind::Ordinary, 3, 101),
        unrelated_control,
    ];
    let (proof, anchor) = complete(&records, &[], 5000, Some(100));
    let report = crate::verify_balance(&proof, &anchor).unwrap();
    assert_eq!(report.scope, SCOPE_RECOMPUTATION);
    assert_eq!(report.contributing, vec![0]);

    // Even excluded payloads must be present, correctly framed and bound.
    for omitted in 0..records.len() {
        let (proof, anchor) = proof_format(
            &records, &[], 5000, Some(100), Some(omitted), BALANCE_FORMAT_V3,
        );
        assert_eq!(
            crate::verify_balance(&proof, &anchor),
            Err(VerifyError::RecordSet { index: omitted as u64 })
        );
    }
    records[2].payload[42] ^= 1;
    let (proof, anchor) = complete(&records, &[], 5000, Some(100));
    assert!(matches!(
        crate::verify_balance(&proof, &anchor),
        Err(VerifyError::Record(_))
    ));
}

#[test]
fn full_payloads_preserve_all_migration_modes_and_only_require_selected_run_bodies() {
    for mode in 0..=2 {
        for sole in [false, true] {
            for terminal in [None, Some(1), Some(2)] {
                for day in [90, 100] {
                    let body = body(mode, sole);
                    let records = history(&body, day, terminal);
                    let visible = terminal == Some(1) && (mode != 2 || sole || day >= 100);
                    let amount = if visible { 5000 } else { 0 };
                    let (bytes, anchor) = complete(&records, &[(0, body)], amount, Some(day));
                    let report = crate::verify_balance(&bytes, &anchor).unwrap();
                    assert_eq!(report.scope, SCOPE_RECOMPUTATION);
                    assert_eq!(report.claim.debits, amount);
                    assert_eq!(report.contributing, if visible { vec![1] } else { vec![] });
                    // The same complete prefix, but the chunk is outside the
                    // cutoff: authenticate it without exporting the run body.
                    let (earlier, anchor) = complete(&records, &[], 0, Some(day - 1));
                    let report = crate::verify_balance(&earlier, &anchor).unwrap();
                    assert_eq!(report.scope, SCOPE_RECOMPUTATION);
                    assert!(report.contributing.is_empty());
                }
            }
        }
    }
}

#[test]
fn complete_record_indices_are_exact_unique_and_ascending() {
    let records = [record(Kind::Ordinary, 1, 100), record(Kind::Ordinary, 2, 101)];
    let (honest, anchor) = complete(&records, &[], 5000, Some(100));
    // Canonical framing: format, checkpoint, claim, envelope list, record count.
    let first = 4 + BALANCE_FORMAT_V3.len() + Checkpoint::ENCODED_LEN
        + 16 + 4 + 1 + 4 + 16 + 16 + 4
        + records.iter().map(|r| 4 + r.envelope.encode().len()).sum::<usize>() + 4;
    let second = first + 16 + records[0].payload.len();
    for (offset, wrong_index) in [(first, 1u64), (second, 0u64), (second, u64::MAX)] {
        let mut forged = honest.clone();
        forged[offset..offset + 8].copy_from_slice(&wrong_index.to_le_bytes());
        assert!(matches!(
            crate::verify_balance(&forged, &anchor),
            Err(VerifyError::RecordSet { .. })
        ));
    }
    let mut extra = honest.clone();
    extra[first - 4..first].copy_from_slice(&3u32.to_le_bytes());
    assert!(matches!(crate::verify_balance(&extra, &anchor), Err(VerifyError::Decode(_))));
    let mut trailing = honest.clone();
    trailing.push(0);
    assert!(matches!(crate::verify_balance(&trailing, &anchor), Err(VerifyError::Decode(_))));
    for end in [0, 4, first, second, honest.len() - 1] {
        assert!(crate::verify_balance(&honest[..end], &anchor).is_err());
    }
    let mut wrong_anchor = anchor;
    wrong_anchor.root[0] ^= 1;
    assert!(matches!(
        crate::verify_balance(&honest, &wrong_anchor),
        Err(VerifyError::NotTrusted { .. })
    ));
}

#[test]
fn empty_prefixes_are_complete_and_bad_claims_still_fail() {
    let (empty, anchor) = complete(&[], &[], 0, None);
    let report = crate::verify_balance(&empty, &anchor).unwrap();
    assert_eq!(report.scope, SCOPE_RECOMPUTATION);
    assert!(report.contributing.is_empty());
    let records = [record(Kind::Ordinary, 1, 100)];
    let (wrong, anchor) = complete(&records, &[], 0, None);
    assert_eq!(
        crate::verify_balance(&wrong, &anchor),
        Err(VerifyError::Claim { debits: 5000, credits: 0 })
    );
}

#[test]
fn oversized_proofs_are_refused_before_prefix_allocation() {
    let (_, anchor) = complete(&[], &[], 0, None);
    let bytes = vec![0; MAX_BALANCE_PROOF_BYTES + 1];
    assert_eq!(
        super::super::verify_balance(&bytes, &anchor),
        Err(VerifyError::Decode(DecodeError {
            offset: 0,
            what: "balance proof bytes",
            reason: Reason::TooLong {
                max: MAX_BALANCE_PROOF_BYTES,
                actual: bytes.len(),
            },
        }))
    );
}
