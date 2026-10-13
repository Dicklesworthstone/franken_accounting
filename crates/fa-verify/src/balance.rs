//! Balance recomputation (plan §13.1 scope `recomputation`, §13.3 balance
//! proof closure).
//!
//! ```text
//! BalanceProof = bytes("fa:acc-balance-proof:v1") ‖ Checkpoint
//!                ‖ account u128 ‖ unit u32 ‖ opt(effective_through i32)
//!                ‖ debits i128 ‖ credits i128                        (the claim)
//!                ‖ list(bytes(LeafEnvelope))                         (every leaf)
//!                ‖ list(leaf_index u64 ‖ proposal_len u32 ‖ bytes(record))
//! ```
//!
//! A stock balance is a fold over every contributing entry from inception
//! through the cutoff, so the proof carries the trusted checkpoint's
//! complete prefix — which makes the in-scope set authenticated — and the
//! payload of exactly the in-scope leaves, ascending. Candidate leaves name
//! the account and unit, are not `Pending`, and meet the effective cutoff.
//! **Migration visibility cannot be established by v1.** If a candidate is
//! a `Migration`, verification refuses with its `RecordSet` index, whether
//! or not the producer supplied its record. Counting it could include an
//! Open/Abandoned run; silently excluding it could omit a Finalized run.
//! Authenticating a leaf is not evidence that its legs currently count.
//! A later format must authenticate the run lifecycle and opening policy
//! (fa-e00). Even finalized migrations are conservatively refused here.
//!
//! For supported scopes each record must rebuild its own envelope (both
//! digests recomputed), and the verifier refolds the posted debits and
//! credits of (account, unit) with checked `i128` and compares the claim.
//!
//! Not covered: pending reservations (a hold's release depends on every
//! resolution's target, which this proof does not carry), periods (the
//! cutoff is a civil day, not a fiscal-period selector), and anything a
//! later known-at would change. Migrations outside the selected cell or
//! after its effective cutoff do not prevent a v1 balance proof.

use crate::codec::{DecodeError, Reader};
use crate::envelope::{LeafEnvelope, MAX_RECORD_BYTES, check_record};
use crate::proof::{Checkpoint, VerifyError, complete_prefix, open, read_envelopes, trusted};

pub const BALANCE_FORMAT: &[u8] = b"fa:acc-balance-proof:v1";
pub const SCOPE_RECOMPUTATION: &str = "recomputation";

/// The `Pending` entry class tag (`registries/entry_classes.toml`): a hold
/// reserves and never posts.
pub const CLASS_PENDING: u16 = 2;

/// The `Migration` tag (`registries/entry_classes.toml`). Its contribution
/// depends on authenticated run controls, not on this class tag alone.
pub const CLASS_MIGRATION: u16 = 12;

/// What a balance proof claims about one (account, unit).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalanceClaim {
    pub account: u128,
    pub unit: u32,
    /// Inclusive civil-day cutoff; `None` folds every effective day.
    pub effective_through: Option<i32>,
    pub debits: i128,
    pub credits: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Balance {
    pub scope: &'static str,
    pub checkpoint: Checkpoint,
    pub claim: BalanceClaim,
    /// The leaves the fold read, ascending.
    pub contributing: Vec<u64>,
}

/// Whether a leaf is a candidate for (account, unit) by the cutoff.
/// This structural predicate does not establish migration visibility.
#[must_use]
pub fn in_scope(e: &LeafEnvelope, account: u128, unit: u32, through: Option<i32>) -> bool {
    e.class != CLASS_PENDING
        && e.account_vids.binary_search(&account).is_ok()
        && e.unit_ids.binary_search(&unit).is_ok()
        && through.is_none_or(|cutoff| e.effective_day.is_some_and(|day| day <= cutoff))
}

fn read_claim(r: &mut Reader<'_>) -> Result<BalanceClaim, DecodeError> {
    let account = r.u128("balance.account")?;
    let unit = r.u32("balance.unit")?;
    let effective_through = if r.present("balance.effective_through")? {
        Some(r.i32("balance.effective_through")?)
    } else {
        None
    };
    Ok(BalanceClaim {
        account,
        unit,
        effective_through,
        debits: r.i128("balance.debits")?,
        credits: r.i128("balance.credits")?,
    })
}

/// Verify a balance proof against the checkpoint the caller trusts.
/// A v1 proof cannot prove the contribution of a Migration candidate;
/// `RecordSet` names the first such leaf in the authenticated prefix.
pub fn verify_balance(
    proof: &[u8],
    trusted_checkpoint: &Checkpoint,
) -> Result<Balance, VerifyError> {
    let mut r = open(proof, BALANCE_FORMAT)?;
    let checkpoint = trusted(Checkpoint::read(&mut r)?, trusted_checkpoint)?;
    let claim = read_claim(&mut r)?;
    let raw = read_envelopes(&mut r)?;
    let n = r.count(raw.len(), 8 + 4 + 4, "proof.records")?;
    let mut records = Vec::with_capacity(n);
    for _ in 0..n {
        let index = r.u64("record.leaf_index")?;
        let proposal_len = usize::try_from(r.u32("record.proposal_len")?).unwrap_or(usize::MAX);
        records.push((
            index,
            proposal_len,
            r.bytes(MAX_RECORD_BYTES, "record.payload")?,
        ));
    }
    r.finish("balance proof")?;

    let envelopes = complete_prefix(&raw, &checkpoint)?;
    let mut expected = Vec::new();
    for (index, envelope) in envelopes.iter().enumerate() {
        if !in_scope(envelope, claim.account, claim.unit, claim.effective_through) {
            continue;
        }
        let index = u64::try_from(index).unwrap_or(u64::MAX);
        // Inspect the authenticated prefix, not `records`: a producer must
        // not be able to choose whether a migration counts by including or
        // withholding its payload. v1 has no lifecycle visibility witness.
        if envelope.class == CLASS_MIGRATION {
            return Err(VerifyError::RecordSet { index });
        }
        expected.push(index);
    }
    // Exactly the in-scope leaves, in order: report the first index where
    // the supplied list and the authenticated set part ways.
    for (k, want) in expected.iter().enumerate() {
        match records.get(k) {
            Some((got, _, _)) if got == want => {}
            Some((got, _, _)) => {
                return Err(VerifyError::RecordSet {
                    index: (*got).min(*want),
                });
            }
            None => return Err(VerifyError::RecordSet { index: *want }),
        }
    }
    if let Some((extra, _, _)) = records.get(expected.len()) {
        return Err(VerifyError::RecordSet { index: *extra });
    }

    let (mut debits, mut credits) = (0i128, 0i128);
    for (index, proposal_len, payload) in &records {
        let envelope = usize::try_from(*index)
            .ok()
            .and_then(|i| envelopes.get(i))
            .ok_or(VerifyError::RecordSet { index: *index })?;
        let legs = check_record(envelope, payload, *proposal_len).map_err(VerifyError::Record)?;
        for leg in legs
            .iter()
            .filter(|l| l.account == claim.account && l.unit == claim.unit)
        {
            if leg.mantissa < 0 {
                return Err(VerifyError::Arithmetic);
            }
            let slot = if leg.debit { &mut debits } else { &mut credits };
            *slot = slot
                .checked_add(leg.mantissa)
                .ok_or(VerifyError::Arithmetic)?;
        }
    }
    if (debits, credits) != (claim.debits, claim.credits) {
        return Err(VerifyError::Claim { debits, credits });
    }
    Ok(Balance {
        scope: SCOPE_RECOMPUTATION,
        checkpoint,
        claim,
        contributing: expected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blake3::hash_parts;
    use crate::codec::Writer;
    use crate::envelope::{
        ENTRY_DIGEST_DOMAIN, KIND_ENTRY, PROPOSAL_DIGEST_DOMAIN, envelope_of_entry,
    };
    use crate::proof::INCLUSION_FORMAT;
    use crate::tree::leaf_hash;

    fn envelope(
        class: u16,
        day: Option<i32>,
        accounts: Vec<u128>,
        units: Vec<u32>,
    ) -> LeafEnvelope {
        LeafEnvelope {
            kind: KIND_ENTRY,
            book_id: [1; 16],
            branch_id: [0; 16],
            commit_seq: 1,
            within_commit_ordinal: 0,
            record_digest: [0; 32],
            class,
            effective_day: day,
            account_vids: accounts,
            unit_ids: units,
        }
    }

    #[test]
    fn scope_is_account_and_unit_named_not_pending_and_within_the_cutoff() {
        let posted = envelope(1, Some(100), vec![5, 9], vec![1, 2]);
        assert!(in_scope(&posted, 5, 1, None));
        assert!(in_scope(&posted, 9, 2, Some(100)));
        assert!(!in_scope(&posted, 9, 2, Some(99)), "after the cutoff");
        assert!(!in_scope(&posted, 6, 1, None), "another account");
        assert!(!in_scope(&posted, 5, 3, None), "another unit");
        let hold = envelope(CLASS_PENDING, Some(100), vec![5], vec![1]);
        assert!(!in_scope(&hold, 5, 1, None), "a hold never posts");
        let undated = envelope(17, None, vec![], vec![]);
        assert!(!in_scope(&undated, 5, 1, Some(100)));
    }

    // Reuse the existing fully encoded posting instead of duplicating the
    // entry codec. Retagging and resealing it below is an adversarial proof-
    // layer fixture, not a claim that the kernel admits the altered entry.
    fn record(class: u16) -> (Vec<u8>, usize, LeafEnvelope) {
        let hex = include_str!("../tests/fixtures/accumulator_v1.txt")
            .lines()
            .find_map(|line| line.strip_prefix("inclusion "))
            .expect("pinned inclusion vector");
        let proof: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let mut r = open(&proof, INCLUSION_FORMAT).unwrap();
        Checkpoint::read(&mut r).unwrap();
        r.u64("leaf index").unwrap();
        r.bytes(MAX_RECORD_BYTES, "envelope").unwrap();
        assert!(r.present("record").unwrap());
        let proposal_len = usize::try_from(r.u32("proposal length").unwrap()).unwrap();
        let mut payload = r.bytes(MAX_RECORD_BYTES, "record").unwrap().to_vec();
        // schema major/minor (4), book and branch (32), then the class u16.
        payload[36..38].copy_from_slice(&class.to_le_bytes());
        let end = payload.len();
        let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&payload[..proposal_len]]);
        let entry_digest = hash_parts(
            ENTRY_DIGEST_DOMAIN,
            &[&proposal_digest, &payload[proposal_len..end - 64]],
        );
        payload[end - 64..end - 32].copy_from_slice(&proposal_digest);
        payload[end - 32..].copy_from_slice(&entry_digest);
        let envelope = envelope_of_entry(&payload, proposal_len, 1, 0).unwrap();
        // The record really binds its selection fields and amount, so the
        // negative reaches visibility rather than a digest/decoding error.
        let legs = check_record(&envelope, &payload, proposal_len).unwrap();
        let cash: Vec<_> = legs
            .iter()
            .filter(|leg| leg.account == 0x30 && leg.unit == 1)
            .collect();
        assert_eq!(cash.len(), 1);
        assert!(!cash[0].debit);
        assert_eq!(cash[0].mantissa, 550);
        (payload, proposal_len, envelope)
    }

    fn proof_for(
        record: &(Vec<u8>, usize, LeafEnvelope),
        claim: BalanceClaim,
        include_record: bool,
    ) -> (Vec<u8>, Checkpoint) {
        let (payload, proposal_len, envelope) = record;
        let raw = envelope.encode();
        let checkpoint = Checkpoint {
            book_id: envelope.book_id,
            branch_id: envelope.branch_id,
            through_seq: 1,
            leaf_count: 1,
            root: leaf_hash(&raw),
        };
        let mut w = Writer::default();
        w.bytes(BALANCE_FORMAT)
            .fixed(&checkpoint.encode())
            .u128(claim.account)
            .u32(claim.unit);
        match claim.effective_through {
            Some(day) => {
                w.u8(1).i32(day);
            }
            None => {
                w.u8(0);
            }
        }
        w.i128(claim.debits)
            .i128(claim.credits)
            .count(1)
            .bytes(&raw);
        if include_record {
            w.count(1)
                .u64(0)
                .u32(u32::try_from(*proposal_len).unwrap())
                .bytes(payload);
        } else {
            w.count(0);
        }
        (w.buf, checkpoint)
    }

    fn cash_claim(credits: i128) -> BalanceClaim {
        BalanceClaim {
            account: 0x30,
            unit: 1,
            effective_through: None,
            debits: 0,
            credits,
        }
    }

    #[test]
    fn a_v1_balance_cannot_choose_migration_visibility_by_supplying_records() {
        let migration = record(CLASS_MIGRATION);
        for include_record in [true, false] {
            for credits in [0, 550] {
                let (proof, checkpoint) =
                    proof_for(&migration, cash_claim(credits), include_record);
                assert_eq!(
                    verify_balance(&proof, &checkpoint),
                    Err(VerifyError::RecordSet { index: 0 }),
                    "migration visibility is not proven: record={include_record}, credits={credits}"
                );
            }
        }
    }

    #[test]
    fn ordinary_balances_still_refold_and_require_the_exact_claim() {
        let original = record(1);
        let (proof, checkpoint) = proof_for(&original, cash_claim(550), true);
        let balance = verify_balance(&proof, &checkpoint).unwrap();
        assert_eq!(balance.contributing, vec![0]);
        assert_eq!((balance.claim.debits, balance.claim.credits), (0, 550));
        let (wrong, checkpoint) = proof_for(&original, cash_claim(0), true);
        assert_eq!(
            verify_balance(&wrong, &checkpoint),
            Err(VerifyError::Claim {
                debits: 0,
                credits: 550,
            })
        );
    }

    #[test]
    fn migrations_outside_the_selected_cell_or_cutoff_do_not_block_v1() {
        let migration = record(CLASS_MIGRATION);
        let mut other_account = cash_claim(0);
        other_account.account = 0x99;
        let mut other_unit = cash_claim(0);
        other_unit.unit = 99;
        let mut earlier = cash_claim(0);
        earlier.effective_through = Some(20_526);
        for claim in [other_account, other_unit, earlier] {
            let (proof, checkpoint) = proof_for(&migration, claim, false);
            let report = verify_balance(&proof, &checkpoint).unwrap();
            assert!(report.contributing.is_empty());
            assert_eq!(report.claim, claim);
        }
        let mut inclusive = cash_claim(550);
        inclusive.effective_through = Some(20_527);
        let (proof, checkpoint) = proof_for(&migration, inclusive, true);
        assert_eq!(
            verify_balance(&proof, &checkpoint),
            Err(VerifyError::RecordSet { index: 0 })
        );
    }

    #[test]
    fn the_prefix_is_authenticated_before_deciding_migration_visibility() {
        let migration = record(CLASS_MIGRATION);
        let (mut proof, mut checkpoint) = proof_for(&migration, cash_claim(550), true);
        // Change the claimed and trusted root together, leaving the actual
        // leaf unchanged. This must fail prefix authentication, not scope.
        checkpoint.root[0] ^= 1;
        let start = 4 + BALANCE_FORMAT.len();
        proof[start..start + Checkpoint::ENCODED_LEN].copy_from_slice(&checkpoint.encode());
        assert_eq!(verify_balance(&proof, &checkpoint), Err(VerifyError::Root));
    }
}
