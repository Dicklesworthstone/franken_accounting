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
//! payload of exactly the in-scope leaves, ascending. In scope: an entry
//! whose envelope names the account and the unit, whose class is not
//! `Pending`, and whose effective day is at or before the cutoff when one
//! is given. Each record must rebuild its own envelope (both digests
//! recomputed), and the verifier refolds the posted debits and credits of
//! (account, unit) with checked `i128` and compares them with the claim.
//!
//! Not covered: pending reservations (a hold's release depends on every
//! resolution's target, which this proof does not carry), periods (the
//! cutoff is a civil day, not a fiscal-period selector), and anything a
//! later known-at would change.

use crate::codec::{DecodeError, Reader};
use crate::envelope::{LeafEnvelope, MAX_RECORD_BYTES, check_record};
use crate::proof::{Checkpoint, VerifyError, complete_prefix, open, read_envelopes, trusted};

pub const BALANCE_FORMAT: &[u8] = b"fa:acc-balance-proof:v1";
pub const SCOPE_RECOMPUTATION: &str = "recomputation";

/// The `Pending` entry class tag (`registries/entry_classes.toml`): a hold
/// reserves and never posts.
pub const CLASS_PENDING: u16 = 2;

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

/// Whether a leaf contributes posted legs to (account, unit) by the cutoff.
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
    let expected: Vec<u64> = envelopes
        .iter()
        .enumerate()
        .filter(|(_, e)| in_scope(e, claim.account, claim.unit, claim.effective_through))
        .map(|(i, _)| u64::try_from(i).unwrap_or(u64::MAX))
        .collect();
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
    use crate::envelope::KIND_ENTRY;

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
}
