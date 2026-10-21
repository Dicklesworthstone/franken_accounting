//! Account bundles with an independently payload-derived index premise.

use super::PayloadIndex;
use super::incremental::IncrementalPayloadIndex;
use crate::BalanceExpectation;
use crate::bundle::{BundleCheck, BundleReport, BundleScope, Grade};
use crate::checkpoint::witness::WitnessedCheckpoint;
use crate::checkpoint::witness::bundle::balances::{
    validate_balance_expectations, verify_witnessed_bundle_balances_for,
};
use crate::checkpoint::witness::bundle::{
    BundleExpectation, MAX_WITNESSED_BUNDLE_BYTES, WitnessBundleError, verify_witnessed_bundle_for,
};

/// Require the account bundle's index to have been independently reconstructed
/// from every authenticated prefix payload. The immutable `index` can be reused
/// for another interval at the same journal coordinate and scope-index root.
/// It cannot be manufactured from a caller-written report or a signature alone.
///
/// `balances` preserves the existing distinction between unspecified (None),
/// explicitly empty (Some(&[])), and exact requested cells. All existing
/// bundle, witness, receipt, scope, disclosure and balance predicates still run;
/// a reconstructed index never repairs a failed predicate or a partial stock
/// proof. Account range and neighbour proofs are still checked for each bundle.
///
/// The source witness's encoded size is counted with bundle and receipt under
/// one 64 MiB policy even when the witness bytes have already been released.
/// The full-prefix disclosure must have been authorized separately: this API
/// neither grants permission nor asserts privacy, provenance or global freshness.
pub fn verify_witnessed_indexed_bundle_for(
    bytes: &[u8],
    anchor: &WitnessedCheckpoint,
    expected: &BundleExpectation,
    receipt: Option<&[u8]>,
    index: &PayloadIndex,
    balances: Option<&[BalanceExpectation]>,
) -> Result<BundleReport, WitnessBundleError> {
    expected.validate()?;
    if !matches!(&expected.scope, BundleScope::Account(_)) {
        return Err(WitnessBundleError::Request(
            "payload-index verification requires an exact account scope",
        ));
    }
    if let Some(balances) = balances {
        validate_balance_expectations(balances)?;
    }
    if !index.matches(anchor.signed_checkpoint()) {
        return Err(WitnessBundleError::Request(
            "payload-derived index does not match the witnessed checkpoint and scope root",
        ));
    }
    if bytes
        .len()
        .checked_add(receipt.map_or(0, <[u8]>::len))
        .and_then(|total| total.checked_add(index.encoded_bytes()))
        .is_none_or(|total| total > MAX_WITNESSED_BUNDLE_BYTES)
    {
        return Err(WitnessBundleError::InputLimit(
            "aggregate index witness, bundle and receipt bytes",
        ));
    }
    let mut report = match balances {
        Some(cells) => {
            verify_witnessed_bundle_balances_for(bytes, anchor, expected, cells, receipt)
        }
        None => verify_witnessed_bundle_for(bytes, anchor, expected, receipt),
    }?;
    let grade = if report.verified() {
        // The existing range proof passed against the SAME root independently
        // derived above. Replace only its weaker premise description, never a
        // grade, to avoid claiming signatures are what established derivation.
        for check in &mut report.checks {
            if check.check == "completeness" {
                check.subject =
                    "the exact account interval in the independently payload-derived scope index"
                        .into();
            }
        }
        Grade::Pass
    } else {
        Grade::Unrun("the bundle must satisfy all existing predicates before attaching the derived-index premise".into())
    };
    report.checks.push(BundleCheck {
        check: "payload_scope_index_derivation",
        scope: "recomputation",
        subject: format!(
            "all {} prefix record selectors and {} account/day/leaf tuples independently checked",
            index.checkpoint().leaf_count,
            index.tuple_count(),
        ),
        grade,
    });
    Ok(report)
}

/// Verify an account bundle against a retained payload-derived index that was
/// advanced from an independently verified baseline with a complete suffix.
///
/// This is the plan §13.2 "verified state + complete delta" path. The sealed
/// incremental state supplies BOTH the current witnessed checkpoint and the
/// independently reconstructed scope-index root, so callers cannot accidentally
/// pair a current bundle with a stale index or a different signature policy.
///
/// The state's cumulative encoded-byte accounting is preserved by delegating to
/// verify_witnessed_indexed_bundle_for: baseline, every accepted candidate,
/// every consistency proof and every appended record remain charged against the
/// same 64 MiB composition budget as the bundle and optional receipt. This API
/// does not persist the state, authorize its underlying disclosures, or claim
/// global freshness, provenance, accounting truth, or logarithmic verification.
pub fn verify_witnessed_incremental_indexed_bundle_for(
    bytes: &[u8],
    expected: &BundleExpectation,
    receipt: Option<&[u8]>,
    state: &IncrementalPayloadIndex,
    balances: Option<&[BalanceExpectation]>,
) -> Result<BundleReport, WitnessBundleError> {
    verify_witnessed_indexed_bundle_for(
        bytes,
        state.checkpoint(),
        expected,
        receipt,
        state.index(),
        balances,
    )
}
