//! Exact recipient-owned stock-cell requests inside witnessed bundles.
//!
//! Entry scope and balance scope are independent: a genuine prefix or account
//! extract may carry no balances, a different unit, or a different stock cutoff.
//! This opt-in API checks an exact SET of distinct cells, not a subset. Proof
//! order and request order need not agree; duplicates are errors, never votes.
//! The existing wire formats, fold laws and completeness grades are unchanged.

use std::collections::{BTreeMap, BTreeSet};

use super::{BundleExpectation, WitnessBundleError, WitnessedCheckpoint, verify_inspecting_balances};
use crate::balance_request::{BalanceAmounts, BalanceExpectation, BalanceScope};
use crate::bundle::{BundleCheck, BundleReport, Grade};
use crate::BalanceClaim;

/// Share the actual bundle decoder limit rather than admitting unencodable requests.
pub const MAX_REQUESTED_BUNDLE_BALANCES: usize = crate::bundle::MAX_BALANCES;

type Cell = (u128, u32, Option<i32>);

fn cell(scope: BalanceScope) -> Cell {
    (scope.account, scope.unit, scope.effective_through)
}

fn requests(
    expected: &[BalanceExpectation],
) -> Result<BTreeMap<Cell, &BalanceExpectation>, WitnessBundleError> {
    if expected.len() > MAX_REQUESTED_BUNDLE_BALANCES {
        return Err(WitnessBundleError::Request("too many requested balance cells"));
    }
    let mut result = BTreeMap::new();
    for request in expected {
        if request.amounts.is_some_and(|amounts| amounts.debits < 0 || amounts.credits < 0) {
            return Err(WitnessBundleError::Request("expected gross balance amounts must be nonnegative"));
        }
        if result.insert(cell(request.scope), request).is_some() {
            return Err(WitnessBundleError::Request("a balance cell is requested more than once"));
        }
    }
    Ok(result)
}

/// Validate a recipient request without observing artifacts. Empty explicitly
/// requires NO balance claims. A missing cutoff means no cutoff, never any
/// cutoff; missing amounts permit learning the value, never a different cell.
pub fn validate_balance_expectations(
    expected: &[BalanceExpectation],
) -> Result<(), WitnessBundleError> {
    requests(expected).map(|_| ())
}

/// Verify the existing witnessed-bundle requirements AND exactly the requested
/// account/unit/inclusive-cutoff cells, optionally including their exact gross
/// debit and credit mantissas. Callers must obtain these expectations separately
/// from the untrusted bundle. The known-at and book/branch come from the sealed
/// checkpoint, not from a second potentially inconsistent balance selector.
///
/// Each proof is folded only once. The internal observation hook sees a claim
/// only after its arithmetic, lifecycle and complete-derivation requirements
/// pass. Observations are kept private until the entire base report succeeds.
/// Neither equal nets nor matching labels rescue invalid or partial proofs.
/// Failures remain per-predicate grades; inspect `BundleReport::verified()`.
/// No report claim is widened and no files, keys or pin state are written.
pub fn verify_witnessed_bundle_balances_for(
    bytes: &[u8],
    anchor: &WitnessedCheckpoint,
    expected_bundle: &BundleExpectation,
    expected_balances: &[BalanceExpectation],
    receipt: Option<&[u8]>,
) -> Result<BundleReport, WitnessBundleError> {
    let wanted = requests(expected_balances)?;
    let mut seen = BTreeSet::new();
    let mut verified_count = 0usize;
    let mut set_error = None;
    let mut amounts_error = None;
    let mut report = verify_inspecting_balances(
        bytes, anchor, expected_bundle, receipt, |ordinal, claim: BalanceClaim| {
            verified_count += 1; // bounded by the decoder's balance count
            let key = cell(BalanceScope::from(&claim));
            if !seen.insert(key) {
                set_error.get_or_insert_with(|| format!("balance {ordinal} repeats a supplied cell"));
            }
            match wanted.get(&key) {
                None => {
                    set_error.get_or_insert_with(|| format!("balance {ordinal} is not a requested cell"));
                }
                Some(request) => {
                    if request.amounts.is_some_and(|amounts| amounts != BalanceAmounts::from(&claim)) {
                        amounts_error.get_or_insert_with(|| format!(
                            "balance {ordinal} gross debit or credit mantissa differs from the request"
                        ));
                    }
                }
            }
        },
    )?;
    // Do not attach successful request grades to an untrusted/misbound bundle,
    // incomplete stock proof, failed receipt, or any other failed base predicate.
    let set_grade = if !report.verified() || verified_count != report.summary.balances.len() {
        Grade::Unrun("the witnessed bundle and all balance proofs must first verify".into())
    } else if verified_count != wanted.len() {
        Grade::Fail(format!(
            "requested {} distinct balance cells; supplied {verified_count}", wanted.len()
        ))
    } else if let Some(why) = set_error {
        Grade::Fail(why)
    } else {
        Grade::Pass
    };
    let amounts_grade = if !matches!(&set_grade, Grade::Pass) {
        Grade::Unrun("the exact requested balance set did not verify".into())
    } else if let Some(why) = amounts_error {
        Grade::Fail(why)
    } else {
        Grade::Pass
    };
    report.checks.extend([
        BundleCheck {
            check: "requested_balance_set",
            scope: "request",
            subject: format!("exactly {} distinct recipient-selected stock cells", wanted.len()),
            grade: set_grade,
        },
        BundleCheck {
            check: "requested_balance_amounts",
            scope: "request",
            subject: "exact requested gross columns; unspecified amounts remain unconstrained".into(),
            grade: amounts_grade,
        },
    ]);
    Ok(report)
}

#[cfg(test)]
mod tests;
