//! Bind a bundle to a sealed recipient-quorum checkpoint and an exact question.
//!
//! A genuine bundle under some trusted key is not necessarily the requested
//! production. Its embedded checkpoint must be the EXACT already-verified
//! artifact, not merely a body with witness signatures removed. Continuity can
//! be established first with verify_checkpoint_advance; this check never
//! replaces or advances the retained pin on its own.

use std::fmt;

use super::WitnessedCheckpoint;
use crate::bundle::{BundleCheck, BundleError, BundleReport, BundleScope, Grade, verify_bundle};

/// Total encoded bundle plus optional detached receipt, checked before decoding.
pub const MAX_WITNESSED_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_REQUESTED_BUNDLE_LEAVES: usize = 65_536;
/// One v1 receipt has one <=1024-byte signature and a bounded fixed body.
pub const MAX_WITNESSED_RECEIPT_BYTES: usize = 4096;

/// Recipient-owned requirements, never inferred from the untrusted manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleExpectation {
    pub scope: BundleScope,
    /// Require every cited document stub to include its complete bytes.
    /// False permits commitments only, never claims omitted bytes were checked.
    pub inline_documents: bool,
    /// Require a detached receipt signed by the policy's PUBLISHER. A witness
    /// key's role does not authorize signing production receipts.
    pub publisher_receipt: bool,
}

impl BundleExpectation {
    /// Syntax/count validation that needs neither a checkpoint nor input I/O.
    pub fn validate(&self) -> Result<(), WitnessBundleError> {
        match &self.scope {
            BundleScope::Account(claim) if claim.from > claim.to =>
                Err(WitnessBundleError::Request("account day interval is reversed")),
            BundleScope::Entries(leaves) if leaves.len() > MAX_REQUESTED_BUNDLE_LEAVES =>
                Err(WitnessBundleError::Request("too many requested leaves")),
            BundleScope::Entries(leaves) if leaves.windows(2).any(|pair| pair[0] >= pair[1]) =>
                Err(WitnessBundleError::Request("requested leaves must be strictly ascending")),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WitnessBundleError {
    Request(&'static str),
    InputLimit(&'static str),
    Bundle(BundleError),
}

impl fmt::Display for WitnessBundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(why) => write!(f, "invalid recipient bundle request: {why}"),
            Self::InputLimit(what) => write!(f, "witnessed bundle exceeds the {what} bound"),
            Self::Bundle(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for WitnessBundleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self { Self::Bundle(error) => Some(error), _ => None }
    }
}

/// Verify every existing bundle predicate AND the recipient's anchor/scope/
/// disclosure/receipt requirements. Parsing/policy errors are Err; artifact
/// failures remain per-predicate grades. Inspect BundleReport::verified().
/// A valid quorum cannot turn a failed, unrun or membership-only predicate
/// into complete accounting assurance. Account index derivation retains its
/// explicitly signed (not recomputed) premise. This does not require any
/// particular balance claims; those expectations belong to verify_balance_for.
///
/// The anchor is sealed by actual signature verification, not constructible
/// from a public report. Exact checkpoint artifact binding intentionally refuses
/// even alternative signature subsets until the caller verifies/selects that
/// artifact as its anchor. Receipts trust ONLY its publisher; witness signing
/// keys are never silently promoted to production-signing authority.
/// No files, persistent pins, policy documents or signing keys are accessed.
pub fn verify_witnessed_bundle_for(
    bytes: &[u8],
    anchor: &WitnessedCheckpoint,
    expected: &BundleExpectation,
    receipt: Option<&[u8]>,
) -> Result<BundleReport, WitnessBundleError> {
    expected.validate()?;
    if let BundleScope::Entries(leaves) = &expected.scope {
        if leaves.last().is_some_and(|index| *index >= anchor.signed.checkpoint.leaf_count) {
            return Err(WitnessBundleError::Request("a requested leaf is outside the pinned prefix"));
        }
    }
    let receipt_length = receipt.map_or(0, <[u8]>::len);
    if receipt_length > MAX_WITNESSED_RECEIPT_BYTES {
        return Err(WitnessBundleError::InputLimit("receipt bytes"));
    }
    if bytes.len().checked_add(receipt_length)
        .is_none_or(|total| total > MAX_WITNESSED_BUNDLE_BYTES)
    {
        return Err(WitnessBundleError::InputLimit("aggregate bundle and receipt bytes"));
    }
    // RecipientWitnessPolicy's private constructor always stores publisher first.
    // Reuse all existing independent bundle checks; do not duplicate the codec,
    // signature verification, stock fold, document hashing or receipt transcript.
    let mut report = verify_bundle(bytes, &anchor.policy.trusted_keys[..1], receipt)
        .map_err(WitnessBundleError::Bundle)?;
    let manifest_valid = report.checks.iter()
        .any(|check| check.check == "manifest" && matches!(check.grade, Grade::Pass));
    let cp = &anchor.signed.checkpoint;
    let m = &report.manifest;
    let exact_anchor = m.checkpoint_oid == anchor.signed.oid
        && (m.book_id, m.branch_id, m.through_seq, m.leaf_count)
            == (cp.book_id, cp.branch_id, cp.through_seq, cp.leaf_count);
    let binding = if !manifest_valid {
        Grade::Unrun("the embedded checkpoint/manifest did not verify".into())
    } else if exact_anchor {
        Grade::Pass
    } else {
        Grade::Fail("the bundle does not name the exact recipient-quorum checkpoint artifact".into())
    };
    let bound = matches!(&binding, Grade::Pass);
    let additional = [
        ("witnessed_checkpoint_binding", "signature", "the independently verified publisher/witness checkpoint", binding),
        ("requested_bundle_scope", "request", "the recipient's exact manifest scope",
            requirement(bound, m.scope == expected.scope, "bundle scope differs from the recipient's request")),
        ("requested_document_disclosure", "document", if expected.inline_documents {
            "all cited document bytes must be supplied; authenticity is graded separately"
        } else { "commitment-only documents are permitted; omitted bytes are not checked" },
            requirement(bound, !expected.inline_documents || report.summary.documents == report.summary.inline,
                "a cited document was not supplied inline")),
        ("requested_publisher_receipt", "production", if expected.publisher_receipt {
            "a detached receipt signed by the publisher is required"
        } else { "no detached receipt is required; any supplied receipt must still verify" },
            requirement(bound, !expected.publisher_receipt || report.receipt.is_some(),
                "the required publisher-signed receipt is absent or invalid")),
    ];
    report.checks.extend(additional.into_iter().map(|(check, scope, subject, grade)| BundleCheck {
        check, scope, subject: subject.into(), grade,
    }));
    Ok(report)
}

fn requirement(bound: bool, passes: bool, why: &str) -> Grade {
    if !bound {
        Grade::Unrun("the bundle is not bound to the recipient's witnessed checkpoint".into())
    } else if passes { Grade::Pass } else { Grade::Fail(why.into()) }
}

#[cfg(test)]
mod tests;
