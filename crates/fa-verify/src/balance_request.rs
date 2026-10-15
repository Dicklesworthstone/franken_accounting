//! Bind a complete balance proof to the recipient's independently chosen question.
//!
//! A trusted checkpoint authenticates a journal prefix, not the account,
//! unit, cutoff, or amounts an operator intended to check. An otherwise valid
//! proof for another cell must not satisfy that question. This layer verifies
//! v1/v2/v3, requires independent scope derivation, then compares the claim
//! with an expectation supplied separately by the recipient. Expectations
//! must not be copied from the untrusted proof or its packaging.
//! Partial legacy proofs may be inspected with `crate::verify_balance`, but
//! membership in an unverified scope index cannot answer a complete balance request.

use std::error::Error;
use std::fmt;

use crate::balance::SCOPE_RECOMPUTATION;
use crate::{Balance, BalanceClaim, Checkpoint, VerifyError};

/// An exact posted-balance scope, from inception through an inclusive day.
/// `None` means no effective-date cutoff; it is not a wildcard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalanceScope {
    pub account: u128,
    pub unit: u32,
    pub effective_through: Option<i32>,
}

impl From<&BalanceClaim> for BalanceScope {
    fn from(claim: &BalanceClaim) -> Self {
        Self {
            account: claim.account,
            unit: claim.unit,
            effective_through: claim.effective_through,
        }
    }
}

/// Exact gross debit and credit mantissas, never a netted or rounded amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalanceAmounts {
    pub debits: i128,
    pub credits: i128,
}

impl From<&BalanceClaim> for BalanceAmounts {
    fn from(claim: &BalanceClaim) -> Self {
        Self {
            debits: claim.debits,
            credits: claim.credits,
        }
    }
}

/// Recipient-owned expectations. Scope is mandatory; exact gross amounts
/// are optional when the recipient is asking to learn the proven balance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalanceExpectation {
    pub scope: BalanceScope,
    pub amounts: Option<BalanceAmounts>,
}

#[derive(Debug)]
pub enum BalanceExpectationError {
    /// The proof itself did not verify against the separate trusted anchor.
    Verification(VerifyError),
    /// A partial proof cannot establish the completeness of the requested balance.
    Assurance { actual: &'static str },
    /// A complete proof answered a different question.
    Scope {
        expected: BalanceScope,
        actual: BalanceScope,
    },
    /// Scope matched, but one or both exact gross amounts differed.
    Amounts {
        expected: BalanceAmounts,
        actual: BalanceAmounts,
    },
}

impl fmt::Display for BalanceExpectationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verification(error) => write!(f, "{error}"),
            Self::Assurance { actual } => write!(
                f,
                "balance completeness is not independently verified (scope {actual}); supply a payload-complete v3 proof",
            ),
            Self::Scope { expected, actual } => write!(
                f,
                "balance scope mismatch: expected account {:032x}, unit {}, through {:?}; got account {:032x}, unit {}, through {:?}",
                expected.account,
                expected.unit,
                expected.effective_through,
                actual.account,
                actual.unit,
                actual.effective_through,
            ),
            Self::Amounts { expected, actual } => write!(
                f,
                "balance amounts mismatch: expected debits {}, credits {}; got debits {}, credits {}",
                expected.debits, expected.credits, actual.debits, actual.credits,
            ),
        }
    }
}

impl Error for BalanceExpectationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Verification(error) => Some(error),
            Self::Assurance { .. } | Self::Scope { .. } | Self::Amounts { .. } => None,
        }
    }
}

/// Verify a complete balance proof and require it to answer exactly the
/// recipient's request. No expectation is inferred from the proof itself.
///
/// Cryptographic, completeness, lifecycle and arithmetic checks run before
/// comparisons. Matching scope and amounts in a partial legacy proof are not
/// sufficient. Gross columns are compared separately, not just their net.
/// Legacy v1/v2 remain accepted when every prefix payload has been checked.
pub fn verify_balance_for(
    proof: &[u8],
    trusted_checkpoint: &Checkpoint,
    expected: &BalanceExpectation,
) -> Result<Balance, BalanceExpectationError> {
    let balance = crate::verify_balance(proof, trusted_checkpoint)
        .map_err(BalanceExpectationError::Verification)?;
    if balance.scope != SCOPE_RECOMPUTATION {
        return Err(BalanceExpectationError::Assurance {
            actual: balance.scope,
        });
    }
    let actual = BalanceScope::from(&balance.claim);
    if actual != expected.scope {
        return Err(BalanceExpectationError::Scope {
            expected: expected.scope,
            actual,
        });
    }
    if let Some(amounts) = expected.amounts {
        let actual = BalanceAmounts::from(&balance.claim);
        if actual != amounts {
            return Err(BalanceExpectationError::Amounts {
                expected: amounts,
                actual,
            });
        }
    }
    Ok(balance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Writer;

    fn proof(format: &[u8], scope: BalanceScope) -> (Vec<u8>, Checkpoint) {
        let checkpoint = Checkpoint {
            book_id: [1; 16],
            branch_id: [0; 16],
            through_seq: 0,
            leaf_count: 0,
            root: crate::tree::empty_root(),
        };
        let mut w = Writer::default();
        w.bytes(format)
            .fixed(&checkpoint.encode())
            .u128(scope.account)
            .u32(scope.unit);
        match scope.effective_through {
            Some(day) => {
                w.u8(1).i32(day);
            }
            None => {
                w.u8(0);
            }
        }
        w.i128(0).i128(0).count(0).count(0);
        if format != crate::balance::BALANCE_FORMAT {
            w.count(0);
        }
        (w.buf, checkpoint)
    }

    fn scope() -> BalanceScope {
        BalanceScope {
            account: 10,
            unit: 1,
            effective_through: Some(100),
        }
    }

    fn expectation(scope: BalanceScope) -> BalanceExpectation {
        BalanceExpectation {
            scope,
            amounts: Some(BalanceAmounts {
                debits: 0,
                credits: 0,
            }),
        }
    }

    fn formats() -> [&'static [u8]; 3] {
        [
            crate::balance::BALANCE_FORMAT,
            crate::migration_balance::BALANCE_FORMAT_V2,
            crate::migration_balance::BALANCE_FORMAT_V3,
        ]
    }

    #[test]
    fn all_supported_versions_preserve_complete_reports_and_wire_bytes() {
        for format in formats() {
            let (bytes, anchor) = proof(format, scope());
            let original = bytes.clone();
            let wanted = expectation(scope());
            let report = verify_balance_for(&bytes, &anchor, &wanted).unwrap();
            assert_eq!(report, crate::verify_balance(&bytes, &anchor).unwrap());
            assert_eq!(bytes, original);
            let learn_amounts = BalanceExpectation {
                amounts: None,
                ..wanted
            };
            assert_eq!(
                verify_balance_for(&bytes, &anchor, &learn_amounts).unwrap(),
                report
            );
        }
    }

    #[test]
    fn valid_proofs_for_other_accounts_or_units_do_not_satisfy_the_request() {
        for format in formats() {
            let wanted = expectation(scope());
            for actual in [
                BalanceScope {
                    account: 11,
                    ..scope()
                },
                BalanceScope { unit: 2, ..scope() },
                BalanceScope {
                    account: u128::MAX,
                    unit: u32::MAX,
                    ..scope()
                },
            ] {
                let (bytes, anchor) = proof(format, actual);
                assert!(crate::verify_balance(&bytes, &anchor).is_ok());
                match verify_balance_for(&bytes, &anchor, &wanted).unwrap_err() {
                    BalanceExpectationError::Scope {
                        expected,
                        actual: got,
                    } => {
                        assert_eq!(expected, wanted.scope);
                        assert_eq!(got, actual);
                    }
                    error => assert!(
                        matches!(error, BalanceExpectationError::Scope { .. }),
                        "unexpected error: {error}"
                    ),
                }
            }
        }
    }

    #[test]
    fn cutoff_is_exact_and_unbounded_is_never_a_wildcard() {
        let cutoffs = [
            None,
            Some(i32::MIN),
            Some(-1),
            Some(0),
            Some(100),
            Some(i32::MAX),
        ];
        for format in formats() {
            for supplied in cutoffs {
                let actual = BalanceScope {
                    effective_through: supplied,
                    ..scope()
                };
                let (bytes, anchor) = proof(format, actual);
                for requested in cutoffs {
                    let wanted = expectation(BalanceScope {
                        effective_through: requested,
                        ..scope()
                    });
                    let result = verify_balance_for(&bytes, &anchor, &wanted);
                    if supplied == requested {
                        assert!(result.is_ok());
                    } else {
                        assert!(matches!(result, Err(BalanceExpectationError::Scope { .. })));
                    }
                }
            }
        }
    }

    #[test]
    fn exact_gross_columns_reject_offsetting_wrong_amounts_and_extremes() {
        for format in formats() {
            let (bytes, anchor) = proof(format, scope());
            for amounts in [
                BalanceAmounts {
                    debits: 1,
                    credits: 0,
                },
                BalanceAmounts {
                    debits: 0,
                    credits: 1,
                },
                // Same zero net as the actual claim: net-only checking is wrong.
                BalanceAmounts {
                    debits: 7,
                    credits: 7,
                },
                BalanceAmounts {
                    debits: i128::MAX,
                    credits: i128::MAX,
                },
                BalanceAmounts {
                    debits: -1,
                    credits: -1,
                },
            ] {
                let wanted = BalanceExpectation {
                    amounts: Some(amounts),
                    ..expectation(scope())
                };
                match verify_balance_for(&bytes, &anchor, &wanted).unwrap_err() {
                    BalanceExpectationError::Amounts { expected, actual } => {
                        assert_eq!(expected, amounts);
                        assert_eq!(
                            actual,
                            BalanceAmounts {
                                debits: 0,
                                credits: 0
                            }
                        );
                    }
                    error => assert!(
                        matches!(error, BalanceExpectationError::Amounts { .. }),
                        "unexpected error: {error}"
                    ),
                }
            }
        }
    }

    #[test]
    fn matching_claims_never_bypass_proof_or_checkpoint_verification() {
        for format in formats() {
            let (bytes, anchor) = proof(format, scope());
            let wanted = expectation(scope());
            for end in 0..bytes.len() {
                assert!(matches!(
                    verify_balance_for(&bytes[..end], &anchor, &wanted),
                    Err(BalanceExpectationError::Verification(_)),
                ));
            }
            let mut other = anchor;
            other.book_id[0] ^= 1;
            let error = verify_balance_for(&bytes, &other, &wanted).unwrap_err();
            assert!(matches!(error, BalanceExpectationError::Verification(_)));
            assert!(error.source().is_some());
            let mut extra = bytes;
            extra.push(0);
            assert!(matches!(
                verify_balance_for(&extra, &anchor, &wanted),
                Err(BalanceExpectationError::Verification(_)),
            ));
        }
    }

    #[test]
    fn matching_legacy_membership_cannot_answer_a_complete_balance_request() {
        let envelope = crate::LeafEnvelope {
            kind: crate::envelope::KIND_ENTRY,
            book_id: [1; 16],
            branch_id: [0; 16],
            commit_seq: 1,
            within_commit_ordinal: 0,
            record_digest: [7; 32],
            class: crate::balance::CLASS_PENDING,
            effective_day: Some(100),
            account_vids: vec![10],
            unit_ids: vec![1],
        }
        .encode();
        let anchor = Checkpoint {
            book_id: [1; 16],
            branch_id: [0; 16],
            through_seq: 1,
            leaf_count: 1,
            root: crate::tree::leaf_hash(&envelope),
        };
        for format in [
            crate::balance::BALANCE_FORMAT,
            crate::migration_balance::BALANCE_FORMAT_V2,
        ] {
            let mut w = Writer::default();
            w.bytes(format)
                .fixed(&anchor.encode())
                .u128(10)
                .u32(1)
                .u8(1)
                .i32(100)
                .i128(0)
                .i128(0)
                .count(1)
                .bytes(&envelope)
                .count(0);
            if format == crate::migration_balance::BALANCE_FORMAT_V2 {
                w.count(0);
            }
            assert_eq!(
                crate::verify_balance(&w.buf, &anchor).unwrap().scope,
                "membership_only"
            );
            let error = verify_balance_for(&w.buf, &anchor, &expectation(scope())).unwrap_err();
            assert!(matches!(
                error,
                BalanceExpectationError::Assurance {
                    actual: "membership_only"
                }
            ));
            assert!(
                error
                    .to_string()
                    .contains("completeness is not independently verified")
            );
            assert!(error.source().is_none());
        }
    }
}
