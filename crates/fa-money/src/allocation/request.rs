//! Law-bound allocation requests and exact, recomputable outcomes (§6.3).
//! Targets are caller-owned stable identities, not implicit vector positions.
//! Their *order* is still semantic: it controls ties, waterfalls and first-
//! recipient residuals. This layer does not resolve accounts or authorize posts.

use core::fmt;
use std::collections::BTreeSet;

use super::{
    AllocationCatalog, AllocationLaw, ProRataAllocation, equal_split_residual_first,
    largest_remainder, pro_rata_residual_to_named, waterfall,
};
use crate::wide::U256;
use crate::{Amount, AmountError, RoundingLaw};

#[derive(Debug)]
pub enum AllocationError {
    Registry(fa_registry::RegistryError),
    Arithmetic(AmountError),
    Invalid(&'static str),
    Mismatch,
    Decode { field: &'static str, offset: usize },
}

impl fmt::Display for AllocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(error) => write!(f, "allocation registry: {error}"),
            Self::Arithmetic(error) => write!(f, "allocation arithmetic: {error}"),
            Self::Invalid(message) => write!(f, "invalid allocation: {message}"),
            Self::Decode { field, offset } => {
                write!(f, "truncated allocation {field} at byte {offset}")
            }
            Self::Mismatch => {
                write!(
                    f,
                    "allocation outcome differs from the requested law and basis"
                )
            }
        }
    }
}
impl core::error::Error for AllocationError {}
impl From<AmountError> for AllocationError {
    fn from(value: AmountError) -> Self {
        Self::Arithmetic(value)
    }
}
impl From<fa_registry::RegistryError> for AllocationError {
    fn from(value: fa_registry::RegistryError) -> Self {
        Self::Registry(value)
    }
}

/// The selected law and all of its runtime parameters. A residual recipient
/// is an explicit target identity; reordering targets never renames it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocationMethod {
    LargestRemainder,
    ProRataResidualToNamed {
        rounding: RoundingLaw,
        recipient: u128,
    },
    Waterfall,
    EqualSplitResidualFirst,
}

impl AllocationMethod {
    pub const fn law(self) -> AllocationLaw {
        match self {
            Self::LargestRemainder => AllocationLaw::LargestRemainder,
            Self::ProRataResidualToNamed { .. } => AllocationLaw::ProRataResidualToNamed,
            Self::Waterfall => AllocationLaw::Waterfall,
            Self::EqualSplitResidualFirst => AllocationLaw::EqualSplitResidualFirst,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllocationTarget {
    pub id: u128,
    /// Weight for proportional laws, native mantissa cap for Waterfall,
    /// exactly 1 for EqualSplitResidualFirst. Never a floating-point value.
    pub basis: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationRequest {
    pub total: Amount,
    pub method: AllocationMethod,
    pub targets: Vec<AllocationTarget>,
}

impl AllocationRequest {
    /// Execute only a registered implemented law. Unit identity/scale comes
    /// from the caller's unit registry; this pure layer never guesses a scale.
    pub fn execute(&self) -> Result<AllocationOutcome, AllocationError> {
        self.execute_with(&AllocationCatalog::embedded()?)
    }

    /// Use an already validated catalog, including its target-count policy.
    pub fn execute_with(
        &self,
        catalog: &AllocationCatalog,
    ) -> Result<AllocationOutcome, AllocationError> {
        self.validate_shape(catalog)?;
        let mut basis = Vec::new();
        basis
            .try_reserve_exact(self.targets.len())
            .map_err(|_| AmountError::Overflow)?;
        basis.extend(self.targets.iter().map(|target| target.basis));
        let (shares, pro_rata) = match self.method {
            AllocationMethod::LargestRemainder => (largest_remainder(self.total, &basis)?, None),
            AllocationMethod::Waterfall => (waterfall(self.total, &basis)?, None),
            AllocationMethod::EqualSplitResidualFirst => (
                equal_split_residual_first(self.total, self.targets.len())?,
                None,
            ),
            AllocationMethod::ProRataResidualToNamed {
                rounding,
                recipient,
            } => {
                let index = self
                    .targets
                    .iter()
                    .position(|target| target.id == recipient)
                    .ok_or(AllocationError::Invalid(
                        "residual recipient is not a target",
                    ))?;
                let result = pro_rata_residual_to_named(self.total, &basis, index, rounding)?;
                (result.shares.clone(), Some(result))
            }
        };
        // Independent signed-wide summation: a cancelling intermediate may
        // exceed i128 even when every share and the final total are valid.
        if shares.len() != self.targets.len() || !conserves(self.total, &shares)? {
            return Err(AllocationError::Mismatch);
        }
        Ok(AllocationOutcome {
            request: self.clone(),
            shares,
            pro_rata,
        })
    }

    pub fn validate_shape(&self, catalog: &AllocationCatalog) -> Result<(), AllocationError> {
        if self.targets.is_empty() || self.targets.len() > catalog.max_targets() {
            return Err(AllocationError::Invalid(
                "target count is outside the catalog bound",
            ));
        }
        let mut ids = BTreeSet::new();
        for target in &self.targets {
            if !ids.insert(target.id) {
                return Err(AllocationError::Invalid("duplicate target identity"));
            }
            if self.method == AllocationMethod::EqualSplitResidualFirst && target.basis != 1 {
                return Err(AllocationError::Invalid(
                    "equal split requires basis 1 for every target",
                ));
            }
        }
        if let AllocationMethod::ProRataResidualToNamed { recipient, .. } = self.method
            && !ids.contains(&recipient)
        {
            return Err(AllocationError::Invalid(
                "residual recipient is not a target",
            ));
        }
        Ok(())
    }
}

/// Only execution constructs an outcome. Its complete request and optional
/// signed rounding transcript remain available for storage and review.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationOutcome {
    request: AllocationRequest,
    shares: Vec<Amount>,
    pro_rata: Option<ProRataAllocation>,
}

impl AllocationOutcome {
    pub fn request(&self) -> &AllocationRequest {
        &self.request
    }
    /// Aligned with request.targets, including zero shares. Dropping zero
    /// targets would lose a part of the declared allocation basis.
    pub fn shares(&self) -> &[Amount] {
        &self.shares
    }
    pub fn pro_rata(&self) -> Option<&ProRataAllocation> {
        self.pro_rata.as_ref()
    }

    /// Recompute, do not merely compare totals or a checksum. `expected`
    /// comes independently from the recipient, not from untrusted output.
    pub fn verify_for(&self, expected: &AllocationRequest) -> Result<(), AllocationError> {
        if &self.request != expected || self != &expected.execute()? {
            return Err(AllocationError::Mismatch);
        }
        Ok(())
    }
}

fn conserves(total: Amount, shares: &[Amount]) -> Result<bool, AmountError> {
    let (mut positive, mut negative) = (U256::ZERO, U256::ZERO);
    for share in shares {
        if share.unit != total.unit {
            return Ok(false);
        }
        let slot = if share.mantissa < 0 {
            &mut negative
        } else {
            &mut positive
        };
        *slot = slot
            .checked_add(U256::from_u128(share.mantissa.unsigned_abs()))
            .ok_or(AmountError::Overflow)?;
    }
    let magnitude = U256::from_u128(total.mantissa.unsigned_abs());
    Ok(if total.mantissa < 0 {
        negative.checked_sub(positive) == Some(magnitude)
    } else {
        positive.checked_sub(negative) == Some(magnitude)
    })
}

#[cfg(test)]
mod tests;
