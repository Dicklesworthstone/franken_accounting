//! Independent, offline verification of an Allocation entry and its driver.
//!
//! The recipient supplies a trusted checkpoint, an expected entry digest and
//! the exact expected Workpaper bytes. Inclusion authenticates the proposal;
//! a separate std-only arithmetic implementation recomputes every leg from
//! those bytes, including residual direction, target order and zero shares.
//! The proposal must cite the exact Workpaper under its book-scoped identity.
//!
//! This proves inclusion, native allocation arithmetic and citation binding.
//! It does NOT establish driver truth, uploader/reviewer provenance, account
//! existence or effectivity, capability/approval validity, period admission,
//! limits, later reversals, unit definitions, completeness or signatures.
//! A driver is confidential source data; the result retains it in decoded form.

mod arithmetic;
mod basis;
mod entry;

use super::authenticated_entry;
use crate::codec::DecodeError;
use crate::evidence::{EvidenceCitation, EvidenceError};
use crate::{Checkpoint, Inclusion};
use core::fmt;

pub use basis::{AllocationBasis, AllocationTarget};

/// Existing entry extension ceiling minus its fixed record framing.
pub const MAX_BASIS_BYTES: usize = 64 * 1024 - 84;
pub const MAX_TARGETS: usize = 1024;
/// Combined bound, not a fresh allowance for each caller-provided artifact.
pub const MAX_ALLOCATION_INPUT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AllocationError {
    Evidence(EvidenceError),
    Decode(DecodeError),
    InputLimit,
    Invalid(&'static str),
    Arithmetic,
    BasisMismatch,
    LegMismatch { ordinal: usize },
    DriverMissing,
}

impl fmt::Display for AllocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evidence(error) => write!(f, "{error}"),
            Self::Decode(error) => write!(f, "{error}"),
            Self::InputLimit => write!(
                f,
                "allocation input or allocation capacity exceeds its bound"
            ),
            Self::Invalid(why) => write!(f, "invalid allocation: {why}"),
            Self::Arithmetic => write!(
                f,
                "allocation does not conserve a representable journal turnover"
            ),
            Self::BasisMismatch => write!(
                f,
                "allocation does not bind the recipient's exact driver and law"
            ),
            Self::LegMismatch { ordinal } => write!(
                f,
                "allocation leg {ordinal} differs from independent recomputation"
            ),
            Self::DriverMissing => write!(
                f,
                "entry does not cite the exact driver Workpaper as Source evidence"
            ),
        }
    }
}
impl core::error::Error for AllocationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Evidence(error) => Some(error),
            Self::Decode(error) => Some(error),
            _ => None,
        }
    }
}
impl From<EvidenceError> for AllocationError {
    fn from(error: EvidenceError) -> Self {
        Self::Evidence(error)
    }
}
impl From<DecodeError> for AllocationError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

/// A complete result: no partially verified allocation is returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAllocation {
    /// Existing cryptographic scope remains `inclusion`.
    pub inclusion: Inclusion,
    pub basis: AllocationBasis,
    /// Signed native mantissas aligned with EVERY target, including zero shares.
    pub shares: Vec<i128>,
    pub law_digest: [u8; 32],
    pub basis_digest: [u8; 32],
    pub driver: EvidenceCitation,
}

/// Verify a record-bearing inclusion proof against recipient-owned inputs.
/// No request selector is taken from the untrusted proof as an authority.
/// Unknown future formats fail closed. This performs no I/O and imports no
/// producer, journal, money, substrate, runtime or external numeric crate.
pub fn verify_allocation_for(
    proof: &[u8],
    checkpoint: &Checkpoint,
    expected_entry_digest: &[u8; 32],
    expected_basis: &[u8],
) -> Result<VerifiedAllocation, AllocationError> {
    if proof
        .len()
        .checked_add(expected_basis.len())
        .is_none_or(|size| size > MAX_ALLOCATION_INPUT_BYTES)
    {
        return Err(AllocationError::InputLimit);
    }
    let basis = AllocationBasis::decode(expected_basis)?;
    let shares = basis.shares()?;
    let (inclusion, proposal) = authenticated_entry(proof, checkpoint, expected_entry_digest)?;
    let law_digest = law_digest(basis.law);
    let basis_digest = basis_digest(expected_basis);
    let driver = entry::verify(proposal, checkpoint, expected_basis, &basis, &shares)?;
    Ok(VerifiedAllocation {
        inclusion,
        basis,
        shares,
        law_digest,
        basis_digest,
        driver,
    })
}

fn law_digest(law: u16) -> [u8; 32] {
    crate::blake3::hash_parts(
        b"fa:allocation-law:v1",
        &[
            &2u32.to_le_bytes(),
            &law.to_le_bytes(),
            &2u32.to_le_bytes(),
            &1u16.to_le_bytes(),
        ],
    )
}
fn basis_digest(bytes: &[u8]) -> [u8; 32] {
    // The public callers have admitted the <=64 KiB bound before this cast.
    crate::blake3::hash_parts(
        b"fa:allocation-basis:v1",
        &[&(bytes.len() as u32).to_le_bytes(), bytes],
    )
}

#[cfg(test)]
mod tests;
