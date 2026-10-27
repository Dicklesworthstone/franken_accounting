//! A registered balanced proportional sub-vector of a monetary hold (§5.4).
//!
//! Round one common debit/credit total per `(unit, normalized legal entity)`,
//! then allocate that same target independently over each side by largest
//! remainder. Ties follow the original leg ordinal. This preserves each
//! native partition and each original capacity; the surrounding posting
//! kernel still checks all other dimensions, valuations and lifecycle laws.
//! Zero shares are omitted from the posted mapping and remain fully released.
//! An entirely empty result is refused: release must name `VoidReserve`.

mod catalog;
mod receipt;

pub use catalog::{MAX_PROPORTIONAL_POST_LEGS, ProportionalPostCatalog};
pub use receipt::{
    MAX_PROPORTIONAL_POST_RATE_BYTES, MAX_PROPORTIONAL_POST_RECEIPT_BYTES,
    MAX_PROPORTIONAL_POST_REQUEST_BYTES,
};

use std::collections::BTreeMap;

use crate::rate::{BudgetMeter, Dimension, MeterError};
use crate::wide::U256;
use crate::{Amount, AmountError, ArithmeticBudget, Rate, RateError, RoundingLaw, Side, UnitId};

/// Stable compiled law identity, independent of a caller's default rounding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProportionalPostLaw {
    BalancedLargestRemainder,
}

impl ProportionalPostLaw {
    pub const ALL: [Self; 1] = [Self::BalancedLargestRemainder];

    pub const fn id(self) -> u16 {
        1
    }
    pub const fn version(self) -> u16 {
        1
    }
    pub const fn name(self) -> &'static str {
        "BalancedLargestRemainder"
    }
    pub const fn rounding(self) -> RoundingLaw {
        RoundingLaw::HalfEven
    }

    pub fn from_id(id: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|law| law.id() == id)
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|law| law.name() == name)
    }
}

/// Arithmetic basis extracted from the authenticated pending entry. The
/// caller normalizes an omitted legal entity to the book's sole entity.
/// Account identity, dimensions and source digest stay bound by that entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldLeg {
    pub source_ordinal: u16,
    pub amount: Amount,
    pub side: Side,
    pub legal_entity: Option<u128>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProportionalPostRequest {
    pub law: ProportionalPostLaw,
    pub rate: Rate,
    /// Positive monetary legs, strictly ascending by original ordinal.
    pub legs: Vec<HeldLeg>,
}

/// One original leg's exact rounding and release transcript. The fractional
/// share is `floor + remainder_numerator / partition.held`; a one-unit
/// increment belongs only to a largest remainder winner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProportionalPostLeg {
    pub source_ordinal: u16,
    pub floor: Amount,
    pub remainder_numerator: u128,
    pub rounding_increment: u8,
    pub posted: Amount,
    pub released: Amount,
}

/// The common per-side pending, posted and released totals for one native
/// partition. No amount in one unit or entity subsidizes another partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProportionalPostPartition {
    pub unit: UnitId,
    pub legal_entity: Option<u128>,
    pub held: i128,
    pub posted: i128,
    pub released: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProportionalPostOutcome {
    request: ProportionalPostRequest,
    legs: Vec<ProportionalPostLeg>,
    partitions: Vec<ProportionalPostPartition>,
}

impl ProportionalPostOutcome {
    pub fn request(&self) -> &ProportionalPostRequest {
        &self.request
    }
    pub fn legs(&self) -> &[ProportionalPostLeg] {
        &self.legs
    }
    pub fn partitions(&self) -> &[ProportionalPostPartition] {
        &self.partitions
    }

    /// The canonical posted sub-vector, preserving source ordinals even when
    /// intervening legs round to zero. All original legs remain in `legs()`.
    pub fn posted_legs(&self) -> impl Iterator<Item = &ProportionalPostLeg> {
        self.legs.iter().filter(|leg| leg.posted.mantissa > 0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProportionalPostError {
    Invalid(&'static str),
    RateOutOfRange,
    Unbalanced {
        unit: UnitId,
        legal_entity: Option<u128>,
        debits: i128,
        credits: i128,
    },
    EmptyResult,
    Mismatch,
    Amount(AmountError),
    Rate(RateError),
    Registry(fa_registry::RegistryError),
}

impl core::fmt::Display for ProportionalPostError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid proportional post: {reason}"),
            Self::RateOutOfRange => f.write_str("ProportionalPost requires an exact rate in [0,1]"),
            Self::Unbalanced { unit, legal_entity, debits, credits } => write!(f,
                "pending partition unit {} entity {legal_entity:?} has debits {debits} and credits {credits}", unit.0),
            Self::EmptyResult => f.write_str("ProportionalPost has no valid nonzero posted sub-vector; use VoidReserve to release the hold"),
            Self::Mismatch => f.write_str("proportional post receipt differs from the independently selected request and its exact computation"),
            Self::Amount(error) => error.fmt(f),
            Self::Rate(error) => error.fmt(f),
            Self::Registry(error) => error.fmt(f),
        }
    }
}
impl core::error::Error for ProportionalPostError {}
impl From<AmountError> for ProportionalPostError {
    fn from(error: AmountError) -> Self {
        Self::Amount(error)
    }
}
impl From<RateError> for ProportionalPostError {
    fn from(error: RateError) -> Self {
        Self::Rate(error)
    }
}
impl From<MeterError> for ProportionalPostError {
    fn from(error: MeterError) -> Self {
        Self::Rate(error.into())
    }
}
impl From<fa_registry::RegistryError> for ProportionalPostError {
    fn from(error: fa_registry::RegistryError) -> Self {
        Self::Registry(error)
    }
}

#[derive(Default)]
struct Partition {
    debits: i128,
    credits: i128,
    debit_indices: Vec<usize>,
    credit_indices: Vec<usize>,
}

impl ProportionalPostRequest {
    fn validate_shape(
        &self,
        budget: &mut ArithmeticBudget<'_, impl Sized>,
        catalog: &ProportionalPostCatalog,
    ) -> Result<usize, ProportionalPostError> {
        budget.checkpoint()?;
        if !(2..=catalog.max_legs()).contains(&self.legs.len()) {
            return Err(ProportionalPostError::Invalid(
                "a hold needs 2..=4096 original monetary legs",
            ));
        }
        if self
            .legs
            .windows(2)
            .any(|pair| pair[0].source_ordinal >= pair[1].source_ordinal)
        {
            return Err(ProportionalPostError::Invalid(
                "source ordinals must be strictly ascending and unique",
            ));
        }
        if self.legs.iter().any(|leg| leg.amount.mantissa <= 0) {
            return Err(ProportionalPostError::Invalid(
                "every reserved monetary amount must be positive",
            ));
        }
        // Bound arbitrary-precision coefficients before encoding or cloning
        // them, even when the caller supplies a looser arithmetic budget.
        let numerator_bytes = usize::try_from(self.rate.numerator().bits().div_ceil(8))
            .map_err(|_| AmountError::Overflow)?;
        let denominator_bytes = usize::try_from(self.rate.denominator().bits().div_ceil(8))
            .map_err(|_| AmountError::Overflow)?;
        let rate_bytes = numerator_bytes
            .checked_add(denominator_bytes)
            .and_then(|n| n.checked_add(12))
            .ok_or(AmountError::Overflow)?;
        if rate_bytes > MAX_PROPORTIONAL_POST_RATE_BYTES {
            return Err(ProportionalPostError::Invalid(
                "rate exceeds the proportional post byte bound",
            ));
        }
        let one = Rate::one(budget)?;
        if self.rate.metered_cmp(budget, &one)?.is_gt() {
            return Err(ProportionalPostError::RateOutOfRange);
        }
        Ok(rate_bytes)
    }

    pub fn execute(
        &self,
        budget: &mut ArithmeticBudget<'_, impl Sized>,
    ) -> Result<ProportionalPostOutcome, ProportionalPostError> {
        let catalog = ProportionalPostCatalog::embedded()?;
        let rate_bytes = self.validate_shape(budget, &catalog)?;
        let count = u64::try_from(self.legs.len()).map_err(|_| AmountError::Overflow)?;
        // Fixed bounded-width work includes partitioning, both side sorts,
        // allocation and transcripts; exact rate operations charge separately.
        budget.charge(
            Dimension::ComputeSteps,
            count.checked_mul(64).ok_or(AmountError::Overflow)?,
        )?;
        let rate_memory = u64::try_from(rate_bytes)
            .map_err(|_| AmountError::Overflow)?
            .checked_mul(2)
            .ok_or(AmountError::Overflow)?;
        budget.reserve(
            count
                .checked_mul(1024)
                .and_then(|n| n.checked_add(rate_memory))
                .ok_or(AmountError::Overflow)?,
            count
                .checked_mul(8)
                .and_then(|n| n.checked_add(4))
                .ok_or(AmountError::Overflow)?,
        )?;
        let mut partitions = BTreeMap::<(UnitId, Option<u128>), Partition>::new();
        let mut results = Vec::new();
        results
            .try_reserve_exact(self.legs.len())
            .map_err(|_| AmountError::Overflow)?;
        for (index, leg) in self.legs.iter().enumerate() {
            let partition = partitions
                .entry((leg.amount.unit, leg.legal_entity))
                .or_default();
            let (total, indices) = match leg.side {
                Side::Debit => (&mut partition.debits, &mut partition.debit_indices),
                Side::Credit => (&mut partition.credits, &mut partition.credit_indices),
            };
            *total = total
                .checked_add(leg.amount.mantissa)
                .ok_or(AmountError::Overflow)?;
            indices.push(index);
            results.push(ProportionalPostLeg {
                source_ordinal: leg.source_ordinal,
                floor: Amount::zero(leg.amount.unit),
                remainder_numerator: 0,
                rounding_increment: 0,
                posted: Amount::zero(leg.amount.unit),
                released: leg.amount,
            });
        }
        let mut summaries = Vec::new();
        summaries
            .try_reserve_exact(partitions.len())
            .map_err(|_| AmountError::Overflow)?;
        for ((unit, legal_entity), partition) in partitions {
            budget.checkpoint()?;
            if partition.debits != partition.credits {
                return Err(ProportionalPostError::Unbalanced {
                    unit,
                    legal_entity,
                    debits: partition.debits,
                    credits: partition.credits,
                });
            }
            let common = partition.debits;
            let target =
                Amount::new(unit, common).mul_rate(budget, &self.rate, self.law.rounding())?;
            if target.mantissa < 0 || target.mantissa > common {
                return Err(ProportionalPostError::Invalid(
                    "rounded partition target exceeds pending capacity",
                ));
            }
            for indices in [&partition.debit_indices, &partition.credit_indices] {
                budget.checkpoint()?;
                let weights: Vec<_> = indices
                    .iter()
                    .map(|index| self.legs[*index].amount.mantissa.unsigned_abs())
                    .collect();
                let shares = crate::largest_remainder(target, &weights)?;
                for (index, posted) in indices.iter().copied().zip(shares) {
                    let reserved = self.legs[index].amount;
                    if posted.mantissa < 0 || posted.mantissa > reserved.mantissa {
                        return Err(ProportionalPostError::Invalid(
                            "allocation exceeds an original leg's capacity",
                        ));
                    }
                    let (floor, remainder) = U256::from_u128(target.mantissa.unsigned_abs())
                        .checked_mul_u128(reserved.mantissa.unsigned_abs())
                        .ok_or(AmountError::Overflow)?
                        .checked_div_rem(U256::from_u128(common.unsigned_abs()))
                        .ok_or(AmountError::InvariantViolation("empty pending partition"))?;
                    let floor = i128::try_from(floor.to_u128().ok_or(AmountError::Overflow)?)
                        .map_err(|_| AmountError::Overflow)?;
                    let increment = posted
                        .mantissa
                        .checked_sub(floor)
                        .ok_or(AmountError::Overflow)?;
                    if !(0..=1).contains(&increment) {
                        return Err(ProportionalPostError::Invalid(
                            "largest remainder correction exceeds one native unit",
                        ));
                    }
                    results[index] = ProportionalPostLeg {
                        source_ordinal: self.legs[index].source_ordinal,
                        floor: Amount::new(unit, floor),
                        remainder_numerator: remainder.to_u128().ok_or(AmountError::Overflow)?,
                        rounding_increment: u8::try_from(increment)
                            .map_err(|_| AmountError::Overflow)?,
                        posted,
                        released: reserved.checked_sub(posted)?,
                    };
                }
            }
            summaries.push(ProportionalPostPartition {
                unit,
                legal_entity,
                held: common,
                posted: target.mantissa,
                released: common
                    .checked_sub(target.mantissa)
                    .ok_or(AmountError::Overflow)?,
            });
        }
        if results.iter().filter(|leg| leg.posted.mantissa > 0).count() < 2 {
            return Err(ProportionalPostError::EmptyResult);
        }
        budget.checkpoint()?;
        Ok(ProportionalPostOutcome {
            request: self.clone(),
            legs: results,
            partitions: summaries,
        })
    }
}

#[cfg(test)]
mod tests;
