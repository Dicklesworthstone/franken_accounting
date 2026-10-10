//! Abacus — FrankenAccounting's exact money algebra (plan §6).
//!
//! Laws this crate makes structural:
//!
//! - An amount is `Amount { unit, mantissa: i128 }` at the unit's **immutable**
//!   registered scale (§4.4). There is no per-amount exponent, so equality,
//!   ordering, hashing, and summation are integer operations.
//! - Arithmetic is checked. Overflow is an error, never a wrap and never a
//!   silent saturation. Integer algebra identities apply only when every
//!   required intermediate and result is representable (§6.1); checked
//!   operations on bounded amounts are partial, not a closed group.
//! - Multiplication by a rate and conversion between units go through exact
//!   metered arbitrary-precision intermediates and are then rounded **under a named law** (§6.2).
//!   No floating-point type appears anywhere in this crate.
//! - Allocation conserves totals exactly (§6.3); valuation into the functional
//!   currency balances exactly by absorbing the rounding residual into one
//!   designated leg rather than inventing a leg (§5.2).
//!
//! FrankenSymPy supplies exact rates; a Cx-backed meter bounds work and
//! observes cancellation. `fgdb-bigint` is an independent test-only
//! differential oracle. The reference engine (`fa-reference`) carries its
//! own arithmetic so a bug here cannot make a differential green.

#![forbid(unsafe_code)]

pub mod allocation;
pub mod amount;
pub mod rate;
pub mod rounding;
pub mod unit;
pub mod valuation;
pub mod wide;

pub use allocation::largest_remainder;
pub use amount::{Amount, AmountError, Side};
pub use rate::{ArithmeticBudget, BudgetLimits, Rate, RateError};
pub use rounding::RoundingLaw;
pub use unit::{Unit, UnitError, UnitId, UnitKind, UnitRegistry};
pub use valuation::{Valuation, ValuationError, value_legs};

#[cfg(test)]
fn test_budget<Caps>(cx: &asupersync::Cx<Caps>) -> ArithmeticBudget<'_, Caps> {
    ArithmeticBudget::new(cx, BudgetLimits::uniform(1_000_000_000, 0), 8192)
}
