//! Functional-currency valuation of an entry's legs (plan §5.2, `base` and
//! `base-residual` clauses).
//!
//! Each monetary leg gets a `base_amount` = its amount converted at the rate
//! under the law. The two base sums will differ by at most `n × ½ ulp`; that
//! difference is **not a leg**: it is absorbed into the valuation of one
//! designated leg — the largest-base-amount leg on the side that needs it,
//! ties by ordinal — so no unit's per-unit balance is touched and the base
//! sums balance exactly.
//!
//! The counterexample that fixes the rule (fa-p7r): EUR `Dr 0.01, Dr 0.01 /
//! Cr 0.02` at a rate of ½ under `HalfUp` values to `Dr 0.01, Dr 0.01 /
//! Cr 0.01` in USD; the credit leg's valuation becomes `0.02` with
//! `residual {ordinal 2, +0.01}` recorded, EUR still balances, USD valuations
//! balance, and no USD leg exists.

use core::fmt;

use crate::amount::{Amount, AmountError, Side};
use crate::rate::Rate;
use crate::rounding::RoundingLaw;
use crate::unit::{UnitId, UnitRegistry};

/// One leg as valuation sees it: side and amount (non-negative mantissa).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegValue {
    pub side: Side,
    pub amount: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Valuation {
    /// Base amounts per leg, in leg order, after the residual is absorbed.
    pub base_amounts: Vec<Amount>,
    /// Which leg absorbed the residual, and by how much (signed, in base
    /// minor units; positive means that leg's valuation was increased).
    pub residual: Option<(usize, i128)>,
    pub base_debits: Amount,
    pub base_credits: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValuationError {
    Amount(AmountError),
    /// A leg had a negative mantissa; valuation only sees lawful legs.
    NegativeLeg {
        ordinal: usize,
    },
    /// The residual exceeded `n × ½ ulp`, which cannot happen under a half
    /// law; reported rather than absorbed so a wrong law is loud.
    ResidualTooLarge {
        residual: i128,
        bound: i128,
    },
    /// No leg on the deficient side can absorb the residual (empty side).
    NoLegToAbsorb,
}

impl fmt::Display for ValuationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Amount(e) => write!(f, "{e}"),
            Self::NegativeLeg { ordinal } => write!(f, "leg {ordinal} has a negative mantissa"),
            Self::ResidualTooLarge { residual, bound } => {
                write!(f, "valuation residual {residual} exceeds bound {bound}")
            }
            Self::NoLegToAbsorb => {
                f.write_str("no leg on the deficient side can absorb the residual")
            }
        }
    }
}

impl core::error::Error for ValuationError {}

impl From<AmountError> for ValuationError {
    fn from(e: AmountError) -> Self {
        Self::Amount(e)
    }
}

/// Value `legs` (all in one foreign unit) into `base` at `rate` (base units per
/// foreign unit) under `law`. Legs already in `base` are valued at 1:1.
pub fn value_legs(
    legs: &[LegValue],
    base: UnitId,
    rate: Rate,
    law: RoundingLaw,
    reg: &UnitRegistry,
) -> Result<Valuation, ValuationError> {
    let mut base_amounts = Vec::with_capacity(legs.len());
    let mut converted = 0usize;
    for (i, leg) in legs.iter().enumerate() {
        if leg.amount.mantissa < 0 {
            return Err(ValuationError::NegativeLeg { ordinal: i });
        }
        let b = if leg.amount.unit == base {
            leg.amount
        } else {
            converted += 1;
            leg.amount.convert(base, rate, law, reg)?
        };
        base_amounts.push(b);
    }
    let mut debits = side_sum(base, legs, &base_amounts, Side::Debit)?;
    let mut credits = side_sum(base, legs, &base_amounts, Side::Credit)?;
    let diff = debits.checked_sub(credits)?.mantissa; // >0: credits short; <0: debits short
    let mut residual = None;
    if diff != 0 {
        // Bound: n × ½ ulp, where n is the number of converted legs. In minor
        // units ½ ulp is ½, so |diff| <= ceil(n/2).
        let bound = i128::try_from(converted.div_ceil(2))
            .map_err(|_| ValuationError::Amount(AmountError::Overflow))?;
        if diff.abs() > bound.max(1) {
            return Err(ValuationError::ResidualTooLarge {
                residual: diff,
                bound,
            });
        }
        let deficient = if diff > 0 { Side::Credit } else { Side::Debit };
        // Largest base amount on the deficient side; ties by ordinal (lowest).
        let target = legs
            .iter()
            .enumerate()
            .filter(|(_, l)| l.side == deficient)
            .max_by(|(ia, _), (ib, _)| {
                base_amounts[*ia]
                    .mantissa
                    .cmp(&base_amounts[*ib].mantissa)
                    .then(ib.cmp(ia))
            })
            .map(|(i, _)| i)
            .ok_or(ValuationError::NoLegToAbsorb)?;
        let adj = diff.abs();
        base_amounts[target] = base_amounts[target].checked_add(Amount::new(base, adj))?;
        residual = Some((target, adj));
        debits = side_sum(base, legs, &base_amounts, Side::Debit)?;
        credits = side_sum(base, legs, &base_amounts, Side::Credit)?;
    }
    debug_assert_eq!(debits, credits);
    Ok(Valuation {
        base_amounts,
        residual,
        base_debits: debits,
        base_credits: credits,
    })
}

fn side_sum(
    base: UnitId,
    legs: &[LegValue],
    base_amounts: &[Amount],
    side: Side,
) -> Result<Amount, AmountError> {
    Amount::sum(
        base,
        legs.iter()
            .zip(base_amounts)
            .filter(|(l, _)| l.side == side)
            .map(|(_, b)| *b),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fa_p7r_counterexample_balances_without_a_new_leg() {
        let reg = UnitRegistry::with_defaults();
        let eur = reg.lookup("EUR").unwrap();
        let usd = reg.lookup("USD").unwrap();
        let legs = [
            LegValue {
                side: Side::Debit,
                amount: Amount::new(eur, 1),
            },
            LegValue {
                side: Side::Debit,
                amount: Amount::new(eur, 1),
            },
            LegValue {
                side: Side::Credit,
                amount: Amount::new(eur, 2),
            },
        ];
        // EUR per-unit balance holds before valuation: 1 + 1 = 2.
        let v = value_legs(
            &legs,
            usd,
            Rate::new(1, 2).unwrap(),
            RoundingLaw::HalfUp,
            &reg,
        )
        .unwrap();
        // Naive: Dr 0.01 (0.005 -> HalfUp 0.01), Dr 0.01, Cr 0.01 -> credits short by 0.01.
        assert_eq!(v.base_amounts[0].mantissa, 1);
        assert_eq!(v.base_amounts[1].mantissa, 1);
        assert_eq!(
            v.base_amounts[2].mantissa, 2,
            "the credit leg absorbed the residual"
        );
        assert_eq!(v.residual, Some((2, 1)));
        assert_eq!(v.base_debits, v.base_credits);
        assert_eq!(v.base_debits.mantissa, 2);
        assert_eq!(v.base_amounts.len(), 3, "no leg was added");
    }

    #[test]
    fn exact_rates_leave_no_residual() {
        let reg = UnitRegistry::with_defaults();
        let eur = reg.lookup("EUR").unwrap();
        let usd = reg.lookup("USD").unwrap();
        let legs = [
            LegValue {
                side: Side::Debit,
                amount: Amount::new(eur, 10_000),
            },
            LegValue {
                side: Side::Credit,
                amount: Amount::new(eur, 10_000),
            },
        ];
        let v = value_legs(
            &legs,
            usd,
            Rate::from_decimal("1.10").unwrap(),
            RoundingLaw::HalfEven,
            &reg,
        )
        .unwrap();
        assert_eq!(v.residual, None);
        assert_eq!(v.base_amounts[0].mantissa, 11_000);
    }

    #[test]
    fn mixed_base_and_foreign_legs_value_base_at_par() {
        let reg = UnitRegistry::with_defaults();
        let eur = reg.lookup("EUR").unwrap();
        let usd = reg.lookup("USD").unwrap();
        // Dr Cash USD 1,100 / Cr Conversion USD 1,100 ; Dr Conversion EUR 1,000 / Cr AR EUR 1,000 — at 1.1 exactly
        let legs = [
            LegValue {
                side: Side::Debit,
                amount: Amount::new(usd, 110_000),
            },
            LegValue {
                side: Side::Credit,
                amount: Amount::new(usd, 110_000),
            },
            LegValue {
                side: Side::Debit,
                amount: Amount::new(eur, 100_000),
            },
            LegValue {
                side: Side::Credit,
                amount: Amount::new(eur, 100_000),
            },
        ];
        let v = value_legs(
            &legs,
            usd,
            Rate::from_decimal("1.1").unwrap(),
            RoundingLaw::HalfEven,
            &reg,
        )
        .unwrap();
        assert_eq!(v.residual, None);
        assert_eq!(v.base_debits.mantissa, 220_000);
    }

    #[test]
    fn residual_bound_is_enforced_and_sides_are_ordered() {
        let reg = UnitRegistry::with_defaults();
        let eur = reg.lookup("EUR").unwrap();
        let usd = reg.lookup("USD").unwrap();
        // Three debit legs of 0.01 and one credit of 0.03 at 1/2 HalfUp:
        // debits 0.01 x3 = 0.03, credit 0.015 -> 0.02: credits short by 0.01, bound ceil(4/2)=2 -> absorbed by the credit leg.
        let legs = [
            LegValue {
                side: Side::Debit,
                amount: Amount::new(eur, 1),
            },
            LegValue {
                side: Side::Debit,
                amount: Amount::new(eur, 1),
            },
            LegValue {
                side: Side::Debit,
                amount: Amount::new(eur, 1),
            },
            LegValue {
                side: Side::Credit,
                amount: Amount::new(eur, 3),
            },
        ];
        let v = value_legs(
            &legs,
            usd,
            Rate::new(1, 2).unwrap(),
            RoundingLaw::HalfUp,
            &reg,
        )
        .unwrap();
        assert_eq!(v.residual, Some((3, 1)));
        assert_eq!(v.base_amounts[3].mantissa, 3);
        // Negative legs are refused before any arithmetic.
        let bad = [LegValue {
            side: Side::Debit,
            amount: Amount::new(eur, -1),
        }];
        assert_eq!(
            value_legs(&bad, usd, Rate::ONE, RoundingLaw::HalfUp, &reg),
            Err(ValuationError::NegativeLeg { ordinal: 0 })
        );
    }
}
