//! Functional-currency valuation of an entry's legs (plan §5.2, `base` and
//! `base-residual` clauses).
//!
//! Each monetary leg gets a `base_amount` = its amount converted at the rate
//! under the law, after checking exact native balance. The base sums differ
//! by at most `n × ½ ulp` for half laws, or less than `n ulp` for directed laws; that
//! difference is **not a leg**: it is absorbed into the valuation of one
//! designated converted leg — the largest base amount on the side that
//! needs it, ties by ordinal — so base-unit legs retain their at-par values,
//! no unit's per-unit balance is touched and the base
//! sums balance exactly.
//!
//! The counterexample that fixes the rule (fa-p7r): EUR `Dr 0.01, Dr 0.01 /
//! Cr 0.02` at a rate of ½ under `HalfUp` values to `Dr 0.01, Dr 0.01 /
//! Cr 0.01` in USD; the credit leg's valuation becomes `0.02` with
//! `residual {ordinal 2, +0.01}` recorded, EUR still balances, USD valuations
//! balance, and no USD leg exists.

use core::fmt;

use crate::amount::{Amount, AmountError, Side};
use crate::rate::{ArithmeticBudget, BudgetMeter, Rate};
use crate::rounding::RoundingLaw;
use crate::unit::{UnitId, UnitRegistry};
use crate::wide::U256;

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
    /// Native imbalance is not a rounding residual and cannot be absorbed.
    UnbalancedUnit {
        unit: UnitId,
    },
    /// The residual exceeded the selected law's bound.
    ResidualTooLarge {
        residual: i128,
        bound: i128,
    },
    /// No converted leg on the deficient side can absorb this law's residual.
    NoLegToAbsorb {
        law: RoundingLaw,
    },
    /// `value_legs` converts at a single foreign->base rate; multiple foreign
    /// units in one valuation call cannot share a single `Rate`.
    MultipleForeignUnits {
        first: UnitId,
        second: UnitId,
    },
}

impl fmt::Display for ValuationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Amount(e) => write!(f, "{e}"),
            Self::NegativeLeg { ordinal } => write!(f, "leg {ordinal} has a negative mantissa"),
            Self::UnbalancedUnit { unit } => write!(
                f,
                "native legs in {unit} do not balance; a valuation residual cannot repair them"
            ),
            Self::ResidualTooLarge { residual, bound } => {
                write!(f, "valuation residual {residual} exceeds bound {bound}")
            }
            Self::NoLegToAbsorb { law } => {
                write!(
                    f,
                    "no converted leg on the deficient side can absorb the {} residual",
                    law.name()
                )
            }
            Self::MultipleForeignUnits { first, second } => write!(
                f,
                "single-rate valuation cannot convert multiple foreign units ({first} and {second})"
            ),
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
/// Only converted legs may absorb a rounding residual: choose the largest
/// base amount on the deficient side, breaking ties by lowest original ordinal.
pub fn value_legs(
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    legs: &[LegValue],
    base: UnitId,
    rate: &Rate,
    law: RoundingLaw,
    reg: &UnitRegistry,
) -> Result<Valuation, ValuationError> {
    budget.checkpoint().map_err(AmountError::from)?;
    if reg.get(base).is_none() {
        return Err(AmountError::UnknownUnit(base.to_string()).into());
    }
    check_native_balance(budget, legs, base, reg)?;
    let bytes = legs
        .len()
        .checked_mul(core::mem::size_of::<Amount>())
        .ok_or(AmountError::Overflow)?;
    budget
        .reserve(u64::try_from(bytes).map_err(|_| AmountError::Overflow)?, 1)
        .map_err(AmountError::from)?;
    let mut base_amounts = Vec::new();
    base_amounts.try_reserve_exact(legs.len()).map_err(|_| {
        AmountError::Rate(crate::rate::RateError::Arithmetic(
            crate::rate::RationalArithmeticError::AllocationFailure,
        ))
    })?;
    let mut converted = 0usize;
    for (i, leg) in legs.iter().enumerate() {
        budget
            .charge(crate::rate::Dimension::ComputeSteps, 1)
            .map_err(AmountError::from)?;
        if leg.amount.mantissa < 0 {
            return Err(ValuationError::NegativeLeg { ordinal: i });
        }
        let b = if leg.amount.unit == base {
            leg.amount
        } else {
            converted += 1;
            leg.amount.convert(budget, base, rate, law, reg)?
        };
        base_amounts.push(b);
    }
    let mut debits = side_sum(base, legs, &base_amounts, Side::Debit)?;
    let mut credits = side_sum(base, legs, &base_amounts, Side::Credit)?;
    let diff = debits.checked_sub(credits)?.mantissa; // >0: credits short; <0: debits short
    let mut residual = None;
    if diff != 0 {
        // The residual is an integer. Half laws admit <= n/2, directed laws
        // admit strictly < n. Base-only entries admit no rounding residual.
        let bound = match law {
            RoundingLaw::Ceiling
            | RoundingLaw::Floor
            | RoundingLaw::TowardZero
            | RoundingLaw::AwayFromZero => converted.saturating_sub(1),
            _ => converted / 2,
        };
        let bound =
            i128::try_from(bound).map_err(|_| ValuationError::Amount(AmountError::Overflow))?;
        if diff.abs() > bound {
            return Err(ValuationError::ResidualTooLarge {
                residual: diff,
                bound,
            });
        }
        let deficient = if diff > 0 { Side::Credit } else { Side::Debit };
        // Base-unit legs stay at par. Among converted legs on the deficient
        // side, choose the largest base amount; ties by ordinal (lowest).
        let target = legs
            .iter()
            .enumerate()
            .filter(|(_, l)| l.side == deficient && l.amount.unit != base)
            .max_by(|(ia, _), (ib, _)| {
                base_amounts[*ia]
                    .mantissa
                    .cmp(&base_amounts[*ib].mantissa)
                    .then(ib.cmp(ia))
            })
            .map(|(i, _)| i)
            // Native balance with nonnegative legs makes this absence
            // unreachable for a nonzero residual; keep a law-naming refusal.
            .ok_or(ValuationError::NoLegToAbsorb { law })?;
        let adj = diff.abs();
        base_amounts[target] = base_amounts[target].checked_add(Amount::new(base, adj))?;
        residual = Some((target, adj));
        debits = side_sum(base, legs, &base_amounts, Side::Debit)?;
        credits = side_sum(base, legs, &base_amounts, Side::Credit)?;
    }
    debug_assert_eq!(debits, credits);
    budget.checkpoint().map_err(AmountError::from)?;
    Ok(Valuation {
        base_amounts,
        residual,
        base_debits: debits,
        base_credits: credits,
    })
}

// Native balance is sufficient for exact pre-rounding base balance: this
// helper applies the same linear rate to every leg in a given unit. Sort a
// bounded copy to avoid per-node allocations and order-dependent i128 sums.
fn check_native_balance(
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    legs: &[LegValue],
    base: UnitId,
    reg: &UnitRegistry,
) -> Result<(), ValuationError> {
    let bytes = legs
        .len()
        .checked_mul(core::mem::size_of::<LegValue>())
        .ok_or(AmountError::Overflow)?;
    budget
        .reserve(u64::try_from(bytes).map_err(|_| AmountError::Overflow)?, 1)
        .map_err(AmountError::from)?;
    let mut sorted = Vec::new();
    sorted.try_reserve_exact(legs.len()).map_err(|_| {
        AmountError::Rate(crate::rate::RateError::Arithmetic(
            crate::rate::RationalArithmeticError::AllocationFailure,
        ))
    })?;
    let mut foreign_unit: Option<UnitId> = None;
    for (ordinal, leg) in legs.iter().enumerate() {
        budget
            .charge(crate::rate::Dimension::ComputeSteps, 1)
            .map_err(AmountError::from)?;
        if leg.amount.mantissa < 0 {
            return Err(ValuationError::NegativeLeg { ordinal });
        }
        if reg.get(leg.amount.unit).is_none() {
            return Err(AmountError::UnknownUnit(leg.amount.unit.to_string()).into());
        }
        if leg.amount.unit != base {
            match foreign_unit {
                None => foreign_unit = Some(leg.amount.unit),
                Some(first) if first != leg.amount.unit => {
                    return Err(ValuationError::MultipleForeignUnits {
                        first,
                        second: leg.amount.unit,
                    });
                }
                Some(_) => {}
            }
        }
        sorted.push(*leg);
    }
    // Deterministic O(n log n) work admission before the allocation-free sort.
    let work = (legs.len() as u64)
        .checked_mul(u64::from(legs.len().checked_ilog2().unwrap_or(0)) + 1)
        .ok_or(AmountError::Overflow)?;
    budget
        .charge(crate::rate::Dimension::ComputeSteps, work)
        .map_err(AmountError::from)?;
    sorted.sort_unstable_by_key(|leg| leg.amount.unit);
    let mut start = 0;
    while start < sorted.len() {
        let unit = sorted[start].amount.unit;
        let mut debits = U256::ZERO;
        let mut credits = U256::ZERO;
        while start < sorted.len() && sorted[start].amount.unit == unit {
            budget
                .charge(crate::rate::Dimension::ComputeSteps, 1)
                .map_err(AmountError::from)?;
            let leg = sorted[start];
            let total = if leg.side == Side::Debit {
                &mut debits
            } else {
                &mut credits
            };
            *total = total
                .checked_add(U256::from_u128(leg.amount.mantissa as u128))
                .ok_or(AmountError::Overflow)?;
            start += 1;
        }
        if debits != credits {
            return Err(ValuationError::UnbalancedUnit { unit });
        }
    }
    Ok(())
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
    fn directed_rounding_accepts_its_larger_lawful_residual() {
        let cx = asupersync::Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        let rate = Rate::new(&mut budget, 99, 100).unwrap();
        let reg = UnitRegistry::with_defaults();
        let eur = reg.lookup("EUR").unwrap();
        let usd = reg.lookup("USD").unwrap();
        let mut legs = vec![
            LegValue {
                side: Side::Debit,
                amount: Amount::new(eur, 1)
            };
            5
        ];
        legs.push(LegValue {
            side: Side::Credit,
            amount: Amount::new(eur, 5),
        });
        let value = value_legs(&mut budget, &legs, usd, &rate, RoundingLaw::Floor, &reg).unwrap();
        assert_eq!(value.residual, Some((0, 4)));
        assert_eq!(value.base_debits.mantissa, 4);
        assert_eq!(value.base_debits, value.base_credits);
        assert_eq!(value.base_amounts.len(), legs.len());
    }

    #[test]
    fn native_imbalance_is_never_absorbed_as_rounding() {
        let cx = asupersync::Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        let rate = Rate::new(&mut budget, 1, 2).unwrap();
        let reg = UnitRegistry::with_defaults();
        let usd = reg.lookup("USD").unwrap();
        let eur = reg.lookup("EUR").unwrap();
        for unit in [usd, eur] {
            let legs = [
                LegValue {
                    side: Side::Debit,
                    amount: Amount::new(unit, 1),
                },
                LegValue {
                    side: Side::Credit,
                    amount: Amount::new(unit, 2),
                },
            ];
            for law in RoundingLaw::ALL {
                assert_eq!(
                    value_legs(&mut budget, &legs, usd, &rate, law, &reg),
                    Err(ValuationError::UnbalancedUnit { unit })
                );
            }
            let balanced = [
                legs[0],
                LegValue {
                    amount: legs[0].amount,
                    ..legs[1]
                },
            ];
            assert!(
                value_legs(
                    &mut budget,
                    &balanced,
                    usd,
                    &rate,
                    RoundingLaw::HalfEven,
                    &reg
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn fa_p7r_counterexample_balances_without_a_new_leg() {
        let cx = asupersync::Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        let half = Rate::new(&mut budget, 1, 2).unwrap();
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
        let v = value_legs(&mut budget, &legs, usd, &half, RoundingLaw::HalfUp, &reg).unwrap();
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
        let cx = asupersync::Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        let rate = Rate::from_decimal(&mut budget, "1.10").unwrap();
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
        let v = value_legs(&mut budget, &legs, usd, &rate, RoundingLaw::HalfEven, &reg).unwrap();
        assert_eq!(v.residual, None);
        assert_eq!(v.base_amounts[0].mantissa, 11_000);
    }

    #[test]
    fn mixed_base_and_foreign_legs_value_base_at_par() {
        let cx = asupersync::Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        let rate = Rate::from_decimal(&mut budget, "1.1").unwrap();
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
        let v = value_legs(&mut budget, &legs, usd, &rate, RoundingLaw::HalfEven, &reg).unwrap();
        assert_eq!(v.residual, None);
        assert_eq!(v.base_debits.mantissa, 220_000);
    }

    #[test]
    fn mixed_base_rounding_residual_preserves_at_par_valuations() {
        let cx = asupersync::Cx::detached_cancel_context();
        let reg = UnitRegistry::with_defaults();
        let eur = reg.lookup("EUR").unwrap();
        let usd = reg.lookup("USD").unwrap();
        for law in RoundingLaw::ALL {
            for swap_sides in [false, true] {
                let mut budget = crate::test_budget(&cx);
                let half = Rate::new(&mut budget, 1, 2).unwrap();
                let mut legs = [
                    LegValue {
                        side: Side::Debit,
                        amount: Amount::new(usd, 100),
                    },
                    LegValue {
                        side: Side::Credit,
                        amount: Amount::new(usd, 100),
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
                        amount: Amount::new(eur, 2),
                    },
                ];
                if swap_sides {
                    for leg in &mut legs {
                        leg.side = match leg.side {
                            Side::Debit => Side::Credit,
                            Side::Credit => Side::Debit,
                        };
                    }
                }
                let value = value_legs(&mut budget, &legs, usd, &half, law, &reg).unwrap();
                // The base-currency pair is larger than every converted leg.
                // Choosing it to absorb rounding would turn USD100 into USD101.
                assert_eq!(value.base_amounts[0], legs[0].amount, "{law:?}");
                assert_eq!(value.base_amounts[1], legs[1].amount, "{law:?}");
                assert_eq!(value.base_amounts.len(), legs.len());
                assert_eq!(value.base_debits, value.base_credits);
                let (ordinal, _) = value
                    .residual
                    .expect("this half-rate vector rounds unevenly");
                assert_eq!(legs[ordinal].amount.unit, eur);
                if law == RoundingLaw::HalfUp {
                    assert_eq!(value.residual, Some((4, 1)));
                    assert_eq!(
                        value.base_amounts,
                        [100, 100, 1, 1, 2].map(|mantissa| Amount::new(usd, mantissa))
                    );
                    assert_eq!(value.base_debits, Amount::new(usd, 102));
                }
            }
        }
    }

    #[test]
    fn residual_bound_is_enforced_and_sides_are_ordered() {
        let cx = asupersync::Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        let half = Rate::new(&mut budget, 1, 2).unwrap();
        let one = Rate::one(&mut budget).unwrap();
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
        let v = value_legs(&mut budget, &legs, usd, &half, RoundingLaw::HalfUp, &reg).unwrap();
        assert_eq!(v.residual, Some((3, 1)));
        assert_eq!(v.base_amounts[3].mantissa, 3);
        // Negative legs are refused before any arithmetic.
        let bad = [LegValue {
            side: Side::Debit,
            amount: Amount::new(eur, -1),
        }];
        assert_eq!(
            value_legs(&mut budget, &bad, usd, &one, RoundingLaw::HalfUp, &reg),
            Err(ValuationError::NegativeLeg { ordinal: 0 })
        );
    }

    #[test]
    fn multiple_foreign_units_are_refused_in_single_rate_valuation() {
        let cx = asupersync::Cx::detached_cancel_context();
        let reg = UnitRegistry::with_defaults();
        let usd = reg.lookup("USD").unwrap();
        let eur = reg.lookup("EUR").unwrap();
        let gbp = reg.lookup("GBP").unwrap();

        let eur_then_gbp = [
            LegValue {
                side: Side::Debit,
                amount: Amount::new(eur, 10_000),
            },
            LegValue {
                side: Side::Credit,
                amount: Amount::new(eur, 10_000),
            },
            LegValue {
                side: Side::Debit,
                amount: Amount::new(gbp, 5_000),
            },
            LegValue {
                side: Side::Credit,
                amount: Amount::new(gbp, 5_000),
            },
        ];
        let gbp_then_eur = [
            eur_then_gbp[2],
            eur_then_gbp[3],
            eur_then_gbp[0],
            eur_then_gbp[1],
        ];
        let zero_eur_then_gbp = [
            LegValue {
                side: Side::Debit,
                amount: Amount::new(eur, 0),
            },
            LegValue {
                side: Side::Credit,
                amount: Amount::new(eur, 0),
            },
            eur_then_gbp[2],
            eur_then_gbp[3],
        ];

        for law in RoundingLaw::ALL {
            let mut budget = crate::test_budget(&cx);
            let rate = Rate::from_decimal(&mut budget, "1.10").unwrap();
            assert_eq!(
                value_legs(&mut budget, &eur_then_gbp, usd, &rate, law, &reg),
                Err(ValuationError::MultipleForeignUnits {
                    first: eur,
                    second: gbp,
                })
            );
            assert_eq!(
                value_legs(&mut budget, &gbp_then_eur, usd, &rate, law, &reg),
                Err(ValuationError::MultipleForeignUnits {
                    first: gbp,
                    second: eur,
                })
            );
            assert_eq!(
                value_legs(&mut budget, &zero_eur_then_gbp, usd, &rate, law, &reg),
                Err(ValuationError::MultipleForeignUnits {
                    first: eur,
                    second: gbp,
                })
            );
        }
    }
}
