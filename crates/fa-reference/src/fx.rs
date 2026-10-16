//! Independent reference oracle for multi-currency FX valuation, residual
//! bounds, realized FX paired conversion postings, and functional-value
//! register folds (plan §5.2, §5.3, §6.4; bead `fa-s3c`; `FA-INV-01.base`,
//! `FA-INV-01.base-residual`, `FA-INV-01.realized-fx`,
//! `FA-INV-04.functional-fold`).
//!
//! Boundary: `std` and `crate::Int` limb arithmetic only — no `fa-money`,
//! no `fa-model`, no substrate.

use std::collections::{BTreeMap, BTreeSet};

use crate::{Int, Side};

/// Rate quote in the reference oracle: `rate_num / rate_den` base units per
/// quote (foreign) unit, with explicit unit scales and rounding law name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleRateQuote {
    pub quote_unit: u32,
    pub quote_scale: u8,
    pub rate_num: u128,
    pub rate_den: u128,
    pub rounding_law: String,
}

/// Input leg to the reference FX valuation oracle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleFxLeg {
    pub side: Side,
    pub account: u128,
    pub unit: u32,
    pub mantissa: i128,
    pub entity: Option<String>,
}

/// Output of the reference FX valuation oracle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleValuation {
    pub base_mantissas: Vec<i128>,
    pub base_debits: i128,
    pub base_credits: i128,
    /// `(leg_ordinal, absorbed_base_mantissa)` if a rounding residual was absorbed.
    pub residual: Option<(u16, i128)>,
}

/// Valued leg for realized FX and functional fold checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleRealizedLeg {
    pub side: Side,
    pub account: u128,
    pub unit: u32,
    pub mantissa: i128,
    pub base_unit: u32,
    pub base_mantissa: i128,
    pub entity: Option<String>,
}

/// Committed entry for the functional-value register fold oracle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleFunctionalEntry {
    pub period: String,
    pub is_pending: bool,
    pub is_resolved: bool,
    pub legs: Vec<OracleRealizedLeg>,
}

fn pow10(exp: u8) -> Int {
    let mut out = Int::from_u128(1);
    let ten = Int::from_u128(10);
    for _ in 0..exp {
        out = out.mul(&ten);
    }
    out
}

/// Independent rational conversion using [`Int`] limb arithmetic and the
/// named rounding law (`HalfEven`, `HalfUp`, `HalfDown`, `HalfAwayFromZero`,
/// `HalfTowardZero`, `Ceiling`, `Floor`, `TowardZero`, `AwayFromZero`, `Exact`).
pub fn round_convert(
    mantissa: i128,
    from_scale: u8,
    to_scale: u8,
    rate_num: u128,
    rate_den: u128,
    rounding_law: &str,
) -> Result<i128, String> {
    if mantissa < 0 {
        return Err("negative mantissa is not admissible on a leg".into());
    }
    if rate_num == 0 || rate_den == 0 {
        return Err("rate numerator and denominator must be positive".into());
    }
    let m = Int::from_i128(mantissa);
    let r_num = Int::from_u128(rate_num);
    let r_den = Int::from_u128(rate_den);

    let (num_scale, den_scale) = if to_scale >= from_scale {
        (pow10(to_scale - from_scale), Int::from_u128(1))
    } else {
        (Int::from_u128(1), pow10(from_scale - to_scale))
    };

    let numer = m.mul(&r_num).mul(&num_scale);
    let denom = r_den.mul(&den_scale);
    let (q, rem) = numer
        .div_rem(&denom)
        .ok_or_else(|| "zero denominator in FX conversion".to_string())?;

    if rem.is_zero() {
        return q
            .to_i128()
            .ok_or_else(|| "converted mantissa overflowed i128".to_string());
    }

    let two_rem = rem.mul(&Int::from_u128(2));
    let cmp_half = two_rem.cmp(&denom);
    let one = Int::from_u128(1);

    let increment = match rounding_law {
        "Exact" => return Err("inexact FX conversion under Exact rounding law".into()),
        "TowardZero" | "Floor" => false,
        "AwayFromZero" | "Ceiling" => true,
        "HalfUp" | "HalfAwayFromZero" => cmp_half != core::cmp::Ordering::Less,
        "HalfDown" | "HalfTowardZero" => cmp_half == core::cmp::Ordering::Greater,
        "HalfEven" => match cmp_half {
            core::cmp::Ordering::Less => false,
            core::cmp::Ordering::Greater => true,
            core::cmp::Ordering::Equal => {
                let (_, q_mod_2) = q.div_rem(&Int::from_u128(2)).unwrap();
                !q_mod_2.is_zero()
            }
        },
        other => return Err(format!("unknown rounding law `{other}`")),
    };

    let rounded = if increment { q.add(&one) } else { q };
    rounded
        .to_i128()
        .ok_or_else(|| "rounded mantissa overflowed i128".to_string())
}

/// Independently value an entry's legs per legal entity and foreign unit,
/// checking native balance and absorbing any rounding residual within its
/// entity and within the law's exact bound (`FA-INV-01.base`,
/// `FA-INV-01.base-residual`).
pub fn value_entity_legs(
    legs: &[OracleFxLeg],
    base_unit: u32,
    base_scale: u8,
    rates: &BTreeMap<u32, OracleRateQuote>,
) -> Result<OracleValuation, String> {
    let mut by_entity: BTreeMap<Option<String>, Vec<usize>> = BTreeMap::new();
    for (idx, leg) in legs.iter().enumerate() {
        if leg.mantissa <= 0 {
            return Err(format!("leg {idx} has non-positive mantissa"));
        }
        by_entity.entry(leg.entity.clone()).or_default().push(idx);
    }

    let mut base_mantissas = vec![0i128; legs.len()];
    let mut total_debits = 0i128;
    let mut total_credits = 0i128;
    let mut recorded_residual: Option<(u16, i128)> = None;

    for (entity, indices) in by_entity {
        let mut by_unit: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        for &idx in &indices {
            by_unit.entry(legs[idx].unit).or_default().push(idx);
        }

        for (unit, u_indices) in by_unit {
            let mut n_debits = 0i128;
            let mut n_credits = 0i128;
            for &idx in &u_indices {
                match legs[idx].side {
                    Side::Debit => {
                        n_debits = n_debits
                            .checked_add(legs[idx].mantissa)
                            .ok_or_else(|| "native debit overflow".to_string())?;
                    }
                    Side::Credit => {
                        n_credits = n_credits
                            .checked_add(legs[idx].mantissa)
                            .ok_or_else(|| "native credit overflow".to_string())?;
                    }
                }
            }
            if n_debits != n_credits {
                return Err(format!(
                    "native legs in unit {unit} for entity {entity:?} do not balance: {n_debits} != {n_credits}"
                ));
            }

            if unit == base_unit {
                for &idx in &u_indices {
                    base_mantissas[idx] = legs[idx].mantissa;
                }
                total_debits = total_debits
                    .checked_add(n_debits)
                    .ok_or_else(|| "base debit overflow".to_string())?;
                total_credits = total_credits
                    .checked_add(n_credits)
                    .ok_or_else(|| "base credit overflow".to_string())?;
                continue;
            }

            let quote = rates
                .get(&unit)
                .ok_or_else(|| format!("missing rate quote for foreign unit {unit}"))?;
            let mut u_debits = 0i128;
            let mut u_credits = 0i128;
            for &idx in &u_indices {
                let b = round_convert(
                    legs[idx].mantissa,
                    quote.quote_scale,
                    base_scale,
                    quote.rate_num,
                    quote.rate_den,
                    &quote.rounding_law,
                )?;
                base_mantissas[idx] = b;
                match legs[idx].side {
                    Side::Debit => {
                        u_debits = u_debits
                            .checked_add(b)
                            .ok_or_else(|| "base debit overflow".to_string())?;
                    }
                    Side::Credit => {
                        u_credits = u_credits
                            .checked_add(b)
                            .ok_or_else(|| "base credit overflow".to_string())?;
                    }
                }
            }

            let diff = u_debits
                .checked_sub(u_credits)
                .ok_or_else(|| "base diff overflow".to_string())?;
            if diff != 0 {
                let converted = u_indices.len();
                let bound_usize = match quote.rounding_law.as_str() {
                    "Ceiling" | "Floor" | "TowardZero" | "AwayFromZero" => {
                        converted.saturating_sub(1)
                    }
                    _ => converted / 2,
                };
                let bound = i128::try_from(bound_usize).unwrap_or(i128::MAX);
                if diff.abs() > bound {
                    return Err(format!(
                        "residual {} exceeds bound {} under {}",
                        diff, bound, quote.rounding_law
                    ));
                }
                let deficient = if diff > 0 { Side::Credit } else { Side::Debit };
                let target_idx = u_indices
                    .iter()
                    .copied()
                    .filter(|&i| legs[i].side == deficient)
                    .max_by(|a, b| base_mantissas[*a].cmp(&base_mantissas[*b]).then(b.cmp(a)))
                    .ok_or_else(|| {
                        "no converted leg on deficient side to absorb residual".to_string()
                    })?;
                let adj = diff.abs();
                base_mantissas[target_idx] = base_mantissas[target_idx]
                    .checked_add(adj)
                    .ok_or_else(|| "residual absorption overflow".to_string())?;
                match deficient {
                    Side::Debit => u_debits += adj,
                    Side::Credit => u_credits += adj,
                }
                if recorded_residual.is_some() {
                    return Err(
                        "multiple entity/unit partitions produced non-zero residuals".into(),
                    );
                }
                let ord = u16::try_from(target_idx).map_err(|_| "ordinal overflow".to_string())?;
                recorded_residual = Some((ord, adj));
            }
            debug_assert_eq!(u_debits, u_credits);
            total_debits = total_debits
                .checked_add(u_debits)
                .ok_or_else(|| "total base debit overflow".to_string())?;
            total_credits = total_credits
                .checked_add(u_credits)
                .ok_or_else(|| "total base credit overflow".to_string())?;
        }
    }

    Ok(OracleValuation {
        base_mantissas,
        base_debits: total_debits,
        base_credits: total_credits,
        residual: recorded_residual,
    })
}

/// Independently verify a realized FX settlement entry under
/// `SettlementCarryingBasis` (`FA-INV-01.realized-fx`).
#[allow(clippy::too_many_arguments)]
pub fn verify_realized_fx(
    legs: &[OracleRealizedLeg],
    base_unit: u32,
    base_scale: u8,
    quote_unit: u32,
    quote_scale: u8,
    rate_num: u128,
    rate_den: u128,
    rounding_law: &str,
) -> Result<(), String> {
    let mut native_by_unit: BTreeMap<u32, (i128, i128)> = BTreeMap::new();
    let mut base_by_entity: BTreeMap<Option<String>, (i128, i128)> = BTreeMap::new();
    let mut by_account: BTreeMap<u128, Vec<&OracleRealizedLeg>> = BTreeMap::new();

    for leg in legs {
        if leg.mantissa <= 0 || leg.base_mantissa <= 0 || leg.base_unit != base_unit {
            return Err("invalid leg mantissa or base_unit on realized FX entry".into());
        }
        if leg.unit == base_unit && leg.base_mantissa != leg.mantissa {
            return Err("base_unit leg must have base_mantissa == mantissa".into());
        }
        let u_slot = native_by_unit.entry(leg.unit).or_insert((0, 0));
        let e_slot = base_by_entity.entry(leg.entity.clone()).or_insert((0, 0));
        match leg.side {
            Side::Debit => {
                u_slot.0 += leg.mantissa;
                e_slot.0 += leg.base_mantissa;
            }
            Side::Credit => {
                u_slot.1 += leg.mantissa;
                e_slot.1 += leg.base_mantissa;
            }
        }
        by_account.entry(leg.account).or_default().push(leg);
    }

    for (u, (d, c)) in native_by_unit {
        if d != c {
            return Err(format!("native unit {u} unbalanced: {d} != {c}"));
        }
    }
    for (e, (d, c)) in base_by_entity {
        if d != c {
            return Err(format!("entity {e:?} base amounts unbalanced: {d} != {c}"));
        }
    }

    let mut conversion = None;
    for (&acct, acct_legs) in &by_account {
        if acct_legs.len() == 2 {
            let l0 = acct_legs[0];
            let l1 = acct_legs[1];
            if l0.side != l1.side
                && l0.base_mantissa == l1.base_mantissa
                && l0.entity == l1.entity
                && ((l0.unit == quote_unit && l1.unit == base_unit)
                    || (l1.unit == quote_unit && l0.unit == base_unit))
            {
                let fx_leg = if l0.unit == quote_unit { l0 } else { l1 };
                conversion = Some((acct, fx_leg.side, fx_leg.mantissa, fx_leg.base_mantissa));
                break;
            }
        }
    }

    let Some((conv_acct, conv_fx_side, foreign_mantissa, carrying_base)) = conversion else {
        return Err("missing paired conversion account postings (FA-INV-01.realized-fx)".into());
    };

    let expected_settlement = round_convert(
        foreign_mantissa,
        quote_scale,
        base_scale,
        rate_num,
        rate_den,
        rounding_law,
    )?;

    let settled_side = conv_fx_side.flipped();
    let has_settled = legs.iter().any(|l| {
        l.account != conv_acct
            && l.side == settled_side
            && l.unit == quote_unit
            && l.mantissa == foreign_mantissa
            && l.base_mantissa == carrying_base
    });
    if !has_settled {
        return Err("missing settled foreign-currency leg matching conversion account".into());
    }

    let has_consideration = legs.iter().any(|l| {
        l.account != conv_acct
            && l.side == conv_fx_side
            && l.unit == base_unit
            && l.mantissa == expected_settlement
            && l.base_mantissa == expected_settlement
    });
    if !has_consideration {
        return Err(
            "missing settlement consideration leg matching rate document conversion".into(),
        );
    }

    Ok(())
}

/// Cell key in the reference functional-value register fold:
/// `(account, base_unit, period, entity)`.
pub type OracleFunctionalKey = (u128, u32, String, Option<String>);

/// Independently fold functional-value register cells `(debits, credits, entry_count)`
/// for `period` (`FA-INV-04.functional-fold`).
pub fn fold_functional_period(
    entries: &[OracleFunctionalEntry],
    base_unit: u32,
    period: &str,
) -> Result<BTreeMap<OracleFunctionalKey, (i128, i128, u64)>, String> {
    let mut cells: BTreeMap<OracleFunctionalKey, (i128, i128, u64)> = BTreeMap::new();
    for entry in entries {
        if entry.period != period || entry.legs.is_empty() || entry.is_pending {
            continue;
        }
        let mut touched = BTreeSet::new();
        let mut by_entity: BTreeMap<Option<String>, (i128, i128)> = BTreeMap::new();
        for leg in &entry.legs {
            if leg.base_unit != base_unit || leg.base_mantissa <= 0 {
                return Err("leg missing positive base_mantissa in base_unit".into());
            }
            if leg.unit == base_unit && leg.base_mantissa != leg.mantissa {
                return Err("base_unit leg base_mantissa != native mantissa".into());
            }
            let key = (
                leg.account,
                base_unit,
                period.to_string(),
                leg.entity.clone(),
            );
            let slot = cells.entry(key.clone()).or_insert((0, 0, 0));
            let e_slot = by_entity.entry(leg.entity.clone()).or_insert((0, 0));
            match leg.side {
                Side::Debit => {
                    slot.0 = slot
                        .0
                        .checked_add(leg.base_mantissa)
                        .ok_or_else(|| "functional debit overflow".to_string())?;
                    e_slot.0 = e_slot
                        .0
                        .checked_add(leg.base_mantissa)
                        .ok_or_else(|| "entity debit overflow".to_string())?;
                }
                Side::Credit => {
                    slot.1 = slot
                        .1
                        .checked_add(leg.base_mantissa)
                        .ok_or_else(|| "functional credit overflow".to_string())?;
                    e_slot.1 = e_slot
                        .1
                        .checked_add(leg.base_mantissa)
                        .ok_or_else(|| "entity credit overflow".to_string())?;
                }
            }
            touched.insert(key);
        }
        for (entity, (d, c)) in by_entity {
            if d != c {
                return Err(format!(
                    "entry functional base amounts unbalanced for entity {entity:?}: {d} != {c}"
                ));
            }
        }
        for key in touched {
            let slot = cells.get_mut(&key).unwrap();
            slot.2 += 1;
        }
    }
    Ok(cells)
}
