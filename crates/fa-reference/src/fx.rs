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

/// A fully-valued final-state projection is malformed or exceeds the stock
/// gross capacity. This oracle does not decide period law or FX admissibility.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OracleCapacityError {
    InvalidLeg {
        entry: usize,
        leg: usize,
    },
    Exceeded {
        entry: usize,
        account: u128,
        unit: u32,
        functional: bool,
        pending: bool,
        side: Side,
    },
}

/// Independent native/functional capacity admission for a fully-valued final
/// state. Each account/unit's four nonnegative stock columns must fit i128;
/// periods and entities are subsets, and arbitrary cross-account report totals
/// are outside this law. Resolved holds are excluded before any addition.
///
/// Sums use the oracle's unbounded limbs, never the production checked-i128
/// implementation. Callers supply the final migration-visible projection and
/// resolution state; this function does not infer either from engine output.
pub fn admit_register_capacity(
    entries: &[OracleFunctionalEntry],
    base_unit: u32,
) -> Result<(), OracleCapacityError> {
    let mut sums: BTreeMap<(u128, u32, bool, bool, bool), Int> = BTreeMap::new();
    for (entry_index, entry) in entries.iter().enumerate() {
        if entry.is_pending && entry.is_resolved {
            continue;
        }
        for (leg_index, leg) in entry.legs.iter().enumerate() {
            if leg.mantissa < 0
                || leg.base_mantissa < 0
                || leg.base_unit != base_unit
                || (leg.unit == base_unit && leg.mantissa != leg.base_mantissa)
            {
                return Err(OracleCapacityError::InvalidLeg {
                    entry: entry_index,
                    leg: leg_index,
                });
            }
            for (unit, functional, amount) in [
                (leg.unit, false, leg.mantissa),
                (base_unit, true, leg.base_mantissa),
            ] {
                let sum = sums
                    .entry((
                        leg.account,
                        unit,
                        functional,
                        entry.is_pending,
                        leg.side == Side::Credit,
                    ))
                    .or_insert_with(Int::zero);
                *sum = sum.add(&Int::from_i128(amount));
                if sum.to_i128().is_none() {
                    return Err(OracleCapacityError::Exceeded {
                        entry: entry_index,
                        account: leg.account,
                        unit,
                        functional,
                        pending: entry.is_pending,
                        side: leg.side,
                    });
                }
            }
        }
    }
    Ok(())
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

/// Independent RemainingCarryingValue relief in native/base minor units
/// (plan §5.7). The final application takes the exact remaining base amount;
/// partial applications round the exact ratio once, under HalfEven.
///
/// Uses this oracle's own unbounded limbs and rounding, never the production
/// amount, rate or carrying implementation. Units and source admissibility
/// belong to the caller; these three inputs describe one current open item.
pub fn remaining_carrying_relief(
    open_native: i128,
    open_base: i128,
    application: i128,
) -> Result<i128, String> {
    if open_native <= 0 || open_base < 0 || application <= 0 || application > open_native {
        return Err("application must be positive and within the nonnegative open item".into());
    }
    if application == open_native {
        return Ok(open_base);
    }
    let numerator = u128::try_from(application).map_err(|_| "invalid application".to_string())?;
    let denominator = u128::try_from(open_native).map_err(|_| "invalid open native".to_string())?;
    round_convert(open_base, 0, 0, numerator, denominator, "HalfEven")
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
        if leg.mantissa <= 0 || leg.base_mantissa < 0 || leg.base_unit != base_unit {
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

    // Zero functional relief preserves the positive foreign postings and
    // omits the zero native base-conversion leg. Its complete four-leg
    // vector has no free choice of a balancing amount.
    if legs.iter().any(|leg| leg.base_mantissa == 0) {
        let [settled, conversion, cash, realized] = legs else {
            return Err("zero relief requires four complete realized FX legs".into());
        };
        let cash_amount = round_convert(
            settled.mantissa,
            quote_scale,
            base_scale,
            rate_num,
            rate_den,
            rounding_law,
        )?;
        let distinct: BTreeSet<_> = legs.iter().map(|leg| leg.account).collect();
        if distinct.len() != 4
            || settled.unit != quote_unit
            || settled.base_mantissa != 0
            || conversion.unit != quote_unit
            || conversion.mantissa != settled.mantissa
            || conversion.base_mantissa != 0
            || conversion.side != settled.side.flipped()
            || conversion.entity != settled.entity
            || cash.side != conversion.side
            || cash.unit != base_unit
            || cash.mantissa != cash_amount
            || realized.side != settled.side
            || realized.unit != base_unit
            || realized.mantissa != cash_amount
        {
            return Err(
                "zero relief does not reproduce its exact foreign, cash and realized FX effects"
                    .into(),
            );
        }
        return Ok(());
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
            if leg.base_unit != base_unit || leg.base_mantissa < 0 {
                return Err("leg missing nonnegative base_mantissa in base_unit".into());
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

/// Account item kind for the reference current-rate translation oracle (plan §12.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OracleTranslationKind {
    Asset,
    Liability,
    ContributedEquity { originating_date: i32 },
    Revenue,
    Expense,
    Dividend { declaration_date: i32 },
}

/// Input line for the reference current-rate translation oracle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleTranslationLine {
    pub account: u128,
    pub kind: OracleTranslationKind,
    pub side: Side,
    pub functional_mantissa: i128,
}

/// Output of the reference current-rate translation oracle (`ASC 830-30 / IAS 21.39`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleTranslationOutput {
    pub reporting_mantissas: Vec<i128>,
    pub total_assets_reporting: i128,
    pub total_liabilities_reporting: i128,
    pub total_contributed_equity_reporting: i128,
    pub total_revenue_reporting: i128,
    pub total_expense_reporting: i128,
    pub translated_net_income_reporting: i128,
    pub total_dividends_reporting: i128,
    pub ending_retained_earnings_reporting: i128,
    pub ending_cumulative_cta_credit: i128,
    pub delta_cta_credit: i128,
}

/// Independently compute current-rate translation (`ASC 830-30 / IAS 21.39`)
/// using [`Int`] limb arithmetic (`round_convert`).
#[allow(clippy::too_many_arguments)]
pub fn translate_current_rate_oracle(
    lines: &[OracleTranslationLine],
    functional_scale: u8,
    reporting_scale: u8,
    closing_quote: &OracleRateQuote,
    average_quote: &OracleRateQuote,
    historical_quotes: &BTreeMap<i32, OracleRateQuote>,
    prior_retained_earnings_functional: i128,
    prior_retained_earnings_reporting: i128,
    prior_cumulative_cta_credit: i128,
) -> Result<OracleTranslationOutput, String> {
    let mut func_dr = 0i128;
    let mut func_cr = prior_retained_earnings_functional;

    let mut reporting_mantissas = Vec::with_capacity(lines.len());
    let mut total_assets = 0i128;
    let mut total_liabilities = 0i128;
    let mut total_equity = 0i128;
    let mut total_revenue = 0i128;
    let mut total_expense = 0i128;
    let mut total_dividends = 0i128;

    for (idx, line) in lines.iter().enumerate() {
        if line.functional_mantissa <= 0 {
            return Err(format!("line {idx} has non-positive functional_mantissa"));
        }
        match line.side {
            Side::Debit => {
                func_dr = func_dr
                    .checked_add(line.functional_mantissa)
                    .ok_or_else(|| "functional debit overflow".to_string())?;
            }
            Side::Credit => {
                func_cr = func_cr
                    .checked_add(line.functional_mantissa)
                    .ok_or_else(|| "functional credit overflow".to_string())?;
            }
        }
        let quote = match line.kind {
            OracleTranslationKind::Asset | OracleTranslationKind::Liability => closing_quote,
            OracleTranslationKind::Revenue | OracleTranslationKind::Expense => average_quote,
            OracleTranslationKind::ContributedEquity { originating_date } => {
                historical_quotes.get(&originating_date).ok_or_else(|| {
                    format!("missing historical SpotClose rate for date {originating_date}")
                })?
            }
            OracleTranslationKind::Dividend { declaration_date } => {
                historical_quotes.get(&declaration_date).ok_or_else(|| {
                    format!("missing historical SpotClose rate for date {declaration_date}")
                })?
            }
        };
        let rep = round_convert(
            line.functional_mantissa,
            functional_scale,
            reporting_scale,
            quote.rate_num,
            quote.rate_den,
            &quote.rounding_law,
        )?;
        reporting_mantissas.push(rep);

        match (line.kind, line.side) {
            (OracleTranslationKind::Asset, Side::Debit) => total_assets += rep,
            (OracleTranslationKind::Asset, Side::Credit) => total_assets -= rep,
            (OracleTranslationKind::Liability, Side::Credit) => total_liabilities += rep,
            (OracleTranslationKind::Liability, Side::Debit) => total_liabilities -= rep,
            (OracleTranslationKind::ContributedEquity { .. }, Side::Credit) => total_equity += rep,
            (OracleTranslationKind::ContributedEquity { .. }, Side::Debit) => total_equity -= rep,
            (OracleTranslationKind::Revenue, Side::Credit) => total_revenue += rep,
            (OracleTranslationKind::Revenue, Side::Debit) => total_revenue -= rep,
            (OracleTranslationKind::Expense, Side::Debit) => total_expense += rep,
            (OracleTranslationKind::Expense, Side::Credit) => total_expense -= rep,
            (OracleTranslationKind::Dividend { .. }, Side::Debit) => total_dividends += rep,
            (OracleTranslationKind::Dividend { .. }, Side::Credit) => total_dividends -= rep,
        }
    }

    if func_dr != func_cr {
        return Err(format!(
            "functional trial balance unbalanced: debits {func_dr} != credits {func_cr}"
        ));
    }

    let translated_net_income = total_revenue
        .checked_sub(total_expense)
        .ok_or_else(|| "translated net income overflow".to_string())?;
    let ending_re = prior_retained_earnings_reporting
        .checked_add(translated_net_income)
        .and_then(|v| v.checked_sub(total_dividends))
        .ok_or_else(|| "ending retained earnings overflow".to_string())?;
    let net_assets = total_assets
        .checked_sub(total_liabilities)
        .ok_or_else(|| "net assets overflow".to_string())?;
    let non_cta_equity = total_equity
        .checked_add(ending_re)
        .ok_or_else(|| "non-cta equity overflow".to_string())?;
    let ending_cta = net_assets
        .checked_sub(non_cta_equity)
        .ok_or_else(|| "ending CTA overflow".to_string())?;
    let delta_cta = ending_cta
        .checked_sub(prior_cumulative_cta_credit)
        .ok_or_else(|| "delta CTA overflow".to_string())?;

    Ok(OracleTranslationOutput {
        reporting_mantissas,
        total_assets_reporting: total_assets,
        total_liabilities_reporting: total_liabilities,
        total_contributed_equity_reporting: total_equity,
        total_revenue_reporting: total_revenue,
        total_expense_reporting: total_expense,
        translated_net_income_reporting: translated_net_income,
        total_dividends_reporting: total_dividends,
        ending_retained_earnings_reporting: ending_re,
        ending_cumulative_cta_credit: ending_cta,
        delta_cta_credit: delta_cta,
    })
}

/// Remeasurement basis for the reference temporal-method oracle (plan §12.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OracleRemeasurementBasis {
    MonetaryClosing,
    NonMonetaryHistorical { acquisition_date: i32 },
    HistoricalCostAllocation { acquisition_date: i32 },
    FlowAverage,
}

/// Input line for the reference temporal-method remeasurement oracle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleRemeasurementLine {
    pub account: u128,
    pub is_income_statement: bool,
    pub basis: OracleRemeasurementBasis,
    pub side: Side,
    pub record_mantissa: i128,
}

/// Output of the reference temporal-method remeasurement oracle (`ASC 830-10-45-17 / IAS 21.23`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleRemeasurementOutput {
    pub functional_mantissas: Vec<i128>,
    pub pre_fx_net_income_functional: i128,
    pub cumulative_remeasurement_gain_credit: i128,
    pub delta_remeasurement_gain_credit: i128,
    pub remeasured_net_income_functional: i128,
    pub ending_retained_earnings_functional: i128,
}

/// Independently compute temporal-method remeasurement (`ASC 830-10-45-17 / IAS 21.23`)
/// using [`Int`] limb arithmetic (`round_convert`).
#[allow(clippy::too_many_arguments)]
pub fn remeasure_temporal_oracle(
    lines: &[OracleRemeasurementLine],
    record_scale: u8,
    functional_scale: u8,
    closing_quote: &OracleRateQuote,
    average_quote: &OracleRateQuote,
    historical_quotes: &BTreeMap<i32, OracleRateQuote>,
    prior_retained_earnings_record: i128,
    prior_retained_earnings_functional: i128,
    prior_cumulative_remeasurement_gain_credit: i128,
) -> Result<OracleRemeasurementOutput, String> {
    let mut rec_dr = 0i128;
    let mut rec_cr = prior_retained_earnings_record;

    let mut functional_mantissas = Vec::with_capacity(lines.len());
    let mut bs_dr_minus_cr = 0i128;
    let mut pre_fx_pnl_cr_minus_dr = 0i128;

    for (idx, line) in lines.iter().enumerate() {
        if line.record_mantissa <= 0 {
            return Err(format!("line {idx} has non-positive record_mantissa"));
        }
        match line.side {
            Side::Debit => rec_dr += line.record_mantissa,
            Side::Credit => rec_cr += line.record_mantissa,
        }
        let quote = match line.basis {
            OracleRemeasurementBasis::MonetaryClosing => closing_quote,
            OracleRemeasurementBasis::FlowAverage => average_quote,
            OracleRemeasurementBasis::NonMonetaryHistorical { acquisition_date }
            | OracleRemeasurementBasis::HistoricalCostAllocation { acquisition_date } => {
                historical_quotes.get(&acquisition_date).ok_or_else(|| {
                    format!("missing historical SpotClose rate for date {acquisition_date}")
                })?
            }
        };
        let func = round_convert(
            line.record_mantissa,
            record_scale,
            functional_scale,
            quote.rate_num,
            quote.rate_den,
            &quote.rounding_law,
        )?;
        functional_mantissas.push(func);

        if line.is_income_statement {
            match line.side {
                Side::Credit => pre_fx_pnl_cr_minus_dr += func,
                Side::Debit => pre_fx_pnl_cr_minus_dr -= func,
            }
        } else {
            match line.side {
                Side::Debit => bs_dr_minus_cr += func,
                Side::Credit => bs_dr_minus_cr -= func,
            }
        }
    }

    if rec_dr != rec_cr {
        return Err(format!(
            "record-currency trial balance unbalanced: debits {rec_dr} != credits {rec_cr}"
        ));
    }

    // Since prior_retained_earnings_functional = prior_pre_fx_re + prior_cumulative_remeasurement_gain_credit,
    // the delta-cumulative remeasurement gain/loss for this period is:
    //   delta_gain = bs_dr_minus_cr - (prior_retained_earnings_functional + pre_fx_pnl_cr_minus_dr)
    // and cumulative_gain = prior_cumulative_remeasurement_gain_credit + delta_gain.
    let delta_gain = bs_dr_minus_cr
        .checked_sub(prior_retained_earnings_functional + pre_fx_pnl_cr_minus_dr)
        .ok_or_else(|| "delta remeasurement gain overflow".to_string())?;
    let cumulative_gain = prior_cumulative_remeasurement_gain_credit
        .checked_add(delta_gain)
        .ok_or_else(|| "cumulative remeasurement gain overflow".to_string())?;
    let remeasured_ni = pre_fx_pnl_cr_minus_dr
        .checked_add(delta_gain)
        .ok_or_else(|| "remeasured net income overflow".to_string())?;
    let ending_re = prior_retained_earnings_functional
        .checked_add(remeasured_ni)
        .ok_or_else(|| "ending retained earnings overflow".to_string())?;

    Ok(OracleRemeasurementOutput {
        functional_mantissas,
        pre_fx_net_income_functional: pre_fx_pnl_cr_minus_dr,
        cumulative_remeasurement_gain_credit: cumulative_gain,
        delta_remeasurement_gain_credit: delta_gain,
        remeasured_net_income_functional: remeasured_ni,
        ending_retained_earnings_functional: ending_re,
    })
}

#[cfg(test)]
mod carrying_tests {
    use super::*;

    #[test]
    fn relief_has_literal_half_even_final_zero_and_wide_boundaries() {
        for (native, base, application, expected) in [
            (2, 1, 1, 0),
            (2, 3, 1, 2),
            (3, 10, 1, 3),
            (2, 7, 1, 4),
            (1, 3, 1, 3),
            (3, 1, 2, 1),
            (3, 0, 1, 0),
            (3, 0, 3, 0),
            (i128::MAX, i128::MAX, i128::MAX - 1, i128::MAX - 1),
            (i128::MAX, i128::MAX - 1, i128::MAX - 2, i128::MAX - 3),
            (2, i128::MAX, 1, i128::MAX / 2 + 1),
            (1, i128::MAX, 1, i128::MAX),
        ] {
            assert_eq!(
                remaining_carrying_relief(native, base, application),
                Ok(expected),
                "native={native}, base={base}, application={application}",
            );
        }
        for (native, base, application) in [
            (0, 1, 1),
            (-1, 1, 1),
            (1, -1, 1),
            (3, 1, 0),
            (3, 1, -1),
            (3, 1, 4),
        ] {
            assert!(remaining_carrying_relief(native, base, application).is_err());
        }
    }

    #[test]
    fn capacity_checks_stock_gross_columns_and_final_pending_state_with_limbs() {
        let entry = |amount, base_amount| OracleFunctionalEntry {
            period: "P1".into(),
            is_pending: false,
            is_resolved: false,
            legs: [Side::Debit, Side::Credit]
                .into_iter()
                .enumerate()
                .map(|(index, side)| OracleRealizedLeg {
                    side,
                    account: 10 + index as u128,
                    unit: 2,
                    mantissa: amount,
                    base_unit: 1,
                    base_mantissa: base_amount,
                    entity: Some("A".into()),
                })
                .collect(),
        };
        let maximum = entry(1, i128::MAX);
        assert_eq!(
            admit_register_capacity(std::slice::from_ref(&maximum), 1),
            Ok(())
        );
        let mut other_subset = entry(1, 1);
        other_subset.period = "P2".into();
        for leg in &mut other_subset.legs {
            leg.entity = Some("B".into());
        }
        assert!(matches!(
            admit_register_capacity(&[maximum.clone(), other_subset.clone()], 1),
            Err(OracleCapacityError::Exceeded {
                entry: 1,
                account: 10,
                functional: true,
                pending: false,
                side: Side::Debit,
                ..
            })
        ));
        // Independent accounts do not share a report-total capacity column.
        let mut other_accounts = maximum.clone();
        for leg in &mut other_accounts.legs {
            leg.account += 2;
        }
        assert_eq!(
            admit_register_capacity(&[maximum.clone(), other_accounts], 1),
            Ok(())
        );
        let mut opposite = maximum.clone();
        for leg in &mut opposite.legs {
            leg.side = leg.side.flipped();
        }
        let mut net_zero = vec![maximum.clone(), opposite];
        assert_eq!(admit_register_capacity(&net_zero, 1), Ok(()));
        net_zero.push(entry(1, 1));
        assert!(matches!(
            admit_register_capacity(&net_zero, 1),
            Err(OracleCapacityError::Exceeded {
                functional: true,
                ..
            })
        ));
        // Zero functional carrying value never waives native capacity.
        assert!(matches!(
            admit_register_capacity(&[entry(i128::MAX, 0), entry(1, 0)], 1),
            Err(OracleCapacityError::Exceeded {
                functional: false,
                ..
            })
        ));
        let mut hold = maximum;
        hold.is_pending = true;
        let mut next = other_subset;
        next.is_pending = true;
        assert!(matches!(
            admit_register_capacity(&[hold.clone(), next.clone()], 1),
            Err(OracleCapacityError::Exceeded { pending: true, .. })
        ));
        hold.is_resolved = true;
        assert_eq!(admit_register_capacity(&[next, hold], 1), Ok(()));
        for (native, functional, unit, base_unit) in
            [(-1, 1, 2, 1), (1, -1, 2, 1), (1, 1, 2, 3), (1, 2, 1, 1)]
        {
            let mut malformed = entry(native, functional);
            malformed.legs[0].unit = unit;
            malformed.legs[0].base_unit = base_unit;
            assert_eq!(
                admit_register_capacity(&[malformed], 1),
                Err(OracleCapacityError::InvalidLeg { entry: 0, leg: 0 })
            );
        }
    }

    #[test]
    fn zero_relief_and_exact_undo_preserve_native_effects_and_functional_folds() {
        let leg = |side, account, unit, mantissa, base_mantissa| OracleRealizedLeg {
            side,
            account,
            unit,
            mantissa,
            base_unit: 1,
            base_mantissa,
            entity: None,
        };
        let legs = vec![
            leg(Side::Credit, 10, 2, 1, 0),
            leg(Side::Debit, 20, 2, 1, 0),
            leg(Side::Debit, 30, 1, 2, 2),
            leg(Side::Credit, 40, 1, 2, 2),
        ];
        verify_realized_fx(&legs, 1, 2, 2, 2, 2, 1, "HalfEven").unwrap();
        let mut reversed = legs.clone();
        for leg in &mut reversed {
            leg.side = leg.side.flipped();
        }
        verify_realized_fx(&reversed, 1, 2, 2, 2, 2, 1, "HalfEven").unwrap();
        let entries = [legs, reversed].map(|legs| OracleFunctionalEntry {
            period: "P1".into(),
            is_pending: false,
            is_resolved: false,
            legs,
        });
        let cells = fold_functional_period(&entries, 1, "P1").unwrap();
        assert_eq!(cells[&(20, 1, "P1".into(), None)], (0, 0, 2));
        assert_eq!(cells[&(30, 1, "P1".into(), None)], (2, 2, 2));
    }
}
