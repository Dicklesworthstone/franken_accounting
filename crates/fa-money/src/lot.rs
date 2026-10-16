//! Lot cost-flow laws (`FIFO`, `LIFO`, `SpecificId`, `WeightedAverage`) and
//! explicit unit conversion laws (`ConversionLaw`) (plan §6.5; bead `fa-2ly`).
//!
//! Laws enforced here:
//! - A `Lot` is an open item `(acquiring leg, open quantity, open cost)`.
//! - Over-relief is refused naming the exact `open_quantity`.
//! - `LIFO` is refused under an `IFRS` accounting regime citing `IAS 2.25`
//!   (and cross-checked against `registries/lot_laws.toml`).
//! - `WeightedAverage` computes the pooled cost `round(C_pool * qty / Q_pool)`
//!   using exact 256-bit integer intermediates under the named `RoundingLaw`
//!   and records the exact rounding residual.
//! - Unit conversion (`convert_with_law`) is never implicit: converting between
//!   distinct units without naming a registered `ConversionLaw` is refused.

use core::cmp::Reverse;
use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use fa_registry::g0::{ConversionLaws, LotLaws};

use crate::amount::{Amount, AmountError};
use crate::rate::{ArithmeticBudget, Rate, RateError};
use crate::rounding::RoundingLaw;
use crate::unit::{UnitId, UnitRegistry};
use crate::wide::U256;

/// Accounting regime governing lot cost-flow admissibility (plan §6.5, §0.4 decision 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AccountingRegime {
    UsGaap,
    UsTax,
    Ifrs,
}

impl AccountingRegime {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UsGaap => "US-GAAP",
            Self::UsTax => "US-TAX",
            Self::Ifrs => "IFRS",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_uppercase().as_str() {
            "US-GAAP" | "US_GAAP" | "USGAAP" => Some(Self::UsGaap),
            "US-TAX" | "US_TAX" | "USTAX" => Some(Self::UsTax),
            "IFRS" => Some(Self::Ifrs),
            _ => None,
        }
    }
}

impl fmt::Display for AccountingRegime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Registered lot cost-flow law (`registries/lot_laws.toml`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LotLaw {
    Fifo,
    Lifo,
    SpecificId,
    WeightedAverage,
}

impl LotLaw {
    pub const ALL: [Self; 4] = [
        Self::Fifo,
        Self::Lifo,
        Self::SpecificId,
        Self::WeightedAverage,
    ];

    #[must_use]
    pub const fn id(self) -> u16 {
        match self {
            Self::Fifo => 1,
            Self::Lifo => 2,
            Self::SpecificId => 3,
            Self::WeightedAverage => 4,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fifo => "FIFO",
            Self::Lifo => "LIFO",
            Self::SpecificId => "SpecificId",
            Self::WeightedAverage => "WeightedAverage",
        }
    }

    #[must_use]
    pub const fn from_id(id: u16) -> Option<Self> {
        match id {
            1 => Some(Self::Fifo),
            2 => Some(Self::Lifo),
            3 => Some(Self::SpecificId),
            4 => Some(Self::WeightedAverage),
            _ => None,
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim() {
            "FIFO" | "fifo" => Some(Self::Fifo),
            "LIFO" | "lifo" => Some(Self::Lifo),
            "SpecificId" | "specific-id" | "specific_id" | "SPECIFIC_ID" => Some(Self::SpecificId),
            "WeightedAverage" | "weighted-average" | "weighted_average" | "WAC" | "wac" => {
                Some(Self::WeightedAverage)
            }
            _ => None,
        }
    }

    /// Check whether this lot law is admitted under `regime` per `registries/lot_laws.toml`.
    pub fn admit_for_regime(self, regime: AccountingRegime) -> Result<(), LotError> {
        let registry =
            LotLaws::embedded().map_err(|e| LotError::InvalidSelection(e.to_string()))?;
        let row = registry
            .by_name(self.name())
            .ok_or_else(|| LotError::InvalidSelection(format!("unregistered lot law `{self}`")))?;
        if row.refused_regimes.iter().any(|r| r == regime.as_str())
            || !row.admitted_regimes.iter().any(|r| r == regime.as_str())
        {
            return Err(LotError::RegimeRefused {
                law: self,
                regime,
                citation: row
                    .refusal_citation
                    .clone()
                    .unwrap_or_else(|| row.citation.clone()),
            });
        }
        Ok(())
    }
}

impl fmt::Display for LotLaw {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One open lot candidate available for relief.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LotCandidate {
    pub entry_id: u128,
    pub qty_ordinal: u16,
    pub cost_ordinal: u16,
    pub effective_day: i32,
    pub recorded_seq: u64,
    pub open_quantity: i128,
    pub open_cost: i128,
}

/// One lot relieved by a disposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LotReliefSlice {
    pub entry_id: u128,
    pub qty_ordinal: u16,
    pub cost_ordinal: u16,
    pub relieved_quantity: i128,
    pub relieved_cost: i128,
    pub open_quantity_before: i128,
    pub open_quantity_after: i128,
    pub open_cost_before: i128,
    pub open_cost_after: i128,
}

/// Complete deterministic outcome of a lot disposal relief calculation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LotReliefOutcome {
    pub law: LotLaw,
    pub regime: AccountingRegime,
    pub rounding_law: RoundingLaw,
    pub requested_quantity: i128,
    pub total_open_quantity: i128,
    pub total_open_cost: i128,
    pub total_relieved_cost: i128,
    /// For `WeightedAverage`, `(total_open_cost * requested_quantity) - (total_relieved_cost * total_open_quantity)`.
    /// Zero when exact or for non-pooled laws.
    pub wac_residual_numerator: i128,
    pub slices: Vec<LotReliefSlice>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LotError {
    NonPositiveDisposalQuantity(i128),
    OverRelief {
        requested: i128,
        open_quantity: i128,
    },
    RegimeRefused {
        law: LotLaw,
        regime: AccountingRegime,
        citation: String,
    },
    SpecificIdTargetsRequired,
    DuplicateTarget {
        entry_id: u128,
        qty_ordinal: u16,
    },
    UnknownTarget {
        entry_id: u128,
        qty_ordinal: u16,
    },
    InvalidCandidate(String),
    Overflow,
    InvalidSelection(String),
}

impl fmt::Display for LotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonPositiveDisposalQuantity(q) => {
                write!(f, "disposal quantity must be positive, got {q}")
            }
            Self::OverRelief {
                requested,
                open_quantity,
            } => write!(
                f,
                "over-relief refused: requested {requested}, but only {open_quantity} is open"
            ),
            Self::RegimeRefused {
                law,
                regime,
                citation,
            } => write!(
                f,
                "lot law `{law}` is refused in `{regime}` books: {citation}"
            ),
            Self::SpecificIdTargetsRequired => {
                f.write_str("SpecificId lot relief requires explicit target lots")
            }
            Self::DuplicateTarget {
                entry_id,
                qty_ordinal,
            } => write!(f, "duplicate target lot {:032x}/{qty_ordinal}", entry_id),
            Self::UnknownTarget {
                entry_id,
                qty_ordinal,
            } => write!(f, "unknown target lot {:032x}/{qty_ordinal}", entry_id),
            Self::InvalidCandidate(msg) => write!(f, "invalid lot candidate: {msg}"),
            Self::Overflow => f.write_str("lot relief integer overflow"),
            Self::InvalidSelection(msg) => write!(f, "{msg}"),
        }
    }
}

impl core::error::Error for LotError {}

/// Compute `(cost * numer) / denom` rounded under `law` using exact 256-bit
/// unsigned intermediate arithmetic.
pub fn mul_div_round_i128(
    cost: i128,
    numer: i128,
    denom: i128,
    law: RoundingLaw,
) -> Result<(i128, i128), LotError> {
    if cost < 0 || numer < 0 || denom <= 0 {
        return Err(LotError::InvalidCandidate(
            "lot quantity and cost must be non-negative with positive denominator".into(),
        ));
    }
    if cost == 0 || numer == 0 {
        return Ok((0, 0));
    }
    let c_u = u128::try_from(cost).map_err(|_| LotError::Overflow)?;
    let n_u = u128::try_from(numer).map_err(|_| LotError::Overflow)?;
    let d_u = u128::try_from(denom).map_err(|_| LotError::Overflow)?;
    let prod = U256::from_u128(c_u)
        .checked_mul_u128(n_u)
        .ok_or(LotError::Overflow)?;
    let (q, r) = prod
        .checked_div_rem(U256::from_u128(d_u))
        .ok_or(LotError::Overflow)?;
    let q_u = q.to_u128().ok_or(LotError::Overflow)?;
    let r_u = r.to_u128().ok_or(LotError::Overflow)?;
    let rounded_u = law
        .apply_magnitude(q_u, r_u, d_u, false)
        .ok_or(LotError::Overflow)?;
    let rounded = i128::try_from(rounded_u).map_err(|_| LotError::Overflow)?;
    // Residual numerator = prod - rounded * denom:
    // If rounded_u == q_u, residual is +r_u; if rounded_u == q_u + 1, residual is -(d_u - r_u).
    let residual_numerator = if rounded_u == q_u {
        i128::try_from(r_u).map_err(|_| LotError::Overflow)?
    } else {
        let diff = d_u.checked_sub(r_u).ok_or(LotError::Overflow)?;
        -i128::try_from(diff).map_err(|_| LotError::Overflow)?
    };
    Ok((rounded, residual_numerator))
}

/// Deterministically relieve `requested_quantity` from `candidates` under `law` and `regime`.
pub fn relieve_lots(
    candidates: &[LotCandidate],
    requested_quantity: i128,
    law: LotLaw,
    regime: AccountingRegime,
    rounding_law: RoundingLaw,
    explicit_targets: Option<&[(u128, u16)]>,
) -> Result<LotReliefOutcome, LotError> {
    law.admit_for_regime(regime)?;
    if requested_quantity <= 0 {
        return Err(LotError::NonPositiveDisposalQuantity(requested_quantity));
    }

    let mut by_id: BTreeMap<(u128, u16), &LotCandidate> = BTreeMap::new();
    let mut total_open_quantity: i128 = 0;
    let mut total_open_cost: i128 = 0;
    for lot in candidates {
        if lot.open_quantity < 0 || lot.open_cost < 0 {
            return Err(LotError::InvalidCandidate(format!(
                "lot {:032x}/{} has negative open quantity or cost",
                lot.entry_id, lot.qty_ordinal
            )));
        }
        if by_id.insert((lot.entry_id, lot.qty_ordinal), lot).is_some() {
            return Err(LotError::DuplicateTarget {
                entry_id: lot.entry_id,
                qty_ordinal: lot.qty_ordinal,
            });
        }
        if lot.open_quantity > 0 {
            total_open_quantity = total_open_quantity
                .checked_add(lot.open_quantity)
                .ok_or(LotError::Overflow)?;
            total_open_cost = total_open_cost
                .checked_add(lot.open_cost)
                .ok_or(LotError::Overflow)?;
        }
    }

    let ordered: Vec<&LotCandidate> = match law {
        LotLaw::Fifo | LotLaw::WeightedAverage => {
            if let Some(targets) = explicit_targets
                && !targets.is_empty()
            {
                return Err(LotError::InvalidSelection(format!(
                    "`{law}` orders open lots by law; omit explicit targets or use SpecificId"
                )));
            }
            let mut v: Vec<&LotCandidate> =
                candidates.iter().filter(|c| c.open_quantity > 0).collect();
            v.sort_by_key(|c| (c.effective_day, c.recorded_seq, c.entry_id, c.qty_ordinal));
            v
        }
        LotLaw::Lifo => {
            if let Some(targets) = explicit_targets
                && !targets.is_empty()
            {
                return Err(LotError::InvalidSelection(
                    "`LIFO` orders open lots by law; omit explicit targets or use SpecificId"
                        .into(),
                ));
            }
            let mut v: Vec<&LotCandidate> =
                candidates.iter().filter(|c| c.open_quantity > 0).collect();
            v.sort_by_key(|c| {
                Reverse((c.effective_day, c.recorded_seq, c.entry_id, c.qty_ordinal))
            });
            v
        }
        LotLaw::SpecificId => {
            let targets = explicit_targets.ok_or(LotError::SpecificIdTargetsRequired)?;
            if targets.is_empty() {
                return Err(LotError::SpecificIdTargetsRequired);
            }
            let mut seen = BTreeSet::new();
            let mut selected = Vec::with_capacity(targets.len());
            let mut selected_open_qty: i128 = 0;
            let mut selected_open_cost: i128 = 0;
            for &(entry_id, qty_ordinal) in targets {
                if !seen.insert((entry_id, qty_ordinal)) {
                    return Err(LotError::DuplicateTarget {
                        entry_id,
                        qty_ordinal,
                    });
                }
                let lot = by_id.get(&(entry_id, qty_ordinal)).copied().ok_or(
                    LotError::UnknownTarget {
                        entry_id,
                        qty_ordinal,
                    },
                )?;
                if lot.open_quantity > 0 {
                    selected_open_qty = selected_open_qty
                        .checked_add(lot.open_quantity)
                        .ok_or(LotError::Overflow)?;
                    selected_open_cost = selected_open_cost
                        .checked_add(lot.open_cost)
                        .ok_or(LotError::Overflow)?;
                    selected.push(lot);
                }
            }
            total_open_quantity = selected_open_qty;
            total_open_cost = selected_open_cost;
            selected
        }
    };

    if requested_quantity > total_open_quantity {
        return Err(LotError::OverRelief {
            requested: requested_quantity,
            open_quantity: total_open_quantity,
        });
    }

    match law {
        LotLaw::Fifo | LotLaw::Lifo | LotLaw::SpecificId => {
            let mut remaining = requested_quantity;
            let mut total_relieved_cost: i128 = 0;
            let mut slices = Vec::new();
            for lot in ordered {
                if remaining == 0 {
                    break;
                }
                let relieved_qty = remaining.min(lot.open_quantity);
                if relieved_qty == 0 {
                    continue;
                }
                let relieved_cost = if relieved_qty == lot.open_quantity {
                    lot.open_cost
                } else {
                    mul_div_round_i128(
                        lot.open_cost,
                        relieved_qty,
                        lot.open_quantity,
                        rounding_law,
                    )?
                    .0
                };
                remaining = remaining
                    .checked_sub(relieved_qty)
                    .ok_or(LotError::Overflow)?;
                total_relieved_cost = total_relieved_cost
                    .checked_add(relieved_cost)
                    .ok_or(LotError::Overflow)?;
                slices.push(LotReliefSlice {
                    entry_id: lot.entry_id,
                    qty_ordinal: lot.qty_ordinal,
                    cost_ordinal: lot.cost_ordinal,
                    relieved_quantity: relieved_qty,
                    relieved_cost,
                    open_quantity_before: lot.open_quantity,
                    open_quantity_after: lot
                        .open_quantity
                        .checked_sub(relieved_qty)
                        .ok_or(LotError::Overflow)?,
                    open_cost_before: lot.open_cost,
                    open_cost_after: lot
                        .open_cost
                        .checked_sub(relieved_cost)
                        .ok_or(LotError::Overflow)?,
                });
            }
            Ok(LotReliefOutcome {
                law,
                regime,
                rounding_law,
                requested_quantity,
                total_open_quantity,
                total_open_cost,
                total_relieved_cost,
                wac_residual_numerator: 0,
                slices,
            })
        }
        LotLaw::WeightedAverage => {
            let (total_relieved_cost, wac_residual_numerator) =
                if requested_quantity == total_open_quantity {
                    (total_open_cost, 0)
                } else {
                    mul_div_round_i128(
                        total_open_cost,
                        requested_quantity,
                        total_open_quantity,
                        rounding_law,
                    )?
                };
            // Relieve quantities in canonical FIFO lot order.
            let mut rem_qty = requested_quantity;
            let mut qty_relieved_per_lot: Vec<(&LotCandidate, i128)> = Vec::new();
            for lot in &ordered {
                let take = rem_qty.min(lot.open_quantity);
                qty_relieved_per_lot.push((*lot, take));
                rem_qty = rem_qty.checked_sub(take).ok_or(LotError::Overflow)?;
            }

            // Allocate `total_relieved_cost` across lots:
            // Prefer exhausting the open cost of fully-relieved quantity lots first when
            // feasible; if early lots have higher unit cost than the pool so exhausting
            // them would exceed `total_relieved_cost`, cap each lot at its `open_cost`
            // in canonical lot order.
            let exhausted_cost_sum: i128 = qty_relieved_per_lot
                .iter()
                .filter(|(lot, q)| *q == lot.open_quantity)
                .try_fold(0i128, |acc, (lot, _)| acc.checked_add(lot.open_cost))
                .ok_or(LotError::Overflow)?;
            let partial_lot_cap: i128 = qty_relieved_per_lot
                .iter()
                .find(|(lot, q)| *q > 0 && *q < lot.open_quantity)
                .map_or(0, |(lot, _)| lot.open_cost);

            let mut slices = Vec::new();
            if exhausted_cost_sum <= total_relieved_cost
                && total_relieved_cost - exhausted_cost_sum <= partial_lot_cap
            {
                let rem_for_partial = total_relieved_cost - exhausted_cost_sum;
                for (lot, relieved_qty) in qty_relieved_per_lot {
                    if relieved_qty == 0 {
                        continue;
                    }
                    let relieved_cost = if relieved_qty == lot.open_quantity {
                        lot.open_cost
                    } else {
                        rem_for_partial
                    };
                    slices.push(LotReliefSlice {
                        entry_id: lot.entry_id,
                        qty_ordinal: lot.qty_ordinal,
                        cost_ordinal: lot.cost_ordinal,
                        relieved_quantity: relieved_qty,
                        relieved_cost,
                        open_quantity_before: lot.open_quantity,
                        open_quantity_after: lot.open_quantity - relieved_qty,
                        open_cost_before: lot.open_cost,
                        open_cost_after: lot.open_cost - relieved_cost,
                    });
                }
            } else {
                let mut rem_cost = total_relieved_cost;
                for (lot, relieved_qty) in qty_relieved_per_lot {
                    if relieved_qty == 0 && rem_cost == 0 {
                        continue;
                    }
                    let relieved_cost = rem_cost.min(lot.open_cost);
                    rem_cost = rem_cost
                        .checked_sub(relieved_cost)
                        .ok_or(LotError::Overflow)?;
                    if relieved_qty > 0 || relieved_cost > 0 {
                        slices.push(LotReliefSlice {
                            entry_id: lot.entry_id,
                            qty_ordinal: lot.qty_ordinal,
                            cost_ordinal: lot.cost_ordinal,
                            relieved_quantity: relieved_qty,
                            relieved_cost,
                            open_quantity_before: lot.open_quantity,
                            open_quantity_after: lot.open_quantity - relieved_qty,
                            open_cost_before: lot.open_cost,
                            open_cost_after: lot.open_cost - relieved_cost,
                        });
                    }
                }
            }

            Ok(LotReliefOutcome {
                law,
                regime,
                rounding_law,
                requested_quantity,
                total_open_quantity,
                total_open_cost,
                total_relieved_cost,
                wac_residual_numerator,
                slices,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Explicit unit conversion (`ConversionLaw`, plan §6.5)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConversionError {
    ImplicitConversionRefused {
        from_code: String,
        to_code: String,
        matching_laws: Vec<String>,
    },
    UnknownLaw(String),
    UnitMismatch {
        law: String,
        expected_from: String,
        expected_to: String,
        actual_from: String,
        actual_to: String,
    },
    ScaleMismatch {
        law: String,
        unit: String,
        expected_scale: u8,
        actual_scale: u8,
    },
    UnknownUnit(UnitId),
    Rate(RateError),
    Amount(AmountError),
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ImplicitConversionRefused {
                from_code,
                to_code,
                matching_laws,
            } => {
                if matching_laws.is_empty() {
                    write!(
                        f,
                        "implicit unit conversion from `{from_code}` to `{to_code}` is refused (plan §6.5): name a registered ConversionLaw in registries/conversion_laws.toml"
                    )
                } else {
                    write!(
                        f,
                        "implicit unit conversion from `{from_code}` to `{to_code}` is refused (plan §6.5): name ConversionLaw `{}`",
                        matching_laws.join("` or `")
                    )
                }
            }
            Self::UnknownLaw(name) => write!(
                f,
                "unknown ConversionLaw `{name}` (not in registries/conversion_laws.toml)"
            ),
            Self::UnitMismatch {
                law,
                expected_from,
                expected_to,
                actual_from,
                actual_to,
            } => write!(
                f,
                "ConversionLaw `{law}` converts `{expected_from}` -> `{expected_to}`, not `{actual_from}` -> `{actual_to}`"
            ),
            Self::ScaleMismatch {
                law,
                unit,
                expected_scale,
                actual_scale,
            } => write!(
                f,
                "ConversionLaw `{law}` expects `{unit}` at scale {expected_scale}, found scale {actual_scale}"
            ),
            Self::UnknownUnit(u) => write!(f, "unknown unit id {u}"),
            Self::Rate(e) => write!(f, "{e}"),
            Self::Amount(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for ConversionError {}

impl From<RateError> for ConversionError {
    fn from(e: RateError) -> Self {
        Self::Rate(e)
    }
}

impl From<AmountError> for ConversionError {
    fn from(e: AmountError) -> Self {
        Self::Amount(e)
    }
}

/// Convert `amount` to `to_unit` under a named `ConversionLaw` from `conversion_laws.toml`.
///
/// Converting between different units (`amount.unit != to_unit`) with `law_name = None`
/// is always refused naming `ConversionLaw` (plan §6.5).
pub fn convert_with_law(
    amount: Amount,
    to_unit: UnitId,
    law_name: Option<&str>,
    laws: &ConversionLaws,
    reg: &UnitRegistry,
    budget: &mut ArithmeticBudget<'_, impl Sized>,
) -> Result<Amount, ConversionError> {
    let from_u = reg
        .get(amount.unit)
        .ok_or(ConversionError::UnknownUnit(amount.unit))?;
    let to_u = reg
        .get(to_unit)
        .ok_or(ConversionError::UnknownUnit(to_unit))?;

    let Some(name) = law_name else {
        if amount.unit == to_unit {
            return Ok(amount);
        }
        let matching_laws = laws
            .for_pair(&from_u.code, &to_u.code)
            .into_iter()
            .map(|r| r.name.clone())
            .collect();
        return Err(ConversionError::ImplicitConversionRefused {
            from_code: from_u.code.clone(),
            to_code: to_u.code.clone(),
            matching_laws,
        });
    };

    let row = laws
        .by_name(name)
        .ok_or_else(|| ConversionError::UnknownLaw(name.to_string()))?;
    if row.from_code != from_u.code || row.to_code != to_u.code {
        return Err(ConversionError::UnitMismatch {
            law: row.name.clone(),
            expected_from: row.from_code.clone(),
            expected_to: row.to_code.clone(),
            actual_from: from_u.code.clone(),
            actual_to: to_u.code.clone(),
        });
    }
    if row.from_scale != from_u.scale {
        return Err(ConversionError::ScaleMismatch {
            law: row.name.clone(),
            unit: from_u.code.clone(),
            expected_scale: row.from_scale,
            actual_scale: from_u.scale,
        });
    }
    if row.to_scale != to_u.scale {
        return Err(ConversionError::ScaleMismatch {
            law: row.name.clone(),
            unit: to_u.code.clone(),
            expected_scale: row.to_scale,
            actual_scale: to_u.scale,
        });
    }

    let rounding = RoundingLaw::from_name(&row.rounding_law).ok_or_else(|| {
        ConversionError::UnknownLaw(format!(
            "{}: unknown rounding law {}",
            row.name, row.rounding_law
        ))
    })?;
    let rate = Rate::from_ratio(budget, &row.numerator, &row.denominator)?;
    Ok(amount.convert(budget, to_unit, &rate, rounding, reg)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::{Unit, UnitKind};

    #[test]
    fn buy_10_at_100_buy_10_at_120_sell_15_fifo_lifo_wac_and_specific_id() {
        let candidates = vec![
            LotCandidate {
                entry_id: 1,
                qty_ordinal: 0,
                cost_ordinal: 2,
                effective_day: 10,
                recorded_seq: 2,
                open_quantity: 10,
                open_cost: 1_000,
            },
            LotCandidate {
                entry_id: 2,
                qty_ordinal: 0,
                cost_ordinal: 2,
                effective_day: 20,
                recorded_seq: 3,
                open_quantity: 10,
                open_cost: 1_200,
            },
        ];

        // 1. FIFO -> cost 1,600 (10@100 = 1,000 + 5@120 = 600)
        let fifo = relieve_lots(
            &candidates,
            15,
            LotLaw::Fifo,
            AccountingRegime::UsGaap,
            RoundingLaw::HalfEven,
            None,
        )
        .expect("FIFO");
        assert_eq!(fifo.total_relieved_cost, 1_600);
        assert_eq!(fifo.slices.len(), 2);
        assert_eq!(
            (
                fifo.slices[0].entry_id,
                fifo.slices[0].relieved_quantity,
                fifo.slices[0].relieved_cost
            ),
            (1, 10, 1_000)
        );
        assert_eq!(
            (
                fifo.slices[1].entry_id,
                fifo.slices[1].relieved_quantity,
                fifo.slices[1].relieved_cost
            ),
            (2, 5, 600)
        );

        // 2. LIFO -> cost 1,700 (10@120 = 1,200 + 5@100 = 500) in US-TAX / US-GAAP
        let lifo = relieve_lots(
            &candidates,
            15,
            LotLaw::Lifo,
            AccountingRegime::UsTax,
            RoundingLaw::HalfEven,
            None,
        )
        .expect("LIFO in US-TAX");
        assert_eq!(lifo.total_relieved_cost, 1_700);
        assert_eq!(
            (
                lifo.slices[0].entry_id,
                lifo.slices[0].relieved_quantity,
                lifo.slices[0].relieved_cost
            ),
            (2, 10, 1_200)
        );
        assert_eq!(
            (
                lifo.slices[1].entry_id,
                lifo.slices[1].relieved_quantity,
                lifo.slices[1].relieved_cost
            ),
            (1, 5, 500)
        );

        // 3. WeightedAverage -> cost 1,650 (pool 20 @ 2,200 => 15 * 110 = 1,650)
        let wac = relieve_lots(
            &candidates,
            15,
            LotLaw::WeightedAverage,
            AccountingRegime::Ifrs,
            RoundingLaw::HalfEven,
            None,
        )
        .expect("WAC in IFRS");
        assert_eq!(wac.total_relieved_cost, 1_650);
        assert_eq!(wac.wac_residual_numerator, 0);
        let sum_cost: i128 = wac.slices.iter().map(|s| s.relieved_cost).sum();
        let sum_qty: i128 = wac.slices.iter().map(|s| s.relieved_quantity).sum();
        assert_eq!(sum_qty, 15);
        assert_eq!(sum_cost, 1_650);

        // 4. SpecificId -> target lot 2 then lot 1 explicitly
        let spec = relieve_lots(
            &candidates,
            15,
            LotLaw::SpecificId,
            AccountingRegime::Ifrs,
            RoundingLaw::HalfEven,
            Some(&[(2, 0), (1, 0)]),
        )
        .expect("SpecificId");
        assert_eq!(spec.total_relieved_cost, 1_700);
    }

    #[test]
    fn planted_negatives_over_relief_ifrs_lifo_and_implicit_unit_conversion_are_refused() {
        let candidates = vec![LotCandidate {
            entry_id: 1,
            qty_ordinal: 0,
            cost_ordinal: 2,
            effective_day: 10,
            recorded_seq: 2,
            open_quantity: 10,
            open_cost: 1_000,
        }];

        // Planted negative 1: over-relief refused with open quantity.
        let err = relieve_lots(
            &candidates,
            11,
            LotLaw::Fifo,
            AccountingRegime::UsGaap,
            RoundingLaw::HalfEven,
            None,
        )
        .expect_err("over-relief must fail");
        assert_eq!(
            err,
            LotError::OverRelief {
                requested: 11,
                open_quantity: 10
            }
        );
        assert!(err.to_string().contains("only 10 is open"), "{err}");

        // Planted negative 2: LIFO in an IFRS book refused with IAS 2.25 citation.
        let err = relieve_lots(
            &candidates,
            5,
            LotLaw::Lifo,
            AccountingRegime::Ifrs,
            RoundingLaw::HalfEven,
            None,
        )
        .expect_err("LIFO in IFRS must fail");
        assert!(
            matches!(
                err,
                LotError::RegimeRefused {
                    law: LotLaw::Lifo,
                    regime: AccountingRegime::Ifrs,
                    ..
                }
            ),
            "{err}"
        );
        assert!(err.to_string().contains("IAS 2.25"), "{err}");

        // Planted negative 3: implicit unit conversion refused naming ConversionLaw.
        let cx = asupersync::Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        let mut reg = UnitRegistry::with_defaults();
        let day_unit = reg
            .register(Unit {
                code: "DAY".into(),
                scale: 4,
                version: 0,
                kind: UnitKind::Time,
                rounding_default: RoundingLaw::HalfEven,
            })
            .expect("register DAY");
        let hour_unit = reg.lookup("HOUR").expect("HOUR");
        let laws = ConversionLaws::embedded().expect("conversion_laws.toml");

        let hours = Amount::new(hour_unit, 1200); // 12.00 HOUR
        let err = convert_with_law(hours, day_unit, None, &laws, &reg, &mut budget)
            .expect_err("implicit conversion must fail");
        assert!(
            err.to_string().contains("ConversionLaw") && err.to_string().contains("HoursToDays8h"),
            "{err}"
        );

        // Positive conversion with named law: 12.00 HOUR -> 1.5000 DAY (15000 at scale 4).
        let days = convert_with_law(
            hours,
            day_unit,
            Some("HoursToDays8h"),
            &laws,
            &reg,
            &mut budget,
        )
        .expect("explicit conversion");
        assert_eq!(days, Amount::new(day_unit, 15_000));
    }
}
