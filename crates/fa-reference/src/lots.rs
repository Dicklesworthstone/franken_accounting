//! Independent reference oracle for lot relief and conversion laws (plan §6.5, §16.2, `fa-2ly`).
//!
//! Uses `fa-reference`'s own limb integer [`Int`](crate::Int) and embedded
//! registry tables (`registries/lot_laws.toml`, `registries/conversion_laws.toml`)
//! with zero dependency on `fa-money`.

use std::collections::BTreeSet;

use fa_registry::{ConversionLaws, LotLaws};

use crate::Int;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefRounding {
    HalfEven,
    HalfUp,
    HalfDown,
    Down,
    Up,
    Floor,
    Ceiling,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefLot {
    pub entry_id: u128,
    pub ordinal: u16,
    pub effective_day: i32,
    pub recorded_seq: u64,
    pub quantity_unit: u32,
    pub open_quantity: i128,
    pub cost_unit: u32,
    pub open_cost: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefLotSlice {
    pub entry_id: u128,
    pub ordinal: u16,
    pub quantity_relieved: i128,
    pub cost_relieved: i128,
    pub open_quantity_before: i128,
    pub open_quantity_after: i128,
    pub open_cost_before: i128,
    pub open_cost_after: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefLotOutcome {
    pub total_quantity: i128,
    pub total_cost: i128,
    pub slices: Vec<RefLotSlice>,
}

/// Exact `round(a * b / d)` using `fa_reference::Int` limb arithmetic.
pub fn mul_div_round_int(a: i128, b: i128, d: i128, rounding: RefRounding) -> Result<i128, String> {
    if d <= 0 {
        return Err("non-positive divisor".into());
    }
    if a == 0 || b == 0 {
        return Ok(0);
    }
    let negative = (a < 0) ^ (b < 0);
    let prod = Int::from_u128(a.unsigned_abs()).mul(&Int::from_u128(b.unsigned_abs()));
    let div = Int::from_u128(d.unsigned_abs());
    let (q, r) = prod
        .div_rem(&div)
        .ok_or_else(|| "zero divisor".to_string())?;
    let inc = if r.is_zero() {
        false
    } else {
        let twice_r = r.mul(&Int::from_u128(2));
        let cmp = twice_r.cmp(&div);
        let q_odd = q.to_u128().is_some_and(|v| (v & 1) == 1);
        match rounding {
            RefRounding::Down => false,
            RefRounding::Up => true,
            RefRounding::Floor => negative,
            RefRounding::Ceiling => !negative,
            RefRounding::HalfUp => cmp != core::cmp::Ordering::Less,
            RefRounding::HalfDown => cmp == core::cmp::Ordering::Greater,
            RefRounding::HalfEven => {
                cmp == core::cmp::Ordering::Greater || (cmp == core::cmp::Ordering::Equal && q_odd)
            }
        }
    };
    let rounded = if inc { q.add(&Int::from_u128(1)) } else { q };
    let signed = if negative { rounded.negated() } else { rounded };
    signed.to_i128().ok_or_else(|| "overflow".into())
}

/// Independent lot relief evaluation consulting `LotLaws::embedded()`.
pub fn relieve_lots_oracle(
    lots: &[RefLot],
    quantity_unit: u32,
    relieve_qty: i128,
    law_name: &str,
    regime: Option<&str>,
    rounding: RefRounding,
    targets: &[(u128, u16)],
) -> Result<RefLotOutcome, String> {
    if relieve_qty <= 0 {
        return Err("non-positive relief quantity".into());
    }
    let registry = LotLaws::embedded().map_err(|e| e.to_string())?;
    let law_row = registry
        .laws
        .iter()
        .find(|row| row.name == law_name)
        .ok_or_else(|| format!("unknown lot law `{law_name}`"))?;
    if let Some(reg) = regime {
        if law_row.refused_regimes.iter().any(|r| r == reg) {
            let citation = law_row.refusal_citation.as_deref().unwrap_or("IFRS");
            return Err(format!("refused in regime `{reg}` under `{citation}`"));
        }
    }
    let requires_targets = law_row.ordering == "explicit-target-order";
    if requires_targets && targets.is_empty() {
        return Err("SpecificId requires explicit targets".into());
    }
    if !requires_targets && !targets.is_empty() {
        return Err("unexpected explicit targets".into());
    }
    if lots.is_empty() {
        return Err("no open lots".into());
    }
    let cost_unit = lots[0].cost_unit;
    for lot in lots {
        if lot.quantity_unit != quantity_unit || lot.cost_unit != cost_unit {
            return Err("unit mismatch".into());
        }
        if lot.open_quantity <= 0 || lot.open_cost < 0 {
            return Err("invalid lot".into());
        }
    }

    match law_name {
        "FIFO" | "LIFO" => {
            let mut indices: Vec<usize> = (0..lots.len()).collect();
            indices.sort_by_key(|&i| {
                (
                    lots[i].effective_day,
                    lots[i].recorded_seq,
                    lots[i].entry_id,
                    lots[i].ordinal,
                )
            });
            if law_name == "LIFO" {
                indices.reverse();
            }
            let total_avail: i128 = indices.iter().map(|&i| lots[i].open_quantity).sum();
            if total_avail < relieve_qty {
                return Err("over-relief".into());
            }
            let mut rem = relieve_qty;
            let mut total_cost = 0i128;
            let mut slices = Vec::new();
            for i in indices {
                if rem == 0 {
                    break;
                }
                let lot = &lots[i];
                let q = rem.min(lot.open_quantity);
                let c = if q == lot.open_quantity {
                    lot.open_cost
                } else {
                    mul_div_round_int(lot.open_cost, q, lot.open_quantity, rounding)?
                };
                rem -= q;
                total_cost += c;
                slices.push(RefLotSlice {
                    entry_id: lot.entry_id,
                    ordinal: lot.ordinal,
                    quantity_relieved: q,
                    cost_relieved: c,
                    open_quantity_before: lot.open_quantity,
                    open_quantity_after: lot.open_quantity - q,
                    open_cost_before: lot.open_cost,
                    open_cost_after: lot.open_cost - c,
                });
            }
            Ok(RefLotOutcome {
                total_quantity: relieve_qty,
                total_cost,
                slices,
            })
        }
        "SpecificId" => {
            let mut seen = BTreeSet::new();
            let mut ordered = Vec::new();
            let mut total_avail = 0i128;
            for &(eid, ord) in targets {
                if !seen.insert((eid, ord)) {
                    return Err("duplicate target".into());
                }
                let idx = lots
                    .iter()
                    .position(|l| l.entry_id == eid && l.ordinal == ord)
                    .ok_or_else(|| "unknown target".to_string())?;
                total_avail += lots[idx].open_quantity;
                ordered.push(idx);
            }
            if total_avail < relieve_qty {
                return Err("over-relief".into());
            }
            let mut rem = relieve_qty;
            let mut total_cost = 0i128;
            let mut slices = Vec::new();
            for i in ordered {
                if rem == 0 {
                    break;
                }
                let lot = &lots[i];
                let q = rem.min(lot.open_quantity);
                let c = if q == lot.open_quantity {
                    lot.open_cost
                } else {
                    mul_div_round_int(lot.open_cost, q, lot.open_quantity, rounding)?
                };
                rem -= q;
                total_cost += c;
                slices.push(RefLotSlice {
                    entry_id: lot.entry_id,
                    ordinal: lot.ordinal,
                    quantity_relieved: q,
                    cost_relieved: c,
                    open_quantity_before: lot.open_quantity,
                    open_quantity_after: lot.open_quantity - q,
                    open_cost_before: lot.open_cost,
                    open_cost_after: lot.open_cost - c,
                });
            }
            Ok(RefLotOutcome {
                total_quantity: relieve_qty,
                total_cost,
                slices,
            })
        }
        "WeightedAverage" => {
            let mut indices: Vec<usize> = (0..lots.len()).collect();
            indices.sort_by_key(|&i| {
                (
                    lots[i].effective_day,
                    lots[i].recorded_seq,
                    lots[i].entry_id,
                    lots[i].ordinal,
                )
            });
            let total_avail: i128 = indices.iter().map(|&i| lots[i].open_quantity).sum();
            let total_open_cost: i128 = indices.iter().map(|&i| lots[i].open_cost).sum();
            if total_avail < relieve_qty {
                return Err("over-relief".into());
            }
            let total_cost = if relieve_qty == total_avail {
                total_open_cost
            } else {
                mul_div_round_int(total_open_cost, relieve_qty, total_avail, rounding)?
            };
            let mut rem_q = relieve_qty;
            let mut qty_per_lot = Vec::new();
            for i in indices {
                let take = rem_q.min(lots[i].open_quantity);
                qty_per_lot.push((i, take));
                rem_q -= take;
            }
            let exhausted_cost_sum: i128 = qty_per_lot
                .iter()
                .filter(|(i, q)| *q == lots[*i].open_quantity)
                .map(|(i, _)| lots[*i].open_cost)
                .sum();
            let partial_cap: i128 = qty_per_lot
                .iter()
                .find(|(i, q)| *q > 0 && *q < lots[*i].open_quantity)
                .map_or(0, |(i, _)| lots[*i].open_cost);
            let mut slices = Vec::new();
            if exhausted_cost_sum <= total_cost && total_cost - exhausted_cost_sum <= partial_cap {
                let rem_for_partial = total_cost - exhausted_cost_sum;
                for (i, q) in qty_per_lot {
                    if q == 0 {
                        continue;
                    }
                    let lot = &lots[i];
                    let c = if q == lot.open_quantity {
                        lot.open_cost
                    } else {
                        rem_for_partial
                    };
                    slices.push(RefLotSlice {
                        entry_id: lot.entry_id,
                        ordinal: lot.ordinal,
                        quantity_relieved: q,
                        cost_relieved: c,
                        open_quantity_before: lot.open_quantity,
                        open_quantity_after: lot.open_quantity - q,
                        open_cost_before: lot.open_cost,
                        open_cost_after: lot.open_cost - c,
                    });
                }
            } else {
                let mut rem_c = total_cost;
                for (i, q) in qty_per_lot {
                    let lot = &lots[i];
                    let c = rem_c.min(lot.open_cost);
                    rem_c -= c;
                    if q > 0 || c > 0 {
                        slices.push(RefLotSlice {
                            entry_id: lot.entry_id,
                            ordinal: lot.ordinal,
                            quantity_relieved: q,
                            cost_relieved: c,
                            open_quantity_before: lot.open_quantity,
                            open_quantity_after: lot.open_quantity - q,
                            open_cost_before: lot.open_cost,
                            open_cost_after: lot.open_cost - c,
                        });
                    }
                }
            }
            Ok(RefLotOutcome {
                total_quantity: relieve_qty,
                total_cost,
                slices,
            })
        }
        other => Err(format!("unsupported lot law `{other}`")),
    }
}

/// Independent conversion oracle consulting `ConversionLaws::embedded()`.
pub fn convert_oracle(
    amount_mantissa: i128,
    from_code: &str,
    from_scale: u8,
    to_code: &str,
    to_scale: u8,
    law_name: Option<&str>,
    rounding: RefRounding,
) -> Result<i128, String> {
    let registry = ConversionLaws::embedded().map_err(|e| e.to_string())?;
    let Some(name) = law_name else {
        let suggested = registry
            .rows
            .iter()
            .find(|l| l.from_code == from_code && l.to_code == to_code)
            .map(|l| l.name.as_str())
            .unwrap_or("<none>");
        return Err(format!(
            "implicit conversion `{from_code}` -> `{to_code}` refused; suggest `{suggested}`"
        ));
    };
    let row = registry
        .rows
        .iter()
        .find(|l| l.name == name)
        .ok_or_else(|| format!("unknown conversion law `{name}`"))?;
    if row.from_code != from_code || row.to_code != to_code {
        return Err("unit mismatch for conversion law".into());
    }
    let factor_num: i128 = row.numerator.parse().map_err(|_| "bad numerator")?;
    let factor_den: i128 = row.denominator.parse().map_err(|_| "bad denominator")?;
    let scale_num = 10i128.pow(u32::from(to_scale));
    let scale_den = 10i128.pow(u32::from(from_scale));
    let num = factor_num * scale_num;
    let den = factor_den * scale_den;
    mul_div_round_int(amount_mantissa, num, den, rounding)
}
