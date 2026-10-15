//! Naïve reference-oracle implementations for allocation laws and the
//! report families: roll-forward, general-ledger detail, effective-date
//! aging, direct cash flow, and indirect cash flow (bead `fa-5kve`).
//!
//! Boundary: `std`, `fa-time`, and `crate::{Int, Known, Oracle, Side}` only.
//! Zero imports from `fa-money`, `fa-registers`, `fa-statements`, or `fa`.

use std::collections::{BTreeMap, BTreeSet};

use fa_time::DateDay;

use crate::{Int, Known, Oracle, Side};

// ---------------------------------------------------------------------------
// 1. Naïve Allocation Laws (std + Int limb arithmetic only)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoundingMode {
    HalfUp,
    HalfDown,
    HalfEven,
    HalfAwayFromZero,
    HalfTowardZero,
    Ceiling,
    Floor,
    TowardZero,
    AwayFromZero,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleProRata {
    pub rounded_shares: Vec<i128>,
    pub residual: i128,
    pub shares: Vec<i128>,
}

fn signed_from_mag(mag: &Int, negative: bool) -> Result<i128, &'static str> {
    let raw = if negative {
        mag.negated()
    } else {
        mag.clone()
    };
    raw.to_i128().ok_or("amount overflow")
}

fn round_unsigned_fraction(
    quotient: &Int,
    remainder: &Int,
    denominator: &Int,
    negative: bool,
    mode: RoundingMode,
) -> Int {
    if remainder.is_zero() {
        return quotient.clone();
    }
    let twice_rem = remainder.add(remainder);
    let cmp_half = twice_rem.cmp(denominator);
    let increment = match mode {
        RoundingMode::TowardZero => false,
        RoundingMode::AwayFromZero => true,
        RoundingMode::Ceiling => !negative,
        RoundingMode::Floor => negative,
        RoundingMode::HalfAwayFromZero => cmp_half != core::cmp::Ordering::Less,
        RoundingMode::HalfTowardZero => cmp_half == core::cmp::Ordering::Greater,
        RoundingMode::HalfUp => {
            if cmp_half == core::cmp::Ordering::Equal {
                !negative
            } else {
                cmp_half == core::cmp::Ordering::Greater
            }
        }
        RoundingMode::HalfDown => {
            if cmp_half == core::cmp::Ordering::Equal {
                negative
            } else {
                cmp_half == core::cmp::Ordering::Greater
            }
        }
        RoundingMode::HalfEven => {
            if cmp_half == core::cmp::Ordering::Equal {
                let (_, rem2) = quotient
                    .div_rem(&Int::from_u128(2))
                    .expect("non-zero divisor 2");
                !rem2.is_zero()
            } else {
                cmp_half == core::cmp::Ordering::Greater
            }
        }
    };
    if increment {
        quotient.add(&Int::from_u128(1))
    } else {
        quotient.clone()
    }
}

/// Naïve Hamilton largest-remainder allocation using `Int` limb arithmetic.
pub fn largest_remainder(total: i128, weights: &[u128]) -> Result<Vec<i128>, &'static str> {
    let mut weight_sum = Int::zero();
    for &w in weights {
        weight_sum = weight_sum.add(&Int::from_u128(w));
    }
    if weight_sum.is_zero() {
        return Err("allocation weights sum to zero");
    }
    let negative = total < 0;
    let mag = Int::from_u128(total.unsigned_abs());
    let mut shares: Vec<Int> = Vec::with_capacity(weights.len());
    let mut remainders: Vec<(Int, usize)> = Vec::with_capacity(weights.len());
    let mut allocated = Int::zero();
    for (i, &w) in weights.iter().enumerate() {
        let num = mag.mul(&Int::from_u128(w));
        let (q, r) = num.div_rem(&weight_sum).ok_or("zero allocation divisor")?;
        allocated = allocated.add(&q);
        shares.push(q);
        remainders.push((r, i));
    }
    let mut residual = mag
        .sub(&allocated)
        .to_u128()
        .ok_or("invalid allocation residual")?;
    remainders.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    for (r, idx) in remainders {
        if residual == 0 || r.is_zero() {
            break;
        }
        shares[idx] = shares[idx].add(&Int::from_u128(1));
        residual -= 1;
    }
    if residual != 0 {
        return Err("allocation residual not fully distributed");
    }
    shares
        .iter()
        .map(|s| signed_from_mag(s, negative))
        .collect()
}

/// Naïve pro-rata allocation with residual assigned to `residual_target`.
pub fn pro_rata_residual_to_named(
    total: i128,
    weights: &[u128],
    residual_target: usize,
    mode: RoundingMode,
) -> Result<OracleProRata, &'static str> {
    if residual_target >= weights.len() {
        return Err("residual target out of bounds");
    }
    let mut denominator = Int::zero();
    for &w in weights {
        denominator = denominator.add(&Int::from_u128(w));
    }
    if denominator.is_zero() {
        return Err("allocation weights sum to zero");
    }
    let negative = total < 0;
    let mag = Int::from_u128(total.unsigned_abs());
    let mut rounded_shares = Vec::with_capacity(weights.len());
    let mut rounded_sum = Int::zero();
    for &w in weights {
        let num = mag.mul(&Int::from_u128(w));
        let (q, r) = num.div_rem(&denominator).ok_or("zero allocation divisor")?;
        let rounded_mag = round_unsigned_fraction(&q, &r, &denominator, negative, mode);
        let signed = signed_from_mag(&rounded_mag, negative)?;
        rounded_sum = rounded_sum.add(&Int::from_i128(signed));
        rounded_shares.push(signed);
    }
    let residual_int = Int::from_i128(total).sub(&rounded_sum);
    let residual = residual_int.to_i128().ok_or("residual overflow")?;
    let mut shares = rounded_shares.clone();
    shares[residual_target] = shares[residual_target]
        .checked_add(residual)
        .ok_or("share overflow")?;
    Ok(OracleProRata {
        rounded_shares,
        residual,
        shares,
    })
}

/// Naïve equal-split allocation assigning the entire remainder to target 0.
pub fn equal_split_residual_first(
    total: i128,
    target_count: usize,
) -> Result<Vec<i128>, &'static str> {
    if target_count == 0 {
        return Err("equal split requires at least one target");
    }
    let count = Int::from_u128(u128::try_from(target_count).map_err(|_| "count overflow")?);
    let negative = total < 0;
    let mag = Int::from_u128(total.unsigned_abs());
    let (q, r) = mag.div_rem(&count).ok_or("zero target count")?;
    let ordinary = signed_from_mag(&q, negative)?;
    let first = signed_from_mag(&q.add(&r), negative)?;
    let mut out = vec![ordinary; target_count];
    out[0] = first;
    Ok(out)
}

/// Naïve sequential waterfall allocation filling caps in priority order.
pub fn waterfall(total: i128, caps: &[u128]) -> Result<Vec<i128>, &'static str> {
    if caps.is_empty() {
        return Err("waterfall requires at least one target");
    }
    let negative = total < 0;
    let mut remaining = Int::from_u128(total.unsigned_abs());
    let mut shares = Vec::with_capacity(caps.len());
    for &cap in caps {
        let cap_int = Int::from_u128(cap);
        let share_mag = if remaining <= cap_int {
            remaining.clone()
        } else {
            cap_int
        };
        remaining = remaining.sub(&share_mag);
        shares.push(signed_from_mag(&share_mag, negative)?);
    }
    if !remaining.is_zero() {
        return Err("waterfall capacity is short");
    }
    Ok(shares)
}

// ---------------------------------------------------------------------------
// 2. Naïve Roll-Forward & General-Ledger Detail
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleRollForwardRow {
    pub account: String,
    pub unit: u32,
    pub opening: Int,
    pub by_class: BTreeMap<String, Int>,
    pub net_change: Int,
    pub closing: Int,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleGlLine {
    pub effective_day: DateDay,
    pub entry_index: usize,
    pub leg_index: usize,
    pub class: String,
    pub debits: i128,
    pub credits: i128,
    pub running_balance: Int,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleGlCell {
    pub account: String,
    pub unit: u32,
    pub opening: Int,
    pub debits: Int,
    pub credits: Int,
    pub net_change: Int,
    pub closing: Int,
    pub lines: Vec<OracleGlLine>,
}

fn net_leg(side: Side, mantissa: i128) -> Int {
    let m = Int::from_i128(mantissa);
    match side {
        Side::Debit => m,
        Side::Credit => m.negated(),
    }
}

/// Literal roll-forward schedule over `[effective_from, effective_through]` at `known`.
#[must_use]
pub fn roll_forward(
    oracle: &Oracle,
    known: Known,
    effective_from: DateDay,
    effective_through: DateDay,
    accounts: &[String],
    units: &[u32],
) -> BTreeMap<(String, u32), OracleRollForwardRow> {
    let mut classes = BTreeSet::new();
    for entry in oracle.entries()[..known.entries].iter() {
        if entry.class != "Pending"
            && oracle.visible(entry, known)
            && entry.date >= effective_from
            && entry.date <= effective_through
            && entry
                .legs
                .iter()
                .any(|l| accounts.contains(&l.account) && units.contains(&l.unit))
        {
            classes.insert(entry.class.clone());
        }
    }

    let mut out = BTreeMap::new();
    for account in accounts {
        for &unit in units {
            let mut opening = Int::zero();
            let mut closing = Int::zero();
            let mut by_class: BTreeMap<String, Int> =
                classes.iter().map(|c| (c.clone(), Int::zero())).collect();

            for entry in oracle.entries()[..known.entries].iter() {
                if entry.class == "Pending" || !oracle.visible(entry, known) {
                    continue;
                }
                for leg in &entry.legs {
                    if &leg.account != account || leg.unit != unit {
                        continue;
                    }
                    let delta = net_leg(leg.side, leg.mantissa);
                    if entry.date < effective_from {
                        opening = opening.add(&delta);
                    }
                    if entry.date <= effective_through {
                        closing = closing.add(&delta);
                    }
                    if entry.date >= effective_from && entry.date <= effective_through {
                        let slot = by_class.entry(entry.class.clone()).or_insert_with(Int::zero);
                        *slot = slot.add(&delta);
                    }
                }
            }
            let mut net_change = Int::zero();
            for v in by_class.values() {
                net_change = net_change.add(v);
            }
            assert_eq!(
                opening.add(&net_change),
                closing,
                "oracle roll-forward conservation for ({account}, {unit})"
            );
            out.insert(
                (account.clone(), unit),
                OracleRollForwardRow {
                    account: account.clone(),
                    unit,
                    opening,
                    by_class,
                    net_change,
                    closing,
                },
            );
        }
    }
    out
}

/// Literal general-ledger detail over `[effective_from, effective_through]` at `known`.
#[must_use]
pub fn gl_detail(
    oracle: &Oracle,
    known: Known,
    effective_from: DateDay,
    effective_through: DateDay,
    accounts: &[String],
    units: &[u32],
) -> BTreeMap<(String, u32), OracleGlCell> {
    let mut out = BTreeMap::new();
    for account in accounts {
        for &unit in units {
            let mut opening = Int::zero();
            let mut closing = Int::zero();
            let mut raw_movements = Vec::new();
            for (entry_idx, entry) in oracle.entries()[..known.entries].iter().enumerate() {
                if entry.class == "Pending" || !oracle.visible(entry, known) {
                    continue;
                }
                for (leg_idx, leg) in entry.legs.iter().enumerate() {
                    if &leg.account != account || leg.unit != unit {
                        continue;
                    }
                    let delta = net_leg(leg.side, leg.mantissa);
                    if entry.date < effective_from {
                        opening = opening.add(&delta);
                    }
                    if entry.date <= effective_through {
                        closing = closing.add(&delta);
                    }
                    if entry.date >= effective_from && entry.date <= effective_through {
                        let (debits, credits) = match leg.side {
                            Side::Debit => (leg.mantissa, 0),
                            Side::Credit => (0, leg.mantissa),
                        };
                        raw_movements.push((
                            entry.date,
                            entry_idx,
                            leg_idx,
                            entry.class.clone(),
                            debits,
                            credits,
                        ));
                    }
                }
            }
            raw_movements.sort_by_key(|(day, e_idx, l_idx, _, _, _)| (*day, *e_idx, *l_idx));
            let mut running = opening.clone();
            let mut debits_sum = Int::zero();
            let mut credits_sum = Int::zero();
            let mut lines = Vec::with_capacity(raw_movements.len());
            for (effective_day, entry_index, leg_index, class, debits, credits) in raw_movements {
                debits_sum = debits_sum.add(&Int::from_i128(debits));
                credits_sum = credits_sum.add(&Int::from_i128(credits));
                running = running
                    .add(&Int::from_i128(debits))
                    .sub(&Int::from_i128(credits));
                lines.push(OracleGlLine {
                    effective_day,
                    entry_index,
                    leg_index,
                    class,
                    debits,
                    credits,
                    running_balance: running.clone(),
                });
            }
            let net_change = debits_sum.sub(&credits_sum);
            assert_eq!(
                opening.add(&net_change),
                closing,
                "oracle gl_detail conservation for ({account}, {unit})"
            );
            assert_eq!(
                running, closing,
                "oracle gl_detail running balance equals closing for ({account}, {unit})"
            );
            out.insert(
                (account.clone(), unit),
                OracleGlCell {
                    account: account.clone(),
                    unit,
                    opening,
                    debits: debits_sum,
                    credits: credits_sum,
                    net_change,
                    closing,
                    lines,
                },
            );
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 3. Naïve Effective-Date Aging & Control Reconciliation
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleAgingBand {
    pub debits: Int,
    pub credits: Int,
    pub net: Int,
    pub item_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleAgingAccountUnit {
    pub account: String,
    pub unit: u32,
    pub bands: Vec<OracleAgingBand>,
    pub total_debits: Int,
    pub total_credits: Int,
    pub total_net: Int,
    pub control_net: Int,
}

/// Literal effective-date open-item aging and control-TB reconciliation at
/// `(accepted_prefix, effective_through)`.
#[must_use]
pub fn aging(
    oracle: &Oracle,
    accepted_prefix: usize,
    account_filter: Option<&str>,
    effective_through: DateDay,
    bucket_bounds: &[u32],
) -> BTreeMap<(String, u32), OracleAgingAccountUnit> {
    let known = oracle.known_after(accepted_prefix);
    let entries = &oracle.entries()[..accepted_prefix];
    let stock = oracle.stock_known(effective_through, known);
    let band_count = bucket_bounds.len() + 1;

    let mut cells: BTreeMap<(String, u32), OracleAgingAccountUnit> = BTreeMap::new();
    for ((acc, unit), cell) in &stock {
        if account_filter.is_some_and(|f| f != acc) {
            continue;
        }
        let control_net = cell.debits.sub(&cell.credits);
        if !control_net.is_zero() || cell.entry_count > 0 {
            cells.insert(
                (acc.clone(), *unit),
                OracleAgingAccountUnit {
                    account: acc.clone(),
                    unit: *unit,
                    bands: (0..band_count)
                        .map(|_| OracleAgingBand {
                            debits: Int::zero(),
                            credits: Int::zero(),
                            net: Int::zero(),
                            item_count: 0,
                        })
                        .collect(),
                    total_debits: Int::zero(),
                    total_credits: Int::zero(),
                    total_net: Int::zero(),
                    control_net,
                },
            );
        }
    }

    for (i, e) in entries.iter().enumerate() {
        if e.date > effective_through
            || !oracle.carries_open_items_at(e, known)
            || !oracle.is_live_at(i, accepted_prefix, effective_through)
        {
            continue;
        }
        for (o, leg) in e.legs.iter().enumerate() {
            if account_filter.is_some_and(|f| f != leg.account) {
                continue;
            }
            let mut applied_in = Int::zero();
            for (j, applying) in entries.iter().enumerate() {
                if applying.date > effective_through
                    || !oracle.carries_open_items_at(applying, known)
                    || !oracle.is_live_at(j, accepted_prefix, effective_through)
                {
                    continue;
                }
                for s in applying
                    .settles
                    .iter()
                    .filter(|s| s.target == i && s.ordinal == o)
                {
                    applied_in = applied_in.add(&Int::from_i128(s.mantissa));
                }
            }
            let mut applied_out = Int::zero();
            for s in e.settles.iter().filter(|s| s.leg == o) {
                applied_out = applied_out.add(&Int::from_i128(s.mantissa));
            }
            let open = Int::from_i128(leg.mantissa)
                .sub(&applied_in)
                .sub(&applied_out);
            if open.is_zero() || open.is_negative() {
                continue;
            }
            let age_days = u32::try_from(effective_through.0 - e.date.0).unwrap_or(0);
            let band_idx = bucket_bounds
                .iter()
                .position(|&bound| age_days <= bound)
                .unwrap_or(bucket_bounds.len());

            let summary = cells
                .entry((leg.account.clone(), leg.unit))
                .or_insert_with(|| OracleAgingAccountUnit {
                    account: leg.account.clone(),
                    unit: leg.unit,
                    bands: (0..band_count)
                        .map(|_| OracleAgingBand {
                            debits: Int::zero(),
                            credits: Int::zero(),
                            net: Int::zero(),
                            item_count: 0,
                        })
                        .collect(),
                    total_debits: Int::zero(),
                    total_credits: Int::zero(),
                    total_net: Int::zero(),
                    control_net: Int::zero(),
                });
            let band = &mut summary.bands[band_idx];
            match leg.side {
                Side::Debit => {
                    band.debits = band.debits.add(&open);
                    summary.total_debits = summary.total_debits.add(&open);
                }
                Side::Credit => {
                    band.credits = band.credits.add(&open);
                    summary.total_credits = summary.total_credits.add(&open);
                }
            }
            band.net = band.debits.sub(&band.credits);
            band.item_count += 1;
            summary.total_net = summary.total_debits.sub(&summary.total_credits);
        }
    }
    cells
}

// ---------------------------------------------------------------------------
// 4. Naïve Direct & Indirect Cash Flow
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CashActivity {
    Operating,
    Investing,
    Financing,
    ExchangeEffect,
    InternalTransfer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleCashSection {
    pub inflows: Int,
    pub outflows: Int,
    pub net: Int,
}

impl OracleCashSection {
    #[must_use]
    pub fn zero() -> Self {
        Self {
            inflows: Int::zero(),
            outflows: Int::zero(),
            net: Int::zero(),
        }
    }

    fn record_net(&mut self, net: &Int) {
        if net.is_zero() {
            return;
        }
        if net.is_negative() {
            self.outflows = self.outflows.add(&net.neg());
        } else {
            self.inflows = self.inflows.add(net);
        }
        self.net = self.inflows.sub(&self.outflows);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleDirectCashFlowUnit {
    pub unit: u32,
    pub opening: Int,
    pub operating: OracleCashSection,
    pub investing: OracleCashSection,
    pub financing: OracleCashSection,
    pub exchange_effects: OracleCashSection,
    pub net_change: Int,
    pub closing: Int,
}

/// Literal direct cash-flow schedule over `gl_detail` for `cash_accounts`.
/// Intra-entry opposing cash legs in the same `(entry_index, unit, activity)`
/// are netted before accumulating gross `inflows` and `outflows`.
pub fn direct_cash_flow(
    oracle: &Oracle,
    known: Known,
    effective_from: DateDay,
    effective_through: DateDay,
    cash_accounts: &[String],
    units: &[u32],
    classifications: &BTreeMap<(usize, usize), CashActivity>,
) -> Result<BTreeMap<u32, OracleDirectCashFlowUnit>, &'static str> {
    let gl = gl_detail(
        oracle,
        known,
        effective_from,
        effective_through,
        cash_accounts,
        units,
    );
    let mut out = BTreeMap::new();
    for &unit in units {
        let mut opening = Int::zero();
        let mut closing = Int::zero();
        let mut operating = OracleCashSection::zero();
        let mut investing = OracleCashSection::zero();
        let mut financing = OracleCashSection::zero();
        let mut exchange_effects = OracleCashSection::zero();
        let mut transfers: BTreeMap<usize, (Int, BTreeSet<String>)> = BTreeMap::new();
        let mut entry_activity_net: BTreeMap<(usize, CashActivity), Int> = BTreeMap::new();

        for account in cash_accounts {
            let cell = &gl[&(account.clone(), unit)];
            opening = opening.add(&cell.opening);
            closing = closing.add(&cell.closing);
            for line in &cell.lines {
                let activity = classifications
                    .get(&(line.entry_index, line.leg_index))
                    .ok_or("unclassified cash leg")?;
                let (side, mantissa) = if line.debits > 0 {
                    (Side::Debit, line.debits)
                } else {
                    (Side::Credit, line.credits)
                };
                match activity {
                    CashActivity::Operating
                    | CashActivity::Investing
                    | CashActivity::Financing
                    | CashActivity::ExchangeEffect => {
                        let slot = entry_activity_net
                            .entry((line.entry_index, *activity))
                            .or_insert_with(Int::zero);
                        *slot = slot.add(&net_leg(side, mantissa));
                    }
                    CashActivity::InternalTransfer => {
                        let slot = transfers
                            .entry(line.entry_index)
                            .or_insert_with(|| (Int::zero(), BTreeSet::new()));
                        slot.0 = slot.0.add(&net_leg(side, mantissa));
                        slot.1.insert(account.clone());
                    }
                }
            }
        }
        for ((_entry_idx, activity), net) in &entry_activity_net {
            match activity {
                CashActivity::Operating => operating.record_net(net),
                CashActivity::Investing => investing.record_net(net),
                CashActivity::Financing => financing.record_net(net),
                CashActivity::ExchangeEffect => exchange_effects.record_net(net),
                CashActivity::InternalTransfer => {}
            }
        }
        for (_, (net, touched_accounts)) in transfers {
            if !net.is_zero() || touched_accounts.len() < 2 {
                return Err("internal transfer does not net to zero across distinct cash accounts");
            }
        }
        let net_change = operating
            .net
            .add(&investing.net)
            .add(&financing.net)
            .add(&exchange_effects.net);
        if opening.add(&net_change) != closing {
            return Err("direct cash flow opening + net_change != closing");
        }
        out.insert(
            unit,
            OracleDirectCashFlowUnit {
                unit,
                opening,
                operating,
                investing,
                financing,
                exchange_effects,
                net_change,
                closing,
            },
        );
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndirectCategory {
    NonCash,
    WorkingCapital,
    NonOperating,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleIndirectAdjustment {
    pub entry_index: usize,
    pub leg_index: usize,
    pub category: IndirectCategory,
    pub debit_minus_credit: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleIndirectCashFlowUnit {
    pub unit: u32,
    pub net_income: Int,
    pub non_cash: Int,
    pub working_capital: Int,
    pub non_operating: Int,
    pub operating: Int,
    pub direct_operating: Int,
    pub operating_residual: Int,
    pub opening: Int,
    pub investing: Int,
    pub financing: Int,
    pub exchange_effects: Int,
    pub net_change: Int,
    pub closing: Int,
}

/// Literal indirect operating-cash reconciliation against `direct_cash_flow`.
pub fn indirect_cash_flow(
    oracle: &Oracle,
    known: Known,
    effective_from: DateDay,
    effective_through: DateDay,
    cash_accounts: &[String],
    net_income_by_unit: &BTreeMap<u32, Int>,
    direct: &BTreeMap<u32, OracleDirectCashFlowUnit>,
    adjustments: &[OracleIndirectAdjustment],
) -> Result<BTreeMap<u32, OracleIndirectCashFlowUnit>, &'static str> {
    let mut seen = BTreeSet::new();
    let mut non_cash_by_unit: BTreeMap<u32, Int> = BTreeMap::new();
    let mut wc_by_unit: BTreeMap<u32, Int> = BTreeMap::new();
    let mut non_op_by_unit: BTreeMap<u32, Int> = BTreeMap::new();

    for adj in adjustments {
        if !seen.insert((adj.entry_index, adj.leg_index)) {
            return Err("duplicate indirect cash-flow adjustment leg");
        }
        let entry = oracle
            .entries()
            .get(adj.entry_index)
            .ok_or("unknown adjustment entry")?;
        if adj.entry_index >= known.entries
            || entry.class == "Pending"
            || !oracle.visible(entry, known)
            || entry.date < effective_from
            || entry.date > effective_through
        {
            return Err("adjustment entry outside selected interval or visibility");
        }
        let leg = entry
            .legs
            .get(adj.leg_index)
            .ok_or("unknown adjustment leg")?;
        if cash_accounts.contains(&leg.account) {
            return Err("indirect adjustment cannot select a cash leg");
        }
        let amount = match (leg.side, adj.debit_minus_credit) {
            (Side::Debit, true) | (Side::Credit, false) => Int::from_i128(leg.mantissa),
            (Side::Debit, false) | (Side::Credit, true) => Int::from_i128(leg.mantissa).negated(),
        };
        let target_map = match adj.category {
            IndirectCategory::NonCash => &mut non_cash_by_unit,
            IndirectCategory::WorkingCapital => &mut wc_by_unit,
            IndirectCategory::NonOperating => &mut non_op_by_unit,
        };
        let slot = target_map.entry(leg.unit).or_insert_with(Int::zero);
        *slot = slot.add(&amount);
    }

    let mut out = BTreeMap::new();
    for (&unit, direct_unit) in direct {
        let net_income = net_income_by_unit
            .get(&unit)
            .cloned()
            .unwrap_or_else(Int::zero);
        let non_cash = non_cash_by_unit
            .get(&unit)
            .cloned()
            .unwrap_or_else(Int::zero);
        let working_capital = wc_by_unit.get(&unit).cloned().unwrap_or_else(Int::zero);
        let non_operating = non_op_by_unit
            .get(&unit)
            .cloned()
            .unwrap_or_else(Int::zero);
        let operating = net_income
            .add(&non_cash)
            .add(&working_capital)
            .add(&non_operating);
        let direct_operating = direct_unit.operating.net.clone();
        let operating_residual = operating.sub(&direct_operating);
        if !operating_residual.is_zero() {
            return Err("indirect operating cash does not reconcile to direct operating cash");
        }
        out.insert(
            unit,
            OracleIndirectCashFlowUnit {
                unit,
                net_income,
                non_cash,
                working_capital,
                non_operating,
                operating,
                direct_operating,
                operating_residual,
                opening: direct_unit.opening.clone(),
                investing: direct_unit.investing.net.clone(),
                financing: direct_unit.financing.net.clone(),
                exchange_effects: direct_unit.exchange_effects.net.clone(),
                net_change: direct_unit.net_change.clone(),
                closing: direct_unit.closing.clone(),
            },
        );
    }
    Ok(out)
}
