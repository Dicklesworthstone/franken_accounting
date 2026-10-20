//! Direct and Indirect Cash Flow statements (`CashFlowClassification`, reconciling
//! to cash and to each other) and `EquityRollForward` statements (reconciling opening
//! equity + net income + equity movements = closing total equity) (plan §12.1, bead `fa-i9yn`).
//!
//! All arithmetic uses exact `i128` and `U256` intermediates with zero floats.

use std::collections::{BTreeMap, BTreeSet};

use fa_model::{AccountType, DecodeError, EncodeError, EntryClass, Id128, Oid, Reader, Writer, domain_digest};
use fa_money::wide::U256;
use fa_time::DateDay;

use crate::{Account, AccountBalance, StatementError, Sum, input, overflow};

pub const CASH_FLOW_STATEMENT_FORMAT: &[u8] = b"fa:cash-flow-statement:v1";
pub const EQUITY_ROLL_FORWARD_FORMAT: &[u8] = b"fa:equity-roll-forward:v1";

const MAX_MOVEMENTS: usize = 2_000_000;

/// Cash-flow activity classification on a cash leg (plan §12.1, `fa-i9yn`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CashFlowClassification {
    Operating,
    Investing,
    Financing,
    ExchangeEffect,
    InternalTransfer,
}

impl CashFlowClassification {
    pub const fn tag(self) -> u8 {
        match self {
            Self::Operating => 1,
            Self::Investing => 2,
            Self::Financing => 3,
            Self::ExchangeEffect => 4,
            Self::InternalTransfer => 5,
        }
    }

    pub fn from_tag(tag: u8, r: &Reader<'_>) -> Result<Self, DecodeError> {
        match tag {
            1 => Ok(Self::Operating),
            2 => Ok(Self::Investing),
            3 => Ok(Self::Financing),
            4 => Ok(Self::ExchangeEffect),
            5 => Ok(Self::InternalTransfer),
            _ => Err(r.bad_tag("cash_flow_classification", tag)),
        }
    }
}

/// Indirect operating cash-flow bridge category (plan §12.1, `fa-i9yn`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IndirectAdjustmentCategory {
    /// Non-cash income/expense (e.g., depreciation, amortization, stock compensation).
    NonCash,
    /// Operating working-capital change (e.g., AR, inventory, AP, accrued expenses).
    WorkingCapital,
    /// Non-operating gain/loss reclassified to investing or financing.
    NonOperating,
}

impl IndirectAdjustmentCategory {
    pub const fn tag(self) -> u8 {
        match self {
            Self::NonCash => 1,
            Self::WorkingCapital => 2,
            Self::NonOperating => 3,
        }
    }

    pub fn from_tag(tag: u8, r: &Reader<'_>) -> Result<Self, DecodeError> {
        match tag {
            1 => Ok(Self::NonCash),
            2 => Ok(Self::WorkingCapital),
            3 => Ok(Self::NonOperating),
            _ => Err(r.bad_tag("indirect_adjustment_category", tag)),
        }
    }
}

/// One posted leg on a designated cash account in `[effective_from, effective_through]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashLegMovement {
    pub entry_digest: [u8; 32],
    pub leg_index: u32,
    pub recorded_seq: u64,
    pub effective_day: DateDay,
    pub account_id: u128,
    pub unit_id: u32,
    pub classification: CashFlowClassification,
    pub debits: i128,
    pub credits: i128,
}

/// One non-cash leg adjustment in the indirect operating cash-flow bridge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndirectAdjustmentLeg {
    pub entry_digest: [u8; 32],
    pub leg_index: u32,
    pub recorded_seq: u64,
    pub effective_day: DateDay,
    pub account_id: u128,
    pub unit_id: u32,
    pub category: IndirectAdjustmentCategory,
    /// When `true`, the bridge adjustment adds `debits - credits`; when `false`, adds `credits - debits`.
    pub debit_minus_credit: bool,
    pub debits: i128,
    pub credits: i128,
}

/// Gross inflows, gross outflows, and net cash flow for one activity section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowSection {
    pub inflows: i128,
    pub outflows: i128,
    pub net: i128,
}

impl CashFlowSection {
    pub const ZERO: Self = Self {
        inflows: 0,
        outflows: 0,
        net: 0,
    };

    fn encode(&self, w: &mut Writer) {
        w.i128(self.inflows).i128(self.outflows).i128(self.net);
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            inflows: r.i128("section.inflows")?,
            outflows: r.i128("section.outflows")?,
            net: r.i128("section.net")?,
        })
    }
}

/// Direct and Indirect cash-flow reconciliation for one native unit (`fa-i9yn`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowUnitReport {
    pub unit_id: u32,
    pub opening_cash: i128,
    pub operating: CashFlowSection,
    pub investing: CashFlowSection,
    pub financing: CashFlowSection,
    pub exchange_effects: CashFlowSection,
    pub net_income: i128,
    pub non_cash_adjustments: i128,
    pub working_capital_changes: i128,
    pub non_operating_adjustments: i128,
    pub indirect_operating_cash: i128,
    /// Must equal `0` (`indirect_operating_cash - operating.net`).
    pub direct_vs_indirect_residual: i128,
    pub net_cash_change: i128,
    pub closing_cash: i128,
    /// Must equal `0` (`opening_cash + net_cash_change - closing_cash`).
    pub cash_tie_out_residual: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowInput {
    pub book_id: Id128,
    pub branch_id: Id128,
    pub known_at: u64,
    pub label: String,
    pub effective_from: DateDay,
    pub effective_through: DateDay,
    pub accounts: Vec<Account>,
    /// Designated cash and cash-equivalent leaf account IDs.
    pub cash_account_ids: Vec<u128>,
    pub units: Vec<u32>,
    /// Opening balances (`< effective_from`) of `cash_account_ids`.
    pub opening_cash_balances: Vec<AccountBalance>,
    /// Closing balances (`<= effective_through`) of `cash_account_ids`.
    pub closing_cash_balances: Vec<AccountBalance>,
    /// Period `net_income` per unit (from the Income Statement fold).
    pub net_income_by_unit: BTreeMap<u32, i128>,
    pub cash_movements: Vec<CashLegMovement>,
    pub indirect_adjustments: Vec<IndirectAdjustmentLeg>,
}

/// Certified-ready Cash Flow Statement containing both Direct and Indirect methods
/// and proving both `direct == indirect` and `opening_cash + net_change == closing_cash`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowStatement {
    pub book_id: Id128,
    pub branch_id: Id128,
    pub known_at: u64,
    pub label: String,
    pub effective_from: DateDay,
    pub effective_through: DateDay,
    pub cash_account_ids: Vec<u128>,
    pub units: Vec<CashFlowUnitReport>,
}

impl CashFlowStatement {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(CASH_FLOW_STATEMENT_FORMAT)
            .fixed(&self.book_id.0)
            .fixed(&self.branch_id.0)
            .u64(self.known_at)
            .str(&self.label)
            .i32(self.effective_from.0)
            .i32(self.effective_through.0)
            .list(&self.cash_account_ids, |w, id| {
                w.u128(*id);
            })
            .list(&self.units, |w, u| {
                w.u32(u.unit_id).i128(u.opening_cash);
                u.operating.encode(w);
                u.investing.encode(w);
                u.financing.encode(w);
                u.exchange_effects.encode(w);
                w.i128(u.net_income)
                    .i128(u.non_cash_adjustments)
                    .i128(u.working_capital_changes)
                    .i128(u.non_operating_adjustments)
                    .i128(u.indirect_operating_cash)
                    .i128(u.direct_vs_indirect_residual)
                    .i128(u.net_cash_change)
                    .i128(u.closing_cash)
                    .i128(u.cash_tie_out_residual);
            });
        w.finish()
    }

    pub fn digest(&self) -> Result<Oid, EncodeError> {
        Ok(Oid(domain_digest(
            CASH_FLOW_STATEMENT_FORMAT,
            &[&self.canonical_bytes()?],
        )))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let magic = r.fixed::<{ CASH_FLOW_STATEMENT_FORMAT.len() }>("cash_flow.magic")?;
        if magic != CASH_FLOW_STATEMENT_FORMAT {
            return Err(r.invalid("cash flow statement header"));
        }
        let book_id = Id128(r.fixed::<16>("book_id")?);
        let branch_id = Id128(r.fixed::<16>("branch_id")?);
        let known_at = r.u64("known_at")?;
        let label = r.str(256, "label")?.to_string();
        let effective_from = DateDay(r.i32("effective_from")?);
        let effective_through = DateDay(r.i32("effective_through")?);
        let cash_account_ids = r.list(4096, "cash_account_ids", |r| r.u128("cash_account_id"))?;
        let units = r.list(4096, "units", |r| {
            let unit_id = r.u32("unit_id")?;
            let opening_cash = r.i128("opening_cash")?;
            let operating = CashFlowSection::decode(r)?;
            let investing = CashFlowSection::decode(r)?;
            let financing = CashFlowSection::decode(r)?;
            let exchange_effects = CashFlowSection::decode(r)?;
            let net_income = r.i128("net_income")?;
            let non_cash_adjustments = r.i128("non_cash_adjustments")?;
            let working_capital_changes = r.i128("working_capital_changes")?;
            let non_operating_adjustments = r.i128("non_operating_adjustments")?;
            let indirect_operating_cash = r.i128("indirect_operating_cash")?;
            let direct_vs_indirect_residual = r.i128("direct_vs_indirect_residual")?;
            let net_cash_change = r.i128("net_cash_change")?;
            let closing_cash = r.i128("closing_cash")?;
            let cash_tie_out_residual = r.i128("cash_tie_out_residual")?;
            Ok(CashFlowUnitReport {
                unit_id,
                opening_cash,
                operating,
                investing,
                financing,
                exchange_effects,
                net_income,
                non_cash_adjustments,
                working_capital_changes,
                non_operating_adjustments,
                indirect_operating_cash,
                direct_vs_indirect_residual,
                net_cash_change,
                closing_cash,
                cash_tie_out_residual,
            })
        })?;
        r.finish()?;
        Ok(Self {
            book_id,
            branch_id,
            known_at,
            label,
            effective_from,
            effective_through,
            cash_account_ids,
            units,
        })
    }
}

/// Evaluate both Direct and Indirect Cash Flow statements and enforce that:
/// 1. Intra-entry opposing cash legs in the same `(entry_digest, unit_id, classification)`
///    are netted before gross inflows and outflows are accumulated (`fa-gb47`).
/// 2. `InternalTransfer` legs net to `0` across at least two distinct cash accounts per entry.
/// 3. Indirect operating cash (`net_income + non_cash + working_capital + non_operating`)
///    reconciles with zero residual to Direct operating cash (`operating.net`).
/// 4. `opening_cash + net_cash_change == closing_cash` for every unit.
pub fn evaluate_cash_flow(source: &CashFlowInput) -> Result<CashFlowStatement, StatementError> {
    if source.label.trim().is_empty() || source.label.len() > 256 {
        return Err(input("cash-flow label is empty or exceeds 256 bytes"));
    }
    if source.effective_from > source.effective_through {
        return Err(input("cash-flow effective bounds are reversed"));
    }
    if source.cash_account_ids.is_empty() || source.units.is_empty() {
        return Err(input(
            "cash-flow statement requires nonempty cash_account_ids and units",
        ));
    }
    if source.cash_movements.len() > MAX_MOVEMENTS
        || source.indirect_adjustments.len() > MAX_MOVEMENTS
    {
        return Err(input("cash-flow movements exceed bound"));
    }

    let accounts: BTreeMap<u128, &Account> = source.accounts.iter().map(|a| (a.id, a)).collect();
    if accounts.len() != source.accounts.len() {
        return Err(input("duplicate account in cash-flow input"));
    }
    let mut cash_set = BTreeSet::new();
    for &cid in &source.cash_account_ids {
        let acct = accounts
            .get(&cid)
            .ok_or_else(|| input(format!("unknown cash account {:032x}", cid)))?;
        if !acct.is_leaf || acct.account_type != 1 {
            return Err(input(format!(
                "cash account `{}` must be a leaf Asset (type 1) account",
                acct.code
            )));
        }
        if !cash_set.insert(cid) {
            return Err(input("duplicate cash account ID"));
        }
    }

    let mut units = source.units.clone();
    units.sort_unstable();
    if units.windows(2).any(|w| w[0] == w[1]) {
        return Err(input("duplicate unit in cash-flow input"));
    }
    let unit_set: BTreeSet<u32> = units.iter().copied().collect();

    let sum_cash_stock = |balances: &[AccountBalance],
                          which: &str|
     -> Result<BTreeMap<u32, i128>, StatementError> {
        let mut seen = BTreeSet::new();
        let mut sums: BTreeMap<u32, Sum> = units.iter().map(|&u| (u, Sum::ZERO)).collect();
        for b in balances {
            if !cash_set.contains(&b.account_id) || !unit_set.contains(&b.unit_id) {
                return Err(input(format!(
                    "{which} cash balance ({:032x}, {}) is outside declared cash/unit scope",
                    b.account_id, b.unit_id
                )));
            }
            if b.debits < 0 || b.credits < 0 {
                return Err(input(format!(
                    "{which} cash balance has negative debit/credit"
                )));
            }
            if !seen.insert((b.account_id, b.unit_id)) {
                return Err(input(format!(
                    "duplicate {which} cash balance for ({:032x}, {})",
                    b.account_id, b.unit_id
                )));
            }
            let slot = sums.get_mut(&b.unit_id).unwrap();
            let failed = || overflow(which, &source.label, b.unit_id);
            slot.add(b.debits, false).ok_or_else(failed)?;
            slot.add(b.credits, true).ok_or_else(failed)?;
        }
        let mut out = BTreeMap::new();
        for (&u, s) in &sums {
            out.insert(
                u,
                s.value().ok_or_else(|| overflow(which, &source.label, u))?,
            );
        }
        Ok(out)
    };

    let opening_by_unit = sum_cash_stock(&source.opening_cash_balances, "opening_cash")?;
    let closing_by_unit = sum_cash_stock(&source.closing_cash_balances, "closing_cash")?;

    // Net intra-entry cash movements per (entry_digest, unit_id, classification).
    let mut seen_cash_legs = BTreeSet::new();
    let mut entry_activity_net: BTreeMap<([u8; 32], u32, CashFlowClassification), Sum> =
        BTreeMap::new();
    let mut transfers: BTreeMap<([u8; 32], u32), (Sum, BTreeSet<u128>)> = BTreeMap::new();

    for mov in &source.cash_movements {
        if !cash_set.contains(&mov.account_id) || !unit_set.contains(&mov.unit_id) {
            return Err(input("cash movement lies outside declared cash/unit scope"));
        }
        if mov.recorded_seq == 0
            || mov.recorded_seq > source.known_at
            || mov.effective_day < source.effective_from
            || mov.effective_day > source.effective_through
        {
            return Err(input(
                "cash movement lies outside selected bitemporal coordinate",
            ));
        }
        if mov.debits < 0 || mov.credits < 0 || (mov.debits > 0) == (mov.credits > 0) {
            return Err(input(
                "cash movement must have exactly one positive debit or credit side",
            ));
        }
        if !seen_cash_legs.insert((mov.entry_digest, mov.leg_index)) {
            return Err(input("duplicate cash leg in cash_movements"));
        }
        let failed = || overflow("cash_movement", &source.label, mov.unit_id);
        match mov.classification {
            CashFlowClassification::InternalTransfer => {
                let slot = transfers
                    .entry((mov.entry_digest, mov.unit_id))
                    .or_insert_with(|| (Sum::ZERO, BTreeSet::new()));
                slot.0.add(mov.debits, false).ok_or_else(failed)?;
                slot.0.add(mov.credits, true).ok_or_else(failed)?;
                slot.1.insert(mov.account_id);
            }
            other => {
                let slot = entry_activity_net
                    .entry((mov.entry_digest, mov.unit_id, other))
                    .or_insert(Sum::ZERO);
                slot.add(mov.debits, false).ok_or_else(failed)?;
                slot.add(mov.credits, true).ok_or_else(failed)?;
            }
        }
    }

    for ((_digest, unit_id), (sum, touched)) in transfers {
        let net = sum
            .value()
            .ok_or_else(|| overflow("internal_transfer", &source.label, unit_id))?;
        if net != 0 || touched.len() < 2 {
            return Err(input(
                "internal cash transfer must net to zero across at least two distinct cash accounts",
            ));
        }
    }

    // Accumulate indirect adjustments per (unit_id, category).
    let mut seen_adj_legs = BTreeSet::new();
    let mut indirect_sums: BTreeMap<(u32, IndirectAdjustmentCategory), Sum> = BTreeMap::new();
    for adj in &source.indirect_adjustments {
        if cash_set.contains(&adj.account_id) {
            return Err(input(
                "indirect cash-flow adjustment cannot reference a cash account leg",
            ));
        }
        let acct = accounts
            .get(&adj.account_id)
            .ok_or_else(|| input("indirect adjustment references unknown account"))?;
        if !acct.is_leaf || !unit_set.contains(&adj.unit_id) {
            return Err(input(
                "indirect adjustment must reference a leaf non-cash account and declared unit",
            ));
        }
        if adj.recorded_seq == 0
            || adj.recorded_seq > source.known_at
            || adj.effective_day < source.effective_from
            || adj.effective_day > source.effective_through
        {
            return Err(input(
                "indirect adjustment lies outside selected bitemporal coordinate",
            ));
        }
        if adj.debits < 0 || adj.credits < 0 || (adj.debits > 0) == (adj.credits > 0) {
            return Err(input(
                "indirect adjustment must have exactly one positive debit or credit side",
            ));
        }
        if !seen_adj_legs.insert((adj.entry_digest, adj.leg_index)) {
            return Err(input("duplicate leg in indirect_adjustments"));
        }
        let slot = indirect_sums
            .entry((adj.unit_id, adj.category))
            .or_insert(Sum::ZERO);
        let failed = || overflow("indirect_adjustment", &source.label, adj.unit_id);
        if adj.debit_minus_credit {
            slot.add(adj.debits, false).ok_or_else(failed)?;
            slot.add(adj.credits, true).ok_or_else(failed)?;
        } else {
            slot.add(adj.credits, false).ok_or_else(failed)?;
            slot.add(adj.debits, true).ok_or_else(failed)?;
        }
    }

    let build_section = |unit_id: u32,
                         classification: CashFlowClassification|
     -> Result<CashFlowSection, StatementError> {
        let mut inflows_wide = U256::ZERO;
        let mut outflows_wide = U256::ZERO;
        let failed = || overflow("cash_section", &source.label, unit_id);
        for ((_digest, u, cls), sum) in &entry_activity_net {
            if *u != unit_id || *cls != classification {
                continue;
            }
            let net = sum.value().ok_or_else(failed)?;
            if net > 0 {
                inflows_wide = inflows_wide
                    .checked_add(U256::from_u128(net.unsigned_abs()))
                    .ok_or_else(failed)?;
            } else if net < 0 {
                outflows_wide = outflows_wide
                    .checked_add(U256::from_u128(net.unsigned_abs()))
                    .ok_or_else(failed)?;
            }
        }
        let inflows = i128::try_from(inflows_wide.to_u128().ok_or_else(failed)?)
            .map_err(|_| failed())?;
        let outflows = i128::try_from(outflows_wide.to_u128().ok_or_else(failed)?)
            .map_err(|_| failed())?;
        let net = inflows.checked_sub(outflows).ok_or_else(failed)?;
        Ok(CashFlowSection {
            inflows,
            outflows,
            net,
        })
    };

    let mut unit_reports = Vec::with_capacity(units.len());
    for &unit_id in &units {
        let failed = || overflow("cash_flow_unit", &source.label, unit_id);
        let opening_cash = opening_by_unit[&unit_id];
        let closing_cash = closing_by_unit[&unit_id];
        let operating = build_section(unit_id, CashFlowClassification::Operating)?;
        let investing = build_section(unit_id, CashFlowClassification::Investing)?;
        let financing = build_section(unit_id, CashFlowClassification::Financing)?;
        let exchange_effects = build_section(unit_id, CashFlowClassification::ExchangeEffect)?;

        let mut net_change_sum = Sum::ZERO;
        for part in [
            operating.net,
            investing.net,
            financing.net,
            exchange_effects.net,
        ] {
            net_change_sum.add(part, false).ok_or_else(failed)?;
        }
        let net_cash_change = net_change_sum.value().ok_or_else(failed)?;

        let mut tie_out = Sum::ZERO;
        tie_out.add(opening_cash, false).ok_or_else(failed)?;
        tie_out.add(net_cash_change, false).ok_or_else(failed)?;
        tie_out.add(closing_cash, true).ok_or_else(failed)?;
        let cash_tie_out_residual = tie_out.value().ok_or_else(failed)?;
        if cash_tie_out_residual != 0 {
            return Err(StatementError::Identity {
                line: "cash_tie_out".into(),
                column: source.label.clone(),
                unit_id,
                residual: cash_tie_out_residual,
            });
        }

        let net_income = source.net_income_by_unit.get(&unit_id).copied().unwrap_or(0);
        let get_ind = |cat: IndirectAdjustmentCategory| -> Result<i128, StatementError> {
            match indirect_sums.get(&(unit_id, cat)) {
                Some(s) => s.value().ok_or_else(failed),
                None => Ok(0),
            }
        };
        let non_cash_adjustments = get_ind(IndirectAdjustmentCategory::NonCash)?;
        let working_capital_changes = get_ind(IndirectAdjustmentCategory::WorkingCapital)?;
        let non_operating_adjustments = get_ind(IndirectAdjustmentCategory::NonOperating)?;

        let mut ind_op_sum = Sum::ZERO;
        for part in [
            net_income,
            non_cash_adjustments,
            working_capital_changes,
            non_operating_adjustments,
        ] {
            ind_op_sum.add(part, false).ok_or_else(failed)?;
        }
        let indirect_operating_cash = ind_op_sum.value().ok_or_else(failed)?;
        let direct_vs_indirect_residual = indirect_operating_cash
            .checked_sub(operating.net)
            .ok_or_else(failed)?;
        if direct_vs_indirect_residual != 0 {
            return Err(StatementError::Identity {
                line: "indirect_vs_direct_operating_cash".into(),
                column: source.label.clone(),
                unit_id,
                residual: direct_vs_indirect_residual,
            });
        }

        unit_reports.push(CashFlowUnitReport {
            unit_id,
            opening_cash,
            operating,
            investing,
            financing,
            exchange_effects,
            net_income,
            non_cash_adjustments,
            working_capital_changes,
            non_operating_adjustments,
            indirect_operating_cash,
            direct_vs_indirect_residual,
            net_cash_change,
            closing_cash,
            cash_tie_out_residual,
        });
    }

    let mut sorted_cash_ids: Vec<u128> = cash_set.into_iter().collect();
    sorted_cash_ids.sort_unstable();

    Ok(CashFlowStatement {
        book_id: source.book_id,
        branch_id: source.branch_id,
        known_at: source.known_at,
        label: source.label.clone(),
        effective_from: source.effective_from,
        effective_through: source.effective_through,
        cash_account_ids: sorted_cash_ids,
        units: unit_reports,
    })
}

/// Classification of direct movements on Equity accounts (`AccountType == 3`)
/// in an `EquityRollForward` statement (plan §12.1, `fa-i9yn`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EquityActivityKind {
    /// Owner contributions / share issuances.
    Issuance,
    /// Dividends, distributions, draws, or share repurchases.
    Distribution,
    /// Closing transfer from nominal accounts (`EntryClass::CLOSING`).
    ClosingTransfer,
    /// Other direct equity movements (e.g., OCI, reclassifications).
    OtherEquity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquityMovement {
    pub entry_digest: [u8; 32],
    pub leg_index: u32,
    pub recorded_seq: u64,
    pub effective_day: DateDay,
    pub class: EntryClass,
    pub kind: EquityActivityKind,
    pub account_id: u128,
    pub unit_id: u32,
    pub debits: i128,
    pub credits: i128,
}

/// Reconciled Statement of Changes in Equity for one unit (`fa-i9yn`).
///
/// Credit-normal sign convention (`credits - debits`):
/// `opening_total_equity + net_income + issuances + distributions + other_equity_movements == closing_total_equity`,
/// and `closing_transfers_net == 0` (closing transfers move unclosed earnings into retained earnings
/// without changing total equity).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquityRollForwardUnit {
    pub unit_id: u32,
    pub opening_contributed_equity: i128,
    pub opening_unclosed_earnings: i128,
    pub opening_total_equity: i128,
    pub net_income: i128,
    pub issuances: i128,
    pub distributions: i128,
    pub other_equity_movements: i128,
    /// Net effect on total equity of `Closing` entries (must equal `0`).
    pub closing_transfers_net: i128,
    pub net_equity_change: i128,
    pub closing_contributed_equity: i128,
    pub closing_unclosed_earnings: i128,
    pub closing_total_equity: i128,
    /// Must equal `0` (`opening_total_equity + net_equity_change - closing_total_equity`).
    pub equity_tie_out_residual: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquityRollForwardInput {
    pub book_id: Id128,
    pub branch_id: Id128,
    pub known_at: u64,
    pub label: String,
    pub effective_from: DateDay,
    pub effective_through: DateDay,
    pub accounts: Vec<Account>,
    pub units: Vec<u32>,
    /// Opening balances (`< effective_from`) across Equity (`3`), Revenue (`4`), and Expense (`5`) accounts.
    pub opening_balances: Vec<AccountBalance>,
    /// Closing balances (`<= effective_through`) across Equity (`3`), Revenue (`4`), and Expense (`5`) accounts.
    pub closing_balances: Vec<AccountBalance>,
    /// Period `net_income` per unit (excluding `Closing` entries, matching Income Statement `net_income`).
    pub net_income_by_unit: BTreeMap<u32, i128>,
    /// Posted legs in `[effective_from, effective_through]` on Equity (`3`) accounts (plus nominal legs of `Closing` entries).
    pub equity_movements: Vec<EquityMovement>,
}

/// Certified-ready Statement of Changes in Equity (`EquityRollForward`, plan §12.1, `fa-i9yn`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquityRollForward {
    pub book_id: Id128,
    pub branch_id: Id128,
    pub known_at: u64,
    pub label: String,
    pub effective_from: DateDay,
    pub effective_through: DateDay,
    pub units: Vec<EquityRollForwardUnit>,
}

impl EquityRollForward {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(EQUITY_ROLL_FORWARD_FORMAT)
            .fixed(&self.book_id.0)
            .fixed(&self.branch_id.0)
            .u64(self.known_at)
            .str(&self.label)
            .i32(self.effective_from.0)
            .i32(self.effective_through.0)
            .list(&self.units, |w, u| {
                w.u32(u.unit_id)
                    .i128(u.opening_contributed_equity)
                    .i128(u.opening_unclosed_earnings)
                    .i128(u.opening_total_equity)
                    .i128(u.net_income)
                    .i128(u.issuances)
                    .i128(u.distributions)
                    .i128(u.other_equity_movements)
                    .i128(u.closing_transfers_net)
                    .i128(u.net_equity_change)
                    .i128(u.closing_contributed_equity)
                    .i128(u.closing_unclosed_earnings)
                    .i128(u.closing_total_equity)
                    .i128(u.equity_tie_out_residual);
            });
        w.finish()
    }

    pub fn digest(&self) -> Result<Oid, EncodeError> {
        Ok(Oid(domain_digest(
            EQUITY_ROLL_FORWARD_FORMAT,
            &[&self.canonical_bytes()?],
        )))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let magic = r.fixed::<{ EQUITY_ROLL_FORWARD_FORMAT.len() }>("equity_rf.magic")?;
        if magic != EQUITY_ROLL_FORWARD_FORMAT {
            return Err(r.invalid("equity roll-forward header"));
        }
        let book_id = Id128(r.fixed::<16>("book_id")?);
        let branch_id = Id128(r.fixed::<16>("branch_id")?);
        let known_at = r.u64("known_at")?;
        let label = r.str(256, "label")?.to_string();
        let effective_from = DateDay(r.i32("effective_from")?);
        let effective_through = DateDay(r.i32("effective_through")?);
        let units = r.list(4096, "units", |r| {
            Ok(EquityRollForwardUnit {
                unit_id: r.u32("unit_id")?,
                opening_contributed_equity: r.i128("opening_contributed_equity")?,
                opening_unclosed_earnings: r.i128("opening_unclosed_earnings")?,
                opening_total_equity: r.i128("opening_total_equity")?,
                net_income: r.i128("net_income")?,
                issuances: r.i128("issuances")?,
                distributions: r.i128("distributions")?,
                other_equity_movements: r.i128("other_equity_movements")?,
                closing_transfers_net: r.i128("closing_transfers_net")?,
                net_equity_change: r.i128("net_equity_change")?,
                closing_contributed_equity: r.i128("closing_contributed_equity")?,
                closing_unclosed_earnings: r.i128("closing_unclosed_earnings")?,
                closing_total_equity: r.i128("closing_total_equity")?,
                equity_tie_out_residual: r.i128("equity_tie_out_residual")?,
            })
        })?;
        r.finish()?;
        Ok(Self {
            book_id,
            branch_id,
            known_at,
            label,
            effective_from,
            effective_through,
            units,
        })
    }
}

/// Evaluate an `EquityRollForward` statement and verify that opening equity plus
/// net income and direct equity movements equals closing equity per unit (`fa-i9yn`).
pub fn evaluate_equity_roll_forward(
    source: &EquityRollForwardInput,
) -> Result<EquityRollForward, StatementError> {
    if source.label.trim().is_empty() || source.label.len() > 256 {
        return Err(input("equity roll-forward label is empty or exceeds 256 bytes"));
    }
    if source.effective_from > source.effective_through {
        return Err(input("equity roll-forward effective bounds are reversed"));
    }
    if source.units.is_empty() {
        return Err(input("equity roll-forward requires at least one unit"));
    }
    let mut units = source.units.clone();
    units.sort_unstable();
    if units.windows(2).any(|w| w[0] == w[1]) {
        return Err(input("duplicate unit in equity roll-forward"));
    }
    let unit_set: BTreeSet<u32> = units.iter().copied().collect();

    let accounts: BTreeMap<u128, &Account> = source.accounts.iter().map(|a| (a.id, a)).collect();
    if accounts.len() != source.accounts.len() {
        return Err(input("duplicate account in equity roll-forward"));
    }
    for acct in accounts.values() {
        if !AccountType(acct.account_type).is_registered() {
            return Err(input(format!(
                "account `{}` has unknown type {}",
                acct.code, acct.account_type
            )));
        }
    }

    let fold_equity_stock = |balances: &[AccountBalance],
                             which: &str|
     -> Result<BTreeMap<u32, (i128, i128)>, StatementError> {
        let mut seen = BTreeSet::new();
        let mut contributed: BTreeMap<u32, Sum> = units.iter().map(|&u| (u, Sum::ZERO)).collect();
        let mut unclosed: BTreeMap<u32, Sum> = units.iter().map(|&u| (u, Sum::ZERO)).collect();
        for b in balances {
            let acct = accounts
                .get(&b.account_id)
                .ok_or_else(|| input(format!("{which} balance names unknown account")))?;
            if !acct.is_leaf || !unit_set.contains(&b.unit_id) {
                return Err(input(format!(
                    "{which} balance must reference a leaf account and declared unit"
                )));
            }
            if b.debits < 0 || b.credits < 0 {
                return Err(input(format!(
                    "{which} balance has negative debit/credit"
                )));
            }
            if !seen.insert((b.account_id, b.unit_id)) {
                return Err(input(format!("duplicate {which} balance cell")));
            }
            let failed = || overflow(which, &source.label, b.unit_id);
            match acct.account_type {
                3 => {
                    // Equity (credit-normal: credits - debits)
                    let slot = contributed.get_mut(&b.unit_id).unwrap();
                    slot.add(b.credits, false).ok_or_else(failed)?;
                    slot.add(b.debits, true).ok_or_else(failed)?;
                }
                4 | 5 => {
                    // Unclosed Revenue (4) and Expense (5): credit - debit
                    let slot = unclosed.get_mut(&b.unit_id).unwrap();
                    slot.add(b.credits, false).ok_or_else(failed)?;
                    slot.add(b.debits, true).ok_or_else(failed)?;
                }
                _ => {}
            }
        }
        let mut out = BTreeMap::new();
        for &u in &units {
            let failed = || overflow(which, &source.label, u);
            out.insert(
                u,
                (
                    contributed[&u].value().ok_or_else(failed)?,
                    unclosed[&u].value().ok_or_else(failed)?,
                ),
            );
        }
        Ok(out)
    };

    let opening_stock = fold_equity_stock(&source.opening_balances, "opening_equity")?;
    let closing_stock = fold_equity_stock(&source.closing_balances, "closing_equity")?;

    let mut seen_legs = BTreeSet::new();
    let mut activity_sums: BTreeMap<(u32, EquityActivityKind), Sum> = BTreeMap::new();
    for mov in &source.equity_movements {
        let acct = accounts
            .get(&mov.account_id)
            .ok_or_else(|| input("equity movement references unknown account"))?;
        if !acct.is_leaf || !unit_set.contains(&mov.unit_id) {
            return Err(input(
                "equity movement must reference a leaf account and declared unit",
            ));
        }
        if !mov.class.is_registered() || mov.class.is_control() || mov.class == EntryClass::PENDING
        {
            return Err(input(
                "equity movement must carry a registered posted EntryClass",
            ));
        }
        if mov.recorded_seq == 0
            || mov.recorded_seq > source.known_at
            || mov.effective_day < source.effective_from
            || mov.effective_day > source.effective_through
        {
            return Err(input(
                "equity movement lies outside selected bitemporal coordinate",
            ));
        }
        if mov.debits < 0 || mov.credits < 0 || (mov.debits > 0) == (mov.credits > 0) {
            return Err(input(
                "equity movement must have exactly one positive debit or credit side",
            ));
        }
        if !seen_legs.insert((mov.entry_digest, mov.leg_index)) {
            return Err(input("duplicate leg in equity_movements"));
        }
        match (mov.kind, acct.account_type) {
            (EquityActivityKind::ClosingTransfer, 3..=5) => {
                if mov.class != EntryClass::CLOSING {
                    return Err(input(
                        "ClosingTransfer equity movement must have EntryClass::CLOSING",
                    ));
                }
            }
            (
                EquityActivityKind::Issuance
                | EquityActivityKind::Distribution
                | EquityActivityKind::OtherEquity,
                3,
            ) => {}
            _ => {
                return Err(input(
                    "direct equity movement must target an Equity (type 3) account",
                ));
            }
        }
        let slot = activity_sums
            .entry((mov.unit_id, mov.kind))
            .or_insert(Sum::ZERO);
        let failed = || overflow("equity_movement", &source.label, mov.unit_id);
        // Credit-normal: credits increase equity, debits decrease equity.
        slot.add(mov.credits, false).ok_or_else(failed)?;
        slot.add(mov.debits, true).ok_or_else(failed)?;
    }

    let mut out_units = Vec::with_capacity(units.len());
    for &unit_id in &units {
        let failed = || overflow("equity_roll_forward", &source.label, unit_id);
        let (opening_contributed_equity, opening_unclosed_earnings) = opening_stock[&unit_id];
        let opening_total_equity = opening_contributed_equity
            .checked_add(opening_unclosed_earnings)
            .ok_or_else(failed)?;
        let (closing_contributed_equity, closing_unclosed_earnings) = closing_stock[&unit_id];
        let closing_total_equity = closing_contributed_equity
            .checked_add(closing_unclosed_earnings)
            .ok_or_else(failed)?;

        let get_kind = |k: EquityActivityKind| -> Result<i128, StatementError> {
            match activity_sums.get(&(unit_id, k)) {
                Some(s) => s.value().ok_or_else(failed),
                None => Ok(0),
            }
        };
        let issuances = get_kind(EquityActivityKind::Issuance)?;
        let distributions = get_kind(EquityActivityKind::Distribution)?;
        let other_equity_movements = get_kind(EquityActivityKind::OtherEquity)?;
        let closing_transfers_net = get_kind(EquityActivityKind::ClosingTransfer)?;
        if closing_transfers_net != 0 {
            return Err(StatementError::Identity {
                line: "equity_closing_transfers_net".into(),
                column: source.label.clone(),
                unit_id,
                residual: closing_transfers_net,
            });
        }

        let net_income = source.net_income_by_unit.get(&unit_id).copied().unwrap_or(0);
        let mut net_change_sum = Sum::ZERO;
        for part in [
            net_income,
            issuances,
            distributions,
            other_equity_movements,
        ] {
            net_change_sum.add(part, false).ok_or_else(failed)?;
        }
        let net_equity_change = net_change_sum.value().ok_or_else(failed)?;

        let mut tie_out = Sum::ZERO;
        tie_out.add(opening_total_equity, false).ok_or_else(failed)?;
        tie_out.add(net_equity_change, false).ok_or_else(failed)?;
        tie_out.add(closing_total_equity, true).ok_or_else(failed)?;
        let equity_tie_out_residual = tie_out.value().ok_or_else(failed)?;
        if equity_tie_out_residual != 0 {
            return Err(StatementError::Identity {
                line: "equity_roll_forward_tie_out".into(),
                column: source.label.clone(),
                unit_id,
                residual: equity_tie_out_residual,
            });
        }

        out_units.push(EquityRollForwardUnit {
            unit_id,
            opening_contributed_equity,
            opening_unclosed_earnings,
            opening_total_equity,
            net_income,
            issuances,
            distributions,
            other_equity_movements,
            closing_transfers_net,
            net_equity_change,
            closing_contributed_equity,
            closing_unclosed_earnings,
            closing_total_equity,
            equity_tie_out_residual,
        });
    }

    Ok(EquityRollForward {
        book_id: source.book_id,
        branch_id: source.branch_id,
        known_at: source.known_at,
        label: source.label.clone(),
        effective_from: source.effective_from,
        effective_through: source.effective_through,
        units: out_units,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_reference::{
        Account as RefAccount, Int, Intent as RefIntent, Leg as RefLeg, Oracle, Side, Verdict,
        reports,
    };
    use fa_time::{FiscalCalendar, PeriodTransition};

    fn test_accounts() -> Vec<Account> {
        vec![
            Account {
                id: 1,
                code: "1010".into(),
                name: "Operating Cash".into(),
                account_type: 1,
                is_leaf: true,
            },
            Account {
                id: 2,
                code: "1020".into(),
                name: "Payroll Cash".into(),
                account_type: 1,
                is_leaf: true,
            },
            Account {
                id: 3,
                code: "1100".into(),
                name: "Accounts Receivable".into(),
                account_type: 1,
                is_leaf: true,
            },
            Account {
                id: 4,
                code: "1500".into(),
                name: "Equipment".into(),
                account_type: 1,
                is_leaf: true,
            },
            Account {
                id: 5,
                code: "1590".into(),
                name: "Accumulated Depreciation".into(),
                account_type: 1,
                is_leaf: true,
            },
            Account {
                id: 6,
                code: "3000".into(),
                name: "Common Stock".into(),
                account_type: 3,
                is_leaf: true,
            },
            Account {
                id: 7,
                code: "3100".into(),
                name: "Retained Earnings".into(),
                account_type: 3,
                is_leaf: true,
            },
            Account {
                id: 8,
                code: "4000".into(),
                name: "Revenue".into(),
                account_type: 4,
                is_leaf: true,
            },
            Account {
                id: 9,
                code: "5000".into(),
                name: "Depreciation Expense".into(),
                account_type: 5,
                is_leaf: true,
            },
        ]
    }

    #[test]
    fn direct_and_indirect_cash_flow_match_oracle_and_net_mixed_cash_entries() {
        // Mixed cash entry (fa-gb47): Dr 1010 100, Cr 1010 80, Cr Revenue 20 -> net inflow 20, outflow 0
        // Plus credit sale: Dr AR 50, Cr Revenue 50 (working capital -50)
        // Plus depreciation: Dr Depr Expense 15, Cr Accum Depr 15 (non-cash +15)
        // Plus equipment purchase: Dr Equipment 40, Cr 1010 40 (investing outflow 40)
        // Plus internal transfer: Dr 1020 30, Cr 1010 30 (internal transfer = 0)
        // Net income = 20 + 50 - 15 = 55; Indirect operating = 55 + 15 - 50 = 20 == Direct operating (20)!
        let cal = FiscalCalendar::monthly("cal", 1, 0).unwrap();
        let p1 = cal.periods_for_year(1970).unwrap()[0].clone();
        let mut oracle = Oracle::new(cal);
        for acc in test_accounts() {
            oracle.add_account(RefAccount {
                code: acc.code,
                is_leaf: acc.is_leaf,
                unit: None,
            });
        }
        oracle.create_periods(1970);
        oracle.transition(&p1.code, PeriodTransition::Open).unwrap();

        let mut seq = 0u64;
        let mut push_entry = |oracle: &mut Oracle, day: i32, legs: Vec<(&str, Side, i128)>| {
            seq += 1;
            let verdict = oracle.post(&RefIntent {
                class: "Original".into(),
                date: DateDay(day),
                discriminator: None,
                legs: legs
                    .into_iter()
                    .map(|(account, side, mantissa)| RefLeg {
                        side,
                        account: account.into(),
                        unit: 1,
                        entity: None,
                        mantissa,
                    })
                    .collect(),
                key: format!("cf-key-{seq}").into_bytes(),
                ops: vec!["post".into()],
                approvals: 0,
                reverses: None,
                supersession_reason: 1,
                resolves: None,
                settles: Vec::new(),
            });
            assert!(matches!(verdict, Verdict::Posted { .. }), "got {verdict:?}");
        };
        // Entry 0 (opening, day 5): Dr 1010 500, Cr Common Stock 500
        push_entry(
            &mut oracle,
            5,
            vec![("1010", Side::Debit, 500), ("3000", Side::Credit, 500)],
        );
        // Entry 1 (day 12): Mixed cash receipt: Dr 1010 100, Cr 1010 80, Cr 4000 20
        push_entry(
            &mut oracle,
            12,
            vec![
                ("1010", Side::Debit, 100),
                ("1010", Side::Credit, 80),
                ("4000", Side::Credit, 20),
            ],
        );
        // Entry 2 (day 14): Credit sale: Dr 1100 50, Cr 4000 50
        push_entry(
            &mut oracle,
            14,
            vec![("1100", Side::Debit, 50), ("4000", Side::Credit, 50)],
        );
        // Entry 3 (day 15): Depreciation: Dr 5000 15, Cr 1590 15
        push_entry(
            &mut oracle,
            15,
            vec![("5000", Side::Debit, 15), ("1590", Side::Credit, 15)],
        );
        // Entry 4 (day 16): Equipment purchase: Dr 1500 40, Cr 1010 40
        push_entry(
            &mut oracle,
            16,
            vec![("1500", Side::Debit, 40), ("1010", Side::Credit, 40)],
        );
        // Entry 5 (day 18): Internal transfer: Dr 1020 30, Cr 1010 30
        push_entry(
            &mut oracle,
            18,
            vec![("1020", Side::Debit, 30), ("1010", Side::Credit, 30)],
        );

        let known = oracle.known_after(oracle.entries().len());
        let mut ref_cls = BTreeMap::new();
        ref_cls.insert((1, 0), reports::CashActivity::Operating);
        ref_cls.insert((1, 1), reports::CashActivity::Operating);
        ref_cls.insert((4, 1), reports::CashActivity::Investing);
        ref_cls.insert((5, 0), reports::CashActivity::InternalTransfer);
        ref_cls.insert((5, 1), reports::CashActivity::InternalTransfer);

        let ref_direct = reports::direct_cash_flow(
            &oracle,
            known,
            DateDay(10),
            DateDay(20),
            &["1010".into(), "1020".into()],
            &[1],
            &ref_cls,
        )
        .unwrap();
        let mut ref_ni = BTreeMap::new();
        ref_ni.insert(1, Int::from_i128(55));
        let ref_indirect = reports::indirect_cash_flow(
            &oracle,
            known,
            DateDay(10),
            DateDay(20),
            &["1010".into(), "1020".into()],
            &ref_ni,
            &ref_direct,
            &[
                reports::OracleIndirectAdjustment {
                    entry_index: 2,
                    leg_index: 0,
                    category: reports::IndirectCategory::WorkingCapital,
                    debit_minus_credit: false, // increase in AR reduces operating cash (-50)
                },
                reports::OracleIndirectAdjustment {
                    entry_index: 3,
                    leg_index: 1,
                    category: reports::IndirectCategory::NonCash,
                    debit_minus_credit: false, // credit to accum depr adds back +15
                },
            ],
        )
        .unwrap();

        let mut net_income_by_unit = BTreeMap::new();
        net_income_by_unit.insert(1, 55);
        let cf_input = CashFlowInput {
            book_id: Id128([0x22; 16]),
            branch_id: Id128::TRUNK,
            known_at: 6,
            label: "FY2026-P01".into(),
            effective_from: DateDay(10),
            effective_through: DateDay(20),
            accounts: test_accounts(),
            cash_account_ids: vec![1, 2],
            units: vec![1],
            opening_cash_balances: vec![AccountBalance {
                account_id: 1,
                unit_id: 1,
                debits: 500,
                credits: 0,
            }],
            closing_cash_balances: vec![
                AccountBalance {
                    account_id: 1,
                    unit_id: 1,
                    debits: 450,
                    credits: 0,
                },
                AccountBalance {
                    account_id: 2,
                    unit_id: 1,
                    debits: 30,
                    credits: 0,
                },
            ],
            net_income_by_unit,
            cash_movements: vec![
                CashLegMovement {
                    entry_digest: [1; 32],
                    leg_index: 0,
                    recorded_seq: 2,
                    effective_day: DateDay(12),
                    account_id: 1,
                    unit_id: 1,
                    classification: CashFlowClassification::Operating,
                    debits: 100,
                    credits: 0,
                },
                CashLegMovement {
                    entry_digest: [1; 32],
                    leg_index: 1,
                    recorded_seq: 2,
                    effective_day: DateDay(12),
                    account_id: 1,
                    unit_id: 1,
                    classification: CashFlowClassification::Operating,
                    debits: 0,
                    credits: 80,
                },
                CashLegMovement {
                    entry_digest: [4; 32],
                    leg_index: 1,
                    recorded_seq: 5,
                    effective_day: DateDay(16),
                    account_id: 1,
                    unit_id: 1,
                    classification: CashFlowClassification::Investing,
                    debits: 0,
                    credits: 40,
                },
                CashLegMovement {
                    entry_digest: [5; 32],
                    leg_index: 0,
                    recorded_seq: 6,
                    effective_day: DateDay(18),
                    account_id: 2,
                    unit_id: 1,
                    classification: CashFlowClassification::InternalTransfer,
                    debits: 30,
                    credits: 0,
                },
                CashLegMovement {
                    entry_digest: [5; 32],
                    leg_index: 1,
                    recorded_seq: 6,
                    effective_day: DateDay(18),
                    account_id: 1,
                    unit_id: 1,
                    classification: CashFlowClassification::InternalTransfer,
                    debits: 0,
                    credits: 30,
                },
            ],
            indirect_adjustments: vec![
                IndirectAdjustmentLeg {
                    entry_digest: [2; 32],
                    leg_index: 0,
                    recorded_seq: 3,
                    effective_day: DateDay(14),
                    account_id: 3,
                    unit_id: 1,
                    category: IndirectAdjustmentCategory::WorkingCapital,
                    debit_minus_credit: false,
                    debits: 50,
                    credits: 0,
                },
                IndirectAdjustmentLeg {
                    entry_digest: [3; 32],
                    leg_index: 1,
                    recorded_seq: 4,
                    effective_day: DateDay(15),
                    account_id: 5,
                    unit_id: 1,
                    category: IndirectAdjustmentCategory::NonCash,
                    debit_minus_credit: false,
                    debits: 0,
                    credits: 15,
                },
            ],
        };

        let cf = evaluate_cash_flow(&cf_input).unwrap();
        let u = &cf.units[0];
        let ref_d = &ref_direct[&1];
        let ref_i = &ref_indirect[&1];
        assert_eq!(u.operating.inflows, ref_d.operating.inflows.to_i128().unwrap());
        assert_eq!(u.operating.outflows, ref_d.operating.outflows.to_i128().unwrap());
        assert_eq!(u.operating.net, 20);
        assert_eq!(u.investing.net, -40);
        assert_eq!(u.indirect_operating_cash, ref_i.operating.to_i128().unwrap());
        assert_eq!(u.direct_vs_indirect_residual, 0);
        assert_eq!(u.opening_cash, 500);
        assert_eq!(u.net_cash_change, -20);
        assert_eq!(u.closing_cash, 480);
        assert_eq!(u.cash_tie_out_residual, 0);

        let bytes = cf.canonical_bytes().unwrap();
        assert_eq!(CashFlowStatement::decode(&bytes).unwrap(), cf);
    }

    #[test]
    fn equity_roll_forward_reconciles_opening_net_income_issuances_dividends_and_closing_transfers() {
        let mut net_income_by_unit = BTreeMap::new();
        net_income_by_unit.insert(1, 55); // Revenue 70 - Expense 15

        // Opening equity: Common Stock = 500, Unclosed earnings = 0 -> Total = 500
        // Activity:
        //   - Net income = +55
        //   - Share issuance = +200 (Cr 3000 200)
        //   - Dividend distribution = -30 (Dr 3100 30)
        //   - Closing entry: Dr 4000 70, Cr 5000 15, Cr 3100 55 (net effect on total equity = 0!)
        // Closing equity: Common Stock = 700, Retained Earnings = 25, Unclosed = 0 -> Total = 725
        let input = EquityRollForwardInput {
            book_id: Id128([0x33; 16]),
            branch_id: Id128::TRUNK,
            known_at: 10,
            label: "FY2026-P01".into(),
            effective_from: DateDay(10),
            effective_through: DateDay(20),
            accounts: test_accounts(),
            units: vec![1],
            opening_balances: vec![AccountBalance {
                account_id: 6,
                unit_id: 1,
                debits: 0,
                credits: 500,
            }],
            closing_balances: vec![
                AccountBalance {
                    account_id: 6,
                    unit_id: 1,
                    debits: 0,
                    credits: 700,
                },
                AccountBalance {
                    account_id: 7,
                    unit_id: 1,
                    debits: 30,
                    credits: 55,
                },
                AccountBalance {
                    account_id: 8,
                    unit_id: 1,
                    debits: 70,
                    credits: 70,
                },
                AccountBalance {
                    account_id: 9,
                    unit_id: 1,
                    debits: 15,
                    credits: 15,
                },
            ],
            net_income_by_unit,
            equity_movements: vec![
                EquityMovement {
                    entry_digest: [7; 32],
                    leg_index: 0,
                    recorded_seq: 7,
                    effective_day: DateDay(15),
                    class: EntryClass::ORIGINAL,
                    kind: EquityActivityKind::Issuance,
                    account_id: 6,
                    unit_id: 1,
                    debits: 0,
                    credits: 200,
                },
                EquityMovement {
                    entry_digest: [8; 32],
                    leg_index: 0,
                    recorded_seq: 8,
                    effective_day: DateDay(17),
                    class: EntryClass::ORIGINAL,
                    kind: EquityActivityKind::Distribution,
                    account_id: 7,
                    unit_id: 1,
                    debits: 30,
                    credits: 0,
                },
                EquityMovement {
                    entry_digest: [9; 32],
                    leg_index: 0,
                    recorded_seq: 9,
                    effective_day: DateDay(20),
                    class: EntryClass::CLOSING,
                    kind: EquityActivityKind::ClosingTransfer,
                    account_id: 8,
                    unit_id: 1,
                    debits: 70,
                    credits: 0,
                },
                EquityMovement {
                    entry_digest: [9; 32],
                    leg_index: 1,
                    recorded_seq: 9,
                    effective_day: DateDay(20),
                    class: EntryClass::CLOSING,
                    kind: EquityActivityKind::ClosingTransfer,
                    account_id: 9,
                    unit_id: 1,
                    debits: 0,
                    credits: 15,
                },
                EquityMovement {
                    entry_digest: [9; 32],
                    leg_index: 2,
                    recorded_seq: 9,
                    effective_day: DateDay(20),
                    class: EntryClass::CLOSING,
                    kind: EquityActivityKind::ClosingTransfer,
                    account_id: 7,
                    unit_id: 1,
                    debits: 0,
                    credits: 55,
                },
            ],
        };

        let eq = evaluate_equity_roll_forward(&input).unwrap();
        let u = &eq.units[0];
        assert_eq!(u.opening_total_equity, 500);
        assert_eq!(u.net_income, 55);
        assert_eq!(u.issuances, 200);
        assert_eq!(u.distributions, -30);
        assert_eq!(u.closing_transfers_net, 0);
        assert_eq!(u.net_equity_change, 225);
        assert_eq!(u.closing_total_equity, 725);
        assert_eq!(u.equity_tie_out_residual, 0);

        let bytes = eq.canonical_bytes().unwrap();
        assert_eq!(EquityRollForward::decode(&bytes).unwrap(), eq);
    }
}
