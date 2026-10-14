//! Exact activity splits of original cash legs (plan §12.1, fa-i9yn).
//!
//! A loan payment may contain both principal and interest on ONE cash leg.
//! Classifying that entire leg as financing or operating loses information.
//! Here the caller supplies positive native-unit portions and a reason; their
//! sum must equal the original leg exactly. No journal legs are synthesized,
//! netted, rounded, or rewritten. Every selected leg needs one complete split.
//!
//! Internal-transfer portions must cancel within one original entry and unit,
//! across distinct selected cash accounts. All other portions retain their
//! source leg's direction, and independently folded opening/closing cash must
//! reconcile in every native unit. Cash-equivalent scope and classification
//! remain professional inputs, NOT economic truth inferred by this module.

mod codec;

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_journal::{Refusal, exit};
use fa_model::AccountType;
use fa_money::wide::U256;
use fa_policy::Capability;
use fgdb_types::{QueryCx, VId, context::PurposeContexts};

use crate::general_ledger::{
    CashFlowActivity, CashFlowSection, CashFlowUnit, GeneralLedger,
    MAX_GENERAL_LEDGER_LINES,
};
use crate::{AsyncBook, BookError, Outcome, RollForwardRequest};

pub const CASH_FLOW_SPLIT_FORMAT: &str = "fa:cash-flow-split:v1";
pub const CASH_FLOW_SPLIT_DEFINITION_FORMAT: &str = "fa:cash-flow-split-definition:v1";
pub const MAX_CASH_FLOW_SPLIT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_CASH_FLOW_SPLIT_DEFINITION_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_CASH_FLOW_SPLIT_ACCOUNTS: usize = 4096;
pub const MAX_CASH_FLOW_SPLIT_PARTS_PER_LEG: usize = 5;

/// A positive native mantissa, in the SAME unit and direction as its source
/// cash leg. It is a classification portion, never another posting amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CashFlowPortion {
    pub activity: CashFlowActivity,
    pub amount: i128,
}

/// Exactly one record for an original cash entry/leg. Each activity may appear
/// at most once. A reason records the caller's judgment, not an approval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowLegSplit {
    pub entry_digest: [u8; 32],
    pub leg_index: u32,
    pub reason: String,
    pub portions: Vec<CashFlowPortion>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowSplitDefinition {
    pub name: String,
    pub cash_accounts: Vec<u128>,
    pub splits: Vec<CashFlowLegSplit>,
}

/// Only native reads or verified native replay can supply the source. The
/// original ledger and canonical input decisions remain available for drilldown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitCashFlow {
    source: GeneralLedger,
    definition: CashFlowSplitDefinition,
    units: Vec<CashFlowUnit>,
}

impl SplitCashFlow {
    #[must_use]
    pub fn source(&self) -> &GeneralLedger { &self.source }
    #[must_use]
    pub fn definition(&self) -> &CashFlowSplitDefinition { &self.definition }
    #[must_use]
    pub fn units(&self) -> &[CashFlowUnit] { &self.units }

    /// Deterministic bounded output, not a self-authenticating certificate.
    /// The source keeps every original leg once; portions never impersonate legs.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let source = self.source.canonical_bytes()?;
        let definition = self.definition.canonical_bytes()?;
        let mut w = codec::Wire::new(MAX_CASH_FLOW_SPLIT_BYTES);
        w.text(CASH_FLOW_SPLIT_FORMAT)?;
        w.bytes(&source)?;
        w.bytes(&definition)?;
        w.count(self.units.len())?;
        for unit in &self.units {
            w.fixed(&unit.unit_id.to_le_bytes())?;
            w.fixed(&unit.opening.to_le_bytes())?;
            for section in [unit.operating, unit.investing, unit.financing, unit.exchange_effects] {
                for amount in [section.inflows, section.outflows, section.net] {
                    w.fixed(&amount.to_le_bytes())?;
                }
            }
            w.fixed(&unit.net_change.to_le_bytes())?;
            w.fixed(&unit.closing.to_le_bytes())?;
        }
        Ok(w.finish())
    }
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::STRUCTURE, exit::USAGE, message,
        "plan §12.1 (cash portions partition original legs and reconcile to native stock)",
        "select the exact cash scope; split every original leg once into positive same-unit portions totaling that leg; transfers must cancel within one entry/unit; never insert a balancing plug",
    )
}

#[derive(Debug)]
enum Error { Refusal(Refusal), Book(BookError) }
impl From<Refusal> for Error { fn from(e: Refusal) -> Self { Self::Refusal(e) } }
impl From<BookError> for Error { fn from(e: BookError) -> Self { Self::Book(e) } }
fn outcome<T>(result: Result<T, Error>) -> Outcome<T> {
    match result {
        Ok(value) => Ok(Ok(value)),
        Err(Error::Refusal(refusal)) => Ok(Err(refusal)),
        Err(Error::Book(error)) => Err(error),
    }
}

/// Bounded magnitudes are accumulated separately. Even 250,000 five-part
/// splits fit well below 256 bits; narrowing occurs only for public amounts.
#[derive(Clone, Copy)]
struct Wide { positive: U256, negative: U256 }
impl Wide {
    const ZERO: Self = Self { positive: U256::ZERO, negative: U256::ZERO };
    fn add(&mut self, value: i128, subtract: bool) -> Result<(), Refusal> {
        let part = if (value < 0) != subtract { &mut self.negative } else { &mut self.positive };
        *part = part.checked_add(U256::from_u128(value.unsigned_abs()))
            .ok_or_else(|| invalid("cash split exceeds its wide arithmetic bound"))?;
        Ok(())
    }
    fn combine(&mut self, other: Self, subtract: bool) -> Result<(), Refusal> {
        let (p, n) = if subtract { (other.negative, other.positive) } else { (other.positive, other.negative) };
        self.positive = self.positive.checked_add(p).ok_or_else(|| invalid("cash split wide overflow"))?;
        self.negative = self.negative.checked_add(n).ok_or_else(|| invalid("cash split wide overflow"))?;
        Ok(())
    }
    fn is_zero(self) -> bool { self.positive == self.negative }
    fn value(self) -> Result<i128, Refusal> {
        let n = if self.positive >= self.negative {
            self.positive.checked_sub(self.negative).and_then(U256::to_u128)
                .and_then(|n| i128::try_from(n).ok())
        } else {
            self.negative.checked_sub(self.positive).and_then(U256::to_u128).and_then(|n| {
                if n == i128::MIN.unsigned_abs() { Some(i128::MIN) }
                else { i128::try_from(n).ok().and_then(i128::checked_neg) }
            })
        };
        n.ok_or_else(|| invalid("cash split amount exceeds the exact i128 output range"))
    }
    fn section(self) -> Result<CashFlowSection, Refusal> {
        let magnitude = |n: U256| n.to_u128().and_then(|n| i128::try_from(n).ok())
            .ok_or_else(|| invalid("cash split gross turnover exceeds i128"));
        Ok(CashFlowSection { inflows: magnitude(self.positive)?, outflows: magnitude(self.negative)?, net: self.value()? })
    }
}

struct Totals { opening: Wide, closing: Wide, sections: [Wide; 4] }
impl Totals {
    fn new() -> Self { Self { opening: Wide::ZERO, closing: Wide::ZERO, sections: [Wide::ZERO; 4] } }
}

fn build(
    source: GeneralLedger, definition: &CashFlowSplitDefinition,
    mut checkpoint: impl FnMut() -> Result<(), BookError>,
) -> Result<SplitCashFlow, Error> {
    checkpoint()?;
    let definition = codec::normalize(definition)?;
    checkpoint()?;
    if definition.splits.len() != source.lines().len()
        || definition.cash_accounts.len() != source.accounts().len()
    { return Err(invalid("cash split definition must cover exactly the selected accounts and every cash leg").into()); }
    let cash: BTreeSet<_> = definition.cash_accounts.iter().copied().collect();
    for account in source.accounts() {
        checkpoint()?;
        if !cash.contains(&account.id) || !account.is_leaf
            || ![AccountType::ASSET.0, AccountType::LIABILITY.0].contains(&account.account_type)
        { return Err(invalid("cash splits require exactly the selected asset or overdraft leaves").into()); }
    }
    let mut splits: BTreeMap<_, _> = definition.splits.iter()
        .map(|s| ((s.entry_digest, s.leg_index), s)).collect();
    let mut totals: BTreeMap<_, _> = source.units().iter().map(|u| (*u, Totals::new())).collect();
    for (i, cell) in source.cells().iter().enumerate() {
        if i % 256 == 0 { checkpoint()?; }
        let total = totals.get_mut(&cell.unit_id).ok_or_else(|| invalid("cash stock has an undeclared unit"))?;
        total.opening.add(cell.opening, false)?;
        total.closing.add(cell.closing, false)?;
    }
    let mut transfers: BTreeMap<([u8; 32], u32), (Wide, BTreeSet<u128>)> = BTreeMap::new();
    for (i, line) in source.lines().iter().enumerate() {
        if i % 256 == 0 { checkpoint()?; }
        let cell = source.cells().get(line.cell_index as usize).ok_or_else(|| invalid("cash leg has no source cell"))?;
        if line.debits < 0 || line.credits < 0 || (line.debits > 0) == (line.credits > 0) {
            return Err(invalid("cash split source must be one positive debit or credit").into());
        }
        let split = splits.remove(&(line.entry_digest, line.leg_index))
            .ok_or_else(|| invalid("cash split is missing an original leg or repeats a citation"))?;
        let mut partition = Wide::ZERO;
        for part in &split.portions { partition.add(part.amount, false)?; }
        partition.add(line.debits.max(line.credits), true)?;
        if !partition.is_zero() {
            return Err(invalid(format!("cash split for leg {} does not total its original native amount", line.leg_index)).into());
        }
        for part in &split.portions {
            let credit = line.credits > 0;
            if part.activity == CashFlowActivity::InternalTransfer {
                let (amount, accounts) = transfers.entry((line.entry_digest, cell.unit_id))
                    .or_insert_with(|| (Wide::ZERO, BTreeSet::new()));
                amount.add(part.amount, credit)?;
                accounts.insert(cell.account_id);
            } else {
                let total = totals.get_mut(&cell.unit_id).ok_or_else(|| invalid("cash leg has an undeclared unit"))?;
                total.sections[part.activity as usize].add(part.amount, credit)?;
            }
        }
    }
    if !splits.is_empty() { return Err(invalid("cash splits cite legs outside the native selection").into()); }
    for (amount, accounts) in transfers.values() {
        checkpoint()?;
        if !amount.is_zero() || accounts.len() < 2 {
            return Err(invalid("transfer portions must cancel within one entry and native unit across distinct cash accounts").into());
        }
    }
    drop(splits);
    let mut units = Vec::with_capacity(totals.len());
    for (unit_id, total) in totals {
        checkpoint()?;
        let mut change = Wide::ZERO;
        for section in total.sections { change.combine(section, false)?; }
        let mut residual = total.opening;
        residual.combine(change, false)?;
        residual.combine(total.closing, true)?;
        if !residual.is_zero() {
            return Err(invalid("split cash movements do not reconcile to independently folded opening and closing stocks").into());
        }
        units.push(CashFlowUnit {
            unit_id, opening: total.opening.value()?,
            operating: total.sections[0].section()?, investing: total.sections[1].section()?,
            financing: total.sections[2].section()?, exchange_effects: total.sections[3].section()?,
            net_change: change.value()?, closing: total.closing.value()?,
        });
    }
    checkpoint()?;
    Ok(SplitCashFlow { source, definition, units })
}

impl GeneralLedger {
    /// Consume an already admitted immutable snapshot, without another read or
    /// invented journal leg. The query context meters/cancels the computation;
    /// it grants no authority over additional book data.
    pub fn split_cash_flow(self, query: &QueryCx, definition: &CashFlowSplitDefinition) -> Outcome<SplitCashFlow> {
        let result = build(self, definition, || query.checkpoint().map_err(BookError::Context));
        query.checkpoint().map_err(BookError::Context)?;
        outcome(result)
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Current whole-book Read admission, historical chart and migration rules
    /// come from the native ledger reader. HEAD resolves once there. Read-only.
    pub fn split_cash_flow(
        &self, cx: &PurposeContexts, principal: VId, capability: &Capability,
        request: &RollForwardRequest, definition: &CashFlowSplitDefinition,
    ) -> Outcome<SplitCashFlow> {
        let ledger = match self.general_ledger(cx, principal, capability, request)? {
            Ok(value) => value, Err(refusal) => return Ok(Err(refusal)),
        };
        ledger.split_cash_flow(&cx.query(), definition)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wide_partition_check_cannot_wrap_or_hide_excess_allocation() {
        let mut total = Wide::ZERO;
        total.add(i128::MAX, false).unwrap();
        total.add(1, false).unwrap();
        total.add(i128::MAX, true).unwrap();
        assert!(!total.is_zero());
        assert_eq!(total.value().unwrap(), 1);
    }
    #[test]
    fn cancellation_preserves_minimum_signed_value_and_gross_overflow_refuses() {
        let mut total = Wide::ZERO;
        total.add(i128::MIN, false).unwrap();
        assert_eq!(total.value().unwrap(), i128::MIN);
        let mut gross = Wide::ZERO;
        gross.add(i128::MAX, false).unwrap();
        gross.add(1, false).unwrap();
        gross.add(i128::MAX, true).unwrap();
        assert_eq!(gross.value().unwrap(), 1);
        assert!(gross.section().is_err());
    }
}
