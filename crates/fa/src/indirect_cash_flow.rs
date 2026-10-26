//! Indirect operating-cash reconciliation over native historical reports.
//!
//! Net income is the registered income statement (including its Closing-lineage
//! exclusion), not a caller amount. Each adjustment selects one entire original
//! NON-CASH journal leg and explicitly states its sign, category and reason.
//! There is no free-form monetary adjustment, FX conversion or balancing plug.
//! The result must equal the separately classified direct operating cash in
//! every selected native unit, and opening + all cash movements = closing.
//!
//! Choosing adjustments, cash equivalents and accounting classifications remains
//! professional judgment. A tie-out does not prove that judgment is correct or
//! that the selected adjustments constitute an economically complete analysis.
//! The retained sources include whole-book income and non-cash ledger detail;
//! unlike a selected cash workpaper, this report must be kept confidential.

mod certificate;
mod native;

pub use certificate::{
    CertifiedIndirectCashFlow, INDIRECT_CASH_FLOW_CERTIFICATE_FORMAT,
    INDIRECT_CASH_FLOW_CERTIFICATE_FORMAT_V2, IndirectCashFlowCertificate,
    MAX_INDIRECT_CASH_FLOW_CERTIFICATE_BYTES,
};

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::{Refusal, exit};
use fa_model::{AccountType, EntryClass};
use fa_money::wide::U256;
use fa_statements::Statement;
use fgdb_types::QueryCx;

use crate::general_ledger::{GeneralLedger, MAX_GENERAL_LEDGER_LINES};
use crate::{
    BookError, CashFlowBasis, CashFlowBasisDefinition, CashFlowBasisKind, Outcome,
    RollForwardRequest,
};

pub const INDIRECT_CASH_FLOW_FORMAT: &str = "fa:indirect-cash-flow:v1";
pub const INDIRECT_CASH_FLOW_FORMAT_V2: &str = "fa:indirect-cash-flow:v2";
pub const MAX_INDIRECT_CASH_FLOW_BYTES: usize = 64 * 1024 * 1024;
const MAX_PERIODS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AdjustmentCategory {
    NonCash = 0,
    WorkingCapital = 1,
    NonOperating = 2,
}

/// Sign of the original nonnegative debit/credit magnitudes. For example,
/// depreciation expense uses DebitMinusCredit; an increase in receivables uses
/// CreditMinusDebit; a gain credited to income uses DebitMinusCredit to remove it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AdjustmentSign {
    DebitMinusCredit = 0,
    CreditMinusDebit = 1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndirectCashFlowAdjustment {
    pub entry_digest: [u8; 32],
    pub leg_index: u32,
    pub category: AdjustmentCategory,
    pub sign: AdjustmentSign,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndirectCashFlowDefinition {
    pub name: String,
    /// Explicit selection, not an instruction to infer omitted adjustments.
    /// A journal leg may be selected only once, even in different categories.
    pub adjustments: Vec<IndirectCashFlowAdjustment>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndirectCashFlowRequest {
    pub cash: RollForwardRequest,
    /// Keep the full explicit, policy or split classification for reconciliation
    /// and independently expected replay, including its original provenance.
    pub cash_definition: CashFlowBasisDefinition,
    /// Exactly all historical periods intersecting the cash interval. The
    /// interval must cover whole periods without gaps, including special periods.
    pub income_periods: Vec<String>,
    pub definition: IndirectCashFlowDefinition,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndirectCashFlowContribution {
    pub entry_digest: [u8; 32],
    pub leg_index: u32,
    pub account_id: u128,
    pub unit_id: u32,
    pub amount: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndirectCashFlowUnit {
    pub unit_id: u32,
    pub net_income: i128,
    pub non_cash: i128,
    pub working_capital: i128,
    pub non_operating: i128,
    pub operating: i128,
    pub direct_operating: i128,
    pub operating_residual: i128,
    pub opening: i128,
    pub investing: i128,
    pub financing: i128,
    pub exchange_effects: i128,
    pub net_change: i128,
    pub closing: i128,
}

/// Private construction: financial inputs originate in native reads or replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndirectCashFlow {
    cash: CashFlowBasis,
    income: Statement,
    non_cash_source: Option<GeneralLedger>,
    definition: IndirectCashFlowDefinition,
    contributions: Vec<IndirectCashFlowContribution>,
    units: Vec<IndirectCashFlowUnit>,
}

impl IndirectCashFlow {
    #[must_use]
    pub fn cash(&self) -> &CashFlowBasis {
        &self.cash
    }
    #[must_use]
    pub fn income(&self) -> &Statement {
        &self.income
    }
    #[must_use]
    pub fn non_cash_source(&self) -> Option<&GeneralLedger> {
        self.non_cash_source.as_ref()
    }
    #[must_use]
    pub fn definition(&self) -> &IndirectCashFlowDefinition {
        &self.definition
    }
    #[must_use]
    pub fn contributions(&self) -> &[IndirectCashFlowContribution] {
        &self.contributions
    }
    #[must_use]
    pub fn units(&self) -> &[IndirectCashFlowUnit] {
        &self.units
    }

    /// Existing explicit classifications retain their exact v1 encoding. Policy
    /// and split bases use v2, which binds the family and its full native output.
    #[must_use]
    pub fn format(&self) -> &'static str {
        match self.cash.kind() {
            CashFlowBasisKind::Explicit => INDIRECT_CASH_FLOW_FORMAT,
            CashFlowBasisKind::Policy | CashFlowBasisKind::Split => INDIRECT_CASH_FLOW_FORMAT_V2,
        }
    }

    /// Exact bounded output, including all source transcripts and adjustment
    /// decisions. These are report bytes, not a standalone authenticity proof.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut out = Bytes::default();
        out.string(self.format())?;
        if self.cash.kind() != CashFlowBasisKind::Explicit {
            out.add(&[self.cash.kind() as u8])?;
        }
        out.blob(&self.cash.canonical_bytes()?)?;
        out.blob(
            &self
                .income
                .canonical_bytes()
                .map_err(|e| invalid(e.to_string()))?,
        )?;
        match &self.non_cash_source {
            Some(source) => {
                out.add(&[1])?;
                out.blob(&source.canonical_bytes()?)?;
            }
            None => out.add(&[0])?,
        }
        write_definition(&mut out, &self.definition)?;
        out.count(self.contributions.len())?;
        for c in &self.contributions {
            out.add(&c.entry_digest)?;
            out.add(&c.leg_index.to_le_bytes())?;
            out.add(&c.account_id.to_le_bytes())?;
            out.add(&c.unit_id.to_le_bytes())?;
            out.add(&c.amount.to_le_bytes())?;
        }
        out.count(self.units.len())?;
        for u in &self.units {
            out.add(&u.unit_id.to_le_bytes())?;
            for amount in [
                u.net_income,
                u.non_cash,
                u.working_capital,
                u.non_operating,
                u.operating,
                u.direct_operating,
                u.operating_residual,
                u.opening,
                u.investing,
                u.financing,
                u.exchange_effects,
                u.net_change,
                u.closing,
            ] {
                out.add(&amount.to_le_bytes())?;
            }
        }
        Ok(out.0)
    }
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §12.1 / fa-i9yn (native earnings + sourced adjustments = operating cash)",
        "select whole historical periods and explicit non-cash journal legs with their intended signs; reconcile each native unit to direct cash without inserting a balancing amount",
    )
}

fn normalize(
    definition: &IndirectCashFlowDefinition,
) -> Result<IndirectCashFlowDefinition, Refusal> {
    if definition.name.trim().is_empty()
        || definition.name.len() > 256
        || definition.adjustments.len() > MAX_GENERAL_LEDGER_LINES
        || definition
            .adjustments
            .iter()
            .any(|a| a.reason.trim().is_empty() || a.reason.len() > 256)
    {
        return Err(invalid(
            "indirect definition needs a bounded name, reasons and adjustment population",
        ));
    }
    let mut value = definition.clone();
    value
        .adjustments
        .sort_unstable_by_key(|a| (a.entry_digest, a.leg_index));
    if value
        .adjustments
        .windows(2)
        .any(|p| (p[0].entry_digest, p[0].leg_index) == (p[1].entry_digest, p[1].leg_index))
    {
        return Err(invalid(
            "an indirect adjustment repeats the same journal leg",
        ));
    }
    Ok(value)
}

fn periods(values: &[String]) -> Result<Vec<String>, Refusal> {
    if values.is_empty()
        || values.len() > MAX_PERIODS
        || values.iter().any(|s| s.is_empty() || s.len() > 128)
    {
        return Err(invalid(
            "indirect cash flow needs 1..=256 bounded income period identities",
        ));
    }
    let mut values = values.to_vec();
    values.sort();
    if values.windows(2).any(|p| p[0] == p[1]) {
        return Err(invalid("indirect income periods repeat an identity"));
    }
    Ok(values)
}

#[derive(Clone, Copy)]
struct Sum {
    positive: U256,
    negative: U256,
}
impl Sum {
    const ZERO: Self = Self {
        positive: U256::ZERO,
        negative: U256::ZERO,
    };
    fn add(&mut self, value: i128, subtract: bool) -> Result<(), Refusal> {
        let target = if (value < 0) != subtract {
            &mut self.negative
        } else {
            &mut self.positive
        };
        *target = target
            .checked_add(U256::from_u128(value.unsigned_abs()))
            .ok_or_else(|| invalid("indirect cash-flow wide accumulation overflow"))?;
        Ok(())
    }
    fn value(self) -> Result<i128, Refusal> {
        let n = if self.positive >= self.negative {
            self.positive
                .checked_sub(self.negative)
                .and_then(U256::to_u128)
                .and_then(|n| i128::try_from(n).ok())
        } else {
            self.negative
                .checked_sub(self.positive)
                .and_then(U256::to_u128)
                .and_then(|n| {
                    if n == i128::MIN.unsigned_abs() {
                        Some(i128::MIN)
                    } else {
                        i128::try_from(n).ok().and_then(i128::checked_neg)
                    }
                })
        };
        n.ok_or_else(|| invalid("indirect cash-flow amount exceeds the exact i128 output range"))
    }
}

#[derive(Default)]
struct Bytes(Vec<u8>);
impl Bytes {
    fn add(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        bounded(self.0.len(), bytes.len())?;
        self.0
            .try_reserve(bytes.len())
            .map_err(|_| invalid("cannot reserve indirect cash-flow bytes"))?;
        self.0.extend_from_slice(bytes);
        Ok(())
    }
    fn count(&mut self, n: usize) -> Result<(), Refusal> {
        self.add(
            &u32::try_from(n)
                .map_err(|_| invalid("indirect cash-flow count overflow"))?
                .to_le_bytes(),
        )
    }
    fn blob(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        self.count(bytes.len())?;
        self.add(bytes)
    }
    fn string(&mut self, s: &str) -> Result<(), Refusal> {
        self.blob(s.as_bytes())
    }
}
fn bounded(a: usize, b: usize) -> Result<usize, Refusal> {
    a.checked_add(b)
        .filter(|n| *n <= MAX_INDIRECT_CASH_FLOW_BYTES)
        .ok_or_else(|| invalid("indirect cash-flow artifact exceeds its 64 MiB total bound"))
}
fn write_definition(
    out: &mut Bytes,
    definition: &IndirectCashFlowDefinition,
) -> Result<(), Refusal> {
    out.string(&definition.name)?;
    out.count(definition.adjustments.len())?;
    for a in &definition.adjustments {
        out.add(&a.entry_digest)?;
        out.add(&a.leg_index.to_le_bytes())?;
        out.add(&[a.category as u8, a.sign as u8])?;
        out.string(&a.reason)?;
    }
    Ok(())
}

enum Error {
    Refusal(Refusal),
    Book(BookError),
}
impl From<Refusal> for Error {
    fn from(e: Refusal) -> Self {
        Self::Refusal(e)
    }
}
impl From<BookError> for Error {
    fn from(e: BookError) -> Self {
        Self::Book(e)
    }
}
fn outcome<T>(result: Result<T, Error>) -> Outcome<T> {
    match result {
        Ok(v) => Ok(Ok(v)),
        Err(Error::Refusal(r)) => Ok(Err(r)),
        Err(Error::Book(e)) => Err(e),
    }
}

fn project(
    cash: CashFlowBasis,
    income: Statement,
    non_cash_source: Option<GeneralLedger>,
    definition: &IndirectCashFlowDefinition,
    query: &QueryCx,
) -> Outcome<IndirectCashFlow> {
    let build = || -> Result<IndirectCashFlow, Error> {
        query.checkpoint().map_err(BookError::Context)?;
        let definition = normalize(definition)?;
        let source = cash.source();
        if income.book_id != source.book_id()
            || income.branch_id != source.branch_id()
            || income.known_at != source.known_at().0
            || income.definition_name != "income-statement"
            || income.columns.len() != 1
            || income.columns[0].effective_from != Some(source.effective_from())
            || income.columns[0].effective_through != source.effective_through()
        {
            return Err(invalid(
                "native income and cash reports have different coordinates or bases",
            )
            .into());
        }
        let cash_ids: BTreeSet<_> = source.accounts().iter().map(|a| a.id).collect();
        let mut accounts = BTreeMap::new();
        let mut legs = BTreeMap::new();
        if let Some(detail) = &non_cash_source {
            if detail.book_id() != source.book_id()
                || detail.branch_id() != source.branch_id()
                || detail.known_at() != source.known_at()
                || detail.units() != source.units()
                || detail.effective_from() != source.effective_from()
                || detail.effective_through() != source.effective_through()
            {
                return Err(
                    invalid("non-cash adjustment source has a different coordinate").into(),
                );
            }
            for account in detail.accounts() {
                if cash_ids.contains(&account.id) {
                    return Err(invalid("cash legs cannot be indirect adjustments").into());
                }
                accounts.insert(account.id, account);
            }
            for (index, leg) in detail.lines().iter().enumerate() {
                if index % 256 == 0 {
                    query.checkpoint().map_err(BookError::Context)?;
                }
                let cell = detail
                    .cells()
                    .get(leg.cell_index as usize)
                    .ok_or_else(|| invalid("non-cash leg has no native account/unit cell"))?;
                let bucket = detail
                    .buckets()
                    .get(leg.bucket_index as usize)
                    .ok_or_else(|| invalid("non-cash leg has no native classification bucket"))?;
                if legs
                    .insert((leg.entry_digest, leg.leg_index), (leg, cell, bucket))
                    .is_some()
                {
                    return Err(invalid("non-cash source repeats a journal leg").into());
                }
            }
        }
        let mut adjustments: BTreeMap<_, _> = source
            .units()
            .iter()
            .map(|u| (*u, [Sum::ZERO; 3]))
            .collect();
        let mut contributions = Vec::new();
        contributions
            .try_reserve(definition.adjustments.len())
            .map_err(|_| invalid("cannot reserve indirect contributions"))?;
        for (index, a) in definition.adjustments.iter().enumerate() {
            if index % 256 == 0 {
                query.checkpoint().map_err(BookError::Context)?;
            }
            let (leg, cell, bucket) = legs.get(&(a.entry_digest, a.leg_index))
                .ok_or_else(|| invalid("indirect adjustment is not an original non-cash leg in the selected history"))?;
            if bucket.class == EntryClass::CLOSING {
                return Err(
                    invalid("a Closing transfer is not an indirect cash adjustment").into(),
                );
            }
            let account = accounts
                .get(&cell.account_id)
                .ok_or_else(|| invalid("adjustment account metadata is absent"))?;
            if a.category == AdjustmentCategory::WorkingCapital
                && ![AccountType::ASSET.0, AccountType::LIABILITY.0].contains(&account.account_type)
            {
                return Err(invalid(
                    "working-capital adjustments must cite asset or liability legs",
                )
                .into());
            }
            let amount = match a.sign {
                AdjustmentSign::DebitMinusCredit => leg.debits.checked_sub(leg.credits),
                AdjustmentSign::CreditMinusDebit => leg.credits.checked_sub(leg.debits),
            }
            .ok_or_else(|| invalid("indirect adjustment magnitude overflow"))?;
            adjustments
                .get_mut(&cell.unit_id)
                .ok_or_else(|| invalid("adjustment native unit is not selected"))?
                [a.category as usize]
                .add(amount, false)?;
            contributions.push(IndirectCashFlowContribution {
                entry_digest: a.entry_digest,
                leg_index: a.leg_index,
                account_id: cell.account_id,
                unit_id: cell.unit_id,
                amount,
            });
        }
        let mut earnings = BTreeMap::new();
        for line in &income.lines {
            if line.code == "net_income"
                && (line.amounts.len() != 1
                    || earnings.insert(line.unit_id, line.amounts[0]).is_some())
            {
                return Err(invalid(
                    "native income has duplicate or non-single-column net-income lines",
                )
                .into());
            }
        }
        let mut units = Vec::with_capacity(cash.units().len());
        for direct in cash.units() {
            query.checkpoint().map_err(BookError::Context)?;
            let net_income = *earnings
                .get(&direct.unit_id)
                .ok_or_else(|| invalid("native income omits a selected unit"))?;
            let sums = adjustments
                .get(&direct.unit_id)
                .ok_or_else(|| invalid("cash native unit is not selected"))?;
            let [non_cash, working_capital, non_operating] =
                [sums[0].value()?, sums[1].value()?, sums[2].value()?];
            let mut total = Sum::ZERO;
            for n in [net_income, non_cash, working_capital, non_operating] {
                total.add(n, false)?;
            }
            let operating = total.value()?;
            total.add(direct.operating.net, true)?;
            let operating_residual = total.value()?;
            if operating_residual != 0 {
                return Err(invalid(format!("indirect operating cash differs from direct cash in unit {}: residual {operating_residual}", direct.unit_id)).into());
            }
            let mut change = Sum::ZERO;
            for n in [
                operating,
                direct.investing.net,
                direct.financing.net,
                direct.exchange_effects.net,
            ] {
                change.add(n, false)?;
            }
            let net_change = change.value()?;
            change.add(direct.opening, false)?;
            change.add(direct.closing, true)?;
            if net_change != direct.net_change || change.value()? != 0 {
                return Err(invalid(
                    "indirect cash flow does not reconcile native opening and closing cash",
                )
                .into());
            }
            units.push(IndirectCashFlowUnit {
                unit_id: direct.unit_id,
                net_income,
                non_cash,
                working_capital,
                non_operating,
                operating,
                direct_operating: direct.operating.net,
                operating_residual,
                opening: direct.opening,
                investing: direct.investing.net,
                financing: direct.financing.net,
                exchange_effects: direct.exchange_effects.net,
                net_change,
                closing: direct.closing,
            });
        }
        query.checkpoint().map_err(BookError::Context)?;
        Ok(IndirectCashFlow {
            cash,
            income,
            non_cash_source,
            definition,
            contributions,
            units,
        })
    };
    outcome(build())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wide_sums_cancel_before_narrowing_and_preserve_the_negative_endpoint() {
        let mut sum = Sum::ZERO;
        for n in [i128::MAX, i128::MAX, -i128::MAX, -i128::MAX, i128::MIN] {
            sum.add(n, false).unwrap();
        }
        assert_eq!(sum.value().unwrap(), i128::MIN);
        sum.add(i128::MIN, true).unwrap();
        assert_eq!(sum.value().unwrap(), 0);
        sum.add(i128::MAX, false).unwrap();
        sum.add(1, false).unwrap();
        assert!(sum.value().is_err());
    }
    #[test]
    fn duplicate_leg_is_refused_across_categories_and_signs() {
        let a = IndirectCashFlowAdjustment {
            entry_digest: [1; 32],
            leg_index: 2,
            category: AdjustmentCategory::NonCash,
            sign: AdjustmentSign::DebitMinusCredit,
            reason: "depreciation".into(),
        };
        let mut b = a.clone();
        b.category = AdjustmentCategory::NonOperating;
        b.sign = AdjustmentSign::CreditMinusDebit;
        assert!(
            normalize(&IndirectCashFlowDefinition {
                name: "v1".into(),
                adjustments: vec![a, b]
            })
            .is_err()
        );
    }
    #[test]
    fn periods_and_output_are_bounded_without_normalizing_away_duplicates() {
        assert!(periods(&[]).is_err());
        assert!(periods(&["P1".into(), "P1".into()]).is_err());
        assert_eq!(periods(&["P2".into(), "P1".into()]).unwrap(), ["P1", "P2"]);
        assert_eq!(
            bounded(MAX_INDIRECT_CASH_FLOW_BYTES, 0).unwrap(),
            MAX_INDIRECT_CASH_FLOW_BYTES
        );
        assert!(bounded(MAX_INDIRECT_CASH_FLOW_BYTES, 1).is_err());
        assert!(bounded(usize::MAX, 1).is_err());
    }
}
