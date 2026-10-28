//! Independent earnings-to-cash replay from the authenticated native prefix.
//! Adjustments cite whole original non-cash legs; no caller amount or residual
//! plug is admitted. Economic selection, cash equivalence and approval remain
//! professional judgments outside the arithmetic proof.

use std::collections::{BTreeMap, BTreeSet};

use super::cash_flow::{self, CashFlowUnit, VerifiedCashFlow, VerifiedGeneralLedger};
use super::cash_flow_split::{self, VerifiedSplitCashFlow};
use super::metadata::{EntryInfo, Schema};
use super::roll_forward;
use super::statement::{self, Sum, VerifiedStatement};
use super::{MAX_REPORT_BUNDLE_BYTES, ReportError, ReportRow, failed, text};
use crate::codec::Writer;
use crate::envelope::{LeafEnvelope, Leg};

const FORMAT_V1: &[u8] = b"fa:indirect-cash-flow-certificate:v1";
const FORMAT_V2: &[u8] = b"fa:indirect-cash-flow-certificate:v2";
const DOMAIN_V1: &[u8] = b"fa:indirect-cash-flow-certificate-digest:v1";
const DOMAIN_V2: &[u8] = b"fa:indirect-cash-flow-certificate-digest:v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AdjustmentCategory {
    NonCash = 0,
    WorkingCapital = 1,
    NonOperating = 2,
}

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
    pub adjustments: Vec<IndirectCashFlowAdjustment>,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifiedCashFlowBasis {
    Explicit(VerifiedCashFlow),
    Policy(VerifiedCashFlow),
    Split(VerifiedSplitCashFlow),
}

impl VerifiedCashFlowBasis {
    pub(super) fn kind(&self) -> u8 {
        match self {
            Self::Explicit(_) => 0,
            Self::Policy(_) => 1,
            Self::Split(_) => 2,
        }
    }
    #[must_use]
    pub fn ledger(&self) -> &VerifiedGeneralLedger {
        match self {
            Self::Explicit(report) | Self::Policy(report) => &report.ledger,
            Self::Split(report) => &report.ledger,
        }
    }
    #[must_use]
    pub fn units(&self) -> &[CashFlowUnit] {
        match self {
            Self::Explicit(report) | Self::Policy(report) => &report.units,
            Self::Split(report) => &report.units,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedIndirectCashFlow {
    pub source_certificate_digest: [u8; 32],
    pub cash: VerifiedCashFlowBasis,
    pub income: VerifiedStatement,
    pub non_cash_source: Option<VerifiedGeneralLedger>,
    pub definition: IndirectCashFlowDefinition,
    pub contributions: Vec<IndirectCashFlowContribution>,
    pub units: Vec<IndirectCashFlowUnit>,
}

pub(super) struct Certificate<'a> {
    pub kind: u8,
    pub source: &'a [u8],
    pub periods: Vec<String>,
    pub definition: IndirectCashFlowDefinition,
    pub output: &'a [u8],
    pub digest: [u8; 32],
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    cash_flow::recognizes_format(bytes, FORMAT_V1) || cash_flow::recognizes_format(bytes, FORMAT_V2)
}

fn invalid(message: impl Into<String>) -> ReportError {
    failed("indirect_cash_definition", message)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    let version_two = cash_flow::recognizes_format(bytes, FORMAT_V2);
    let (mut r, digest) = if version_two {
        cash_flow::body(bytes, FORMAT_V2, DOMAIN_V2)?
    } else {
        cash_flow::body(bytes, FORMAT_V1, DOMAIN_V1)?
    };
    let kind = if version_two {
        match r.u8("indirect.cash_basis")? {
            value @ (1 | 2) => value,
            _ => return Err(invalid("version two requires a policy or split cash basis")),
        }
    } else {
        0
    };
    let source = r.bytes(MAX_REPORT_BUNDLE_BYTES, "indirect.source")?;
    if !match kind {
        0 => cash_flow::recognizes(source),
        1 => cash_flow::policy::recognizes(source),
        2 => cash_flow_split::recognizes(source),
        _ => false,
    } {
        return Err(failed(
            "supported_report",
            "indirect cash basis does not match its declared family",
        ));
    }
    let count = r.count(256, 4, "indirect.periods")?;
    let mut periods = Vec::with_capacity(count);
    for _ in 0..count {
        periods.push(text(&mut r, 128, "indirect.period")?.to_owned());
    }
    if periods.is_empty()
        || periods.iter().any(String::is_empty)
        || !periods.windows(2).all(|p| p[0] < p[1])
    {
        return Err(invalid(
            "income periods must be nonempty, distinct and strictly ordered",
        ));
    }
    let name = text(&mut r, 256, "indirect.definition_name")?.to_owned();
    if name.trim().is_empty() {
        return Err(invalid("indirect definition name is empty"));
    }
    let count = r.count(cash_flow::MAX_LINES, 42, "indirect.adjustments")?;
    let mut adjustments = Vec::with_capacity(count);
    let mut previous = None;
    for _ in 0..count {
        let entry_digest = r.fixed("indirect.entry")?;
        let leg_index = r.u32("indirect.leg")?;
        let key = (entry_digest, leg_index);
        if previous.is_some_and(|p| p >= key) {
            return Err(invalid("adjustment legs repeat or are unordered"));
        }
        previous = Some(key);
        let category = match r.u8("indirect.category")? {
            0 => AdjustmentCategory::NonCash,
            1 => AdjustmentCategory::WorkingCapital,
            2 => AdjustmentCategory::NonOperating,
            _ => return Err(invalid("unknown indirect adjustment category")),
        };
        let sign = match r.u8("indirect.sign")? {
            0 => AdjustmentSign::DebitMinusCredit,
            1 => AdjustmentSign::CreditMinusDebit,
            _ => return Err(invalid("unknown indirect adjustment sign")),
        };
        let reason = text(&mut r, 256, "indirect.reason")?.to_owned();
        if reason.trim().is_empty() {
            return Err(invalid("indirect adjustment reason is empty"));
        }
        adjustments.push(IndirectCashFlowAdjustment {
            entry_digest,
            leg_index,
            category,
            sign,
            reason,
        });
    }
    let output = r.bytes(MAX_REPORT_BUNDLE_BYTES, "indirect.output")?;
    r.finish("indirect cash certificate")?;
    Ok(Certificate {
        kind,
        source,
        periods,
        definition: IndirectCashFlowDefinition { name, adjustments },
        output,
        digest,
    })
}

/// The v1 indirect law calls for this fixed embedded income definition. It
/// never accepts a redefined net_income formula delivered in the output.
fn income_definition() -> Vec<u8> {
    let mut w = Writer::default();
    w.fixed(b"FA-STATEMENT-DEF\0")
        .u16(1)
        .u16(0)
        .bytes(b"income-statement")
        .bytes(b"Income statement")
        .u32(1)
        .u8(1)
        .count(3);
    for (code, label, typ, credit) in [
        (b"revenue".as_slice(), b"Revenue".as_slice(), 4, 1),
        (b"expense".as_slice(), b"Expenses".as_slice(), 5, 0),
    ] {
        w.bytes(code).bytes(label).u8(0).count(1).u8(typ).u8(credit);
    }
    w.bytes(b"net_income")
        .bytes(b"Net income")
        .u8(1)
        .count(1)
        .bytes(b"revenue")
        .count(1)
        .bytes(b"expense")
        .count(0);
    w.buf
}

pub(super) struct Sources<'a, 'record> {
    pub native_source_digest: [u8; 32],
    pub registered_units: &'a [u32],
    pub schema: &'a Schema,
    pub envelopes: &'a [LeafEnvelope],
    pub infos: &'a BTreeMap<usize, EntryInfo<'record>>,
    pub legs: &'a [Vec<Leg>],
    pub visible_migrations: &'a BTreeSet<u64>,
    pub resolved: &'a BTreeSet<usize>,
    pub source_rows: &'a [ReportRow],
}

fn overflow() -> ReportError {
    failed(
        "exact_arithmetic",
        "indirect cash amount exceeds its exact range",
    )
}

fn reconcile(
    cash: &VerifiedCashFlowBasis,
    income: &VerifiedStatement,
    detail: Option<&VerifiedGeneralLedger>,
    definition: &IndirectCashFlowDefinition,
) -> Result<(Vec<IndirectCashFlowContribution>, Vec<IndirectCashFlowUnit>), ReportError> {
    let mut selected = BTreeMap::new();
    if let Some(detail) = detail {
        let accounts: BTreeMap<_, _> = detail.accounts.iter().map(|a| (a.id, a)).collect();
        for leg in &detail.lines {
            let cell = &detail.cells[leg.cell_index as usize];
            let bucket = &detail.buckets[leg.bucket_index as usize];
            let account = accounts
                .get(&cell.account_id)
                .copied()
                .ok_or_else(|| failed("indirect_source", "non-cash leg has no account metadata"))?;
            if selected
                .insert(
                    (leg.entry_digest, leg.leg_index),
                    (leg, cell, bucket, account),
                )
                .is_some()
            {
                return Err(failed(
                    "indirect_source",
                    "non-cash source repeats an original leg",
                ));
            }
        }
    }
    let mut sums: BTreeMap<_, [Sum; 3]> = cash
        .ledger()
        .units
        .iter()
        .map(|&u| (u, [Sum::default(); 3]))
        .collect();
    let mut contributions = Vec::with_capacity(definition.adjustments.len());
    for adjustment in &definition.adjustments {
        let (leg, cell, bucket, account) = selected
            .get(&(adjustment.entry_digest, adjustment.leg_index))
            .ok_or_else(|| {
                failed(
                    "indirect_adjustment_source",
                    "adjustment is not an original selected non-cash leg",
                )
            })?;
        if bucket.class == 8 {
            return Err(failed(
                "indirect_adjustment_source",
                "Closing transfers cannot be indirect adjustments",
            ));
        }
        if adjustment.category == AdjustmentCategory::WorkingCapital
            && !matches!(account.account_type, 1 | 2)
        {
            return Err(failed(
                "indirect_adjustment_source",
                "working-capital adjustments require an asset or liability leg",
            ));
        }
        let amount = match adjustment.sign {
            AdjustmentSign::DebitMinusCredit => leg.debits.checked_sub(leg.credits),
            AdjustmentSign::CreditMinusDebit => leg.credits.checked_sub(leg.debits),
        }
        .ok_or_else(overflow)?;
        sums.get_mut(&cell.unit_id)
            .ok_or_else(|| failed("indirect_source", "adjustment unit is not selected"))?
            [adjustment.category as usize]
            .add(amount, false)
            .ok_or_else(overflow)?;
        contributions.push(IndirectCashFlowContribution {
            entry_digest: adjustment.entry_digest,
            leg_index: adjustment.leg_index,
            account_id: cell.account_id,
            unit_id: cell.unit_id,
            amount,
        });
    }
    let earnings: BTreeMap<_, _> = income
        .lines
        .iter()
        .filter(|l| l.code == "net_income")
        .map(|l| (l.unit, l.amounts[0]))
        .collect();
    let mut units = Vec::with_capacity(cash.units().len());
    for direct in cash.units() {
        let net_income = *earnings
            .get(&direct.unit_id)
            .ok_or_else(|| failed("indirect_income", "income omits a selected cash unit"))?;
        let sums = &sums[&direct.unit_id];
        let non_cash = sums[0].value().ok_or_else(overflow)?;
        let working_capital = sums[1].value().ok_or_else(overflow)?;
        let non_operating = sums[2].value().ok_or_else(overflow)?;
        let mut total = Sum::default();
        for amount in [net_income, non_cash, working_capital, non_operating] {
            total.add(amount, false).ok_or_else(overflow)?;
        }
        let operating = total.value().ok_or_else(overflow)?;
        total.add(direct.operating.net, true).ok_or_else(overflow)?;
        let operating_residual = total.value().ok_or_else(overflow)?;
        if operating_residual != 0 {
            return Err(failed(
                "indirect_operating_reconciliation",
                "earnings plus sourced adjustments differ from independently classified operating cash",
            ));
        }
        let mut change = Sum::default();
        for amount in [
            operating,
            direct.investing.net,
            direct.financing.net,
            direct.exchange_effects.net,
        ] {
            change.add(amount, false).ok_or_else(overflow)?;
        }
        let net_change = change.value().ok_or_else(overflow)?;
        change.add(direct.opening, false).ok_or_else(overflow)?;
        change.add(direct.closing, true).ok_or_else(overflow)?;
        if net_change != direct.net_change || change.value() != Some(0) {
            return Err(failed(
                "indirect_cash_reconciliation",
                "indirect cash does not reconcile opening and closing stock",
            ));
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
    Ok((contributions, units))
}

fn output(
    report: &VerifiedIndirectCashFlow,
    cash: &[u8],
    income: &[u8],
) -> Result<Vec<u8>, ReportError> {
    let detail = report
        .non_cash_source
        .as_ref()
        .map(cash_flow::ledger_bytes)
        .transpose()?;
    let format = if report.cash.kind() == 0 {
        b"fa:indirect-cash-flow:v1"
    } else {
        b"fa:indirect-cash-flow:v2"
    };
    let mut size = 4 + format.len() + usize::from(report.cash.kind() != 0);
    cash_flow::add_size(&mut size, 4 + cash.len() + 4 + income.len() + 1)?;
    if let Some(detail) = &detail {
        cash_flow::add_size(&mut size, 4 + detail.len())?;
    }
    cash_flow::add_size(&mut size, 4 + report.definition.name.len() + 4)?;
    for adjustment in &report.definition.adjustments {
        cash_flow::add_size(&mut size, 42 + adjustment.reason.len())?;
    }
    cash_flow::add_size(
        &mut size,
        4 + report.contributions.len() * 72 + 4 + report.units.len() * 212,
    )?;
    let mut w = cash_flow::writer(size)?;
    w.bytes(format);
    if report.cash.kind() != 0 {
        w.u8(report.cash.kind());
    }
    w.bytes(cash).bytes(income).u8(u8::from(detail.is_some()));
    if let Some(detail) = detail {
        w.bytes(&detail);
    }
    w.bytes(report.definition.name.as_bytes())
        .count(report.definition.adjustments.len());
    for adjustment in &report.definition.adjustments {
        w.fixed(&adjustment.entry_digest)
            .u32(adjustment.leg_index)
            .u8(adjustment.category as u8)
            .u8(adjustment.sign as u8)
            .bytes(adjustment.reason.as_bytes());
    }
    w.count(report.contributions.len());
    for c in &report.contributions {
        w.fixed(&c.entry_digest)
            .u32(c.leg_index)
            .u128(c.account_id)
            .u32(c.unit_id)
            .i128(c.amount);
    }
    w.count(report.units.len());
    for unit in &report.units {
        w.u32(unit.unit_id);
        for amount in [
            unit.net_income,
            unit.non_cash,
            unit.working_capital,
            unit.non_operating,
            unit.operating,
            unit.direct_operating,
            unit.operating_residual,
            unit.opening,
            unit.investing,
            unit.financing,
            unit.exchange_effects,
            unit.net_change,
            unit.closing,
        ] {
            w.i128(amount);
        }
    }
    debug_assert_eq!(size, w.buf.len());
    Ok(w.buf)
}

pub(super) fn replay(
    certificate: &Certificate<'_>,
    cash: VerifiedCashFlowBasis,
    cash_output: &[u8],
    source: Sources<'_, '_>,
) -> Result<(VerifiedIndirectCashFlow, Vec<u8>), ReportError> {
    if certificate.kind != cash.kind() {
        return Err(failed(
            "indirect_cash_basis",
            "recomputed cash basis has a different family",
        ));
    }
    let ledger = cash.ledger();
    let selected = source
        .schema
        .whole_periods_between(ledger.effective_from, ledger.effective_through)?;
    if certificate.periods != selected {
        return Err(failed(
            "indirect_period_coverage",
            "income periods omit or add a historical overlapping period",
        ));
    }
    let selection = statement::Selection::new(&income_definition(), selected, Vec::new())?;
    let (income, income_bytes) = statement::replay(
        &selection,
        &ledger.book_id,
        &[0; 16],
        ledger.known_at,
        source.registered_units,
        source.schema,
        source.envelopes,
        source.infos,
        source.legs,
        source.visible_migrations,
        source.resolved,
    )?;
    if income.columns.len() != 1
        || income.columns[0].effective_from != Some(ledger.effective_from)
        || income.columns[0].effective_through != ledger.effective_through
    {
        return Err(failed(
            "indirect_income",
            "income and cash intervals differ",
        ));
    }
    let cash_ids: BTreeSet<_> = ledger.accounts.iter().map(|a| a.id).collect();
    let accounts: Vec<_> = source
        .schema
        .accounts
        .iter()
        .filter(|(id, a)| a.is_leaf && (1..=5).contains(&a.account_type) && !cash_ids.contains(id))
        .map(|(&id, _)| id)
        .collect();
    if accounts.len() > 4096 {
        return Err(failed(
            "bounded_output",
            "non-cash source exceeds 4096 monetary leaves",
        ));
    }
    let non_cash_source = if accounts.is_empty() {
        None
    } else {
        // Scope comes exclusively from the authenticated historical chart. No
        // output-supplied account list or derived transcript can prune it.
        let request = roll_forward::Certificate {
            source: &[],
            accounts,
            units: ledger.units.clone(),
            label: &ledger.label,
            effective_from: ledger.effective_from,
            effective_through: ledger.effective_through,
            output: &[],
            digest: [0; 32],
        };
        let (detail, _) = roll_forward::recompute(
            &request,
            ledger.book_id,
            ledger.known_at,
            source.native_source_digest,
            source.registered_units,
            source.schema,
            source.envelopes,
            source.infos,
            source.legs,
            source.visible_migrations,
            source.source_rows,
            MAX_REPORT_BUNDLE_BYTES,
        )?;
        Some(cash_flow::ledger(detail)?)
    };
    let (contributions, units) = reconcile(
        &cash,
        &income,
        non_cash_source.as_ref(),
        &certificate.definition,
    )?;
    let source_certificate_digest = certificate
        .source
        .get(certificate.source.len().saturating_sub(32)..)
        .and_then(|digest| digest.try_into().ok())
        .ok_or_else(|| failed("indirect_cash_basis", "cash source omits its digest"))?;
    let report = VerifiedIndirectCashFlow {
        source_certificate_digest,
        cash,
        income,
        non_cash_source,
        definition: certificate.definition.clone(),
        contributions,
        units,
    };
    let output = output(&report, cash_output, &income_bytes)?;
    if output != certificate.output {
        let first_difference = output
            .iter()
            .zip(certificate.output)
            .position(|(a, b)| a != b)
            .unwrap_or(output.len().min(certificate.output.len()));
        return Err(failed(
            "indirect_cash_recomputation",
            format!(
                "income, cash basis, complete non-cash detail, adjustment citations or exact reconciliation differ from independent replay at byte {first_difference} (recomputed {} bytes, supplied {} bytes)",
                output.len(),
                certificate.output.len()
            ),
        ));
    }
    Ok((report, output))
}
