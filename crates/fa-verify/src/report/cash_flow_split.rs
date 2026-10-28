//! Independent original-leg cash partitions over authenticated native detail.
//! Split decisions and their reasons are report parameters. Arithmetic,
//! coverage and transfer cancellation are checked; economic judgment is not.

use std::collections::{BTreeMap, BTreeSet};

use super::cash_flow::{
    self, CashFlowActivity, CashFlowSection, CashFlowUnit, VerifiedGeneralLedger,
};
use super::roll_forward::VerifiedRollForward;
use super::statement::Sum;
use super::{MAX_REPORT_BUNDLE_BYTES, ReportError, failed, text};
use crate::codec::Reader;

pub(super) const FORMAT: &[u8] = b"fa:cash-flow-split-certificate:v1";
const DOMAIN: &[u8] = b"fa:cash-flow-split-certificate-digest:v1";
const DEFINITION_FORMAT: &[u8] = b"fa:cash-flow-split-definition:v1";
const OUTPUT_FORMAT: &[u8] = b"fa:cash-flow-split:v1";
const MAX_DEFINITION_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CashFlowPortion {
    pub activity: CashFlowActivity,
    pub amount: i128,
}

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSplitCashFlow {
    pub source_certificate_digest: [u8; 32],
    pub ledger: VerifiedGeneralLedger,
    pub definition: CashFlowSplitDefinition,
    pub units: Vec<CashFlowUnit>,
}

pub(super) struct Certificate<'a> {
    pub source: &'a [u8],
    pub definition: CashFlowSplitDefinition,
    pub output: &'a [u8],
    pub digest: [u8; 32],
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    cash_flow::recognizes_format(bytes, FORMAT)
}

fn invalid(message: impl Into<String>) -> ReportError {
    failed("cash_split_definition", message)
}

fn definition(bytes: &[u8]) -> Result<CashFlowSplitDefinition, ReportError> {
    let mut r = Reader::new(bytes);
    if r.bytes(64, "split.definition_format")? != DEFINITION_FORMAT {
        return Err(invalid("unsupported cash split definition"));
    }
    let name = text(&mut r, 256, "split.name")?.to_owned();
    if name.trim().is_empty() {
        return Err(invalid("cash split name is empty"));
    }
    let cash_accounts = cash_flow::accounts(&mut r)?;
    let count = r.count(cash_flow::MAX_LINES, 61, "split.legs")?;
    let mut splits = Vec::with_capacity(count);
    let mut previous = None;
    for _ in 0..count {
        let entry_digest = r.fixed("split.entry")?;
        let leg_index = r.u32("split.leg")?;
        let key = (entry_digest, leg_index);
        if previous.is_some_and(|p| p >= key) {
            return Err(invalid("cash split legs repeat or are unordered"));
        }
        previous = Some(key);
        let reason = text(&mut r, 256, "split.reason")?.to_owned();
        if reason.trim().is_empty() {
            return Err(invalid("cash split reason is empty"));
        }
        let count = r.count(5, 17, "split.portions")?;
        if count == 0 {
            return Err(invalid("cash split has no portions"));
        }
        let mut portions = Vec::with_capacity(count);
        let mut previous = None;
        for _ in 0..count {
            let activity = CashFlowActivity::read(&mut r)?;
            let amount = r.i128("split.amount")?;
            if amount <= 0 || previous.is_some_and(|p| p >= activity) {
                return Err(invalid(
                    "cash portions must be positive with strictly ordered distinct activities",
                ));
            }
            previous = Some(activity);
            portions.push(CashFlowPortion { activity, amount });
        }
        splits.push(CashFlowLegSplit {
            entry_digest,
            leg_index,
            reason,
            portions,
        });
    }
    r.finish("cash split definition")?;
    Ok(CashFlowSplitDefinition {
        name,
        cash_accounts,
        splits,
    })
}

pub(super) fn decode(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    let (mut r, digest) = cash_flow::body(bytes, FORMAT, DOMAIN)?;
    let source = r.bytes(MAX_REPORT_BUNDLE_BYTES, "split.source")?;
    if !super::roll_forward::recognizes(source) {
        return Err(failed(
            "supported_report",
            "cash split requires a native roll-forward source",
        ));
    }
    let definition = definition(r.bytes(MAX_DEFINITION_BYTES, "split.definition")?)?;
    let output = r.bytes(MAX_REPORT_BUNDLE_BYTES, "split.output")?;
    r.finish("cash split certificate")?;
    Ok(Certificate {
        source,
        definition,
        output,
        digest,
    })
}

fn overflow() -> ReportError {
    failed(
        "exact_arithmetic",
        "cash split amount exceeds its exact native range",
    )
}

#[derive(Default)]
struct Totals {
    opening: Sum,
    closing: Sum,
    sections: [CashFlowSection; 4],
}

fn classify(
    ledger: &VerifiedGeneralLedger,
    definition: &CashFlowSplitDefinition,
) -> Result<Vec<CashFlowUnit>, ReportError> {
    let accounts: BTreeSet<_> = definition.cash_accounts.iter().copied().collect();
    if accounts.len() != ledger.accounts.len()
        || definition.splits.len() != ledger.lines.len()
        || ledger
            .accounts
            .iter()
            .any(|a| !accounts.contains(&a.id) || !a.is_leaf || !matches!(a.account_type, 1 | 2))
    {
        return Err(failed(
            "cash_split_scope",
            "cash partitions must cover exactly the selected asset/overdraft leaves and original legs",
        ));
    }
    let mut splits: BTreeMap<_, _> = definition
        .splits
        .iter()
        .map(|s| ((s.entry_digest, s.leg_index), s))
        .collect();
    let mut totals: BTreeMap<_, Totals> = ledger
        .units
        .iter()
        .map(|&u| (u, Totals::default()))
        .collect();
    for cell in &ledger.cells {
        let total = totals
            .get_mut(&cell.unit_id)
            .ok_or_else(|| failed("cash_split_scope", "cash stock has an undeclared unit"))?;
        total
            .opening
            .add(cell.opening, false)
            .ok_or_else(overflow)?;
        total
            .closing
            .add(cell.closing, false)
            .ok_or_else(overflow)?;
    }
    let mut sections: BTreeMap<([u8; 32], u32, CashFlowActivity), Sum> = BTreeMap::new();
    let mut transfers: BTreeMap<([u8; 32], u32), (Sum, BTreeSet<u128>)> = BTreeMap::new();
    for line in &ledger.lines {
        let cell = &ledger.cells[line.cell_index as usize];
        let split = splits
            .remove(&(line.entry_digest, line.leg_index))
            .ok_or_else(|| {
                failed(
                    "cash_split_coverage",
                    "an original cash leg has no unique partition",
                )
            })?;
        let mut total = Sum::default();
        for portion in &split.portions {
            total.add(portion.amount, false).ok_or_else(overflow)?;
        }
        total
            .add(line.debits.max(line.credits), true)
            .ok_or_else(overflow)?;
        if total.value() != Some(0) {
            return Err(failed(
                "cash_split_partition",
                "cash portions do not sum exactly to their original leg",
            ));
        }
        for portion in &split.portions {
            let sum = if portion.activity == CashFlowActivity::InternalTransfer {
                let (sum, accounts) = transfers
                    .entry((line.entry_digest, cell.unit_id))
                    .or_default();
                accounts.insert(cell.account_id);
                sum
            } else {
                sections
                    .entry((line.entry_digest, cell.unit_id, portion.activity))
                    .or_default()
            };
            sum.add(portion.amount, line.credits > 0)
                .ok_or_else(overflow)?;
        }
    }
    if !splits.is_empty() {
        return Err(failed(
            "cash_split_coverage",
            "cash portions cite unselected original legs",
        ));
    }
    for (sum, accounts) in transfers.values() {
        if accounts.len() < 2 || sum.value() != Some(0) {
            return Err(failed(
                "cash_split_transfers",
                "transfer portions must cancel within one original entry and native unit across distinct cash accounts",
            ));
        }
    }
    // Gross turnover nets only within an original entry/unit/activity. Distinct
    // receipts and payments retain their separate inflow/outflow magnitudes.
    for ((_, unit, activity), sum) in sections {
        let net = sum.value().ok_or_else(overflow)?;
        let section = &mut totals
            .get_mut(&unit)
            .ok_or_else(|| failed("cash_split_scope", "cash portion has an undeclared unit"))?
            .sections[activity as usize];
        if net >= 0 {
            section.inflows = section.inflows.checked_add(net).ok_or_else(overflow)?;
        } else {
            section.outflows = section
                .outflows
                .checked_add(net.checked_neg().ok_or_else(overflow)?)
                .ok_or_else(overflow)?;
        }
    }
    let mut units = Vec::with_capacity(totals.len());
    for (unit_id, mut total) in totals {
        let opening = total.opening.value().ok_or_else(overflow)?;
        let closing = total.closing.value().ok_or_else(overflow)?;
        let mut change = Sum::default();
        for section in &mut total.sections {
            section.net = section
                .inflows
                .checked_sub(section.outflows)
                .ok_or_else(overflow)?;
            change.add(section.net, false).ok_or_else(overflow)?;
        }
        let net_change = change.value().ok_or_else(overflow)?;
        let mut residual = change;
        residual.add(opening, false).ok_or_else(overflow)?;
        residual.add(closing, true).ok_or_else(overflow)?;
        if residual.value() != Some(0) {
            return Err(failed(
                "cash_split_reconciliation",
                "partitioned movements differ from independently folded cash stocks",
            ));
        }
        units.push(CashFlowUnit {
            unit_id,
            opening,
            operating: total.sections[0],
            investing: total.sections[1],
            financing: total.sections[2],
            exchange_effects: total.sections[3],
            net_change,
            closing,
        });
    }
    Ok(units)
}

fn definition_bytes(definition: &CashFlowSplitDefinition) -> Result<Vec<u8>, ReportError> {
    let mut size = 4
        + DEFINITION_FORMAT.len()
        + 4
        + definition.name.len()
        + 4
        + definition.cash_accounts.len() * 16
        + 4;
    for split in &definition.splits {
        cash_flow::add_size(
            &mut size,
            44 + split.reason.len() + split.portions.len() * 17,
        )?;
    }
    if size > MAX_DEFINITION_BYTES {
        return Err(failed(
            "bounded_output",
            "cash split definition exceeds 32 MiB",
        ));
    }
    let mut w = cash_flow::writer(size)?;
    w.bytes(DEFINITION_FORMAT)
        .bytes(definition.name.as_bytes())
        .count(definition.cash_accounts.len());
    for account in &definition.cash_accounts {
        w.u128(*account);
    }
    w.count(definition.splits.len());
    for split in &definition.splits {
        w.fixed(&split.entry_digest)
            .u32(split.leg_index)
            .bytes(split.reason.as_bytes())
            .count(split.portions.len());
        for portion in &split.portions {
            w.u8(portion.activity as u8).i128(portion.amount);
        }
    }
    debug_assert_eq!(w.buf.len(), size);
    Ok(w.buf)
}

fn output(report: &VerifiedSplitCashFlow) -> Result<Vec<u8>, ReportError> {
    let ledger = cash_flow::ledger_bytes(&report.ledger)?;
    let definition = definition_bytes(&report.definition)?;
    let mut size = 4 + OUTPUT_FORMAT.len();
    cash_flow::add_size(
        &mut size,
        4 + ledger.len() + 4 + definition.len() + 4 + report.units.len() * 244,
    )?;
    let mut w = cash_flow::writer(size)?;
    w.bytes(OUTPUT_FORMAT)
        .bytes(&ledger)
        .bytes(&definition)
        .count(report.units.len());
    for unit in &report.units {
        w.u32(unit.unit_id).i128(unit.opening);
        for section in [
            unit.operating,
            unit.investing,
            unit.financing,
            unit.exchange_effects,
        ] {
            w.i128(section.inflows)
                .i128(section.outflows)
                .i128(section.net);
        }
        w.i128(unit.net_change).i128(unit.closing);
    }
    debug_assert_eq!(w.buf.len(), size);
    Ok(w.buf)
}

pub(super) fn replay(
    certificate: &Certificate<'_>,
    source: VerifiedRollForward,
    source_digest: [u8; 32],
) -> Result<(VerifiedSplitCashFlow, Vec<u8>), ReportError> {
    let ledger = cash_flow::ledger(source)?;
    let units = classify(&ledger, &certificate.definition)?;
    let report = VerifiedSplitCashFlow {
        source_certificate_digest: source_digest,
        ledger,
        definition: certificate.definition.clone(),
        units,
    };
    let output = output(&report)?;
    if output != certificate.output {
        return Err(failed(
            "cash_split_recomputation",
            "cash ledger, original-leg portions, reasons, transfer netting, gross turnover or stocks differ from independent replay",
        ));
    }
    Ok((report, output))
}
