//! Independent direct cash-flow recomputation over a verified lead schedule.
//! Classifications and cash designations are authenticated report parameters,
//! not assertions that their economic treatment or approval is correct.

pub(super) mod policy;
pub use policy::{
    CashFlowAccountRule, CashFlowDecisionBasis, CashFlowPolicy, CashFlowPolicyDecision,
    VerifiedCashFlowPolicy,
};

use super::roll_forward::{RollForwardAccount, RollForwardBucket, VerifiedRollForward};
use super::statement::Sum;
use super::{MAX_REPORT_BUNDLE_BYTES, ReportError, failed, hash_parts, text};
use crate::codec::{Reader, Writer};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const FORMAT: &[u8] = b"fa:cash-flow-certificate:v1";
const DIGEST_DOMAIN: &[u8] = b"fa:cash-flow-certificate-digest:v1";
const LEDGER_FORMAT: &[u8] = b"fa:general-ledger:v1";
const OUTPUT_FORMAT: &[u8] = b"fa:cash-flow:v1";
pub(super) const MAX_ACCOUNTS: usize = 4096;
pub(super) const MAX_LINES: usize = 250_000;
const MAX_CELLS: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum CashFlowActivity {
    Operating = 0,
    Investing = 1,
    Financing = 2,
    ExchangeEffect = 3,
    InternalTransfer = 4,
}

impl CashFlowActivity {
    pub(super) fn read(r: &mut Reader<'_>) -> Result<Self, ReportError> {
        Ok(match r.u8("cash.activity")? {
            0 => Self::Operating,
            1 => Self::Investing,
            2 => Self::Financing,
            3 => Self::ExchangeEffect,
            4 => Self::InternalTransfer,
            _ => return Err(failed("cash_flow_classification", "unknown cash activity")),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowAssignment {
    pub entry_digest: [u8; 32],
    pub leg_index: u32,
    pub activity: CashFlowActivity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowDefinition {
    pub name: String,
    pub cash_accounts: Vec<u128>,
    pub assignments: Vec<CashFlowAssignment>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CashFlowSection {
    pub inflows: i128,
    pub outflows: i128,
    pub net: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowUnit {
    pub unit_id: u32,
    pub opening: i128,
    pub operating: CashFlowSection,
    pub investing: CashFlowSection,
    pub financing: CashFlowSection,
    pub exchange_effects: CashFlowSection,
    pub net_change: i128,
    pub closing: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneralLedgerCell {
    pub account_id: u128,
    pub unit_id: u32,
    pub opening: i128,
    pub debits: i128,
    pub credits: i128,
    pub net_change: i128,
    pub closing: i128,
    pub line_start: u32,
    pub line_end: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneralLedgerLine {
    pub cell_index: u32,
    pub entry_digest: [u8; 32],
    pub leg_index: u32,
    pub recorded_seq: u64,
    pub effective_day: i32,
    pub bucket_index: u32,
    pub debits: i128,
    pub credits: i128,
    pub running_balance: i128,
}

/// Complete selected native detail, including zero cells and effective-order
/// running balances. It makes no claim about contemporaneous recorded balances.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGeneralLedger {
    pub book_id: [u8; 16],
    pub known_at: u64,
    pub label: String,
    pub effective_from: i32,
    pub effective_through: i32,
    pub accounts: Vec<RollForwardAccount>,
    pub units: Vec<u32>,
    pub buckets: Vec<RollForwardBucket>,
    pub cells: Vec<GeneralLedgerCell>,
    pub lines: Vec<GeneralLedgerLine>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCashFlow {
    /// Digest of the independently recomputed roll-forward source.
    pub source_certificate_digest: [u8; 32],
    pub ledger: VerifiedGeneralLedger,
    pub definition: CashFlowDefinition,
    pub units: Vec<CashFlowUnit>,
    /// Present only when original counterpart payloads independently reproduce
    /// the policy's every decision. This does not establish policy approval.
    pub policy: Option<VerifiedCashFlowPolicy>,
}

pub(super) struct Certificate<'a> {
    pub source: &'a [u8],
    pub definition: CashFlowDefinition,
    pub output: &'a [u8],
    pub digest: [u8; 32],
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    recognizes_format(bytes, FORMAT)
}

pub(super) fn recognizes_format(bytes: &[u8], format: &[u8]) -> bool {
    bytes.starts_with(&(format.len() as u32).to_le_bytes())
        && bytes.get(4..4 + format.len()) == Some(format)
}

pub(super) fn body<'a>(
    bytes: &'a [u8],
    format: &[u8],
    domain: &[u8],
) -> Result<(Reader<'a>, [u8; 32]), ReportError> {
    if bytes.len() < 32 || bytes.len() > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed(
            "bounded_input",
            "cash certificate exceeds its byte bound",
        ));
    }
    let content = &bytes[..bytes.len() - 32];
    let digest = hash_parts(domain, &[&(content.len() as u32).to_le_bytes(), content]);
    if bytes[content.len()..] != digest {
        return Err(failed(
            "certificate_digest",
            "cash certificate digest differs",
        ));
    }
    let mut r = Reader::new(content);
    if r.bytes(64, "cash.certificate_format")? != format {
        return Err(failed(
            "supported_report",
            "unsupported cash certificate format",
        ));
    }
    Ok((r, digest))
}

pub(super) fn accounts(r: &mut Reader<'_>) -> Result<Vec<u128>, ReportError> {
    let count = r.count(MAX_ACCOUNTS, 16, "cash.accounts")?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(r.u128("cash.account")?);
    }
    if values.is_empty() || !values.windows(2).all(|p| p[0] < p[1]) {
        return Err(failed(
            "cash_flow_selection",
            "cash accounts are empty, repeated or unordered",
        ));
    }
    Ok(values)
}

pub(super) fn assignments(r: &mut Reader<'_>) -> Result<Vec<CashFlowAssignment>, ReportError> {
    let count = r.count(MAX_LINES, 37, "cash.assignments")?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(CashFlowAssignment {
            entry_digest: r.fixed("cash.assignment_entry")?,
            leg_index: r.u32("cash.assignment_leg")?,
            activity: CashFlowActivity::read(r)?,
        });
    }
    if !values
        .windows(2)
        .all(|p| assignment_key(&p[0]) < assignment_key(&p[1]))
    {
        return Err(failed(
            "cash_flow_classification",
            "cash assignments repeat a leg or are unordered",
        ));
    }
    Ok(values)
}

pub(super) fn assignment_key(a: &CashFlowAssignment) -> ([u8; 32], u32) {
    (a.entry_digest, a.leg_index)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    let (mut r, digest) = body(bytes, FORMAT, DIGEST_DOMAIN)?;
    let source = r.bytes(MAX_REPORT_BUNDLE_BYTES, "cash.roll_forward")?;
    if !super::roll_forward::recognizes(source) {
        return Err(failed(
            "supported_report",
            "cash flow requires a native roll-forward source",
        ));
    }
    let name = text(&mut r, 256, "cash.name")?.to_string();
    if name.trim().is_empty() {
        return Err(failed(
            "cash_flow_selection",
            "cash definition has an empty name",
        ));
    }
    let definition = CashFlowDefinition {
        name,
        cash_accounts: accounts(&mut r)?,
        assignments: assignments(&mut r)?,
    };
    let output = r.bytes(MAX_REPORT_BUNDLE_BYTES, "cash.output")?;
    r.finish("cash certificate")?;
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
        "cash-flow or ledger amount exceeds its exact native range",
    )
}

fn add(a: i128, b: i128) -> Result<i128, ReportError> {
    a.checked_add(b).ok_or_else(overflow)
}

fn subtract(a: i128, b: i128) -> Result<i128, ReportError> {
    a.checked_sub(b).ok_or_else(overflow)
}

fn ledger(mut source: VerifiedRollForward) -> Result<VerifiedGeneralLedger, ReportError> {
    if source.rows.len() > MAX_CELLS || source.movements.len() > MAX_LINES {
        return Err(failed(
            "bounded_input",
            "cash ledger exceeds 65,536 cells or 250,000 movements",
        ));
    }
    let mut indices = BTreeMap::new();
    let mut cells = Vec::with_capacity(source.rows.len());
    for row in source.rows {
        let index = cells.len();
        if indices
            .insert((row.account_id, row.unit_id), index)
            .is_some()
        {
            return Err(failed(
                "cash_flow_source",
                "cash ledger repeats a source cell",
            ));
        }
        cells.push(GeneralLedgerCell {
            account_id: row.account_id,
            unit_id: row.unit_id,
            opening: row.opening,
            debits: 0,
            credits: 0,
            net_change: row.net_change,
            closing: row.closing,
            line_start: 0,
            line_end: 0,
        });
    }
    let buckets: BTreeMap<_, _> = source
        .buckets
        .iter()
        .enumerate()
        .map(|(i, b)| (b, i))
        .collect();
    let mut seen = BTreeSet::new();
    for m in &source.movements {
        if !indices.contains_key(&(m.account_id, m.unit_id))
            || !buckets.contains_key(&m.bucket)
            || !seen.insert((m.entry_digest, m.leg_index))
            || m.recorded_seq == 0
            || m.recorded_seq > source.known_at
            || m.effective_day < source.effective_from
            || m.effective_day > source.effective_through
            || m.debits < 0
            || m.credits < 0
            || (m.debits > 0) == (m.credits > 0)
        {
            return Err(failed(
                "cash_flow_source",
                "cash movement has an invalid source citation",
            ));
        }
    }
    source.movements.sort_unstable_by_key(|m| {
        (
            indices[&(m.account_id, m.unit_id)],
            m.effective_day,
            m.recorded_seq,
            m.entry_digest,
            m.leg_index,
        )
    });
    let mut lines = Vec::with_capacity(source.movements.len());
    let mut movements = source.movements.into_iter().peekable();
    for (index, cell) in cells.iter_mut().enumerate() {
        cell.line_start = lines.len() as u32;
        let mut running = cell.opening;
        while movements
            .peek()
            .is_some_and(|m| (m.account_id, m.unit_id) == (cell.account_id, cell.unit_id))
        {
            let m = movements
                .next()
                .ok_or_else(|| failed("cash_flow_source", "cash movement is absent"))?;
            cell.debits = add(cell.debits, m.debits)?;
            cell.credits = add(cell.credits, m.credits)?;
            running = subtract(add(running, m.debits)?, m.credits)?;
            lines.push(GeneralLedgerLine {
                cell_index: index as u32,
                entry_digest: m.entry_digest,
                leg_index: m.leg_index,
                recorded_seq: m.recorded_seq,
                effective_day: m.effective_day,
                bucket_index: buckets[&m.bucket] as u32,
                debits: m.debits,
                credits: m.credits,
                running_balance: running,
            });
        }
        cell.line_end = lines.len() as u32;
        if subtract(cell.debits, cell.credits)? != cell.net_change
            || running != cell.closing
            || add(cell.opening, cell.net_change)? != cell.closing
        {
            return Err(failed(
                "cash_flow_source",
                "cash ledger does not reconcile to its independent stocks",
            ));
        }
    }
    if movements.next().is_some() {
        return Err(failed(
            "cash_flow_source",
            "cash ledger has unconsumed movements",
        ));
    }
    Ok(VerifiedGeneralLedger {
        book_id: source.book_id,
        known_at: source.known_at,
        label: source.label,
        effective_from: source.effective_from,
        effective_through: source.effective_through,
        accounts: source.accounts,
        units: source.units,
        buckets: source.buckets,
        cells,
        lines,
    })
}

#[derive(Default)]
struct Totals {
    opening: Sum,
    closing: Sum,
    sections: [CashFlowSection; 4],
}

fn classify(
    ledger: &VerifiedGeneralLedger,
    definition: &CashFlowDefinition,
) -> Result<Vec<CashFlowUnit>, ReportError> {
    let cash: BTreeSet<_> = definition.cash_accounts.iter().copied().collect();
    if cash.len() != ledger.accounts.len()
        || definition.assignments.len() != ledger.lines.len()
        || ledger
            .accounts
            .iter()
            .any(|a| !cash.contains(&a.id) || !a.is_leaf || !matches!(a.account_type, 1 | 2))
    {
        return Err(failed(
            "cash_flow_selection",
            "cash scope must exactly cover selected asset/overdraft leaves and every movement",
        ));
    }
    let mut assigned: BTreeMap<_, _> = definition
        .assignments
        .iter()
        .map(|a| (assignment_key(a), a.activity))
        .collect();
    let mut totals: BTreeMap<_, Totals> = ledger
        .units
        .iter()
        .map(|&u| (u, Totals::default()))
        .collect();
    for cell in &ledger.cells {
        let total = totals
            .get_mut(&cell.unit_id)
            .ok_or_else(|| failed("cash_flow_source", "cash stock names an undeclared unit"))?;
        total
            .opening
            .add(cell.opening, false)
            .ok_or_else(overflow)?;
        total
            .closing
            .add(cell.closing, false)
            .ok_or_else(overflow)?;
    }
    let mut groups: BTreeMap<([u8; 32], u32, CashFlowActivity), Sum> = BTreeMap::new();
    let mut transfers: BTreeMap<([u8; 32], u32), (Sum, BTreeSet<u128>)> = BTreeMap::new();
    for line in &ledger.lines {
        let cell = &ledger.cells[line.cell_index as usize];
        let activity = assigned
            .remove(&(line.entry_digest, line.leg_index))
            .ok_or_else(|| {
                failed(
                    "cash_flow_classification",
                    "a cash movement has no unique assignment",
                )
            })?;
        let sum = if activity == CashFlowActivity::InternalTransfer {
            let (sum, accounts) = transfers
                .entry((line.entry_digest, cell.unit_id))
                .or_default();
            accounts.insert(cell.account_id);
            sum
        } else {
            groups
                .entry((line.entry_digest, cell.unit_id, activity))
                .or_default()
        };
        sum.add(line.debits, false).ok_or_else(overflow)?;
        sum.add(line.credits, true).ok_or_else(overflow)?;
    }
    if !assigned.is_empty() {
        return Err(failed(
            "cash_flow_classification",
            "cash assignment names an unselected leg",
        ));
    }
    for (sum, accounts) in transfers.values() {
        if accounts.len() < 2 || sum.value() != Some(0) {
            return Err(failed(
                "cash_flow_transfers",
                "internal transfers must cancel within one entry and unit across distinct cash accounts",
            ));
        }
    }
    for ((_, unit, activity), sum) in groups {
        let net = sum.value().ok_or_else(overflow)?;
        let section = &mut totals
            .get_mut(&unit)
            .ok_or_else(|| failed("cash_flow_source", "cash movement names an undeclared unit"))?
            .sections[activity as usize];
        if net >= 0 {
            section.inflows = add(section.inflows, net)?;
        } else {
            section.outflows = add(section.outflows, net.checked_neg().ok_or_else(overflow)?)?;
        }
    }
    let mut units = Vec::with_capacity(totals.len());
    for (unit_id, mut total) in totals {
        let mut change = Sum::default();
        let opening = total.opening.value().ok_or_else(overflow)?;
        let closing = total.closing.value().ok_or_else(overflow)?;
        for section in &mut total.sections {
            section.net = subtract(section.inflows, section.outflows)?;
            change.add(section.net, false).ok_or_else(overflow)?;
        }
        let net_change = change.value().ok_or_else(overflow)?;
        let mut residual = change;
        residual.add(opening, false).ok_or_else(overflow)?;
        residual.add(closing, true).ok_or_else(overflow)?;
        if residual.value() != Some(0) {
            return Err(failed(
                "cash_flow_reconciliation",
                "classified activity differs from the change in independent cash stock",
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

pub(super) fn add_size(total: &mut usize, amount: usize) -> Result<(), ReportError> {
    *total = total
        .checked_add(amount)
        .filter(|n| *n <= MAX_REPORT_BUNDLE_BYTES)
        .ok_or_else(|| failed("bounded_output", "cash report exceeds 64 MiB"))?;
    Ok(())
}

pub(super) fn writer(size: usize) -> Result<Writer, ReportError> {
    let mut w = Writer::default();
    w.buf
        .try_reserve_exact(size)
        .map_err(|_| failed("bounded_output", "cannot reserve cash report output"))?;
    Ok(w)
}

fn ledger_bytes(ledger: &VerifiedGeneralLedger) -> Result<Vec<u8>, ReportError> {
    let mut size = 4 + LEDGER_FORMAT.len() + 16 + 16 + 8 + 4 + ledger.label.len() + 8;
    add_size(
        &mut size,
        5 * 4 + ledger.units.len() * 4 + ledger.cells.len() * 108 + ledger.lines.len() * 104,
    )?;
    for a in &ledger.accounts {
        add_size(&mut size, 16 + 4 + a.code.len() + 4 + a.name.len() + 2)?;
    }
    for b in &ledger.buckets {
        add_size(
            &mut size,
            2 + 4 + b.reason_code.len() + 1 + if b.rule_digest.is_some() { 32 } else { 0 },
        )?;
    }
    let mut w = writer(size)?;
    w.bytes(LEDGER_FORMAT)
        .fixed(&ledger.book_id)
        .fixed(&[0; 16])
        .u64(ledger.known_at)
        .bytes(ledger.label.as_bytes())
        .i32(ledger.effective_from)
        .i32(ledger.effective_through)
        .count(ledger.accounts.len());
    for a in &ledger.accounts {
        w.u128(a.id)
            .bytes(a.code.as_bytes())
            .bytes(a.name.as_bytes())
            .u8(a.account_type)
            .u8(u8::from(a.is_leaf));
    }
    w.count(ledger.units.len());
    for unit in &ledger.units {
        w.u32(*unit);
    }
    w.count(ledger.buckets.len());
    for b in &ledger.buckets {
        w.u16(b.class)
            .bytes(b.reason_code.as_bytes())
            .u8(u8::from(b.rule_digest.is_some()));
        if let Some(digest) = b.rule_digest {
            w.fixed(&digest);
        }
    }
    w.count(ledger.cells.len());
    for c in &ledger.cells {
        w.u128(c.account_id)
            .u32(c.unit_id)
            .i128(c.opening)
            .i128(c.debits)
            .i128(c.credits)
            .i128(c.net_change)
            .i128(c.closing)
            .u32(c.line_start)
            .u32(c.line_end);
    }
    w.count(ledger.lines.len());
    for line in &ledger.lines {
        w.u32(line.cell_index)
            .fixed(&line.entry_digest)
            .u32(line.leg_index)
            .u64(line.recorded_seq)
            .i32(line.effective_day)
            .u32(line.bucket_index)
            .i128(line.debits)
            .i128(line.credits)
            .i128(line.running_balance);
    }
    debug_assert_eq!(w.buf.len(), size);
    Ok(w.buf)
}

pub(super) fn write_assignments(w: &mut Writer, values: &[CashFlowAssignment]) {
    w.count(values.len());
    for a in values {
        w.fixed(&a.entry_digest)
            .u32(a.leg_index)
            .u8(a.activity as u8);
    }
}

fn output(report: &VerifiedCashFlow) -> Result<Vec<u8>, ReportError> {
    let ledger = ledger_bytes(&report.ledger)?;
    let d = &report.definition;
    let mut size = 4 + OUTPUT_FORMAT.len();
    add_size(
        &mut size,
        4 + ledger.len()
            + 4
            + d.name.len()
            + 4
            + d.cash_accounts.len() * 16
            + 4
            + d.assignments.len() * 37
            + 4
            + report.units.len() * 244,
    )?;
    let mut w = writer(size)?;
    w.bytes(OUTPUT_FORMAT)
        .bytes(&ledger)
        .bytes(d.name.as_bytes())
        .count(d.cash_accounts.len());
    for id in &d.cash_accounts {
        w.u128(*id);
    }
    write_assignments(&mut w, &d.assignments);
    w.count(report.units.len());
    for u in &report.units {
        w.u32(u.unit_id).i128(u.opening);
        for s in [u.operating, u.investing, u.financing, u.exchange_effects] {
            w.i128(s.inflows).i128(s.outflows).i128(s.net);
        }
        w.i128(u.net_change).i128(u.closing);
    }
    debug_assert_eq!(w.buf.len(), size);
    Ok(w.buf)
}

pub(super) fn replay(
    certificate: &Certificate<'_>,
    source: VerifiedRollForward,
    source_digest: [u8; 32],
) -> Result<(VerifiedCashFlow, Vec<u8>), ReportError> {
    let ledger = ledger(source)?;
    let units = classify(&ledger, &certificate.definition)?;
    let report = VerifiedCashFlow {
        source_certificate_digest: source_digest,
        ledger,
        definition: certificate.definition.clone(),
        units,
        policy: None,
    };
    let output = output(&report)?;
    if output != certificate.output {
        return Err(failed(
            "cash_flow_recomputation",
            "cash ledger, complete classifications, gross turnover, stocks or canonical bytes differ from independent replay",
        ));
    }
    Ok((report, output))
}
