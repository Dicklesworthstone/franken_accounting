//! General-ledger detail at one historical accounting coordinate (plan §15.3).
//!
//! A native roll-forward supplies the opening stock, complete posted movement
//! set and independently folded closing stock. This view orders those movements
//! by effective day, recorded sequence, entry digest and leg ordinal WITHIN each
//! account/unit, computes exact running balances, and reconciles every cell.
//! Pending reservations are not posted activity. Reversals are real movements;
//! nothing is netted away merely because the selected interval finishes at zero.
//!
//! Running balances are effective-date balances as known at the selected prefix,
//! not claims about the balance actually known on each movement's recorded day.
//! Entry digests/ordinals are drilldown citations. No protected text is opened.

pub mod cash_flow;
pub use cash_flow::{
    CASH_FLOW_FORMAT, CashFlow, CashFlowActivity, CashFlowAssignment, CashFlowDefinition,
    CashFlowSection, CashFlowUnit,
};

mod workpaper;
pub use workpaper::{CertifiedGeneralLedger, GENERAL_LEDGER_WORKPAPER_FORMAT};

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_journal::{Refusal, exit};
use fa_model::Id128;
use fa_policy::Capability;
use fa_statements::Account;
use fa_statements::roll_forward::{Bucket, RollForward};
use fa_time::DateDay;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, QueryCx, VId};

use crate::{AsyncBook, BookError, Outcome, RollForwardRequest};

pub const GENERAL_LEDGER_FORMAT: &str = "fa:general-ledger:v1";
pub const MAX_GENERAL_LEDGER_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_GENERAL_LEDGER_CELLS: usize = 65_536;
pub const MAX_GENERAL_LEDGER_LINES: usize = 250_000;

/// A selected account/unit, including cells with no movement and zero stock.
/// The line range is half-open in GeneralLedger::lines(). Amounts use the
/// debit-minus-credit convention, even for credit-normal accounts.
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

/// One original journal leg; opposing legs and net-zero entries remain visible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneralLedgerLine {
    pub cell_index: u32,
    pub entry_digest: [u8; 32],
    pub leg_index: u32,
    pub recorded_seq: u64,
    pub effective_day: DateDay,
    pub bucket_index: u32,
    pub debits: i128,
    pub credits: i128,
    pub running_balance: i128,
}

/// An immutable view built only by a native read or retained-history replay.
/// Its canonical bytes are an output transcript, NOT a standalone certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneralLedger {
    book_id: Id128,
    branch_id: Id128,
    known_at: CommitSeq,
    label: String,
    effective_from: DateDay,
    effective_through: DateDay,
    accounts: Vec<Account>,
    units: Vec<u32>,
    buckets: Vec<Bucket>,
    cells: Vec<GeneralLedgerCell>,
    lines: Vec<GeneralLedgerLine>,
}

impl GeneralLedger {
    #[must_use]
    pub fn book_id(&self) -> Id128 { self.book_id }
    #[must_use]
    pub fn branch_id(&self) -> Id128 { self.branch_id }
    #[must_use]
    pub fn known_at(&self) -> CommitSeq { self.known_at }
    #[must_use]
    pub fn label(&self) -> &str { &self.label }
    #[must_use]
    pub fn effective_from(&self) -> DateDay { self.effective_from }
    #[must_use]
    pub fn effective_through(&self) -> DateDay { self.effective_through }
    #[must_use]
    pub fn accounts(&self) -> &[Account] { &self.accounts }
    #[must_use]
    pub fn units(&self) -> &[u32] { &self.units }
    #[must_use]
    pub fn buckets(&self) -> &[Bucket] { &self.buckets }
    #[must_use]
    pub fn cells(&self) -> &[GeneralLedgerCell] { &self.cells }
    #[must_use]
    pub fn lines(&self) -> &[GeneralLedgerLine] { &self.lines }

    /// Classify an already admitted immutable cash-ledger snapshot without a
    /// second database read. Its original known-at coordinate and all source
    /// citations are retained. The query context supplies cancellation/budget,
    /// not authority over any additional data. No journal mutation occurs.
    pub fn classify_cash_flow(
        self, query: &QueryCx, definition: &CashFlowDefinition,
    ) -> Outcome<CashFlow> {
        cash_flow::project(self, definition, query)
    }

    /// A missing account/unit is outside the selected scope, NOT a zero cell.
    #[must_use]
    pub fn cell(&self, account: VId, unit: u32) -> Option<&GeneralLedgerCell> {
        self.cells.iter().find(|cell| cell.account_id == account.0 && cell.unit_id == unit)
    }

    /// Canonical bounded output. No partial bytes escape on size/allocation
    /// failure. This does not replace replay of the native source certificate.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut out = Bytes::default();
        out.string(GENERAL_LEDGER_FORMAT)?;
        out.add(&self.book_id.0)?;
        out.add(&self.branch_id.0)?;
        out.add(&self.known_at.0.to_le_bytes())?;
        out.string(&self.label)?;
        out.add(&self.effective_from.0.to_le_bytes())?;
        out.add(&self.effective_through.0.to_le_bytes())?;
        out.count(self.accounts.len())?;
        for account in &self.accounts {
            out.add(&account.id.to_le_bytes())?;
            out.string(&account.code)?;
            out.string(&account.name)?;
            out.add(&[account.account_type, u8::from(account.is_leaf)])?;
        }
        out.count(self.units.len())?;
        for unit in &self.units { out.add(&unit.to_le_bytes())?; }
        out.count(self.buckets.len())?;
        for bucket in &self.buckets {
            out.add(&bucket.class.0.to_le_bytes())?;
            out.string(&bucket.reason_code)?;
            match bucket.rule_digest {
                None => out.add(&[0])?,
                Some(digest) => { out.add(&[1])?; out.add(&digest)?; }
            }
        }
        out.count(self.cells.len())?;
        for cell in &self.cells {
            out.add(&cell.account_id.to_le_bytes())?;
            out.add(&cell.unit_id.to_le_bytes())?;
            for amount in [cell.opening, cell.debits, cell.credits, cell.net_change, cell.closing] {
                out.add(&amount.to_le_bytes())?;
            }
            out.add(&cell.line_start.to_le_bytes())?;
            out.add(&cell.line_end.to_le_bytes())?;
        }
        out.count(self.lines.len())?;
        for line in &self.lines {
            out.add(&line.cell_index.to_le_bytes())?;
            out.add(&line.entry_digest)?;
            out.add(&line.leg_index.to_le_bytes())?;
            out.add(&line.recorded_seq.to_le_bytes())?;
            out.add(&line.effective_day.0.to_le_bytes())?;
            out.add(&line.bucket_index.to_le_bytes())?;
            for amount in [line.debits, line.credits, line.running_balance] {
                out.add(&amount.to_le_bytes())?;
            }
        }
        Ok(out.0)
    }
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §12.1 / §15.3 (general-ledger detail must reconcile to native stock)",
        "re-read the original account/unit scope at a retained fixed prefix; narrow an excessive scope; do not insert a balancing line",
    )
}

fn length(current: usize, additional: usize) -> Result<usize, Refusal> {
    current.checked_add(additional).filter(|n| *n <= MAX_GENERAL_LEDGER_BYTES)
        .ok_or_else(|| invalid("general-ledger output exceeds its 64 MiB bound"))
}

#[derive(Default)]
struct Bytes(Vec<u8>);
impl Bytes {
    fn add(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        length(self.0.len(), bytes.len())?;
        self.0.try_reserve(bytes.len()).map_err(|_| invalid("cannot reserve general-ledger output"))?;
        self.0.extend_from_slice(bytes);
        Ok(())
    }
    fn count(&mut self, count: usize) -> Result<(), Refusal> {
        let count = u32::try_from(count).map_err(|_| invalid("general-ledger count exceeds its wire bound"))?;
        self.add(&count.to_le_bytes())
    }
    fn string(&mut self, value: &str) -> Result<(), Refusal> {
        self.count(value.len())?;
        self.add(value.as_bytes())
    }
}

fn add(left: i128, right: i128) -> Result<i128, Refusal> {
    left.checked_add(right).ok_or_else(|| invalid("general-ledger running balance or turnover exceeds i128"))
}

fn sub(left: i128, right: i128) -> Result<i128, Refusal> {
    left.checked_sub(right).ok_or_else(|| invalid("general-ledger running balance or turnover exceeds i128"))
}

enum ProjectionError { Refusal(Refusal), Book(BookError) }
impl From<Refusal> for ProjectionError { fn from(r: Refusal) -> Self { Self::Refusal(r) } }
impl From<BookError> for ProjectionError { fn from(e: BookError) -> Self { Self::Book(e) } }

fn project(mut source: RollForward, query: &QueryCx) -> Outcome<GeneralLedger> {
    query.checkpoint().map_err(BookError::Context)?;
    // The source is exclusively a native reader/replay result, never caller
    // supplied advice. Still reconcile independent stocks and defend indexing.
    if source.rows.len() > MAX_GENERAL_LEDGER_CELLS || source.movements.len() > MAX_GENERAL_LEDGER_LINES {
        return Ok(Err(invalid("general-ledger detail exceeds 65,536 cells or 250,000 lines; narrow the scope")));
    }
    let build = || -> Result<GeneralLedger, ProjectionError> {
        let mut cells = Vec::new();
        cells.try_reserve(source.rows.len()).map_err(|_| invalid("cannot reserve general-ledger cells"))?;
        let mut indexes = BTreeMap::new();
        for (ordinal, row) in source.rows.iter().enumerate() {
            if ordinal % 256 == 0 { query.checkpoint().map_err(BookError::Context)?; }
            let index = cells.len();
            if indexes.insert((row.account_id, row.unit_id), index).is_some() {
                return Err(invalid("native general-ledger scope repeats a cell").into());
            }
            cells.push(GeneralLedgerCell {
                account_id: row.account_id, unit_id: row.unit_id, opening: row.opening,
                debits: 0, credits: 0, net_change: row.net_change, closing: row.closing,
                line_start: 0, line_end: 0,
            });
        }
        let buckets: BTreeMap<_, _> = source.buckets.iter().cloned().enumerate()
            .map(|(index, bucket)| (bucket, index)).collect();
        let mut seen = BTreeSet::new();
        for (ordinal, movement) in source.movements.iter().enumerate() {
            if ordinal % 256 == 0 { query.checkpoint().map_err(BookError::Context)?; }
            if !indexes.contains_key(&(movement.account_id, movement.unit_id))
                || !buckets.contains_key(&movement.bucket)
                || !seen.insert((movement.entry_digest, movement.leg_index))
                || movement.recorded_seq == 0 || movement.recorded_seq > source.known_at
                || movement.effective_day < source.effective_from
                || movement.effective_day > source.effective_through
                || movement.debits < 0 || movement.credits < 0
                || (movement.debits > 0) == (movement.credits > 0)
            {
                return Err(invalid("native general-ledger movement has an invalid scope, citation or coordinate").into());
            }
        }
        query.checkpoint().map_err(BookError::Context)?;
        source.movements.sort_unstable_by_key(|m| (
            indexes[&(m.account_id, m.unit_id)], m.effective_day, m.recorded_seq,
            m.entry_digest, m.leg_index,
        ));
        query.checkpoint().map_err(BookError::Context)?;
        let mut lines = Vec::new();
        lines.try_reserve(source.movements.len()).map_err(|_| invalid("cannot reserve general-ledger lines"))?;
        let mut movements = source.movements.into_iter().peekable();
        for (index, cell) in cells.iter_mut().enumerate() {
            if index % 256 == 0 { query.checkpoint().map_err(BookError::Context)?; }
            cell.line_start = u32::try_from(lines.len()).map_err(|_| invalid("general-ledger line index overflow"))?;
            let mut running = cell.opening;
            while movements.peek().is_some_and(|m| (m.account_id, m.unit_id) == (cell.account_id, cell.unit_id)) {
                if lines.len() % 256 == 0 { query.checkpoint().map_err(BookError::Context)?; }
                let Some(m) = movements.next() else { return Err(invalid("general-ledger movement disappeared").into()); };
                cell.debits = add(cell.debits, m.debits)?;
                cell.credits = add(cell.credits, m.credits)?;
                running = sub(add(running, m.debits)?, m.credits)?;
                lines.push(GeneralLedgerLine {
                    cell_index: u32::try_from(index).map_err(|_| invalid("general-ledger cell index overflow"))?,
                    entry_digest: m.entry_digest, leg_index: m.leg_index,
                    recorded_seq: m.recorded_seq, effective_day: m.effective_day,
                    bucket_index: u32::try_from(buckets[&m.bucket]).map_err(|_| invalid("general-ledger bucket index overflow"))?,
                    debits: m.debits, credits: m.credits, running_balance: running,
                });
            }
            cell.line_end = u32::try_from(lines.len()).map_err(|_| invalid("general-ledger line index overflow"))?;
            if sub(cell.debits, cell.credits)? != cell.net_change || running != cell.closing
                || add(cell.opening, cell.net_change)? != cell.closing
            {
                return Err(invalid("general-ledger movements do not reconcile to the native opening and closing stocks").into());
            }
        }
        if movements.next().is_some() { return Err(invalid("unconsumed native general-ledger movements").into()); }
        Ok(GeneralLedger {
            book_id: source.book_id, branch_id: source.branch_id, known_at: CommitSeq(source.known_at),
            label: source.label, effective_from: source.effective_from, effective_through: source.effective_through,
            accounts: source.accounts, units: source.units, buckets: source.buckets, cells, lines,
        })
    };
    let result = build();
    query.checkpoint().map_err(BookError::Context)?;
    match result {
        Ok(report) => Ok(Ok(report)),
        Err(ProjectionError::Refusal(refusal)) => Ok(Err(refusal)),
        Err(ProjectionError::Book(error)) => Err(error),
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Read complete selected posted detail and exact running balances at one
    /// recorded prefix. The native reader applies CURRENT whole-book authority,
    /// historical chart membership and migration visibility. Inclusive effective
    /// dates and explicit account/unit scope match RollForwardRequest. No writes,
    /// private-text reads, invented entries or cross-unit totals are performed.
    pub fn general_ledger(
        &self, cx: &PurposeContexts, principal: VId, capability: &Capability,
        request: &RollForwardRequest,
    ) -> Outcome<GeneralLedger> {
        let source = match self.roll_forward(cx, principal, capability, request)? {
            Ok(source) => source, Err(refusal) => return Ok(Err(refusal)),
        };
        project(source, &cx.query())
    }

    /// Read and classify native cash movements under CURRENT read authority.
    /// The general-ledger reader pins one known-at prefix and supplies the
    /// independent opening/closing stocks. All selected accounts must be
    /// explicitly designated cash/equivalents/overdrafts in the definition.
    /// Missing, stale, duplicated or foreign leg classifications fail closed.
    ///
    /// Prepare assignments from `general_ledger` at a fixed `known_at`, or use
    /// `GeneralLedger::classify_cash_flow` to consume that exact admitted view
    /// without re-reading. Classifications are retained accounting assertions,
    /// not engine-certified GAAP/IFRS judgments. No writes or private-text reads
    /// occur, and native currencies are never netted together.
    pub fn cash_flow(
        &self, cx: &PurposeContexts, principal: VId, capability: &Capability,
        request: &RollForwardRequest, definition: &CashFlowDefinition,
    ) -> Outcome<CashFlow> {
        let source = match self.general_ledger(cx, principal, capability, request)? {
            Ok(source) => source, Err(refusal) => return Ok(Err(refusal)),
        };
        source.classify_cash_flow(&cx.query(), definition)
    }
}

#[cfg(test)]
mod tests;
