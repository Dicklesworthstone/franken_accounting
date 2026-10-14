//! Whole-selection aging/control reconciliation at ONE historical coordinate.
//!
//! A chart partition, one whole-book aging fold and one stock trial balance
//! replace a loop of independent account reads. Empty posting accounts remain
//! in the selection; omitted leaves remain explicit. A zero total cannot hide
//! offsetting differences between accounts or native units. This is an internal
//! consistency report, NOT an external subledger attestation or a close permit.

use fa_journal::chart::ChartSnapshot;
use fa_model::{Id128, Writer};

use super::*;
use crate::aging::{AgedOpenItem, AgingCell, AgingTotal};

pub const MAX_AGING_PORTFOLIO_ACCOUNTS: usize = 4096;
pub const MAX_AGING_PORTFOLIO_ROWS: usize = 100_000;
pub const MAX_AGING_PORTFOLIO_BYTES: usize = 64 * 1024 * 1024;
mod certificate;
pub use certificate::{AgingPortfolioCertificate, CertifiedAgingPortfolio};

const OUTPUT_FORMAT: &[u8] = b"fa:aging-portfolio:v1";

/// This is a report selection, never an authorization scope. AllPosting
/// includes every historical posting leaf, not just nonzero or AR/AP accounts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgingAccountScope {
    AllPosting,
    /// Order is immaterial; duplicates, summaries and unknown IDs are refused.
    /// An empty selection is allowed, but is not a complete nonempty chart.
    Selected(Vec<VId>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgingPortfolioRequest {
    pub scope: AgingAccountScope,
    pub effective_through: DateDay,
    /// None resolves HEAD once for the entire portfolio, not once per account.
    pub known_at: Option<CommitSeq>,
    pub buckets: AgingBuckets,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgingPortfolio {
    book_id: Id128,
    request: AgingPortfolioRequest,
    /// Code order, including selected zero-activity accounts.
    accounts: Vec<AgingReconciliation>,
    /// Every unselected posting leaf, including those with zero activity.
    uncovered: Vec<AccountRow>,
}

impl AgingPortfolio {
    #[must_use]
    pub fn book_id(&self) -> Id128 {
        self.book_id
    }
    #[must_use]
    pub fn request(&self) -> &AgingPortfolioRequest {
        &self.request
    }
    #[must_use]
    pub fn accounts(&self) -> &[AgingReconciliation] {
        &self.accounts
    }
    #[must_use]
    pub fn uncovered_accounts(&self) -> &[AccountRow] {
        &self.uncovered
    }
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.uncovered.is_empty()
    }
    /// Only selected cells; completeness is a separate question.
    #[must_use]
    pub fn is_reconciled(&self) -> bool {
        self.accounts.iter().all(AgingReconciliation::is_reconciled)
    }
    #[must_use]
    pub fn is_complete_and_reconciled(&self) -> bool {
        self.is_complete() && self.is_reconciled()
    }
    /// Pending holds remain visible even if the posted comparison is zero.
    /// This does NOT decide whether a period may legally close.
    #[must_use]
    pub fn has_pending_reservations(&self) -> bool {
        self.accounts
            .iter()
            .flat_map(|account| account.rows())
            .any(|row| row.pending_debits != 0 || row.pending_credits != 0)
    }

    /// Comparison bytes include the request, every selected cell, coverage,
    /// historical account presentation and the independent verdicts. Source
    /// item/application detail is available in accounts(); certificates retain
    /// the complete native sources rather than treating these bytes as proof.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut length = bounded([
            4,
            OUTPUT_FORMAT.len(),
            16,
            1,
            8,
            4,
            4,
            self.request.buckets.upper_bounds().len() * 4,
            4,
            4,
            4,
        ])?;
        if let AgingAccountScope::Selected(ids) = &self.request.scope {
            length = bounded([length, 4, ids.len() * 16])?;
        }
        for account in &self.accounts {
            length = bounded([
                length,
                account_size(account.account())?,
                4,
                account
                    .rows()
                    .len()
                    .checked_mul(156)
                    .ok_or_else(|| selection_error("portfolio row size overflow"))?,
            ])?;
        }
        for account in &self.uncovered {
            length = bounded([length, account_size(account)?])?;
        }
        let mut w = Writer::with_capacity(length);
        w.bytes(OUTPUT_FORMAT).fixed(&self.book_id.0);
        write_scope(&mut w, &self.request.scope);
        let at = self
            .request
            .known_at
            .ok_or_else(|| selection_error("portfolio has no fixed prefix"))?;
        w.u64(at.0)
            .i32(self.request.effective_through.0)
            .list(self.request.buckets.upper_bounds(), |w, bound| {
                w.u32(*bound);
            })
            .list(&self.accounts, |w, account| {
                write_account(w, account.account());
                w.list(account.rows(), |w, row| {
                    w.u32(row.unit_id)
                        .i128(row.posted_debits)
                        .i128(row.posted_credits)
                        .i128(row.pending_debits)
                        .i128(row.pending_credits)
                        .i128(row.open_debits)
                        .i128(row.open_credits)
                        .u64(row.open_item_count)
                        .i128(row.posted_net)
                        .i128(row.open_net)
                        .i128(row.difference);
                });
            })
            .list(&self.uncovered, write_account)
            .bool(self.is_complete())
            .bool(self.is_reconciled())
            .bool(self.is_complete_and_reconciled())
            .bool(self.has_pending_reservations());
        let bytes = w.finish().map_err(|e| selection_error(e.to_string()))?;
        if bytes.len() != length {
            return Err(selection_error(
                "portfolio output size disagrees with encoding",
            ));
        }
        Ok(bytes)
    }
}

fn bounded(parts: impl IntoIterator<Item = usize>) -> Result<usize, Refusal> {
    let length = parts
        .into_iter()
        .try_fold(0usize, |n, part| n.checked_add(part))
        .ok_or_else(|| selection_error("portfolio encoding size overflow"))?;
    if length > MAX_AGING_PORTFOLIO_BYTES {
        return Err(selection_error(
            "complete portfolio exceeds 64 MiB; no rows were truncated",
        ));
    }
    Ok(length)
}

fn account_size(account: &AccountRow) -> Result<usize, Refusal> {
    bounded([16, 4, account.code.len(), 4, account.name.len(), 1, 1, 1, 8])
}

fn write_account(w: &mut Writer, a: &AccountRow) {
    w.u128(a.vid.0)
        .str(&a.code)
        .str(&a.name)
        .u8(a.account_type)
        .u8(a.normal_balance)
        .bool(a.is_leaf)
        .u64(a.created_at.0);
}

fn write_scope(w: &mut Writer, scope: &AgingAccountScope) {
    match scope {
        AgingAccountScope::AllPosting => {
            w.u8(0);
        }
        AgingAccountScope::Selected(ids) => {
            w.u8(1).list(ids, |w, id| {
                w.u128(id.0);
            });
        }
    }
}

fn normalize(
    request: &AgingPortfolioRequest,
    head: CommitSeq,
) -> Result<AgingPortfolioRequest, Refusal> {
    if request.buckets.upper_bounds().len() > MAX_AGING_BUCKET_BOUNDS {
        return Err(selection_error("too many finite portfolio aging bounds"));
    }
    let at = request.known_at.unwrap_or(head);
    if at > head {
        return Err(selection_error(
            "portfolio known-at is beyond the book head",
        ));
    }
    let scope = match &request.scope {
        AgingAccountScope::AllPosting => AgingAccountScope::AllPosting,
        AgingAccountScope::Selected(ids) => {
            if ids.len() > MAX_AGING_PORTFOLIO_ACCOUNTS {
                return Err(selection_error("portfolio selects more than 4096 accounts"));
            }
            let mut ids = ids.clone();
            ids.sort();
            if ids.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(selection_error(
                    "portfolio repeats an account; select each posting leaf once",
                ));
            }
            AgingAccountScope::Selected(ids)
        }
    };
    Ok(AgingPortfolioRequest {
        scope,
        known_at: Some(at),
        ..request.clone()
    })
}

fn selected(chart: &ChartSnapshot, scope: &AgingAccountScope) -> Result<BTreeSet<VId>, Refusal> {
    if chart.accounts().len() > MAX_AGING_PORTFOLIO_ACCOUNTS {
        return Err(selection_error(
            "historical chart exceeds the 4096-account portfolio bound",
        ));
    }
    match scope {
        AgingAccountScope::AllPosting => Ok(chart
            .accounts()
            .values()
            .filter(|a| a.is_leaf)
            .map(|a| a.vid)
            .collect()),
        AgingAccountScope::Selected(ids) => {
            for id in ids {
                if !chart.accounts().get(id).is_some_and(|a| a.is_leaf) {
                    return Err(selection_error(
                        "portfolio selection names a missing or summary account",
                    ));
                }
            }
            Ok(ids.iter().copied().collect())
        }
    }
}

#[derive(Default)]
struct Partition {
    items: Vec<AgedOpenItem>,
    cells: Vec<AgingCell>,
    totals: Vec<AgingTotal>,
    control: Vec<TbRow>,
}

fn leaf<'a>(
    accounts: &'a BTreeMap<VId, AccountRow>,
    id: VId,
    unit: u32,
    units: &fa_money::UnitRegistry,
) -> Result<&'a AccountRow, BookError> {
    let account = accounts
        .get(&id)
        .filter(|a| a.is_leaf)
        .ok_or_else(|| corruption("portfolio source names an absent or summary account"))?;
    if units.get(UnitId(unit)).is_none() {
        return Err(corruption(
            "portfolio source names an unregistered native unit",
        ));
    }
    Ok(account)
}

/// Both folds are consumed and partitioned once. No per-account journal scan,
/// and no full source clone per account. Bounds apply even to omitted rows;
/// omission is never a way to hide malformed source data or bypass a limit.
fn partition(
    book_id: Id128,
    request: AgingPortfolioRequest,
    chart: &BTreeMap<VId, AccountRow>,
    chosen: &BTreeSet<VId>,
    aging: EffectiveDateAging,
    control: TrialBalance,
    units: &fa_money::UnitRegistry,
) -> Outcome<AgingPortfolio> {
    if aging.book_id != book_id
        || aging.account.is_some()
        || Some(aging.known_at) != request.known_at
        || control.known_at != aging.known_at
        || aging.effective_through != request.effective_through
        || control.activity
        || control.effective_through != Some(request.effective_through)
        || aging.bands != request.buckets.bands()
    {
        return Err(corruption(
            "portfolio sources disagree on book, coordinates or buckets",
        ));
    }
    let row_count = [
        aging.items.len(),
        aging.cells.len(),
        aging.totals.len(),
        control.rows.len(),
    ]
    .into_iter()
    .chain(aging.items.iter().map(|row| row.item.applications.len()))
    .try_fold(0usize, |sum, n| sum.checked_add(n));
    if row_count.is_none_or(|n| n > MAX_AGING_PORTFOLIO_ROWS) {
        return Ok(Err(selection_error(
            "complete portfolio source exceeds 100000 detail rows",
        )));
    }
    let mut parts: BTreeMap<VId, Partition> = chosen
        .iter()
        .map(|id| (*id, Partition::default()))
        .collect();
    let mut seen = BTreeSet::new();
    for row in control.rows {
        let account = leaf(chart, row.account, row.unit_id, units)?;
        if account.code != row.code
            || account.name != row.name
            || account.account_type != row.account_type.0
            || [
                row.debits,
                row.credits,
                row.debits_pending,
                row.credits_pending,
            ]
            .iter()
            .any(|n| *n < 0)
            || !seen.insert((row.account, row.unit_id))
        {
            return Err(corruption("invalid or repeated portfolio control row"));
        }
        if let Some(part) = parts.get_mut(&row.account) {
            part.control.push(row);
        }
    }
    seen.clear();
    for row in aging.totals {
        leaf(chart, row.account, row.unit_id, units)?;
        if row.amounts.debits < 0
            || row.amounts.credits < 0
            || !seen.insert((row.account, row.unit_id))
        {
            return Err(corruption("invalid or repeated portfolio aging total"));
        }
        if let Some(part) = parts.get_mut(&row.account) {
            part.totals.push(row);
        }
    }
    let mut cells = BTreeSet::new();
    for row in aging.cells {
        leaf(chart, row.account, row.unit_id, units)?;
        if row.bucket >= aging.bands.len()
            || row.amounts.debits < 0
            || row.amounts.credits < 0
            || !cells.insert((row.account, row.unit_id, row.bucket))
        {
            return Err(corruption("invalid or repeated portfolio aging cell"));
        }
        if let Some(part) = parts.get_mut(&row.account) {
            part.cells.push(row);
        }
    }
    let mut items = BTreeSet::new();
    for row in aging.items {
        leaf(chart, row.item.account, row.item.unit_id, units)?;
        if row.bucket >= aging.bands.len()
            || row.item.open <= 0
            || !items.insert((row.item.entry, row.item.ordinal))
        {
            return Err(corruption("invalid or repeated portfolio open item"));
        }
        if let Some(part) = parts.get_mut(&row.item.account) {
            part.items.push(row);
        }
    }
    let mut accounts = Vec::with_capacity(chosen.len());
    let mut uncovered = Vec::new();
    for a in chart.values().filter(|a| a.is_leaf) {
        if let Some(part) = parts.remove(&a.vid) {
            let source = EffectiveDateAging {
                book_id,
                account: Some(a.vid),
                known_at: aging.known_at,
                effective_through: request.effective_through,
                bands: aging.bands.clone(),
                items: part.items,
                cells: part.cells,
                totals: part.totals,
            };
            // assemble uses the selected control rows, not whole-book totals.
            let control = TrialBalance {
                known_at: aging.known_at,
                effective_through: Some(request.effective_through),
                activity: false,
                periods: Vec::new(),
                rows: part.control,
                unit_totals: BTreeMap::new(),
                pending_unit_totals: BTreeMap::new(),
            };
            accounts.push(assemble(a.clone(), source, control)?);
        } else {
            uncovered.push(a.clone());
        }
    }
    if !parts.is_empty() {
        return Err(corruption("portfolio lost a selected historical account"));
    }
    accounts.sort_by(|a, b| a.account().code.cmp(&b.account().code));
    uncovered.sort_by(|a, b| a.code.cmp(&b.code));
    let result = AgingPortfolio {
        book_id,
        request,
        accounts,
        uncovered,
    };
    if let Err(r) = result.canonical_bytes() {
        return Ok(Err(r));
    }
    Ok(Ok(result))
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Current whole-book read authority precedes all observation. One fixed
    /// chart, one whole-book aging fold and one stock trial balance feed every
    /// comparison. No rows are published, retained or silently truncated.
    pub fn reconcile_aging_portfolio(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &AgingPortfolioRequest,
    ) -> Outcome<AgingPortfolio> {
        let head = match authorize(self, cx, principal, capability, false)? {
            Ok(head) => head,
            Err(r) => return Ok(Err(r)),
        };
        let request = match normalize(request, head) {
            Ok(r) => r,
            Err(r) => return Ok(Err(r)),
        };
        let at = request.known_at.unwrap_or(head);
        let query = cx.query();
        let chart = query.with_restriction(|| {
            crate::certificate::context_at(&self.db, self.context(), at)?;
            fa_journal::chart::read_at(&self.db, self.context(), at).map_err(BookError::from)
        })?;
        let chosen = match selected(&chart, &request.scope) {
            Ok(ids) => ids,
            Err(r) => return Ok(Err(r)),
        };
        query.checkpoint().map_err(BookError::Context)?;
        let aging = match self.effective_date_aging(
            cx,
            None,
            request.effective_through,
            Some(at),
            &request.buckets,
        ) {
            Ok(report) => report,
            Err(BookError::Registers(RegisterError::InvalidSelection(message))) => {
                return Ok(Err(selection_error(message)));
            }
            Err(error) => return Err(error),
        };
        query.checkpoint().map_err(BookError::Context)?;
        let control = query.with_restriction(|| {
            fa_registers::balance_as_of(
                &self.db,
                self.context(),
                request.effective_through,
                Some(at),
            )
        })?;
        let result = partition(
            self.context().book_id,
            request,
            chart.accounts(),
            &chosen,
            aging,
            control,
            &self.context().units,
        )?;
        query.checkpoint().map_err(BookError::Context)?;
        Ok(result)
    }
}

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
