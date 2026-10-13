//! Summary-account trial balances (plan §4.3/§5.6, fa-up7).
//!
//! A summary is a presentation of disjoint posting leaves, never another
//! posting or an authoritative register. Both the chart and the underlying
//! stock/activity fold are selected at one recorded frontier. Exact native
//! units and posted/pending columns stay separate; source leaf rows remain
//! available for drilldown. These reports do not claim to be certificates.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_journal::chart::ChartSnapshot;
use fa_journal::rows::AccountRow;
use fa_journal::{KernelError, LimitScope, Refusal, UnitPolicy, exit};
use fa_model::{AccountType, EncodeError, Id128, Writer};
use fa_policy::Capability;
use fa_registers::{RegisterError, TbRow, TrialBalance};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, BookError, Outcome, TrialBalanceSelection};

pub const OUTPUT_FORMAT: &[u8] = b"fa:summary-trial-balance:v1";

type Totals = BTreeMap<u32, (i128, i128)>;

/// Root selection is a presentation choice, NOT an authorization scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SummaryScope {
    /// Every top-level account in the historical forest. Covers every leaf
    /// exactly once, including standalone leaves and empty summaries.
    AllRoots,
    /// Disjoint subtrees or individual leaves. Repeated roots and any
    /// ancestor/descendant pair are refused. An empty vector selects none.
    Selected(Vec<VId>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SummaryRequest {
    pub selection: TrialBalanceSelection,
    pub scope: SummaryScope,
    /// None resolves HEAD once, before either chart or balance is read.
    pub known_at: Option<CommitSeq>,
}

/// One selected root and its exact leaf partition. An empty summary has
/// no leaf members and no invented currency row. Rows carry the root's
/// metadata, but their values are derived only from the listed leaves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SummaryGroup {
    pub account: AccountRow,
    /// Historical metadata, sorted by account code. Includes zero-activity
    /// leaves even when no source balance row exists for them.
    pub leaves: Vec<AccountRow>,
    /// One row per unit that actually occurs in the source leaf rows.
    pub rows: Vec<TbRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SummaryTrialBalance {
    pub book_id: Id128,
    /// The unchanged literal leaf fold, including its whole-book totals,
    /// effective selector and fixed known-at coordinate. It is drilldown,
    /// not an additional set of rows to add to the summary totals.
    pub source: TrialBalance,
    /// Sorted by root code, independent of requested root ordering.
    pub groups: Vec<SummaryGroup>,
    /// Every unselected posting leaf, including ones with no activity.
    /// A numerically balanced partial selection is not a complete book.
    pub uncovered_leaves: Vec<AccountRow>,
    /// Totals for the selected groups ONLY. Whole-book totals are in source.
    pub unit_totals: BTreeMap<u32, (i128, i128)>,
    pub pending_unit_totals: BTreeMap<u32, (i128, i128)>,
}

impl SummaryTrialBalance {
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.uncovered_leaves.is_empty()
    }

    /// Never present a balanced but partial subtree as a complete trial
    /// balance. The source retains the book's independent balance check.
    #[must_use]
    pub fn is_complete_and_balanced(&self) -> bool {
        self.is_complete()
            && self.source.is_balanced()
            && self.unit_totals == self.source.unit_totals
            && self.pending_unit_totals == self.source.pending_unit_totals
    }

    /// Exact deterministic report bytes, not a signature or certificate.
    /// Retain the source fold, group membership, all metadata and explicit
    /// uncovered leaves, so identical totals cannot hide changed membership.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(OUTPUT_FORMAT)
            .fixed(&self.book_id.0)
            .bytes(&self.source.canonical_bytes()?)
            .list(&self.groups, |w, group| {
                write_account(w, &group.account);
                w.list(&group.leaves, write_account)
                    .list(&group.rows, write_row);
            })
            .list(&self.uncovered_leaves, write_account);
        for totals in [&self.unit_totals, &self.pending_unit_totals] {
            let ordered: Vec<_> = totals.iter().collect();
            w.list(&ordered, |w, (unit, (debits, credits))| {
                w.u32(**unit).i128(*debits).i128(*credits);
            });
        }
        w.finish()
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Fold summary subtrees under the caller's query context and current
    /// whole-book read capability. Authorization precedes even frontier
    /// lookup. Selecting roots never authorizes reading a partial book:
    /// source contains the complete underlying leaf report.
    ///
    /// This uses the same book-scoped capability posture as the existing
    /// proof-export API. It creates no runtime, register, certificate or
    /// other journal object. Lifecycle edits beyond chart installation
    /// remain unsupported by the historical chart reader.
    pub fn summary_trial_balance(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &SummaryRequest,
    ) -> Outcome<SummaryTrialBalance> {
        let book = self.context();
        if let Err(denial) = fa_policy::admit_read(capability, principal, book.book_id) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        query.with_restriction(|| {
            let head = self.db.frontier().map_err(KernelError::from)?;
            if let Err(denial) = fa_policy::current(capability, head) {
                return Ok(Err(fa_journal::policy::refusal(&denial)));
            }
            if let Err(refusal) =
                fa_journal::policy::capability_admitted(&self.db, book, capability)?
            {
                return Ok(Err(refusal));
            }
            let at = request.known_at.unwrap_or(head);
            if at > head {
                return Ok(Err(selection_refusal(format!(
                    "known-at {} is beyond the book head {}",
                    at.0, head.0
                ))));
            }
            let chart = fa_journal::chart::read_at(&self.db, book, at)?;
            let roots = match selected_roots(&chart, &request.scope) {
                Ok(roots) => roots,
                Err(refusal) => return Ok(Err(refusal)),
            };
            query.checkpoint().map_err(BookError::Context)?;
            let source = match &request.selection {
                TrialBalanceSelection::Periods(periods) => {
                    fa_registers::trial_balance_at(&self.db, book, periods, Some(at))?
                }
                TrialBalanceSelection::AsOf(day) => {
                    fa_registers::balance_as_of(&self.db, book, *day, Some(at))?
                }
                TrialBalanceSelection::Activity(periods) => {
                    fa_registers::period_activity(&self.db, book, periods, Some(at))?
                }
            };
            for row in &source.rows {
                if book.units.get(fa_money::UnitId(row.unit_id)).is_none() {
                    return Err(KernelError::Corrupt(format!(
                        "summary source account `{}` has unknown unit {}",
                        row.code, row.unit_id
                    ))
                    .into());
                }
            }
            let report = aggregate(book.book_id, &chart, source, &roots)?;
            query.checkpoint().map_err(BookError::Context)?;
            Ok(Ok(report))
        })
    }
}

fn selection_refusal(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §4.3 / §5.6 (summary roots form a disjoint partition of posting leaves)",
        "select existing non-overlapping chart roots at an available known-at sequence, or use SummaryScope::AllRoots",
    )
}

fn selected_roots(chart: &ChartSnapshot, scope: &SummaryScope) -> Result<Vec<VId>, Refusal> {
    let roots = match scope {
        SummaryScope::AllRoots => chart
            .accounts()
            .values()
            .filter(|account| !chart.parents().contains_key(&account.vid))
            .map(|account| account.vid)
            .collect::<Vec<_>>(),
        SummaryScope::Selected(roots) => roots.clone(),
    };
    let mut selected = BTreeSet::new();
    for root in &roots {
        let account = chart.accounts().get(root).ok_or_else(|| {
            selection_refusal(format!(
                "account {:032x} is absent at sequence {}",
                root.0, chart.known_at().0
            ))
        })?;
        if !selected.insert(*root) {
            return Err(selection_refusal(format!(
                "account `{}` was selected more than once", account.code
            )));
        }
    }
    for root in &roots {
        let mut ancestor = chart.parents().get(root).copied();
        while let Some(parent) = ancestor {
            if selected.contains(&parent) {
                return Err(selection_refusal(format!(
                    "selected accounts `{}` and `{}` overlap: one is an ancestor of the other",
                    chart.accounts()[&parent].code, chart.accounts()[root].code
                )));
            }
            ancestor = chart.parents().get(&parent).copied();
        }
    }
    let mut roots = roots;
    roots.sort_by(|a, b| {
        chart.accounts()[a].code.cmp(&chart.accounts()[b].code).then(a.cmp(b))
    });
    Ok(roots)
}

fn corruption(message: impl Into<String>) -> RegisterError {
    KernelError::Corrupt(format!("summary trial balance: {}", message.into())).into()
}

fn add(values: &mut [i128; 4], row: &TbRow) -> Result<(), RegisterError> {
    for (slot, amount) in values.iter_mut().zip([
        row.debits, row.credits, row.debits_pending, row.credits_pending,
    ]) {
        if amount < 0 {
            return Err(corruption("negative gross debit or credit in source fold"));
        }
        *slot = slot.checked_add(amount).ok_or(RegisterError::Overflow)?;
    }
    Ok(())
}

fn totals(sums: &BTreeMap<u32, [i128; 4]>) -> (Totals, Totals) {
    (
        sums.iter().map(|(unit, v)| (*unit, (v[0], v[1]))).collect(),
        sums.iter().map(|(unit, v)| (*unit, (v[2], v[3]))).collect(),
    )
}

fn aggregate(
    book_id: Id128,
    chart: &ChartSnapshot,
    source: TrialBalance,
    roots: &[VId],
) -> Result<SummaryTrialBalance, RegisterError> {
    if chart.known_at() != source.known_at {
        return Err(corruption("chart and source use different historical frontiers"));
    }
    let mut groups = Vec::with_capacity(roots.len());
    let mut owners = BTreeMap::new();
    for (index, root) in roots.iter().enumerate() {
        let account = chart.accounts().get(root)
            .ok_or_else(|| corruption("selected root disappeared"))?.clone();
        let leaf_ids = chart.leaves_under(*root)?;
        let mut leaves = Vec::with_capacity(leaf_ids.len());
        for vid in leaf_ids {
            if owners.insert(vid, index).is_some() {
                return Err(corruption("a posting leaf belongs to two selected groups"));
            }
            leaves.push(chart.accounts()[&vid].clone());
        }
        leaves.sort_by(|a, b| a.code.cmp(&b.code));
        groups.push(SummaryGroup { account, leaves, rows: Vec::new() });
    }
    let mut all_sums: BTreeMap<u32, [i128; 4]> = BTreeMap::new();
    let mut selected_sums: BTreeMap<u32, [i128; 4]> = BTreeMap::new();
    let mut group_sums = vec![BTreeMap::<u32, [i128; 4]>::new(); groups.len()];
    let mut seen = BTreeSet::new();
    for row in &source.rows {
        let account = chart.accounts().get(&row.account).ok_or_else(|| {
            corruption(format!("source leaf `{}` is absent from the chart", row.code))
        })?;
        if !account.is_leaf || account.code != row.code || account.name != row.name
            || account.account_type != row.account_type.0
            || !seen.insert((row.account, row.unit_id))
        {
            return Err(corruption(format!(
                "duplicate, nonleaf or mismatched source row `{}`", row.code
            )));
        }
        add(all_sums.entry(row.unit_id).or_insert([0; 4]), row)?;
        if let Some(index) = owners.get(&row.account) {
            add(group_sums[*index].entry(row.unit_id).or_insert([0; 4]), row)?;
            add(selected_sums.entry(row.unit_id).or_insert([0; 4]), row)?;
        }
    }
    let (posted, pending) = totals(&all_sums);
    if posted != source.unit_totals || pending != source.pending_unit_totals {
        return Err(corruption("source rows do not reconcile to whole-book totals"));
    }
    for (group, sums) in groups.iter_mut().zip(group_sums) {
        group.rows = sums.into_iter().map(|(unit_id, v)| TbRow {
            account: group.account.vid,
            code: group.account.code.clone(),
            name: group.account.name.clone(),
            account_type: AccountType(group.account.account_type),
            unit_id,
            debits: v[0],
            credits: v[1],
            debits_pending: v[2],
            credits_pending: v[3],
        }).collect();
    }
    let mut uncovered_leaves: Vec<_> = chart.accounts().values()
        .filter(|account| account.is_leaf && !owners.contains_key(&account.vid))
        .cloned().collect();
    uncovered_leaves.sort_by(|a, b| a.code.cmp(&b.code));
    let (unit_totals, pending_unit_totals) = totals(&selected_sums);
    Ok(SummaryTrialBalance {
        book_id, source, groups, uncovered_leaves, unit_totals, pending_unit_totals,
    })
}

fn write_row(w: &mut Writer, row: &TbRow) {
    w.u128(row.account.0).str(&row.code).str(&row.name).u8(row.account_type.0)
        .u32(row.unit_id).i128(row.debits).i128(row.credits)
        .i128(row.debits_pending).i128(row.credits_pending);
}

fn write_account(w: &mut Writer, account: &AccountRow) {
    w.u128(account.vid.0).str(&account.code).str(&account.name)
        .u8(account.account_type).u8(account.normal_balance).bool(account.is_leaf);
    match account.unit_policy {
        UnitPolicy::Single(unit) => { w.u8(0).u32(unit.0); }
        UnitPolicy::AnyCurrency => { w.u8(1); }
        UnitPolicy::AnyUnit => { w.u8(2); }
    }
    w.opt(account.limit.as_ref(), |w, limit| {
        w.opt(limit.lower.as_ref(), |w, value| { w.i128(*value); })
            .opt(limit.upper.as_ref(), |w, value| { w.i128(*value); })
            .u8(match limit.scope { LimitScope::Lifetime => 0, LimitScope::Period => 1 });
    }).u64(account.created_at.0);
}

#[cfg(test)]
mod tests;
