//! Tie an effective-date open-item fold to its posting account (plan §5.6–§5.7).
//!
//! This is a selected-account consistency check, not an external subledger
//! attestation or an inference that an account is receivable/payable. Both
//! sides use one recorded prefix and one inclusive civil cutoff. Gross
//! journal turnover is NOT compared with residual open amounts: their net
//! debit balances must agree in EACH native unit. Reservations are shown
//! separately and never finance, settle, or change the posted comparison.
//! A discrepancy is returned as data; this reader never creates a correction.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_journal::rows::AccountRow;
use fa_journal::{KernelError, Refusal, exit};
use fa_money::UnitId;
use fa_policy::{Capability, Op};
use fa_registers::{RegisterError, TbRow, TrialBalance};
use fa_time::DateDay;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use super::{AgingAmounts, AgingBuckets, EffectiveDateAging, MAX_AGING_BUCKET_BOUNDS};
use crate::{AsyncBook, BookError, Outcome};

pub mod portfolio;

mod certificate;
pub use certificate::{
    AgingReconciliationCertificate, CertifiedAgingReconciliation, MAX_AGING_RECONCILIATION_BYTES,
};

/// The account is an explicit posting-leaf selection, not an access scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgingReconciliationRequest {
    pub account: VId,
    pub effective_through: DateDay,
    /// Resolve HEAD once for a new report. Saved/replayed requests are fixed.
    pub known_at: Option<CommitSeq>,
    pub buckets: AgingBuckets,
}

/// Positive net values mean debit balances, including on a credit-normal
/// account. All values are exact mantissas in this row's native unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgingReconciliationRow {
    pub unit_id: u32,
    pub posted_debits: i128,
    pub posted_credits: i128,
    pub pending_debits: i128,
    pub pending_credits: i128,
    pub open_debits: i128,
    pub open_credits: i128,
    pub open_item_count: u64,
    pub posted_net: i128,
    pub open_net: i128,
    /// posted_net - open_net. Never net differences across native units.
    pub difference: i128,
}

/// Immutable computed result. Source detail remains available for drilldown;
/// success means the comparison ran, not that all rows reconciled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgingReconciliation {
    account: AccountRow,
    aging: EffectiveDateAging,
    control_rows: Vec<TbRow>,
    rows: Vec<AgingReconciliationRow>,
}

impl AgingReconciliation {
    #[must_use]
    pub fn account(&self) -> &AccountRow {
        &self.account
    }
    #[must_use]
    pub fn aging(&self) -> &EffectiveDateAging {
        &self.aging
    }
    #[must_use]
    pub fn control_rows(&self) -> &[TbRow] {
        &self.control_rows
    }
    #[must_use]
    pub fn rows(&self) -> &[AgingReconciliationRow] {
        &self.rows
    }
    #[must_use]
    pub fn known_at(&self) -> CommitSeq {
        self.aging.known_at
    }
    #[must_use]
    pub fn effective_through(&self) -> DateDay {
        self.aging.effective_through
    }
    /// Only the explicitly named account, at this report's two coordinates.
    /// A valid empty account reconciles without inventing a currency row.
    #[must_use]
    pub fn is_reconciled(&self) -> bool {
        self.rows.iter().all(|row| row.difference == 0)
    }
}

fn selection_error(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §5.6–§5.7 (open-item and control balances share both time coordinates)",
        "select an existing posting account, a retained recorded sequence, an inclusive civil date and at most 128 strictly increasing age bounds",
    )
}

fn corruption(message: impl Into<String>) -> BookError {
    KernelError::Corrupt(message.into()).into()
}

/// Authority precedes frontier, chart, or financial data observation. Selecting
/// one account does not authorize a restricted caller to scan the whole book.
fn authorize<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    principal: VId,
    capability: &Capability,
    produce: bool,
) -> Outcome<CommitSeq> {
    let admitted =
        fa_policy::admit_read(capability, principal, book.context().book_id).and_then(|()| {
            if produce {
                fa_policy::require(
                    capability,
                    Op::Produce,
                    "certifying open-item reconciliation",
                )
            } else {
                Ok(())
            }
        });
    if let Err(denial) = admitted {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    let query = cx.query();
    query.checkpoint().map_err(BookError::Context)?;
    query.with_restriction(|| {
        let head = book.db.frontier().map_err(KernelError::from)?;
        if let Err(denial) = fa_policy::current(capability, head) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        if let Err(refusal) =
            fa_journal::policy::capability_admitted(&book.db, book.context(), capability)?
        {
            return Ok(Err(refusal));
        }
        Ok(Ok(head))
    })
}

fn fixed_request(
    request: &AgingReconciliationRequest,
    head: CommitSeq,
) -> Result<AgingReconciliationRequest, Refusal> {
    if request.buckets.upper_bounds().len() > MAX_AGING_BUCKET_BOUNDS {
        return Err(selection_error("too many finite aging bounds"));
    }
    let at = request.known_at.unwrap_or(head);
    if at > head {
        return Err(selection_error(
            "reconciliation known-at is beyond the book head",
        ));
    }
    Ok(AgingReconciliationRequest {
        known_at: Some(at),
        ..request.clone()
    })
}

fn selected_account<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    account: VId,
    at: CommitSeq,
) -> Outcome<AccountRow> {
    let query = cx.query();
    query.checkpoint().map_err(BookError::Context)?;
    query.with_restriction(|| {
        crate::certificate::context_at(&book.db, book.context(), at)?;
        // This comparison reads Account vertices, already inside both native
        // certificate closures. It does not depend on unauthenticated chart
        // hierarchy edges or reinterpret the selection as a subtree.
        let Some(row) = book
            .db
            .vertex_at(account, at)
            .map_err(KernelError::from)?
            .filter(|row| row.labels.contains(&fa_model::symbols::label::ACCOUNT))
        else {
            return Ok(Err(selection_error(
                "reconciliation account is absent at its selected prefix",
            )));
        };
        let selected = AccountRow::decode(&row)?;
        if AccountRow::vid_for(book.context().book_id, &selected.code) != account {
            return Err(corruption(
                "reconciliation account identity disagrees with its historical code",
            ));
        }
        if !selected.is_leaf {
            return Ok(Err(selection_error(
                "reconciliation requires a posting leaf, not a summary",
            )));
        }
        Ok(Ok(selected))
    })
}

fn assemble(
    account: AccountRow,
    aging: EffectiveDateAging,
    control: TrialBalance,
) -> Result<AgingReconciliation, BookError> {
    if !account.is_leaf
        || aging.account != Some(account.vid)
        || aging.known_at != control.known_at
        || control.activity
        || control.effective_through != Some(aging.effective_through)
    {
        return Err(corruption(
            "aging and control folds disagree on their selection",
        ));
    }
    let mut controls = BTreeMap::new();
    for row in control
        .rows
        .into_iter()
        .filter(|row| row.account == account.vid)
    {
        if row.code != account.code
            || row.name != account.name
            || row.account_type.0 != account.account_type
            || [
                row.debits,
                row.credits,
                row.debits_pending,
                row.credits_pending,
            ]
            .iter()
            .any(|n| *n < 0)
            || controls.insert(row.unit_id, row).is_some()
        {
            return Err(corruption("invalid or repeated control-account row"));
        }
    }
    let mut opens = BTreeMap::new();
    for total in &aging.totals {
        if total.account != account.vid
            || total.amounts.debits < 0
            || total.amounts.credits < 0
            || opens.insert(total.unit_id, &total.amounts).is_some()
        {
            return Err(corruption("invalid or repeated aging-account total"));
        }
    }
    let units: BTreeSet<_> = controls.keys().chain(opens.keys()).copied().collect();
    let mut rows = Vec::with_capacity(units.len());
    for unit_id in units {
        let source = controls.get(&unit_id);
        let empty = AgingAmounts::default();
        let open = opens.get(&unit_id).copied().unwrap_or(&empty);
        let posted_debits = source.map_or(0, |row| row.debits);
        let posted_credits = source.map_or(0, |row| row.credits);
        let posted_net = posted_debits
            .checked_sub(posted_credits)
            .ok_or(RegisterError::Overflow)?;
        let open_net = open
            .debits
            .checked_sub(open.credits)
            .ok_or(RegisterError::Overflow)?;
        let difference = posted_net
            .checked_sub(open_net)
            .ok_or(RegisterError::Overflow)?;
        rows.push(AgingReconciliationRow {
            unit_id,
            posted_debits,
            posted_credits,
            pending_debits: source.map_or(0, |row| row.debits_pending),
            pending_credits: source.map_or(0, |row| row.credits_pending),
            open_debits: open.debits,
            open_credits: open.credits,
            open_item_count: open.item_count,
            posted_net,
            open_net,
            difference,
        });
    }
    Ok(AgingReconciliation {
        account,
        aging,
        control_rows: controls.into_values().collect(),
        rows,
    })
}

fn validate_units(
    report: &AgingReconciliation,
    units: &fa_money::UnitRegistry,
) -> Result<(), BookError> {
    for row in &report.rows {
        if units.get(UnitId(row.unit_id)).is_none() {
            return Err(corruption(
                "reconciliation source has an unregistered native unit",
            ));
        }
    }
    Ok(())
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Compare the production historical open-item fold with the production
    /// stock trial balance, under current whole-book read authority. Neither
    /// today's mutable applied mirrors nor maintained register cells are used.
    /// A mismatching unit is data, not an automatic write or a false success.
    pub fn reconcile_effective_date_aging(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &AgingReconciliationRequest,
    ) -> Outcome<AgingReconciliation> {
        let head = match authorize(self, cx, principal, capability, false)? {
            Ok(head) => head,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let request = match fixed_request(request, head) {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let at = request.known_at.unwrap_or(head);
        let account = match selected_account(self, cx, request.account, at)? {
            Ok(account) => account,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let query = cx.query();
        let aging = match self.effective_date_aging(
            cx,
            Some(request.account),
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
        let report = assemble(account, aging, control)?;
        validate_units(&report, &self.context().units)?;
        query.checkpoint().map_err(BookError::Context)?;
        Ok(Ok(report))
    }
}

#[cfg(test)]
mod tests;
