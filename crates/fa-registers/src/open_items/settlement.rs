//! Read-only settlement planning over the authoritative open-item fold.
//!
//! A caller explicitly selects the eligible legs (for example, one customer's
//! invoices). Allocation is oldest-effective-date first, with stable identity
//! tie breakers. It never silently spends a receipt against another customer,
//! another account, another unit or another debit/credit direction.
//!
//! A plan is not a posted entry, an authorization or an idempotency receipt.
//! Posting must still use the journal kernel's normal identity, policy and
//! concurrency checks. Refresh and revalidate the plan under that write path;
//! validation against an earlier snapshot is not a lock on the database.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::UnitPolicy;
use fa_journal::genesis::BookContext;
use fa_model::{EncodeError, Writer};
use fa_money::Side;
use fa_time::DateDay;
use fgdb::Database;
use fgdb_types::{CommitSeq, VId};

use super::{OpenItem, OpenItemsReport, open_items_report};
use crate::RegisterError;

/// An explicit, single-account, single-unit payment allocation request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementRequest {
    /// The receivable or payable account, not the cash offset account.
    pub account: VId,
    /// Exact unit of every target and of the applying leg; no conversion occurs.
    pub unit_id: u32,
    /// Side of the applying leg. Eligible items must have the opposite side.
    pub side: Side,
    /// Positive integer mantissa of the available receipt or payment.
    pub amount: i128,
    /// A payment cannot settle an item effective after this date.
    pub effective_date: DateDay,
    /// Explicit eligible entry/leg identities. Duplicates and unknown legs fail.
    /// Input order does not change the allocation order.
    pub targets: Vec<(VId, u16)>,
}

/// One proposed application, retaining its observed open-amount witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementAllocation {
    /// Entry containing the target leg.
    pub entry: VId,
    /// Ordinal of the target leg within its entry.
    pub ordinal: u16,
    /// Exact positive amount to apply.
    pub amount: i128,
    /// Open amount observed in the source snapshot.
    pub open_before: i128,
    /// Open amount if this application is accepted by the journal kernel.
    pub open_after: i128,
}

/// Deterministic allocation advice, bound to one known-at coordinate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementPlan {
    /// Snapshot used for every target and its account metadata.
    pub known_at: CommitSeq,
    /// The request with its target identities sorted into canonical order.
    pub request: SettlementRequest,
    /// Positive applications in oldest-effective-date-first order.
    pub allocations: Vec<SettlementAllocation>,
    /// Receipt/payment amount left over, never silently written off or netted.
    pub unapplied: i128,
}

impl SettlementPlan {
    /// Bind the request, snapshot, allocation order and exact before/after
    /// mantissas. These are plan bytes, not a posted-entry certificate.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(b"fa:settlement-plan:v1")
            .u64(self.known_at.0)
            .u128(self.request.account.0)
            .u32(self.request.unit_id)
            .u8(crate::report::side(self.request.side))
            .i128(self.request.amount)
            .i32(self.request.effective_date.0)
            .list(&self.request.targets, |w, (entry, ordinal)| {
                w.u128(entry.0).u16(*ordinal);
            })
            .list(&self.allocations, |w, allocation| {
                w.u128(allocation.entry.0)
                    .u16(allocation.ordinal)
                    .i128(allocation.amount)
                    .i128(allocation.open_before)
                    .i128(allocation.open_after);
            })
            .i128(self.unapplied);
        w.finish()
    }

    /// Reject stale or altered advice by recomputing it against a fresh report.
    /// Even an unrelated commit advances the snapshot and requires replanning.
    /// Callers must still use the kernel's atomic posting checks after this.
    pub fn validate_against(&self, report: &OpenItemsReport) -> Result<(), RegisterError> {
        if self.known_at != report.known_at {
            return Err(invalid(
                "settlement plan snapshot is stale; refresh and replan",
            ));
        }
        if report.plan_settlement(&self.request)? != *self {
            return Err(invalid(
                "settlement plan no longer matches its open-item witnesses",
            ));
        }
        Ok(())
    }
}

/// A reusable identity lookup borrowing one immutable open-item report.
///
/// Building the index checks duplicate identities once. Planning many requests
/// then looks up only their explicit targets instead of indexing the entire
/// report again for each request. The borrow prevents the report's items,
/// account metadata or known-at coordinate from changing beneath the lookup.
/// This is neither authority nor a capacity reservation: independent requests
/// can still select the same item. Atomic group callers must enforce disjoint
/// selections and use the normal posting kernel for publication.
#[derive(Debug)]
pub struct SettlementIndex<'a> {
    report: &'a OpenItemsReport,
    by_identity: BTreeMap<(VId, u16), &'a OpenItem>,
}

impl OpenItemsReport {
    /// Build a reusable lookup for explicit allocations at this exact snapshot.
    /// No open-item or application-history payload is cloned into the index.
    pub fn settlement_index(&self) -> Result<SettlementIndex<'_>, RegisterError> {
        let mut by_identity = BTreeMap::new();
        for item in &self.items {
            if by_identity
                .insert((item.entry, item.ordinal), item)
                .is_some()
            {
                return Err(invalid(
                    "open-item report contains a duplicate entry/leg identity",
                ));
            }
        }
        Ok(SettlementIndex {
            report: self,
            by_identity,
        })
    }

    /// Allocate against explicitly eligible legs without mutating the report.
    /// All selected legs are validated before allocation, including targets
    /// beyond the point where the payment would have been exhausted.
    pub fn plan_settlement(
        &self,
        request: &SettlementRequest,
    ) -> Result<SettlementPlan, RegisterError> {
        self.validate_settlement_request(request)?;
        self.settlement_index()?.plan_validated(request)
    }

    fn validate_settlement_request(
        &self,
        request: &SettlementRequest,
    ) -> Result<(), RegisterError> {
        if request.amount <= 0 {
            return Err(invalid("settlement amount must be positive"));
        }
        if request.targets.is_empty() {
            return Err(invalid(
                "settlement requires explicitly selected target legs",
            ));
        }
        if self
            .account_filter
            .is_some_and(|account| account != request.account)
        {
            return Err(invalid(
                "settlement account differs from the report account filter",
            ));
        }
        let account = self
            .accounts
            .get(&request.account)
            .ok_or_else(|| invalid("settlement account is absent from the report snapshot"))?;
        if account.vid != request.account || !account.is_leaf || account.created_at > self.known_at
        {
            return Err(invalid(
                "settlement account metadata is invalid for this snapshot",
            ));
        }
        if let UnitPolicy::Single(unit) = account.unit_policy
            && unit.0 != request.unit_id
        {
            return Err(invalid(
                "settlement unit differs from the account unit policy",
            ));
        }

        Ok(())
    }
}

impl SettlementIndex<'_> {
    /// Allocate with the same validation and exact oldest-first semantics as
    /// OpenItemsReport::plan_settlement, reusing the report-wide identity map.
    /// Every target is checked on every call, including unused/exhausted ones.
    pub fn plan_settlement(
        &self,
        request: &SettlementRequest,
    ) -> Result<SettlementPlan, RegisterError> {
        self.report.validate_settlement_request(request)?;
        self.plan_validated(request)
    }

    fn plan_validated(&self, request: &SettlementRequest) -> Result<SettlementPlan, RegisterError> {
        let mut targets = BTreeSet::new();
        let mut eligible = Vec::new();
        for identity in &request.targets {
            if !targets.insert(*identity) {
                return Err(invalid("settlement request contains a duplicate target"));
            }
            let item = self.by_identity.get(identity).copied().ok_or_else(|| {
                invalid(format!(
                    "unknown settlement target {:032x}/{}",
                    identity.0.0, identity.1
                ))
            })?;
            validate_target(item, request, self.report.known_at)?;
            eligible.push(item);
        }
        eligible.sort_by_key(|item| {
            (
                item.effective_date.0,
                item.recorded_at,
                item.entry,
                item.ordinal,
            )
        });

        let mut remaining = request.amount;
        let mut allocations = Vec::new();
        for item in eligible {
            if remaining == 0 {
                break;
            }
            let amount = remaining.min(item.open);
            if amount == 0 {
                continue;
            }
            remaining = remaining
                .checked_sub(amount)
                .ok_or(RegisterError::Overflow)?;
            let open_after = item
                .open
                .checked_sub(amount)
                .ok_or(RegisterError::Overflow)?;
            allocations.push(SettlementAllocation {
                entry: item.entry,
                ordinal: item.ordinal,
                amount,
                open_before: item.open,
                open_after,
            });
        }
        let mut canonical_request = request.clone();
        canonical_request.targets = targets.into_iter().collect();
        Ok(SettlementPlan {
            known_at: self.report.known_at,
            request: canonical_request,
            allocations,
            unapplied: remaining,
        })
    }
}

fn invalid(message: impl Into<String>) -> RegisterError {
    RegisterError::InvalidSelection(message.into())
}

fn validate_target(
    item: &OpenItem,
    request: &SettlementRequest,
    known_at: CommitSeq,
) -> Result<(), RegisterError> {
    if item.account != request.account || item.unit_id != request.unit_id {
        return Err(invalid(
            "settlement target crosses an account or unit boundary",
        ));
    }
    if item.side == request.side {
        return Err(invalid(
            "settlement target must have the opposite debit/credit side",
        ));
    }
    if item.recorded_at > known_at || item.effective_date.0 > request.effective_date.0 {
        return Err(invalid(
            "settlement target is outside the snapshot or payment effective date",
        ));
    }
    if [item.original, item.applied, item.applied_out, item.open]
        .iter()
        .any(|amount| *amount < 0)
    {
        return Err(invalid("settlement target has a negative amount witness"));
    }
    let expected_open = item
        .original
        .checked_sub(item.applied_out)
        .and_then(|amount| amount.checked_sub(item.applied))
        .ok_or(RegisterError::Overflow)?;
    if expected_open != item.open {
        return Err(invalid(
            "settlement target open amount disagrees with its application fold",
        ));
    }
    let mut applied = 0_i128;
    for application in &item.applications {
        if application.amount < 0
            || application.recorded_at > known_at
            || application.recorded_at < item.recorded_at
        {
            return Err(invalid(
                "settlement target has an invalid application history",
            ));
        }
        if application.live {
            applied = applied
                .checked_add(application.amount)
                .ok_or(RegisterError::Overflow)?;
        }
    }
    if applied != item.applied {
        return Err(invalid(
            "settlement target applied amount disagrees with its live history",
        ));
    }
    Ok(())
}

/// Read a book's authoritative open-item fold at one resolved snapshot, then
/// plan without performing a write. A requested historical snapshot is honored.
pub fn plan_settlement<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    request: &SettlementRequest,
    known_at: Option<CommitSeq>,
) -> Result<SettlementPlan, RegisterError> {
    open_items_report(db, book, Some(request.account), known_at)?.plan_settlement(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::open_items::Application;
    use fa_journal::rows::AccountRow;
    use fa_money::UnitId;

    fn item(entry: u128, day: i32, amount: i128) -> OpenItem {
        OpenItem {
            entry: VId(entry),
            ordinal: 0,
            account: VId(9),
            unit_id: 1,
            side: Side::Debit,
            effective_date: DateDay(day),
            recorded_at: CommitSeq(2),
            original: amount,
            applied: 0,
            applied_out: 0,
            open: amount,
            applications: Vec::new(),
        }
    }

    fn report() -> OpenItemsReport {
        let account = AccountRow {
            vid: VId(9),
            code: "AR".into(),
            name: "Receivables".into(),
            account_type: 1,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(UnitId(1)),
            limit: None,
            created_at: CommitSeq(1),
        };
        OpenItemsReport {
            known_at: CommitSeq(10),
            account_filter: Some(account.vid),
            accounts: BTreeMap::from([(account.vid, account)]),
            items: vec![item(11, 10, 100), item(12, 20, 200)],
        }
    }

    fn request(amount: i128) -> SettlementRequest {
        SettlementRequest {
            account: VId(9),
            unit_id: 1,
            side: Side::Credit,
            amount,
            effective_date: DateDay(30),
            targets: vec![(VId(12), 0), (VId(11), 0)],
        }
    }

    #[test]
    fn partial_payment_is_oldest_first_and_never_mutates_the_inputs() {
        let report = report();
        let request = request(250);
        let before = (report.clone(), request.clone());
        let plan = report.plan_settlement(&request).unwrap();
        assert_eq!(plan.known_at, report.known_at);
        assert_eq!(plan.unapplied, 0);
        assert_eq!(
            plan.allocations,
            vec![
                SettlementAllocation {
                    entry: VId(11),
                    ordinal: 0,
                    amount: 100,
                    open_before: 100,
                    open_after: 0,
                },
                SettlementAllocation {
                    entry: VId(12),
                    ordinal: 0,
                    amount: 150,
                    open_before: 200,
                    open_after: 50,
                },
            ]
        );
        assert_eq!((report, request), before);
    }

    #[test]
    fn overpayment_remains_explicit_and_unselected_items_are_untouched() {
        let mut report = report();
        report.items.push(item(13, 1, 999));
        let plan = report.plan_settlement(&request(500)).unwrap();
        assert_eq!(plan.unapplied, 200);
        assert_eq!(plan.allocations.len(), 2);
        assert!(
            plan.allocations
                .iter()
                .all(|allocation| allocation.entry != VId(13))
        );
    }

    #[test]
    fn permutations_have_identical_plans_and_canonical_bytes() {
        let mut report = report();
        let mut request = request(150);
        let first = report.plan_settlement(&request).unwrap();
        report.items.reverse();
        request.targets.reverse();
        let second = report.plan_settlement(&request).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.canonical_bytes().unwrap(),
            second.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn equal_dates_break_ties_by_commit_entry_and_ordinal() {
        let mut report = report();
        report.items[1].effective_date = DateDay(10);
        report.items[0].recorded_at = CommitSeq(3);
        let plan = report.plan_settlement(&request(50)).unwrap();
        assert_eq!(plan.allocations[0].entry, VId(12));
        report.items[0].recorded_at = CommitSeq(2);
        let plan = report.plan_settlement(&request(50)).unwrap();
        assert_eq!(plan.allocations[0].entry, VId(11));
        report.items[1].entry = VId(11);
        report.items[1].ordinal = 1;
        let mut request = request(50);
        request.targets = vec![(VId(11), 1), (VId(11), 0)];
        report.items.reverse();
        assert_eq!(
            report.plan_settlement(&request).unwrap().allocations[0].ordinal,
            0
        );
    }

    #[test]
    fn live_applications_reduce_capacity_and_reversed_applications_reopen_it() {
        let mut report = report();
        report.items[0].applied = 40;
        report.items[0].open = 60;
        report.items[0].applications.push(Application {
            entry: VId(20),
            ordinal: 1,
            amount: 40,
            recorded_at: CommitSeq(5),
            live: true,
        });
        let plan = report.plan_settlement(&request(100)).unwrap();
        assert_eq!(plan.allocations[0].amount, 60);
        assert_eq!(plan.allocations[1].amount, 40);
        report.items[0].applications[0].live = false;
        report.items[0].applied = 0;
        report.items[0].open = 100;
        let plan = report.plan_settlement(&request(100)).unwrap();
        assert_eq!(plan.allocations.len(), 1);
        assert_eq!(plan.allocations[0].amount, 100);
    }

    #[test]
    fn payable_payments_use_the_opposite_direction() {
        let mut report = report();
        for item in &mut report.items {
            item.side = Side::Credit;
        }
        let mut request = request(100);
        assert!(report.plan_settlement(&request).is_err());
        request.side = Side::Debit;
        assert_eq!(
            report.plan_settlement(&request).unwrap().allocations[0].amount,
            100
        );
    }

    #[test]
    fn full_i128_precision_and_capacity_sums_larger_than_i128_are_supported() {
        let mut report = report();
        for item in &mut report.items {
            item.original = i128::MAX;
            item.open = i128::MAX;
        }
        let plan = report.plan_settlement(&request(i128::MAX)).unwrap();
        assert_eq!(plan.allocations.len(), 1);
        assert_eq!(plan.allocations[0].amount, i128::MAX);
        assert_eq!(plan.unapplied, 0);
        let exact = 9_007_199_254_740_993_i128;
        let plan = report.plan_settlement(&request(exact)).unwrap();
        assert_eq!(plan.allocations[0].amount, exact);
        assert!(
            plan.canonical_bytes()
                .unwrap()
                .windows(16)
                .any(|bytes| { bytes == exact.to_le_bytes().as_slice() })
        );
    }

    #[test]
    fn validates_every_target_before_spending_any_payment() {
        for case in 0..7 {
            let mut report = report();
            // The first item covers the payment. The second still must validate.
            match case {
                0 => report.items[1].account = VId(99),
                1 => report.items[1].unit_id = 2,
                2 => report.items[1].side = Side::Credit,
                3 => report.items[1].effective_date = DateDay(31),
                4 => report.items[1].recorded_at = CommitSeq(11),
                5 => report.items[1].open = -1,
                _ => report.items[1].open = 201,
            }
            assert!(report.plan_settlement(&request(1)).is_err(), "case {case}");
        }
    }

    #[test]
    fn rejects_duplicate_missing_and_implicit_selections() {
        let report = report();
        for targets in [
            vec![],
            vec![(VId(11), 0), (VId(11), 0)],
            vec![(VId(999), 0)],
            vec![(VId(11), 1)],
        ] {
            let mut request = request(1);
            request.targets = targets;
            assert!(report.plan_settlement(&request).is_err());
        }
        let mut duplicate_report = report.clone();
        duplicate_report
            .items
            .push(duplicate_report.items[0].clone());
        assert!(duplicate_report.plan_settlement(&request(1)).is_err());
        for amount in [0, -1, i128::MIN] {
            assert!(report.plan_settlement(&request(amount)).is_err());
        }
    }

    #[test]
    fn rejects_inconsistent_account_metadata_and_application_witnesses() {
        for case in 0..6 {
            let mut report = report();
            match case {
                0 => report.account_filter = Some(VId(99)),
                1 => {
                    report.accounts.clear();
                }
                2 => report.accounts.get_mut(&VId(9)).unwrap().is_leaf = false,
                3 => report.accounts.get_mut(&VId(9)).unwrap().created_at = CommitSeq(11),
                4 => {
                    report.accounts.get_mut(&VId(9)).unwrap().unit_policy =
                        UnitPolicy::Single(UnitId(2));
                }
                _ => {
                    report.items[0].applied = 10;
                    report.items[0].open = 90;
                    // No live history supports the changed applied witness.
                }
            }
            assert!(
                report.plan_settlement(&request(100)).is_err(),
                "case {case}"
            );
        }
    }

    #[test]
    fn stale_changed_and_tampered_plans_fail_revalidation() {
        let mut report = report();
        let mut plan = report.plan_settlement(&request(100)).unwrap();
        plan.validate_against(&report).unwrap();
        report.known_at = CommitSeq(11);
        assert!(plan.validate_against(&report).is_err());
        report.known_at = CommitSeq(10);
        plan.allocations[0].amount = 99;
        assert!(plan.validate_against(&report).is_err());
        plan.allocations[0].amount = 100;
        report.items[0].original = 101;
        report.items[0].open = 101;
        assert!(plan.validate_against(&report).is_err());
    }

    #[test]
    fn small_domain_exhaustion_conserves_money_and_never_overapplies() {
        for first in 0..8_i128 {
            for second in 0..8_i128 {
                for amount in 1..25_i128 {
                    let mut report = report();
                    report.items = vec![item(11, 10, first), item(12, 20, second)];
                    let plan = report.plan_settlement(&request(amount)).unwrap();
                    let applied: i128 = plan.allocations.iter().map(|row| row.amount).sum();
                    assert_eq!(applied + plan.unapplied, amount);
                    assert_eq!(applied, amount.min(first + second));
                    assert!(plan.allocations.iter().all(|row| {
                        row.amount > 0
                            && row.open_after >= 0
                            && row.amount + row.open_after == row.open_before
                    }));
                }
            }
        }
    }

    #[test]
    fn reused_index_preserves_exact_plans_without_reserving_capacity() {
        let report = report();
        let before = report.clone();
        let index = report.settlement_index().unwrap();
        for amount in [1, 50, 99, 100, 101, 250, 300, 301, 999, i128::MAX] {
            let mut request = request(amount);
            let first = index.plan_settlement(&request).unwrap();
            request.targets.reverse();
            let repeated = index.plan_settlement(&request).unwrap();
            assert_eq!(
                first, repeated,
                "the lookup must not spend or reserve capacity"
            );
            assert_eq!(first, report.plan_settlement(&request).unwrap());
            assert_eq!(
                first.canonical_bytes().unwrap(),
                repeated.canonical_bytes().unwrap()
            );
            assert_eq!(first.allocations[0].amount, amount.min(100));
            let applied: i128 = first.allocations.iter().map(|part| part.amount).sum();
            assert_eq!(applied, amount.min(300));
            assert_eq!(first.unapplied, amount - applied);
        }
        assert_eq!(report, before);
    }

    #[test]
    fn one_index_supports_disjoint_accounts_units_and_payment_sides() {
        let mut report = report();
        report.account_filter = None;
        let mut payable = report.accounts[&VId(9)].clone();
        payable.vid = VId(10);
        payable.code = "AP".into();
        payable.unit_policy = UnitPolicy::Single(UnitId(2));
        report.accounts.insert(payable.vid, payable);
        let mut bill = item(21, 20, 70);
        bill.account = VId(10);
        bill.unit_id = 2;
        bill.side = Side::Credit;
        report.items.push(bill);
        let index = report.settlement_index().unwrap();
        let invoice_plan = index.plan_settlement(&request(125)).unwrap();
        let bill_request = SettlementRequest {
            account: VId(10),
            unit_id: 2,
            side: Side::Debit,
            amount: 60,
            effective_date: DateDay(30),
            targets: vec![(VId(21), 0)],
        };
        let bill_plan = index.plan_settlement(&bill_request).unwrap();
        assert_eq!(bill_plan.known_at, invoice_plan.known_at);
        assert_eq!(bill_plan.allocations[0].open_after, 10);
        assert_eq!(invoice_plan.allocations[1].open_after, 175);
        let mut wrong_unit = bill_request;
        wrong_unit.unit_id = 1;
        assert!(index.plan_settlement(&wrong_unit).is_err());
    }

    #[test]
    fn index_checks_duplicate_report_identities_before_reuse() {
        let mut report = report();
        // The duplicate would be unused by a request selecting only 11/0.
        report.items.push(report.items[1].clone());
        assert!(report.settlement_index().is_err());
    }

    #[test]
    fn reused_lookup_revalidates_every_selected_target_including_unused() {
        for case in 0..7 {
            let mut report = report();
            match case {
                0 => report.items[1].account = VId(99),
                1 => report.items[1].unit_id = 2,
                2 => report.items[1].side = Side::Credit,
                3 => report.items[1].effective_date = DateDay(31),
                4 => report.items[1].recorded_at = CommitSeq(11),
                5 => report.items[1].open = -1,
                _ => report.items[1].open = 201,
            }
            let index = report.settlement_index().unwrap();
            let mut first_only = request(1);
            first_only.targets = vec![(VId(11), 0)];
            assert!(index.plan_settlement(&first_only).is_ok());
            assert!(index.plan_settlement(&request(1)).is_err(), "case {case}");
            assert!(
                index.plan_settlement(&first_only).is_ok(),
                "failure must not mutate advice"
            );
        }
    }

    #[test]
    fn fresh_index_cannot_relabel_an_old_allocation_after_snapshot_change() {
        let mut report = report();
        let original = report
            .settlement_index()
            .unwrap()
            .plan_settlement(&request(100))
            .unwrap();
        report.known_at = CommitSeq(11);
        report.items[0].applied = 40;
        report.items[0].open = 60;
        report.items[0].applications.push(Application {
            entry: VId(30),
            ordinal: 1,
            amount: 40,
            recorded_at: CommitSeq(11),
            live: true,
        });
        let fresh = report
            .settlement_index()
            .unwrap()
            .plan_settlement(&request(100))
            .unwrap();
        assert_eq!(fresh.known_at, CommitSeq(11));
        assert_eq!(fresh.allocations[0].amount, 60);
        assert_eq!(fresh.allocations[1].amount, 40);
        assert!(original.validate_against(&report).is_err());
        assert_eq!(original.allocations[0].amount, 100);
    }

    #[test]
    fn index_borrows_report_items_instead_of_copying_application_histories() {
        let report = report();
        let index = report.settlement_index().unwrap();
        assert!(std::ptr::eq(index.report, &report));
        for item in &report.items {
            let indexed = index.by_identity[&(item.entry, item.ordinal)];
            assert!(std::ptr::eq(indexed, item));
        }
    }
}
