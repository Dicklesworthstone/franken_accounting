//! Aging of historical open amounts (plan §5.7, §7.5 and §11.7).
//!
//! **Effective-date aging** ([`effective_date_aging`]) measures civil days
//! since the item's effective date. It is not a claim that anything is due.
//!
//! **Due-date aging** ([`due_date_aging`]) measures civil days past each
//! contractual due date the journal records: the obligation maturity terms an
//! entry carries on its leg (extension 33, `fa:obligation-maturity:v1`).
//! - Settlements relieve a schedule's earliest installments first, as
//!   `solvency.cash_flow_test` does, and each open remainder is aged from its
//!   own due date.
//! - An item without contractual terms is listed as unscheduled, with the
//!   reason, and is never given a guessed due date.
//! - The kernel admits terms on credit legs only, where an obligation is
//!   booked, so receivables are unscheduled until terms can name a debit leg.
//!
//! Both keep both time coordinates, exact native-unit debit and credit
//! columns, bucket definitions, and item-level drilldown. They never add
//! different units or treat credit balances as receivables.
//!
//! Results are literal journal folds, not certificates. The caller must
//! supply a recorded prefix and explicit effective date for stable replay.

use std::collections::BTreeMap;

use fa_journal::genesis::BookContext;
use fa_model::entry::OBLIGATION_MATURITY_EXTENSION;
use fa_model::obligation::{InlineObligationTerms, ObligationStatus};
use fa_model::{Entry, Id128};
use fa_money::Side;
use fa_time::DateDay;
use fgdb::Database;
use fgdb_types::{CommitSeq, VId};

use super::OpenItem;
use super::history::{OpenItemSnapshot, open_items_as_of, snapshot_of};
use crate::{KernelError, RegisterError, entries_at, resolve_known_at};

/// Inclusive upper ages for successive buckets, strictly increasing. The
/// last bucket is open-ended. An empty list means one bucket for all ages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgingBuckets {
    upper_bounds: Vec<u32>,
}

impl AgingBuckets {
    pub fn new(upper_bounds: Vec<u32>) -> Result<Self, RegisterError> {
        if upper_bounds.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(RegisterError::InvalidSelection(
                "aging bucket upper bounds must be strictly increasing".into(),
            ));
        }
        Ok(Self { upper_bounds })
    }

    /// Explicit conventional age bands: 0, 1–30, 31–60, 61–90, and 91+.
    /// These are effective-date ages, not a claim that an item is overdue.
    #[must_use]
    pub fn thirty_day() -> Self {
        Self {
            upper_bounds: vec![0, 30, 60, 90],
        }
    }

    #[must_use]
    pub fn upper_bounds(&self) -> &[u32] {
        &self.upper_bounds
    }

    #[must_use]
    pub fn bands(&self) -> Vec<AgingBand> {
        let mut lower = 0;
        let mut bands = Vec::with_capacity(self.upper_bounds.len() + 1);
        for upper in &self.upper_bounds {
            bands.push(AgingBand {
                lower_inclusive: lower,
                upper_inclusive: Some(u64::from(*upper)),
            });
            lower = u64::from(*upper) + 1;
        }
        bands.push(AgingBand {
            lower_inclusive: lower,
            upper_inclusive: None,
        });
        bands
    }

    fn index(&self, age: u64) -> usize {
        self.upper_bounds
            .partition_point(|upper| u64::from(*upper) < age)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgingBand {
    pub lower_inclusive: u64,
    pub upper_inclusive: Option<u64>,
}

/// Nonnegative native-unit sums. Debit and credit balances are never netted
/// across items, units or accounts, including when their net would be zero.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgingAmounts {
    pub debits: i128,
    pub credits: i128,
    pub item_count: u64,
}

impl AgingAmounts {
    fn add(&mut self, side: Side, open: i128) -> Result<(), RegisterError> {
        let column = match side {
            Side::Debit => &mut self.debits,
            Side::Credit => &mut self.credits,
        };
        *column = column.checked_add(open).ok_or(RegisterError::Overflow)?;
        self.item_count = self
            .item_count
            .checked_add(1)
            .ok_or(RegisterError::Overflow)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgedOpenItem {
    pub item: OpenItem,
    pub age_days: u64,
    /// Index into the report's `bands`.
    pub bucket: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgingCell {
    pub account: VId,
    pub unit_id: u32,
    pub bucket: usize,
    pub amounts: AgingAmounts,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgingTotal {
    pub account: VId,
    pub unit_id: u32,
    pub amounts: AgingAmounts,
}

/// Deterministically ordered detail, nonempty cells, and per-account/unit
/// totals. Fully applied items are absent. Empty reports are successful.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveDateAging {
    pub book_id: Id128,
    pub known_at: CommitSeq,
    pub effective_through: DateDay,
    pub account: Option<VId>,
    pub bands: Vec<AgingBand>,
    pub items: Vec<AgedOpenItem>,
    pub cells: Vec<AgingCell>,
    pub totals: Vec<AgingTotal>,
}

/// Age the historical open-item fold at one inclusive effective cutoff and
/// one resolved recorded prefix. Cutoffs that split a backdated settlement
/// or reversal link are refused by the historical selector, not omitted.
pub fn effective_date_aging<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    account: Option<VId>,
    effective_through: DateDay,
    known_at: Option<CommitSeq>,
    buckets: &AgingBuckets,
) -> Result<EffectiveDateAging, RegisterError> {
    let snapshot = open_items_as_of(db, book, account, effective_through, known_at)?;
    age_snapshot(snapshot, buckets)
}

/// Bucket an already-selected historical snapshot. Public for the analytics
/// layer (fa-lantern), which reads the fold at snapshot time and applies its
/// registered bucket edges at procedure time.
pub fn age_snapshot(
    snapshot: OpenItemSnapshot,
    buckets: &AgingBuckets,
) -> Result<EffectiveDateAging, RegisterError> {
    let mut cells: BTreeMap<(VId, u32, usize), AgingAmounts> = BTreeMap::new();
    let mut totals: BTreeMap<(VId, u32), AgingAmounts> = BTreeMap::new();
    let mut items = Vec::new();
    for item in snapshot.items {
        let age_days = checked_age(&item, snapshot.effective_through)?;
        if item.open == 0 {
            continue;
        }
        let bucket = buckets.index(age_days);
        cells
            .entry((item.account, item.unit_id, bucket))
            .or_default()
            .add(item.side, item.open)?;
        totals
            .entry((item.account, item.unit_id))
            .or_default()
            .add(item.side, item.open)?;
        items.push(AgedOpenItem {
            item,
            age_days,
            bucket,
        });
    }
    items.sort_by_key(|row| {
        (
            row.item.account,
            row.item.unit_id,
            row.bucket,
            row.item.effective_date,
            row.item.recorded_at,
            row.item.entry,
            row.item.ordinal,
        )
    });
    Ok(EffectiveDateAging {
        book_id: snapshot.book_id,
        known_at: snapshot.known_at,
        effective_through: snapshot.effective_through,
        account: snapshot.account,
        bands: buckets.bands(),
        items,
        cells: cells
            .into_iter()
            .map(|((account, unit_id, bucket), amounts)| AgingCell {
                account,
                unit_id,
                bucket,
                amounts,
            })
            .collect(),
        totals: totals
            .into_iter()
            .map(|((account, unit_id), amounts)| AgingTotal {
                account,
                unit_id,
                amounts,
            })
            .collect(),
    })
}

/// An open item's civil days since its effective date, once its amounts are
/// consistent and its date is not after the cutoff.
fn checked_age(item: &OpenItem, effective_through: DateDay) -> Result<u64, RegisterError> {
    let expected_open = item
        .original
        .checked_sub(item.applied_out)
        .and_then(|amount| amount.checked_sub(item.applied))
        .ok_or(RegisterError::Overflow)?;
    if item.original < 0
        || item.applied < 0
        || item.applied_out < 0
        || item.open < 0
        || item.open != expected_open
    {
        return Err(KernelError::Corrupt(format!(
            "inconsistent open amount for entry {:?} leg {}",
            item.entry, item.ordinal
        ))
        .into());
    }
    let age = i64::from(effective_through.0) - i64::from(item.effective_date.0);
    u64::try_from(age).map_err(|_| {
        KernelError::Corrupt("open-item snapshot includes a future effective date".into()).into()
    })
}

/// Why due-date aging lists an open item without a due date.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unscheduled {
    /// Its leg carries no obligation maturity terms.
    NoTerms,
    /// Its terms declare its maturity unknown.
    MissingMaturity,
    /// Its terms declare it disputed, with the reason code.
    Disputed { reason_code: u16 },
}

/// An open item due-date aging lists without a due date.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnscheduledItem {
    pub item: OpenItem,
    pub reason: Unscheduled,
}

/// The part of an open item that falls due on one contractual date.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DueDateAgedItem {
    pub item: OpenItem,
    pub due_date: DateDay,
    /// What remains open of the installment due on `due_date`: settlements
    /// relieve a schedule's earliest installments first.
    pub open: i128,
    /// Civil days from `due_date` to the cutoff, and 0 while not yet due.
    pub days_past_due: u64,
    /// Index into the report's `bands`.
    pub bucket: usize,
}

/// Open amounts aged by days past their journaled due dates. `items`,
/// `cells` and `totals` cover the scheduled parts. `unscheduled` lists every
/// other open item, with `unscheduled_totals` per account and unit, so the
/// two together are the whole open fold. Fully applied items are absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DueDateAging {
    pub book_id: Id128,
    pub known_at: CommitSeq,
    pub effective_through: DateDay,
    pub account: Option<VId>,
    pub bands: Vec<AgingBand>,
    pub items: Vec<DueDateAgedItem>,
    pub cells: Vec<AgingCell>,
    pub totals: Vec<AgingTotal>,
    pub unscheduled: Vec<UnscheduledItem>,
    pub unscheduled_totals: Vec<AgingTotal>,
}

/// Each leg's obligation maturity terms, by `(entry, leg ordinal)`. The
/// kernel validated them at admission, so bytes that no longer decode are
/// corruption.
pub type ObligationTerms = BTreeMap<(VId, u16), InlineObligationTerms>;

fn obligation_terms(entries: &[(VId, Entry, CommitSeq)]) -> Result<ObligationTerms, RegisterError> {
    let mut terms = BTreeMap::new();
    for (vid, entry, _) in entries {
        for (tag, bytes) in &entry.proposal.extensions {
            if *tag != OBLIGATION_MATURITY_EXTENSION {
                continue;
            }
            for term in InlineObligationTerms::decode_list(bytes).map_err(|e| {
                KernelError::Corrupt(format!(
                    "entry {vid:?} carries obligation terms that do not decode: {e}"
                ))
            })? {
                terms.insert((*vid, term.ordinal), term);
            }
        }
    }
    Ok(terms)
}

/// Age the historical open-item fold by days past each journaled due date,
/// at one inclusive effective cutoff and one resolved recorded prefix. The
/// terms are those recorded in that prefix; a term recorded later does not
/// change a historical aging.
pub fn due_date_aging<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    account: Option<VId>,
    effective_through: DateDay,
    known_at: Option<CommitSeq>,
    buckets: &AgingBuckets,
) -> Result<DueDateAging, RegisterError> {
    let known_at = resolve_known_at(db, known_at)?;
    let entries = entries_at(db, book, known_at)?;
    let terms = obligation_terms(&entries)?;
    let snapshot = snapshot_of(book, entries, account, effective_through, known_at)?;
    age_by_due_date(snapshot, &terms, buckets)
}

/// Bucket an already-selected snapshot by days past due under `terms`.
pub fn age_by_due_date(
    snapshot: OpenItemSnapshot,
    terms: &ObligationTerms,
    buckets: &AgingBuckets,
) -> Result<DueDateAging, RegisterError> {
    let through = snapshot.effective_through;
    let mut cells: BTreeMap<(VId, u32, usize), AgingAmounts> = BTreeMap::new();
    let mut totals: BTreeMap<(VId, u32), AgingAmounts> = BTreeMap::new();
    let mut unscheduled_totals: BTreeMap<(VId, u32), AgingAmounts> = BTreeMap::new();
    let mut items = Vec::new();
    let mut unscheduled = Vec::new();
    for item in snapshot.items {
        checked_age(&item, through)?;
        if item.open == 0 {
            continue;
        }
        let term = terms.get(&(item.entry, item.ordinal));
        let reason = match term.map(|term| term.status) {
            None => Some(Unscheduled::NoTerms),
            Some(ObligationStatus::MissingMaturity) => Some(Unscheduled::MissingMaturity),
            Some(ObligationStatus::Disputed { reason_code }) => {
                Some(Unscheduled::Disputed { reason_code })
            }
            Some(ObligationStatus::Contractual) => None,
        };
        let (Some(term), None) = (term, reason) else {
            unscheduled_totals
                .entry((item.account, item.unit_id))
                .or_default()
                .add(item.side, item.open)?;
            unscheduled.push(UnscheduledItem {
                item,
                reason: reason.unwrap_or(Unscheduled::NoTerms),
            });
            continue;
        };
        let mut installments = term.installments.clone();
        installments.sort();
        let mut scheduled: i128 = 0;
        for installment in &installments {
            scheduled = scheduled
                .checked_add(installment.amount)
                .ok_or(RegisterError::Overflow)?;
        }
        if scheduled != item.original {
            return Err(KernelError::Corrupt(format!(
                "the installments of entry {:?} leg {} total {scheduled}, not the leg's {}",
                item.entry, item.ordinal, item.original
            ))
            .into());
        }
        let mut relief = item
            .original
            .checked_sub(item.open)
            .ok_or(RegisterError::Overflow)?;
        for installment in installments {
            let relieved = relief.min(installment.amount);
            relief -= relieved;
            let open = installment.amount - relieved;
            if open == 0 {
                continue;
            }
            let days = i64::from(through.0) - i64::from(installment.due_date.0);
            let days_past_due = u64::try_from(days).unwrap_or(0);
            let bucket = buckets.index(days_past_due);
            cells
                .entry((item.account, item.unit_id, bucket))
                .or_default()
                .add(item.side, open)?;
            totals
                .entry((item.account, item.unit_id))
                .or_default()
                .add(item.side, open)?;
            items.push(DueDateAgedItem {
                item: item.clone(),
                due_date: installment.due_date,
                open,
                days_past_due,
                bucket,
            });
        }
    }
    items.sort_by_key(|row| {
        (
            row.item.account,
            row.item.unit_id,
            row.bucket,
            row.due_date,
            row.item.effective_date,
            row.item.recorded_at,
            row.item.entry,
            row.item.ordinal,
        )
    });
    unscheduled.sort_by_key(|row| {
        (
            row.item.account,
            row.item.unit_id,
            row.item.effective_date,
            row.item.recorded_at,
            row.item.entry,
            row.item.ordinal,
        )
    });
    let aging_totals = |totals: BTreeMap<(VId, u32), AgingAmounts>| {
        totals
            .into_iter()
            .map(|((account, unit_id), amounts)| AgingTotal {
                account,
                unit_id,
                amounts,
            })
            .collect()
    };
    Ok(DueDateAging {
        book_id: snapshot.book_id,
        known_at: snapshot.known_at,
        effective_through: through,
        account: snapshot.account,
        bands: buckets.bands(),
        items,
        cells: cells
            .into_iter()
            .map(|((account, unit_id, bucket), amounts)| AgingCell {
                account,
                unit_id,
                bucket,
                amounts,
            })
            .collect(),
        totals: aging_totals(totals),
        unscheduled,
        unscheduled_totals: aging_totals(unscheduled_totals),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: u128, age: i32, side: Side, unit: u32, open: i128) -> OpenItem {
        OpenItem {
            entry: VId(id),
            ordinal: 0,
            account: VId(100),
            unit_id: unit,
            side,
            effective_date: DateDay(-age),
            recorded_at: CommitSeq(1),
            original: open,
            applied: 0,
            applied_out: 0,
            open,
            applications: Vec::new(),
        }
    }

    fn snapshot(items: Vec<OpenItem>) -> OpenItemSnapshot {
        OpenItemSnapshot {
            book_id: Id128([1; 16]),
            known_at: CommitSeq(42),
            effective_through: DateDay::EPOCH,
            account: None,
            items,
        }
    }

    #[test]
    fn bucket_boundaries_are_inclusive_and_the_tail_is_open_ended() {
        let ages = [0, 1, 30, 31, 60, 61, 90, 91];
        let items = ages
            .iter()
            .enumerate()
            .map(|(i, age)| item(i as u128, *age, Side::Debit, 1, 10))
            .collect();
        let report = age_snapshot(snapshot(items), &AgingBuckets::thirty_day()).unwrap();
        for row in &report.items {
            let expected = match row.age_days {
                0 => 0,
                1..=30 => 1,
                31..=60 => 2,
                61..=90 => 3,
                _ => 4,
            };
            assert_eq!(row.bucket, expected);
        }
        assert_eq!(report.bands[0].lower_inclusive, 0);
        assert_eq!(report.bands[0].upper_inclusive, Some(0));
        assert_eq!(report.bands[4].lower_inclusive, 91);
        assert_eq!(report.bands[4].upper_inclusive, None);
        assert_eq!(report.totals[0].amounts.debits, 80);
        assert_eq!(report.totals[0].amounts.item_count, 8);
        assert_eq!(report.known_at, CommitSeq(42));
        assert_eq!(report.effective_through, DateDay::EPOCH);
    }

    #[test]
    fn bucket_configuration_is_explicit_and_validated() {
        for bounds in [vec![30, 30], vec![90, 30], vec![30, 0]] {
            assert!(matches!(
                AgingBuckets::new(bounds),
                Err(RegisterError::InvalidSelection(_))
            ));
        }
        let all = AgingBuckets::new(Vec::new()).unwrap();
        assert_eq!(all.bands().len(), 1);
        assert_eq!(all.index(0), 0);
        assert_eq!(all.index(u64::from(u32::MAX)), 0);
        let maximum = AgingBuckets::new(vec![u32::MAX]).unwrap();
        assert_eq!(maximum.bands()[1].lower_inclusive, 4_294_967_296);
        assert!(
            age_snapshot(snapshot(Vec::new()), &all)
                .unwrap()
                .cells
                .is_empty()
        );
    }

    #[test]
    fn partial_applications_and_unapplied_credits_keep_exact_native_columns() {
        let mut partial = item(1, 40, Side::Debit, 1, 60);
        partial.original = 100;
        partial.applied = 40;
        let mut other_account = item(5, 40, Side::Debit, 1, 7);
        other_account.account = VId(200);
        let report = age_snapshot(
            snapshot(vec![
                partial,
                item(2, 40, Side::Credit, 1, 20),
                item(3, 40, Side::Debit, 2, 500),
                item(4, 40, Side::Debit, 1, 0),
                other_account,
            ]),
            &AgingBuckets::thirty_day(),
        )
        .unwrap();
        assert_eq!(report.items.len(), 4);
        assert_eq!(report.cells.len(), 3);
        assert_eq!(report.totals.len(), 3);
        assert_eq!(
            report.totals[0].amounts,
            AgingAmounts {
                debits: 60,
                credits: 20,
                item_count: 2,
            }
        );
        assert_eq!(
            (report.totals[1].unit_id, report.totals[1].amounts.debits),
            (2, 500)
        );
        assert_eq!(report.totals[2].account, VId(200));
        assert_eq!(report.totals[2].amounts.debits, 7);
    }

    #[test]
    fn totals_and_detail_are_deterministic_under_input_permutation() {
        let rows = vec![
            item(9, 100, Side::Debit, 2, 30),
            item(1, 31, Side::Debit, 1, 10),
            item(7, 31, Side::Credit, 1, 15),
            item(4, 0, Side::Debit, 1, 1),
        ];
        let buckets = AgingBuckets::thirty_day();
        let expected = age_snapshot(snapshot(rows.clone()), &buckets).unwrap();
        for shift in 0..rows.len() {
            let mut permuted = rows.clone();
            permuted.rotate_left(shift);
            permuted.reverse();
            assert_eq!(
                age_snapshot(snapshot(permuted), &buckets).unwrap(),
                expected
            );
        }
        for total in &expected.totals {
            let matching: Vec<_> = expected
                .cells
                .iter()
                .filter(|c| c.account == total.account && c.unit_id == total.unit_id)
                .collect();
            assert_eq!(
                matching.iter().map(|c| c.amounts.debits).sum::<i128>(),
                total.amounts.debits
            );
            assert_eq!(
                matching.iter().map(|c| c.amounts.credits).sum::<i128>(),
                total.amounts.credits
            );
        }
    }

    #[test]
    fn invalid_open_amounts_future_items_and_overflow_are_not_reports() {
        let mut inconsistent = item(1, 0, Side::Debit, 1, 10);
        inconsistent.applied = 20;
        for bad in [
            inconsistent,
            item(1, 0, Side::Debit, 1, -1),
            item(1, -1, Side::Debit, 1, 10),
        ] {
            assert!(matches!(
                age_snapshot(snapshot(vec![bad]), &AgingBuckets::thirty_day()),
                Err(RegisterError::Kernel(KernelError::Corrupt(_)))
            ));
        }
        for age in [0, 31] {
            // Same-bucket and cross-bucket totals both enforce the ceiling.
            assert!(matches!(
                age_snapshot(
                    snapshot(vec![
                        item(1, 0, Side::Debit, 1, i128::MAX),
                        item(2, age, Side::Debit, 1, 1),
                    ]),
                    &AgingBuckets::thirty_day(),
                ),
                Err(RegisterError::Overflow)
            ));
        }
    }

    #[test]
    fn installments_are_relieved_earliest_first_and_must_tie_to_the_leg() {
        use fa_model::obligation::ObligationInstallment;
        let mut paid = item(1, 40, Side::Credit, 1, 300);
        paid.original = 1_000;
        paid.applied = 700;
        let schedule = |amounts: [(i32, i128); 2]| InlineObligationTerms {
            ordinal: 0,
            status: ObligationStatus::Contractual,
            installments: amounts
                .into_iter()
                .map(|(day, amount)| ObligationInstallment {
                    due_date: DateDay(day),
                    amount,
                })
                .collect(),
        };
        // Stated out of order, the schedule is still relieved by due date:
        // 700 clears the -20 installment and 100 of the +10 one.
        let terms = ObligationTerms::from([((VId(1), 0), schedule([(10, 400), (-20, 600)]))]);
        let report = age_by_due_date(
            snapshot(vec![paid.clone()]),
            &terms,
            &AgingBuckets::thirty_day(),
        )
        .unwrap();
        assert_eq!(report.items.len(), 1);
        assert_eq!(report.items[0].due_date, DateDay(10));
        assert_eq!(report.items[0].open, 300);
        // Due ten days after the cutoff: not yet past due.
        assert_eq!(report.items[0].days_past_due, 0);
        assert_eq!(report.totals[0].amounts.credits, 300);
        assert!(report.unscheduled.is_empty());
        // A schedule that does not total the leg is corruption, not a report.
        let short = ObligationTerms::from([((VId(1), 0), schedule([(10, 300), (-20, 600)]))]);
        assert!(matches!(
            age_by_due_date(snapshot(vec![paid]), &short, &AgingBuckets::thirty_day()),
            Err(RegisterError::Kernel(KernelError::Corrupt(_)))
        ));
    }

    #[test]
    fn age_arithmetic_covers_the_full_civil_date_domain() {
        let mut oldest = item(1, 0, Side::Debit, 1, 1);
        oldest.effective_date = DateDay(i32::MIN);
        let mut input = snapshot(vec![oldest]);
        input.effective_through = DateDay(i32::MAX);
        let report = age_snapshot(input, &AgingBuckets::thirty_day()).unwrap();
        assert_eq!(report.items[0].age_days, 4_294_967_295);
        assert_eq!(report.items[0].bucket, 4);
    }
}
