//! Effective-date aging of historical open amounts (plan §5.7 and §7.5).
//!
//! This is explicitly **not due-date aging**: the current payload has no
//! contractual due date. Ages are civil days since the item's effective
//! date. The report retains both time coordinates, exact native-unit debit
//! and credit columns, bucket definitions, and item-level drilldown.
//! It never adds different units or treats credit balances as receivables.
//!
//! Results are literal journal folds, not certificates. The caller must
//! supply a recorded prefix and explicit effective date for stable replay.

use std::collections::BTreeMap;

use fa_journal::genesis::BookContext;
use fa_model::Id128;
use fa_money::Side;
use fa_time::DateDay;
use fgdb::Database;
use fgdb_types::{CommitSeq, VId};

use super::OpenItem;
use super::history::{OpenItemSnapshot, open_items_as_of};
use crate::{KernelError, RegisterError};

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
    fn add(&mut self, item: &OpenItem) -> Result<(), RegisterError> {
        let column = match item.side {
            Side::Debit => &mut self.debits,
            Side::Credit => &mut self.credits,
        };
        *column = column
            .checked_add(item.open)
            .ok_or(RegisterError::Overflow)?;
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

fn age_snapshot(
    snapshot: OpenItemSnapshot,
    buckets: &AgingBuckets,
) -> Result<EffectiveDateAging, RegisterError> {
    let mut cells: BTreeMap<(VId, u32, usize), AgingAmounts> = BTreeMap::new();
    let mut totals: BTreeMap<(VId, u32), AgingAmounts> = BTreeMap::new();
    let mut items = Vec::new();
    for item in snapshot.items {
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
        let age = i64::from(snapshot.effective_through.0) - i64::from(item.effective_date.0);
        let age_days = u64::try_from(age).map_err(|_| {
            KernelError::Corrupt("open-item snapshot includes a future effective date".into())
        })?;
        if item.open == 0 {
            continue;
        }
        let bucket = buckets.index(age_days);
        cells
            .entry((item.account, item.unit_id, bucket))
            .or_default()
            .add(&item)?;
        totals
            .entry((item.account, item.unit_id))
            .or_default()
            .add(&item)?;
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
