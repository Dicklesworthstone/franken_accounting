//! Exact lead schedules (plan §12.1): opening stock plus classified posted
//! movements equals closing stock, independently for every account and unit.
//!
//! The source must select one book/branch/known-at frontier, opening stock at
//! EFFECTIVE < start, closing stock at EFFECTIVE <= end, and every eligible
//! posted leg in [start, end]. In particular, migration visibility and reversal
//! lineage are resolved by that source, not guessed here. Closing entries are
//! real activity in a lead schedule; Pending and control entries are not.
//!
//! This is a pure arithmetic and source-shape checker, not an authenticated
//! journal reader or an outsider completeness proof. Reconciliation cannot
//! detect two omitted legs that cancel. The facade must retain the native
//! read evidence and authenticated prefix alongside these canonical bytes.

use std::collections::{BTreeMap, BTreeSet};

use fa_model::{AccountType, EntryClass, Id128, Writer};
use fa_time::DateDay;

use crate::{
    Account, AccountBalance, MAX_ACCOUNTS, MAX_BALANCES, MAX_UNITS, StatementError,
    StatementKind, Sum, input, overflow,
};

pub const OUTPUT_FORMAT: &str = "fa:roll-forward:v1";
const OUTPUT_MAGIC: &[u8; 16] = b"FA-ROLL-FORWARD\0";
const MAX_BUCKETS: usize = 256;
const MAX_REASON_BYTES: usize = 256;
/// Bound the *expanded* schedule, not just its sparse input vectors.
const MAX_OUTPUT_VALUES: usize = 2_000_000;

type Cell = (u128, u32);

/// Activity is partitioned by the recorded class, reason and exact rule
/// version. None is a manual/no-rule origin, not an invented rule version.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Bucket {
    pub class: EntryClass,
    pub reason_code: String,
    pub rule_digest: Option<[u8; 32]>,
}

/// One selected, posted leg. Its digest/index is unique across the input,
/// even when a caller tries to assign the same leg to a different bucket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Movement {
    pub entry_digest: [u8; 32],
    pub leg_index: u32,
    pub recorded_seq: u64,
    pub effective_day: DateDay,
    pub account_id: u128,
    pub unit_id: u32,
    pub bucket: Bucket,
    /// Exactly one side is positive. These are unsigned magnitudes carried
    /// in the accounting i128 type, not already-netted account balances.
    pub debits: i128,
    pub credits: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollForwardInput {
    pub book_id: Id128,
    pub branch_id: Id128,
    pub known_at: u64,
    pub label: String,
    pub effective_from: DateDay,
    pub effective_through: DateDay,
    /// Explicit selected monetary leaf scope, including zero-valued leaves.
    /// A historical chart expansion is a source obligation.
    pub accounts: Vec<Account>,
    pub units: Vec<u32>,
    /// At the same known-at frontier as activity and closing stock. Missing
    /// account/unit cells mean zero; duplicate cells are never additive.
    pub opening: Vec<AccountBalance>,
    pub closing: Vec<AccountBalance>,
    pub movements: Vec<Movement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub account_id: u128,
    pub unit_id: u32,
    /// Every amount uses the debit-minus-credit convention. Credit-normal
    /// balances remain negative; no account-type-dependent sign is hidden.
    pub opening: i128,
    /// Aligned with RollForward.buckets, including zero-valued buckets.
    pub activity: Vec<i128>,
    pub net_change: i128,
    pub closing: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollForward {
    pub book_id: Id128,
    pub branch_id: Id128,
    pub known_at: u64,
    pub label: String,
    pub effective_from: DateDay,
    pub effective_through: DateDay,
    /// Account code/id order, followed by ascending units in rows.
    pub accounts: Vec<Account>,
    pub units: Vec<u32>,
    pub buckets: Vec<Bucket>,
    pub rows: Vec<Row>,
    /// Exact inputs retained in (recorded sequence, digest, leg index) order.
    /// They are citations for a source closure, not self-authenticating proof.
    pub movements: Vec<Movement>,
}

impl RollForward {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut w = Writer::new();
        w.fixed(OUTPUT_MAGIC)
            .u16(1)
            .u16(0)
            .fixed(&self.book_id.0)
            .fixed(&self.branch_id.0)
            .u64(self.known_at)
            .str(&self.label)
            .i32(self.effective_from.0)
            .i32(self.effective_through.0)
            .list(&self.accounts, |w, account| {
                w.u128(account.id)
                    .str(&account.code)
                    .str(&account.name)
                    .u8(account.account_type)
                    .bool(account.is_leaf);
            })
            .list(&self.units, |w, unit| {
                w.u32(*unit);
            })
            .list(&self.buckets, write_bucket)
            .list(&self.rows, |w, row| {
                w.u128(row.account_id)
                    .u32(row.unit_id)
                    .i128(row.opening)
                    .list(&row.activity, |w, amount| {
                        w.i128(*amount);
                    })
                    .i128(row.net_change)
                    .i128(row.closing);
            })
            .list(&self.movements, |w, movement| {
                w.fixed(&movement.entry_digest)
                    .u32(movement.leg_index)
                    .u64(movement.recorded_seq)
                    .i32(movement.effective_day.0)
                    .u128(movement.account_id)
                    .u32(movement.unit_id);
                write_bucket(w, &movement.bucket);
                w.i128(movement.debits).i128(movement.credits);
            });
        w.finish()
    }
}

fn write_bucket(w: &mut Writer, bucket: &Bucket) {
    w.u16(bucket.class.0)
        .str(&bucket.reason_code)
        .opt(bucket.rule_digest.as_ref(), |w, digest| {
            w.fixed(digest);
        });
}

/// Reconcile all selected cells before returning any schedule. Opposing
/// residuals in two accounts or currencies cannot make an invalid schedule
/// pass. Nothing is silently filtered, rounded or inserted to make it foot.
pub fn evaluate(source: &RollForwardInput) -> Result<RollForward, StatementError> {
    if source.label.trim().is_empty() || source.label.len() > 256 {
        return Err(input("roll-forward label is empty or exceeds 256 bytes"));
    }
    if source.effective_from > source.effective_through {
        return Err(input("roll-forward effective bounds are reversed"));
    }
    if source.accounts.len() > MAX_ACCOUNTS
        || source.units.is_empty()
        || source.units.len() > MAX_UNITS
        || source.opening.len() > MAX_BALANCES
        || source.closing.len() > MAX_BALANCES
        || source.movements.len() > MAX_BALANCES
    {
        return Err(input("roll-forward inputs exceed their bounded scope"));
    }
    let mut accounts = BTreeMap::new();
    let mut codes = BTreeSet::new();
    for account in &source.accounts {
        if !account.is_leaf
            || !AccountType(account.account_type).is_registered()
            || !StatementKind::BalanceSheet
                .covered_types()
                .contains(&account.account_type)
            || account.code.is_empty()
            || account.code.len() > 64
            || account.name.len() > fa_model::limits::MAX_SCHEMA_CHANGE_BYTES
            || accounts.insert(account.id, account).is_some()
            || !codes.insert(account.code.as_str())
        {
            return Err(input("roll-forward scope needs distinct, valid monetary leaf accounts"));
        }
    }
    let units: BTreeSet<_> = source.units.iter().copied().collect();
    if units.len() != source.units.len() {
        return Err(input("roll-forward native units are repeated"));
    }
    let mut buckets = BTreeSet::new();
    let mut legs = BTreeSet::new();
    let mut headers: BTreeMap<[u8; 32], &Movement> = BTreeMap::new();
    for movement in &source.movements {
        check_cell(movement.account_id, movement.unit_id, &accounts, &units)?;
        let class = movement.bucket.class;
        if !class.is_registered() || class.is_control() || class == EntryClass::PENDING {
            return Err(input("roll-forward activity must contain only registered posted classes"));
        }
        if movement.bucket.reason_code.len() > MAX_REASON_BYTES {
            return Err(input("roll-forward reason code exceeds 256 bytes"));
        }
        if movement.recorded_seq == 0
            || movement.recorded_seq > source.known_at
            || movement.effective_day < source.effective_from
            || movement.effective_day > source.effective_through
        {
            return Err(input("roll-forward movement lies outside its selected coordinate"));
        }
        if movement.debits < 0
            || movement.credits < 0
            || (movement.debits > 0) == (movement.credits > 0)
        {
            return Err(input("a roll-forward movement must be one positive debit or credit leg"));
        }
        if !legs.insert((movement.entry_digest, movement.leg_index)) {
            return Err(input("roll-forward repeats a journal leg, possibly in another bucket"));
        }
        if let Some(previous) = headers.insert(movement.entry_digest, movement) {
            if previous.recorded_seq != movement.recorded_seq
                || previous.effective_day != movement.effective_day
                || previous.bucket != movement.bucket
            {
                return Err(input("roll-forward legs disagree about their entry's metadata"));
            }
        }
        buckets.insert(movement.bucket.clone());
        if buckets.len() > MAX_BUCKETS {
            return Err(input("roll-forward has more than 256 activity buckets"));
        }
    }
    let width = buckets.len() + 3;
    let values = accounts
        .len()
        .checked_mul(units.len())
        .and_then(|cells| cells.checked_mul(width))
        .ok_or_else(|| input("roll-forward output dimensions overflow"))?;
    if values > MAX_OUTPUT_VALUES {
        return Err(input("roll-forward expanded output exceeds two million amounts; narrow the scope"));
    }
    let opening = read_balances(&source.opening, &accounts, &units)?;
    let closing = read_balances(&source.closing, &accounts, &units)?;
    let buckets: Vec<_> = buckets.into_iter().collect();
    let indexes: BTreeMap<_, _> = buckets
        .iter()
        .enumerate()
        .map(|(index, bucket)| (bucket, index))
        .collect();
    let mut activity: BTreeMap<Cell, Vec<Sum>> = BTreeMap::new();
    for movement in &source.movements {
        let sums = activity
            .entry((movement.account_id, movement.unit_id))
            .or_insert_with(|| vec![Sum::ZERO; buckets.len()]);
        let sum = &mut sums[indexes[&movement.bucket]];
        let failed = || overflow("roll-forward activity", &source.label, movement.unit_id);
        sum.add(movement.debits, false).ok_or_else(failed)?;
        sum.add(movement.credits, true).ok_or_else(failed)?;
    }
    let mut ordered_accounts: Vec<_> = accounts.into_values().cloned().collect();
    ordered_accounts.sort_by(|a, b| a.code.cmp(&b.code).then(a.id.cmp(&b.id)));
    let mut rows = Vec::with_capacity(ordered_accounts.len() * units.len());
    for account in &ordered_accounts {
        for unit in &units {
            let cell = (account.id, *unit);
            let failed = || overflow(&account.code, &source.label, *unit);
            let opening = opening.get(&cell).copied().unwrap_or(0);
            let closing = closing.get(&cell).copied().unwrap_or(0);
            let mut net = Sum::ZERO;
            let mut amounts = Vec::with_capacity(buckets.len());
            for index in 0..buckets.len() {
                let amount = match activity.get(&cell) {
                    Some(sums) => sums[index].value().ok_or_else(failed)?,
                    None => 0,
                };
                net.add(amount, false).ok_or_else(failed)?;
                amounts.push(amount);
            }
            let net_change = net.value().ok_or_else(failed)?;
            net.add(opening, false).ok_or_else(failed)?;
            net.add(closing, true).ok_or_else(failed)?;
            let residual = net.value().ok_or_else(failed)?;
            if residual != 0 {
                return Err(StatementError::Identity {
                    line: format!("roll-forward:{}", account.code),
                    column: source.label.clone(),
                    unit_id: *unit,
                    residual,
                });
            }
            rows.push(Row {
                account_id: account.id,
                unit_id: *unit,
                opening,
                activity: amounts,
                net_change,
                closing,
            });
        }
    }
    let mut movements = source.movements.clone();
    movements.sort_by_key(|movement| {
        (movement.recorded_seq, movement.entry_digest, movement.leg_index)
    });
    Ok(RollForward {
        book_id: source.book_id,
        branch_id: source.branch_id,
        known_at: source.known_at,
        label: source.label.clone(),
        effective_from: source.effective_from,
        effective_through: source.effective_through,
        accounts: ordered_accounts,
        units: units.into_iter().collect(),
        buckets,
        rows,
        movements,
    })
}

fn check_cell(
    account: u128,
    unit: u32,
    accounts: &BTreeMap<u128, &Account>,
    units: &BTreeSet<u32>,
) -> Result<(), StatementError> {
    if !accounts.contains_key(&account) || !units.contains(&unit) {
        return Err(input(format!(
            "roll-forward cell {account:032x}/{unit} is outside the declared scope"
        )));
    }
    Ok(())
}

fn read_balances(
    balances: &[AccountBalance],
    accounts: &BTreeMap<u128, &Account>,
    units: &BTreeSet<u32>,
) -> Result<BTreeMap<Cell, i128>, StatementError> {
    let mut result = BTreeMap::new();
    for balance in balances {
        check_cell(balance.account_id, balance.unit_id, accounts, units)?;
        if balance.debits < 0 || balance.credits < 0 {
            return Err(input("roll-forward stock has a negative debit or credit magnitude"));
        }
        // Both magnitudes are nonnegative i128: their difference fits i128.
        let net = balance.debits - balance.credits;
        if result.insert((balance.account_id, balance.unit_id), net).is_some() {
            return Err(input("roll-forward stock repeats an account/unit cell"));
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(id: u128) -> Account {
        Account {
            id,
            code: format!("{id:04}"),
            name: format!("Account {id}"),
            account_type: 1,
            is_leaf: true,
        }
    }

    fn stock(account_id: u128, unit_id: u32, net: i128) -> AccountBalance {
        AccountBalance {
            account_id,
            unit_id,
            debits: net.max(0),
            credits: (-net).max(0),
        }
    }

    fn movement(id: u8, class: EntryClass, reason: &str, net: i128) -> Movement {
        Movement {
            entry_digest: [id; 32],
            leg_index: 0,
            recorded_seq: u64::from(id),
            effective_day: DateDay(10),
            account_id: 1,
            unit_id: 1,
            bucket: Bucket {
                class,
                reason_code: reason.into(),
                rule_digest: None,
            },
            debits: net.max(0),
            credits: (-net).max(0),
        }
    }

    fn source() -> RollForwardInput {
        RollForwardInput {
            book_id: Id128([7; 16]),
            branch_id: Id128::TRUNK,
            known_at: 9,
            label: "P1 lead schedule".into(),
            effective_from: DateDay(10),
            effective_through: DateDay(20),
            accounts: vec![account(1), account(2)],
            units: vec![1, 9],
            opening: vec![stock(1, 1, 100)],
            closing: vec![stock(1, 1, 125)],
            movements: vec![
                movement(1, EntryClass::ORIGINAL, "receipt", 50),
                movement(2, EntryClass::ADJUSTING, "depreciation", -20),
                movement(3, EntryClass::CLOSING, "close", -5),
            ],
        }
    }

    #[test]
    fn leads_reconcile_by_class_reason_and_rule_with_zero_cells_retained() {
        let mut source = source();
        source.movements[1].bucket.rule_digest = Some([8; 32]);
        let result = evaluate(&source).unwrap();
        assert_eq!(result.rows.len(), 4);
        let row = &result.rows[0];
        assert_eq!((row.opening, row.net_change, row.closing), (100, 25, 125));
        assert_eq!(row.activity, [50, -20, -5]);
        assert_eq!(result.buckets[1].rule_digest, Some([8; 32]));
        assert!(result.rows[1..].iter().all(|row| {
            row.opening == 0 && row.closing == 0 && row.activity == [0, 0, 0]
        }));
        assert_eq!(result.movements, source.movements);
    }

    #[test]
    fn input_order_does_not_change_canonical_bytes_but_coordinate_does() {
        let mut source = source();
        let bytes = evaluate(&source).unwrap().canonical_bytes().unwrap();
        source.accounts.reverse();
        source.units.reverse();
        source.movements.reverse();
        assert_eq!(bytes, evaluate(&source).unwrap().canonical_bytes().unwrap());
        source.known_at += 1;
        assert_ne!(bytes, evaluate(&source).unwrap().canonical_bytes().unwrap());
    }

    #[test]
    fn missing_activity_cannot_be_replaced_by_a_silent_balancing_plug() {
        let mut source = source();
        source.movements.pop();
        assert!(matches!(
            evaluate(&source),
            Err(StatementError::Identity { residual: 5, unit_id: 1, .. })
        ));
    }

    #[test]
    fn opposing_account_or_unit_residuals_do_not_cancel() {
        for (account, unit) in [(2, 1), (1, 9)] {
            let mut source = source();
            source.closing = vec![stock(1, 1, 126), stock(account, unit, -1)];
            assert!(matches!(evaluate(&source), Err(StatementError::Identity { .. })));
        }
    }

    #[test]
    fn duplicate_legs_and_inconsistent_headers_are_rejected() {
        let base = source();
        let mut source = base.clone();
        let mut duplicate = source.movements[0].clone();
        duplicate.bucket.reason_code = "another bucket".into();
        source.movements.push(duplicate);
        assert!(matches!(evaluate(&source), Err(StatementError::Input(_))));
        source = base;
        let mut contradictory = source.movements[0].clone();
        contradictory.leg_index = 1;
        contradictory.recorded_seq += 1;
        source.movements.push(contradictory);
        assert!(matches!(evaluate(&source), Err(StatementError::Input(_))));
    }

    #[test]
    fn wrong_coordinates_pending_controls_unknown_classes_and_bad_legs_refuse() {
        let base = source();
        for class in [EntryClass::PENDING, EntryClass::PERIOD_CONTROL, EntryClass(65535)] {
            let mut source = base.clone();
            source.movements[0].bucket.class = class;
            assert!(matches!(evaluate(&source), Err(StatementError::Input(_))));
        }
        for (seq, day) in [(0, 10), (10, 10), (1, 9), (1, 21)] {
            let mut source = base.clone();
            source.movements[0].recorded_seq = seq;
            source.movements[0].effective_day = DateDay(day);
            assert!(matches!(evaluate(&source), Err(StatementError::Input(_))));
        }
        for (debits, credits) in [(-1, 0), (0, -1), (0, 0), (1, 1)] {
            let mut source = base.clone();
            source.movements[0].debits = debits;
            source.movements[0].credits = credits;
            assert!(matches!(evaluate(&source), Err(StatementError::Input(_))));
        }
    }

    #[test]
    fn duplicates_undeclared_cells_and_summary_scopes_refuse_even_when_zero() {
        let base = source();
        let mut source = base.clone();
        source.opening.push(source.opening[0].clone());
        assert!(matches!(evaluate(&source), Err(StatementError::Input(_))));
        source = base.clone();
        source.closing.push(stock(99, 1, 0));
        assert!(matches!(evaluate(&source), Err(StatementError::Input(_))));
        source = base.clone();
        source.closing.push(stock(1, 99, 0));
        assert!(matches!(evaluate(&source), Err(StatementError::Input(_))));
        source = base.clone();
        source.units.push(1);
        assert!(matches!(evaluate(&source), Err(StatementError::Input(_))));
        source = base;
        source.accounts[1].is_leaf = false;
        assert!(matches!(evaluate(&source), Err(StatementError::Input(_))));
    }

    #[test]
    fn cancellation_uses_wide_intermediates_and_true_overflow_refuses() {
        let mut source = source();
        source.opening.clear();
        source.closing = vec![stock(1, 1, i128::MAX)];
        source.movements = vec![
            movement(1, EntryClass::ORIGINAL, "wide", i128::MAX),
            movement(2, EntryClass::ORIGINAL, "wide", i128::MAX),
            movement(3, EntryClass::ORIGINAL, "wide", -i128::MAX),
        ];
        assert_eq!(evaluate(&source).unwrap().rows[0].net_change, i128::MAX);
        source.movements.pop();
        assert!(matches!(evaluate(&source), Err(StatementError::Overflow { .. })));
    }

    #[test]
    fn empty_scope_and_empty_activity_keep_exact_opening_and_closing_stock() {
        let mut source = source();
        source.movements.clear();
        source.closing = source.opening.clone();
        let result = evaluate(&source).unwrap();
        assert!(result.buckets.is_empty());
        assert_eq!(result.rows[0].net_change, 0);
        source.accounts.clear();
        source.opening.clear();
        source.closing.clear();
        assert!(evaluate(&source).unwrap().rows.is_empty());
    }

    #[test]
    fn sparse_inputs_cannot_request_an_unbounded_dense_output() {
        let mut source = source();
        source.accounts = (1..=500).map(account).collect();
        source.units = (1..=MAX_UNITS as u32).collect();
        assert!(matches!(evaluate(&source), Err(StatementError::Input(_))));
    }
}
