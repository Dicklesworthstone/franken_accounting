//! Exact, bounded attribution through a chronological transfer network.
//!
//! Inputs are one native unit and one legal entity, netted per account within
//! each entry by the caller. All debits of an entry are applied after all its
//! credits. A source is one entry's net deposit into one account. Every unit
//! of that source ends in a held position or an explicit terminal position;
//! paths are evidence, not independent amounts to sum a second time.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use asupersync::Cx;
use fa_money::{ArithmeticBudget, BudgetLimits, Rate};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Law {
    Libr,
    Fifo,
    Lifo,
    ProRata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntradayOrder {
    StatementOrdinal,
    WithdrawalsFirst,
    DepositsFirst,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hop {
    pub entry: u128,
    pub from: u128,
    pub to: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub entry: u128,
    pub day: i32,
    pub recorded: u64,
    pub from: u128,
    pub to: u128,
    pub amount: i128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Disposition {
    Held,
    Spent,
    RepaidOverdraft,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Position {
    pub account: u128,
    pub disposition: Disposition,
    pub amount: i128,
    pub path: Vec<Hop>,
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_transfers: usize,
    pub max_fragments: usize,
    pub max_hops: usize,
    pub max_steps: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    Overflow(&'static str),
    Limit(&'static str),
    Allocation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub source_amount: i128,
    pub positions: Vec<Position>,
    pub steps: u64,
}

struct Meter {
    limits: Limits,
    steps: u64,
    fragments: usize,
}

impl Meter {
    fn step(&mut self, n: u64) -> Result<(), Error> {
        self.steps = self.steps.checked_add(n).ok_or(Error::Limit("max_steps"))?;
        if self.steps > self.limits.max_steps {
            return Err(Error::Limit("max_steps"));
        }
        Ok(())
    }

    fn fragment(&mut self) -> Result<(), Error> {
        self.step(1)?;
        self.fragments = self
            .fragments
            .checked_add(1)
            .ok_or(Error::Limit("max_fragments"))?;
        if self.fragments > self.limits.max_fragments {
            return Err(Error::Limit("max_fragments"));
        }
        Ok(())
    }

    fn path(&mut self, path: &[Hop], next: Hop) -> Result<Vec<Hop>, Error> {
        if path.len() >= self.limits.max_hops {
            return Err(Error::Limit("max_hops"));
        }
        self.step(path.len() as u64 + 1)?;
        let mut extended = path.to_vec();
        extended.push(next);
        Ok(extended)
    }
}

#[derive(Clone, Debug)]
struct Lot {
    amount: i128,
    // An empty path denotes clean money. No fictitious source is created.
    path: Vec<Hop>,
}

#[derive(Default)]
struct Account {
    balance: i128,
    lots: VecDeque<Lot>,
}

fn add(a: i128, b: i128, label: &'static str) -> Result<i128, Error> {
    a.checked_add(b).ok_or(Error::Overflow(label))
}

/// Validate even the caller's allocation result. An erroneous allocator can
/// never silently create money, exceed a destination's capacity or drop a lot.
fn split<F>(
    amount: i128,
    capacities: &[i128],
    allocate: &mut F,
    meter: &mut Meter,
) -> Result<Vec<i128>, Error>
where
    F: FnMut(i128, &[i128]) -> Result<Vec<i128>, Error>,
{
    let n = capacities.len() as u64;
    meter.step(
        n.saturating_mul(u64::from(n.max(1).ilog2()) + 257)
            .saturating_add(1),
    )?;
    if amount < 0 || capacities.iter().any(|capacity| *capacity < 0) {
        return Err(Error::Allocation);
    }
    if amount == 0 {
        return Ok(vec![0; capacities.len()]);
    }
    let shares = allocate(amount, capacities)?;
    if shares.len() != capacities.len() {
        return Err(Error::Allocation);
    }
    let mut sum = 0i128;
    for (&share, &capacity) in shares.iter().zip(capacities) {
        if share < 0 || share > capacity {
            return Err(Error::Allocation);
        }
        sum = add(sum, share, "allocated shares")?;
    }
    if sum != amount {
        return Err(Error::Allocation);
    }
    Ok(shares)
}

impl Account {
    fn withdraw(&mut self, amount: i128, law: Law, meter: &mut Meter) -> Result<Vec<Lot>, Error> {
        self.balance = self
            .balance
            .checked_sub(amount)
            .ok_or(Error::Overflow("account withdrawal"))?;
        let mut remaining = amount;
        let mut out = Vec::new();
        while remaining > 0 {
            meter.fragment()?;
            let next = match law {
                Law::Fifo | Law::Libr | Law::ProRata => self.lots.pop_front(),
                Law::Lifo => self.lots.pop_back(),
            };
            let Some(mut lot) = next else {
                // Borrowing is clean funding, not a replenishment of taint.
                out.push(Lot {
                    amount: remaining,
                    path: Vec::new(),
                });
                break;
            };
            let taken = remaining.min(lot.amount);
            remaining -= taken;
            lot.amount -= taken;
            meter.step(lot.path.len() as u64)?;
            out.push(Lot {
                amount: taken,
                path: lot.path.clone(),
            });
            if lot.amount != 0 {
                match law {
                    Law::Fifo | Law::Libr | Law::ProRata => self.lots.push_front(lot),
                    Law::Lifo => self.lots.push_back(lot),
                }
            }
        }
        Ok(out)
    }

    fn deposit<F>(
        &mut self,
        account: u128,
        lots: Vec<Lot>,
        terminal: &mut Vec<Position>,
        allocate: &mut F,
        meter: &mut Meter,
    ) -> Result<(), Error>
    where
        F: FnMut(i128, &[i128]) -> Result<Vec<i128>, Error>,
    {
        let capacities: Vec<i128> = lots.iter().map(|lot| lot.amount).collect();
        let total = capacities
            .iter()
            .try_fold(0, |a, b| add(a, *b, "deposit"))?;
        // unsigned_abs handles i128::MIN; the min is <= a positive i128.
        let repaid = if self.balance < 0 {
            i128::try_from(self.balance.unsigned_abs().min(total as u128))
                .map_err(|_| Error::Overflow("overdraft"))?
        } else {
            0
        };
        let repayments = split(repaid, &capacities, allocate, meter)?;
        self.balance = add(self.balance, total, "account deposit")?;
        for (mut lot, repayment) in lots.into_iter().zip(repayments) {
            meter.step(1)?;
            if repayment > 0 && !lot.path.is_empty() {
                meter.fragment()?;
                meter.step(lot.path.len() as u64)?;
                terminal.push(Position {
                    account,
                    disposition: Disposition::RepaidOverdraft,
                    amount: repayment,
                    path: lot.path.clone(),
                });
            }
            lot.amount -= repayment;
            if lot.amount > 0 {
                // Adjacent identical arrivals have identical FIFO/LIFO age.
                if let Some(last) = self.lots.back_mut()
                    && last.path == lot.path
                {
                    last.amount = add(last.amount, lot.amount, "adjacent lots")?;
                } else {
                    self.lots.push_back(lot);
                }
            }
        }
        Ok(())
    }
}

/// Follow the selected deposit through all admitted transfers. The allocator
/// is the registered largest-remainder law; it receives remaining capacities.
/// Every bound is fail-closed: no partial Report can escape on exhaustion.
#[cfg(test)]
pub fn trace<F>(
    transfers: &[Transfer],
    assets: &BTreeSet<u128>,
    source: (u128, u128),
    law: Law,
    limits: Limits,
    allocate: F,
) -> Result<Report, Error>
where
    F: FnMut(i128, &[i128]) -> Result<Vec<i128>, Error>,
{
    trace_with_options(
        transfers,
        assets,
        source,
        law,
        IntradayOrder::StatementOrdinal,
        &BTreeSet::new(),
        limits,
        allocate,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn trace_with_options<F>(
    transfers: &[Transfer],
    assets: &BTreeSet<u128>,
    source: (u128, u128),
    law: Law,
    intraday: IntradayOrder,
    replenish_entries: &BTreeSet<u128>,
    limits: Limits,
    mut allocate: F,
) -> Result<Report, Error>
where
    F: FnMut(i128, &[i128]) -> Result<Vec<i128>, Error>,
{
    let (source_entry, source_account) = source;
    if limits.max_hops == 0
        || limits.max_hops > 64
        || limits.max_steps == 0
        || limits.max_transfers == 0
        || limits.max_fragments == 0
    {
        return Err(Error::Invalid(
            "positive limits and max_hops <= 64 are required",
        ));
    }
    if !assets.contains(&source_account) {
        return Err(Error::Invalid("source account must be a tracked asset"));
    }
    if transfers.len() > limits.max_transfers {
        return Err(Error::Limit("max_transfers"));
    }
    let mut meter = Meter {
        limits,
        steps: 0,
        fragments: 0,
    };
    let n = transfers.len() as u64;
    meter.step(n.saturating_mul(u64::from(n.max(1).ilog2()) + 1))?;
    let mut entry_has_asset_outflow: BTreeMap<u128, bool> = BTreeMap::new();
    for t in transfers {
        let slot = entry_has_asset_outflow.entry(t.entry).or_insert(false);
        if assets.contains(&t.from) {
            *slot = true;
        }
    }
    let rank = |entry: u128| -> u8 {
        let is_deposit = !entry_has_asset_outflow
            .get(&entry)
            .copied()
            .unwrap_or(false);
        match intraday {
            IntradayOrder::StatementOrdinal => 0,
            IntradayOrder::WithdrawalsFirst => u8::from(is_deposit),
            IntradayOrder::DepositsFirst => u8::from(!is_deposit),
        }
    };
    let mut ordered = transfers.to_vec();
    ordered.sort_by_key(|t| {
        (
            t.day,
            rank(t.entry),
            t.recorded,
            t.entry,
            t.from,
            t.to,
            t.amount,
        )
    });
    let mut identities = BTreeMap::new();
    for t in &ordered {
        meter.step(1)?;
        if t.amount <= 0 || t.from == t.to {
            return Err(Error::Invalid("transfers must be positive and netted"));
        }
        if let Some(at) = identities.insert(t.entry, (t.day, t.recorded))
            && at != (t.day, t.recorded)
        {
            return Err(Error::Invalid("one entry has conflicting coordinates"));
        }
    }
    match law {
        Law::Libr => return trace_libr(&ordered, assets, source, replenish_entries, &mut meter),
        Law::ProRata => return trace_pro_rata(&ordered, assets, source, &mut meter),
        Law::Fifo | Law::Lifo => {}
    }
    let mut accounts: BTreeMap<u128, Account> = BTreeMap::new();
    let mut positions = Vec::new();
    let mut source_amount = 0i128;
    let mut start = 0;
    while start < ordered.len() {
        let entry = ordered[start].entry;
        let mut end = start + 1;
        while end < ordered.len() && ordered[end].entry == entry {
            end += 1;
        }
        let batch = &ordered[start..end];
        let mut outgoing: BTreeMap<u128, Vec<&Transfer>> = BTreeMap::new();
        let mut receivers = BTreeSet::new();
        for t in batch {
            meter.step(1)?;
            outgoing.entry(t.from).or_default().push(t);
            receivers.insert(t.to);
        }
        if outgoing.keys().any(|from| receivers.contains(from)) {
            return Err(Error::Invalid(
                "net opposing account legs before tracing an entry",
            ));
        }
        let mut arrivals: BTreeMap<u128, Vec<Lot>> = BTreeMap::new();
        for (from, targets) in outgoing {
            let mut capacities: Vec<i128> = targets.iter().map(|t| t.amount).collect();
            let total = capacities
                .iter()
                .try_fold(0, |a, b| add(a, *b, "entry outflow"))?;
            let chunks = if assets.contains(&from) {
                accounts
                    .entry(from)
                    .or_default()
                    .withdraw(total, law, &mut meter)?
            } else {
                meter.fragment()?;
                vec![Lot {
                    amount: total,
                    path: Vec::new(),
                }]
            };
            for lot in chunks {
                let shares = split(lot.amount, &capacities, &mut allocate, &mut meter)?;
                for ((t, capacity), share) in targets.iter().zip(&mut capacities).zip(shares) {
                    if share == 0 {
                        continue;
                    }
                    meter.fragment()?;
                    *capacity -= share;
                    let hop = Hop {
                        entry,
                        from,
                        to: t.to,
                    };
                    let path = if entry == source_entry && t.to == source_account {
                        source_amount = add(source_amount, share, "source deposit")?;
                        meter.path(&[], hop)?
                    } else if lot.path.is_empty() {
                        Vec::new()
                    } else {
                        meter.path(&lot.path, hop)?
                    };
                    if assets.contains(&t.to) {
                        arrivals.entry(t.to).or_default().push(Lot {
                            amount: share,
                            path,
                        });
                    } else if !path.is_empty() {
                        positions.push(Position {
                            account: t.to,
                            disposition: Disposition::Spent,
                            amount: share,
                            path,
                        });
                    }
                }
            }
            if capacities.iter().any(|capacity| *capacity != 0) {
                return Err(Error::Allocation);
            }
        }
        // Atomic-entry semantics: no incoming money funds another leg of
        // this same entry. Entry IDs do not imply a fictitious within-entry time.
        for (account, lots) in arrivals {
            accounts.entry(account).or_default().deposit(
                account,
                lots,
                &mut positions,
                &mut allocate,
                &mut meter,
            )?;
        }
        start = end;
    }
    if source_amount == 0 {
        return Err(Error::Invalid(
            "source has no positive net deposit in the selected scope",
        ));
    }
    for (account, state) in accounts {
        let mut held = 0i128;
        for lot in state.lots {
            meter.step(1)?;
            held = add(held, lot.amount, "account held lots")?;
            if !lot.path.is_empty() {
                positions.push(Position {
                    account: account,
                    disposition: Disposition::Held,
                    amount: lot.amount,
                    path: lot.path,
                });
            }
        }
        if held != state.balance.max(0) {
            return Err(Error::Invalid("lots do not reconcile to account balance"));
        }
    }
    let n = positions.len() as u64;
    meter.step(
        n.saturating_mul(u64::from(n.max(1).ilog2()) + 1)
            .saturating_mul(limits.max_hops as u64),
    )?;
    positions.sort_by(|a, b| {
        (a.account, a.disposition, &a.path).cmp(&(b.account, b.disposition, &b.path))
    });
    let attributed = positions.iter().try_fold(0, |sum, position| {
        add(sum, position.amount, "source conservation")
    })?;
    if attributed != source_amount {
        return Err(Error::Invalid(
            "source does not equal held plus spent plus overdraft repayment",
        ));
    }
    Ok(Report {
        source_amount,
        positions,
        steps: meter.steps,
    })
}

#[derive(Clone, Debug)]
struct RationalLot {
    amount: Rate,
    path: Vec<Hop>,
}

#[derive(Default)]
struct ProRataAccount {
    balance: i128,
    lots: Vec<RationalLot>,
}

fn add_rational_lot<C>(
    lots: &mut Vec<RationalLot>,
    amount: Rate,
    path: Vec<Hop>,
    budget: &mut ArithmeticBudget<'_, C>,
    meter: &mut Meter,
) -> Result<(), Error> {
    if amount.is_zero() {
        return Ok(());
    }
    meter.step(path.len() as u64 + 1)?;
    if let Some(existing) = lots.iter_mut().find(|lot| lot.path == path) {
        existing.amount = existing
            .amount
            .checked_add(budget, &amount)
            .map_err(|_| Error::Allocation)?;
    } else {
        meter.fragment()?;
        lots.push(RationalLot { amount, path });
    }
    Ok(())
}

fn add_terminal_rational<C>(
    terminal: &mut BTreeMap<(u128, Disposition, Vec<Hop>), Rate>,
    account: u128,
    disposition: Disposition,
    amount: Rate,
    path: Vec<Hop>,
    budget: &mut ArithmeticBudget<'_, C>,
    meter: &mut Meter,
) -> Result<(), Error> {
    if amount.is_zero() {
        return Ok(());
    }
    meter.step(path.len() as u64 + 1)?;
    let key = (account, disposition, path);
    if let Some(existing) = terminal.get_mut(&key) {
        *existing = existing
            .checked_add(budget, &amount)
            .map_err(|_| Error::Allocation)?;
    } else {
        meter.fragment()?;
        terminal.insert(key, amount);
    }
    Ok(())
}

fn trace_pro_rata(
    ordered: &[Transfer],
    assets: &BTreeSet<u128>,
    source: (u128, u128),
    meter: &mut Meter,
) -> Result<Report, Error> {
    let (source_entry, source_account) = source;
    let cx = Cx::detached_cancel_context();
    let budget_steps = meter.limits.max_steps.saturating_mul(64).max(1_000_000);
    let mut budget = ArithmeticBudget::new(&cx, BudgetLimits::uniform(budget_steps, 0), 65_536);
    let mut accounts: BTreeMap<u128, ProRataAccount> = BTreeMap::new();
    let mut terminal: BTreeMap<(u128, Disposition, Vec<Hop>), Rate> = BTreeMap::new();
    let mut source_amount = 0i128;
    let mut start = 0;
    while start < ordered.len() {
        let entry = ordered[start].entry;
        let mut end = start + 1;
        while end < ordered.len() && ordered[end].entry == entry {
            end += 1;
        }
        let batch = &ordered[start..end];
        let mut outgoing: BTreeMap<u128, Vec<&Transfer>> = BTreeMap::new();
        let mut incoming_totals: BTreeMap<u128, i128> = BTreeMap::new();
        for t in batch {
            meter.step(1)?;
            outgoing.entry(t.from).or_default().push(t);
            let slot = incoming_totals.entry(t.to).or_insert(0);
            *slot = add(*slot, t.amount, "entry inflow")?;
        }
        if outgoing
            .keys()
            .any(|from| incoming_totals.contains_key(from))
        {
            return Err(Error::Invalid(
                "net opposing account legs before tracing an entry",
            ));
        }
        let mut arrivals: BTreeMap<u128, Vec<RationalLot>> = BTreeMap::new();
        for (from, targets) in outgoing {
            let total = targets
                .iter()
                .try_fold(0i128, |a, t| add(a, t.amount, "entry outflow"))?;
            if assets.contains(&from) {
                let acct = accounts.entry(from).or_default();
                let bal_before = acct.balance;
                acct.balance = acct
                    .balance
                    .checked_sub(total)
                    .ok_or(Error::Overflow("account withdrawal"))?;
                if bal_before <= 0 || acct.lots.is_empty() {
                    meter.fragment()?;
                    acct.lots.clear();
                } else {
                    if total > bal_before {
                        meter.fragment()?;
                    }
                    let denom =
                        u128::try_from(bal_before.max(total)).map_err(|_| Error::Allocation)?;
                    let old_lots = core::mem::take(&mut acct.lots);
                    for lot in old_lots {
                        meter.fragment()?;
                        for t in &targets {
                            if entry == source_entry && t.to == source_account {
                                continue;
                            }
                            let ratio = Rate::new(&mut budget, t.amount as u128, denom)
                                .map_err(|_| Error::Allocation)?;
                            let share = lot
                                .amount
                                .checked_mul(&mut budget, &ratio)
                                .map_err(|_| Error::Allocation)?;
                            let hop = Hop {
                                entry,
                                from,
                                to: t.to,
                            };
                            let path = meter.path(&lot.path, hop)?;
                            if assets.contains(&t.to) {
                                add_rational_lot(
                                    arrivals.entry(t.to).or_default(),
                                    share,
                                    path,
                                    &mut budget,
                                    meter,
                                )?;
                            } else {
                                add_terminal_rational(
                                    &mut terminal,
                                    t.to,
                                    Disposition::Spent,
                                    share,
                                    path,
                                    &mut budget,
                                    meter,
                                )?;
                            }
                        }
                        if total < bal_before {
                            let keep_ratio =
                                Rate::new(&mut budget, (bal_before - total) as u128, denom)
                                    .map_err(|_| Error::Allocation)?;
                            let kept = lot
                                .amount
                                .checked_mul(&mut budget, &keep_ratio)
                                .map_err(|_| Error::Allocation)?;
                            add_rational_lot(&mut acct.lots, kept, lot.path, &mut budget, meter)?;
                        }
                    }
                }
            } else {
                meter.fragment()?;
            }
            for t in &targets {
                if entry == source_entry && t.to == source_account {
                    source_amount = add(source_amount, t.amount, "source deposit")?;
                    let hop = Hop {
                        entry,
                        from,
                        to: t.to,
                    };
                    let path = meter.path(&[], hop)?;
                    let share = Rate::new(&mut budget, t.amount as u128, 1)
                        .map_err(|_| Error::Allocation)?;
                    add_rational_lot(
                        arrivals.entry(t.to).or_default(),
                        share,
                        path,
                        &mut budget,
                        meter,
                    )?;
                }
            }
        }
        for (account, total_deposit) in incoming_totals {
            if !assets.contains(&account) {
                continue;
            }
            let acct = accounts.entry(account).or_default();
            let repaid = if acct.balance < 0 {
                i128::try_from(acct.balance.unsigned_abs().min(total_deposit as u128))
                    .map_err(|_| Error::Overflow("overdraft"))?
            } else {
                0
            };
            acct.balance = add(acct.balance, total_deposit, "account deposit")?;
            if let Some(lots) = arrivals.remove(&account) {
                let total_u = u128::try_from(total_deposit).map_err(|_| Error::Allocation)?;
                for lot in lots {
                    meter.step(1)?;
                    if repaid > 0 {
                        let rep_ratio = Rate::new(&mut budget, repaid as u128, total_u)
                            .map_err(|_| Error::Allocation)?;
                        let rep_share = lot
                            .amount
                            .checked_mul(&mut budget, &rep_ratio)
                            .map_err(|_| Error::Allocation)?;
                        add_terminal_rational(
                            &mut terminal,
                            account,
                            Disposition::RepaidOverdraft,
                            rep_share,
                            lot.path.clone(),
                            &mut budget,
                            meter,
                        )?;
                    }
                    if total_deposit > repaid {
                        let surv_ratio =
                            Rate::new(&mut budget, (total_deposit - repaid) as u128, total_u)
                                .map_err(|_| Error::Allocation)?;
                        let surv_share = lot
                            .amount
                            .checked_mul(&mut budget, &surv_ratio)
                            .map_err(|_| Error::Allocation)?;
                        add_rational_lot(&mut acct.lots, surv_share, lot.path, &mut budget, meter)?;
                    }
                }
            }
        }
        start = end;
    }
    if source_amount == 0 {
        return Err(Error::Invalid(
            "source has no positive net deposit in the selected scope",
        ));
    }
    for (account, state) in accounts {
        for lot in state.lots {
            add_terminal_rational(
                &mut terminal,
                account,
                Disposition::Held,
                lot.amount,
                lot.path,
                &mut budget,
                meter,
            )?;
        }
    }
    let keys: Vec<(u128, Disposition, Vec<Hop>)> = terminal.keys().cloned().collect();
    let shares: Vec<Rate> = terminal.values().cloned().collect();
    let n = keys.len() as u64;
    meter.step(
        n.saturating_mul(u64::from(n.max(1).ilog2()) + 1)
            .saturating_mul(meter.limits.max_hops as u64),
    )?;
    let rounded = Rate::round_largest_remainder(&mut budget, source_amount, &shares)
        .map_err(|_| Error::Allocation)?;
    let mut positions = Vec::new();
    for ((account, disposition, path), amount) in keys.into_iter().zip(rounded) {
        if amount > 0 {
            positions.push(Position {
                account,
                disposition,
                amount,
                path,
            });
        }
    }
    let attributed = positions
        .iter()
        .try_fold(0i128, |sum, p| add(sum, p.amount, "source conservation"))?;
    if attributed != source_amount {
        return Err(Error::Invalid(
            "source does not equal held plus spent plus overdraft repayment",
        ));
    }
    Ok(Report {
        source_amount,
        positions,
        steps: meter.steps,
    })
}

#[derive(Clone, Debug)]
struct DagEdge {
    from: usize,
    to: usize,
    cap: i128,
    flow: i128,
    cost: i32,
    hop: Option<Hop>,
    terminal: Option<(u128, Disposition)>,
}

fn add_dag_edge(
    edges: &mut Vec<DagEdge>,
    adj: &mut [Vec<usize>],
    rev_adj: &mut [Vec<usize>],
    edge: DagEdge,
) {
    let idx = edges.len();
    adj[edge.from].push(idx);
    rev_adj[edge.to].push(idx);
    edges.push(edge);
}

#[allow(clippy::too_many_lines)]
fn trace_libr(
    ordered: &[Transfer],
    assets: &BTreeSet<u128>,
    source: (u128, u128),
    replenish_entries: &BTreeSet<u128>,
    meter: &mut Meter,
) -> Result<Report, Error> {
    let (source_entry, source_account) = source;
    let mut batches: Vec<&[Transfer]> = Vec::new();
    let mut start = 0;
    while start < ordered.len() {
        let entry = ordered[start].entry;
        let mut end = start + 1;
        while end < ordered.len() && ordered[end].entry == entry {
            end += 1;
        }
        batches.push(&ordered[start..end]);
        start = end;
    }

    let mut source_batch_idx: Option<usize> = None;
    let mut source_amount = 0i128;
    let mut active_assets: BTreeSet<u128> = BTreeSet::from([source_account]);
    for (b_idx, batch) in batches.iter().enumerate() {
        let mut outgoing = BTreeSet::new();
        let mut receivers = BTreeSet::new();
        for t in *batch {
            meter.step(1)?;
            outgoing.insert(t.from);
            receivers.insert(t.to);
            if assets.contains(&t.from) {
                active_assets.insert(t.from);
            }
            if assets.contains(&t.to) {
                active_assets.insert(t.to);
            }
            if t.entry == source_entry && t.to == source_account {
                source_batch_idx = Some(b_idx);
                source_amount = add(source_amount, t.amount, "source deposit")?;
            }
        }
        if outgoing.iter().any(|from| receivers.contains(from)) {
            return Err(Error::Invalid(
                "net opposing account legs before tracing an entry",
            ));
        }
    }
    let Some(b_source) = source_batch_idx else {
        return Err(Error::Invalid(
            "source has no positive net deposit in the selected scope",
        ));
    };
    if source_amount == 0 {
        return Err(Error::Invalid(
            "source has no positive net deposit in the selected scope",
        ));
    }

    // Forward pass to compute exact intermediate account balances and overdraft repayments.
    let num_batches = batches.len();
    let mut balances: BTreeMap<u128, i128> = BTreeMap::new();
    let mut hold_caps: Vec<BTreeMap<u128, i128>> = vec![BTreeMap::new(); num_batches];
    let mut survive_caps: Vec<BTreeMap<u128, i128>> = vec![BTreeMap::new(); num_batches];
    let mut repaid_caps: Vec<BTreeMap<u128, i128>> = vec![BTreeMap::new(); num_batches];

    for (b_idx, batch) in batches.iter().enumerate() {
        let mut outflows: BTreeMap<u128, i128> = BTreeMap::new();
        let mut inflows: BTreeMap<u128, i128> = BTreeMap::new();
        for t in *batch {
            meter.step(1)?;
            if assets.contains(&t.from) {
                let s = outflows.entry(t.from).or_insert(0);
                *s = add(*s, t.amount, "entry outflow")?;
            }
            if assets.contains(&t.to) {
                let s = inflows.entry(t.to).or_insert(0);
                *s = add(*s, t.amount, "entry inflow")?;
            }
        }
        for (from, out) in outflows {
            let bal = balances.entry(from).or_insert(0);
            *bal = bal
                .checked_sub(out)
                .ok_or(Error::Overflow("account withdrawal"))?;
        }
        for &a in &active_assets {
            let mid = balances.get(&a).copied().unwrap_or(0);
            if mid > 0 {
                hold_caps[b_idx].insert(a, mid.min(source_amount));
            }
        }
        for (to, inf) in inflows {
            let bal = balances.entry(to).or_insert(0);
            let repaid = if *bal < 0 {
                i128::try_from(bal.unsigned_abs().min(inf as u128))
                    .map_err(|_| Error::Overflow("overdraft"))?
            } else {
                0
            };
            let survive = inf - repaid;
            *bal = add(*bal, inf, "account deposit")?;
            if repaid > 0 {
                repaid_caps[b_idx].insert(to, repaid.min(source_amount));
            }
            if survive > 0 {
                survive_caps[b_idx].insert(to, survive.min(source_amount));
            }
        }
    }

    // Build time-expanded DAG from b_source..=num_batches.
    let asset_vec: Vec<u128> = active_assets.iter().copied().collect();
    let asset_idx: BTreeMap<u128, usize> =
        asset_vec.iter().enumerate().map(|(i, &a)| (a, i)).collect();
    let a_count = asset_vec.len();
    let v_source = 0usize;
    let v_held_sink = 1usize;
    let v_diss_sink = 2usize;
    let state_base = 3usize;
    let state_node =
        |a: u128, step: usize| -> usize { state_base + step * a_count + asset_idx[&a] };
    let arrive_base = state_base + (num_batches + 1) * a_count;
    let arrive_node =
        |a: u128, b_idx: usize| -> usize { arrive_base + b_idx * a_count + asset_idx[&a] };
    let mut next_vertex = arrive_base + num_batches * a_count;
    let mut diss_nodes: Vec<(usize, usize, Transfer)> = Vec::new();
    let mut rep_nodes: Vec<(usize, usize, Transfer)> = Vec::new();
    for (b_idx, batch) in batches.iter().enumerate().skip(b_source) {
        for &t in *batch {
            if b_idx > b_source && assets.contains(&t.from) && !assets.contains(&t.to) {
                diss_nodes.push((next_vertex, b_idx, t));
                next_vertex += 1;
            }
            if b_idx > b_source
                && !assets.contains(&t.from)
                && t.to == source_account
                && replenish_entries.contains(&t.entry)
            {
                rep_nodes.push((next_vertex, b_idx, t));
                next_vertex += 1;
            }
        }
    }

    let mut edges: Vec<DagEdge> = Vec::new();
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); next_vertex];
    let mut rev_adj: Vec<Vec<usize>> = vec![Vec::new(); next_vertex];

    // Source injection at b_source.
    for &t in batches[b_source] {
        if t.entry == source_entry && t.to == source_account {
            meter.fragment()?;
            add_dag_edge(
                &mut edges,
                &mut adj,
                &mut rev_adj,
                DagEdge {
                    from: v_source,
                    to: arrive_node(source_account, b_source),
                    cap: t.amount,
                    flow: 0,
                    cost: 1,
                    hop: Some(Hop {
                        entry: t.entry,
                        from: t.from,
                        to: t.to,
                    }),
                    terminal: None,
                },
            );
        }
    }
    if let Some(&survive) = survive_caps[b_source].get(&source_account) {
        add_dag_edge(
            &mut edges,
            &mut adj,
            &mut rev_adj,
            DagEdge {
                from: arrive_node(source_account, b_source),
                to: state_node(source_account, b_source + 1),
                cap: survive,
                flow: 0,
                cost: 0,
                hop: None,
                terminal: None,
            },
        );
    }

    // Subsequent batches b_source + 1 .. num_batches.
    for (b_idx, batch) in batches.iter().enumerate().skip(b_source + 1) {
        // Priority 0: holding edges (cost 0, explored before transfer edges).
        for &a in &asset_vec {
            if let Some(&hcap) = hold_caps[b_idx].get(&a) {
                add_dag_edge(
                    &mut edges,
                    &mut adj,
                    &mut rev_adj,
                    DagEdge {
                        from: state_node(a, b_idx),
                        to: state_node(a, b_idx + 1),
                        cap: hcap,
                        flow: 0,
                        cost: 0,
                        hop: None,
                        terminal: None,
                    },
                );
            }
        }
        // Priority 1: asset-to-asset transfer edges (cost 1).
        for &t in *batch {
            if assets.contains(&t.from) && assets.contains(&t.to) {
                add_dag_edge(
                    &mut edges,
                    &mut adj,
                    &mut rev_adj,
                    DagEdge {
                        from: state_node(t.from, b_idx),
                        to: arrive_node(t.to, b_idx),
                        cap: t.amount.min(source_amount),
                        flow: 0,
                        cost: 1,
                        hop: Some(Hop {
                            entry: t.entry,
                            from: t.from,
                            to: t.to,
                        }),
                        terminal: None,
                    },
                );
            }
        }
        // Arrival survival edges (cost 0).
        for &a in &asset_vec {
            if let Some(&survive) = survive_caps[b_idx].get(&a) {
                add_dag_edge(
                    &mut edges,
                    &mut adj,
                    &mut rev_adj,
                    DagEdge {
                        from: arrive_node(a, b_idx),
                        to: state_node(a, b_idx + 1),
                        cap: survive,
                        flow: 0,
                        cost: 0,
                        hop: None,
                        terminal: None,
                    },
                );
            }
        }
    }

    // Dissipation nodes (for Spent and optional OnEvidence replenishment).
    for &(d_node, b_idx, t) in &diss_nodes {
        add_dag_edge(
            &mut edges,
            &mut adj,
            &mut rev_adj,
            DagEdge {
                from: state_node(t.from, b_idx),
                to: d_node,
                cap: t.amount.min(source_amount),
                flow: 0,
                cost: 0,
                hop: None,
                terminal: None,
            },
        );
    }
    for &(r_node, r_b_idx, t_rep) in &rep_nodes {
        for &(d_node, d_b_idx, t_diss) in &diss_nodes {
            if d_b_idx < r_b_idx && t_diss.from == source_account {
                add_dag_edge(
                    &mut edges,
                    &mut adj,
                    &mut rev_adj,
                    DagEdge {
                        from: d_node,
                        to: r_node,
                        cap: t_diss.amount.min(source_amount),
                        flow: 0,
                        cost: 0,
                        hop: None,
                        terminal: None,
                    },
                );
            }
        }
        add_dag_edge(
            &mut edges,
            &mut adj,
            &mut rev_adj,
            DagEdge {
                from: r_node,
                to: arrive_node(source_account, r_b_idx),
                cap: t_rep.amount.min(source_amount),
                flow: 0,
                cost: 1,
                hop: Some(Hop {
                    entry: t_rep.entry,
                    from: t_rep.from,
                    to: source_account,
                }),
                terminal: None,
            },
        );
    }

    // Final HeldSink edges at step = num_batches.
    for &a in &asset_vec {
        let final_pos = balances.get(&a).copied().unwrap_or(0).max(0);
        if final_pos > 0 {
            add_dag_edge(
                &mut edges,
                &mut adj,
                &mut rev_adj,
                DagEdge {
                    from: state_node(a, num_batches),
                    to: v_held_sink,
                    cap: final_pos.min(source_amount),
                    flow: 0,
                    cost: 0,
                    hop: None,
                    terminal: Some((a, Disposition::Held)),
                },
            );
        }
    }

    // Phase 1: Min-Cost (shortest hop, holding-first) Max-Flow from v_source to v_held_sink.
    let mut held_flow = 0i128;
    while held_flow < source_amount {
        let Some((delta, path)) = shortest_augmenting_path(
            v_source,
            v_held_sink,
            next_vertex,
            &edges,
            &adj,
            &rev_adj,
            true,
            meter,
        )?
        else {
            break;
        };
        let push = delta.min(source_amount - held_flow);
        for (ei, forward) in path {
            if forward {
                edges[ei].flow = add(edges[ei].flow, push, "libr flow")?;
            } else {
                edges[ei].flow = edges[ei]
                    .flow
                    .checked_sub(push)
                    .ok_or(Error::Overflow("libr reverse flow"))?;
            }
        }
        held_flow = add(held_flow, push, "libr held flow")?;
    }

    // Self-certifying Max-Flow = Min-Cut witness check on the Phase 1 network.
    let mut reachable = vec![false; next_vertex];
    let mut queue = VecDeque::new();
    reachable[v_source] = true;
    queue.push_back(v_source);
    while let Some(u) = queue.pop_front() {
        meter.step(1)?;
        for &ei in &adj[u] {
            let e = &edges[ei];
            if e.cap > e.flow && !reachable[e.to] {
                reachable[e.to] = true;
                queue.push_back(e.to);
            }
        }
        for &ei in &rev_adj[u] {
            let e = &edges[ei];
            if e.flow > 0 && !reachable[e.from] {
                reachable[e.from] = true;
                queue.push_back(e.from);
            }
        }
    }
    if reachable[v_held_sink] {
        return Err(Error::Invalid(
            "LIBR phase 1 terminated with augmenting path remaining",
        ));
    }
    let mut min_cut_cap = 0i128;
    for e in &edges {
        if reachable[e.from] && !reachable[e.to] {
            min_cut_cap = min_cut_cap.saturating_add(e.cap);
        }
    }
    if min_cut_cap.min(source_amount) != held_flow {
        return Err(Error::Invalid("LIBR max-flow did not equal min-cut"));
    }

    // Phase 2: Route remaining (source_amount - held_flow) to v_diss_sink.
    for (b_idx, _) in batches.iter().enumerate().skip(b_source) {
        for (&a, &rep) in &repaid_caps[b_idx] {
            add_dag_edge(
                &mut edges,
                &mut adj,
                &mut rev_adj,
                DagEdge {
                    from: arrive_node(a, b_idx),
                    to: v_diss_sink,
                    cap: rep,
                    flow: 0,
                    cost: 0,
                    hop: None,
                    terminal: Some((a, Disposition::RepaidOverdraft)),
                },
            );
        }
    }
    for &(d_node, _, t) in &diss_nodes {
        add_dag_edge(
            &mut edges,
            &mut adj,
            &mut rev_adj,
            DagEdge {
                from: d_node,
                to: v_diss_sink,
                cap: t.amount.min(source_amount),
                flow: 0,
                cost: 1,
                hop: Some(Hop {
                    entry: t.entry,
                    from: t.from,
                    to: t.to,
                }),
                terminal: Some((t.to, Disposition::Spent)),
            },
        );
    }

    let mut total_flow = held_flow;
    while total_flow < source_amount {
        let Some((delta, path)) = shortest_augmenting_path(
            v_source,
            v_diss_sink,
            next_vertex,
            &edges,
            &adj,
            &rev_adj,
            false,
            meter,
        )?
        else {
            return Err(Error::Invalid(
                "source does not equal held plus spent plus overdraft repayment",
            ));
        };
        let push = delta.min(source_amount - total_flow);
        for (ei, forward) in path {
            if forward {
                edges[ei].flow = add(edges[ei].flow, push, "libr diss flow")?;
            } else {
                edges[ei].flow = edges[ei]
                    .flow
                    .checked_sub(push)
                    .ok_or(Error::Overflow("libr diss reverse flow"))?;
            }
        }
        total_flow = add(total_flow, push, "libr total flow")?;
    }

    // Decompose DAG flow into canonical Positions.
    let mut merged: BTreeMap<(u128, Disposition, Vec<Hop>), i128> = BTreeMap::new();
    loop {
        let mut u = v_source;
        let mut path_edges: Vec<usize> = Vec::new();
        let mut hops: Vec<Hop> = Vec::new();
        while u != v_held_sink && u != v_diss_sink {
            meter.step(1)?;
            let Some(&ei) = adj[u].iter().find(|&&ei| edges[ei].flow > 0) else {
                break;
            };
            path_edges.push(ei);
            if let Some(hop) = edges[ei].hop {
                if !hops.is_empty() {
                    meter.fragment()?;
                }
                hops = meter.path(&hops, hop)?;
            }
            u = edges[ei].to;
        }
        if path_edges.is_empty() {
            break;
        }
        let last_edge = &edges[*path_edges.last().unwrap()];
        let Some((account, disposition)) = last_edge.terminal else {
            return Err(Error::Invalid("unterminated LIBR flow path"));
        };
        if disposition == Disposition::RepaidOverdraft {
            meter.fragment()?;
        }
        let delta = path_edges
            .iter()
            .map(|&ei| edges[ei].flow)
            .min()
            .unwrap_or(0);
        for &ei in &path_edges {
            edges[ei].flow -= delta;
        }
        let slot = merged.entry((account, disposition, hops)).or_insert(0);
        *slot = add(*slot, delta, "merged position")?;
    }

    let mut positions: Vec<Position> = merged
        .into_iter()
        .filter(|(_, amount)| *amount > 0)
        .map(|((account, disposition, path), amount)| Position {
            account,
            disposition,
            amount,
            path,
        })
        .collect();
    let n = positions.len() as u64;
    meter.step(
        n.saturating_mul(u64::from(n.max(1).ilog2()) + 1)
            .saturating_mul(meter.limits.max_hops as u64),
    )?;
    positions.sort_by(|a, b| {
        (a.account, a.disposition, &a.path).cmp(&(b.account, b.disposition, &b.path))
    });
    let attributed = positions
        .iter()
        .try_fold(0i128, |sum, p| add(sum, p.amount, "source conservation"))?;
    if attributed != source_amount {
        return Err(Error::Invalid(
            "source does not equal held plus spent plus overdraft repayment",
        ));
    }
    Ok(Report {
        source_amount,
        positions,
        steps: meter.steps,
    })
}

#[allow(clippy::too_many_arguments)]
fn shortest_augmenting_path(
    source: usize,
    sink: usize,
    num_vertices: usize,
    edges: &[DagEdge],
    adj: &[Vec<usize>],
    rev_adj: &[Vec<usize>],
    allow_reverse: bool,
    meter: &mut Meter,
) -> Result<Option<(i128, Vec<(usize, bool)>)>, Error> {
    let mut dist = vec![i32::MAX; num_vertices];
    let mut parent: Vec<Option<(usize, usize, bool)>> = vec![None; num_vertices];
    let mut in_queue = vec![false; num_vertices];
    let mut queue = VecDeque::new();
    dist[source] = 0;
    in_queue[source] = true;
    queue.push_back(source);
    while let Some(u) = queue.pop_front() {
        in_queue[u] = false;
        meter.step(1)?;
        for &ei in &adj[u] {
            let e = &edges[ei];
            if e.cap > e.flow {
                let next_cost = dist[u].saturating_add(e.cost);
                if next_cost < dist[e.to] {
                    dist[e.to] = next_cost;
                    parent[e.to] = Some((u, ei, true));
                    if !in_queue[e.to] {
                        in_queue[e.to] = true;
                        queue.push_back(e.to);
                    }
                }
            }
        }
        if allow_reverse {
            for &ei in &rev_adj[u] {
                let e = &edges[ei];
                if e.flow > 0 {
                    let next_cost = dist[u].saturating_sub(e.cost);
                    if next_cost < dist[e.from] {
                        dist[e.from] = next_cost;
                        parent[e.from] = Some((u, ei, false));
                        if !in_queue[e.from] {
                            in_queue[e.from] = true;
                            queue.push_back(e.from);
                        }
                    }
                }
            }
        }
    }
    if dist[sink] == i32::MAX {
        return Ok(None);
    }
    let mut path = Vec::new();
    let mut cur = sink;
    let mut bottleneck = i128::MAX;
    while cur != source {
        let Some((prev, ei, forward)) = parent[cur] else {
            return Ok(None);
        };
        let avail = if forward {
            edges[ei].cap - edges[ei].flow
        } else {
            edges[ei].flow
        };
        bottleneck = bottleneck.min(avail);
        path.push((ei, forward));
        cur = prev;
    }
    path.reverse();
    Ok(Some((bottleneck, path)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Literal Hamilton allocation for small oracle fixtures. Large boundary
    // fixtures have one nonzero target and never multiply large integers.
    fn allocate(amount: i128, capacities: &[i128]) -> Result<Vec<i128>, Error> {
        let sum: i128 = capacities.iter().sum();
        if sum < amount || sum == 0 {
            return Err(Error::Allocation);
        }
        if capacities.iter().filter(|x| **x > 0).count() == 1 {
            return Ok(capacities
                .iter()
                .map(|c| if *c > 0 { amount } else { 0 })
                .collect());
        }
        let mut shares = Vec::new();
        let mut remainders = Vec::new();
        for (i, c) in capacities.iter().enumerate() {
            let p = amount.checked_mul(*c).ok_or(Error::Allocation)?;
            shares.push(p / sum);
            remainders.push((p % sum, i));
        }
        let mut residual = amount - shares.iter().sum::<i128>();
        remainders.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        for (_, i) in remainders {
            if residual == 0 {
                break;
            }
            shares[i] += 1;
            residual -= 1;
        }
        Ok(shares)
    }

    fn limits() -> Limits {
        Limits {
            max_transfers: 1000,
            max_fragments: 100_000,
            max_hops: 64,
            max_steps: 10_000_000,
        }
    }
    fn t(entry: u128, from: u128, to: u128, amount: i128) -> Transfer {
        Transfer {
            entry,
            day: 1,
            recorded: entry as u64,
            from,
            to,
            amount,
        }
    }
    fn run(edges: &[Transfer], law: Law) -> Report {
        trace(
            edges,
            &BTreeSet::from([1, 2, 3, 4]),
            (10, 1),
            law,
            limits(),
            allocate,
        )
        .unwrap()
    }
    fn sum(r: &Report, account: u128, disposition: Disposition) -> i128 {
        r.positions
            .iter()
            .filter(|p| p.account == account && p.disposition == disposition)
            .map(|p| p.amount)
            .sum()
    }

    #[test]
    fn follows_three_accounts_and_retains_the_full_path() {
        let r = run(
            &[t(10, 9, 1, 100), t(11, 1, 2, 80), t(12, 2, 3, 60)],
            Law::Fifo,
        );
        assert_eq!(r.source_amount, 100);
        for (account, held) in [(1, 20), (2, 20), (3, 60)] {
            assert_eq!(sum(&r, account, Disposition::Held), held);
        }
        let p = r.positions.iter().find(|p| p.account == 3).unwrap();
        assert_eq!(
            p.path
                .iter()
                .map(|h| (h.entry, h.from, h.to))
                .collect::<Vec<_>>(),
            [(10, 9, 1), (11, 1, 2), (12, 2, 3)]
        );
    }

    #[test]
    fn fifo_and_lifo_consume_different_commingled_layers() {
        let edges = [
            t(9, 9, 1, 100),
            t(10, 9, 1, 100),
            t(11, 1, 2, 150),
            t(12, 2, 8, 100),
        ];
        let fifo = run(&edges, Law::Fifo);
        let lifo = run(&edges, Law::Lifo);
        assert_eq!(
            (
                sum(&fifo, 1, Disposition::Held),
                sum(&fifo, 2, Disposition::Held),
                sum(&fifo, 8, Disposition::Spent)
            ),
            (50, 50, 0)
        );
        assert_eq!(
            (
                sum(&lifo, 1, Disposition::Held),
                sum(&lifo, 2, Disposition::Held),
                sum(&lifo, 8, Disposition::Spent)
            ),
            (0, 50, 50)
        );
    }

    #[test]
    fn branches_and_returns_never_multiply_the_source() {
        let edges = [
            t(10, 9, 1, 100),
            t(11, 1, 2, 33),
            t(11, 1, 3, 67),
            t(12, 2, 1, 33),
            t(13, 1, 4, 33),
            t(14, 3, 8, 20),
        ];
        for law in [Law::Fifo, Law::Lifo] {
            let r = run(&edges, law);
            assert_eq!(sum(&r, 4, Disposition::Held), 33);
            assert_eq!(sum(&r, 3, Disposition::Held), 47);
            assert_eq!(sum(&r, 8, Disposition::Spent), 20);
            assert_eq!(r.positions.iter().map(|p| p.amount).sum::<i128>(), 100);
            let mut reversed = edges;
            reversed.reverse();
            assert_eq!(r, run(&reversed, law));
        }
    }

    #[test]
    fn prior_overdrafts_and_destination_overdrafts_are_explicit_dissipation() {
        let edges = [
            t(1, 1, 8, 20),
            t(2, 2, 8, 30),
            t(10, 9, 1, 100),
            t(11, 1, 2, 80),
            t(12, 9, 2, 500),
        ];
        let r = run(&edges, Law::Fifo);
        assert_eq!(sum(&r, 1, Disposition::RepaidOverdraft), 20);
        assert_eq!(sum(&r, 2, Disposition::RepaidOverdraft), 30);
        assert_eq!(sum(&r, 2, Disposition::Held), 50);
        assert_eq!(r.positions.iter().map(|p| p.amount).sum::<i128>(), 100);
    }

    #[test]
    fn same_day_recorded_order_precedes_hashed_entry_identity() {
        let mut edges = [t(10, 9, 1, 10), t(1, 1, 2, 10)];
        edges[1].recorded = 11;
        assert_eq!(sum(&run(&edges, Law::Fifo), 2, Disposition::Held), 10);
        edges[1].recorded = 9;
        let r = run(&edges, Law::Fifo);
        assert_eq!(sum(&r, 1, Disposition::RepaidOverdraft), 10);
        assert_eq!(sum(&r, 2, Disposition::Held), 0);
    }

    #[test]
    fn bounds_and_malformed_inputs_fail_without_partial_reports() {
        let edges = [t(10, 9, 1, 10), t(11, 1, 2, 10), t(12, 2, 3, 10)];
        let assets = BTreeSet::from([1, 2, 3]);
        for (l, expected) in [
            (
                Limits {
                    max_hops: 2,
                    ..limits()
                },
                Error::Limit("max_hops"),
            ),
            (
                Limits {
                    max_transfers: 2,
                    ..limits()
                },
                Error::Limit("max_transfers"),
            ),
            (
                Limits {
                    max_steps: 1,
                    ..limits()
                },
                Error::Limit("max_steps"),
            ),
            (
                Limits {
                    max_fragments: 1,
                    ..limits()
                },
                Error::Limit("max_fragments"),
            ),
        ] {
            assert_eq!(
                trace(&edges, &assets, (10, 1), Law::Fifo, l, allocate),
                Err(expected)
            );
        }
        for bad in [
            vec![t(10, 9, 1, -1)],
            vec![t(10, 1, 1, 1)],
            vec![t(10, 9, 1, 2), t(10, 1, 2, 1)],
        ] {
            assert!(trace(&bad, &assets, (10, 1), Law::Fifo, limits(), allocate).is_err());
        }
        assert!(trace(&edges, &assets, (99, 1), Law::Fifo, limits(), allocate).is_err());
        assert!(
            trace(&edges, &assets, (10, 1), Law::Fifo, limits(), |_, caps| Ok(
                vec![0; caps.len()]
            ))
            .is_err()
        );
    }

    #[test]
    fn i128_boundary_and_repeated_turnover_do_not_accumulate_dormant_balances() {
        let edges = [t(1, 1, 8, i128::MAX), t(2, 1, 8, 1), t(10, 9, 1, 1)];
        for law in [Law::Fifo, Law::Lifo] {
            let r = run(&edges, law);
            assert_eq!(sum(&r, 1, Disposition::RepaidOverdraft), 1);
            let r = run(
                &[
                    t(10, 9, 1, i128::MAX),
                    t(11, 1, 2, i128::MAX),
                    t(12, 2, 1, i128::MAX),
                    t(13, 1, 2, i128::MAX),
                ],
                law,
            );
            assert_eq!(sum(&r, 2, Disposition::Held), i128::MAX);
        }
    }

    #[test]
    fn differential_against_a_literal_token_ledger() {
        for seed in 1..=128u64 {
            for law in [Law::Fifo, Law::Lifo] {
                let mut state = seed;
                let mut edges = vec![t(1, 9, 1, 8), t(2, 9, 2, 8), t(3, 9, 3, 8), t(10, 9, 1, 7)];
                let mut tokens: BTreeMap<u128, VecDeque<bool>> = BTreeMap::from([
                    (1, VecDeque::from(vec![false; 8])),
                    (2, VecDeque::from(vec![false; 8])),
                    (3, VecDeque::from(vec![false; 8])),
                ]);
                tokens.get_mut(&1).unwrap().extend(vec![true; 7]);
                let mut spent = 0;
                for entry in 11..=70 {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    let from = u128::from(state % 3 + 1);
                    let to = if state & 8 == 0 { 8 } else { from % 3 + 1 };
                    let available = tokens[&from].len();
                    let amount = ((state >> 16) as usize % 4).min(available);
                    if amount == 0 {
                        continue;
                    }
                    edges.push(t(entry, from, to, amount as i128));
                    let mut moved = Vec::new();
                    for _ in 0..amount {
                        moved.push(match law {
                            Law::Fifo => tokens.get_mut(&from).unwrap().pop_front().unwrap(),
                            Law::Lifo => tokens.get_mut(&from).unwrap().pop_back().unwrap(),
                            Law::Libr | Law::ProRata => unreachable!(),
                        });
                    }
                    if to == 8 {
                        spent += moved.iter().filter(|t| **t).count() as i128;
                    } else {
                        tokens.get_mut(&to).unwrap().extend(moved);
                    }
                }
                let r = run(&edges, law);
                for account in 1..=3 {
                    assert_eq!(
                        sum(&r, account, Disposition::Held),
                        tokens[&account].iter().filter(|t| **t).count() as i128,
                        "seed {seed}, {law:?}, account {account}"
                    );
                }
                assert_eq!(
                    sum(&r, 8, Disposition::Spent),
                    spent,
                    "seed {seed}, {law:?}"
                );
            }
        }
    }

    #[test]
    fn five_account_twenty_entry_graph_distinguishes_all_four_tracing_laws() {
        let assets = BTreeSet::from([1, 2, 3, 4, 5]);
        let edges = [
            // 5 clean pre-source funding entries across accounts 1..=5.
            t(1, 9, 1, 100),
            t(2, 9, 2, 50),
            t(3, 9, 3, 50),
            t(4, 9, 4, 50),
            t(5, 9, 5, 50),
            // 4 clean pre-source churn entries.
            t(6, 2, 3, 10),
            t(7, 3, 2, 10),
            t(8, 4, 5, 10),
            t(9, 5, 4, 10),
            // Source deposit of 100 into account 1 (pool in 1 is now 100 clean + 100 tainted = 200).
            t(10, 9, 1, 100),
            // Transfer 100 from 1 -> 2 (pool in 2 becomes 150).
            t(11, 1, 2, 100),
            // Spend 60 from 1 -> 8 (leaving 40 in account 1).
            t(12, 1, 8, 60),
            // Transfer 60 from 2 -> 3 (leaving 90 in account 2; pool in 3 becomes 110).
            t(13, 2, 3, 60),
            // Spend 75 from 2 -> 8 (leaving 15 in account 2).
            t(14, 2, 8, 75),
            // Transfer 55 from 3 -> 4 (leaving 55 in account 3; pool in 4 becomes 105).
            t(15, 3, 4, 55),
            // Transfer 35 from 4 -> 5 (leaving 70 in account 4; pool in 5 becomes 85).
            t(16, 4, 5, 35),
            // Spend 20 from 3 -> 8 (leaving 35 in account 3).
            t(17, 3, 8, 20),
            // Spend 15 from 4 -> 8 (leaving 55 in account 4).
            t(18, 4, 8, 15),
            // Spend 10 from 5 -> 8 (leaving 75 in account 5).
            t(19, 5, 8, 10),
            // Clean deposit into 5 after spend.
            t(20, 9, 5, 25),
        ];
        assert_eq!(edges.len(), 20);

        let schedules: Vec<(Law, [i128; 5], i128)> =
            [Law::Libr, Law::Fifo, Law::Lifo, Law::ProRata]
                .into_iter()
                .map(|law| {
                    let r = trace(&edges, &assets, (10, 1), law, limits(), allocate).unwrap();
                    assert_eq!(
                        r.positions.iter().map(|p| p.amount).sum::<i128>(),
                        100,
                        "conservation failed for {law:?}"
                    );
                    let held = [
                        sum(&r, 1, Disposition::Held),
                        sum(&r, 2, Disposition::Held),
                        sum(&r, 3, Disposition::Held),
                        sum(&r, 4, Disposition::Held),
                        sum(&r, 5, Disposition::Held),
                    ];
                    let total_held: i128 = held.iter().sum();
                    (law, held, total_held)
                })
                .collect();

        // Every law produces a distinct 5-account held schedule.
        for i in 0..schedules.len() {
            for j in (i + 1)..schedules.len() {
                assert_ne!(
                    schedules[i].1, schedules[j].1,
                    "{:?} and {:?} should produce distinct held schedules",
                    schedules[i].0, schedules[j].0
                );
            }
        }
        // LIBR retains the full 100 across the network (40 in acct 1, 15 in acct 2, 35 in acct 3, 10 in acct 4).
        assert_eq!(schedules[0].1, [40, 15, 35, 10, 0]);
        assert_eq!(schedules[0].2, 100);
        // FIFO keeps all 100 tainted in acct 1 at step 11 (since 100 old clean moves to 2), then spends 60 at step 12 -> [40, 0, 0, 0, 0].
        assert_eq!(schedules[1].1, [40, 0, 0, 0, 0]);
        assert_eq!(schedules[1].2, 40);
    }

    #[test]
    fn libr_replenishment_and_intraday_ordering_follow_registered_semantics() {
        let assets = BTreeSet::from([1, 2]);
        // Source 100 into 1, spend 80 from 1 -> 8 (dips LIBR to 20), then entry 12 deposits 50 into 1,
        // and entry 13 transfers 60 from 1 -> 2.
        let edges = [
            t(10, 9, 1, 100),
            t(11, 1, 8, 80),
            t(12, 9, 1, 50),
            t(13, 1, 2, 60),
        ];
        // Without replenishment (`Never`), only 20 survived the dip at entry 11:
        // 10 stays in account 1 (0 hops) and 10 transfers to account 2 (1 hop).
        let never = trace_with_options(
            &edges,
            &assets,
            (10, 1),
            Law::Libr,
            IntradayOrder::StatementOrdinal,
            &BTreeSet::new(),
            limits(),
            allocate,
        )
        .unwrap();
        assert_eq!(sum(&never, 1, Disposition::Held), 10);
        assert_eq!(sum(&never, 2, Disposition::Held), 10);
        assert_eq!(sum(&never, 8, Disposition::Spent), 80);

        // With `OnEvidence` replenishment on entry 12, 50 is restored (capped at initial 100 -> 70),
        // so 10 remains in 1 and 60 transfers to 2!
        let on_ev = trace_with_options(
            &edges,
            &assets,
            (10, 1),
            Law::Libr,
            IntradayOrder::StatementOrdinal,
            &BTreeSet::from([12]),
            limits(),
            allocate,
        )
        .unwrap();
        assert_eq!(sum(&on_ev, 1, Disposition::Held), 10);
        assert_eq!(sum(&on_ev, 2, Disposition::Held), 60);
        assert_eq!(sum(&on_ev, 8, Disposition::Spent), 30);

        // Intraday ordering: on day 1, clean balance 100 is already in 1 (day 0),
        // then on day 1 source deposit (entry 10, recorded 10, +100) and spend (entry 11, recorded 11, -100) happen on the same day.
        let intraday_edges = [
            Transfer {
                entry: 1,
                day: 0,
                recorded: 1,
                from: 9,
                to: 1,
                amount: 100,
            },
            Transfer {
                entry: 10,
                day: 1,
                recorded: 10,
                from: 9,
                to: 1,
                amount: 100,
            },
            Transfer {
                entry: 11,
                day: 1,
                recorded: 11,
                from: 1,
                to: 8,
                amount: 100,
            },
        ];
        let ord_lifo = trace_with_options(
            &intraday_edges,
            &assets,
            (10, 1),
            Law::Lifo,
            IntradayOrder::StatementOrdinal,
            &BTreeSet::new(),
            limits(),
            allocate,
        )
        .unwrap();
        assert_eq!(sum(&ord_lifo, 1, Disposition::Held), 0);

        let wf_lifo = trace_with_options(
            &intraday_edges,
            &assets,
            (10, 1),
            Law::Lifo,
            IntradayOrder::WithdrawalsFirst,
            &BTreeSet::new(),
            limits(),
            allocate,
        )
        .unwrap();
        assert_eq!(sum(&wf_lifo, 1, Disposition::Held), 100);
    }
}
