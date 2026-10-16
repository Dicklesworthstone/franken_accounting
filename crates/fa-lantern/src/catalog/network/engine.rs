//! Exact, bounded attribution through a chronological transfer network.
//!
//! Inputs are one native unit and one legal entity, netted per account within
//! each entry by the caller. All debits of an entry are applied after all its
//! credits. A source is one entry's net deposit into one account. Every unit
//! of that source ends in a held position or an explicit terminal position;
//! paths are evidence, not independent amounts to sum a second time.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Law {
    Fifo,
    Lifo,
    Libr,
    ProRata,
}

impl Law {
    fn pooled(self) -> bool { matches!(self, Self::Libr | Self::ProRata) }
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
        self.fragments = self.fragments.checked_add(1).ok_or(Error::Limit("max_fragments"))?;
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
fn split<F>(amount: i128, capacities: &[i128], allocate: &mut F, meter: &mut Meter) -> Result<Vec<i128>, Error>
where
    F: FnMut(i128, &[i128]) -> Result<Vec<i128>, Error>,
{
    let n = capacities.len() as u64;
    meter.step(n.saturating_mul(u64::from(n.max(1).ilog2()) + 257).saturating_add(1))?;
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

// Color totals precede path allocation for pooled laws. Otherwise breaking
// one tainted lot into several paths changes the rounding of clean/tainted
// amounts, even though the account's economic balances did not change.
fn color_totals(lots: &[Lot], meter: &mut Meter) -> Result<[i128; 2], Error> {
    let mut totals = [0i128; 2]; // tainted, clean; ties favor tainted.
    for lot in lots {
        meter.step(1)?;
        let color = usize::from(lot.path.is_empty());
        totals[color] = add(totals[color], lot.amount, "color pool")?;
    }
    Ok(totals)
}

fn color_shares<F>(draws: [i128; 2], lots: &[Lot], allocate: &mut F, meter: &mut Meter) -> Result<Vec<i128>, Error>
where
    F: FnMut(i128, &[i128]) -> Result<Vec<i128>, Error>,
{
    let mut result = vec![0i128; lots.len()];
    for (color, amount) in draws.into_iter().enumerate() {
        meter.step(lots.len() as u64)?;
        let capacities: Vec<i128> = lots.iter().map(|lot| {
            if usize::from(lot.path.is_empty()) == color { lot.amount } else { 0 }
        }).collect();
        let shares = split(amount, &capacities, allocate, meter)?;
        for (out, share) in result.iter_mut().zip(shares) {
            *out = add(*out, share, "color shares")?;
        }
    }
    Ok(result)
}

impl Account {
    fn withdraw_pooled<F>(&mut self, amount: i128, law: Law, allocate: &mut F, meter: &mut Meter) -> Result<Vec<Lot>, Error>
    where
        F: FnMut(i128, &[i128]) -> Result<Vec<i128>, Error>,
    {
        let lots: Vec<Lot> = std::mem::take(&mut self.lots).into_iter().collect();
        let [tainted, clean] = color_totals(&lots, meter)?;
        let held = add(tainted, clean, "held pool")?;
        if held != self.balance.max(0) {
            return Err(Error::Invalid("pool does not reconcile to account balance"));
        }
        let drawn = amount.min(held);
        let taken = match law {
            // Preservation: spend clean money first, never replenish taint
            // from a later clean deposit. Actual returning taint keeps its path.
            Law::Libr => drawn - drawn.min(clean),
            Law::ProRata => split(drawn, &[tainted, clean], allocate, meter)?[0],
            _ => return Err(Error::Invalid("a pooled law is required")),
        };
        let shares = color_shares([taken, drawn - taken], &lots, allocate, meter)?;
        self.balance = self.balance.checked_sub(amount).ok_or(Error::Overflow("pooled withdrawal"))?;
        let mut out = Vec::new();
        for (mut lot, take) in lots.into_iter().zip(shares) {
            meter.step(1)?;
            if take > 0 {
                meter.fragment()?;
                meter.step(lot.path.len() as u64)?;
                out.push(Lot { amount: take, path: lot.path.clone() });
            }
            lot.amount = lot.amount.checked_sub(take).ok_or(Error::Allocation)?;
            if lot.amount > 0 { self.lots.push_back(lot); }
        }
        if amount > drawn {
            meter.fragment()?;
            out.push(Lot { amount: amount - drawn, path: Vec::new() });
        }
        Ok(out)
    }
}

impl Account {
    fn withdraw<F>(&mut self, amount: i128, law: Law, allocate: &mut F, meter: &mut Meter) -> Result<Vec<Lot>, Error>
    where
        F: FnMut(i128, &[i128]) -> Result<Vec<i128>, Error>,
    {
        if law.pooled() { return self.withdraw_pooled(amount, law, allocate, meter); }
        self.balance = self.balance.checked_sub(amount).ok_or(Error::Overflow("account withdrawal"))?;
        let mut remaining = amount;
        let mut out = Vec::new();
        while remaining > 0 {
            meter.fragment()?;
            let next = if law == Law::Fifo { self.lots.pop_front() } else { self.lots.pop_back() };
            let Some(mut lot) = next else {
                // Borrowing is clean funding, not a replenishment of taint.
                out.push(Lot { amount: remaining, path: Vec::new() });
                break;
            };
            let taken = remaining.min(lot.amount);
            remaining -= taken;
            lot.amount -= taken;
            meter.step(lot.path.len() as u64)?;
            out.push(Lot { amount: taken, path: lot.path.clone() });
            if lot.amount != 0 {
                if law == Law::Fifo { self.lots.push_front(lot); } else { self.lots.push_back(lot); }
            }
        }
        Ok(out)
    }

    fn deposit<F>(&mut self, account: u128, lots: Vec<Lot>, law: Law, terminal: &mut Vec<Position>, allocate: &mut F, meter: &mut Meter) -> Result<(), Error>
    where
        F: FnMut(i128, &[i128]) -> Result<Vec<i128>, Error>,
    {
        let capacities: Vec<i128> = lots.iter().map(|lot| lot.amount).collect();
        let total = capacities.iter().try_fold(0, |a, b| add(a, *b, "deposit"))?;
        // unsigned_abs handles i128::MIN; the min is <= a positive i128.
        let repaid = if self.balance < 0 {
            i128::try_from(self.balance.unsigned_abs().min(total as u128)).map_err(|_| Error::Overflow("overdraft"))?
        } else {
            0
        };
        let repayments = if law.pooled() {
            let totals = color_totals(&lots, meter)?;
            let colors = split(repaid, &totals, allocate, meter)?;
            color_shares([colors[0], colors[1]], &lots, allocate, meter)?
        } else {
            split(repaid, &capacities, allocate, meter)?
        };
        self.balance = add(self.balance, total, "account deposit")?;
        for (mut lot, repayment) in lots.into_iter().zip(repayments) {
            meter.step(1)?;
            if repayment > 0 && !lot.path.is_empty() {
                meter.fragment()?;
                meter.step(lot.path.len() as u64)?;
                terminal.push(Position { account, disposition: Disposition::RepaidOverdraft, amount: repayment, path: lot.path.clone() });
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
pub fn trace<F>(transfers: &[Transfer], assets: &BTreeSet<u128>, source: (u128, u128), law: Law, limits: Limits, mut allocate: F) -> Result<Report, Error>
where
    F: FnMut(i128, &[i128]) -> Result<Vec<i128>, Error>,
{
    let (source_entry, source_account) = source;
    if limits.max_hops == 0 || limits.max_hops > 64 || limits.max_steps == 0
        || limits.max_transfers == 0 || limits.max_fragments == 0
    {
        return Err(Error::Invalid("positive limits and max_hops <= 64 are required"));
    }
    if !assets.contains(&source_account) {
        return Err(Error::Invalid("source account must be a tracked asset"));
    }
    if transfers.len() > limits.max_transfers {
        return Err(Error::Limit("max_transfers"));
    }
    let mut meter = Meter { limits, steps: 0, fragments: 0 };
    let n = transfers.len() as u64;
    meter.step(n.saturating_mul(u64::from(n.max(1).ilog2()) + 1))?;
    let mut ordered = transfers.to_vec();
    ordered.sort_by_key(|t| (t.day, t.recorded, t.entry, t.from, t.to, t.amount));
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
            return Err(Error::Invalid("net opposing account legs before tracing an entry"));
        }
        let mut arrivals: BTreeMap<u128, Vec<Lot>> = BTreeMap::new();
        for (from, targets) in outgoing {
            let mut capacities: Vec<i128> = targets.iter().map(|t| t.amount).collect();
            let total = capacities.iter().try_fold(0, |a, b| add(a, *b, "entry outflow"))?;
            let chunks = if assets.contains(&from) {
                accounts.entry(from).or_default().withdraw(total, law, &mut allocate, &mut meter)?
            } else {
                meter.fragment()?;
                vec![Lot { amount: total, path: Vec::new() }]
            };
            // Pooled laws apportion the whole tainted amount before path
            // fragments. A fragmented provenance must not change a recipient's
            // aggregate taint merely by getting more rounding tie-break slots.
            let mut tainted_capacities = if law.pooled() {
                let totals = color_totals(&chunks, &mut meter)?;
                split(totals[0], &capacities, &mut allocate, &mut meter)?
            } else { Vec::new() };
            let mut clean_capacities = if law.pooled() {
                capacities.iter().zip(&tainted_capacities).map(|(total, tainted)| total.checked_sub(*tainted).ok_or(Error::Allocation)).collect::<Result<Vec<_>, _>>()?
            } else { Vec::new() };
            for lot in chunks {
                let remaining = if law.pooled() {
                    if lot.path.is_empty() { &mut clean_capacities } else { &mut tainted_capacities }
                } else { &mut capacities };
                let shares = split(lot.amount, remaining, &mut allocate, &mut meter)?;
                for ((t, capacity), share) in targets.iter().zip(remaining).zip(shares) {
                    if share == 0 {
                        continue;
                    }
                    meter.fragment()?;
                    *capacity -= share;
                    let hop = Hop { entry, from, to: t.to };
                    let path = if entry == source_entry && t.to == source_account {
                        source_amount = add(source_amount, share, "source deposit")?;
                        meter.path(&[], hop)?
                    } else if lot.path.is_empty() {
                        Vec::new()
                    } else {
                        meter.path(&lot.path, hop)?
                    };
                    if assets.contains(&t.to) {
                        arrivals.entry(t.to).or_default().push(Lot { amount: share, path });
                    } else if !path.is_empty() {
                        positions.push(Position { account: t.to, disposition: Disposition::Spent, amount: share, path });
                    }
                }
            }
            let leftover = if law.pooled() {
                tainted_capacities.iter().chain(&clean_capacities).any(|capacity| *capacity != 0)
            } else { capacities.iter().any(|capacity| *capacity != 0) };
            if leftover { return Err(Error::Allocation); }
        }
        // Atomic-entry semantics: no incoming money funds another leg of
        // this same entry. Entry IDs do not imply a fictitious within-entry time.
        for (account, lots) in arrivals {
            accounts.entry(account).or_default().deposit(account, lots, law, &mut positions, &mut allocate, &mut meter)?;
        }
        start = end;
    }
    if source_amount == 0 {
        return Err(Error::Invalid("source has no positive net deposit in the selected scope"));
    }
    for (account, state) in accounts {
        let mut held = 0i128;
        for lot in state.lots {
            meter.step(1)?;
            held = add(held, lot.amount, "account held lots")?;
            if !lot.path.is_empty() {
                positions.push(Position { account, disposition: Disposition::Held, amount: lot.amount, path: lot.path });
            }
        }
        if held != state.balance.max(0) {
            return Err(Error::Invalid("lots do not reconcile to account balance"));
        }
    }
    let n = positions.len() as u64;
    meter.step(n.saturating_mul(u64::from(n.max(1).ilog2()) + 1).saturating_mul(limits.max_hops as u64))?;
    positions.sort_by(|a, b| (a.account, a.disposition, &a.path).cmp(&(b.account, b.disposition, &b.path)));
    let attributed = positions.iter().try_fold(0, |sum, position| add(sum, position.amount, "source conservation"))?;
    if attributed != source_amount {
        return Err(Error::Invalid("source does not equal held plus spent plus overdraft repayment"));
    }
    Ok(Report { source_amount, positions, steps: meter.steps })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Literal Hamilton allocation for small oracle fixtures. Large boundary
    // fixtures have one nonzero target and never multiply large integers.
    fn allocate(amount: i128, capacities: &[i128]) -> Result<Vec<i128>, Error> {
        let sum: i128 = capacities.iter().sum();
        if sum < amount || sum == 0 { return Err(Error::Allocation); }
        if capacities.iter().filter(|x| **x > 0).count() == 1 {
            return Ok(capacities.iter().map(|c| if *c > 0 { amount } else { 0 }).collect());
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
            if residual == 0 { break; }
            shares[i] += 1;
            residual -= 1;
        }
        Ok(shares)
    }

    fn limits() -> Limits { Limits { max_transfers: 1000, max_fragments: 100_000, max_hops: 64, max_steps: 10_000_000 } }
    fn t(entry: u128, from: u128, to: u128, amount: i128) -> Transfer {
        Transfer { entry, day: 1, recorded: entry as u64, from, to, amount }
    }
    fn run(edges: &[Transfer], law: Law) -> Report {
        trace(edges, &BTreeSet::from([1, 2, 3, 4]), (10, 1), law, limits(), allocate).unwrap()
    }
    fn sum(r: &Report, account: u128, disposition: Disposition) -> i128 {
        r.positions.iter().filter(|p| p.account == account && p.disposition == disposition).map(|p| p.amount).sum()
    }

    #[test]
    fn follows_three_accounts_and_retains_the_full_path() {
        let r = run(&[t(10, 9, 1, 100), t(11, 1, 2, 80), t(12, 2, 3, 60)], Law::Fifo);
        assert_eq!(r.source_amount, 100);
        for (account, held) in [(1, 20), (2, 20), (3, 60)] { assert_eq!(sum(&r, account, Disposition::Held), held); }
        let p = r.positions.iter().find(|p| p.account == 3).unwrap();
        assert_eq!(p.path.iter().map(|h| (h.entry, h.from, h.to)).collect::<Vec<_>>(), [(10, 9, 1), (11, 1, 2), (12, 2, 3)]);
    }

    #[test]
    fn fifo_and_lifo_consume_different_commingled_layers() {
        let edges = [t(9, 9, 1, 100), t(10, 9, 1, 100), t(11, 1, 2, 150), t(12, 2, 8, 100)];
        let fifo = run(&edges, Law::Fifo);
        let lifo = run(&edges, Law::Lifo);
        assert_eq!((sum(&fifo, 1, Disposition::Held), sum(&fifo, 2, Disposition::Held), sum(&fifo, 8, Disposition::Spent)), (50, 50, 0));
        assert_eq!((sum(&lifo, 1, Disposition::Held), sum(&lifo, 2, Disposition::Held), sum(&lifo, 8, Disposition::Spent)), (0, 50, 50));
    }

    #[test]
    fn branches_and_returns_never_multiply_the_source() {
        let edges = [t(10, 9, 1, 100), t(11, 1, 2, 33), t(11, 1, 3, 67), t(12, 2, 1, 33), t(13, 1, 4, 33), t(14, 3, 8, 20)];
        for law in [Law::Fifo, Law::Lifo] {
            let r = run(&edges, law);
            assert_eq!(sum(&r, 4, Disposition::Held), 33);
            assert_eq!(sum(&r, 3, Disposition::Held), 47);
            assert_eq!(sum(&r, 8, Disposition::Spent), 20);
            assert_eq!(r.positions.iter().map(|p| p.amount).sum::<i128>(), 100);
            let mut reversed = edges; reversed.reverse();
            assert_eq!(r, run(&reversed, law));
        }
    }

    #[test]
    fn prior_overdrafts_and_destination_overdrafts_are_explicit_dissipation() {
        let edges = [t(1, 1, 8, 20), t(2, 2, 8, 30), t(10, 9, 1, 100), t(11, 1, 2, 80), t(12, 9, 2, 500)];
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
            (Limits { max_hops: 2, ..limits() }, Error::Limit("max_hops")),
            (Limits { max_transfers: 2, ..limits() }, Error::Limit("max_transfers")),
            (Limits { max_steps: 1, ..limits() }, Error::Limit("max_steps")),
            (Limits { max_fragments: 1, ..limits() }, Error::Limit("max_fragments")),
        ] { assert_eq!(trace(&edges, &assets, (10, 1), Law::Fifo, l, allocate), Err(expected)); }
        for bad in [vec![t(10, 9, 1, -1)], vec![t(10, 1, 1, 1)], vec![t(10, 9, 1, 2), t(10, 1, 2, 1)]] {
            assert!(trace(&bad, &assets, (10, 1), Law::Fifo, limits(), allocate).is_err());
        }
        assert!(trace(&edges, &assets, (99, 1), Law::Fifo, limits(), allocate).is_err());
        assert!(trace(&edges, &assets, (10, 1), Law::Fifo, limits(), |_, caps| Ok(vec![0; caps.len()])).is_err());
    }

    #[test]
    fn i128_boundary_and_repeated_turnover_do_not_accumulate_dormant_balances() {
        let edges = [t(1, 1, 8, i128::MAX), t(2, 1, 8, 1), t(10, 9, 1, 1)];
        for law in [Law::Fifo, Law::Lifo] {
            let r = run(&edges, law);
            assert_eq!(sum(&r, 1, Disposition::RepaidOverdraft), 1);
            let r = run(&[t(10, 9, 1, i128::MAX), t(11, 1, 2, i128::MAX), t(12, 2, 1, i128::MAX), t(13, 1, 2, i128::MAX)], law);
            assert_eq!(sum(&r, 2, Disposition::Held), i128::MAX);
        }
    }

    #[test]
    fn differential_against_a_literal_token_ledger() {
        for seed in 1..=128u64 {
            for law in [Law::Fifo, Law::Lifo] {
                let mut state = seed;
                let mut edges = vec![t(1, 9, 1, 8), t(2, 9, 2, 8), t(3, 9, 3, 8), t(10, 9, 1, 7)];
                let mut tokens: BTreeMap<u128, VecDeque<bool>> = BTreeMap::from([(1, VecDeque::from(vec![false; 8])), (2, VecDeque::from(vec![false; 8])), (3, VecDeque::from(vec![false; 8]))]);
                tokens.get_mut(&1).unwrap().extend(vec![true; 7]);
                let mut spent = 0;
                for entry in 11..=70 {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    let from = u128::from(state % 3 + 1);
                    let to = if state & 8 == 0 { 8 } else { from % 3 + 1 };
                    let available = tokens[&from].len();
                    let amount = ((state >> 16) as usize % 4).min(available);
                    if amount == 0 { continue; }
                    edges.push(t(entry, from, to, amount as i128));
                    let mut moved = Vec::new();
                    for _ in 0..amount {
                        moved.push(match law { Law::Fifo => tokens.get_mut(&from).unwrap().pop_front().unwrap(), Law::Lifo => tokens.get_mut(&from).unwrap().pop_back().unwrap(), _ => panic!("layered oracle") });
                    }
                    if to == 8 { spent += moved.iter().filter(|t| **t).count() as i128; }
                    else { tokens.get_mut(&to).unwrap().extend(moved); }
                }
                let r = run(&edges, law);
                for account in 1..=3 {
                    assert_eq!(sum(&r, account, Disposition::Held), tokens[&account].iter().filter(|t| **t).count() as i128, "seed {seed}, {law:?}, account {account}");
                }
                assert_eq!(sum(&r, 8, Disposition::Spent), spent, "seed {seed}, {law:?}");
            }
        }
    }

    #[test]
    fn libr_preserves_clean_first_and_pro_rata_uses_exact_color_shares() {
        let edges = [t(8, 9, 2, 100), t(9, 9, 1, 100), t(10, 9, 1, 100), t(11, 1, 2, 150), t(12, 2, 8, 225)];
        let libr = run(&edges, Law::Libr);
        assert_eq!(sum(&libr, 1, Disposition::Held), 50);
        assert_eq!(sum(&libr, 2, Disposition::Held), 25);
        assert_eq!(sum(&libr, 8, Disposition::Spent), 25);
        let pro = run(&edges, Law::ProRata);
        assert_eq!(sum(&pro, 1, Disposition::Held), 25);
        assert_eq!(sum(&pro, 2, Disposition::Held), 7);
        // 225 * 75 / 250 = 67.5; Hamilton's tie favors tainted over clean.
        assert_eq!(sum(&pro, 8, Disposition::Spent), 68);
        for r in [&libr, &pro] {
            assert_eq!(r.positions.iter().map(|p| p.amount).sum::<i128>(), 100);
            assert!(r.positions.iter().filter(|p| p.disposition == Disposition::Spent).all(|p| p.path.len() == 3));
        }
    }

    #[test]
    fn splitting_a_path_does_not_change_recipient_color_rounding() {
        let base = [t(10, 9, 1, 2), t(12, 9, 1, 2), t(14, 1, 3, 1), t(14, 1, 4, 3)];
        let split_path = [t(10, 9, 1, 2), t(11, 1, 2, 1), t(12, 9, 1, 2), t(13, 2, 1, 1), t(14, 1, 3, 1), t(14, 1, 4, 3)];
        for law in [Law::Libr, Law::ProRata] {
            for edges in [&base[..], &split_path[..]] {
                let r = run(edges, law);
                assert_eq!(sum(&r, 3, Disposition::Held), 1);
                assert_eq!(sum(&r, 4, Disposition::Held), 1);
                assert_eq!(sum(&r, 1, Disposition::Held), 0);
            }
        }
    }

    #[test]
    fn pooled_overdraft_repayment_rounds_colors_before_individual_paths() {
        let path = |entry| vec![Hop { entry, from: 9, to: 2 }];
        for law in [Law::Libr, Law::ProRata] {
            for lots in [
                vec![Lot { amount: 3, path: path(10) }, Lot { amount: 3, path: Vec::new() }],
                vec![Lot { amount: 1, path: path(10) }, Lot { amount: 1, path: path(11) }, Lot { amount: 1, path: path(12) }, Lot { amount: 3, path: Vec::new() }],
            ] {
                let mut account = Account { balance: -3, lots: VecDeque::new() };
                let mut terminal = Vec::new();
                let mut meter = Meter { limits: limits(), steps: 0, fragments: 0 };
                account.deposit(2, lots, law, &mut terminal, &mut allocate, &mut meter).unwrap();
                assert_eq!(terminal.iter().map(|p| p.amount).sum::<i128>(), 2);
                assert_eq!(account.lots.iter().filter(|lot| !lot.path.is_empty()).map(|lot| lot.amount).sum::<i128>(), 1);
                assert_eq!(account.balance, 3);
            }
        }
    }

    #[test]
    fn clean_replenishment_never_restores_spent_libr_value() {
        let r = run(&[t(10, 9, 1, 100), t(11, 1, 8, 70), t(12, 9, 1, 100), t(13, 1, 2, 100), t(14, 2, 1, 100)], Law::Libr);
        assert_eq!(sum(&r, 1, Disposition::Held), 30);
        assert_eq!(sum(&r, 8, Disposition::Spent), 70);
        assert_eq!(r.source_amount, 100);
    }

    #[test]
    fn pooled_signed_boundaries_and_limits_are_fail_closed() {
        let assets = BTreeSet::from([1, 2, 3, 4]);
        for law in [Law::Libr, Law::ProRata] {
            let r = run(&[t(1, 1, 8, i128::MAX), t(2, 1, 8, 1), t(10, 9, 1, 1)], law);
            assert_eq!(sum(&r, 1, Disposition::RepaidOverdraft), 1);
            let r = run(&[t(10, 9, 1, i128::MAX), t(11, 1, 2, i128::MAX)], law);
            assert_eq!(sum(&r, 2, Disposition::Held), i128::MAX);
            let edges = [t(10, 9, 1, 10), t(11, 1, 2, 10), t(12, 2, 3, 10)];
            assert_eq!(trace(&edges, &assets, (10, 1), law, Limits { max_hops: 2, ..limits() }, allocate), Err(Error::Limit("max_hops")));
            assert_eq!(trace(&edges, &assets, (10, 1), law, Limits { max_steps: 1, ..limits() }, allocate), Err(Error::Limit("max_steps")));
        }
    }

    #[test]
    fn differential_against_an_independent_two_color_balance_ledger() {
        for seed in 1..=128u64 {
            for law in [Law::Libr, Law::ProRata] {
                let mut state = seed;
                let mut edges = vec![t(1, 9, 1, 8), t(2, 9, 2, 8), t(3, 9, 3, 8), t(10, 9, 1, 7)];
                // Independent oracle has no paths, layers or allocation helper.
                // It computes the two-color Hamilton result from an exact
                // rational numerator; ties go to tainted, matching the policy.
                let portion = |amount: i128, tainted: i128, total: i128| {
                    if amount == 0 || tainted == 0 { return 0; }
                    let product = amount * tainted;
                    let floor = product / total;
                    floor + i128::from((product % total) * 2 >= total)
                };
                let mut balances = BTreeMap::from([(1u128, (15i128, 7i128)), (2, (8, 0)), (3, (8, 0))]);
                let mut repaid: BTreeMap<u128, i128> = BTreeMap::new();
                let mut spent = 0;
                for entry in 11..=70 {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    let from = if state & 7 == 0 { 9 } else { u128::from(state % 3 + 1) };
                    let mut to = if state & 8 == 0 { 8 } else { u128::from((state >> 8) % 3 + 1) };
                    if to == from { to = from % 3 + 1; }
                    let amount = i128::from((state >> 16) % 10 + 1);
                    edges.push(t(entry, from, to, amount));
                    let carried = if from == 9 { 0 } else {
                        let (balance, tainted) = balances.get_mut(&from).unwrap();
                        let drawn = amount.min((*balance).max(0));
                        let carry = match law {
                            Law::Libr => (drawn - ((*balance).max(0) - *tainted)).max(0),
                            Law::ProRata => portion(drawn, *tainted, (*balance).max(0)),
                            _ => panic!("pooled oracle"),
                        };
                        *balance -= amount;
                        *tainted -= carry;
                        carry
                    };
                    if to == 8 { spent += carried; }
                    else {
                        let (balance, tainted) = balances.get_mut(&to).unwrap();
                        let repayment = amount.min((-*balance).max(0));
                        let lost = portion(repayment, carried, amount);
                        *balance += amount;
                        *tainted += carried - lost;
                        *repaid.entry(to).or_default() += lost;
                    }
                }
                let r = run(&edges, law);
                for account in 1..=3 {
                    assert_eq!(sum(&r, account, Disposition::Held), balances[&account].1, "seed={seed} {law:?} account={account}");
                    assert_eq!(sum(&r, account, Disposition::RepaidOverdraft), repaid.get(&account).copied().unwrap_or(0), "seed={seed} {law:?} repayment={account}");
                }
                assert_eq!(sum(&r, 8, Disposition::Spent), spent, "seed={seed} {law:?}");
                assert_eq!(r.positions.iter().map(|p| p.amount).sum::<i128>(), 7);
                let mut permuted = edges; permuted.reverse();
                assert_eq!(r, run(&permuted, law));
            }
        }
    }
}
