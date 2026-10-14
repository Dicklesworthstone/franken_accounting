//! Naive Lantern procedures (plan §11; bead fa-nlu): the literal definitions
//! fa-lantern's folds must agree with, over a flat row model the
//! differential test builds from the same intents it posts to the kernel.
//! Deliberately simple, single pass where possible, own arithmetic.

use std::collections::BTreeMap;

use fa_time::{DateDay, Weekday};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leg {
    pub account: String,
    pub debit: bool,
    pub unit: u32,
    /// Decimal places of the unit.
    pub scale: u32,
    pub mantissa: i128,
}

/// One posting entry as the naive procedures see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub index: usize,
    pub date: DateDay,
    pub document_date: Option<DateDay>,
    pub period: String,
    /// The period's exclusive end (fa-time `PeriodDef::end`); its last day
    /// is one before.
    pub period_end: DateDay,
    pub legs: Vec<Leg>,
    pub preparer: String,
    pub approvers: Vec<String>,
    /// `None` when the description is unreadable.
    pub description_chars: Option<usize>,
    pub external_ids: Vec<(String, String)>,
    /// Whether the entry was recorded after its period's first close-side
    /// transition.
    pub recorded_after_close: bool,
}

/// `(row index, round legs)` for rows with at least one round leg.
pub fn round_amounts(rows: &[Row], round_power: u32) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for r in rows {
        let mut round = 0;
        for l in &r.legs {
            let base = 10i128.pow(l.scale + round_power);
            if l.mantissa != 0 && l.mantissa % base == 0 {
                round += 1;
            }
        }
        if round > 0 {
            out.push((r.index, round));
        }
    }
    out
}

pub fn period_end_timing(rows: &[Row], window: i32) -> Vec<usize> {
    rows.iter()
        .filter(|r| {
            let d = r.period_end.0 - 1 - r.date.0;
            d >= 0 && d < window
        })
        .map(|r| r.index)
        .collect()
}

pub fn post_closing(rows: &[Row]) -> Vec<usize> {
    rows.iter()
        .filter(|r| r.recorded_after_close)
        .map(|r| r.index)
        .collect()
}

pub fn weekend(rows: &[Row]) -> Vec<usize> {
    rows.iter()
        .filter(|r| {
            matches!(
                r.document_date.unwrap_or(r.date).weekday(),
                Weekday::Saturday | Weekday::Sunday
            )
        })
        .map(|r| r.index)
        .collect()
}

pub fn self_approved(rows: &[Row]) -> Vec<usize> {
    rows.iter()
        .filter(|r| r.approvers.contains(&r.preparer))
        .map(|r| r.index)
        .collect()
}

pub fn thin_descriptions(rows: &[Row], min_chars: usize) -> Vec<usize> {
    rows.iter()
        .filter(|r| r.description_chars.is_some_and(|c| c < min_chars))
        .map(|r| r.index)
        .collect()
}

/// A row's leg multiset: `(account, debit, unit, mantissa)` sorted.
type LegKey = Vec<(String, bool, u32, i128)>;

fn leg_key(r: &Row) -> LegKey {
    let mut s: LegKey = r
        .legs
        .iter()
        .map(|l| (l.account.clone(), l.debit, l.unit, l.mantissa))
        .collect();
    s.sort();
    s
}

/// Groups (ascending row indexes) of two or more rows with the same legs and
/// date.
pub fn same_same_same(rows: &[Row]) -> Vec<Vec<usize>> {
    let mut groups: BTreeMap<(LegKey, i32), Vec<usize>> = BTreeMap::new();
    for r in rows {
        groups
            .entry((leg_key(r), r.date.0))
            .or_default()
            .push(r.index);
    }
    let mut out: Vec<Vec<usize>> = groups
        .into_values()
        .filter(|g| g.len() >= 2)
        .map(|mut g| {
            g.sort_unstable();
            g
        })
        .collect();
    out.sort();
    out
}

/// Pairs `(i, j)` with `i < j`: for each row `a`, the rows with the same legs
/// on later dates are found by brute force; the earliest such date, if it is
/// at most `window` days after `a`'s, contributes its lowest-index row `b`
/// (the first recorded) as `a`'s pair.
pub fn same_same_different(rows: &[Row], window: i32) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for a in rows {
        let later: Vec<&Row> = rows
            .iter()
            .filter(|b| leg_key(b) == leg_key(a) && b.date.0 > a.date.0)
            .collect();
        let Some(next_day) = later.iter().map(|b| b.date.0).min() else {
            continue;
        };
        if next_day - a.date.0 > window {
            continue;
        }
        let b = later
            .iter()
            .filter(|b| b.date.0 == next_day)
            .map(|b| b.index)
            .min()
            .expect("a row on the earliest later date");
        out.push((a.index.min(b), a.index.max(b)));
    }
    out.sort_unstable();
    out
}

/// `(system, missing numbers)` per gap, in `(system, prefix, number)` order.
pub fn sequence_gaps(rows: &[Row]) -> Vec<(String, u64)> {
    let mut sequences: BTreeMap<(String, String), Vec<u64>> = BTreeMap::new();
    for r in rows {
        for (system, id) in &r.external_ids {
            let digits: String = id
                .chars()
                .rev()
                .take_while(char::is_ascii_digit)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            if digits.is_empty() || digits.len() > 18 {
                continue;
            }
            let prefix = id[..id.len() - digits.len()].to_string();
            sequences
                .entry((system.clone(), prefix))
                .or_default()
                .push(digits.parse().expect("digits"));
        }
    }
    let mut out = Vec::new();
    for ((system, _), mut numbers) in sequences {
        numbers.sort_unstable();
        for w in numbers.windows(2) {
            if w[1] > w[0] + 1 {
                out.push((system.clone(), w[1] - w[0] - 1));
            }
        }
    }
    out
}

pub fn cutoff(rows: &[Row], period_of: &dyn Fn(DateDay) -> String) -> Vec<usize> {
    rows.iter()
        .filter(|r| r.document_date.is_some_and(|d| period_of(d) != r.period))
        .map(|r| r.index)
        .collect()
}

/// First-digit counts of leg magnitudes of at least one whole unit.
pub fn first_digit_counts(rows: &[Row]) -> [u64; 9] {
    let mut counts = [0u64; 9];
    for r in rows {
        for l in &r.legs {
            let mut m = l.mantissa.unsigned_abs();
            if m < 10u128.pow(l.scale) {
                continue;
            }
            while m >= 10 {
                m /= 10;
            }
            counts[(m - 1) as usize] += 1;
        }
    }
    counts
}

/// Nigrini's MAD at nine decimal places, with the expected proportions
/// written out literally.
pub fn benford_mad_1e9(counts: &[u64; 9]) -> i128 {
    const EXPECTED: [i128; 9] = [
        301_029_996,
        176_091_259,
        124_938_737,
        96_910_013,
        79_181_246,
        66_946_790,
        57_991_947,
        51_152_522,
        45_757_490,
    ];
    let n: i128 = counts.iter().map(|c| i128::from(*c)).sum();
    if n == 0 {
        return 0;
    }
    let mut total = 0i128;
    for d in 0..9 {
        let observed = i128::from(counts[d]) * 1_000_000_000;
        let expected = n * EXPECTED[d];
        total += (observed - expected).abs();
    }
    total / (9 * n)
}

/// A two-leg row as `(credit account, debit account, unit, magnitude)`: the
/// naive flow of value from the credited account to the debited one.
fn transfer(r: &Row) -> Option<(&str, &str, u32, i128)> {
    match r.legs.as_slice() {
        [a, b] if a.debit && !b.debit => Some((&b.account, &a.account, a.unit, a.mantissa.abs())),
        [a, b] if !a.debit && b.debit => Some((&a.account, &b.account, a.unit, b.mantissa.abs())),
        _ => None,
    }
}

/// Pairs `(i, j)` of two-leg rows where value leaves asset `A` for asset `B`
/// in row `i` and the same magnitude returns from `B` to `A` in row `j`,
/// 0..=window days later (`i` before `j` when the dates tie).
pub fn round_trips(
    rows: &[Row],
    window: i32,
    is_asset: &dyn Fn(&str) -> bool,
) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for a in rows {
        for b in rows {
            let (Some((from_a, to_a, unit_a, m_a)), Some((from_b, to_b, unit_b, m_b))) =
                (transfer(a), transfer(b))
            else {
                continue;
            };
            let gap = b.date.0 - a.date.0;
            if a.index != b.index
                && from_a == to_b
                && to_a == from_b
                && from_a != to_a
                && unit_a == unit_b
                && m_a == m_b
                && m_a != 0
                && (0..=window).contains(&gap)
                && (gap != 0 || a.index < b.index)
                && is_asset(from_a)
                && is_asset(to_a)
            {
                out.push((a.index, b.index));
            }
        }
    }
    out.sort_unstable();
    out
}

/// Transfers between one ordered account pair in one unit:
/// `(date, row index, magnitude)` keyed by `(from, to, unit)`.
type TransferGroups = BTreeMap<(String, String, u32), Vec<(i32, usize, i128)>>;

/// `(from account, to account, row indexes)` of every chain of two-leg
/// transfers between one pair of accounts in one unit whose magnitudes lie in
/// `floor..threshold`, with consecutive dates at most `window` days apart,
/// at least `min_count` long and summing to at least `threshold`.
pub fn structuring(
    rows: &[Row],
    threshold: i128,
    floor: i128,
    window: i32,
    min_count: usize,
) -> Vec<(String, String, Vec<usize>)> {
    let mut groups: TransferGroups = BTreeMap::new();
    for r in rows {
        if let Some((from, to, unit, m)) = transfer(r)
            && m >= floor
            && m < threshold
        {
            groups
                .entry((from.to_string(), to.to_string(), unit))
                .or_default()
                .push((r.date.0, r.index, m));
        }
    }
    let mut out = Vec::new();
    for ((from, to, _), mut legs) in groups {
        legs.sort_unstable();
        let mut chain: Vec<(i32, usize, i128)> = Vec::new();
        let flush = |chain: &mut Vec<(i32, usize, i128)>,
                     out: &mut Vec<(String, String, Vec<usize>)>| {
            let sum: i128 = chain.iter().map(|l| l.2).sum();
            if chain.len() >= min_count && sum >= threshold {
                let mut idx: Vec<usize> = chain.iter().map(|l| l.1).collect();
                idx.sort_unstable();
                out.push((from.clone(), to.clone(), idx));
            }
            chain.clear();
        };
        for l in legs {
            if let Some(last) = chain.last()
                && l.0 - last.0 > window
            {
                flush(&mut chain, &mut out);
            }
            chain.push(l);
        }
        flush(&mut chain, &mut out);
    }
    out.sort();
    out
}

/// A naive tracing law over a debit-normal account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceLaw {
    Libr,
    Fifo,
    Lifo,
    ProRata,
}

/// The traceable share of row `source`'s deposit into `account` at `claim`
/// under `law`, and the rows whose withdrawals carried tainted value (for
/// LIBR, the row at which the lowest balance was reached). Movements are
/// each row's debits minus credits on the account, in date then row
/// (recorded) order; money before the deposit is clean; an overdraft is
/// repaid by the next money in, so a deposit into an overdrawn account is
/// traceable only above the overdraft, and a withdrawal beyond the money
/// held overdraws; pro rata splits a withdrawal by exact integer proportion,
/// which the planted corpus keeps exact.
pub fn trace(
    rows: &[Row],
    account: &str,
    source: usize,
    claim: DateDay,
    law: TraceLaw,
) -> (i128, Vec<usize>) {
    let mut moves: Vec<(i32, usize, i128)> = Vec::new();
    for r in rows {
        if r.date.0 > claim.0 {
            continue;
        }
        let net: i128 = r
            .legs
            .iter()
            .filter(|l| l.account == account)
            .map(|l| {
                if l.debit {
                    l.mantissa.abs()
                } else {
                    -l.mantissa.abs()
                }
            })
            .sum();
        if net != 0 {
            moves.push((r.date.0, r.index, net));
        }
    }
    moves.sort_unstable();
    let at = moves
        .iter()
        .position(|m| m.1 == source)
        .expect("the source row moves the account");
    let opening: i128 = moves[..at].iter().map(|m| m.2).sum();
    let deposit = moves[at].2;
    let mut balance = opening + deposit;
    let mut lowest = (balance, None);
    let mut overdraft = (-opening).max(0);
    let traceable = (deposit - overdraft).max(0);
    overdraft = (overdraft - deposit).max(0);
    let mut tainted = traceable;
    let mut clean = opening.max(0);
    let mut layers: Vec<(bool, i128)> = Vec::new();
    if opening > 0 {
        layers.push((false, opening));
    }
    if traceable > 0 {
        layers.push((true, traceable));
    }
    let mut carriers: Vec<usize> = Vec::new();
    for m in &moves[at + 1..] {
        if m.2 > 0 {
            balance += m.2;
            let held = (m.2 - overdraft).max(0);
            overdraft = (overdraft - m.2).max(0);
            if held > 0 {
                clean += held;
                layers.push((false, held));
            }
            continue;
        }
        let w = -m.2;
        balance -= w;
        if balance < lowest.0 {
            lowest = (balance, Some(m.1));
        }
        match law {
            TraceLaw::Libr => {
                if balance.max(0) < tainted {
                    tainted = balance.max(0);
                }
            }
            TraceLaw::Fifo | TraceLaw::Lifo => {
                let mut remaining = w;
                while remaining > 0 && !layers.is_empty() {
                    let i = if law == TraceLaw::Fifo {
                        0
                    } else {
                        layers.len() - 1
                    };
                    let take = remaining.min(layers[i].1);
                    if layers[i].0 && take > 0 && !carriers.contains(&m.1) {
                        carriers.push(m.1);
                    }
                    layers[i].1 -= take;
                    remaining -= take;
                    if layers[i].1 == 0 {
                        layers.remove(i);
                    }
                }
                overdraft += remaining;
            }
            TraceLaw::ProRata => {
                let pool = tainted + clean;
                let drawn = w.min(pool.max(0));
                overdraft += w - drawn;
                if drawn == 0 {
                    continue;
                }
                let t_out = drawn * tainted / pool;
                if t_out > 0 {
                    carriers.push(m.1);
                }
                tainted -= t_out;
                clean -= drawn - t_out;
            }
        }
    }
    let traced = match law {
        TraceLaw::Libr | TraceLaw::ProRata => tainted,
        TraceLaw::Fifo | TraceLaw::Lifo => layers.iter().filter(|l| l.0).map(|l| l.1).sum(),
    };
    if law == TraceLaw::Libr
        && let Some(i) = lowest.1
    {
        carriers.push(i);
    }
    carriers.sort_unstable();
    carriers.dedup();
    (traced, carriers)
}
