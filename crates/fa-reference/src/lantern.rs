//! Naive Lantern procedures (plan §11; bead fa-nlu): the literal definitions
//! fa-lantern's folds must agree with, over a flat row model the
//! differential test builds from the same intents it posts to the kernel.
//! Deliberately simple, single pass where possible, own arithmetic.

use std::collections::{BTreeMap, BTreeSet};

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
    /// Optional inclusive start of the entry's resolved period (used when an
    /// entry names a special/adjustment period discriminator).
    pub period_start: Option<DateDay>,
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
    /// Target row index when this row is a `Reversal` (`SupersessionKind::Reverses`).
    pub reverses: Option<usize>,
    /// Target row index when this row is a `Replacement` (`SupersessionKind::Replaces`).
    pub replaces: Option<usize>,
}

fn live_rows_through(rows: &[Row], through: Option<DateDay>) -> Vec<&Row> {
    let window: Vec<&Row> = rows
        .iter()
        .filter(|r| through.is_none_or(|d| r.date <= d))
        .collect();
    fn unreversed(idx: usize, window: &[&Row]) -> bool {
        match window.iter().find(|r| r.reverses == Some(idx)) {
            None => true,
            Some(rev) => !unreversed(rev.index, window),
        }
    }
    window
        .iter()
        .copied()
        .filter(|r| {
            r.reverses.is_none()
                && unreversed(r.index, &window)
                && !window.iter().any(|other| {
                    other.replaces == Some(r.index) && unreversed(other.index, &window)
                })
        })
        .collect()
}

fn live_rows(rows: &[Row]) -> Vec<&Row> {
    live_rows_through(rows, None)
}

fn linked_supersession(rows: &[Row], a: usize, b: usize) -> bool {
    fn reaches(rows: &[Row], cur: usize, goal: usize) -> bool {
        if cur == goal {
            return true;
        }
        let Some(r) = rows.iter().find(|r| r.index == cur) else {
            return false;
        };
        r.reverses.is_some_and(|t| reaches(rows, t, goal))
            || r.replaces.is_some_and(|t| reaches(rows, t, goal))
    }
    reaches(rows, a, b) || reaches(rows, b, a)
}

/// `(row index, round legs)` for rows with at least one round leg.
pub fn round_amounts(rows: &[Row], round_power: u32) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for r in live_rows(rows) {
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
    live_rows(rows)
        .into_iter()
        .filter(|r| {
            let d = r.period_end.0 - 1 - r.date.0;
            d >= 0 && d < window
        })
        .map(|r| r.index)
        .collect()
}

pub fn post_closing(rows: &[Row]) -> Vec<usize> {
    live_rows(rows)
        .into_iter()
        .filter(|r| r.recorded_after_close)
        .map(|r| r.index)
        .collect()
}

pub fn weekend(rows: &[Row]) -> Vec<usize> {
    live_rows(rows)
        .into_iter()
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
    live_rows(rows)
        .into_iter()
        .filter(|r| r.approvers.contains(&r.preparer))
        .map(|r| r.index)
        .collect()
}

pub fn thin_descriptions(rows: &[Row], min_chars: usize) -> Vec<usize> {
    live_rows(rows)
        .into_iter()
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

/// Groups (ascending row indexes) of two or more live rows with the same legs
/// and date, excluding supersession pairs. Found by brute-force pairwise
/// equivalence over live rows (no hash/tree grouping map).
pub fn same_same_same(rows: &[Row]) -> Vec<Vec<usize>> {
    let live = live_rows(rows);
    let mut visited = BTreeSet::new();
    let mut out = Vec::new();
    for (pos, a) in live.iter().enumerate() {
        if visited.contains(&a.index) {
            continue;
        }
        let key_a = leg_key(a);
        let mut group = vec![a.index];
        visited.insert(a.index);
        for b in &live[pos + 1..] {
            if b.date == a.date
                && leg_key(b) == key_a
                && group
                    .iter()
                    .all(|&other| !linked_supersession(rows, other, b.index))
            {
                visited.insert(b.index);
                group.push(b.index);
            }
        }
        if group.len() >= 2 {
            group.sort_unstable();
            out.push(group);
        }
    }
    out.sort();
    out
}

/// Pairs `(i, j)` with `i < j`: for each live row `a`, the live rows with the
/// same legs on later dates (excluding supersession pairs) are found by brute
/// force; the earliest such date, if it is at most `window` days after `a`'s,
/// contributes its lowest-index row `b` (the first recorded) as `a`'s pair.
pub fn same_same_different(rows: &[Row], window: i32) -> Vec<(usize, usize)> {
    let live = live_rows(rows);
    let mut out = Vec::new();
    for a in &live {
        let later: Vec<&Row> = live
            .iter()
            .copied()
            .filter(|b| {
                leg_key(b) == leg_key(a)
                    && b.date.0 > a.date.0
                    && !linked_supersession(rows, a.index, b.index)
            })
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

/// `(system, missing numbers)` per gap, in `(system, prefix, number)` order,
/// computed by brute-force successor lookup over the flat list of parsed
/// `(system, prefix, number)` triples.
pub fn sequence_gaps(rows: &[Row]) -> Vec<(String, u64)> {
    let mut parsed: Vec<(String, String, u64)> = Vec::new();
    for r in live_rows(rows) {
        for (system, id) in &r.external_ids {
            let Some(non_digit_end) = id
                .char_indices()
                .rev()
                .find(|(_, c)| !c.is_ascii_digit())
                .map(|(idx, c)| idx + c.len_utf8())
                .or(Some(0))
            else {
                continue;
            };
            let digits = &id[non_digit_end..];
            if digits.is_empty() || digits.len() > 18 {
                continue;
            }
            let prefix = id[..non_digit_end].to_string();
            let num: u64 = digits.parse().expect("digits");
            parsed.push((system.clone(), prefix, num));
        }
    }
    let keys: BTreeSet<(String, String)> = parsed
        .iter()
        .map(|(s, p, _)| (s.clone(), p.clone()))
        .collect();
    let mut out = Vec::new();
    for (system, prefix) in keys {
        let nums: BTreeSet<u64> = parsed
            .iter()
            .filter(|(s, p, _)| s == &system && p == &prefix)
            .map(|(_, _, n)| *n)
            .collect();
        for &n in &nums {
            if let Some(&next) = nums.range((n + 1)..).next()
                && next > n + 1
            {
                out.push((system.clone(), next - n - 1));
            }
        }
    }
    out
}

pub fn cutoff(rows: &[Row], period_of: &dyn Fn(DateDay) -> String) -> Vec<usize> {
    live_rows(rows)
        .into_iter()
        .filter(|r| {
            r.document_date.is_some_and(|d| {
                let in_own_period = r
                    .period_start
                    .is_some_and(|start| d >= start && d < r.period_end);
                !in_own_period && period_of(d) != r.period
            })
        })
        .map(|r| r.index)
        .collect()
}

/// First-digit counts of live leg magnitudes on `debit` side in `unit` of at
/// least one whole unit.
pub fn first_digit_counts_for(rows: &[Row], unit: u32, debit: bool) -> [u64; 9] {
    let mut counts = [0u64; 9];
    for r in live_rows(rows) {
        for l in &r.legs {
            if l.debit != debit || l.unit != unit {
                continue;
            }
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

/// First-digit counts of debit-side leg magnitudes in the primary unit of at
/// least one whole unit.
pub fn first_digit_counts(rows: &[Row]) -> [u64; 9] {
    let unit = rows
        .iter()
        .flat_map(|r| r.legs.iter())
        .map(|l| l.unit)
        .next()
        .unwrap_or(0);
    first_digit_counts_for(rows, unit, true)
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

/// One-to-one chronological pairs `(i, j)` of live two-leg rows where value
/// leaves asset `A` for asset `B` in row `i` and the same magnitude returns
/// from `B` to `A` in the earliest unmatched row `j`, 0..=window days later
/// (`i` before `j` when the dates tie).
pub fn round_trips(
    rows: &[Row],
    window: i32,
    is_asset: &dyn Fn(&str) -> bool,
) -> Vec<(usize, usize)> {
    let mut ordered = live_rows(rows);
    ordered.sort_by_key(|r| (r.date.0, r.index));
    let mut matched: BTreeSet<usize> = BTreeSet::new();
    let mut out = Vec::new();
    for (pos, a) in ordered.iter().enumerate() {
        if matched.contains(&a.index) {
            continue;
        }
        let Some((from_a, to_a, unit_a, m_a)) = transfer(a) else {
            continue;
        };
        if from_a == to_a || m_a == 0 || !is_asset(from_a) || !is_asset(to_a) {
            continue;
        }
        for b in &ordered[pos + 1..] {
            if matched.contains(&b.index) || a.index == b.index {
                continue;
            }
            let Some((from_b, to_b, unit_b, m_b)) = transfer(b) else {
                continue;
            };
            let gap = b.date.0 - a.date.0;
            if from_a == to_b
                && to_a == from_b
                && unit_a == unit_b
                && m_a == m_b
                && (0..=window).contains(&gap)
            {
                matched.insert(a.index);
                matched.insert(b.index);
                out.push((a.index, b.index));
                break;
            }
        }
    }
    out.sort_unstable();
    out
}

/// `(from account, to account, row indexes)` of every maximal date-window run
/// of live two-leg transfers between one pair of accounts in `unit_filter`
/// (or any unit when `None`) whose magnitudes lie in `floor..threshold`, with
/// consecutive dates at most `window` days apart, at least `min_count` long
/// and summing to at least `threshold`.
pub fn structuring_for_unit(
    rows: &[Row],
    unit_filter: Option<u32>,
    threshold: i128,
    floor: i128,
    window: i32,
    min_count: usize,
) -> Vec<(String, String, Vec<usize>)> {
    let candidates: Vec<(String, String, u32, i32, usize, i128)> = live_rows(rows)
        .into_iter()
        .filter_map(|r| {
            let (from, to, unit, m) = transfer(r)?;
            if from == to || unit_filter.is_some_and(|u| u != unit) || m < floor || m >= threshold {
                return None;
            }
            Some((from.to_string(), to.to_string(), unit, r.date.0, r.index, m))
        })
        .collect();
    let triples: BTreeSet<(String, String, u32)> = candidates
        .iter()
        .map(|(f, t, u, _, _, _)| (f.clone(), t.clone(), *u))
        .collect();
    let mut out = Vec::new();
    for (from, to, unit) in triples {
        let mut seq: Vec<(i32, usize, i128)> = candidates
            .iter()
            .filter(|(f, t, u, _, _, _)| f == &from && t == &to && *u == unit)
            .map(|(_, _, _, d, idx, m)| (*d, *idx, *m))
            .collect();
        seq.sort_unstable();
        // Partition `seq` into maximal contiguous slices where adjacent dates
        // are within `window` days.
        let mut start = 0usize;
        while start < seq.len() {
            let mut end = start + 1;
            while end < seq.len() && seq[end].0 - seq[end - 1].0 <= window {
                end += 1;
            }
            let slice = &seq[start..end];
            let sum: i128 = slice.iter().map(|x| x.2).sum();
            if slice.len() >= min_count && sum >= threshold {
                let mut idx: Vec<usize> = slice.iter().map(|x| x.1).collect();
                idx.sort_unstable();
                idx.dedup();
                out.push((from.clone(), to.clone(), idx));
            }
            start = end;
        }
    }
    out.sort();
    out
}

/// Structuring across all units (or the single unit of a single-currency book).
pub fn structuring(
    rows: &[Row],
    threshold: i128,
    floor: i128,
    window: i32,
    min_count: usize,
) -> Vec<(String, String, Vec<usize>)> {
    structuring_for_unit(rows, None, threshold, floor, window, min_count)
}

/// A naive tracing law over a debit-normal account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceLaw {
    Libr,
    Fifo,
    Lifo,
    ProRata,
}

/// Same-day ordering mode for naive tracing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntradayOrder {
    StatementOrdinal,
    WithdrawalsFirst,
    DepositsFirst,
}

/// Naive tracing with explicit same-day ordering.
///
/// Uses independent definitions per law:
/// - `LIBR`: direct minimum over all post-deposit balance prefix sums
///   `min_{k >= at} max(0, balance_k)` clamped by initial traceable deposit.
/// - `FIFO`: cumulative held-inflow interval `[clean_before, clean_before + traceable)`
///   compared against cumulative post-deposit withdrawals drawn from held money.
/// - `LIFO`: stack of held inflows `(is_source, remaining)`.
/// - `ProRata`: exact integer proportional reduction at each withdrawal.
pub fn trace_with_order(
    rows: &[Row],
    account: &str,
    source: usize,
    claim: DateDay,
    law: TraceLaw,
    order: IntradayOrder,
) -> (i128, Vec<usize>) {
    let mut moves: Vec<(i32, u8, usize, i128)> = Vec::new();
    for r in live_rows_through(rows, Some(claim)) {
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
            let rank = match order {
                IntradayOrder::StatementOrdinal => 0,
                IntradayOrder::WithdrawalsFirst => u8::from(net > 0),
                IntradayOrder::DepositsFirst => u8::from(net < 0),
            };
            moves.push((r.date.0, rank, r.index, net));
        }
    }
    moves.sort_unstable();
    let at = moves
        .iter()
        .position(|m| m.2 == source)
        .expect("the source row moves the account");
    let opening: i128 = moves[..at].iter().map(|m| m.3).sum();
    let deposit = moves[at].3;
    let initial_overdraft = (-opening).max(0);
    let traceable = (deposit - initial_overdraft).max(0);
    let initial_clean = opening.max(0);

    match law {
        TraceLaw::Libr => {
            // Direct prefix-sum evaluation: after each movement k > at, compute
            // the exact balance prefix sum from `moves[..=k]`.
            let mut running = opening + deposit;
            let mut min_bal = running;
            let mut min_row = None;
            let mut cap = traceable.min(running.max(0));
            for m in &moves[at + 1..] {
                running += m.3;
                if m.3 < 0 {
                    if running < min_bal {
                        min_bal = running;
                        min_row = Some(m.2);
                    }
                    cap = cap.min(running.max(0));
                }
            }
            let carriers = min_row.into_iter().collect();
            (cap, carriers)
        }
        TraceLaw::Fifo => {
            // Clayton's rule via cumulative held-inflow intervals:
            // Initial held money occupies `[0, initial_clean)` (clean) and
            // `[initial_clean, initial_clean + traceable)` (tainted).
            let taint_lo = initial_clean;
            let taint_hi = initial_clean + traceable;
            let mut total_inflows_held = taint_hi;
            let mut total_drawn_from_held = 0i128;
            let mut overdraft = (initial_overdraft - deposit).max(0);
            let mut carriers = Vec::new();
            for m in &moves[at + 1..] {
                if m.3 > 0 {
                    let held = (m.3 - overdraft).max(0);
                    overdraft = (overdraft - m.3).max(0);
                    total_inflows_held += held;
                } else {
                    let w = -m.3;
                    let available = (total_inflows_held - total_drawn_from_held).max(0);
                    let drawn = w.min(available);
                    overdraft += w - drawn;
                    let prev_drawn = total_drawn_from_held;
                    let next_drawn = prev_drawn + drawn;
                    total_drawn_from_held = next_drawn;
                    // Overlap between `[prev_drawn, next_drawn)` and `[taint_lo, taint_hi)`.
                    let overlap = next_drawn.min(taint_hi) - prev_drawn.max(taint_lo);
                    if overlap > 0 {
                        carriers.push(m.2);
                    }
                }
            }
            let consumed_taint =
                (total_drawn_from_held.min(taint_hi) - total_drawn_from_held.min(taint_lo)).max(0);
            let remaining_taint = (traceable - consumed_taint).max(0);
            carriers.sort_unstable();
            carriers.dedup();
            (remaining_taint, carriers)
        }
        TraceLaw::Lifo => {
            let mut overdraft = (initial_overdraft - deposit).max(0);
            let mut stack: Vec<(bool, i128)> = Vec::new();
            if initial_clean > 0 {
                stack.push((false, initial_clean));
            }
            if traceable > 0 {
                stack.push((true, traceable));
            }
            let mut carriers = Vec::new();
            for m in &moves[at + 1..] {
                if m.3 > 0 {
                    let held = (m.3 - overdraft).max(0);
                    overdraft = (overdraft - m.3).max(0);
                    if held > 0 {
                        stack.push((false, held));
                    }
                } else {
                    let mut rem = -m.3;
                    while rem > 0 && !stack.is_empty() {
                        let last = stack.last_mut().expect("non-empty");
                        let take = rem.min(last.1);
                        if last.0 && take > 0 {
                            carriers.push(m.2);
                        }
                        last.1 -= take;
                        rem -= take;
                        if last.1 == 0 {
                            stack.pop();
                        }
                    }
                    overdraft += rem;
                }
            }
            let traced = stack.into_iter().filter(|(t, _)| *t).map(|(_, a)| a).sum();
            carriers.sort_unstable();
            carriers.dedup();
            (traced, carriers)
        }
        TraceLaw::ProRata => {
            let mut overdraft = (initial_overdraft - deposit).max(0);
            let mut tainted = traceable;
            let mut clean = initial_clean;
            let mut carriers = Vec::new();
            for m in &moves[at + 1..] {
                if m.3 > 0 {
                    let held = (m.3 - overdraft).max(0);
                    overdraft = (overdraft - m.3).max(0);
                    clean += held;
                } else {
                    let w = -m.3;
                    let pool = tainted + clean;
                    let drawn = w.min(pool.max(0));
                    overdraft += w - drawn;
                    if drawn == 0 {
                        continue;
                    }
                    let t_out = drawn * tainted / pool;
                    if t_out > 0 {
                        carriers.push(m.2);
                    }
                    tainted -= t_out;
                    clean -= drawn - t_out;
                }
            }
            carriers.sort_unstable();
            carriers.dedup();
            (tainted, carriers)
        }
    }
}

/// Naive tracing under `StatementOrdinal` (recorded order).
pub fn trace(
    rows: &[Row],
    account: &str,
    source: usize,
    claim: DateDay,
    law: TraceLaw,
) -> (i128, Vec<usize>) {
    trace_with_order(
        rows,
        account,
        source,
        claim,
        law,
        IntradayOrder::StatementOrdinal,
    )
}

fn gcd_i128(mut a: i128, mut b: i128) -> i128 {
    a = a.abs();
    b = b.abs();
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a.max(1)
}

fn rat_add(a: (i128, i128), b: (i128, i128)) -> (i128, i128) {
    if a.0 == 0 {
        return b;
    }
    if b.0 == 0 {
        return a;
    }
    let g = gcd_i128(a.1, b.1);
    let den = (a.1 / g) * b.1;
    let num = a.0 * (b.1 / g) + b.0 * (a.1 / g);
    if num == 0 {
        return (0, 1);
    }
    let g2 = gcd_i128(num, den);
    (num / g2, den / g2)
}

fn rat_mul(a: (i128, i128), b: (i128, i128)) -> (i128, i128) {
    if a.0 == 0 || b.0 == 0 {
        return (0, 1);
    }
    let g1 = gcd_i128(a.0, b.1);
    let g2 = gcd_i128(b.0, a.1);
    let num = (a.0 / g1) * (b.0 / g2);
    let den = (a.1 / g2) * (b.1 / g1);
    let g3 = gcd_i128(num, den);
    (num / g3, den / g3)
}

/// Independent multi-hop network LIBR oracle via layered `s-t` cut enumeration
/// over the time-expanded asset-account graph (`max_flow == min_cut`).
///
/// Requires `assets.len() <= 10` so that the exact subset cut enumeration
/// across `2^|assets|` account subsets per time step runs in bounded time.
pub fn network_libr_min_cut(
    rows: &[Row],
    assets: &[&str],
    source_account: &str,
    source: usize,
    claim: DateDay,
) -> i128 {
    assert!(
        assets.len() <= 10,
        "network_libr_min_cut subset oracle expects at most 10 asset accounts"
    );
    let asset_idx = |name: &str| -> Option<usize> { assets.iter().position(|a| *a == name) };
    let src_acct = asset_idx(source_account).expect("source_account must be in assets");

    let mut moves: Vec<(i32, usize, String, String, i128)> = Vec::new();
    for r in live_rows_through(rows, Some(claim)) {
        if let Some((from, to, _unit, m)) = transfer(r)
            && from != to
            && m > 0
        {
            moves.push((r.date.0, r.index, from.to_string(), to.to_string(), m));
        }
    }
    moves.sort_by_key(|m| (m.0, m.1));
    let at = moves
        .iter()
        .position(|m| m.1 == source && m.3 == source_account)
        .expect("source row deposits into source_account");

    let k = assets.len();
    let mut bal = vec![0i128; k];
    for m in &moves[..at] {
        if let Some(fi) = asset_idx(&m.2) {
            bal[fi] -= m.4;
        }
        if let Some(ti) = asset_idx(&m.3) {
            bal[ti] += m.4;
        }
    }
    let deposit = moves[at].4;
    let init_od = (-bal[src_acct]).max(0);
    let traceable = (deposit - init_od).max(0);
    bal[src_acct] += deposit;
    if traceable == 0 {
        return 0;
    }

    let n_subsets = 1usize << k;
    let mut dp = vec![i128::MAX / 4; n_subsets];
    for (mask, slot) in dp.iter_mut().enumerate() {
        // If `src_acct` is not in the S-side mask at step 0, the source edge is cut.
        *slot = if (mask & (1 << src_acct)) == 0 {
            traceable
        } else {
            0
        };
    }

    for m in &moves[at + 1..] {
        let from_i = asset_idx(&m.2);
        let to_i = asset_idx(&m.3);
        let amount = m.4;
        let drawn = from_i.map_or(0, |fi| amount.min(bal[fi].max(0)));
        let surv = to_i.map_or(0, |ti| {
            let od = (-bal[ti]).max(0);
            (amount - od).max(0)
        });
        let xfer_cap = if from_i.is_some() && to_i.is_some() {
            drawn.min(surv).min(traceable)
        } else {
            0
        };

        let mut surv_caps = vec![0i128; k];
        for a in 0..k {
            let avail = bal[a].max(0);
            let rem = if Some(a) == from_i {
                (avail - drawn).max(0)
            } else {
                avail
            };
            surv_caps[a] = rem.min(traceable);
        }

        let mut next_dp = vec![i128::MAX / 4; n_subsets];
        for (mask_u, &base_cost) in dp.iter().enumerate() {
            for (mask_v, next_slot) in next_dp.iter_mut().enumerate() {
                let mut step_cut = 0i128;
                for (a, &sc) in surv_caps.iter().enumerate() {
                    if (mask_u & (1 << a)) != 0 && (mask_v & (1 << a)) == 0 {
                        step_cut = (step_cut + sc).min(traceable);
                    }
                }
                if xfer_cap > 0
                    && let (Some(fi), Some(ti)) = (from_i, to_i)
                    && (mask_u & (1 << fi)) != 0
                    && (mask_v & (1 << ti)) == 0
                {
                    step_cut = (step_cut + xfer_cap).min(traceable);
                }
                let candidate = (base_cost + step_cut).min(traceable);
                if candidate < *next_slot {
                    *next_slot = candidate;
                }
            }
        }
        dp = next_dp;

        if let Some(fi) = from_i {
            bal[fi] -= amount;
        }
        if let Some(ti) = to_i {
            bal[ti] += amount;
        }
    }

    let mut best = traceable;
    for (mask, &cost) in dp.iter().enumerate() {
        let mut sink_cut = 0i128;
        for (a, &b) in bal.iter().enumerate() {
            if (mask & (1 << a)) != 0 {
                sink_cut = (sink_cut + b.max(0)).min(traceable);
            }
        }
        best = best.min(cost + sink_cut);
    }
    best
}

/// Independent multi-hop network Pro-Rata oracle using exact reduced rational
/// `(num, den)` propagation rounded once at the output via largest-remainder.
/// Returns `BTreeMap<account, held_mantissa>`.
pub fn network_pro_rata_held(
    rows: &[Row],
    assets: &[&str],
    source_account: &str,
    source: usize,
    claim: DateDay,
) -> BTreeMap<String, i128> {
    let is_asset = |name: &str| assets.contains(&name);
    let mut moves: Vec<(i32, usize, String, String, i128)> = Vec::new();
    for r in live_rows_through(rows, Some(claim)) {
        if let Some((from, to, _unit, m)) = transfer(r)
            && from != to
            && m > 0
        {
            moves.push((r.date.0, r.index, from.to_string(), to.to_string(), m));
        }
    }
    moves.sort_by_key(|m| (m.0, m.1));
    let at = moves
        .iter()
        .position(|m| m.1 == source && m.3 == source_account)
        .expect("source row deposits into source_account");

    let mut bal: BTreeMap<String, i128> = BTreeMap::new();
    for m in &moves[..at] {
        if is_asset(&m.2) {
            *bal.entry(m.2.clone()).or_default() -= m.4;
        }
        if is_asset(&m.3) {
            *bal.entry(m.3.clone()).or_default() += m.4;
        }
    }

    type Path = Vec<(usize, String, String)>;
    type Lot = (Path, (i128, i128));
    // Disposition tag: 0 = Held, 1 = Spent, 2 = RepaidOverdraft (matching Disposition order).
    type Terminal = (String, u8, Path);
    let mut lots: BTreeMap<String, Vec<Lot>> = BTreeMap::new();
    let mut terminal: BTreeMap<Terminal, (i128, i128)> = BTreeMap::new();

    let src_move = &moves[at];
    let deposit = src_move.4;
    let init_od = (-bal.get(source_account).copied().unwrap_or(0)).max(0);
    let repaid = deposit.min(init_od);
    let traceable = deposit - repaid;
    *bal.entry(source_account.to_string()).or_default() += deposit;
    let init_path: Path = vec![(src_move.1, src_move.2.clone(), src_move.3.clone())];
    if repaid > 0 {
        terminal.insert(
            (source_account.to_string(), 2, init_path.clone()),
            (repaid, 1),
        );
    }
    if traceable > 0 {
        lots.entry(source_account.to_string())
            .or_default()
            .push((init_path, (traceable, 1)));
    }

    for m in &moves[at + 1..] {
        let (_, entry, from, to, amount) = m;
        let mut moved: Vec<(Path, (i128, i128))> = Vec::new();
        if is_asset(from) {
            let b_before = bal.get(from).copied().unwrap_or(0);
            let avail = b_before.max(0);
            let drawn = (*amount).min(avail);
            *bal.entry(from.clone()).or_default() -= *amount;
            if drawn > 0
                && avail > 0
                && let Some(prev_lots) = lots.remove(from)
            {
                let mut kept_lots = Vec::new();
                for (path, r) in prev_lots {
                    let out = rat_mul(r, (drawn, avail));
                    let kept = rat_mul(r, (avail - drawn, avail));
                    if kept.0 > 0 {
                        kept_lots.push((path.clone(), kept));
                    }
                    if out.0 > 0 {
                        let mut ext = path;
                        ext.push((*entry, from.clone(), to.clone()));
                        if is_asset(to) {
                            moved.push((ext, out));
                        } else {
                            let e = terminal.entry((to.clone(), 1, ext)).or_insert((0, 1));
                            *e = rat_add(*e, out);
                        }
                    }
                }
                if !kept_lots.is_empty() {
                    lots.insert(from.clone(), kept_lots);
                }
            }
        }
        if is_asset(to) {
            let b_before = bal.get(to).copied().unwrap_or(0);
            let od = (-b_before).max(0);
            let repaid_to = (*amount).min(od);
            let surv_to = *amount - repaid_to;
            *bal.entry(to.clone()).or_default() += *amount;
            for (path, r) in moved {
                if repaid_to == 0 {
                    let list = lots.entry(to.clone()).or_default();
                    if let Some(ex) = list.iter_mut().find(|(p, _)| *p == path) {
                        ex.1 = rat_add(ex.1, r);
                    } else {
                        list.push((path, r));
                    }
                } else if surv_to == 0 {
                    let e = terminal.entry((to.clone(), 2, path)).or_insert((0, 1));
                    *e = rat_add(*e, r);
                } else {
                    let rep_r = rat_mul(r, (repaid_to, *amount));
                    let surv_r = rat_mul(r, (surv_to, *amount));
                    if rep_r.0 > 0 {
                        let e = terminal
                            .entry((to.clone(), 2, path.clone()))
                            .or_insert((0, 1));
                        *e = rat_add(*e, rep_r);
                    }
                    if surv_r.0 > 0 {
                        let list = lots.entry(to.clone()).or_default();
                        if let Some(ex) = list.iter_mut().find(|(p, _)| *p == path) {
                            ex.1 = rat_add(ex.1, surv_r);
                        } else {
                            list.push((path, surv_r));
                        }
                    }
                }
            }
        }
    }

    for (acct, acct_lots) in lots {
        for (path, r) in acct_lots {
            if r.0 > 0 {
                let e = terminal.entry((acct.clone(), 0, path)).or_insert((0, 1));
                *e = rat_add(*e, r);
            }
        }
    }

    let entries: Vec<(Terminal, (i128, i128))> = terminal.into_iter().collect();
    let mut floors: Vec<i128> = Vec::with_capacity(entries.len());
    let mut rems: Vec<(usize, i128, i128)> = Vec::with_capacity(entries.len());
    let mut floor_sum = 0i128;
    for (idx, (_, (num, den))) in entries.iter().enumerate() {
        let q = num / den;
        let rem = num % den;
        floors.push(q);
        floor_sum += q;
        rems.push((idx, rem, *den));
    }
    let deficit = (deposit - floor_sum).max(0) as usize;
    rems.sort_by(|a, b| {
        let lhs = a.1 * b.2;
        let rhs = b.1 * a.2;
        rhs.cmp(&lhs).then_with(|| a.0.cmp(&b.0))
    });
    for &(idx, _, _) in rems.iter().take(deficit) {
        floors[idx] += 1;
    }

    let mut held_by_acct: BTreeMap<String, i128> = BTreeMap::new();
    for (((acct, disp, _), _), val) in entries.into_iter().zip(floors) {
        if disp == 0 && val > 0 {
            *held_by_acct.entry(acct).or_default() += val;
        }
    }
    held_by_acct
}

/// Independent reference oracle for finite-sample split-conformal quantile
/// (`fa-dh9g`). Returns `(quantile_rank_1based, calibrated_threshold)`.
#[must_use]
pub fn naive_split_conformal_quantile(clean_scores: &[i128], alpha_bps: u32) -> (usize, i128) {
    let mut s = clean_scores.to_vec();
    s.sort();
    let n = s.len();
    let num = ((n as u128) + 1) * (10_000u128 - u128::from(alpha_bps));
    let k = num.div_ceil(10_000) as usize;
    if k == 0 {
        (1, s[0])
    } else if k <= n {
        (k, s[k - 1])
    } else {
        (n + 1, i128::MAX)
    }
}

/// Independent reference oracle for 95% Wilson confidence interval in basis
/// points (`fa-dh9g`). Returns `(point_estimate_bps, lower_bps, upper_bps)`.
#[must_use]
pub fn naive_wilson_interval_bps(successes: u64, trials: u64) -> (u32, u32, u32) {
    if trials == 0 {
        return (0, 0, 10_000);
    }
    let k = u128::from(successes.min(trials));
    let n = u128::from(trials);
    let pt = ((k * 10_000) / n) as u32;
    let denom = n * (10_000 * n + 38_416);
    let center = 10_000 * n * (10_000 * k + 19_208);
    let rad = n * (40_000 * k * (n - k) + 38_416 * n);
    let half = 980_000 * rad.isqrt();
    let lo = ((center.saturating_sub(half)) / denom) as u32;
    let hi = ((center + half).div_ceil(denom)).min(10_000) as u32;
    (pt, lo.min(pt), hi.max(pt))
}

/// Independent reference oracle for Monetary Unit Sampling (`fa-kaf7`).
///
/// Given canonical `(item_id, book_value_mantissa)` pairs, `start_mantissa` in
/// `1..=interval`, and `interval_mantissa`, returns the selected `item_id` list.
#[must_use]
pub fn naive_sample_mus(
    items: &[(String, i128)],
    start_mantissa: i128,
    interval_mantissa: i128,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut cum: i128 = 0;
    let mut hit = start_mantissa;
    for (id, val) in items {
        if *val >= interval_mantissa {
            out.push(id.clone());
            continue;
        }
        let next = cum + *val;
        if hit <= next {
            out.push(id.clone());
            while hit <= next {
                hit += interval_mantissa;
            }
        }
        cum = next;
    }
    out
}

/// Independent reference oracle for the Stringer upper misstatement limit
/// (`fa-kaf7`) using `Int` limb arithmetic.
#[must_use]
pub fn naive_stringer_bound_mantissa(
    interval_mantissa: i128,
    confidence_level_bps: u32,
    audited_pairs: &[(i128, i128)],
) -> i128 {
    use crate::Int;
    // The one-sided Poisson upper limits for 0..=40 misstatements, each
    // rounded up to 0.01 (basis points); the engine refuses beyond them.
    let factors: &[i128] = match confidence_level_bps {
        9_000 => &[
            23_100, 38_900, 53_300, 66_900, 80_000, 92_800, 105_400, 117_800, 130_000, 142_100,
            154_100, 166_000, 177_900, 189_600, 201_300, 213_000, 224_600, 236_100, 247_600,
            259_100, 270_500, 281_900, 293_300, 304_600, 315_900, 327_200, 338_400, 349_600,
            360_800, 372_000, 383_200, 394_300, 405_500, 416_600, 427_700, 438_800, 449_800,
            460_900, 471_900, 482_900, 494_000,
        ],
        9_500 => &[
            30_000, 47_500, 63_000, 77_600, 91_600, 105_200, 118_500, 131_500, 144_400, 157_100,
            169_700, 182_100, 194_500, 206_700, 218_900, 231_000, 243_100, 255_000, 267_000,
            278_800, 290_700, 302_500, 314_200, 325_900, 337_600, 349_200, 360_800, 372_400,
            383_900, 395_500, 407_000, 418_400, 429_900, 441_300, 452_700, 464_100, 475_500,
            486_800, 498_100, 509_400, 520_700,
        ],
        _ => &[
            46_100, 66_400, 84_100, 100_500, 116_100, 131_100, 145_800, 160_000, 174_100, 187_900,
            201_500, 214_900, 228_300, 241_400, 254_500, 267_500, 280_400, 293_100, 305_900,
            318_500, 331_100, 343_600, 356_100, 368_500, 380_800, 393_100, 405_400, 417_600,
            429_800, 441_900, 454_100, 466_100, 478_200, 490_200, 502_200, 514_100, 526_100,
            538_000, 549_800, 561_700, 573_500,
        ],
    };

    let mut top_over: i128 = 0;
    let mut taints: Vec<(i128, i128)> = Vec::new();
    for &(bv, av) in audited_pairs {
        let over = bv - av;
        if over <= 0 {
            continue;
        }
        if bv >= interval_mantissa {
            top_over += over;
        } else {
            taints.push((over, bv));
        }
    }
    taints.sort_by(|a, b| (b.0 * a.1).cmp(&(a.0 * b.1)));

    // Exact common-denominator sum over (10_000 * prod(bv_i)) using Int limbs:
    let mut common_den = Int::from_i128(10_000);
    for &(_, bv) in &taints {
        common_den = common_den.mul(&Int::from_i128(bv));
    }
    let mut prod_bv = Int::from_i128(1);
    for &(_, bv) in &taints {
        prod_bv = prod_bv.mul(&Int::from_i128(bv));
    }

    // Numerator starts with interval * R(0) * prod_bv + top_over * 10_000 * prod_bv
    let top_term = Int::from_i128(top_over)
        .mul(&Int::from_i128(10_000))
        .mul(&prod_bv);
    let mut num = Int::from_i128(interval_mantissa)
        .mul(&Int::from_i128(factors[0]))
        .mul(&prod_bv)
        .add(&top_term);

    for (idx, &(over, bv)) in taints.iter().enumerate() {
        let rk = factors[idx + 1];
        let rk_prev = factors[idx];
        let delta_r = rk - rk_prev;
        let mut other_bv = Int::from_i128(1);
        for (j, &(_, bv_j)) in taints.iter().enumerate() {
            if j != idx {
                other_bv = other_bv.mul(&Int::from_i128(bv_j));
            }
        }
        let _ = bv;
        let term = Int::from_i128(interval_mantissa)
            .mul(&Int::from_i128(delta_r))
            .mul(&Int::from_i128(over))
            .mul(&other_bv);
        num = num.add(&term);
    }

    let num_i = num.to_i128().expect("fits i128");
    let den_i = common_den.to_i128().expect("fits i128");
    (num_i + den_i - 1) / den_i
}

/// Independent reference oracle for `jet.unusual_accounts` (`FA-EVID-L24`).
#[must_use]
pub fn unusual_accounts(rows: &[Row], max_pair_count: usize, min_population: usize) -> Vec<usize> {
    let live = live_rows(rows);
    if live.len() < min_population {
        return Vec::new();
    }
    let mut pair_counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    for r in &live {
        let debits: BTreeSet<String> = r
            .legs
            .iter()
            .filter(|l| l.debit)
            .map(|l| l.account.clone())
            .collect();
        let credits: BTreeSet<String> = r
            .legs
            .iter()
            .filter(|l| !l.debit)
            .map(|l| l.account.clone())
            .collect();
        let mut row_pairs = BTreeSet::new();
        for d in &debits {
            for c in &credits {
                let p = if d <= c {
                    (d.clone(), c.clone())
                } else {
                    (c.clone(), d.clone())
                };
                row_pairs.insert(p);
            }
        }
        for p in row_pairs {
            *pair_counts.entry(p).or_insert(0) += 1;
        }
    }
    let mut out = Vec::new();
    for r in &live {
        let debits: BTreeSet<String> = r
            .legs
            .iter()
            .filter(|l| l.debit)
            .map(|l| l.account.clone())
            .collect();
        let credits: BTreeSet<String> = r
            .legs
            .iter()
            .filter(|l| !l.debit)
            .map(|l| l.account.clone())
            .collect();
        let mut min_c = usize::MAX;
        for d in &debits {
            for c in &credits {
                let p = if d <= c {
                    (d.clone(), c.clone())
                } else {
                    (c.clone(), d.clone())
                };
                if let Some(&cnt) = pair_counts.get(&p) {
                    min_c = min_c.min(cnt);
                }
            }
        }
        if min_c <= max_pair_count {
            out.push(r.index);
        }
    }
    out
}

/// Independent reference oracle for `benford.second_digit` (`FA-EVID-L30`).
#[must_use]
pub fn second_digit_counts_for(rows: &[Row], unit: Option<u32>, debit: bool) -> [u64; 10] {
    let mut counts = [0u64; 10];
    for r in live_rows(rows) {
        for l in &r.legs {
            if l.debit != debit || unit.is_some_and(|u| l.unit != u) {
                continue;
            }
            let min = 10i128.pow(l.scale) * 10;
            if l.mantissa.abs() >= min {
                let s = l.mantissa.abs().to_string();
                let bytes = s.as_bytes();
                if bytes.len() >= 2 {
                    let d = (bytes[1] - b'0') as usize;
                    counts[d] += 1;
                }
            }
        }
    }
    counts
}

/// Independent reference oracle for `benford.first_two_digits` (`FA-EVID-L31`).
#[must_use]
pub fn first_two_digits_counts_for(rows: &[Row], unit: Option<u32>, debit: bool) -> [u64; 90] {
    let mut counts = [0u64; 90];
    for r in live_rows(rows) {
        for l in &r.legs {
            if l.debit != debit || unit.is_some_and(|u| l.unit != u) {
                continue;
            }
            let min = 10i128.pow(l.scale) * 10;
            if l.mantissa.abs() >= min {
                let s = l.mantissa.abs().to_string();
                let bytes = s.as_bytes();
                if bytes.len() >= 2 {
                    let d1 = (bytes[0] - b'0') as usize;
                    let d2 = (bytes[1] - b'0') as usize;
                    let two = d1 * 10 + d2;
                    if (10..=99).contains(&two) {
                        counts[two - 10] += 1;
                    }
                }
            }
        }
    }
    counts
}

/// Independent reference oracle for `numbers.relative_size_factor` (`FA-EVID-L32`)
/// grouped by debit account and unit.
#[must_use]
pub fn relative_size_factor_by_account(
    rows: &[Row],
    min_subset_size: usize,
    min_rsf_bps: i128,
) -> Vec<(String, u32, i128)> {
    let mut groups: BTreeMap<(String, u32), Vec<i128>> = BTreeMap::new();
    for r in live_rows(rows) {
        for l in &r.legs {
            if l.debit && l.mantissa.abs() > 0 {
                groups
                    .entry((l.account.clone(), l.unit))
                    .or_default()
                    .push(l.mantissa.abs());
            }
        }
    }
    let mut out = Vec::new();
    for ((acct, unit), mut vals) in groups {
        if vals.len() < min_subset_size {
            continue;
        }
        vals.sort_by(|a, b| b.cmp(a));
        let largest = vals[0];
        let second = vals[1];
        if second > 0 {
            let rsf_bps = (largest * 10_000) / second;
            if rsf_bps >= min_rsf_bps {
                out.push((acct, unit, rsf_bps));
            }
        }
    }
    out
}

/// Independent reference oracle for Benford integer expected counts under
/// LargestRemainder (`fa-vpk`): given population `n` and `expected_1e9`
/// proportions summing to `10^9`, returns bucket counts summing to `n`.
#[must_use]
pub fn naive_benford_expected_counts(n: u64, expected_1e9: &[i128]) -> Vec<u64> {
    let n_i = i128::from(n);
    let mut floors: Vec<u64> = Vec::with_capacity(expected_1e9.len());
    let mut rems: Vec<(i128, usize)> = Vec::with_capacity(expected_1e9.len());
    let mut floor_sum: u64 = 0;
    for (idx, &p) in expected_1e9.iter().enumerate() {
        let prod = n_i * p;
        let q = (prod / 1_000_000_000) as u64;
        let r = prod % 1_000_000_000;
        floors.push(q);
        floor_sum += q;
        rems.push((r, idx));
    }
    let deficit = n.saturating_sub(floor_sum) as usize;
    rems.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    for &(_, idx) in rems.iter().take(deficit) {
        floors[idx] += 1;
    }
    floors
}

/// Independent reference oracle for Nigrini MAD at `10^9` scale over an
/// arbitrary expected-proportion table (`fa-vpk`).
#[must_use]
pub fn naive_mad_table_1e9(counts: &[u64], expected_1e9: &[i128]) -> i128 {
    let k = expected_1e9.len() as i128;
    let n: i128 = counts.iter().map(|c| i128::from(*c)).sum();
    if n == 0 || k == 0 {
        return 0;
    }
    let mut total = 0i128;
    for (&c, &p) in counts.iter().zip(expected_1e9.iter()) {
        let obs = i128::from(c) * 1_000_000_000;
        let exp = n * p;
        total += (obs - exp).abs();
    }
    total / (k * n)
}

/// Independent reference oracle for Pearson's chi-square at `10^6` scale over
/// an arbitrary expected-proportion table (`fa-vpk`).
#[must_use]
pub fn naive_chi_square_table_1e6(counts: &[u64], expected_1e9: &[i128]) -> i128 {
    let n: i128 = counts.iter().map(|c| i128::from(*c)).sum();
    if n == 0 {
        return 0;
    }
    let mut sum = 0i128;
    for (&c, &p) in counts.iter().zip(expected_1e9.iter()) {
        let diff = i128::from(c) * 1_000_000_000 - n * p;
        let num = diff * diff * 1_000_000;
        let den = n * p * 1_000_000_000;
        sum += num / den;
    }
    sum
}

/// Independent reference oracle for Kolmogorov-Smirnov supremum distance
/// $D = \max_k |F_{\text{obs}}(k) - F_{\text{exp}}(k)|$ at `10^9` scale (`fa-vpk`).
#[must_use]
pub fn naive_ks_table_1e9(counts: &[u64], expected_1e9: &[i128]) -> i128 {
    let n: i128 = counts.iter().map(|c| i128::from(*c)).sum();
    if n == 0 {
        return 0;
    }
    let mut cum_obs = 0i128;
    let mut cum_exp = 0i128;
    let mut max_d = 0i128;
    for (&c, &p) in counts.iter().zip(expected_1e9.iter()) {
        cum_obs += i128::from(c);
        cum_exp += p;
        let diff = (cum_obs * 1_000_000_000 - n * cum_exp).abs() / n;
        if diff > max_d {
            max_d = diff;
        }
    }
    max_d
}

/// One leg of the literal PAID fold (bead fa-b6xs): its side, every party
/// dimension value it names, its unit, the legal entity it names (if any),
/// and its magnitude.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaidLeg {
    pub debit: bool,
    pub party_values: Vec<u128>,
    pub unit: u32,
    pub entity: Option<u128>,
    pub mantissa: i128,
}

/// The book itself as a PAID node: a leg naming no party value, or several.
pub const PAID_BOOK: u128 = 0;

/// The literal PAID fold, `(from, to, unit, entity) -> total`, over live
/// posting entries given as their legs, with `parties` mapping a party
/// dimension value to its party. Per entry and `(unit, entity)`: a leg's node
/// is the party of its one party value (the value itself when no party
/// carries it), else the book; each credit, ascending by `(node, magnitude)`,
/// is spread over the debits' remaining capacity, ascending by `(node,
/// magnitude)`, by Hamilton largest remainder with ties to the lower index;
/// a transfer from a node to itself is dropped. A leg naming no legal entity
/// takes the one entity the population names, or none when none is named;
/// several named entities and an unnamed leg is refused.
pub fn paid_fold(
    entries: &[Vec<PaidLeg>],
    parties: &BTreeMap<u128, u128>,
) -> Result<BTreeMap<(u128, u128, u32, Option<u128>), i128>, &'static str> {
    type Legs = Vec<(u128, i128)>;
    let named: BTreeSet<u128> = entries.iter().flatten().filter_map(|l| l.entity).collect();
    let mut totals: BTreeMap<(u128, u128, u32, Option<u128>), crate::Int> = BTreeMap::new();
    for legs in entries {
        let mut partitions: BTreeMap<(u32, Option<u128>), (Legs, Legs)> = BTreeMap::new();
        for leg in legs {
            if leg.mantissa < 0 {
                return Err("a negative leg");
            }
            let entity = match (leg.entity, named.len()) {
                (Some(entity), _) => Some(entity),
                (None, 0) => None,
                (None, 1) => named.first().copied(),
                (None, _) => return Err("an unnamed legal entity among several"),
            };
            let node = match leg.party_values.as_slice() {
                [value] => parties.get(value).copied().unwrap_or(*value),
                _ => PAID_BOOK,
            };
            let slot = partitions.entry((leg.unit, entity)).or_default();
            if leg.debit {
                slot.1.push((node, leg.mantissa));
            } else {
                slot.0.push((node, leg.mantissa));
            }
        }
        for ((unit, entity), (mut credits, mut debits)) in partitions {
            let margin = |side: &Legs| {
                side.iter().fold(crate::Int::zero(), |sum, (_, m)| {
                    sum.add(&crate::Int::from_u128(m.unsigned_abs()))
                })
            };
            if margin(&credits) != margin(&debits) {
                return Err("an unbalanced partition");
            }
            credits.sort_unstable();
            debits.sort_unstable();
            let mut remaining: Vec<u128> = debits.iter().map(|(_, m)| m.unsigned_abs()).collect();
            for (from, amount) in credits {
                if amount == 0 {
                    continue;
                }
                let shares = crate::reports::largest_remainder(amount, &remaining)?;
                for (i, share) in shares.into_iter().enumerate() {
                    let share = share.unsigned_abs();
                    remaining[i] = remaining[i]
                        .checked_sub(share)
                        .ok_or("a debit over its capacity")?;
                    let to = debits[i].0;
                    if share != 0 && from != to {
                        let slot = totals
                            .entry((from, to, unit, entity))
                            .or_insert_with(crate::Int::zero);
                        *slot = slot.add(&crate::Int::from_u128(share));
                    }
                }
            }
            if remaining.iter().any(|r| *r != 0) {
                return Err("an unallocated debit");
            }
        }
    }
    totals
        .into_iter()
        .map(|(key, total)| {
            total
                .to_i128()
                .map(|t| (key, t))
                .ok_or("a PAID total past i128")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(index: usize, day: u8, debit: &str, credit: &str, unit: u32, mantissa: i128) -> Row {
        Row {
            index,
            date: DateDay::from_ymd(2026, 1, day).unwrap(),
            document_date: None,
            period: "FY2026-P01".into(),
            period_start: Some(DateDay::from_ymd(2026, 1, 1).unwrap()),
            period_end: DateDay::from_ymd(2026, 2, 1).unwrap(),
            legs: vec![
                Leg {
                    account: debit.into(),
                    debit: true,
                    unit,
                    scale: 2,
                    mantissa,
                },
                Leg {
                    account: credit.into(),
                    debit: false,
                    unit,
                    scale: 2,
                    mantissa,
                },
            ],
            preparer: "P1".into(),
            approvers: Vec::new(),
            description_chars: Some(12),
            external_ids: Vec::new(),
            recorded_after_close: false,
            reverses: None,
            replaces: None,
        }
    }

    #[test]
    fn naive_oracle_handles_intraday_order_overdraft_and_unit_scoped_structuring() {
        // Same-day deposit (row 1) then withdrawal (row 2) on account 1020.
        let rows = vec![
            row(0, 2, "1020", "4000", 840, 100_000),
            row(1, 9, "1020", "4000", 840, 50_000),
            row(2, 9, "6000", "1020", 840, 60_000),
        ];
        let claim = DateDay::from_ymd(2026, 1, 31).unwrap();
        assert_eq!(
            trace_with_order(
                &rows,
                "1020",
                1,
                claim,
                TraceLaw::Lifo,
                IntradayOrder::StatementOrdinal
            )
            .0,
            0
        );
        assert_eq!(
            trace_with_order(
                &rows,
                "1020",
                1,
                claim,
                TraceLaw::Lifo,
                IntradayOrder::WithdrawalsFirst
            )
            .0,
            50_000
        );

        // Multi-unit structuring: 3 USD (840) transfers and 3 JPY (392) transfers.
        let s_rows = vec![
            row(0, 10, "1000", "4000", 840, 900_000),
            row(1, 11, "1000", "4000", 840, 910_000),
            row(2, 12, "1000", "4000", 840, 920_000),
            row(3, 10, "1000", "4000", 392, 900_000),
            row(4, 11, "1000", "4000", 392, 910_000),
            row(5, 12, "1000", "4000", 392, 920_000),
        ];
        assert_eq!(
            structuring_for_unit(&s_rows, Some(840), 1_000_000, 800_000, 7, 3),
            vec![("4000".into(), "1000".into(), vec![0, 1, 2])]
        );
        assert_eq!(
            structuring_for_unit(&s_rows, Some(392), 1_000_000, 800_000, 7, 3),
            vec![("4000".into(), "1000".into(), vec![3, 4, 5])]
        );
    }

    #[test]
    fn network_libr_and_pro_rata_oracles_handle_commingled_multi_hop_transfers() {
        let rows = vec![
            row(0, 1, "1000", "3000", 840, 10_000), // clean in 1000
            row(1, 2, "1000", "4000", 840, 10_000), // tainted source in 1000 (pool = 20_000)
            row(2, 3, "1010", "1000", 840, 10_000), // transfer 10_000 from 1000 -> 1010
            row(3, 4, "6000", "1000", 840, 5_000),  // spend 5_000 from 1000
        ];
        let claim = DateDay::from_ymd(2026, 1, 31).unwrap();
        let assets = ["1000", "1010"];
        // Under LIBR, 5_000 remains in 1000 and up to 10_000 could have moved to 1010,
        // so total held is capped at traceable = 10_000 (5_000 in 1000 + 5_000 in 1010).
        assert_eq!(
            network_libr_min_cut(&rows, &assets, "1000", 1, claim),
            10_000
        );
        // Under Pro-Rata, 50% of 1000's 10_000 transfer to 1010 is tainted (5_000 in 1010),
        // and of the remaining 5_000 in 1000 after 5_000 is spent, 50% is tainted (2_500 in 1000).
        let pr = network_pro_rata_held(&rows, &assets, "1000", 1, claim);
        assert_eq!(pr.get("1000").copied().unwrap_or(0), 2_500);
        assert_eq!(pr.get("1010").copied().unwrap_or(0), 5_000);
    }
}
