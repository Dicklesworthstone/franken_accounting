//! Naive Lantern procedures (plan §11; bead fa-nlu): the literal definitions
//! fa-lantern's folds must agree with, over a flat row model the
//! differential test builds from the same intents it posts to the kernel.
//! Deliberately simple, single pass where possible, own arithmetic.

use std::collections::BTreeSet;

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
}
