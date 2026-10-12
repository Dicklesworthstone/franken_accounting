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
            let d = r.period_end.0 - r.date.0;
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

/// Pairs `(i, j)` with `i < j` of rows with the same legs whose dates differ
/// by 1..=window days.
pub fn same_same_different(rows: &[Row], window: i32) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for a in rows {
        for b in rows {
            if a.index < b.index && leg_key(a) == leg_key(b) {
                let apart = (a.date.0 - b.date.0).abs();
                if (1..=window).contains(&apart) {
                    out.push((a.index, b.index));
                }
            }
        }
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
