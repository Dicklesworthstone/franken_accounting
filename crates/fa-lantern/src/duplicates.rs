//! Duplicate detection (plan §11.3): entries with the same leg multiset
//! (account, side, unit, magnitude) on the same date, or on different dates
//! inside a window, and `duplicates.near`: the same leg shape (account,
//! side, unit, dimensions, so the same parties) with amounts inside a
//! tolerance and similar descriptions.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use fa_journal::genesis::BookContext;
use fa_model::limits::MAX_DESCRIPTION_BYTES;
use fa_money::Side;
use fgdb_types::VId;

use crate::jet::{finding, procedure_boilerplate};
use crate::{
    Cite, Finding, LanternError, MAX_CITES, Meter, Params, Procedure, Severity, Snapshot,
    SnapshotEntry, Statistic,
};

type LegMultiset = Vec<(u128, u8, u32, i128)>;

fn leg_multiset(e: &SnapshotEntry, work: &mut Meter<'_>) -> Result<LegMultiset, LanternError> {
    for _ in &e.entry.proposal.legs {
        work.leg()?;
    }
    let mut s: LegMultiset = e
        .entry
        .proposal
        .legs
        .iter()
        .map(|l| {
            (
                l.account_ref.0,
                match l.side {
                    Side::Debit => 0,
                    Side::Credit => 1,
                },
                l.amount.unit.0,
                l.amount.mantissa,
            )
        })
        .collect();
    s.sort_unstable();
    Ok(s)
}

/// `duplicates.same_same_same`: same legs, same effective date.
pub struct SameSameSame {
    params: Params,
}
procedure_boilerplate!(SameSameSame, "duplicates.same_same_same");

impl Procedure for SameSameSame {
    fn id(&self) -> &'static str {
        Self::ID
    }
    fn version(&self) -> u16 {
        1
    }
    fn params(&self) -> &Params {
        &self.params
    }
    fn run(
        &self,
        snapshot: &Snapshot,
        _book: &BookContext,
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        let mut groups: BTreeMap<(LegMultiset, i32), Vec<VId>> = BTreeMap::new();
        let mut population = 0u64;
        let has_supersession = snapshot
            .entries
            .iter()
            .any(|e| !e.entry.proposal.supersession.is_empty());
        for e in snapshot.live_postings()? {
            work.entry()?;
            population += 1;
            let list = groups
                .entry((leg_multiset(e, work)?, e.entry.proposal.effective_date.0))
                .or_default();
            if !has_supersession
                || list
                    .iter()
                    .all(|&other| !snapshot.shares_supersession_lineage(other, e.vid))
            {
                list.push(e.vid);
            }
        }
        work.compare(population.saturating_mul(population.max(1).ilog2().into()))?;
        Ok(groups
            .into_values()
            .filter(|g| g.len() >= 2)
            .map(|mut g| {
                g.sort_unstable();
                let n = g.len() as u64;
                // A finding cites at most MAX_CITES handles; a larger group is
                // still one finding, its full size in the statistic.
                let cited = if g.len() > MAX_CITES {
                    format!(" (the first {MAX_CITES} by entry id cited)")
                } else {
                    String::new()
                };
                g.truncate(MAX_CITES);
                finding(
                    Self::ID,
                    Severity::Medium,
                    Statistic::count("entries", n, population),
                    g.into_iter().map(Cite::Entry).collect(),
                    format!("{n} entries share the same legs and effective date{cited}"),
                )
            })
            .collect())
    }
}

/// `duplicates.same_same_different`: same legs, different effective dates at
/// most `window_days` apart. Each entry is paired with the next occurrence of
/// its legs on a later date (the first recorded entry on that date), so a
/// group of k identical entries yields at most k pairs: a retail book with
/// identical daily sales reports a chain, not every pair of days.
pub struct SameSameDifferent {
    params: Params,
}
procedure_boilerplate!(SameSameDifferent, "duplicates.same_same_different");

impl Procedure for SameSameDifferent {
    fn id(&self) -> &'static str {
        Self::ID
    }
    fn version(&self) -> u16 {
        1
    }
    fn params(&self) -> &Params {
        &self.params
    }
    fn run(
        &self,
        snapshot: &Snapshot,
        _book: &BookContext,
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        let window = i32::try_from(self.params.get_u32("window_days")?)
            .map_err(|_| LanternError::Overflow("window_days"))?;
        // `(effective day, recorded sequence, entry)` per leg multiset.
        let mut groups: BTreeMap<LegMultiset, Vec<(i32, u64, VId)>> = BTreeMap::new();
        let mut population = 0u64;
        for e in snapshot.live_postings()? {
            work.entry()?;
            population += 1;
            groups.entry(leg_multiset(e, work)?).or_default().push((
                e.entry.proposal.effective_date.0,
                e.recorded_at.0,
                e.vid,
            ));
        }
        let mut out = Vec::new();
        for list in groups.values_mut() {
            list.sort_unstable();
            // `next` is the first index on a later date than `list[i]`; it
            // only moves forward, so the scan is linear after the sort.
            let mut next = 0usize;
            for i in 0..list.len() {
                next = next.max(i + 1);
                while next < list.len() && list[next].0 == list[i].0 {
                    work.compare(1)?;
                    next += 1;
                }
                let mut cand = next;
                while cand < list.len()
                    && snapshot.shares_supersession_lineage(list[i].2, list[cand].2)
                {
                    work.compare(1)?;
                    cand += 1;
                }
                let Some(&(day, _, later)) = list.get(cand) else {
                    continue;
                };
                work.compare(1)?;
                let apart = day - list[i].0;
                if apart > window {
                    continue;
                }
                // Earlier then later, in (date, recorded) order: the
                // chronology a reader checks, never the hashed vid order.
                let pair = [list[i].2, later];
                out.push(finding(
                    Self::ID,
                    Severity::Low,
                    Statistic::count("days_apart", apart as u64, population),
                    pair.into_iter().map(Cite::Entry).collect(),
                    format!(
                        "two entries share the same legs {apart} day(s) apart (window {window})"
                    ),
                ));
            }
        }
        Ok(out)
    }
}

/// The most later candidates `duplicates.near` compares one entry with in
/// its group. The registered complexity arm bounds the run with it; an entry
/// whose window held more is reported, never silently truncated.
pub const MAX_NEAR_CANDIDATES: u64 = 64;

/// Basis points in one whole.
const BP: u128 = 10_000;

/// A leg with its magnitude dropped: (account, side, unit, dimensions).
type Shape = Vec<(VId, u8, u32, Vec<(u32, VId)>)>;

/// One live posting as `duplicates.near` compares it.
struct NearEntry {
    day: i32,
    recorded: u64,
    vid: VId,
    /// The leg multiset with magnitudes, as the exact procedures key it.
    exact_legs: LegMultiset,
    /// The debit magnitude per unit, in `unit_totals` order.
    debits: Vec<(u32, u128)>,
    bigrams: Vec<(char, char)>,
}

/// The description lowercased, with every run of other characters collapsed
/// to one space and the ends trimmed, as a sorted multiset of character
/// bigrams.
fn bigrams(text: &str) -> Vec<(char, char)> {
    let mut norm: Vec<char> = Vec::new();
    for c in text.chars() {
        if c.is_alphanumeric() {
            norm.extend(c.to_lowercase());
        } else if norm.last().is_some_and(|&last| last != ' ') {
            norm.push(' ');
        }
    }
    if norm.last() == Some(&' ') {
        norm.pop();
    }
    let mut out: Vec<(char, char)> = norm.windows(2).map(|w| (w[0], w[1])).collect();
    out.sort_unstable();
    out
}

/// Character-bigram Dice similarity in whole percent, rounded down: twice the
/// bigrams the two multisets share over their total count. A description
/// with no bigram is no evidence of similarity, so 0.
fn similarity_pct(a: &[(char, char)], b: &[(char, char)]) -> u64 {
    if a.is_empty() || b.is_empty() {
        return 0;
    }
    let (mut i, mut j, mut shared) = (0, 0, 0_u64);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            Ordering::Less => i += 1,
            Ordering::Greater => j += 1,
            Ordering::Equal => {
                shared += 1;
                i += 1;
                j += 1;
            }
        }
    }
    // Descriptions are bounded by MAX_DESCRIPTION_BYTES, so neither the
    // product nor the sum comes near u64.
    shared * 200 / (a.len() + b.len()) as u64
}

/// Whether `a` and `b` differ by at most `tolerance_bp` basis points of the
/// larger: `|a - b| * 10_000 <= tolerance_bp * max(a, b)`, exactly. Both
/// sides are integers, so that is `|a - b| <= floor(tolerance_bp * max /
/// 10_000)`, computed in two parts so no product leaves u128.
fn within_tolerance(a: u128, b: u128, tolerance_bp: u128) -> Result<bool, LanternError> {
    let overflow = || LanternError::Overflow("duplicates.near tolerance");
    let max = a.max(b);
    let whole = (max / BP).checked_mul(tolerance_bp).ok_or_else(overflow)?;
    let part = (max % BP).checked_mul(tolerance_bp).ok_or_else(overflow)? / BP;
    let bound = whole.checked_add(part).ok_or_else(overflow)?;
    Ok(a.abs_diff(b) <= bound)
}

/// `duplicates.near`: pairs of live entries with the same leg shape whose
/// effective dates are at most `window_days` apart, whose debit totals are
/// within `tolerance_bp` of each other in every unit, and whose descriptions
/// are at least `min_similarity_pct` similar.
///
/// Entries with identical legs are left to the exact procedures. As in
/// `same_same_different`, each entry is paired with its nearest qualifying
/// later candidate only, so a run of k near entries yields at most k pairs.
/// Each entry is compared with at most [`MAX_NEAR_CANDIDATES`] later
/// candidates in its group.
pub struct Near {
    params: Params,
}
procedure_boilerplate!(Near, "duplicates.near");

impl Procedure for Near {
    fn id(&self) -> &'static str {
        Self::ID
    }
    fn version(&self) -> u16 {
        1
    }
    fn params(&self) -> &Params {
        &self.params
    }
    fn run(
        &self,
        snapshot: &Snapshot,
        book: &BookContext,
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        let window = i32::try_from(self.params.get_u32("window_days")?)
            .map_err(|_| LanternError::Overflow("window_days"))?;
        let tolerance = self.params.get_u32("tolerance_bp")?;
        if u128::from(tolerance) > BP {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "tolerance_bp".into(),
                message: format!("{tolerance} is not in 0..=10000"),
            });
        }
        let min_similarity = self.params.get_u32("min_similarity_pct")?;
        if !(1..=100).contains(&min_similarity) {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "min_similarity_pct".into(),
                message: format!("{min_similarity} is not in 1..=100"),
            });
        }
        let has_supersession = snapshot
            .entries
            .iter()
            .any(|e| !e.entry.proposal.supersession.is_empty());

        let mut groups: BTreeMap<Shape, Vec<NearEntry>> = BTreeMap::new();
        let mut population = 0u64;
        let mut unreadable: Vec<VId> = Vec::new();
        for e in snapshot.live_postings()? {
            work.entry()?;
            let Ok(text) = e
                .entry
                .proposal
                .description
                .open(&book.seal_key, MAX_DESCRIPTION_BYTES)
            else {
                unreadable.push(e.vid);
                continue;
            };
            population += 1;
            let exact_legs = leg_multiset(e, work)?;
            let mut shape: Shape = e
                .entry
                .proposal
                .legs
                .iter()
                .map(|l| {
                    (
                        l.account_ref,
                        match l.side {
                            Side::Debit => 0,
                            Side::Credit => 1,
                        },
                        l.amount.unit.0,
                        l.dimension_set.clone(),
                    )
                })
                .collect();
            shape.sort_unstable();
            let debits = e
                .entry
                .proposal
                .unit_totals
                .iter()
                .map(|t| (t.unit_id, t.debits.unsigned_abs()))
                .collect();
            groups.entry(shape).or_default().push(NearEntry {
                day: e.entry.proposal.effective_date.0,
                recorded: e.recorded_at.0,
                vid: e.vid,
                exact_legs,
                debits,
                bigrams: bigrams(&text),
            });
        }
        work.compare(population.saturating_mul(population.max(1).ilog2().into()))?;

        let mut out = Vec::new();
        let mut capped: Vec<VId> = Vec::new();
        for list in groups.values_mut() {
            list.sort_unstable_by_key(|n| (n.day, n.recorded, n.vid));
            for (i, earlier) in list.iter().enumerate() {
                for (examined, later) in list[i + 1..].iter().enumerate() {
                    if later.day - earlier.day > window {
                        break;
                    }
                    if examined as u64 == MAX_NEAR_CANDIDATES {
                        capped.push(earlier.vid);
                        break;
                    }
                    work.compare(1)?;
                    // Identical legs are an exact duplicate, not a near one.
                    if later.exact_legs == earlier.exact_legs
                        || earlier.debits.len() != later.debits.len()
                    {
                        continue;
                    }
                    let mut amounts_near = true;
                    for (&(unit_a, a), &(unit_b, b)) in earlier.debits.iter().zip(&later.debits) {
                        if unit_a != unit_b || !within_tolerance(a, b, u128::from(tolerance))? {
                            amounts_near = false;
                            break;
                        }
                    }
                    if !amounts_near {
                        continue;
                    }
                    let similarity = similarity_pct(&earlier.bigrams, &later.bigrams);
                    if similarity < u64::from(min_similarity)
                        || (has_supersession
                            && snapshot.shares_supersession_lineage(earlier.vid, later.vid))
                    {
                        continue;
                    }
                    let apart = later.day - earlier.day;
                    out.push(finding(
                        Self::ID,
                        Severity::Low,
                        Statistic::count("similarity_pct", similarity, population),
                        vec![Cite::Entry(earlier.vid), Cite::Entry(later.vid)],
                        format!(
                            "two entries on the same accounts and dimensions {apart} day(s) apart: amounts within {tolerance} bp in every unit, descriptions {similarity}% similar (window {window}, threshold {min_similarity}%)"
                        ),
                    ));
                    break;
                }
            }
        }
        // A cap or an unreadable description narrows what was compared; both
        // are reported as such, never silently skipped.
        if !capped.is_empty() {
            let n = capped.len() as u64;
            capped.sort_unstable();
            capped.truncate(MAX_CITES);
            out.push(finding(
                Self::ID,
                Severity::Info,
                Statistic::count("capped_entries", n, population),
                capped.into_iter().map(Cite::Entry).collect(),
                format!(
                    "{n} entr(ies) had more than {MAX_NEAR_CANDIDATES} later candidates of the same shape inside the window; each was compared with the nearest {MAX_NEAR_CANDIDATES} only"
                ),
            ));
        }
        if !unreadable.is_empty() {
            let n = unreadable.len() as u64;
            unreadable.sort_unstable();
            unreadable.truncate(MAX_CITES);
            out.push(finding(
                Self::ID,
                Severity::Info,
                Statistic::count("unreadable_descriptions", n, population + n),
                unreadable.into_iter().map(Cite::Entry).collect(),
                format!(
                    "{n} description(s) could not be opened under the book's seal key; those entries were not compared"
                ),
            ));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn near_tolerance_is_exact_at_its_boundary_and_never_overflows() {
        // 100 bp of 10_100 is 101: a difference of 100 is in, of 102 out.
        assert!(within_tolerance(10_000, 10_100, 100).unwrap());
        assert!(within_tolerance(10_100, 10_000, 100).unwrap());
        assert!(!within_tolerance(10_000, 10_102, 100).unwrap());
        // |a - b| * 10_000 == tolerance * max exactly: 1 * 10_000 == 1 * 10_000.
        assert!(within_tolerance(9_999, 10_000, 1).unwrap());
        assert!(!within_tolerance(9_998, 10_000, 1).unwrap());
        // Zero tolerance admits only equal amounts.
        assert!(within_tolerance(7, 7, 0).unwrap());
        assert!(!within_tolerance(7, 8, 0).unwrap());
        // The whole i128 magnitude range, where tolerance * max leaves u128.
        let max = i128::MAX.unsigned_abs();
        let one_pct = max / 100;
        let near = max.checked_sub(one_pct).unwrap();
        let far = max.checked_sub(one_pct.checked_add(2).unwrap()).unwrap();
        assert!(within_tolerance(max, near, 100).unwrap());
        assert!(!within_tolerance(max, far, 100).unwrap());
        assert!(within_tolerance(0, max, 10_000).unwrap());
        assert!(within_tolerance(0, 0, 100).unwrap());
    }

    #[test]
    fn similarity_is_bigram_dice_over_normalized_text() {
        let pct = |a: &str, b: &str| similarity_pct(&bigrams(a), &bigrams(b));
        // Case, punctuation and spacing are normalized away; a transposed
        // invoice number shares 22 of 25 bigrams: 2 * 22 * 100 / 50 = 88.
        assert_eq!(
            pct(
                "Invoice 1043 Acme Supplies",
                "INVOICE #1034 - ACME SUPPLIES"
            ),
            88
        );
        assert_eq!(
            pct("Invoice 1043 Acme Supplies", "Invoice 1043 Acme Supplies"),
            100
        );
        assert_eq!(
            pct("Invoice 1043 Acme Supplies", "Quarterly rent payment"),
            4
        );
        assert_eq!(pct("  --Ünïcode  ", "ünïcode"), 100);
        // A description with no bigram is no evidence either way.
        assert_eq!(pct("a", "a"), 0);
        assert_eq!(pct("", "Invoice"), 0);
        assert_eq!(bigrams(" a--b "), vec![(' ', 'b'), ('a', ' ')]);
    }
}
