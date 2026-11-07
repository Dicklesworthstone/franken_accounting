//! Duplicate detection (plan §11.3): entries with the same leg multiset
//! (account, side, unit, magnitude) on the same date, or on different dates
//! inside a window, and `duplicates.near`: the same leg shape (account,
//! side, unit, dimensions, so the same parties) with amounts inside a
//! tolerance and similar descriptions.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

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

/// A run builds the sparse correction graph once, rather than rebuilding it
/// from the entire journal for every candidate pair. Most corrections form
/// single-parent trees: DFS intervals answer their directed ancestry in
/// constant time after the id lookup. Multi-parent components retain the
/// exact directed reachability test, charged to the procedure's work budget.
/// Sharing a common ancestor alone does not make two entries a lineage pair.
struct Lineages {
    ids: BTreeMap<VId, usize>,
    nodes: Vec<LineageNode>,
}

#[derive(Default)]
struct LineageNode {
    parents: Vec<usize>,
    children: Vec<usize>,
    component: Option<usize>,
    interval: Option<(usize, usize)>,
}

#[derive(Default)]
struct SelectedLineages {
    trees: BTreeMap<usize, BTreeMap<usize, usize>>,
    graphs: BTreeMap<usize, Vec<VId>>,
}

impl Lineages {
    fn new(snapshot: &Snapshot, work: &mut Meter<'_>) -> Result<Self, LanternError> {
        let mut index = Self {
            ids: BTreeMap::new(),
            nodes: Vec::new(),
        };
        for entry in &snapshot.entries {
            work.compare(1)?;
            if entry.entry.proposal.supersession.is_empty() {
                continue;
            }
            let source = index.intern(entry.vid);
            for edge in &entry.entry.proposal.supersession {
                work.compare(1)?;
                let target = index.intern(edge.target.vid);
                index.nodes[source].parents.push(target);
                index.nodes[target].children.push(source);
            }
        }
        index.index_components(work)?;
        Ok(index)
    }

    fn index_components(&mut self, work: &mut Meter<'_>) -> Result<(), LanternError> {
        for start in 0..self.nodes.len() {
            if self.nodes[start].component.is_some() {
                continue;
            }
            let mut stack = vec![start];
            self.nodes[start].component = Some(start);
            let mut members = Vec::new();
            let mut edges = 0_usize;
            let mut single_parent = true;
            while let Some(node) = stack.pop() {
                work.compare(1)?;
                members.push(node);
                edges += self.nodes[node].parents.len();
                single_parent &= self.nodes[node].parents.len() <= 1;
                let neighbors: Vec<_> = self.nodes[node]
                    .parents
                    .iter()
                    .chain(&self.nodes[node].children)
                    .copied()
                    .collect();
                work.compare(neighbors.len() as u64)?;
                for neighbor in neighbors {
                    if self.nodes[neighbor].component.is_none() {
                        self.nodes[neighbor].component = Some(start);
                        stack.push(neighbor);
                    }
                }
            }
            // A connected single-parent component with |V|-1 edges is a
            // tree. A malformed cycle uses the cycle-safe exact search.
            if single_parent && edges == members.len().saturating_sub(1) {
                let root = members
                    .iter()
                    .copied()
                    .find(|&node| self.nodes[node].parents.is_empty())
                    .expect("a single-parent tree has a root");
                let mut clock = 0_usize;
                let mut stack = vec![(root, false)];
                while let Some((node, exiting)) = stack.pop() {
                    if exiting {
                        self.nodes[node].interval.as_mut().expect("entered node").1 = clock;
                    } else {
                        work.compare(1)?;
                        self.nodes[node].interval = Some((clock, clock));
                        clock += 1;
                        stack.push((node, true));
                        stack.extend(
                            self.nodes[node]
                                .children
                                .iter()
                                .map(|&child| (child, false)),
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn intern(&mut self, vid: VId) -> usize {
        *self.ids.entry(vid).or_insert_with(|| {
            let node = self.nodes.len();
            self.nodes.push(LineageNode::default());
            node
        })
    }

    fn node(&self, vid: VId) -> Option<&LineageNode> {
        self.ids.get(&vid).map(|&node| &self.nodes[node])
    }

    fn shares(&self, a: VId, b: VId, work: &mut Meter<'_>) -> Result<bool, LanternError> {
        if a == b {
            return Ok(true);
        }
        let (Some(&a), Some(&b)) = (self.ids.get(&a), self.ids.get(&b)) else {
            return Ok(false);
        };
        let (left, right) = (&self.nodes[a], &self.nodes[b]);
        if left.component != right.component {
            return Ok(false);
        }
        if let (Some((a_start, a_end)), Some((b_start, b_end))) = (left.interval, right.interval) {
            return Ok(
                (a_start <= b_start && b_start < a_end) || (b_start <= a_start && a_start < b_end)
            );
        }
        Ok(self.reaches(a, b, work)? || self.reaches(b, a, work)?)
    }

    fn reaches(
        &self,
        start: usize,
        goal: usize,
        work: &mut Meter<'_>,
    ) -> Result<bool, LanternError> {
        let mut stack = vec![start];
        let mut seen = BTreeSet::new();
        while let Some(node) = stack.pop() {
            work.compare(1)?;
            if node == goal {
                return Ok(true);
            }
            if seen.insert(node) {
                for &parent in &self.nodes[node].parents {
                    work.compare(1)?;
                    stack.push(parent);
                }
            }
        }
        Ok(false)
    }

    /// Keep the existing greedy group semantics without comparing every
    /// unrelated entry with every earlier member. In a tree, accepted
    /// intervals are disjoint, so two neighbors decide the next insertion.
    fn select(
        &self,
        vid: VId,
        selected: &mut SelectedLineages,
        work: &mut Meter<'_>,
    ) -> Result<bool, LanternError> {
        let Some(node) = self.node(vid) else {
            return Ok(true);
        };
        let component = node.component.expect("indexed component");
        if let Some((start, end)) = node.interval {
            work.compare(2)?;
            let intervals = selected.trees.entry(component).or_default();
            if intervals
                .range(..=start)
                .next_back()
                .is_some_and(|(_, &end)| end > start)
                || intervals
                    .range(start..)
                    .next()
                    .is_some_and(|(&next, _)| next < end)
            {
                return Ok(false);
            }
            intervals.insert(start, end);
        } else {
            let members = selected.graphs.entry(component).or_default();
            for &other in members.iter() {
                work.compare(1)?;
                if self.shares(other, vid, work)? {
                    return Ok(false);
                }
            }
            members.push(vid);
        }
        Ok(true)
    }
}

#[derive(Clone, Copy, Default)]
struct LineageRange {
    len: usize,
    component: Option<usize>,
    forest: bool,
    min_end: usize,
    max_start: usize,
}

impl LineageRange {
    fn combine(left: Self, right: Self) -> Self {
        if left.len == 0 {
            return right;
        }
        if right.len == 0 {
            return left;
        }
        Self {
            len: left.len + right.len,
            component: left
                .component
                .filter(|component| Some(*component) == right.component),
            forest: left.forest && right.forest,
            min_end: left.min_end.min(right.min_end),
            max_start: left.max_start.max(right.max_start),
        }
    }

    fn may_be_unrelated(self, node: &LineageNode) -> bool {
        if self.len == 0 {
            return false;
        }
        if self.component != node.component {
            return true;
        }
        match node.interval {
            Some((start, end)) if self.forest => self.min_end <= start || self.max_start >= end,
            _ => true,
        }
    }
}

/// Chronological candidates can all belong to one correction chain. Range
/// extrema skip an entire comparable tree range, rather than repeatedly
/// walking every remaining candidate for every entry in the chain.
struct LineageSearch {
    ranges: Vec<LineageRange>,
    leaves: usize,
}

impl LineageSearch {
    fn new(
        list: &[(i32, u64, VId)],
        lineage: &Lineages,
        work: &mut Meter<'_>,
    ) -> Result<Self, LanternError> {
        let leaves = list.len().next_power_of_two();
        let mut ranges = vec![LineageRange::default(); leaves * 2];
        for (i, &(_, _, vid)) in list.iter().enumerate() {
            work.compare(1)?;
            let node = lineage.node(vid);
            let interval = node.and_then(|node| node.interval);
            ranges[leaves + i] = LineageRange {
                len: 1,
                component: node.and_then(|node| node.component),
                forest: interval.is_some(),
                min_end: interval.map_or(0, |(_, end)| end),
                max_start: interval.map_or(0, |(start, _)| start),
            };
        }
        for i in (1..leaves).rev() {
            work.compare(1)?;
            ranges[i] = LineageRange::combine(ranges[i * 2], ranges[i * 2 + 1]);
        }
        Ok(Self { ranges, leaves })
    }

    fn first_unrelated(
        &self,
        list: &[(i32, u64, VId)],
        from: usize,
        vid: VId,
        lineage: &Lineages,
        work: &mut Meter<'_>,
    ) -> Result<Option<usize>, LanternError> {
        let Some(node) = lineage.node(vid) else {
            return Ok((from < list.len()).then_some(from));
        };
        let mut stack = vec![(1_usize, 0_usize, self.leaves)];
        while let Some((index, start, end)) = stack.pop() {
            work.compare(1)?;
            if end <= from || !self.ranges[index].may_be_unrelated(node) {
                continue;
            }
            if index >= self.leaves {
                if !lineage.shares(vid, list[start].2, work)? {
                    return Ok(Some(start));
                }
            } else {
                let middle = start + (end - start) / 2;
                stack.push((index * 2 + 1, middle, end));
                stack.push((index * 2, start, middle));
            }
        }
        Ok(None)
    }
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
        let mut groups: BTreeMap<(LegMultiset, i32), (Vec<VId>, SelectedLineages)> =
            BTreeMap::new();
        let mut population = 0u64;
        let lineage = Lineages::new(snapshot, work)?;
        for e in snapshot.live_postings()? {
            work.entry()?;
            population += 1;
            let (list, selected) = groups
                .entry((leg_multiset(e, work)?, e.entry.proposal.effective_date.0))
                .or_default();
            if lineage.select(e.vid, selected, work)? {
                list.push(e.vid);
            }
        }
        work.compare(population.saturating_mul(population.max(1).ilog2().into()))?;
        Ok(groups
            .into_values()
            .map(|(entries, _)| entries)
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
        let window = i64::from(self.params.get_u32("window_days")?);
        // `(effective day, recorded sequence, entry)` per leg multiset.
        let mut groups: BTreeMap<LegMultiset, Vec<(i32, u64, VId)>> = BTreeMap::new();
        let mut population = 0u64;
        let lineage = Lineages::new(snapshot, work)?;
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
            let search = if lineage.ids.is_empty() {
                None
            } else {
                Some(LineageSearch::new(list, &lineage, work)?)
            };
            // `next` is the first index on a later date than `list[i]`; it
            // only moves forward, so the scan is linear after the sort.
            let mut next = 0usize;
            for i in 0..list.len() {
                next = next.max(i + 1);
                while next < list.len() && list[next].0 == list[i].0 {
                    work.compare(1)?;
                    next += 1;
                }
                let candidate = match &search {
                    Some(search) => {
                        search.first_unrelated(list, next, list[i].2, &lineage, work)?
                    }
                    None => (next < list.len()).then_some(next),
                };
                let Some((day, _, later)) = candidate.map(|index| list[index]) else {
                    continue;
                };
                work.compare(1)?;
                let apart = i64::from(day) - i64::from(list[i].0);
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
        let window = i64::from(self.params.get_u32("window_days")?);
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
        let lineage = Lineages::new(snapshot, work)?;

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
                    if i64::from(later.day) - i64::from(earlier.day) > window {
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
                        || lineage.shares(earlier.vid, later.vid, work)?
                    {
                        continue;
                    }
                    let apart = i64::from(later.day) - i64::from(earlier.day);
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

    fn lineage_index(edges: &[(u128, u128)], work: &mut Meter<'_>) -> Lineages {
        let mut index = Lineages {
            ids: BTreeMap::new(),
            nodes: Vec::new(),
        };
        for &(source, target) in edges {
            let source = index.intern(VId(source));
            let target = index.intern(VId(target));
            index.nodes[source].parents.push(target);
            index.nodes[target].children.push(source);
        }
        index.index_components(work).unwrap();
        index
    }

    /// Deliberately independent, naive edge-list walks: no indexed graph,
    /// components or intervals are reused by the differential oracle.
    fn naive_lineage(edges: &[(u128, u128)], a: u128, b: u128) -> bool {
        let reaches = |start, goal| {
            let mut todo = vec![start];
            let mut seen = BTreeSet::new();
            while let Some(current) = todo.pop() {
                if current == goal {
                    return true;
                }
                if seen.insert(current) {
                    todo.extend(
                        edges
                            .iter()
                            .filter_map(|&(source, target)| (source == current).then_some(target)),
                    );
                }
            }
            false
        };
        reaches(a, b) || reaches(b, a)
    }

    #[test]
    fn lineage_index_matches_directed_walks_group_selection_and_next_candidates() {
        let mut cases = vec![
            vec![],
            vec![(2, 1), (3, 1), (4, 2), (5, 2), (6, 3)],
            vec![(2, 1), (3, 1), (4, 2), (4, 3), (5, 4), (6, 2)],
            vec![(1, 2), (2, 3), (3, 1), (4, 2), (5, 6)],
            vec![(1, 1), (3, 2), (3, 2)],
        ];
        // A deterministic family of forests and multi-parent DAGs, including
        // unrelated components, siblings and nodes absent from the graph.
        let mut seed = 13_u64;
        for case in 0..24 {
            let mut edges = Vec::new();
            for source in 2..=18_u128 {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                if !seed.is_multiple_of(3) {
                    edges.push((source, 1 + u128::from(seed) % (source - 1)));
                }
                if case % 2 == 1 && seed.is_multiple_of(5) {
                    edges.push((source, 1 + u128::from(seed / 5) % (source - 1)));
                }
            }
            cases.push(edges);
        }
        for edges in cases {
            let mut work = Meter::new(SameSameDifferent::ID, None, None);
            let index = lineage_index(&edges, &mut work);
            for a in 0..20 {
                for b in 0..20 {
                    assert_eq!(
                        index.shares(VId(a), VId(b), &mut work).unwrap(),
                        naive_lineage(&edges, a, b),
                        "lineage {a}, {b}: {edges:?}"
                    );
                }
            }
            for reverse in [false, true] {
                let mut order: Vec<_> = (0..20).collect();
                if reverse {
                    order.reverse();
                }
                let mut selected = SelectedLineages::default();
                let mut expected = Vec::new();
                for &vid in &order {
                    let accept = expected
                        .iter()
                        .all(|&other| !naive_lineage(&edges, vid, other));
                    assert_eq!(
                        index.select(VId(vid), &mut selected, &mut work).unwrap(),
                        accept
                    );
                    if accept {
                        expected.push(vid);
                    }
                }
                let list: Vec<_> = order
                    .iter()
                    .enumerate()
                    .map(|(i, &vid)| {
                        (
                            i32::try_from(i).expect("bounded fixture ordinal"),
                            u64::try_from(i).expect("bounded fixture ordinal"),
                            VId(vid),
                        )
                    })
                    .collect();
                let search = LineageSearch::new(&list, &index, &mut work).unwrap();
                for a in 0..20 {
                    let first_later = order.iter().position(|&vid| vid == a).unwrap() + 1;
                    for from in first_later..=list.len() {
                        let expected =
                            (from..list.len()).find(|&i| !naive_lineage(&edges, a, list[i].2.0));
                        assert_eq!(
                            search
                                .first_unrelated(&list, from, VId(a), &index, &mut work)
                                .unwrap(),
                            expected,
                            "next candidate for {a} from {from}: {edges:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn hundred_thousand_corrections_skip_related_ranges_with_linear_work() {
        const N: u128 = 100_000;
        let edges: Vec<_> = (2..=N).map(|vid| (vid, vid - 1)).collect();
        let mut work = Meter::new(SameSameDifferent::ID, Some(1_000_000), None);
        let index = lineage_index(&edges, &mut work);
        let list: Vec<_> = (1..=N)
            .map(|vid| {
                (
                    i32::try_from(vid).expect("bounded fixture vertex"),
                    u64::try_from(vid).expect("bounded fixture vertex"),
                    VId(vid),
                )
            })
            .collect();
        let search = LineageSearch::new(&list, &index, &mut work).unwrap();
        let mut selected = SelectedLineages::default();
        for (i, &(_, _, vid)) in list.iter().enumerate() {
            assert_eq!(
                search
                    .first_unrelated(&list, i + 1, vid, &index, &mut work)
                    .unwrap(),
                None
            );
            assert_eq!(index.select(vid, &mut selected, &mut work).unwrap(), i == 0);
        }
        assert!(
            work.work().comparisons < 10 * u64::try_from(N).expect("bounded test population"),
            "{:?}",
            work.work()
        );
    }

    #[test]
    fn lineage_index_and_range_search_honor_budget_and_cancellation() {
        struct Cancelled;
        impl crate::Cancellation for Cancelled {
            fn cancelled(&self) -> bool {
                true
            }
        }
        let mut work = Meter::new(SameSameDifferent::ID, None, None);
        let mut index = lineage_index(&[(2, 1)], &mut work);
        for node in &mut index.nodes {
            node.component = None;
        }
        let mut cancelled = Meter::new(SameSameDifferent::ID, None, Some(&Cancelled));
        assert!(matches!(
            index.index_components(&mut cancelled),
            Err(LanternError::Cancelled { .. })
        ));
        let mut budget = Meter::new(SameSameDifferent::ID, Some(0), None);
        assert!(matches!(
            LineageSearch::new(&[(0, 0, VId(1))], &index, &mut budget),
            Err(LanternError::BudgetExhausted { .. })
        ));
    }

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
