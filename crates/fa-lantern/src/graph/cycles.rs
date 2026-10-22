//! Bounded temporal cycle search. This kernel intentionally uses only std:
//! amounts are compared, never converted to floats or summed across units.
//! A cycle is a motif, not a tracing-law allocation or proof of wrongdoing.

use std::collections::{BTreeMap, BTreeSet};

/// A positive, entry-level transfer. The adapter supplies only asset accounts
/// and preserves the journal's legal-entity partition in `entity`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Edge {
    pub day: i32,
    pub recorded: u64,
    pub entry: u128,
    pub from: u128,
    pub to: u128,
    pub unit: u32,
    pub amount: i128,
    pub entity: Option<u128>,
}

impl Edge {
    fn time(self) -> (i32, u64, u128) {
        (self.day, self.recorded, self.entry)
    }

    fn key(self, from: u128) -> (Option<u128>, u32, i128, u128) {
        (self.entity, self.unit, self.amount, from)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error<E> {
    Parameters,
    NonPositiveAmount,
    SearchLimit,
    Interrupted(E),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Cycles {
    /// Paths refer to positions in the caller's `edges`. Every edge is used
    /// in at most one path; rotations are not additional findings.
    pub paths: Vec<Vec<usize>>,
    pub steps: u64,
}

type Adjacency = BTreeMap<(Option<u128>, u32, i128, u128), Vec<usize>>;

struct Search<'a, E> {
    edges: &'a [Edge],
    adjacent: &'a Adjacency,
    used: &'a [bool],
    origin: Edge,
    path: Vec<usize>,
    accounts: BTreeSet<u128>,
    entries: BTreeSet<u128>,
    max_hops: usize,
    window_days: i64,
    steps: &'a mut u64,
    max_steps: u64,
    checkpoint: &'a mut dyn FnMut() -> Result<(), E>,
}

impl<E> Search<'_, E> {
    fn extend(&mut self) -> Result<Option<Vec<usize>>, Error<E>> {
        let last = self.edges[*self.path.last().ok_or(Error::Parameters)?];
        let key = self.origin.key(last.to);
        let Some(adjacent) = self.adjacent.get(&key) else {
            return Ok(None);
        };
        // Never walk backwards in effective/recorded time. Identical commit
        // coordinates have the registered entry-identity tie break.
        let start = adjacent.partition_point(|i| self.edges[*i].time() <= last.time());
        let end = adjacent.len();
        for cursor in start..end {
            charge(self.steps, self.max_steps, self.checkpoint)?;
            let index = self.adjacent[&key][cursor];
            let edge = self.edges[index];
            // Widen BEFORE subtracting: valid DateDay values can span i32.
            if i64::from(edge.day) - i64::from(self.origin.day) > self.window_days {
                break;
            }
            if self.used[index] || self.entries.contains(&edge.entry) {
                continue;
            }
            if edge.to == self.origin.from {
                let mut found = self.path.clone();
                found.push(index);
                return Ok(Some(found));
            }
            if self.path.len() + 1 >= self.max_hops || self.accounts.contains(&edge.to) {
                continue;
            }
            self.path.push(index);
            self.accounts.insert(edge.to);
            self.entries.insert(edge.entry);
            if let Some(found) = self.extend()? {
                return Ok(Some(found));
            }
            self.path.pop();
            self.accounts.remove(&edge.to);
            self.entries.remove(&edge.entry);
        }
        Ok(None)
    }
}

fn charge<E>(
    steps: &mut u64,
    limit: u64,
    checkpoint: &mut dyn FnMut() -> Result<(), E>,
) -> Result<(), Error<E>> {
    if *steps >= limit {
        return Err(Error::SearchLimit);
    }
    checkpoint().map_err(Error::Interrupted)?;
    *steps += 1;
    Ok(())
}

/// Canonical, greedy, edge-disjoint simple cycles of 2..=max_hops transfers.
/// Starts and outgoing alternatives are in (effective day, recorded sequence,
/// entry identity, edge identity) order. The first depth-first completion is
/// selected, NOT an asserted maximum-value packing or exhaustive cycle list.
/// Every transfer must have the same amount, unit and legal entity. An entry
/// cannot serve as two hops. Reaching the work bound refuses the WHOLE run;
/// partial results must not masquerade as a complete successful report.
pub(crate) fn find<E>(
    edges: &[Edge],
    max_hops: usize,
    window_days: i32,
    max_steps: u64,
    checkpoint: &mut dyn FnMut() -> Result<(), E>,
) -> Result<Cycles, Error<E>> {
    if !(2..=8).contains(&max_hops) || window_days < 0 || max_steps == 0 {
        return Err(Error::Parameters);
    }
    if edges.iter().any(|edge| edge.amount <= 0) {
        return Err(Error::NonPositiveAmount);
    }
    let mut order: Vec<usize> = (0..edges.len()).collect();
    order.sort_unstable_by_key(|i| (edges[*i], *i));
    let mut adjacent: Adjacency = BTreeMap::new();
    for index in &order {
        let edge = edges[*index];
        if edge.from != edge.to {
            adjacent
                .entry(edge.key(edge.from))
                .or_default()
                .push(*index);
        }
    }
    let mut used = vec![false; edges.len()];
    let mut paths = Vec::new();
    let mut steps = 0;
    for start in order {
        charge(&mut steps, max_steps, checkpoint)?;
        let origin = edges[start];
        if used[start] || origin.from == origin.to {
            continue;
        }
        let path = Search {
            edges,
            adjacent: &adjacent,
            used: &used,
            origin,
            path: vec![start],
            accounts: BTreeSet::from([origin.from, origin.to]),
            entries: BTreeSet::from([origin.entry]),
            max_hops,
            window_days: i64::from(window_days),
            steps: &mut steps,
            max_steps,
            checkpoint,
        }
        .extend()?;
        if let Some(path) = path {
            for index in &path {
                used[*index] = true;
            }
            paths.push(path);
        }
    }
    Ok(Cycles { paths, steps })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The independent motif/oracle cases do not constrain runtime work.
    // Production supplies the caller's meter; the interruption cases below
    // exercise that same entry point with an actual bounded/cancellable meter.
    fn find(
        edges: &[Edge],
        max_hops: usize,
        window_days: i32,
        max_steps: u64,
    ) -> Result<Cycles, Error<core::convert::Infallible>> {
        super::find(edges, max_hops, window_days, max_steps, &mut || Ok(()))
    }

    fn edge(entry: u128, from: u128, to: u128, day: i32) -> Edge {
        Edge {
            day,
            recorded: entry as u64,
            entry,
            from,
            to,
            unit: 1,
            amount: 100,
            entity: Some(1),
        }
    }

    fn identities(edges: &[Edge], paths: &[Vec<usize>]) -> Vec<Vec<Edge>> {
        paths
            .iter()
            .map(|path| path.iter().map(|i| edges[*i]).collect())
            .collect()
    }

    #[test]
    fn three_and_four_account_cycles_are_detected_not_rotated_or_reused() {
        let edges = [
            edge(1, 10, 20, 1),
            edge(2, 20, 30, 2),
            edge(3, 30, 10, 3),
            edge(4, 10, 40, 4),
            edge(5, 40, 50, 5),
            edge(6, 50, 60, 6),
            edge(7, 60, 10, 7),
        ];
        assert!(find(&edges, 2, 10, 1000).unwrap().paths.is_empty());
        assert_eq!(
            find(&edges, 3, 10, 1000).unwrap().paths,
            vec![vec![0, 1, 2]]
        );
        let result = find(&edges, 4, 10, 1000).unwrap();
        assert_eq!(result.paths, vec![vec![0, 1, 2], vec![3, 4, 5, 6]]);
        let mut reversed = edges;
        reversed.reverse();
        assert_eq!(
            identities(&edges, &result.paths),
            identities(&reversed, &find(&reversed, 4, 10, 1000).unwrap().paths)
        );
    }

    #[test]
    fn time_amount_currency_entity_and_distinct_entry_are_required() {
        let good = [edge(1, 10, 20, 1), edge(2, 20, 30, 2), edge(3, 30, 10, 3)];
        for change in 0..5 {
            let mut bad = good;
            match change {
                0 => bad[1].day = 4,
                1 => bad[1].amount += 1,
                2 => bad[1].unit = 2,
                3 => bad[1].entity = Some(2),
                _ => bad[1].entry = bad[0].entry,
            }
            assert!(
                find(&bad, 8, 10, 1000).unwrap().paths.is_empty(),
                "case {change}"
            );
        }
        assert!(find(&good, 3, 1, 1000).unwrap().paths.is_empty());
        assert_eq!(find(&good, 3, 2, 1000).unwrap().paths.len(), 1);
    }

    #[test]
    fn same_day_uses_recorded_sequence_before_hashed_identity() {
        let mut edges = [
            edge(300, 10, 20, 1),
            edge(200, 20, 30, 1),
            edge(100, 30, 10, 1),
        ];
        for (i, edge) in edges.iter_mut().enumerate() {
            edge.recorded = i as u64;
        }
        assert_eq!(find(&edges, 3, 0, 1000).unwrap().paths, vec![vec![0, 1, 2]]);
    }

    #[test]
    fn repeated_intermediate_accounts_are_not_simple_cycles() {
        let edges = [
            edge(1, 10, 20, 1),
            edge(2, 20, 30, 2),
            edge(3, 30, 20, 3),
            edge(4, 20, 40, 4),
            edge(5, 40, 10, 5),
        ];
        let paths = find(&edges, 8, 10, 1000).unwrap().paths;
        // The root's first continuation is a dead end for a simple cycle;
        // backtracking finds A->B->D->A. B->C->B is a separate unused motif.
        assert_eq!(paths, vec![vec![0, 3, 4], vec![1, 2]]);
    }

    #[test]
    fn date_extremes_and_large_amounts_never_overflow_or_mix() {
        let mut edges = [edge(1, 10, 20, i32::MIN), edge(2, 20, 10, i32::MAX)];
        edges.iter_mut().for_each(|edge| edge.amount = i128::MAX);
        assert!(find(&edges, 2, i32::MAX, 1000).unwrap().paths.is_empty());
        edges[1].day = i32::MIN + 1;
        assert_eq!(find(&edges, 2, 1, 1000).unwrap().paths.len(), 1);
    }

    #[test]
    fn bounds_refuse_the_entire_run_even_after_a_cycle_was_found() {
        let edges = [edge(1, 10, 20, 1), edge(2, 20, 10, 2), edge(3, 30, 40, 3)];
        assert_eq!(find(&edges, 2, 10, 2), Err(Error::SearchLimit));
        for hops in [0, 1, 9, usize::MAX] {
            assert_eq!(find(&edges, hops, 10, 100), Err(Error::Parameters));
        }
        assert_eq!(find(&edges, 2, -1, 100), Err(Error::Parameters));
        assert_eq!(find(&edges, 2, 10, 0), Err(Error::Parameters));
        let mut bad = edges;
        bad[0].amount = 0;
        assert_eq!(find(&bad, 2, 10, 100), Err(Error::NonPositiveAmount));
    }

    #[test]
    fn runtime_budget_interrupts_recursion_and_discards_already_found_cycles() {
        let edges = [
            edge(1, 10, 20, 1),
            edge(2, 20, 10, 2),
            edge(3, 30, 40, 3),
            edge(4, 40, 50, 4),
            edge(5, 50, 30, 5),
        ];
        let complete = find(&edges, 3, 10, 100).unwrap();
        assert_eq!(complete.paths, vec![vec![0, 1], vec![2, 3, 4]]);

        // Four steps have already found the first cycle and entered the
        // second. The fifth charge must stop the recursive extension, not
        // return that first motif as an apparently complete result.
        let mut meter = crate::Meter::new("graph.round_trips", Some(4), None);
        let result = super::find(&edges, 3, 10, 100, &mut || meter.compare(1));
        assert!(matches!(
            result,
            Err(Error::Interrupted(crate::LanternError::BudgetExhausted {
                used: 5,
                budget: 4,
                ..
            }))
        ));
        assert_eq!(meter.work().comparisons, 5);
        assert!(complete.steps > meter.work().comparisons);

        // No lost or duplicated work charge on a successful search.
        let mut meter = crate::Meter::new("graph.round_trips", Some(complete.steps), None);
        let metered = super::find(&edges, 3, 10, 100, &mut || meter.compare(1)).unwrap();
        assert_eq!(metered, complete);
        assert_eq!(meter.work().comparisons, complete.steps);
    }

    #[test]
    fn runtime_cancellation_is_observed_within_recursive_search_interval() {
        use std::cell::Cell;

        struct Flag<'a>(&'a Cell<bool>);
        impl crate::Cancellation for Flag<'_> {
            fn cancelled(&self) -> bool {
                self.0.get()
            }
        }

        // One root has many chronological continuations, with no completing
        // cycle. Cancellation therefore has to be consulted within extend(),
        // before this root's entire search returns to the outer loop.
        let mut edges = vec![edge(1, 10, 20, 1)];
        edges.extend((2..2_100).map(|id| edge(id, 20, 30, 2)));
        let complete = find(&edges, 3, 10, 10_000).unwrap();
        assert!(complete.paths.is_empty());
        let cancel = Cell::new(false);
        let flag = Flag(&cancel);
        let mut meter = crate::Meter::new("graph.round_trips", None, Some(&flag));
        let mut visited = 0u64;
        let result = super::find(&edges, 3, 10, 10_000, &mut || {
            visited += 1;
            if visited == 5 {
                cancel.set(true);
            }
            meter.compare(1)
        });
        let Err(Error::Interrupted(crate::LanternError::Cancelled { used, .. })) = result else {
            panic!("the recursive search did not propagate cancellation: {result:?}");
        };
        assert!(used >= 5 && used <= 5 + crate::CANCELLATION_INTERVAL);
        assert_eq!(visited, used);
        assert_eq!(meter.work().comparisons, used);
        assert!(used < 2_099, "the first root was still being searched");
        assert!(used < complete.steps);
    }

    /// Independent tiny-graph oracle: enumerate chronological subsets, check
    /// complete paths literally, sort them, then greedily consume disjoint
    /// paths. It does not use adjacency, DFS, or the production search state.
    fn oracle(edges: &[Edge], hops: usize, window: i32) -> Vec<Vec<Edge>> {
        let mut sorted = edges.to_vec();
        sorted.sort_unstable();
        let mut possible = Vec::new();
        for mask in 0..1usize << sorted.len() {
            let path: Vec<usize> = (0..sorted.len()).filter(|i| mask & (1 << i) != 0).collect();
            if path.len() < 2 || path.len() > hops {
                continue;
            }
            let first = sorted[path[0]];
            let last = sorted[*path.last().unwrap()];
            if first.from != last.to
                || i64::from(last.day) - i64::from(first.day) > i64::from(window)
            {
                continue;
            }
            let entries: BTreeSet<u128> = path.iter().map(|i| sorted[*i].entry).collect();
            let nodes: BTreeSet<u128> = path.iter().map(|i| sorted[*i].from).collect();
            if entries.len() != path.len() || nodes.len() != path.len() {
                continue;
            }
            if path.iter().any(|i| {
                let e = sorted[*i];
                e.from == e.to
                    || e.unit != first.unit
                    || e.amount != first.amount
                    || e.entity != first.entity
            }) {
                continue;
            }
            if !path.windows(2).all(|pair| {
                sorted[pair[0]].to == sorted[pair[1]].from
                    && sorted[pair[0]].time() < sorted[pair[1]].time()
            }) {
                continue;
            }
            possible.push(path);
        }
        possible.sort();
        let mut used = BTreeSet::new();
        let mut result = Vec::new();
        for path in possible {
            if path.iter().any(|i| used.contains(i)) {
                continue;
            }
            used.extend(path.iter().copied());
            result.push(path.into_iter().map(|i| sorted[i]).collect());
        }
        result
    }

    #[test]
    fn differential_against_exhaustive_subsets_and_input_permutations() {
        let mut seed = 0xFA11u64;
        for case in 0..128 {
            let mut edges = vec![edge(1, 0, 1, 0), edge(2, 1, 2, 1), edge(3, 2, 0, 2)];
            for i in 3..10 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let mut e = edge(
                    (i + 1) as u128,
                    u128::from(seed % 4),
                    u128::from((seed >> 8) % 4),
                    i,
                );
                e.amount = 100 + i128::from((seed >> 16) % 2);
                e.unit = 1 + ((seed >> 24) % 2) as u32;
                e.entity = Some(1 + u128::from((seed >> 32) % 2));
                edges.push(e);
            }
            for hops in 2..=5 {
                let expected = oracle(&edges, hops, 6);
                let result = find(&edges, hops, 6, 100_000).unwrap();
                assert_eq!(
                    identities(&edges, &result.paths),
                    expected,
                    "case={case} hops={hops}"
                );
                edges.reverse();
                let result = find(&edges, hops, 6, 100_000).unwrap();
                assert_eq!(
                    identities(&edges, &result.paths),
                    expected,
                    "permuted case={case} hops={hops}"
                );
            }
        }
    }
}
