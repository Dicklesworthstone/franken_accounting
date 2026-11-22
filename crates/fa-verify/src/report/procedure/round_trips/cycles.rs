//! Independent bounded temporal-cycle replay, using an explicit DFS stack.
//!
//! This module depends only on std so its production search can also be
//! compared directly with another implementation. It accepts original exact
//! transfers, not producer-selected paths. Exhausting the shared search budget
//! discards every path, including complete paths found before exhaustion.

use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Parameters,
    NonPositiveAmount,
    SearchLimit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Cycles {
    /// Input positions in temporal path order. Each transfer is consumed at
    /// most once, and each path has distinct entries and intermediate accounts.
    pub paths: Vec<Vec<usize>>,
    pub search_steps: u64,
}

type Scope = (Option<u128>, u32, i128, u128);
type Adjacency = BTreeMap<Scope, Vec<usize>>;

#[derive(Clone, Copy)]
struct Limits {
    max_hops: usize,
    window_days: i64,
    max_steps: u64,
}

fn time(edge: Edge) -> (i32, u64, u128) {
    (edge.day, edge.recorded, edge.entry)
}

fn scope(edge: Edge, from: u128) -> Scope {
    (edge.entity, edge.unit, edge.amount, from)
}

fn charge(steps: &mut u64, limit: u64) -> Result<(), Error> {
    if *steps >= limit {
        return Err(Error::SearchLimit);
    }
    *steps += 1;
    Ok(())
}

/// First admissible completion under chronological, depth-first alternatives.
/// A cursor at each depth resumes immediately after the branch just explored.
/// Path-local uniqueness is checked directly over the at-most-eight hops;
/// there is no recursive search or shared mutable visited set to unwind.
fn first_path(
    edges: &[Edge],
    adjacent: &Adjacency,
    used: &[bool],
    start: usize,
    limits: Limits,
    steps: &mut u64,
) -> Result<Option<Vec<usize>>, Error> {
    let origin = edges[start];
    let first_future = |last: Edge| {
        adjacent.get(&scope(origin, last.to)).map_or(0, |outgoing| {
            outgoing.partition_point(|&index| time(edges[index]) <= time(last))
        })
    };
    let mut path = vec![start];
    let mut cursors = vec![first_future(origin)];
    while let Some(&last_index) = path.last() {
        let depth = path.len() - 1;
        let last = edges[last_index];
        let outgoing = adjacent
            .get(&scope(origin, last.to))
            .map_or(&[][..], Vec::as_slice);
        if cursors[depth] == outgoing.len() {
            path.pop();
            cursors.pop();
            continue;
        }
        let next_index = outgoing[cursors[depth]];
        cursors[depth] += 1;
        charge(steps, limits.max_steps)?;
        let next = edges[next_index];
        if i64::from(next.day) - i64::from(origin.day) > limits.window_days {
            // Every later alternative at this depth is also beyond the
            // inclusive window. The examined boundary still costs one step.
            path.pop();
            cursors.pop();
            continue;
        }
        if used[next_index] || path.iter().any(|&index| edges[index].entry == next.entry) {
            continue;
        }
        if next.to == origin.from {
            path.push(next_index);
            return Ok(Some(path));
        }
        if path.len() + 1 >= limits.max_hops || path.iter().any(|&index| edges[index].to == next.to)
        {
            continue;
        }
        path.push(next_index);
        cursors.push(first_future(next));
    }
    Ok(None)
}

/// Greedy, edge-disjoint simple cycles with identical amount, unit and entity.
/// The complete ordering includes the input position only as the final tie
/// breaker for otherwise identical edges. This is a canonical motif screen,
/// not an exhaustive cycle list or a maximum-value packing.
pub(crate) fn find(
    edges: &[Edge],
    max_hops: usize,
    window_days: i64,
    max_steps: u64,
) -> Result<Cycles, Error> {
    if !(2..=8).contains(&max_hops) || window_days < 0 || max_steps == 0 {
        return Err(Error::Parameters);
    }
    if edges.iter().any(|edge| edge.amount <= 0) {
        return Err(Error::NonPositiveAmount);
    }
    let mut ordered: Vec<_> = (0..edges.len()).collect();
    ordered.sort_unstable_by_key(|&index| {
        let edge = edges[index];
        (
            edge.day,
            edge.recorded,
            edge.entry,
            edge.from,
            edge.to,
            edge.unit,
            edge.amount,
            edge.entity,
            index,
        )
    });
    let mut adjacent = Adjacency::new();
    for &index in &ordered {
        let edge = edges[index];
        if edge.from != edge.to {
            adjacent
                .entry(scope(edge, edge.from))
                .or_default()
                .push(index);
        }
    }
    let mut used = vec![false; edges.len()];
    let limits = Limits {
        max_hops,
        window_days,
        max_steps,
    };
    let mut result = Cycles {
        paths: Vec::new(),
        search_steps: 0,
    };
    for start in ordered {
        charge(&mut result.search_steps, max_steps)?;
        if used[start] || edges[start].from == edges[start].to {
            continue;
        }
        if let Some(path) = first_path(
            edges,
            &adjacent,
            &used,
            start,
            limits,
            &mut result.search_steps,
        )? {
            for &index in &path {
                used[index] = true;
            }
            result.paths.push(path);
        }
    }
    Ok(result)
}
