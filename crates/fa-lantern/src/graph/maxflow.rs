//! Exact max-flow decomposition for `graph.ultimate_beneficiary` (bead
//! fa-b6xs, plan §11.4: "max-flow decomposition of where money finally
//! rests").
//!
//! Edmonds-Karp over a directed graph with exact amount capacities: each
//! augmentation follows a shortest path found by breadth-first search that
//! visits neighbours in ascending index, so the decomposition is
//! deterministic. A flow decomposition is not unique; this one is the
//! shortest-augmenting-path one, and a finding states so. Arithmetic is
//! checked; `max_augmentations` bounds the work, and a search stopped by it
//! reports what it traced as a lower bound.

use std::collections::{BTreeMap, VecDeque};

use crate::amount::{amount_difference, amount_sum};
use crate::{LanternError, Meter};

/// A max flow from `source` to `sink`.
pub(crate) struct Flow {
    /// The flow on each original arc `(from, to)`, where positive.
    pub(crate) arcs: BTreeMap<(usize, usize), i128>,
    /// The flow's value.
    pub(crate) value: i128,
    /// False when `max_augmentations` stopped the search: `value` is then a
    /// lower bound on the maximum.
    pub(crate) complete: bool,
}

/// The max flow from `source` to `sink` over `capacity[(from, to)]` (positive
/// capacities, `n` nodes).
pub(crate) fn max_flow(
    n: usize,
    capacity: &BTreeMap<(usize, usize), i128>,
    source: usize,
    sink: usize,
    max_augmentations: u32,
    work: &mut Meter<'_>,
) -> Result<Flow, LanternError> {
    const WHAT: &str = "graph.ultimate_beneficiary flow";
    // Residual capacities, with a reverse arc for every forward arc.
    let mut residual: Vec<BTreeMap<usize, i128>> = vec![BTreeMap::new(); n];
    for (&(u, v), &c) in capacity {
        if u >= n || v >= n || u == v || c <= 0 {
            return Err(LanternError::Overflow("graph.ultimate_beneficiary arc"));
        }
        let forward = residual[u].entry(v).or_insert(0);
        *forward = amount_sum(*forward, c, WHAT)?;
        residual[v].entry(u).or_insert(0);
    }
    let mut value = 0i128;
    let mut complete = true;
    let mut augmentations = 0u32;
    loop {
        // Shortest augmenting path, neighbours in ascending index.
        let mut parent: Vec<Option<usize>> = vec![None; n];
        let mut seen = vec![false; n];
        seen[source] = true;
        let mut queue = VecDeque::from([source]);
        while let Some(u) = queue.pop_front() {
            work.compare(residual[u].len() as u64)?;
            if u == sink {
                break;
            }
            for (&v, &c) in &residual[u] {
                if c > 0 && !seen[v] {
                    seen[v] = true;
                    parent[v] = Some(u);
                    queue.push_back(v);
                }
            }
        }
        if !seen[sink] {
            break;
        }
        if augmentations >= max_augmentations {
            complete = false;
            break;
        }
        augmentations = augmentations.saturating_add(1);
        // The bottleneck along the path, then push it.
        let mut bottleneck = i128::MAX;
        let mut v = sink;
        while let Some(u) = parent[v] {
            bottleneck = bottleneck.min(residual[u][&v]);
            v = u;
        }
        let mut v = sink;
        while let Some(u) = parent[v] {
            let forward = residual[u].get_mut(&v).expect("residual arc");
            *forward = amount_difference(*forward, bottleneck, WHAT)?;
            let backward = residual[v].get_mut(&u).expect("reverse arc");
            *backward = amount_sum(*backward, bottleneck, WHAT)?;
            v = u;
        }
        value = amount_sum(value, bottleneck, WHAT)?;
    }
    // Net flow on each original arc: capacity minus what is left, when
    // positive (a cancelled pair nets to zero and is dropped).
    let mut arcs = BTreeMap::new();
    for (&(u, v), &c) in capacity {
        let left = residual[u].get(&v).copied().unwrap_or(0);
        let used = amount_difference(c, left.min(c), WHAT)?;
        if used > 0 {
            arcs.insert((u, v), used);
        }
    }
    Ok(Flow {
        arcs,
        value,
        complete,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(n: usize, arcs: &[(usize, usize, i128)], s: usize, t: usize, cap: u32) -> Flow {
        let capacity = arcs.iter().map(|&(u, v, c)| ((u, v), c)).collect();
        let mut work = Meter::new("graph.ultimate_beneficiary", None, None);
        max_flow(n, &capacity, s, t, cap, &mut work).unwrap()
    }

    #[test]
    fn a_chain_carries_its_bottleneck() {
        let f = flow(4, &[(0, 1, 100), (1, 2, 90), (2, 3, 95)], 0, 3, 64);
        assert_eq!(f.value, 90);
        assert!(f.complete);
        assert_eq!(f.arcs[&(0, 1)], 90);
    }

    #[test]
    fn parallel_routes_add_up() {
        // 0 -> 1 -> 3 (50) and 0 -> 2 -> 3 (30), plus a dead end 1 -> 2.
        let f = flow(
            4,
            &[(0, 1, 60), (1, 3, 50), (0, 2, 30), (2, 3, 40), (1, 2, 5)],
            0,
            3,
            64,
        );
        assert_eq!(f.value, 85);
        let into_sink: i128 = f
            .arcs
            .iter()
            .filter(|((_, v), _)| *v == 3)
            .map(|(_, c)| *c)
            .try_fold(0i128, |s, c| s.checked_add(c))
            .unwrap();
        assert_eq!(into_sink, f.value);
    }

    #[test]
    fn the_augmentation_cap_reports_a_lower_bound() {
        let f = flow(
            4,
            &[(0, 1, 10), (1, 3, 10), (0, 2, 10), (2, 3, 10)],
            0,
            3,
            1,
        );
        assert_eq!(f.value, 10);
        assert!(!f.complete);
    }
}
