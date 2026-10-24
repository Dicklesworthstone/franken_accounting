//! Exact amount-weighted Louvain (bead fa-b6xs, `graph.party_communities`).
//!
//! Modularity at resolution 1 over an undirected graph whose edge weights are
//! exact amounts. Moving node `i` (degree `k_i`) into community `C` (degree
//! total `tot_C`, `k_in` of `i`'s weight into it) gains
//! `ΔQ = k_in / m − tot_C · k_i / (2m²)`; scaled by `2m²` that is the integer
//! `2m · k_in − tot_C · k_i`, so two moves are compared by cross-adding the
//! two products of each in 256 bits. No float, no tolerance: a move is taken
//! only when it strictly increases modularity, so every level terminates.
//!
//! Deterministic: nodes are visited in ascending index, a node stays put when
//! staying is as good as the best move, and otherwise joins the lowest-index
//! best community. Each level's communities become the next level's nodes,
//! numbered by their lowest member. `max_passes` and `max_levels` bound the
//! work; every candidate examined is charged to the meter.

use std::collections::BTreeMap;

use fa_money::wide::U256;

use crate::amount::{amount_difference, amount_sum};
use crate::{LanternError, Meter};

/// The community of each of `n` nodes (labels ascending by lowest member),
/// for `edges` `(a, b, weight)` with `a != b` and positive weights.
pub(crate) fn communities(
    n: usize,
    edges: &[(usize, usize, i128)],
    max_levels: u32,
    max_passes: u32,
    work: &mut Meter<'_>,
) -> Result<Vec<usize>, LanternError> {
    const WHAT: &str = "graph.party_communities weight";
    // Level graph: adjacency without self-loops, and each node's self-loop
    // weight (a community's internal weight after aggregation).
    let mut adj: Vec<BTreeMap<usize, i128>> = vec![BTreeMap::new(); n];
    let mut own = vec![0i128; n];
    let mut m = 0i128;
    for &(a, b, w) in edges {
        if a == b || w <= 0 || a >= n || b >= n {
            return Err(LanternError::Overflow("graph.party_communities edge"));
        }
        for (x, y) in [(a, b), (b, a)] {
            let slot = adj[x].entry(y).or_insert(0);
            *slot = amount_sum(*slot, w, WHAT)?;
        }
        m = amount_sum(m, w, WHAT)?;
    }
    // Every product below is at most (2m)², so 2m must fit i128.
    let two_m = amount_sum(m, m, WHAT)?;
    let mut membership: Vec<usize> = (0..n).collect();
    if m == 0 {
        return Ok(membership);
    }
    for _ in 0..max_levels {
        let size = adj.len();
        let degree: Vec<i128> = (0..size)
            .map(|i| {
                adj[i]
                    .values()
                    .try_fold(amount_sum(own[i], own[i], WHAT)?, |sum, w| {
                        amount_sum(sum, *w, WHAT)
                    })
            })
            .collect::<Result<_, _>>()?;
        let mut community: Vec<usize> = (0..size).collect();
        let mut total = degree.clone();
        let mut moved_any = false;
        for _ in 0..max_passes {
            let mut moved = false;
            for i in 0..size {
                let from = community[i];
                total[from] = amount_difference(total[from], degree[i], WHAT)?;
                let mut into: BTreeMap<usize, i128> = BTreeMap::new();
                for (&j, &w) in &adj[i] {
                    let slot = into.entry(community[j]).or_insert(0);
                    *slot = amount_sum(*slot, w, WHAT)?;
                }
                work.compare(1 + into.len() as u64)?;
                // A move's gain as (earned, cost): 2m · k_in and tot · k_i.
                let gain = |c: usize, k_in: i128| -> (U256, U256) {
                    (
                        U256::from_product(two_m.unsigned_abs(), k_in.unsigned_abs()),
                        U256::from_product(total[c].unsigned_abs(), degree[i].unsigned_abs()),
                    )
                };
                // gain(a) > gain(b)  ⇔  earned_a + cost_b > earned_b + cost_a.
                let better = |a: (U256, U256), b: (U256, U256)| -> Result<bool, LanternError> {
                    let left =
                        a.0.checked_add(b.1)
                            .ok_or(LanternError::Overflow("graph.party_communities gain"))?;
                    let right =
                        b.0.checked_add(a.1)
                            .ok_or(LanternError::Overflow("graph.party_communities gain"))?;
                    Ok(left > right)
                };
                let mut best = from;
                let mut best_gain = gain(from, into.get(&from).copied().unwrap_or(0));
                for (&c, &k_in) in &into {
                    if c == from {
                        continue;
                    }
                    let g = gain(c, k_in);
                    // Strictly better only: staying wins ties, and among
                    // movers the lowest community (visited first) wins.
                    if better(g, best_gain)? {
                        best = c;
                        best_gain = g;
                    }
                }
                total[best] = amount_sum(total[best], degree[i], WHAT)?;
                if best != from {
                    community[i] = best;
                    moved = true;
                    moved_any = true;
                }
            }
            if !moved {
                break;
            }
        }
        if !moved_any {
            break;
        }
        // Renumber communities by their lowest member, then aggregate.
        let mut label: BTreeMap<usize, usize> = BTreeMap::new();
        for &c in &community {
            let next = label.len();
            label.entry(c).or_insert(next);
        }
        let next_size = label.len();
        let mut next_adj: Vec<BTreeMap<usize, i128>> = vec![BTreeMap::new(); next_size];
        let mut next_own = vec![0i128; next_size];
        for i in 0..size {
            let ci = label[&community[i]];
            next_own[ci] = amount_sum(next_own[ci], own[i], WHAT)?;
            for (&j, &w) in &adj[i] {
                let cj = label[&community[j]];
                if ci == cj {
                    // Each internal edge is seen from both ends: count it once.
                    if i < j {
                        next_own[ci] = amount_sum(next_own[ci], w, WHAT)?;
                    }
                } else {
                    let slot = next_adj[ci].entry(cj).or_insert(0);
                    *slot = amount_sum(*slot, w, WHAT)?;
                }
            }
        }
        for node in &mut membership {
            *node = label[&community[*node]];
        }
        adj = next_adj;
        own = next_own;
    }
    Ok(membership)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(n: usize, edges: &[(usize, usize, i128)]) -> Vec<usize> {
        let mut work = Meter::new("graph.party_communities", None, None);
        communities(n, edges, 4, 8, &mut work).unwrap()
    }

    #[test]
    fn two_heavy_pairs_joined_by_a_light_edge_split_by_amount() {
        // A-B and C-D move 1,000,000 each; B-C moves 1.
        let c = run(4, &[(0, 1, 1_000_000), (2, 3, 1_000_000), (1, 2, 1)]);
        assert_eq!(c[0], c[1]);
        assert_eq!(c[2], c[3]);
        assert_ne!(c[0], c[2]);
    }

    #[test]
    fn amounts_not_topology_decide_the_grouping() {
        // A light triangle A-B-C with a heavy C-D: C goes with D.
        let c = run(4, &[(0, 1, 1), (0, 2, 1), (1, 2, 1), (2, 3, 1_000_000)]);
        assert_eq!(c[2], c[3]);
        assert_ne!(c[0], c[2]);
    }

    #[test]
    fn an_edgeless_graph_keeps_every_node_alone() {
        assert_eq!(run(3, &[]), vec![0, 1, 2]);
    }

    /// 4m² · Q of `partition`, from the definition: the sum over communities
    /// of 4m · (internal weight) − (degree total)². Independent of the
    /// incremental gain the algorithm compares.
    fn scaled_modularity(n: usize, edges: &[(usize, usize, i128)], partition: &[usize]) -> i128 {
        let m = edges
            .iter()
            .try_fold(0i128, |sum, e| sum.checked_add(e.2))
            .unwrap();
        let mut internal: BTreeMap<usize, i128> = BTreeMap::new();
        let mut total: BTreeMap<usize, i128> = BTreeMap::new();
        let add = |map: &mut BTreeMap<usize, i128>, key: usize, w: i128| {
            let slot = map.entry(key).or_default();
            *slot = slot.checked_add(w).unwrap();
        };
        for &(a, b, w) in edges {
            if partition[a] == partition[b] {
                add(&mut internal, partition[a], w);
            }
            add(&mut total, partition[a], w);
            add(&mut total, partition[b], w);
        }
        (0..n)
            .map(|i| partition[i])
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(|c| {
                let tot = total.get(&c).copied().unwrap_or(0);
                m.checked_mul(4)
                    .and_then(|x| x.checked_mul(internal.get(&c).copied().unwrap_or(0)))
                    .and_then(|x| x.checked_sub(tot.checked_mul(tot)?))
                    .unwrap()
            })
            .try_fold(0i128, i128::checked_add)
            .unwrap()
    }

    /// Over seeded random graphs: the result is a partition of the nodes, its
    /// literal modularity is at least the all-singletons partition's (every
    /// move strictly improves), and it does not depend on edge order.
    #[test]
    fn moves_only_raise_literal_modularity_and_edge_order_is_irrelevant() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move |bound: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.checked_rem(bound).unwrap()
        };
        for _ in 0..200 {
            let n = usize::try_from(next(6)).unwrap().checked_add(3).unwrap();
            let mut pairs: BTreeMap<(usize, usize), i128> = BTreeMap::new();
            for _ in 0..n.checked_mul(2).unwrap() {
                let a = usize::try_from(next(n as u64)).unwrap();
                let b = usize::try_from(next(n as u64)).unwrap();
                if a != b {
                    let key = (a.min(b), a.max(b));
                    let slot = pairs.entry(key).or_default();
                    *slot = slot
                        .checked_add(i128::from(next(1_000_000)))
                        .unwrap()
                        .checked_add(1)
                        .unwrap();
                }
            }
            let edges: Vec<(usize, usize, i128)> =
                pairs.iter().map(|(&(a, b), &w)| (a, b, w)).collect();
            let found = run(n, &edges);
            assert_eq!(found.len(), n);
            let singletons: Vec<usize> = (0..n).collect();
            assert!(
                scaled_modularity(n, &edges, &found) >= scaled_modularity(n, &edges, &singletons),
                "{edges:?} -> {found:?}"
            );
            let mut reversed = edges.clone();
            reversed.reverse();
            assert_eq!(run(n, &reversed), found, "{edges:?}");
        }
    }
}
