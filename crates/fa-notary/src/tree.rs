//! The accumulator tree (plan §13.2): a Merkle Mountain Range whose root
//! bags the peaks right to left — the RFC 9162 Merkle tree shape — over
//! BLAKE3 with FrankenAccounting domain separation:
//!
//! - leaf  = `BLAKE3("fa:acc-leaf:v1" ‖ canonical(LeafEnvelope))`
//! - node  = `BLAKE3("fa:acc-node:v1" ‖ left ‖ right)`
//! - empty = `BLAKE3("fa:acc-empty:v1")`
//!
//! The tree keeps every level of complete nodes, so an append costs
//! amortized O(1) hashes, the peaks at any size are lookups, and every proof
//! node is a lookup or an O(log n) recombination along the right edge. It is
//! a derived structure: [`crate::Journal`] rebuilds it from the journal
//! prefix, and nothing reads it as a source of truth.

use fgdb_crypto::Hasher;

pub const LEAF_DOMAIN: &[u8] = b"fa:acc-leaf:v1";
pub const NODE_DOMAIN: &[u8] = b"fa:acc-node:v1";
pub const EMPTY_DOMAIN: &[u8] = b"fa:acc-empty:v1";

pub type Digest = [u8; 32];

fn hash(domain: &[u8], parts: &[&[u8]]) -> Digest {
    let mut h = Hasher::new();
    h.update(domain);
    for p in parts {
        h.update(p);
    }
    h.finalize().0
}

#[must_use]
pub fn leaf_hash(envelope_bytes: &[u8]) -> Digest {
    hash(LEAF_DOMAIN, &[envelope_bytes])
}

#[must_use]
pub fn node_hash(left: &Digest, right: &Digest) -> Digest {
    hash(NODE_DOMAIN, &[left, right])
}

#[must_use]
pub fn empty_root() -> Digest {
    hash(EMPTY_DOMAIN, &[])
}

/// The largest power of two strictly below `n` (`n ≥ 2`).
fn split(n: usize) -> usize {
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tree {
    /// The domain of interior nodes: [`NODE_DOMAIN`] for the accumulator,
    /// another for a derived index with the same shape (the scope index).
    node_domain: &'static [u8],
    /// `levels[0]` are the leaves; `levels[h][i]` is the root of the
    /// complete subtree over leaves `[i·2^h, (i+1)·2^h)`.
    levels: Vec<Vec<Digest>>,
}

impl Default for Tree {
    fn default() -> Self {
        Self::new()
    }
}

impl Tree {
    /// The accumulator tree.
    #[must_use]
    pub fn new() -> Self {
        Self::with_node_domain(NODE_DOMAIN)
    }

    /// A tree of the same shape whose interior nodes hash under
    /// `node_domain`. Its empty root is the accumulator's: an index with
    /// its own empty commitment handles size 0 itself.
    #[must_use]
    pub fn with_node_domain(node_domain: &'static [u8]) -> Self {
        Self {
            node_domain,
            levels: Vec::new(),
        }
    }

    fn node(&self, left: &Digest, right: &Digest) -> Digest {
        hash(self.node_domain, &[left, right])
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.levels.first().map_or(0, Vec::len)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn push(&mut self, leaf: Digest) {
        if self.levels.is_empty() {
            self.levels.push(Vec::new());
        }
        self.levels[0].push(leaf);
        // A binary counter: a level that reaches an even length completes
        // one node of the level above.
        let mut h = 0;
        while self.levels[h].len().is_multiple_of(2) {
            let n = self.levels[h].len();
            let node = self.node(&self.levels[h][n - 2], &self.levels[h][n - 1]);
            if self.levels.len() == h + 1 {
                self.levels.push(Vec::new());
            }
            self.levels[h + 1].push(node);
            h += 1;
        }
    }

    /// The root of leaves `[a, b)`, `a < b ≤ len`. Every left subtree the
    /// RFC 9162 recursion visits is complete and aligned, hence a lookup.
    fn subtree(&self, a: usize, b: usize) -> Digest {
        let n = b - a;
        if n.is_power_of_two() && a.is_multiple_of(n) {
            let h = n.trailing_zeros() as usize;
            return self.levels[h][a >> h];
        }
        let k = split(n);
        self.node(&self.subtree(a, a + k), &self.subtree(a + k, b))
    }

    /// The root over the first `size` leaves, or `None` beyond the tree.
    #[must_use]
    pub fn root_at(&self, size: usize) -> Option<Digest> {
        match size {
            0 => Some(empty_root()),
            s if s <= self.len() => Some(self.subtree(0, s)),
            _ => None,
        }
    }

    #[must_use]
    pub fn root(&self) -> Digest {
        self.root_at(self.len()).unwrap_or_else(empty_root)
    }

    /// The peaks of the first `size` leaves: the complete subtrees of the
    /// binary decomposition of `size`, largest (leftmost) first.
    #[must_use]
    pub fn peaks_at(&self, size: usize) -> Option<Vec<Digest>> {
        if size > self.len() {
            return None;
        }
        let mut peaks = Vec::with_capacity(size.count_ones() as usize);
        let mut at = 0;
        for h in (0..usize::BITS as usize).rev() {
            if (size >> h) & 1 == 1 {
                peaks.push(self.levels[h][at >> h]);
                at += 1 << h;
            }
        }
        Some(peaks)
    }

    /// The RFC 9162 §2.1.3.1 inclusion path of leaf `index` in the tree of
    /// the first `size` leaves, deepest sibling first.
    #[must_use]
    pub fn inclusion_path(&self, index: usize, size: usize) -> Option<Vec<Digest>> {
        if index >= size || size > self.len() {
            return None;
        }
        let mut out = Vec::new();
        self.path(index, 0, size, &mut out);
        Some(out)
    }

    fn path(&self, m: usize, a: usize, b: usize, out: &mut Vec<Digest>) {
        let n = b - a;
        if n <= 1 {
            return;
        }
        let k = split(n);
        if m < k {
            self.path(m, a, a + k, out);
            out.push(self.subtree(a + k, b));
        } else {
            self.path(m - k, a + k, b, out);
            out.push(self.subtree(a, a + k));
        }
    }

    /// The RFC 9162 §2.1.4.1 consistency path from the first `old` leaves
    /// to the first `new` leaves. Empty when `old` is 0 or equals `new`.
    #[must_use]
    pub fn consistency_path(&self, old: usize, new: usize) -> Option<Vec<Digest>> {
        if old > new || new > self.len() {
            return None;
        }
        let mut out = Vec::new();
        if old > 0 && old < new {
            self.subproof(old, 0, new, true, &mut out);
        }
        Some(out)
    }

    fn subproof(&self, m: usize, a: usize, b: usize, complete: bool, out: &mut Vec<Digest>) {
        let n = b - a;
        if m == n {
            if !complete {
                out.push(self.subtree(a, b));
            }
            return;
        }
        let k = split(n);
        if m <= k {
            self.subproof(m, a, a + k, complete, out);
            out.push(self.subtree(a + k, b));
        } else {
            self.subproof(m - k, a + k, b, false, out);
            out.push(self.subtree(a, a + k));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The definition, recursively, with no caching.
    fn naive_root(leaves: &[Digest]) -> Digest {
        match leaves.len() {
            0 => empty_root(),
            1 => leaves[0],
            n => {
                let k = split(n);
                node_hash(&naive_root(&leaves[..k]), &naive_root(&leaves[k..]))
            }
        }
    }

    #[test]
    fn incremental_roots_and_peaks_equal_the_definition_at_every_size() {
        let mut tree = Tree::new();
        let mut leaves = Vec::new();
        assert_eq!(tree.root(), empty_root());
        for i in 0..130u64 {
            let leaf = leaf_hash(&i.to_le_bytes());
            tree.push(leaf);
            leaves.push(leaf);
            assert_eq!(tree.root(), naive_root(&leaves), "size {}", leaves.len());
            for size in [0, leaves.len() / 2, leaves.len()] {
                assert_eq!(tree.root_at(size), Some(naive_root(&leaves[..size])));
                let peaks = tree.peaks_at(size).unwrap();
                assert_eq!(peaks.len(), size.count_ones() as usize);
                let bagged = peaks
                    .split_last()
                    .map(|(last, rest)| rest.iter().rev().fold(*last, |acc, p| node_hash(p, &acc)))
                    .unwrap_or_else(empty_root);
                assert_eq!(bagged, naive_root(&leaves[..size]));
            }
        }
        assert_eq!(tree.root_at(131), None);
        assert_eq!(tree.inclusion_path(130, 130), None);
        assert_eq!(tree.consistency_path(5, 131), None);
        assert_eq!(tree.consistency_path(0, 130), Some(Vec::new()));
        assert_eq!(tree.consistency_path(130, 130), Some(Vec::new()));
    }
}
