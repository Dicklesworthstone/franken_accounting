//! The accumulator's tree law (plan §13.2), on the verifier's side.
//!
//! The journal accumulator is a Merkle Mountain Range whose root bags the
//! peaks right to left — exactly the RFC 9162 (Certificate Transparency v2)
//! Merkle tree shape, so its inclusion and consistency proofs and their
//! verification algorithms are the RFC's (§2.1.3, §2.1.4), with BLAKE3 and
//! FrankenAccounting domain separation in place of `SHA-256(0x00 ‖ …)` and
//! `SHA-256(0x01 ‖ …)`:
//!
//! - leaf `i`  = `BLAKE3("fa:acc-leaf:v1" ‖ canonical(LeafEnvelope_i))`
//! - node      = `BLAKE3("fa:acc-node:v1" ‖ left ‖ right)`
//! - root of 0 = `BLAKE3("fa:acc-empty:v1")`
//! - root of n>1 leaves `D[0:n]`: with `k` the largest power of two below
//!   `n`, `node(root(D[0:k]), root(D[k:n]))`.
//!
//! The two domains have equal length and differ, so a leaf can never be
//! read as a node or the reverse (second-preimage separation).

use crate::blake3::hash_parts;

pub const LEAF_DOMAIN: &[u8] = b"fa:acc-leaf:v1";
pub const NODE_DOMAIN: &[u8] = b"fa:acc-node:v1";
pub const EMPTY_DOMAIN: &[u8] = b"fa:acc-empty:v1";

pub type Digest = [u8; 32];

#[must_use]
pub fn leaf_hash(envelope_bytes: &[u8]) -> Digest {
    hash_parts(LEAF_DOMAIN, &[envelope_bytes])
}

#[must_use]
pub fn node_hash(left: &Digest, right: &Digest) -> Digest {
    hash_parts(NODE_DOMAIN, &[left, right])
}

#[must_use]
pub fn empty_root() -> Digest {
    hash_parts(EMPTY_DOMAIN, &[])
}

/// The largest power of two strictly below `n` (`n ≥ 2`).
fn split(n: usize) -> usize {
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// The root over `leaves` by the recursive definition. Linear time; the
/// verifier uses it for complete-prefix proofs, where every leaf is present.
#[must_use]
pub fn root_of(leaves: &[Digest]) -> Digest {
    match leaves.len() {
        0 => empty_root(),
        _ => root_of_with(node_hash, leaves),
    }
}

/// The root over one or more `leaves` of a tree of the same shape whose
/// interior nodes hash with `node` (the caller defines the empty tree).
#[must_use]
pub fn root_of_with(node_hash: fn(&Digest, &Digest) -> Digest, leaves: &[Digest]) -> Digest {
    match leaves.len() {
        0 | 1 => leaves.first().copied().unwrap_or([0; 32]),
        n => {
            let k = split(n);
            node_hash(
                &root_of_with(node_hash, &leaves[..k]),
                &root_of_with(node_hash, &leaves[k..]),
            )
        }
    }
}

/// The root over a tree's peaks — the roots of the perfect subtrees of the
/// binary decomposition of its size, largest (leftmost) first — bagged
/// right to left. Equal to [`root_of`] over the leaves those peaks cover.
#[must_use]
pub fn bag_peaks(peaks: &[Digest]) -> Digest {
    let Some((last, rest)) = peaks.split_last() else {
        return empty_root();
    };
    rest.iter().rev().fold(*last, |acc, p| node_hash(p, &acc))
}

/// The root an inclusion path implies for `leaf` at `leaf_index` in a tree
/// of `tree_size` leaves (RFC 9162 §2.1.3.2), or `None` when the path's
/// shape does not fit that position and size.
#[must_use]
pub fn root_from_inclusion(
    leaf_index: u64,
    tree_size: u64,
    leaf: &Digest,
    path: &[Digest],
) -> Option<Digest> {
    root_from_inclusion_with(node_hash, leaf_index, tree_size, leaf, path)
}

/// [`root_from_inclusion`] for a tree of the same shape whose interior
/// nodes hash with `node` (the scope index's domain, for one).
#[must_use]
pub fn root_from_inclusion_with(
    node_hash: fn(&Digest, &Digest) -> Digest,
    leaf_index: u64,
    tree_size: u64,
    leaf: &Digest,
    path: &[Digest],
) -> Option<Digest> {
    if leaf_index >= tree_size {
        return None;
    }
    let mut fnode = leaf_index;
    let mut snode = tree_size - 1;
    let mut r = *leaf;
    for p in path {
        if snode == 0 {
            return None;
        }
        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(p, &r);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    (snode == 0).then_some(r)
}

/// Whether `path` proves that the tree of `new_size` leaves under
/// `new_root` extends the tree of `old_size` leaves under `old_root`
/// (RFC 9162 §2.1.4.2). Equal sizes need an empty path and equal roots;
/// every tree extends the empty one, whose root must be [`empty_root`] —
/// and a zero-leaf new tree is the empty tree, so its root must be too.
#[must_use]
pub fn consistent(
    old_size: u64,
    new_size: u64,
    old_root: &Digest,
    new_root: &Digest,
    path: &[Digest],
) -> bool {
    if old_size > new_size {
        return false;
    }
    if old_size == 0 {
        return path.is_empty()
            && *old_root == empty_root()
            && (new_size > 0 || *new_root == empty_root());
    }
    if old_size == new_size {
        return path.is_empty() && old_root == new_root;
    }
    if path.is_empty() {
        return false;
    }
    // When the old tree is a complete subtree, its root is the first node.
    let mut nodes: Vec<Digest> = Vec::with_capacity(path.len() + 1);
    if old_size.is_power_of_two() {
        nodes.push(*old_root);
    }
    nodes.extend_from_slice(path);
    let mut fnode = old_size - 1;
    let mut snode = new_size - 1;
    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }
    let mut fr = nodes[0];
    let mut sr = nodes[0];
    for c in &nodes[1..] {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    fr == *old_root && sr == *new_root && snode == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blake3::hash;

    fn leaves(n: usize) -> Vec<Digest> {
        (0..n)
            .map(|i| leaf_hash(&(i as u64).to_le_bytes()))
            .collect()
    }

    /// A deliberately naive path builder (RFC 9162 §2.1.3.1, recursive), so
    /// the verification arithmetic above is checked against the definition
    /// rather than against itself.
    fn path(m: usize, d: &[Digest]) -> Vec<Digest> {
        if d.len() <= 1 {
            return Vec::new();
        }
        let k = split(d.len());
        if m < k {
            let mut p = path(m, &d[..k]);
            p.push(root_of(&d[k..]));
            p
        } else {
            let mut p = path(m - k, &d[k..]);
            p.push(root_of(&d[..k]));
            p
        }
    }

    fn subproof(m: usize, d: &[Digest], complete: bool) -> Vec<Digest> {
        let n = d.len();
        if m == n {
            return if complete {
                Vec::new()
            } else {
                vec![root_of(d)]
            };
        }
        let k = split(n);
        if m <= k {
            let mut p = subproof(m, &d[..k], complete);
            p.push(root_of(&d[k..]));
            p
        } else {
            let mut p = subproof(m - k, &d[k..], false);
            p.push(root_of(&d[..k]));
            p
        }
    }

    #[test]
    fn domains_separate_leaves_nodes_and_the_empty_tree() {
        assert_eq!(LEAF_DOMAIN.len(), NODE_DOMAIN.len());
        let l = leaf_hash(b"x");
        assert_ne!(l, hash(b"x"));
        assert_ne!(node_hash(&l, &l), leaf_hash(&[l, l].concat()));
        assert_ne!(empty_root(), hash(b""));
        assert_eq!(root_of(&[]), empty_root());
        assert_eq!(root_of(&leaves(1)), leaves(1)[0]);
        let three = leaves(3);
        assert_eq!(
            root_of(&three),
            node_hash(&node_hash(&three[0], &three[1]), &three[2])
        );
    }

    /// The peaks of `n` leaves, by the binary decomposition of `n`.
    fn peaks(d: &[Digest]) -> Vec<Digest> {
        let mut out = Vec::new();
        let mut at = 0;
        for h in (0..usize::BITS).rev() {
            let size = 1usize << h;
            if d.len() & size != 0 {
                out.push(root_of(&d[at..at + size]));
                at += size;
            }
        }
        out
    }

    #[test]
    fn bagged_peaks_equal_the_recursive_root() {
        assert_eq!(bag_peaks(&[]), empty_root());
        for n in 1..=70usize {
            let d = leaves(n);
            let p = peaks(&d);
            assert_eq!(p.len(), n.count_ones() as usize);
            assert_eq!(bag_peaks(&p), root_of(&d), "{n}");
        }
    }

    #[test]
    fn every_inclusion_path_verifies_and_every_wrong_claim_fails() {
        for n in 1..=33usize {
            let d = leaves(n);
            let root = root_of(&d);
            for m in 0..n {
                let p = path(m, &d);
                let (m64, n64) = (m as u64, n as u64);
                assert_eq!(
                    root_from_inclusion(m64, n64, &d[m], &p),
                    Some(root),
                    "{m}/{n}"
                );
                // Another leaf, another position, another size, or a
                // damaged or truncated path never reproduces the root.
                let other = (m + 1) % n;
                if other != m {
                    assert_ne!(root_from_inclusion(m64, n64, &d[other], &p), Some(root));
                    assert_ne!(
                        root_from_inclusion(other as u64, n64, &d[m], &p),
                        Some(root)
                    );
                }
                // A path is checked against a trusted (size, root) *pair*:
                // the size-3 path of leaf 0 also evaluates to the size-3 root
                // under a claimed size 4, so the size is never trusted apart
                // from its root. Against the real larger tree it fails.
                assert_ne!(
                    root_from_inclusion(m64, n64 + 1, &d[m], &p),
                    Some(root_of(&leaves(n + 1)))
                );
                assert_eq!(root_from_inclusion(n64, n64, &d[m], &p), None);
                for i in 0..p.len() {
                    let mut bad = p.clone();
                    bad[i][0] ^= 1;
                    assert_ne!(root_from_inclusion(m64, n64, &d[m], &bad), Some(root));
                }
                if !p.is_empty() {
                    assert_ne!(
                        root_from_inclusion(m64, n64, &d[m], &p[..p.len() - 1]),
                        Some(root)
                    );
                }
                let mut long = p.clone();
                long.push(root);
                assert_ne!(root_from_inclusion(m64, n64, &d[m], &long), Some(root));
            }
        }
    }

    /// WhiteCreek's counterexample (fa-l3c review): 0 → 0 must not accept
    /// a new root other than the empty root.
    #[test]
    fn the_empty_tree_extends_only_to_trees_with_honest_roots() {
        let e = empty_root();
        assert!(!consistent(0, 0, &e, &[0xab; 32], &[]));
        assert!(consistent(0, 0, &e, &e, &[]));
        assert!(!consistent(0, 0, &[0xab; 32], &e, &[]));
        assert!(!consistent(0, 0, &e, &e, &[e]));
        let d = leaves(5);
        assert!(consistent(0, 5, &e, &root_of(&d), &[]));
        assert!(!consistent(0, 5, &e, &root_of(&d), &[d[0]]));
    }

    #[test]
    fn every_consistency_path_verifies_and_every_wrong_claim_fails() {
        for n in 1..=33usize {
            let d = leaves(n);
            let new_root = root_of(&d);
            assert!(consistent(0, n as u64, &empty_root(), &new_root, &[]));
            assert!(!consistent(0, n as u64, &d[0], &new_root, &[]));
            for m in 1..=n {
                let old_root = root_of(&d[..m]);
                let p = subproof(m, &d, true);
                let (m64, n64) = (m as u64, n as u64);
                assert!(consistent(m64, n64, &old_root, &new_root, &p), "{m}->{n}");
                assert!(!consistent(n64, m64, &new_root, &old_root, &p) || m == n);
                if m < n {
                    // A rewritten old leaf, a different old size, or a
                    // damaged path is detected.
                    let mut rewritten = d.clone();
                    rewritten[m - 1][0] ^= 1;
                    assert!(!consistent(
                        m64,
                        n64,
                        &root_of(&rewritten[..m]),
                        &new_root,
                        &p
                    ));
                    assert!(!consistent(m64, n64, &old_root, &root_of(&rewritten), &p));
                    if m > 1 {
                        assert!(!consistent(m64 - 1, n64, &old_root, &new_root, &p));
                    }
                    for i in 0..p.len() {
                        let mut bad = p.clone();
                        bad[i][31] ^= 0x80;
                        assert!(!consistent(m64, n64, &old_root, &new_root, &bad));
                    }
                    assert!(!consistent(m64, n64, &old_root, &new_root, &[]));
                }
            }
        }
    }
}
