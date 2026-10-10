//! The producer against the independent verifier, below the journal:
//! `fa-verify`'s own BLAKE3 against `fgdb-crypto`'s, and the producer's
//! cached tree against the verifier's path arithmetic for every position and
//! size — two implementations that share no code and must agree.

use fa_notary::tree::{Tree, empty_root, leaf_hash};

/// Deterministic pseudo-random bytes (an LCG; no entropy source needed).
fn bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed;
    (0..len)
        .map(|_| {
            x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (x >> 56) as u8
        })
        .collect()
}

#[test]
fn verifier_blake3_equals_fgdb_crypto_at_every_length_through_three_chunks() {
    for len in 0..=3_200usize {
        let input = bytes(len, len as u64);
        assert_eq!(
            fa_verify::blake3::hash(&input),
            fgdb_crypto::hash(&input).0,
            "length {len}"
        );
    }
    for len in [8_191usize, 8_192, 8_193, 65_536, 1 << 20, (1 << 20) + 1] {
        let input = bytes(len, 7);
        assert_eq!(
            fa_verify::blake3::hash(&input),
            fgdb_crypto::hash(&input).0,
            "length {len}"
        );
    }
}

#[test]
fn producer_paths_verify_in_the_independent_verifier_at_every_position_and_size() {
    let mut tree = Tree::new();
    let mut leaves = Vec::new();
    assert_eq!(empty_root(), fa_verify::tree::empty_root());
    for n in 1..=48usize {
        let leaf = leaf_hash(&(n as u64).to_le_bytes());
        assert_eq!(leaf, fa_verify::tree::leaf_hash(&(n as u64).to_le_bytes()));
        tree.push(leaf);
        leaves.push(leaf);
        let root = tree.root();
        assert_eq!(root, fa_verify::tree::root_of(&leaves), "size {n}");
        assert_eq!(
            fa_verify::tree::bag_peaks(&tree.peaks_at(n).unwrap()),
            root,
            "peaks at {n}"
        );
        for (m, leaf) in leaves.iter().enumerate() {
            let path = tree.inclusion_path(m, n).unwrap();
            assert_eq!(
                fa_verify::tree::root_from_inclusion(m as u64, n as u64, leaf, &path),
                Some(root),
                "inclusion {m}/{n}"
            );
        }
        for m in 0..=n {
            let old_root = tree.root_at(m).unwrap();
            let path = tree.consistency_path(m, n).unwrap();
            assert!(
                fa_verify::tree::consistent(m as u64, n as u64, &old_root, &root, &path),
                "consistency {m}->{n}"
            );
            if m > 0 && m < n {
                let mut forged = old_root;
                forged[0] ^= 1;
                assert!(!fa_verify::tree::consistent(
                    m as u64, n as u64, &forged, &root, &path
                ));
            }
        }
    }
}

/// The verifier recomputes the public document commitment from the bytes
/// alone and agrees with the kernel's intake at every chunk boundary.
#[test]
fn verifier_doc_commit_equals_the_kernel_at_every_chunk_boundary() {
    const C: usize = 4096;
    for len in [
        0,
        1,
        C - 1,
        C,
        C + 1,
        2 * C,
        3 * C + 5,
        5 * C,
        7 * C + 1,
        16 * C + 3,
    ] {
        let doc = bytes(len, len as u64 + 11);
        for kind in [1u8, 2, 9] {
            assert_eq!(
                fa_verify::document::doc_commit(kind, &doc),
                fa_journal::evidence::doc_commit(kind, &doc),
                "length {len} kind {kind}"
            );
        }
    }
}

fn checkpoint(through_seq: u64, leaf_count: u64, root: [u8; 32]) -> fa_verify::Checkpoint {
    fa_verify::Checkpoint {
        book_id: [0x5a; 16],
        branch_id: [0; 16],
        through_seq,
        leaf_count,
        root,
    }
}

fn consistency_proof(
    old: &fa_verify::Checkpoint,
    new: &fa_verify::Checkpoint,
    path: &[[u8; 32]],
) -> Vec<u8> {
    let mut w = fa_model::Writer::new();
    w.bytes(b"fa:acc-consistency-proof:v1")
        .fixed(&old.encode())
        .fixed(&new.encode());
    w.list(path, |w, d| {
        w.fixed(d);
    });
    w.finish().unwrap()
}

/// TopazOsprey's R1 (fa-l3c review): a later claim of more leaves at the
/// trusted checkpoint's own sequence contradicts it — the trusted state said
/// its leaves were exactly the records through that sequence — and is
/// refused even though the RFC 9162 path is valid.
#[test]
fn more_leaves_at_the_same_sequence_are_a_regression_not_an_extension() {
    let mut t = Tree::new();
    for i in 0..4u64 {
        t.push(leaf_hash(&i.to_le_bytes()));
    }
    let old = checkpoint(6, 2, t.root_at(2).unwrap());
    let backdated = checkpoint(6, 4, t.root_at(4).unwrap());
    let path = t.consistency_path(2, 4).unwrap();
    assert!(fa_verify::tree::consistent(
        2,
        4,
        &old.root,
        &backdated.root,
        &path
    ));
    assert_eq!(
        fa_verify::verify_consistency(
            &consistency_proof(&old, &backdated, &path),
            &old,
            &backdated
        ),
        Err(fa_verify::VerifyError::Regression)
    );
    // The same tree at the same sequence is the trusted checkpoint itself.
    let same = consistency_proof(&old, &old, &[]);
    assert_eq!(
        fa_verify::verify_consistency(&same, &old, &old)
            .unwrap()
            .extended,
        old
    );
    // The same leaves at a later sequence (nothing recorded in between) and
    // more leaves at a later sequence both extend.
    let quiet = checkpoint(9, 2, old.root);
    assert!(
        fa_verify::verify_consistency(&consistency_proof(&old, &quiet, &[]), &old, &quiet).is_ok()
    );
    let later = checkpoint(7, 4, backdated.root);
    assert!(
        fa_verify::verify_consistency(&consistency_proof(&old, &later, &path), &old, &later)
            .is_ok()
    );
}

/// WhiteCreek's 0/0 counterexample through the encoded proof: an empty
/// trusted checkpoint does not extend to a zero-leaf claim with any root.
#[test]
fn an_empty_checkpoint_extends_only_to_the_honest_empty_root() {
    let empty = checkpoint(1, 0, empty_root());
    let forged = checkpoint(2, 0, [0xab; 32]);
    assert_eq!(
        fa_verify::verify_consistency(&consistency_proof(&empty, &forged, &[]), &empty, &forged),
        Err(fa_verify::VerifyError::Consistency)
    );
    let honest = checkpoint(2, 0, empty_root());
    assert!(
        fa_verify::verify_consistency(&consistency_proof(&empty, &honest, &[]), &empty, &honest)
            .is_ok()
    );
}
