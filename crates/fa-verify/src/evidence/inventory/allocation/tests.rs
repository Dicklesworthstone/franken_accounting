use super::*;
use crate::blake3::hash_parts;
use crate::codec::Writer;
use crate::document::doc_commit;
use crate::envelope::{ENTRY_DIGEST_DOMAIN, PROPOSAL_DIGEST_DOMAIN, envelope_of_entry};
use crate::proof::{INCLUSION_FORMAT, RecordCheck};
use crate::tree::leaf_hash;

const BOOK: [u8; 16] = [0x42; 16];

// Raw protocol fixtures, built independently of every producer codec. These
// prove wire/arithmetic handling, not that an accounting kernel admitted them.
fn basis(law: u16, rounding: u16, total: i128, weights: &[u128], debit: bool) -> Vec<u8> {
    let mut request = Writer::default();
    request
        .fixed(b"FA-ALLOC-REQUEST\0")
        .u16(1)
        .u16(0)
        .u16(law)
        .u16(1)
        .u32(1)
        .i128(total);
    if law == 2 {
        request.u16(rounding).u128(20);
    }
    request.count(weights.len());
    for (i, weight) in weights.iter().enumerate() {
        request.u128(20 + i as u128).u128(*weight);
    }
    let mut w = Writer::default();
    w.fixed(b"FA-ALLOC-BASIS\0")
        .u16(1)
        .u128(10)
        .u8(u8::from(!debit))
        .count(0)
        .bytes(&request.buf);
    w.buf
}

fn citation(bytes: &[u8]) -> EvidenceCitation {
    let commitment = doc_commit(21, bytes);
    EvidenceCitation {
        document_oid: super::super::document_oid(&BOOK, &commitment),
        doc_commit: commitment,
        role: 1,
    }
}
fn erased(w: &mut Writer) {
    w.fixed(&[0; 32]).u8(0).fixed(&[0; 24]).bytes(&[]);
}

fn proposal(bytes: &[u8], shares: &[i128], citations: &[EvidenceCitation]) -> Vec<u8> {
    let b = AllocationBasis::decode(bytes).unwrap();
    let mut w = Writer::default();
    // Allocation entries are written at the registered extensions minor (1)
    // since 752c2f08c.
    w.u16(1)
        .u16(1)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u16(9)
        .i32(20_527)
        .u8(0);
    erased(&mut w);
    w.u8(0)
        .count(1 + shares.iter().filter(|share| **share != 0).count());
    let vector = core::iter::once((b.source, b.total, b.source_debit, b.dimensions.as_slice()))
        .chain(
            shares
                .iter()
                .enumerate()
                .filter(|(_, share)| **share != 0)
                .map(|(i, share)| {
                    let (account, dimensions) = b.target_cell(i).unwrap();
                    (
                        account,
                        *share,
                        if *share < 0 {
                            b.source_debit
                        } else {
                            !b.source_debit
                        },
                        dimensions,
                    )
                }),
        );
    for (account, share, debit, dimensions) in vector {
        w.u8(u8::from(!debit))
            .u128(account)
            .u32(1)
            .i128(share.checked_abs().unwrap())
            .u8(0);
        write_dimensions(&mut w, dimensions);
        w.u8(0).count(0);
    }
    let gross: i128 = shares.iter().filter(|share| **share > 0).sum();
    w.u8(0)
        .count(1)
        .u32(1)
        .i128(gross)
        .i128(gross)
        .u8(0)
        .bytes(b"allocation-test")
        .u8(0)
        .fixed(&[9; 32])
        .u16(1)
        .u128(7)
        .u8(0)
        .count(citations.len());
    for cite in citations {
        w.fixed(&cite.document_oid)
            .fixed(&cite.doc_commit)
            .u8(cite.role);
    }
    w.count(0).u8(0).count(0).count(0).count(1).u16(5);
    let mut record = Writer::default();
    record
        .fixed(b"FA-ALLOC-POST\0")
        .u16(b.version())
        .bytes(bytes)
        .fixed(&law_digest(b.law))
        .fixed(&basis_digest(b.version(), bytes));
    w.bytes(&record.buf);
    w.buf
}

fn proof(proposal: &[u8], record: bool) -> (Vec<u8>, Checkpoint, [u8; 32]) {
    let pd = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[proposal]);
    let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&pd, &[0; 5]]);
    let mut payload = proposal.to_vec();
    payload.extend_from_slice(&[0; 5]);
    payload.extend_from_slice(&pd);
    payload.extend_from_slice(&digest);
    let envelope = envelope_of_entry(&payload, proposal.len(), 7, 0)
        .unwrap()
        .encode();
    let checkpoint = Checkpoint {
        book_id: BOOK,
        branch_id: [0; 16],
        through_seq: 9,
        leaf_count: 1,
        root: leaf_hash(&envelope),
    };
    let mut w = Writer::default();
    w.bytes(INCLUSION_FORMAT)
        .fixed(&checkpoint.encode())
        .u64(0)
        .bytes(&envelope)
        .u8(u8::from(record));
    if record {
        w.u32(proposal.len() as u32).bytes(&payload);
    }
    w.count(0);
    (w.buf, checkpoint, digest)
}

#[test]
fn known_allocations_bind_native_legs_and_exact_workpaper_for_both_source_sides() {
    for debit in [true, false] {
        for (law, rounding, total, weights, expected) in [
            (1, 0, 10_000, vec![1, 1, 1], vec![3334, 3333, 3333]),
            (2, 6, 1, vec![1, 1, 1], vec![-1, 1, 1]),
            (3, 0, 10, vec![4, 0, 9], vec![4, 0, 6]),
            (5, 0, 2, vec![1; 5], vec![2, 0, 0, 0, 0]),
        ] {
            let bytes = basis(law, rounding, total, &weights, debit);
            let p = proposal(&bytes, &expected, &[citation(&bytes)]);
            let (proof, checkpoint, digest) = proof(&p, true);
            let verified = verify_allocation_for(&proof, &checkpoint, &digest, &bytes).unwrap();
            assert_eq!(verified.shares, expected);
            assert_eq!(verified.basis.source_debit, debit);
            assert_eq!(verified.driver, citation(&bytes));
            assert_eq!(verified.inclusion.scope, "inclusion");
            assert_eq!(verified.inclusion.record, RecordCheck::Recomputed);
            assert_eq!(verified.basis.targets.len(), weights.len());
        }
    }
}

#[test]
fn all_rounding_laws_keep_their_positive_tie_semantics() {
    for (law, first) in [
        (1, 2),
        (2, 3),
        (3, 3),
        (4, 2),
        (5, 3),
        (6, 2),
        (7, 3),
        (8, 3),
        (9, 2),
    ] {
        let bytes = basis(2, law, 5, &[1, 1], true);
        // The first target receives the signed residual; the second remains
        // independently rounded (3 for up, 2 for down/even on a 2.5 tie).
        assert_eq!(
            AllocationBasis::decode(&bytes).unwrap().shares().unwrap(),
            [first, 5 - first]
        );
    }
}

#[test]
fn generated_pro_rata_matches_a_separate_small_integer_oracle() {
    for total in 1..=31i128 {
        for a in 0..=3u128 {
            for b in 0..=3u128 {
                for c in 0..=3u128 {
                    let weights = [a, b, c];
                    let sum = a + b + c;
                    if sum == 0 {
                        continue;
                    }
                    for law in 1..=9 {
                        let mut expected = weights.map(|weight| {
                            let product = total as u128 * weight;
                            let q = product / sum;
                            let r = product % sum;
                            let increment = r != 0
                                && match law {
                                    1 | 4 => 2 * r >= sum,
                                    2 | 5 => 2 * r > sum,
                                    3 => 2 * r > sum || (2 * r == sum && q % 2 == 1),
                                    6 | 9 => true,
                                    7 | 8 => false,
                                    _ => unreachable!(),
                                };
                            (q + u128::from(increment)) as i128
                        });
                        let residual = total - expected.iter().sum::<i128>();
                        expected[0] += residual;
                        let bytes = basis(2, law, total, &weights, true);
                        assert_eq!(
                            AllocationBasis::decode(&bytes).unwrap().shares().unwrap(),
                            expected,
                            "total={total} weights={weights:?} law={law}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn wide_weights_and_journal_turnover_have_separate_representability_rules() {
    let bytes = basis(1, 0, 7, &[u128::MAX, u128::MAX], true);
    assert_eq!(
        AllocationBasis::decode(&bytes).unwrap().shares().unwrap(),
        [4, 3]
    );
    let bytes = basis(3, 0, i128::MAX, &[u128::MAX, u128::MAX], true);
    assert_eq!(
        AllocationBasis::decode(&bytes).unwrap().shares().unwrap(),
        [i128::MAX, 0]
    );
    let bytes = basis(2, 6, i128::MAX, &[0, 1, 1], true);
    assert_eq!(
        AllocationBasis::decode(&bytes).unwrap().shares(),
        Err(AllocationError::Arithmetic)
    );
    let bytes = basis(1, 0, i128::MAX, &[1, 1], true);
    assert_eq!(
        AllocationBasis::decode(&bytes).unwrap().shares().unwrap(),
        [i128::MAX / 2 + 1, i128::MAX / 2]
    );
}

#[test]
fn repaired_entry_hashes_do_not_validate_balanced_but_wrong_allocations() {
    let bytes = basis(1, 0, 10_000, &[1, 1, 1], true);
    let p = proposal(&bytes, &[3333, 3334, 3333], &[citation(&bytes)]);
    let (proof, checkpoint, digest) = proof(&p, true);
    assert_eq!(
        verify_allocation_for(&proof, &checkpoint, &digest, &bytes),
        Err(AllocationError::LegMismatch { ordinal: 1 })
    );
}

#[test]
fn same_result_different_basis_cannot_substitute_for_recipient_question() {
    let bytes = basis(1, 0, 100, &[1, 1], true);
    let p = proposal(&bytes, &[50, 50], &[citation(&bytes)]);
    let (proof, checkpoint, digest) = proof(&p, true);
    for other in [
        basis(1, 0, 100, &[2, 2], true),
        basis(5, 0, 100, &[1, 1], true),
        basis(1, 0, 100, &[1, 1], false),
    ] {
        assert!(verify_allocation_for(&proof, &checkpoint, &digest, &other).is_err());
    }
    let mut wrong_digest = digest;
    wrong_digest[0] ^= 1;
    assert!(matches!(
        verify_allocation_for(&proof, &checkpoint, &wrong_digest, &bytes),
        Err(AllocationError::Evidence(EvidenceError::EntryMismatch))
    ));
    let mut wrong_checkpoint = checkpoint;
    wrong_checkpoint.root[0] ^= 1;
    assert!(verify_allocation_for(&proof, &wrong_checkpoint, &digest, &bytes).is_err());
}

#[test]
fn cited_driver_role_identity_and_commitment_must_all_match() {
    let bytes = basis(1, 0, 100, &[1, 1], true);
    let good = citation(&bytes);
    let mut wrong_role = good;
    wrong_role.role = 2;
    let mut wrong_identity = good;
    wrong_identity.document_oid[0] ^= 1;
    let wrong_driver = citation(&basis(1, 0, 100, &[2, 2], true));
    for cites in [
        vec![],
        vec![wrong_role],
        vec![wrong_identity],
        vec![wrong_driver],
        vec![good, good],
    ] {
        let p = proposal(&bytes, &[50, 50], &cites);
        let (proof, checkpoint, digest) = proof(&p, true);
        assert!(verify_allocation_for(&proof, &checkpoint, &digest, &bytes).is_err());
    }
}

#[test]
fn repaired_outer_hash_does_not_hide_a_damaged_computation_record() {
    let bytes = basis(1, 0, 100, &[1, 1], true);
    let p = proposal(&bytes, &[50, 50], &[citation(&bytes)]);
    for distance in [1, 32, 33, 64] {
        let mut changed = p.clone();
        let index = changed.len() - distance;
        changed[index] ^= 1;
        let (proof, checkpoint, digest) = proof(&changed, true);
        assert_eq!(
            verify_allocation_for(&proof, &checkpoint, &digest, &bytes),
            Err(AllocationError::BasisMismatch)
        );
    }
    let mut trailing = p;
    trailing.push(0);
    let (proof, checkpoint, digest) = proof(&trailing, true);
    assert!(verify_allocation_for(&proof, &checkpoint, &digest, &bytes).is_err());
}

#[test]
fn missing_records_and_every_truncated_artifact_refuse_without_partial_success() {
    let bytes = basis(1, 0, 7, &[1, 1], true);
    let p = proposal(&bytes, &[4, 3], &[citation(&bytes)]);
    let (full, checkpoint, digest) = proof(&p, true);
    let (bare, _, _) = proof(&p, false);
    assert!(matches!(
        verify_allocation_for(&bare, &checkpoint, &digest, &bytes),
        Err(AllocationError::Evidence(EvidenceError::RecordRequired))
    ));
    for end in 0..full.len() {
        assert!(verify_allocation_for(&full[..end], &checkpoint, &digest, &bytes).is_err());
    }
    for end in 0..bytes.len() {
        assert!(AllocationBasis::decode(&bytes[..end]).is_err());
    }
}

#[test]
fn driver_bounds_and_noncanonical_requests_fail_closed() {
    for bytes in [
        basis(4, 0, 10, &[1, 1], true),
        basis(6, 0, 10, &[1, 1], true),
        basis(1, 0, 0, &[1, 1], true),
        basis(1, 0, -1, &[1, 1], true),
        basis(1, 0, 1, &[], true),
        basis(2, 0, 1, &[1], true),
        basis(5, 0, 1, &[0, 1], true),
        basis(1, 0, 1, &vec![1; MAX_TARGETS + 1], true),
    ] {
        assert!(AllocationBasis::decode(&bytes).is_err());
    }
    let bytes = basis(1, 0, 1024, &vec![1; MAX_TARGETS], true);
    assert_eq!(
        AllocationBasis::decode(&bytes).unwrap().shares().unwrap(),
        vec![1; MAX_TARGETS]
    );
    let mut trailing = basis(1, 0, 7, &[1], true);
    trailing.push(0);
    assert!(AllocationBasis::decode(&trailing).is_err());
    let mut duplicate = basis(1, 0, 7, &[1, 1], true);
    // Basis prefix is 42 bytes, ordinary request prefix is 49 bytes.
    duplicate[42 + 49 + 32..42 + 49 + 48].copy_from_slice(&20u128.to_le_bytes());
    assert!(AllocationBasis::decode(&duplicate).is_err());
    assert!(AllocationBasis::decode(&vec![0; MAX_BASIS_BYTES + 1]).is_err());
}

#[test]
fn public_basis_values_are_revalidated_before_arithmetic() {
    let bytes = basis(1, 0, 7, &[1, 1], true);
    let valid = AllocationBasis::decode(&bytes).unwrap();
    let mut changed = valid.clone();
    changed.law = 4;
    assert!(changed.shares().is_err());
    let mut changed = valid.clone();
    changed.recipient = Some(20);
    assert!(changed.shares().is_err());
    let mut changed = valid.clone();
    changed.dimensions = vec![(1, 2), (1, 3)];
    assert!(changed.shares().is_err());
    let mut changed = valid;
    changed.targets[0].account = changed.source;
    assert!(changed.shares().is_err());
}

fn write_dimensions(w: &mut Writer, dimensions: &[(u32, u128)]) {
    w.count(dimensions.len());
    for (dimension, value) in dimensions {
        w.u32(*dimension).u128(*value);
    }
}

fn dimensional_basis(
    law: u16,
    rounding: u16,
    total: i128,
    weights: &[u128],
    cells: &[(u128, Vec<(u32, u128)>)],
    source_debit: bool,
) -> Vec<u8> {
    assert_eq!(weights.len(), cells.len());
    let ids: Vec<_> = cells
        .iter()
        .map(|(account, dimensions)| {
            let mut w = Writer::default();
            w.u128(*account);
            write_dimensions(&mut w, dimensions);
            let digest = hash_parts(
                b"fa:allocation-target:v2",
                &[&(w.buf.len() as u32).to_le_bytes(), &w.buf],
            );
            u128::from_le_bytes(digest[..16].try_into().unwrap())
        })
        .collect();
    let mut request = Writer::default();
    request
        .fixed(b"FA-ALLOC-REQUEST\0")
        .u16(1)
        .u16(0)
        .u16(law)
        .u16(1)
        .u32(1)
        .i128(total);
    if law == 2 {
        request.u16(rounding).u128(ids[0]);
    }
    request.count(weights.len());
    for (id, weight) in ids.iter().zip(weights) {
        request.u128(*id).u128(*weight);
    }
    let mut w = Writer::default();
    w.fixed(b"FA-ALLOC-BASIS\0")
        .u16(2)
        .u128(10)
        .u8(u8::from(!source_debit));
    write_dimensions(&mut w, &[(2, 100)]);
    w.bytes(&request.buf).count(cells.len());
    for (account, dimensions) in cells {
        w.u128(*account);
        write_dimensions(&mut w, dimensions);
    }
    w.buf
}

#[test]
fn dimensional_allocations_keep_same_account_cells_zero_shares_and_signed_residuals() {
    for source_debit in [true, false] {
        for (law, rounding, total, weights, expected) in [
            (1, 0, 100, vec![3, 2], vec![60, 40]),
            (2, 6, 1, vec![1, 1, 1], vec![-1, 1, 1]),
            (3, 0, 10, vec![4, 0, 9], vec![4, 0, 6]),
            (5, 0, 2, vec![1; 5], vec![2, 0, 0, 0, 0]),
        ] {
            let cells: Vec<_> = (0..weights.len())
                .map(|index| (10, vec![(2, 101 + index as u128)]))
                .collect();
            let bytes = dimensional_basis(law, rounding, total, &weights, &cells, source_debit);
            let p = proposal(&bytes, &expected, &[citation(&bytes)]);
            let (full, checkpoint, digest) = proof(&p, true);
            let verified = verify_allocation_for(&full, &checkpoint, &digest, &bytes).unwrap();
            assert_eq!(verified.shares, expected);
            assert_eq!(verified.basis.version(), 2);
            assert_eq!(verified.basis.target_cells.len(), cells.len());
            for (index, cell) in cells.iter().enumerate() {
                assert_eq!(
                    verified.basis.target_cell(index),
                    Some((cell.0, cell.1.as_slice()))
                );
            }
        }
    }
}

#[test]
fn dimension_only_entry_changes_refuse_even_after_repairing_outer_hashes() {
    let cells = vec![(10, vec![(2, 101)]), (10, vec![(2, 102)])];
    let bytes = dimensional_basis(1, 0, 100, &[3, 2], &cells, false);
    let mut p = proposal(&bytes, &[60, 40], &[citation(&bytes)]);
    // First occurrence is the first destination leg, before any record/citation.
    let value = 101u128.to_le_bytes();
    let offset = p
        .windows(value.len())
        .position(|window| window == value.as_slice())
        .unwrap();
    p[offset..offset + value.len()].copy_from_slice(&102u128.to_le_bytes());
    let (full, checkpoint, digest) = proof(&p, true);
    assert_eq!(
        verify_allocation_for(&full, &checkpoint, &digest, &bytes),
        Err(AllocationError::LegMismatch { ordinal: 1 })
    );
}

#[test]
fn cell_order_identity_and_exact_source_exclusion_are_independently_checked() {
    let cells = vec![(10, vec![(2, 101)]), (10, vec![(2, 102)])];
    let bytes = dimensional_basis(1, 0, 100, &[3, 2], &cells, false);
    // One source dimension makes the request begin at byte 62. Law 1 has a
    // 49-byte header; each target is 32 bytes. The cell list follows it.
    let first_id = 62 + 49;
    let first_cell = 62 + 49 + 2 * 32 + 4;
    let mut changed = bytes.clone();
    changed[first_id] ^= 1;
    assert!(AllocationBasis::decode(&changed).is_err());
    let mut changed = bytes.clone();
    let first = changed[first_cell..first_cell + 40].to_vec();
    let second = changed[first_cell + 40..first_cell + 80].to_vec();
    changed[first_cell..first_cell + 40].copy_from_slice(&second);
    changed[first_cell + 40..first_cell + 80].copy_from_slice(&first);
    assert!(AllocationBasis::decode(&changed).is_err());
    for cells in [
        vec![(10, vec![(2, 101)]), (10, vec![(2, 101)])],
        vec![(10, vec![(2, 100)]), (10, vec![(2, 102)])],
        vec![(10, vec![(3, 1), (2, 2)]), (10, vec![(2, 102)])],
        vec![(10, vec![(2, 1), (2, 2)]), (10, vec![(2, 102)])],
    ] {
        assert!(
            AllocationBasis::decode(&dimensional_basis(1, 0, 100, &[3, 2], &cells, false)).is_err()
        );
    }
}

#[test]
fn changed_destination_basis_cannot_replace_the_recipient_expectation() {
    let cells = vec![(10, vec![(2, 101)]), (10, vec![(2, 102)])];
    let bytes = dimensional_basis(1, 0, 100, &[3, 2], &cells, false);
    let p = proposal(&bytes, &[60, 40], &[citation(&bytes)]);
    let (full, checkpoint, digest) = proof(&p, true);
    let changed = dimensional_basis(
        1,
        0,
        100,
        &[3, 2],
        &[(10, vec![(2, 103)]), (10, vec![(2, 102)])],
        false,
    );
    assert_eq!(
        AllocationBasis::decode(&changed).unwrap().shares().unwrap(),
        [60, 40]
    );
    assert!(verify_allocation_for(&full, &checkpoint, &digest, &changed).is_err());
}

#[test]
fn v2_framing_bounds_and_record_version_are_checked() {
    let cells = vec![(10, vec![(2, 101)]), (10, vec![(2, 102)])];
    let bytes = dimensional_basis(1, 0, 100, &[3, 2], &cells, false);
    for end in 0..bytes.len() {
        assert!(AllocationBasis::decode(&bytes[..end]).is_err());
    }
    let mut changed = bytes.clone();
    changed[15..17].copy_from_slice(&3u16.to_le_bytes());
    assert!(AllocationBasis::decode(&changed).is_err());
    let cell_count = 62 + 49 + 2 * 32;
    for count in [0u32, 1, 3, 1025] {
        let mut changed = bytes.clone();
        changed[cell_count..cell_count + 4].copy_from_slice(&count.to_le_bytes());
        assert!(AllocationBasis::decode(&changed).is_err());
    }
    let mut changed = bytes.clone();
    let dimension_count = cell_count + 4 + 16;
    changed[dimension_count..dimension_count + 4].copy_from_slice(&65u32.to_le_bytes());
    assert!(AllocationBasis::decode(&changed).is_err());
    let mut changed = bytes.clone();
    changed.push(0);
    assert!(AllocationBasis::decode(&changed).is_err());
    let p = proposal(&bytes, &[60, 40], &[citation(&bytes)]);
    let marker = b"FA-ALLOC-POST\0";
    let offset = p
        .windows(marker.len())
        .position(|window| window == marker.as_slice())
        .unwrap();
    for version in [1u16, 3] {
        let mut changed = p.clone();
        changed[offset + marker.len()..offset + marker.len() + 2]
            .copy_from_slice(&version.to_le_bytes());
        let (full, checkpoint, digest) = proof(&changed, true);
        assert_eq!(
            verify_allocation_for(&full, &checkpoint, &digest, &bytes),
            Err(AllocationError::BasisMismatch)
        );
    }
    let mut changed = p;
    let wrong_digest = basis_digest(1, &bytes);
    let end = changed.len();
    changed[end - 32..].copy_from_slice(&wrong_digest);
    let (full, checkpoint, digest) = proof(&changed, true);
    assert_eq!(
        verify_allocation_for(&full, &checkpoint, &digest, &bytes),
        Err(AllocationError::BasisMismatch)
    );
}

#[test]
fn modified_public_v2_cells_are_revalidated_before_arithmetic() {
    let cells = vec![(10, vec![(2, 101)]), (10, vec![(2, 102)])];
    let bytes = dimensional_basis(1, 0, 100, &[3, 2], &cells, false);
    let valid = AllocationBasis::decode(&bytes).unwrap();
    let mut changed = valid.clone();
    changed.target_cells[0].dimensions[0].1 = 103;
    assert!(changed.shares().is_err());
    let mut changed = valid.clone();
    changed.target_cells.pop();
    assert!(changed.shares().is_err());
    let mut changed = valid.clone();
    changed.targets[0].account ^= 1;
    assert!(changed.shares().is_err());
    let mut changed = valid;
    changed.dimensions = vec![(2, 101)];
    assert!(changed.shares().is_err());
}

#[test]
fn legacy_driver_identity_and_shared_cell_interpretation_remain_unchanged() {
    let bytes = basis(1, 0, 7, &[1, 1], true);
    let p = proposal(&bytes, &[4, 3], &[citation(&bytes)]);
    let (full, checkpoint, digest) = proof(&p, true);
    let verified = verify_allocation_for(&full, &checkpoint, &digest, &bytes).unwrap();
    assert_eq!(verified.basis.version(), 1);
    assert!(verified.basis.target_cells.is_empty());
    assert_eq!(verified.basis.target_cell(0), Some((20, &[][..])));
    assert_eq!(
        verified.basis_digest,
        hash_parts(
            b"fa:allocation-basis:v1",
            &[&(bytes.len() as u32).to_le_bytes(), &bytes],
        )
    );
}
