use super::*;
use fa_money::allocation::{AllocationMethod, AllocationTarget};
use fa_money::{RoundingLaw, UnitId};

fn cells(total: i128, weights: &[u128]) -> AllocationPosting {
    let target_cells: Vec<_> = weights
        .iter()
        .enumerate()
        .map(|(index, _)| AllocationTargetCell {
            account: VId(10),
            dimensions: vec![(7, VId(200 + index as u128))],
        })
        .collect();
    AllocationPosting {
        source: VId(10),
        source_side: Side::Credit,
        dimensions: vec![(7, VId(100))],
        request: AllocationRequest {
            total: Amount::new(UnitId(7), total),
            method: AllocationMethod::LargestRemainder,
            targets: target_cells
                .iter()
                .zip(weights)
                .map(|(cell, weight)| AllocationTarget {
                    id: cell.identity().unwrap(),
                    basis: *weight,
                })
                .collect(),
        },
        target_cells,
    }
}

#[test]
fn same_account_destinations_keep_separate_dimensions_and_balanced_amounts() {
    let basis = cells(100, &[3, 2]);
    let legs = basis.legs(&basis.request.execute().unwrap()).unwrap();
    assert_eq!(legs.len(), 3);
    assert!(legs.iter().all(|leg| leg.account_ref == VId(10)));
    assert_eq!(
        legs.iter()
            .map(|leg| (
                side_tag(leg.side),
                leg.amount.mantissa,
                leg.dimension_set.clone()
            ))
            .collect::<Vec<_>>(),
        [
            (1, 100, vec![(7, VId(100))]),
            (0, 60, vec![(7, VId(200))]),
            (0, 40, vec![(7, VId(201))]),
        ]
    );
    let totals = EntryPayload::fold_unit_totals(&legs).unwrap();
    assert_eq!((totals[0].debits, totals[0].credits), (100, 100));
    assert_eq!(basis.target_cell(1).unwrap(), basis.target_cells[1]);
    assert!(basis.target_cell(2).is_err());
}

#[test]
fn cell_record_roundtrips_and_refuses_truncation_tampering_and_mixed_versions() {
    let basis = cells(7, &[1, 0, 2]);
    let encoded = basis.basis_bytes().unwrap();
    assert_eq!(&encoded[15..17], &2_u16.to_le_bytes());
    assert_eq!(AllocationPosting::decode_basis(&encoded).unwrap(), basis);
    let record = basis.record_bytes().unwrap();
    assert_eq!(&record[14..16], &2_u16.to_le_bytes());
    assert_eq!(AllocationPosting::decode_record(&record).unwrap(), basis);
    for cut in 0..record.len() {
        assert!(
            AllocationPosting::decode_record(&record[..cut]).is_err(),
            "cut {cut}"
        );
    }
    // A destination's dimension is covered by the cell identity, then by the
    // driver commitment. Altering only that value must refuse at decode time.
    let mut changed = encoded.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(AllocationPosting::decode_basis(&changed).is_err());
    let mut changed = record.clone();
    changed[14..16].copy_from_slice(&1_u16.to_le_bytes());
    assert!(AllocationPosting::decode_record(&changed).is_err());
    let mut changed = record.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(AllocationPosting::decode_record(&changed).is_err());
    let mut trailing = record;
    trailing.push(0);
    assert!(AllocationPosting::decode_record(&trailing).is_err());
    let mut unknown = encoded;
    unknown[15..17].copy_from_slice(&3_u16.to_le_bytes());
    assert!(AllocationPosting::decode_basis(&unknown).is_err());
}

#[test]
fn cell_identity_and_driver_bind_destinations_even_when_amounts_are_unchanged() {
    let basis = cells(100, &[3, 2]);
    let mut changed = basis.clone();
    changed.target_cells[0].dimensions[0].1 = VId(999);
    assert!(changed.basis_bytes().is_err());
    changed.request.targets[0].id = changed.target_cells[0].identity().unwrap();
    assert_eq!(
        basis.request.execute().unwrap().shares(),
        changed.request.execute().unwrap().shares()
    );
    assert_ne!(
        basis.basis_digest().unwrap(),
        changed.basis_digest().unwrap()
    );
    assert_ne!(
        basis.driver_evidence(Id128([1; 16])).unwrap(),
        changed.driver_evidence(Id128([1; 16])).unwrap()
    );
    assert_eq!(basis.law_digest(), changed.law_digest());
    let mut reordered = basis.clone();
    reordered.target_cells.swap(0, 1);
    assert!(reordered.basis_bytes().is_err());
}

#[test]
fn duplicate_source_missing_and_noncanonical_destination_cells_refuse() {
    let basis = cells(100, &[3, 2]);
    let mut duplicate = basis.clone();
    duplicate.target_cells[1] = duplicate.target_cells[0].clone();
    duplicate.request.targets[1].id = duplicate.target_cells[1].identity().unwrap();
    assert!(duplicate.basis_bytes().is_err());

    let mut source = basis.clone();
    source.target_cells[0].dimensions = source.dimensions.clone();
    source.request.targets[0].id = source.target_cells[0].identity().unwrap();
    assert!(source.basis_bytes().is_err());

    let mut missing = basis.clone();
    missing.target_cells.pop();
    assert!(missing.basis_bytes().is_err());

    for dimensions in [
        vec![(7, VId(1)), (7, VId(2))],
        vec![(8, VId(1)), (7, VId(2))],
    ] {
        let cell = AllocationTargetCell {
            account: VId(10),
            dimensions,
        };
        assert!(cell.identity().is_err());
    }
    let mut excessive = basis.target_cells[0].clone();
    excessive.dimensions = (0..=MAX_DIMENSIONS_PER_LEG)
        .map(|id| (id as u32, VId(id as u128)))
        .collect();
    assert!(excessive.identity().is_err());
}

#[test]
fn zero_shares_and_signed_residuals_preserve_their_declared_cells() {
    let mut zero = cells(2, &[1; 5]);
    zero.request.method = AllocationMethod::EqualSplitResidualFirst;
    let legs = zero.legs(&zero.request.execute().unwrap()).unwrap();
    assert_eq!(legs.len(), 2);
    assert_eq!(legs[1].dimension_set, zero.target_cells[0].dimensions);
    let decoded = AllocationPosting::decode_record(&zero.record_bytes().unwrap()).unwrap();
    assert_eq!(decoded.target_cells.len(), 5);
    assert_eq!(decoded, zero);

    let mut signed = cells(1, &[1; 3]);
    signed.request.method = AllocationMethod::ProRataResidualToNamed {
        rounding: RoundingLaw::Ceiling,
        recipient: signed.target_cells[1].identity().unwrap(),
    };
    for source_side in [Side::Credit, Side::Debit] {
        signed.source_side = source_side;
        let legs = signed.legs(&signed.request.execute().unwrap()).unwrap();
        assert_eq!(legs.len(), 4);
        assert_eq!(legs[2].side, source_side);
        assert_eq!(legs[2].dimension_set, signed.target_cells[1].dimensions);
        assert_eq!(legs[2].amount.mantissa, 1);
        let totals = EntryPayload::fold_unit_totals(&legs).unwrap();
        assert_eq!((totals[0].debits, totals[0].credits), (2, 2));
    }
}

#[test]
fn target_cells_still_fit_the_existing_extension_budget_or_refuse() {
    let mut basis = cells(100, &vec![1; MAX_POSTING_TARGETS]);
    for (index, cell) in basis.target_cells.iter_mut().enumerate() {
        cell.dimensions = (0..MAX_DIMENSIONS_PER_LEG)
            .map(|kind| (kind as u32, VId(1000 + index as u128)))
            .collect();
        basis.request.targets[index].id = cell.identity().unwrap();
    }
    assert!(basis.basis_bytes().is_err());
}
