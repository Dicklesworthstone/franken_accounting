use super::*;
use fa_money::allocation::{AllocationMethod, AllocationTarget};
use fa_money::{RoundingLaw, UnitId};

fn basis(total: i128, method: AllocationMethod, weights: &[u128]) -> AllocationPosting {
    AllocationPosting {
        source: VId(10),
        source_side: Side::Credit,
        dimensions: Vec::new(),
        request: AllocationRequest {
            total: Amount::new(UnitId(7), total),
            method,
            targets: weights
                .iter()
                .enumerate()
                .map(|(index, weight)| AllocationTarget {
                    id: 11 + index as u128,
                    basis: *weight,
                })
                .collect(),
        },
    }
}

#[test]
fn explicit_native_allocation_constructs_the_exact_source_and_target_vector() {
    let basis = basis(10_000, AllocationMethod::LargestRemainder, &[1; 3]);
    let outcome = basis.request.execute().unwrap();
    let legs = basis.legs(&outcome).unwrap();
    assert_eq!(
        legs.iter()
            .map(|leg| (leg.account_ref.0, side_tag(leg.side), leg.amount.mantissa))
            .collect::<Vec<_>>(),
        [(10, 1, 10_000), (11, 0, 3334), (12, 0, 3333), (13, 0, 3333)]
    );
    let totals = EntryPayload::fold_unit_totals(&legs).unwrap();
    assert_eq!(totals.len(), 1);
    assert_eq!((totals[0].debits, totals[0].credits), (10_000, 10_000));
    assert!(
        legs.iter()
            .all(|leg| leg.settles.is_empty() && leg.base_amount.is_none())
    );
}

#[test]
fn zero_shares_stay_in_the_driver_without_zero_valued_postings() {
    let basis = basis(2, AllocationMethod::EqualSplitResidualFirst, &[1; 5]);
    let legs = basis.legs(&basis.request.execute().unwrap()).unwrap();
    assert_eq!(legs.len(), 2);
    assert_eq!(legs[1].account_ref, VId(11));
    assert!(legs.iter().all(|leg| leg.amount.mantissa > 0));
    let decoded = AllocationPosting::decode_record(&basis.record_bytes().unwrap()).unwrap();
    assert_eq!(decoded.request.targets.len(), 5);
    assert_eq!(decoded, basis);
}

#[test]
fn signed_rounding_corrections_change_side_not_the_total_or_the_recipient() {
    let mut basis = basis(
        1,
        AllocationMethod::ProRataResidualToNamed {
            rounding: RoundingLaw::Ceiling,
            recipient: 12,
        },
        &[1; 3],
    );
    for source_side in [Side::Debit, Side::Credit] {
        basis.source_side = source_side;
        let legs = basis.legs(&basis.request.execute().unwrap()).unwrap();
        assert_eq!(legs[0].side, source_side);
        assert_eq!(legs[1].side, opposite(source_side));
        assert_eq!(legs[2].side, source_side);
        assert_eq!(legs[2].account_ref, VId(12));
        assert_eq!(legs[3].side, opposite(source_side));
        assert!(
            legs.iter()
                .all(|leg| leg.amount == Amount::new(UnitId(7), 1))
        );
        let total = EntryPayload::fold_unit_totals(&legs).unwrap();
        assert_eq!((total[0].debits, total[0].credits), (2, 2));
    }
}

#[test]
fn driver_commitment_is_book_scoped_and_sensitive_to_every_basis_choice() {
    let basis = basis(10_000, AllocationMethod::LargestRemainder, &[1; 3]);
    let book = Id128([1; 16]);
    let expected = basis.driver_evidence(book).unwrap();
    assert_eq!(
        expected.doc_commit,
        doc_commit(21, &basis.basis_bytes().unwrap())
    );
    assert_eq!(expected.role, 1);
    let other = basis.driver_evidence(Id128([2; 16])).unwrap();
    assert_ne!(expected.document_oid, other.document_oid);
    assert_eq!(expected.doc_commit, other.doc_commit);
    let mut changed = basis.clone();
    changed.request.targets.swap(0, 1);
    assert_ne!(expected, changed.driver_evidence(book).unwrap());
    changed = basis.clone();
    changed.source_side = Side::Debit;
    assert_ne!(expected, changed.driver_evidence(book).unwrap());
    changed = basis.clone();
    changed.dimensions = vec![(1, VId(55))];
    assert_ne!(expected, changed.driver_evidence(book).unwrap());
    changed = basis.clone();
    changed.request.targets[0].basis = 2;
    assert_ne!(
        basis.basis_digest().unwrap(),
        changed.basis_digest().unwrap()
    );
    assert_eq!(basis.law_digest(), changed.law_digest());
    changed.request.method = AllocationMethod::Waterfall;
    assert_ne!(basis.law_digest(), changed.law_digest());
}

#[test]
fn record_roundtrips_and_rejects_every_truncation_and_digest_mutation() {
    let basis = basis(7, AllocationMethod::LargestRemainder, &[1, 0, 2]);
    let bytes = basis.record_bytes().unwrap();
    assert_eq!(AllocationPosting::decode_record(&bytes).unwrap(), basis);
    for cut in 0..bytes.len() {
        assert!(
            AllocationPosting::decode_record(&bytes[..cut]).is_err(),
            "cut {cut}"
        );
    }
    for index in bytes.len() - 64..bytes.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        assert!(
            AllocationPosting::decode_record(&changed).is_err(),
            "digest byte {index}"
        );
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(AllocationPosting::decode_record(&trailing).is_err());
}

#[test]
fn posting_scope_refuses_invalid_targets_dimensions_totals_and_versions() {
    let original = basis(7, AllocationMethod::LargestRemainder, &[1; 3]);
    for total in [0, -1, i128::MIN] {
        let mut bad = original.clone();
        bad.request.total.mantissa = total;
        assert!(bad.basis_bytes().is_err());
    }
    let mut bad = original.clone();
    bad.source = VId(11);
    assert!(bad.basis_bytes().is_err());
    let mut bad = original.clone();
    bad.request.targets[1].id = 11;
    assert!(bad.basis_bytes().is_err());
    for dimensions in [
        vec![(1, VId(1)), (1, VId(2))],
        vec![(2, VId(2)), (1, VId(1))],
    ] {
        let mut bad = original.clone();
        bad.dimensions = dimensions;
        assert!(bad.basis_bytes().is_err());
    }
    assert!(
        basis(
            7,
            AllocationMethod::LargestRemainder,
            &vec![1; MAX_POSTING_TARGETS + 1]
        )
        .basis_bytes()
        .is_err()
    );
    let mut bytes = original.basis_bytes().unwrap();
    bytes[15..17].copy_from_slice(&2u16.to_le_bytes());
    assert!(AllocationPosting::decode_basis(&bytes).is_err());
    let mut bytes = original.basis_bytes().unwrap();
    bytes[33] = 2;
    assert!(AllocationPosting::decode_basis(&bytes).is_err());
    assert!(AllocationPosting::decode_record(&vec![0; MAX_EXTENSION_BYTES + 1]).is_err());
}

#[test]
fn maximum_posting_basis_fits_the_existing_entry_extension_limit() {
    let mut basis = basis(
        i128::MAX,
        AllocationMethod::LargestRemainder,
        &vec![u128::MAX; MAX_POSTING_TARGETS],
    );
    basis.dimensions = (0..64).map(|id| (id, VId(u128::from(id) + 1))).collect();
    let encoded = basis.record_bytes().unwrap();
    assert!(encoded.len() < MAX_EXTENSION_BYTES);
    assert_eq!(AllocationPosting::decode_record(&encoded).unwrap(), basis);
    let legs = basis.legs(&basis.request.execute().unwrap()).unwrap();
    assert_eq!(legs.len(), MAX_POSTING_TARGETS + 1);
    assert!(legs.iter().all(|leg| leg.dimension_set == basis.dimensions));
    let total = EntryPayload::fold_unit_totals(&legs).unwrap();
    assert_eq!((total[0].debits, total[0].credits), (i128::MAX, i128::MAX));
}

#[test]
fn schema_registry_matches_the_live_posting_format() {
    let schema = fa_registry::toml::parse(include_str!(
        "../../../../registries/object_schemas/allocation.toml"
    ))
    .unwrap();
    let integer = |name| {
        schema
            .root
            .get(name)
            .and_then(fa_registry::toml::Value::as_int)
            .unwrap()
    };
    assert_eq!(
        integer("entry_extension_tag"),
        i128::from(ALLOCATION_EXTENSION)
    );
    assert_eq!(
        integer("entry_schema_minor"),
        i128::from(ALLOCATION_SCHEMA_MINOR)
    );
    // A writer seals only the minors it knows (fa-hoi5): the posting rides a
    // tag the entry model registers at that minor, never a newer minor's
    // unknown tag.
    assert!(integer("entry_schema_minor") <= i128::from(fa_model::entry::SCHEMA_MINOR));
    assert!(fa_model::entry::KNOWN_EXTENSION_TAGS.contains(&ALLOCATION_EXTENSION));
    assert_eq!(integer("max_targets"), MAX_POSTING_TARGETS as i128);
    assert_eq!(
        integer("document_kind"),
        i128::from(ALLOCATION_DOCUMENT_KIND)
    );
    assert_eq!(
        integer("evidence_role"),
        i128::from(ALLOCATION_EVIDENCE_ROLE)
    );
}

#[test]
fn canonical_driver_matches_an_independent_binary_layout_vector() {
    let basis = basis(10_000, AllocationMethod::LargestRemainder, &[1; 3]);
    let expected = concat!(
        "46412d414c4c4f432d42415349530001000a0000000000000000000000000000",
        "0001000000009100000046412d414c4c4f432d52455155455354000100000001",
        "0001000700000010270000000000000000000000000000030000000b00000000",
        "0000000000000000000000010000000000000000000000000000000c00000000",
        "0000000000000000000000010000000000000000000000000000000d00000000",
        "000000000000000000000001000000000000000000000000000000",
    );
    let bytes: Vec<u8> = expected
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    assert_eq!(basis.basis_bytes().unwrap(), bytes);
    assert_eq!(AllocationPosting::decode_basis(&bytes).unwrap(), basis);
}

#[test]
fn journal_turnover_overflow_is_refused_even_when_signed_allocation_conserves() {
    let basis = basis(
        i128::MAX,
        AllocationMethod::ProRataResidualToNamed {
            rounding: RoundingLaw::Ceiling,
            recipient: 11,
        },
        &[0, 1, 1],
    );
    let result = basis.request.execute().unwrap();
    assert_eq!(result.shares()[0].mantissa, -1);
    let legs = basis.legs(&result).unwrap();
    assert!(matches!(
        EntryPayload::fold_unit_totals(&legs),
        Err(fa_model::EntryError::Overflow)
    ));
    // proposal() uses this same checked fold before returning any EntryPayload.
}
