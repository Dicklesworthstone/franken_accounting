use super::*;

fn batch() -> ExternalSubledgerBatch {
    ExternalSubledgerBatch {
        book_id: Id128([1; 16]),
        feed: "ap-system".into(),
        batch_key: "2026-03-15.001".into(),
        effective_date: DateDay::from_ymd(2026, 3, 15).unwrap(),
        rows: vec![
            ExternalSubledgerDetail {
                source_digest: [1; 32],
                account: VId(10),
                side: Side::Debit,
                amount: Amount::new(UnitId(1), 40),
                dimensions: vec![],
            },
            ExternalSubledgerDetail {
                source_digest: [2; 32],
                account: VId(10),
                side: Side::Debit,
                amount: Amount::new(UnitId(1), 60),
                dimensions: vec![],
            },
            ExternalSubledgerDetail {
                source_digest: [3; 32],
                account: VId(20),
                side: Side::Credit,
                amount: Amount::new(UnitId(1), 100),
                dimensions: vec![],
            },
        ],
    }
}

#[test]
fn canonical_detail_round_trips_and_binds_coordinate_and_each_source_row() {
    let detail = batch();
    let bytes = detail.canonical_bytes().unwrap();
    assert_eq!(ExternalSubledgerBatch::decode(&bytes).unwrap(), detail);
    let evidence = detail.evidence().unwrap();
    assert_eq!(
        evidence.doc_commit,
        doc_commit(EXTERNAL_SUBLEDGER_DOCUMENT_KIND, &bytes)
    );
    let mut changed = detail.clone();
    changed.rows[0].source_digest = [0; 32];
    assert!(changed.canonical_bytes().is_err());
    let mut changed = detail.clone();
    changed.rows[1].source_digest = changed.rows[0].source_digest;
    assert!(changed.canonical_bytes().is_err());
    let mut changed = detail.clone();
    changed.effective_date.0 += 1;
    assert_ne!(changed.evidence().unwrap(), evidence);
    let mut changed = detail.clone();
    changed.rows[0].amount.mantissa += 1;
    assert_ne!(changed.evidence().unwrap(), evidence);
    let mut trailing = bytes;
    trailing.push(0);
    assert!(ExternalSubledgerBatch::decode(&trailing).is_err());
}

#[test]
fn gross_folding_preserves_opposing_sides_and_party_dimensions() {
    let mut detail = batch();
    detail.rows[1].side = Side::Credit;
    detail.rows[1].amount.mantissa = 40;
    detail.rows[2].dimensions = vec![(fa_model::PARTY_DIMENSION, VId(90))];
    let legs = detail.summary_legs().unwrap();
    assert_eq!(legs.len(), 3);
    assert_eq!(legs[0].amount.mantissa, 40);
    assert_eq!(legs[1].amount.mantissa, 40);
    assert_ne!(legs[0].side, legs[1].side);
    assert_eq!(
        legs[2].dimension_set,
        vec![(fa_model::PARTY_DIMENSION, VId(90))]
    );
    detail.rows.push(ExternalSubledgerDetail {
        source_digest: [4; 32],
        account: VId(20),
        side: Side::Credit,
        amount: Amount::new(UnitId(1), 25),
        dimensions: vec![(fa_model::PARTY_DIMENSION, VId(91))],
    });
    assert_eq!(detail.summary_legs().unwrap().len(), 4);
}

#[test]
fn gross_column_overflow_refuses_even_if_the_signed_net_would_fit() {
    let mut detail = batch();
    detail.rows[0].amount.mantissa = i128::MAX;
    detail.rows[1].amount.mantissa = 1;
    detail.rows[2].account = VId(10);
    detail.rows[2].amount.mantissa = i128::MAX;
    assert!(
        detail
            .summary_legs()
            .unwrap_err()
            .message
            .contains("overflows")
    );
}

#[test]
fn source_batch_identity_is_independent_of_contents_and_unambiguous() {
    let mut original = batch();
    let mut changed = original.clone();
    changed.rows[0].amount.mantissa += 1;
    assert_eq!(original.identity(), changed.identity());
    assert_ne!(original.evidence().unwrap(), changed.evidence().unwrap());
    original.feed = "ab".into();
    original.batch_key = "c".into();
    changed.feed = "a".into();
    changed.batch_key = "bc".into();
    assert_ne!(original.identity(), changed.identity());
    changed = original.clone();
    changed.book_id = Id128([2; 16]);
    assert_ne!(original.identity(), changed.identity());
}

#[test]
fn detail_fold_agrees_with_independent_limb_oracle_over_grouped_histories() {
    use fa_reference::external_subledger::{Column, Detail, summarize};
    for case in 0_u32..96 {
        let mut detail = batch();
        detail.rows.clear();
        for index in 0_u32..(2 + case % 80) {
            let mut source = [0; 32];
            source[28..].copy_from_slice(&(index + 1).to_be_bytes());
            detail.rows.push(ExternalSubledgerDetail {
                source_digest: source,
                account: VId(u128::from(10 + (index + case) % 4)),
                side: if index % 3 == 0 {
                    Side::Debit
                } else {
                    Side::Credit
                },
                amount: Amount::new(
                    UnitId(1 + index % 2),
                    if case % 11 == 0 {
                        i128::MAX
                    } else {
                        i128::from(1 + index * 37 + case)
                    },
                ),
                dimensions: if case % 2 == 0 {
                    vec![]
                } else {
                    vec![(2, VId(u128::from(90 + index % 2)))]
                },
            });
        }
        let input: Vec<_> = detail
            .rows
            .iter()
            .map(|row| Detail {
                source: row.source_digest,
                account: row.account.0,
                unit: row.amount.unit.0,
                credit: row.side == Side::Credit,
                amount: row.amount.mantissa,
                dimensions: row
                    .dimensions
                    .iter()
                    .map(|(kind, value)| (*kind, value.0))
                    .collect(),
            })
            .collect();
        let expected = summarize(&input);
        let actual = detail.summary_legs().map(|legs| {
            legs.into_iter()
                .map(|leg| Column {
                    account: leg.account_ref.0,
                    unit: leg.amount.unit.0,
                    dimensions: leg
                        .dimension_set
                        .into_iter()
                        .map(|(kind, value)| (kind, value.0))
                        .collect(),
                    credit: leg.side == Side::Credit,
                    amount: leg.amount.mantissa,
                })
                .collect::<Vec<_>>()
        });
        assert_eq!(actual.is_ok(), expected.is_ok(), "case {case}");
        if let (Ok(actual), Ok(expected)) = (actual, expected) {
            assert_eq!(actual, expected, "case {case}");
        }
    }
}

#[test]
fn identity_join_searches_large_selected_populations_without_a_second_index() {
    for count in [16_usize, 1_024, 100_000] {
        let rows: Vec<_> = (0..count)
            .map(|index| VertexRow {
                vid: VId(2 * index as u128 + 2),
                birth_ordinal: index as u64,
                created_at: CommitSeq(1),
                retired_at: None,
                labels: vec![],
                props: vec![],
            })
            .collect();
        let mut queries = vec![VId(0), VId(2), VId(2 * count as u128), VId(u128::MAX)];
        queries.extend((0..128).map(|index| VId((index * 7_919) % (2 * count as u128 + 3))));
        let mut work = ExternalSubledgerVerificationWork::default();
        let mut literal_comparisons = 0;
        for target in &queries {
            let expected = rows.iter().find(|row| {
                literal_comparisons += 1;
                row.vid == *target
            });
            assert_eq!(identity_row(&rows, *target, &mut work), expected);
        }
        assert!(
            work.identity_row_comparisons <= queries.len() * (count.ilog2() as usize + 2),
            "count={count}, work={work:?}"
        );
        if count == 100_000 {
            assert!(literal_comparisons > work.identity_row_comparisons * 1_000);
        }
        assert_eq!(work.review_edge_point_reads, 0);
    }
    let mut work = ExternalSubledgerVerificationWork::default();
    assert!(identity_row(&[], VId(1), &mut work).is_none());
    assert_eq!(work.identity_row_comparisons, 0);
}

#[test]
fn review_point_lookup_preserves_exact_identity_topology_and_properties() {
    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;
    use fgdb::DatabaseKeys;
    use fgdb_types::EId;
    use fgdb_types::context::PurposeContexts;
    use fgdb_types::ids::DatabaseSecurityNamespaceId;

    let runtime = RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let ctx = PurposeContexts::narrow_runtime_root(&root);
    let keys = DatabaseKeys::new(
        [0x5a; 32],
        DatabaseSecurityNamespaceId([0x5b; 32]),
        [0x5c; 32],
    );
    let mut db = runtime
        .block_on(Database::open_memory(&ctx.commit(), keys))
        .unwrap();
    for (index, case) in [
        "exact",
        "identity",
        "relation",
        "source",
        "destination",
        "properties",
    ]
    .into_iter()
    .enumerate()
    {
        let target = VId(10 * index as u128 + 1);
        let review = VId(target.0 + 1);
        let other = VId(target.0 + 2);
        let expected = edge_id(relation::REVIEWED_BY, target, review);
        let relation = if case == "relation" {
            relation::IN_BOOK
        } else {
            relation::REVIEWED_BY
        };
        let mut write = WriteBatch::new(relation);
        for vid in [target, review, other] {
            write.create_vertex(vid, vec![], vec![]);
        }
        write.add_edge(
            if case == "identity" {
                EId(expected.0 ^ 1)
            } else {
                expected
            },
            if case == "source" { other } else { target },
            if case == "destination" { other } else { review },
            if case == "properties" {
                vec![(property::CODE, CanonicalScalar::Int(1))]
            } else {
                vec![]
            },
        );
        let before = db.frontier().unwrap();
        runtime.block_on(db.write(&ctx.commit(), write)).unwrap();
        let at = db.frontier().unwrap();
        let mut work = ExternalSubledgerVerificationWork::default();
        assert!(!review_lineage_at(&db, target, review, before, &mut work).unwrap());
        let actual = review_lineage_at(&db, target, review, at, &mut work).unwrap();
        let literal = db.edges_at(at).unwrap().iter().any(|edge| {
            edge.entry.eid == expected
                && edge.entry.relation == relation::REVIEWED_BY
                && edge.entry.src == target
                && edge.entry.dst == review
                && edge.props.is_empty()
        });
        assert_eq!(actual, literal, "case={case}");
        assert_eq!(actual, case == "exact", "case={case}");
        assert_eq!(work.review_edge_point_reads, 2, "case={case}");
    }
}
