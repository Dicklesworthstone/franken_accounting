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
