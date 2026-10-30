//! Independently authored mixed-unit and invalid-source aggregation fixtures.

use super::*;

fn edge_account(code: &str) -> VerifiedReportAccount {
    let mut account = displayed(code);
    account.unit_policy = if matches!(code, "10" | "8000") {
        OpenItemUnitPolicy::AnyUnit
    } else {
        OpenItemUnitPolicy::AnyCurrency
    };
    account
}

fn chart_records(parents: &[(&str, Option<&str>)]) -> Vec<Record> {
    let mut chart = Writer::default();
    chart.count(parents.len());
    for &(code, parent) in parents {
        let account = edge_account(code);
        let policy: i64 = match account.unit_policy {
            OpenItemUnitPolicy::AnyUnit => -2,
            OpenItemUnitPolicy::AnyCurrency => -1,
            OpenItemUnitPolicy::Single(unit) => i64::from(unit),
        };
        chart
            .bytes(code.as_bytes())
            .bytes(account.name.as_bytes())
            .u8(account.account_type)
            .u8(account.normal_balance)
            .u8(u8::from(account.is_leaf))
            .fixed(&policy.to_le_bytes())
            .u8(u8::from(parent.is_some()));
        if let Some(parent) = parent {
            chart.bytes(parent.as_bytes());
        }
    }
    let mut records = schema();
    records[0] = record(
        17,
        1,
        0,
        b"edge-chart",
        0,
        Some((1, &chart.buf)),
        None,
        None,
    );
    records
}

fn entry(class: u16, seq: u64, key: &[u8], legs: &[(&str, u32, bool, i128)]) -> Record {
    let mut w = Writer::default();
    w.u16(1)
        .u16(0)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u16(class)
        .i32(10)
        .u8(0);
    erasable(&mut w);
    w.u8(0).count(legs.len());
    for &(code, unit, debit, amount) in legs {
        w.u8(u8::from(!debit))
            .u128(account_id(code))
            .u32(unit)
            .i128(amount)
            .u8(0)
            .count(0)
            .u8(0)
            .count(0);
    }
    w.u8(0)
        .count(0)
        .u8(0)
        .bytes(key)
        .u8(0)
        .fixed(&[0; 32])
        .u16(1)
        .u128(PRINCIPAL)
        .u8(0)
        .count(0)
        .count(0);
    if class == 2 {
        w.u8(1).u8(0).u8(0).u8(0);
    } else {
        w.u8(0);
    }
    w.count(0).count(0);
    let len = w.buf.len();
    let proposal = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&w.buf]);
    let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal, &[]]);
    w.fixed(&proposal).fixed(&digest);
    let envelope = envelope_of_entry(&w.buf, len, seq, 0).unwrap();
    Record {
        bytes: w.buf,
        len,
        envelope,
    }
}

#[test]
fn summary_preserves_native_units_and_memo_rows_without_adding_them_to_monetary_totals() {
    let mut records = chart_records(&[
        ("10", None),
        ("1000", Some("10")),
        ("30", None),
        ("3000", Some("30")),
        ("6000", Some("10")),
        ("8000", Some("10")),
    ]);
    records.push(entry(
        1,
        3,
        b"mixed-native-post",
        &[
            ("1000", 0, true, 100),
            ("3000", 0, false, 100),
            ("1000", 1, true, 70),
            ("3000", 1, false, 70),
            ("6000", 0, true, 9),
            ("8000", 12, true, 4),
        ],
    ));
    records.push(entry(
        2,
        4,
        b"mixed-native-pending",
        &[
            ("1000", 0, true, 20),
            ("3000", 0, false, 20),
            ("6000", 1, true, 7),
            ("8000", 12, false, 2),
        ],
    ));
    let source_rows = vec![
        displayed_row("1000", 0, [100, 0, 20, 0]),
        displayed_row("1000", 1, [70, 0, 0, 0]),
        displayed_row("3000", 0, [0, 100, 0, 20]),
        displayed_row("3000", 1, [0, 70, 0, 0]),
        displayed_row("6000", 0, [9, 0, 0, 0]),
        displayed_row("6000", 1, [0, 0, 7, 0]),
        displayed_row("8000", 12, [4, 0, 0, 2]),
    ];
    let fixture = fixture(&records, 4, Selection::AsOf(20), &source_rows);
    let expected = VerifiedSummaryTrialBalance {
        book_id: BOOK,
        known_at: 4,
        source_certificate_digest: certificate(&fixture.source).unwrap().digest,
        scope: SummaryScope::AllRoots,
        groups: vec![
            VerifiedSummaryGroup {
                account: edge_account("10"),
                leaves: ["1000", "6000", "8000"]
                    .into_iter()
                    .map(edge_account)
                    .collect(),
                rows: vec![
                    displayed_row("10", 0, [109, 0, 20, 0]),
                    displayed_row("10", 1, [70, 0, 7, 0]),
                    displayed_row("10", 12, [4, 0, 0, 2]),
                ],
            },
            VerifiedSummaryGroup {
                account: edge_account("30"),
                leaves: vec![edge_account("3000")],
                rows: vec![
                    displayed_row("30", 0, [0, 100, 0, 20]),
                    displayed_row("30", 1, [0, 70, 0, 0]),
                ],
            },
        ],
        uncovered_leaves: vec![],
        unit_totals: BTreeMap::from([(0, (100, 100)), (1, (70, 70))]),
        pending_unit_totals: BTreeMap::from([(0, (20, 20)), (1, (0, 0))]),
    };
    let verified = verify(&fixture, &expected).unwrap();
    assert_eq!(verified.rows, source_rows);
    assert_eq!(verified.summary.as_ref(), Some(&expected));
    assert!(expected.is_complete());
    assert!(!expected.unit_totals.contains_key(&12));
    assert_eq!(expected.groups[0].rows[0].debits, 109);
    assert_eq!(expected.unit_totals[&0].0, 100);
}

#[test]
fn summary_refuses_group_overflow_after_the_native_memo_source_successfully_replays() {
    let mut records = chart_records(&[("10", None), ("6000", Some("10")), ("8000", Some("10"))]);
    records.push(entry(
        1,
        3,
        b"separate-memo-cells",
        &[("6000", 1, true, i128::MAX), ("8000", 1, true, 1)],
    ));
    let source_rows = vec![
        displayed_row("6000", 1, [i128::MAX, 0, 0, 0]),
        displayed_row("8000", 1, [1, 0, 0, 0]),
    ];
    let fixture = fixture(&records, 3, Selection::AsOf(20), &source_rows);
    let mut expected = VerifiedSummaryTrialBalance {
        book_id: BOOK,
        known_at: 3,
        source_certificate_digest: certificate(&fixture.source).unwrap().digest,
        scope: selected(&[]),
        groups: vec![],
        uncovered_leaves: vec![edge_account("6000"), edge_account("8000")],
        unit_totals: BTreeMap::new(),
        pending_unit_totals: BTreeMap::new(),
    };
    let unselected = verify(&fixture, &expected).unwrap();
    assert_eq!(unselected.rows, source_rows);
    assert!(unselected.summary.unwrap().unit_totals.is_empty());

    // Each native row fits and monetary footing excludes both rows. Only
    // combining the two into one selected group overflows the exact column.
    expected.scope = selected(&["10"]);
    let failure = verify(&fixture, &expected).unwrap_err();
    assert_eq!(failure.predicate, "exact_arithmetic");
    assert!(failure.detail.contains("summary column overflow"));
}

#[test]
fn summary_refuses_a_nonposting_source_row_without_authenticated_promotion() {
    let mut records = chart_records(&[("10", None), ("30", None), ("3000", Some("30"))]);
    records.push(entry(
        1,
        3,
        b"posted-to-declared-summary",
        &[("10", 1, true, 100), ("3000", 1, false, 100)],
    ));
    let fixture = fixture(
        &records,
        3,
        Selection::AsOf(20),
        &[
            displayed_row("10", 1, [100, 0, 0, 0]),
            displayed_row("3000", 1, [0, 100, 0, 0]),
        ],
    );
    // Selecting no roots must not hide an invalid row in the complete source.
    for scope in [SummaryScope::AllRoots, selected(&[])] {
        let claimed = VerifiedSummaryTrialBalance {
            book_id: BOOK,
            known_at: 3,
            source_certificate_digest: certificate(&fixture.source).unwrap().digest,
            scope,
            groups: vec![],
            uncovered_leaves: vec![],
            unit_totals: BTreeMap::new(),
            pending_unit_totals: BTreeMap::new(),
        };
        let failure = verify(&fixture, &claimed).unwrap_err();
        assert_eq!(failure.predicate, "account_metadata");
        assert!(failure.detail.contains("nonposting"));
    }
}
