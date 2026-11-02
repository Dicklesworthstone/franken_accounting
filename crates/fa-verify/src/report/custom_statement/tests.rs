use super::super::statement::definition::Source;
use super::*;

fn definition_bytes() -> Vec<u8> {
    let mut w = Writer::default();
    w.fixed(definition::FORMAT)
        .bytes(b"company-income")
        .bytes(b"Company income")
        .u32(7)
        .u8(1)
        .count(3);
    w.bytes(b"first")
        .bytes(b"First revenue")
        .u8(0)
        .u8(2)
        .count(1)
        .bytes(b"A")
        .u8(1);
    w.bytes(b"other")
        .bytes(b"Other revenue")
        .u8(0)
        .u8(5)
        .u8(1)
        .count(1)
        .u8(4)
        .u8(2)
        .count(1)
        .bytes(b"A")
        .u8(1);
    w.bytes(b"total")
        .bytes(b"Total revenue")
        .u8(1)
        .count(2)
        .bytes(b"first")
        .bytes(b"other")
        .count(0);
    w.count(0);
    w.buf
}

fn schema() -> metadata::Schema {
    let mut chart = Writer::default();
    chart.count(5);
    for (code, kind, leaf) in [
        ("A", 4, true),
        ("B", 4, true),
        ("C", 4, true),
        ("S", 4, false),
        ("cash", 1, true),
    ] {
        chart
            .bytes(code.as_bytes())
            .bytes(code.as_bytes())
            .u8(kind)
            .u8(u8::from(kind == 4))
            .u8(u8::from(leaf))
            .fixed(&0i64.to_le_bytes())
            .u8(0);
    }
    let mut periods = Writer::default();
    periods
        .fixed(b"fa:period-creation:v1")
        .bytes(b"cy")
        .i32(2026)
        .count(2);
    for (code, ordinal, start, end) in [("P1", 1, 0, 10), ("P2", 2, 10, 20)] {
        periods
            .bytes(code.as_bytes())
            .i32(2026)
            .u16(ordinal)
            .u8(1)
            .i32(start)
            .i32(end)
            .u8(0);
    }
    let mut schema = metadata::Schema::default();
    schema.apply(1, &chart.buf, &[0; 16], 1).unwrap();
    schema.apply(13, &periods.buf, &[0; 16], 2).unwrap();
    schema
}

fn source() -> statement::Selection {
    statement::Selection::from_definition(
        definition::decode(&definition_bytes()).unwrap(),
        vec!["P2".into()],
        vec!["P1".into()],
    )
    .unwrap()
}

fn exact(selection: &statement::Selection) -> statement::VerifiedStatement {
    let envelope = LeafEnvelope {
        kind: crate::envelope::KIND_ENTRY,
        book_id: [0; 16],
        branch_id: [0; 16],
        commit_seq: 3,
        within_commit_ordinal: 0,
        record_digest: [9; 32],
        class: 1,
        effective_day: Some(15),
        account_vids: vec![],
        unit_ids: vec![],
    };
    let info = metadata::EntryInfo {
        schema: None,
        time_tick: None,
        period: Some(("cy", "P2")),
        resolution: None,
        supersession: vec![],
        supersession_reasons: vec![],
        rule_version_oid: None,
        fx_revaluation_basis: None,
        year_end_close_basis: None,
        obligation_maturity: None,
        case_member: None,
        prior_period_adjustment: None,
        evidence: vec![],
        principal: 1,
        identity: 1,
        legacy_identity: None,
    };
    let legs = [("cash", true, 10), ("A", false, 5), ("B", false, 5)]
        .into_iter()
        .map(|(code, debit, mantissa)| Leg {
            debit,
            account: crate::ads::account_vid(&[0; 16], code),
            unit: 0,
            mantissa,
        })
        .collect();
    statement::replay(
        selection,
        &[0; 16],
        &[0; 16],
        3,
        &[0, 1],
        &schema(),
        &[envelope],
        &BTreeMap::from([(0, info)]),
        &[legs],
        &BTreeSet::new(),
        &BTreeSet::new(),
    )
    .unwrap()
    .0
}

fn spec() -> PresentationSpec {
    PresentationSpec {
        rounding_law: 3,
        scale_reduction_digits: 1,
        residual_line_code: "rounding".into(),
        residual_line_label: "Rounding".into(),
    }
}

#[test]
fn custom_partition_and_formula_reuse_exact_historical_registers() {
    let selection = source();
    let statement = exact(&selection);
    assert_eq!(statement.definition_name, "company-income");
    assert_eq!(statement.definition_version, 7);
    assert_eq!(
        statement.definition_digest,
        hash_parts(
            definition::FORMAT,
            &[
                &(definition_bytes().len() as u32).to_le_bytes(),
                &definition_bytes()
            ]
        )
    );
    assert_eq!(
        statement
            .lines
            .iter()
            .map(|line| (line.code.as_str(), line.unit, line.amounts.clone()))
            .collect::<Vec<_>>(),
        [
            ("first", 0, vec![5, 0]),
            ("first", 1, vec![0, 0]),
            ("other", 0, vec![5, 0]),
            ("other", 1, vec![0, 0]),
            ("total", 0, vec![10, 0]),
            ("total", 1, vec![0, 0]),
        ]
    );
    assert_eq!(
        statement
            .mappings
            .iter()
            .map(|mapping| (mapping.code.as_str(), mapping.line_code.as_str()))
            .collect::<Vec<_>>(),
        [("A", "first"), ("B", "other"), ("C", "other")]
    );
    assert_eq!(statement.columns[0].effective_from, Some(10));
    assert_eq!(statement.columns[1].effective_through, 9);
}

#[test]
fn presentation_emits_formula_residuals_in_unit_order_and_canonical_bytes() {
    let selection = source();
    let statement = exact(&selection);
    let (presented, bytes) = presentation::replay(
        &spec(),
        &selection.definition,
        &statement,
        &[0; 16],
        &[0; 16],
        3,
        0,
    )
    .unwrap();
    assert_eq!(
        presented
            .lines
            .iter()
            .map(|line| (line.code.as_str(), line.unit))
            .collect::<Vec<_>>(),
        [
            ("first", 0),
            ("other", 0),
            ("total_rounding", 0),
            ("total", 0),
            ("first", 1),
            ("other", 1),
            ("total", 1),
        ]
    );
    assert_eq!(presented.lines[2].exact_amounts, [0, 0]);
    assert_eq!(presented.lines[2].presented_amounts, [1, 0]);
    assert_eq!(presented.lines[2].rounding_errors, [10, 0]);
    assert!(presented.lines[2].is_residual_line);
    let mut expected = Writer::default();
    expected
        .fixed(b"fa:presented-statement:v1")
        .fixed(&[0; 16])
        .fixed(&[0; 16])
        .u64(3)
        .bytes(b"company-income")
        .u32(7)
        .fixed(&statement.definition_digest)
        .u16(3)
        .u8(1)
        .i128(10)
        .count(2);
    for (label, code, first, last) in [("current", "P2", 10, 19), ("comparative", "P1", 0, 9)] {
        expected
            .bytes(label.as_bytes())
            .count(1)
            .bytes(code.as_bytes())
            .u8(1)
            .i32(first)
            .i32(last);
    }
    expected.count(7);
    for (code, label, unit, exact, shown, error, residual) in [
        ("first", "First revenue", 0, 5, 0, -5, false),
        ("other", "Other revenue", 0, 5, 0, -5, false),
        (
            "total_rounding",
            "Rounding (Total revenue)",
            0,
            0,
            1,
            10,
            true,
        ),
        ("total", "Total revenue", 0, 10, 1, 0, false),
        ("first", "First revenue", 1, 0, 0, 0, false),
        ("other", "Other revenue", 1, 0, 0, 0, false),
        ("total", "Total revenue", 1, 0, 0, 0, false),
    ] {
        expected
            .bytes(code.as_bytes())
            .bytes(label.as_bytes())
            .u32(unit);
        for amount in [exact, shown, error] {
            expected.count(2).i128(amount).i128(0);
        }
        expected.u8(u8::from(residual));
    }
    assert_eq!(bytes, expected.buf);
    assert_eq!(
        presentation::replay(
            &spec(),
            &selection.definition,
            &statement,
            &[0; 16],
            &[0; 16],
            3,
            MAX_REPORT_BUNDLE_BYTES
        )
        .unwrap_err()
        .predicate,
        "bounded_input"
    );
}

#[test]
fn mappings_refuse_unmapped_duplicate_unknown_summary_and_outside_codes() {
    for case in 0..5 {
        let mut definition = source().definition;
        let Source::CustomAccounts { set, .. } = &mut definition.lines[1].source else {
            unreachable!()
        };
        *set = match case {
            0 => definition::AccountSet::Codes(vec!["B".into()]),
            1 => definition::AccountSet::Types(vec![4]),
            2 => definition::AccountSet::Difference(
                Box::new(definition::AccountSet::Types(vec![4])),
                Box::new(definition::AccountSet::Codes(vec!["missing".into()])),
            ),
            3 => definition::AccountSet::Codes(vec!["S".into()]),
            4 => definition::AccountSet::Codes(vec!["cash".into()]),
            _ => unreachable!(),
        };
        assert_eq!(
            definition::mappings(&definition, &schema())
                .unwrap_err()
                .predicate,
            "statement_partition"
        );
    }
}

#[test]
fn union_and_prefix_sets_keep_zero_balance_partition_complete() {
    let mut definition = source().definition;
    let Source::CustomAccounts { set, .. } = &mut definition.lines[1].source else {
        unreachable!()
    };
    *set = definition::AccountSet::Union(vec![
        definition::AccountSet::Prefixes(vec!["B".into()]),
        definition::AccountSet::Codes(vec!["C".into()]),
    ]);
    let mappings = definition::mappings(&definition, &schema()).unwrap();
    assert_eq!(mappings.len(), 3);
    assert_eq!(mappings[2].code, "C");
}

#[test]
fn custom_formulas_refuse_forward_cycles_duplicate_operands_and_nonformula_checks() {
    for case in 0..5 {
        let mut w = Writer::default();
        w.fixed(definition::FORMAT)
            .bytes(b"formula")
            .bytes(b"Formula")
            .u32(1)
            .u8(1)
            .count(2)
            .bytes(b"a")
            .bytes(b"A")
            .u8(0)
            .u8(1)
            .count(1)
            .u8(4)
            .u8(1)
            .bytes(b"b")
            .bytes(b"B")
            .u8(1);
        match case {
            0 => {
                w.count(1).bytes(b"b").count(0);
            }
            1 => {
                w.count(1).bytes(b"future").count(0);
            }
            2 => {
                w.count(1).bytes(b"a").count(1).bytes(b"a");
            }
            3 => {
                w.count(0).count(0);
            }
            4 => {
                w.count(1).bytes(b"a").count(0);
            }
            _ => unreachable!(),
        }
        if case == 4 {
            w.count(1).bytes(b"a");
        } else {
            w.count(0);
        }
        assert!(definition::decode(&w.buf).is_err());
    }
}

fn write_expression(w: &mut Writer, depth: usize) {
    if depth == 0 {
        w.u8(1).count(1).u8(4);
    } else {
        w.u8(5);
        write_expression(w, depth - 1);
        w.u8(2).count(1).bytes(b"A");
    }
}

#[test]
fn expressions_enforce_depth_and_canonical_sorted_sets() {
    for depth in [8, 9] {
        let mut w = Writer::default();
        w.fixed(definition::FORMAT)
            .bytes(b"depth")
            .bytes(b"Depth")
            .u32(1)
            .u8(1)
            .count(1)
            .bytes(b"rev")
            .bytes(b"Revenue")
            .u8(0);
        write_expression(&mut w, depth);
        w.u8(1).count(0);
        assert_eq!(definition::decode(&w.buf).is_ok(), depth == 8);
    }
    for codes in [["B", "A"], ["A", "A"]] {
        let mut w = Writer::default();
        w.fixed(definition::FORMAT)
            .bytes(b"codes")
            .bytes(b"Codes")
            .u32(1)
            .u8(1)
            .count(1)
            .bytes(b"rev")
            .bytes(b"Revenue")
            .u8(0)
            .u8(2)
            .count(2);
        for code in codes {
            w.bytes(code.as_bytes());
        }
        w.u8(1).count(0);
        assert!(definition::decode(&w.buf).is_err());
    }
}

#[test]
fn selector_rejects_invalid_activation_rounding_and_noncanonical_periods() {
    for case in 0..4 {
        let mut w = Writer::default();
        w.bytes(&definition_bytes())
            .u128(1)
            .u64(if case == 0 { 0 } else { 2 });
        if case == 1 {
            w.count(2).bytes(b"P2").bytes(b"P1");
        } else {
            w.count(1).bytes(b"P2");
        }
        w.count(0).u8(1);
        let mut spec = Writer::default();
        spec.fixed(b"fa:presentation-rounding-spec:v1")
            .u16(if case == 2 { 10 } else { 3 })
            .u8(if case == 3 { 39 } else { 1 })
            .bytes(b"rounding")
            .bytes(b"Rounding");
        w.bytes(&spec.buf);
        assert!(Selection::read(&mut Reader::new(&w.buf), false).is_err());
    }
}

#[test]
fn expression_partition_caps_work_for_a_valid_large_definition_and_chart() {
    let mut w = Writer::default();
    w.fixed(definition::FORMAT)
        .bytes(b"work")
        .bytes(b"Work bound")
        .u32(1)
        .u8(1)
        .count(1)
        .bytes(b"revenue")
        .bytes(b"Revenue")
        .u8(0)
        .u8(4)
        .count(2)
        .u8(3)
        .count(512);
    for index in 0..512 {
        w.bytes(format!("z{index:063}").as_bytes());
    }
    w.u8(1).count(1).u8(4).u8(1).count(0);
    let definition = definition::decode(&w.buf).unwrap();
    let mut schema = schema();
    let seed = schema.accounts[&crate::ads::account_vid(&[0; 16], "A")].clone();
    schema.accounts.clear();
    for index in 0..1024 {
        let mut account = seed.clone();
        account.code = format!("A{index:04}");
        schema.accounts.insert(index, account);
    }
    assert_eq!(
        definition::mappings(&definition, &schema)
            .unwrap_err()
            .predicate,
        "bounded_input"
    );
}
