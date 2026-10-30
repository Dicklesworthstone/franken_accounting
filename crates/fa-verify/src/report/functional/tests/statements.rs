//! Functional financial statements over hand-calculated foreign-currency
//! histories. Fixture output is encoded independently from replay.

use super::*;
use crate::report::{
    FUNCTIONAL_STATEMENT_CERTIFICATE_FORMAT, StatementColumn, StatementLine, StatementMapping,
    VerifiedReport, VerifiedStatement,
};

fn definition(activity: bool) -> Vec<u8> {
    unhex(if activity {
        include_str!("../../tests/income-statement.hex")
    } else {
        include_str!("../../tests/balance-sheet.hex")
    })
}

fn chart() -> [(&'static str, &'static str, u8, bool); 6] {
    [
        ("1000", "Cash", 1, true),
        ("1100", "Summary", 1, false),
        ("3000", "Equity", 3, true),
        ("4000", "Revenue", 4, true),
        ("5000", "Expenses", 5, true),
        ("5001", "Unused expense", 5, true),
    ]
}

fn valued_pair(
    debit: &'static str,
    credit: &'static str,
    native: i128,
    base: i128,
) -> Vec<TestLeg> {
    let mut legs = pair(native, base);
    legs[0].code = debit;
    legs[1].code = credit;
    legs
}

fn at_par(debit: &'static str, credit: &'static str, amount: i128) -> Vec<TestLeg> {
    valued_pair(debit, credit, amount, amount)
        .into_iter()
        .map(|mut leg| {
            leg.unit = 0;
            leg.base = None;
            leg
        })
        .collect()
}

fn history() -> (Vec<Record>, Vec<RateFixture>) {
    let mut chart_bytes = Writer::default();
    chart_bytes.count(chart().len());
    for (code, name, typ, leaf) in chart() {
        chart_bytes
            .bytes(code.as_bytes())
            .bytes(name.as_bytes())
            .u8(typ)
            .u8(u8::from(matches!(typ, 2..=4)))
            .u8(u8::from(leaf))
            .fixed(&(-1i64).to_le_bytes())
            .u8(0);
    }
    let mut records = schema();
    records[0] = schema_record(1, 1, &chart_bytes.buf);
    let spot = rate_fixture(11, 10, 1, 10);
    let average = rate_fixture(3, 2, 3, 58);
    records.push(intake(&spot, 3));
    records.push(entry(
        4,
        1,
        10,
        b"capital",
        &valued_pair("1000", "3000", 1000, 1100),
        Some((1, &spot, None)),
        None,
        None,
    ));
    records.push(intake(&average, 5));
    for (seq, class, day, key, legs) in [
        (
            6,
            1,
            40,
            b"sale".as_slice(),
            valued_pair("1000", "4000", 200, 300),
        ),
        (
            7,
            1,
            41,
            b"expense".as_slice(),
            valued_pair("5000", "1000", 60, 90),
        ),
    ] {
        records.push(entry(
            seq,
            class,
            day,
            key,
            &legs,
            Some((3, &average, None)),
            None,
            None,
        ));
    }
    // A reservation is a commitment, not posted stock or income. It must not
    // appear in either financial statement even before it is released.
    records.push(entry(
        8,
        2,
        42,
        b"reservation",
        &at_par("1000", "4000", 99),
        None,
        None,
        None,
    ));
    let closing = entry(
        9,
        8,
        50,
        b"closing",
        &at_par("4000", "3000", 210),
        None,
        None,
        None,
    );
    let reversed = entry(
        10,
        4,
        51,
        b"reverse-closing",
        &at_par("4000", "3000", 210)
            .into_iter()
            .map(|mut leg| {
                leg.debit = !leg.debit;
                leg
            })
            .collect::<Vec<_>>(),
        None,
        Some(&closing),
        None,
    );
    let restored = entry(
        11,
        4,
        52,
        b"reverse-reversal",
        &at_par("4000", "3000", 210),
        None,
        Some(&reversed),
        None,
    );
    records.extend([closing, reversed, restored]);
    records.push(entry(
        12,
        1,
        40,
        b"later-backdate",
        &valued_pair("1000", "4000", 6660, 9990),
        Some((3, &average, None)),
        None,
        None,
    ));
    // A newer unused quote is in the checkpoint but supplies no earlier value.
    records.push(intake(&rate_fixture(17, 10, 3, 58), 13));
    (records, vec![spot, average])
}

struct Request {
    activity: bool,
    current: Vec<String>,
    comparative: Vec<String>,
    known_at: u64,
}

fn request(activity: bool) -> Request {
    Request {
        activity,
        current: vec!["P2".into()],
        comparative: vec!["P1".into()],
        known_at: 11,
    }
}

fn expected(request: &Request, later_sale: i128) -> VerifiedFunctionalStatement {
    let definition = definition(request.activity);
    let rows: Vec<(&str, &str, i128, i128)> = if request.activity {
        vec![
            ("revenue", "Revenue", 300 + later_sale, 0),
            ("expense", "Expenses", 90, 0),
            ("net_income", "Net income", 210 + later_sale, 0),
        ]
    } else {
        vec![
            ("assets", "Assets", 1310 + later_sale, 1100),
            ("liabilities", "Liabilities", 0, 0),
            ("equity", "Posted equity", 1310, 1100),
            (
                "unclosed_revenue",
                "Unclosed revenue, all years",
                90 + later_sale,
                0,
            ),
            ("unclosed_expense", "Unclosed expenses, all years", 90, 0),
            (
                "unclosed_earnings",
                "Unclosed earnings, all years",
                later_sale,
                0,
            ),
            (
                "total_equity",
                "Equity including unclosed earnings",
                1310 + later_sale,
                1100,
            ),
            (
                "liabilities_and_equity",
                "Liabilities and equity including unclosed earnings",
                1310 + later_sale,
                1100,
            ),
            (
                "balance_check",
                "Assets less liabilities and equity (must equal zero)",
                0,
                0,
            ),
        ]
    };
    let mappings = chart()
        .into_iter()
        .filter(|(_, _, typ, leaf)| *leaf && (!request.activity || matches!(typ, 4 | 5)))
        .map(|(code, name, typ, leaf)| StatementMapping {
            account: id(code),
            code: code.into(),
            name: name.into(),
            account_type: typ,
            is_leaf: leaf,
            line_code: match (request.activity, typ) {
                (true, 4) => "revenue",
                (true, 5) => "expense",
                (_, 1) => "assets",
                (_, 3) => "equity",
                (_, 4) => "unclosed_revenue",
                (_, 5) => "unclosed_expense",
                _ => unreachable!(),
            }
            .into(),
        })
        .collect();
    VerifiedFunctionalStatement {
        base_unit: 0,
        statement: VerifiedStatement {
            definition_name: if request.activity {
                "income-statement"
            } else {
                "balance-sheet"
            }
            .into(),
            definition_version: 1,
            definition_digest: hash_parts(
                b"fa:statement-definition:v1",
                &[&(definition.len() as u32).to_le_bytes(), &definition],
            ),
            kind: if request.activity {
                "IncomeStatement"
            } else {
                "BalanceSheet"
            },
            units: vec![0],
            columns: vec![
                StatementColumn {
                    label: "current".into(),
                    periods: request.current.clone(),
                    effective_from: request.activity.then_some(if request.current.len() == 2 {
                        0
                    } else {
                        31
                    }),
                    effective_through: 58,
                },
                StatementColumn {
                    label: "comparative".into(),
                    periods: request.comparative.clone(),
                    effective_from: request.activity.then_some(0),
                    effective_through: 30,
                },
            ],
            lines: rows
                .into_iter()
                .map(|(code, label, current, comparative)| StatementLine {
                    code: code.into(),
                    label: label.into(),
                    unit: 0,
                    amounts: vec![current, comparative],
                })
                .collect(),
            mappings,
        },
        book_parameters_source: BOOK_PARAMETERS_SOURCE,
    }
}

fn output(result: &VerifiedFunctionalStatement, request: &Request) -> Vec<u8> {
    let result = &result.statement;
    let mut w = Writer::default();
    w.fixed(b"FA-STATEMENT\0")
        .u16(1)
        .u16(0)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u64(request.known_at)
        .bytes(result.definition_name.as_bytes())
        .u32(result.definition_version)
        .fixed(&result.definition_digest)
        .bytes(&definition(request.activity))
        .count(result.columns.len());
    for column in &result.columns {
        w.bytes(column.label.as_bytes()).count(column.periods.len());
        for period in &column.periods {
            w.bytes(period.as_bytes());
        }
        w.u8(u8::from(column.effective_from.is_some()));
        if let Some(from) = column.effective_from {
            w.i32(from);
        }
        w.i32(column.effective_through);
    }
    w.count(result.lines.len());
    for line in &result.lines {
        w.bytes(line.code.as_bytes())
            .bytes(line.label.as_bytes())
            .u32(line.unit)
            .count(line.amounts.len());
        for amount in &line.amounts {
            w.i128(*amount);
        }
    }
    w.count(result.mappings.len());
    for mapping in &result.mappings {
        w.u128(mapping.account)
            .bytes(mapping.code.as_bytes())
            .bytes(mapping.name.as_bytes())
            .u8(mapping.account_type)
            .u8(u8::from(mapping.is_leaf))
            .bytes(mapping.line_code.as_bytes());
    }
    let mut wrapper = Writer::default();
    wrapper
        .fixed(STATEMENT_OUTPUT_FORMAT)
        .bytes(b"retained-base-amounts")
        .bytes(&w.buf);
    wrapper.buf
}

fn pack_statement(
    records: &[Record],
    request: &Request,
    spec: &[u8],
    rates: &[RateFixture],
    output: &[u8],
) -> (Vec<u8>, SignedCheckpoint, [u8; 32]) {
    pack_statement_with_migrations(records, request, spec, rates, output, &[])
}

fn pack_statement_with_migrations(
    records: &[Record],
    request: &Request,
    spec: &[u8],
    rates: &[RateFixture],
    output: &[u8],
    bodies: &[(u64, &[u8])],
) -> (Vec<u8>, SignedCheckpoint, [u8; 32]) {
    let mut selector = Writer::default();
    selector.u8(3).bytes(&definition(request.activity));
    for periods in [&request.current, &request.comparative] {
        selector.count(periods.len());
        for period in periods {
            selector.bytes(period.as_bytes());
        }
    }
    pack_profile_with_migrations(
        records,
        request.known_at,
        spec,
        rates,
        output,
        CertificateProfile {
            format: FUNCTIONAL_STATEMENT_CERTIFICATE_FORMAT,
            output_format: STATEMENT_OUTPUT_FORMAT,
            selector: &selector.buf,
        },
        &registries(),
        bodies,
    )
}

fn verify(
    bundle: &[u8],
    signed: &SignedCheckpoint,
    pin: &[u8; 32],
) -> Result<VerifiedReport, ReportError> {
    verify_report_with_inputs(
        bundle,
        &[],
        Some(&signed.checkpoint),
        None,
        Some(pin),
        None,
        |_, _| Ok(signed.clone()),
    )
}

#[test]
fn functional_statements_recompute_stock_activity_comparatives_and_closing_ancestry() {
    let (records, rates) = history();
    for activity in [false, true] {
        for periods in [vec!["P2".into()], vec!["P1".into(), "P2".into()]] {
            for (known_at, later_sale) in [(11, 0), (12, 9990)] {
                let mut request = request(activity);
                request.current = periods.clone();
                request.known_at = known_at;
                let expected = expected(&request, later_sale);
                let output = output(&expected, &request);
                let (bundle, signed, pin) =
                    pack_statement(&records, &request, &book(&[]), &rates, &output);
                let verified = verify(&bundle, &signed, &pin).unwrap();
                assert_eq!(verified.functional_statement, Some(expected));
                assert_eq!(verified.output, output);
                assert_eq!(verified.known_at, known_at);
                assert_eq!(verified.effective_through, Some(58));
                assert_eq!(verified.activity, activity);
                assert_eq!(verified.periods, request.current);
                assert!(verified.statement.is_none());
                assert!(verified.functional_trial_balance.is_none());
            }
        }
    }
}

#[test]
fn resealed_functional_statement_lines_units_and_zero_leaf_omissions_fail_recomputation() {
    let (records, rates) = history();
    for activity in [false, true] {
        let request = request(activity);
        let expected = expected(&request, 0);
        let mut mutations = Vec::new();
        let mut amount = expected.clone();
        amount.statement.lines[0].amounts[0] += 1;
        mutations.push(output(&amount, &request));
        let mut units = expected.clone();
        units.statement.units = vec![1];
        for line in &mut units.statement.lines {
            line.unit = 1;
        }
        mutations.push(output(&units, &request));
        let mut mapping = expected.clone();
        mapping
            .statement
            .mappings
            .retain(|mapping| mapping.code != "5001");
        mutations.push(output(&mapping, &request));
        let mut basis = output(&expected, &request);
        let at = basis
            .windows(b"retained-base-amounts".len())
            .position(|bytes| bytes == b"retained-base-amounts")
            .unwrap();
        basis[at] = b'X';
        mutations.push(basis);
        for changed in mutations {
            let (bundle, signed, pin) =
                pack_statement(&records, &request, &book(&[]), &rates, &changed);
            assert_eq!(
                verify(&bundle, &signed, &pin).unwrap_err().predicate,
                "report_recomputation"
            );
        }
    }
}

#[test]
fn functional_statement_scope_and_basis_are_not_producer_selected_reinterpretations() {
    let (records, rates) = history();
    let mut request = request(true);
    let output = output(&expected(&request, 0), &request);
    request.current = vec!["P1".into()];
    let (bundle, signed, pin) = pack_statement(&records, &request, &book(&[]), &rates, &output);
    assert_eq!(
        verify(&bundle, &signed, &pin).unwrap_err().predicate,
        "report_recomputation"
    );
    request.current = vec!["P2".into()];
    request.comparative = vec!["P2".into()];
    let (bundle, signed, pin) = pack_statement(&records, &request, &book(&[]), &rates, &output);
    assert_eq!(
        verify(&bundle, &signed, &pin).unwrap_err().predicate,
        "report_recomputation"
    );
    request.comparative = vec!["P1".into()];
    let mut wrong_book = book(&[]);
    let base_offset = 2 + 16 + 4 + b"Functional fixture".len();
    wrong_book[base_offset..base_offset + 4].copy_from_slice(&1u32.to_le_bytes());
    let (bundle, signed, pin) = pack_statement(&records, &request, &wrong_book, &rates, &output);
    assert!(verify(&bundle, &signed, &pin).is_err());
}

#[test]
fn functional_statements_require_exact_original_rates_and_authenticated_receivers() {
    let (records, rates) = history();
    let request = request(true);
    let output = output(&expected(&request, 0), &request);
    let mut substituted = rates.clone();
    substituted[1] = rate_fixture(17, 10, 3, 58);
    let mut forged_receiver = rates.clone();
    let receiver = 2 + 16 + 1 + 4 + b"application/vnd.fa.fx-rate".len() + 8 + 32 + 1;
    forged_receiver[1].document[receiver..receiver + 16].copy_from_slice(&99u128.to_le_bytes());
    for (rates, predicate) in [
        (rates[..1].to_vec(), "functional_rates"),
        (substituted, "functional_rates"),
        (forged_receiver, "functional_rate_visibility"),
    ] {
        let (bundle, signed, pin) = pack_statement(&records, &request, &book(&[]), &rates, &output);
        assert_eq!(
            verify(&bundle, &signed, &pin).unwrap_err().predicate,
            predicate
        );
    }
}

#[test]
fn statements_do_not_hide_unsupported_or_false_valuations_outside_the_selected_columns() {
    let (mut records, rates) = history();
    let mut request = request(true);
    request.known_at = 14;
    request.current = vec!["P1".into()];
    let output = output(&expected(&request, 0), &request);
    // A supported law with missing source proof is still rejected throughout
    // the authenticated history, including outside the selected columns.
    for (law, predicate) in [
        (2, "functional_revaluation"),
        (4, "supported_report"),
        (8, "functional_closing"),
        (9, "supported_report"),
    ] {
        records.push(entry(
            14,
            1,
            40,
            b"unsupported-outside-selection",
            &valued_pair("1000", "4000", 200, 300),
            Some((law, &rates[1], None)),
            None,
            None,
        ));
        let (bundle, signed, pin) = pack_statement(&records, &request, &book(&[]), &rates, &output);
        let error = verify(&bundle, &signed, &pin).unwrap_err();
        assert_eq!(error.predicate, predicate);
        if law == 2 {
            assert!(error.detail.contains("complete source-bound basis"));
        }
        records.pop();
    }
    records.push(entry(
        14,
        1,
        40,
        b"false-outside-selection",
        &valued_pair("1000", "4000", 200, 301),
        Some((3, &rates[1], None)),
        None,
        None,
    ));
    let (bundle, signed, pin) = pack_statement(&records, &request, &book(&[]), &rates, &output);
    assert_eq!(
        verify(&bundle, &signed, &pin).unwrap_err().predicate,
        "functional_valuation"
    );
}

#[test]
fn source_bound_carrying_close_reproduces_independent_balance_sheet_and_income() {
    let (records, rates) = super::closing::history();
    for activity in [false, true] {
        let request = Request {
            activity,
            current: vec![if activity { "P1" } else { "FY1970-CLOSE" }.into()],
            comparative: Vec::new(),
            known_at: 9,
        };
        let mut expected = expected(&request, 0);
        expected.statement.columns = vec![StatementColumn {
            label: "current".into(),
            periods: request.current.clone(),
            effective_from: activity.then_some(0),
            effective_through: if activity { 30 } else { 364 },
        }];
        for line in &mut expected.statement.lines {
            line.amounts = vec![match line.code.as_str() {
                "assets"
                | "equity"
                | "total_equity"
                | "liabilities_and_equity"
                | "revenue"
                | "net_income" => -10,
                _ => 0,
            }];
        }
        expected.statement.mappings = super::closing::chart()
            .into_iter()
            .filter(|(_, kind)| !activity || matches!(kind, 4 | 5))
            .map(|(code, kind)| StatementMapping {
                account: id(code),
                code: code.into(),
                name: code.into(),
                account_type: kind,
                is_leaf: true,
                line_code: match (activity, kind) {
                    (true, 4) => "revenue",
                    (true, 5) => "expense",
                    (_, 1) => "assets",
                    (_, 3) => "equity",
                    (_, 4) => "unclosed_revenue",
                    (_, 5) => "unclosed_expense",
                    _ => unreachable!(),
                }
                .into(),
            })
            .collect();
        let bytes = output(&expected, &request);
        let (bundle, signed, pin) = pack_statement(&records, &request, &book(&[]), &rates, &bytes);
        let verified = verify(&bundle, &signed, &pin).unwrap();
        assert_eq!(verified.functional_statement, Some(expected.clone()));
        assert_eq!(verified.output, bytes);
        expected.statement.lines[0].amounts[0] += 1;
        let (bundle, signed, pin) = pack_statement(
            &records,
            &request,
            &book(&[]),
            &rates,
            &output(&expected, &request),
        );
        assert!(
            verify(&bundle, &signed, &pin).is_err(),
            "a resealed false statement remains false"
        );
    }
}

#[test]
fn functional_statement_parameters_require_a_recipient_pin_or_verified_receipt() {
    let (records, rates) = history();
    let request = request(true);
    let output = output(&expected(&request, 0), &request);
    let (bundle, signed, pin) = pack_statement(&records, &request, &book(&[]), &rates, &output);
    assert_eq!(
        verify_report_with_inputs(
            &bundle,
            &[],
            Some(&signed.checkpoint),
            None,
            None,
            None,
            |_, _| Ok(signed.clone())
        )
        .unwrap_err()
        .predicate,
        "report_input_authority"
    );
    assert_eq!(
        verify(&bundle, &signed, &[99; 32]).unwrap_err().predicate,
        "recipient_certificate"
    );
    assert_eq!(
        verify_report_with_inputs(
            &bundle,
            &[],
            None,
            Some(b"forged receipt"),
            Some(&pin),
            None,
            |_, _| Ok(signed.clone())
        )
        .unwrap_err()
        .predicate,
        "production_receipt"
    );
    assert_eq!(
        verify_report_with_inputs(&bundle, &[], None, None, Some(&pin), Some(&[0]), |_, _| Ok(
            signed.clone()
        ))
        .unwrap_err()
        .predicate,
        "supported_report"
    );
}

#[test]
fn migrated_capital_reproduces_hand_calculated_statements_and_requires_later_activation() {
    let (original, rates) = history();
    let body = super::migration::body(0, false);
    let run = super::migration::run();
    let mut records = original[..3].to_vec();
    records.push(super::migration::control(4, 0, run, &body));
    records.push(entry_with_migration(
        5,
        12,
        10,
        b"capital",
        &valued_pair("1000", "3000", 1000, 1100),
        Some((1, &rates[0], None)),
        None,
        None,
        Some(run),
    ));
    records.push(super::migration::control(6, 1, run, &body));
    records.extend(original[4..].iter().cloned().map(|mut record| {
        record.envelope.commit_seq += 2;
        record
    }));
    let bodies = [(3, body.as_slice())];
    for activity in [false, true] {
        for (known_at, later_sale) in [(13, 0), (14, 9990)] {
            let mut request = request(activity);
            request.known_at = known_at;
            // The independently written rows remain 1310/1100 assets and
            // 210/0 income before the later 9990 backdate, exactly as for
            // ordinary capital. Replacing its origin must not change value.
            let expected = expected(&request, later_sale);
            let output = output(&expected, &request);
            let (bundle, signed, pin) = pack_statement_with_migrations(
                &records,
                &request,
                &book(&[]),
                &rates,
                &output,
                &bodies,
            );
            let verified = verify(&bundle, &signed, &pin).unwrap();
            assert_eq!(verified.functional_statement, Some(expected));
            assert_eq!(verified.output, output);
            let (bundle, signed, pin) = pack_statement_with_migrations(
                &records,
                &request,
                &book(&[]),
                &rates,
                &output,
                &[],
            );
            assert!(verify(&bundle, &signed, &pin).is_err());
            // Reseal the complete prefix and certificate after moving Finalize
            // into the chunk's own publication. Membership and sequence order
            // remain valid, but this cannot activate an already published item.
            let mut same_publication = records.clone();
            same_publication[5].envelope.commit_seq = 5;
            same_publication[5].envelope.within_commit_ordinal = 1;
            let (bundle, signed, pin) = pack_statement_with_migrations(
                &same_publication,
                &request,
                &book(&[]),
                &rates,
                &output,
                &bodies,
            );
            assert_eq!(
                verify(&bundle, &signed, &pin).unwrap_err().predicate,
                "migration_visibility"
            );
        }
    }
}

#[test]
fn aggregate_revaluation_reproduces_hand_calculated_balance_sheet_and_income() {
    let (records, rates) = super::revaluation::history();
    for activity in [false, true] {
        let request = Request {
            activity,
            current: vec!["P1".into()],
            comparative: Vec::new(),
            known_at: 8,
        };
        let mut expected = expected(&request, 0);
        expected.statement.columns = vec![StatementColumn {
            label: "current".into(),
            periods: vec!["P1".into()],
            effective_from: activity.then_some(0),
            effective_through: 30,
        }];
        // EUR100 capital carried at110, then repriced to120: no new native
        // units, base valuation +10, unrealized income10 and total equity120.
        for line in &mut expected.statement.lines {
            line.amounts = vec![match line.code.as_str() {
                "assets" | "total_equity" | "liabilities_and_equity" => 120,
                "equity" => 110,
                "revenue" | "net_income" | "unclosed_revenue" | "unclosed_earnings" => 10,
                "liabilities" | "expense" | "unclosed_expense" | "balance_check" => 0,
                other => panic!("unexpected fixed definition line {other}"),
            }];
        }
        expected.statement.mappings = super::revaluation::chart()
            .into_iter()
            .filter(|(_, kind, _)| !activity || *kind == 4)
            .map(|(code, kind, _)| StatementMapping {
                account: id(code),
                code: code.into(),
                name: code.into(),
                account_type: kind,
                is_leaf: true,
                line_code: match (activity, kind) {
                    (true, 4) => "revenue",
                    (_, 1) => "assets",
                    (_, 3) => "equity",
                    (_, 4) => "unclosed_revenue",
                    _ => unreachable!(),
                }
                .into(),
            })
            .collect();
        let bytes = output(&expected, &request);
        let (bundle, signed, pin) = pack_statement(&records, &request, &book(&[]), &rates, &bytes);
        let verified = verify(&bundle, &signed, &pin).unwrap();
        assert_eq!(verified.functional_statement, Some(expected.clone()));
        expected.statement.lines[0].amounts[0] += 1;
        let (bundle, signed, pin) = pack_statement(
            &records,
            &request,
            &book(&[]),
            &rates,
            &output(&expected, &request),
        );
        assert!(
            verify(&bundle, &signed, &pin).is_err(),
            "a self-consistently resealed false line still fails independent recomputation"
        );
    }
}
