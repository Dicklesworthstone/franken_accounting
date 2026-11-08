//! Integration and conformance tests for `fa-formats` (plan §8.6, §9.5,
//! §12.1, §15.3, §15.9, §16.3, §18.1; bead `fa-npi`).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use fa_formats::{
    FormatAccount, FormatAssertion, FormatEntry, FormatError, FormatJournal, FormatLeg,
    UnitCatalog,
    ads::{read_ads_package, write_ads_package},
    bank::{parse_bai2, parse_camt053, parse_ofx_qbo, verify_statement_sequence_continuity},
    beancount::{
        SubprocessOracleStatus, compare_balances_exact, probe_external_oracle_binary,
        read_beancount, read_hledger, write_beancount, write_hledger,
    },
    conformance::{ConformanceMatrix, ConformanceRow},
    csv_gl::{read_csv_gl, verify_ndjson_gl_stream, write_csv_gl, write_ndjson_gl_stream},
    format_dimension_set, hex_encode, parse_dimension_set, parse_exact_decimal,
    saft::{read_saft_xml, write_saft_xml},
    tigerbeetle::TbCorpus,
    verify_round_trip_identity,
    xbrl::{
        XbrlCalculationLinkbase, XbrlFact, XbrlInstance, read_xbrl_instance_xml,
        validate_calculation_linkbase, validate_calculation_linkbase_detailed,
        verify_format_journal_xbrl_xml, write_format_journal_xbrl_xml, write_xbrl_instance_xml,
    },
};
use fa_model::{AccountType, EntryClass};
use fa_money::{Amount, Side, UnitId};
use fa_registry::Formats;
use fa_time::DateDay;

/// Render folded balances as `account:UNIT=±int.frac` at each unit's scale, in map order.
fn render_balances(balances: &BTreeMap<(String, String), i128>, units: &UnitCatalog) -> String {
    balances
        .iter()
        .map(|((account, unit), mantissa)| {
            let scale = units.lookup_code(unit).map_or(0, |(_, s)| usize::from(s));
            let sign = if *mantissa < 0 { '-' } else { '+' };
            let digits = format!("{:0>width$}", mantissa.unsigned_abs(), width = scale + 1);
            let (int, frac) = digits.split_at(digits.len() - scale);
            if scale == 0 {
                format!("{account}:{unit}={sign}{int}")
            } else {
                format!("{account}:{unit}={sign}{int}.{frac}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn sample_multi_unit_journal() -> FormatJournal {
    let d1 = DateDay::from_ymd(2026, 3, 10).expect("valid date");
    let d2 = DateDay::from_ymd(2026, 3, 15).expect("valid date");
    let d3 = DateDay::from_ymd(2026, 3, 25).expect("valid date");

    let accounts = vec![
        FormatAccount {
            code: "1000".to_owned(),
            name: "Operating Cash".to_owned(),
            account_type: AccountType::ASSET,
            normal_side: Side::Debit,
            roles: Vec::new(),
        },
        FormatAccount {
            code: "1010".to_owned(),
            name: "Euro Treasury Cash".to_owned(),
            account_type: AccountType::ASSET,
            normal_side: Side::Debit,
            roles: Vec::new(),
        },
        FormatAccount {
            code: "1200".to_owned(),
            name: "Accounts Receivable".to_owned(),
            account_type: AccountType::ASSET,
            normal_side: Side::Debit,
            roles: Vec::new(),
        },
        FormatAccount {
            code: "2000".to_owned(),
            name: "Accounts Payable".to_owned(),
            account_type: AccountType::LIABILITY,
            normal_side: Side::Credit,
            roles: Vec::new(),
        },
        FormatAccount {
            code: "3000".to_owned(),
            name: "Contributed Capital".to_owned(),
            account_type: AccountType::EQUITY,
            normal_side: Side::Credit,
            roles: Vec::new(),
        },
        FormatAccount {
            code: "4000".to_owned(),
            name: "Product Revenue".to_owned(),
            account_type: AccountType::REVENUE,
            normal_side: Side::Credit,
            roles: Vec::new(),
        },
        FormatAccount {
            code: "5000".to_owned(),
            name: "Cloud Hosting Expense".to_owned(),
            account_type: AccountType::EXPENSE,
            normal_side: Side::Debit,
            roles: Vec::new(),
        },
    ];

    let entries = vec![
        FormatEntry {
            entry_id: "E-0001".to_owned(),
            effective_date: d1,
            recorded_seq: 1,
            class: EntryClass::ORIGINAL,
            description: "Initial capital contribution in USD and EUR".to_owned(),
            migrated_from: None,
            legs: vec![
                FormatLeg {
                    dimensions: Vec::new(),
                    account_code: "1000".to_owned(),
                    side: Side::Debit,
                    amount: Amount::new(UnitId(0), 250_000),
                    unit_code: "USD".to_owned(),
                    unit_scale: 2,
                    memo: Some("Seed wire USD".to_owned()),
                },
                FormatLeg {
                    dimensions: Vec::new(),
                    account_code: "3000".to_owned(),
                    side: Side::Credit,
                    amount: Amount::new(UnitId(0), 250_000),
                    unit_code: "USD".to_owned(),
                    unit_scale: 2,
                    memo: None,
                },
                FormatLeg {
                    dimensions: Vec::new(),
                    account_code: "1010".to_owned(),
                    side: Side::Debit,
                    amount: Amount::new(UnitId(1), 100_000),
                    unit_code: "EUR".to_owned(),
                    unit_scale: 2,
                    memo: Some("Seed wire EUR".to_owned()),
                },
                FormatLeg {
                    dimensions: Vec::new(),
                    account_code: "3000".to_owned(),
                    side: Side::Credit,
                    amount: Amount::new(UnitId(1), 100_000),
                    unit_code: "EUR".to_owned(),
                    unit_scale: 2,
                    memo: None,
                },
            ],
        },
        FormatEntry {
            entry_id: "E-0002".to_owned(),
            effective_date: d2,
            recorded_seq: 2,
            class: EntryClass::ORIGINAL,
            description: "Customer invoice for enterprise subscription".to_owned(),
            migrated_from: None,
            legs: vec![
                FormatLeg {
                    dimensions: Vec::new(),
                    account_code: "1200".to_owned(),
                    side: Side::Debit,
                    amount: Amount::new(UnitId(0), 75_500),
                    unit_code: "USD".to_owned(),
                    unit_scale: 2,
                    memo: Some("INV-2026-042".to_owned()),
                },
                FormatLeg {
                    dimensions: Vec::new(),
                    account_code: "4000".to_owned(),
                    side: Side::Credit,
                    amount: Amount::new(UnitId(0), 75_500),
                    unit_code: "USD".to_owned(),
                    unit_scale: 2,
                    memo: None,
                },
            ],
        },
        FormatEntry {
            entry_id: "E-0003".to_owned(),
            effective_date: d3,
            recorded_seq: 3,
            class: EntryClass::ORIGINAL,
            description: "Vendor bill for March hosting".to_owned(),
            migrated_from: Some("LEGACY-QB-991".to_owned()),
            legs: vec![
                FormatLeg {
                    dimensions: Vec::new(),
                    account_code: "5000".to_owned(),
                    side: Side::Debit,
                    amount: Amount::new(UnitId(0), 18_250),
                    unit_code: "USD".to_owned(),
                    unit_scale: 2,
                    memo: None,
                },
                FormatLeg {
                    dimensions: Vec::new(),
                    account_code: "2000".to_owned(),
                    side: Side::Credit,
                    amount: Amount::new(UnitId(0), 18_250),
                    unit_code: "USD".to_owned(),
                    unit_scale: 2,
                    memo: None,
                },
            ],
        },
    ];

    let assertions = vec![
        FormatAssertion {
            account_code: "1000".to_owned(),
            as_of: d3,
            side: Side::Debit,
            amount: Amount::new(UnitId(0), 250_000),
            unit_code: "USD".to_owned(),
            unit_scale: 2,
        },
        FormatAssertion {
            account_code: "1010".to_owned(),
            as_of: d3,
            side: Side::Debit,
            amount: Amount::new(UnitId(1), 100_000),
            unit_code: "EUR".to_owned(),
            unit_scale: 2,
        },
        FormatAssertion {
            account_code: "1200".to_owned(),
            as_of: d3,
            side: Side::Debit,
            amount: Amount::new(UnitId(0), 75_500),
            unit_code: "USD".to_owned(),
            unit_scale: 2,
        },
    ];

    FormatJournal::new(
        "acme-fy2026-p03",
        "USD",
        2,
        d3,
        3,
        accounts,
        entries,
        assertions,
    )
    .expect("valid sample journal")
}

#[test]
fn embedded_formats_registry_matches_fa_formats_surface() {
    let formats = Formats::embedded().expect("registries/formats.toml must parse");
    assert_eq!(formats.rows.len(), 26);
    assert!(
        formats
            .by_name("aicpa_ads_gl_v2")
            .unwrap()
            .round_trip_identity
    );
    assert!(formats.by_name("oecd_saft_v2").unwrap().round_trip_identity);
    assert!(
        formats
            .by_name("aicpa_ads_gl_v3")
            .unwrap()
            .round_trip_identity
    );
    assert!(
        formats
            .by_name("aicpa_ads_gl_v4")
            .unwrap()
            .round_trip_identity
    );
    assert!(formats.by_name("csv_gl_v1").unwrap().round_trip_identity);
    assert_eq!(
        formats.by_name("beancount_v3").unwrap().oracle_tool,
        "bean-check"
    );
    assert_eq!(
        formats.by_name("hledger_journal").unwrap().oracle_tool,
        "hledger"
    );
    // Every bank statement reader `fa bank import --bank-format` reaches has
    // its row (fa-d22b): the names are the readers' own format_name values.
    for name in [
        "iso20022_camt053",
        "iso20022_camt052",
        "bai2_v2",
        "ofx_qbo_v2",
        "swift_mt940",
        "bank_csv_v1",
        "bank_csv_layout_v1",
        "fwc_plaid_transactions_sync_v1",
    ] {
        let row = formats
            .by_name(name)
            .unwrap_or_else(|| panic!("{name} has no formats.toml row"));
        assert_eq!(row.kind, "bank_statement", "{name}");
        assert_eq!(row.direction, "import", "{name}");
    }
}

#[test]
fn exact_decimal_parser_forbids_floats_and_excess_precision() {
    assert_eq!(parse_exact_decimal("test", "1234.56", 2).unwrap(), 123_456);
    assert_eq!(parse_exact_decimal("test", "-0.05", 2).unwrap(), -5);
    assert_eq!(parse_exact_decimal("test", "42", 2).unwrap(), 4_200);

    let float_err = parse_exact_decimal("test", "1.25e2", 2).unwrap_err();
    assert!(matches!(float_err, FormatError::FloatForbidden { .. }));

    let nan_err = parse_exact_decimal("test", "NaN", 2).unwrap_err();
    assert!(matches!(nan_err, FormatError::FloatForbidden { .. }));

    let scale_err = parse_exact_decimal("test", "10.123", 2).unwrap_err();
    assert!(matches!(scale_err, FormatError::ExactDecimal { .. }));
}

#[test]
fn beancount_and_hledger_balance_differential_and_one_minor_unit_mutation_negative() {
    let units = UnitCatalog::embedded().expect("units.toml");
    let journal = sample_multi_unit_journal();
    let fa_balances = journal.fold_balances().expect("fa fold");

    // 1. Beancount v3 write -> read -> balance differential
    let bc_text = write_beancount(&journal).expect("write_beancount");
    let bc_parsed = read_beancount(&bc_text, &units).expect("read_beancount");
    let bc_balances = bc_parsed.fold_balances().expect("bc fold");
    compare_balances_exact("acme-fy2026-p03", &fa_balances, &bc_balances)
        .expect("Beancount balances agree cell-by-cell");
    let bc_proof = verify_round_trip_identity("beancount_v3", &journal, &bc_parsed)
        .expect("Beancount round-trip identity");
    assert_eq!(bc_proof.entry_count, 3);
    assert_eq!(bc_proof.leg_count, 8);

    // 2. hledger write -> read -> balance differential
    let hl_text = write_hledger(&journal);
    let hl_parsed = read_hledger(&hl_text, &units).expect("read_hledger");
    let hl_balances = hl_parsed.fold_balances().expect("hledger fold");
    compare_balances_exact("acme-fy2026-p03", &fa_balances, &hl_balances)
        .expect("hledger balances agree cell-by-cell");

    // The differential above is a self round-trip through fa-formats' own
    // writers and readers. The external tools are only probed for presence;
    // neither evaluates these journals (fa-sa4w).
    for bin in ["bean-check", "hledger"] {
        match probe_external_oracle_binary(bin) {
            SubprocessOracleStatus::Present { binary, version } => {
                println!("external oracle {binary}: present ({version}), not evaluated");
            }
            SubprocessOracleStatus::Unrun { binary, reason } => {
                println!("external oracle {binary}: UNRUN ({reason})");
            }
        }
    }

    // 3. Planted negative (bead fa-npi requirement):
    // Mutating an hledger balance by 1 minor unit fails the differential naming the account!
    let mut mutated_hl_balances = hl_balances.clone();
    *mutated_hl_balances
        .get_mut(&("1200".to_owned(), "USD".to_owned()))
        .expect("account 1200 USD present") += 1;
    let err = compare_balances_exact("acme-fy2026-p03", &fa_balances, &mutated_hl_balances)
        .expect_err("1 minor unit mutation must fail differential");
    match &err {
        FormatError::DifferentialMismatch {
            fixture,
            account_code,
            unit_code,
            expected,
            observed,
        } => {
            assert_eq!(fixture, "acme-fy2026-p03");
            assert_eq!(account_code, "1200");
            assert_eq!(unit_code, "USD");
            assert_eq!(*expected, 75_500);
            assert_eq!(*observed, 75_501);
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
    println!("judged planted hledger +1 minor-unit mutation: refused ({err}), naming account 1200");
}

#[test]
fn saft_and_xbrl_keep_text_whitespace_exactly() {
    let units = UnitCatalog::embedded().expect("units.toml");
    for inline in [
        "prefix <!-- fa:xbrl-coordinate x -->",
        "<!-- wrapper <!-- fa:xbrl-coordinate x --> -->",
    ] {
        assert!(fa_formats::xbrl::read_xbrl_equity_attribution(inline).is_err());
        assert!(fa_formats::xbrl::read_xbrl_income_attribution(inline).is_err());
    }
    for book_name in [
        "  Acme  ",
        "\tAcme & <Co> \"suite\"\t",
        "\nAcme\r\nBooks\n",
        "\u{a0}Acme\u{2003}",
    ] {
        let mut source = sample_multi_unit_journal();
        source.accounts[0].name = "\t Asset & \"cash\" \n".into();
        source.entries[0].description = "\t description & <tag> \"quoted\" '\n".into();
        source.entries[0].migrated_from = Some(" \tLEGACY & item\n ".into());
        source.entries[0].legs[0].memo = Some("  memo text\t\n ".into());
        // Construct a certificate for the new input, never alter a written
        // artifact's digest to make a lossy read appear to match.
        let journal = FormatJournal::new(
            book_name,
            &source.coordinate.base_unit_code,
            source.coordinate.base_unit_scale,
            source.coordinate.effective_through,
            source.coordinate.known_at_seq,
            source.accounts,
            source.entries,
            source.assertions,
        )
        .unwrap();

        let saft = write_saft_xml(&journal).unwrap();
        let parsed = read_saft_xml(&saft, &units).unwrap();
        assert_eq!(parsed, journal, "SAF-T text for {book_name:?}");
        assert_eq!(write_saft_xml(&parsed).unwrap(), saft);
        verify_round_trip_identity("oecd_saft_v2", &journal, &parsed).unwrap();
        let changed = saft.replacen("<Memo>  memo text\t\n </Memo>", "<Memo>memo text</Memo>", 1);
        assert_ne!(changed, saft);
        assert!(matches!(
            read_saft_xml(&changed, &units),
            Err(FormatError::CertificateMismatch { .. })
        ));

        // XBRL carries the book identifier and coordinate, not the complete
        // journal's descriptions and memos. Do not claim their reconstruction.
        let xbrl = write_format_journal_xbrl_xml(&journal).unwrap();
        let instance = read_xbrl_instance_xml(&xbrl).unwrap();
        assert_eq!(instance.entity_identifier, book_name);
        let (coordinate, report) = verify_format_journal_xbrl_xml(&xbrl).unwrap();
        assert_eq!(coordinate, journal.coordinate);
        assert!(report.checks_passed > 0);
        assert!(
            report
                .rows
                .iter()
                .all(|row| row.passed && row.delta_mantissa == 0)
        );

        let commented = xbrl.replacen(
            '\n',
            "\n<!-- <xbrli:identifier scheme=\"http://frankenaccounting.org/entity\">spoof</xbrli:identifier> -->\n",
            1,
        );
        assert_eq!(
            read_xbrl_instance_xml(&commented)
                .unwrap()
                .entity_identifier,
            book_name
        );
        assert!(verify_format_journal_xbrl_xml(&commented).is_err());

        let start = xbrl.find("<!-- fa:xbrl-coordinate ").unwrap();
        let end = start + xbrl[start..].find("-->").unwrap() + 3;
        let duplicated = format!("{xbrl}{}\n", &xbrl[start..end]);
        let error = verify_format_journal_xbrl_xml(&duplicated).unwrap_err();
        assert!(matches!(error, FormatError::Parse { ref detail, .. }
            if detail.contains("multiple fa:xbrl-coordinate")));
        let unterminated = xbrl.replacen(" -->\n", "\n", 1);
        assert_ne!(unterminated, xbrl);
        assert!(verify_format_journal_xbrl_xml(&unterminated).is_err());

        if book_name == "  Acme  " {
            let changed = xbrl.replacen("book_name=\"  Acme  \"", "book_name=\"Acme\"", 1);
            assert_ne!(changed, xbrl);
            assert!(matches!(
                verify_format_journal_xbrl_xml(&changed),
                Err(FormatError::CertificateMismatch { .. })
            ));
        }
    }
}

#[test]
fn saft_dimension_element_names_in_text_are_not_extension_markup() {
    let units = UnitCatalog::embedded().unwrap();
    for literal in [
        "fa:DimensionSetV1",
        "fa:DimensionEncoding",
        "<fa:DimensionSetV1>literal</fa:DimensionSetV1>",
        "<fa:DimensionEncoding>fa-dimension-ids-v1</fa:DimensionEncoding>",
        "fa:DimensionSetV1 > literal",
        "fa:DimensionEncoding > literal",
    ] {
        let mut source = sample_multi_unit_journal();
        let text = format!("  {literal}\n");
        source.accounts[0].name = text.clone();
        source.entries[0].description = text.clone();
        source.entries[0].migrated_from = Some(text.clone());
        source.entries[0].legs[0].memo = Some(text.clone());
        let journal = FormatJournal::new(
            &text,
            &source.coordinate.base_unit_code,
            source.coordinate.base_unit_scale,
            source.coordinate.effective_through,
            source.coordinate.known_at_seq,
            source.accounts,
            source.entries,
            source.assertions,
        )
        .unwrap();
        let xml = write_saft_xml(&journal).unwrap();
        assert!(!xml.contains("xmlns:fa="));
        let restored = read_saft_xml(&xml, &units).unwrap();
        assert_eq!(restored, journal, "literal text {literal:?}");
        assert_eq!(write_saft_xml(&restored).unwrap(), xml);
        verify_round_trip_identity("oecd_saft_v2", &journal, &restored).unwrap();
        let raw_greater_than = xml.replace("&gt;", ">");
        if raw_greater_than != xml {
            let restored = read_saft_xml(&raw_greater_than, &units).unwrap();
            assert_eq!(restored, journal, "raw > in literal text {literal:?}");
            assert_eq!(write_saft_xml(&restored).unwrap(), xml);
            verify_round_trip_identity("oecd_saft_v2", &journal, &restored).unwrap();
        }
    }

    // Raw dimension markup still requires the registered Header declaration,
    // including self-closing and orphaned closing tags our scalar readers
    // would otherwise ignore. Keep the original certificate unchanged.
    let xml = write_saft_xml(&sample_multi_unit_journal()).unwrap();
    for markup in [
        "<fa:DimensionSetV1>3:000000000000000000000000000000ab</fa:DimensionSetV1>",
        "<fa:DimensionEncoding>fa-dimension-ids-v1</fa:DimensionEncoding>",
        "<fa:DimensionSetV1/>",
        "<fa:DimensionEncoding/>",
        "</fa:DimensionSetV1>",
        "</fa:DimensionEncoding>",
        "<extra fa:DimensionSetV1=\"ignored\"/>",
        "<extra fa:DimensionEncoding=\"ignored\"/>",
        "<extra before='>' fa:DimensionSetV1='ignored'/>",
        "<extra before='>' fa:DimensionEncoding='ignored'/>",
        "<extra before=\">\" fa:DimensionSetV1=\"ignored\"/>",
        "<extra before=\">\" fa:DimensionEncoding=\"ignored\"/>",
        r#"<extra before="'>'" fa:DimensionSetV1="ignored"/>"#,
        r#"<extra before='">"' fa:DimensionEncoding='ignored'/>"#,
        "<extra before='>' fa:DimensionSetV1='ignored'/",
        "<extra before=\">\" fa:DimensionEncoding=\"ignored\"/",
    ] {
        let changed = xml.replacen("</Line>", &format!("{markup}</Line>"), 1);
        assert_ne!(changed, xml);
        assert!(matches!(
            read_saft_xml(&changed, &units),
            Err(FormatError::Parse { ref detail, .. })
                if detail == "dimension elements require the registered encoding in Header"
        ));
    }
}

#[test]
fn saft_dates_normalize_xml_whitespace_but_refuse_signed_tokens() {
    let units = UnitCatalog::embedded().unwrap();
    let journal = sample_multi_unit_journal();
    let canonical = write_saft_xml(&journal).unwrap();
    let mut padded = canonical.clone();
    for tag in ["SelectionEndDate", "AsOfDate", "TransactionDate"] {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        assert!(padded.contains(&open) && padded.contains(&close));
        padded = padded.replacen(&open, &format!("{open}\n \t"), 1).replacen(
            &close,
            &format!("\r\n {close}"),
            1,
        );

        let date = canonical
            .split_once(&open)
            .unwrap()
            .1
            .split_once(&close)
            .unwrap()
            .0;
        let changed = canonical.replacen(
            &format!("{open}{date}{close}"),
            &format!("{open}{}-+1-+5{close}", &date[..4]),
            1,
        );
        assert_ne!(changed, canonical);
        assert!(matches!(
            read_saft_xml(&changed, &units),
            Err(FormatError::Parse { ref detail, .. })
                if detail.contains("invalid YYYY-MM-DD date")
        ));
    }
    let restored = read_saft_xml(&padded, &units).unwrap();
    assert_eq!(restored, journal);
    assert_eq!(write_saft_xml(&restored).unwrap(), canonical);
    verify_round_trip_identity("oecd_saft_v2", &journal, &restored).unwrap();
}

#[test]
fn aicpa_ads_and_oecd_saft_and_csv_gl_round_trip_identity_and_dropped_leg_negative() {
    let units = UnitCatalog::embedded().expect("units.toml");
    let journal = sample_multi_unit_journal();

    // 1. AICPA ADS export -> import round-trip identity + FA-INV-04 refold
    let ads_pkg = write_ads_package(&journal).expect("write_ads_package");
    assert!(
        ads_pkg
            .certificate_toml
            .contains("format = \"aicpa_ads_gl_v2\"")
    );
    let ads_reimported = read_ads_package(&ads_pkg, &units).expect("read_ads_package");
    let ads_proof = verify_round_trip_identity("aicpa_ads_gl_v2", &journal, &ads_reimported)
        .expect("ADS export-import identity");
    assert_eq!(
        ads_proof.refold_digest,
        journal.refold_digest().expect("refold digest")
    );
    println!(
        "judged AICPA ADS round-trip: cert={} refold={}",
        hex_encode(&ads_proof.coordinate_digest),
        hex_encode(&ads_proof.refold_digest)
    );

    // Planted negative (bead fa-npi requirement):
    // Dropping a leg from ADS GL_Detail fails round-trip / balance check!
    let mut dropped_ads = ads_pkg.clone();
    let mut gl_lines: Vec<&str> = ads_pkg.gl_detail.lines().collect();
    gl_lines.pop(); // drop the final credit leg of E-0003
    dropped_ads.gl_detail = format!("{}\n", gl_lines.join("\n"));
    let drop_err = read_ads_package(&dropped_ads, &units)
        .expect_err("ADS export with a dropped leg must fail");
    assert!(
        matches!(drop_err, FormatError::UnbalancedEntry { .. }),
        "expected UnbalancedEntry on dropped leg, got {drop_err:?}"
    );
    println!("judged planted ADS dropped-leg negative: refused ({drop_err})");

    // 2. OECD SAF-T v2.0 XML export -> import round-trip identity + FA-INV-04 refold
    let saft_xml = write_saft_xml(&journal).expect("write_saft_xml");
    let saft_reimported = read_saft_xml(&saft_xml, &units).expect("read_saft_xml");
    let saft_proof = verify_round_trip_identity("oecd_saft_v2", &journal, &saft_reimported)
        .expect("SAF-T export-import identity");
    assert_eq!(
        saft_proof.canonical_journal_digest,
        ads_proof.canonical_journal_digest
    );
    assert_eq!(saft_proof.refold_digest, ads_proof.refold_digest);
    println!(
        "judged OECD SAF-T v2.0 round-trip: cert={} refold={}",
        hex_encode(&saft_proof.coordinate_digest),
        hex_encode(&saft_proof.refold_digest)
    );

    // Planted negative: dropping an entire balanced entry in SAF-T fails NumberOfEntries / CertificateMismatch
    let mutated_saft = saft_xml.replacen(
        "<CreditAmount>182.50</CreditAmount>",
        "<CreditAmount>182.00</CreditAmount>",
        1,
    );
    let saft_err =
        read_saft_xml(&mutated_saft, &units).expect_err("SAF-T with tampered leg amount must fail");
    assert!(matches!(saft_err, FormatError::UnbalancedEntry { .. }));

    // 3. CSV GL extract -> import round-trip + NDJSON GL stream verification
    let csv_text = write_csv_gl(&journal);
    let csv_reimported = read_csv_gl(&csv_text, &units).expect("read_csv_gl");
    assert_eq!(
        csv_reimported.fold_balances().unwrap(),
        journal.fold_balances().unwrap()
    );

    let ndjson = write_ndjson_gl_stream(&journal).expect("write_ndjson_gl_stream");
    let streamed_rows = verify_ndjson_gl_stream(&ndjson).expect("verify_ndjson_gl_stream");
    assert_eq!(streamed_rows, 8);
}

#[test]
fn csv_gl_round_trip_preserves_real_world_text_and_escaped_metadata() {
    let units = UnitCatalog::embedded().unwrap();
    let original = sample_multi_unit_journal();
    let mut accounts = original.accounts.clone();
    accounts[0].name = "  Cash | Treasury, \"North\"\r\nCafé  ".into();
    accounts[1].name = "Literal %7C and %0A remain literal".into();
    let mut entries = original.entries.clone();
    entries[0].entry_id = "# invoice,\"2025\"".into();
    entries[0].description = "  Supplier, \"North\"\r\n# line two  ".into();
    entries[0].migrated_from = Some("source,1\nledger | 2025".into());
    entries[0].legs[0].memo = Some("invoice, tax\r\nallocation \"A\"".into());
    entries[0].legs[1].memo = Some(" trailing space ".into());
    let c = &original.coordinate;
    let journal = FormatJournal::new(
        "Public | records\nFY2025 % archive",
        &c.base_unit_code,
        c.base_unit_scale,
        c.effective_through,
        c.known_at_seq,
        accounts,
        entries,
        original.assertions.clone(),
    )
    .unwrap();
    let csv = write_csv_gl(&journal);
    assert!(csv.starts_with("# fa_csv_text_encoding_v1|percent-utf8\n"));
    let restored = read_csv_gl(&csv, &units).expect("quoted source text survives extraction");
    verify_round_trip_identity("csv_gl_v1", &journal, &restored).unwrap();
    assert_eq!(restored.coordinate, journal.coordinate);
    assert_eq!(restored.accounts, journal.accounts);
    assert_eq!(restored.entries, journal.entries);
    assert_eq!(write_csv_gl(&restored), csv, "canonical output is stable");
    for bad in [
        csv.replacen("Public%20", "Public%GG", 1),
        csv.replacen("Public%20", "Public%FF", 1),
        csv.replacen("percent-utf8", "unknown", 1),
        format!("# fa_csv_text_encoding_v1|percent-utf8\n{csv}"),
    ] {
        read_csv_gl(&bad, &units).expect_err("invalid or repeated metadata codec is refused");
    }
    let plain = write_csv_gl(&original);
    assert!(plain.starts_with("# fa_csv_gl_v1|"));
    verify_round_trip_identity(
        "csv_gl_v1",
        &original,
        &read_csv_gl(&plain, &units).unwrap(),
    )
    .unwrap();
}

#[test]
fn csv_and_beancount_cannot_downgrade_original_coordinate_verification() {
    let units = UnitCatalog::embedded().unwrap();
    let journal = sample_multi_unit_journal();
    let mut entries = journal.entries.clone();
    // Change both sides of the first USD posting by one cent. The amended
    // journal is balanced and valid in its own right, but is not the original.
    for leg in &mut entries[0].legs[..2] {
        assert_eq!(leg.amount.mantissa, 250_000);
        leg.amount.mantissa = 250_001;
    }
    let mut assertions = journal.assertions.clone();
    let cash = assertions
        .iter_mut()
        .find(|assertion| assertion.account_code == "1000" && assertion.unit_code == "USD")
        .unwrap();
    assert_eq!(cash.amount.mantissa, 250_000);
    cash.amount.mantissa = 250_001;
    let c = &journal.coordinate;
    let amended = FormatJournal::new(
        &c.book_name,
        &c.base_unit_code,
        c.base_unit_scale,
        c.effective_through,
        c.known_at_seq,
        journal.accounts.clone(),
        entries,
        assertions,
    )
    .unwrap();
    let original_content = hex_encode(&c.content_digest);
    let original_certificate = hex_encode(&c.certificate_digest);
    let amended_content = hex_encode(&amended.coordinate.content_digest);
    let amended_certificate = hex_encode(&amended.coordinate.certificate_digest);
    assert_ne!(original_content, amended_content);
    assert_ne!(original_certificate, amended_certificate);

    for (format, original, revised, content_field, certificate_field) in [
        (
            "csv_gl_v1",
            write_csv_gl(&journal),
            write_csv_gl(&amended),
            format!("|content_digest={original_content}"),
            format!("|certificate_digest={original_certificate}"),
        ),
        (
            "beancount_v3",
            write_beancount(&journal).unwrap(),
            write_beancount(&amended).unwrap(),
            format!("; fa_content_digest: {original_content}\n"),
            format!("; fa_certificate_digest: {original_certificate}\n"),
        ),
    ] {
        let read = |text: &str| {
            if format == "csv_gl_v1" {
                read_csv_gl(text, &units)
            } else {
                read_beancount(text, &units)
            }
        };
        for (text, expected) in [(&original, &journal), (&revised, &amended)] {
            let restored = read(text).unwrap();
            assert_eq!(&restored, expected, "{format}");
            verify_round_trip_identity(format, expected, &restored).unwrap();
        }
        let tampered = revised
            .replace(&amended_content, &original_content)
            .replace(&amended_certificate, &original_certificate);
        assert_ne!(tampered, original);
        assert_ne!(tampered, revised);
        assert!(matches!(
            read(&tampered),
            Err(FormatError::CertificateMismatch { .. })
        ));

        for text in [&original, &tampered] {
            for (remove_content, remove_certificate) in [(true, false), (false, true), (true, true)]
            {
                let mut stripped = text.clone();
                if remove_content {
                    assert!(stripped.contains(&content_field));
                    stripped = stripped.replace(&content_field, "");
                }
                if remove_certificate {
                    assert!(stripped.contains(&certificate_field));
                    stripped = stripped.replace(&certificate_field, "");
                }
                assert_ne!(&stripped, text);
                assert!(
                    matches!(
                        read(&stripped),
                        Err(FormatError::Parse { format: actual, ref detail })
                            if actual == format && detail.contains("must be supplied together")
                    ),
                    "{format}: removed content={remove_content}, certificate={remove_certificate}"
                );
            }
        }
    }
}

#[test]
fn csv_gl_refuses_changed_row_identity_and_truncated_certificate_metadata() {
    let units = UnitCatalog::embedded().unwrap();
    let source = write_csv_gl(&sample_multi_unit_journal());
    let first = source
        .lines()
        .find(|line| line.starts_with("E-0001,"))
        .unwrap();
    let columns = first.split(',').collect::<Vec<_>>();
    assert_eq!(columns.len(), 13);
    for (column, replacement, expected) in [
        (1, "2", "consecutive line_no"),
        (9, "3", "registered scale"),
    ] {
        let mut changed = columns.clone();
        changed[column] = replacement;
        let bad = source.replacen(first, &changed.join(","), 1);
        let error = read_csv_gl(&bad, &units).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
    // The second leg must repeat its entry metadata, even if that field
    // would have been ignored by the old first-row-wins decoder.
    let second = source
        .lines()
        .find(|line| line.starts_with("E-0001,2,"))
        .unwrap();
    let mut changed = second.split(',').collect::<Vec<_>>();
    changed[10] = "substituted narration";
    let bad = source.replacen(second, &changed.join(","), 1);
    let error = read_csv_gl(&bad, &units).unwrap_err();
    assert!(
        error.to_string().contains("conflicting metadata"),
        "{error}"
    );

    let bad = source.replacen("|entries=3|", "|entries=4|", 1);
    assert_ne!(bad, source);
    let error = read_csv_gl(&bad, &units).unwrap_err();
    assert!(error.to_string().contains("header declares 4"), "{error}");
    let first_line = source.lines().next().unwrap();
    let truncated = first_line.split("|certificate_digest=").next().unwrap();
    let bad = source.replacen(first_line, truncated, 1);
    let error = read_csv_gl(&bad, &units).unwrap_err();
    assert!(
        error.to_string().contains("must be supplied together"),
        "{error}"
    );
    // A declared coordinate is evidence, not a default that later rows may
    // silently repair back to the original certified date.
    let bad = source.replacen(
        "effective_through=2026-03-25",
        "effective_through=2026-03-01",
        1,
    );
    assert_ne!(bad, source);
    assert!(matches!(
        read_csv_gl(&bad, &units).unwrap_err(),
        FormatError::CertificateMismatch { .. }
    ));
}

#[test]
fn csv_gl_distinguishes_empty_optional_text_from_absent_text() {
    let units = UnitCatalog::embedded().unwrap();
    let original = sample_multi_unit_journal();
    let mut entries = original.entries.clone();
    entries[0].migrated_from = Some(String::new());
    entries[0].legs[0].memo = Some(String::new());
    entries[0].legs[1].memo = Some("occupied".into());
    entries[1].migrated_from = None;
    entries[1].legs[0].memo = None;
    let c = &original.coordinate;
    let journal = FormatJournal::new(
        &c.book_name,
        &c.base_unit_code,
        c.base_unit_scale,
        c.effective_through,
        c.known_at_seq,
        original.accounts.clone(),
        entries,
        original.assertions.clone(),
    )
    .unwrap();
    let source = write_csv_gl(&journal);
    let migrated = "# fa_csv_empty_optional_v1|1|0|migrated_from\n";
    let memo = "# fa_csv_empty_optional_v1|1|1|memo\n";
    assert!(source.contains(migrated));
    assert!(source.contains(memo));
    let restored = read_csv_gl(&source, &units).unwrap();
    verify_round_trip_identity("csv_gl_v1", &journal, &restored).unwrap();
    assert_eq!(restored.entries, journal.entries);
    assert_eq!(write_csv_gl(&restored), source);
    for bad in [
        source.replace(migrated, ""),
        source.replace(memo, ""),
        source.replace(memo, &format!("{memo}{memo}")),
        source.replace(memo, "# fa_csv_empty_optional_v1|99|1|memo\n"),
        source.replace(memo, "# fa_csv_empty_optional_v1|1|99|memo\n"),
        source.replace(memo, "# fa_csv_empty_optional_v1|1|0|memo\n"),
        source.replace(memo, "# fa_csv_empty_optional_v1|1|2|memo\n"),
        format!("{}{memo}", source.replace(memo, "")),
    ] {
        read_csv_gl(&bad, &units)
            .expect_err("ambiguous or substituted optional text must not verify");
    }
}

#[test]
fn canonical_csv_round_trip_preserves_quoted_source_text() {
    let units = UnitCatalog::embedded().unwrap();
    let original = sample_multi_unit_journal();
    let plain = write_csv_gl(&original);
    assert_eq!(write_csv_gl(&read_csv_gl(&plain, &units).unwrap()), plain);
    let mut entries = original.entries.clone();
    entries[0].entry_id = "#journal, \"one\"".into();
    entries[0].description =
        "  Café, \"entry\"\r\n# fa_account|injected|Bad|Asset|D\ncontinued  ".into();
    entries[0].migrated_from = Some("Old,GL\nsource".into());
    entries[0].legs[0].memo = Some(" memo\t\"quoted\", value\r\nsecond ".into());
    let journal = FormatJournal::new(
        &original.coordinate.book_name,
        &original.coordinate.base_unit_code,
        original.coordinate.base_unit_scale,
        original.coordinate.effective_through,
        original.coordinate.known_at_seq,
        original.accounts.clone(),
        entries,
        original.assertions.clone(),
    )
    .unwrap();
    let csv = write_csv_gl(&journal);
    let marker = "\"#journal, \"\"one\"\"\"";
    assert!(csv.contains(marker));
    let read = read_csv_gl(&csv, &units).unwrap();
    assert_eq!(
        read, journal,
        "all text and the original certificate survive"
    );
    verify_round_trip_identity("csv_gl_v1", &journal, &read).unwrap();
    assert_eq!(write_csv_gl(&read), csv);
    let malformed = csv.replacen(marker, &format!("{marker}suffix"), 1);
    assert!(matches!(
        read_csv_gl(&malformed, &units),
        Err(FormatError::Parse { .. })
    ));
    let changed = csv.replacen("Café", "Changed", 1);
    assert!(
        read_csv_gl(&changed, &units).is_err(),
        "changed source text must not retain its certificate"
    );
}

#[test]
fn canonical_csv_accepts_certified_old_unquoted_whitespace() {
    let units = UnitCatalog::embedded().unwrap();
    let original = sample_multi_unit_journal();
    let mut entries = original.entries.clone();
    entries[0].description = "  Historical memo  ".into();
    entries[0].migrated_from = Some("  Source export  ".into());
    let c = &original.coordinate;
    let journal = FormatJournal::new(
        &c.book_name,
        &c.base_unit_code,
        c.base_unit_scale,
        c.effective_through,
        c.known_at_seq,
        original.accounts,
        entries,
        original.assertions,
    )
    .unwrap();
    let modern = write_csv_gl(&journal);
    // The old writer left middle-field whitespace unquoted; its original
    // reader retained it and its certificate therefore binds that text.
    let historical = modern
        .replace("\"  Historical memo  \"", "  Historical memo  ")
        .replace("\"  Source export  \"", "  Source export  ");
    assert_ne!(historical, modern);
    assert_eq!(read_csv_gl(&historical, &units).unwrap(), journal);
}

#[test]
fn canonical_csv_old_literal_quotes_require_the_original_complete_certificate() {
    let units = UnitCatalog::embedded().unwrap();
    for description in ["He said \"hold\"", "\"archive\""] {
        let original = sample_multi_unit_journal();
        let mut entries = original.entries.clone();
        entries[0].description = description.into();
        let c = &original.coordinate;
        let journal = FormatJournal::new(
            &c.book_name,
            &c.base_unit_code,
            c.base_unit_scale,
            c.effective_through,
            c.known_at_seq,
            original.accounts,
            entries,
            original.assertions,
        )
        .unwrap();
        let modern = write_csv_gl(&journal);
        let escaped = format!("\"{}\"", description.replace('"', "\"\""));
        let historical = modern.replace(&escaped, description);
        assert_ne!(historical, modern);
        assert_eq!(read_csv_gl(&historical, &units).unwrap(), journal);
        let changed = historical.replace(description, &format!("{description} changed"));
        assert!(read_csv_gl(&changed, &units).is_err());

        if description == "He said \"hold\"" {
            // Interior unescaped quotes are invalid strict CSV. A fallback
            // must not accept them with either original digest missing.
            for field in [
                format!(
                    "|content_digest={}",
                    hex_encode(&journal.coordinate.content_digest)
                ),
                format!(
                    "|certificate_digest={}",
                    hex_encode(&journal.coordinate.certificate_digest)
                ),
            ] {
                let uncertified = historical.replace(&field, "");
                assert_ne!(uncertified, historical);
                assert!(read_csv_gl(&uncertified, &units).is_err());
            }
        }
    }
}

#[test]
fn canonical_csv_never_hides_changed_repeated_metadata_or_ignored_columns() {
    let units = UnitCatalog::embedded().unwrap();
    let journal = sample_multi_unit_journal();
    let csv = write_csv_gl(&journal);
    for column in [1, 2, 3, 4, 9, 10, 11] {
        let mut lines: Vec<_> = csv.lines().map(str::to_owned).collect();
        let row = lines
            .iter_mut()
            .find(|row| row.starts_with("E-0001,2,"))
            .unwrap();
        let mut fields: Vec<_> = row.split(',').map(str::to_owned).collect();
        fields[column] = "changed\"forged".into();
        *row = fields.join(",");
        let changed = lines.join("\n");
        assert!(read_csv_gl(&changed, &units).is_err(), "column {column}");
    }
    // Even syntactically valid redundant fields must agree.
    for (column, value) in [(1, "1"), (9, "3"), (10, "Different description")] {
        let mut lines: Vec<_> = csv.lines().map(str::to_owned).collect();
        let row = lines
            .iter_mut()
            .find(|row| row.starts_with("E-0001,2,"))
            .unwrap();
        let mut fields: Vec<_> = row.split(',').map(str::to_owned).collect();
        fields[column] = value.into();
        *row = fields.join(",");
        assert!(
            read_csv_gl(&lines.join("\n"), &units).is_err(),
            "column {column}"
        );
    }
}

fn dimensioned_journal() -> FormatJournal {
    let original = sample_multi_unit_journal();
    let mut entries = original.entries.clone();
    entries[0].legs[0].dimensions = vec![(3, 0xab), (7, u128::MAX)];
    entries[0].legs[1].dimensions = vec![(3, 0xac)];
    entries[1].legs[0].dimensions = vec![(3, 0xab)];
    let c = &original.coordinate;
    FormatJournal::new(
        &c.book_name,
        &c.base_unit_code,
        c.base_unit_scale,
        c.effective_through,
        c.known_at_seq,
        original.accounts,
        entries,
        original.assertions,
    )
    .unwrap()
}

#[test]
fn csv_gl_dimensions_text_metadata_and_empty_optionals_share_one_lossless_profile() {
    let units = UnitCatalog::embedded().unwrap();
    let original = dimensioned_journal();
    let mut accounts = original.accounts.clone();
    accounts[0].name = "  Cash | Treasury, \"North\"\r\nCafé  ".into();
    let mut entries = original.entries.clone();
    entries[0].entry_id = "# allocation,\"2026\"".into();
    entries[0].description = concat!(
        "  Café, \"allocation\"\r\n",
        "# fa_csv_gl_v1|dimension_encoding=not-a-declaration\n",
        "# fa_csv_empty_optional_v1|99|1|memo\r\n",
        "retained source text  "
    )
    .into();
    entries[0].migrated_from = Some(String::new());
    entries[0].legs[0].memo = Some(String::new());
    entries[0].legs[1].memo = Some("  split, \"B\"\r\n# memo continuation  ".into());
    entries[0].legs[2].memo = None;
    entries[1].migrated_from = Some("Old,GL\nsource | retained".into());
    let c = &original.coordinate;
    let journal = FormatJournal::new(
        "Dimensioned | records\nFY2026 % archive",
        &c.base_unit_code,
        c.base_unit_scale,
        c.effective_through,
        c.known_at_seq,
        accounts,
        entries,
        original.assertions.clone(),
    )
    .unwrap();
    let csv = write_csv_gl(&journal);
    let text_encoding = "# fa_csv_text_encoding_v1|percent-utf8\n";
    let dimension_encoding = "|dimension_encoding=fa-dimension-ids-v1";
    let empty_migrated = "# fa_csv_empty_optional_v1|1|0|migrated_from\n";
    let empty_memo = "# fa_csv_empty_optional_v1|1|1|memo\n";
    assert!(csv.starts_with(text_encoding));
    assert!(csv.contains(dimension_encoding));
    assert!(csv.contains(empty_migrated));
    assert!(csv.contains(empty_memo));
    assert!(csv.contains(",dimension_set_v1\n"));
    let restored = read_csv_gl(&csv, &units).expect("all three CSV extensions compose");
    assert_eq!(
        restored, journal,
        "every source field and exact dimension ID survives"
    );
    verify_round_trip_identity("csv_gl_v1", &journal, &restored).unwrap();
    assert_eq!(
        write_csv_gl(&restored),
        csv,
        "combined encoding is deterministic"
    );
    assert!(restored.entries[0].legs[2].dimensions.is_empty());
    assert_eq!(restored.entries[0].legs[2].memo, None);

    let wire = format_dimension_set(&journal.entries[0].legs[0].dimensions);
    let header = csv
        .lines()
        .find(|line| line.starts_with("entry_id,"))
        .unwrap();
    let without_certificates = csv
        .replace(
            &format!(
                "|content_digest={}",
                hex_encode(&journal.coordinate.content_digest)
            ),
            "",
        )
        .replace(
            &format!(
                "|certificate_digest={}",
                hex_encode(&journal.coordinate.certificate_digest)
            ),
            "",
        );
    for (case, changed) in [
        (
            "changed dimension ID",
            csv.replacen(&wire, &wire.replace("000ab", "000ad"), 1),
        ),
        (
            "missing dimension declaration",
            csv.replace(dimension_encoding, ""),
        ),
        ("missing metadata codec", csv.replace(text_encoding, "")),
        (
            "lost empty migration provenance",
            csv.replace(empty_migrated, ""),
        ),
        ("lost empty leg memo", csv.replace(empty_memo, "")),
        (
            "duplicate empty marker",
            csv.replace(empty_memo, &format!("{empty_memo}{empty_memo}")),
        ),
        ("repeated column header", format!("{csv}{header}\n")),
        ("uncertified dimensions", without_certificates),
    ] {
        assert_ne!(changed, csv, "{case} must change the retained source");
        assert!(read_csv_gl(&changed, &units).is_err(), "{case}");
    }
}

#[test]
fn dimension_set_wire_is_bounded_exact_and_never_repairs_invalid_order() {
    let canonical = "3:000000000000000000000000000000ab;7:ffffffffffffffffffffffffffffffff";
    let dimensions = vec![(3, 0xab), (7, u128::MAX)];
    assert_eq!(format_dimension_set(&dimensions), canonical);
    assert_eq!(parse_dimension_set(canonical).unwrap(), dimensions);
    assert_eq!(parse_dimension_set("").unwrap(), Vec::new());
    assert_eq!(format_dimension_set(&[]), "");
    for bad in [
        "03:000000000000000000000000000000ab",
        "+3:000000000000000000000000000000ab",
        "-3:000000000000000000000000000000ab",
        "4294967296:000000000000000000000000000000ab",
        "3:000000000000000000000000000000AB",
        "3:ab",
        "3:0000000000000000000000000000000ab",
        "3:000000000000000000000000000000ag",
        "3:000000000000000000000000000000ab;",
        " 3:000000000000000000000000000000ab",
        "3:000000000000000000000000000000ab ",
        "3:000000000000000000000000000000ab,7:ffffffffffffffffffffffffffffffff",
        "3:000000000000000000000000000000ab;3:000000000000000000000000000000ac",
        "7:ffffffffffffffffffffffffffffffff;3:000000000000000000000000000000ab",
    ] {
        assert!(parse_dimension_set(bad).is_err(), "{bad:?}");
    }
    let maximum: Vec<_> = (1_u32..=64).map(|kind| (kind, u128::from(kind))).collect();
    assert_eq!(
        parse_dimension_set(&format_dimension_set(&maximum)).unwrap(),
        maximum
    );
    let mut too_many = maximum;
    too_many.push((u32::MAX, u128::MAX));
    assert!(parse_dimension_set(&format_dimension_set(&too_many)).is_err());
    let unsorted = vec![(7, 0xff), (3, 0xab)];
    let wire = format_dimension_set(&unsorted);
    assert!(
        wire.starts_with("7:"),
        "a writer never repairs the supplied order"
    );
    assert!(parse_dimension_set(&wire).is_err());
}

#[test]
fn dimension_content_commitment_binds_value_kind_entry_and_leg_without_changing_money() {
    let plain = sample_multi_unit_journal();
    let tagged = dimensioned_journal();
    assert_ne!(
        plain.coordinate.content_digest,
        tagged.coordinate.content_digest
    );
    assert_eq!(
        plain.fold_balances().unwrap(),
        tagged.fold_balances().unwrap()
    );
    for mutation in 0..5 {
        let mut changed = tagged.clone();
        match mutation {
            0 => changed.entries[0].legs[0].dimensions[0].1 ^= 1,
            1 => changed.entries[0].legs[0].dimensions[0].0 = 2,
            2 => changed.entries[0].legs[0].dimensions.clear(),
            3 => {
                let tags = std::mem::take(&mut changed.entries[0].legs[0].dimensions);
                changed.entries[0].legs[2].dimensions = tags;
            }
            _ => {
                let tags = std::mem::take(&mut changed.entries[0].legs[0].dimensions);
                changed.entries[2].legs[0].dimensions = tags;
            }
        }
        assert_eq!(
            changed.fold_balances().unwrap(),
            tagged.fold_balances().unwrap()
        );
        let digest = FormatJournal::compute_content_digest(
            &changed.accounts,
            &changed.entries,
            &changed.assertions,
        );
        assert_ne!(
            digest, tagged.coordinate.content_digest,
            "mutation {mutation}"
        );
        assert!(tagged.coordinate.verify(&digest).is_err());
    }
    let mut cleared = tagged;
    for entry in &mut cleared.entries {
        for leg in &mut entry.legs {
            leg.dimensions.clear();
        }
    }
    assert_eq!(
        FormatJournal::compute_content_digest(
            &cleared.accounts,
            &cleared.entries,
            &cleared.assertions
        ),
        plain.coordinate.content_digest,
        "empty dimensions have no additive digest bytes",
    );
    for invalid in [
        vec![(3, 1), (3, 2)],
        vec![(7, 1), (3, 2)],
        (0..65).map(|id| (id, 1)).collect(),
    ] {
        let mut journal = plain.clone();
        journal.entries[0].legs[0].dimensions = invalid;
        assert!(journal.fold_balances().is_err());
        assert!(write_ads_package(&journal).is_err());
        assert!(write_ndjson_gl_stream(&journal).is_err());
    }
}

#[test]
fn dimension_interop_round_trips_exact_native_ids_including_untagged_legs() {
    let units = UnitCatalog::embedded().unwrap();
    let tagged = dimensioned_journal();
    let csv = write_csv_gl(&tagged);
    let ads = write_ads_package(&tagged).unwrap();
    let saft = write_saft_xml(&tagged).unwrap();
    let bean = write_beancount(&tagged).unwrap();
    for (format, read) in [
        ("csv", read_csv_gl(&csv, &units).unwrap()),
        ("ads", read_ads_package(&ads, &units).unwrap()),
        ("saft", read_saft_xml(&saft, &units).unwrap()),
        ("beancount", read_beancount(&bean, &units).unwrap()),
    ] {
        assert_eq!(
            read, tagged,
            "{format}: tag identity and source text survive"
        );
        verify_round_trip_identity(format, &tagged, &read).unwrap();
    }
    assert!(
        csv.lines()
            .next()
            .unwrap()
            .contains("|dimension_encoding=fa-dimension-ids-v1")
    );
    assert!(
        ads.certificate_toml
            .contains("dimension_encoding = \"fa-dimension-ids-v1\"\n")
    );
    assert!(
        csv.lines()
            .filter(|line| !line.starts_with('#'))
            .all(|line| line.split(',').count() == 14)
    );
    assert!(
        ads.gl_detail
            .lines()
            .all(|line| line.split('|').count() == 14)
    );

    // hledger has an intentionally narrower text profile. Its posting tags
    // and exact monetary fold still survive, without claiming its missing
    // memo, migrated-from, and assertion fields are an identity round trip.
    let hledger = read_hledger(&write_hledger(&tagged), &units).unwrap();
    assert_eq!(
        hledger.fold_balances().unwrap(),
        tagged.fold_balances().unwrap()
    );
    let tags = |journal: &FormatJournal| {
        journal
            .entries
            .iter()
            .flat_map(|e| e.legs.iter().map(|l| l.dimensions.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(tags(&hledger), tags(&tagged));

    let ndjson = write_ndjson_gl_stream(&tagged).unwrap();
    assert_eq!(verify_ndjson_gl_stream(&ndjson).unwrap(), 8);
    assert!(
        ndjson
            .lines()
            .next()
            .unwrap()
            .contains("\"dimension_encoding\":\"fa-dimension-ids-v1\"")
    );
    assert_eq!(ndjson.matches("\"dimensions\":").count(), 8);
    assert!(ndjson.contains("\"dimensions\":[{\"dimension\":3,\"value\":\"000000000000000000000000000000ab\"},{\"dimension\":7,\"value\":\"ffffffffffffffffffffffffffffffff\"}]"));
    assert!(ndjson.contains("\"dimensions\":[]}"));

    let plain = sample_multi_unit_journal();
    let old_csv = write_csv_gl(&plain);
    let old_ads = write_ads_package(&plain).unwrap();
    assert!(!old_csv.contains("dimension_encoding"));
    assert!(
        old_csv
            .lines()
            .filter(|line| !line.starts_with('#'))
            .all(|line| line.split(',').count() == 13)
    );
    assert!(!old_ads.certificate_toml.contains("dimension_encoding"));
    assert!(
        old_ads
            .gl_detail
            .lines()
            .all(|line| line.split('|').count() == 13)
    );
    assert!(
        !write_ndjson_gl_stream(&plain)
            .unwrap()
            .contains("\"dimensions\"")
    );
}

#[test]
fn dimension_csv_preserves_lossless_text_metadata_and_empty_optional_fields_together() {
    let units = UnitCatalog::embedded().unwrap();
    let original = dimensioned_journal();
    let mut accounts = original.accounts.clone();
    accounts[0].name = "Cost centre | A\r\n\"Finance\"".into();
    let mut entries = original.entries.clone();
    entries[0].description = "published, \"exact\"\r\n# continuation".into();
    entries[0].migrated_from = Some(String::new());
    entries[0].legs[0].memo = Some(String::new());
    entries[0].legs[1].memo = Some("  source row, \"quoted\"\n# retained  ".into());
    let coordinate = &original.coordinate;
    let journal = FormatJournal::new(
        "  Public | records\n2025  ",
        &coordinate.base_unit_code,
        coordinate.base_unit_scale,
        coordinate.effective_through,
        coordinate.known_at_seq,
        accounts,
        entries,
        original.assertions,
    )
    .unwrap();
    let csv = write_csv_gl(&journal);
    assert!(csv.starts_with("# fa_csv_text_encoding_v1|percent-utf8\n"));
    assert!(csv.contains("|dimension_encoding=fa-dimension-ids-v1\n"));
    assert!(csv.contains("# fa_csv_empty_optional_v1|1|0|migrated_from\n"));
    assert!(csv.contains("# fa_csv_empty_optional_v1|1|1|memo\n"));
    let imported = read_csv_gl(&csv, &units).unwrap();
    assert_eq!(imported, journal);
    verify_round_trip_identity("csv_gl_v1", &journal, &imported).unwrap();
    assert_eq!(write_csv_gl(&imported), csv);
    let wire = format_dimension_set(&journal.entries[0].legs[0].dimensions);
    for changed in [
        csv.replacen(&wire, &wire.replace("000ab", "000ad"), 1),
        csv.replace("# fa_csv_empty_optional_v1|1|1|memo\n", ""),
        csv.replace("%7C", "%2F"),
    ] {
        assert_ne!(changed, csv);
        assert!(read_csv_gl(&changed, &units).is_err());
    }
}

#[test]
fn dimension_csv_refuses_attribution_tampering_and_extension_downgrades() {
    let units = UnitCatalog::embedded().unwrap();
    let journal = dimensioned_journal();
    let csv = write_csv_gl(&journal);
    let wire = format_dimension_set(&journal.entries[0].legs[0].dimensions);
    for changed in [
        csv.replacen(&wire, &wire.replace("000ab", "000ad"), 1),
        csv.replacen(
            &wire,
            &format!("{wire};3:000000000000000000000000000000ab"),
            1,
        ),
        csv.replacen(
            &wire,
            "7:ffffffffffffffffffffffffffffffff;3:000000000000000000000000000000ab",
            1,
        ),
        csv.replace("|dimension_encoding=fa-dimension-ids-v1", ""),
        csv.replace(
            "dimension_encoding=fa-dimension-ids-v1",
            "dimension_encoding=unknown",
        ),
        csv.replace(
            "|dimension_encoding=fa-dimension-ids-v1",
            "|dimension_encoding=fa-dimension-ids-v1|dimension_encoding=fa-dimension-ids-v1",
        ),
        csv.replace(",dimension_set_v1", ""),
        csv.replace(
            &format!(
                "|certificate_digest={}",
                hex_encode(&journal.coordinate.certificate_digest)
            ),
            "",
        ),
    ] {
        assert_ne!(changed, csv);
        assert!(read_csv_gl(&changed, &units).is_err(), "{changed}");
    }
    let drop_columns = |all: bool| {
        csv.lines()
            .map(|line| {
                if (!line.starts_with('#') && all) || line.starts_with("E-0001,1,") {
                    line.rsplit_once(',').unwrap().0.to_owned()
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert!(
        read_csv_gl(&drop_columns(false), &units).is_err(),
        "a single row may not omit its declared tag set"
    );
    let downgraded = drop_columns(true).replace("|dimension_encoding=fa-dimension-ids-v1", "");
    assert!(
        read_csv_gl(&downgraded, &units).is_err(),
        "stripping the entire extension cannot retain the original certificate"
    );
}

#[test]
fn dimension_ads_refuses_attribution_tampering_and_extension_downgrades() {
    let units = UnitCatalog::embedded().unwrap();
    let journal = dimensioned_journal();
    let ads = write_ads_package(&journal).unwrap();
    let wire = format_dimension_set(&journal.entries[0].legs[0].dimensions);
    for replacement in [
        wire.replace("000ab", "000ad"),
        format!("{wire};3:000000000000000000000000000000ab"),
        "7:ffffffffffffffffffffffffffffffff;3:000000000000000000000000000000ab".into(),
    ] {
        let mut changed = ads.clone();
        changed.gl_detail = changed.gl_detail.replacen(&wire, &replacement, 1);
        assert_ne!(changed.gl_detail, ads.gl_detail);
        assert!(read_ads_package(&changed, &units).is_err());
    }
    for replacement in [
        "",
        "dimension_encoding = \"unknown\"\n",
        "dimension_encoding = \"fa-dimension-ids-v1\"\ndimension_encoding = \"fa-dimension-ids-v1\"\n",
    ] {
        let mut changed = ads.clone();
        changed.certificate_toml = changed.certificate_toml.replace(
            "dimension_encoding = \"fa-dimension-ids-v1\"\n",
            replacement,
        );
        assert!(read_ads_package(&changed, &units).is_err());
    }
    for all in [false, true] {
        let mut changed = ads.clone();
        changed.gl_detail = changed
            .gl_detail
            .lines()
            .map(|line| {
                if all || line.starts_with("E-0001|1|") {
                    line.rsplit_once('|').unwrap().0
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        if all {
            changed.certificate_toml = changed
                .certificate_toml
                .replace("dimension_encoding = \"fa-dimension-ids-v1\"\n", "");
        }
        assert!(
            read_ads_package(&changed, &units).is_err(),
            "a removed dimension column is never an approved downgrade"
        );
    }
}

#[test]
fn dimension_saft_and_beancount_refuse_changed_or_ambiguous_posting_tags() {
    let units = UnitCatalog::embedded().unwrap();
    let journal = dimensioned_journal();
    let wire = format_dimension_set(&journal.entries[0].legs[0].dimensions);
    let saft = write_saft_xml(&journal).unwrap();
    let field = format!("<fa:DimensionSetV1>{wire}</fa:DimensionSetV1>");
    for attribute in [
        "before='>'",
        "before=\">\"",
        "before=\"'>'\"",
        "before='\">\"'",
    ] {
        let decorated = saft.replacen("<AuditFile ", &format!("<AuditFile {attribute} "), 1);
        assert_ne!(decorated, saft);
        assert_eq!(read_saft_xml(&decorated, &units).unwrap(), journal);
    }
    let namespace = "xmlns:fa=\"urn:frankenaccounting:saft:extensions:v1\"";
    let with_probe = saft.replacen(namespace, &format!("{namespace} probe='{namespace}'"), 1);
    assert_ne!(with_probe, saft);
    assert_eq!(read_saft_xml(&with_probe, &units).unwrap(), journal);
    for declaration in [
        "xmlns:fa='urn:frankenaccounting:saft:extensions:v1'",
        "xmlns:fa = \"urn:frankenaccounting:saft:extensions:v1\"",
    ] {
        let changed = saft.replacen(namespace, declaration, 1);
        assert_ne!(changed, saft);
        assert_eq!(read_saft_xml(&changed, &units).unwrap(), journal);
    }
    for root_attributes in [
        format!("probe='{namespace}'"),
        format!("{namespace} {namespace}"),
        format!("{namespace} broken=unquoted"),
    ] {
        let changed = saft.replacen(namespace, &root_attributes, 1);
        assert_ne!(changed, saft);
        assert!(matches!(
            read_saft_xml(&changed, &units),
            Err(FormatError::Parse { ref detail, .. })
                if detail == "dimension extension namespace is missing, different or rebound"
        ));
    }
    for changed in [
        saft.replacen(&wire, &wire.replace("000ab", "000ad"), 1),
        saft.replacen(&field, "", 1),
        saft.replacen(&field, &format!("{field}{field}"), 1),
        saft.replacen(&field, &format!("<!-- {field} -->"), 1),
        saft.replacen(&field, &format!("<![CDATA[{field}]]>"), 1),
        saft.replacen(
            &field,
            &format!("<x xmlns:fa = \"urn:another:extension\">{field}</x>"),
            1,
        ),
        saft.replacen(
            &field,
            &format!("<x xmlns:fa = 'urn:another:extension'>{field}</x>"),
            1,
        ),
        saft.replacen(&field, &format!("{field}<fa:DimensionSetV1>"), 1),
        saft.replace(
            "urn:frankenaccounting:saft:extensions:v1",
            "urn:another:extension",
        ),
        saft.replace(
            "<fa:DimensionEncoding>fa-dimension-ids-v1</fa:DimensionEncoding>",
            "",
        ),
    ] {
        assert_ne!(changed, saft);
        assert!(read_saft_xml(&changed, &units).is_err());
    }
    for wrapped in [
        format!("<x before='>' xmlns:fa='urn:another:extension'>{field}</x>"),
        format!("<x before=\">\" xmlns:fa=\"urn:another:extension\">{field}</x>"),
    ] {
        let changed = saft.replacen(&field, &wrapped, 1);
        assert_ne!(changed, saft);
        assert!(matches!(
            read_saft_xml(&changed, &units),
            Err(FormatError::Parse { ref detail, .. })
                if detail == "dimension extension namespace is missing, different or rebound"
        ));
    }
    let bean = write_beancount(&journal).unwrap();
    let field = format!("    fa_dimensions_v1: \"{wire}\"\n");
    for changed in [
        bean.replacen(&wire, &wire.replace("000ab", "000ad"), 1),
        bean.replacen(&field, "", 1),
        bean.replacen(&field, &format!("{field}{field}"), 1),
        bean.replacen(&field, &field.replacen("    ", "  ", 1), 1),
    ] {
        assert_ne!(changed, bean);
        assert!(read_beancount(&changed, &units).is_err());
    }
}

#[test]
fn account_roles_survive_every_journal_round_trip_and_substitution_is_refused() {
    let original = sample_multi_unit_journal();
    let mut accounts = original.accounts.clone();
    accounts
        .iter_mut()
        .find(|a| a.code == "3000")
        .unwrap()
        .roles = vec![
        "contributed_capital".into(),
        "noncontrolling_interest".into(),
    ];
    let c = &original.coordinate;
    let classified = FormatJournal::new(
        &c.book_name,
        &c.base_unit_code,
        c.base_unit_scale,
        c.effective_through,
        c.known_at_seq,
        accounts,
        original.entries.clone(),
        original.assertions.clone(),
    )
    .unwrap();
    assert_ne!(classified.coordinate.content_digest, c.content_digest);
    assert_eq!(
        classified.fold_balances().unwrap(),
        original.fold_balances().unwrap()
    );
    let units = UnitCatalog::embedded().unwrap();
    let ads = write_ads_package(&classified).unwrap();
    let saft = write_saft_xml(&classified).unwrap();
    let csv = write_csv_gl(&classified);
    let bean = write_beancount(&classified).unwrap();
    for (format, restored) in [
        ("ads", read_ads_package(&ads, &units).unwrap()),
        ("saft", read_saft_xml(&saft, &units).unwrap()),
        ("csv", read_csv_gl(&csv, &units).unwrap()),
        ("beancount", read_beancount(&bean, &units).unwrap()),
    ] {
        assert_eq!(restored.accounts, classified.accounts, "{format}");
        verify_round_trip_identity(format, &classified, &restored).unwrap();
    }
    // hledger carries neither leg memos, migration sources nor assertions.
    // Test full identity on its own representable profile, retaining every
    // role and amount; the four richer profiles above keep all their fields.
    let mut entries = classified.entries.clone();
    for entry in &mut entries {
        entry.migrated_from = None;
        for leg in &mut entry.legs {
            leg.memo = None;
        }
    }
    let c = &classified.coordinate;
    let hledger_profile = FormatJournal::new(
        &c.book_name,
        &c.base_unit_code,
        c.base_unit_scale,
        c.effective_through,
        c.known_at_seq,
        classified.accounts.clone(),
        entries,
        Vec::new(),
    )
    .unwrap();
    assert_eq!(
        hledger_profile.fold_balances().unwrap(),
        classified.fold_balances().unwrap()
    );
    let hledger = write_hledger(&hledger_profile);
    let restored = read_hledger(&hledger, &units).unwrap();
    assert_eq!(restored.accounts, classified.accounts);
    verify_round_trip_identity("hledger", &hledger_profile, &restored).unwrap();
    let mut substituted = ads;
    substituted.certificate_toml = substituted
        .certificate_toml
        .replace("noncontrolling_interest", "retained_earnings");
    assert!(read_ads_package(&substituted, &units).is_err());
    assert!(
        read_saft_xml(
            &saft.replace("noncontrolling_interest", "retained_earnings"),
            &units
        )
        .is_err()
    );
    assert!(
        read_csv_gl(
            &csv.replace("noncontrolling_interest", "retained_earnings"),
            &units
        )
        .is_err()
    );
    assert!(
        read_beancount(
            &bean.replace("noncontrolling_interest", "retained_earnings"),
            &units
        )
        .is_err()
    );
    // hledger's reader does not carry the producer's original coordinate, so
    // the independent round-trip comparison must reject a changed role set.
    let changed = read_hledger(
        &hledger.replace("noncontrolling_interest", "retained_earnings"),
        &units,
    )
    .unwrap();
    assert!(verify_round_trip_identity("hledger", &hledger_profile, &changed).is_err());
}

#[test]
fn ads_v3_preserves_delimiters_controls_unicode_and_empty_optional_text() {
    let mut input = sample_multi_unit_journal();
    let text = "one\nline\rreturn|pipe\\literal \"quote\"\t nul:\0 C1:\u{85} café";
    input.accounts[0].name = text.into();
    input.entries[0].description = text.into();
    input.entries[0].entry_id.push_str(text);
    input.entries[0].migrated_from = Some(text.into());
    input.entries[0].legs[0].memo = Some(text.into());
    input.entries[1].migrated_from = Some(String::new());
    input.entries[1].legs[0].memo = Some(String::new());
    let input = FormatJournal::new(
        text,
        &input.coordinate.base_unit_code,
        input.coordinate.base_unit_scale,
        input.coordinate.effective_through,
        input.coordinate.known_at_seq,
        input.accounts,
        input.entries,
        input.assertions,
    )
    .expect("valid exact-text source");
    let package = write_ads_package(&input).expect("lossless ADS writer");
    assert!(
        package
            .certificate_toml
            .contains("format = \"aicpa_ads_gl_v3\"")
    );
    assert!(package.certificate_toml.contains("book_name_utf8_hex = \""));
    assert_eq!(
        package.chart_of_accounts.lines().count(),
        input.accounts.len() + 1
    );
    assert_eq!(
        package.gl_detail.lines().count(),
        input.entries.iter().map(|e| e.legs.len()).sum::<usize>() + 1
    );
    for line in package.gl_detail.lines().skip(1) {
        assert_eq!(
            line.split('|').count(),
            13,
            "one physical row per leg: {line:?}"
        );
        assert!(
            !line.chars().any(char::is_control),
            "escaped controls: {line:?}"
        );
    }
    let units = UnitCatalog::embedded().unwrap();
    let restored = read_ads_package(&package, &units).expect("decode v3");
    verify_round_trip_identity("aicpa_ads_gl_v3", &input, &restored)
        .expect("all canonical source bytes, not only amounts, survive");
    assert_eq!(restored.coordinate.book_name, text);
    assert_eq!(restored.accounts[0].name, text);
    assert_eq!(restored.entries[0].description, text);
    assert_eq!(restored.entries[0].legs[0].memo.as_deref(), Some(text));
    assert_eq!(restored.entries[1].migrated_from.as_deref(), Some(""));
    assert_eq!(restored.entries[1].legs[0].memo.as_deref(), Some(""));
    assert_eq!(
        write_ads_package(&restored).unwrap(),
        package,
        "canonical re-export"
    );

    for bad in ["\\q", "\\uD800", "\\u000a", "\\u001F", "\t", "\\N"] {
        let mut corrupt = package.clone();
        corrupt.gl_detail = corrupt.gl_detail.replacen("\\p", bad, 1);
        assert!(
            matches!(
                read_ads_package(&corrupt, &units),
                Err(FormatError::Parse { .. })
            ),
            "malformed/noncanonical escape must fail before certificate comparison: {bad:?}"
        );
    }
    let mut unknown = package;
    unknown.certificate_toml = unknown
        .certificate_toml
        .replace("aicpa_ads_gl_v3", "aicpa_ads_gl_v999");
    assert!(read_ads_package(&unknown, &units).is_err());
}

#[test]
fn ads_reader_refuses_conflicting_headers_line_numbers_and_metadata() {
    let units = UnitCatalog::embedded().unwrap();
    let package = write_ads_package(&sample_multi_unit_journal()).unwrap();
    for (column, bad) in [
        (1, "9"),
        (9, "255"),
        (10, "different header text"),
        (11, "different origin"),
    ] {
        let mut corrupted = package.clone();
        let mut lines: Vec<String> = package.gl_detail.lines().map(str::to_owned).collect();
        let mut fields: Vec<String> = lines[2].split('|').map(str::to_owned).collect();
        fields[column] = bad.to_owned();
        lines[2] = fields.join("|");
        corrupted.gl_detail = format!("{}\n", lines.join("\n"));
        assert!(
            matches!(
                read_ads_package(&corrupted, &units),
                Err(FormatError::Parse { .. })
            ),
            "column {column}"
        );
    }
    for (old, new) in [
        ("base_unit_scale = 2", "base_unit_scale = -254"),
        ("known_at_seq = 3", "known_at_seq = -1"),
        ("entry_count = 3", "entry_count = 99"),
        ("schema_version = 1", "schema_version = 999"),
    ] {
        let mut corrupted = package.clone();
        assert!(corrupted.certificate_toml.contains(old));
        corrupted.certificate_toml = corrupted.certificate_toml.replace(old, new);
        assert!(
            read_ads_package(&corrupted, &units).is_err(),
            "metadata {new}"
        );
    }
}

/// fa-2q91 (plan §13.1): an account-scoped ADS package holds every entry with
/// a leg on its account, each whole, and that account's balance only. Its
/// certificate binds the account under its own digest domain; a whole-chart
/// certificate's bytes are unchanged. The reader refuses a scoped package
/// carrying another account's entry, and stripping the scope fails the
/// certificate.
#[test]
fn ads_account_scope_keeps_whole_entries_binds_the_account_and_refuses_foreign_rows() {
    let units = UnitCatalog::embedded().unwrap();
    let journal = sample_multi_unit_journal();
    let whole = write_ads_package(&journal).unwrap();
    assert!(!whole.certificate_toml.contains("account_scope"));

    let scoped = journal.clone().scoped_to_account("1000").unwrap();
    assert_eq!(scoped.coordinate.account_scope.as_deref(), Some("1000"));
    let naming: Vec<&FormatEntry> = journal
        .entries
        .iter()
        .filter(|e| e.legs.iter().any(|l| l.account_code == "1000"))
        .collect();
    assert!(!naming.is_empty() && naming.len() < journal.entries.len());
    assert_eq!(scoped.entries.iter().collect::<Vec<_>>(), naming);
    let balances: Vec<&FormatAssertion> = journal
        .assertions
        .iter()
        .filter(|a| a.account_code == "1000")
        .collect();
    assert_eq!(balances.len(), 1);
    assert_eq!(scoped.assertions.iter().collect::<Vec<_>>(), balances);
    assert_eq!(scoped.coordinate.entry_count, naming.len() as u64);
    assert_ne!(
        scoped.coordinate.certificate_digest,
        journal.coordinate.certificate_digest
    );

    let package = write_ads_package(&scoped).unwrap();
    assert!(
        package
            .certificate_toml
            .ends_with("account_scope = \"1000\"\n")
    );
    let tb: Vec<&str> = package.trial_balance.lines().skip(1).collect();
    assert_eq!(tb.len(), 1, "{}", package.trial_balance);
    assert!(tb[0].starts_with("1000|"), "{}", package.trial_balance);
    let restored = read_ads_package(&package, &units).unwrap();
    assert_eq!(restored, scoped);

    // Planted: an entry naming no 1000 leg, copied in from the whole chart
    // with the chart rows of its accounts, so only the scope can refuse it.
    let foreign = journal
        .entries
        .iter()
        .find(|e| e.legs.iter().all(|l| l.account_code != "1000"))
        .unwrap();
    let mut smuggled = package.clone();
    for line in whole.chart_of_accounts.lines().skip(1) {
        let code = line.split('|').next().unwrap();
        let missing = !package
            .chart_of_accounts
            .lines()
            .any(|kept| kept.starts_with(&format!("{code}|")));
        if missing && foreign.legs.iter().any(|l| l.account_code == code) {
            smuggled.chart_of_accounts.push_str(line);
            smuggled.chart_of_accounts.push('\n');
        }
    }
    for line in whole.gl_detail.lines() {
        if line.starts_with(&format!("{}|", foreign.entry_id)) {
            smuggled.gl_detail.push_str(line);
            smuggled.gl_detail.push('\n');
        }
    }
    let refused = read_ads_package(&smuggled, &units).unwrap_err();
    assert!(
        refused.to_string().contains("scoped to account 1000"),
        "{refused}"
    );
    // Planted: the same rows without the scope line read as a whole chart,
    // whose certificate digest they do not carry.
    let mut unscoped = package.clone();
    unscoped.certificate_toml = unscoped
        .certificate_toml
        .replace("account_scope = \"1000\"\n", "");
    assert!(matches!(
        read_ads_package(&unscoped, &units),
        Err(FormatError::CertificateMismatch { .. })
    ));
    assert!(matches!(
        journal.scoped_to_account("9999"),
        Err(FormatError::UnknownAccount { .. })
    ));
}

/// A certificate can faithfully bind an internally false balance assertion.
/// Readers must check the accounting claim even when every digest is correct.
#[test]
fn ads_trial_balance_refuses_certified_false_duplicate_and_invalid_assertions() {
    let units = UnitCatalog::embedded().unwrap();
    let source = sample_multi_unit_journal();
    let package = write_ads_package(&source).unwrap();
    let rebuild = |assertions| {
        FormatJournal::new(
            &source.coordinate.book_name,
            &source.coordinate.base_unit_code,
            source.coordinate.base_unit_scale,
            source.coordinate.effective_through,
            source.coordinate.known_at_seq,
            source.accounts.clone(),
            source.entries.clone(),
            assertions,
        )
        .unwrap()
    };
    let mut variants = Vec::new();
    let mut changed = source.assertions.clone();
    changed[0].amount.mantissa += 1;
    variants.push(("false magnitude", changed));
    let mut changed = source.assertions.clone();
    changed[0].side = Side::Credit;
    variants.push(("false side", changed));
    let mut changed = source.assertions.clone();
    changed[0].amount.mantissa = -changed[0].amount.mantissa;
    variants.push(("negative magnitude", changed));
    let mut changed = source.assertions.clone();
    changed[0].account_code = "absent".into();
    variants.push(("unknown account", changed));
    let mut changed = source.assertions.clone();
    changed[0].as_of = DateDay::from_ymd(2026, 3, 26).unwrap();
    variants.push(("future assertion", changed));
    let mut changed = source.assertions.clone();
    changed.push(changed[0].clone());
    variants.push(("duplicate assertion", changed));

    for (label, assertions) in variants {
        let inconsistent = rebuild(assertions);
        assert!(write_ads_package(&inconsistent).is_err(), "{label}: writer");
        let mut forged = package.clone();
        forged.certificate_toml = forged
            .certificate_toml
            .replace(
                &hex_encode(&source.coordinate.content_digest),
                &hex_encode(&inconsistent.coordinate.content_digest),
            )
            .replace(
                &hex_encode(&source.coordinate.certificate_digest),
                &hex_encode(&inconsistent.coordinate.certificate_digest),
            );
        forged.trial_balance = format!("{}\n", package.trial_balance.lines().next().unwrap());
        for row in &inconsistent.assertions {
            forged.trial_balance.push_str(&format!(
                "{}|{}|{}|{}|{}|{}\n",
                row.account_code,
                fa_formats::format_date_iso(row.as_of),
                if row.side == Side::Debit { "D" } else { "C" },
                fa_formats::format_exact_decimal(row.amount.mantissa, row.unit_scale),
                row.unit_code,
                row.unit_scale,
            ));
        }
        let error = read_ads_package(&forged, &units).expect_err(label);
        assert!(
            !matches!(error, FormatError::CertificateMismatch { .. }),
            "{label}: digests must be valid so the accounting check catches this: {error}"
        );
    }
}

#[test]
fn ads_trial_balance_uses_each_assertions_date_and_registered_unit_scale() {
    let units = UnitCatalog::embedded().unwrap();
    let mut source = sample_multi_unit_journal();
    // The same account has a later movement. Its earlier assertion remains
    // true, and a second assertion at the export cutoff has a different value.
    let mut later = source.entries[0].clone();
    later.entry_id = "E-0004".into();
    later.recorded_seq = 4;
    later.effective_date = source.coordinate.effective_through;
    later.legs.retain(|leg| leg.unit_code == "USD");
    for leg in &mut later.legs {
        leg.amount.mantissa = 7_500;
    }
    source.entries.push(later);
    let mut earlier = source.assertions[0].clone();
    earlier.as_of = source.entries[0].effective_date;
    source.assertions[0].amount.mantissa += 7_500;
    source.assertions.push(earlier);
    let journal = FormatJournal::new(
        &source.coordinate.book_name,
        "USD",
        2,
        source.coordinate.effective_through,
        4,
        source.accounts,
        source.entries,
        source.assertions,
    )
    .unwrap();
    let package = write_ads_package(&journal).unwrap();
    let restored = read_ads_package(&package, &units).unwrap();
    assert_eq!(restored, journal);
    verify_round_trip_identity("ads", &journal, &restored).unwrap();

    for scale in ["0", "4", "256", "not-a-scale"] {
        let mut corrupted = package.clone();
        corrupted.trial_balance = corrupted
            .trial_balance
            .replace("|USD|2", &format!("|USD|{scale}"));
        assert!(
            matches!(read_ads_package(&corrupted, &units), Err(FormatError::Parse { detail, .. })
                if detail.contains("Unit_Scale")),
            "scale={scale}"
        );
    }
    let mut corrupted = package.clone();
    corrupted.trial_balance =
        corrupted
            .trial_balance
            .replacen("Ending_Balance", "Unrelated_Value", 1);
    assert!(read_ads_package(&corrupted, &units).is_err());
}

#[test]
fn ads_derived_trial_balance_preserves_assertion_free_journals_and_scope() {
    let units = UnitCatalog::embedded().unwrap();
    let source = sample_multi_unit_journal();
    let journal = FormatJournal::new(
        "Derived | balances\nwithout assertions",
        "USD",
        2,
        source.coordinate.effective_through,
        source.coordinate.known_at_seq,
        source.accounts,
        source.entries,
        Vec::new(),
    )
    .unwrap();
    for input in [journal.clone(), journal.scoped_to_account("1000").unwrap()] {
        let package = write_ads_package(&input).unwrap();
        assert!(
            package
                .certificate_toml
                .contains("format = \"aicpa_ads_gl_v4\"")
        );
        assert!(package.trial_balance.lines().count() > 1);
        let restored = read_ads_package(&package, &units).unwrap();
        assert!(restored.assertions.is_empty());
        assert_eq!(restored, input);
        verify_round_trip_identity("ads-v4", &input, &restored).unwrap();
        assert_eq!(write_ads_package(&restored).unwrap(), package);

        // Derived rows are not source assertions in the content digest.
        // Exact recomputation must therefore refuse changes independently.
        let mut wrong = package.clone();
        wrong.trial_balance = wrong.trial_balance.replace("|2500.00|", "|2500.01|");
        assert!(matches!(
            read_ads_package(&wrong, &units),
            Err(FormatError::RoundTripMismatch { .. })
        ));
        let mut missing = package.clone();
        missing.trial_balance = format!("{}\n", package.trial_balance.lines().next().unwrap());
        assert!(read_ads_package(&missing, &units).is_err());
        let mut duplicate = package.clone();
        duplicate
            .trial_balance
            .push_str(package.trial_balance.lines().nth(1).unwrap());
        duplicate.trial_balance.push('\n');
        assert!(read_ads_package(&duplicate, &units).is_err());
        let mut downgraded = package;
        downgraded.certificate_toml = downgraded
            .certificate_toml
            .replace("aicpa_ads_gl_v4", "aicpa_ads_gl_v3");
        assert!(matches!(
            read_ads_package(&downgraded, &units),
            Err(FormatError::CertificateMismatch { .. })
        ));
    }
}

#[test]
fn ads_derived_trial_balance_preserves_zero_cells_and_refuses_unrepresentable_magnitudes() {
    let units = UnitCatalog::embedded().unwrap();
    let source = sample_multi_unit_journal();
    let mut opening = source.entries[0].clone();
    opening.legs.retain(|leg| leg.unit_code == "USD");
    let mut reversing = opening.clone();
    reversing.entry_id = "reversing".into();
    reversing.recorded_seq = 2;
    for leg in &mut reversing.legs {
        leg.side = if leg.side == Side::Debit {
            Side::Credit
        } else {
            Side::Debit
        };
    }
    let zero = FormatJournal::new(
        "zero balances",
        "USD",
        2,
        source.coordinate.effective_through,
        3,
        source.accounts.clone(),
        vec![opening.clone(), reversing],
        Vec::new(),
    )
    .unwrap();
    let package = write_ads_package(&zero).unwrap();
    assert_eq!(package.trial_balance.lines().count(), 3);
    assert!(
        package
            .trial_balance
            .lines()
            .skip(1)
            .all(|row| row.contains("|D|0.00|USD|2"))
    );
    assert_eq!(read_ads_package(&package, &units).unwrap(), zero);

    // Two valid entries can give one account MIN while another account
    // offsets it. The balance exists, but its positive C magnitude does not.
    for leg in &mut opening.legs {
        leg.amount.mantissa = i128::MAX;
    }
    let mut extra = opening.clone();
    extra.entry_id = "one-more-credit".into();
    extra.recorded_seq = 2;
    for leg in &mut extra.legs {
        leg.amount.mantissa = 1;
        if leg.side == Side::Debit {
            leg.account_code = "1200".into();
        }
    }
    let extreme = FormatJournal::new(
        "minimum balance",
        "USD",
        2,
        source.coordinate.effective_through,
        3,
        source.accounts,
        vec![opening, extra],
        Vec::new(),
    )
    .unwrap();
    assert_eq!(
        extreme.fold_balances().unwrap()[&("3000".into(), "USD".into())],
        i128::MIN
    );
    assert!(matches!(
        write_ads_package(&extreme),
        Err(FormatError::Overflow { .. })
    ));
}

#[test]
fn tigerbeetle_semantic_corpus_agrees_on_all_scenarios_and_catches_planted_mutation() {
    let corpus = TbCorpus::embedded().expect("tigerbeetle_semantics.toml");
    assert_eq!(corpus.scenarios.len(), 9);
    let results = corpus
        .evaluate_all()
        .expect("all 9 TigerBeetle semantic scenarios must agree");
    for r in &results {
        println!(
            "judged TigerBeetle scenario {}: outcomes={:?} balances={:?} divergence={}",
            r.scenario_id, r.outcomes, r.final_balances, r.divergence
        );
    }

    // Planted negative: mutating expected balance by 1 minor unit fails evaluate_all()
    let mut bad_corpus = corpus.clone();
    bad_corpus.scenarios[2].expected_balances[0] = "1000:dp=0:dpost=6501:cp=0:cpost=0".to_owned();
    let err = bad_corpus
        .evaluate_all()
        .expect_err("mutated TigerBeetle corpus must fail");
    assert!(
        matches!(&err, FormatError::TigerBeetleViolation { scenario, .. } if scenario == "tb_03_pending_then_post_partial"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn xbrl_calculation_linkbase_validates_statements_and_catches_inconsistency() {
    let bs_linkbase = XbrlCalculationLinkbase::standard_balance_sheet();
    let bs_instance = XbrlInstance {
        entity_identifier: "ACME-CORP".to_owned(),
        period_start: None,
        period_end: "2026-03-31".to_owned(),
        facts: vec![
            XbrlFact {
                concept: "us-gaap:CurrentAssets".to_owned(),
                context_ref: "ctx_current".to_owned(),
                unit_code: "USD".to_owned(),
                scale: 2,
                mantissa: 425_500,
            },
            XbrlFact {
                concept: "us-gaap:NoncurrentAssets".to_owned(),
                context_ref: "ctx_current".to_owned(),
                unit_code: "USD".to_owned(),
                scale: 2,
                mantissa: 100_000,
            },
            XbrlFact {
                concept: "us-gaap:Assets".to_owned(),
                context_ref: "ctx_current".to_owned(),
                unit_code: "USD".to_owned(),
                scale: 2,
                mantissa: 525_500,
            },
            XbrlFact {
                concept: "us-gaap:Liabilities".to_owned(),
                context_ref: "ctx_current".to_owned(),
                unit_code: "USD".to_owned(),
                scale: 2,
                mantissa: 18_250,
            },
            XbrlFact {
                concept: "us-gaap:StockholdersEquity".to_owned(),
                context_ref: "ctx_current".to_owned(),
                unit_code: "USD".to_owned(),
                scale: 2,
                mantissa: 507_250,
            },
            XbrlFact {
                concept: "us-gaap:LiabilitiesAndStockholdersEquity".to_owned(),
                context_ref: "ctx_current".to_owned(),
                unit_code: "USD".to_owned(),
                scale: 2,
                mantissa: 525_500,
            },
        ],
    };

    let xml = write_xbrl_instance_xml(&bs_instance);
    assert!(xml.contains("<us-gaap:Assets"));
    let checked = validate_calculation_linkbase(&bs_instance, &bs_linkbase).expect("valid XBRL BS");
    assert_eq!(checked, 2);

    // Income statement with negative (-1) weight on expenses
    let is_linkbase = XbrlCalculationLinkbase::standard_income_statement();
    let is_instance = XbrlInstance {
        entity_identifier: "ACME-CORP".to_owned(),
        period_start: Some("2026-01-01".to_owned()),
        period_end: "2026-03-31".to_owned(),
        facts: vec![
            XbrlFact {
                concept: "us-gaap:Revenues".to_owned(),
                context_ref: "ctx_current".to_owned(),
                unit_code: "USD".to_owned(),
                scale: 2,
                mantissa: 75_500,
            },
            XbrlFact {
                concept: "us-gaap:CostOfGoodsAndServicesSold".to_owned(),
                context_ref: "ctx_current".to_owned(),
                unit_code: "USD".to_owned(),
                scale: 2,
                mantissa: 15_000,
            },
            XbrlFact {
                concept: "us-gaap:GrossProfit".to_owned(),
                context_ref: "ctx_current".to_owned(),
                unit_code: "USD".to_owned(),
                scale: 2,
                mantissa: 60_500,
            },
            XbrlFact {
                concept: "us-gaap:OperatingExpenses".to_owned(),
                context_ref: "ctx_current".to_owned(),
                unit_code: "USD".to_owned(),
                scale: 2,
                mantissa: 18_250,
            },
            XbrlFact {
                concept: "us-gaap:NetIncomeLoss".to_owned(),
                context_ref: "ctx_current".to_owned(),
                unit_code: "USD".to_owned(),
                scale: 2,
                mantissa: 42_250,
            },
        ],
    };
    let is_checked =
        validate_calculation_linkbase(&is_instance, &is_linkbase).expect("valid XBRL IS");
    assert_eq!(is_checked, 2);

    // Planted negative: perturbing NetIncomeLoss by 1 minor unit fails calculation linkbase validation
    let mut bad_is = is_instance.clone();
    bad_is.facts[4].mantissa += 1;
    let err = validate_calculation_linkbase(&bad_is, &is_linkbase)
        .expect_err("inconsistent XBRL calculation tree must fail");
    assert_eq!(
        err,
        FormatError::XbrlCalculationInconsistency {
            parent_concept: "us-gaap:NetIncomeLoss".to_owned(),
            unit_code: "USD".to_owned(),
            scale: 2,
            reported_mantissa: 42_251,
            computed_children_mantissa: 42_250,
        }
    );

    // End-to-end FormatJournal -> XBRL instance export + vendored calculation linkbase & coordinate verification
    let journal = sample_multi_unit_journal();
    let exported_xbrl =
        write_format_journal_xbrl_xml(&journal).expect("export FormatJournal to XBRL");
    let (verified_coord, report) =
        verify_format_journal_xbrl_xml(&exported_xbrl).expect("verify exported XBRL instance");
    assert_eq!(verified_coord, journal.coordinate);
    assert_eq!(report.checks_passed, 6); // 3 checks per unit across USD and EUR
    for line in report.log_lines() {
        println!("{line}");
        assert!(line.contains("delta=0 status=PASS"));
    }
}

fn xbrl_calculation_instance(facts: &str) -> XbrlInstance {
    // Keep the monetary literals independent of the exporter while matching
    // the reader's documented emitted-instance envelope.
    read_xbrl_instance_xml(&format!(
        r#"<xbrli:xbrl xmlns:xbrli="http://www.xbrl.org/2003/instance" xmlns:us-gaap="http://fasb.org/us-gaap/2026" xmlns:iso4217="http://www.xbrl.org/2003/iso4217">
<xbrli:context id="ctx_current">
<xbrli:entity>
<xbrli:identifier scheme="http://frankenaccounting.org/entity">SCALE-CONTROL</xbrli:identifier>
</xbrli:entity>
<xbrli:period>
<xbrli:instant>2026-03-31</xbrli:instant>
</xbrli:period>
</xbrli:context>
<xbrli:unit id="USD"><xbrli:measure>iso4217:USD</xbrli:measure></xbrli:unit>
{facts}
</xbrli:xbrl>"#
    ))
    .expect("read literal XBRL amount controls")
}

#[test]
fn xbrl_summation_compares_scaled_values_and_refuses_duplicate_facts() {
    let linkbase = XbrlCalculationLinkbase::standard_income_statement();
    // Independent literal values: USD100.00 - USD25.0000 = USD75.
    let instance = xbrl_calculation_instance(
        r#"<us-gaap:Revenues contextRef="ctx_current" unitRef="USD" decimals="2">100.00</us-gaap:Revenues>
<us-gaap:CostOfGoodsAndServicesSold contextRef="ctx_current" unitRef="USD" decimals="4">25.0000</us-gaap:CostOfGoodsAndServicesSold>
<us-gaap:GrossProfit contextRef="ctx_current" unitRef="USD" decimals="0">75</us-gaap:GrossProfit>"#,
    );
    let report = validate_calculation_linkbase_detailed(&instance, &linkbase, None)
        .expect("equal values must tie despite different scales");
    assert_eq!(report.checks_passed, 1);
    let row = &report.rows[0];
    assert_eq!(row.scale, 4);
    assert_eq!(row.reported_mantissa, 750_000);
    assert_eq!(row.computed_mantissa, 750_000);
    assert_eq!(row.delta_mantissa, 0);
    assert!(row.to_log_line().contains("scale=4 computed=750000"));

    // The old raw-mantissa sum accepted USD1.0000 = USD100.00.
    let false_tie = xbrl_calculation_instance(
        r#"<us-gaap:Revenues contextRef="ctx_current" unitRef="USD" decimals="4">1.0000</us-gaap:Revenues>
<us-gaap:GrossProfit contextRef="ctx_current" unitRef="USD" decimals="2">100.00</us-gaap:GrossProfit>"#,
    );
    assert_eq!(
        validate_calculation_linkbase(&false_tie, &linkbase),
        Err(FormatError::XbrlCalculationInconsistency {
            parent_concept: "us-gaap:GrossProfit".into(),
            unit_code: "USD".into(),
            scale: 4,
            reported_mantissa: 1_000_000,
            computed_children_mantissa: 10_000,
        })
    );

    // A conflicting duplicate cannot disappear behind a later correct value.
    // Check both orders, and also a fact absent from this linkbase entirely.
    for concept in ["us-gaap:GrossProfit", "us-gaap:Assets"] {
        let mut bad = instance.clone();
        let mut first = instance.facts[2].clone();
        first.concept = concept.into();
        first.mantissa = 76;
        let mut second = first.clone();
        second.mantissa = 75;
        bad.facts.extend([first, second]);
        for _ in 0..2 {
            let err = validate_calculation_linkbase(&bad, &linkbase).unwrap_err();
            assert!(
                matches!(&err, FormatError::Parse { detail, .. }
                    if detail.contains("conflicting duplicate fact") && detail.contains(concept)),
                "{err:?}"
            );
            bad.facts.reverse();
        }
    }
}

#[test]
fn xbrl_exact_duplicates_preserve_scale_context_and_unit() {
    let linkbase = XbrlCalculationLinkbase::standard_income_statement();
    let mut instance = xbrl_calculation_instance(
        r#"<us-gaap:Revenues contextRef="ctx_current" unitRef="USD" decimals="0">100</us-gaap:Revenues>
<us-gaap:GrossProfit contextRef="ctx_current" unitRef="USD" decimals="2">100.00</us-gaap:GrossProfit>
<us-gaap:GrossProfit contextRef="ctx_current" unitRef="USD" decimals="4">100.0000</us-gaap:GrossProfit>"#,
    );
    let original_facts = instance.facts.clone();
    for (context, unit, multiplier) in [("ctx_previous", "USD", 2), ("ctx_current", "EUR", 3)] {
        for original in &original_facts {
            let mut fact = original.clone();
            fact.context_ref = context.into();
            fact.unit_code = unit.into();
            fact.mantissa = fact.mantissa.checked_mul(multiplier).unwrap();
            instance.facts.push(fact);
        }
    }
    let report = validate_calculation_linkbase_detailed(&instance, &linkbase, None).unwrap();
    assert_eq!(report.checks_passed, 3);
    assert!(report.rows.iter().all(|row| row.scale == 4 && row.passed));
    assert_eq!(
        report
            .rows
            .iter()
            .map(|row| row.reported_mantissa)
            .collect::<Vec<_>>(),
        [3_000_000, 1_000_000, 2_000_000]
    );
    instance.facts.reverse();
    assert_eq!(
        validate_calculation_linkbase_detailed(&instance, &linkbase, None).unwrap(),
        report,
        "duplicate ordering must not choose a different precision or value"
    );
}

#[test]
fn xbrl_calculation_rescaling_and_signed_arithmetic_fail_closed() {
    let linkbase = XbrlCalculationLinkbase::standard_income_statement();
    let base = xbrl_calculation_instance(
        r#"<us-gaap:Revenues contextRef="ctx_current" unitRef="USD" decimals="2">0.00</us-gaap:Revenues>
<us-gaap:CostOfGoodsAndServicesSold contextRef="ctx_current" unitRef="USD" decimals="4">25.0000</us-gaap:CostOfGoodsAndServicesSold>
<us-gaap:GrossProfit contextRef="ctx_current" unitRef="USD" decimals="0">-25</us-gaap:GrossProfit>"#,
    );
    let report = validate_calculation_linkbase_detailed(&base, &linkbase, None).unwrap();
    assert_eq!(report.rows[0].computed_mantissa, -250_000);

    let mut overflow = base.clone();
    overflow.facts[0].mantissa = i128::MAX;
    assert!(matches!(
        validate_calculation_linkbase(&overflow, &linkbase),
        Err(FormatError::Overflow { .. })
    ));

    let mut negation = base.clone();
    negation.facts[1].mantissa = i128::MIN;
    assert!(matches!(
        validate_calculation_linkbase(&negation, &linkbase),
        Err(FormatError::Overflow { .. })
    ));

    let mut tiny = base;
    tiny.facts[0].scale = u8::MAX;
    tiny.facts[0].mantissa = 1;
    assert!(matches!(
        validate_calculation_linkbase(&tiny, &linkbase),
        Err(FormatError::Overflow { .. })
    ));
}

#[test]
fn bank_statement_parsers_camt053_bai2_ofx_and_sequence_continuity() {
    let units = UnitCatalog::embedded().expect("units.toml");

    let camt1 = r#"
    <Document>
      <Stmt>
        <ElctrncSeqNb>1</ElctrncSeqNb>
        <Acct><Id>BANK-OPER-01</Id><Ccy>USD</Ccy></Acct>
        <Bal><Cd>OPBD</Cd><Amt>1000.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt>2026-03-01</Dt></Bal>
        <Bal><Cd>CLBD</Cd><Amt>1450.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt>2026-03-15</Dt></Bal>
        <Ntry><Amt>600.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><BookgDt>2026-03-05</BookgDt><AcctSvcrRef>WIRE-IN-1</AcctSvcrRef><Nm>Acme Customer</Nm></Ntry>
        <Ntry><Amt>150.00</Amt><CdtDbtInd>DBIT</CdtDbtInd><BookgDt>2026-03-10</BookgDt><AcctSvcrRef>ACH-OUT-1</AcctSvcrRef><Nm>Cloud Vendor</Nm></Ntry>
      </Stmt>
    </Document>
    "#;
    let camt2 = r#"
    <Document>
      <Stmt>
        <ElctrncSeqNb>2</ElctrncSeqNb>
        <Acct><Id>BANK-OPER-01</Id><Ccy>USD</Ccy></Acct>
        <Bal><Cd>OPBD</Cd><Amt>1450.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt>2026-03-16</Dt></Bal>
        <Bal><Cd>CLBD</Cd><Amt>1250.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt>2026-03-31</Dt></Bal>
        <Ntry><Amt>200.00</Amt><CdtDbtInd>DBIT</CdtDbtInd><BookgDt>2026-03-20</BookgDt><AcctSvcrRef>FEE-01</AcctSvcrRef><Nm>Bank Fee</Nm></Ntry>
      </Stmt>
    </Document>
    "#;

    let s1 = parse_camt053(camt1, &units).expect("camt1");
    let s2 = parse_camt053(camt2, &units).expect("camt2");
    verify_statement_sequence_continuity(&[s1.clone(), s2.clone()])
        .expect("camt.053 sequence continuity");

    // Planted negative: sequence gap (1 -> 3) is caught
    let mut s3_gap = s2.clone();
    s3_gap.sequence_number = 3;
    let gap_err = verify_statement_sequence_continuity(&[s1.clone(), s3_gap])
        .expect_err("sequence gap must fail");
    assert!(matches!(gap_err, FormatError::BankContinuity { .. }));

    // BAI2 parser
    let bai2 = "\
02,ACME,BANK,1,2026-03-31,2359,USD,1/\n\
03,BANK-OPER-01,USD,010,100000,015,145000/\n\
16,195,60000,2026-03-05,WIRE-IN-1,Acme Customer/\n\
16,475,15000,2026-03-10,ACH-OUT-1,Cloud Vendor/\n";
    let bai_stmt = parse_bai2(bai2, &units).expect("parse_bai2");
    assert_eq!(bai_stmt.opening_balance, 100_000);
    assert_eq!(bai_stmt.closing_balance, 145_000);
    assert_eq!(bai_stmt.lines.len(), 2);

    // OFX/QBO parser
    let ofx = "\
<OFX><TRNUID>1</TRNUID><CURDEF>USD</CURDEF><ACCTID>BANK-OPER-01</ACCTID>\
<OPENBAL>1000.00</OPENBAL>\
<STMTTRN><DTPOSTED>2026-03-05</DTPOSTED><TRNAMT>600.00</TRNAMT><FITID>WIRE-IN-1</FITID><NAME>Acme Customer</NAME></STMTTRN>\
<STMTTRN><DTPOSTED>2026-03-10</DTPOSTED><TRNAMT>-150.00</TRNAMT><FITID>ACH-OUT-1</FITID><NAME>Cloud Vendor</NAME></STMTTRN>\
<LEDGERBAL><BALAMT>1450.00</BALAMT><DTASOF>2026-03-31</DTASOF></LEDGERBAL></OFX>";
    let ofx_stmt = parse_ofx_qbo(ofx, &units).expect("parse_ofx_qbo");
    assert_eq!(ofx_stmt.closing_balance, 145_000);
    assert_eq!(ofx_stmt.lines.len(), 2);
}

#[test]
fn conformance_matrices_match_published_docs_and_refuse_undocumented_divergence() {
    // Both columns are computed: FrankenAccounting's fold of the fixture, and
    // the fold after fa-formats writes it as Beancount v3 / hledger and reads
    // it back with its own reader. No external tool evaluates it (fa-sa4w).
    let units = UnitCatalog::embedded().expect("units.toml");
    let journal = sample_multi_unit_journal();
    let fa_fold = render_balances(&journal.fold_balances().expect("fa fold"), &units);
    let bc_fold = render_balances(
        &read_beancount(&write_beancount(&journal).expect("write_beancount"), &units)
            .expect("read_beancount")
            .fold_balances()
            .expect("beancount fold"),
        &units,
    );
    let hl_fold = render_balances(
        &read_hledger(&write_hledger(&journal), &units)
            .expect("read_hledger")
            .fold_balances()
            .expect("hledger fold"),
        &units,
    );
    let bc_matrix = ConformanceMatrix {
        schema_version: 1,
        oracle: "fa-formats beancount_v3 + hledger writers and readers (self round-trip)".to_owned(),
        proof_class: "metamorphic (self round-trip); external tools not run".to_owned(),
        no_claim_boundary: "Shows that FrankenAccounting's fold survives its own Beancount v3 and hledger export read back by its own reader. bean-check and hledger did not evaluate these journals, so no agreement with either tool is claimed; that differential is fa-sa4w.".to_owned(),
        notes: concat!(
            "The separately executed [external public-data oracle](plaintext-external-oracle.md)\n",
            "now covers the complete HMRC March 2025 expenditure model with real Beancount\n",
            "and hledger tools. It does not change the proof class of this historical matrix\n",
            "or claim that every fixture below has been externally evaluated.",
        ).to_owned(),
        rows: vec![
            ConformanceRow {
                fixture: "acme_multi_unit_fy2026_p03 via Beancount v3".to_owned(),
                expected: fa_fold.clone(),
                observed: bc_fold,
                divergence: "none".to_owned(),
                reason: "Written by fa-formats and read back by fa-formats; computed in this test.".to_owned(),
            },
            ConformanceRow {
                fixture: "acme_multi_unit_fy2026_p03 via hledger".to_owned(),
                expected: fa_fold,
                observed: hl_fold,
                divergence: "none".to_owned(),
                reason: "Written by fa-formats and read back by fa-formats; computed in this test.".to_owned(),
            },
            ConformanceRow {
                fixture: "fx_designated_leg_base_residual_eur_half_up".to_owned(),
                expected: "native EUR 0.01+0.01/0.02 balanced; base USD +0.01/+0.01/-0.02 with -0.01 designated-leg residual".to_owned(),
                observed: "not evaluated: bean-check was not run".to_owned(),
                divergence: "not_run".to_owned(),
                reason: "Plan §5.2 / §16.3 expect a divergence here (FrankenAccounting records the designated-leg base residual; Beancount documents per-posting @ price tolerance), but it has not been observed; fa-sa4w runs the tool.".to_owned(),
            },
        ],
    };
    bc_matrix.verify_matrix_laws().expect("valid bc_matrix");

    let tb_corpus = TbCorpus::embedded().expect("tb corpus");
    let tb_results = tb_corpus.evaluate_all().expect("tb evaluate_all");
    let tb_matrix = ConformanceMatrix {
        schema_version: 1,
        oracle: "tigerbeetle_corpus_v1 (in-house simulator in fa-formats)".to_owned(),
        proof_class: "self-consistency (simulator vs. author-written expectations)".to_owned(),
        no_claim_boundary: "The scenarios run through a TigerBeetle-semantics simulator inside fa-formats and are compared with expectations written by this project. This matrix does not exercise the FrankenAccounting posting kernel: tests/tigerbeetle.rs runs the same corpus through it (fa-w3n6). TigerBeetle itself is not run, so no agreement with TigerBeetle is claimed.".to_owned(),
        notes: String::new(),
        rows: tb_corpus
            .scenarios
            .iter()
            .zip(tb_results.iter())
            .map(|(sc, res)| ConformanceRow {
                fixture: sc.id.clone(),
                expected: format!("{:?}; {:?}", sc.expected_outcomes, sc.expected_balances),
                observed: format!("{:?}; {:?}", res.outcomes, res.final_balances),
                divergence: sc.divergence.clone(),
                reason: sc.divergence_reason.clone(),
            })

            .collect(),
    };
    tb_matrix.verify_matrix_laws().expect("valid tb_matrix");

    let standards_matrix = ConformanceMatrix {
        schema_version: 1,
        oracle: "fa-formats ADS-shaped, SAF-T-shaped and XBRL writers and readers (self round-trip)".to_owned(),
        proof_class: "metamorphic (self round-trip) + summation check against a hand-written linkbase".to_owned(),
        no_claim_boundary: "Shows export-import round-trip identity through fa-formats' own writers and readers, coordinate certificate verification, FA-INV-04 refold equality, and summation consistency against XbrlCalculationLinkbase::standard_balance_sheet/standard_income_statement (written in this repository). No published AICPA ADS column set, OECD SAF-T XSD or XBRL taxonomy was used, so standards conformance is not claimed; that is fa-ipom.".to_owned(),
        // The ADS text-version law lives in the README (f8babb03 relocated
        // it from this note), so the published note carries none.
        notes: String::new(),
        rows: vec![
            ConformanceRow {
                fixture: "aicpa_ads_gl_v2_acme_fy2026_p03".to_owned(),
                expected: "round_trip_identity=true, refold_equal=true".to_owned(),
                observed: "round_trip_identity=true, refold_equal=true".to_owned(),
                divergence: "none".to_owned(),
                reason: "Byte-identical FormatJournal and FA-INV-04 refold digest after fa-formats' ADS-shaped export and its own re-import (asserted in aicpa_ads_and_oecd_saft_and_csv_gl_round_trip_identity_and_dropped_leg_negative).".to_owned(),
            },
            ConformanceRow {
                fixture: "aicpa_ads_gl_v3_exact_text".to_owned(),
                expected: "round_trip_identity=true, refold_equal=true".to_owned(),
                observed: "round_trip_identity=true, refold_equal=true".to_owned(),
                divergence: "none".to_owned(),
                reason: "Exact canonical text and FA-INV-04 refold survive escaped delimiters, Unicode controls and absent versus empty optional fields (asserted in ads_v3_preserves_delimiters_controls_unicode_and_empty_optional_text); not an external AICPA escaping standard.".to_owned(),
            },
            ConformanceRow {
                fixture: "oecd_saft_v2_acme_fy2026_p03".to_owned(),
                expected: "round_trip_identity=true, refold_equal=true".to_owned(),
                observed: "round_trip_identity=true, refold_equal=true".to_owned(),
                divergence: "none".to_owned(),
                reason: "Byte-identical FormatJournal and FA-INV-04 refold digest after fa-formats' SAF-T-shaped XML export and its own re-import (asserted in the same test); no XSD validation.".to_owned(),
            },
            ConformanceRow {
                fixture: "xbrl_us_gaap_bs_and_is_calc_linkbase".to_owned(),
                expected: "calc_parents_verified=4".to_owned(),
                observed: "calc_parents_verified=4".to_owned(),
                divergence: "none".to_owned(),
                reason: "Balance-sheet and income-statement summation arcs of the hand-written linkbase verify with zero discrepancy (asserted in xbrl_calculation_linkbase_validates_statements_and_catches_inconsistency); not a published taxonomy.".to_owned(),
            },
        ],
    };
    standards_matrix
        .verify_matrix_laws()
        .expect("valid standards_matrix");

    // Planted negative: a row whose observed differs from expected without a documented reason fails
    let mut bad_matrix = bc_matrix.clone();
    bad_matrix.rows[0].observed = "1000:USD=+2500.01".to_owned();
    let err = bad_matrix
        .verify_matrix_laws()
        .expect_err("undocumented divergence must fail");
    assert!(
        err.to_string()
            .contains("without a declared divergence tag")
    );

    // Verify published docs match rendered matrices byte-for-byte
    let expected_bc_doc = bc_matrix.to_markdown("Beancount v3 & hledger Self Round-Trip Matrix");
    let expected_tb_doc =
        tb_matrix.to_markdown("TigerBeetle-Semantics Simulator Self-Consistency Matrix");
    let expected_std_doc =
        standards_matrix.to_markdown("ADS-, SAF-T- and XBRL-Shaped Export Round-Trip Matrix");

    // The docs are renderings of the matrices above. Setting
    // FA_WRITE_CONFORMANCE_DOCS rewrites them from this run; the comparison
    // below still runs against what was compiled in.
    if std::env::var_os("FA_WRITE_CONFORMANCE_DOCS").is_some() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/conformance");
        std::fs::write(format!("{root}/beancount.md"), &expected_bc_doc).expect("write");
        std::fs::write(format!("{root}/tigerbeetle.md"), &expected_tb_doc).expect("write");
        std::fs::write(format!("{root}/ads_saft_xbrl.md"), &expected_std_doc).expect("write");
    }

    let on_disk_bc = include_str!("../../../docs/conformance/beancount.md");
    let on_disk_tb = include_str!("../../../docs/conformance/tigerbeetle.md");
    let on_disk_std = include_str!("../../../docs/conformance/ads_saft_xbrl.md");

    assert_eq!(
        on_disk_bc, expected_bc_doc,
        "docs/conformance/beancount.md drifted from matrix"
    );
    assert_eq!(
        on_disk_tb, expected_tb_doc,
        "docs/conformance/tigerbeetle.md drifted from matrix"
    );
    assert_eq!(
        on_disk_std, expected_std_doc,
        "docs/conformance/ads_saft_xbrl.md drifted from matrix"
    );
}

/// fa-kkxl: a binary that answers `--version` and evaluates nothing is only
/// `Present`; the probe has no status that claims a journal was checked. A
/// missing binary, or one whose `--version` fails, is `Unrun`.
#[cfg(unix)]
#[test]
fn a_version_only_oracle_binary_is_present_never_verified() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("fa-oracle-probe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let script = |name: &str, body: &str| {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.display().to_string()
    };
    let fake = script("hledger", "echo 'hledger 1.99, fake'");
    assert_eq!(
        probe_external_oracle_binary(&fake),
        SubprocessOracleStatus::Present {
            binary: fake.clone(),
            version: "hledger 1.99, fake".into(),
        }
    );
    let failing = script("bean-check", "exit 3");
    assert!(matches!(
        probe_external_oracle_binary(&failing),
        SubprocessOracleStatus::Unrun { .. }
    ));
    let missing = dir.join("absent").display().to_string();
    assert!(matches!(
        probe_external_oracle_binary(&missing),
        SubprocessOracleStatus::Unrun { .. }
    ));
}

/// fa-formats review: a Beancount or hledger account name keeps only letters,
/// digits and dashes, so the code `1200.01` is written `Assets:A1200-01`.
/// Its `open` (or `account`) directive carries the exact code, but legs and
/// assertions were read back from the name, as `1200-01`, so a book with such
/// a code could not be read back (or its legs moved to `1200-01`). Two codes
/// that export to one name are refused, naming both.
#[test]
fn beancount_and_hledger_read_back_codes_their_names_cannot_spell() {
    let units = UnitCatalog::embedded().expect("units.toml");
    let base = sample_multi_unit_journal();
    let respelled = |code: &str| {
        if code == "1200" {
            "1200.01".to_owned()
        } else {
            code.to_owned()
        }
    };
    let rebuild = |accounts: Vec<FormatAccount>| {
        let mut entries = base.entries.clone();
        for leg in entries.iter_mut().flat_map(|e| e.legs.iter_mut()) {
            leg.account_code = respelled(&leg.account_code);
        }
        let mut assertions = base.assertions.clone();
        for assertion in &mut assertions {
            assertion.account_code = respelled(&assertion.account_code);
        }
        FormatJournal::new(
            &base.coordinate.book_name,
            &base.coordinate.base_unit_code,
            base.coordinate.base_unit_scale,
            base.coordinate.effective_through,
            base.coordinate.known_at_seq,
            accounts,
            entries,
            assertions,
        )
        .expect("a valid journal")
    };
    let mut accounts = base.accounts.clone();
    for account in &mut accounts {
        account.code = respelled(&account.code);
    }
    let journal = rebuild(accounts.clone());
    let expected = journal.fold_balances().expect("fa fold");
    assert!(
        expected.keys().any(|(account, _)| account == "1200.01"),
        "{expected:?}"
    );
    for (format, read) in [
        (
            "beancount",
            read_beancount(&write_beancount(&journal).unwrap(), &units),
        ),
        ("hledger", read_hledger(&write_hledger(&journal), &units)),
    ] {
        let read = read.unwrap_or_else(|e| panic!("{format}: {e}"));
        let balances = read.fold_balances().expect("fold");
        compare_balances_exact("acme-fy2026-p03", &expected, &balances)
            .unwrap_or_else(|e| panic!("{format}: {e}"));
    }

    // `1200_01` exports to the same name as `1200.01`.
    let mut colliding = accounts;
    let mut twin = colliding
        .iter()
        .find(|a| a.code == "1200.01")
        .cloned()
        .expect("the respelled account");
    twin.code = "1200_01".to_owned();
    colliding.push(twin);
    let journal = rebuild(colliding);
    for (format, read) in [
        (
            "beancount",
            read_beancount(&write_beancount(&journal).unwrap(), &units),
        ),
        ("hledger", read_hledger(&write_hledger(&journal), &units)),
    ] {
        let message = read.expect_err(format).to_string();
        assert!(
            message.contains("1200.01") && message.contains("1200_01"),
            "{format}: {message}"
        );
    }
}

/// fa-formats review: the NDJSON footer's `row_count` was checked as a
/// substring, so a footer of 12 counted a stream of 1 detail row.
#[test]
fn ndjson_gl_stream_footer_counts_its_rows_exactly() {
    let journal = sample_multi_unit_journal();
    let ndjson = write_ndjson_gl_stream(&journal).expect("write_ndjson_gl_stream");
    assert_eq!(verify_ndjson_gl_stream(&ndjson).expect("verify"), 8);
    let lines: Vec<&str> = ndjson.lines().filter(|l| !l.trim().is_empty()).collect();
    let footer = lines[lines.len() - 1];
    assert!(footer.contains("\"row_count\":8"), "{footer}");
    let truncated = format!(
        "{}\n{}\n{}\n",
        lines[0],
        lines[1],
        footer.replace("\"row_count\":8", "\"row_count\":12")
    );
    assert!(verify_ndjson_gl_stream(&truncated).is_err());
}

/// fa-formats review: the TigerBeetle corpus evaluator looked up a step's
/// credit account only by `expect` and summed balances unchecked, so a
/// scenario naming an unknown credit account, or an amount near `i128::MAX`,
/// panicked. Both are now refused as scenario violations.
#[test]
fn tigerbeetle_corpus_refuses_unknown_accounts_and_overflow_without_panicking() {
    use fa_formats::tigerbeetle::{TbStep, evaluate_scenario};

    let corpus = TbCorpus::embedded().expect("tigerbeetle_semantics.toml");
    let base = corpus.scenarios[0].clone();
    let account = base.accounts[0].code.clone();
    let step = |credit: &str, amount: i128| TbStep::Post {
        id: "planted".to_owned(),
        debit_account: account.clone(),
        credit_account: credit.to_owned(),
        amount,
        day: 0,
    };
    for (credit, amount, says) in [
        ("NOPE", 1, "unknown credit account NOPE"),
        (account.as_str(), i128::MAX, "overflows i128"),
    ] {
        let mut scenario = base.clone();
        // No limit, so the planted amount reaches the arithmetic.
        for state in &mut scenario.accounts {
            state.max_debit_net = 0;
        }
        scenario.steps.push(step(credit, amount));
        scenario.steps.push(step(credit, amount));
        let err = evaluate_scenario(&scenario).expect_err(says);
        assert!(
            matches!(&err, FormatError::TigerBeetleViolation { detail, .. } if detail.contains(says)),
            "{err:?}"
        );
    }
}
