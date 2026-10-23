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
    hex_encode, parse_exact_decimal,
    saft::{read_saft_xml, write_saft_xml},
    tigerbeetle::TbCorpus,
    verify_round_trip_identity,
    xbrl::{
        XbrlCalculationLinkbase, XbrlFact, XbrlInstance, validate_calculation_linkbase,
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
        },
        FormatAccount {
            code: "1010".to_owned(),
            name: "Euro Treasury Cash".to_owned(),
            account_type: AccountType::ASSET,
            normal_side: Side::Debit,
        },
        FormatAccount {
            code: "1200".to_owned(),
            name: "Accounts Receivable".to_owned(),
            account_type: AccountType::ASSET,
            normal_side: Side::Debit,
        },
        FormatAccount {
            code: "2000".to_owned(),
            name: "Accounts Payable".to_owned(),
            account_type: AccountType::LIABILITY,
            normal_side: Side::Credit,
        },
        FormatAccount {
            code: "3000".to_owned(),
            name: "Contributed Capital".to_owned(),
            account_type: AccountType::EQUITY,
            normal_side: Side::Credit,
        },
        FormatAccount {
            code: "4000".to_owned(),
            name: "Product Revenue".to_owned(),
            account_type: AccountType::REVENUE,
            normal_side: Side::Credit,
        },
        FormatAccount {
            code: "5000".to_owned(),
            name: "Cloud Hosting Expense".to_owned(),
            account_type: AccountType::EXPENSE,
            normal_side: Side::Debit,
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
                    account_code: "1000".to_owned(),
                    side: Side::Debit,
                    amount: Amount::new(UnitId(0), 250_000),
                    unit_code: "USD".to_owned(),
                    unit_scale: 2,
                    memo: Some("Seed wire USD".to_owned()),
                },
                FormatLeg {
                    account_code: "3000".to_owned(),
                    side: Side::Credit,
                    amount: Amount::new(UnitId(0), 250_000),
                    unit_code: "USD".to_owned(),
                    unit_scale: 2,
                    memo: None,
                },
                FormatLeg {
                    account_code: "1010".to_owned(),
                    side: Side::Debit,
                    amount: Amount::new(UnitId(1), 100_000),
                    unit_code: "EUR".to_owned(),
                    unit_scale: 2,
                    memo: Some("Seed wire EUR".to_owned()),
                },
                FormatLeg {
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
                    account_code: "1200".to_owned(),
                    side: Side::Debit,
                    amount: Amount::new(UnitId(0), 75_500),
                    unit_code: "USD".to_owned(),
                    unit_scale: 2,
                    memo: Some("INV-2026-042".to_owned()),
                },
                FormatLeg {
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
                    account_code: "5000".to_owned(),
                    side: Side::Debit,
                    amount: Amount::new(UnitId(0), 18_250),
                    unit_code: "USD".to_owned(),
                    unit_scale: 2,
                    memo: None,
                },
                FormatLeg {
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
    assert_eq!(formats.rows.len(), 24);
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
    let bc_text = write_beancount(&journal);
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
fn tigerbeetle_semantic_corpus_agrees_on_all_scenarios_and_catches_planted_mutation() {
    let corpus = TbCorpus::embedded().expect("tigerbeetle_semantics.toml");
    assert_eq!(corpus.scenarios.len(), 8);
    let results = corpus
        .evaluate_all()
        .expect("all 8 TigerBeetle semantic scenarios must agree");
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
        &read_beancount(&write_beancount(&journal), &units)
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
        notes: String::new(),
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
        no_claim_boundary: "The scenarios run through a TigerBeetle-semantics simulator inside fa-formats and are compared with expectations written by this project. The FrankenAccounting posting kernel is not exercised and TigerBeetle itself is not run, so no agreement with either is claimed; running the corpus through the kernel is fa-w3n6.".to_owned(),
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
        notes: concat!(
            "## ADS text versions (fa-8kpw)\n",
            "\n",
            "The writer retains literal `aicpa_ads_gl_v2` bytes for representable ordinary\n",
            "text. Text containing pipes, backslashes, quotes or control characters selects\n",
            "`aicpa_ads_gl_v3`, named explicitly in the coordinate certificate. Both versions\n",
            "remain readable. This is this repository's ADS-shaped profile, not a claim about\n",
            "an external AICPA escaping standard.\n",
            "\n",
            r"In v3 every table text field uses `\\` for a backslash, `\p` for a pipe,", "\n",
            r"`\n` and `\r` for line endings, and `\u` followed by four lowercase hex digits", "\n",
            "for other Unicode control characters. Every other character remains literal.\n",
            "Noncanonical and unknown escapes are refused. In GL_Detail's two optional text\n",
            r"columns, the whole field `\N` means absent; an empty field means present but", "\n",
            r"empty. Literal `\N` text therefore starts with an escaped backslash. Coordinate", "\n",
            "names use `book_name_utf8_hex` and `base_unit_code_utf8_hex`, preserving UTF-8\n",
            "without depending on the small TOML parser's supported escape subset.\n",
            "\n",
            "The same text law applies to identifiers in the chart, GL and trial balance.\n",
            "The std-only offline verifier has its own decoder and continues to verify the\n",
            "same proven selection, accounts, units, amounts and trial-balance refold. It\n",
            "does not authenticate description/memo text or chart names; escaping does not\n",
            "raise that proof class. New v3 regressions are authored in\n",
            "`ads_v3_preserves_delimiters_controls_unicode_and_empty_optional_text` and\n",
            "`ads_text_survives_real_post_export_reimport_and_offline_verification`; their\n",
            "current-source execution status must be taken from the corresponding gate,\n",
            "not from this format description.",
        )
        .to_owned(),
        rows: vec![
            ConformanceRow {
                fixture: "aicpa_ads_gl_v2_acme_fy2026_p03".to_owned(),
                expected: "round_trip_identity=true, refold_equal=true".to_owned(),
                observed: "round_trip_identity=true, refold_equal=true".to_owned(),
                divergence: "none".to_owned(),
                reason: "Byte-identical FormatJournal and FA-INV-04 refold digest after fa-formats' ADS-shaped export and its own re-import (asserted in aicpa_ads_and_oecd_saft_and_csv_gl_round_trip_identity_and_dropped_leg_negative).".to_owned(),
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
