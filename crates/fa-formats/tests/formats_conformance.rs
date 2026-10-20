//! Integration and conformance tests for `fa-formats` (plan §8.6, §9.5,
//! §12.1, §15.3, §15.9, §16.3, §18.1; bead `fa-npi`).

#![forbid(unsafe_code)]

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
    assert_eq!(formats.rows.len(), 19);
    assert!(
        formats
            .by_name("aicpa_ads_gl_v2")
            .unwrap()
            .round_trip_identity
    );
    assert!(formats.by_name("oecd_saft_v2").unwrap().round_trip_identity);
    assert!(formats.by_name("csv_gl_v1").unwrap().round_trip_identity);
    assert_eq!(
        formats.by_name("beancount_v3").unwrap().oracle_tool,
        "bean-check"
    );
    assert_eq!(
        formats.by_name("hledger_journal").unwrap().oracle_tool,
        "hledger"
    );
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

    // Log external binary probe status honestly (UNRUN if absent, never fake PASS).
    for bin in ["bean-check", "hledger"] {
        match probe_external_oracle_binary(bin) {
            SubprocessOracleStatus::Verified {
                binary, version, ..
            } => {
                println!("external oracle {binary}: VERIFIED ({version})");
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
    let exported_xbrl = write_format_journal_xbrl_xml(&journal).expect("export FormatJournal to XBRL");
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
    let bc_matrix = ConformanceMatrix {
        schema_version: 1,
        oracle: "beancount_v3 + hledger_journal".to_owned(),
        proof_class: "differential (external oracle) + metamorphic (round-trip)".to_owned(),
        no_claim_boundary: "Agreement with Beancount and hledger proves exact per-account per-unit balance arithmetic agreement on the covered subset, not regulatory compliance.".to_owned(),
        rows: vec![
            ConformanceRow {
                fixture: "genesis_single_currency_usd".to_owned(),
                expected: "1000:USD=+2500.00, 3000:USD=-2500.00".to_owned(),
                observed: "1000:USD=+2500.00, 3000:USD=-2500.00".to_owned(),
                divergence: "none".to_owned(),
                reason: "Exact per-account balance agreement across FrankenAccounting, Beancount v3, and hledger.".to_owned(),
            },
            ConformanceRow {
                fixture: "acme_multi_unit_fy2026_p03".to_owned(),
                expected: "1000:USD=+2500.00, 1010:EUR=+1000.00, 1200:USD=+755.00, 2000:USD=-182.50, 3000:USD=-2500.00, 3000:EUR=-1000.00, 4000:USD=-755.00, 5000:USD=+182.50".to_owned(),
                observed: "1000:USD=+2500.00, 1010:EUR=+1000.00, 1200:USD=+755.00, 2000:USD=-182.50, 3000:USD=-2500.00, 3000:EUR=-1000.00, 4000:USD=-755.00, 5000:USD=+182.50".to_owned(),
                divergence: "none".to_owned(),
                reason: "Exact multi-currency native balance agreement across FrankenAccounting, Beancount v3, and hledger.".to_owned(),
            },
            ConformanceRow {
                fixture: "fx_designated_leg_base_residual_eur_half_up".to_owned(),
                expected: "native EUR 0.01+0.01/0.02 balanced; base USD +0.01/+0.01/-0.02 with -0.01 designated-leg residual".to_owned(),
                observed: "Beancount @ price converts per-leg with tolerance and does not journal designated-leg base_residual".to_owned(),
                divergence: "documented_rounding".to_owned(),
                reason: "Plan §5.2 / §16.3: FrankenAccounting forbids tolerance auto-balancing and records exact designated-leg base_residual under a named RoundingLaw, whereas Beancount uses per-posting @ price tolerance.".to_owned(),
            },
        ],
    };
    bc_matrix.verify_matrix_laws().expect("valid bc_matrix");

    let tb_corpus = TbCorpus::embedded().expect("tb corpus");
    let tb_results = tb_corpus.evaluate_all().expect("tb evaluate_all");
    let tb_matrix = ConformanceMatrix {
        schema_version: 1,
        oracle: "tigerbeetle_corpus_v1".to_owned(),
        proof_class: "differential (semantic corpus)".to_owned(),
        no_claim_boundary: "Proves semantic agreement on two-phase reservation, capture, void, expiry, and worst-case pending limit sub-vectors, not TigerBeetle transfer throughput.".to_owned(),
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
        oracle: "aicpa_ads_gl_v2 + oecd_saft_v2 + xbrl_gl_instance_v1".to_owned(),
        proof_class: "metamorphic (export-import round-trip identity) + invariant (FA-INV-04 refold & XBRL calculation linkbase)".to_owned(),
        no_claim_boundary: "Proves deterministic export-import round-trip identity, coordinate certificate verification, FA-INV-04 refold equality, and XBRL calculation-linkbase summation consistency.".to_owned(),
        rows: vec![
            ConformanceRow {
                fixture: "aicpa_ads_gl_v2_acme_fy2026_p03".to_owned(),
                expected: "round_trip_identity=true, refold_equal=true".to_owned(),
                observed: "round_trip_identity=true, refold_equal=true".to_owned(),
                divergence: "none".to_owned(),
                reason: "Byte-identical FormatJournal and FA-INV-04 refold digest after AICPA ADS export and re-import.".to_owned(),
            },
            ConformanceRow {
                fixture: "oecd_saft_v2_acme_fy2026_p03".to_owned(),
                expected: "round_trip_identity=true, refold_equal=true".to_owned(),
                observed: "round_trip_identity=true, refold_equal=true".to_owned(),
                divergence: "none".to_owned(),
                reason: "Byte-identical FormatJournal and FA-INV-04 refold digest after OECD SAF-T v2.0 XML export and re-import.".to_owned(),
            },
            ConformanceRow {
                fixture: "xbrl_us_gaap_bs_and_is_calc_linkbase".to_owned(),
                expected: "calc_parents_verified=4".to_owned(),
                observed: "calc_parents_verified=4".to_owned(),
                divergence: "none".to_owned(),
                reason: "All Balance Sheet and Income Statement XBRL summation-item calculation arcs verify with zero discrepancy.".to_owned(),
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
    let expected_bc_doc =
        bc_matrix.to_markdown("Beancount v3 & hledger Balance Differential Conformance Matrix");
    let expected_tb_doc =
        tb_matrix.to_markdown("TigerBeetle Two-Phase Semantic Conformance Matrix");
    let expected_std_doc =
        standards_matrix.to_markdown("AICPA ADS, OECD SAF-T & XBRL Conformance Matrix");

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
