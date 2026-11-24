//! Native account-role screens must survive portable, independent replay.
//! Later role changes and reversals cannot reinterpret the retained frontier;
//! repaired hashes on fabricated findings must not substitute for that replay.

use super::*;
use fa_verify::report::{VerifiedProcedureParameters, VerifiedProcedureStatistic};

fn request(f: &Fixture, procedure: &str, through: Option<u8>) -> ProcedureRequest {
    let mut request = ProcedureRequest::new(procedure, catalog::Inputs::default()).unwrap();
    request.known_at = Some(f.head());
    request.effective_through = through.map(day);
    request
}

fn clear_suspense(f: &mut Fixture, source: VId, amount: i128) -> VId {
    let (entry, _) = f.book.read_entry(&f.cx(), source).unwrap().unwrap();
    let ordinal = entry
        .proposal
        .legs
        .iter()
        .position(|leg| leg.account_ref == f.id("1000") && leg.side == Side::Debit)
        .unwrap();
    let mut proposal = template(f, source, b"offline-clear-suspense", 5);
    proposal.legs = vec![
        LegPayload::simple(Side::Credit, f.id("1000"), Amount::new(f.unit, amount)),
        LegPayload::simple(Side::Debit, f.id("1010"), Amount::new(f.unit, amount)),
    ];
    proposal.legs[0].settles.push(fa_model::Settlement {
        target: fa_model::EntryRef {
            vid: source,
            entry_digest: entry.entry_digest,
        },
        ordinal: u16::try_from(ordinal).unwrap(),
        amount: Amount::new(f.unit, amount),
    });
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    post(f, proposal)
}

fn unassign_role(f: &mut Fixture, code: &str, role: &str) {
    let cx = f.cx();
    let spec = crate::account_role::AccountRoleSpec {
        account: f.id(code),
        role: role.into(),
        assigned: false,
    };
    f.runtime
        .block_on(f.book.record_account_role(
            &cx,
            &spec,
            PRINCIPAL,
            format!("offline-unassign:{code}:{role}").as_bytes(),
            &cap(&["schema_change"]),
        ))
        .unwrap()
        .unwrap();
}

#[test]
fn suspense_aging_portably_replays_settlement_residuals_zero_net_and_historical_roles() {
    let mut f = Fixture::new(226);
    f.assign_role("1000", "suspense");
    let (cleared, _) = f.post(1, "3000", "1000", 10_000, false);
    let payment = clear_suspense(&mut f, cleared, 10_000);
    let (debit, _) = f.post(15, "3000", "1000", 6_000, false);
    let (credit, _) = f.post(20, "1000", "3000", 6_000, false);

    let cleared_history = f.certify(&request(&f, "jet.suspense_aging", Some(10)));
    assert!(cleared_history.report.findings.is_empty());
    let latest_live_day = f.certify(&request(&f, "jet.suspense_aging", None));
    assert!(latest_live_day.report.findings.is_empty());
    let exact_boundary = f.certify(&request(&f, "jet.suspense_aging", Some(22)));
    assert!(exact_boundary.report.findings.is_empty());
    let aged = f.certify(&request(&f, "jet.suspense_aging", Some(30)));
    assert_eq!(aged.report.findings.len(), 1);
    let finding = &aged.report.findings[0];
    assert_eq!(finding.statistic.value, 15);
    assert_eq!(finding.severity, Severity::High);
    assert!(finding.narrative.contains("net balance 0 in unit"));
    let mut cited = [debit, credit];
    cited.sort_unstable();
    assert_eq!(
        finding.cites,
        vec![
            Cite::Account(f.id("1000")),
            Cite::Entry(cited[0]),
            Cite::Entry(cited[1]),
        ]
    );
    reverse(&mut f, payment, b"offline-suspense-later-reversal", 31);
    let same_date_later_knowledge = f.certify(&request(&f, "jet.suspense_aging", Some(30)));
    assert_eq!(
        aged.report.findings,
        same_date_later_knowledge.report.findings
    );
    let restored = f.certify(&request(&f, "jet.suspense_aging", Some(31)));
    assert_eq!(restored.report.findings[0].statistic.value, 30);
    assert!(
        restored.report.findings[0]
            .cites
            .contains(&Cite::Entry(cleared))
    );
    unassign_role(&mut f, "1000", "suspense");

    let account = f.id("1000").0;
    let key = f.book.checkpoint_public_key();
    let artifacts = [
        cleared_history,
        latest_live_day,
        exact_boundary,
        aged,
        same_date_later_knowledge,
        restored,
    ]
    .into_iter()
    .map(|certified| {
        let produced = produce(&mut f, &certified.certificate);
        (certified, produced)
    })
    .collect::<Vec<_>>();
    drop(f);
    for (index, (certified, produced)) in artifacts.into_iter().enumerate() {
        let verified = verify(&produced, &certified.certificate, key);
        let procedure = verified.procedure.unwrap();
        assert_eq!(
            procedure.parameters,
            VerifiedProcedureParameters::SuspenseAging { max_age_days: 7 }
        );
        assert_eq!(procedure.version, 3);
        assert_eq!(procedure.live_entries, certified.report.work.entries);
        assert_eq!(procedure.live_legs, certified.report.work.legs);
        assert_eq!(procedure.comparisons, certified.report.work.comparisons);
        if index < 3 {
            assert!(procedure.findings.is_empty());
        } else {
            let VerifiedProcedureStatistic::SuspenseAge {
                account: found,
                age,
                ..
            } = procedure.findings[0].statistic
            else {
                panic!("suspense statistic");
            };
            assert_eq!(found, account);
            assert_eq!(age, if index == 5 { 30 } else { 15 });
        }
    }
}

#[test]
fn capitalization_portably_replays_declared_asset_and_accrual_roles_and_full_width_amounts() {
    let mut f = Fixture::new(227);
    f.assign_role("1020", "fixed_asset");
    // Retain a second unused fixed asset so later unassignment produces a
    // valid empty population, rather than a missing-role refusal.
    f.assign_role("1010", "fixed_asset");
    let cx = f.cx();
    f.runtime
        .block_on(f.book.open_account(
            &cx,
            &AccountSpec {
                code: "2000".into(),
                name: "Accrued operating costs".into(),
                account_type: AccountType::LIABILITY.0,
                normal_balance: 1,
                is_leaf: true,
                unit_policy: UnitPolicy::AnyCurrency,
                parent_code: None,
                limit: None,
            },
            day(1),
            None,
            PRINCIPAL,
            day(1),
            b"offline-accrued-account",
            &cap(&["schema_change"]),
        ))
        .unwrap()
        .unwrap();
    f.assign_role("2000", "accrued_expense");
    let amount = i128::from(i64::MAX) + 1;
    let (expense, _) = f.post(1, "6000", "1020", amount, false);
    f.post(2, "3000", "1020", 100, false);
    let (accrual, _) = f.post(3, "2000", "1020", 5_000, false);
    f.post(4, "6000", "1000", 8_000, false);
    let historical = f.certify(&request(&f, "expense.capitalization", None));
    assert_eq!(historical.report.findings.len(), 2);
    assert_eq!(historical.report.findings[0].statistic.value, amount);
    assert_eq!(
        historical.report.findings[0].cites,
        vec![
            Cite::Entry(expense),
            Cite::Account(f.id("1020")),
            Cite::Account(f.id("6000")),
        ]
    );
    assert_eq!(
        historical.report.findings[1].cites,
        vec![
            Cite::Entry(accrual),
            Cite::Account(f.id("1020")),
            Cite::Account(f.id("2000")),
        ]
    );
    unassign_role(&mut f, "2000", "accrued_expense");
    let no_accrual = f.certify(&request(&f, "expense.capitalization", None));
    assert_eq!(no_accrual.report.findings.len(), 1);
    unassign_role(&mut f, "1020", "fixed_asset");
    let no_selected_asset = f.certify(&request(&f, "expense.capitalization", None));
    assert!(no_selected_asset.report.findings.is_empty());
    let key = f.book.checkpoint_public_key();
    let artifacts = [historical, no_accrual, no_selected_asset]
        .into_iter()
        .map(|certified| {
            let produced = produce(&mut f, &certified.certificate);
            (certified, produced)
        })
        .collect::<Vec<_>>();
    drop(f);
    for (index, (certified, produced)) in artifacts.into_iter().enumerate() {
        let verified = verify(&produced, &certified.certificate, key);
        let procedure = verified.procedure.unwrap();
        assert_eq!(
            procedure.parameters,
            VerifiedProcedureParameters::ExpenseCapitalization
        );
        assert_eq!(procedure.version, 2);
        assert_eq!(procedure.findings.len(), 2 - index);
        assert_eq!(procedure.live_entries, certified.report.work.entries);
        assert_eq!(procedure.live_legs, certified.report.work.legs);
        assert_eq!(procedure.comparisons, 0);
        if let Some(first) = procedure.findings.first() {
            let VerifiedProcedureStatistic::CapitalizedExpense {
                amount: found,
                scale,
                ..
            } = first.statistic
            else {
                panic!("capitalization statistic");
            };
            assert_eq!(found, amount);
            assert_eq!(scale, 2);
        }
        let result = fa_verify::cli::run(
            &[
                "report".into(),
                "capitalization.fab".into(),
                "--key".into(),
                key.iter().map(|byte| format!("{byte:02x}")).collect(),
                "--receipt".into(),
                "capitalization.receipt".into(),
                "--json".into(),
            ],
            &|path| match path {
                "capitalization.fab" => Ok(produced.bundle.bytes.clone()),
                "capitalization.receipt" => Ok(produced.receipt.clone()),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "unexpected artifact",
                )),
            },
        );
        assert_eq!(result.exit, 0, "{}", result.stdout);
        if index < 2 {
            assert!(result.stdout.contains("\"value\":\"9223372036854775808\""));
        }
    }
}

fn liability_account(f: &mut Fixture, code: &str) {
    let cx = f.cx();
    f.runtime
        .block_on(f.book.open_account(
            &cx,
            &AccountSpec {
                code: code.into(),
                name: code.into(),
                account_type: AccountType::LIABILITY.0,
                normal_balance: 1,
                is_leaf: true,
                unit_policy: UnitPolicy::AnyCurrency,
                parent_code: None,
                limit: None,
            },
            day(1),
            None,
            PRINCIPAL,
            day(1),
            format!("offline-liability:{code}").as_bytes(),
            &cap(&["schema_change"]),
        ))
        .unwrap()
        .unwrap();
}

fn inventory_request(f: &Fixture, through: Option<u8>) -> ProcedureRequest {
    let mut selected = request(f, "aging.inventory", through);
    selected.parameters = selected.parameters.set("stale_days", 10).unwrap();
    selected
}

fn solvency_request(f: &Fixture, through: Option<u8>, haircut: u32) -> ProcedureRequest {
    let mut selected = request(f, "solvency.balance_sheet_test", through);
    selected.parameters = selected
        .parameters
        .set("fair_value_haircut_bps", i128::from(haircut))
        .unwrap();
    selected
}

#[test]
fn inventory_aging_portably_replays_relief_dates_cutoffs_reversals_and_historical_roles() {
    let mut f = Fixture::new(229);
    f.assign_role("1000", "inventory");
    f.assign_role("1010", "inventory");
    let empty = f.certify(&inventory_request(&f, None));
    assert!(empty.report.findings.is_empty());
    let (stock, _) = f.post(1, "3000", "1000", 10_000, false);
    let (relief, _) = f.post(5, "1000", "6000", 2_500, false);
    // Negative inventory positions do not become stale positive balances.
    f.post(6, "1010", "6000", 50, false);
    // An omitted cutoff comes from all live postings, including other accounts.
    f.post(28, "3000", "6000", 1, false);
    let boundary = f.certify(&inventory_request(&f, Some(15)));
    assert!(boundary.report.findings.is_empty());
    let moderate = f.certify(&inventory_request(&f, Some(16)));
    assert_eq!(moderate.report.findings.len(), 1);
    assert_eq!(moderate.report.findings[0].severity, Severity::Medium);
    assert_eq!(moderate.report.findings[0].statistic.value, 7_500);
    assert_eq!(moderate.report.findings[0].statistic.population, 3);
    let aged = f.certify(&inventory_request(&f, Some(25)));
    assert_eq!(aged.report.findings[0].severity, Severity::High);
    let derived_date = f.certify(&inventory_request(&f, None));
    assert!(
        derived_date.report.findings[0]
            .narrative
            .contains("23 day(s)")
    );
    reverse(&mut f, relief, b"offline-inventory-later-reversal", 31);
    let historical = f.certify(&inventory_request(&f, Some(25)));
    assert_eq!(historical.report.findings, aged.report.findings);
    let restored = f.certify(&inventory_request(&f, Some(31)));
    assert_eq!(restored.report.findings[0].statistic.value, 10_000);
    assert!(restored.report.findings[0].narrative.contains("30 day(s)"));
    assert_eq!(
        restored.report.findings[0].cites,
        vec![
            Cite::Account(f.id("1000")),
            Cite::Leg {
                entry: stock,
                ordinal: 1,
            },
        ]
    );
    unassign_role(&mut f, "1000", "inventory");
    let no_positive_inventory = f.certify(&inventory_request(&f, None));
    assert!(no_positive_inventory.report.findings.is_empty());

    let account = f.id("1000").0;
    let unit = f.unit.0;
    let key = f.book.checkpoint_public_key();
    let artifacts = [
        (empty, None),
        (boundary, None),
        (moderate, Some(7_500)),
        (aged, Some(7_500)),
        (derived_date, Some(7_500)),
        (historical, Some(7_500)),
        (restored, Some(10_000)),
        (no_positive_inventory, None),
    ]
    .into_iter()
    .map(|(certified, amount)| {
        let produced = produce(&mut f, &certified.certificate);
        (certified, produced, amount)
    })
    .collect::<Vec<_>>();
    drop(f);
    for (certified, produced, expected) in artifacts {
        let procedure = verify(&produced, &certified.certificate, key)
            .procedure
            .unwrap();
        assert_eq!(
            procedure.parameters,
            VerifiedProcedureParameters::InventoryAging { stale_days: 10 }
        );
        assert_eq!(procedure.version, 3);
        assert_eq!(procedure.live_entries, certified.report.work.entries);
        assert_eq!(procedure.live_legs, certified.report.work.legs);
        assert_eq!(procedure.comparisons, certified.report.work.comparisons);
        let Some(expected) = expected else {
            assert!(procedure.findings.is_empty());
            continue;
        };
        assert_eq!(procedure.findings.len(), 1);
        let VerifiedProcedureStatistic::StaleInventory {
            account: found,
            unit: found_unit,
            amount,
            scale,
            legs,
        } = &procedure.findings[0].statistic
        else {
            panic!("inventory statistic");
        };
        assert_eq!(*found, account);
        assert_eq!(*found_unit, unit);
        assert_eq!(*amount, expected);
        assert_eq!(*scale, 2);
        assert_eq!(*legs, vec![(stock.0, 1)]);
    }
}

#[test]
fn balance_sheet_solvency_portably_replays_signed_bases_exact_haircuts_and_effective_history() {
    let mut f = Fixture::new(230);
    liability_account(&mut f, "2000");
    liability_account(&mut f, "2010");
    let (asset, _) = f.post(1, "3000", "1000", 10_003, false);
    f.post(2, "1010", "6000", 2_001, false);
    let (debt, _) = f.post(3, "2000", "6000", 9_000, false);
    f.post(4, "6000", "2010", 1_000, false);
    let without_haircut = f.certify(&solvency_request(&f, Some(30), 0));
    assert!(without_haircut.report.findings.is_empty());
    let haircut = f.certify(&solvency_request(&f, Some(30), 1_000));
    assert_eq!(haircut.report.findings.len(), 1);
    assert_eq!(haircut.report.findings[0].severity, Severity::Critical);
    assert_eq!(haircut.report.findings[0].statistic.value, 799);
    assert_eq!(haircut.report.findings[0].statistic.population, 4);
    assert!(
        haircut.report.findings[0]
            .narrative
            .contains("asset_basis=8002, adjusted_assets=7201, total_liabilities=8000")
    );
    let total_haircut = f.certify(&solvency_request(&f, Some(30), 10_000));
    assert_eq!(total_haircut.report.findings[0].statistic.value, 8_000);

    let jpy = f.book.context().units.lookup("JPY").unwrap();
    let eur = f.book.context().units.lookup("EUR").unwrap();
    let large = i128::MAX / 2;
    let large_deficit = 8_507_059_173_023_461_586_584_365_185_794_205_287i128;
    let mut yen = template(&f, asset, b"offline-solvency-wide", 10);
    yen.legs = vec![
        LegPayload::simple(Side::Debit, f.id("1000"), Amount::new(jpy, large)),
        LegPayload::simple(Side::Credit, f.id("2000"), Amount::new(jpy, large)),
    ];
    yen.unit_totals = EntryPayload::fold_unit_totals(&yen.legs).unwrap();
    post(&mut f, yen);
    let wide = f.certify(&solvency_request(&f, Some(30), 1_000));
    assert_eq!(wide.report.findings[0].statistic.value, large_deficit);

    for (key, from, amount) in [
        (b"offline-solvency-negative-asset".as_slice(), "1020", 500),
        (b"offline-solvency-euro-debt".as_slice(), "2000", 100),
    ] {
        let mut euro = template(&f, asset, key, 11);
        euro.legs = vec![
            LegPayload::simple(Side::Credit, f.id(from), Amount::new(eur, amount)),
            LegPayload::simple(Side::Debit, f.id("6000"), Amount::new(eur, amount)),
        ];
        euro.unit_totals = EntryPayload::fold_unit_totals(&euro.legs).unwrap();
        post(&mut f, euro);
    }
    let signed = f.certify(&solvency_request(&f, Some(30), 1_000));
    let negative_assets = signed
        .report
        .findings
        .iter()
        .find(|finding| finding.statistic.value == 600)
        .unwrap();
    assert!(
        negative_assets
            .narrative
            .contains("asset_basis=-500, adjusted_assets=-500")
    );
    reverse(&mut f, debt, b"offline-solvency-future-reversal", 31);
    let historical = f.certify(&solvency_request(&f, Some(30), 1_000));
    assert_eq!(historical.report.findings, signed.report.findings);
    let after_reversal = f.certify(&solvency_request(&f, Some(31), 1_000));
    let all_dates = f.certify(&solvency_request(&f, None, 1_000));
    assert_eq!(after_reversal.report.findings, all_dates.report.findings);

    let usd = f.unit.0;
    let key = f.book.checkpoint_public_key();
    let artifacts = [
        (without_haircut, 0, vec![]),
        (haircut, 1_000, vec![(usd, 799)]),
        (total_haircut, 10_000, vec![(usd, 8_000)]),
        (wide, 1_000, vec![(usd, 799), (jpy.0, large_deficit)]),
        (
            signed,
            1_000,
            vec![(usd, 799), (jpy.0, large_deficit), (eur.0, 600)],
        ),
        (
            historical,
            1_000,
            vec![(usd, 799), (jpy.0, large_deficit), (eur.0, 600)],
        ),
        (
            after_reversal,
            1_000,
            vec![(jpy.0, large_deficit), (eur.0, 600)],
        ),
        (all_dates, 1_000, vec![(jpy.0, large_deficit), (eur.0, 600)]),
    ]
    .into_iter()
    .map(|(certified, haircut, amounts)| {
        let produced = produce(&mut f, &certified.certificate);
        (certified, produced, haircut, amounts)
    })
    .collect::<Vec<_>>();
    drop(f);
    for (certified, produced, haircut, expected) in artifacts {
        let procedure = verify(&produced, &certified.certificate, key)
            .procedure
            .unwrap();
        assert_eq!(
            procedure.parameters,
            VerifiedProcedureParameters::BalanceSheetSolvency {
                fair_value_haircut_bps: haircut,
            }
        );
        assert_eq!(procedure.version, 3);
        assert_eq!(procedure.live_entries, certified.report.work.entries);
        assert_eq!(procedure.live_legs, certified.report.work.legs);
        assert_eq!(procedure.comparisons, certified.report.work.comparisons);
        let amounts = procedure
            .findings
            .iter()
            .map(|finding| {
                let VerifiedProcedureStatistic::InsolvencyDeficit {
                    unit,
                    amount,
                    scale,
                    accounts,
                    entries,
                } = &finding.statistic
                else {
                    panic!("solvency statistic");
                };
                assert_eq!(*scale, if *unit == jpy.0 { 0 } else { 2 });
                assert!(!accounts.is_empty());
                assert!(!entries.is_empty());
                assert!(accounts.windows(2).all(|pair| pair[0] < pair[1]));
                assert!(entries.windows(2).all(|pair| pair[0] < pair[1]));
                (*unit, *amount)
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(amounts, expected.into_iter().collect());
    }
}

#[test]
fn portable_solvency_refuses_inline_valuations_even_outside_its_effective_window() {
    use fa_model::valuation::{
        InlineValuationTerms, ValuationApplicabilityLaw, ValuationBasisLaw, ValuationSubject,
    };

    let mut f = Fixture::new(231);
    liability_account(&mut f, "2000");
    let (source, _) = f.post(1, "2000", "1000", 10_000, false);
    let original = f.certify(&solvency_request(&f, Some(30), 1_000));
    let mut later_valuation = template(&f, source, b"offline-future-valuation", 31);
    later_valuation.extensions.push(
        InlineValuationTerms::to_extension(&[InlineValuationTerms {
            valuation_id: "future-independent-valuation".into(),
            subject: ValuationSubject::Account(f.id("1000")),
            entity: None,
            unit: f.unit,
            basis_law: ValuationBasisLaw::SignedDelta,
            applicability: ValuationApplicabilityLaw::ExactAsOf {
                effective_date: day(31),
            },
            signed_amount: 500,
            supersedes: None,
        }])
        .unwrap(),
    );
    post(&mut f, later_valuation);
    let selected = f.certify(&solvency_request(&f, Some(30), 1_000));
    assert_eq!(original.report.findings, selected.report.findings);

    // A supported carrier transports the same authenticated prefix. Replacing
    // only its certificate bypasses the producer guard; the recipient must
    // independently reject the valuation-bearing solvency source profile.
    let carrier = f.certify(&round_request(&f, 2, Some(day(30))));
    let produced = produce(&mut f, &carrier.certificate);
    let key = f.book.checkpoint_public_key();
    let forged = replace_certificate(&produced.bundle.bytes, &selected.certificate);
    let refused = verify_report_expected(
        &forged,
        &[key],
        None,
        None,
        Some(selected.certificate.digest()),
    )
    .unwrap_err();
    assert_eq!(refused.predicate, "procedure_profile", "{refused:?}");

    let before = f.head();
    let cx = f.cx();
    let refused = f
        .runtime
        .block_on(f.book.produce_procedure_report_bundle(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            None,
            &selected.certificate,
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, fa_notary::code::SCOPE_UNSUPPORTED);
    assert!(refused.message.contains("inline valuation"));
    assert_eq!(f.head(), before);

    // A later checkpoint covers an older certificate without importing later
    // valuation records into that certificate's original known-at prefix.
    let historical = produce(&mut f, &original.certificate);
    drop(f);
    verify(&historical, &original.certificate, key);
}

#[test]
fn account_screens_refuse_rehashed_omissions_amounts_roles_citations_and_work() {
    let mut f = Fixture::new(228);
    f.assign_role("1000", "suspense");
    f.assign_role("1000", "inventory");
    f.assign_role("1020", "fixed_asset");
    liability_account(&mut f, "2000");
    f.post(1, "3000", "1000", 10_000, false);
    f.post(2, "6000", "1020", 5_000, false);
    f.post(3, "2000", "6000", 20_000, false);
    for procedure in [
        "jet.suspense_aging",
        "expense.capitalization",
        "aging.inventory",
        "solvency.balance_sheet_test",
    ] {
        let selected = match procedure {
            "aging.inventory" => inventory_request(&f, Some(30)),
            "solvency.balance_sheet_test" => solvency_request(&f, Some(30), 0),
            "jet.suspense_aging" => request(&f, procedure, Some(30)),
            _ => request(&f, procedure, None),
        };
        let certified = f.certify(&selected);
        assert_eq!(certified.report.findings.len(), 1);
        let produced = produce(&mut f, &certified.certificate);
        let key = f.book.checkpoint_public_key();
        verify(&produced, &certified.certificate, key);
        for variant in [
            "amount",
            "population",
            "severity",
            "account",
            "entry",
            "narrative",
            "omitted",
            "work",
        ] {
            let mut forged = certified.certificate.clone();
            let report = &mut forged.report;
            match variant {
                "amount" => report.findings[0].statistic.value += 1,
                "population" => report.findings[0].statistic.population += 1,
                "severity" => report.findings[0].severity = Severity::Info,
                "account" => {
                    let cite = report.findings[0]
                        .cites
                        .iter_mut()
                        .find(|cite| matches!(cite, Cite::Account(_)))
                        .unwrap();
                    *cite = Cite::Account(f.id("1010"));
                }
                "entry" => {
                    let cite = report.findings[0]
                        .cites
                        .iter_mut()
                        .find(|cite| matches!(cite, Cite::Entry(_) | Cite::Leg { .. }))
                        .unwrap();
                    match cite {
                        Cite::Entry(entry) | Cite::Leg { entry, .. } => *entry = VId(1),
                        _ => unreachable!(),
                    }
                }
                "narrative" => report.findings[0].narrative.push_str(" fabricated"),
                "omitted" => report.findings.clear(),
                "work" => report.work.comparisons += 1,
                _ => unreachable!(),
            }
            reseal(&mut forged);
            let bytes = replace_certificate(&produced.bundle.bytes, &forged);
            let error = verify_report_expected(&bytes, &[key], None, None, Some(forged.digest()))
                .unwrap_err();
            assert_eq!(
                error.predicate, "procedure_recomputation",
                "{procedure}: resealed {variant}: {error:?}",
            );
        }
    }
}
