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

#[test]
fn account_screens_refuse_rehashed_omissions_amounts_roles_citations_and_work() {
    let mut f = Fixture::new(228);
    f.assign_role("1000", "suspense");
    f.assign_role("1020", "fixed_asset");
    f.post(1, "3000", "1000", 10_000, false);
    f.post(2, "6000", "1020", 5_000, false);
    for procedure in ["jet.suspense_aging", "expense.capitalization"] {
        let through = (procedure == "jet.suspense_aging").then_some(30);
        let certified = f.certify(&request(&f, procedure, through));
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
                        .find(|cite| matches!(cite, Cite::Entry(_)))
                        .unwrap();
                    *cite = Cite::Entry(VId(1));
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
