//! Receiver schedules must be independently reproducible after the producing
//! book is gone. Public hashes alone never establish principal attribution.

use super::*;
use fa_verify::report::{VerifiedProcedureParameters, VerifiedProcedureStatistic};

fn party(f: &mut Fixture, code: &str) {
    let cx = f.cx();
    let spec = fa_model::PartySpec {
        code: code.into(),
        kind: fa_model::PartyKind::Vendor,
        name: f.book.seal_text(&cx, code).unwrap(),
        identifiers: Vec::new(),
        external_ids: Vec::new(),
    };
    f.runtime
        .block_on(f.book.create_party(
            &cx,
            &spec,
            PRINCIPAL,
            day(1),
            code.as_bytes(),
            &cap(&["schema_change"]),
        ))
        .unwrap()
        .unwrap();
}

fn fixture(seed: u8) -> (Fixture, VId) {
    let mut f = Fixture::new(seed);
    f.assign_role("1000", "cash");
    f.assign_role("1010", "investor_transfer");
    let cx = f.cx();
    f.runtime
        .block_on(f.book.open_account(
            &cx,
            &AccountSpec {
                code: "2000".into(),
                name: "Investor principal liability".into(),
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
            b"offline-investor-liability",
            &cap(&["schema_change"]),
        ))
        .unwrap()
        .unwrap();
    f.assign_role("2000", "investor_capital");
    for name in ["INV-A", "INV-B", "VENDOR"] {
        party(&mut f, name);
    }
    let (source, _) = f.post(1, "3000", "1000", 1, false);
    (f, source)
}

fn movement(
    f: &mut Fixture,
    source: VId,
    key: &[u8],
    date: u8,
    legs: &[(&str, Side, i128, Option<&str>)],
) -> VId {
    let mut proposal = template(f, source, key, date);
    proposal.legs = legs
        .iter()
        .map(|&(account, side, amount, party)| {
            let mut leg = LegPayload::simple(side, f.id(account), Amount::new(f.unit, amount));
            if let Some(party) = party {
                leg.dimension_set.push((
                    fa_model::PARTY_DIMENSION,
                    fa_model::party_value_vid(f.book.context().book_id, party),
                ));
            }
            leg
        })
        .collect();
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    post(f, proposal)
}

fn request(f: &Fixture, through: Option<u8>) -> ProcedureRequest {
    let mut request =
        ProcedureRequest::new("ponzi.net_investment", catalog::Inputs::default()).unwrap();
    request.known_at = Some(f.head());
    request.effective_through = through.map(day);
    request.parameters = request.parameters.set("cohort_window_days", 2).unwrap();
    request
}

fn named<'a>(report: &'a ProcedureRun, name: &str) -> &'a fa_lantern::Finding {
    report
        .findings
        .iter()
        .find(|finding| finding.narrative.starts_with(&format!("investor {name} ")))
        .unwrap()
}

#[test]
fn ponzi_net_investment_exports_posted_principal_cutoffs_and_historical_roles_offline() {
    let (mut f, source) = fixture(192);
    movement(
        &mut f,
        source,
        b"subscribe",
        2,
        &[
            ("1000", Side::Debit, 100, None),
            ("3000", Side::Credit, 100, Some("INV-A")),
        ],
    );
    movement(
        &mut f,
        source,
        b"direct-transfer",
        5,
        &[
            ("3000", Side::Debit, 40, Some("INV-A")),
            ("3000", Side::Credit, 40, Some("INV-B")),
        ],
    );
    movement(
        &mut f,
        source,
        b"clearing-out",
        6,
        &[
            ("3000", Side::Debit, 10, Some("INV-B")),
            ("1010", Side::Credit, 10, None),
        ],
    );
    movement(
        &mut f,
        source,
        b"clearing-in",
        7,
        &[
            ("1010", Side::Debit, 10, None),
            ("2000", Side::Credit, 10, Some("INV-A")),
        ],
    );
    let payout = movement(
        &mut f,
        source,
        b"external-payout",
        8,
        &[
            ("1000", Side::Credit, 110, Some("INV-A")),
            ("6000", Side::Debit, 110, None),
        ],
    );
    movement(
        &mut f,
        source,
        b"vendor-refund",
        9,
        &[
            ("1000", Side::Debit, 7, None),
            ("6000", Side::Credit, 7, Some("VENDOR")),
        ],
    );
    movement(
        &mut f,
        source,
        b"unmarked-fee",
        10,
        &[
            ("3000", Side::Debit, 5, Some("INV-A")),
            ("6000", Side::Credit, 5, None),
        ],
    );
    let historical = f.certify(&request(&f, None));
    assert_eq!(historical.report.version, 5);
    assert_eq!(historical.report.findings.len(), 2);
    let a = named(&historical.report, "INV-A");
    assert_eq!(
        (
            a.statistic.name.as_str(),
            a.statistic.value,
            a.statistic.population
        ),
        ("fictitious_profit_clawback", 40, 7)
    );
    assert!(
        a.narrative
            .contains("cash_in=100, cash_out=110, transfer_in=10, transfer_out=40")
    );
    let b = named(&historical.report, "INV-B");
    assert_eq!(
        (b.statistic.name.as_str(), b.statistic.value),
        ("net_equity_claim", 30)
    );
    assert!(b.narrative.contains("cohort 2"));
    assert_eq!(
        (
            historical.report.work.entries,
            historical.report.work.legs,
            historical.report.work.comparisons
        ),
        (8, 16, 11)
    );
    let original_frontier = historical.certificate.known_at();
    let undo = reverse(&mut f, payout, b"later-payout-reversal", 20);
    let before_reversal = f.certify(&request(&f, Some(19)));
    assert_eq!(before_reversal.report.findings, historical.report.findings);
    let corrected = f.certify(&request(&f, Some(20)));
    assert_eq!(named(&corrected.report, "INV-A").statistic.value, 70);
    assert_eq!(
        named(&corrected.report, "INV-A").statistic.name,
        "net_equity_claim"
    );
    reverse(&mut f, undo, b"restore-payout", 21);
    let restored = f.certify(&request(&f, Some(21)));
    assert_eq!(restored.report.findings, historical.report.findings);
    let empty = f.certify(&request(&f, Some(1)));
    assert!(empty.report.findings.is_empty());
    // A later role revocation cannot reinterpret any saved frontier.
    let cx = f.cx();
    let revoked = crate::account_role::AccountRoleSpec {
        account: f.id("1000"),
        role: "cash".into(),
        assigned: false,
    };
    f.runtime
        .block_on(f.book.record_account_role(
            &cx,
            &revoked,
            PRINCIPAL,
            b"remove-cash-role",
            &cap(&["schema_change"]),
        ))
        .unwrap()
        .unwrap();
    let key = f.book.checkpoint_public_key();
    let mut artifacts = Vec::new();
    for certified in [historical, before_reversal, corrected, restored, empty] {
        assert_eq!(
            certified.certificate.format(),
            EXTENDED_PROCEDURE_CERTIFICATE_FORMAT
        );
        certified.certificate.check_offline_profile().unwrap();
        assert_eq!(
            f.book
                .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &certified.certificate)
                .unwrap()
                .unwrap(),
            certified.report
        );
        let produced = produce(&mut f, &certified.certificate);
        artifacts.push((certified, produced));
    }
    drop(f);
    for (certified, produced) in artifacts {
        let verified = verify(&produced, &certified.certificate, key);
        assert!(verified.checkpoint.checkpoint.through_seq > original_frontier.0);
        assert_eq!(decode_run(&verified.output).unwrap(), certified.report);
        let procedure = verified.procedure.unwrap();
        assert_eq!(
            procedure.parameters,
            VerifiedProcedureParameters::PonziNetInvestment {
                cohort_window_days: 2
            }
        );
        assert_eq!(
            (
                procedure.live_entries,
                procedure.live_legs,
                procedure.comparisons
            ),
            (
                certified.report.work.entries,
                certified.report.work.legs,
                certified.report.work.comparisons
            )
        );
        assert!(procedure.findings.iter().all(|finding| matches!(
            finding.statistic,
            VerifiedProcedureStatistic::InvestorPrincipal { .. }
        )));
    }
}

#[test]
fn ponzi_net_investment_discloses_unresolved_multi_party_cash_in_portable_output() {
    let (mut f, source) = fixture(193);
    movement(
        &mut f,
        source,
        b"known-principal",
        2,
        &[
            ("1000", Side::Debit, 100, None),
            ("3000", Side::Credit, 100, Some("INV-A")),
        ],
    );
    movement(
        &mut f,
        source,
        b"unresolved-mixed-funding",
        3,
        &[
            ("1000", Side::Debit, 50, None),
            ("6000", Side::Debit, 100, None),
            ("3000", Side::Credit, 100, Some("INV-A")),
            ("3000", Side::Credit, 50, Some("INV-B")),
        ],
    );
    let certified = f.certify(&request(&f, None));
    assert_eq!(certified.report.findings.len(), 2);
    let investor = named(&certified.report, "INV-A");
    assert_eq!(investor.statistic.value, 100);
    assert!(investor.narrative.ends_with("attribution=incomplete"));
    let unresolved = certified
        .report
        .findings
        .iter()
        .find(|finding| finding.statistic.name == "unresolved_attribution")
        .unwrap();
    assert_eq!(unresolved.statistic.value, 50);
    assert!(
        unresolved
            .narrative
            .contains("parties named: [INV-A, INV-B]")
    );
    let produced = produce(&mut f, &certified.certificate);
    let key = f.book.checkpoint_public_key();
    drop(f);
    let verified = verify(&produced, &certified.certificate, key);
    assert_eq!(decode_run(&verified.output).unwrap(), certified.report);
    assert!(
        verified
            .procedure
            .unwrap()
            .findings
            .iter()
            .any(|finding| matches!(
                finding.statistic,
                VerifiedProcedureStatistic::UnresolvedInvestorCash {
                    amount: 50,
                    scale: 2,
                    ..
                }
            ))
    );
}

#[test]
fn ponzi_net_investment_refuses_resealed_principal_attribution_and_selection_tampering() {
    let (mut f, source) = fixture(194);
    movement(
        &mut f,
        source,
        b"large-exact-principal",
        2,
        &[
            ("1000", Side::Debit, 9_007_199_254_740_993, None),
            ("3000", Side::Credit, 9_007_199_254_740_993, Some("INV-A")),
        ],
    );
    let certified = f.certify(&request(&f, None));
    let produced = produce(&mut f, &certified.certificate);
    let key = f.book.checkpoint_public_key();
    verify(&produced, &certified.certificate, key);
    for variant in [
        "amount",
        "population",
        "severity",
        "account",
        "entry",
        "party",
        "transfer",
        "omitted",
        "invented",
        "comparisons",
        "legs",
        "entries",
        "cutoff",
    ] {
        let mut forged = certified.certificate.clone();
        let report = &mut forged.report;
        match variant {
            "amount" => report.findings[0].statistic.value += 1,
            "population" => report.findings[0].statistic.population += 1,
            "severity" => report.findings[0].severity = Severity::Info,
            "account" => report.findings[0].cites[0] = Cite::Account(f.id("6000")),
            "entry" => {
                *report.findings[0]
                    .cites
                    .iter_mut()
                    .find(|cite| matches!(cite, Cite::Entry(_)))
                    .unwrap() = Cite::Entry(VId(1))
            }
            "party" => {
                report.findings[0].narrative =
                    report.findings[0].narrative.replace("INV-A", "INV-B")
            }
            "transfer" => {
                report.findings[0].narrative = report.findings[0]
                    .narrative
                    .replace("transfer_in=0", "transfer_in=1")
            }
            "omitted" => report.findings.clear(),
            "invented" => {
                let mut extra = report.findings[0].clone();
                extra.narrative.push_str(" fabricated additional investor");
                report.findings.push(extra);
            }
            "comparisons" => report.work.comparisons += 1,
            "legs" => report.work.legs += 1,
            "entries" => report.work.entries += 1,
            "cutoff" => report.coordinate.effective_through = Some(day(1)),
            _ => unreachable!(),
        }
        reseal(&mut forged);
        let changed = replace_certificate(&produced.bundle.bytes, &forged);
        assert_eq!(
            verify_report_expected(&changed, &[key], None, None, Some(forged.digest()))
                .unwrap_err()
                .predicate,
            "procedure_recomputation",
            "resealed {variant}"
        );
    }
    for variant in [
        "old-version",
        "future-version",
        "zero-window",
        "overflow-window",
        "missing-window",
        "duplicate-window",
        "account-filter",
    ] {
        let mut forged = certified.certificate.clone();
        match variant {
            "old-version" => change_report_version(&mut forged, 4),
            "future-version" => change_report_version(&mut forged, 6),
            "zero-window" => forged.report.parameters[0].1 = 0,
            "overflow-window" => forged.report.parameters[0].1 = i128::from(u32::MAX) + 1,
            "missing-window" => forged.report.parameters.clear(),
            "duplicate-window" => forged
                .report
                .parameters
                .push(forged.report.parameters[0].clone()),
            "account-filter" => forged
                .report
                .inputs
                .push(("account".into(), format!("{:032x}", f.id("1000").0))),
            _ => unreachable!(),
        }
        assert_eq!(
            forged.check_offline_profile().unwrap_err().code,
            fa_notary::code::SCOPE_UNSUPPORTED,
            "{variant}"
        );
        if variant == "duplicate-window" {
            // The native integrity-only decoder already refuses duplicate
            // parameter names; `reseal` intentionally requires that decoder
            // to accept every vector it passes to independent verification.
            continue;
        }
        reseal(&mut forged);
        let changed = replace_certificate(&produced.bundle.bytes, &forged);
        let error = verify_report_expected(&changed, &[key], None, None, Some(forged.digest()))
            .unwrap_err();
        assert!(
            matches!(error.predicate, "procedure_profile" | "canonical_encoding"),
            "{variant}: {error}"
        );
    }
    let command = fa_verify::cli::run(
        &[
            "report".into(),
            "investors.fab".into(),
            "--key".into(),
            key.iter().map(|byte| format!("{byte:02x}")).collect(),
            "--receipt".into(),
            "investors.receipt".into(),
            "--json".into(),
        ],
        &|path| match path {
            "investors.fab" => Ok(produced.bundle.bytes.clone()),
            "investors.receipt" => Ok(produced.receipt.clone()),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "unexpected input",
            )),
        },
    );
    assert_eq!(command.exit, 0, "{}", command.stdout);
    assert!(
        command.stdout.contains("\"value\":\"9007199254740993\""),
        "monetary mantissas must remain exact in JSON: {}",
        command.stdout
    );
    assert!(command.stdout.contains("posted_principal_transfer_v1"));
}
