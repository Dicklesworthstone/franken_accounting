//! Real kernel migrations exported through the functional report contract.
use super::*;
use fa_journal::{RunBody, RunControlRequest, RunMode, TrialBalanceLine};
use fa_model::{ApprovalRef, PeriodRef};

fn approvals(book: &mut Book, proposal: &EntryPayload) -> Vec<ApprovalRef> {
    let digest = proposal.proposal_digest().unwrap();
    [VId(8), VId(9)]
        .into_iter()
        .map(|principal| {
            book.approve(
                Capability::embedded(principal, &["approve"]).unwrap(),
                digest,
            )
            .unwrap()
            .unwrap()
            .approval()
        })
        .collect()
}

fn stage(fixture: &mut Fixture, foreign: bool) -> RunBody {
    fixture
        .book
        .install_chart(
            &[AccountSpec {
                code: "3000".into(),
                name: "Imported capital".into(),
                account_type: AccountType::EQUITY.0,
                normal_balance: 1,
                is_leaf: true,
                unit_policy: UnitPolicy::AnyCurrency,
                parent_code: None,
                limit: None,
            }],
            PRINCIPAL,
            day(1, 1),
            b"migration-equity-account",
            &cap(&["schema_change"]),
        )
        .unwrap()
        .unwrap();
    let close = cap(&["close"]);
    for (index, transition) in [
        PeriodTransition::Open,
        PeriodTransition::SoftClose,
        PeriodTransition::Close,
    ]
    .into_iter()
    .enumerate()
    {
        fixture
            .book
            .transition_period(
                "FY2026-OPEN",
                transition,
                PRINCIPAL,
                1,
                format!("migration-opening-{index}").as_bytes(),
                &close,
            )
            .unwrap()
            .unwrap();
    }
    let lock = fixture
        .book
        .plan_transition(
            "FY2026-OPEN",
            PeriodTransition::Lock,
            PRINCIPAL,
            1,
            b"migration-lock",
        )
        .unwrap()
        .unwrap();
    let digest = fixture.book.plan_digest(&lock).unwrap().unwrap();
    let approval = fixture
        .book
        .approve(Capability::embedded(VId(8), &["approve"]).unwrap(), digest)
        .unwrap()
        .unwrap()
        .approval();
    fixture
        .book
        .transition_planned(&lock, PeriodTransition::Lock, &close, &[approval])
        .unwrap()
        .unwrap();
    let evidence = fa_journal::evidence::Document {
        book_id: fixture.book.context().book_id,
        kind: 18,
        mime: "text/csv".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: b"account,native_minor_units\n1200,10000\n3000,-10000\n".to_vec(),
    };
    fixture.book.add_document(&evidence).unwrap().unwrap();
    let unit = if foreign { fixture.eur } else { fixture.usd };
    let body = RunBody {
        book_id: fixture.book.context().book_id,
        run_key: "portable-functional-opening".into(),
        source_system: "legacy".into(),
        mode: RunMode::OpeningOnly,
        trial_balance: evidence.oid(),
        opening_date: day(1, 1),
        lines: [("1200", 10_000), ("3000", -10_000)]
            .into_iter()
            .map(|(code, mantissa)| TrialBalanceLine {
                account_code: code.into(),
                unit,
                mantissa,
            })
            .collect(),
        periods: Vec::new(),
        detail_base: Vec::new(),
        sole_opening_source: false,
    };
    let authority = cap(&["post", "migrate"]);
    let proposal = fixture
        .book
        .open_migration_proposal(
            PRINCIPAL,
            &body,
            vec![evidence.evidence_ref(1)],
            b"open-functional-import",
            fixture
                .book
                .seal_text("Open imported carrying balances")
                .unwrap(),
        )
        .unwrap();
    fixture
        .book
        .open_migration_run(
            &body,
            RunControlRequest {
                proposal,
                capability: authority.clone(),
                approvals: Vec::new(),
            },
        )
        .unwrap()
        .unwrap();
    let mut proposal = fixture.proposal(b"functional-import", day(1, 1), 10_000);
    proposal.class = EntryClass::MIGRATION;
    proposal.legs[1].account_ref = account_vid(body.book_id, "3000");
    for leg in &mut proposal.legs {
        leg.amount.unit = unit;
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    proposal.effective_period = Some(PeriodRef {
        calendar: "fx-stock".into(),
        code: "FY2026-OPEN".into(),
    });
    proposal.origin = EntryOrigin::Migration {
        run_ref: body.vid(),
        source_system: body.source_system.clone(),
        source_id: fixture.book.seal_text("legacy-opening").unwrap(),
        source_recorded_at_ns: None,
        source_entered_by: None,
        source_approved_by: None,
        batch_oid: evidence.oid(),
    };
    proposal.evidence = vec![evidence.evidence_ref(1)];
    if foreign {
        let rate = fixture.rate(day(1, 1), 11, "Imported opening SpotClose");
        proposal = fixture
            .book
            .value_fx_proposal(
                &cap(&["read", "post", "migrate"]),
                proposal,
                FxLawId::SpotClose,
                &[rate],
            )
            .unwrap()
            .unwrap();
    }
    let approvals = approvals(&mut fixture.book, &proposal);
    fixture
        .book
        .post(PostRequest {
            proposal,
            capability: authority,
            approvals,
            plan_certificate: None,
        })
        .unwrap()
        .unwrap();
    body
}

fn finish(fixture: &mut Fixture, body: &RunBody, kind: u8) -> CommitSeq {
    let proposal = fixture
        .book
        .plan_migration_transition(
            body.vid(),
            kind,
            PRINCIPAL,
            b"finish-functional-import",
            fixture
                .book
                .seal_text("Finish imported carrying balances")
                .unwrap(),
        )
        .unwrap()
        .unwrap();
    let approvals = if kind == fa_journal::migration::kind::FINALIZE {
        approvals(&mut fixture.book, &proposal)
    } else {
        Vec::new()
    };
    fixture
        .book
        .transition_migration_run(RunControlRequest {
            proposal,
            capability: cap(&["post", "migrate"]),
            approvals,
        })
        .unwrap()
        .unwrap()
        .recorded_at
}

#[test]
fn functional_imports_reproduce_native_stock_activity_and_financial_statements_offline() {
    for foreign in [false, true] {
        let mut fixture = Fixture::new();
        let body = stage(&mut fixture, foreign);
        let staged = fixture.book.head().unwrap();
        let before = certify(&mut fixture, TrialBalanceSelection::AsOf(day(1, 31)));
        assert!(fixture.stock(day(1, 31), Some(staged)).cells.is_empty());
        let finalized = finish(&mut fixture, &body, fa_journal::migration::kind::FINALIZE);
        let expected = if foreign { 11_000 } else { 10_000 };
        let native = fixture.stock(day(1, 31), Some(finalized));
        assert_eq!(native.total_debits().unwrap(), expected);
        assert_eq!(native.total_credits().unwrap(), expected);
        assert_eq!(native.watermark, Some(finalized));
        let mut certificates = vec![before.clone()];
        for selection in [
            TrialBalanceSelection::AsOf(day(1, 31)),
            TrialBalanceSelection::Periods(vec!["FY2026-OPEN".into()]),
            TrialBalanceSelection::Activity(vec!["FY2026-OPEN".into()]),
        ] {
            certificates.push(certify(&mut fixture, selection));
        }
        for definition in ["balance-sheet", "income-statement"] {
            let certified = fixture
                .book
                .certify_functional_statement(
                    PRINCIPAL,
                    &producer(),
                    statement_selection(definition, true),
                    Some(finalized),
                )
                .unwrap()
                .unwrap();
            let line = if definition == "balance-sheet" {
                "assets"
            } else {
                "net_income"
            };
            assert_eq!(
                statement_amounts(&certified.statement, line, fixture.usd),
                if definition == "balance-sheet" {
                    vec![expected, expected]
                } else {
                    vec![0, 0]
                },
            );
            certificates.push(certified.certificate);
        }
        // A later ordinary backdate changes current balances but not any
        // retained pre- or post-Finalize mathematical claim.
        fixture.post(b"later-migration-backdate", day(1, 15), 500, 12);
        let state = checkpoint(&mut fixture.book);
        let head = fixture.book.head().unwrap();
        for certificate in certificates {
            let produced = produce(&mut fixture, state, &certificate);
            let verified = verify(&fixture, &produced, &certificate);
            assert_eq!(verified.output, certificate.output);
            if let Some(report) = verified.functional_trial_balance {
                let is_before = certificate.digest == before.digest;
                assert_eq!(
                    report.watermark,
                    if is_before { None } else { Some(finalized.0) }
                );
                assert_eq!(
                    report.cells.iter().map(|cell| cell.debits).sum::<i128>(),
                    if is_before { 0 } else { expected }
                );
            }
        }
        assert_eq!(fixture.book.head().unwrap(), head);
        assert!(
            fixture
                .book
                .produce_report_bundle(
                    PRINCIPAL,
                    &producer().for_accounts(&["1200"]).unwrap(),
                    Some(state),
                    &before,
                )
                .unwrap()
                .is_err()
        );
        assert_eq!(fixture.book.head().unwrap(), head);
    }
}

#[test]
fn an_abandoned_import_stays_absent_from_portable_functional_reports() {
    let mut fixture = Fixture::new();
    let body = stage(&mut fixture, true);
    finish(&mut fixture, &body, fa_journal::migration::kind::ABANDON);
    let certificate = certify(&mut fixture, TrialBalanceSelection::AsOf(day(1, 31)));
    let state = checkpoint(&mut fixture.book);
    let produced = produce(&mut fixture, state, &certificate);
    let verified = verify(&fixture, &produced, &certificate);
    assert!(verified.functional_trial_balance.unwrap().cells.is_empty());
    assert_eq!(verified.output, certificate.output);
}
