//! Issued company layouts remain exact case questions across later activations.

use super::*;
use fa::{
    AccountSetExpr, CustomLineSource, CustomStatementDefinition, CustomStatementSelection,
    PresentationRoundingSpec, ReportCertificate, ReportSelection, StatementDefinition,
};

fn activate(
    book: &mut Book,
    name: &str,
    version: u32,
    effective: DateDay,
    stock: bool,
) -> CustomStatementSelection {
    let mut definition = CustomStatementDefinition::from_builtin(
        &StatementDefinition::embedded(if stock {
            "balance-sheet"
        } else {
            "income-statement"
        })
        .unwrap(),
    );
    definition.name = name.into();
    definition.title = format!("{name} version {version}");
    definition.version = version;
    if stock {
        for line in &mut definition.lines {
            if line.code == "assets"
                && let CustomLineSource::AccountSet { expr, .. } = &mut line.source
            {
                *expr = AccountSetExpr::AccountCodes(vec!["1000".into()]);
            }
        }
    }
    let capability = Capability::embedded(PRINCIPAL, &["rule_change"]).unwrap();
    let plan = book
        .plan_statement_definition(
            &capability,
            definition,
            effective,
            format!("{name}-{version}").as_bytes(),
        )
        .unwrap()
        .unwrap();
    let digest = plan.proposal_digest().unwrap();
    let approvals = [VId(2), VId(3)]
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
        .collect();
    let active = book
        .activate_statement_definition(&capability, plan, approvals)
        .unwrap()
        .unwrap();
    CustomStatementSelection {
        definition: active.definition,
        activation: active.activation,
        activated_at: active.recorded_at,
        functional: false,
        periods: vec!["FY2025-P12".into()],
        comparative: vec!["FY2025-P11".into()],
        presentation: Some(PresentationRoundingSpec {
            rounding_law: fa_money::RoundingLaw::HalfEven,
            scale_reduction_digits: 1,
            residual_line_code: "rounding".into(),
            residual_line_label: "Presentation rounding".into(),
        }),
    }
}

fn issue(book: &mut Book, selected: CustomStatementSelection) -> ReportCertificate {
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce", "close"]).unwrap();
    let source = if selected.functional {
        book.certify_functional_custom_statement(&capability, selected, None)
    } else {
        book.certify_custom_statement(&capability, selected, None)
    }
    .unwrap()
    .unwrap()
    .certificate;
    issue_source(book, source)
}

fn issue_instant_builtin(book: &mut Book) -> ReportCertificate {
    let runtime = asupersync::runtime::RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    let witness = Capability::embedded(PRINCIPAL, &["witness"]).unwrap();
    let instant = fa_time::UtcInstant::parse("2026-01-10T00:00:00Z")
        .unwrap()
        .unix_ns();
    for (observed, monotonic) in [(instant, false), (instant + 10, true)] {
        runtime
            .block_on(book.record_tick(&root, observed, monotonic, &witness))
            .unwrap()
            .unwrap();
    }
    let source = book
        .certify_statement_at_instant(
            fa::StatementSelection {
                definition: StatementDefinition::embedded("balance-sheet").unwrap(),
                periods: vec!["FY2025-P12".into()],
                comparative: vec!["FY2025-P11".into()],
            },
            instant + 5,
        )
        .unwrap()
        .unwrap()
        .certificate;
    assert!(source.time_selection.is_some());
    issue_source(book, source)
}

fn issue_source(book: &mut Book, source: ReportCertificate) -> ReportCertificate {
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce", "close"]).unwrap();
    book.retain_certificate(PRINCIPAL, &capability, &source)
        .unwrap()
        .unwrap();
    assert!(
        book.plan_statement_issuance(
            &capability,
            &source.digest,
            Some("FY2025-P11"),
            fa_journal::IssuedTo::Auditor,
            None,
            day(2026, 1, 10),
            b"comparative-is-not-issued",
        )
        .unwrap()
        .is_err(),
        "a comparative is not an issuance's current period"
    );
    let plan = book
        .plan_statement_issuance(
            &capability,
            &source.digest,
            None,
            fa_journal::IssuedTo::Auditor,
            None,
            day(2026, 1, 10),
            b"custom-original",
        )
        .unwrap()
        .unwrap();
    let metadata = source.selection.statement_metadata().unwrap().unwrap();
    assert_eq!(plan.issuance.definition_digest, metadata.definition_digest);
    assert_eq!(plan.issuance.definition_name, metadata.definition_name);
    assert_eq!(
        plan.issuance.definition_version,
        metadata.definition_version
    );
    let approval = book
        .approve(
            Capability::embedded(VId(9), &["approve"]).unwrap(),
            plan.proposal_digest(book.context()).unwrap(),
        )
        .unwrap()
        .unwrap()
        .approval();
    book.issue_statements(&capability, plan, vec![approval])
        .unwrap()
        .unwrap();
    source
}

fn posted_custom_case(
    seed: u8,
    functional: bool,
    first_effective: DateDay,
    add_unmapped_account: bool,
    instant_builtin: bool,
) -> (Book, ReportCertificate) {
    let (mut book, narrative, authority) = book(seed);
    let close = Capability::embedded(PRINCIPAL, &["close"]).unwrap();
    book.transition_period(
        "FY2025-P12",
        PeriodTransition::Open,
        PRINCIPAL,
        1,
        b"open",
        &close,
    )
    .unwrap()
    .unwrap();
    let book_id = book.context().book_id;
    let usd = book.context().units.lookup("USD").unwrap();
    let legs = |amount| {
        vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book_id, "1000"),
                Amount::new(usd, amount),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(book_id, "3000"),
                Amount::new(usd, amount),
            ),
        ]
    };
    let receipt = Document {
        book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: b"Receipt of 10.53 USD originally recorded as 10.02".to_vec(),
    };
    book.add_document(&receipt).unwrap().unwrap();
    let original_legs = legs(1_002);
    let original = EntryPayload {
        schema_minor: 0,
        book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: day(2025, 12, 15),
        document_date: None,
        description: book
            .seal_text("Receipt corrected by the custom case")
            .unwrap(),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&original_legs).unwrap(),
        legs: original_legs,
        control: None,
        base_totals: None,
        idempotency_key: b"receipt".to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([seed; 32]),
            intent_kind: 1,
        },
        principal_ref: PRINCIPAL,
        session_ref: None,
        evidence: vec![receipt.evidence_ref(1)],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    let target = book
        .post(PostRequest {
            proposal: original.clone(),
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        })
        .unwrap()
        .unwrap()
        .entry_ref();
    let mut chosen = activate(&mut book, "company-position", 1, first_effective, true);
    chosen.functional = functional;
    activate(&mut book, "company-income", 1, day(2025, 1, 1), false);
    activate(&mut book, "current-only-layout", 1, day(2025, 12, 1), true);
    // This frontier already knows a newer version; issuance still pins v1.
    let second_effective = if first_effective < day(2025, 6, 1) {
        day(2025, 6, 1)
    } else {
        day(2025, 12, 10)
    };
    activate(&mut book, "company-position", 2, second_effective, true);
    let source = if instant_builtin {
        issue_instant_builtin(&mut book)
    } else {
        issue(&mut book, chosen)
    };
    activate(&mut book, "company-position", 3, day(2025, 12, 20), true);
    activate(&mut book, "later-company-layout", 1, day(2025, 1, 1), true);
    if add_unmapped_account {
        book.install_chart(
            &[AccountSpec {
                code: "1100".into(),
                name: "New zero-balance asset".into(),
                account_type: AccountType::ASSET.0,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::AnyCurrency,
                parent_code: None,
                limit: None,
            }],
            PRINCIPAL,
            day(2025, 12, 21),
            b"new-zero-account",
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        )
        .unwrap()
        .unwrap();
    }
    book.transition_period(
        "FY2025-P12",
        PeriodTransition::Close,
        PRINCIPAL,
        1,
        b"close",
        &close,
    )
    .unwrap()
    .unwrap();
    let restate = Capability::embedded(PRINCIPAL, &["restate", "read", "produce"]).unwrap();
    let date = day(2026, 2, 12);
    book.open_case(
        restate.clone(),
        CaseKind::Revision,
        vec!["FY2025-P12".into()],
        Some(narrative),
        Some(Determination {
            day: date,
            authority,
        }),
        date,
        b"revision",
    )
    .unwrap()
    .unwrap();
    let planner = Capability::embedded(VId(4), &["post", "read", "restate"]).unwrap();
    book.open_scenario(
        planner.clone(),
        "custom-revision",
        ScenarioFork::default(),
        original.effective_date,
        "Correct the original receipt",
    )
    .unwrap()
    .unwrap();
    let mut revision = original;
    revision.class = EntryClass::REVISION;
    revision.principal_ref = VId(4);
    revision.idempotency_key = b"delta".to_vec();
    revision.legs = legs(51);
    revision.unit_totals = EntryPayload::fold_unit_totals(&revision.legs).unwrap();
    revision.supersession = vec![fa_model::Supersession {
        target,
        kind: fa_model::SupersessionKind::Revises,
        reason_code: 4,
    }];
    book.run_in_scenario(
        planner,
        "custom-revision",
        PostIntent::new(revision, Vec::new()).unwrap(),
    )
    .unwrap()
    .unwrap();
    let rehearsal = book
        .certify_scenario_diff(
            PRINCIPAL,
            &restate,
            "custom-revision",
            &["FY2025-P12".into()],
            false,
        )
        .unwrap()
        .unwrap();
    book.rehearse_case(
        restate.clone(),
        1,
        &rehearsal.certificate,
        date,
        b"rehearsal",
    )
    .unwrap()
    .unwrap();
    let digest = book.case_manifest(1).unwrap().unwrap().digest().unwrap();
    let approvals = [VId(2), VId(3)]
        .into_iter()
        .map(|principal| {
            book.approve(
                Capability::embedded(principal, &["approve"]).unwrap(),
                digest,
            )
            .unwrap()
            .unwrap()
            .approval()
            .approval_vid
        })
        .collect();
    book.approve_case(restate, 1, approvals, date, b"approve")
        .unwrap()
        .unwrap();
    book.post_case(
        Capability::embedded(PRINCIPAL, &["restate", "post", "read"]).unwrap(),
        1,
        date,
        b"post",
    )
    .unwrap()
    .unwrap();
    (book, source)
}

#[test]
fn issued_custom_case_comparisons_preserve_exact_sources_and_require_all_original_layouts() {
    for functional in [false, true] {
        let (mut book, source) = posted_custom_case(
            0xe1 + u8::from(functional),
            functional,
            day(2025, 1, 1),
            false,
            false,
        );
        let read = Capability::embedded(PRINCIPAL, &["read"]).unwrap();
        let produce = Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap();
        assert_eq!(
            book.reported_statement(&read, &source.digest, "FY2025-P12")
                .unwrap()
                .unwrap(),
            source
        );
        assert_eq!(
            book.reported_statement(&read, &source.digest, "FY2025-P11")
                .unwrap()
                .unwrap(),
            source
        );
        assert!(
            book.reported_statement(&read, &source.digest, "FY2025-P10")
                .unwrap()
                .is_err()
        );
        assert!(
            book.reported_statement(
                &Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
                &source.digest,
                "FY2025-P12"
            )
            .unwrap()
            .is_err()
        );
        let originally = book.originally_reported("FY2025-P12").unwrap().unwrap();
        assert_eq!(originally.known_at, source.known_at);
        assert!(
            matches!(originally.basis, fa_journal::ReportedBasis::Issuance(record)
            if record.issuance.certificate == source.digest)
        );
        assert_eq!(
            book.issued_to("FY2025-P12", fa_journal::IssuedTo::Auditor)
                .unwrap()
                .unwrap()
                .issuance
                .certificate,
            source.digest
        );
        let questions = book
            .case_statement_diff_requests(PRINCIPAL, &read, 1, None)
            .unwrap()
            .unwrap();
        let question = questions
            .iter()
            .find(|question| !question.opening && question.request.selection == source.selection)
            .unwrap();
        assert!(
            questions
                .iter()
                .all(|question| question.functional == functional)
        );
        assert!(questions.iter().any(|question| {
            question
                .request
                .selection
                .statement_metadata()
                .unwrap()
                .unwrap()
                .definition_name
                == "company-income"
        }));
        assert!(questions.iter().all(|question| {
            question
                .request
                .selection
                .statement_metadata()
                .unwrap()
                .unwrap()
                .definition_name
                != "later-company-layout"
        }));
        let current_only: Vec<_> = questions
            .iter()
            .filter(|question| {
                question
                    .request
                    .selection
                    .statement_metadata()
                    .unwrap()
                    .unwrap()
                    .definition_name
                    == "current-only-layout"
            })
            .collect();
        assert_eq!(current_only.len(), 1);
        assert!(
            !current_only[0].opening,
            "an unissued stock name first effective after opening is not an opening layout"
        );
        let opening = questions
            .iter()
            .find(|question| {
                question.opening
                    && question
                        .request
                        .selection
                        .statement_metadata()
                        .unwrap()
                        .unwrap()
                        .definition_name
                        == "company-position"
            })
            .unwrap();
        assert_eq!(
            opening.period, "FY2025-P10",
            "opening precedes the earliest issued comparative"
        );
        let ReportSelection::CustomStatement(opening_selection) = &opening.request.selection else {
            panic!()
        };
        let ReportSelection::CustomStatement(original_selection) = &source.selection else {
            panic!()
        };
        assert_eq!(opening_selection.activation, original_selection.activation);
        assert_eq!(
            opening_selection.presentation,
            original_selection.presentation
        );
        let before_read = book.head().unwrap();
        let difference = book
            .case_statement_diff(PRINCIPAL, &read, question)
            .unwrap()
            .unwrap();
        assert!(
            difference
                .lines()
                .iter()
                .any(|line| line.code == "assets" && line.delta == [51, 0])
        );
        assert_eq!(
            book.head().unwrap(),
            before_read,
            "Read-only comparison does not publish"
        );
        assert!(
            book.certify_case_statement_diff(PRINCIPAL, &read, question)
                .unwrap()
                .is_err()
        );
        let certified = book
            .certify_case_statement_diff(PRINCIPAL, &produce, question)
            .unwrap()
            .unwrap();
        assert_eq!(
            certified.certificate.sources().0,
            &source,
            "keep the certificate actually issued"
        );
        assert_eq!(
            certified.certificate.report_selection().unwrap(),
            source.selection
        );
        let mut wrong_measure = question.clone();
        wrong_measure.functional = !functional;
        assert!(
            book.case_statement_diff(PRINCIPAL, &read, &wrong_measure)
                .unwrap()
                .is_err()
        );
        let comparisons = retain_case_comparisons(&mut book, 1);
        let disclosure = Document {
            book_id: book.context().book_id,
            kind: 20,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"Custom layout correction disclosure".to_vec(),
        };
        book.add_document(&disclosure).unwrap().unwrap();
        book.record_review(
            &Capability::embedded(VId(5), &["approve"]).unwrap(),
            &disclosure.oid(),
            Vec::new(),
        )
        .unwrap()
        .unwrap();
        let disclose = Capability::embedded(PRINCIPAL, &["restate", "read"]).unwrap();
        let mut omitted = comparisons.clone();
        omitted.retain(|digest| digest != certified.certificate.digest());
        assert_eq!(omitted.len() + 1, comparisons.len());
        let head = book.head().unwrap();
        assert_eq!(
            book.disclose_case(
                disclose.clone(),
                1,
                disclosure.oid(),
                &omitted,
                day(2026, 2, 15),
                b"missing-original-layout"
            )
            .unwrap()
            .unwrap_err()
            .code,
            code::CASE_STATEMENT_DIFF
        );
        assert_eq!(book.head().unwrap(), head);
        let mut changed_presentation = question.clone();
        let ReportSelection::CustomStatement(selection) =
            &mut changed_presentation.request.selection
        else {
            panic!()
        };
        selection.presentation = None;
        let wrong = book
            .certify_case_statement_diff(PRINCIPAL, &produce, &changed_presentation)
            .unwrap()
            .unwrap()
            .certificate;
        book.retain_report_artifact(
            PRINCIPAL,
            &produce,
            &wrong.canonical_bytes().unwrap(),
            Some(wrong.digest()),
        )
        .unwrap()
        .unwrap();
        let mut replaced = omitted;
        replaced.push(*wrong.digest());
        assert_eq!(
            book.disclose_case(
                disclose.clone(),
                1,
                disclosure.oid(),
                &replaced,
                day(2026, 2, 15),
                b"changed-presentation"
            )
            .unwrap()
            .unwrap_err()
            .code,
            code::CASE_STATEMENT_DIFF
        );
        let disclosed = book
            .disclose_case(
                disclose,
                1,
                disclosure.oid(),
                &comparisons,
                day(2026, 2, 15),
                b"complete-disclosure",
            )
            .unwrap()
            .unwrap();
        assert_eq!(disclosed.case.state, CaseState::Disclosed);
        assert_eq!(
            book.case_statement_diff_requests(PRINCIPAL, &read, 1, None)
                .unwrap()
                .unwrap(),
            questions
        );
    }
}

#[test]
fn an_issued_stock_layout_without_an_opening_version_cannot_silently_drop_that_comparison() {
    let (mut book, _) = posted_custom_case(0xe3, false, day(2025, 12, 1), false, false);
    let read = Capability::embedded(PRINCIPAL, &["read"]).unwrap();
    let head = book.head().unwrap();
    let refusal = book
        .case_statement_diff_requests(PRINCIPAL, &read, 1, None)
        .unwrap()
        .unwrap_err();
    assert!(
        refusal
            .message
            .contains("no approved version at opening period"),
        "{refusal:?}"
    );
    assert_eq!(book.head().unwrap(), head);
}

#[test]
fn an_unmapped_zero_balance_account_cannot_disappear_from_the_original_custom_case_layout() {
    let (mut book, source) = posted_custom_case(0xe4, false, day(2025, 1, 1), true, false);
    let read = Capability::embedded(PRINCIPAL, &["read"]).unwrap();
    let questions = book
        .case_statement_diff_requests(PRINCIPAL, &read, 1, None)
        .unwrap()
        .unwrap();
    let question = questions
        .iter()
        .find(|question| !question.opening && question.request.selection == source.selection)
        .unwrap();
    let head = book.head().unwrap();
    assert!(
        book.case_statement_diff(PRINCIPAL, &read, question)
            .unwrap()
            .is_err()
    );
    assert!(
        book.certify_case_statement_diff(
            PRINCIPAL,
            &Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap(),
            question
        )
        .unwrap()
        .is_err()
    );
    assert_eq!(book.head().unwrap(), head);
}

#[test]
fn instant_issued_statements_keep_their_original_frontier_in_sequence_case_comparisons() {
    let (mut book, source) = posted_custom_case(0xe5, false, day(2025, 1, 1), false, true);
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap();
    let questions = book
        .case_statement_diff_requests(PRINCIPAL, &capability, 1, None)
        .unwrap()
        .unwrap();
    let original = questions
        .iter()
        .find(|question| !question.opening && question.request.selection == source.selection)
        .unwrap();
    assert_eq!(original.request.before, source.known_at);
    assert!(
        matches!(&original.basis, fa::CaseStatementBasis::FirstIssuance { certificate, .. }
        if certificate == &source.digest)
    );
    let comparison = book
        .certify_case_statement_diff(PRINCIPAL, &capability, original)
        .unwrap()
        .unwrap();
    let (before, after) = comparison.certificate.sources();
    assert_eq!(before.selection, source.selection);
    assert_eq!(before.known_at, source.known_at);
    assert!(before.time_selection.is_none() && after.time_selection.is_none());
    assert_ne!(
        before.digest, source.digest,
        "comparison sources keep the sequence-only contract"
    );
    assert!(
        comparison
            .report
            .lines()
            .iter()
            .any(|line| line.code == "assets" && line.delta == [51, 0])
    );
    assert_eq!(
        book.reported_statement(&capability, &source.digest, "FY2025-P12")
            .unwrap()
            .unwrap(),
        source
    );
}
