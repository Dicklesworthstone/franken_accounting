//! Approved company layouts over real native entries and retained FX sources.

use super::*;

use fa_journal::fx::{FxLawId, FxRateDocument, FxRatePurpose, RATE_DOCUMENT_KIND};
use fa_money::rate::{ArithmeticBudget, BudgetLimits};
use fa_money::{Amount, RoundingLaw, Side, UnitId};

use crate::{CustomStatementReport, CustomStatementSelection, ReportOutput};

fn date(month: u8, day: u8) -> DateDay {
    DateDay::from_ymd(2026, month, day).unwrap()
}

fn retain_rate(
    harness: &mut Harness,
    as_of: DateDay,
    numerator: u128,
    denominator: u128,
    source: &str,
) -> FxRateDocument {
    let units = &harness.book.context.units;
    let rate = FxRateDocument {
        base_unit: units.lookup("USD").unwrap(),
        quote_unit: units.lookup("EUR").unwrap(),
        rate_num: numerator,
        rate_den: denominator,
        rounding: RoundingLaw::HalfEven,
        as_of,
        retrieved_at_ns: 1,
        purpose: FxRatePurpose::SpotClose,
        source: source.into(),
    };
    let document = fa_journal::Document {
        book_id: harness.book.context.book_id,
        kind: RATE_DOCUMENT_KIND,
        mime: "application/vnd.fa.fx-rate".into(),
        grade: 3,
        retrieved_by: PREPARER,
        bytes: rate.canonical_bytes().unwrap(),
    };
    let cx = harness.cx();
    harness
        .runtime
        .block_on(harness.book.add_document(&cx, &document))
        .unwrap()
        .unwrap();
    rate
}

enum Activity {
    Revenue,
    Expense,
}

fn post_amount(
    harness: &mut Harness,
    key: &[u8],
    effective: DateDay,
    unit: &str,
    amount: i128,
    activity: Activity,
    rate: Option<&FxRateDocument>,
) -> fa_journal::Posted {
    let cx = harness.cx();
    let source = fa_journal::Document {
        book_id: harness.book.context.book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PREPARER,
        bytes: b"Actual sales and expense source for functional company statements".to_vec(),
    };
    harness
        .runtime
        .block_on(harness.book.add_document(&cx, &source))
        .unwrap()
        .unwrap();
    let unit = harness.book.context.units.lookup(unit).unwrap();
    let (debit, credit) = match activity {
        Activity::Revenue => ("1000", "4000"),
        Activity::Expense => ("6000", "1000"),
    };
    let legs = vec![
        fa_model::LegPayload::simple(
            Side::Debit,
            fa_model::account_vid(harness.book.context.book_id, debit),
            Amount::new(unit, amount),
        ),
        fa_model::LegPayload::simple(
            Side::Credit,
            fa_model::account_vid(harness.book.context.book_id, credit),
            Amount::new(unit, amount),
        ),
    ];
    let mut proposal = EntryPayload {
        schema_minor: 0,
        book_id: harness.book.context.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: effective,
        document_date: None,
        description: harness
            .book
            .seal_text(&cx, "Retained native and functional accounting amounts")
            .unwrap(),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: key.to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([31; 32]),
            intent_kind: 1,
        },
        principal_ref: PREPARER,
        session_ref: None,
        evidence: vec![source.evidence_ref(1)],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    if let Some(rate) = rate {
        let spec = fa_journal::genesis::read_book_spec(&harness.book.db)
            .unwrap()
            .unwrap();
        let arithmetic = harness.root.restrict::<asupersync::cx::cap::None>();
        let mut budget =
            ArithmeticBudget::new(&arithmetic, BudgetLimits::uniform(1_000_000, 0), 4096);
        proposal = cx
            .merge_eval()
            .with_restriction(|| {
                fa_journal::fx::value_proposal(
                    &mut budget,
                    proposal,
                    &spec,
                    &harness.book.context.units,
                    FxLawId::SpotClose,
                    std::slice::from_ref(rate),
                )
            })
            .unwrap();
    }
    harness
        .runtime
        .block_on(harness.book.post(
            &cx,
            fa_journal::PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(PREPARER, &["post"]),
            },
        ))
        .unwrap()
        .unwrap()
}

fn activate_layout(
    harness: &mut Harness,
    layout: CustomStatementDefinition,
    effective: DateDay,
    key: &[u8],
) -> ActivatedStatementDefinition {
    let plan = harness.plan(layout, effective, key);
    let approvals = harness.approve(&plan);
    harness.activate(plan, approvals).unwrap().unwrap()
}

fn selection(active: &ActivatedStatementDefinition) -> CustomStatementSelection {
    CustomStatementSelection {
        definition: active.definition.clone(),
        activation: active.activation,
        activated_at: active.recorded_at,
        functional: true,
        periods: vec!["FY2026-P02".into()],
        comparative: vec!["FY2026-P01".into()],
        presentation: None,
    }
}

fn fixture() -> (Harness, ActivatedStatementDefinition, FxRateDocument) {
    let mut harness = Harness::new();
    let cx = harness.cx();
    harness
        .runtime
        .block_on(harness.book.transition_period(
            &cx,
            "FY2026-P02",
            fa_time::PeriodTransition::Open,
            PREPARER,
            1,
            b"open-february",
            &cap(PREPARER, &["close"]),
        ))
        .unwrap()
        .unwrap();
    let january = retain_rate(&mut harness, date(1, 15), 5, 4, "January reviewed source");
    let february = retain_rate(&mut harness, date(2, 15), 3, 2, "February reviewed source");
    for (key, month, currency, amount, activity, rate) in [
        ("jan-usd-sales", 1, "USD", 1001, Activity::Revenue, None),
        (
            "jan-eur-sales",
            1,
            "EUR",
            2002,
            Activity::Revenue,
            Some(&january),
        ),
        (
            "jan-eur-expense",
            1,
            "EUR",
            201,
            Activity::Expense,
            Some(&january),
        ),
        ("feb-usd-sales", 2, "USD", 296, Activity::Revenue, None),
        (
            "feb-eur-sales",
            2,
            "EUR",
            805,
            Activity::Revenue,
            Some(&february),
        ),
        ("feb-usd-expense", 2, "USD", 104, Activity::Expense, None),
        (
            "feb-eur-expense",
            2,
            "EUR",
            101,
            Activity::Expense,
            Some(&february),
        ),
    ] {
        post_amount(
            &mut harness,
            key.as_bytes(),
            date(month, 15),
            currency,
            amount,
            activity,
            rate,
        );
    }
    let active = activate_layout(
        &mut harness,
        definition(1),
        day(1),
        b"functional-company-v1",
    );
    (harness, active, january)
}

fn certify(harness: &mut Harness, selection: CustomStatementSelection) -> crate::CertifiedReport {
    let cx = harness.cx();
    harness
        .runtime
        .block_on(harness.book.certify_functional_custom_statement(
            &cx,
            &cap(PREPARER, &["read", "produce"]),
            selection,
            None,
        ))
        .unwrap()
        .unwrap()
}

fn output(report: &ReportOutput) -> &CustomStatementReport {
    let ReportOutput::CustomStatement(report) = report else {
        panic!("expected an approved custom statement");
    };
    report
}

fn amounts<'a>(statement: &'a fa_statements::Statement, code: &str, unit: UnitId) -> &'a [i128] {
    &statement
        .lines
        .iter()
        .find(|line| line.code == code && line.unit_id == unit.0)
        .unwrap_or_else(|| panic!("missing {code} in unit {}", unit.0))
        .amounts
}

#[test]
fn functional_company_columns_use_retained_values_and_explicit_rounding_residuals() {
    let (mut harness, active, _) = fixture();
    let usd = harness.book.context.units.lookup("USD").unwrap();
    let eur = harness.book.context.units.lookup("EUR").unwrap();
    let mut selected = selection(&active);
    selected.presentation = Some(fa_statements::custom::PresentationRoundingSpec {
        rounding_law: RoundingLaw::HalfEven,
        scale_reduction_digits: 1,
        residual_line_code: "rounding".into(),
        residual_line_label: "Presentation rounding".into(),
    });
    let at = harness.head();
    let certified = certify(&mut harness, selected.clone());
    assert_eq!(
        harness.head(),
        at,
        "report certification publishes no accounting entry"
    );
    let report = output(&certified.report);
    assert_eq!(report.functional_unit, Some(usd));
    assert!(
        report
            .statement
            .lines
            .iter()
            .all(|line| line.unit_id == usd.0)
    );
    // Expectations are hand-calculated from the separate transaction rates,
    // including half-even ties; the most recent rate is not a restatement.
    assert_eq!(amounts(&report.statement, "revenue", usd), [1504, 3503]);
    assert_eq!(amounts(&report.statement, "expense", usd), [256, 251]);
    assert_eq!(amounts(&report.statement, "net_income", usd), [1248, 3252]);
    let presented = report.presented.as_ref().unwrap();
    assert_eq!(presented.divisor, 10);
    let rounded = |code: &str| {
        presented
            .lines
            .iter()
            .find(|line| line.code == code)
            .unwrap()
    };
    assert_eq!(rounded("revenue").presented_amounts, [150, 350]);
    assert_eq!(rounded("expense").presented_amounts, [26, 25]);
    assert_eq!(rounded("net_income").presented_amounts, [125, 325]);
    let residual = rounded("net_income_rounding");
    assert!(residual.is_residual_line);
    assert_eq!(residual.presented_amounts, [1, 0]);
    assert_eq!(residual.rounding_errors, [10, 0]);

    let mut native = selected;
    native.functional = false;
    native.presentation = None;
    let native = harness
        .book
        .custom_statement(&harness.cx(), &cap(PREPARER, &["read"]), native, Some(at))
        .unwrap()
        .unwrap();
    assert_eq!(native.functional_unit, None);
    assert_eq!(amounts(&native.statement, "net_income", usd), [192, 1001]);
    assert_eq!(amounts(&native.statement, "net_income", eur), [704, 1801]);
    assert_ne!(
        native.canonical_bytes().unwrap(),
        report.canonical_bytes().unwrap()
    );

    let encoded = certified.certificate.canonical_bytes().unwrap();
    assert!(encoded.starts_with(b"fa:report-certificate:v12"));
    assert_eq!(certified.certificate.inputs.len(), 13);
    assert!(
        certified
            .certificate
            .inputs
            .iter()
            .any(|input| input.statement.contains("WHERE n.code = 'Rate'"))
    );
    let decoded = crate::ReportCertificate::decode(&encoded).unwrap();
    assert_eq!(decoded.canonical_bytes().unwrap(), encoded);
    assert_eq!(
        harness
            .book
            .replay_report(&harness.cx(), &decoded)
            .unwrap()
            .unwrap(),
        certified.report
    );

    let mut balance = CustomStatementDefinition::from_builtin(
        &StatementDefinition::embedded("balance-sheet").unwrap(),
    );
    balance.name = "company-balance".into();
    let active_balance = activate_layout(&mut harness, balance, day(1), b"functional-balance-v1");
    let stock = certify(&mut harness, selection(&active_balance));
    let stock = output(&stock.report);
    assert_eq!(amounts(&stock.statement, "assets", usd), [4500, 3252]);
    assert_eq!(amounts(&stock.statement, "total_equity", usd), [4500, 3252]);
    assert_eq!(amounts(&stock.statement, "balance_check", usd), [0, 0]);
}

#[test]
fn retained_functional_company_report_does_not_reselect_new_rates_or_layouts() {
    let (mut harness, active, _) = fixture();
    let selected = selection(&active);
    let certified = certify(&mut harness, selected.clone());
    let encoded = certified.certificate.canonical_bytes().unwrap();
    let cx = harness.cx();
    let retained = harness
        .runtime
        .block_on(harness.book.retain_report_artifact(
            &cx,
            PREPARER,
            &cap(PREPARER, &["read", "produce"]),
            &encoded,
            Some(&certified.certificate.digest),
        ))
        .unwrap()
        .unwrap();
    let stored = harness
        .runtime
        .block_on(harness.book.read_certificate(&cx, &retained.digest))
        .unwrap()
        .unwrap();
    assert_eq!(stored, certified.certificate);
    retain_rate(&mut harness, date(2, 28), 9, 1, "Unused later market rate");
    assert_eq!(
        harness.book.replay_report(&cx, &stored).unwrap().unwrap(),
        certified.report
    );
    assert!(matches!(
        harness
            .book
            .certificate_status(&cx, &stored)
            .unwrap()
            .unwrap(),
        crate::CertificateStatus::Current { .. }
    ));

    let posted = post_amount(
        &mut harness,
        b"later-functional-sales",
        date(2, 20),
        "USD",
        200,
        Activity::Revenue,
        None,
    );
    let mut next = definition(2);
    next.title = "New management layout".into();
    next.lines[0].label = "Sales under the newer layout".into();
    let active_next = activate_layout(&mut harness, next, date(2, 1), b"functional-company-v2");
    let resolved = harness
        .book
        .active_statement_definition(
            &cx,
            &cap(PREPARER, &["read"]),
            "company-income",
            date(2, 28),
            harness.head(),
        )
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(resolved.activation, active_next.activation);
    let current = harness
        .runtime
        .block_on(harness.book.functional_custom_statement(
            &cx,
            &cap(PREPARER, &["read"]),
            selected,
            None,
        ))
        .unwrap()
        .unwrap();
    let usd = harness.book.context.units.lookup("USD").unwrap();
    assert_eq!(current.activation, active.activation);
    assert_eq!(amounts(&current.statement, "net_income", usd), [1448, 3252]);
    assert_eq!(
        harness.book.replay_report(&cx, &stored).unwrap().unwrap(),
        certified.report
    );
    assert_eq!(
        harness
            .book
            .certificate_status(&cx, &stored)
            .unwrap()
            .unwrap(),
        crate::CertificateStatus::SupersededBy {
            checked_at: harness.head(),
            later_entries: vec![posted.entry_ref().vid],
            cases: Vec::new(),
        }
    );
}

#[test]
fn functional_company_report_requires_every_foreign_contribution_to_be_valued() {
    let mut harness = Harness::new();
    post_amount(
        &mut harness,
        b"unvalued-foreign-sales",
        day(15),
        "EUR",
        1000,
        Activity::Revenue,
        None,
    );
    let active = activate_layout(&mut harness, definition(1), day(1), b"unvalued-layout");
    let mut selected = selection(&active);
    selected.periods = vec!["FY2026-P01".into()];
    selected.comparative.clear();
    let cx = harness.cx();
    let at = harness.head();
    let read = harness
        .runtime
        .block_on(harness.book.functional_custom_statement(
            &cx,
            &cap(PREPARER, &["read"]),
            selected.clone(),
            None,
        ));
    assert!(
        matches!(read, Err(BookError::Registers(fa_registers::RegisterError::ProjectionDrift(message)))
        if message.contains("foreign unit") && message.contains("without a functional base_amount"))
    );
    let certified = harness
        .runtime
        .block_on(harness.book.certify_functional_custom_statement(
            &cx,
            &cap(PREPARER, &["read", "produce"]),
            selected.clone(),
            None,
        ));
    assert!(
        matches!(certified, Err(BookError::Registers(fa_registers::RegisterError::ProjectionDrift(message)))
        if message.contains("without a functional base_amount"))
    );
    assert_eq!(
        harness.head(),
        at,
        "refused reports never invent valuations or post entries"
    );
    selected.functional = false;
    let native = harness
        .book
        .custom_statement(&cx, &cap(PREPARER, &["read"]), selected, None)
        .unwrap()
        .unwrap();
    assert_eq!(
        amounts(
            &native.statement,
            "revenue",
            harness.book.context.units.lookup("EUR").unwrap()
        ),
        [1000]
    );
}

#[test]
fn functional_company_certificates_reject_missing_rates_changed_output_and_rewritten_sources() {
    let (mut harness, active, rate) = fixture();
    let selected = selection(&active);
    let certified = certify(&mut harness, selected.clone());
    let rate_input = certified
        .certificate
        .inputs
        .iter()
        .position(|input| input.statement.contains("WHERE n.code = 'Rate'"))
        .unwrap();
    let mut incomplete = certified.certificate.clone();
    incomplete.inputs.remove(rate_input);
    let incomplete = incomplete.resealed_under(incomplete.registry_digest);
    let refusal = harness
        .book
        .replay_report(&harness.cx(), &incomplete)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
    assert!(refusal.message.contains("native input closure"));

    let mut altered_report = output(&certified.report).clone();
    altered_report
        .statement
        .lines
        .iter_mut()
        .find(|line| line.code == "net_income")
        .unwrap()
        .amounts[0] += 1;
    let mut altered = certified.certificate.clone();
    altered.output = altered_report.canonical_bytes().unwrap();
    let mut output_digest = fgdb_crypto::Hasher::new();
    output_digest.update(b"fa:report-output:v1");
    output_digest.update(&altered.output);
    altered.output_digest = output_digest.finalize().0;
    let altered = altered.resealed_under(altered.registry_digest);
    let altered = crate::ReportCertificate::decode(&altered.canonical_bytes().unwrap()).unwrap();
    let refusal = harness
        .book
        .replay_report(&harness.cx(), &altered)
        .unwrap()
        .unwrap_err();
    assert!(
        refusal
            .message
            .contains("differs from its certified output"),
        "{refusal:?}"
    );

    let rate_vid =
        fa_journal::evidence::document_vid(&rate.oid(harness.book.context.book_id).unwrap());
    let mut damage = WriteBatch::new(relation::IN_BOOK);
    damage.set_vertex_property(
        rate_vid,
        property::CODE,
        Some(fa_journal::rows::scalar_text("rate kind", "Invoice").unwrap()),
    );
    let cx = harness.cx();
    harness
        .runtime
        .block_on(harness.book.db.write(&cx.commit(), damage))
        .unwrap();
    let refused = harness
        .book
        .replay_report(&cx, &certified.certificate)
        .unwrap()
        .unwrap_err();
    assert!(
        refused.message.contains("Rate document") && refused.message.contains("rewritten"),
        "{refused:?}"
    );
    let refused = harness
        .runtime
        .block_on(harness.book.functional_custom_statement(
            &cx,
            &cap(PREPARER, &["read"]),
            selected.clone(),
            None,
        ))
        .unwrap()
        .unwrap_err();
    assert!(refused.message.contains("Rate document"), "{refused:?}");
    let denied = harness
        .runtime
        .block_on(harness.book.certify_functional_custom_statement(
            &cx,
            &cap(PREPARER, &["read"]),
            selected,
            None,
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(
        denied.exit,
        fa_journal::exit::SAFETY,
        "Produce authority is checked before inspecting the corrupted source"
    );
}
