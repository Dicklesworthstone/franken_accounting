//! Real approved layouts exported through the facade and independently folded
//! by the dependency-free receiver, including retained presentation and FX laws.

use super::*;

use fa::{
    AccountSetExpr, CustomLineSource, CustomStatementDefinition, CustomStatementSelection, FxLawId,
    FxRateDocument, FxRatePurpose, FxRateTerms,
};
use fa_money::RoundingLaw;

#[path = "custom_statement_diff_bundle.rs"]
mod diff;
#[path = "custom_statement_trace_bundle.rs"]
mod trace;

fn layout(version: u32) -> CustomStatementDefinition {
    let mut definition = CustomStatementDefinition::from_builtin(
        &StatementDefinition::embedded("income-statement").unwrap(),
    );
    definition.name = "company-income".into();
    definition.title = format!("Company income version {version}");
    definition.version = version;
    for line in &mut definition.lines {
        if let CustomLineSource::AccountSet { expr, .. } = &mut line.source {
            *expr = match line.code.as_str() {
                "revenue" => AccountSetExpr::AccountCodes(vec!["4000".into()]),
                "expense" => AccountSetExpr::Union(vec![
                    AccountSetExpr::AccountCodePrefixes(vec!["60".into()]),
                    AccountSetExpr::AccountCodes(vec!["6100".into()]),
                ]),
                other => panic!("unexpected income mapping {other}"),
            };
        }
    }
    definition
}

fn activate(book: &mut Book, version: u32, effective: DateDay) -> CustomStatementSelection {
    let capability = Capability::embedded(PRINCIPAL, &["rule_change"]).unwrap();
    let key = format!("portable-company-layout-{version}");
    let plan = book
        .plan_statement_definition(&capability, layout(version), effective, key.as_bytes())
        .unwrap()
        .unwrap();
    let proposal_digest = plan.proposal_digest().unwrap();
    let approvals = [VId(2), VId(3)]
        .into_iter()
        .map(|principal| {
            book.approve(
                Capability::embedded(principal, &["approve"]).unwrap(),
                proposal_digest,
            )
            .unwrap()
            .unwrap()
            .approval()
        })
        .collect();
    let activated = book
        .activate_statement_definition(&capability, plan, approvals)
        .unwrap()
        .unwrap();
    CustomStatementSelection {
        definition: activated.definition,
        activation: activated.activation,
        activated_at: activated.recorded_at,
        functional: false,
        periods: vec![FEBRUARY.into()],
        comparative: vec![JANUARY.into()],
        presentation: Some(fa::PresentationRoundingSpec {
            rounding_law: RoundingLaw::HalfEven,
            scale_reduction_digits: 1,
            residual_line_code: "rounding".into(),
            residual_line_label: "Presentation rounding".into(),
        }),
    }
}

fn verify(
    book: &Book,
    produced: &fa::ProducedBundle,
    certificate: &ReportCertificate,
    major: u16,
) -> fa_verify::report::VerifiedReport {
    let mut wire = fa_model::Reader::new(&produced.bundle.bytes);
    assert_eq!(wire.bytes(64, "format").unwrap(), b"fa:report-bundle:v1");
    assert_eq!(wire.u16("major").unwrap(), major);
    assert_eq!(wire.u16("minor").unwrap(), 0);
    assert_eq!(
        wire.bytes(64 * 1024 * 1024, "source").unwrap(),
        certificate.canonical_bytes().unwrap(),
        "export preserves every original native source attestation"
    );
    let key = book.checkpoint_public_key();
    let anchor = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    let verified = fa_verify::report::verify_report_expected(
        &produced.bundle.bytes,
        &[key],
        Some(&anchor.checkpoint),
        Some(&produced.receipt),
        Some(&certificate.digest),
    )
    .expect("the real producer's complete closure must reproduce the custom report offline");
    assert_eq!(verified.output, certificate.output);
    assert_eq!(verified.certificate_digest, certificate.digest);
    assert_eq!(verified.known_at, certificate.known_at.0);
    assert_eq!(verified.scope, "recomputation");
    assert_eq!(verified.unit_universe_source, "authenticated-registry");
    let custom = verified.custom_statement.as_ref().unwrap();
    assert!(!custom.activation.approval_admission_verified);
    assert!(!custom.activation.definition_birth_verified);
    assert_eq!(custom.activation.approval_refs.len(), 2);
    verified
}

#[test]
fn native_custom_bundles_preserve_approved_layout_rounding_and_historical_reopen() {
    let seed = 0xd9;
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fa-custom-statement-proof-{}-{suffix}",
        std::process::id()
    ));
    let mut fixture = Fixture::at(seed, Some(&directory));
    for (key, month, unit, accounts, amount) in [
        ("jan-revenue", 1, fixture.usd, ("1000", "4000"), 1_004),
        ("jan-expense", 1, fixture.usd, ("6000", "1000"), 253),
        ("feb-revenue", 2, fixture.usd, ("1000", "4000"), 2_505),
        ("feb-expense", 2, fixture.usd, ("6000", "1000"), 356),
        ("jpy-revenue", 2, fixture.jpy, ("1000", "4000"), 37),
    ] {
        fixture.transfer(day(2026, month, 15), key.as_bytes(), unit, accounts, amount);
    }
    let selected = activate(&mut fixture.book, 1, day(2026, 1, 1));
    let producer = Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap();
    let certified = fixture
        .book
        .certify_custom_statement(&producer, selected.clone(), None)
        .unwrap()
        .unwrap();
    assert_eq!(certified.certificate.inputs.len(), 12);
    let original = report_bundle::produce(&mut fixture.book, &certified.certificate);
    let verified = verify(&fixture.book, &original, &certified.certificate, 2);
    let custom = verified.custom_statement.unwrap();
    assert_eq!(custom.activation.activation, selected.activation.0);
    assert_eq!(custom.activation.activated_at, selected.activated_at.0);
    assert_eq!(custom.functional_unit, None);
    let line = |code: &str, unit: UnitId| {
        &custom
            .statement
            .lines
            .iter()
            .find(|line| line.code == code && line.unit == unit.0)
            .unwrap()
            .amounts
    };
    assert_eq!(line("net_income", fixture.usd), &[2_149, 751]);
    assert_eq!(line("net_income", fixture.jpy), &[37, 0]);
    let eur = fixture.book.context().units.lookup("EUR").unwrap();
    assert_eq!(line("net_income", eur), &[0, 0]);
    let residual = custom
        .presented
        .as_ref()
        .unwrap()
        .lines
        .iter()
        .find(|line| line.code == "net_income_rounding" && line.unit == fixture.usd.0)
        .unwrap();
    assert!(residual.is_residual_line);
    assert_eq!(residual.presented_amounts, [1, 0]);

    let retained = fixture
        .book
        .retain_certificate(PRINCIPAL, &producer, &certified.certificate)
        .unwrap()
        .unwrap();
    activate(&mut fixture.book, 2, day(2026, 2, 1));
    fixture.transfer(
        day(2026, 1, 20),
        b"backdated-after-original-custom-certificate",
        fixture.usd,
        ("1000", "4000"),
        9_000,
    );
    drop(fixture);
    let mut book = Book::open_dir(
        &directory,
        BookKeys::for_development(seed),
        Entropy::deterministic(u64::from(seed)),
    )
    .unwrap();
    let loaded = book.read_certificate(&retained.digest).unwrap().unwrap();
    assert_eq!(loaded, certified.certificate);
    let repeated = book
        .produce_report_bundle(
            PRINCIPAL,
            &producer,
            Some(original.checkpoint.checkpoint.body.state_oid),
            &loaded,
        )
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(repeated.bundle.bytes, original.bundle.bytes);
    verify(&book, &repeated, &loaded, 2);
    let later = report_bundle::produce(&mut book, &loaded);
    verify(&book, &later, &loaded, 2);
}

#[test]
fn functional_custom_bundles_recompute_original_rates_and_explicit_presentation_residual() {
    let mut fixture = Fixture::new(0xda);
    let eur = fixture.book.context().units.lookup("EUR").unwrap();
    let posting = Capability::embedded(PRINCIPAL, &["read", "post"]).unwrap();
    let mut rates = Vec::new();
    for (month, rate_num, rate_den) in [(1, 5, 4), (2, 3, 2)] {
        let rate = FxRateDocument::new(
            FxRateTerms {
                base_unit: fixture.usd,
                quote_unit: eur,
                rate_num,
                rate_den,
                rounding: RoundingLaw::HalfEven,
            },
            day(2026, month, 15),
            1_767_571_200_000_000_000,
            FxRatePurpose::SpotClose,
            "Original custom statement Rate",
        )
        .unwrap();
        rates.push(
            fixture
                .book
                .upload_fx_rate(&posting, &rate)
                .unwrap()
                .unwrap()
                .oid,
        );
    }
    for (key, month, unit, accounts, amount, rate) in [
        (
            "jan-usd-sales",
            1,
            fixture.usd,
            ("1000", "4000"),
            1_001,
            None,
        ),
        (
            "jan-eur-sales",
            1,
            eur,
            ("1000", "4000"),
            2_002,
            Some(rates[0]),
        ),
        (
            "jan-eur-cost",
            1,
            eur,
            ("6000", "1000"),
            201,
            Some(rates[0]),
        ),
        ("feb-usd-sales", 2, fixture.usd, ("1000", "4000"), 296, None),
        (
            "feb-eur-sales",
            2,
            eur,
            ("1000", "4000"),
            805,
            Some(rates[1]),
        ),
        ("feb-usd-cost", 2, fixture.usd, ("6000", "1000"), 104, None),
        (
            "feb-eur-cost",
            2,
            eur,
            ("6000", "1000"),
            101,
            Some(rates[1]),
        ),
    ] {
        let mut proposal = fixture.proposal(
            day(2026, month, 15),
            key.as_bytes(),
            EntryClass::ORIGINAL,
            fixture.legs(unit, accounts, amount),
        );
        if let Some(rate) = rate {
            proposal = fixture
                .book
                .value_fx_proposal(&posting, proposal, FxLawId::SpotClose, &[rate])
                .unwrap()
                .unwrap();
        }
        fixture.commit(proposal);
    }
    let selected = activate(&mut fixture.book, 1, day(2026, 1, 1));
    let producer = Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap();
    let certified = fixture
        .book
        .certify_functional_custom_statement(&producer, selected, None)
        .unwrap()
        .unwrap();
    assert_eq!(certified.certificate.inputs.len(), 13);
    fixture
        .book
        .retain_certificate(PRINCIPAL, &producer, &certified.certificate)
        .unwrap()
        .unwrap();
    activate(&mut fixture.book, 2, day(2026, 2, 1));
    fixture.transfer(
        day(2026, 1, 20),
        b"later-functional-custom-activity",
        fixture.usd,
        ("1000", "4000"),
        7_000,
    );
    let produced = report_bundle::produce(&mut fixture.book, &certified.certificate);
    let verified = verify(&fixture.book, &produced, &certified.certificate, 3);
    let custom = verified.custom_statement.unwrap();
    assert_eq!(custom.functional_unit, Some(fixture.usd.0));
    assert!(
        custom
            .statement
            .lines
            .iter()
            .all(|line| line.unit == fixture.usd.0)
    );
    for (code, expected) in [
        ("revenue", [1_504, 3_503]),
        ("expense", [256, 251]),
        ("net_income", [1_248, 3_252]),
    ] {
        let line = custom
            .statement
            .lines
            .iter()
            .find(|line| line.code == code)
            .unwrap();
        assert_eq!(
            line.amounts, expected,
            "{code} uses the original transaction rates"
        );
    }
    let residual = custom
        .presented
        .unwrap()
        .lines
        .into_iter()
        .find(|line| line.code == "net_income_rounding")
        .unwrap();
    assert_eq!(residual.presented_amounts, [1, 0]);
    assert_eq!(residual.rounding_errors, [10, 0]);

    let limited = producer.clone().for_accounts(&["1000"]).unwrap();
    let mut corrupt = certified.certificate.clone();
    corrupt.digest[0] ^= 1;
    let refused = fixture
        .book
        .produce_report_bundle(PRINCIPAL, &limited, None, &corrupt)
        .unwrap()
        .unwrap_err();
    assert_eq!((refused.code, refused.exit), ("FA-REF-011", 7));
    assert!(refused.message.contains("`accounts`"));
}
