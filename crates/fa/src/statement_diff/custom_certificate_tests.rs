use super::*;

use crate::{CustomStatementDefinition, CustomStatementSelection, PresentationRoundingSpec};
use fa_money::RoundingLaw;

fn activate(h: &mut Harness, version: u32) -> CustomStatementSelection {
    let mut definition = CustomStatementDefinition::from_builtin(
        &StatementDefinition::embedded("income-statement").unwrap(),
    );
    definition.name = "company-income".into();
    definition.version = version;
    let cx = h.cx();
    let authority = cap(&["rule_change"]);
    let key = format!("comparison-layout-{version}");
    let effective = if version == 1 {
        "2025-01-01"
    } else {
        "2026-03-01"
    };
    let plan = h
        .book
        .plan_statement_definition(&cx, &authority, definition, day(effective), key.as_bytes())
        .unwrap()
        .unwrap();
    let mut approvals = Vec::new();
    for principal in [VId(2), VId(3)] {
        approvals.push(
            h.runtime
                .block_on(fa_journal::policy::record_approval(
                    &mut h.book.db,
                    &cx,
                    &h.book.context,
                    fa_journal::ApprovalRequest {
                        capability: Capability::embedded(principal, &["approve"]).unwrap(),
                        approved_proposal_digest: plan.proposal_digest().unwrap(),
                        role: 0,
                    },
                ))
                .unwrap()
                .unwrap()
                .approval(),
        );
    }
    let activation = h
        .runtime
        .block_on(
            h.book
                .activate_statement_definition(&cx, &authority, plan, approvals),
        )
        .unwrap()
        .unwrap();
    CustomStatementSelection {
        definition: activation.definition,
        activation: activation.activation,
        activated_at: activation.recorded_at,
        functional: false,
        periods: vec!["FY2026-P03".into()],
        comparative: vec!["FY2025-P03".into()],
        presentation: Some(PresentationRoundingSpec {
            rounding_law: RoundingLaw::HalfEven,
            scale_reduction_digits: 1,
            residual_line_code: "rounding".into(),
            residual_line_label: "Presentation rounding".into(),
        }),
    }
}

fn certify(h: &mut Harness, selection: CustomStatementSelection) -> crate::CertifiedReport {
    let cx = h.cx();
    let authority = cap(&["read", "produce"]);
    if selection.functional {
        h.runtime
            .block_on(
                h.book
                    .certify_functional_custom_statement(&cx, &authority, selection, None),
            )
            .unwrap()
            .unwrap()
    } else {
        h.book
            .certify_custom_statement(&cx, &authority, selection, None)
            .unwrap()
            .unwrap()
    }
}

#[test]
fn approved_custom_sources_preserve_rounding_and_exact_deltas_through_later_activation() {
    for functional in [false, true] {
        let mut h = Harness::new();
        h.post(
            "custom-before",
            "2026-03-10",
            h.usd,
            ("cash", "sales"),
            100,
            false,
        );
        let mut selection = activate(&mut h, 1);
        selection.functional = functional;
        let before = certify(&mut h, selection.clone());
        h.post(
            "custom-small-change",
            "2026-03-15",
            h.usd,
            ("cash", "sales"),
            1,
            false,
        );
        let after = certify(&mut h, selection.clone());
        let (ReportOutput::CustomStatement(a), ReportOutput::CustomStatement(b)) =
            (&before.report, &after.report)
        else {
            panic!("custom certificates must retain their complete presentation");
        };
        let presented_revenue = |report: &crate::CustomStatementReport| {
            report
                .presented
                .as_ref()
                .unwrap()
                .lines
                .iter()
                .find(|line| line.code == "revenue" && line.unit_id == h.usd.0)
                .unwrap()
                .presented_amounts
                .clone()
        };
        assert_eq!(presented_revenue(a), [10, 0]);
        assert_eq!(presented_revenue(a), presented_revenue(b));
        let original_head = h.head();
        let comparison = h
            .book
            .compare_statement_certificates(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &before.certificate,
                &after.certificate,
            )
            .unwrap()
            .unwrap();
        assert!(comparison.report.is_custom());
        assert!(
            !comparison.report.is_unchanged(),
            "rounded equality cannot hide exact changes"
        );
        assert_eq!(delta(&comparison.report, "net_income", h.usd), [1, 0]);
        assert!(comparison.certificate.is_custom());
        assert_eq!(
            comparison.certificate.uses_functional_valuations(),
            functional
        );
        assert_eq!(
            comparison.certificate.report_selection().unwrap(),
            ReportSelection::CustomStatement(Box::new(selection.clone()))
        );
        assert!(
            comparison.certificate.request().is_err(),
            "no embedded placeholder selection"
        );
        assert_eq!(
            comparison.certificate.sources(),
            (&before.certificate, &after.certificate)
        );
        let bytes = comparison.certificate.canonical_bytes().unwrap();
        let decoded = StatementDiffCertificate::decode(&bytes).unwrap();
        assert_eq!(decoded, comparison.certificate);
        assert_eq!(
            h.book
                .diff_statement_certificates(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read"]),
                    &before.certificate,
                    &after.certificate,
                )
                .unwrap()
                .unwrap(),
            comparison.report
        );
        assert!(
            h.book
                .compare_statement_certificates(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read"]),
                    &before.certificate,
                    &after.certificate,
                )
                .unwrap()
                .is_err()
        );
        assert_eq!(h.head(), original_head);

        let mut differently_presented = selection;
        differently_presented
            .presentation
            .as_mut()
            .unwrap()
            .scale_reduction_digits = 2;
        let altered = certify(&mut h, differently_presented);
        assert!(
            h.book
                .diff_statement_certificates(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read"]),
                    &before.certificate,
                    &altered.certificate,
                )
                .unwrap()
                .is_err()
        );
        let mut next = activate(&mut h, 2);
        next.functional = functional;
        let replacement = certify(&mut h, next);
        assert!(
            h.book
                .diff_statement_certificates(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read"]),
                    &before.certificate,
                    &replacement.certificate,
                )
                .unwrap()
                .is_err()
        );
        h.post(
            "after-custom-diff",
            "2026-03-20",
            h.usd,
            ("cash", "sales"),
            900,
            false,
        );
        assert_eq!(h.replay(&decoded), comparison.report);

        let mut false_output = decoded.output.clone();
        *false_output.last_mut().unwrap() ^= 1;
        let resealed = StatementDiffCertificate::seal(
            decoded.before.clone(),
            decoded.after.clone(),
            decoded.producer,
            decoded.capability_commitment,
            false_output,
        )
        .unwrap();
        assert!(
            h.book
                .replay_statement_diff(&h.cx(), PRINCIPAL, &cap(&["read"]), &resealed,)
                .unwrap()
                .is_err()
        );
    }
}
