use super::*;

use crate::{
    CustomStatementDefinition, CustomStatementSelection, CustomStatementTraceRequest,
    PresentationRoundingSpec, StatementDefinition,
};
use fa_money::RoundingLaw;

pub(super) fn activate(h: &mut Harness, version: u32) -> CustomStatementSelection {
    let mut definition = CustomStatementDefinition::from_builtin(
        &StatementDefinition::embedded("income-statement").unwrap(),
    );
    definition.name = "trace-company-income".into();
    definition.version = version;
    let cx = h.cx();
    let authority = cap(&["rule_change"]);
    let key = format!("trace-company-layout-{version}");
    let plan = h
        .book
        .plan_statement_definition(
            &cx,
            &authority,
            definition,
            day(if version == 1 {
                "2025-01-01"
            } else {
                "2026-03-01"
            }),
            key.as_bytes(),
        )
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

fn source(h: &mut Harness, selection: &CustomStatementSelection) -> crate::CertifiedReport {
    let cx = h.cx();
    let authority = cap(&["read", "produce"]);
    if selection.functional {
        h.runtime
            .block_on(h.book.certify_functional_custom_statement(
                &cx,
                &authority,
                selection.clone(),
                None,
            ))
            .unwrap()
            .unwrap()
    } else {
        h.book
            .certify_custom_statement(&cx, &authority, selection.clone(), None)
            .unwrap()
            .unwrap()
    }
}

pub(super) fn direct(
    h: &mut Harness,
    request: &CustomStatementTraceRequest,
) -> CertifiedStatementTrace {
    let cx = h.cx();
    let authority = cap(&["read", "produce"]);
    if request.selection.functional {
        h.runtime
            .block_on(
                h.book
                    .certify_functional_custom_statement_trace(&cx, PRINCIPAL, &authority, request),
            )
            .unwrap()
            .unwrap()
    } else {
        h.book
            .certify_custom_statement_trace(&cx, PRINCIPAL, &authority, request)
            .unwrap()
            .unwrap()
    }
}

#[test]
fn custom_traces_keep_exact_cancelling_changes_original_layout_and_cold_sources() {
    for functional in [false, true] {
        let mut h = Harness::new();
        h.post(
            "original",
            "2026-03-10",
            h.usd,
            ("cash", "sales"),
            100,
            false,
        );
        let mut selection = activate(&mut h, 1);
        selection.functional = functional;
        let first = source(&mut h, &selection);
        let before = first.certificate.known_at;
        h.post("plus", "2026-03-15", h.usd, ("cash", "sales"), 1, false);
        let middle = source(&mut h, &selection);
        h.post("minus", "2026-03-15", h.usd, ("sales", "cash"), 1, false);
        // A new layout with the same name is itself part of the traced
        // history. All intermediate sources must retain the old activation.
        activate(&mut h, 2);
        let last = source(&mut h, &selection);
        let after = last.certificate.known_at;
        let cx = h.cx();
        let authority = cap(&["read", "produce"]);
        let comparison = h
            .book
            .compare_statement_certificates(
                &cx,
                PRINCIPAL,
                &authority,
                &first.certificate,
                &last.certificate,
            )
            .unwrap()
            .unwrap();
        let request = CustomStatementTraceRequest {
            selection: selection.clone(),
            before,
            after: Some(after),
            max_publications: (after.0 - before.0) as usize,
        };
        let direct = direct(&mut h, &request);
        assert!(direct.report.is_custom());
        assert_eq!(direct.report.is_functional(), functional);
        assert!(direct.report.summary().is_unchanged());
        assert!(direct.report.had_changes());
        for (step, delta) in direct.report.publications().iter().take(2).zip([1, -1]) {
            assert_eq!(
                step.changes
                    .iter()
                    .find(|row| row.code == "net_income")
                    .unwrap()
                    .delta,
                [delta, 0],
            );
        }
        assert!(
            direct
                .report
                .publications()
                .iter()
                .skip(2)
                .all(StatementPublication::is_unchanged)
        );
        let rendered = |source: &crate::CertifiedReport| {
            let ReportOutput::CustomStatement(report) = &source.report else {
                panic!("custom report")
            };
            report
                .presented
                .as_ref()
                .unwrap()
                .lines
                .iter()
                .find(|row| row.code == "net_income")
                .unwrap()
                .presented_amounts
                .clone()
        };
        assert_eq!(rendered(&first), [10, 0]);
        assert_eq!(rendered(&first), rendered(&middle));
        assert_eq!(rendered(&first), rendered(&last));
        for (offset, source) in direct.certificate.sources().iter().enumerate() {
            assert_eq!(source.known_at.0, before.0 + offset as u64);
            assert_eq!(source.selection, first.certificate.selection);
        }
        assert_eq!(
            direct.certificate.sources().len(),
            request.max_publications + 1
        );
        assert_eq!(
            direct.certificate.report_selection().unwrap(),
            first.certificate.selection
        );
        assert!(direct.certificate.request().is_err());
        let ordinary = if functional {
            h.runtime
                .block_on(h.book.functional_custom_statement_trace(
                    &cx,
                    PRINCIPAL,
                    &cap(&["read"]),
                    &request,
                ))
                .unwrap()
                .unwrap()
        } else {
            h.book
                .custom_statement_trace(&cx, PRINCIPAL, &cap(&["read"]), &request)
                .unwrap()
                .unwrap()
        };
        assert_eq!(ordinary, direct.report);

        h.post("later", "2026-03-20", h.usd, ("cash", "sales"), 900, false);
        let head = h.head();
        let traced = if functional {
            h.runtime
                .block_on(h.book.certify_functional_statement_trace_from_diff(
                    &cx,
                    PRINCIPAL,
                    &authority,
                    &comparison.certificate,
                    request.max_publications,
                ))
                .unwrap()
                .unwrap()
        } else {
            h.book
                .certify_statement_trace_from_diff(
                    &cx,
                    PRINCIPAL,
                    &authority,
                    &comparison.certificate,
                    request.max_publications,
                )
                .unwrap()
                .unwrap()
        };
        assert_eq!(traced.report, direct.report);
        assert_eq!(
            traced.certificate.sources().first().unwrap(),
            &first.certificate
        );
        assert_eq!(
            traced.certificate.sources().last().unwrap(),
            &last.certificate
        );
        let bytes = traced.certificate.canonical_bytes().unwrap();
        let decoded = StatementTraceCertificate::decode(&bytes).unwrap();
        assert_eq!(decoded, traced.certificate);
        assert_eq!(
            decoded.format(),
            if functional {
                FUNCTIONAL_CUSTOM_CERTIFICATE_FORMAT
            } else {
                CUSTOM_CERTIFICATE_FORMAT
            }
        );
        let mut h = h.reopen();
        let cx = h.cx();
        let replayed = h
            .runtime
            .block_on(h.book.replay_report_artifact_for_with_history(
                &cx,
                PRINCIPAL,
                &cap(&["read"]),
                &bytes,
                Some(decoded.digest()),
                crate::ReportArtifactExpectation::AsSupplied,
            ))
            .unwrap()
            .unwrap();
        assert_eq!(replayed.output, direct.report.canonical_bytes().unwrap());
        let jsonl = h
            .book
            .statement_trace_jsonl(&cx, PRINCIPAL, &authority, &decoded)
            .unwrap()
            .unwrap();
        assert!(jsonl.contains(if functional {
            "\"format\":\"fa:functional-custom-statement-trace-jsonl:v1\""
        } else {
            "\"format\":\"fa:custom-statement-trace-jsonl:v1\""
        }));
        assert!(jsonl.contains("\"amount_basis\":\"exact-underlying-statement\""));
        assert_eq!(h.head(), head);
    }
}

#[test]
fn custom_trace_replay_rejects_resealed_hidden_changes_and_selector_drift() {
    let mut h = Harness::new();
    let selection = activate(&mut h, 1);
    let before = h.head();
    h.post("change", "2026-03-15", h.usd, ("cash", "sales"), 1, false);
    h.post("cancel", "2026-03-15", h.usd, ("sales", "cash"), 1, false);
    let request = CustomStatementTraceRequest {
        selection: selection.clone(),
        before,
        after: None,
        max_publications: 2,
    };
    let good = direct(&mut h, &request);
    let mut false_report = good.report.clone();
    false_report.publications[0].changes.clear();
    let forged = reseal(&good.certificate, false_report.canonical_bytes().unwrap());
    assert_false_trace(&h, &forged);

    let mut alternate = selection;
    alternate
        .presentation
        .as_mut()
        .unwrap()
        .scale_reduction_digits = 2;
    let cx = h.cx();
    let alternate = h
        .book
        .certify_custom_statement(
            &cx,
            &cap(&["read", "produce"]),
            alternate,
            Some(CommitSeq(before.0 + 1)),
        )
        .unwrap()
        .unwrap();
    let mut changed = good.certificate.sources().to_vec();
    changed[1] = alternate.certificate;
    assert!(
        StatementTraceCertificate::seal(
            changed,
            PRINCIPAL,
            *good.certificate.capability_commitment(),
            good.certificate.output().to_vec(),
        )
        .is_err()
    );
    let mut skipped = good.certificate.sources().to_vec();
    skipped.remove(1);
    assert!(
        StatementTraceCertificate::seal(
            skipped,
            PRINCIPAL,
            *good.certificate.capability_commitment(),
            good.certificate.output().to_vec(),
        )
        .is_err()
    );
}

#[test]
fn custom_trace_admission_preserves_authority_basis_activation_and_work_bounds() {
    let mut h = Harness::new();
    let selection = activate(&mut h, 1);
    let before = h.head();
    h.post("change", "2026-03-15", h.usd, ("cash", "sales"), 1, false);
    let request = CustomStatementTraceRequest {
        selection,
        before,
        after: None,
        max_publications: 1,
    };
    let cx = h.cx();
    assert!(
        h.book
            .certify_custom_statement_trace(&cx, PRINCIPAL, &cap(&["read"]), &request)
            .unwrap()
            .is_err()
    );
    assert!(
        h.book
            .custom_statement_trace(&cx, VId(999), &cap(&["read"]), &request)
            .unwrap()
            .is_err()
    );
    let mut wrong_basis = request.clone();
    wrong_basis.selection.functional = true;
    assert!(
        h.book
            .custom_statement_trace(&cx, PRINCIPAL, &cap(&["read"]), &wrong_basis)
            .unwrap()
            .is_err()
    );
    assert!(
        h.runtime
            .block_on(h.book.functional_custom_statement_trace(
                &cx,
                PRINCIPAL,
                &cap(&["read"]),
                &request,
            ))
            .unwrap()
            .is_err()
    );
    let mut invalid = request.clone();
    invalid.before = CommitSeq(request.selection.activated_at.0 - 1);
    invalid.max_publications = 256;
    assert!(
        h.book
            .custom_statement_trace(&cx, PRINCIPAL, &cap(&["read"]), &invalid)
            .unwrap()
            .is_err()
    );
    invalid = request.clone();
    invalid.max_publications = 0;
    assert!(
        h.book
            .custom_statement_trace(&cx, PRINCIPAL, &cap(&["read"]), &invalid)
            .unwrap()
            .is_err()
    );
    let mut empty = request;
    empty.after = Some(before);
    let empty = direct(&mut h, &empty);
    assert!(empty.report.publications().is_empty());
    assert_eq!(empty.certificate.sources().len(), 1);
}
