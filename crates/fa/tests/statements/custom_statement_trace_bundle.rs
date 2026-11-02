//! Approved company layouts retain every publication across the actual
//! producer/recipient boundary, even when exact changes cancel at the endpoints.

use super::*;
use fa::{CustomStatementTraceRequest, ReportArtifact, ReportArtifactFamily};

fn source(
    book: &mut Book,
    selected: CustomStatementSelection,
    functional: bool,
) -> fa::CertifiedReport {
    let authority = Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap();
    if functional {
        book.certify_functional_custom_statement(&authority, selected, None)
            .unwrap()
            .unwrap()
    } else {
        book.certify_custom_statement(&authority, selected, None)
            .unwrap()
            .unwrap()
    }
}

#[test]
fn original_custom_layout_traces_hidden_changes_through_later_activation_and_offline_replay() {
    for (seed, functional) in [(0xc7, false), (0xc8, true)] {
        let mut fixture = Fixture::new(seed);
        fixture.transfer(
            day(2026, 2, 15),
            b"custom-trace-original",
            fixture.usd,
            ("1000", "4000"),
            100,
        );
        let mut selected = activate(&mut fixture.book, 1, day(2026, 1, 1));
        selected.functional = functional;
        let before = source(&mut fixture.book, selected.clone(), functional);
        let increase = fixture.transfer(
            day(2026, 2, 16),
            b"custom-trace-small-increase",
            fixture.usd,
            ("1000", "4000"),
            1,
        );
        // The new named layout is active inside the interval. The saved
        // accounting question still selects the first original activation.
        activate(&mut fixture.book, 2, day(2026, 2, 1));
        let decrease = fixture.transfer(
            day(2026, 2, 17),
            b"custom-trace-small-decrease",
            fixture.usd,
            ("4000", "1000"),
            1,
        );
        let after = source(&mut fixture.book, selected.clone(), functional);
        let authority = Capability::embedded(PRINCIPAL, &["read", "produce", "witness"]).unwrap();
        let comparison = fixture
            .book
            .compare_statement_certificates(
                PRINCIPAL,
                &authority,
                &before.certificate,
                &after.certificate,
            )
            .unwrap()
            .unwrap();
        assert!(comparison.report.is_unchanged());

        fixture.transfer(
            day(2026, 2, 18),
            b"custom-trace-later-backdate",
            fixture.usd,
            ("1000", "4000"),
            900,
        );
        let head = fixture.book.head().unwrap();
        let certified = if functional {
            fixture.book.certify_functional_statement_trace_from_diff(
                PRINCIPAL,
                &authority,
                &comparison.certificate,
                64,
            )
        } else {
            fixture.book.certify_statement_trace_from_diff(
                PRINCIPAL,
                &authority,
                &comparison.certificate,
                64,
            )
        }
        .unwrap()
        .unwrap();
        assert_eq!(fixture.book.head().unwrap(), head);
        assert_eq!(certified.report.summary(), &comparison.report);
        assert!(certified.report.is_custom());
        assert!(certified.report.had_changes());
        assert_eq!(certified.report.is_functional(), functional);
        let sources = certified.certificate.sources();
        assert_eq!(sources.first(), Some(&before.certificate));
        assert_eq!(sources.last(), Some(&after.certificate));
        assert_eq!(
            sources.len() as u64,
            after.certificate.known_at.0 - before.certificate.known_at.0 + 1
        );
        for (index, retained) in sources.iter().enumerate() {
            assert_eq!(
                retained.known_at.0,
                before.certificate.known_at.0 + index as u64
            );
            assert_eq!(retained.selection, before.certificate.selection);
        }
        for (posted, delta) in [(increase, 1), (decrease, -1)] {
            let publication = certified
                .report
                .publications()
                .iter()
                .find(|step| step.recorded_at == posted.recorded_at())
                .unwrap();
            let row = publication
                .changes
                .iter()
                .find(|line| line.code == "revenue")
                .unwrap();
            assert_eq!(row.delta, [delta, 0]);
            assert!(
                publication
                    .entries
                    .iter()
                    .any(|link| link.entry_ref == posted.entry_ref())
            );
        }
        assert!(
            certified
                .report
                .publications()
                .iter()
                .any(|step| step.is_unchanged())
        );

        let request = CustomStatementTraceRequest {
            selection: selected,
            before: before.certificate.known_at,
            after: Some(after.certificate.known_at),
            max_publications: 64,
        };
        let direct = if functional {
            fixture
                .book
                .certify_functional_custom_statement_trace(PRINCIPAL, &authority, &request)
        } else {
            fixture
                .book
                .certify_custom_statement_trace(PRINCIPAL, &authority, &request)
        }
        .unwrap()
        .unwrap();
        assert_eq!(direct.report, certified.report);
        let bytes = certified.certificate.canonical_bytes().unwrap();
        let artifact = ReportArtifact::decode(&bytes).unwrap();
        assert_eq!(artifact.family(), ReportArtifactFamily::StatementTrace);
        assert_eq!(artifact.digest(), certified.certificate.digest());
        assert_eq!(
            fixture
                .book
                .replay_statement_trace(PRINCIPAL, &authority, &certified.certificate)
                .unwrap()
                .unwrap(),
            certified.report
        );

        let state = fixture
            .book
            .checkpoint(PRINCIPAL, &authority)
            .unwrap()
            .unwrap()
            .checkpoint
            .checkpoint
            .body
            .state_oid;
        let head = fixture.book.head().unwrap();
        let produced = fixture
            .book
            .produce_statement_trace_bundle(
                PRINCIPAL,
                &authority,
                Some(state),
                &certified.certificate,
            )
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(fixture.book.head().unwrap(), head);
        let key = fixture.book.checkpoint_public_key();
        let anchor = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
        let verified = fa_verify::report::verify_report_expected(
            &produced.bundle.bytes,
            &[key],
            Some(&anchor.checkpoint),
            Some(&produced.receipt),
            Some(certified.certificate.digest()),
        )
        .expect(
            "an independent recipient must reconstruct every original company-layout publication",
        );
        assert_eq!(verified.scope, "recomputation");
        assert_eq!(verified.output, certified.certificate.output());
        assert_eq!(verified.known_at, after.certificate.known_at.0);
        let trace = verified.statement_trace.unwrap();
        assert_eq!(
            trace.publications.len(),
            certified.report.publications().len()
        );
        assert!(trace.summary.lines.iter().all(|line| line.delta == [0, 0]));
        let context = trace.summary.custom.as_ref().unwrap();
        assert_eq!(
            context.activation.activation,
            request.selection.activation.0
        );
        assert!(!context.activation.approval_admission_verified);
        assert!(!context.activation.definition_birth_verified);
        for shown in [
            context.before_presented.as_ref(),
            context.after_presented.as_ref(),
        ] {
            assert_eq!(
                shown
                    .unwrap()
                    .lines
                    .iter()
                    .find(|line| line.code == "revenue")
                    .unwrap()
                    .presented_amounts,
                [10, 0]
            );
        }
        for (actual, expected) in trace
            .publications
            .iter()
            .zip(certified.report.publications())
        {
            assert_eq!(actual.recorded_at, expected.recorded_at.0);
            assert_eq!(actual.before_source_digest, expected.before_source_digest);
            assert_eq!(actual.after_source_digest, expected.after_source_digest);
            assert_eq!(actual.changes.len(), expected.changes.len());
            for (actual, expected) in actual.changes.iter().zip(&expected.changes) {
                assert_eq!(actual.code, expected.code);
                assert_eq!(actual.unit, expected.unit_id);
                assert_eq!(actual.before, expected.before);
                assert_eq!(actual.after, expected.after);
                assert_eq!(actual.delta, expected.delta);
            }
        }
        for pin in [
            comparison.certificate.digest(),
            &before.certificate.digest,
            &after.certificate.digest,
        ] {
            assert!(
                fa_verify::report::verify_report_expected(
                    &produced.bundle.bytes,
                    &[key],
                    None,
                    None,
                    Some(pin)
                )
                .is_err()
            );
        }
    }
}
