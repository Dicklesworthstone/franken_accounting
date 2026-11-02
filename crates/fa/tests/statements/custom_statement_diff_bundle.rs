//! A real approved layout and two real kernel frontiers cross the complete
//! producer/recipient boundary without replacing either original certificate.

use super::*;
use fa::ReportSelection;

fn source(
    book: &mut Book,
    selection: CustomStatementSelection,
    functional: bool,
) -> fa::CertifiedReport {
    let authority = Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap();
    if functional {
        book.certify_functional_custom_statement(&authority, selection, None)
            .unwrap()
            .unwrap()
    } else {
        book.certify_custom_statement(&authority, selection, None)
            .unwrap()
            .unwrap()
    }
}

#[test]
fn approved_native_and_functional_custom_comparisons_export_exact_original_sources() {
    for (seed, functional) in [(0xd7, false), (0xd8, true)] {
        let mut fixture = Fixture::new(seed);
        fixture.transfer(
            day(2026, 2, 15),
            b"custom-diff-original",
            fixture.usd,
            ("1000", "4000"),
            100,
        );
        let selected = activate(&mut fixture.book, 1, day(2026, 1, 1));
        let before = source(&mut fixture.book, selected.clone(), functional);
        fixture.transfer(
            day(2026, 2, 16),
            b"custom-diff-small-change",
            fixture.usd,
            ("1000", "4000"),
            1,
        );
        let after = source(&mut fixture.book, selected, functional);
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
        assert!(comparison.report.is_custom());
        assert!(!comparison.report.is_unchanged());
        let revenue = comparison
            .report
            .lines()
            .iter()
            .find(|line| line.code == "revenue" && line.unit_id == fixture.usd.0)
            .unwrap();
        assert_eq!(revenue.before, [100, 0]);
        assert_eq!(revenue.after, [101, 0]);
        assert_eq!(revenue.delta, [1, 0]);

        activate(&mut fixture.book, 2, day(2026, 2, 1));
        fixture.transfer(
            day(2026, 2, 17),
            b"custom-diff-later-backdate",
            fixture.usd,
            ("1000", "4000"),
            900,
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
            .produce_statement_diff_bundle(
                PRINCIPAL,
                &authority,
                Some(state),
                &comparison.certificate,
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
            Some(comparison.certificate.digest()),
        )
        .expect("the independent recipient must replay both original custom statements");
        assert_eq!(verified.output, comparison.certificate.output());
        assert_eq!(
            verified.certificate_digest,
            *comparison.certificate.digest()
        );
        assert_eq!(verified.known_at, after.certificate.known_at.0);
        let diff = verified.statement_diff.unwrap();
        let custom = diff.custom.as_ref().unwrap();
        let ReportSelection::CustomStatement(original) =
            comparison.certificate.report_selection().unwrap()
        else {
            panic!("comparison must retain its company-defined selection");
        };
        assert_eq!(custom.activation.activation, original.activation.0);
        assert_eq!(custom.activation.activated_at, original.activated_at.0);
        let shown = |presented: &fa_verify::report::VerifiedPresentedStatement| {
            presented
                .lines
                .iter()
                .find(|line| line.code == "revenue" && line.unit == fixture.usd.0)
                .unwrap()
                .presented_amounts
                .clone()
        };
        assert_eq!(shown(custom.before_presented.as_ref().unwrap()), [10, 0]);
        assert_eq!(shown(custom.after_presented.as_ref().unwrap()), [10, 0]);
        for (actual, expected) in diff.lines.iter().zip(comparison.report.lines()) {
            assert_eq!(actual.code, expected.code);
            assert_eq!(actual.unit, expected.unit_id);
            assert_eq!(actual.before, expected.before);
            assert_eq!(actual.after, expected.after);
            assert_eq!(actual.delta, expected.delta);
        }
        assert_eq!(diff.lines.len(), comparison.report.lines().len());
        let mut wire = fa_model::Reader::new(&produced.bundle.bytes);
        assert_eq!(wire.bytes(64, "format").unwrap(), b"fa:report-bundle:v1");
        assert_eq!(wire.u16("major").unwrap(), if functional { 3 } else { 2 });
        assert_eq!(wire.u16("minor").unwrap(), 0);
        let decoded =
            fa::StatementDiffCertificate::decode(wire.bytes(64 * 1024 * 1024, "outer").unwrap())
                .unwrap();
        assert_eq!(decoded.sources(), (&before.certificate, &after.certificate));
        for pin in [&before.certificate.digest, &after.certificate.digest] {
            assert!(
                fa_verify::report::verify_report_expected(
                    &produced.bundle.bytes,
                    &[key],
                    None,
                    None,
                    Some(pin),
                )
                .is_err(),
                "a source pin cannot substitute for the complete custom comparison"
            );
        }
    }
}
