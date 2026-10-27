//! Financial statements use the same independently checked valuation closure
//! as functional trial balances, then reproduce their own mapping and formulas.

use super::*;

#[test]
fn functional_statement_exports_reproduce_comparative_columns_after_later_backdates() {
    let mut fixture = Fixture::new();
    fixture.post(b"statement-export-january", day(1, 5), 10_000, 11);
    fixture.post(b"statement-export-february", day(2, 5), 20_000, 12);
    average_post(&mut fixture);
    let known_at = fixture.book.head().unwrap();
    let mut reports = Vec::new();
    for definition in ["balance-sheet", "income-statement"] {
        for cumulative in [false, true] {
            let mut selection = statement_selection(definition, true);
            if cumulative {
                selection.periods.insert(0, "FY2026-P01".into());
            }
            let certified = fixture
                .book
                .certify_functional_statement(PRINCIPAL, &producer(), selection, Some(known_at))
                .unwrap()
                .unwrap();
            let line = if definition == "balance-sheet" {
                "assets"
            } else {
                "net_income"
            };
            let expected = if definition == "balance-sheet" || cumulative {
                vec![41_000, 11_000]
            } else {
                vec![30_000, 11_000]
            };
            assert_eq!(
                statement_amounts(&certified.statement, line, fixture.usd),
                expected
            );
            reports.push((certified.certificate, line, expected));
        }
    }
    fixture.rate(day(1, 5), 99, "Unused quote after original statement");
    fixture.post(b"statement-export-late-backdate", day(1, 20), 2_000, 13);
    let state = checkpoint(&mut fixture.book);
    let before = fixture.book.head().unwrap();
    for (certificate, line, expected) in reports {
        let produced = produce(&mut fixture, state, &certificate);
        let again = produce(&mut fixture, state, &certificate);
        assert_eq!(produced.bundle.bytes, again.bundle.bytes);
        assert_eq!(produced.receipt, again.receipt);
        assert_eq!(produced.documents.len(), 3);
        let verified = verify(&fixture, &produced, &certificate);
        assert_eq!(verified.output, certificate.output);
        assert_eq!(verified.known_at, known_at.0);
        assert!(verified.statement.is_none());
        assert!(verified.functional_trial_balance.is_none());
        let functional = verified.functional_statement.unwrap();
        assert_eq!(functional.base_unit, fixture.usd.0);
        assert_eq!(functional.statement.units, vec![fixture.usd.0]);
        assert_eq!(functional.statement.columns.len(), 2);
        assert_eq!(functional.statement.columns[1].periods, vec!["FY2026-P01"]);
        assert_eq!(
            functional
                .statement
                .lines
                .iter()
                .find(|row| row.code == line)
                .unwrap()
                .amounts,
            expected
        );
    }
    assert_eq!(fixture.book.head().unwrap(), before);
}

#[test]
fn functional_statement_export_requires_authority_and_authenticated_original_rate_receiver() {
    let mut fixture = Fixture::new();
    fixture.post(b"statement-export-source", day(1, 5), 10_000, 11);
    let certificate = fixture
        .book
        .certify_functional_statement(
            PRINCIPAL,
            &producer(),
            statement_selection("balance-sheet", true),
            None,
        )
        .unwrap()
        .unwrap()
        .certificate;
    let state = checkpoint(&mut fixture.book);
    let pin = fixture.book.head().unwrap();
    fixture.post(b"statement-after-producer-pin", day(2, 5), 500, 12);
    let before = fixture.book.head().unwrap();
    for denied in [
        cap(&["read"]),
        producer().for_accounts(&["1200"]).unwrap(),
        producer().known_at_most(CommitSeq(certificate.known_at.0 - 1)),
    ] {
        assert!(
            fixture
                .book
                .produce_report_bundle(PRINCIPAL, &denied, Some(state), &certificate)
                .unwrap()
                .is_err()
        );
    }
    let produced = fixture
        .book
        .produce_report_bundle(
            PRINCIPAL,
            &producer().known_at_most(pin),
            Some(state),
            &certificate,
        )
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        verify(&fixture, &produced, &certificate).output,
        certificate.output
    );
    for (receipt, pin) in [
        (Some(produced.receipt.as_slice()), None),
        (None, Some(&certificate.digest)),
    ] {
        let verified = fa_verify::report::verify_report_expected(
            &produced.bundle.bytes,
            &[fixture.book.checkpoint_public_key()],
            None,
            receipt,
            pin,
        )
        .unwrap();
        assert_eq!(verified.output, certificate.output);
    }
    assert!(
        fa_verify::report::verify_report_expected(
            &produced.bundle.bytes,
            &[fixture.book.checkpoint_public_key()],
            None,
            None,
            None,
        )
        .is_err(),
        "a checkpoint alone does not authenticate the statement question"
    );
    let forged = forged_rate_receiver(&fixture, &produced, &certificate);
    assert!(
        fa_verify::report::verify_report_expected(
            &forged,
            &[fixture.book.checkpoint_public_key()],
            None,
            None,
            Some(&certificate.digest),
        )
        .is_err(),
        "the receiver must match its signed original ImportReceipt"
    );
    assert_eq!(fixture.book.head().unwrap(), before);
}
