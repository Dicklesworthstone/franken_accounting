//! Optional equity evidence joins the real PPA disclosure lifecycle. The fixed
//! statement set remains mandatory, and an independent question binds roles,
//! all posted monetary units and the current posting period.

use super::*;

pub(super) fn prepare(
    book: &mut Book,
    closer: &Capability,
    document: Oid,
    statements: &[[u8; 32]],
    post: fa_journal::DisclosurePost,
    date: DateDay,
) -> fa::CaseEquityDisclosureComparison {
    let book_id = book.context().book_id;
    let units = UnitRegistry::embedded().unwrap();
    let usd = units.lookup("USD").unwrap().0;
    let eur = units.lookup("EUR").unwrap().0;
    let selection = fa::CaseEquityComparisonSelection {
        period: "FY2026-P02".into(),
        label: "February prior-period adjustment impact".into(),
        units: vec![usd],
        issuance_accounts: vec![account_vid(book_id, "3000")],
        distribution_accounts: Vec::new(),
    };
    let read = Capability::embedded(PRINCIPAL, &["read"]).unwrap();
    let head = book.head().unwrap();
    let (request, report) = book
        .case_equity_diff(PRINCIPAL, &read, 1, &selection)
        .unwrap()
        .unwrap();
    assert_eq!(request.before.known_at.unwrap().0 + 1, post.recorded_at.0);
    assert_eq!(request.after, post.recorded_at);
    assert_eq!(request.before.effective_from, day(2026, 2, 1));
    assert_eq!(request.before.effective_through, day(2026, 2, 28));
    assert_eq!(report.units().len(), 1);
    let row = |code| {
        report.units()[0]
            .lines
            .iter()
            .find(|line| line.code == code)
            .unwrap()
    };
    assert_eq!(row("prior_period_adjustments").delta, 50_000);
    assert_eq!(row("opening_equity_as_adjusted").delta, 50_000);
    assert_eq!(row("net_income").delta, 0);
    assert_eq!(row("issuances").delta, 0);
    assert_eq!(row("equity_tie_out_residual").delta, 0);
    assert_eq!(
        book.head().unwrap(),
        head,
        "Read alone computes without publishing"
    );

    for bad in [
        fa::CaseEquityComparisonSelection {
            period: "FY2025-P12".into(),
            ..selection.clone()
        },
        fa::CaseEquityComparisonSelection {
            units: vec![eur],
            ..selection.clone()
        },
        fa::CaseEquityComparisonSelection {
            units: Vec::new(),
            ..selection.clone()
        },
        fa::CaseEquityComparisonSelection {
            units: vec![usd, usd],
            ..selection.clone()
        },
        fa::CaseEquityComparisonSelection {
            distribution_accounts: selection.issuance_accounts.clone(),
            ..selection.clone()
        },
        fa::CaseEquityComparisonSelection {
            issuance_accounts: vec![account_vid(book_id, "1000")],
            ..selection.clone()
        },
    ] {
        let refusal = book
            .case_equity_diff_request(PRINCIPAL, &read, 1, &bad)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, code::CASE_STATEMENT_DIFF, "{refusal:?}");
        assert_eq!(book.head().unwrap(), head);
    }
    let denied = book
        .case_equity_diff_request(
            PRINCIPAL,
            &Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
            0,
            &fa::CaseEquityComparisonSelection {
                units: Vec::new(),
                ..selection.clone()
            },
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(
        denied.code, "FA-REF-011",
        "authority precedes malformed scope and unknown case"
    );

    let produce = Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap();
    let before = book
        .certify_equity_roll_forward(PRINCIPAL, &produce, &request.before)
        .unwrap()
        .unwrap();
    let after = book
        .certify_equity_roll_forward(
            PRINCIPAL,
            &produce,
            &fa::EquityRollForwardRequest {
                known_at: Some(request.after),
                ..request.before.clone()
            },
        )
        .unwrap()
        .unwrap();
    let comparison = book
        .compare_equity_roll_forward_certificates(
            PRINCIPAL,
            &produce,
            &before.certificate,
            &after.certificate,
            &request,
        )
        .unwrap()
        .unwrap();
    assert_eq!(comparison.report, report);
    let bytes = comparison.certificate.canonical_bytes().unwrap();
    let digest = *comparison.certificate.digest();
    let kernel = fa_journal::validate_disclosure_comparison(book_id, post, digest, &bytes)
        .expect("the bounded journal parser accepts actual producer bytes");
    assert_eq!(kernel.digest(), &digest);
    let mut changed = bytes.clone();
    let middle = changed.len() / 2;
    changed[middle] ^= 1;
    assert!(fa_journal::validate_disclosure_comparison(book_id, post, digest, &changed).is_err());
    assert!(
        fa_journal::validate_disclosure_comparison(
            book_id,
            fa_journal::DisclosurePost {
                recorded_at: fgdb_types::CommitSeq(post.recorded_at.0 + 1),
                ..post
            },
            digest,
            &bytes,
        )
        .is_err()
    );
    book.retain_report_artifact_for(
        PRINCIPAL,
        &produce,
        &bytes,
        Some(&digest),
        fa::ReportArtifactExpectation::EquityRollForwardDiff(&request),
    )
    .unwrap()
    .unwrap();
    let attachment = fa::CaseEquityDisclosureComparison {
        certificate: digest,
        expected: request,
    };
    let head = book.head().unwrap();
    let mut wrong_after = attachment.clone();
    wrong_after.expected.after = head;
    let mut wrong_before = attachment.clone();
    wrong_before.expected.before.known_at = Some(fgdb_types::CommitSeq(post.recorded_at.0 - 2));
    let mut annual = attachment.clone();
    annual.expected.before.effective_from = day(2026, 1, 1);
    annual.expected.before.effective_through = day(2026, 12, 31);
    let mut omitted_unit = attachment.clone();
    omitted_unit.expected.before.units = vec![eur];
    let mut changed_roles = attachment.clone();
    changed_roles.expected.before.issuance_accounts.clear();
    let mut missing = attachment.clone();
    missing.certificate = [0x98; 32];
    for (key, extras) in [
        ("wrong-equity-after", vec![wrong_after]),
        ("wrong-equity-before", vec![wrong_before]),
        ("wrong-equity-period", vec![annual]),
        ("omitted-equity-unit", vec![omitted_unit]),
        ("changed-equity-roles", vec![changed_roles]),
        ("missing-equity", vec![missing]),
        (
            "duplicate-equity",
            vec![attachment.clone(), attachment.clone()],
        ),
    ] {
        let refusal = book
            .disclose_case_with_equity(
                closer.clone(),
                1,
                document,
                statements,
                &extras,
                date,
                key.as_bytes(),
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, code::CASE_STATEMENT_DIFF, "{refusal:?}");
        assert_eq!(
            book.head().unwrap(),
            head,
            "invalid supplemental evidence writes nothing"
        );
    }
    let refusal = book
        .disclose_case_with_equity(
            closer.clone(),
            1,
            document,
            &statements[1..],
            std::slice::from_ref(&attachment),
            date,
            b"equity-replaces-no-statement",
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, code::CASE_STATEMENT_DIFF);
    let denied = book
        .disclose_case_with_equity(
            Capability::embedded(PRINCIPAL, &["restate"]).unwrap(),
            1,
            document,
            &[[0; 32]],
            std::slice::from_ref(&attachment),
            date,
            b"equity-no-read",
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(denied.code, "FA-REF-011");
    assert_eq!(book.head().unwrap(), head);
    attachment
}

pub(super) fn replay_after_disclosure(
    book: &mut Book,
    comparison: &fa::CaseEquityDisclosureComparison,
) {
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce", "witness"]).unwrap();
    let artifact = book
        .read_report_artifact(PRINCIPAL, &capability, &comparison.certificate)
        .unwrap()
        .unwrap();
    let certificate =
        fa::EquityRollForwardDiffCertificate::decode(&artifact.canonical_bytes().unwrap()).unwrap();
    let replay = book
        .replay_equity_roll_forward_diff(PRINCIPAL, &capability, &certificate, &comparison.expected)
        .unwrap()
        .unwrap();
    assert_eq!(replay.canonical_bytes().unwrap(), certificate.output());
    let state = book
        .checkpoint(PRINCIPAL, &capability)
        .unwrap()
        .unwrap()
        .checkpoint
        .checkpoint
        .body
        .state_oid;
    let bundle = book
        .produce_equity_roll_forward_diff_bundle(
            PRINCIPAL,
            &capability,
            Some(state),
            &certificate,
            &comparison.expected,
        )
        .unwrap()
        .unwrap()
        .unwrap();
    let recipient = fa_verify::report::EquityRollForwardDiffRequest::decode(
        &comparison.expected.canonical_bytes().unwrap(),
    )
    .unwrap();
    let verified = fa_verify::report::verify_equity_roll_forward_diff_report_expected(
        &bundle.bundle.bytes,
        &[book.checkpoint_public_key()],
        None,
        Some(&bundle.receipt),
        &recipient,
        Some(&comparison.certificate),
    )
    .expect("the disclosed equity comparison recomputes independently after later case controls");
    assert_eq!(verified.output, certificate.output());
}
