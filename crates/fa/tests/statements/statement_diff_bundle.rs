//! The outsider independently reconstructs both historical statements and the
//! complete bridge, including chart changes that move no money.

use super::*;
use fa::{CertifiedStatementDiff, StatementDiffCertificate, StatementDiffRequest};

fn capability() -> Capability {
    Capability::embedded(PRINCIPAL, &["read", "produce", "witness"]).unwrap()
}

fn checkpoint(book: &mut Book) -> Oid {
    book.checkpoint(PRINCIPAL, &capability())
        .unwrap()
        .unwrap()
        .checkpoint
        .checkpoint
        .body
        .state_oid
}

fn comparison(fixture: &mut Fixture, definition: &str) -> CertifiedStatementDiff {
    fixture.transfer(
        day(2025, 12, 20),
        b"diff-comparative-income",
        fixture.usd,
        ("1000", "4000"),
        900,
    );
    fixture.transfer(
        day(2026, 1, 15),
        b"diff-original-income",
        fixture.usd,
        ("1000", "4000"),
        1_000,
    );
    let before = fixture.book.head().unwrap();
    fixture.transfer(
        day(2026, 1, 15),
        b"diff-late-income",
        fixture.usd,
        ("1000", "4000"),
        225,
    );
    fixture.transfer(
        day(2026, 1, 16),
        b"diff-late-expense",
        fixture.usd,
        ("6000", "1000"),
        50,
    );
    fixture
        .book
        .open_account(
            &account("6200", "New unused expense", AccountType::EXPENSE),
            day(2025, 12, 1),
            None,
            PRINCIPAL,
            day(2026, 1, 20),
            b"diff-new-zero-account",
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        )
        .unwrap()
        .unwrap();
    fixture
        .book
        .certify_statement_diff(
            PRINCIPAL,
            &capability(),
            &StatementDiffRequest {
                selection: selection(definition, JANUARY, DECEMBER),
                before,
                after: Some(fixture.book.head().unwrap()),
            },
        )
        .unwrap()
        .unwrap()
}

fn reseal(
    source: &StatementDiffCertificate,
    before: &ReportCertificate,
    after: &ReportCertificate,
    output: &[u8],
) -> StatementDiffCertificate {
    let mut writer = fa_model::Writer::new();
    writer
        .bytes(b"fa:statement-diff-certificate:v1")
        .u128(source.producer().0)
        .fixed(source.capability_commitment())
        .bytes(&before.canonical_bytes().unwrap())
        .bytes(&after.canonical_bytes().unwrap())
        .bytes(output);
    let mut bytes = writer.finish().unwrap();
    let digest = fa_model::domain_digest(b"fa:statement-diff-certificate-digest:v1", &[&bytes]);
    bytes.extend_from_slice(&digest);
    StatementDiffCertificate::decode(&bytes).unwrap()
}

fn substitute_certificate(bundle: &[u8], outer: &StatementDiffCertificate) -> Vec<u8> {
    let offset = 4 + fa_notary::report::REPORT_BUNDLE_FORMAT.len() + 4;
    let length = u32::from_le_bytes(bundle[offset..offset + 4].try_into().unwrap()) as usize;
    let certificate = outer.canonical_bytes().unwrap();
    let mut changed = bundle[..offset].to_vec();
    changed.extend_from_slice(&u32::try_from(certificate.len()).unwrap().to_le_bytes());
    changed.extend_from_slice(&certificate);
    changed.extend_from_slice(&bundle[offset + 4 + length..]);
    changed
}

#[test]
fn statement_diff_bundle_recomputes_both_frontiers_comparatives_and_zero_mappings() {
    for (seed, definition) in [(0xa1, "income-statement"), (0xa2, "balance-sheet")] {
        let mut fixture = Fixture::new(seed);
        let certified = comparison(&mut fixture, definition);
        let certificate = &certified.certificate;
        let (before, after) = certificate.sources();
        // Later backdates are present in the authenticated prefix but belong
        // to neither side of the original comparison.
        fixture.transfer(
            day(2026, 1, 17),
            b"diff-later-backdate",
            fixture.usd,
            ("1000", "4000"),
            999,
        );
        let state = checkpoint(&mut fixture.book);
        let head = fixture.book.head().unwrap();
        let produced = fixture
            .book
            .produce_statement_diff_bundle(PRINCIPAL, &capability(), Some(state), certificate)
            .unwrap()
            .unwrap()
            .unwrap();
        let again = fixture
            .book
            .produce_statement_diff_bundle(PRINCIPAL, &capability(), Some(state), certificate)
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(produced.bundle.bytes, again.bundle.bytes);
        assert_eq!(produced.receipt, again.receipt);
        assert_eq!(fixture.book.head().unwrap(), head);
        let key = fixture.book.checkpoint_public_key();
        let trusted = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
        let verified = fa_verify::report::verify_report_expected(
            &produced.bundle.bytes,
            &[key],
            Some(&trusted.checkpoint),
            Some(&produced.receipt),
            Some(certificate.digest()),
        )
        .expect("independent two-frontier statement recomputation");
        assert_eq!(verified.output, certificate.output());
        assert_eq!(verified.certificate_digest, *certificate.digest());
        assert_eq!(verified.known_at, after.known_at.0);
        assert_eq!(verified.scope, "recomputation");
        assert_eq!(verified.unit_universe_source, "authenticated-registry");
        assert!(verified.statement.is_none());
        let diff = verified.statement_diff.unwrap();
        assert_eq!(diff.before_known_at, before.known_at.0);
        assert_eq!(diff.after_known_at, after.known_at.0);
        assert_eq!(diff.lines.len(), certified.report.lines().len());
        assert_eq!(
            diff.mapping_changes.len(),
            certified.report.mapping_changes().len()
        );
        assert_eq!(diff.mapping_changes.len(), 1, "zero leaf remains visible");
        for (actual, expected) in diff.lines.iter().zip(certified.report.lines()) {
            assert_eq!(actual.code, expected.code);
            assert_eq!(actual.unit, expected.unit_id);
            assert_eq!(actual.before, expected.before);
            assert_eq!(actual.after, expected.after);
            assert_eq!(actual.delta, expected.delta);
            assert_eq!(actual.delta[1], 0, "comparative column is unchanged");
        }
        for nested in [&before.digest, &after.digest] {
            assert!(
                fa_verify::report::verify_report_expected(
                    &produced.bundle.bytes,
                    &[key],
                    None,
                    Some(&produced.receipt),
                    Some(nested),
                )
                .is_err(),
                "one source never pins the complete comparison"
            );
        }
        assert!(
            fa_verify::report::verify_report_expected(
                &produced.bundle.bytes,
                &[key],
                None,
                None,
                None,
            )
            .is_err()
        );
    }
}

#[test]
fn statement_diff_bundle_refuses_resealed_bridge_and_incomplete_checkpoint() {
    let mut fixture = Fixture::new(0xa3);
    let early_state = checkpoint(&mut fixture.book);
    let certified = comparison(&mut fixture, "income-statement");
    let certificate = &certified.certificate;
    let state = checkpoint(&mut fixture.book);
    let produced = fixture
        .book
        .produce_statement_diff_bundle(PRINCIPAL, &capability(), Some(state), certificate)
        .unwrap()
        .unwrap()
        .unwrap();
    let head = fixture.book.head().unwrap();
    assert!(fixture.book.produce_statement_diff_bundle(
        PRINCIPAL, &capability(), Some(early_state), certificate,
    ).unwrap().is_err());
    assert!(
        fixture
            .book
            .produce_statement_diff_bundle(
                PRINCIPAL,
                &capability(),
                Some(Oid([0xfe; 32])),
                certificate,
            )
            .unwrap()
            .unwrap()
            .is_none()
    );
    let mut output = certificate.output().to_vec();
    // Change a real nonzero amount while repairing the complete outer digest.
    let amount = 1_225_i128.to_le_bytes();
    let offset = output
        .windows(16)
        .position(|bytes| bytes == amount)
        .unwrap();
    output[offset] ^= 1;
    let (before, after) = certificate.sources();
    let forged = reseal(certificate, before, after, &output);
    assert!(
        fixture
            .book
            .produce_statement_diff_bundle(PRINCIPAL, &capability(), Some(state), &forged,)
            .unwrap()
            .is_err()
    );
    let changed = substitute_certificate(&produced.bundle.bytes, &forged);
    assert!(
        fa_verify::report::verify_report_expected(
            &changed,
            &[fixture.book.checkpoint_public_key()],
            None,
            None,
            Some(forged.digest()),
        )
        .is_err(),
        "even a supplied digest cannot make false bridge arithmetic true"
    );
    assert_eq!(fixture.book.head().unwrap(), head);
}

#[test]
fn statement_diff_bundle_requires_current_whole_book_authority() {
    let mut fixture = Fixture::new(0xa4);
    let certified = comparison(&mut fixture, "income-statement");
    let state = checkpoint(&mut fixture.book);
    let head = fixture.book.head().unwrap();
    for denied in [
        Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        capability().for_accounts(&["1000"]).unwrap(),
        capability().for_periods(&[JANUARY]).unwrap(),
        capability().known_at_most(head),
        capability().expiring_at(head),
    ] {
        assert!(
            fixture
                .book
                .produce_statement_diff_bundle(
                    PRINCIPAL,
                    &denied,
                    Some(state),
                    &certified.certificate,
                )
                .unwrap()
                .is_err()
        );
    }
    assert_eq!(fixture.book.head().unwrap(), head);
}

#[test]
fn functional_statement_diff_does_not_borrow_the_native_portable_profile() {
    let mut fixture = Fixture::new(0xa5);
    let native = comparison(&mut fixture, "income-statement");
    let functional = fixture
        .book
        .certify_functional_statement_diff(
            PRINCIPAL,
            &capability(),
            &native.certificate.request().unwrap(),
        )
        .unwrap()
        .unwrap();
    assert!(functional.certificate.uses_functional_valuations());
    let state = checkpoint(&mut fixture.book);
    let head = fixture.book.head().unwrap();
    let refusal = fixture
        .book
        .produce_statement_diff_bundle(
            PRINCIPAL,
            &capability(),
            Some(state),
            &functional.certificate,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, fa_notary::code::SCOPE_UNSUPPORTED);
    assert_eq!(fixture.book.head().unwrap(), head);
}

#[test]
fn statement_diff_bundle_counts_migration_only_after_finalize_at_each_source_frontier() {
    use fa_journal::{RunBody, RunControlRequest, RunMode, TrialBalanceLine};
    use fa_model::{ApprovalRef, PeriodRef};

    let mut fixture = Fixture::new(0xa6);
    let opening = "FY2026-OPEN";
    let close = Capability::embedded(PRINCIPAL, &["close"]).unwrap();
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
                opening,
                transition,
                PRINCIPAL,
                1,
                format!("diff-migration-opening-{index}").as_bytes(),
                &close,
            )
            .unwrap()
            .unwrap();
    }
    let lock = fixture
        .book
        .plan_transition(
            opening,
            PeriodTransition::Lock,
            PRINCIPAL,
            1,
            b"diff-migration-lock-opening",
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
    let evidence = Document {
        book_id: fixture.book.context().book_id,
        kind: 18,
        mime: "text/csv".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: b"account,unit,net\n1000,USD,5000\n3000,USD,-5000\n".to_vec(),
    };
    fixture.book.add_document(&evidence).unwrap().unwrap();
    let body = RunBody {
        book_id: fixture.book.context().book_id,
        run_key: "statement-diff-opening".into(),
        source_system: "legacy".into(),
        mode: RunMode::OpeningOnly,
        trial_balance: evidence.oid(),
        opening_date: day(2026, 1, 1),
        lines: [("1000", 5_000), ("3000", -5_000)]
            .into_iter()
            .map(|(account_code, mantissa)| TrialBalanceLine {
                account_code: account_code.into(),
                unit: fixture.usd,
                mantissa,
            })
            .collect(),
        periods: Vec::new(),
        detail_base: Vec::new(),
        sole_opening_source: false,
    };
    let migration = Capability::embedded(PRINCIPAL, &["post", "migrate"]).unwrap();
    let before_open = fixture.book.head().unwrap();
    let proposal = fixture
        .book
        .open_migration_proposal(
            PRINCIPAL,
            &body,
            vec![evidence.evidence_ref(1)],
            b"diff-open-migration",
            fixture.book.seal_text("Open statement migration").unwrap(),
        )
        .unwrap();
    let opened = fixture
        .book
        .open_migration_run(
            &body,
            RunControlRequest {
                proposal,
                capability: migration.clone(),
                approvals: Vec::new(),
            },
        )
        .unwrap()
        .unwrap()
        .recorded_at;
    let approve = |book: &mut Book, proposal: &EntryPayload| -> Vec<ApprovalRef> {
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
    };
    let mut proposal = fixture.proposal(
        body.opening_date,
        b"diff-migration-chunk",
        EntryClass::MIGRATION,
        fixture.legs(fixture.usd, ("1000", "3000"), 5_000),
    );
    proposal.effective_period = Some(PeriodRef {
        calendar: "statement-calendar".into(),
        code: opening.into(),
    });
    proposal.origin = EntryOrigin::Migration {
        run_ref: body.vid(),
        source_system: body.source_system.clone(),
        source_id: fixture.book.seal_text("legacy-opening-1").unwrap(),
        source_recorded_at_ns: None,
        source_entered_by: None,
        source_approved_by: None,
        batch_oid: evidence.oid(),
    };
    proposal.evidence = vec![evidence.evidence_ref(1)];
    let approvals = approve(&mut fixture.book, &proposal);
    fixture
        .book
        .post(PostRequest {
            proposal,
            approvals,
            plan_certificate: None,
            capability: migration.clone(),
        })
        .unwrap()
        .unwrap();
    let staged = fixture.book.head().unwrap();
    let proposal = fixture
        .book
        .plan_migration_transition(
            body.vid(),
            fa_journal::migration::kind::FINALIZE,
            PRINCIPAL,
            b"diff-finalize-migration",
            fixture
                .book
                .seal_text("Finalize statement migration")
                .unwrap(),
        )
        .unwrap()
        .unwrap();
    let approvals = approve(&mut fixture.book, &proposal);
    let finalized = fixture
        .book
        .transition_migration_run(RunControlRequest {
            proposal,
            capability: migration,
            approvals,
        })
        .unwrap()
        .unwrap()
        .recorded_at;
    let state = checkpoint(&mut fixture.book);
    let head = fixture.book.head().unwrap();
    // The shared closure needs this run body for AFTER. BEFORE needs no body
    // before Open or before the first chunk, and needs the body but excludes
    // its amounts while staged. Finalize must never rewrite those old views.
    for before in [before_open, opened, staged] {
        let certified = fixture
            .book
            .certify_statement_diff(
                PRINCIPAL,
                &capability(),
                &StatementDiffRequest {
                    selection: selection("balance-sheet", JANUARY, DECEMBER),
                    before,
                    after: Some(finalized),
                },
            )
            .unwrap()
            .unwrap();
        for line in ["assets", "equity"] {
            assert_eq!(
                amounts(certified.report.before(), line, fixture.usd),
                [0, 0]
            );
            assert_eq!(
                amounts(certified.report.after(), line, fixture.usd),
                [5_000, 0]
            );
        }
        let produced = fixture
            .book
            .produce_statement_diff_bundle(
                PRINCIPAL,
                &capability(),
                Some(state),
                &certified.certificate,
            )
            .unwrap()
            .unwrap()
            .unwrap();
        let key = fixture.book.checkpoint_public_key();
        let trusted = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
        let verified = fa_verify::report::verify_report_expected(
            &produced.bundle.bytes,
            &[key],
            Some(&trusted.checkpoint),
            Some(&produced.receipt),
            Some(certified.certificate.digest()),
        )
        .expect("migration activation is independently selected at each statement frontier");
        assert_eq!(verified.output, certified.certificate.output());
        let comparison = verified.statement_diff.unwrap();
        assert_eq!(comparison.before_known_at, before.0);
        assert_eq!(comparison.after_known_at, finalized.0);
        assert!(comparison.mapping_changes.is_empty());
        for code in ["assets", "equity"] {
            let line = comparison
                .lines
                .iter()
                .find(|line| line.code == code && line.unit == fixture.usd.0)
                .unwrap();
            assert_eq!(line.before, [0, 0]);
            assert_eq!(line.after, [5_000, 0]);
            assert_eq!(line.delta, [5_000, 0]);
        }
    }
    assert_eq!(fixture.book.head().unwrap(), head);
}
