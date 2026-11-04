//! Account-scoped migration extracts through the actual producer and the
//! independent verifier. Hidden chunks remain authenticated candidates:
//! their balance witnesses prove exclusion, rather than silently omitting
//! the history that would decide whether they belong.

use super::*;
use fa_verify::bundle::{BundleScope, Completeness, Grade};

fn cutoff() -> DateDay {
    DateDay::parse("2026-12-31").unwrap()
}

fn cells(requests: &[fa::BalanceRequest]) -> Vec<(VId, u32, Option<i32>)> {
    requests
        .iter()
        .map(|request| (request.account, request.unit, request.effective_through))
        .collect()
}

#[test]
fn migration_witness_cells_are_checkpoint_bound_exact_and_currently_authorized() {
    let fixture = Fixture::in_unit("EUR");
    let mut book = fixture.open();
    let before = Fixture::checkpoint(&mut book);
    fixture.stage(&mut book);
    let staged = Fixture::checkpoint(&mut book);
    let allowed = capability(&["read", "produce"]);
    let head = book.head().unwrap();
    let request = |book: &Book, state, account, through| {
        book.migration_balance_requests(PREPARER, &allowed, state, account, through)
            .unwrap()
            .unwrap()
    };
    assert!(request(&book, before.oid, None, cutoff()).is_empty());
    let all = request(&book, staged.oid, None, cutoff());
    let mut expected = vec![
        (
            account_vid(BOOK_ID, "1000"),
            fixture.unit.0,
            Some(cutoff().0),
        ),
        (
            account_vid(BOOK_ID, "3000"),
            fixture.unit.0,
            Some(cutoff().0),
        ),
    ];
    expected.sort();
    assert_eq!(cells(&all), expected);
    assert_eq!(all, request(&book, staged.oid, None, cutoff()));
    assert_eq!(
        cells(&request(
            &book,
            staged.oid,
            Some(account_vid(BOOK_ID, "1000")),
            cutoff()
        )),
        vec![(
            account_vid(BOOK_ID, "1000"),
            fixture.unit.0,
            Some(cutoff().0)
        )]
    );
    assert!(
        request(
            &book,
            staged.oid,
            Some(account_vid(BOOK_ID, "2000")),
            cutoff()
        )
        .is_empty()
    );
    assert!(request(&book, staged.oid, None, DateDay(day().0 - 1)).is_empty());
    assert_eq!(book.head().unwrap(), head, "deriving requests never writes");

    // An apparently narrow result still reads and checks the complete
    // prefix and current checkpoint chain. Every such read needs full reach.
    let denied = [
        capability(&["read"]),
        capability(&["produce"]),
        Capability::embedded(VId(77), &["read", "produce"]).unwrap(),
        allowed.clone().for_books(&[Id128([0x99; 16])]).unwrap(),
        allowed.clone().for_accounts(&["1000"]).unwrap(),
        allowed.clone().for_periods(&[OPENING]).unwrap(),
        allowed
            .clone()
            .for_classes(&[EntryClass::MIGRATION])
            .unwrap(),
        allowed.clone().effective_through(cutoff()),
        allowed.clone().known_at_most(staged.state.through_seq),
        allowed.clone().expiring_at(head),
    ];
    for cap in denied {
        let refused = book
            .migration_balance_requests(
                PREPARER,
                &cap,
                staged.oid,
                Some(account_vid(BOOK_ID, "1000")),
                cutoff(),
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(refused.exit, 7, "{refused:?}");
        assert_eq!(book.head().unwrap(), head);
    }
    let absent = book
        .migration_balance_requests(PREPARER, &allowed, Oid([0x77; 32]), None, cutoff())
        .unwrap()
        .unwrap_err();
    assert_eq!(absent.code, fa::proof::code::PROOF_STATE_UNKNOWN);
    book.revoke_capability(
        capability(&["issue_capability"]),
        allowed.commitment().unwrap(),
        day(),
        b"revoke-proof-reader",
        "Revoke migration witness discovery",
    )
    .unwrap()
    .unwrap();
    let revoked_head = book.head().unwrap();
    let refused = book
        .migration_balance_requests(PREPARER, &allowed, before.oid, None, cutoff())
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.exit, 7, "historical state cannot revive authority");
    assert_eq!(book.head().unwrap(), revoked_head);
}

#[test]
fn migrated_account_ads_verifies_open_finalized_abandoned_and_historical_selections() {
    for terminal in [kind::FINALIZE, kind::ABANDON] {
        let fixture = Fixture::new();
        let mut book = fixture.open();
        let before = Fixture::checkpoint(&mut book);
        let run = fixture.stage(&mut book);
        let staged = Fixture::checkpoint(&mut book);
        Fixture::terminal(&mut book, run, terminal);
        let after = Fixture::checkpoint(&mut book);
        let key = book.checkpoint_public_key();
        drop(book);
        let mut staged_bytes = None;
        for (name, state, expected_entries, has_candidates) in [
            ("before", &before, 0, false),
            ("staged", &staged, 0, true),
            ("after", &after, u64::from(terminal == kind::FINALIZE), true),
            ("staged-again", &staged, 0, true),
        ] {
            let oid = fa_verify::blake3::hex(&state.oid.0);
            let (package, warnings) = AdsPackage::export_at(
                &fixture,
                name,
                "2026-12-31",
                &["--account", "1000", "--state", &oid],
            );
            assert_eq!(package.key, key, "trust comes from the retained book key");
            let judged = package.verify(&package.gl);
            assert!(judged.verified(), "{name}: {:?}", judged.failures);
            assert_eq!(
                (judged.entries, judged.rows),
                (expected_entries, expected_entries * 2)
            );
            assert_eq!(judged.tb_rows, expected_entries);
            assert_eq!(judged.account_scope.as_deref(), Some("1000"));
            assert_eq!(
                judged.chart_rows, None,
                "full payload disclosure does not inflate scope claims"
            );
            assert_eq!(
                judged.bundle.manifest.through_seq,
                state.state.through_seq.0
            );
            assert_eq!(judged.bundle.manifest.leaf_count, state.state.leaf_count);
            assert_eq!(
                judged.bundle.manifest.completeness,
                Completeness::ScopeIndexComplete
            );
            assert!(matches!(
                judged.bundle.manifest.scope,
                BundleScope::Account(_)
            ));
            assert_eq!(
                judged.bundle.summary.balances.len(),
                usize::from(has_candidates)
            );
            assert_eq!(
                judged.bundle.summary.format,
                (1, if has_candidates { 2 } else { 0 })
            );
            assert_eq!(
                warnings
                    .iter()
                    .any(|warning| warning.contains("whole-prefix payload disclosure")),
                has_candidates,
                "{warnings:?}"
            );
            if has_candidates {
                assert!(judged.bundle.checks.iter().any(|check| {
                    check.check == "payload_disclosure" && check.grade == Grade::Pass
                }));
                assert!(warnings.iter().any(|warning| {
                    warning.contains(&format!(
                        "all {} distinct checkpoint-prefix journal records",
                        state.state.leaf_count
                    ))
                }));
            }
            if name == "staged" {
                staged_bytes = Some(package.bundle.clone());
            } else if name == "staged-again" {
                assert_eq!(
                    Some(package.bundle.clone()),
                    staged_bytes,
                    "replaying the same state is deterministic"
                );
            }
            if expected_entries > 0 {
                assert_eq!(AdsPackage::migration_rows(&package.gl).lines().count(), 2);
                let omitted = format!("{}\n", package.gl.lines().next().unwrap());
                let bad = package.verify(&omitted);
                assert!(!bad.verified());
                assert!(
                    bad.failures
                        .iter()
                        .any(|failure| failure.contains("missing from GL_Detail"))
                );
                let altered = package.gl.replacen("|50.00|", "|50.01|", 1);
                assert_ne!(altered, package.gl);
                assert!(!package.verify(&altered).verified());
            }
        }
        if terminal == kind::FINALIZE {
            // Neither an unrelated account nor a cutoff before the chunk
            // needs visibility witnesses or whole-prefix payload disclosure.
            for (name, account, through) in [
                ("other-account", "2000", "2026-12-31"),
                ("before-effective", "1000", "2025-12-31"),
            ] {
                let (package, warnings) =
                    AdsPackage::export_at(&fixture, name, through, &["--account", account]);
                let judged = package.verify(&package.gl);
                assert!(judged.verified(), "{name}: {:?}", judged.failures);
                assert_eq!((judged.entries, judged.tb_rows), (0, 0));
                assert_eq!(judged.bundle.summary.format, (1, 0));
                assert!(judged.bundle.summary.balances.is_empty());
                assert!(
                    !warnings
                        .iter()
                        .any(|warning| warning.contains("whole-prefix payload disclosure"))
                );
            }
        }
    }
}

#[test]
fn a_valid_balance_for_the_wrong_unit_account_or_cutoff_cannot_decide_a_migrated_extract() {
    let fixture = Fixture::in_unit("EUR");
    let mut book = fixture.open();
    let run = fixture.stage(&mut book);
    Fixture::terminal(&mut book, run, kind::FINALIZE);
    let state = Fixture::checkpoint(&mut book);
    drop(book);
    let (package, _) = AdsPackage::export_with(&fixture, &["--account", "1000"]);
    let good = package.verify(&package.gl);
    assert!(good.verified(), "{:?}", good.failures);
    let mut book = fixture.open();
    let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
    for (account, unit, through) in [
        ("1000", usd, cutoff()),
        ("2000", fixture.unit, cutoff()),
        ("1000", fixture.unit, DateDay(day().0 - 1)),
    ] {
        let unrelated = book
            .produce_bundle(
                PREPARER,
                &capability(&["read", "produce"]),
                Some(state.oid),
                &fa::BundleRequest {
                    scope: fa::BundleScope::Index(fa::ScopeRequest::Account {
                        account: account_vid(BOOK_ID, "1000"),
                        from: i32::MIN,
                        to: cutoff().0,
                    }),
                    balances: vec![fa::BalanceRequest {
                        account: account_vid(BOOK_ID, account),
                        unit: unit.0,
                        effective_through: Some(through.0),
                    }],
                    inline_documents: false,
                },
            )
            .unwrap()
            .unwrap()
            .unwrap();
        let judged = fa_verify::ads::verify_ads(
            &package.certificate,
            &package.chart,
            &package.gl,
            &package.tb,
            &unrelated.bundle.bytes,
            &[package.key],
            Some(&unrelated.receipt),
        )
        .unwrap();
        assert!(
            judged.bundle.verified(),
            "the replacement is a real valid proof"
        );
        assert!(!judged.verified());
        assert!(
            judged
                .failures
                .iter()
                .any(|failure| failure.contains("no migration-aware balance")),
            "{:?}",
            judged.failures
        );
    }
}

fn saft_at(fixture: &Fixture, state: &StoredState, name: &str) -> fa_verify::ads::AdsReport {
    let out = fixture.path.parent().unwrap().join(name);
    let oid = fa_verify::blake3::hex(&state.oid.0);
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(&fixture.path)
        .args([
            "export",
            "saft",
            "--as-of",
            "2026-12-31",
            "--with-proofs",
            "--state",
            &oid,
            "--out",
        ])
        .arg(&out)
        .arg("--json")
        .env_remove("FA_BOOK")
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 1);
    fa_cli::verbs::registry()
        .unwrap()
        .check_line(lines[0])
        .unwrap();
    let key = fixture.open().checkpoint_public_key();
    fa_verify::saft::verify_saft(
        &std::fs::read_to_string(out.join("SAF-T.xml")).unwrap(),
        &std::fs::read(out.join("SAFT_Proof.fab")).unwrap(),
        &[key],
        Some(&std::fs::read(out.join("SAFT_Proof.receipt")).unwrap()),
    )
    .unwrap()
}

#[test]
fn whole_chart_ads_and_saft_prove_hidden_foreign_unit_chunks_at_the_selected_state() {
    let fixture = Fixture::in_unit("EUR");
    let mut book = fixture.open();
    let run = fixture.stage(&mut book);
    let staged = Fixture::checkpoint(&mut book);
    Fixture::terminal(&mut book, run, kind::FINALIZE);
    let finalized = Fixture::checkpoint(&mut book);
    let key = book.checkpoint_public_key();
    drop(book);
    let mut hidden = None;
    for (name, state, count) in [("open", &staged, 0), ("final", &finalized, 1)] {
        let oid = fa_verify::blake3::hex(&state.oid.0);
        let (package, _) = AdsPackage::export_at(
            &fixture,
            &format!("ads-{name}"),
            "2026-12-31",
            &["--state", &oid],
        );
        assert_eq!(package.key, key);
        let judged = package.verify(&package.gl);
        assert!(judged.verified(), "{name}: {:?}", judged.failures);
        assert_eq!(
            (judged.entries, judged.rows, judged.tb_rows),
            (count, count * 2, count * 2)
        );
        assert_eq!(
            judged.bundle.manifest.through_seq,
            state.state.through_seq.0
        );
        assert_eq!(judged.chart_rows, Some(3));
        if name == "open" {
            // Three retained base-unit chart cells plus the two actual EUR
            // migration cells. A Cartesian expansion would add unused EUR
            // account 2000; visible rows alone would omit both required cells.
            assert_eq!(judged.bundle.summary.balances.len(), 5);
            hidden = Some(package);
        } else {
            let hidden = hidden.as_ref().unwrap();
            let smuggled = format!("{}{}", hidden.gl, AdsPackage::migration_rows(&package.gl));
            let bad = hidden.verify(&smuggled);
            assert!(!bad.verified());
            assert!(
                bad.failures
                    .iter()
                    .any(|failure| failure.contains("is no proven entry"))
            );
        }
        let saft = saft_at(&fixture, state, &format!("saft-{name}"));
        assert!(saft.verified(), "{name}: {:?}", saft.failures);
        assert_eq!(
            (saft.entries, saft.rows, saft.tb_rows),
            (count, count * 2, count * 2)
        );
        assert_eq!(saft.bundle.manifest.through_seq, state.state.through_seq.0);
    }
}
