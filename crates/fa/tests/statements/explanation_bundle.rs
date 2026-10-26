//! Native producer output and the independent explanation interpreter agree
//! on whole-period commitments, released reservations, lineage and evidence.

use super::report_bundle::{produce, replace_certificate, reseal};
use super::*;

fn chosen(book: &Book, code: &str) -> fa::ReportSelection {
    fa::ReportSelection::ExplainBalance {
        account: account_vid(book.context().book_id, code),
        period: JANUARY.into(),
    }
}

fn verify(
    book: &Book,
    produced: &fa::ProducedBundle,
    certificate: &ReportCertificate,
) -> fa_verify::report::VerifiedReport {
    let key = book.checkpoint_public_key();
    let anchor = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    let verified = fa_verify::report::verify_report_expected(
        &produced.bundle.bytes,
        &[key],
        Some(&anchor.checkpoint),
        Some(&produced.receipt),
        Some(&certificate.digest),
    )
    .expect("the independent prefix must reproduce every native explanation byte");
    assert_eq!(verified.output, certificate.output);
    assert_eq!(verified.certificate_digest, certificate.digest);
    assert_eq!(verified.known_at, certificate.known_at.0);
    assert_eq!(verified.scope, "recomputation");
    assert_eq!(verified.unit_universe_source, "authenticated-registry");
    assert!(verified.explanation.is_some());
    assert!(verified.open_items.is_none());
    assert!(verified.statement.is_none());
    assert!(verified.rows.is_empty());
    verified
}

fn reverse(fixture: &mut Fixture, target: fa_model::EntryRef) -> Posted {
    let (source, _) = fixture.book.read_entry(target.vid).unwrap().unwrap();
    let mut legs = source.proposal.legs.clone();
    for leg in &mut legs {
        leg.side = if leg.side == Side::Debit {
            Side::Credit
        } else {
            Side::Debit
        };
        leg.settles.clear();
    }
    let mut proposal = fixture.proposal(
        source.proposal.effective_date,
        b"explanation-reverse",
        EntryClass::REVERSAL,
        legs,
    );
    proposal.supersession = vec![fa_model::Supersession {
        target,
        kind: fa_model::SupersessionKind::Reverses,
        reason_code: 9,
    }];
    fixture.commit(proposal)
}

#[test]
fn historical_explanations_recompute_whole_period_digest_released_holds_lineage_and_evidence() {
    let mut fixture = Fixture::new(0x85);
    let usd = fixture.usd;
    let cash = account_vid(fixture.book.context().book_id, "1000");
    let revenue = account_vid(fixture.book.context().book_id, "4000");
    // Two same-cell legs count as one entry but retain distinct ordinals.
    let original = fixture.commit(fixture.proposal(
        day(2026, 1, 10),
        b"explanation-original",
        EntryClass::ORIGINAL,
        vec![
            LegPayload::simple(Side::Debit, cash, Amount::new(usd, 600)),
            LegPayload::simple(Side::Debit, cash, Amount::new(usd, 400)),
            LegPayload::simple(Side::Credit, revenue, Amount::new(usd, 1_000)),
        ],
    ));
    let before_other = fixture.book.explain_balance(cash, JANUARY, None).unwrap();
    assert_eq!(before_other.cells[0].entry_count, 1);
    assert_eq!(before_other.contributions.len(), 2);
    let unrelated = fixture.transfer(
        day(2026, 1, 11),
        b"explanation-unrelated",
        usd,
        ("6000", "2000"),
        25,
    );
    let after_other = fixture.book.explain_balance(cash, JANUARY, None).unwrap();
    assert_eq!(after_other.contributions, before_other.contributions);
    assert_eq!(after_other.history, before_other.history);
    assert_ne!(after_other.fold_digest, before_other.fold_digest);
    assert_eq!(after_other.watermark, Some(unrelated.recorded_at()));

    let mut hold = fixture.proposal(
        day(2026, 1, 20),
        b"explanation-reservation",
        EntryClass::PENDING,
        fixture.legs(usd, ("6000", "1000"), 200),
    );
    hold.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    let hold = fixture.commit(hold);
    let held_at = hold.recorded_at();
    // A legless release in another effective period still changes January's
    // historical pending column and whole-period watermark.
    let mut release = fixture.proposal(
        day(2026, 2, 10),
        b"explanation-release",
        EntryClass::RESOLUTION,
        Vec::new(),
    );
    release.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: Some(hold.entry_ref()),
        disposition: Some(Disposition::Voids),
    });
    release.control = Some(fa_model::ControlPayload::ReservationRelease);
    let release = fixture.commit(release);
    let released_at = release.recorded_at();
    let reversed = reverse(&mut fixture, original.entry_ref());
    let reversed_at = reversed.recorded_at();
    let later = fixture.transfer(
        day(2026, 1, 1),
        b"explanation-later-backdated",
        usd,
        ("1000", "4000"),
        900,
    );

    let mut final_fold = None;
    for (at, released, reversed_present) in [
        (held_at, false, false),
        (released_at, true, false),
        (reversed_at, true, true),
    ] {
        let certified = fixture
            .book
            .certify_report(chosen(&fixture.book, "1000"), Some(at))
            .unwrap()
            .unwrap();
        let ReportOutput::ExplainBalance(native) = &certified.report else {
            panic!("explanation selector");
        };
        assert_eq!(native.account_row.code, "1000");
        assert_eq!(native.cells[0].debits, 1_000);
        assert_eq!(
            native.cells[0].credits,
            if reversed_present { 1_000 } else { 0 }
        );
        assert_eq!(
            native.cells[0].entry_count,
            if reversed_present { 2 } else { 1 }
        );
        assert_eq!(
            native.contributions.len(),
            if reversed_present { 5 } else { 3 }
        );
        assert!(
            !native
                .contributions
                .iter()
                .any(|row| row.entry == later.entry_ref().vid)
        );
        let reservation = native
            .contributions
            .iter()
            .find(|row| row.entry == hold.entry_ref().vid)
            .unwrap();
        assert_eq!(reservation.ordinal, 1);
        assert_eq!(reservation.recorded_at, held_at);
        assert_eq!(reservation.visible_at, held_at);
        assert_eq!(
            reservation.column,
            if released {
                fa_registers::explain::Column::Released
            } else {
                fa_registers::explain::Column::Pending
            },
        );
        assert_eq!(reservation.released_at, released.then_some(released_at));
        assert_eq!(native.pending.len(), usize::from(!released));
        let release_point = native
            .history
            .iter()
            .find(|point| point.recorded_at == released_at);
        assert_eq!(release_point.is_some(), released);
        if let Some(point) = release_point {
            assert_eq!(point.credits_pending, 0);
        }
        if at == released_at {
            assert_eq!(native.watermark, Some(released_at));
        }
        for contribution in &native.contributions {
            assert_eq!(contribution.evidence, fixture.evidence);
            if contribution.entry == reversed.entry_ref().vid {
                assert_eq!(contribution.supersedes.len(), 1);
                assert_eq!(contribution.supersedes[0].target, original.entry_ref());
                assert_eq!(contribution.supersedes[0].reason_code, 9);
            }
        }
        final_fold = Some(native.fold_digest);
        fixture
            .book
            .retain_certificate(&certified.certificate)
            .unwrap()
            .unwrap();
        let produced = produce(&mut fixture.book, &certified.certificate);
        verify(&fixture.book, &produced, &certified.certificate);
    }

    // An empty selected account still carries the authenticated whole-period
    // commitment, with no invented zero cells or contribution/history rows.
    let empty = fixture
        .book
        .certify_report(chosen(&fixture.book, "6100"), Some(reversed_at))
        .unwrap()
        .unwrap();
    let ReportOutput::ExplainBalance(native) = &empty.report else {
        panic!("explanation selector");
    };
    assert!(native.cells.is_empty() && native.pending.is_empty());
    assert!(native.contributions.is_empty() && native.history.is_empty());
    assert_eq!(Some(native.fold_digest), final_fold);
    assert_eq!(native.watermark, Some(reversed_at));
    fixture
        .book
        .retain_certificate(&empty.certificate)
        .unwrap()
        .unwrap();
    let produced = produce(&mut fixture.book, &empty.certificate);
    verify(&fixture.book, &produced, &empty.certificate);
}

#[test]
fn resealed_explanation_history_evidence_metadata_and_whole_period_forgery_are_refused() {
    let mut fixture = Fixture::new(0x86);
    let usd = fixture.usd;
    fixture.transfer(
        day(2026, 1, 10),
        b"explanation-forgery-source",
        usd,
        ("1000", "4000"),
        300,
    );
    let certified = fixture
        .book
        .certify_report(chosen(&fixture.book, "1000"), None)
        .unwrap()
        .unwrap();
    let ReportOutput::ExplainBalance(original) = certified.report else {
        panic!("explanation selector");
    };
    fixture
        .book
        .retain_certificate(&certified.certificate)
        .unwrap()
        .unwrap();
    let produced = produce(&mut fixture.book, &certified.certificate);
    verify(&fixture.book, &produced, &certified.certificate);
    for change in [
        "history",
        "evidence",
        "metadata",
        "whole-period",
        "missing-leg",
    ] {
        let mut report = original.clone();
        match change {
            "history" => report.history[0].debits += 1,
            "evidence" => report.contributions[0].evidence[0].doc_commit[0] ^= 1,
            "metadata" => report.account_row.name = "An invented historical label".into(),
            "whole-period" => report.fold_digest[0] ^= 1,
            "missing-leg" => {
                report.contributions.clear();
            }
            _ => unreachable!(),
        }
        let mut certificate = certified.certificate.clone();
        certificate.output = report.canonical_bytes().unwrap();
        reseal(&mut certificate);
        let forged = replace_certificate(&produced.bundle.bytes, &certificate);
        let error = fa_verify::report::verify_report_expected(
            &forged,
            &[fixture.book.checkpoint_public_key()],
            None,
            None,
            Some(&certificate.digest),
        )
        .unwrap_err();
        assert_eq!(error.predicate, "report_recomputation", "{change}: {error}");
    }
}

#[test]
fn explanation_export_requires_current_authority_and_the_original_retained_reason_epoch() {
    let mut fixture = Fixture::new(0x87);
    let certificate = fixture
        .book
        .certify_report(chosen(&fixture.book, "1000"), None)
        .unwrap()
        .unwrap()
        .certificate;
    let authority = Capability::embedded(PRINCIPAL, &["read", "produce", "witness"]).unwrap();
    fixture
        .book
        .checkpoint(PRINCIPAL, &authority)
        .unwrap()
        .unwrap();
    for operations in [&["read"][..], &["produce"][..]] {
        let limited = Capability::embedded(PRINCIPAL, operations).unwrap();
        let before = fixture.book.head().unwrap();
        assert!(
            fixture
                .book
                .produce_report_bundle(PRINCIPAL, &limited, None, &certificate)
                .unwrap()
                .is_err()
        );
        assert_eq!(fixture.book.head().unwrap(), before);
    }
    let before = fixture.book.head().unwrap();
    let refusal = fixture
        .book
        .produce_report_bundle(PRINCIPAL, &authority, None, &certificate)
        .unwrap()
        .unwrap_err();
    assert_eq!(
        refusal.code,
        fa::certificate::code::CERTIFICATE_REGISTRY_UNAVAILABLE
    );
    assert_eq!(
        fixture.book.head().unwrap(),
        before,
        "a missing reason archive is never repaired by export"
    );
    fixture
        .book
        .retain_certificate(&certificate)
        .unwrap()
        .unwrap();
    let produced = produce(&mut fixture.book, &certificate);
    verify(&fixture.book, &produced, &certificate);
}
