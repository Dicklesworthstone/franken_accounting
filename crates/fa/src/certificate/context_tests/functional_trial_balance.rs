//! The v10 report is built from actual retained Rate evidence and native folds.

use super::*;
use crate::{
    FUNCTIONAL_TRIAL_BALANCE_CERTIFICATE_FORMAT, FUNCTIONAL_TRIAL_BALANCE_OUTPUT_FORMAT,
    FunctionalTrialBalance, ReportSelection, TrialBalanceSelection,
};

fn activity() -> TrialBalanceSelection {
    TrialBalanceSelection::Activity(vec![PERIOD.into()])
}

fn certify(h: &mut Harness, selection: TrialBalanceSelection) -> CertifiedReport {
    let cx = h.cx();
    h.runtime
        .block_on(h.book.certify_functional_trial_balance(
            &cx,
            &cap(&["read", "produce"]),
            selection,
            None,
        ))
        .unwrap()
        .unwrap()
}

fn output(report: &ReportOutput) -> &FunctionalTrialBalance {
    let ReportOutput::FunctionalTrialBalance(report) = report else {
        panic!("expected a functional trial balance");
    };
    report
}

#[test]
fn stock_and_activity_certificates_preserve_exact_cells_chart_and_native_rate_witnesses() {
    let (mut h, rate) = fixture();
    let at = h.head();
    for selection in [
        activity(),
        TrialBalanceSelection::Periods(vec![PERIOD.into()]),
        TrialBalanceSelection::AsOf(day()),
    ] {
        let certified = certify(&mut h, selection.clone());
        assert_eq!(h.head(), at, "certification itself does not append");
        let report = output(&certified.report);
        assert_eq!(report.selection, selection);
        assert_eq!(report.known_at, at);
        assert_eq!(report.base_unit, rate.base_unit);
        assert_eq!(report.total_debits().unwrap(), 25_050);
        assert_eq!(report.total_credits().unwrap(), 25_050);
        assert_eq!(report.cells.len(), 2);
        assert!(report.pending.is_empty());
        assert_eq!(report.accounts.len(), 2);
        assert!(report.cells.iter().all(|cell| {
            cell.unit_id == rate.base_unit.0
                && report
                    .accounts
                    .get(&cell.account)
                    .is_some_and(|account| account.vid == cell.account && account.created_at <= at)
        }));
        match selection {
            TrialBalanceSelection::Activity(_) => {
                assert_eq!(report.effective_through, None);
                let fold = fa_registers::fold_period_functional(
                    &h.book.db,
                    h.book.context(),
                    PERIOD,
                    Some(at),
                )
                .unwrap();
                assert_eq!(report.fold_digest, fold.fold_digest);
                assert_eq!(report.watermark, fold.watermark);
                assert_eq!(report.entries, fold.entries);
            }
            TrialBalanceSelection::Periods(_) => {
                assert_eq!(
                    report.effective_through,
                    Some(DateDay::from_ymd(2026, 1, 31).unwrap())
                );
            }
            TrialBalanceSelection::AsOf(date) => assert_eq!(report.effective_through, Some(date)),
        }
        let certificate = &certified.certificate;
        assert_eq!(certificate.inputs.len(), 8);
        assert!(
            certificate.inputs[7]
                .statement
                .contains("WHERE n.code = 'Rate'")
        );
        assert_eq!(
            certificate.output_format(),
            FUNCTIONAL_TRIAL_BALANCE_OUTPUT_FORMAT
        );
        assert_eq!(
            crate::certificate::report_registries(&certificate.selection)
                .iter()
                .map(|(name, _)| *name)
                .collect::<Vec<_>>(),
            [
                "account_types",
                "entry_classes",
                "units",
                "foundations",
                "fx_laws",
                "rounding_laws"
            ]
        );
        let bytes = certificate.canonical_bytes().unwrap();
        assert!(bytes.starts_with(FUNCTIONAL_TRIAL_BALANCE_CERTIFICATE_FORMAT));
        assert!(
            certificate
                .output
                .starts_with(FUNCTIONAL_TRIAL_BALANCE_OUTPUT_FORMAT.as_bytes())
        );
        let decoded = ReportCertificate::decode(&bytes).unwrap();
        assert_eq!(decoded, *certificate);
        assert_eq!(
            h.book.replay_report(&h.cx(), &decoded).unwrap().unwrap(),
            certified.report
        );
        assert_eq!(
            ReportArtifact::decode(&bytes).unwrap().family(),
            ReportArtifactFamily::Native
        );
    }
}

#[test]
fn v10_selectors_are_not_accepted_by_earlier_formats_or_as_native_unit_reports() {
    let selection = ReportSelection::FunctionalTrialBalance(activity());
    let mut writer = fa_model::Writer::new();
    selection.write(&mut writer).unwrap();
    let encoded = writer.finish().unwrap();
    assert_eq!(encoded[0], 8);
    let mut reader = fa_model::Reader::new(&encoded);
    assert_eq!(ReportSelection::read(&mut reader, 10).unwrap(), selection);
    reader.finish().unwrap();
    for version in 1..10 {
        assert!(ReportSelection::read(&mut fa_model::Reader::new(&encoded), version).is_err());
    }
    let (mut h, _) = fixture();
    let certified = certify(&mut h, activity());
    let mut native = certified.certificate.clone();
    native.selection = ReportSelection::TrialBalance(activity());
    reseal(&mut native);
    assert!(ReportCertificate::decode(&native.canonical_bytes().unwrap()).is_err());
    for invalid in [
        TrialBalanceSelection::Periods(Vec::new()),
        TrialBalanceSelection::Activity(vec![PERIOD.into(), "FY2026-P02".into()]),
    ] {
        assert!(!ReportSelection::FunctionalTrialBalance(invalid).is_canonical());
    }
}

#[test]
fn retained_functional_trial_balance_replays_after_later_rates_and_backdated_entries() {
    let (mut h, rate) = fixture();
    let certified = certify(&mut h, activity());
    let bytes = certified.certificate.canonical_bytes().unwrap();
    let cx = h.cx();
    let retained = h
        .runtime
        .block_on(h.book.retain_report_artifact(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &bytes,
            Some(&certified.certificate.digest),
        ))
        .unwrap()
        .unwrap();
    let stored = h
        .runtime
        .block_on(h.book.read_certificate(&cx, &retained.digest))
        .unwrap()
        .unwrap();
    assert_eq!(stored, certified.certificate);
    let mut next_rate = rate;
    next_rate.rate_num = 2;
    next_rate.source = "later rate cannot revalue committed amounts".into();
    let refusal = next_rate.canonical_bytes().unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-100", 2));
    assert!(refusal.message.contains("canonical reduced form"));
    // The intended later rate is 2/4: retain the same rational in the
    // canonical 1/2 representation required by the unchanged document law.
    next_rate.rate_num = 1;
    next_rate.rate_den = 2;
    let document = Document {
        book_id: BOOK,
        kind: RATE_DOCUMENT_KIND,
        mime: "application/vnd.fa.fx-rate".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: next_rate.canonical_bytes().unwrap(),
    };
    h.runtime
        .block_on(h.book.add_document(&cx, &document))
        .unwrap()
        .unwrap();
    assert_eq!(
        h.book.replay_report(&cx, &stored).unwrap().unwrap(),
        certified.report
    );
    assert!(matches!(
        h.book.certificate_status(&cx, &stored).unwrap().unwrap(),
        CertificateStatus::Current { .. }
    ));
    let mut proposal = original(&h);
    proposal.idempotency_key = b"functional-tb-backdated".to_vec();
    proposal.origin = EntryOrigin::Intent {
        intent_oid: Oid([0x78; 32]),
        intent_kind: 1,
    };
    for leg in &mut proposal.legs {
        leg.amount.mantissa = 100;
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    let posted = h
        .runtime
        .block_on(h.book.post(
            &cx,
            PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(&["post"]),
            },
        ))
        .unwrap()
        .unwrap();
    assert_eq!(
        h.book.replay_report(&cx, &stored).unwrap().unwrap(),
        certified.report
    );
    assert_eq!(
        h.book.certificate_status(&cx, &stored).unwrap().unwrap(),
        CertificateStatus::SupersededBy {
            checked_at: posted.recorded_at(),
            later_entries: vec![posted.entry_ref().vid],
            cases: Vec::new(),
        }
    );
}

#[test]
fn functional_trial_balance_rejects_resealed_amount_entity_metadata_and_missing_rate_input() {
    let (mut h, _) = fixture();
    let certified = certify(&mut h, activity());
    for alteration in 0..4 {
        let mut report = output(&certified.report).clone();
        match alteration {
            0 => report.cells[0].debits += 1,
            1 => report.cells[0].entity = Some("invented-entity".into()),
            2 => report.accounts.values_mut().next().unwrap().name = "invented chart name".into(),
            _ => report.watermark = None,
        }
        let mut altered = certified.certificate.clone();
        altered.output = report.canonical_bytes().unwrap();
        reseal(&mut altered);
        ReportCertificate::decode(&altered.canonical_bytes().unwrap()).unwrap();
        let refusal = h
            .book
            .replay_report(&h.cx(), &altered)
            .unwrap()
            .unwrap_err();
        assert!(
            refusal
                .message
                .contains("differs from its certified output"),
            "{refusal:?}"
        );
    }
    let mut missing = certified.certificate.clone();
    missing.inputs.pop();
    reseal(&mut missing);
    assert!(ReportCertificate::decode(&missing.canonical_bytes().unwrap()).is_err());
    let mut wrong_laws = certified.certificate;
    wrong_laws.registry_digest = wrong_laws.legacy_v2_registry_closure();
    reseal(&mut wrong_laws);
    assert_eq!(
        h.book
            .replay_report(&h.cx(), &wrong_laws)
            .unwrap()
            .unwrap_err()
            .code,
        crate::certificate::code::CERTIFICATE_REGISTRY_UNAVAILABLE
    );
}

#[test]
fn functional_trial_balance_certification_requires_produce_before_history_or_append() {
    let (mut h, _) = fixture();
    let before = h.head();
    let cx = h.cx();
    for capability in [cap(&["read"]), cap(&["produce"])] {
        let refusal = h
            .runtime
            .block_on(h.book.certify_functional_trial_balance(
                &cx,
                &capability,
                activity(),
                Some(before),
            ))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, fa_journal::refusal::code::CAPABILITY);
        assert_eq!(h.head(), before);
    }
    assert!(
        h.runtime
            .block_on(h.book.functional_trial_balance(
                &cx,
                &cap(&["read"]),
                activity(),
                Some(before),
            ))
            .unwrap()
            .is_ok()
    );
    assert_eq!(h.head(), before);
    certify(&mut h, activity());
    assert_eq!(h.head(), before);
}

#[test]
fn uncertified_functional_read_stays_available_but_certificate_refuses_rewritten_rate() {
    let (mut h, rate) = fixture();
    let certified = certify(&mut h, activity());
    let rate_vid = fa_journal::evidence::document_vid(&rate.oid(BOOK).unwrap());
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.set_vertex_property(
        rate_vid,
        property::CODE,
        Some(fa_journal::rows::scalar_text("changed rate kind", "Invoice").unwrap()),
    );
    let cx = h.cx();
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), batch))
        .unwrap();
    let report = h
        .runtime
        .block_on(
            h.book
                .functional_trial_balance(&cx, &cap(&["read"]), activity(), None),
        )
        .unwrap()
        .unwrap();
    assert_eq!(report.total_debits().unwrap(), 25_050);
    let refusal = h
        .runtime
        .block_on(h.book.certify_functional_trial_balance(
            &cx,
            &cap(&["read", "produce"]),
            activity(),
            None,
        ))
        .unwrap()
        .unwrap_err();
    assert!(refusal.message.contains("Rate"), "{refusal:?}");
    assert!(
        h.book
            .replay_report(&cx, &certified.certificate)
            .unwrap()
            .is_err()
    );
}

#[test]
fn instant_selected_functional_trial_balance_retains_original_time_brackets() {
    let (mut h, _) = fixture();
    let cx = h.cx();
    let lower = 1_768_435_200_000_000_000;
    h.runtime
        .block_on(h.book.record_tick(&cx, lower, true, &cap(&["witness"])))
        .unwrap()
        .unwrap();
    let at = h.head();
    h.runtime
        .block_on(
            h.book
                .record_tick(&cx, lower + 10, true, &cap(&["witness"])),
        )
        .unwrap()
        .unwrap();
    let certified = h
        .runtime
        .block_on(h.book.certify_functional_trial_balance_at_instant(
            &cx,
            &cap(&["read", "produce"]),
            activity(),
            lower + 1,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(certified.certificate.known_at, at);
    let time = certified.certificate.time_selection.as_ref().unwrap();
    assert_eq!(time.resolution.resolved_seq, at.0);
    let decoded =
        ReportCertificate::decode(&certified.certificate.canonical_bytes().unwrap()).unwrap();
    assert_eq!(decoded, certified.certificate);
    assert_eq!(
        h.book.replay_report(&cx, &decoded).unwrap().unwrap(),
        certified.report
    );
}

#[test]
fn functional_stock_carries_prior_periods_while_activity_and_empty_cutoffs_do_not() {
    let (mut h, _) = fixture();
    let january = certify(&mut h, activity());
    let cx = h.cx();
    h.runtime
        .block_on(h.book.transition_period(
            &cx,
            "FY2026-P02",
            PeriodTransition::Open,
            PRINCIPAL,
            1,
            b"functional-tb-february-open",
            &cap(&["close"]),
        ))
        .unwrap()
        .unwrap();
    let mut proposal = original(&h);
    proposal.effective_date = DateDay::from_ymd(2026, 2, 5).unwrap();
    proposal.idempotency_key = b"functional-tb-february-post".to_vec();
    proposal.origin = EntryOrigin::Intent {
        intent_oid: Oid([0x79; 32]),
        intent_kind: 1,
    };
    for leg in &mut proposal.legs {
        leg.amount.mantissa = 100;
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    h.runtime
        .block_on(h.book.post(
            &cx,
            PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(&["post"]),
            },
        ))
        .unwrap()
        .unwrap();
    assert!(matches!(
        h.book
            .certificate_status(&cx, &january.certificate)
            .unwrap()
            .unwrap(),
        CertificateStatus::Current { .. }
    ));
    let stock = certify(
        &mut h,
        TrialBalanceSelection::Periods(vec!["FY2026-P02".into()]),
    );
    let february = certify(
        &mut h,
        TrialBalanceSelection::Activity(vec!["FY2026-P02".into()]),
    );
    assert_eq!(output(&stock.report).total_debits().unwrap(), 25_150);
    assert_eq!(output(&february.report).total_debits().unwrap(), 100);
    assert_ne!(
        output(&stock.report).fold_digest,
        output(&february.report).fold_digest
    );
    let empty = certify(
        &mut h,
        TrialBalanceSelection::AsOf(DateDay::from_ymd(2026, 1, 1).unwrap()),
    );
    assert!(output(&empty.report).cells.is_empty());
    assert!(output(&empty.report).accounts.is_empty());
    assert_eq!(output(&empty.report).watermark, None);
    assert_eq!(output(&empty.report).entries, 0);
    assert_eq!(
        h.book
            .replay_report(&cx, &empty.certificate)
            .unwrap()
            .unwrap(),
        empty.report
    );
}

#[test]
fn functional_trial_balance_retains_pending_cells_and_detects_cross_period_releases() {
    let (mut h, _) = fixture();
    let mut pending = original(&h);
    pending.class = EntryClass::PENDING;
    pending.idempotency_key = b"functional-tb-held".to_vec();
    pending.origin = EntryOrigin::Intent {
        intent_oid: Oid([0x7a; 32]),
        intent_kind: 1,
    };
    for leg in &mut pending.legs {
        leg.amount.mantissa = 100;
    }
    pending.unit_totals = EntryPayload::fold_unit_totals(&pending.legs).unwrap();
    pending.pending = Some(fa_model::Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    let cx = h.cx();
    let held = h
        .runtime
        .block_on(h.book.post(
            &cx,
            PostRequest {
                proposal: pending.clone(),
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(&["post"]),
            },
        ))
        .unwrap()
        .unwrap()
        .entry_ref();
    let certificates = [
        certify(&mut h, activity()),
        certify(&mut h, TrialBalanceSelection::AsOf(day())),
    ];
    for certified in &certificates {
        let report = output(&certified.report);
        assert_eq!(report.total_debits().unwrap(), 25_050);
        assert_eq!(report.pending.len(), 2);
        assert_eq!(
            report.pending.iter().map(|cell| cell.debits).sum::<i128>(),
            100
        );
        assert_eq!(
            report.pending.iter().map(|cell| cell.credits).sum::<i128>(),
            100
        );
    }
    let mut release = pending;
    release.class = EntryClass::RESOLUTION;
    release.effective_date = DateDay::from_ymd(2026, 2, 5).unwrap();
    release.idempotency_key = b"functional-tb-released".to_vec();
    release.legs.clear();
    release.unit_totals.clear();
    release.control = Some(fa_model::ControlPayload::ReservationRelease);
    release.pending = Some(fa_model::Pending {
        timeout_ns: None,
        resolution_of: Some(held),
        disposition: Some(fa_model::Disposition::Voids),
    });
    let before_refusal = h.head();
    let refused = h
        .runtime
        .block_on(h.book.post(
            &cx,
            PostRequest {
                proposal: release.clone(),
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(&["post"]),
            },
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!((refused.code, refused.exit), ("FA-REF-010", 7));
    assert_eq!(h.head(), before_refusal);
    h.runtime
        .block_on(h.book.transition_period(
            &cx,
            "FY2026-P02",
            PeriodTransition::Open,
            PRINCIPAL,
            1,
            b"functional-tb-release-february-open",
            &cap(&["close"]),
        ))
        .unwrap()
        .unwrap();
    let posted = h
        .runtime
        .block_on(h.book.post(
            &cx,
            PostRequest {
                proposal: release,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(&["post"]),
            },
        ))
        .unwrap()
        .unwrap();
    for certified in certificates {
        assert_eq!(
            h.book
                .replay_report(&cx, &certified.certificate)
                .unwrap()
                .unwrap(),
            certified.report
        );
        assert_eq!(
            h.book
                .certificate_status(&cx, &certified.certificate)
                .unwrap()
                .unwrap(),
            CertificateStatus::SupersededBy {
                checked_at: posted.recorded_at(),
                later_entries: vec![posted.entry_ref().vid],
                cases: Vec::new(),
            }
        );
        let current = certify(&mut h, output(&certified.report).selection.clone());
        assert!(output(&current.report).pending.is_empty());
        assert_eq!(output(&current.report).total_debits().unwrap(), 25_050);
    }
}

#[test]
fn functional_trial_balance_refuses_forged_chart_mirrors_but_keeps_the_historical_display() {
    for (field, value) in [
        (
            property::CODE,
            fa_journal::rows::scalar_text("forged code", "FAKE").unwrap(),
        ),
        (
            property::NAME,
            fa_journal::rows::scalar_text("forged name", "Forged cash").unwrap(),
        ),
        (
            property::ACCOUNT_TYPE,
            CanonicalScalar::Int(i64::from(AccountType::LIABILITY.0)),
        ),
    ] {
        let (mut h, _) = fixture();
        let certified = certify(&mut h, activity());
        let original_at = certified.certificate.known_at;
        let account = account_vid(BOOK, "1000");
        let mut batch = WriteBatch::new(relation::IN_BOOK);
        batch.set_vertex_property(account, field, Some(value));
        let cx = h.cx();
        h.runtime
            .block_on(h.book.db.write(&cx.commit(), batch))
            .unwrap();
        let poisoned_at = h.head();
        let plain_error = h
            .runtime
            .block_on(h.book.functional_trial_balance(
                &cx,
                &cap(&["read"]),
                activity(),
                Some(poisoned_at),
            ))
            .unwrap_err();
        assert!(
            plain_error.to_string().contains("immutable declaration"),
            "{plain_error:?}"
        );
        let certificate_error = h
            .runtime
            .block_on(h.book.certify_functional_trial_balance(
                &cx,
                &cap(&["read", "produce"]),
                activity(),
                Some(poisoned_at),
            ))
            .unwrap_err();
        assert!(
            certificate_error
                .to_string()
                .contains("immutable declaration"),
            "{certificate_error:?}"
        );
        assert_eq!(h.head(), poisoned_at, "neither refused read may append");
        let historical = h
            .runtime
            .block_on(h.book.functional_trial_balance(
                &cx,
                &cap(&["read"]),
                activity(),
                Some(original_at),
            ))
            .unwrap()
            .unwrap();
        assert_eq!(&historical, output(&certified.report));
        assert_eq!(
            h.book
                .replay_report(&cx, &certified.certificate)
                .unwrap()
                .unwrap(),
            certified.report
        );
    }
}
