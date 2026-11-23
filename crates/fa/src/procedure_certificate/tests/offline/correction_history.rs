//! Correction procedures must survive the dependency-free verifier boundary
//! with full historical lineage and journal-authenticated period state.

use super::*;
use fa_verify::report::{VerifiedProcedureParameters, VerifiedProcedureStatistic};

fn request(f: &Fixture, id: &str) -> ProcedureRequest {
    let mut request = ProcedureRequest::new(id, catalog::Inputs::default()).unwrap();
    request.known_at = Some(f.head());
    request
}

fn subsequent_request(f: &Fixture, minimum: i128, window: i128) -> ProcedureRequest {
    let mut request = request(f, "events.subsequent");
    request.parameters = request
        .parameters
        .set("min_amount", minimum)
        .unwrap()
        .set("window_days", window)
        .unwrap();
    request
}

fn export(f: &mut Fixture, certified: &CertifiedProcedure) -> crate::ProducedBundle {
    certified.certificate.check_offline_profile().unwrap();
    assert_eq!(
        f.book
            .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &certified.certificate)
            .unwrap()
            .unwrap(),
        certified.report
    );
    produce(f, &certified.certificate)
}

fn february(
    f: &mut Fixture,
    source: VId,
    key: &[u8],
    class: EntryClass,
    date: u8,
    amount: i128,
) -> VId {
    let mut proposal = template(f, source, key, 1);
    proposal.class = class;
    proposal.effective_date = DateDay::from_ymd(2026, 2, date).unwrap();
    for leg in &mut proposal.legs {
        leg.amount.mantissa = amount;
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    post(f, proposal)
}

fn february_reversal(f: &mut Fixture, source: VId, key: &[u8], date: u8) -> VId {
    let mut proposal = reversal(f, source, key, 1);
    proposal.effective_date = DateDay::from_ymd(2026, 2, date).unwrap();
    post(f, proposal)
}

#[test]
fn reversal_patterns_export_complete_chains_cross_period_and_historical_results() {
    let mut f = Fixture::new(170);
    let (source, _) = f.post(2, "3000", "1000", 100_000, false);
    let undone = reverse(&mut f, source, b"patterns-first-reversal", 3);
    let unchained = f.certify(&request(&f, "reversal.patterns"));
    assert!(unchained.report.findings.is_empty());
    let restored = reverse(&mut f, undone, b"patterns-reversal-of-reversal", 4);
    let chained = f.certify(&request(&f, "reversal.patterns"));
    assert_eq!(chained.report.findings.len(), 2);
    assert!(
        chained
            .report
            .findings
            .iter()
            .all(|finding| finding.severity == Severity::High)
    );
    assert!(chained.report.findings.iter().any(|finding| finding.cites
        == [
            Cite::Entry(undone),
            Cite::Entry(source),
            Cite::Entry(restored)
        ]));

    let (replacement_source, _) = f.post(5, "3000", "1000", 200_000, false);
    let (_, corrected) = replace(
        &mut f,
        replacement_source,
        b"patterns-replace",
        6,
        7,
        210_000,
    );
    let (correction_undo, correction_next) =
        replace(&mut f, corrected, b"patterns-replace-again", 8, 9, 220_000);
    // Original replacement identities require a later authenticated EntryRef
    // in portable closures, even when their predecessors already have one.
    pay_corrected(&mut f, correction_next);
    post_closing_transition(
        &mut f,
        "FY2026-P02",
        PeriodTransition::Open,
        b"patterns-open-february",
    );
    let (cross_source, _) = f.post(10, "3000", "1020", 300_000, false);
    let cross = february_reversal(&mut f, cross_source, b"patterns-cross-period", 1);
    let current = f.certify(&request(&f, "reversal.patterns"));
    assert!(current.report.findings.iter().any(|finding| {
        finding.cites
            == [
                Cite::Entry(corrected),
                Cite::Entry(replacement_source),
                Cite::Entry(correction_undo.min(correction_next)),
            ]
    }));
    assert!(current.report.findings.iter().any(|finding| {
        finding.cites == [Cite::Entry(cross), Cite::Entry(cross_source)]
            && finding.severity == Severity::Medium
    }));
    let key = f.book.checkpoint_public_key();
    let artifacts: Vec<_> = [unchained, chained, current]
        .into_iter()
        .map(|certified| {
            let produced = export(&mut f, &certified);
            (certified, produced)
        })
        .collect();
    drop(f);
    for (certified, produced) in artifacts {
        let verified = verify(&produced, &certified.certificate, key);
        let replay = verified.procedure.unwrap();
        assert_eq!(
            replay.parameters,
            VerifiedProcedureParameters::ReversalPatterns
        );
        assert_eq!(
            (replay.live_entries, replay.live_legs, replay.comparisons),
            (
                certified.report.work.entries,
                0,
                certified.report.work.comparisons
            )
        );
        assert!(replay.findings.iter().all(|finding| matches!(
            finding.statistic,
            VerifiedProcedureStatistic::ReversalChainEntries { .. }
        )));
    }
}

#[test]
fn subsequent_events_export_latest_close_reopen_lineage_and_exact_window() {
    let mut f = Fixture::new(171);
    let (source, _) = f.post(2, "3000", "1000", 100_000, false);
    post_closing_transition(
        &mut f,
        "FY2026-P02",
        PeriodTransition::Open,
        b"subsequent-open-february",
    );
    let first_day = february(
        &mut f,
        source,
        b"subsequent-first-day",
        EntryClass::ADJUSTING,
        1,
        100_000,
    );
    let last_day = february(
        &mut f,
        source,
        b"subsequent-last-day",
        EntryClass::ADJUSTING,
        2,
        100_000,
    );
    february(
        &mut f,
        source,
        b"subsequent-outside-window",
        EntryClass::ADJUSTING,
        3,
        100_000,
    );
    february(
        &mut f,
        source,
        b"subsequent-below-minimum",
        EntryClass::ADJUSTING,
        1,
        99_999,
    );
    february(
        &mut f,
        source,
        b"subsequent-ordinary-original",
        EntryClass::ORIGINAL,
        1,
        200_000,
    );
    let open = f.certify(&subsequent_request(&f, 100_000, 2));
    assert!(
        open.report.findings.is_empty(),
        "opening a period is not closing it"
    );
    post_closing_transition(
        &mut f,
        "FY2026-P01",
        PeriodTransition::SoftClose,
        b"subsequent-first-close",
    );
    let closed = f.certify(&subsequent_request(&f, 100_000, 2));
    assert_eq!(closed.report.findings.len(), 2);
    for (identity, days) in [(first_day, 1), (last_day, 2)] {
        assert!(closed.report.findings.iter().any(|finding| {
            finding.cites
                == [
                    Cite::Entry(identity),
                    Cite::Period("FY2026-P02".into()),
                    Cite::Period("FY2026-P01".into()),
                ]
                && finding.narrative.contains(&format!("({days} day(s)"))
        }));
    }
    post_closing_transition(
        &mut f,
        "FY2026-P01",
        PeriodTransition::Reopen {
            to: fa_time::PeriodState::Open,
        },
        b"subsequent-reopen",
    );
    let reopened = f.certify(&subsequent_request(&f, 100_000, 2));
    assert!(
        reopened.report.findings.is_empty(),
        "latest state removes the closed boundary"
    );
    let undo = february_reversal(&mut f, source, b"subsequent-lineage-after-reopen", 2);
    let lineage = f.certify(&subsequent_request(&f, 100_000, 2));
    assert_eq!(lineage.report.findings.len(), 1);
    assert_eq!(
        lineage.report.findings[0].cites,
        [
            Cite::Entry(undo),
            Cite::Period("FY2026-P02".into()),
            Cite::Period("FY2026-P01".into()),
            Cite::Entry(source)
        ]
    );
    let high_threshold = f.certify(&subsequent_request(&f, i128::MAX, 2));
    assert!(high_threshold.report.findings.is_empty());
    post_closing_transition(
        &mut f,
        "FY2026-P01",
        PeriodTransition::SoftClose,
        b"subsequent-close-again",
    );
    let reclosed = f.certify(&subsequent_request(&f, 100_000, 2));
    assert_eq!(reclosed.report.findings.len(), 3);
    let key = f.book.checkpoint_public_key();
    let artifacts: Vec<_> = [open, closed, reopened, lineage, high_threshold, reclosed]
        .into_iter()
        .map(|certified| {
            let produced = export(&mut f, &certified);
            (certified, produced)
        })
        .collect();
    drop(f);
    for (certified, produced) in artifacts {
        let verified = verify(&produced, &certified.certificate, key);
        let replay = verified.procedure.unwrap();
        assert!(matches!(
            replay.parameters,
            VerifiedProcedureParameters::SubsequentEvents { window_days: 2, .. }
        ));
        assert_eq!(
            (replay.live_entries, replay.live_legs, replay.comparisons),
            (
                certified.report.work.entries,
                certified.report.work.legs,
                certified.report.work.comparisons
            )
        );
        assert!(replay.findings.iter().all(|finding| matches!(
            finding.statistic,
            VerifiedProcedureStatistic::SubsequentEventAmount {
                scale: 2,
                mantissa: 100_000,
                ..
            }
        )));
    }
}

#[test]
fn correction_history_rejects_resealed_missing_altered_and_extra_findings() {
    let mut f = Fixture::new(172);
    let (source, _) = f.post(2, "3000", "1000", 100_000, false);
    post_closing_transition(
        &mut f,
        "FY2026-P02",
        PeriodTransition::Open,
        b"correction-tamper-open-february",
    );
    february_reversal(&mut f, source, b"correction-tamper-lineage", 2);
    let key = f.book.checkpoint_public_key();
    for id in ["reversal.patterns", "events.subsequent"] {
        let certified = f.certify(&request(&f, id));
        assert_eq!(certified.report.findings.len(), 1);
        let produced = export(&mut f, &certified);
        verify(&produced, &certified.certificate, key);
        for variant in [
            "amount",
            "population",
            "severity",
            "entry",
            "omitted",
            "extra",
            "comparisons",
            "legs",
            "entries",
            "narrative",
        ] {
            let mut forged = certified.certificate.clone();
            let report = &mut forged.report;
            match variant {
                "amount" => report.findings[0].statistic.value += 1,
                "population" => report.findings[0].statistic.population += 1,
                "severity" => report.findings[0].severity = Severity::Low,
                "entry" => report.findings[0].cites[0] = Cite::Entry(source),
                "omitted" => report.findings.clear(),
                "extra" => report.findings.push(report.findings[0].clone()),
                "comparisons" => report.work.comparisons += 1,
                "legs" => report.work.legs += 1,
                "entries" => report.work.entries += 1,
                "narrative" => report.findings[0].narrative.push_str(" altered"),
                _ => unreachable!(),
            }
            reseal(&mut forged);
            let changed = replace_certificate(&produced.bundle.bytes, &forged);
            assert_eq!(
                verify_report_expected(&changed, &[key], None, None, Some(forged.digest()))
                    .unwrap_err()
                    .predicate,
                "procedure_recomputation",
                "{id}: {variant}"
            );
        }
        if id == "events.subsequent" {
            for variant in ["prior_period", "original", "window", "minimum"] {
                let mut forged = certified.certificate.clone();
                match variant {
                    "prior_period" => {
                        forged.report.findings[0].cites[2] = Cite::Period("FY2026-P03".into())
                    }
                    "original" => {
                        forged.report.findings[0].cites.pop();
                    }
                    "window" => forged.report.parameters[1].1 = 1,
                    "minimum" => forged.report.parameters[0].1 = 100_001,
                    _ => unreachable!(),
                }
                reseal(&mut forged);
                let changed = replace_certificate(&produced.bundle.bytes, &forged);
                assert_eq!(
                    verify_report_expected(&changed, &[key], None, None, Some(forged.digest()))
                        .unwrap_err()
                        .predicate,
                    "procedure_recomputation",
                    "{id}: {variant}"
                );
            }
        }
        let variants: &[&str] = if id == "events.subsequent" {
            &[
                "version",
                "cutoff",
                "handle",
                "negative_minimum",
                "zero_window",
                "wide_window",
            ]
        } else {
            &["version", "cutoff", "handle", "unexpected_parameter"]
        };
        for &variant in variants {
            let mut forged = certified.certificate.clone();
            match variant {
                "version" => change_report_version(&mut forged, 1),
                "cutoff" => forged.report.coordinate.effective_through = Some(day(31)),
                "handle" => forged.report.inputs.push(("account".into(), "1000".into())),
                "negative_minimum" => forged.report.parameters[0].1 = -1,
                "zero_window" => forged.report.parameters[1].1 = 0,
                "wide_window" => forged.report.parameters[1].1 = i128::from(u32::MAX) + 1,
                "unexpected_parameter" => forged.report.parameters.push(("window_days".into(), 30)),
                _ => unreachable!(),
            }
            assert_eq!(
                forged.check_offline_profile().unwrap_err().code,
                fa_notary::code::SCOPE_UNSUPPORTED
            );
            reseal(&mut forged);
            let changed = replace_certificate(&produced.bundle.bytes, &forged);
            assert_eq!(
                verify_report_expected(&changed, &[key], None, None, Some(forged.digest()))
                    .unwrap_err()
                    .predicate,
                if variant == "handle" {
                    "canonical_encoding"
                } else {
                    "procedure_profile"
                },
                "{id}: {variant}"
            );
        }
    }
}
