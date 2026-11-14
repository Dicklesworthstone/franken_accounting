//! Ordered tracing is recomputed from the complete authenticated history,
//! independently of both the producer's result and its public commitments.

use super::*;

fn population(seed: u8) -> (Fixture, VId, VId) {
    let mut f = Fixture::new(seed);
    f.post(1, "3000", "1000", 20, false);
    let (source, _) = f.post(2, "3000", "1000", 100, false);
    let (withdrawal, _) = f.post(2, "1000", "6000", 90, false);
    let (clean, _) = f.post(2, "3000", "1000", 70, false);
    f.post(3, "1000", "6000", 200, false);
    reverse(&mut f, withdrawal, b"ordered-later-effective-reversal", 4);
    (f, source, clean)
}

fn request(f: &Fixture, id: &str, source: VId, order: i128) -> ProcedureRequest {
    let mut request = f.request(id, source);
    request.version = Some(2);
    request.effective_through = Some(day(2));
    request.parameters = request.parameters.set("intraday_order", order).unwrap();
    request
}

#[test]
fn ordered_tracing_replays_each_law_and_intraday_order_from_authenticated_records() {
    let (mut f, source, _) = population(235);
    // Opening 20, source 100, withdrawal 90, later clean deposit 70.
    // WithdrawalsFirst repays an overdraft before either source can be held;
    // DepositsFirst places the new clean money above the source for LIFO.
    for (id, evidence, order, expected) in [
        ("trace.fifo", "FA-EVID-L16", 0, 30),
        ("trace.fifo", "FA-EVID-L16", 2, 30),
        ("trace.fifo", "FA-EVID-L16", 3, 30),
        ("trace.lifo", "FA-EVID-L17", 0, 10),
        ("trace.lifo", "FA-EVID-L17", 2, 30),
        ("trace.lifo", "FA-EVID-L17", 3, 80),
    ] {
        let certified = f.certify(&request(&f, id, source, order));
        certified.certificate.check_offline_profile().unwrap();
        assert_eq!(certified.report.procedure, id);
        assert_eq!(certified.report.evidence, evidence);
        assert_eq!(certified.report.findings.len(), 1);
        let finding = &certified.report.findings[0];
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.statistic.name, "traced_mantissa");
        assert_eq!(
            (
                finding.statistic.value,
                finding.statistic.scale,
                finding.statistic.population
            ),
            (expected, 2, 4)
        );
        let produced = produce(&mut f, &certified.certificate);
        let verified = verify(
            &produced,
            &certified.certificate,
            f.book.checkpoint_public_key(),
        );
        assert_eq!(decode_run(&verified.output).unwrap(), certified.report);
        let independent = verified.procedure.unwrap();
        assert_eq!(independent.procedure, id);
        assert_eq!(
            (
                independent.live_entries,
                independent.live_legs,
                independent.comparisons
            ),
            (4, 3, 8)
        );
        let fa_verify::report::VerifiedProcedureStatistic::TracedAmount {
            account,
            unit,
            mantissa,
            scale,
            entries,
        } = &independent.findings[0].statistic
        else {
            panic!("independent native-unit tracing result");
        };
        assert_eq!(
            (*account, *unit, *mantissa, *scale),
            (f.id("1000").0, f.unit.0, expected, 2)
        );
        assert_eq!(
            *entries,
            finding
                .cites
                .iter()
                .filter_map(|cite| match cite {
                    Cite::Entry(entry) => Some(entry.0),
                    _ => None,
                })
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn ordered_tracing_rejects_resealed_wrong_laws_questions_and_results() {
    let (mut f, source, clean) = population(236);
    for id in ["trace.fifo", "trace.lifo"] {
        let certified = f.certify(&request(&f, id, source, 0));
        let produced = produce(&mut f, &certified.certificate);
        let key = f.book.checkpoint_public_key();
        verify(&produced, &certified.certificate, key);
        for variant in [
            "law",
            "amount",
            "scale",
            "population",
            "work",
            "citation",
            "narrative",
            "source",
            "cutoff",
            "order",
        ] {
            let mut forged = certified.certificate.clone();
            let run = &mut forged.report;
            match variant {
                "law" => {
                    let (other, evidence) = if id == "trace.fifo" {
                        ("trace.lifo", "FA-EVID-L17")
                    } else {
                        ("trace.fifo", "FA-EVID-L16")
                    };
                    run.procedure = other.into();
                    run.evidence = evidence.into();
                    for finding in &mut run.findings {
                        finding.procedure = other.into();
                    }
                }
                "amount" => run.findings[0].statistic.value += 1,
                "scale" => run.findings[0].statistic.scale = 0,
                "population" => run.findings[0].statistic.population += 1,
                "work" => run.work.legs += 1,
                "citation" => {
                    run.findings[0].cites.pop();
                }
                "narrative" => run.findings[0].narrative.push_str(" altered"),
                "source" => run.inputs[1].1 = format!("{:032x}", clean.0),
                "cutoff" => run.coordinate.effective_through = Some(day(3)),
                "order" => run.parameters[0].1 = 2,
                _ => unreachable!(),
            }
            forged.check_offline_profile().unwrap();
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
}

#[test]
fn ordered_tracing_rejects_unsupported_versions_orders_and_extra_parameters() {
    let (f, source, _) = population(237);
    for id in ["trace.fifo", "trace.lifo"] {
        let certified = f.certify(&request(&f, id, source, 0));
        for variant in [
            "old version",
            "missing cutoff",
            "reserved order",
            "replenishment",
            "missing source",
            "short account",
        ] {
            let mut changed = certified.certificate.clone();
            let run = &mut changed.report;
            match variant {
                "old version" => run.version = 1,
                "missing cutoff" => run.coordinate.effective_through = None,
                "reserved order" => run.parameters[0].1 = 1,
                "replenishment" => run.parameters.push(("replenishment".into(), 0)),
                "missing source" => {
                    run.inputs.pop();
                }
                "short account" => run.inputs[0].1 = "1000".into(),
                _ => unreachable!(),
            }
            assert_eq!(
                changed.check_offline_profile().unwrap_err().code,
                fa_notary::code::SCOPE_UNSUPPORTED,
                "{id}: {variant}"
            );
        }
    }
}
