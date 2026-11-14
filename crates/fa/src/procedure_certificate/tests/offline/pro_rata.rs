//! Proportional tracing crosses the native/independent arithmetic boundary,
//! including products wider than i128 and source-first residual ties.

use super::*;

fn request(f: &Fixture, source: VId, order: i128, through: u8) -> ProcedureRequest {
    let mut request = f.request("trace.pro_rata", source);
    request.version = Some(2);
    request.effective_through = Some(day(through));
    request.parameters = request.parameters.set("intraday_order", order).unwrap();
    request
}

#[test]
fn pro_rata_tracing_exports_exact_shares_for_each_intraday_order() {
    let mut f = Fixture::new(238);
    f.post(1, "3000", "1000", 20, false);
    let (source, _) = f.post(2, "3000", "1000", 100, false);
    f.post(2, "1000", "6000", 90, false);
    f.post(2, "3000", "1000", 70, false);
    f.post(3, "1000", "6000", 200, false);
    for (order, expected) in [(0, 25), (2, 30), (3, 53)] {
        let certified = f.certify(&request(&f, source, order, 2));
        certified.certificate.check_offline_profile().unwrap();
        assert_eq!(certified.report.evidence, "FA-EVID-L18");
        assert_eq!(certified.report.findings.len(), 1);
        assert_eq!(certified.report.findings[0].statistic.value, expected);
        assert_eq!(certified.report.findings[0].statistic.population, 4);
        let produced = produce(&mut f, &certified.certificate);
        let verified = verify(
            &produced,
            &certified.certificate,
            f.book.checkpoint_public_key(),
        );
        assert_eq!(decode_run(&verified.output).unwrap(), certified.report);
        let independent = verified.procedure.unwrap();
        assert_eq!(independent.procedure, "trace.pro_rata");
        assert_eq!(independent.version, 2);
        assert_eq!(
            (
                independent.live_entries,
                independent.live_legs,
                independent.comparisons
            ),
            (4, 3, 8)
        );
        assert!(matches!(independent.findings[0].statistic,
            fa_verify::report::VerifiedProcedureStatistic::TracedAmount { mantissa, scale: 2, .. } if mantissa == expected));
    }
}

#[test]
fn pro_rata_tracing_verifies_full_width_products_and_exact_source_first_ties() {
    let mut f = Fixture::new(239);
    // Keep the complete native source's gross turnover representable too.
    // The 125-bit weights still require a 250-bit product during allocation.
    let half = i128::MAX / 4;
    f.post(1, "3000", "1000", half, false);
    let (source, _) = f.post(2, "3000", "1000", half, false);
    f.post(3, "1000", "6000", half, false);
    let certified = f.certify(&request(&f, source, 0, 3));
    // Equal tainted and clean pools split this odd withdrawal. The source
    // receives the residual unit, leaving floor(half / 2) traced. Computing
    // half * half in i128 would overflow before deriving this valid result.
    assert_eq!(certified.report.findings[0].statistic.value, half / 2);
    let produced = produce(&mut f, &certified.certificate);
    let verified = verify(
        &produced,
        &certified.certificate,
        f.book.checkpoint_public_key(),
    );
    assert_eq!(decode_run(&verified.output).unwrap(), certified.report);
    assert!(matches!(verified.procedure.unwrap().findings[0].statistic,
        fa_verify::report::VerifiedProcedureStatistic::TracedAmount { mantissa, .. } if mantissa == half / 2));
}

#[test]
fn pro_rata_tracing_refuses_resealed_wrong_shares_law_and_claim_date() {
    let mut f = Fixture::new(240);
    f.post(1, "3000", "1000", 20, false);
    let (source, _) = f.post(2, "3000", "1000", 100, false);
    f.post(2, "1000", "6000", 90, false);
    f.post(2, "3000", "1000", 70, false);
    f.post(3, "1000", "6000", 60, false);
    let certified = f.certify(&request(&f, source, 0, 2));
    let produced = produce(&mut f, &certified.certificate);
    let key = f.book.checkpoint_public_key();
    verify(&produced, &certified.certificate, key);
    for variant in ["share", "law", "cutoff", "order", "citation", "work"] {
        let mut forged = certified.certificate.clone();
        let run = &mut forged.report;
        match variant {
            "share" => run.findings[0].statistic.value += 1,
            "law" => {
                run.procedure = "trace.fifo".into();
                run.evidence = "FA-EVID-L16".into();
                run.findings[0].procedure = "trace.fifo".into();
            }
            "cutoff" => run.coordinate.effective_through = Some(day(3)),
            "order" => run.parameters[0].1 = 3,
            "citation" => {
                run.findings[0].cites.pop();
            }
            "work" => run.work.legs += 1,
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
            "{variant}"
        );
    }
    let mut unsupported = certified.certificate.clone();
    unsupported
        .report
        .parameters
        .push(("replenishment".into(), 1));
    assert_eq!(
        unsupported.check_offline_profile().unwrap_err().code,
        fa_notary::code::SCOPE_UNSUPPORTED
    );
}
