//! The registered tracing laws cross the public producer and independent
//! verifier boundary, including their authenticated source handles and facts.

use super::*;

fn population(seed: u8) -> (Fixture, VId, VId, VId) {
    let mut f = Fixture::new(seed);
    f.post(1, "3000", "1000", 20, false);
    let (source, _) = f.post(2, "3000", "1000", 100, false);
    let (withdrawal, _) = f.post(2, "1000", "6000", 90, false);
    let (returned, _) = f.post(2, "3000", "1000", 70, false);
    // Both later effective events remain in the complete source. Neither the
    // withdrawal nor reversal changes a claim ending on the second day.
    f.post(3, "1000", "6000", 200, false);
    reverse(&mut f, withdrawal, b"libr-later-effective-reversal", 4);
    (f, source, withdrawal, returned)
}

fn request(f: &Fixture, source: VId, order: i128, replenishment: i128) -> ProcedureRequest {
    let mut request = f.request("trace.libr", source);
    request.version = Some(2);
    request.effective_through = Some(day(2));
    request.parameters = request
        .parameters
        .set("intraday_order", order)
        .unwrap()
        .set("replenishment", replenishment)
        .unwrap();
    request
}

#[test]
fn libr_exports_all_three_intraday_laws_and_evidence_replenishment_exactly() {
    let (mut f, source, withdrawal, returned) = population(233);
    let mut certificates = Vec::new();
    for (order, replenishment, expected) in [
        (0, 0, 30),
        (2, 0, 30),
        (3, 0, 100),
        (0, 1, 100),
        (2, 1, 30),
        (3, 1, 100),
    ] {
        let certified = f.certify(&request(&f, source, order, replenishment));
        certified.certificate.check_offline_profile().unwrap();
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
        let mut supporting = if order == 2 {
            Vec::new()
        } else {
            vec![withdrawal]
        };
        if (order, replenishment) == (0, 1) {
            supporting.push(returned);
        }
        supporting.sort_unstable();
        let mut expected_cites = vec![Cite::Account(f.id("1000")), Cite::Entry(source)];
        expected_cites.extend(supporting.into_iter().map(Cite::Entry));
        assert_eq!(finding.cites, expected_cites);
        assert_eq!(
            (
                certified.report.work.entries,
                certified.report.work.legs,
                certified.report.work.comparisons
            ),
            (4, 3, 8)
        );
        assert_eq!(certified.report.coordinate.effective_through, Some(day(2)));
        certificates.push(certified);
    }
    let key = f.book.checkpoint_public_key();
    for certified in certificates {
        let produced = produce(&mut f, &certified.certificate);
        let verified = verify(&produced, &certified.certificate, key);
        assert_eq!(decode_run(&verified.output).unwrap(), certified.report);
        let procedure = verified.procedure.unwrap();
        assert_eq!(
            (
                procedure.live_entries,
                procedure.live_legs,
                procedure.comparisons
            ),
            (4, 3, 8)
        );
        let fa_verify::report::VerifiedProcedureStatistic::TracedAmount {
            account,
            unit,
            mantissa,
            scale,
            entries,
        } = &procedure.findings[0].statistic
        else {
            panic!("independent native-unit tracing result");
        };
        assert_eq!(
            (*account, *unit, *mantissa, *scale),
            (
                f.id("1000").0,
                f.unit.0,
                certified.report.findings[0].statistic.value,
                2
            )
        );
        let expected_entries: Vec<_> = certified.report.findings[0]
            .cites
            .iter()
            .filter_map(|cite| {
                if let Cite::Entry(entry) = cite {
                    Some(entry.0)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(*entries, expected_entries);
    }
}

#[test]
fn libr_rejects_resealed_questions_findings_and_missing_uncited_source_records() {
    let (mut f, source, _, returned) = population(234);
    let certified = f.certify(&request(&f, source, 0, 0));
    let produced = produce(&mut f, &certified.certificate);
    let key = f.book.checkpoint_public_key();
    verify(&produced, &certified.certificate, key);
    assert!(
        !certified.report.findings[0]
            .cites
            .contains(&Cite::Entry(returned))
    );

    // Every variant remains a valid supported question or well-formed output.
    // Repair all public commitments and supply the replacement recipient pin:
    // independent reconstruction must still reject the retained old answer.
    for variant in [
        "amount",
        "scale",
        "movement count",
        "work",
        "citation",
        "narrative",
        "account",
        "source",
        "claim date",
        "intraday",
        "replenishment",
    ] {
        let mut forged = certified.certificate.clone();
        let run = &mut forged.report;
        match variant {
            "amount" => run.findings[0].statistic.value += 1,
            "scale" => run.findings[0].statistic.scale = 0,
            "movement count" => run.findings[0].statistic.population += 1,
            "work" => run.work.legs += 1,
            "citation" => {
                run.findings[0].cites.pop();
            }
            "narrative" => run.findings[0].narrative.push_str(" altered"),
            "account" => run.inputs[0].1 = format!("{:032x}", f.id("3000").0),
            "source" => run.inputs[1].1 = format!("{:032x}", returned.0),
            "claim date" => run.coordinate.effective_through = Some(day(3)),
            "intraday" => run.parameters[0].1 = 2,
            "replenishment" => run.parameters[1].1 = 1,
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
    for variant in [
        "old version",
        "missing cutoff",
        "reserved order",
        "unknown replenishment",
        "missing handle",
        "extra handle",
        "short handle",
        "uppercase handle",
    ] {
        let mut forged = certified.certificate.clone();
        let run = &mut forged.report;
        match variant {
            "old version" => {
                run.version = 1;
                run.findings[0].version = 1;
            }
            "missing cutoff" => run.coordinate.effective_through = None,
            "reserved order" => run.parameters[0].1 = 1,
            "unknown replenishment" => run.parameters[1].1 = 2,
            "missing handle" => {
                run.inputs.pop();
            }
            "extra handle" => run
                .inputs
                .push(("unused".into(), format!("{:032x}", source.0))),
            "short handle" => run.inputs[0].1 = "1000".into(),
            "uppercase handle" => run.inputs[1].1 = "0000000000000000000000000000000A".into(),
            _ => unreachable!(),
        }
        assert_eq!(
            forged.check_offline_profile().unwrap_err().code,
            fa_notary::code::SCOPE_UNSUPPORTED,
            "{variant}"
        );
        reseal(&mut forged);
        let changed = replace_certificate(&produced.bundle.bytes, &forged);
        let refused = verify_report_expected(&changed, &[key], None, None, Some(forged.digest()))
            .unwrap_err();
        assert!(
            matches!(
                refused.predicate,
                "procedure_profile" | "canonical_encoding"
            ),
            "{variant}: {refused}"
        );
    }

    // The clean, uncited inflow is part of the signed complete prefix. Its
    // omission or alteration fails independently of the producer's citations.
    let digest = f
        .book
        .read_entry(&f.cx(), returned)
        .unwrap()
        .unwrap()
        .0
        .entry_digest;
    let bytes = &produced.bundle.bytes;
    let mut reader = Reader::new(bytes);
    reader.bytes(64, "format").unwrap();
    assert_eq!(reader.u16("major").unwrap(), 2);
    assert_eq!(reader.u16("minor").unwrap(), 0);
    for field in ["certificate", "checkpoint", "prefix"] {
        reader
            .bytes(MAX_PROCEDURE_CERTIFICATE_BYTES, field)
            .unwrap();
    }
    let count_offset = reader.offset();
    let count = reader.u32("records").unwrap();
    let mut target_range = None;
    for _ in 0..count {
        let start = reader.offset();
        reader.u32("proposal length").unwrap();
        let payload = reader
            .bytes(MAX_PROCEDURE_CERTIFICATE_BYTES, "record")
            .unwrap();
        if fa_model::Entry::decode(payload).is_ok_and(|entry| entry.entry_digest == digest) {
            target_range = Some((start, reader.offset()));
        }
    }
    let (start, end) = target_range.expect("the uncited balance input is in the complete prefix");
    let mut writer = Writer::new();
    writer
        .fixed(&bytes[..count_offset])
        .u32(count - 1)
        .fixed(&bytes[count_offset + 4..start])
        .fixed(&bytes[end..]);
    let mut altered = bytes.clone();
    altered[end - 1] ^= 1;
    for (changed, predicate) in [
        (writer.finish().unwrap(), "record_completeness"),
        (altered, "record_derivation"),
    ] {
        assert_eq!(
            verify_report_expected(
                &changed,
                &[key],
                None,
                None,
                Some(certified.certificate.digest())
            )
            .unwrap_err()
            .predicate,
            predicate
        );
    }
}
