//! The public producer must reach the transport and independent computation.
//! Both profiles were already independently verifiable while a stale facade
//! whitelist still refused their export before inspecting the source closure.

use super::*;

fn request(f: &Fixture, id: &str, parameters: &[(&str, i128)]) -> ProcedureRequest {
    let mut request = ProcedureRequest::new(id, catalog::Inputs::default()).unwrap();
    request.version = Some(1);
    request.known_at = Some(f.head());
    for &(name, value) in parameters {
        request.parameters = request.parameters.set(name, value).unwrap();
    }
    request
}

fn rejects_profile_changes(certificate: &ProcedureCertificate) {
    for variant in [
        "version",
        "cutoff",
        "input",
        "missing parameter",
        "duplicate parameter",
        "claim",
        "evidence",
        "unknown registry",
        "raw-text registry",
    ] {
        let mut changed = certificate.clone();
        match variant {
            "version" => changed.report.version = 2,
            "cutoff" => changed.report.coordinate.effective_through = Some(day(31)),
            "input" => changed
                .report
                .inputs
                .push(("account".into(), "1000".into())),
            "missing parameter" => {
                changed.report.parameters.pop();
            }
            "duplicate parameter" => changed
                .report
                .parameters
                .push(changed.report.parameters[0].clone()),
            "claim" => changed.report.claim = Claim::Invariant,
            "evidence" => changed.report.evidence = "FA-EVID-L01".into(),
            "unknown registry" => changed.registry = [0; 32],
            "raw-text registry" => changed.registry = legacy_registry_digest(),
            _ => unreachable!(),
        }
        assert_eq!(
            changed.check_offline_profile().unwrap_err().code,
            fa_notary::code::SCOPE_UNSUPPORTED,
            "{}: {variant}",
            certificate.report.procedure
        );
    }
}

#[test]
fn different_date_duplicates_export_through_native_facade_and_notary() {
    let mut f = Fixture::new(231);
    let (first, _) = f.post(2, "3000", "1000", 10_000, false);
    let (second, _) = f.post(3, "3000", "1000", 10_000, false);
    f.post(4, "3000", "6000", 123, false);
    let certified = f.certify(&request(
        &f,
        "duplicates.same_same_different",
        &[("window_days", 1)],
    ));
    assert_eq!(certified.report.findings.len(), 1);
    let finding = &certified.report.findings[0];
    assert_eq!(finding.statistic.name, "days_apart");
    assert_eq!(finding.statistic.value, 1);
    assert_eq!(finding.statistic.population, 3);
    assert_eq!(finding.cites, vec![Cite::Entry(first), Cite::Entry(second)]);
    // Current JET is v2 in this registry; unrelated v1 procedures must retain
    // their own version instead of inheriting the JET epoch's version number.
    assert_eq!(
        registry_versions(&certified.certificate.registry)
            .unwrap()
            .unwrap()
            .0,
        2
    );
    certified.certificate.check_offline_profile().unwrap();
    rejects_profile_changes(&certified.certificate);
    let produced = produce(&mut f, &certified.certificate);
    let verified = verify(
        &produced,
        &certified.certificate,
        f.book.checkpoint_public_key(),
    );
    assert_eq!(decode_run(&verified.output).unwrap(), certified.report);
    let procedure = verified.procedure.unwrap();
    assert_eq!(procedure.procedure, "duplicates.same_same_different");
    assert_eq!(procedure.version, 1);
    assert_eq!(
        procedure.parameters,
        fa_verify::report::VerifiedProcedureParameters::SameSameDifferent { window_days: 1 }
    );
    assert_eq!((procedure.live_entries, procedure.live_legs), (3, 6));
    assert_eq!(
        procedure.findings[0].statistic,
        fa_verify::report::VerifiedProcedureStatistic::DaysApart {
            earlier: first.0,
            later: second.0,
            days: 1,
        }
    );
}

#[test]
fn round_density_exports_through_native_facade_and_notary() {
    let mut f = Fixture::new(232);
    for date in 2..=5 {
        f.post(date, "3000", "1000", 10_000, false);
        f.post(date, "6000", "1010", 123, false);
    }
    let certified = f.certify(&request(
        &f,
        "numbers.round_amount_density",
        &[("min_legs", 4), ("round_power", 2), ("z_squared", 4)],
    ));
    assert_eq!(certified.report.findings.len(), 2);
    for finding in &certified.report.findings {
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.statistic.name, "round_legs");
        assert_eq!(finding.statistic.value, 4);
        assert_eq!(finding.statistic.population, 4);
        assert_eq!(finding.cites.len(), 5);
    }
    let accounts: BTreeSet<_> = certified
        .report
        .findings
        .iter()
        .map(|finding| {
            let Cite::Account(account) = finding.cites[0] else {
                panic!("density findings begin with their account citation");
            };
            account
        })
        .collect();
    assert_eq!(accounts, BTreeSet::from([f.id("1000"), f.id("3000")]));
    certified.certificate.check_offline_profile().unwrap();
    rejects_profile_changes(&certified.certificate);
    let produced = produce(&mut f, &certified.certificate);
    let verified = verify(
        &produced,
        &certified.certificate,
        f.book.checkpoint_public_key(),
    );
    assert_eq!(decode_run(&verified.output).unwrap(), certified.report);
    let procedure = verified.procedure.unwrap();
    assert_eq!(procedure.procedure, "numbers.round_amount_density");
    assert_eq!(procedure.version, 1);
    assert_eq!((procedure.live_entries, procedure.live_legs), (8, 16));
    assert_eq!(procedure.comparisons, 4);
    assert_eq!(
        procedure.parameters,
        fa_verify::report::VerifiedProcedureParameters::RoundAmountDensity {
            min_legs: 4,
            round_power: 2,
            z_squared: 4,
        }
    );
    for finding in procedure.findings {
        let fa_verify::report::VerifiedProcedureStatistic::AccountRoundLegs {
            account,
            count,
            legs,
        } = finding.statistic
        else {
            panic!("expected independently reconstructed account density");
        };
        assert!(accounts.contains(&VId(account)));
        assert_eq!((count, finding.population, legs.len()), (4, 4, 4));
    }
}
