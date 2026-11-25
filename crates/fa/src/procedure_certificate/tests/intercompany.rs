use super::*;

#[test]
fn intercompany_v3_certifies_each_uncovered_leg_without_netting_and_replays_v2() {
    let mut f = Fixture::new(0xe1);
    f.assign_role("1000", "intercompany");
    let (receipt, _) = f.post(1, "3000", "1000", 5_000, false);
    f.post(20, "1000", "1010", 5_000, false);
    let before = f.head();
    let mut request = f.request("recon.intercompany", receipt);
    let current = f.certify(&request);
    assert_eq!(current.report.version, 3);
    assert_eq!(current.report.claim, Claim::Statistical);
    assert_eq!(current.report.findings.len(), 2);
    assert!(current.report.findings.iter().all(|finding| {
        finding.version == 3
            && finding.severity == Severity::Critical
            && finding.statistic.name == "intercompany_undeclared"
            && finding.statistic.value == 5_000
            && finding.statistic.scale == 2
            && finding.statistic.population == 2
            && matches!(finding.cites.as_slice(), [
                Cite::Entry(_), Cite::Leg { .. }, Cite::Account(_), Cite::Period(_),
            ])
    }));
    assert_eq!(current.certificate.format(), EXTENDED_PROCEDURE_CERTIFICATE_FORMAT);
    assert_eq!(current.certificate.supplemental_inputs().len(), extended::COUNT);
    assert!(current.certificate.check_offline_profile().is_err());

    request.version = Some(2);
    request.effective_through = None;
    let prior = f.certify(&request);
    assert_eq!(prior.report.version, 2);
    assert!(prior.report.findings.is_empty(), "retained v2 keeps its aggregate law");
    assert_ne!(prior.certificate.registry, current.certificate.registry);
    assert_eq!(
        prior.certificate.registry,
        intercompany_v2_registry_digest().unwrap(),
    );
    assert_eq!(
        canonical_registry_document(&prior.certificate.registry).unwrap().unwrap(),
        pre_intercompany_registry_document().unwrap(),
    );
    for certified in [&prior, &current] {
        let bytes = certified.certificate.canonical_bytes().unwrap();
        let decoded = ProcedureCertificate::decode(&bytes).unwrap();
        assert_eq!(
            f.book.replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &decoded)
                .unwrap().unwrap(),
            certified.report,
        );
        assert_eq!(ReportArtifact::decode(&bytes).unwrap().family(), ReportArtifactFamily::Procedure);
    }
    let mut wrong = current.certificate.clone();
    wrong.registry = prior.certificate.registry;
    assert!(wrong.request().is_err(), "v3 never borrows the v2 registry");
    wrong = prior.certificate.clone();
    wrong.registry = current.certificate.registry;
    assert!(wrong.request().is_err(), "v2 never borrows the v3 registry");

    request.version = Some(3);
    request.effective_through = Some(day(10));
    let cutoff = f.certify(&request);
    assert_eq!(cutoff.report.findings.len(), 1);
    assert_eq!(cutoff.report.findings[0].statistic.population, 1);
    assert_eq!(cutoff.report.coordinate.effective_through, Some(day(10)));
    assert_eq!(f.head(), before, "certification and replay publish nothing");
}

#[test]
fn unrelated_certificates_keep_every_published_procedure_registry_epoch() {
    let mut f = Fixture::new(0xe2);
    let (source, _) = f.post(1, "3000", "1000", 1_000, false);
    let current = f.certify(&f.request("jet.weekend", source)).certificate;
    let documents = [
        pre_intercompany_registry_document().unwrap(),
        pre_kiting_registry_document().unwrap().canonical_bytes(),
        pre_solvency_registry_document().unwrap().canonical_bytes(),
        pre_lapping_metering_registry_document().unwrap().canonical_bytes(),
        pre_lapping_registry_document().unwrap().canonical_bytes(),
        legacy_lookback_registry_document().unwrap(),
        layering_v2_registry_document(false).unwrap(),
        layering_v2_registry_document(true).unwrap(),
        retained_registry_document().unwrap(),
    ];
    for (index, document) in documents.into_iter().enumerate() {
        let mut foundations = vec![published_foundations()[0]];
        if index == 0 {
            foundations.push(PROCEDURE_REGISTRIES[1].1);
        }
        for foundation in foundations {
            let registry = canonical_procedure_closure(&document, foundation).unwrap();
            assert!(registry_versions(&registry).unwrap().is_some());
            assert!(!declares_intercompany_v3(&registry).unwrap());
            assert_eq!(canonical_registry_document(&registry).unwrap(), Some(document.clone()));
            let mut retained = current.clone();
            retained.registry = registry;
            retained.digest = domain_digest(CERTIFICATE_DOMAIN, &[&retained.body().unwrap()]);
            let replayed = f.book.replay_procedure(
                &f.cx(), PRINCIPAL, &cap(&["read"]), &retained,
            ).unwrap().unwrap();
            assert_eq!(replayed, current.report, "unrelated retained epoch {index}");
        }
    }
    for text in [
        pre_intercompany_registry_text().unwrap().to_owned(),
        pre_kiting_registry_text().unwrap().to_owned(),
        pre_solvency_registry_text().unwrap(),
        pre_lapping_metering_registry_text().unwrap(),
        pre_lapping_registry_text().unwrap(),
        legacy_lookback_registry_text().unwrap(),
        retained_legacy_registry_text().unwrap(),
    ] {
        let registry = raw_procedure_closure(&text, published_foundations()[0]);
        assert!(registry_versions(&registry).unwrap().is_some());
        assert!(!declares_intercompany_v3(&registry).unwrap());
        assert!(canonical_registry_document(&registry).unwrap().is_none());
        let mut retained = current.clone();
        retained.registry = registry;
        retained.digest = domain_digest(CERTIFICATE_DOMAIN, &[&retained.body().unwrap()]);
        assert_eq!(
            f.book.replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &retained)
                .unwrap().unwrap(),
            current.report,
        );
    }
}
