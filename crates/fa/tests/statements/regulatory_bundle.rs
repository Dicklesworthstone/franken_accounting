//! A recipient reconstructs regulatory GL projections from exported evidence,
//! with no source book, native evaluator, or assumption that Instrument inputs
//! were read. The native schedule definition and original output remain bound.

use super::*;

fn selection(schedule: fa::RegulatoryScheduleDefinition) -> fa::ReportSelection {
    fa::ReportSelection::RegulatorySchedule(Box::new(fa::RegulatorySelection {
        schedule,
        periods: vec![FEBRUARY.into()],
        comparative: vec![JANUARY.into()],
    }))
}

fn post_comparatives(fixture: &mut Fixture) {
    for (key, month, unit, accounts, amount) in [
        ("jan-capital", 1, fixture.usd, ("1000", "3000"), 10_000),
        ("jan-revenue", 1, fixture.usd, ("1000", "4000"), 1_004),
        ("jan-expense", 1, fixture.usd, ("6000", "1000"), 253),
        ("feb-revenue", 2, fixture.usd, ("1000", "4000"), 2_505),
        ("feb-expense", 2, fixture.usd, ("6000", "1000"), 356),
        ("feb-jpy-revenue", 2, fixture.jpy, ("1000", "4000"), 37),
    ] {
        fixture.transfer(day(2026, month, 15), key.as_bytes(), unit, accounts, amount);
    }
}

fn verify(
    key: [u8; 32],
    produced: &fa::ProducedBundle,
    certificate: &ReportCertificate,
) -> fa_verify::report::VerifiedReport {
    let mut wire = fa_model::Reader::new(&produced.bundle.bytes);
    assert_eq!(wire.bytes(64, "format").unwrap(), b"fa:report-bundle:v1");
    assert_eq!(wire.u16("major").unwrap(), 2);
    assert_eq!(wire.u16("minor").unwrap(), 0);
    assert_eq!(
        wire.bytes(64 * 1024 * 1024, "source").unwrap(),
        certificate.canonical_bytes().unwrap(),
        "the original native v9 certificate is exported without translation"
    );
    let anchor = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    let verified = fa_verify::report::verify_report_expected(
        &produced.bundle.bytes,
        &[key],
        Some(&anchor.checkpoint),
        Some(&produced.receipt),
        Some(&certificate.digest),
    )
    .expect("the independent receiver must reproduce the complete regulatory GL output");
    assert_eq!(verified.output, certificate.output);
    assert_eq!(verified.certificate_digest, certificate.digest);
    assert_eq!(verified.known_at, certificate.known_at.0);
    assert_eq!(verified.scope, "recomputation");
    assert_eq!(verified.unit_universe_source, "authenticated-registry");
    assert!(verified.statement.is_none());
    assert!(verified.custom_statement.is_none());
    let regulatory = verified.regulatory_schedule.as_ref().unwrap();
    assert!(!regulatory.instrument_inputs_read);
    let fa::ReportSelection::RegulatorySchedule(selected) = &certificate.selection else {
        panic!("test source is not a regulatory schedule");
    };
    assert_eq!(regulatory.form, selected.schedule.form.as_str());
    assert_eq!(
        regulatory.schedule_digest,
        selected.schedule.digest().unwrap().0
    );
    assert_eq!(regulatory.schedule_code, selected.schedule.schedule_code);
    assert_eq!(
        regulatory.instruction_version,
        selected.schedule.instruction_version
    );
    assert_eq!(
        regulatory
            .declared_instrument_inputs
            .iter()
            .map(|input| (
                &input.line_code,
                &input.instrument_kind,
                &input.attribute_name
            ))
            .collect::<Vec<_>>(),
        selected
            .schedule
            .declared_instrument_inputs
            .iter()
            .map(|input| (
                &input.line_code,
                &input.instrument_kind,
                &input.attribute_name
            ))
            .collect::<Vec<_>>()
    );
    let command = fa_verify::cli::run(
        &[
            "report".into(),
            "bundle".into(),
            "--key".into(),
            key.iter().map(|byte| format!("{byte:02x}")).collect(),
            "--receipt".into(),
            "receipt".into(),
            "--expect".into(),
            certificate
                .digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            "--json".into(),
        ],
        &|path| match path {
            "bundle" => Ok(produced.bundle.bytes.clone()),
            "receipt" => Ok(produced.receipt.clone()),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("unexpected input {path}"),
            )),
        },
    );
    assert_eq!(command.exit, 0, "{}", command.stdout);
    for claim in [
        "\"report_mode\":\"regulatory_schedule\"",
        "\"calculation\":\"general_ledger_projection\"",
        "\"instrument_inputs_read\":false",
        "\"instrument_values\":\"not_judged\"",
        "\"regulatory_compliance\":\"not_judged\"",
    ] {
        assert!(
            command.stdout.contains(claim),
            "{claim}: {}",
            command.stdout
        );
    }
    verified
}

#[test]
fn regulatory_bundles_recompute_all_shipped_schedules_without_the_source_book() {
    for (schedule, total_code, expected_usd) in [
        (
            fa::RegulatoryScheduleDefinition::ffiec_041_schedule_rc_2026q1(),
            "RCON2170",
            [12_900, 10_751],
        ),
        (
            fa::RegulatoryScheduleDefinition::ffiec_041_schedule_ri_2026q1(),
            "RIAD4340",
            [2_149, 751],
        ),
        (
            fa::RegulatoryScheduleDefinition::fr_y9c_schedule_hc_2026q1(),
            "BHCK2170",
            [12_900, 10_751],
        ),
    ] {
        let mut fixture = Fixture::new(0xe0);
        post_comparatives(&mut fixture);
        let usd = fixture.usd.0;
        let jpy = fixture.jpy.0;
        let eur = fixture.book.context().units.lookup("EUR").unwrap().0;
        let before = fixture.book.head().unwrap();
        let certified = fixture
            .book
            .certify_report(selection(schedule), None)
            .unwrap()
            .unwrap();
        assert_eq!(fixture.book.head().unwrap(), before);
        assert!(matches!(
            certified.report,
            ReportOutput::RegulatorySchedule(_)
        ));
        let produced = report_bundle::produce(&mut fixture.book, &certified.certificate);
        let key = fixture.book.checkpoint_public_key();
        drop(fixture);

        let verified = verify(key, &produced, &certified.certificate);
        let report = verified.regulatory_schedule.unwrap();
        let line = |unit| {
            &report
                .statement
                .lines
                .iter()
                .find(|line| line.code == total_code && line.unit == unit)
                .unwrap()
                .amounts
        };
        assert_eq!(line(usd), &expected_usd);
        assert_eq!(line(jpy), &[37, 0]);
        assert_eq!(line(eur), &[0, 0], "unused registered units remain visible");
        assert!(
            fa_verify::report::verify_report_expected(
                &produced.bundle.bytes,
                &[key],
                None,
                Some(&produced.receipt),
                Some(&[0xff; 32]),
            )
            .is_err(),
            "a valid alternate certificate cannot replace the recipient's selected report"
        );
    }
}

#[test]
fn retained_regulatory_bundles_reopen_and_ignore_later_backdated_postings() {
    let seed = 0xe1;
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fa-regulatory-proof-{}-{suffix}",
        std::process::id()
    ));
    let mut fixture = Fixture::at(seed, Some(&directory));
    post_comparatives(&mut fixture);
    let certified = fixture
        .book
        .certify_report(
            selection(fa::RegulatoryScheduleDefinition::ffiec_041_schedule_rc_2026q1()),
            None,
        )
        .unwrap()
        .unwrap();
    let producer = Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap();
    let retained = fixture
        .book
        .retain_certificate(PRINCIPAL, &producer, &certified.certificate)
        .unwrap()
        .unwrap();
    let original = report_bundle::produce(&mut fixture.book, &certified.certificate);
    let key = fixture.book.checkpoint_public_key();
    fixture.transfer(
        day(2026, 1, 20),
        b"backdated-after-regulatory-certificate",
        fixture.usd,
        ("1000", "4000"),
        9_000,
    );
    drop(fixture);
    let mut book = Book::open_dir(
        &directory,
        BookKeys::for_development(seed),
        Entropy::deterministic(u64::from(seed)),
    )
    .unwrap();
    let loaded = book.read_certificate(&retained.digest).unwrap().unwrap();
    assert_eq!(loaded, certified.certificate);
    let repeated = book
        .produce_report_bundle(
            PRINCIPAL,
            &producer,
            Some(original.checkpoint.checkpoint.body.state_oid),
            &loaded,
        )
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(repeated.bundle.bytes, original.bundle.bytes);
    assert_ne!(
        repeated.receipt, original.receipt,
        "a new receipt binds the later production frontier and producer capability"
    );
    let later = report_bundle::produce(&mut book, &loaded);
    drop(book);
    verify(key, &repeated, &loaded);
    verify(key, &later, &loaded);
}

#[test]
fn regulatory_export_checks_authority_before_inspecting_certificate_or_checkpoint() {
    let mut fixture = Fixture::new(0xe2);
    post_comparatives(&mut fixture);
    let certified = fixture
        .book
        .certify_report(
            selection(fa::RegulatoryScheduleDefinition::ffiec_041_schedule_ri_2026q1()),
            None,
        )
        .unwrap()
        .unwrap();
    let before = fixture.book.head().unwrap();
    let denied = Capability::embedded(PRINCIPAL, &["read", "produce"])
        .unwrap()
        .for_accounts(&["1000"])
        .unwrap();
    let mut damaged = certified.certificate.clone();
    damaged.digest[0] ^= 1;
    let mut first = None;
    for certificate in [&certified.certificate, &damaged] {
        for state in [None, Some(Oid([0xff; 32]))] {
            let refusal = fixture
                .book
                .produce_report_bundle(PRINCIPAL, &denied, state, certificate)
                .unwrap()
                .unwrap_err();
            assert_eq!((refusal.code, refusal.exit), ("FA-REF-011", 7));
            if let Some(first) = &first {
                assert_eq!(&refusal, first);
            } else {
                first = Some(refusal);
            }
        }
    }
    assert_eq!(fixture.book.head().unwrap(), before);
}
