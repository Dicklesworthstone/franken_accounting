//! Real producer artifacts must cross the dependency-free verifier boundary.
//! The forged outputs below have repaired public hashes and replacement pins:
//! only reconstruction from the authenticated complete prefix can reject them.

use super::*;
use fa_verify::report::{VerifiedReport, verify_report_expected};

fn round_request(f: &Fixture, power: i128, through: Option<DateDay>) -> ProcedureRequest {
    let mut request =
        ProcedureRequest::new("jet.round_amounts", catalog::Inputs::default()).unwrap();
    request.parameters = request.parameters.set("round_power", power).unwrap();
    request.known_at = Some(f.head());
    request.effective_through = through;
    request
}

fn produce(f: &mut Fixture, certificate: &ProcedureCertificate) -> crate::ProducedBundle {
    let cx = f.cx();
    f.runtime
        .block_on(f.book.checkpoint(&cx, PRINCIPAL, &cap(&["witness"])))
        .unwrap()
        .unwrap();
    let before = f.head();
    let result = f
        .runtime
        .block_on(f.book.produce_procedure_report_bundle(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            None,
            certificate,
        ))
        .unwrap()
        .unwrap()
        .expect("checkpoint covers the original native procedure inputs");
    assert_eq!(
        f.head(),
        before,
        "production must not publish journal effects"
    );
    result
}

fn verify(
    produced: &crate::ProducedBundle,
    certificate: &ProcedureCertificate,
    key: [u8; 32],
) -> VerifiedReport {
    let checkpoint = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    let result = verify_report_expected(
        &produced.bundle.bytes,
        &[key],
        Some(&checkpoint.checkpoint),
        Some(&produced.receipt),
        Some(certificate.digest()),
    )
    .expect("independent reconstruction must agree with the retained native result");
    assert_eq!(result.certificate_digest, *certificate.digest());
    assert_eq!(result.known_at, certificate.known_at().0);
    assert_eq!(result.output, certificate.output());
    assert!(result.receipt.is_some());
    result
}

fn template(f: &Fixture, source: VId, key: &[u8], date: u8) -> EntryPayload {
    let (entry, _) = f.book.read_entry(&f.cx(), source).unwrap().unwrap();
    let mut proposal = entry.proposal;
    proposal.idempotency_key = key.to_vec();
    proposal.effective_date = day(date);
    proposal.effective_period = None;
    proposal
}

fn post(f: &mut Fixture, proposal: EntryPayload) -> VId {
    let cx = f.cx();
    f.runtime
        .block_on(f.book.post(
            &cx,
            PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(&["post"]),
            },
        ))
        .unwrap()
        .unwrap()
        .entry_ref()
        .vid
}

fn reversal(f: &Fixture, source: VId, key: &[u8], date: u8) -> EntryPayload {
    let (entry, _) = f.book.read_entry(&f.cx(), source).unwrap().unwrap();
    let target = fa_model::EntryRef {
        vid: source,
        entry_digest: entry.entry_digest,
    };
    let mut proposal = template(f, source, key, date);
    proposal.class = EntryClass::REVERSAL;
    proposal.supersession = vec![fa_model::Supersession {
        target,
        kind: fa_model::SupersessionKind::Reverses,
        reason_code: 1,
    }];
    for leg in &mut proposal.legs {
        leg.side = match leg.side {
            Side::Debit => Side::Credit,
            Side::Credit => Side::Debit,
        };
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    proposal
}

fn reverse(f: &mut Fixture, source: VId, key: &[u8], date: u8) -> VId {
    let proposal = reversal(f, source, key, date);
    post(f, proposal)
}

fn partial_round(f: &mut Fixture, source: VId) -> VId {
    let mut proposal = template(f, source, b"offline-partial-round", 3);
    proposal.legs = vec![
        LegPayload::simple(Side::Credit, f.id("3000"), Amount::new(f.unit, 100_000)),
        LegPayload::simple(Side::Debit, f.id("1000"), Amount::new(f.unit, 99_999)),
        LegPayload::simple(Side::Debit, f.id("1010"), Amount::new(f.unit, 1)),
    ];
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    post(f, proposal)
}

fn replace_certificate(bundle: &[u8], certificate: &ProcedureCertificate) -> Vec<u8> {
    let mut r = Reader::new(bundle);
    let format = r.bytes(64, "format").unwrap();
    let major = r.u16("major").unwrap();
    let minor = r.u16("minor").unwrap();
    r.bytes(MAX_PROCEDURE_CERTIFICATE_BYTES, "certificate")
        .unwrap();
    let mut w = Writer::new();
    w.bytes(format)
        .u16(major)
        .u16(minor)
        .bytes(&certificate.canonical_bytes().unwrap())
        .fixed(&bundle[r.offset()..]);
    w.finish().unwrap()
}

fn reseal(certificate: &mut ProcedureCertificate) {
    let run = &mut certificate.report;
    let mut parameters = Writer::new();
    parameters.str(&run.procedure).u16(run.version);
    parameters.list(&run.parameters, |w, (name, value)| {
        w.str(name).i128(*value);
    });
    parameters.list(&run.inputs, |w, (name, value)| {
        w.str(name).str(value);
    });
    run.parameters_digest = raw_digest(
        fa_lantern::PARAMETERS_DIGEST_DOMAIN,
        &parameters.finish().unwrap(),
    );
    // Keep negative vectors canonical even when their severity, amount or
    // citation changes move a finding to a different position in the ranking.
    run.findings.sort_by(|a, b| {
        let cites = |finding: &Finding| {
            finding
                .cites
                .iter()
                .map(|cite| cite.canonical_bytes().unwrap())
                .collect::<Vec<_>>()
        };
        b.severity
            .cmp(&a.severity)
            .then(b.statistic.value.cmp(&a.statistic.value))
            .then_with(|| cites(a).cmp(&cites(b)))
            .then_with(|| a.narrative.cmp(&b.narrative))
    });
    let mut findings = Writer::new();
    findings
        .str(&run.procedure)
        .u16(run.version)
        .fixed(&run.parameters_digest)
        .fixed(&run.inputs_digest);
    run.coordinate.encode(&mut findings);
    findings.list(&run.findings, |w, finding| finding.encode(w));
    run.findings_digest = raw_digest(
        fa_lantern::FINDINGS_DIGEST_DOMAIN,
        &findings.finish().unwrap(),
    );
    run.decision_card_digest = run.decision_card.digest().unwrap();
    certificate.output = encode_run(run).unwrap();
    certificate.digest = domain_digest(CERTIFICATE_DOMAIN, &[&certificate.body().unwrap()]);
    assert_eq!(
        ProcedureCertificate::decode(&certificate.canonical_bytes().unwrap()).unwrap(),
        *certificate,
        "the negative must pass the producer's integrity-only decoder"
    );
}

#[test]
fn round_amounts_reconstructs_historical_native_units_liveness_and_exact_citations() {
    let mut f = Fixture::new(110);
    let (whole, _) = f.post(1, "3000", "1000", 100_000, false);
    f.post(2, "3000", "1000", 99_999, false);
    let partial = partial_round(&mut f, whole);
    let (reversed, _) = f.post(4, "3000", "1000", 200_000, false);
    reverse(&mut f, reversed, b"offline-reverse-round", 5);
    let (restored, _) = f.post(6, "3000", "1000", 300_000, false);
    let undo = reverse(&mut f, restored, b"offline-first-undo", 7);
    reverse(&mut f, undo, b"offline-undo-the-undo", 8);
    let jpy = UnitRegistry::embedded().unwrap().lookup("JPY").unwrap();
    let mut japanese = template(&f, whole, b"offline-jpy-round", 9);
    for leg in &mut japanese.legs {
        leg.amount = Amount::new(jpy, 1_000);
    }
    japanese.unit_totals = EntryPayload::fold_unit_totals(&japanese.legs).unwrap();
    let japanese = post(&mut f, japanese);
    let (later_effective, _) = f.post(20, "3000", "1000", 400_000, false);
    let mut pending = template(&f, whole, b"offline-pending-round", 10);
    pending.class = EntryClass::PENDING;
    pending.pending = Some(fa_model::Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    let pending = post(&mut f, pending);
    let certified = f.certify(&round_request(&f, 3, None));
    let original_at = f.head();
    let (new_at_head, _) = f.post(1, "3000", "1000", 500_000, false);
    reverse(&mut f, whole, b"offline-later-undo", 21);
    let produced = produce(&mut f, &certified.certificate);
    let key = f.book.checkpoint_public_key();
    let verified = verify(&produced, &certified.certificate, key);
    assert_eq!(verified.known_at, original_at.0);
    assert!(verified.checkpoint.checkpoint.through_seq > original_at.0);
    let procedure = verified.procedure.as_ref().unwrap();
    assert_eq!(procedure.procedure, "jet.round_amounts");
    assert_eq!((procedure.live_entries, procedure.live_legs), (6, 13));
    assert_eq!(procedure.findings.len(), 5);
    assert!(
        verified.open_items.is_none(),
        "the nested source is not the exported analytical result"
    );
    let replayed = decode_run(&verified.output).unwrap();
    assert_eq!(replayed.coordinate.effective_through, None);
    assert_eq!(
        replayed.work,
        Work {
            entries: 6,
            legs: 13,
            comparisons: 0
        }
    );
    assert!(replayed.population > replayed.work.entries);
    assert_eq!(replayed.findings.len(), 5);
    for entry in [whole, restored, japanese, later_effective] {
        let finding = replayed
            .findings
            .iter()
            .find(|finding| finding.cites.first() == Some(&Cite::Entry(entry)))
            .unwrap();
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(
            (finding.statistic.value, finding.statistic.population),
            (2, 13)
        );
        assert_eq!(
            finding.cites,
            vec![
                Cite::Entry(entry),
                Cite::Leg { entry, ordinal: 0 },
                Cite::Leg { entry, ordinal: 1 },
            ]
        );
    }
    let finding = replayed
        .findings
        .iter()
        .find(|finding| finding.cites.first() == Some(&Cite::Entry(partial)))
        .unwrap();
    assert_eq!(finding.severity, Severity::Low);
    assert_eq!(
        (finding.statistic.value, finding.statistic.population),
        (1, 13)
    );
    assert_eq!(
        finding.cites,
        vec![
            Cite::Entry(partial),
            Cite::Leg {
                entry: partial,
                ordinal: 0
            }
        ]
    );
    for excluded in [reversed, undo, pending, new_at_head] {
        assert!(
            replayed
                .findings
                .iter()
                .all(|finding| { !finding.cites.contains(&Cite::Entry(excluded)) })
        );
    }
    let before = f.head();
    let cx = f.cx();
    let repeated = f
        .runtime
        .block_on(f.book.produce_procedure_report_bundle(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            None,
            &certified.certificate,
        ))
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(repeated.bundle.bytes, produced.bundle.bytes);
    assert_eq!(repeated.receipt, produced.receipt);
    assert_eq!(f.head(), before);
    let command = fa_verify::cli::run(
        &[
            "report".into(),
            "procedure.fab".into(),
            "--key".into(),
            key.iter().map(|byte| format!("{byte:02x}")).collect(),
            "--receipt".into(),
            "procedure.receipt".into(),
            "--json".into(),
        ],
        &|path| match path {
            "procedure.fab" => Ok(produced.bundle.bytes.clone()),
            "procedure.receipt" => Ok(produced.receipt.clone()),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "unexpected input",
            )),
        },
    );
    assert_eq!(command.exit, 0, "{}", command.stdout);
    assert!(command.stdout.contains("\"report_mode\":\"procedure\""));
    assert!(command.stdout.contains("\"check\":\"procedure_summary\""));
    assert_eq!(
        command
            .stdout
            .matches("\"check\":\"procedure_finding\"")
            .count(),
        5
    );
    assert!(
        !command
            .stdout
            .contains("\"check\":\"open_items_parameters\"")
    );
    assert!(!command.stdout.contains("\"check\":\"open_item\""));
}

#[test]
fn round_amounts_replays_nondefault_parameters_large_exact_values_and_empty_findings() {
    let mut f = Fixture::new(111);
    let empty = f.certify(&round_request(&f, 3, None));
    let produced = produce(&mut f, &empty.certificate);
    let empty = decode_run(
        &verify(
            &produced,
            &empty.certificate,
            f.book.checkpoint_public_key(),
        )
        .output,
    )
    .unwrap();
    assert!(empty.findings.is_empty());
    assert_eq!(empty.work, Work::default());
    assert!(
        empty.population > 0,
        "schema controls remain in the recorded population"
    );

    let (whole, _) = f.post(1, "3000", "1000", 9_007_199_254_800_000, false);
    f.post(2, "3000", "1000", 9_007_199_254_800_001, false);
    let (small, _) = f.post(3, "3000", "1000", 100, false);
    for (power, expected) in [(0, vec![whole, small]), (3, vec![whole]), (30, vec![])] {
        let certified = f.certify(&round_request(&f, power, None));
        let produced = produce(&mut f, &certified.certificate);
        let replayed = decode_run(
            &verify(
                &produced,
                &certified.certificate,
                f.book.checkpoint_public_key(),
            )
            .output,
        )
        .unwrap();
        let observed: BTreeSet<_> = replayed
            .findings
            .iter()
            .map(|finding| {
                let Cite::Entry(vid) = &finding.cites[0] else {
                    panic!("entry citation first")
                };
                *vid
            })
            .collect();
        assert_eq!(observed, expected.into_iter().collect());
        assert_eq!(
            replayed.work,
            Work {
                entries: 3,
                legs: 6,
                comparisons: 0
            }
        );
        assert_eq!(replayed.parameters, vec![("round_power".into(), power)]);
    }
}

#[test]
fn repaired_round_amount_outputs_cannot_fabricate_findings_population_work_or_decisions() {
    let mut f = Fixture::new(112);
    let (whole, _) = f.post(1, "3000", "1000", 100_000, false);
    let (nonround, _) = f.post(2, "3000", "1000", 99_999, false);
    partial_round(&mut f, whole);
    let certified = f.certify(&round_request(&f, 3, None));
    let produced = produce(&mut f, &certified.certificate);
    let key = f.book.checkpoint_public_key();
    verify(&produced, &certified.certificate, key);
    for variant in [
        "omitted finding",
        "false positive",
        "round leg count",
        "missing citation",
        "wrong ordinal",
        "wrong severity",
        "finding population",
        "snapshot population",
        "entry work",
        "leg work",
        "comparison work",
        "narrative",
        "parameters",
        "snapshot digest",
        "decision population",
        "decision choice",
    ] {
        let mut forged = certified.certificate.clone();
        let run = &mut forged.report;
        match variant {
            "omitted finding" => {
                run.findings.pop();
            }
            "false positive" => {
                run.findings[0].cites = vec![
                    Cite::Entry(nonround),
                    Cite::Leg {
                        entry: nonround,
                        ordinal: 0,
                    },
                    Cite::Leg {
                        entry: nonround,
                        ordinal: 1,
                    },
                ];
            }
            "round leg count" => run.findings[0].statistic.value += 1,
            "missing citation" => {
                run.findings[0].cites.pop();
            }
            "wrong ordinal" => {
                run.findings[0].cites[1] = Cite::Leg {
                    entry: whole,
                    ordinal: 9,
                };
            }
            "wrong severity" => run.findings[0].severity = Severity::Low,
            "finding population" => run.findings[0].statistic.population += 1,
            "snapshot population" => run.population += 1,
            "entry work" => run.work.entries += 1,
            "leg work" => run.work.legs += 1,
            "comparison work" => run.work.comparisons += 1,
            "narrative" => run.findings[0].narrative.push_str(" invented observation"),
            "parameters" => run.parameters[0].1 = 4,
            "snapshot digest" => run.inputs_digest[0] ^= 1,
            "decision population" => {
                run.decision_card
                    .features
                    .iter_mut()
                    .find(|feature| feature.name == "population")
                    .unwrap()
                    .value += 1;
            }
            "decision choice" => {
                run.decision_card.chosen = run.decision_card.candidates[1].clone();
            }
            _ => unreachable!(),
        }
        reseal(&mut forged);
        let bundle = replace_certificate(&produced.bundle.bytes, &forged);
        // A fresh recipient pin deliberately accepts the attacker's repaired
        // outer digest. Do not pass the old receipt: it would mask replay bugs.
        let error = verify_report_expected(&bundle, &[key], None, None, Some(forged.digest()))
            .expect_err(variant);
        assert_eq!(
            error.predicate, "procedure_recomputation",
            "{variant}: {error}"
        );
    }
}

#[test]
fn round_amounts_requires_complete_signed_payloads_and_an_independent_outer_pin_or_receipt() {
    let mut f = Fixture::new(113);
    f.post(1, "3000", "1000", 100_000, false);
    let certified = f.certify(&round_request(&f, 3, None));
    let produced = produce(&mut f, &certified.certificate);
    let key = f.book.checkpoint_public_key();
    verify(&produced, &certified.certificate, key);
    assert!(
        verify_report_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            None,
            Some(certified.certificate.digest()),
        )
        .is_ok(),
        "an independent outer pin can replace the detached receipt"
    );
    assert!(
        verify_report_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            Some(&produced.receipt),
            None,
        )
        .is_ok(),
        "the trusted producer receipt can authenticate the exact closure"
    );
    for (trusted, receipt, pin) in [
        (
            vec![],
            Some(produced.receipt.as_slice()),
            Some(certified.certificate.digest()),
        ),
        (vec![key], None, None),
        (
            vec![key],
            Some(produced.receipt.as_slice()),
            Some(&certified.certificate.source.digest),
        ),
    ] {
        assert!(
            verify_report_expected(&produced.bundle.bytes, &trusted, None, receipt, pin,).is_err()
        );
    }
    let mut receipt = produced.receipt.clone();
    *receipt.last_mut().unwrap() ^= 1;
    assert!(
        verify_report_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            Some(&receipt),
            Some(certified.certificate.digest()),
        )
        .is_err(),
        "a supplied invalid signature cannot be ignored because the pin matches"
    );

    let bytes = &produced.bundle.bytes;
    let mut r = Reader::new(bytes);
    r.bytes(64, "format").unwrap();
    r.u16("major").unwrap();
    r.u16("minor").unwrap();
    r.bytes(MAX_PROCEDURE_CERTIFICATE_BYTES, "certificate")
        .unwrap();
    r.bytes(MAX_PROCEDURE_CERTIFICATE_BYTES, "checkpoint")
        .unwrap();
    r.bytes(MAX_PROCEDURE_CERTIFICATE_BYTES, "prefix").unwrap();
    let count_offset = r.offset();
    let count = r.u32("records").unwrap();
    assert!(count > 0);
    r.u32("proposal length").unwrap();
    let first_record = r.bytes(MAX_PROCEDURE_CERTIFICATE_BYTES, "record").unwrap();
    assert!(!first_record.is_empty());
    let first_end = r.offset();
    let mut w = Writer::new();
    w.fixed(&bytes[..count_offset])
        .u32(count - 1)
        .fixed(&bytes[first_end..]);
    let omitted = w.finish().unwrap();
    assert!(
        verify_report_expected(
            &omitted,
            &[key],
            None,
            None,
            Some(certified.certificate.digest()),
        )
        .is_err(),
        "repairing the payload count must not hide an omitted authenticated record"
    );
    let mut altered = bytes.clone();
    altered[first_end - 1] ^= 1;
    assert!(
        verify_report_expected(
            &altered,
            &[key],
            None,
            None,
            Some(certified.certificate.digest()),
        )
        .is_err(),
        "a retained leaf must authenticate the disclosed record bytes"
    );
    for _ in 1..count {
        r.u32("proposal length").unwrap();
        r.bytes(MAX_PROCEDURE_CERTIFICATE_BYTES, "record").unwrap();
    }
    assert_eq!(r.u32("migration bodies").unwrap(), 0);
    let registry_offset = r.offset();
    assert_eq!(r.u32("registry count").unwrap(), 6);
    let mut registries = Vec::new();
    for _ in 0..6 {
        registries.push((
            r.str(64, "registry name").unwrap(),
            r.bytes(1024 * 1024, "registry document").unwrap(),
        ));
    }
    r.finish().unwrap();
    for variant in ["missing procedures", "missing policy", "reordered closure"] {
        let mut selected = registries.clone();
        match variant {
            "missing procedures" => {
                selected.remove(4);
            }
            "missing policy" => {
                selected.pop();
            }
            "reordered closure" => selected.swap(4, 5),
            _ => unreachable!(),
        }
        let mut w = Writer::new();
        w.fixed(&bytes[..registry_offset]);
        w.list(&selected, |w, (name, canonical)| {
            w.str(name).bytes(canonical);
        });
        let changed = w.finish().unwrap();
        let error = verify_report_expected(
            &changed,
            &[key],
            None,
            None,
            Some(certified.certificate.digest()),
        )
        .expect_err(variant);
        assert_eq!(error.predicate, "registry_closure", "{variant}: {error}");
    }
}

#[test]
fn round_amounts_offline_scope_is_explicit_and_production_authority_precedes_observation() {
    let mut f = Fixture::new(114);
    let (source, _) = f.post(1, "3000", "1000", 100_000, false);
    let ordinary = f.certify(&round_request(&f, 3, None)).certificate;
    let cutoff = f.certify(&round_request(&f, 3, Some(day(5)))).certificate;
    let other = f.certify(&f.request("jet.weekend", source)).certificate;
    let produced = produce(&mut f, &ordinary);
    let key = f.book.checkpoint_public_key();
    let cx = f.cx();
    let before = f.head();
    for unsupported in [&cutoff, &other] {
        let refused = f
            .runtime
            .block_on(f.book.produce_procedure_report_bundle(
                &cx,
                PRINCIPAL,
                &cap(&["read", "produce"]),
                None,
                unsupported,
            ))
            .unwrap()
            .unwrap_err();
        assert_eq!(refused.code, fa_notary::code::SCOPE_UNSUPPORTED);
        assert_eq!(f.head(), before);
        let bundle = replace_certificate(&produced.bundle.bytes, unsupported);
        assert!(
            verify_report_expected(&bundle, &[key], None, None, Some(unsupported.digest()),)
                .is_err(),
            "an unsupported native procedure cannot masquerade as a supported offline one"
        );
    }
    for variant in ["version", "handles", "power above range", "negative power"] {
        let mut forged = ordinary.clone();
        match variant {
            "version" => {
                forged.report.version = 2;
                for finding in &mut forged.report.findings {
                    finding.version = 2;
                }
            }
            "handles" => forged
                .report
                .inputs
                .push(("account".into(), format!("{:032x}", f.id("1000").0))),
            "power above range" => forged.report.parameters[0].1 = 31,
            "negative power" => forged.report.parameters[0].1 = -1,
            _ => unreachable!(),
        }
        reseal(&mut forged);
        let bundle = replace_certificate(&produced.bundle.bytes, &forged);
        assert!(
            verify_report_expected(&bundle, &[key], None, None, Some(forged.digest())).is_err(),
            "{variant}"
        );
    }
    let mut damaged = ordinary.clone();
    damaged.digest[0] ^= 1;
    for capability in [
        cap(&["read"]),
        cap(&["produce"]),
        cap(&["read", "produce"]).for_accounts(&["1000"]).unwrap(),
        cap(&["read", "produce"]).known_at_most(ordinary.known_at()),
        cap(&["read", "produce"]).expiring_at(before),
    ] {
        for certificate in [&ordinary, &damaged] {
            for state in [None, Some(Oid([0xff; 32]))] {
                let refusal = f
                    .runtime
                    .block_on(f.book.produce_procedure_report_bundle(
                        &cx,
                        PRINCIPAL,
                        &capability,
                        state,
                        certificate,
                    ))
                    .unwrap()
                    .unwrap_err();
                assert_eq!((refusal.code, refusal.exit), ("FA-REF-011", exit::SAFETY));
                assert_eq!(f.head(), before);
            }
        }
    }
}

#[test]
fn round_amounts_large_population_replays_the_calibrated_decision_branch() {
    let mut f = Fixture::new(115);
    for index in 0..100 {
        f.post(
            1,
            "3000",
            "1000",
            if index == 0 { 100_000 } else { 99_999 },
            false,
        );
    }
    let certified = f.certify(&round_request(&f, 3, None));
    let produced = produce(&mut f, &certified.certificate);
    let result = verify(
        &produced,
        &certified.certificate,
        f.book.checkpoint_public_key(),
    );
    let replayed = decode_run(&result.output).unwrap();
    assert!(replayed.population >= 100);
    assert_eq!(replayed.findings.len(), 1);
    assert_eq!(
        replayed.work,
        Work {
            entries: 100,
            legs: 200,
            comparisons: 0
        }
    );
    assert_eq!(
        replayed.decision_card.chosen.action,
        "split_conformal_calibrated"
    );
    assert_eq!(replayed.decision_card.chosen.parameter, 3);
}

#[test]
fn round_amounts_refuses_replacement_sources_but_preserves_earlier_certificates() {
    let mut f = Fixture::new(116);
    let (source, _) = f.post(1, "3000", "1000", 100_000, false);
    let original = f.certify(&round_request(&f, 3, None)).certificate;
    let undo = reversal(&f, source, b"offline-replacement-undo", 2);
    let mut replacement = template(&f, source, b"offline-corrected-round", 2);
    replacement.class = EntryClass::REPLACEMENT;
    replacement.supersession = vec![fa_model::Supersession {
        target: undo.supersession[0].target,
        kind: fa_model::SupersessionKind::Replaces,
        reason_code: 1,
    }];
    for leg in &mut replacement.legs {
        leg.amount.mantissa = 200_000;
    }
    replacement.unit_totals = EntryPayload::fold_unit_totals(&replacement.legs).unwrap();
    let request = |proposal| PostRequest {
        proposal,
        approvals: Vec::new(),
        plan_certificate: None,
        capability: cap(&["post"]),
    };
    let cx = f.cx();
    let (_, corrected) = f
        .runtime
        .block_on(
            f.book
                .post_replacement_pair(&cx, request(undo), request(replacement)),
        )
        .unwrap()
        .unwrap();
    let current = f.certify(&round_request(&f, 3, None)).certificate;
    assert!(
        current.report.findings.iter().any(|finding| {
            finding
                .cites
                .contains(&Cite::Entry(corrected.entry_ref().vid))
        }),
        "the producer can still run this native procedure in its original book"
    );
    // A later replacement is outside the earlier certificate's selected
    // history even though its leaf is disclosed in the complete checkpoint.
    let produced = produce(&mut f, &original);
    let key = f.book.checkpoint_public_key();
    let verified = verify(&produced, &original, key);
    let replayed = decode_run(&verified.output).unwrap();
    assert_eq!(replayed.findings.len(), 1);
    assert!(replayed.findings[0].cites.contains(&Cite::Entry(source)));
    let before = f.head();
    let refused = f
        .runtime
        .block_on(f.book.produce_procedure_report_bundle(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            None,
            &current,
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, fa_notary::code::SCOPE_UNSUPPORTED);
    assert!(refused.message.contains("replacement"));
    assert_eq!(f.head(), before);
    let bundle = replace_certificate(&produced.bundle.bytes, &current);
    assert!(
        verify_report_expected(&bundle, &[key], None, None, Some(current.digest()),).is_err(),
        "an outer pin cannot establish an unsupported replacement identity law"
    );
}
