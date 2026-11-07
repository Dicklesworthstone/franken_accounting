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
        leg.settles.clear();
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    proposal
}

fn reverse(f: &mut Fixture, source: VId, key: &[u8], date: u8) -> VId {
    let proposal = reversal(f, source, key, date);
    post(f, proposal)
}

fn replace(
    f: &mut Fixture,
    source: VId,
    key: &[u8],
    undo_day: u8,
    corrected_day: u8,
    amount: i128,
) -> (VId, VId) {
    let undo = reversal(f, source, &[key, b":undo"].concat(), undo_day);
    let mut corrected = template(f, source, key, corrected_day);
    corrected.class = EntryClass::REPLACEMENT;
    corrected.supersession = vec![fa_model::Supersession {
        target: undo.supersession[0].target,
        kind: fa_model::SupersessionKind::Replaces,
        reason_code: 1,
    }];
    for leg in &mut corrected.legs {
        leg.amount.mantissa = amount;
        leg.settles.clear();
    }
    corrected.unit_totals = EntryPayload::fold_unit_totals(&corrected.legs).unwrap();
    let request = |proposal| PostRequest {
        proposal,
        approvals: Vec::new(),
        plan_certificate: None,
        capability: cap(&["post"]),
    };
    let cx = f.cx();
    let (undo, corrected) = f
        .runtime
        .block_on(
            f.book
                .post_replacement_pair(&cx, request(undo), request(corrected)),
        )
        .unwrap()
        .unwrap();
    (undo.entry_ref().vid, corrected.entry_ref().vid)
}

fn pay_corrected(f: &mut Fixture, corrected: VId) -> VId {
    let (entry, _) = f.book.read_entry(&f.cx(), corrected).unwrap().unwrap();
    let target = fa_model::EntryRef {
        vid: corrected,
        entry_digest: entry.entry_digest,
    };
    let mut proposal = template(f, corrected, b"offline-paid-correction", 30);
    proposal.class = EntryClass::ORIGINAL;
    proposal.supersession.clear();
    proposal.legs = vec![
        LegPayload::simple(Side::Credit, f.id("1000"), Amount::new(f.unit, 50_000)),
        LegPayload::simple(Side::Debit, f.id("1010"), Amount::new(f.unit, 50_000)),
    ];
    proposal.legs[0].settles.push(fa_model::Settlement {
        target,
        ordinal: 1,
        amount: Amount::new(f.unit, 50_000),
    });
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
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
fn native_replay_classifies_invalid_retained_parameters_as_verification() {
    let mut f = Fixture::new(127);
    let (source, _) = f.post(31, "3000", "1000", 100_000, false);
    let head = f.head();
    for (id, parameter, invalid_values) in [
        (
            "jet.round_amounts",
            "round_power",
            vec![-1, 31, i128::from(u32::MAX) + 1],
        ),
        (
            "jet.period_end_timing",
            "window_days",
            vec![-1, i128::from(u32::MAX) + 1],
        ),
    ] {
        let request = f.request(id, source);
        let certified = f.certify(&request);
        assert_eq!(
            f.book
                .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &certified.certificate)
                .unwrap()
                .unwrap(),
            certified.report,
            "valid native replay: {id}"
        );
        for value in invalid_values {
            let mut fresh_request = request.clone();
            fresh_request.parameters = fresh_request.parameters.set(parameter, value).unwrap();
            let usage = f
                .book
                .certify_procedure(
                    &f.cx(),
                    PRINCIPAL,
                    &cap(&["read", "produce"]),
                    &fresh_request,
                )
                .expect_err("a new invalid request is still a caller error");
            assert_eq!(usage.exit(), exit::USAGE, "new {id}: {value}");
            assert!(matches!(
                usage,
                BookError::Lantern(fa_lantern::LanternError::Parameter { name, .. })
                    if name == parameter
            ));

            let mut forged = certified.certificate.clone();
            assert_eq!(forged.report.parameters[0].0, parameter);
            forged.report.parameters[0].1 = value;
            // Repair every enclosing checksum: the rejection must come
            // from executing the retained parameters, not integrity framing.
            reseal(&mut forged);
            let decoded = ProcedureCertificate::decode(&forged.canonical_bytes().unwrap()).unwrap();
            let refusal = f
                .book
                .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &decoded)
                .expect("invalid retained parameters are a typed verification refusal")
                .unwrap_err();
            assert_eq!(refusal.exit, exit::VERIFICATION, "retained {id}: {value}");
            assert_eq!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
            assert!(refusal.message.contains(parameter));
            assert_eq!(f.head(), head, "neither path may publish");
        }
    }
}

fn cutoff_request(f: &Fixture, procedure: &str, through: Option<u8>) -> ProcedureRequest {
    let mut request = ProcedureRequest::new(procedure, catalog::Inputs::default()).unwrap();
    request.known_at = Some(f.head());
    request.effective_through = through.map(day);
    request
}

#[test]
fn retained_registry_closures_match_the_published_baseline_and_replay_old_versions() {
    // Independently hashed the exact git objects at 383e7108d5755ad1eff6bbb9569c7c758be22f52.
    // Keep both the canonical closure and the pre-canonical raw-text contract.
    let hex = |digest: [u8; 32]| {
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    assert_eq!(
        hex(retained_registry_digest().unwrap()),
        "2665c0983ceae1dbfea287404ff767774d0eb66838ce6718a1ce714a29d02783"
    );
    assert_eq!(
        hex(retained_legacy_registry_digest().unwrap()),
        "ac6da88181fe324ea7298fb65566c5ec7f7ebb568ae1f49fbd977fe71cbd2bab"
    );
    let mut f = Fixture::new(126);
    f.post(31, "3000", "1000", 100_000, false);
    for id in ["jet.round_amounts", "jet.period_end_timing", "jet.weekend"] {
        let mut request = cutoff_request(&f, id, None);
        request.version = Some(1);
        let certified = f.certify(&request);
        for registry in [
            retained_registry_digest().unwrap(),
            retained_legacy_registry_digest().unwrap(),
        ] {
            let mut retained = certified.certificate.clone();
            retained.registry = registry;
            reseal(&mut retained);
            let replayed = f
                .book
                .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &retained)
                .unwrap()
                .unwrap();
            assert_eq!(
                replayed, certified.report,
                "retained {id}@1 must not use the current algorithm"
            );
            if registry == retained_legacy_registry_digest().unwrap() {
                assert!(
                    retained.check_offline_profile().is_err(),
                    "raw-text closures remain native-only"
                );
            }
        }
    }
}

#[test]
fn effective_cutoffs_replay_before_reversal_liveness_at_the_original_known_at() {
    for (seed, id) in [(122, "jet.round_amounts"), (123, "jet.period_end_timing")] {
        let mut f = Fixture::new(seed);
        let (original, _) = f.post(29, "3000", "1000", 100_000, false);
        let (future, _) = f.post(31, "3000", "1000", 200_000, false);
        let historical = f.certify(&cutoff_request(&f, id, Some(29)));
        let historical_at = f.head();
        let reversal = reverse(&mut f, original, b"cutoff-reversal", 30);
        reverse(&mut f, reversal, b"cutoff-restoration", 31);
        let frontier = f.head();
        let runs: Vec<_> = [(28, 0), (29, 1), (30, 0), (31, 2)]
            .into_iter()
            .map(|(through, expected)| {
                (
                    through,
                    expected,
                    f.certify(&cutoff_request(&f, id, Some(through))),
                )
            })
            .collect();
        let mut legacy_request = cutoff_request(&f, id, None);
        legacy_request.version = Some(1);
        let legacy = f.certify(&legacy_request);
        assert_eq!(legacy.report.version, 1);
        assert_eq!(legacy.report.work.entries, 2);
        assert!(
            legacy
                .report
                .findings
                .iter()
                .all(|finding| finding.version == 1)
        );
        assert!(matches!(
            f.book.procedure_certificate_status(&f.cx(), PRINCIPAL, &cap(&["read"]), &legacy.certificate)
                .unwrap().unwrap(),
            ProcedureCertificateStatus::Current { checked_at } if checked_at == frontier
        ));

        // A subsequently recorded backdated entry and the later reversals are
        // in the signed checkpoint, but cannot enter an earlier known-at view.
        f.post(29, "3000", "1000", 300_000, false);
        let key = f.book.checkpoint_public_key();
        let produced = produce(&mut f, &historical.certificate);
        let verified = verify(&produced, &historical.certificate, key);
        assert_eq!(verified.known_at, historical_at.0);
        assert!(verified.checkpoint.checkpoint.through_seq > frontier.0);
        assert_eq!(verified.procedure.as_ref().unwrap().live_entries, 1);
        assert_eq!(
            verified.procedure.as_ref().unwrap().findings[0].entry,
            original.0
        );

        let mut input_digests = BTreeSet::new();
        let population = runs[0].2.report.population;
        for (through, expected, certified) in runs {
            assert_eq!(certified.report.population, population);
            let native = f
                .book
                .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &certified.certificate)
                .unwrap()
                .unwrap();
            assert_eq!(native, certified.report);
            let produced = produce(&mut f, &certified.certificate);
            let verified = verify(&produced, &certified.certificate, key);
            assert_eq!(verified.known_at, frontier.0);
            assert_eq!(verified.effective_through, Some(day(through).0));
            let procedure = verified.procedure.unwrap();
            assert_eq!(procedure.version, 2);
            assert_eq!(procedure.effective_through, Some(day(through).0));
            assert_eq!(procedure.population, population);
            assert!(
                population > procedure.live_entries,
                "undated controls remain in the closure"
            );
            assert_eq!(procedure.live_entries, expected);
            assert_eq!(procedure.findings.len() as u64, expected);
            assert!(input_digests.insert(procedure.inputs_digest));
            if through == 29 {
                let command = fa_verify::cli::run(
                    &[
                        "report".into(),
                        "cutoff.fab".into(),
                        "--key".into(),
                        key.iter().map(|byte| format!("{byte:02x}")).collect(),
                        "--receipt".into(),
                        "cutoff.receipt".into(),
                        "--json".into(),
                    ],
                    &|path| match path {
                        "cutoff.fab" => Ok(produced.bundle.bytes.clone()),
                        "cutoff.receipt" => Ok(produced.receipt.clone()),
                        _ => Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "unexpected input",
                        )),
                    },
                );
                assert_eq!(command.exit, 0, "{}", command.stdout);
                assert!(
                    command
                        .stdout
                        .contains(&format!("\"effective_through\":{}", day(29).0))
                );
                assert!(command.stdout.contains("\"version\":2"));
            }
            if through == 31 {
                assert_eq!(
                    procedure
                        .findings
                        .iter()
                        .map(|finding| finding.entry)
                        .collect::<BTreeSet<_>>(),
                    BTreeSet::from([original.0, future.0]),
                );
            }
        }
        let produced = produce(&mut f, &legacy.certificate);
        let verified = verify(&produced, &legacy.certificate, key);
        assert_eq!(verified.effective_through, None);
        let procedure = verified.procedure.unwrap();
        assert_eq!(procedure.version, 1);
        assert_eq!(procedure.live_entries, 2);
        assert_eq!(decode_run(&verified.output).unwrap(), legacy.report);
    }
}

#[test]
fn repaired_effective_cutoff_outputs_cannot_hide_reversals_future_entries_or_controls() {
    for (seed, id) in [(124, "jet.round_amounts"), (125, "jet.period_end_timing")] {
        let mut f = Fixture::new(seed);
        let (original, _) = f.post(29, "3000", "1000", 100_000, false);
        let (future, _) = f.post(31, "3000", "1000", 200_000, false);
        reverse(&mut f, original, b"hostile-cutoff-reversal", 30);
        let certified = f.certify(&cutoff_request(&f, id, Some(29)));
        let later = f.certify(&cutoff_request(&f, id, Some(30)));
        assert_eq!(certified.report.findings.len(), 1);
        assert!(later.report.findings.is_empty());
        let produced = produce(&mut f, &certified.certificate);
        let key = f.book.checkpoint_public_key();
        verify(&produced, &certified.certificate, key);
        for variant in [
            "changed cutoff",
            "out-of-window reversal",
            "future entry omitted",
            "controls omitted",
        ] {
            let mut forged = certified.certificate.clone();
            match variant {
                "changed cutoff" => {
                    forged.report.coordinate.effective_through =
                        later.report.coordinate.effective_through;
                    forged.report.inputs_digest = later.report.inputs_digest;
                }
                "out-of-window reversal" => {
                    forged.report.findings = later.report.findings.clone();
                    forged.report.work = later.report.work;
                }
                _ => {
                    // Re-run the real producer over a deliberately incomplete
                    // population and repair every input/decision/output hash.
                    // The independent verifier still has the complete prefix.
                    let cx = f.cx();
                    forged.report = f
                        .book
                        .query(&cx, |db, book| {
                            let mut snapshot = Snapshot::read(
                                db,
                                &cx.query(),
                                book,
                                Some(certified.certificate.known_at()),
                                Some(day(29)),
                            )?;
                            snapshot.entries.retain(|entry| {
                                if variant == "future entry omitted" {
                                    entry.vid != future
                                } else {
                                    !entry.entry.proposal.legs.is_empty()
                                }
                            });
                            let mut inputs = Writer::new();
                            inputs.u64(snapshot.coordinate.known_at.0).opt(
                                snapshot.coordinate.effective_through.as_ref(),
                                |w, through| {
                                    w.i32(through.0);
                                },
                            );
                            inputs.list(&snapshot.entries, |w, entry| {
                                w.u128(entry.vid.0)
                                    .fixed(&entry.entry.entry_digest)
                                    .u64(entry.recorded_at.0);
                            });
                            snapshot.inputs_digest =
                                raw_digest(b"fa:lantern-inputs:v1", &inputs.finish().unwrap());
                            let method = catalog::build(
                                id,
                                Params::defaults(id)?,
                                catalog::Inputs::default(),
                            )?;
                            Ok(fa_lantern::run_over_metered(
                                &snapshot,
                                book,
                                method.as_ref(),
                                None,
                                Some(&cx.query()),
                            )?)
                        })
                        .unwrap();
                }
            }
            reseal(&mut forged);
            let bundle = replace_certificate(&produced.bundle.bytes, &forged);
            let error = verify_report_expected(&bundle, &[key], None, None, Some(forged.digest()))
                .expect_err(variant);
            assert_eq!(
                error.predicate, "procedure_recomputation",
                "{id} {variant}: {error}"
            );
        }
    }
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
    let mut handles = ordinary.clone();
    handles
        .report
        .inputs
        .push(("account".into(), format!("{:032x}", f.id("1000").0)));
    reseal(&mut handles);
    let mut legacy_cutoff = ordinary.clone();
    legacy_cutoff.registry = retained_registry_digest().unwrap();
    legacy_cutoff.report.version = 1;
    legacy_cutoff.report.coordinate.effective_through = Some(day(5));
    for finding in &mut legacy_cutoff.report.findings {
        finding.version = 1;
    }
    reseal(&mut legacy_cutoff);
    let other = f.certify(&f.request("jet.weekend", source)).certificate;
    let produced = produce(&mut f, &ordinary);
    let key = f.book.checkpoint_public_key();
    let cx = f.cx();
    let before = f.head();
    for unsupported in [&handles, &legacy_cutoff, &other] {
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
                forged.report.version = 3;
                for finding in &mut forged.report.findings {
                    finding.version = 3;
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
    for (capability, expected_code) in [
        (cap(&["read"]), "FA-REF-011"),
        (cap(&["produce"]), "FA-REF-011"),
        (
            cap(&["read", "produce"]).for_accounts(&["1000"]).unwrap(),
            "FA-REF-011",
        ),
        (
            cap(&["read", "produce"]).known_at_most(ordinary.known_at()),
            "FA-REF-011",
        ),
        // Expiry has its own registered refusal; it must still precede
        // certificate replay and checkpoint selection, including bad inputs.
        (cap(&["read", "produce"]).expiring_at(before), "FA-REF-014"),
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
                assert_eq!((refusal.code, refusal.exit), (expected_code, exit::SAFETY));
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
fn round_amounts_refuses_unreferenced_replacements_but_preserves_earlier_certificates() {
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

#[test]
fn corrected_and_paid_procedures_resolve_identity_at_known_at_before_filtering_dates() {
    let mut f = Fixture::new(121);
    let (original, _) = f.post(27, "3000", "1000", 100_000, false);
    let (_, corrected) = replace(&mut f, original, b"offline-paid-pair", 28, 29, 200_000);
    let unresolved: Vec<_> = ["jet.round_amounts", "jet.period_end_timing"]
        .into_iter()
        .map(|id| f.certify(&cutoff_request(&f, id, Some(29))).certificate)
        .collect();
    let payment = pay_corrected(&mut f, corrected);
    let frontier = f.head();
    let cases: Vec<_> = ["jet.round_amounts", "jet.period_end_timing"]
        .into_iter()
        .flat_map(|id| {
            [27, 28, 29, 30]
                .into_iter()
                .map(|through| {
                    (
                        id,
                        through,
                        f.certify(&cutoff_request(&f, id, Some(through))),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let versions: Vec<_> = ["jet.round_amounts", "jet.period_end_timing"]
        .into_iter()
        .flat_map(|id| {
            [1, 2]
                .into_iter()
                .map(|version| {
                    let mut request = cutoff_request(&f, id, None);
                    request.version = Some(version);
                    f.certify(&request)
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let key = f.book.checkpoint_public_key();
    for (id, through, certified) in cases {
        let produced = produce(&mut f, &certified.certificate);
        let result = verify(&produced, &certified.certificate, key);
        let procedure = result.procedure.as_ref().unwrap();
        assert_eq!(result.known_at, frontier.0);
        assert_eq!(
            procedure.live_entries,
            match through {
                28 => 0,
                30 => 2,
                _ => 1,
            }
        );
        let expected = match (id, through) {
            ("jet.round_amounts", 27) => vec![original.0],
            (_, 29) | ("jet.round_amounts", 30) => vec![corrected.0],
            ("jet.period_end_timing", 30) => vec![corrected.0, payment.0],
            _ => Vec::new(),
        };
        assert_eq!(
            procedure
                .findings
                .iter()
                .map(|finding| finding.entry)
                .collect::<BTreeSet<_>>(),
            expected.into_iter().collect()
        );
        if through == 29 {
            // The signed later payment resolves the canonical VID while its
            // day-30 monetary effects remain outside this inclusive cutoff.
            assert_eq!(procedure.findings[0].entry, corrected.0);
            let historical = unresolved
                .iter()
                .find(|cert| cert.report.procedure == id)
                .unwrap();
            let before = f.head();
            let cx = f.cx();
            let refusal = f
                .runtime
                .block_on(f.book.produce_procedure_report_bundle(
                    &cx,
                    PRINCIPAL,
                    &cap(&["read", "produce"]),
                    None,
                    historical,
                ))
                .unwrap()
                .unwrap_err();
            assert_eq!(refusal.code, fa_notary::code::SCOPE_UNSUPPORTED);
            assert!(refusal.message.contains("no authenticated later reference"));
            assert_eq!(f.head(), before);
            for repaired_output in [false, true] {
                let mut forged = historical.clone();
                if repaired_output {
                    forged.report.findings.clear();
                    forged.report.work = Work::default();
                    reseal(&mut forged);
                }
                let bundle = replace_certificate(&produced.bundle.bytes, &forged);
                let error =
                    verify_report_expected(&bundle, &[key], None, None, Some(forged.digest()))
                        .unwrap_err();
                assert_eq!(
                    error.predicate, "procedure_identity",
                    "{id}, repaired={repaired_output}: {error}"
                );
            }
        }
    }
    for certified in versions {
        let produced = produce(&mut f, &certified.certificate);
        let result = verify(&produced, &certified.certificate, key);
        assert_eq!(
            result.procedure.as_ref().unwrap().version,
            certified.report.version
        );
        assert_eq!(result.procedure.as_ref().unwrap().live_entries, 2);
    }
}

#[test]
fn corrected_procedures_replay_reversal_restoration_and_reject_rehashed_aliases() {
    let mut f = Fixture::new(122);
    let (original, _) = f.post(27, "3000", "1000", 100_000, false);
    let (paired_undo, corrected) =
        replace(&mut f, original, b"offline-restored-pair", 28, 29, 200_000);
    reverse(&mut f, paired_undo, b"offline-revive-original", 29);
    let undo_corrected = reverse(&mut f, corrected, b"offline-reverse-correction", 30);
    let historical: Vec<_> = ["jet.round_amounts", "jet.period_end_timing"]
        .into_iter()
        .map(|id| f.certify(&cutoff_request(&f, id, Some(31))))
        .collect();
    reverse(&mut f, undo_corrected, b"offline-restore-correction", 31);
    let cases: Vec<_> = ["jet.round_amounts", "jet.period_end_timing"]
        .into_iter()
        .flat_map(|id| {
            [27, 28, 29, 30, 31]
                .into_iter()
                .map(|through| {
                    (
                        id,
                        through,
                        f.certify(&cutoff_request(&f, id, Some(through))),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let key = f.book.checkpoint_public_key();
    for certified in historical {
        let produced = produce(&mut f, &certified.certificate);
        let result = verify(&produced, &certified.certificate, key);
        let procedure = result.procedure.as_ref().unwrap();
        assert_eq!(procedure.live_entries, 1);
        let expected = if procedure.procedure == "jet.round_amounts" {
            vec![original.0]
        } else {
            Vec::new()
        };
        assert_eq!(
            procedure
                .findings
                .iter()
                .map(|finding| finding.entry)
                .collect::<Vec<_>>(),
            expected
        );
    }
    for (id, through, certified) in cases {
        let produced = produce(&mut f, &certified.certificate);
        let result = verify(&produced, &certified.certificate, key);
        let procedure = result.procedure.as_ref().unwrap();
        assert_eq!(procedure.live_entries, u64::from(through != 28));
        let expected = match (id, through) {
            (_, 29 | 31) => vec![corrected.0],
            ("jet.round_amounts", 27 | 30) => vec![original.0],
            _ => Vec::new(),
        };
        assert_eq!(
            procedure
                .findings
                .iter()
                .map(|finding| finding.entry)
                .collect::<Vec<_>>(),
            expected
        );
        if through != 31 {
            continue;
        }
        for variant in [
            "legacy alias",
            "missing paired reversal",
            "missing identity witness",
        ] {
            let mut forged = certified.certificate.clone();
            let cx = f.cx();
            forged.report = f
                .book
                .query(&cx, |db, book| {
                    let mut snapshot = Snapshot::read(
                        db,
                        &cx.query(),
                        book,
                        Some(certified.certificate.known_at()),
                        Some(day(31)),
                    )?;
                    match variant {
                        "legacy alias" => {
                            let target = snapshot
                                .entries
                                .iter_mut()
                                .find(|entry| entry.vid == corrected)
                                .unwrap();
                            target.vid = fa_model::entry_vid(
                                target.entry.proposal.book_id,
                                &target.entry.proposal.principal_ref.0.to_le_bytes(),
                                &target.entry.proposal.idempotency_key,
                            );
                        }
                        "missing paired reversal" => {
                            snapshot.entries.retain(|entry| entry.vid != paired_undo)
                        }
                        "missing identity witness" => {
                            snapshot.entries.retain(|entry| entry.vid != undo_corrected)
                        }
                        _ => unreachable!(),
                    }
                    snapshot.entries.sort_by_key(|entry| entry.vid);
                    let mut inputs = Writer::new();
                    inputs.u64(snapshot.coordinate.known_at.0).opt(
                        snapshot.coordinate.effective_through.as_ref(),
                        |w, through| {
                            w.i32(through.0);
                        },
                    );
                    inputs.list(&snapshot.entries, |w, entry| {
                        w.u128(entry.vid.0)
                            .fixed(&entry.entry.entry_digest)
                            .u64(entry.recorded_at.0);
                    });
                    snapshot.inputs_digest =
                        raw_digest(b"fa:lantern-inputs:v1", &inputs.finish().unwrap());
                    let method =
                        catalog::build(id, Params::defaults(id)?, catalog::Inputs::default())?;
                    Ok(fa_lantern::run_over_metered(
                        &snapshot,
                        book,
                        method.as_ref(),
                        None,
                        Some(&cx.query()),
                    )?)
                })
                .unwrap();
            reseal(&mut forged);
            let bundle = replace_certificate(&produced.bundle.bytes, &forged);
            let error = verify_report_expected(&bundle, &[key], None, None, Some(forged.digest()))
                .expect_err(variant);
            assert_eq!(
                error.predicate, "procedure_recomputation",
                "{id} {variant}: {error}"
            );
        }
    }
}

fn timing_request(f: &Fixture, window_days: i128) -> ProcedureRequest {
    let mut request =
        ProcedureRequest::new("jet.period_end_timing", catalog::Inputs::default()).unwrap();
    request.parameters = request.parameters.set("window_days", window_days).unwrap();
    request.known_at = Some(f.head());
    request
}

#[test]
fn period_end_timing_reconstructs_historical_periods_liveness_and_exact_citations() {
    let mut f = Fixture::new(117);
    let (outside, _) = f.post(28, "3000", "1000", 100_000, false);
    let (boundary, _) = f.post(29, "3000", "1000", 99_999, false);
    let (middle, _) = f.post(30, "3000", "1000", 200_000, false);
    let (last, _) = f.post(31, "3000", "1000", 300_000, false);
    let (reversed, _) = f.post(31, "3000", "1000", 400_000, false);
    reverse(&mut f, reversed, b"timing-reverse", 31);
    let (restored, _) = f.post(31, "3000", "1000", 500_000, false);
    let undo = reverse(&mut f, restored, b"timing-first-undo", 30);
    reverse(&mut f, undo, b"timing-undo-the-undo", 31);
    let mut pending = template(&f, outside, b"timing-pending", 31);
    pending.class = EntryClass::PENDING;
    pending.pending = Some(fa_model::Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    let pending = post(&mut f, pending);
    let certified = f.certify(&timing_request(&f, 3));
    let original_at = f.head();
    let (later, _) = f.post(31, "3000", "1000", 600_000, false);
    reverse(&mut f, boundary, b"timing-later-reversal", 31);
    let produced = produce(&mut f, &certified.certificate);
    let key = f.book.checkpoint_public_key();
    let verified = verify(&produced, &certified.certificate, key);
    assert_eq!(verified.known_at, original_at.0);
    assert!(verified.checkpoint.checkpoint.through_seq > original_at.0);
    assert!(verified.open_items.is_none());
    let procedure = verified.procedure.as_ref().unwrap();
    assert_eq!(procedure.procedure, "jet.period_end_timing");
    assert_eq!(
        procedure.parameters,
        fa_verify::report::VerifiedProcedureParameters::PeriodEndTiming { window_days: 3 }
    );
    assert_eq!((procedure.live_entries, procedure.live_legs), (5, 0));
    let replayed = decode_run(&verified.output).unwrap();
    assert_eq!(replayed, certified.report);
    assert_eq!(replayed.evidence, "FA-EVID-L02");
    assert_eq!(replayed.parameters, vec![("window_days".into(), 3)]);
    assert_eq!(
        replayed.work,
        Work {
            entries: 5,
            legs: 0,
            comparisons: 0,
        }
    );
    assert_eq!(
        replayed
            .findings
            .iter()
            .map(|f| f.statistic.value)
            .collect::<Vec<_>>(),
        vec![2, 1, 0, 0]
    );
    for (entry, distance) in [(boundary, 2), (middle, 1), (last, 0), (restored, 0)] {
        let finding = replayed
            .findings
            .iter()
            .find(|finding| finding.cites.first() == Some(&Cite::Entry(entry)))
            .unwrap();
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.statistic.name, "days_to_period_end");
        assert_eq!(
            (finding.statistic.value, finding.statistic.population),
            (distance, 5)
        );
        assert_eq!(
            finding.cites,
            vec![Cite::Entry(entry), Cite::Period("FY2026-P01".into())]
        );
        assert_eq!(
            finding.narrative,
            format!("effective {distance} day(s) before the period's last day (window 3)")
        );
    }
    for entry in [outside, reversed, undo, pending, later] {
        assert!(
            replayed
                .findings
                .iter()
                .all(|finding| !finding.cites.contains(&Cite::Entry(entry)))
        );
    }
    let command = fa_verify::cli::run(
        &[
            "report".into(),
            "timing.fab".into(),
            "--key".into(),
            key.iter().map(|byte| format!("{byte:02x}")).collect(),
            "--receipt".into(),
            "timing.receipt".into(),
            "--json".into(),
        ],
        &|path| match path {
            "timing.fab" => Ok(produced.bundle.bytes.clone()),
            "timing.receipt" => Ok(produced.receipt.clone()),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "unexpected input",
            )),
        },
    );
    assert_eq!(command.exit, 0, "{}", command.stdout);
    assert!(
        command
            .stdout
            .contains("\"procedure\":\"jet.period_end_timing\"")
    );
    assert!(command.stdout.contains("\"evidence\":\"FA-EVID-L02\""));
    assert!(command.stdout.contains("\"window_days\":3"));
    assert!(command.stdout.contains("\"period\":\"FY2026-P01\""));
    assert_eq!(
        command
            .stdout
            .matches("\"check\":\"procedure_finding\"")
            .count(),
        4
    );
    assert!(!command.stdout.contains("\"round_power\""));
    assert!(!command.stdout.contains("\"leg_ordinals\""));
}

#[test]
fn period_end_timing_replays_zero_nondefault_windows_and_empty_findings() {
    let mut f = Fixture::new(118);
    let empty = f.certify(&timing_request(&f, 3));
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
    assert!(empty.population > 0);

    let (early, _) = f.post(1, "3000", "1000", 100, false);
    let (outside, _) = f.post(28, "3000", "1000", 99_999, false);
    let (boundary, _) = f.post(29, "3000", "1000", 200_000, false);
    let (last, _) = f.post(31, "3000", "1000", 300_000, false);
    for (window, expected) in [
        (0, vec![]),
        (1, vec![last]),
        (3, vec![boundary, last]),
        (i128::from(i32::MAX), vec![early, outside, boundary, last]),
        (
            i128::from(i32::MAX) + 1,
            vec![early, outside, boundary, last],
        ),
        (i128::from(u32::MAX), vec![early, outside, boundary, last]),
    ] {
        let certified = f.certify(&timing_request(&f, window));
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
        assert_eq!(replayed, certified.report);
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
        assert_eq!(replayed.parameters, vec![("window_days".into(), window)]);
        assert_eq!(
            replayed.work,
            Work {
                entries: 4,
                legs: 0,
                comparisons: 0,
            }
        );
    }
}

#[test]
fn repaired_period_end_outputs_cannot_omit_or_forge_findings_periods_or_decisions() {
    let mut f = Fixture::new(119);
    let (outside, _) = f.post(28, "3000", "1000", 100_000, false);
    f.post(29, "3000", "1000", 99_999, false);
    f.post(31, "3000", "1000", 200_000, false);
    let certified = f.certify(&timing_request(&f, 3));
    let produced = produce(&mut f, &certified.certificate);
    let key = f.book.checkpoint_public_key();
    verify(&produced, &certified.certificate, key);
    for variant in [
        "omitted finding",
        "false positive",
        "distance",
        "period citation",
        "missing citation",
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
            "false positive" => run.findings[0].cites[0] = Cite::Entry(outside),
            "distance" => run.findings[0].statistic.value += 1,
            "period citation" => run.findings[0].cites[1] = Cite::Period("FY2026-P02".into()),
            "missing citation" => {
                run.findings[0].cites.pop();
            }
            "wrong severity" => run.findings[0].severity = Severity::Medium,
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
        // Repaired digests and a fresh outer pin must not replace replay.
        let error = verify_report_expected(&bundle, &[key], None, None, Some(forged.digest()))
            .expect_err(variant);
        assert_eq!(
            error.predicate, "procedure_recomputation",
            "{variant}: {error}"
        );
    }
    for variant in [
        "negative window",
        "altered legal window",
        "oversized window",
        "wrong parameter",
        "wrong evidence",
    ] {
        let mut forged = certified.certificate.clone();
        match variant {
            "negative window" => forged.report.parameters[0].1 = -1,
            // This original forgery is in the registered domain, but its
            // retained findings and decision card still describe window 3.
            "altered legal window" => forged.report.parameters[0].1 = i128::from(i32::MAX) + 1,
            "oversized window" => forged.report.parameters[0].1 = i128::from(u32::MAX) + 1,
            "wrong parameter" => forged.report.parameters[0].0 = "round_power".into(),
            "wrong evidence" => forged.report.evidence = "FA-EVID-L01".into(),
            _ => unreachable!(),
        }
        reseal(&mut forged);
        let bundle = replace_certificate(&produced.bundle.bytes, &forged);
        let checked = verify_report_expected(&bundle, &[key], None, None, Some(forged.digest()));
        assert!(checked.is_err(), "{variant}");
        if matches!(variant, "altered legal window" | "oversized window") {
            assert_eq!(
                checked.unwrap_err().predicate,
                if variant == "altered legal window" {
                    "procedure_recomputation"
                } else {
                    "procedure_profile"
                },
                "{variant}"
            );
        }
    }
}

#[test]
fn period_end_timing_requires_complete_signed_history_and_an_authenticated_closure() {
    let mut f = Fixture::new(120);
    f.post(31, "3000", "1000", 100_000, false);
    let certified = f.certify(&timing_request(&f, 3));
    let produced = produce(&mut f, &certified.certificate);
    let key = f.book.checkpoint_public_key();
    assert!(
        verify_report_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            None,
            Some(certified.certificate.digest()),
        )
        .is_ok()
    );
    assert!(
        verify_report_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            Some(&produced.receipt),
            None,
        )
        .is_ok()
    );
    assert!(verify_report_expected(&produced.bundle.bytes, &[key], None, None, None).is_err());
    assert!(
        verify_report_expected(
            &produced.bundle.bytes,
            &[],
            None,
            Some(&produced.receipt),
            Some(certified.certificate.digest()),
        )
        .is_err()
    );

    let bytes = &produced.bundle.bytes;
    let mut reader = Reader::new(bytes);
    reader.bytes(64, "format").unwrap();
    reader.u16("major").unwrap();
    reader.u16("minor").unwrap();
    reader
        .bytes(MAX_PROCEDURE_CERTIFICATE_BYTES, "certificate")
        .unwrap();
    reader
        .bytes(MAX_PROCEDURE_CERTIFICATE_BYTES, "checkpoint")
        .unwrap();
    reader
        .bytes(MAX_PROCEDURE_CERTIFICATE_BYTES, "prefix")
        .unwrap();
    let count_offset = reader.offset();
    let count = reader.u32("records").unwrap();
    assert!(count > 0);
    reader.u32("proposal length").unwrap();
    reader
        .bytes(MAX_PROCEDURE_CERTIFICATE_BYTES, "first record")
        .unwrap();
    let first_end = reader.offset();
    let mut writer = Writer::new();
    writer
        .fixed(&bytes[..count_offset])
        .u32(count - 1)
        .fixed(&bytes[first_end..]);
    let omitted = writer.finish().unwrap();
    let mut altered = bytes.clone();
    altered[first_end - 1] ^= 1;
    for changed in [omitted, altered] {
        assert!(
            verify_report_expected(
                &changed,
                &[key],
                None,
                None,
                Some(certified.certificate.digest()),
            )
            .is_err(),
            "period and posting facts must come from every authenticated record"
        );
    }
}

#[test]
fn period_end_timing_uses_each_authenticated_months_own_end_and_citation() {
    let mut f = Fixture::new(121);
    let (source, _) = f.post(1, "3000", "1000", 100_000, false);
    let cx = f.cx();
    f.runtime
        .block_on(f.book.transition_period(
            &cx,
            "FY2026-P02",
            PeriodTransition::Open,
            PRINCIPAL,
            1,
            b"timing-open-february",
            &cap(&["close"]),
        ))
        .unwrap()
        .unwrap();
    let mut expected = Vec::new();
    for date in [25, 26, 27, 28] {
        let mut proposal = template(&f, source, format!("timing-february-{date}").as_bytes(), 1);
        proposal.effective_date = DateDay::from_ymd(2026, 2, date).unwrap();
        let entry = post(&mut f, proposal);
        if date >= 26 {
            expected.push((entry, i128::from(28 - date)));
        }
    }
    let certified = f.certify(&timing_request(&f, 3));
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
    assert_eq!(replayed, certified.report);
    assert_eq!(replayed.work.entries, 5);
    assert_eq!(replayed.findings.len(), expected.len());
    for (entry, distance) in expected {
        let finding = replayed
            .findings
            .iter()
            .find(|finding| finding.cites.first() == Some(&Cite::Entry(entry)))
            .unwrap();
        assert_eq!(finding.statistic.value, distance);
        assert_eq!(finding.statistic.population, 5);
        assert_eq!(
            finding.cites,
            vec![Cite::Entry(entry), Cite::Period("FY2026-P02".into())]
        );
    }
}
