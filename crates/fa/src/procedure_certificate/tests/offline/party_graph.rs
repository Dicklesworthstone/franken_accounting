//! PAID procedures must replay from the complete historical journal after
//! the producer book is gone, including parties hidden by one clearing GL.

use super::*;
use fa_verify::report::{VerifiedProcedureParameters, VerifiedProcedureStatistic};

fn party(f: &mut Fixture, code: &str) {
    let cx = f.cx();
    let spec = fa_model::PartySpec {
        code: code.into(),
        kind: fa_model::PartyKind::Vendor,
        name: f.book.seal_text(&cx, code).unwrap(),
        identifiers: Vec::new(),
        external_ids: Vec::new(),
    };
    f.runtime
        .block_on(f.book.create_party(
            &cx,
            &spec,
            PRINCIPAL,
            day(1),
            code.as_bytes(),
            &cap(&["schema_change"]),
        ))
        .unwrap()
        .unwrap();
}

fn fixture(seed: u8) -> (Fixture, VId) {
    let mut f = Fixture::new(seed);
    for code in ["SHELL-A", "SHELL-B", "SHELL-C", "SHELL-D"] {
        party(&mut f, code);
    }
    let (source, _) = f.post(1, "3000", "1000", 1, false);
    (f, source)
}

fn movement(
    f: &mut Fixture,
    source: VId,
    key: &[u8],
    date: u8,
    unit: fa_money::UnitId,
    legs: &[(Side, i128, Option<&str>)],
) -> VId {
    let mut proposal = template(f, source, key, date);
    proposal.legs = legs
        .iter()
        .map(|&(side, amount, party)| {
            let mut leg = LegPayload::simple(side, f.id("1010"), Amount::new(unit, amount));
            if let Some(code) = party {
                leg.dimension_set.push((
                    fa_model::PARTY_DIMENSION,
                    fa_model::party_value_vid(f.book.context().book_id, code),
                ));
            }
            leg
        })
        .collect();
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    post(f, proposal)
}

fn transfer(
    f: &mut Fixture,
    source: VId,
    key: &[u8],
    date: u8,
    from: &str,
    to: &str,
    amount: i128,
) -> VId {
    let unit = f.unit;
    movement(
        f,
        source,
        key,
        date,
        unit,
        &[
            (Side::Credit, amount, Some(from)),
            (Side::Debit, amount, Some(to)),
        ],
    )
}

fn request(f: &Fixture, id: &str) -> ProcedureRequest {
    let mut request = ProcedureRequest::new(id, catalog::Inputs::default()).unwrap();
    request.known_at = Some(f.head());
    request
}

fn export(f: &mut Fixture, certified: &CertifiedProcedure) -> crate::ProducedBundle {
    assert_eq!(
        certified.certificate.format(),
        EXTENDED_PROCEDURE_CERTIFICATE_FORMAT
    );
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

fn check(
    produced: &crate::ProducedBundle,
    certified: &CertifiedProcedure,
    key: [u8; 32],
) -> fa_verify::report::VerifiedProcedure {
    let verified = verify(produced, &certified.certificate, key);
    assert_eq!(decode_run(&verified.output).unwrap(), certified.report);
    let run = verified.procedure.unwrap();
    assert_eq!(
        (run.live_entries, run.live_legs, run.comparisons),
        (
            certified.report.work.entries,
            certified.report.work.legs,
            certified.report.work.comparisons
        )
    );
    run
}

#[test]
fn paid_graphs_export_clearing_account_paths_historical_parties_and_reversal_liveness() {
    for (seed, id, last) in [
        (181, "graph.party_circular_flows", "SHELL-A"),
        (182, "graph.party_layering", "SHELL-D"),
    ] {
        let (mut f, source) = fixture(seed);
        let first = transfer(&mut f, source, b"paid-first", 2, "SHELL-A", "SHELL-B", 1000);
        let second = transfer(&mut f, source, b"paid-second", 3, "SHELL-B", "SHELL-C", 900);
        let third = transfer(&mut f, source, b"paid-third", 4, "SHELL-C", last, 810);
        let unit = f.unit;
        movement(
            &mut f,
            source,
            b"paid-anonymous",
            5,
            unit,
            &[(Side::Credit, 50, None), (Side::Debit, 50, None)],
        );
        transfer(&mut f, source, b"paid-self", 5, "SHELL-A", "SHELL-A", 50);
        let account_id = if id == "graph.party_circular_flows" {
            "graph.circular_flows"
        } else {
            "graph.layering"
        };
        assert!(
            f.certify(&request(&f, account_id))
                .report
                .findings
                .is_empty()
        );
        let certified = f.certify(&request(&f, id));
        assert_eq!(certified.report.findings.len(), 1);
        assert_eq!(certified.report.findings[0].statistic.value, 810);
        assert_eq!(certified.report.findings[0].statistic.population, 3);
        assert_eq!(
            certified.report.findings[0].cites,
            [Cite::Entry(first), Cite::Entry(second), Cite::Entry(third)]
        );
        assert!(certified.report.findings[0].narrative.contains(&format!(
            "through parties SHELL-A -> SHELL-B -> SHELL-C -> {last}"
        )));
        let historical = certified.report.coordinate.known_at;
        let undo = reverse(&mut f, first, b"paid-reverse", 20);
        let reversed = f.certify(&request(&f, id));
        assert!(reversed.report.findings.is_empty());
        reverse(&mut f, undo, b"paid-restore", 21);
        let restored = f.certify(&request(&f, id));
        assert_eq!(restored.report.findings, certified.report.findings);
        party(&mut f, "LATER-PARTY");
        let mut historical_request = request(&f, id);
        historical_request.known_at = Some(historical);
        assert_eq!(f.certify(&historical_request).report, certified.report);
        let key = f.book.checkpoint_public_key();
        let artifacts: Vec<_> = [certified, reversed, restored]
            .into_iter()
            .map(|certified| {
                let produced = export(&mut f, &certified);
                (produced, certified)
            })
            .collect();
        drop(f);
        for (produced, certified) in artifacts {
            let run = check(&produced, &certified, key);
            assert!(matches!(
                run.parameters,
                VerifiedProcedureParameters::GraphPartyCircularFlows { .. }
                    | VerifiedProcedureParameters::GraphPartyLayering { .. }
            ));
            assert!(run.findings.iter().all(|finding| matches!(
                finding.statistic,
                VerifiedProcedureStatistic::PartyCircularFlow { .. }
                    | VerifiedProcedureStatistic::PartyLayeredFlow { .. }
            )));
        }
    }
}

#[test]
fn paid_layering_advances_same_day_recording_order_and_preserves_shortcut_paths() {
    let (mut f, source) = fixture(183);
    transfer(&mut f, source, b"paid-start", 2, "SHELL-A", "SHELL-B", 1000);
    let earlier = transfer(
        &mut f,
        source,
        b"paid-too-early",
        3,
        "SHELL-C",
        "SHELL-D",
        810,
    );
    transfer(&mut f, source, b"paid-middle", 3, "SHELL-B", "SHELL-C", 900);
    let none = f.certify(&request(&f, "graph.party_layering"));
    assert!(none.report.findings.is_empty());
    transfer(
        &mut f,
        source,
        b"paid-terminal",
        3,
        "SHELL-C",
        "SHELL-D",
        810,
    );
    transfer(
        &mut f,
        source,
        b"paid-shortcut",
        3,
        "SHELL-A",
        "SHELL-D",
        1000,
    );
    let found = f.certify(&request(&f, "graph.party_layering"));
    assert_eq!(found.report.findings.len(), 1);
    assert!(
        !found.report.findings[0]
            .cites
            .contains(&Cite::Entry(earlier))
    );
    let key = f.book.checkpoint_public_key();
    let empty = export(&mut f, &none);
    let produced = export(&mut f, &found);
    drop(f);
    assert!(check(&empty, &none, key).findings.is_empty());
    assert_eq!(check(&produced, &found, key).findings.len(), 1);
}

#[test]
fn paid_split_allocations_book_nodes_and_native_units_reproduce_offline() {
    let (mut f, source) = fixture(184);
    let usd = f.unit;
    movement(
        &mut f,
        source,
        b"paid-split",
        2,
        usd,
        &[
            (Side::Credit, 100, Some("SHELL-A")),
            (Side::Credit, 100, Some("SHELL-B")),
            (Side::Debit, 100, Some("SHELL-C")),
            (Side::Debit, 100, Some("SHELL-D")),
        ],
    );
    transfer(
        &mut f,
        source,
        b"paid-split-close-c",
        3,
        "SHELL-C",
        "SHELL-A",
        90,
    );
    transfer(
        &mut f,
        source,
        b"paid-split-close-d",
        3,
        "SHELL-D",
        "SHELL-B",
        90,
    );
    let yen = f.book.context().units.lookup("JPY").unwrap();
    for (key, date, from, to) in [
        (b"paid-yen-out".as_slice(), 4, Some("SHELL-A"), None),
        (b"paid-yen-book".as_slice(), 5, None, Some("SHELL-B")),
        (
            b"paid-yen-back".as_slice(),
            6,
            Some("SHELL-B"),
            Some("SHELL-A"),
        ),
    ] {
        movement(
            &mut f,
            source,
            key,
            date,
            yen,
            &[(Side::Credit, 80, from), (Side::Debit, 80, to)],
        );
    }
    let certified = f.certify(&request(&f, "graph.party_circular_flows"));
    assert!(certified.report.findings.iter().any(|finding| {
        finding.statistic.scale == 0
            && finding
                .narrative
                .contains("SHELL-A -> book -> SHELL-B -> SHELL-A")
    }));
    assert!(
        certified
            .report
            .findings
            .iter()
            .any(|finding| finding.statistic.scale == 2)
    );
    let key = f.book.checkpoint_public_key();
    let produced = export(&mut f, &certified);
    drop(f);
    let run = check(&produced, &certified, key);
    assert!(run.findings.iter().any(|finding| matches!(finding.statistic, VerifiedProcedureStatistic::PartyCircularFlow { unit, scale:0, .. } if unit == yen.0)));
}

#[test]
fn paid_graph_bundles_reject_resealed_names_citations_counts_parameters_and_omissions() {
    for (seed, id, last) in [
        (185, "graph.party_circular_flows", "SHELL-A"),
        (186, "graph.party_layering", "SHELL-D"),
    ] {
        let (mut f, source) = fixture(seed);
        let first = transfer(
            &mut f,
            source,
            b"paid-tamper-first",
            2,
            "SHELL-A",
            "SHELL-B",
            1000,
        );
        transfer(
            &mut f,
            source,
            b"paid-tamper-second",
            3,
            "SHELL-B",
            "SHELL-C",
            900,
        );
        transfer(
            &mut f,
            source,
            b"paid-tamper-third",
            4,
            "SHELL-C",
            last,
            810,
        );
        let certified = f.certify(&request(&f, id));
        assert_eq!(certified.report.findings.len(), 1);
        let produced = export(&mut f, &certified);
        let key = f.book.checkpoint_public_key();
        check(&produced, &certified, key);
        for variant in [
            "amount",
            "names",
            "entry",
            "account",
            "population",
            "comparisons",
            "legs",
            "entries",
            "omitted",
            "witness",
            "chronology",
            "window",
        ] {
            let mut forged = certified.certificate.clone();
            let report = &mut forged.report;
            match variant {
                "amount" => report.findings[0].statistic.value += 1,
                "names" => {
                    report.findings[0].narrative =
                        report.findings[0].narrative.replace("SHELL-A", "FORGED-A")
                }
                "entry" => report.findings[0].cites[0] = Cite::Entry(source),
                "account" => report.findings[0].cites.push(Cite::Account(f.id("1010"))),
                "population" => report.findings[0].statistic.population += 1,
                "comparisons" => report.work.comparisons += 1,
                "legs" => report.work.legs += 1,
                "entries" => report.work.entries += 1,
                "omitted" => report.findings.clear(),
                "witness" => report.findings[0].narrative.push_str(" forged"),
                "chronology" => report.findings[0].cites.swap(0, 1),
                "window" => {
                    report
                        .parameters
                        .iter_mut()
                        .find(|(name, _)| name == "window_days")
                        .unwrap()
                        .1 = 0
                }
                _ => unreachable!(),
            }
            reseal(&mut forged);
            let bytes = replace_certificate(&produced.bundle.bytes, &forged);
            assert_eq!(
                verify_report_expected(&bytes, &[key], None, None, Some(forged.digest()))
                    .unwrap_err()
                    .predicate,
                "procedure_recomputation",
                "{id}: {variant}"
            );
        }
        for variant in ["historical-version", "cutoff", "party-handle", "hop-bound"] {
            let mut forged = certified.certificate.clone();
            match variant {
                "historical-version" => {
                    let version = if id == "graph.party_layering" { 2 } else { 1 };
                    forged.report.version = version;
                    for finding in &mut forged.report.findings {
                        finding.version = version;
                    }
                }
                "cutoff" => forged.report.coordinate.effective_through = Some(day(4)),
                "party-handle" => forged
                    .report
                    .inputs
                    .push(("party".into(), "SHELL-A".into())),
                "hop-bound" => {
                    forged
                        .report
                        .parameters
                        .iter_mut()
                        .find(|(name, _)| name.ends_with("hops"))
                        .unwrap()
                        .1 = 9
                }
                _ => unreachable!(),
            }
            assert!(forged.check_offline_profile().is_err());
            reseal(&mut forged);
            let bytes = replace_certificate(&produced.bundle.bytes, &forged);
            assert_eq!(
                verify_report_expected(&bytes, &[key], None, None, Some(forged.digest()))
                    .unwrap_err()
                    .predicate,
                "procedure_profile",
                "{id}: {variant}"
            );
        }
        let digest = f
            .book
            .read_entry(&f.cx(), first)
            .unwrap()
            .unwrap()
            .0
            .entry_digest;
        let omitted = super::portable_graph::omit_posting(&produced, digest);
        assert_eq!(
            verify_report_expected(
                &omitted,
                &[key],
                None,
                None,
                Some(certified.certificate.digest())
            )
            .unwrap_err()
            .predicate,
            "record_completeness"
        );
    }
}
