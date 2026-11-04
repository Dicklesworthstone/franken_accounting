//! fa-80es: an attested register is an exact entity cell at its own day,
//! backed by gross period activity. Different claims cannot overwrite it.

use super::*;
use fa_journal::attestation::{
    Attestation, AttestationClaim, CapabilityBinding, RegisterEqualsClaim, StoredAttestation,
    Subject,
};
use fa_lantern::cutoff::{DamagesAttestedBaseline, ReconAttestedRegisterCompare};
use fa_lantern::snapshot::SnapshotEntry;

fn procedures() -> [Box<dyn Procedure>; 2] {
    [
        Box::new(ReconAttestedRegisterCompare::new().unwrap()),
        Box::new(DamagesAttestedBaseline::new().unwrap()),
    ]
}

fn declare(h: &Harness, snapshot: &mut Snapshot, code: &str) -> VId {
    let value = fa_model::entity_value_vid(h.book.book_id, code);
    snapshot.declared_entities.insert(code.into(), value);
    value
}

#[allow(clippy::too_many_arguments)]
fn posting(
    h: &mut Harness,
    id: u128,
    recorded: u64,
    date: DateDay,
    amount: i128,
    entity: Option<VId>,
    reverses: Option<&SnapshotEntry>,
) -> SnapshotEntry {
    let period = h.period_code(date);
    let unit = h.usd;
    let mut entry = make_snapshot_entry(
        h,
        VId(id),
        CommitSeq(recorded),
        date,
        &period,
        if reverses.is_some() {
            EntryClass::REVERSAL
        } else {
            // Isolate attested comparisons from the explicitly separate
            // original-lineage fallback, which is exercised below.
            EntryClass::ADJUSTING
        },
        vec![
            (
                "6000",
                if amount > 0 {
                    Side::Debit
                } else {
                    Side::Credit
                },
                unit,
                amount.abs(),
            ),
            (
                "2000",
                if amount > 0 {
                    Side::Credit
                } else {
                    Side::Debit
                },
                unit,
                amount.abs(),
            ),
        ],
        reverses
            .map(|target| fa_model::Supersession {
                target: fa_model::EntryRef {
                    vid: target.vid,
                    entry_digest: target.entry.entry_digest,
                },
                kind: SupersessionKind::Reverses,
                reason_code: 1,
            })
            .into_iter()
            .collect(),
        None,
        None,
        None,
        Vec::new(),
    );
    if let Some(value) = entity {
        let mut proposal = entry.entry.proposal;
        for leg in &mut proposal.legs {
            leg.dimension_set = vec![(fa_model::LEGAL_ENTITY_DIMENSION, value)];
        }
        entry.entry = proposal.seal(Vec::new(), None).unwrap();
    }
    entry
}

fn claim(h: &Harness, date: DateDay, entity: Option<&str>, mantissa: i128) -> RegisterEqualsClaim {
    RegisterEqualsClaim {
        account: h.account("2000"),
        unit_id: h.usd.0,
        period: h.period_code(date),
        entity: entity.map(str::to_string),
        mantissa,
        as_of_effective: date,
        evaluated_known_at: CommitSeq(10),
        fold_digest: [0xAB; 32],
    }
}

fn attest(h: &Harness, snapshot: &mut Snapshot, id: u128, claim: RegisterEqualsClaim) {
    let subject = Subject::Cell(claim.cell_digest());
    snapshot.attestations.insert(
        VId(id),
        StoredAttestation {
            attestation: Attestation {
                book_id: h.book.book_id,
                claim: AttestationClaim::RegisterEquals(claim),
                subject,
                principal: REVIEWER,
                evidence_refs: Vec::new(),
            },
            signed_digest: [0xCD; 32],
            binding: CapabilityBinding {
                profile: Profile::Human,
                capability_commitment: [0xEF; 32],
            },
            signature: None,
        },
    );
}

#[test]
fn attested_baselines_preserve_entities_and_every_distinct_attestation() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    // Declared entities alone determine register cells; informational REA
    // entities are not needed to make either declaration effective.
    let alpha = declare(&h, &mut snapshot, "ALPHA");
    let beta = declare(&h, &mut snapshot, "BETA");
    snapshot.entries = vec![
        posting(
            &mut h,
            96_001,
            10,
            day(2026, 1, 5),
            50_000,
            Some(alpha),
            None,
        ),
        posting(
            &mut h,
            96_002,
            10,
            day(2026, 1, 5),
            30_000,
            Some(beta),
            None,
        ),
    ];
    attest(
        &h,
        &mut snapshot,
        97_001,
        claim(&h, day(2026, 1, 31), Some("ALPHA"), -50_000),
    );
    attest(
        &h,
        &mut snapshot,
        97_002,
        claim(&h, day(2026, 1, 31), Some("BETA"), -30_000),
    );
    for procedure in procedures() {
        let run = run_over(&snapshot, &h.book, procedure.as_ref()).unwrap();
        assert_eq!(run.version, 2);
        assert!(
            run.findings.is_empty(),
            "{}: {:?}",
            procedure.id(),
            run.findings
        );
    }

    // A later attestation of the same cell cannot overwrite an earlier
    // discrepant one, even when it has the higher vertex id and prefix.
    attest(
        &h,
        &mut snapshot,
        97_003,
        claim(&h, day(2026, 1, 31), Some("ALPHA"), -40_000),
    );
    let mut later = claim(&h, day(2026, 1, 31), Some("ALPHA"), -50_000);
    later.evaluated_known_at = CommitSeq(20);
    attest(&h, &mut snapshot, 97_004, later);
    for procedure in procedures() {
        let budget = fa_lantern::default_budget(procedure.id(), &snapshot).unwrap();
        let run = fa_lantern::run_over_metered(
            &snapshot,
            &h.book,
            procedure.as_ref(),
            Some(budget),
            None,
        )
        .unwrap();
        assert_eq!(
            run.findings.len(),
            1,
            "{}: {:?}",
            procedure.id(),
            run.findings
        );
        assert_eq!(run.findings[0].statistic.value, 10_000);
        assert_eq!(
            run.findings[0].cites,
            vec![
                Cite::Attestation(VId(97_003)),
                Cite::Account(h.account("2000")),
                Cite::Period(h.period_code(day(2026, 1, 31))),
                Cite::Entry(VId(96_001)),
            ]
        );
        assert!(run.findings[0].narrative.contains("entity ALPHA"));
        witness::determinism(&snapshot, &h.book, procedure.as_ref()).unwrap();
    }
}

#[test]
fn attested_gross_periods_keep_each_day_across_reversal_chains() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    let original = posting(&mut h, 96_011, 10, day(2026, 1, 5), 5_000, None, None);
    let reversal = posting(
        &mut h,
        96_012,
        20,
        day(2026, 1, 15),
        -5_000,
        None,
        Some(&original),
    );
    let restored = posting(
        &mut h,
        96_013,
        30,
        day(2026, 2, 1),
        5_000,
        None,
        Some(&reversal),
    );
    snapshot.entries = vec![original, reversal, restored];
    for (id, date, value) in [
        (97_011, day(2026, 1, 10), -5_000),
        (97_012, day(2026, 1, 20), 0),
        (97_013, day(2026, 1, 31), 0),
        (97_014, day(2026, 2, 28), -5_000),
    ] {
        attest(&h, &mut snapshot, id, claim(&h, date, None, value));
    }
    for procedure in procedures() {
        let run = run_over(&snapshot, &h.book, procedure.as_ref()).unwrap();
        assert!(
            run.findings.is_empty(),
            "{}: {:?}",
            procedure.id(),
            run.findings
        );
    }
    attest(
        &h,
        &mut snapshot,
        97_015,
        claim(&h, day(2026, 1, 20), None, -5_000),
    );
    for procedure in procedures() {
        let run = run_over(&snapshot, &h.book, procedure.as_ref()).unwrap();
        assert_eq!(
            run.findings.len(),
            1,
            "{}: {:?}",
            procedure.id(),
            run.findings
        );
        assert_eq!(run.findings[0].statistic.value, 5_000);
        assert_eq!(
            run.findings[0].cites,
            vec![
                Cite::Attestation(VId(97_015)),
                Cite::Account(h.account("2000")),
                Cite::Period(h.period_code(day(2026, 1, 20))),
                Cite::Entry(VId(96_011)),
                Cite::Entry(VId(96_012)),
            ]
        );
        witness::determinism(&snapshot, &h.book, procedure.as_ref()).unwrap();
    }
    // A report cutoff selects claims; it cannot make a January 20 baseline
    // masquerade as a January 10 claim by truncating that claim's fold.
    snapshot.coordinate.effective_through = Some(day(2026, 1, 10));
    for procedure in procedures() {
        assert!(
            run_over(&snapshot, &h.book, procedure.as_ref())
                .unwrap()
                .findings
                .is_empty()
        );
    }
}

#[test]
fn entity_dimension_unassigned_cells_units_and_future_activity_do_not_leak() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    let alpha = declare(&h, &mut snapshot, "ALPHA");
    let beta = declare(&h, &mut snapshot, "BETA");
    for code in ["2000", "6000"] {
        snapshot
            .accounts
            .get_mut(&h.account(code))
            .unwrap()
            .unit_policy = UnitPolicy::AnyCurrency;
    }
    let mut other_dimension = posting(&mut h, 96_023, 11, day(2026, 1, 10), 700, None, None);
    let mut proposal = other_dimension.entry.proposal;
    for leg in &mut proposal.legs {
        leg.dimension_set = vec![(fa_model::PARTY_DIMENSION, alpha)];
    }
    other_dimension.entry = proposal.seal(Vec::new(), None).unwrap();
    let eur = h.book.units.lookup("EUR").unwrap();
    let mut other_unit = posting(&mut h, 96_024, 12, day(2026, 1, 10), 900, Some(alpha), None);
    let mut proposal = other_unit.entry.proposal;
    for leg in &mut proposal.legs {
        leg.amount.unit = eur;
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    other_unit.entry = proposal.seal(Vec::new(), None).unwrap();
    snapshot.entries = vec![
        posting(
            &mut h,
            96_021,
            10,
            day(2026, 1, 5),
            5_000,
            Some(alpha),
            None,
        ),
        posting(&mut h, 96_022, 10, day(2026, 1, 5), 3_000, Some(beta), None),
        other_dimension,
        other_unit,
        posting(&mut h, 96_025, 13, day(2026, 1, 25), 300, Some(alpha), None),
    ];
    for (id, entity, value) in [
        (97_021, Some("ALPHA"), -5_000),
        (97_022, Some("BETA"), -3_000),
        (97_023, None, -700),
    ] {
        attest(
            &h,
            &mut snapshot,
            id,
            claim(&h, day(2026, 1, 20), entity, value),
        );
    }
    let mut euro_claim = claim(&h, day(2026, 1, 20), Some("ALPHA"), -900);
    euro_claim.unit_id = eur.0;
    attest(&h, &mut snapshot, 97_024, euro_claim);
    for procedure in procedures() {
        let run = run_over(&snapshot, &h.book, procedure.as_ref()).unwrap();
        assert!(
            run.findings.is_empty(),
            "{}: {:?}",
            procedure.id(),
            run.findings
        );
    }
    attest(
        &h,
        &mut snapshot,
        97_025,
        claim(&h, day(2026, 1, 31), Some("ALPHA"), -5_000),
    );
    for procedure in procedures() {
        let run = run_over(&snapshot, &h.book, procedure.as_ref()).unwrap();
        assert_eq!(
            run.findings.len(),
            1,
            "{}: {:?}",
            procedure.id(),
            run.findings
        );
        assert_eq!(run.findings[0].statistic.value, 300);
        assert_eq!(
            run.findings[0].cites,
            vec![
                Cite::Attestation(VId(97_025)),
                Cite::Account(h.account("2000")),
                Cite::Period(h.period_code(day(2026, 1, 31))),
                Cite::Entry(VId(96_021)),
                Cite::Entry(VId(96_025)),
            ]
        );
    }
}

#[test]
fn sole_declared_entity_is_implicit_but_absent_claim_entity_is_never_a_wildcard() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    declare(&h, &mut snapshot, "ALPHA");
    snapshot.entries = vec![posting(
        &mut h,
        96_031,
        10,
        day(2026, 1, 5),
        5_000,
        None,
        None,
    )];
    attest(
        &h,
        &mut snapshot,
        97_031,
        claim(&h, day(2026, 1, 31), Some("ALPHA"), -5_000),
    );
    attest(
        &h,
        &mut snapshot,
        97_032,
        claim(&h, day(2026, 1, 31), None, 0),
    );
    for procedure in procedures() {
        let run = run_over(&snapshot, &h.book, procedure.as_ref()).unwrap();
        assert!(
            run.findings.is_empty(),
            "{}: {:?}",
            procedure.id(),
            run.findings
        );
    }
    attest(
        &h,
        &mut snapshot,
        97_033,
        claim(&h, day(2026, 1, 31), None, -5_000),
    );
    for procedure in procedures() {
        let run = run_over(&snapshot, &h.book, procedure.as_ref()).unwrap();
        assert_eq!(run.findings.len(), 1);
        assert_eq!(run.findings[0].statistic.value, 5_000);
        assert_eq!(run.findings[0].cites[0], Cite::Attestation(VId(97_033)));
        assert!(!run.findings[0].cites.contains(&Cite::Entry(VId(96_031))));
    }
}

#[test]
fn informational_entity_metadata_cannot_turn_an_unknown_claim_into_a_wildcard() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    let alpha = declare(&h, &mut snapshot, "ALPHA");
    snapshot.entries = vec![posting(
        &mut h,
        96_041,
        10,
        day(2026, 1, 5),
        5_000,
        Some(alpha),
        None,
    )];
    let vid = VId(98_041);
    snapshot.rea.legal_entities.insert(
        vid,
        fa_journal::rea::LegalEntityRow {
            vid,
            dimension_value_vid: fa_model::entity_value_vid(h.book.book_id, "INFORMATIONAL"),
            code: "INFORMATIONAL".into(),
            name: "Informational entity, not a declared balancing entity".into(),
            jurisdiction: "US".into(),
            functional_unit: h.usd,
            formed: None,
            dissolved: None,
            external_ids: Vec::new(),
            created_at: CommitSeq(1),
        },
    );
    attest(
        &h,
        &mut snapshot,
        97_041,
        claim(&h, day(2026, 1, 31), Some("INFORMATIONAL"), -5_000),
    );
    for procedure in procedures() {
        let error = run_over(&snapshot, &h.book, procedure.as_ref()).unwrap_err();
        assert!(
            matches!(error, LanternError::Parameter { name, message, .. }
            if name == "attestation" && message.contains("does not declare"))
        );
    }
}

#[test]
fn original_lineage_fallback_stays_separate_and_respects_entity_and_report_day() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    let alpha = declare(&h, &mut snapshot, "ALPHA");
    let beta = declare(&h, &mut snapshot, "BETA");
    let original = |mut entry: SnapshotEntry| {
        let mut proposal = entry.entry.proposal;
        proposal.class = EntryClass::ORIGINAL;
        entry.entry = proposal.seal(Vec::new(), None).unwrap();
        entry
    };
    let alpha_original = original(posting(
        &mut h,
        96_051,
        10,
        day(2026, 1, 5),
        5_000,
        Some(alpha),
        None,
    ));
    let beta_original = original(posting(
        &mut h,
        96_052,
        10,
        day(2026, 1, 5),
        3_000,
        Some(beta),
        None,
    ));
    let reversed = posting(
        &mut h,
        96_053,
        20,
        day(2026, 1, 20),
        -5_000,
        Some(alpha),
        Some(&alpha_original),
    );
    snapshot.entries = vec![alpha_original, beta_original, reversed];
    attest(
        &h,
        &mut snapshot,
        97_051,
        claim(&h, day(2026, 1, 31), Some("BETA"), -3_000),
    );
    let procedure = DamagesAttestedBaseline::new().unwrap();
    let run = run_over(&snapshot, &h.book, &procedure).unwrap();
    assert_eq!(run.findings.len(), 2, "{:?}", run.findings);
    assert!(run.findings.iter().all(|finding| {
        finding.statistic.value == 5_000
            && finding.narrative.contains("baseline=original_lineage")
            && finding.narrative.contains("entity ALPHA")
            && !finding.cites.contains(&Cite::Entry(VId(96_052)))
            && !finding.cites.contains(&Cite::Attestation(VId(97_051)))
    }));
    // ALPHA's correct gross claim now supplies this account's baseline; it
    // does not suppress the other account's separate lineage observation.
    attest(
        &h,
        &mut snapshot,
        97_052,
        claim(&h, day(2026, 1, 31), Some("ALPHA"), 0),
    );
    let run = run_over(&snapshot, &h.book, &procedure).unwrap();
    assert_eq!(run.findings.len(), 1);
    assert!(
        run.findings[0]
            .cites
            .contains(&Cite::Account(h.account("6000")))
    );
    snapshot.coordinate.effective_through = Some(day(2026, 1, 10));
    let earlier = run_over(&snapshot, &h.book, &procedure).unwrap();
    assert!(earlier.findings.is_empty(), "{:?}", earlier.findings);
    witness::determinism(&snapshot, &h.book, &procedure).unwrap();
}

#[test]
fn a_register_comparison_cannot_silently_omit_its_participating_entries() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    let template = posting(&mut h, 100_000, 10, day(2026, 1, 5), 1, None, None);
    snapshot.entries = (0..fa_lantern::MAX_CITES)
        .map(|n| {
            let mut entry = template.clone();
            entry.vid = VId(100_000 + n as u128);
            entry
        })
        .collect();
    attest(
        &h,
        &mut snapshot,
        97_061,
        claim(&h, day(2026, 1, 31), None, 0),
    );
    for procedure in procedures() {
        let error = run_over(&snapshot, &h.book, procedure.as_ref()).unwrap_err();
        assert!(
            matches!(error, LanternError::Parameter { name, message, .. }
            if name == "citations" && message.contains("no partial run"))
        );
    }
}
