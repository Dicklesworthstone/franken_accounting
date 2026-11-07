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
        assert!(
            witness::determinism(&snapshot, &h.book, procedure.as_ref())
                .unwrap()
                .deterministic()
        );
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
        assert!(
            witness::determinism(&snapshot, &h.book, procedure.as_ref())
                .unwrap()
                .deterministic()
        );
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
    assert!(
        witness::determinism(&snapshot, &h.book, &procedure)
            .unwrap()
            .deterministic()
    );
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

fn instrument(snapshot: &mut Snapshot, id: u128, account: VId, unit: UnitId) {
    snapshot.rea.instruments.insert(
        VId(id),
        fa_journal::rea::InstrumentRow {
            vid: VId(id),
            code: format!("BANK-{id}"),
            name: "unit consistency witness".into(),
            kind: fa_model::InstrumentKind::BankAccount,
            unit,
            held_at_party: PREPARER,
            mirrors_account: account,
            external_ids: Vec::new(),
            created_at: CommitSeq(1),
        },
    );
}

/// The original instrument-by-entry-by-leg loop, including unique entry counts
/// and the earliest bounded citations. This intentionally retains its scan cost.
fn literal_instrument_findings(snapshot: &Snapshot) -> (Vec<Finding>, u64) {
    let mut live = snapshot
        .live_postings_through(snapshot.coordinate.effective_through)
        .unwrap();
    live.sort_by_key(|entry| entry.vid);
    let population = (snapshot.attestations.len() + snapshot.rea.instruments.len()) as u64;
    let mut findings = Vec::new();
    let mut entries_read = 0;
    for instrument in snapshot.rea.instruments.values() {
        let mut entries = Vec::new();
        for entry in &live {
            entries_read += 1;
            for leg in &entry.entry.proposal.legs {
                if leg.account_ref == instrument.mirrors_account
                    && leg.amount.unit != instrument.unit
                {
                    entries.push(entry.vid);
                }
            }
        }
        entries.sort_unstable();
        entries.dedup();
        if !entries.is_empty() {
            let count = entries.len() as u64;
            let mut cites = vec![Cite::Account(instrument.mirrors_account)];
            cites.extend(
                entries
                    .into_iter()
                    .take(fa_lantern::MAX_CITES - 1)
                    .map(Cite::Entry),
            );
            findings.push(Finding {
                procedure: ReconAttestedRegisterCompare::ID.into(),
                version: 2,
                severity: Severity::Critical,
                statistic: Statistic::count("instrument_unit_mismatch_entries", count, population.max(1)),
                cites,
                narrative: format!(
                    "instrument {} mirrors account in unit {}, but {count} posting(s) use a different unit",
                    instrument.code, instrument.unit.0
                ),
            });
        }
    }
    (findings, entries_read)
}

#[test]
fn instrument_unit_index_matches_literal_findings_across_units_entries_and_history() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    snapshot.entries.clear();
    let usd = h.usd;
    let foreign = UnitId(usd.0 + 1);
    let other = UnitId(usd.0 + 2);
    let expense = h.account("6000");
    for (id, account, unit) in [
        (5001, expense, usd),
        (5002, expense, foreign),
        (5003, expense, other),
        (5004, h.account("2000"), usd),
        (5005, h.account("1000"), usd),
        (5006, h.account("1010"), foreign),
    ] {
        instrument(&mut snapshot, id, account, unit);
    }
    let original = posting(&mut h, 1001, 10, day(2026, 1, 5), 100, None, None);
    snapshot.entries.push(original.clone());
    let mut changed = posting(&mut h, 1002, 11, day(2026, 1, 10), 100, None, None);
    for leg in &mut changed.entry.proposal.legs {
        leg.amount.unit = foreign;
    }
    snapshot.entries.push(changed.clone());
    // Multiple source rows for one VID still count once. Their combined
    // units make this entry disagree with either individual expected unit.
    let mut repeated = changed.clone();
    for leg in &mut repeated.entry.proposal.legs {
        leg.amount.unit = usd;
    }
    snapshot.entries.push(repeated);
    let mut mixed = posting(&mut h, 1003, 12, day(2026, 1, 15), 100, None, None);
    mixed.entry.proposal.legs.extend([
        LegPayload::simple(Side::Debit, expense, Amount::new(foreign, 100)),
        LegPayload::simple(Side::Credit, h.account("2000"), Amount::new(foreign, 100)),
        LegPayload::simple(Side::Debit, expense, Amount::new(usd, 100)),
        LegPayload::simple(Side::Credit, expense, Amount::new(usd, 100)),
    ]);
    snapshot.entries.push(mixed);
    let mut same = posting(&mut h, 1004, 13, day(2026, 1, 20), 100, None, None);
    same.entry.proposal.legs[1].account_ref = expense;
    snapshot.entries.push(same);
    let mut elsewhere = posting(&mut h, 1005, 14, day(2026, 1, 25), 100, None, None);
    elsewhere.entry.proposal.legs[0].account_ref = h.account("1000");
    for leg in &mut elsewhere.entry.proposal.legs {
        leg.amount.unit = other;
    }
    snapshot.entries.push(elsewhere);
    let mut source = changed.clone();
    source.vid = VId(1006);
    source.entry.proposal.effective_date = day(2026, 1, 5);
    let mut reversal = posting(
        &mut h,
        1007,
        15,
        day(2026, 1, 20),
        -100,
        None,
        Some(&source),
    );
    for leg in &mut reversal.entry.proposal.legs {
        leg.amount.unit = foreign;
    }
    snapshot.entries.extend([source, reversal]);
    let mut replacement = changed.clone();
    replacement.vid = VId(1008);
    replacement.entry.proposal.class = EntryClass::REPLACEMENT;
    replacement.entry.proposal.effective_date = day(2026, 1, 25);
    replacement
        .entry
        .proposal
        .supersession
        .push(fa_model::Supersession {
            target: fa_model::EntryRef {
                vid: original.vid,
                entry_digest: original.entry.entry_digest,
            },
            kind: SupersessionKind::Replaces,
            reason_code: 1,
        });
    snapshot.entries.push(replacement);
    // Irrelevant malformed schema controls must not be newly interpreted by
    // an index that only consumes the already-selected live posting legs.
    let mut control = original.clone();
    control.vid = VId(1009);
    control.entry.proposal.class = EntryClass::SCHEMA_CONTROL;
    control.entry.proposal.legs.clear();
    control.entry.proposal.control = Some(fa_model::ControlPayload::SchemaChange {
        kind: fa_model::rea::SCHEMA_CHANGE_UPDATE_PARTY_IDENTIFIERS,
        canonical_bytes: vec![0xff],
    });
    snapshot.entries.push(control);
    let mut empty_claim = claim(&h, day(2026, 1, 31), None, 0);
    empty_claim.account = h.account("1010");
    attest(&h, &mut snapshot, 6001, empty_claim);
    let procedure = ReconAttestedRegisterCompare::new().unwrap();
    for through in [None, Some(day(2026, 1, 10)), Some(day(2026, 1, 20))] {
        snapshot.coordinate.effective_through = through;
        let (expected, _) = literal_instrument_findings(&snapshot);
        assert!(!expected.is_empty());
        for order in 0..3 {
            let mut work = Meter::new(ReconAttestedRegisterCompare::ID, None, None);
            assert_eq!(
                procedure.run(&snapshot, &h.book, &mut work).unwrap(),
                expected,
                "through={through:?} order={order}"
            );
            if order == 0 {
                snapshot.entries.reverse();
            } else {
                snapshot.entries.rotate_left(3);
            }
        }
    }
}

#[test]
fn instrument_unit_index_keeps_exact_counts_and_earliest_bounded_citations() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    let template = posting(&mut h, 100_000, 10, day(2026, 1, 5), 1, None, None);
    let foreign = UnitId(h.usd.0 + 1);
    let n = 2 * fa_lantern::MAX_CITES + 17;
    snapshot.entries = (0..n)
        .map(|i| {
            let mut entry = template.clone();
            entry.vid = VId(100_000 + i as u128);
            if i % 3 != 0 {
                for leg in &mut entry.entry.proposal.legs {
                    leg.amount.unit = foreign;
                }
            }
            entry
        })
        .collect();
    for (id, unit) in [
        (9001, h.usd),
        (9002, foreign),
        (9003, UnitId(foreign.0 + 1)),
    ] {
        instrument(&mut snapshot, id, h.account("6000"), unit);
    }
    let (expected, _) = literal_instrument_findings(&snapshot);
    let mut work = Meter::new(ReconAttestedRegisterCompare::ID, None, None);
    let actual = ReconAttestedRegisterCompare::new()
        .unwrap()
        .run(&snapshot, &h.book, &mut work)
        .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(actual[0].cites.len(), fa_lantern::MAX_CITES);
    assert!(actual[0].statistic.value > (fa_lantern::MAX_CITES - 1) as i128);
    assert_eq!(actual[2].statistic.value, n as i128);
    assert_eq!(
        actual[2].cites.last(),
        Some(&Cite::Entry(VId(
            100_000 + (fa_lantern::MAX_CITES - 2) as u128
        )))
    );
}

fn instrument_population(h: &mut Harness, n: u64) -> Snapshot {
    let mut snapshot = h.snapshot();
    let mut template = posting(h, 1_000_000, 10, day(2026, 1, 5), 1, None, None);
    template.entry.proposal.legs[1].account_ref = h.account("1000");
    snapshot.entries = (0..n)
        .map(|i| {
            let mut entry = template.clone();
            entry.vid = VId(1_000_000 + u128::from(i));
            entry
        })
        .collect();
    for i in 0..n {
        instrument(
            &mut snapshot,
            3_000_000 + u128::from(i),
            h.account(if i % 997 == 0 { "6000" } else { "1000" }),
            h.usd,
        );
    }
    snapshot
}

fn plant_instrument_mismatch(h: &Harness, snapshot: &mut Snapshot) {
    let foreign = UnitId(h.usd.0 + 1);
    // A single discrepant entry after a large matching prefix. Both units
    // remain balanced, and the unmirrored clearing account needs no index.
    snapshot.entries.last_mut().unwrap().entry.proposal.legs = vec![
        LegPayload::simple(Side::Debit, h.account("6000"), Amount::new(foreign, 1)),
        LegPayload::simple(Side::Credit, h.account("2000"), Amount::new(foreign, 1)),
        LegPayload::simple(Side::Debit, h.account("1000"), Amount::new(h.usd, 1)),
        LegPayload::simple(Side::Credit, h.account("2000"), Amount::new(h.usd, 1)),
    ];
}

#[test]
fn hundred_thousand_instruments_do_not_rescan_hundred_thousand_entries() {
    const N: u64 = 100_000;
    let mut h = harness();
    let procedure = ReconAttestedRegisterCompare::new().unwrap();
    // The literal implementation remains live on a smaller population.
    let mut small = instrument_population(&mut h, 128);
    plant_instrument_mismatch(&h, &mut small);
    let (expected, old_entries) = literal_instrument_findings(&small);
    let mut work = Meter::new(ReconAttestedRegisterCompare::ID, None, None);
    assert_eq!(procedure.run(&small, &h.book, &mut work).unwrap(), expected);
    assert_eq!(old_entries, 128 * 128);
    assert_eq!(work.work().entries, 2 * 128);

    let mut snapshot = instrument_population(&mut h, N);
    let mut work = Meter::new(ReconAttestedRegisterCompare::ID, Some(80 * N), None);
    assert!(
        procedure
            .run(&snapshot, &h.book, &mut work)
            .unwrap()
            .is_empty()
    );
    assert_eq!(work.work().entries, 2 * N);
    assert_eq!(work.work().legs, 4 * N);
    assert!(work.work().comparisons <= 50 * N);

    plant_instrument_mismatch(&h, &mut snapshot);
    let mut work = Meter::new(ReconAttestedRegisterCompare::ID, Some(80 * N), None);
    let actual = procedure.run(&snapshot, &h.book, &mut work).unwrap();
    let expected: Vec<_> = (0..N).step_by(997).map(|i| Finding {
        procedure: ReconAttestedRegisterCompare::ID.into(),
        version: 2,
        severity: Severity::Critical,
        statistic: Statistic::count("instrument_unit_mismatch_entries", 1, N),
        cites: vec![Cite::Account(h.account("6000")), Cite::Entry(VId(1_000_000 + u128::from(N - 1)))],
        narrative: format!("instrument BANK-{} mirrors account in unit {}, but 1 posting(s) use a different unit", 3_000_000 + u128::from(i), h.usd.0),
    }).collect();
    assert_eq!(actual, expected);
    assert_eq!(work.work().entries, 2 * N);
    assert_eq!(work.work().legs, 4 * N + 4);
    assert!(work.work().comparisons <= 50 * N, "{:?}", work.work());
    assert!(
        work.work().within_registered_bound(
            &fa_lantern::bind(ReconAttestedRegisterCompare::ID)
                .unwrap()
                .complexity,
            &snapshot
        )
    );
}

#[test]
fn instrument_unit_index_dense_citations_fit_registered_comparison_bound() {
    const ENTRIES: u64 = 128;
    const INSTRUMENTS: u64 = 1024;
    let mut h = harness();
    let mut snapshot = instrument_population(&mut h, ENTRIES);
    snapshot.rea.instruments.clear();
    let foreign = UnitId(h.usd.0 + 1);
    for (i, entry) in snapshot.entries.iter_mut().enumerate() {
        if i % 2 != 0 {
            for leg in &mut entry.entry.proposal.legs {
                leg.amount.unit = foreign;
            }
        }
    }
    for i in 0..INSTRUMENTS {
        instrument(
            &mut snapshot,
            3_000_000 + u128::from(i),
            h.account("6000"),
            h.usd,
        );
    }
    let (expected, literal_entries) = literal_instrument_findings(&snapshot);
    let mut work = Meter::new(ReconAttestedRegisterCompare::ID, Some(500_000), None);
    let actual = ReconAttestedRegisterCompare::new()
        .unwrap()
        .run(&snapshot, &h.book, &mut work)
        .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), INSTRUMENTS as usize);
    assert!(actual.iter().all(|finding| {
        finding.statistic.value == i128::from(ENTRIES / 2)
            && finding.cites.len() == (ENTRIES / 2 + 1) as usize
    }));
    assert_eq!(literal_entries, ENTRIES * INSTRUMENTS);
    assert_eq!(work.work().entries, 2 * ENTRIES);
    assert_eq!(work.work().legs, 4 * ENTRIES);
    // The previous component bound charged instrument scans as entry/leg
    // visits and allowed only one comparison per instrument. It does not
    // cover the actual, now-metered bounded run and citation traversal.
    let previous_comparisons =
        4 * INSTRUMENTS * u64::from((INSTRUMENTS + 1).ilog2()) + 4 * ENTRIES + INSTRUMENTS;
    assert!(work.work().comparisons > previous_comparisons);
    assert!(
        work.work().within_registered_bound(
            &fa_lantern::bind(ReconAttestedRegisterCompare::ID)
                .unwrap()
                .complexity,
            &snapshot
        )
    );
}

#[test]
fn instrument_unit_index_obeys_budget_and_cancellation_during_preparation() {
    struct CancelAtCheck {
        checks: std::cell::Cell<u64>,
        at: u64,
    }
    impl fa_lantern::Cancellation for CancelAtCheck {
        fn cancelled(&self) -> bool {
            self.checks.set(self.checks.get() + 1);
            self.checks.get() >= self.at
        }
    }
    let mut h = harness();
    let mut snapshot = instrument_population(&mut h, 512);
    snapshot.rea.instruments.clear();
    let procedure = ReconAttestedRegisterCompare::new().unwrap();
    let observe = CancelAtCheck {
        checks: std::cell::Cell::new(0),
        at: u64::MAX,
    };
    let mut baseline = Meter::new(ReconAttestedRegisterCompare::ID, None, Some(&observe));
    assert!(
        procedure
            .run(&snapshot, &h.book, &mut baseline)
            .unwrap()
            .is_empty()
    );
    let baseline = baseline.work();
    for i in 0..1024 {
        instrument(&mut snapshot, 3_000_000 + i, h.account("6000"), h.usd);
    }
    let mut work = Meter::new(
        ReconAttestedRegisterCompare::ID,
        Some(baseline.total()),
        None,
    );
    assert!(
        matches!(procedure.run(&snapshot, &h.book, &mut work), Err(LanternError::BudgetExhausted { used, .. }) if used == baseline.total() + 1)
    );
    assert_eq!(work.work().entries, baseline.entries);
    assert_eq!(work.work().legs, baseline.legs);

    // Metadata indexing and the first live-entry visit fit. Refuse the first
    // additional leg, rather than silently running an unmetered preparation.
    let budget = baseline.total() + 1024 + 1;
    let mut work = Meter::new(ReconAttestedRegisterCompare::ID, Some(budget), None);
    assert!(
        matches!(procedure.run(&snapshot, &h.book, &mut work), Err(LanternError::BudgetExhausted { used, .. }) if used == budget + 1)
    );
    assert_eq!(work.work().entries, baseline.entries + 1);
    assert_eq!(work.work().legs, baseline.legs + 1);
    for extra_checks in [1, 2] {
        let cancel = CancelAtCheck {
            checks: std::cell::Cell::new(0),
            at: observe.checks.get() + extra_checks,
        };
        let mut work = Meter::new(ReconAttestedRegisterCompare::ID, None, Some(&cancel));
        assert!(
            matches!(procedure.run(&snapshot, &h.book, &mut work), Err(LanternError::Cancelled { used, .. }) if used > baseline.total())
        );
        if extra_checks == 1 {
            assert_eq!(work.work().entries, baseline.entries);
            assert_eq!(work.work().legs, baseline.legs);
        } else {
            assert!(work.work().entries > baseline.entries);
            assert!(work.work().legs > baseline.legs);
        }
    }
}

#[test]
fn instrument_unit_index_preserves_claim_and_lineage_refusal_order() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    let source = posting(&mut h, 1001, 10, day(2026, 1, 5), 100, None, None);
    let reverse_a = posting(&mut h, 1002, 11, day(2026, 1, 6), -100, None, Some(&source));
    let reverse_b = posting(&mut h, 1003, 12, day(2026, 1, 7), -100, None, Some(&source));
    snapshot.entries = vec![source, reverse_a, reverse_b];
    let procedure = ReconAttestedRegisterCompare::new().unwrap();
    // Liveness validation still runs even with no instruments to index.
    let mut work = Meter::new(ReconAttestedRegisterCompare::ID, None, None);
    assert!(
        matches!(procedure.run(&snapshot, &h.book, &mut work), Err(LanternError::Kernel(KernelError::Corrupt(message))) if message.contains("reversed twice"))
    );
    instrument(&mut snapshot, 5001, h.account("6000"), h.usd);
    attest(
        &h,
        &mut snapshot,
        6001,
        claim(&h, day(2026, 1, 31), Some("UNDECLARED"), 0),
    );
    let mut work = Meter::new(ReconAttestedRegisterCompare::ID, None, None);
    assert!(
        matches!(procedure.run(&snapshot, &h.book, &mut work), Err(LanternError::Parameter { name, .. }) if name == "attestation")
    );
}
