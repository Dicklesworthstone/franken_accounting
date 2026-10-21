//! Independent counterexamples to pooling native amounts or topology across
//! currency and legal-entity coordinates. Snapshot fixtures expose both the
//! positive motifs and the otherwise identical separated controls.

use super::*;
use fa_lantern::graph::{Communities, RelatedPartyExposure, ShellSignature};

const ENTITY_A: VId = VId(70_001);
const ENTITY_B: VId = VId(70_002);

fn reseal(entry: &mut fa_lantern::SnapshotEntry) {
    let mut proposal = entry.entry.proposal.clone();
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    entry.entry = proposal.seal(Vec::new(), None).unwrap();
}

fn transfer(
    h: &mut Harness,
    id: u64,
    accounts: (&str, &str),
    amount: Amount,
    entity: Option<VId>,
    documented: bool,
) -> fa_lantern::SnapshotEntry {
    let period = h.period_code(day(2026, 1, 5));
    let mut entry = make_snapshot_entry(
        h,
        VId(u128::from(id)),
        CommitSeq(id),
        day(2026, 1, 5),
        &period,
        EntryClass::ORIGINAL,
        vec![
            (accounts.0, Side::Credit, amount.unit, amount.mantissa),
            (accounts.1, Side::Debit, amount.unit, amount.mantissa),
        ],
        Vec::new(),
        None,
        None,
        None,
        Vec::new(),
    );
    if let Some(entity) = entity {
        for leg in &mut entry.entry.proposal.legs {
            leg.dimension_set
                .push((fa_model::LEGAL_ENTITY_DIMENSION, entity));
        }
    }
    if !documented {
        entry.entry.proposal.evidence.clear();
    }
    reseal(&mut entry);
    entry
}

fn related_party(h: &mut Harness, snapshot: &mut Snapshot) -> VId {
    let root = fa_model::party_vid(h.book.book_id, "PARENT");
    let affiliate = fa_model::party_vid(h.book.book_id, "AFFILIATE");
    for (vid, code) in [(root, "PARENT"), (affiliate, "AFFILIATE")] {
        snapshot.rea.parties.insert(
            vid,
            fa_journal::rea::PartyRow {
                vid,
                dimension_value_vid: fa_model::party_value_vid(h.book.book_id, code),
                code: code.into(),
                kind: fa_model::PartyKind::RelatedEntity,
                name: h.seal(code),
                identifiers: Vec::new(),
                external_ids: Vec::new(),
                created_at: CommitSeq(1),
            },
        );
    }
    snapshot
        .rea
        .relationships
        .push(fa_journal::rea::RelationshipRow {
            eid: fgdb_types::EId(1),
            spec: fa_model::RelationshipSpec {
                from: root,
                to: affiliate,
                kind: fa_model::RelationshipKind::Controls,
                basis: "majority_voting_control".into(),
                valid_from: day(2026, 1, 1),
                valid_to: None,
            },
            recorded_at: CommitSeq(1),
            control_entry: VId(70_003),
        });
    fa_model::party_value_vid(h.book.book_id, "AFFILIATE")
}

fn assert_coordinate(finding: &Finding, unit: UnitId, entity: Option<VId>) {
    assert_eq!(finding.version, 2);
    assert!(finding.narrative.contains(&format!("unit {},", unit.0)));
    let entity = entity.map_or_else(
        || "implicit book entity".into(),
        |entity| format!("entity {:032x}", entity.0),
    );
    assert!(finding.narrative.contains(&entity));
    assert!(finding.narrative.contains("cgse_witness="));
}

#[test]
fn communities_do_not_join_paths_across_currencies_or_entities() {
    let mut h = harness();
    let usd = h.usd;
    let jpy = h.book.units.lookup("JPY").unwrap();
    let procedure = Communities::with(
        Params::defaults(Communities::ID)
            .unwrap()
            .set("min_community_size", 3)
            .unwrap(),
    );
    // Each separated coordinate has only two accounts. Pooling them would
    // manufacture a three-account community with a 100% internal share.
    for (second_unit, first_entity, second_entity) in
        [(jpy, None, None), (usd, Some(ENTITY_A), Some(ENTITY_B))]
    {
        let mut snapshot = h.snapshot();
        snapshot.entries = vec![
            transfer(
                &mut h,
                71_001,
                ("1000", "1010"),
                Amount::new(usd, 100),
                first_entity,
                true,
            ),
            transfer(
                &mut h,
                71_002,
                ("1010", "1020"),
                Amount::new(second_unit, 100),
                second_entity,
                true,
            ),
        ];
        assert!(
            run_over(&snapshot, &h.book, &procedure)
                .unwrap()
                .findings
                .is_empty()
        );

        snapshot.entries[1] = transfer(
            &mut h,
            71_002,
            ("1010", "1020"),
            Amount::new(usd, 100),
            first_entity,
            true,
        );
        let result = run_over(&snapshot, &h.book, &procedure).unwrap();
        assert_eq!(result.version, 2);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].statistic.value, 10_000);
        assert_eq!(result.findings[0].statistic.population, 3);
        assert_coordinate(&result.findings[0], usd, first_entity);
        assert!(
            determinism(&snapshot, &h.book, &procedure)
                .unwrap()
                .deterministic()
        );
    }
}

#[test]
fn communities_keep_maximum_amounts_and_witnesses_in_their_own_coordinates() {
    let mut h = harness();
    let usd = h.usd;
    let jpy = h.book.units.lookup("JPY").unwrap();
    let coordinates = [(usd, ENTITY_A), (jpy, ENTITY_A), (usd, ENTITY_B)];
    let mut snapshot = h.snapshot();
    snapshot.entries = coordinates
        .iter()
        .enumerate()
        .map(|(index, &(unit, entity))| {
            transfer(
                &mut h,
                72_001 + u64::try_from(index).unwrap(),
                ("1000", "1010"),
                Amount::new(unit, i128::MAX),
                Some(entity),
                true,
            )
        })
        .collect();
    let procedure = Communities::new().unwrap();
    let result = run_over(&snapshot, &h.book, &procedure).unwrap();
    assert_eq!(result.findings.len(), 3);
    let mut witnesses = BTreeSet::new();
    for (unit, entity) in coordinates {
        let finding = result
            .findings
            .iter()
            .find(|finding| {
                finding.narrative.contains(&format!("unit {},", unit.0))
                    && finding
                        .narrative
                        .contains(&format!("entity {:032x}", entity.0))
            })
            .unwrap();
        assert_eq!(finding.statistic.value, 10_000);
        assert_eq!(finding.statistic.population, 2);
        assert_coordinate(finding, unit, Some(entity));
        witnesses.insert(finding.narrative.split("cgse_witness=").nth(1).unwrap());
    }
    assert_eq!(
        witnesses.len(),
        3,
        "the witness binds the monetary coordinate"
    );
    assert!(
        determinism(&snapshot, &h.book, &procedure)
            .unwrap()
            .deterministic()
    );
}

#[test]
fn shell_signatures_do_not_pair_different_currencies_or_entities() {
    let mut h = harness();
    let usd = h.usd;
    let jpy = h.book.units.lookup("JPY").unwrap();
    let procedure = ShellSignature::new().unwrap();
    for (second_unit, first_entity, second_entity) in
        [(jpy, None, None), (usd, Some(ENTITY_A), Some(ENTITY_B))]
    {
        let mut snapshot = h.snapshot();
        snapshot.entries = vec![
            transfer(
                &mut h,
                73_001,
                ("4000", "1000"),
                Amount::new(usd, 100),
                first_entity,
                false,
            ),
            transfer(
                &mut h,
                73_002,
                ("1000", "6000"),
                Amount::new(second_unit, 100),
                second_entity,
                false,
            ),
        ];
        assert!(
            run_over(&snapshot, &h.book, &procedure)
                .unwrap()
                .findings
                .is_empty()
        );
        snapshot.entries[1] = transfer(
            &mut h,
            73_002,
            ("1000", "6000"),
            Amount::new(usd, 100),
            first_entity,
            false,
        );
        let result = run_over(&snapshot, &h.book, &procedure).unwrap();
        assert_eq!(result.version, 2);
        assert_eq!(result.findings.len(), 1);
        let finding = &result.findings[0];
        assert_eq!(finding.statistic.value, 10_000);
        assert_eq!(finding.statistic.population, 2);
        assert_eq!(
            finding.cites,
            vec![
                Cite::Account(h.account("1000")),
                Cite::Entry(VId(73_001)),
                Cite::Entry(VId(73_002))
            ]
        );
        assert_coordinate(finding, usd, first_entity);
    }
}

#[test]
fn other_coordinates_documents_do_not_hide_an_undocumented_conduit() {
    let mut h = harness();
    let usd = h.usd;
    let jpy = h.book.units.lookup("JPY").unwrap();
    let mut snapshot = h.snapshot();
    snapshot.entries = vec![
        transfer(
            &mut h,
            74_001,
            ("4000", "1000"),
            Amount::new(usd, 100),
            Some(ENTITY_A),
            false,
        ),
        transfer(
            &mut h,
            74_002,
            ("1000", "6000"),
            Amount::new(usd, 90),
            Some(ENTITY_A),
            false,
        ),
        transfer(
            &mut h,
            74_003,
            ("4000", "1000"),
            Amount::new(jpy, 100),
            Some(ENTITY_A),
            true,
        ),
        transfer(
            &mut h,
            74_004,
            ("4000", "1000"),
            Amount::new(usd, 100),
            Some(ENTITY_B),
            true,
        ),
    ];
    let procedure = ShellSignature::new().unwrap();
    let result = run_over(&snapshot, &h.book, &procedure).unwrap();
    assert_eq!(result.findings.len(), 1);
    let finding = &result.findings[0];
    assert_coordinate(finding, usd, Some(ENTITY_A));
    assert_eq!(finding.statistic.value, 9_000);
    assert_eq!(finding.statistic.population, 2);
    assert_eq!(
        finding.cites,
        vec![
            Cite::Account(h.account("1000")),
            Cite::Entry(VId(74_001)),
            Cite::Entry(VId(74_002))
        ]
    );
    assert!(
        determinism(&snapshot, &h.book, &procedure)
            .unwrap()
            .deterministic()
    );
}

#[test]
fn related_exposure_uses_only_the_affected_currency_and_entity_at_registered_scale() {
    let mut h = harness();
    let usd = h.usd;
    let jpy = h.book.units.lookup("JPY").unwrap();
    let mut snapshot = h.snapshot();
    let affiliate = related_party(&mut h, &mut snapshot);
    let mut entry = transfer(
        &mut h,
        75_001,
        ("1000", "1010"),
        Amount::new(usd, 100),
        Some(ENTITY_A),
        true,
    );
    // A credit-side counterparty still identifies this balanced partition's
    // debit exposure; it need not be repeated on the debit leg.
    entry.entry.proposal.legs[0]
        .dimension_set
        .push((fa_model::PARTY_DIMENSION, affiliate));
    for (unit, amount, entity, related) in [
        (jpy, 8_000, ENTITY_A, true),
        (usd, 700, ENTITY_B, false),
        (jpy, 900, ENTITY_B, false),
    ] {
        let mut other = transfer(
            &mut h,
            75_002,
            ("1000", "1010"),
            Amount::new(unit, amount),
            Some(entity),
            true,
        );
        if related {
            other.entry.proposal.legs[1]
                .dimension_set
                .push((fa_model::PARTY_DIMENSION, affiliate));
        }
        entry.entry.proposal.legs.extend(other.entry.proposal.legs);
    }
    reseal(&mut entry);
    snapshot.entries = vec![entry];
    let procedure = RelatedPartyExposure::new().unwrap();
    let result = run_over(&snapshot, &h.book, &procedure).unwrap();
    assert_eq!(result.version, 2);
    assert_eq!(result.findings.len(), 2);
    for (unit, amount, scale) in [(usd, 100, 2), (jpy, 8_000, 0)] {
        let finding = result
            .findings
            .iter()
            .find(|finding| finding.statistic.value == amount)
            .unwrap();
        assert_coordinate(finding, unit, Some(ENTITY_A));
        assert_eq!(finding.statistic.scale, scale);
        assert_eq!(finding.statistic.population, 1);
        assert!(finding.cites.contains(&Cite::Entry(VId(75_001))));
    }
    assert!(
        determinism(&snapshot, &h.book, &procedure)
            .unwrap()
            .deterministic()
    );
}

#[test]
fn related_exposure_does_not_overflow_from_unrelated_native_units() {
    let mut h = harness();
    let usd = h.usd;
    let jpy = h.book.units.lookup("JPY").unwrap();
    let mut snapshot = h.snapshot();
    let affiliate = related_party(&mut h, &mut snapshot);
    let mut entry = transfer(
        &mut h,
        76_001,
        ("1000", "1010"),
        Amount::new(usd, i128::MAX),
        None,
        true,
    );
    let other = transfer(
        &mut h,
        76_002,
        ("1000", "1010"),
        Amount::new(jpy, i128::MAX),
        None,
        true,
    );
    entry.entry.proposal.legs.extend(other.entry.proposal.legs);
    for leg in &mut entry.entry.proposal.legs {
        leg.dimension_set
            .push((fa_model::PARTY_DIMENSION, affiliate));
    }
    reseal(&mut entry);
    snapshot.entries = vec![entry];
    let result = run_over(&snapshot, &h.book, &RelatedPartyExposure::new().unwrap()).unwrap();
    assert_eq!(result.findings.len(), 2);
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.statistic.value == i128::MAX)
    );
    assert_eq!(
        result
            .findings
            .iter()
            .map(|finding| finding.statistic.scale)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([0, 2])
    );
}

#[test]
fn graph_amount_procedures_refuse_ambiguous_implicit_entities() {
    let mut h = harness();
    let usd = h.usd;
    let mut snapshot = h.snapshot();
    related_party(&mut h, &mut snapshot);
    snapshot.entries = vec![
        transfer(
            &mut h,
            77_001,
            ("4000", "1000"),
            Amount::new(usd, 100),
            Some(ENTITY_A),
            false,
        ),
        transfer(
            &mut h,
            77_002,
            ("1000", "1010"),
            Amount::new(usd, 100),
            Some(ENTITY_B),
            false,
        ),
        transfer(
            &mut h,
            77_003,
            ("1010", "6000"),
            Amount::new(usd, 100),
            None,
            false,
        ),
    ];
    let procedures: Vec<Box<dyn Procedure>> = vec![
        Box::new(Communities::new().unwrap()),
        Box::new(ShellSignature::new().unwrap()),
        Box::new(RelatedPartyExposure::new().unwrap()),
    ];
    for procedure in procedures {
        assert!(matches!(
            run_over(&snapshot, &h.book, procedure.as_ref()),
            Err(LanternError::Overflow("missing money-flow legal entity"))
        ));
    }
}
