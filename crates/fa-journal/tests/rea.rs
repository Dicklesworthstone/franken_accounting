//! Kernel and differential tests for REA graph objects and valid-time
//! relationship closure (bet A4, plan §4.1, §4.5, bead `fa-l2h`).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use asupersync::Budget;
use asupersync::runtime::{Runtime, RuntimeBuilder};
use fa_journal::{
    AccountSpec, BookContext, BookSpec, Capability, LegalEntitySpec, PostRequest, UnitPolicy,
    bind_external_id, create_book, create_instrument, create_legal_entity, create_party,
    create_periods, install_chart, post, read_rea_at, record_relationship,
    update_party_identifiers, verify_projections,
};
use fa_model::symbols::{label, relation};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, Erasable, ExternalId, ExternalIdBinding,
    Id128, InstrumentKind, InstrumentSpec, LEGAL_ENTITY_DIMENSION, LegPayload, LegalEntityFullSpec,
    Oid, OwnershipPct, PARTY_DIMENSION, PartyIdentifierUpdate, PartyKind, PartySpec,
    RelationshipKind, RelationshipSpec, SealKey, SymbolTable, account_vid, entity_value_vid,
    external_id_vid, instrument_vid, legal_entity_vid, party_value_vid, party_vid, principal_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_policy::{Op, Profile};
use fa_reference::rea::{
    RefRelationshipEdge, RefRelationshipKind, naive_effective_ownership_as_of, naive_related_as_of,
    validate_relationship_edge,
};
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs};
use fgdb_types::VId;
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;

fn seal_str(s: &str, key: &SealKey, tag: u8) -> Erasable<String> {
    Erasable::seal(
        &s.to_string(),
        None,
        key,
        [tag; 32],
        [tag.wrapping_add(1); 24],
    )
}

fn setup_book() -> (
    Runtime,
    Database<MemVfs>,
    PurposeContexts,
    BookContext,
    UnitId,
) {
    let runtime = RuntimeBuilder::new().build().expect("runtime");
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let ctx = PurposeContexts::narrow_runtime_root(&root);
    let keys = DatabaseKeys::new(
        [0x5a; 32],
        DatabaseSecurityNamespaceId([0x5b; 32]),
        [0x5c; 32],
    );
    let mut db = runtime
        .block_on(async { Database::open_memory(&ctx.commit(), keys).await })
        .expect("open in-memory db");
    let units = UnitRegistry::with_defaults();
    let usd = units.lookup("USD").unwrap();
    let calendar = FiscalCalendar::monthly("std", 1, 1).unwrap();
    let book_id = Id128([0x44; 16]);
    let spec = BookSpec {
        book_id,
        name: "REA Test Book".into(),
        base_unit: usd,
        calendar: calendar.clone(),
        time_zone_policy: None,
        entities: vec![LegalEntitySpec {
            code: "HOLDCO".into(),
            name: "HoldCo Inc.".into(),
        }],
        opening_date: None,
    };
    let symbols = SymbolTable::compiled();
    runtime
        .block_on(create_book(&mut db, &ctx, &spec, &units, &symbols))
        .expect("create_book");
    let book = BookContext {
        book_id,
        calendar,
        units,
        seal_key: SealKey([0x55; 32]),
        symbols,
    };
    let (_, periods) = runtime
        .block_on(create_periods(&mut db, &ctx, &book, 2026))
        .expect("create_periods");
    let jan_period = periods
        .iter()
        .find(|p| {
            p.contains(DateDay::from_ymd(2026, 1, 15).unwrap()) && p.kind == PeriodKind::Normal
        })
        .unwrap()
        .code
        .clone();
    let controller = principal_vid("controller");
    let cap = Capability::embedded(controller, &["post", "schema_change", "close"]).expect("cap");
    let d_jan1 = DateDay::from_ymd(2026, 1, 1).unwrap();
    let chart = vec![
        AccountSpec {
            code: "1000".into(),
            name: "Assets".into(),
            account_type: AccountType::ASSET.0,
            normal_balance: 0,
            is_leaf: false,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "1010".into(),
            name: "Operating Cash".into(),
            account_type: AccountType::ASSET.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: Some("1000".into()),
            limit: None,
        },
        AccountSpec {
            code: "2010".into(),
            name: "Accounts Payable".into(),
            account_type: AccountType::LIABILITY.0,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        },
    ];
    runtime
        .block_on(install_chart(
            &mut db,
            &ctx,
            &book,
            &chart,
            controller,
            d_jan1,
            b"rea-chart-1",
            seal_str("install chart", &book.seal_key, 1),
        ))
        .expect("install_chart")
        .expect("install_chart ok");
    runtime
        .block_on(fa_journal::transition_period(
            &mut db,
            &ctx,
            &book,
            &jan_period,
            PeriodTransition::Open,
            controller,
            1,
            d_jan1,
            b"open-p01",
            seal_str("open P01", &book.seal_key, 2),
            &cap,
            &[],
        ))
        .expect("open P01")
        .expect("open P01 ok");
    (runtime, db, ctx, book, usd)
}

#[test]
fn rea_objects_party_dimensions_instruments_and_temporal_closure() {
    let (rt, mut db, ctx, book, usd) = setup_book();
    let controller = principal_vid("controller");
    let cap = Capability::embedded(controller, &["post", "schema_change", "close"]).expect("cap");
    let d_jan1 = DateDay::from_ymd(2026, 1, 1).unwrap();

    // 1. Create Bank Party and Vendor Party with ExternalId and identifiers.
    let bank_spec = PartySpec {
        code: "BANK-JPM".into(),
        kind: PartyKind::Bank,
        name: seal_str("JPMorgan Chase", &book.seal_key, 10),
        identifiers: vec![(
            "routing_aba".into(),
            seal_str("021000021", &book.seal_key, 11),
        )],
        external_ids: vec![ExternalId {
            system: "swift".into(),
            id: seal_str("CHASUS33", &book.seal_key, 12),
        }],
    };
    let bank_rec = rt
        .block_on(create_party(
            &mut db,
            &ctx,
            &book,
            &bank_spec,
            controller,
            d_jan1,
            b"party-bank-jpm",
            seal_str("create bank party", &book.seal_key, 13),
            &cap,
        ))
        .expect("create_party db")
        .expect("create_party ok");
    assert!(!bank_rec.already_recorded);
    assert_eq!(bank_rec.target_vid, party_vid(book.book_id, "BANK-JPM"));

    // Idempotent retry returns already_recorded = true.
    let bank_retry = rt
        .block_on(create_party(
            &mut db,
            &ctx,
            &book,
            &bank_spec,
            controller,
            d_jan1,
            b"party-bank-jpm",
            seal_str("create bank party", &book.seal_key, 13),
            &cap,
        ))
        .expect("retry db")
        .expect("retry ok");
    assert!(bank_retry.already_recorded);
    assert_eq!(bank_retry.recorded_at, bank_rec.recorded_at);

    let vendor_spec = PartySpec {
        code: "VEND-ACME".into(),
        kind: PartyKind::Vendor,
        name: seal_str("Acme Supplies LLC", &book.seal_key, 14),
        identifiers: vec![(
            "bank_account".into(),
            seal_str("ACCT-111222", &book.seal_key, 15),
        )],
        external_ids: vec![ExternalId {
            system: "netsuite".into(),
            id: seal_str("NS-VEND-001", &book.seal_key, 16),
        }],
    };
    let vendor_rec = rt
        .block_on(create_party(
            &mut db,
            &ctx,
            &book,
            &vendor_spec,
            controller,
            d_jan1,
            b"party-vend-acme",
            seal_str("create vendor party", &book.seal_key, 17),
            &cap,
        ))
        .expect("create_party db")
        .expect("create_party ok");
    assert_eq!(vendor_rec.target_vid, party_vid(book.book_id, "VEND-ACME"));

    // 2. Duplicate ExternalId on another Party is refused with exit::CONFLICT (6) citing VEND-ACME!
    let dup_ext_party = PartySpec {
        code: "VEND-CLONE".into(),
        kind: PartyKind::Vendor,
        name: seal_str("Clone Vendor", &book.seal_key, 18),
        identifiers: Vec::new(),
        external_ids: vec![ExternalId {
            system: "netsuite".into(),
            id: seal_str("NS-VEND-001", &book.seal_key, 19),
        }],
    };
    let dup_err = rt
        .block_on(create_party(
            &mut db,
            &ctx,
            &book,
            &dup_ext_party,
            controller,
            d_jan1,
            b"party-vend-clone",
            seal_str("dup ext party", &book.seal_key, 20),
            &cap,
        ))
        .expect("dup ext db")
        .expect_err("duplicate ExternalId must be refused");
    assert_eq!(dup_err.code, "FA-REF-032");
    assert_eq!(dup_err.exit, fa_journal::exit::CONFLICT);
    assert!(
        dup_err.message.contains("VEND-ACME"),
        "expected refusal to cite existing party VEND-ACME, got: {}",
        dup_err.message
    );

    // 3. Create Instrument HELD_AT BANK-JPM and MIRRORS 1010 Operating Cash.
    let cash_vid = account_vid(book.book_id, "1010");
    let ap_vid = account_vid(book.book_id, "2010");
    let inst_spec = InstrumentSpec {
        code: "CHK-JPM-01".into(),
        name: "JPM Operating Checking".into(),
        kind: InstrumentKind::BankAccount,
        unit: usd,
        held_at_party: bank_rec.target_vid,
        mirrors_account: cash_vid,
        external_ids: vec![ExternalId {
            system: "bai2".into(),
            id: seal_str("021000021-998877", &book.seal_key, 21),
        }],
    };
    let inst_rec = rt
        .block_on(create_instrument(
            &mut db,
            &ctx,
            &book,
            &inst_spec,
            controller,
            d_jan1,
            b"inst-chk-jpm-01",
            seal_str("create checking instrument", &book.seal_key, 22),
            &cap,
        ))
        .expect("create_instrument db")
        .expect("create_instrument ok");
    assert_eq!(
        inst_rec.target_vid,
        instrument_vid(book.book_id, "CHK-JPM-01")
    );
    assert!(
        db.edge(fa_journal::rows::edge_id(
            relation::HELD_AT,
            inst_rec.target_vid,
            bank_rec.target_vid
        ))
        .unwrap()
        .is_some()
    );
    assert!(
        db.edge(fa_journal::rows::edge_id(
            relation::MIRRORS,
            inst_rec.target_vid,
            cash_vid
        ))
        .unwrap()
        .is_some()
    );

    // 4. Lift genesis LegalEntity HOLDCO and create subsidiary SUB-EU.
    let holdco_full = LegalEntityFullSpec {
        code: "HOLDCO".into(),
        name: "HoldCo Inc.".into(),
        jurisdiction: "US-DE".into(),
        functional_unit: usd,
        formed: Some(DateDay::from_ymd(2020, 1, 1).unwrap()),
        dissolved: None,
        external_ids: vec![ExternalId {
            system: "lei".into(),
            id: seal_str("549300HOLDCO000001", &book.seal_key, 23),
        }],
    };
    let holdco_rec = rt
        .block_on(create_legal_entity(
            &mut db,
            &ctx,
            &book,
            &holdco_full,
            controller,
            d_jan1,
            b"le-holdco",
            seal_str("enrich holdco", &book.seal_key, 24),
            &cap,
        ))
        .expect("create_legal_entity db")
        .expect("create_legal_entity ok");
    assert_eq!(
        holdco_rec.target_vid,
        legal_entity_vid(book.book_id, "HOLDCO")
    );

    let sub_full = LegalEntityFullSpec {
        code: "SUB-US".into(),
        name: "Sub US LLC".into(),
        jurisdiction: "US-NY".into(),
        functional_unit: usd,
        formed: Some(DateDay::from_ymd(2025, 1, 1).unwrap()),
        dissolved: None,
        external_ids: Vec::new(),
    };
    let sub_rec = rt
        .block_on(create_legal_entity(
            &mut db,
            &ctx,
            &book,
            &sub_full,
            controller,
            d_jan1,
            b"le-sub-us",
            seal_str("create sub-us", &book.seal_key, 25),
            &cap,
        ))
        .expect("create_legal_entity sub db")
        .expect("create_legal_entity sub ok");
    assert_eq!(sub_rec.target_vid, legal_entity_vid(book.book_id, "SUB-US"));

    // Bind an additional ExternalId to VEND-ACME.
    let extra_binding = ExternalIdBinding {
        target_vid: vendor_rec.target_vid,
        external_id: ExternalId {
            system: "duns".into(),
            id: seal_str("12-345-6789", &book.seal_key, 26),
        },
    };
    let bind_rec = rt
        .block_on(bind_external_id(
            &mut db,
            &ctx,
            &book,
            &extra_binding,
            controller,
            d_jan1,
            b"bind-duns-acme",
            seal_str("bind duns", &book.seal_key, 27),
            &cap,
        ))
        .expect("bind_external_id db")
        .expect("bind_external_id ok");
    assert_eq!(
        bind_rec.target_vid,
        external_id_vid(book.book_id, "duns", "12-345-6789")
    );

    // Update VEND-ACME identifiers.
    let upd = PartyIdentifierUpdate {
        party_vid: vendor_rec.target_vid,
        identifiers: vec![
            (
                "bank_account".into(),
                seal_str("ACCT-999888", &book.seal_key, 28),
            ),
            ("ein".into(), seal_str("98-7654321", &book.seal_key, 29)),
        ],
    };
    rt.block_on(update_party_identifiers(
        &mut db,
        &ctx,
        &book,
        &upd,
        controller,
        d_jan1,
        b"upd-vend-acme-id",
        seal_str("update vendor bank account", &book.seal_key, 30),
        &cap,
    ))
    .expect("update_party_identifiers db")
    .expect("update_party_identifiers ok");

    // 5. Post a journal entry carrying PARTY_DIMENSION on its legs and verify projections!
    let holdco_val = entity_value_vid(book.book_id, "HOLDCO");
    let acme_val = party_value_vid(book.book_id, "VEND-ACME");
    let mut leg_dr = LegPayload::simple(Side::Debit, ap_vid, Amount::new(usd, 25_000));
    leg_dr.dimension_set = vec![
        (LEGAL_ENTITY_DIMENSION, holdco_val),
        (PARTY_DIMENSION, acme_val),
    ];
    let mut leg_cr = LegPayload::simple(Side::Credit, cash_vid, Amount::new(usd, 25_000));
    leg_cr.dimension_set = vec![
        (LEGAL_ENTITY_DIMENSION, holdco_val),
        (PARTY_DIMENSION, acme_val),
    ];
    let legs = vec![leg_dr, leg_cr];
    let unit_totals = EntryPayload::fold_unit_totals(&legs).unwrap();
    let doc = fa_journal::Document {
        book_id: book.book_id,
        kind: 1,
        mime: "application/pdf".into(),
        grade: 3,
        retrieved_by: controller,
        bytes: b"invoice-acme-001".to_vec(),
    };
    rt.block_on(fa_journal::add_document(&mut db, &ctx, &book, &doc))
        .expect("add_document")
        .expect("add_document ok");

    let proposal = EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: DateDay::from_ymd(2026, 1, 15).unwrap(),
        document_date: None,
        description: seal_str("Pay Acme invoice", &book.seal_key, 31),
        effective_period: None,
        legs,
        control: None,
        unit_totals,
        base_totals: None,
        idempotency_key: b"post-with-party-dim".to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([1; 32]),
            intent_kind: 1,
        },
        principal_ref: controller,
        session_ref: None,
        evidence: vec![doc.evidence_ref(1)],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        tags: Vec::new(),
        extensions: Vec::new(),
    };
    rt.block_on(post(
        &mut db,
        &ctx,
        &book,
        PostRequest {
            proposal: proposal.clone(),
            approvals: Vec::new(),
            capability: cap.clone(),
            plan_certificate: None,
        },
    ))
    .expect("post with party dim db")
    .expect("post with party dim ok");

    let proj_report = verify_projections(&db, &book, None).expect("verify_projections");
    assert!(proj_report.is_green(), "drift: {:?}", proj_report.drift);

    // Undeclared party dimension value on a leg is refused!
    let mut bad_proposal = proposal;
    bad_proposal.idempotency_key = b"post-bad-party-dim".to_vec();
    bad_proposal.legs[0].dimension_set = vec![
        (LEGAL_ENTITY_DIMENSION, holdco_val),
        (PARTY_DIMENSION, VId(0xDEAD_BEEF)),
    ];
    let bad_dim_err = rt
        .block_on(post(
            &mut db,
            &ctx,
            &book,
            PostRequest {
                proposal: bad_proposal,
                approvals: Vec::new(),
                capability: cap.clone(),
                plan_certificate: None,
            },
        ))
        .expect("post bad party dim db")
        .expect_err("undeclared party dimension value must be refused");
    assert_eq!(bad_dim_err.code, "FA-REF-100");
    assert_eq!(bad_dim_err.exit, fa_journal::exit::USAGE);

    // 6. Record valid-time OWNS, CONTROLS, and RELATED_TO edges and verify temporal closure
    //    and differential equivalence against fa_reference::rea!
    //    HOLDCO --OWNS(80%, [2026-01-01, 2026-07-01))--> SUB-US
    //    SUB-US --CONTROLS([2026-01-01, None))--> VEND-ACME
    //    HOLDCO --RELATED_TO([2026-03-01, None))--> BANK-JPM
    let owns_spec = RelationshipSpec {
        from: holdco_rec.target_vid,
        to: sub_rec.target_vid,
        kind: RelationshipKind::Owns {
            pct: OwnershipPct::new(4, 5).unwrap(),
        },
        basis: "equity_voting".into(),
        valid_from: DateDay::from_ymd(2026, 1, 1).unwrap(),
        valid_to: Some(DateDay::from_ymd(2026, 7, 1).unwrap()),
    };
    rt.block_on(record_relationship(
        &mut db,
        &ctx,
        &book,
        &owns_spec,
        controller,
        d_jan1,
        b"rel-holdco-owns-sub",
        seal_str("holdco owns 80% of sub-us", &book.seal_key, 32),
        &cap,
    ))
    .expect("record owns db")
    .expect("record owns ok");

    let controls_spec = RelationshipSpec {
        from: sub_rec.target_vid,
        to: vendor_rec.target_vid,
        kind: RelationshipKind::Controls,
        basis: "contractual_management".into(),
        valid_from: DateDay::from_ymd(2026, 1, 1).unwrap(),
        valid_to: None,
    };
    rt.block_on(record_relationship(
        &mut db,
        &ctx,
        &book,
        &controls_spec,
        controller,
        d_jan1,
        b"rel-sub-controls-acme",
        seal_str("sub-us controls acme", &book.seal_key, 33),
        &cap,
    ))
    .expect("record controls db")
    .expect("record controls ok");

    let related_spec = RelationshipSpec {
        from: holdco_rec.target_vid,
        to: bank_rec.target_vid,
        kind: RelationshipKind::RelatedTo,
        basis: "executive_officer_or_director".into(),
        valid_from: DateDay::from_ymd(2026, 3, 1).unwrap(),
        valid_to: None,
    };
    rt.block_on(record_relationship(
        &mut db,
        &ctx,
        &book,
        &related_spec,
        controller,
        d_jan1,
        b"rel-holdco-related-bank",
        seal_str("shared director with bank", &book.seal_key, 34),
        &cap,
    ))
    .expect("record related db")
    .expect("record related ok");

    // Verify chart::read_at still succeeds with REA controls present.
    let head = db.frontier().unwrap();
    let chart_snap = fa_journal::chart::read_at(&db, &book, head).expect("chart::read_at");
    assert_eq!(chart_snap.accounts().len(), 3);

    // Read REA snapshot and check CONTROLS semantics + temporal closure across dates!
    let rea_snap = read_rea_at(&db, &book, head).expect("read_rea_at");
    assert_eq!(rea_snap.parties.len(), 2);
    assert_eq!(rea_snap.instruments.len(), 1);
    assert_eq!(rea_snap.legal_entities.len(), 2);
    assert_eq!(rea_snap.external_ids.len(), 5);
    assert_eq!(rea_snap.relationships.len(), 3);

    // Check updated identifiers on VEND-ACME.
    let acme_row = &rea_snap.parties[&vendor_rec.target_vid];
    assert_eq!(acme_row.identifiers.len(), 2);
    assert_eq!(
        acme_row.identifiers[0].1.open(&book.seal_key, 256).unwrap(),
        "ACCT-999888"
    );

    // Build reference oracle inputs for differential comparison.
    let mut ref_endpoints = BTreeMap::new();
    for (vid, p) in &rea_snap.parties {
        ref_endpoints.insert(vid.0, p.code.clone());
    }
    for (vid, le) in &rea_snap.legal_entities {
        ref_endpoints.insert(vid.0, le.code.clone());
    }
    let ref_edges: Vec<RefRelationshipEdge> = rea_snap
        .relationships
        .iter()
        .map(|r| RefRelationshipEdge {
            from: r.spec.from.0,
            to: r.spec.to.0,
            kind: match r.spec.kind {
                RelationshipKind::Owns { pct } => RefRelationshipKind::Owns {
                    num: pct.num(),
                    den: pct.den(),
                },
                RelationshipKind::Controls => RefRelationshipKind::Controls,
                RelationshipKind::RelatedTo => RefRelationshipKind::RelatedTo,
            },
            basis: r.spec.basis.clone(),
            valid_from: r.spec.valid_from,
            valid_to: r.spec.valid_to,
        })
        .collect();

    // Date 1: 2026-02-15 (OWNS active, CONTROLS active, RELATED_TO not yet active).
    let d_feb15 = DateDay::from_ymd(2026, 2, 15).unwrap();
    // Date 2: 2026-04-15 (OWNS active, CONTROLS active, RELATED_TO active).
    let d_apr15 = DateDay::from_ymd(2026, 4, 15).unwrap();
    // Date 3: 2026-08-15 (OWNS expired at 2026-07-01, CONTROLS active, RELATED_TO active).
    let d_aug15 = DateDay::from_ymd(2026, 8, 15).unwrap();

    for date in [d_feb15, d_apr15, d_aug15] {
        let kernel_hits = rea_snap.related_as_of(holdco_rec.target_vid, date, 3);
        let oracle_hits =
            naive_related_as_of(&ref_endpoints, &ref_edges, holdco_rec.target_vid.0, date, 3);
        assert_eq!(kernel_hits.len(), oracle_hits.len());
        for (k, o) in kernel_hits.iter().zip(&oracle_hits) {
            assert_eq!(k.vid.0, o.vid);
            assert_eq!(k.code, o.code);
            assert_eq!(k.depth, o.depth);
            assert_eq!(k.via.0, o.via);
            assert_eq!(k.basis, o.basis);
        }

        let k_own = rea_snap
            .effective_ownership_as_of(holdco_rec.target_vid, sub_rec.target_vid, date, 3)
            .unwrap();
        let o_own = naive_effective_ownership_as_of(
            &ref_edges,
            holdco_rec.target_vid.0,
            sub_rec.target_vid.0,
            date,
            3,
        )
        .unwrap();
        assert_eq!((k_own.num(), k_own.den()), o_own);
    }

    // Positive check: related-party closure as of d_apr15 vs d_aug15 differs
    // exactly by the expired OWNS edge (SUB-US at depth 1 and VEND-ACME at depth 2).
    let codes_apr: Vec<String> = rea_snap
        .related_as_of(holdco_rec.target_vid, d_apr15, 3)
        .into_iter()
        .map(|h| h.code)
        .collect();
    let codes_aug: Vec<String> = rea_snap
        .related_as_of(holdco_rec.target_vid, d_aug15, 3)
        .into_iter()
        .map(|h| h.code)
        .collect();
    assert_eq!(codes_apr, vec!["SUB-US", "BANK-JPM", "VEND-ACME"]);
    assert_eq!(codes_aug, vec!["BANK-JPM"]);

    // Verify all CONTROLS edges in the database have only control semantics
    // (no Entry -> MigrationRun edges use CONTROLS).
    for edge in db.edges_at(head).unwrap() {
        if edge.entry.relation == relation::CONTROLS {
            let src_row = db.vertex(edge.entry.src).unwrap().unwrap();
            let dst_row = db.vertex(edge.entry.dst).unwrap().unwrap();
            assert!(
                src_row.labels.contains(&label::PARTY)
                    || src_row.labels.contains(&label::LEGAL_ENTITY)
                    || src_row.labels.contains(&label::SUBLEDGER)
            );
            assert!(
                dst_row.labels.contains(&label::PARTY)
                    || dst_row.labels.contains(&label::LEGAL_ENTITY)
                    || dst_row.labels.contains(&label::ACCOUNT)
            );
        }
    }
}

#[test]
fn rea_planted_negatives_agent_trunk_pct_bounds_and_nonexistent_party() {
    let (rt, mut db, ctx, book, _) = setup_book();
    let controller = principal_vid("controller");
    let cap_controller = Capability::embedded(controller, &["post", "schema_change"]).expect("cap");
    let agent = principal_vid("agent-bot");
    let cap_agent = Capability::new(agent, Profile::Agent, &[Op::Post], controller).expect("agent");
    let d_jan1 = DateDay::from_ymd(2026, 1, 1).unwrap();

    // 1. Agent session creating a Party on trunk is refused with FA-REF-013 (exit 7).
    let agent_party = PartySpec {
        code: "VEND-SHELL".into(),
        kind: PartyKind::Vendor,
        name: seal_str("Shell Vendor", &book.seal_key, 40),
        identifiers: Vec::new(),
        external_ids: Vec::new(),
    };
    let agent_err = rt
        .block_on(create_party(
            &mut db,
            &ctx,
            &book,
            &agent_party,
            agent,
            d_jan1,
            b"agent-party-1",
            seal_str("agent attempt", &book.seal_key, 41),
            &cap_agent,
        ))
        .expect("agent create_party db")
        .expect_err("Agent creating Party on trunk must be refused");
    assert_eq!(agent_err.code, "FA-REF-013");
    assert_eq!(agent_err.exit, fa_journal::exit::SAFETY);

    // Create two valid parties as controller for relationship negative tests.
    let p1 = rt
        .block_on(create_party(
            &mut db,
            &ctx,
            &book,
            &PartySpec {
                code: "P-ONE".into(),
                kind: PartyKind::BeneficialOwner,
                name: seal_str("Owner One", &book.seal_key, 42),
                identifiers: Vec::new(),
                external_ids: Vec::new(),
            },
            controller,
            d_jan1,
            b"create-p1",
            seal_str("p1", &book.seal_key, 43),
            &cap_controller,
        ))
        .unwrap()
        .unwrap()
        .target_vid;

    let p2 = rt
        .block_on(create_party(
            &mut db,
            &ctx,
            &book,
            &PartySpec {
                code: "P-TWO".into(),
                kind: PartyKind::RelatedEntity,
                name: seal_str("Entity Two", &book.seal_key, 44),
                identifiers: Vec::new(),
                external_ids: Vec::new(),
            },
            controller,
            d_jan1,
            b"create-p2",
            seal_str("p2", &book.seal_key, 45),
            &cap_controller,
        ))
        .unwrap()
        .unwrap()
        .target_vid;

    let mut endpoints = BTreeMap::new();
    endpoints.insert(p1.0, "P-ONE".to_string());
    endpoints.insert(p2.0, "P-TWO".to_string());

    // 2. OWNS with pct > 1 (e.g. 120/100) is refused by both kernel and reference oracle!
    let bad_pct_spec = RelationshipSpec {
        from: p1,
        to: p2,
        kind: RelationshipKind::Owns {
            pct: OwnershipPct::new(120, 100).unwrap(),
        },
        basis: "equity_voting".into(),
        valid_from: d_jan1,
        valid_to: None,
    };
    let pct_err = rt
        .block_on(record_relationship(
            &mut db,
            &ctx,
            &book,
            &bad_pct_spec,
            controller,
            d_jan1,
            b"bad-pct",
            seal_str("bad pct", &book.seal_key, 46),
            &cap_controller,
        ))
        .unwrap()
        .expect_err("OWNS pct > 1 must be refused");
    assert_eq!(pct_err.code, "FA-REF-100");
    assert_eq!(pct_err.exit, fa_journal::exit::USAGE);
    assert_eq!(
        validate_relationship_edge(
            &RefRelationshipEdge {
                from: p1.0,
                to: p2.0,
                kind: RefRelationshipKind::Owns { num: 120, den: 100 },
                basis: "equity_voting".into(),
                valid_from: d_jan1,
                valid_to: None,
            },
            &endpoints,
            false,
        ),
        Err((pct_err.code, pct_err.exit))
    );

    // 3. Relationship edge to a nonexistent party is refused by both kernel and reference oracle!
    let missing_target_spec = RelationshipSpec {
        from: p1,
        to: VId(0x9999_8888),
        kind: RelationshipKind::RelatedTo,
        basis: "common_control".into(),
        valid_from: d_jan1,
        valid_to: None,
    };
    let missing_err = rt
        .block_on(record_relationship(
            &mut db,
            &ctx,
            &book,
            &missing_target_spec,
            controller,
            d_jan1,
            b"missing-target",
            seal_str("missing target", &book.seal_key, 47),
            &cap_controller,
        ))
        .unwrap()
        .expect_err("relationship to nonexistent party must be refused");
    assert_eq!(missing_err.code, "FA-REF-100");
    assert_eq!(missing_err.exit, fa_journal::exit::USAGE);
    assert_eq!(
        validate_relationship_edge(
            &RefRelationshipEdge {
                from: p1.0,
                to: 0x9999_8888,
                kind: RefRelationshipKind::RelatedTo,
                basis: "common_control".into(),
                valid_from: d_jan1,
                valid_to: None,
            },
            &endpoints,
            false,
        ),
        Err((missing_err.code, missing_err.exit))
    );
}

#[test]
fn rea_event_recording_and_post_derived_from_linkage_match_oracle() {
    let (rt, mut db, ctx, book, usd) = setup_book();
    let controller = principal_vid("controller");
    let cap = Capability::embedded(controller, &["post", "schema_change", "close"]).expect("cap");
    let d_jan1 = DateDay::from_ymd(2026, 1, 1).unwrap();
    let d_jan14 = DateDay::from_ymd(2026, 1, 14).unwrap();

    let vendor_rec = rt
        .block_on(create_party(
            &mut db,
            &ctx,
            &book,
            &PartySpec {
                code: "VEND-ACME".into(),
                kind: PartyKind::Vendor,
                name: seal_str("Acme Supplies LLC", &book.seal_key, 60),
                identifiers: Vec::new(),
                external_ids: Vec::new(),
            },
            controller,
            d_jan1,
            b"ev-party-acme",
            seal_str("create vendor", &book.seal_key, 61),
            &cap,
        ))
        .unwrap()
        .unwrap();

    let cash_vid = account_vid(book.book_id, "1010");
    let ap_vid = account_vid(book.book_id, "2010");
    let inst_rec = rt
        .block_on(create_instrument(
            &mut db,
            &ctx,
            &book,
            &InstrumentSpec {
                code: "CHK-JPM-01".into(),
                name: "JPM Operating Checking".into(),
                kind: InstrumentKind::BankAccount,
                unit: usd,
                held_at_party: vendor_rec.target_vid,
                mirrors_account: cash_vid,
                external_ids: Vec::new(),
            },
            controller,
            d_jan1,
            b"ev-inst-chk",
            seal_str("create instrument", &book.seal_key, 62),
            &cap,
        ))
        .unwrap()
        .unwrap();

    let doc = fa_journal::Document {
        book_id: book.book_id,
        kind: 1,
        mime: "application/pdf".into(),
        grade: 3,
        retrieved_by: controller,
        bytes: b"event-invoice-bytes-1001".to_vec(),
    };
    rt.block_on(fa_journal::add_document(&mut db, &ctx, &book, &doc))
        .unwrap()
        .unwrap();
    let doc_oid = doc.oid();

    let ev_spec = fa_model::EventSpec {
        code: "EV-1001".into(),
        kind: fa_model::EventKind::Purchase,
        occurred_on: d_jan14,
        description: seal_str("Purchase of supplies from Acme", &book.seal_key, 63),
        participants: vec![vendor_rec.target_vid],
        resources: vec![fa_model::EventResource {
            label: "cash_outflow".into(),
            amount: Amount::new(usd, 15_000),
            instrument: Some(inst_rec.target_vid),
        }],
        evidence: vec![doc.evidence_ref(1)],
        external_ids: vec![ExternalId {
            system: "stripe".into(),
            id: seal_str("ch_1001", &book.seal_key, 64),
        }],
    };
    let ev_digest = ev_spec.event_digest().unwrap();
    let ev_rec = rt
        .block_on(fa_journal::record_event(
            &mut db,
            &ctx,
            &book,
            &ev_spec,
            controller,
            d_jan14,
            b"event:EV-1001",
            seal_str("record EV-1001", &book.seal_key, 65),
            &cap,
        ))
        .unwrap()
        .unwrap();
    assert!(!ev_rec.already_recorded);
    assert_eq!(ev_rec.target_vid, fa_model::event_vid(book.book_id, "EV-1001"));

    // Idempotent retry returns already_recorded = true.
    let ev_retry = rt
        .block_on(fa_journal::record_event(
            &mut db,
            &ctx,
            &book,
            &ev_spec,
            controller,
            d_jan14,
            b"event:EV-1001",
            seal_str("record EV-1001", &book.seal_key, 65),
            &cap,
        ))
        .unwrap()
        .unwrap();
    assert!(ev_retry.already_recorded);
    assert_eq!(ev_retry.recorded_at, ev_rec.recorded_at);

    // Cross-check with reference oracle validate_event.
    let parties_set = [vendor_rec.target_vid.0].into_iter().collect();
    let inst_set = [inst_rec.target_vid.0].into_iter().collect();
    let units_set = [usd.0].into_iter().collect();
    let ev_ref = doc.evidence_ref(1);
    let docs_map: BTreeMap<[u8; 32], [u8; 32]> =
        [(doc_oid.0, ev_ref.doc_commit)].into_iter().collect();
    let existing_events = BTreeMap::new();
    assert_eq!(
        fa_reference::rea::validate_event(
            &fa_reference::rea::RefEvent {
                vid: ev_rec.target_vid.0,
                code: "EV-1001".into(),
                kind_tag: 2,
                occurred_on: d_jan14,
                participants: vec![vendor_rec.target_vid.0],
                resources: vec![fa_reference::rea::RefEventResource {
                    label: "cash_outflow".into(),
                    unit_id: usd.0,
                    mantissa: 15_000,
                    instrument: Some(inst_rec.target_vid.0),
                }],
                evidence: vec![(doc_oid.0, ev_ref.doc_commit, 1)],
                event_digest: ev_digest,
            },
            &parties_set,
            &inst_set,
            &units_set,
            &docs_map,
            &existing_events,
            false,
        ),
        Ok(())
    );

    // Post an entry citing EV-1001 and verify DERIVED_FROM edge and read_rea_at reconstruction.
    let holdco_val = entity_value_vid(book.book_id, "HOLDCO");
    let mut leg_dr = LegPayload::simple(Side::Debit, ap_vid, Amount::new(usd, 15_000));
    leg_dr.dimension_set = vec![(LEGAL_ENTITY_DIMENSION, holdco_val)];
    let mut leg_cr = LegPayload::simple(Side::Credit, cash_vid, Amount::new(usd, 15_000));
    leg_cr.dimension_set = vec![(LEGAL_ENTITY_DIMENSION, holdco_val)];
    let legs = vec![leg_dr, leg_cr];
    let unit_totals = EntryPayload::fold_unit_totals(&legs).unwrap();
    let mut proposal = EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: d_jan14,
        document_date: None,
        description: seal_str("Entry from EV-1001", &book.seal_key, 66),
        effective_period: None,
        legs,
        control: None,
        unit_totals,
        base_totals: None,
        idempotency_key: b"post-from-ev-1001".to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([2; 32]),
            intent_kind: 1,
        },
        principal_ref: controller,
        session_ref: None,
        evidence: vec![doc.evidence_ref(1)],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        tags: Vec::new(),
        extensions: Vec::new(),
    };
    proposal.with_event_ref(ev_rec.target_vid, ev_digest);

    let posted = rt
        .block_on(post(
            &mut db,
            &ctx,
            &book,
            PostRequest {
                proposal,
                approvals: Vec::new(),
                capability: cap.clone(),
                plan_certificate: None,
            },
        ))
        .unwrap()
        .unwrap();
    let entry_vid = match posted {
        fa_journal::Posted::Committed { entry_ref, .. } => entry_ref.vid,
        other => panic!("expected Committed, got {other:?}"),
    };

    assert!(
        db.edge(fa_journal::rows::edge_id(
            relation::DERIVED_FROM,
            entry_vid,
            ev_rec.target_vid,
        ))
        .unwrap()
        .is_some(),
        "DERIVED_FROM edge from entry to event must exist"
    );

    let head = db.frontier().unwrap();
    let rea_snap = read_rea_at(&db, &book, head).unwrap();
    let ev_row = rea_snap.events.get(&ev_rec.target_vid).expect("event in rea_snap");
    assert_eq!(ev_row.spec.code, "EV-1001");
    assert_eq!(ev_row.event_digest, ev_digest);
}

#[test]
fn rea_event_missing_or_unevidenced_event_citation_is_refused() {
    let (rt, mut db, ctx, book, usd) = setup_book();
    let controller = principal_vid("controller");
    let cap = Capability::embedded(controller, &["post", "schema_change", "close"]).expect("cap");
    let d_jan14 = DateDay::from_ymd(2026, 1, 14).unwrap();

    // 1. Recording an Event with empty evidence is refused with FA-REF-080 (exit 3).
    let no_ev_spec = fa_model::EventSpec {
        code: "EV-NO-DOC".into(),
        kind: fa_model::EventKind::Sale,
        occurred_on: d_jan14,
        description: seal_str("no evidence event", &book.seal_key, 70),
        participants: Vec::new(),
        resources: Vec::new(),
        evidence: Vec::new(),
        external_ids: Vec::new(),
    };
    let no_ev_err = rt
        .block_on(fa_journal::record_event(
            &mut db,
            &ctx,
            &book,
            &no_ev_spec,
            controller,
            d_jan14,
            b"ev-no-doc",
            seal_str("record ev-no-doc", &book.seal_key, 71),
            &cap,
        ))
        .unwrap()
        .expect_err("Event without evidence must be refused");
    assert_eq!(no_ev_err.code, "FA-REF-080");
    assert_eq!(no_ev_err.exit, fa_journal::exit::REFUSAL);
    assert_eq!(
        fa_reference::rea::validate_event(
            &fa_reference::rea::RefEvent {
                vid: 1,
                code: "EV-NO-DOC".into(),
                kind_tag: 1,
                occurred_on: d_jan14,
                participants: Vec::new(),
                resources: Vec::new(),
                evidence: Vec::new(),
                event_digest: [0; 32],
            },
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            false,
        ),
        Err((no_ev_err.code, no_ev_err.exit))
    );

    // 2. Posting an entry citing a nonexistent Event is refused with FA-REF-080 (exit 3).
    let doc = fa_journal::Document {
        book_id: book.book_id,
        kind: 1,
        mime: "application/pdf".into(),
        grade: 3,
        retrieved_by: controller,
        bytes: b"valid-doc-for-post".to_vec(),
    };
    rt.block_on(fa_journal::add_document(&mut db, &ctx, &book, &doc))
        .unwrap()
        .unwrap();
    let cash_vid = account_vid(book.book_id, "1010");
    let ap_vid = account_vid(book.book_id, "2010");
    let holdco_val = entity_value_vid(book.book_id, "HOLDCO");
    let mut leg_dr = LegPayload::simple(Side::Debit, ap_vid, Amount::new(usd, 5_000));
    leg_dr.dimension_set = vec![(LEGAL_ENTITY_DIMENSION, holdco_val)];
    let mut leg_cr = LegPayload::simple(Side::Credit, cash_vid, Amount::new(usd, 5_000));
    leg_cr.dimension_set = vec![(LEGAL_ENTITY_DIMENSION, holdco_val)];
    let legs = vec![leg_dr, leg_cr];
    let unit_totals = EntryPayload::fold_unit_totals(&legs).unwrap();
    let missing_ev_vid = fa_model::event_vid(book.book_id, "EV-DOES-NOT-EXIST");
    let mut bad_post = EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: d_jan14,
        document_date: None,
        description: seal_str("Citing nonexistent event", &book.seal_key, 72),
        effective_period: None,
        legs,
        control: None,
        unit_totals,
        base_totals: None,
        idempotency_key: b"post-missing-ev".to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([3; 32]),
            intent_kind: 1,
        },
        principal_ref: controller,
        session_ref: None,
        evidence: vec![doc.evidence_ref(1)],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        tags: Vec::new(),
        extensions: Vec::new(),
    };
    bad_post.with_event_ref(missing_ev_vid, [0u8; 32]);

    let post_err = rt
        .block_on(post(
            &mut db,
            &ctx,
            &book,
            PostRequest {
                proposal: bad_post,
                approvals: Vec::new(),
                capability: cap,
                plan_certificate: None,
            },
        ))
        .unwrap()
        .expect_err("posting with nonexistent event citation must be refused");
    assert_eq!(post_err.code, "FA-REF-080");
    assert_eq!(post_err.exit, fa_journal::exit::REFUSAL);
    assert_eq!(
        fa_reference::rea::validate_event_citation(
            missing_ev_vid.0,
            Some([0u8; 32]),
            &Default::default(),
        ),
        Err((post_err.code, post_err.exit))
    );
}
