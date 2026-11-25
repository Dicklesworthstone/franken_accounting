//! Scenario lifecycle records reserve their canonical control keys in the
//! same successful-intent namespace as postings and atomic batches.

use super::*;
use fa_intents::PostIntent;
use fa_journal::refusal::{Outcome, code};
use fa_journal::scenario::{
    ScenarioFork, ScenarioRecorded, ScenarioRequest, ScenarioState, discard_scenario,
    list_scenarios, open_scenario, plan_into_scenario, read_scenario,
};
use fa_model::symbols::label;

const NAME: &str = "counterfactual";
const INTENT_KEY: &[u8] = b"scenario-planned";

fn request(h: &Harness) -> ScenarioRequest {
    ScenarioRequest {
        capability: Capability::embedded(PRINCIPAL, &["post", "read"]).unwrap(),
        effective_date: h.day(),
        description: h.statement("scenario outcome", 201),
    }
}

fn intent(h: &Harness, cents: i128) -> PostIntent {
    PostIntent::new(
        h.proposal(h.rent_legs(cents), INTENT_KEY, EntryClass::ORIGINAL),
        Vec::new(),
    )
    .unwrap()
}

fn key(h: &Harness, kind: u8) -> Vec<u8> {
    let discriminator = if kind == 1 { INTENT_KEY } else { &[] };
    fa_model::domain_digest(
        b"fa:scenario-record-key:v1",
        &[
            &[kind],
            &fa_model::scenario_vid(h.book.book_id, NAME).0.to_le_bytes(),
            discriminator,
        ],
    )
    .to_vec()
}

fn outcome(h: &Harness, kind: u8) -> VId {
    fa_model::intent_outcome_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), &key(h, kind))
}

fn execute(
    h: &mut Harness,
    kind: u8,
    intent: &PostIntent,
    request: &ScenarioRequest,
) -> Outcome<ScenarioRecorded> {
    let ctx = h.ctx();
    match kind {
        0 => h.runtime.block_on(open_scenario(
            &mut h.db,
            &ctx,
            &h.book,
            NAME,
            ScenarioFork::default(),
            request.clone(),
        )),
        1 => h.runtime.block_on(plan_into_scenario(
            &mut h.db,
            &ctx,
            &h.book,
            NAME,
            intent.clone(),
            request.clone(),
        )),
        2 => h.runtime.block_on(discard_scenario(
            &mut h.db,
            &ctx,
            &h.book,
            NAME,
            request.clone(),
        )),
        _ => unreachable!(),
    }
}

fn assert_claim(h: &Harness, recorded: &ScenarioRecorded) {
    let (entry, sequence) = read_entry(&h.db, recorded.control_entry).unwrap().unwrap();
    let claim =
        h.db.vertex(fa_model::intent_outcome_vid(
            h.book.book_id,
            &entry.proposal.principal_ref.0.to_le_bytes(),
            &entry.proposal.idempotency_key,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(claim.labels, vec![label::INTENT_OUTCOME]);
    assert_eq!(
        (sequence, claim.created_at),
        (recorded.recorded_at, recorded.recorded_at)
    );
    assert_eq!(
        fa_journal::rows::prop(&claim, property::TARGET_REF),
        Some(&CanonicalScalar::bytes(recorded.control_entry.0.to_le_bytes().to_vec()).unwrap())
    );
}

#[test]
fn every_posting_family_reserves_keys_against_all_scenario_transitions() {
    for kind in 0..=2 {
        for family in [
            "original",
            "reversal",
            "replacement",
            "pending",
            "resolution",
            "batch",
        ] {
            let mut h = harness();
            let request = request(&h);
            let intent = intent(&h, 100);
            if kind != 0 {
                execute(&mut h, 0, &intent, &request).unwrap().unwrap();
            }
            let key = key(&h, kind);
            let source = h.proposal(h.rent_legs(100), b"scenario-source", EntryClass::ORIGINAL);
            let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
            let occupied = match family {
                "original" | "batch" => h.proposal(h.rent_legs(200), &key, EntryClass::ORIGINAL),
                "reversal" => h.reversal_of_entry(target, &key),
                "replacement" => replacement_proposal(
                    target,
                    h.proposal(h.rent_legs(125), &key, EntryClass::REPLACEMENT),
                ),
                "pending" => h.pending(h.rent_legs(200), &key),
                "resolution" => {
                    let pending = h.pending(h.rent_legs(200), b"scenario-hold");
                    let hold = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
                    h.resolution_posts(hold, h.rent_legs(150), vec![0, 1], &key)
                }
                _ => unreachable!(),
            };
            if family == "replacement" {
                h.post_pair(
                    h.request(h.reversal_of_entry(target, b"scenario-pair"), &["post"]),
                    h.request(occupied, &["post"]),
                )
                .unwrap();
            } else if family == "batch" {
                let mut member = occupied;
                member.idempotency_key = b"scenario-member".to_vec();
                h.post_batch(h.batch(&key, vec![member])).unwrap();
            } else {
                h.post(h.request(occupied, &["post"])).unwrap();
            }
            let head = h.db.frontier().unwrap();
            let rows = h.db.vertices().unwrap();
            let edges = h.db.edges_at(head).unwrap();
            let refused = execute(&mut h, kind, &intent, &request)
                .unwrap()
                .unwrap_err();
            assert_eq!(
                (refused.code, refused.exit),
                (code::IDEMPOTENCY_CONFLICT, exit::CONFLICT),
                "transition {kind}, {family}"
            );
            assert_eq!(h.db.frontier().unwrap(), head);
            assert_eq!(h.db.vertices().unwrap(), rows);
            assert_eq!(h.db.edges_at(head).unwrap(), edges);
            let scenario = read_scenario(&h.db, &h.book, NAME).unwrap();
            if kind == 0 {
                assert!(scenario.is_none());
            } else {
                let scenario = scenario.unwrap();
                assert_eq!(scenario.state, ScenarioState::Open);
                assert!(scenario.intents.is_empty());
                assert!(scenario.discarded.is_none());
            }
        }
    }
}

#[test]
fn all_scenario_claims_block_postings_pairs_and_outer_batches_atomically() {
    for kind in 0..=2 {
        let mut h = harness();
        let source = h.proposal(h.rent_legs(100), b"blocked-source", EntryClass::ORIGINAL);
        let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
        let pending = h.pending(h.rent_legs(200), b"blocked-hold");
        let hold = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
        let request = request(&h);
        let intent = intent(&h, 100);
        if kind != 0 {
            execute(&mut h, 0, &intent, &request).unwrap().unwrap();
        }
        let recorded = execute(&mut h, kind, &intent, &request).unwrap().unwrap();
        assert_claim(&h, &recorded);
        let key = key(&h, kind);
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let edges = h.db.edges_at(head).unwrap();
        let original = h.proposal(h.rent_legs(300), &key, EntryClass::ORIGINAL);
        let reversal = h.reversal_of_entry(target, &key);
        let pending = h.pending(h.rent_legs(300), &key);
        let resolution = h.resolution_posts(hold, h.rent_legs(150), vec![0, 1], &key);
        for proposal in [original, reversal, pending, resolution] {
            let refused = h.post(h.request(proposal, &["post"])).unwrap_err();
            assert_eq!(
                (refused.code, refused.exit),
                (code::IDEMPOTENCY_CONFLICT, exit::CONFLICT),
                "transition {kind}"
            );
        }
        let reversal = h.request(
            h.reversal_of_entry(target, b"unpublished-reversal"),
            &["post"],
        );
        let replacement = h.request(
            replacement_proposal(
                target,
                h.proposal(h.rent_legs(125), &key, EntryClass::REPLACEMENT),
            ),
            &["post"],
        );
        assert_eq!(
            h.post_pair(reversal, replacement).unwrap_err().code,
            code::IDEMPOTENCY_CONFLICT
        );
        let member = h.proposal(
            h.rent_legs(300),
            b"unpublished-member",
            EntryClass::ORIGINAL,
        );
        assert_eq!(
            h.post_batch(h.batch(&key, vec![member])).unwrap_err().code,
            code::IDEMPOTENCY_CONFLICT
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert_eq!(h.db.edges_at(head).unwrap(), edges);
        assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
        assert!(h.db.vertex(resolution_vid(hold.vid)).unwrap().is_none());
    }
}

#[test]
fn exact_retries_keep_original_outcomes_after_discard_and_bind_content() {
    let mut h = harness();
    let request = request(&h);
    let original = intent(&h, 100);
    let mut records = Vec::new();
    for kind in 0..=2 {
        let recorded = execute(&mut h, kind, &original, &request).unwrap().unwrap();
        assert_claim(&h, &recorded);
        records.push(recorded);
    }
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let mut resealed_request = request.clone();
    resealed_request.description = h.statement("scenario outcome", 202);
    let mut resealed = original.proposal().clone();
    resealed.description = h.statement("March rent", 203);
    let resealed = PostIntent::new(resealed, Vec::new()).unwrap();
    for (kind, first) in records.iter().enumerate() {
        let again = execute(&mut h, kind as u8, &resealed, &resealed_request)
            .unwrap()
            .unwrap();
        assert!(again.already_recorded);
        assert_eq!(
            (again.control_entry, again.recorded_at),
            (first.control_entry, first.recorded_at)
        );
    }
    for kind in [0, 2] {
        let mut changed = request.clone();
        changed.effective_date = DateDay::from_ymd(2026, 3, 16).unwrap();
        assert_eq!(
            execute(&mut h, kind, &original, &changed)
                .unwrap()
                .unwrap_err()
                .code,
            code::IDEMPOTENCY_CONFLICT
        );
        changed = request.clone();
        changed.description = h.statement("changed scenario outcome", 204);
        assert_eq!(
            execute(&mut h, kind, &original, &changed)
                .unwrap()
                .unwrap_err()
                .code,
            code::IDEMPOTENCY_CONFLICT
        );
    }
    let changed = intent(&h, 101);
    assert_eq!(
        execute(&mut h, 1, &changed, &request)
            .unwrap()
            .unwrap_err()
            .code,
        code::IDEMPOTENCY_CONFLICT
    );
    let ctx = h.ctx();
    let day = h.day();
    let changed_fork = h.runtime.block_on(open_scenario(
        &mut h.db,
        &ctx,
        &h.book,
        NAME,
        ScenarioFork {
            from: Some(day),
            ..ScenarioFork::default()
        },
        request,
    ));
    assert_eq!(
        changed_fork.unwrap().unwrap_err().code,
        code::IDEMPOTENCY_CONFLICT
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
    let scenario = read_scenario(&h.db, &h.book, NAME).unwrap().unwrap();
    assert_eq!(scenario.state, ScenarioState::Discarded);
    assert_eq!(scenario.intents.len(), 1);
}

#[test]
fn a_scenario_reserves_its_control_key_without_claiming_the_counterfactual_intent() {
    let mut h = harness();
    let request = request(&h);
    let intent = intent(&h, 100);
    execute(&mut h, 0, &intent, &request).unwrap().unwrap();
    let planned = execute(&mut h, 1, &intent, &request).unwrap().unwrap();
    assert_claim(&h, &planned);
    let trunk_key =
        fa_model::intent_outcome_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), INTENT_KEY);
    assert!(h.db.vertex(trunk_key).unwrap().is_none());
    let posted = h
        .post(h.request(intent.proposal().clone(), &["post"]))
        .unwrap();
    assert_ne!(posted.entry_ref().vid, planned.control_entry);
    let retry = execute(&mut h, 1, &intent, &request).unwrap().unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.recorded_at, planned.recorded_at);
}

#[test]
fn a_prepared_reversal_loses_to_each_scenario_claim() {
    for kind in 0..=2 {
        let mut h = harness();
        let source = h.proposal(h.rent_legs(100), b"race-source", EntryClass::ORIGINAL);
        let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
        let request = request(&h);
        let intent = intent(&h, 100);
        if kind != 0 {
            execute(&mut h, 0, &intent, &request).unwrap().unwrap();
        }
        let reversal = h.request(h.reversal_of_entry(target, &key(&h, kind)), &["post"]);
        let ctx = h.ctx();
        let PostPreparation::Ready(prepared) = prepare_post(&mut h.db, &ctx, &h.book, reversal)
            .unwrap()
            .unwrap()
        else {
            panic!("fresh reversal");
        };
        execute(&mut h, kind, &intent, &request).unwrap().unwrap();
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let refused = h
            .runtime
            .block_on(prepared.commit(&mut h.db, &ctx))
            .unwrap()
            .unwrap_err();
        assert_eq!(refused.exit, exit::CONFLICT);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    }
}

#[test]
fn authority_precedes_malformed_scenario_claim_observation() {
    for kind in 0..=2 {
        let mut h = harness();
        let original = request(&h);
        let intent = intent(&h, 100);
        if kind != 0 {
            execute(&mut h, 0, &intent, &original).unwrap().unwrap();
        }
        let mut write = fgdb::WriteBatch::new(relation::IN_CASE);
        write.create_vertex(
            outcome(&h, kind),
            vec![label::INTENT_OUTCOME],
            vec![(
                property::FA_PAYLOAD,
                CanonicalScalar::bytes(vec![0]).unwrap(),
            )],
        );
        h.write_raw(write);
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        for capability in [
            Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
            Capability::embedded(PRINCIPAL, &["post"])
                .unwrap()
                .for_classes(&[EntryClass::ORIGINAL])
                .unwrap(),
            Capability::embedded(PRINCIPAL, &["post"])
                .unwrap()
                .with_requires_dry_run(),
        ] {
            let mut denied = original.clone();
            denied.capability = capability;
            let refused = execute(&mut h, kind, &intent, &denied)
                .unwrap()
                .unwrap_err();
            assert_eq!(refused.code, code::CAPABILITY, "transition {kind}");
        }
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn rewritten_records_and_missing_or_retargeted_claims_never_retry_as_legacy() {
    for kind in 0..=2 {
        for variant in ["mirror", "deleted claim", "retargeted claim"] {
            let mut h = harness();
            let request = request(&h);
            let intent = intent(&h, 100);
            if kind != 0 {
                execute(&mut h, 0, &intent, &request).unwrap().unwrap();
            }
            let recorded = execute(&mut h, kind, &intent, &request).unwrap().unwrap();
            let mut write = fgdb::WriteBatch::new(relation::IN_CASE);
            match variant {
                "mirror" => write.set_vertex_property(
                    recorded.control_entry,
                    property::FA_EFFECTIVE_DAY,
                    Some(CanonicalScalar::Int(1)),
                ),
                "deleted claim" => write.delete_vertex(outcome(&h, kind)),
                "retargeted claim" => write.set_vertex_property(
                    outcome(&h, kind),
                    property::TARGET_REF,
                    Some(CanonicalScalar::bytes(VId(209).0.to_le_bytes().to_vec()).unwrap()),
                ),
                _ => unreachable!(),
            };
            h.write_raw(write);
            let head = h.db.frontier().unwrap();
            let rows = h.db.vertices().unwrap();
            assert!(
                read_scenario(&h.db, &h.book, NAME).is_err(),
                "transition {kind}, {variant}"
            );
            assert!(
                !matches!(execute(&mut h, kind, &intent, &request), Ok(Ok(_))),
                "transition {kind}, {variant}"
            );
            assert_eq!(h.db.frontier().unwrap(), head);
            assert_eq!(h.db.vertices().unwrap(), rows);
        }
    }
}

#[test]
fn authentic_legacy_and_modern_scenario_retries_survive_compaction_and_reopen() {
    let mut producer = harness();
    let request = request(&producer);
    let intent = intent(&producer, 100);
    let first = execute(&mut producer, 0, &intent, &request)
        .unwrap()
        .unwrap();
    let claim = outcome(&producer, 0);
    for with_claim in [false, true] {
        let mut original = fgdb::WriteBatch::new(relation::IN_CASE);
        let mut created = std::collections::BTreeSet::new();
        for row in producer.db.vertices_at(first.recorded_at).unwrap() {
            if row.created_at == first.recorded_at && (with_claim || row.vid != claim) {
                assert!(created.insert(row.vid));
                original.create_vertex(row.vid, row.labels, row.props);
            }
        }
        assert_eq!(created.len(), if with_claim { 3 } else { 2 });
        for edge in producer.db.edges_at(first.recorded_at).unwrap() {
            if created.contains(&edge.entry.src) {
                assert_eq!(edge.entry.relation, relation::IN_CASE);
                original.add_edge(edge.entry.eid, edge.entry.src, edge.entry.dst, edge.props);
            }
        }
        let mut h = harness_legacy();
        h.write_raw(original);
        let sequence = h.db.frontier().unwrap();
        let original_row = h.db.vertex(first.control_entry).unwrap().unwrap();
        let original_claim = h.db.vertex(claim).unwrap();
        let ctx = h.ctx();
        h.runtime.block_on(h.db.compact(&ctx.commit())).unwrap();
        let (vfs, keys) = h.legacy_storage.clone().unwrap();
        let empty = h
            .runtime
            .block_on(Database::open_memory(&ctx.commit(), keys.clone()))
            .unwrap();
        drop(std::mem::replace(&mut h.db, empty));
        h.db = h
            .runtime
            .block_on(Database::open_with_vfs(
                &ctx.commit(),
                vfs.clone(),
                vfs.database_dir(),
                keys,
            ))
            .unwrap();
        let head = h.db.frontier().unwrap();
        let retry = execute(&mut h, 0, &intent, &request).unwrap().unwrap();
        assert!(retry.already_recorded);
        assert_eq!(
            (retry.control_entry, retry.recorded_at),
            (first.control_entry, sequence)
        );
        assert_eq!(
            h.db.vertex(first.control_entry).unwrap().unwrap(),
            original_row
        );
        assert_eq!(h.db.vertex(claim).unwrap(), original_claim);
        assert_eq!(h.db.frontier().unwrap(), head);
    }
}

#[test]
fn scenario_membership_reads_are_independent_of_unrelated_posting_edges() {
    let mut h = harness();
    let request = request(&h);
    let planned = intent(&h, 125);
    let opened = execute(&mut h, 0, &planned, &request).unwrap().unwrap();
    let recorded = execute(&mut h, 1, &planned, &request).unwrap().unwrap();
    let census = fa_journal::op_witness::begin();
    let expected = read_scenario(&h.db, &h.book, NAME).unwrap().unwrap();
    let original_work = census.finish();
    assert_eq!(original_work.edge_scans, 1);
    assert!(original_work.scanned_edges > 0);
    assert_eq!(original_work.vertex_scans, 0);

    for (batch_number, count) in [(1, 8), (2, 32)] {
        let members = (0..count)
            .map(|index| {
                h.proposal(
                    h.rent_legs(100),
                    format!("unrelated-{batch_number}-{index}").as_bytes(),
                    EntryClass::ORIGINAL,
                )
            })
            .collect();
        h.post_batch(h.batch(format!("unrelated-batch-{batch_number}").as_bytes(), members))
            .unwrap();
        let head = h.db.frontier().unwrap();
        assert!(h.db.edges_at(head).unwrap().len() > original_work.scanned_edges as usize);

        let census = fa_journal::op_witness::begin();
        let actual = read_scenario(&h.db, &h.book, NAME).unwrap().unwrap();
        let work = census.finish();
        assert_eq!(work.edge_scans, 1);
        assert_eq!(work.scanned_edges, original_work.scanned_edges);
        assert_eq!(work.vertex_scans, 0);
        assert_eq!(actual.body, expected.body);
        assert_eq!(actual.state, ScenarioState::Open);
        assert_eq!(actual.opened_at, opened.recorded_at);
        assert_eq!(actual.assumptions, expected.assumptions);
        assert_eq!(actual.intents.len(), 1);
        assert_eq!(actual.intents[0].record, recorded.control_entry);
        assert_eq!(actual.intents[0].recorded_at, recorded.recorded_at);
        assert_eq!(
            actual.intents[0].intent.canonical_bytes().unwrap(),
            planned.canonical_bytes().unwrap()
        );
        assert!(actual.discarded.is_none());
        assert_eq!(h.db.frontier().unwrap(), head);
    }
}

#[test]
fn scenario_listing_reads_memberships_once_and_keeps_order_and_corruption_checks() {
    let mut h = harness();
    let request = request(&h);
    let ctx = h.ctx();
    let mut records = Vec::new();
    // Names deliberately sort differently from their opening sequence.
    for name in ["z-last-name", "a-first-name", "m-middle-name"] {
        let recorded = h
            .runtime
            .block_on(open_scenario(
                &mut h.db,
                &ctx,
                &h.book,
                name,
                ScenarioFork::default(),
                request.clone(),
            ))
            .unwrap()
            .unwrap();
        records.push((name, recorded));
    }
    h.runtime
        .block_on(discard_scenario(
            &mut h.db,
            &ctx,
            &h.book,
            records[1].0,
            request,
        ))
        .unwrap()
        .unwrap();

    let census = fa_journal::op_witness::begin();
    let listed = list_scenarios(&h.db, &h.book).unwrap();
    let work = census.finish();
    let relation_work = h
        .db
        .edges_by_relation_at(relation::IN_CASE, h.db.frontier().unwrap())
        .unwrap();
    assert_eq!(work.edge_scans, 1);
    assert_eq!(work.scanned_edges as usize, relation_work.candidate_edges);
    assert_eq!(work.vertex_scans, 1);
    assert_eq!(listed.len(), records.len());
    for (index, (view, (name, opened))) in listed.iter().zip(&records).enumerate() {
        let single = read_scenario(&h.db, &h.book, name).unwrap().unwrap();
        assert_eq!(view.body, single.body);
        assert_eq!(view.body.name, *name);
        assert_eq!(view.opened_at, opened.recorded_at);
        assert_eq!(view.discarded, single.discarded);
        assert_eq!(
            view.state,
            if index == 1 {
                ScenarioState::Discarded
            } else {
                ScenarioState::Open
            }
        );
    }

    let mut damage = fgdb::WriteBatch::new(relation::IN_CASE);
    damage.set_vertex_property(
        records[2].1.control_entry,
        property::FA_EFFECTIVE_DAY,
        Some(CanonicalScalar::Int(1)),
    );
    h.write_raw(damage);
    assert!(list_scenarios(&h.db, &h.book).is_err());
    assert!(read_scenario(&h.db, &h.book, records[2].0).is_err());
    assert!(read_scenario(&h.db, &h.book, records[0].0).is_ok());
}
