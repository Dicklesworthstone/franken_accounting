//! Canon's immutable output grant and the posting principal's current
//! capability both constrain a rule-derived entry (plan §5.1, fa-c34).

use super::*;
use fa_canon::{CompiledRule, Inputs};
use fa_intents::{BatchPlan, PostBatch, PostIntent, PostPlan};
use fa_journal::batch::{commit_batch_plan, plan_batch, post_batch};
use fa_journal::plan::{commit_plan, plan_post};
use fa_journal::refusal::code;
use fa_journal::rule::{
    RuleDerivation, activate_rule_version, automatic_rules_at, plan_rule_activation,
    propose_rule_version, rule_derived_proposal, rule_version_at, rule_versions_at,
};
use fa_model::{EventKind, EventResource, EventSpec};
use fgdb_delta_types::DeltaRow;

#[path = "rule_authority/automatic_drafts.rs"]
mod automatic_drafts;
#[path = "rule_authority/drafts.rs"]
mod drafts;
#[path = "rule_authority/outcome_keys.rs"]
mod outcome_keys;

fn source(ceiling: &str) -> String {
    format!(
        r#"rule bounded_sale v1 for event Sale {{
  authority {{
    debit "1000" upto "{ceiling} USD"
    credit "6000" upto "{ceiling} USD"
  }}
  let net = event.resource("net", "USD")
  debit "1000" net
  credit "6000" net
}}"#
    )
}

fn large_rule_source() -> String {
    let mut source = String::from(
        "rule large_balanced_sale v1 for event Sale {\n\
         authority {\n\
         debit \"1000\" upto \"100000.00 USD\"\n\
         credit \"6000\" upto \"100000.00 USD\"\n\
         }\n",
    );
    // Real expressions grow both source and IR. These 320 legs stay inside
    // Canon's 512-statement/leg bounds and allocate no let slots.
    for _ in 0..160 {
        source.push_str("debit \"1000\" event.resource(\"net\", \"USD\") / 2 round HalfEven\n");
        source.push_str("credit \"6000\" event.resource(\"net\", \"USD\") / 2 round HalfEven\n");
    }
    source.push('}');
    source
}

#[test]
fn oversized_canon_rule_round_trips_activates_and_posts() {
    let mut h = harness();
    let source = large_rule_source();
    let rule = fa_canon::compile(&source, &h.book.units).unwrap();
    assert!(source.len() > 16_384);
    assert!(source.len() <= fa_canon::MAX_SOURCE_BYTES);
    assert!(rule.ir().len() > 16_384);
    assert!(rule.slots().is_empty());
    assert_eq!(rule.legs().len(), 320);
    assert_eq!(
        CompiledRule::decode(rule.ir(), &h.book.units).unwrap(),
        rule
    );

    let before = h.db.frontier().unwrap();
    let rows_before = h.db.vertices().unwrap();
    let ctx = h.ctx();
    let description = h.period_description();
    let result = h.runtime.block_on(propose_rule_version(
        &mut h.db,
        &ctx,
        &h.book,
        &source,
        PREPARER,
        b"large-rule",
        description,
        &controller(),
    ));
    let recorded = match result {
        Ok(Ok(recorded)) => recorded,
        failure => {
            assert_eq!(h.db.frontier().unwrap(), before);
            assert_eq!(h.db.vertices().unwrap(), rows_before);
            panic!("valid oversized rule proposal failed: {failure:?}");
        }
    };
    assert!(!recorded.already_recorded);
    assert_eq!(recorded.version.spec.source, source);
    assert_eq!(recorded.version.spec.ir, rule.ir());
    let control_vid = recorded.control_entry.unwrap();
    let (control, recorded_at) = read_entry(&h.db, control_vid).unwrap().unwrap();
    let entry_bytes = control.encode().unwrap();
    assert!(entry_bytes.len() > 16_384);
    assert_eq!(recorded_at, recorded.version.created_at);
    assert_eq!(recorded_at.0, before.0 + 1);

    // The complete rule and SchemaControl body publish atomically. Pin the
    // registered cost to native effects, including the fragments and edge.
    let rule_fragments = recorded.version.spec.encode().unwrap().len().div_ceil(4096);
    let entry_fragments = entry_bytes.len().div_ceil(4096);
    let publications: Vec<_> = h.db.delta_since(before).unwrap().collect();
    assert_eq!(publications.len(), 1);
    let (mut entries, mut versions, mut fragments, mut memberships, mut outcomes) = (0, 0, 0, 0, 0);
    for coordinate in publications[0].coordinate_entries() {
        for row in &coordinate.rows {
            match row {
                DeltaRow::CreateVertex { labels, .. } if labels == &[label::ENTRY] => entries += 1,
                DeltaRow::CreateVertex { labels, .. } if labels == &[label::RULE_VERSION] => {
                    versions += 1;
                }
                DeltaRow::CreateVertex { labels, .. } if labels == &[label::ENTRY_FRAGMENT] => {
                    fragments += 1;
                }
                DeltaRow::CreateVertex { labels, .. } if labels == &[label::INTENT_OUTCOME] => {
                    outcomes += 1;
                }
                DeltaRow::CreateEdge {
                    relation, src, dst, ..
                } => {
                    assert_eq!(*relation, relation::IN_BOOK);
                    assert_eq!(*src, recorded.version.vid);
                    assert_eq!(*dst, book_root());
                    memberships += 1;
                }
                other => panic!("unexpected rule proposal effect: {other:?}"),
            }
        }
    }
    assert_eq!(
        (entries, versions, fragments, memberships, outcomes),
        (1, 1 + rule_fragments, entry_fragments, 1, 1)
    );
    assert_eq!(
        rule_version_at(&h.db, &h.book, &rule.ir_digest(), recorded_at).unwrap(),
        Some(recorded.version.clone()),
    );
    assert_eq!(
        rule_versions_at(&h.db, &h.book, recorded_at).unwrap(),
        vec![recorded.version.clone()],
        "storage fragments are not additional logical rule versions",
    );

    let rows = h.db.vertices().unwrap();
    for (key, expected_control) in [
        (b"large-rule".as_slice(), Some(control_vid)),
        (b"same-large-ir".as_slice(), None),
    ] {
        let description = h.period_description();
        let retry = h
            .runtime
            .block_on(propose_rule_version(
                &mut h.db,
                &ctx,
                &h.book,
                &source,
                PREPARER,
                key,
                description,
                &controller(),
            ))
            .unwrap()
            .unwrap();
        assert!(retry.already_recorded);
        assert_eq!(retry.version, recorded.version);
        assert_eq!(retry.control_entry, expected_control);
        assert_eq!(h.db.frontier().unwrap(), recorded_at);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert_eq!(h.db.delta_since(recorded_at).unwrap().count(), 0);
    }

    activate(&mut h, &rule);
    let event = event(&mut h, "LARGE-SALE", 4_000);
    let candidate = proposal(&h, &rule, &event, b"large-rule-output");
    assert_eq!(candidate.legs.len(), 320);
    assert!(
        candidate
            .legs
            .iter()
            .all(|leg| leg.amount == Amount::new(h.usd, 2_000))
    );
    assert!(matches!(
        h.post(candidate, controller(), Vec::new()).unwrap(),
        Posted::Committed { .. }
    ));
}

fn damage_rule_fragment(h: &mut Harness, version: VId, delete: bool) -> (VId, Vec<u8>) {
    let fragment =
        h.db.vertices()
            .unwrap()
            .into_iter()
            .find(|row| {
                row.vid != version
                    && row.labels == [label::RULE_VERSION]
                    && row.props.iter().any(|(key, _)| *key == property::FA_DIGEST)
            })
            .expect("a large rule has a native fragment");
    let original =
        fa_journal::rows::bytes(&fragment, property::FA_PAYLOAD, "rule fragment").unwrap();
    let mut mutation = WriteBatch::new(relation::CITES);
    if delete {
        mutation.delete_vertex(fragment.vid);
    } else {
        let mut damaged = original.clone();
        damaged[0] ^= 1;
        mutation.set_vertex_property(
            fragment.vid,
            property::FA_PAYLOAD,
            Some(fa_journal::rows::scalar_bytes("damaged rule fragment", damaged).unwrap()),
        );
    }
    let ctx = h.ctx();
    h.runtime
        .block_on(h.db.write(&ctx.commit(), mutation))
        .unwrap();
    (fragment.vid, original)
}

#[test]
fn oversized_rule_fragments_are_required_for_activation() {
    for delete in [false, true] {
        let mut h = harness();
        let rule = propose_source(&mut h, &large_rule_source(), b"fragment-activation-rule");
        let born = h.db.frontier().unwrap();
        let original = rule_version_at(&h.db, &h.book, &rule.ir_digest(), born)
            .unwrap()
            .unwrap();
        let plan = plan_rule_activation(
            &h.db,
            &h.book,
            &controller(),
            &rule.ir_digest(),
            DateDay::from_ymd(2026, 3, 1).unwrap(),
            b"fragment-activation",
            h.period_description(),
        )
        .unwrap()
        .unwrap();
        let digest = plan.proposal_digest(&h.book).unwrap();
        let approvals = vec![
            h.approve(ALICE, digest).unwrap().approval(),
            h.approve(BOB, digest).unwrap().approval(),
        ];
        let (fragment, original_bytes) = damage_rule_fragment(&mut h, original.vid, delete);
        let ctx = h.ctx();
        for restored in [false, true] {
            if restored {
                if delete {
                    break;
                }
                let mut restore = WriteBatch::new(relation::CITES);
                restore.set_vertex_property(
                    fragment,
                    property::FA_PAYLOAD,
                    Some(
                        fa_journal::rows::scalar_bytes(
                            "restored rule fragment",
                            original_bytes.clone(),
                        )
                        .unwrap(),
                    ),
                );
                h.runtime
                    .block_on(h.db.write(&ctx.commit(), restore))
                    .unwrap();
            }
            let head = h.db.frontier().unwrap();
            let rows = h.db.vertices().unwrap();
            assert!(matches!(
                rule_version_at(&h.db, &h.book, &rule.ir_digest(), head),
                Err(KernelError::Corrupt(_))
            ));
            assert_eq!(
                rule_version_at(&h.db, &h.book, &rule.ir_digest(), born).unwrap(),
                Some(original.clone())
            );
            let result = h.runtime.block_on(activate_rule_version(
                &mut h.db,
                &ctx,
                &h.book,
                &controller(),
                plan.clone(),
                approvals.clone(),
            ));
            assert!(
                matches!(result, Err(KernelError::Corrupt(_))),
                "delete={delete}, restored={restored}: {result:?}"
            );
            assert_eq!(h.db.frontier().unwrap(), head);
            assert_eq!(h.db.vertices().unwrap(), rows);
        }
    }
}

#[test]
fn rule_fragment_changes_conflict_with_prepared_posts_and_refuse_fresh_posts() {
    for delete in [false, true] {
        let mut h = harness();
        let rule = propose_source(&mut h, &large_rule_source(), b"fragment-post-rule");
        activate(&mut h, &rule);
        let event = event(&mut h, "FRAGMENT-SALE", 4_000);
        let candidate = proposal(&h, &rule, &event, b"fragment-post");
        let ctx = h.ctx();
        let request = PostRequest {
            proposal: candidate,
            capability: controller(),
            approvals: Vec::new(),
            plan_certificate: None,
        };
        let prepared = fa_journal::post::prepare_post(&mut h.db, &ctx, &h.book, request.clone())
            .unwrap()
            .unwrap();
        let fa_journal::post::PostPreparation::Ready(prepared) = prepared else {
            panic!("a valid large rule output must prepare before its storage changes");
        };
        let basis = h.db.frontier().unwrap();
        let original = rule_version_at(&h.db, &h.book, &rule.ir_digest(), basis)
            .unwrap()
            .unwrap();
        damage_rule_fragment(&mut h, original.vid, delete);
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let refused = h
            .runtime
            .block_on(prepared.commit(&mut h.db, &ctx))
            .unwrap()
            .unwrap_err();
        assert_eq!(refused.code, code::CONFLICT, "delete={delete}: {refused:?}");
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
        let fresh = h.runtime.block_on(post(&mut h.db, &ctx, &h.book, request));
        assert!(
            matches!(fresh, Err(KernelError::Corrupt(_))),
            "delete={delete}: {fresh:?}"
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert_eq!(
            rule_version_at(&h.db, &h.book, &rule.ir_digest(), basis).unwrap(),
            Some(original)
        );
    }
}

fn propose(h: &mut Harness, ceiling: &str, key: &[u8]) -> CompiledRule {
    propose_source(h, &source(ceiling), key)
}

fn propose_source(h: &mut Harness, source: &str, key: &[u8]) -> CompiledRule {
    let ctx = h.ctx();
    let description = h.period_description();
    h.runtime
        .block_on(propose_rule_version(
            &mut h.db,
            &ctx,
            &h.book,
            source,
            PREPARER,
            key,
            description,
            &controller(),
        ))
        .unwrap()
        .unwrap()
        .version
        .rule
}

fn activate(h: &mut Harness, rule: &CompiledRule) {
    activate_with_key(h, rule, b"activate-bounded-rule");
}

fn activate_with_key(h: &mut Harness, rule: &CompiledRule, key: &[u8]) {
    let plan = plan_rule_activation(
        &h.db,
        &h.book,
        &controller(),
        &rule.ir_digest(),
        DateDay::from_ymd(2026, 3, 1).unwrap(),
        key,
        h.period_description(),
    )
    .unwrap()
    .unwrap();
    let digest = plan.proposal_digest(&h.book).unwrap();
    let approvals = vec![
        h.approve(ALICE, digest).unwrap().approval(),
        h.approve(BOB, digest).unwrap().approval(),
    ];
    let ctx = h.ctx();
    h.runtime
        .block_on(activate_rule_version(
            &mut h.db,
            &ctx,
            &h.book,
            &controller(),
            plan,
            approvals,
        ))
        .unwrap()
        .unwrap();
}

fn event(h: &mut Harness, code: &str, cents: i128) -> EventSpec {
    let spec = EventSpec {
        code: code.into(),
        kind: EventKind::Sale,
        occurred_on: DateDay::from_ymd(2026, 3, 15).unwrap(),
        description: h.period_description(),
        participants: Vec::new(),
        resources: vec![EventResource {
            label: "net".into(),
            amount: Amount::new(h.usd, cents),
            instrument: None,
        }],
        evidence: h.evidence.clone(),
        external_ids: Vec::new(),
    };
    let ctx = h.ctx();
    let description = h.period_description();
    h.runtime
        .block_on(fa_journal::rea::record_event(
            &mut h.db,
            &ctx,
            &h.book,
            &spec,
            PREPARER,
            spec.occurred_on,
            code.as_bytes(),
            description,
            &controller(),
        ))
        .unwrap()
        .unwrap();
    spec
}

fn proposal(h: &Harness, rule: &CompiledRule, event: &EventSpec, key: &[u8]) -> EntryPayload {
    let inputs = Inputs::new();
    let bytes = fa_canon::encode_inputs(rule, &inputs).unwrap();
    let derivation = fa_canon::evaluate(rule, event, &inputs).unwrap();
    rule_derived_proposal(
        &h.book,
        &RuleDerivation {
            rule,
            event: fa_model::event_vid(h.book.book_id, &event.code),
            inputs: &bytes,
            derivation: &derivation,
            evidence: &event.evidence,
        },
        PREPARER,
        key,
        h.period_description(),
    )
    .unwrap()
}

#[test]
fn declared_rule_authority_is_enforced_during_preparation_and_commit() {
    let mut h = harness();
    let rule = propose(&mut h, "40.00", b"bounded-rule");
    activate(&mut h, &rule);
    let allowed = event(&mut h, "AT-LIMIT", 4_000);
    let forbidden = event(&mut h, "OVER-LIMIT", 4_001);
    let valid = proposal(&h, &rule, &allowed, b"allowed-rule-output");

    // Still exactly the arithmetic the rule derives from OVER-LIMIT.
    // Only the separate, immutable authority grant makes it inadmissible.
    let mut forged = valid.clone();
    forged.idempotency_key = b"outside-rule-authority".to_vec();
    if let EntryOrigin::Rule { event_ref, .. } = &mut forged.origin {
        *event_ref = fa_model::event_vid(h.book.book_id, &forbidden.code);
    } else {
        panic!("a rule proposal must carry its rule origin");
    }
    for leg in &mut forged.legs {
        leg.amount = Amount::new(h.usd, 4_001);
    }
    forged.unit_totals = EntryPayload::fold_unit_totals(&forged.legs).unwrap();
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let ctx = h.ctx();
    // Encoding a Rule-derived intent does not grant its candidate effects
    // authority: ordinary native planning must reproduce the same refusal.
    let intent = PostIntent::rule_derived(forged.clone(), Vec::new()).unwrap();
    let refused = plan_post(&mut h.db, &ctx, &h.book, controller(), intent, None)
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, "FA-REF-196", "{refused:?}");
    assert!(refused.fix.contains("authority"), "{refused:?}");
    let request = |proposal| PostRequest {
        proposal,
        capability: controller(),
        approvals: Vec::new(),
        plan_certificate: None,
    };
    let refused = fa_journal::post::prepare_post(&mut h.db, &ctx, &h.book, request(forged.clone()))
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, "FA-REF-196", "{refused:?}");
    assert!(refused.fix.contains("authority"), "{refused:?}");
    let refused = h.post(forged, controller(), Vec::new()).unwrap_err();
    assert_eq!(refused.code, "FA-REF-196", "{refused:?}");
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);

    let prepared = fa_journal::post::prepare_post(&mut h.db, &ctx, &h.book, request(valid.clone()))
        .unwrap()
        .unwrap();
    let fa_journal::post::PostPreparation::Ready(prepared) = prepared else {
        panic!("a fresh permitted rule output must be prepared");
    };
    prepared.abort();
    assert_eq!(h.db.frontier().unwrap(), head);
    let posted = h.post(valid, controller(), Vec::new()).unwrap();
    assert!(matches!(posted, Posted::Committed { .. }));
}

#[test]
fn rule_authority_never_widens_the_callers_capability() {
    let mut h = harness();
    let rule = propose(&mut h, "40.00", b"caller-intersection");
    activate(&mut h, &rule);
    let event = event(&mut h, "CALLER-CEILING", 4_000);
    let candidate = proposal(&h, &rule, &event, b"caller-intersection-post");
    let cap = controller().with_ceiling(h.usd, 3_999).unwrap();
    let head = h.db.frontier().unwrap();
    let refused = h.post(candidate.clone(), cap, Vec::new()).unwrap_err();
    assert_eq!(refused.exit, exit::SAFETY, "{refused:?}");
    assert_eq!(h.db.frontier().unwrap(), head);
    h.post(candidate, controller(), Vec::new()).unwrap();
}

#[test]
fn changing_rule_authority_requires_new_activation_approvals() {
    let mut h = harness();
    let narrow = propose(&mut h, "40.00", b"authority-narrow");
    let broad = propose(&mut h, "400.00", b"authority-broad");
    assert_ne!(narrow.ir_digest(), broad.ir_digest());
    let prepare = |rule: &CompiledRule, key: &[u8]| {
        plan_rule_activation(
            &h.db,
            &h.book,
            &controller(),
            &rule.ir_digest(),
            DateDay::from_ymd(2026, 3, 1).unwrap(),
            key,
            h.period_description(),
        )
        .unwrap()
        .unwrap()
    };
    let narrow_plan = prepare(&narrow, b"approve-narrow-authority");
    let broad_plan = prepare(&broad, b"activate-broad-authority");
    let digest = narrow_plan.proposal_digest(&h.book).unwrap();
    let approvals = vec![
        h.approve(ALICE, digest).unwrap().approval(),
        h.approve(BOB, digest).unwrap().approval(),
    ];
    let head = h.db.frontier().unwrap();
    let ctx = h.ctx();
    assert!(
        h.runtime
            .block_on(activate_rule_version(
                &mut h.db,
                &ctx,
                &h.book,
                &controller(),
                broad_plan,
                approvals.clone(),
            ))
            .unwrap()
            .is_err(),
        "approvals of a narrow grant cannot activate a wider one",
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    h.runtime
        .block_on(activate_rule_version(
            &mut h.db,
            &ctx,
            &h.book,
            &controller(),
            narrow_plan,
            approvals,
        ))
        .unwrap()
        .unwrap();
}

#[test]
fn stored_source_cannot_present_a_narrower_grant_than_its_retained_ir() {
    let mut h = harness();
    let rule = propose(&mut h, "400.00", b"source-authority-binding");
    let vid = fa_model::rule_version_vid(h.book.book_id, &rule.ir_digest());
    let mut row = h.db.vertex(vid).unwrap().unwrap();
    let decoded = fa_journal::rule::RuleVersionRow::decode(&row, &h.book)
        .unwrap()
        .unwrap();
    let mut spec = decoded.spec;
    spec.source = source("40.00");
    let (_, payload) = row
        .props
        .iter_mut()
        .find(|(key, _)| *key == property::FA_PAYLOAD)
        .unwrap();
    *payload = CanonicalScalar::bytes(spec.encode().unwrap()).unwrap();
    let error = fa_journal::rule::RuleVersionRow::decode(&row, &h.book).unwrap_err();
    assert!(format!("{error:?}").contains("stored source"), "{error:?}");
}

#[test]
fn the_proposal_factory_rejects_a_forged_public_derivation_outside_the_grant() {
    let mut h = harness();
    let rule = propose(&mut h, "40.00", b"factory-authority");
    let event = event(&mut h, "FACTORY-BOUNDARY", 4_000);
    let inputs = Inputs::new();
    let bytes = fa_canon::encode_inputs(&rule, &inputs).unwrap();
    let mut derivation = fa_canon::evaluate(&rule, &event, &inputs).unwrap();
    for leg in &mut derivation.legs {
        leg.amount = Amount::new(h.usd, 4_001);
    }
    let refused = rule_derived_proposal(
        &h.book,
        &RuleDerivation {
            rule: &rule,
            event: fa_model::event_vid(h.book.book_id, &event.code),
            inputs: &bytes,
            derivation: &derivation,
            evidence: &event.evidence,
        },
        PREPARER,
        b"forged-factory-output",
        h.period_description(),
    )
    .unwrap_err();
    assert_eq!(refused.code, "FA-REF-196", "{refused:?}");
}

#[test]
fn rule_derived_portable_plan_binds_authority_and_retries_its_exact_outcome() {
    let mut h = harness();
    let rule = propose(&mut h, "40.00", b"portable-rule-authority");
    activate(&mut h, &rule);
    let event = event(&mut h, "PORTABLE-RULE", 4_000);
    let candidate = proposal(&h, &rule, &event, b"portable-rule-post");
    let intent = PostIntent::rule_derived(candidate, Vec::new()).unwrap();
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let ctx = h.ctx();
    let refused = fa_journal::scenario::admit_scenario_intent(
        &h.db,
        &h.book,
        "rule-profile-must-refuse",
        &intent,
        &controller(),
    )
    .unwrap()
    .unwrap_err();
    assert_eq!(refused.code, fa_journal::refusal::code::STRUCTURE);
    assert_eq!(refused.exit, exit::USAGE);
    assert!(
        refused.message.contains("single native PostPlan"),
        "{refused:?}"
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);

    let plan = plan_post(&mut h.db, &ctx, &h.book, controller(), intent, None)
        .unwrap()
        .unwrap();
    let bytes = plan.canonical_bytes().unwrap();
    let decoded = PostPlan::decode(&bytes).unwrap();
    assert_eq!(decoded, plan);
    assert!(matches!(
        &decoded.intent().proposal().origin,
        EntryOrigin::Rule { rule_version_oid, .. } if rule_version_oid.0 == rule.ir_digest()
    ));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);

    // This capability may post the exact effects, but it is not the capability
    // whose commitment the saved plan binds. The artifact supplies no authority.
    let different_capability = human(PREPARER, &["post", "rule_change", "read"]);
    assert_ne!(
        different_capability.commitment().unwrap(),
        plan.certificate().capability_commitment
    );
    let refused = h
        .runtime
        .block_on(commit_plan(
            &mut h.db,
            &ctx,
            &h.book,
            different_capability,
            decoded.clone(),
            None,
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(
        refused.code,
        fa_journal::refusal::code::PLAN_INVALIDATED,
        "{refused:?}"
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);

    let posted = h
        .runtime
        .block_on(commit_plan(
            &mut h.db,
            &ctx,
            &h.book,
            controller(),
            decoded,
            None,
        ))
        .unwrap()
        .unwrap();
    assert!(matches!(&posted, Posted::Committed { .. }));
    let reference = posted.entry_ref();
    let (recorded, recorded_at) = read_entry(&h.db, reference.vid).unwrap().unwrap();
    assert_eq!(&recorded.proposal, plan.proposal());
    assert_eq!(recorded.proposal_digest, plan.certificate().proposal_digest);
    assert_eq!(recorded.entry_ref(reference.vid), reference);
    assert_eq!(recorded_at, posted.recorded_at());

    // Reopen the same portable bytes after publication. Its exact retained
    // certificate and entry must be recognized without a second journal write.
    let committed_head = h.db.frontier().unwrap();
    let committed_rows = h.db.vertices().unwrap();
    let retry = h
        .runtime
        .block_on(commit_plan(
            &mut h.db,
            &ctx,
            &h.book,
            controller(),
            PostPlan::decode(&bytes).unwrap(),
            None,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(
        retry,
        Posted::AlreadyRecorded {
            entry_ref: reference,
            recorded_at,
        }
    );
    assert_eq!(h.db.frontier().unwrap(), committed_head);
    assert_eq!(h.db.vertices().unwrap(), committed_rows);
}

fn automatic_capability() -> Capability {
    human(PREPARER, &["read", "post"])
}

fn automatic_rule(h: &mut Harness, name: &str, credit: &str) -> CompiledRule {
    let source = format!(
        r#"rule {name} v1 for event Sale {{
  let net = event.resource("net", "USD")
  debit "1000" net
  credit "{credit}" net
}}"#
    );
    let rule = propose_source(h, &source, format!("propose-{name}").as_bytes());
    activate_with_key(h, &rule, format!("activate-{name}").as_bytes());
    rule
}

fn automatic_batch(
    h: &Harness,
    rules: &[&CompiledRule],
    event: &EventSpec,
    key: &[u8],
) -> PostBatch {
    let members = rules
        .iter()
        .map(|rule| {
            let key = format!("automatic:{}:{}", rule.name(), event.code);
            PostIntent::rule_derived(proposal(h, rule, event, key.as_bytes()), Vec::new()).unwrap()
        })
        .collect();
    PostBatch::automatic_rules(
        fa_model::event_vid(h.book.book_id, &event.code),
        key.to_vec(),
        members,
    )
    .unwrap()
}

#[test]
fn automatic_rule_batch_commits_one_complete_plan_and_retries_after_catalog_growth() {
    let mut h = harness();
    let alpha = automatic_rule(&mut h, "alpha_sale", "6000");
    let omega = automatic_rule(&mut h, "omega_sale", "6000");
    let event = event(&mut h, "AUTOMATIC", 4_000);
    let event_vid = fa_model::event_vid(h.book.book_id, &event.code);
    let capability = automatic_capability();
    let before = h.db.frontier().unwrap();
    let selected = automatic_rules_at(&h.db, &h.book, &capability, event_vid, before)
        .unwrap()
        .unwrap();
    assert_eq!(selected.event.spec, event);
    assert_eq!(
        selected
            .versions
            .iter()
            .map(|version| version.rule.name())
            .collect::<Vec<_>>(),
        vec!["alpha_sale", "omega_sale"],
    );
    let batch = automatic_batch(&h, &[&alpha, &omega], &event, b"automatic-complete");
    let requested = batch.clone();
    let ctx = h.ctx();
    let before_rows = h.db.vertices().unwrap();
    let plan = plan_batch(&mut h.db, &ctx, &h.book, capability.clone(), batch, None)
        .unwrap()
        .unwrap();
    let bytes = plan.canonical_bytes().unwrap();
    let decoded = BatchPlan::decode(&bytes).unwrap();
    assert_eq!(decoded, plan);
    assert_eq!(decoded.batch().automatic_event(), Some(event_vid));
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(h.db.vertices().unwrap(), before_rows);
    let posted = h
        .runtime
        .block_on(commit_batch_plan(
            &mut h.db,
            &ctx,
            &h.book,
            capability.clone(),
            decoded,
            None,
        ))
        .unwrap()
        .unwrap();
    assert!(!posted.already_recorded);
    assert_eq!(posted.entries.len(), 2);
    for (reference, member) in posted.entries.iter().zip(requested.members()) {
        let (recorded, sequence) = read_entry(&h.db, reference.vid).unwrap().unwrap();
        assert_eq!(recorded.entry_ref(reference.vid), *reference);
        assert_eq!(&recorded.proposal, member.proposal());
        assert_eq!(
            sequence, posted.recorded_at,
            "every member shares one publication"
        );
    }
    let (outcome, recorded_at) =
        fa_journal::batch::read_outcome(&h.db, &ctx.query(), posted.outcome)
            .unwrap()
            .unwrap();
    assert_eq!(outcome.entries, posted.entries);
    assert_eq!(recorded_at, posted.recorded_at);

    // Existing explicit derivation keys still find the member's exact outcome.
    let member_retry = h
        .post(
            requested.members()[0].proposal().clone(),
            capability.clone(),
            Vec::new(),
        )
        .unwrap();
    assert_eq!(member_retry.entry_ref(), posted.entries[0]);
    assert!(matches!(member_retry, Posted::AlreadyRecorded { .. }));

    automatic_rule(&mut h, "zeta_sale", "6000");
    let after_activation = h.db.frontier().unwrap();
    assert_eq!(
        automatic_rules_at(&h.db, &h.book, &capability, event_vid, after_activation)
            .unwrap()
            .unwrap()
            .versions
            .len(),
        3,
    );
    let after_rows = h.db.vertices().unwrap();
    // A saved successful plan and the original immediate request retain their
    // recorded outcome even though today's complete rule set is larger.
    let retry = h
        .runtime
        .block_on(commit_batch_plan(
            &mut h.db,
            &ctx,
            &h.book,
            capability.clone(),
            BatchPlan::decode(&bytes).unwrap(),
            None,
        ))
        .unwrap()
        .unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, posted.entries);
    assert_eq!(retry.recorded_at, posted.recorded_at);
    let immediate_retry = h
        .runtime
        .block_on(post_batch(&mut h.db, &ctx, &h.book, capability, requested))
        .unwrap()
        .unwrap();
    assert!(immediate_retry.already_recorded);
    assert_eq!(immediate_retry.entries, posted.entries);
    assert_eq!(h.db.frontier().unwrap(), after_activation);
    assert_eq!(h.db.vertices().unwrap(), after_rows);
}

#[test]
fn automatic_rule_batch_refuses_omitted_or_reordered_active_rules_without_writes() {
    let mut h = harness();
    let alpha = automatic_rule(&mut h, "alpha_sale", "6000");
    let omega = automatic_rule(&mut h, "omega_sale", "6000");
    let event = event(&mut h, "COMPLETE-SET", 4_000);
    let capability = automatic_capability();
    let before = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let ctx = h.ctx();
    let incomplete = automatic_batch(&h, &[&alpha], &event, b"omitted-rule");
    let reordered = automatic_batch(&h, &[&omega, &alpha], &event, b"reordered-rules");
    for batch in [incomplete, reordered] {
        let refused = plan_batch(
            &mut h.db,
            &ctx,
            &h.book,
            capability.clone(),
            batch.clone(),
            None,
        )
        .unwrap()
        .unwrap_err();
        assert_eq!(refused.code, code::CANON_RULE, "{refused:?}");
        assert!(
            refused.message.contains("complete activated selection"),
            "{refused:?}"
        );
        let refused = h
            .runtime
            .block_on(post_batch(
                &mut h.db,
                &ctx,
                &h.book,
                capability.clone(),
                batch,
            ))
            .unwrap()
            .unwrap_err();
        assert_eq!(refused.code, code::CANON_RULE, "{refused:?}");
        assert_eq!(h.db.frontier().unwrap(), before);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn automatic_rule_batch_rolls_back_an_earlier_member_when_the_later_rule_refuses() {
    let mut h = harness();
    let alpha = automatic_rule(&mut h, "alpha_sale", "6000");
    let omega = automatic_rule(&mut h, "omega_missing_account", "9999");
    let event = event(&mut h, "LATE-FAILURE", 4_000);
    let batch = automatic_batch(&h, &[&alpha, &omega], &event, b"atomic-late-failure");
    let capability = automatic_capability();
    let ctx = h.ctx();
    let before = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let refusal = plan_batch(
        &mut h.db,
        &ctx,
        &h.book,
        capability.clone(),
        batch.clone(),
        None,
    )
    .unwrap()
    .unwrap_err();
    assert!(
        refusal.message.starts_with("batch member 1:"),
        "{refusal:?}"
    );
    let immediate = h
        .runtime
        .block_on(post_batch(
            &mut h.db,
            &ctx,
            &h.book,
            capability,
            batch.clone(),
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(immediate.code, refusal.code);
    assert!(
        immediate.message.starts_with("batch member 1:"),
        "{immediate:?}"
    );
    for member in batch.members() {
        let proposal = member.proposal();
        let vid = fa_model::entry_vid(
            h.book.book_id,
            &proposal.principal_ref.0.to_le_bytes(),
            &proposal.idempotency_key,
        );
        assert!(read_entry(&h.db, vid).unwrap().is_none());
    }
    assert!(
        fa_journal::batch::read_outcome(
            &h.db,
            &ctx.query(),
            fa_journal::batch::outcome_vid(&h.book, &batch),
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

#[test]
fn automatic_rule_batch_plan_refuses_a_new_matching_activation_before_publication() {
    let mut h = harness();
    let alpha = automatic_rule(&mut h, "alpha_sale", "6000");
    let event = event(&mut h, "CATALOG-DRIFT", 4_000);
    let batch = automatic_batch(&h, &[&alpha], &event, b"catalog-drift");
    let requested = batch.clone();
    let capability = automatic_capability();
    let ctx = h.ctx();
    let plan = plan_batch(&mut h.db, &ctx, &h.book, capability.clone(), batch, None)
        .unwrap()
        .unwrap();
    automatic_rule(&mut h, "omega_sale", "6000");
    let after_activation = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let refused = h
        .runtime
        .block_on(commit_batch_plan(
            &mut h.db,
            &ctx,
            &h.book,
            capability.clone(),
            plan,
            None,
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, code::PLAN_INVALIDATED, "{refused:?}");
    // A caller cannot evade catalog invalidation by submitting that old
    // one-member selection as a fresh immediate automatic batch.
    let refused = h
        .runtime
        .block_on(post_batch(&mut h.db, &ctx, &h.book, capability, requested))
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, code::CANON_RULE, "{refused:?}");
    assert!(
        refused.message.contains("complete activated selection"),
        "{refused:?}"
    );
    assert_eq!(h.db.frontier().unwrap(), after_activation);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

#[test]
fn automatic_rule_selection_requires_read_and_refuses_empty_or_input_dependent_populations() {
    let mut h = harness();
    let event = event(&mut h, "REQUIRED-INPUT", 4_000);
    let event_vid = fa_model::event_vid(h.book.book_id, &event.code);
    let capability = automatic_capability();
    let before = h.db.frontier().unwrap();
    let no_rules = automatic_rules_at(&h.db, &h.book, &capability, event_vid, before)
        .unwrap()
        .unwrap_err();
    assert_eq!(no_rules.code, code::CANON_RULE);
    assert!(
        no_rules.message.contains("no activated rule"),
        "{no_rules:?}"
    );

    let alpha = automatic_rule(&mut h, "alpha_sale", "6000");
    let batch = automatic_batch(&h, &[&alpha], &event, b"must-not-skip-input");
    let post_only = human(PREPARER, &["post"]);
    let at = h.db.frontier().unwrap();
    let denied = automatic_rules_at(&h.db, &h.book, &post_only, event_vid, at)
        .unwrap()
        .unwrap_err();
    let absent = automatic_rules_at(&h.db, &h.book, &post_only, VId(0xfafa), at)
        .unwrap()
        .unwrap_err();
    assert_eq!(denied.code, code::CAPABILITY);
    assert_eq!(
        denied, absent,
        "source existence is not observed without read authority"
    );
    let ctx = h.ctx();
    let refused = plan_batch(&mut h.db, &ctx, &h.book, post_only, batch.clone(), None)
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, denied.code);

    let input_rule = propose_source(
        &mut h,
        r#"rule omega_with_input v1 for event Sale {
  inputs { as_of: date }
  let net = event.resource("net", "USD")
  debit "1000" net
  credit "6000" net
  effective as_of
}"#,
        b"propose-input-rule",
    );
    activate_with_key(&mut h, &input_rule, b"activate-input-rule");
    let at = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let refused = automatic_rules_at(&h.db, &h.book, &capability, event_vid, at)
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, code::CANON_RULE);
    assert!(
        refused.message.contains("requires explicit inputs"),
        "{refused:?}"
    );
    let refused = h
        .runtime
        .block_on(post_batch(&mut h.db, &ctx, &h.book, capability, batch))
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, code::CANON_RULE);
    assert!(
        refused.message.contains("requires explicit inputs"),
        "{refused:?}"
    );
    assert_eq!(h.db.frontier().unwrap(), at);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

#[test]
fn automatic_rule_batch_allows_agent_rehearsal_without_trunk_publication() {
    let mut h = harness();
    let rule = automatic_rule(&mut h, "agent_sale", "6000");
    let event = event(&mut h, "AGENT-AUTOMATIC", 4_000);
    let event_vid = fa_model::event_vid(h.book.book_id, &event.code);
    let mut member = proposal(&h, &rule, &event, b"agent-rule-member");
    member.principal_ref = AGENT;
    let batch = PostBatch::automatic_rules(
        event_vid,
        b"agent-rule-batch".to_vec(),
        vec![PostIntent::rule_derived(member, Vec::new()).unwrap()],
    )
    .unwrap();
    let capability =
        Capability::new(AGENT, Profile::Agent, &[Op::Read, Op::Post], PREPARER).unwrap();
    let ctx = h.ctx();
    let before = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let plan = plan_batch(&mut h.db, &ctx, &h.book, capability.clone(), batch, None)
        .unwrap()
        .unwrap();
    assert_eq!(plan.batch().automatic_event(), Some(event_vid));
    let refusal = h
        .runtime
        .block_on(commit_batch_plan(
            &mut h.db, &ctx, &h.book, capability, plan, None,
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-013");
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(h.db.vertices().unwrap(), rows);
}
