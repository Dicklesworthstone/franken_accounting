//! Canon's immutable output grant and the posting principal's current
//! capability both constrain a rule-derived entry (plan §5.1, fa-c34).

use super::*;
use fa_canon::{CompiledRule, Inputs};
use fa_intents::{PostIntent, PostPlan};
use fa_journal::plan::{commit_plan, plan_post};
use fa_journal::rule::{
    RuleDerivation, activate_rule_version, plan_rule_activation, propose_rule_version,
    rule_derived_proposal,
};
use fa_model::{EventKind, EventResource, EventSpec};

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

fn propose(h: &mut Harness, ceiling: &str, key: &[u8]) -> CompiledRule {
    let ctx = h.ctx();
    let description = h.period_description();
    h.runtime
        .block_on(propose_rule_version(
            &mut h.db,
            &ctx,
            &h.book,
            &source(ceiling),
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
    let plan = plan_rule_activation(
        &h.db,
        &h.book,
        &controller(),
        &rule.ir_digest(),
        DateDay::from_ymd(2026, 3, 1).unwrap(),
        b"activate-bounded-rule",
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
