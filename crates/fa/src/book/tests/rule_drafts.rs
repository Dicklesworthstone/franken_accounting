//! A named Canon derivation is a confined posting preparation, not a read grant.

use super::*;
use crate::rule::{CompiledRule, InputValue, Inputs, RuleIntentKind};
use fa_journal::refusal::code;
use fa_policy::{Op, Profile};

const NAME: &str = "private-rule-review";
const OWNER: VId = VId(41);
const RULE: &str = r#"rule confidential_accrual v1 for event Sale produces Adjusting {
  inputs { as_of: date, fee: amount("USD") }
  authority {
    debit "6000" upto "80.00 USD"
    credit "1000" upto "80.00 USD"
  }
  let net = event.resource("private_net", "USD") + fee
  debit "6000" net
  credit "1000" net
  effective as_of
}"#;

const AUTOMATIC_RULE: &str = r#"rule automatic_private_alpha v1 for event Sale produces Adjusting {
  authority {
    debit "6000" upto "80.00 USD"
    credit "1000" upto "80.00 USD"
  }
  let net = event.resource("private_net", "USD")
  debit "6000" net
  credit "1000" net
  effective event.occurred_on
}"#;

struct Fixture {
    book: Book,
    usd: fa_money::UnitId,
    day: DateDay,
    rule: CompiledRule,
    event: VId,
    planner: Capability,
    inputs: Inputs,
}

fn activate(book: &mut Book, source: &str, from: DateDay, key: &str) -> CompiledRule {
    let controller = Capability::embedded(VId(1), &["rule_change", "read"]).unwrap();
    let rule = book
        .propose_rule_version(
            source,
            VId(1),
            format!("propose-{key}").as_bytes(),
            &controller,
        )
        .unwrap()
        .unwrap()
        .version
        .rule;
    let plan = book
        .plan_rule_activation(&controller, &rule.ir_digest(), from, key.as_bytes())
        .unwrap()
        .unwrap();
    let digest = plan.proposal_digest(book.context()).unwrap();
    let approvals = [VId(2), VId(3)]
        .into_iter()
        .map(|who| {
            book.approve(Capability::embedded(who, &["approve"]).unwrap(), digest)
                .unwrap()
                .unwrap()
                .approval()
        })
        .collect();
    book.activate_rule_version(&controller, plan, approvals)
        .unwrap()
        .unwrap();
    rule
}

fn fixture() -> Fixture {
    fixture_with_rule(RULE)
}

fn fixture_with_rule(source_rule: &str) -> Fixture {
    let (mut book, usd, day, source) = certified_fixture();
    let event = fa_model::EventSpec {
        code: "PRIVATE-EVENT-CODE".into(),
        kind: fa_model::EventKind::Sale,
        occurred_on: day,
        description: book.seal_text("private source description").unwrap(),
        participants: Vec::new(),
        resources: vec![fa_model::EventResource {
            label: "private_net".into(),
            amount: Amount::new(usd, 4_000),
            instrument: None,
        }],
        evidence: book
            .read_entry(source)
            .unwrap()
            .unwrap()
            .0
            .proposal
            .evidence,
        external_ids: Vec::new(),
    };
    book.record_event(
        &event,
        VId(1),
        day,
        b"private-rule-event",
        &Capability::embedded(VId(1), &["schema_change"]).unwrap(),
    )
    .unwrap()
    .unwrap();
    let event = fa_model::event_vid(book.context().book_id, &event.code);
    let rule = activate(&mut book, source_rule, day, "private-rule-v1");
    let planner = Capability::new(OWNER, Profile::Agent, &[Op::Post], VId(1))
        .unwrap()
        .on_branch(fa_model::draft_branch(book.context().book_id, NAME))
        .unwrap()
        .for_accounts(&["1000", "6000"])
        .unwrap()
        .for_periods(&["FY2026-P03"])
        .unwrap()
        .for_classes(&[EntryClass::ADJUSTING])
        .unwrap()
        .with_ceiling(usd, 4_300)
        .unwrap();
    book.open_draft(planner.clone(), NAME, day, "Review selected effects")
        .unwrap()
        .unwrap();
    let mut inputs = Inputs::new();
    inputs
        .set("as_of", InputValue::Date(day))
        .set("fee", InputValue::Amount(Amount::new(usd, 300)));
    Fixture {
        book,
        usd,
        day,
        rule,
        event,
        planner,
        inputs,
    }
}

fn prepare(f: &Fixture, capability: &Capability) -> Outcome<fa_intents::PostIntent> {
    f.book.prepare_rule_entry_in_draft(
        capability,
        NAME,
        &f.rule.ir_digest(),
        f.event,
        &f.inputs,
        None,
    )
}

fn assert_private(refusal: &fa_journal::Refusal) {
    let text = format!("{refusal:?}");
    for hidden in [
        "confidential_accrual",
        "PRIVATE-EVENT-CODE",
        "private_net",
        "43.00",
        "4300",
    ] {
        assert!(!text.contains(hidden), "source escaped in {text}");
    }
}

#[test]
fn post_only_rule_sources_preserve_identity_and_promote_exact_reviewed_effects() {
    let mut f = fixture();
    let before = f.book.head().unwrap();
    let intent = prepare(&f, &f.planner).unwrap().unwrap();
    let p = intent.proposal();
    assert_eq!(
        p.idempotency_key,
        crate::rule::default_derivation_key(&f.rule, f.event, &f.inputs)
            .unwrap()
            .into_bytes()
    );
    assert_eq!(p.class, EntryClass::ADJUSTING);
    assert_eq!(p.legs.len(), 2);
    assert!(
        p.legs
            .iter()
            .all(|leg| leg.amount == Amount::new(f.usd, 4_300))
    );
    assert_eq!(p.effective_date, f.day);
    assert_eq!(p.principal_ref, OWNER);
    assert_eq!(
        p.description
            .open(
                &f.book.context().seal_key,
                fa_model::limits::MAX_DESCRIPTION_BYTES
            )
            .unwrap(),
        "Selected rule derivation for draft review"
    );
    assert_eq!(f.book.head().unwrap(), before);
    assert_eq!(
        f.book
            .rule_version(&f.rule.ir_digest(), None, &f.planner)
            .unwrap()
            .unwrap_err()
            .code,
        code::CAPABILITY
    );
    assert_eq!(
        f.book
            .prepare_rule_entry(
                &f.planner,
                &f.rule.ir_digest(),
                f.event,
                &f.inputs,
                b"read-denied"
            )
            .unwrap()
            .unwrap_err()
            .code,
        code::CAPABILITY
    );
    assert!(f.book.plan(intent.clone(), &f.planner).unwrap().is_err());
    assert!(
        f.book
            .post(PostRequest {
                proposal: p.clone(),
                capability: f.planner.clone(),
                approvals: Vec::new(),
                plan_certificate: None
            })
            .unwrap()
            .is_err()
    );
    assert_eq!(f.book.head().unwrap(), before);
    let planned = f
        .book
        .plan_into_draft(f.planner.clone(), NAME, intent)
        .unwrap()
        .unwrap();
    let reviewed = planned.plan.unwrap().members()[0].entry.clone();
    let planned_at = f.book.head().unwrap();
    for kind in [RuleIntentKind::Accrue, RuleIntentKind::Defer] {
        let retry = f
            .book
            .prepare_rule_intent_in_draft(
                &f.planner,
                NAME,
                kind,
                &f.rule.ir_digest(),
                f.event,
                &f.inputs,
                None,
            )
            .unwrap()
            .unwrap();
        let retry = f
            .book
            .plan_into_draft(f.planner.clone(), NAME, retry)
            .unwrap()
            .unwrap();
        assert!(retry.recorded.already_recorded);
        assert_eq!(f.book.head().unwrap(), planned_at);
    }
    let promoted = f
        .book
        .promote_draft(
            Capability::embedded(VId(1), &["approve", "read"]).unwrap(),
            NAME,
            f.day,
            "Independent review",
        )
        .unwrap()
        .unwrap();
    assert_eq!(promoted.entries.len(), 1);
    let (published, at) = f.book.read_entry(promoted.entries[0].vid).unwrap().unwrap();
    assert_eq!(published, reviewed);
    assert_eq!(at, promoted.recorded_at);
}

#[test]
fn rule_source_scope_and_ceiling_failures_disclose_no_generated_values() {
    let f = fixture();
    let before = f.book.head().unwrap();
    let capabilities = [
        f.planner.clone().with_ceiling(f.usd, 4_299).unwrap(),
        f.planner.clone().for_accounts(&["1000"]).unwrap(),
    ];
    for capability in capabilities {
        let refused = prepare(&f, &capability).unwrap().unwrap_err();
        assert!(matches!(
            refused.code,
            code::CAPABILITY | fa_policy::denial::code::CEILING
        ));
        assert_private(&refused);
    }
    let mut missing = Inputs::new();
    missing.set("as_of", InputValue::Date(f.day));
    let mut wrong_type = f.inputs.clone();
    wrong_type.set("fee", InputValue::Date(f.day));
    let mut above_grant = f.inputs.clone();
    above_grant.set("fee", InputValue::Amount(Amount::new(f.usd, 9_999)));
    for inputs in [missing, wrong_type, above_grant] {
        let refused = f
            .book
            .prepare_rule_entry_in_draft(
                &f.planner,
                NAME,
                &f.rule.ir_digest(),
                f.event,
                &inputs,
                None,
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(refused.code, code::CANON_RULE);
        assert_private(&refused);
        assert!(!format!("{refused:?}").contains("fee"));
    }
    assert_eq!(f.book.head().unwrap(), before);
}

#[test]
fn rule_source_admission_precedes_poisoned_sources_and_preserves_revocation() {
    let mut f = fixture();
    let contexts = f.book.purposes();
    let mut damage = fgdb::WriteBatch::new(fa_model::symbols::relation::IN_BOOK);
    damage.set_vertex_property(
        fa_model::rule_version_vid(f.book.context().book_id, &f.rule.ir_digest()),
        fa_model::symbols::property::FA_PAYLOAD,
        Some(fgdb_types::CanonicalScalar::Int(4_300)),
    );
    with_store!(&mut f.book.store, core => f.book.runtime.block_on(core.db.write(&contexts.commit(), damage))).unwrap();
    let before = f.book.head().unwrap();
    let unconfined = Capability::new(OWNER, Profile::Agent, &[Op::Post], VId(1)).unwrap();
    let wrong_owner = Capability::new(VId(42), Profile::Agent, &[Op::Post], VId(1))
        .unwrap()
        .on_branch(fa_model::draft_branch(f.book.context().book_id, NAME))
        .unwrap();
    let read_only = Capability::new(OWNER, Profile::Agent, &[Op::Read], VId(1))
        .unwrap()
        .on_branch(fa_model::draft_branch(f.book.context().book_id, NAME))
        .unwrap();
    for capability in [&unconfined, &wrong_owner, &read_only] {
        assert_eq!(
            prepare(&f, capability).unwrap().unwrap_err().code,
            code::CAPABILITY
        );
    }
    assert_eq!(
        f.book
            .prepare_rule_entry_in_draft(
                &f.planner,
                "another-draft",
                &f.rule.ir_digest(),
                f.event,
                &f.inputs,
                None
            )
            .unwrap()
            .unwrap_err()
            .code,
        code::CAPABILITY
    );
    let corrupt = prepare(&f, &f.planner).unwrap_err();
    assert!(matches!(
        corrupt,
        BookError::Kernel(fa_journal::KernelError::Corrupt(_))
    ));
    assert!(!corrupt.to_string().contains("4300"));
    assert_eq!(f.book.head().unwrap(), before);
    f.book
        .revoke_capability(
            Capability::embedded(VId(1), &["issue_capability"]).unwrap(),
            f.planner.commitment().unwrap(),
            f.day,
            b"revoke-private-rule",
            "Withdraw source preparation",
        )
        .unwrap()
        .unwrap();
    let revoked_at = f.book.head().unwrap();
    assert_eq!(
        prepare(&f, &f.planner).unwrap().unwrap_err().code,
        "FA-REF-023"
    );
    assert_eq!(f.book.head().unwrap(), revoked_at);
}

#[test]
fn rule_source_preparation_and_promotion_both_refuse_superseded_activation() {
    let mut f = fixture();
    let mut inputs = f.inputs.clone();
    let later = DateDay::from_ymd(2026, 3, 16).unwrap();
    inputs.set("as_of", InputValue::Date(later));
    let intent = f
        .book
        .prepare_rule_entry_in_draft(
            &f.planner,
            NAME,
            &f.rule.ir_digest(),
            f.event,
            &inputs,
            Some(b"activation-drift"),
        )
        .unwrap()
        .unwrap();
    f.book
        .plan_into_draft(f.planner.clone(), NAME, intent)
        .unwrap()
        .unwrap();
    activate(
        &mut f.book,
        &RULE.replace(" v1 ", " v2 "),
        later,
        "private-rule-v2",
    );
    let head = f.book.head().unwrap();
    let refused = f
        .book
        .prepare_rule_entry_in_draft(
            &f.planner,
            NAME,
            &f.rule.ir_digest(),
            f.event,
            &inputs,
            None,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, code::CANON_RULE);
    assert_private(&refused);
    let refused = f
        .book
        .promote_draft(
            Capability::embedded(VId(1), &["approve", "read"]).unwrap(),
            NAME,
            later,
            "Review stale derivation",
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, code::CANON_RULE);
    assert_eq!(f.book.head().unwrap(), head);
}

#[test]
fn named_rule_preparation_does_not_decode_unrelated_event_sources() {
    let mut f = fixture();
    let contexts = f.book.purposes();
    let mut damage = fgdb::WriteBatch::new(fa_model::symbols::relation::IN_BOOK);
    damage.create_vertex(
        VId(0xdead_cafe),
        vec![fa_model::symbols::label::EVENT],
        vec![(
            fa_model::symbols::property::FA_PAYLOAD,
            fgdb_types::CanonicalScalar::Int(99),
        )],
    );
    with_store!(&mut f.book.store, core => f.book.runtime.block_on(core.db.write(&contexts.commit(), damage))).unwrap();
    let before = f.book.head().unwrap();
    assert!(
        f.book.rea_snapshot(None).is_err(),
        "the poisoned unrelated Event would break catalog reconstruction"
    );
    let intent = prepare(&f, &f.planner).unwrap().unwrap();
    assert!(
        intent
            .proposal()
            .legs
            .iter()
            .all(|leg| leg.amount == Amount::new(f.usd, 4_300))
    );
    assert_eq!(f.book.head().unwrap(), before);
}

fn assert_automatic_private(refusal: &fa_journal::Refusal) {
    assert_private(refusal);
    let text = format!("{refusal:?}");
    for hidden in [
        "automatic_private_alpha",
        "automatic_private_beta",
        "automatic_private_gamma",
        "40.00",
        "4000",
        "44.00",
        "4400",
    ] {
        assert!(!text.contains(hidden), "automatic source escaped in {text}");
    }
}

#[test]
fn post_only_automatic_group_preserves_keys_retries_and_independent_promotion() {
    let mut f = fixture_with_rule(AUTOMATIC_RULE);
    let second = activate(
        &mut f.book,
        &AUTOMATIC_RULE.replace("automatic_private_alpha", "automatic_private_beta"),
        f.day,
        "automatic-beta-v1",
    );
    let before = f.book.head().unwrap();
    let batch = f
        .book
        .prepare_rule_batch_in_draft(&f.planner, NAME, f.event)
        .unwrap()
        .unwrap();
    assert_eq!(batch.automatic_event(), Some(f.event));
    assert_eq!(batch.members().len(), 2);
    let ordinary = f
        .book
        .prepare_rule_batch(
            &Capability::embedded(OWNER, &["read", "post"]).unwrap(),
            f.event,
        )
        .unwrap()
        .unwrap();
    assert_eq!(batch.idempotency_key(), ordinary.batch.idempotency_key());
    for ((member, ordinary), rule) in batch
        .members()
        .iter()
        .zip(ordinary.batch.members())
        .zip([&f.rule, &second])
    {
        let p = member.proposal();
        assert_eq!(p.principal_ref, OWNER);
        assert_eq!(p.class, EntryClass::ADJUSTING);
        assert_eq!(p.idempotency_key, ordinary.proposal().idempotency_key);
        assert_eq!(p.origin, ordinary.proposal().origin);
        assert_eq!(p.legs, ordinary.proposal().legs);
        assert_eq!(
            p.idempotency_key,
            crate::rule::default_derivation_key(rule, f.event, &Inputs::new())
                .unwrap()
                .into_bytes()
        );
        assert_eq!(
            p.description
                .open(
                    &f.book.context().seal_key,
                    fa_model::limits::MAX_DESCRIPTION_BYTES,
                )
                .unwrap(),
            "Automatic rule derivation for draft review"
        );
    }
    assert_eq!(f.book.head().unwrap(), before);
    assert_eq!(
        f.book
            .prepare_rule_batch(&f.planner, f.event)
            .unwrap()
            .unwrap_err()
            .code,
        code::CAPABILITY
    );
    let planned = f
        .book
        .plan_batch_into_draft(f.planner.clone(), NAME, batch)
        .unwrap()
        .unwrap();
    let reviewed: Vec<_> = planned
        .plan
        .unwrap()
        .members()
        .iter()
        .map(|member| member.entry.clone())
        .collect();
    let planned_at = f.book.head().unwrap();
    let retry = f
        .book
        .prepare_rule_batch_in_draft(&f.planner, NAME, f.event)
        .unwrap()
        .unwrap();
    let retry = f
        .book
        .plan_batch_into_draft(f.planner.clone(), NAME, retry)
        .unwrap()
        .unwrap();
    assert!(retry.recorded.already_recorded);
    assert_eq!(f.book.head().unwrap(), planned_at);
    assert!(
        f.book
            .promote_draft(
                Capability::embedded(OWNER, &["approve", "read"]).unwrap(),
                NAME,
                f.day,
                "Owner cannot independently approve",
            )
            .unwrap()
            .is_err()
    );
    assert_eq!(f.book.head().unwrap(), planned_at);
    let promoted = f
        .book
        .promote_draft(
            Capability::embedded(VId(1), &["approve", "read"]).unwrap(),
            NAME,
            f.day,
            "Review every selected rule",
        )
        .unwrap()
        .unwrap();
    assert_eq!(promoted.entries.len(), reviewed.len());
    for (published, expected) in promoted.entries.iter().zip(&reviewed) {
        let (entry, at) = f.book.read_entry(published.vid).unwrap().unwrap();
        assert_eq!(&entry, expected);
        assert_eq!(at, promoted.recorded_at);
    }
}

#[test]
fn automatic_draft_input_requirement_refuses_the_whole_private_group() {
    let mut f = fixture_with_rule(AUTOMATIC_RULE);
    activate(&mut f.book, RULE, f.day, "automatic-input-rule");
    let before = f.book.head().unwrap();
    let refusal = f
        .book
        .prepare_rule_batch_in_draft(&f.planner, NAME, f.event)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, code::CANON_RULE);
    assert_automatic_private(&refusal);
    assert!(!format!("{refusal:?}").contains("fee"));
    assert_eq!(f.book.head().unwrap(), before);
    assert!(f.book.draft(NAME).unwrap().unwrap().intents.is_empty());
}

#[test]
fn automatic_draft_denies_all_effects_if_any_member_exceeds_private_scope() {
    let mut f = fixture_with_rule(AUTOMATIC_RULE);
    let second = AUTOMATIC_RULE
        .replace("automatic_private_alpha", "automatic_private_beta")
        .replace(
            "event.resource(\"private_net\", \"USD\")",
            "event.resource(\"private_net\", \"USD\") * 11 / 10 round HalfEven",
        );
    activate(&mut f.book, &second, f.day, "automatic-larger-beta");
    let before = f.book.head().unwrap();
    // Alpha is within the 43.00 ceiling; Beta is 44.00. Returning the
    // admitted prefix would silently turn complete selection into a subset.
    for capability in [
        f.planner.clone(),
        f.planner.clone().for_accounts(&["1000"]).unwrap(),
    ] {
        let refusal = f
            .book
            .prepare_rule_batch_in_draft(&capability, NAME, f.event)
            .unwrap()
            .unwrap_err();
        assert!(matches!(
            refusal.code,
            code::CAPABILITY | fa_policy::denial::code::CEILING
        ));
        assert_automatic_private(&refusal);
    }
    assert_eq!(f.book.head().unwrap(), before);
    assert!(f.book.draft(NAME).unwrap().unwrap().intents.is_empty());
}

#[test]
fn automatic_draft_admission_precedes_private_corruption_and_revocation() {
    let mut f = fixture_with_rule(AUTOMATIC_RULE);
    let contexts = f.book.purposes();
    let mut damage = fgdb::WriteBatch::new(fa_model::symbols::relation::IN_BOOK);
    damage.set_vertex_property(
        fa_model::rule_version_vid(f.book.context().book_id, &f.rule.ir_digest()),
        fa_model::symbols::property::FA_PAYLOAD,
        Some(fgdb_types::CanonicalScalar::Int(4_000)),
    );
    with_store!(&mut f.book.store, core => f.book.runtime.block_on(core.db.write(&contexts.commit(), damage))).unwrap();
    let before = f.book.head().unwrap();
    let unconfined = Capability::new(OWNER, Profile::Agent, &[Op::Post], VId(1)).unwrap();
    let wrong_owner = Capability::new(VId(42), Profile::Agent, &[Op::Post], VId(1))
        .unwrap()
        .on_branch(fa_model::draft_branch(f.book.context().book_id, NAME))
        .unwrap();
    let read_only = Capability::new(OWNER, Profile::Agent, &[Op::Read], VId(1))
        .unwrap()
        .on_branch(fa_model::draft_branch(f.book.context().book_id, NAME))
        .unwrap();
    for capability in [&unconfined, &wrong_owner, &read_only] {
        let refusal = f
            .book
            .prepare_rule_batch_in_draft(capability, NAME, f.event)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, code::CAPABILITY);
        assert_automatic_private(&refusal);
    }
    let corrupt = f
        .book
        .prepare_rule_batch_in_draft(&f.planner, NAME, f.event)
        .unwrap_err();
    assert!(matches!(
        corrupt,
        BookError::Kernel(fa_journal::KernelError::Corrupt(_))
    ));
    assert!(!corrupt.to_string().contains("4000"));
    assert!(!corrupt.to_string().contains("automatic_private_alpha"));
    assert_eq!(f.book.head().unwrap(), before);
    f.book
        .revoke_capability(
            Capability::embedded(VId(1), &["issue_capability"]).unwrap(),
            f.planner.commitment().unwrap(),
            f.day,
            b"revoke-private-automatic-rule",
            "Withdraw automatic source preparation",
        )
        .unwrap()
        .unwrap();
    let revoked_at = f.book.head().unwrap();
    assert_eq!(
        f.book
            .prepare_rule_batch_in_draft(&f.planner, NAME, f.event)
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-023"
    );
    assert_eq!(f.book.head().unwrap(), revoked_at);
}

#[test]
fn automatic_draft_selection_does_not_decode_unrelated_events() {
    let mut f = fixture_with_rule(AUTOMATIC_RULE);
    let contexts = f.book.purposes();
    let mut damage = fgdb::WriteBatch::new(fa_model::symbols::relation::IN_BOOK);
    damage.create_vertex(
        VId(0xdead_cafe),
        vec![fa_model::symbols::label::EVENT],
        vec![(
            fa_model::symbols::property::FA_PAYLOAD,
            fgdb_types::CanonicalScalar::Int(99),
        )],
    );
    with_store!(&mut f.book.store, core => f.book.runtime.block_on(core.db.write(&contexts.commit(), damage))).unwrap();
    let before = f.book.head().unwrap();
    assert!(f.book.rea_snapshot(None).is_err());
    let batch = f
        .book
        .prepare_rule_batch_in_draft(&f.planner, NAME, f.event)
        .unwrap()
        .unwrap();
    assert_eq!(batch.members().len(), 1);
    assert!(
        batch.members()[0]
            .proposal()
            .legs
            .iter()
            .all(|leg| leg.amount == Amount::new(f.usd, 4_000))
    );
    assert_eq!(f.book.head().unwrap(), before);
}

#[test]
fn retained_automatic_draft_refuses_a_new_matching_rule_without_partial_promotion() {
    let mut f = fixture_with_rule(AUTOMATIC_RULE);
    let batch = f
        .book
        .prepare_rule_batch_in_draft(&f.planner, NAME, f.event)
        .unwrap()
        .unwrap();
    f.book
        .plan_batch_into_draft(f.planner.clone(), NAME, batch)
        .unwrap()
        .unwrap();
    activate(
        &mut f.book,
        &AUTOMATIC_RULE.replace("automatic_private_alpha", "automatic_private_gamma"),
        f.day,
        "automatic-new-matching-rule",
    );
    let before = f.book.head().unwrap();
    let preview = f.book.preview_draft(&f.planner, NAME).unwrap().unwrap_err();
    assert_eq!(preview.code, code::CANON_RULE);
    assert_automatic_private(&preview);
    let refused = f
        .book
        .promote_draft(
            Capability::embedded(VId(1), &["approve", "read"]).unwrap(),
            NAME,
            f.day,
            "Review changed automatic selection",
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, code::CANON_RULE);
    assert_eq!(f.book.head().unwrap(), before);
    let draft = f.book.draft(NAME).unwrap().unwrap();
    assert_eq!(draft.intents.len(), 1);
    let proposal = draft.intents[0].intent.proposal();
    let target = fa_model::entry_vid(
        f.book.context().book_id,
        &proposal.principal_ref.0.to_le_bytes(),
        &proposal.idempotency_key,
    );
    assert!(f.book.read_entry(target).unwrap().is_none());
}
