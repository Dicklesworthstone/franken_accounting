//! Complete Canon event groups retain their operation boundary inside a
//! mixed ordered draft, including historical rehearsal and current admission.

use super::*;

fn planner(h: &Harness, name: &str) -> Capability {
    Capability::new(AGENT, Profile::Agent, &[Op::Post], PREPARER)
        .unwrap()
        .on_branch(fa_model::draft_branch(h.book.book_id, name))
        .unwrap()
}

fn request(h: &Harness, capability: Capability) -> fa_journal::DraftRequest {
    fa_journal::DraftRequest {
        capability,
        effective_date: DateDay::from_ymd(2026, 3, 15).unwrap(),
        description: h.period_description(),
    }
}

fn open(h: &mut Harness, name: &str, capability: &Capability) {
    let ctx = h.ctx();
    let request = request(h, capability.clone());
    h.runtime
        .block_on(fa_journal::open_draft(
            &mut h.db, &ctx, &h.book, name, request,
        ))
        .unwrap()
        .unwrap();
}

fn group(h: &Harness, rules: &[&CompiledRule], event: &EventSpec, key: &[u8]) -> PostBatch {
    let original = automatic_batch(h, rules, event, key);
    let members = original
        .members()
        .iter()
        .map(|member| {
            let mut proposal = member.proposal().clone();
            proposal.principal_ref = AGENT;
            PostIntent::rule_derived(proposal, Vec::new()).unwrap()
        })
        .collect();
    PostBatch::automatic_rules(original.automatic_event().unwrap(), key.to_vec(), members).unwrap()
}

fn append(
    h: &mut Harness,
    name: &str,
    capability: &Capability,
    batch: PostBatch,
) -> fa_journal::refusal::Outcome<fa_journal::DraftPlanned> {
    let ctx = h.ctx();
    let request = request(h, capability.clone());
    h.runtime.block_on(fa_journal::plan_batch_into_draft(
        &mut h.db, &ctx, &h.book, name, batch, request,
    ))
}

fn ordinary(
    h: &mut Harness,
    name: &str,
    capability: &Capability,
    key: &[u8],
) -> fa_journal::refusal::Outcome<fa_journal::DraftPlanned> {
    let intent =
        PostIntent::new(h.proposal(AGENT, 50, key, EntryClass::ORIGINAL), Vec::new()).unwrap();
    let ctx = h.ctx();
    let request = request(h, capability.clone());
    h.runtime.block_on(fa_journal::plan_into_draft(
        &mut h.db, &ctx, &h.book, name, intent, request,
    ))
}

fn preview(
    h: &mut Harness,
    name: &str,
    capability: &Capability,
) -> fa_journal::refusal::Outcome<Option<fa_journal::draft::DraftPreview>> {
    let ctx = h.ctx();
    h.runtime.block_on(fa_journal::draft::preview_draft(
        &mut h.db, &ctx, &h.book, capability, name,
    ))
}

fn promote(h: &mut Harness, name: &str) -> fa_journal::refusal::Outcome<fa_journal::DraftPromoted> {
    let ctx = h.ctx();
    let request = request(
        h,
        Capability::embedded(PREPARER, &["approve", "read"]).unwrap(),
    );
    h.runtime.block_on(fa_journal::promote_draft(
        &mut h.db, &ctx, &h.book, name, request,
    ))
}

fn rehearse(
    h: &mut Harness,
    name: &str,
    known_at: CommitSeq,
) -> fa_journal::refusal::Outcome<fa_journal::draft::DraftRehearsal> {
    let ctx = h.ctx();
    let scratch = h
        .runtime
        .block_on(Database::open_memory(
            &ctx.commit(),
            DatabaseKeys::new([201; 32], DatabaseSecurityNamespaceId([202; 32]), [203; 32]),
        ))
        .unwrap();
    let (scratch, rehearsal) = match h.runtime.block_on(fa_journal::draft::rehearse_draft_into(
        &mut h.db,
        scratch,
        &ctx,
        &h.book,
        &Capability::embedded(PREPARER, &["read"]).unwrap(),
        fa_journal::draft::DraftRehearsalRequest {
            name: name.into(),
            known_at,
        },
    ))? {
        Ok(rehearsed) => rehearsed,
        Err(refusal) => return Ok(Err(refusal)),
    };
    for reference in &rehearsal.batch.entries {
        let (entry, recorded_at) = read_entry(&scratch, reference.vid).unwrap().unwrap();
        assert_eq!(entry.entry_ref(reference.vid), *reference);
        assert_eq!(recorded_at, rehearsal.batch.recorded_at);
    }
    Ok(Ok(rehearsal))
}

fn activate_later(h: &mut Harness, rule: &CompiledRule) {
    let plan = plan_rule_activation(
        &h.db,
        &h.book,
        &controller(),
        &rule.ir_digest(),
        DateDay::from_ymd(2026, 3, 10).unwrap(),
        b"activate-later-automatic-version",
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

fn assert_private(refusal: &Refusal) {
    let text = format!("{refusal:?}");
    assert!(!text.contains("private_alpha"), "{text}");
    assert!(!text.contains("private_omega"), "{text}");
    assert!(!text.contains("PRIVATE-EVENT"), "{text}");
}

#[test]
fn multiple_automatic_groups_and_ordinary_members_rehearse_and_promote_exactly_once() {
    let mut h = harness();
    let alpha = automatic_rule(&mut h, "alpha_sale", "6000");
    let omega = automatic_rule(&mut h, "omega_sale", "6000");
    let first = event(&mut h, "GROUP-FIRST", 4_000);
    let second = event(&mut h, "GROUP-SECOND", 2_500);
    let name = "two-complete-groups";
    let capability = planner(&h, name);
    open(&mut h, name, &capability);
    ordinary(&mut h, name, &capability, b"ordinary-before")
        .unwrap()
        .unwrap();
    let first = group(&h, &[&alpha, &omega], &first, b"first-group");
    let first_record = append(&mut h, name, &capability, first.clone())
        .unwrap()
        .unwrap()
        .recorded;
    ordinary(&mut h, name, &capability, b"ordinary-between")
        .unwrap()
        .unwrap();
    let second = group(&h, &[&alpha, &omega], &second, b"second-group");
    let planned = append(&mut h, name, &capability, second).unwrap().unwrap();
    let reviewed = planned.plan.unwrap();
    let ctx = h.ctx();
    let view = fa_journal::read_draft(&h.db, &ctx.query(), &h.book, name)
        .unwrap()
        .unwrap();
    assert_eq!(view.intents.len(), 6);
    assert_eq!(view.intents[1].record, first_record.control_entry);
    assert_eq!(view.intents[2].record, first_record.control_entry);
    assert_eq!(view.intents[4].record, planned.recorded.control_entry);
    assert_eq!(view.intents[5].record, planned.recorded.control_entry);
    assert_ne!(view.intents[1].record, view.intents[4].record);
    let expected: Vec<_> = reviewed
        .members()
        .iter()
        .map(|member| {
            member.entry.entry_ref(fa_model::entry_vid(
                h.book.book_id,
                &AGENT.0.to_le_bytes(),
                &member.intent.proposal().idempotency_key,
            ))
        })
        .collect();
    for reference in &expected {
        assert!(read_entry(&h.db, reference.vid).unwrap().is_none());
    }
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let rehearsal = rehearse(&mut h, name, head).unwrap().unwrap();
    assert_eq!(rehearsal.batch.entries, expected);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
    let promoted = promote(&mut h, name).unwrap().unwrap();
    assert_eq!(promoted.entries, expected);
    for (reference, reviewed) in promoted.entries.iter().zip(reviewed.members()) {
        let (entry, sequence) = read_entry(&h.db, reference.vid).unwrap().unwrap();
        assert_eq!(entry, reviewed.entry);
        assert_eq!(sequence, promoted.recorded_at);
    }
    // Retained operation outcomes do not become new effects after catalog growth.
    automatic_rule(&mut h, "zeta_sale", "6000");
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let retry = append(&mut h, name, &capability, first).unwrap().unwrap();
    assert!(retry.recorded.already_recorded);
    assert_eq!(retry.recorded.recorded_at, first_record.recorded_at);
    assert!(retry.plan.is_none());
    let retry = promote(&mut h, name).unwrap().unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, promoted.entries);
    assert_eq!(retry.recorded_at, promoted.recorded_at);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

#[test]
fn malformed_automatic_group_never_appends_a_valid_prefix_or_discloses_source_metadata() {
    let mut h = harness();
    let alpha = automatic_rule(&mut h, "private_alpha", "6000");
    let omega = automatic_rule(&mut h, "private_omega", "6000");
    let source = event(&mut h, "PRIVATE-EVENT", 4_000);
    let name = "all-or-none-automatic";
    let capability = planner(&h, name);
    open(&mut h, name, &capability);
    let omitted = group(&h, &[&alpha], &source, b"omitted-member");
    let reordered = group(&h, &[&omega, &alpha], &source, b"reordered-members");
    let valid = group(&h, &[&alpha, &omega], &source, b"forged-effects");
    let mut members = valid.members().to_vec();
    let mut forged = members[1].proposal().clone();
    for leg in &mut forged.legs {
        leg.amount = Amount::new(h.usd, 4_001);
    }
    forged.unit_totals = EntryPayload::fold_unit_totals(&forged.legs).unwrap();
    members[1] = PostIntent::rule_derived(forged, Vec::new()).unwrap();
    let forged = PostBatch::automatic_rules(
        valid.automatic_event().unwrap(),
        b"forged-effects".to_vec(),
        members,
    )
    .unwrap();
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    for batch in [omitted, reordered, forged] {
        let refused = append(&mut h, name, &capability, batch)
            .unwrap()
            .unwrap_err();
        assert_eq!(refused.code, code::CANON_RULE, "{refused:?}");
        assert_private(&refused);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert!(
            fa_journal::read_draft(&h.db, &h.ctx().query(), &h.book, name)
                .unwrap()
                .unwrap()
                .intents
                .is_empty()
        );
    }
}

#[test]
fn retained_automatic_groups_recheck_catalog_and_activation_on_every_fresh_execution() {
    for replace_version in [false, true] {
        let mut h = harness();
        let alpha = automatic_rule(&mut h, "private_alpha", "6000");
        let source = event(&mut h, "PRIVATE-EVENT", 4_000);
        let name = "automatic-catalog-drift";
        let capability = planner(&h, name);
        open(&mut h, name, &capability);
        let batch = group(&h, &[&alpha], &source, b"retained-group");
        let planned = append(&mut h, name, &capability, batch.clone())
            .unwrap()
            .unwrap();
        let reviewed_at = h.db.frontier().unwrap();
        if replace_version {
            let next = propose_source(
                &mut h,
                r#"rule private_alpha v2 for event Sale {
  let net = event.resource("net", "USD")
  debit "1000" net
  credit "6000" net
}"#,
                b"propose-new-active-version",
            );
            activate_later(&mut h, &next);
        } else {
            automatic_rule(&mut h, "private_omega", "6000");
        }
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        // Historical scratch replay selects the original complete catalog.
        let historical = rehearse(&mut h, name, reviewed_at).unwrap().unwrap();
        assert_eq!(historical.batch.entries.len(), 1);
        let retry = append(&mut h, name, &capability, batch).unwrap().unwrap();
        assert!(retry.recorded.already_recorded);
        assert_eq!(retry.recorded.recorded_at, planned.recorded.recorded_at);
        let refusal = preview(&mut h, name, &capability).unwrap().unwrap_err();
        assert_eq!(refusal.code, code::CANON_RULE, "{refusal:?}");
        assert_private(&refusal);
        let refusal = ordinary(&mut h, name, &capability, b"new-single-member")
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, code::CANON_RULE, "{refusal:?}");
        assert_private(&refusal);
        let ordinary = PostIntent::new(
            h.proposal(AGENT, 50, b"new-batch-member", EntryClass::ORIGINAL),
            Vec::new(),
        )
        .unwrap();
        let refusal = append(
            &mut h,
            name,
            &capability,
            PostBatch::new(b"new-ordinary-batch".to_vec(), vec![ordinary]).unwrap(),
        )
        .unwrap()
        .unwrap_err();
        assert_eq!(refusal.code, code::CANON_RULE, "{refusal:?}");
        assert_private(&refusal);
        let refusal = rehearse(&mut h, name, head).unwrap().unwrap_err();
        assert_eq!(refusal.code, code::CANON_RULE, "{refusal:?}");
        assert_private(&refusal);
        let refusal = promote(&mut h, name).unwrap().unwrap_err();
        assert_eq!(refusal.code, code::CANON_RULE, "{refusal:?}");
        assert_private(&refusal);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert_eq!(
            fa_journal::read_draft(&h.db, &h.ctx().query(), &h.book, name)
                .unwrap()
                .unwrap()
                .intents
                .len(),
            1
        );
    }
}

#[test]
fn automatic_and_explicit_group_keys_conflict_in_both_orders_but_semantic_retries_survive() {
    for automatic_first in [false, true] {
        let mut h = harness();
        let alpha = automatic_rule(&mut h, "alpha_sale", "6000");
        let source = event(&mut h, "PROFILE-IDENTITY", 4_000);
        let name = "profile-bound-key";
        let capability = planner(&h, name);
        open(&mut h, name, &capability);
        let automatic = group(&h, &[&alpha], &source, b"shared-group-key");
        let explicit = PostBatch::for_draft(
            automatic.idempotency_key().to_vec(),
            automatic.members().to_vec(),
        )
        .unwrap();
        let (original, conflicting) = if automatic_first {
            (automatic, explicit)
        } else {
            (explicit, automatic)
        };
        let recorded = append(&mut h, name, &capability, original.clone())
            .unwrap()
            .unwrap()
            .recorded;
        let mut proposal = original.members()[0].proposal().clone();
        proposal.description = Erasable::seal(
            &"period".to_string(),
            None,
            &h.book.seal_key,
            [71; 32],
            [72; 24],
        );
        let resealed = PostIntent::rule_derived(proposal, Vec::new()).unwrap();
        let same = match original.automatic_event() {
            Some(event) => PostBatch::automatic_rules(
                event,
                original.idempotency_key().to_vec(),
                vec![resealed],
            ),
            None => PostBatch::for_draft(original.idempotency_key().to_vec(), vec![resealed]),
        }
        .unwrap();
        assert_ne!(
            same.canonical_bytes().unwrap(),
            original.canonical_bytes().unwrap()
        );
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let retry = append(&mut h, name, &capability, same).unwrap().unwrap();
        assert!(retry.recorded.already_recorded);
        assert_eq!(retry.recorded.recorded_at, recorded.recorded_at);
        let refusal = append(&mut h, name, &capability, conflicting)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, code::IDEMPOTENCY_CONFLICT, "{refusal:?}");
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn rewritten_or_restored_plan_cannot_erase_the_retained_automatic_group_claim() {
    for restore in [false, true] {
        let mut h = harness();
        let alpha = automatic_rule(&mut h, "alpha_sale", "6000");
        let source = event(&mut h, "GROUP-INTEGRITY", 4_000);
        let name = "immutable-group-profile";
        let capability = planner(&h, name);
        open(&mut h, name, &capability);
        let automatic = group(&h, &[&alpha], &source, b"immutable-group");
        let record = append(&mut h, name, &capability, automatic.clone())
            .unwrap()
            .unwrap()
            .recorded
            .control_entry;
        let (original, _) = read_entry(&h.db, record).unwrap().unwrap();
        let mut proposal = original.proposal.clone();
        let bytes = &proposal.extensions[0].1;
        let mut reader = fa_model::Reader::new(bytes);
        assert_eq!(reader.u16("version").unwrap(), 6);
        let key = reader
            .bytes(fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES, "key")
            .unwrap()
            .to_vec();
        reader.u128("event").unwrap();
        let members = reader
            .list(fa_model::limits::MAX_BATCH_ENTRIES, "members", |r| {
                Ok(r.bytes(fa_model::limits::MAX_EXTENSION_BYTES, "member")?
                    .to_vec())
            })
            .unwrap();
        reader.finish().unwrap();
        let mut writer = fa_model::Writer::new();
        writer.u16(4).bytes(&key).list(&members, |w, bytes| {
            w.bytes(bytes);
        });
        proposal.extensions[0].1 = writer.finish().unwrap();
        let changed = proposal.seal(Vec::new(), None).unwrap();
        assert!(fa_model::Entry::decode(&changed.encode().unwrap()).is_ok());
        let ctx = h.ctx();
        let mut damage = WriteBatch::new(relation::IN_CASE);
        for (key, value) in fa_model::entry_mirrors(&changed).unwrap() {
            damage.set_vertex_property(record, key, Some(value));
        }
        h.runtime
            .block_on(h.db.write(&ctx.commit(), damage))
            .unwrap();
        if restore {
            let mut restore_bytes = WriteBatch::new(relation::IN_CASE);
            for (key, value) in fa_model::entry_mirrors(&original).unwrap() {
                restore_bytes.set_vertex_property(record, key, Some(value));
            }
            h.runtime
                .block_on(h.db.write(&ctx.commit(), restore_bytes))
                .unwrap();
        }
        // The hostile record is structurally canonical and still has a full
        // flattened member. Native original-birth authentication must reject it.
        let view = fa_journal::read_draft(&h.db, &ctx.query(), &h.book, name)
            .unwrap()
            .unwrap();
        assert_eq!(view.intents.len(), 1);
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let retry = if restore {
            automatic
        } else {
            PostBatch::for_draft(
                automatic.idempotency_key().to_vec(),
                automatic.members().to_vec(),
            )
            .unwrap()
        };
        assert!(matches!(
            append(&mut h, name, &capability, retry),
            Err(KernelError::Corrupt(_))
        ));
        assert!(matches!(
            preview(&mut h, name, &capability),
            Err(KernelError::Corrupt(_))
        ));
        assert!(matches!(
            promote(&mut h, name),
            Err(KernelError::Corrupt(_))
        ));
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}
