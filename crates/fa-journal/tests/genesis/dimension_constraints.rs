//! Account-local dimension policies through the real posting pipeline.

use super::*;
use fa_journal::dimension::{
    DimensionConstraintRecorded, DimensionConstraintSpec, DimensionRequirementSpec,
    DimensionValueSpec, constraints_at, create_dimension_value, record_dimension_constraint,
    record_dimension_requirement,
};
use std::collections::BTreeMap;

const KIND: u32 = 2;

fn fixture() -> (Harness, BTreeMap<&'static str, VId>) {
    let mut h = harness();
    let mut values = BTreeMap::new();
    for (code, parent) in [("A", None), ("A-CHILD", Some("A")), ("B", None)] {
        let cx = h.ctx();
        let key = format!("constraint-value-{code}");
        let spec = DimensionValueSpec {
            dimension: "cost_center".into(),
            code: code.into(),
            name: code.into(),
            parent: parent.map(str::to_string),
            valid_from: None,
            valid_to: None,
        };
        let description = h.statement("Declare cost center", 93);
        let value = h
            .runtime
            .block_on(create_dimension_value(
                &mut h.db,
                &cx,
                &h.book,
                &spec,
                PRINCIPAL,
                key.as_bytes(),
                description,
                &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap()
            .value;
        assert_eq!(value.dimension_id, KIND);
        values.insert(code, value.vid);
    }
    (h, values)
}

fn policy(account: VId, allowed: Option<&[&str]>, forbidden: &[&str]) -> DimensionConstraintSpec {
    DimensionConstraintSpec {
        dimension: "cost_center".into(),
        account,
        allowed: allowed.map(|values| values.iter().map(|value| (*value).into()).collect()),
        forbidden: forbidden.iter().map(|value| (*value).into()).collect(),
    }
}

fn record_with(
    h: &mut Harness,
    spec: &DimensionConstraintSpec,
    key: &[u8],
    capability: &Capability,
) -> Result<DimensionConstraintRecorded, Refusal> {
    let cx = h.ctx();
    let description = h.statement("Set cost center values", 94);
    h.runtime
        .block_on(record_dimension_constraint(
            &mut h.db,
            &cx,
            &h.book,
            spec,
            PRINCIPAL,
            key,
            description,
            capability,
        ))
        .expect("constraint kernel")
}

fn record(
    h: &mut Harness,
    spec: &DimensionConstraintSpec,
    key: &[u8],
) -> DimensionConstraintRecorded {
    record_with(
        h,
        spec,
        key,
        &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
    )
    .unwrap()
}

fn require(h: &mut Harness, required: bool, key: &[u8]) {
    let cx = h.ctx();
    let spec = DimensionRequirementSpec {
        dimension: "cost_center".into(),
        account: h.rent,
        required,
    };
    let description = h.statement("Require cost center", 95);
    h.runtime
        .block_on(record_dimension_requirement(
            &mut h.db,
            &cx,
            &h.book,
            &spec,
            PRINCIPAL,
            key,
            description,
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
}

fn tagged(h: &Harness, value: Option<VId>, key: &[u8]) -> EntryPayload {
    let mut legs = h.rent_legs(100);
    if let Some(value) = value {
        legs[0].dimension_set.push((KIND, value));
    }
    h.proposal(legs, key, EntryClass::ORIGINAL)
}

fn oracle(h: &Harness) -> fa_reference::Oracle {
    let mut oracle = fa_reference::Oracle::new(h.book.calendar.clone());
    for code in ["1000", "6000"] {
        oracle.add_account(fa_reference::Account {
            code: code.into(),
            is_leaf: true,
            unit: Some(h.usd.0),
        });
    }
    oracle.create_periods(2026);
    oracle.transition(&h.march, PeriodTransition::Open).unwrap();
    for (code, parent) in [("A", None), ("A-CHILD", Some("A")), ("B", None)] {
        oracle
            .declare_dimension_value(fa_reference::DimensionValue {
                kind: KIND,
                code: code.into(),
                parent: parent.map(str::to_string),
                valid_from: None,
                valid_to: None,
            })
            .unwrap();
    }
    oracle
}

fn model_policy(oracle: &mut fa_reference::Oracle, spec: &DimensionConstraintSpec) {
    oracle
        .constrain_dimension(
            KIND,
            "6000",
            fa_reference::DimensionConstraint {
                allowed: spec.allowed.clone(),
                forbidden: spec.forbidden.clone(),
            },
        )
        .unwrap();
}

fn compare_post(
    h: &mut Harness,
    oracle: &mut fa_reference::Oracle,
    values: &BTreeMap<&str, VId>,
    codes: [Option<&str>; 2],
    key: &[u8],
    expected: Option<&str>,
) {
    let mut legs = h.rent_legs(100);
    for (leg, code) in legs.iter_mut().zip(codes) {
        if let Some(code) = code {
            leg.dimension_set.push((KIND, values[code]));
        }
    }
    let intent = fa_reference::Intent {
        class: "Original".into(),
        date: h.day(),
        discriminator: None,
        legs: vec![
            fa_reference::Leg {
                side: fa_reference::Side::Debit,
                account: "6000".into(),
                unit: h.usd.0,
                entity: None,
                mantissa: 100,
            },
            fa_reference::Leg {
                side: fa_reference::Side::Credit,
                account: "1000".into(),
                unit: h.usd.0,
                entity: None,
                mantissa: 100,
            },
        ],
        key: key.to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    };
    let tags = codes.map(|code| {
        code.map(|code| fa_reference::DimensionTag {
            dimension: KIND,
            value_kind: KIND,
            code: code.into(),
        })
        .into_iter()
        .collect::<Vec<_>>()
    });
    let head = h.db.frontier().unwrap();
    let count = oracle.journal_len();
    let modeled = oracle.post_dimensioned(&intent, &tags);
    let posted = h.post(h.request(h.proposal(legs, key, EntryClass::ORIGINAL), &["post"]));
    match expected {
        Some(expected) => {
            assert!(
                matches!(modeled, fa_reference::Verdict::Refused { code } if code == expected),
                "{modeled:?}"
            );
            let refusal = posted.unwrap_err();
            assert_eq!((refusal.code, refusal.exit), (expected, exit::REFUSAL));
            assert_eq!(h.db.frontier().unwrap(), head);
            assert_eq!(oracle.journal_len(), count);
        }
        None => {
            assert!(matches!(modeled, fa_reference::Verdict::Posted { .. }));
            assert!(matches!(posted.unwrap(), Posted::Committed { .. }));
            assert_eq!(oracle.journal_len(), count + 1);
        }
    }
}

#[test]
fn dimension_constraints_match_reference_for_exact_values_and_account_locality() {
    let (mut h, values) = fixture();
    let mut model = oracle(&h);
    compare_post(
        &mut h,
        &mut model,
        &values,
        [Some("B"), None],
        b"globally-valid-before-policy",
        None,
    );
    let spec = policy(h.rent, Some(&["A"]), &["B"]);
    record(&mut h, &spec, b"allow-parent-only");
    model_policy(&mut model, &spec);
    for (index, (codes, expected)) in [
        ([Some("A"), None], None),
        ([Some("A-CHILD"), None], Some("FA-REF-207")),
        ([Some("B"), None], Some("FA-REF-207")),
        ([None, None], None),
        ([Some("A"), Some("B")], None),
    ]
    .into_iter()
    .enumerate()
    {
        compare_post(
            &mut h,
            &mut model,
            &values,
            codes,
            format!("exact-policy-{index}").as_bytes(),
            expected,
        );
    }
    // A denylist without an allowlist permits another globally valid value.
    let deny = policy(h.rent, None, &["B"]);
    record(&mut h, &deny, b"deny-one-value");
    model_policy(&mut model, &deny);
    compare_post(
        &mut h,
        &mut model,
        &values,
        [Some("A-CHILD"), None],
        b"child-without-allowlist",
        None,
    );
    compare_post(
        &mut h,
        &mut model,
        &values,
        [Some("B"), None],
        b"denied-without-allowlist",
        Some("FA-REF-207"),
    );
}

#[test]
fn dimension_requirements_and_value_constraints_are_independent_and_historical() {
    let (mut h, values) = fixture();
    let mut model = oracle(&h);
    let before = h.db.frontier().unwrap();
    let spec = policy(h.rent, Some(&["A"]), &[]);
    let first = record(&mut h, &spec, b"independent-policy");
    model_policy(&mut model, &spec);
    require(&mut h, true, b"require-on");
    model.require_dimension(KIND, "6000", true);
    compare_post(
        &mut h,
        &mut model,
        &values,
        [None, None],
        b"required-omission",
        Some("FA-REF-005"),
    );
    require(&mut h, false, b"require-off");
    model.require_dimension(KIND, "6000", false);
    compare_post(
        &mut h,
        &mut model,
        &values,
        [None, None],
        b"optional-omission",
        None,
    );
    compare_post(
        &mut h,
        &mut model,
        &values,
        [Some("B"), None],
        b"optional-still-constrained",
        Some("FA-REF-207"),
    );
    assert_eq!(
        constraints_at(&h.db, &h.book, h.db.frontier().unwrap()).unwrap()[0].spec,
        spec
    );

    let none = policy(h.rent, Some(&[]), &[]);
    record(&mut h, &none, b"allow-no-tagged-values");
    model_policy(&mut model, &none);
    compare_post(
        &mut h,
        &mut model,
        &values,
        [None, None],
        b"empty-allowlist-absent",
        None,
    );
    compare_post(
        &mut h,
        &mut model,
        &values,
        [Some("A"), None],
        b"empty-allowlist-present",
        Some("FA-REF-207"),
    );
    require(&mut h, true, b"require-on-again");
    model.require_dimension(KIND, "6000", true);
    let clear = policy(h.rent, None, &[]);
    let cleared = record(&mut h, &clear, b"clear-value-policy");
    model_policy(&mut model, &clear);
    compare_post(
        &mut h,
        &mut model,
        &values,
        [None, None],
        b"clear-keeps-requirement",
        Some("FA-REF-005"),
    );
    compare_post(
        &mut h,
        &mut model,
        &values,
        [Some("B"), None],
        b"clear-admits-known-value",
        None,
    );

    assert!(constraints_at(&h.db, &h.book, before).unwrap().is_empty());
    let historical = constraints_at(&h.db, &h.book, first.recorded_at.unwrap()).unwrap();
    assert_eq!(historical.len(), 1);
    assert_eq!(historical[0].spec, spec);
    assert_eq!(Some(historical[0].control_entry), first.control_entry);
    assert_eq!(Some(historical[0].recorded_at), first.recorded_at);
    let current = constraints_at(&h.db, &h.book, h.db.frontier().unwrap()).unwrap();
    assert_eq!(current.len(), 1, "clear is retained as a journaled policy");
    assert_eq!(current[0].vid, historical[0].vid);
    assert_eq!(current[0].spec, clear);
    assert_eq!(Some(current[0].control_entry), cleared.control_entry);
    assert_eq!(Some(current[0].recorded_at), cleared.recorded_at);
}

#[test]
fn dimension_constraint_retries_preserve_later_policy_and_authorize_before_observation() {
    let (mut h, values) = fixture();
    let spec = policy(h.rent, Some(&["A"]), &[]);
    let old = record(&mut h, &spec, b"policy-original-key");
    let original_head = h.db.frontier().unwrap();
    let retry = record(&mut h, &spec, b"policy-original-key");
    assert!(retry.already_recorded);
    assert_eq!(retry.control_entry, old.control_entry);
    assert_eq!(retry.recorded_at, old.recorded_at);
    assert_eq!(h.db.frontier().unwrap(), original_head);

    let later_spec = policy(h.rent, Some(&["B"]), &[]);
    let later = record(&mut h, &later_spec, b"policy-later-key");
    let head = h.db.frontier().unwrap();
    let original_retry = record(&mut h, &spec, b"policy-original-key");
    assert!(original_retry.already_recorded);
    assert_eq!(original_retry.spec, spec);
    assert_eq!(original_retry.control_entry, old.control_entry);
    assert_eq!(original_retry.recorded_at, old.recorded_at);
    assert_eq!(h.db.frontier().unwrap(), head);
    let current = constraints_at(&h.db, &h.book, head).unwrap();
    assert_eq!(current[0].spec, later_spec);
    assert_eq!(Some(current[0].control_entry), later.control_entry);

    let cap = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
    let refused = record_with(&mut h, &later_spec, b"policy-original-key", &cap).unwrap_err();
    assert_eq!((refused.code, refused.exit), ("FA-REF-032", exit::CONFLICT));
    let post = tagged(&h, Some(values["B"]), b"policy-later-key");
    let refused = h.post(h.request(post, &["post"])).unwrap_err();
    assert_eq!((refused.code, refused.exit), ("FA-REF-032", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), head);

    let post = tagged(&h, Some(values["B"]), b"already-posted-key");
    h.post(h.request(post, &["post"])).unwrap();
    let head = h.db.frontier().unwrap();
    let refused = record_with(&mut h, &later_spec, b"already-posted-key", &cap).unwrap_err();
    assert_eq!((refused.code, refused.exit), ("FA-REF-032", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), head);

    // This original control cannot be decoded. Insufficient schema authority
    // must still return its ordinary denial before reading the retry payload.
    let mut poison = fgdb::WriteBatch::new(relation::IN_BOOK);
    poison.set_vertex_property(
        old.control_entry.unwrap(),
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(vec![0; 7]).unwrap()),
    );
    h.write_raw(poison);
    assert!(read_entry(&h.db, old.control_entry.unwrap()).is_err());
    let head = h.db.frontier().unwrap();
    let denied = record_with(
        &mut h,
        &spec,
        b"policy-original-key",
        &Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
    )
    .unwrap_err();
    assert_eq!((denied.code, denied.exit), ("FA-REF-011", exit::SAFETY));
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn prepared_post_witnesses_missing_changed_and_restored_dimension_constraints() {
    for case in 0..3 {
        let (mut h, values) = fixture();
        let allowed = policy(h.rent, Some(&["A"]), &[]);
        if case != 0 {
            record(&mut h, &allowed, b"prepared-original-policy");
        }
        let proposal = tagged(&h, Some(values["A"]), b"prepared-constrained-post");
        let vid = h.member_ref(&proposal).vid;
        let request = h.request(proposal.clone(), &["post"]);
        let cx = h.ctx();
        let prepared = match prepare_post(&mut h.db, &cx, &h.book, request)
            .unwrap()
            .unwrap()
        {
            PostPreparation::Ready(prepared) => prepared,
            PostPreparation::AlreadyRecorded(_) => panic!("the posting key is fresh"),
        };
        let denied = policy(h.rent, Some(&["B"]), &[]);
        record(&mut h, &denied, b"prepared-new-policy");
        if case == 2 {
            // Intervening policy history matters even when its final payload
            // permits the original value again.
            record(&mut h, &allowed, b"prepared-policy-restored");
        }
        let head = h.db.frontier().unwrap();
        let refusal = h
            .runtime
            .block_on(prepared.commit(&mut h.db, &cx))
            .unwrap()
            .unwrap_err();
        assert_eq!(
            (refusal.code, refusal.exit),
            ("FA-REF-030", exit::CONFLICT),
            "case {case}: {refusal}"
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert!(read_entry(&h.db, vid).unwrap().is_none());
        let fresh = h.post(h.request(proposal, &["post"]));
        if case == 2 {
            fresh.expect("a fresh plan may use the restored permission");
        } else {
            assert_eq!(fresh.unwrap_err().code, "FA-REF-207");
            assert_eq!(h.db.frontier().unwrap(), head);
        }
    }
}

#[test]
fn dimension_constraints_refuse_atomic_batches_and_dry_runs_without_partial_effects() {
    let (mut h, values) = fixture();
    let spec = policy(h.rent, Some(&["A"]), &[]);
    record(&mut h, &spec, b"batch-value-policy");
    let first = tagged(&h, Some(values["A"]), b"constraint-batch-good");
    let second = tagged(&h, Some(values["B"]), b"constraint-batch-bad");
    let batch = h.batch(b"constraint-batch", vec![first.clone(), second.clone()]);
    let outcome = outcome_vid(&h.book, &batch);
    let cap = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let refusal = h.planned_batch(batch.clone(), &cap).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-207");
    assert!(refusal.message.starts_with("batch member 1:"));
    let refusal = h.post_batch(batch.clone()).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-207");
    assert!(refusal.message.starts_with("batch member 1:"));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    assert!(h.db.vertex(outcome).unwrap().is_none());
    for proposal in [&first, &second] {
        assert!(
            read_entry(&h.db, h.member_ref(proposal).vid)
                .unwrap()
                .is_none()
        );
    }

    let untagged = tagged(&h, None, b"constraint-batch-optional");
    let reviewed = h.batch(b"constraint-reviewed-batch", vec![first, untagged]);
    let plan = h.planned_batch(reviewed.clone(), &cap).unwrap();
    assert_eq!(plan.prepared_entries().len(), 2);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);

    let stricter = policy(h.rent, Some(&["B"]), &[]);
    record(&mut h, &stricter, b"constraint-after-review");
    let head = h.db.frontier().unwrap();
    let refusal = h.publish_batch_plan(plan, &cap).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-034", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert!(
        h.db.vertex(outcome_vid(&h.book, &reviewed))
            .unwrap()
            .is_none()
    );

    // A refused batch reserved no keys. Clearing the value policy allows its
    // original request to commit once, and the ordinary success retry remains.
    let clear = policy(h.rent, None, &[]);
    record(&mut h, &clear, b"constraint-batch-clear");
    let posted = h.post_batch(batch.clone()).unwrap();
    assert_eq!(posted.entries.len(), 2);
    let retry = h.post_batch(batch).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, posted.entries);
    assert_eq!(retry.recorded_at, posted.recorded_at);
    assert_eq!(h.db.frontier().unwrap(), posted.recorded_at);
}

#[test]
fn tightened_dimension_constraints_preserve_historical_undo_holds_and_applications() {
    let (mut h, values) = fixture();
    let original = tagged(&h, Some(values["A"]), b"historical-dimension-post");
    let posted = h.post(h.request(original.clone(), &["post"])).unwrap();
    let mut pending_legs = h.rent_legs(30);
    pending_legs[0].dimension_set.push((KIND, values["A"]));
    let pending = h.pending(pending_legs.clone(), b"historical-dimension-hold");
    let held = h.post(h.request(pending, &["post"])).unwrap();
    let mut invoice = h.invoice(100, b"historical-dimension-invoice");
    invoice.legs[0].dimension_set.push((KIND, values["A"]));
    let invoiced = h.post(h.request(invoice, &["post"])).unwrap();

    for (account, key) in [
        (h.rent, b"tighten-rent".as_slice()),
        (h.receivable, b"tighten-receivable".as_slice()),
    ] {
        record(&mut h, &policy(account, Some(&[]), &[]), key);
    }
    let head = h.db.frontier().unwrap();
    let fresh = tagged(&h, Some(values["A"]), b"new-forbidden-dimension-post");
    assert_eq!(
        h.post(h.request(fresh, &["post"])).unwrap_err().code,
        "FA-REF-207"
    );
    let retry = h.post(h.request(original.clone(), &["post"])).unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(h.db.frontier().unwrap(), head);

    let mut reversed = original;
    reversed.class = EntryClass::REVERSAL;
    reversed.idempotency_key = b"undo-historical-dimension".to_vec();
    reversed.supersession = vec![Supersession {
        target: posted.entry_ref(),
        kind: SupersessionKind::Reverses,
        reason_code: 1,
    }];
    for leg in &mut reversed.legs {
        leg.side = leg.side.flipped();
    }
    reversed.unit_totals = EntryPayload::fold_unit_totals(&reversed.legs).unwrap();
    h.post(h.request(reversed, &["post"])).unwrap();

    let resolution = h.resolution_posts(
        held.entry_ref(),
        pending_legs,
        vec![0, 1],
        b"resolve-historical-dimension",
    );
    h.post(h.request(resolution, &["post"])).unwrap();

    let mut receipt = h.receipt(
        40,
        vec![settle(invoiced.entry_ref(), 0, h.usd, 40)],
        b"settle-historical-dimension",
    );
    receipt.legs[1].dimension_set.push((KIND, values["A"]));
    h.post(h.request(receipt.clone(), &["post"])).unwrap();
    assert_eq!(h.applied_to(invoiced.entry_ref().vid, 0), 40);

    receipt.idempotency_key = b"fresh-not-an-application".to_vec();
    receipt.legs[1].settles.clear();
    let head = h.db.frontier().unwrap();
    assert_eq!(
        h.post(h.request(receipt, &["post"])).unwrap_err().code,
        "FA-REF-207"
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.applied_to(invoiced.entry_ref().vid, 0), 40);
}

#[test]
fn dimension_constraints_are_rechecked_when_a_reviewed_draft_promotes() {
    let (mut h, values) = fixture();
    let name = "dimension-policy-draft";
    let agent = h.agent_capability();
    h.open_draft(agent.clone(), name).unwrap();

    // Both members were reviewed before this account had any value policy.
    // The untagged first member will remain admissible after tightening.
    h.plan_draft(
        agent.clone(),
        name,
        h.agent_rent(200, b"dimension-draft-first"),
    )
    .unwrap();
    let mut second = h.agent_rent(300, b"dimension-draft-second");
    second.legs[0].dimension_set.push((KIND, values["A"]));
    let planned = h.plan_draft(agent.clone(), name, second).unwrap();
    let reviewed = planned.plan.unwrap();
    assert_eq!(reviewed.members().len(), 2);
    let entries: Vec<_> = reviewed
        .members()
        .iter()
        .map(|member| {
            member.entry.entry_ref(entry_vid(
                h.book.book_id,
                &AGENT.0.to_le_bytes(),
                &member.entry.proposal.idempotency_key,
            ))
        })
        .collect();
    assert!(
        constraints_at(&h.db, &h.book, reviewed.snapshot_seq())
            .unwrap()
            .is_empty()
    );
    for entry in &entries {
        assert!(read_entry(&h.db, entry.vid).unwrap().is_none());
    }

    let restricted = policy(h.rent, Some(&["B"]), &[]);
    record(&mut h, &restricted, b"dimension-policy-after-draft");
    let head = h.db.frontier().unwrap();
    assert!(head > planned.recorded.recorded_at);
    assert!(head > reviewed.snapshot_seq());
    let vertices = h.db.vertices().unwrap();
    let refusal = h.promote(h.approver_capability(), name).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-207", exit::REFUSAL));
    assert!(refusal.message.starts_with("batch member 1:"), "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    assert_eq!(h.draft(name).state, DraftState::Open);
    assert_eq!(h.draft(name).intents.len(), 2);
    for entry in &entries {
        assert!(read_entry(&h.db, entry.vid).unwrap().is_none());
    }

    let cx = h.ctx();
    let refusal = h
        .runtime
        .block_on(fa_journal::draft::preview_draft(
            &mut h.db, &cx, &h.book, &agent, name,
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-207");
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);

    // Clearing permits a fresh review at the current trunk prefix. The
    // original reviewed entries and their planner identity remain exact.
    let clear = policy(h.rent, None, &[]);
    record(&mut h, &clear, b"dimension-policy-clear-for-draft");
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let refreshed = h
        .runtime
        .block_on(fa_journal::draft::preview_draft(
            &mut h.db, &cx, &h.book, &agent, name,
        ))
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(refreshed.snapshot_seq(), head);
    assert_eq!(refreshed.members(), reviewed.members());
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);

    let promoted = h.promote(h.approver_capability(), name).unwrap();
    assert!(!promoted.already_recorded);
    assert_eq!(promoted.entries, entries);
    assert_eq!(promoted.recorded_at.0, head.0 + 1);
    assert_eq!(h.draft(name).state, DraftState::Promoted);
    for entry in &entries {
        let (stored, recorded_at) = read_entry(&h.db, entry.vid).unwrap().unwrap();
        assert_eq!(stored.entry_digest, entry.entry_digest);
        assert_eq!(stored.proposal.principal_ref, AGENT);
        assert_eq!(recorded_at, promoted.recorded_at);
    }
    let retry = h.promote(h.approver_capability(), name).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, promoted.entries);
    assert_eq!(retry.recorded_at, promoted.recorded_at);
    assert_eq!(h.db.frontier().unwrap(), promoted.recorded_at);
}
