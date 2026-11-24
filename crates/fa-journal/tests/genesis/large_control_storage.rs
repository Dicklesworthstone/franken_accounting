//! Large scenario and restatement controls use the native Entry storage contract.
//! The retained native comparison fixtures below check framing and storage;
//! report arithmetic and replay are exercised by the facade regression.

use super::*;
use fa_intents::PostIntent;
use fa_journal::post::read_entry_at;
use fa_journal::scenario::{
    Coordinates, ScenarioFork, ScenarioRequest, discard_scenario, materialize_into, open_scenario,
    plan_into_scenario, read_scenario,
};
use fa_model::symbols::label;
use fa_model::{Entry, Writer, report_certificate_vid};
use fgdb::WriteBatch;
use fgdb_types::CommitSeq;

const LARGE_SCENARIO: &str = "large-counterfactual";
const CASE_SCENARIO: &str = "large-case";
const PLANNER: VId = VId(44);

fn scenario_request(h: &Harness, owner: VId) -> ScenarioRequest {
    ScenarioRequest {
        capability: Capability::embedded(owner, &["post", "read"]).unwrap(),
        effective_date: h.day(),
        description: h.statement("Large scenario control", 221),
    }
}

fn large_intent(h: &Harness) -> PostIntent {
    let legs = (0..256).flat_map(|_| h.rent_legs(100)).collect();
    let intent = PostIntent::new(
        h.proposal(legs, b"large-scenario-intent", EntryClass::ORIGINAL),
        Vec::new(),
    )
    .unwrap();
    assert!(intent.canonical_bytes().unwrap().len() > 16 * 1024);
    intent
}

fn start_large(h: &mut Harness) -> (ScenarioRequest, PostIntent, fa_journal::ScenarioRecorded) {
    let ctx = h.ctx();
    let req = scenario_request(h, PRINCIPAL);
    let intent = large_intent(h);
    h.runtime
        .block_on(open_scenario(
            &mut h.db,
            &ctx,
            &h.book,
            LARGE_SCENARIO,
            ScenarioFork::default(),
            req.clone(),
        ))
        .unwrap()
        .unwrap();
    let before = h.db.frontier().unwrap();
    let recorded = h
        .runtime
        .block_on(plan_into_scenario(
            &mut h.db,
            &ctx,
            &h.book,
            LARGE_SCENARIO,
            intent.clone(),
            req.clone(),
        ))
        .unwrap()
        .unwrap();
    assert_eq!(recorded.recorded_at.0, before.0 + 1);
    (req, intent, recorded)
}

fn fragments(h: &Harness, at: CommitSeq) -> Vec<VId> {
    h.db.vertices()
        .unwrap()
        .into_iter()
        .filter(|row| row.created_at == at && row.labels == [label::ENTRY_FRAGMENT])
        .map(|row| row.vid)
        .collect()
}

fn large_control(h: &Harness, vid: VId, at: CommitSeq, class: EntryClass) -> Entry {
    let (entry, recorded) = read_entry(&h.db, vid).unwrap().unwrap();
    assert_eq!(recorded, at);
    assert_eq!(entry.proposal.class, class);
    let bytes = entry.encode().unwrap();
    assert!(
        bytes.len() > 16 * 1024,
        "fixture must exceed the native row limit"
    );
    let parts = fragments(h, at);
    assert_eq!(
        parts.len(),
        bytes.len().div_ceil(fa_model::limits::OBJECT_CHUNK_BYTES)
    );
    let root = h.db.vertex(vid).unwrap().unwrap();
    let CanonicalScalar::Bytes(stored) =
        fa_journal::rows::prop(&root, property::FA_PAYLOAD).unwrap()
    else {
        panic!("control payload bytes");
    };
    assert!(stored.as_slice().len() < fa_model::limits::OBJECT_CHUNK_BYTES);
    entry
}

fn corrupt_fragment(h: &mut Harness, vid: VId, delete: bool) -> CanonicalScalar {
    let original =
        fa_journal::rows::prop(&h.db.vertex(vid).unwrap().unwrap(), property::FA_PAYLOAD)
            .unwrap()
            .clone();
    let mut write = WriteBatch::new(relation::IN_CASE);
    if delete {
        write.delete_vertex(vid);
    } else {
        let CanonicalScalar::Bytes(bytes) = &original else {
            panic!("fragment bytes");
        };
        let mut changed = bytes.as_slice().to_vec();
        changed[0] ^= 1;
        write.set_vertex_property(
            vid,
            property::FA_PAYLOAD,
            Some(CanonicalScalar::bytes(changed).unwrap()),
        );
    }
    h.write_raw(write);
    original
}

fn assert_corrupt<T: std::fmt::Debug>(result: Result<T, KernelError>) {
    assert!(
        matches!(&result, Err(KernelError::Corrupt(_))),
        "{result:?}"
    );
}

#[test]
fn oversized_scenario_plan_is_atomic_rehearsable_and_retries_without_a_write() {
    let mut h = harness();
    let (mut req, original, recorded) = start_large(&mut h);
    let entry = large_control(
        &h,
        recorded.control_entry,
        recorded.recorded_at,
        EntryClass::SCENARIO_CONTROL,
    );
    let new_rows: Vec<_> =
        h.db.vertices()
            .unwrap()
            .into_iter()
            .filter(|row| row.created_at == recorded.recorded_at)
            .collect();
    assert_eq!(
        new_rows
            .iter()
            .filter(|row| row.labels == [label::ENTRY])
            .count(),
        1
    );
    assert_eq!(
        new_rows
            .iter()
            .filter(|row| row.labels == [label::INTENT_OUTCOME])
            .count(),
        1
    );
    assert!(!new_rows.iter().any(|row| row.labels.contains(&label::LEG)));

    let view = read_scenario(&h.db, &h.book, LARGE_SCENARIO)
        .unwrap()
        .unwrap();
    assert_eq!(view.intents.len(), 1);
    assert_eq!(view.intents[0].intent, original);
    let ctx = h.ctx();
    let target = h
        .runtime
        .block_on(Database::open_memory(
            &ctx.commit(),
            DatabaseKeys::new([231; 32], DatabaseSecurityNamespaceId([232; 32]), [233; 32]),
        ))
        .unwrap();
    let posting = h.request(original.proposal().clone(), &["read", "post"]);
    let (scratch, _, posted) = h
        .runtime
        .block_on(materialize_into(
            &mut h.db,
            target,
            &ctx,
            &h.book,
            view.body.fork_at,
            Coordinates::Protected,
            vec![posting],
        ))
        .unwrap()
        .unwrap();
    assert_eq!(posted.len(), 1);
    assert_eq!(
        read_entry(&scratch, posted[0])
            .unwrap()
            .unwrap()
            .0
            .proposal
            .legs,
        original.proposal().legs,
    );
    assert_eq!(h.db.frontier().unwrap(), recorded.recorded_at);

    // The outer description can be sealed again without changing the request.
    req.description = h.statement("Large scenario control", 222);
    let before = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let retry = h
        .runtime
        .block_on(plan_into_scenario(
            &mut h.db,
            &ctx,
            &h.book,
            LARGE_SCENARIO,
            original.clone(),
            req.clone(),
        ))
        .unwrap()
        .unwrap();
    assert!(retry.already_recorded);
    assert_eq!(
        (retry.control_entry, retry.recorded_at),
        (recorded.control_entry, recorded.recorded_at)
    );
    assert_eq!(
        read_entry(&h.db, retry.control_entry).unwrap().unwrap().0,
        entry
    );
    let mut different = original.proposal().clone();
    different.legs = h.rent_legs(101);
    different.unit_totals = EntryPayload::fold_unit_totals(&different.legs).unwrap();
    let refused = h
        .runtime
        .block_on(plan_into_scenario(
            &mut h.db,
            &ctx,
            &h.book,
            LARGE_SCENARIO,
            PostIntent::new(different, Vec::new()).unwrap(),
            req,
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(
        refused.code,
        fa_journal::refusal::code::IDEMPOTENCY_CONFLICT
    );
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

#[test]
fn missing_tampered_or_restored_scenario_fragment_refuses_consumers_without_publication() {
    for delete in [false, true] {
        let mut h = harness();
        let (req, original, recorded) = start_large(&mut h);
        let entry = large_control(
            &h,
            recorded.control_entry,
            recorded.recorded_at,
            EntryClass::SCENARIO_CONTROL,
        );
        let fragment = fragments(&h, recorded.recorded_at)[0];
        let original_fragment = corrupt_fragment(&mut h, fragment, delete);
        for restored in [false, true] {
            if restored {
                if delete {
                    break;
                }
                let mut restore = WriteBatch::new(relation::IN_CASE);
                restore.set_vertex_property(
                    fragment,
                    property::FA_PAYLOAD,
                    Some(original_fragment.clone()),
                );
                h.write_raw(restore);
            }
            let head = h.db.frontier().unwrap();
            let rows = h.db.vertices().unwrap();
            let edges = h.db.edges_at(head).unwrap();
            assert_corrupt(read_scenario(&h.db, &h.book, LARGE_SCENARIO));
            let ctx = h.ctx();
            assert_corrupt(h.runtime.block_on(plan_into_scenario(
                &mut h.db,
                &ctx,
                &h.book,
                LARGE_SCENARIO,
                original.clone(),
                req.clone(),
            )));
            assert_corrupt(h.runtime.block_on(discard_scenario(
                &mut h.db,
                &ctx,
                &h.book,
                LARGE_SCENARIO,
                req.clone(),
            )));
            assert_eq!(
                read_entry_at(&h.db, recorded.control_entry, recorded.recorded_at)
                    .unwrap()
                    .unwrap()
                    .0,
                entry,
            );
            assert_eq!(
                h.db.frontier().unwrap(),
                head,
                "delete={delete}, restored={restored}"
            );
            assert_eq!(h.db.vertices().unwrap(), rows);
            assert_eq!(h.db.edges_at(head).unwrap(), edges);
        }
    }
}

fn case_request(h: &Harness, key: &[u8]) -> CaseRequest {
    CaseRequest {
        capability: Capability::embedded(PRINCIPAL, &["restate", "post", "read"]).unwrap(),
        effective_date: h.day(),
        description: h.statement("Large controlled correction", 223),
        idempotency_key: key.to_vec(),
    }
}

fn retain_native_certificate(
    h: &Harness,
    batch: &mut WriteBatch,
    digest: [u8; 32],
    payload: Vec<u8>,
) {
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            CanonicalScalar::bytes(payload).unwrap(),
        ),
        (
            property::FA_DIGEST,
            CanonicalScalar::bytes(digest.to_vec()).unwrap(),
        ),
        (
            property::BOOK_ID,
            CanonicalScalar::bytes(h.book.book_id.0.to_vec()).unwrap(),
        ),
    ];
    props.sort_by_key(|(key, _)| key.0);
    batch.create_vertex(
        report_certificate_vid(h.book.book_id, &digest),
        vec![label::CERTIFICATE],
        props,
    );
}

fn approved_case() -> (Harness, CaseRequest, fa_journal::CaseRecorded) {
    let mut h = harness();
    let ctx = h.ctx();
    let schema = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
    let equity = account_vid(h.book.book_id, "3000");
    let description = h.statement("Large-case retained earnings", 224);
    let at = h.day();
    h.runtime
        .block_on(install_chart(
            &mut h.db,
            &ctx,
            &h.book,
            &[AccountSpec {
                code: "3000".into(),
                name: "Retained earnings".into(),
                account_type: fa_model::AccountType::EQUITY.0,
                normal_balance: 1,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(h.usd),
                parent_code: None,
                limit: None,
            }],
            PRINCIPAL,
            at,
            b"large-case-equity",
            description.clone(),
            &schema,
        ))
        .unwrap()
        .unwrap();
    h.runtime
        .block_on(create_periods(
            &mut h.db,
            &ctx,
            &h.book,
            2025,
            PRINCIPAL,
            description.clone(),
            &schema,
        ))
        .unwrap()
        .unwrap();
    h.runtime
        .block_on(record_account_role(
            &mut h.db,
            &ctx,
            &h.book,
            &AccountRoleSpec {
                account: equity,
                role: "retained_earnings".into(),
                assigned: true,
            },
            PRINCIPAL,
            b"large-case-role",
            description,
            &schema,
        ))
        .unwrap()
        .unwrap();
    let authority = h.evidence[0].document_oid;
    let req = case_request(&h, b"large-case-open");
    h.runtime
        .block_on(open_case(
            &mut h.db,
            &ctx,
            &h.book,
            CaseBody {
                book_id: h.book.book_id,
                ordinal: 0,
                kind: CaseKind::PriorPeriodAdjustment,
                periods: vec!["FY2025-P12".into()],
                narrative: Some(authority),
                determination: Some(Determination { day: at, authority }),
            },
            req,
        ))
        .unwrap()
        .unwrap();
    let plan_req = scenario_request(&h, PLANNER);
    h.runtime
        .block_on(open_scenario(
            &mut h.db,
            &ctx,
            &h.book,
            CASE_SCENARIO,
            ScenarioFork::default(),
            plan_req.clone(),
        ))
        .unwrap()
        .unwrap();
    for index in 0..fa_model::limits::MAX_PROOF_REFS {
        let mut proposal = h.proposal(
            vec![
                LegPayload::simple(Side::Debit, h.cash, Amount::new(h.usd, 1)),
                LegPayload::simple(Side::Credit, equity, Amount::new(h.usd, 1)),
            ],
            format!("large-case-member-{index}").as_bytes(),
            EntryClass::ORIGINAL,
        );
        proposal.principal_ref = PLANNER;
        proposal
            .with_prior_period_adjustment(&fa_model::PeriodRef {
                calendar: h.book.calendar.id.clone(),
                code: "FY2025-P12".into(),
            })
            .unwrap();
        h.runtime
            .block_on(plan_into_scenario(
                &mut h.db,
                &ctx,
                &h.book,
                CASE_SCENARIO,
                PostIntent::new(proposal, Vec::new()).unwrap(),
                plan_req.clone(),
            ))
            .unwrap()
            .unwrap();
    }
    let scenario = read_scenario(&h.db, &h.book, CASE_SCENARIO)
        .unwrap()
        .unwrap();
    let digest = [225; 32];
    // The kernel's Rehearse contract witnesses retention; full report replay
    // is the facade's responsibility, covered separately with real certificates.
    let mut retained = WriteBatch::new(relation::IN_CASE);
    retain_native_certificate(
        &h,
        &mut retained,
        digest,
        b"native storage rehearsal fixture".to_vec(),
    );
    h.write_raw(retained);
    let request = case_request(&h, b"large-case-rehearse");
    h.runtime
        .block_on(rehearse_case(
            &mut h.db,
            &ctx,
            &h.book,
            1,
            Rehearsal {
                scenario: CASE_SCENARIO.into(),
                certificate: digest,
                fork_at: scenario.body.fork_at,
                periods: vec!["FY2025-P12".into(), h.march.clone()],
                intents: scenario
                    .intents
                    .iter()
                    .map(|planned| planned.record)
                    .collect(),
            },
            request,
        ))
        .unwrap()
        .unwrap();
    let manifest = case_manifest(&h.db, &h.book, 1).unwrap().unwrap();
    assert_eq!(manifest.entries.len(), fa_model::limits::MAX_PROOF_REFS);
    let digest = manifest.digest().unwrap();
    let approvals = [REVIEWER, OTHER_REVIEWER]
        .into_iter()
        .map(|who| h.approve_digest(who, digest).unwrap().approval_vid)
        .collect();
    let req = case_request(&h, b"large-case-approve");
    let before = h.db.frontier().unwrap();
    let approved = h
        .runtime
        .block_on(approve_case(
            &mut h.db,
            &ctx,
            &h.book,
            1,
            approvals,
            req.clone(),
        ))
        .unwrap()
        .unwrap();
    assert_eq!(approved.recorded_at.0, before.0 + 1);
    large_control(
        &h,
        approved.control_entry,
        approved.recorded_at,
        EntryClass::CASE_CONTROL,
    );
    (h, req, approved)
}

fn native_comparison(
    h: &Harness,
    post: DisclosurePost,
    marker: u128,
) -> ([u8; 32], Vec<u8>, ValidatedDisclosureComparison) {
    let source = |at: u64| {
        let mut w = Writer::new();
        w.fixed(b"fa:report-certificate:v4")
            .str("fa-fold-over-prefix")
            .str("embedded-owner")
            .str("fa:statement:v1")
            .fixed(&h.book.book_id.0)
            .fixed(&Id128::TRUNK.0)
            .u64(at)
            .u8(2)
            .bytes(b"opaque definition")
            .u32(1)
            .str(&h.march)
            .u32(0)
            .fixed(&[1; 32])
            .fixed(&[2; 32])
            .u64(1)
            .u32(7);
        for _ in 0..7 {
            w.bytes(b"opaque native proof");
        }
        w.bytes(b"opaque statement")
            .fixed(&[3; 32])
            .u8(0)
            .fixed(&[4; 32]);
        w.finish().unwrap()
    };
    let before = post.recorded_at.0 - 1;
    let mut output = Writer::new();
    output
        .bytes(b"fa:statement-diff:v1")
        .fixed(&h.book.book_id.0)
        .fixed(&Id128::TRUNK.0)
        .u64(before)
        .u64(post.recorded_at.0);
    let mut outer = Writer::new();
    outer
        .bytes(b"fa:statement-diff-certificate:v1")
        .u128(marker)
        .fixed(&[5; 32])
        .bytes(&source(before))
        .bytes(&source(post.recorded_at.0))
        .bytes(&output.finish().unwrap());
    let mut bytes = outer.finish().unwrap();
    let digest = fa_model::domain_digest(b"fa:statement-diff-certificate-digest:v1", &[&bytes]);
    bytes.extend_from_slice(&digest);
    let comparison = validate_disclosure_comparison(h.book.book_id, post, digest, &bytes).unwrap();
    (digest, bytes, comparison)
}

#[test]
fn large_case_manifest_post_and_complete_disclosure_are_atomic_and_keep_every_reference() {
    let (mut h, approval_request, approved) = approved_case();
    let ctx = h.ctx();
    let approvals: Vec<_> = approved
        .case
        .approval
        .as_ref()
        .unwrap()
        .approvals
        .iter()
        .map(|approval| approval.approval_vid)
        .collect();
    let before = h.db.frontier().unwrap();
    let retry = h
        .runtime
        .block_on(approve_case(
            &mut h.db,
            &ctx,
            &h.book,
            1,
            approvals,
            approval_request,
        ))
        .unwrap()
        .unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.control_entry, approved.control_entry);
    assert_eq!(h.db.frontier().unwrap(), before);

    let req = case_request(&h, b"large-case-post");
    let posted = h
        .runtime
        .block_on(post_case(&mut h.db, &ctx, &h.book, 1, req.clone()))
        .unwrap()
        .unwrap();
    assert_eq!(posted.recorded_at.0, before.0 + 1);
    assert_eq!(posted.case.posted.len(), fa_model::limits::MAX_PROOF_REFS);
    large_control(
        &h,
        posted.control_entry,
        posted.recorded_at,
        EntryClass::CASE_CONTROL,
    );
    for member in &posted.case.posted {
        let (entry, at) = read_entry(&h.db, member.entry).unwrap().unwrap();
        assert_eq!(at, posted.recorded_at);
        assert_eq!(entry.entry_digest, member.entry_digest);
        assert_eq!(entry.proposal.class, EntryClass::PRIOR_PERIOD_ADJUSTMENT);
    }
    let before = h.db.frontier().unwrap();
    assert!(
        h.runtime
            .block_on(post_case(&mut h.db, &ctx, &h.book, 1, req,))
            .unwrap()
            .unwrap()
            .already_recorded
    );
    assert_eq!(h.db.frontier().unwrap(), before);

    let post = DisclosurePost {
        entry: posted.control_entry,
        recorded_at: posted.recorded_at,
    };
    let mut retention = WriteBatch::new(relation::IN_CASE);
    let mut tokens = Vec::new();
    let mut digests = Vec::new();
    for marker in 0..fa_journal::case::MAX_DISCLOSURE_COMPARISONS {
        let (digest, bytes, token) = native_comparison(&h, post, marker as u128);
        retain_native_certificate(&h, &mut retention, digest, bytes);
        digests.push(digest);
        tokens.push(token);
    }
    h.write_raw(retention);
    let document = h.document(20, HUMAN_UPLOAD, b"Complete large-case disclosure");
    h.add_document(&document).unwrap();
    h.review(REVIEWER, document.oid(), Vec::new()).unwrap();
    let request = case_request(&h, b"large-case-disclose");
    let before = h.db.frontier().unwrap();
    let disclosed = h
        .runtime
        .block_on(disclose_case(
            &mut h.db,
            &ctx,
            &h.book,
            1,
            document.oid(),
            post,
            &tokens,
            request.clone(),
        ))
        .unwrap()
        .unwrap();
    assert_eq!(disclosed.recorded_at.0, before.0 + 1);
    assert_eq!(disclosed.case.state, CaseState::Disclosed);
    let entry = large_control(
        &h,
        disclosed.control_entry,
        disclosed.recorded_at,
        EntryClass::CASE_CONTROL,
    );
    digests.sort();
    assert_eq!(
        disclosed.case.disclosure.as_ref().unwrap().comparisons,
        digests
    );
    let Some(ControlPayload::LifecycleTransition { proof_refs, .. }) = &entry.proposal.control
    else {
        panic!("disclosure lifecycle");
    };
    assert_eq!(proof_refs.len(), fa_model::limits::MAX_PROOF_REFS);
    let before = h.db.frontier().unwrap();
    let retry = h
        .runtime
        .block_on(disclose_case(
            &mut h.db,
            &ctx,
            &h.book,
            1,
            document.oid(),
            post,
            &tokens,
            request,
        ))
        .unwrap()
        .unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.control_entry, disclosed.control_entry);
    assert_eq!(h.db.frontier().unwrap(), before);

    let fragment = fragments(&h, disclosed.recorded_at)[0];
    let original = corrupt_fragment(&mut h, fragment, false);
    for restored in [false, true] {
        if restored {
            let mut restore = WriteBatch::new(relation::IN_CASE);
            restore.set_vertex_property(fragment, property::FA_PAYLOAD, Some(original.clone()));
            h.write_raw(restore);
        }
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let request = case_request(&h, b"must-not-close-damaged-disclosure");
        assert_corrupt(read_case(&h.db, &h.book, 1));
        assert_corrupt(
            h.runtime
                .block_on(close_case(&mut h.db, &ctx, &h.book, 1, request)),
        );
        assert_eq!(
            read_entry_at(&h.db, disclosed.control_entry, disclosed.recorded_at)
                .unwrap()
                .unwrap()
                .0,
            entry,
        );
        assert_eq!(h.db.frontier().unwrap(), head, "restored={restored}");
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}
