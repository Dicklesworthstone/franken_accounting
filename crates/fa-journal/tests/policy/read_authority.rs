//! Read admissions and control plans require current, journaled authority
//! before observing payloads. Reusable admissions and exact control retries
//! never preserve authority after revocation or expiry.

use super::*;
use fa_journal::policy::ReadAuthority;
use fa_journal::refusal::code;

const CORRUPT: VId = VId(0x5eed_1001);
const ABSENT: VId = VId(0x5eed_1002);

fn historical_entries(h: &mut Harness) -> (VId, CommitSeq) {
    h.post_ok(
        h.proposal(
            PREPARER,
            1_000,
            b"read-authority-history",
            EntryClass::ORIGINAL,
        ),
        controller(),
    );
    let valid = fa_model::entry_vid(
        h.book.book_id,
        &PREPARER.0.to_le_bytes(),
        b"read-authority-history",
    );
    let ctx = h.ctx();
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(
        CORRUPT,
        vec![label::ENTRY],
        vec![(
            property::FA_PAYLOAD,
            fa_journal::rows::scalar_bytes("planted payload", vec![0xff; 8]).unwrap(),
        )],
    );
    h.runtime
        .block_on(h.db.write(&ctx.commit(), batch))
        .unwrap();
    (valid, h.db.frontier().unwrap())
}

fn assert_refused_before_payload(
    h: &Harness,
    reads: &ReadAuthority,
    valid: VId,
    history: CommitSeq,
    code: &str,
) {
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let expected = reads
        .read_entry(&h.db, ABSENT, history)
        .unwrap()
        .expect_err("even an absent target requires current authority");
    assert_eq!((expected.code, expected.exit), (code, exit::SAFETY));
    for target in [valid, CORRUPT] {
        let refusal = reads
            .read_entry(&h.db, target, history)
            .expect("refusal precedes decoding the corrupt historical payload")
            .unwrap_err();
        assert_eq!(refusal, expected, "target contents are not observed");
    }
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

#[test]
fn read_authority_rechecks_revocation_before_historical_payloads() {
    let mut h = harness();
    let (valid, history) = historical_entries(&mut h);
    let capability = human(PREPARER, &["read"]).known_at_most(history);
    let reads = admit_reads(&h.db, &h.book, PREPARER, &capability)
        .unwrap()
        .unwrap();
    assert!(
        reads
            .read_entry(&h.db, valid, history)
            .unwrap()
            .unwrap()
            .is_some()
    );
    assert!(
        reads.read_entry(&h.db, CORRUPT, history).is_err(),
        "the corrupt-payload trap is live while authority is current",
    );
    let cloned = reads.clone();
    h.revoke(
        &human(ALICE, &["issue_capability"]),
        &capability,
        b"revoke-admitted-reader",
    )
    .unwrap();
    for authority in [&reads, &cloned] {
        assert_refused_before_payload(&h, authority, valid, history, "FA-REF-023");
    }
}

#[test]
fn read_authority_rechecks_expiry_before_historical_payloads() {
    let mut h = harness();
    let (valid, history) = historical_entries(&mut h);
    let expires_at = CommitSeq(history.0 + 1);
    let capability = human(PREPARER, &["read"])
        .known_at_most(history)
        .expiring_at(expires_at);
    let reads = admit_reads(&h.db, &h.book, PREPARER, &capability)
        .unwrap()
        .unwrap();
    assert!(
        reads
            .read_entry(&h.db, valid, history)
            .unwrap()
            .unwrap()
            .is_some()
    );
    h.revoke(
        &human(ALICE, &["issue_capability"]),
        &human(CAROL, &["read"]),
        b"advance-past-read-expiry",
    )
    .unwrap();
    assert_eq!(h.db.frontier().unwrap(), expires_at);
    assert_refused_before_payload(&h, &reads, valid, history, "FA-REF-014");
}

#[test]
fn read_authority_rechecks_issuance_ancestor_revocation() {
    let mut h = harness();
    let (valid, history) = historical_entries(&mut h);
    let root = human(PREPARER, &["read", "issue_capability"]);
    let capability = Capability::new(ALICE, Profile::Human, &[Op::Read], PREPARER)
        .unwrap()
        .holder_bound(possession_digest(&[0x73; 32]));
    h.issue(&root, &capability, b"issue-admitted-reader")
        .unwrap();
    let reads = admit_reads(&h.db, &h.book, ALICE, &capability)
        .unwrap()
        .unwrap();
    assert!(
        reads
            .read_entry(&h.db, valid, history)
            .unwrap()
            .unwrap()
            .is_some()
    );
    h.revoke(
        &human(BOB, &["issue_capability"]),
        &root,
        b"revoke-admitted-reader-ancestor",
    )
    .unwrap();
    assert_refused_before_payload(&h, &reads, valid, history, "FA-REF-023");
}

#[test]
fn read_authority_remains_usable_after_unrelated_commits() {
    let mut h = harness();
    let (valid, history) = historical_entries(&mut h);
    let reads = admit_reads(&h.db, &h.book, PREPARER, &human(PREPARER, &["read"]))
        .unwrap()
        .unwrap();
    let original = reads.read_entry(&h.db, valid, history).unwrap().unwrap();
    assert!(original.is_some());
    let later = h
        .revoke(
            &human(ALICE, &["issue_capability"]),
            &human(CAROL, &["read"]),
            b"later-read-authority-entry",
        )
        .unwrap()
        .control_entry;
    assert_eq!(
        reads.read_entry(&h.db, valid, history).unwrap().unwrap(),
        original
    );
    assert_eq!(
        reads.read_entry(&h.db, later, history).unwrap().unwrap(),
        None
    );
    assert!(
        reads
            .read_entry(&h.db, later, h.db.frontier().unwrap())
            .unwrap()
            .unwrap()
            .is_some(),
    );
    assert!(
        reads.read_entry(&h.db, CORRUPT, history).is_err(),
        "a current reader still reaches the payload decoder",
    );
}

#[test]
fn read_authority_cannot_be_retargeted_to_another_books_database() {
    let h = harness();
    let capability = human(PREPARER, &["read"])
        .for_books(&[h.book.book_id])
        .unwrap();
    let reads = admit_reads(&h.db, &h.book, PREPARER, &capability)
        .unwrap()
        .unwrap();
    let ctx = h.ctx();
    let keys = DatabaseKeys::new(
        [0x6a; 32],
        DatabaseSecurityNamespaceId([0x6b; 32]),
        [0x6c; 32],
    );
    let mut other = h
        .runtime
        .block_on(Database::open_memory(&ctx.commit(), keys))
        .unwrap();
    let mut spec = fa_journal::genesis::read_book_spec(&h.db).unwrap().unwrap();
    spec.book_id = Id128([0x6d; 16]);
    h.runtime
        .block_on(create_book(
            &mut other,
            &ctx,
            &spec,
            &h.book.units,
            &h.book.symbols,
        ))
        .unwrap();
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(
        CORRUPT,
        vec![label::ENTRY],
        vec![(
            property::FA_PAYLOAD,
            fa_journal::rows::scalar_bytes("foreign payload", vec![0xff; 8]).unwrap(),
        )],
    );
    h.runtime
        .block_on(other.write(&ctx.commit(), batch))
        .unwrap();
    let head = other.frontier().unwrap();
    let absent = reads.read_entry(&other, ABSENT, head).unwrap().unwrap_err();
    assert_eq!((absent.code, absent.exit), ("FA-REF-011", exit::SAFETY));
    let planted = reads
        .read_entry(&other, CORRUPT, head)
        .expect("another book's payload is never decoded")
        .unwrap_err();
    assert_eq!(planted, absent);
    let mismatched_context = admit_reads(&other, &h.book, PREPARER, &capability)
        .unwrap()
        .expect_err("a caller-supplied context cannot misidentify the database");
    assert_eq!(mismatched_context, absent);
    assert_eq!(other.frontier().unwrap(), head);
}

#[derive(Clone, Copy, Debug)]
enum ControlAuthorityLoss {
    HolderRevoked,
    IssuerRevoked,
    NotIssued,
}

impl ControlAuthorityLoss {
    const ALL: [Self; 3] = [Self::HolderRevoked, Self::IssuerRevoked, Self::NotIssued];

    fn apply(self, h: &mut Harness, issuer: &Capability, capability: &Capability) -> Capability {
        match self {
            Self::HolderRevoked | Self::IssuerRevoked => {
                let revoked = match self {
                    Self::HolderRevoked => capability,
                    _ => issuer,
                };
                h.revoke(
                    &human(CAROL, &["issue_capability"]),
                    revoked,
                    b"revoke-control-authority",
                )
                .unwrap();
                capability.clone()
            }
            Self::NotIssued => capability
                .clone()
                .holder_bound(possession_digest(&[0xd2; 32])),
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::HolderRevoked | Self::IssuerRevoked => "FA-REF-023",
            Self::NotIssued => code::CAPABILITY_NOT_ISSUED,
        }
    }
}

fn control_authority(h: &mut Harness) -> (Capability, Capability) {
    let issuer = human(
        PREPARER,
        &[
            "post",
            "close",
            "rule_change",
            "restate",
            "produce",
            "hold",
            "issue_capability",
        ],
    );
    let capability = Capability::new(
        ALICE,
        Profile::Human,
        &[
            Op::Post,
            Op::Close,
            Op::RuleChange,
            Op::Restate,
            Op::Produce,
            Op::Hold,
        ],
        PREPARER,
    )
    .unwrap()
    .holder_bound(possession_digest(&[0xd1; 32]));
    h.issue(&issuer, &capability, b"issue-control-authority")
        .unwrap();
    (issuer, capability)
}

fn control_refusal<T: std::fmt::Debug>(
    outcome: Result<Result<T, Refusal>, KernelError>,
    loss: ControlAuthorityLoss,
) -> Refusal {
    let refusal = outcome
        .expect("authority refusal precedes protected payload decoding")
        .expect_err("the complete authority path is required even for a plan or retry");
    assert_eq!((refusal.code, refusal.exit), (loss.code(), exit::SAFETY));
    refusal
}

fn corrupt_control_payload(h: &mut Harness, vid: VId) {
    let ctx = h.ctx();
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.set_vertex_property(
        vid,
        property::FA_PAYLOAD,
        Some(fa_journal::rows::scalar_bytes("corrupt control payload", vec![0xff; 8]).unwrap()),
    );
    h.runtime
        .block_on(h.db.write(&ctx.commit(), batch))
        .unwrap();
}

#[test]
fn rule_control_planning_requires_current_issuance_ancestry_before_decoding() {
    use fa_journal::rule::{plan_rule_activation, propose_rule_version};

    for loss in ControlAuthorityLoss::ALL {
        let mut h = harness();
        let (issuer, capability) = control_authority(&mut h);
        let ctx = h.ctx();
        let description = h.seal("rule control", 71);
        let source =
            r#"rule fee v1 for event Sale { debit "1000" "1.00 USD" credit "6000" "1.00 USD" }"#;
        let recorded = h
            .runtime
            .block_on(propose_rule_version(
                &mut h.db,
                &ctx,
                &h.book,
                source,
                capability.holder(),
                b"authority-rule-propose",
                description.clone(),
                &capability,
            ))
            .unwrap()
            .unwrap();
        let digest = recorded.version.rule.ir_digest();
        let plan = |h: &Harness, capability: &Capability, digest: &[u8; 32]| {
            plan_rule_activation(
                &h.db,
                &h.book,
                capability,
                digest,
                DateDay::from_ymd(2026, 4, 1).unwrap(),
                b"authority-rule-activate",
                description.clone(),
            )
        };
        assert!(plan(&h, &capability, &digest).unwrap().is_ok());
        let vid = fa_model::rule_version_vid(h.book.book_id, &digest);
        corrupt_control_payload(&mut h, vid);
        assert!(
            plan(&h, &capability, &digest).is_err(),
            "the payload trap is live while authority is current",
        );
        let capability = loss.apply(&mut h, &issuer, &capability);
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let expected = control_refusal(plan(&h, &capability, &[0; 32]), loss);
        assert_eq!(
            control_refusal(plan(&h, &capability, &digest), loss),
            expected
        );
        assert_eq!(
            control_refusal(
                h.runtime.block_on(propose_rule_version(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    "invalid source",
                    capability.holder(),
                    b"authority-rule-refused",
                    description.clone(),
                    &capability,
                )),
                loss,
            ),
            expected,
            "the change gate refuses before compiling an unauthorized proposal",
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn statement_issuance_planning_requires_current_issuance_ancestry_before_period_reads() {
    use fa_journal::issuance::{IssuedTo, StatementIssuance, plan_issuance};

    for loss in ControlAuthorityLoss::ALL {
        let mut h = harness();
        let (issuer, capability) = control_authority(&mut h);
        let plan = |h: &Harness, capability: &Capability, period: &str| {
            plan_issuance(
                &h.db,
                &h.book,
                capability,
                StatementIssuance {
                    book_id: h.book.book_id,
                    period: period.to_string(),
                    ordinal: 1,
                    definition_digest: [1; 32],
                    definition_name: "balance-sheet".into(),
                    definition_version: 1,
                    certificate: [2; 32],
                    certified_at: h.db.frontier().unwrap(),
                    issued_to: IssuedTo::Board,
                    document: None,
                },
                DateDay::from_ymd(2026, 4, 1).unwrap(),
                b"authority-issuance",
                h.seal("statement issuance", 72),
            )
        };
        assert!(plan(&h, &capability, &h.march).unwrap().is_ok());
        assert!(plan(&h, &capability, "absent-period").unwrap().is_err());
        let capability = loss.apply(&mut h, &issuer, &capability);
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let expected = control_refusal(plan(&h, &capability, "absent-period"), loss);
        assert_eq!(
            control_refusal(plan(&h, &capability, &h.march), loss),
            expected,
            "a period's existence must not be observable without authority",
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn scenario_retries_and_assumptions_require_current_issuance_ancestry() {
    use fa_journal::scenario::{ScenarioFork, ScenarioRequest, discard_scenario, open_scenario};

    for loss in ControlAuthorityLoss::ALL {
        let mut h = harness();
        let (issuer, capability) = control_authority(&mut h);
        let ctx = h.ctx();
        let mut request = ScenarioRequest {
            capability: capability.clone(),
            effective_date: DateDay::from_ymd(2026, 3, 1).unwrap(),
            description: h.seal("scenario control", 73),
        };
        h.runtime
            .block_on(open_scenario(
                &mut h.db,
                &ctx,
                &h.book,
                "authority-scenario",
                ScenarioFork::default(),
                request.clone(),
            ))
            .unwrap()
            .unwrap();
        for already_recorded in [false, true] {
            let discarded = h
                .runtime
                .block_on(discard_scenario(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    "authority-scenario",
                    request.clone(),
                ))
                .unwrap()
                .unwrap();
            assert_eq!(discarded.already_recorded, already_recorded);
        }
        request.capability = loss.apply(&mut h, &issuer, &capability);
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let expected = control_refusal(
            h.runtime.block_on(discard_scenario(
                &mut h.db,
                &ctx,
                &h.book,
                "absent-scenario",
                request.clone(),
            )),
            loss,
        );
        assert_eq!(
            control_refusal(
                h.runtime.block_on(discard_scenario(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    "authority-scenario",
                    request.clone(),
                )),
                loss,
            ),
            expected,
            "an exact retry requires the same current authority as a new operation",
        );
        assert_eq!(
            control_refusal(
                h.runtime.block_on(open_scenario(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    "another-scenario",
                    ScenarioFork {
                        assumptions: vec![Oid([0xee; 32])],
                        ..ScenarioFork::default()
                    },
                    request,
                )),
                loss,
            ),
            expected,
            "assumption documents are not looked up before authority is checked",
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn case_controls_require_current_issuance_ancestry_before_decoding() {
    use fa_journal::case::{CaseBody, CaseKind, CaseRequest, approve_case, open_case, post_case};

    for loss in ControlAuthorityLoss::ALL {
        let mut h = harness();
        let (issuer, capability) = control_authority(&mut h);
        let ctx = h.ctx();
        let mut request = CaseRequest {
            capability: capability.clone(),
            effective_date: DateDay::from_ymd(2026, 3, 1).unwrap(),
            description: h.seal("case control", 74),
            idempotency_key: b"authority-case".to_vec(),
        };
        let body = CaseBody {
            book_id: h.book.book_id,
            ordinal: 0,
            kind: CaseKind::Restatement,
            periods: vec![h.march.clone()],
            narrative: None,
            determination: None,
        };
        let opened = h
            .runtime
            .block_on(open_case(&mut h.db, &ctx, &h.book, body, request.clone()))
            .unwrap()
            .unwrap();
        let ordinal = opened.case.body.ordinal;
        let refusal = h
            .runtime
            .block_on(approve_case(
                &mut h.db,
                &ctx,
                &h.book,
                ordinal,
                Vec::new(),
                request.clone(),
            ))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, code::CASE_STATE);
        corrupt_control_payload(&mut h, opened.case.vid);
        assert!(
            h.runtime
                .block_on(approve_case(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    ordinal,
                    Vec::new(),
                    request.clone(),
                ))
                .is_err(),
            "the case payload trap is live while authority is current",
        );
        request.capability = loss.apply(&mut h, &issuer, &capability);
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let mut expected = None;
        for target in [ordinal, ordinal + 1] {
            for refusal in [
                control_refusal(
                    h.runtime.block_on(approve_case(
                        &mut h.db,
                        &ctx,
                        &h.book,
                        target,
                        Vec::new(),
                        request.clone(),
                    )),
                    loss,
                ),
                control_refusal(
                    h.runtime.block_on(post_case(
                        &mut h.db,
                        &ctx,
                        &h.book,
                        target,
                        request.clone(),
                    )),
                    loss,
                ),
            ] {
                if let Some(expected) = &expected {
                    assert_eq!(&refusal, expected, "case contents are not observed");
                } else {
                    expected = Some(refusal);
                }
            }
        }
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn opening_engagements_requires_current_issuance_ancestry_before_book_reads() {
    use fa_journal::engagement::{
        EngagementKind, EngagementProfile, EngagementRequest, Materiality, open_engagement,
    };

    for loss in ControlAuthorityLoss::ALL {
        let mut h = harness();
        let (issuer, capability) = control_authority(&mut h);
        let ctx = h.ctx();
        let profile = |h: &Harness, capability: &Capability| EngagementProfile {
            book_id: h.book.book_id,
            engagement: "authority-engagement".into(),
            kind: EngagementKind::Audit,
            firm_principal: capability.holder(),
            scope_periods: vec![h.march.clone()],
            unit: h.usd,
            materiality: Materiality {
                overall: 100_000,
                performance: 75_000,
                clearly_trivial: 1_000,
            },
            report_release_day: None,
            capability_commitment: capability.commitment().unwrap(),
        };
        let mut request = EngagementRequest {
            capability: capability.clone(),
            effective_date: DateDay::from_ymd(2026, 3, 1).unwrap(),
            description: h.seal("engagement control", 75),
            idempotency_key: b"authority-engagement".to_vec(),
        };
        let valid_profile = profile(&h, &capability);
        h.runtime
            .block_on(open_engagement(
                &mut h.db,
                &ctx,
                &h.book,
                valid_profile,
                request.clone(),
            ))
            .unwrap()
            .unwrap();
        request.capability = loss.apply(&mut h, &issuer, &capability);
        let unauthorized_profile = profile(&h, &request.capability);
        // The authority records remain valid. Only the protected BookSpec
        // is damaged, so admission must refuse before decoding its unit.
        corrupt_control_payload(&mut h, book_root());
        let valid = human(BOB, &["produce"]);
        let valid_profile = profile(&h, &valid);
        assert!(
            h.runtime
                .block_on(open_engagement(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    valid_profile,
                    EngagementRequest {
                        capability: valid,
                        ..request.clone()
                    },
                ))
                .is_err(),
            "a current principal reaches the damaged book specification",
        );
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        control_refusal(
            h.runtime.block_on(open_engagement(
                &mut h.db,
                &ctx,
                &h.book,
                unauthorized_profile,
                request,
            )),
            loss,
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn head_hold_retries_require_current_issuance_ancestry_before_decoding() {
    use fa_journal::legal_hold::{HoldReach, LegalHoldRequest, place_legal_hold};

    for loss in ControlAuthorityLoss::ALL {
        let mut h = harness();
        let (issuer, capability) = control_authority(&mut h);
        let ctx = h.ctx();
        let request = LegalHoldRequest {
            principal: capability.holder(),
            reach: HoldReach::ThroughHead,
            authority: h.evidence[0].document_oid,
            effective_date: DateDay::from_ymd(2026, 3, 1).unwrap(),
            idempotency_key: b"authority-hold".to_vec(),
            description: h.seal("hold control", 76),
        };
        let mut hold = None;
        for already_recorded in [false, true] {
            let placed = h
                .runtime
                .block_on(place_legal_hold(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    &capability,
                    request.clone(),
                ))
                .unwrap()
                .unwrap();
            assert_eq!(placed.already_recorded, already_recorded);
            if let Some(hold) = hold {
                assert_eq!(placed.hold, hold);
            } else {
                hold = Some(placed.hold);
            }
        }
        let capability = loss.apply(&mut h, &issuer, &capability);
        corrupt_control_payload(&mut h, hold.unwrap());
        assert!(
            h.runtime
                .block_on(place_legal_hold(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    &human(ALICE, &["hold"]),
                    request.clone(),
                ))
                .is_err(),
            "a separately authorized holder reaches the corrupt hold on an exact retry",
        );
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let expected = control_refusal(
            h.runtime.block_on(place_legal_hold(
                &mut h.db,
                &ctx,
                &h.book,
                &capability,
                request.clone(),
            )),
            loss,
        );
        assert_eq!(
            control_refusal(
                h.runtime.block_on(place_legal_hold(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    &capability,
                    LegalHoldRequest {
                        idempotency_key: b"absent-hold".to_vec(),
                        ..request
                    },
                )),
                loss,
            ),
            expected,
            "current authority is required before distinguishing a recorded hold from a new one",
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}
