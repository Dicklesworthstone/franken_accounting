//! Steward in the kernel (bead fa-llx, plan §14, FA-INV-10) against the real
//! in-memory substrate. Posting: an Agent-profile capability never writes
//! trunk; a capability acts only for its holder; ceilings and expiry refuse
//! before any storage read; approvals are recorded objects, point-read at
//! commit, bound to the proposal digest and the security policy epoch, and
//! judged by `sod_policy.toml` (self-approval and duplicates refused, a
//! distinct Human admits, an approval from a superseded epoch is stale).
//! Steward's own writes: approvals are recorded once per approver, proposal
//! and epoch, only under `approve`; a policy activation is a journaled
//! PolicyControl entry under dual control that moves the epoch by
//! compare-and-set, names only the enforced policy, and is idempotent; and a
//! transaction that point-read the epoch loses first-committer-wins to a
//! concurrent activation, while the same interleaving without the witness
//! commits.

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::evidence::{
    Document, EvidenceAttached, SupplementalEvidence, add_document, attach_evidence,
};
use fa_journal::policy::{
    ActivationRequest, ApprovalRequest, Approved, OPEN_END, PolicyActivated, RevocationRequest,
    Revoked, activate_policy, activation_proposal, approval_vid, epoch_witness, record_approval,
    revocation_vid, revoke_capability, security_policy_epoch, steward,
};
use fa_journal::post::read_entry;
use fa_journal::rows::book_root;
use fa_journal::*;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ApprovalRef, ControlPayload, EntryClass, EntryOrigin, EntryPayload, Erasable, EvidenceRef,
    Id128, LegPayload, Oid, SealKey, SymbolTable, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_policy::{Capability, Op, Profile};
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodState, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs, WriteBatch, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

const PREPARER: VId = VId(7);
const ALICE: VId = VId(21);
const BOB: VId = VId(22);
const CAROL: VId = VId(23);
const AGENT: VId = VId(31);

struct Harness {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
    usd: UnitId,
    cash: VId,
    rent: VId,
    march: String,
    /// A real source document recorded at setup; every posting proposal
    /// cites it (FA-INV-05 `evidence-minimum`).
    evidence: Vec<EvidenceRef>,
}

impl Harness {
    fn ctx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn proposal(&self, principal: VId, cents: i128, key: &[u8], class: EntryClass) -> EntryPayload {
        let legs = vec![
            LegPayload::simple(Side::Debit, self.rent, Amount::new(self.usd, cents)),
            LegPayload::simple(Side::Credit, self.cash, Amount::new(self.usd, cents)),
        ];
        EntryPayload {
            schema_minor: 0,
            book_id: self.book.book_id,
            branch_id: Id128::TRUNK,
            class,
            effective_date: DateDay::from_ymd(2026, 3, 15).unwrap(),
            document_date: None,
            description: Erasable::seal(
                &"March rent".to_string(),
                None,
                &self.book.seal_key,
                [1; 32],
                [2; 24],
            ),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([1; 32]),
                intent_kind: 1,
            },
            principal_ref: principal,
            session_ref: None,
            evidence: self.evidence.clone(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        }
    }

    fn post(
        &mut self,
        proposal: EntryPayload,
        capability: Capability,
        approvals: Vec<ApprovalRef>,
    ) -> Result<Posted, Refusal> {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        let req = PostRequest {
            proposal,
            approvals,
            plan_certificate: None,
            capability,
        };
        self.runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .expect("kernel")
    }

    fn transition(&mut self, t: PeriodTransition, key: &[u8]) {
        self.transition_with(t, key, &period_cap(), &[])
            .expect("transition");
    }

    fn period_description(&self) -> Erasable<String> {
        Erasable::seal(
            &"period".to_string(),
            None,
            &self.book.seal_key,
            [3; 32],
            [4; 24],
        )
    }

    /// The exact PeriodControl proposal a March transition by the preparer
    /// commits; approvers approve its digest.
    fn period_proposal(&self, from: PeriodState, to: PeriodState, key: &[u8]) -> EntryPayload {
        transition_proposal(
            &self.book,
            &self.march,
            from,
            to,
            PREPARER,
            1,
            DateDay::from_ymd(2026, 3, 1).unwrap(),
            key,
            self.period_description(),
        )
    }

    fn transition_with(
        &mut self,
        t: PeriodTransition,
        key: &[u8],
        capability: &Capability,
        approvals: &[ApprovalRef],
    ) -> Result<Transitioned, Refusal> {
        let ctx = self.ctx();
        let description = self.period_description();
        let db = &mut self.db;
        let book = &self.book;
        let code = self.march.clone();
        let day = DateDay::from_ymd(2026, 3, 1).unwrap();
        self.runtime
            .block_on(async move {
                transition_period(
                    db,
                    &ctx,
                    book,
                    &code,
                    t,
                    PREPARER,
                    1,
                    day,
                    key,
                    description,
                    capability,
                    approvals,
                )
                .await
            })
            .expect("kernel")
    }

    fn revoke(
        &mut self,
        issuer: &Capability,
        revoked: &Capability,
        key: &[u8],
    ) -> Result<Revoked, Refusal> {
        let ctx = self.ctx();
        let req = RevocationRequest {
            capability: issuer.clone(),
            revoked: revoked.commitment().unwrap(),
            effective_date: DateDay::from_ymd(2026, 3, 1).unwrap(),
            idempotency_key: key.to_vec(),
            description: Erasable::seal(
                &"revoke".to_string(),
                None,
                &self.book.seal_key,
                [5; 32],
                [6; 24],
            ),
        };
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { revoke_capability(db, &ctx, book, req).await })
            .expect("kernel")
    }

    fn march_state(&self) -> PeriodState {
        PeriodRow::decode(
            &self
                .db
                .vertex(fa_model::period_vid("cal", &self.march))
                .unwrap()
                .expect("period row"),
        )
        .unwrap()
        .state
    }

    fn close_march(&mut self) {
        self.transition(PeriodTransition::SoftClose, b"sc");
        self.transition(PeriodTransition::Close, b"c");
    }

    fn approve(&mut self, approver: VId, digest: [u8; 32]) -> Result<Approved, Refusal> {
        self.approve_with(human(approver, &["approve"]), digest)
    }

    fn approve_with(
        &mut self,
        capability: Capability,
        digest: [u8; 32],
    ) -> Result<Approved, Refusal> {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        let req = ApprovalRequest {
            capability,
            approved_proposal_digest: digest,
            role: 0,
        };
        self.runtime
            .block_on(async move { record_approval(db, &ctx, book, req).await })
            .expect("kernel")
    }

    fn activation(&self, preparer: VId, key: &[u8]) -> EntryPayload {
        activation_proposal(
            &self.book,
            preparer,
            steward().expect("policy").policy_oid,
            DateDay::from_ymd(2026, 3, 1).unwrap(),
            key,
            Erasable::seal(
                &"activate sod policy".to_string(),
                None,
                &self.book.seal_key,
                [3; 32],
                [4; 24],
            ),
        )
    }

    fn activate(
        &mut self,
        proposal: EntryPayload,
        capability: Capability,
        approvals: Vec<ApprovalRef>,
    ) -> Result<PolicyActivated, Refusal> {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        let req = ActivationRequest {
            proposal,
            capability,
            approvals,
        };
        self.runtime
            .block_on(async move { activate_policy(db, &ctx, book, req).await })
            .expect("kernel")
    }

    /// A dual-controlled activation: Bob and Carol approve, the controller commits.
    fn activate_with_dual_control(&mut self, key: &[u8]) -> PolicyActivated {
        let proposal = self.activation(PREPARER, key);
        let digest = proposal.proposal_digest().unwrap();
        let bob = self.approve(BOB, digest).expect("bob approves").approval();
        let carol = self
            .approve(CAROL, digest)
            .expect("carol approves")
            .approval();
        self.activate(proposal, controller(), vec![bob, carol])
            .expect("activated")
    }
}

fn human(principal: VId, ops: &[&str]) -> Capability {
    Capability::embedded(principal, ops).expect("registered ops")
}

fn controller() -> Capability {
    human(PREPARER, &["post", "rule_change"])
}

/// The preparer's period-control capability (`close` and `reopen`).
fn period_cap() -> Capability {
    human(PREPARER, &["close", "reopen"])
}

fn harness() -> Harness {
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
        .expect("open");
    let units = UnitRegistry::with_defaults();
    let usd = units.lookup("USD").unwrap();
    let calendar = FiscalCalendar::monthly("cal", 1, 1).unwrap();
    let book_id = Id128([9; 16]);
    let spec = BookSpec {
        book_id,
        name: "Policy Co".into(),
        base_unit: usd,
        calendar: calendar.clone(),
        time_zone_policy: None,
        entities: Vec::new(),
    };
    let symbols = SymbolTable::compiled();
    runtime
        .block_on(async { create_book(&mut db, &ctx, &spec, &units, &symbols).await })
        .expect("create_book");
    let book = BookContext {
        book_id,
        calendar,
        units,
        seal_key: SealKey([0x11; 32]),
        symbols,
    };
    let leaf = |code: &str, account_type: u8| AccountSpec {
        code: code.into(),
        name: code.into(),
        account_type,
        normal_balance: 0,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(usd),
        parent_code: None,
        limit: None,
    };
    let chart = vec![leaf("1000", 1), leaf("6000", 5)];
    runtime
        .block_on(async {
            install_chart(
                &mut db,
                &ctx,
                &book,
                &chart,
                PREPARER,
                DateDay::from_ymd(2026, 1, 1).unwrap(),
                b"chart-1",
                Erasable::seal(&"chart".to_string(), None, &book.seal_key, [5; 32], [6; 24]),
            )
            .await
        })
        .expect("kernel")
        .expect("chart installs");
    let (_, periods) = runtime
        .block_on(async { create_periods(&mut db, &ctx, &book, 2026).await })
        .expect("periods");
    let march = periods
        .iter()
        .find(|p| {
            p.contains(DateDay::from_ymd(2026, 3, 15).unwrap()) && p.kind == PeriodKind::Normal
        })
        .expect("march")
        .code
        .clone();
    let mut h = Harness {
        runtime,
        root,
        db,
        cash: account_vid(book_id, "1000"),
        rent: account_vid(book_id, "6000"),
        book,
        usd,
        march,
        evidence: Vec::new(),
    };
    let source = Document {
        book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PREPARER,
        bytes: b"INVOICE 2026-0315 Policy Co: March rent (fixture source document)".to_vec(),
    };
    let cited = source.evidence_ref(1);
    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        h.runtime
            .block_on(async move { add_document(db, &ctx, book, &source).await })
            .expect("kernel")
            .expect("document admitted");
    }
    h.evidence = vec![cited];
    h.transition(PeriodTransition::Open, b"open-march");
    h
}

// ---------------------------------------------------------------------------
// Posting under Steward (post.rs steps 1a, 3', 5', 5'')
// ---------------------------------------------------------------------------

#[test]
fn an_agent_profile_capability_never_writes_trunk_and_its_refusal_cites_fa_s7x() {
    let mut h = harness();
    let agent = Capability::new(AGENT, Profile::Agent, &[Op::Read, Op::Post], PREPARER)
        .expect("an agent may hold post");
    let proposal = h.proposal(AGENT, 5_000, b"agent-1", EntryClass::ORIGINAL);
    let vid = fa_model::entry_vid(h.book.book_id, &AGENT.0.to_le_bytes(), b"agent-1");
    let head = h.db.frontier().unwrap();
    let r = h.post(proposal, agent, Vec::new()).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-013", exit::SAFETY));
    assert!(r.cite.contains("fa-s7x"), "{}", r.cite);
    assert!(r.fix.contains("Human"), "{}", r.fix);
    assert!(r.cite.contains("Agent"), "{}", r.cite);
    assert!(h.db.vertex(vid).unwrap().is_none(), "nothing was written");
    assert_eq!(h.db.frontier().unwrap(), head);
    // The same intent from a Human principal posts.
    let proposal = h.proposal(PREPARER, 5_000, b"human-1", EntryClass::ORIGINAL);
    assert!(matches!(
        h.post(proposal, human(PREPARER, &["post"]), Vec::new()),
        Ok(Posted::Committed { .. })
    ));
}

#[test]
fn a_capability_authorizes_only_its_holder_and_refusals_precede_any_read() {
    let mut h = harness();
    // Another principal's capability.
    let proposal = h.proposal(PREPARER, 5_000, b"x-1", EntryClass::ORIGINAL);
    let r = h
        .post(proposal, human(ALICE, &["post"]), Vec::new())
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-011", exit::SAFETY));
    assert!(r.message.contains("held by principal"), "{}", r.message);
    // No `post`.
    let proposal = h.proposal(PREPARER, 5_000, b"x-2", EntryClass::ORIGINAL);
    let r = h
        .post(proposal, human(PREPARER, &["read"]), Vec::new())
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-011");
    // A ceiling refuses from the payload alone: the leg names an account the
    // book does not have, and the ceiling refusal still wins, so nothing was read.
    let mut proposal = h.proposal(PREPARER, 12_000, b"x-3", EntryClass::ORIGINAL);
    proposal.legs[0].account_ref = account_vid(h.book.book_id, "9999");
    let capped = human(PREPARER, &["post"])
        .with_ceiling(h.usd, 10_000)
        .unwrap();
    let r = h.post(proposal, capped.clone(), Vec::new()).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-015", exit::SAFETY));
    assert!(r.message.contains("ceiling 10000"), "{}", r.message);
    // Under the ceiling the same unknown account is the account refusal.
    let mut small = h.proposal(PREPARER, 9_000, b"x-4", EntryClass::ORIGINAL);
    small.legs[0].account_ref = account_vid(h.book.book_id, "9999");
    assert_eq!(
        h.post(small, capped, Vec::new()).unwrap_err().code,
        "FA-REF-004"
    );
}

#[test]
fn expiry_is_evaluated_at_the_admission_point() {
    let mut h = harness();
    let head = h.db.frontier().unwrap();
    let proposal = h.proposal(PREPARER, 5_000, b"e-1", EntryClass::ORIGINAL);
    let expired = human(PREPARER, &["post"]).expiring_at(head);
    let r = h.post(proposal.clone(), expired, Vec::new()).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-014", exit::SAFETY));
    let live = human(PREPARER, &["post"]).expiring_at(CommitSeq(head.0 + 1));
    let posted = h
        .post(proposal, live.clone(), Vec::new())
        .expect("admitted");
    assert!(posted.recorded_at() > head);
    // The bound has now passed: the head moved to the commit it authorized.
    let next = h.proposal(PREPARER, 5_000, b"e-2", EntryClass::ORIGINAL);
    assert_eq!(
        h.post(next, live, Vec::new()).unwrap_err().code,
        "FA-REF-014"
    );
}

#[test]
fn self_approval_is_refused_and_a_distinct_human_approval_admits() {
    let mut h = harness();
    h.close_march();
    let cap = human(PREPARER, &["post", "post_closed"]);
    let adj = h.proposal(PREPARER, 7_500, b"adj-1", EntryClass::ADJUSTING);
    let digest = adj.proposal_digest().unwrap();

    // Adjusting in a Closed period needs one approval (Appendix C).
    let r = h.post(adj.clone(), cap.clone(), Vec::new()).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-012", exit::SAFETY));
    assert_eq!(r.cite, "sod_policy.toml#adjusting-closed");

    // A fabricated reference is not an approval.
    let forged = ApprovalRef {
        approval_vid: VId(0xfeed),
        approved_digest: digest,
    };
    let r = h.post(adj.clone(), cap.clone(), vec![forged]).unwrap_err();
    assert_eq!(r.code, "FA-REF-017");

    // The preparer approving its own entry.
    let own = h.approve(PREPARER, digest).expect("recorded").approval();
    let r = h.post(adj.clone(), cap.clone(), vec![own]).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-008", exit::SAFETY));
    assert!(r.message.contains("cannot approve"), "{}", r.message);
    assert_eq!(r.cite, "sod_policy.toml#adjusting-closed");

    // An approval of a different proposal does not transfer, relabelled or not.
    let other = h.proposal(PREPARER, 7_501, b"adj-other", EntryClass::ADJUSTING);
    let elsewhere = h
        .approve(ALICE, other.proposal_digest().unwrap())
        .expect("recorded")
        .approval();
    let relabelled = ApprovalRef {
        approved_digest: digest,
        ..elsewhere
    };
    for cited in [elsewhere, relabelled] {
        let r = h.post(adj.clone(), cap.clone(), vec![cited]).unwrap_err();
        assert_eq!(r.code, "FA-REF-016", "{cited:?}");
    }

    // The same approver twice is one approver.
    let alice = h.approve(ALICE, digest).expect("recorded").approval();
    let r = h
        .post(adj.clone(), cap.clone(), vec![alice, alice])
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-008");
    assert!(r.message.contains("more than once"), "{}", r.message);

    // A distinct Human approver: admitted, and the transcript is in the envelope.
    let posted = h
        .post(adj, cap, vec![alice])
        .expect("admitted with a distinct approver");
    let (entry, _) = read_entry(&h.db, posted.entry_ref().vid).unwrap().unwrap();
    assert_eq!(entry.approvals, vec![alice]);
    assert_eq!(entry.proposal_digest, digest);
}

#[test]
fn approvals_attached_where_none_is_required_are_still_judged() {
    let mut h = harness();
    let orig = h.proposal(PREPARER, 5_000, b"o-1", EntryClass::ORIGINAL);
    let own = h
        .approve(PREPARER, orig.proposal_digest().unwrap())
        .expect("recorded")
        .approval();
    let r = h
        .post(orig.clone(), human(PREPARER, &["post"]), vec![own])
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-008");
    assert_eq!(r.cite, "sod_policy.toml#default");
    assert!(matches!(
        h.post(orig, human(PREPARER, &["post"]), Vec::new()),
        Ok(Posted::Committed { .. })
    ));
}

#[test]
fn a_post_reads_the_current_epoch_so_an_earlier_approval_is_stale() {
    let mut h = harness();
    h.close_march();
    let cap = human(PREPARER, &["post", "post_closed"]);
    let adj = h.proposal(PREPARER, 7_500, b"adj-stale", EntryClass::ADJUSTING);
    let digest = adj.proposal_digest().unwrap();
    let before = h.approve(ALICE, digest).unwrap().approval();
    h.activate_with_dual_control(b"policy-1");
    let r = h.post(adj.clone(), cap.clone(), vec![before]).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-022", exit::CONFLICT));
    assert!(
        r.message.contains("epoch 0") && r.message.contains("epoch 1"),
        "{}",
        r.message
    );
    let after = h.approve(ALICE, digest).unwrap().approval();
    assert_ne!(after.approval_vid, before.approval_vid);
    assert!(matches!(
        h.post(adj, cap, vec![after]),
        Ok(Posted::Committed { .. })
    ));
}

// ---------------------------------------------------------------------------
// Steward's own writes: approvals and policy activation
// ---------------------------------------------------------------------------

#[test]
fn approvals_are_objects_recorded_once_per_approver_proposal_and_epoch() {
    let mut h = harness();
    let digest = [0x42; 32];
    let first = h.approve(ALICE, digest).expect("recorded");
    assert!(
        matches!(
            first,
            Approved::Recorded {
                security_policy_epoch: 0,
                ..
            }
        ),
        "{first:?}"
    );
    let (approval, recorded_at) = (first.approval(), first.recorded_at());
    assert_eq!(
        approval.approval_vid,
        approval_vid(h.book.book_id, ALICE, &digest, 0)
    );
    assert_eq!(approval.approved_digest, digest);
    let row =
        h.db.vertex(approval.approval_vid)
            .unwrap()
            .expect("approval row");
    assert_eq!(row.labels, vec![label::APPROVAL]);
    assert_eq!(row.created_at, recorded_at);
    // The payload is the fa:approval:v1 object naming the approver and epoch.
    let payload = row
        .props
        .iter()
        .find(|(k, _)| *k == property::FA_PAYLOAD)
        .map(|(_, v)| v.clone());
    let Some(CanonicalScalar::Bytes(b)) = payload else {
        assert!(payload.is_some(), "approval payload missing");
        return;
    };
    let decoded = fa_policy::Approval::decode(b.as_slice()).unwrap();
    assert_eq!(
        (
            decoded.principal,
            decoded.profile,
            decoded.op,
            decoded.security_policy_epoch
        ),
        (ALICE, Profile::Human, Op::Approve, 0)
    );
    assert_eq!(
        decoded.capability_commitment,
        human(ALICE, &["approve"]).commitment().unwrap()
    );
    // The identical approval again is the recorded outcome; nothing is written.
    let head = h.db.frontier().unwrap();
    assert_eq!(
        h.approve(ALICE, digest).expect("idempotent"),
        Approved::AlreadyRecorded {
            approval,
            recorded_at
        }
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    // The same approver under a different capability at the same epoch is a
    // conflict, never a second approval.
    let r = h
        .approve_with(human(ALICE, &["approve", "verify"]), digest)
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-032", exit::CONFLICT));
    // A capability without `approve` records nothing.
    let r = h.approve_with(human(BOB, &["post"]), digest).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-011", exit::SAFETY));
    assert!(
        h.db.vertex(approval_vid(h.book.book_id, BOB, &digest, 0))
            .unwrap()
            .is_none()
    );
    // An expired capability records nothing either.
    let stale = human(BOB, &["approve"]).expiring_at(h.db.frontier().unwrap());
    let r = h.approve_with(stale, digest).unwrap_err();
    assert_eq!(r.code, "FA-REF-014");
    // No Agent- or System-profile capability can hold `approve` at all.
    assert!(Capability::new(AGENT, Profile::Agent, &[Op::Approve], PREPARER).is_err());
    assert!(Capability::new(AGENT, Profile::System, &[Op::Approve], PREPARER).is_err());
}

#[test]
fn policy_activation_is_a_dual_controlled_journaled_control_that_moves_the_epoch() {
    let mut h = harness();
    assert_eq!(security_policy_epoch(&h.db).unwrap(), 0);
    let proposal = h.activation(PREPARER, b"policy-1");
    let digest = proposal.proposal_digest().unwrap();

    // The capability must be the preparer's, and it needs rule_change.
    let r = h
        .activate(proposal.clone(), human(ALICE, &["rule_change"]), Vec::new())
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-011", exit::SAFETY));
    assert!(r.message.contains("held by principal"), "{}", r.message);
    let r = h
        .activate(proposal.clone(), human(PREPARER, &["post"]), Vec::new())
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-011", exit::SAFETY));
    assert!(r.message.contains("rule_change"), "{}", r.message);
    // An Agent can never activate a policy on trunk.
    let agent = Capability::new(AGENT, Profile::Agent, &[Op::Post], PREPARER).unwrap();
    let r = h
        .activate(h.activation(AGENT, b"policy-agent"), agent, Vec::new())
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-013");
    assert!(r.cite.contains("fa-s7x"), "{}", r.cite);
    assert!(r.fix.contains("Human"), "{}", r.fix);

    // Two approvers (Appendix C, policy-activate).
    let bob = h.approve(BOB, digest).unwrap().approval();
    let r = h
        .activate(proposal.clone(), controller(), vec![bob])
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-012", exit::SAFETY));
    assert_eq!(r.cite, "sod_policy.toml#policy-activate");
    // The preparer approving its own activation.
    let own = h.approve(PREPARER, digest).unwrap().approval();
    let r = h
        .activate(proposal.clone(), controller(), vec![bob, own])
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-008", exit::SAFETY));
    assert!(r.message.contains("cannot approve"), "{}", r.message);
    // The same approver twice is one approver.
    let r = h
        .activate(proposal.clone(), controller(), vec![bob, bob])
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-008");
    assert!(r.message.contains("more than once"), "{}", r.message);
    // A fabricated reference is not an approval.
    let forged = ApprovalRef {
        approval_vid: VId(0xfeed),
        approved_digest: digest,
    };
    let r = h
        .activate(proposal.clone(), controller(), vec![bob, forged])
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-017");
    assert_eq!(security_policy_epoch(&h.db).unwrap(), 0, "nothing moved");

    // Bob and Carol: activated, journaled, epoch 0 → 1.
    let carol = h.approve(CAROL, digest).unwrap().approval();
    let done = h
        .activate(proposal.clone(), controller(), vec![bob, carol])
        .expect("activated");
    assert_eq!((done.from_epoch, done.to_epoch), (0, 1));
    assert_eq!(security_policy_epoch(&h.db).unwrap(), 1);
    let (entry, at) = read_entry(&h.db, done.control_entry)
        .unwrap()
        .expect("control entry");
    assert_eq!(at, done.recorded_at);
    assert_eq!(entry.proposal.class, EntryClass::POLICY_CONTROL);
    assert!(entry.proposal.legs.is_empty());
    assert_eq!(entry.approvals, vec![bob, carol]);
    assert_eq!(entry.proposal_digest, digest);
    assert!(matches!(
        entry.proposal.control,
        Some(ControlPayload::PolicyActivation { policy_oid, .. })
            if policy_oid == Oid(steward().unwrap().policy_oid)
    ));
    let root = h.db.vertex(book_root()).unwrap().unwrap();
    assert!(
        root.props
            .iter()
            .any(|(k, v)| *k == property::SECURITY_POLICY_EPOCH && *v == CanonicalScalar::Int(1))
    );

    // The same activation again is its recorded outcome, not a second epoch
    // (the retry law in detail: an_identical_activation_retry_is_its_recorded_outcome).
    assert!(!done.already_recorded);
    assert_eq!(
        h.activate(proposal, controller(), vec![bob, carol])
            .expect("recorded"),
        PolicyActivated {
            already_recorded: true,
            ..done
        }
    );
    assert_eq!(security_policy_epoch(&h.db).unwrap(), 1);
    // policy-1's approvals do not bind policy-2.
    let again = h.activation(PREPARER, b"policy-2");
    let r = h
        .activate(again.clone(), controller(), vec![bob, carol])
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-016");
    // Approvals of policy-2 recorded at epoch 1 move it to epoch 2; the
    // approval identities carry the epoch they were recorded under.
    let d2 = again.proposal_digest().unwrap();
    let b2 = h.approve(BOB, d2).unwrap().approval();
    assert_eq!(b2.approval_vid, approval_vid(h.book.book_id, BOB, &d2, 1));
    let c2 = h.approve(CAROL, d2).unwrap().approval();
    let done = h.activate(again, controller(), vec![b2, c2]).unwrap();
    assert_eq!((done.from_epoch, done.to_epoch), (1, 2));
}

#[test]
fn an_approval_recorded_before_an_activation_is_stale_after_it() {
    let mut h = harness();
    // Bob and Carol approve policy-2 under epoch 0; policy-1 then moves the
    // epoch, so their approvals no longer authorize policy-2.
    let next = h.activation(PREPARER, b"policy-2");
    let digest = next.proposal_digest().unwrap();
    let bob = h.approve(BOB, digest).unwrap().approval();
    let carol = h.approve(CAROL, digest).unwrap().approval();
    h.activate_with_dual_control(b"policy-1");
    let r = h
        .activate(next.clone(), controller(), vec![bob, carol])
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-022", exit::CONFLICT));
    assert!(
        r.message.contains("epoch 0") && r.message.contains("epoch 1"),
        "{}",
        r.message
    );
    // Re-approval under the current epoch is a new approval with a new identity.
    let bob1 = h.approve(BOB, digest).unwrap().approval();
    let carol1 = h.approve(CAROL, digest).unwrap().approval();
    assert_ne!(bob1.approval_vid, bob.approval_vid);
    let done = h.activate(next, controller(), vec![bob1, carol1]).unwrap();
    assert_eq!((done.from_epoch, done.to_epoch), (1, 2));
}

#[test]
fn a_transaction_that_witnessed_the_epoch_loses_to_a_concurrent_activation() {
    let mut h = harness();
    // Open a transaction, optionally point-read the epoch, let another writer
    // activate a policy, then ask the substrate to advance the transaction's
    // snapshot: that validates every observation it made (FG-LAW-FCW-01).
    let probe = |h: &mut Harness, witness: bool| -> Result<CommitSeq, WriteTxnError> {
        let ctx = h.ctx();
        let txn_cx = ctx.txn();
        let mut txn = h.db.begin(&txn_cx).expect("begin");
        if witness {
            assert_eq!(
                epoch_witness(&txn, &h.db).unwrap(),
                security_policy_epoch(&h.db).unwrap()
            );
        }
        let key: &[u8] = if witness { b"race-w" } else { b"race-n" };
        h.activate_with_dual_control(key);
        // A stale workspace cannot stage at all.
        let mut batch = WriteBatch::new(relation::IN_BOOK);
        batch.create_vertex(VId(0xabc0), vec![label::FINDING], Vec::new());
        assert!(
            matches!(
                txn.write(&mut h.db, batch),
                Err(WriteTxnError::SnapshotAdvanced { .. })
            ),
            "staging on a stale snapshot is refused"
        );
        let refreshed = txn.refresh_snapshot(&h.db, &txn_cx);
        txn.abort();
        refreshed
    };
    // Control: without the epoch witness the snapshot advances cleanly.
    let advanced = probe(&mut h, false);
    assert!(advanced.is_ok(), "{advanced:?}");
    // With it, the activation is the first committer and this transaction loses.
    let err = probe(&mut h, true).unwrap_err();
    assert!(
        matches!(
            err,
            WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { .. })
        ),
        "{err:?}"
    );
}

#[test]
fn only_the_enforced_policy_activates_and_only_from_its_date_onward() {
    let mut h = harness();
    // A fully approved activation of rules this build does not embed.
    let mut foreign = h.activation(PREPARER, b"foreign");
    if let Some(ControlPayload::PolicyActivation { policy_oid, .. }) = &mut foreign.control {
        *policy_oid = Oid([0xab; 32]);
    }
    let digest = foreign.proposal_digest().unwrap();
    let bob = h.approve(BOB, digest).unwrap().approval();
    let carol = h.approve(CAROL, digest).unwrap().approval();
    let head = h.db.frontier().unwrap();
    let r = h
        .activate(foreign.clone(), controller(), vec![bob, carol])
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-019", exit::SAFETY));
    assert!(r.message.contains(&"ab".repeat(32)), "{}", r.message);
    assert_eq!(h.db.frontier().unwrap(), head, "nothing was written");
    assert_eq!(security_policy_epoch(&h.db).unwrap(), 0);
    let foreign_vid = fa_model::entry_vid(h.book.book_id, &PREPARER.0.to_le_bytes(), b"foreign");
    assert!(h.db.vertex(foreign_vid).unwrap().is_none());

    // A bounded interval claims a date scoping the kernel does not enforce.
    let mut bounded = h.activation(PREPARER, b"bounded");
    if let Some(ControlPayload::PolicyActivation { effective_to, .. }) = &mut bounded.control {
        assert_eq!(*effective_to, OPEN_END);
        *effective_to = DateDay::from_ymd(2027, 1, 1).unwrap();
    }
    let r = h.activate(bounded, controller(), Vec::new()).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-100", exit::USAGE));
    assert!(r.message.contains("OPEN_END"), "{}", r.message);
    // So does an interval that starts anywhere but the activation's own date.
    let mut shifted = h.activation(PREPARER, b"shifted");
    if let Some(ControlPayload::PolicyActivation { effective_from, .. }) = &mut shifted.control {
        *effective_from = DateDay::from_ymd(2026, 1, 1).unwrap();
    }
    let r = h.activate(shifted, controller(), Vec::new()).unwrap_err();
    assert_eq!(r.code, "FA-REF-100");
    assert_eq!(h.db.frontier().unwrap(), head);

    // The embedded policy, over the same approvers, still activates.
    let done = h.activate_with_dual_control(b"embedded");
    assert_eq!((done.from_epoch, done.to_epoch), (0, 1));
}

#[test]
fn an_identical_activation_retry_is_its_recorded_outcome() {
    let mut h = harness();
    let proposal = h.activation(PREPARER, b"policy-1");
    let digest = proposal.proposal_digest().unwrap();
    let bob = h.approve(BOB, digest).unwrap().approval();
    let carol = h.approve(CAROL, digest).unwrap().approval();
    let first = h
        .activate(proposal.clone(), controller(), vec![bob, carol])
        .expect("activated");
    assert_eq!((first.from_epoch, first.to_epoch), (0, 1));
    let recorded = PolicyActivated {
        already_recorded: true,
        ..first.clone()
    };
    let head = h.db.frontier().unwrap();

    // The identical retry is the recorded outcome, although its approvals
    // were recorded under epoch 0 and the book is now at epoch 1: they were
    // judged at the activation's own commit and are not judged again.
    assert_eq!(
        h.activate(proposal.clone(), controller(), vec![bob, carol]),
        Ok(recorded.clone())
    );
    // Approvals are envelope, not request: a retry citing none is the same request.
    assert_eq!(
        h.activate(proposal.clone(), controller(), Vec::new()),
        Ok(recorded.clone())
    );
    // A semantically identical retry (the erasable description re-sealed with
    // fresh salt, so different bytes) is the same request too.
    let mut resealed = proposal.clone();
    resealed.description = Erasable::seal(
        &"activate sod policy".to_string(),
        None,
        &h.book.seal_key,
        [9; 32],
        [8; 24],
    );
    assert_ne!(resealed.proposal_digest().unwrap(), digest);
    assert_eq!(
        h.activate(resealed, controller(), Vec::new()),
        Ok(recorded.clone())
    );
    assert_eq!(
        h.db.frontier().unwrap(),
        head,
        "a recorded outcome writes nothing"
    );
    assert_eq!(security_policy_epoch(&h.db).unwrap(), 1);

    // A different request under the same key is a conflict, never a second epoch.
    let mut changed = h.activation(PREPARER, b"policy-1");
    changed.effective_date = DateDay::from_ymd(2026, 4, 1).unwrap();
    if let Some(ControlPayload::PolicyActivation { effective_from, .. }) = &mut changed.control {
        *effective_from = changed.effective_date;
    }
    let r = h.activate(changed, controller(), Vec::new()).unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-032", exit::CONFLICT));
    let mut renamed = proposal;
    renamed.description = Erasable::seal(
        &"a different description".to_string(),
        None,
        &h.book.seal_key,
        [9; 32],
        [8; 24],
    );
    let r = h.activate(renamed, controller(), Vec::new()).unwrap_err();
    assert_eq!(r.code, "FA-REF-032");
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(security_policy_epoch(&h.db).unwrap(), 1);
}

// ---------------------------------------------------------------------------
// PeriodControl under Steward (period.rs: admission before any read, the
// revocation and epoch witnesses, SoD keyed on (PeriodControl, from, t))
// ---------------------------------------------------------------------------

#[test]
fn period_control_is_admitted_under_close_and_a_lock_needs_a_distinct_human_approver() {
    let mut h = harness();
    assert_eq!(
        h.march_state(),
        PeriodState::Open,
        "opened under `close` in setup"
    );
    h.transition(PeriodTransition::SoftClose, b"sc");
    h.transition(PeriodTransition::Close, b"c");
    assert_eq!(h.march_state(), PeriodState::Closed);

    let lock = h.period_proposal(PeriodState::Closed, PeriodState::Locked, b"lock");
    let digest = lock.proposal_digest().unwrap();
    // Lock needs one approval (sod_policy.toml period-lock).
    let r = h
        .transition_with(PeriodTransition::Lock, b"lock", &period_cap(), &[])
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-012", exit::SAFETY));
    assert_eq!(r.cite, "sod_policy.toml#period-lock");
    // The preparer approving its own lock.
    let own = h.approve(PREPARER, digest).unwrap().approval();
    let r = h
        .transition_with(PeriodTransition::Lock, b"lock", &period_cap(), &[own])
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-008", exit::SAFETY));
    // An approval of a different transition does not transfer.
    let other = h
        .period_proposal(PeriodState::Closed, PeriodState::Locked, b"other-lock")
        .proposal_digest()
        .unwrap();
    let elsewhere = h.approve(ALICE, other).unwrap().approval();
    let r = h
        .transition_with(PeriodTransition::Lock, b"lock", &period_cap(), &[elsewhere])
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-016");
    assert_eq!(h.march_state(), PeriodState::Closed, "nothing moved");
    // A distinct Human approver over this exact proposal: locked, and the
    // transcript rides in the control entry's envelope.
    let alice = h.approve(ALICE, digest).unwrap().approval();
    let done = h
        .transition_with(PeriodTransition::Lock, b"lock", &period_cap(), &[alice])
        .expect("locked under dual control");
    assert_eq!(
        (done.from, done.to),
        (PeriodState::Closed, PeriodState::Locked)
    );
    let (entry, _) = read_entry(&h.db, done.control_entry).unwrap().unwrap();
    assert_eq!(entry.approvals, vec![alice]);
    assert_eq!(entry.proposal_digest, digest);
}

#[test]
fn close_without_close_and_reopen_without_reopen_are_refused_before_any_read() {
    let mut h = harness();
    let head = h.db.frontier().unwrap();
    let poster = human(PREPARER, &["post"]);
    let r = h
        .transition_with(PeriodTransition::Close, b"c", &poster, &[])
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-011", exit::SAFETY));
    assert!(r.message.contains("`close`"), "{}", r.message);
    // Admission precedes observation: a period that does not exist is still
    // the capability refusal, not the unknown-period one.
    let ctx = h.ctx();
    let description = h.period_description();
    let db = &mut h.db;
    let book = &h.book;
    let unknown = h
        .runtime
        .block_on(async move {
            transition_period(
                db,
                &ctx,
                book,
                "FY2099-P01",
                PeriodTransition::Close,
                PREPARER,
                1,
                DateDay::from_ymd(2026, 3, 1).unwrap(),
                b"nowhere",
                description,
                &poster,
                &[],
            )
            .await
        })
        .expect("kernel")
        .unwrap_err();
    assert_eq!(unknown.code, "FA-REF-011");
    // Reopen needs `reopen`, which `close` alone does not give.
    h.transition(PeriodTransition::SoftClose, b"sc");
    let closer = human(PREPARER, &["close"]);
    let r = h
        .transition_with(
            PeriodTransition::Reopen {
                to: PeriodState::Open,
            },
            b"reopen",
            &closer,
            &[],
        )
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-011");
    assert!(r.message.contains("`reopen`"), "{}", r.message);
    // Another principal's capability, and an Agent's, are refused too.
    let r = h
        .transition_with(
            PeriodTransition::Close,
            b"c2",
            &human(ALICE, &["close"]),
            &[],
        )
        .unwrap_err();
    assert!(r.message.contains("held by principal"), "{}", r.message);
    let agent = Capability::new(PREPARER, Profile::Agent, &[Op::Read], AGENT).unwrap();
    assert_eq!(
        h.transition_with(PeriodTransition::Close, b"c3", &agent, &[])
            .unwrap_err()
            .code,
        "FA-REF-013"
    );
    assert_eq!(h.march_state(), PeriodState::SoftClosed);
    assert!(
        h.db.frontier().unwrap() > head,
        "only the SoftClose committed"
    );
}

#[test]
fn expired_out_of_scope_and_revoked_capabilities_cannot_transition_post_or_approve() {
    let mut h = harness();
    // Expired at the admission point.
    let expired = period_cap().expiring_at(h.db.frontier().unwrap());
    let r = h
        .transition_with(PeriodTransition::SoftClose, b"sc", &expired, &[])
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-014", exit::SAFETY));
    // Confined to another book.
    let elsewhere = period_cap().for_books(&[Id128([0xee; 16])]).unwrap();
    let r = h
        .transition_with(PeriodTransition::SoftClose, b"sc", &elsewhere, &[])
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-011");
    assert!(r.message.contains("`books` caveat"), "{}", r.message);
    // The same caveat naming this book admits.
    let here = period_cap().for_books(&[h.book.book_id]).unwrap();
    h.transition_with(PeriodTransition::SoftClose, b"sc", &here, &[])
        .expect("in scope");

    // Revocation: only `issue_capability` revokes, and it is journaled once.
    let doomed = period_cap();
    let r = h
        .revoke(&human(ALICE, &["approve"]), &doomed, b"rv-0")
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-011");
    let issuer = human(ALICE, &["issue_capability"]);
    let done = h.revoke(&issuer, &doomed, b"rv-1").expect("revoked");
    assert!(!done.already_recorded);
    assert_eq!(
        done.control_entry,
        revocation_vid(h.book.book_id, &doomed.commitment().unwrap())
    );
    let (entry, _) = read_entry(&h.db, done.control_entry).unwrap().unwrap();
    assert_eq!(entry.proposal.class, EntryClass::POLICY_CONTROL);
    assert!(matches!(
        entry.proposal.control,
        Some(ControlPayload::CapabilityEvent { kind: 1, .. })
    ));
    assert!(
        h.revoke(&issuer, &doomed, b"rv-2")
            .unwrap()
            .already_recorded
    );
    // The revoked token can no longer transition, post, or approve.
    let r = h
        .transition_with(PeriodTransition::Close, b"c", &doomed, &[])
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-023", exit::SAFETY));
    let doomed_poster = human(PREPARER, &["post"]);
    h.revoke(&issuer, &doomed_poster, b"rv-3").unwrap();
    let orig = h.proposal(PREPARER, 5_000, b"after-revoke", EntryClass::ORIGINAL);
    assert_eq!(
        h.post(orig, doomed_poster, Vec::new()).unwrap_err().code,
        "FA-REF-023"
    );
    let doomed_approver = human(BOB, &["approve"]);
    h.revoke(&issuer, &doomed_approver, b"rv-4").unwrap();
    assert_eq!(
        h.approve_with(doomed_approver, [0x11; 32])
            .unwrap_err()
            .code,
        "FA-REF-023"
    );
    // A different capability of the same principal is unaffected.
    h.transition_with(
        PeriodTransition::Close,
        b"c",
        &human(PREPARER, &["close", "reopen", "read"]),
        &[],
    )
    .expect("an unrevoked capability still closes");
}

/// `vid(revocation) = H("fa:vid:capability-revocation:v1" ‖ book ‖
/// commitment)`, low 16 bytes little-endian: a fixed vector, so the identity
/// a revocation is found at can never drift silently.
#[test]
fn the_revocation_identity_is_a_fixed_vector() {
    assert_eq!(
        revocation_vid(Id128([9; 16]), &[0x42; 32]),
        VId(0x6f1e_9e5f_89a7_35a8_f0e4_3225_d409_761e)
    );
    assert_ne!(
        revocation_vid(Id128([9; 16]), &[0x42; 32]),
        revocation_vid(Id128([8; 16]), &[0x42; 32]),
        "the book is bound"
    );
}

#[test]
fn a_lock_approval_from_a_superseded_epoch_is_stale() {
    let mut h = harness();
    h.close_march();
    let digest = h
        .period_proposal(PeriodState::Closed, PeriodState::Locked, b"lock")
        .proposal_digest()
        .unwrap();
    let before = h.approve(ALICE, digest).unwrap().approval();
    h.activate_with_dual_control(b"policy-1");
    let r = h
        .transition_with(PeriodTransition::Lock, b"lock", &period_cap(), &[before])
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-022", exit::CONFLICT));
    let after = h.approve(ALICE, digest).unwrap().approval();
    h.transition_with(PeriodTransition::Lock, b"lock", &period_cap(), &[after])
        .expect("re-approved under the current epoch");
}

#[test]
fn a_soft_closed_reopen_needs_one_approver_and_a_case_bound_reopen_fails_closed() {
    let mut h = harness();
    h.transition(PeriodTransition::SoftClose, b"sc");
    let reopen = PeriodTransition::Reopen {
        to: PeriodState::Open,
    };
    let r = h
        .transition_with(reopen, b"ro", &period_cap(), &[])
        .unwrap_err();
    assert_eq!(r.cite, "sod_policy.toml#period-reopen-softclosed");
    let digest = h
        .period_proposal(PeriodState::SoftClosed, PeriodState::Open, b"ro")
        .proposal_digest()
        .unwrap();
    let alice = h.approve(ALICE, digest).unwrap().approval();
    h.transition_with(reopen, b"ro", &period_cap(), &[alice])
        .expect("reopened under one approver");
    assert_eq!(h.march_state(), PeriodState::Open);
    // A control entry's identity derives from its key: reusing `sc` for the
    // next soft-close is refused before staging, and nothing moves.
    let r = h
        .transition_with(PeriodTransition::SoftClose, b"sc", &period_cap(), &[])
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-100", exit::USAGE));
    assert_eq!(h.march_state(), PeriodState::Open);
    // Closed -> Reopen is case-bound (Appendix C W(reopen, 2, case)): with two
    // distinct Human approvers it still refuses, because no case exists to
    // decide the case_preparer exclusion. Fail closed, never exempt.
    h.transition(PeriodTransition::Close, b"c-after-reopen");
    let digest = h
        .period_proposal(PeriodState::Closed, PeriodState::Open, b"ro-closed")
        .proposal_digest()
        .unwrap();
    let a = h.approve(ALICE, digest).unwrap().approval();
    let b = h.approve(BOB, digest).unwrap().approval();
    let r = h
        .transition_with(reopen, b"ro-closed", &period_cap(), &[a, b])
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-008", exit::SAFETY));
    assert!(r.message.contains("case_preparer"), "{}", r.message);
    assert_eq!(h.march_state(), PeriodState::Closed);
}

// ---------------------------------------------------------------------------
// Revocation on the writes that landed beside the admission slice (fa-bcd)
// ---------------------------------------------------------------------------

/// A refusal of a revoked token: FA-REF-023, exit 7, and nothing written.
fn assert_revoked<T: std::fmt::Debug>(h: &Harness, before: CommitSeq, r: Result<T, Refusal>) {
    let r = r.unwrap_err();
    assert_eq!(
        (r.code, r.exit),
        ("FA-REF-023", exit::SAFETY),
        "{}",
        r.message
    );
    assert_eq!(h.db.frontier().unwrap(), before, "a revoked token wrote");
}

impl Harness {
    fn seal(&self, text: &str, n: u8) -> Erasable<String> {
        Erasable::seal(
            &text.to_string(),
            None,
            &self.book.seal_key,
            [n; 32],
            [n; 24],
        )
    }

    fn tick(&mut self, capability: Capability, ns: u64, key: &[u8]) -> Result<Ticked, Refusal> {
        let ctx = self.ctx();
        let req = TickRequest {
            observed_utc_ns: ns,
            source: fa_journal::sweep::SOURCE_DAEMON_CLOCK,
            monotonic_ok: true,
            principal_ref: PREPARER,
            capability,
            idempotency_key: key.to_vec(),
            description: self.seal("tick", key[key.len() - 1]),
        };
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { record_tick(db, &ctx, book, req).await })
            .expect("kernel")
    }

    /// One expiry batch and one reversal batch under `capability`, run as
    /// the book's System principal.
    fn sweeps(
        &mut self,
        capability: Capability,
    ) -> (
        Result<Option<SweepBatch>, Refusal>,
        Result<Option<ReversalBatch>, Refusal>,
    ) {
        let ctx = self.ctx();
        let req = SweepRequest {
            principal_ref: fa_journal::rows::system_principal(self.book.book_id),
            capability,
            max_batch: 8,
        };
        let db = &mut self.db;
        let book = &self.book;
        self.runtime.block_on(async move {
            let mut describe = |text: &str| {
                Erasable::seal(
                    &text.to_string(),
                    None,
                    &book.seal_key,
                    [0x5d; 32],
                    [0x5d; 24],
                )
            };
            let expiry = sweep_batch(db, &ctx, book, &req, &mut describe)
                .await
                .expect("kernel");
            let reversals = sweep_reversals_batch(db, &ctx, book, &req, &mut describe)
                .await
                .expect("kernel");
            (expiry, reversals)
        })
    }

    fn review(&mut self, capability: Capability, document: Oid) -> Result<Attested, Refusal> {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move {
                record_review(db, &ctx, book, &capability, ALICE, document, Vec::new()).await
            })
            .expect("kernel")
    }

    fn assert_manually(
        &mut self,
        capability: Capability,
        proposal: &EntryPayload,
    ) -> Result<Attested, Refusal> {
        let ctx = self.ctx();
        let statement = self.seal("the bank issues no document for this fee", 0x4a);
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move {
                record_manual_assertion(db, &ctx, book, &capability, proposal, 1, statement).await
            })
            .expect("kernel")
    }

    fn attach(
        &mut self,
        capability: Capability,
        supplement: &SupplementalEvidence,
    ) -> Result<EvidenceAttached, Refusal> {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { attach_evidence(db, &ctx, book, &capability, supplement).await })
            .expect("kernel")
    }
}

/// A revoked token authorizes none of the Steward-checked writes that
/// landed beside the admission slice: a tick, both sweeps (refused before
/// their candidate scans, so even with nothing due a revoked System token
/// learns nothing), a review, a ManualAssertion, and attached evidence each
/// refuse FA-REF-023 and write nothing. Each write then succeeds under
/// another capability of the same principal: the refusal is the
/// revocation's, not the request's.
#[test]
fn a_revoked_capability_cannot_tick_sweep_attest_or_attach_evidence() {
    let mut h = harness();
    let issuer = human(ALICE, &["issue_capability"]);

    // record_tick.
    let ticker = human(PREPARER, &["witness"]);
    h.revoke(&issuer, &ticker, b"rv-tick").expect("revoked");
    let before = h.db.frontier().unwrap();
    let r = h.tick(ticker, 1_000, b"tick-1");
    assert_revoked(&h, before, r);
    assert_eq!(latest_tick(&h.db).unwrap(), None);
    h.tick(human(PREPARER, &["witness", "read"]), 1_000, b"tick-2")
        .expect("an unrevoked capability ticks");

    // sweep_batch and sweep_reversals_batch, as the System principal.
    let system = fa_journal::rows::system_principal(h.book.book_id);
    let sweeper = Capability::new(system, Profile::System, &[Op::Post], system).unwrap();
    h.revoke(&issuer, &sweeper, b"rv-sweep").expect("revoked");
    let before = h.db.frontier().unwrap();
    let (expiry, reversals) = h.sweeps(sweeper);
    assert_revoked(&h, before, expiry);
    assert_revoked(&h, before, reversals);
    let fresh = Capability::new(system, Profile::System, &[Op::Post, Op::Read], system).unwrap();
    let (expiry, reversals) = h.sweeps(fresh);
    assert_eq!(expiry.expect("admitted"), None, "nothing is due");
    assert_eq!(reversals.expect("admitted"), None, "nothing is due");

    // record_review over the setup document, by a reviewer who did not upload it.
    let document = h.evidence[0].document_oid;
    let reviewer = human(ALICE, &["approve"]);
    h.revoke(&issuer, &reviewer, b"rv-review").expect("revoked");
    let before = h.db.frontier().unwrap();
    let r = h.review(reviewer, document);
    assert_revoked(&h, before, r);
    assert!(
        !h.review(human(ALICE, &["approve", "read"]), document)
            .expect("an unrevoked capability reviews")
            .already_recorded
    );

    // record_manual_assertion over an Original with no document.
    let poster = human(PREPARER, &["post"]);
    h.revoke(&issuer, &poster, b"rv-post").expect("revoked");
    let mut bare = h.proposal(PREPARER, 4_200, b"asserted", EntryClass::ORIGINAL);
    bare.evidence.clear();
    let before = h.db.frontier().unwrap();
    let r = h.assert_manually(poster.clone(), &bare);
    assert_revoked(&h, before, r);
    let renewed = human(PREPARER, &["post", "read"]);
    h.assert_manually(renewed.clone(), &bare)
        .expect("an unrevoked capability asserts");

    // attach_evidence to a committed entry, citing a second document.
    let entry_ref = match h
        .post(
            h.proposal(PREPARER, 6_100, b"supported", EntryClass::ORIGINAL),
            controller(),
            Vec::new(),
        )
        .expect("posted")
    {
        Posted::Committed { entry_ref, .. } => Some(entry_ref),
        Posted::AlreadyRecorded { .. } => None,
    }
    .expect("a new entry commits");
    let receipt = Document {
        book_id: h.book.book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PREPARER,
        bytes: b"RECEIPT 2026-0316 Policy Co: March rent paid (fixture supplement)".to_vec(),
    };
    let supplement = SupplementalEvidence {
        book_id: h.book.book_id,
        entry_ref,
        documents: vec![receipt.evidence_ref(1)],
        attached_by: PREPARER,
    };
    {
        let ctx = h.ctx();
        let db = &mut h.db;
        let book = &h.book;
        h.runtime
            .block_on(async move { add_document(db, &ctx, book, &receipt).await })
            .expect("kernel")
            .expect("document admitted");
    }
    let before = h.db.frontier().unwrap();
    let r = h.attach(poster, &supplement);
    assert_revoked(&h, before, r);
    assert!(
        !h.attach(renewed, &supplement)
            .expect("an unrevoked capability attaches")
            .already_recorded
    );
}
