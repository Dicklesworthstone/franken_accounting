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
    Revoked, activate_policy, activation_proposal, admit_reads, approval_vid, epoch_witness,
    record_approval, revocation_vid, revoke_capability, security_policy_epoch, steward,
};
use fa_journal::post::read_entry;
use fa_journal::rows::book_root;
use fa_journal::*;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ApprovalRef, ControlPayload, Disposition, EntryClass, EntryOrigin, EntryPayload, EntryRef,
    Erasable, EvidenceRef, Id128, LegPayload, Oid, Pending, SealKey, Settlement, Supersession,
    SupersessionKind, SymbolTable, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_policy::{Capability, Op, Profile, possession_digest};
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

#[path = "policy/capability_retries.rs"]
mod capability_retries;

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
            &fa_journal::policy::calendar_period(&self.book, &self.march).expect("March"),
            from,
            to,
            PREPARER,
            1,
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
        opening_date: None,
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
                &Capability::embedded(PREPARER, &["schema_change"]).unwrap(),
            )
            .await
        })
        .expect("kernel")
        .expect("chart installs");
    let (_, periods) = runtime
        .block_on(async {
            create_periods(
                &mut db,
                &ctx,
                &book,
                2026,
                PREPARER,
                fa_model::Erasable::seal(
                    &"periods".to_string(),
                    None,
                    &book.seal_key,
                    [1; 32],
                    [2; 24],
                ),
                &fa_journal::Capability::embedded(PREPARER, &["schema_change"]).unwrap(),
            )
            .await
        })
        .expect("periods")
        .expect("admitted");
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

/// fa-ge0y: an entry's provenance closure holds what it was posted with
/// (its cited document, the approval in its envelope, its principal and its
/// intent origin), each with the sequence that recorded it. A supplement
/// attached later joins the closure but leaves the closure as posted, and
/// its digest, unchanged.
#[test]
fn the_provenance_closure_holds_documents_approvals_and_later_supplements() {
    use fa_journal::evidence::{ClosureKind, explain_entry_evidence};
    let mut h = harness();
    h.close_march();
    let adj = h.proposal(PREPARER, 7_500, b"adj-closure", EntryClass::ADJUSTING);
    let digest = adj.proposal_digest().unwrap();
    let alice = h.approve(ALICE, digest).expect("recorded").approval();
    let posted = h
        .post(adj, human(PREPARER, &["post", "post_closed"]), vec![alice])
        .expect("admitted with a distinct approver");
    let entry_ref = posted.entry_ref();
    let explain = |h: &Harness| {
        explain_entry_evidence(&h.db, &h.book, entry_ref.vid)
            .expect("kernel")
            .expect("a committed entry")
    };
    let before = explain(&h);
    let closure = &before.closure;
    let of = |kind| {
        closure
            .members
            .iter()
            .filter(|m| m.kind == kind)
            .cloned()
            .collect::<Vec<_>>()
    };
    let documents = of(ClosureKind::Document);
    assert_eq!(documents.len(), h.evidence.len(), "{closure:?}");
    for (member, cited) in documents.iter().zip(&h.evidence) {
        assert_eq!(member.digest, Some(cited.document_oid.0));
        assert_eq!(member.role, Some(cited.role));
        assert!(
            member
                .recorded_at
                .is_some_and(|seq| seq <= before.recorded_at)
        );
    }
    let approvals = of(ClosureKind::Approval);
    assert_eq!(approvals.len(), 1, "{closure:?}");
    assert_eq!(approvals[0].vid, Some(alice.approval_vid));
    assert!(approvals[0].digest.is_some());
    assert!(
        approvals[0]
            .recorded_at
            .is_some_and(|seq| seq < before.recorded_at)
    );
    let principal = of(ClosureKind::Principal);
    assert_eq!(principal.len(), 1);
    assert_eq!(
        (principal[0].vid, principal[0].recorded_at),
        (Some(PREPARER), None)
    );
    assert_eq!(of(ClosureKind::Origin).len(), 1, "{closure:?}");
    assert!(of(ClosureKind::Supplement).is_empty());
    assert_eq!(
        closure.original_digest, closure.digest,
        "nothing joined after posting"
    );

    let receipt = Document {
        book_id: h.book.book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PREPARER,
        bytes: b"RECEIPT 2026-0330 Policy Co: the adjustment's memo (closure fixture)".to_vec(),
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
    h.attach(human(PREPARER, &["post", "read"]), &supplement)
        .expect("attached");
    let after = explain(&h).closure;
    assert_eq!(
        after.original_digest, closure.original_digest,
        "the closure as posted does not move"
    );
    assert_ne!(after.digest, closure.digest);
    let kinds: Vec<ClosureKind> = after.members.iter().map(|m| m.kind).collect();
    assert!(kinds.contains(&ClosureKind::Supplement), "{after:?}");
    assert!(
        after
            .members
            .iter()
            .any(|m| m.kind == ClosureKind::SupplementDocument
                && m.digest == Some(supplement.documents[0].document_oid.0)),
        "{after:?}"
    );
    assert_eq!(after.members.len(), closure.members.len() + 2);
}

#[test]
fn balancing_approvals_bind_resolved_effects_and_preserve_request_identity() {
    let mut h = harness();
    let limited = AccountSpec {
        code: "6100".into(),
        name: "Limited expense".into(),
        account_type: 5,
        normal_balance: 0,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(h.usd),
        parent_code: None,
        limit: Some(BalanceLimit {
            lower: None,
            upper: Some(40),
            scope: LimitScope::Lifetime,
        }),
    };
    let ctx = h.ctx();
    let description = h.period_description();
    h.runtime
        .block_on(install_chart(
            &mut h.db,
            &ctx,
            &h.book,
            &[limited],
            PREPARER,
            DateDay::from_ymd(2026, 3, 1).unwrap(),
            b"limited-chart",
            description,
            &Capability::embedded(PREPARER, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    h.close_march();
    let cap = human(PREPARER, &["post", "post_closed"]);
    let mut request = h.proposal(PREPARER, 100, b"approved-balancing", EntryClass::ADJUSTING);
    request.legs[0].account_ref = account_vid(h.book.book_id, "6100");
    request.schema_minor = fa_model::entry::EXTENSIONS_MINOR;
    request.extensions.push((
        fa_model::entry::BALANCING_EXTENSION,
        fa_journal::limit::balancing_bytes(0, 100),
    ));
    let requested = h
        .approve(ALICE, request.proposal_digest().unwrap())
        .unwrap()
        .approval();
    let head = h.db.frontier().unwrap();
    let refusal = h
        .post(request.clone(), cap.clone(), vec![requested])
        .expect_err("approval of 100 cannot bind the resolved posting of 40");
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-016", exit::SAFETY));
    assert_eq!(h.db.frontier().unwrap(), head);

    // The complete resolved proposal still records the original requested
    // amount in its extension. Approving it permits the actual clamped post.
    let mut resolved = request.clone();
    for leg in &mut resolved.legs {
        leg.amount.mantissa = 40;
    }
    resolved.unit_totals = EntryPayload::fold_unit_totals(&resolved.legs).unwrap();
    let approved = h
        .approve(ALICE, resolved.proposal_digest().unwrap())
        .unwrap()
        .approval();
    let head = h.db.frontier().unwrap();
    let mut changed = request.clone();
    changed.effective_date = DateDay::from_ymd(2026, 3, 16).unwrap();
    let refusal = h
        .post(changed, cap.clone(), vec![approved])
        .expect_err("changing the approved coordinate still refuses");
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-016", exit::SAFETY));
    assert_eq!(h.db.frontier().unwrap(), head);

    let posted = h
        .post(request.clone(), cap.clone(), vec![approved])
        .expect("resolved effects have a distinct human approval");
    assert!(matches!(posted, Posted::Committed { .. }));
    let (entry, _) = read_entry(&h.db, posted.entry_ref().vid).unwrap().unwrap();
    assert_eq!(entry.proposal, resolved);
    assert_eq!(entry.proposal_digest, approved.approved_digest);
    assert_eq!(entry.approvals, vec![approved]);
    assert_eq!(
        fa_journal::limit::request_form(&entry.proposal).unwrap(),
        Some(request.clone())
    );
    let head = h.db.frontier().unwrap();
    let retry = h.post(request, cap, vec![approved]).unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn balancing_approval_binding_precedes_observation_and_unchanged_amounts_post() {
    let mut h = harness();
    h.close_march();
    let cap = human(PREPARER, &["post", "post_closed"]);
    let mut request = h.proposal(PREPARER, 100, b"unlimited-balancing", EntryClass::ADJUSTING);
    request.schema_minor = fa_model::entry::EXTENSIONS_MINOR;
    request.extensions.push((
        fa_model::entry::BALANCING_EXTENSION,
        fa_journal::limit::balancing_bytes(0, 100),
    ));
    let own_foreign = h.approve(PREPARER, [0xa9; 32]).unwrap().approval();
    let head = h.db.frontier().unwrap();
    // Neither existence nor the foreign record's self-approval status may
    // be judged before its digest binds to this resolved proposal.
    for foreign in [
        own_foreign,
        ApprovalRef {
            approval_vid: VId(0xdead_beef),
            approved_digest: [0xa9; 32],
        },
    ] {
        let refusal = h
            .post(request.clone(), cap.clone(), vec![foreign])
            .unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-016", exit::SAFETY));
        assert_eq!(h.db.frontier().unwrap(), head);
    }
    let approved = h
        .approve(ALICE, request.proposal_digest().unwrap())
        .unwrap()
        .approval();
    let posted = h.post(request.clone(), cap, vec![approved]).unwrap();
    let (entry, _) = read_entry(&h.db, posted.entry_ref().vid).unwrap().unwrap();
    assert_eq!(entry.proposal, request);
    assert_eq!(entry.proposal_digest, approved.approved_digest);
    assert_eq!(entry.approvals, vec![approved]);
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

    // Activation publishes through its own control path, not `post`. Its
    // structural check must also reject FX claims with no legs to value.
    let mut valued = h.activation(PREPARER, b"valued-control");
    valued.base_totals = Some(fa_model::BaseTotals {
        unit_id: h.usd.0,
        debits: 10,
        credits: 11,
        fx_law_oid: Oid([0x91; 32]),
        rate_doc_oids: vec![Oid([0x92; 32])],
        residual: None,
    });
    let digest = valued.proposal_digest().unwrap();
    let bob = h.approve(BOB, digest).unwrap().approval();
    let carol = h.approve(CAROL, digest).unwrap().approval();
    let valued_head = h.db.frontier().unwrap();
    let r = h
        .activate(valued, controller(), vec![bob, carol])
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-100", exit::USAGE));
    assert!(r.message.contains("base_totals"), "{r}");
    assert_eq!(h.db.frontier().unwrap(), valued_head);
    assert_eq!(security_policy_epoch(&h.db).unwrap(), 0);

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
    // The immutable outcome binds its ordered approvals. They are not
    // re-authorized at the new epoch, but cannot be omitted or reordered.
    for approvals in [Vec::new(), vec![carol, bob]] {
        let refused = h
            .activate(proposal.clone(), controller(), approvals)
            .unwrap_err();
        assert_eq!((refused.code, refused.exit), ("FA-REF-032", exit::CONFLICT));
    }
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
        h.activate(resealed, controller(), vec![bob, carol]),
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

    // fa-l93 D8: a Locked period admits no class this slice posts, so the
    // fix never suggests a Reversal or Adjusting entry there.
    let late = h.proposal(PREPARER, 5, b"late-into-locked", EntryClass::ORIGINAL);
    let r = h
        .post(late, human(PREPARER, &["post", "post_closed"]), Vec::new())
        .unwrap_err();
    assert_eq!((r.code, r.exit), ("FA-REF-010", exit::SAFETY), "{r}");
    assert_eq!(
        r.fix,
        "keep the entry's true effective date; never re-date it to escape the period law: a Locked period admits no posting class in this build, only Resolution releases; a reopen of a Locked period is case-bound and refused in this build; `fa period list --json` shows each period's state"
    );
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
fn chart_install_requires_current_whole_book_schema_authority() {
    let mut h = harness();
    let schema = human(PREPARER, &["schema_change"]);
    let head = h.db.frontier().unwrap();
    let denied = [
        human(PREPARER, &["post"]),
        human(ALICE, &["schema_change"]),
        Capability::new(PREPARER, Profile::Agent, &[Op::Read], AGENT).unwrap(),
        schema.clone().expiring_at(head),
        schema.clone().for_books(&[Id128([0xee; 16])]).unwrap(),
        schema.clone().for_accounts(&["1000"]).unwrap(),
        schema.clone().for_periods(&["FY2026-P03"]).unwrap(),
    ];
    let spec = AccountSpec {
        code: "schema-authorized".into(),
        name: "Authorized chart extension".into(),
        account_type: 5,
        normal_balance: 0,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(h.usd),
        parent_code: None,
        limit: None,
    };
    let description = h.period_description();
    let ctx = h.ctx();
    for capability in &denied {
        let refusal = h
            .runtime
            .block_on(install_chart(
                &mut h.db,
                &ctx,
                &h.book,
                std::slice::from_ref(&spec),
                PREPARER,
                DateDay::from_ymd(2026, 3, 1).unwrap(),
                b"schema-authorized",
                description.clone(),
                capability,
            ))
            .expect("typed admission")
            .unwrap_err();
        assert_eq!(refusal.exit, exit::SAFETY, "{refusal:?}");
        assert_eq!(h.db.frontier().unwrap(), head, "denied chart wrote");
        assert!(
            h.db.vertex(account_vid(h.book.book_id, &spec.code))
                .unwrap()
                .is_none()
        );
    }
    let installed = h
        .runtime
        .block_on(install_chart(
            &mut h.db,
            &ctx,
            &h.book,
            std::slice::from_ref(&spec),
            PREPARER,
            DateDay::from_ymd(2026, 3, 1).unwrap(),
            b"schema-authorized",
            description,
            &schema,
        ))
        .unwrap()
        .expect("authorized chart");
    let (entry, created_at) = read_entry(&h.db, installed.control_entry).unwrap().unwrap();
    assert_eq!(entry.proposal.principal_ref, PREPARER);
    assert_eq!(entry.proposal.class, EntryClass::SCHEMA_CONTROL);
    assert_eq!(created_at, installed.recorded_at);
    let account =
        h.db.vertex(account_vid(h.book.book_id, &spec.code))
            .unwrap()
            .unwrap();
    assert_eq!(
        account.created_at, installed.recorded_at,
        "chart and control publish together"
    );
    let chart = fa_journal::chart::read_at(&h.db, &h.book, installed.recorded_at).unwrap();
    assert!(chart.accounts().contains_key(&account.vid));
}

#[test]
fn revoked_chart_authority_is_checked_before_existing_periods_are_observed() {
    let mut h = harness();
    let schema = human(PREPARER, &["schema_change"]);
    h.revoke(
        &human(ALICE, &["issue_capability"]),
        &schema,
        b"revoke-chart",
    )
    .unwrap();
    let ctx = h.ctx();
    let period = fa_model::period_vid(&h.book.calendar.id, &h.march);
    let mut corrupt = WriteBatch::new(relation::IN_BOOK);
    corrupt.set_vertex_property(
        period,
        property::PERIOD_START,
        Some(CanonicalScalar::Bool(true)),
    );
    h.runtime
        .block_on(h.db.write(&ctx.commit(), corrupt))
        .unwrap();
    let before = h.db.frontier().unwrap();
    let spec = AccountSpec {
        code: "guarded-period-budget".into(),
        name: "Period budget".into(),
        account_type: 5,
        normal_balance: 0,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(h.usd),
        parent_code: None,
        limit: Some(fa_journal::BalanceLimit {
            lower: None,
            upper: Some(1000),
            scope: fa_journal::LimitScope::Period,
        }),
    };
    let description = h.period_description();
    let refusal = h
        .runtime
        .block_on(install_chart(
            &mut h.db,
            &ctx,
            &h.book,
            &[spec],
            PREPARER,
            DateDay::from_ymd(2026, 3, 1).unwrap(),
            b"guarded-budget",
            description,
            &schema,
        ))
        .expect("revocation precedes corrupt period decoding")
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-023");
    assert_eq!(h.db.frontier().unwrap(), before);
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
                Ok::<_, KernelError>(Erasable::seal(
                    &text.to_string(),
                    None,
                    &book.seal_key,
                    [0x5d; 32],
                    [0x5d; 24],
                ))
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

// ---------------------------------------------------------------------------
// Scope caveats (plan §14.2, fa-llx): accounts, periods, effective, known_at,
// branch — each refused before any query is constructed, never filtered
// ---------------------------------------------------------------------------

/// A scope refusal: FA-REF-011 `out_of_scope` naming the caveat, exit 7,
/// and nothing written.
fn assert_out_of_scope<T: std::fmt::Debug>(
    h: &Harness,
    before: CommitSeq,
    r: Result<T, Refusal>,
    caveat: &str,
) {
    let r = r.unwrap_err();
    assert_eq!(
        (r.code, r.exit),
        ("FA-REF-011", exit::SAFETY),
        "{}",
        r.message
    );
    assert!(
        r.message.contains(&format!("`{caveat}` caveat")),
        "{}",
        r.message
    );
    assert_eq!(h.db.frontier().unwrap(), before, "a scope refusal wrote");
}

impl Harness {
    /// A second chart batch: summary `6100` over leaves `6110` and `6120`.
    fn install_subtree(&mut self) -> (VId, VId) {
        let ctx = self.ctx();
        let usd = self.usd;
        let account = |code: &str, is_leaf: bool, parent: Option<&str>| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type: 5,
            normal_balance: 0,
            is_leaf,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: parent.map(Into::into),
            limit: None,
        };
        let chart = vec![
            account("6100", false, None),
            account("6110", true, Some("6100")),
            account("6120", true, Some("6100")),
        ];
        let description = self.seal("chart 2", 0x62);
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move {
                install_chart(
                    db,
                    &ctx,
                    book,
                    &chart,
                    PREPARER,
                    DateDay::from_ymd(2026, 1, 1).unwrap(),
                    b"chart-2",
                    description,
                    &Capability::embedded(PREPARER, &["schema_change"]).unwrap(),
                )
                .await
            })
            .expect("kernel")
            .expect("the subtree installs");
        (
            account_vid(self.book.book_id, "6110"),
            account_vid(self.book.book_id, "6120"),
        )
    }

    /// An Original moving `cents` from `credit` to `debit`, dated `day`.
    fn between(
        &self,
        debit: VId,
        credit: VId,
        cents: i128,
        key: &[u8],
        day: DateDay,
    ) -> EntryPayload {
        let mut p = self.proposal(PREPARER, cents, key, EntryClass::ORIGINAL);
        p.legs = vec![
            LegPayload::simple(Side::Debit, debit, Amount::new(self.usd, cents)),
            LegPayload::simple(Side::Credit, credit, Amount::new(self.usd, cents)),
        ];
        p.unit_totals = EntryPayload::fold_unit_totals(&p.legs).unwrap();
        p.effective_date = day;
        p
    }

    fn post_ok(&mut self, proposal: EntryPayload, capability: Capability) {
        assert!(matches!(
            self.post(proposal, capability, Vec::new()),
            Ok(Posted::Committed { .. })
        ));
    }
}

/// A post reaches its legs' accounts, the period its date resolves to, and
/// that date: each scope caveat admits it only inside its bound, refuses it
/// with FA-REF-011 before anything is written, and a whole-book pin
/// (`known_at`) or a draft confinement (`branch`) refuses every trunk post.
#[test]
fn scope_caveats_confine_a_post_to_its_accounts_periods_and_dates() {
    let mut h = harness();
    let (travel, meals) = h.install_subtree();
    let mid_march = DateDay::from_ymd(2026, 3, 15).unwrap();

    // accounts ⊆ subtree(6100): both legs under the summary admit, a cash
    // leg outside it refuses, and naming both roots admits that entry.
    let expenses = human(PREPARER, &["post"]).for_accounts(&["6100"]).unwrap();
    h.post_ok(
        h.between(travel, meals, 1_000, b"in-tree", mid_march),
        expenses.clone(),
    );
    let before = h.db.frontier().unwrap();
    let r = h.post(
        h.between(travel, h.cash, 1_000, b"cross", mid_march),
        expenses,
        Vec::new(),
    );
    assert_out_of_scope(&h, before, r, "accounts");
    let both = human(PREPARER, &["post"])
        .for_accounts(&["1000", "6100"])
        .unwrap();
    h.post_ok(h.between(travel, h.cash, 1_000, b"cross", mid_march), both);
    // A root the chart lacks scopes no account.
    let nowhere = human(PREPARER, &["post"]).for_accounts(&["9999"]).unwrap();
    let before = h.db.frontier().unwrap();
    let r = h.post(
        h.between(travel, meals, 1_000, b"nowhere", mid_march),
        nowhere,
        Vec::new(),
    );
    assert_out_of_scope(&h, before, r, "accounts");
    // The base checks precede the caveat's compile: another principal's
    // scoped token is refused as not its holder, before the chart is read.
    let alices = human(ALICE, &["post"]).for_accounts(&["6100"]).unwrap();
    let r = h
        .post(
            h.between(travel, meals, 1_000, b"not-holder", mid_march),
            alices,
            Vec::new(),
        )
        .unwrap_err();
    assert!(r.fix.contains("--as <holder>"), "{}", r.fix);
    assert_eq!(h.db.frontier().unwrap(), before);

    // periods ⊆ {March}: a March post admits; a token for February refuses
    // it before the period law is read.
    let march_only = human(PREPARER, &["post"])
        .for_periods(&[h.march.as_str()])
        .unwrap();
    h.post_ok(
        h.proposal(PREPARER, 2_000, b"p-in", EntryClass::ORIGINAL),
        march_only,
    );
    let february = human(PREPARER, &["post"])
        .for_periods(&["FY2026-P02"])
        .unwrap();
    let before = h.db.frontier().unwrap();
    let r = h.post(
        h.proposal(PREPARER, 2_000, b"p-out", EntryClass::ORIGINAL),
        february,
        Vec::new(),
    );
    assert_out_of_scope(&h, before, r, "periods");

    // effective ≤ date: the 15th is past the 14th and inside the 31st.
    let through_14th =
        human(PREPARER, &["post"]).effective_through(DateDay::from_ymd(2026, 3, 14).unwrap());
    let before = h.db.frontier().unwrap();
    let r = h.post(
        h.proposal(PREPARER, 3_000, b"e-out", EntryClass::ORIGINAL),
        through_14th,
        Vec::new(),
    );
    assert_out_of_scope(&h, before, r, "effective");
    let through_31st =
        human(PREPARER, &["post"]).effective_through(DateDay::from_ymd(2026, 3, 31).unwrap());
    h.post_ok(
        h.proposal(PREPARER, 3_000, b"e-in", EntryClass::ORIGINAL),
        through_31st,
    );

    // known_at ≤ seq: a pinned token never writes, even pinned past the head.
    let pinned = human(PREPARER, &["post"]).known_at_most(CommitSeq(u64::MAX));
    let before = h.db.frontier().unwrap();
    let r = h.post(
        h.proposal(PREPARER, 4_000, b"k", EntryClass::ORIGINAL),
        pinned,
        Vec::new(),
    );
    assert_out_of_scope(&h, before, r, "known_at");

    // branch = <draft>: confined to a draft, it cannot post to trunk; a
    // token confined to trunk can.
    let drafted = human(PREPARER, &["post"])
        .on_branch(Id128([0xd7; 16]))
        .unwrap();
    let before = h.db.frontier().unwrap();
    let r = h.post(
        h.proposal(PREPARER, 5_000, b"b", EntryClass::ORIGINAL),
        drafted,
        Vec::new(),
    );
    assert_out_of_scope(&h, before, r, "branch");
    let trunk = human(PREPARER, &["post"]).on_branch(Id128::TRUNK).unwrap();
    h.post_ok(
        h.proposal(PREPARER, 5_000, b"b", EntryClass::ORIGINAL),
        trunk,
    );
}

/// Acts on the whole book (a tick, the sweeps, an approval of an opaque
/// proposal, a review) refuse every scoped token; a period transition
/// reaches its one period, so a `periods` caveat naming it and an
/// `effective` caveat through its last day admit it, while an `accounts`
/// caveat (a close binds every account) refuses it.
#[test]
fn a_scoped_token_cannot_act_on_the_whole_book_and_a_transition_reaches_its_period() {
    let mut h = harness();
    let march = h.march.clone();

    let before = h.db.frontier().unwrap();
    let r = h.tick(
        human(PREPARER, &["witness"])
            .for_periods(&[march.as_str()])
            .unwrap(),
        1_000,
        b"tick-1",
    );
    assert_out_of_scope(&h, before, r, "periods");

    let system = fa_journal::rows::system_principal(h.book.book_id);
    let pinned_sweeper = Capability::new(system, Profile::System, &[Op::Post], system)
        .unwrap()
        .known_at_most(CommitSeq(u64::MAX));
    let (expiry, reversals) = h.sweeps(pinned_sweeper);
    assert_out_of_scope(&h, before, expiry, "known_at");
    assert_out_of_scope(&h, before, reversals, "known_at");

    let tree_approver = human(ALICE, &["approve"]).for_accounts(&["6000"]).unwrap();
    let r = h.approve_with(tree_approver, [0x11; 32]);
    assert_out_of_scope(&h, before, r, "accounts");

    let document = h.evidence[0].document_oid;
    let r = h.review(
        human(ALICE, &["approve"]).effective_through(DateDay::from_ymd(2026, 3, 31).unwrap()),
        document,
    );
    assert_out_of_scope(&h, before, r, "effective");

    // Transitions: a February token, an accounts-scoped token and a date
    // bound short of March's last day refuse; March's own scope admits.
    for (cap, caveat) in [
        (
            period_cap().for_periods(&["FY2026-P02"]).unwrap(),
            "periods",
        ),
        (period_cap().for_accounts(&["1000"]).unwrap(), "accounts"),
        (
            period_cap().effective_through(DateDay::from_ymd(2026, 3, 30).unwrap()),
            "effective",
        ),
        (period_cap().known_at_most(CommitSeq(u64::MAX)), "known_at"),
    ] {
        let r = h.transition_with(PeriodTransition::SoftClose, b"sc", &cap, &[]);
        assert_out_of_scope(&h, before, r, caveat);
    }
    assert_eq!(h.march_state(), PeriodState::Open);
    h.transition_with(
        PeriodTransition::SoftClose,
        b"sc",
        &period_cap().for_periods(&[march.as_str()]).unwrap(),
        &[],
    )
    .expect("a periods caveat naming March admits its soft close");
    h.transition_with(
        PeriodTransition::Close,
        b"c",
        &period_cap().effective_through(DateDay::from_ymd(2026, 3, 31).unwrap()),
        &[],
    )
    .expect("an effective bound through March's last day admits its close");
    assert_eq!(h.march_state(), PeriodState::Closed);
}

/// WhiteCreek 3559 (planted negative): a scoped token that is revoked or
/// expired now gets that refusal before its `accounts` caveat is compiled,
/// so a probe of an account inside its subtree and one outside it return
/// the same envelope: the token learns nothing about the chart. The pinned
/// substrate has no read counter; the compile's order is also fixed by type,
/// since `account_scope` needs the `Current` proof only `current_at` mints
/// after the expiry and revocation checks.
#[test]
fn a_revoked_or_expired_scoped_token_learns_nothing_about_its_subtree() {
    let mut h = harness();
    let (travel, meals) = h.install_subtree();
    let mid_march = DateDay::from_ymd(2026, 3, 15).unwrap();
    let revoked = human(PREPARER, &["post"]).for_accounts(&["6100"]).unwrap();
    h.revoke(&human(ALICE, &["issue_capability"]), &revoked, b"rv-scoped")
        .expect("revoked");
    let expired = human(PREPARER, &["post", "read"])
        .for_accounts(&["6100"])
        .unwrap()
        .expiring_at(h.db.frontier().unwrap());
    for (cap, code) in [(revoked, "FA-REF-023"), (expired, "FA-REF-014")] {
        let before = h.db.frontier().unwrap();
        let inside = h
            .post(
                h.between(travel, meals, 1_000, b"probe-in", mid_march),
                cap.clone(),
                Vec::new(),
            )
            .unwrap_err();
        let outside = h
            .post(
                h.between(travel, h.cash, 1_000, b"probe-out", mid_march),
                cap,
                Vec::new(),
            )
            .unwrap_err();
        assert_eq!(
            (inside.code, inside.exit),
            (code, exit::SAFETY),
            "{}",
            inside.message
        );
        assert_eq!(inside, outside, "the probes are indistinguishable");
        assert_eq!(h.db.frontier().unwrap(), before);
    }
}

/// WhiteCreek 3559 (planted negative): a `known_at`-pinned read never loads
/// or decodes an entry recorded after its pin. The vertex planted past the
/// pin carries a payload that does not decode, so reading it at all would
/// fail: through the pin it is simply absent, exactly like a vid that names
/// nothing; at the head the pin refuses before any read, identically for
/// both; and an unpinned reader at the head does hit the corrupt payload,
/// so the trap is armed.
#[test]
fn a_pinned_read_never_decodes_an_entry_recorded_after_its_pin() {
    let mut h = harness();
    h.post_ok(
        h.proposal(PREPARER, 1_000, b"before-pin", EntryClass::ORIGINAL),
        controller(),
    );
    let early = fa_model::entry_vid(h.book.book_id, &PREPARER.0.to_le_bytes(), b"before-pin");
    let pin = h.db.frontier().unwrap();
    let planted = VId(0x5eed_0001);
    {
        let ctx = h.ctx();
        let txn_cx = ctx.txn();
        let mut txn = h.db.begin(&txn_cx).expect("begin");
        let mut batch = WriteBatch::new(relation::IN_BOOK);
        batch.create_vertex(
            planted,
            vec![label::ENTRY],
            vec![(
                property::FA_PAYLOAD,
                fa_journal::rows::scalar_bytes("planted", vec![0xff; 8]).unwrap(),
            )],
        );
        txn.write(&mut h.db, batch).expect("stage");
        let commit_cx = ctx.commit();
        let db = &mut h.db;
        h.runtime
            .block_on(async move { txn.commit(db, &commit_cx).await })
            .expect("planted past the pin");
    }
    let head = h.db.frontier().unwrap();
    assert!(head > pin);
    let absent = VId(0x5eed_0002);

    let pinned = human(PREPARER, &["read"]).known_at_most(pin);
    let reads = admit_reads(&h.db, &h.book, PREPARER, &pinned)
        .unwrap()
        .expect("admitted");
    assert!(
        reads
            .read_entry(&h.db, early, pin)
            .unwrap()
            .unwrap()
            .is_some()
    );
    assert_eq!(
        reads.read_entry(&h.db, planted, pin).unwrap().unwrap(),
        None
    );
    assert_eq!(reads.read_entry(&h.db, absent, pin).unwrap().unwrap(), None);
    let at_planted = reads.read_entry(&h.db, planted, head).unwrap().unwrap_err();
    let at_absent = reads.read_entry(&h.db, absent, head).unwrap().unwrap_err();
    assert_eq!(
        (at_planted.code, at_planted.exit),
        ("FA-REF-011", exit::SAFETY)
    );
    assert_eq!(at_planted, at_absent, "refused before any read");

    let open = admit_reads(&h.db, &h.book, PREPARER, &human(PREPARER, &["read"]))
        .unwrap()
        .expect("admitted");
    assert!(
        open.read_entry(&h.db, planted, head).is_err(),
        "the planted payload does not decode, so the pinned reads never decoded it"
    );
}

// ---------------------------------------------------------------------------
// The complete effect footprint (CobaltGull 3570; WhiteCreek 3571/3582/3584):
// holds, scheduled reversals, applications and their undo, the transition's
// own date, and a retained identity — judged before any payload is loaded
// ---------------------------------------------------------------------------

/// A refusal of a target a scoped token does not reach is the refusal of a
/// target that does not exist: the same code, exit, cite and fix, and the
/// same message but for the vid it names. Nothing is written.
fn assert_like_absent(
    h: &Harness,
    before: CommitSeq,
    (refused, vid): (Refusal, VId),
    (absent, nowhere): (Refusal, VId),
) {
    assert_eq!(
        (refused.code, refused.exit, &refused.cite, &refused.fix),
        (absent.code, absent.exit, &absent.cite, &absent.fix),
        "{} / {}",
        refused.message,
        absent.message
    );
    assert_eq!(
        refused.message.replace(&format!("{:032x}", vid.0), "<vid>"),
        absent
            .message
            .replace(&format!("{:032x}", nowhere.0), "<vid>")
    );
    assert_eq!(
        h.db.frontier().unwrap(),
        before,
        "a footprint refusal wrote"
    );
}

const NOWHERE: EntryRef = EntryRef {
    vid: VId(0x0bad_0001),
    entry_digest: [0; 32],
};

impl Harness {
    fn leg(&self, side: Side, account: VId, cents: i128) -> LegPayload {
        LegPayload::simple(side, account, Amount::new(self.usd, cents))
    }

    /// A proposal of `class` with exactly `legs`, dated `day`.
    fn with_legs(
        &self,
        class: EntryClass,
        legs: Vec<LegPayload>,
        key: &[u8],
        day: DateDay,
    ) -> EntryPayload {
        let mut p = self.proposal(PREPARER, 1, key, class);
        p.unit_totals = EntryPayload::fold_unit_totals(&legs).unwrap();
        p.legs = legs;
        p.effective_date = day;
        p
    }

    fn hold(&self, legs: Vec<LegPayload>, key: &[u8], day: DateDay) -> EntryPayload {
        let mut p = self.with_legs(EntryClass::PENDING, legs, key, day);
        p.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: None,
            disposition: None,
        });
        p
    }

    fn voids(&self, target: EntryRef, key: &[u8], day: DateDay) -> EntryPayload {
        let mut p = self.with_legs(EntryClass::RESOLUTION, Vec::new(), key, day);
        p.control = Some(ControlPayload::ReservationRelease);
        p.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: Some(target),
            disposition: Some(Disposition::Voids),
        });
        p
    }

    fn posts(
        &self,
        target: EntryRef,
        legs: Vec<LegPayload>,
        source_ordinals: Vec<u16>,
        key: &[u8],
        day: DateDay,
    ) -> EntryPayload {
        let mut p = self.with_legs(EntryClass::RESOLUTION, legs, key, day);
        p.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: Some(target),
            disposition: Some(Disposition::Posts { source_ordinals }),
        });
        p
    }

    fn reverses(
        &self,
        target: EntryRef,
        legs: Vec<LegPayload>,
        key: &[u8],
        day: DateDay,
    ) -> EntryPayload {
        let mut p = self.with_legs(EntryClass::REVERSAL, legs, key, day);
        p.supersession = vec![Supersession {
            target,
            kind: SupersessionKind::Reverses,
            reason_code: 1,
        }];
        p
    }

    fn commit(&mut self, proposal: EntryPayload, capability: Capability) -> EntryRef {
        self.post(proposal, capability, Vec::new())
            .expect("posted")
            .entry_ref()
    }

    /// `post` without unwrapping the kernel error (the armed negatives).
    fn post_outcome(
        &mut self,
        proposal: EntryPayload,
        capability: Capability,
    ) -> Result<Result<Posted, Refusal>, KernelError> {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        let req = PostRequest {
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
            capability,
        };
        self.runtime
            .block_on(async move { post(db, &ctx, book, req).await })
    }

    /// The Normal period of FY2026 that contains `day`.
    fn period_of(&self, day: DateDay) -> String {
        self.book
            .calendar
            .periods_for_year(2026)
            .unwrap()
            .into_iter()
            .find(|p| p.contains(day) && p.kind == PeriodKind::Normal)
            .expect("a normal period")
            .code
    }

    fn open(&mut self, day: DateDay, key: &[u8]) {
        let code = self.period_of(day);
        self.transition_of(PeriodTransition::Open, key, &period_cap(), &code, 1)
            .expect("opened");
    }

    /// `t` on period `code` with registered reason `reason`; the period
    /// dates the control (fa-87r).
    fn transition_of(
        &mut self,
        t: PeriodTransition,
        key: &[u8],
        capability: &Capability,
        code: &str,
        reason: u16,
    ) -> Result<Transitioned, Refusal> {
        let ctx = self.ctx();
        let description = self.period_description();
        let db = &mut self.db;
        let book = &self.book;
        let code = code.to_string();
        self.runtime
            .block_on(async move {
                transition_period(
                    db,
                    &ctx,
                    book,
                    &code,
                    t,
                    PREPARER,
                    reason,
                    key,
                    description,
                    capability,
                    &[],
                )
                .await
            })
            .expect("kernel")
    }

    /// Plant an ENTRY vertex whose payload does not decode, with mirrors
    /// that put it on `day` with one leg on `account`.
    fn plant(&mut self, vid: VId, day: DateDay, account: VId) {
        let ctx = self.ctx();
        let txn_cx = ctx.txn();
        let mut txn = self.db.begin(&txn_cx).expect("begin");
        let mut batch = WriteBatch::new(relation::IN_BOOK);
        batch.create_vertex(
            vid,
            vec![label::ENTRY],
            vec![
                (
                    property::FA_PAYLOAD,
                    fa_journal::rows::scalar_bytes("planted", vec![0xff; 8]).unwrap(),
                ),
                (
                    property::FA_EFFECTIVE_DAY,
                    CanonicalScalar::Int(i64::from(day.0)),
                ),
            ],
        );
        batch.create_vertex(
            fa_journal::rows::leg_vid(vid, 0),
            vec![label::LEG],
            vec![(
                property::ACCOUNT_REF,
                fa_journal::rows::scalar_bytes("account_ref", account.0.to_le_bytes().to_vec())
                    .unwrap(),
            )],
        );
        txn.write(&mut self.db, batch).expect("stage");
        let commit_cx = ctx.commit();
        let db = &mut self.db;
        self.runtime
            .block_on(async move { txn.commit(db, &commit_cx).await })
            .expect("planted");
    }
}

/// (a) and (b): a hold is part of the footprint of the resolution that
/// releases it. A zero-leg Voids of a hold with a leg outside the
/// `accounts` subtree — or under a root the chart lacks — and a partial
/// Posts that omits that leg are refused exactly as a hold that does not
/// exist; the unscoped controller still voids and posts them.
#[test]
fn a_scoped_token_never_voids_or_partially_posts_a_hold_reaching_outside_its_scope() {
    let mut h = harness();
    let (travel, meals) = h.install_subtree();
    let day = DateDay::from_ymd(2026, 3, 15).unwrap();
    let held = h.hold(
        vec![
            h.leg(Side::Debit, travel, 1_000),
            h.leg(Side::Credit, h.cash, 1_000),
        ],
        b"hold-1",
        day,
    );
    let hold = h.commit(held, controller());
    let split = h.hold(
        vec![
            h.leg(Side::Debit, travel, 1_000),
            h.leg(Side::Credit, meals, 600),
            h.leg(Side::Credit, h.cash, 400),
        ],
        b"hold-2",
        day,
    );
    let split = h.commit(split, controller());
    let posted = |h: &Harness, target: EntryRef, key: &[u8]| {
        h.posts(
            target,
            vec![
                h.leg(Side::Debit, travel, 600),
                h.leg(Side::Credit, meals, 600),
            ],
            vec![0, 1],
            key,
            day,
        )
    };
    for roots in [["6100"], ["9999"]] {
        let tree = human(PREPARER, &["post"]).for_accounts(&roots).unwrap();
        let before = h.db.frontier().unwrap();
        let refused = h.post(h.voids(hold, b"void", day), tree.clone(), Vec::new());
        let absent = h.post(h.voids(NOWHERE, b"void-0", day), tree.clone(), Vec::new());
        assert_like_absent(
            &h,
            before,
            (refused.unwrap_err(), hold.vid),
            (absent.unwrap_err(), NOWHERE.vid),
        );
        let refused = h.post(posted(&h, split, b"posts"), tree.clone(), Vec::new());
        let absent = h.post(posted(&h, NOWHERE, b"posts-0"), tree, Vec::new());
        assert_like_absent(
            &h,
            before,
            (refused.unwrap_err(), split.vid),
            (absent.unwrap_err(), NOWHERE.vid),
        );
    }
    h.post_ok(h.voids(hold, b"void", day), controller());
    h.post_ok(posted(&h, split, b"posts"), controller());
}

/// (c): an Adjusting's scheduled reversal is in its footprint now. A
/// March-only or `effective <= Mar 31` token cannot schedule one for April
/// — refused before anything is read, ahead of the request's own checks
/// (unscoped, this book's missing time_zone_policy is the refusal).
#[test]
fn a_scoped_token_cannot_schedule_a_reversal_outside_its_scope() {
    let mut h = harness();
    let april = DateDay::from_ymd(2026, 4, 1).unwrap();
    let accrual = |h: &Harness| {
        with_auto_reverse(
            h.proposal(PREPARER, 1_000, b"accrual", EntryClass::ADJUSTING),
            april,
        )
    };
    let march_only = human(PREPARER, &["post"])
        .for_periods(&[h.march.as_str()])
        .unwrap();
    let before = h.db.frontier().unwrap();
    let r = h.post(accrual(&h), march_only, Vec::new());
    assert_out_of_scope(&h, before, r, "periods");
    let through_march =
        human(PREPARER, &["post"]).effective_through(DateDay::from_ymd(2026, 3, 31).unwrap());
    let r = h.post(accrual(&h), through_march, Vec::new());
    assert_out_of_scope(&h, before, r, "effective");
    let r = h
        .post(accrual(&h), human(PREPARER, &["post"]), Vec::new())
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-102", "{}", r.message);
}

/// (d): an application changes its target leg, so a February open item is
/// in the footprint of the March receipt that applies to it, and of the
/// reversal that undoes that application. A March-only token is refused
/// both as if the target did not exist; the unscoped controller applies
/// and undoes.
#[test]
fn a_scoped_token_cannot_apply_to_or_unapply_a_leg_outside_its_scope() {
    let mut h = harness();
    let (travel, meals) = h.install_subtree();
    let february = DateDay::from_ymd(2026, 2, 15).unwrap();
    let day = DateDay::from_ymd(2026, 3, 15).unwrap();
    h.open(february, b"open-feb");
    let item = h.with_legs(
        EntryClass::ORIGINAL,
        vec![
            h.leg(Side::Debit, travel, 500),
            h.leg(Side::Credit, meals, 500),
        ],
        b"feb-item",
        february,
    );
    let item = h.commit(item, controller());
    let receipt = |h: &Harness, target: EntryRef, key: &[u8]| {
        let mut credit = h.leg(Side::Credit, travel, 500);
        credit.settles = vec![Settlement {
            target,
            ordinal: 0,
            amount: Amount::new(h.usd, 500),
        }];
        h.with_legs(
            EntryClass::ORIGINAL,
            vec![h.leg(Side::Debit, meals, 500), credit],
            key,
            day,
        )
    };
    let march_tree = human(PREPARER, &["post"])
        .for_accounts(&["6100"])
        .unwrap()
        .for_periods(&[h.march.as_str()])
        .unwrap();
    let before = h.db.frontier().unwrap();
    let refused = h.post(
        receipt(&h, item, b"receipt"),
        march_tree.clone(),
        Vec::new(),
    );
    let absent = h.post(
        receipt(&h, NOWHERE, b"receipt-0"),
        march_tree.clone(),
        Vec::new(),
    );
    assert_like_absent(
        &h,
        before,
        (refused.unwrap_err(), item.vid),
        (absent.unwrap_err(), NOWHERE.vid),
    );
    let applied = h.commit(receipt(&h, item, b"receipt"), controller());
    let undo = |h: &Harness, target: EntryRef, key: &[u8]| {
        h.reverses(
            target,
            vec![
                h.leg(Side::Credit, meals, 500),
                h.leg(Side::Debit, travel, 500),
            ],
            key,
            day,
        )
    };
    let before = h.db.frontier().unwrap();
    let refused = h.post(undo(&h, applied, b"undo"), march_tree.clone(), Vec::new());
    let absent = h.post(undo(&h, NOWHERE, b"undo-0"), march_tree, Vec::new());
    assert_like_absent(
        &h,
        before,
        (refused.unwrap_err(), applied.vid),
        (absent.unwrap_err(), NOWHERE.vid),
    );
    h.post_ok(undo(&h, applied, b"undo"), controller());
}

/// The transition's own date is in its footprint, and the period law fixes
/// it (fa-87r): a SoftClose of March is dated March 31, so a revoked token
/// bounded short of that day, or to February, gets FA-REF-011, not
/// FA-REF-023 — the scope refusal precedes every read, the revocation's
/// included — and a live token bounded through March 31 transitions.
#[test]
fn a_transition_outside_a_scope_is_refused_before_any_read() {
    let mut h = harness();
    let march = h.march.clone();
    let issuer = human(ALICE, &["issue_capability"]);
    let bounded = period_cap().effective_through(DateDay::from_ymd(2026, 3, 30).unwrap());
    let february_only = period_cap().for_periods(&["FY2026-P02"]).unwrap();
    h.revoke(&issuer, &bounded, b"rv-bounded").expect("revoked");
    h.revoke(&issuer, &february_only, b"rv-february")
        .expect("revoked");
    let before = h.db.frontier().unwrap();
    for (cap, caveat) in [(bounded, "effective"), (february_only, "periods")] {
        let r = h.transition_of(PeriodTransition::SoftClose, b"sc", &cap, &march, 1);
        assert_out_of_scope(&h, before, r, caveat);
    }
    let live = human(PREPARER, &["close", "reopen", "read"])
        .effective_through(DateDay::from_ymd(2026, 3, 31).unwrap());
    let done = h
        .transition_of(PeriodTransition::SoftClose, b"sc", &live, &march, 1)
        .expect("March's last day inside the bound admits");
    let (control, _) = read_entry(&h.db, done.control_entry)
        .unwrap()
        .expect("control entry");
    assert_eq!(
        control.proposal.effective_date,
        DateDay::from_ymd(2026, 3, 31).unwrap()
    );
}

/// WhiteCreek 3571/3582: a scoped token never loads an entry outside its
/// scope. A key it reused from its own out-of-scope entry is a conflict —
/// never compared, never the recorded outcome. Armed: entries planted with
/// undecodable payloads behind mirrors outside the scope, at a key identity
/// and as a hold to void, get the conflict and the absent-target refusal,
/// while an unscoped caller that does load them hits the decode error.
#[test]
fn a_scoped_token_never_loads_an_entry_outside_its_scope() {
    let mut h = harness();
    let (travel, meals) = h.install_subtree();
    let day = DateDay::from_ymd(2026, 3, 15).unwrap();
    let tree = human(PREPARER, &["post"]).for_accounts(&["6100"]).unwrap();
    h.commit(
        h.proposal(PREPARER, 700, b"k", EntryClass::ORIGINAL),
        controller(),
    );
    let unscoped = h
        .post(
            h.proposal(PREPARER, 701, b"k", EntryClass::ORIGINAL),
            controller(),
            Vec::new(),
        )
        .unwrap_err();
    let before = h.db.frontier().unwrap();
    let r = h
        .post(
            h.between(travel, meals, 700, b"k", day),
            tree.clone(),
            Vec::new(),
        )
        .unwrap_err();
    assert_eq!(
        (r.code, r.exit),
        (unscoped.code, unscoped.exit),
        "{}",
        r.message
    );
    assert_eq!(h.db.frontier().unwrap(), before);

    // Armed, at a key identity.
    let planted = fa_model::entry_vid(h.book.book_id, &PREPARER.0.to_le_bytes(), b"kx");
    h.plant(planted, day, h.cash);
    let before = h.db.frontier().unwrap();
    let r = h
        .post(
            h.between(travel, meals, 700, b"kx", day),
            tree.clone(),
            Vec::new(),
        )
        .unwrap_err();
    assert_eq!(
        (r.code, r.exit),
        (unscoped.code, unscoped.exit),
        "{}",
        r.message
    );
    assert_eq!(h.db.frontier().unwrap(), before);
    assert!(
        h.post_outcome(
            h.proposal(PREPARER, 700, b"kx", EntryClass::ORIGINAL),
            controller()
        )
        .is_err(),
        "unscoped, the planted payload is loaded and does not decode"
    );

    // Armed, as a hold to void.
    let hold = EntryRef {
        vid: VId(0x5eed_0101),
        entry_digest: [0; 32],
    };
    h.plant(hold.vid, day, h.cash);
    let before = h.db.frontier().unwrap();
    let refused = h.post(
        h.voids(hold, b"void-planted", day),
        tree.clone(),
        Vec::new(),
    );
    let absent = h.post(h.voids(NOWHERE, b"void-nowhere", day), tree, Vec::new());
    assert_like_absent(
        &h,
        before,
        (refused.unwrap_err(), hold.vid),
        (absent.unwrap_err(), NOWHERE.vid),
    );
    assert!(
        h.post_outcome(h.voids(hold, b"void-planted", day), controller())
            .is_err(),
        "unscoped, the planted hold is loaded and does not decode"
    );
}

impl Harness {
    /// Rewrite (or, with `None`, remove) a leg vertex's `account_ref`
    /// mirror: the corruption a scope admission must never trust.
    fn set_account_mirror(&mut self, leg: VId, value: Option<CanonicalScalar>) {
        let ctx = self.ctx();
        let txn_cx = ctx.txn();
        let mut txn = self.db.begin(&txn_cx).expect("begin");
        let mut batch = WriteBatch::new(relation::IN_BOOK);
        batch.set_vertex_property(leg, property::ACCOUNT_REF, value);
        txn.write(&mut self.db, batch).expect("stage");
        let commit_cx = ctx.commit();
        let db = &mut self.db;
        self.runtime
            .block_on(async move { txn.commit(db, &commit_cx).await })
            .expect("mirror rewritten");
    }

    fn open_code(&mut self, code: &str, key: &[u8]) {
        self.transition_of(PeriodTransition::Open, key, &period_cap(), code, 1)
            .expect("opened");
    }
}

/// CobaltGull 3610 (planted negative): mirror drift is corruption before
/// any effect, for every caller. An honest hold [travel, cash] whose leg-1
/// `account_ref` mirror is rewritten to travel — or removed, so the
/// metadata walk stops early — would be admitted by a subtree(6100)
/// token's metadata; the decode disagrees, so its Void is a kernel error
/// with nothing written, and the controller's unscoped Void of the same
/// hold is too.
#[test]
fn mirror_drift_is_corruption_before_any_effect_for_every_caller() {
    let mut h = harness();
    let (travel, _) = h.install_subtree();
    let day = DateDay::from_ymd(2026, 3, 15).unwrap();
    let tree = human(PREPARER, &["post"]).for_accounts(&["6100"]).unwrap();
    let rewritten =
        fa_journal::rows::scalar_bytes("account_ref", travel.0.to_le_bytes().to_vec()).unwrap();
    for (key, mirror) in [
        (&b"drift-rewritten"[..], Some(rewritten)),
        (&b"drift-removed"[..], None),
    ] {
        let held = h.hold(
            vec![
                h.leg(Side::Debit, travel, 1_000),
                h.leg(Side::Credit, h.cash, 1_000),
            ],
            key,
            day,
        );
        let hold = h.commit(held, controller());
        h.set_account_mirror(fa_journal::rows::leg_vid(hold.vid, 1), mirror);
        let before = h.db.frontier().unwrap();
        for cap in [tree.clone(), controller()] {
            let r = h.post_outcome(h.voids(hold, b"void", day), cap);
            assert!(
                matches!(&r, Err(KernelError::Corrupt(m)) if m.contains("mirrors drifted")),
                "{r:?}"
            );
            assert_eq!(h.db.frontier().unwrap(), before, "drift wrote");
        }
    }
}

/// CobaltGull 3618/3622 (planted negative): a date a special period shares
/// with a normal one is ambiguous to the metadata, which carries no period
/// discriminator yet, so under a `periods` caveat every such target is out
/// of scope — the A1 Pending and the P12 Pending dated Dec 31 alike — and
/// is refused like a target that does not exist. The same token voids a
/// Pending on an unambiguous December day, and the controller voids both
/// Dec 31 holds. The period mirror that restores the P12 case is slice 2.
#[test]
fn ambiguous_dates_are_out_of_scope_until_the_period_mirror_exists() {
    let mut h = harness();
    let dec15 = DateDay::from_ymd(2026, 12, 15).unwrap();
    let dec31 = DateDay::from_ymd(2026, 12, 31).unwrap();
    h.open(dec15, b"open-p12");
    h.open_code("FY2026-A1", b"open-a1");
    let legs = |h: &Harness| {
        vec![
            h.leg(Side::Debit, h.rent, 100),
            h.leg(Side::Credit, h.cash, 100),
        ]
    };
    // An Adjustment period admits no Pending (the special-period allowlist,
    // admissibility.toml), so a hold can never sit in FY2026-A1 itself; the
    // ambiguity is the date: December 31 is shared by P12 and A1.
    let mut adjustment = h.hold(legs(&h), b"a1-hold", dec31);
    adjustment.effective_period = Some(fa_model::PeriodRef {
        calendar: "cal".into(),
        code: "FY2026-A1".into(),
    });
    let refused = h
        .post(adjustment, controller(), Vec::new())
        .expect_err("an Adjustment period admits no Pending");
    assert_eq!(refused.code, "FA-REF-010", "{refused}");
    let p12_hold = h.commit(h.hold(legs(&h), b"p12-hold", dec31), controller());
    let plain_hold = h.commit(h.hold(legs(&h), b"dec15-hold", dec15), controller());
    let p12 = h.period_of(dec15);
    let december = human(PREPARER, &["post"])
        .for_periods(&[p12.as_str()])
        .unwrap();
    let before = h.db.frontier().unwrap();
    let refused = h.post(
        h.voids(p12_hold, b"void", dec15),
        december.clone(),
        Vec::new(),
    );
    let absent = h.post(
        h.voids(NOWHERE, b"void-0", dec15),
        december.clone(),
        Vec::new(),
    );
    assert_like_absent(
        &h,
        before,
        (refused.unwrap_err(), p12_hold.vid),
        (absent.unwrap_err(), NOWHERE.vid),
    );
    h.post_ok(h.voids(plain_hold, b"void", dec15), december);
    // A committed key binds one intent per principal (plan §5.9), so the
    // second release names its own key.
    h.post_ok(h.voids(p12_hold, b"void-p12", dec15), controller());
}

#[test]
fn identical_period_transition_and_period_create_retries_return_recorded_outcomes_and_changed_retry_conflicts()
 {
    let mut h = harness();
    let closer = human(PREPARER, &["close"]);

    // 1. Retrying create_periods for an already-created fiscal year is idempotent.
    let head_before_create = h.db.frontier().unwrap();
    let ctx = h.ctx();
    let (seq_create, periods_again) = h
        .runtime
        .block_on(async {
            create_periods(
                &mut h.db,
                &ctx,
                &h.book,
                2026,
                PREPARER,
                fa_model::Erasable::seal(
                    &"periods".to_string(),
                    None,
                    &h.book.seal_key,
                    [1; 32],
                    [2; 24],
                ),
                &fa_journal::Capability::embedded(PREPARER, &["schema_change"]).unwrap(),
            )
            .await
        })
        .expect("idempotent create_periods")
        .expect("admitted");
    assert_eq!(h.db.frontier().unwrap(), head_before_create);
    assert!(!periods_again.is_empty());
    assert!(seq_create <= head_before_create);

    // 2. SoftClose March, then retry with the same key and fresh salt on description:
    //    returns the recorded Transitioned without advancing the frontier.
    let first_sc = h
        .transition_with(
            PeriodTransition::SoftClose,
            b"sc-march-idempotent",
            &closer,
            &[],
        )
        .expect("first SoftClose");
    let head_after_sc = h.db.frontier().unwrap();
    assert_eq!(first_sc.from, PeriodState::Open);
    assert_eq!(first_sc.to, PeriodState::SoftClosed);
    let retry_sc = h
        .transition_with(
            PeriodTransition::SoftClose,
            b"sc-march-idempotent",
            &closer,
            &[],
        )
        .expect("identical SoftClose retry returns recorded Transitioned");
    assert_eq!(
        retry_sc,
        Transitioned {
            already_recorded: true,
            ..first_sc
        }
    );
    assert_eq!(h.db.frontier().unwrap(), head_after_sc);

    // 3. Reusing the same idempotency key for a different transition (Close instead
    //    of SoftClose) or a different reason is refused with FA-REF-032
    //    (IDEMPOTENCY_CONFLICT). The period fixes the date (fa-87r), so a
    //    retry cannot differ in it.
    let conflict_transition = h
        .transition_with(
            PeriodTransition::Close,
            b"sc-march-idempotent",
            &closer,
            &[],
        )
        .expect_err("reusing key for Close must conflict");
    assert_eq!(
        (conflict_transition.code, conflict_transition.exit),
        (
            fa_journal::refusal::code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT
        ),
        "{conflict_transition}"
    );
    assert_eq!(h.db.frontier().unwrap(), head_after_sc);

    let march = h.march.clone();
    let conflict_reason = h
        .transition_of(
            PeriodTransition::SoftClose,
            b"sc-march-idempotent",
            &closer,
            &march,
            2,
        )
        .expect_err("reusing key with a different reason must conflict");
    assert_eq!(
        (conflict_reason.code, conflict_reason.exit),
        (
            fa_journal::refusal::code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT
        ),
        "{conflict_reason}"
    );
    assert_eq!(h.db.frontier().unwrap(), head_after_sc);

    // 4. Open April and retry Open with the same key: returns the recorded outcome.
    let apr1 = DateDay::from_ymd(2026, 4, 1).unwrap();
    let apr = h.period_of(apr1);
    let first_open = h
        .transition_of(
            PeriodTransition::Open,
            b"open-apr-idempotent",
            &closer,
            &apr,
            1,
        )
        .expect("first Open");
    let head_after_open = h.db.frontier().unwrap();
    let retry_open = h
        .transition_of(
            PeriodTransition::Open,
            b"open-apr-idempotent",
            &closer,
            &apr,
            1,
        )
        .expect("identical Open retry returns recorded Transitioned");
    assert_eq!(
        retry_open,
        Transitioned {
            already_recorded: true,
            ..first_open
        }
    );
    assert_eq!(h.db.frontier().unwrap(), head_after_open);
}

// ---------------------------------------------------------------------------
// Capability issuance (plan §14.2, bead fa-v62)
// ---------------------------------------------------------------------------

impl Harness {
    fn issue(
        &mut self,
        issuer: &Capability,
        issued: &Capability,
        key: &[u8],
    ) -> Result<Issued, Refusal> {
        let ctx = self.ctx();
        let req = IssuanceRequest {
            capability: issuer.clone(),
            issued: issued.clone(),
            effective_date: DateDay::from_ymd(2026, 3, 1).unwrap(),
            idempotency_key: key.to_vec(),
            description: Erasable::seal(
                &"issue".to_string(),
                None,
                &self.book.seal_key,
                [7; 32],
                [8; 24],
            ),
        };
        let db = &mut self.db;
        let book = &self.book;
        self.runtime
            .block_on(async move { issue_capability(db, &ctx, book, req).await })
            .expect("kernel")
    }
}

/// fa-v62: a steward issues a holder-bound token; the kernel admits it only
/// against its journaled issuance (a forged body is another commitment), a
/// retry is the recorded issuance, revocation applies as to any capability,
/// and an issuance never widens the issuer.
#[test]
fn an_issued_holder_bound_capability_is_admitted_only_against_its_journaled_issuance() {
    let mut h = harness();
    // The steward holds every op it grants below (the grant law refuses a
    // widening, as the `close` probe shows).
    let steward = human(PREPARER, &["read", "post", "issue_capability"]);
    let secret = [9; 32];
    let token = Capability::new(ALICE, Profile::Human, &[Op::Post], PREPARER)
        .unwrap()
        .holder_bound(possession_digest(&secret));

    // Before its issuance the holder-bound token is refused; nothing is written.
    let head = h.db.frontier().unwrap();
    let r = h
        .post(
            h.proposal(ALICE, 1_000, b"alice-1", EntryClass::ORIGINAL),
            token.clone(),
            Vec::new(),
        )
        .unwrap_err();
    eprintln!("issuance: unissued token -> {} {}", r.code, r.message);
    assert_eq!((r.code, r.exit), ("FA-REF-156", exit::SAFETY));
    assert_eq!(h.db.frontier().unwrap(), head);

    let issued = h.issue(&steward, &token, b"issue-alice").expect("issued");
    assert!(!issued.already_recorded);
    assert_eq!(issued.commitment, token.commitment().unwrap());
    let again = h.issue(&steward, &token, b"issue-alice").expect("a retry");
    assert!(again.already_recorded);
    assert_eq!(again.recorded_at, issued.recorded_at);
    let read = read_issued(&h.db, &h.book, &issued.commitment)
        .unwrap()
        .expect("journaled");
    assert_eq!(read.capability, token, "the caveats come from the journal");
    assert_eq!(read.revoked_at, None);
    assert_eq!(list_issued(&h.db, &h.book).unwrap().len(), 1);

    h.post(
        h.proposal(ALICE, 1_000, b"alice-1", EntryClass::ORIGINAL),
        token.clone(),
        Vec::new(),
    )
    .expect("the issued token posts");

    // A body that differs from the journaled one (here: an extra op) is
    // another commitment, which was never issued.
    let forged = Capability::new(ALICE, Profile::Human, &[Op::Post, Op::PostClosed], PREPARER)
        .unwrap()
        .holder_bound(possession_digest(&secret));
    let r = h
        .post(
            h.proposal(ALICE, 1_000, b"alice-2", EntryClass::ORIGINAL),
            forged,
            Vec::new(),
        )
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-156");

    // Revocation applies to an issued token as to any capability.
    h.revoke(&steward, &token, b"revoke-alice")
        .expect("revoked");
    let r = h
        .post(
            h.proposal(ALICE, 1_000, b"alice-3", EntryClass::ORIGINAL),
            token.clone(),
            Vec::new(),
        )
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-023");
    assert!(
        read_issued(&h.db, &h.book, &issued.commitment)
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );

    // The grant law: no op the issuer lacks; issue_capability is required;
    // the body is holder-bound and names its issuer.
    let head = h.db.frontier().unwrap();
    let widen = Capability::new(BOB, Profile::Human, &[Op::Post, Op::Close], PREPARER)
        .unwrap()
        .holder_bound(possession_digest(&[1; 32]));
    let r = h.issue(&steward, &widen, b"issue-bob").unwrap_err();
    eprintln!("issuance: widening -> {} {}", r.code, r.message);
    assert_eq!((r.code, r.exit), ("FA-REF-011", exit::SAFETY));
    assert!(r.message.contains("close"), "{}", r.message);
    let narrow = Capability::new(BOB, Profile::Human, &[Op::Post], PREPARER)
        .unwrap()
        .holder_bound(possession_digest(&[1; 32]));
    let r = h
        .issue(&human(PREPARER, &["post"]), &narrow, b"issue-bob")
        .unwrap_err();
    assert_eq!(
        r.code, "FA-REF-011",
        "the issuer must hold issue_capability"
    );
    let unbound = Capability::new(BOB, Profile::Human, &[Op::Post], PREPARER).unwrap();
    assert_eq!(
        h.issue(&steward, &unbound, b"issue-unbound")
            .unwrap_err()
            .exit,
        exit::USAGE
    );
    let other_issuer = Capability::new(BOB, Profile::Human, &[Op::Post], CAROL)
        .unwrap()
        .holder_bound(possession_digest(&[1; 32]));
    assert_eq!(
        h.issue(&steward, &other_issuer, b"issue-other")
            .unwrap_err()
            .exit,
        exit::USAGE
    );
    assert_eq!(
        h.db.frontier().unwrap(),
        head,
        "refused issuances write nothing"
    );

    // An issued Agent token reads and is still never a trunk writer.
    let agent = Capability::new(AGENT, Profile::Agent, &[Op::Read, Op::Post], PREPARER)
        .unwrap()
        .holder_bound(possession_digest(&[2; 32]));
    h.issue(&steward, &agent, b"issue-agent")
        .expect("an Agent token is issued");
    let r = h
        .post(
            h.proposal(AGENT, 1_000, b"agent-1", EntryClass::ORIGINAL),
            agent,
            Vec::new(),
        )
        .unwrap_err();
    assert_eq!(r.code, "FA-REF-013");
    assert_eq!(list_issued(&h.db, &h.book).unwrap().len(), 2);
}

/// fa-0x0: an issuance never drops its issuer's caveats. Issuance is a
/// whole-book act, so an issuer confined by a scope caveat (here a period)
/// issues nothing at all; an issuer confined to a redaction contract issues
/// only grants that keep it.
#[test]
fn an_issuance_never_drops_its_issuers_caveats() {
    let mut h = harness();
    let grant = |holder| {
        Capability::new(holder, Profile::Human, &[Op::Read], PREPARER)
            .unwrap()
            .holder_bound(possession_digest(&[3; 32]))
    };
    let head = h.db.frontier().unwrap();

    let scoped = human(PREPARER, &["read", "issue_capability"])
        .for_periods(&["FY2026-P03"])
        .unwrap();
    let narrow = grant(BOB).for_periods(&["FY2026-P03"]).unwrap();
    let r = h.issue(&scoped, &narrow, b"scoped-issuer").unwrap_err();
    eprintln!("issuance: scoped issuer -> {} {}", r.code, r.message);
    assert_eq!((r.code, r.exit), ("FA-REF-011", exit::SAFETY));
    assert!(r.message.contains("`periods`"), "{}", r.message);
    assert_eq!(h.db.frontier().unwrap(), head);

    let redacted = human(PREPARER, &["read", "issue_capability"])
        .with_redaction(1)
        .unwrap();
    let r = h
        .issue(&redacted, &grant(BOB), b"drops-redaction")
        .unwrap_err();
    eprintln!("issuance: redaction dropped -> {} {}", r.code, r.message);
    assert_eq!((r.code, r.exit), ("FA-REF-011", exit::SAFETY));
    assert!(r.message.contains("redaction = 1"), "{}", r.message);
    assert_eq!(h.db.frontier().unwrap(), head);
    let kept = grant(BOB).with_redaction(1).unwrap();
    let issued = h
        .issue(&redacted, &kept, b"keeps-redaction")
        .expect("a grant that keeps the redaction caveat");
    assert_eq!(issued.commitment, kept.commitment().unwrap());
}

/// fa-v62: revoking an issuer capability cascades to every capability it
/// issued (and their descendants), refusing both writes and reads with
/// FA-REF-023 and reporting `revoked_at` in `read_issued` / `list_issued`.
#[test]
fn revoking_an_issuer_cascades_to_revoke_its_issued_children_and_grandchildren() {
    let mut h = harness();
    let root_steward = human(PREPARER, &["read", "post", "issue_capability"]);
    let other_steward = human(CAROL, &["read", "issue_capability"]);

    // 1. Root steward issues a delegate capability to ALICE (holding read, post, issue_capability),
    //    and ALICE issues an attenuated leaf capability to BOB (holding read, post).
    let alice_delegate = Capability::new(
        ALICE,
        Profile::Human,
        &[Op::Read, Op::Post, Op::IssueCapability],
        PREPARER,
    )
    .unwrap()
    .holder_bound(possession_digest(&[0x11; 32]));
    let alice_issued = h
        .issue(&root_steward, &alice_delegate, b"issue-alice-delegate")
        .expect("issue alice delegate");

    let bob_leaf = Capability::new(BOB, Profile::Human, &[Op::Read, Op::Post], ALICE)
        .unwrap()
        .holder_bound(possession_digest(&[0x22; 32]));
    let bob_issued = h
        .issue(&alice_delegate, &bob_leaf, b"issue-bob-leaf")
        .expect("alice issues bob leaf");

    // Both ALICE and BOB are admitted for reads and posts before revocation.
    admit_reads(&h.db, &h.book, ALICE, &alice_delegate)
        .unwrap()
        .expect("alice reads admitted");
    admit_reads(&h.db, &h.book, BOB, &bob_leaf)
        .unwrap()
        .expect("bob reads admitted");
    h.post(
        h.proposal(BOB, 500, b"bob-before-revoke", EntryClass::ORIGINAL),
        bob_leaf.clone(),
        Vec::new(),
    )
    .expect("bob posts before parent revocation");

    // 2. Revoke the root_steward capability (an embedded issuer): both ALICE
    //    (child) and BOB (grandchild) are immediately revoked by cascade!
    let revoked = h
        .revoke(&other_steward, &root_steward, b"revoke-root-steward")
        .expect("revoke root steward");

    for (who, cap, key) in [
        (ALICE, &alice_delegate, &b"alice-after-cascade"[..]),
        (BOB, &bob_leaf, &b"bob-after-cascade"[..]),
    ] {
        let write_refusal = h
            .post(
                h.proposal(who, 500, key, EntryClass::ORIGINAL),
                cap.clone(),
                Vec::new(),
            )
            .expect_err("write must be refused after ancestor issuer revocation");
        assert_eq!(write_refusal.code, "FA-REF-023", "{write_refusal}");
        assert!(
            write_refusal
                .message
                .contains(&format!("sequence {}", revoked.recorded_at.0)),
            "{}",
            write_refusal.message
        );
        let read_refusal = admit_reads(&h.db, &h.book, who, cap)
            .unwrap()
            .expect_err("read must be refused after ancestor issuer revocation");
        assert_eq!(read_refusal.code, "FA-REF-023", "{read_refusal}");
    }

    for commitment in [alice_issued.commitment, bob_issued.commitment] {
        let info = read_issued(&h.db, &h.book, &commitment)
            .unwrap()
            .expect("issued record exists");
        assert_eq!(info.revoked_at, Some(revoked.recorded_at));
    }
}
