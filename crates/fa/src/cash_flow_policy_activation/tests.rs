use super::*;

use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{AccountSpec, BookSpec, UnitPolicy};
use fa_time::FiscalCalendar;
use fgdb::MemVfs;

use crate::{BookKeys, Entropy};

const PREPARER: VId = VId(1);

fn day(value: u8) -> DateDay {
    DateDay::from_ymd(2026, 1, value).unwrap()
}
fn cap(principal: VId, ops: &[&str]) -> Capability {
    Capability::embedded(principal, ops).unwrap()
}
fn account(code: &str, kind: AccountType) -> AccountSpec {
    AccountSpec {
        code: code.into(),
        name: code.into(),
        account_type: kind.0,
        normal_balance: u8::from(matches!(
            kind,
            AccountType::LIABILITY | AccountType::REVENUE
        )),
        is_leaf: true,
        unit_policy: UnitPolicy::AnyCurrency,
        parent_code: None,
        limit: None,
    }
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    book: AsyncBook<MemVfs>,
}

impl Harness {
    fn new() -> Self {
        Self::with_extra_rules(0)
    }

    fn with_extra_rules(extra_rules: usize) -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let units = fa_money::UnitRegistry::embedded().unwrap();
        let spec = BookSpec {
            book_id: Id128([182; 16]),
            name: "Approved cash policies".into(),
            base_unit: units.lookup("USD").unwrap(),
            calendar: FiscalCalendar::monthly("cash-policy-activation", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs,
                Path::new("approved-cash-policies"),
                BookKeys::for_development(182),
                spec,
                Entropy::deterministic(182),
            ))
            .unwrap();
        let mut accounts = vec![
            account("1000", AccountType::ASSET),
            account("2000", AccountType::LIABILITY),
            account("4000", AccountType::REVENUE),
            account("6000", AccountType::EXPENSE),
        ];
        accounts.extend((0..extra_rules).map(|i| account(&format!("r{i}"), AccountType::REVENUE)));
        runtime
            .block_on(book.install_chart(
                &cx,
                &accounts,
                PREPARER,
                day(1),
                b"chart",
                &cap(PREPARER, &["schema_change"]),
            ))
            .unwrap()
            .unwrap();
        Self {
            runtime,
            root,
            book,
        }
    }
    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }
    fn head(&self) -> CommitSeq {
        self.book.head(&self.cx()).unwrap()
    }
    fn id(&self, code: &str) -> u128 {
        fa_model::account_vid(self.book.context.book_id, code).0
    }
    fn definition(&self, version: u32) -> CashFlowPolicyDefinition {
        let mut cash_accounts = vec![self.id("1000"), self.id("2000")];
        cash_accounts.sort_unstable();
        let mut account_rules = vec![(self.id("4000"), 0), (self.id("6000"), 0)];
        account_rules.sort_unstable();
        CashFlowPolicyDefinition {
            name: "company-cash".into(),
            version,
            cash_accounts,
            account_rules,
        }
    }
    fn plan(&self, version: u32, from: u8, key: &[u8]) -> CashFlowPolicyPlan {
        self.book
            .plan_cash_flow_policy(
                &self.cx(),
                &cap(PREPARER, &["rule_change"]),
                self.definition(version),
                day(from),
                key,
            )
            .unwrap()
            .unwrap()
    }
    fn approval(&mut self, plan: &CashFlowPolicyPlan, principal: VId) -> ApprovalRef {
        let cx = self.cx();
        self.runtime
            .block_on(fa_journal::policy::record_approval(
                &mut self.book.db,
                &cx,
                &self.book.context,
                fa_journal::ApprovalRequest {
                    capability: cap(principal, &["approve"]),
                    approved_proposal_digest: plan.proposal_digest().unwrap(),
                    role: 0,
                },
            ))
            .unwrap()
            .unwrap()
            .approval()
    }
    fn approve(&mut self, plan: &CashFlowPolicyPlan) -> Vec<ApprovalRef> {
        vec![self.approval(plan, VId(2)), self.approval(plan, VId(3))]
    }
    fn activate(
        &mut self,
        plan: CashFlowPolicyPlan,
        approvals: Vec<ApprovalRef>,
    ) -> Outcome<ActivatedCashFlowPolicy> {
        let cx = self.cx();
        self.runtime.block_on(self.book.activate_cash_flow_policy(
            &cx,
            &cap(PREPARER, &["rule_change"]),
            plan,
            approvals,
        ))
    }
    fn lookup(
        &self,
        from: u8,
        through: u8,
        at: CommitSeq,
    ) -> Outcome<Option<ActivatedCashFlowPolicy>> {
        self.book.active_cash_flow_policy(
            &self.cx(),
            &cap(PREPARER, &["read"]),
            "company-cash",
            day(from),
            day(through),
            at,
        )
    }
}

#[test]
fn approved_cash_policy_activates_atomically_and_retries_without_advancing_history() {
    let mut h = Harness::new();
    let before_plan = h.head();
    let plan = h.plan(1, 1, b"cash-policy-one");
    assert_eq!(h.head(), before_plan);
    assert_eq!(
        CashFlowPolicyPlan::decode(&plan.encode().unwrap()).unwrap(),
        plan
    );
    let bytes = plan.encode().unwrap();
    for end in 0..bytes.len() {
        assert!(CashFlowPolicyPlan::decode(&bytes[..end]).is_err());
    }
    let approvals = h.approve(&plan);
    let before = h.head();
    let active = h
        .activate(plan.clone(), approvals.clone())
        .unwrap()
        .unwrap();
    assert!(!active.already_recorded);
    assert!(active.recorded_at > before);
    assert_eq!(active.definition_digest, plan.definition.digest().unwrap());
    assert_eq!(active.policy.account_rules.len(), 2);
    assert!(active.policy.overrides.is_empty());
    assert!(h.lookup(1, 31, before).unwrap().unwrap().is_none());
    assert_eq!(
        h.lookup(1, 31, active.recorded_at)
            .unwrap()
            .unwrap()
            .unwrap(),
        active
    );
    let again = h.activate(plan, approvals).unwrap().unwrap();
    assert!(again.already_recorded);
    assert_eq!(again.activation, active.activation);
    assert_eq!(h.head(), active.recorded_at);
    assert!(h.book.verify_projections(&h.cx(), None).unwrap().is_green());
}

#[test]
fn cash_policy_chunked_entry_retains_the_complete_approved_definition() {
    let mut h = Harness::with_extra_rules(180);
    let mut definition = h.definition(1);
    definition
        .account_rules
        .extend((0..180).map(|i| (h.id(&format!("r{i}")), 0)));
    definition.account_rules.sort_unstable();
    let mut plan = h
        .book
        .plan_cash_flow_policy(
            &h.cx(),
            &cap(PREPARER, &["rule_change"]),
            definition.clone(),
            day(1),
            b"chunked-cash-policy",
        )
        .unwrap()
        .unwrap();
    plan.description = h.book.seal_text(&h.cx(), &"x".repeat(1024)).unwrap();
    let approvals = h.approve(&plan);
    let encoded = plan
        .proposal()
        .unwrap()
        .seal(approvals.clone(), None)
        .unwrap()
        .encode()
        .unwrap();
    assert!(encoded.len() > fa_journal::object::CHUNK_BYTES);
    let active = h
        .activate(plan.clone(), approvals.clone())
        .unwrap()
        .unwrap();
    let row = h.book.db.vertex(active.activation).unwrap().unwrap();
    assert_eq!(
        fa_journal::entry_storage::payload_at(&h.book.db, &row, active.recorded_at).unwrap(),
        encoded
    );
    assert_eq!(
        h.lookup(1, 31, active.recorded_at)
            .unwrap()
            .unwrap()
            .unwrap()
            .policy
            .account_rules
            .len(),
        182
    );
    assert_eq!(active.definition_digest, definition.digest().unwrap());
    let before = h.head();
    assert!(
        h.activate(plan, approvals)
            .unwrap()
            .unwrap()
            .already_recorded
    );
    assert_eq!(h.head(), before);
    assert!(h.book.verify_projections(&h.cx(), None).unwrap().is_green());
}

#[test]
fn cash_policy_history_pins_recorded_prefix_and_refuses_a_version_change_inside_the_report() {
    let mut h = Harness::new();
    let first_plan = h.plan(1, 1, b"cash-v1");
    let first_approvals = h.approve(&first_plan);
    let first = h
        .activate(first_plan.clone(), first_approvals.clone())
        .unwrap()
        .unwrap();
    let mut second_plan = h.plan(2, 15, b"cash-v2");
    second_plan.definition.account_rules[0].1 = 1;
    let second_approvals = h.approve(&second_plan);
    let second = h.activate(second_plan, second_approvals).unwrap().unwrap();
    assert_eq!(
        h.lookup(1, 31, first.recorded_at)
            .unwrap()
            .unwrap()
            .unwrap()
            .activation,
        first.activation
    );
    assert_eq!(
        h.lookup(1, 14, second.recorded_at)
            .unwrap()
            .unwrap()
            .unwrap()
            .activation,
        first.activation
    );
    assert_eq!(
        h.lookup(15, 31, second.recorded_at)
            .unwrap()
            .unwrap()
            .unwrap()
            .activation,
        second.activation
    );
    assert!(h.lookup(1, 31, second.recorded_at).unwrap().is_err());
    assert!(h.lookup(31, 1, second.recorded_at).unwrap().is_err());
    assert!(
        h.lookup(1, 1, CommitSeq(second.recorded_at.0 + 1))
            .unwrap()
            .is_err()
    );
    let before = h.head();
    assert!(
        h.activate(first_plan, first_approvals)
            .unwrap()
            .unwrap()
            .already_recorded
    );
    assert_eq!(h.head(), before);
    assert!(
        h.book
            .plan_cash_flow_policy(
                &h.cx(),
                &cap(PREPARER, &["rule_change"]),
                h.definition(2),
                day(16),
                b"same-version"
            )
            .unwrap()
            .is_err()
    );
    assert!(
        h.book
            .plan_cash_flow_policy(
                &h.cx(),
                &cap(PREPARER, &["rule_change"]),
                h.definition(3),
                day(15),
                b"same-date"
            )
            .unwrap()
            .is_err()
    );
}

#[test]
fn cash_policy_requires_independent_humans_and_unchanged_approved_content() {
    let mut h = Harness::new();
    let plan = h.plan(1, 1, b"cash-approval-law");
    let first = h.approval(&plan, VId(2));
    let self_approval = h.approval(&plan, PREPARER);
    let before = h.head();
    for approvals in [
        vec![],
        vec![first],
        vec![first, first],
        vec![first, self_approval],
    ] {
        assert!(h.activate(plan.clone(), approvals).unwrap().is_err());
        assert_eq!(h.head(), before);
    }
    let second = h.approval(&plan, VId(3));
    let before = h.head();
    let mut changed = plan.clone();
    changed.definition.account_rules[0].1 = 2;
    assert!(h.activate(changed, vec![first, second]).unwrap().is_err());
    assert_eq!(h.head(), before);
    let active = h.activate(plan, vec![first, second]).unwrap().unwrap();
    let next = h.plan(2, 2, b"cash-approval-law");
    let approvals = h.approve(&next);
    let before = h.head();
    assert_eq!(
        h.activate(next, approvals).unwrap().unwrap_err().code,
        fa_journal::refusal::code::IDEMPOTENCY_CONFLICT
    );
    assert_eq!(h.head(), before);
    assert_eq!(
        h.lookup(1, 31, before)
            .unwrap()
            .unwrap()
            .unwrap()
            .activation,
        active.activation
    );
}

#[test]
fn cash_policy_chart_change_invalidates_review_even_when_named_accounts_remain_valid() {
    let mut h = Harness::new();
    let plan = h.plan(1, 1, b"cash-chart");
    let approvals = h.approve(&plan);
    let cx = h.cx();
    h.runtime
        .block_on(h.book.open_account(
            &cx,
            &account("6100", AccountType::EXPENSE),
            day(1),
            None,
            PREPARER,
            day(1),
            b"new-expense",
            &cap(PREPARER, &["schema_change"]),
        ))
        .unwrap()
        .unwrap();
    let before = h.head();
    assert_eq!(
        h.activate(plan, approvals).unwrap().unwrap_err().exit,
        fa_journal::exit::CONFLICT
    );
    assert_eq!(h.head(), before);
    let fresh = h.plan(1, 1, b"cash-chart-fresh");
    let approvals = h.approve(&fresh);
    h.activate(fresh, approvals).unwrap().unwrap();
}

#[test]
fn cash_policy_authority_and_rehearsal_caveats_precede_publication() {
    let mut h = Harness::new();
    let cap_wrong_class = cap(PREPARER, &["rule_change"])
        .for_classes(&[EntryClass::ORIGINAL])
        .unwrap();
    let before = h.head();
    for denied in [cap(PREPARER, &["read"]), cap_wrong_class] {
        assert!(
            h.book
                .plan_cash_flow_policy(&h.cx(), &denied, h.definition(1), day(1), b"unauthorized")
                .unwrap()
                .is_err()
        );
        assert_eq!(h.head(), before);
    }
    let scoped = cap(PREPARER, &["rule_change"])
        .for_classes(&[EntryClass::POLICY_CONTROL])
        .unwrap();
    assert!(
        h.book
            .admit_cash_flow_policy(&h.cx(), &scoped, true)
            .unwrap()
            .is_ok()
    );
    assert!(
        h.book
            .admit_cash_flow_policy(&h.cx(), &scoped, false)
            .unwrap()
            .is_ok()
    );
    let rehearsal = scoped.with_requires_dry_run();
    let plan = h
        .book
        .plan_cash_flow_policy(
            &h.cx(),
            &rehearsal,
            h.definition(1),
            day(1),
            b"requires-rehearsal",
        )
        .unwrap()
        .unwrap();
    let approvals = h.approve(&plan);
    let before = h.head();
    let cx = h.cx();
    let refused = h
        .runtime
        .block_on(h.book.activate_cash_flow_policy(
            &cx,
            &rehearsal,
            plan.clone(),
            approvals.clone(),
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.exit, fa_journal::exit::SAFETY);
    assert_eq!(h.head(), before);
    h.activate(plan, approvals).unwrap().unwrap();
    assert!(
        h.book
            .active_cash_flow_policy(
                &h.cx(),
                &cap(PREPARER, &["rule_change"]),
                "company-cash",
                day(1),
                day(31),
                h.head()
            )
            .unwrap()
            .is_err()
    );
}

#[test]
fn cash_policy_malformed_scope_and_raw_control_cannot_bypass_activation() {
    let mut h = Harness::new();
    for bad in 0..5 {
        let mut definition = h.definition(1);
        match bad {
            0 => definition.cash_accounts = vec![h.id("4000")],
            1 => definition.cash_accounts = vec![99],
            2 => definition.account_rules = vec![(99, 0)],
            3 => definition.account_rules[0].1 = 4,
            _ => definition.account_rules = vec![(definition.cash_accounts[0], 0)],
        }
        assert!(
            h.book
                .plan_cash_flow_policy(
                    &h.cx(),
                    &cap(PREPARER, &["rule_change"]),
                    definition,
                    day(1),
                    b"bad-policy"
                )
                .unwrap()
                .is_err()
        );
    }
    let plan = h.plan(1, 1, b"raw-cash-control");
    let proposal = plan.proposal().unwrap();
    proposal.validate_for_write().unwrap();
    for bad in 0..6 {
        let mut malformed = proposal.clone();
        match bad {
            0 => malformed.extensions.clear(),
            1 => malformed.schema_minor = fa_model::entry::CASH_FLOW_POLICY_MINOR - 1,
            2 => malformed.extensions[0].1.push(0),
            3 => {
                malformed.origin = EntryOrigin::Control {
                    control_kind: ControlKind::POLICY_ACTIVATION,
                    spec_body_digest: [0; 32],
                }
            }
            4 => {
                if let Some(ControlPayload::LifecycleTransition { object_ref, .. }) =
                    &mut malformed.control
                {
                    *object_ref = VId(77);
                }
            }
            _ => malformed.class = EntryClass::SCHEMA_CONTROL,
        }
        assert!(
            malformed.validate_for_write().is_err(),
            "malformed case {bad}"
        );
    }
    let mut future = proposal.clone();
    future.schema_minor = fa_model::entry::SCHEMA_MINOR + 1;
    assert!(future.validate().is_ok());
    assert!(future.validate_for_write().is_err());
    let approvals = h.approve(&plan);
    let before = h.head();
    let cx = h.cx();
    assert!(
        h.runtime
            .block_on(h.book.post(
                &cx,
                fa_journal::PostRequest {
                    proposal,
                    approvals: approvals.clone(),
                    plan_certificate: None,
                    capability: cap(PREPARER, &["rule_change", "post"]),
                }
            ))
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), before);
    h.activate(plan, approvals).unwrap().unwrap();
}

#[test]
fn cash_policy_history_rejects_a_control_injected_without_its_atomic_intent_claim() {
    let mut h = Harness::new();
    let plan = h.plan(1, 1, b"missing-cash-intent-claim");
    let approvals = h.approve(&plan);
    let entry = plan.proposal().unwrap().seal(approvals, None).unwrap();
    let vid = entry_vid(
        plan.book_id,
        &plan.principal_ref.0.to_le_bytes(),
        &plan.idempotency_key,
    );
    let cx = h.cx();
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    fa_journal::entry_storage::stage(&cx.query(), &mut batch, &entry, vid).unwrap();
    batch.create_vertex(
        vid,
        vec![label::ENTRY],
        fa_journal::entry_storage::stored_mirrors(&entry).unwrap(),
    );
    let mut txn = h.book.db.begin(&cx.txn()).unwrap();
    txn.write(&mut h.book.db, batch).unwrap();
    h.runtime
        .block_on(txn.commit(&mut h.book.db, &cx.commit()))
        .unwrap();
    assert!(matches!(
        h.lookup(1, 31, h.head()),
        Err(BookError::Kernel(KernelError::Corrupt(_)))
    ));
    assert!(!h.book.verify_projections(&h.cx(), None).unwrap().is_green());
}
