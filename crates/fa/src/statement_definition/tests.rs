use super::*;

use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{AccountSpec, BookSpec, UnitPolicy};
use fa_model::AccountType;
use fa_statements::{
    StatementDefinition,
    custom::{CustomLineDefinition, CustomLineSource},
};
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

fn definition(version: u32) -> CustomStatementDefinition {
    let mut definition = CustomStatementDefinition::from_builtin(
        &StatementDefinition::embedded("income-statement").unwrap(),
    );
    definition.name = "company-income".into();
    definition.version = version;
    definition
}

fn account(code: &str, kind: AccountType) -> AccountSpec {
    AccountSpec {
        code: code.into(),
        name: code.into(),
        account_type: kind.0,
        normal_balance: u8::from(kind == AccountType::REVENUE),
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
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let units = fa_money::UnitRegistry::embedded().unwrap();
        let spec = BookSpec {
            book_id: Id128([181; 16]),
            name: "Approved statement layouts".into(),
            base_unit: units.lookup("USD").unwrap(),
            calendar: FiscalCalendar::monthly("custom-statements", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs,
                Path::new("custom-statements"),
                BookKeys::for_development(181),
                spec,
                Entropy::deterministic(181),
            ))
            .unwrap();
        runtime
            .block_on(book.install_chart(
                &cx,
                &[
                    account("1000", AccountType::ASSET),
                    account("4000", AccountType::REVENUE),
                    account("6000", AccountType::EXPENSE),
                ],
                PREPARER,
                day(1),
                b"chart",
                &cap(PREPARER, &["schema_change"]),
            ))
            .unwrap()
            .unwrap();
        runtime
            .block_on(book.create_periods(&cx, 2026, PREPARER, &cap(PREPARER, &["schema_change"])))
            .unwrap()
            .unwrap();
        runtime
            .block_on(book.transition_period(
                &cx,
                "FY2026-P01",
                fa_time::PeriodTransition::Open,
                PREPARER,
                1,
                b"open-january",
                &cap(PREPARER, &["close"]),
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

    fn plan(
        &self,
        definition: CustomStatementDefinition,
        from: DateDay,
        key: &[u8],
    ) -> StatementDefinitionPlan {
        self.book
            .plan_statement_definition(
                &self.cx(),
                &cap(PREPARER, &["rule_change"]),
                definition,
                from,
                key,
            )
            .unwrap()
            .unwrap()
    }

    fn approval(&mut self, plan: &StatementDefinitionPlan, principal: VId) -> ApprovalRef {
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

    fn approve(&mut self, plan: &StatementDefinitionPlan) -> Vec<ApprovalRef> {
        vec![self.approval(plan, VId(2)), self.approval(plan, VId(3))]
    }

    fn activate(
        &mut self,
        plan: StatementDefinitionPlan,
        approvals: Vec<ApprovalRef>,
    ) -> Outcome<ActivatedStatementDefinition> {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.activate_statement_definition(
                &cx,
                &cap(PREPARER, &["rule_change"]),
                plan,
                approvals,
            ))
    }

    fn post_revenue(&mut self, key: &[u8], amount: i128) {
        let cx = self.cx();
        let source = fa_journal::Document {
            book_id: self.book.context.book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PREPARER,
            bytes: b"Native revenue source for custom statement replay".to_vec(),
        };
        self.runtime
            .block_on(self.book.add_document(&cx, &source))
            .unwrap()
            .unwrap();
        let usd = self.book.context.units.lookup("USD").unwrap();
        let legs = vec![
            fa_model::LegPayload::simple(
                fa_money::Side::Debit,
                fa_model::account_vid(self.book.context.book_id, "1000"),
                fa_money::Amount::new(usd, amount),
            ),
            fa_model::LegPayload::simple(
                fa_money::Side::Credit,
                fa_model::account_vid(self.book.context.book_id, "4000"),
                fa_money::Amount::new(usd, amount),
            ),
        ];
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id: self.book.context.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day(1),
            document_date: None,
            description: self
                .book
                .seal_text(&cx, "Revenue for approved custom statement")
                .unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([29; 32]),
                intent_kind: 1,
            },
            principal_ref: PREPARER,
            session_ref: None,
            evidence: vec![source.evidence_ref(1)],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        self.runtime
            .block_on(self.book.post(
                &cx,
                fa_journal::PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: cap(PREPARER, &["post"]),
                },
            ))
            .unwrap()
            .unwrap();
    }
}

#[test]
fn chunked_definition_activates_atomically_survives_approval_commits_and_retries() {
    let mut harness = Harness::new();
    let mut layout = definition(1);
    for ordinal in 0..32 {
        layout.lines.push(CustomLineDefinition {
            code: format!("extra_{ordinal}"),
            label: "x".repeat(256),
            source: CustomLineSource::Formula {
                add: vec!["revenue".into()],
                subtract: Vec::new(),
            },
        });
    }
    assert!(layout.canonical_bytes().unwrap().len() > object::CHUNK_BYTES);
    let plan = harness.plan(layout.clone(), day(1), b"first-layout");
    assert_eq!(
        StatementDefinitionPlan::decode(&plan.encode().unwrap()).unwrap(),
        plan
    );
    let approvals = harness.approve(&plan);
    let before = harness.head();
    let active = harness
        .activate(plan.clone(), approvals.clone())
        .unwrap()
        .unwrap();
    assert!(!active.already_recorded);
    assert!(active.recorded_at > before);
    let root = statement_definition_vid(harness.book.context.book_id, &active.definition_oid.0);
    let row = harness.book.db.vertex(root).unwrap().unwrap();
    assert_eq!(row.created_at, active.recorded_at);
    assert!(harness.book.db.vertex_at(root, before).unwrap().is_none());
    assert_eq!(
        definition_at(
            &harness.book.db,
            &harness.cx().query(),
            &harness.book.context,
            active.definition_oid,
            active.recorded_at
        )
        .unwrap()
        .0,
        layout
    );
    let repeated = harness.activate(plan, approvals).unwrap().unwrap();
    assert!(repeated.already_recorded);
    assert_eq!(repeated.activation, active.activation);
    assert_eq!(harness.head(), active.recorded_at);
    assert!(
        harness
            .book
            .verify_projections(&harness.cx(), None)
            .unwrap()
            .is_green()
    );
    assert!(
        harness
            .book
            .verify_periods(&harness.cx(), None)
            .unwrap()
            .is_green()
    );
}

#[test]
fn named_history_advances_but_an_explicit_prior_version_remains_replayable() {
    let mut harness = Harness::new();
    let first = harness.plan(definition(1), day(1), b"layout-v1");
    let approvals = harness.approve(&first);
    let first = harness.activate(first, approvals).unwrap().unwrap();
    let second = harness.plan(definition(2), day(2), b"layout-v2");
    let approvals = harness.approve(&second);
    let second = harness.activate(second, approvals).unwrap().unwrap();
    let read = cap(PREPARER, &["read"]);
    let lookup = |day, at| {
        harness
            .book
            .active_statement_definition(&harness.cx(), &read, "company-income", day, at)
            .unwrap()
            .unwrap()
            .unwrap()
    };
    assert_eq!(
        lookup(day(3), first.recorded_at).activation,
        first.activation
    );
    assert_eq!(
        lookup(day(1), second.recorded_at).activation,
        first.activation
    );
    assert_eq!(
        lookup(day(2), second.recorded_at).activation,
        second.activation
    );
    assert!(
        validate_active_at(
            &harness.book.db,
            &harness.cx().query(),
            &harness.book.context,
            &first.definition,
            first.activation,
            day(3),
            second.recorded_at
        )
        .unwrap()
        .is_ok()
    );
    assert!(
        validate_active_at(
            &harness.book.db,
            &harness.cx().query(),
            &harness.book.context,
            &second.definition,
            second.activation,
            day(1),
            second.recorded_at
        )
        .unwrap()
        .is_err()
    );
}

#[test]
fn incomplete_self_and_duplicate_approvals_never_publish_a_definition() {
    let mut harness = Harness::new();
    let plan = harness.plan(definition(1), day(1), b"approval-law");
    let independent = harness.approval(&plan, VId(2));
    let self_approval = harness.approval(&plan, PREPARER);
    let before = harness.head();
    for approvals in [
        vec![independent],
        vec![independent, independent],
        vec![independent, self_approval],
    ] {
        assert!(harness.activate(plan.clone(), approvals).unwrap().is_err());
        assert_eq!(harness.head(), before);
    }
    let oid = plan.definition.digest().unwrap();
    assert!(
        harness
            .book
            .db
            .vertex(statement_definition_vid(
                harness.book.context.book_id,
                &oid.0
            ))
            .unwrap()
            .is_none()
    );
    assert!(
        harness
            .book
            .db
            .vertex(intent_outcome_vid(
                harness.book.context.book_id,
                &PREPARER.0.to_le_bytes(),
                &plan.idempotency_key
            ))
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_chart_change_requires_new_review_even_when_the_definition_still_partitions_it() {
    let mut harness = Harness::new();
    let plan = harness.plan(definition(1), day(1), b"chart-bound");
    let approvals = harness.approve(&plan);
    let cx = harness.cx();
    harness
        .runtime
        .block_on(harness.book.open_account(
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
    let before = harness.head();
    let refusal = harness
        .activate(plan.clone(), approvals)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.exit, fa_journal::exit::CONFLICT);
    assert_eq!(harness.head(), before);
    let fresh = harness.plan(definition(1), day(1), b"chart-bound-fresh");
    assert_ne!(fresh.chart_digest, plan.chart_digest);
    let approvals = harness.approve(&fresh);
    harness.activate(fresh, approvals).unwrap().unwrap();
}

#[test]
fn changed_plan_or_reused_successful_key_is_refused_without_partial_publication() {
    let mut harness = Harness::new();
    let plan = harness.plan(definition(1), day(1), b"one-success");
    let approvals = harness.approve(&plan);
    let mut changed = plan.clone();
    changed.definition.title = "Unreviewed title".into();
    let before = harness.head();
    assert!(
        harness
            .activate(changed, approvals.clone())
            .unwrap()
            .is_err()
    );
    assert_eq!(harness.head(), before);
    let active = harness.activate(plan, approvals).unwrap().unwrap();
    let second = harness.plan(definition(2), day(2), b"one-success");
    let approvals = harness.approve(&second);
    let before = harness.head();
    let refused = harness.activate(second, approvals).unwrap().unwrap_err();
    assert_eq!(
        refused.code,
        fa_journal::refusal::code::IDEMPOTENCY_CONFLICT
    );
    assert_eq!(harness.head(), before);
    let key = intent_outcome_vid(
        harness.book.context.book_id,
        &PREPARER.0.to_le_bytes(),
        b"one-success",
    );
    assert_eq!(
        bytes(
            &harness.book.db.vertex(key).unwrap().unwrap(),
            property::TARGET_REF,
            "successful key"
        )
        .unwrap(),
        active.activation.0.to_le_bytes()
    );
}

#[test]
fn malformed_mappings_are_refused_before_review_and_authority_precedes_chart_observation() {
    let mut harness = Harness::new();
    let mut overlaps = definition(1);
    let mut repeated = overlaps.lines[0].clone();
    repeated.code = "also_revenue".into();
    overlaps.lines.push(repeated);
    assert!(
        harness
            .book
            .plan_statement_definition(
                &harness.cx(),
                &cap(PREPARER, &["rule_change"]),
                overlaps,
                day(1),
                b"overlap"
            )
            .unwrap()
            .is_err()
    );
    let mut missing = definition(1);
    missing.lines[0].source = CustomLineSource::AccountSet {
        expr: fa_statements::custom::AccountSetExpr::AccountCodes(vec!["4999".into()]),
        sign: fa_statements::Sign::Credit,
    };
    assert!(
        harness
            .book
            .plan_statement_definition(
                &harness.cx(),
                &cap(PREPARER, &["rule_change"]),
                missing,
                day(1),
                b"missing"
            )
            .unwrap()
            .is_err()
    );

    let cx = harness.cx();
    let mut damage = WriteBatch::new(relation::IN_BOOK);
    damage.set_vertex_property(
        fa_model::account_vid(harness.book.context.book_id, "4000"),
        property::NAME,
        Some(fa_journal::rows::scalar_text("poisoned chart", "not its journaled name").unwrap()),
    );
    harness
        .runtime
        .block_on(harness.book.db.write(&cx.commit(), damage))
        .unwrap();
    let at = harness.head();
    assert!(
        harness
            .book
            .plan_statement_definition(
                &cx,
                &cap(PREPARER, &["read"]),
                definition(1),
                day(1),
                b"denied"
            )
            .unwrap()
            .is_err()
    );
    assert!(
        harness
            .book
            .lint_statement_definition(&cx, &cap(PREPARER, &["rule_change"]), &definition(1), at)
            .unwrap()
            .is_err()
    );
    assert!(
        harness
            .book
            .active_statement_definition(
                &cx,
                &cap(PREPARER, &["rule_change"]),
                "company-income",
                day(1),
                at
            )
            .unwrap()
            .is_err()
    );
    assert!(
        harness
            .book
            .lint_statement_definition(&cx, &cap(PREPARER, &["read"]), &definition(1), at)
            .is_err(),
        "an authorized read detects the deliberately corrupt chart"
    );
}

#[test]
fn approved_custom_certificate_replays_after_later_posts_and_layout_activation() {
    let mut harness = Harness::new();
    harness.post_revenue(b"first-revenue", 12_345);
    let plan = harness.plan(definition(1), day(1), b"certified-layout-v1");
    let approvals = harness.approve(&plan);
    let first = harness.activate(plan, approvals).unwrap().unwrap();
    let selection = crate::CustomStatementSelection {
        definition: first.definition.clone(),
        activation: first.activation,
        activated_at: first.recorded_at,
        periods: vec!["FY2026-P01".into()],
        comparative: Vec::new(),
        presentation: None,
    };
    let capability = cap(PREPARER, &["read", "produce"]);
    let certified = harness
        .book
        .certify_custom_statement(&harness.cx(), &capability, selection.clone(), None)
        .unwrap()
        .unwrap();
    let encoded = certified.certificate.canonical_bytes().unwrap();
    let decoded = crate::ReportCertificate::decode(&encoded).unwrap();
    assert_eq!(decoded.canonical_bytes().unwrap(), encoded);
    assert_eq!(
        harness
            .book
            .replay_report(&harness.cx(), &decoded)
            .unwrap()
            .unwrap(),
        certified.report
    );

    let crate::ReportSelection::CustomStatement(mut forged_selection) = decoded.selection.clone()
    else {
        panic!("the decoded certificate must retain the approved custom selector");
    };
    forged_selection.activated_at = CommitSeq(first.recorded_at.0 - 1);
    let refused = harness
        .book
        .custom_statement(
            &harness.cx(),
            &capability,
            *forged_selection,
            Some(decoded.known_at),
        )
        .unwrap()
        .unwrap_err();
    assert!(refused.message.contains("declared original commit"));

    let approval_input = decoded
        .inputs
        .iter()
        .position(|input| input.statement.starts_with("MATCH (n:Approval) "))
        .expect("the certificate must bind the original approval rows");
    for remove in [true, false] {
        let mut altered = decoded.clone();
        if remove {
            altered.inputs.remove(approval_input);
        } else {
            altered.inputs.swap(approval_input, 0);
        }
        // Reseal the outer envelope so the refusal specifically checks the
        // required native sources, rather than only a stale content digest.
        let altered = altered.resealed_under(altered.registry_digest);
        let refusal = harness
            .book
            .replay_report(&harness.cx(), &altered)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
        assert!(refusal.message.contains("native input closure"));
    }

    harness.post_revenue(b"later-revenue", 765);
    let mut next_definition = definition(2);
    next_definition.title = "A different current company layout".into();
    let plan = harness.plan(next_definition, day(2), b"certified-layout-v2");
    let approvals = harness.approve(&plan);
    harness.activate(plan, approvals).unwrap().unwrap();
    let current = harness
        .book
        .custom_statement(&harness.cx(), &capability, selection, None)
        .unwrap()
        .unwrap();
    let crate::ReportOutput::CustomStatement(historical) = &certified.report else {
        panic!("the certificate must name the custom statement family");
    };
    assert_ne!(current.statement, historical.statement);
    assert_eq!(
        current.activation, first.activation,
        "an explicit approved layout stays pinned"
    );
    assert_eq!(
        harness
            .book
            .replay_report(&harness.cx(), &decoded)
            .unwrap()
            .unwrap(),
        certified.report
    );
    assert!(
        harness
            .book
            .verify_projections(&harness.cx(), None)
            .unwrap()
            .is_green()
    );
}

#[test]
fn a_rewritten_definition_fails_book_verification_without_poisoning_older_history() {
    let mut harness = Harness::new();
    let plan = harness.plan(definition(1), day(1), b"immutable-layout");
    let approvals = harness.approve(&plan);
    let active = harness.activate(plan, approvals).unwrap().unwrap();
    let root = statement_definition_vid(harness.book.context.book_id, &active.definition_oid.0);
    let cx = harness.cx();
    let mut damage = WriteBatch::new(relation::IN_BOOK);
    damage.set_vertex_property(
        root,
        property::FA_DIGEST,
        Some(scalar_bytes("damaged statement digest", vec![0; 32]).unwrap()),
    );
    harness
        .runtime
        .block_on(harness.book.db.write(&cx.commit(), damage))
        .unwrap();
    let read = cap(PREPARER, &["read"]);
    assert!(
        harness
            .book
            .active_statement_definition(&cx, &read, "company-income", day(1), harness.head())
            .is_err()
    );
    let verified = harness.book.verify_projections(&cx, None).unwrap();
    assert!(!verified.is_green());
    assert!(
        verified
            .drift
            .iter()
            .any(|error| error.contains("statement definition"))
    );
    let old = harness
        .book
        .active_statement_definition(&cx, &read, "company-income", day(1), active.recorded_at)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(old.definition, active.definition);
    assert_eq!(old.activation, active.activation);
}
