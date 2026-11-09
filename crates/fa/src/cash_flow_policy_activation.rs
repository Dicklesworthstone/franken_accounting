//! Immutable, independently approved cash-flow classification policy versions.
//!
//! Activations retain the complete classification body in a typed journal
//! extension, bind its reviewed chart and require two independent Human
//! approvals. Named reads pin both recorded history and the complete effective
//! interval. Report certificates continue to certify their exact policy inputs
//! and arithmetic; the activation citation is separate authorization evidence.

use std::collections::BTreeMap;

use asupersync::fs::Vfs;
use fa_journal::outcome;
use fa_journal::{BookContext, KernelError, Refusal};
use fa_model::cash_flow_policy::CASH_FLOW_POLICY_ACTIVATION_REASON;
use fa_model::limits::{
    MAX_CASH_FLOW_POLICY_DEFINITION_BYTES, MAX_CASH_FLOW_POLICY_PLAN_BYTES, MAX_DESCRIPTION_BYTES,
    MAX_IDEMPOTENCY_KEY_BYTES,
};
use fa_model::symbols::{label, property, relation};
use fa_model::{
    AccountType, ApprovalRef, CashFlowPolicyDefinition, ControlKind, ControlPayload, Entry,
    EntryClass, EntryOrigin, EntryPayload, Erasable, Id128, Oid, Reader, TypedRef, Writer,
    entry_vid, intent_outcome_vid,
};
use fa_policy::{Capability, Intent, Op, Party, Reach};
use fa_statements::Account;
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteTxnError};
use fgdb_types::{CanonicalScalar, CommitSeq, QueryCx, VId, context::PurposeContexts};

use crate::cash_flow_policy::{CashFlowAccountRule, CashFlowPolicy};
use crate::general_ledger::CashFlowActivity;
use crate::statement_definition::{accounts_and_basis, admit_read, approvals_at, original};
use crate::{AsyncBook, BookError, Outcome};

pub const CASH_FLOW_POLICY_PLAN_FORMAT: &[u8] = b"fa:cash-flow-policy-plan:v1";

/// The unchanged proposal reviewed by approvers. Recording time is assigned by
/// the native commit stream and is never supplied by the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowPolicyPlan {
    pub book_id: Id128,
    pub definition: CashFlowPolicyDefinition,
    pub principal_ref: VId,
    pub effective_from: DateDay,
    pub chart_digest: [u8; 32],
    pub idempotency_key: Vec<u8>,
    pub description: Erasable<String>,
}

impl CashFlowPolicyPlan {
    pub fn proposal(&self) -> Result<EntryPayload, KernelError> {
        self.definition.validate().map_err(corrupt)?;
        let definition_digest = self.definition.digest()?;
        Ok(EntryPayload {
            schema_minor: fa_model::entry::CASH_FLOW_POLICY_MINOR,
            book_id: self.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::POLICY_CONTROL,
            effective_date: self.effective_from,
            document_date: None,
            description: self.description.clone(),
            effective_period: None,
            legs: Vec::new(),
            control: Some(ControlPayload::LifecycleTransition {
                object_ref: entry_vid(
                    self.book_id,
                    &self.principal_ref.0.to_le_bytes(),
                    &self.idempotency_key,
                ),
                from: 0,
                to: 1,
                proof_refs: vec![TypedRef::Object(Oid(self.chart_digest))],
                reason_code: CASH_FLOW_POLICY_ACTIVATION_REASON,
            }),
            unit_totals: Vec::new(),
            base_totals: None,
            idempotency_key: self.idempotency_key.clone(),
            origin: EntryOrigin::Control {
                control_kind: ControlKind::POLICY_ACTIVATION,
                spec_body_digest: definition_digest,
            },
            principal_ref: self.principal_ref,
            session_ref: None,
            evidence: Vec::new(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: vec![(
                fa_model::entry::CASH_FLOW_POLICY,
                self.definition.canonical_bytes()?,
            )],
            tags: Vec::new(),
        })
    }

    pub fn proposal_digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(self.proposal()?.proposal_digest()?)
    }

    pub fn encode(&self) -> Result<Vec<u8>, KernelError> {
        self.definition.validate().map_err(corrupt)?;
        if self.idempotency_key.is_empty() || self.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        {
            return Err(corrupt("activation review has an invalid idempotency key"));
        }
        let mut w = Writer::new();
        w.fixed(CASH_FLOW_POLICY_PLAN_FORMAT)
            .fixed(&self.book_id.0)
            .bytes(&self.definition.canonical_bytes()?)
            .u128(self.principal_ref.0)
            .i32(self.effective_from.0)
            .fixed(&self.chart_digest)
            .bytes(&self.idempotency_key);
        self.description.encode(&mut w);
        let encoded = w.finish()?;
        if encoded.len() > MAX_CASH_FLOW_POLICY_PLAN_BYTES {
            return Err(corrupt(
                "activation review exceeds its registered byte bound",
            ));
        }
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, KernelError> {
        if encoded.len() > MAX_CASH_FLOW_POLICY_PLAN_BYTES {
            return Err(corrupt(
                "activation review exceeds its registered byte bound",
            ));
        }
        let mut r = Reader::new(encoded);
        if r.fixed::<{ CASH_FLOW_POLICY_PLAN_FORMAT.len() }>("cash policy plan format")
            .map_err(decode)?
            != CASH_FLOW_POLICY_PLAN_FORMAT
        {
            return Err(corrupt("unsupported activation review format"));
        }
        let plan = Self {
            book_id: Id128(r.fixed("cash policy book").map_err(decode)?),
            definition: CashFlowPolicyDefinition::decode(
                r.bytes(
                    MAX_CASH_FLOW_POLICY_DEFINITION_BYTES,
                    "cash policy definition",
                )
                .map_err(decode)?,
            )
            .map_err(decode)?,
            principal_ref: VId(r.u128("cash policy principal").map_err(decode)?),
            effective_from: DateDay(r.i32("cash policy effective date").map_err(decode)?),
            chart_digest: r.fixed("cash policy chart basis").map_err(decode)?,
            idempotency_key: r
                .bytes(MAX_IDEMPOTENCY_KEY_BYTES, "cash policy key")
                .map_err(decode)?
                .to_vec(),
            description: Erasable::decode(&mut r, MAX_DESCRIPTION_BYTES).map_err(decode)?,
        };
        r.finish().map_err(decode)?;
        if plan.encode()? != encoded {
            return Err(corrupt("activation review is not canonical"));
        }
        Ok(plan)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivatedCashFlowPolicy {
    pub policy: CashFlowPolicy,
    pub version: u32,
    pub definition_digest: [u8; 32],
    pub activation: VId,
    pub effective_from: DateDay,
    pub recorded_at: CommitSeq,
    pub chart_digest: [u8; 32],
    pub already_recorded: bool,
}

fn corrupt(message: impl Into<String>) -> KernelError {
    KernelError::Corrupt(format!("cash-flow policy: {}", message.into()))
}

fn decode(error: fa_model::DecodeError) -> KernelError {
    corrupt(error.to_string())
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::STRUCTURE,
        fa_journal::exit::USAGE,
        message,
        "plan §12.1 (versioned, approved CashFlowClassification)",
        "prepare a bounded policy over existing cash and non-cash leaves, then obtain two independent Human approvals",
    )
}

fn conflict(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::PLAN_INVALIDATED,
        fa_journal::exit::CONFLICT,
        message,
        "plan §12.1 (activate exactly the policy and chart that were reviewed)",
        "prepare the policy against the current chart and obtain fresh approvals",
    )
}

fn key_conflict() -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::IDEMPOTENCY_CONFLICT,
        fa_journal::exit::CONFLICT,
        "this idempotency key already records another operation, different content or different approvals",
        "plan §5.9 (one successful intent per book, principal and key)",
        "retry the unchanged saved activation plan and approvals, or use a new key",
    )
}

fn checkpoint(cx: &QueryCx) -> Result<(), BookError> {
    cx.checkpoint().map_err(BookError::Context)
}

fn validate_chart(
    definition: &CashFlowPolicyDefinition,
    accounts: &[Account],
) -> Result<(), Refusal> {
    definition.validate().map_err(invalid)?;
    let accounts: BTreeMap<_, _> = accounts.iter().map(|a| (a.id, a)).collect();
    for id in &definition.cash_accounts {
        let Some(account) = accounts.get(id) else {
            return Err(invalid(format!(
                "cash account {id:032x} is absent from the reviewed chart"
            )));
        };
        if !account.is_leaf
            || !matches!(
                AccountType(account.account_type),
                AccountType::ASSET | AccountType::LIABILITY
            )
        {
            return Err(invalid(format!(
                "cash account {id:032x} must be an asset or overdraft liability leaf"
            )));
        }
    }
    for (id, _) in &definition.account_rules {
        let Some(account) = accounts.get(id) else {
            return Err(invalid(format!(
                "counterpart account {id:032x} is absent from the reviewed chart"
            )));
        };
        if !account.is_leaf || !(1..=5).contains(&account.account_type) {
            return Err(invalid(format!(
                "counterpart account {id:032x} must be a non-cash monetary leaf"
            )));
        }
    }
    Ok(())
}

fn report_policy(definition: &CashFlowPolicyDefinition) -> Result<CashFlowPolicy, KernelError> {
    definition.validate().map_err(corrupt)?;
    Ok(CashFlowPolicy {
        name: definition.name.clone(),
        cash_accounts: definition.cash_accounts.clone(),
        account_rules: definition
            .account_rules
            .iter()
            .map(|(account_id, tag)| {
                let activity = match tag {
                    0 => CashFlowActivity::Operating,
                    1 => CashFlowActivity::Investing,
                    2 => CashFlowActivity::Financing,
                    3 => CashFlowActivity::ExchangeEffect,
                    _ => unreachable!("validated activity tag"),
                };
                CashFlowAccountRule {
                    account_id: *account_id,
                    activity,
                }
            })
            .collect(),
        overrides: Vec::new(),
    })
}

fn activation_of<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    row: &VertexRow,
    entry: &Entry,
) -> Result<ActivatedCashFlowPolicy, BookError> {
    if !outcome::is_cash_flow_policy_activation(entry)
        || row.labels.as_slice() != [label::ENTRY]
        || entry.proposal.book_id != book.book_id
        || entry.proposal.branch_id != Id128::TRUNK
        || row.vid
            != entry_vid(
                book.book_id,
                &entry.proposal.principal_ref.0.to_le_bytes(),
                &entry.proposal.idempotency_key,
            )
        || !original(db, row)?
        || db
            .vertex_at(
                intent_outcome_vid(
                    book.book_id,
                    &entry.proposal.principal_ref.0.to_le_bytes(),
                    &entry.proposal.idempotency_key,
                ),
                row.created_at,
            )
            .map_err(KernelError::from)?
            .is_none()
        || !outcome::verify_control_recorded(db, row, entry)?
    {
        return Err(corrupt(
            "malformed, rebound or rewritten activation control or missing atomic intent claim",
        )
        .into());
    }
    let extension = entry
        .proposal
        .extensions
        .iter()
        .find(|(tag, _)| *tag == fa_model::entry::CASH_FLOW_POLICY)
        .ok_or_else(|| corrupt("activation has no policy definition"))?;
    let definition = CashFlowPolicyDefinition::decode(&extension.1).map_err(decode)?;
    let Some(ControlPayload::LifecycleTransition { proof_refs, .. }) = &entry.proposal.control
    else {
        return Err(corrupt("activation has no lifecycle transition").into());
    };
    let [TypedRef::Object(chart_digest)] = proof_refs.as_slice() else {
        return Err(corrupt("activation chart proof is not one object digest").into());
    };
    approvals_at(db, cx, book, entry, row.created_at)?;
    let before = row
        .created_at
        .0
        .checked_sub(1)
        .map(CommitSeq)
        .ok_or_else(|| corrupt("activation has no preceding chart"))?;
    let (accounts, actual_chart) = accounts_and_basis(db, cx, book, before)?;
    if actual_chart != chart_digest.0 {
        return Err(corrupt("activation's reviewed chart differs from its original chart").into());
    }
    validate_chart(&definition, &accounts).map_err(|refusal| corrupt(refusal.message))?;
    Ok(ActivatedCashFlowPolicy {
        policy: report_policy(&definition)?,
        version: definition.version,
        definition_digest: definition.digest().map_err(KernelError::from)?,
        activation: row.vid,
        effective_from: entry.proposal.effective_date,
        recorded_at: row.created_at,
        chart_digest: chart_digest.0,
        already_recorded: false,
    })
}

fn history<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    at: CommitSeq,
) -> Result<Vec<ActivatedCashFlowPolicy>, BookError> {
    if at > db.frontier().map_err(KernelError::from)? {
        return Err(corrupt("selected recorded sequence is beyond the book head").into());
    }
    let mut activations = Vec::new();
    for row in db.vertices_at(at).map_err(KernelError::from)? {
        checkpoint(cx)?;
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = fa_journal::entry_storage::decode_at(db, &row, at)?;
        if (entry.proposal.class == EntryClass::POLICY_CONTROL
            && matches!(
                &entry.proposal.control,
                Some(ControlPayload::LifecycleTransition {
                    reason_code: CASH_FLOW_POLICY_ACTIVATION_REASON,
                    ..
                })
            ))
            || entry
                .proposal
                .extensions
                .iter()
                .any(|(tag, _)| *tag == fa_model::entry::CASH_FLOW_POLICY)
        {
            activations.push(activation_of(db, cx, book, &row, &entry)?);
        }
    }
    activations.sort_by_key(|a| (a.recorded_at, a.activation));
    let mut latest = BTreeMap::<&str, (u32, DateDay)>::new();
    for activation in &activations {
        if let Some((version, day)) = latest.insert(
            &activation.policy.name,
            (activation.version, activation.effective_from),
        ) && (version >= activation.version || day >= activation.effective_from)
        {
            return Err(
                corrupt("a name's activation versions or effective dates do not advance").into(),
            );
        }
    }
    Ok(activations)
}

/// Resolve one immutable policy for a complete effective interval at a fixed
/// recorded prefix. Callers must authorize the metadata read first.
pub fn resolve_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    name: &str,
    from: DateDay,
    through: DateDay,
    at: CommitSeq,
) -> Outcome<Option<ActivatedCashFlowPolicy>> {
    if from > through || at > db.frontier().map_err(KernelError::from)? {
        return Ok(Err(invalid(
            "cash policy selection needs an ordered interval and a recorded sequence at or before the head",
        )));
    }
    let history = history(db, cx, book, at)?;
    if history
        .iter()
        .any(|a| a.policy.name == name && a.effective_from > from && a.effective_from <= through)
    {
        return Ok(Err(invalid(
            "the cash policy changes within this effective interval; split the report at the activation date",
        )));
    }
    Ok(Ok(history
        .into_iter()
        .filter(|a| a.policy.name == name && a.effective_from <= from)
        .max_by_key(|a| (a.effective_from, a.recorded_at))))
}

/// Compose immutable cash-policy law into the existing projection verifier.
pub fn verify_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    at: CommitSeq,
) -> Result<Vec<String>, BookError> {
    match history(db, cx, book, at) {
        Ok(_) => Ok(Vec::new()),
        Err(BookError::Kernel(KernelError::Corrupt(message))) => {
            Ok(vec![format!("cash-flow policies: {message}")])
        }
        Err(BookError::Kernel(KernelError::Model(error))) => {
            Ok(vec![format!("cash-flow policies: {error}")])
        }
        Err(error) => Err(error),
    }
}

fn admit_definition<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    cap: &Capability,
) -> Outcome<()> {
    if let Err(denial) = fa_policy::admit_preparation(
        cap,
        &Intent {
            principal: cap.holder(),
            trunk: true,
            op: Op::RuleChange,
            book: book.book_id,
            legs: &[],
        },
        &Reach::whole_book(true),
        None,
        Some(EntryClass::POLICY_CONTROL),
    ) {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    if let Err(denial) = fa_policy::current(cap, db.frontier().map_err(KernelError::from)?) {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    Ok(fa_journal::policy::capability_admitted(db, book, cap)?)
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Admit the native cash-policy operation before a transport reads review
    /// files. Preparation does not consume a capability's rehearsal requirement;
    /// publication retains the ordinary direct-write restriction.
    pub fn admit_cash_flow_policy(
        &self,
        cx: &PurposeContexts,
        cap: &Capability,
        preview: bool,
    ) -> Outcome<()> {
        checkpoint(&cx.query())?;
        if !preview && let Err(denial) = fa_policy::admit_direct_write(cap) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        admit_definition(&self.db, &self.context, cap)
    }

    pub fn active_cash_flow_policy(
        &self,
        cx: &PurposeContexts,
        cap: &Capability,
        name: &str,
        from: DateDay,
        through: DateDay,
        at: CommitSeq,
    ) -> Outcome<Option<ActivatedCashFlowPolicy>> {
        self.query(cx, |db, book| {
            if let Err(refusal) = admit_read(db, book, cap, at)? {
                return Ok(Err(refusal));
            }
            resolve_at(db, &cx.query(), book, name, from, through, at)
        })
    }

    pub fn plan_cash_flow_policy(
        &self,
        cx: &PurposeContexts,
        cap: &Capability,
        definition: CashFlowPolicyDefinition,
        effective_from: DateDay,
        idempotency_key: &[u8],
    ) -> Outcome<CashFlowPolicyPlan> {
        if let Err(refusal) = self.admit_cash_flow_policy(cx, cap, true)? {
            return Ok(Err(refusal));
        }
        if let Err(message) = definition.validate() {
            return Ok(Err(invalid(message)));
        }
        if idempotency_key.is_empty() || idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
            return Ok(Err(invalid(
                "activation requires a nonempty bounded idempotency key",
            )));
        }
        let at = self.db.frontier().map_err(KernelError::from)?;
        let (accounts, chart_digest) =
            self.query(cx, |db, book| accounts_and_basis(db, &cx.query(), book, at))?;
        if let Err(refusal) = validate_chart(&definition, &accounts) {
            return Ok(Err(refusal));
        }
        if let Some(last) = history(&self.db, &cx.query(), &self.context, at)?
            .into_iter()
            .rfind(|a| a.policy.name == definition.name)
            && (definition.version <= last.version || effective_from <= last.effective_from)
        {
            return Ok(Err(invalid(
                "a cash policy name's version and effective date must both advance",
            )));
        }
        let description = self.seal_text(
            cx,
            &format!(
                "Activate cash-flow policy {} version {}",
                definition.name, definition.version
            ),
        )?;
        Ok(Ok(CashFlowPolicyPlan {
            book_id: self.context.book_id,
            definition,
            principal_ref: cap.holder(),
            effective_from,
            chart_digest,
            idempotency_key: idempotency_key.to_vec(),
            description,
        }))
    }

    pub async fn activate_cash_flow_policy(
        &mut self,
        cx: &PurposeContexts,
        cap: &Capability,
        plan: CashFlowPolicyPlan,
        approvals: Vec<ApprovalRef>,
    ) -> Outcome<ActivatedCashFlowPolicy> {
        if let Err(refusal) = self.admit_cash_flow_policy(cx, cap, false)? {
            return Ok(Err(refusal));
        }
        if plan.book_id != self.context.book_id || plan.principal_ref != cap.holder() {
            return Ok(Err(invalid(
                "the activation plan names another book or preparer",
            )));
        }
        if let Err(message) = plan.definition.validate() {
            return Ok(Err(invalid(message)));
        }
        if plan.idempotency_key.is_empty() || plan.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        {
            return Ok(Err(invalid(
                "the activation plan has an invalid idempotency key",
            )));
        }
        let proposal = plan.proposal()?;
        if let Err(error) = proposal.validate_for_write() {
            return Ok(Err(invalid(format!(
                "invalid activation proposal: {error}"
            ))));
        }
        let proposal_digest = proposal.proposal_digest().map_err(KernelError::from)?;
        if let Err(refusal) = fa_journal::scratch::ensure_history(&mut self.db, cx).await? {
            return Ok(Err(refusal));
        }
        let evid = entry_vid(
            self.context.book_id,
            &plan.principal_ref.0.to_le_bytes(),
            &plan.idempotency_key,
        );
        let mut txn = self.db.begin(&cx.txn()).map_err(KernelError::from)?;
        if let Err(refusal) =
            fa_journal::policy::capability_witness(&txn, &self.db, &self.context, cap)?
        {
            txn.abort();
            return Ok(Err(refusal));
        }
        let epoch = fa_journal::policy::epoch_witness(&txn, &self.db)?;
        // A class-scoped RuleChange grant admits this policy operation, not an
        // unrelated Entry's payload. Inspect only identity/class mirrors before
        // the common intent witness or chunked retry reader sees its content.
        let present = txn
            .vertex_has_label(&self.db, evid, label::ENTRY)
            .map_err(KernelError::from)?;
        if present.is_some()
            && (present != Some(true)
                || txn
                    .vertex_property(&self.db, evid, property::CLASS)
                    .map_err(KernelError::from)?
                    != Some(CanonicalScalar::Int(i64::from(
                        EntryClass::POLICY_CONTROL.0,
                    ))))
        {
            txn.abort();
            return Ok(Err(key_conflict()));
        }
        if let Err(refusal) = outcome::witness_named_key(
            &txn,
            &self.db,
            self.context.book_id,
            plan.principal_ref,
            &plan.idempotency_key,
            evid,
        )? {
            txn.abort();
            return Ok(Err(refusal));
        }
        if let Some(row) = txn.vertex(&self.db, evid).map_err(KernelError::from)? {
            txn.abort();
            let stored = fa_journal::entry_storage::decode_at(
                &self.db,
                &row,
                self.db.frontier().map_err(KernelError::from)?,
            )?;
            if stored.proposal_digest != proposal_digest
                || stored.approvals != approvals
                || !outcome::verify_control_recorded(&self.db, &row, &stored)?
            {
                return Ok(Err(key_conflict()));
            }
            let mut recorded = activation_of(&self.db, &cx.query(), &self.context, &row, &stored)?;
            recorded.already_recorded = true;
            return Ok(Ok(recorded));
        }
        if let Err(refusal) = outcome::require_unused_legacy_key(
            &txn,
            &self.db,
            &self.context,
            intent_outcome_vid(
                self.context.book_id,
                &plan.principal_ref.0.to_le_bytes(),
                &plan.idempotency_key,
            ),
        )? {
            txn.abort();
            return Ok(Err(refusal));
        }
        let basis = txn.basis();
        let (accounts, actual_chart) =
            accounts_and_basis(&self.db, &cx.query(), &self.context, basis)?;
        if actual_chart != plan.chart_digest {
            txn.abort();
            return Ok(Err(conflict(
                "the accounting schema changed after this cash policy was reviewed",
            )));
        }
        if let Err(refusal) = validate_chart(&plan.definition, &accounts) {
            txn.abort();
            return Ok(Err(refusal));
        }
        if let Some(last) = history(&self.db, &cx.query(), &self.context, basis)?
            .into_iter()
            .rfind(|a| a.policy.name == plan.definition.name)
            && (plan.definition.version <= last.version
                || plan.effective_from <= last.effective_from)
        {
            txn.abort();
            return Ok(Err(conflict(
                "another activation already advanced this cash policy's name",
            )));
        }
        for account in &accounts {
            txn.vertex(&self.db, VId(account.id))
                .map_err(KernelError::from)?;
        }
        let sod = fa_policy::sod::control_key("PolicyControl", None, "ActivateStatement");
        if let Err(refusal) = fa_journal::policy::authorize_approvals(
            &txn,
            &self.db,
            &self.context,
            &approvals,
            &proposal_digest,
            epoch,
            &sod,
            0,
            Party::for_capability(plan.principal_ref, cap),
        )? {
            txn.abort();
            return Ok(Err(refusal));
        }
        let entry = proposal.seal(approvals, None).map_err(KernelError::from)?;
        let mut batch = WriteBatch::new(relation::IN_BOOK);
        fa_journal::entry_storage::stage(&cx.query(), &mut batch, &entry, evid)?;
        batch.create_vertex(
            evid,
            vec![label::ENTRY],
            fa_journal::entry_storage::stored_mirrors(&entry)?,
        );
        outcome::stage_control(&mut batch, &entry, evid)?;
        if let Err(error) = txn.write(&mut self.db, batch) {
            txn.abort();
            return Err(KernelError::from(error).into());
        }
        if self.db.frontier().map_err(KernelError::from)? != basis {
            txn.abort();
            return Ok(Err(conflict(
                "the committed frontier changed during activation publication",
            )));
        }
        if let Err(denial) = fa_policy::current(cap, basis) {
            txn.abort();
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        match txn.commit(&mut self.db, &cx.commit()).await {
            Ok(recorded_at) => Ok(Ok(ActivatedCashFlowPolicy {
                policy: report_policy(&plan.definition)?,
                version: plan.definition.version,
                definition_digest: plan.definition.digest().map_err(KernelError::from)?,
                activation: evid,
                effective_from: plan.effective_from,
                recorded_at,
                chart_digest: plan.chart_digest,
                already_recorded: false,
            })),
            Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => Ok(
                Err(conflict(format!("an activation witness changed: {detail}"))),
            ),
            Err(WriteTxnError::Write(
                fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
            )) => Ok(Err(conflict(
                "a concurrent activation claimed this identity; retry the unchanged plan",
            ))),
            Err(error) => Err(KernelError::from(error).into()),
        }
    }
}

#[cfg(test)]
mod tests;
