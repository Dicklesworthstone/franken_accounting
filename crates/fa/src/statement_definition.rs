//! Company statement layouts as immutable, independently approved policy.
//!
//! A name's activations advance in effective date and version. Named reads
//! select the latest applicable activation at their recorded prefix; an exact
//! definition/activation citation remains valid after later versions appear.
//! Mapping partition is checked against authoritative chart history both when
//! preparing and publishing. Approval commits do not alter that chart basis.

use std::collections::BTreeSet;

use asupersync::fs::Vfs;
use fa_journal::object::{self, ObjectKind};
use fa_journal::outcome::{self, STATEMENT_ACTIVATION_REASON};
use fa_journal::rows::{book_root, bytes, prop, scalar_bytes};
use fa_journal::{BookContext, KernelError, Refusal};
use fa_model::limits::{
    MAX_DESCRIPTION_BYTES, MAX_IDEMPOTENCY_KEY_BYTES, MAX_STATEMENT_DEFINITION_BYTES,
    MAX_STATEMENT_DEFINITION_PLAN_BYTES,
};
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ApprovalRef, ControlKind, ControlPayload, Entry, EntryClass, EntryOrigin, EntryPayload,
    Erasable, Id128, Oid, Reader, TypedRef, Writer, domain_digest, entry_mirrors, entry_vid,
    intent_outcome_vid, statement_definition_vid,
};
use fa_policy::{Approval, Capability, Intent, Op, Party, Profile, Reach};
use fa_statements::Account;
use fa_statements::custom::{
    CustomStatementDefinition, StatementLintReport, lint_custom_statement_definition,
};
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteTxnError};
use fgdb_types::{CanonicalScalar, CommitSeq, QueryCx, VId, context::PurposeContexts};

use crate::{AsyncBook, BookError, Outcome};

pub const STATEMENT_DEFINITION_PLAN_FORMAT: &[u8] = b"fa:statement-definition-plan:v1";
pub const STATEMENT_CHART_BASIS_DOMAIN: &[u8] = b"fa:statement-chart-basis:v1";

/// One unchanged review envelope, including its sealed description. No caller
/// controls a recording sequence; publication receives its sequence from FGDB.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementDefinitionPlan {
    pub book_id: Id128,
    pub definition: CustomStatementDefinition,
    pub principal_ref: VId,
    pub effective_from: DateDay,
    pub chart_digest: [u8; 32],
    pub idempotency_key: Vec<u8>,
    pub description: Erasable<String>,
}

impl StatementDefinitionPlan {
    pub fn proposal(&self) -> Result<EntryPayload, KernelError> {
        let oid = self.definition.digest()?;
        Ok(EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: self.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::POLICY_CONTROL,
            effective_date: self.effective_from,
            document_date: None,
            description: self.description.clone(),
            effective_period: None,
            legs: Vec::new(),
            control: Some(ControlPayload::LifecycleTransition {
                object_ref: statement_definition_vid(self.book_id, &oid.0),
                from: 0,
                to: 1,
                proof_refs: vec![TypedRef::Object(Oid(self.chart_digest))],
                reason_code: STATEMENT_ACTIVATION_REASON,
            }),
            unit_totals: Vec::new(),
            base_totals: None,
            idempotency_key: self.idempotency_key.clone(),
            origin: EntryOrigin::Control {
                control_kind: ControlKind::POLICY_ACTIVATION,
                spec_body_digest: oid.0,
            },
            principal_ref: self.principal_ref,
            session_ref: None,
            evidence: Vec::new(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        })
    }

    pub fn proposal_digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(self.proposal()?.proposal_digest()?)
    }

    pub fn encode(&self) -> Result<Vec<u8>, KernelError> {
        let definition_bytes = self.definition.canonical_bytes()?;
        if definition_bytes.len() > MAX_STATEMENT_DEFINITION_BYTES
            || self.idempotency_key.is_empty()
            || self.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        {
            return Err(corrupt(
                "activation review contains an oversized definition or invalid key",
            ));
        }
        let mut writer = Writer::new();
        writer
            .fixed(STATEMENT_DEFINITION_PLAN_FORMAT)
            .fixed(&self.book_id.0)
            .bytes(&definition_bytes)
            .u128(self.principal_ref.0)
            .i32(self.effective_from.0)
            .fixed(&self.chart_digest)
            .bytes(&self.idempotency_key);
        self.description.encode(&mut writer);
        let encoded = writer.finish()?;
        if encoded.len() > MAX_STATEMENT_DEFINITION_PLAN_BYTES {
            return Err(corrupt(
                "activation review exceeds its registered byte bound",
            ));
        }
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, KernelError> {
        if encoded.len() > MAX_STATEMENT_DEFINITION_PLAN_BYTES {
            return Err(corrupt(
                "activation review exceeds its registered byte bound",
            ));
        }
        let mut reader = Reader::new(encoded);
        if reader
            .fixed::<{ STATEMENT_DEFINITION_PLAN_FORMAT.len() }>("statement activation format")
            .map_err(decode)?
            != STATEMENT_DEFINITION_PLAN_FORMAT
        {
            return Err(corrupt("unsupported activation review format"));
        }
        let book_id = Id128(reader.fixed("statement activation book").map_err(decode)?);
        let definition = CustomStatementDefinition::decode(
            reader
                .bytes(MAX_STATEMENT_DEFINITION_BYTES, "statement definition")
                .map_err(decode)?,
        )
        .map_err(|error| corrupt(error.to_string()))?;
        let plan = Self {
            book_id,
            definition,
            principal_ref: VId(reader
                .u128("statement activation principal")
                .map_err(decode)?),
            effective_from: DateDay(
                reader
                    .i32("statement activation effective date")
                    .map_err(decode)?,
            ),
            chart_digest: reader
                .fixed("statement activation chart basis")
                .map_err(decode)?,
            idempotency_key: reader
                .bytes(MAX_IDEMPOTENCY_KEY_BYTES, "statement activation key")
                .map_err(decode)?
                .to_vec(),
            description: Erasable::decode(&mut reader, MAX_DESCRIPTION_BYTES).map_err(decode)?,
        };
        reader.finish().map_err(decode)?;
        if plan.encode()? != encoded {
            return Err(corrupt("activation review is not canonical"));
        }
        Ok(plan)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivatedStatementDefinition {
    pub definition: CustomStatementDefinition,
    pub definition_oid: Oid,
    pub activation: VId,
    pub effective_from: DateDay,
    pub recorded_at: CommitSeq,
    pub chart_digest: [u8; 32],
    pub already_recorded: bool,
}

fn corrupt(message: impl Into<String>) -> KernelError {
    KernelError::Corrupt(format!("statement definition: {}", message.into()))
}

fn decode(error: fa_model::DecodeError) -> KernelError {
    corrupt(error.to_string())
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::STRUCTURE,
        fa_journal::exit::REFUSAL,
        message,
        "plan §12.1 (approved statement definitions partition the selected chart)",
        "lint the complete definition against this book, then prepare a new activation and obtain two independent Human approvals",
    )
}

fn conflict(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::PLAN_INVALIDATED,
        fa_journal::exit::CONFLICT,
        message,
        "plan §12.1 (the committed definition and chart are exactly those reviewed)",
        "prepare the definition again against the current chart and obtain fresh approvals",
    )
}

fn checkpoint(cx: &QueryCx) -> Result<(), BookError> {
    cx.checkpoint().map_err(BookError::Context)
}

fn definition_valid(definition: &CustomStatementDefinition) -> Result<(), Refusal> {
    definition
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    if definition
        .canonical_bytes()
        .map_err(|error| invalid(error.to_string()))?
        .len()
        > MAX_STATEMENT_DEFINITION_BYTES
    {
        return Err(invalid(format!(
            "definition exceeds max_statement_definition_bytes={MAX_STATEMENT_DEFINITION_BYTES}; reduce its account-set expressions or number of lines"
        )));
    }
    if crate::statements::statement_definition_kind(&definition.name).is_some() {
        return Err(invalid(
            "a custom layout cannot replace a reserved built-in or preset definition name",
        ));
    }
    Ok(())
}

fn original<V: Vfs + Clone>(db: &Database<V>, row: &VertexRow) -> Result<bool, KernelError> {
    let Some(before) = row.created_at.0.checked_sub(1).map(CommitSeq) else {
        return Ok(false);
    };
    Ok(db.vertex_at(row.vid, row.created_at)?.as_ref() == Some(row)
        && db.vertex_at(row.vid, before)?.is_none())
}

fn accounts_and_basis<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    at: CommitSeq,
) -> Result<(Vec<Account>, [u8; 32]), BookError> {
    checkpoint(cx)?;
    let chart = fa_journal::chart::read_at(db, book, at)?;
    let accounts = chart
        .accounts()
        .values()
        .map(|account| Account {
            id: account.vid.0,
            code: account.code.clone(),
            name: account.name.clone(),
            account_type: account.account_type,
            is_leaf: account.is_leaf,
        })
        .collect();
    // Bind all original schema controls: this includes account lifecycle,
    // hierarchy, dimensions, units, closing routes and calendar declarations.
    // An approval or monetary posting is not a schema change.
    let mut controls = Vec::new();
    for row in db.vertices_at(at).map_err(KernelError::from)? {
        checkpoint(cx)?;
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "chart-basis entry")?)
            .map_err(KernelError::from)?;
        if entry.proposal.class != EntryClass::SCHEMA_CONTROL {
            continue;
        }
        if entry.proposal.book_id != book.book_id
            || entry.proposal.branch_id != Id128::TRUNK
            || !original(db, &row)?
        {
            return Err(corrupt(
                "chart-basis schema control is not an original entry of this book",
            )
            .into());
        }
        controls.push((row.created_at, row.vid, entry.entry_digest));
    }
    controls.sort_by_key(|(seq, vid, _)| (*seq, *vid));
    let mut writer = Writer::new();
    writer
        .fixed(&book.book_id.0)
        .list(&controls, |writer, (seq, vid, digest)| {
            writer.u64(seq.0).u128(vid.0).fixed(digest);
        });
    Ok((
        accounts,
        domain_digest(
            STATEMENT_CHART_BASIS_DOMAIN,
            &[&writer.finish().map_err(KernelError::from)?],
        ),
    ))
}

fn lint(
    definition: &CustomStatementDefinition,
    accounts: &[Account],
) -> Result<StatementLintReport, Refusal> {
    lint_custom_statement_definition(definition, accounts)
        .map_err(|error| invalid(error.to_string()))
}

fn require_clean(report: &StatementLintReport) -> Result<(), Refusal> {
    if report.is_clean() {
        return Ok(());
    }
    Err(invalid(format!(
        "definition does not partition the chart: unmapped={:?}; multiply_mapped={:?}; unknown={:?}; summary={:?}; outside_coverage={:?}",
        report.unmapped_leaves,
        report.multiply_mapped_leaves,
        report.unknown_referenced_codes,
        report.summary_referenced_codes,
        report.outside_coverage_codes
    )))
}

fn definition_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    oid: Oid,
    at: CommitSeq,
) -> Result<(CustomStatementDefinition, CommitSeq), BookError> {
    let vid = statement_definition_vid(book.book_id, &oid.0);
    let row = db
        .vertex_at(vid, at)
        .map_err(KernelError::from)?
        .ok_or_else(|| corrupt("activation's immutable definition is absent"))?;
    if row.labels.as_slice() != [label::STATEMENT_DEFINITION]
        || row.props.len() != 3
        || !original(db, &row)?
        || bytes(&row, property::BOOK_ID, "statement definition book")? != book.book_id.0
        || bytes(&row, property::FA_DIGEST, "statement definition digest")? != oid.0
    {
        return Err(corrupt("definition identity, metadata or original birth differs").into());
    }
    let encoded = object::read(
        db,
        cx,
        book.book_id,
        &row,
        label::STATEMENT_DEFINITION,
        ObjectKind::StatementDefinition,
        at,
        MAX_STATEMENT_DEFINITION_BYTES,
    )?;
    let definition =
        CustomStatementDefinition::decode(&encoded).map_err(|error| corrupt(error.to_string()))?;
    if definition.canonical_bytes().map_err(KernelError::from)? != encoded
        || definition.digest().map_err(KernelError::from)? != oid
    {
        return Err(corrupt("definition content does not reproduce its immutable address").into());
    }
    Ok((definition, row.created_at))
}

fn approvals_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    entry: &Entry,
    at: CommitSeq,
) -> Result<(), BookError> {
    let root = db
        .vertex_at(book_root(), at)
        .map_err(KernelError::from)?
        .ok_or_else(|| corrupt("activation has no historical book root"))?;
    let epoch = match prop(&root, property::SECURITY_POLICY_EPOCH) {
        None => 0,
        Some(CanonicalScalar::Int(epoch)) => {
            u64::try_from(*epoch).map_err(|_| corrupt("historical policy epoch is negative"))?
        }
        _ => return Err(corrupt("historical policy epoch is not an integer").into()),
    };
    let mut humans = BTreeSet::new();
    for (index, cited) in entry.approvals.iter().enumerate() {
        checkpoint(cx)?;
        let row = db
            .vertex_at(cited.approval_vid, at)
            .map_err(KernelError::from)?
            .ok_or_else(|| corrupt("activation cites a missing historical approval"))?;
        if row.labels.as_slice() != [label::APPROVAL]
            || row.created_at >= at
            || !original(db, &row)?
        {
            return Err(
                corrupt("activation approval is not an original preceding approval").into(),
            );
        }
        let approval = Approval::decode(&bytes(&row, property::FA_PAYLOAD, "statement approval")?)
            .map_err(|error| corrupt(error.to_string()))?;
        if fa_journal::policy::approval_vid(
            approval.book_id,
            approval.principal,
            &approval.approved_proposal_digest,
            approval.security_policy_epoch,
        ) != row.vid
            || approval
                .check_binding(
                    index,
                    &cited.approved_digest,
                    &entry.proposal_digest,
                    book.book_id,
                    epoch,
                )
                .is_err()
            || approval.profile != Profile::Human
            || approval.op != Op::Approve
            || approval.principal == entry.proposal.principal_ref
            || !humans.insert(approval.principal)
        {
            return Err(corrupt(
                "activation approval violates its binding or independent Human approval law",
            )
            .into());
        }
    }
    if humans.len() < 2 {
        return Err(corrupt("activation lacks two independent Human approvals").into());
    }
    Ok(())
}

fn activation_of<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    row: &VertexRow,
    entry: &Entry,
    at: CommitSeq,
) -> Result<ActivatedStatementDefinition, BookError> {
    if !outcome::is_statement_activation(entry)
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
    {
        return Err(corrupt("malformed, rebound or rewritten activation control").into());
    }
    let EntryOrigin::Control {
        spec_body_digest, ..
    } = &entry.proposal.origin
    else {
        unreachable!()
    };
    let Some(ControlPayload::LifecycleTransition { proof_refs, .. }) = &entry.proposal.control
    else {
        unreachable!()
    };
    let oid = Oid(*spec_body_digest);
    let (definition, born) = definition_at(db, cx, book, oid, at)?;
    if born != row.created_at {
        return Err(
            corrupt("definition and its first activation did not publish atomically").into(),
        );
    }
    approvals_at(db, cx, book, entry, row.created_at)?;
    let [TypedRef::Object(chart_digest)] = proof_refs.as_slice() else {
        return Err(corrupt("activation chart proof is not one object digest").into());
    };
    Ok(ActivatedStatementDefinition {
        definition,
        definition_oid: oid,
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
) -> Result<Vec<ActivatedStatementDefinition>, BookError> {
    if at > db.frontier().map_err(KernelError::from)? {
        return Err(corrupt("selected recorded sequence is beyond the book head").into());
    }
    let mut activations = Vec::new();
    for row in db.vertices_at(at).map_err(KernelError::from)? {
        checkpoint(cx)?;
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = Entry::decode(&bytes(
            &row,
            property::FA_PAYLOAD,
            "statement activation entry",
        )?)
        .map_err(KernelError::from)?;
        if !matches!(
            &entry.proposal.control,
            Some(ControlPayload::LifecycleTransition {
                reason_code: STATEMENT_ACTIVATION_REASON,
                ..
            })
        ) {
            continue;
        }
        activations.push(activation_of(db, cx, book, &row, &entry, at)?);
    }
    activations.sort_by_key(|activation| (activation.recorded_at, activation.activation));
    let mut latest = std::collections::BTreeMap::<&str, (u32, DateDay)>::new();
    for activation in &activations {
        if let Some((version, day)) = latest.insert(
            &activation.definition.name,
            (activation.definition.version, activation.effective_from),
        ) && (version >= activation.definition.version || day >= activation.effective_from)
        {
            return Err(
                corrupt("a name's activation versions or effective dates do not advance").into(),
            );
        }
    }
    Ok(activations)
}

/// Resolve a name at an already authorized recorded/effective coordinate.
/// The caller must admit the complete metadata read before invoking this low-level reader.
pub fn resolve_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    name: &str,
    day: DateDay,
    at: CommitSeq,
) -> Outcome<Option<ActivatedStatementDefinition>> {
    let selected = history(db, cx, book, at)?
        .into_iter()
        .filter(|activation| activation.definition.name == name && activation.effective_from <= day)
        .max_by_key(|activation| (activation.effective_from, activation.recorded_at));
    match selected {
        None => Ok(Ok(None)),
        Some(selected) => validate_active_at(
            db,
            cx,
            book,
            &selected.definition,
            selected.activation,
            day,
            at,
        )
        .map(|result| result.map(Some)),
    }
}

/// Validate an explicitly pinned approved version. A later name activation
/// does not replace this question or invalidate native certificate replay.
/// The caller independently lints the chart at each report column coordinate.
pub fn validate_active_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    definition: &CustomStatementDefinition,
    activation: VId,
    day: DateDay,
    at: CommitSeq,
) -> Outcome<ActivatedStatementDefinition> {
    checkpoint(cx)?;
    if at > db.frontier().map_err(KernelError::from)? {
        return Ok(Err(invalid(
            "the selected recorded sequence is beyond the book head",
        )));
    }
    let Some(row) = db.vertex_at(activation, at).map_err(KernelError::from)? else {
        return Ok(Err(invalid(
            "the cited statement activation does not exist at this known-at",
        )));
    };
    let entry = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "statement activation")?)
        .map_err(KernelError::from)?;
    let activated = activation_of(db, cx, book, &row, &entry, at)?;
    if &activated.definition != definition || activated.effective_from > day {
        return Ok(Err(invalid(
            "the cited activation does not approve this exact definition at the selected effective date",
        )));
    }
    let before = CommitSeq(
        activated
            .recorded_at
            .0
            .checked_sub(1)
            .ok_or_else(|| corrupt("activation has no preceding chart"))?,
    );
    let (accounts, basis) = accounts_and_basis(db, cx, book, before)?;
    if basis != activated.chart_digest {
        return Err(
            corrupt("activation's reviewed chart digest differs from its original chart").into(),
        );
    }
    let lint = match lint(definition, &accounts) {
        Ok(lint) => lint,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Err(refusal) = require_clean(&lint) {
        return Ok(Err(refusal));
    }
    Ok(Ok(activated))
}

/// Semantic integrity checks composed into the facade's existing projection
/// verification. Malformed retained data is drift; interruption and storage
/// failures retain their normal error classes.
pub fn verify_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    at: CommitSeq,
) -> Result<Vec<String>, BookError> {
    let checked = (|| -> Result<Vec<String>, BookError> {
        let activations = history(db, cx, book, at)?;
        let mut drift = Vec::new();
        let mut roots = BTreeSet::new();
        for activation in activations {
            roots.insert(statement_definition_vid(
                book.book_id,
                &activation.definition_oid.0,
            ));
            if let Err(refusal) = validate_active_at(
                db,
                cx,
                book,
                &activation.definition,
                activation.activation,
                activation.effective_from,
                at,
            )? {
                drift.push(format!(
                    "statement activation {:032x}: {}",
                    activation.activation.0, refusal.message
                ));
            }
        }
        for row in db.vertices_at(at).map_err(KernelError::from)? {
            checkpoint(cx)?;
            if !row.labels.contains(&label::STATEMENT_DEFINITION) {
                continue;
            }
            let digest = bytes(&row, property::FA_DIGEST, "statement storage digest")?;
            let digest: [u8; 32] = digest
                .try_into()
                .map_err(|_| corrupt("statement storage digest has the wrong length"))?;
            if row.vid == statement_definition_vid(book.book_id, &digest)
                && !roots.contains(&row.vid)
            {
                drift.push(format!(
                    "statement definition {:032x} has no immutable activation control",
                    row.vid.0
                ));
            }
        }
        Ok(drift)
    })();
    match checked {
        Err(BookError::Kernel(KernelError::Corrupt(message))) => {
            Ok(vec![format!("statement definitions: {message}")])
        }
        Err(BookError::Kernel(KernelError::Model(error))) => {
            Ok(vec![format!("statement definitions: {error}")])
        }
        other => other,
    }
}

fn admit_activation<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
) -> Outcome<()> {
    if let Err(denial) = fa_policy::admit(
        capability,
        &Intent {
            principal: capability.holder(),
            trunk: true,
            op: Op::RuleChange,
            book: book.book_id,
            legs: &[],
        },
    )
    .and_then(|()| fa_policy::reach(capability, &Reach::whole_book(true), None))
    {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    if let Err(denial) = fa_policy::current(capability, db.frontier().map_err(KernelError::from)?) {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    Ok(fa_journal::policy::capability_admitted(
        db, book, capability,
    )?)
}

fn admit_read<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
    at: CommitSeq,
) -> Outcome<()> {
    if let Err(denial) = fa_policy::admit_read(capability, capability.holder(), book.book_id)
        .and_then(|()| {
            fa_policy::reach(
                capability,
                &Reach {
                    observes: fa_policy::Observes::At(at),
                    ..Reach::whole_book(true)
                },
                None,
            )
        })
    {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    Ok(fa_journal::policy::admit_reads(db, book, capability.holder(), capability)?.map(|_| ()))
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    pub fn lint_statement_definition(
        &self,
        cx: &PurposeContexts,
        capability: &Capability,
        definition: &CustomStatementDefinition,
        at: CommitSeq,
    ) -> Outcome<StatementLintReport> {
        self.query(cx, |db, book| {
            if let Err(refusal) = admit_read(db, book, capability, at)? {
                return Ok(Err(refusal));
            }
            if let Err(refusal) = definition_valid(definition) {
                return Ok(Err(refusal));
            }
            let (accounts, _) = accounts_and_basis(db, &cx.query(), book, at)?;
            Ok(lint(definition, &accounts))
        })
    }

    pub fn active_statement_definition(
        &self,
        cx: &PurposeContexts,
        capability: &Capability,
        name: &str,
        day: DateDay,
        at: CommitSeq,
    ) -> Outcome<Option<ActivatedStatementDefinition>> {
        self.query(cx, |db, book| {
            if let Err(refusal) = admit_read(db, book, capability, at)? {
                return Ok(Err(refusal));
            }
            resolve_at(db, &cx.query(), book, name, day, at)
        })
    }

    pub fn plan_statement_definition(
        &self,
        cx: &PurposeContexts,
        capability: &Capability,
        definition: CustomStatementDefinition,
        effective_from: DateDay,
        idempotency_key: &[u8],
    ) -> Outcome<StatementDefinitionPlan> {
        if let Err(refusal) = admit_activation(&self.db, &self.context, capability)? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = definition_valid(&definition) {
            return Ok(Err(refusal));
        }
        if idempotency_key.is_empty() || idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
            return Ok(Err(invalid(format!(
                "activation requires an idempotency key of 1..={MAX_IDEMPOTENCY_KEY_BYTES} bytes"
            ))));
        }
        let (accounts, chart_digest) = self.query(cx, |db, book| {
            let at = db.frontier().map_err(KernelError::from)?;
            accounts_and_basis(db, &cx.query(), book, at)
        })?;
        let report = match lint(&definition, &accounts) {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if let Err(refusal) = require_clean(&report) {
            return Ok(Err(refusal));
        }
        let at = self.db.frontier().map_err(KernelError::from)?;
        if let Some(last) = history(&self.db, &cx.query(), &self.context, at)?
            .into_iter()
            .rfind(|activation| activation.definition.name == definition.name)
            && (definition.version <= last.definition.version
                || effective_from <= last.effective_from)
        {
            return Ok(Err(invalid(
                "a statement name's version and effective date must both advance",
            )));
        }
        let description = self.seal_text(
            cx,
            &format!(
                "Activate statement {} version {}",
                definition.name, definition.version
            ),
        )?;
        Ok(Ok(StatementDefinitionPlan {
            book_id: self.context.book_id,
            definition,
            principal_ref: capability.holder(),
            effective_from,
            chart_digest,
            idempotency_key: idempotency_key.to_vec(),
            description,
        }))
    }

    /// Publish the complete definition, activation and shared intent claim in
    /// one transaction. The exclusive book borrow prevents interleaved schema
    /// writes while the chart is checked; native witnesses guard approvals,
    /// authority, existing accounts and publication identities as well.
    pub async fn activate_statement_definition(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        plan: StatementDefinitionPlan,
        approvals: Vec<ApprovalRef>,
    ) -> Outcome<ActivatedStatementDefinition> {
        checkpoint(&cx.query())?;
        if let Err(refusal) = admit_activation(&self.db, &self.context, capability)? {
            return Ok(Err(refusal));
        }
        if plan.book_id != self.context.book_id || plan.principal_ref != capability.holder() {
            return Ok(Err(invalid(
                "the activation plan names another book or preparer",
            )));
        }
        if let Err(refusal) = definition_valid(&plan.definition) {
            return Ok(Err(refusal));
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
            fa_journal::policy::capability_witness(&txn, &self.db, &self.context, capability)?
        {
            txn.abort();
            return Ok(Err(refusal));
        }
        let epoch = fa_journal::policy::epoch_witness(&txn, &self.db)?;
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
            let stored = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "activation retry")?)
                .map_err(KernelError::from)?;
            if stored.proposal_digest != proposal_digest
                || stored.approvals != approvals
                || !outcome::verify_control_recorded(&self.db, &row, &stored)?
            {
                return Ok(Err(Refusal::new(
                    fa_journal::refusal::code::IDEMPOTENCY_CONFLICT,
                    fa_journal::exit::CONFLICT,
                    "this idempotency key already records different content or approvals",
                    "plan §5.9 (one successful intent per book, principal and key)",
                    "retry the unchanged saved activation plan and approvals, or use a new key",
                )));
            }
            let at = self.db.frontier().map_err(KernelError::from)?;
            let mut recorded = match validate_active_at(
                &self.db,
                &cx.query(),
                &self.context,
                &plan.definition,
                evid,
                plan.effective_from,
                at,
            )? {
                Ok(recorded) => recorded,
                Err(refusal) => return Ok(Err(refusal)),
            };
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
                "the accounting schema changed after this definition was reviewed",
            )));
        }
        let report = match lint(&plan.definition, &accounts) {
            Ok(report) => report,
            Err(refusal) => {
                txn.abort();
                return Ok(Err(refusal));
            }
        };
        if let Err(refusal) = require_clean(&report) {
            txn.abort();
            return Ok(Err(refusal));
        }
        if let Some(last) = history(&self.db, &cx.query(), &self.context, basis)?
            .into_iter()
            .rfind(|activation| activation.definition.name == plan.definition.name)
            && (plan.definition.version <= last.definition.version
                || plan.effective_from <= last.effective_from)
        {
            txn.abort();
            return Ok(Err(conflict(
                "another activation already advanced this definition's name",
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
            Party::for_capability(plan.principal_ref, capability),
        )? {
            txn.abort();
            return Ok(Err(refusal));
        }
        let definition_oid = plan.definition.digest().map_err(KernelError::from)?;
        let root = statement_definition_vid(self.context.book_id, &definition_oid.0);
        if txn
            .vertex(&self.db, root)
            .map_err(KernelError::from)?
            .is_some()
        {
            txn.abort();
            return Err(corrupt(
                "an immutable definition root exists without its lawful advancing activation",
            )
            .into());
        }
        let encoded = plan
            .definition
            .canonical_bytes()
            .map_err(KernelError::from)?;
        let entry = proposal.seal(approvals, None).map_err(KernelError::from)?;
        let mut batch = WriteBatch::new(relation::IN_BOOK);
        object::stage(
            &cx.query(),
            &mut batch,
            self.context.book_id,
            root,
            label::STATEMENT_DEFINITION,
            ObjectKind::StatementDefinition,
            &encoded,
        )?;
        batch.create_vertex(
            root,
            vec![label::STATEMENT_DEFINITION],
            vec![
                (
                    property::FA_PAYLOAD,
                    scalar_bytes(
                        "statement definition",
                        object::payload(ObjectKind::StatementDefinition, &encoded)?,
                    )?,
                ),
                (
                    property::FA_DIGEST,
                    scalar_bytes("statement definition digest", definition_oid.0.to_vec())?,
                ),
                (
                    property::BOOK_ID,
                    scalar_bytes("statement definition book", self.context.book_id.0.to_vec())?,
                ),
            ],
        );
        batch.create_vertex(
            evid,
            vec![label::ENTRY],
            entry_mirrors(&entry).map_err(KernelError::from)?,
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
        if let Err(denial) = fa_policy::current(capability, basis) {
            txn.abort();
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        match txn.commit(&mut self.db, &cx.commit()).await {
            Ok(recorded_at) => Ok(Ok(ActivatedStatementDefinition {
                definition: plan.definition,
                definition_oid,
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
