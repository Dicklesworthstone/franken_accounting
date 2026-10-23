//! Canon rule versions in the journal (plan §10.3, §10.6, bead fa-c34).
//!
//! `fa rule propose` journals a rule version: one immutable schema control
//! whose canonical body is the rule's source and the IR the kernel compiled
//! it to against the book's units, and, in the same transaction, the
//! `RuleVersion` vertex that carries that body. The vertex is addressed by
//! the IR's digest, so a version is its content: proposing the same IR
//! again writes nothing, and a reader that decodes a stored IR to another
//! digest has found corruption, never a different rule. Proposing needs
//! `rule_change`; it activates nothing, and no entry derives from a version
//! until an activation names it.

use asupersync::fs::Vfs;
use fa_canon::{CanonError, CompiledRule, Derivation, EvalError};
use fa_model::limits::{MAX_DESCRIPTION_BYTES, MAX_IDEMPOTENCY_KEY_BYTES};
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ApprovalRef, ControlKind, ControlPayload, Entry, EntryClass, EntryOrigin, EntryPayload,
    Erasable, Id128, LegPayload, Oid, Reader, Writer, domain_digest, entry_mirrors, entry_vid,
    rule_name_vid, rule_version_vid,
};
use fa_policy::{Capability, Intent, Op, Party, Reach};
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::chart::schema_control_proposal;
use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{book_root, bytes, edge_id, scalar_bytes, scalar_text, text};

pub const SCHEMA_CHANGE_RULE_VERSION: u16 = 20;
const FORMAT: &[u8] = b"fa:rule-version:v1";
const MAX_IR_BYTES: usize = 4 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 1024;

const CITE: &str = "plan §10.3 (Canon: a total, statically typed rule language whose units, laws and balance are checked before it runs)";
const EVAL_CITE: &str = "plan §10.3 (a rule that cannot be evaluated fails closed with a typed error instead of posting a guess)";

fn corrupt(message: impl Into<String>) -> KernelError {
    KernelError::Corrupt(format!("rule version: {}", message.into()))
}

/// The refusal for a source the checker rejects, at the line and column it
/// names (FA-REF-196).
#[must_use]
pub fn rule_refusal(error: &CanonError) -> Refusal {
    Refusal::new(
        code::CANON_RULE,
        exit::REFUSAL,
        format!(
            "the rule is refused at line {}, column {}: {}",
            error.line, error.column, error.message
        ),
        CITE,
        "revise the rule at that line and column, then run fa rule check <file> again",
    )
    .at("rule", format!("{}:{}", error.line, error.column))
}

/// The refusal for an evaluation that cannot be computed over an event
/// (FA-REF-196).
#[must_use]
pub fn evaluation_refusal(rule: &CompiledRule, event: &str, error: &EvalError) -> Refusal {
    let fix = match error {
        EvalError::WrongEventKind { rule, .. } => {
            format!("evaluate the rule over a {} event (fa event list)", rule.name())
        }
        EvalError::MissingResource { .. } | EvalError::AmbiguousResource { .. } => {
            "evaluate an event that carries each resource the rule reads exactly once (fa event show <code>), or revise the rule".to_string()
        }
        EvalError::ResourceUnit { .. } => {
            "read the resource in the unit the event records it in, or evaluate another event"
                .to_string()
        }
        EvalError::MissingInput { name } => format!("supply --input {name}=<value>"),
        EvalError::UndeclaredInput { name } => {
            format!("drop --input {name}, or declare it in the rule's inputs block")
        }
        EvalError::InputType { name, .. } => {
            format!("supply --input {name}=<value> in the declared type")
        }
        EvalError::Overflow { .. } | EvalError::NegativeLeg { .. } | EvalError::Encode(_) => {
            "revise the rule so every leg is a non-negative amount within range for this event"
                .to_string()
        }
    };
    Refusal::new(
        code::CANON_RULE,
        exit::REFUSAL,
        format!(
            "rule {} v{} cannot be evaluated over event {event}: {error}",
            rule.name(),
            rule.version()
        ),
        EVAL_CITE,
        fix,
    )
    .at("event", event)
}

/// A rule version's canonical body: the source as proposed and the IR the
/// kernel compiled it to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleVersionSpec {
    pub source: String,
    pub ir: Vec<u8>,
}

impl RuleVersionSpec {
    pub fn encode(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut w = Writer::new();
        w.fixed(FORMAT).str(&self.source).bytes(&self.ir);
        w.finish()
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(encoded);
        let bad = |error: fa_model::DecodeError| corrupt(error.to_string());
        if r.fixed::<{ FORMAT.len() }>("rule version format")
            .map_err(bad)?
            .as_slice()
            != FORMAT
        {
            return Err(corrupt("unknown rule version encoding"));
        }
        let source = r
            .str(fa_canon::MAX_SOURCE_BYTES, "rule source")
            .map_err(bad)?
            .to_string();
        let ir = r.bytes(MAX_IR_BYTES, "rule ir").map_err(bad)?.to_vec();
        r.finish().map_err(bad)?;
        Ok(Self { source, ir })
    }
}

/// A rule version as the book holds it: its body and the rule its IR
/// decodes to, whose digest is the version's address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleVersionRow {
    pub vid: VId,
    pub spec: RuleVersionSpec,
    pub rule: CompiledRule,
    pub created_at: CommitSeq,
}

impl RuleVersionRow {
    /// Decode a `RuleVersion` vertex; `None` for any other vertex. The IR is
    /// decoded through Canon's validation and balance proof against the
    /// book's units, and must address this very vertex.
    pub fn decode(row: &VertexRow, book: &BookContext) -> Result<Option<Self>, KernelError> {
        if !row.labels.contains(&label::RULE_VERSION) {
            return Ok(None);
        }
        let spec =
            RuleVersionSpec::decode(&bytes(row, property::FA_PAYLOAD, "rule version payload")?)?;
        let rule = CompiledRule::decode(&spec.ir, &book.units)
            .map_err(|e| corrupt(format!("{:032x}: {e}", row.vid.0)))?;
        if rule_version_vid(book.book_id, &rule.ir_digest()) != row.vid {
            return Err(corrupt(format!(
                "{:032x}: its IR digests to another version",
                row.vid.0
            )));
        }
        Ok(Some(Self {
            vid: row.vid,
            spec,
            rule,
            created_at: row.created_at,
        }))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleVersionRecorded {
    pub version: RuleVersionRow,
    /// The control entry this key recorded; `None` when another proposal
    /// had already recorded the same IR, so this one wrote nothing.
    pub control_entry: Option<VId>,
    /// True when nothing was written: an identical retry of the same key, or
    /// a version whose IR the book already holds.
    pub already_recorded: bool,
}

/// The sealed control `propose_rule_version` journals for `spec`: one
/// book-scoped SchemaControl with no legs, under the idempotency `key`.
pub fn rule_version_control(
    book: &BookContext,
    spec: &RuleVersionSpec,
    principal: VId,
    key: &[u8],
    description: Erasable<String>,
) -> Result<(EntryPayload, Entry), KernelError> {
    let proposal = schema_control_proposal(
        book,
        SCHEMA_CHANGE_RULE_VERSION,
        spec.encode()?,
        principal,
        DateDay(0),
        key,
        description,
    );
    let entry = proposal.clone().seal(Vec::new(), None)?;
    Ok((proposal, entry))
}

/// Every rule version the book holds at `at`, by rule name then version
/// then address.
pub fn rule_versions_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    at: CommitSeq,
) -> Result<Vec<RuleVersionRow>, KernelError> {
    if at > db.frontier()? {
        return Err(corrupt("known-at is beyond the book head"));
    }
    let mut versions = Vec::new();
    for vid in db.in_neighbours_at(book_root(), relation::IN_BOOK, at)? {
        let Some(row) = db.vertex_at(vid, at)? else {
            continue;
        };
        if let Some(version) = RuleVersionRow::decode(&row, book)? {
            versions.push(version);
        }
    }
    versions.sort_by(|a, b| {
        (a.rule.name(), a.rule.version(), a.rule.ir_digest()).cmp(&(
            b.rule.name(),
            b.rule.version(),
            b.rule.ir_digest(),
        ))
    });
    Ok(versions)
}

/// The rule version addressed by `ir_digest` at `at`, if the book holds it.
pub fn rule_version_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    ir_digest: &[u8; 32],
    at: CommitSeq,
) -> Result<Option<RuleVersionRow>, KernelError> {
    if at > db.frontier()? {
        return Err(corrupt("known-at is beyond the book head"));
    }
    match db.vertex_at(rule_version_vid(book.book_id, ir_digest), at)? {
        Some(row) => RuleVersionRow::decode(&row, book),
        None => Ok(None),
    }
}

/// Admit `capability` to change rules, before anything is observed: whole-
/// book `rule_change` authority, current at the head.
pub fn admit_rule_change<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    principal: VId,
    capability: &Capability,
) -> Result<Option<Refusal>, KernelError> {
    if let Err(d) = fa_policy::admit_within(
        capability,
        &Intent {
            principal,
            trunk: true,
            op: Op::RuleChange,
            book: book.book_id,
            legs: &[],
        },
        &Reach::whole_book(true),
        None,
    ) {
        return Ok(Some(crate::policy::refusal(&d)));
    }
    if let Err(d) = fa_policy::current(capability, db.frontier()?) {
        return Ok(Some(crate::policy::refusal(&d)));
    }
    Ok(None)
}

/// Journal a rule version under current whole-book `rule_change` authority
/// (plan §10.6). The kernel compiles `source` against the book's units
/// itself, so a stored IR is always the compiler's output for its source;
/// a source the compiler refuses is FA-REF-196. A retry of the same key,
/// or a source whose IR the book already holds, writes nothing.
#[allow(clippy::too_many_arguments)]
pub async fn propose_rule_version<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    source: &str,
    principal: VId,
    key: &[u8],
    description: Erasable<String>,
    capability: &Capability,
) -> Outcome<RuleVersionRecorded> {
    if let Some(refusal) = admit_rule_change(db, book, principal, capability)? {
        return Ok(Err(refusal));
    }
    let rule = match fa_canon::compile(source, &book.units) {
        Ok(rule) => rule,
        Err(error) => return Ok(Err(rule_refusal(&error))),
    };
    let spec = RuleVersionSpec {
        source: source.to_string(),
        ir: rule.ir().to_vec(),
    };
    let (proposal, entry) = rule_version_control(book, &spec, principal, key, description)?;
    let evid = entry_vid(book.book_id, &principal.0.to_le_bytes(), key);
    let version_vid = rule_version_vid(book.book_id, &rule.ir_digest());
    let mut txn = db.begin(&ctx.txn())?;
    if let Err(refusal) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let _epoch = crate::policy::epoch_witness(&txn, db)?;
    if let Some(row) = txn.vertex(db, evid)? {
        let version_row = txn.vertex(db, version_vid)?;
        txn.abort();
        let stored = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "entry payload")?)?;
        if stored.proposal.semantic_digest(&book.seal_key)?
            != proposal.semantic_digest(&book.seal_key)?
        {
            return Ok(Err(Refusal::new(
                code::IDEMPOTENCY_CONFLICT,
                exit::CONFLICT,
                "this idempotency key already records different content",
                "FA-INV-09",
                "retry the original rule version or use a new key",
            )));
        }
        let Some(row) = version_row else {
            return Err(corrupt(
                "a recorded proposal's rule version vertex is missing",
            ));
        };
        let Some(version) = RuleVersionRow::decode(&row, book)? else {
            return Err(corrupt(
                "a recorded proposal names a vertex that is not a rule version",
            ));
        };
        return Ok(Ok(RuleVersionRecorded {
            version,
            control_entry: Some(evid),
            already_recorded: true,
        }));
    }
    if let Some(row) = txn.vertex(db, version_vid)? {
        txn.abort();
        let Some(version) = RuleVersionRow::decode(&row, book)? else {
            return Err(corrupt("a rule version address names another vertex"));
        };
        return Ok(Ok(RuleVersionRecorded {
            version,
            control_entry: None,
            already_recorded: true,
        }));
    }
    let root = book_root();
    let mut props = vec![
        (
            property::BOOK_ID,
            scalar_bytes("book_id", book.book_id.0.to_vec())?,
        ),
        (property::NAME, scalar_text("name", rule.name())?),
        (
            property::FA_PAYLOAD,
            scalar_bytes("rule_version._fa_payload", spec.encode()?)?,
        ),
    ];
    props.sort_by_key(|(k, _)| k.0);
    let mut in_book = WriteBatch::new(relation::IN_BOOK);
    in_book.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    in_book.create_vertex(version_vid, vec![label::RULE_VERSION], props);
    in_book.add_edge(
        edge_id(relation::IN_BOOK, version_vid, root),
        version_vid,
        root,
        vec![],
    );
    if let Err(error) = txn.write_ordered(db, vec![in_book]) {
        txn.abort();
        return Err(error.into());
    }
    if let Err(denial) = fa_policy::current(capability, db.frontier()?) {
        txn.abort();
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(recorded_at) => Ok(Ok(RuleVersionRecorded {
            version: RuleVersionRow {
                vid: version_vid,
                spec,
                rule,
                created_at: recorded_at,
            },
            control_entry: Some(evid),
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("a rule version witness changed: {detail}"),
                "FG-LAW-FCW-01",
                "retry against the current frontier",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            "a concurrent proposal of the same rule version collided on its address",
            "FA-INV-09",
            "fa rule list shows the recorded version; retry its original key",
        ))),
        Err(error) => Err(error.into()),
    }
}

/// Decode a rule version's control body, as chart replay does to skip it.
pub(crate) fn validate_control(canonical_bytes: &[u8]) -> Result<(), KernelError> {
    RuleVersionSpec::decode(canonical_bytes).map(|_| ())
}

// ---- Activation (plan §10.3, §10.6; Appendix C PolicyControl) ----------

/// The plan file of a rule activation: `"fa:rule-activate" ‖ u16 version ‖
/// [32] ir_digest ‖ str name ‖ u128 principal ‖ i32 effective_from ‖ bytes
/// key ‖ erasable description`.
pub const RULE_ACTIVATION_PLAN_DOMAIN: &[u8; 16] = b"fa:rule-activate";
const ACTIVATION_PLAN_VERSION: u16 = 1;
const ACTIVATION_KEY_DOMAIN: &[u8] = b"fa:rule-activation-key:v1";
const BINDINGS_FORMAT: &[u8] = b"fa:rule-bindings:v1";
const MAX_BINDINGS: usize = 4096;
/// The `LifecycleTransition` state an activation journals on its version.
const ACTIVATED: u8 = 1;

/// From `effective_from`, the rule is in force at the version `ir_digest`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleBinding {
    pub effective_from: DateDay,
    pub ir_digest: [u8; 32],
}

/// A rule name's bindings, strictly ascending by date: on any date the
/// version in force is the last binding effective on or before it, and
/// before the first there is none. The `RuleName` vertex carries them, a
/// projection of the name's activation controls in recorded order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleBindings(pub Vec<RuleBinding>);

impl RuleBindings {
    /// The version in force on `day`, if any.
    #[must_use]
    pub fn in_force(&self, day: DateDay) -> Option<[u8; 32]> {
        self.0
            .iter()
            .rev()
            .find(|binding| binding.effective_from <= day)
            .map(|binding| binding.ir_digest)
    }

    fn encode(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut w = Writer::new();
        w.fixed(BINDINGS_FORMAT).list(&self.0, |w, binding| {
            w.i32(binding.effective_from.0).fixed(&binding.ir_digest);
        });
        w.finish()
    }

    fn decode(encoded: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(encoded);
        let bad = |error: fa_model::DecodeError| corrupt(error.to_string());
        if r.fixed::<{ BINDINGS_FORMAT.len() }>("rule bindings format")
            .map_err(bad)?
            .as_slice()
            != BINDINGS_FORMAT
        {
            return Err(corrupt("unknown rule bindings encoding"));
        }
        let bindings = r
            .list(MAX_BINDINGS, "rule bindings", |r| {
                Ok(RuleBinding {
                    effective_from: DateDay(r.i32("rule binding date")?),
                    ir_digest: r.fixed("rule binding version")?,
                })
            })
            .map_err(bad)?;
        r.finish().map_err(bad)?;
        if bindings
            .windows(2)
            .any(|pair| pair[0].effective_from >= pair[1].effective_from)
        {
            return Err(corrupt("rule bindings are not strictly ascending by date"));
        }
        Ok(Self(bindings))
    }
}

/// A rule name as the book holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleNameRow {
    pub vid: VId,
    pub name: String,
    pub bindings: RuleBindings,
}

impl RuleNameRow {
    /// Decode a `RuleName` vertex; `None` for any other vertex.
    pub fn decode(row: &VertexRow) -> Result<Option<Self>, KernelError> {
        if !row.labels.contains(&label::RULE_NAME) {
            return Ok(None);
        }
        Ok(Some(Self {
            vid: row.vid,
            name: text(row, property::NAME, "rule name")?,
            bindings: RuleBindings::decode(&bytes(row, property::FA_PAYLOAD, "rule bindings")?)?,
        }))
    }
}

/// Every rule name with an activation at `at`, by name.
pub fn rule_names_at<V: Vfs + Clone>(
    db: &Database<V>,
    at: CommitSeq,
) -> Result<Vec<RuleNameRow>, KernelError> {
    if at > db.frontier()? {
        return Err(corrupt("known-at is beyond the book head"));
    }
    let mut names = Vec::new();
    for vid in db.in_neighbours_at(book_root(), relation::IN_BOOK, at)? {
        let Some(row) = db.vertex_at(vid, at)? else {
            continue;
        };
        if let Some(name) = RuleNameRow::decode(&row)? {
            names.push(name);
        }
    }
    names.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(names)
}

/// A planned activation: what [`activate_rule_version`] rebuilds its
/// proposal from, with the description sealed once. Approvers bind
/// [`RuleActivationPlan::proposal_digest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleActivationPlan {
    pub ir_digest: [u8; 32],
    pub rule_name: String,
    pub principal_ref: VId,
    pub effective_from: DateDay,
    pub idempotency_key: Vec<u8>,
    pub description: Erasable<String>,
}

impl RuleActivationPlan {
    /// The `PolicyControl` proposal this plan commits: a `LifecycleTransition`
    /// on the version's vertex, effective from the activation date.
    pub fn proposal(&self, book: &BookContext) -> EntryPayload {
        EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: book.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::POLICY_CONTROL,
            effective_date: self.effective_from,
            document_date: None,
            description: self.description.clone(),
            effective_period: None,
            legs: Vec::new(),
            control: Some(ControlPayload::LifecycleTransition {
                object_ref: rule_version_vid(book.book_id, &self.ir_digest),
                from: 0,
                to: ACTIVATED,
                proof_refs: Vec::new(),
                reason_code: 0,
            }),
            unit_totals: Vec::new(),
            base_totals: None,
            idempotency_key: domain_digest(ACTIVATION_KEY_DOMAIN, &[&self.idempotency_key])
                .to_vec(),
            origin: EntryOrigin::Control {
                control_kind: ControlKind::RULE_ACTIVATION,
                spec_body_digest: self.ir_digest,
            },
            principal_ref: self.principal_ref,
            session_ref: None,
            evidence: Vec::new(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// The digest an approval of this plan binds.
    pub fn proposal_digest(&self, book: &BookContext) -> Result<[u8; 32], KernelError> {
        Ok(self.proposal(book).proposal_digest()?)
    }

    pub fn encode(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::new();
        w.fixed(RULE_ACTIVATION_PLAN_DOMAIN)
            .u16(ACTIVATION_PLAN_VERSION)
            .fixed(&self.ir_digest)
            .str(&self.rule_name)
            .u128(self.principal_ref.0)
            .i32(self.effective_from.0)
            .bytes(&self.idempotency_key);
        self.description.encode(&mut w);
        Ok(w.finish()?)
    }

    /// Decode a plan; refuses another format, an unknown version and
    /// trailing bytes.
    pub fn decode(encoded: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(encoded);
        let bad = |error: fa_model::DecodeError| corrupt(error.to_string());
        let domain: [u8; 16] = r.fixed("rule activation plan domain").map_err(bad)?;
        if domain != *RULE_ACTIVATION_PLAN_DOMAIN {
            return Err(corrupt("not a rule activation plan"));
        }
        if r.u16("rule activation plan version").map_err(bad)? != ACTIVATION_PLAN_VERSION {
            return Err(corrupt("unknown rule activation plan version"));
        }
        let plan = Self {
            ir_digest: r.fixed("rule activation version").map_err(bad)?,
            rule_name: r
                .str(MAX_TEXT_BYTES, "rule activation name")
                .map_err(bad)?
                .to_string(),
            principal_ref: VId(r.u128("rule activation principal").map_err(bad)?),
            effective_from: DateDay(r.i32("rule activation date").map_err(bad)?),
            idempotency_key: r
                .bytes(MAX_IDEMPOTENCY_KEY_BYTES, "rule activation key")
                .map_err(bad)?
                .to_vec(),
            description: Erasable::decode(&mut r, MAX_DESCRIPTION_BYTES).map_err(bad)?,
        };
        r.finish().map_err(bad)?;
        Ok(plan)
    }
}

/// A journaled activation, and whether this commit found it already
/// recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleActivated {
    pub rule_name: String,
    pub binding: RuleBinding,
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
    pub approvals: usize,
    pub already_recorded: bool,
}

fn activation_refusal(message: String) -> Refusal {
    Refusal::new(
        code::CANON_RULE,
        exit::REFUSAL,
        message,
        "plan §10.3 (a rule version is activated from a date by a PolicyControl entry; a name's activations move forward in time)",
        "fa rule list shows each name's versions in force; activate a later date, or another version",
    )
}

/// Whether activating `ir_digest` for a name with `bindings` from `from` is
/// lawful: activations move forward in time, and a version already in force
/// from the last binding is not activated again.
fn binding_refusal(
    bindings: &RuleBindings,
    name: &str,
    from: DateDay,
    ir_digest: &[u8; 32],
) -> Option<Refusal> {
    let last = bindings.0.last()?;
    if last.ir_digest == *ir_digest {
        return Some(activation_refusal(format!(
            "rule {name} is already in force at this version from {}",
            last.effective_from.render()
        )));
    }
    if from <= last.effective_from {
        return Some(activation_refusal(format!(
            "rule {name} was last activated from {}; a later activation takes effect after it, not on {}",
            last.effective_from.render(),
            from.render()
        )));
    }
    None
}

/// Authority before any read (doctrine 8): the `PolicyControl`
/// `ActivateRule` row's preparer op, held by the acting principal for this
/// book and current at the head.
pub fn admit_rule_activation<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
) -> Outcome<()> {
    let op = crate::policy::steward()?
        .transition_op("PolicyControl", "ActivateRule")
        .ok_or_else(|| {
            KernelError::Corrupt(
                "sod_policy.toml registers no PolicyControl ActivateRule rule; the activation is refused, never unconstrained".into(),
            )
        })?;
    if let Err(d) = fa_policy::admit(
        capability,
        &Intent {
            principal: capability.holder(),
            trunk: true,
            op,
            book: book.book_id,
            legs: &[],
        },
    ) {
        return Ok(Err(crate::policy::refusal(&d)));
    }
    if let Err(d) = fa_policy::current(capability, db.frontier()?) {
        return Ok(Err(crate::policy::refusal(&d)));
    }
    Ok(Ok(()))
}

/// Plan activating the version `ir_digest` from `effective_from` under
/// `capability`: admitted first, then the version and its name's bindings
/// are read at the head. Nothing is written; the commit rechecks
/// everything.
pub fn plan_rule_activation<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
    ir_digest: &[u8; 32],
    effective_from: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
) -> Outcome<RuleActivationPlan> {
    if let Err(r) = admit_rule_activation(db, book, capability)? {
        return Ok(Err(r));
    }
    if idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Ok(Err(activation_refusal(format!(
            "an idempotency key is at most {MAX_IDEMPOTENCY_KEY_BYTES} bytes"
        ))));
    }
    let head = db.frontier()?;
    let Some(version) = rule_version_at(db, book, ir_digest, head)? else {
        return Ok(Err(unknown_version(ir_digest)));
    };
    let name = version.rule.name().to_string();
    let bindings = match db.vertex(rule_name_vid(book.book_id, &name))? {
        Some(row) => RuleNameRow::decode(&row)?
            .map(|r| r.bindings)
            .unwrap_or_default(),
        None => RuleBindings::default(),
    };
    if let Some(refusal) = binding_refusal(&bindings, &name, effective_from, ir_digest) {
        return Ok(Err(refusal));
    }
    let plan = RuleActivationPlan {
        ir_digest: *ir_digest,
        rule_name: name,
        principal_ref: capability.holder(),
        effective_from,
        idempotency_key: idempotency_key.to_vec(),
        description,
    };
    if plan.proposal(book).validate().is_err() {
        return Ok(Err(activation_refusal(
            "the planned activation is not a valid PolicyControl entry".into(),
        )));
    }
    Ok(Ok(plan))
}

/// The refusal for an address the book holds no rule version at.
#[must_use]
pub fn unknown_version(ir_digest: &[u8; 32]) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        format!(
            "this book holds no rule version {}",
            crate::evidence::hex(ir_digest)
        ),
        "plan §10.6 (a rule is proposed as a version before it is activated)",
        "fa rule list names the versions; fa rule propose <file> journals one",
    )
}

/// Commit `plan` under `capability` and the cited `approvals`: one commit of
/// the `PolicyControl` record and the rule name's bindings, compare-and-set
/// from the value this transaction witnessed. The plan's principal must be
/// the capability's holder; the version must be this book's and still the
/// plan's rule; the activation must still move the name forward; and the
/// approvals must satisfy the `rule-activate` SoD rule over exactly the
/// plan's proposal. The same plan committed again returns the recorded
/// activation.
pub async fn activate_rule_version<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    plan: RuleActivationPlan,
    approvals: Vec<ApprovalRef>,
) -> Outcome<RuleActivated> {
    if let Err(r) = admit_rule_activation(db, book, capability)? {
        return Ok(Err(r));
    }
    let principal = capability.holder();
    if plan.principal_ref != principal {
        return Ok(Err(activation_refusal(format!(
            "the plan was prepared by principal {:032x}, not by the committing principal {:032x}; plan the activation as the principal who commits it",
            plan.principal_ref.0, principal.0
        ))));
    }
    let proposal = plan.proposal(book);
    if proposal.validate().is_err() {
        return Ok(Err(activation_refusal(
            "the planned activation is not a valid PolicyControl entry".into(),
        )));
    }
    let proposal_digest = proposal.proposal_digest()?;
    let evid = entry_vid(
        book.book_id,
        &principal.0.to_le_bytes(),
        &proposal.idempotency_key,
    );
    let binding = RuleBinding {
        effective_from: plan.effective_from,
        ir_digest: plan.ir_digest,
    };
    let mut txn = db.begin(&ctx.txn())?;
    if let Err(r) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let epoch = crate::policy::epoch_witness(&txn, db)?;
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        let (stored, recorded_at) = crate::post::entry_of(&row)?;
        if stored.proposal_digest != proposal_digest {
            return Ok(Err(Refusal::new(
                code::IDEMPOTENCY_CONFLICT,
                exit::CONFLICT,
                format!(
                    "this activation's identity holds different content; the recorded entry is {:032x}",
                    row.vid.0
                ),
                "FA-INV-09",
                "commit the identical plan to get its recorded outcome, or plan the activation under a new --key",
            )));
        }
        return Ok(Ok(RuleActivated {
            rule_name: plan.rule_name,
            binding,
            control_entry: evid,
            recorded_at,
            approvals: stored.approvals.len(),
            already_recorded: true,
        }));
    }
    let version_vid = rule_version_vid(book.book_id, &plan.ir_digest);
    let version = match txn.vertex(db, version_vid)? {
        Some(row) => RuleVersionRow::decode(&row, book)?,
        None => None,
    };
    let Some(version) = version else {
        txn.abort();
        return Ok(Err(unknown_version(&plan.ir_digest)));
    };
    if version.rule.name() != plan.rule_name {
        txn.abort();
        return Ok(Err(activation_refusal(format!(
            "version {} is rule {}, not {}",
            crate::evidence::hex(&plan.ir_digest),
            version.rule.name(),
            plan.rule_name
        ))));
    }
    let name_vid = rule_name_vid(book.book_id, &plan.rule_name);
    let name_row = txn.vertex(db, name_vid)?;
    let witnessed = txn.vertex_property(db, name_vid, property::FA_PAYLOAD)?;
    let mut bindings = match &name_row {
        Some(row) => {
            RuleNameRow::decode(row)?
                .ok_or_else(|| corrupt("a rule name address holds another vertex"))?
                .bindings
        }
        None => RuleBindings::default(),
    };
    if let Some(refusal) = binding_refusal(
        &bindings,
        &plan.rule_name,
        plan.effective_from,
        &plan.ir_digest,
    ) {
        txn.abort();
        return Ok(Err(refusal));
    }
    let key = fa_policy::sod::control_key("PolicyControl", None, "ActivateRule");
    let preparer = Party {
        principal,
        profile: capability.profile(),
    };
    if let Err(r) = crate::policy::authorize_approvals(
        &txn,
        db,
        book,
        &approvals,
        &proposal_digest,
        epoch,
        &key,
        0,
        preparer,
    )? {
        txn.abort();
        return Ok(Err(r));
    }
    let cited = approvals.len();
    let entry = proposal.seal(approvals, None)?;
    bindings.0.push(binding);
    let encoded = scalar_bytes("rule_name._fa_payload", bindings.encode()?)?;
    let mut in_book = WriteBatch::new(relation::IN_BOOK);
    in_book.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    if name_row.is_some() {
        in_book.compare_and_set_vertex_property(
            name_vid,
            property::FA_PAYLOAD,
            witnessed,
            encoded,
            WriteMismatchPolicy::AbortWrite,
        );
    } else {
        let mut props = vec![
            (
                property::BOOK_ID,
                scalar_bytes("book_id", book.book_id.0.to_vec())?,
            ),
            (property::NAME, scalar_text("name", &plan.rule_name)?),
            (property::FA_PAYLOAD, encoded),
        ];
        props.sort_by_key(|(k, _)| k.0);
        in_book.create_vertex(name_vid, vec![label::RULE_NAME], props);
        in_book.add_edge(
            edge_id(relation::IN_BOOK, name_vid, book_root()),
            name_vid,
            book_root(),
            vec![],
        );
    }
    if let Err(error) = txn.write(db, in_book) {
        txn.abort();
        return Err(error.into());
    }
    if let Err(denial) = fa_policy::current(capability, db.frontier()?) {
        txn.abort();
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(recorded_at) => Ok(Ok(RuleActivated {
            rule_name: plan.rule_name,
            binding,
            control_entry: evid,
            recorded_at,
            approvals: cited,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("a rule activation witness changed: {detail}"),
                "FG-LAW-FCW-01",
                "plan the activation again against the current frontier",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            "a concurrent activation collided on its identity",
            "FA-INV-09",
            "commit the identical plan again to get its recorded outcome",
        ))),
        Err(error) => Err(error.into()),
    }
}

// ---- Rule-derived entries (plan §10.3; FA-INV-05 rule-reproduction) -----

const DERIVATION_CITE: &str = "plan §10.3, FA-INV-05 rule-reproduction (an entry records which version derived it from which event and inputs; re-running the version reproduces it)";

fn derivation_refusal(message: String, fix: &str) -> Refusal {
    Refusal::new(
        code::CANON_RULE,
        exit::REFUSAL,
        message,
        DERIVATION_CITE,
        fix,
    )
}

/// The legs `derivation` posts in this book: each account by its code, each
/// dimension tag as its registered dimension id and the value's identity,
/// ascending by dimension id. The kernel judges the accounts and values as
/// for any posting.
pub fn derived_legs(
    book: &BookContext,
    derivation: &Derivation,
) -> Result<Vec<LegPayload>, Refusal> {
    let mut legs = Vec::with_capacity(derivation.legs.len());
    for leg in &derivation.legs {
        let mut dimension_set = Vec::with_capacity(leg.dims.len());
        for (dimension, code) in &leg.dims {
            let Some(kind) = fa_model::dimension_kind(dimension) else {
                return Err(derivation_refusal(
                    format!("the rule tags `{dimension}`, which is not a registered dimension"),
                    "revise the rule's dims",
                ));
            };
            dimension_set.push((
                kind.id,
                fa_model::dimension_value_vid(book.book_id, kind.code, code),
            ));
        }
        dimension_set.sort_by_key(|(id, _)| *id);
        legs.push(LegPayload {
            side: leg.side,
            account_ref: fa_model::account_vid(book.book_id, &leg.account),
            amount: leg.amount,
            base_amount: None,
            dimension_set,
            memo: None,
            settles: Vec::new(),
        });
    }
    Ok(legs)
}

/// What a rule-derived entry asserts: the version, the event, the inputs'
/// canonical bytes and the derivation they give.
pub struct RuleDerivation<'a> {
    pub rule: &'a CompiledRule,
    pub event: VId,
    pub inputs: &'a [u8],
    pub derivation: &'a Derivation,
    /// The cited event's evidence, which the entry carries as its own.
    pub evidence: &'a [fa_model::EvidenceRef],
}

/// The proposal a rule derivation posts, in the class the rule produces
/// (Original or Adjusting): the derived legs at the derivation's effective
/// date, its origin naming the version, event and inputs digest, and the
/// inputs themselves in extension 32 so the kernel can re-run it. Its
/// evidence is the cited event's.
pub fn rule_derived_proposal(
    book: &BookContext,
    derived: &RuleDerivation<'_>,
    principal: VId,
    idempotency_key: &[u8],
    description: Erasable<String>,
) -> Result<EntryPayload, Refusal> {
    let legs = derived_legs(book, derived.derivation)?;
    let unit_totals = EntryPayload::fold_unit_totals(&legs).map_err(|e| {
        derivation_refusal(
            format!("the derived legs do not fold: {e}"),
            "revise the rule",
        )
    })?;
    Ok(EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: derived.rule.produces().entry_class(),
        effective_date: derived.derivation.effective,
        document_date: None,
        description,
        effective_period: None,
        legs,
        control: None,
        unit_totals,
        base_totals: None,
        idempotency_key: idempotency_key.to_vec(),
        origin: EntryOrigin::Rule {
            rule_version_oid: Oid(derived.rule.ir_digest()),
            event_ref: derived.event,
            inputs_digest: derived.derivation.inputs_digest,
        },
        principal_ref: principal,
        session_ref: None,
        evidence: {
            let mut evidence = derived.evidence.to_vec();
            evidence.sort_unstable();
            evidence.dedup();
            evidence
        },
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: vec![(
            fa_model::entry::RULE_INPUTS_EXTENSION,
            derived.inputs.to_vec(),
        )],
        tags: Vec::new(),
    })
}

/// FA-INV-05 `rule-reproduction`, judged inside the posting transaction:
/// the entry is admitted only when its rule version is this book's and in
/// force (by its name's witnessed bindings) on the entry's effective date,
/// and re-running it over the witnessed cited event with the recorded
/// inputs reproduces the entry's legs and effective date exactly.
pub(crate) fn verify_rule_origin<V: Vfs + Clone>(
    txn: &fgdb::WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    proposal: &EntryPayload,
) -> Outcome<()> {
    let EntryOrigin::Rule {
        rule_version_oid,
        event_ref,
        inputs_digest,
    } = &proposal.origin
    else {
        return Ok(Ok(()));
    };
    let digest = rule_version_oid.0;
    let version = match txn.vertex(db, rule_version_vid(book.book_id, &digest))? {
        Some(row) => RuleVersionRow::decode(&row, book)?,
        None => None,
    };
    let Some(version) = version else {
        return Ok(Err(derivation_refusal(
            format!(
                "the entry names rule version {}, which this book does not hold",
                crate::evidence::hex(&digest)
            ),
            "derive entries with fa rule derive from a proposed and activated version",
        )));
    };
    let rule = &version.rule;
    let bindings = match txn.vertex(db, rule_name_vid(book.book_id, rule.name()))? {
        Some(row) => {
            RuleNameRow::decode(&row)?
                .ok_or_else(|| corrupt("a rule name address holds another vertex"))?
                .bindings
        }
        None => RuleBindings::default(),
    };
    if bindings.in_force(proposal.effective_date) != Some(digest) {
        return Ok(Err(derivation_refusal(
            format!(
                "rule {} is not in force at version {} on {}",
                rule.name(),
                crate::evidence::hex(&digest),
                proposal.effective_date.render()
            ),
            "fa rule list shows the version in force on each date; activate the version (fa rule activate) or derive with the one in force",
        )));
    }
    let Some(row) = txn.vertex(db, *event_ref)? else {
        return Ok(Err(derivation_refusal(
            format!("the cited event {:032x} is not in this book", event_ref.0),
            "fa event list names the recorded events",
        )));
    };
    let event =
        fa_model::EventSpec::decode(&bytes(&row, property::FA_PAYLOAD, "event._fa_payload")?)
            .map_err(|e| corrupt(format!("event payload: {e}")))?;
    let Some((_, recorded)) = proposal
        .extensions
        .iter()
        .find(|(tag, _)| *tag == fa_model::entry::RULE_INPUTS_EXTENSION)
    else {
        return Ok(Err(derivation_refusal(
            "a rule-derived entry records its inputs (extension 32)".into(),
            "derive entries with fa rule derive",
        )));
    };
    if domain_digest(fa_canon::CANON_INPUTS_DOMAIN, &[recorded]) != *inputs_digest {
        return Ok(Err(derivation_refusal(
            "the recorded inputs do not digest to the entry's inputs_digest".into(),
            "derive entries with fa rule derive",
        )));
    }
    let derivation = fa_canon::decode_inputs(rule, recorded)
        .and_then(|inputs| fa_canon::evaluate(rule, &event, &inputs));
    let derivation = match derivation {
        Ok(derivation) => derivation,
        Err(error) => return Ok(Err(evaluation_refusal(rule, &event.code, &error))),
    };
    let expected = match derived_legs(book, &derivation) {
        Ok(legs) => legs,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if derivation.effective != proposal.effective_date || expected != proposal.legs {
        return Ok(Err(derivation_refusal(
            format!(
                "the entry's legs or effective date are not what rule {} v{} ({}) derives from event {} with its recorded inputs",
                rule.name(),
                rule.version(),
                crate::evidence::hex(&digest),
                event.code
            ),
            "derive the entry with fa rule derive, which posts exactly the rule's legs",
        )));
    }
    if proposal.class != rule.produces().entry_class() {
        return Ok(Err(derivation_refusal(
            format!(
                "rule {} v{} produces {} entries, and this entry is another class",
                rule.name(),
                rule.version(),
                rule.produces().name()
            ),
            "derive the entry with fa rule derive, which posts the class the rule produces",
        )));
    }
    Ok(Ok(()))
}
