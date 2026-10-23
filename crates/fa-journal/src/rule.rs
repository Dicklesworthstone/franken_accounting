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
use fa_canon::{CanonError, CompiledRule, EvalError};
use fa_model::symbols::{label, property, relation};
use fa_model::{
    Entry, EntryPayload, Erasable, Reader, Writer, entry_mirrors, entry_vid, rule_version_vid,
};
use fa_policy::{Capability, Intent, Op, Reach};
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::chart::schema_control_proposal;
use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{book_root, bytes, edge_id, scalar_bytes, scalar_text};

pub const SCHEMA_CHANGE_RULE_VERSION: u16 = 20;
const FORMAT: &[u8] = b"fa:rule-version:v1";
const MAX_IR_BYTES: usize = 4 * 1024 * 1024;

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
