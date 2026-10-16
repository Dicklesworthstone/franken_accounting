//! Lantern: forensic and audit analytics (plan §11, bet A4; bead fa-nlu).
//!
//! A procedure is a registered (`registries/procedures.toml`), deterministic
//! computation over a pinned snapshot of the trunk journal as known at one
//! commit sequence. It runs under no clock, entropy, network or filesystem
//! capability: every input is declared (a date is an input, never "today"),
//! the snapshot is read once through the entry-stream reader the register
//! folds use, and the same inputs yield the same findings bit-for-bit,
//! which [`witness::determinism`] checks by re-running over a permuted
//! stream. Findings cite entries, legs, accounts, periods, documents,
//! principals and approvals by typed handle — a free-text citation has no
//! encoding — and carry a statistic with its population. A finding is
//! statistical evidence (plan §11.9): a reproducible observation, never an
//! accusation or a legal conclusion.
//!
//! This slice journals nothing: projections and findings are derived values,
//! rebuildable from the journal and never more authoritative than it
//! (FA-INV-04). The CLI surface is `fa procedure` (`list` and `run`), and
//! journaled `Finding` vertices with `CITES` edges are tracked in follow-on
//! slices of fa-nlu.

#![forbid(unsafe_code)]

pub mod aging;
pub mod catalog;
pub mod conformal;
pub mod cutoff;
pub mod digits;
pub mod duplicates;
pub mod graph;
pub mod jet;
pub mod numbers;
pub mod projection;
pub mod sample;
pub mod snapshot;
pub mod trace;
pub mod witness;

use core::fmt;
use std::collections::BTreeMap;

use fa_journal::KernelError;
use fa_journal::genesis::BookContext;
use fa_journal::rows::leg_vid;
use fa_model::symbols::label;
use fa_model::{DecodeError, EncodeError, Id128, Oid, Reader, Writer, period_vid};
use fa_money::AmountError;
use fa_registers::RegisterError;
use fa_registry::RegistryError;
use fa_registry::procedures::{Claim, Procedure as Row, Procedures};
use fa_time::DateDay;
use fgdb::Database;
use fgdb_crypto::Hasher;
use fgdb_types::{CommitSeq, VId};

pub use snapshot::{Snapshot, SnapshotEntry, Transition};

pub const FINDINGS_DIGEST_DOMAIN: &[u8] = b"fa:lantern-findings:v1";
pub const PARAMETERS_DIGEST_DOMAIN: &[u8] = b"fa:lantern-parameters:v1";

/// The longest narrative a finding may carry; longer text is a defect in the
/// procedure, not data.
pub const MAX_NARRATIVE_BYTES: usize = 1024;
/// The most citations one finding may carry.
pub const MAX_CITES: usize = 4096;

#[derive(Debug)]
pub enum LanternError {
    Kernel(KernelError),
    Register(RegisterError),
    Registry(RegistryError),
    Read(fgdb::ReadError),
    Encoding(EncodeError),
    Decoding(DecodeError),
    Money(AmountError),
    /// The procedure's code names an id the registry does not carry.
    Unregistered {
        procedure: String,
    },
    /// The code and the registry disagree on the procedure's version.
    Version {
        procedure: String,
        code: u16,
        registry: u16,
    },
    /// A parameter the registry does not declare, or a value outside its range.
    Parameter {
        procedure: String,
        name: String,
        message: String,
    },
    /// A sum or statistic exceeded its declared bound.
    Overflow(&'static str),
    /// A procedure exceeded its declared work budget.
    BudgetExhausted {
        procedure: String,
        used: u64,
        budget: u64,
        fix: String,
    },
}

impl LanternError {
    /// Actionable fix hint for CLI and MCP surfaces (plan §15.3).
    #[must_use]
    pub fn fix_hint(&self) -> Option<String> {
        match self {
            Self::Unregistered { .. } => {
                Some("fa procedure list --json names every registered procedure id".into())
            }
            Self::Parameter { .. } => Some(
                "fa procedure list --json shows each procedure's registered parameters and inputs"
                    .into(),
            ),
            Self::Overflow(_) => {
                Some("narrow the coordinate with --effective-through YYYY-MM-DD".into())
            }
            Self::BudgetExhausted { fix, .. } => Some(fix.clone()),
            _ => None,
        }
    }
}

impl fmt::Display for LanternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kernel(e) => write!(f, "{e}"),
            Self::Register(e) => write!(f, "{e}"),
            Self::Registry(e) => write!(f, "{e}"),
            Self::Read(e) => write!(f, "substrate read: {e:?}"),
            Self::Encoding(e) => write!(f, "lantern encoding: {e}"),
            Self::Decoding(e) => write!(f, "lantern decoding: {e:?}"),
            Self::Money(e) => write!(f, "lantern arithmetic: {e:?}"),
            Self::Unregistered { procedure } => {
                write!(
                    f,
                    "procedure `{procedure}` is not registered in procedures.toml"
                )
            }
            Self::Version {
                procedure,
                code,
                registry,
            } => write!(
                f,
                "procedure `{procedure}` is version {code} in code but {registry} in procedures.toml"
            ),
            Self::Parameter {
                procedure,
                name,
                message,
            } => write!(f, "procedure `{procedure}` parameter `{name}`: {message}"),
            Self::Overflow(what) => write!(f, "lantern bound exceeded: {what}"),
            Self::BudgetExhausted {
                procedure,
                used,
                budget,
                fix,
            } => write!(
                f,
                "procedure `{procedure}` exhausted its work budget ({used} > {budget} work units); fix: {fix}"
            ),
        }
    }
}

impl core::error::Error for LanternError {}

/// The registered decimal places of `unit`: a statistic that is an amount
/// carries its unit's scale, never a bare mantissa at scale 0.
pub(crate) fn unit_scale(
    book: &fa_journal::genesis::BookContext,
    unit: u32,
) -> Result<u8, LanternError> {
    book.units
        .get(fa_money::UnitId(unit))
        .map(|u| u.scale)
        .ok_or_else(|| KernelError::Corrupt("a leg names an unregistered unit".into()).into())
}

impl From<KernelError> for LanternError {
    fn from(e: KernelError) -> Self {
        Self::Kernel(e)
    }
}
impl From<RegisterError> for LanternError {
    fn from(e: RegisterError) -> Self {
        Self::Register(e)
    }
}
impl From<RegistryError> for LanternError {
    fn from(e: RegistryError) -> Self {
        Self::Registry(e)
    }
}
impl From<fgdb::ReadError> for LanternError {
    fn from(e: fgdb::ReadError) -> Self {
        Self::Read(e)
    }
}
impl From<EncodeError> for LanternError {
    fn from(e: EncodeError) -> Self {
        Self::Encoding(e)
    }
}
impl From<DecodeError> for LanternError {
    fn from(e: DecodeError) -> Self {
        Self::Decoding(e)
    }
}
impl From<AmountError> for LanternError {
    fn from(e: AmountError) -> Self {
        Self::Money(e)
    }
}

/// The pinned coordinate a run reads (plan §11.1): the trunk of `book_id`
/// as known at `known_at` and, for the historical folds, through
/// `effective_through`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Coordinate {
    pub book_id: Id128,
    pub known_at: CommitSeq,
    /// The inclusive effective date of the historical folds a run reads
    /// (aging); `None` when the run declares none.
    pub effective_through: Option<DateDay>,
}

impl Coordinate {
    pub fn encode(&self, w: &mut Writer) {
        w.fixed(&self.book_id.0).u64(self.known_at.0).opt(
            self.effective_through.as_ref(),
            |w, d| {
                w.i32(d.0);
            },
        );
    }
}

/// A finding's severity: a band of its statistic, never a legal conclusion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }

    #[must_use]
    pub fn from_tag(t: u8) -> Option<Self> {
        Some(match t {
            0 => Self::Info,
            1 => Self::Low,
            2 => Self::Medium,
            3 => Self::High,
            4 => Self::Critical,
            _ => return None,
        })
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

/// A typed citation (plan §11.8): a handle that resolves in the book. There
/// is no text variant, so a free-text citation cannot be encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cite {
    Entry(VId),
    Leg { entry: VId, ordinal: u16 },
    Account(VId),
    Period(String),
    Document(Oid),
    Principal(VId),
    Approval(VId),
}

impl Cite {
    pub fn encode(&self, w: &mut Writer) {
        match self {
            Self::Entry(v) => {
                w.u8(1).u128(v.0);
            }
            Self::Leg { entry, ordinal } => {
                w.u8(2).u128(entry.0).u16(*ordinal);
            }
            Self::Account(v) => {
                w.u8(3).u128(v.0);
            }
            Self::Period(code) => {
                w.u8(4).str(code);
            }
            Self::Document(oid) => {
                w.u8(5).fixed(&oid.0);
            }
            Self::Principal(v) => {
                w.u8(6).u128(v.0);
            }
            Self::Approval(v) => {
                w.u8(7).u128(v.0);
            }
        }
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let tag = r.u8("cite.tag")?;
        Ok(match tag {
            1 => Self::Entry(VId(r.u128("cite.entry")?)),
            2 => Self::Leg {
                entry: VId(r.u128("cite.leg.entry")?),
                ordinal: r.u16("cite.leg.ordinal")?,
            },
            3 => Self::Account(VId(r.u128("cite.account")?)),
            4 => Self::Period(r.str(64, "cite.period")?.to_string()),
            5 => Self::Document(Oid(r.fixed::<32>("cite.document")?)),
            6 => Self::Principal(VId(r.u128("cite.principal")?)),
            7 => Self::Approval(VId(r.u128("cite.approval")?)),
            other => return Err(r.bad_tag("cite.tag", other)),
        })
    }

    /// The canonical bytes of one citation: the sort key of a ranking.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        self.encode(&mut w);
        w.finish()
    }

    /// Whether the handle resolves in the book as known at `seq`.
    pub fn resolves<V: asupersync::fs::Vfs + Clone>(
        &self,
        db: &Database<V>,
        book: &BookContext,
        seq: CommitSeq,
    ) -> Result<bool, LanternError> {
        let labelled =
            |vid: VId, wanted: Option<fgdb_delta_types::LabelId>| -> Result<bool, LanternError> {
                Ok(db
                    .vertex_at(vid, seq)?
                    .is_some_and(|row| wanted.is_none_or(|l| row.labels.contains(&l))))
            };
        match self {
            Self::Entry(v) => labelled(*v, Some(label::ENTRY)),
            Self::Leg { entry, ordinal } => labelled(leg_vid(*entry, *ordinal), Some(label::LEG)),
            Self::Account(v) => labelled(*v, Some(label::ACCOUNT)),
            Self::Period(code) => {
                labelled(period_vid(&book.calendar.id, code), Some(label::PERIOD))
            }
            Self::Document(oid) => labelled(
                fa_journal::evidence::document_vid(oid),
                Some(label::DOCUMENT),
            ),
            Self::Principal(v) => labelled(*v, None),
            Self::Approval(v) => labelled(*v, Some(label::APPROVAL)),
        }
    }
}

/// The test statistic a finding rests on, in fixed point, with the size of
/// the population it was computed over (plan §11.9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statistic {
    pub name: String,
    pub value: i128,
    /// Decimal places of `value`.
    pub scale: u8,
    pub population: u64,
}

impl Statistic {
    #[must_use]
    pub fn count(name: &str, value: u64, population: u64) -> Self {
        Self {
            name: name.to_string(),
            value: i128::from(value),
            scale: 0,
            population,
        }
    }

    pub fn encode(&self, w: &mut Writer) {
        w.str(&self.name)
            .i128(self.value)
            .u8(self.scale)
            .u64(self.population);
    }
}

/// One finding (plan §11.8): the procedure that produced it, its severity
/// band, its statistic, its typed citations and a narrative built only from
/// resolved handles and numbers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub procedure: String,
    pub version: u16,
    pub severity: Severity,
    pub statistic: Statistic,
    pub cites: Vec<Cite>,
    pub narrative: String,
}

impl Finding {
    pub fn encode(&self, w: &mut Writer) {
        w.str(&self.procedure)
            .u16(self.version)
            .u8(self.severity.tag());
        self.statistic.encode(w);
        w.list(&self.cites, |w, c| c.encode(w));
        w.str(&self.narrative);
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        self.encode(&mut w);
        w.finish()
    }

    fn check(&self, procedure: &str, version: u16) -> Result<(), LanternError> {
        if self.procedure != procedure || self.version != version {
            return Err(LanternError::Parameter {
                procedure: procedure.to_string(),
                name: "finding".into(),
                message: "a finding names another procedure or version".into(),
            });
        }
        if self.narrative.len() > MAX_NARRATIVE_BYTES || self.cites.len() > MAX_CITES {
            return Err(LanternError::Overflow(
                "finding narrative or citation count",
            ));
        }
        Ok(())
    }
}

/// A procedure's parameters: the registry's pinned defaults, overridable by
/// registered name only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    procedure: String,
    values: BTreeMap<String, i128>,
}

impl Params {
    /// The registered defaults of `procedure`.
    pub fn defaults(procedure: &str) -> Result<Self, LanternError> {
        let row = bind(procedure)?;
        Ok(Self {
            procedure: row.id.clone(),
            values: row
                .parameters
                .iter()
                .map(|p| (p.name.clone(), p.default))
                .collect(),
        })
    }

    /// Set a registered parameter; an unregistered name is refused.
    pub fn set(mut self, name: &str, value: i128) -> Result<Self, LanternError> {
        if !self.values.contains_key(name) {
            return Err(LanternError::Parameter {
                procedure: self.procedure.clone(),
                name: name.to_string(),
                message: "not a registered parameter".into(),
            });
        }
        self.values.insert(name.to_string(), value);
        Ok(self)
    }

    /// A registered parameter's value.
    pub fn get(&self, name: &str) -> Result<i128, LanternError> {
        self.values
            .get(name)
            .copied()
            .ok_or_else(|| LanternError::Parameter {
                procedure: self.procedure.clone(),
                name: name.to_string(),
                message: "not a registered parameter".into(),
            })
    }

    /// A registered parameter as a small non-negative count.
    pub fn get_u32(&self, name: &str) -> Result<u32, LanternError> {
        let v = self.get(name)?;
        u32::try_from(v).map_err(|_| LanternError::Parameter {
            procedure: self.procedure.clone(),
            name: name.to_string(),
            message: format!("{v} is not in 0..=4294967295"),
        })
    }

    #[must_use]
    pub fn values(&self) -> Vec<(String, i128)> {
        self.values.iter().map(|(k, v)| (k.clone(), *v)).collect()
    }
}

/// Work counted while a procedure runs: the complexity witness the tests
/// check against the registry's declared bound.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Work {
    pub entries: u64,
    pub legs: u64,
    pub comparisons: u64,
}

impl Work {
    pub fn entry(&mut self) {
        self.entries = self.entries.saturating_add(1);
    }
    pub fn leg(&mut self) {
        self.legs = self.legs.saturating_add(1);
    }
    pub fn compare(&mut self, n: u64) {
        self.comparisons = self.comparisons.saturating_add(n);
    }

    /// Total work units counted (`entries + legs + comparisons`).
    #[must_use]
    pub fn total(&self) -> u64 {
        self.entries
            .saturating_add(self.legs)
            .saturating_add(self.comparisons)
    }

    /// Whether the recorded operation counts satisfy the procedure's
    /// registered complexity class from `registries/procedures.toml` over
    /// `snapshot` (never a quadratic `n²` fallback).
    #[must_use]
    pub fn within_registered_bound(&self, complexity: &str, snapshot: &Snapshot) -> bool {
        let entries = snapshot.entries.len() as u64;
        let legs: u64 = snapshot
            .entries
            .iter()
            .map(|e| e.entry.proposal.legs.len() as u64)
            .sum();
        let ids: u64 = snapshot
            .entries
            .iter()
            .map(|e| e.entry.proposal.external_ids.len() as u64)
            .sum();
        let transitions: u64 = snapshot.transitions.values().map(|v| v.len() as u64).sum();
        let approvals: u64 = snapshot
            .entries
            .iter()
            .map(|e| e.approvals.len() as u64 + 1)
            .sum();
        let open_items: u64 = snapshot
            .open_items_as_of
            .as_ref()
            .map_or(0, |s| s.items.len() as u64);
        let rea_nodes: u64 = (snapshot.rea.parties.len()
            + snapshot.rea.relationships.len()
            + snapshot.rea.instruments.len()
            + snapshot.attestations.len()) as u64;
        let n = legs.max(entries).max(ids).max(rea_nodes).max(1);
        let n_log_n = n
            .saturating_mul(u64::from((n + 1).ilog2().max(1)))
            .saturating_mul(4);
        match complexity {
            "O(entries)" => self.entries <= entries && self.legs == 0 && self.comparisons == 0,
            "O(legs)" => self.entries <= entries && self.legs <= legs && self.comparisons == 0,
            "O(entries + transitions)" => {
                self.entries <= entries && self.legs == 0 && self.comparisons <= transitions
            }
            "O(entries + approvals)" => {
                self.entries <= entries && self.legs == 0 && self.comparisons <= approvals
            }
            "O(open items)" => {
                self.entries == 0 && self.legs <= open_items && self.comparisons == 0
            }
            "O(legs log legs)"
            | "O(ids log ids)"
            | "O(flow legs log flow legs)"
            | "O(movements log movements)"
            | "O(posting_legs log entities + movements log movements)" => {
                self.entries <= entries.max(rea_nodes)
                    && self.legs <= legs.max(entries).max(rea_nodes).saturating_mul(2)
                    && self.comparisons
                        <= n_log_n.saturating_add(rea_nodes.saturating_mul(rea_nodes).max(16))
            }
            "O(posting_legs log posting_legs + allocation_cells log debit_legs + flow_legs log flow_legs)"
            | "O(posting_legs log posting_legs + allocation_cells log debit_legs + flow_legs log flow_legs + max_search_steps * max_hops)"
            | "O(input_legs log input_legs + max_steps log max_transfers + max_fragments * max_hops)" => {
                self.entries <= entries.saturating_mul(2)
                    && self.legs <= legs.max(entries).saturating_mul(4)
                    && self.comparisons <= n_log_n.saturating_add(n.saturating_mul(300))
            }
            _ => false,
        }
    }
}

/// A registered procedure (plan §11.1).
pub trait Procedure {
    /// The registry id (`family.name`).
    fn id(&self) -> &'static str;
    /// The version this code implements; must equal the registry row's.
    fn version(&self) -> u16;
    fn params(&self) -> &Params;
    /// Declared inputs beyond the parameters (a date, a period, an account),
    /// as canonical strings.
    fn inputs(&self) -> Vec<(String, String)> {
        Vec::new()
    }
    /// Emit findings over the snapshot. Order is irrelevant: the run sorts
    /// them canonically.
    fn run(
        &self,
        snapshot: &Snapshot,
        book: &BookContext,
        work: &mut Work,
    ) -> Result<Vec<Finding>, LanternError>;
}

/// The certified result of one run: what was computed, over what, with what,
/// and a digest an opposing expert can reproduce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcedureRun {
    pub procedure: String,
    pub version: u16,
    pub claim: Claim,
    pub evidence: String,
    pub coordinate: Coordinate,
    pub parameters: Vec<(String, i128)>,
    pub inputs: Vec<(String, String)>,
    pub parameters_digest: [u8; 32],
    /// The snapshot's digest: every entry's vid, digest and recorded commit.
    pub inputs_digest: [u8; 32],
    /// Entries in the snapshot.
    pub population: u64,
    pub work: Work,
    /// Sorted: severity descending, statistic descending, citations ascending.
    pub findings: Vec<Finding>,
    pub findings_digest: [u8; 32],
    pub decision_card: fa_policy::DecisionCard,
    pub decision_card_digest: [u8; 32],
}

impl ProcedureRun {
    /// Structured summary line logging population size, parameters digest,
    /// and findings count for audit and test transcripts.
    #[must_use]
    pub fn log_line(&self) -> String {
        let mut hex = String::with_capacity(64);
        for b in &self.parameters_digest {
            use core::fmt::Write as _;
            let _ = write!(&mut hex, "{b:02x}");
        }
        format!(
            "lantern_run procedure={} population={} parameters_digest={hex} findings={}",
            self.procedure,
            self.population,
            self.findings.len()
        )
    }
}

/// The registry row of `id`, or `Unregistered`.
pub fn bind(id: &str) -> Result<Row, LanternError> {
    Procedures::embedded()?
        .get(id)
        .cloned()
        .ok_or_else(|| LanternError::Unregistered {
            procedure: id.to_string(),
        })
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(domain);
    h.update(bytes);
    h.finalize().0
}

/// Run `procedure` over the trunk of `book` as known at `known_at` (the head
/// when `None`), with the historical folds read through `effective_through`
/// when one is declared.
pub fn run<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    known_at: Option<CommitSeq>,
    effective_through: Option<DateDay>,
    procedure: &dyn Procedure,
) -> Result<ProcedureRun, LanternError> {
    let snapshot = Snapshot::read(db, book, known_at, effective_through)?;
    run_over(&snapshot, book, procedure)
}

/// Run `procedure` over an already-read snapshot (the witness re-runs over a
/// permuted one).
pub fn run_over(
    snapshot: &Snapshot,
    book: &BookContext,
    procedure: &dyn Procedure,
) -> Result<ProcedureRun, LanternError> {
    run_over_with_budget(snapshot, book, procedure, None)
}

/// Run `procedure` over an already-read snapshot with an explicit work budget.
pub fn run_over_with_budget(
    snapshot: &Snapshot,
    book: &BookContext,
    procedure: &dyn Procedure,
    budget: Option<u64>,
) -> Result<ProcedureRun, LanternError> {
    let row = bind(procedure.id())?;
    if row.version != procedure.version() {
        return Err(LanternError::Version {
            procedure: row.id,
            code: procedure.version(),
            registry: row.version,
        });
    }
    let params = procedure.params();
    if params.procedure != row.id {
        return Err(LanternError::Parameter {
            procedure: row.id,
            name: "params".into(),
            message: format!("parameters belong to `{}`", params.procedure),
        });
    }
    let inputs = procedure.inputs();
    for (name, _) in &inputs {
        if !row.inputs.iter().any(|i| &i.name == name) {
            return Err(LanternError::Parameter {
                procedure: row.id,
                name: name.clone(),
                message: "not a registered input".into(),
            });
        }
    }
    let parameters = params.values();
    let parameters_digest = {
        let mut w = Writer::new();
        w.str(&row.id).u16(row.version);
        w.list(&parameters, |w, (k, v)| {
            w.str(k).i128(*v);
        });
        w.list(&inputs, |w, (k, v)| {
            w.str(k).str(v);
        });
        digest(PARAMETERS_DIGEST_DOMAIN, &w.finish()?)
    };
    let mut work = Work::default();
    let mut findings = procedure.run(snapshot, book, &mut work)?;
    if let Some(limit) = budget
        && work.total() > limit
    {
        return Err(LanternError::BudgetExhausted {
            procedure: row.id,
            used: work.total(),
            budget: limit,
            fix: "narrow the coordinate with --effective-through YYYY-MM-DD or increase the work budget".into(),
        });
    }
    for f in &findings {
        f.check(&row.id, row.version)?;
    }
    let mut keyed = Vec::with_capacity(findings.len());
    for f in findings.drain(..) {
        let mut cites = Vec::with_capacity(f.cites.len());
        for c in &f.cites {
            cites.push(c.canonical_bytes()?);
        }
        keyed.push((cites, f));
    }
    keyed.sort_by(|(ca, a), (cb, b)| {
        b.severity
            .cmp(&a.severity)
            .then(b.statistic.value.cmp(&a.statistic.value))
            .then_with(|| ca.cmp(cb))
            .then_with(|| a.narrative.cmp(&b.narrative))
    });
    let findings: Vec<Finding> = keyed.into_iter().map(|(_, f)| f).collect();
    let findings_digest = {
        let mut w = Writer::new();
        w.str(&row.id)
            .u16(row.version)
            .fixed(&parameters_digest)
            .fixed(&snapshot.inputs_digest);
        snapshot.coordinate.encode(&mut w);
        w.list(&findings, |w, f| f.encode(w));
        digest(FINDINGS_DIGEST_DOMAIN, &w.finish()?)
    };
    let population = snapshot.entries.len() as u64;
    let policy_oid = fa_policy::Steward::embedded()?.policy_oid;
    let decision_card = fa_policy::decide_lantern_threshold(
        Some(policy_oid),
        policy_oid,
        &row.id,
        row.version,
        &parameters,
        population,
    );
    let decision_card_digest = decision_card.digest()?;
    Ok(ProcedureRun {
        procedure: row.id,
        version: row.version,
        claim: row.claim,
        evidence: row.evidence,
        coordinate: snapshot.coordinate,
        parameters,
        inputs,
        parameters_digest,
        inputs_digest: snapshot.inputs_digest,
        population,
        work,
        findings,
        findings_digest,
        decision_card,
        decision_card_digest,
    })
}

/// A finding's canonical bytes, for callers that want to store or compare it.
pub fn finding_bytes(f: &Finding) -> Result<Vec<u8>, LanternError> {
    Ok(f.canonical_bytes()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn citations_round_trip_and_refuse_an_unknown_tag() {
        let cites = vec![
            Cite::Entry(VId(5)),
            Cite::Leg {
                entry: VId(5),
                ordinal: 2,
            },
            Cite::Account(VId(9)),
            Cite::Period("FY2026-P03".into()),
            Cite::Document(Oid([3; 32])),
            Cite::Principal(VId(7)),
            Cite::Approval(VId(11)),
        ];
        for c in &cites {
            let bytes = c.canonical_bytes().unwrap();
            let mut r = Reader::new(&bytes);
            assert_eq!(&Cite::decode(&mut r).unwrap(), c);
        }
        // A planted free-text citation kind: there is no tag for it, so it
        // cannot be decoded into a finding.
        let mut w = Writer::new();
        w.u8(9).str("the vendor told me so");
        let bytes = w.finish().unwrap();
        let mut r = Reader::new(&bytes);
        assert!(Cite::decode(&mut r).is_err());
    }

    #[test]
    fn parameters_start_from_the_registry_and_refuse_unknown_names() {
        let p = Params::defaults("jet.round_amounts").unwrap();
        assert_eq!(p.get("round_power").unwrap(), 3);
        let p = p.set("round_power", 2).unwrap();
        assert_eq!(p.get("round_power").unwrap(), 2);
        assert!(matches!(
            p.clone().set("fudge", 1),
            Err(LanternError::Parameter { name, .. }) if name == "fudge"
        ));
        assert!(matches!(
            Params::defaults("graph.kiting"),
            Err(LanternError::Unregistered { .. })
        ));
    }

    #[test]
    fn severity_tags_are_stable() {
        for s in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(Severity::from_tag(s.tag()), Some(s));
        }
        assert_eq!(Severity::from_tag(5), None);
        assert!(Severity::Critical > Severity::Info);
    }

    /// Doctrine 3: no procedure reads a clock, entropy, the network or the
    /// filesystem. The crate's sources name none of those facilities.
    #[test]
    fn the_crate_names_no_clock_entropy_network_or_filesystem() {
        let sources = [
            include_str!("lib.rs"),
            include_str!("snapshot.rs"),
            include_str!("projection.rs"),
            include_str!("projection/transport.rs"),
            include_str!("jet.rs"),
            include_str!("duplicates.rs"),
            include_str!("numbers.rs"),
            include_str!("digits.rs"),
            include_str!("cutoff.rs"),
            include_str!("aging.rs"),
            include_str!("witness.rs"),
            include_str!("graph.rs"),
            include_str!("trace.rs"),
            include_str!("catalog.rs"),
            include_str!("conformal.rs"),
            include_str!("sample.rs"),
        ];
        let forbidden = [
            "std::time",
            "SystemTime",
            "Instant::now",
            "std::fs",
            "std::net",
            "rand",
            "getrandom",
            "std::env",
        ];
        for src in sources {
            // Only code lines count: this test names the facilities in its
            // own string literals and doc comments.
            for line in src.lines().filter(|l| {
                let t = l.trim_start();
                !t.starts_with("//") && !t.starts_with('"') && !t.contains("forbidden")
            }) {
                for f in forbidden {
                    assert!(
                        !line.contains(f),
                        "{f} appears in a lantern source line: {line}"
                    );
                }
            }
        }
    }
}
