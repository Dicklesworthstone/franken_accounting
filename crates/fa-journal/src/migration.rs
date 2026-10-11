//! Migration runs (plan §8.6, Appendix A `MigrationRun`, bead fa-xo0).
//!
//! A run is a lifecycle object, `Open → Finalized | Abandoned`, whose
//! history is exactly its `MigrationControl` records (class 22): `Open`
//! journals the run's immutable body — the legacy trial balance as typed
//! lines, sorted `(account_code, unit, signed mantissa)`, with the trial
//! balance document cited as its evidence — and every later record moves the
//! run's `state` projection by compare-and-set in the same transaction.
//!
//! **Staging is in the same engine and invisible until activation.** While
//! the run is `Open`, `Migration` entries (`post`, with origin
//! `Migration { run_ref }`) commit durably into the run's Opening period,
//! one chunk per entry, and [`visible_at`] — the FA-INV-07 migration
//! predicate, implemented once here — hides them from every fold at every
//! known-at. `Finalize` is one control record: it refolds the run's chunks
//! at the head it commits on (the §5.10 aggregate guard), refuses unless
//! the fold equals the declared lines exactly, binds the ordered chunk list
//! in its `tie_out_digest`, and needs two Human approvals of that proposal
//! (the interim `MigrationAttestation`, ruling 3236 R4). From its commit
//! on, the run's entries are visible at every known-at at or after it; at an
//! earlier known-at they never were. `Abandon` makes them permanently
//! invisible; nothing is deleted, and a retry is a new run under a new key
//! whose entry identities include the new run.
//!
//! Supported subset (plan §18.1): `OpeningOnly` runs. `PeriodBalances` and
//! `FullDetail` decode and are refused until the Historical-period slice.
//! The legacy system's own timestamps ride `EntryOrigin::Migration` as
//! provenance and are never read as recorded time (doctrine 6).

use std::collections::BTreeMap;

use fa_model::symbols::{label, property, relation};
use fa_model::{
    ApprovalRef, ControlPayload, DecodeError, Entry, EntryClass, EntryOrigin, EntryPayload,
    Erasable, EvidenceRef, Id128, Oid, Reader, Writer, account_vid, domain_digest, entry_mirrors,
    entry_vid, migration_run_vid,
};
use fa_money::UnitId;
use fa_policy::{Capability, Intent, Party};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::evidence::{evidenced_by, resolve_documents};
use crate::genesis::BookContext;
use crate::policy::{
    authorize_approvals, capability_witness, epoch_witness, refusal as denial, steward,
};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{bytes, edge_id, prop, scalar_bytes, scalar_text};

/// Canonical bytes of a run body: `u16 version ‖ book_id[16] ‖ str run_key
/// ‖ str source_system ‖ u8 mode ‖ trial_balance oid[32] ‖ i32 opening_date
/// ‖ list(str account_code ‖ u32 unit ‖ i128 mantissa)`.
pub const RUN_BODY_VERSION: u16 = 1;
/// The run body's digest: the `_fa_digest` mirror and the `Open` record's
/// `tie_out_digest`.
pub const RUN_BODY_DOMAIN: &[u8] = b"fa:migration-run-body:v1";
/// `H(domain ‖ body_digest ‖ list(chunk vid ‖ proposal_digest))`: the
/// ordered chunk set a `Finalize` (or `Abandon`) binds.
pub const TIE_OUT_DOMAIN: &[u8] = b"fa:migration-tie-out:v1";
/// `EntryOrigin::Control.control_kind` of a run's control records.
pub const MIGRATION_CONTROL_KIND: u16 = 4;
pub const MAX_RUN_KEY_BYTES: usize = 64;
pub const MAX_ACCOUNT_CODE_BYTES: usize = 64;
pub const MAX_TRIAL_BALANCE_LINES: usize = fa_model::limits::MAX_LEGS_PER_ENTRY;

/// `ControlPayload::MigrationControl.kind` (plan Appendix A).
pub mod kind {
    pub const OPEN: u8 = 0;
    pub const FINALIZE: u8 = 1;
    pub const ABANDON: u8 = 2;
}

/// The run's declared mode (plan §8.6). Only `OpeningOnly` is admitted here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunMode {
    OpeningOnly,
    PeriodBalances,
    FullDetail,
}

impl RunMode {
    fn tag(self) -> u8 {
        match self {
            Self::OpeningOnly => 0,
            Self::PeriodBalances => 1,
            Self::FullDetail => 2,
        }
    }
}

/// The `state` projection of a run vertex (lifecycle-by-transition).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunState {
    Open,
    Finalized,
    Abandoned,
}

impl RunState {
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Finalized => 1,
            Self::Abandoned => 2,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Finalized => "Finalized",
            Self::Abandoned => "Abandoned",
        }
    }

    fn from_scalar(v: Option<&CanonicalScalar>) -> Option<Self> {
        match v {
            Some(CanonicalScalar::Int(0)) => Some(Self::Open),
            Some(CanonicalScalar::Int(1)) => Some(Self::Finalized),
            Some(CanonicalScalar::Int(2)) => Some(Self::Abandoned),
            _ => None,
        }
    }

    fn scalar(self) -> CanonicalScalar {
        CanonicalScalar::Int(i64::from(self.tag()))
    }
}

/// One declared line of the legacy trial balance: the account's net in
/// debit sign (`debits − credits`), never zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrialBalanceLine {
    pub account_code: String,
    pub unit: UnitId,
    pub mantissa: i128,
}

/// A run's immutable body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunBody {
    pub book_id: Id128,
    pub run_key: String,
    pub source_system: String,
    pub mode: RunMode,
    /// The legacy trial balance document; the `Open` record cites it.
    pub trial_balance: Oid,
    /// The first day of a fiscal year: the Opening period's one day.
    pub opening_date: DateDay,
    /// Strictly ascending by `(account_code, unit)`.
    pub lines: Vec<TrialBalanceLine>,
}

impl RunBody {
    #[must_use]
    pub fn vid(&self) -> VId {
        migration_run_vid(self.book_id, &self.run_key)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::new();
        w.u16(RUN_BODY_VERSION)
            .fixed(&self.book_id.0)
            .str(&self.run_key)
            .str(&self.source_system)
            .u8(self.mode.tag())
            .fixed(&self.trial_balance.0)
            .i32(self.opening_date.0)
            .list(&self.lines, |w, l| {
                w.str(&l.account_code).u32(l.unit.0).i128(l.mantissa);
            });
        w.finish().map_err(|e| KernelError::Model(e.into()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(bytes);
        let body = (|| -> Result<Self, DecodeError> {
            if r.u16("run.version")? != RUN_BODY_VERSION {
                return Err(r.invalid("run.version"));
            }
            let book_id = Id128(r.fixed("run.book_id")?);
            let run_key = r.str(MAX_RUN_KEY_BYTES, "run.key")?.to_string();
            let source_system = r
                .str(fa_model::limits::MAX_SYSTEM_BYTES, "run.source_system")?
                .to_string();
            let mode = match r.u8("run.mode")? {
                0 => RunMode::OpeningOnly,
                1 => RunMode::PeriodBalances,
                2 => RunMode::FullDetail,
                t => return Err(r.bad_tag("run.mode", t)),
            };
            let trial_balance = Oid(r.fixed("run.trial_balance")?);
            let opening_date = DateDay(r.i32("run.opening_date")?);
            let lines = r.list(MAX_TRIAL_BALANCE_LINES, "run.lines", |r| {
                Ok(TrialBalanceLine {
                    account_code: r
                        .str(MAX_ACCOUNT_CODE_BYTES, "run.line.account")?
                        .to_string(),
                    unit: UnitId(r.u32("run.line.unit")?),
                    mantissa: r.i128("run.line.mantissa")?,
                })
            })?;
            r.finish()?;
            Ok(Self {
                book_id,
                run_key,
                source_system,
                mode,
                trial_balance,
                opening_date,
                lines,
            })
        })()
        .map_err(|e| KernelError::Model(e.into()))?;
        Ok(body)
    }

    pub fn digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(RUN_BODY_DOMAIN, &[&self.canonical_bytes()?]))
    }

    /// The structural law of a body, decided from the body alone: key and
    /// codes within bounds, lines strictly ascending and non-zero, and the
    /// declared balance balanced in every unit.
    fn check(&self, book: &BookContext) -> Result<(), Refusal> {
        let structure = |what: String| {
            Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                what,
                "plan §8.6, Appendix A MigrationRun",
                "fix the named field of the run body and open again",
            )
        };
        if self.book_id != book.book_id {
            return Err(Refusal::new(
                code::COORDINATE,
                exit::USAGE,
                "the run body names another book",
                "plan §2.2 (an object belongs to exactly one book)",
                "set the body's book_id to this book's id",
            ));
        }
        if self.run_key.is_empty() || self.run_key.len() > MAX_RUN_KEY_BYTES {
            return Err(structure(format!(
                "run_key must be 1..={MAX_RUN_KEY_BYTES} bytes"
            )));
        }
        if self.source_system.len() > fa_model::limits::MAX_SYSTEM_BYTES {
            return Err(structure("source_system exceeds max_system_bytes".into()));
        }
        if self.lines.is_empty() || self.lines.len() > MAX_TRIAL_BALANCE_LINES {
            return Err(structure(format!(
                "a trial balance declares 1..={MAX_TRIAL_BALANCE_LINES} lines"
            )));
        }
        for (i, l) in self.lines.iter().enumerate() {
            if l.account_code.is_empty() || l.account_code.len() > MAX_ACCOUNT_CODE_BYTES {
                return Err(structure(format!(
                    "line {i}: account_code must be 1..={MAX_ACCOUNT_CODE_BYTES} bytes"
                )));
            }
            if l.mantissa == 0 {
                return Err(structure(format!(
                    "line {i} (`{}`): a declared line is never zero; omit it",
                    l.account_code
                )));
            }
        }
        if !fa_model::canon::strictly_ascending(&self.lines, |l| (l.account_code.clone(), l.unit)) {
            return Err(structure(
                "lines must be strictly ascending by (account_code, unit)".into(),
            ));
        }
        let mut per_unit: BTreeMap<UnitId, i128> = BTreeMap::new();
        for l in &self.lines {
            let slot = per_unit.entry(l.unit).or_insert(0);
            *slot = slot.checked_add(l.mantissa).ok_or_else(|| {
                structure(format!("unit {}: the declared lines overflow", l.unit.0))
            })?;
        }
        if let Some((unit, net)) = per_unit.iter().find(|(_, net)| **net != 0) {
            return Err(Refusal::new(
                code::TIE_OUT_MISMATCH,
                exit::REFUSAL,
                format!(
                    "the declared trial balance does not balance in {}: its lines net to {}",
                    unit_name(book, *unit),
                    show(book, *unit, *net)
                ),
                "plan §8.6 (opening balances post as balanced entries), FA-INV-01",
                "declare the legacy trial balance exactly as the document states it; a legacy suspense balance is a line of its own",
            ));
        }
        if self.mode != RunMode::OpeningOnly {
            return Err(Refusal::new(
                code::CLASS_NOT_IMPLEMENTED,
                exit::REFUSAL,
                format!(
                    "migration mode {:?} is registered but this slice admits only OpeningOnly",
                    self.mode
                ),
                "plan §18.1 (a slice is a subset of the final abstraction, never a substitute)",
                "open an OpeningOnly run; PeriodBalances and FullDetail land with the Historical-period slice",
            ));
        }
        let fy_start = book
            .calendar
            .fiscal_year_of(self.opening_date)
            .and_then(|fy| book.calendar.year_bounds(fy))
            .map(|(start, _)| start);
        if fy_start.ok() != Some(self.opening_date) {
            return Err(structure(format!(
                "opening_date {} is not the first day of a fiscal year (its Opening period)",
                self.opening_date.render()
            )));
        }
        Ok(())
    }
}

fn unit_name(book: &BookContext, unit: UnitId) -> String {
    book.units
        .get(unit)
        .map_or_else(|| format!("unit {}", unit.0), |u| u.code.clone())
}

fn show(book: &BookContext, unit: UnitId, mantissa: i128) -> String {
    if book.units.get(unit).is_some() {
        fa_money::Amount::new(unit, mantissa).render(&book.units)
    } else {
        format!("{mantissa} (mantissa of unregistered unit {})", unit.0)
    }
}

/// A run as recorded: its body, its current state, and when it opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    pub vid: VId,
    pub body: RunBody,
    pub state: RunState,
    pub opened_at: CommitSeq,
}

fn run_from_row(row: &VertexRow) -> Result<Run, KernelError> {
    if !row.labels.contains(&label::MIGRATION_RUN) {
        return Err(KernelError::Corrupt(format!(
            "{:032x} is not a MigrationRun",
            row.vid.0
        )));
    }
    let body = RunBody::decode(&bytes(row, property::FA_PAYLOAD, "run._fa_payload")?)?;
    if body.vid() != row.vid {
        return Err(KernelError::Corrupt(format!(
            "run {:032x} does not carry the identity its body derives",
            row.vid.0
        )));
    }
    let state = RunState::from_scalar(prop(row, property::STATE))
        .ok_or_else(|| KernelError::Corrupt(format!("run {:032x} state mirror", row.vid.0)))?;
    Ok(Run {
        vid: row.vid,
        body,
        state,
        opened_at: row.created_at,
    })
}

/// The run at `vid` as of `at` (head when `None`).
pub fn read_run<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    vid: VId,
    at: Option<CommitSeq>,
) -> Result<Option<Run>, KernelError> {
    let row = match at {
        Some(seq) => db.vertex_at(vid, seq)?,
        None => db.vertex(vid)?,
    };
    row.as_ref().map(run_from_row).transpose()
}

/// The FA-INV-07 migration predicate: an entry whose origin names a run is
/// selected at `at` iff that run is `Finalized` at `at`; every other entry
/// is unaffected. `cache` memoizes run states for one scan at one `at`.
pub fn visible_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    entry: &Entry,
    at: CommitSeq,
    cache: &mut BTreeMap<VId, bool>,
) -> Result<bool, KernelError> {
    let EntryOrigin::Migration { run_ref, .. } = &entry.proposal.origin else {
        return Ok(true);
    };
    if let Some(v) = cache.get(run_ref) {
        return Ok(*v);
    }
    let row = db.vertex_at(*run_ref, at)?.ok_or_else(|| {
        KernelError::Corrupt(format!(
            "a Migration entry names run {:032x}, which does not exist at {}",
            run_ref.0, at.0
        ))
    })?;
    let state = RunState::from_scalar(prop(&row, property::STATE))
        .ok_or_else(|| KernelError::Corrupt(format!("run {:032x} state mirror", run_ref.0)))?;
    let visible = state == RunState::Finalized;
    cache.insert(*run_ref, visible);
    Ok(visible)
}

/// One staged chunk of a run: a committed `Migration` entry naming it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunChunk {
    pub vid: VId,
    pub proposal_digest: [u8; 32],
    pub recorded_at: CommitSeq,
}

/// A line where the run's fold and its declared trial balance differ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TieOutLine {
    pub account_code: String,
    pub unit: UnitId,
    pub declared: i128,
    pub folded: i128,
}

/// The run's chunks at one sequence, their fold against the declared lines,
/// and the digest a `Finalize` binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TieOut {
    pub at: CommitSeq,
    /// Ascending by `(recorded_at, vid)`.
    pub chunks: Vec<RunChunk>,
    pub mismatches: Vec<TieOutLine>,
    pub digest: [u8; 32],
}

/// Fold the run's chunks as known at `at` (every chunk, visible or not: the
/// tie-out is what Finalize would activate) and compare the fold with the
/// declared lines exactly.
pub fn tie_out<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    run: &Run,
    at: CommitSeq,
) -> Result<TieOut, KernelError> {
    let mut chunks = Vec::new();
    let mut folded: BTreeMap<(VId, UnitId), i128> = BTreeMap::new();
    for row in db.vertices_at(at)? {
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "entry.payload")?)?;
        let EntryOrigin::Migration { run_ref, .. } = &entry.proposal.origin else {
            continue;
        };
        if *run_ref != run.vid {
            continue;
        }
        for leg in &entry.proposal.legs {
            let signed = match leg.side {
                fa_money::Side::Debit => leg.amount.mantissa,
                fa_money::Side::Credit => leg.amount.mantissa.checked_neg().ok_or_else(|| {
                    KernelError::Corrupt("a migration leg's mantissa has no negation".into())
                })?,
            };
            let slot = folded
                .entry((leg.account_ref, leg.amount.unit))
                .or_insert(0);
            *slot = slot
                .checked_add(signed)
                .ok_or_else(|| KernelError::Corrupt("a run's fold overflowed i128".into()))?;
        }
        chunks.push(RunChunk {
            vid: row.vid,
            proposal_digest: entry.proposal_digest,
            recorded_at: row.created_at,
        });
    }
    chunks.sort_by_key(|c| (c.recorded_at, c.vid.0));
    let mut declared: BTreeMap<(VId, UnitId), (String, i128)> = BTreeMap::new();
    for l in &run.body.lines {
        declared.insert(
            (account_vid(book.book_id, &l.account_code), l.unit),
            (l.account_code.clone(), l.mantissa),
        );
    }
    let mut mismatches = Vec::new();
    for ((account, unit), (code, want)) in &declared {
        let got = folded.get(&(*account, *unit)).copied().unwrap_or(0);
        if got != *want {
            mismatches.push(TieOutLine {
                account_code: code.clone(),
                unit: *unit,
                declared: *want,
                folded: got,
            });
        }
    }
    for ((account, unit), got) in &folded {
        if *got != 0 && !declared.contains_key(&(*account, *unit)) {
            let code = match db.vertex_at(*account, at)? {
                Some(row) => crate::rows::text(&row, property::CODE, "account.code")?,
                None => format!("{:032x}", account.0),
            };
            mismatches.push(TieOutLine {
                account_code: code,
                unit: *unit,
                declared: 0,
                folded: *got,
            });
        }
    }
    mismatches.sort_by(|a, b| (&a.account_code, a.unit).cmp(&(&b.account_code, b.unit)));
    let mut w = Writer::new();
    w.list(&chunks, |w, c| {
        w.u128(c.vid.0).fixed(&c.proposal_digest);
    });
    let list = w.finish().map_err(|e| KernelError::Model(e.into()))?;
    let digest = domain_digest(TIE_OUT_DOMAIN, &[&run.body.digest()?, &list]);
    Ok(TieOut {
        at,
        chunks,
        mismatches,
        digest,
    })
}

fn mismatch_refusal(book: &BookContext, lines: &[TieOutLine]) -> Refusal {
    let named: Vec<String> = lines
        .iter()
        .map(|l| {
            format!(
                "`{}` {}: declared {}, folded {}",
                l.account_code,
                unit_name(book, l.unit),
                show(book, l.unit, l.declared),
                show(book, l.unit, l.folded)
            )
        })
        .collect();
    Refusal::new(
        code::TIE_OUT_MISMATCH,
        exit::REFUSAL,
        format!(
            "the run's chunks do not fold to its declared trial balance ({} line(s), in debit sign): {}",
            lines.len(),
            named.join("; ")
        ),
        "plan §8.6 (Finalize activates the run only when its fold equals the legacy trial balance)",
        "post the missing chunks (or abandon the run and retry under a new run key) until every line ties out",
    )
}

/// A `MigrationControl` proposal (class 22, book-scoped, legs = []).
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn control_proposal(
    book: &BookContext,
    principal: VId,
    run: VId,
    body_digest: [u8; 32],
    control_kind: u8,
    tie_out_digest: [u8; 32],
    effective_date: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
    evidence: Vec<EvidenceRef>,
) -> EntryPayload {
    EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::MIGRATION_CONTROL,
        effective_date,
        document_date: None,
        description,
        effective_period: None,
        legs: Vec::new(),
        control: Some(ControlPayload::MigrationControl {
            run_ref: run,
            kind: control_kind,
            tie_out_digest,
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: idempotency_key.to_vec(),
        origin: EntryOrigin::Control {
            control_kind: MIGRATION_CONTROL_KIND,
            spec_body_digest: body_digest,
        },
        principal_ref: principal,
        session_ref: None,
        evidence,
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    }
}

/// The `Open` proposal for `body`: dated on its opening date, citing its
/// trial balance document under `role`.
pub fn open_proposal(
    book: &BookContext,
    principal: VId,
    body: &RunBody,
    trial_balance: EvidenceRef,
    idempotency_key: &[u8],
    description: Erasable<String>,
) -> Result<EntryPayload, KernelError> {
    let digest = body.digest()?;
    Ok(control_proposal(
        book,
        principal,
        body.vid(),
        digest,
        kind::OPEN,
        digest,
        body.opening_date,
        idempotency_key,
        description,
        vec![trial_balance],
    ))
}

/// The `Finalize` (or `Abandon`) proposal for the run at `run_vid`, planned
/// against the head: its `tie_out_digest` binds the chunks committed so
/// far. Approvers approve its `proposal_digest()`. A run that is not Open,
/// or (for Finalize) whose fold does not tie out, is refused here already.
pub fn plan_run_transition<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    run_vid: VId,
    control_kind: u8,
    principal: VId,
    idempotency_key: &[u8],
    description: Erasable<String>,
) -> Outcome<EntryPayload> {
    let Some(run) = read_run(db, run_vid, None)? else {
        return Ok(Err(unknown_run(run_vid)));
    };
    if run.state != RunState::Open {
        return Ok(Err(not_open(&run)));
    }
    let tie = tie_out(db, book, &run, db.frontier()?)?;
    if control_kind == kind::FINALIZE && !tie.mismatches.is_empty() {
        return Ok(Err(mismatch_refusal(book, &tie.mismatches)));
    }
    Ok(Ok(control_proposal(
        book,
        principal,
        run.vid,
        run.body.digest()?,
        control_kind,
        tie.digest,
        run.body.opening_date,
        idempotency_key,
        description,
        Vec::new(),
    )))
}

pub(crate) fn unknown_run(run: VId) -> Refusal {
    Refusal::new(
        code::MIGRATION_OUTSIDE_RUN,
        exit::REFUSAL,
        format!("no migration run {:032x} in this book", run.0),
        "plan §8.6 (Migration entries and run controls name an opened MigrationRun)",
        "open the run first (fa_journal::migration::open_run) and name its vid as run_ref",
    )
}

pub(crate) fn not_open(run: &Run) -> Refusal {
    Refusal::new(
        code::RUN_NOT_OPEN,
        exit::REFUSAL,
        format!(
            "migration run `{}` is {}; only an Open run takes chunks, a Finalize, or an Abandon",
            run.body.run_key,
            run.state.name()
        ),
        "plan §8.6 (a MigrationRun is Open → Finalized | Abandoned)",
        match run.state {
            RunState::Finalized => {
                "the run is already active; correct a migrated balance with an admissible class in its period, never by reopening the run"
            }
            _ => {
                "open a new run under a new run key; the abandoned run's entries stay journaled and invisible"
            }
        },
    )
}

/// Witness the run's state inside `txn` (a property-granular point read):
/// a Finalize or Abandon that commits first makes this transaction a
/// first-committer-wins conflict, never a chunk staged into a closed run.
pub(crate) fn witness_open<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    run_vid: VId,
) -> Outcome<Run> {
    let Some(row) = txn.vertex(db, run_vid)? else {
        return Ok(Err(unknown_run(run_vid)));
    };
    let mut run = run_from_row(&row)?;
    let state = RunState::from_scalar(txn.vertex_property(db, run_vid, property::STATE)?.as_ref())
        .ok_or_else(|| KernelError::Corrupt(format!("run {:032x} state mirror", run_vid.0)))?;
    run.state = state;
    if state != RunState::Open {
        return Ok(Err(not_open(&run)));
    }
    Ok(Ok(run))
}

/// A run control request: the proposal (from [`open_proposal`] or
/// [`plan_run_transition`]), the preparer's capability, and the approvals its
/// SoD row requires.
#[derive(Clone, Debug)]
pub struct RunControlRequest {
    pub proposal: EntryPayload,
    pub capability: Capability,
    pub approvals: Vec<ApprovalRef>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunControlled {
    pub run: VId,
    pub kind: u8,
    pub from: Option<RunState>,
    pub to: RunState,
    pub recorded_at: CommitSeq,
    pub control_entry: VId,
    /// The same control was already recorded (FA-INV-09): nothing was written.
    pub already_recorded: bool,
    /// For Finalize and Abandon: the chunks bound by `tie_out_digest`.
    pub chunks: Vec<RunChunk>,
}

/// Open a run: one commit journaling the `Open` record, the run vertex with
/// its immutable body and `state = Open`, the `CONTROLS` edge, and the
/// record's citation of the trial balance document.
pub async fn open_run<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    body: &RunBody,
    req: RunControlRequest,
) -> Outcome<RunControlled> {
    let proposal = &req.proposal;
    let body_digest = body.digest()?;
    let run_vid = body.vid();
    if let Err(r) = check_control(proposal, book, kind::OPEN, run_vid) {
        return Ok(Err(r));
    }
    if let Err(r) = body.check(book) {
        return Ok(Err(r));
    }
    if !matches!(
        proposal.control,
        Some(ControlPayload::MigrationControl { tie_out_digest, .. }) if tie_out_digest == body_digest
    ) || proposal.effective_date != body.opening_date
        || !proposal
            .evidence
            .iter()
            .any(|e| e.document_oid == body.trial_balance)
    {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "an Open record binds its body's digest, is dated on the opening date, and cites the trial balance document",
            "plan §8.6, Appendix A ControlPayload::MigrationControl",
            "build the proposal with fa_journal::migration::open_proposal",
        )));
    }
    if let Err(r) = admit_control(db, book, &req, "Open")? {
        return Ok(Err(r));
    }
    let proposal_digest = proposal.proposal_digest()?;
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    // The capability is not revoked (plan §14.2): the first read.
    if let Err(r) = capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let evid = control_vid(book, proposal);
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return recorded_or_conflict(book, &row, proposal, &proposal_digest, run_vid);
    }
    if let Some(existing) = txn.vertex(db, run_vid)? {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            format!(
                "run key `{}` is already a run (opened at {}); a retry is a new run under a new key",
                body.run_key, existing.created_at.0
            ),
            "plan §8.6 (a retry is a new run whose entry vids include the run id)",
            "open the retry under a new run key",
        )));
    }
    if let Err(r) = authorize(&txn, db, book, &req, &proposal_digest, "Open")? {
        txn.abort();
        return Ok(Err(r));
    }
    let policy = EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let documents = match resolve_documents(&txn, db, &policy, &proposal.evidence)? {
        Ok(d) => d,
        Err(r) => {
            txn.abort();
            return Ok(Err(r));
        }
    };
    let entry = proposal.clone().seal(req.approvals.clone(), None)?;
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("run._fa_payload", body.canonical_bytes()?)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("run._fa_digest", body_digest.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("book_id", book.book_id.0.to_vec())?,
        ),
        (property::CODE, scalar_text("run.code", &body.run_key)?),
        (property::STATE, RunState::Open.scalar()),
    ];
    props.sort_by_key(|(k, _)| k.0);
    let mut controls = WriteBatch::new(relation::CONTROLS);
    controls.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    controls.create_vertex(run_vid, vec![label::MIGRATION_RUN], props);
    controls.add_edge(
        edge_id(relation::CONTROLS, evid, run_vid),
        evid,
        run_vid,
        vec![],
    );
    let mut batches = vec![controls];
    let cited: Vec<VId> = documents.iter().map(|d| d.vid).collect();
    if let Some(edges) = evidenced_by(evid, &cited) {
        batches.push(edges);
    }
    txn.write_ordered(db, batches)?;
    finish(
        db,
        ctx,
        book,
        txn,
        proposal,
        &proposal_digest,
        RunControlled {
            run: run_vid,
            kind: kind::OPEN,
            from: None,
            to: RunState::Open,
            recorded_at: CommitSeq(0),
            control_entry: evid,
            already_recorded: false,
            chunks: Vec::new(),
        },
    )
    .await
}

/// Finalize or abandon the run the proposal names: one commit journaling
/// the record and moving `state` from the witnessed `Open` by compare-and-set.
/// The chunk set is refolded at the head this transaction commits on (the
/// §5.10 aggregate guard under the exclusive handle) and must be exactly the
/// one the proposal's `tie_out_digest` binds; a Finalize also needs the fold
/// to equal the declared lines and two Human approvals of the proposal.
pub async fn transition_run<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    req: RunControlRequest,
) -> Outcome<RunControlled> {
    let proposal = &req.proposal;
    let (run_vid, control_kind, bound) = match &proposal.control {
        Some(ControlPayload::MigrationControl {
            run_ref,
            kind: k,
            tie_out_digest,
        }) if *k == kind::FINALIZE || *k == kind::ABANDON => (*run_ref, *k, *tie_out_digest),
        _ => {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                "a run transition carries MigrationControl { kind: Finalize | Abandon }",
                "plan Appendix A ControlPayload::MigrationControl",
                "build the proposal with fa_journal::migration::plan_run_transition",
            )));
        }
    };
    if let Err(r) = check_control(proposal, book, control_kind, run_vid) {
        return Ok(Err(r));
    }
    let transition = if control_kind == kind::FINALIZE {
        "Finalize"
    } else {
        "Abandon"
    };
    if let Err(r) = admit_control(db, book, &req, transition)? {
        return Ok(Err(r));
    }
    let proposal_digest = proposal.proposal_digest()?;
    // The aggregate basis (plan §5.10): the head this exclusive handle sees;
    // nothing can publish between this fold and the commit below.
    let basis = db.frontier()?;
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    // The capability is not revoked (plan §14.2): the first read.
    if let Err(r) = capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let evid = control_vid(book, proposal);
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return recorded_or_conflict(book, &row, proposal, &proposal_digest, run_vid);
    }
    let run = match witness_open(&txn, db, run_vid)? {
        Ok(run) => run,
        Err(r) => {
            txn.abort();
            return Ok(Err(r));
        }
    };
    let body_digest = run.body.digest()?;
    if proposal.effective_date != run.body.opening_date
        || !matches!(
            proposal.origin,
            EntryOrigin::Control { spec_body_digest, .. } if spec_body_digest == body_digest
        )
    {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "a run transition is dated on the run's opening date and names its body digest",
            "plan §8.6, Appendix A ControlPayload::MigrationControl",
            "build the proposal with fa_journal::migration::plan_run_transition",
        )));
    }
    let tie = tie_out(db, book, &run, basis)?;
    if control_kind == kind::FINALIZE && !tie.mismatches.is_empty() {
        txn.abort();
        return Ok(Err(mismatch_refusal(book, &tie.mismatches)));
    }
    if tie.digest != bound {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::CONFLICT,
            exit::CONFLICT,
            format!(
                "run `{}` now has {} chunk(s), not the set this {transition} was planned and approved over",
                run.body.run_key,
                tie.chunks.len()
            ),
            "plan §5.10 (an aggregate plan is valid only at its basis), §8.6",
            "re-plan with fa_journal::migration::plan_run_transition and approve the new proposal",
        )));
    }
    if let Err(r) = authorize(&txn, db, book, &req, &proposal_digest, transition)? {
        txn.abort();
        return Ok(Err(r));
    }
    let to = if control_kind == kind::FINALIZE {
        RunState::Finalized
    } else {
        RunState::Abandoned
    };
    let entry = proposal.clone().seal(req.approvals.clone(), None)?;
    let mut controls = WriteBatch::new(relation::CONTROLS);
    controls.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    controls.compare_and_set_vertex_property(
        run_vid,
        property::STATE,
        Some(RunState::Open.scalar()),
        to.scalar(),
        WriteMismatchPolicy::AbortWrite,
    );
    controls.add_edge(
        edge_id(relation::CONTROLS, evid, run_vid),
        evid,
        run_vid,
        vec![],
    );
    txn.write(db, controls)?;
    if db.frontier()? != basis {
        return Err(KernelError::Corrupt(
            "the head moved under an exclusive handle between the run's fold and its commit".into(),
        ));
    }
    finish(
        db,
        ctx,
        book,
        txn,
        proposal,
        &proposal_digest,
        RunControlled {
            run: run_vid,
            kind: control_kind,
            from: Some(RunState::Open),
            to,
            recorded_at: CommitSeq(0),
            control_entry: evid,
            already_recorded: false,
            chunks: tie.chunks,
        },
    )
    .await
}

/// Decided from the proposal alone: a valid `MigrationControl` record of
/// this kind on this book's trunk, naming `run`.
fn check_control(
    proposal: &EntryPayload,
    book: &BookContext,
    control_kind: u8,
    run: VId,
) -> Result<(), Refusal> {
    let structure = |why: String| {
        Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            why,
            "plan Appendix A ControlPayload::MigrationControl (book-scoped: no effective_period)",
            "build the proposal with fa_journal::migration::open_proposal or plan_run_transition",
        )
    };
    if let Err(e) = proposal.validate() {
        return Err(structure(e.to_string()));
    }
    let shaped = proposal.class == EntryClass::MIGRATION_CONTROL
        && matches!(
            proposal.control,
            Some(ControlPayload::MigrationControl { run_ref, kind: k, .. })
                if run_ref == run && k == control_kind
        )
        && proposal.effective_period.is_none();
    if !shaped {
        return Err(structure(format!(
            "not a book-scoped MigrationControl record of kind {control_kind} naming run {:032x}",
            run.0
        )));
    }
    if proposal.book_id != book.book_id || proposal.branch_id != Id128::TRUNK {
        return Err(Refusal::new(
            code::COORDINATE,
            exit::USAGE,
            "the run control names another book or a branch",
            "plan §2.2",
            "control runs on this book's trunk",
        ));
    }
    Ok(())
}

/// Authorization precedes observation (doctrine 8): the capability is the
/// preparer's, holds the SoD row's preparer op, and is current at the
/// admission point — decided before any read.
fn admit_control<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    req: &RunControlRequest,
    transition: &str,
) -> Outcome<()> {
    let steward = steward()?;
    let key = fa_policy::sod::control_key("MigrationControl", None, transition);
    let op = steward.preparer_op(&key).ok_or_else(|| {
        KernelError::Corrupt(format!(
            "sod_policy.toml has no MigrationControl {transition} rule"
        ))
    })?;
    if let Err(d) = fa_policy::admit(
        &req.capability,
        &Intent {
            principal: req.proposal.principal_ref,
            trunk: true,
            op,
            book: book.book_id,
            legs: &[],
        },
    ) {
        return Ok(Err(denial(&d)));
    }
    if let Err(d) = fa_policy::current(&req.capability, db.frontier()?) {
        return Ok(Err(denial(&d)));
    }
    Ok(Ok(()))
}

/// SoD for the transition over the witnessed approvals, under the epoch
/// witnessed in the same transaction (`sod_policy.toml` MigrationControl rows).
fn authorize<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    req: &RunControlRequest,
    proposal_digest: &[u8; 32],
    transition: &str,
) -> Outcome<()> {
    let epoch = epoch_witness(txn, db)?;
    authorize_approvals(
        txn,
        db,
        book,
        &req.approvals,
        proposal_digest,
        epoch,
        &fa_policy::sod::control_key("MigrationControl", None, transition),
        0,
        Party {
            principal: req.proposal.principal_ref,
            profile: req.capability.profile(),
        },
    )
}

fn control_vid(book: &BookContext, proposal: &EntryPayload) -> VId {
    entry_vid(
        book.book_id,
        &proposal.principal_ref.0.to_le_bytes(),
        &proposal.idempotency_key,
    )
}

async fn finish<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    mut txn: WriteTxn,
    proposal: &EntryPayload,
    proposal_digest: &[u8; 32],
    mut done: RunControlled,
) -> Outcome<RunControlled> {
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => {
            done.recorded_at = seq;
            Ok(Ok(done))
        }
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!(
                    "a concurrent commit invalidated a witness this run control read: {detail}"
                ),
                "FG-LAW-FCW-01 (first committer wins)",
                "re-read the run, re-plan, and retry",
            )))
        }
        Err(WriteTxnError::Write(fgdb::WriteError::CompareAndSetMismatch(_))) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                "the run's state moved under this control",
                "plan §8.6 (a run moves Open → Finalized | Abandoned exactly once)",
                "re-read the run; a run that already moved is final",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => match db.vertex(done.control_entry)? {
            Some(row) => recorded_or_conflict(book, &row, proposal, proposal_digest, done.run),
            None => Err(KernelError::Corrupt(
                "identity spent but no live row".into(),
            )),
        },
        Err(e) => Err(e.into()),
    }
}

/// An existing record at the control's identity: the recorded outcome when
/// the proposal is the same (byte for byte, or semantically under the book
/// key), a conflict otherwise.
fn recorded_or_conflict(
    book: &BookContext,
    row: &VertexRow,
    proposal: &EntryPayload,
    proposal_digest: &[u8; 32],
    run: VId,
) -> Outcome<RunControlled> {
    let stored = Entry::decode(&bytes(row, property::FA_PAYLOAD, "entry._fa_payload")?)?;
    let conflict = Refusal::new(
        code::IDEMPOTENCY_CONFLICT,
        exit::CONFLICT,
        format!(
            "idempotency key reused with different content; the recorded entry is {:032x}",
            row.vid.0
        ),
        "plan §4.9 (identity is derived from the key; content is bound by proposal_digest)",
        "resubmit the identical control to get the recorded outcome, or use a new idempotency key",
    );
    let same = if &stored.proposal_digest == proposal_digest {
        true
    } else {
        match (
            stored.proposal.semantic_digest(&book.seal_key),
            proposal.semantic_digest(&book.seal_key),
        ) {
            (Ok(a), Ok(b)) => a == b,
            (Err(fa_model::EntryError::Sealed(_)), _)
            | (_, Err(fa_model::EntryError::Sealed(_))) => {
                return Ok(Err(Refusal::new(
                    code::EQUIVALENCE_UNVERIFIABLE,
                    exit::CONFLICT,
                    format!(
                        "a run control with this identity exists ({:032x}) but a sealed field cannot be opened, so equivalence cannot be verified",
                        row.vid.0
                    ),
                    "plan §8.5 (no plaintext equivalence over destroyed secrets)",
                    "resubmit the exact prepared bytes to get the recorded outcome, or use a new idempotency key",
                )));
            }
            (Err(e), _) | (_, Err(e)) => return Err(e.into()),
        }
    };
    let Some(ControlPayload::MigrationControl { kind: k, .. }) = stored.proposal.control else {
        return Ok(Err(conflict));
    };
    if !same || stored.proposal.class != EntryClass::MIGRATION_CONTROL {
        return Ok(Err(conflict));
    }
    let to = match k {
        kind::OPEN => RunState::Open,
        kind::FINALIZE => RunState::Finalized,
        kind::ABANDON => RunState::Abandoned,
        t => {
            return Err(KernelError::Corrupt(format!(
                "MigrationControl kind {t} is not registered"
            )));
        }
    };
    Ok(Ok(RunControlled {
        run,
        kind: k,
        from: (k != kind::OPEN).then_some(RunState::Open),
        to,
        recorded_at: row.created_at,
        control_entry: row.vid,
        already_recorded: true,
        chunks: Vec::new(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> RunBody {
        RunBody {
            book_id: Id128([1; 16]),
            run_key: "go-live".into(),
            source_system: "legacy-gl".into(),
            mode: RunMode::OpeningOnly,
            trial_balance: Oid([9; 32]),
            opening_date: DateDay::from_ymd(2026, 1, 1).unwrap(),
            lines: vec![
                TrialBalanceLine {
                    account_code: "1000".into(),
                    unit: UnitId(1),
                    mantissa: 500,
                },
                TrialBalanceLine {
                    account_code: "3000".into(),
                    unit: UnitId(1),
                    mantissa: -500,
                },
            ],
        }
    }

    #[test]
    fn a_run_body_round_trips_and_binds_its_identity() {
        let b = body();
        let bytes = b.canonical_bytes().unwrap();
        assert_eq!(RunBody::decode(&bytes).unwrap(), b);
        assert_eq!(b.vid(), migration_run_vid(b.book_id, "go-live"));
        let mut other = b.clone();
        other.lines[0].mantissa = 501;
        other.lines[1].mantissa = -501;
        assert_ne!(other.digest().unwrap(), b.digest().unwrap());
        // Trailing bytes and an unknown mode are refused, never skipped.
        let mut long = bytes.clone();
        long.push(0);
        assert!(RunBody::decode(&long).is_err());
        let mode_at = 2 + 16 + 4 + b.run_key.len() + 4 + b.source_system.len();
        let mut bad = bytes;
        bad[mode_at] = 7;
        assert!(RunBody::decode(&bad).is_err());
    }

    #[test]
    fn run_states_round_trip_through_their_scalar() {
        for s in [RunState::Open, RunState::Finalized, RunState::Abandoned] {
            assert_eq!(RunState::from_scalar(Some(&s.scalar())), Some(s));
        }
        assert_eq!(RunState::from_scalar(None), None);
        assert_eq!(RunState::from_scalar(Some(&CanonicalScalar::Int(3))), None);
    }
}
