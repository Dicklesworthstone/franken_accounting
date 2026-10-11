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
//! **Modes** (plan §8.6). `OpeningOnly`: the opening balances, in the
//! Opening period. `PeriodBalances` (the mid-year go-live): the opening
//! balances at the fiscal-year start, then one or more chunks in each
//! elapsed period before the book's opening date — those periods are born
//! `Historical` (genesis) — and the body declares, per period, the legacy
//! trial balance as of its end. Finalize ties out cumulatively: the opening
//! chunks to the opening lines, and the opening plus every period through
//! `p` to `p`'s lines. Both modes' chunks count in trunk folds once the run
//! is Finalized. `FullDetail` (ruling 3675): legacy journal entries as
//! detail chunks in a contiguous run of declared Historical periods ending
//! at the book's opening date, anchored by `detail_base` (the trial balance
//! at the start of the first declared period); one cumulative chain ties
//! out `detail_base + Σ detail through p` to each `p`'s lines. Not sole
//! source: the Opening chunks tie to `lines`, `lines` must equal the chain
//! at the run's opening date, and a detail chunk counts in folds iff it is
//! dated on or after the run's opening date (earlier detail is summarized by
//! the Opening chunks and stays journaled for drill-down). Sole source: no
//! Opening chunk, no `lines`, no `detail_base`; every detail chunk counts.
//! The legacy system's own timestamps ride `EntryOrigin::Migration` as
//! provenance and are never read as recorded time (doctrine 6).

use std::collections::BTreeMap;

use fa_model::symbols::{label, property, relation};
use fa_model::{
    ApprovalRef, ControlKind, ControlPayload, DecodeError, Entry, EntryClass, EntryOrigin,
    EntryPayload, Erasable, EvidenceRef, Id128, Oid, Reader, Writer, account_vid, domain_digest,
    entry_mirrors, entry_vid, migration_run_vid,
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
/// ‖ list(str account_code ‖ u32 unit ‖ i128 mantissa)`, then for
/// `PeriodBalances` and `FullDetail` `list(str period_code ‖ trial_balance
/// oid[32] ‖ list(lines))`, then for `FullDetail` only `list(detail_base
/// lines) ‖ u8 sole_opening_source`.
pub const RUN_BODY_VERSION: u16 = 1;
/// The run body's digest: the `_fa_digest` mirror and the `Open` record's
/// `tie_out_digest`.
pub const RUN_BODY_DOMAIN: &[u8] = b"fa:migration-run-body:v1";
/// `H(domain ‖ body_digest ‖ list(chunk vid ‖ proposal_digest))`: the
/// ordered chunk set a `Finalize` (or `Abandon`) binds.
pub const TIE_OUT_DOMAIN: &[u8] = b"fa:migration-tie-out:v1";
pub const MAX_RUN_KEY_BYTES: usize = 64;
pub const MAX_ACCOUNT_CODE_BYTES: usize = 64;
pub const MAX_TRIAL_BALANCE_LINES: usize = fa_model::limits::MAX_LEGS_PER_ENTRY;
/// The elapsed periods one `PeriodBalances` run may declare.
pub const MAX_RUN_PERIODS: usize = 256;
pub const MAX_PERIOD_CODE_BYTES: usize = 64;

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

/// One elapsed period of a `PeriodBalances` run (plan §8.6): the legacy
/// trial balance as of the period's end — cumulative from the run's opening
/// date — and the document that states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodBalance {
    pub period_code: String,
    pub trial_balance: Oid,
    /// Strictly ascending by `(account_code, unit)`, never zero.
    pub lines: Vec<TrialBalanceLine>,
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
    /// `PeriodBalances`: every elapsed period from the opening date to the
    /// book's opening date. `FullDetail`: a contiguous run of Historical
    /// periods ending at the book's opening date. In calendar order; empty
    /// for `OpeningOnly`.
    pub periods: Vec<PeriodBalance>,
    /// `FullDetail` only (empty otherwise): the legacy trial balance at the
    /// start of the first declared period; empty for an import from legacy
    /// inception.
    pub detail_base: Vec<TrialBalanceLine>,
    /// `FullDetail` only: the detail is the sole source of the opening
    /// balances (no Opening chunk, no `lines`, no `detail_base`).
    pub sole_opening_source: bool,
}

fn encode_lines(w: &mut Writer, lines: &[TrialBalanceLine]) {
    w.list(lines, |w, l| {
        w.str(&l.account_code).u32(l.unit.0).i128(l.mantissa);
    });
}

fn decode_lines(
    r: &mut Reader<'_>,
    field: &'static str,
) -> Result<Vec<TrialBalanceLine>, DecodeError> {
    r.list(MAX_TRIAL_BALANCE_LINES, field, |r| {
        Ok(TrialBalanceLine {
            account_code: r
                .str(MAX_ACCOUNT_CODE_BYTES, "run.line.account")?
                .to_string(),
            unit: UnitId(r.u32("run.line.unit")?),
            mantissa: r.i128("run.line.mantissa")?,
        })
    })
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
            .i32(self.opening_date.0);
        encode_lines(&mut w, &self.lines);
        if self.mode != RunMode::OpeningOnly {
            w.list(&self.periods, |w, p| {
                w.str(&p.period_code).fixed(&p.trial_balance.0);
                encode_lines(w, &p.lines);
            });
        }
        if self.mode == RunMode::FullDetail {
            encode_lines(&mut w, &self.detail_base);
            w.u8(u8::from(self.sole_opening_source));
        }
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
            let lines = decode_lines(&mut r, "run.lines")?;
            let periods = if mode != RunMode::OpeningOnly {
                r.list(MAX_RUN_PERIODS, "run.periods", |r| {
                    Ok(PeriodBalance {
                        period_code: r.str(MAX_PERIOD_CODE_BYTES, "run.period.code")?.to_string(),
                        trial_balance: Oid(r.fixed("run.period.trial_balance")?),
                        lines: decode_lines(r, "run.period.lines")?,
                    })
                })?
            } else {
                Vec::new()
            };
            let (detail_base, sole_opening_source) = if mode == RunMode::FullDetail {
                let base = decode_lines(&mut r, "run.detail_base")?;
                let sole = match r.u8("run.sole_opening_source")? {
                    0 => false,
                    1 => true,
                    t => return Err(r.bad_tag("run.sole_opening_source", t)),
                };
                (base, sole)
            } else {
                (Vec::new(), false)
            };
            r.finish()?;
            Ok(Self {
                book_id,
                run_key,
                source_system,
                mode,
                trial_balance,
                opening_date,
                lines,
                periods,
                detail_base,
                sole_opening_source,
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
        let sole = self.mode == RunMode::FullDetail && self.sole_opening_source;
        if sole {
            if !self.lines.is_empty() || !self.detail_base.is_empty() {
                return Err(structure(
                    "a sole-source FullDetail run declares no opening lines and no detail_base: its detail, from legacy inception, is the opening balances".into(),
                ));
            }
        } else {
            check_lines(book, &self.lines, "the opening trial balance", false)?;
        }
        if self.mode != RunMode::FullDetail
            && (!self.detail_base.is_empty() || self.sole_opening_source)
        {
            return Err(structure(
                "only a FullDetail run declares detail_base or sole_opening_source".into(),
            ));
        }
        match self.mode {
            RunMode::OpeningOnly if !self.periods.is_empty() => {
                return Err(structure("an OpeningOnly run declares no periods".into()));
            }
            RunMode::OpeningOnly => {}
            RunMode::PeriodBalances | RunMode::FullDetail => {
                if self.periods.is_empty() || self.periods.len() > MAX_RUN_PERIODS {
                    return Err(structure(format!(
                        "a PeriodBalances run declares 1..={MAX_RUN_PERIODS} elapsed periods"
                    )));
                }
                let mut seen = std::collections::BTreeSet::new();
                for p in &self.periods {
                    if p.period_code.is_empty() || p.period_code.len() > MAX_PERIOD_CODE_BYTES {
                        return Err(structure(format!(
                            "a period code must be 1..={MAX_PERIOD_CODE_BYTES} bytes"
                        )));
                    }
                    if !seen.insert(p.period_code.as_str()) {
                        return Err(structure(format!(
                            "period `{}` is declared twice",
                            p.period_code
                        )));
                    }
                    // A FullDetail cumulative balance may net to nothing.
                    check_lines(
                        book,
                        &p.lines,
                        &format!("the trial balance at the end of `{}`", p.period_code),
                        self.mode == RunMode::FullDetail,
                    )?;
                }
                if self.mode == RunMode::FullDetail {
                    check_lines(book, &self.detail_base, "detail_base", true)?;
                }
            }
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

    /// Whether this run declares `period_code` as one of its elapsed periods.
    #[must_use]
    pub fn declares(&self, period_code: &str) -> bool {
        self.periods.iter().any(|p| p.period_code == period_code)
    }

    /// Every trial balance document the body names, ascending and unique.
    #[must_use]
    pub fn documents(&self) -> Vec<Oid> {
        let mut out: Vec<Oid> = std::iter::once(self.trial_balance)
            .chain(self.periods.iter().map(|p| p.trial_balance))
            .collect();
        out.sort_by_key(|o| o.0);
        out.dedup();
        out
    }
}

/// The law of one declared trial balance, decided from its lines alone:
/// 1..=max lines, codes within bounds, strictly ascending by
/// `(account_code, unit)`, never zero, and balanced in every unit.
fn check_lines(
    book: &BookContext,
    lines: &[TrialBalanceLine],
    what: &str,
    allow_empty: bool,
) -> Result<(), Refusal> {
    let structure = |why: String| {
        Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!("{what}: {why}"),
            "plan §8.6, Appendix A MigrationRun",
            "fix the named field of the run body and open again",
        )
    };
    if (lines.is_empty() && !allow_empty) || lines.len() > MAX_TRIAL_BALANCE_LINES {
        return Err(structure(format!(
            "a trial balance declares 1..={MAX_TRIAL_BALANCE_LINES} lines"
        )));
    }
    for (i, l) in lines.iter().enumerate() {
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
    if !fa_model::canon::strictly_ascending(lines, |l| (l.account_code.clone(), l.unit)) {
        return Err(structure(
            "lines must be strictly ascending by (account_code, unit)".into(),
        ));
    }
    let mut per_unit: BTreeMap<UnitId, i128> = BTreeMap::new();
    for l in lines {
        let slot = per_unit.entry(l.unit).or_insert(0);
        *slot = slot
            .checked_add(l.mantissa)
            .ok_or_else(|| structure(format!("unit {}: the declared lines overflow", l.unit.0)))?;
    }
    if let Some((unit, net)) = per_unit.iter().find(|(_, net)| **net != 0) {
        return Err(Refusal::new(
            code::TIE_OUT_MISMATCH,
            exit::REFUSAL,
            format!(
                "{what} does not balance in {}: its lines net to {}",
                unit_name(book, *unit),
                show(book, *unit, *net)
            ),
            "plan §8.6 (opening balances post as balanced entries), FA-INV-01",
            "declare the legacy trial balance exactly as the document states it; a legacy suspense balance is a line of its own",
        ));
    }
    Ok(())
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

/// What [`visible_at`] needs of one run at one sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunVisibility {
    finalized: bool,
    /// A non-sole `FullDetail` run counts only chunks dated on or after this
    /// day (its opening date, ruling 3675); `None`: every chunk counts.
    counts_from: Option<DateDay>,
}

/// The FA-INV-07 migration predicate: an entry whose origin names a run is
/// selected at `at` iff that run is `Finalized` at `at` and, for a non-sole
/// `FullDetail` run, the entry is dated on or after the run's opening date
/// (earlier detail is summarized by the Opening chunks; it stays journaled
/// for drill-down). Every other entry is unaffected. `cache` memoizes runs
/// for one scan at one `at`.
pub fn visible_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    entry: &Entry,
    at: CommitSeq,
    cache: &mut BTreeMap<VId, RunVisibility>,
) -> Result<bool, KernelError> {
    let EntryOrigin::Migration { run_ref, .. } = &entry.proposal.origin else {
        return Ok(true);
    };
    let run = match cache.get(run_ref) {
        Some(v) => *v,
        None => {
            let row = db.vertex_at(*run_ref, at)?.ok_or_else(|| {
                KernelError::Corrupt(format!(
                    "a Migration entry names run {:032x}, which does not exist at {}",
                    run_ref.0, at.0
                ))
            })?;
            let run = run_from_row(&row)?;
            let v = RunVisibility {
                finalized: run.state == RunState::Finalized,
                counts_from: counts_from(&run.body),
            };
            cache.insert(*run_ref, v);
            v
        }
    };
    Ok(run.finalized
        && run
            .counts_from
            .is_none_or(|day| entry.proposal.effective_date >= day))
}

/// The day from which a run's chunks count (ruling 3675 F3): a non-sole
/// `FullDetail` run's opening date; `None` for every other run (all its
/// chunks count).
fn counts_from(body: &RunBody) -> Option<DateDay> {
    (body.mode == RunMode::FullDetail && !body.sole_opening_source).then_some(body.opening_date)
}

/// A migrated leg as a settlement target (ruling 3733 C1): it is an open
/// item iff its run is `Finalized` and its chunk counts, exactly the
/// [`visible_at`] predicate at the head. The run's state is read inside
/// `txn` (a property-granular point read), so an `Abandon` that commits
/// first is a first-committer-wins conflict. `entry` is the witnessed
/// target at `target`; any other origin passes.
pub(crate) fn witness_open_item<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    target: VId,
    entry: &Entry,
    leg: usize,
) -> Outcome<()> {
    let EntryOrigin::Migration { run_ref, .. } = &entry.proposal.origin else {
        return Ok(Ok(()));
    };
    let row = txn.vertex(db, *run_ref)?.ok_or_else(|| {
        KernelError::Corrupt(format!(
            "a Migration entry names run {:032x}, which does not exist",
            run_ref.0
        ))
    })?;
    let run = run_from_row(&row)?;
    let state = RunState::from_scalar(txn.vertex_property(db, *run_ref, property::STATE)?.as_ref())
        .ok_or_else(|| KernelError::Corrupt(format!("run {:032x} state mirror", run_ref.0)))?;
    if state != RunState::Finalized {
        return Ok(Err(Refusal::new(
            code::SETTLE_TARGET,
            exit::REFUSAL,
            format!(
                "leg {leg}: entry {:032x} is a chunk of migration run `{}`, which is {}: nothing of it is open",
                target.0,
                run.body.run_key,
                state.name()
            ),
            "plan §8.6 (a migrated leg is an open item once its run is Finalized), ruling 3733",
            "finalize the run first; an abandoned run's chunks never open",
        )));
    }
    if let Some(day) = counts_from(&run.body)
        && entry.proposal.effective_date < day
    {
        return Ok(Err(Refusal::new(
            code::SETTLE_TARGET,
            exit::REFUSAL,
            format!(
                "leg {leg}: entry {:032x} is legacy detail dated {}, before run `{}`'s opening date {}: it is summarized by the run's opening balances",
                target.0,
                entry.proposal.effective_date.render(),
                run.body.run_key,
                day.render()
            ),
            "plan §8.6 (FullDetail detail before the run's opening date does not count), ruling 3733",
            "settle the Opening leg that carries this balance",
        )));
    }
    Ok(Ok(()))
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
    /// `None`: the opening trial balance. `Some(code)`: the cumulative trial
    /// balance at the end of that declared period.
    pub period: Option<String>,
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

type Fold = BTreeMap<(VId, UnitId), i128>;

/// Fold the run's chunks as known at `at` (every chunk, visible or not: the
/// tie-out is what Finalize would activate) and compare the folds with the
/// declared lines exactly: the chunks outside the declared periods (the
/// Opening period's) with the opening lines, and, for each declared period
/// `p` in order, the opening plus every declared period through `p` with
/// `p`'s cumulative lines.
pub fn tie_out<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    run: &Run,
    at: CommitSeq,
) -> Result<TieOut, KernelError> {
    let mut chunks = Vec::new();
    // The fold of the run's own Opening period (its opening chunks), and of
    // every other period by code.
    let own_opening = own_opening_code(book, run)?;
    let mut by_period: BTreeMap<String, Fold> = BTreeMap::new();
    let mut opening: Fold = BTreeMap::new();
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
        let folded = match &entry.proposal.effective_period {
            Some(p) if p.code != own_opening => by_period.entry(p.code.clone()).or_default(),
            _ => &mut opening,
        };
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
    let mut mismatches = compare(db, book, at, None, &run.body.lines, &opening)?;
    if run.body.mode == RunMode::FullDetail {
        mismatches.extend(full_detail_chain(db, book, at, run, &by_period)?);
        return finish_tie_out(run, at, chunks, mismatches);
    }
    let mut cumulative = opening;
    for p in &run.body.periods {
        if let Some(fold) = by_period.get(&p.period_code) {
            for (key, v) in fold {
                let slot = cumulative.entry(*key).or_insert(0);
                *slot = slot
                    .checked_add(*v)
                    .ok_or_else(|| KernelError::Corrupt("a run's fold overflowed i128".into()))?;
            }
        }
        mismatches.extend(compare(
            db,
            book,
            at,
            Some(p.period_code.as_str()),
            &p.lines,
            &cumulative,
        )?);
    }
    finish_tie_out(run, at, chunks, mismatches)
}

fn finish_tie_out(
    run: &Run,
    at: CommitSeq,
    chunks: Vec<RunChunk>,
    mismatches: Vec<TieOutLine>,
) -> Result<TieOut, KernelError> {
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

/// The code of the run's own Opening period: the Opening period of the
/// fiscal year that starts on the run's opening date.
fn own_opening_code(book: &BookContext, run: &Run) -> Result<String, KernelError> {
    book.calendar
        .periods_for_year(book.calendar.fiscal_year_of(run.body.opening_date)?)?
        .into_iter()
        .find(|p| p.kind == fa_time::PeriodKind::Opening)
        .map(|p| p.code)
        .ok_or_else(|| KernelError::Corrupt("the run's fiscal year has no Opening period".into()))
}

/// The fiscal calendar's period order within a year (ruling 3685): the
/// Opening period, the Normal periods, the adjustment periods, then the
/// Closing period.
fn calendar_rank(kind: fa_time::PeriodKind) -> u8 {
    match kind {
        fa_time::PeriodKind::Opening => 0,
        fa_time::PeriodKind::Normal | fa_time::PeriodKind::Historical => 1,
        fa_time::PeriodKind::Adjustment => 2,
        fa_time::PeriodKind::Closing => 3,
    }
}

/// A declared period's immutable start or end mirror, read inside `txn`.
fn period_bound<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    code: &str,
    key: fgdb_delta_types::PropertyKeyId,
) -> Result<DateDay, KernelError> {
    match txn.vertex_property(db, fa_model::period_vid(&book.calendar.id, code), key)? {
        Some(CanonicalScalar::Int(d)) => i32::try_from(d)
            .map(DateDay)
            .map_err(|_| KernelError::Corrupt(format!("period `{code}` date mirror"))),
        other => Err(KernelError::Corrupt(format!(
            "declared period `{code}` date mirror: {other:?}"
        ))),
    }
}

/// Whether `period` lies inside a FullDetail run's declared run of periods,
/// between the first declared period's start and the last one's end (the
/// book's opening date): where legacy Opening, Adjustment and Closing
/// detail lands (ruling 3685). Read inside the posting transaction.
pub(crate) fn within_declared<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    body: &RunBody,
    period: &fa_time::PeriodDef,
) -> Result<bool, KernelError> {
    let (Some(first), Some(last)) = (body.periods.first(), body.periods.last()) else {
        return Ok(false);
    };
    let from = period_bound(txn, db, book, &first.period_code, property::PERIOD_START)?;
    let to = period_bound(txn, db, book, &last.period_code, property::PERIOD_END)?;
    Ok(period.start >= from && period.end <= to)
}

/// The FullDetail chain (ruling 3675 F2, 3685): from `detail_base`, every
/// period between the first declared period's start and the last one's end
/// in calendar order (special periods included, undeclared), each declared
/// `p` compared with its lines; unless the run is the sole source, the
/// Opening lines against the chain at the run's opening date (mismatches
/// name the Opening period).
fn full_detail_chain<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    at: CommitSeq,
    run: &Run,
    by_period: &BTreeMap<String, Fold>,
) -> Result<Vec<TieOutLine>, KernelError> {
    let (Some(first), Some(last)) = (run.body.periods.first(), run.body.periods.last()) else {
        return Ok(Vec::new());
    };
    let row_of = |code: &str| -> Result<crate::rows::PeriodRow, KernelError> {
        let row = db
            .vertex_at(fa_model::period_vid(&book.calendar.id, code), at)?
            .ok_or_else(|| KernelError::Corrupt(format!("declared period `{code}` is missing")))?;
        crate::rows::PeriodRow::decode(&row)
    };
    let from = row_of(&first.period_code)?.start;
    let to = row_of(&last.period_code)?.end;
    let own_opening = own_opening_code(book, run)?;
    let mut order = Vec::new();
    for fy in book.calendar.fiscal_year_of(from)?..=book.calendar.fiscal_year_of(to)? {
        for p in book.calendar.periods_for_year(fy)? {
            if p.start >= from && p.end <= to && p.code != own_opening {
                order.push(p);
            }
        }
    }
    order.sort_by_key(|p| (p.start, calendar_rank(p.kind)));
    let mut chain: Fold = BTreeMap::new();
    for l in &run.body.detail_base {
        chain.insert(
            (account_vid(book.book_id, &l.account_code), l.unit),
            l.mantissa,
        );
    }
    let mut out = Vec::new();
    let mut opening_checked = run.body.sole_opening_source;
    for q in &order {
        if !opening_checked && q.start >= run.body.opening_date {
            out.extend(compare(
                db,
                book,
                at,
                Some(own_opening.as_str()),
                &run.body.lines,
                &chain,
            )?);
            opening_checked = true;
        }
        if let Some(fold) = by_period.get(&q.code) {
            for (key, v) in fold {
                let slot = chain.entry(*key).or_insert(0);
                *slot = slot
                    .checked_add(*v)
                    .ok_or_else(|| KernelError::Corrupt("a run's fold overflowed i128".into()))?;
            }
        }
        if let Some(p) = run.body.periods.iter().find(|p| p.period_code == q.code) {
            out.extend(compare(
                db,
                book,
                at,
                Some(q.code.as_str()),
                &p.lines,
                &chain,
            )?);
        }
    }
    if !opening_checked {
        out.extend(compare(
            db,
            book,
            at,
            Some(own_opening.as_str()),
            &run.body.lines,
            &chain,
        )?);
    }
    Ok(out)
}

/// The lines where `folded` differs from the `declared` trial balance,
/// ascending by `(account_code, unit)`.
fn compare<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    at: CommitSeq,
    period: Option<&str>,
    lines: &[TrialBalanceLine],
    folded: &Fold,
) -> Result<Vec<TieOutLine>, KernelError> {
    let mut declared: BTreeMap<(VId, UnitId), (String, i128)> = BTreeMap::new();
    for l in lines {
        declared.insert(
            (account_vid(book.book_id, &l.account_code), l.unit),
            (l.account_code.clone(), l.mantissa),
        );
    }
    let mut out = Vec::new();
    for ((account, unit), (code, want)) in &declared {
        let got = folded.get(&(*account, *unit)).copied().unwrap_or(0);
        if got != *want {
            out.push(TieOutLine {
                period: period.map(str::to_string),
                account_code: code.clone(),
                unit: *unit,
                declared: *want,
                folded: got,
            });
        }
    }
    for ((account, unit), got) in folded {
        if *got != 0 && !declared.contains_key(&(*account, *unit)) {
            let code = match db.vertex_at(*account, at)? {
                Some(row) => crate::rows::text(&row, property::CODE, "account.code")?,
                None => format!("{:032x}", account.0),
            };
            out.push(TieOutLine {
                period: period.map(str::to_string),
                account_code: code,
                unit: *unit,
                declared: 0,
                folded: *got,
            });
        }
    }
    out.sort_by(|a, b| (&a.account_code, a.unit).cmp(&(&b.account_code, b.unit)));
    Ok(out)
}

fn mismatch_refusal(book: &BookContext, lines: &[TieOutLine]) -> Refusal {
    let named: Vec<String> = lines
        .iter()
        .map(|l| {
            format!(
                "`{}` {} {}: declared {}, folded {}",
                l.account_code,
                unit_name(book, l.unit),
                l.period.as_ref().map_or_else(
                    || "at the opening date".to_string(),
                    |p| format!("through `{p}`")
                ),
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
            control_kind: ControlKind::MIGRATION_RUN,
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

/// The `Open` proposal for `body`: dated on its opening date, citing every
/// trial balance document the body names (`citations`, put in canonical
/// order here).
pub fn open_proposal(
    book: &BookContext,
    principal: VId,
    body: &RunBody,
    mut citations: Vec<EvidenceRef>,
    idempotency_key: &[u8],
    description: Erasable<String>,
) -> Result<EntryPayload, KernelError> {
    citations.sort_by(|a, b| {
        (a.document_oid.0, a.doc_commit, a.role).cmp(&(b.document_oid.0, b.doc_commit, b.role))
    });
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
        citations,
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
        || !body
            .documents()
            .iter()
            .all(|d| proposal.evidence.iter().any(|e| e.document_oid == *d))
    {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "an Open record binds its body's digest, is dated on the opening date, and cites every trial balance document the body names",
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
    if let Err(r) = check_history(&txn, db, book, body)? {
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

/// A run's declared periods are exactly a contiguous run of the book's
/// Historical periods (plan §8.6, §7.2), in calendar order, each already
/// created and born `Historical`, ending at the book's opening date:
/// `PeriodBalances` from the run's opening date; `FullDetail` from its
/// first declared period, which for a non-sole run starts on or before the
/// run's opening date (the chain must have a value there to tie the Opening
/// chunks to, ruling 3675). Read inside the opening transaction; the book
/// spec and a period's kind and dates are immutable.
fn check_history<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    body: &RunBody,
) -> Outcome<()> {
    if body.mode == RunMode::OpeningOnly {
        return Ok(Ok(()));
    }
    let structure = |what: String, fix: &str| {
        Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            what,
            "plan §8.6 (PeriodBalances: one entry per elapsed period), §7.2 (Historical periods precede the book's opening date)",
            fix,
        )
    };
    let root = txn
        .vertex(db, crate::rows::book_root())?
        .ok_or_else(|| KernelError::Corrupt("a run needs a book: no genesis row".into()))?;
    let spec =
        crate::genesis::BookSpec::decode(&bytes(&root, property::FA_PAYLOAD, "book._fa_payload")?)?;
    let Some(go_live) = spec.opening_date else {
        return Ok(Err(structure(
            "the book declares no opening date, so no period is Historical".into(),
            "declare the book's opening date at genesis, or open an OpeningOnly run",
        )));
    };
    let start = if body.mode == RunMode::PeriodBalances {
        body.opening_date
    } else {
        let first = body.periods.first().ok_or_else(|| {
            KernelError::Corrupt("a checked FullDetail body declares periods".into())
        })?;
        match txn.vertex(
            db,
            fa_model::period_vid(&book.calendar.id, &first.period_code),
        )? {
            Some(row) => crate::rows::PeriodRow::decode(&row)?.start,
            None => {
                return Ok(Err(structure(
                    format!("period `{}` does not exist yet", first.period_code),
                    "create the fiscal year's periods first (they are born Historical before the opening date)",
                )));
            }
        }
    };
    if body.mode == RunMode::FullDetail && !body.sole_opening_source && start > body.opening_date {
        return Ok(Err(structure(
            format!(
                "the declared periods start on {}, after the run's opening date {}: the Opening chunks are tied to the detail chain at that date",
                start.render(),
                body.opening_date.render()
            ),
            "declare the periods from on or before the run's opening date, or declare the run the sole source",
        )));
    }
    let mut expected = Vec::new();
    let first = book.calendar.fiscal_year_of(start)?;
    let last = book.calendar.fiscal_year_of(go_live)?;
    for fy in first..=last {
        for p in book.calendar.periods_for_year(fy)? {
            if p.kind == fa_time::PeriodKind::Normal && p.start >= start && p.end <= go_live {
                expected.push(p.code);
            }
        }
    }
    let named: Vec<&str> = body
        .periods
        .iter()
        .map(|p| p.period_code.as_str())
        .collect();
    if named != expected.iter().map(String::as_str).collect::<Vec<_>>() {
        return Ok(Err(structure(
            format!(
                "the run must declare exactly the elapsed periods from {} to the book's opening date {}: [{}], in order; it declares [{}]",
                start.render(),
                go_live.render(),
                expected.join(", "),
                named.join(", ")
            ),
            "list every elapsed period once, in calendar order, each with its trial balance as of its end",
        )));
    }
    for code in &expected {
        let pvid = fa_model::period_vid(&book.calendar.id, code);
        let born = match txn.vertex(db, pvid)? {
            Some(row) => crate::rows::PeriodRow::decode(&row)?.kind,
            None => {
                return Ok(Err(structure(
                    format!("period `{code}` does not exist yet"),
                    "create the fiscal year's periods first (they are born Historical before the opening date)",
                )));
            }
        };
        if born != fa_time::PeriodKind::Historical {
            return Err(KernelError::Corrupt(format!(
                "period `{code}` precedes the book's opening date but was born {born:?}"
            )));
        }
    }
    Ok(Ok(()))
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
            periods: Vec::new(),
            detail_base: Vec::new(),
            sole_opening_source: false,
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
