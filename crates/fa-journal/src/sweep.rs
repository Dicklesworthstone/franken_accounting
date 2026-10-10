//! Time evidence and the expiry sweep (plan §5.4, §7.1a).
//!
//! **Ticks.** Instants enter the book only as journaled `TimeControl`
//! entries carrying `ControlPayload::TimeTick` (plan §7.1a). The kernel never
//! reads a clock: the caller (the daemon, under its time capability) supplies
//! the observation, and [`record_tick`] refuses one that does not strictly
//! follow the book's latest tick. The latest tick rides the book root as
//! `latest_tick` (`observed_utc_ns ‖ tick entry vid`), moved by
//! compare-and-set, so every reader of "now" in a transaction holds a point
//! witness of it.
//!
//! **Timed holds.** A `Pending` with `timeout_ns` anchors on the latest tick
//! in the strictly preceding committed prefix — the root's `latest_tick` as
//! of the commit before the hold's own ([`tick_before`]) — so the anchor is
//! derived from the hold's journal position, never stored in its proposal.
//! The posting kernel witnesses `latest_tick` when it admits a timed hold (a
//! tick that commits first is a first-committer-wins conflict), and a tick
//! never shares a commit with a hold. `deadline = anchor + timeout_ns`
//! (checked); the hold is *due* once a committed tick has
//! `observed_utc_ns ≥ deadline`.
//!
//! **The sweep.** [`sweep_batch`] expires due holds in the commit order of
//! the holds, at most `max_batch` (≤ `max_batch_entries`) per transaction.
//! Each batch commits its `Resolution(Expires { at_tick })` entries — each
//! at the hold's derived resolution identity, so a manual void racing the
//! sweep is an `AlreadyLive` point conflict, never a double release — and
//! one `SweepControl` entry carrying `ControlPayload::SweepCursor`, whose
//! position also rides the book root as `sweep_cursor` (`tick vid ‖ last
//! pending vid`). A later batch under the same tick continues after the
//! cursor; a new tick starts a new epoch from the first due hold. A due hold
//! the batch bound left behind is still pending in every register and is
//! reported by [`due_holds`] until a batch expires it.
//!
//! **Routing.** An `Expires` is dated in its hold's own period (its date and
//! discriminator), so it releases the reservation cells the hold reserved;
//! Appendix C admits a release in every state but `Future`, so a hold whose
//! period has since closed or locked is still released, unconditionally,
//! and closing or locking a period never waits on its holds.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry as MapEntry;

use fa_model::limits::MAX_BATCH_ENTRIES;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ControlPayload, Disposition, Entry, EntryClass, EntryOrigin, EntryPayload, EntryRef, Erasable,
    Id128, Oid, Pending, entry_mirrors, entry_vid, period_vid,
};
use fa_money::Side;
use fa_policy::{Intent, Party};
/// The capability vocabulary a sweep request is built from (the sweep's
/// capability is a `Profile::System` one holding `Op::Post`).
pub use fa_policy::{Op, Profile};
use fa_registry::{Admissibility, Decision, EntryClasses};
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::genesis::BookContext;
use crate::limit::{self, LimitCell, LimitScope, Movement};
use crate::policy;
use crate::post::{Capability, Identity, Posted, recorded_or_conflict};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{
    AccountRow, book_root, edge_id, prop, resolution_vid, scalar_bytes, state_from_scalar,
    sweep_cursor_vid,
};

/// `TimeEvidence.source`: the daemon's clock (plan §7.1a). The only source
/// this slice admits; `AuthorityDocument` and `SubstrateMarker` land with
/// their evidence rules (Appendix H R-HLC).
pub const SOURCE_DAEMON_CLOCK: u8 = 0;

/// `SweepCursor.sweep_kind` / `EntryOrigin::Sweep.sweep_kind`: the expiry
/// sweep (scheduled reversals take the next kind).
pub const SWEEP_EXPIRY: u8 = 1;

/// The `EntryOrigin::Control.control_kind` of a tick.
const CONTROL_KIND_TICK: u16 = 4;

const NS_PER_DAY: u64 = 86_400_000_000_000;

/// One committed TimeEvidence tick: the observed instant and the
/// `TimeControl` entry that journaled it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tick {
    pub observed_utc_ns: u64,
    pub entry: VId,
}

impl Tick {
    fn scalar(&self) -> Result<CanonicalScalar, KernelError> {
        let mut b = Vec::with_capacity(24);
        b.extend_from_slice(&self.observed_utc_ns.to_le_bytes());
        b.extend_from_slice(&self.entry.0.to_le_bytes());
        scalar_bytes("latest_tick", b)
    }

    fn from_scalar(s: Option<&CanonicalScalar>) -> Result<Option<Self>, KernelError> {
        match s {
            None => Ok(None),
            Some(CanonicalScalar::Bytes(b)) => {
                let raw = b.as_slice();
                let (Ok(ns), Ok(vid)) = (
                    <[u8; 8]>::try_from(raw.get(..8).unwrap_or_default()),
                    <[u8; 16]>::try_from(raw.get(8..).unwrap_or_default()),
                ) else {
                    return Err(KernelError::Corrupt(format!(
                        "book root latest_tick is {} bytes, not 24",
                        raw.len()
                    )));
                };
                Ok(Some(Self {
                    observed_utc_ns: u64::from_le_bytes(ns),
                    entry: VId(u128::from_le_bytes(vid)),
                }))
            }
            Some(other) => Err(KernelError::Corrupt(format!(
                "book root latest_tick: {other:?}"
            ))),
        }
    }
}

/// The sweep's position: the tick whose epoch it is and the last hold it
/// expired (plan §5.4 `SweepCursor`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub tick: VId,
    pub last_pending: VId,
}

impl Cursor {
    pub(crate) fn scalar(&self) -> Result<CanonicalScalar, KernelError> {
        let mut b = Vec::with_capacity(32);
        b.extend_from_slice(&self.tick.0.to_le_bytes());
        b.extend_from_slice(&self.last_pending.0.to_le_bytes());
        scalar_bytes("sweep_cursor", b)
    }

    pub(crate) fn from_scalar(s: Option<&CanonicalScalar>) -> Result<Option<Self>, KernelError> {
        match s {
            None => Ok(None),
            Some(CanonicalScalar::Bytes(b)) => {
                let raw = b.as_slice();
                let (Ok(tick), Ok(last)) = (
                    <[u8; 16]>::try_from(raw.get(..16).unwrap_or_default()),
                    <[u8; 16]>::try_from(raw.get(16..).unwrap_or_default()),
                ) else {
                    return Err(KernelError::Corrupt(format!(
                        "book root sweep_cursor is {} bytes, not 32",
                        raw.len()
                    )));
                };
                Ok(Some(Self {
                    tick: VId(u128::from_le_bytes(tick)),
                    last_pending: VId(u128::from_le_bytes(last)),
                }))
            }
            Some(other) => Err(KernelError::Corrupt(format!(
                "book root sweep_cursor: {other:?}"
            ))),
        }
    }
}

pub(crate) fn root_row<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    at: Option<CommitSeq>,
) -> Result<Option<VertexRow>, KernelError> {
    Ok(match at {
        None => db.vertex(book_root())?,
        Some(seq) => db.vertex_at(book_root(), seq)?,
    })
}

/// The book's latest committed tick at head.
pub fn latest_tick<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
) -> Result<Option<Tick>, KernelError> {
    match root_row(db, None)? {
        Some(row) => Tick::from_scalar(prop(&row, property::LATEST_TICK)),
        None => Err(KernelError::Corrupt("no book root".into())),
    }
}

/// The latest tick in the committed prefix strictly before `seq` (the
/// anchor of a timed hold committed at `seq`, plan §5.4).
pub fn tick_before<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    seq: CommitSeq,
) -> Result<Option<Tick>, KernelError> {
    let Some(prev) = seq.0.checked_sub(1) else {
        return Ok(None);
    };
    match root_row(db, Some(CommitSeq(prev)))? {
        Some(row) => Tick::from_scalar(prop(&row, property::LATEST_TICK)),
        None => Ok(None),
    }
}

/// The latest tick as a point witness of `txn`, with the raw scalar (the
/// expectation of a compare-and-set).
pub(crate) fn tick_witness<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
) -> Result<(Option<CanonicalScalar>, Option<Tick>), KernelError> {
    let scalar = txn.vertex_property(db, book_root(), property::LATEST_TICK)?;
    let tick = Tick::from_scalar(scalar.as_ref())?;
    Ok((scalar, tick))
}

/// The deadline of a timed hold committed at `seq`: its anchor tick (the
/// latest tick strictly before `seq`) plus `timeout_ns`. The kernel admits
/// a timed hold only with an anchor and a representable deadline, so either
/// failing here is corruption.
pub fn deadline<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    seq: CommitSeq,
    timeout_ns: u64,
) -> Result<u64, KernelError> {
    let anchor = tick_before(db, seq)?.ok_or_else(|| {
        KernelError::Corrupt(format!(
            "a timed hold committed at {} has no preceding tick",
            seq.0
        ))
    })?;
    anchor
        .observed_utc_ns
        .checked_add(timeout_ns)
        .ok_or_else(|| {
            KernelError::Corrupt(format!(
                "a timed hold committed at {} has a deadline beyond u64",
                seq.0
            ))
        })
}

/// The UTC civil day of an instant: the positional date a book-scoped
/// control carries (its period law is its authority row, not a date).
pub(crate) fn utc_day(ns: u64) -> Result<DateDay, KernelError> {
    i32::try_from(ns / NS_PER_DAY)
        .map(DateDay)
        .map_err(|_| KernelError::Corrupt("tick day beyond i32".into()))
}

pub(crate) fn decode_entry(row: &VertexRow) -> Result<Entry, KernelError> {
    match prop(row, property::FA_PAYLOAD) {
        Some(CanonicalScalar::Bytes(b)) => Ok(Entry::decode(b.as_slice())?),
        other => Err(KernelError::Corrupt(format!(
            "entry _fa_payload: {other:?}"
        ))),
    }
}

/// One hold the latest tick has made due and no resolution has resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DueHold {
    pub hold: EntryRef,
    pub recorded_at: CommitSeq,
    pub deadline_ns: u64,
}

/// Every unresolved timed hold that `at` (the latest tick when `None`) has
/// made due, in the holds' commit order — the backlog `fa triage` reports
/// as `due` (plan §5.4, FA-CFG-02). A snapshot scan at head: the sweep
/// re-reads each candidate as a point witness inside its transaction.
pub fn due_holds<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    at: Option<Tick>,
) -> Result<Vec<DueHold>, KernelError> {
    let at = match at {
        Some(t) => Some(t),
        None => latest_tick(db)?,
    };
    let Some(at) = at else {
        return Ok(Vec::new());
    };
    let mut due = Vec::new();
    for row in db.vertices()? {
        if !row.labels.contains(&label::ENTRY)
            || prop(&row, property::CLASS)
                != Some(&CanonicalScalar::Int(i64::from(EntryClass::PENDING.0)))
        {
            continue;
        }
        let entry = decode_entry(&row)?;
        let Some(Pending {
            timeout_ns: Some(timeout),
            ..
        }) = entry.proposal.pending
        else {
            continue;
        };
        if db.vertex(resolution_vid(row.vid))?.is_some() {
            continue;
        }
        let deadline_ns = deadline(db, row.created_at, timeout)?;
        if at.observed_utc_ns >= deadline_ns {
            due.push(DueHold {
                hold: entry.entry_ref(row.vid),
                recorded_at: row.created_at,
                deadline_ns,
            });
        }
    }
    due.sort_by_key(|d| (d.recorded_at, d.hold.vid));
    Ok(due)
}

/// One TimeEvidence observation to journal (plan §7.1a). The kernel reads
/// no clock: `observed_utc_ns` is the caller's observation under its time
/// capability.
#[derive(Clone, Debug)]
pub struct TickRequest {
    pub observed_utc_ns: u64,
    /// `TimeEvidence.source`; this slice admits [`SOURCE_DAEMON_CLOCK`].
    pub source: u8,
    pub monotonic_ok: bool,
    pub principal_ref: VId,
    pub capability: Capability,
    pub idempotency_key: Vec<u8>,
    pub description: Erasable<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticked {
    pub tick: Tick,
    pub entry_ref: EntryRef,
    pub recorded_at: CommitSeq,
    /// The same tick request was already recorded: nothing was written.
    pub already_recorded: bool,
}

/// The `TimeControl` proposal journaling `req`.
#[must_use]
pub fn tick_proposal(book: &BookContext, req: &TickRequest) -> EntryPayload {
    EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::TIME_CONTROL,
        // The UTC day of the observation; the date is positional in v1 and
        // a book-scoped control carries no effective day (plan §7.1).
        effective_date: DateDay(
            i32::try_from(req.observed_utc_ns / NS_PER_DAY).unwrap_or(i32::MAX),
        ),
        document_date: None,
        description: req.description.clone(),
        effective_period: None,
        legs: Vec::new(),
        control: Some(ControlPayload::TimeTick {
            observed_utc_ns: req.observed_utc_ns,
            source: req.source,
            monotonic_ok: req.monotonic_ok,
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: req.idempotency_key.clone(),
        origin: EntryOrigin::Control {
            control_kind: CONTROL_KIND_TICK,
            spec_body_digest: fgdb_crypto::hash(&req.observed_utc_ns.to_le_bytes()).0,
        },
        principal_ref: req.principal_ref,
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    }
}

pub(crate) fn conflict(what: &str, detail: impl core::fmt::Display) -> Refusal {
    Refusal::new(
        code::CONFLICT,
        exit::CONFLICT,
        format!("a concurrent commit invalidated {what}: {detail}"),
        "FG-LAW-FCW-01 (first committer wins)",
        "re-read and retry",
    )
}

/// Journal one tick: a `TimeControl` entry and a compare-and-set moving the
/// book root's `latest_tick` from the value this transaction witnessed.
/// Refused before any read: a source this slice does not admit, a malformed
/// proposal, a capability that is not the preparer's, lacks the `time-tick`
/// row's op (`witness`), or has expired. Then the identity (the same request
/// again is its recorded outcome), then the order: `observed_utc_ns` must
/// strictly exceed the latest tick's (FA-REF-094).
pub async fn record_tick<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    req: TickRequest,
) -> Outcome<Ticked> {
    if req.source != SOURCE_DAEMON_CLOCK {
        return Ok(Err(Refusal::new(
            code::CLASS_NOT_IMPLEMENTED,
            exit::REFUSAL,
            format!(
                "tick source {} is registered but this slice admits only DaemonClock (0)",
                req.source
            ),
            "plan §7.1a (TimeEvidence sources), Appendix H R-HLC",
            "journal the daemon clock's observation; AuthorityDocument and SubstrateMarker ticks land with their evidence rules",
        )));
    }
    let proposal = tick_proposal(book, &req);
    if let Err(e) = proposal.validate() {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            e.to_string(),
            "Appendix A fa:entry:v1",
            "fix the named field and resubmit",
        )));
    }
    let steward = policy::steward()?;
    let key = fa_policy::sod::control_key("TimeControl", None, "Tick");
    let Some(op) = steward.preparer_op(&key) else {
        return Err(KernelError::Corrupt(
            "sod_policy.toml has no time-tick rule".into(),
        ));
    };
    if let Err(d) = fa_policy::admit(
        &req.capability,
        &Intent {
            principal: req.principal_ref,
            trunk: true,
            op,
            legs: &[],
        },
    ) {
        return Ok(Err(policy::refusal(&d)));
    }
    if let Err(d) = fa_policy::current(&req.capability, db.frontier()?) {
        return Ok(Err(policy::refusal(&d)));
    }
    let proposal_digest = proposal.proposal_digest()?;
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    let evid = entry_vid(
        book.book_id,
        &req.principal_ref.0.to_le_bytes(),
        &req.idempotency_key,
    );
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return recorded_tick(&row, &proposal, book);
    }
    let (witnessed, latest) = tick_witness(&txn, db)?;
    if let Some(prev) = latest
        && req.observed_utc_ns <= prev.observed_utc_ns
    {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::TICK_ORDER,
            exit::REFUSAL,
            format!(
                "tick {} ns does not follow the book's latest tick {} ns (entry {:032x})",
                req.observed_utc_ns, prev.observed_utc_ns, prev.entry.0
            ),
            "plan §7.1a (ticks are strictly increasing; a rollback is refused)",
            format!(
                "journal an observation later than {} ns; a clock that stepped back is an operational incident, not a tick",
                prev.observed_utc_ns
            ),
        )));
    }
    let epoch = policy::epoch_witness(&txn, db)?;
    let preparer = Party {
        principal: req.principal_ref,
        profile: req.capability.profile(),
    };
    if let Err(r) = policy::authorize_approvals(
        &txn,
        db,
        book,
        &[],
        &proposal_digest,
        epoch,
        &key,
        0,
        preparer,
    )? {
        txn.abort();
        return Ok(Err(r));
    }
    let entry = proposal.clone().seal(Vec::new(), None)?;
    let tick = Tick {
        observed_utc_ns: req.observed_utc_ns,
        entry: evid,
    };
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    batch.compare_and_set_vertex_property(
        book_root(),
        property::LATEST_TICK,
        witnessed,
        tick.scalar()?,
        WriteMismatchPolicy::AbortWrite,
    );
    txn.write(db, batch)?;
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(Ticked {
            tick,
            entry_ref: entry.entry_ref(evid),
            recorded_at: seq,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(conflict("this tick's witness", detail)))
        }
        Err(WriteTxnError::Write(fgdb::WriteError::CompareAndSetMismatch(_))) => {
            Ok(Err(conflict("this tick", "the latest tick moved")))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => match db.vertex(evid)? {
            Some(row) => recorded_tick(&row, &proposal, book),
            None => Err(KernelError::Corrupt(
                "identity spent but no live row".into(),
            )),
        },
        Err(e) => Err(e.into()),
    }
}

/// The recorded outcome of the tick at `row`, or a conflict.
fn recorded_tick(row: &VertexRow, proposal: &EntryPayload, book: &BookContext) -> Outcome<Ticked> {
    match recorded_or_conflict(row, proposal, &book.seal_key, Identity::Key)? {
        Err(r) => Ok(Err(r)),
        Ok(posted) => {
            let stored = decode_entry(row)?;
            let Some(ControlPayload::TimeTick {
                observed_utc_ns, ..
            }) = stored.proposal.control
            else {
                return Err(KernelError::Corrupt(format!(
                    "entry {:032x} matched a tick request but is not a tick",
                    row.vid.0
                )));
            };
            let Posted::AlreadyRecorded {
                entry_ref,
                recorded_at,
            } = posted
            else {
                return Err(KernelError::Corrupt("recorded outcome expected".into()));
            };
            Ok(Ok(Ticked {
                tick: Tick {
                    observed_utc_ns,
                    entry: row.vid,
                },
                entry_ref,
                recorded_at,
                already_recorded: true,
            }))
        }
    }
}

/// One sweep transaction's request. The sweep is the book's intrinsic actor:
/// its capability is a `System`-profile capability holding the
/// `expiry-sweep` row's op (`post`).
#[derive(Clone, Debug)]
pub struct SweepRequest {
    pub principal_ref: VId,
    pub capability: Capability,
    /// Holds expired per transaction, `1..=max_batch_entries`.
    pub max_batch: usize,
}

/// One committed sweep batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SweepBatch {
    /// The tick whose evidence the batch ran under.
    pub tick: Tick,
    /// `(hold, its Expires resolution)`, in the holds' commit order.
    pub expired: Vec<(EntryRef, EntryRef)>,
    /// The batch's `SweepControl` entry.
    pub cursor_entry: EntryRef,
    pub recorded_at: CommitSeq,
    /// Holds due under this tick that the batch bound left for the next
    /// batch: still pending in every register until a batch expires them.
    pub remaining_due: usize,
}

/// The `Resolution(Expires)` of `hold` under `tick` (plan §5.4): no legs,
/// `ReservationRelease`, dated in the hold's own period.
fn expires_proposal(
    book: &BookContext,
    principal: VId,
    hold: &Entry,
    hold_vid: VId,
    tick: Tick,
    tick_digest: [u8; 32],
    description: Erasable<String>,
) -> EntryPayload {
    EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::RESOLUTION,
        effective_date: hold.proposal.effective_date,
        document_date: None,
        description,
        effective_period: hold.proposal.effective_period.clone(),
        legs: Vec::new(),
        control: Some(ControlPayload::ReservationRelease),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: format!("expires:{:032x}", hold_vid.0).into_bytes(),
        origin: EntryOrigin::Sweep {
            sweep_kind: SWEEP_EXPIRY,
            tick_evidence_oid: Oid(tick_digest),
        },
        principal_ref: principal,
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: Some(Pending {
            timeout_ns: None,
            resolution_of: Some(hold.entry_ref(hold_vid)),
            disposition: Some(Disposition::Expires {
                at_tick: tick.observed_utc_ns,
            }),
        }),
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    }
}

/// The `SweepControl` proposal recording a batch's progress.
#[allow(clippy::too_many_arguments)]
pub(crate) fn cursor_proposal(
    book: &BookContext,
    principal: VId,
    sweep_kind: u8,
    cursor: Cursor,
    cursor_vid: VId,
    tick: Tick,
    tick_digest: [u8; 32],
    description: Erasable<String>,
) -> Result<EntryPayload, KernelError> {
    Ok(EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::SWEEP_CONTROL,
        effective_date: utc_day(tick.observed_utc_ns)?,
        document_date: None,
        description,
        effective_period: None,
        legs: Vec::new(),
        control: Some(ControlPayload::SweepCursor {
            sweep_kind,
            last_pending_vid: cursor.last_pending,
            tick_ref: cursor.tick,
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: format!("sweep:{:032x}", cursor_vid.0).into_bytes(),
        origin: EntryOrigin::Sweep {
            sweep_kind,
            tick_evidence_oid: Oid(tick_digest),
        },
        principal_ref: principal,
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    })
}

/// Period law for one `Resolution(Expires)` (plan §5.4): the registered
/// `Resolution(Expires)` row of the hold's period state decides — never an
/// assumption in the sweep. A refusing (or `with:` an op the sweep lacks)
/// row refuses the batch.
fn expires_admissible(
    matrix: &Admissibility,
    state: fa_time::PeriodState,
    period: &str,
    capability: &Capability,
) -> Result<(), Refusal> {
    let cell = format!("admissibility.toml (Resolution(Expires), {})", state.name());
    match matrix.decide_expires(state) {
        Some(Decision::Admit) => Ok(()),
        Some(Decision::With { op, .. })
            if Op::from_name(op).is_some_and(|o| capability.holds(o)) =>
        {
            Ok(())
        }
        Some(Decision::With { op, .. }) => Err(Refusal::new(
            code::CAPABILITY,
            exit::SAFETY,
            format!(
                "Resolution(Expires) in a {} period requires capability op `{op}`",
                state.name()
            ),
            cell,
            format!("grant the sweep's System capability `{op}`"),
        )),
        Some(Decision::Refuse) | None => Err(Refusal::new(
            code::PERIOD_LAW,
            exit::SAFETY,
            format!(
                "Resolution(Expires) is not admissible in period `{period}` ({})",
                state.name()
            ),
            cell,
            "release the hold with Resolution(Voids) where admissible; a hold's period is never Future, so `fa verify` names any corruption",
        )),
    }
}

/// A limit cell a batch moves: the witnessed state and the running state
/// after every hold released so far (one generation per entry).
pub(crate) struct CellRun {
    pub(crate) before: LimitCell,
    pub(crate) after: LimitCell,
}

/// Release `hold`'s full original legs from its own period's reservation
/// cells (plan §5.4), folding into `cells` so several holds of one batch on
/// one cell compose; every read is a point witness of `txn`.
fn release_hold<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    accounts: &mut BTreeMap<VId, AccountRow>,
    cells: &mut BTreeMap<VId, CellRun>,
    hold: &EntryPayload,
    hold_period: &str,
) -> Result<(), KernelError> {
    let mut moves: BTreeMap<VId, (VId, Option<String>, Movement)> = BTreeMap::new();
    for leg in &hold.legs {
        let account = match accounts.entry(leg.account_ref) {
            MapEntry::Occupied(o) => o.into_mut(),
            MapEntry::Vacant(v) => {
                let row = txn.vertex(db, leg.account_ref)?.ok_or_else(|| {
                    KernelError::Corrupt(format!(
                        "the hold's account {:032x} is missing",
                        leg.account_ref.0
                    ))
                })?;
                v.insert(AccountRow::decode(&row)?)
            }
        };
        let Some(limit) = account.limit else {
            continue;
        };
        let cell_period = match limit.scope {
            LimitScope::Lifetime => None,
            LimitScope::Period => Some(hold_period.to_string()),
        };
        let cvid = limit::cell_vid(account.vid, cell_period.as_deref());
        moves
            .entry(cvid)
            .or_insert_with(|| (account.vid, cell_period, Movement::default()))
            .2
            .release(leg.side, leg.amount.mantissa)?;
    }
    for (cvid, (account_vid, cell_period, m)) in moves {
        let account = accounts
            .get(&account_vid)
            .ok_or_else(|| KernelError::Corrupt("released account row".into()))?;
        let limit = account
            .limit
            .ok_or_else(|| KernelError::Corrupt("released account has no limit".into()))?;
        let run = match cells.entry(cvid) {
            MapEntry::Occupied(o) => o.into_mut(),
            MapEntry::Vacant(v) => {
                let row = txn
                    .vertex(db, cvid)?
                    .filter(|r| r.labels.contains(&label::LIMIT_CELL))
                    .ok_or_else(|| {
                        KernelError::Corrupt(format!(
                            "limited account `{}` has no limit cell; `fa verify availability` names it",
                            account.code
                        ))
                    })?;
                let before = LimitCell::decode_bound(&row, account_vid, cell_period.as_deref())?;
                v.insert(CellRun {
                    before,
                    after: before,
                })
            }
        };
        let normal = if account.normal_balance == 0 {
            Side::Debit
        } else {
            Side::Credit
        };
        // A pure release never breaches: it lowers a reservation and moves
        // nothing posted. A breach here is corruption.
        match limit::apply(&run.after, normal, &limit, &m)? {
            Ok(next) => run.after = next,
            Err(b) => {
                return Err(KernelError::Corrupt(format!(
                    "releasing a hold breached account `{}`: {b:?}",
                    account.code
                )));
            }
        }
    }
    Ok(())
}

/// Admission of one sweep transaction, decided before any read (plan §5.4,
/// §7.6): the batch bound, the System profile (the sweep is the book's
/// intrinsic actor), the authority row's preparer op and `post`, and the
/// capability current at the admission point.
pub(crate) fn admit_sweep<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    req: &SweepRequest,
    key: &fa_registry::sod_policy::SodKey,
) -> Outcome<()> {
    if req.max_batch == 0 || req.max_batch > MAX_BATCH_ENTRIES {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "a sweep batch processes 1..={MAX_BATCH_ENTRIES} entries, not {}",
                req.max_batch
            ),
            "registries/limits.toml max_batch_entries (plan §5.4)",
            format!("choose a batch size between 1 and {MAX_BATCH_ENTRIES}"),
        )));
    }
    let system = crate::rows::system_principal(book.book_id);
    if req.capability.profile() != Profile::System || req.principal_ref != system {
        return Ok(Err(Refusal::new(
            code::CAPABILITY,
            exit::SAFETY,
            format!(
                "the sweep runs as the book's System principal {:032x}; this request is principal {:032x} under a {} capability",
                system.0,
                req.principal_ref.0,
                req.capability.profile().name()
            ),
            "plan §5.4 (the sweep runs as the System principal), sod_policy.toml expiry-sweep / reversal-sweep",
            "run the sweep from the daemon (its System capability); a person releases a hold with Resolution(Voids) or reverses an entry by hand",
        )));
    }
    let Some(op) = policy::steward()?.preparer_op(key) else {
        return Err(KernelError::Corrupt(format!(
            "sod_policy.toml has no rule for {key:?}"
        )));
    };
    for op in [op, Op::Post] {
        if let Err(d) = fa_policy::admit(
            &req.capability,
            &Intent {
                principal: req.principal_ref,
                trunk: true,
                op,
                legs: &[],
            },
        ) {
            return Ok(Err(policy::refusal(&d)));
        }
    }
    if let Err(d) = fa_policy::current(&req.capability, db.frontier()?) {
        return Ok(Err(policy::refusal(&d)));
    }
    Ok(Ok(()))
}

/// Expire up to `req.max_batch` due holds in one transaction (plan §5.4).
/// `Ok(None)`: no tick yet, or nothing due after the cursor — nothing is
/// written. `describe` seals each new entry's description (the kernel holds
/// no entropy). Refusals: a batch bound outside `1..=max_batch_entries`, a
/// capability that is not the `System` principal's or lacks `post`, an
/// expired capability, or a conflict (a hold resolved concurrently — its
/// identity was taken — or a witness moved): rerun the sweep.
pub async fn sweep_batch<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    req: &SweepRequest,
    describe: &mut dyn FnMut(&str) -> Erasable<String>,
) -> Outcome<Option<SweepBatch>> {
    let sweep_key = fa_policy::sod::control_key("SweepControl", None, "Expire");
    if let Err(r) = admit_sweep(db, book, req, &sweep_key)? {
        return Ok(Err(r));
    }

    // The candidates, from the head snapshot this single-writer handle is
    // about to open its transaction on; each is re-read as a witness below.
    let Some(tick) = latest_tick(db)? else {
        return Ok(Ok(None));
    };
    let root = root_row(db, None)?.ok_or_else(|| KernelError::Corrupt("no book root".into()))?;
    let cursor = Cursor::from_scalar(prop(&root, property::SWEEP_CURSOR))?;
    let mut due = due_holds(db, Some(tick))?;
    if let Some(c) = cursor
        && c.tick == tick.entry
    {
        let last = db.vertex(c.last_pending)?.ok_or_else(|| {
            KernelError::Corrupt(format!(
                "the sweep cursor names hold {:032x}, which is missing",
                c.last_pending.0
            ))
        })?;
        let at = (last.created_at, c.last_pending);
        due.retain(|d| (d.recorded_at, d.hold.vid) > at);
    }
    if due.is_empty() {
        return Ok(Ok(None));
    }
    let take = due.len().min(req.max_batch);
    let remaining_due = due.len() - take;
    due.truncate(take);

    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    let (_, witnessed_tick) = tick_witness(&txn, db)?;
    if witnessed_tick != Some(tick) {
        txn.abort();
        return Ok(Err(conflict("the sweep's tick", "a tick committed")));
    }
    let witnessed_cursor = txn.vertex_property(db, book_root(), property::SWEEP_CURSOR)?;
    let epoch = policy::epoch_witness(&txn, db)?;
    let tick_row = txn
        .vertex(db, tick.entry)?
        .ok_or_else(|| KernelError::Corrupt("the latest tick's entry is missing".into()))?;
    let tick_digest = decode_entry(&tick_row)?.entry_digest;
    let classes = EntryClasses::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let matrix =
        Admissibility::embedded(&classes).map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let preparer = Party {
        principal: req.principal_ref,
        profile: req.capability.profile(),
    };

    let mut accounts: BTreeMap<VId, AccountRow> = BTreeMap::new();
    let mut cells: BTreeMap<VId, CellRun> = BTreeMap::new();
    let mut entries = WriteBatch::new(relation::IN_PERIOD);
    let mut resolves = WriteBatch::new(relation::RESOLVES);
    let mut expired = Vec::with_capacity(due.len());
    for d in &due {
        let hold_vid = d.hold.vid;
        let row = txn
            .vertex(db, hold_vid)?
            .ok_or_else(|| KernelError::Corrupt("a due hold is missing".into()))?;
        let hold = decode_entry(&row)?;
        if hold.entry_digest != d.hold.entry_digest || hold.proposal.class != EntryClass::PENDING {
            return Err(KernelError::Corrupt(format!(
                "due hold {:032x} changed under the sweep",
                hold_vid.0
            )));
        }
        let rvid = resolution_vid(hold_vid);
        if txn.vertex(db, rvid)?.is_some() {
            txn.abort();
            return Ok(Err(conflict(
                "the sweep batch",
                format!("hold {:032x} was resolved", hold_vid.0),
            )));
        }
        // Period law for the release, in the hold's own period: Appendix C
        // admits Voids/Expires in every state but Future.
        let period = limit::period_code(book, &hold.proposal)?;
        let pvid = period_vid(&book.calendar.id, &period);
        let state_scalar = txn.vertex_property(db, pvid, property::STATE)?;
        let state = state_from_scalar(state_scalar.as_ref())
            .ok_or_else(|| KernelError::Corrupt(format!("period `{period}` state mirror")))?;
        if let Err(r) = expires_admissible(&matrix, state, &period, &req.capability) {
            txn.abort();
            return Ok(Err(r));
        }
        let proposal = expires_proposal(
            book,
            req.principal_ref,
            &hold,
            hold_vid,
            tick,
            tick_digest,
            describe(&format!(
                "expired by the sweep at tick {} ns (deadline {} ns)",
                tick.observed_utc_ns, d.deadline_ns
            )),
        );
        if let Err(r) = policy::authorize_approvals(
            &txn,
            db,
            book,
            &[],
            &proposal.proposal_digest()?,
            epoch,
            &fa_policy::sod::posting_key("Resolution", state, false),
            0,
            preparer,
        )? {
            txn.abort();
            return Ok(Err(r));
        }
        release_hold(&txn, db, &mut accounts, &mut cells, &hold.proposal, &period)?;
        let entry = proposal.seal(Vec::new(), None)?;
        entries.create_vertex(rvid, vec![label::ENTRY], entry_mirrors(&entry)?);
        entries.add_edge(edge_id(relation::IN_PERIOD, rvid, pvid), rvid, pvid, vec![]);
        resolves.add_edge(
            edge_id(relation::RESOLVES, rvid, hold_vid),
            rvid,
            hold_vid,
            vec![(property::DISPOSITION, CanonicalScalar::Int(2))],
        );
        expired.push((d.hold, entry.entry_ref(rvid)));
    }

    let last = due
        .last()
        .map(|d| d.hold.vid)
        .ok_or_else(|| KernelError::Corrupt("an empty sweep batch".into()))?;
    let next = Cursor {
        tick: tick.entry,
        last_pending: last,
    };
    let cvid = sweep_cursor_vid(tick.entry, last);
    if txn.vertex(db, cvid)?.is_some() {
        txn.abort();
        return Ok(Err(conflict(
            "the sweep batch",
            "its cursor is already journaled",
        )));
    }
    let cursor_entry = cursor_proposal(
        book,
        req.principal_ref,
        SWEEP_EXPIRY,
        next,
        cvid,
        tick,
        tick_digest,
        describe(&format!(
            "expiry sweep at tick {} ns: {} expired, {remaining_due} due after this batch",
            tick.observed_utc_ns,
            expired.len()
        )),
    )?;
    if let Err(r) = policy::authorize_approvals(
        &txn,
        db,
        book,
        &[],
        &cursor_entry.proposal_digest()?,
        epoch,
        &sweep_key,
        0,
        preparer,
    )? {
        txn.abort();
        return Ok(Err(r));
    }
    let cursor_entry = cursor_entry.seal(Vec::new(), None)?;
    entries.create_vertex(cvid, vec![label::ENTRY], entry_mirrors(&cursor_entry)?);
    for (cell, run) in &cells {
        run.before.stage(&run.after, *cell, &mut entries)?;
    }
    entries.compare_and_set_vertex_property(
        book_root(),
        property::SWEEP_CURSOR,
        witnessed_cursor,
        next.scalar()?,
        WriteMismatchPolicy::AbortWrite,
    );
    txn.write_ordered(db, vec![entries, resolves])?;
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(Some(SweepBatch {
            tick,
            expired,
            cursor_entry: cursor_entry.entry_ref(cvid),
            recorded_at: seq,
            remaining_due,
        }))),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(conflict("a witness of this sweep batch", detail)))
        }
        Err(WriteTxnError::Write(fgdb::WriteError::CompareAndSetMismatch(_))) => Ok(Err(conflict(
            "this sweep batch",
            "the cursor or a limit cell moved",
        ))),
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => Ok(Err(Refusal::new(
            code::CONFLICT,
            exit::CONFLICT,
            "a hold in this sweep batch was resolved concurrently (one resolution per hold, by identity)",
            "plan §5.4 (a manual void racing the sweep is an AlreadyLive point conflict)",
            "rerun the sweep; the resolved hold is no longer due",
        ))),
        Err(e) => Err(e.into()),
    }
}

/// What one full sweep committed: the expiry batches, then the
/// scheduled-reversal batches.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Swept {
    pub expiry: Vec<SweepBatch>,
    pub reversals: Vec<crate::schedule::ReversalBatch>,
}

/// Sweep until nothing remains under the latest tick: expiry batches (plan
/// §5.4), then scheduled-reversal batches (§7.6), each batch at most
/// `req.max_batch` and its own transaction. A refusal stops the sweep; the
/// batches committed before it stay journaled.
pub async fn sweep<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    req: &SweepRequest,
    describe: &mut dyn FnMut(&str) -> Erasable<String>,
) -> Outcome<Swept> {
    let mut out = Swept::default();
    loop {
        match sweep_batch(db, ctx, book, req, describe).await? {
            Err(r) => return Ok(Err(r)),
            Ok(None) => break,
            Ok(Some(batch)) => {
                let done = batch.remaining_due == 0;
                out.expiry.push(batch);
                if done {
                    break;
                }
            }
        }
    }
    loop {
        match crate::schedule::sweep_reversals_batch(db, ctx, book, req, describe).await? {
            Err(r) => return Ok(Err(r)),
            Ok(None) => return Ok(Ok(out)),
            Ok(Some(batch)) => {
                let done = batch.remaining == 0;
                out.reversals.push(batch);
                if done {
                    return Ok(Ok(out));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_and_cursor_scalars_round_trip_and_reject_bad_widths() {
        let t = Tick {
            observed_utc_ns: u64::MAX - 7,
            entry: VId(0x0123_4567_89ab_cdef_0011_2233_4455_6677),
        };
        let s = t.scalar().expect("scalar");
        assert_eq!(Tick::from_scalar(Some(&s)).expect("decode"), Some(t));
        assert_eq!(Tick::from_scalar(None).expect("absent"), None);
        let short = scalar_bytes("latest_tick", vec![0; 23]).expect("scalar");
        assert!(Tick::from_scalar(Some(&short)).is_err());
        assert!(Tick::from_scalar(Some(&CanonicalScalar::Int(1))).is_err());
        let c = Cursor {
            tick: VId(9),
            last_pending: VId(u128::MAX),
        };
        let s = c.scalar().expect("scalar");
        assert_eq!(Cursor::from_scalar(Some(&s)).expect("decode"), Some(c));
        let long = scalar_bytes("sweep_cursor", vec![0; 33]).expect("scalar");
        assert!(Cursor::from_scalar(Some(&long)).is_err());
    }

    /// The sweep's period law is the registered `Resolution(Expires)` rows:
    /// the embedded matrix admits every state but Future, and a planted
    /// matrix whose Locked row refuses refuses the sweep there (no bypass).
    #[test]
    fn the_sweep_obeys_the_registered_expires_rows() {
        use fa_time::PeriodState;
        let classes = EntryClasses::embedded().expect("classes");
        let cap = Capability::new(VId(1), Profile::System, &[Op::Post], VId(1)).expect("cap");
        let embedded = Admissibility::embedded(&classes).expect("matrix");
        for s in [
            PeriodState::Open,
            PeriodState::SoftClosed,
            PeriodState::Closed,
            PeriodState::Locked,
        ] {
            assert!(expires_admissible(&embedded, s, "P", &cap).is_ok(), "{s:?}");
        }
        let r = expires_admissible(&embedded, PeriodState::Future, "P", &cap).expect_err("Future");
        assert_eq!((r.code, r.exit), (code::PERIOD_LAW, exit::SAFETY));
        let text = include_str!("../../../registries/admissibility.toml");
        let locked = "state = \"Locked\"\ndecision = \"admit\"\nnote = \"a reservation release";
        assert_eq!(text.matches(locked).count(), 1, "the Locked Expires row");
        let planted = Admissibility::parse(
            &classes,
            &text.replace(
                locked,
                "state = \"Locked\"\ndecision = \"refuse\"\nnote = \"a reservation release",
            ),
        )
        .expect("planted matrix");
        let r = expires_admissible(&planted, PeriodState::Locked, "FY2026-P03", &cap)
            .expect_err("the row refuses");
        assert_eq!((r.code, r.exit), (code::PERIOD_LAW, exit::SAFETY));
        assert!(r.cite.contains("Resolution(Expires), Locked"), "{r}");
        assert!(expires_admissible(&planted, PeriodState::Closed, "P", &cap).is_ok());
    }

    #[test]
    fn utc_day_is_the_civil_day_of_the_instant() {
        assert_eq!(utc_day(0).expect("day"), DateDay(0));
        assert_eq!(utc_day(NS_PER_DAY - 1).expect("day"), DateDay(0));
        assert_eq!(utc_day(NS_PER_DAY).expect("day"), DateDay(1));
        assert_eq!(
            utc_day(u64::MAX).expect("day"),
            DateDay(i32::try_from(u64::MAX / NS_PER_DAY).expect("fits"))
        );
    }
}
