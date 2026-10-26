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

use std::collections::btree_map::Entry as MapEntry;
use std::collections::{BTreeMap, BTreeSet};

use fa_model::limits::{MAX_BATCH_ENTRIES, MAX_CLOCK_SKEW_NS};
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ControlPayload, Disposition, Entry, EntryClass, EntryOrigin, EntryPayload, EntryRef, Erasable,
    Id128, Oid, Pending, Reader, SupersessionKind, Writer, entry_mirrors, entry_vid, period_vid,
};
use fa_money::Side;
use fa_policy::{Intent, Party};
/// The capability vocabulary a sweep request is built from (the sweep's
/// capability is a `Profile::System` one holding `Op::Post`).
pub use fa_policy::{Op, Profile};
use fa_registry::{Admissibility, Decision, EntryClasses};
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxn, WriteTxnError};
use fgdb_crypto::Hasher;
use fgdb_delta_types::{DeltaRow, IndexError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::genesis::BookContext;
use crate::limit::{self, LimitCell, LimitScope, Movement};
use crate::policy;
use crate::post::{Capability, Identity, Posted, recorded_or_conflict};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{
    AccountRow, book_root, bytes, edge_id, prop, resolution_vid, reversal_vid, scalar_bytes,
    state_from_scalar, sweep_cursor_vid, sweep_index_page_vid, sweep_index_vid,
};

/// Fixed page size for the disposable `SweepIndex` (FA-CFG-02).
pub const SWEEP_INDEX_PAGE_SIZE: usize = 64;

const SWEEP_INDEX_MAGIC: &[u8; 4] = b"FASI";
const SWEEP_INDEX_PAGE_MAGIC: &[u8; 4] = b"FASP";
const SWEEP_INDEX_VERSION: u16 = 1;

/// `TimeEvidence.source`: the daemon's clock (plan §7.1a). The only source
/// this slice admits; `AuthorityDocument` and `SubstrateMarker` land with
/// their evidence rules (Appendix H R-HLC).
pub const SOURCE_DAEMON_CLOCK: u8 = 0;

/// `SweepCursor.sweep_kind` / `EntryOrigin::Sweep.sweep_kind`: the expiry
/// sweep (scheduled reversals take the next kind).
pub const SWEEP_EXPIRY: u8 = 1;

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

    pub(crate) fn from_scalar(s: Option<&CanonicalScalar>) -> Result<Option<Self>, KernelError> {
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

/// The latest committed tick at head (or at `at`) whose `TimeControl` entry
/// carries `monotonic_ok = true` (fa-psz).
pub fn latest_corroborated_tick<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    at: Option<CommitSeq>,
) -> Result<Option<Tick>, KernelError> {
    let latest = match root_row(db, at)? {
        Some(row) => Tick::from_scalar(prop(&row, property::LATEST_TICK))?,
        None => return Ok(None),
    };
    let Some(latest) = latest else {
        return Ok(None);
    };
    let latest_row = match at {
        None => db.vertex(latest.entry)?,
        Some(seq) => db.vertex_at(latest.entry, seq)?,
    }
    .ok_or_else(|| KernelError::Corrupt("the latest tick's entry is missing".into()))?;
    if tick_corroborated(&latest_row)? {
        return Ok(Some(latest));
    }
    if at.is_none()
        && let Ok(Some(tick)) = indexed_latest_corroborated_tick(db)
    {
        return Ok(tick);
    }
    let rows = match at {
        None => db.vertices()?,
        Some(seq) => db.vertices_at(seq)?,
    };
    let mut best: Option<(CommitSeq, Tick)> = None;
    for row in rows {
        if !row.labels.contains(&label::ENTRY)
            || prop(&row, property::CLASS)
                != Some(&CanonicalScalar::Int(i64::from(EntryClass::TIME_CONTROL.0)))
        {
            continue;
        }
        let entry = decode_entry(&row)?;
        if let Some(ControlPayload::TimeTick {
            observed_utc_ns,
            monotonic_ok: true,
            ..
        }) = entry.proposal.control
        {
            let candidate = (
                row.created_at,
                Tick {
                    observed_utc_ns,
                    entry: row.vid,
                },
            );
            if best.is_none_or(|(seq, t)| (candidate.0, candidate.1.entry) > (seq, t.entry)) {
                best = Some(candidate);
            }
        }
    }
    Ok(best.map(|(_, t)| t))
}

/// The latest corroborated tick in the committed prefix strictly before `seq`
/// (falling back to the latest tick only when no corroborated tick exists yet
/// in that prefix): the anchor of a timed hold committed at `seq` (plan §5.4).
pub fn tick_before<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    seq: CommitSeq,
) -> Result<Option<Tick>, KernelError> {
    let Some(prev) = seq.0.checked_sub(1) else {
        return Ok(None);
    };
    let at = Some(CommitSeq(prev));
    if let Some(corroborated) = latest_corroborated_tick(db, at)? {
        return Ok(Some(corroborated));
    }
    match root_row(db, at)? {
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

/// Whether the tick journaled in `row` (its `TimeControl` entry) was
/// corroborated by its source's monotonic clock: its TimeTick payload's
/// `monotonic_ok`. Entries are immutable, so a witness that the tick is
/// still the latest keeps this answer current.
pub(crate) fn tick_corroborated(row: &VertexRow) -> Result<bool, KernelError> {
    match decode_entry(row)?.proposal.control {
        Some(ControlPayload::TimeTick { monotonic_ok, .. }) => Ok(monotonic_ok),
        other => Err(KernelError::Corrupt(format!(
            "tick entry {:032x} carries {other:?}, not a TimeTick",
            row.vid.0
        ))),
    }
}

fn effective_monotonic_ok(
    observed_utc_ns: u64,
    requested_monotonic_ok: bool,
    prev_anchor: Option<Tick>,
) -> bool {
    if !requested_monotonic_ok {
        return false;
    }
    match prev_anchor {
        Some(prev) if observed_utc_ns > prev.observed_utc_ns => {
            observed_utc_ns.saturating_sub(prev.observed_utc_ns) <= MAX_CLOCK_SKEW_NS
        }
        _ => true,
    }
}

/// **Automatic effects take time only from a corroborated committed tick**
/// (CobaltGull 3599; WhiteCreek 3579, 3602). The expiry sweep, the
/// scheduled-reversal sweep and an `Open`'s scheduled reversals (plan §7.6
/// rule (b)) act on the book's latest tick only when its TimeTick payload
/// records that its source's monotonic clock corroborated it; otherwise the
/// sweeps refuse (FA-REF-144) and the `Open` reaches no date. It is one
/// kernel rule for every caller (the library, the daemon, a period
/// transition), not a policy one caller holds, and it claims committed-tick
/// semantics only: nothing about how an observed instant relates to true
/// UTC. (A remark under assumptions, not a guarantee: given a trusted,
/// calibrated initial UTC baseline and bounded drift, a reading that fell
/// behind its monotonic clock could not be early. The rule relies on no
/// such assumption.)
pub(crate) fn uncorroborated(tick: Tick) -> Refusal {
    Refusal::new(
        code::TICK_UNCORROBORATED,
        exit::REFUSAL,
        format!(
            "the latest TimeEvidence tick ({} ns, entry {:032x}) was not corroborated by its source's monotonic clock (monotonic_ok false); automatic effects take time only from a corroborated tick",
            tick.observed_utc_ns, tick.entry.0
        ),
        "plan §5.4, §7.1a, §7.6 (automatic effects take time only from a corroborated committed tick)",
        "journal a newer TimeEvidence tick that its source's monotonic clock corroborates (Book::record_tick or AsyncBook::record_tick with monotonic_ok true, by the caller that holds the clock), then rerun the sweep under it (Book::sweep or AsyncBook::sweep)",
    )
}

/// The automatic-effects rule for `tick`, the book's latest at head: a
/// sweep's transaction then witnesses that it is still the latest.
pub(crate) fn corroborated_at_head<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    tick: Tick,
) -> Outcome<()> {
    let row = db
        .vertex(tick.entry)?
        .ok_or_else(|| KernelError::Corrupt("the latest tick's entry is missing".into()))?;
    if tick_corroborated(&row)? {
        Ok(Ok(()))
    } else {
        Ok(Err(uncorroborated(tick)))
    }
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

/// Witness of the substrate reads performed during a sweep discovery or
/// batch cycle (plan §5.4, §7.6, FA-CFG-02).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SweepReadWitness {
    /// Whether a servable `SweepIndex` root was used.
    pub used_index: bool,
    /// Number of `SweepIndex` page vertices read.
    pub pages_read: usize,
    /// Number of due candidate holds/schedules inspected from read pages.
    pub candidates_read: usize,
    /// Total substrate vertex / property point reads plus any full-scan rows.
    pub substrate_rows_read: usize,
    /// Number of delta batches after the index cursor examined.
    pub delta_batches_read: usize,
    /// Number of unrelated (non-Pending/Resolution/TimeControl/Reversal)
    /// `Entry` payloads decoded.
    pub unrelated_entries_decoded: usize,
}

/// One unresolved timed hold stored in a `SweepIndex` hold page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedHold {
    pub hold: EntryRef,
    pub recorded_at: CommitSeq,
    pub deadline_ns: u64,
}

/// Metadata for one page of the disposable `SweepIndex`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SweepIndexPageMeta {
    pub page: u32,
    pub min_key: i128,
    pub max_key: i128,
    pub count: u32,
    pub digest: [u8; 32],
}

/// Disposable root state of the paged `SweepIndex` (FA-CFG-02).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SweepIndexState {
    pub book_id: Id128,
    pub through: CommitSeq,
    pub latest_corroborated_tick: Option<(CommitSeq, Tick)>,
    pub hold_pages: Vec<SweepIndexPageMeta>,
    pub schedule_pages: Vec<SweepIndexPageMeta>,
}

/// Result of refolding and verifying the disposable `SweepIndex` against
/// the authoritative journal (FA-CFG-02).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SweepIndexVerification {
    pub index_present: bool,
    pub through: Option<CommitSeq>,
    pub holds_checked: usize,
    pub schedules_checked: usize,
    pub pages_checked: usize,
    pub drift: Vec<String>,
}

impl SweepIndexVerification {
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.drift.is_empty()
    }
}

/// Every unresolved timed hold that `at` (the latest tick when `None`) has
/// made due, in the holds' commit order — the backlog `fa triage` reports
/// as `due` (plan §5.4, FA-CFG-02). Uses the paged `SweepIndex` plus any
/// committed delta tail when available, falling back to a snapshot scan
/// when no servable index is present; the sweep re-reads each candidate as
/// a point witness inside its transaction.
pub fn due_holds<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    at: Option<Tick>,
) -> Result<Vec<DueHold>, KernelError> {
    Ok(due_holds_with_witness(db, at)?.0)
}

/// [`due_holds`] together with a [`SweepReadWitness`] recording the
/// substrate reads performed during candidate discovery (FA-CFG-02).
pub fn due_holds_with_witness<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    at: Option<Tick>,
) -> Result<(Vec<DueHold>, SweepReadWitness), KernelError> {
    let mut witness = SweepReadWitness::default();
    let at = match at {
        Some(t) => Some(t),
        None => {
            witness.substrate_rows_read += 1;
            latest_tick(db)?
        }
    };
    let Some(at) = at else {
        return Ok((Vec::new(), witness));
    };
    if let Ok(Some((due, indexed_witness))) = indexed_due_holds(db, at) {
        witness.used_index = true;
        witness.pages_read += indexed_witness.pages_read;
        witness.candidates_read += indexed_witness.candidates_read;
        witness.substrate_rows_read += indexed_witness.substrate_rows_read;
        witness.delta_batches_read += indexed_witness.delta_batches_read;
        witness.unrelated_entries_decoded += indexed_witness.unrelated_entries_decoded;
        return Ok((due, witness));
    }
    let rows = db.vertices()?;
    witness.substrate_rows_read += rows.len();
    let mut due = Vec::new();
    for row in rows {
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
        witness.candidates_read += 1;
        witness.substrate_rows_read += 1;
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
    Ok((due, witness))
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
            control_kind: fa_model::ControlKind::TIME_TICK,
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
/// strictly exceed the book's latest corroborated tick (or the latest
/// uncorroborated tick when recording another uncorroborated tick with no
/// corroborated tick yet, FA-REF-094). An observation jumping beyond the
/// previous anchor by more than `max_clock_skew_ns` is recorded with
/// `monotonic_ok = false` (fa-psz).
pub async fn record_tick<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    mut req: TickRequest,
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
    let initial_proposal = tick_proposal(book, &req);
    if let Err(e) = initial_proposal.validate() {
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
            book: book.book_id,
            legs: &[],
        },
    ) {
        return Ok(Err(policy::refusal(&d)));
    }
    if let Err(d) = fa_policy::current(&req.capability, db.frontier()?) {
        return Ok(Err(policy::refusal(&d)));
    }
    if let Err(refusal) = policy::capability_admitted(db, book, &req.capability)? {
        return Ok(Err(refusal));
    }
    // Reopened books may need their retained native history hydrated to
    // authenticate recovered outcome coverage. Admission precedes that read.
    if let Err(refusal) = crate::scratch::ensure_history(db, ctx).await? {
        return Ok(Err(refusal));
    }
    let prev_corroborated = latest_corroborated_tick(db, None)?;
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    // Not revoked (plan §14.2): the first read, before the identity.
    if let Err(r) = policy::capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let evid = entry_vid(
        book.book_id,
        &req.principal_ref.0.to_le_bytes(),
        &req.idempotency_key,
    );
    // TimeEvidence shares the same scoped key as postings and atomic batches.
    // A target-derived reversal/resolution or an outer batch can reserve this
    // key without creating the ordinary Entry identity checked below.
    if let Err(refusal) = crate::outcome::witness_named_key(
        &txn,
        db,
        book.book_id,
        req.principal_ref,
        &req.idempotency_key,
        evid,
    )? {
        txn.abort();
        return Ok(Err(refusal));
    }
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return recorded_tick(db, &row, &req, book);
    }
    // An exact legacy retry above remains readable. A new tick must prove
    // that an old target-derived posting did not already consume its key.
    if let Err(refusal) = crate::outcome::require_unused_legacy_key(
        &txn,
        db,
        book,
        crate::outcome::entry_outcome_vid(&initial_proposal),
    )? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let (witnessed, latest) = tick_witness(&txn, db)?;
    if let Some(corr) = prev_corroborated
        && Some(corr) != latest
    {
        let _ = txn.vertex(db, corr.entry)?;
    }
    req.monotonic_ok = effective_monotonic_ok(
        req.observed_utc_ns,
        req.monotonic_ok,
        prev_corroborated.or(latest),
    );
    let baseline = prev_corroborated.or(if req.monotonic_ok { None } else { latest });
    if let Some(prev) = baseline
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
    let proposal = tick_proposal(book, &req);
    let proposal_digest = proposal.proposal_digest()?;
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
    crate::outcome::stage_control(&mut batch, &entry, evid)?;
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
            Some(row) => recorded_tick(db, &row, &req, book),
            None if db
                .vertex(crate::outcome::entry_outcome_vid(&initial_proposal))?
                .is_some() =>
            {
                Ok(Err(crate::outcome::key_conflict()))
            }
            None => Err(KernelError::Corrupt(
                "identity spent but no live row".into(),
            )),
        },
        Err(e) => Err(e.into()),
    }
}

/// The recorded outcome of the tick at `row`, or a conflict.
fn recorded_tick<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    row: &VertexRow,
    req: &TickRequest,
    book: &BookContext,
) -> Outcome<Ticked> {
    let mut adjusted = req.clone();
    let prev_anchor = tick_before(db, row.created_at)?;
    adjusted.monotonic_ok =
        effective_monotonic_ok(req.observed_utc_ns, req.monotonic_ok, prev_anchor);
    let proposal = tick_proposal(book, &adjusted);
    match recorded_or_conflict(row, &proposal, &book.seal_key, Identity::Key)? {
        Err(r) => Ok(Err(r)),
        Ok(posted) => {
            let stored = decode_entry(row)?;
            if !crate::outcome::verify_control_recorded(db, row, &stored)? {
                return Ok(Err(crate::outcome::key_conflict()));
            }
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

/// How a sweep seals each description it writes (the kernel holds no
/// entropy). `Send`, so a sweep's future is too: the daemon's scheduler
/// awaits it as a task of its own runtime, or of the lab's (bead fa-ffo).
pub type Describe<'a> = dyn FnMut(&str) -> Result<Erasable<String>, KernelError> + Send + 'a;

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
                book: book.book_id,
                legs: &[],
            },
        ) {
            return Ok(Err(policy::refusal(&d)));
        }
    }
    if let Err(d) = fa_policy::current(&req.capability, db.frontier()?) {
        return Ok(Err(policy::refusal(&d)));
    }
    // Not revoked, before the candidate scan reads the head; each batch
    // re-reads it as the first witness of its transaction.
    policy::capability_admitted(db, book, &req.capability)
}

/// Expire up to `req.max_batch` due holds in one transaction (plan §5.4).
/// `Ok(None)`: no tick yet, or nothing due after the cursor — nothing is
/// written. `describe` seals each new entry's description (the kernel holds
/// no entropy); when it fails, the open transaction is aborted and its
/// error returned — nothing is committed, the cursor does not move, and a
/// rerun sweeps the same holds. Refusals: a batch bound outside `1..=max_batch_entries`, a
/// capability that is not the `System` principal's or lacks `post`, an
/// expired capability, a latest tick its source's monotonic clock did not
/// corroborate (FA-REF-144, [`corroborated_at_head`]), or a conflict (a hold
/// resolved concurrently — its identity was taken — or a witness moved):
/// rerun the sweep.
pub async fn sweep_batch<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    req: &SweepRequest,
    describe: &mut Describe<'_>,
) -> Outcome<Option<SweepBatch>> {
    match sweep_batch_with_witness(db, ctx, book, req, describe).await? {
        Ok((batch, _)) => Ok(Ok(batch)),
        Err(r) => Ok(Err(r)),
    }
}

/// [`sweep_batch`] together with a [`SweepReadWitness`] recording the
/// substrate reads performed during candidate discovery and witness
/// validation (FA-CFG-02).
pub async fn sweep_batch_with_witness<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    req: &SweepRequest,
    describe: &mut Describe<'_>,
) -> Outcome<(Option<SweepBatch>, SweepReadWitness)> {
    let mut witness = SweepReadWitness::default();
    let sweep_key = fa_policy::sod::control_key("SweepControl", None, "Expire");
    if let Err(r) = admit_sweep(db, book, req, &sweep_key)? {
        return Ok(Err(r));
    }
    witness.substrate_rows_read += 1;

    // The candidates, from the head snapshot this single-writer handle is
    // about to open its transaction on; each is re-read as a witness below.
    witness.substrate_rows_read += 1;
    let Some(tick) = latest_tick(db)? else {
        return Ok(Ok((None, witness)));
    };
    // Automatic effects take time only from a corroborated committed tick;
    // the transaction below witnesses that this tick is still the latest.
    witness.substrate_rows_read += 1;
    if let Err(r) = corroborated_at_head(db, tick)? {
        return Ok(Err(r));
    }
    witness.substrate_rows_read += 1;
    let root = root_row(db, None)?.ok_or_else(|| KernelError::Corrupt("no book root".into()))?;
    let cursor = Cursor::from_scalar(prop(&root, property::SWEEP_CURSOR))?;
    let (mut due, due_witness) = due_holds_with_witness(db, Some(tick))?;
    witness.used_index = due_witness.used_index;
    witness.pages_read += due_witness.pages_read;
    witness.candidates_read += due_witness.candidates_read;
    witness.substrate_rows_read += due_witness.substrate_rows_read;
    witness.delta_batches_read += due_witness.delta_batches_read;
    witness.unrelated_entries_decoded += due_witness.unrelated_entries_decoded;
    if let Some(c) = cursor
        && c.tick == tick.entry
    {
        witness.substrate_rows_read += 1;
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
        return Ok(Ok((None, witness)));
    }
    let take = due.len().min(req.max_batch);
    let remaining_due = due.len() - take;
    due.truncate(take);

    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    witness.substrate_rows_read += 1;
    if let Err(r) = policy::capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    witness.substrate_rows_read += 1;
    let (_, witnessed_tick) = tick_witness(&txn, db)?;
    if witnessed_tick != Some(tick) {
        txn.abort();
        return Ok(Err(conflict("the sweep's tick", "a tick committed")));
    }
    witness.substrate_rows_read += 1;
    let witnessed_cursor = txn.vertex_property(db, book_root(), property::SWEEP_CURSOR)?;
    witness.substrate_rows_read += 1;
    let epoch = policy::epoch_witness(&txn, db)?;
    witness.substrate_rows_read += 1;
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
        witness.substrate_rows_read += 1;
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
        witness.substrate_rows_read += 1;
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
        witness.substrate_rows_read += 1;
        let state_scalar = txn.vertex_property(db, pvid, property::STATE)?;
        let state = state_from_scalar(state_scalar.as_ref())
            .ok_or_else(|| KernelError::Corrupt(format!("period `{period}` state mirror")))?;
        if let Err(r) = expires_admissible(&matrix, state, &period, &req.capability) {
            txn.abort();
            return Ok(Err(r));
        }
        let description = match describe(&format!(
            "expired by the sweep at tick {} ns (deadline {} ns)",
            tick.observed_utc_ns, d.deadline_ns
        )) {
            Ok(sealed) => sealed,
            Err(e) => {
                txn.abort();
                return Err(e);
            }
        };
        let proposal = expires_proposal(
            book,
            req.principal_ref,
            &hold,
            hold_vid,
            tick,
            tick_digest,
            description,
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
        witness.substrate_rows_read += 1;
        if let Err(refusal) = crate::outcome::require_fresh_key(&txn, db, book, &proposal, rvid)? {
            txn.abort();
            return Ok(Err(refusal));
        }
        release_hold(&txn, db, &mut accounts, &mut cells, &hold.proposal, &period)?;
        let entry = proposal.seal(Vec::new(), None)?;
        entries.create_vertex(rvid, vec![label::ENTRY], entry_mirrors(&entry)?);
        crate::outcome::stage_entry(&mut entries, &entry, rvid)?;
        entries.add_edge(edge_id(relation::IN_PERIOD, rvid, pvid), rvid, pvid, vec![]);
        resolves.add_edge(
            edge_id(relation::RESOLVES, rvid, hold_vid),
            rvid,
            hold_vid,
            vec![(property::DISPOSITION, CanonicalScalar::Int(2))],
        );
        expired.push((d.hold, entry.entry_ref(rvid)));
    }
    witness.substrate_rows_read += accounts.len() + cells.len();

    let last = due
        .last()
        .map(|d| d.hold.vid)
        .ok_or_else(|| KernelError::Corrupt("an empty sweep batch".into()))?;
    let next = Cursor {
        tick: tick.entry,
        last_pending: last,
    };
    let cvid = sweep_cursor_vid(tick.entry, last);
    witness.substrate_rows_read += 1;
    if txn.vertex(db, cvid)?.is_some() {
        txn.abort();
        return Ok(Err(conflict(
            "the sweep batch",
            "its cursor is already journaled",
        )));
    }
    let description = match describe(&format!(
        "expiry sweep at tick {} ns: {} expired, {remaining_due} due after this batch",
        tick.observed_utc_ns,
        expired.len()
    )) {
        Ok(sealed) => sealed,
        Err(e) => {
            txn.abort();
            return Err(e);
        }
    };
    let cursor_entry = cursor_proposal(
        book,
        req.principal_ref,
        SWEEP_EXPIRY,
        next,
        cvid,
        tick,
        tick_digest,
        description,
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
        Ok(seq) => Ok(Ok((
            Some(SweepBatch {
                tick,
                expired,
                cursor_entry: cursor_entry.entry_ref(cvid),
                recorded_at: seq,
                remaining_due,
            }),
            witness,
        ))),
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
    pub recurring: Vec<crate::recurring::RecurringBatch>,
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
    describe: &mut Describe<'_>,
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
            Ok(None) => break,
            Ok(Some(batch)) => {
                let done = batch.remaining == 0;
                out.reversals.push(batch);
                if done {
                    break;
                }
            }
        }
    }
    loop {
        match crate::recurring::sweep_recurring_batch(db, ctx, book, req).await? {
            Err(r) => return Ok(Err(r)),
            Ok(None) => return Ok(Ok(out)),
            Ok(Some(batch)) => {
                let more = batch.more;
                out.recurring.push(batch);
                if !more {
                    return Ok(Ok(out));
                }
            }
        }
    }
}

pub(crate) fn sweep_index_digest(book_id: Id128, payload: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"fa:sweep-index-payload:v1");
    h.update(&book_id.0);
    h.update(payload);
    h.finalize().0
}

pub(crate) fn sweep_page_digest(book_id: Id128, kind: u8, page: u32, payload: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"fa:sweep-index-page-payload:v1");
    h.update(&book_id.0);
    h.update(&[kind]);
    h.update(&page.to_le_bytes());
    h.update(payload);
    h.finalize().0
}

pub(crate) fn encode_sweep_index_state(state: &SweepIndexState) -> Result<Vec<u8>, KernelError> {
    let mut w = Writer::new();
    w.fixed(SWEEP_INDEX_MAGIC)
        .u16(SWEEP_INDEX_VERSION)
        .fixed(&state.book_id.0)
        .u64(state.through.0);
    w.opt(state.latest_corroborated_tick.as_ref(), |w, (seq, tick)| {
        w.u64(seq.0).u64(tick.observed_utc_ns).u128(tick.entry.0);
    });
    w.list(&state.hold_pages, |w, m| {
        w.u32(m.page)
            .i128(m.min_key)
            .i128(m.max_key)
            .u32(m.count)
            .fixed(&m.digest);
    });
    w.list(&state.schedule_pages, |w, m| {
        w.u32(m.page)
            .i128(m.min_key)
            .i128(m.max_key)
            .u32(m.count)
            .fixed(&m.digest);
    });
    w.finish().map_err(|e| KernelError::Corrupt(e.to_string()))
}

pub(crate) fn decode_sweep_index_state(payload: &[u8]) -> Result<SweepIndexState, KernelError> {
    let read = || -> Result<SweepIndexState, fa_model::DecodeError> {
        let mut r = Reader::new(payload);
        if &r.fixed::<4>("sweep-index.magic")? != SWEEP_INDEX_MAGIC
            || r.u16("sweep-index.version")? != SWEEP_INDEX_VERSION
        {
            return Err(r.invalid("sweep-index.format"));
        }
        let book_id = Id128(r.fixed::<16>("sweep-index.book_id")?);
        let through = CommitSeq(r.u64("sweep-index.through")?);
        let latest_corroborated_tick = r.opt("sweep-index.latest_corroborated_tick", |r| {
            let seq = CommitSeq(r.u64("sweep-index.tick_seq")?);
            let observed_utc_ns = r.u64("sweep-index.tick_ns")?;
            let entry = VId(r.u128("sweep-index.tick_vid")?);
            Ok((
                seq,
                Tick {
                    observed_utc_ns,
                    entry,
                },
            ))
        })?;
        let read_meta = |r: &mut Reader<'_>| -> Result<SweepIndexPageMeta, fa_model::DecodeError> {
            let page = r.u32("sweep-index.page")?;
            let min_key = r.i128("sweep-index.min_key")?;
            let max_key = r.i128("sweep-index.max_key")?;
            let count = r.u32("sweep-index.count")?;
            let digest = r.fixed::<32>("sweep-index.page_digest")?;
            if count == 0 || count as usize > SWEEP_INDEX_PAGE_SIZE || min_key > max_key {
                return Err(r.invalid("sweep-index.page_meta"));
            }
            Ok(SweepIndexPageMeta {
                page,
                min_key,
                max_key,
                count,
                digest,
            })
        };
        let hold_pages = r.list(
            fa_model::limits::MAX_BATCH_ENTRIES,
            "sweep-index.hold_pages",
            read_meta,
        )?;
        let schedule_pages = r.list(
            fa_model::limits::MAX_BATCH_ENTRIES,
            "sweep-index.schedule_pages",
            read_meta,
        )?;
        r.finish()?;
        Ok(SweepIndexState {
            book_id,
            through,
            latest_corroborated_tick,
            hold_pages,
            schedule_pages,
        })
    };
    read().map_err(|e| KernelError::Corrupt(format!("sweep index state: {e}")))
}

pub(crate) fn encode_hold_page(holds: &[IndexedHold]) -> Result<Vec<u8>, KernelError> {
    let mut w = Writer::new();
    w.fixed(SWEEP_INDEX_PAGE_MAGIC)
        .u16(SWEEP_INDEX_VERSION)
        .u8(SWEEP_EXPIRY);
    w.list(holds, |w, h| {
        w.u128(h.hold.vid.0)
            .fixed(&h.hold.entry_digest)
            .u64(h.recorded_at.0)
            .u64(h.deadline_ns);
    });
    w.finish().map_err(|e| KernelError::Corrupt(e.to_string()))
}

pub(crate) fn decode_hold_page(payload: &[u8]) -> Result<Vec<IndexedHold>, KernelError> {
    let read = || -> Result<Vec<IndexedHold>, fa_model::DecodeError> {
        let mut r = Reader::new(payload);
        if &r.fixed::<4>("sweep-page.magic")? != SWEEP_INDEX_PAGE_MAGIC
            || r.u16("sweep-page.version")? != SWEEP_INDEX_VERSION
            || r.u8("sweep-page.kind")? != SWEEP_EXPIRY
        {
            return Err(r.invalid("sweep-page.format"));
        }
        let holds = r.list(SWEEP_INDEX_PAGE_SIZE, "sweep-page.holds", |r| {
            let vid = VId(r.u128("sweep-page.hold_vid")?);
            let entry_digest = r.fixed::<32>("sweep-page.hold_digest")?;
            let recorded_at = CommitSeq(r.u64("sweep-page.recorded_at")?);
            let deadline_ns = r.u64("sweep-page.deadline_ns")?;
            Ok(IndexedHold {
                hold: EntryRef { vid, entry_digest },
                recorded_at,
                deadline_ns,
            })
        })?;
        r.finish()?;
        Ok(holds)
    };
    read().map_err(|e| KernelError::Corrupt(format!("sweep hold page: {e}")))
}

pub(crate) fn encode_schedule_page(
    schedules: &[crate::schedule::Schedule],
) -> Result<Vec<u8>, KernelError> {
    let mut w = Writer::new();
    w.fixed(SWEEP_INDEX_PAGE_MAGIC)
        .u16(SWEEP_INDEX_VERSION)
        .u8(crate::schedule::SWEEP_REVERSAL);
    w.list(schedules, |w, s| {
        w.u128(s.vid.0)
            .u128(s.target.vid.0)
            .fixed(&s.target.entry_digest)
            .i32(s.reverse_on.0)
            .str(&s.period)
            .str(&s.exec_op)
            .fixed(&s.effects_digest)
            .u64(s.recorded_at.0);
    });
    w.finish().map_err(|e| KernelError::Corrupt(e.to_string()))
}

pub(crate) fn decode_schedule_page(
    payload: &[u8],
) -> Result<Vec<crate::schedule::Schedule>, KernelError> {
    let read = || -> Result<Vec<crate::schedule::Schedule>, fa_model::DecodeError> {
        let mut r = Reader::new(payload);
        if &r.fixed::<4>("sweep-page.magic")? != SWEEP_INDEX_PAGE_MAGIC
            || r.u16("sweep-page.version")? != SWEEP_INDEX_VERSION
            || r.u8("sweep-page.kind")? != crate::schedule::SWEEP_REVERSAL
        {
            return Err(r.invalid("sweep-page.format"));
        }
        let schedules = r.list(SWEEP_INDEX_PAGE_SIZE, "sweep-page.schedules", |r| {
            let vid = VId(r.u128("sweep-page.schedule_vid")?);
            let target_vid = VId(r.u128("sweep-page.target_vid")?);
            let entry_digest = r.fixed::<32>("sweep-page.target_digest")?;
            let reverse_on = DateDay(r.i32("sweep-page.reverse_on")?);
            let period = r.str(64, "sweep-page.period")?.to_string();
            let exec_op = r.str(64, "sweep-page.exec_op")?.to_string();
            let effects_digest = r.fixed::<32>("sweep-page.effects_digest")?;
            let recorded_at = CommitSeq(r.u64("sweep-page.recorded_at")?);
            Ok(crate::schedule::Schedule {
                vid,
                target: EntryRef {
                    vid: target_vid,
                    entry_digest,
                },
                reverse_on,
                period,
                exec_op,
                effects_digest,
                recorded_at,
            })
        })?;
        r.finish()?;
        Ok(schedules)
    };
    read().map_err(|e| KernelError::Corrupt(format!("sweep schedule page: {e}")))
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SweepDeltaTail {
    pub latest_corroborated_tick: Option<(CommitSeq, Tick)>,
    pub added_holds: BTreeMap<VId, IndexedHold>,
    pub resolved_holds: BTreeSet<VId>,
    pub added_schedules: BTreeMap<VId, crate::schedule::Schedule>,
    pub reversed_targets: BTreeSet<VId>,
    pub witness: SweepReadWitness,
}

pub(crate) fn load_servable_sweep_index<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
) -> Result<Option<(SweepIndexState, CanonicalScalar)>, KernelError> {
    let basis = db.frontier()?;
    let Some(row) = db.vertex(sweep_index_vid())? else {
        return Ok(None);
    };
    if row.labels != vec![label::REGISTER_STATE] {
        return Ok(None);
    }
    let Ok(owner) = bytes(&row, property::BOOK_ID, "sweep-index.book") else {
        return Ok(None);
    };
    let Ok(book_id_bytes): Result<[u8; 16], _> = owner.try_into() else {
        return Ok(None);
    };
    let book_id = Id128(book_id_bytes);
    let Ok(payload) = bytes(&row, property::FA_PAYLOAD, "sweep-index.payload") else {
        return Ok(None);
    };
    let Ok(digest) = bytes(&row, property::FA_DIGEST, "sweep-index.digest") else {
        return Ok(None);
    };
    if digest.as_slice() != &sweep_index_digest(book_id, &payload)[..] {
        return Ok(None);
    }
    let Ok(state) = decode_sweep_index_state(&payload) else {
        return Ok(None);
    };
    if state.book_id != book_id || state.through > basis {
        return Ok(None);
    }
    Ok(Some((state, scalar_bytes("sweep-index.payload", payload)?)))
}

fn deadline_with_tracked_tick<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    seq: CommitSeq,
    timeout_ns: u64,
    tracked: Option<(CommitSeq, Tick)>,
) -> Result<u64, KernelError> {
    if let Some((tick_seq, tick)) = tracked
        && tick_seq < seq
    {
        return tick.observed_utc_ns.checked_add(timeout_ns).ok_or_else(|| {
            KernelError::Corrupt(format!(
                "a timed hold committed at {} has a deadline beyond u64",
                seq.0
            ))
        });
    }
    deadline(db, seq, timeout_ns)
}

pub(crate) fn fold_sweep_delta_tail<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    from: CommitSeq,
    initial_tick: Option<(CommitSeq, Tick)>,
) -> Result<Option<SweepDeltaTail>, KernelError> {
    let batches = match db.delta_since(from) {
        Ok(b) => b,
        Err(fgdb::ReadError::DeltaCursorRetired { .. }) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut tail = SweepDeltaTail {
        latest_corroborated_tick: initial_tick,
        ..SweepDeltaTail::default()
    };
    for batch in batches {
        tail.witness.delta_batches_read += 1;
        let seq = batch.commit_seq();
        let mut batch_entries = Vec::new();
        let mut batch_schedules = Vec::new();
        for coordinate in batch.coordinate_entries() {
            for row in &coordinate.rows {
                if let DeltaRow::CreateVertex {
                    vid,
                    labels,
                    props,
                    birth_ordinal,
                    ..
                } = row
                {
                    if labels.contains(&label::REVERSAL_SCHEDULE) {
                        let vrow = VertexRow {
                            vid: *vid,
                            labels: labels.clone(),
                            props: props.clone(),
                            created_at: seq,
                            birth_ordinal: *birth_ordinal,
                            retired_at: None,
                        };
                        batch_schedules.push(crate::schedule::decode_schedule(&vrow)?);
                        continue;
                    }
                    if !labels.contains(&label::ENTRY) {
                        continue;
                    }
                    let class_tag = props.iter().find_map(|(k, v)| {
                        if *k == property::CLASS
                            && let CanonicalScalar::Int(c) = v
                        {
                            u16::try_from(*c).ok()
                        } else {
                            None
                        }
                    });
                    if !matches!(
                        class_tag,
                        Some(c)
                            if c == EntryClass::TIME_CONTROL.0
                                || c == EntryClass::PENDING.0
                                || c == EntryClass::RESOLUTION.0
                                || c == EntryClass::REVERSAL.0
                    ) {
                        continue;
                    }
                    let payload = props
                        .iter()
                        .find_map(|(k, v)| {
                            if *k == property::FA_PAYLOAD
                                && let CanonicalScalar::Bytes(b) = v
                            {
                                Some(b.as_slice())
                            } else {
                                None
                            }
                        })
                        .ok_or_else(|| {
                            KernelError::Corrupt("delta Entry lacks canonical payload".into())
                        })?;
                    let entry = Entry::decode(payload)?;
                    batch_entries.push((*vid, entry));
                }
            }
        }
        batch_entries.sort_by_key(|(vid, _)| vid.0);
        batch_schedules.sort_by_key(|s| s.vid.0);
        for s in batch_schedules {
            tail.added_schedules.insert(s.target.vid, s);
        }
        for (vid, entry) in batch_entries {
            match entry.proposal.class {
                EntryClass::TIME_CONTROL => {
                    if let Some(ControlPayload::TimeTick {
                        observed_utc_ns,
                        monotonic_ok: true,
                        ..
                    }) = entry.proposal.control
                    {
                        let candidate = (
                            seq,
                            Tick {
                                observed_utc_ns,
                                entry: vid,
                            },
                        );
                        if tail
                            .latest_corroborated_tick
                            .is_none_or(|(s, t)| (candidate.0, candidate.1.entry) > (s, t.entry))
                        {
                            tail.latest_corroborated_tick = Some(candidate);
                        }
                    }
                }
                EntryClass::PENDING => {
                    if let Some(Pending {
                        timeout_ns: Some(timeout),
                        ..
                    }) = entry.proposal.pending
                    {
                        let deadline_ns = deadline_with_tracked_tick(
                            db,
                            seq,
                            timeout,
                            tail.latest_corroborated_tick,
                        )?;
                        tail.added_holds.insert(
                            vid,
                            IndexedHold {
                                hold: entry.entry_ref(vid),
                                recorded_at: seq,
                                deadline_ns,
                            },
                        );
                    }
                }
                EntryClass::RESOLUTION => {
                    if let Some(Pending {
                        resolution_of: Some(target),
                        ..
                    }) = entry.proposal.pending
                    {
                        tail.added_holds.remove(&target.vid);
                        tail.resolved_holds.insert(target.vid);
                    }
                }
                EntryClass::REVERSAL => {
                    for sup in &entry.proposal.supersession {
                        if sup.kind == SupersessionKind::Reverses {
                            tail.added_schedules.remove(&sup.target.vid);
                            tail.reversed_targets.insert(sup.target.vid);
                        }
                    }
                }
                _ => {
                    tail.witness.unrelated_entries_decoded += 1;
                }
            }
        }
    }
    Ok(Some(tail))
}

fn indexed_latest_corroborated_tick<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
) -> Result<Option<Option<Tick>>, KernelError> {
    let Some((state, _)) = load_servable_sweep_index(db)? else {
        return Ok(None);
    };
    let Some(tail) = fold_sweep_delta_tail(db, state.through, state.latest_corroborated_tick)?
    else {
        return Ok(None);
    };
    Ok(Some(tail.latest_corroborated_tick.map(|(_, t)| t)))
}

fn read_hold_page_checked<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book_id: Id128,
    meta: &SweepIndexPageMeta,
) -> Result<Option<Vec<IndexedHold>>, KernelError> {
    let Some(row) = db.vertex(sweep_index_page_vid(SWEEP_EXPIRY, meta.page))? else {
        return Ok(None);
    };
    if row.labels != vec![label::REGISTER_STATE] {
        return Ok(None);
    }
    let Ok(owner) = bytes(&row, property::BOOK_ID, "sweep-page.book") else {
        return Ok(None);
    };
    if owner.as_slice() != &book_id.0[..] {
        return Ok(None);
    }
    let Ok(payload) = bytes(&row, property::FA_PAYLOAD, "sweep-page.payload") else {
        return Ok(None);
    };
    let Ok(digest) = bytes(&row, property::FA_DIGEST, "sweep-page.digest") else {
        return Ok(None);
    };
    if digest.as_slice() != &meta.digest[..]
        || sweep_page_digest(book_id, SWEEP_EXPIRY, meta.page, &payload) != meta.digest
    {
        return Ok(None);
    }
    let Ok(holds) = decode_hold_page(&payload) else {
        return Ok(None);
    };
    if holds.len() != meta.count as usize
        || holds.first().map(|h| i128::from(h.deadline_ns)) != Some(meta.min_key)
        || holds.last().map(|h| i128::from(h.deadline_ns)) != Some(meta.max_key)
    {
        return Ok(None);
    }
    Ok(Some(holds))
}

pub(crate) fn read_schedule_page_checked<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book_id: Id128,
    meta: &SweepIndexPageMeta,
) -> Result<Option<Vec<crate::schedule::Schedule>>, KernelError> {
    let Some(row) = db.vertex(sweep_index_page_vid(
        crate::schedule::SWEEP_REVERSAL,
        meta.page,
    ))?
    else {
        return Ok(None);
    };
    if row.labels != vec![label::REGISTER_STATE] {
        return Ok(None);
    }
    let Ok(owner) = bytes(&row, property::BOOK_ID, "sweep-page.book") else {
        return Ok(None);
    };
    if owner.as_slice() != &book_id.0[..] {
        return Ok(None);
    }
    let Ok(payload) = bytes(&row, property::FA_PAYLOAD, "sweep-page.payload") else {
        return Ok(None);
    };
    let Ok(digest) = bytes(&row, property::FA_DIGEST, "sweep-page.digest") else {
        return Ok(None);
    };
    if digest.as_slice() != &meta.digest[..]
        || sweep_page_digest(
            book_id,
            crate::schedule::SWEEP_REVERSAL,
            meta.page,
            &payload,
        ) != meta.digest
    {
        return Ok(None);
    }
    let Ok(schedules) = decode_schedule_page(&payload) else {
        return Ok(None);
    };
    if schedules.len() != meta.count as usize
        || schedules.first().map(|s| i128::from(s.reverse_on.0)) != Some(meta.min_key)
        || schedules.last().map(|s| i128::from(s.reverse_on.0)) != Some(meta.max_key)
    {
        return Ok(None);
    }
    Ok(Some(schedules))
}

fn indexed_due_holds<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    at: Tick,
) -> Result<Option<(Vec<DueHold>, SweepReadWitness)>, KernelError> {
    let Some((state, _)) = load_servable_sweep_index(db)? else {
        return Ok(None);
    };
    let Some(mut tail) = fold_sweep_delta_tail(db, state.through, state.latest_corroborated_tick)?
    else {
        return Ok(None);
    };
    tail.witness.used_index = true;
    // 1 vertex read for `sweep_index_vid()`.
    tail.witness.substrate_rows_read += 1;

    let cutoff = i128::from(at.observed_utc_ns);
    let mut due = Vec::new();
    for meta in &state.hold_pages {
        if meta.min_key > cutoff {
            continue;
        }
        tail.witness.pages_read += 1;
        tail.witness.substrate_rows_read += 1;
        let Some(holds) = read_hold_page_checked(db, state.book_id, meta)? else {
            return Ok(None);
        };
        for h in holds {
            if h.deadline_ns > at.observed_utc_ns || tail.resolved_holds.contains(&h.hold.vid) {
                continue;
            }
            tail.witness.candidates_read += 1;
            tail.witness.substrate_rows_read += 1;
            if db.vertex(resolution_vid(h.hold.vid))?.is_some() {
                continue;
            }
            due.push(DueHold {
                hold: h.hold,
                recorded_at: h.recorded_at,
                deadline_ns: h.deadline_ns,
            });
        }
    }
    for h in tail.added_holds.into_values() {
        if h.deadline_ns > at.observed_utc_ns || tail.resolved_holds.contains(&h.hold.vid) {
            continue;
        }
        tail.witness.candidates_read += 1;
        tail.witness.substrate_rows_read += 1;
        if db.vertex(resolution_vid(h.hold.vid))?.is_some() {
            continue;
        }
        due.push(DueHold {
            hold: h.hold,
            recorded_at: h.recorded_at,
            deadline_ns: h.deadline_ns,
        });
    }
    due.sort_by_key(|d| (d.recorded_at, d.hold.vid));
    Ok(Some((due, tail.witness)))
}

#[allow(clippy::type_complexity)]
fn refold_sweep_index_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    through: CommitSeq,
) -> Result<
    (
        Option<(CommitSeq, Tick)>,
        Vec<IndexedHold>,
        Vec<crate::schedule::Schedule>,
    ),
    KernelError,
> {
    let rows = if through == db.frontier()? {
        db.vertices()?
    } else {
        db.vertices_at(through)?
    };
    let mut latest_corroborated: Option<(CommitSeq, Tick)> = None;
    let mut pending_rows = Vec::new();
    let mut schedule_rows = Vec::new();
    for row in rows {
        if row.created_at > through {
            continue;
        }
        if row.labels.contains(&label::REVERSAL_SCHEDULE) {
            schedule_rows.push(row);
            continue;
        }
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let class_tag = match prop(&row, property::CLASS) {
            Some(CanonicalScalar::Int(c)) => u16::try_from(*c).ok(),
            _ => None,
        };
        if class_tag == Some(EntryClass::TIME_CONTROL.0) {
            let entry = decode_entry(&row)?;
            if let Some(ControlPayload::TimeTick {
                observed_utc_ns,
                monotonic_ok: true,
                ..
            }) = entry.proposal.control
            {
                let candidate = (
                    row.created_at,
                    Tick {
                        observed_utc_ns,
                        entry: row.vid,
                    },
                );
                if latest_corroborated
                    .is_none_or(|(s, t)| (candidate.0, candidate.1.entry) > (s, t.entry))
                {
                    latest_corroborated = Some(candidate);
                }
            }
        } else if class_tag == Some(EntryClass::PENDING.0) {
            pending_rows.push(row);
        }
    }
    let at_head = through == db.frontier()?;
    let mut holds = Vec::new();
    for row in pending_rows {
        let entry = decode_entry(&row)?;
        let Some(Pending {
            timeout_ns: Some(timeout),
            ..
        }) = entry.proposal.pending
        else {
            continue;
        };
        let resolved = if at_head {
            db.vertex(resolution_vid(row.vid))?.is_some()
        } else {
            db.vertex_at(resolution_vid(row.vid), through)?.is_some()
        };
        if resolved {
            continue;
        }
        let deadline_ns = deadline(db, row.created_at, timeout)?;
        holds.push(IndexedHold {
            hold: entry.entry_ref(row.vid),
            recorded_at: row.created_at,
            deadline_ns,
        });
    }
    holds.sort_by_key(|h| (h.deadline_ns, h.recorded_at, h.hold.vid));

    let mut schedules = Vec::new();
    for row in schedule_rows {
        let s = crate::schedule::decode_schedule(&row)?;
        let reversed = if at_head {
            db.vertex(reversal_vid(s.target.vid))?.is_some()
        } else {
            db.vertex_at(reversal_vid(s.target.vid), through)?.is_some()
        };
        if !reversed {
            schedules.push(s);
        }
    }
    schedules.sort_by_key(|s| (s.reverse_on, s.recorded_at, s.vid));
    Ok((latest_corroborated, holds, schedules))
}

#[allow(clippy::too_many_arguments)]
fn stage_sweep_index_write(
    book_id: Id128,
    through: CommitSeq,
    latest_corroborated_tick: Option<(CommitSeq, Tick)>,
    mut holds: Vec<IndexedHold>,
    mut schedules: Vec<crate::schedule::Schedule>,
    prev_hold_pages: usize,
    prev_schedule_pages: usize,
    expected_root_payload: Option<CanonicalScalar>,
) -> Result<(SweepIndexState, WriteBatch), KernelError> {
    holds.sort_by_key(|h| (h.deadline_ns, h.recorded_at, h.hold.vid));
    schedules.sort_by_key(|s| (s.reverse_on, s.recorded_at, s.vid));

    let mut batch = WriteBatch::new(relation::IN_BOOK);
    let mut hold_pages = Vec::new();
    for (idx, chunk) in holds.chunks(SWEEP_INDEX_PAGE_SIZE).enumerate() {
        let page = u32::try_from(idx)
            .map_err(|_| KernelError::Corrupt("sweep index hold page overflow".into()))?;
        let page_bytes = encode_hold_page(chunk)?;
        let digest = sweep_page_digest(book_id, SWEEP_EXPIRY, page, &page_bytes);
        let min_key = i128::from(chunk.first().map_or(0, |h| h.deadline_ns));
        let max_key = i128::from(chunk.last().map_or(0, |h| h.deadline_ns));
        hold_pages.push(SweepIndexPageMeta {
            page,
            min_key,
            max_key,
            count: chunk.len() as u32,
            digest,
        });
        let pvid = sweep_index_page_vid(SWEEP_EXPIRY, page);
        batch.ensure_vertex(pvid, vec![label::REGISTER_STATE], Vec::new());
        batch.set_vertex_label(pvid, label::REGISTER_STATE, true);
        batch.set_vertex_property(
            pvid,
            property::BOOK_ID,
            Some(scalar_bytes("sweep-page.book", book_id.0.to_vec())?),
        );
        batch.set_vertex_property(
            pvid,
            property::FA_DIGEST,
            Some(scalar_bytes("sweep-page.digest", digest.to_vec())?),
        );
        batch.set_vertex_property(
            pvid,
            property::FA_PAYLOAD,
            Some(scalar_bytes("sweep-page.payload", page_bytes)?),
        );
    }
    for old_idx in hold_pages.len()..prev_hold_pages {
        if let Ok(page) = u32::try_from(old_idx) {
            let pvid = sweep_index_page_vid(SWEEP_EXPIRY, page);
            batch.set_vertex_label(pvid, label::REGISTER_STATE, false);
            batch.set_vertex_property(pvid, property::FA_DIGEST, None);
            batch.set_vertex_property(pvid, property::FA_PAYLOAD, None);
        }
    }

    let mut schedule_pages = Vec::new();
    for (idx, chunk) in schedules.chunks(SWEEP_INDEX_PAGE_SIZE).enumerate() {
        let page = u32::try_from(idx)
            .map_err(|_| KernelError::Corrupt("sweep index schedule page overflow".into()))?;
        let page_bytes = encode_schedule_page(chunk)?;
        let digest = sweep_page_digest(book_id, crate::schedule::SWEEP_REVERSAL, page, &page_bytes);
        let min_key = i128::from(chunk.first().map_or(0, |s| s.reverse_on.0));
        let max_key = i128::from(chunk.last().map_or(0, |s| s.reverse_on.0));
        schedule_pages.push(SweepIndexPageMeta {
            page,
            min_key,
            max_key,
            count: chunk.len() as u32,
            digest,
        });
        let pvid = sweep_index_page_vid(crate::schedule::SWEEP_REVERSAL, page);
        batch.ensure_vertex(pvid, vec![label::REGISTER_STATE], Vec::new());
        batch.set_vertex_label(pvid, label::REGISTER_STATE, true);
        batch.set_vertex_property(
            pvid,
            property::BOOK_ID,
            Some(scalar_bytes("sweep-page.book", book_id.0.to_vec())?),
        );
        batch.set_vertex_property(
            pvid,
            property::FA_DIGEST,
            Some(scalar_bytes("sweep-page.digest", digest.to_vec())?),
        );
        batch.set_vertex_property(
            pvid,
            property::FA_PAYLOAD,
            Some(scalar_bytes("sweep-page.payload", page_bytes)?),
        );
    }
    for old_idx in schedule_pages.len()..prev_schedule_pages {
        if let Ok(page) = u32::try_from(old_idx) {
            let pvid = sweep_index_page_vid(crate::schedule::SWEEP_REVERSAL, page);
            batch.set_vertex_label(pvid, label::REGISTER_STATE, false);
            batch.set_vertex_property(pvid, property::FA_DIGEST, None);
            batch.set_vertex_property(pvid, property::FA_PAYLOAD, None);
        }
    }

    let state = SweepIndexState {
        book_id,
        through,
        latest_corroborated_tick,
        hold_pages,
        schedule_pages,
    };
    let root_bytes = encode_sweep_index_state(&state)?;
    let root_digest = sweep_index_digest(book_id, &root_bytes);
    let rvid = sweep_index_vid();
    batch.ensure_vertex(rvid, vec![label::REGISTER_STATE], Vec::new());
    batch.set_vertex_label(rvid, label::REGISTER_STATE, true);
    batch.set_vertex_property(
        rvid,
        property::BOOK_ID,
        Some(scalar_bytes("sweep-index.book", book_id.0.to_vec())?),
    );
    batch.set_vertex_property(
        rvid,
        property::FA_DIGEST,
        Some(scalar_bytes("sweep-index.digest", root_digest.to_vec())?),
    );
    batch.compare_and_set_vertex_property(
        rvid,
        property::FA_PAYLOAD,
        expected_root_payload,
        scalar_bytes("sweep-index.payload", root_bytes)?,
        WriteMismatchPolicy::AbortWrite,
    );
    Ok((state, batch))
}

/// Discard any cached `SweepIndex` and rebuild it from the authoritative
/// journal at head (plan §5.4, §7.6, FA-CFG-02).
pub async fn rebuild_sweep_index<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
) -> Result<SweepIndexState, KernelError> {
    let basis = db.frontier()?;
    let existing = db.vertex(sweep_index_vid())?;
    let expected_payload = existing
        .as_ref()
        .and_then(|r| prop(r, property::FA_PAYLOAD).cloned());
    let (prev_holds, prev_schedules) = existing
        .as_ref()
        .and_then(|r| bytes(r, property::FA_PAYLOAD, "sweep-index.payload").ok())
        .and_then(|b| decode_sweep_index_state(&b).ok())
        .map_or((0, 0), |s| (s.hold_pages.len(), s.schedule_pages.len()));
    let (latest_corroborated, holds, schedules) = refold_sweep_index_at(db, basis)?;
    let (state, batch) = stage_sweep_index_write(
        book.book_id,
        basis,
        latest_corroborated,
        holds,
        schedules,
        prev_holds,
        prev_schedules,
        expected_payload,
    )?;
    db.write(&ctx.commit(), batch).await?;
    Ok(state)
}

/// Advance the disposable `SweepIndex` over the committed delta stream to
/// the current frontier, skipping unrelated `Original` entries via their
/// `CLASS` mirror without decoding their payloads (plan §5.4, §7.6,
/// FA-CFG-02). Falls back to [`rebuild_sweep_index`] when no valid state
/// exists or the delta cursor has been retired.
pub async fn advance_sweep_index<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
) -> Result<SweepIndexState, KernelError> {
    let basis = db.frontier()?;
    let (
        from,
        mut holds_map,
        mut schedules_map,
        initial_tick,
        prev_holds,
        prev_schedules,
        expected,
    ) = match load_servable_sweep_index(db)? {
        Some((state, payload)) if state.book_id == book.book_id => {
            if state.through == basis {
                return Ok(state);
            }
            let mut hmap = BTreeMap::new();
            for meta in &state.hold_pages {
                let Some(page_holds) = read_hold_page_checked(db, book.book_id, meta)? else {
                    return rebuild_sweep_index(db, ctx, book).await;
                };
                for h in page_holds {
                    hmap.insert(h.hold.vid, h);
                }
            }
            let mut smap = BTreeMap::new();
            for meta in &state.schedule_pages {
                let Some(page_schedules) = read_schedule_page_checked(db, book.book_id, meta)?
                else {
                    return rebuild_sweep_index(db, ctx, book).await;
                };
                for s in page_schedules {
                    smap.insert(s.target.vid, s);
                }
            }
            (
                state.through,
                hmap,
                smap,
                state.latest_corroborated_tick,
                state.hold_pages.len(),
                state.schedule_pages.len(),
                Some(payload),
            )
        }
        _ => {
            let existing = db.vertex(sweep_index_vid())?;
            if existing.is_some() {
                return rebuild_sweep_index(db, ctx, book).await;
            }
            (
                CommitSeq::ORIGIN,
                BTreeMap::new(),
                BTreeMap::new(),
                None,
                0,
                0,
                None,
            )
        }
    };

    if let Err(err) = db.ensure_delta_window(&ctx.commit(), from).await {
        return match err {
            fgdb::RebuildError::Index {
                error: IndexError::CursorRetired { .. },
                ..
            } => rebuild_sweep_index(db, ctx, book).await,
            other => Err(fgdb::WriteError::from(other).into()),
        };
    }

    let Some(tail) = fold_sweep_delta_tail(db, from, initial_tick)? else {
        return rebuild_sweep_index(db, ctx, book).await;
    };
    for resolved in &tail.resolved_holds {
        holds_map.remove(resolved);
    }
    for (vid, hold) in tail.added_holds {
        if !tail.resolved_holds.contains(&vid) && db.vertex(resolution_vid(vid))?.is_none() {
            holds_map.insert(vid, hold);
        }
    }
    for reversed in &tail.reversed_targets {
        schedules_map.remove(reversed);
    }
    for (target_vid, schedule) in tail.added_schedules {
        if !tail.reversed_targets.contains(&target_vid)
            && db.vertex(reversal_vid(target_vid))?.is_none()
        {
            schedules_map.insert(target_vid, schedule);
        }
    }

    let (state, batch) = stage_sweep_index_write(
        book.book_id,
        basis,
        tail.latest_corroborated_tick,
        holds_map.into_values().collect(),
        schedules_map.into_values().collect(),
        prev_holds,
        prev_schedules,
        expected,
    )?;
    db.write(&ctx.commit(), batch).await?;
    Ok(state)
}

/// Refold the authoritative journal and verify the disposable `SweepIndex`
/// root and all of its hold/schedule pages against the refold (plan §5.4,
/// §7.6, FA-CFG-02).
pub fn verify_sweep_index<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
) -> Result<SweepIndexVerification, KernelError> {
    let mut v = SweepIndexVerification::default();
    let Some(root_row) = db.vertex(sweep_index_vid())? else {
        for (kind, name) in [
            (SWEEP_EXPIRY, "hold"),
            (crate::schedule::SWEEP_REVERSAL, "schedule"),
        ] {
            if db
                .vertex(sweep_index_page_vid(kind, 0))?
                .is_some_and(|r| r.labels.contains(&label::REGISTER_STATE))
            {
                v.drift.push(format!(
                    "sweep index {name} page 0 exists without a sweep index root"
                ));
            }
        }
        return Ok(v);
    };
    v.index_present = true;
    if root_row.labels != vec![label::REGISTER_STATE] {
        v.drift
            .push("sweep index root does not carry label RegisterState".into());
        return Ok(v);
    }
    let owner = match bytes(&root_row, property::BOOK_ID, "sweep-index.book") {
        Ok(b) => b,
        Err(e) => {
            v.drift.push(format!("sweep index root book_id: {e}"));
            return Ok(v);
        }
    };
    if owner.as_slice() != &book.book_id.0[..] {
        v.drift
            .push("sweep index root book_id disagrees with book".into());
        return Ok(v);
    }
    let payload = match bytes(&root_row, property::FA_PAYLOAD, "sweep-index.payload") {
        Ok(b) => b,
        Err(e) => {
            v.drift.push(format!("sweep index root payload: {e}"));
            return Ok(v);
        }
    };
    let digest = match bytes(&root_row, property::FA_DIGEST, "sweep-index.digest") {
        Ok(b) => b,
        Err(e) => {
            v.drift.push(format!("sweep index root digest: {e}"));
            return Ok(v);
        }
    };
    if digest.as_slice() != &sweep_index_digest(book.book_id, &payload)[..] {
        v.drift.push("sweep index root checksum mismatch".into());
        return Ok(v);
    }
    let state = match decode_sweep_index_state(&payload) {
        Ok(s) => s,
        Err(e) => {
            v.drift.push(e.to_string());
            return Ok(v);
        }
    };
    v.through = Some(state.through);
    let frontier = db.frontier()?;
    if state.through > frontier {
        v.drift.push(format!(
            "sweep index cursor {} exceeds book frontier {}",
            state.through.0, frontier.0
        ));
        return Ok(v);
    }

    let mut stored_holds = Vec::new();
    for (idx, meta) in state.hold_pages.iter().enumerate() {
        v.pages_checked += 1;
        if meta.page as usize != idx {
            v.drift.push(format!(
                "sweep index hold page ordinal {} is out of sequence at {idx}",
                meta.page
            ));
        }
        match read_hold_page_checked(db, book.book_id, meta)? {
            Some(page_holds) => stored_holds.extend(page_holds),
            None => v.drift.push(format!(
                "sweep index hold page {} is missing, corrupted, or fails its digest/range check",
                meta.page
            )),
        }
    }

    let mut stored_schedules = Vec::new();
    for (idx, meta) in state.schedule_pages.iter().enumerate() {
        v.pages_checked += 1;
        if meta.page as usize != idx {
            v.drift.push(format!(
                "sweep index schedule page ordinal {} is out of sequence at {idx}",
                meta.page
            ));
        }
        match read_schedule_page_checked(db, book.book_id, meta)? {
            Some(page_schedules) => stored_schedules.extend(page_schedules),
            None => v.drift.push(format!(
                "sweep index schedule page {} is missing, corrupted, or fails its digest/range check",
                meta.page
            )),
        }
    }

    let (expected_tick, expected_holds, expected_schedules) =
        refold_sweep_index_at(db, state.through)?;
    v.holds_checked = expected_holds.len();
    v.schedules_checked = expected_schedules.len();

    if state.latest_corroborated_tick != expected_tick {
        v.drift.push(format!(
            "sweep index latest_corroborated_tick {:?} disagrees with journal refold {:?}",
            state.latest_corroborated_tick, expected_tick
        ));
    }

    let stored_hold_map: BTreeMap<VId, &IndexedHold> =
        stored_holds.iter().map(|h| (h.hold.vid, h)).collect();
    let expected_hold_map: BTreeMap<VId, &IndexedHold> =
        expected_holds.iter().map(|h| (h.hold.vid, h)).collect();
    for (vid, exp) in &expected_hold_map {
        match stored_hold_map.get(vid) {
            None => v.drift.push(format!(
                "sweep index omits unresolved timed hold {:032x} (deadline {} ns)",
                vid.0, exp.deadline_ns
            )),
            Some(got) if *got != *exp => v.drift.push(format!(
                "sweep index entry for hold {:032x} disagrees with journal refold",
                vid.0
            )),
            Some(_) => {}
        }
    }
    for vid in stored_hold_map.keys() {
        if !expected_hold_map.contains_key(vid) {
            v.drift.push(format!(
                "sweep index retains resolved or unknown hold {:032x}",
                vid.0
            ));
        }
    }
    if v.drift.is_empty() && stored_holds != expected_holds {
        v.drift
            .push("sweep index hold page ordering disagrees with journal refold".into());
    }

    let stored_sched_map: BTreeMap<VId, &crate::schedule::Schedule> =
        stored_schedules.iter().map(|s| (s.vid, s)).collect();
    let expected_sched_map: BTreeMap<VId, &crate::schedule::Schedule> =
        expected_schedules.iter().map(|s| (s.vid, s)).collect();
    for (vid, exp) in &expected_sched_map {
        match stored_sched_map.get(vid) {
            None => v.drift.push(format!(
                "sweep index omits unreversed schedule {:032x} (target {:032x})",
                vid.0, exp.target.vid.0
            )),
            Some(got) if *got != *exp => v.drift.push(format!(
                "sweep index entry for schedule {:032x} disagrees with journal refold",
                vid.0
            )),
            Some(_) => {}
        }
    }
    for vid in stored_sched_map.keys() {
        if !expected_sched_map.contains_key(vid) {
            v.drift.push(format!(
                "sweep index retains reversed or unknown schedule {:032x}",
                vid.0
            ));
        }
    }
    if v.drift.is_empty() && stored_schedules != expected_schedules {
        v.drift
            .push("sweep index schedule page ordering disagrees with journal refold".into());
    }

    Ok(v)
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

    struct SweepTestEnv {
        runtime: asupersync::runtime::Runtime,
        root: asupersync::Cx,
        db: Database<fgdb::MemVfs>,
        book: BookContext,
        usd: fa_money::UnitId,
        cash: VId,
        rent: VId,
        evidence: Vec<fa_model::EvidenceRef>,
    }

    impl SweepTestEnv {
        fn new() -> Self {
            use asupersync::Budget;
            use asupersync::runtime::RuntimeBuilder;
            use fa_model::{SealKey, SymbolTable, account_vid};
            use fa_money::UnitRegistry;
            use fa_time::{FiscalCalendar, PeriodKind, PeriodTransition};
            use fgdb::DatabaseKeys;
            use fgdb_types::ids::DatabaseSecurityNamespaceId;

            let runtime = RuntimeBuilder::new().build().expect("runtime");
            let root = runtime.request_cx_with_budget(Budget::INFINITE);
            let ctx = PurposeContexts::narrow_runtime_root(&root);
            let keys = DatabaseKeys::new(
                [0x5a; 32],
                DatabaseSecurityNamespaceId([0x5b; 32]),
                [0x5c; 32],
            );
            let mut db = runtime
                .block_on(async { Database::open_memory(&ctx.commit(), keys).await })
                .expect("open");
            let units = UnitRegistry::with_defaults();
            let usd = units.lookup("USD").expect("USD");
            let calendar = FiscalCalendar::monthly("cal", 1, 1).expect("calendar");
            let book_id = Id128([9; 16]);
            let spec = crate::genesis::BookSpec {
                book_id,
                name: "Sweep Test Co".into(),
                base_unit: usd,
                calendar: calendar.clone(),
                time_zone_policy: Some(crate::genesis::TimeZonePolicy::Utc),
                entities: Vec::new(),
                opening_date: None,
            };
            let symbols = SymbolTable::compiled();
            runtime
                .block_on(async {
                    crate::genesis::create_book(&mut db, &ctx, &spec, &units, &symbols).await
                })
                .expect("create_book");
            let book = BookContext {
                book_id,
                calendar,
                units,
                seal_key: SealKey([0x11; 32]),
                symbols,
            };
            let principal = VId(7);
            let chart = vec![
                crate::genesis::AccountSpec {
                    code: "1000".into(),
                    name: "Cash".into(),
                    account_type: 1,
                    normal_balance: 0,
                    is_leaf: true,
                    unit_policy: crate::genesis::UnitPolicy::Single(usd),
                    parent_code: None,
                    limit: None,
                },
                crate::genesis::AccountSpec {
                    code: "6000".into(),
                    name: "Rent".into(),
                    account_type: 5,
                    normal_balance: 0,
                    is_leaf: true,
                    unit_policy: crate::genesis::UnitPolicy::Single(usd),
                    parent_code: None,
                    limit: None,
                },
            ];
            let day = DateDay::from_ymd(2026, 3, 15).expect("day");
            let schema_cap = Capability::embedded(principal, &["schema_change"]).expect("cap");
            runtime
                .block_on(async {
                    crate::genesis::install_chart(
                        &mut db,
                        &ctx,
                        &book,
                        &chart,
                        principal,
                        day,
                        b"chart-1",
                        Erasable::seal(
                            &"chart".to_string(),
                            None,
                            &book.seal_key,
                            [5; 32],
                            [6; 24],
                        ),
                        &schema_cap,
                    )
                    .await
                })
                .expect("install_chart")
                .expect("admitted");
            let (_, periods) = runtime
                .block_on(async {
                    crate::genesis::create_periods(
                        &mut db,
                        &ctx,
                        &book,
                        2026,
                        principal,
                        Erasable::seal(
                            &"periods".to_string(),
                            None,
                            &book.seal_key,
                            [1; 32],
                            [2; 24],
                        ),
                        &schema_cap,
                    )
                    .await
                })
                .expect("create_periods")
                .expect("admitted");
            let march = periods
                .iter()
                .find(|p| p.contains(day) && p.kind == PeriodKind::Normal)
                .expect("march")
                .code
                .clone();
            let doc = crate::evidence::Document {
                book_id,
                kind: 1,
                mime: "text/plain".into(),
                grade: 3,
                retrieved_by: principal,
                bytes: b"INVOICE 2026-0315 Sweep Test Co fixture source document".to_vec(),
            };
            runtime
                .block_on(async { crate::evidence::add_document(&mut db, &ctx, &book, &doc).await })
                .expect("add_document")
                .expect("admitted");
            let evidence = vec![doc.evidence_ref(1)];
            let open_cap = Capability::embedded(principal, &["close"]).expect("cap");
            runtime
                .block_on(async {
                    crate::period::transition_period(
                        &mut db,
                        &ctx,
                        &book,
                        &march,
                        PeriodTransition::Open,
                        principal,
                        1,
                        b"open-march",
                        Erasable::seal(&"open".to_string(), None, &book.seal_key, [3; 32], [4; 24]),
                        &open_cap,
                        &[],
                    )
                    .await
                })
                .expect("open")
                .expect("admitted");

            Self {
                runtime,
                root,
                db,
                book,
                usd,
                cash: account_vid(book_id, "1000"),
                rent: account_vid(book_id, "6000"),
                evidence,
            }
        }

        fn ctx(&self) -> PurposeContexts {
            PurposeContexts::narrow_runtime_root(&self.root)
        }

        fn seal(&self, s: &str) -> Erasable<String> {
            Erasable::seal(
                &s.to_string(),
                None,
                &self.book.seal_key,
                [0x22; 32],
                [0x33; 24],
            )
        }

        fn record_tick_at(&mut self, ns: u64, key: &[u8]) -> Ticked {
            let principal = VId(7);
            let cap = Capability::embedded(principal, &["witness"]).expect("witness cap");
            let req = TickRequest {
                observed_utc_ns: ns,
                source: SOURCE_DAEMON_CLOCK,
                monotonic_ok: true,
                principal_ref: principal,
                capability: cap,
                idempotency_key: key.to_vec(),
                description: self.seal("tick"),
            };
            let ctx = self.ctx();
            self.runtime
                .block_on(record_tick(&mut self.db, &ctx, &self.book, req))
                .expect("kernel")
                .expect("tick recorded")
        }

        fn post_timed_hold(&mut self, timeout_ns: u64, key: &[u8]) -> EntryRef {
            use fa_model::LegPayload;
            use fa_money::Amount;
            let principal = VId(7);
            let legs = vec![
                LegPayload::simple(Side::Debit, self.rent, Amount::new(self.usd, 1_000)),
                LegPayload::simple(Side::Credit, self.cash, Amount::new(self.usd, 1_000)),
            ];
            let unit_totals = EntryPayload::fold_unit_totals(&legs).expect("totals");
            let proposal = EntryPayload {
                schema_minor: 0,
                book_id: self.book.book_id,
                branch_id: Id128::TRUNK,
                class: EntryClass::PENDING,
                effective_date: DateDay::from_ymd(2026, 3, 15).expect("day"),
                document_date: None,
                description: self.seal("timed hold"),
                effective_period: None,
                legs,
                control: None,
                unit_totals,
                base_totals: None,
                idempotency_key: key.to_vec(),
                origin: EntryOrigin::Intent {
                    intent_oid: Oid([1; 32]),
                    intent_kind: 1,
                },
                principal_ref: principal,
                session_ref: None,
                evidence: self.evidence.clone(),
                supersession: Vec::new(),
                pending: Some(Pending {
                    timeout_ns: Some(timeout_ns),
                    resolution_of: None,
                    disposition: None,
                }),
                external_ids: Vec::new(),
                extensions: Vec::new(),
                tags: Vec::new(),
            };
            let cap = Capability::embedded(principal, &["post"]).expect("post cap");
            let req = crate::post::PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap,
            };
            let ctx = self.ctx();
            match self
                .runtime
                .block_on(crate::post::post(&mut self.db, &ctx, &self.book, req))
                .expect("kernel")
                .expect("posted")
            {
                Posted::Committed { entry_ref, .. } | Posted::AlreadyRecorded { entry_ref, .. } => {
                    entry_ref
                }
            }
        }

        fn bulk_append_unrelated_originals(&mut self, count: usize) {
            use fa_model::LegPayload;
            use fa_money::Amount;
            let principal = VId(7);
            let legs = vec![
                LegPayload::simple(Side::Debit, self.rent, Amount::new(self.usd, 100)),
                LegPayload::simple(Side::Credit, self.cash, Amount::new(self.usd, 100)),
            ];
            let unit_totals = EntryPayload::fold_unit_totals(&legs).expect("totals");
            let template_proposal = EntryPayload {
                schema_minor: 0,
                book_id: self.book.book_id,
                branch_id: Id128::TRUNK,
                class: EntryClass::ORIGINAL,
                effective_date: DateDay::from_ymd(2026, 3, 15).expect("day"),
                document_date: None,
                description: self.seal("unrelated original"),
                effective_period: None,
                legs,
                control: None,
                unit_totals,
                base_totals: None,
                idempotency_key: b"bulk-template".to_vec(),
                origin: EntryOrigin::Intent {
                    intent_oid: Oid([1; 32]),
                    intent_kind: 1,
                },
                principal_ref: principal,
                session_ref: None,
                evidence: self.evidence.clone(),
                supersession: Vec::new(),
                pending: None,
                external_ids: Vec::new(),
                extensions: Vec::new(),
                tags: Vec::new(),
            };
            let template_entry = template_proposal.seal(Vec::new(), None).expect("seal");
            let mirrors = entry_mirrors(&template_entry).expect("mirrors");
            let ctx = self.ctx();
            let chunk_size = 10_000;
            for chunk_start in (0..count).step_by(chunk_size) {
                let chunk_end = (chunk_start + chunk_size).min(count);
                let mut batch = WriteBatch::new(relation::IN_BOOK);
                for idx in chunk_start..chunk_end {
                    let vid = VId(0x9000_0000_0000_0000_u128 + idx as u128);
                    batch.create_vertex(vid, vec![label::ENTRY], mirrors.clone());
                }
                self.runtime
                    .block_on(self.db.write(&ctx.commit(), batch))
                    .expect("bulk write");
            }
        }
    }

    #[test]
    fn cycle_reads_are_independent_of_unrelated_history() {
        let t0 = 1_773_532_800_000_000_000_u64;
        let t1 = t0 + 120_000_000_000;

        // Baseline book: 3 due holds, 70 future holds (spanning 2 index pages), 0 unrelated entries.
        let mut small = SweepTestEnv::new();
        small.record_tick_at(t0, b"tick-0");
        for i in 0..3 {
            small.post_timed_hold(60_000_000_000, format!("due-{i}").as_bytes());
        }
        for i in 0..70 {
            small.post_timed_hold(86_400_000_000_000, format!("future-{i}").as_bytes());
        }
        let ctx_small = small.ctx();
        let small_state = small
            .runtime
            .block_on(advance_sweep_index(&mut small.db, &ctx_small, &small.book))
            .expect("advance_sweep_index");
        assert_eq!(small_state.hold_pages.len(), 2);
        small.record_tick_at(t1, b"tick-1");

        let system = crate::rows::system_principal(small.book.book_id);
        let sys_cap = Capability::new(system, Profile::System, &[Op::Post], VId(7)).expect("cap");
        let req = SweepRequest {
            principal_ref: system,
            capability: sys_cap.clone(),
            max_batch: 64,
        };
        let small_seal_key = small.book.seal_key.clone();
        let mut describe_small = |s: &str| {
            Ok(Erasable::seal(
                &s.to_string(),
                None,
                &small_seal_key,
                [0x22; 32],
                [0x33; 24],
            ))
        };
        let (small_batch, small_witness) = small
            .runtime
            .block_on(sweep_batch_with_witness(
                &mut small.db,
                &ctx_small,
                &small.book,
                &req,
                &mut describe_small,
            ))
            .expect("kernel")
            .expect("sweep_batch");
        let small_batch = small_batch.expect("3 due holds expired");
        assert_eq!(small_batch.expired.len(), 3);
        assert_eq!(small_batch.remaining_due, 0);
        assert!(small_witness.used_index);
        // Page 0 contains the 3 due holds; Page 1 has min_key = t0 + 24h > t1 so it is skipped!
        assert_eq!(small_witness.pages_read, 1);
        assert_eq!(small_witness.candidates_read, 3);
        assert_eq!(small_witness.unrelated_entries_decoded, 0);

        // Large book: 3 due holds, 70 future holds, and 100,000 unrelated Original entries!
        let mut large = SweepTestEnv::new();
        large.record_tick_at(t0, b"tick-0");
        for i in 0..3 {
            large.post_timed_hold(60_000_000_000, format!("due-{i}").as_bytes());
        }
        for i in 0..70 {
            large.post_timed_hold(86_400_000_000_000, format!("future-{i}").as_bytes());
        }
        large.bulk_append_unrelated_originals(100_000);
        let ctx_large = large.ctx();
        let large_state = large
            .runtime
            .block_on(advance_sweep_index(&mut large.db, &ctx_large, &large.book))
            .expect("advance_sweep_index on 100k book");
        assert_eq!(large_state.hold_pages.len(), 2);
        large.record_tick_at(t1, b"tick-1");

        let large_seal_key = large.book.seal_key.clone();
        let mut describe_large = |s: &str| {
            Ok(Erasable::seal(
                &s.to_string(),
                None,
                &large_seal_key,
                [0x22; 32],
                [0x33; 24],
            ))
        };
        let (large_batch, large_witness) = large
            .runtime
            .block_on(sweep_batch_with_witness(
                &mut large.db,
                &ctx_large,
                &large.book,
                &req,
                &mut describe_large,
            ))
            .expect("kernel")
            .expect("sweep_batch");
        let large_batch = large_batch.expect("3 due holds expired");
        assert_eq!(large_batch.expired.len(), 3);
        assert_eq!(large_batch.remaining_due, 0);
        assert!(large_witness.used_index);
        assert_eq!(large_witness.pages_read, 1);
        assert_eq!(large_witness.candidates_read, 3);
        assert_eq!(large_witness.unrelated_entries_decoded, 0);
        // Exact O(due + page) independence: 100,000 unrelated entries add 0 substrate reads.
        assert_eq!(
            large_witness.substrate_rows_read,
            small_witness.substrate_rows_read
        );
        assert!(large_witness.substrate_rows_read <= 32);
    }

    #[test]
    fn index_drift_detected_by_refold() {
        let t0 = 1_773_532_800_000_000_000_u64;
        let mut env = SweepTestEnv::new();
        env.record_tick_at(t0, b"tick-0");
        let h1 = env.post_timed_hold(60_000_000_000, b"hold-1");
        let h2 = env.post_timed_hold(90_000_000_000, b"hold-2");
        let ctx = env.ctx();
        let clean_state = env
            .runtime
            .block_on(advance_sweep_index(&mut env.db, &ctx, &env.book))
            .expect("advance_sweep_index");
        let verified = verify_sweep_index(&env.db, &env.book).expect("verify_sweep_index");
        assert!(verified.is_green(), "{verified:?}");
        assert_eq!(verified.holds_checked, 2);

        // Drift 1: Coherently re-checksummed index missing due hold h2.
        let page0_row = env
            .db
            .vertex(sweep_index_page_vid(SWEEP_EXPIRY, 0))
            .expect("read")
            .expect("page 0");
        let page0_bytes = bytes(&page0_row, property::FA_PAYLOAD, "page0").expect("page0 payload");
        let mut holds = decode_hold_page(&page0_bytes).expect("decode page0");
        assert_eq!(holds.len(), 2);
        holds.retain(|h| h.hold.vid != h2.vid);
        let root_row = env
            .db
            .vertex(sweep_index_vid())
            .expect("read")
            .expect("root");
        let expected_root = prop(&root_row, property::FA_PAYLOAD).cloned();
        let (_, missing_batch) = stage_sweep_index_write(
            env.book.book_id,
            clean_state.through,
            clean_state.latest_corroborated_tick,
            holds.clone(),
            Vec::new(),
            1,
            0,
            expected_root,
        )
        .expect("stage missing hold");
        env.runtime
            .block_on(env.db.write(&ctx.commit(), missing_batch))
            .expect("write missing hold");

        let drift_missing = verify_sweep_index(&env.db, &env.book).expect("verify missing");
        assert!(!drift_missing.is_green(), "{drift_missing:?}");
        assert!(
            drift_missing.drift.iter().any(|d| {
                d.contains(&format!("{:032x}", h2.vid.0))
                    && d.contains("omits unresolved timed hold")
            }),
            "expected missing-hold drift, got: {:?}",
            drift_missing.drift
        );

        // Drift 2: Coherently re-checksummed index with a corrupted/forged deadline on h1,
        // plus a corrupted page digest.
        let mut forged = decode_hold_page(&page0_bytes).expect("decode original");
        for item in &mut forged {
            if item.hold.vid == h1.vid {
                item.deadline_ns += 999_999;
            }
        }
        let root_row = env
            .db
            .vertex(sweep_index_vid())
            .expect("read")
            .expect("root");
        let expected_root = prop(&root_row, property::FA_PAYLOAD).cloned();
        let (_, forged_batch) = stage_sweep_index_write(
            env.book.book_id,
            clean_state.through,
            clean_state.latest_corroborated_tick,
            forged,
            Vec::new(),
            1,
            0,
            expected_root,
        )
        .expect("stage forged hold");
        env.runtime
            .block_on(env.db.write(&ctx.commit(), forged_batch))
            .expect("write forged hold");

        let drift_forged = verify_sweep_index(&env.db, &env.book).expect("verify forged");
        assert!(!drift_forged.is_green(), "{drift_forged:?}");
        assert!(
            drift_forged.drift.iter().any(|d| {
                d.contains(&format!("{:032x}", h1.vid.0))
                    && d.contains("disagrees with journal refold")
            }),
            "expected forged-entry drift, got: {:?}",
            drift_forged.drift
        );

        // Rebuild restores a clean index.
        env.runtime
            .block_on(rebuild_sweep_index(&mut env.db, &ctx, &env.book))
            .expect("rebuild_sweep_index");
        assert!(
            verify_sweep_index(&env.db, &env.book)
                .expect("verify rebuilt")
                .is_green()
        );
    }
}
