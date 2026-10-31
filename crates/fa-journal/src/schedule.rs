//! Scheduled reversals (plan §7.6; §5.4's cursor discipline; FA-INV-08).
//!
//! **Binding.** An `Adjusting` entry may carry extension tag 2
//! `fa:auto-reverse:v1` (`reverse_on`, `rule`). Its proposal digest covers
//! the extension, so the approvals of the original plan bind the date and the
//! rule, and no future reversal envelope exists anywhere. The posting kernel
//! creates the entry's `ReversalSchedule` vertex in the same commit, at
//! `H("fa:vid:reversal-schedule:v1" ‖ target)`, mirroring what §7.6 says a
//! schedule records: the target, `reverse_on` and its period, the execution
//! authority (`exec_op` = `post`, judged by the Reversal row of the reversal
//! period's state), and the bound effects (`effects_digest`, a commitment to
//! the exact side swap of the committed target). [`verify_schedules`] refolds
//! all of it from the payloads.
//!
//! **Execution.** A scheduled reversal *is* the target's one reversal,
//! `vid(Reversal) = H("fa:vid:reversal:v1" ‖ target)`. It is minted at the
//! later of two moments:
//! - (a) the first tick whose civil date, under the book's declared
//!   `time_zone_policy`, is on or after `reverse_on` (the reversal sweep,
//!   [`sweep_reversals_batch`]);
//! - (b) the `Open` transition of the period containing `reverse_on`, inside
//!   that transition's commit ([`mint_on_open`]).
//!
//! Its envelope is fully determined by the schedule, so both paths mint the
//! same thing:
//! - the book's System principal, with the original author retained by lineage;
//! - the exact swap, under the target's own sealed description, retaining its
//!   functional carrying amounts, original Rate evidence and residual;
//! - dated `reverse_on`;
//! - the date basis recorded as extension 3.
//!
//! Execution rechecks the period law against the Reversal row (Open and
//! SoftClosed admit; Closed needs `post_closed`, which the scheduler never
//! holds; Locked refuses), live applications against the target, and the
//! ordinary account/subledger and availability laws, current executor authority,
//! and daily spending limits. A schedule that does not pass is **blocked**: reported,
//! never minted, and never stalling a batch. A person reverses it by hand.
//!
//! Both moments take time only from a corroborated committed tick (sweep.rs
//! `corroborated_at_head`): under a latest tick whose source's monotonic
//! clock did not corroborate it, the reversal sweep refuses (FA-REF-144) and
//! an `Open` mints nothing, so the schedule waits for the next corroborated
//! tick.
//!
//! **Cancellation by lineage.** A manual Reversal of a scheduled target
//! takes that identity first. Its commit journals a `ScheduleControl` entry
//! carrying `ScheduleCancelled { schedule_ref, cause_ref }` at
//! `H("fa:vid:schedule-cancel:v1" ‖ schedule)`, so a cancelled schedule can
//! never fire (post.rs, [`cancellation`]).

use std::collections::BTreeMap;
use std::collections::btree_map::Entry as MapEntry;

use fa_model::entry::{AUTO_REVERSE_EXTENSION, DATE_BASIS_EXTENSION};
use fa_model::limits::MAX_BATCH_ENTRIES;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ControlPayload, EntryClass, EntryOrigin, EntryPayload, EntryRef, Id128, LegPayload,
    ScheduleTrigger, Supersession, SupersessionKind, entry_mirrors, period_vid,
};
use fa_money::Side;
use fa_policy::Party;
use fa_registry::evidence_policy::EvidencePolicy;
use fa_registry::{Admissibility, Decision, EntryClasses};
use fa_time::{DateDay, PeriodState, resolve_period};
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxn, WriteTxnError};
use fgdb_crypto::Hasher;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::genesis::{BookContext, TimeZonePolicy, read_book_spec};
use crate::limit::{self, LimitCell, LimitScope, Movement};
use crate::policy;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{
    AccountRow, applied_witness, book_root, edge_id, leg_vid, prop, reversal_vid, scalar_bytes,
    scalar_text, schedule_cancel_vid, schedule_cursor_vid, schedule_vid, state_from_scalar,
    system_principal,
};
use crate::sweep::{
    CellRun, Cursor, SweepRequest, Tick, admit_sweep, conflict, corroborated_at_head,
    cursor_proposal, decode_entry, latest_tick, root_row, tick_corroborated, tick_witness,
};

/// `fa:auto-reverse:v1` rule 1: the exact negation (`supersession_kinds`
/// `Reverses`: side swap preserving native mantissas, never revaluation).
pub const RULE_EXACT_NEGATION: u8 = 1;

/// `SweepCursor.sweep_kind` / `EntryOrigin::Sweep.sweep_kind` of the
/// scheduled-reversal sweep.
pub const SWEEP_REVERSAL: u8 = 2;

/// The execution authority a schedule records: the op its executor holds,
/// judged by the Reversal row of the reversal period's state.
pub const EXEC_OP: &str = "post";

const EFFECTS_DOMAIN: &[u8] = b"fa:schedule-effects:v1";

/// The `fa:auto-reverse:v1` bytes: `reverse_on: i32 LE ‖ rule: u8`.
#[must_use]
pub fn auto_reverse_bytes(reverse_on: DateDay, rule: u8) -> Vec<u8> {
    let mut b = Vec::with_capacity(5);
    b.extend_from_slice(&reverse_on.0.to_le_bytes());
    b.push(rule);
    b
}

/// The scheduled reversal an entry requests: `Ok(None)` without the
/// extension, `Err(why)` when its bytes are malformed.
pub fn auto_reverse(p: &EntryPayload) -> Result<Option<(DateDay, u8)>, String> {
    let Some((_, b)) = p
        .extensions
        .iter()
        .find(|(t, _)| *t == AUTO_REVERSE_EXTENSION)
    else {
        return Ok(None);
    };
    let (Ok(day), Some(rule)) = (
        <[u8; 4]>::try_from(b.get(..4).unwrap_or_default()),
        b.get(4),
    ) else {
        return Err(format!(
            "the fa:auto-reverse:v1 extension is {} bytes, not 5",
            b.len()
        ));
    };
    if b.len() != 5 {
        return Err(format!(
            "the fa:auto-reverse:v1 extension is {} bytes, not 5",
            b.len()
        ));
    }
    Ok(Some((DateDay(i32::from_le_bytes(day)), *rule)))
}

/// `p` with the scheduled-reversal request (extensions stay sorted by tag).
#[must_use]
pub fn with_auto_reverse(mut p: EntryPayload, reverse_on: DateDay) -> EntryPayload {
    p.schema_minor = p.schema_minor.max(fa_model::entry::EXTENSIONS_MINOR);
    p.extensions.retain(|(t, _)| *t != AUTO_REVERSE_EXTENSION);
    p.extensions.push((
        AUTO_REVERSE_EXTENSION,
        auto_reverse_bytes(reverse_on, RULE_EXACT_NEGATION),
    ));
    p.extensions.sort_by_key(|(t, _)| *t);
    p
}

/// The `fa:effective-date-basis:v1` bytes: `policy: u8 ‖ tick_ref: u128 LE`.
#[must_use]
pub fn date_basis_bytes(policy: TimeZonePolicy, tick: VId) -> Vec<u8> {
    let mut b = Vec::with_capacity(17);
    b.push(policy.tag());
    b.extend_from_slice(&tick.0.to_le_bytes());
    b
}

/// The date basis a minted entry records: `Ok(None)` without it.
pub fn date_basis(p: &EntryPayload) -> Result<Option<(TimeZonePolicy, VId)>, String> {
    let Some((_, b)) = p
        .extensions
        .iter()
        .find(|(t, _)| *t == DATE_BASIS_EXTENSION)
    else {
        return Ok(None);
    };
    let (Some(tag), Ok(tick)) = (
        b.first(),
        <[u8; 16]>::try_from(b.get(1..).unwrap_or_default()),
    ) else {
        return Err(format!(
            "the fa:effective-date-basis:v1 extension is {} bytes, not 17",
            b.len()
        ));
    };
    let policy = TimeZonePolicy::from_tag(*tag)
        .ok_or_else(|| format!("unregistered time_zone_policy tag {tag}"))?;
    Ok(Some((policy, VId(u128::from_le_bytes(tick)))))
}

/// The commitment to a schedule's bound effects: the exact side swap of the
/// committed target under `rule`, dated `reverse_on`.
#[must_use]
pub fn effects_digest(target: EntryRef, reverse_on: DateDay, rule: u8) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(EFFECTS_DOMAIN);
    h.update(&target.vid.0.to_le_bytes());
    h.update(&target.entry_digest);
    h.update(&reverse_on.0.to_le_bytes());
    h.update(&[rule]);
    h.finalize().0
}

/// The book's declared `time_zone_policy` (its genesis spec, immutable).
pub fn book_policy<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
) -> Result<Option<TimeZonePolicy>, KernelError> {
    Ok(read_book_spec(db)?.and_then(|s| s.time_zone_policy))
}

/// The normal period containing `day`.
fn period_of(book: &BookContext, day: DateDay) -> Result<Result<String, String>, KernelError> {
    let fy = book.calendar.fiscal_year_of(day)?;
    let periods = book.calendar.periods_for_year(fy)?;
    Ok(resolve_period(&periods, day, None)
        .map(|p| p.code.clone())
        .map_err(|e| format!("{e:?}")))
}

fn structure(why: impl Into<String>) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        why,
        "plan §7.6 (Accrue/Defer auto_reverse_on; Appendix B)",
        "schedule the reversal of an Adjusting entry with no applications, on a date after its effective date",
    )
}

/// The scheduled-reversal request of a submitted proposal, judged before
/// the posting transaction (plan §7.6, §7.7): `Ok(None)` when it carries none;
/// `Some((reverse_on, period))` when it is admissible. Only the kernel
/// records a date basis; only an `Adjusting` entry schedules its reversal,
/// with the exact-negation rule, carrying no applications, for a date after
/// its own. A functional valuation uses SpotClose or PeriodAverage and is
/// inherited without repricing. The book must declare its
/// `time_zone_policy` (FA-REF-102 otherwise).
pub(crate) fn admit_request<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    p: &EntryPayload,
) -> Outcome<Option<(DateDay, String)>> {
    if p.extensions.iter().any(|(t, _)| *t == DATE_BASIS_EXTENSION) {
        return Ok(Err(structure(
            "fa:effective-date-basis:v1 is recorded by the kernel on the reversals it mints, never submitted",
        )));
    }
    let (reverse_on, rule) = match auto_reverse(p) {
        Ok(None) => return Ok(Ok(None)),
        Ok(Some(r)) => r,
        Err(why) => return Ok(Err(structure(why))),
    };
    if p.class != EntryClass::ADJUSTING {
        return Ok(Err(structure(format!(
            "only an Adjusting entry schedules its reversal; this is a {}",
            p.class.name().unwrap_or("?")
        ))));
    }
    if rule != RULE_EXACT_NEGATION {
        return Ok(Err(structure(format!(
            "auto-reverse rule {rule} is not registered (1 = exact negation)"
        ))));
    }
    if p.legs.iter().any(|l| !l.settles.is_empty()) {
        return Ok(Err(structure(
            "a scheduled-reversal Adjusting carries no applications",
        )));
    }
    if p.base_totals.as_ref().is_some_and(|totals| {
        !matches!(
            crate::fx::FxLawId::from_oid(&totals.fx_law_oid),
            Some(crate::fx::FxLawId::SpotClose | crate::fx::FxLawId::PeriodAverage)
        )
    }) {
        return Ok(Err(structure(
            "a scheduled-reversal Adjusting retains only a SpotClose or PeriodAverage valuation; other carrying laws require their own execution effects",
        )));
    }
    if reverse_on <= p.effective_date {
        return Ok(Err(structure(format!(
            "auto_reverse_on {} must follow the effective date {}",
            reverse_on.render(),
            p.effective_date.render()
        ))));
    }
    if book_policy(db)?.is_none() {
        return Ok(Err(Refusal::new(
            code::CLASS_NOT_IMPLEMENTED,
            exit::REFUSAL,
            "this book declares no time_zone_policy, so no tick can become the civil date a scheduled reversal waits for",
            "plan §7.7 (the book's time_zone_policy governs instant → civil date; always explicit)",
            "declare the policy at genesis (BookSpec.time_zone_policy = Utc; `fa book create --time-zone UTC`), or post the reversal by hand when it is due",
        )));
    }
    match period_of(book, reverse_on)? {
        Ok(period) => Ok(Ok(Some((reverse_on, period)))),
        Err(e) => Ok(Err(Refusal::new(
            code::PERIOD_RESOLVE,
            exit::REFUSAL,
            format!(
                "auto_reverse_on {} does not resolve to one normal period: {e}",
                reverse_on.render()
            ),
            "plan §7.3 (period law), §7.6",
            "choose a reversal date inside a normal period of the calendar",
        ))),
    }
}

/// The properties of the `ReversalSchedule` vertex of `target` (sorted).
fn schedule_props(
    target: EntryRef,
    reverse_on: DateDay,
    period: &str,
) -> Result<Vec<(fgdb_delta_types::PropertyKeyId, CanonicalScalar)>, KernelError> {
    let mut target_ref = Vec::with_capacity(48);
    target_ref.extend_from_slice(&target.vid.0.to_le_bytes());
    target_ref.extend_from_slice(&target.entry_digest);
    let mut props = vec![
        (
            property::TARGET_REF,
            scalar_bytes("target_ref", target_ref)?,
        ),
        (
            property::REVERSE_ON,
            CanonicalScalar::Int(i64::from(reverse_on.0)),
        ),
        (
            property::EFFECTIVE_PERIOD,
            scalar_text("effective_period", period)?,
        ),
        (property::EXEC_OP, scalar_text("exec_op", EXEC_OP)?),
        (
            property::EFFECTS_DIGEST,
            scalar_bytes(
                "effects_digest",
                effects_digest(target, reverse_on, RULE_EXACT_NEGATION).to_vec(),
            )?,
        ),
    ];
    props.sort_by_key(|(k, _)| k.0);
    Ok(props)
}

/// Stage the `ReversalSchedule` vertex of the entry being posted (post.rs
/// step 8, the Adjusting's own commit).
pub(crate) fn stage_schedule(
    batch: &mut WriteBatch,
    tracker: &mut crate::batch::TemplateByteTracker,
    target: EntryRef,
    reverse_on: DateDay,
    period: &str,
) -> Result<VId, KernelError> {
    let svid = schedule_vid(target.vid);
    let props = schedule_props(target, reverse_on, period)?;
    tracker.create_vertex(relation::HAS_LEG, svid, 1, &props);
    batch.create_vertex(svid, vec![label::REVERSAL_SCHEDULE], props);
    Ok(svid)
}

/// A stored `ReversalSchedule` vertex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schedule {
    pub vid: VId,
    pub target: EntryRef,
    pub reverse_on: DateDay,
    pub period: String,
    pub exec_op: String,
    pub effects_digest: [u8; 32],
    /// The target's commit (the schedule is created in it).
    pub recorded_at: CommitSeq,
}

/// Decode a stored schedule; any missing or malformed mirror is corruption.
pub fn decode_schedule(row: &VertexRow) -> Result<Schedule, KernelError> {
    let bad = |what: &str| {
        KernelError::Corrupt(format!(
            "reversal schedule {:032x}: {what}; `fa verify schedules` names it",
            row.vid.0
        ))
    };
    let target = match prop(row, property::TARGET_REF) {
        Some(CanonicalScalar::Bytes(b)) if b.as_slice().len() == 48 => {
            let raw = b.as_slice();
            let mut vid = [0u8; 16];
            vid.copy_from_slice(&raw[..16]);
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&raw[16..]);
            EntryRef {
                vid: VId(u128::from_le_bytes(vid)),
                entry_digest: digest,
            }
        }
        _ => return Err(bad("target_ref")),
    };
    let reverse_on = match prop(row, property::REVERSE_ON) {
        Some(CanonicalScalar::Int(d)) => {
            DateDay(i32::try_from(*d).map_err(|_| bad("reverse_on out of range"))?)
        }
        _ => return Err(bad("reverse_on")),
    };
    let text = |key, what| crate::rows::text(row, key, what).map_err(|_| bad(what));
    let effects_digest = match prop(row, property::EFFECTS_DIGEST) {
        Some(CanonicalScalar::Bytes(b)) => {
            <[u8; 32]>::try_from(b.as_slice()).map_err(|_| bad("effects_digest width"))?
        }
        _ => return Err(bad("effects_digest")),
    };
    Ok(Schedule {
        vid: row.vid,
        target,
        reverse_on,
        period: text(property::EFFECTIVE_PERIOD, "effective_period")?,
        exec_op: text(property::EXEC_OP, "exec_op")?,
        effects_digest,
        recorded_at: row.created_at,
    })
}

/// Where a live schedule stands at the latest tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReversalStatus {
    /// Its period admits a Reversal under the schedule's authority: the next
    /// reversal sweep mints it (unless the availability law blocks it then).
    Due,
    /// Its period does not exist yet or is still Future: the `Open`
    /// transition mints it.
    Waiting { period: String },
    /// Its period's Reversal row (or a live application on the target)
    /// refuses the scheduler: reported, never minted; reverse it by hand.
    Blocked { state: PeriodState, row: String },
}

/// One live schedule whose date the latest tick has reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DueReversal {
    pub schedule: Schedule,
    pub status: ReversalStatus,
}

/// The Reversal row's verdict on the scheduler (which holds `exec_op`).
fn row_status(matrix: &Admissibility, state: PeriodState, period: &str) -> ReversalStatus {
    if state == PeriodState::Future {
        return ReversalStatus::Waiting {
            period: period.to_string(),
        };
    }
    match matrix.decide("Reversal", state) {
        Some(Decision::Admit) => ReversalStatus::Due,
        Some(Decision::With { op, .. }) if op == EXEC_OP => ReversalStatus::Due,
        _ => ReversalStatus::Blocked {
            state,
            row: format!("admissibility.toml (Reversal, {})", state.name()),
        },
    }
}

const LIVE_APPLICATIONS_ROW: &str = "plan §5.7 (live applications against the target)";

/// The live schedules whose date the latest tick has reached, in the commit
/// order of their targets, with their status (plan §7.6, R4): `Due`,
/// `Waiting { period }`, or `Blocked { state, row }`. Empty when the book
/// declares no `time_zone_policy` or has no tick. Uses the paged `SweepIndex`
/// when servable; execution re-reads everything as witnesses.
pub fn due_reversals<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
) -> Result<Vec<DueReversal>, KernelError> {
    Ok(due_reversals_with_witness(db, book)?.0)
}

/// [`due_reversals`] together with a [`crate::sweep::SweepReadWitness`]
/// recording the substrate reads performed during candidate discovery
/// (FA-CFG-02).
pub fn due_reversals_with_witness<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
) -> Result<(Vec<DueReversal>, crate::sweep::SweepReadWitness), KernelError> {
    let mut witness = crate::sweep::SweepReadWitness::default();
    witness.substrate_rows_read += 2;
    let (Some(policy), Some(tick)) = (book_policy(db)?, latest_tick(db)?) else {
        return Ok((Vec::new(), witness));
    };
    let today = policy.civil_date(tick.observed_utc_ns);
    let classes = EntryClasses::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let matrix =
        Admissibility::embedded(&classes).map_err(|e| KernelError::Corrupt(e.to_string()))?;

    let candidates = match indexed_due_schedules(db, book, today) {
        Ok(Some((scheds, idx_witness))) => {
            witness.used_index = true;
            witness.pages_read += idx_witness.pages_read;
            witness.candidates_read += idx_witness.candidates_read;
            witness.substrate_rows_read += idx_witness.substrate_rows_read;
            witness.delta_batches_read += idx_witness.delta_batches_read;
            witness.unrelated_entries_decoded += idx_witness.unrelated_entries_decoded;
            scheds
        }
        _ => {
            let rows = db.vertices()?;
            witness.substrate_rows_read += rows.len();
            let mut scheds = Vec::new();
            for row in rows {
                if !row.labels.contains(&label::REVERSAL_SCHEDULE) {
                    continue;
                }
                let schedule = decode_schedule(&row)?;
                if schedule.reverse_on > today {
                    continue;
                }
                witness.candidates_read += 1;
                witness.substrate_rows_read += 1;
                if db.vertex(reversal_vid(schedule.target.vid))?.is_some() {
                    continue;
                }
                scheds.push(schedule);
            }
            scheds
        }
    };

    let mut out = Vec::with_capacity(candidates.len());
    for schedule in candidates {
        witness.substrate_rows_read += 1;
        let status = match db.vertex(period_vid(&book.calendar.id, &schedule.period))? {
            None => ReversalStatus::Waiting {
                period: schedule.period.clone(),
            },
            Some(prow) => {
                let state = state_from_scalar(prop(&prow, property::STATE)).ok_or_else(|| {
                    KernelError::Corrupt(format!("period `{}` state mirror", schedule.period))
                })?;
                match row_status(&matrix, state, &schedule.period) {
                    ReversalStatus::Due if live_applications(db, &schedule)? => {
                        ReversalStatus::Blocked {
                            state,
                            row: LIVE_APPLICATIONS_ROW.into(),
                        }
                    }
                    ReversalStatus::Due => {
                        witness.substrate_rows_read += 1;
                        let row = db.vertex(schedule.target.vid)?.ok_or_else(|| {
                            KernelError::Corrupt("a scheduled target is missing".into())
                        })?;
                        let target = decode_entry(&row)?;
                        match crate::post::admit_accounts(
                            db,
                            book,
                            EntryClass::REVERSAL,
                            schedule.reverse_on,
                            &target.proposal.legs,
                            |vid| Ok(db.vertex(vid)?),
                        )? {
                            Ok(_) => ReversalStatus::Due,
                            Err(refusal) => ReversalStatus::Blocked {
                                state,
                                row: refusal_reason(&refusal),
                            },
                        }
                    }
                    s => s,
                }
            }
        };
        out.push(DueReversal { schedule, status });
    }
    out.sort_by_key(|d| (d.schedule.recorded_at, d.schedule.vid));
    Ok((out, witness))
}

fn indexed_due_schedules<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    today: DateDay,
) -> Result<Option<(Vec<Schedule>, crate::sweep::SweepReadWitness)>, KernelError> {
    let Some((state, _)) = crate::sweep::load_servable_sweep_index(db)? else {
        return Ok(None);
    };
    if state.book_id != book.book_id {
        return Ok(None);
    }
    let Some(mut tail) =
        crate::sweep::fold_sweep_delta_tail(db, state.through, state.latest_corroborated_tick)?
    else {
        return Ok(None);
    };
    tail.witness.used_index = true;
    tail.witness.substrate_rows_read += 1;

    let cutoff = i128::from(today.0);
    let mut due = Vec::new();
    for meta in &state.schedule_pages {
        if meta.min_key > cutoff {
            continue;
        }
        tail.witness.pages_read += 1;
        tail.witness.substrate_rows_read += 1;
        let Some(schedules) = crate::sweep::read_schedule_page_checked(db, book.book_id, meta)?
        else {
            return Ok(None);
        };
        for s in schedules {
            if s.reverse_on > today || tail.reversed_targets.contains(&s.target.vid) {
                continue;
            }
            tail.witness.candidates_read += 1;
            tail.witness.substrate_rows_read += 1;
            if db.vertex(reversal_vid(s.target.vid))?.is_some() {
                continue;
            }
            due.push(s);
        }
    }
    for s in tail.added_schedules.into_values() {
        if s.reverse_on > today || tail.reversed_targets.contains(&s.target.vid) {
            continue;
        }
        tail.witness.candidates_read += 1;
        tail.witness.substrate_rows_read += 1;
        if db.vertex(reversal_vid(s.target.vid))?.is_some() {
            continue;
        }
        due.push(s);
    }
    Ok(Some((due, tail.witness)))
}

fn live_applications<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    schedule: &Schedule,
) -> Result<bool, KernelError> {
    let Some(row) = db.vertex(schedule.target.vid)? else {
        return Err(KernelError::Corrupt("a scheduled target is missing".into()));
    };
    let target = decode_entry(&row)?;
    for i in 0..target.proposal.legs.len() {
        let ordinal =
            u16::try_from(i).map_err(|_| KernelError::Corrupt("more than u16 legs".into()))?;
        let leg = db
            .vertex(leg_vid(schedule.target.vid, ordinal))?
            .ok_or_else(|| KernelError::Corrupt("a scheduled target's leg is missing".into()))?;
        if applied_witness(&leg)? != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The exact side swap of `legs` (`Reverses`): native mantissas, base
/// valuations, dimensions and memos preserved; no applications (the undo of
/// a target's own applications is derived, and a scheduled target has none).
fn swapped(legs: &[LegPayload]) -> Vec<LegPayload> {
    legs.iter()
        .map(|l| LegPayload {
            side: match l.side {
                Side::Debit => Side::Credit,
                Side::Credit => Side::Debit,
            },
            settles: Vec::new(),
            ..l.clone()
        })
        .collect()
}

/// The writes of the reversals one transaction mints, and what it blocked.
pub(crate) struct Mints {
    has_leg: WriteBatch,
    cells: BTreeMap<VId, CellRun>,
    accounts: BTreeMap<VId, AccountRow>,
    tracker: crate::batch::TemplateByteTracker,
    /// Corroborated tick used by an Open preparation, including an empty
    /// candidate population. Other minting paths do not use this field.
    pub(crate) opening_tick: Option<VId>,
    /// `(target, reversal)` in mint order.
    pub(crate) minted: Vec<(EntryRef, EntryRef)>,
    /// `(target, why)`.
    pub(crate) blocked: Vec<(EntryRef, String)>,
}

impl Mints {
    pub(crate) fn new() -> Self {
        Self {
            has_leg: WriteBatch::new(relation::HAS_LEG),
            cells: BTreeMap::new(),
            accounts: BTreeMap::new(),
            tracker: crate::batch::TemplateByteTracker::default(),
            opening_tick: None,
            minted: Vec::new(),
            blocked: Vec::new(),
        }
    }

    /// Exact footprint of the staged reversal entries and their final limit
    /// cells. An opening planner adds its control and retained certificate
    /// to this same tracker before admitting the complete transaction.
    pub(crate) fn template_tracker(
        &self,
    ) -> Result<crate::batch::TemplateByteTracker, KernelError> {
        let mut tracker = self.tracker.clone();
        for (cell, run) in &self.cells {
            tracker.record_limit_cell_move(relation::HAS_LEG, *cell, &run.before, &run.after)?;
        }
        Ok(tracker)
    }

    /// The batches to write (limit cells staged as compare-and-sets).
    pub(crate) fn into_batches(mut self) -> Result<Vec<WriteBatch>, KernelError> {
        for (cell, run) in &self.cells {
            run.before.stage(&run.after, *cell, &mut self.has_leg)?;
        }
        let mut out = vec![self.has_leg];
        out.retain(|b| !b.is_empty());
        Ok(out)
    }
}

/// The availability law on the reversal's posted legs, composed with the
/// moves already staged in `mints` (one generation per entry per cell).
/// `Ok(Some(why))` blocks the mint and leaves `mints` unchanged.
fn judge_limits(
    mut read_vertex: impl FnMut(VId) -> Result<Option<fgdb::VertexRow>, KernelError>,
    book: &BookContext,
    mints: &mut Mints,
    legs: &[LegPayload],
    period: &str,
) -> Result<Option<String>, KernelError> {
    let mut moves: BTreeMap<VId, (VId, Option<String>, Movement)> = BTreeMap::new();
    for leg in legs {
        let account = match mints.accounts.entry(leg.account_ref) {
            MapEntry::Occupied(o) => o.into_mut(),
            MapEntry::Vacant(v) => {
                let row = read_vertex(leg.account_ref)?.ok_or_else(|| {
                    KernelError::Corrupt("a scheduled target's account is missing".into())
                })?;
                v.insert(AccountRow::decode(&row)?)
            }
        };
        let Some(lim) = account.limit else {
            continue;
        };
        let cell_period = match lim.scope {
            LimitScope::Lifetime => None,
            LimitScope::Period => Some(period.to_string()),
        };
        let cvid = limit::cell_vid(account.vid, cell_period.as_deref());
        moves
            .entry(cvid)
            .or_insert_with(|| (account.vid, cell_period, Movement::default()))
            .2
            .post(leg.side, leg.amount.mantissa)?;
    }
    let mut next: Vec<(VId, LimitCell, LimitCell)> = Vec::with_capacity(moves.len());
    for (cvid, (account_vid, cell_period, m)) in moves {
        let account = mints
            .accounts
            .get(&account_vid)
            .ok_or_else(|| KernelError::Corrupt("judged account row".into()))?;
        let lim = account
            .limit
            .ok_or_else(|| KernelError::Corrupt("judged account has no limit".into()))?;
        let (before, current) = match mints.cells.get(&cvid) {
            Some(run) => (run.before, run.after),
            None => {
                let row = read_vertex(cvid)?
                    .filter(|r| r.labels.contains(&label::LIMIT_CELL))
                    .ok_or_else(|| {
                        KernelError::Corrupt(format!(
                            "limited account `{}` has no limit cell; `fa verify availability` names it",
                            account.code
                        ))
                    })?;
                let c = LimitCell::decode_bound(&row, account_vid, cell_period.as_deref())?;
                (c, c)
            }
        };
        let normal = if account.normal_balance == 0 {
            Side::Debit
        } else {
            Side::Credit
        };
        match limit::apply(&current, normal, &lim, &m)? {
            Ok(after) => next.push((cvid, before, after)),
            Err(breach) => {
                let crate::genesis::UnitPolicy::Single(unit) = account.unit_policy else {
                    return Err(KernelError::Corrupt(format!(
                        "limited account `{}` has no single unit",
                        account.code
                    )));
                };
                let r = limit::refusal(
                    &breach,
                    &account.code,
                    cell_period.as_deref(),
                    unit,
                    &book.units,
                );
                return Ok(Some(format!("{}: {}", r.code, r.message)));
            }
        }
    }
    for (cvid, before, after) in next {
        mints.cells.insert(cvid, CellRun { before, after });
    }
    Ok(None)
}

fn refusal_reason(refusal: &Refusal) -> String {
    format!("{}: {}", refusal.code, refusal.message)
}

fn execution_refusal(
    mints: &mut Mints,
    schedule: &Schedule,
    trigger: ScheduleTrigger,
    refusal: Refusal,
) -> Outcome<bool> {
    if matches!(trigger, ScheduleTrigger::Sweep { .. }) {
        mints
            .blocked
            .push((schedule.target, refusal_reason(&refusal)));
        Ok(Ok(true))
    } else {
        // Open cannot silently record an authority-dependent block that its
        // exact historical retry cannot reproduce from immutable sources.
        Ok(Err(refusal))
    }
}

/// Recheck the original quote-based calculation under transaction witnesses.
/// The schedule already binds the immutable Adjusting entry, so its original
/// date, period and sides are the valuation context even when the reversal is
/// published in a later period. No current-date quote is selected.
fn inherited_valuation<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    original: &EntryPayload,
    reversal: &EntryPayload,
) -> Outcome<()> {
    if !crate::post::exact_side_swap(original, reversal) {
        return Err(KernelError::Corrupt(
            "a scheduled reversal does not preserve its bound native and functional effects".into(),
        ));
    }
    if original.base_totals.is_none() {
        return Ok(Ok(()));
    }
    let spec = match txn.vertex_property(db, book_root(), property::FA_PAYLOAD)? {
        Some(CanonicalScalar::Bytes(payload)) => crate::genesis::BookSpec::decode(payload.as_slice())?,
        _ => {
            return Err(KernelError::Corrupt(
                "a scheduled valuation has no canonical book declaration".into(),
            ));
        }
    };
    if spec.book_id != book.book_id
        || spec.calendar != book.calendar
        || original
            .effective_period
            .as_ref()
            .is_some_and(|period| period.calendar != spec.calendar.id)
    {
        return Err(KernelError::Corrupt(
            "a scheduled valuation disagrees with its original book or fiscal calendar".into(),
        ));
    }
    let entities = match crate::entity::leg_entities(&spec, &reversal.legs) {
        Ok(entities) => entities,
        Err(crate::entity::LegEntityError::Refused(refusal)) => return Ok(Err(refusal)),
        Err(crate::entity::LegEntityError::OtherDimension) => {
            return Err(KernelError::Corrupt(
                "a scheduled valuation has an unregistered dimension".into(),
            ));
        }
    };
    let claim = match crate::fx::admit_structure(reversal, &spec, &entities, &book.units) {
        Ok(Some(claim)) => claim,
        Ok(None) => {
            return Err(KernelError::Corrupt(
                "a valued scheduled reversal lost its FX claim".into(),
            ));
        }
        Err(refusal) => return Ok(Err(refusal)),
    };
    let periods = spec
        .calendar
        .periods_for_year(spec.calendar.fiscal_year_of(original.effective_date)?)?;
    let source_period = resolve_period(
        &periods,
        original.effective_date,
        original
            .effective_period
            .as_ref()
            .map(|period| period.code.as_str()),
    )
    .map_err(|error| {
        KernelError::Corrupt(format!(
            "a scheduled valuation has no original fiscal period: {error:?}",
        ))
    })?;
    crate::fx::verify_in_txn(
        txn,
        db,
        &spec,
        source_period,
        &book.units,
        &entities,
        reversal,
        &claim,
        Some((original, source_period)),
    )
}

/// Mint (or block) the scheduled reversal of `schedule` inside `txn`, in a
/// period of `state`, under `tick`'s evidence (plan §7.6). The envelope is
/// fully determined by the schedule. Its actual effects undergo shared native
/// authority and account admission, availability, reconciliation, daily usage,
/// the Reversal row, live applications and SoD (default row, no approvals).
/// `Ok(Err)` refuses the whole transaction; a block is recorded in `mints`.
/// `Ok(Ok(false))` stops the batch before this schedule so the transaction
/// stays within `MAX_BATCH_TEMPLATE_BYTES` (`fa-gbkc`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn mint<V: asupersync::fs::Vfs + Clone>(
    txn: &mut WriteTxn,
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &fa_policy::Capability,
    matrix: &Admissibility,
    mints: &mut Mints,
    schedule: &Schedule,
    state: PeriodState,
    policy: TimeZonePolicy,
    tick: Tick,
    trigger: ScheduleTrigger,
    executor: Party,
    epoch: u64,
) -> Outcome<bool> {
    // A period-scoped opener must reach the accrual being undone before
    // its payload is observed, just as a manually posted Reversal must.
    if capability.is_scoped() {
        let current = match policy::current_at(db, book, capability)? {
            Ok(current) => current,
            Err(refusal) => return execution_refusal(mints, schedule, trigger, refusal),
        };
        let scope = policy::account_scope(db, book, &current)?;
        if !policy::entry_in_scope_by_metadata(
            txn,
            db,
            book,
            capability,
            scope.as_ref(),
            schedule.target.vid,
        )? {
            return execution_refusal(
                mints,
                schedule,
                trigger,
                policy::refusal(&fa_policy::Denial::OutOfScope {
                    caveat: "scheduled_target",
                    value: "the original accrual's complete account and effective-date footprint"
                        .into(),
                }),
            );
        }
    }
    let target_row = txn
        .vertex(db, schedule.target.vid)?
        .ok_or_else(|| KernelError::Corrupt("a scheduled target is missing".into()))?;
    let target = decode_entry(&target_row)?;
    if target.entry_digest != schedule.target.entry_digest
        || schedule.effects_digest
            != effects_digest(schedule.target, schedule.reverse_on, RULE_EXACT_NEGATION)
    {
        return Err(KernelError::Corrupt(format!(
            "reversal schedule {:032x} does not bind its target; `fa verify schedules` names it",
            schedule.vid.0
        )));
    }
    let rvid = reversal_vid(schedule.target.vid);
    if txn.vertex(db, rvid)?.is_some() {
        return Ok(Err(conflict(
            "the scheduled reversal",
            format!("target {:032x} was reversed", schedule.target.vid.0),
        )));
    }
    match row_status(matrix, state, &schedule.period) {
        ReversalStatus::Due => {}
        ReversalStatus::Waiting { period } => {
            mints
                .blocked
                .push((schedule.target, format!("waiting for period `{period}`")));
            return Ok(Ok(true));
        }
        ReversalStatus::Blocked { row, .. } => {
            mints.blocked.push((schedule.target, row));
            return Ok(Ok(true));
        }
    }
    for i in 0..target.proposal.legs.len() {
        let ordinal =
            u16::try_from(i).map_err(|_| KernelError::Corrupt("more than u16 legs".into()))?;
        let leg = txn
            .vertex(db, leg_vid(schedule.target.vid, ordinal))?
            .ok_or_else(|| KernelError::Corrupt("a scheduled target's leg is missing".into()))?;
        if applied_witness(&leg)? != 0 {
            mints
                .blocked
                .push((schedule.target, LIVE_APPLICATIONS_ROW.into()));
            return Ok(Ok(true));
        }
    }
    let legs = swapped(&target.proposal.legs);
    let mut extensions = vec![(DATE_BASIS_EXTENSION, date_basis_bytes(policy, tick.entry))];
    // These source commitments survive an exact manual reversal too. The
    // original auto-reversal request itself never propagates to its result.
    extensions.extend(
        target
            .proposal
            .extensions
            .iter()
            .filter(|(tag, _)| {
                matches!(
                    *tag,
                    fa_model::entry::ASSET_CHARGE_EXTENSION
                        | fa_model::entry::LOT_DISPOSAL_EXTENSION
                        | fa_model::entry::FX_SETTLEMENT_VALUATION_EXTENSION
                )
            })
            .cloned(),
    );
    extensions.sort_by_key(|(tag, _)| *tag);
    let proposal = EntryPayload {
        schema_minor: target
            .proposal
            .schema_minor
            .max(fa_model::entry::EXTENSIONS_MINOR),
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::REVERSAL,
        effective_date: schedule.reverse_on,
        document_date: None,
        description: target.proposal.description.clone(),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs)?,
        legs,
        control: None,
        base_totals: target.proposal.base_totals.clone(),
        idempotency_key: format!("scheduled:{:032x}", schedule.target.vid.0).into_bytes(),
        // Authorship travels through the schedule's lineage (the target, its
        // proposal and approvals); the entry is the book's own (CobaltGull
        // 3183 D1), identical on both paths but for the trigger.
        origin: EntryOrigin::Schedule {
            schedule_ref: schedule.vid,
            trigger,
        },
        principal_ref: system_principal(book.book_id),
        session_ref: None,
        evidence: target
            .proposal
            .evidence
            .iter()
            .filter(|evidence| evidence.role == crate::fx::RATE_EVIDENCE_ROLE)
            .copied()
            .collect(),
        supersession: vec![Supersession {
            target: schedule.target,
            kind: SupersessionKind::Reverses,
            reason_code: fa_registry::reason_codes::SCHEDULED_ACCRUAL_REVERSAL,
        }],
        pending: None,
        external_ids: Vec::new(),
        extensions,
        tags: Vec::new(),
    };
    // System is attribution, not ambient authority. The actual executor
    // must authorize every leg at execution; the transaction retains its
    // revocation/issuance witness and the current policy epoch.
    match crate::post::authorize_effects(
        db,
        book,
        capability,
        capability.holder(),
        &proposal,
        false,
    )? {
        Ok(_) => {}
        Err(refusal) => return execution_refusal(mints, schedule, trigger, refusal),
    };
    if capability.has_requires_dry_run_caveat() {
        return execution_refusal(
            mints,
            schedule,
            trigger,
            policy::refusal(&fa_policy::Denial::OutOfScope {
                caveat: "requires_dry_run",
                value: "an automatic reversal without a verified posting certificate".into(),
            }),
        );
    }
    if let Err(refusal) = policy::capability_witness(txn, db, book, capability)? {
        return execution_refusal(mints, schedule, trigger, refusal);
    }
    if let Err(refusal) = inherited_valuation(txn, db, book, &target.proposal, &proposal)? {
        return execution_refusal(mints, schedule, trigger, refusal);
    }
    let evidence_policy =
        EvidencePolicy::embedded().map_err(|error| KernelError::Corrupt(error.to_string()))?;
    let evidence = match crate::evidence::resolve_evidence(txn, db, &evidence_policy, &proposal)? {
        Ok(evidence) => evidence,
        Err(refusal) => return execution_refusal(mints, schedule, trigger, refusal),
    };
    match crate::post::admit_accounts(
        db,
        book,
        EntryClass::REVERSAL,
        schedule.reverse_on,
        &proposal.legs,
        |vid| Ok(txn.vertex(db, vid)?),
    )? {
        Ok(_) => {}
        Err(refusal) => {
            mints
                .blocked
                .push((schedule.target, refusal_reason(&refusal)));
            return Ok(Ok(true));
        }
    }
    let reconciliation = match crate::post::reconciliation_citations(
        txn,
        db,
        ctx,
        book,
        capability,
        schedule.reverse_on,
        &proposal.legs,
        &mut None,
    )? {
        Ok(citations) => citations,
        Err(refusal) => return execution_refusal(mints, schedule, trigger, refusal),
    };
    if let Err(e) = proposal.validate() {
        return Err(KernelError::Corrupt(format!(
            "a scheduled reversal is malformed: {e}"
        )));
    }
    if let Err(r) = policy::authorize_approvals(
        txn,
        db,
        book,
        &[],
        &proposal.proposal_digest()?,
        epoch,
        &fa_policy::sod::posting_key("Reversal", state, false),
        0,
        executor,
    )? {
        return Ok(Err(r));
    }
    if let Err(refusal) = crate::outcome::require_fresh_key(txn, db, book, &proposal, rvid)? {
        return Ok(Err(refusal));
    }
    let entry = proposal.seal(Vec::new(), None)?;
    let usage = match crate::usage::judge(txn, db, ctx, book, capability, &entry, rvid)? {
        Ok(usage) => usage,
        Err(refusal) => return execution_refusal(mints, schedule, trigger, refusal),
    };
    if let Err(refusal) = crate::register_capacity::admit_addition(
        txn,
        db,
        ctx,
        mints.minted.iter().map(|(_, r)| r.vid),
        rvid,
        &entry,
    )? {
        return execution_refusal(mints, schedule, trigger, refusal);
    }
    let mirrors = entry_mirrors(&entry)?;
    let mut next_tracker = mints.tracker.clone();
    next_tracker.create_vertex(relation::HAS_LEG, rvid, 1, &mirrors);
    next_tracker.record_entry_outcome_claim(relation::HAS_LEG, &entry.proposal);
    next_tracker.record_legs(rvid, &entry, book)?;
    next_tracker.add_edge(relation::IN_PERIOD, &[]);
    next_tracker.add_edge(relation::SUPERSEDES, &[]);
    for _ in &evidence.documents {
        next_tracker.add_edge(relation::EVIDENCED_BY, &[]);
    }
    if evidence.manual_assertion.is_some() {
        next_tracker.add_edge(relation::ATTESTS, &[]);
    }
    if let Some(usage) = &usage {
        usage.record_template_bytes(&mut next_tracker)?;
    }
    for _ in &reconciliation {
        next_tracker.add_edge(relation::CITES, &[]);
    }
    let cell_and_cursor_reserve = (mints.cells.len() + entry.proposal.legs.len()) * 400 + 4096;
    if !mints.minted.is_empty()
        && next_tracker.total_bytes() + cell_and_cursor_reserve
            > fa_model::limits::MAX_BATCH_TEMPLATE_BYTES
    {
        return Ok(Ok(false));
    }
    if let Some(why) = judge_limits(
        |vid| Ok(txn.vertex(db, vid)?),
        book,
        mints,
        &entry.proposal.legs,
        &schedule.period,
    )? {
        mints.blocked.push((schedule.target, why));
        return Ok(Ok(true));
    }
    mints.tracker = next_tracker;
    let pvid = period_vid(&book.calendar.id, &schedule.period);
    let mut has_leg = WriteBatch::new(relation::HAS_LEG);
    has_leg.create_vertex(rvid, vec![label::ENTRY], mirrors);
    crate::outcome::stage_entry(&mut has_leg, &entry, rvid)?;
    let leg_edges = crate::projections::stage_legs(&mut has_leg, rvid, &entry, book)?;
    let mut in_period = WriteBatch::new(relation::IN_PERIOD);
    in_period.add_edge(edge_id(relation::IN_PERIOD, rvid, pvid), rvid, pvid, vec![]);
    let mut supersedes = WriteBatch::new(relation::SUPERSEDES);
    supersedes.add_edge(
        edge_id(relation::SUPERSEDES, rvid, schedule.target.vid),
        rvid,
        schedule.target.vid,
        vec![],
    );
    let usage_edges = usage
        .as_ref()
        .map(|usage| usage.stage(&mut has_leg))
        .transpose()?;
    let mut batches = vec![has_leg, in_period, supersedes];
    batches.extend(leg_edges);
    batches.extend(crate::evidence::evidence_edges(rvid, &evidence));
    if let Some(edges) = usage_edges {
        batches.extend(edges);
    }
    if let Some(edges) = crate::post::reconciliation_edges(rvid, &reconciliation) {
        batches.push(edges);
    }
    // Dimensionless legs have no FOR edges; the substrate rejects empty
    // relation batches, just as it does on the ordinary posting path.
    // A reversal without party legs is one such case.
    batches.retain(|batch| !batch.is_empty());
    // The next reversal must observe this entry and quota receipt in the
    // same overlay. Publishing remains the caller's single atomic commit.
    txn.write_ordered(db, batches)?;
    mints.minted.push((schedule.target, entry.entry_ref(rvid)));
    Ok(Ok(true))
}

/// Inside the `Open` transition of `period` (plan §7.6 rule (b), R5): mint
/// the live schedules dated in it whose date the latest committed tick —
/// when its source's monotonic clock corroborated it — has reached (at
/// most `max_batch_entries`; any rest is the sweep's, the period being
/// Open). Every read is a witness of the transition's transaction;
/// minted reversals are dated in the period being opened, which they find
/// Open.
pub(crate) fn mint_on_open<V: asupersync::fs::Vfs + Clone>(
    txn: &mut WriteTxn,
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &fa_policy::Capability,
    period: &str,
    transition_ref: VId,
) -> Outcome<Mints> {
    // Authorship remains the book's System principal. The transition's
    // admitted capability must also hold Reconcile if its automatic effects
    // reach an already-attested cash cutoff.
    let executor = Party {
        principal: system_principal(book.book_id),
        profile: fa_policy::Profile::System,
    };
    let mut mints = Mints::new();
    let Some(policy) = book_policy(db)? else {
        return Ok(Ok(mints));
    };
    let (_, Some(tick)) = tick_witness(txn, db)? else {
        return Ok(Ok(mints));
    };
    // An uncorroborated latest tick reaches no date (automatic effects take
    // time only from a corroborated committed tick, sweep.rs
    // `corroborated_at_head`): the schedules stay Waiting for the reversal
    // sweep under the next corroborated tick, rule (a).
    let tick_row = txn
        .vertex(db, tick.entry)?
        .ok_or_else(|| KernelError::Corrupt("the latest tick's entry is missing".into()))?;
    if !tick_corroborated(&tick_row)? {
        return Ok(Ok(mints));
    }
    mints.opening_tick = Some(tick.entry);
    let today = policy.civil_date(tick.observed_utc_ns);
    let mut due: Vec<Schedule> = Vec::new();
    // The candidate population is itself a dependency, including when it
    // is empty. A schedule posted after preparation must invalidate Open
    // instead of being silently omitted from its automatic reversals.
    for row in txn.vertices(db)? {
        if !row.labels.contains(&label::REVERSAL_SCHEDULE) {
            continue;
        }
        let s = decode_schedule(&row)?;
        if s.period == period
            && s.reverse_on <= today
            && txn.vertex(db, reversal_vid(s.target.vid))?.is_none()
        {
            due.push(s);
        }
    }
    if due.is_empty() {
        return Ok(Ok(mints));
    }
    due.sort_by_key(|s| (s.recorded_at, s.vid));
    due.truncate(MAX_BATCH_ENTRIES);
    let epoch = policy::epoch_witness(txn, db)?;
    let classes = EntryClasses::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let matrix =
        Admissibility::embedded(&classes).map_err(|e| KernelError::Corrupt(e.to_string()))?;
    for s in &due {
        let row = txn
            .vertex(db, s.vid)?
            .ok_or_else(|| KernelError::Corrupt("a reversal schedule vanished".into()))?;
        let s = decode_schedule(&row)?;
        match mint(
            txn,
            db,
            ctx,
            book,
            capability,
            &matrix,
            &mut mints,
            &s,
            PeriodState::Open,
            policy,
            tick,
            ScheduleTrigger::OpenPeriod { transition_ref },
            executor,
            epoch,
        )? {
            Ok(true) => {}
            Ok(false) => break,
            Err(r) => return Ok(Err(r)),
        }
    }
    Ok(Ok(mints))
}

/// Reconstruct the `(minted, blocked)` lists of a previously committed `Open`
/// transition at `recorded_at` for idempotent retry (`fa-l93` D13).
#[allow(clippy::type_complexity)]
pub(crate) fn recorded_open_mints<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period: &str,
    transition_ref: VId,
    recorded_at: CommitSeq,
) -> Result<(Vec<(EntryRef, EntryRef)>, Vec<(EntryRef, String)>), KernelError> {
    let before = CommitSeq(recorded_at.0.saturating_sub(1));
    let mut mints = Mints::new();
    let Some(policy) = book_policy(db)? else {
        return Ok((Vec::new(), Vec::new()));
    };
    let Some(root) = crate::sweep::root_row(db, Some(before))? else {
        return Ok((Vec::new(), Vec::new()));
    };
    let Some(tick) = Tick::from_scalar(crate::rows::prop(&root, property::LATEST_TICK))? else {
        return Ok((Vec::new(), Vec::new()));
    };
    let tick_row = db
        .vertex_at(tick.entry, before)?
        .ok_or_else(|| KernelError::Corrupt("the latest tick's entry is missing".into()))?;
    if !tick_corroborated(&tick_row)? {
        return Ok((Vec::new(), Vec::new()));
    }
    let today = policy.civil_date(tick.observed_utc_ns);
    let mut due: Vec<Schedule> = Vec::new();
    for row in db.vertices()? {
        if row.created_at > before || !row.labels.contains(&label::REVERSAL_SCHEDULE) {
            continue;
        }
        let s = decode_schedule(&row)?;
        if s.period == period
            && s.reverse_on <= today
            && db.vertex_at(reversal_vid(s.target.vid), before)?.is_none()
        {
            due.push(s);
        }
    }
    if due.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    due.sort_by_key(|s| (s.recorded_at, s.vid));
    due.truncate(MAX_BATCH_ENTRIES);
    for s in &due {
        let target_row = db
            .vertex_at(s.target.vid, before)?
            .ok_or_else(|| KernelError::Corrupt("a scheduled target is missing".into()))?;
        let target = decode_entry(&target_row)?;
        let legs = swapped(&target.proposal.legs);
        let rvid = reversal_vid(s.target.vid);
        if let Some(rev_row) = db.vertex_at(rvid, recorded_at)? {
            let rev_entry = decode_entry(&rev_row)?;
            if rev_row.created_at == recorded_at
                && matches!(
                    rev_entry.proposal.origin,
                    EntryOrigin::Schedule {
                        trigger: ScheduleTrigger::OpenPeriod {
                            transition_ref: tref
                        },
                        ..
                    } if tref == transition_ref
                )
            {
                let _ = judge_limits(
                    |vid| Ok(db.vertex_at(vid, before)?),
                    book,
                    &mut mints,
                    &legs,
                    &s.period,
                )?;
                mints.minted.push((s.target, rev_entry.entry_ref(rvid)));
                continue;
            }
        }
        let mut applied_blocked = false;
        for i in 0..target.proposal.legs.len() {
            let ordinal =
                u16::try_from(i).map_err(|_| KernelError::Corrupt("more than u16 legs".into()))?;
            let leg = db
                .vertex_at(leg_vid(s.target.vid, ordinal), before)?
                .ok_or_else(|| {
                    KernelError::Corrupt("a scheduled target's leg is missing".into())
                })?;
            if applied_witness(&leg)? != 0 {
                mints.blocked.push((s.target, LIVE_APPLICATIONS_ROW.into()));
                applied_blocked = true;
                break;
            }
        }
        if applied_blocked {
            continue;
        }
        if let Err(refusal) = crate::post::admit_accounts(
            db,
            book,
            EntryClass::REVERSAL,
            s.reverse_on,
            &legs,
            |vid| Ok(db.vertex_at(vid, before)?),
        )? {
            mints.blocked.push((s.target, refusal_reason(&refusal)));
            continue;
        }
        if let Some(why) = judge_limits(
            |vid| Ok(db.vertex_at(vid, before)?),
            book,
            &mut mints,
            &legs,
            &s.period,
        )? {
            mints.blocked.push((s.target, why));
        }
    }
    Ok((mints.minted, mints.blocked))
}

/// One committed scheduled-reversal sweep batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReversalBatch {
    pub tick: Tick,
    /// `(target, its scheduled reversal)`, in the targets' commit order.
    pub minted: Vec<(EntryRef, EntryRef)>,
    /// `(target, why)`: examined, not minted; reverse by hand.
    pub blocked: Vec<(EntryRef, String)>,
    pub cursor_entry: EntryRef,
    pub recorded_at: CommitSeq,
    /// Schedules under this tick the batch bound left for the next batch.
    pub remaining: usize,
}

/// Examine up to `req.max_batch` reached schedules whose periods exist and
/// are not Future, in their targets' commit order after the cursor (when it
/// belongs to the latest tick), minting the admissible ones and blocking the
/// rest, plus one `SweepCursor` (kind 2) — one transaction (plan §7.6 rule
/// (a), §5.4 cursor discipline). `Ok(None)`: nothing reached, nothing
/// written.
pub async fn sweep_reversals_batch<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    req: &SweepRequest,
    describe: &mut crate::sweep::Describe<'_>,
) -> Outcome<Option<ReversalBatch>> {
    let sweep_key = fa_policy::sod::control_key("SweepControl", None, "Reverse");
    if let Err(r) = admit_sweep(db, book, req, &sweep_key)? {
        return Ok(Err(r));
    }
    if let Err(refusal) = crate::scratch::ensure_history(db, ctx).await? {
        return Ok(Err(refusal));
    }
    let (Some(policy), Some(tick)) = (book_policy(db)?, latest_tick(db)?) else {
        return Ok(Ok(None));
    };
    // Automatic effects take time only from a corroborated committed tick;
    // the transaction below witnesses that this tick is still the latest.
    if let Err(r) = corroborated_at_head(db, tick)? {
        return Ok(Err(r));
    }
    let root = root_row(db, None)?.ok_or_else(|| KernelError::Corrupt("no book root".into()))?;
    let cursor = Cursor::from_scalar(prop(&root, property::SCHEDULE_CURSOR))?;
    let mut due: Vec<Schedule> = due_reversals(db, book)?
        .into_iter()
        .filter(|d| !matches!(d.status, ReversalStatus::Waiting { .. }))
        .map(|d| d.schedule)
        .collect();
    if let Some(c) = cursor
        && c.tick == tick.entry
    {
        let last = db.vertex(schedule_vid(c.last_pending))?.ok_or_else(|| {
            KernelError::Corrupt(format!(
                "the schedule cursor names target {:032x}, which has no schedule",
                c.last_pending.0
            ))
        })?;
        let at = (last.created_at, last.vid);
        due.retain(|s| (s.recorded_at, s.vid) > at);
    }
    if due.is_empty() {
        return Ok(Ok(None));
    }
    let take = due.len().min(req.max_batch);
    let mut remaining = due.len() - take;
    due.truncate(take);

    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = policy::capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let (_, witnessed_tick) = tick_witness(&txn, db)?;
    if witnessed_tick != Some(tick) {
        txn.abort();
        return Ok(Err(conflict("the sweep's tick", "a tick committed")));
    }
    let witnessed_cursor = txn.vertex_property(db, book_root(), property::SCHEDULE_CURSOR)?;
    let epoch = policy::epoch_witness(&txn, db)?;
    let tick_row = txn
        .vertex(db, tick.entry)?
        .ok_or_else(|| KernelError::Corrupt("the latest tick's entry is missing".into()))?;
    let tick_digest = decode_entry(&tick_row)?.entry_digest;
    let classes = EntryClasses::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let matrix =
        Admissibility::embedded(&classes).map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let executor = Party {
        principal: req.principal_ref,
        profile: req.capability.profile(),
    };
    let mut mints = Mints::new();
    let mut processed = 0usize;
    for s in &due {
        let row = txn
            .vertex(db, s.vid)?
            .ok_or_else(|| KernelError::Corrupt("a reversal schedule vanished".into()))?;
        let s = decode_schedule(&row)?;
        if s.exec_op != EXEC_OP {
            return Err(KernelError::Corrupt(format!(
                "reversal schedule {:032x} records exec_op `{}`",
                s.vid.0, s.exec_op
            )));
        }
        let pvid = period_vid(&book.calendar.id, &s.period);
        let state = state_from_scalar(txn.vertex_property(db, pvid, property::STATE)?.as_ref())
            .ok_or_else(|| KernelError::Corrupt(format!("period `{}` state mirror", s.period)))?;
        match mint(
            &mut txn,
            db,
            ctx,
            book,
            &req.capability,
            &matrix,
            &mut mints,
            &s,
            state,
            policy,
            tick,
            ScheduleTrigger::Sweep {
                tick_ref: tick.entry,
            },
            executor,
            epoch,
        )? {
            Ok(true) => processed += 1,
            Ok(false) => break,
            Err(r) => {
                txn.abort();
                return Ok(Err(r));
            }
        }
    }
    remaining += due.len() - processed;
    due.truncate(processed);

    let last = due
        .last()
        .map(|s| s.target.vid)
        .ok_or_else(|| KernelError::Corrupt("an empty reversal batch".into()))?;
    let next = Cursor {
        tick: tick.entry,
        last_pending: last,
    };
    let cvid = schedule_cursor_vid(tick.entry, last);
    if txn.vertex(db, cvid)?.is_some() {
        txn.abort();
        return Ok(Err(conflict(
            "the reversal sweep batch",
            "its cursor is already journaled",
        )));
    }
    // A failing `describe` (the caller's entropy) aborts the open
    // transaction: nothing is committed and the cursor does not move.
    let description = match describe(&format!(
        "reversal sweep at tick {} ns: {} minted, {} blocked, {remaining} after this batch",
        tick.observed_utc_ns,
        mints.minted.len(),
        mints.blocked.len()
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
        SWEEP_REVERSAL,
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
        executor,
    )? {
        txn.abort();
        return Ok(Err(r));
    }
    let cursor_entry = cursor_entry.seal(Vec::new(), None)?;
    let minted = mints.minted.clone();
    let blocked = mints.blocked.clone();
    let mut batches = mints.into_batches()?;
    let mut control = WriteBatch::new(relation::IN_BOOK);
    control.create_vertex(cvid, vec![label::ENTRY], entry_mirrors(&cursor_entry)?);
    control.compare_and_set_vertex_property(
        book_root(),
        property::SCHEDULE_CURSOR,
        witnessed_cursor,
        next.scalar()?,
        WriteMismatchPolicy::AbortWrite,
    );
    batches.push(control);
    txn.write_ordered(db, batches)?;
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(Some(ReversalBatch {
            tick,
            minted,
            blocked,
            cursor_entry: cursor_entry.entry_ref(cvid),
            recorded_at: seq,
            remaining,
        }))),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(conflict("a witness of this reversal batch", detail)))
        }
        Err(WriteTxnError::Write(fgdb::WriteError::CompareAndSetMismatch(_))) => Ok(Err(conflict(
            "this reversal batch",
            "the cursor or a limit cell moved",
        ))),
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => Ok(Err(Refusal::new(
            code::CONFLICT,
            exit::CONFLICT,
            "a target in this batch was reversed concurrently (one reversal per target, by identity)",
            "plan §7.6, §8.2 (reversed-once by identity)",
            "rerun the sweep; the reversed target's schedule is cancelled by lineage",
        ))),
        Err(e) => Err(e.into()),
    }
}

/// The cancellation a manual Reversal of `target` journals in its own
/// commit, when `target` has a schedule (plan §7.6, FA-INV-08): staged into
/// `batch` at `H("fa:vid:schedule-cancel:v1" ‖ schedule)`. `Ok(None)` when
/// the target has no schedule. The SoD row `schedule-cancel` is judged with
/// the Reversal's preparer.
#[allow(clippy::too_many_arguments)]
pub(crate) fn cancellation<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    batch: &mut WriteBatch,
    tracker: &mut crate::batch::TemplateByteTracker,
    target: VId,
    reversal: &EntryPayload,
    reversal_vid: VId,
    preparer: Party,
    epoch: u64,
) -> Outcome<Option<VId>> {
    let svid = schedule_vid(target);
    if txn.vertex(db, svid)?.is_none() {
        return Ok(Ok(None));
    }
    let cvid = schedule_cancel_vid(svid);
    if txn.vertex(db, cvid)?.is_some() {
        return Err(KernelError::Corrupt(format!(
            "schedule {:032x} is cancelled but its target is unreversed; `fa verify schedules` names it",
            svid.0
        )));
    }
    let proposal = EntryPayload {
        schema_minor: fa_model::entry::EXTENSIONS_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::SCHEDULE_CONTROL,
        effective_date: reversal.effective_date,
        document_date: None,
        description: reversal.description.clone(),
        effective_period: None,
        legs: Vec::new(),
        control: Some(ControlPayload::ScheduleCancelled {
            schedule_ref: svid,
            cause_ref: reversal_vid,
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: format!("cancel:{:032x}", svid.0).into_bytes(),
        origin: EntryOrigin::Control {
            control_kind: fa_model::ControlKind::SCHEDULE_CANCEL,
            spec_body_digest: fgdb_crypto::hash(&svid.0.to_le_bytes()).0,
        },
        principal_ref: reversal.principal_ref,
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    if let Err(r) = policy::authorize_approvals(
        txn,
        db,
        book,
        &[],
        &proposal.proposal_digest()?,
        epoch,
        &fa_policy::sod::control_key("ScheduleControl", None, "Cancel"),
        0,
        preparer,
    )? {
        return Ok(Err(r));
    }
    let entry = proposal.seal(Vec::new(), None)?;
    let mirrors = entry_mirrors(&entry)?;
    tracker.create_vertex(relation::HAS_LEG, cvid, 1, &mirrors);
    batch.create_vertex(cvid, vec![label::ENTRY], mirrors);
    Ok(Ok(Some(cvid)))
}

/// What `fa verify schedules` finds (FA-INV-08 and the schedule mirrors).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScheduleVerification {
    pub schedules_checked: usize,
    /// Schedules whose target's reversal is the scheduled one.
    pub executed: usize,
    /// Schedules cancelled by a manual reversal's lineage.
    pub cancelled: usize,
    pub drift: Vec<String>,
}

impl ScheduleVerification {
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.drift.is_empty()
    }
}

/// Refold every schedule from the payloads (plan §7.6, FA-INV-08 clause
/// `scheduled-once`): each entry requesting a reversal has exactly its
/// schedule vertex, mirroring what the payload binds; a scheduled target
/// reversed by its schedule has the exact swap dated `reverse_on` and no
/// cancellation; one reversed by hand has exactly one `ScheduleCancelled`
/// naming the schedule and that reversal; every cancellation names a
/// schedule.
pub fn verify_schedules<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
) -> Result<ScheduleVerification, KernelError> {
    let mut v = ScheduleVerification::default();
    let mut expected: BTreeMap<VId, (EntryRef, DateDay, String)> = BTreeMap::new();
    let mut stored: BTreeMap<VId, Schedule> = BTreeMap::new();
    let mut cancels: BTreeMap<VId, (VId, VId)> = BTreeMap::new();
    for row in db.vertices()? {
        if row.labels.contains(&label::REVERSAL_SCHEDULE) {
            match decode_schedule(&row) {
                Ok(s) => {
                    stored.insert(row.vid, s);
                }
                Err(e) => v.drift.push(e.to_string()),
            }
            continue;
        }
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = decode_entry(&row)?;
        if let Some(ControlPayload::ScheduleCancelled {
            schedule_ref,
            cause_ref,
        }) = entry.proposal.control
        {
            if matches!(
                entry.proposal.origin,
                EntryOrigin::Control {
                    control_kind: fa_model::ControlKind::RECURRING_SCHEDULE,
                    ..
                }
            ) {
                // The recurring verifier folds this separate lifecycle.
                continue;
            }
            cancels.insert(row.vid, (schedule_ref, cause_ref));
            continue;
        }
        if let Ok(Some((reverse_on, _))) = auto_reverse(&entry.proposal) {
            let period = match period_of(book, reverse_on)? {
                Ok(p) => p,
                Err(e) => {
                    v.drift.push(format!(
                        "entry {:032x} schedules a reversal on an unresolvable date: {e}",
                        row.vid.0
                    ));
                    continue;
                }
            };
            expected.insert(
                schedule_vid(row.vid),
                (entry.entry_ref(row.vid), reverse_on, period),
            );
        }
    }
    v.schedules_checked = expected.len();
    for (svid, (target, reverse_on, period)) in &expected {
        let Some(s) = stored.get(svid) else {
            v.drift.push(format!(
                "entry {:032x} schedules a reversal but has no schedule vertex",
                target.vid.0
            ));
            continue;
        };
        let bound = effects_digest(*target, *reverse_on, RULE_EXACT_NEGATION);
        if s.target != *target
            || s.reverse_on != *reverse_on
            || s.period != *period
            || s.exec_op != EXEC_OP
            || s.effects_digest != bound
        {
            v.drift.push(format!(
                "schedule {:032x} does not mirror its target's request",
                svid.0
            ));
        }
        let cancel = cancels.get(&schedule_cancel_vid(*svid));
        let Some(rrow) = db.vertex(reversal_vid(target.vid))? else {
            if cancel.is_some() {
                v.drift.push(format!(
                    "schedule {:032x} is cancelled but its target is unreversed",
                    svid.0
                ));
            }
            continue;
        };
        let reversal = decode_entry(&rrow)?;
        let scheduled = matches!(
            reversal.proposal.origin,
            EntryOrigin::Schedule { schedule_ref, .. } if schedule_ref == *svid
        );
        if scheduled {
            v.executed += 1;
            let target_row = db
                .vertex(target.vid)?
                .ok_or_else(|| KernelError::Corrupt("a scheduled target is missing".into()))?;
            let original = decode_entry(&target_row)?;
            let exact = crate::post::exact_side_swap(&original.proposal, &reversal.proposal)
                && reversal.proposal.legs == swapped(&original.proposal.legs)
                && reversal.proposal.effective_date == *reverse_on
                && reversal.proposal.principal_ref == system_principal(book.book_id)
                && matches!(date_basis(&reversal.proposal), Ok(Some(_)));
            if !exact {
                v.drift.push(format!(
                    "the scheduled reversal of {:032x} is not the bound effect",
                    target.vid.0
                ));
            }
            let before = CommitSeq(rrow.created_at.0.saturating_sub(1));
            if let Err(refusal) = crate::post::admit_accounts(
                db,
                book,
                reversal.proposal.class,
                reversal.proposal.effective_date,
                &reversal.proposal.legs,
                |vid| Ok(db.vertex_at(vid, before)?),
            )? {
                v.drift.push(format!(
                    "scheduled reversal {:032x} violated native account admission: {}",
                    rrow.vid.0,
                    refusal_reason(&refusal),
                ));
            }
            if cancel.is_some() {
                v.drift.push(format!(
                    "schedule {:032x} both executed and cancelled",
                    svid.0
                ));
            }
        } else {
            match cancel {
                Some((schedule_ref, cause_ref))
                    if *schedule_ref == *svid && *cause_ref == rrow.vid =>
                {
                    v.cancelled += 1;
                }
                _ => v.drift.push(format!(
                    "target {:032x} was reversed by hand without exactly one ScheduleCancelled naming its schedule and that reversal",
                    target.vid.0
                )),
            }
        }
    }
    for (cvid, (schedule_ref, _)) in &cancels {
        if !expected.contains_key(schedule_ref) || schedule_cancel_vid(*schedule_ref) != *cvid {
            v.drift.push(format!(
                "cancellation {:032x} names no schedule of this book",
                cvid.0
            ));
        }
    }
    for svid in stored.keys() {
        if !expected.contains_key(svid) {
            v.drift
                .push(format!("schedule {:032x} has no requesting entry", svid.0));
        }
    }
    let idx = crate::sweep::verify_sweep_index(db, book)?;
    v.drift.extend(idx.drift);
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_model::Oid;

    fn blank() -> EntryPayload {
        EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: Id128([1; 16]),
            branch_id: Id128::TRUNK,
            class: EntryClass::ADJUSTING,
            effective_date: DateDay(19_000),
            document_date: None,
            description: fa_model::Erasable::seal(
                &"accrual".to_string(),
                None,
                &fa_model::SealKey([1; 32]),
                [2; 32],
                [3; 24],
            ),
            effective_period: None,
            legs: Vec::new(),
            control: None,
            unit_totals: Vec::new(),
            base_totals: None,
            idempotency_key: b"k".to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([1; 32]),
                intent_kind: 1,
            },
            principal_ref: VId(7),
            session_ref: None,
            evidence: Vec::new(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        }
    }

    #[test]
    fn the_extensions_round_trip_and_reject_bad_widths() {
        let mut p = blank();
        assert_eq!(auto_reverse(&p), Ok(None));
        p = with_auto_reverse(p, DateDay(20_000));
        assert_eq!(
            auto_reverse(&p),
            Ok(Some((DateDay(20_000), RULE_EXACT_NEGATION)))
        );
        p.extensions = vec![(AUTO_REVERSE_EXTENSION, vec![1, 2, 3])];
        assert!(auto_reverse(&p).is_err());
        p.extensions = vec![(
            DATE_BASIS_EXTENSION,
            date_basis_bytes(TimeZonePolicy::Utc, VId(77)),
        )];
        assert_eq!(date_basis(&p), Ok(Some((TimeZonePolicy::Utc, VId(77)))));
        p.extensions = vec![(DATE_BASIS_EXTENSION, vec![9; 17])];
        assert!(date_basis(&p).is_err());
        let t = EntryRef {
            vid: VId(5),
            entry_digest: [6; 32],
        };
        assert_ne!(
            effects_digest(t, DateDay(1), 1),
            effects_digest(t, DateDay(2), 1)
        );
    }
}
