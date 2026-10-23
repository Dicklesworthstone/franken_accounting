//! Period transitions as journaled control records (plan §7.3, fa-bvx).
//!
//! A transition is one commit carrying a `PeriodControl` entry (legs = [],
//! `ControlPayload::PeriodTransition`) and a compare-and-set on the period's
//! `state` mirror. The compare-and-set is the witness: a post that read the
//! old state in its own transaction and a close that moves it are
//! first-committer-wins rivals, never a cron job's finding.
//!
//! **Authority (plan §14, Appendix C PeriodControl, FA-INV-10).** A
//! transition is a Steward-checked write: before the period is read, the
//! capability must be the preparer's, hold the transition's op (from the
//! `sod_policy.toml` rows: `close` for Open/SoftClose/Close/Lock, `reopen`
//! for Reopen — §14.2 has no `open` op), name this book, and be current at
//! the admission point; an Agent never holds either op. Inside the
//! transaction the capability's revocation and the security policy epoch are
//! point witnesses, and the rule for `(PeriodControl, from, transition)`
//! judges the approvals, which bind [`transition_proposal`]'s digest. Lock
//! and SoftClosed→Reopen need one Human approver; Closed/Locked→Reopen is
//! case-bound and refuses until restatement cases land.

use fa_model::symbols::{label, property, relation};
use fa_model::{
    ApprovalRef, ControlPayload, DecodeError, EncodeError, EntryClass, EntryOrigin, EntryPayload,
    EntryRef, Erasable, Id128, PeriodRef, Reader, Writer, entry_mirrors, entry_vid, limits,
    period_vid,
};
use fa_policy::{Capability, Intent, Party};
use fa_time::period::transition;
use fa_time::{DateDay, PeriodDef, PeriodKind, PeriodState, PeriodTransition};
use fgdb::{Database, WriteBatch, WriteMismatchPolicy, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::genesis::BookContext;
use crate::policy;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{edge_id, state_from_scalar};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transitioned {
    pub period: String,
    pub from: PeriodState,
    pub to: PeriodState,
    pub recorded_at: CommitSeq,
    pub control_entry: VId,
    /// An `Open` transition's scheduled reversals (plan §7.6 rule (b)):
    /// `(target, reversal)` minted in this commit.
    pub minted: Vec<(EntryRef, EntryRef)>,
    /// Schedules due in the opened period that the commit examined but did
    /// not mint, with why (live applications, the availability law).
    pub blocked: Vec<(EntryRef, String)>,
    /// True when this is an identical retry's recorded outcome (FA-INV-09):
    /// nothing new was written; `minted` and `blocked` are then empty.
    pub already_recorded: bool,
}

#[derive(Debug)]
struct StagedTransition {
    txn: WriteTxn,
    book: BookContext,
    capability: Capability,
    period: String,
    transition: PeriodTransition,
    from: PeriodState,
    to: PeriodState,
    control_entry: VId,
    proposal: EntryPayload,
    proposal_digest: [u8; 32],
    minted: Vec<(EntryRef, EntryRef)>,
    blocked: Vec<(EntryRef, String)>,
}

/// An authorized period transition staged against its original witnesses.
/// Its capability and effects cannot be replaced after preparation. Dropping
/// it abandons the staged write and releases the substrate's read pin.
#[derive(Debug)]
enum PreparedTransitionState {
    Staged(Box<StagedTransition>),
    AlreadyRecorded {
        basis: CommitSeq,
        recorded: Transitioned,
    },
}

/// An authorized period transition staged against its original witnesses.
/// Its capability and effects cannot be replaced after preparation. Dropping
/// it abandons the staged write and releases the substrate's read pin.
#[derive(Debug)]
#[must_use]
pub struct PreparedTransition {
    state: PreparedTransitionState,
}

impl PreparedTransition {
    /// The committed prefix from which the transition's witnesses were read.
    #[must_use]
    pub fn basis(&self) -> CommitSeq {
        match &self.state {
            PreparedTransitionState::Staged(staged) => staged.txn.basis(),
            PreparedTransitionState::AlreadyRecorded { basis, .. } => *basis,
        }
    }

    /// Release the prepared transaction without publishing any effects.
    pub fn abort(self) {
        if let PreparedTransitionState::Staged(staged) = self.state {
            staged.txn.abort();
        }
    }

    /// Commit with the original witnesses and a fresh check of the same
    /// acting capability's expiry. A changed period, revocation, approval,
    /// or policy epoch is judged by the ordinary transaction validator.
    pub async fn commit<V: asupersync::fs::Vfs + Clone>(
        self,
        db: &mut Database<V>,
        ctx: &PurposeContexts,
    ) -> Outcome<Transitioned> {
        let commit = ctx.commit();
        commit.checkpoint().map_err(WriteTxnError::Interrupted)?;
        let StagedTransition {
            mut txn,
            book,
            capability,
            period,
            transition,
            from,
            to,
            control_entry,
            proposal,
            proposal_digest,
            minted,
            blocked,
        } = match self.state {
            PreparedTransitionState::AlreadyRecorded { recorded, .. } => {
                return Ok(Ok(recorded));
            }
            PreparedTransitionState::Staged(staged) => *staged,
        };
        if let Err(d) = fa_policy::current(&capability, db.frontier()?) {
            txn.abort();
            return Ok(Err(policy::refusal(&d)));
        }
        match txn.commit(db, &commit).await {
            Ok(seq) => Ok(Ok(Transitioned {
                period,
                from,
                to,
                recorded_at: seq,
                control_entry,
                minted,
                blocked,
                already_recorded: false,
            })),
            Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
                Ok(Err(Refusal::new(
                    code::CONFLICT,
                    exit::CONFLICT,
                    format!("a concurrent commit invalidated this transition's witness: {detail}"),
                    "FG-LAW-FCW-01 (first committer wins)",
                    "re-read the period and retry",
                )))
            }
            Err(WriteTxnError::Write(fgdb::WriteError::CompareAndSetMismatch(_))) => {
                Ok(Err(Refusal::new(
                    code::PERIOD_MOVED,
                    exit::CONFLICT,
                    format!("period `{period}` is no longer {}", from.name()),
                    "plan §7.3 (state changes are serialized through the period vertex)",
                    "re-read the period state and choose the transition again",
                )))
            }
            Err(WriteTxnError::Write(
                fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
            )) => match db.vertex(control_entry)? {
                Some(row) => recorded_proposal_or_conflict(
                    db,
                    &book,
                    &row,
                    &period,
                    transition,
                    &proposal,
                    &proposal_digest,
                ),
                None => Err(KernelError::Corrupt(
                    "identity spent but no live row".into(),
                )),
            },
            Err(e) => Err(e.into()),
        }
    }
}

/// The registered name of a transition (the `transition` key of its
/// `sod_policy.toml` rows).
#[must_use]
pub fn transition_name(t: PeriodTransition) -> &'static str {
    match t {
        PeriodTransition::Open => "Open",
        PeriodTransition::SoftClose => "SoftClose",
        PeriodTransition::Close => "Close",
        PeriodTransition::Lock => "Lock",
        PeriodTransition::Reopen { .. } => "Reopen",
    }
}

/// The `reason_codes.toml` scope a transition's reason is registered in
/// (plan §7.3, fa-cvg): a reopen says why the period reopens
/// (`period_reopen`); every other transition is a step of the period's
/// close (`period_control`).
#[must_use]
pub fn reason_scope(t: PeriodTransition) -> &'static str {
    match t {
        PeriodTransition::Reopen { .. } => "period_reopen",
        _ => "period_control",
    }
}

/// [`reason_scope`] of a recorded `from → to` transition: a reopen is the
/// one transition that moves a period back along the state order.
#[must_use]
pub fn reason_scope_of(from: PeriodState, to: PeriodState) -> &'static str {
    if to < from {
        "period_reopen"
    } else {
        "period_control"
    }
}

/// The refusal for a reason that `t`'s scope does not register (FA-REF-041).
fn reason_refusal(t: PeriodTransition, reason_code: u16) -> Result<Option<Refusal>, KernelError> {
    let reasons = fa_registry::reason_codes::ReasonCodes::embedded()
        .map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let scope = reason_scope(t);
    if reasons.get(scope, reason_code).is_some() {
        return Ok(None);
    }
    Ok(Some(Refusal::new(
        code::PERIOD_REASON,
        exit::REFUSAL,
        format!(
            "{} reason {reason_code} is not registered in reason_codes.toml scope {scope} (zero is not a reason)",
            transition_name(t)
        ),
        "plan §7.3 (every transition is journaled with its principal and reason); reason_codes.toml",
        format!("give a registered reason: {}", reasons.listing(scope)),
    )
    .or_field_change(
        "reason",
        reasons
            .rows
            .iter()
            .filter(|r| r.scope == scope)
            .map(|r| r.name.clone())
            .collect(),
    )))
}

/// The effective date of the `PeriodControl` entry that moves `period` out
/// of `from` (plan §7.3, fa-87r). The period fixes it; no caller supplies
/// it. Opening a `Future` period is dated on the period's first day. Every
/// later transition (soft close, close, lock, reopen) acts at the period's
/// closing boundary and is dated on its last day. Both days lie inside the
/// period, so the control resolves to the period it names.
#[must_use]
pub fn transition_date(period: &PeriodDef, from: PeriodState) -> DateDay {
    if from == PeriodState::Future {
        period.start
    } else {
        period.last_day()
    }
}

/// The `PeriodControl` proposal a transition commits, deterministic in its
/// inputs, so an approver can compute the `proposal_digest` it approves:
/// the same period, from/to states, preparer, reason, key and description
/// bytes the preparer will submit. The date is [`transition_date`]'s.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn transition_proposal(
    book: &BookContext,
    period: &PeriodDef,
    from: PeriodState,
    to: PeriodState,
    principal_ref: VId,
    reason_code: u16,
    idempotency_key: &[u8],
    description: Erasable<String>,
) -> EntryPayload {
    let period_code = period.code.as_str();
    EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::PERIOD_CONTROL,
        effective_date: transition_date(period, from),
        document_date: None,
        description,
        effective_period: Some(PeriodRef {
            calendar: book.calendar.id.clone(),
            code: period_code.to_string(),
        }),
        legs: Vec::new(),
        control: Some(ControlPayload::PeriodTransition {
            period_ref: PeriodRef {
                calendar: book.calendar.id.clone(),
                code: period_code.to_string(),
            },
            from: from.tag(),
            to: to.tag(),
            reason_code,
            case_ref: None,
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: idempotency_key.to_vec(),
        origin: EntryOrigin::Control {
            control_kind: fa_model::ControlKind::PERIOD_TRANSITION,
            spec_body_digest: fgdb_crypto::hash(idempotency_key).0,
        },
        principal_ref,
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    }
}

pub(crate) fn unknown_period(book: &BookContext, period_code: &str) -> Refusal {
    Refusal::new(
        code::PERIOD_UNKNOWN,
        exit::SAFETY,
        format!(
            "period `{period_code}` does not exist in calendar `{}`",
            book.calendar.id
        ),
        "plan §7.3 (periods are created per fiscal year)",
        format!("fa period create --fiscal-year <FY> (then transition `{period_code}`)"),
    )
}

fn existing_names_transition(
    row: &fgdb::VertexRow,
    book: &BookContext,
    period_code: &str,
    t: PeriodTransition,
) -> Result<bool, KernelError> {
    let stored = match crate::rows::prop(row, property::FA_PAYLOAD) {
        Some(CanonicalScalar::Bytes(b)) => fa_model::Entry::decode(b.as_slice())?,
        other => {
            return Err(KernelError::Corrupt(format!(
                "entry _fa_payload: {other:?}"
            )));
        }
    };
    if stored.proposal.class != EntryClass::PERIOD_CONTROL {
        return Ok(false);
    }
    let Some(ControlPayload::PeriodTransition {
        period_ref,
        from: from_tag,
        to: to_tag,
        ..
    }) = &stored.proposal.control
    else {
        return Ok(false);
    };
    if period_ref.calendar != book.calendar.id || period_ref.code != period_code {
        return Ok(false);
    }
    let (Some(stored_from), Some(stored_to)) = (
        PeriodState::from_tag(*from_tag),
        PeriodState::from_tag(*to_tag),
    ) else {
        return Ok(false);
    };
    Ok(transition(stored_from, t) == Ok(stored_to))
}

#[allow(clippy::too_many_arguments)]
fn recorded_or_conflict<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    row: &fgdb::VertexRow,
    period: &PeriodDef,
    t: PeriodTransition,
    principal_ref: VId,
    reason_code: u16,
    idempotency_key: &[u8],
    description: &Erasable<String>,
) -> Outcome<Transitioned> {
    let period_code = period.code.as_str();
    let stored = match crate::rows::prop(row, property::FA_PAYLOAD) {
        Some(CanonicalScalar::Bytes(b)) => fa_model::Entry::decode(b.as_slice())?,
        other => {
            return Err(KernelError::Corrupt(format!(
                "entry _fa_payload: {other:?}"
            )));
        }
    };
    let conflict = || {
        Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            format!(
                "idempotency key reused with different content; the recorded entry is {:032x}",
                row.vid.0
            ),
            "plan §4.9 (identity is derived from the key; content is bound by proposal_digest)",
            "resubmit the identical transition to get the recorded outcome, or use a new idempotency key",
        )
    };
    if stored.proposal.class != EntryClass::PERIOD_CONTROL {
        return Ok(Err(conflict()));
    }
    let Some(ControlPayload::PeriodTransition {
        period_ref,
        from: from_tag,
        to: to_tag,
        ..
    }) = &stored.proposal.control
    else {
        return Ok(Err(conflict()));
    };
    if period_ref.calendar != book.calendar.id || period_ref.code != period_code {
        return Ok(Err(conflict()));
    }
    let Some(stored_from) = PeriodState::from_tag(*from_tag) else {
        return Err(KernelError::Corrupt(format!(
            "transition {:032x} carries invalid from state tag {from_tag}",
            row.vid.0
        )));
    };
    let Some(stored_to) = PeriodState::from_tag(*to_tag) else {
        return Err(KernelError::Corrupt(format!(
            "transition {:032x} carries invalid to state tag {to_tag}",
            row.vid.0
        )));
    };
    if transition(stored_from, t) != Ok(stored_to) {
        return Ok(Err(conflict()));
    }
    let candidate = transition_proposal(
        book,
        period,
        stored_from,
        stored_to,
        principal_ref,
        reason_code,
        idempotency_key,
        description.clone(),
    );
    let candidate_digest = candidate.proposal_digest()?;
    recorded_proposal_or_conflict(db, book, row, period_code, t, &candidate, &candidate_digest)
}

fn recorded_proposal_or_conflict<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    row: &fgdb::VertexRow,
    period_code: &str,
    t: PeriodTransition,
    proposal: &EntryPayload,
    proposal_digest: &[u8; 32],
) -> Outcome<Transitioned> {
    let stored = match crate::rows::prop(row, property::FA_PAYLOAD) {
        Some(CanonicalScalar::Bytes(b)) => fa_model::Entry::decode(b.as_slice())?,
        other => {
            return Err(KernelError::Corrupt(format!(
                "entry _fa_payload: {other:?}"
            )));
        }
    };
    let conflict = || {
        Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            format!(
                "idempotency key reused with different content; the recorded entry is {:032x}",
                row.vid.0
            ),
            "plan §4.9 (identity is derived from the key; content is bound by proposal_digest)",
            "resubmit the identical transition to get the recorded outcome, or use a new idempotency key",
        )
    };
    if stored.proposal.class != EntryClass::PERIOD_CONTROL {
        return Ok(Err(conflict()));
    }
    let Some(ControlPayload::PeriodTransition {
        period_ref,
        from: from_tag,
        to: to_tag,
        ..
    }) = &stored.proposal.control
    else {
        return Ok(Err(conflict()));
    };
    if period_ref.calendar != book.calendar.id || period_ref.code != period_code {
        return Ok(Err(conflict()));
    }
    let Some(stored_from) = PeriodState::from_tag(*from_tag) else {
        return Err(KernelError::Corrupt(format!(
            "transition {:032x} carries invalid from state tag {from_tag}",
            row.vid.0
        )));
    };
    let Some(stored_to) = PeriodState::from_tag(*to_tag) else {
        return Err(KernelError::Corrupt(format!(
            "transition {:032x} carries invalid to state tag {to_tag}",
            row.vid.0
        )));
    };
    if transition(stored_from, t) != Ok(stored_to) {
        return Ok(Err(conflict()));
    }
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
                        "a transition with this identity exists ({:032x}) but a sealed field cannot be opened, so equivalence cannot be verified",
                        row.vid.0
                    ),
                    "plan §8.5 (no plaintext equivalence over destroyed secrets)",
                    "resubmit the exact prepared bytes to get the recorded outcome, or use a new idempotency key",
                )));
            }
            (Err(e), _) | (_, Err(e)) => return Err(e.into()),
        }
    };
    if !same {
        return Ok(Err(conflict()));
    }
    let pvid = period_vid(&book.calendar.id, period_code);
    if let Some(period_row) = db.vertex(pvid)? {
        let current = state_from_scalar(crate::rows::prop(&period_row, property::STATE))
            .ok_or_else(|| KernelError::Corrupt(format!("period `{period_code}` state mirror")))?;
        if current != stored_to {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                "a control entry with this idempotency key already exists",
                "plan §4.9",
                "use a fresh idempotency key",
            )));
        }
    }
    let (minted, blocked) = if t == PeriodTransition::Open {
        crate::schedule::recorded_open_mints(db, book, period_code, row.vid, row.created_at)?
    } else {
        (Vec::new(), Vec::new())
    };
    Ok(Ok(Transitioned {
        period: period_code.to_string(),
        from: stored_from,
        to: stored_to,
        recorded_at: row.created_at,
        control_entry: row.vid,
        minted,
        blocked,
        already_recorded: true,
    }))
}

/// The refusal for a transition of a period whose born kind has a registered
/// kind row (`admissibility.toml` `[[kind]]`, plan §7.2): a Historical
/// period is born `Locked` and never transitions.
fn kind_refusal(
    row: &fgdb::VertexRow,
    period_code: &str,
    t: PeriodTransition,
    opening_date: Option<fa_time::DateDay>,
) -> Result<Option<Refusal>, KernelError> {
    let period = crate::rows::PeriodRow::decode(row)?;
    let born = period.kind;
    let classes =
        fa_registry::EntryClasses::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let matrix = fa_registry::Admissibility::embedded(&classes)
        .map_err(|e| KernelError::Corrupt(e.to_string()))?;
    // A Historical period (its `[[kind]]` row) or a special period before
    // the book's opening date (`[[pre_opening]]`, ruling 3685) is born
    // Locked and never transitions.
    let (refusal, cite) = if let Some(rule) = matrix.kind_rule(born) {
        (
            rule.transition_refusal.clone(),
            format!(
                "plan §7.2, Appendix C (admissibility.toml kind {born:?}: born Locked, never transitions)"
            ),
        )
    } else if let Some(rule) = matrix
        .pre_opening()
        .filter(|r| r.governs(born, period.end, opening_date))
    {
        (rule.transition_refusal.clone(), rule.cite.clone())
    } else {
        return Ok(None);
    };
    if refusal != code::TRANSITION {
        return Err(KernelError::Corrupt(format!(
            "admissibility.toml refuses a {born:?} transition with `{refusal}`, not {}",
            code::TRANSITION
        )));
    }
    Ok(Some(Refusal::new(
        code::TRANSITION,
        exit::SAFETY,
        format!(
            "period `{period_code}` is {born:?} (before the book's opening date) and cannot take {t:?}"
        ),
        cite,
        "transition a live period; legacy history enters a period before the opening date only through a MigrationRun",
    )))
}

fn illegal_transition(period_code: &str, from: PeriodState, t: PeriodTransition) -> Refusal {
    // The transitions this state admits (probed against the one transition
    // table, fa_time::transition), as the commands that take them. Open and
    // soft-close default their reason; the others keep a `<reason>` slot,
    // since the reason is a fact the caller states, never one chosen for it.
    let candidates = [
        (PeriodTransition::Open, "open", ""),
        (PeriodTransition::SoftClose, "soft-close", ""),
        (PeriodTransition::Close, "close", " --reason <reason>"),
        (PeriodTransition::Lock, "lock", " --reason <reason>"),
        (
            PeriodTransition::Reopen {
                to: PeriodState::Open,
            },
            "reopen",
            " --to open --reason <reason>",
        ),
        (
            PeriodTransition::Reopen {
                to: PeriodState::SoftClosed,
            },
            "reopen",
            " --to soft-closed --reason <reason>",
        ),
    ];
    let legal: Vec<String> = candidates
        .iter()
        .filter(|(c, ..)| transition(from, *c).is_ok())
        .map(|(_, verb, rest)| format!("`fa period {verb} {period_code}{rest}`"))
        .collect();
    let fix = if legal.is_empty() {
        format!("a {} period takes no further transition", from.name())
    } else {
        format!(
            "from {} the legal transitions are {}",
            from.name(),
            legal.join(" or ")
        )
    };
    Refusal::new(
        code::TRANSITION,
        exit::SAFETY,
        format!(
            "period `{period_code}` is {} and cannot take {t:?}",
            from.name()
        ),
        "plan §7.3 period state machine",
        fix,
    )
    .at("period", period_code)
    .at("state", from.name())
}

/// A planned transition (R4): the inputs [`transition_period`] rebuilds its
/// proposal from, with the description sealed once. Approvers bind
/// [`TransitionPlan::proposal_digest`]; the committing process passes the
/// same inputs back, so the digest matches, or the approval binding refuses
/// (FA-REF-016) when the period has moved since the plan was made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionPlan {
    pub period_code: String,
    pub from: PeriodState,
    pub to: PeriodState,
    pub principal_ref: VId,
    pub reason_code: u16,
    pub idempotency_key: Vec<u8>,
    pub description: Erasable<String>,
}

/// The plan file's leading domain tag; the format is versioned after it.
pub const PLAN_DOMAIN: &[u8; 14] = b"fa:period-plan";
/// Version 2 dropped version 1's caller-supplied date: the period fixes the
/// control's date (fa-87r), so a version 1 plan is refused.
const PLAN_VERSION: u16 = 2;

impl TransitionPlan {
    /// The proposal this plan commits, dated by its period
    /// ([`transition_date`]); refused when the book's calendar has no such
    /// period.
    pub fn proposal(&self, book: &BookContext) -> Result<EntryPayload, Refusal> {
        let period = policy::calendar_period(book, &self.period_code)
            .ok_or_else(|| unknown_period(book, &self.period_code))?;
        Ok(transition_proposal(
            book,
            &period,
            self.from,
            self.to,
            self.principal_ref,
            self.reason_code,
            &self.idempotency_key,
            self.description.clone(),
        ))
    }

    /// The digest an approval of this plan binds.
    pub fn proposal_digest(&self, book: &BookContext) -> Outcome<[u8; 32]> {
        match self.proposal(book) {
            Ok(proposal) => Ok(Ok(proposal.proposal_digest()?)),
            Err(refusal) => Ok(Err(refusal)),
        }
    }

    /// `"fa:period-plan" ‖ u16 version ‖ str period ‖ u8 from ‖ u8 to ‖
    /// u128 principal ‖ u16 reason ‖ bytes key ‖ erasable description`.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(PLAN_DOMAIN)
            .u16(PLAN_VERSION)
            .str(&self.period_code)
            .u8(self.from.tag())
            .u8(self.to.tag())
            .u128(self.principal_ref.0)
            .u16(self.reason_code)
            .bytes(&self.idempotency_key);
        self.description.encode(&mut w);
        w.finish()
    }

    /// Decode a plan; refuses another format, an unknown version or state
    /// tag, a transition the state machine does not have, and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let domain: [u8; 14] = r.fixed("plan.domain")?;
        if domain != *PLAN_DOMAIN {
            return Err(r.invalid("plan.domain"));
        }
        if r.u16("plan.version")? != PLAN_VERSION {
            return Err(r.invalid("plan.version"));
        }
        let period_code = r
            .str(limits::MAX_PERIOD_REF_BYTES, "plan.period")?
            .to_string();
        let mut state = |what: &'static str| {
            let tag = r.u8(what)?;
            PeriodState::from_tag(tag).ok_or_else(|| r.bad_tag(what, tag))
        };
        let from = state("plan.from")?;
        let to = state("plan.to")?;
        let plan = Self {
            period_code,
            from,
            to,
            principal_ref: VId(r.u128("plan.principal")?),
            reason_code: r.u16("plan.reason")?,
            idempotency_key: r
                .bytes(limits::MAX_IDEMPOTENCY_KEY_BYTES, "plan.key")?
                .to_vec(),
            description: Erasable::decode(&mut r, limits::MAX_DESCRIPTION_BYTES)?,
        };
        r.finish()?;
        Ok(plan)
    }

    /// Whether `t` takes this plan's `from` to its `to`.
    #[must_use]
    pub fn is_for(&self, t: PeriodTransition) -> bool {
        matches!(transition(self.from, t), Ok(to) if to == self.to)
    }
}

/// Plan a transition without committing (R4): the period is read at the
/// head and the same unknown-period and state-machine refusals as
/// [`transition_period`] apply. Authority is not judged here; the commit
/// judges it, before any read.
#[allow(clippy::too_many_arguments)]
pub fn plan_transition<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period_code: &str,
    t: PeriodTransition,
    principal_ref: VId,
    reason_code: u16,
    idempotency_key: &[u8],
    description: Erasable<String>,
) -> Outcome<TransitionPlan> {
    let Some(row) = db.vertex(period_vid(&book.calendar.id, period_code))? else {
        return Ok(Err(unknown_period(book, period_code)));
    };
    let from = state_from_scalar(crate::rows::prop(&row, property::STATE))
        .ok_or_else(|| KernelError::Corrupt(format!("period `{period_code}` state mirror")))?;
    let opening_date = crate::genesis::read_book_spec(db)?.and_then(|s| s.opening_date);
    if let Some(r) = kind_refusal(&row, period_code, t, opening_date)? {
        return Ok(Err(r));
    }
    let Ok(to) = transition(from, t) else {
        return Ok(Err(illegal_transition(period_code, from, t)));
    };
    if let Some(r) = reason_refusal(t, reason_code)? {
        return Ok(Err(r));
    }
    Ok(Ok(TransitionPlan {
        period_code: period_code.to_string(),
        from,
        to,
        principal_ref,
        reason_code,
        idempotency_key: idempotency_key.to_vec(),
        description,
    }))
}

/// Move one period along the state machine, journaled, under `capability`
/// and the cited `approvals` (see the module docs for the authority law).
#[allow(clippy::too_many_arguments)]
pub async fn transition_period<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    period_code: &str,
    t: PeriodTransition,
    principal_ref: VId,
    reason_code: u16,
    idempotency_key: &[u8],
    description: Erasable<String>,
    capability: &Capability,
    approvals: &[ApprovalRef],
) -> Outcome<Transitioned> {
    if t == PeriodTransition::Open {
        if let Err(refusal) = admit_transition(db, book, period_code, t, principal_ref, capability)?
        {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = policy::capability_admitted(db, book, capability)? {
            return Ok(Err(refusal));
        }
        // Opening can mint due cash reversals. Their cutoff guard needs the
        // same retained reconciliation history as the ordinary post path.
        if let Err(refusal) = crate::scratch::ensure_history(db, ctx).await? {
            return Ok(Err(refusal));
        }
    }
    match prepare_transition(
        db,
        ctx,
        book,
        period_code,
        t,
        principal_ref,
        reason_code,
        idempotency_key,
        description,
        capability,
        approvals,
    )? {
        Ok(prepared) => prepared.commit(db, ctx).await,
        // An identical retry finds the period already moved (FA-INV-09,
        // fa-l93 D13). The refusal came after authorization, so the caller
        // may see the recorded outcome of its own request.
        Err(refusal) if refusal.code == code::TRANSITION => Ok(recorded_transition(
            db,
            book,
            period_code,
            t,
            principal_ref,
            reason_code,
            idempotency_key,
        )?
        .ok_or(refusal)),
        Err(refusal) => Ok(Err(refusal)),
    }
}

/// The recorded outcome of this exact request, when the control entry at
/// its identity (principal, key) moved `period_code` along `t` with the
/// same reason, dated as the period law dates it; `None` otherwise (the
/// caller's refusal stands).
fn recorded_transition<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period_code: &str,
    t: PeriodTransition,
    principal_ref: VId,
    reason_code: u16,
    idempotency_key: &[u8],
) -> Result<Option<Transitioned>, KernelError> {
    let evid = entry_vid(
        book.book_id,
        &principal_ref.0.to_le_bytes(),
        idempotency_key,
    );
    let Some((entry, recorded_at)) = crate::post::read_entry(db, evid)? else {
        return Ok(None);
    };
    let Some(ControlPayload::PeriodTransition {
        period_ref,
        from,
        to,
        reason_code: recorded_reason,
        ..
    }) = &entry.proposal.control
    else {
        return Ok(None);
    };
    let (Some(from), Some(to)) = (PeriodState::from_tag(*from), PeriodState::from_tag(*to)) else {
        return Ok(None);
    };
    let same = period_ref.code == period_code
        && entry.proposal.principal_ref == principal_ref
        && *recorded_reason == reason_code
        && policy::calendar_period(book, period_code)
            .is_some_and(|p| entry.proposal.effective_date == transition_date(&p, from))
        && transition(from, t).ok() == Some(to);
    Ok(same.then(|| Transitioned {
        period: period_code.to_string(),
        from,
        to,
        recorded_at,
        control_entry: evid,
        minted: Vec::new(),
        blocked: Vec::new(),
        already_recorded: true,
    }))
}

/// Capability and coordinate admission shared by preparation and the async
/// history loader. This observes no period payload before scope admission.
fn admit_transition<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period_code: &str,
    transition: PeriodTransition,
    principal: VId,
    capability: &Capability,
) -> Outcome<Option<PeriodDef>> {
    let steward = policy::steward()?;
    let name = transition_name(transition);
    let op = steward.transition_op("PeriodControl", name).ok_or_else(|| {
        KernelError::Corrupt(format!(
            "sod_policy.toml registers no PeriodControl {name} rule; the transition is refused, never unconstrained"
        ))
    })?;
    let calendar_period = policy::calendar_period(book, period_code);
    let reached = [period_code];
    let through = calendar_period.as_ref().map(PeriodDef::last_day);
    if let Err(denial) = fa_policy::admit_within(
        capability,
        &Intent {
            principal,
            trunk: true,
            op,
            book: book.book_id,
            legs: &[],
        },
        &fa_policy::Reach {
            branch: Some(Id128::TRUNK),
            observes: fa_policy::Observes::Head,
            periods: Some(&reached),
            through,
            accounts: None,
        },
        None,
    ) {
        return Ok(Err(policy::refusal(&denial)));
    }
    if let Err(denial) = fa_policy::current(capability, db.frontier()?) {
        return Ok(Err(policy::refusal(&denial)));
    }
    Ok(Ok(calendar_period))
}

/// Stage the production transition without publishing it. Its witnesses
/// remain pinned while another prepared operation is allowed to commit;
/// [`PreparedTransition::commit`] validates those original witnesses.
/// Opening a period may mint scheduled reversals and therefore requires
/// retained history from sequence zero; [`transition_period`] loads it.
#[allow(clippy::too_many_arguments)]
pub fn prepare_transition<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    period_code: &str,
    t: PeriodTransition,
    principal_ref: VId,
    reason_code: u16,
    idempotency_key: &[u8],
    description: Erasable<String>,
    capability: &Capability,
    approvals: &[ApprovalRef],
) -> Outcome<PreparedTransition> {
    ctx.txn().checkpoint().map_err(WriteTxnError::Interrupted)?;
    let calendar_period =
        match admit_transition(db, book, period_code, t, principal_ref, capability)? {
            Ok(period) => period,
            Err(refusal) => return Ok(Err(refusal)),
        };
    let name = transition_name(t);

    let pvid = period_vid(&book.calendar.id, period_code);
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    // Current authority: not revoked, under the witnessed policy epoch.
    if let Err(r) = policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let evid = entry_vid(
        book.book_id,
        &principal_ref.0.to_le_bytes(),
        idempotency_key,
    );
    let epoch = policy::epoch_witness(&txn, db)?;

    let Some(row) = txn.vertex(db, pvid)? else {
        txn.abort();
        return Ok(Err(unknown_period(book, period_code)));
    };
    let from = state_from_scalar(crate::rows::prop(&row, property::STATE))
        .ok_or_else(|| KernelError::Corrupt(format!("period `{period_code}` state mirror")))?;
    let opening_date = crate::genesis::opening_date_in(&txn, db)?;
    if let Some(r) = kind_refusal(&row, period_code, t, opening_date)? {
        txn.abort();
        return Ok(Err(r));
    }
    // Period creation generates every period a book holds from its
    // calendar, so the calendar dates this control.
    let Some(period) = calendar_period else {
        txn.abort();
        return Err(KernelError::Corrupt(format!(
            "period `{period_code}` is held but calendar `{}` does not define it",
            book.calendar.id
        )));
    };
    let Ok(to) = transition(from, t) else {
        // When `t` is not admissible from the period's current state `from`,
        // check whether `evid` already recorded this `(period_code, t)`
        // transition (FA-INV-09, fa-l93 D13): if so, return the recorded
        // outcome on an identical retry or an idempotency conflict when the
        // retry changed its reason or description; if `evid` is absent or
        // recorded a different transition, the state-machine refusal stands.
        if let Some(existing) = txn.vertex(db, evid)?
            && existing_names_transition(&existing, book, period_code, t)?
        {
            let basis = txn.basis();
            txn.abort();
            return match recorded_or_conflict(
                db,
                book,
                &existing,
                &period,
                t,
                principal_ref,
                reason_code,
                idempotency_key,
                &description,
            )? {
                Ok(recorded) => Ok(Ok(PreparedTransition {
                    state: PreparedTransitionState::AlreadyRecorded { basis, recorded },
                })),
                Err(r) => Ok(Err(r)),
            };
        }
        txn.abort();
        return Ok(Err(illegal_transition(period_code, from, t)));
    };
    if let Some(existing) = txn.vertex(db, evid)? {
        let basis = txn.basis();
        txn.abort();
        return match recorded_or_conflict(
            db,
            book,
            &existing,
            &period,
            t,
            principal_ref,
            reason_code,
            idempotency_key,
            &description,
        )? {
            Ok(recorded) => Ok(Ok(PreparedTransition {
                state: PreparedTransitionState::AlreadyRecorded { basis, recorded },
            })),
            Err(r) => Ok(Err(r)),
        };
    }

    // A fresh transition names a reason its scope registers (fa-cvg).
    // Outcome recognition stays first: an identical retry returns the
    // recorded outcome, including one recorded before this law.
    if let Some(r) = reason_refusal(t, reason_code)? {
        txn.abort();
        return Ok(Err(r));
    }
    let proposal = transition_proposal(
        book,
        &period,
        from,
        to,
        principal_ref,
        reason_code,
        idempotency_key,
        description,
    );
    let proposal_digest = proposal.proposal_digest()?;
    // Segregation of duties for this transition from this state (plan §14.3):
    // every cited approval is a witnessed Approval of exactly this proposal
    // under the current epoch, judged by the registered rule.
    let key = fa_policy::sod::control_key("PeriodControl", Some(from), name);
    let preparer = Party {
        principal: principal_ref,
        profile: capability.profile(),
    };
    if let Err(r) = policy::authorize_approvals(
        &txn,
        db,
        book,
        approvals,
        &proposal_digest,
        epoch,
        &key,
        0,
        preparer,
    )? {
        txn.abort();
        return Ok(Err(r));
    }
    let entry = proposal.clone().seal(approvals.to_vec(), None)?;

    let mut batch = WriteBatch::new(relation::IN_PERIOD);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    batch.compare_and_set_vertex_property(
        pvid,
        property::STATE,
        Some(CanonicalScalar::Int(i64::from(from.tag()))),
        CanonicalScalar::Int(i64::from(to.tag())),
        WriteMismatchPolicy::AbortWrite,
    );
    batch.add_edge(edge_id(relation::IN_PERIOD, evid, pvid), evid, pvid, vec![]);
    // Plan §7.6 rule (b): opening a period mints, in this commit, the
    // scheduled reversals dated in it whose date the latest committed tick
    // has reached — so a scheduled reversal never meets a Future period.
    let (minted, blocked, mut batches) = if t == PeriodTransition::Open {
        // The trigger is this transition's own control entry; the minted
        // reversals are the book's (its System principal). The executor is
        // this transition, admitted under `close` at the head of this
        // function. Every due effect additionally requires its executor's
        // current Post authority, amount/scope limits and daily budget.
        match crate::schedule::mint_on_open(&mut txn, db, ctx, book, capability, period_code, evid)?
        {
            Ok(mints) => {
                let minted = mints.minted.clone();
                let blocked = mints.blocked.clone();
                (minted, blocked, mints.into_batches()?)
            }
            Err(r) => {
                txn.abort();
                return Ok(Err(r));
            }
        }
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };
    batches.insert(0, batch);
    txn.write_ordered(db, batches)?;
    Ok(Ok(PreparedTransition {
        state: PreparedTransitionState::Staged(Box::new(StagedTransition {
            txn,
            book: book.clone(),
            capability: capability.clone(),
            period: period_code.to_string(),
            transition: t,
            from,
            to,
            control_entry: evid,
            proposal,
            proposal_digest,
            minted,
            blocked,
        })),
    }))
}

/// One committed `PeriodControl` transition entry on a fiscal period (`fa explain period`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodTransitionRecord {
    pub entry_vid: VId,
    pub entry_digest: [u8; 32],
    pub recorded_at: CommitSeq,
    pub effective_date: DateDay,
    pub from: PeriodState,
    pub to: PeriodState,
    pub reason_code: u16,
    pub principal_ref: VId,
    pub approvals: Vec<ApprovalRef>,
}

/// Read the ordered `PeriodControl` transition entries for `period_code`,
/// sorted by `(recorded_at, entry_vid)`.
pub fn period_transitions<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period_code: &str,
) -> Result<Vec<PeriodTransitionRecord>, KernelError> {
    let pvid = period_vid(&book.calendar.id, period_code);
    let mut out = Vec::new();
    for evid in db.in_neighbours(pvid, relation::IN_PERIOD)? {
        let Some(row) = db.vertex(evid)? else {
            continue;
        };
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let Some((entry, recorded_at)) = crate::post::read_entry(db, evid)? else {
            continue;
        };
        if entry.proposal.book_id != book.book_id {
            continue;
        }
        let Some(ControlPayload::PeriodTransition {
            period_ref,
            from,
            to,
            reason_code,
            ..
        }) = &entry.proposal.control
        else {
            continue;
        };
        if period_ref.code != period_code {
            continue;
        }
        let from_state = PeriodState::from_tag(*from).ok_or_else(|| {
            KernelError::Corrupt(format!(
                "period transition entry {:032x} bad from tag",
                evid.0
            ))
        })?;
        let to_state = PeriodState::from_tag(*to).ok_or_else(|| {
            KernelError::Corrupt(format!(
                "period transition entry {:032x} bad to tag",
                evid.0
            ))
        })?;
        out.push(PeriodTransitionRecord {
            entry_vid: evid,
            entry_digest: entry.entry_digest,
            recorded_at,
            effective_date: entry.proposal.effective_date,
            from: from_state,
            to: to_state,
            reason_code: *reason_code,
            principal_ref: entry.proposal.principal_ref,
            approvals: entry.approvals,
        });
    }
    out.sort_by_key(|r| (r.recorded_at, r.entry_vid));
    Ok(out)
}

/// The `AS ORIGINALLY REPORTED` coordinate of one period (plan §7.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginallyReported {
    pub period: String,
    /// The known-at sequence every read `AS ORIGINALLY REPORTED` pins.
    pub known_at: CommitSeq,
    /// The control entry that fixed it.
    pub basis: ReportedBasis,
}

/// What fixed a period's `AS ORIGINALLY REPORTED` coordinate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReportedBasis {
    /// The period's first `StatementIssuance`: the coordinate is the
    /// `certified_at` of the certificate it issued.
    Issuance(Box<crate::issuance::IssuanceRecord>),
    /// No issuance: the period's first `Lock`, at its recorded sequence.
    Lock(PeriodTransitionRecord),
}

/// Where `AS ORIGINALLY REPORTED` pins a period's reads (plan §7.4): the
/// known-at of the certificate the period's first `StatementIssuance`
/// issued and, absent any issuance, its first `Lock` transition, never its
/// first `Close`, because `Closed` admits audit adjustments by design. A
/// period neither issued nor locked was never reported, which is a refusal,
/// not HEAD.
pub fn originally_reported<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period_code: &str,
) -> Outcome<OriginallyReported> {
    if db
        .vertex(period_vid(&book.calendar.id, period_code))?
        .is_none()
    {
        return Ok(Err(unknown_period(book, period_code)));
    }
    if let Some(first) = crate::issuance::first_issuance(db, book, period_code)? {
        return Ok(Ok(OriginallyReported {
            period: period_code.to_string(),
            known_at: first.issuance.certified_at,
            basis: ReportedBasis::Issuance(Box::new(first)),
        }));
    }
    let first_lock = period_transitions(db, book, period_code)?
        .into_iter()
        .find(|t| t.to == PeriodState::Locked);
    Ok(match first_lock {
        Some(lock) => Ok(OriginallyReported {
            period: period_code.to_string(),
            known_at: lock.recorded_at,
            basis: ReportedBasis::Lock(lock),
        }),
        None => Err(Refusal::new(
            code::NOT_ORIGINALLY_REPORTED,
            exit::REFUSAL,
            format!(
                "period `{period_code}` has no Lock transition and no statement issuance, so nothing was originally reported (an opening period born Locked has neither)"
            ),
            "plan §7.4 (AS ORIGINALLY REPORTED pins the first StatementIssuance, else the first Lock; never the first Close)",
            format!(
                "read the period as currently stated (omit --as-originally-reported); record the statements that left the entity with `fa statement issue --certificate C:<oid> --for {period_code} --issued-to <audience>`, or lock the period once it is final: fa period lock {period_code} --reason AuditComplete --yes"
            ),
        )),
    })
}

/// One fiscal period's refolded state vs its stored `Period.state` mirror (`fa verify periods`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodCheck {
    pub code: String,
    pub fiscal_year: i32,
    pub ordinal: u16,
    pub kind: PeriodKind,
    pub born_state: PeriodState,
    pub stored_state: Option<PeriodState>,
    pub refolded_state: PeriodState,
    pub transitions: usize,
    pub green: bool,
}

/// Comparison of retained period declarations and transitions with `Period`
/// states and mirrors (`fa verify periods`, plan §7.3, FA-INV-02
/// `lifecycle-by-transition`). Complete journal integrity is a separate check
/// by [`crate::verify_entry_history`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodVerification {
    pub known_at: CommitSeq,
    pub periods_checked: usize,
    /// Version-1 periods checked against the old calendar-derived baseline.
    /// They have no recorded creation principal or independently enumerable
    /// birth declarations; a wholly missing legacy year cannot be discovered.
    pub legacy_periods: usize,
    pub transitions_checked: usize,
    pub periods: Vec<PeriodCheck>,
    pub drift: Vec<String>,
}

impl PeriodVerification {
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.drift.is_empty()
    }
}

fn is_legal_step(from: PeriodState, to: PeriodState) -> bool {
    [
        PeriodTransition::Open,
        PeriodTransition::SoftClose,
        PeriodTransition::Close,
        PeriodTransition::Lock,
        PeriodTransition::Reopen {
            to: PeriodState::Open,
        },
        PeriodTransition::Reopen {
            to: PeriodState::SoftClosed,
        },
    ]
    .into_iter()
    .any(|t| transition(from, t) == Ok(to))
}

/// Refold every `Period` vertex's state from its retained birth declaration
/// and its retained `PeriodControl` transition stream at `known_at` (or HEAD
/// when `None`), comparing it against the stored `Period` mirrors and `IN_BOOK` /
/// `IN_PERIOD` topology (plan §7.3, FA-INV-02 `lifecycle-by-transition`).
/// This validates declaration projections. Complete journal integrity also
/// requires [`crate::verify_entry_history`] at the same prefix: retiring both
/// a fiscal year's control and all its projections can hide that year from
/// this visible-row comparison.
///
/// Version-1 books retain their original calendar-derived baseline for rows
/// preceding their earliest retained CreatePeriods control. This legacy
/// check cannot prove creation provenance or discover a wholly missing old
/// fiscal year; `legacy_periods` makes that narrower coverage explicit.
pub fn verify_periods<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    known_at: Option<CommitSeq>,
) -> Result<PeriodVerification, KernelError> {
    use std::collections::{BTreeMap, BTreeSet};

    let known_at = known_at.unwrap_or(db.frontier()?);
    let rows: Vec<_> = db
        .vertices_at(known_at)?
        .into_iter()
        .map(|row| row.seen_at(known_at))
        .collect();
    let edges = db.edges_at(known_at)?;
    let bvid = crate::rows::book_root();
    let root_row = rows
        .iter()
        .find(|r| r.vid == bvid && r.labels.contains(&label::BOOK))
        .ok_or_else(|| {
            KernelError::Corrupt(format!(
                "periods need a book: no genesis row at sequence {}",
                known_at.0
            ))
        })?;
    let spec_bytes = crate::rows::bytes(root_row, property::FA_PAYLOAD, "book._fa_payload")?;
    let spec = crate::genesis::BookSpec::decode(&spec_bytes)?;
    let legacy_genesis = spec_bytes.starts_with(&1_u16.to_le_bytes());
    let classes =
        fa_registry::EntryClasses::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let matrix = fa_registry::Admissibility::embedded(&classes)
        .map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let pre_opening = matrix
        .pre_opening()
        .ok_or_else(|| KernelError::Corrupt("admissibility.toml has no pre_opening rule".into()))?;

    let mut in_book_periods: BTreeSet<VId> = BTreeSet::new();
    let mut in_period_by_entry: BTreeMap<VId, BTreeSet<VId>> = BTreeMap::new();
    for edge in &edges {
        let e = &edge.entry;
        if e.relation == relation::IN_BOOK
            && e.dst == bvid
            && e.eid == edge_id(relation::IN_BOOK, e.src, bvid)
            && edge.props.is_empty()
        {
            in_book_periods.insert(e.src);
        } else if e.relation == relation::IN_PERIOD
            && e.eid == edge_id(relation::IN_PERIOD, e.src, e.dst)
            && edge.props.is_empty()
        {
            in_period_by_entry.entry(e.src).or_default().insert(e.dst);
        }
    }

    let mut drift: Vec<String> = Vec::new();
    let births = match crate::period_creation::births_from_rows(&rows, book) {
        Ok(births) => births,
        Err(error) => {
            drift.push(error.to_string());
            BTreeMap::new()
        }
    };
    for birth in births.values() {
        if !in_book_periods.contains(&birth.control_entry) {
            drift.push(format!(
                "period creation {:032x} is missing its IN_BOOK edge",
                birth.control_entry.0
            ));
        }
    }
    let mut transitions_checked: usize = 0;
    let mut transitions_by_period: BTreeMap<
        String,
        Vec<(CommitSeq, VId, PeriodState, PeriodState)>,
    > = BTreeMap::new();

    for row in &rows {
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let payload = match crate::rows::bytes(row, property::FA_PAYLOAD, "entry._fa_payload") {
            Ok(b) => b,
            Err(e) => {
                drift.push(format!("entry {:032x}: {e}", row.vid.0));
                continue;
            }
        };
        let entry = match fa_model::Entry::decode(&payload) {
            Ok(e) => e,
            Err(e) => {
                drift.push(format!("entry {:032x} payload: {e}", row.vid.0));
                continue;
            }
        };
        let is_period_control_class = entry.proposal.class == EntryClass::PERIOD_CONTROL;
        match &entry.proposal.control {
            Some(ControlPayload::PeriodTransition {
                period_ref,
                from,
                to,
                ..
            }) => {
                transitions_checked += 1;
                if !is_period_control_class {
                    drift.push(format!(
                        "entry {:032x} carries PeriodTransition payload under class {:?}",
                        row.vid.0, entry.proposal.class
                    ));
                }
                if entry.proposal.book_id != book.book_id
                    || entry.proposal.branch_id != Id128::TRUNK
                {
                    drift.push(format!(
                        "period transition entry {:032x} coordinate disagrees with trunk book",
                        row.vid.0
                    ));
                }
                if period_ref.calendar != book.calendar.id {
                    drift.push(format!(
                        "period transition entry {:032x} names calendar `{}`, expected `{}`",
                        row.vid.0, period_ref.calendar, book.calendar.id
                    ));
                }
                if entry.proposal.effective_period.as_ref() != Some(period_ref) {
                    drift.push(format!(
                        "period transition entry {:032x} effective_period disagrees with control payload `{}`",
                        row.vid.0, period_ref.code
                    ));
                }
                let expected_evid = entry_vid(
                    book.book_id,
                    &entry.proposal.principal_ref.0.to_le_bytes(),
                    &entry.proposal.idempotency_key,
                );
                if row.vid != expected_evid {
                    drift.push(format!(
                        "period transition entry {:032x} identity disagrees with derived {:032x}",
                        row.vid.0, expected_evid.0
                    ));
                }
                for (key, value) in entry_mirrors(&entry)? {
                    if crate::rows::prop(row, key) != Some(&value) {
                        drift.push(format!(
                            "period transition entry {:032x} mirror {} disagrees with payload",
                            row.vid.0, key.0
                        ));
                    }
                }
                let expected_pvid = period_vid(&book.calendar.id, &period_ref.code);
                let linked = in_period_by_entry.get(&row.vid);
                if !linked.is_some_and(|set| set.len() == 1 && set.contains(&expected_pvid)) {
                    drift.push(format!(
                        "period transition entry {:032x} is missing its IN_PERIOD edge to period `{}` ({:032x})",
                        row.vid.0, period_ref.code, expected_pvid.0
                    ));
                }
                let from_state = PeriodState::from_tag(*from);
                let to_state = PeriodState::from_tag(*to);
                match (from_state, to_state) {
                    (Some(f), Some(t)) => {
                        // The period law dates the control (fa-87r).
                        match policy::calendar_period(book, &period_ref.code) {
                            Some(def)
                                if entry.proposal.effective_date == transition_date(&def, f) => {}
                            Some(def) => drift.push(format!(
                                "period transition entry {:032x} is dated {}; the period law dates `{}` {} -> {} on {}",
                                row.vid.0,
                                entry.proposal.effective_date.render(),
                                period_ref.code,
                                f.name(),
                                t.name(),
                                transition_date(&def, f).render()
                            )),
                            None => drift.push(format!(
                                "period transition entry {:032x} names period `{}`, which calendar `{}` does not define",
                                row.vid.0, period_ref.code, book.calendar.id
                            )),
                        }
                        transitions_by_period
                            .entry(period_ref.code.clone())
                            .or_default()
                            .push((row.created_at, row.vid, f, t));
                    }
                    _ => {
                        drift.push(format!(
                            "period transition entry {:032x} for `{}` has invalid state tags ({from} -> {to})",
                            row.vid.0, period_ref.code
                        ));
                    }
                }
            }
            _ if is_period_control_class => {
                drift.push(format!(
                    "entry {:032x} has class PeriodControl without a PeriodTransition payload",
                    row.vid.0
                ));
            }
            _ => {}
        }
    }

    let mut period_rows: BTreeMap<String, &fgdb::VertexRow> = BTreeMap::new();
    let journal_cutover = births.values().map(|birth| birth.recorded_at).min();
    // A state transition creates a new row version. Membership in the
    // pre-control snapshot, rather than that version's created_at, decides
    // whether an old Period belongs to the version-1 baseline.
    let legacy_members: BTreeSet<_> = if legacy_genesis {
        let basis =
            journal_cutover.map_or(known_at, |cutover| CommitSeq(cutover.0.saturating_sub(1)));
        db.vertices_at(basis)?
            .into_iter()
            .filter(|row| row.labels.contains(&label::PERIOD))
            .map(|row| row.vid)
            .collect()
    } else {
        BTreeSet::new()
    };
    let is_legacy_row = |row: &fgdb::VertexRow| legacy_members.contains(&row.vid);
    let mut legacy_years: BTreeSet<i32> = BTreeSet::new();
    for row in &rows {
        if !row.labels.contains(&label::PERIOD) {
            continue;
        }
        let code = match crate::rows::text(row, property::CODE, "period.code") {
            Ok(c) => c,
            Err(e) => {
                drift.push(format!("period vertex {:032x}: {e}", row.vid.0));
                continue;
            }
        };
        if period_rows.insert(code.clone(), row).is_some() {
            drift.push(format!("period `{code}` has multiple Period vertices"));
        }
        if is_legacy_row(row)
            && !births.contains_key(&code)
            && let Ok(year) = crate::rows::int(row, property::FISCAL_YEAR, "period.fiscal_year")
            && let Ok(year) = i32::try_from(year)
        {
            legacy_years.insert(year);
        }
    }

    let mut legacy_definitions = BTreeMap::new();
    for year in legacy_years {
        match crate::period_creation::PeriodCreation::from_spec(&spec, year) {
            Ok(creation) => {
                for (definition, state) in creation.periods {
                    if !period_rows.contains_key(&definition.code) {
                        drift.push(format!(
                            "legacy period `{}` of fiscal year {year} is missing from stored Period vertices",
                            definition.code
                        ));
                    }
                    legacy_definitions.insert(definition.code.clone(), (definition, state));
                }
            }
            Err(error) => drift.push(format!("legacy fiscal year {year}: {error}")),
        }
    }

    for (code, birth) in &births {
        if !period_rows.contains_key(code) {
            drift.push(format!(
                "period `{code}` declared at sequence {} is missing from stored Period vertices",
                birth.recorded_at.0
            ));
        }
    }

    let mut checks: Vec<PeriodCheck> = Vec::with_capacity(period_rows.len());
    let mut legacy_periods = 0;
    for (code, row) in &period_rows {
        let mut period_green = true;
        let mut note_drift = |msg: String| {
            period_green = false;
            drift.push(msg);
        };

        if row.labels.as_slice() != [label::PERIOD] {
            note_drift(format!(
                "period `{code}` ({:032x}) has unexpected labels",
                row.vid.0
            ));
        }
        if row.retired_at.is_some() {
            note_drift(format!(
                "period `{code}` is retired; period projections are retained"
            ));
        }
        let expected_pvid = period_vid(&book.calendar.id, code);
        if row.vid != expected_pvid {
            note_drift(format!(
                "period `{code}` is stored at {:032x}, expected {:032x}",
                row.vid.0, expected_pvid.0
            ));
        }
        if !in_book_periods.contains(&row.vid) {
            note_drift(format!(
                "period `{code}` ({:032x}) is missing its IN_BOOK edge to book root",
                row.vid.0
            ));
        }
        match crate::rows::bytes(row, property::BOOK_ID, "period.book_id") {
            Ok(b) if b.as_slice() == book.book_id.0 => {}
            _ => note_drift(format!(
                "period `{code}` book_id mirror disagrees with book"
            )),
        }
        match crate::rows::text(row, property::CALENDAR_ID, "period.calendar_id") {
            Ok(cid) if cid == book.calendar.id => {}
            _ => note_drift(format!(
                "period `{code}` calendar_id mirror disagrees with `{}`",
                book.calendar.id
            )),
        }

        let stored_fy = crate::rows::int(row, property::FISCAL_YEAR, "period.fiscal_year")
            .ok()
            .and_then(|v| i32::try_from(v).ok());
        let stored_ordinal = crate::rows::int(row, property::ORDINAL, "period.ordinal")
            .ok()
            .and_then(|v| u16::try_from(v).ok());
        let stored_kind =
            crate::rows::kind_from_scalar(crate::rows::prop(row, property::PERIOD_KIND));
        let stored_start = crate::rows::int(row, property::PERIOD_START, "period.period_start")
            .ok()
            .and_then(|v| i32::try_from(v).ok())
            .map(DateDay);
        let stored_end = crate::rows::int(row, property::PERIOD_END, "period.period_end")
            .ok()
            .and_then(|v| i32::try_from(v).ok())
            .map(DateDay);
        let stored_state = match crate::rows::prop(row, property::STATE) {
            Some(CanonicalScalar::Int(i)) => u8::try_from(*i).ok().and_then(PeriodState::from_tag),
            _ => None,
        };

        let (
            expected_fy,
            expected_ordinal,
            expected_kind,
            born_state,
            expected_start,
            expected_end,
        ) = if let Some(birth) = births.get(code) {
            let def = &birth.definition;
            let original = db.vertex_at(expected_pvid, birth.recorded_at)?;
            let existed_before = birth
                .recorded_at
                .0
                .checked_sub(1)
                .map(|sequence| db.vertex_at(expected_pvid, CommitSeq(sequence)))
                .transpose()?
                .flatten()
                .is_some();
            if existed_before
                || original.as_ref().is_none_or(|original| {
                    original.created_at != birth.recorded_at
                        || original.birth_ordinal != row.birth_ordinal
                        || original.labels.as_slice() != [label::PERIOD]
                        || crate::rows::prop(original, property::STATE)
                            != Some(&CanonicalScalar::Int(i64::from(birth.born_state.tag())))
                })
            {
                note_drift(format!(
                    "period `{code}` has no matching native projection birth at declaration sequence {}",
                    birth.recorded_at.0
                ));
            }
            (
                def.fiscal_year,
                def.ordinal,
                def.kind,
                birth.born_state,
                def.start,
                def.end,
            )
        } else if is_legacy_row(row)
            && let Some((def, state)) = legacy_definitions.get(code)
        {
            legacy_periods += 1;
            (
                def.fiscal_year,
                def.ordinal,
                def.kind,
                *state,
                def.start,
                def.end,
            )
        } else {
            note_drift(format!(
                "period `{code}` has no journaled birth declaration in calendar `{}`",
                book.calendar.id
            ));
            (
                stored_fy.unwrap_or(0),
                stored_ordinal.unwrap_or(0),
                stored_kind.unwrap_or(PeriodKind::Normal),
                PeriodState::Future,
                stored_start.unwrap_or(DateDay(0)),
                stored_end.unwrap_or(DateDay(0)),
            )
        };

        if stored_fy != Some(expected_fy) {
            note_drift(format!(
                "period `{code}` fiscal_year mirror is {stored_fy:?}, expected {expected_fy}"
            ));
        }
        if stored_ordinal != Some(expected_ordinal) {
            note_drift(format!(
                "period `{code}` ordinal mirror is {stored_ordinal:?}, expected {expected_ordinal}"
            ));
        }
        if stored_kind != Some(expected_kind) {
            note_drift(format!(
                "period `{code}` period_kind mirror is {stored_kind:?}, expected {expected_kind:?}"
            ));
        }
        if stored_start != Some(expected_start) {
            note_drift(format!(
                "period `{code}` period_start mirror disagrees with calendar definition"
            ));
        }
        if stored_end != Some(expected_end) {
            note_drift(format!(
                "period `{code}` period_end mirror disagrees with calendar definition"
            ));
        }

        let mut transitions = transitions_by_period.get(code).cloned().unwrap_or_default();
        transitions.sort_by_key(|(seq, evid, _, _)| (*seq, *evid));

        let immobile = matrix.kind_rule(expected_kind).is_some()
            || pre_opening.governs(expected_kind, expected_end, spec.opening_date);
        if immobile && !transitions.is_empty() {
            note_drift(format!(
                "period `{code}` ({expected_kind:?}) is born {} and cannot transition, but has {} PeriodControl entry(s)",
                born_state.name(),
                transitions.len()
            ));
        }

        let mut refolded_state = born_state;
        for (seq, evid, from_state, to_state) in &transitions {
            if births
                .get(code)
                .is_some_and(|birth| *seq <= birth.recorded_at)
            {
                note_drift(format!(
                    "period `{code}` transition {:032x} does not follow its birth declaration",
                    evid.0
                ));
            }
            if *from_state != refolded_state {
                note_drift(format!(
                    "period `{code}` transition {:032x} at sequence {} claims from={}, but refolded state was {}",
                    evid.0,
                    seq.0,
                    from_state.name(),
                    refolded_state.name()
                ));
            }
            if !is_legal_step(*from_state, *to_state) {
                note_drift(format!(
                    "period `{code}` transition {:032x} at sequence {} takes illegal step {} -> {}",
                    evid.0,
                    seq.0,
                    from_state.name(),
                    to_state.name()
                ));
            }
            refolded_state = *to_state;
        }

        if stored_state != Some(refolded_state) {
            note_drift(format!(
                "period `{code}` state mirror is {}, but journaled transitions from {} refold to {}",
                stored_state.map_or("missing/corrupt", PeriodState::name),
                born_state.name(),
                refolded_state.name()
            ));
        }

        checks.push(PeriodCheck {
            code: code.clone(),
            fiscal_year: expected_fy,
            ordinal: expected_ordinal,
            kind: expected_kind,
            born_state,
            stored_state,
            refolded_state,
            transitions: transitions.len(),
            green: period_green,
        });
    }

    for (code, ts) in &transitions_by_period {
        if !period_rows.contains_key(code) {
            for (seq, evid, from, to) in ts {
                drift.push(format!(
                    "period transition entry {:032x} at sequence {} ({} -> {}) names non-existent period `{code}`",
                    evid.0,
                    seq.0,
                    from.name(),
                    to.name()
                ));
            }
        }
    }

    checks.sort_by(|a, b| {
        (a.fiscal_year, a.ordinal, a.code.as_str()).cmp(&(
            b.fiscal_year,
            b.ordinal,
            b.code.as_str(),
        ))
    });

    Ok(PeriodVerification {
        known_at,
        periods_checked: checks.len(),
        legacy_periods,
        transitions_checked,
        periods: checks,
        drift,
    })
}
