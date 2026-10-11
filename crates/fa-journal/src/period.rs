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
use fa_time::{DateDay, PeriodState, PeriodTransition};
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
}

/// An authorized period transition staged against its original witnesses.
/// Its capability and effects cannot be replaced after preparation. Dropping
/// it abandons the staged write and releases the substrate's read pin.
#[derive(Debug)]
#[must_use]
pub struct PreparedTransition {
    txn: WriteTxn,
    capability: Capability,
    period: String,
    from: PeriodState,
    to: PeriodState,
    control_entry: VId,
    minted: Vec<(EntryRef, EntryRef)>,
    blocked: Vec<(EntryRef, String)>,
}

impl PreparedTransition {
    /// The committed prefix from which the transition's witnesses were read.
    #[must_use]
    pub fn basis(&self) -> CommitSeq {
        self.txn.basis()
    }

    /// Release the prepared transaction without publishing any effects.
    pub fn abort(self) {
        self.txn.abort();
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
        let Self {
            mut txn,
            capability,
            period,
            from,
            to,
            control_entry,
            minted,
            blocked,
        } = self;
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
            )) => Ok(Err(reused_key())),
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

/// The `PeriodControl` proposal a transition commits, deterministic in its
/// inputs, so an approver can compute the `proposal_digest` it approves:
/// the same period, from/to states, preparer, reason, date, key and
/// description bytes the preparer will submit.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn transition_proposal(
    book: &BookContext,
    period_code: &str,
    from: PeriodState,
    to: PeriodState,
    principal_ref: VId,
    reason_code: u16,
    effective_date: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
) -> EntryPayload {
    EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::PERIOD_CONTROL,
        effective_date,
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

fn unknown_period(book: &BookContext, period_code: &str) -> Refusal {
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

fn reused_key() -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        "a control entry with this idempotency key already exists",
        "plan §4.9",
        "use a fresh idempotency key",
    )
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
    Refusal::new(
        code::TRANSITION,
        exit::SAFETY,
        format!(
            "period `{period_code}` is {} and cannot take {t:?}",
            from.name()
        ),
        "plan §7.3 period state machine",
        "pick a legal transition: Future→Open, Open→SoftClose, SoftClosed→Close|Reopen, Closed→Lock|Reopen",
    )
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
    pub effective_date: DateDay,
    pub idempotency_key: Vec<u8>,
    pub description: Erasable<String>,
}

/// The plan file's leading domain tag; the format is versioned after it.
pub const PLAN_DOMAIN: &[u8; 14] = b"fa:period-plan";
const PLAN_VERSION: u16 = 1;

impl TransitionPlan {
    /// The proposal this plan commits.
    #[must_use]
    pub fn proposal(&self, book: &BookContext) -> EntryPayload {
        transition_proposal(
            book,
            &self.period_code,
            self.from,
            self.to,
            self.principal_ref,
            self.reason_code,
            self.effective_date,
            &self.idempotency_key,
            self.description.clone(),
        )
    }

    /// The digest an approval of this plan binds.
    pub fn proposal_digest(&self, book: &BookContext) -> Result<[u8; 32], KernelError> {
        Ok(self.proposal(book).proposal_digest()?)
    }

    /// `"fa:period-plan" ‖ u16 version ‖ str period ‖ u8 from ‖ u8 to ‖
    /// u128 principal ‖ u16 reason ‖ i32 date ‖ bytes key ‖ erasable
    /// description`.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(PLAN_DOMAIN)
            .u16(PLAN_VERSION)
            .str(&self.period_code)
            .u8(self.from.tag())
            .u8(self.to.tag())
            .u128(self.principal_ref.0)
            .u16(self.reason_code)
            .i32(self.effective_date.0)
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
            effective_date: DateDay(r.i32("plan.date")?),
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
    effective_date: DateDay,
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
    Ok(Ok(TransitionPlan {
        period_code: period_code.to_string(),
        from,
        to,
        principal_ref,
        reason_code,
        effective_date,
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
    effective_date: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
    capability: &Capability,
    approvals: &[ApprovalRef],
) -> Outcome<Transitioned> {
    match prepare_transition(
        db,
        ctx,
        book,
        period_code,
        t,
        principal_ref,
        reason_code,
        effective_date,
        idempotency_key,
        description,
        capability,
        approvals,
    )? {
        Ok(prepared) => prepared.commit(db, ctx).await,
        Err(refusal) => Ok(Err(refusal)),
    }
}

/// Stage the production transition without publishing it. Its witnesses
/// remain pinned while another prepared operation is allowed to commit;
/// [`PreparedTransition::commit`] validates those original witnesses.
#[allow(clippy::too_many_arguments)]
pub fn prepare_transition<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    period_code: &str,
    t: PeriodTransition,
    principal_ref: VId,
    reason_code: u16,
    effective_date: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
    capability: &Capability,
    approvals: &[ApprovalRef],
) -> Outcome<PreparedTransition> {
    ctx.txn().checkpoint().map_err(WriteTxnError::Interrupted)?;
    // 0. Authorization precedes observation (doctrine 8, FA-INV-10): decided
    //    from the capability and the request alone, before the period is read.
    let steward = policy::steward()?;
    let name = transition_name(t);
    let op = steward
        .transition_op("PeriodControl", name)
        .ok_or_else(|| {
            KernelError::Corrupt(format!(
                "sod_policy.toml registers no PeriodControl {name} rule; the transition is refused, never unconstrained"
            ))
        })?;
    if let Err(d) = fa_policy::admit(
        capability,
        &Intent {
            principal: principal_ref,
            trunk: true,
            op,
            book: book.book_id,
            legs: &[],
        },
    ) {
        return Ok(Err(policy::refusal(&d)));
    }
    if let Err(d) = fa_policy::current(capability, db.frontier()?) {
        return Ok(Err(policy::refusal(&d)));
    }

    let pvid = period_vid(&book.calendar.id, period_code);
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    // Current authority: not revoked, under the witnessed policy epoch.
    if let Err(r) = policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
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
    let Ok(to) = transition(from, t) else {
        txn.abort();
        return Ok(Err(illegal_transition(period_code, from, t)));
    };

    let proposal = transition_proposal(
        book,
        period_code,
        from,
        to,
        principal_ref,
        reason_code,
        effective_date,
        idempotency_key,
        description,
    );
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
        &proposal.proposal_digest()?,
        epoch,
        &key,
        0,
        preparer,
    )? {
        txn.abort();
        return Ok(Err(r));
    }
    let entry = proposal.seal(approvals.to_vec(), None)?;
    let evid = entry_vid(
        book.book_id,
        &principal_ref.0.to_le_bytes(),
        idempotency_key,
    );
    // The control entry's identity derives from the key, so an existing one
    // is a reused key: refused here, before staging (the substrate would
    // reject the batch as AlreadyLive), and the absent read is a witness.
    if txn.vertex(db, evid)?.is_some() {
        txn.abort();
        return Ok(Err(reused_key()));
    }

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
        // function (fa-llx); the hook still rechecks the Reversal row, SoD
        // and epoch for each minted entry.
        match crate::schedule::mint_on_open(&txn, db, book, period_code, evid)? {
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
        txn,
        capability: capability.clone(),
        period: period_code.to_string(),
        from,
        to,
        control_entry: evid,
        minted,
        blocked,
    }))
}
