//! Period transitions as journaled control records (plan §7.3, fa-bvx).
//!
//! A transition is one commit carrying a `PeriodControl` entry (legs = [],
//! `ControlPayload::PeriodTransition`) and a compare-and-set on the period's
//! `state` mirror. The compare-and-set is the witness: a post that read the
//! old state in its own transaction and a close that moves it are
//! first-committer-wins rivals, never a cron job's finding.

use fa_model::symbols::{label, property, relation};
use fa_model::{
    ControlPayload, EntryClass, EntryOrigin, EntryPayload, EntryRef, Erasable, Id128, PeriodRef,
    entry_mirrors, entry_vid, period_vid,
};
use fa_time::period::transition;
use fa_time::{DateDay, PeriodState, PeriodTransition};
use fgdb::{Database, WriteBatch, WriteMismatchPolicy, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::genesis::BookContext;
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

/// Move one period along the state machine, journaled.
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
) -> Outcome<Transitioned> {
    let pvid = period_vid(&book.calendar.id, period_code);
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;

    let Some(row) = txn.vertex(db, pvid)? else {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::PERIOD_UNKNOWN,
            exit::SAFETY,
            format!(
                "period `{period_code}` does not exist in calendar `{}`",
                book.calendar.id
            ),
            "plan §7.3 (periods are created per fiscal year)",
            format!("fa period create --fiscal-year <FY> (then transition `{period_code}`)"),
        )));
    };
    let from = state_from_scalar(crate::rows::prop(&row, property::STATE))
        .ok_or_else(|| KernelError::Corrupt(format!("period `{period_code}` state mirror")))?;
    let to = match transition(from, t) {
        Ok(s) => s,
        Err(_) => {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::TRANSITION,
                exit::SAFETY,
                format!(
                    "period `{period_code}` is {} and cannot take {t:?}",
                    from.name()
                ),
                "plan §7.3 period state machine",
                "pick a legal transition: Future→Open, Open→SoftClose, SoftClosed→Close|Reopen, Closed→Lock|Reopen",
            )));
        }
    };

    let proposal = EntryPayload {
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
            control_kind: 2,
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
    };
    let entry = proposal.seal(Vec::new(), None)?;
    let evid = entry_vid(
        book.book_id,
        &principal_ref.0.to_le_bytes(),
        idempotency_key,
    );

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
        // reversals are the book's (its System principal). Executor
        // capability admission arrives with fa-llx's start-of-function hunk;
        // until then the hook rechecks the Reversal row, SoD and epoch.
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
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(Transitioned {
            period: period_code.to_string(),
            from,
            to,
            recorded_at: seq,
            control_entry: evid,
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
                format!("period `{period_code}` is no longer {}", from.name()),
                "plan §7.3 (state changes are serialized through the period vertex)",
                "re-read the period state and choose the transition again",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "a control entry with this idempotency key already exists",
            "plan §4.9",
            "use a fresh idempotency key",
        ))),
        Err(e) => Err(e.into()),
    }
}
