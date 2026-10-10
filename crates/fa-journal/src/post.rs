//! The post pipeline (plan §5.1, §5.10, §7.3, §8.4): resolve → laws → commit.
//!
//! Order matters and is the point: nothing is staged until every law has
//! passed inside the transaction that read the witnesses it depends on. The
//! period's state is read through the transaction (a point-read witness), so
//! a close that commits first makes this post a first-committer-wins
//! conflict — exit 6, retry with a fresh read — never a post that slipped
//! into a closed period.

use std::collections::BTreeSet;

use fa_model::symbols::{label, property, relation};
use fa_model::{
    ApprovalRef, Entry, EntryPayload, EntryRef, entry_mirrors, entry_vid, leg_mirrors, period_vid,
};
use fa_registry::{Admissibility, Decision, EntryClasses};
use fa_time::resolve_period;
use fgdb::{Database, VertexRow, WriteBatch, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::genesis::{BookContext, UnitPolicy};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{AccountRow, edge_id, leg_vid, prop, state_from_scalar};

/// The capability ops a principal holds (`post`, `post_softclosed`,
/// `post_closed`, `close`, `restate`, `migrate`). Steward (plan §14) issues
/// these; in this slice the facade supplies them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Capability {
    pub ops: BTreeSet<String>,
}

impl Capability {
    pub fn with_ops(ops: &[&str]) -> Self {
        Self {
            ops: ops.iter().map(|s| (*s).to_string()).collect(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PostRequest {
    pub proposal: EntryPayload,
    pub approvals: Vec<ApprovalRef>,
    /// The principal scope the entry identity is derived under (plan §4.9).
    pub principal_scope: Vec<u8>,
    pub capability: Capability,
    /// The dry-run certificate the plan was approved under, bound in the envelope.
    pub plan_certificate: Option<fa_model::Oid>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Posted {
    Committed {
        entry_ref: EntryRef,
        recorded_at: CommitSeq,
        period: String,
    },
    /// The idempotency key was already recorded; this is that outcome.
    AlreadyRecorded {
        entry_ref: EntryRef,
        recorded_at: CommitSeq,
    },
}

impl Posted {
    #[must_use]
    pub fn entry_ref(&self) -> EntryRef {
        match self {
            Self::Committed { entry_ref, .. } | Self::AlreadyRecorded { entry_ref, .. } => {
                *entry_ref
            }
        }
    }

    #[must_use]
    pub fn recorded_at(&self) -> CommitSeq {
        match self {
            Self::Committed { recorded_at, .. } | Self::AlreadyRecorded { recorded_at, .. } => {
                *recorded_at
            }
        }
    }

    /// The period a fresh commit landed in; `None` for a recorded outcome.
    #[must_use]
    pub fn period(&self) -> Option<&str> {
        match self {
            Self::Committed { period, .. } => Some(period),
            Self::AlreadyRecorded { .. } => None,
        }
    }
}

fn recorded(row: &VertexRow) -> Result<Posted, KernelError> {
    let digest = match prop(row, property::FA_DIGEST) {
        Some(CanonicalScalar::Bytes(b)) if b.len() == 32 => {
            let mut d = [0u8; 32];
            d.copy_from_slice(b.as_slice());
            d
        }
        other => return Err(KernelError::Corrupt(format!("entry _fa_digest: {other:?}"))),
    };
    Ok(Posted::AlreadyRecorded {
        entry_ref: EntryRef {
            vid: row.vid,
            entry_digest: digest,
        },
        recorded_at: row.created_at,
    })
}

/// Post one entry. Exactly one substrate transaction commits on success;
/// a refusal leaves the book unchanged.
pub async fn post<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    req: PostRequest,
) -> Outcome<Posted> {
    let proposal = &req.proposal;

    // 1. Structure (fa-model's rules). Usage error: the payload is malformed.
    if let Err(e) = proposal.validate() {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            e.to_string(),
            "Appendix A fa:entry:v1",
            "fix the named field and resubmit",
        )));
    }
    let class_name = proposal.class.name().unwrap_or("?");
    if proposal.class.is_control() {
        return Ok(Err(Refusal::new(
            code::CONTROL_VIA_POST,
            exit::USAGE,
            format!("`{class_name}` is a control class"),
            "plan §8.1",
            "use `fa period <transition>` or `fa chart import`; control records are not posted",
        )));
    }

    // 2. Balance law per unit (FA-INV-01). The suggested residual is text.
    for t in &proposal.unit_totals {
        if t.debits != t.credits {
            let diff = t.debits - t.credits;
            let unit = book
                .units
                .get(fa_money::UnitId(t.unit_id))
                .map_or_else(|| format!("unit {}", t.unit_id), |u| u.code.clone());
            let side = if diff > 0 { "credit" } else { "debit" };
            return Ok(Err(Refusal::new(
                code::UNBALANCED,
                exit::REFUSAL,
                format!(
                    "{unit}: debits {} ≠ credits {} (difference {})",
                    t.debits,
                    t.credits,
                    diff.abs()
                ),
                "FA-INV-01 per-unit balance law",
                format!(
                    "add a {side} leg of {} {unit} to the account that explains it; the kernel never invents one",
                    diff.abs()
                ),
            )));
        }
    }

    // 3. Resolve the effective date to exactly one period (plan §7.3).
    let fy = book.calendar.fiscal_year_of(proposal.effective_date)?;
    let periods = book.calendar.periods_for_year(fy)?;
    let period = match resolve_period(
        &periods,
        proposal.effective_date,
        proposal.effective_period.as_ref().map(|p| p.code.as_str()),
    ) {
        Ok(p) => p.clone(),
        Err(e) => {
            return Ok(Err(Refusal::new(
                code::PERIOD_RESOLVE,
                exit::REFUSAL,
                format!(
                    "effective date {} does not resolve to one period: {e:?}",
                    proposal.effective_date.render()
                ),
                "plan §7.3 (effective_period discriminator)",
                "name the period with effective_period when the date is shared with an adjustment, opening, or closing period",
            )));
        }
    };

    // From here every read is a witness of this transaction.
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;

    // 4. Idempotency by derived identity (plan §4.9, FA-INV-09).
    let evid = entry_vid(
        book.book_id,
        &req.principal_scope,
        &proposal.idempotency_key,
    );
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return Ok(Ok(recorded(&row)?));
    }

    // 5. Period law (Appendix C) against the witnessed state.
    let pvid = period_vid(&book.calendar.id, &period.code);
    let state_scalar = txn.vertex_property(db, pvid, property::STATE)?;
    let state = state_from_scalar(state_scalar.as_ref())
        .ok_or_else(|| KernelError::Corrupt(format!("period `{}` state mirror", period.code)))?;
    let classes = EntryClasses::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let matrix =
        Admissibility::embedded(&classes).map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let cell = format!("admissibility.toml ({class_name}, {})", state.name());
    match matrix.decide(class_name, state) {
        Some(Decision::Admit) => {}
        Some(Decision::With { op, approvals }) => {
            if !req.capability.ops.contains(op) {
                txn.abort();
                return Ok(Err(Refusal::new(
                    code::CAPABILITY,
                    exit::SAFETY,
                    format!(
                        "`{class_name}` in a {} period requires capability op `{op}`",
                        state.name()
                    ),
                    cell,
                    format!(
                        "obtain `{op}` from the book's steward, or post an Original in an Open period"
                    ),
                )));
            }
            if req.approvals.len() < usize::from(*approvals) {
                txn.abort();
                return Ok(Err(Refusal::new(
                    code::APPROVALS,
                    exit::SAFETY,
                    format!(
                        "`{class_name}` in a {} period requires {approvals} approval(s); {} supplied",
                        state.name(),
                        req.approvals.len()
                    ),
                    cell,
                    "collect the approvals over proposal_digest and resubmit",
                )));
            }
        }
        Some(Decision::Refuse) | None => {
            txn.abort();
            let fix = if state == fa_time::PeriodState::Future {
                format!(
                    "open period `{}` first: fa period open {}",
                    period.code, period.code
                )
            } else {
                format!(
                    "post in an Open period, or use an admissible class for a {} period (Reversal/Replacement/Adjusting with post_closed, Restatement inside a case)",
                    state.name()
                )
            };
            return Ok(Err(Refusal::new(
                code::PERIOD_LAW,
                exit::SAFETY,
                format!(
                    "`{class_name}` is not admissible in period `{}` ({})",
                    period.code,
                    state.name()
                ),
                cell,
                fix,
            )));
        }
    }

    // 6. Accounts: exist, leaf-only, unit policy (plan §4.3).
    let mut accounts: Vec<AccountRow> = Vec::with_capacity(proposal.legs.len());
    for (i, leg) in proposal.legs.iter().enumerate() {
        let Some(row) = txn.vertex(db, leg.account_ref)? else {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::UNKNOWN_ACCOUNT,
                exit::REFUSAL,
                format!("leg {i} names an account this book does not have"),
                "plan §4.3",
                "fa chart list --json to find the account, or fa chart import to add it",
            )));
        };
        let account = AccountRow::decode(&row)?;
        if !account.is_leaf {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::NOT_A_LEAF,
                exit::REFUSAL,
                format!("leg {i} posts to `{}`, a summary account", account.code),
                "plan §4.3 (only leaves accept legs)",
                format!("post to a leaf under `{}`", account.code),
            )));
        }
        let unit_ok = match account.unit_policy {
            UnitPolicy::Single(u) => u == leg.amount.unit,
            UnitPolicy::AnyCurrency => book
                .units
                .get(leg.amount.unit)
                .is_some_and(|u| matches!(u.kind, fa_money::UnitKind::Currency { .. })),
            UnitPolicy::AnyUnit => true,
        };
        if !unit_ok {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::UNIT_POLICY,
                exit::REFUSAL,
                format!(
                    "leg {i}: account `{}` does not accept unit {}",
                    account.code,
                    book.units
                        .get(leg.amount.unit)
                        .map_or_else(|| leg.amount.unit.0.to_string(), |u| u.code.clone())
                ),
                "plan §4.3 unit_policy",
                format!(
                    "post in the account's unit ({:?}) or choose an account whose policy admits it",
                    account.unit_policy
                ),
            )));
        }
        accounts.push(account);
    }

    // 7. Seal and stage: Entry + Legs + edges, one commit.
    let entry: Entry = req
        .proposal
        .clone()
        .seal(req.approvals.clone(), req.plan_certificate)?;
    let mut has_leg = WriteBatch::new(relation::HAS_LEG);
    let mut posts_to = WriteBatch::new(relation::POSTS_TO);
    let mut in_period = WriteBatch::new(relation::IN_PERIOD);
    has_leg.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    for (i, leg) in entry.proposal.legs.iter().enumerate() {
        let ordinal =
            u16::try_from(i).map_err(|_| KernelError::Corrupt("more than u16 legs".into()))?;
        let lvid = leg_vid(evid, ordinal);
        has_leg.create_vertex(
            lvid,
            vec![label::LEG],
            leg_mirrors(leg, ordinal, entry.proposal.effective_date, &book.units)?,
        );
        has_leg.add_edge(
            edge_id(relation::HAS_LEG, evid, lvid),
            evid,
            lvid,
            vec![(property::ORDINAL, CanonicalScalar::Int(i64::from(ordinal)))],
        );
        posts_to.add_edge(
            edge_id(relation::POSTS_TO, lvid, accounts[i].vid),
            lvid,
            accounts[i].vid,
            vec![],
        );
    }
    in_period.add_edge(edge_id(relation::IN_PERIOD, evid, pvid), evid, pvid, vec![]);
    txn.write_ordered(db, vec![has_leg, posts_to, in_period])?;

    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(Posted::Committed {
            entry_ref: entry.entry_ref(evid),
            recorded_at: seq,
            period: period.code,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("a concurrent commit invalidated a witness this post read: {detail}"),
                "FG-LAW-FCW-01 (first committer wins)",
                "re-plan and retry; if a close won, the period law refusal will say so",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => {
            // Lost the identity race to an identical intent: the recorded outcome.
            match db.vertex(evid)? {
                Some(row) => Ok(Ok(recorded(&row)?)),
                None => Err(KernelError::Corrupt(
                    "identity spent but no live row".into(),
                )),
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// Read a committed entry back by its derived identity.
pub fn read_entry<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    vid: VId,
) -> Result<Option<(Entry, CommitSeq)>, KernelError> {
    let Some(row) = db.vertex(vid)? else {
        return Ok(None);
    };
    let payload = match prop(&row, property::FA_PAYLOAD) {
        Some(CanonicalScalar::Bytes(b)) => b.as_slice().to_vec(),
        other => {
            return Err(KernelError::Corrupt(format!(
                "entry _fa_payload: {other:?}"
            )));
        }
    };
    Ok(Some((Entry::decode(&payload)?, row.created_at)))
}
