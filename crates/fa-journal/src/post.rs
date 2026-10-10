//! The post pipeline (plan §5.1, §5.10, §7.3, §8.4): resolve → laws → commit.
//!
//! Order matters and is the point: nothing is staged until every law has
//! passed inside the transaction that read the witnesses it depends on. The
//! period's state is read through the transaction (a point-read witness), so
//! a close that commits first makes this post a first-committer-wins
//! conflict — exit 6, retry with a fresh read — never a post that slipped
//! into a closed period.
//!
//! Supported subset (plan §18.1 rule: a subset of the final abstraction,
//! never a substitute): this slice admits `Original`, `Adjusting`, and
//! `Reversal` — the last with the exact side-swap law against a witnessed
//! target and an identity derived from the target, so one reversal per
//! target. Every other registered class is refused with the bead that lands
//! it; no class passes through a generic two-leg check.

use std::collections::BTreeSet;

use fa_model::SealKey;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ApprovalRef, Entry, EntryClass, EntryPayload, EntryRef, SupersessionKind, entry_mirrors,
    entry_vid, leg_mirrors, period_vid,
};
use fa_money::Side;
use fa_registry::{Admissibility, Decision, EntryClasses};
use fa_time::resolve_period;
use fgdb::{Database, VertexRow, WriteBatch, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::genesis::{BookContext, UnitPolicy};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{AccountRow, edge_id, leg_vid, prop, reversal_vid, state_from_scalar};

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

/// One post. **Trust boundary:** `proposal.principal_ref` and `capability`
/// are the caller's claims. In the embedded posture the calling process is the
/// principal's own agent and that claim is trusted; the daemon/MCP posture must
/// bind both from an authenticated session before calling `post` (Steward,
/// bead fa-llx). The kernel never authenticates a caller itself.
#[derive(Clone, Debug)]
pub struct PostRequest {
    pub proposal: EntryPayload,
    pub approvals: Vec<ApprovalRef>,
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
    /// The same intent was already recorded (same identity, same proposal
    /// digest); this is that outcome. Nothing was written.
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

/// The existing row at this identity (plan §4.9, FA-INV-09), decided in
/// this order: (1) exact prepared bytes — the stored `proposal_digest` equals
/// the new one — is the recorded outcome without opening anything, so a
/// byte-identical replay works even after erasure; (2) a reversal by a
/// different principal is a conflict, never a comparison (the target-derived
/// identity is not principal-scoped, so comparing would let one principal
/// probe another's sealed content); (3) otherwise a private plaintext
/// transcript under the book key decides equal (recorded) or different
/// (conflict); (4) a field that cannot be opened is "cannot verify", never a
/// claimed equivalence.
fn recorded_or_conflict(
    row: &VertexRow,
    proposal: &EntryPayload,
    key: &SealKey,
    is_reversal: bool,
) -> Result<Result<Posted, Refusal>, KernelError> {
    let stored = match prop(row, property::FA_PAYLOAD) {
        Some(CanonicalScalar::Bytes(b)) => Entry::decode(b.as_slice())?,
        other => {
            return Err(KernelError::Corrupt(format!(
                "entry _fa_payload: {other:?}"
            )));
        }
    };
    let entry_ref = EntryRef {
        vid: row.vid,
        entry_digest: stored.entry_digest,
    };
    let recorded = Posted::AlreadyRecorded {
        entry_ref,
        recorded_at: row.created_at,
    };
    if stored.proposal_digest == proposal.proposal_digest()? {
        return Ok(Ok(recorded));
    }
    let conflict = if is_reversal {
        Refusal::new(
            code::ALREADY_REVERSED,
            exit::CONFLICT,
            format!("the target is already reversed by entry {:032x}", row.vid.0),
            "plan §4.9 (one reversal per target, by identity)",
            "cite the existing reversal instead of posting another",
        )
    } else {
        Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            format!(
                "idempotency key reused with different content; the recorded entry is {:032x}",
                row.vid.0
            ),
            "plan §4.9 (identity is derived from the key; content is bound by proposal_digest)",
            "resubmit the identical intent to get the recorded outcome, or use a new idempotency key for new content",
        )
    };
    if is_reversal && stored.proposal.principal_ref != proposal.principal_ref {
        return Ok(Err(conflict));
    }
    match (
        stored.proposal.semantic_digest(key),
        proposal.semantic_digest(key),
    ) {
        (Ok(a), Ok(b)) if a == b => Ok(Ok(recorded)),
        (Ok(_), Ok(_)) => Ok(Err(conflict)),
        (Err(fa_model::EntryError::Sealed(_)), _) | (_, Err(fa_model::EntryError::Sealed(_))) => {
            Ok(Err(Refusal::new(
                code::EQUIVALENCE_UNVERIFIABLE,
                exit::CONFLICT,
                format!(
                    "an entry with this identity exists ({:032x}) but a sealed field cannot be opened, so equivalence cannot be verified",
                    row.vid.0
                ),
                "plan §8.5 (no plaintext equivalence over destroyed secrets)",
                "resubmit the exact prepared bytes to get the recorded outcome, read it with `fa entry show`, or use a new idempotency key for new content",
            )))
        }
        (Err(e), _) | (_, Err(e)) => Err(e.into()),
    }
}

fn not_implemented(class_name: &str) -> Refusal {
    let lands_with = match class_name {
        "Pending" | "Resolution" => "fa-rqe (two-phase reserves)",
        "Replacement" | "Reclassification" => "fa-omi (supersession beyond exact reversal)",
        "Revision" | "Restatement" | "PriorPeriodAdjustment" => {
            "the restatement-case slice (fa-azu children)"
        }
        "Closing" => "the incremental closing slice (plan §7.5)",
        "Allocation" | "Revaluation" | "Elimination" => "Canon rules (plan §10)",
        "Migration" => "MigrationRun (plan §12)",
        _ => "a later slice",
    };
    Refusal::new(
        code::CLASS_NOT_IMPLEMENTED,
        exit::REFUSAL,
        format!("`{class_name}` is registered but this slice does not enforce its semantics"),
        "plan §18.1 (a slice is a subset of the final abstraction, never a substitute)",
        format!(
            "use Original, Adjusting, or Reversal for now; `{class_name}` lands with {lands_with}"
        ),
    )
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
    // 1a. Authorization precedes observation (doctrine 8): the base `post`
    //     op is required before anything is read, including the identity row.
    if !req.capability.ops.contains("post") {
        return Ok(Err(Refusal::new(
            code::CAPABILITY,
            exit::SAFETY,
            "the principal holds no `post` capability",
            "plan §14.2 (capability caveats precede observation)",
            "obtain `post` from the book's steward",
        )));
    }
    // 1b. The supported subset.
    let is_reversal = proposal.class == EntryClass::REVERSAL;
    if !matches!(
        proposal.class,
        EntryClass::ORIGINAL | EntryClass::ADJUSTING | EntryClass::REVERSAL
    ) {
        return Ok(Err(not_implemented(class_name)));
    }
    let reversal_target = if is_reversal {
        match proposal.supersession.as_slice() {
            [s] if s.kind == SupersessionKind::Reverses => Some(s.target),
            _ => {
                return Ok(Err(Refusal::new(
                    code::REVERSAL_TARGET,
                    exit::REFUSAL,
                    "a Reversal names exactly one target with kind Reverses in `supersession`",
                    "plan §4.4 (a reversal is a side swap of one entry)",
                    "set supersession = [{ target: <EntryRef of the original>, kind: Reverses }]",
                )));
            }
        }
    } else {
        if !proposal.supersession.is_empty() {
            return Ok(Err(not_implemented("supersession on a non-Reversal class")));
        }
        None
    };

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

    // 4. Identity (plan §4.9, FA-INV-09): derived from the key, or from the
    //    reversed target; an existing row is the recorded outcome or a conflict.
    let evid = match reversal_target {
        Some(t) => reversal_vid(t.vid),
        None => entry_vid(
            book.book_id,
            &proposal.principal_ref.0.to_le_bytes(),
            &proposal.idempotency_key,
        ),
    };
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return recorded_or_conflict(&row, proposal, &book.seal_key, is_reversal);
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
                    "post in an Open period, or use an admissible class for a {} period (Reversal/Adjusting with post_closed)",
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

    // 7. Reversal law (plan §4.4): the witnessed target exists, its digest
    //    matches the handle, and the legs are its exact side-swap.
    if let Some(target) = reversal_target {
        let Some(row) = txn.vertex(db, target.vid)? else {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::REVERSAL_TARGET,
                exit::REFUSAL,
                format!("no entry {:032x} in this book", target.vid.0),
                "plan §4.4",
                "fa entry show <vid> to find the entry to reverse",
            )));
        };
        let original = match prop(&row, property::FA_PAYLOAD) {
            Some(CanonicalScalar::Bytes(b)) => Entry::decode(b.as_slice())?,
            other => {
                return Err(KernelError::Corrupt(format!(
                    "entry _fa_payload: {other:?}"
                )));
            }
        };
        if original.entry_digest != target.entry_digest {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::REVERSAL_TARGET,
                exit::REFUSAL,
                format!(
                    "the handle's entry_digest does not match entry {:032x}",
                    target.vid.0
                ),
                "plan §4.9 (EntryRef is self-verifying)",
                "re-read the entry and cite its current entry_digest",
            )));
        }
        let swapped = original.proposal.legs.len() == proposal.legs.len()
            && original
                .proposal
                .legs
                .iter()
                .zip(&proposal.legs)
                .all(|(o, r)| {
                    o.account_ref == r.account_ref
                        && o.amount == r.amount
                        && matches!(
                            (o.side, r.side),
                            (Side::Debit, Side::Credit) | (Side::Credit, Side::Debit)
                        )
                });
        if original.proposal.legs.is_empty() || !swapped {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::REVERSAL_SHAPE,
                exit::REFUSAL,
                format!(
                    "the legs are not the exact side-swap of entry {:032x}",
                    target.vid.0
                ),
                "plan §4.4 (a reversal is a side swap with the same mantissa, never a signed storno)",
                "post the same accounts and amounts in the same order with debit and credit exchanged; a different correction is a Replacement",
            )));
        }
    }

    // 8. Seal and stage: Entry + Legs + edges, one commit.
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
    let mut batches = vec![has_leg, posts_to, in_period];
    if let Some(target) = reversal_target {
        let mut supersedes = WriteBatch::new(relation::SUPERSEDES);
        supersedes.add_edge(
            edge_id(relation::SUPERSEDES, evid, target.vid),
            evid,
            target.vid,
            vec![],
        );
        batches.push(supersedes);
    }
    txn.write_ordered(db, batches)?;

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
            // Lost the identity race: the recorded outcome if it is the same
            // intent, a conflict if it is not.
            match db.vertex(evid)? {
                Some(row) => recorded_or_conflict(&row, proposal, &book.seal_key, is_reversal),
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
