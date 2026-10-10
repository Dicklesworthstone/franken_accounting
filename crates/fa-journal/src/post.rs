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
//! never a substitute): this slice admits `Original`, `Adjusting`,
//! `Reversal` — with the exact side-swap law against a witnessed target and
//! an identity derived from the target, so one reversal per target — and the
//! two-phase pair of plan §5.4: `Pending` (reserves; never posts) and
//! `Resolution` (`Posts { source_ordinals }` draws a balanced sub-vector leg
//! by leg from the witnessed pending entry; `Voids` releases everything),
//! with the identity `H("fa:vid:resolution:v1" ‖ pending_vid)` so a pending
//! entry has exactly one resolution. Timed pendings and `Expires` need the
//! TimeEvidence ticks and the sweep and are refused until that slice.
//! Application (plan §5.7): a leg's `settles` apply it to witnessed open
//! target legs (same account and unit, opposite side) within their open
//! amount, creating SETTLES edges and moving the target leg's `applied`
//! mirror by compare-and-set; reversing an applying entry emits the exact
//! derived UNSETTLES effects, and an entry with live applications against
//! it is not reversed. Reserved availability (plan §5.4, §5.5 interim
//! R-ESC): every limited account the entry moves is judged on its
//! `LimitCell`, read as a point witness and moved by compare-and-set on its
//! generation — pending outflows reserve, pending inflows never finance, a
//! resolution releases its hold's full original legs. Every other registered
//! class is refused with the bead that lands it; no class passes through a
//! generic two-leg check.

use std::collections::btree_map::Entry as MapEntry;
use std::collections::{BTreeMap, BTreeSet};

use fa_model::Id128;
use fa_model::SealKey;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ApprovalRef, Disposition, Entry, EntryClass, EntryPayload, EntryRef, Pending, SupersessionKind,
    entry_mirrors, entry_vid, leg_mirrors, period_vid,
};
use fa_money::Side;
use fa_registry::{Admissibility, Decision, EntryClasses};
use fa_time::resolve_period;
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::genesis::{BookContext, UnitPolicy};
use crate::limit::{self, LimitCell, Movement, limit_cell_vid};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{
    AccountRow, applied_witness, edge_id, leg_vid, mantissa_scalar, prop, resolution_vid,
    reversal_vid, state_from_scalar,
};

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

/// How an entry's identity was derived (plan §4.9, §5.4): from the
/// principal's idempotency key, or from the target it reverses or resolves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Identity {
    Key,
    Reversal,
    Resolution,
}

/// The existing row at this identity (plan §4.9, FA-INV-09), decided in
/// this order: (1) exact prepared bytes — the stored `proposal_digest` equals
/// the new one — is the recorded outcome without opening anything, so a
/// byte-identical replay works even after erasure; (2) a target-derived
/// identity (reversal, resolution) claimed by a different principal is a
/// conflict, never a comparison (such an identity is not principal-scoped, so
/// comparing would let one principal probe another's sealed content); (3)
/// otherwise a private plaintext transcript under the book key decides equal
/// (recorded) or different (conflict); (4) a field that cannot be opened is
/// "cannot verify", never a claimed equivalence.
fn recorded_or_conflict(
    row: &VertexRow,
    proposal: &EntryPayload,
    key: &SealKey,
    identity: Identity,
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
    let conflict = match identity {
        Identity::Reversal => Refusal::new(
            code::ALREADY_REVERSED,
            exit::CONFLICT,
            format!("the target is already reversed by entry {:032x}", row.vid.0),
            "plan §4.9 (one reversal per target, by identity)",
            "cite the existing reversal instead of posting another",
        ),
        Identity::Resolution => Refusal::new(
            code::ALREADY_RESOLVED,
            exit::CONFLICT,
            format!(
                "the pending entry is already resolved by entry {:032x}",
                row.vid.0
            ),
            "plan §5.4 (one resolution per pending entry, by identity)",
            "read the existing resolution with `fa entry show`; a pending entry is resolved exactly once",
        ),
        Identity::Key => Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            format!(
                "idempotency key reused with different content; the recorded entry is {:032x}",
                row.vid.0
            ),
            "plan §4.9 (identity is derived from the key; content is bound by proposal_digest)",
            "resubmit the identical intent to get the recorded outcome, or use a new idempotency key for new content",
        ),
    };
    if identity != Identity::Key && stored.proposal.principal_ref != proposal.principal_ref {
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
        "Resolution(Expires)" | "timed Pending" => {
            "the TimeEvidence tick and expiry-sweep slice (plan §5.4, §7.1a)"
        }
        "settles on a two-phase entry" | "re-application by reversing a reversal" => {
            "the full application-netting law (plan §5.7, §8.2; fa-06a)"
        }
        "leg.base_amount" => "the FX law slice (fa-p7r)",
        "leg.dimension_set" => "the dimension registry slice (plan §4.3)",
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
            "use Original, Adjusting, Reversal, Pending, or Resolution(Posts|Voids) for now; `{class_name}` lands with {lands_with}"
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
    // 1'. The coordinate (plan §2.2): this book, trunk. Decided from the
    //     payload alone, before any storage observation; branches arrive with
    //     the branch API (Appendix H), not by admitting a foreign branch_id.
    if proposal.book_id != book.book_id {
        return Ok(Err(Refusal::new(
            code::COORDINATE,
            exit::USAGE,
            format!(
                "the intent names book {} but this book is {}",
                proposal.book_id.to_hex(),
                book.book_id.to_hex()
            ),
            "plan §2.2 (an entry belongs to exactly one book)",
            "set book_id to this book's id (fa book info --json) or open the book the intent names",
        )));
    }
    if proposal.branch_id != Id128::TRUNK {
        return Ok(Err(Refusal::new(
            code::COORDINATE,
            exit::USAGE,
            format!(
                "the intent names branch {}, but only trunk is writable in this slice",
                proposal.branch_id.to_hex()
            ),
            "plan Appendix H (branches: interim posture = intent-log drafts)",
            "set branch_id to trunk; drafts and scenarios land with the branch slice",
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
        EntryClass::ORIGINAL
            | EntryClass::ADJUSTING
            | EntryClass::REVERSAL
            | EntryClass::PENDING
            | EntryClass::RESOLUTION
    ) {
        return Ok(Err(not_implemented(class_name)));
    }
    // 1c. Two-phase shape (plan §5.4). `validate` already fixed the arity;
    //     here the slice declares what it does not yet enforce: timed
    //     pendings anchor on TimeEvidence ticks, and `Expires` is the sweep's.
    if proposal.class == EntryClass::PENDING
        && matches!(
            proposal.pending,
            Some(Pending {
                timeout_ns: Some(_),
                ..
            })
        )
    {
        return Ok(Err(not_implemented("timed Pending")));
    }
    let resolution: Option<(EntryRef, Disposition)> = match (&proposal.pending, class_name) {
        (
            Some(Pending {
                resolution_of: Some(target),
                disposition: Some(disposition),
                ..
            }),
            "Resolution",
        ) => Some((*target, disposition.clone())),
        (_, "Resolution") => {
            return Err(KernelError::Corrupt(
                "a validated Resolution without target or disposition".into(),
            ));
        }
        _ => None,
    };
    if matches!(resolution, Some((_, Disposition::Expires { .. }))) {
        return Ok(Err(not_implemented("Resolution(Expires)")));
    }
    // 1d. Rich leg fields this slice does not enforce are refused, never
    //     admitted unchecked: a leg that settles, converts, or carries
    //     dimensions waits for the law that reads it.
    for leg in &proposal.legs {
        if leg.base_amount.is_some() {
            return Ok(Err(not_implemented("leg.base_amount")));
        }
        if !leg.dimension_set.is_empty() {
            return Ok(Err(not_implemented("leg.dimension_set")));
        }
    }
    // 1e. Application structure (plan §5.7), decided from the payload alone:
    //     only a posting entry applies (a Reversal's undo is derived; a hold
    //     reserves), every settlement is positive in the leg's unit, a leg
    //     names each target leg once, and the applications fit the leg.
    for (i, leg) in proposal.legs.iter().enumerate() {
        if leg.settles.is_empty() {
            continue;
        }
        match proposal.class {
            EntryClass::ORIGINAL | EntryClass::ADJUSTING => {}
            EntryClass::REVERSAL => {
                return Ok(Err(Refusal::new(
                    code::SETTLE_SHAPE,
                    exit::REFUSAL,
                    format!("leg {i}: a Reversal carries no settles"),
                    "plan §5.7 (application undo is derived from the reversed target, never re-entered)",
                    "remove `settles`; reversing an applying entry undoes its applications",
                )));
            }
            _ => return Ok(Err(not_implemented("settles on a two-phase entry"))),
        }
        let mut sum: i128 = 0;
        let mut named: BTreeSet<(VId, u16)> = BTreeSet::new();
        for (j, s) in leg.settles.iter().enumerate() {
            if s.amount.mantissa <= 0 || s.amount.unit != leg.amount.unit {
                return Ok(Err(Refusal::new(
                    code::SETTLE_SHAPE,
                    exit::REFUSAL,
                    format!(
                        "leg {i} settles[{j}]: a settlement is a positive amount in the leg's unit"
                    ),
                    "plan §5.7",
                    "state the applied amount in the leg's unit; a different unit is an FX conversion under a law",
                )));
            }
            if !named.insert((s.target.vid, s.ordinal)) {
                return Ok(Err(Refusal::new(
                    code::SETTLE_SHAPE,
                    exit::REFUSAL,
                    format!("leg {i} settles[{j}]: the same target leg is named twice"),
                    "plan §5.7",
                    "merge the two settlements into one amount",
                )));
            }
            sum = match sum.checked_add(s.amount.mantissa) {
                Some(v) => v,
                None => {
                    return Ok(Err(Refusal::new(
                        code::SETTLE_SHAPE,
                        exit::REFUSAL,
                        format!("leg {i}: the settlements overflow"),
                        "plan §6.1 (checked arithmetic)",
                        "apply amounts that sum within the leg",
                    )));
                }
            };
        }
        if sum > leg.amount.mantissa {
            return Ok(Err(Refusal::new(
                code::SETTLE_SHAPE,
                exit::REFUSAL,
                format!(
                    "leg {i} applies {sum} but carries only {}",
                    leg.amount.mantissa
                ),
                "plan §5.7 (a leg applies at most itself)",
                "reduce the settlements to the leg's amount",
            )));
        }
    }
    let is_release = matches!(resolution, Some((_, Disposition::Voids)));
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

    // 4. Identity (plan §4.9, FA-INV-09): derived from the key, from the
    //    reversed target, or from the resolved pending entry; an existing row
    //    is the recorded outcome or a conflict.
    let (evid, identity) = match (reversal_target, &resolution) {
        (Some(t), _) => (reversal_vid(t.vid), Identity::Reversal),
        (None, Some((t, _))) => (resolution_vid(t.vid), Identity::Resolution),
        (None, None) => (
            entry_vid(
                book.book_id,
                &proposal.principal_ref.0.to_le_bytes(),
                &proposal.idempotency_key,
            ),
            Identity::Key,
        ),
    };
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return recorded_or_conflict(&row, proposal, &book.seal_key, identity);
    }

    // 5. Period law (Appendix C) against the witnessed state.
    let pvid = period_vid(&book.calendar.id, &period.code);
    let state_scalar = txn.vertex_property(db, pvid, property::STATE)?;
    let state = state_from_scalar(state_scalar.as_ref())
        .ok_or_else(|| KernelError::Corrupt(format!("period `{}` state mirror", period.code)))?;
    let classes = EntryClasses::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let matrix =
        Admissibility::embedded(&classes).map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let family = match &resolution {
        Some((_, Disposition::Posts { .. })) => "(Posts)",
        Some((_, Disposition::Voids)) => "(Voids)",
        Some((_, Disposition::Expires { .. })) | None => "",
    };
    let cell = format!(
        "admissibility.toml ({class_name}{family}, {})",
        state.name()
    );
    match matrix.decide_disposition(class_name, state, is_release) {
        Some(Decision::Admit) => {}
        Some(Decision::With { op, approvals }) => {
            let op = op.as_str();
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
            if req.approvals.len() < usize::from(approvals) {
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
            } else if matches!(resolution, Some((_, Disposition::Posts { .. }))) {
                format!(
                    "a {} period admits only a release: resolve with Voids, or post the sub-vector dated in an Open period",
                    state.name()
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

    // 7a. Application law (plan §5.7): each settlement names a witnessed,
    //     posted, unreversed target leg on the same account and unit with
    //     the opposite side, and the amount fits the target's open amount
    //     (original − applied). The `applied` mirror is read as a point
    //     witness, so a concurrent application is a first-committer-wins
    //     conflict, never an over-application.
    let mut applications: Vec<(u16, VId, i128)> = Vec::new();
    let mut undo: Vec<(u16, VId, i128)> = Vec::new();
    let mut applied_delta: BTreeMap<VId, (i128, i128)> = BTreeMap::new();
    for (i, leg) in proposal.legs.iter().enumerate() {
        let ordinal =
            u16::try_from(i).map_err(|_| KernelError::Corrupt("more than u16 legs".into()))?;
        for s in &leg.settles {
            let Some(row) = txn.vertex(db, s.target.vid)? else {
                txn.abort();
                return Ok(Err(Refusal::new(
                    code::SETTLE_TARGET,
                    exit::REFUSAL,
                    format!("leg {i}: no entry {:032x} in this book", s.target.vid.0),
                    "plan §5.7",
                    "fa open-items --account <code> lists the open items to apply to",
                )));
            };
            if !row.labels.contains(&label::ENTRY) {
                txn.abort();
                return Ok(Err(Refusal::new(
                    code::SETTLE_TARGET,
                    exit::REFUSAL,
                    format!("leg {i}: {:032x} is not an entry", s.target.vid.0),
                    "plan §5.7 (a settlement cites an entry's leg)",
                    "cite the entry vid from `fa open-items`",
                )));
            }
            let target = match prop(&row, property::FA_PAYLOAD) {
                Some(CanonicalScalar::Bytes(b)) => Entry::decode(b.as_slice())?,
                other => {
                    return Err(KernelError::Corrupt(format!(
                        "entry _fa_payload: {other:?}"
                    )));
                }
            };
            if target.entry_digest != s.target.entry_digest {
                txn.abort();
                return Ok(Err(Refusal::new(
                    code::SETTLE_TARGET,
                    exit::REFUSAL,
                    format!(
                        "leg {i}: the handle's entry_digest does not match entry {:032x}",
                        s.target.vid.0
                    ),
                    "plan §4.9 (EntryRef is self-verifying)",
                    "re-read the entry and cite its current entry_digest",
                )));
            }
            let open_item_class = matches!(
                target.proposal.class,
                EntryClass::ORIGINAL | EntryClass::ADJUSTING
            ) || (target.proposal.class == EntryClass::RESOLUTION
                && !target.proposal.legs.is_empty());
            if !open_item_class {
                txn.abort();
                return Ok(Err(Refusal::new(
                    code::SETTLE_TARGET,
                    exit::REFUSAL,
                    format!(
                        "leg {i}: entry {:032x} is a {}, which carries no open item",
                        s.target.vid.0,
                        target.proposal.class.name().unwrap_or("?")
                    ),
                    "plan §5.7 (open items are posted legs; a hold, a release, or a reversal leg is not one)",
                    "apply to the posted entry; fa open-items --account <code>",
                )));
            }
            // Liveness is a lineage predicate (plan §8.2): a reversed entry
            // nets to zero, and a reversed reversal revives it; a chain of any
            // length is legal, so the walk is bounded only by a cycle check
            // (impossible for honest identities, corruption otherwise). Each
            // hop is a witnessed point read, so a concurrent reversal conflicts.
            let mut reversed = false;
            let mut current = s.target.vid;
            let mut seen: BTreeSet<VId> = BTreeSet::new();
            while txn.vertex(db, reversal_vid(current))?.is_some() {
                if !seen.insert(current) {
                    return Err(KernelError::Corrupt(format!(
                        "reversal lineage of {:032x} cycles",
                        s.target.vid.0
                    )));
                }
                reversed = !reversed;
                current = reversal_vid(current);
            }
            if reversed {
                txn.abort();
                return Ok(Err(Refusal::new(
                    code::SETTLE_TARGET,
                    exit::REFUSAL,
                    format!(
                        "leg {i}: entry {:032x} is reversed; nothing of it is open",
                        s.target.vid.0
                    ),
                    "plan §8.2 (a reversed entry nets to zero)",
                    "apply to the replacement entry, or post a new open item",
                )));
            }
            let Some(target_leg) = target.proposal.legs.get(usize::from(s.ordinal)) else {
                txn.abort();
                return Ok(Err(Refusal::new(
                    code::SETTLE_SHAPE,
                    exit::REFUSAL,
                    format!(
                        "leg {i}: entry {:032x} has {} legs, no ordinal {}",
                        s.target.vid.0,
                        target.proposal.legs.len(),
                        s.ordinal
                    ),
                    "plan §5.7",
                    "fa entry show <vid> and name the 0-based leg being settled",
                )));
            };
            if target_leg.account_ref != leg.account_ref
                || target_leg.amount.unit != leg.amount.unit
                || target_leg.side == leg.side
            {
                txn.abort();
                return Ok(Err(Refusal::new(
                    code::SETTLE_SHAPE,
                    exit::REFUSAL,
                    format!(
                        "leg {i} does not settle entry {:032x} leg {}: an application is the opposite side on the same account and unit",
                        s.target.vid.0, s.ordinal
                    ),
                    "plan §5.7 (a receipt settles a debit-side open item in the same unit)",
                    "apply the leg on the open item's account with the opposite side",
                )));
            }
            let target_leg_vid = leg_vid(s.target.vid, s.ordinal);
            if let MapEntry::Vacant(slot) = applied_delta.entry(target_leg_vid) {
                let leg_row = txn.vertex(db, target_leg_vid)?.ok_or_else(|| {
                    KernelError::Corrupt("settlement target leg row missing".into())
                })?;
                slot.insert((applied_witness(&leg_row)?, 0));
            }
            let (witnessed, delta) = applied_delta
                .get_mut(&target_leg_vid)
                .ok_or_else(|| KernelError::Corrupt("applied witness".into()))?;
            // What the target leg itself applied to others consumed it too.
            let mut consumed: i128 = 0;
            for t in &target_leg.settles {
                consumed = consumed
                    .checked_add(t.amount.mantissa)
                    .ok_or_else(|| KernelError::Corrupt("applied_out overflow".into()))?;
            }
            let capacity = target_leg
                .amount
                .mantissa
                .checked_sub(consumed)
                .ok_or_else(|| KernelError::Corrupt("applied_out exceeds the leg".into()))?;
            if *witnessed > capacity {
                return Err(KernelError::Corrupt(format!(
                    "leg {:032x} applied mirror {} exceeds its capacity {capacity}; `fa verify open-items` names it",
                    target_leg_vid.0, *witnessed
                )));
            }
            let open = capacity
                .checked_sub(*witnessed)
                .and_then(|o| o.checked_sub(*delta))
                .ok_or_else(|| KernelError::Corrupt("open amount underflow".into()))?;
            if s.amount.mantissa > open {
                txn.abort();
                return Ok(Err(Refusal::new(
                    code::OVER_APPLICATION,
                    exit::REFUSAL,
                    format!(
                        "leg {i} applies {} to entry {:032x} leg {}, but only {open} is open",
                        s.amount.mantissa, s.target.vid.0, s.ordinal
                    ),
                    "plan §5.7 (over-application is refused with the open amount)",
                    format!(
                        "apply at most {open}; the remainder is a new open item or an unapplied receipt"
                    ),
                )));
            }
            *delta = delta
                .checked_add(s.amount.mantissa)
                .ok_or_else(|| KernelError::Corrupt("applied overflow".into()))?;
            applications.push((ordinal, target_leg_vid, s.amount.mantissa));
        }
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
        if !row.labels.contains(&label::ENTRY) {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::REVERSAL_TARGET,
                exit::REFUSAL,
                format!("{:032x} is not an entry", target.vid.0),
                "plan §4.4 (a reversal cites an entry)",
                "cite the entry's vid from the posted event or `fa entry show`",
            )));
        }
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
        // Only a posted entry is reversible (plan §8.2): a hold posted
        // nothing (release it), a release posted nothing (it is final), and
        // the classes this slice does not post are not reversed through it.
        let reversible = match original.proposal.class {
            EntryClass::ORIGINAL | EntryClass::ADJUSTING | EntryClass::REVERSAL => true,
            EntryClass::RESOLUTION => matches!(
                original.proposal.pending,
                Some(Pending {
                    disposition: Some(Disposition::Posts { .. }),
                    ..
                })
            ),
            _ => false,
        };
        if !reversible {
            txn.abort();
            let (why, fix) = match original.proposal.class {
                EntryClass::PENDING => (
                    "a Pending reserves and posts nothing, so there is nothing to reverse",
                    "release the hold with a Resolution(Voids), or resolve it with Posts and reverse that",
                ),
                EntryClass::RESOLUTION => (
                    "a release posted nothing and is final",
                    "reserve again with a new Pending if the hold is still wanted",
                ),
                _ => (
                    "this class is not reversed through the exact side-swap",
                    "use the correction class registered for it",
                ),
            };
            return Ok(Err(Refusal::new(
                code::REVERSAL_TARGET,
                exit::REFUSAL,
                format!(
                    "entry {:032x} is a {}: {why}",
                    target.vid.0,
                    original.proposal.class.name().unwrap_or("?")
                ),
                "plan §8.2 (a reversal negates posted legs)",
                fix,
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
                        && o.dimension_set == r.dimension_set
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
        // 7c. Application effects (plan §5.7, §8.2): a target with live
        //     applications against its legs is not reversed — the applying
        //     entries come first; the target's own applications are undone
        //     exactly as derived UNSETTLES effects, never re-entered. Reversing
        //     a reversal that undid applications would re-apply them; that
        //     waits for the full netting law.
        for i in 0..original.proposal.legs.len() {
            let ordinal =
                u16::try_from(i).map_err(|_| KernelError::Corrupt("more than u16 legs".into()))?;
            let lvid = leg_vid(target.vid, ordinal);
            let row = txn
                .vertex(db, lvid)?
                .ok_or_else(|| KernelError::Corrupt("reversal target leg row missing".into()))?;
            let live = applied_witness(&row)?;
            if live != 0 {
                txn.abort();
                return Ok(Err(Refusal::new(
                    code::LIVE_APPLICATIONS,
                    exit::REFUSAL,
                    format!(
                        "leg {i} of entry {:032x} has {live} applied against it",
                        target.vid.0
                    ),
                    "plan §5.7 (reversing an open item with live applications would strand them)",
                    "reverse the applying entries first (fa open-items --account <code> lists them), then reverse this entry",
                )));
            }
        }
        if original.proposal.class == EntryClass::REVERSAL
            && let [first] = original.proposal.supersession.as_slice()
            && let Some(grand) = txn.vertex(db, first.target.vid)?
        {
            let grand = match prop(&grand, property::FA_PAYLOAD) {
                Some(CanonicalScalar::Bytes(b)) => Entry::decode(b.as_slice())?,
                other => {
                    return Err(KernelError::Corrupt(format!(
                        "entry _fa_payload: {other:?}"
                    )));
                }
            };
            if grand.proposal.legs.iter().any(|l| !l.settles.is_empty()) {
                txn.abort();
                return Ok(Err(not_implemented(
                    "re-application by reversing a reversal",
                )));
            }
        }
        for (i, oleg) in original.proposal.legs.iter().enumerate() {
            let ordinal =
                u16::try_from(i).map_err(|_| KernelError::Corrupt("more than u16 legs".into()))?;
            for s in &oleg.settles {
                let target_leg_vid = leg_vid(s.target.vid, s.ordinal);
                if let MapEntry::Vacant(slot) = applied_delta.entry(target_leg_vid) {
                    let leg_row = txn.vertex(db, target_leg_vid)?.ok_or_else(|| {
                        KernelError::Corrupt("undo target leg row missing".into())
                    })?;
                    slot.insert((applied_witness(&leg_row)?, 0));
                }
                let (_, delta) = applied_delta
                    .get_mut(&target_leg_vid)
                    .ok_or_else(|| KernelError::Corrupt("applied witness".into()))?;
                *delta = delta
                    .checked_sub(s.amount.mantissa)
                    .ok_or_else(|| KernelError::Corrupt("applied underflow".into()))?;
                undo.push((ordinal, target_leg_vid, s.amount.mantissa));
            }
        }
    }

    // 7b. Resolution law (plan §5.4): the witnessed target is a Pending whose
    //     digest matches the handle; a Posts sub-vector is drawn leg by leg
    //     from it (same account, unit, side, dimensions; 0 < posted ≤
    //     reserved). Balance per unit was checked in step 2. The hold's legs
    //     are kept: a resolution releases all of them (step 7d).
    let mut released: Vec<fa_model::LegPayload> = Vec::new();
    if let Some((target, disposition)) = &resolution {
        let Some(row) = txn.vertex(db, target.vid)? else {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::RESOLUTION_TARGET,
                exit::REFUSAL,
                format!("no entry {:032x} in this book", target.vid.0),
                "plan §5.4",
                "fa entry show <vid> to find the pending entry to resolve",
            )));
        };
        if !row.labels.contains(&label::ENTRY) {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::RESOLUTION_TARGET,
                exit::REFUSAL,
                format!("{:032x} is not an entry", target.vid.0),
                "plan §5.4 (a resolution cites a pending entry)",
                "cite the hold's vid from the posted event or `fa entry show`",
            )));
        }
        let pending_entry = match prop(&row, property::FA_PAYLOAD) {
            Some(CanonicalScalar::Bytes(b)) => Entry::decode(b.as_slice())?,
            other => {
                return Err(KernelError::Corrupt(format!(
                    "entry _fa_payload: {other:?}"
                )));
            }
        };
        if pending_entry.entry_digest != target.entry_digest {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::RESOLUTION_TARGET,
                exit::REFUSAL,
                format!(
                    "the handle's entry_digest does not match entry {:032x}",
                    target.vid.0
                ),
                "plan §4.9 (EntryRef is self-verifying)",
                "re-read the entry and cite its current entry_digest",
            )));
        }
        if pending_entry.proposal.class != EntryClass::PENDING {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::RESOLUTION_TARGET,
                exit::REFUSAL,
                format!(
                    "entry {:032x} is a {}, not a Pending",
                    target.vid.0,
                    pending_entry.proposal.class.name().unwrap_or("?")
                ),
                "plan §5.4 (only a pending entry is resolved)",
                "name the pending entry; a posted entry is corrected with a Reversal",
            )));
        }
        released.clone_from(&pending_entry.proposal.legs);
        if let Disposition::Posts { source_ordinals } = disposition {
            for (i, (leg, ordinal)) in proposal.legs.iter().zip(source_ordinals).enumerate() {
                let Some(src) = pending_entry.proposal.legs.get(usize::from(*ordinal)) else {
                    txn.abort();
                    return Ok(Err(Refusal::new(
                        code::RESOLUTION_SHAPE,
                        exit::REFUSAL,
                        format!(
                            "leg {i} names pending leg {ordinal}, but the pending entry has {} legs",
                            pending_entry.proposal.legs.len()
                        ),
                        "plan §5.4 (source_ordinals index the pending entry's legs)",
                        "fa entry show <pending vid> and map each posted leg to one of its legs",
                    )));
                };
                if src.account_ref != leg.account_ref
                    || src.amount.unit != leg.amount.unit
                    || src.side != leg.side
                    || src.dimension_set != leg.dimension_set
                {
                    txn.abort();
                    return Ok(Err(Refusal::new(
                        code::RESOLUTION_SHAPE,
                        exit::REFUSAL,
                        format!(
                            "leg {i} is not drawn from pending leg {ordinal}: a posted leg keeps its source's account, unit, side, and dimensions"
                        ),
                        "plan §5.4 (per-leg balanced sub-vector)",
                        "post the same account, unit, and side as the pending leg; a different posting is a Voids plus a new Original",
                    )));
                }
                if leg.amount.mantissa <= 0 || leg.amount.mantissa > src.amount.mantissa {
                    txn.abort();
                    return Ok(Err(Refusal::new(
                        code::RESOLUTION_SHAPE,
                        exit::REFUSAL,
                        format!(
                            "leg {i} posts {} but pending leg {ordinal} reserved {} (0 < posted ≤ reserved)",
                            leg.amount.mantissa, src.amount.mantissa
                        ),
                        "plan §5.4 (each posted mantissa ≤ its pending mantissa)",
                        "post at most the reserved amount; the remainder is released automatically",
                    )));
                }
            }
        }
    }

    // 7d. Reserved availability (plan §5.4, §5.5 interim R-ESC): each limited
    //     account the entry moves, in order of first appearance (its own
    //     legs, then a resolved hold's legs), is judged on its LimitCell —
    //     read here as a point witness, so a post that moves the cell first
    //     makes this one a first-committer-wins conflict. Pending legs
    //     reserve, a resolution releases the hold's full original legs, and
    //     every other leg posts.
    let mut account_rows: BTreeMap<VId, AccountRow> =
        accounts.iter().map(|a| (a.vid, a.clone())).collect();
    let mut moves: Vec<(VId, Movement)> = Vec::new();
    let effects = proposal
        .legs
        .iter()
        .map(|l| (l, false))
        .chain(released.iter().map(|l| (l, true)));
    for (leg, is_release) in effects {
        let account = match account_rows.entry(leg.account_ref) {
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
        if account.limit.is_none() {
            continue;
        }
        let at = match moves.iter().position(|(a, _)| *a == leg.account_ref) {
            Some(at) => at,
            None => {
                moves.push((leg.account_ref, Movement::default()));
                moves.len() - 1
            }
        };
        let m = &mut moves[at].1;
        if is_release {
            m.release(leg.side, leg.amount.mantissa)?;
        } else if proposal.class == EntryClass::PENDING {
            m.reserve(leg.side, leg.amount.mantissa)?;
        } else {
            m.post(leg.side, leg.amount.mantissa)?;
        }
    }
    let mut cell_moves: Vec<(VId, LimitCell, LimitCell)> = Vec::with_capacity(moves.len());
    for (account_vid, m) in &moves {
        let account = account_rows
            .get(account_vid)
            .ok_or_else(|| KernelError::Corrupt("judged account row".into()))?;
        let limit_spec = account
            .limit
            .ok_or_else(|| KernelError::Corrupt("judged account has no limit".into()))?;
        let cvid = limit_cell_vid(*account_vid);
        let row = txn
            .vertex(db, cvid)?
            .filter(|r| r.labels.contains(&label::LIMIT_CELL))
            .ok_or_else(|| {
                KernelError::Corrupt(format!(
                    "limited account `{}` has no limit cell; `fa verify availability` names it; nothing is admitted on it",
                    account.code
                ))
            })?;
        let before = LimitCell::decode(&row)?;
        let normal = if account.normal_balance == 0 {
            Side::Debit
        } else {
            Side::Credit
        };
        match limit::apply(&before, normal, &limit_spec, m)? {
            Ok(next) => cell_moves.push((cvid, before, next)),
            Err(breach) => {
                txn.abort();
                // install_chart admits a limit only on a single-unit account.
                let UnitPolicy::Single(unit) = account.unit_policy else {
                    return Err(KernelError::Corrupt(format!(
                        "limited account `{}` has no single unit",
                        account.code
                    )));
                };
                return Ok(Err(limit::refusal(
                    &breach,
                    &account.code,
                    unit,
                    &book.units,
                )));
            }
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
        let mut mirrors = leg_mirrors(leg, ordinal, entry.proposal.effective_date, &book.units)?;
        mirrors.push((property::APPLIED, mantissa_scalar("applied", 0)?));
        has_leg.create_vertex(lvid, vec![label::LEG], mirrors);
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
    for (cvid, before, next) in &cell_moves {
        before.stage(next, *cvid, &mut has_leg)?;
    }
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
    if let Some((target, disposition)) = &resolution {
        let tag = match disposition {
            Disposition::Posts { .. } => 0,
            Disposition::Voids => 1,
            Disposition::Expires { .. } => 2,
        };
        let mut resolves = WriteBatch::new(relation::RESOLVES);
        resolves.add_edge(
            edge_id(relation::RESOLVES, evid, target.vid),
            evid,
            target.vid,
            vec![(property::DISPOSITION, CanonicalScalar::Int(tag))],
        );
        batches.push(resolves);
    }
    if !applications.is_empty() || !undo.is_empty() {
        let mut settles = WriteBatch::new(relation::SETTLES);
        for (ordinal, target_leg, amount) in &applications {
            let src = leg_vid(evid, *ordinal);
            settles.add_edge(
                edge_id(relation::SETTLES, src, *target_leg),
                src,
                *target_leg,
                vec![(
                    property::AMOUNT_BYTES,
                    mantissa_scalar("settles.amount", *amount)?,
                )],
            );
        }
        let mut unsettles = WriteBatch::new(relation::UNSETTLES);
        for (ordinal, target_leg, amount) in &undo {
            let src = leg_vid(evid, *ordinal);
            unsettles.add_edge(
                edge_id(relation::UNSETTLES, src, *target_leg),
                src,
                *target_leg,
                vec![(
                    property::AMOUNT_BYTES,
                    mantissa_scalar("unsettles.amount", *amount)?,
                )],
            );
        }
        for (target_leg, (witnessed, delta)) in &applied_delta {
            let next = witnessed
                .checked_add(*delta)
                .filter(|n| *n >= 0)
                .ok_or_else(|| KernelError::Corrupt("applied mirror out of range".into()))?;
            settles.compare_and_set_vertex_property(
                *target_leg,
                property::APPLIED,
                Some(mantissa_scalar("applied", *witnessed)?),
                mantissa_scalar("applied", next)?,
                WriteMismatchPolicy::AbortWrite,
            );
        }
        batches.push(settles);
        batches.push(unsettles);
    }
    batches.retain(|b| !b.is_empty());
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
                Some(row) => recorded_or_conflict(&row, proposal, &book.seal_key, identity),
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
