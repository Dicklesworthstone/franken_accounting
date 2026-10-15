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
//! entry has exactly one resolution. A timed `Pending` anchors its deadline
//! on the latest TimeEvidence tick, witnessed here; a `Posts` on a hold a
//! committed tick has made due is refused; `Expires` is minted only by the
//! expiry sweep (`crate::sweep`), never posted.
//! Application (plan §5.7): a leg's `settles` apply it to witnessed open
//! target legs (same account and unit, opposite side) within their open
//! amount, creating SETTLES edges and moving the target leg's `applied`
//! mirror by compare-and-set; reversing an applying entry emits the exact
//! derived UNSETTLES effects, and an entry with live applications against
//! it is not reversed. A Resolution(Posts) can settle open items with its
//! actual posted sub-vector while releasing the entire reservation in the
//! same transaction; Pending legs never apply. Reserved availability (plan §5.4, §5.5 interim
//! R-ESC): every limited account the entry moves is judged on its
//! `LimitCell`, read as a point witness and moved by compare-and-set on its
//! generation — pending outflows reserve, pending inflows never finance, a
//! resolution releases its hold's full original legs. `Migration` (plan
//! §8.6): a chunk of an open `MigrationRun`, named by its origin, in the
//! run's Opening period (dated on the run's opening date) or a period its
//! body declares (for `FullDetail`, also the special periods between them),
//! identified by `H("fa:vid:migration-entry:v1" ‖ book ‖ run ‖ key)`, and
//! staged invisible until the run's Finalize (`migration::visible_at`). A
//! chunk carries no `settles`; once its run is Finalized, a counting chunk's
//! legs are open items (ruling 3733). `Allocation` redistributes an explicit
//! native amount under a registered law and a committed driver Workpaper
//! (`crate::allocation`); all targets, including zero shares, are witnessed.
//! Its exact side-swap is reversible. Every other registered
//! class is refused with the bead that lands it; no class passes through a
//! generic two-leg check.

use std::collections::btree_map::Entry as MapEntry;
use std::collections::{BTreeMap, BTreeSet};

use fa_model::Id128;
use fa_model::SealKey;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ApprovalRef, Disposition, Entry, EntryClass, EntryOrigin, EntryPayload, EntryRef, Pending,
    SupersessionKind, entry_mirrors, entry_vid, migration_entry_vid, period_vid,
};
use fa_money::Side;
use fa_registry::evidence_policy::EvidencePolicy;
use fa_registry::{Admissibility, Decision, EntryClasses};
use fa_time::resolve_period;
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::entity;
use crate::evidence::{evidence_edges, resolve_evidence};
use crate::genesis::{BookContext, UnitPolicy};
use crate::limit;
use crate::migration;
use crate::policy;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{
    AccountRow, applied_witness, edge_id, leg_vid, mantissa_scalar, prop, resolution_vid,
    reversal_vid, state_from_scalar,
};
use crate::schedule;
use crate::sweep;

/// The capability a post is authorized under: Steward's typed object
/// (holder, profile, ops, per-unit ceilings, a declared CommitSeq expiry,
/// issuer), defined and judged in the laws layer (`fa-policy`, bead fa-llx).
pub use fa_policy::Capability;

/// One post. **Trust boundary:** `proposal.principal_ref` and `capability`
/// are the caller's claims; the kernel checks that they agree (the
/// capability's holder is the principal) and judges the capability, but it
/// does not authenticate. In the embedded posture the calling process is the
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

/// Pure kernel decision entry point for Appendix C admissibility (`fa-nfq`):
/// evaluates the exact four-stage period-law gate used by `prepare_post_in`
/// and `sweep` over `(class, state, family, kind, pre_opening)`.
#[must_use]
pub fn decide_admissibility_cell(
    matrix: &Admissibility,
    class: &str,
    state: fa_time::PeriodState,
    family: fa_registry::DispositionFamily,
    kind: fa_time::PeriodKind,
    pre_opening: bool,
) -> Option<Decision> {
    if let Some(rule) = matrix.kind_rule(kind)
        && !rule.admits(class)
    {
        return Some(Decision::Refuse);
    }
    if pre_opening
        && let Some(rule) = matrix.pre_opening()
        && rule.kinds.contains(&kind)
        && !rule.admits(class)
    {
        return Some(Decision::Refuse);
    }
    if let Some(rule) = matrix.special_period_rule(kind)
        && !rule.admits(class)
    {
        return Some(Decision::Refuse);
    }
    match family {
        fa_registry::DispositionFamily::Expires if class == "Resolution" => {
            matrix.decide_expires(state).cloned()
        }
        fa_registry::DispositionFamily::Expires | fa_registry::DispositionFamily::Voids => {
            matrix.decide_disposition(class, state, true)
        }
        fa_registry::DispositionFamily::Standard => matrix.decide_disposition(class, state, false),
    }
}

/// An admitted retry is already complete; a fresh post retains the actual
/// substrate transaction until its caller chooses to commit or abort it.
#[derive(Debug)]
#[must_use]
pub enum PostPreparation {
    AlreadyRecorded(Posted),
    Ready(Box<PreparedPost>),
}

/// A sealed post and its original read witnesses. Fields stay private so a
/// caller cannot replace the acting capability, proposal, or transaction.
/// Dropping this value abandons the staged write and releases its pin.
#[derive(Debug)]
#[must_use]
pub struct PreparedPost {
    txn: WriteTxn,
    request: PostRequest,
    entry: Entry,
    entry_ref: EntryRef,
    period: String,
    security_policy_epoch: u64,
    effects_digest: [u8; 32],
    identity: Identity,
    seal_key: SealKey,
}

impl PreparedPost {
    /// The committed prefix against which all laws and witnesses were read.
    #[must_use]
    pub fn basis(&self) -> CommitSeq {
        self.txn.basis()
    }

    pub(crate) fn entry(&self) -> &Entry {
        &self.entry
    }

    pub(crate) fn period(&self) -> &str {
        &self.period
    }

    pub(crate) fn security_policy_epoch(&self) -> u64 {
        self.security_policy_epoch
    }

    pub(crate) fn effects_digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(self.effects_digest)
    }

    /// Only the verified planning path appends its immutable graph evidence
    /// after comparing the actual accounting effect. The original witnesses
    /// and exact prepared Entry remain in this same transaction.
    pub(crate) fn retain_plan<V: asupersync::fs::Vfs + Clone>(
        &mut self,
        db: &mut Database<V>,
        batch: WriteBatch,
    ) -> Result<(), KernelError> {
        self.txn.write_ordered(db, vec![batch])?;
        Ok(())
    }

    /// Release the prepared transaction without publishing any effects.
    pub fn abort(self) {
        self.txn.abort();
    }

    /// Publish once through the ordinary substrate validator. Expiry is
    /// judged again at the current frontier, without refreshing any of the
    /// preparation's revocation, policy, period, or accounting witnesses.
    pub async fn commit<V: asupersync::fs::Vfs + Clone>(
        self,
        db: &mut Database<V>,
        ctx: &PurposeContexts,
    ) -> Outcome<Posted> {
        let commit = ctx.commit();
        commit.checkpoint().map_err(WriteTxnError::Interrupted)?;
        let Self {
            mut txn,
            request,
            entry: _,
            entry_ref,
            period,
            security_policy_epoch: _,
            effects_digest: _,
            identity,
            seal_key,
        } = self;
        if let Err(d) = fa_policy::current(&request.capability, db.frontier()?) {
            txn.abort();
            return Ok(Err(policy::refusal(&d)));
        }
        match txn.commit(db, &commit).await {
            Ok(seq) => Ok(Ok(Posted::Committed {
                entry_ref,
                recorded_at: seq,
                period,
            })),
            Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
                Ok(Err(Refusal::new(
                    code::CONFLICT,
                    exit::CONFLICT,
                    format!("a concurrent commit invalidated a witness this post read: {detail}"),
                    "FG-LAW-FCW-01 (first committer wins)",
                    "re-plan and retry; if a close or a policy activation won, the period-law or stale-approval refusal will say so",
                )))
            }
            Err(WriteTxnError::Write(
                fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
            )) => {
                // Lost the identity race: the recorded outcome if it is the
                // same intent, a conflict if it is not. A scoped token cannot
                // judge the winner's scope without loading it, so it gets the
                // conflict unread (WhiteCreek 3584); its retry decides from
                // metadata.
                if request.capability.is_scoped() {
                    return Ok(Err(identity_conflict(identity, entry_ref.vid)));
                }
                match db.vertex(entry_ref.vid)? {
                    Some(row) => {
                        checked_entry(db, &row)?;
                        recorded_or_conflict(&row, &request.proposal, &seal_key, identity)
                    }
                    None => Err(KernelError::Corrupt(
                        "identity spent but no live row".into(),
                    )),
                }
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// How an entry's identity was derived (plan §4.9, §5.4): from the
/// principal's idempotency key, or from the target it reverses or resolves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Identity {
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
pub(crate) fn recorded_or_conflict(
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
    // A balancing post's identity binds its request (plan §5.5): a stored
    // balancing entry is compared in request form — its legs at the
    // requested amount, never at what moved.
    let request_form = limit::request_form(&stored.proposal)?;
    let stored_digest = match &request_form {
        Some(r) => r.proposal_digest()?,
        None => stored.proposal_digest,
    };
    if stored_digest == proposal.proposal_digest()? {
        return Ok(Ok(recorded));
    }
    let conflict = identity_conflict(identity, row.vid);
    if identity != Identity::Key && stored.proposal.principal_ref != proposal.principal_ref {
        return Ok(Err(conflict));
    }
    match (
        request_form
            .as_ref()
            .unwrap_or(&stored.proposal)
            .semantic_digest(key),
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

/// The conflict for an identity already taken by different content.
fn identity_conflict(identity: Identity, vid: VId) -> Refusal {
    match identity {
        Identity::Reversal => Refusal::new(
            code::ALREADY_REVERSED,
            exit::CONFLICT,
            format!("the target is already reversed by entry {:032x}", vid.0),
            "plan §4.9 (one reversal per target, by identity)",
            "cite the existing reversal instead of posting another",
        ),
        Identity::Resolution => Refusal::new(
            code::ALREADY_RESOLVED,
            exit::CONFLICT,
            format!(
                "the pending entry is already resolved by entry {:032x}",
                vid.0
            ),
            "plan §5.4 (one resolution per pending entry, by identity)",
            "read the existing resolution with `fa entry show`; a pending entry is resolved exactly once",
        ),
        Identity::Key => Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            format!(
                "idempotency key reused with different content; the recorded entry is {:032x}",
                vid.0
            ),
            "plan §4.9 (identity is derived from the key; content is bound by proposal_digest)",
            "resubmit the identical intent to get the recorded outcome, or use a new idempotency key for new content",
        ),
    }
}

/// A reversal's target is absent — or, to a scoped token, not wholly in its
/// scope: one envelope, so the token cannot tell the two apart.
fn no_reversal_target(vid: VId) -> Refusal {
    Refusal::new(
        code::REVERSAL_TARGET,
        exit::REFUSAL,
        format!("no entry {:032x} in this book", vid.0),
        "plan §4.4",
        "fa entry show <vid> to find the entry to reverse",
    )
}

/// A resolution's hold is absent, or not wholly in a scoped token's scope.
fn no_resolution_target(vid: VId) -> Refusal {
    Refusal::new(
        code::RESOLUTION_TARGET,
        exit::REFUSAL,
        format!("no entry {:032x} in this book", vid.0),
        "plan §5.4",
        "fa entry show <vid> to find the pending entry to resolve",
    )
}

/// Leg `i`'s settlement target is absent, or not wholly in a scoped token's
/// scope.
fn no_settle_target(i: usize, vid: VId) -> Refusal {
    Refusal::new(
        code::SETTLE_TARGET,
        exit::REFUSAL,
        format!("leg {i}: no entry {:032x} in this book", vid.0),
        "plan §5.7",
        "fa open-items --account <code> lists the open items to apply to",
    )
}

/// Whether a scoped token reaches the entry at `vid`: decided from its
/// metadata alone ([`policy::entry_in_scope_by_metadata`]), so an entry
/// outside the scope is never loaded or decoded. `false` for an absent
/// vertex or a non-entry too: one answer for all three.
fn reaches<V: asupersync::fs::Vfs + Clone>(
    txn: &fgdb::WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    req: &PostRequest,
    scope: Option<&fa_policy::AccountScope>,
    vid: VId,
) -> Result<bool, KernelError> {
    policy::entry_in_scope_by_metadata(txn, db, book, &req.capability, scope, vid)
}

/// Step 3''' for a scoped token (plan §14.2, CobaltGull 3570): the targets
/// the commit releases, applies to or undoes are part of its footprint — a
/// resolution's hold (every leg, so a partial Posts never silently releases
/// an out-of-scope leg), each settled entry, and a reversal's target with
/// its predecessor and every entry its legs applied to (the undo, WhiteCreek
/// 3584). Each is judged from metadata before any payload of it is read;
/// only the reversal's target, once admitted, is decoded here (its payload
/// names the rest), and a payload that disagrees with its admitted mirrors
/// is corruption. Out of scope, absent or not an entry, the refusal is the
/// path's own "no entry" envelope.
fn footprint_refusal<V: asupersync::fs::Vfs + Clone>(
    txn: &fgdb::WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    req: &PostRequest,
    scope: Option<&fa_policy::AccountScope>,
    reversal_target: Option<EntryRef>,
    resolution: Option<&(EntryRef, Disposition)>,
) -> Result<Option<Refusal>, KernelError> {
    let reached = |vid: VId| reaches(txn, db, book, req, scope, vid);
    if let Some(target) = reversal_target {
        let mut current = target.vid;
        let mut seen: BTreeSet<VId> = BTreeSet::new();
        loop {
            if !seen.insert(current) {
                return Err(KernelError::Corrupt(format!(
                    "reversal ancestry of {:032x} cycles",
                    target.vid.0
                )));
            }
            if !reached(current)? {
                return Ok(Some(no_reversal_target(target.vid)));
            }
            let row = txn.vertex(db, current)?.ok_or_else(|| {
                KernelError::Corrupt("an admitted reversal target vanished".into())
            })?;
            let (entry, _) = checked_entry(db, &row)?;
            let predecessors = entry.proposal.supersession.iter().map(|s| s.target.vid);
            let applied = entry
                .proposal
                .legs
                .iter()
                .flat_map(|l| l.settles.iter().map(|s| s.target.vid));
            for vid in predecessors.chain(applied) {
                if !reached(vid)? {
                    return Ok(Some(no_reversal_target(target.vid)));
                }
            }
            if entry.proposal.class == EntryClass::REVERSAL
                && let [first] = entry.proposal.supersession.as_slice()
            {
                current = first.target.vid;
            } else {
                break;
            }
        }
    }
    if let Some((target, _)) = resolution
        && !reached(target.vid)?
    {
        return Ok(Some(no_resolution_target(target.vid)));
    }
    for (i, leg) in req.proposal.legs.iter().enumerate() {
        for s in &leg.settles {
            if !reached(s.target.vid)? {
                return Ok(Some(no_settle_target(i, s.target.vid)));
            }
        }
    }
    Ok(None)
}

fn not_implemented(class_name: &str) -> Refusal {
    let lands_with = match class_name {
        "settles on a two-phase entry" | "re-application by reversing a reversal" => {
            "the full application-netting law (plan §5.7, §8.2; fa-06a)"
        }
        "leg.base_amount" | "base_totals" => "the FX law slice (fa-p7r)",
        "leg.dimension_set" => "the dimension registry slice (plan §4.3)",
        "Replacement" | "Reclassification" => "fa-omi (supersession beyond exact reversal)",
        "Revision" | "Restatement" | "PriorPeriodAdjustment" => {
            "the restatement-case slice (fa-azu children)"
        }
        "Closing" => "the incremental closing slice (plan §7.5)",
        "Revaluation" | "Elimination" => "Canon rules (plan §10)",
        "Migration into a limited account" => {
            "the migration availability slice (a staged chunk must not move a LimitCell before Finalize)"
        }
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
    match prepare_post(db, ctx, book, req)? {
        Err(refusal) => Ok(Err(refusal)),
        Ok(PostPreparation::AlreadyRecorded(posted)) => Ok(Ok(posted)),
        Ok(PostPreparation::Ready(prepared)) => prepared.commit(db, ctx).await,
    }
}

/// The classes this kernel slice posts (step 1b); every other registered
/// class is refused as not implemented, and no refusal suggests one.
const POSTED_CLASSES: [EntryClass; 7] = [
    EntryClass::ORIGINAL,
    EntryClass::ADJUSTING,
    EntryClass::REVERSAL,
    EntryClass::PENDING,
    EntryClass::RESOLUTION,
    EntryClass::MIGRATION,
    EntryClass::ALLOCATION,
];

/// Run the production posting pipeline through staging, retaining its
/// witnesses at one prefix without publishing a commit. Another prepared
/// operation may commit before this one; the ordinary validator decides
/// whether the original witnesses still hold.
pub fn prepare_post<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    req: PostRequest,
) -> Outcome<PostPreparation> {
    ctx.txn().checkpoint().map_err(WriteTxnError::Interrupted)?;
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
    if proposal.class == EntryClass::SCHEDULE_CONTROL {
        return Ok(Err(Refusal::new(
            code::CANCEL_BY_KERNEL,
            exit::USAGE,
            "a ScheduleControl entry (a schedule's cancellation) is journaled by the kernel, never posted",
            "plan §7.6 (cancelled by lineage), FA-INV-08",
            "reverse the scheduled target with a Reversal; its commit journals the cancellation",
        )));
    }
    if proposal.class.is_control() {
        return Ok(Err(Refusal::new(
            code::CONTROL_VIA_POST,
            exit::USAGE,
            format!("`{class_name}` is a control class"),
            "plan §8.1",
            "use `fa period <transition>` or `fa chart import`; control records are not posted",
        )));
    }
    // 1a. Authorization precedes observation (doctrine 8, FA-INV-10): the
    //     capability is the acting principal's, an Agent profile never
    //     writes trunk, `post` is held, every explicit leg is within its
    //     unit's ceiling, and the scope caveats admit what the payload
    //     reaches (plan §14.2, [`policy::payload_reach`]): every leg's
    //     account inside the `accounts` subtrees, the periods its date and
    //     any `auto_reverse_on` resolve to (from the calendar alone) inside
    //     `periods`, both dates inside `effective`, no `known_at` pin (a
    //     write observes the head), the token's `branch` — decided by
    //     fa-policy from the payload alone, before anything is read,
    //     including the identity row. Only the `accounts` caveat's compile
    //     reads: after the base checks and 1a', and only the caveat's own
    //     subtrees. The targets it releases, applies to or undoes are judged
    //     in step 3'''.
    let explicit: Vec<(fa_money::UnitId, i128)> = proposal
        .legs
        .iter()
        .map(|l| (l.amount.unit, l.amount.mantissa))
        .collect();
    if let Err(d) = fa_policy::admit_base(
        &req.capability,
        &fa_policy::Intent {
            principal: proposal.principal_ref,
            trunk: proposal.branch_id == Id128::TRUNK,
            op: fa_policy::Op::Post,
            book: book.book_id,
            legs: &explicit,
        },
    ) {
        return Ok(Err(policy::refusal(&d)));
    }
    // 1a'. The capability is current at the admission point (plan §14.2):
    //      not expired at the head this single-writer handle observes, and
    //      not revoked there (one point read at the token's own revocation
    //      identity) — before the chart or anything else is read, so a
    //      token expired or revoked now learns nothing, not even which
    //      accounts its caveat covers. Nothing commits between here and the
    //      transaction, which witnesses the revocation again for FCW.
    let current = match policy::current_at(db, book, &req.capability)? {
        Ok(current) => current,
        Err(r) => return Ok(Err(r)),
    };
    let scope = policy::account_scope(db, book, &current)?;
    if let Err(d) = policy::payload_reach(&req.capability, book, proposal, scope.as_ref()) {
        return Ok(Err(policy::refusal(&d)));
    }
    // 1b. The supported subset.
    let is_reversal = proposal.class == EntryClass::REVERSAL;
    if !POSTED_CLASSES.contains(&proposal.class) {
        return Ok(Err(not_implemented(class_name)));
    }
    // Allocation is admitted only by recomputing its exact, evidence-bound
    // native legs. This also rejects its provenance on a different class.
    let allocation = match crate::allocation::admit(proposal) {
        Ok(basis) => basis,
        Err(refusal) => return Ok(Err(refusal)),
    };
    ctx.txn().checkpoint().map_err(WriteTxnError::Interrupted)?;
    // 1b'. Migration provenance (plan §8.6): a Migration entry names its run
    //      in its origin, and no other class carries migration provenance.
    let migration_run = match (&proposal.origin, proposal.class == EntryClass::MIGRATION) {
        (EntryOrigin::Migration { run_ref, .. }, true) => Some(*run_ref),
        (EntryOrigin::Migration { .. }, false) => {
            return Ok(Err(Refusal::new(
                code::MIGRATION_OUTSIDE_RUN,
                exit::REFUSAL,
                format!("a `{class_name}` entry carries migration provenance"),
                "plan §8.6 (migrated_from rides Migration entries only)",
                "post legacy history as a Migration entry inside an open run, or drop the Migration origin",
            )));
        }
        (_, true) => {
            return Ok(Err(Refusal::new(
                code::MIGRATION_OUTSIDE_RUN,
                exit::REFUSAL,
                "a Migration entry names no run: its origin is not Migration { run_ref, .. }",
                "plan §8.6, Appendix C (Migration: inside an open MigrationRun)",
                "set origin = Migration { run_ref: <the run's vid>, .. } and post into the run",
            )));
        }
        _ => None,
    };
    // Provenance and plan references are claims, not caller-selected labels.
    // The public path admits authored intents and the migration path checked
    // above. System entries are minted by their own internal constructors;
    // Canon and verified dry-run certificates have not shipped yet. Refuse
    // these fields before any storage observation other than the
    // capability's own currency and scope reads (1a'), including on retry.
    if req.plan_certificate.is_some() {
        return Ok(Err(Refusal::new(
            code::CLASS_NOT_IMPLEMENTED,
            exit::REFUSAL,
            "plan_certificate names an unverified dry-run certificate",
            "Appendix A Entry envelope; FA-INV-05; fa-we7",
            "omit plan_certificate until the plan-certificate verifier is available (fa-we7)",
        )));
    }
    let unsupported_origin = match &proposal.origin {
        EntryOrigin::Intent { .. } | EntryOrigin::Migration { .. } => None,
        EntryOrigin::Rule { .. } => Some((
            "Rule",
            "leave the rule-derived entry unposted until Canon verifies its rule, event and inputs (fa-c34)",
        )),
        EntryOrigin::Sweep { .. } => Some((
            "Sweep",
            "run the kernel expiry sweep under a committed tick; only that sweep may mint Sweep provenance",
        )),
        EntryOrigin::Schedule { .. } => Some((
            "Schedule",
            "register the scheduled effect and let the kernel scheduler mint it from its trigger",
        )),
        EntryOrigin::Control { .. } => Some((
            "Control",
            "use the typed control operation; public post cannot mint a control origin",
        )),
    };
    if let Some((origin, fix)) = unsupported_origin {
        return Ok(Err(Refusal::new(
            code::CLASS_NOT_IMPLEMENTED,
            exit::REFUSAL,
            format!("entry.origin.{origin} cannot be supplied through public post"),
            "Appendix A EntryOrigin; FA-INV-05 (registered origin)",
            fix,
        )));
    }
    // 1c. Two-phase shape (plan §5.4). `validate` already fixed the arity;
    //     `Expires` is the system's void at timeout — the expiry sweep mints
    //     it under a committed tick, so a caller never posts one.
    let timeout = match &proposal.pending {
        Some(Pending {
            timeout_ns: Some(t),
            ..
        }) if proposal.class == EntryClass::PENDING => Some(*t),
        _ => None,
    };
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
        return Ok(Err(Refusal::new(
            code::EXPIRES_BY_SWEEP,
            exit::USAGE,
            "a Resolution(Expires) is minted by the expiry sweep under a committed tick, never posted",
            "plan §5.4 (Expires is the system's void at timeout)",
            "release the hold now with Resolution(Voids), or let the expiry sweep expire it once a tick reaches its deadline",
        )));
    }
    // 1d. FX valuations this slice does not enforce are refused, never
    //     admitted unchecked. The aggregate is itself a claim about a law
    //     and its rate documents, even when no leg carries a base amount.
    if proposal.base_totals.is_some() {
        return Ok(Err(not_implemented("base_totals")));
    }
    for leg in &proposal.legs {
        if leg.base_amount.is_some() {
            return Ok(Err(not_implemented("leg.base_amount")));
        }
    }
    // 1d'. Legal entities (plan §4.1, §5.2): a leg names its entity in its
    //      dimension_set; the book's declaration (its immutable genesis spec)
    //      decides — undeclared is refused, and in a multi-entity book every
    //      leg names one. Other dimensions wait for the dimension registry.
    let spec = crate::genesis::read_book_spec(db)?
        .ok_or_else(|| KernelError::Corrupt("no book spec on the root".into()))?;
    let leg_entities = match entity::leg_entities(&spec, &proposal.legs) {
        Ok(e) => e,
        Err(entity::LegEntityError::OtherDimension) => {
            return Ok(Err(not_implemented("leg.dimension_set")));
        }
        Err(entity::LegEntityError::Refused(r)) => return Ok(Err(r)),
    };
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
            // The reservation carries no applications. A Posts resolution
            // declares applications on its actual posted sub-vector; steps
            // 7a/7b judge both capacities before either effect is staged.
            EntryClass::RESOLUTION
                if matches!(&resolution, Some((_, Disposition::Posts { .. }))) => {}
            EntryClass::REVERSAL => {
                return Ok(Err(Refusal::new(
                    code::SETTLE_SHAPE,
                    exit::REFUSAL,
                    format!("leg {i}: a Reversal carries no settles"),
                    "plan §5.7 (application undo is derived from the reversed target, never re-entered)",
                    "remove `settles`; reversing an applying entry undoes its applications",
                )));
            }
            // Legacy applications inside a run are the interim posture's
            // gap (ruling 3733 C2, plan §8.6, Appendix H): until substrate
            // branches, a chunk is imported net of them.
            EntryClass::MIGRATION => {
                return Ok(Err(Refusal::new(
                    code::SETTLE_SHAPE,
                    exit::REFUSAL,
                    format!("leg {i}: a Migration chunk carries no settles"),
                    "plan §8.6, Appendix H (legacy applications inside a MigrationRun: interim posture), ruling 3733",
                    "import the legacy open item net of its legacy applications",
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
    // 1f. A scheduled reversal (plan §7.6, §7.7): an Adjusting entry's
    //     `fa:auto-reverse:v1` request, judged from the payload and the
    //     book's declared time_zone_policy (its immutable genesis spec).
    let scheduled = match schedule::admit_request(db, book, proposal)? {
        Ok(s) => s,
        Err(r) => return Ok(Err(r)),
    };
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
    //    Amounts are rendered at the unit's registered scale ("0.01 USD"), so
    //    the fix names an amount the caller can post as written.
    for t in &proposal.unit_totals {
        if t.debits != t.credits {
            let (side, gap) = if t.debits > t.credits {
                ("credit", t.debits.checked_sub(t.credits))
            } else {
                ("debit", t.credits.checked_sub(t.debits))
            };
            let gap = gap.ok_or_else(|| {
                KernelError::Corrupt(format!(
                    "unit {} totals outside the validated domain",
                    t.unit_id
                ))
            })?;
            let unit = fa_money::UnitId(t.unit_id);
            let show = |m: i128| {
                if book.units.get(unit).is_some() {
                    fa_money::Amount::new(unit, m).render(&book.units)
                } else {
                    format!("{m} (mantissa of unregistered unit {})", t.unit_id)
                }
            };
            return Ok(Err(Refusal::new(
                code::UNBALANCED,
                exit::REFUSAL,
                format!(
                    "debits {} ≠ credits {} (difference {})",
                    show(t.debits),
                    show(t.credits),
                    show(gap)
                ),
                "FA-INV-01 per-unit balance law",
                format!(
                    "add a {side} leg of {} to the account that explains it; the kernel never invents one",
                    show(gap)
                ),
            )));
        }
    }
    // 2'. Per legal entity (FA-INV-01 `per-entity`): the same law per
    //     (unit, legal_entity); a cross-entity imbalance is never closed by
    //     an invented leg.
    if let Some(r) = entity::per_entity_refusal(&proposal.legs, &leg_entities, &book.units)? {
        return Ok(Err(r));
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

    // 3''. A Migration chunk names its period (plan §8.6): its run's Opening
    //      period, a declared Historical period, or (FullDetail) a
    //      pre-opening special period between them. Which of those the
    //      named period is, the run (4') and the period row (5) decide.
    if migration_run.is_some() && proposal.effective_period.is_none() {
        return Ok(Err(Refusal::new(
            code::MIGRATION_OUTSIDE_RUN,
            exit::REFUSAL,
            format!(
                "a Migration entry must name its period with effective_period; it resolves to `{}`, a {:?} period",
                period.code, period.kind
            ),
            "plan §8.6, Appendix C (Migration: Opening and Historical periods only)",
            format!(
                "name FY{}-OPEN (dated on the run's opening date) or one of the run's declared Historical periods in effective_period",
                period.fiscal_year
            ),
        )));
    }

    // (The capability was found current at the admission point in 1a'.)

    // From here every read is a witness of this transaction.
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    // The capability is not revoked (plan §14.2): the first read, so a
    // revoked token learns nothing about the book, not even a recorded outcome.
    if let Err(r) = policy::capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    // 3'''. A scoped token's footprint beyond the payload (plan §14.2,
    //       CobaltGull 3570): every target the commit releases, applies to
    //       or undoes lies wholly inside the scope, or the refusal is that
    //       path's "no entry" envelope — read here, before the identity row.
    if req.capability.is_scoped()
        && let Some(r) = footprint_refusal(
            &txn,
            db,
            book,
            &req,
            scope.as_ref(),
            reversal_target,
            resolution.as_ref(),
        )?
    {
        txn.abort();
        return Ok(Err(r));
    }

    // 4. Identity (plan §4.9, FA-INV-09): derived from the key, from the
    //    reversed target, or from the resolved pending entry; an existing row
    //    is the recorded outcome or a conflict.
    let (evid, identity) = match (reversal_target, &resolution) {
        (Some(t), _) => (reversal_vid(t.vid), Identity::Reversal),
        (None, Some((t, _))) => (resolution_vid(t.vid), Identity::Resolution),
        // A chunk's identity includes its run (plan §8.6): a retry run
        // reuses an abandoned run's keys.
        (None, None) => match migration_run {
            Some(run) => (
                migration_entry_vid(book.book_id, run, &proposal.idempotency_key),
                Identity::Key,
            ),
            None => (
                entry_vid(
                    book.book_id,
                    &proposal.principal_ref.0.to_le_bytes(),
                    &proposal.idempotency_key,
                ),
                Identity::Key,
            ),
        },
    };
    // A scoped token never loads or compares a recorded entry outside its
    // scope (WhiteCreek 3571/3582): existence and membership come from
    // metadata first; a taken identity it does not reach conflicts — no
    // payload read, no digest or plaintext comparison, no recorded outcome.
    if req.capability.is_scoped()
        && txn.vertex_has_label(db, evid, label::ENTRY)?.is_some()
        && !reaches(&txn, db, book, &req, scope.as_ref(), evid)?
    {
        txn.abort();
        return Ok(Err(identity_conflict(identity, evid)));
    }
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        checked_entry(db, &row)?;
        return Ok(
            recorded_or_conflict(&row, proposal, &book.seal_key, identity)?
                .map(PostPreparation::AlreadyRecorded),
        );
    }

    // A fresh correction names a registered reason. Outcome recognition
    // stays first: an identical retry never rewrites or reinterprets an old
    // immutable entry, including a reversal recorded before this law.
    if is_reversal {
        let reasons = fa_registry::reason_codes::ReasonCodes::embedded()
            .map_err(|e| KernelError::Corrupt(e.to_string()))?;
        let reason = proposal.supersession[0].reason_code;
        // ScheduledAccrualReversal names the kernel's own scheduled effect,
        // which the scheduler mints without this path; a manual reversal
        // citing it would impersonate one (fa-cvg), so it is not a reason a
        // principal may give here.
        let registered = reasons
            .get("supersession", reason)
            .filter(|_| reason != fa_registry::reason_codes::SCHEDULED_ACCRUAL_REVERSAL);
        let described = registered.is_none_or(|row| {
            row.name != "Other"
                || proposal
                    .description
                    .open(&book.seal_key, 1024)
                    .is_ok_and(|text| !text.trim().is_empty())
        });
        if registered.is_none() || !described {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::SUPERSESSION_REASON,
                exit::REFUSAL,
                if reason == fa_registry::reason_codes::SCHEDULED_ACCRUAL_REVERSAL {
                    format!(
                        "supersession reason {reason} (ScheduledAccrualReversal) is reserved for the kernel's scheduled reversal; a manual reversal gives its own reason"
                    )
                } else if registered.is_none() {
                    format!("supersession reason {reason} is not registered (zero is not a reason)")
                } else {
                    "supersession reason Other requires a nonempty description sealed for this book"
                        .into()
                },
                "plan §8.2, reason_codes.toml scope supersession",
                format!(
                    "choose a registered reason: {}; for Other, supply --description with the particulars",
                    reasons.listing("supersession")
                ),
            )));
        }
    }

    // 4'. The run (plan §8.6): its state is a point witness, so a Finalize
    //     or Abandon that commits first makes this chunk a first-committer-wins
    //     conflict. An Opening-period chunk is dated on the run's opening
    //     date; any other chunk lands in a Historical period its run
    //     declares.
    if let Some(run_vid) = migration_run {
        let run = match migration::witness_open(&txn, db, run_vid)? {
            Ok(run) => run,
            Err(r) => {
                txn.abort();
                return Ok(Err(r));
            }
        };
        // The run's own Opening period holds the opening chunks; a Normal
        // code must be declared; any other special period is FullDetail
        // detail inside the declared run of periods (a pre-opening Opening,
        // Adjustment or Closing period, ruling 3685).
        let own_opening =
            period.kind == fa_time::PeriodKind::Opening && period.start == run.body.opening_date;
        let admitted = if own_opening {
            true
        } else if period.kind == fa_time::PeriodKind::Normal {
            run.body.declares(&period.code)
        } else {
            run.body.mode == crate::migration::RunMode::FullDetail
                && migration::within_declared(&txn, db, book, &run.body, &period)?
        };
        if !admitted {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::MIGRATION_OUTSIDE_RUN,
                exit::REFUSAL,
                format!(
                    "run `{}` ({:?}) declares no period `{}`",
                    run.body.run_key, run.body.mode, period.code
                ),
                "plan §8.6 (imported detail only in the run's declared Historical periods, and for FullDetail the special periods between them)",
                "post into the run's Opening period, or into a period its body declares",
            )));
        }
        if own_opening
            && run.body.mode == crate::migration::RunMode::FullDetail
            && run.body.sole_opening_source
        {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::MIGRATION_OUTSIDE_RUN,
                exit::REFUSAL,
                format!(
                    "run `{}` is the sole source of its opening balances: it holds no Opening chunk",
                    run.body.run_key
                ),
                "plan §8.6 (FullDetail sole_opening_source: no opening-balance entry), ruling 3675",
                "post the legacy detail into its Historical periods; the detail is the opening balances",
            )));
        }
        if own_opening && proposal.effective_date != run.body.opening_date {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::MIGRATION_OUTSIDE_RUN,
                exit::REFUSAL,
                format!(
                    "the chunk is dated {} but run `{}` opens on {}",
                    proposal.effective_date.render(),
                    run.body.run_key,
                    run.body.opening_date.render()
                ),
                "plan §8.6 (opening balances are effective on the opening date)",
                format!(
                    "date the chunk {} (the run's opening date)",
                    run.body.opening_date.render()
                ),
            )));
        }
    }

    // 5. Period law (Appendix C) against the witnessed state and kind. A
    //    period's kind is decided at its birth (a Normal period before the
    //    book's opening date is Historical), and a registered kind row
    //    (`admissibility.toml` `[[kind]]`) narrows the classes it admits,
    //    whatever its state: a Historical period admits only Migration. (A
    //    run's chunks reach only its Opening period or the Historical periods
    //    `check_history` verified at its Open, so a chunk never reaches a
    //    live period.)
    let pvid = period_vid(&book.calendar.id, &period.code);
    let state_scalar = txn.vertex_property(db, pvid, property::STATE)?;
    let state = state_from_scalar(state_scalar.as_ref())
        .ok_or_else(|| KernelError::Corrupt(format!("period `{}` state mirror", period.code)))?;
    let kind_scalar = txn.vertex_property(db, pvid, property::PERIOD_KIND)?;
    // Every created period carries its kind, so a missing kind is a period
    // the calendar defines but nobody created (a lawful request ahead of
    // `fa period create`), unless the vertex exists without it (corruption).
    if kind_scalar.is_none() && txn.vertex(db, pvid)?.is_none() {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::PERIOD_UNKNOWN,
            exit::SAFETY,
            format!(
                "effective date {} falls in period `{}` of fiscal year {}, which was never created",
                proposal.effective_date.render(),
                period.code,
                period.fiscal_year
            ),
            "plan §7.3 (periods are created per fiscal year)",
            format!(
                "fa period create --fiscal-year {}, then open `{}`",
                period.fiscal_year, period.code
            ),
        )));
    }
    let born = crate::rows::kind_from_scalar(kind_scalar.as_ref())
        .ok_or_else(|| KernelError::Corrupt(format!("period `{}` kind mirror", period.code)))?;
    // 5'. The security policy epoch, a point witness exactly like the period
    //     state: an activation that commits first makes this post a
    //     first-committer-wins conflict (plan §14.2 `current-policy`).
    let epoch = policy::epoch_witness(&txn, db)?;
    let classes = EntryClasses::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let matrix =
        Admissibility::embedded(&classes).map_err(|e| KernelError::Corrupt(e.to_string()))?;
    if let Some(rule) = matrix.kind_rule(born)
        && !rule.admits(class_name)
    {
        if rule.refusal != code::PERIOD_LAW {
            return Err(KernelError::Corrupt(format!(
                "admissibility.toml refuses a {born:?} period with `{}`, not the period law's {}",
                rule.refusal,
                code::PERIOD_LAW
            )));
        }
        txn.abort();
        return Ok(Err(Refusal::new(
            code::PERIOD_LAW,
            exit::SAFETY,
            format!(
                "`{}` is a {born:?} period (before the book's opening date); it admits only {}, not `{class_name}`",
                period.code,
                rule.admits.join(", ")
            ),
            format!(
                "plan §7.2, Appendix C (admissibility.toml kind {born:?}: Historical periods admit only Migration)"
            ),
            "keep the entry's true effective date; history dated before the book's opening date enters only through a MigrationRun (plan §8.6), never by re-dating it into a live period",
        )));
    }
    // 5''. A special period before the book's opening date (the registered
    //      pre_opening rule, ruling 3685) admits only its classes, whatever
    //      its state.
    if let Some(rule) = matrix.pre_opening()
        && rule.kinds.contains(&born)
        && rule.governs(born, period.end, crate::genesis::opening_date_in(&txn, db)?)
        && !rule.admits(class_name)
    {
        if rule.refusal != code::PERIOD_LAW {
            return Err(KernelError::Corrupt(format!(
                "admissibility.toml refuses a pre-opening {born:?} period with `{}`, not the period law's {}",
                rule.refusal,
                code::PERIOD_LAW
            )));
        }
        txn.abort();
        return Ok(Err(Refusal::new(
            code::PERIOD_LAW,
            exit::SAFETY,
            format!(
                "`{}` is a {born:?} period before the book's opening date; it admits only {}, not `{class_name}`",
                period.code,
                rule.admits.join(", ")
            ),
            rule.cite.clone(),
            "keep the entry's true effective date; history dated before the book's opening date enters only through a MigrationRun (plan §8.6), never by re-dating it into a live period",
        )));
    }
    if let Some(rule) = matrix.special_period_rule(born)
        && !rule.admits(class_name)
    {
        if rule.refusal != code::PERIOD_LAW {
            return Err(KernelError::Corrupt(format!(
                "admissibility.toml special period {born:?} cites an unexpected refusal {}",
                rule.refusal
            )));
        }
        txn.abort();
        return Ok(Err(Refusal::new(
            code::PERIOD_LAW,
            exit::SAFETY,
            format!(
                "`{}` is a {born:?} period and does not admit `{class_name}`",
                period.code
            ),
            rule.cite.clone(),
            format!(
                "post `{class_name}` in a Normal period; this special period admits only {}",
                rule.admits.join(", ")
            ),
        )));
    }
    let family = match &resolution {
        Some((_, Disposition::Posts { .. })) => "(Posts)",
        Some((_, Disposition::Voids)) => "(Voids)",
        Some((_, Disposition::Expires { .. })) | None => "",
    };
    let cell = format!(
        "admissibility.toml ({class_name}{family}, {})",
        state.name()
    );
    let matrix_approvals = match matrix.decide_disposition(class_name, state, is_release) {
        Some(Decision::Admit) => 0,
        Some(Decision::With { op, approvals }) => {
            let op = op.as_str();
            let needed = fa_policy::Op::from_name(op).ok_or_else(|| {
                KernelError::Corrupt(format!("admissibility.toml cites unregistered op `{op}`"))
            })?;
            if !req.capability.holds(needed) {
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
                        "keep the entry's true effective date and obtain `{op}` from the book's steward (embedded posture: `--grant {op}`); never re-date an entry to escape the period law"
                    ),
                )));
            }
            approvals
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
                    "a {} period admits only a release of the hold: resolve it with Voids; a Posts resolution carries the date it actually posts, never one chosen to escape the period law",
                    state.name()
                )
            } else {
                // Lawful routes only (doctrine: never re-date an entry to
                // escape the period law; rulings 3397/3408, fa-l93 D8): the
                // classes this state's cells admit that this slice posts,
                // without case-bound cells (refused in this build), Migration
                // (its run's periods only) and Resolution (its own route).
                let posted = |class: &str| {
                    class != "Migration"
                        && class != "Allocation"
                        && POSTED_CLASSES.iter().any(|c| c.name() == Some(class))
                };
                let postings: Vec<String> = matrix
                    .admitting(state, false)
                    .into_iter()
                    .filter(|(class, _)| {
                        posted(class)
                            && *class != "Resolution"
                            && matrix.note(class, state) != Some("case")
                    })
                    .map(|(class, decision)| match decision {
                        Decision::With { op, approvals: 0 } => format!("{class} (with `{op}`)"),
                        Decision::With { op, approvals: 1 } => {
                            format!("{class} (with `{op}` and 1 approval)")
                        }
                        Decision::With { op, approvals } => {
                            format!("{class} (with `{op}` and {approvals} approvals)")
                        }
                        Decision::Admit | Decision::Refuse => class.to_string(),
                    })
                    .collect();
                let releases: Vec<String> = matrix
                    .admitting(state, true)
                    .into_iter()
                    .filter(|(class, _)| posted(class))
                    .map(|(class, _)| format!("{class} releases"))
                    .collect();
                let name = state.name();
                let mut fix = format!(
                    "keep the entry's true effective date; never re-date it to escape the period law: {}",
                    match (postings.is_empty(), releases.is_empty()) {
                        (false, _) => format!("a {name} period admits {}", postings.join(", ")),
                        (true, false) => format!(
                            "a {name} period admits no posting class in this build, only {}",
                            releases.join(", ")
                        ),
                        (true, true) => format!("a {name} period admits no entry in this build"),
                    }
                );
                if is_reversal {
                    fix.push_str(
                        "; a Reversal may instead be dated in the next Open period (Appendix B Reverse)",
                    );
                }
                if matches!(
                    state,
                    fa_time::PeriodState::Closed | fa_time::PeriodState::Locked
                ) {
                    fix.push_str(&format!(
                        "; a reopen of a {name} period is case-bound and refused in this build"
                    ));
                }
                fix.push_str("; `fa period list --json` shows each period's state");
                fix
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
    };
    // 5''. Segregation of duties (plan §14.3, FA-INV-10 `sod`): every cited
    //      approval is a witnessed Approval binding this proposal under the
    //      current epoch, and sod_policy.toml judges the set — on `admit`
    //      cells too, so an attached approval is never ignored. Balancing
    //      effects are not resolved yet, so that path performs the complete
    //      approval check at step 8 instead. It must establish the final
    //      digest before observing any cited approval record.
    //      The count is max(matrix, rule).
    let sod_key = fa_policy::sod::posting_key(
        class_name,
        state,
        matches!(resolution, Some((_, Disposition::Posts { .. }))),
    );
    let preparer = fa_policy::Party {
        principal: proposal.principal_ref,
        profile: req.capability.profile(),
    };
    let balancing = proposal
        .extensions
        .iter()
        .any(|(tag, _)| *tag == fa_model::entry::BALANCING_EXTENSION);
    if !balancing
        && let Err(r) = policy::authorize_approvals(
            &txn,
            db,
            book,
            &req.approvals,
            &proposal.proposal_digest()?,
            epoch,
            &sod_key,
            matrix_approvals,
            preparer,
        )?
    {
        txn.abort();
        return Ok(Err(r));
    }

    // 5b. Evidence minimum (plan §9.2, FA-INV-05 `evidence-minimum`): every
    //     citation names a document this book holds under its exact
    //     commitment, read as a witness of this transaction, as is the
    //     Reviewed attestation of each self-sourced one and, where the class
    //     admits one, the preparer's ManualAssertion; the class's registered
    //     minimum holds. Nothing posts without a why.
    let evidence_policy =
        EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let evidence = match resolve_evidence(&txn, db, &evidence_policy, proposal)? {
        Ok(d) => d,
        Err(r) => {
            txn.abort();
            return Ok(Err(r));
        }
    };

    // The driver citation above is witnessed under the same transaction.
    // Zero shares omit journal legs, not account legality or dependencies.
    if let Some(basis) = &allocation
        && let Err(refusal) = crate::allocation::witness_targets(&txn, db, book, basis)?
    {
        txn.abort();
        return Ok(Err(refusal));
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
        // A caller-supplied vid that names some other vertex (an entry, a
        // period, a document) is the same lawful mistake as a missing one,
        // never a corrupt Account row (fa-l93 D9).
        if !row.labels.contains(&label::ACCOUNT) {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::UNKNOWN_ACCOUNT,
                exit::REFUSAL,
                format!("leg {i} names a vertex that is not an account of this book"),
                "plan §4.3",
                "fa chart list --json to find the account, or fa chart import to add it",
            )));
        }
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
        if book.units.get(leg.amount.unit).is_none() {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::UNIT_UNREGISTERED,
                exit::REFUSAL,
                format!(
                    "leg {i}: unit id {} is not registered in this book",
                    leg.amount.unit.0
                ),
                "plan §4.4 (amounts are mantissas at a registered unit version's scale)",
                "post in a unit registered in registries/units.toml (fa book info --json reports units_registered)",
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
    if migration_run.is_some() && accounts.iter().any(|a| a.limit.is_some()) {
        txn.abort();
        return Ok(Err(not_implemented("Migration into a limited account")));
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
                return Ok(Err(no_settle_target(i, s.target.vid)));
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
            let (target, _) = checked_entry(db, &row)?;
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
            let open_item_class =
                target.proposal.class.carries_open_items() && !target.proposal.legs.is_empty();
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
            // A migrated leg is open iff its run is Finalized and its chunk
            // counts (ruling 3733 C1); the run state is a point witness.
            if let Err(r) = migration::witness_open_item(&txn, db, s.target.vid, &target, i)? {
                txn.abort();
                return Ok(Err(r));
            }
            // Liveness is a lineage predicate (plan §8.2): a reversed entry
            // nets to zero, and a reversed reversal revives it; a chain of any
            // length is legal, so the walk is bounded only by a cycle check
            // (impossible for honest identities, corruption otherwise). Each
            // hop is a witnessed point read, so a concurrent reversal conflicts.
            let mut reversed = false;
            let mut current = s.target.vid;
            let mut seen: BTreeSet<VId> = BTreeSet::new();
            // Existence only: a label point read, never the reversal's row.
            while txn
                .vertex_has_label(db, reversal_vid(current), label::ENTRY)?
                .is_some()
            {
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
            let target_entity =
                entity::leg_entity(&spec, target_leg).or_else(|| match spec.entities.as_slice() {
                    [only] => Some(only.code.clone()),
                    _ => None,
                });
            let leg_entity = leg_entities.get(i).and_then(Option::as_deref);
            let other_dims_match = target_leg
                .dimension_set
                .iter()
                .filter(|(d, _)| *d != fa_model::LEGAL_ENTITY_DIMENSION)
                .eq(leg
                    .dimension_set
                    .iter()
                    .filter(|(d, _)| *d != fa_model::LEGAL_ENTITY_DIMENSION));
            if target_entity.as_deref() != leg_entity || !other_dims_match {
                txn.abort();
                let applying_who = leg_entity.unwrap_or("(the book)");
                let target_who = target_entity.as_deref().unwrap_or("(the book)");
                return Ok(Err(Refusal::new(
                    code::SETTLE_SHAPE,
                    exit::REFUSAL,
                    format!(
                        "leg {i} (entity `{applying_who}`) does not settle entry {:032x} leg {} (entity `{target_who}`): an application must match the open item's legal entity and balancing dimensions",
                        s.target.vid.0, s.ordinal
                    ),
                    "plan §4.1, §5.2, §5.7 (per-entity open-item settlement)",
                    format!(
                        "apply an entry for entity `{target_who}` with matching balancing dimensions; cross-entity settlement requires an intercompany transfer first"
                    ),
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
            return Ok(Err(no_reversal_target(target.vid)));
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
        let (original, _) = checked_entry(db, &row)?;
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
            EntryClass::ORIGINAL
            | EntryClass::ADJUSTING
            | EntryClass::REVERSAL
            | EntryClass::ALLOCATION => true,
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
        let target_fy = book
            .calendar
            .fiscal_year_of(original.proposal.effective_date)?;
        let target_periods = book.calendar.periods_for_year(target_fy)?;
        let target_period = resolve_period(
            &target_periods,
            original.proposal.effective_date,
            original
                .proposal
                .effective_period
                .as_ref()
                .map(|p| p.code.as_str()),
        )
        .map_err(|error| {
            KernelError::Corrupt(format!(
                "reversal target {:032x} has no fiscal period: {error:?}",
                target.vid.0
            ))
        })?;
        // Civil dates alone cannot decide this: the normal year-end period
        // and its adjustment/closing periods share the same last day.
        if period.chronological_key() < target_period.chronological_key() {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::REVERSAL_PERIOD,
                exit::REFUSAL,
                format!(
                    "reversal period `{}` precedes target period `{}` in the fiscal calendar",
                    period.code, target_period.code
                ),
                "plan §8.1 (Reversal: same or later period)",
                format!(
                    "post the reversal in `{}` if its class is permitted there, or a later open Normal period",
                    target_period.code
                ),
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
        // 7c. Application effects (plan §5.7, §8.2): a target or any ancestor
        //     in its witnessed reversal chain with live applications against its
        //     legs is not reversed — the applying entries come first; the
        //     target's own applications are undone exactly as derived UNSETTLES
        //     effects, never re-entered. Reversing a reversal that undid
        //     applications would re-apply them; that waits for the full netting
        //     law.
        let mut anc_vid = target.vid;
        let mut anc_entry = original.clone();
        let mut seen_ancestors: BTreeSet<VId> = BTreeSet::new();
        loop {
            if !seen_ancestors.insert(anc_vid) {
                return Err(KernelError::Corrupt(format!(
                    "reversal ancestry of {:032x} cycles",
                    target.vid.0
                )));
            }
            for i in 0..anc_entry.proposal.legs.len() {
                let ordinal = u16::try_from(i)
                    .map_err(|_| KernelError::Corrupt("more than u16 legs".into()))?;
                let lvid = leg_vid(anc_vid, ordinal);
                let row = txn.vertex(db, lvid)?.ok_or_else(|| {
                    KernelError::Corrupt("reversal target leg row missing".into())
                })?;
                let live = applied_witness(&row)?;
                if live != 0 {
                    txn.abort();
                    return Ok(Err(Refusal::new(
                        code::LIVE_APPLICATIONS,
                        exit::REFUSAL,
                        format!(
                            "leg {i} of entry {:032x} has {live} applied against it",
                            anc_vid.0
                        ),
                        "plan §5.7 (reversing an open item with live applications would strand them)",
                        "reverse the applying entries first (fa open-items --account <code> lists them), then reverse this entry",
                    )));
                }
            }
            if anc_entry.proposal.class == EntryClass::REVERSAL
                && let [first] = anc_entry.proposal.supersession.as_slice()
            {
                let next_vid = first.target.vid;
                let Some(grand) = txn.vertex(db, next_vid)? else {
                    break;
                };
                let (grand, _) = checked_entry(db, &grand)?;
                if grand.proposal.legs.iter().any(|l| !l.settles.is_empty()) {
                    txn.abort();
                    return Ok(Err(not_implemented(
                        "re-application by reversing a reversal",
                    )));
                }
                anc_vid = next_vid;
                anc_entry = grand;
            } else {
                break;
            }
        }
        let mut undone: BTreeSet<VId> = BTreeSet::new();
        for (i, oleg) in original.proposal.legs.iter().enumerate() {
            let ordinal =
                u16::try_from(i).map_err(|_| KernelError::Corrupt("more than u16 legs".into()))?;
            for s in &oleg.settles {
                // Each entry the undo touches is bound to its mirrors first.
                if undone.insert(s.target.vid) {
                    let row = txn.vertex(db, s.target.vid)?.ok_or_else(|| {
                        KernelError::Corrupt("an applied-to entry is missing".into())
                    })?;
                    checked_entry(db, &row)?;
                }
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
    let mut hold: Option<EntryPayload> = None;
    let mut hold_seq: Option<CommitSeq> = None;
    if let Some((target, disposition)) = &resolution {
        let Some(row) = txn.vertex(db, target.vid)? else {
            txn.abort();
            return Ok(Err(no_resolution_target(target.vid)));
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
        let (pending_entry, _) = checked_entry(db, &row)?;
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
        hold = Some(pending_entry.proposal.clone());
        hold_seq = Some(row.created_at);
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

    // 7e. Timing (plan §5.4, §7.1a). A timed hold anchors on the latest
    //     committed tick, read here as a point witness: a tick that commits
    //     first is a first-committer-wins conflict, so the anchor is the
    //     latest tick of the strictly preceding prefix. A Posts resolution is
    //     admissible only while no committed tick has reached its hold's
    //     deadline — a tick committed after this witness conflicts, and the
    //     re-plan refuses. Voids keeps the identity race with the sweep.
    let posts_timed = match (&resolution, &hold, hold_seq) {
        (Some((_, Disposition::Posts { .. })), Some(h), Some(seq)) => match &h.pending {
            Some(Pending {
                timeout_ns: Some(t),
                ..
            }) => Some((seq, *t)),
            _ => None,
        },
        _ => None,
    };
    if timeout.is_some() || posts_timed.is_some() {
        let (_, latest) = sweep::tick_witness(&txn, db)?;
        let corroborated = sweep::latest_corroborated_tick(db, None)?;
        if let Some(t) = timeout {
            let Some(anchor) = corroborated.or(latest) else {
                txn.abort();
                return Ok(Err(Refusal::new(
                    code::TICK_MISSING,
                    exit::REFUSAL,
                    "a timed Pending anchors on a committed TimeEvidence tick, and this book has none",
                    "plan §5.4 (anchor = the latest tick in a strictly preceding committed prefix)",
                    "journal a tick first (the daemon's time evidence), then post the hold; or post it without timeout_ns",
                )));
            };
            if anchor.observed_utc_ns.checked_add(t).is_none() {
                txn.abort();
                return Ok(Err(Refusal::new(
                    code::DEADLINE_OVERFLOW,
                    exit::REFUSAL,
                    format!(
                        "the deadline {} ns + {t} ns leaves u64",
                        anchor.observed_utc_ns
                    ),
                    "plan §5.4 (deadline = anchor + timeout_ns, checked)",
                    format!(
                        "use a timeout_ns of at most {} ns",
                        u64::MAX - anchor.observed_utc_ns
                    ),
                )));
            }
        }
        if let Some((seq, t)) = posts_timed {
            let deadline = sweep::deadline(db, seq, t)?;
            if let Some(now) = corroborated
                && now.observed_utc_ns >= deadline
            {
                txn.abort();
                let target = resolution.as_ref().map_or(0, |(r, _)| r.vid.0);
                return Ok(Err(Refusal::new(
                    code::HOLD_DUE,
                    exit::REFUSAL,
                    format!(
                        "pending entry {target:032x} is due: tick {} ns has reached its deadline {deadline} ns",
                        now.observed_utc_ns
                    ),
                    "plan §5.4 (a manual Posts is admissible only while no committed tick has observed_utc_ns ≥ deadline)",
                    "release it with Resolution(Voids) or let the expiry sweep expire it, then post the amount as a new entry",
                )));
            }
        }
    }

    // 7d. Reserved availability, budget caps, and balancing (plan §5.4–5.5,
    //     interim R-ESC): `limit::judge` reads every limit cell the entry
    //     moves through this transaction (point witnesses, bound to their
    //     account and period), resolves a balancing request's legs from its
    //     leg's cell, and applies the law; the moves are staged as
    //     compare-and-sets on each cell's generation (step 8).
    let judged = match limit::judge(
        &txn,
        db,
        book,
        &accounts,
        proposal,
        &period.code,
        hold.as_ref(),
    )? {
        Ok(judged) => judged,
        Err(refusal) => {
            txn.abort();
            return Ok(Err(refusal));
        }
    };

    // 8. Seal and stage: Entry + Legs + edges, one commit.
    // A balancing request records the legs that moved (step 7d).
    let mut sealed = req.proposal.clone();
    if let Some(legs) = &judged.resolved_legs {
        sealed.legs.clone_from(legs);
        sealed.unit_totals = EntryPayload::fold_unit_totals(&sealed.legs)
            .map_err(|e| KernelError::Corrupt(format!("balancing unit totals: {e:?}")))?;
        let resolved_digest = sealed.proposal_digest()?;
        if let Err(refusal) = policy::authorize_approvals(
            &txn,
            db,
            book,
            &req.approvals,
            &resolved_digest,
            epoch,
            &sod_key,
            matrix_approvals,
            preparer,
        )? {
            txn.abort();
            return Ok(Err(refusal));
        }
    }
    let entry: Entry = sealed.seal(req.approvals.clone(), req.plan_certificate)?;
    let mut has_leg = WriteBatch::new(relation::HAS_LEG);
    let mut in_period = WriteBatch::new(relation::IN_PERIOD);
    has_leg.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    let leg_edges = crate::projections::stage_legs(&mut has_leg, evid, &entry, book)?;
    in_period.add_edge(edge_id(relation::IN_PERIOD, evid, pvid), evid, pvid, vec![]);
    for m in &judged.moves {
        m.before.stage(&m.after, m.cell, &mut has_leg)?;
    }
    // 8'. Scheduled reversals (plan §7.6): an entry that requests one gets
    //     its schedule in this commit; a manual Reversal of a scheduled
    //     target takes the reversal identity first and journals the
    //     schedule's cancellation here, so the schedule never fires.
    if let Some((reverse_on, reverse_period)) = &scheduled {
        schedule::stage_schedule(
            &mut has_leg,
            entry.entry_ref(evid),
            *reverse_on,
            reverse_period,
        )?;
    }
    let mut cancelled_schedule = None;
    if let Some(target) = reversal_target {
        match schedule::cancellation(
            &txn,
            db,
            book,
            &mut has_leg,
            target.vid,
            &entry.proposal,
            evid,
            preparer,
            epoch,
        )? {
            Ok(c) => cancelled_schedule = c,
            Err(r) => {
                txn.abort();
                return Ok(Err(r));
            }
        }
    }
    let mut batches = vec![has_leg, in_period];
    batches.extend(leg_edges);
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
    batches.extend(evidence_edges(evid, &evidence));
    batches.retain(|b| !b.is_empty());
    txn.write_ordered(db, batches)?;

    let mut effect_hasher = fgdb_crypto::Hasher::new();
    effect_hasher.update(b"fa:post-effects:v1");
    effect_hasher.update(&book.book_id.0);
    effect_hasher.update(&evid.0.to_le_bytes());
    effect_hasher.update(&pvid.0.to_le_bytes());
    let entry_bytes = entry.encode()?;
    effect_hasher.update(&(entry_bytes.len() as u64).to_le_bytes());
    effect_hasher.update(&entry_bytes);
    effect_hasher.update(&(judged.moves.len() as u64).to_le_bytes());
    for m in &judged.moves {
        effect_hasher.update(&m.cell.0.to_le_bytes());
        effect_hasher.update(&m.before.debits_posted.to_le_bytes());
        effect_hasher.update(&m.before.credits_posted.to_le_bytes());
        effect_hasher.update(&m.before.debits_pending.to_le_bytes());
        effect_hasher.update(&m.before.credits_pending.to_le_bytes());
        effect_hasher.update(&m.before.generation.to_le_bytes());
        effect_hasher.update(&m.after.debits_posted.to_le_bytes());
        effect_hasher.update(&m.after.credits_posted.to_le_bytes());
        effect_hasher.update(&m.after.debits_pending.to_le_bytes());
        effect_hasher.update(&m.after.credits_pending.to_le_bytes());
        effect_hasher.update(&m.after.generation.to_le_bytes());
    }
    match &scheduled {
        Some((reverse_on, reverse_period)) => {
            effect_hasher.update(&[1]);
            effect_hasher.update(&reverse_on.0.to_le_bytes());
            effect_hasher.update(&(reverse_period.len() as u64).to_le_bytes());
            effect_hasher.update(reverse_period.as_bytes());
        }
        None => {
            effect_hasher.update(&[0]);
        }
    }
    match cancelled_schedule {
        Some(cvid) => {
            effect_hasher.update(&[1]);
            effect_hasher.update(&cvid.0.to_le_bytes());
        }
        None => {
            effect_hasher.update(&[0]);
        }
    }
    match reversal_target {
        Some(target) => {
            effect_hasher.update(&[1]);
            effect_hasher.update(&target.vid.0.to_le_bytes());
            effect_hasher.update(&target.entry_digest);
        }
        None => {
            effect_hasher.update(&[0]);
        }
    }
    match &resolution {
        Some((target, disposition)) => {
            let tag = match disposition {
                Disposition::Posts { .. } => 0_u8,
                Disposition::Voids => 1_u8,
                Disposition::Expires { .. } => 2_u8,
            };
            effect_hasher.update(&[1, tag]);
            effect_hasher.update(&target.vid.0.to_le_bytes());
            effect_hasher.update(&target.entry_digest);
        }
        None => {
            effect_hasher.update(&[0]);
        }
    }
    effect_hasher.update(&(applications.len() as u64).to_le_bytes());
    for (ordinal, target_leg, amount) in &applications {
        effect_hasher.update(&ordinal.to_le_bytes());
        effect_hasher.update(&target_leg.0.to_le_bytes());
        effect_hasher.update(&amount.to_le_bytes());
    }
    effect_hasher.update(&(undo.len() as u64).to_le_bytes());
    for (ordinal, target_leg, amount) in &undo {
        effect_hasher.update(&ordinal.to_le_bytes());
        effect_hasher.update(&target_leg.0.to_le_bytes());
        effect_hasher.update(&amount.to_le_bytes());
    }
    effect_hasher.update(&(applied_delta.len() as u64).to_le_bytes());
    for (target_leg, (witnessed, delta)) in &applied_delta {
        effect_hasher.update(&target_leg.0.to_le_bytes());
        effect_hasher.update(&witnessed.to_le_bytes());
        effect_hasher.update(&delta.to_le_bytes());
    }
    effect_hasher.update(&(evidence.documents.len() as u64).to_le_bytes());
    for doc_vid in &evidence.documents {
        effect_hasher.update(&doc_vid.0.to_le_bytes());
    }
    match evidence.manual_assertion {
        Some(avid) => {
            effect_hasher.update(&[1]);
            effect_hasher.update(&avid.0.to_le_bytes());
        }
        None => {
            effect_hasher.update(&[0]);
        }
    }
    let effects_digest = effect_hasher.finalize().0;

    Ok(Ok(PostPreparation::Ready(Box::new(PreparedPost {
        txn,
        request: req,
        entry_ref: entry.entry_ref(evid),
        entry,
        period: period.code,
        security_policy_epoch: epoch,
        effects_digest,
        identity,
        seal_key: book.seal_key.clone(),
    }))))
}

/// Read a committed entry back by its derived identity.
pub fn read_entry<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    vid: VId,
) -> Result<Option<(Entry, CommitSeq)>, KernelError> {
    db.vertex(vid)?.map(|row| entry_of(&row)).transpose()
}

/// Every committed entry in `book` that supersedes `vid`, in recorded order,
/// returned as [`fa_model::Supersession`] rows whose `target` names the
/// superseding entry (`evid`).
pub fn superseded_by<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    vid: VId,
) -> Result<Vec<fa_model::Supersession>, KernelError> {
    let mut rows = Vec::new();
    for evid in db.in_neighbours(vid, relation::SUPERSEDES)? {
        let Some((entry, seq)) = read_entry(db, evid)? else {
            continue;
        };
        if entry.proposal.book_id != book.book_id {
            continue;
        }
        for link in &entry.proposal.supersession {
            if link.target.vid == vid {
                rows.push((
                    seq,
                    evid,
                    fa_model::Supersession {
                        kind: link.kind,
                        target: entry.entry_ref(evid),
                        reason_code: link.reason_code,
                    },
                ));
            }
        }
    }
    rows.sort_by_key(|(seq, evid, link)| (*seq, *evid, link.kind as u8, link.reason_code));
    Ok(rows.into_iter().map(|(_, _, link)| link).collect())
}

/// [`read_entry`] through the snapshot at `seq`: an entry recorded after
/// `seq` does not exist there, so its payload is never loaded or decoded
/// (a `known_at`-pinned read observes nothing past its pin).
pub fn read_entry_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    vid: VId,
    seq: CommitSeq,
) -> Result<Option<(Entry, CommitSeq)>, KernelError> {
    db.vertex_at(vid, seq)?
        .map(|row| entry_of(&row))
        .transpose()
}

/// Decode an entry row bound to its mirrors (CobaltGull 3610): the payload
/// must agree with the `_fa_effective_day` mirror on the row and, leg by
/// leg, with each leg vertex's `account_ref` mirror, with no mirror past
/// its last leg — exactly what a scope admission reads. Any disagreement is
/// corruption, raised before the payload drives an effect, for every
/// caller: the mirrors are what scoped tokens are admitted by.
fn checked_entry<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    row: &VertexRow,
) -> Result<(Entry, CommitSeq), KernelError> {
    let (entry, recorded_at) = entry_of(row)?;
    let drift = |what: String| {
        KernelError::Corrupt(format!(
            "entry {:032x}: {what} disagrees with its payload; its mirrors drifted",
            row.vid.0
        ))
    };
    match prop(row, property::FA_EFFECTIVE_DAY) {
        Some(CanonicalScalar::Int(d)) if *d == i64::from(entry.proposal.effective_date.0) => {}
        other => return Err(drift(format!("the _fa_effective_day mirror {other:?}"))),
    }
    let legs = &entry.proposal.legs;
    for k in 0..=legs.len() {
        let ordinal =
            u16::try_from(k).map_err(|_| KernelError::Corrupt("more than u16 legs".into()))?;
        let leg_row = db.vertex(leg_vid(row.vid, ordinal))?;
        let mirrored = leg_row
            .as_ref()
            .and_then(|r| prop(r, property::ACCOUNT_REF));
        match (legs.get(k), mirrored) {
            (Some(leg), Some(CanonicalScalar::Bytes(b)))
                if b.as_slice() == &leg.account_ref.0.to_le_bytes()[..] => {}
            (None, None) => {}
            (_, other) => return Err(drift(format!("leg {k}'s account_ref mirror {other:?}"))),
        }
    }
    Ok((entry, recorded_at))
}

/// Decode an entry row's payload, verifying its digests.
fn entry_of(row: &VertexRow) -> Result<(Entry, CommitSeq), KernelError> {
    let payload = match prop(row, property::FA_PAYLOAD) {
        Some(CanonicalScalar::Bytes(b)) => b.as_slice().to_vec(),
        other => {
            return Err(KernelError::Corrupt(format!(
                "entry _fa_payload: {other:?}"
            )));
        }
    };
    Ok((Entry::decode(&payload)?, row.created_at))
}
