//! Steward at the kernel boundary (plan §5.1 steps 1/5, §14, FA-INV-10).
//!
//! The kernel calls *down* into `fa-policy`, the laws layer, and supplies
//! only what the laws cannot observe themselves: the admission point (the
//! book head on the single-writer handle, read just before the transaction
//! opens), the book's **security policy epoch** read as a point witness
//! inside the transaction, and the approvals a transcript cites, each one a
//! point read. Every decision is fa-policy's; this module maps a
//! [`Denial`] onto the refusal envelope one-to-one.
//!
//! **Current-policy witness.** The epoch is the `security_policy_epoch`
//! property of the book root vertex (absent = 0, the policy this build
//! embeds). A post point-reads it exactly as it reads its period's `state`;
//! [`activate_policy`] moves it by compare-and-set. So a policy activation
//! that commits between a post's read and its commit makes the post a
//! first-committer-wins conflict, never a post admitted under superseded
//! policy; and an approval recorded under an earlier epoch is refused as
//! stale, never silently honoured.
//!
//! **Revocation is journaled.** [`revoke_capability`] commits a
//! PolicyControl entry carrying `ControlPayload::CapabilityEvent { Revoke }`
//! at an identity derived from the revoked capability's commitment, so the
//! kernel's [`capability_witness`] is one point read: present means revoked,
//! and an absent read is a witness a concurrent revocation invalidates.
//! Every Steward-checked write (post, transitions, approvals, activations,
//! revocations, ticks, sweeps, attestations, attached evidence) takes it
//! right after its transaction opens, before any other read; a write that
//! reads the head before its transaction also checks it there first
//! ([`capability_admitted`]).
//!
//! **Scope caveats are compiled, never filtered.** fa-policy judges what an
//! act reaches ([`fa_policy::reach`]); the kernel supplies only the
//! `accounts` caveat compiled for this book ([`account_scope`], read from
//! the caveat's own roots downward) and a period's dates from the calendar
//! ([`calendar_period`], no read). Acts on the whole book refuse a scoped
//! token; a post and a period transition name what they reach.
//!
//! **Approvals are objects.** [`record_approval`] writes an `Approval`
//! vertex (`fa:approval:v1`) whose identity derives from (book, approver,
//! approved proposal digest, epoch); a transcript's `ApprovalRef` must name
//! one, bind this proposal's digest, and pass SoD. A fabricated reference
//! is a refusal, not a count.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use fa_model::symbols::{label, property, relation};
use fa_model::{
    ApprovalRef, ControlPayload, Entry, EntryClass, EntryOrigin, EntryPayload, Erasable, Id128,
    Oid, account_vid, entry_mirrors, entry_vid,
};
use fa_policy::{
    AccountScope, Approval, Approver, Capability, CapabilityError, Denial, Intent, Op, Party,
    Reach, Steward,
};
use fa_registry::sod_policy::SodKey;
use fa_time::{DateDay, PeriodDef};
use fgdb::{Database, WriteBatch, WriteMismatchPolicy, WriteTxn, WriteTxnError};
use fgdb_crypto::Hasher;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{book_root, prop, scalar_bytes};

/// The kernel's refusal for a policy denial: code, exit, message, cite and
/// fix exactly as fa-policy decided them.
#[must_use]
pub fn refusal(d: &Denial) -> Refusal {
    Refusal::new(d.code(), d.exit(), d.message(), d.cite(), d.fix())
}

/// The embedded policy, parsed and cross-checked once per process.
pub fn steward() -> Result<&'static Steward, KernelError> {
    static STEWARD: OnceLock<Result<Steward, String>> = OnceLock::new();
    STEWARD
        .get_or_init(|| Steward::embedded().map_err(|e| e.to_string()))
        .as_ref()
        .map_err(|e| KernelError::Corrupt(format!("embedded policy: {e}")))
}

fn capability_error(e: CapabilityError) -> KernelError {
    match e {
        CapabilityError::Encode(e) => KernelError::Model(e.into()),
        CapabilityError::Decode(e) => KernelError::Model(e.into()),
        other => KernelError::Corrupt(format!("capability: {other}")),
    }
}

/// `vid(Approval) = H("fa:vid:approval:v1" ‖ book ‖ approver ‖ digest ‖ epoch)`:
/// one approval per approver per proposal per policy epoch, by identity.
#[must_use]
pub fn approval_vid(book: Id128, approver: VId, approved_digest: &[u8; 32], epoch: u64) -> VId {
    let mut h = Hasher::new();
    h.update(b"fa:vid:approval:v1");
    h.update(&book.0);
    h.update(&approver.0.to_le_bytes());
    h.update(approved_digest);
    h.update(&epoch.to_le_bytes());
    let d = h.finalize();
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d.0[..16]);
    VId(u128::from_le_bytes(lo))
}

fn epoch_from(scalar: Option<&CanonicalScalar>) -> Result<u64, KernelError> {
    match scalar {
        None => Ok(0),
        Some(CanonicalScalar::Int(n)) => u64::try_from(*n)
            .map_err(|_| KernelError::Corrupt(format!("security_policy_epoch {n} is negative"))),
        Some(other) => Err(KernelError::Corrupt(format!(
            "security_policy_epoch: expected Int, found {other:?}"
        ))),
    }
}

/// The security policy epoch as a point witness of `txn` (plan §14.2
/// `current-policy`): a concurrent activation invalidates the transaction.
pub fn epoch_witness<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
) -> Result<u64, KernelError> {
    let scalar = txn.vertex_property(db, book_root(), property::SECURITY_POLICY_EPOCH)?;
    epoch_from(scalar.as_ref())
}

/// The security policy epoch at the book head (outside a transaction).
pub fn security_policy_epoch<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
) -> Result<u64, KernelError> {
    let row = db
        .vertex(book_root())?
        .ok_or_else(|| KernelError::Corrupt("no book root".into()))?;
    epoch_from(prop(&row, property::SECURITY_POLICY_EPOCH))
}

/// Witness every cited approval inside `txn` and evaluate SoD for `key`.
/// Each `ApprovalRef` must bind `proposal_digest`, name a recorded approval
/// of this book whose identity matches its content, and have been recorded
/// under `epoch`; then the rule (or the default) decides. Runs on every
/// post, so an approval attached where none is required is still checked.
#[allow(clippy::too_many_arguments)]
pub fn authorize_approvals<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    approvals: &[ApprovalRef],
    proposal_digest: &[u8; 32],
    epoch: u64,
    key: &SodKey,
    matrix_approvals: u8,
    preparer: Party,
) -> Outcome<()> {
    authorize_approvals_in(
        txn,
        db,
        book,
        approvals,
        proposal_digest,
        epoch,
        key,
        matrix_approvals,
        preparer,
        None,
    )
}

/// [`authorize_approvals`] for work in a case: `case_preparers` are the
/// principals who prepared any entry in it, so a rule's `case_preparer`
/// exclusion is decided (`None` keeps it undecidable: fail closed).
#[allow(clippy::too_many_arguments)]
pub fn authorize_approvals_in<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    approvals: &[ApprovalRef],
    proposal_digest: &[u8; 32],
    epoch: u64,
    key: &SodKey,
    matrix_approvals: u8,
    preparer: Party,
    case_preparers: Option<&std::collections::BTreeSet<VId>>,
) -> Outcome<()> {
    let steward = steward()?;
    let mut witnessed: Vec<Approver> = Vec::with_capacity(approvals.len());
    for (index, cited) in approvals.iter().enumerate() {
        if &cited.approved_digest != proposal_digest {
            return Ok(Err(refusal(&Denial::ApprovalBinding { index })));
        }
        let unknown = Denial::UnknownApproval {
            index,
            approval: cited.approval_vid,
        };
        let Some(row) = txn.vertex(db, cited.approval_vid)? else {
            return Ok(Err(refusal(&unknown)));
        };
        if !row.labels.contains(&label::APPROVAL) {
            return Ok(Err(refusal(&unknown)));
        }
        let approval = match prop(&row, property::FA_PAYLOAD) {
            Some(CanonicalScalar::Bytes(b)) => {
                Approval::decode(b.as_slice()).map_err(|e| KernelError::Model(e.into()))?
            }
            other => {
                return Err(KernelError::Corrupt(format!(
                    "approval _fa_payload: {other:?}"
                )));
            }
        };
        let derived = approval_vid(
            approval.book_id,
            approval.principal,
            &approval.approved_proposal_digest,
            approval.security_policy_epoch,
        );
        if derived != cited.approval_vid {
            return Err(KernelError::Corrupt(format!(
                "approval {:032x} does not carry the identity its content derives",
                cited.approval_vid.0
            )));
        }
        if let Err(d) = approval.check_binding(
            index,
            &cited.approved_digest,
            proposal_digest,
            book.book_id,
            epoch,
        ) {
            return Ok(Err(refusal(&d)));
        }
        witnessed.push(Approver::from(&approval));
    }
    Ok(steward
        .segregate_in(key, matrix_approvals, preparer, &witnessed, case_preparers)
        .map_err(|d| refusal(&d)))
}

/// Record one approval over a proposal digest.
#[derive(Clone, Debug)]
pub struct ApprovalRequest {
    /// The approver's capability; it must hold `approve`.
    pub capability: Capability,
    /// The `proposal_digest` of the entry being approved.
    pub approved_proposal_digest: [u8; 32],
    pub role: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Approved {
    Recorded {
        approval: ApprovalRef,
        security_policy_epoch: u64,
        recorded_at: CommitSeq,
    },
    /// The identical approval already exists; nothing was written.
    AlreadyRecorded {
        approval: ApprovalRef,
        recorded_at: CommitSeq,
    },
}

impl Approved {
    #[must_use]
    pub fn approval(&self) -> ApprovalRef {
        match self {
            Self::Recorded { approval, .. } | Self::AlreadyRecorded { approval, .. } => *approval,
        }
    }

    #[must_use]
    pub fn recorded_at(&self) -> CommitSeq {
        match self {
            Self::Recorded { recorded_at, .. } | Self::AlreadyRecorded { recorded_at, .. } => {
                *recorded_at
            }
        }
    }
}

/// Record an approval (plan Appendix A `Approval`): admitted from the
/// capability alone (it holds `approve`, which no Agent or System profile
/// can), current at the admission point, bound to the epoch witnessed in
/// the same transaction. One commit on success.
pub async fn record_approval<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    req: ApprovalRequest,
) -> Outcome<Approved> {
    // An approval binds an opaque proposal digest, so it reaches the whole
    // book: a scoped token cannot judge what it approves and is refused.
    if let Err(d) = fa_policy::require(&req.capability, Op::Approve, "recording an approval")
        .and_then(|()| fa_policy::scope(&req.capability, book.book_id))
        .and_then(|()| fa_policy::reach(&req.capability, &Reach::whole_book(true), None))
    {
        return Ok(Err(refusal(&d)));
    }
    let at = db.frontier()?;
    if let Err(d) = fa_policy::current(&req.capability, at) {
        return Ok(Err(refusal(&d)));
    }
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let epoch = epoch_witness(&txn, db)?;
    let approval = match Approval::by(
        &req.capability,
        Op::Approve,
        book.book_id,
        req.approved_proposal_digest,
        epoch,
        req.role,
    )
    .map_err(capability_error)?
    {
        Ok(a) => a,
        Err(d) => {
            txn.abort();
            return Ok(Err(refusal(&d)));
        }
    };
    let bytes = approval
        .canonical_bytes()
        .map_err(|e| KernelError::Model(e.into()))?;
    let digest = approval
        .digest()
        .map_err(|e| KernelError::Model(e.into()))?;
    let vid = approval_vid(
        book.book_id,
        approval.principal,
        &approval.approved_proposal_digest,
        epoch,
    );
    let handle = ApprovalRef {
        approval_vid: vid,
        approved_digest: approval.approved_proposal_digest,
    };
    if let Some(row) = txn.vertex(db, vid)? {
        txn.abort();
        return Ok(match prop(&row, property::FA_PAYLOAD) {
            Some(CanonicalScalar::Bytes(b)) if b.as_slice() == bytes.as_slice() => {
                Ok(Approved::AlreadyRecorded {
                    approval: handle,
                    recorded_at: row.created_at,
                })
            }
            _ => Err(Refusal::new(
                code::IDEMPOTENCY_CONFLICT,
                exit::CONFLICT,
                format!(
                    "approval {:032x} already exists for this approver, proposal and epoch with different content",
                    vid.0
                ),
                "plan Appendix A Approval (one per approver, proposal and policy epoch)",
                "cite the existing approval; re-approving under a different capability or role needs a new policy epoch",
            )),
        });
    }
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("approval.payload", bytes)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("approval.digest", digest.to_vec())?,
        ),
    ];
    props.sort_by_key(|(k, _)| k.0);
    batch.create_vertex(vid, vec![label::APPROVAL], props);
    txn.write(db, batch)?;
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(Approved::Recorded {
            approval: handle,
            security_policy_epoch: epoch,
            recorded_at: seq,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("a concurrent commit invalidated this approval's witness: {detail}"),
                "FG-LAW-FCW-01 (first committer wins)",
                "the security policy moved; approve again under the current epoch",
            )))
        }
        Err(e) => Err(e.into()),
    }
}

/// The one `effective_to` this subset accepts. The security policy is
/// selected by known-at (the epoch a commit witnesses), not by effective
/// date: an activation governs every commit after it, whatever date the
/// entry carries. A bounded interval would claim a date scoping the kernel
/// does not enforce, so it is refused rather than recorded and ignored.
pub const OPEN_END: DateDay = DateDay(i32::MAX);

/// The `PolicyControl` proposal that activates `policy_oid` from
/// `effective_from` onward, `[effective_from, OPEN_END)`, the one interval
/// this subset accepts. Approvers approve its `proposal_digest()` before
/// [`activate_policy`] commits it.
#[must_use]
pub fn activation_proposal(
    book: &BookContext,
    principal: VId,
    policy_oid: [u8; 32],
    effective_from: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
) -> EntryPayload {
    EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::POLICY_CONTROL,
        effective_date: effective_from,
        document_date: None,
        description,
        effective_period: None,
        legs: Vec::new(),
        control: Some(ControlPayload::PolicyActivation {
            policy_oid: Oid(policy_oid),
            effective_from,
            effective_to: OPEN_END,
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: idempotency_key.to_vec(),
        origin: EntryOrigin::Control {
            control_kind: fa_model::ControlKind::POLICY_ACTIVATION,
            spec_body_digest: policy_oid,
        },
        principal_ref: principal,
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    }
}

#[derive(Clone, Debug)]
pub struct ActivationRequest {
    pub proposal: EntryPayload,
    pub capability: Capability,
    pub approvals: Vec<ApprovalRef>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyActivated {
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub recorded_at: CommitSeq,
    pub control_entry: VId,
    /// The same activation was already recorded (FA-INV-09): this is that
    /// outcome, nothing was written, and its approvals were not re-judged
    /// (they were judged at its own commit, under the epoch it then moved).
    pub already_recorded: bool,
}

/// The recorded outcome of the activation at `row`: its epochs are read
/// from the book root as of the activation's own commit, which is the
/// commit that moved the epoch to `to_epoch`.
fn recorded_activation<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    row: &fgdb::VertexRow,
) -> Result<PolicyActivated, KernelError> {
    let root = db
        .vertex_at(book_root(), row.created_at)?
        .ok_or_else(|| KernelError::Corrupt("no book root at the activation's commit".into()))?;
    let to_epoch = epoch_from(prop(&root, property::SECURITY_POLICY_EPOCH))?;
    let from_epoch = to_epoch.checked_sub(1).ok_or_else(|| {
        KernelError::Corrupt(format!(
            "activation {:032x} is recorded but the epoch at its commit is 0",
            row.vid.0
        ))
    })?;
    Ok(PolicyActivated {
        from_epoch,
        to_epoch,
        recorded_at: row.created_at,
        control_entry: row.vid,
        already_recorded: true,
    })
}

/// An existing row at the activation's identity (plan §4.9, FA-INV-09):
/// the recorded outcome when the proposal is the same — byte for byte, or
/// semantically equal under the book key (an erasable description re-sealed
/// with fresh salt is the same request) — and a conflict otherwise.
fn recorded_or_conflict<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    row: &fgdb::VertexRow,
    proposal: &EntryPayload,
    proposal_digest: &[u8; 32],
) -> Outcome<PolicyActivated> {
    let stored = match prop(row, property::FA_PAYLOAD) {
        Some(CanonicalScalar::Bytes(b)) => Entry::decode(b.as_slice())?,
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
            "resubmit the identical activation to get the recorded outcome, or use a new idempotency key",
        )
    };
    if stored.proposal.class != EntryClass::POLICY_CONTROL {
        return Ok(Err(conflict()));
    }
    if &stored.proposal_digest == proposal_digest {
        return recorded_activation(db, row).map(Ok);
    }
    match (
        stored.proposal.semantic_digest(&book.seal_key),
        proposal.semantic_digest(&book.seal_key),
    ) {
        (Ok(a), Ok(b)) if a == b => recorded_activation(db, row).map(Ok),
        (Ok(_), Ok(_)) => Ok(Err(conflict())),
        (Err(fa_model::EntryError::Sealed(_)), _) | (_, Err(fa_model::EntryError::Sealed(_))) => {
            Ok(Err(Refusal::new(
                code::EQUIVALENCE_UNVERIFIABLE,
                exit::CONFLICT,
                format!(
                    "an activation with this identity exists ({:032x}) but a sealed field cannot be opened, so equivalence cannot be verified",
                    row.vid.0
                ),
                "plan §8.5 (no plaintext equivalence over destroyed secrets)",
                "resubmit the exact prepared bytes to get the recorded outcome, or use a new idempotency key",
            )))
        }
        (Err(e), _) | (_, Err(e)) => Err(e.into()),
    }
}

/// Activate a security policy: one commit journaling the `PolicyControl`
/// entry (legs = [], `ControlPayload::PolicyActivation`) and moving the
/// book's `security_policy_epoch` by compare-and-set from the value this
/// transaction witnessed. Refused before any read: a malformed proposal, an
/// interval other than `[effective_date, OPEN_END)`, a policy digest this
/// build does not enforce, a capability that is not the preparer's,
/// lacks `rule_change`, or has expired. Then the identity: the same
/// activation again is its recorded outcome. Then authority at commit: the
/// `policy-activate` SoD row (two Human approvers who are not the preparer,
/// recorded under the current epoch).
pub async fn activate_policy<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    req: ActivationRequest,
) -> Outcome<PolicyActivated> {
    let proposal = &req.proposal;
    let activation = match (&proposal.control, proposal.validate()) {
        (
            Some(ControlPayload::PolicyActivation {
                policy_oid,
                effective_from,
                effective_to,
            }),
            Ok(()),
        ) if proposal.class == EntryClass::POLICY_CONTROL => {
            Some((policy_oid.0, *effective_from, *effective_to))
        }
        _ => None,
    };
    let Some((policy_oid, effective_from, effective_to)) = activation else {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "a policy activation is a valid PolicyControl entry carrying a PolicyActivation payload",
            "Appendix A ControlPayload::PolicyActivation",
            "build the proposal with fa_journal::activation_proposal",
        )));
    };
    if proposal.base_totals.is_some() {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "a policy activation carries base_totals but has no legs to value",
            "plan §5.2 (functional-currency valuations belong to monetary legs)",
            "remove base_totals; build the control with fa_journal::activation_proposal",
        )));
    }
    if effective_from != proposal.effective_date || effective_to != OPEN_END {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "this slice activates a policy from its own effective date onward: effective_from must equal effective_date ({}) and effective_to must be OPEN_END",
                proposal.effective_date.render()
            ),
            "plan §14.2 (policy is selected by known-at, the security_policy_epoch a commit witnesses, not by effective date)",
            "build the proposal with fa_journal::activation_proposal; date-scoped policy versions land with loaded, versioned policies",
        )));
    }
    if proposal.book_id != book.book_id || proposal.branch_id != Id128::TRUNK {
        return Ok(Err(Refusal::new(
            code::COORDINATE,
            exit::USAGE,
            "the activation names another book or a branch",
            "plan §2.2",
            "activate on this book's trunk",
        )));
    }
    // Admission before any read: the policy is the one this build enforces,
    // and the capability is the preparer's, current, and holds the SoD
    // row's preparer op.
    let steward = steward()?;
    if let Err(d) = steward.check_activation(&policy_oid) {
        return Ok(Err(refusal(&d)));
    }
    let key = fa_policy::sod::control_key("PolicyControl", None, "Activate");
    let Some(op) = steward.preparer_op(&key) else {
        return Err(KernelError::Corrupt(
            "sod_policy.toml has no policy-activate rule".into(),
        ));
    };
    if let Err(d) = fa_policy::admit(
        &req.capability,
        &Intent {
            principal: proposal.principal_ref,
            trunk: true,
            op,
            book: book.book_id,
            legs: &[],
        },
    ) {
        return Ok(Err(refusal(&d)));
    }
    let at = db.frontier()?;
    if let Err(d) = fa_policy::current(&req.capability, at) {
        return Ok(Err(refusal(&d)));
    }
    let proposal_digest = proposal.proposal_digest()?;
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let evid = entry_vid(
        book.book_id,
        &proposal.principal_ref.0.to_le_bytes(),
        &proposal.idempotency_key,
    );
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return recorded_or_conflict(db, book, &row, proposal, &proposal_digest);
    }
    // The witnessed scalar is the compare-and-set's expectation (absent on
    // a book that never activated a policy).
    let witnessed = txn.vertex_property(db, book_root(), property::SECURITY_POLICY_EPOCH)?;
    let epoch = epoch_from(witnessed.as_ref())?;
    let preparer = Party::for_capability(proposal.principal_ref, &req.capability);
    if let Err(r) = authorize_approvals(
        &txn,
        db,
        book,
        &req.approvals,
        &proposal_digest,
        epoch,
        &key,
        0,
        preparer,
    )? {
        txn.abort();
        return Ok(Err(r));
    }
    let next_epoch = epoch
        .checked_add(1)
        .ok_or_else(|| KernelError::Corrupt("security_policy_epoch overflow".into()))?;
    let next = i64::try_from(next_epoch)
        .map(CanonicalScalar::Int)
        .map_err(|_| KernelError::Corrupt("security_policy_epoch exceeds i64".into()))?;
    let entry = proposal.clone().seal(req.approvals.clone(), None)?;
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    batch.compare_and_set_vertex_property(
        book_root(),
        property::SECURITY_POLICY_EPOCH,
        witnessed,
        next,
        WriteMismatchPolicy::AbortWrite,
    );
    txn.write(db, batch)?;
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(PolicyActivated {
            from_epoch: epoch,
            to_epoch: next_epoch,
            recorded_at: seq,
            control_entry: evid,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("a concurrent commit invalidated this activation's witness: {detail}"),
                "FG-LAW-FCW-01 (first committer wins)",
                "re-read the policy epoch, re-approve under it, and retry",
            )))
        }
        Err(WriteTxnError::Write(fgdb::WriteError::CompareAndSetMismatch(_))) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                "the security policy epoch moved under this activation",
                "plan §14.2 (policy changes are serialized through the epoch)",
                "re-read the policy epoch, re-approve under it, and retry",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => match db.vertex(evid)? {
            // Lost the identity race: the recorded outcome if it is the same
            // activation, a conflict if it is not.
            Some(row) => recorded_or_conflict(db, book, &row, proposal, &proposal_digest),
            None => Err(KernelError::Corrupt(
                "identity spent but no live row".into(),
            )),
        },
        Err(e) => Err(e.into()),
    }
}

/// `vid(revocation of C) = H("fa:vid:capability-revocation:v1" ‖ book ‖
/// commitment(C))`: one revocation per capability by identity, found by a
/// point read.
#[must_use]
pub fn revocation_vid(book: Id128, commitment: &[u8; 32]) -> VId {
    let mut h = Hasher::new();
    h.update(b"fa:vid:capability-revocation:v1");
    h.update(&book.0);
    h.update(commitment);
    let d = h.finalize();
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d.0[..16]);
    VId(u128::from_le_bytes(lo))
}

const MAX_ISSUANCE_LINEAGE: usize = 16;

/// The capability is not revoked, as a point witness of `txn` (plan §14.2:
/// authority is evaluated against current policy at commit). A revocation
/// committed after this read makes the transaction a first-committer-wins
/// conflict.
pub fn capability_witness<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
) -> Outcome<()> {
    let commitment = capability.commitment().map_err(capability_error)?;
    let mut parent_issuer = None;
    if capability.possession().is_some() || !capability.daily_totals().is_empty() {
        let issued = txn.vertex(db, issuance_vid(book.book_id, &commitment))?;
        match issued_here(issued.as_ref(), &commitment) {
            Ok(parent) => parent_issuer = parent,
            Err(r) => return Ok(Err(r)),
        }
    }
    if let Err(r) = not_revoked(txn.vertex(db, revocation_vid(book.book_id, &commitment))?) {
        return Ok(Err(r));
    }
    let mut seen = BTreeSet::from([commitment]);
    let mut cur_parent = parent_issuer;
    for _ in 0..MAX_ISSUANCE_LINEAGE {
        let Some(parent) = cur_parent else {
            break;
        };
        if !seen.insert(parent) {
            break;
        }
        if let Err(r) = not_revoked(txn.vertex(db, revocation_vid(book.book_id, &parent))?) {
            return Ok(Err(r));
        }
        let Some(parent_row) = txn.vertex(db, issuance_vid(book.book_id, &parent))? else {
            break;
        };
        cur_parent = issued_here(Some(&parent_row), &parent).ok().flatten();
    }
    if !capability.daily_totals().is_empty() {
        let root = capability.daily_root().unwrap_or(commitment);
        let row = txn.vertex(db, issuance_vid(book.book_id, &root))?;
        if let Err(r) = daily_root_current(row.as_ref(), book, capability, &root, txn.basis())? {
            return Ok(Err(r));
        }
        if let Err(r) = not_revoked(txn.vertex(db, revocation_vid(book.book_id, &root))?) {
            return Ok(Err(r));
        }
    }
    Ok(Ok(()))
}

/// The capability is not revoked at the admission point (the head this
/// single-writer handle opens its transaction on), for a write that reads
/// the head before its transaction does (the sweeps' candidate scans): a
/// revoked token is refused before it observes anything, not even whether
/// work is due. The write still takes [`capability_witness`] inside its
/// transaction, the read a concurrent revocation invalidates.
pub fn capability_admitted<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
) -> Outcome<()> {
    let commitment = capability.commitment().map_err(capability_error)?;
    let mut parent_issuer = None;
    if capability.possession().is_some() || !capability.daily_totals().is_empty() {
        let issued = db.vertex(issuance_vid(book.book_id, &commitment))?;
        match issued_here(issued.as_ref(), &commitment) {
            Ok(parent) => parent_issuer = parent,
            Err(r) => return Ok(Err(r)),
        }
    }
    if let Err(r) = not_revoked(db.vertex(revocation_vid(book.book_id, &commitment))?) {
        return Ok(Err(r));
    }
    let mut seen = BTreeSet::from([commitment]);
    let mut cur_parent = parent_issuer;
    for _ in 0..MAX_ISSUANCE_LINEAGE {
        let Some(parent) = cur_parent else {
            break;
        };
        if !seen.insert(parent) {
            break;
        }
        if let Err(r) = not_revoked(db.vertex(revocation_vid(book.book_id, &parent))?) {
            return Ok(Err(r));
        }
        let Some(parent_row) = db.vertex(issuance_vid(book.book_id, &parent))? else {
            break;
        };
        cur_parent = issued_here(Some(&parent_row), &parent).ok().flatten();
    }
    if !capability.daily_totals().is_empty() {
        let root = capability.daily_root().unwrap_or(commitment);
        let row = db.vertex(issuance_vid(book.book_id, &root))?;
        if let Err(r) = daily_root_current(row.as_ref(), book, capability, &root, db.frontier()?)? {
            return Ok(Err(r));
        }
        if let Err(r) = not_revoked(db.vertex(revocation_vid(book.book_id, &root))?) {
            return Ok(Err(r));
        }
    }
    Ok(Ok(()))
}

/// A daily quota cannot acquire authority by naming another root, or keep
/// operating after that root expires. Revocation is point-witnessed by the
/// caller as well as the presented issuance's own revocation.
fn daily_root_current(
    row: Option<&fgdb::VertexRow>,
    book: &BookContext,
    capability: &Capability,
    root: &[u8; 32],
    at: CommitSeq,
) -> Outcome<()> {
    let Some(row) = row else {
        return Ok(Err(crate::usage::not_issued(
            "the daily spending root issuance is missing",
        )));
    };
    let (original, _) = crate::usage::issued_capability(row, book.book_id, root)?;
    if original.daily_root().is_some()
        || original.daily_totals().is_empty()
        || capability.daily_totals().iter().any(|(unit, max)| {
            original
                .daily_totals()
                .get(unit)
                .is_none_or(|bound| max > bound)
        })
    {
        return Ok(Err(crate::usage::mismatch(
            "daily spending lineage does not attenuate an original issued quota",
        )));
    }
    if let Err(denial) = fa_policy::current(&original, at) {
        return Ok(Err(refusal(&denial)));
    }
    Ok(Ok(()))
}

/// A capability that is current at the head: not expired at the admission
/// point and not revoked there. Only [`current_at`] makes one, and
/// [`account_scope`] requires it, so the chart is never read for a token
/// that is expired or revoked now (WhiteCreek 3559): such a token gets its
/// expiry or revocation refusal whichever accounts it names.
#[derive(Clone, Copy, Debug)]
pub struct Current<'c> {
    capability: &'c Capability,
    at: CommitSeq,
}

impl<'c> Current<'c> {
    #[must_use]
    pub fn capability(&self) -> &'c Capability {
        self.capability
    }

    /// The head the capability was found current at.
    #[must_use]
    pub fn at(&self) -> CommitSeq {
        self.at
    }
}

/// The capability is current at the head this single-writer handle
/// observes (plan §14.2): its declared expiry bound is above the head
/// (fa-policy), and no revocation names it there (one point read at the
/// token's own revocation identity, nothing else). A write still takes
/// [`capability_witness`] inside its transaction for first-committer-wins.
pub fn current_at<'c, V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &'c Capability,
) -> Outcome<Current<'c>> {
    let at = db.frontier()?;
    if let Err(d) = fa_policy::current(capability, at) {
        return Ok(Err(refusal(&d)));
    }
    if let Err(r) = capability_admitted(db, book, capability)? {
        return Ok(Err(r));
    }
    Ok(Ok(Current { capability, at }))
}

/// Compile the capability's `accounts` caveat for this book (plan §14.2):
/// each root code's account vid and its `CHILD_OF` descendants, walked from
/// the roots downward, so the compile reads only accounts inside the scope
/// and observes nothing the caveat does not already name. It takes a
/// [`Current`] proof: a token expired or revoked now never reaches the
/// chart. `None` when the capability carries no `accounts` caveat. A root
/// the chart lacks contributes only its own vid, which names no account, so
/// every act on a real account is refused under it.
pub fn account_scope<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    current: &Current<'_>,
) -> Result<Option<AccountScope>, KernelError> {
    let Some(roots) = current.capability.accounts() else {
        return Ok(None);
    };
    let mut members = BTreeSet::new();
    let mut pending: Vec<VId> = roots
        .iter()
        .map(|code| account_vid(book.book_id, code))
        .collect();
    while let Some(vid) = pending.pop() {
        if members.insert(vid) {
            pending.extend(db.in_neighbours(vid, relation::CHILD_OF)?);
        }
    }
    Ok(Some(AccountScope::compiled(members)))
}

/// The period `code` names in this book's calendar, computed from the
/// calendar alone (codes are `FY{year}-…`, plan §7.3), so a `periods` or
/// `effective` caveat is judged before the period row is read. `None` when
/// the code names no period of the calendar.
#[must_use]
pub fn calendar_period(book: &BookContext, code: &str) -> Option<PeriodDef> {
    let year = code
        .strip_prefix("FY")?
        .split('-')
        .next()?
        .parse::<i32>()
        .ok()?;
    book.calendar
        .periods_for_year(year)
        .ok()?
        .into_iter()
        .find(|p| p.code == code)
}

/// The period `day` resolves to in this book's calendar (with an explicit
/// `hint` for a date shared with a special period), from the calendar alone;
/// `None` when it resolves to no single period.
pub(crate) fn resolved_period(
    book: &BookContext,
    day: DateDay,
    hint: Option<&str>,
) -> Option<String> {
    let fy = book.calendar.fiscal_year_of(day).ok()?;
    let periods = book.calendar.periods_for_year(fy).ok()?;
    fa_time::resolve_period(&periods, day, hint)
        .ok()
        .map(|p| p.code.clone())
}

/// The scope caveats admit the effects a posting proposal's payload alone
/// determines (plan §14.2, CobaltGull 3570): its legs' accounts, the period
/// its date resolves to and that date, and, for an Adjusting with
/// `auto_reverse_on`, the scheduled reversal's period and date — the System
/// mints that reversal later under the scope admitted now. A date that
/// resolves to no single period reaches none here; the pipeline refuses it
/// before anything is written. The targets a commit releases, applies to or
/// undoes are judged inside its transaction by
/// [`entry_in_scope_by_metadata`].
pub fn payload_reach(
    capability: &Capability,
    book: &BookContext,
    proposal: &EntryPayload,
    accounts: Option<&AccountScope>,
) -> Result<(), Denial> {
    if !capability.admits_class(proposal.class) {
        return Err(Denial::OutOfScope {
            caveat: "classes",
            value: format!("class `{}`", proposal.class.name().unwrap_or("unknown")),
        });
    }
    let legs: Vec<VId> = proposal.legs.iter().map(|l| l.account_ref).collect();
    let mut periods: Vec<String> = resolved_period(
        book,
        proposal.effective_date,
        proposal.effective_period.as_ref().map(|p| p.code.as_str()),
    )
    .into_iter()
    .collect();
    let mut through = proposal.effective_date;
    if let Ok(Some((reverse_on, _))) = crate::schedule::auto_reverse(proposal) {
        periods.extend(resolved_period(book, reverse_on, None));
        through = through.max(reverse_on);
    }
    let codes: Vec<&str> = periods.iter().map(String::as_str).collect();
    fa_policy::reach(
        capability,
        &Reach {
            branch: Some(proposal.branch_id),
            observes: fa_policy::Observes::Head,
            periods: Some(&codes),
            through: Some(through),
            accounts: Some(&legs),
        },
        accounts,
    )
}

/// Whether the entry at `vid` lies wholly inside the capability's scope,
/// decided from its metadata alone (WhiteCreek 3575/3582): the ENTRY label,
/// the `_fa_effective_day` mirror and each leg vertex's `account_ref`
/// mirror, each a projection point read of `txn` that copies only the
/// selected label or scalar and is a witness of the transaction. The
/// payload is never loaded, so an entry outside the scope is never
/// decoded; a caller decodes only an entry this admits. `false` for an
/// absent vertex or one that is not an entry. The period is resolved from
/// the date alone: a date shared with a special period (which only the
/// payload's `effective_period` names) fails closed under a `periods`
/// caveat. The act's own branch and `known_at` were judged at admission.
pub fn entry_in_scope_by_metadata<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
    accounts: Option<&AccountScope>,
    vid: VId,
) -> Result<bool, KernelError> {
    if txn.vertex_has_label(db, vid, label::ENTRY)? != Some(true) {
        return Ok(false);
    }
    let day = match txn.vertex_property(db, vid, property::FA_EFFECTIVE_DAY)? {
        Some(CanonicalScalar::Int(d)) => DateDay(
            i32::try_from(d)
                .map_err(|_| KernelError::Corrupt(format!("entry _fa_effective_day {d}")))?,
        ),
        other => {
            return Err(KernelError::Corrupt(format!(
                "entry _fa_effective_day mirror: {other:?}"
            )));
        }
    };
    let mut legs: Vec<VId> = Vec::new();
    for ordinal in 0..=u16::MAX {
        let leg = crate::rows::leg_vid(vid, ordinal);
        match txn.vertex_property(db, leg, property::ACCOUNT_REF)? {
            None => break,
            Some(CanonicalScalar::Bytes(b)) => {
                let raw: [u8; 16] = b.as_slice().try_into().map_err(|_| {
                    KernelError::Corrupt(format!("leg {ordinal} account_ref mirror width"))
                })?;
                legs.push(VId(u128::from_le_bytes(raw)));
            }
            Some(other) => {
                return Err(KernelError::Corrupt(format!(
                    "leg {ordinal} account_ref mirror: {other:?}"
                )));
            }
        }
    }
    Ok(footprint_in_scope(capability, accounts, book, &legs, day))
}

/// The accounts, period and effective-date caveats admit an entry with
/// these legs on `day`, its period resolved from the date alone. Branch and
/// `known_at` are the act's own and were judged at its admission, so they
/// pass here.
fn footprint_in_scope(
    capability: &Capability,
    accounts: Option<&AccountScope>,
    book: &BookContext,
    legs: &[VId],
    day: DateDay,
) -> bool {
    if capability.accounts().is_some() && legs.is_empty() {
        return false;
    }
    // A date a special period shares with a normal one names no period
    // without the payload's `effective_period`, which no mirror carries yet
    // (CobaltGull 3618/3622): out of scope under a `periods` caveat.
    if capability.periods().is_some() && shared_date(book, day) {
        return false;
    }
    let period = resolved_period(book, day, None);
    if period.is_none() && capability.periods().is_some() {
        return false;
    }
    let codes: Vec<&str> = period.iter().map(String::as_str).collect();
    fa_policy::reach(
        capability,
        &Reach {
            branch: capability.branch().or(Some(Id128::TRUNK)),
            observes: capability
                .known_at_pin()
                .map_or(fa_policy::Observes::Head, fa_policy::Observes::At),
            periods: Some(&codes),
            through: Some(day),
            accounts: Some(legs),
        },
        accounts,
    )
    .is_ok()
}

/// More than one period of the calendar contains `day`: a special period
/// (opening, adjustment, closing) shares it with a normal one, so the date
/// alone does not name the entry's period. An unresolvable year counts as
/// shared (fail closed).
fn shared_date(book: &BookContext, day: DateDay) -> bool {
    let Ok(fy) = book.calendar.fiscal_year_of(day) else {
        return true;
    };
    let Ok(periods) = book.calendar.periods_for_year(fy) else {
        return true;
    };
    periods.iter().filter(|p| p.contains(day)).count() > 1
}

/// Reads admitted under one capability (plan §14.2): the kernel core every
/// read surface shares (the facade's `ReadScope`, the async book, fa-query
/// and fa-mcp). [`admit_reads`] admits it once against current policy;
/// each read is then judged by the scope caveats before its query is
/// constructed, refused and never filtered. After admission every judgment
/// is pure: a period's dates come from the calendar.
#[derive(Clone, Debug)]
pub struct ReadAuthority {
    capability: Capability,
}

/// Admit `principal`'s reads of this book under `capability`: the pure
/// checks first (the holder, `read`, the `books` caveat), then expiry and
/// revocation at the head. Historical selectors never resurrect authority:
/// a token expired or revoked now reads nothing, whatever `known_at` a read
/// would select. An `accounts` caveat is refused here until whole-entry
/// visibility lands (an entry may cross the scope), never filtered.
pub fn admit_reads<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    principal: VId,
    capability: &Capability,
) -> Outcome<ReadAuthority> {
    if let Err(d) = fa_policy::admit_read(capability, principal, book.book_id) {
        return Ok(Err(refusal(&d)));
    }
    if capability.accounts().is_some() {
        return Ok(Err(refusal(&Denial::OutOfScope {
            caveat: "accounts",
            value: "a read in this build (whole-entry visibility is not implemented, so a scoped read is refused, never filtered)".into(),
        })));
    }
    if let Err(r) = current_at(db, book, capability)? {
        return Ok(Err(r));
    }
    Ok(Ok(ReadAuthority {
        capability: capability.clone(),
    }))
}

impl ReadAuthority {
    /// The capability these reads are admitted under.
    #[must_use]
    pub fn capability(&self) -> &Capability {
        &self.capability
    }

    /// The entry `vid` as recorded at frontier `seq`. The entry's period is
    /// known only once it is read, so a `periods` or `effective` caveat
    /// refuses the read before it; a `known_at` pin refuses a frontier past
    /// it. The read itself goes through the snapshot at `seq`
    /// ([`crate::post::read_entry_at`]), so an entry recorded later is
    /// never loaded or decoded: to this token it is no entry at all.
    pub fn read_entry<V: asupersync::fs::Vfs + Clone>(
        &self,
        db: &Database<V>,
        vid: VId,
        seq: CommitSeq,
    ) -> Outcome<Option<(Entry, CommitSeq)>> {
        if let Err(r) = self.reach(seq, None, None) {
            return Ok(Err(r));
        }
        Ok(Ok(crate::post::read_entry_at(db, vid, seq)?))
    }

    /// A read of exactly the periods `codes` (their activity, or one
    /// account's explanation in one of them) at `seq`, through the latest
    /// of their last days.
    pub fn periods(
        &self,
        book: &BookContext,
        seq: CommitSeq,
        codes: &[&str],
    ) -> Result<(), Refusal> {
        self.reach(seq, Some(codes), last_day(book, codes))
    }

    /// A stock read through the latest of `codes` (a trial balance): stock
    /// runs from inception, so it reaches every earlier period and a
    /// `periods` caveat refuses it; an `effective` caveat bounds its last day.
    pub fn stock_through(
        &self,
        book: &BookContext,
        seq: CommitSeq,
        codes: &[&str],
    ) -> Result<(), Refusal> {
        self.reach(seq, None, last_day(book, codes))
    }

    /// A stock read as of civil `day` (every period that starts by then).
    pub fn as_of(&self, seq: CommitSeq, day: DateDay) -> Result<(), Refusal> {
        self.reach(seq, None, Some(day))
    }

    /// A read of the whole book at `seq` (every period and effective date,
    /// such as open items): a `periods` or `effective` caveat refuses it.
    pub fn whole_book(&self, seq: CommitSeq) -> Result<(), Refusal> {
        self.reach(seq, None, None)
    }

    fn reach(
        &self,
        seq: CommitSeq,
        periods: Option<&[&str]>,
        through: Option<DateDay>,
    ) -> Result<(), Refusal> {
        fa_policy::reach(
            &self.capability,
            &Reach {
                branch: Some(Id128::TRUNK),
                observes: fa_policy::Observes::At(seq),
                periods,
                through,
                accounts: None,
            },
            None,
        )
        .map_err(|d| refusal(&d))
    }
}

/// The latest last day of the periods `codes` names, from the calendar
/// alone; `None` when a code names no period of the calendar.
fn last_day(book: &BookContext, codes: &[&str]) -> Option<DateDay> {
    let mut through: Option<DateDay> = None;
    for code in codes {
        let last = calendar_period(book, code)?.last_day();
        through = Some(through.map_or(last, |d| d.max(last)));
    }
    through
}

/// A revocation row read at the capability's identity means revoked.
fn not_revoked(row: Option<fgdb::VertexRow>) -> Result<(), Refusal> {
    match row {
        Some(row) => Err(refusal(&Denial::Revoked {
            revoked_at: row.created_at,
        })),
        None => Ok(()),
    }
}

/// `ControlPayload::CapabilityEvent.kind` for a revocation (Issue = 0,
/// Revoke = 1, Attenuate = 2; plan Appendix A).
pub const CAPABILITY_EVENT_REVOKE: u8 = 1;

/// Revoke a capability by its commitment.
#[derive(Clone, Debug)]
pub struct RevocationRequest {
    /// The revoker's capability: it must hold `issue_capability` (which no
    /// Agent- or System-profile capability can).
    pub capability: Capability,
    /// The commitment of the capability being revoked.
    pub revoked: [u8; 32],
    pub effective_date: DateDay,
    pub idempotency_key: Vec<u8>,
    pub description: Erasable<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revoked {
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
    /// The capability was already revoked; nothing was written.
    pub already_recorded: bool,
}

/// Journal a revocation (plan §14.2: "issuance and revocation are journaled
/// control entries"): a PolicyControl entry carrying a `CapabilityEvent`
/// with `kind = Revoke`, at [`revocation_vid`], in one commit. A revocation
/// carries no caveats, so its `caveats_digest` is zero. The revoked token is
/// refused by every later Steward-checked write; recorded approvals it made
/// stay in history (plan §14.2) but no longer authorize anything new.
pub async fn revoke_capability<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    req: RevocationRequest,
) -> Outcome<Revoked> {
    if let Err(d) = fa_policy::admit(
        &req.capability,
        &Intent {
            principal: req.capability.holder(),
            trunk: true,
            op: Op::IssueCapability,
            book: book.book_id,
            legs: &[],
        },
    ) {
        return Ok(Err(refusal(&d)));
    }
    if let Err(d) = fa_policy::current(&req.capability, db.frontier()?) {
        return Ok(Err(refusal(&d)));
    }
    let proposal = EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::POLICY_CONTROL,
        effective_date: req.effective_date,
        document_date: None,
        description: req.description,
        effective_period: None,
        legs: Vec::new(),
        control: Some(ControlPayload::CapabilityEvent {
            commitment: req.revoked,
            kind: CAPABILITY_EVENT_REVOKE,
            caveats_digest: [0; 32],
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: req.idempotency_key,
        origin: EntryOrigin::Control {
            control_kind: fa_model::ControlKind::CAPABILITY_REVOCATION,
            spec_body_digest: req.revoked,
        },
        principal_ref: req.capability.holder(),
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    if proposal.validate().is_err() {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "the revocation is not a valid PolicyControl entry (a non-empty idempotency key is required)",
            "Appendix A ControlPayload::CapabilityEvent",
            "supply a non-empty idempotency key",
        )));
    }
    let vid = revocation_vid(book.book_id, &req.revoked);
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    if let Some(row) = txn.vertex(db, vid)? {
        txn.abort();
        return Ok(Ok(Revoked {
            control_entry: vid,
            recorded_at: row.created_at,
            already_recorded: true,
        }));
    }
    let entry = proposal.seal(Vec::new(), None)?;
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(vid, vec![label::ENTRY], entry_mirrors(&entry)?);
    txn.write(db, batch)?;
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(Revoked {
            control_entry: vid,
            recorded_at: seq,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("a concurrent commit invalidated this revocation's witness: {detail}"),
                "FG-LAW-FCW-01 (first committer wins)",
                "retry; if the capability is already revoked the retry says so",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => match db.vertex(vid)? {
            Some(row) => Ok(Ok(Revoked {
                control_entry: vid,
                recorded_at: row.created_at,
                already_recorded: true,
            })),
            None => Err(KernelError::Corrupt(
                "revocation identity spent but no live row".into(),
            )),
        },
        Err(e) => Err(e.into()),
    }
}

/// `ControlPayload::CapabilityEvent.kind` for an issuance (plan Appendix A).
pub const CAPABILITY_EVENT_ISSUE: u8 = 0;

/// `vid(issuance of C) = H("fa:vid:capability-issuance:v1" ‖ book ‖
/// commitment(C))`: one issuance per capability by identity, found by a
/// point read (plan §14.2, bead fa-v62).
#[must_use]
pub fn issuance_vid(book: Id128, commitment: &[u8; 32]) -> VId {
    let mut h = Hasher::new();
    h.update(b"fa:vid:capability-issuance:v1");
    h.update(&book.0);
    h.update(commitment);
    let d = h.finalize();
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d.0[..16]);
    VId(u128::from_le_bytes(lo))
}

/// A holder-bound capability is admitted only when this book journaled its
/// issuance: the row at its issuance identity is an issuance of exactly
/// this commitment (plan §14.2: "issuance and revocation are journaled
/// control entries"). Its caveats are therefore the journaled ones. Returns
/// the issuing capability's commitment when recorded in `origin`.
fn issued_here(
    row: Option<&fgdb::VertexRow>,
    commitment: &[u8; 32],
) -> Result<Option<[u8; 32]>, Refusal> {
    let mut parent_issuer = None;
    let issued = row.is_some_and(|row| {
        crate::post::entry_of(row).is_ok_and(|(entry, _)| {
            if let EntryOrigin::Control {
                control_kind,
                spec_body_digest,
            } = entry.proposal.origin
                && control_kind == fa_model::ControlKind::CAPABILITY_ISSUANCE
                && &spec_body_digest != commitment
                && spec_body_digest != [0; 32]
            {
                parent_issuer = Some(spec_body_digest);
            }
            matches!(
                entry.proposal.control,
                Some(ControlPayload::CapabilityEvent { kind: CAPABILITY_EVENT_ISSUE, commitment: c, .. })
                    if &c == commitment
            )
        })
    });
    if issued {
        Ok(parent_issuer)
    } else {
        Err(Refusal::new(
            code::CAPABILITY_NOT_ISSUED,
            exit::SAFETY,
            "this holder-bound capability was never issued in this book",
            "plan §14.2 (issuance is a journaled control entry; bead fa-v62)",
            "present a capability issued in this book (`fa capability list --json`), or ask a principal holding issue_capability to run `fa capability issue`",
        ))
    }
}

/// Issue a capability (plan §14.2).
#[derive(Clone, Debug)]
pub struct IssuanceRequest {
    /// The issuer's capability: it must hold `issue_capability` (which no
    /// Agent- or System-profile capability can).
    pub capability: Capability,
    /// The capability being issued: holder-bound, naming the issuer.
    pub issued: Capability,
    pub effective_date: DateDay,
    pub idempotency_key: Vec<u8>,
    pub description: Erasable<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issued {
    pub control_entry: VId,
    /// The issued capability's commitment, the identity of its grant.
    pub commitment: [u8; 32],
    pub recorded_at: CommitSeq,
    /// This exact capability was already issued; nothing was written.
    pub already_recorded: bool,
}

/// Grants only what the issuer holds (plan §14.2: caveats are conjunctive
/// and attenuable only). An issued capability holds no op the issuer lacks,
/// no unit beyond the issuer's ceilings and no larger ceiling, no book
/// beyond the issuer's books, keeps the issuer's redaction caveat, and
/// expires no later than the issuer.
fn grant_refusal(issuer: &Capability, issued: &Capability) -> Option<Refusal> {
    let widen = |what: String| {
        Some(Refusal::new(
            code::CAPABILITY,
            exit::SAFETY,
            format!("the issued capability would widen the issuer's authority: {what}"),
            "plan §14.2 (caveats are conjunctive and attenuable only)",
            "issue only ops, units, ceilings, books, a redaction caveat and an expiry within the issuing capability",
        ))
    };
    if let Some(op) = issued.ops().iter().find(|op| !issuer.holds(**op)) {
        return widen(format!("it grants `{op}`, which the issuer does not hold"));
    }
    if !issuer.ceilings().is_empty() {
        for (unit, max) in issued.ceilings() {
            match issuer.ceilings().get(unit) {
                Some(bound) if max <= bound => {}
                _ => {
                    return widen(format!(
                        "its ceiling on unit {} exceeds the issuer's",
                        unit.0
                    ));
                }
            }
        }
        if issued.ceilings().is_empty() {
            return widen("it carries no ceiling where the issuer is bounded".to_string());
        }
    }
    if issuer.daily_totals().is_empty() {
        if issued.daily_root().is_some() {
            return widen(
                "an unbounded issuer cannot attach a grant to someone else's daily spending root"
                    .to_string(),
            );
        }
    } else {
        if issued.daily_totals().is_empty() {
            return widen("it drops the issuer's cumulative daily limit".to_string());
        }
        for (unit, max) in issued.daily_totals() {
            if issuer
                .daily_totals()
                .get(unit)
                .is_none_or(|bound| max > bound)
            {
                return widen(format!(
                    "its daily limit on unit {} exceeds the issuer's bounded units or amount",
                    unit.0
                ));
            }
        }
        let root = match issuer.daily_root() {
            Some(root) => root,
            None => match issuer.commitment() {
                Ok(root) => root,
                Err(_) => {
                    return widen(
                        "the issuer's daily spending commitment is not canonical".to_string(),
                    );
                }
            },
        };
        if issued.daily_root() != Some(root) {
            return widen("it drops or changes the shared daily spending root".to_string());
        }
    }
    if let Some(books) = issuer.books() {
        match issued.books() {
            Some(own) if own.is_subset(books) => {}
            _ => return widen("it reaches a book the issuer cannot".to_string()),
        }
    }
    // Issuance is a whole-book act on trunk, so admission already refuses an
    // issuer carrying an accounts, periods, effective, known-at or branch
    // caveat. A redaction caveat does not limit reach, so it is kept here.
    if let Some(contract) = issuer.redaction()
        && issued.redaction() != Some(contract)
    {
        return widen(format!(
            "it drops the issuer's redaction = {contract} caveat"
        ));
    }
    if let Some(bound) = issuer.expires_at()
        && issued.expires_at().is_none_or(|at| at > bound)
    {
        return widen(format!(
            "it outlives the issuer's expiry at sequence {}",
            bound.0
        ));
    }
    if issuer.operator_kind() == fa_policy::OperatorKind::Agent
        && issued.operator_kind() != fa_policy::OperatorKind::Agent
    {
        return widen("it escalates an AI operator capability to Human".to_string());
    }
    if issuer.requires_dry_run() && !issued.requires_dry_run() {
        return widen("it drops the issuer's requires_dry_run caveat".to_string());
    }
    if let Some(classes) = issuer.classes() {
        match issued.classes() {
            Some(own) if own.is_subset(classes) => {}
            _ => return widen("it admits an EntryClass the issuer cannot".to_string()),
        }
    }
    None
}

/// Journal an issuance (plan §14.2): a PolicyControl entry carrying a
/// `CapabilityEvent { kind: Issue }` for the issued commitment, with the
/// issued capability's canonical bytes as extension `fa:capability-body:v1`,
/// at [`issuance_vid`], in one commit. The kernel admits the holder-bound
/// token only against this row.
pub async fn issue_capability<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    req: IssuanceRequest,
) -> Outcome<Issued> {
    if let Err(d) = fa_policy::admit(
        &req.capability,
        &Intent {
            principal: req.capability.holder(),
            trunk: true,
            op: Op::IssueCapability,
            book: book.book_id,
            legs: &[],
        },
    ) {
        return Ok(Err(refusal(&d)));
    }
    if let Err(d) = fa_policy::current(&req.capability, db.frontier()?) {
        return Ok(Err(refusal(&d)));
    }
    let usage = |message: &str| {
        Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            message.to_string(),
            "plan §14.2, Appendix A ControlPayload::CapabilityEvent",
            "issue a holder-bound capability that names the issuing principal as its issuer",
        )))
    };
    if req.issued.issuer() != req.capability.holder() {
        return usage("the issued capability must name the issuing principal as its issuer");
    }
    if req.issued.possession().is_none() {
        return usage("an issued capability is holder-bound: it carries a possession digest");
    }
    if let Some(r) = grant_refusal(&req.capability, &req.issued) {
        return Ok(Err(r));
    }
    let body = req.issued.canonical_bytes().map_err(capability_error)?;
    let commitment = req.issued.commitment().map_err(capability_error)?;
    let issuer_commitment = req.capability.commitment().map_err(capability_error)?;
    let proposal = EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::POLICY_CONTROL,
        effective_date: req.effective_date,
        document_date: None,
        description: req.description,
        effective_period: None,
        legs: Vec::new(),
        control: Some(ControlPayload::CapabilityEvent {
            commitment,
            kind: CAPABILITY_EVENT_ISSUE,
            caveats_digest: fa_model::domain_digest(b"fa:capability-body:v1", &[&body]),
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: req.idempotency_key,
        origin: EntryOrigin::Control {
            control_kind: fa_model::ControlKind::CAPABILITY_ISSUANCE,
            spec_body_digest: issuer_commitment,
        },
        principal_ref: req.capability.holder(),
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: vec![(fa_model::entry::CAPABILITY_BODY_EXTENSION, body)],
        tags: Vec::new(),
    };
    if proposal.validate().is_err() {
        return usage(
            "the issuance is not a valid PolicyControl entry (a non-empty idempotency key is required)",
        );
    }
    let vid = issuance_vid(book.book_id, &commitment);
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    if let Some(row) = txn.vertex(db, vid)? {
        txn.abort();
        return Ok(Ok(Issued {
            control_entry: vid,
            commitment,
            recorded_at: row.created_at,
            already_recorded: true,
        }));
    }
    let entry = proposal.seal(Vec::new(), None)?;
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(vid, vec![label::ENTRY], entry_mirrors(&entry)?);
    txn.write(db, batch)?;
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(Issued {
            control_entry: vid,
            commitment,
            recorded_at: seq,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("a concurrent commit invalidated this issuance's witness: {detail}"),
                "FG-LAW-FCW-01 (first committer wins)",
                "retry; if the capability is already issued the retry says so",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => match db.vertex(vid)? {
            Some(row) => Ok(Ok(Issued {
                control_entry: vid,
                commitment,
                recorded_at: row.created_at,
                already_recorded: true,
            })),
            None => Err(KernelError::Corrupt(
                "issuance identity spent but no live row".into(),
            )),
        },
        Err(e) => Err(e.into()),
    }
}

/// One issued capability as the journal records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedCapability {
    pub capability: Capability,
    pub commitment: [u8; 32],
    pub control_entry: VId,
    pub issued_at: CommitSeq,
    /// The sequence that revoked it, if any.
    pub revoked_at: Option<CommitSeq>,
}

/// The capability issued at `commitment`, decoded from its journaled body
/// (never from a presenter), with its revocation state.
pub fn read_issued<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    commitment: &[u8; 32],
) -> Result<Option<IssuedCapability>, KernelError> {
    let vid = issuance_vid(book.book_id, commitment);
    let Some(row) = db.vertex(vid)? else {
        return Ok(None);
    };
    let (entry, issued_at) = crate::post::entry_of(&row)?;
    let Some((_, body)) = entry
        .proposal
        .extensions
        .iter()
        .find(|(tag, _)| *tag == fa_model::entry::CAPABILITY_BODY_EXTENSION)
    else {
        return Err(KernelError::Corrupt(
            "a capability issuance without its body".into(),
        ));
    };
    let capability = Capability::decode(body).map_err(capability_error)?;
    if &capability.commitment().map_err(capability_error)? != commitment {
        return Err(KernelError::Corrupt(
            "a capability issuance body does not match its commitment".into(),
        ));
    }
    let mut revoked_at = db
        .vertex(revocation_vid(book.book_id, commitment))?
        .map(|row| row.created_at);
    let mut seen = BTreeSet::from([*commitment]);
    let mut cur_parent = issued_here(Some(&row), commitment).ok().flatten();
    for _ in 0..MAX_ISSUANCE_LINEAGE {
        let Some(parent) = cur_parent else {
            break;
        };
        if !seen.insert(parent) {
            break;
        }
        if let Some(rev) = db.vertex(revocation_vid(book.book_id, &parent))? {
            revoked_at = Some(revoked_at.map_or(rev.created_at, |cur| cur.min(rev.created_at)));
        }
        let Some(parent_row) = db.vertex(issuance_vid(book.book_id, &parent))? else {
            break;
        };
        cur_parent = issued_here(Some(&parent_row), &parent).ok().flatten();
    }
    Ok(Some(IssuedCapability {
        capability,
        commitment: *commitment,
        control_entry: vid,
        issued_at,
        revoked_at,
    }))
}

/// Every capability issued in this book, in issuance order. A scan of the
/// journal's PolicyControl issuances (a slice-1 read; plan §14.2).
pub fn list_issued<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
) -> Result<Vec<IssuedCapability>, KernelError> {
    let mut out = Vec::new();
    for row in db.vertices()? {
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let Ok((entry, _)) = crate::post::entry_of(&row) else {
            continue;
        };
        if let Some(ControlPayload::CapabilityEvent {
            kind: CAPABILITY_EVENT_ISSUE,
            commitment,
            ..
        }) = entry.proposal.control
            && row.vid == issuance_vid(book.book_id, &commitment)
            && let Some(issued) = read_issued(db, book, &commitment)?
        {
            out.push(issued);
        }
    }
    out.sort_by_key(|i| (i.issued_at, i.control_entry));
    Ok(out)
}
