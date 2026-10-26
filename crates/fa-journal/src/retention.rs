//! Retention floors as registered Policy objects honoring legal holds (plan §8.5; bead fa-v6di).
//!
//! A [`RetentionPolicy`] (`fa:retention-policy:v1`) specifies:
//! - [`RetentionScope`]: the book as a whole, a specific [`EntryClass`], a
//!   specific document `kind`, or a canonical ascending list of subject [`VId`]s;
//! - [`RetentionFloor`]: a minimum retention period in calendar days (`Days`)
//!   or commit sequence delta (`Commits`);
//! - `authority`: the verified [`Oid`] of the authority document (statute,
//!   regulatory order, or retention schedule) in this book;
//! - `[effective_from, effective_to)`: the effective date interval.
//!
//! Activating a [`RetentionPolicy`] via [`activate_retention_policy`] journals a
//! `PolicyControl` entry carrying `ControlPayload::PolicyActivation { policy_oid,
//! effective_from, effective_to }` under the `policy-activate` segregation-of-duties
//! rule (requiring dual control: two distinct Human approvers other than the
//! preparer), witnesses the authority document and its complete custody chain,
//! stores the canonical [`RetentionPolicy`] body at [`retention_policy_vid`], and
//! updates the book's retention cell [`retention_cell_vid`] by compare-and-set.
//!
//! Any retention cut ([`retention_cut`]) checks:
//! 1. **Capability admission** (`Op::Erase`, whole-book reach, current at frontier,
//!    not revoked);
//! 2. **Legal hold override (§8.5):** if the subject is pinned by an active
//!    subject-specific or book-scope legal hold ([`crate::legal_hold::active_legal_holds`]),
//!    the cut is refused with `FA-REF-117` (`exit::SAFETY`), naming both the active
//!    legal hold(s) and any active [`RetentionPolicy`] covering the subject;
//! 3. **Retention floor enforcement (§8.5):** if the cut sequence or date lies
//!    inside any active [`RetentionPolicy`]'s floor covering the subject, the cut
//!    is refused with [`RETENTION_FLOOR_ACTIVE`] (`FA-REF-199`, `exit::SAFETY`),
//!    naming the policy OID, control entry, authority document, and floor;
//! 4. **Checkpoint cadence check ([`check_checkpoint_cadence`]):** verifies that
//!    a register checkpoint cadence never exceeds any active retention floor.

use fa_model::limits::MAX_LEGAL_HOLD_SUBJECTS;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ApprovalRef, ControlKind, ControlPayload, DecodeError, Entry, EntryClass, EntryOrigin,
    EntryPayload, Erasable, Id128, Oid, Reader, Writer, domain_digest, entry_mirrors, entry_vid,
};
use fa_policy::{Capability, Intent, Op, Party, Reach};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::custody::witness_custody;
use crate::evidence::{DocumentRecord, document_vid, drift, hex, verify_row};
use crate::genesis::BookContext;
use crate::legal_hold::active_legal_holds;
use crate::policy::{
    OPEN_END, authorize_approvals, capability_admitted, capability_witness, epoch_witness, refusal,
    steward,
};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{prop, scalar_bytes};

/// Domain string for [`RetentionPolicy::policy_oid`].
pub const RETENTION_POLICY_DOMAIN: &[u8] = b"fa:retention-policy:v1";
/// Wire format version for [`RetentionPolicy`].
pub const RETENTION_POLICY_VERSION: u16 = 1;
/// Maximum number of active retention policies in a single book cell.
pub const MAX_ACTIVE_RETENTION_POLICIES: usize = 256;

/// Refusal code when a retention cut attempts to drop an object still inside an
/// active retention policy floor (plan §8.5).
pub const RETENTION_FLOOR_ACTIVE: &str = "FA-REF-199";
/// Refusal code when a register checkpoint cadence exceeds an active retention
/// floor (plan §8.5, bead fa-9xf9).
pub const RETENTION_CADENCE_EXCEEDS_FLOOR: &str = "FA-REF-200";

const SCOPE_BOOK: u8 = 0;
const SCOPE_ENTRY_CLASS: u8 = 1;
const SCOPE_DOCUMENT_KIND: u8 = 2;
const SCOPE_SUBJECTS: u8 = 3;

const FLOOR_DAYS: u8 = 0;
const FLOOR_COMMITS: u8 = 1;

/// The scope of records a [`RetentionPolicy`] governs (plan §8.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetentionScope {
    /// Every entry, document, and party in the book.
    Book,
    /// Every entry of the named [`EntryClass`].
    EntryClass(EntryClass),
    /// Every document of the named document kind (`1..=9`).
    DocumentKind(u8),
    /// Specific named subjects (entries, documents, or parties), strictly ascending.
    Subjects(Vec<VId>),
}

/// The minimum retention floor a [`RetentionPolicy`] enforces (plan §8.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionFloor {
    /// Minimum retention window in calendar days (`>= 1`).
    Days(u32),
    /// Minimum retention window in commit sequence delta (`>= 1`).
    Commits(u64),
}

impl RetentionFloor {
    /// Human-readable summary of the floor.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Days(days) => format!("{days} days"),
            Self::Commits(commits) => format!("{commits} commits"),
        }
    }
}

/// Registered retention floor policy object (plan §8.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub book_id: Id128,
    pub scope: RetentionScope,
    pub floor: RetentionFloor,
    pub authority: Oid,
    pub effective_from: DateDay,
    pub effective_to: DateDay,
}

impl RetentionPolicy {
    /// Construct a retention policy effective from `effective_from` through [`OPEN_END`].
    #[must_use]
    pub fn new(
        book_id: Id128,
        scope: RetentionScope,
        floor: RetentionFloor,
        authority: Oid,
        effective_from: DateDay,
    ) -> Self {
        Self {
            book_id,
            scope,
            floor,
            authority,
            effective_from,
            effective_to: OPEN_END,
        }
    }

    /// Structural validation of the retention policy.
    pub fn validate(&self) -> Result<(), String> {
        if self.effective_from > self.effective_to {
            return Err(format!(
                "effective_from ({}) exceeds effective_to ({})",
                self.effective_from.render(),
                self.effective_to.render()
            ));
        }
        match self.floor {
            RetentionFloor::Days(0) => {
                return Err("retention floor_days must be at least 1".into());
            }
            RetentionFloor::Commits(0) => {
                return Err("retention floor_seq must be at least 1".into());
            }
            RetentionFloor::Days(_) | RetentionFloor::Commits(_) => {}
        }
        match &self.scope {
            RetentionScope::Book => {}
            RetentionScope::EntryClass(class) => {
                if !class.is_registered() {
                    return Err(format!("entry class {} is not registered", class.0));
                }
            }
            RetentionScope::DocumentKind(kind) => {
                if *kind == 0 {
                    return Err("document kind must be non-zero".into());
                }
            }
            RetentionScope::Subjects(subjects) => {
                if subjects.is_empty() || subjects.len() > MAX_LEGAL_HOLD_SUBJECTS {
                    return Err(format!(
                        "retention subject scope must name 1..={MAX_LEGAL_HOLD_SUBJECTS} subjects; found {}",
                        subjects.len()
                    ));
                }
                if !subjects.windows(2).all(|w| w[0].0 < w[1].0) {
                    return Err("retention subjects must be strictly ascending".into());
                }
            }
        }
        Ok(())
    }

    /// Deterministic canonical bytes (`fa:retention-policy:v1`).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::new();
        w.u16(RETENTION_POLICY_VERSION)
            .fixed(&self.book_id.0)
            .fixed(&self.authority.0)
            .i32(self.effective_from.0)
            .i32(self.effective_to.0);
        match &self.scope {
            RetentionScope::Book => {
                w.u8(SCOPE_BOOK);
            }
            RetentionScope::EntryClass(class) => {
                w.u8(SCOPE_ENTRY_CLASS).u16(class.0);
            }
            RetentionScope::DocumentKind(kind) => {
                w.u8(SCOPE_DOCUMENT_KIND).u8(*kind);
            }
            RetentionScope::Subjects(subjects) => {
                w.u8(SCOPE_SUBJECTS).list(subjects, |w, s| {
                    w.u128(s.0);
                });
            }
        }
        match self.floor {
            RetentionFloor::Days(days) => {
                w.u8(FLOOR_DAYS).u32(days);
            }
            RetentionFloor::Commits(commits) => {
                w.u8(FLOOR_COMMITS).u64(commits);
            }
        }
        w.finish().map_err(|e| KernelError::Model(e.into()))
    }

    /// Decode a [`RetentionPolicy`] from its canonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let version = r.u16("retention_policy.version")?;
        if version != RETENTION_POLICY_VERSION {
            return Err(r.invalid("retention_policy.version"));
        }
        let book_id = Id128(r.fixed::<16>("retention_policy.book_id")?);
        let authority = Oid(r.fixed::<32>("retention_policy.authority")?);
        let effective_from = DateDay(r.i32("retention_policy.effective_from")?);
        let effective_to = DateDay(r.i32("retention_policy.effective_to")?);
        if effective_from > effective_to {
            return Err(r.invalid("retention_policy.effective_range"));
        }
        let scope = match r.u8("retention_policy.scope_kind")? {
            SCOPE_BOOK => RetentionScope::Book,
            SCOPE_ENTRY_CLASS => {
                let class = EntryClass(r.u16("retention_policy.entry_class")?);
                if !class.is_registered() {
                    return Err(r.invalid("retention_policy.entry_class"));
                }
                RetentionScope::EntryClass(class)
            }
            SCOPE_DOCUMENT_KIND => {
                let kind = r.u8("retention_policy.document_kind")?;
                if kind == 0 {
                    return Err(r.invalid("retention_policy.document_kind"));
                }
                RetentionScope::DocumentKind(kind)
            }
            SCOPE_SUBJECTS => {
                let subjects =
                    r.list(MAX_LEGAL_HOLD_SUBJECTS, "retention_policy.subjects", |r| {
                        Ok(VId(r.u128("retention_policy.subject")?))
                    })?;
                if subjects.is_empty() {
                    return Err(r.invalid("retention_policy.subjects"));
                }
                if !subjects.windows(2).all(|w| w[0].0 < w[1].0) {
                    return Err(r.unsorted("retention_policy.subjects"));
                }
                RetentionScope::Subjects(subjects)
            }
            t => return Err(r.bad_tag("retention_policy.scope_kind", t)),
        };
        let floor = match r.u8("retention_policy.floor_kind")? {
            FLOOR_DAYS => {
                let days = r.u32("retention_policy.floor_days")?;
                if days == 0 {
                    return Err(r.invalid("retention_policy.floor_days"));
                }
                RetentionFloor::Days(days)
            }
            FLOOR_COMMITS => {
                let commits = r.u64("retention_policy.floor_seq")?;
                if commits == 0 {
                    return Err(r.invalid("retention_policy.floor_seq"));
                }
                RetentionFloor::Commits(commits)
            }
            t => return Err(r.bad_tag("retention_policy.floor_kind", t)),
        };
        r.finish()?;
        Ok(Self {
            book_id,
            scope,
            floor,
            authority,
            effective_from,
            effective_to,
        })
    }

    /// Content-addressed [`Oid`] (`H("fa:retention-policy:v1" ‖ canonical_bytes)`).
    pub fn policy_oid(&self) -> Result<Oid, KernelError> {
        Ok(Oid(domain_digest(
            RETENTION_POLICY_DOMAIN,
            &[&self.canonical_bytes()?],
        )))
    }
}

/// `vid(retention policy) = H("fa:vid:retention-policy:v1" ‖ book ‖ policy_oid)`.
#[must_use]
pub fn retention_policy_vid(book: Id128, policy_oid: &Oid) -> VId {
    let d = domain_digest(b"fa:vid:retention-policy:v1", &[&book.0, &policy_oid.0]);
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d[..16]);
    VId(u128::from_le_bytes(lo))
}

/// `vid(retention cell) = H("fa:vid:retention-cell:v1" ‖ book)`: the book-level
/// cell listing active `(control_entry, policy_oid)` pairs.
#[must_use]
pub fn retention_cell_vid(book: Id128) -> VId {
    let d = domain_digest(b"fa:vid:retention-cell:v1", &[&book.0]);
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d[..16]);
    VId(u128::from_le_bytes(lo))
}

fn cell_scalar(entries: &[(VId, Oid)]) -> Result<CanonicalScalar, KernelError> {
    let mut w = Writer::new();
    w.list(entries, |w, (evid, oid)| {
        w.u128(evid.0).fixed(&oid.0);
    });
    scalar_bytes(
        "retention_cell",
        w.finish().map_err(|e| KernelError::Model(e.into()))?,
    )
}

fn decode_cell(row: &VertexRow) -> Result<Vec<(VId, Oid)>, KernelError> {
    let corrupt =
        |why: String| KernelError::Corrupt(format!("retention cell {:032x}: {why}", row.vid.0));
    let Some(CanonicalScalar::Bytes(b)) = prop(row, property::FA_PAYLOAD) else {
        return Err(corrupt("carries no _fa_payload".into()));
    };
    let mut r = Reader::new(b.as_slice());
    let items = r
        .list(MAX_ACTIVE_RETENTION_POLICIES, "retention_cell", |r| {
            let evid = VId(r.u128("retention_cell.entry")?);
            let oid = Oid(r.fixed::<32>("retention_cell.policy_oid")?);
            Ok((evid, oid))
        })
        .map_err(|e| corrupt(e.to_string()))?;
    r.finish().map_err(|e| corrupt(e.to_string()))?;
    if !items.windows(2).all(|w| w[0].0.0 < w[1].0.0) {
        return Err(corrupt(
            "retention cell entries are not strictly ascending".into(),
        ));
    }
    Ok(items)
}

/// Build the `PolicyControl` proposal that activates `policy`. Approvers approve
/// its `proposal_digest()` before [`activate_retention_policy`] commits it.
pub fn retention_activation_proposal(
    book: &BookContext,
    principal: VId,
    policy: &RetentionPolicy,
    idempotency_key: &[u8],
    description: Erasable<String>,
) -> Result<EntryPayload, KernelError> {
    let policy_oid = policy.policy_oid()?;
    Ok(EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::POLICY_CONTROL,
        effective_date: policy.effective_from,
        document_date: None,
        description,
        effective_period: None,
        legs: Vec::new(),
        control: Some(ControlPayload::PolicyActivation {
            policy_oid,
            effective_from: policy.effective_from,
            effective_to: policy.effective_to,
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: idempotency_key.to_vec(),
        origin: EntryOrigin::Control {
            control_kind: ControlKind::POLICY_ACTIVATION,
            spec_body_digest: policy_oid.0,
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

/// Request to activate a [`RetentionPolicy`] under dual control (plan §8.5, §14.3).
#[derive(Clone, Debug)]
pub struct RetentionActivationRequest {
    pub policy: RetentionPolicy,
    pub proposal: EntryPayload,
    pub capability: Capability,
    pub approvals: Vec<ApprovalRef>,
}

/// Outcome of [`activate_retention_policy`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionPolicyActivated {
    pub policy_oid: Oid,
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
    pub security_policy_epoch: u64,
    pub already_recorded: bool,
}

/// An active [`RetentionPolicy`] as recorded in the journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveRetentionPolicy {
    pub control_entry: VId,
    pub policy_oid: Oid,
    pub policy: RetentionPolicy,
    pub activated_at: CommitSeq,
}

/// Verification report for all journaled retention policies in a book.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionVerification {
    pub active_policies: Vec<ActiveRetentionPolicy>,
    pub drifts: Vec<String>,
}

impl RetentionVerification {
    /// True when every recorded retention policy, control entry, and authority
    /// document verified without drift.
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.drifts.is_empty()
    }
}

fn holdable(row: &VertexRow) -> bool {
    [label::ENTRY, label::DOCUMENT, label::PARTY]
        .iter()
        .any(|l| row.labels.contains(l))
}

fn recorded_or_conflict<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    row: &VertexRow,
    proposal: &EntryPayload,
    proposal_digest: &[u8; 32],
    expected_oid: Oid,
    approvals: &[ApprovalRef],
) -> Outcome<RetentionPolicyActivated> {
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
            "resubmit the identical retention policy activation to get the recorded outcome, or use a new idempotency key",
        )
    };
    if stored.proposal.class != EntryClass::POLICY_CONTROL || stored.approvals != approvals {
        return Ok(Err(conflict()));
    }
    if !crate::outcome::verify_control_recorded(db, row, &stored)? {
        return Ok(Err(crate::outcome::key_conflict()));
    }
    let same = &stored.proposal_digest == proposal_digest
        || matches!(
            (
                stored.proposal.semantic_digest(&book.seal_key),
                proposal.semantic_digest(&book.seal_key),
            ),
            (Ok(a), Ok(b)) if a == b
        );
    if !same {
        return Ok(Err(conflict()));
    }
    let epoch = crate::policy::security_policy_epoch_at(db, row.created_at)?;
    Ok(Ok(RetentionPolicyActivated {
        policy_oid: expected_oid,
        control_entry: row.vid,
        recorded_at: row.created_at,
        security_policy_epoch: epoch,
        already_recorded: true,
    }))
}

/// Activate a [`RetentionPolicy`] with dual control (plan §8.5, §14.3):
/// validates structure and capability before any storage read, enforces the
/// `policy-activate` SoD rule (two distinct Human approvers other than the
/// preparer), witnesses the authority document and its complete custody chain,
/// and journals the `PolicyControl` entry alongside the canonical policy body.
pub async fn activate_retention_policy<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    req: RetentionActivationRequest,
) -> Outcome<RetentionPolicyActivated> {
    if let Err(why) = req.policy.validate() {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!("retention policy is invalid: {why}"),
            "plan §8.5 (a RetentionPolicy names a valid scope, a non-zero floor, and an effective range)",
            "supply a non-zero floor_days or floor_seq and a valid scope",
        )));
    }
    if req.policy.book_id != book.book_id {
        return Ok(Err(Refusal::new(
            code::COORDINATE,
            exit::USAGE,
            "the retention policy names another book",
            "plan §2.2",
            "set policy.book_id to this book's book_id",
        )));
    }
    let expected_oid = req.policy.policy_oid()?;
    let proposal = &req.proposal;
    let valid_proposal = match (&proposal.control, proposal.validate()) {
        (
            Some(ControlPayload::PolicyActivation {
                policy_oid,
                effective_from,
                effective_to,
            }),
            Ok(()),
        ) => {
            proposal.class == EntryClass::POLICY_CONTROL
                && *policy_oid == expected_oid
                && *effective_from == req.policy.effective_from
                && *effective_to == req.policy.effective_to
                && proposal.effective_date == req.policy.effective_from
                && proposal.base_totals.is_none()
        }
        _ => false,
    };
    if !valid_proposal {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "retention policy activation requires a valid PolicyControl proposal matching the RetentionPolicy's policy_oid and effective range",
            "Appendix A ControlPayload::PolicyActivation; plan §8.5",
            "build the proposal with fa_journal::retention_activation_proposal",
        )));
    }
    if proposal.book_id != book.book_id || proposal.branch_id != Id128::TRUNK {
        return Ok(Err(Refusal::new(
            code::COORDINATE,
            exit::USAGE,
            "the retention activation names another book or a branch",
            "plan §2.2",
            "activate on this book's trunk",
        )));
    }
    let steward = steward()?;
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
    if let Err(r) = capability_admitted(db, book, &req.capability)? {
        return Ok(Err(r));
    }
    if let Err(r) = crate::scratch::ensure_history(db, ctx).await? {
        return Ok(Err(r));
    }

    let evidence_policy =
        EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let proposal_digest = proposal.proposal_digest()?;
    let policy_bytes = req.policy.canonical_bytes()?;
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
    if let Err(r) = crate::outcome::witness_named_key(
        &txn,
        db,
        book.book_id,
        proposal.principal_ref,
        &proposal.idempotency_key,
        evid,
    )? {
        txn.abort();
        return Ok(Err(r));
    }
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return recorded_or_conflict(
            db,
            book,
            &row,
            proposal,
            &proposal_digest,
            expected_oid,
            &req.approvals,
        );
    }
    if let Err(r) = crate::outcome::require_unused_legacy_key(
        &txn,
        db,
        book,
        crate::outcome::entry_outcome_vid(proposal),
    )? {
        txn.abort();
        return Ok(Err(r));
    }
    let epoch = epoch_witness(&txn, db)?;
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

    let Some(authority_row) = txn.vertex(db, document_vid(&req.policy.authority))? else {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::EVIDENCE_UNKNOWN,
            exit::REFUSAL,
            format!(
                "the retention policy's authority, document {}, is not in this book",
                hex(&req.policy.authority.0)
            ),
            "plan §8.5 (a RetentionPolicy names the authority document it rests on)",
            "record the authority document first with `fa document add <file> --kind <Kind> --json` and cite its oid",
        )));
    };
    if let Err(why) = verify_row(&authority_row, &evidence_policy) {
        txn.abort();
        return Ok(Err(drift(&req.policy.authority, &why)));
    }
    if let Err(r) = witness_custody(&txn, db, &evidence_policy, &req.policy.authority)? {
        txn.abort();
        return Ok(Err(r));
    }
    if let RetentionScope::Subjects(subjects) = &req.policy.scope {
        for subject in subjects {
            let Some(row) = txn.vertex(db, *subject)? else {
                txn.abort();
                return Ok(Err(Refusal::new(
                    code::LEGAL_HOLD_SUBJECT,
                    exit::REFUSAL,
                    format!("retention subject {:032x} is not in this book", subject.0),
                    "plan §8.5 (subject-scoped retention policies govern recorded entries, documents, or parties)",
                    "name the vids of entries, documents, or parties recorded in this book",
                )));
            };
            if !holdable(&row) {
                txn.abort();
                return Ok(Err(Refusal::new(
                    code::LEGAL_HOLD_SUBJECT,
                    exit::REFUSAL,
                    format!(
                        "retention subject {:032x} is not an entry, a document, or a party",
                        subject.0
                    ),
                    "plan §8.5 (subject-scoped retention policies govern recorded entries, documents, or parties)",
                    "name the vids of entries, documents, or parties recorded in this book",
                )));
            }
        }
    }

    let entry = proposal.clone().seal(req.approvals.clone(), None)?;
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    crate::outcome::stage_control(&mut batch, &entry, evid)?;

    let pvid = retention_policy_vid(book.book_id, &expected_oid);
    if txn.vertex(db, pvid)?.is_none() {
        let mut props = vec![
            (
                property::FA_PAYLOAD,
                scalar_bytes("retention_policy.payload", policy_bytes)?,
            ),
            (
                property::FA_DIGEST,
                scalar_bytes("retention_policy.digest", expected_oid.0.to_vec())?,
            ),
        ];
        props.sort_by_key(|(k, _)| k.0);
        batch.create_vertex(pvid, vec![label::LEGAL_HOLD_CELL], props);
    }

    let cell = retention_cell_vid(book.book_id);
    match txn.vertex(db, cell)? {
        None => {
            batch.create_vertex(
                cell,
                vec![label::LEGAL_HOLD_CELL],
                vec![(property::FA_PAYLOAD, cell_scalar(&[(evid, expected_oid)])?)],
            );
        }
        Some(row) => {
            let mut active = decode_cell(&row)?;
            if active.len() >= MAX_ACTIVE_RETENTION_POLICIES {
                txn.abort();
                return Ok(Err(Refusal::new(
                    code::STRUCTURE,
                    exit::USAGE,
                    format!(
                        "the book already carries max_active_retention_policies ({MAX_ACTIVE_RETENTION_POLICIES})"
                    ),
                    "plan §8.5",
                    "consolidate subject scopes under a book- or class-scoped retention policy",
                )));
            }
            if let Err(pos) = active.binary_search_by_key(&evid.0, |(v, _)| v.0) {
                active.insert(pos, (evid, expected_oid));
            }
            batch.compare_and_set_vertex_property(
                cell,
                property::FA_PAYLOAD,
                prop(&row, property::FA_PAYLOAD).cloned(),
                cell_scalar(&active)?,
                WriteMismatchPolicy::AbortWrite,
            );
        }
    }

    if let Err(e) = txn.write(db, batch) {
        txn.abort();
        return Err(e.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(RetentionPolicyActivated {
            policy_oid: expected_oid,
            control_entry: evid,
            recorded_at: seq,
            security_policy_epoch: epoch,
            already_recorded: false,
        })),
        Err(
            WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { .. })
            | WriteTxnError::Write(fgdb::WriteError::CompareAndSetMismatch(_)),
        ) => Ok(Err(Refusal::new(
            code::CONFLICT,
            exit::CONFLICT,
            "a concurrent commit invalidated a witness this retention activation read",
            "FG-LAW-FCW-01 (first committer wins)",
            "re-read the book's policy epoch and retention state and retry",
        ))),
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => match db.vertex(evid)? {
            Some(row) => recorded_or_conflict(
                db,
                book,
                &row,
                proposal,
                &proposal_digest,
                expected_oid,
                &req.approvals,
            ),
            None => {
                if db
                    .vertex(crate::outcome::entry_outcome_vid(proposal))?
                    .is_some()
                {
                    Ok(Err(crate::outcome::key_conflict()))
                } else {
                    Ok(Err(Refusal::new(
                        code::CONFLICT,
                        exit::CONFLICT,
                        "a concurrent retention activation won the cell creation race",
                        "FG-LAW-FCW-01 (first committer wins)",
                        "retry the retention policy activation",
                    )))
                }
            }
        },
        Err(e) => Err(e.into()),
    }
}

/// Read all active [`RetentionPolicy`] objects recorded in `book`.
pub fn active_retention_policies<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: Id128,
) -> Result<Vec<ActiveRetentionPolicy>, KernelError> {
    Ok(verify_retention_policies(db, book)?.active_policies)
}

/// Verify all retention policies recorded in `book`: checks the retention cell,
/// each `PolicyControl` activation entry, the content-addressed policy payload,
/// and the cited authority document (plan §8.5).
pub fn verify_retention_policies<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: Id128,
) -> Result<RetentionVerification, KernelError> {
    let Some(cell_row) = db.vertex(retention_cell_vid(book))? else {
        return Ok(RetentionVerification {
            active_policies: Vec::new(),
            drifts: Vec::new(),
        });
    };
    let items = match decode_cell(&cell_row) {
        Ok(items) => items,
        Err(e) => {
            return Ok(RetentionVerification {
                active_policies: Vec::new(),
                drifts: vec![e.to_string()],
            });
        }
    };
    let evidence_policy =
        EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let mut active_policies = Vec::with_capacity(items.len());
    let mut drifts = Vec::new();
    for (evid, oid) in items {
        let Some(entry_row) = db.vertex(evid)? else {
            drifts.push(format!(
                "retention control entry {:032x} for policy {} is missing",
                evid.0,
                hex(&oid.0)
            ));
            continue;
        };
        let Ok((entry, activated_at)) = crate::post::entry_of(&entry_row) else {
            drifts.push(format!(
                "retention control entry {:032x} failed to decode",
                evid.0
            ));
            continue;
        };
        if entry.proposal.class != EntryClass::POLICY_CONTROL
            || !matches!(
                entry.proposal.control,
                Some(ControlPayload::PolicyActivation { policy_oid, .. }) if policy_oid == oid
            )
        {
            drifts.push(format!(
                "retention control entry {:032x} does not carry PolicyActivation({})",
                evid.0,
                hex(&oid.0)
            ));
            continue;
        }
        let pvid = retention_policy_vid(book, &oid);
        let Some(policy_row) = db.vertex(pvid)? else {
            drifts.push(format!(
                "retention policy vertex {:032x} ({}) is missing",
                pvid.0,
                hex(&oid.0)
            ));
            continue;
        };
        let Some(CanonicalScalar::Bytes(bytes)) = prop(&policy_row, property::FA_PAYLOAD) else {
            drifts.push(format!(
                "retention policy vertex {:032x} carries no _fa_payload",
                pvid.0
            ));
            continue;
        };
        let policy = match RetentionPolicy::decode(bytes.as_slice()) {
            Ok(p) => p,
            Err(e) => {
                drifts.push(format!(
                    "retention policy {} failed to decode: {e}",
                    hex(&oid.0)
                ));
                continue;
            }
        };
        let recomputed = policy.policy_oid()?;
        if recomputed != oid {
            drifts.push(format!(
                "retention policy {} recomputed to {} (digest drift)",
                hex(&oid.0),
                hex(&recomputed.0)
            ));
            continue;
        }
        match db.vertex(document_vid(&policy.authority))? {
            None => {
                drifts.push(format!(
                    "retention policy {} cites missing authority document {}",
                    hex(&oid.0),
                    hex(&policy.authority.0)
                ));
            }
            Some(doc_row) => {
                if let Err(why) = verify_row(&doc_row, &evidence_policy) {
                    drifts.push(format!(
                        "retention policy {} authority document {} failed verification: {why}",
                        hex(&oid.0),
                        hex(&policy.authority.0)
                    ));
                }
            }
        }
        active_policies.push(ActiveRetentionPolicy {
            control_entry: evid,
            policy_oid: oid,
            policy,
            activated_at,
        });
    }
    Ok(RetentionVerification {
        active_policies,
        drifts,
    })
}

/// Verify that a register checkpoint cadence does not exceed any active
/// retention policy floor (plan §8.5, bead fa-9xf9).
pub fn check_checkpoint_cadence(
    policies: &[ActiveRetentionPolicy],
    cadence_commits: u64,
    cadence_days: Option<u32>,
) -> Result<(), Refusal> {
    if cadence_commits == 0 || cadence_days == Some(0) {
        return Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "register checkpoint cadence must be at least 1",
            "plan §8.5 (checkpoint cadence is bounded below by 1 and above by active retention floors)",
            "specify a non-zero checkpoint cadence",
        ));
    }
    for active in policies {
        match active.policy.floor {
            RetentionFloor::Commits(floor_seq) if cadence_commits > floor_seq => {
                return Err(Refusal::new(
                    RETENTION_CADENCE_EXCEEDS_FLOOR,
                    exit::REFUSAL,
                    format!(
                        "checkpoint cadence ({cadence_commits} commits) exceeds active retention policy {} (entry {:032x}) floor of {floor_seq} commits",
                        hex(&active.policy_oid.0),
                        active.control_entry.0
                    ),
                    "plan §8.5 (register checkpoint cadence must not exceed any active retention floor)",
                    format!("set register checkpoint cadence to at most {floor_seq} commits"),
                ));
            }
            RetentionFloor::Days(floor_days)
                if cadence_days.is_some_and(|days| days > floor_days) =>
            {
                let days = cadence_days.unwrap_or(0);
                return Err(Refusal::new(
                    RETENTION_CADENCE_EXCEEDS_FLOOR,
                    exit::REFUSAL,
                    format!(
                        "checkpoint cadence ({days} days) exceeds active retention policy {} (entry {:032x}) floor of {floor_days} days",
                        hex(&active.policy_oid.0),
                        active.control_entry.0
                    ),
                    "plan §8.5 (register checkpoint cadence must not exceed any active retention floor)",
                    format!("set register checkpoint cadence to at most {floor_days} days"),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn scope_covers_subject(scope: &RetentionScope, subject_row: &VertexRow) -> bool {
    match scope {
        RetentionScope::Book => holdable(subject_row),
        RetentionScope::EntryClass(class) => {
            subject_row.labels.contains(&label::ENTRY)
                && matches!(
                    prop(subject_row, property::CLASS),
                    Some(CanonicalScalar::Int(c)) if *c == i64::from(class.0)
                )
        }
        RetentionScope::DocumentKind(kind) => {
            if !subject_row.labels.contains(&label::DOCUMENT) {
                return false;
            }
            let Some(CanonicalScalar::Bytes(b)) = prop(subject_row, property::FA_PAYLOAD) else {
                return false;
            };
            DocumentRecord::decode(b.as_slice()).is_ok_and(|doc| doc.kind == *kind)
        }
        RetentionScope::Subjects(subjects) => subjects
            .binary_search_by_key(&subject_row.vid.0, |s| s.0)
            .is_ok(),
    }
}

fn subject_effective_day(subject_row: &VertexRow, fallback: DateDay) -> DateDay {
    if let Some(CanonicalScalar::Int(day)) = prop(subject_row, property::FA_EFFECTIVE_DAY)
        && let Ok(day_i32) = i32::try_from(*day)
    {
        return DateDay(day_i32);
    }
    fallback
}

fn judge_retention_floors(
    subject: VId,
    subject_row: Option<&VertexRow>,
    covering_policies: &[&ActiveRetentionPolicy],
    cut_at_seq: CommitSeq,
    cut_at_day: Option<DateDay>,
) -> Option<Refusal> {
    let row = subject_row?;
    for active in covering_policies {
        match active.policy.floor {
            RetentionFloor::Commits(floor_seq) => {
                let min_cut_seq = row.created_at.0.saturating_add(floor_seq);
                if cut_at_seq.0 < min_cut_seq {
                    return Some(Refusal::new(
                        RETENTION_FLOOR_ACTIVE,
                        exit::SAFETY,
                        format!(
                            "{:032x} (recorded at seq {}) is inside retention policy {} (entry {:032x}, authority {}, floor {} commits; earliest cut seq is {min_cut_seq}, requested {})",
                            subject.0,
                            row.created_at.0,
                            hex(&active.policy_oid.0),
                            active.control_entry.0,
                            hex(&active.policy.authority.0),
                            floor_seq,
                            cut_at_seq.0,
                        ),
                        "plan §8.5 (retention floors are registered Policy objects; any retention cut that would drop an in-floor object is refused)",
                        format!(
                            "retain {:032x} until at least commit sequence {min_cut_seq}",
                            subject.0
                        ),
                    ));
                }
            }
            RetentionFloor::Days(floor_days) => {
                let origin_day = subject_effective_day(row, active.policy.effective_from);
                let Some(cut_day) = cut_at_day else {
                    return Some(Refusal::new(
                        RETENTION_FLOOR_ACTIVE,
                        exit::SAFETY,
                        format!(
                            "{:032x} (effective {}) is covered by retention policy {} (entry {:032x}, authority {}, floor {} days), and no corroborated TimeEvidence tick bounds the cut",
                            subject.0,
                            origin_day.render(),
                            hex(&active.policy_oid.0),
                            active.control_entry.0,
                            hex(&active.policy.authority.0),
                            floor_days,
                        ),
                        "plan §8.5 (retention floors are registered Policy objects; any retention cut that would drop an in-floor object is refused); §7.1a",
                        format!(
                            "journal a corroborated TimeEvidence tick at least {floor_days} days after {} before requesting a cut of {:032x}",
                            origin_day.render(),
                            subject.0
                        ),
                    ));
                };
                let min_cut_day = i64::from(origin_day.0).saturating_add(i64::from(floor_days));
                if i64::from(cut_day.0) < min_cut_day {
                    return Some(Refusal::new(
                        RETENTION_FLOOR_ACTIVE,
                        exit::SAFETY,
                        format!(
                            "{:032x} (effective {}) is inside retention policy {} (entry {:032x}, authority {}, floor {} days; requested cut at {})",
                            subject.0,
                            origin_day.render(),
                            hex(&active.policy_oid.0),
                            active.control_entry.0,
                            hex(&active.policy.authority.0),
                            floor_days,
                            cut_day.render(),
                        ),
                        "plan §8.5 (retention floors are registered Policy objects; any retention cut that would drop an in-floor object is refused)",
                        format!(
                            "retain {:032x} until at least {floor_days} days after {}",
                            subject.0,
                            origin_day.render()
                        ),
                    ));
                }
            }
        }
    }
    None
}

/// Judge active [`RetentionPolicy`] floors covering `subject` at the book's
/// current frontier and latest corroborated `TimeEvidence` tick UTC day
/// (called by [`crate::evidence::erasure_cut`] after the legal-hold check and
/// before the `FA-REF-088` absence).
pub fn check_erasure_retention_floor<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    subject: VId,
) -> Result<Option<Refusal>, KernelError> {
    let all_policies = active_retention_policies(db, book.book_id)?;
    if all_policies.is_empty() {
        return Ok(None);
    }
    let Some(row) = db.vertex(subject)? else {
        return Ok(None);
    };
    let covering: Vec<&ActiveRetentionPolicy> = all_policies
        .iter()
        .filter(|p| scope_covers_subject(&p.policy.scope, &row))
        .collect();
    if covering.is_empty() {
        return Ok(None);
    }
    let cut_at_seq = db.frontier()?;
    let cut_at_day = match crate::sweep::latest_corroborated_tick(db, None)? {
        Some(tick) => Some(crate::sweep::utc_day(tick.observed_utc_ns)?),
        None => None,
    };
    Ok(judge_retention_floors(
        subject,
        Some(&row),
        &covering,
        cut_at_seq,
        cut_at_day,
    ))
}

/// Evaluate a retention cut on `subject` at `(cut_at_seq, cut_at_day)` (plan §8.5):
///
/// 1. Admits `capability` (`Op::Erase`, whole-book reach, current, not revoked).
/// 2. **Legal hold override:** if `subject` is under any active legal hold,
///    refuses with `FA-REF-117` (`code::LEGAL_HOLD_ACTIVE`, `exit::SAFETY`),
///    naming both the active hold(s) and any active [`RetentionPolicy`] covering
///    `subject`.
/// 3. **Retention floor:** if `subject` lies inside the floor of any active
///    [`RetentionPolicy`] covering it, refuses with [`RETENTION_FLOOR_ACTIVE`]
///    (`FA-REF-199`, `exit::SAFETY`), naming the policy OID, control entry,
///    authority document, and floor.
/// 4. Otherwise returns the substrate's registered-absence refusal (`FA-REF-088`
///    `code::ERASURE_ABSENT`), matching [`crate::evidence::erasure_cut`].
pub fn retention_cut<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
    subject: VId,
    cut_at_seq: CommitSeq,
    cut_at_day: DateDay,
) -> Outcome<()> {
    let at = db.frontier()?;
    if let Err(d) = fa_policy::require(capability, Op::Erase, "evaluating a retention cut")
        .and_then(|()| fa_policy::scope(capability, book.book_id))
        .and_then(|()| fa_policy::reach(capability, &Reach::whole_book(false), None))
        .and_then(|()| fa_policy::current(capability, at))
    {
        return Ok(Err(refusal(&d)));
    }
    if let Err(r) = capability_admitted(db, book, capability)? {
        return Ok(Err(r));
    }

    let subject_row = db.vertex(subject)?;
    let all_policies = active_retention_policies(db, book.book_id)?;
    let covering_policies: Vec<&ActiveRetentionPolicy> = match &subject_row {
        Some(row) => all_policies
            .iter()
            .filter(|p| scope_covers_subject(&p.policy.scope, row))
            .collect(),
        None => all_policies
            .iter()
            .filter(|p| match &p.policy.scope {
                RetentionScope::Book => true,
                RetentionScope::Subjects(s) => s.binary_search_by_key(&subject.0, |v| v.0).is_ok(),
                _ => false,
            })
            .collect(),
    };

    let holds = active_legal_holds(db, book.book_id, subject)?;
    if !holds.is_empty() {
        let named_holds: Vec<String> = holds.iter().map(|h| format!("{:032x}", h.0)).collect();
        let policy_clause = if covering_policies.is_empty() {
            String::new()
        } else {
            let named_policies: Vec<String> = covering_policies
                .iter()
                .map(|p| {
                    format!(
                        "{} (entry {:032x}, floor {})",
                        hex(&p.policy_oid.0),
                        p.control_entry.0,
                        p.policy.floor.describe()
                    )
                })
                .collect();
            format!(
                "; legal hold overrides retention policy [{}]",
                named_policies.join(", ")
            )
        };
        return Ok(Err(Refusal::new(
            code::LEGAL_HOLD_ACTIVE,
            exit::SAFETY,
            format!(
                "{:032x} is under legal hold ({}); retention expiry is pinned while a hold is active{policy_clause}",
                subject.0,
                named_holds.join(", "),
            ),
            "plan §8.5 (a legal hold pins every object in scope against erasure, GC and retention expiry until released; legal holds override retention policies); §14.6",
            "nothing to run while the hold stands: it lifts only by a journaled HoldControl Release of that hold, approved by a Human principal other than the release's preparer",
        )));
    }

    if let Some(r) = judge_retention_floors(
        subject,
        subject_row.as_ref(),
        &covering_policies,
        cut_at_seq,
        Some(cut_at_day),
    ) {
        return Ok(Err(r));
    }

    Ok(Err(Refusal::new(
        code::ERASURE_ABSENT,
        exit::REFUSAL,
        format!(
            "cannot cut {:032x}: retention/erasure tombstones (R-ERASE) are not live in this build",
            subject.0
        ),
        "plan §8.5; Appendix H R-ERASE (substrate erasure tombstones not live; interim: ErasureCut refused)",
        "place a legal hold if the record must be pinned (`fa document hold place`), or use a governed RedactedView for disclosure (`fa document view`)",
    )))
}

#[cfg(test)]
struct TestEnv {
    runtime: asupersync::runtime::Runtime,
    root: asupersync::Cx,
    db: Database<fgdb::MemVfs>,
    book: BookContext,
    authority_oid: Oid,
    subject_doc_vid: VId,
}

#[cfg(test)]
impl TestEnv {
    const PREPARER: VId = VId(7);
    const BOB: VId = VId(22);
    const CAROL: VId = VId(23);

    fn new() -> Self {
        use crate::evidence::{Document, add_document, document_vid};
        use crate::genesis::{BookSpec, create_book};
        use asupersync::Budget;
        use asupersync::runtime::RuntimeBuilder;
        use fa_model::{SealKey, SymbolTable};
        use fa_money::UnitRegistry;
        use fa_time::FiscalCalendar;
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
        let usd = units.lookup("USD").unwrap();
        let calendar = FiscalCalendar::monthly("cal", 1, 1).unwrap();
        let book_id = Id128([9; 16]);
        let spec = BookSpec {
            book_id,
            name: "Retention Co".into(),
            base_unit: usd,
            calendar: calendar.clone(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        let symbols = SymbolTable::compiled();
        runtime
            .block_on(async { create_book(&mut db, &ctx, &spec, &units, &symbols).await })
            .expect("create_book");
        let book = BookContext {
            book_id,
            calendar,
            units,
            seal_key: SealKey([0x11; 32]),
            symbols,
        };
        let authority_doc = runtime
            .block_on(async {
                add_document(
                    &mut db,
                    &ctx,
                    &book,
                    &Document {
                        book_id,
                        kind: 5,
                        mime: "text/plain".into(),
                        grade: 3,
                        retrieved_by: Self::PREPARER,
                        bytes: b"26 U.S.C. 6001 retention order".to_vec(),
                    },
                )
                .await
            })
            .expect("kernel")
            .expect("authority document");
        let subject_doc = runtime
            .block_on(async {
                add_document(
                    &mut db,
                    &ctx,
                    &book,
                    &Document {
                        book_id,
                        kind: 1,
                        mime: "text/plain".into(),
                        grade: 3,
                        retrieved_by: Self::PREPARER,
                        bytes: b"Invoice #1042".to_vec(),
                    },
                )
                .await
            })
            .expect("kernel")
            .expect("subject document");
        Self {
            runtime,
            root,
            db,
            book,
            authority_oid: authority_doc.oid,
            subject_doc_vid: document_vid(&subject_doc.oid),
        }
    }

    fn ctx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn seal(&self, text: &str) -> Erasable<String> {
        Erasable::seal(
            &text.to_string(),
            None,
            &self.book.seal_key,
            [3; 32],
            [4; 24],
        )
    }

    fn cap(principal: VId, ops: &[&str]) -> Capability {
        Capability::embedded(principal, ops).expect("registered ops")
    }

    fn approve(&mut self, approver: VId, digest: [u8; 32]) -> ApprovalRef {
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        let req = crate::policy::ApprovalRequest {
            capability: Self::cap(approver, &["approve"]),
            approved_proposal_digest: digest,
            role: 0,
        };
        self.runtime
            .block_on(async move { crate::policy::record_approval(db, &ctx, book, req).await })
            .expect("kernel")
            .expect("approved")
            .approval()
    }

    fn activate_policy_dual_control(
        &mut self,
        policy: RetentionPolicy,
        key: &[u8],
    ) -> Result<RetentionPolicyActivated, Refusal> {
        let proposal = retention_activation_proposal(
            &self.book,
            Self::PREPARER,
            &policy,
            key,
            self.seal("activate retention policy"),
        )
        .expect("proposal");
        let digest = proposal.proposal_digest().expect("digest");
        let bob = self.approve(Self::BOB, digest);
        let carol = self.approve(Self::CAROL, digest);
        let ctx = self.ctx();
        let db = &mut self.db;
        let book = &self.book;
        let req = RetentionActivationRequest {
            policy,
            proposal,
            capability: Self::cap(Self::PREPARER, &["post", "rule_change"]),
            approvals: vec![bob, carol],
        };
        self.runtime
            .block_on(async move { activate_retention_policy(db, &ctx, book, req).await })
            .expect("kernel")
    }
}

#[cfg(test)]
#[test]
fn cut_inside_hold_refused() {
    use crate::legal_hold::{HoldReach, LegalHoldRequest, place_legal_hold};

    let mut env = TestEnv::new();
    let effective_from = DateDay::from_ymd(2026, 1, 1).unwrap();
    let policy = RetentionPolicy::new(
        env.book.book_id,
        RetentionScope::Book,
        RetentionFloor::Days(30),
        env.authority_oid,
        effective_from,
    );
    let activated = env
        .activate_policy_dual_control(policy, b"ret-pol-1")
        .expect("retention policy activates with dual control");
    let verified = verify_retention_policies(&env.db, env.book.book_id).expect("verify");
    assert!(verified.is_green(), "drifts: {:?}", verified.drifts);
    assert_eq!(verified.active_policies.len(), 1);
    assert_eq!(verified.active_policies[0].policy_oid, activated.policy_oid);

    // Place a legal hold on the subject document.
    let ctx = env.ctx();
    let hold_cap = TestEnv::cap(TestEnv::PREPARER, &["hold"]);
    let hold_req = LegalHoldRequest {
        principal: TestEnv::PREPARER,
        reach: HoldReach::Subjects(vec![env.subject_doc_vid]),
        authority: env.authority_oid,
        effective_date: effective_from,
        idempotency_key: b"hold-subject-1".to_vec(),
        description: env.seal("litigation preservation hold"),
    };
    let placed = env
        .runtime
        .block_on(async {
            place_legal_hold(&mut env.db, &ctx, &env.book, &hold_cap, hold_req).await
        })
        .expect("kernel")
        .expect("legal hold placed");

    // Attempt a retention cut well past the 30-day retention floor while the legal hold is active.
    let erase_cap = TestEnv::cap(TestEnv::PREPARER, &["erase"]);
    let cut_day = DateDay::from_ymd(2027, 6, 1).unwrap();
    let refusal = retention_cut(
        &env.db,
        &env.book,
        &erase_cap,
        env.subject_doc_vid,
        CommitSeq(1000),
        cut_day,
    )
    .expect("kernel")
    .expect_err("cut inside legal hold must be refused");

    assert_eq!(refusal.code, code::LEGAL_HOLD_ACTIVE);
    assert_eq!(refusal.exit, exit::SAFETY);
    let hold_hex = format!("{:032x}", placed.hold.0);
    let policy_hex = hex(&activated.policy_oid.0);
    assert!(
        refusal.message.contains(&hold_hex),
        "refusal must name the active hold {hold_hex}: {}",
        refusal.message
    );
    assert!(
        refusal.message.contains(&policy_hex),
        "refusal must name the active retention policy {policy_hex}: {}",
        refusal.message
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_policy_round_trips_and_validates() {
        let policy = RetentionPolicy::new(
            Id128([3; 16]),
            RetentionScope::Subjects(vec![VId(2), VId(9)]),
            RetentionFloor::Commits(128),
            Oid([0xaa; 32]),
            DateDay::from_ymd(2026, 3, 1).unwrap(),
        );
        assert!(policy.validate().is_ok());
        let bytes = policy.canonical_bytes().unwrap();
        let decoded = RetentionPolicy::decode(&bytes).unwrap();
        assert_eq!(decoded, policy);
        assert_eq!(decoded.policy_oid().unwrap(), policy.policy_oid().unwrap());

        let zero_floor = RetentionPolicy::new(
            Id128([3; 16]),
            RetentionScope::Book,
            RetentionFloor::Days(0),
            Oid([0xaa; 32]),
            DateDay::from_ymd(2026, 3, 1).unwrap(),
        );
        assert!(zero_floor.validate().is_err());
        assert!(RetentionPolicy::decode(&zero_floor.canonical_bytes().unwrap()).is_err());
    }

    #[test]
    fn cut_inside_retention_floor_is_refused_and_cadence_is_checked() {
        let mut env = TestEnv::new();
        let effective_from = DateDay::from_ymd(2026, 1, 1).unwrap();
        let policy = RetentionPolicy::new(
            env.book.book_id,
            RetentionScope::Book,
            RetentionFloor::Commits(50),
            env.authority_oid,
            effective_from,
        );
        let activated = env
            .activate_policy_dual_control(policy, b"ret-pol-floor")
            .expect("activated");
        let policies = active_retention_policies(&env.db, env.book.book_id).unwrap();
        assert_eq!(policies.len(), 1);

        // Checkpoint cadence within floor is admitted; exceeding floor is refused.
        assert!(check_checkpoint_cadence(&policies, 50, None).is_ok());
        let cadence_refusal = check_checkpoint_cadence(&policies, 51, None).unwrap_err();
        assert_eq!(cadence_refusal.code, RETENTION_CADENCE_EXCEEDS_FLOOR);

        // Cut inside the 50-commit floor is refused naming the policy OID.
        let erase_cap = TestEnv::cap(TestEnv::PREPARER, &["erase"]);
        let refusal = retention_cut(
            &env.db,
            &env.book,
            &erase_cap,
            env.subject_doc_vid,
            CommitSeq(10),
            DateDay::from_ymd(2026, 2, 1).unwrap(),
        )
        .expect("kernel")
        .expect_err("cut inside floor must be refused");
        assert_eq!(refusal.code, RETENTION_FLOOR_ACTIVE);
        assert_eq!(refusal.exit, exit::SAFETY);
        assert!(refusal.message.contains(&hex(&activated.policy_oid.0)));
    }

    #[test]
    fn single_approver_retention_activation_is_refused_by_dual_control() {
        let mut env = TestEnv::new();
        let policy = RetentionPolicy::new(
            env.book.book_id,
            RetentionScope::Book,
            RetentionFloor::Days(365),
            env.authority_oid,
            DateDay::from_ymd(2026, 1, 1).unwrap(),
        );
        let proposal = retention_activation_proposal(
            &env.book,
            TestEnv::PREPARER,
            &policy,
            b"ret-single-approver",
            env.seal("single approver attempt"),
        )
        .unwrap();
        let digest = proposal.proposal_digest().unwrap();
        let bob_only = env.approve(TestEnv::BOB, digest);
        let ctx = env.ctx();
        let req = RetentionActivationRequest {
            policy,
            proposal,
            capability: TestEnv::cap(TestEnv::PREPARER, &["post", "rule_change"]),
            approvals: vec![bob_only],
        };
        let refusal = env
            .runtime
            .block_on(async { activate_retention_policy(&mut env.db, &ctx, &env.book, req).await })
            .expect("kernel")
            .expect_err("single approval must be refused");
        assert_eq!(refusal.exit, exit::SAFETY);
    }

    #[test]
    fn erasure_cut_judges_active_days_and_commits_retention_floors() {
        let mut env = TestEnv::new();
        let erase_cap = TestEnv::cap(TestEnv::PREPARER, &["erase"]);

        // 1. With no retention policy active, erasure_cut answers FA-REF-088 (ERASURE_ABSENT).
        let r0 = crate::evidence::erasure_cut(&env.db, &env.book, &erase_cap, env.subject_doc_vid)
            .expect("kernel");
        assert_eq!((r0.code, r0.exit), (code::ERASURE_ABSENT, exit::REFUSAL));

        // 2. Activate a 1-commit floor: frontier already exceeds created_at + 1, so out-of-floor
        // subject falls through to FA-REF-088.
        let short_commits = RetentionPolicy::new(
            env.book.book_id,
            RetentionScope::Book,
            RetentionFloor::Commits(1),
            env.authority_oid,
            DateDay::from_ymd(2026, 1, 1).unwrap(),
        );
        env.activate_policy_dual_control(short_commits, b"ret-short-commits")
            .expect("activated");
        let r1 = crate::evidence::erasure_cut(&env.db, &env.book, &erase_cap, env.subject_doc_vid)
            .expect("kernel");
        assert_eq!((r1.code, r1.exit), (code::ERASURE_ABSENT, exit::REFUSAL));

        // 3. Activate a 100-commit floor: subject is inside the floor -> FA-REF-199 (exit 7).
        let long_commits = RetentionPolicy::new(
            env.book.book_id,
            RetentionScope::Book,
            RetentionFloor::Commits(100),
            env.authority_oid,
            DateDay::from_ymd(2026, 1, 1).unwrap(),
        );
        let act_commits = env
            .activate_policy_dual_control(long_commits, b"ret-long-commits")
            .expect("activated");
        let r2 = crate::evidence::erasure_cut(&env.db, &env.book, &erase_cap, env.subject_doc_vid)
            .expect("kernel");
        assert_eq!((r2.code, r2.exit), (RETENTION_FLOOR_ACTIVE, exit::SAFETY));
        assert!(r2.message.contains(&hex(&act_commits.policy_oid.0)));

        // 4. On a fresh book with a Days(30) floor and no corroborated TimeEvidence tick,
        // erasure_cut fails closed with FA-REF-199 naming the missing time evidence.
        let mut env_days = TestEnv::new();
        let days_pol = RetentionPolicy::new(
            env_days.book.book_id,
            RetentionScope::Book,
            RetentionFloor::Days(30),
            env_days.authority_oid,
            DateDay::from_ymd(2026, 1, 1).unwrap(),
        );
        let act_days = env_days
            .activate_policy_dual_control(days_pol, b"ret-days-floor")
            .expect("activated");
        let r3 = crate::evidence::erasure_cut(
            &env_days.db,
            &env_days.book,
            &erase_cap,
            env_days.subject_doc_vid,
        )
        .expect("kernel");
        assert_eq!((r3.code, r3.exit), (RETENTION_FLOOR_ACTIVE, exit::SAFETY));
        assert!(r3.message.contains("no corroborated TimeEvidence tick"));
        assert!(r3.message.contains(&hex(&act_days.policy_oid.0)));

        // Journal a corroborated tick on 2026-01-10 (inside the 30-day floor from 2026-01-01):
        // still refused with FA-REF-199.
        let sys_vid = crate::rows::system_principal(env_days.book.book_id);
        let tick_cap = Capability::new(
            sys_vid,
            fa_policy::Profile::System,
            &[Op::Witness],
            TestEnv::BOB,
        )
        .unwrap();
        let jan10_ns =
            u64::try_from(DateDay::from_ymd(2026, 1, 10).unwrap().0).unwrap() * 86_400_000_000_000;
        let ctx = env_days.ctx();
        let tick_desc = env_days.seal("tick jan 10");
        env_days
            .runtime
            .block_on(async {
                crate::sweep::record_tick(
                    &mut env_days.db,
                    &ctx,
                    &env_days.book,
                    crate::sweep::TickRequest {
                        observed_utc_ns: jan10_ns,
                        source: crate::sweep::SOURCE_DAEMON_CLOCK,
                        monotonic_ok: true,
                        principal_ref: sys_vid,
                        capability: tick_cap.clone(),
                        idempotency_key: b"tick-jan10".to_vec(),
                        description: tick_desc,
                    },
                )
                .await
            })
            .expect("kernel")
            .expect("tick recorded");
        let r4 = crate::evidence::erasure_cut(
            &env_days.db,
            &env_days.book,
            &erase_cap,
            env_days.subject_doc_vid,
        )
        .expect("kernel");
        assert_eq!((r4.code, r4.exit), (RETENTION_FLOOR_ACTIVE, exit::SAFETY));
        assert!(r4.message.contains("requested cut at 2026-01-10"));

        // Journal a corroborated tick on 2026-02-05 (outside the 30-day floor):
        // falls through to FA-REF-088.
        let feb5_ns =
            u64::try_from(DateDay::from_ymd(2026, 2, 5).unwrap().0).unwrap() * 86_400_000_000_000;
        let tick_desc2 = env_days.seal("tick feb 5");
        env_days
            .runtime
            .block_on(async {
                crate::sweep::record_tick(
                    &mut env_days.db,
                    &ctx,
                    &env_days.book,
                    crate::sweep::TickRequest {
                        observed_utc_ns: feb5_ns,
                        source: crate::sweep::SOURCE_DAEMON_CLOCK,
                        monotonic_ok: true,
                        principal_ref: sys_vid,
                        capability: tick_cap,
                        idempotency_key: b"tick-feb5".to_vec(),
                        description: tick_desc2,
                    },
                )
                .await
            })
            .expect("kernel")
            .expect("tick recorded");
        let r5 = crate::evidence::erasure_cut(
            &env_days.db,
            &env_days.book,
            &erase_cap,
            env_days.subject_doc_vid,
        )
        .expect("kernel");
        assert_eq!((r5.code, r5.exit), (code::ERASURE_ABSENT, exit::REFUSAL));
    }
}
