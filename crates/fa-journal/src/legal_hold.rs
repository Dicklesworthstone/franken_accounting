//! Legal holds (plan §8.5, §14.6; fa-txf).
//!
//! A legal hold `{scope, authority, issued_by}` pins every subject in its
//! scope — entries, documents and parties the book holds — against erasure,
//! garbage collection and retention expiry until an authorized principal
//! releases it. Placing and releasing are `HoldControl` control entries
//! (book-scoped, undated) whose payload is
//! `HoldEvent { scope_digest, authority_oid, kind: Place | Release }`; the
//! scope itself rides in extension 4, `fa:legal-hold-scope:v1`: a Place
//! carries `0u8 ‖ list(u128 subject)` strictly ascending, a Release
//! `1u8 ‖ u128 hold`, and `scope_digest = H("fa:legal-hold-scope:v1" ‖
//! scope)`.
//!
//! Each held subject has one `LegalHoldCell` at
//! `H("fa:vid:legal-hold-cell:v1" ‖ book ‖ subject)` whose `legal_holds`
//! lists the holds active on it, ascending. A Place or a Release moves every
//! cell it touches by compare-and-set in the transaction that journals it,
//! so a concurrent place, release or erasure is a typed conflict, never a
//! lost update. A Place draws a `HOLDS` edge to each subject. A Release's
//! identity is `H("fa:vid:legal-hold-release:v1" ‖ book ‖ hold)` — one per
//! hold — and it carries the approvals the `legal-hold-release` row requires
//! (a Human principal other than its preparer), bound to its proposal
//! through a [`ReleasePlan`].
//!
//! A book-scope Place (`fa document hold place --through <seq>`; the
//! receiver's pre-appointment trunk, plan §15.6) carries `2u8 ‖ u64
//! through` instead of a subject list: it pins every entry, document and
//! party recorded at or before `through`, however many there are. Its
//! active set rides one book-level cell, [`book_hold_cell_vid`], moved by
//! compare-and-set exactly like a subject's, and [`active_legal_holds`]
//! reports it on every subject it covers.
//!
//! What a hold does not pin (ruling 3251): the two-phase reservation sweep.
//! A held Pending still expires at its deadline (plan §5.4); the hold
//! preserves the record, not the reservation.
//!
//! Erasure is a registered absence in this build (Appendix H R-ERASE):
//! `evidence::erasure_cut` admits the `erase` op, then refuses FA-REF-117
//! while a hold is active on the subject and FA-REF-088 otherwise. Garbage
//! collection and retention expiry are the substrate's (not live); whatever
//! acts for them asks [`pinned`] first.

use fa_model::entry::LEGAL_HOLD_SCOPE_EXTENSION;
use fa_model::limits::{MAX_ACTIVE_LEGAL_HOLDS, MAX_LEGAL_HOLD_SUBJECTS};
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ApprovalRef, ControlPayload, DecodeError, Entry, EntryClass, EntryOrigin, EntryPayload,
    Erasable, Id128, Oid, Reader, Writer, domain_digest, entry_mirrors, entry_vid,
};
use fa_policy::{Capability, Intent, Party};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::custody::witness_custody;
use crate::evidence::{document_vid, drift, hex, verify_row};
use crate::genesis::BookContext;
use crate::policy::{authorize_approvals, capability_witness, epoch_witness, refusal, steward};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{book_root, edge_id, prop, scalar_bytes};
use crate::sweep::decode_entry;

/// Domain of a hold's `scope_digest`.
pub const SCOPE_DOMAIN: &[u8] = b"fa:legal-hold-scope:v1";
/// `HoldEvent.kind` of a placement (plan Appendix A: `Place | Release`).
pub const PLACE: u8 = 0;
/// `HoldEvent.kind` of a release.
pub const RELEASE: u8 = 1;
/// The scope tag of a book-scope Place (`2u8 ‖ u64 through`). Its
/// `HoldEvent.kind` is [`PLACE`].
pub const BOOK_THROUGH: u8 = 2;

/// What a legal hold pins (plan §8.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pinned {
    Erasure,
    Collection,
    RetentionExpiry,
}

impl Pinned {
    fn name(self) -> &'static str {
        match self {
            Self::Erasure => "erasure",
            Self::Collection => "garbage collection",
            Self::RetentionExpiry => "retention expiry",
        }
    }
}

/// A `HoldControl` entry's scope, as extension 4 carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    /// The subjects a Place pins, strictly ascending.
    Place(Vec<VId>),
    /// The Place a Release releases.
    Release(VId),
    /// A book-scope Place: every entry, document and party recorded at or
    /// before this sequence (`>= 1`).
    Book(CommitSeq),
}

impl Scope {
    /// `0u8 ‖ list(u128 subject)`, `1u8 ‖ u128 hold` or `2u8 ‖ u64 through`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::new();
        match self {
            Self::Place(subjects) => {
                w.u8(PLACE).list(subjects, |w, s| {
                    w.u128(s.0);
                });
            }
            Self::Release(hold) => {
                w.u8(RELEASE).u128(hold.0);
            }
            Self::Book(through) => {
                w.u8(BOOK_THROUGH).u64(through.0);
            }
        }
        w.finish().map_err(|e| KernelError::Model(e.into()))
    }

    /// Decode a scope; refuses an unknown kind, an empty or unsorted
    /// subject list, one past `max_legal_hold_subjects`, a book scope
    /// through sequence 0, and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let scope = match r.u8("legal_hold.kind")? {
            PLACE => {
                let subjects = r.list(MAX_LEGAL_HOLD_SUBJECTS, "legal_hold.subjects", |r| {
                    Ok(VId(r.u128("legal_hold.subject")?))
                })?;
                if subjects.is_empty() {
                    return Err(r.invalid("legal_hold.subjects"));
                }
                if !subjects.windows(2).all(|w| w[0].0 < w[1].0) {
                    return Err(r.unsorted("legal_hold.subjects"));
                }
                Self::Place(subjects)
            }
            RELEASE => Self::Release(VId(r.u128("legal_hold.hold")?)),
            BOOK_THROUGH => match r.u64("legal_hold.through")? {
                0 => return Err(r.invalid("legal_hold.through")),
                through => Self::Book(CommitSeq(through)),
            },
            t => return Err(r.bad_tag("legal_hold.kind", t)),
        };
        r.finish()?;
        Ok(scope)
    }

    /// `H("fa:legal-hold-scope:v1" ‖ canonical_bytes)`.
    pub fn digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(SCOPE_DOMAIN, &[&self.canonical_bytes()?]))
    }

    fn kind(&self) -> u8 {
        match self {
            Self::Place(_) | Self::Book(_) => PLACE,
            Self::Release(_) => RELEASE,
        }
    }
}

fn vid_of(domain: &[u8], book: Id128, of: VId) -> VId {
    let d = domain_digest(domain, &[&book.0, &of.0.to_le_bytes()]);
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d[..16]);
    VId(u128::from_le_bytes(lo))
}

/// `vid(cell) = H("fa:vid:legal-hold-cell:v1" ‖ book ‖ subject)`.
#[must_use]
pub fn legal_hold_cell_vid(book: Id128, subject: VId) -> VId {
    vid_of(b"fa:vid:legal-hold-cell:v1", book, subject)
}

/// `vid(cell) = H("fa:vid:legal-hold-book-cell:v1" ‖ book)`: the one cell
/// listing the book's active book-scope holds.
#[must_use]
pub fn book_hold_cell_vid(book: Id128) -> VId {
    let d = domain_digest(b"fa:vid:legal-hold-book-cell:v1", &[&book.0]);
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d[..16]);
    VId(u128::from_le_bytes(lo))
}

/// `vid(release) = H("fa:vid:legal-hold-release:v1" ‖ book ‖ hold)`: one
/// release per hold.
#[must_use]
pub fn release_vid(book: Id128, hold: VId) -> VId {
    vid_of(b"fa:vid:legal-hold-release:v1", book, hold)
}

fn holds_scalar(holds: &[VId]) -> Result<CanonicalScalar, KernelError> {
    let mut w = Writer::new();
    w.list(holds, |w, h| {
        w.u128(h.0);
    });
    scalar_bytes(
        "legal_holds",
        w.finish().map_err(|e| KernelError::Model(e.into()))?,
    )
}

/// A cell's active holds, verified ascending.
fn holds_of(row: &VertexRow) -> Result<Vec<VId>, KernelError> {
    let corrupt =
        |why: String| KernelError::Corrupt(format!("legal hold cell {:032x}: {why}", row.vid.0));
    let Some(CanonicalScalar::Bytes(b)) = prop(row, property::LEGAL_HOLDS) else {
        return Err(corrupt("carries no legal_holds".into()));
    };
    let mut r = Reader::new(b.as_slice());
    let holds = r
        .list(MAX_ACTIVE_LEGAL_HOLDS, "legal_holds", |r| {
            Ok(VId(r.u128("legal_hold")?))
        })
        .map_err(|e| corrupt(e.to_string()))?;
    r.finish().map_err(|e| corrupt(e.to_string()))?;
    if !holds.windows(2).all(|w| w[0].0 < w[1].0) {
        return Err(corrupt("legal_holds is not strictly ascending".into()));
    }
    Ok(holds)
}

/// What a placement pins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HoldReach {
    /// The named entries, documents and parties, each once, in any order.
    Subjects(Vec<VId>),
    /// Every entry, document and party recorded at or before this sequence
    /// (a book-scope hold; plan §15.6, the receiver's pre-appointment
    /// trunk). The sequence must be recorded: `1..=` the head.
    Through(CommitSeq),
    /// As `Through` at the head when the hold is placed (after authority is
    /// admitted): the same request again is the recorded hold.
    ThroughHead,
}

/// Place a legal hold.
#[derive(Clone, Debug)]
pub struct LegalHoldRequest {
    /// Who places it (`issued_by`; the capability's holder).
    pub principal: VId,
    /// What it pins.
    pub reach: HoldReach,
    /// The document that authorizes it (an order, a preservation letter):
    /// one this book holds, verified, with a complete custody chain.
    pub authority: Oid,
    /// The business date it is recorded under (the class is undated: it
    /// resolves no period).
    pub effective_date: DateDay,
    pub idempotency_key: Vec<u8>,
    pub description: Erasable<String>,
}

/// The outcome of a placement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegalHoldPlaced {
    /// The Place entry: the hold's identity.
    pub hold: VId,
    /// Its subjects, ascending (empty for a book-scope hold).
    pub subjects: Vec<VId>,
    /// A book-scope hold's sequence: it pins everything recorded at or
    /// before it.
    pub through: Option<CommitSeq>,
    pub recorded_at: CommitSeq,
    /// The same placement was already recorded; nothing was written.
    pub already_recorded: bool,
}

/// A placed hold, as journaled, with its release if one is recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegalHold {
    pub hold: VId,
    pub authority: Oid,
    /// The named subjects, ascending (empty for a book-scope hold).
    pub subjects: Vec<VId>,
    /// A book-scope hold's sequence.
    pub through: Option<CommitSeq>,
    pub issued_by: VId,
    pub placed_at: CommitSeq,
    /// The release entry and the sequence that recorded it.
    pub released: Option<(VId, CommitSeq)>,
}

/// A planned release (the period plan's shape, R4): approvers bind
/// [`ReleasePlan::proposal_digest`]; the committing process passes the plan
/// back, so the release commits exactly the proposal that was approved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleasePlan {
    pub hold: VId,
    /// The hold's authority, read when the plan was made: a release names
    /// the authority it lifts.
    pub authority: Oid,
    pub principal_ref: VId,
    pub effective_date: DateDay,
    pub idempotency_key: Vec<u8>,
    pub description: Erasable<String>,
}

impl ReleasePlan {
    /// The proposal this plan commits.
    pub fn proposal(&self, book: &BookContext) -> Result<EntryPayload, KernelError> {
        control_proposal(
            book,
            &Scope::Release(self.hold),
            self.authority,
            self.principal_ref,
            self.effective_date,
            &self.idempotency_key,
            self.description.clone(),
        )
    }

    /// The digest an approval of this release binds.
    pub fn proposal_digest(&self, book: &BookContext) -> Result<[u8; 32], KernelError> {
        Ok(self.proposal(book)?.proposal_digest()?)
    }
}

/// The outcome of a release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegalHoldReleased {
    pub release: VId,
    pub hold: VId,
    pub recorded_at: CommitSeq,
    /// This release was already recorded; nothing was written.
    pub already_recorded: bool,
}

fn control_proposal(
    book: &BookContext,
    scope: &Scope,
    authority: Oid,
    principal: VId,
    effective_date: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
) -> Result<EntryPayload, KernelError> {
    let bytes = scope.canonical_bytes()?;
    let scope_digest = domain_digest(SCOPE_DOMAIN, &[&bytes]);
    Ok(EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::HOLD_CONTROL,
        effective_date,
        document_date: None,
        description,
        effective_period: None,
        legs: Vec::new(),
        control: Some(ControlPayload::HoldEvent {
            scope_digest,
            authority_oid: authority,
            kind: scope.kind(),
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: idempotency_key.to_vec(),
        origin: EntryOrigin::Control {
            control_kind: fa_model::ControlKind::LEGAL_HOLD,
            spec_body_digest: scope_digest,
        },
        principal_ref: principal,
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: vec![(LEGAL_HOLD_SCOPE_EXTENSION, bytes)],
        tags: Vec::new(),
    })
}

/// A stored `HoldControl` entry's scope and authority, the scope checked
/// against the digest its payload carries. `None` for any other entry.
fn hold_event(entry: &Entry) -> Result<Option<(Scope, Oid)>, KernelError> {
    let p = &entry.proposal;
    let (
        &EntryClass::HOLD_CONTROL,
        Some(ControlPayload::HoldEvent {
            scope_digest,
            authority_oid,
            kind,
        }),
    ) = (&p.class, &p.control)
    else {
        return Ok(None);
    };
    let corrupt = |why: &str| KernelError::Corrupt(format!("HoldControl entry: {why}"));
    let Some((_, bytes)) = p
        .extensions
        .iter()
        .find(|(t, _)| *t == LEGAL_HOLD_SCOPE_EXTENSION)
    else {
        return Err(corrupt("no fa:legal-hold-scope:v1 extension"));
    };
    let scope = Scope::decode(bytes).map_err(|e| corrupt(&e.to_string()))?;
    if scope.kind() != *kind || domain_digest(SCOPE_DOMAIN, &[bytes]) != *scope_digest {
        return Err(corrupt("its scope does not match the HoldEvent it rides"));
    }
    Ok(Some((scope, *authority_oid)))
}

/// The Place stored at `row`, if `row` is one.
fn placed_of(row: &VertexRow) -> Result<Option<LegalHold>, KernelError> {
    if !row.labels.contains(&label::ENTRY) {
        return Ok(None);
    }
    let entry = decode_entry(row)?;
    let (subjects, through, authority) = match hold_event(&entry)? {
        Some((Scope::Place(subjects), authority)) => (subjects, None, authority),
        Some((Scope::Book(through), authority)) => (Vec::new(), Some(through), authority),
        _ => return Ok(None),
    };
    Ok(Some(LegalHold {
        hold: row.vid,
        authority,
        subjects,
        through,
        issued_by: entry.proposal.principal_ref,
        placed_at: row.created_at,
        released: None,
    }))
}

/// The legal hold placed as `hold`, with its release if one is recorded;
/// `None` when `hold` is not a Place in this book.
pub fn read_legal_hold<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: Id128,
    hold: VId,
) -> Result<Option<LegalHold>, KernelError> {
    let Some(row) = db.vertex(hold)? else {
        return Ok(None);
    };
    let Some(mut placed) = placed_of(&row)? else {
        return Ok(None);
    };
    let release = release_vid(book, hold);
    placed.released = db.vertex(release)?.map(|r| (release, r.created_at));
    Ok(Some(placed))
}

/// The holds active on `subject`, ascending (empty when none ever was):
/// those that name it and the book-scope holds that cover it (it is an
/// entry, document or party recorded at or before their sequence).
pub fn active_legal_holds<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: Id128,
    subject: VId,
) -> Result<Vec<VId>, KernelError> {
    let mut holds = match db.vertex(legal_hold_cell_vid(book, subject))? {
        Some(row) => holds_of(&row)?,
        None => Vec::new(),
    };
    holds.extend(book_holds_covering(db, book, subject)?);
    holds.sort_by_key(|h| h.0);
    holds.dedup();
    Ok(holds)
}

/// The active book-scope holds whose sequence `subject` was recorded at or
/// before; none when `subject` is not an entry, document or party.
fn book_holds_covering<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: Id128,
    subject: VId,
) -> Result<Vec<VId>, KernelError> {
    let Some(cell) = db.vertex(book_hold_cell_vid(book))? else {
        return Ok(Vec::new());
    };
    let active = holds_of(&cell)?;
    if active.is_empty() {
        return Ok(Vec::new());
    }
    let Some(row) = db.vertex(subject)? else {
        return Ok(Vec::new());
    };
    if !holdable(&row) {
        return Ok(Vec::new());
    }
    let mut covering = Vec::new();
    for hold in active {
        let through = match db.vertex(hold)?.as_ref().map(placed_of).transpose()? {
            Some(Some(LegalHold {
                through: Some(through),
                ..
            })) => through,
            _ => {
                return Err(KernelError::Corrupt(format!(
                    "the book hold cell names {:032x}, which is not a book-scope placement",
                    hold.0
                )));
            }
        };
        if row.created_at <= through {
            covering.push(hold);
        }
    }
    Ok(covering)
}

/// A legal hold pins entries, documents and parties.
fn holdable(row: &VertexRow) -> bool {
    [label::ENTRY, label::DOCUMENT, label::PARTY]
        .iter()
        .any(|l| row.labels.contains(l))
}

/// FA-REF-117 when a hold is active on `subject`: the refusal any act that
/// would destroy or let lapse what the hold preserves returns.
pub fn pinned<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: Id128,
    subject: VId,
    act: Pinned,
) -> Result<Option<Refusal>, KernelError> {
    let holds = active_legal_holds(db, book, subject)?;
    if holds.is_empty() {
        return Ok(None);
    }
    let named: Vec<String> = holds.iter().map(|h| format!("{:032x}", h.0)).collect();
    Ok(Some(Refusal::new(
        code::LEGAL_HOLD_ACTIVE,
        exit::SAFETY,
        format!(
            "{:032x} is under legal hold ({}); {} is pinned while a hold is active",
            subject.0,
            named.join(", "),
            act.name()
        ),
        "plan §8.5 (a legal hold pins every object in scope against erasure, GC and retention expiry until released); §14.6",
        "nothing to run while the hold stands: it lifts only by a journaled HoldControl Release of that hold, approved by a Human principal other than the release's preparer",
    )))
}

fn structure(message: impl Into<String>, fix: &str) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §8.5 (a legal hold names its authority document and 1..=max_legal_hold_subjects distinct subjects)",
        fix,
    )
}

fn unknown_hold(hold: VId, why: &str) -> Refusal {
    Refusal::new(
        code::LEGAL_HOLD_UNKNOWN,
        exit::REFUSAL,
        format!("{:032x} {why}", hold.0),
        "plan §8.5 (a release names an active legal hold of this book)",
        "name the vid a placement returned for a hold that is still active; a hold is released once",
    )
}

fn unholdable(subject: VId, why: &str) -> Refusal {
    Refusal::new(
        code::LEGAL_HOLD_SUBJECT,
        exit::REFUSAL,
        format!("subject {:032x} {why}", subject.0),
        "plan §8.5 (a legal hold pins entries, documents and parties the book holds)",
        "name the vids of entries, documents or parties recorded in this book",
    )
}

fn conflict(what: &str) -> Refusal {
    Refusal::new(
        code::CONFLICT,
        exit::CONFLICT,
        format!("a concurrent commit invalidated a witness this {what} read"),
        "FG-LAW-FCW-01 (first committer wins)",
        "re-read the subject's legal holds and retry",
    )
}

/// Authority before any read (doctrine 8): the HoldControl row's preparer
/// op for `transition`, the capability the principal's own and current.
pub(crate) fn admit<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
    principal: VId,
    transition: &str,
) -> Outcome<()> {
    let op = steward()?
        .transition_op("HoldControl", transition)
        .ok_or_else(|| {
            KernelError::Corrupt(format!(
                "sod_policy.toml registers no HoldControl {transition} rule; the hold is refused, never unconstrained"
            ))
        })?;
    if let Err(d) = fa_policy::admit(
        capability,
        &Intent {
            principal,
            trunk: true,
            op,
            book: book.book_id,
            legs: &[],
        },
    ) {
        return Ok(Err(refusal(&d)));
    }
    if let Err(d) = fa_policy::current(capability, db.frontier()?) {
        return Ok(Err(refusal(&d)));
    }
    Ok(Ok(()))
}

fn placed_or_conflict(
    book: &BookContext,
    row: &VertexRow,
    proposal: &EntryPayload,
    digest: &[u8; 32],
) -> Outcome<LegalHoldPlaced> {
    let stored = decode_entry(row)?;
    let same = &stored.proposal_digest == digest
        || matches!(
            (
                stored.proposal.semantic_digest(&book.seal_key),
                proposal.semantic_digest(&book.seal_key),
            ),
            (Ok(a), Ok(b)) if a == b
        );
    match (same, hold_event(&stored)?) {
        (true, Some((Scope::Place(subjects), _))) => Ok(Ok(LegalHoldPlaced {
            hold: row.vid,
            subjects,
            through: None,
            recorded_at: row.created_at,
            already_recorded: true,
        })),
        (true, Some((Scope::Book(through), _))) => Ok(Ok(LegalHoldPlaced {
            hold: row.vid,
            subjects: Vec::new(),
            through: Some(through),
            recorded_at: row.created_at,
            already_recorded: true,
        })),
        _ => Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            format!(
                "idempotency key reused with a different entry; the recorded entry is {:032x}",
                row.vid.0
            ),
            "plan §4.9 (identity is derived from the key; content is bound by proposal_digest)",
            "resubmit the identical hold to get its recorded outcome, or use a new idempotency key",
        ))),
    }
}

/// Place a legal hold (plan §8.5): refused before any read on structure or
/// authority (the `legal-hold-place` row's preparer op, a current
/// capability that is the principal's own). Then, in one transaction: the
/// capability not revoked; the hold's identity (the same hold again is its
/// recorded outcome); the SoD rule over the witnessed policy epoch; the
/// authority document held, verified and its custody complete; each subject
/// an entry, document or party the book holds; each subject's cell moved by
/// compare-and-set to include the hold, a `HOLDS` edge to it, and the Place.
pub async fn place_legal_hold<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    req: LegalHoldRequest,
) -> Outcome<LegalHoldPlaced> {
    // Structure before authority, and authority before any read: a subject
    // list's shape and a book scope's sequence are judged without the book.
    let named = match &req.reach {
        HoldReach::Subjects(named) => {
            let mut subjects = named.clone();
            if subjects.is_empty() || subjects.len() > MAX_LEGAL_HOLD_SUBJECTS {
                return Ok(Err(structure(
                    format!(
                        "a legal hold pins 1..={MAX_LEGAL_HOLD_SUBJECTS} subjects; this one names {}",
                        subjects.len()
                    ),
                    "name each subject the hold preserves; place a larger scope as several holds under the same authority, or hold the whole recorded book with --through",
                )));
            }
            subjects.sort_by_key(|s| s.0);
            if subjects.windows(2).any(|w| w[0].0 == w[1].0) {
                return Ok(Err(structure(
                    "a legal hold names each subject once",
                    "remove the repeated subject",
                )));
            }
            Some(Scope::Place(subjects))
        }
        HoldReach::Through(CommitSeq(0)) => {
            return Ok(Err(structure(
                "a book-scope hold pins what is recorded through a sequence of at least 1; sequence 0 records nothing",
                "hold through HEAD or a recorded sequence: fa document hold place --authority <oid> --through HEAD",
            )));
        }
        HoldReach::Through(through) => Some(Scope::Book(*through)),
        HoldReach::ThroughHead => None,
    };
    if let Err(r) = admit(db, book, capability, req.principal, "Place")? {
        return Ok(Err(r));
    }
    let hold = entry_vid(
        book.book_id,
        &req.principal.0.to_le_bytes(),
        &req.idempotency_key,
    );
    let scope = match named {
        Some(scope) => scope,
        // The head when the hold was first placed: the same request again is
        // the recorded hold, however far the head has moved since.
        None => match db
            .vertex(hold)?
            .as_ref()
            .map(placed_of)
            .transpose()?
            .flatten()
        {
            Some(LegalHold {
                through: Some(through),
                ..
            }) => Scope::Book(through),
            _ => Scope::Book(db.frontier()?),
        },
    };
    if let Scope::Book(through) = &scope {
        // This exclusive handle's head is the transaction's basis below.
        let head = db.frontier()?;
        if *through > head {
            return Ok(Err(Refusal::new(
                code::LEGAL_HOLD_SUBJECT,
                exit::REFUSAL,
                format!(
                    "sequence {} is not recorded in this book; its head is {}",
                    through.0, head.0
                ),
                "plan §8.5, §15.6 (a book-scope hold pins what the book has recorded through its sequence)",
                format!(
                    "hold through HEAD or a sequence at or before {}: fa document hold place --authority <oid> --through HEAD",
                    head.0
                ),
            )));
        }
    }
    let proposal = control_proposal(
        book,
        &scope,
        req.authority,
        req.principal,
        req.effective_date,
        &req.idempotency_key,
        req.description,
    )?;
    if let Err(e) = proposal.validate() {
        return Ok(Err(structure(
            format!("the hold's control record is malformed: {e}"),
            "fix the named field",
        )));
    }
    let policy = EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let digest = proposal.proposal_digest()?;
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    if let Some(row) = txn.vertex(db, hold)? {
        txn.abort();
        return placed_or_conflict(book, &row, &proposal, &digest);
    }
    let epoch = epoch_witness(&txn, db)?;
    let key = fa_policy::sod::control_key("HoldControl", None, "Place");
    let preparer = Party {
        principal: req.principal,
        profile: capability.profile(),
    };
    if let Err(r) = authorize_approvals(&txn, db, book, &[], &digest, epoch, &key, 0, preparer)? {
        txn.abort();
        return Ok(Err(r));
    }
    let Some(authority) = txn.vertex(db, document_vid(&req.authority))? else {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::EVIDENCE_UNKNOWN,
            exit::REFUSAL,
            format!(
                "the hold's authority, document {}, is not in this book",
                hex(&req.authority.0)
            ),
            "plan §8.5 (a legal hold names the authority it rests on)",
            "record the order or letter first with `fa document add <file> --kind <Kind> --json` and name the oid it prints",
        )));
    };
    if let Err(why) = verify_row(&authority, &policy) {
        txn.abort();
        return Ok(Err(drift(&req.authority, &why)));
    }
    if let Err(r) = witness_custody(&txn, db, &policy, &req.authority)? {
        txn.abort();
        return Ok(Err(r));
    }
    let entry = proposal.clone().seal(Vec::new(), None)?;
    let mut batch = WriteBatch::new(relation::HOLDS);
    batch.create_vertex(hold, vec![label::ENTRY], entry_mirrors(&entry)?);
    // Each target is (the cell whose active set gains the hold, the vertex
    // its HOLDS edge points at): a named subject's own cell, or the book's
    // cell with the edge to the book root.
    let mut targets = Vec::new();
    let (subjects, through) = match &scope {
        Scope::Place(subjects) => {
            for subject in subjects {
                let Some(row) = txn.vertex(db, *subject)? else {
                    txn.abort();
                    return Ok(Err(unholdable(*subject, "is not in this book")));
                };
                if !holdable(&row) {
                    txn.abort();
                    return Ok(Err(unholdable(
                        *subject,
                        "is not an entry, a document or a party",
                    )));
                }
                targets.push((legal_hold_cell_vid(book.book_id, *subject), *subject));
            }
            (subjects.clone(), None)
        }
        Scope::Book(through) => {
            targets.push((book_hold_cell_vid(book.book_id), book_root()));
            (Vec::new(), Some(*through))
        }
        Scope::Release(_) => {
            txn.abort();
            return Err(KernelError::Corrupt(
                "a placement built a release scope".into(),
            ));
        }
    };
    for &(cell, subject) in &targets {
        match txn.vertex(db, cell)? {
            None => {
                batch.create_vertex(
                    cell,
                    vec![label::LEGAL_HOLD_CELL],
                    vec![(property::LEGAL_HOLDS, holds_scalar(&[hold])?)],
                );
            }
            Some(row) => {
                let mut holds = holds_of(&row)?;
                if holds.len() >= MAX_ACTIVE_LEGAL_HOLDS {
                    txn.abort();
                    let carrier = if matches!(scope, Scope::Book(_)) {
                        "the book".to_string()
                    } else {
                        format!("subject {:032x}", subject.0)
                    };
                    return Ok(Err(structure(
                        format!(
                            "{carrier} already carries max_active_legal_holds ({MAX_ACTIVE_LEGAL_HOLDS}) holds"
                        ),
                        "release a hold on it first, or rest the new scope on a hold already active",
                    )));
                }
                let Err(at) = holds.binary_search_by_key(&hold.0, |h| h.0) else {
                    txn.abort();
                    return Err(KernelError::Corrupt(format!(
                        "legal hold cell {:032x} names hold {:032x}, which is not recorded",
                        cell.0, hold.0
                    )));
                };
                holds.insert(at, hold);
                batch.compare_and_set_vertex_property(
                    cell,
                    property::LEGAL_HOLDS,
                    prop(&row, property::LEGAL_HOLDS).cloned(),
                    holds_scalar(&holds)?,
                    WriteMismatchPolicy::AbortWrite,
                );
            }
        }
        batch.add_edge(
            edge_id(relation::HOLDS, hold, subject),
            hold,
            subject,
            vec![],
        );
    }
    if let Err(e) = txn.write(db, batch) {
        txn.abort();
        return Err(e.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(LegalHoldPlaced {
            hold,
            subjects,
            through,
            recorded_at: seq,
            already_recorded: false,
        })),
        Err(
            WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { .. })
            | WriteTxnError::Write(fgdb::WriteError::CompareAndSetMismatch(_)),
        ) => Ok(Err(conflict("legal hold"))),
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => match db.vertex(hold)? {
            Some(row) => placed_or_conflict(book, &row, &proposal, &digest),
            // A first hold on one of the subjects raced this one.
            None => Ok(Err(conflict("legal hold"))),
        },
        Err(e) => Err(e.into()),
    }
}

/// Plan the release of `hold` without committing: the hold is read at the
/// head and must be an active Place of this book (FA-REF-118). Authority is
/// not judged here; the commit judges it, before any read.
pub fn plan_release<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    hold: VId,
    principal_ref: VId,
    effective_date: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
) -> Outcome<ReleasePlan> {
    let Some(placed) = read_legal_hold(db, book.book_id, hold)? else {
        return Ok(Err(unknown_hold(
            hold,
            "is not a legal hold placed in this book",
        )));
    };
    if let Some((release, at)) = placed.released {
        return Ok(Err(unknown_hold(
            hold,
            &format!("was released by {:032x} at sequence {}", release.0, at.0),
        )));
    }
    Ok(Ok(ReleasePlan {
        hold,
        authority: placed.authority,
        principal_ref,
        effective_date,
        idempotency_key: idempotency_key.to_vec(),
        description,
    }))
}

/// Release a legal hold as planned, citing `approvals` of the plan's
/// proposal digest: refused before any read on structure or authority (the
/// `legal-hold-release` row's preparer op). Then, in one transaction: the
/// capability not revoked; the release's identity (this plan again is its
/// recorded outcome; another release of the same hold is FA-REF-118); the
/// hold an active Place whose authority the plan names; the SoD rule over
/// the witnessed policy epoch (a Human approver other than the preparer);
/// each subject's cell moved by compare-and-set to drop the hold; the
/// Release.
pub async fn release_legal_hold<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    plan: &ReleasePlan,
    approvals: &[ApprovalRef],
) -> Outcome<LegalHoldReleased> {
    let proposal = plan.proposal(book)?;
    if let Err(e) = proposal.validate() {
        return Ok(Err(structure(
            format!("the release's control record is malformed: {e}"),
            "fix the named field",
        )));
    }
    if let Err(r) = admit(db, book, capability, plan.principal_ref, "Release")? {
        return Ok(Err(r));
    }
    let digest = proposal.proposal_digest()?;
    let release = release_vid(book.book_id, plan.hold);
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    if let Some(row) = txn.vertex(db, release)? {
        txn.abort();
        return released_or_refused(&row, plan.hold, &digest);
    }
    let Some(hold_row) = txn.vertex(db, plan.hold)? else {
        txn.abort();
        return Ok(Err(unknown_hold(plan.hold, "is not in this book")));
    };
    let Some(placed) = placed_of(&hold_row)? else {
        txn.abort();
        return Ok(Err(unknown_hold(
            plan.hold,
            "is not a legal hold's placement",
        )));
    };
    if placed.authority != plan.authority {
        txn.abort();
        return Ok(Err(unknown_hold(
            plan.hold,
            &format!(
                "rests on authority {}, not the plan's {}: the plan is not this hold's",
                hex(&placed.authority.0),
                hex(&plan.authority.0)
            ),
        )));
    }
    let epoch = epoch_witness(&txn, db)?;
    let key = fa_policy::sod::control_key("HoldControl", None, "Release");
    let preparer = Party {
        principal: plan.principal_ref,
        profile: capability.profile(),
    };
    if let Err(r) =
        authorize_approvals(&txn, db, book, approvals, &digest, epoch, &key, 0, preparer)?
    {
        txn.abort();
        return Ok(Err(r));
    }
    let entry = proposal.seal(approvals.to_vec(), None)?;
    let mut batch = WriteBatch::new(relation::HOLDS);
    batch.create_vertex(release, vec![label::ENTRY], entry_mirrors(&entry)?);
    // The cells that list the hold: the book's for a book-scope hold, each
    // named subject's otherwise.
    let cells: Vec<VId> = match placed.through {
        Some(_) => vec![book_hold_cell_vid(book.book_id)],
        None => placed
            .subjects
            .iter()
            .map(|s| legal_hold_cell_vid(book.book_id, *s))
            .collect(),
    };
    for cell in cells {
        let missing = || {
            KernelError::Corrupt(format!(
                "legal hold {:032x}'s cell {:032x} does not name the hold",
                plan.hold.0, cell.0
            ))
        };
        let Some(row) = txn.vertex(db, cell)? else {
            txn.abort();
            return Err(missing());
        };
        let mut holds = holds_of(&row)?;
        let Ok(at) = holds.binary_search_by_key(&plan.hold.0, |h| h.0) else {
            txn.abort();
            return Err(missing());
        };
        holds.remove(at);
        batch.compare_and_set_vertex_property(
            cell,
            property::LEGAL_HOLDS,
            prop(&row, property::LEGAL_HOLDS).cloned(),
            holds_scalar(&holds)?,
            WriteMismatchPolicy::AbortWrite,
        );
    }
    if let Err(e) = txn.write(db, batch) {
        txn.abort();
        return Err(e.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(LegalHoldReleased {
            release,
            hold: plan.hold,
            recorded_at: seq,
            already_recorded: false,
        })),
        Err(
            WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { .. })
            | WriteTxnError::Write(fgdb::WriteError::CompareAndSetMismatch(_)),
        ) => Ok(Err(conflict("release"))),
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => match db.vertex(release)? {
            Some(row) => released_or_refused(&row, plan.hold, &digest),
            None => Err(KernelError::Corrupt(
                "release identity spent but no live row".into(),
            )),
        },
        Err(e) => Err(e.into()),
    }
}

fn released_or_refused(
    row: &VertexRow,
    hold: VId,
    digest: &[u8; 32],
) -> Outcome<LegalHoldReleased> {
    if &decode_entry(row)?.proposal_digest == digest {
        return Ok(Ok(LegalHoldReleased {
            release: row.vid,
            hold,
            recorded_at: row.created_at,
            already_recorded: true,
        }));
    }
    Ok(Err(unknown_hold(
        hold,
        &format!(
            "was released by {:032x} at sequence {}",
            row.vid.0, row.created_at.0
        ),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_round_trip_and_bind_every_byte() {
        let place = Scope::Place(vec![VId(3), VId(9), VId(1 << 100)]);
        let release = Scope::Release(VId(77));
        let book = Scope::Book(CommitSeq(42));
        assert_eq!(book.canonical_bytes().unwrap()[0], BOOK_THROUGH);
        assert_eq!(book.kind(), PLACE, "a book-scope hold is a Place");
        for s in [&place, &release, &book] {
            let bytes = s.canonical_bytes().unwrap();
            assert_eq!(&Scope::decode(&bytes).unwrap(), s);
            for i in 0..bytes.len() {
                let mut x = bytes.clone();
                x[i] ^= 0x01;
                assert_ne!(Scope::decode(&x).ok().as_ref(), Some(s), "byte {i}");
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(Scope::decode(&trailing).is_err());
        }
        assert_ne!(place.digest().unwrap(), release.digest().unwrap());
        assert_ne!(book.digest().unwrap(), place.digest().unwrap());
        assert_ne!(
            book.digest().unwrap(),
            Scope::Book(CommitSeq(43)).digest().unwrap()
        );
        let refused = [
            Scope::Place(vec![]),
            Scope::Place(vec![VId(9), VId(3)]),
            Scope::Place(vec![VId(3), VId(3)]),
            Scope::Book(CommitSeq(0)),
        ];
        for s in &refused {
            assert!(
                Scope::decode(&s.canonical_bytes().unwrap()).is_err(),
                "{s:?}"
            );
        }
        assert!(Scope::decode(&[3]).is_err(), "an unknown kind");
        assert!(
            Scope::decode(&[BOOK_THROUGH]).is_err(),
            "a truncated book scope"
        );
        let over: Vec<VId> = (0..=MAX_LEGAL_HOLD_SUBJECTS as u128).map(VId).collect();
        assert!(Scope::decode(&Scope::Place(over).canonical_bytes().unwrap()).is_err());
    }

    #[test]
    fn identities_are_per_book_and_subject() {
        let (a, b) = (Id128([5; 16]), Id128([6; 16]));
        let cell = legal_hold_cell_vid(a, VId(9));
        assert_ne!(cell, legal_hold_cell_vid(a, VId(10)));
        assert_ne!(cell, legal_hold_cell_vid(b, VId(9)));
        assert_ne!(
            cell,
            release_vid(a, VId(9)),
            "cells and releases never collide"
        );
        assert_ne!(release_vid(a, VId(9)), release_vid(b, VId(9)));
        assert_ne!(book_hold_cell_vid(a), book_hold_cell_vid(b));
        assert_ne!(
            book_hold_cell_vid(a),
            legal_hold_cell_vid(a, book_root()),
            "the book's cell is not a subject cell of its root"
        );
    }
}
