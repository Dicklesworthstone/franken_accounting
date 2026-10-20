//! Litigation productions (plan §0.4 decision 4, §13.2, Appendix A
//! `ProductionProfile`, Appendix B `Produce`; bead fa-6l9).
//!
//! A matter's productions are its `ProductionControl` records (class 27,
//! control kind 14), each a `LifecycleTransition` on the matter's
//! `ProductionProfile` vertex at [`fa_model::production_profile_vid`]:
//!
//! - **Open** (`0 → Open`) journals the profile (extension 13
//!   `fa:production-profile:v1`: the matter, its Bates prefix and first
//!   number, its load-file format and the optional protective order, which
//!   is also the record's proof ref) and creates the vertex with
//!   `state = Open` and `next_bates` at the first number.
//! - **Produce** (`Open → Open`) journals the Bates ranges it assigns
//!   (extension 14 `fa:production-bates:v1`), in production order, with the
//!   produced documents as its proof refs; it moves `next_bates` by
//!   compare-and-set and stages one `BatesRange` vertex per newly produced
//!   document at [`fa_model::bates_range_vid`].
//!
//! A Bates number is never reassigned: a document already produced in its
//! matter keeps its range, and producing it again burns no number. The same
//! document produced in another matter receives that matter's range. The
//! Document payload and its `doc_commit` never change; Bates metadata lives
//! only in these records.
//!
//! Both records are trunk records under the `produce` op (`sod_policy.toml`
//! `production-open`, `production-produce`), so an Agent-profile capability
//! prepares neither (plan §14.4). Productions in one matter race on
//! `next_bates`: the first committer wins and the other retries for the next
//! numbers. A production that would assign nothing new writes nothing.

use fa_model::limits::MAX_PROOF_REFS;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ControlKind, ControlPayload, EntryClass, EntryOrigin, EntryPayload, Erasable, Id128, Oid,
    Reader, TypedRef, Writer, bates_range_vid, domain_digest, entry_mirrors, entry_vid,
    production_profile_vid,
};
use fa_policy::{Capability, Intent};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::evidence::{document_vid, drift, hex, verify_row};
use crate::genesis::BookContext;
use crate::policy::{capability_witness, refusal as denial, steward};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{bytes, edge_id, prop, scalar_bytes, scalar_text};

/// Canonical bytes of a profile: `u16 version ‖ book_id[16] ‖ str matter ‖
/// str bates_prefix ‖ u64 first_bates ‖ u8 load_file_format ‖ opt oid
/// protective_order` (extension 13).
pub const PROFILE_VERSION: u16 = 1;
/// Canonical bytes of a Produce record's ranges: `u16 version ‖ str matter ‖
/// [32] request_digest ‖ list(range)` (extension 14).
pub const BATES_VERSION: u16 = 1;
/// A matter id's bound, in bytes.
pub const MAX_MATTER_BYTES: usize = 128;
/// A Bates prefix's bound, in bytes (Appendix A `bates_prefix: String(≤16)`).
pub const MAX_BATES_PREFIX_BYTES: usize = 16;
/// The documents one production names: its proof refs.
pub const MAX_PRODUCED_DOCUMENTS: usize = MAX_PROOF_REFS;
/// The last Bates number a range may end on (the `next_bates` projection is
/// a canonical integer).
pub const MAX_BATES: u64 = i64::MAX.unsigned_abs();
/// The highest confidentiality designation tag (Appendix A `designations`):
/// 0 none, 1 CONFIDENTIAL, 2 ATTORNEYS' EYES ONLY, 3 HIGHLY CONFIDENTIAL —
/// fa-notary `ConfidentialityDesignation`.
pub const MAX_DESIGNATION: u8 = 3;
/// The load-file format tags (Appendix A `load_file_format: u8`): 1
/// Concordance DAT/OPT, 2 EDRM XML, 3 both — fa-notary `LoadFileFormat`.
pub const LOAD_FILE_FORMATS: core::ops::RangeInclusive<u8> = 1..=3;
const PROFILE_DOMAIN: &[u8] = b"fa:production-profile:v1";
const REQUEST_DOMAIN: &[u8] = b"fa:production-request:v1";
const RECORD_KEY_DOMAIN: &[u8] = b"fa:production-record-key:v1";
const RANGE_VERSION: u16 = 1;

/// The `state` projection of a `ProductionProfile`. A matter's profile has
/// one state in this build; its later lifecycle (closing a matter) is added
/// as a new transition, never by reusing this tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionState {
    Open,
}

impl ProductionState {
    /// The `LifecycleTransition` state tag; 0 is "no profile yet".
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::Open => 1,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
        }
    }

    fn scalar(self) -> CanonicalScalar {
        CanonicalScalar::Int(i64::from(self.tag()))
    }

    fn from_scalar(v: Option<&CanonicalScalar>) -> Option<Self> {
        match v {
            Some(CanonicalScalar::Int(1)) => Some(Self::Open),
            _ => None,
        }
    }
}

/// A matter's immutable production profile (Appendix A `ProductionProfile`;
/// its per-document designations are journaled with each range).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionProfile {
    pub book_id: Id128,
    pub matter: String,
    pub bates_prefix: String,
    /// The number the matter's first production starts at (`>= 1`).
    pub first_bates: u64,
    pub load_file_format: u8,
    pub protective_order: Option<Oid>,
}

impl ProductionProfile {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::with_capacity(96 + self.matter.len());
        w.u16(PROFILE_VERSION)
            .fixed(&self.book_id.0)
            .str(&self.matter)
            .str(&self.bates_prefix)
            .u64(self.first_bates)
            .u8(self.load_file_format)
            .opt(self.protective_order.as_ref(), |w, oid| {
                w.fixed(&oid.0);
            });
        Ok(w.finish()?)
    }

    /// Decode and validate a profile; refuses an unknown version, a field
    /// out of its domain, and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(bytes);
        if r.u16("production.version").map_err(decode)? != PROFILE_VERSION {
            return Err(KernelError::Corrupt(
                "unsupported production profile version".into(),
            ));
        }
        let book_id = Id128(r.fixed("production.book_id").map_err(decode)?);
        let matter = r
            .str(MAX_MATTER_BYTES, "production.matter")
            .map_err(decode)?
            .to_string();
        let bates_prefix = r
            .str(MAX_BATES_PREFIX_BYTES, "production.bates_prefix")
            .map_err(decode)?
            .to_string();
        let first_bates = r.u64("production.first_bates").map_err(decode)?;
        let load_file_format = r.u8("production.load_file_format").map_err(decode)?;
        let protective_order = r
            .opt("production.protective_order", |r| {
                Ok(Oid(r.fixed("production.protective_order")?))
            })
            .map_err(decode)?;
        r.finish().map_err(decode)?;
        let profile = Self {
            book_id,
            matter,
            bates_prefix,
            first_bates,
            load_file_format,
            protective_order,
        };
        profile
            .check()
            .map_err(|why| KernelError::Corrupt(format!("production profile: {why}")))?;
        Ok(profile)
    }

    /// The field domains a profile must satisfy, as one sentence.
    pub fn check(&self) -> Result<(), String> {
        check_matter(&self.matter)?;
        if self.bates_prefix.is_empty()
            || self.bates_prefix.len() > MAX_BATES_PREFIX_BYTES
            || !self.bates_prefix.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(format!(
                "a Bates prefix is 1..={MAX_BATES_PREFIX_BYTES} printable ASCII bytes with no spaces; `{}` is not",
                self.bates_prefix
            ));
        }
        if self.first_bates == 0 || self.first_bates > MAX_BATES {
            return Err(format!(
                "the first Bates number is 1..={MAX_BATES}; {} is not",
                self.first_bates
            ));
        }
        if !LOAD_FILE_FORMATS.contains(&self.load_file_format) {
            return Err(format!(
                "load-file format {} is not registered (1 Concordance DAT/OPT, 2 EDRM XML, 3 both)",
                self.load_file_format
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(PROFILE_DOMAIN, &[&self.canonical_bytes()?]))
    }

    #[must_use]
    pub fn vid(&self) -> VId {
        production_profile_vid(self.book_id, &self.matter)
    }

    /// The Bates label of `number` in this matter: `PREFIX-00000042`.
    #[must_use]
    pub fn label(&self, number: u64) -> String {
        format!("{}-{number:08}", self.bates_prefix)
    }
}

fn check_matter(matter: &str) -> Result<(), String> {
    if matter.is_empty()
        || matter.len() > MAX_MATTER_BYTES
        || matter.trim() != matter
        || matter.chars().any(char::is_control)
    {
        return Err(format!(
            "a matter id is 1..={MAX_MATTER_BYTES} bytes with no surrounding whitespace or control characters"
        ));
    }
    Ok(())
}

/// One document's Bates range in a matter, as its Produce record journals it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatesRange {
    pub document: Oid,
    /// The document's public commitment, unchanged by the production.
    pub doc_commit: [u8; 32],
    pub start: u64,
    /// Inclusive.
    pub end: u64,
    pub designation: u8,
}

impl BatesRange {
    #[must_use]
    pub fn pages(&self) -> u64 {
        self.end - self.start + 1
    }

    fn encode(&self, w: &mut Writer) {
        w.fixed(&self.document.0)
            .fixed(&self.doc_commit)
            .u64(self.start)
            .u64(self.end)
            .u8(self.designation);
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, fa_model::DecodeError> {
        let range = Self {
            document: Oid(r.fixed("bates.document")?),
            doc_commit: r.fixed("bates.doc_commit")?,
            start: r.u64("bates.start")?,
            end: r.u64("bates.end")?,
            designation: r.u8("bates.designation")?,
        };
        if range.start == 0
            || range.end < range.start
            || range.end > MAX_BATES
            || range.designation > MAX_DESIGNATION
        {
            return Err(r.invalid("bates.range"));
        }
        Ok(range)
    }
}

/// A Produce record's ranges (extension 14): every range it assigned, in
/// production order, and the digest of the request that assigned them.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BatesRecord {
    matter: String,
    request_digest: [u8; 32],
    ranges: Vec<BatesRange>,
}

impl BatesRecord {
    fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::with_capacity(64 + self.ranges.len() * 81);
        w.u16(BATES_VERSION)
            .str(&self.matter)
            .fixed(&self.request_digest)
            .list(&self.ranges, |w, r| r.encode(w));
        Ok(w.finish()?)
    }

    fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(bytes);
        if r.u16("bates.version").map_err(decode)? != BATES_VERSION {
            return Err(KernelError::Corrupt(
                "unsupported production Bates record version".into(),
            ));
        }
        let matter = r
            .str(MAX_MATTER_BYTES, "bates.matter")
            .map_err(decode)?
            .to_string();
        let request_digest = r.fixed("bates.request_digest").map_err(decode)?;
        let ranges = r
            .list(MAX_PRODUCED_DOCUMENTS, "bates.ranges", BatesRange::decode)
            .map_err(decode)?;
        r.finish().map_err(decode)?;
        if ranges.is_empty() {
            return Err(KernelError::Corrupt(
                "a Produce record assigns no range".into(),
            ));
        }
        Ok(Self {
            matter,
            request_digest,
            ranges,
        })
    }
}

/// A `BatesRange` vertex's payload: `u16 version ‖ str matter ‖ range ‖ u128
/// record` — the range and the Produce record that assigned it.
fn range_payload(matter: &str, range: &BatesRange, record: VId) -> Result<Vec<u8>, KernelError> {
    let mut w = Writer::with_capacity(128 + matter.len());
    w.u16(RANGE_VERSION).str(matter);
    range.encode(&mut w);
    w.u128(record.0);
    Ok(w.finish()?)
}

fn decode_range_payload(bytes: &[u8]) -> Result<(String, BatesRange, VId), KernelError> {
    let mut r = Reader::new(bytes);
    if r.u16("bates_range.version").map_err(decode)? != RANGE_VERSION {
        return Err(KernelError::Corrupt(
            "unsupported Bates range version".into(),
        ));
    }
    let matter = r
        .str(MAX_MATTER_BYTES, "bates_range.matter")
        .map_err(decode)?
        .to_string();
    let range = BatesRange::decode(&mut r).map_err(decode)?;
    let record = VId(r.u128("bates_range.record").map_err(decode)?);
    r.finish().map_err(decode)?;
    Ok((matter, range, record))
}

fn decode(e: fa_model::DecodeError) -> KernelError {
    KernelError::Model(e.into())
}

/// One document a production names. `pages` and `designation` apply to a
/// document newly produced in the matter (defaults: one page, no
/// designation); for a document the matter already produced they must be
/// absent or equal to its recorded range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProducedDocument {
    pub document: Oid,
    pub pages: Option<u64>,
    pub designation: Option<u8>,
}

/// A production control request: the acting capability, the record's
/// (undated, book-scoped) effective date, its sealed description and the
/// caller's idempotency key.
#[derive(Clone, Debug)]
pub struct ProductionRequest {
    pub capability: Capability,
    pub effective_date: DateDay,
    pub description: Erasable<String>,
    pub idempotency_key: Vec<u8>,
}

/// A recorded Open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionOpened {
    pub profile: VId,
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
    /// The same Open was already journaled (FA-INV-09): nothing written.
    pub already_recorded: bool,
}

/// One requested document's range, and whether this production assigned it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProducedRange {
    pub range: BatesRange,
    /// False when the matter had produced the document before.
    pub assigned: bool,
}

/// A production's outcome: every requested document's range in request
/// order, and the Produce record if it assigned any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Produced {
    pub profile: ProductionProfile,
    pub ranges: Vec<ProducedRange>,
    /// The Produce record and its sequence; `None` when every document was
    /// already produced in the matter (nothing was written).
    pub record: Option<(VId, CommitSeq)>,
    /// The matter's next unassigned Bates number after this production.
    pub next_bates: u64,
    /// The identical production was already journaled: nothing written.
    pub already_recorded: bool,
}

/// One assigned range as the matter's journal states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedRange {
    pub range: BatesRange,
    /// The Produce record that assigned it, and its sequence.
    pub record: VId,
    pub recorded_at: CommitSeq,
    pub produced_by: VId,
}

/// A matter's production profile and every range its records assigned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionView {
    pub vid: VId,
    pub profile: ProductionProfile,
    pub state: ProductionState,
    pub opened_at: CommitSeq,
    pub opened_by: VId,
    pub next_bates: u64,
    /// Ascending by Bates number.
    pub ranges: Vec<RecordedRange>,
}

#[derive(Clone, Copy)]
enum Kind {
    Open,
    Produce,
}

impl Kind {
    fn transition(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Produce => "Produce",
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Produce => 1,
        }
    }

    fn states(self) -> (u8, u8) {
        let open = ProductionState::Open.tag();
        match self {
            Self::Open => (0, open),
            Self::Produce => (open, open),
        }
    }
}

/// A record's idempotency key: `H(domain ‖ kind ‖ profile ‖ caller key)`,
/// within the key bound whatever the caller's key.
fn record_key(kind: Kind, profile: VId, key: &[u8]) -> Vec<u8> {
    domain_digest(
        RECORD_KEY_DOMAIN,
        &[&[kind.tag()], &profile.0.to_le_bytes(), key],
    )
    .to_vec()
}

fn record_proposal(
    book: &BookContext,
    profile: &ProductionProfile,
    kind: Kind,
    req: &ProductionRequest,
    proof_refs: Vec<TypedRef>,
    extension: (u16, Vec<u8>),
) -> Result<EntryPayload, KernelError> {
    let vid = profile.vid();
    let (from, to) = kind.states();
    Ok(EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::PRODUCTION_CONTROL,
        effective_date: req.effective_date,
        document_date: None,
        description: req.description.clone(),
        effective_period: None,
        legs: Vec::new(),
        control: Some(ControlPayload::LifecycleTransition {
            object_ref: vid,
            from,
            to,
            proof_refs,
            reason_code: 0,
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: record_key(kind, vid, &req.idempotency_key),
        origin: EntryOrigin::Control {
            control_kind: ControlKind::PRODUCTION_TRANSITION,
            spec_body_digest: profile.digest()?,
        },
        principal_ref: req.capability.holder(),
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: vec![extension],
        tags: Vec::new(),
    })
}

/// Authority before any read (doctrine 8): the `ProductionControl` row's
/// preparer op for `kind`, held by the acting principal, current at the
/// head. A production record is a trunk record, so an Agent is refused.
fn admit<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
    kind: Kind,
) -> Outcome<()> {
    let op = steward()?
        .transition_op("ProductionControl", kind.transition())
        .ok_or_else(|| {
            KernelError::Corrupt(format!(
                "sod_policy.toml registers no ProductionControl {} rule; the record is refused, never unconstrained",
                kind.transition()
            ))
        })?;
    if let Err(d) = fa_policy::admit(
        capability,
        &Intent {
            principal: capability.holder(),
            trunk: true,
            op,
            book: book.book_id,
            legs: &[],
        },
    ) {
        return Ok(Err(denial(&d)));
    }
    if let Err(d) = fa_policy::current(capability, db.frontier()?) {
        return Ok(Err(denial(&d)));
    }
    Ok(Ok(()))
}

fn usage(message: impl Into<String>, fix: &str) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        message.into(),
        "plan §13.2, Appendix A ProductionProfile (bead fa-6l9)",
        fix,
    )
}

fn unknown(matter: &str) -> Refusal {
    Refusal::new(
        code::PRODUCTION_UNKNOWN,
        exit::REFUSAL,
        format!("this book has no production profile for matter `{matter}`"),
        "plan §13.2 (a ProductionProfile governs a matter's productions)",
        "list the book's matters with `fa production list --json`, or open one with `fa production open <matter> --bates-prefix <PREFIX>`",
    )
}

fn range_fixed(profile: &ProductionProfile, range: &BatesRange, what: &str) -> Refusal {
    Refusal::new(
        code::BATES_RANGE_FIXED,
        exit::REFUSAL,
        format!(
            "document {} was produced in matter `{}` as {}..={} ({} pages, designation {}); this production asks for a different {what}",
            hex(&range.document.0),
            profile.matter,
            profile.label(range.start),
            profile.label(range.end),
            range.pages(),
            range.designation
        ),
        "plan §13.2 (a document's Bates range in a matter is assigned once and never changes)",
        "produce it again without --pages or --designation to receive its recorded range, or record the corrected document with `fa document add` and produce the new document",
    )
}

fn conflict_with(row: &VertexRow) -> Refusal {
    Refusal::new(
        code::IDEMPOTENCY_CONFLICT,
        exit::CONFLICT,
        format!(
            "this production record's identity holds different content; the recorded entry is {:032x}",
            row.vid.0
        ),
        "plan §4.9 (identity is derived from the key; content is bound by proposal_digest)",
        "resubmit the identical request to get its recorded outcome, or use a new --key",
    )
}

fn fcw(detail: &str) -> Refusal {
    Refusal::new(
        code::CONFLICT,
        exit::CONFLICT,
        format!("a concurrent commit invalidated a witness this production read: {detail}"),
        "FG-LAW-FCW-01 (first committer wins)",
        "retry; a concurrent production in the matter took the numbers this one read, so the retry receives the next ones",
    )
}

/// The identical record's sequence, or the conflict (plan §4.9: exact bytes,
/// else a seal-aware semantic comparison under the book key).
fn recorded_or_conflict(
    book: &BookContext,
    row: &VertexRow,
    proposal: &EntryPayload,
) -> Outcome<CommitSeq> {
    let (stored, recorded_at) = crate::post::entry_of(row)?;
    if stored.proposal_digest == proposal.proposal_digest()? {
        return Ok(Ok(recorded_at));
    }
    match (
        stored.proposal.semantic_digest(&book.seal_key),
        proposal.semantic_digest(&book.seal_key),
    ) {
        (Ok(a), Ok(b)) if a == b => Ok(Ok(recorded_at)),
        (Ok(_), Ok(_)) => Ok(Err(conflict_with(row))),
        (Err(fa_model::EntryError::Sealed(_)), _) | (_, Err(fa_model::EntryError::Sealed(_))) => {
            Ok(Err(Refusal::new(
                code::EQUIVALENCE_UNVERIFIABLE,
                exit::CONFLICT,
                format!(
                    "the recorded production record {:032x} has erased text, so a retry cannot be judged identical",
                    row.vid.0
                ),
                "plan §4.9, §14.6 (erasure leaves identity, not plaintext)",
                "use a new --key",
            )))
        }
        (Err(e), _) | (_, Err(e)) => Err(e.into()),
    }
}

fn profile_of(row: &VertexRow) -> Result<ProductionProfile, KernelError> {
    ProductionProfile::decode(&bytes(row, property::FA_PAYLOAD, "production._fa_payload")?)
}

fn next_of(row_or_value: Option<&CanonicalScalar>, profile: VId) -> Result<u64, KernelError> {
    match row_or_value {
        Some(CanonicalScalar::Int(n)) if *n >= 1 => Ok(n.unsigned_abs()),
        _ => Err(KernelError::Corrupt(format!(
            "production profile {:032x} carries no next_bates",
            profile.0
        ))),
    }
}

fn next_scalar(n: u64) -> Result<CanonicalScalar, KernelError> {
    i64::try_from(n)
        .map(CanonicalScalar::Int)
        .map_err(|_| KernelError::Scalar("next_bates"))
}

/// Open the production profile of `profile.matter`: one commit journaling
/// the Open record, the `ProductionProfile` vertex with its immutable body,
/// `state = Open` and `next_bates = first_bates`, and the record's `IN_CASE`
/// edge to it. A protective order must be a verified document of this book.
pub async fn open_production<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    profile: ProductionProfile,
    req: ProductionRequest,
) -> Outcome<ProductionOpened> {
    if profile.book_id != book.book_id {
        return Ok(Err(usage(
            "the production profile names another book",
            "open the matter's profile in the book that holds its documents",
        )));
    }
    if let Err(why) = profile.check() {
        return Ok(Err(usage(
            why,
            "fa production open <matter> --bates-prefix <PREFIX> [--start <n>] [--load-file dat|edrm|both]",
        )));
    }
    if let Err(r) = admit(db, book, &req.capability, Kind::Open)? {
        return Ok(Err(r));
    }
    let body = profile.canonical_bytes()?;
    let proof_refs = profile
        .protective_order
        .iter()
        .map(|oid| TypedRef::Object(*oid))
        .collect();
    let proposal = record_proposal(
        book,
        &profile,
        Kind::Open,
        &req,
        proof_refs,
        (fa_model::entry::PRODUCTION_PROFILE_EXTENSION, body.clone()),
    )?;
    if proposal.validate().is_err() {
        return Ok(Err(usage(
            "the Open record is not a valid ProductionControl entry",
            "open the matter with `fa production open <matter> --bates-prefix <PREFIX>`",
        )));
    }
    let vid = profile.vid();
    let evid = entry_vid(
        book.book_id,
        &proposal.principal_ref.0.to_le_bytes(),
        &proposal.idempotency_key,
    );
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    // The capability is not revoked (plan §14.2): the first read.
    if let Err(r) = capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return Ok(
            recorded_or_conflict(book, &row, &proposal)?.map(|recorded_at| ProductionOpened {
                profile: vid,
                control_entry: evid,
                recorded_at,
                already_recorded: true,
            }),
        );
    }
    if let Some(existing) = txn.vertex(db, vid)? {
        txn.abort();
        let prefix = profile_of(&existing).map(|p| p.bates_prefix).ok();
        return Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            format!(
                "matter `{}` already has a production profile{}",
                profile.matter,
                prefix.map_or_else(String::new, |p| format!(" (Bates prefix {p})"))
            ),
            "plan §13.2 (one ProductionProfile per matter in a book; its Bates numbering is never restarted)",
            "produce into the existing matter with `fa produce --matter <matter>`, or inspect it with `fa production show <matter> --json`",
        )));
    }
    if let Some(order) = &profile.protective_order
        && let Err(r) = witness_document(&txn, db, order)?
    {
        txn.abort();
        return Ok(Err(r));
    }
    let entry = proposal.clone().seal(Vec::new(), None)?;
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("production._fa_payload", body)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("production._fa_digest", profile.digest()?.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("book_id", book.book_id.0.to_vec())?,
        ),
        (
            property::CODE,
            scalar_text("production.code", &profile.matter)?,
        ),
        (property::STATE, ProductionState::Open.scalar()),
        (property::NEXT_BATES, next_scalar(profile.first_bates)?),
    ];
    props.sort_by_key(|(k, _)| k.0);
    let mut in_case = WriteBatch::new(relation::IN_CASE);
    in_case.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    in_case.create_vertex(vid, vec![label::PRODUCTION_PROFILE], props);
    in_case.add_edge(edge_id(relation::IN_CASE, evid, vid), evid, vid, vec![]);
    txn.write(db, in_case)?;
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(ProductionOpened {
            profile: vid,
            control_entry: evid,
            recorded_at: seq,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(fcw(&detail)))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => match db.vertex(evid)? {
            Some(row) => Ok(
                recorded_or_conflict(book, &row, &proposal)?.map(|recorded_at| ProductionOpened {
                    profile: vid,
                    control_entry: evid,
                    recorded_at,
                    already_recorded: true,
                }),
            ),
            // Another principal opened the same matter first.
            None => Ok(Err(fcw("the matter's profile was opened concurrently"))),
        },
        Err(e) => Err(e.into()),
    }
}

/// A document this book holds, verified; its record.
fn witness_document<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    oid: &Oid,
) -> Outcome<crate::evidence::DocumentRecord> {
    let policy = EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let Some(row) = txn.vertex(db, document_vid(oid))? else {
        return Ok(Err(Refusal::new(
            code::EVIDENCE_UNKNOWN,
            exit::REFUSAL,
            format!("document {} is not in this book", hex(&oid.0)),
            "plan §13.2 (a production names documents the book holds)",
            "record it first with `fa document add <file> --kind <Kind> --json` and name the oid it prints",
        )));
    };
    match verify_row(&row, &policy) {
        Ok(record) => Ok(Ok(record)),
        Err(why) => Ok(Err(drift(oid, &why))),
    }
}

/// The request's digest: the matter and every named document with its
/// requested pages and designation, in order. A retry under the same key
/// must carry the same request.
fn request_digest(matter: &str, documents: &[ProducedDocument]) -> Result<[u8; 32], KernelError> {
    let mut w = Writer::with_capacity(64 + documents.len() * 48);
    w.str(matter).list(documents, |w, d| {
        w.fixed(&d.document.0)
            .opt(d.pages.as_ref(), |w, p| {
                w.u64(*p);
            })
            .opt(d.designation.as_ref(), |w, g| {
                w.u8(*g);
            });
    });
    Ok(domain_digest(REQUEST_DOMAIN, &[&w.finish()?]))
}

fn check_documents(documents: &[ProducedDocument]) -> Result<(), String> {
    if documents.is_empty() || documents.len() > MAX_PRODUCED_DOCUMENTS {
        return Err(format!(
            "a production names 1..={MAX_PRODUCED_DOCUMENTS} documents; this one names {}",
            documents.len()
        ));
    }
    let mut seen: Vec<&Oid> = documents.iter().map(|d| &d.document).collect();
    seen.sort_by_key(|o| o.0);
    if seen.windows(2).any(|w| w[0] == w[1]) {
        return Err("a production names each document once".into());
    }
    for d in documents {
        if d.pages.is_some_and(|p| p == 0 || p > MAX_BATES) {
            return Err(format!(
                "document {}: a page count is 1..={MAX_BATES}",
                hex(&d.document.0)
            ));
        }
        if d.designation.is_some_and(|g| g > MAX_DESIGNATION) {
            return Err(format!(
                "document {}: designation {} is not registered (0 none, 1 CONFIDENTIAL, 2 ATTORNEYS' EYES ONLY, 3 HIGHLY CONFIDENTIAL)",
                hex(&d.document.0),
                d.designation.unwrap_or_default()
            ));
        }
    }
    Ok(())
}

/// Produce `documents` in `matter` (plan §13.2, Appendix B `Produce`):
/// refused before any read on structure or authority. Then, in one
/// transaction: the capability not revoked; the record's identity (the
/// identical request again is its recorded outcome); the matter's profile
/// open; each document held and verified; a document the matter produced
/// before keeps its range; every other document receives the next numbers
/// in request order, `next_bates` moves by compare-and-set, and the Produce
/// record journals exactly the ranges it assigned.
pub async fn produce<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    matter: &str,
    documents: Vec<ProducedDocument>,
    req: ProductionRequest,
) -> Outcome<Produced> {
    if let Err(why) = check_matter(matter).and_then(|()| check_documents(&documents)) {
        return Ok(Err(usage(
            why,
            "fa produce --matter <matter> --document <oid>[:pages[:designation]]... --out <new-dir>",
        )));
    }
    if let Err(r) = admit(db, book, &req.capability, Kind::Produce)? {
        return Ok(Err(r));
    }
    let digest = request_digest(matter, &documents)?;
    let vid = production_profile_vid(book.book_id, matter);
    let key = record_key(Kind::Produce, vid, &req.idempotency_key);
    let evid = entry_vid(book.book_id, &req.capability.holder().0.to_le_bytes(), &key);
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let Some(row) = txn.vertex(db, vid)? else {
        txn.abort();
        return Ok(Err(unknown(matter)));
    };
    if !row.labels.contains(&label::PRODUCTION_PROFILE) {
        txn.abort();
        return Err(KernelError::Corrupt(format!(
            "production identity {:032x} holds a vertex that is not a ProductionProfile",
            vid.0
        )));
    }
    let profile = profile_of(&row)?;
    if profile.vid() != vid {
        txn.abort();
        return Err(KernelError::Corrupt(format!(
            "production profile {:032x} carries another matter's body",
            vid.0
        )));
    }
    if let Some(stored) = txn.vertex(db, evid)? {
        txn.abort();
        return recorded_production(db, book, &profile, &stored, &digest, &documents);
    }
    // Property-granular point reads: a concurrent production that moves
    // `next_bates` first makes this transaction a first-committer conflict.
    if ProductionState::from_scalar(txn.vertex_property(db, vid, property::STATE)?.as_ref())
        != Some(ProductionState::Open)
    {
        txn.abort();
        return Err(KernelError::Corrupt(format!(
            "production profile {:032x} state mirror",
            vid.0
        )));
    }
    let read_next = txn.vertex_property(db, vid, property::NEXT_BATES)?;
    let mut next = next_of(read_next.as_ref(), vid)?;
    let mut ranges = Vec::with_capacity(documents.len());
    let mut assigned = Vec::new();
    for d in &documents {
        let record = match witness_document(&txn, db, &d.document)? {
            Ok(record) => record,
            Err(r) => {
                txn.abort();
                return Ok(Err(r));
            }
        };
        let range_vid = bates_range_vid(book.book_id, matter, &d.document);
        if let Some(existing) = txn.vertex(db, range_vid)? {
            let (_, range, _) = decode_range_payload(&bytes(
                &existing,
                property::FA_PAYLOAD,
                "bates_range._fa_payload",
            )?)?;
            if range.doc_commit != record.doc_commit {
                txn.abort();
                return Err(KernelError::Corrupt(format!(
                    "Bates range {:032x} commits to another document",
                    range_vid.0
                )));
            }
            let what = if d.pages.is_some_and(|p| p != range.pages()) {
                Some("page count")
            } else if d.designation.is_some_and(|g| g != range.designation) {
                Some("designation")
            } else {
                None
            };
            if let Some(what) = what {
                txn.abort();
                return Ok(Err(range_fixed(&profile, &range, what)));
            }
            ranges.push(ProducedRange {
                range,
                assigned: false,
            });
            continue;
        }
        let pages = d.pages.unwrap_or(1);
        // `next_bates` stays representable: the last range ends before MAX_BATES.
        let Some(end) = next.checked_add(pages - 1).filter(|end| *end < MAX_BATES) else {
            txn.abort();
            return Ok(Err(usage(
                format!(
                    "matter `{matter}` would pass the last Bates number {MAX_BATES} at document {}",
                    hex(&d.document.0)
                ),
                "open a new matter profile with another Bates prefix for further productions",
            )));
        };
        let range = BatesRange {
            document: d.document,
            doc_commit: record.doc_commit,
            start: next,
            end,
            designation: d.designation.unwrap_or(0),
        };
        next = end + 1;
        assigned.push((range_vid, range.clone()));
        ranges.push(ProducedRange {
            range,
            assigned: true,
        });
    }
    if assigned.is_empty() {
        txn.abort();
        return Ok(Ok(Produced {
            profile,
            ranges,
            record: None,
            next_bates: next,
            already_recorded: false,
        }));
    }
    let record = BatesRecord {
        matter: matter.to_string(),
        request_digest: digest,
        ranges: assigned.iter().map(|(_, r)| r.clone()).collect(),
    };
    let proof_refs = assigned
        .iter()
        .map(|(_, r)| TypedRef::Object(r.document))
        .collect();
    let proposal = record_proposal(
        book,
        &profile,
        Kind::Produce,
        &req,
        proof_refs,
        (
            fa_model::entry::PRODUCTION_BATES_EXTENSION,
            record.canonical_bytes()?,
        ),
    )?;
    if proposal.validate().is_err() {
        txn.abort();
        return Ok(Err(usage(
            "the Produce record is not a valid ProductionControl entry",
            "produce fewer documents at once",
        )));
    }
    let entry = proposal.clone().seal(Vec::new(), None)?;
    let mut batch = WriteBatch::new(relation::IN_CASE);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    batch.add_edge(edge_id(relation::IN_CASE, evid, vid), evid, vid, vec![]);
    for (range_vid, range) in &assigned {
        let mut props = vec![
            (
                property::FA_PAYLOAD,
                scalar_bytes(
                    "bates_range._fa_payload",
                    range_payload(matter, range, evid)?,
                )?,
            ),
            (
                property::BOOK_ID,
                scalar_bytes("book_id", book.book_id.0.to_vec())?,
            ),
        ];
        props.sort_by_key(|(k, _)| k.0);
        batch.create_vertex(*range_vid, vec![label::BATES_RANGE], props);
    }
    batch.compare_and_set_vertex_property(
        vid,
        property::NEXT_BATES,
        read_next,
        next_scalar(next)?,
        WriteMismatchPolicy::AbortWrite,
    );
    if let Err(e) = txn.write(db, batch) {
        txn.abort();
        return Err(e.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(Produced {
            profile,
            ranges,
            record: Some((evid, seq)),
            next_bates: next,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(fcw(&detail)))
        }
        Err(WriteTxnError::Write(fgdb::WriteError::CompareAndSetMismatch(_))) => {
            Ok(Err(fcw("the matter's next Bates number moved")))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => match db.vertex(evid)? {
            Some(stored) => recorded_production(db, book, &profile, &stored, &digest, &documents),
            // A concurrent production assigned one of these documents first.
            None => Ok(Err(fcw(
                "a document was produced in the matter concurrently",
            ))),
        },
        Err(e) => Err(e.into()),
    }
}

/// The outcome of a Produce record already journaled under this request's
/// identity: the identical request gets every document's recorded range;
/// another request under the same key is a conflict.
fn recorded_production<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    profile: &ProductionProfile,
    stored: &VertexRow,
    digest: &[u8; 32],
    documents: &[ProducedDocument],
) -> Outcome<Produced> {
    let (entry, recorded_at) = crate::post::entry_of(stored)?;
    let Some(record) = bates_record(&entry)? else {
        return Ok(Err(conflict_with(stored)));
    };
    if &record.request_digest != digest || record.matter != profile.matter {
        return Ok(Err(conflict_with(stored)));
    }
    let mut ranges = Vec::with_capacity(documents.len());
    for d in documents {
        let range_vid = bates_range_vid(book.book_id, &profile.matter, &d.document);
        let Some(row) = db.vertex(range_vid)? else {
            return Err(KernelError::Corrupt(format!(
                "Produce record {:032x} has no Bates range for document {}",
                stored.vid.0,
                hex(&d.document.0)
            )));
        };
        let (_, range, by) = decode_range_payload(&bytes(
            &row,
            property::FA_PAYLOAD,
            "bates_range._fa_payload",
        )?)?;
        ranges.push(ProducedRange {
            range,
            assigned: by == stored.vid,
        });
    }
    let next = next_of(
        db.vertex(profile.vid())?
            .as_ref()
            .and_then(|row| prop(row, property::NEXT_BATES)),
        profile.vid(),
    )?;
    Ok(Ok(Produced {
        profile: profile.clone(),
        ranges,
        record: Some((stored.vid, recorded_at)),
        next_bates: next,
        already_recorded: true,
    }))
}

/// A `ProductionControl` Produce record's ranges; `None` for any other
/// entry.
fn bates_record(entry: &fa_model::Entry) -> Result<Option<BatesRecord>, KernelError> {
    if entry.proposal.class != EntryClass::PRODUCTION_CONTROL {
        return Ok(None);
    }
    let Some((_, ext)) = entry
        .proposal
        .extensions
        .iter()
        .find(|(tag, _)| *tag == fa_model::entry::PRODUCTION_BATES_EXTENSION)
    else {
        return Ok(None);
    };
    BatesRecord::decode(ext).map(Some)
}

/// The production profile of `matter` and every range its records assigned,
/// at the head.
pub fn read_production<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    matter: &str,
) -> Result<Option<ProductionView>, KernelError> {
    let vid = production_profile_vid(book.book_id, matter);
    match db.vertex(vid)? {
        Some(row) if row.labels.contains(&label::PRODUCTION_PROFILE) => {
            Ok(Some(view_of(db, &row)?))
        }
        Some(_) => Err(KernelError::Corrupt(format!(
            "production identity {:032x} holds a vertex that is not a ProductionProfile",
            vid.0
        ))),
        None => Ok(None),
    }
}

/// Every matter's production profile, by opening sequence.
pub fn list_productions<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
) -> Result<Vec<ProductionView>, KernelError> {
    let mut out = Vec::new();
    for row in db.vertices()? {
        if row.labels.contains(&label::PRODUCTION_PROFILE) {
            let view = view_of(db, &row)?;
            if view.profile.book_id == book.book_id {
                out.push(view);
            }
        }
    }
    out.sort_by_key(|v| (v.opened_at, v.vid.0));
    Ok(out)
}

/// Every matter's range for `document`, by matter: what `fa document show`
/// lists (plan §13.2).
pub fn document_ranges<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    document: &Oid,
) -> Result<Vec<(ProductionProfile, RecordedRange)>, KernelError> {
    let mut out = Vec::new();
    for view in list_productions(db, book)? {
        if let Some(range) = view.ranges.iter().find(|r| &r.range.document == document) {
            out.push((view.profile.clone(), range.clone()));
        }
    }
    out.sort_by(|a, b| a.0.matter.cmp(&b.0.matter));
    Ok(out)
}

/// A profile as its records state it: the Open record and every Produce
/// record's ranges, each cross-checked against its staged `BatesRange`.
fn view_of<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    row: &VertexRow,
) -> Result<ProductionView, KernelError> {
    let vid = row.vid;
    let profile = profile_of(row)?;
    if profile.vid() != vid {
        return Err(KernelError::Corrupt(format!(
            "production profile {:032x} carries another matter's body",
            vid.0
        )));
    }
    let state = ProductionState::from_scalar(prop(row, property::STATE)).ok_or_else(|| {
        KernelError::Corrupt(format!("production profile {:032x} state mirror", vid.0))
    })?;
    let next_bates = next_of(prop(row, property::NEXT_BATES), vid)?;
    let seq = db.frontier()?;
    let mut opened = None;
    let mut ranges = Vec::new();
    let open = ProductionState::Open.tag();
    for edge in db.edges_at(seq)? {
        let e = &edge.entry;
        if e.dst != vid
            || e.relation != relation::IN_CASE
            || e.eid != edge_id(relation::IN_CASE, e.src, vid)
        {
            continue;
        }
        let Some(src) = db.vertex_at(e.src, seq)? else {
            continue;
        };
        if !src.labels.contains(&label::ENTRY) {
            continue;
        }
        let (entry, recorded_at) = crate::post::entry_of(&src)?;
        if entry.proposal.class != EntryClass::PRODUCTION_CONTROL {
            continue;
        }
        let Some(ControlPayload::LifecycleTransition {
            object_ref,
            from,
            to,
            ..
        }) = &entry.proposal.control
        else {
            return Err(KernelError::Corrupt(format!(
                "production record {:032x} carries no LifecycleTransition",
                e.src.0
            )));
        };
        if *object_ref != vid {
            continue;
        }
        match (*from, *to) {
            (0, t) if t == open => opened = Some((recorded_at, entry.proposal.principal_ref)),
            (f, t) if f == open && t == open => {
                let Some(record) = bates_record(&entry)? else {
                    return Err(KernelError::Corrupt(format!(
                        "Produce record {:032x} carries no Bates ranges",
                        e.src.0
                    )));
                };
                for range in record.ranges {
                    let range_vid =
                        bates_range_vid(profile.book_id, &profile.matter, &range.document);
                    let staged = db.vertex_at(range_vid, seq)?.ok_or_else(|| {
                        KernelError::Corrupt(format!(
                            "Produce record {:032x} assigned a range with no BatesRange vertex",
                            e.src.0
                        ))
                    })?;
                    let (matter, staged_range, by) = decode_range_payload(&bytes(
                        &staged,
                        property::FA_PAYLOAD,
                        "bates_range._fa_payload",
                    )?)?;
                    if matter != profile.matter || staged_range != range || by != e.src {
                        return Err(KernelError::Corrupt(format!(
                            "BatesRange {:032x} disagrees with the Produce record that assigned it",
                            range_vid.0
                        )));
                    }
                    ranges.push(RecordedRange {
                        range,
                        record: e.src,
                        recorded_at,
                        produced_by: entry.proposal.principal_ref,
                    });
                }
            }
            _ => {
                return Err(KernelError::Corrupt(format!(
                    "production record {:032x} names transition {from} -> {to}",
                    e.src.0
                )));
            }
        }
    }
    let (opened_at, opened_by) = opened.ok_or_else(|| {
        KernelError::Corrupt(format!(
            "production profile {:032x} has no Open record",
            vid.0
        ))
    })?;
    ranges.sort_by_key(|r| r.range.start);
    if ranges
        .windows(2)
        .any(|w| w[1].range.start <= w[0].range.end)
        || ranges
            .first()
            .is_some_and(|r| r.range.start != profile.first_bates)
        || ranges
            .last()
            .map_or(profile.first_bates, |r| r.range.end + 1)
            != next_bates
    {
        return Err(KernelError::Corrupt(format!(
            "matter `{}`: its recorded ranges are not contiguous from {} to next_bates {next_bates}",
            profile.matter, profile.first_bates
        )));
    }
    Ok(ProductionView {
        vid,
        profile,
        state,
        opened_at,
        opened_by,
        next_bates,
        ranges,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> ProductionProfile {
        ProductionProfile {
            book_id: Id128([7; 16]),
            matter: "SEC v. Acme".into(),
            bates_prefix: "ACME-SEC".into(),
            first_bates: 1,
            load_file_format: 1,
            protective_order: Some(Oid([9; 32])),
        }
    }

    #[test]
    fn profiles_round_trip_and_refuse_every_truncation_and_bad_field() {
        let p = profile();
        let bytes = p.canonical_bytes().unwrap();
        assert_eq!(ProductionProfile::decode(&bytes).unwrap(), p);
        for end in 0..bytes.len() {
            assert!(ProductionProfile::decode(&bytes[..end]).is_err(), "{end}");
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ProductionProfile::decode(&trailing).is_err());
        for bad in [
            ProductionProfile {
                bates_prefix: String::new(),
                ..profile()
            },
            ProductionProfile {
                bates_prefix: "ACME SEC".into(),
                ..profile()
            },
            ProductionProfile {
                bates_prefix: "A".repeat(17),
                ..profile()
            },
            ProductionProfile {
                first_bates: 0,
                ..profile()
            },
            ProductionProfile {
                load_file_format: 4,
                ..profile()
            },
            ProductionProfile {
                matter: " padded".into(),
                ..profile()
            },
        ] {
            assert!(bad.check().is_err(), "{bad:?}");
            let bytes = bad.canonical_bytes().unwrap();
            assert!(ProductionProfile::decode(&bytes).is_err(), "{bad:?}");
        }
        assert_eq!(p.label(42), "ACME-SEC-00000042");
    }

    #[test]
    fn bates_records_round_trip_and_refuse_inverted_or_undesignated_ranges() {
        let range = BatesRange {
            document: Oid([1; 32]),
            doc_commit: [2; 32],
            start: 5,
            end: 7,
            designation: 2,
        };
        let record = BatesRecord {
            matter: "M-1".into(),
            request_digest: [3; 32],
            ranges: vec![range.clone()],
        };
        let bytes = record.canonical_bytes().unwrap();
        assert_eq!(BatesRecord::decode(&bytes).unwrap(), record);
        assert_eq!(range.pages(), 3);
        for end in 0..bytes.len() {
            assert!(BatesRecord::decode(&bytes[..end]).is_err(), "{end}");
        }
        for bad in [
            BatesRange {
                start: 0,
                ..range.clone()
            },
            BatesRange {
                end: 4,
                ..range.clone()
            },
            BatesRange {
                designation: 4,
                ..range.clone()
            },
        ] {
            let bytes = BatesRecord {
                ranges: vec![bad.clone()],
                ..record.clone()
            }
            .canonical_bytes()
            .unwrap();
            assert!(BatesRecord::decode(&bytes).is_err(), "{bad:?}");
        }
        let empty = BatesRecord {
            ranges: Vec::new(),
            ..record.clone()
        }
        .canonical_bytes()
        .unwrap();
        assert!(BatesRecord::decode(&empty).is_err());
        let payload = range_payload("M-1", &range, VId(11)).unwrap();
        assert_eq!(
            decode_range_payload(&payload).unwrap(),
            ("M-1".to_string(), range, VId(11))
        );
    }

    #[test]
    fn requests_bind_order_pages_and_designations() {
        let a = ProducedDocument {
            document: Oid([1; 32]),
            pages: None,
            designation: None,
        };
        let b = ProducedDocument {
            document: Oid([2; 32]),
            pages: Some(3),
            designation: Some(1),
        };
        let base = request_digest("M", &[a.clone(), b.clone()]).unwrap();
        assert_ne!(base, request_digest("M", &[b.clone(), a.clone()]).unwrap());
        assert_ne!(base, request_digest("N", &[a.clone(), b.clone()]).unwrap());
        let paged = ProducedDocument {
            pages: Some(1),
            ..a.clone()
        };
        assert_ne!(base, request_digest("M", &[paged, b.clone()]).unwrap());
        assert!(check_documents(&[]).is_err());
        assert!(check_documents(&[a.clone(), a.clone()]).is_err());
        assert!(
            check_documents(&[ProducedDocument {
                pages: Some(0),
                ..a.clone()
            }])
            .is_err()
        );
        assert!(
            check_documents(&[ProducedDocument {
                designation: Some(4),
                ..a.clone()
            }])
            .is_err()
        );
        assert!(check_documents(&[a, b]).is_ok());
    }
}
