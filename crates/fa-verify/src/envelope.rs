//! The leaf envelope and the record it commits (plan §13.2, Appendix A).
//!
//! ```text
//! LeafEnvelope { kind: u8, book_id: [16], branch_id: [16], commit_seq: u64,
//!                within_commit_ordinal: u32, record_digest: [32], class: u16,
//!                effective_day: Option<i32>, account_vids: sorted [u128],
//!                unit_ids: sorted [u32] }
//! ```
//!
//! The envelope, not the checkpoint, binds each record's commit sequence and
//! within-commit ordinal, so leaf order is `(commit_seq, ordinal)` and the
//! selection fields let a verifier apply a scope predicate without payloads.
//! When the payload is supplied, the verifier recomputes the record digest
//! from its bytes and rebuilds every selection field from them: an envelope
//! that disagrees with its own record is refused.
//!
//! The record of kind 1 is an `fa:entry:v1` payload (the `_fa_payload`
//! bytes): `proposal ‖ envelope ‖ proposal_digest ‖ entry_digest`, with
//! `proposal_digest = BLAKE3("fa:entry-proposal:v1" ‖ proposal)` and
//! `record_digest = entry_digest = BLAKE3("fa:entry:v1" ‖ proposal_digest ‖
//! envelope)`. The verifier is told where the proposal ends and checks both
//! trailing digests against its recomputation, so a wrong split cannot pass
//! (it would change the proposal digest).

use crate::blake3::hash_parts;
use crate::codec::{DecodeError, Reader, Reason, Writer};

pub(crate) mod access;
mod reconciled;

/// Record kinds covered by the accumulator (plan §13.2, bead `fa-va02`):
/// journal entries (posting and control classes), attestations (`Reviewed`,
/// `ManualAssertion`, `RegisterEquals`, `Reconciled`), custody receipts and transfers, and
/// supplemental evidence attachments, and recorded access events.
pub const KIND_ENTRY: u8 = 1;
pub const KIND_ATTESTATION: u8 = 2;
pub const KIND_IMPORT_RECEIPT: u8 = 3;
pub const KIND_CUSTODY_TRANSFER: u8 = 4;
pub const KIND_SUPPLEMENTAL_EVIDENCE: u8 = 5;
pub const KIND_ACCESS_EVENT: u8 = 6;

pub const PROPOSAL_DIGEST_DOMAIN: &[u8] = b"fa:entry-proposal:v1";
pub const ENTRY_DIGEST_DOMAIN: &[u8] = b"fa:entry:v1";
pub const ATTESTATION_DIGEST_DOMAIN: &[u8] = b"fa:attestation:v1";
pub const CUSTODY_DIGEST_DOMAIN: &[u8] = b"fa:custody:v1";
pub const SUPPLEMENTAL_DIGEST_DOMAIN: &[u8] = b"fa:supplemental-evidence:v1";
pub const ACCESS_EVENT_DIGEST_DOMAIN: &[u8] = b"fa:access-event-digest:v1";
pub const REGISTER_CELL_DOMAIN: &[u8] = b"fa:register-cell:v1";

/// The entry classes that are book-scoped and undated (`SchemaControl`,
/// `PolicyControl`, `TimeControl`, `SweepControl`, `ScheduleControl`,
/// `ImportControl`, `HoldControl`, `DraftControl`, `ScenarioControl`,
/// `ProductionControl`, `IssuanceControl`, `EngagementControl`,
/// `CaseControl`; `registries/entry_classes.toml`): their envelopes carry no
/// effective day. Every other class is period-scoped and carries one.
pub const UNDATED_CLASSES: [u16; 13] = [17, 18, 19, 20, 21, 23, 24, 25, 26, 27, 28, 29, 30];

/// Bounds for the selection lists (`max_legs_per_entry` bounds both).
pub const MAX_ENVELOPE_LIST: usize = 4096;
/// The largest entry payload (`max_entry_bytes`).
pub const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafEnvelope {
    pub kind: u8,
    pub book_id: [u8; 16],
    pub branch_id: [u8; 16],
    pub commit_seq: u64,
    pub within_commit_ordinal: u32,
    pub record_digest: [u8; 32],
    pub class: u16,
    pub effective_day: Option<i32>,
    /// Strictly ascending.
    pub account_vids: Vec<u128>,
    /// Strictly ascending.
    pub unit_ids: Vec<u32>,
}

fn strictly_ascending<T: Ord>(v: &[T]) -> bool {
    v.windows(2).all(|w| w[0] < w[1])
}

impl LeafEnvelope {
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let kind = r.u8("envelope.kind")?;
        if !matches!(
            kind,
            KIND_ENTRY
                | KIND_ATTESTATION
                | KIND_IMPORT_RECEIPT
                | KIND_CUSTODY_TRANSFER
                | KIND_SUPPLEMENTAL_EVIDENCE
                | KIND_ACCESS_EVENT
        ) {
            return Err(r.error("envelope.kind", Reason::BadTag(kind)));
        }
        let book_id = r.fixed("envelope.book_id")?;
        let branch_id = r.fixed("envelope.branch_id")?;
        let commit_seq = r.u64("envelope.commit_seq")?;
        let within_commit_ordinal = r.u32("envelope.within_commit_ordinal")?;
        let record_digest = r.fixed("envelope.record_digest")?;
        let class = r.u16("envelope.class")?;
        let effective_day = if r.present("envelope.effective_day")? {
            Some(r.i32("envelope.effective_day")?)
        } else {
            None
        };
        let n = r.count(MAX_ENVELOPE_LIST, 16, "envelope.account_vids")?;
        let mut account_vids = Vec::with_capacity(n);
        for _ in 0..n {
            account_vids.push(r.u128("envelope.account_vid")?);
        }
        if !strictly_ascending(&account_vids) {
            return Err(r.error("envelope.account_vids", Reason::Unsorted));
        }
        let n = r.count(MAX_ENVELOPE_LIST, 4, "envelope.unit_ids")?;
        let mut unit_ids = Vec::with_capacity(n);
        for _ in 0..n {
            unit_ids.push(r.u32("envelope.unit_id")?);
        }
        if !strictly_ascending(&unit_ids) {
            return Err(r.error("envelope.unit_ids", Reason::Unsorted));
        }
        r.finish("envelope")?;
        Ok(Self {
            kind,
            book_id,
            branch_id,
            commit_seq,
            within_commit_ordinal,
            record_digest,
            class,
            effective_day,
            account_vids,
            unit_ids,
        })
    }

    /// The canonical bytes (the inverse of [`LeafEnvelope::decode`]).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u8(self.kind)
            .fixed(&self.book_id)
            .fixed(&self.branch_id)
            .u64(self.commit_seq)
            .u32(self.within_commit_ordinal)
            .fixed(&self.record_digest)
            .u16(self.class);
        match self.effective_day {
            None => {
                w.u8(0);
            }
            Some(d) => {
                w.u8(1).i32(d);
            }
        }
        w.count(self.account_vids.len());
        for v in &self.account_vids {
            w.u128(*v);
        }
        w.count(self.unit_ids.len());
        for u in &self.unit_ids {
            w.u32(*u);
        }
        w.buf
    }

    /// `(commit_seq, within_commit_ordinal)`: the leaf order.
    #[must_use]
    pub fn position(&self) -> (u64, u32) {
        (self.commit_seq, self.within_commit_ordinal)
    }
}

/// Why a supplied record does not support its envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// The record bytes do not parse as an `fa:entry:v1` payload.
    Decode(DecodeError),
    /// The split hint does not leave room for the envelope and two digests.
    Split,
    /// A trailing digest does not match its recomputation from the bytes.
    Digest { which: &'static str },
    /// The envelope rebuilt from the record differs from the one presented.
    Envelope,
}

/// One leg of an `fa:entry:v1` proposal, as a fold reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Leg {
    pub debit: bool,
    pub account: u128,
    pub unit: u32,
    /// Non-negative in a valid entry; the fold checks rather than assumes.
    pub mantissa: i128,
}

/// Application facts retained independently of the public balance-leg view.
/// A digest authenticates the target payload; the VId identifies its leg.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SettlementRef {
    pub target: u128,
    pub digest: [u8; 32],
    pub ordinal: u16,
    pub unit: u32,
    pub amount: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LegDetails {
    pub base_amount: Option<(u32, i128)>,
    pub dimensions: Vec<(u32, u128)>,
    pub settlements: Vec<SettlementRef>,
}

/// The selection fields an `fa:entry:v1` proposal determines, read from the
/// front of the proposal through its legs. Every byte after the legs is
/// covered by the digests and does not feed an envelope field.
struct ProposalPrefix {
    book_id: [u8; 16],
    branch_id: [u8; 16],
    class: u16,
    effective_date: i32,
    legs: Vec<Leg>,
    leg_details: Vec<LegDetails>,
}

impl ProposalPrefix {
    fn account_vids(&self) -> Vec<u128> {
        let mut v: Vec<u128> = self.legs.iter().map(|l| l.account).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    fn unit_ids(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.legs.iter().map(|l| l.unit).collect();
        v.sort_unstable();
        v.dedup();
        v
    }
}

/// The `fa:entry:v1` erasable field: digest, optional subject, nonce, sealed
/// bytes. Its content never feeds an envelope; it is skipped exactly.
pub(crate) fn skip_erasable(r: &mut Reader<'_>, what: &'static str) -> Result<(), DecodeError> {
    r.fixed::<32>(what)?;
    if r.present(what)? {
        r.u128(what)?;
    }
    r.fixed::<24>(what)?;
    r.bytes(MAX_RECORD_BYTES, what)?;
    Ok(())
}

fn amount(r: &mut Reader<'_>, what: &'static str) -> Result<(u32, i128), DecodeError> {
    Ok((r.u32(what)?, r.i128(what)?))
}

fn proposal_prefix(proposal: &[u8]) -> Result<ProposalPrefix, DecodeError> {
    read_proposal_prefix(&mut Reader::new(proposal))
}

/// Continue an authenticated proposal after its legs without duplicating
/// the prefix decoder used to recompute its leaf envelope. This positions
/// a reader; it does not authenticate the proposal by itself.
pub(crate) fn proposal_after_legs(proposal: &[u8]) -> Result<Reader<'_>, DecodeError> {
    let mut r = Reader::new(proposal);
    read_proposal_prefix(&mut r)?;
    Ok(r)
}

/// Decode application facts from the same canonical prefix parser that derives
/// leaf selectors. Authentication remains the caller's `check_record` duty.
pub(crate) fn proposal_leg_details(proposal: &[u8]) -> Result<Vec<LegDetails>, DecodeError> {
    Ok(proposal_prefix(proposal)?.leg_details)
}

fn read_proposal_prefix(r: &mut Reader<'_>) -> Result<ProposalPrefix, DecodeError> {
    let major = r.u16("entry.schema_major")?;
    if major != 1 {
        return Err(r.error("entry.schema_major", Reason::BadTag(major.to_le_bytes()[0])));
    }
    r.u16("entry.schema_minor")?;
    let book_id = r.fixed("entry.book_id")?;
    let branch_id = r.fixed("entry.branch_id")?;
    let class = r.u16("entry.class")?;
    // The supported native registry assigns posting classes 1..=15 and
    // control classes 16..=30. Validate this vocabulary while deriving every
    // record, before a report can exclude its date, prefix or retired state.
    if class == 0 {
        return Err(r.error("entry.class", Reason::BadTag(0)));
    }
    if class > 30 {
        return Err(r.error(
            "entry.class",
            Reason::TooLong {
                max: 30,
                actual: usize::from(class),
            },
        ));
    }
    let effective_date = r.i32("entry.effective_date")?;
    if r.present("entry.document_date")? {
        r.i32("entry.document_date")?;
    }
    skip_erasable(r, "entry.description")?;
    if r.present("entry.effective_period")? {
        r.bytes(MAX_RECORD_BYTES, "entry.effective_period.calendar")?;
        r.bytes(MAX_RECORD_BYTES, "entry.effective_period.code")?;
    }
    // side u8, account u128, amount (u32, i128), option tag, two counts, memo tag.
    // Native control records carry no monetary legs, including the dated
    // PeriodControl and MigrationControl classes. Enforce zero before any
    // leg allocation; otherwise a resealed control could masquerade as a post.
    let max_legs = if class >= 16 { 0 } else { MAX_ENVELOPE_LIST };
    let legs = r.count(max_legs, 1 + 16 + 20 + 1 + 4 + 1 + 4, "entry.legs")?;
    let mut parsed = Vec::with_capacity(legs);
    let mut leg_details = Vec::with_capacity(legs);
    for _ in 0..legs {
        let debit = match r.u8("leg.side")? {
            0 => true,
            1 => false,
            t => return Err(r.error("leg.side", Reason::BadTag(t))),
        };
        let account = r.u128("leg.account_ref")?;
        let (unit, mantissa) = amount(r, "leg.amount")?;
        parsed.push(Leg {
            debit,
            account,
            unit,
            mantissa,
        });
        let base_amount = if r.present("leg.base_amount")? {
            Some(amount(r, "leg.base_amount")?)
        } else {
            None
        };
        // Authenticate the native dimension bound and order before any report
        // selection can exclude a malformed record.
        let dims = r.count(64, 20, "leg.dimension_set")?;
        let mut dimensions = Vec::with_capacity(dims);
        let mut previous = None;
        for _ in 0..dims {
            let id = r.u32("dimension.id")?;
            if previous.is_some_and(|before| before >= id) {
                return Err(r.error("leg.dimension_set", Reason::Unsorted));
            }
            previous = Some(id);
            dimensions.push((id, r.u128("dimension.value")?));
        }
        if r.present("leg.memo")? {
            skip_erasable(r, "leg.memo")?;
        }
        let settles = r.count(MAX_ENVELOPE_LIST, 16 + 32 + 2 + 20, "leg.settles")?;
        let mut settlements = Vec::with_capacity(settles);
        for _ in 0..settles {
            let target = r.u128("settles.target.vid")?;
            let digest = r.fixed("settles.target.entry_digest")?;
            let ordinal = r.u16("settles.ordinal")?;
            let (unit, amount) = amount(r, "settles.amount")?;
            settlements.push(SettlementRef {
                target,
                digest,
                ordinal,
                unit,
                amount,
            });
        }
        leg_details.push(LegDetails {
            base_amount,
            dimensions,
            settlements,
        });
    }
    Ok(ProposalPrefix {
        book_id,
        branch_id,
        class,
        effective_date,
        legs: parsed,
        leg_details,
    })
}

/// Bound for the schema-change bytes and the other variable fields skipped
/// on the way to the evidence list.
const MAX_FIELD_BYTES: usize = MAX_RECORD_BYTES;

fn oid(r: &mut Reader<'_>, what: &'static str) -> Result<(), DecodeError> {
    r.fixed::<32>(what).map(|_| ())
}

fn opt_u128(r: &mut Reader<'_>, what: &'static str) -> Result<(), DecodeError> {
    if r.present(what)? {
        r.u128(what)?;
    }
    Ok(())
}

/// The control payload (Appendix A `ControlPayload`, tags 0–11 and 13; 12
/// is unassigned), skipped exactly. An unknown tag is refused: this
/// verifier cannot know where the evidence list starts after a payload it
/// does not read.
pub(crate) fn skip_control(r: &mut Reader<'_>) -> Result<(), DecodeError> {
    match r.u8("control.tag")? {
        0 => {
            r.bytes(MAX_FIELD_BYTES, "control.period_ref.calendar")?;
            r.bytes(MAX_FIELD_BYTES, "control.period_ref.code")?;
            r.u8("control.from")?;
            r.u8("control.to")?;
            r.u16("control.reason_code")?;
            opt_u128(r, "control.case_ref")?;
        }
        1 => {
            r.u16("control.kind")?;
            r.bytes(MAX_FIELD_BYTES, "control.canonical_bytes")?;
        }
        2 => {
            oid(r, "control.policy_oid")?;
            r.i32("control.effective_from")?;
            r.i32("control.effective_to")?;
        }
        3 => {
            r.u128("control.object_ref")?;
            r.u8("control.from")?;
            r.u8("control.to")?;
            let n = r.count(MAX_ENVELOPE_LIST, 1 + 16, "control.proof_refs")?;
            for _ in 0..n {
                match r.u8("typed_ref.tag")? {
                    0 => {
                        r.u128("typed_ref.vid")?;
                    }
                    1 => oid(r, "typed_ref.oid")?,
                    t => return Err(r.error("typed_ref.tag", Reason::BadTag(t))),
                }
            }
            r.u16("control.reason_code")?;
        }
        4 => {
            r.u64("control.observed_utc_ns")?;
            r.u8("control.source")?;
            r.present("control.monotonic_ok")?;
        }
        5 => {
            r.u8("control.sweep_kind")?;
            r.u128("control.last_pending_vid")?;
            r.u128("control.tick_ref")?;
        }
        6 => {
            r.u128("control.schedule_ref")?;
            r.u128("control.cause_ref")?;
        }
        7 => {
            r.fixed::<32>("control.commitment")?;
            r.u8("control.kind")?;
            r.fixed::<32>("control.caveats_digest")?;
        }
        8 => {
            r.fixed::<32>("control.scope_digest")?;
            oid(r, "control.authority_oid")?;
            r.u8("control.kind")?;
        }
        9 => {
            r.u128("control.subject_ref")?;
            let n = r.count(MAX_ENVELOPE_LIST, 32, "control.field_digests")?;
            for _ in 0..n {
                r.fixed::<32>("control.field_digest")?;
            }
        }
        10 => {
            r.u128("control.run_ref")?;
            r.u8("control.kind")?;
            r.fixed::<32>("control.tie_out_digest")?;
        }
        11 => {}
        13 => {
            // An import run (fa-txf): its intake source, then its counts
            // and roots.
            match r.u8("control.intake.tag")? {
                1 => {
                    r.u128("control.intake.principal")?;
                }
                2 => {
                    r.bytes(MAX_FIELD_BYTES, "control.intake.name")?;
                    r.bytes(MAX_FIELD_BYTES, "control.intake.version")?;
                }
                3 => {
                    r.bytes(MAX_FIELD_BYTES, "control.intake.message_id")?;
                }
                4 => {
                    r.bytes(MAX_FIELD_BYTES, "control.intake.device")?;
                }
                t => return Err(r.error("control.intake.tag", Reason::BadTag(t))),
            }
            r.u32("control.document_count")?;
            r.u64("control.byte_count")?;
            r.fixed::<32>("control.oids_root")?;
            r.fixed::<32>("control.receipt_hash")?;
        }
        t => return Err(r.error("control.tag", Reason::BadTag(t))),
    }
    Ok(())
}

/// The entry's origin (Appendix A `EntryOrigin`, tags 0–5), skipped exactly.
pub(crate) fn skip_origin(r: &mut Reader<'_>) -> Result<(), DecodeError> {
    match r.u8("origin.tag")? {
        0 => {
            oid(r, "origin.intent_oid")?;
            r.u16("origin.intent_kind")?;
        }
        1 => {
            oid(r, "origin.rule_version_oid")?;
            r.u128("origin.event_ref")?;
            r.fixed::<32>("origin.inputs_digest")?;
        }
        2 => {
            r.u128("origin.run_ref")?;
            r.bytes(MAX_FIELD_BYTES, "origin.source_system")?;
            skip_erasable(r, "origin.source_id")?;
            if r.present("origin.source_recorded_at")? {
                r.i64("origin.source_recorded_at")?;
            }
            for what in ["origin.source_entered_by", "origin.source_approved_by"] {
                if r.present(what)? {
                    skip_erasable(r, what)?;
                }
            }
            oid(r, "origin.batch_oid")?;
        }
        3 => {
            r.u16("origin.control_kind")?;
            r.fixed::<32>("origin.spec_body_digest")?;
        }
        4 => {
            r.u8("origin.sweep_kind")?;
            oid(r, "origin.tick_evidence_oid")?;
        }
        5 => {
            r.u128("origin.schedule_ref")?;
            match r.u8("origin.trigger")? {
                0 | 1 => {
                    r.u128("origin.trigger_ref")?;
                }
                t => return Err(r.error("origin.trigger", Reason::BadTag(t))),
            }
        }
        t => return Err(r.error("origin.tag", Reason::BadTag(t))),
    }
    Ok(())
}

/// The `doc_commit`s an `fa:entry:v1` proposal's evidence list cites,
/// ascending and distinct (one document cited in two roles is one
/// commitment). The proposal is read field by field up to and including
/// the evidence list; what follows it is covered by the digests and cited
/// nothing.
pub fn cited_documents(proposal: &[u8]) -> Result<Vec<[u8; 32]>, DecodeError> {
    let mut r = Reader::new(proposal);
    read_proposal_prefix(&mut r)?;
    if r.present("entry.control")? {
        skip_control(&mut r)?;
    }
    skip_to_principal(&mut r)?;
    opt_u128(&mut r, "entry.session_ref")?;
    let n = r.count(MAX_ENVELOPE_LIST, 32 + 32 + 1, "entry.evidence")?;
    let mut commits = Vec::with_capacity(n);
    for _ in 0..n {
        oid(&mut r, "evidence.document_oid")?;
        commits.push(r.fixed::<32>("evidence.doc_commit")?);
        r.u8("evidence.role")?;
    }
    commits.sort_unstable();
    commits.dedup();
    Ok(commits)
}

/// The fields between an `fa:entry:v1` proposal's control payload and its
/// principal reference, skipped exactly; returns `principal_ref`.
fn skip_to_principal(r: &mut Reader<'_>) -> Result<u128, DecodeError> {
    let n = r.count(MAX_ENVELOPE_LIST, 4 + 16 + 16, "entry.unit_totals")?;
    for _ in 0..n {
        r.u32("unit_total.unit_id")?;
        r.i128("unit_total.debits")?;
        r.i128("unit_total.credits")?;
    }
    if r.present("entry.base_totals")? {
        r.u32("base_totals.unit_id")?;
        r.i128("base_totals.debits")?;
        r.i128("base_totals.credits")?;
        oid(r, "base_totals.fx_law_oid")?;
        let n = r.count(MAX_ENVELOPE_LIST, 32, "base_totals.rate_doc_oids")?;
        for _ in 0..n {
            oid(r, "base_totals.rate_doc_oid")?;
        }
        if r.present("base_totals.residual")? {
            r.u16("residual.leg_ordinal")?;
            amount(r, "residual.amount")?;
        }
    }
    r.bytes(MAX_FIELD_BYTES, "entry.idempotency_key")?;
    skip_origin(r)?;
    r.u128("entry.principal_ref")
}

/// `PolicyControl`, the class a principal-key generation is journaled in.
const CLASS_POLICY_CONTROL: u16 = 18;
const CONTROL_SCHEMA_CHANGE: u8 = 1;
const SCHEMA_CHANGE_PRINCIPAL_KEY: u16 = 24;
/// An entry cites at most this many approvals.
const MAX_ENTRY_APPROVALS: usize = 256;

/// A principal-key generation (a PolicyControl `SchemaChange` of kind 24)
/// in an `fa:entry:v1` proposal.
pub(crate) struct KeyControl<'a> {
    /// The control's canonical bytes: the key generation's body.
    pub canonical: &'a [u8],
    /// The principal that recorded it.
    pub principal_ref: u128,
}

/// The principal-key generation `proposal` carries, or `None` for any other
/// proposal. Nothing about the key itself is judged here.
pub(crate) fn principal_key_control(
    proposal: &[u8],
) -> Result<Option<KeyControl<'_>>, DecodeError> {
    let mut r = Reader::new(proposal);
    let prefix = read_proposal_prefix(&mut r)?;
    if prefix.class != CLASS_POLICY_CONTROL || !r.present("entry.control")? {
        return Ok(None);
    }
    if r.u8("control.tag")? != CONTROL_SCHEMA_CHANGE {
        return Ok(None);
    }
    let kind = r.u16("control.kind")?;
    let canonical = r.bytes(MAX_FIELD_BYTES, "control.canonical_bytes")?;
    if kind != SCHEMA_CHANGE_PRINCIPAL_KEY {
        return Ok(None);
    }
    let principal_ref = skip_to_principal(&mut r)?;
    Ok(Some(KeyControl {
        canonical,
        principal_ref,
    }))
}

/// The approvals an entry's envelope cites: `(approval vid, approved
/// digest)`, in order.
pub(crate) type CitedApprovals = Vec<(u128, [u8; 32])>;

/// The proposal digest of an `fa:entry:v1` payload and the approvals its
/// envelope cites. Read after [`check_record`] authenticated the payload;
/// no digest is checked here.
pub(crate) fn entry_approvals(
    payload: &[u8],
    proposal_len: usize,
) -> Result<([u8; 32], CitedApprovals), RecordError> {
    let n = payload.len();
    if proposal_len > n || n - proposal_len < 64 {
        return Err(RecordError::Split);
    }
    let approvals =
        read_envelope_approvals(&payload[proposal_len..n - 64]).map_err(RecordError::Decode)?;
    let mut proposal_digest = [0u8; 32];
    proposal_digest.copy_from_slice(&payload[n - 64..n - 32]);
    Ok((proposal_digest, approvals))
}

/// `opt(plan_certificate) ‖ list(u128 approval vid ‖ [32] approved digest)`.
fn read_envelope_approvals(envelope: &[u8]) -> Result<CitedApprovals, DecodeError> {
    let mut r = Reader::new(envelope);
    if r.present("entry.plan_certificate")? {
        oid(&mut r, "entry.plan_certificate")?;
    }
    let count = r.count(MAX_ENTRY_APPROVALS, 16 + 32, "entry.approvals")?;
    let mut approvals = Vec::with_capacity(count);
    for _ in 0..count {
        approvals.push((
            r.u128("entry.approval.vid")?,
            r.fixed("entry.approval.approved_digest")?,
        ));
    }
    r.finish("entry envelope")?;
    Ok(approvals)
}

/// Recompute the record digest of an `fa:entry:v1` payload whose proposal
/// is its first `proposal_len` bytes, checking both stored digests.
pub fn entry_record_digest(payload: &[u8], proposal_len: usize) -> Result<[u8; 32], RecordError> {
    let n = payload.len();
    if proposal_len > n || n - proposal_len < 64 {
        return Err(RecordError::Split);
    }
    let proposal = &payload[..proposal_len];
    let envelope = &payload[proposal_len..n - 64];
    let stored_proposal_digest = &payload[n - 64..n - 32];
    let stored_entry_digest = &payload[n - 32..];
    let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[proposal]);
    if proposal_digest[..] != *stored_proposal_digest {
        return Err(RecordError::Digest {
            which: "proposal_digest",
        });
    }
    let entry_digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal_digest, envelope]);
    if entry_digest[..] != *stored_entry_digest {
        return Err(RecordError::Digest {
            which: "entry_digest",
        });
    }
    Ok(entry_digest)
}

/// `BLAKE3(domain ‖ u32::le(body.len()) ‖ body)`.
fn framed_digest(domain: &[u8], body: &[u8]) -> [u8; 32] {
    let len = u32::try_from(body.len()).unwrap_or(u32::MAX).to_le_bytes();
    hash_parts(domain, &[&len, body])
}

fn register_cell_digest(
    account: u128,
    unit_id: u32,
    period: &[u8],
    entity: Option<&[u8]>,
) -> [u8; 32] {
    let account_bytes = account.to_le_bytes();
    let unit_bytes = unit_id.to_le_bytes();
    let entity_bytes: Vec<u8> = match entity {
        None => vec![0],
        Some(e) => {
            let mut v = Vec::with_capacity(1 + e.len());
            v.push(1);
            v.extend_from_slice(e);
            v
        }
    };
    let a_len = 16u32.to_le_bytes();
    let u_len = 4u32.to_le_bytes();
    let p_len = u32::try_from(period.len())
        .unwrap_or(u32::MAX)
        .to_le_bytes();
    let e_len = u32::try_from(entity_bytes.len())
        .unwrap_or(u32::MAX)
        .to_le_bytes();
    hash_parts(
        REGISTER_CELL_DOMAIN,
        &[
            &a_len,
            &account_bytes,
            &u_len,
            &unit_bytes,
            &p_len,
            period,
            &e_len,
            &entity_bytes,
        ],
    )
}

fn non_empty_str<'a>(
    r: &mut Reader<'a>,
    max: usize,
    what: &'static str,
) -> Result<&'a [u8], DecodeError> {
    let bytes = r.bytes(max, what)?;
    if bytes.is_empty() || std::str::from_utf8(bytes).is_err() {
        return Err(r.error(what, Reason::BadTag(0)));
    }
    Ok(bytes)
}

fn attestation_record(
    payload: &[u8],
    proposal_len: usize,
    commit_seq: u64,
    within_commit_ordinal: u32,
) -> Result<LeafEnvelope, RecordError> {
    let n = payload.len();
    if n > MAX_RECORD_BYTES {
        return Err(RecordError::Decode(DecodeError {
            offset: 0,
            what: "attestation.payload",
            reason: Reason::TooLong {
                max: MAX_RECORD_BYTES,
                actual: n,
            },
        }));
    }
    if proposal_len > n || n - proposal_len != 66 {
        return Err(RecordError::Split);
    }
    let body = &payload[..proposal_len];
    let stored_digest = &payload[proposal_len..proposal_len + 32];
    let scheme = payload[proposal_len + 32];
    let profile = payload[proposal_len + 33];
    if scheme != 0 {
        return Err(RecordError::Decode(DecodeError {
            offset: proposal_len + 32,
            what: "attestation.scheme",
            reason: Reason::BadTag(scheme),
        }));
    }
    // The admitting capability's profile tag as the kernel journals it
    // (`fa_policy::Profile::tag`: Human 0, Agent 1, System 2). A review is
    // recorded only under a Human capability, so every real Reviewed
    // attestation carries 0.
    if profile > 2 {
        return Err(RecordError::Decode(DecodeError {
            offset: proposal_len + 33,
            what: "attestation.profile",
            reason: Reason::BadTag(profile),
        }));
    }
    let record_digest = framed_digest(ATTESTATION_DIGEST_DOMAIN, body);
    if record_digest[..] != *stored_digest {
        return Err(RecordError::Digest {
            which: "attestation.signed_digest",
        });
    }
    let (book_id, claim_tag) = (|| -> Result<([u8; 16], u8), DecodeError> {
        let mut r = Reader::new(body);
        let version = r.u16("attestation.version")?;
        if version != 1 {
            return Err(r.error(
                "attestation.version",
                Reason::BadTag(version.to_le_bytes()[0]),
            ));
        }
        let book_id = r.fixed("attestation.book_id")?;
        let claim_tag = r.u8("attestation.claim")?;
        let mut expected_cell = None;
        let mut expected_source = None;
        match claim_tag {
            2 => {
                let count = r.count(1024, 32, "attestation.against")?;
                let mut prev: Option<[u8; 32]> = None;
                for _ in 0..count {
                    let oid = r.fixed::<32>("attestation.against")?;
                    if prev.is_some_and(|p| p >= oid) {
                        return Err(r.error("attestation.against", Reason::Unsorted));
                    }
                    prev = Some(oid);
                }
            }
            8 => {
                r.u16("attestation.reason_code")?;
                skip_erasable(&mut r, "attestation.statement")?;
            }
            // Confirmed: by_party, the balance's unit and mantissa, as_of.
            5 => {
                r.u128("confirmed.by_party")?;
                amount(&mut r, "confirmed.balance")?;
                r.i32("confirmed.as_of")?;
            }
            // Represented: 1..=64 sealed claims (32-byte digest, presence,
            // 24-byte nonce, length: at least 61 bytes each), then as_of.
            9 => {
                let claims = r.count(64, 61, "represented.claims")?;
                if claims == 0 {
                    return Err(r.error("represented.claims", Reason::BadTag(0)));
                }
                for _ in 0..claims {
                    skip_erasable(&mut r, "represented.claim")?;
                }
                r.i32("represented.as_of")?;
            }
            // ExhibitMarked: matter (1..=128 bytes) and label (1..=64 bytes).
            10 => {
                non_empty_str(&mut r, 128, "exhibit_marked.matter")?;
                non_empty_str(&mut r, 64, "exhibit_marked.label")?;
            }
            4 => {
                let account = r.u128("register_equals.account")?;
                let unit_id = r.u32("register_equals.unit_id")?;
                let period = non_empty_str(&mut r, 64, "register_equals.period")?;
                let entity = if r.present("register_equals.entity")? {
                    Some(non_empty_str(&mut r, 64, "register_equals.entity")?)
                } else {
                    None
                };
                r.i128("register_equals.mantissa")?;
                r.i32("register_equals.as_of_effective")?;
                r.u64("register_equals.evaluated_known_at")?;
                r.fixed::<32>("register_equals.fold_digest")?;
                expected_cell = Some(register_cell_digest(account, unit_id, period, entity));
            }
            3 => {
                if profile != 0 {
                    return Err(r.error("reconciled.profile", Reason::BadTag(profile)));
                }
                expected_source = Some(reconciled::read(&mut r, book_id, commit_seq)?);
            }
            t => return Err(r.error("attestation.claim", Reason::BadTag(t))),
        }
        let subjects = r.count(1, 33, "attestation.subject_refs")?;
        if subjects != 1 {
            return Err(r.error("attestation.subject_refs", Reason::BadTag(subjects as u8)));
        }
        let subject_tag = r.u8("attestation.subject")?;
        let subject_bytes = r.fixed::<32>("attestation.subject")?;
        let valid_subject = match (claim_tag, subject_tag) {
            (2, 1) | (8, 2) | (5, 1) | (9, 1) | (10, 1) => true,
            (4, 3) => expected_cell == Some(subject_bytes),
            (3, 1) => expected_source
                .as_ref()
                .is_some_and(|source| source.manifest_oid == subject_bytes),
            _ => false,
        };
        if !valid_subject {
            return Err(r.error("attestation.subject", Reason::BadTag(subject_tag)));
        }
        r.u128("attestation.principal")?;
        if let Some(source) = expected_source {
            let mut expected = [source.manifest_oid, source.statement_oid];
            expected.sort();
            let count = r.count(2, 32, "reconciled.evidence_refs")?;
            if count != 2 || expected[0] == expected[1] {
                return Err(r.error("reconciled.evidence_refs", Reason::BadTag(0)));
            }
            for oid in expected {
                if r.fixed::<32>("reconciled.evidence_ref")? != oid {
                    return Err(r.error("reconciled.evidence_refs", Reason::Unsorted));
                }
            }
        } else if claim_tag == 4 {
            let count = r.count(1024, 32, "attestation.evidence_refs")?;
            let mut prev: Option<[u8; 32]> = None;
            for _ in 0..count {
                let oid = r.fixed::<32>("attestation.evidence_ref")?;
                if prev.is_some_and(|p| p >= oid) {
                    return Err(r.error("attestation.evidence_refs", Reason::Unsorted));
                }
                prev = Some(oid);
            }
        } else {
            let count = r.count(0, 32, "attestation.evidence_refs")?;
            if count != 0 {
                return Err(r.error("attestation.evidence_refs", Reason::BadTag(count as u8)));
            }
        }
        r.finish("attestation.body")?;
        Ok((book_id, claim_tag))
    })()
    .map_err(RecordError::Decode)?;
    Ok(LeafEnvelope {
        kind: KIND_ATTESTATION,
        book_id,
        branch_id: [0; 16],
        commit_seq,
        within_commit_ordinal,
        record_digest,
        class: u16::from(claim_tag),
        effective_day: None,
        account_vids: Vec::new(),
        unit_ids: Vec::new(),
    })
}

fn import_receipt_record(
    payload: &[u8],
    proposal_len: usize,
    commit_seq: u64,
    within_commit_ordinal: u32,
) -> Result<LeafEnvelope, RecordError> {
    let n = payload.len();
    if proposal_len > n || n - proposal_len != 32 {
        return Err(RecordError::Split);
    }
    let body = &payload[..proposal_len];
    let stored_digest = &payload[proposal_len..];
    let record_digest = framed_digest(CUSTODY_DIGEST_DOMAIN, body);
    if record_digest[..] != *stored_digest {
        return Err(RecordError::Digest {
            which: "custody.digest",
        });
    }
    let (book_id, source_tag) = (|| -> Result<([u8; 16], u8), DecodeError> {
        let mut r = Reader::new(body);
        let version = r.u16("custody.version")?;
        if version != 1 {
            return Err(r.error("custody.version", Reason::BadTag(version.to_le_bytes()[0])));
        }
        let book_id = r.fixed("custody.book_id")?;
        r.fixed::<32>("custody.document_oid")?;
        let index = r.u32("custody.index")?;
        if index != 0 {
            return Err(r.error("custody.index", Reason::BadTag(index.to_le_bytes()[0])));
        }
        let prev_digest = r.fixed::<32>("custody.prev_digest")?;
        if prev_digest != [0; 32] {
            return Err(r.error("custody.prev_digest", Reason::BadTag(1)));
        }
        let body_tag = r.u8("custody.body")?;
        if body_tag != 1 {
            return Err(r.error("custody.body", Reason::BadTag(body_tag)));
        }
        let source_tag = r.u8("intake.tag")?;
        match source_tag {
            1 => {
                r.u128("intake.principal")?;
            }
            2 => {
                non_empty_str(&mut r, 256, "intake.name")?;
                non_empty_str(&mut r, 256, "intake.version")?;
            }
            3 => {
                non_empty_str(&mut r, 256, "intake.message_id")?;
            }
            4 => {
                non_empty_str(&mut r, 256, "intake.device")?;
            }
            t => return Err(r.error("intake.tag", Reason::BadTag(t))),
        }
        r.u128("custody.received_by")?;
        r.fixed::<32>("custody.digest_at_receipt")?;
        opt_u128(&mut r, "custody.run_ref")?;
        let count = r.count(0, 1, "custody.transformations")?;
        if count != 0 {
            return Err(r.error("custody.transformations", Reason::BadTag(count as u8)));
        }
        r.finish("custody.body")?;
        Ok((book_id, source_tag))
    })()
    .map_err(RecordError::Decode)?;
    Ok(LeafEnvelope {
        kind: KIND_IMPORT_RECEIPT,
        book_id,
        branch_id: [0; 16],
        commit_seq,
        within_commit_ordinal,
        record_digest,
        class: u16::from(source_tag),
        effective_day: None,
        account_vids: Vec::new(),
        unit_ids: Vec::new(),
    })
}

fn custody_transfer_record(
    payload: &[u8],
    proposal_len: usize,
    commit_seq: u64,
    within_commit_ordinal: u32,
) -> Result<LeafEnvelope, RecordError> {
    let n = payload.len();
    if proposal_len > n || n - proposal_len != 32 {
        return Err(RecordError::Split);
    }
    let body = &payload[..proposal_len];
    let stored_digest = &payload[proposal_len..];
    let record_digest = framed_digest(CUSTODY_DIGEST_DOMAIN, body);
    if record_digest[..] != *stored_digest {
        return Err(RecordError::Digest {
            which: "custody.digest",
        });
    }
    let book_id = (|| -> Result<[u8; 16], DecodeError> {
        let mut r = Reader::new(body);
        let version = r.u16("custody.version")?;
        if version != 1 {
            return Err(r.error("custody.version", Reason::BadTag(version.to_le_bytes()[0])));
        }
        let book_id = r.fixed("custody.book_id")?;
        r.fixed::<32>("custody.document_oid")?;
        let index = r.u32("custody.index")?;
        if index == 0 {
            return Err(r.error("custody.index", Reason::BadTag(0)));
        }
        r.fixed::<32>("custody.prev_digest")?;
        let body_tag = r.u8("custody.body")?;
        if body_tag != 2 {
            return Err(r.error("custody.body", Reason::BadTag(body_tag)));
        }
        r.u128("custody.from")?;
        r.u128("custody.to")?;
        r.finish("custody.body")?;
        Ok(book_id)
    })()
    .map_err(RecordError::Decode)?;
    Ok(LeafEnvelope {
        kind: KIND_CUSTODY_TRANSFER,
        book_id,
        branch_id: [0; 16],
        commit_seq,
        within_commit_ordinal,
        record_digest,
        class: 2,
        effective_day: None,
        account_vids: Vec::new(),
        unit_ids: Vec::new(),
    })
}

fn supplemental_evidence_record(
    payload: &[u8],
    proposal_len: usize,
    commit_seq: u64,
    within_commit_ordinal: u32,
) -> Result<LeafEnvelope, RecordError> {
    let n = payload.len();
    if proposal_len > n || n - proposal_len != 32 {
        return Err(RecordError::Split);
    }
    let body = &payload[..proposal_len];
    let stored_digest = &payload[proposal_len..];
    let record_digest = framed_digest(SUPPLEMENTAL_DIGEST_DOMAIN, body);
    if record_digest[..] != *stored_digest {
        return Err(RecordError::Digest {
            which: "supplement.body_digest",
        });
    }
    let book_id = (|| -> Result<[u8; 16], DecodeError> {
        let mut r = Reader::new(body);
        let version = r.u16("supplement.version")?;
        if version != 1 {
            return Err(r.error(
                "supplement.version",
                Reason::BadTag(version.to_le_bytes()[0]),
            ));
        }
        let book_id = r.fixed("supplement.book_id")?;
        r.u128("supplement.entry_vid")?;
        r.fixed::<32>("supplement.entry_digest")?;
        let count = r.count(1024, 65, "supplement.documents")?;
        if count == 0 {
            return Err(r.error("supplement.documents", Reason::BadTag(0)));
        }
        let mut prev: Option<([u8; 32], [u8; 32], u8)> = None;
        for _ in 0..count {
            let doc_oid = r.fixed::<32>("supplement.document_oid")?;
            let doc_commit = r.fixed::<32>("supplement.doc_commit")?;
            let role = r.u8("supplement.role")?;
            let cur = (doc_oid, doc_commit, role);
            if prev.is_some_and(|p| p >= cur) {
                return Err(r.error("supplement.documents", Reason::Unsorted));
            }
            prev = Some(cur);
        }
        r.u128("supplement.attached_by")?;
        r.finish("supplement.body")?;
        Ok(book_id)
    })()
    .map_err(RecordError::Decode)?;
    Ok(LeafEnvelope {
        kind: KIND_SUPPLEMENTAL_EVIDENCE,
        book_id,
        branch_id: [0; 16],
        commit_seq,
        within_commit_ordinal,
        record_digest,
        class: 1,
        effective_day: None,
        account_vids: Vec::new(),
        unit_ids: Vec::new(),
    })
}

/// The envelope a journal entry's payload determines at journal position
/// `(commit_seq, ordinal)`.
pub fn envelope_of_entry(
    payload: &[u8],
    proposal_len: usize,
    commit_seq: u64,
    within_commit_ordinal: u32,
) -> Result<LeafEnvelope, RecordError> {
    record_of_entry(payload, proposal_len, commit_seq, within_commit_ordinal).map(|(e, _)| e)
}

/// The envelope a journaled record of `kind` (`KIND_ENTRY`,
/// `KIND_ATTESTATION`, `KIND_IMPORT_RECEIPT`, `KIND_CUSTODY_TRANSFER`,
/// `KIND_SUPPLEMENTAL_EVIDENCE`, `KIND_ACCESS_EVENT`) determines at journal position
/// `(commit_seq, ordinal)`.
pub fn envelope_of_record(
    kind: u8,
    payload: &[u8],
    proposal_len: usize,
    commit_seq: u64,
    within_commit_ordinal: u32,
) -> Result<LeafEnvelope, RecordError> {
    match kind {
        KIND_ENTRY => envelope_of_entry(payload, proposal_len, commit_seq, within_commit_ordinal),
        KIND_ATTESTATION => {
            attestation_record(payload, proposal_len, commit_seq, within_commit_ordinal)
        }
        KIND_IMPORT_RECEIPT => {
            import_receipt_record(payload, proposal_len, commit_seq, within_commit_ordinal)
        }
        KIND_CUSTODY_TRANSFER => {
            custody_transfer_record(payload, proposal_len, commit_seq, within_commit_ordinal)
        }
        KIND_SUPPLEMENTAL_EVIDENCE => {
            supplemental_evidence_record(payload, proposal_len, commit_seq, within_commit_ordinal)
        }
        KIND_ACCESS_EVENT => {
            access::record(payload, proposal_len, commit_seq, within_commit_ordinal)
        }
        other => Err(RecordError::Decode(DecodeError {
            offset: 0,
            what: "envelope.kind",
            reason: Reason::BadTag(other),
        })),
    }
}

/// The envelope and the legs of an `fa:entry:v1` payload at a journal
/// position.
fn record_of_entry(
    payload: &[u8],
    proposal_len: usize,
    commit_seq: u64,
    within_commit_ordinal: u32,
) -> Result<(LeafEnvelope, Vec<Leg>), RecordError> {
    let record_digest = entry_record_digest(payload, proposal_len)?;
    let p = proposal_prefix(&payload[..proposal_len]).map_err(RecordError::Decode)?;
    let envelope = LeafEnvelope {
        kind: KIND_ENTRY,
        book_id: p.book_id,
        branch_id: p.branch_id,
        commit_seq,
        within_commit_ordinal,
        record_digest,
        class: p.class,
        effective_day: (!UNDATED_CLASSES.contains(&p.class)).then_some(p.effective_date),
        account_vids: p.account_vids(),
        unit_ids: p.unit_ids(),
    };
    Ok((envelope, p.legs))
}

/// Check that `envelope` is exactly the envelope its record determines, and
/// return the record's legs (empty for non-entry evidence records).
pub fn check_record(
    envelope: &LeafEnvelope,
    payload: &[u8],
    proposal_len: usize,
) -> Result<Vec<Leg>, RecordError> {
    let (rebuilt, legs) = match envelope.kind {
        KIND_ENTRY => record_of_entry(
            payload,
            proposal_len,
            envelope.commit_seq,
            envelope.within_commit_ordinal,
        )?,
        kind => (
            envelope_of_record(
                kind,
                payload,
                proposal_len,
                envelope.commit_seq,
                envelope.within_commit_ordinal,
            )?,
            Vec::new(),
        ),
    };
    if rebuilt != *envelope {
        return Err(RecordError::Envelope);
    }
    Ok(legs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> LeafEnvelope {
        LeafEnvelope {
            kind: KIND_ENTRY,
            book_id: [8; 16],
            branch_id: [0; 16],
            commit_seq: 42,
            within_commit_ordinal: 0,
            record_digest: [3; 32],
            class: 1,
            effective_day: Some(20_527),
            account_vids: vec![5, 9],
            unit_ids: vec![1],
        }
    }

    #[test]
    fn envelope_round_trips_and_refuses_disorder_unknown_kinds_and_trailing_bytes() {
        let e = envelope();
        let bytes = e.encode();
        assert_eq!(LeafEnvelope::decode(&bytes).unwrap(), e);
        // kind 1 + ids 32 + seq 8 + ordinal 4 + digest 32 + class 2 + day 5 + lists 4+32 + 4+4.
        assert_eq!(bytes.len(), 1 + 32 + 8 + 4 + 32 + 2 + 5 + 36 + 8);

        let mut undated = e.clone();
        undated.effective_day = None;
        assert_eq!(LeafEnvelope::decode(&undated.encode()).unwrap(), undated);

        for kind in [
            KIND_ATTESTATION,
            KIND_IMPORT_RECEIPT,
            KIND_CUSTODY_TRANSFER,
            KIND_SUPPLEMENTAL_EVIDENCE,
            KIND_ACCESS_EVENT,
        ] {
            let mut evidence = undated.clone();
            evidence.kind = kind;
            evidence.account_vids.clear();
            evidence.unit_ids.clear();
            assert_eq!(LeafEnvelope::decode(&evidence.encode()).unwrap(), evidence);
        }

        let mut unsorted = e.clone();
        unsorted.account_vids = vec![9, 5];
        assert_eq!(
            LeafEnvelope::decode(&unsorted.encode()).unwrap_err().reason,
            Reason::Unsorted
        );
        let mut duplicate = e.clone();
        duplicate.unit_ids = vec![1, 1];
        assert_eq!(
            LeafEnvelope::decode(&duplicate.encode())
                .unwrap_err()
                .reason,
            Reason::Unsorted
        );
        let mut foreign = bytes.clone();
        foreign[0] = 7;
        assert_eq!(
            LeafEnvelope::decode(&foreign).unwrap_err().reason,
            Reason::BadTag(7)
        );
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(
            LeafEnvelope::decode(&long).unwrap_err().reason,
            Reason::Trailing
        );
        assert_eq!(
            LeafEnvelope::decode(&bytes[..bytes.len() - 1])
                .unwrap_err()
                .reason,
            Reason::Truncated
        );
    }

    #[test]
    fn a_split_that_leaves_no_room_for_the_digests_is_refused() {
        assert_eq!(entry_record_digest(&[0; 63], 0), Err(RecordError::Split));
        assert_eq!(entry_record_digest(&[0; 64], 1), Err(RecordError::Split));
        assert_eq!(
            entry_record_digest(&[0; 64], 0),
            Err(RecordError::Digest {
                which: "proposal_digest"
            })
        );
    }
}
