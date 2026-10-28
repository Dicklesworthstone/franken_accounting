//! Typed PostEntry requests and portable, bounded planning transcripts.
//!
//! This is the first admitted slice of plan §10.4 and Appendix B: one exact
//! sealed PostEntry, including its already supplied approvals. The bytes
//! retain randomized erasable fields, so a second process never has to seal
//! the same plaintext again. The intent digest binds the entire typed
//! request; it is not an unkeyed digest of its private plaintext.
//!
//! A certificate binds the complete certificate-free native staged effect
//! at one committed prefix. The kernel authenticates its issuance and runs
//! the production laws again before committing. These types confer no
//! capability. This version deliberately requires an unchanged basis and
//! fixed approvals; acquiring new approvals after planning needs a future
//! witness/approval contract, not reinterpretation of these bytes.
//!
//! Certificates are retained as immutable FA graph evidence. Their public
//! digest is a graph locator, **not** a substrate ObjectId. The substrate's
//! native application-object store is not exposed by the pinned API, so
//! this slice does not populate Entry.plan_certificate with a fake OID.

#![forbid(unsafe_code)]

use core::fmt;

use fa_model::limits::{MAX_ENTRY_BYTES, MAX_PERIOD_REF_BYTES};
use fa_model::{
    ApprovalRef, DecodeError, EncodeError, Entry, EntryError, EntryOrigin, EntryPayload, Id128,
    Reader, Writer, domain_digest,
};
use fgdb_types::{CommitSeq, VId};

mod replacement_review;

pub use replacement_review::{MAX_REPLACEMENT_REVIEW_BYTES, ReplacementReview};

const INTENT_MAGIC: &[u8; 10] = b"FA-INTENT\0";
const PLAN_MAGIC: &[u8; 13] = b"FA-POST-PLAN\0";
const CERTIFICATE_MAGIC: &[u8; 13] = b"FA-POST-CERT\0";
const SCHEMA_MAJOR: u16 = 1;
const SCHEMA_MINOR: u16 = 0;
const MAX_INTENT_BYTES: usize = MAX_ENTRY_BYTES + 32;
const MAX_CERTIFICATE_BYTES: usize = 1024;

/// Hard preallocation bound: the exact request, its resolved Entry preview,
/// and a small fixed certificate. Each Entry independently keeps its own
/// registered bound. This is a binary bound; hex transports need twice it.
pub const MAX_PLAN_BYTES: usize = 2 * MAX_ENTRY_BYTES + 4096;

/// A malformed or unsupported typed transcript. No storage is consulted by
/// any of the codecs in this crate.
#[derive(Debug)]
pub enum IntentError {
    Decode(DecodeError),
    Encode(EncodeError),
    Entry(EntryError),
    Invalid(&'static str),
    TooLarge { max: usize, actual: usize },
}

impl fmt::Display for IntentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "{e}"),
            Self::Encode(e) => write!(f, "{e}"),
            Self::Entry(e) => write!(f, "{e}"),
            Self::Invalid(what) => write!(f, "invalid post plan: {what}"),
            Self::TooLarge { max, actual } => {
                write!(f, "post plan length {actual} exceeds bound {max}")
            }
        }
    }
}

impl core::error::Error for IntentError {}

impl From<DecodeError> for IntentError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

impl From<EncodeError> for IntentError {
    fn from(value: EncodeError) -> Self {
        Self::Encode(value)
    }
}

impl From<EntryError> for IntentError {
    fn from(value: EntryError) -> Self {
        Self::Entry(value)
    }
}

fn bounded(bytes: &[u8], max: usize) -> Result<(), IntentError> {
    if bytes.len() > max {
        return Err(IntentError::TooLarge {
            max,
            actual: bytes.len(),
        });
    }
    Ok(())
}

fn version(reader: &mut Reader<'_>) -> Result<(), IntentError> {
    if reader.u16("plan.schema_major")? != SCHEMA_MAJOR
        || reader.u16("plan.schema_minor")? != SCHEMA_MINOR
    {
        return Err(IntentError::Invalid("unsupported schema version"));
    }
    Ok(())
}

/// The exact sealed request for the admitted PostEntry verb. The envelope
/// has no caller-supplied plan reference. Keeping it private makes every
/// construction pass the canonical Entry checks and the origin boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostIntent {
    entry: Entry,
}

impl PostIntent {
    pub fn new(proposal: EntryPayload, approvals: Vec<ApprovalRef>) -> Result<Self, IntentError> {
        if !matches!(proposal.origin, EntryOrigin::Intent { .. }) {
            return Err(IntentError::Invalid(
                "PostEntry planning requires an Intent-origin proposal",
            ));
        }
        Ok(Self {
            entry: proposal.seal(approvals, None)?,
        })
    }

    #[must_use]
    pub fn proposal(&self) -> &EntryPayload {
        &self.entry.proposal
    }

    #[must_use]
    pub fn approvals(&self) -> &[ApprovalRef] {
        &self.entry.approvals
    }

    /// Canonical typed intent bytes include the verb, all proposal fields,
    /// the sealed description/memos, and the ordered approval references.
    /// Transport choices such as dry-run or confirmation are not fields.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IntentError> {
        let mut w = Writer::new();
        w.fixed(INTENT_MAGIC)
            .u16(SCHEMA_MAJOR)
            .u16(SCHEMA_MINOR)
            .u8(0) // PostEntry; other verbs require their own admitted codec.
            .bytes(&self.entry.encode()?);
        let bytes = w.finish()?;
        bounded(&bytes, MAX_INTENT_BYTES)?;
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IntentError> {
        bounded(bytes, MAX_INTENT_BYTES)?;
        let mut r = Reader::new(bytes);
        if r.fixed::<10>("intent.magic")? != *INTENT_MAGIC {
            return Err(IntentError::Invalid("wrong intent magic"));
        }
        version(&mut r)?;
        if r.u8("intent.verb")? != 0 {
            return Err(IntentError::Invalid("unsupported intent verb"));
        }
        let entry = Entry::decode(r.bytes(MAX_ENTRY_BYTES, "intent.entry")?)?;
        r.finish()?;
        if entry.plan_certificate.is_some() {
            return Err(IntentError::Invalid(
                "a caller cannot supply a plan certificate in an intent",
            ));
        }
        Self::new(entry.proposal, entry.approvals)
    }

    pub fn digest(&self) -> Result<[u8; 32], IntentError> {
        Ok(domain_digest(
            b"fa:intent:post-entry:v1",
            &[&self.canonical_bytes()?],
        ))
    }
}

/// Kernel-issued evidence for one exact native rehearsal. Authentication is
/// checked by the kernel using a domain-separated book key, never accepted
/// as a replacement for the current caller's capability or approvals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanCertificate {
    pub book_id: Id128,
    pub branch_id: Id128,
    pub principal: VId,
    pub capability_commitment: [u8; 32],
    pub intent_digest: [u8; 32],
    pub proposal_digest: [u8; 32],
    pub effects_digest: [u8; 32],
    pub snapshot_seq: CommitSeq,
    pub security_policy_epoch: u64,
    pub expires_at: Option<CommitSeq>,
    pub period: String,
    pub authentication: [u8; 32],
}

impl PlanCertificate {
    /// The exact authenticated transcript, excluding only the authentication
    /// tag itself. The certificate-free staged digest does not contain this
    /// transcript, its graph locator, or its later retaining edge.
    pub fn authentication_bytes(&self) -> Result<Vec<u8>, IntentError> {
        if self.period.is_empty() || self.period.len() > MAX_PERIOD_REF_BYTES {
            return Err(IntentError::Invalid("certificate period is out of bounds"));
        }
        let mut w = Writer::new();
        w.fixed(CERTIFICATE_MAGIC)
            .u16(SCHEMA_MAJOR)
            .u16(SCHEMA_MINOR)
            .fixed(&self.book_id.0)
            .fixed(&self.branch_id.0)
            .u128(self.principal.0)
            .fixed(&self.capability_commitment)
            .fixed(&self.intent_digest)
            .fixed(&self.proposal_digest)
            .fixed(&self.effects_digest)
            .u64(self.snapshot_seq.0)
            .u64(self.security_policy_epoch)
            .opt(self.expires_at.as_ref(), |w, seq| {
                w.u64(seq.0);
            })
            .str(&self.period);
        Ok(w.finish()?)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IntentError> {
        let mut bytes = self.authentication_bytes()?;
        bytes.extend_from_slice(&self.authentication);
        bounded(&bytes, MAX_CERTIFICATE_BYTES)?;
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IntentError> {
        bounded(bytes, MAX_CERTIFICATE_BYTES)?;
        let mut r = Reader::new(bytes);
        if r.fixed::<13>("certificate.magic")? != *CERTIFICATE_MAGIC {
            return Err(IntentError::Invalid("wrong certificate magic"));
        }
        version(&mut r)?;
        let certificate = Self {
            book_id: Id128(r.fixed("certificate.book_id")?),
            branch_id: Id128(r.fixed("certificate.branch_id")?),
            principal: VId(r.u128("certificate.principal")?),
            capability_commitment: r.fixed("certificate.capability_commitment")?,
            intent_digest: r.fixed("certificate.intent_digest")?,
            proposal_digest: r.fixed("certificate.proposal_digest")?,
            effects_digest: r.fixed("certificate.effects_digest")?,
            snapshot_seq: CommitSeq(r.u64("certificate.snapshot_seq")?),
            security_policy_epoch: r.u64("certificate.security_policy_epoch")?,
            expires_at: r.opt("certificate.expires_at", |r| {
                Ok(CommitSeq(r.u64("certificate.expires_at")?))
            })?,
            period: r
                .str(MAX_PERIOD_REF_BYTES, "certificate.period")?
                .to_string(),
            authentication: r.fixed("certificate.authentication")?,
        };
        r.finish()?;
        certificate.authentication_bytes()?;
        Ok(certificate)
    }

    /// A public digest for the immutable graph record, not a native ObjectId.
    pub fn digest(&self) -> Result<[u8; 32], IntentError> {
        Ok(domain_digest(
            b"fa:post-plan-certificate:v1",
            &[&self.canonical_bytes()?],
        ))
    }
}

/// The request, the exact resolved Entry preview, and the authenticated
/// rehearsal certificate. A balancing request can have different input and
/// resolved legs; both are retained and independently bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostPlan {
    intent: PostIntent,
    prepared: Entry,
    certificate: PlanCertificate,
}

impl PostPlan {
    pub fn new(
        intent: PostIntent,
        prepared: Entry,
        certificate: PlanCertificate,
    ) -> Result<Self, IntentError> {
        let plan = Self {
            intent,
            prepared,
            certificate,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), IntentError> {
        let request = self.intent.proposal();
        let proposal = &self.prepared.proposal;
        let certificate = &self.certificate;
        if self.prepared.plan_certificate.is_some()
            || self.prepared.approvals != self.intent.approvals()
        {
            return Err(IntentError::Invalid("prepared envelope changed"));
        }
        if request.book_id != certificate.book_id
            || proposal.book_id != certificate.book_id
            || request.branch_id != certificate.branch_id
            || proposal.branch_id != certificate.branch_id
            || request.principal_ref != certificate.principal
            || proposal.principal_ref != certificate.principal
            || request.idempotency_key != proposal.idempotency_key
            || request.class != proposal.class
        {
            return Err(IntentError::Invalid(
                "intent and certificate coordinates differ",
            ));
        }
        if self.intent.digest()? != certificate.intent_digest
            || proposal.proposal_digest()? != certificate.proposal_digest
            || self.prepared.proposal_digest != certificate.proposal_digest
        {
            return Err(IntentError::Invalid("intent or proposal digest differs"));
        }
        // Re-encode the full Entry so in-memory callers cannot bypass the
        // model's digest/envelope validation by editing public Entry fields.
        let encoded = self.prepared.encode()?;
        if Entry::decode(&encoded)? != self.prepared {
            return Err(IntentError::Invalid("prepared Entry is not canonical"));
        }
        certificate.authentication_bytes()?;
        Ok(())
    }

    #[must_use]
    pub fn intent(&self) -> &PostIntent {
        &self.intent
    }

    /// The actual resolved proposal judged and staged by the kernel.
    #[must_use]
    pub fn proposal(&self) -> &EntryPayload {
        &self.prepared.proposal
    }

    #[must_use]
    pub fn approvals(&self) -> &[ApprovalRef] {
        self.intent.approvals()
    }

    #[must_use]
    pub fn prepared_entry(&self) -> &Entry {
        &self.prepared
    }

    #[must_use]
    pub fn certificate(&self) -> &PlanCertificate {
        &self.certificate
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IntentError> {
        self.validate()?;
        let mut w = Writer::new();
        w.fixed(PLAN_MAGIC)
            .u16(SCHEMA_MAJOR)
            .u16(SCHEMA_MINOR)
            .bytes(&self.intent.canonical_bytes()?)
            .bytes(&self.prepared.encode()?)
            .bytes(&self.certificate.canonical_bytes()?);
        let bytes = w.finish()?;
        bounded(&bytes, MAX_PLAN_BYTES)?;
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IntentError> {
        bounded(bytes, MAX_PLAN_BYTES)?;
        let mut r = Reader::new(bytes);
        if r.fixed::<13>("plan.magic")? != *PLAN_MAGIC {
            return Err(IntentError::Invalid("wrong plan magic"));
        }
        version(&mut r)?;
        let intent = PostIntent::decode(r.bytes(MAX_INTENT_BYTES, "plan.intent")?)?;
        let prepared = Entry::decode(r.bytes(MAX_ENTRY_BYTES, "plan.prepared")?)?;
        let certificate =
            PlanCertificate::decode(r.bytes(MAX_CERTIFICATE_BYTES, "plan.certificate")?)?;
        r.finish()?;
        Self::new(intent, prepared, certificate)
    }

    pub fn digest(&self) -> Result<[u8; 32], IntentError> {
        Ok(domain_digest(
            b"fa:post-plan:v1",
            &[&self.canonical_bytes()?],
        ))
    }
}

/// One portable atomic correction. Both member transcripts bind the same
/// complete native effect and current authority, and have a joint kernel
/// authentication tag in a separate domain. Neither member authenticates as
/// a standalone PostPlan. Existing single-entry wire formats are unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplacementPlan {
    reversal: PostPlan,
    replacement: PostPlan,
}

impl ReplacementPlan {
    pub const MAGIC: &'static [u8; 16] = b"FA-REPLACE-PLAN\0";

    pub fn new(reversal: PostPlan, replacement: PostPlan) -> Result<Self, IntentError> {
        let plan = Self {
            reversal,
            replacement,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), IntentError> {
        self.reversal.validate()?;
        self.replacement.validate()?;
        let a = self.reversal.certificate();
        let b = self.replacement.certificate();
        if a.book_id != b.book_id
            || a.branch_id != b.branch_id
            || a.principal != b.principal
            || a.capability_commitment != b.capability_commitment
            || a.snapshot_seq != b.snapshot_seq
            || a.security_policy_epoch != b.security_policy_epoch
            || a.expires_at != b.expires_at
            || a.effects_digest != b.effects_digest
            || a.authentication != b.authentication
        {
            return Err(IntentError::Invalid(
                "correction members have different authority, basis, or effects",
            ));
        }
        for (rev, rep) in [
            (
                self.reversal.intent().proposal(),
                self.replacement.intent().proposal(),
            ),
            (self.reversal.proposal(), self.replacement.proposal()),
        ] {
            let shape = match (rev.supersession.as_slice(), rep.supersession.as_slice()) {
                ([a], [b]) => {
                    rev.class == fa_model::EntryClass::REVERSAL
                        && rep.class == fa_model::EntryClass::REPLACEMENT
                        && a.kind == fa_model::SupersessionKind::Reverses
                        && b.kind == fa_model::SupersessionKind::Replaces
                        && a.target == b.target
                }
                _ => false,
            };
            if !shape {
                return Err(IntentError::Invalid(
                    "a correction has one Reversal and one Replacement of the same target",
                ));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn reversal(&self) -> &PostPlan {
        &self.reversal
    }

    #[must_use]
    pub fn replacement(&self) -> &PostPlan {
        &self.replacement
    }

    /// Both ordered member certificates, excluding only their authentication
    /// tags. Each already commits its complete request, prepared proposal,
    /// approvals through the intent digest, period and native effects.
    pub fn authentication_bytes(&self) -> Result<Vec<u8>, IntentError> {
        self.validate()?;
        let mut w = Writer::new();
        w.fixed(b"FA-REPLACE-CERT\0")
            .u16(SCHEMA_MAJOR)
            .u16(SCHEMA_MINOR)
            .bytes(&self.reversal.certificate().authentication_bytes()?)
            .bytes(&self.replacement.certificate().authentication_bytes()?);
        Ok(w.finish()?)
    }

    pub fn certificate_digest(&self) -> Result<[u8; 32], IntentError> {
        Ok(domain_digest(
            b"fa:replacement-plan-certificate:v1",
            &[
                &self.authentication_bytes()?,
                &self.reversal.certificate().authentication,
            ],
        ))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IntentError> {
        self.validate()?;
        let mut w = Writer::new();
        w.fixed(Self::MAGIC)
            .u16(SCHEMA_MAJOR)
            .u16(SCHEMA_MINOR)
            .bytes(&self.reversal.canonical_bytes()?)
            .bytes(&self.replacement.canonical_bytes()?);
        let bytes = w.finish()?;
        bounded(&bytes, MAX_PLAN_BYTES)?;
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IntentError> {
        bounded(bytes, MAX_PLAN_BYTES)?;
        let mut r = Reader::new(bytes);
        if r.fixed::<16>("replacement_plan.magic")? != *Self::MAGIC {
            return Err(IntentError::Invalid("wrong correction plan magic"));
        }
        version(&mut r)?;
        let reversal = PostPlan::decode(r.bytes(MAX_PLAN_BYTES, "replacement_plan.reversal")?)?;
        let replacement =
            PostPlan::decode(r.bytes(MAX_PLAN_BYTES, "replacement_plan.replacement")?)?;
        r.finish()?;
        Self::new(reversal, replacement)
    }

    pub fn digest(&self) -> Result<[u8; 32], IntentError> {
        Ok(domain_digest(
            b"fa:replacement-plan:v1",
            &[&self.canonical_bytes()?],
        ))
    }
}

const BATCH_MAGIC: &[u8; 9] = b"FA-BATCH\0";

/// Hard decode bound for a whole batch transcript. Each member keeps its
/// own registered Entry bound; this caps what one request can allocate.
pub const MAX_BATCH_BYTES: usize = 4 * MAX_ENTRY_BYTES;

/// An ordered list of PostEntry intents committed atomically in one
/// substrate transaction (plan §5.8): all or none, in order, each member
/// seeing every earlier member's staged effects. A member names an earlier
/// member by its identity-derived entry vid (an invoice and its application
/// in one batch). A forward or absent name finds no entry and is refused by
/// the kernel like any other missing target. The batch's own key derives
/// its IntentOutcome identity under the members' common principal
/// (plan §5.9): an identical retry returns the recorded outcome. Retry
/// identity is the key and the members' identities, never these bytes:
/// re-sealing a member's erasable fields draws fresh salts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostBatch {
    idempotency_key: Vec<u8>,
    members: Vec<PostIntent>,
}

impl PostBatch {
    /// Check the batch's own shape: a bounded key, 1..=`max_batch_entries`
    /// members on one book, branch and principal, and distinct member keys
    /// (two members with one key would derive one entry identity).
    pub fn new(idempotency_key: Vec<u8>, members: Vec<PostIntent>) -> Result<Self, IntentError> {
        if idempotency_key.is_empty()
            || idempotency_key.len() > fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES
        {
            return Err(IntentError::Invalid(
                "a batch key is 1..=max_idempotency_key_bytes bytes",
            ));
        }
        let Some(first) = members.first() else {
            return Err(IntentError::Invalid("a batch has at least one member"));
        };
        if members.len() > fa_model::limits::MAX_BATCH_ENTRIES {
            return Err(IntentError::Invalid(
                "a batch has at most max_batch_entries members",
            ));
        }
        let head = first.proposal();
        let mut keys = std::collections::BTreeSet::new();
        for member in &members {
            let p = member.proposal();
            if p.book_id != head.book_id || p.branch_id != head.branch_id {
                return Err(IntentError::Invalid(
                    "every batch member targets the same book and branch",
                ));
            }
            if p.principal_ref != head.principal_ref {
                return Err(IntentError::Invalid(
                    "every batch member names the same principal",
                ));
            }
            if !keys.insert(p.idempotency_key.as_slice()) {
                return Err(IntentError::Invalid(
                    "two batch members share one idempotency key",
                ));
            }
        }
        let batch = Self {
            idempotency_key,
            members,
        };
        batch.canonical_bytes()?;
        Ok(batch)
    }

    #[must_use]
    pub fn idempotency_key(&self) -> &[u8] {
        &self.idempotency_key
    }

    #[must_use]
    pub fn members(&self) -> &[PostIntent] {
        &self.members
    }

    /// The members' common principal.
    #[must_use]
    pub fn principal(&self) -> VId {
        self.members[0].proposal().principal_ref
    }

    /// The members' common book.
    #[must_use]
    pub fn book_id(&self) -> Id128 {
        self.members[0].proposal().book_id
    }

    /// The members' common branch.
    #[must_use]
    pub fn branch_id(&self) -> Id128 {
        self.members[0].proposal().branch_id
    }

    /// The batch key, then each member's canonical intent bytes in order.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IntentError> {
        let mut w = Writer::new();
        w.fixed(BATCH_MAGIC)
            .u16(SCHEMA_MAJOR)
            .u16(SCHEMA_MINOR)
            .bytes(&self.idempotency_key);
        let members = self
            .members
            .iter()
            .map(PostIntent::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        w.list(&members, |w, m| {
            w.bytes(m);
        });
        let bytes = w.finish()?;
        bounded(&bytes, MAX_BATCH_BYTES)?;
        Ok(bytes)
    }

    /// Full ordered request, including every member's sealed proposal and
    /// approval references. Portable plans bind this transcript, not merely
    /// the identities used by the ordinary batch retry namespace.
    pub fn digest(&self) -> Result<[u8; 32], IntentError> {
        Ok(domain_digest(
            b"fa:intent:post-batch:v1",
            &[&self.canonical_bytes()?],
        ))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IntentError> {
        bounded(bytes, MAX_BATCH_BYTES)?;
        let mut r = Reader::new(bytes);
        if r.fixed::<9>("batch.magic")? != *BATCH_MAGIC {
            return Err(IntentError::Invalid("wrong batch magic"));
        }
        version(&mut r)?;
        let key = r
            .bytes(fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES, "batch.key")?
            .to_vec();
        let members = r.list(fa_model::limits::MAX_BATCH_ENTRIES, "batch.members", |r| {
            Ok(r.bytes(MAX_INTENT_BYTES, "batch.member")?.to_vec())
        })?;
        r.finish()?;
        let members = members
            .iter()
            .map(|m| PostIntent::decode(m))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(key, members)
    }
}

/// A bounded batch request plus its resolved entries, period names and one
/// fixed certificate. Both large components retain MAX_BATCH_BYTES bounds.
pub const MAX_BATCH_PLAN_BYTES: usize =
    2 * MAX_BATCH_BYTES + fa_model::limits::MAX_BATCH_ENTRIES * (MAX_PERIOD_REF_BYTES + 8) + 4096;

/// Kernel-authenticated evidence for one complete atomic batch rehearsal.
/// The effect digest is the substrate's whole staged transaction, including
/// the IntentOutcome, before the certificate's own retention is appended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchPlanCertificate {
    pub book_id: Id128,
    pub branch_id: Id128,
    pub principal: VId,
    pub capability_commitment: [u8; 32],
    pub intent_digest: [u8; 32],
    pub prepared_digest: [u8; 32],
    pub effects_digest: [u8; 32],
    pub snapshot_seq: CommitSeq,
    pub security_policy_epoch: u64,
    pub expires_at: Option<CommitSeq>,
    pub authentication: [u8; 32],
}

impl BatchPlanCertificate {
    pub fn authentication_bytes(&self) -> Result<Vec<u8>, IntentError> {
        let mut w = Writer::new();
        w.fixed(b"FA-BATCH-CERT\0")
            .u16(SCHEMA_MAJOR)
            .u16(SCHEMA_MINOR)
            .fixed(&self.book_id.0)
            .fixed(&self.branch_id.0)
            .u128(self.principal.0)
            .fixed(&self.capability_commitment)
            .fixed(&self.intent_digest)
            .fixed(&self.prepared_digest)
            .fixed(&self.effects_digest)
            .u64(self.snapshot_seq.0)
            .u64(self.security_policy_epoch)
            .opt(self.expires_at.as_ref(), |w, seq| {
                w.u64(seq.0);
            });
        Ok(w.finish()?)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IntentError> {
        let mut bytes = self.authentication_bytes()?;
        bytes.extend_from_slice(&self.authentication);
        bounded(&bytes, MAX_CERTIFICATE_BYTES)?;
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IntentError> {
        bounded(bytes, MAX_CERTIFICATE_BYTES)?;
        let mut r = Reader::new(bytes);
        if r.fixed::<14>("batch_certificate.magic")? != *b"FA-BATCH-CERT\0" {
            return Err(IntentError::Invalid("wrong batch certificate magic"));
        }
        version(&mut r)?;
        let certificate = Self {
            book_id: Id128(r.fixed("batch_certificate.book")?),
            branch_id: Id128(r.fixed("batch_certificate.branch")?),
            principal: VId(r.u128("batch_certificate.principal")?),
            capability_commitment: r.fixed("batch_certificate.capability")?,
            intent_digest: r.fixed("batch_certificate.intent")?,
            prepared_digest: r.fixed("batch_certificate.prepared")?,
            effects_digest: r.fixed("batch_certificate.effects")?,
            snapshot_seq: CommitSeq(r.u64("batch_certificate.snapshot")?),
            security_policy_epoch: r.u64("batch_certificate.policy")?,
            expires_at: r.opt("batch_certificate.expires", |r| {
                Ok(CommitSeq(r.u64("batch_certificate.expires")?))
            })?,
            authentication: r.fixed("batch_certificate.authentication")?,
        };
        r.finish()?;
        Ok(certificate)
    }

    pub fn digest(&self) -> Result<[u8; 32], IntentError> {
        Ok(domain_digest(
            b"fa:batch-plan-certificate:v1",
            &[&self.canonical_bytes()?],
        ))
    }
}

/// One portable, ordered, all-or-none batch. Private fields force the
/// request, resolved entries, periods and authenticated digests to agree.
/// Authentication and current authority are enforced by the kernel, never
/// by these pure format types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchPlan {
    batch: PostBatch,
    prepared: Vec<Entry>,
    periods: Vec<String>,
    certificate: BatchPlanCertificate,
}

impl BatchPlan {
    pub const MAGIC: &'static [u8; 14] = b"FA-BATCH-PLAN\0";

    pub fn new(
        batch: PostBatch,
        prepared: Vec<Entry>,
        periods: Vec<String>,
        certificate: BatchPlanCertificate,
    ) -> Result<Self, IntentError> {
        let plan = Self {
            batch,
            prepared,
            periods,
            certificate,
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Digest the exact resolved entries and period decisions in execution
    /// order, including all sealed fields and final approval lists.
    pub fn prepared_digest(entries: &[Entry], periods: &[String]) -> Result<[u8; 32], IntentError> {
        Ok(domain_digest(
            b"fa:batch-prepared:v1",
            &[&Self::prepared_bytes(entries, periods)?],
        ))
    }

    fn prepared_bytes(entries: &[Entry], periods: &[String]) -> Result<Vec<u8>, IntentError> {
        if entries.is_empty()
            || entries.len() > fa_model::limits::MAX_BATCH_ENTRIES
            || entries.len() != periods.len()
            || periods
                .iter()
                .any(|period| period.is_empty() || period.len() > MAX_PERIOD_REF_BYTES)
        {
            return Err(IntentError::Invalid(
                "batch previews or periods are out of bounds",
            ));
        }
        let mut total = 0_usize;
        let encoded = entries
            .iter()
            .map(|entry| {
                let bytes = entry.encode()?;
                total = total
                    .checked_add(bytes.len())
                    .ok_or(IntentError::Invalid("batch preview length overflow"))?;
                if total > MAX_BATCH_BYTES {
                    return Err(IntentError::TooLarge {
                        max: MAX_BATCH_BYTES,
                        actual: total,
                    });
                }
                Ok(bytes)
            })
            .collect::<Result<Vec<_>, IntentError>>()?;
        let mut w = Writer::new();
        w.list(&encoded, |w, bytes| {
            w.bytes(bytes);
        })
        .list(periods, |w, period| {
            w.str(period);
        });
        Ok(w.finish()?)
    }

    pub fn validate(&self) -> Result<(), IntentError> {
        if self.batch.book_id() != self.certificate.book_id
            || self.batch.branch_id() != self.certificate.branch_id
            || self.batch.principal() != self.certificate.principal
            || self.prepared.len() != self.batch.members().len()
        {
            return Err(IntentError::Invalid(
                "batch plan coordinates or member count differ",
            ));
        }
        for (intent, entry) in self.batch.members().iter().zip(&self.prepared) {
            let request = intent.proposal();
            let proposal = &entry.proposal;
            if request.book_id != proposal.book_id
                || request.branch_id != proposal.branch_id
                || request.principal_ref != proposal.principal_ref
                || request.idempotency_key != proposal.idempotency_key
                || request.class != proposal.class
                || entry.approvals != intent.approvals()
                || entry.plan_certificate.is_some()
                || Entry::decode(&entry.encode()?)? != *entry
            {
                return Err(IntentError::Invalid(
                    "batch member preview differs from its request",
                ));
            }
        }
        if self.batch.digest()? != self.certificate.intent_digest
            || Self::prepared_digest(&self.prepared, &self.periods)?
                != self.certificate.prepared_digest
        {
            return Err(IntentError::Invalid(
                "batch request or preview digest differs",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn batch(&self) -> &PostBatch {
        &self.batch
    }

    #[must_use]
    pub fn prepared_entries(&self) -> &[Entry] {
        &self.prepared
    }

    #[must_use]
    pub fn periods(&self) -> &[String] {
        &self.periods
    }

    #[must_use]
    pub fn certificate(&self) -> &BatchPlanCertificate {
        &self.certificate
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IntentError> {
        self.validate()?;
        let mut w = Writer::new();
        w.fixed(Self::MAGIC)
            .u16(SCHEMA_MAJOR)
            .u16(SCHEMA_MINOR)
            .bytes(&self.batch.canonical_bytes()?)
            .bytes(&Self::prepared_bytes(&self.prepared, &self.periods)?)
            .bytes(&self.certificate.canonical_bytes()?);
        let bytes = w.finish()?;
        bounded(&bytes, MAX_BATCH_PLAN_BYTES)?;
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IntentError> {
        bounded(bytes, MAX_BATCH_PLAN_BYTES)?;
        let mut r = Reader::new(bytes);
        if r.fixed::<14>("batch_plan.magic")? != *Self::MAGIC {
            return Err(IntentError::Invalid("wrong batch plan magic"));
        }
        version(&mut r)?;
        let batch = PostBatch::decode(r.bytes(MAX_BATCH_BYTES, "batch_plan.request")?)?;
        let mut preview = Reader::new(r.bytes(MAX_BATCH_PLAN_BYTES, "batch_plan.previews")?);
        let entries = preview.list(
            fa_model::limits::MAX_BATCH_ENTRIES,
            "batch_plan.entries",
            |r| Ok(r.bytes(MAX_ENTRY_BYTES, "batch_plan.entry")?.to_vec()),
        )?;
        let periods = preview.list(
            fa_model::limits::MAX_BATCH_ENTRIES,
            "batch_plan.periods",
            |r| {
                Ok(r.str(MAX_PERIOD_REF_BYTES, "batch_plan.period")?
                    .to_string())
            },
        )?;
        preview.finish()?;
        let entries = entries
            .iter()
            .map(|entry| Entry::decode(entry))
            .collect::<Result<Vec<_>, _>>()?;
        let certificate = BatchPlanCertificate::decode(
            r.bytes(MAX_CERTIFICATE_BYTES, "batch_plan.certificate")?,
        )?;
        r.finish()?;
        Self::new(batch, entries, periods, certificate)
    }

    pub fn certificate_digest(&self) -> Result<[u8; 32], IntentError> {
        self.certificate.digest()
    }

    pub fn digest(&self) -> Result<[u8; 32], IntentError> {
        Ok(domain_digest(
            b"fa:batch-plan:v1",
            &[&self.canonical_bytes()?],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate() -> PlanCertificate {
        PlanCertificate {
            book_id: Id128([1; 16]),
            branch_id: Id128([2; 16]),
            principal: VId(3),
            capability_commitment: [4; 32],
            intent_digest: [5; 32],
            proposal_digest: [6; 32],
            effects_digest: [7; 32],
            snapshot_seq: CommitSeq(8),
            security_policy_epoch: 9,
            expires_at: Some(CommitSeq(10)),
            period: "FY2026-P03".into(),
            authentication: [11; 32],
        }
    }

    #[test]
    fn certificate_wire_fields_have_a_fixed_order_and_explicit_version() {
        // Built without Writer so a writer/reader field-order drift cannot
        // turn a round-trip test into evidence for the changed format.
        let mut expected = b"FA-POST-CERT\0".to_vec();
        expected.extend_from_slice(&[1, 0, 0, 0]);
        expected.extend_from_slice(&[1; 16]);
        expected.extend_from_slice(&[2; 16]);
        expected.extend_from_slice(&3_u128.to_le_bytes());
        for byte in [4, 5, 6, 7] {
            expected.extend_from_slice(&[byte; 32]);
        }
        expected.extend_from_slice(&8_u64.to_le_bytes());
        expected.extend_from_slice(&9_u64.to_le_bytes());
        expected.push(1);
        expected.extend_from_slice(&10_u64.to_le_bytes());
        expected.extend_from_slice(&10_u32.to_le_bytes());
        expected.extend_from_slice(b"FY2026-P03");
        let authenticated = expected.clone();
        expected.extend_from_slice(&[11; 32]);
        assert_eq!(expected.len(), 264);
        let cert = certificate();
        assert_eq!(cert.authentication_bytes().unwrap(), authenticated);
        assert_eq!(cert.canonical_bytes().unwrap(), expected);
        assert_eq!(PlanCertificate::decode(&expected).unwrap(), cert);
        let mut no_expiry = cert;
        no_expiry.expires_at = None;
        let bytes = no_expiry.canonical_bytes().unwrap();
        assert_eq!(bytes.len(), expected.len() - 8);
        assert_eq!(PlanCertificate::decode(&bytes).unwrap(), no_expiry);
    }

    #[test]
    fn certificates_refuse_unknown_versions_truncation_trailing_bytes_and_bad_tags() {
        let bytes = certificate().canonical_bytes().unwrap();
        for end in 0..bytes.len() {
            assert!(
                PlanCertificate::decode(&bytes[..end]).is_err(),
                "prefix {end}"
            );
        }
        for offset in [0, 13, 15, 209] {
            let mut changed = bytes.clone();
            changed[offset] = 255;
            assert!(
                PlanCertificate::decode(&changed).is_err(),
                "offset {offset}"
            );
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(PlanCertificate::decode(&trailing).is_err());
        let mut empty = certificate();
        empty.period.clear();
        assert!(empty.canonical_bytes().is_err());
    }

    #[test]
    fn batch_certificate_wire_order_is_fixed_and_malformed_transcripts_are_refused() {
        let certificate = BatchPlanCertificate {
            book_id: Id128([1; 16]),
            branch_id: Id128([2; 16]),
            principal: VId(3),
            capability_commitment: [4; 32],
            intent_digest: [5; 32],
            prepared_digest: [6; 32],
            effects_digest: [7; 32],
            snapshot_seq: CommitSeq(8),
            security_policy_epoch: 9,
            expires_at: Some(CommitSeq(10)),
            authentication: [11; 32],
        };
        // Independent byte construction pins the durable field order;
        // changing writer and reader together must not bless a new format.
        let mut expected = b"FA-BATCH-CERT\0".to_vec();
        expected.extend_from_slice(&[1, 0, 0, 0]);
        expected.extend_from_slice(&[1; 16]);
        expected.extend_from_slice(&[2; 16]);
        expected.extend_from_slice(&3_u128.to_le_bytes());
        for value in [4, 5, 6, 7] {
            expected.extend_from_slice(&[value; 32]);
        }
        expected.extend_from_slice(&8_u64.to_le_bytes());
        expected.extend_from_slice(&9_u64.to_le_bytes());
        expected.push(1);
        expected.extend_from_slice(&10_u64.to_le_bytes());
        assert_eq!(certificate.authentication_bytes().unwrap(), expected);
        expected.extend_from_slice(&[11; 32]);
        assert_eq!(expected.len(), 251);
        assert_eq!(certificate.canonical_bytes().unwrap(), expected);
        assert_eq!(
            BatchPlanCertificate::decode(&expected).unwrap(),
            certificate
        );
        for end in 0..expected.len() {
            assert!(
                BatchPlanCertificate::decode(&expected[..end]).is_err(),
                "prefix {end}"
            );
        }
        for offset in [0, 14, 16, 210] {
            let mut malformed = expected.clone();
            malformed[offset] = 255;
            assert!(
                BatchPlanCertificate::decode(&malformed).is_err(),
                "offset {offset}"
            );
        }
        let mut trailing = expected;
        trailing.push(0);
        assert!(BatchPlanCertificate::decode(&trailing).is_err());
        let mut unexpiring = certificate;
        unexpiring.expires_at = None;
        let bytes = unexpiring.canonical_bytes().unwrap();
        assert_eq!(bytes.len(), 243);
        assert_eq!(BatchPlanCertificate::decode(&bytes).unwrap(), unexpiring);

        let mut hostile = BatchPlan::MAGIC.to_vec();
        hostile.extend_from_slice(&[1, 0, 0, 0]);
        hostile.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            BatchPlan::decode(&hostile),
            Err(IntentError::Decode(_))
        ));
    }

    #[test]
    fn hostile_lengths_fail_before_they_can_drive_an_allocation() {
        let mut intent = INTENT_MAGIC.to_vec();
        intent.extend_from_slice(&[1, 0, 0, 0, 0]);
        intent.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            PostIntent::decode(&intent),
            Err(IntentError::Decode(_))
        ));
        let mut plan = PLAN_MAGIC.to_vec();
        plan.extend_from_slice(&[1, 0, 0, 0]);
        plan.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            PostPlan::decode(&plan),
            Err(IntentError::Decode(_))
        ));
        let too_large = vec![0; MAX_PLAN_BYTES + 1];
        assert!(matches!(
            PostPlan::decode(&too_large),
            Err(IntentError::TooLarge { .. })
        ));
    }
}
