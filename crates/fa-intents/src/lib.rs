//! Typed posting requests and portable, bounded planning transcripts.
//!
//! This slice of plan §10.4 and Appendix B admits exact sealed PostEntry and
//! rule-derived requests, including supplied approvals and automatic event
//! batches with their own protocol. The bytes
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
mod schema_control_review;

pub use replacement_review::{MAX_REPLACEMENT_REVIEW_BYTES, ReplacementReview};
pub use schema_control_review::{MAX_SCHEMA_CONTROL_REVIEW_BYTES, SchemaControlReview};

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

/// A distinct wire verb and digest domain keep rule derivation from being
/// reinterpreted as the original PostEntry contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PostIntentKind {
    PostEntry,
    RuleDerived,
}

impl PostIntentKind {
    const fn verb(self) -> u8 {
        match self {
            Self::PostEntry => 0,
            Self::RuleDerived => 1,
        }
    }

    const fn digest_domain(self) -> &'static [u8] {
        match self {
            Self::PostEntry => b"fa:intent:post-entry:v1",
            Self::RuleDerived => b"fa:intent:rule-derived:v1",
        }
    }
}

/// The exact sealed request for PostEntry or a single rule derivation. The
/// envelope has no caller-supplied plan reference. Private construction keeps
/// each wire verb bound to its own origin and the canonical Entry checks.
/// Decoding confers no authority or proof that the named rule reproduces the
/// proposal; native planning and commit independently enforce those laws.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostIntent {
    kind: PostIntentKind,
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
            kind: PostIntentKind::PostEntry,
            entry: proposal.seal(approvals, None)?,
        })
    }

    /// Retain an exact rule-derived request for a native PostPlan or a
    /// member of [`PostBatch::automatic_rules`].
    /// The kernel must witness the rule version, activation, event and inputs,
    /// reproduce the derivation, and enforce both caller and rule authority.
    /// This constructor only checks the origin and canonical Entry structure.
    pub fn rule_derived(
        proposal: EntryPayload,
        approvals: Vec<ApprovalRef>,
    ) -> Result<Self, IntentError> {
        if !matches!(proposal.origin, EntryOrigin::Rule { .. }) {
            return Err(IntentError::Invalid(
                "rule-derived planning requires a Rule-origin proposal",
            ));
        }
        Ok(Self {
            kind: PostIntentKind::RuleDerived,
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
            .u8(self.kind.verb())
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
        let kind = match r.u8("intent.verb")? {
            0 => PostIntentKind::PostEntry,
            1 => PostIntentKind::RuleDerived,
            _ => return Err(IntentError::Invalid("unsupported intent verb")),
        };
        let entry = Entry::decode(r.bytes(MAX_ENTRY_BYTES, "intent.entry")?)?;
        r.finish()?;
        if entry.plan_certificate.is_some() {
            return Err(IntentError::Invalid(
                "a caller cannot supply a plan certificate in an intent",
            ));
        }
        match kind {
            PostIntentKind::PostEntry => Self::new(entry.proposal, entry.approvals),
            PostIntentKind::RuleDerived => Self::rule_derived(entry.proposal, entry.approvals),
        }
    }

    pub fn digest(&self) -> Result<[u8; 32], IntentError> {
        Ok(domain_digest(
            self.kind.digest_domain(),
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
        if self.reversal.intent().kind != PostIntentKind::PostEntry
            || self.replacement.intent().kind != PostIntentKind::PostEntry
        {
            return Err(IntentError::Invalid(
                "rule-derived intents require a single-entry PostPlan",
            ));
        }
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
const RULE_BATCH_MAGIC: &[u8; 14] = b"FA-RULE-BATCH\0";

/// Hard decode bound for a whole batch transcript. Each member keeps its
/// own registered Entry bound; this caps what one request can allocate.
pub const MAX_BATCH_BYTES: usize = 4 * MAX_ENTRY_BYTES;

/// Automatic event derivation is a separate protocol from an explicit
/// PostEntry batch. Its event and entire ordered membership are retained in
/// the request, so native admission can require the complete active rule set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BatchKind {
    PostEntry,
    AutomaticRules { event_ref: VId },
}

impl BatchKind {
    const fn magic(self) -> &'static [u8] {
        match self {
            Self::PostEntry => BATCH_MAGIC,
            Self::AutomaticRules { .. } => RULE_BATCH_MAGIC,
        }
    }

    const fn digest_domain(self) -> &'static [u8] {
        match self {
            Self::PostEntry => b"fa:intent:post-batch:v1",
            Self::AutomaticRules { .. } => b"fa:intent:rule-batch:v1",
        }
    }
}

/// An ordered list of posting intents committed atomically in one substrate
/// transaction (plan §5.8): all or none, in order, each member seeing every
/// earlier member's staged effects. The ordinary profile admits PostEntry
/// intents; automatic event derivation has its own checked constructor,
/// framing and digest domain.
///
/// An ordinary member names an earlier member by its identity-derived entry
/// vid (an invoice and its application in one batch). A forward or absent
/// name finds no entry and is refused by the kernel like any other missing
/// target. The batch's own key derives its IntentOutcome identity under the
/// members' common principal (plan §5.9): an identical retry returns the
/// recorded outcome. Retry identity is the key and the members' identities,
/// never these bytes: re-sealing a member's erasable fields draws fresh salts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostBatch {
    kind: BatchKind,
    idempotency_key: Vec<u8>,
    members: Vec<PostIntent>,
}

impl PostBatch {
    /// Check an ordinary PostEntry batch: a bounded key,
    /// 1..=max_batch_entries Intent-origin members on one book, branch and
    /// principal, and distinct member keys. This constructor and its durable
    /// encoding retain the original PostEntry-only protocol.
    pub fn new(idempotency_key: Vec<u8>, members: Vec<PostIntent>) -> Result<Self, IntentError> {
        Self::checked(BatchKind::PostEntry, idempotency_key, members)
    }

    /// Retain the complete automatic derivation of one recorded event.
    /// Members must be distinct Rule-origin Original or Adjusting requests
    /// for that event, on one book's trunk and under one principal.
    ///
    /// The native kernel independently selects every matching active rule
    /// in name order, refuses rules requiring explicit inputs, and checks
    /// exact membership, reproduction, caller authority and RuleAuthority.
    /// These bytes assert a selection; constructing or decoding them does
    /// not authenticate its completeness or authorize publication.
    pub fn automatic_rules(
        event_ref: VId,
        idempotency_key: Vec<u8>,
        members: Vec<PostIntent>,
    ) -> Result<Self, IntentError> {
        Self::checked(
            BatchKind::AutomaticRules { event_ref },
            idempotency_key,
            members,
        )
    }

    fn checked(
        kind: BatchKind,
        idempotency_key: Vec<u8>,
        members: Vec<PostIntent>,
    ) -> Result<Self, IntentError> {
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
        let mut versions = std::collections::BTreeSet::new();
        for member in &members {
            let p = member.proposal();
            match kind {
                BatchKind::PostEntry => {
                    if member.kind != PostIntentKind::PostEntry {
                        return Err(IntentError::Invalid(
                            "PostEntry batches require Intent-origin members",
                        ));
                    }
                }
                BatchKind::AutomaticRules { event_ref } => {
                    if member.kind != PostIntentKind::RuleDerived {
                        return Err(IntentError::Invalid(
                            "automatic rule batches require Rule-origin members",
                        ));
                    }
                    let EntryOrigin::Rule {
                        rule_version_oid,
                        event_ref: member_event,
                        ..
                    } = &p.origin
                    else {
                        return Err(IntentError::Invalid(
                            "automatic rule batches require Rule-origin members",
                        ));
                    };
                    if *member_event != event_ref {
                        return Err(IntentError::Invalid(
                            "every automatic rule batch member derives from the named event",
                        ));
                    }
                    if p.branch_id != Id128::TRUNK {
                        return Err(IntentError::Invalid(
                            "automatic rule batches target the trunk",
                        ));
                    }
                    if !matches!(
                        p.class,
                        fa_model::EntryClass::ORIGINAL | fa_model::EntryClass::ADJUSTING
                    ) {
                        return Err(IntentError::Invalid(
                            "automatic rule batches admit only Original or Adjusting members",
                        ));
                    }
                    if !versions.insert(rule_version_oid.0) {
                        return Err(IntentError::Invalid(
                            "two automatic rule batch members share one rule version",
                        ));
                    }
                }
            }
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
            kind,
            idempotency_key,
            members,
        };
        batch.canonical_bytes()?;
        Ok(batch)
    }

    /// The event whose complete active rule selection this request asserts,
    /// or None for an ordinary explicit PostEntry batch.
    #[must_use]
    pub fn automatic_event(&self) -> Option<VId> {
        match self.kind {
            BatchKind::PostEntry => None,
            BatchKind::AutomaticRules { event_ref } => Some(event_ref),
        }
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

    /// Profile-specific magic and version, the automatic event when present,
    /// then the batch key and each member's canonical intent bytes in order.
    /// Ordinary PostEntry bytes retain their original layout exactly.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IntentError> {
        let mut w = Writer::new();
        w.fixed(self.kind.magic())
            .u16(SCHEMA_MAJOR)
            .u16(SCHEMA_MINOR);
        if let Some(event) = self.automatic_event() {
            w.u128(event.0);
        }
        w.bytes(&self.idempotency_key);
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

    /// Full ordered request, including its profile, automatic event, every
    /// sealed proposal and approval reference. Portable plans bind this
    /// transcript, not merely the ordinary batch retry identities.
    pub fn digest(&self) -> Result<[u8; 32], IntentError> {
        Ok(domain_digest(
            self.kind.digest_domain(),
            &[&self.canonical_bytes()?],
        ))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IntentError> {
        bounded(bytes, MAX_BATCH_BYTES)?;
        let mut r = Reader::new(bytes);
        let kind = if bytes.starts_with(RULE_BATCH_MAGIC) {
            r.fixed::<14>("batch.magic")?;
            version(&mut r)?;
            BatchKind::AutomaticRules {
                event_ref: VId(r.u128("batch.event")?),
            }
        } else {
            if r.fixed::<9>("batch.magic")? != *BATCH_MAGIC {
                return Err(IntentError::Invalid("wrong batch magic"));
            }
            version(&mut r)?;
            BatchKind::PostEntry
        };
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
        Self::checked(kind, key, members)
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

    // A fixed canonical minor-0 Entry: balanced native legs, deterministic
    // sealed description, Intent origin and no approvals. Keeping the model
    // fixture as bytes avoids extra dependencies just to construct dates and
    // amounts, and pins the legacy wrapper independently of its encoder.
    const LEGACY_ENTRY_HEX: &str = concat!(
        "0100000009090909090909090909090909090909000000000000000000000000",
        "000000000100204e000000b633e6b3da10a53ce11f85afbc878cc37840a26e69",
        "062343bf3abc912b456a40000202020202020202020202020202020202020202",
        "0202020248000000dbb001fd899c36864736648030b516f247b41a0b0b429124",
        "ba907e6ddd3c7bd292622ecb110fb7b0f2700e352d87dbe348c0fb7b91ad127b",
        "0861e11418830c59c06f90e56976f18700020000000001000000000000000000",
        "00000000000001000000c0d40100000000000000000000000000000000000000",
        "00000000010200000000000000000000000000000001000000c0d40100000000",
        "00000000000000000000000000000000000000000100000001000000c0d40100",
        "000000000000000000000000c0d40100000000000000000000000000000d0000",
        "00706f727461626c652d72756c65000101010101010101010101010101010101",
        "01010101010101010101010101010101004d0000000000000000000000000000",
        "00000000000000000000000000000000000000000000000092e3d13084318e4b",
        "54891c43173e73924a534f5d4db232bca597ed563e8e1608b3592ac165e256a6",
        "6e5042947d1addd6599bfca3a970a557affe4fdf47fdb102",
    );
    const LEGACY_INTENT_DIGEST: &str =
        "24ea604d3cf5c81b1d9d6d2d8513c06205862e754d4a3f142e490b0cb1334754";
    const LEGACY_BATCH_DIGEST: &str =
        "ac9ceaa1011b6d49f71ebe68918a4d1f4ca39fa99f71f44d4ba54e24ff8dcef5";

    fn legacy_entry() -> Entry {
        let bytes = LEGACY_ENTRY_HEX
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        Entry::decode(&bytes).unwrap()
    }

    fn rule_proposal() -> EntryPayload {
        let mut proposal = legacy_entry().proposal;
        let inputs = vec![0; 4];
        proposal.schema_minor = fa_model::entry::EXTENSIONS_MINOR;
        proposal.origin = EntryOrigin::Rule {
            rule_version_oid: fa_model::Oid([12; 32]),
            event_ref: VId(13),
            inputs_digest: domain_digest(b"fa:canon-inputs:v1", &[&inputs]),
        };
        proposal.idempotency_key = b"rule-plan".to_vec();
        proposal.extensions = vec![(fa_model::entry::RULE_INPUTS_EXTENSION, inputs)];
        proposal
    }

    /// Construct the wrapper without PostIntent's writer or private kind.
    fn intent_wire(verb: u8, entry: &Entry) -> Vec<u8> {
        let entry = entry.encode().unwrap();
        let mut bytes = b"FA-INTENT\0".to_vec();
        bytes.extend_from_slice(&[1, 0, 0, 0, verb]);
        bytes.extend_from_slice(&u32::try_from(entry.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(&entry);
        bytes
    }

    /// Pure codec fixture, not a kernel-issued or authenticated certificate.
    fn plan_for(intent: PostIntent) -> PostPlan {
        let mut certificate = certificate();
        certificate.book_id = intent.proposal().book_id;
        certificate.branch_id = intent.proposal().branch_id;
        certificate.principal = intent.proposal().principal_ref;
        certificate.intent_digest = intent.digest().unwrap();
        certificate.proposal_digest = intent.entry.proposal_digest;
        PostPlan::new(intent.clone(), intent.entry, certificate).unwrap()
    }

    fn correction_plan(rule_derived: bool, replacement: bool) -> PostPlan {
        let mut proposal = if rule_derived {
            rule_proposal()
        } else {
            legacy_entry().proposal
        };
        proposal.class = if replacement {
            fa_model::EntryClass::REPLACEMENT
        } else {
            fa_model::EntryClass::REVERSAL
        };
        proposal.idempotency_key = if replacement {
            b"replacement".to_vec()
        } else {
            b"reversal".to_vec()
        };
        proposal.supersession = vec![fa_model::Supersession {
            target: fa_model::EntryRef {
                vid: VId(90),
                entry_digest: [91; 32],
            },
            kind: if replacement {
                fa_model::SupersessionKind::Replaces
            } else {
                fa_model::SupersessionKind::Reverses
            },
            reason_code: 1,
        }];
        let intent = if rule_derived {
            PostIntent::rule_derived(proposal, Vec::new())
        } else {
            PostIntent::new(proposal, Vec::new())
        };
        plan_for(intent.unwrap())
    }

    fn automatic_member(version: u8, key: &[u8]) -> PostIntent {
        let mut proposal = rule_proposal();
        let EntryOrigin::Rule {
            rule_version_oid, ..
        } = &mut proposal.origin
        else {
            panic!("the rule fixture must retain Rule origin");
        };
        *rule_version_oid = fa_model::Oid([version; 32]);
        proposal.idempotency_key = key.to_vec();
        PostIntent::rule_derived(proposal, Vec::new()).unwrap()
    }

    // Independent framing for both batch profiles. Deliberately accepts
    // hostile members so decode must enforce the constructor's contract.
    fn batch_wire(event: Option<VId>, key: &[u8], members: &[PostIntent]) -> Vec<u8> {
        let mut bytes = match event {
            Some(_) => b"FA-RULE-BATCH\0".to_vec(),
            None => b"FA-BATCH\0".to_vec(),
        };
        bytes.extend_from_slice(&[1, 0, 0, 0]);
        if let Some(event) = event {
            bytes.extend_from_slice(&event.0.to_le_bytes());
        }
        bytes.extend_from_slice(&u32::try_from(key.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(key);
        bytes.extend_from_slice(&u32::try_from(members.len()).unwrap().to_le_bytes());
        for member in members {
            let member = member.canonical_bytes().unwrap();
            bytes.extend_from_slice(&u32::try_from(member.len()).unwrap().to_le_bytes());
            bytes.extend_from_slice(&member);
        }
        bytes
    }

    fn automatic_refusal(event: VId, key: &[u8], members: Vec<PostIntent>, expected: &str) {
        let encoded = batch_wire(Some(event), key, &members);
        for result in [
            PostBatch::automatic_rules(event, key.to_vec(), members),
            PostBatch::decode(&encoded),
        ] {
            assert!(
                matches!(result, Err(IntentError::Invalid(actual)) if actual == expected),
                "constructor and decoder must enforce {expected}"
            );
        }
    }

    fn automatic_batch() -> PostBatch {
        PostBatch::automatic_rules(
            VId(13),
            b"automatic".to_vec(),
            vec![
                automatic_member(12, b"rule-a"),
                automatic_member(14, b"rule-b"),
            ],
        )
        .unwrap()
    }

    // A structural fixture, never evidence that a kernel authenticated this plan.
    fn batch_plan_for(batch: PostBatch) -> BatchPlan {
        let prepared = batch
            .members()
            .iter()
            .map(|member| member.entry.clone())
            .collect::<Vec<_>>();
        let periods = vec!["FY2026-P03".to_string(); prepared.len()];
        let certificate = BatchPlanCertificate {
            book_id: batch.book_id(),
            branch_id: batch.branch_id(),
            principal: batch.principal(),
            capability_commitment: [4; 32],
            intent_digest: batch.digest().unwrap(),
            prepared_digest: BatchPlan::prepared_digest(&prepared, &periods).unwrap(),
            effects_digest: [7; 32],
            snapshot_seq: CommitSeq(8),
            security_policy_epoch: 9,
            expires_at: Some(CommitSeq(10)),
            authentication: [11; 32],
        };
        BatchPlan::new(batch, prepared, periods, certificate).unwrap()
    }

    #[test]
    fn legacy_post_entry_keeps_its_exact_wire_and_digest() {
        let entry = legacy_entry();
        let intent = PostIntent::new(entry.proposal.clone(), entry.approvals.clone()).unwrap();
        let expected = intent_wire(0, &entry);
        assert_eq!(intent.canonical_bytes().unwrap(), expected);
        assert_eq!(PostIntent::decode(&expected).unwrap(), intent);
        let digest = intent.digest().unwrap();
        let hex = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(hex, LEGACY_INTENT_DIGEST);
        assert_eq!(
            digest,
            domain_digest(b"fa:intent:post-entry:v1", &[&expected])
        );
    }

    #[test]
    fn rule_derived_intent_has_its_own_verb_domain_and_exact_approval_bytes() {
        let proposal = rule_proposal();
        let approvals = vec![ApprovalRef {
            approval_vid: VId(44),
            approved_digest: proposal.proposal_digest().unwrap(),
        }];
        let expected_entry = proposal.clone().seal(approvals.clone(), None).unwrap();
        let intent = PostIntent::rule_derived(proposal, approvals.clone()).unwrap();
        let expected = intent_wire(1, &expected_entry);
        assert_eq!(intent.canonical_bytes().unwrap(), expected);
        assert_eq!(PostIntent::decode(&expected).unwrap(), intent);
        assert_eq!(intent.approvals(), approvals.as_slice());
        assert_eq!(
            intent.digest().unwrap(),
            domain_digest(b"fa:intent:rule-derived:v1", &[&expected])
        );
        assert_ne!(
            intent.digest().unwrap(),
            domain_digest(b"fa:intent:post-entry:v1", &[&expected])
        );
        let unapproved = PostIntent::rule_derived(intent.proposal().clone(), Vec::new()).unwrap();
        assert_ne!(intent.digest().unwrap(), unapproved.digest().unwrap());
    }

    #[test]
    fn intent_verbs_cannot_be_swapped_or_carry_an_existing_plan_certificate() {
        let legacy = legacy_entry();
        let rule = rule_proposal().seal(Vec::new(), None).unwrap();
        assert!(PostIntent::new(rule.proposal.clone(), Vec::new()).is_err());
        assert!(PostIntent::rule_derived(legacy.proposal.clone(), Vec::new()).is_err());
        assert!(matches!(
            PostIntent::decode(&intent_wire(0, &rule)),
            Err(IntentError::Invalid(
                "PostEntry planning requires an Intent-origin proposal"
            ))
        ));
        assert!(matches!(
            PostIntent::decode(&intent_wire(1, &legacy)),
            Err(IntentError::Invalid(
                "rule-derived planning requires a Rule-origin proposal"
            ))
        ));
        for (verb, entry) in [(0, legacy), (1, rule)] {
            for unknown in [2, u8::MAX] {
                assert!(matches!(
                    PostIntent::decode(&intent_wire(unknown, &entry)),
                    Err(IntentError::Invalid("unsupported intent verb"))
                ));
            }
            let certified = entry
                .proposal
                .seal(entry.approvals, Some(fa_model::Oid([9; 32])))
                .unwrap();
            assert!(matches!(
                PostIntent::decode(&intent_wire(verb, &certified)),
                Err(IntentError::Invalid(
                    "a caller cannot supply a plan certificate in an intent"
                ))
            ));
        }
    }

    #[test]
    fn rule_intent_and_single_entry_plan_reject_malformed_transcripts() {
        let intent = PostIntent::rule_derived(rule_proposal(), Vec::new()).unwrap();
        let bytes = intent.canonical_bytes().unwrap();
        for end in 0..bytes.len() {
            assert!(PostIntent::decode(&bytes[..end]).is_err(), "prefix {end}");
        }
        // Magic, major, minor, verb, embedded Entry digest.
        for offset in [0, 10, 12, 14, bytes.len() - 1] {
            let mut changed = bytes.clone();
            changed[offset] ^= 0xff;
            assert!(PostIntent::decode(&changed).is_err(), "offset {offset}");
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(PostIntent::decode(&trailing).is_err());
        let mut hostile = b"FA-INTENT\0".to_vec();
        hostile.extend_from_slice(&[1, 0, 0, 0, 1]);
        hostile.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            PostIntent::decode(&hostile),
            Err(IntentError::Decode(_))
        ));

        let plan = plan_for(intent);
        let bytes = plan.canonical_bytes().unwrap();
        assert_eq!(PostPlan::decode(&bytes).unwrap(), plan);
        let mut wrong_domain = plan.certificate().clone();
        wrong_domain.intent_digest = domain_digest(
            b"fa:intent:post-entry:v1",
            &[&plan.intent().canonical_bytes().unwrap()],
        );
        assert!(matches!(
            PostPlan::new(
                plan.intent().clone(),
                plan.prepared_entry().clone(),
                wrong_domain
            ),
            Err(IntentError::Invalid("intent or proposal digest differs"))
        ));
        let mut changed = bytes;
        // Cross-kind substitution inside a valid plan must fail in its intent decoder.
        changed[PLAN_MAGIC.len() + 4 + 4 + INTENT_MAGIC.len() + 4] = 0;
        assert!(PostPlan::decode(&changed).is_err());
    }

    #[test]
    fn batches_keep_post_entry_compatibility_and_refuse_rule_members() {
        let entry = legacy_entry();
        let ordinary = PostIntent::new(entry.proposal, entry.approvals).unwrap();
        let batch = PostBatch::new(b"batch".to_vec(), vec![ordinary.clone()]).unwrap();
        // Literal v1.0 framing around the independently frozen Entry fixture.
        let mut legacy = b"FA-BATCH\0".to_vec();
        legacy.extend_from_slice(&[1, 0, 0, 0]);
        legacy.extend_from_slice(&5_u32.to_le_bytes());
        legacy.extend_from_slice(b"batch");
        legacy.extend_from_slice(&1_u32.to_le_bytes());
        legacy.extend_from_slice(&491_u32.to_le_bytes());
        legacy.extend_from_slice(&intent_wire(0, &legacy_entry()));
        assert_eq!(legacy.len(), 521);
        assert_eq!(batch.canonical_bytes().unwrap(), legacy);
        assert_eq!(PostBatch::decode(&legacy).unwrap(), batch);
        assert_eq!(batch.automatic_event(), None);
        let digest = batch.digest().unwrap();
        assert_eq!(
            digest,
            domain_digest(b"fa:intent:post-batch:v1", &[&legacy])
        );
        let hex = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(hex, LEGACY_BATCH_DIGEST);

        let rule = PostIntent::rule_derived(rule_proposal(), Vec::new()).unwrap();
        for members in [
            vec![rule.clone()],
            vec![ordinary.clone(), rule.clone()],
            vec![rule.clone(), ordinary],
        ] {
            assert!(matches!(
                PostBatch::new(b"batch".to_vec(), members),
                Err(IntentError::Invalid(
                    "PostEntry batches require Intent-origin members"
                ))
            ));
        }
        let mut embedded = Writer::new();
        embedded
            .fixed(BATCH_MAGIC)
            .u16(1)
            .u16(0)
            .bytes(b"batch")
            .u32(1)
            .bytes(&rule.canonical_bytes().unwrap());
        assert!(matches!(
            PostBatch::decode(&embedded.finish().unwrap()),
            Err(IntentError::Invalid(
                "PostEntry batches require Intent-origin members"
            ))
        ));
    }

    #[test]
    fn automatic_rule_batches_bind_distinct_framing_event_order_and_approvals() {
        let first = automatic_member(12, b"rule-a");
        let mut proposal = automatic_member(14, b"rule-b").proposal().clone();
        proposal.class = fa_model::EntryClass::ADJUSTING;
        let approvals = vec![ApprovalRef {
            approval_vid: VId(44),
            approved_digest: proposal.proposal_digest().unwrap(),
        }];
        let second = PostIntent::rule_derived(proposal, approvals.clone()).unwrap();
        let members = vec![first.clone(), second.clone()];
        let expected = batch_wire(Some(VId(13)), b"automatic", &members);
        let batch = PostBatch::automatic_rules(VId(13), b"automatic".to_vec(), members).unwrap();
        assert_eq!(batch.automatic_event(), Some(VId(13)));
        assert_eq!(batch.branch_id(), Id128::TRUNK);
        assert_eq!(batch.members()[1].approvals(), approvals.as_slice());
        assert_eq!(batch.canonical_bytes().unwrap(), expected);
        assert_eq!(PostBatch::decode(&expected).unwrap(), batch);
        assert_eq!(
            batch.digest().unwrap(),
            domain_digest(b"fa:intent:rule-batch:v1", &[&expected])
        );
        assert_ne!(
            batch.digest().unwrap(),
            domain_digest(b"fa:intent:post-batch:v1", &[&expected])
        );

        // The codec preserves explicit execution order. Only native selection
        // knows rule names and can decide whether that order is complete.
        let reversed = PostBatch::automatic_rules(
            VId(13),
            b"automatic".to_vec(),
            vec![second.clone(), first.clone()],
        )
        .unwrap();
        assert_ne!(batch.digest().unwrap(), reversed.digest().unwrap());
        let unapproved = PostBatch::automatic_rules(
            VId(13),
            b"automatic".to_vec(),
            vec![
                first,
                PostIntent::rule_derived(second.proposal().clone(), Vec::new()).unwrap(),
            ],
        )
        .unwrap();
        assert_ne!(batch.digest().unwrap(), unapproved.digest().unwrap());
    }

    #[test]
    fn automatic_rule_batches_refuse_cross_profile_and_unrelated_members() {
        let entry = legacy_entry();
        let ordinary = PostIntent::new(entry.proposal, entry.approvals).unwrap();
        let first = automatic_member(12, b"rule-a");
        for members in [
            vec![ordinary.clone()],
            vec![ordinary.clone(), first.clone()],
            vec![first.clone(), ordinary],
        ] {
            automatic_refusal(
                VId(13),
                b"automatic",
                members,
                "automatic rule batches require Rule-origin members",
            );
        }
        for replacement in [false, true] {
            automatic_refusal(
                VId(13),
                b"automatic",
                vec![correction_plan(true, replacement).intent().clone()],
                "automatic rule batches admit only Original or Adjusting members",
            );
        }

        let other = automatic_member(14, b"rule-b");
        let mut proposal = other.proposal().clone();
        let EntryOrigin::Rule { event_ref, .. } = &mut proposal.origin else {
            panic!("the rule fixture must retain Rule origin");
        };
        *event_ref = VId(99);
        automatic_refusal(
            VId(13),
            b"automatic",
            vec![PostIntent::rule_derived(proposal, Vec::new()).unwrap()],
            "every automatic rule batch member derives from the named event",
        );
        let mut proposal = other.proposal().clone();
        proposal.branch_id = Id128([18; 16]);
        automatic_refusal(
            VId(13),
            b"automatic",
            vec![PostIntent::rule_derived(proposal, Vec::new()).unwrap()],
            "automatic rule batches target the trunk",
        );
        let mut proposal = other.proposal().clone();
        proposal.book_id = Id128([19; 16]);
        automatic_refusal(
            VId(13),
            b"automatic",
            vec![
                first.clone(),
                PostIntent::rule_derived(proposal, Vec::new()).unwrap(),
            ],
            "every batch member targets the same book and branch",
        );
        let mut proposal = other.proposal().clone();
        proposal.principal_ref = VId(78);
        automatic_refusal(
            VId(13),
            b"automatic",
            vec![
                first,
                PostIntent::rule_derived(proposal, Vec::new()).unwrap(),
            ],
            "every batch member names the same principal",
        );

        // The trunk restriction belongs only to the automatic profile.
        let mut proposal = legacy_entry().proposal;
        proposal.branch_id = Id128([18; 16]);
        let ordinary = PostBatch::new(
            b"draft".to_vec(),
            vec![PostIntent::new(proposal, Vec::new()).unwrap()],
        )
        .unwrap();
        assert_eq!(ordinary.automatic_event(), None);
        assert_eq!(
            PostBatch::decode(&ordinary.canonical_bytes().unwrap()).unwrap(),
            ordinary
        );
    }

    #[test]
    fn automatic_rule_batches_refuse_duplicate_versions_and_keys() {
        automatic_refusal(
            VId(13),
            b"automatic",
            vec![
                automatic_member(12, b"rule-a"),
                automatic_member(12, b"rule-b"),
            ],
            "two automatic rule batch members share one rule version",
        );
        automatic_refusal(
            VId(13),
            b"automatic",
            vec![
                automatic_member(12, b"rule-a"),
                automatic_member(14, b"rule-a"),
            ],
            "two batch members share one idempotency key",
        );
    }

    #[test]
    fn automatic_rule_batch_requests_enforce_key_and_membership_bounds() {
        automatic_refusal(
            VId(13),
            b"automatic",
            Vec::new(),
            "a batch has at least one member",
        );
        for key in [
            Vec::new(),
            vec![b'x'; fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES + 1],
        ] {
            assert!(matches!(
                PostBatch::automatic_rules(
                    VId(13),
                    key.clone(),
                    vec![automatic_member(12, b"rule-a")]
                ),
                Err(IntentError::Invalid(
                    "a batch key is 1..=max_idempotency_key_bytes bytes"
                ))
            ));
            assert!(
                PostBatch::decode(&batch_wire(
                    Some(VId(13)),
                    &key,
                    &[automatic_member(12, b"rule-a")],
                ))
                .is_err()
            );
        }
        let maximum_key = vec![b'x'; fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES];
        let batch =
            PostBatch::automatic_rules(VId(13), maximum_key, vec![automatic_member(12, b"rule-a")])
                .unwrap();
        assert_eq!(
            PostBatch::decode(&batch.canonical_bytes().unwrap()).unwrap(),
            batch
        );
    }

    #[test]
    fn automatic_rule_batch_decoder_refuses_malformed_transcripts() {
        let bytes = automatic_batch().canonical_bytes().unwrap();
        for end in 0..bytes.len() {
            assert!(PostBatch::decode(&bytes[..end]).is_err(), "prefix {end}");
        }
        // Independent offsets: magic, major, minor, event and final Entry digest.
        for offset in [0, 14, 16, 18, bytes.len() - 1] {
            let mut changed = bytes.clone();
            changed[offset] ^= 0xff;
            assert!(PostBatch::decode(&changed).is_err(), "offset {offset}");
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(PostBatch::decode(&trailing).is_err());

        let mut prefix = b"FA-RULE-BATCH\0".to_vec();
        prefix.extend_from_slice(&[1, 0, 0, 0]);
        prefix.extend_from_slice(&13_u128.to_le_bytes());
        let mut key_length = prefix.clone();
        key_length.extend_from_slice(&u32::MAX.to_le_bytes());
        prefix.extend_from_slice(&1_u32.to_le_bytes());
        prefix.push(b'k');
        let mut member_count = prefix.clone();
        member_count.extend_from_slice(&u32::MAX.to_le_bytes());
        let mut member_length = prefix;
        member_length.extend_from_slice(&1_u32.to_le_bytes());
        member_length.extend_from_slice(&u32::MAX.to_le_bytes());
        for hostile in [key_length, member_count, member_length] {
            assert!(matches!(
                PostBatch::decode(&hostile),
                Err(IntentError::Decode(_))
            ));
        }
    }

    #[test]
    fn automatic_rule_batch_plans_retain_profile_and_reject_request_substitution() {
        let plan = batch_plan_for(automatic_batch());
        let bytes = plan.canonical_bytes().unwrap();
        assert_eq!(BatchPlan::decode(&bytes).unwrap(), plan);
        assert_eq!(plan.batch().automatic_event(), Some(VId(13)));

        let mut wrong_domain = plan.certificate().clone();
        wrong_domain.intent_digest = domain_digest(
            b"fa:intent:post-batch:v1",
            &[&plan.batch().canonical_bytes().unwrap()],
        );
        assert!(matches!(
            BatchPlan::new(
                plan.batch().clone(),
                plan.prepared_entries().to_vec(),
                plan.periods().to_vec(),
                wrong_domain,
            ),
            Err(IntentError::Invalid(
                "batch request or preview digest differs"
            ))
        ));
        let mut reversed = plan.batch().members().to_vec();
        reversed.reverse();
        let mut entries = plan.prepared_entries().to_vec();
        entries.reverse();
        let changed = PostBatch::automatic_rules(VId(13), b"automatic".to_vec(), reversed).unwrap();
        assert!(matches!(
            BatchPlan::new(
                changed,
                entries,
                plan.periods().to_vec(),
                plan.certificate().clone(),
            ),
            Err(IntentError::Invalid(
                "batch request or preview digest differs"
            ))
        ));
        let omitted = PostBatch::automatic_rules(
            VId(13),
            b"automatic".to_vec(),
            vec![plan.batch().members()[0].clone()],
        )
        .unwrap();
        assert!(matches!(
            BatchPlan::new(
                omitted,
                vec![plan.prepared_entries()[0].clone()],
                vec![plan.periods()[0].clone()],
                plan.certificate().clone(),
            ),
            Err(IntentError::Invalid(
                "batch request or preview digest differs"
            ))
        ));
        let mut changed = bytes;
        // Plan header 14 + version 4 + request length 4; batch header 14 +
        // version 4 precede the explicitly bound event.
        changed[40] ^= 0xff;
        assert!(BatchPlan::decode(&changed).is_err());
    }

    #[test]
    fn replacement_plans_keep_legacy_pairs_and_refuse_rule_members() {
        let reversal = correction_plan(false, false);
        let replacement = correction_plan(false, true);
        let legacy = ReplacementPlan::new(reversal.clone(), replacement.clone()).unwrap();
        assert_eq!(
            ReplacementPlan::decode(&legacy.canonical_bytes().unwrap()).unwrap(),
            legacy
        );
        for (reversal, replacement) in [
            (correction_plan(true, false), replacement),
            (reversal, correction_plan(true, true)),
        ] {
            assert!(matches!(
                ReplacementPlan::new(reversal.clone(), replacement.clone()),
                Err(IntentError::Invalid(
                    "rule-derived intents require a single-entry PostPlan"
                ))
            ));
            let mut embedded = Writer::new();
            embedded
                .fixed(ReplacementPlan::MAGIC)
                .u16(1)
                .u16(0)
                .bytes(&reversal.canonical_bytes().unwrap())
                .bytes(&replacement.canonical_bytes().unwrap());
            assert!(matches!(
                ReplacementPlan::decode(&embedded.finish().unwrap()),
                Err(IntentError::Invalid(
                    "rule-derived intents require a single-entry PostPlan"
                ))
            ));
        }
    }

    #[test]
    fn replacement_reviews_keep_legacy_pairs_and_refuse_rule_members() {
        let reversal = correction_plan(false, false).intent().clone();
        let replacement = correction_plan(false, true).intent().clone();
        let legacy = ReplacementReview::new(reversal.clone(), replacement.clone()).unwrap();
        assert_eq!(
            ReplacementReview::decode(&legacy.canonical_bytes().unwrap()).unwrap(),
            legacy
        );
        for (reversal, replacement) in [
            (correction_plan(true, false).intent().clone(), replacement),
            (reversal, correction_plan(true, true).intent().clone()),
        ] {
            assert!(matches!(
                ReplacementReview::new(reversal.clone(), replacement.clone()),
                Err(IntentError::Invalid(
                    "rule-derived intents require a single-entry PostPlan"
                ))
            ));
            let mut embedded = Writer::new();
            embedded
                .fixed(ReplacementReview::MAGIC)
                .u16(1)
                .u16(0)
                .bytes(&reversal.canonical_bytes().unwrap())
                .bytes(&replacement.canonical_bytes().unwrap());
            assert!(matches!(
                ReplacementReview::decode(&embedded.finish().unwrap()),
                Err(IntentError::Invalid(
                    "rule-derived intents require a single-entry PostPlan"
                ))
            ));
        }
    }

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
