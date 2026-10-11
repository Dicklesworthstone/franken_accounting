//! Attestations (plan §9.2–§9.4, Appendix A `Attestation`): a principal's
//! statement about objects, journaled, immutable, content-addressed.
//!
//! Two claims are implemented, the two the evidence law reads:
//! - **`Reviewed { against }`** (§9.3): a reviewer attests a document. A
//!   self-sourced document (`AgentUpload`, `Generated`) counts toward an
//!   entry's evidence minimum only once a principal other than the one who
//!   uploaded it has recorded this attestation over it. The reviewer must
//!   hold `approve` (an approver's attestation: no Agent or System profile
//!   can hold it) and must not be the uploader (SoD by identity).
//! - **`ManualAssertion { reason_code, statement }`** (§9.2): the preparer
//!   asserts that no document exists, with a reason from
//!   `reason_codes.toml` and a sealed statement of the particulars. It
//!   satisfies the minimum, in place of a document, only for the classes
//!   whose `evidence_policy.toml` row says `manual_assertion = true`.
//!
//! The other Appendix A claims (`Prepared`, `Reconciled`, `RegisterEquals`,
//! `Confirmed`, `Examined`, `Custom`) keep their tags (1, 3–7) and are not
//! representable in this build: no constructor exists, and a stored payload
//! carrying one does not decode.
//!
//! **Identities are derived, so the kernel reads them as point witnesses.**
//! A ManualAssertion's subject is the entry's `proposal_digest`; the
//! proposal cannot cite an attestation over its own digest, so instead
//! `vid = H("fa:vid:attestation-manual:v1" ‖ book ‖ proposal_digest)` (one
//! per proposal; only the preparer can record it). A Reviewed attestation is
//! `vid = H("fa:vid:attestation-review:v1" ‖ book ‖ document_oid)` (one per
//! document). Inside the posting transaction the kernel point-reads both
//! exactly as it reads a cited document, so an attestation counts iff it
//! was recorded before the post's snapshot, and stages `ATTESTS`
//! ManualAssertion → Entry beside the entry. A Reviewed attestation's
//! `ATTESTS` edge to its document is written when it is recorded.
//!
//! Interim postures, stated rather than hidden:
//! - **No signature.** Appendix A's `signature` needs principal keys
//!   (Warden), which this build does not have. The stored payload carries,
//!   after `signed_digest` and outside it exactly where the signature goes,
//!   the capability binding the kernel admitted it under: scheme 0
//!   (capability-bound), the profile, and the capability's commitment.
//! - **One subject, no `evidence_refs`.** `subject_refs` is written as a
//!   list (of exactly one in this subset) and `evidence_refs` as an empty
//!   list, so the v1 bytes already carry Appendix A's field set; a decoder
//!   refuses any other shape until a claim needs it.
//! - **The Human-profile check is a named hook** ([`human_reviewer`]): this
//!   build checks the reviewer's capability (it holds `approve`) and the
//!   identity inequality; principals carry no registered profile until
//!   fa-llx ships them.

use fa_model::symbols::{label, property, relation};
use fa_model::{
    DecodeError, EntryPayload, Erasable, Id128, Oid, Reader, SealKey, Writer, domain_digest,
};
use fa_policy::{Capability, Op, Profile};
use fa_registry::evidence_policy::{EvidencePolicy, Requirement};
use fa_registry::reason_codes::ReasonCodes;
use fgdb::{Database, VertexRow, WriteBatch, WriteTxn};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::evidence::{document_vid, drift, hex, verify_row};
use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{edge_id, prop, scalar_bytes, scalar_text};

/// Domain of `signed_digest` (Appendix A).
pub const ATTESTATION_DOMAIN: &[u8] = b"fa:attestation:v1";
const ATTESTATION_VERSION: u16 = 1;
/// The authentication trailer's scheme: the admitting capability's binding.
const SCHEME_CAPABILITY: u8 = 0;
/// The `reason_codes.toml` scope a ManualAssertion's reason belongs to.
pub const MANUAL_ASSERTION_SCOPE: &str = "manual_assertion";

/// `AttestationClaim` tags, in Appendix A's order; 8 is §9.2's
/// ManualAssertion. Only [`claim::REVIEWED`] and
/// [`claim::MANUAL_ASSERTION`] are implemented.
pub mod claim {
    pub const PREPARED: u8 = 1;
    pub const REVIEWED: u8 = 2;
    pub const RECONCILED: u8 = 3;
    pub const REGISTER_EQUALS: u8 = 4;
    pub const CONFIRMED: u8 = 5;
    pub const EXAMINED: u8 = 6;
    pub const CUSTOM: u8 = 7;
    pub const MANUAL_ASSERTION: u8 = 8;
}

/// Subject tags of `subject_refs`.
const SUBJECT_DOCUMENT: u8 = 1;
const SUBJECT_PROPOSAL: u8 = 2;

/// What an attestation claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestationClaim {
    /// "I reviewed this document against these": `against` names the
    /// documents compared, strictly ascending; it may be empty (the
    /// comparison was with an original the book does not hold).
    Reviewed { against: Vec<Oid> },
    /// "No document exists because …": a registered reason and the
    /// preparer's statement of the particulars, sealed under the book key.
    ManualAssertion {
        reason_code: u16,
        statement: Erasable<String>,
    },
}

impl AttestationClaim {
    #[must_use]
    pub fn tag(&self) -> u8 {
        match self {
            Self::Reviewed { .. } => claim::REVIEWED,
            Self::ManualAssertion { .. } => claim::MANUAL_ASSERTION,
        }
    }

    /// The claim's name, mirrored on the vertex as `code`.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Reviewed { .. } => "Reviewed",
            Self::ManualAssertion { .. } => "ManualAssertion",
        }
    }
}

/// The object an attestation is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Subject {
    /// A document this book holds (a Reviewed attestation's subject).
    Document(Oid),
    /// An entry's `proposal_digest` (a ManualAssertion's subject).
    Proposal([u8; 32]),
}

/// An attestation's signed content (`signed_digest` covers exactly this).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    pub book_id: Id128,
    pub claim: AttestationClaim,
    pub subject: Subject,
    /// The attesting principal.
    pub principal: VId,
}

/// The binding the kernel admitted an attestation under, stored where
/// Appendix A's signature goes (outside `signed_digest`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityBinding {
    pub profile: Profile,
    pub capability_commitment: [u8; 32],
}

/// A stored attestation, decoded and verified against its digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAttestation {
    pub attestation: Attestation,
    pub signed_digest: [u8; 32],
    pub binding: CapabilityBinding,
}

fn vid_of(domain: &[u8], book: Id128, key: &[u8; 32]) -> VId {
    let d = domain_digest(domain, &[&book.0, key]);
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d[..16]);
    VId(u128::from_le_bytes(lo))
}

/// `vid(Reviewed) = H("fa:vid:attestation-review:v1" ‖ book ‖ document_oid)`:
/// one review per document, which the posting kernel point-reads.
#[must_use]
pub fn review_vid(book: Id128, document: &Oid) -> VId {
    vid_of(b"fa:vid:attestation-review:v1", book, &document.0)
}

/// `vid(ManualAssertion) = H("fa:vid:attestation-manual:v1" ‖ book ‖
/// proposal_digest)`: one assertion per proposal, which the posting kernel
/// point-reads.
#[must_use]
pub fn manual_assertion_vid(book: Id128, proposal_digest: &[u8; 32]) -> VId {
    vid_of(b"fa:vid:attestation-manual:v1", book, proposal_digest)
}

impl Attestation {
    /// The derived identity: the claim and its subject decide it.
    #[must_use]
    pub fn vid(&self) -> Option<VId> {
        match (&self.claim, &self.subject) {
            (AttestationClaim::Reviewed { .. }, Subject::Document(oid)) => {
                Some(review_vid(self.book_id, oid))
            }
            (AttestationClaim::ManualAssertion { .. }, Subject::Proposal(d)) => {
                Some(manual_assertion_vid(self.book_id, d))
            }
            _ => None,
        }
    }

    /// `u16 version ‖ id128 book ‖ claim ‖ list(subject_refs) ‖ u128
    /// principal ‖ list(evidence_refs)`.
    fn body(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::new();
        w.u16(ATTESTATION_VERSION)
            .fixed(&self.book_id.0)
            .u8(self.claim.tag());
        match &self.claim {
            AttestationClaim::Reviewed { against } => {
                w.list(against, |w, o| {
                    w.fixed(&o.0);
                });
            }
            AttestationClaim::ManualAssertion {
                reason_code,
                statement,
            } => {
                w.u16(*reason_code);
                statement.encode(&mut w);
            }
        }
        w.list(&[self.subject], |w, s| match s {
            Subject::Document(oid) => {
                w.u8(SUBJECT_DOCUMENT).fixed(&oid.0);
            }
            Subject::Proposal(d) => {
                w.u8(SUBJECT_PROPOSAL).fixed(d);
            }
        })
        .u128(self.principal.0);
        let evidence_refs: [Oid; 0] = [];
        w.list(&evidence_refs, |w, o| {
            w.fixed(&o.0);
        });
        w.finish().map_err(|e| KernelError::Model(e.into()))
    }

    /// `signed_digest = BLAKE3("fa:attestation:v1" ‖ body)`.
    pub fn signed_digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(ATTESTATION_DOMAIN, &[&self.body()?]))
    }

    /// `body ‖ signed_digest ‖ u8 scheme ‖ u8 profile ‖ [32] capability
    /// commitment`: the stored payload.
    pub fn canonical_bytes(&self, binding: &CapabilityBinding) -> Result<Vec<u8>, KernelError> {
        let mut bytes = self.body()?;
        bytes.extend_from_slice(&self.signed_digest()?);
        bytes.push(SCHEME_CAPABILITY);
        bytes.push(binding.profile.tag());
        bytes.extend_from_slice(&binding.capability_commitment);
        Ok(bytes)
    }
}

impl StoredAttestation {
    /// Decode and verify: the trailing digest is the body's, and the claim
    /// and subject are a pair this build records.
    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(bytes);
        let (attestation, signed_digest, binding) =
            (|| -> Result<(Attestation, [u8; 32], CapabilityBinding), DecodeError> {
                if r.u16("attestation.version")? != ATTESTATION_VERSION {
                    return Err(r.invalid("attestation.version"));
                }
                let book_id = Id128(r.fixed("attestation.book_id")?);
                let tag = r.u8("attestation.claim")?;
                let claim = match tag {
                    claim::REVIEWED => {
                        let against = r.list(
                            fa_model::limits::MAX_EVIDENCE_PER_ENTRY,
                            "attestation.against",
                            |r| Ok(Oid(r.fixed("attestation.against")?)),
                        )?;
                        if !against.windows(2).all(|w| w[0] < w[1]) {
                            return Err(r.unsorted("attestation.against"));
                        }
                        AttestationClaim::Reviewed { against }
                    }
                    claim::MANUAL_ASSERTION => AttestationClaim::ManualAssertion {
                        reason_code: r.u16("attestation.reason_code")?,
                        statement: Erasable::decode(
                            &mut r,
                            fa_model::limits::MAX_DESCRIPTION_BYTES,
                        )?,
                    },
                    // Prepared, Reconciled, RegisterEquals, Confirmed,
                    // Examined, Custom: not in this build.
                    t => return Err(r.bad_tag("attestation.claim", t)),
                };
                let subjects = r.list(1, "attestation.subject_refs", |r| {
                    match r.u8("attestation.subject")? {
                        SUBJECT_DOCUMENT => {
                            Ok(Subject::Document(Oid(r.fixed("attestation.subject")?)))
                        }
                        SUBJECT_PROPOSAL => Ok(Subject::Proposal(r.fixed("attestation.subject")?)),
                        t => Err(r.bad_tag("attestation.subject", t)),
                    }
                })?;
                let [subject] = subjects.as_slice() else {
                    return Err(r.invalid("attestation.subject_refs"));
                };
                let principal = VId(r.u128("attestation.principal")?);
                // Empty in this subset: a count above 0 is refused.
                r.count(0, "attestation.evidence_refs")?;
                let signed_digest: [u8; 32] = r.fixed("attestation.signed_digest")?;
                if r.u8("attestation.scheme")? != SCHEME_CAPABILITY {
                    return Err(r.invalid("attestation.scheme"));
                }
                let profile_tag = r.u8("attestation.profile")?;
                let profile = Profile::from_tag(profile_tag)
                    .ok_or_else(|| r.bad_tag("attestation.profile", profile_tag))?;
                let capability_commitment = r.fixed("attestation.capability")?;
                r.finish()?;
                Ok((
                    Attestation {
                        book_id,
                        claim,
                        subject: *subject,
                        principal,
                    },
                    signed_digest,
                    CapabilityBinding {
                        profile,
                        capability_commitment,
                    },
                ))
            })()
            .map_err(|e| KernelError::Model(e.into()))?;
        if attestation.vid().is_none() {
            return Err(KernelError::Corrupt(format!(
                "attestation {}: a {} claim cannot have this subject",
                hex(&signed_digest),
                attestation.claim.name()
            )));
        }
        if attestation.signed_digest()? != signed_digest {
            return Err(KernelError::Corrupt(format!(
                "attestation {}: the payload does not hash to its signed_digest",
                hex(&signed_digest)
            )));
        }
        Ok(Self {
            attestation,
            signed_digest,
            binding,
        })
    }
}

/// The refusal for a stored attestation the kernel would never have
/// recorded (exit 8): it does not verify, its mirrors disagree with its
/// payload, or it breaks a law its recording enforces.
fn attestation_drift(vid: VId, why: &str) -> Refusal {
    Refusal::new(
        code::ATTESTATION_DRIFT,
        exit::VERIFICATION,
        format!("attestation {:032x}: {why}", vid.0),
        "FA-INV-04 (a mirror is never more authoritative than the payload), FA-INV-05 (the closure verifies)",
        "preserve the store and report the drift; nothing that relies on this attestation is admitted until it is explained",
    )
}

/// Check a stored Attestation row against itself: the payload decodes and
/// hashes to its digest, the vertex is the one its claim and subject derive,
/// and every mirror equals what the payload says.
fn verify_attestation_row(row: &VertexRow) -> Result<StoredAttestation, String> {
    if !row.labels.contains(&label::ATTESTATION) {
        return Err("the vertex is not labeled Attestation".into());
    }
    let Some(CanonicalScalar::Bytes(payload)) = prop(row, property::FA_PAYLOAD) else {
        return Err("the vertex carries no attestation payload".into());
    };
    let stored = StoredAttestation::decode(payload.as_slice())
        .map_err(|e| format!("the payload does not verify: {e}"))?;
    let a = &stored.attestation;
    if a.vid() != Some(row.vid) {
        return Err("the payload is not the attestation this vertex's identity names".into());
    }
    match prop(row, property::FA_DIGEST) {
        Some(CanonicalScalar::Bytes(b)) if b.as_slice() == stored.signed_digest.as_slice() => {}
        _ => return Err("the digest mirror differs from the payload's signed_digest".into()),
    }
    match prop(row, property::CODE) {
        Some(CanonicalScalar::Text(t)) if t.as_bytes() == a.claim.name().as_bytes() => {}
        _ => {
            return Err(format!(
                "the claim mirror differs from the payload's claim `{}`",
                a.claim.name()
            ));
        }
    }
    match prop(row, property::BOOK_ID) {
        Some(CanonicalScalar::Bytes(b)) if b.as_slice() == a.book_id.0.as_slice() => {}
        _ => return Err("the book_id mirror differs from the payload's book".into()),
    }
    Ok(stored)
}

/// The attestation at `vid`, verified, with the sequence that recorded it.
pub fn read_attestation<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    vid: VId,
) -> Result<Option<(StoredAttestation, CommitSeq)>, KernelError> {
    let Some(row) = db.vertex(vid)? else {
        return Ok(None);
    };
    match verify_attestation_row(&row) {
        Ok(stored) => Ok(Some((stored, row.created_at))),
        Err(why) => Err(KernelError::Corrupt(format!(
            "{} attestation {:032x}: {why}",
            code::ATTESTATION_DRIFT,
            vid.0
        ))),
    }
}

/// A Reviewed attestation the posting kernel relied on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Review {
    /// The attestation's vertex.
    pub attestation: VId,
    pub reviewer: VId,
}

/// Inside `txn`: the Reviewed attestation over `document`, read as a point
/// witness and verified, or `None` when there is none.
pub fn witness_review<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: Id128,
    document: &Oid,
) -> Outcome<Option<Review>> {
    let vid = review_vid(book, document);
    let Some(row) = txn.vertex(db, vid)? else {
        return Ok(Ok(None));
    };
    match verify_attestation_row(&row) {
        Ok(StoredAttestation { attestation, .. }) => Ok(Ok(Some(Review {
            attestation: vid,
            reviewer: attestation.principal,
        }))),
        Err(why) => Ok(Err(attestation_drift(vid, &why))),
    }
}

/// A ManualAssertion the posting kernel relied on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assertion {
    /// The attestation's vertex.
    pub attestation: VId,
    pub reason_code: u16,
}

/// Inside `txn`: the ManualAssertion over `proposal`'s digest, read as a
/// point witness and verified, or `None` when there is none. One whose
/// principal is not the proposal's preparer is drift: recording refuses it.
pub fn witness_manual_assertion<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    proposal: &EntryPayload,
    proposal_digest: &[u8; 32],
) -> Outcome<Option<Assertion>> {
    let vid = manual_assertion_vid(proposal.book_id, proposal_digest);
    let Some(row) = txn.vertex(db, vid)? else {
        return Ok(Ok(None));
    };
    let stored = match verify_attestation_row(&row) {
        Ok(stored) => stored,
        Err(why) => return Ok(Err(attestation_drift(vid, &why))),
    };
    if stored.attestation.principal != proposal.principal_ref {
        return Ok(Err(attestation_drift(
            vid,
            "the assertion's principal is not the proposal's preparer",
        )));
    }
    match stored.attestation.claim {
        AttestationClaim::ManualAssertion { reason_code, .. } => Ok(Ok(Some(Assertion {
            attestation: vid,
            reason_code,
        }))),
        AttestationClaim::Reviewed { .. } => Ok(Err(attestation_drift(
            vid,
            "a Reviewed claim sits at a ManualAssertion's identity",
        ))),
    }
}

/// The outcome of recording an attestation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attested {
    pub vid: VId,
    pub signed_digest: [u8; 32],
    pub recorded_at: CommitSeq,
    /// The same attestation was already recorded; nothing was written.
    pub already_recorded: bool,
}

fn subject_refusal(message: String, fix: &str) -> Refusal {
    Refusal::new(
        code::ATTESTATION_SUBJECT,
        exit::REFUSAL,
        message,
        "plan §9.2–§9.3 (a Reviewed attestation names documents the book holds; a ManualAssertion stands in for a document only where evidence_policy.toml allows it)",
        fix,
    )
}

/// The refusal for an unregistered ManualAssertion reason (exit 2).
#[must_use]
pub fn reason_refusal(reasons: &ReasonCodes, reason_code: u16) -> Refusal {
    Refusal::new(
        code::REASON_CODE,
        exit::USAGE,
        format!("reason code {reason_code} is not a registered ManualAssertion reason"),
        "registries/reason_codes.toml (scope manual_assertion); plan §9.2",
        format!(
            "use a registered reason: {}; the statement carries the particulars",
            reasons.listing(MANUAL_ASSERTION_SCOPE)
        ),
    )
}

/// The refusal for a reviewer who uploaded the document (exit 7, SoD).
#[must_use]
pub fn self_review_refusal(document: &Oid, principal: VId) -> Refusal {
    Refusal::new(
        code::SELF_REVIEW,
        exit::SAFETY,
        format!(
            "principal {:032x} uploaded document {} and cannot review it",
            principal.0,
            hex(&document.0)
        ),
        "plan §9.3 (self-sourced evidence counts once an approver other than the uploader reviews it); FA-INV-10 (segregation of duties)",
        "have a principal other than the uploader, holding `approve`, record the Reviewed attestation",
    )
}

/// **The Human-profile hook (fa-llx).** Plan §9.3 requires the reviewer to
/// be an approver, and §14.4 makes approval human authority. This build
/// checks what it can before any read: the capability is the reviewer's,
/// it is not an Agent's on trunk, and it holds `approve` — which no Agent or
/// System profile can hold (`Profile::forbidden_ops`), so only a Human
/// capability passes. What it cannot check yet is the *principal's*
/// registered profile: principals carry none until fa-llx ships them, and
/// the embedded posture self-issues Human capabilities. When they land, this
/// function also reads the reviewer's registered profile and refuses one
/// that is not Human; identity inequality with the uploader is checked in
/// the recording transaction either way.
fn human_reviewer(
    capability: &Capability,
    reviewer: VId,
    book: &BookContext,
) -> Result<(), Refusal> {
    fa_policy::admit(
        capability,
        &fa_policy::Intent {
            principal: reviewer,
            trunk: true,
            op: Op::Approve,
            book: book.book_id,
            legs: &[],
        },
    )
    .map_err(|d| crate::policy::refusal(&d))
}

/// The capability binding stored with an attestation.
fn binding(capability: &Capability) -> Result<CapabilityBinding, KernelError> {
    Ok(CapabilityBinding {
        profile: capability.profile(),
        capability_commitment: capability
            .commitment()
            .map_err(|e| KernelError::Corrupt(format!("capability: {e}")))?,
    })
}

/// Whether a stored attestation states what `ours` states: the same signed
/// digest, or — for a ManualAssertion re-sealed on a retry — the same
/// principal, subject and reason with a statement that opens, under the book
/// key, to the same text.
fn same_statement(stored: &Attestation, ours: &Attestation, key: &SealKey) -> bool {
    if stored.principal != ours.principal || stored.subject != ours.subject {
        return false;
    }
    match (&stored.claim, &ours.claim) {
        (
            AttestationClaim::ManualAssertion {
                reason_code: a,
                statement: s,
            },
            AttestationClaim::ManualAssertion {
                reason_code: b,
                statement: t,
            },
        ) => {
            let max = fa_model::limits::MAX_DESCRIPTION_BYTES;
            a == b
                && matches!(
                    (s.open(key, max), t.open(key, max)),
                    (Ok(x), Ok(y)) if x == y
                )
        }
        (stored, ours) => stored == ours,
    }
}

/// Record `attestation` in `txn` (whose reads already happened): the
/// recorded outcome if its identity holds the same statement, a conflict if
/// it holds another, else one Attestation vertex plus `edges`.
async fn commit_attestation<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    mut txn: WriteTxn,
    attestation: &Attestation,
    binding: &CapabilityBinding,
    attests: Option<VId>,
) -> Outcome<Attested> {
    let vid = attestation
        .vid()
        .ok_or_else(|| KernelError::Corrupt("an attestation without an identity".into()))?;
    let signed_digest = attestation.signed_digest()?;
    if let Some(row) = txn.vertex(db, vid)? {
        txn.abort();
        return recorded_or_conflict(&row, attestation, &book.seal_key);
    }
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("_fa_payload", attestation.canonical_bytes(binding)?)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("_fa_digest", signed_digest.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("book_id", book.book_id.0.to_vec())?,
        ),
        (
            property::CODE,
            scalar_text("code", attestation.claim.name())?,
        ),
    ];
    props.sort_by_key(|(k, _)| k.0);
    let mut batch = WriteBatch::new(relation::ATTESTS);
    batch.create_vertex(vid, vec![label::ATTESTATION], props);
    if let Some(target) = attests {
        batch.add_edge(edge_id(relation::ATTESTS, vid, target), vid, target, vec![]);
    }
    if let Err(e) = txn.write(db, batch) {
        txn.abort();
        return Err(e.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(Attested {
            vid,
            signed_digest,
            recorded_at: seq,
            already_recorded: false,
        })),
        Err(fgdb::WriteTxnError::Write(fgdb::WriteError::AlreadyLive { .. })) => {
            match db.vertex(vid)? {
                Some(row) => recorded_or_conflict(&row, attestation, &book.seal_key),
                None => Err(KernelError::Corrupt(
                    "an attestation reported live is absent".into(),
                )),
            }
        }
        Err(fgdb::WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins {
            detail, ..
        })) => Ok(Err(Refusal::new(
            code::CONFLICT,
            exit::CONFLICT,
            format!("a concurrent commit invalidated a witness this attestation read: {detail}"),
            "FG-LAW-FCW-01 (first committer wins)",
            "retry the attestation",
        ))),
        Err(e) => Err(e.into()),
    }
}

fn recorded_or_conflict(row: &VertexRow, ours: &Attestation, key: &SealKey) -> Outcome<Attested> {
    let stored = match verify_attestation_row(row) {
        Ok(stored) => stored,
        Err(why) => return Ok(Err(attestation_drift(row.vid, &why))),
    };
    if stored.signed_digest == ours.signed_digest()?
        || same_statement(&stored.attestation, ours, key)
    {
        return Ok(Ok(Attested {
            vid: row.vid,
            signed_digest: stored.signed_digest,
            recorded_at: row.created_at,
            already_recorded: true,
        }));
    }
    let what = match &stored.attestation.subject {
        Subject::Document(oid) => format!(
            "document {} was already reviewed by principal {:032x}",
            hex(&oid.0),
            stored.attestation.principal.0
        ),
        Subject::Proposal(d) => format!(
            "proposal {} already carries a ManualAssertion with a different statement",
            hex(d)
        ),
    };
    Ok(Err(Refusal::new(
        code::IDEMPOTENCY_CONFLICT,
        exit::CONFLICT,
        format!("{what} (recorded at sequence {})", row.created_at.0),
        "plan Appendix A Attestation (immutable; one Reviewed per document and one ManualAssertion per proposal in this build)",
        "the recorded attestation stands; rely on it, or prepare a new proposal (a new idempotency key) to assert over",
    )))
}

/// Record a `Reviewed { against }` attestation over `document` by
/// `reviewer` (plan §9.3). Before any read: `against` is strictly ascending
/// and does not name the subject, and the capability passes the
/// [`human_reviewer`] hook and is current at the admission point. Then, in
/// one transaction: the subject and every `against` document are documents
/// this book holds, read as witnesses and verified (FA-REF-110 if absent,
/// FA-REF-085 if drifted); the reviewer is not the subject's uploader
/// (FA-REF-111); and one Attestation vertex with `ATTESTS → Document` is
/// written. Recording the same review again is the recorded outcome.
pub async fn record_review<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    reviewer: VId,
    document: Oid,
    against: Vec<Oid>,
) -> Outcome<Attested> {
    let policy = EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    if against.len() > fa_model::limits::MAX_EVIDENCE_PER_ENTRY
        || !against.windows(2).all(|w| w[0] < w[1])
        || against.contains(&document)
    {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "`against` lists at most max_evidence_per_entry documents, strictly ascending, other than the one reviewed",
            "Appendix A AttestationClaim::Reviewed { against }",
            "list each compared document once, sorted, and not the reviewed document itself",
        )));
    }
    if let Err(r) = human_reviewer(capability, reviewer, book) {
        return Ok(Err(r));
    }
    if let Err(d) = fa_policy::current(capability, db.frontier()?) {
        return Ok(Err(crate::policy::refusal(&d)));
    }
    let binding = binding(capability)?;
    let attestation = Attestation {
        book_id: book.book_id,
        claim: AttestationClaim::Reviewed {
            against: against.clone(),
        },
        subject: Subject::Document(document),
        principal: reviewer,
    };

    let txn_cx = ctx.txn();
    let txn = db.begin(&txn_cx)?;
    let dvid = document_vid(&document);
    let subject = match held_document(&txn, db, &policy, &document)? {
        Ok(Some(doc)) => doc,
        Ok(None) => {
            txn.abort();
            return Ok(Err(subject_refusal(
                format!(
                    "the review names document {} which this book does not hold",
                    hex(&document.0)
                ),
                "record the document with `fa document add <file> --json` and review the oid it prints",
            )));
        }
        Err(r) => {
            txn.abort();
            return Ok(Err(r));
        }
    };
    if subject.retrieved_by == reviewer {
        txn.abort();
        return Ok(Err(self_review_refusal(&document, reviewer)));
    }
    for (i, oid) in against.iter().enumerate() {
        match held_document(&txn, db, &policy, oid)? {
            Ok(Some(_)) => {}
            Ok(None) => {
                txn.abort();
                return Ok(Err(subject_refusal(
                    format!(
                        "against[{i}] names document {} which this book does not hold",
                        hex(&oid.0)
                    ),
                    "record each compared document with `fa document add <file> --json` first, or leave it out of `against`",
                )));
            }
            Err(r) => {
                txn.abort();
                return Ok(Err(r));
            }
        }
    }
    commit_attestation(db, ctx, book, txn, &attestation, &binding, Some(dvid)).await
}

/// A document this book holds, read in `txn` and verified, or `None`.
fn held_document<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    policy: &EvidencePolicy,
    oid: &Oid,
) -> Outcome<Option<crate::evidence::Document>> {
    let Some(row) = txn.vertex(db, document_vid(oid))? else {
        return Ok(Ok(None));
    };
    match verify_row(&row, policy) {
        Ok(doc) if doc.oid() == *oid => Ok(Ok(Some(doc))),
        Ok(_) => Ok(Err(drift(oid, "the vertex holds another document"))),
        Err(why) => Ok(Err(drift(oid, &why))),
    }
}

/// Record the preparer's `ManualAssertion` over `proposal` (plan §9.2): no
/// document exists, for `reason_code`, as `statement` describes. Before any
/// read: the statement opens under the book key and is not blank; the
/// proposal is this book's; the capability is the preparer's own (an Agent
/// never writes trunk) and holds `post`; the reason is registered
/// (FA-REF-112); the class's evidence row admits an assertion (FA-REF-110);
/// the capability is current. Then one Attestation vertex at the
/// proposal's derived identity. Posting the proposal afterwards relies on
/// it, inside the posting transaction.
pub async fn record_manual_assertion<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    proposal: &EntryPayload,
    reason_code: u16,
    statement: Erasable<String>,
) -> Outcome<Attested> {
    let policy = EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let reasons = ReasonCodes::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let readable = statement
        .open(&book.seal_key, fa_model::limits::MAX_DESCRIPTION_BYTES)
        .is_ok_and(|s| !s.trim().is_empty());
    if !readable {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "a ManualAssertion's statement must be non-blank text sealed under this book's key",
            "plan §9.2 (\"no document exists because …\": the statement carries the particulars)",
            "state the particulars (who, what, when, why there is no document) and seal them with the book key",
        )));
    }
    if proposal.book_id != book.book_id {
        return Ok(Err(Refusal::new(
            code::COORDINATE,
            exit::USAGE,
            format!(
                "the proposal names book {} but this book is {}",
                proposal.book_id.to_hex(),
                book.book_id.to_hex()
            ),
            "plan §2.2 (an object belongs to exactly one book)",
            "set book_id to this book's id (fa book info --json)",
        )));
    }
    // Authorization precedes observation: the assertion is the preparer's,
    // made under the capability that will post the proposal.
    if let Err(d) = fa_policy::admit(
        capability,
        &fa_policy::Intent {
            principal: proposal.principal_ref,
            trunk: true,
            op: Op::Post,
            book: book.book_id,
            legs: &[],
        },
    ) {
        return Ok(Err(crate::policy::refusal(&d)));
    }
    if reasons.get(MANUAL_ASSERTION_SCOPE, reason_code).is_none() {
        return Ok(Err(reason_refusal(&reasons, reason_code)));
    }
    let class_name = proposal.class.name().unwrap_or("?");
    let admits = policy
        .minimum(class_name)
        .is_some_and(|m| m.requirement == Requirement::Documents && m.manual_assertion);
    if !admits {
        return Ok(Err(subject_refusal(
            format!("class `{class_name}` does not admit a ManualAssertion in place of a document"),
            "cite a document recorded with `fa document add <file> --json`; never fabricate one",
        )));
    }
    if let Err(d) = fa_policy::current(capability, db.frontier()?) {
        return Ok(Err(crate::policy::refusal(&d)));
    }
    let binding = binding(capability)?;
    let attestation = Attestation {
        book_id: book.book_id,
        claim: AttestationClaim::ManualAssertion {
            reason_code,
            statement,
        },
        subject: Subject::Proposal(proposal.proposal_digest()?),
        principal: proposal.principal_ref,
    };
    let txn_cx = ctx.txn();
    let txn = db.begin(&txn_cx)?;
    commit_attestation(db, ctx, book, txn, &attestation, &binding, None).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement(text: &str, salt: u8) -> Erasable<String> {
        Erasable::seal(
            &text.to_string(),
            None,
            &SealKey([0x11; 32]),
            [salt; 32],
            [salt; 24],
        )
    }

    fn binding() -> CapabilityBinding {
        CapabilityBinding {
            profile: Profile::Human,
            capability_commitment: [0xc0; 32],
        }
    }

    #[test]
    fn both_claims_round_trip_and_the_digest_binds_every_signed_byte() {
        let review = Attestation {
            book_id: Id128([5; 16]),
            claim: AttestationClaim::Reviewed {
                against: vec![Oid([1; 32]), Oid([2; 32])],
            },
            subject: Subject::Document(Oid([9; 32])),
            principal: VId(8),
        };
        let manual = Attestation {
            book_id: Id128([5; 16]),
            claim: AttestationClaim::ManualAssertion {
                reason_code: 3,
                statement: statement("an oral agreement with the landlord", 4),
            },
            subject: Subject::Proposal([7; 32]),
            principal: VId(7),
        };
        for a in [&review, &manual] {
            let bytes = a.canonical_bytes(&binding()).unwrap();
            let stored = StoredAttestation::decode(&bytes).unwrap();
            assert_eq!(&stored.attestation, a);
            assert_eq!(stored.binding, binding());
            // Every signed byte is bound by the digest; the trailer (scheme,
            // profile, commitment: 34 bytes) is outside it, like a signature.
            let signed = bytes.len() - 32 - 34;
            for i in 0..signed {
                let mut t = bytes.clone();
                t[i] ^= 0x01;
                assert!(StoredAttestation::decode(&t).is_err(), "byte {i}");
            }
            assert!(StoredAttestation::decode(&bytes[..bytes.len() - 1]).is_err());
        }
        assert_ne!(review.vid(), manual.vid());
        assert_eq!(
            review.vid(),
            Some(review_vid(Id128([5; 16]), &Oid([9; 32])))
        );
        // A claim with the other claim's subject has no identity and does not decode.
        let crossed = Attestation {
            subject: Subject::Proposal([7; 32]),
            ..review.clone()
        };
        assert_eq!(crossed.vid(), None);
        assert!(StoredAttestation::decode(&crossed.canonical_bytes(&binding()).unwrap()).is_err());
    }

    /// Fixed vectors for both derived identities, computed by an independent
    /// single-chunk BLAKE3 written from the specification (checked against
    /// the published vectors for "" and "abc"), never by this code: a change
    /// to a domain, a part, its length prefix, or the truncation fails here.
    #[test]
    fn derived_identities_match_fixed_vectors() {
        assert_eq!(
            review_vid(Id128([5; 16]), &Oid([9; 32])),
            VId(0x1e76_2740_d45e_7b7f_cea0_8e91_3347_fbc0)
        );
        assert_eq!(
            manual_assertion_vid(Id128([5; 16]), &[7; 32]),
            VId(0xe6c5_8dbc_ed33_9374_f6b8_d767_41e8_9916)
        );
        // The two domains never collide on the same 32 bytes.
        assert_ne!(
            review_vid(Id128([5; 16]), &Oid([7; 32])),
            manual_assertion_vid(Id128([5; 16]), &[7; 32])
        );
    }

    #[test]
    fn unimplemented_claims_and_unsorted_against_do_not_decode() {
        let review = Attestation {
            book_id: Id128([5; 16]),
            claim: AttestationClaim::Reviewed {
                against: vec![Oid([1; 32])],
            },
            subject: Subject::Document(Oid([9; 32])),
            principal: VId(8),
        };
        let bytes = review.canonical_bytes(&binding()).unwrap();
        // The claim tag sits after the version (2) and the book (16).
        for tag in [
            claim::PREPARED,
            claim::RECONCILED,
            claim::REGISTER_EQUALS,
            claim::CONFIRMED,
            claim::EXAMINED,
            claim::CUSTOM,
            9,
        ] {
            let mut t = bytes.clone();
            t[18] = tag;
            assert!(StoredAttestation::decode(&t).is_err(), "claim tag {tag}");
        }
        let unsorted = Attestation {
            claim: AttestationClaim::Reviewed {
                against: vec![Oid([2; 32]), Oid([1; 32])],
            },
            ..review
        };
        assert!(StoredAttestation::decode(&unsorted.canonical_bytes(&binding()).unwrap()).is_err());
    }

    #[test]
    fn a_resealed_statement_is_the_same_assertion_and_a_different_one_is_not() {
        let key = SealKey([0x11; 32]);
        let base = Attestation {
            book_id: Id128([5; 16]),
            claim: AttestationClaim::ManualAssertion {
                reason_code: 1,
                statement: statement("bank fee shown only on the statement", 1),
            },
            subject: Subject::Proposal([7; 32]),
            principal: VId(7),
        };
        let resealed = Attestation {
            claim: AttestationClaim::ManualAssertion {
                reason_code: 1,
                statement: statement("bank fee shown only on the statement", 2),
            },
            ..base.clone()
        };
        assert_ne!(
            base.signed_digest().unwrap(),
            resealed.signed_digest().unwrap()
        );
        assert!(same_statement(&base, &resealed, &key));
        let other_text = Attestation {
            claim: AttestationClaim::ManualAssertion {
                reason_code: 1,
                statement: statement("a different statement", 3),
            },
            ..base.clone()
        };
        assert!(!same_statement(&base, &other_text, &key));
        let other_reason = Attestation {
            claim: AttestationClaim::ManualAssertion {
                reason_code: 2,
                statement: statement("bank fee shown only on the statement", 2),
            },
            ..base.clone()
        };
        assert!(!same_statement(&base, &other_reason, &key));
        // Under a key that cannot open them, equivalence is never claimed.
        assert!(!same_statement(&base, &resealed, &SealKey([0x22; 32])));
    }
}
