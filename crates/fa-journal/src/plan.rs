//! Portable PostEntry rehearsal and verified publication (fa-we7).
//!
//! The same production transaction stages every accounting effect for both
//! operations. Planning hashes that exact native delta, retains the sealed
//! input and resolved Entry, and aborts. Commit authenticates the artifact,
//! checks current external authority, and reproduces the same delta at the
//! same basis. It then appends only immutable certificate retention to that
//! very transaction. It never refreshes witnesses after their comparison.
//!
//! The pinned substrate has no public native application-object store.
//! Consequently this contract retains a Certificate graph vertex and a
//! strong CITES edge in the posting commit; its public digest is not an OID
//! and Entry.plan_certificate stays None. This also keeps the accounting
//! effect transcript acyclic, including scheduled reversal target digests.

use asupersync::fs::Vfs;
use fa_intents::{PlanCertificate, PostIntent, PostPlan};
use fa_model::symbols::{label, property, relation};
use fa_model::{EntryClass, Id128, domain_digest, entry_mirrors, entry_vid};
use fa_policy::Capability;
use fgdb::{Database, WriteBatch, WriteTxnError};
use fgdb_types::VId;
use fgdb_types::context::PurposeContexts;

use crate::genesis::BookContext;
use crate::policy;
use crate::post::{PostPreparation, PostRequest, Posted, prepare_post};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{edge_id, resolution_vid, reversal_vid, scalar_bytes};

fn invalidated(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::PLAN_INVALIDATED,
        exit::CONFLICT,
        message,
        "plan §10.4; fa-we7; Appendix H R-POST-PLAN (exact basis, authenticated proposal and native effects)",
        "run a fresh PostEntry dry-run with the current capability and required approvals, then commit its unchanged plan before another publication",
    )
}

fn codec(error: fa_intents::IntentError) -> KernelError {
    KernelError::Corrupt(format!("kernel-produced post plan: {error}"))
}

fn authentication(
    book: &BookContext,
    certificate: &PlanCertificate,
) -> Result<[u8; 32], KernelError> {
    let key = fgdb_crypto::derive_key("fa:post-plan-authentication-key:v1", &book.seal_key.0);
    let bytes = certificate.authentication_bytes().map_err(codec)?;
    Ok(fgdb_crypto::keyed_hash(&key, &bytes).0)
}

fn same_tag(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn request(intent: &PostIntent, capability: Capability) -> PostRequest {
    PostRequest {
        proposal: intent.proposal().clone(),
        approvals: intent.approvals().to_vec(),
        capability,
        plan_certificate: None,
    }
}

/// Run every production posting law and stage every native effect, then
/// release the transaction without a publication. Already recorded intents
/// are refused: a fresh plan must describe an actual prospective effect.
pub fn plan_post<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: Capability,
    intent: PostIntent,
) -> Outcome<PostPlan> {
    let commitment = capability
        .commitment()
        .map_err(|e| KernelError::Corrupt(format!("capability commitment: {e}")))?;
    let expires_at = capability.expires_at();
    match prepare_post(db, ctx, book, request(&intent, capability))? {
        Err(refusal) => Ok(Err(refusal)),
        Ok(PostPreparation::AlreadyRecorded(posted)) => Ok(Err(invalidated(format!(
            "this intent is already recorded as {:032x} at sequence {}; no new effects were planned",
            posted.entry_ref().vid.0,
            posted.recorded_at().0,
        )))),
        Ok(PostPreparation::Ready(prepared)) => {
            let entry = prepared.entry().clone();
            let mut certificate = PlanCertificate {
                book_id: entry.proposal.book_id,
                branch_id: entry.proposal.branch_id,
                principal: entry.proposal.principal_ref,
                capability_commitment: commitment,
                intent_digest: intent.digest().map_err(codec)?,
                proposal_digest: entry.proposal_digest,
                effects_digest: prepared.effects_digest()?,
                snapshot_seq: prepared.basis(),
                security_policy_epoch: prepared.security_policy_epoch(),
                expires_at,
                period: prepared.period().to_string(),
                authentication: [0; 32],
            };
            certificate.authentication = authentication(book, &certificate)?;
            let plan = PostPlan::new(intent, entry, certificate).map_err(codec)?;
            // Enforce the portable bound before returning and before claiming
            // this plan can be persisted by a caller in another process.
            plan.canonical_bytes().map_err(codec)?;
            prepared.abort();
            Ok(Ok(plan))
        }
    }
}

/// The locator namespace is deliberately separate from report certificates.
/// The complete certificate digest is checked at every use; a truncated
/// vertex identity is never accepted as evidence on its own.
#[must_use]
pub fn plan_certificate_vid(book_id: Id128, digest: &[u8; 32]) -> VId {
    let hash = domain_digest(b"fa:vid:post-plan-certificate:v1", &[&book_id.0, digest]);
    let mut low = [0_u8; 16];
    low.copy_from_slice(&hash[..16]);
    VId(u128::from_le_bytes(low))
}

/// Only an authenticated kernel-issued plan reaches this helper. It repeats
/// the three identity laws used by the admitted non-migration posting
/// classes, using the retained actual proposal rather than caller text.
fn planned_entry_vid(plan: &PostPlan) -> Result<VId, Refusal> {
    let proposal = plan.proposal();
    if proposal.class == EntryClass::REVERSAL {
        return proposal
            .supersession
            .first()
            .map(|target| reversal_vid(target.target.vid))
            .ok_or_else(|| invalidated("the planned reversal has no identity target"));
    }
    if proposal.class == EntryClass::RESOLUTION {
        return proposal
            .pending
            .as_ref()
            .and_then(|pending| pending.resolution_of)
            .map(|target| resolution_vid(target.vid))
            .ok_or_else(|| invalidated("the planned resolution has no identity target"));
    }
    Ok(entry_vid(
        proposal.book_id,
        &proposal.principal_ref.0.to_le_bytes(),
        &proposal.idempotency_key,
    ))
}

fn retention_props(
    book: &BookContext,
    plan: &PostPlan,
) -> Result<Vec<(fgdb_delta_types::PropertyKeyId, fgdb_types::CanonicalScalar)>, KernelError> {
    Ok(vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("post plan payload", plan.canonical_bytes().map_err(codec)?)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes(
                "post plan certificate digest",
                plan.certificate().digest().map_err(codec)?.to_vec(),
            )?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("post plan book_id", book.book_id.0.to_vec())?,
        ),
    ])
}

/// Exact same-plan outcome recognition precedes the strict basis check.
/// This is narrower than ordinary semantic post retry: it requires the
/// unchanged Entry, certificate, and retaining edge from the same original
/// commit. A direct post or another certificate cannot claim this outcome.
fn recorded_plan<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    plan: &PostPlan,
) -> Outcome<Option<Posted>> {
    let evid = match planned_entry_vid(plan) {
        Ok(vid) => vid,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let Some(entry) = db.vertex(evid)? else {
        return Ok(Ok(None));
    };
    // The native marker's next_commit_seq is checked_successor(frontier).
    // The same-basis contract therefore anchors this outcome to exactly
    // basis+1. VertexRow.created_at is a *version* start, so comparing only
    // a row with vertex_at(row.created_at) would let a later coordinated
    // rewrite/backfill masquerade as the original atomic publication.
    let Some(expected_sequence) = plan.certificate().snapshot_seq.0.checked_add(1) else {
        return Ok(Err(invalidated("the plan basis has no successor sequence")));
    };
    if entry.labels.as_slice() != [label::ENTRY]
        || entry.retired_at.is_some()
        || entry.props != entry_mirrors(plan.prepared_entry())?
        || entry.created_at.0 != expected_sequence
        || db.vertex_at(evid, entry.created_at)?.as_ref() != Some(&entry)
    {
        return Ok(Err(invalidated(
            "the planned identity is occupied by a different or changed Entry",
        )));
    }
    let digest = plan.certificate().digest().map_err(codec)?;
    let cvid = plan_certificate_vid(book.book_id, &digest);
    let Some(certificate) = db.vertex(cvid)? else {
        return Ok(Err(invalidated(
            "the recorded Entry has no retained evidence for this exact plan",
        )));
    };
    if certificate.labels.as_slice() != [label::CERTIFICATE]
        || certificate.retired_at.is_some()
        || certificate.props != retention_props(book, plan)?
        || certificate.created_at != entry.created_at
        || db.vertex_at(cvid, certificate.created_at)?.as_ref() != Some(&certificate)
    {
        return Ok(Err(invalidated(
            "the retained plan certificate changed or was not recorded with the Entry",
        )));
    }
    let eid = edge_id(relation::CITES, evid, cvid);
    let Some(edge) = db.edge(eid)? else {
        return Ok(Err(invalidated(
            "the recorded Entry has no strong CITES edge to this plan certificate",
        )));
    };
    if edge.entry.src != evid
        || edge.entry.dst != cvid
        || edge.entry.relation != relation::CITES
        || edge.entry.created_at != entry.created_at
        || edge.entry.retired_at.is_some()
        || !edge.props.is_empty()
        || db.edge_at(eid, entry.created_at)?.as_ref() != Some(&edge)
    {
        return Ok(Err(invalidated(
            "the plan's retaining edge changed or was not recorded with the Entry",
        )));
    }
    Ok(Ok(Some(Posted::AlreadyRecorded {
        entry_ref: plan.prepared_entry().entry_ref(evid),
        recorded_at: entry.created_at,
    })))
}

/// Commit an authenticated portable plan under a *current*, externally
/// supplied capability. No field in the artifact grants authority. A stale
/// basis, changed policy, changed preparation, or forged plan returns
/// PlanInvalidated (exit 6), with no publication.
pub async fn commit_plan<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: Capability,
    plan: PostPlan,
) -> Outcome<Posted> {
    ctx.txn().checkpoint().map_err(WriteTxnError::Interrupted)?;
    if let Err(error) = plan.validate() {
        return Ok(Err(invalidated(error.to_string())));
    }
    let proposal = plan.intent().proposal();
    // This API opens only this book's trunk. Reject a forged foreign branch
    // before admission can mistake it for an Agent's writable draft, and
    // before even the frontier or revocation identity is observed.
    if proposal.book_id != book.book_id || proposal.branch_id != Id128::TRUNK {
        return Ok(Err(invalidated(
            "the plan does not target this book's writable trunk coordinate",
        )));
    }
    let explicit: Vec<_> = proposal
        .legs
        .iter()
        .map(|leg| (leg.amount.unit, leg.amount.mantissa))
        .collect();
    // Authentication of the plan never replaces admission of the caller.
    // Do this before observing the identity, retained certificate, or head.
    if let Err(denial) = fa_policy::admit(
        &capability,
        &fa_policy::Intent {
            principal: proposal.principal_ref,
            trunk: proposal.branch_id == Id128::TRUNK,
            op: fa_policy::Op::Post,
            book: book.book_id,
            legs: &explicit,
        },
    ) {
        return Ok(Err(policy::refusal(&denial)));
    }
    if let Err(denial) = fa_policy::current(&capability, db.frontier()?) {
        return Ok(Err(policy::refusal(&denial)));
    }
    if let Err(refusal) = policy::capability_admitted(db, book, &capability)? {
        return Ok(Err(refusal));
    }
    let certificate = plan.certificate();
    let commitment = capability
        .commitment()
        .map_err(|e| KernelError::Corrupt(format!("capability commitment: {e}")))?;
    if certificate.book_id != book.book_id
        || certificate.branch_id != Id128::TRUNK
        || certificate.principal != capability.holder()
        || certificate.capability_commitment != commitment
        || certificate.expires_at != capability.expires_at()
    {
        return Ok(Err(invalidated(
            "the plan belongs to a different coordinate or acting capability",
        )));
    }
    if !same_tag(
        &authentication(book, certificate)?,
        &certificate.authentication,
    ) {
        return Ok(Err(invalidated(
            "the plan was not issued by this book or its authenticated fields changed",
        )));
    }
    match recorded_plan(db, book, &plan)? {
        Err(refusal) => return Ok(Err(refusal)),
        Ok(Some(posted)) => return Ok(Ok(posted)),
        Ok(None) => {}
    }
    if db.frontier()? != certificate.snapshot_seq {
        return Ok(Err(invalidated(format!(
            "the plan's basis {} is no longer the current committed prefix",
            certificate.snapshot_seq.0,
        ))));
    }
    let mut prepared = match prepare_post(db, ctx, book, request(plan.intent(), capability))? {
        Err(refusal) => {
            return Ok(Err(invalidated(format!(
                "production revalidation refused the plan: {} ({})",
                refusal.message, refusal.code,
            ))));
        }
        Ok(PostPreparation::AlreadyRecorded(_)) => {
            return Ok(Err(invalidated(
                "the identity was recorded without this plan's verified retaining evidence",
            )));
        }
        Ok(PostPreparation::Ready(prepared)) => prepared,
    };
    if prepared.basis() != certificate.snapshot_seq
        || prepared.security_policy_epoch() != certificate.security_policy_epoch
        || prepared.period() != certificate.period
        || prepared.entry() != plan.prepared_entry()
        || prepared.effects_digest()? != certificate.effects_digest
    {
        prepared.abort();
        return Ok(Err(invalidated(
            "the current production transaction does not reproduce the planned proposal, policy, period, or native effects",
        )));
    }
    let evid = match planned_entry_vid(&plan) {
        Ok(vid) => vid,
        Err(refusal) => {
            prepared.abort();
            return Ok(Err(refusal));
        }
    };
    let digest = certificate.digest().map_err(codec)?;
    let cvid = plan_certificate_vid(book.book_id, &digest);
    if db.vertex(cvid)?.is_some() {
        prepared.abort();
        return Ok(Err(invalidated(
            "the plan certificate locator is already occupied without its atomic Entry outcome",
        )));
    }
    let mut batch = WriteBatch::new(relation::CITES);
    batch.create_vertex(
        cvid,
        vec![label::CERTIFICATE],
        retention_props(book, &plan)?,
    );
    batch.add_edge(edge_id(relation::CITES, evid, cvid), evid, cvid, vec![]);
    prepared.retain_plan(db, batch)?;
    // No await or re-read/replan occurs between the effect comparison and
    // publication; &mut Database holds the single-writer handle throughout.
    match prepared.commit(db, ctx).await? {
        Err(refusal) if refusal.exit == exit::CONFLICT => Ok(Err(invalidated(refusal.message))),
        Ok(Posted::AlreadyRecorded { .. }) => match recorded_plan(db, book, &plan)? {
            Err(refusal) => Ok(Err(refusal)),
            Ok(Some(posted)) => Ok(Ok(posted)),
            Ok(None) => Ok(Err(invalidated(
                "a publication race did not retain this exact plan outcome",
            ))),
        },
        other => Ok(other),
    }
}
