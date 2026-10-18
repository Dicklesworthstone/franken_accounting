//! Append-only human decisions over replay-backed Finding occurrences.
//!
//! The original observation and its workpaper never change. A reviewer must
//! currently hold whole-book read and approve authority, must be Human, and
//! must differ from the certificate producer. Decisions occupy deterministic
//! per-finding slots. An explicit predecessor prevents lost updates; an exact
//! retry returns that original decision even after subsequent reviews.
//!
//! This first review format supports acknowledgement, evidence-backed dismissal
//! and explicit reopening. Escalation is not inferred without a native case
//! lifecycle. Capability bindings describe the admitted writer, not an external
//! signature, proof of reviewer identity, or the truth of their explanation.

use super::*;
use fa_model::{Oid, Reader};
use fa_policy::Profile;

pub const FINDING_REVIEW_FORMAT: &[u8] = b"fa:finding-review:v1";
pub const MAX_FINDING_REVIEWS: usize = 256;
pub const MAX_REVIEW_NOTE_BYTES: usize = 2048;
pub const MAX_REVIEW_EVIDENCE: usize = 16;
pub const MAX_REVIEW_BYTES: usize = 4096;

/// Stable reason tags pinned in registries/finding_storage.toml, not assertions
/// that the cited facts are true. Every dismissal also requires retained evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum DismissalReason {
    Explained = 1,
    Duplicate = 2,
    DataQuality = 3,
    OutsideScope = 4,
    Other = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingReviewAction {
    Acknowledge,
    Dismiss(DismissalReason),
    Reopen,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingReviewRequest {
    pub finding_vid: VId,
    /// None asserts that this occurrence has never been reviewed. Otherwise
    /// name the exact last review you observed, not the Finding itself.
    pub expected_previous: Option<VId>,
    pub action: FindingReviewAction,
    /// A bounded human explanation, retained as book-protected UTF-8 data.
    pub note: String,
    /// Strictly sorted unique Document OIds; dismissal requires at least one.
    /// References bind verified document records; this is not a blob export.
    pub evidence: Vec<Oid>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingReviewStatus {
    Open,
    Reviewed,
    Dismissed {
        reason: DismissalReason,
        principal: VId,
    },
}

/// An immutable recorded decision. Native commit time is never caller supplied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingReview {
    pub review_vid: VId,
    pub ordinal: u32,
    pub recorded_at: CommitSeq,
    pub principal: VId,
    pub capability_commitment: [u8; 32],
    pub request: FindingReviewRequest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingReviewHistory {
    pub finding: RecordedFinding,
    /// Inclusive historical selector for the returned decisions.
    pub known_at: CommitSeq,
    /// Complete native history was checked through this current frontier too;
    /// a historical selector cannot hide a subsequently damaged review record.
    pub checked_through: CommitSeq,
    pub reviews: Vec<FindingReview>,
}

impl FindingReviewHistory {
    #[must_use]
    pub fn status(&self) -> FindingReviewStatus {
        match self.reviews.last() {
            None => FindingReviewStatus::Open,
            Some(review) => match review.request.action {
                FindingReviewAction::Acknowledge => FindingReviewStatus::Reviewed,
                FindingReviewAction::Reopen => FindingReviewStatus::Open,
                FindingReviewAction::Dismiss(reason) => FindingReviewStatus::Dismissed {
                    reason,
                    principal: review.principal,
                },
            },
        }
    }

    #[must_use]
    pub fn latest_review(&self) -> Option<VId> {
        self.reviews.last().map(|review| review.review_vid)
    }
}

fn refused(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §11.8; registries/finding_storage.toml [review]",
        "supply a nonempty explanation, the exact previous review, and sorted retained evidence for a dismissal",
    )
}

fn conflict() -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::CONFLICT,
        exit::CONFLICT,
        "the finding has a different review successor than the one requested",
        "FA-INV-10/11; explicit finding-review predecessor",
        "read the complete current review history, then explicitly decide against its latest review; do not silently replace another decision",
    )
}

fn check_request(request: &FindingReviewRequest) -> Result<(), Refusal> {
    if request.note.trim().is_empty() || request.note.len() > MAX_REVIEW_NOTE_BYTES {
        return Err(refused(
            "review explanation is empty or exceeds its UTF-8 byte bound",
        ));
    }
    if request.evidence.len() > MAX_REVIEW_EVIDENCE
        || !request.evidence.windows(2).all(|pair| pair[0] < pair[1])
        || matches!(request.action, FindingReviewAction::Dismiss(_)) && request.evidence.is_empty()
    {
        return Err(refused(
            "dismissal requires evidence; review evidence must be a bounded strictly sorted unique list",
        ));
    }
    Ok(())
}

#[must_use]
pub fn finding_review_vid(book: Id128, finding: VId, ordinal: u32) -> VId {
    let hash = domain_digest(
        b"fa:vid:finding-review:v1",
        &[&book.0, &finding.0.to_le_bytes(), &ordinal.to_le_bytes()],
    );
    let mut low = [0; 16];
    low.copy_from_slice(&hash[..16]);
    VId(u128::from_le_bytes(low))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Body {
    book: Id128,
    certificate: [u8; 32],
    ordinal: u32,
    principal: VId,
    capability: [u8; 32],
    request: FindingReviewRequest,
}

impl Body {
    fn encode(&self) -> Result<Vec<u8>, Refusal> {
        check_request(&self.request)?;
        if self.ordinal as usize >= MAX_FINDING_REVIEWS {
            return Err(refused(
                "finding review history reached its admitted bound; no partial decision",
            ));
        }
        let mut w = Writer::new();
        w.fixed(FINDING_REVIEW_FORMAT)
            .fixed(&self.book.0)
            .fixed(&self.certificate)
            .u128(self.request.finding_vid.0)
            .u32(self.ordinal)
            .u128(self.principal.0)
            .fixed(&self.capability);
        w.opt(self.request.expected_previous.as_ref(), |w, id| {
            w.u128(id.0);
        });
        match self.request.action {
            FindingReviewAction::Acknowledge => {
                w.u8(1);
            }
            FindingReviewAction::Dismiss(reason) => {
                w.u8(2).u16(reason as u16);
            }
            FindingReviewAction::Reopen => {
                w.u8(3);
            }
        }
        w.str(&self.request.note)
            .list(&self.request.evidence, |w, oid| {
                w.fixed(&oid.0);
            });
        let bytes = encoded(w)?;
        if bytes.len() > MAX_REVIEW_BYTES {
            return Err(refused("review encoding exceeds its native-row bound"));
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_REVIEW_BYTES {
            return Err(invalid("review payload exceeds its byte bound"));
        }
        let rest = bytes
            .strip_prefix(FINDING_REVIEW_FORMAT)
            .ok_or_else(|| invalid("unknown review format"))?;
        let mut r = Reader::new(rest);
        let decoded = (|| -> Result<Self, fa_model::DecodeError> {
            let book = Id128(r.fixed("review book")?);
            let certificate = r.fixed("review certificate")?;
            let finding_vid = VId(r.u128("review finding")?);
            let ordinal = r.u32("review ordinal")?;
            let principal = VId(r.u128("review principal")?);
            let capability = r.fixed("review capability")?;
            let expected_previous =
                r.opt("previous review", |r| Ok(VId(r.u128("previous review")?)))?;
            let action = match r.u8("review action")? {
                1 => FindingReviewAction::Acknowledge,
                2 => FindingReviewAction::Dismiss(match r.u16("dismissal reason")? {
                    1 => DismissalReason::Explained,
                    2 => DismissalReason::Duplicate,
                    3 => DismissalReason::DataQuality,
                    4 => DismissalReason::OutsideScope,
                    5 => DismissalReason::Other,
                    _ => return Err(r.invalid("unregistered dismissal reason")),
                }),
                3 => FindingReviewAction::Reopen,
                tag => return Err(r.bad_tag("review action", tag)),
            };
            let note = r
                .str(MAX_REVIEW_NOTE_BYTES, "review explanation")?
                .to_owned();
            let evidence = r.list(MAX_REVIEW_EVIDENCE, "review evidence", |r| {
                Ok(Oid(r.fixed("review document")?))
            })?;
            r.finish()?;
            Ok(Self {
                book,
                certificate,
                ordinal,
                principal,
                capability,
                request: FindingReviewRequest {
                    finding_vid,
                    expected_previous,
                    action,
                    note,
                    evidence,
                },
            })
        })()
        .map_err(|e| invalid(format!("review payload: {e}")))?;
        if decoded.encode()? != bytes {
            return Err(invalid("noncanonical finding review"));
        }
        Ok(decoded)
    }

    fn id(&self) -> VId {
        finding_review_vid(self.book, self.request.finding_vid, self.ordinal)
    }

    fn result(&self, recorded_at: CommitSeq) -> FindingReview {
        FindingReview {
            review_vid: self.id(),
            ordinal: self.ordinal,
            recorded_at,
            principal: self.principal,
            capability_commitment: self.capability,
            request: self.request.clone(),
        }
    }
}

fn decision_digest(bytes: &[u8]) -> [u8; 32] {
    domain_digest(b"fa:finding-review-record:v1", &[bytes])
}

/// Check references at the original review frontier and now. Document record
/// integrity is verified, but this operation never claims to export blob bytes.
fn check_evidence<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    evidence: &[Oid],
    before: CommitSeq,
    head: CommitSeq,
) -> Outcome<()> {
    for oid in evidence {
        let Some(record) = fa_journal::evidence::document_record(db, oid)? else {
            return Ok(Err(refused("review evidence document is missing")));
        };
        if record.book_id != book.book_id {
            return Ok(Err(refused("review evidence belongs to another book")));
        }
        let id = fa_journal::evidence::document_vid(oid);
        let Some(original) = db.vertex_at(id, before).map_err(KernelError::from)? else {
            return Ok(Err(invalid(
                "review evidence was not retained before the decision",
            )));
        };
        if db.vertex_at(id, head).map_err(KernelError::from)?.as_ref() != Some(&original)
            || original.retired_at.is_some()
        {
            return Ok(Err(invalid(
                "review evidence was rewritten or retired after the decision",
            )));
        }
    }
    Ok(Ok(()))
}

#[derive(Clone, Copy)]
enum ReviewLink {
    Finding,
    Previous,
    Evidence,
}

fn links(body: &Body) -> Vec<(ReviewLink, VId)> {
    let mut links = vec![(ReviewLink::Finding, body.request.finding_vid)];
    if let Some(previous) = body.request.expected_previous {
        links.push((ReviewLink::Previous, previous));
    }
    links.extend(body.request.evidence.iter().map(|oid| {
        (
            ReviewLink::Evidence,
            fa_journal::evidence::document_vid(oid),
        )
    }));
    links
}

fn read_history<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    finding: RecordedFinding,
    selected: Option<CommitSeq>,
) -> Outcome<FindingReviewHistory> {
    let head = db.frontier().map_err(KernelError::from)?;
    let at = selected.unwrap_or(head);
    if at > head || at < finding.recorded_at {
        return Ok(Err(refused(
            "review selector must lie between finding publication and the current frontier",
        )));
    }
    let births = fa_journal::finding_history::finding_births(db, cx, head)?;
    let mut decisions = Vec::new();
    for (id, born) in births {
        cx.query().checkpoint().map_err(BookError::Context)?;
        let row = db
            .vertex_at(id, born)
            .map_err(KernelError::from)?
            .ok_or_else(|| {
                BookError::Kernel(KernelError::Corrupt("missing Finding birth row".into()))
            })?;
        let Some(CanonicalScalar::Bytes(payload)) = prop(&row, property::FA_PAYLOAD) else {
            return Ok(Err(invalid(
                "a Finding-family record lacks canonical bytes",
            )));
        };
        if payload.as_slice().starts_with(FINDING_RUN_FORMAT)
            || payload.as_slice().starts_with(FINDING_RECORD_FORMAT)
        {
            continue;
        }
        let body = match Body::decode(payload.as_slice()) {
            Ok(b) => b,
            Err(r) => return Ok(Err(r)),
        };
        if body.book != book.book_id
            || body.id() != id
            || row.props.len() != 3
            || !matches!(prop(&row, property::BOOK_ID), Some(CanonicalScalar::Bytes(b)) if b.as_slice() == book.book_id.0)
            || !matches!(prop(&row, property::FA_DIGEST), Some(CanonicalScalar::Bytes(b)) if b.as_slice() == decision_digest(payload.as_slice()))
        {
            return Ok(Err(invalid(
                "finding review identity, book or digest differs from its original native record",
            )));
        }
        if body.request.finding_vid != finding.finding_vid {
            continue;
        }
        if body.certificate != finding.certificate_digest
            || body.principal == finding.producer
            || born <= finding.recorded_at
        {
            return Ok(Err(invalid(
                "finding review source, reviewer or publication is inconsistent",
            )));
        }
        let before = CommitSeq(born.0 - 1);
        if let Err(r) = check_evidence(db, book, &body.request.evidence, before, head)? {
            return Ok(Err(r));
        }
        for (kind, target) in links(&body) {
            let rel = match kind {
                ReviewLink::Finding => relation::RESOLVES,
                ReviewLink::Previous => relation::SUPERSEDES,
                ReviewLink::Evidence => relation::CITES,
            };
            let eid = edge_id(rel, id, target);
            let Some(edge) = db.edge_at(eid, head).map_err(KernelError::from)? else {
                return Ok(Err(invalid(
                    "finding review lineage or evidence edge is missing",
                )));
            };
            if edge.entry.src != id
                || edge.entry.dst != target
                || edge.entry.relation != rel
                || edge.entry.created_at != born
                || edge.entry.retired_at.is_some()
                || !edge.props.is_empty()
                || db
                    .edge_at(eid, before)
                    .map_err(KernelError::from)?
                    .is_some()
                || db.edge_at(eid, born).map_err(KernelError::from)?.as_ref() != Some(&edge)
            {
                return Ok(Err(invalid(
                    "finding review edge was rewritten or separately published",
                )));
            }
        }
        if decisions.len() >= MAX_FINDING_REVIEWS {
            return Ok(Err(invalid(
                "review history exceeds its complete-chain bound",
            )));
        }
        decisions.push(body.result(born));
    }
    decisions.sort_by_key(|decision| decision.ordinal);
    let mut previous = None;
    let mut previous_at = finding.recorded_at;
    let mut dismissed = false;
    for (ordinal, review) in decisions.iter().enumerate() {
        if review.ordinal as usize != ordinal
            || review.request.expected_previous != previous
            || review.recorded_at <= previous_at
            || review.request.action == FindingReviewAction::Reopen && !dismissed
            || review.request.action == FindingReviewAction::Acknowledge && dismissed
        {
            return Ok(Err(invalid(
                "finding review history is missing a predecessor or violates its lifecycle",
            )));
        }
        dismissed = matches!(review.request.action, FindingReviewAction::Dismiss(_));
        previous = Some(review.review_vid);
        previous_at = review.recorded_at;
    }
    decisions.retain(|review| review.recorded_at <= at);
    Ok(Ok(FindingReviewHistory {
        finding,
        known_at: at,
        checked_through: head,
        reviews: decisions,
    }))
}

fn authorize_reviewer<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    principal: VId,
    capability: &Capability,
) -> Outcome<()> {
    if let Err(r) = authorize(book, cx, principal, capability, false)? {
        return Ok(Err(r));
    }
    if let Err(d) = fa_policy::admit(
        capability,
        &fa_policy::Intent {
            principal,
            trunk: true,
            op: Op::Approve,
            book: book.context().book_id,
            legs: &[],
        },
    ) {
        return Ok(Err(fa_journal::policy::refusal(&d)));
    }
    if capability.profile() != Profile::Human {
        return Ok(Err(fa_journal::policy::refusal(
            &fa_policy::Denial::ApproverProfile {
                rule: "finding_reviewer".into(),
                approver: principal,
                profile: capability.profile(),
                allowed: vec!["Human".into()],
            },
        )));
    }
    Ok(Ok(()))
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Read the original observation and a complete decision timeline, including
    /// a checked historical status. Loading native history does not publish.
    pub async fn finding_review_history(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        finding: VId,
        known_at: Option<CommitSeq>,
    ) -> Outcome<FindingReviewHistory> {
        if let Err(r) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(r));
        }
        if let Err(r) = fa_journal::scratch::ensure_history(&mut self.db, cx).await? {
            return Ok(Err(r));
        }
        let observation = match self
            .finding_by_vid(cx, principal, capability, finding)
            .await?
        {
            Ok(finding) => finding,
            Err(r) => return Ok(Err(r)),
        };
        let history = self.query(cx, |db, book| {
            read_history(db, cx, book, observation, known_at)
        })?;
        if let Err(r) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(r));
        }
        Ok(history)
    }

    /// Publish one decision and all its references at one native sequence.
    /// An exact predecessor/body/actor/capability retry reuses its original slot;
    /// stale conflicting requests refuse. Existing observations are never edited.
    pub async fn review_finding(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &FindingReviewRequest,
    ) -> Outcome<FindingReview> {
        if let Err(r) = authorize_reviewer(self, cx, principal, capability)? {
            return Ok(Err(r));
        }
        if let Err(r) = check_request(request) {
            return Ok(Err(r));
        }
        let history = match self
            .finding_review_history(cx, principal, capability, request.finding_vid, None)
            .await?
        {
            Ok(h) => h,
            Err(r) => return Ok(Err(r)),
        };
        if history.finding.producer == principal {
            return Ok(Err(fa_journal::policy::refusal(
                &fa_policy::Denial::SelfApproval {
                    rule: "finding_reviewer excludes the procedure certificate producer".into(),
                    approver: principal,
                },
            )));
        }
        let ordinal = match request.expected_previous {
            None => 0,
            Some(previous) => match history
                .reviews
                .iter()
                .position(|review| review.review_vid == previous)
            {
                Some(index) => index + 1,
                None => return Ok(Err(conflict())),
            },
        };
        let body = Body {
            book: self.context().book_id,
            certificate: history.finding.certificate_digest,
            ordinal: ordinal as u32,
            principal,
            capability: capability
                .commitment()
                .map_err(|e| BookError::Kernel(KernelError::Corrupt(e.to_string())))?,
            request: request.clone(),
        };
        let bytes = match body.encode() {
            Ok(bytes) => bytes,
            Err(r) => return Ok(Err(r)),
        };
        if let Some(recorded) = history.reviews.get(ordinal) {
            if *recorded != body.result(recorded.recorded_at) {
                return Ok(Err(conflict()));
            }
            // Recheck current authority even for a no-op historical retry.
            if let Err(r) = authorize_reviewer(self, cx, principal, capability)? {
                return Ok(Err(r));
            }
            return Ok(Ok(recorded.clone()));
        }
        if request.expected_previous != history.latest_review() {
            return Ok(Err(conflict()));
        }
        let dismissed = matches!(history.status(), FindingReviewStatus::Dismissed { .. });
        if request.action == FindingReviewAction::Reopen && !dismissed
            || request.action == FindingReviewAction::Acknowledge && dismissed
        {
            return Ok(Err(refused(
                "only a dismissal can be reopened; acknowledging a dismissed finding requires explicit reopening first",
            )));
        }
        let head = history.checked_through;
        if let Err(r) = self.query(cx, |db, book| {
            check_evidence(db, book, &request.evidence, head, head)
        })? {
            return Ok(Err(r));
        }
        let mut txn = self.db.begin(&cx.txn()).map_err(KernelError::from)?;
        if txn.basis() != head {
            txn.abort();
            return Ok(Err(conflict()));
        }
        if let Err(d) = fa_policy::current(capability, txn.basis()) {
            txn.abort();
            return Ok(Err(fa_journal::policy::refusal(&d)));
        }
        if let Err(r) =
            fa_journal::policy::capability_witness(&txn, &self.db, self.context(), capability)?
        {
            txn.abort();
            return Ok(Err(r));
        }
        fa_journal::policy::epoch_witness(&txn, &self.db)?;
        let id = body.id();
        if txn
            .vertex(&self.db, id)
            .map_err(KernelError::from)?
            .is_some()
        {
            txn.abort();
            return Ok(Err(conflict()));
        }
        let mut props = vec![
            (
                property::FA_PAYLOAD,
                scalar_bytes("review payload", bytes.clone())?,
            ),
            (
                property::FA_DIGEST,
                scalar_bytes("review digest", decision_digest(&bytes).to_vec())?,
            ),
            (
                property::BOOK_ID,
                scalar_bytes("review book", self.context().book_id.0.to_vec())?,
            ),
        ];
        props.sort_by_key(|(key, _)| key.0);
        let mut resolved = WriteBatch::new(relation::RESOLVES);
        resolved.create_vertex(id, vec![label::FINDING], props);
        let mut supersedes = WriteBatch::new(relation::SUPERSEDES);
        let mut citations = WriteBatch::new(relation::CITES);
        for (kind, target) in links(&body) {
            let rel = match kind {
                ReviewLink::Finding => relation::RESOLVES,
                ReviewLink::Previous => relation::SUPERSEDES,
                ReviewLink::Evidence => relation::CITES,
            };
            if txn
                .vertex(&self.db, target)
                .map_err(KernelError::from)?
                .is_none()
            {
                txn.abort();
                return Ok(Err(invalid("review target is no longer retained")));
            }
            let batch = if rel == relation::RESOLVES {
                &mut resolved
            } else if rel == relation::SUPERSEDES {
                &mut supersedes
            } else {
                &mut citations
            };
            batch.add_edge(edge_id(rel, id, target), id, target, vec![]);
        }
        let mut batches = vec![resolved];
        if request.expected_previous.is_some() {
            batches.push(supersedes);
        }
        if !request.evidence.is_empty() {
            batches.push(citations);
        }
        if let Err(e) = txn.write_ordered(&mut self.db, batches) {
            txn.abort();
            return refused_write(e);
        }
        cx.commit().checkpoint().map_err(BookError::Context)?;
        match txn.commit(&mut self.db, &cx.commit()).await {
            Ok(at) => Ok(Ok(body.result(at))),
            Err(e) => refused_write(e),
        }
    }
}
