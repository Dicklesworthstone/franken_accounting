//! One publication path for single decisions and atomic selections from a run.
//! A batch reuses the v1 per-finding records; it does not invent another ledger
//! or claim a saved batch identity. Every returned decision has one native birth.

use super::*;

impl FindingRunReviewHistory {
    /// Admission bound for one atomic review selection. Each decision retains
    /// its existing 2 KiB note / 16-document limits. At most 64 vertices and
    /// 1,152 lineage/evidence edges are staged, in three ordered native batches.
    pub const MAX_BATCH_DECISIONS: usize = 64;
}

pub(in crate::findings::review) struct PreparedReview {
    body: Body,
    bytes: Vec<u8>,
    existing: Option<FindingReview>,
}

/// Both entrypoints apply identical SoD, predecessor, retry and lifecycle law.
pub(in crate::findings::review) fn prepare(
    book: Id128,
    principal: VId,
    capability: &Capability,
    history: &FindingReviewHistory,
    request: &FindingReviewRequest,
) -> Result<PreparedReview, Refusal> {
    check_request(request)?;
    if history.finding.finding_vid != request.finding_vid {
        return Err(invalid(
            "review request does not name its verified observation",
        ));
    }
    if history.finding.producer == principal {
        return Err(fa_journal::policy::refusal(
            &fa_policy::Denial::SelfApproval {
                rule: "finding_reviewer excludes the procedure certificate producer".into(),
                approver: principal,
            },
        ));
    }
    let ordinal = match request.expected_previous {
        None => 0,
        Some(previous) => history
            .reviews
            .iter()
            .position(|review| review.review_vid == previous)
            .map(|index| index + 1)
            .ok_or_else(conflict)?,
    };
    let body = Body {
        book,
        certificate: history.finding.certificate_digest,
        ordinal: u32::try_from(ordinal)
            .map_err(|_| refused("review ordinal exceeds its wire range"))?,
        principal,
        capability: capability
            .commitment()
            .map_err(|e| invalid(format!("review capability: {e}")))?,
        request: request.clone(),
    };
    let bytes = body.encode()?;
    let existing = if let Some(recorded) = history.reviews.get(ordinal) {
        if *recorded != body.result(recorded.recorded_at) {
            return Err(conflict());
        }
        Some(recorded.clone())
    } else {
        if request.expected_previous != history.latest_review() {
            return Err(conflict());
        }
        let dismissed = matches!(history.status(), FindingReviewStatus::Dismissed { .. });
        if request.action == FindingReviewAction::Reopen && !dismissed
            || request.action == FindingReviewAction::Acknowledge && dismissed
        {
            return Err(refused(
                "only a dismissal can be reopened; acknowledging a dismissed finding requires explicit reopening first",
            ));
        }
        None
    };
    Ok(PreparedReview {
        body,
        bytes,
        existing,
    })
}

fn mixed_publication() -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::CONFLICT,
        exit::CONFLICT,
        "atomic review selection mixes new decisions with recorded decisions, or decisions from different publications",
        "plan §11.8; registries/finding_storage.toml [review_batch]",
        "submit only new explicit successors, or retry an exact same-publication selection; existing decisions are never republished to assemble a batch",
    )
}

/// A same-publication retry may select a subset of that publication; it does not
/// assert the original command's batch membership. Mixing old and new rows is
/// refused, rather than turning a requested atomic decision into partial writes.
pub(in crate::findings::review) async fn publish<V: Vfs + Clone, B: Vfs + Clone>(
    book: &mut AsyncBook<V, B>,
    cx: &PurposeContexts,
    principal: VId,
    capability: &Capability,
    head: CommitSeq,
    prepared: Vec<PreparedReview>,
) -> Outcome<Vec<FindingReview>> {
    if let Err(r) = authorize_reviewer(book, cx, principal, capability)? {
        return Ok(Err(r));
    }
    if prepared.is_empty() || prepared.len() > FindingRunReviewHistory::MAX_BATCH_DECISIONS {
        return Ok(Err(refused(
            "atomic review requires 1..=64 decisions; no partial publication",
        )));
    }
    let mut unique = BTreeSet::new();
    if prepared
        .iter()
        .any(|p| !unique.insert(p.body.request.finding_vid))
    {
        return Ok(Err(refused(
            "atomic review repeats a finding; one explicit decision per occurrence is required",
        )));
    }
    let recorded: Vec<_> = prepared
        .iter()
        .filter_map(|p| p.existing.as_ref())
        .collect();
    if let Some(first) = recorded.first() {
        if recorded.len() != prepared.len()
            || recorded.iter().any(|r| r.recorded_at != first.recorded_at)
        {
            return Ok(Err(mixed_publication()));
        }
        return Ok(Ok(recorded.into_iter().cloned().collect()));
    }
    // Validate shared document references once, before any write is staged.
    let evidence: Vec<_> = prepared
        .iter()
        .flat_map(|p| &p.body.request.evidence)
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if let Err(r) = book.query(cx, |db, context| {
        check_evidence(db, context, &evidence, head, head)
    })? {
        return Ok(Err(r));
    }
    let mut txn = book.db.begin(&cx.txn()).map_err(KernelError::from)?;
    if txn.basis() != head {
        txn.abort();
        return Ok(Err(conflict()));
    }
    if let Err(d) = fa_policy::current(capability, txn.basis()) {
        txn.abort();
        return Ok(Err(fa_journal::policy::refusal(&d)));
    }
    if let Err(r) =
        fa_journal::policy::capability_witness(&txn, &book.db, book.context(), capability)?
    {
        txn.abort();
        return Ok(Err(r));
    }
    fa_journal::policy::epoch_witness(&txn, &book.db)?;
    let mut resolved = WriteBatch::new(relation::RESOLVES);
    let mut supersedes = WriteBatch::new(relation::SUPERSEDES);
    let mut citations = WriteBatch::new(relation::CITES);
    let mut has_previous = false;
    for prepared in &prepared {
        cx.txn().checkpoint().map_err(BookError::Context)?;
        let body = &prepared.body;
        let id = body.id();
        if txn
            .vertex(&book.db, id)
            .map_err(KernelError::from)?
            .is_some()
        {
            txn.abort();
            return Ok(Err(conflict()));
        }
        let mut props = vec![
            (
                property::FA_PAYLOAD,
                scalar_bytes("review payload", prepared.bytes.clone())?,
            ),
            (
                property::FA_DIGEST,
                scalar_bytes("review digest", decision_digest(&prepared.bytes).to_vec())?,
            ),
            (
                property::BOOK_ID,
                scalar_bytes("review book", book.context().book_id.0.to_vec())?,
            ),
        ];
        props.sort_by_key(|(key, _)| key.0);
        resolved.create_vertex(id, vec![label::FINDING], props);
        for (kind, target) in links(body) {
            if txn
                .vertex(&book.db, target)
                .map_err(KernelError::from)?
                .is_none()
            {
                txn.abort();
                return Ok(Err(invalid("review target is no longer retained")));
            }
            let (batch, rel) = match kind {
                ReviewLink::Finding => (&mut resolved, relation::RESOLVES),
                ReviewLink::Previous => {
                    has_previous = true;
                    (&mut supersedes, relation::SUPERSEDES)
                }
                ReviewLink::Evidence => (&mut citations, relation::CITES),
            };
            batch.add_edge(edge_id(rel, id, target), id, target, vec![]);
        }
    }
    let mut batches = vec![resolved];
    if has_previous {
        batches.push(supersedes);
    }
    if !evidence.is_empty() {
        batches.push(citations);
    }
    if let Err(e) = txn.write_ordered(&mut book.db, batches) {
        txn.abort();
        return refused_write(e);
    }
    cx.commit().checkpoint().map_err(BookError::Context)?;
    match txn.commit(&mut book.db, &cx.commit()).await {
        Ok(at) => Ok(Ok(prepared.iter().map(|p| p.body.result(at)).collect())),
        Err(e) => refused_write(e),
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Review an explicit selection from ONE retained, replayed finding run in
    /// one native transaction. The original certificate, observations and
    /// workpaper are never modified. Result order is certified occurrence order,
    /// independent of request order. A run need not be reviewed in its entirety.
    ///
    /// Each request names its observed predecessor. Duplicate/foreign findings,
    /// failed evidence, SoD, lifecycle or authority checks refuse the WHOLE set.
    /// All-new decisions share one publication. All-existing exact decisions
    /// must already share a publication; mixed old/new selections refuse. This
    /// returns per-finding history, not a separately journaled batch identity.
    pub async fn review_finding_run(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &[u8; 32],
        requests: &[FindingReviewRequest],
    ) -> Outcome<Vec<FindingReview>> {
        // Admission precedes untrusted request inspection and source discovery.
        if let Err(r) = authorize_reviewer(self, cx, principal, capability)? {
            return Ok(Err(r));
        }
        if requests.is_empty() || requests.len() > FindingRunReviewHistory::MAX_BATCH_DECISIONS {
            return Ok(Err(refused(
                "atomic review requires 1..=64 decisions; no partial publication",
            )));
        }
        let mut selected = BTreeMap::new();
        for request in requests {
            if let Err(r) = check_request(request) {
                return Ok(Err(r));
            }
            if selected.insert(request.finding_vid, request).is_some() {
                return Ok(Err(refused(
                    "atomic review repeats a finding; one explicit decision per occurrence is required",
                )));
            }
        }
        // One source replay and one complete Finding-history scan for the run,
        // rather than one replay/scan for each selected occurrence.
        let history = match self
            .finding_run_review_history(cx, principal, capability, certificate, None)
            .await?
        {
            Ok(history) => history,
            Err(r) => return Ok(Err(r)),
        };
        let mut prepared = Vec::with_capacity(requests.len());
        for occurrence in &history.histories {
            let Some(request) = selected.remove(&occurrence.finding.finding_vid) else {
                continue;
            };
            match prepare(
                self.context().book_id,
                principal,
                capability,
                occurrence,
                request,
            ) {
                Ok(decision) => prepared.push(decision),
                Err(r) => return Ok(Err(r)),
            }
        }
        if !selected.is_empty() {
            return Ok(Err(refused(
                "atomic review contains a finding outside the named complete run",
            )));
        }
        publish(
            self,
            cx,
            principal,
            capability,
            history.checked_through,
            prepared,
        )
        .await
    }
}
