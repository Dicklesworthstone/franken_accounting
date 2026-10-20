//! A complete review view of one certified run, with one native history scan.
//! No current-status cache or per-finding query can hide a retired last decision.

use std::collections::BTreeMap;

use super::*;

mod batch;
pub(super) use batch::{prepare, publish};

pub const MAX_RUN_REVIEW_DECISIONS: usize = 8192;
pub const MAX_RUN_REVIEW_NOTE_BYTES: usize = 8 * 1024 * 1024;

/// Original observations plus every selected decision, in certified occurrence
/// order. An empty run is explicit. This is not a global book inventory or a
/// claim that a reviewer's explanation is true. Public fields are output only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingRunReviewHistory {
    pub run: RecordedFindings,
    pub known_at: CommitSeq,
    pub checked_through: CommitSeq,
    pub histories: Vec<FindingReviewHistory>,
}

#[derive(Default)]
struct ReviewBudget {
    decisions: usize,
    note_bytes: usize,
}

impl ReviewBudget {
    fn admit(&mut self, note_bytes: usize) -> Result<(), Refusal> {
        let decisions = self.decisions.checked_add(1);
        let notes = self.note_bytes.checked_add(note_bytes);
        if decisions.is_none_or(|n| n > MAX_RUN_REVIEW_DECISIONS)
            || notes.is_none_or(|n| n > MAX_RUN_REVIEW_NOTE_BYTES)
        {
            return Err(invalid(
                "complete run review history exceeds its aggregate bound; no partial result",
            ));
        }
        self.decisions += 1;
        self.note_bytes += note_bytes;
        Ok(())
    }
}

type Histories = (CommitSeq, CommitSeq, Vec<FindingReviewHistory>);

/// Apply the single-occurrence reader's integrity checks to the full run. All
/// selected decisions, even those after the requested cutoff, are validated
/// before historical filtering. Complete native history is scanned only once.
pub(super) fn read_many<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    findings: Vec<RecordedFinding>,
    published: CommitSeq,
    selected: Option<CommitSeq>,
) -> Outcome<Histories> {
    let head = db.frontier().map_err(KernelError::from)?;
    let at = selected.unwrap_or(head);
    if at > head || at < published {
        return Ok(Err(refused(
            "review selector must lie between finding publication and the current frontier",
        )));
    }
    if findings.len() > MAX_RECORDED_FINDINGS {
        return Ok(Err(invalid("run exceeds its complete-finding bound")));
    }
    let mut index = BTreeMap::new();
    for (ordinal, finding) in findings.iter().enumerate() {
        if finding.recorded_at != published || index.insert(finding.finding_vid, ordinal).is_some()
        {
            return Ok(Err(invalid(
                "run review selection has repeated or mismatched occurrences",
            )));
        }
    }
    let mut histories: Vec<_> = findings
        .into_iter()
        .map(|finding| FindingReviewHistory {
            finding,
            known_at: at,
            checked_through: head,
            reviews: Vec::new(),
        })
        .collect();
    let births = fa_journal::finding_history::finding_births(db, cx, head)?;
    let mut budget = ReviewBudget::default();
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
            Ok(body) => body,
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
        let Some(&position) = index.get(&body.request.finding_vid) else {
            continue;
        };
        let history = &mut histories[position];
        let finding = &history.finding;
        if body.certificate != finding.certificate_digest
            || body.principal == finding.producer
            || born <= finding.recorded_at
        {
            return Ok(Err(invalid(
                "finding review source, reviewer or publication is inconsistent",
            )));
        }
        if history.reviews.len() >= MAX_FINDING_REVIEWS {
            return Ok(Err(invalid(
                "review history exceeds its complete-chain bound",
            )));
        }
        if let Err(r) = budget.admit(body.request.note.len()) {
            return Ok(Err(r));
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
        history.reviews.push(body.result(born));
    }
    for history in &mut histories {
        history.reviews.sort_by_key(|decision| decision.ordinal);
        let mut previous = None;
        let mut previous_at = history.finding.recorded_at;
        let mut dismissed = false;
        for (ordinal, review) in history.reviews.iter().enumerate() {
            cx.query().checkpoint().map_err(BookError::Context)?;
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
        history.reviews.retain(|review| review.recorded_at <= at);
    }
    Ok(Ok((head, at, histories)))
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Replay one entire recorded run, then verify its complete human decision
    /// histories at a single native cutoff. Read-only, current whole-book scope;
    /// every observation is included, including never-reviewed occurrences.
    pub async fn finding_run_review_history(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &[u8; 32],
        known_at: Option<CommitSeq>,
    ) -> Outcome<FindingRunReviewHistory> {
        if let Err(r) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(r));
        }
        if let Err(r) = self
            .prepare_retained_procedure_history(cx, principal, capability, certificate)
            .await?
        {
            return Ok(Err(r));
        }
        if let Err(r) = fa_journal::scratch::ensure_history(&mut self.db, cx).await? {
            return Ok(Err(r));
        }
        let run = match self
            .read_findings(cx, principal, capability, certificate)
            .await?
        {
            Ok(run) => run,
            Err(r) => return Ok(Err(r)),
        };
        if run.finding_ids.len() != run.report.findings.len() {
            return Ok(Err(invalid(
                "finding run occurrence coverage differs from its certificate",
            )));
        }
        let findings = run
            .finding_ids
            .iter()
            .zip(&run.report.findings)
            .enumerate()
            .map(|(ordinal, (&finding_vid, finding))| RecordedFinding {
                finding_vid,
                run_vid: run.run_vid,
                certificate_digest: run.certificate_digest,
                ordinal: ordinal as u32,
                recorded_at: run.recorded_at,
                producer: run.producer,
                coordinate: run.report.coordinate,
                finding: finding.clone(),
            })
            .collect();
        let checked = self.query(cx, |db, book| {
            read_many(db, cx, book, findings, run.recorded_at, known_at)
        })?;
        if let Err(r) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(r));
        }
        Ok(checked.map(
            |(checked_through, known_at, histories)| FindingRunReviewHistory {
                run,
                known_at,
                checked_through,
                histories,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_review_bounds_are_checked_before_acceptance_without_truncation() {
        let mut count = ReviewBudget::default();
        for _ in 0..MAX_RUN_REVIEW_DECISIONS {
            count.admit(0).unwrap();
        }
        assert!(count.admit(0).is_err());
        assert_eq!(count.decisions, MAX_RUN_REVIEW_DECISIONS);
        let mut notes = ReviewBudget::default();
        notes.admit(MAX_RUN_REVIEW_NOTE_BYTES).unwrap();
        assert!(notes.admit(1).is_err());
        assert_eq!(notes.note_bytes, MAX_RUN_REVIEW_NOTE_BYTES);
        assert_eq!(notes.decisions, 1);
    }
}
