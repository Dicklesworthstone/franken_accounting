//! Rehearse a reviewed close graph against one captured trunk prefix (§7.5).
//!
//! Each unfinished draft is applied, atomically and in deterministic dependency
//! order, to the preceding scratch result. This exposes interactions that a
//! collection of independent draft reviews cannot detect. Every original review
//! is replayed first, and the combined rehearsal must preserve its exact native
//! entry identities and amounts. Source Certificate vertices are never copied
//! into scratch, and scratch results never claim the source database's identity.
//!
//! A period transition remains explicitly awaiting its native review and any
//! independent approvals. This certificate proves the combined monetary review;
//! it is neither a promotion permission nor a claim that the close completed.

use std::collections::BTreeSet;

use fa_journal::close_run::{CloseRunView, CloseTaskReceipt};
use fa_journal::draft::DraftRehearsalStep;
use fa_journal::{Refusal, exit};
use fa_model::{
    CloseRunBody, CloseTaskBody, CloseTaskBodyAction, EntryRef, Id128, Reader, Writer,
    close_run_vid, domain_digest,
};
use fa_policy::{Capability, Op, Reach};
use fa_registers::TrialBalance;
use fgdb_types::{CommitSeq, VId};

use crate::{
    Book, DraftDiff, DraftDiffCertificate, DraftDiffRow, Outcome, ReportArtifactFamily,
    ReportCertificate, ReportOutput, ReportSelection, TrialBalanceSelection,
};

pub const CLOSE_RUN_REHEARSAL_CERTIFICATE_FORMAT: &[u8] = b"fa:close-run-rehearsal-certificate:v1";
pub const CLOSE_RUN_REHEARSAL_OUTPUT_FORMAT: &str = "fa:close-run-rehearsal:v1";
pub const MAX_CLOSE_RUN_REHEARSAL_CERTIFICATE_BYTES: usize =
    crate::certificate::MAX_CERTIFICATE_BYTES;
const DIGEST_DOMAIN: &[u8] = b"fa:close-run-rehearsal-certificate-digest:v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseTaskRehearsalOutcome {
    /// An original, authenticated native effect already present at the source
    /// prefix. It is included in the baseline and is never applied twice.
    AlreadyCompleted(CloseTaskReceipt),
    /// A hypothetical native batch, in this rehearsal's own scratch database.
    Rehearsed {
        batch_outcome: VId,
        recorded_at: CommitSeq,
        entries: Vec<EntryRef>,
    },
    /// No period state was changed. Live execution still requires the native
    /// transition plan and its independent approval references.
    AwaitingNativeTransitionReview { to: u8 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseTaskRehearsal {
    pub id: String,
    pub outcome: CloseTaskRehearsalOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseRunRehearsal {
    pub name: String,
    pub run: VId,
    pub body_digest: [u8; 32],
    pub period: String,
    pub opened_at: CommitSeq,
    pub source_known_at: CommitSeq,
    /// The original source-to-scratch map. Every task then runs in this one
    /// owned database; hypothetical markers never replace original evidence.
    pub seq_map_digest: Option<[u8; 32]>,
    pub rehearsal_known_at: CommitSeq,
    /// True only when every task had an authenticated trunk receipt at the
    /// captured prefix. Successful hypothetical batches never set this flag.
    pub complete_on_trunk: bool,
    /// Original completion receipts first, by task id; unfinished tasks then
    /// select the lexicographically first ready id, as live execution does.
    pub tasks: Vec<CloseTaskRehearsal>,
    /// One native unit per row; posted and pending effects remain separate.
    pub rows: Vec<DraftDiffRow>,
}

/// The complete original graph and retained draft reviews, bound to the native
/// baseline and the exact combined output. Container integrity is not replay.
/// Producer and capability metadata are unsigned provenance, never authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseRunRehearsalCertificate {
    trunk: ReportCertificate,
    body: CloseRunBody,
    opened_at: CommitSeq,
    /// The graph's draft tasks in its canonical task-id order.
    reviews: Vec<DraftDiffCertificate>,
    producer: VId,
    capability_commitment: [u8; 32],
    output: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedCloseRunRehearsal {
    pub report: CloseRunRehearsal,
    pub certificate: CloseRunRehearsalCertificate,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §7.5 (a complete close rehearsal preserves its reviewed graph and native effects)",
        "replay the original certificate in its book, or review the complete current close run again",
    )
}

fn encoded(error: impl std::fmt::Display) -> Refusal {
    invalid(error.to_string())
}

fn in_task(id: &str, refusal: Refusal) -> Refusal {
    Refusal {
        message: format!("close rehearsal task `{id}`: {}", refusal.message),
        ..refusal
    }
    .at("task", id)
}

fn authorize(book: &Book, principal: VId, capability: &Capability, produce: bool) -> Outcome<()> {
    if let Err(refusal) = book.read_scope(principal, capability)? {
        return Ok(Err(refusal));
    }
    // The original lifecycle and retained review mirrors are validated through
    // current history even when replay selects an older monetary prefix.
    let result = fa_policy::reach(capability, &Reach::whole_book(true), None).and_then(|()| {
        if produce {
            fa_policy::require(
                capability,
                Op::Produce,
                "certifying a complete close rehearsal",
            )
        } else {
            Ok(())
        }
    });
    Ok(result.map_err(|denial| fa_journal::policy::refusal(&denial)))
}

fn entries_digest(entries: &[EntryRef]) -> Result<[u8; 32], Refusal> {
    let mut w = Writer::new();
    w.list(entries, |w, entry| entry.encode(w));
    Ok(domain_digest(
        b"fa:close-task-entries:v1",
        &[&w.finish().map_err(encoded)?],
    ))
}

fn check_review(
    body: &CloseRunBody,
    task: &CloseTaskBody,
    certificate: &DraftDiffCertificate,
    report: Option<&DraftDiff>,
) -> Result<(), Refusal> {
    let CloseTaskBodyAction::PromoteDraft {
        draft,
        name,
        owner,
        source_known_at,
        source_digest,
        certificate_digest,
        entries_digest: expected_entries,
        entry_count,
    } = &task.action
    else {
        return Err(invalid(
            "a non-draft close task cannot carry a draft review",
        ));
    };
    let source = certificate.source();
    if certificate.digest() != certificate_digest
        || certificate.period() != body.period
        || source.body.book_id != body.book_id
        || source.body.vid() != *draft
        || source.body.name != *name
        || source.body.owner != *owner
        || source.known_at != *source_known_at
        || source.digest().map_err(encoded)? != *source_digest
    {
        return Err(invalid(
            "the retained draft review differs from the immutable close task",
        ));
    }
    if let Some(report) = report
        && (report.entries.len() != *entry_count as usize
            || entries_digest(&report.entries)? != *expected_entries)
    {
        return Err(invalid(
            "the replayed review does not contain the complete bound effects",
        ));
    }
    Ok(())
}

impl CloseRunRehearsal {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        if self.name.is_empty()
            || self.name.len() > fa_model::limits::MAX_CLOSE_RUN_TEXT_BYTES
            || self.period.is_empty()
            || self.period.len() > fa_model::limits::MAX_CLOSE_RUN_TEXT_BYTES
            || self.opened_at.0 == 0
            || self.opened_at > self.source_known_at
            || self.tasks.is_empty()
            || self.tasks.len() > fa_model::limits::MAX_CLOSE_RUN_TASKS
            || self.rows.len() > crate::draft_review::MAX_DRAFT_DIFF_ROWS
        {
            return Err(invalid(
                "the close rehearsal exceeds or contradicts its source bounds",
            ));
        }
        let mut task_ids = BTreeSet::new();
        let mut next = self.source_known_at;
        let mut rehearsed = false;
        let mut all_completed = true;
        for task in &self.tasks {
            if task.id.is_empty()
                || task.id.len() > fa_model::limits::MAX_CLOSE_RUN_TEXT_BYTES
                || !task_ids.insert(&task.id)
            {
                return Err(invalid(
                    "close rehearsal task ids must be bounded and distinct",
                ));
            }
            match &task.outcome {
                CloseTaskRehearsalOutcome::AlreadyCompleted(receipt) => {
                    if receipt.recorded_at < self.opened_at
                        || receipt.recorded_at > self.source_known_at
                    {
                        return Err(invalid(
                            "a completed task is outside the captured source prefix",
                        ));
                    }
                }
                CloseTaskRehearsalOutcome::Rehearsed {
                    recorded_at,
                    entries,
                    ..
                } => {
                    next = CommitSeq(
                        next.0
                            .checked_add(1)
                            .ok_or_else(|| invalid("rehearsal sequence overflow"))?,
                    );
                    if *recorded_at != next
                        || entries.is_empty()
                        || entries.len() > fa_model::limits::MAX_BATCH_ENTRIES
                        || entries
                            .iter()
                            .map(|entry| entry.vid)
                            .collect::<BTreeSet<_>>()
                            .len()
                            != entries.len()
                    {
                        return Err(invalid(
                            "each rehearsed task needs one fresh, complete native batch",
                        ));
                    }
                    rehearsed = true;
                    all_completed = false;
                }
                CloseTaskRehearsalOutcome::AwaitingNativeTransitionReview { to } => {
                    if !matches!(*to, 2..=4) {
                        return Err(invalid(
                            "the pending native transition has an unsupported state",
                        ));
                    }
                    all_completed = false;
                }
            }
        }
        if self.rehearsal_known_at != next
            || self.seq_map_digest.is_some() != rehearsed
            || self.complete_on_trunk != all_completed
        {
            return Err(invalid(
                "the close result confuses hypothetical work with committed completion",
            ));
        }
        let mut w = Writer::new();
        w.str(CLOSE_RUN_REHEARSAL_OUTPUT_FORMAT)
            .str(&self.name)
            .u128(self.run.0)
            .fixed(&self.body_digest)
            .str(&self.period)
            .u64(self.opened_at.0)
            .u64(self.source_known_at.0)
            .opt(self.seq_map_digest.as_ref(), |w, digest| {
                w.fixed(digest);
            })
            .u64(self.rehearsal_known_at.0)
            .bool(self.complete_on_trunk)
            .list(&self.tasks, |w, task| {
                w.str(&task.id);
                match &task.outcome {
                    CloseTaskRehearsalOutcome::AlreadyCompleted(receipt) => {
                        w.u8(0)
                            .u128(receipt.record.0)
                            .u128(receipt.effect.0)
                            .u64(receipt.recorded_at.0)
                            .u128(receipt.principal.0);
                    }
                    CloseTaskRehearsalOutcome::Rehearsed {
                        batch_outcome,
                        recorded_at,
                        entries,
                    } => {
                        w.u8(1)
                            .u128(batch_outcome.0)
                            .u64(recorded_at.0)
                            .list(entries, |w, entry| entry.encode(w));
                    }
                    CloseTaskRehearsalOutcome::AwaitingNativeTransitionReview { to } => {
                        w.u8(2).u8(*to);
                    }
                }
            })
            .list(&self.rows, |w, row| {
                w.u128(row.account.0)
                    .str(&row.code)
                    .str(&row.name)
                    .u32(row.unit_id)
                    .i128(row.trunk_debits)
                    .i128(row.trunk_credits)
                    .i128(row.draft_debits)
                    .i128(row.draft_credits)
                    .i128(row.delta)
                    .i128(row.trunk_debits_pending)
                    .i128(row.trunk_credits_pending)
                    .i128(row.draft_debits_pending)
                    .i128(row.draft_credits_pending)
                    .i128(row.pending_delta);
            });
        let bytes = w.finish().map_err(encoded)?;
        if bytes.len() > MAX_CLOSE_RUN_REHEARSAL_CERTIFICATE_BYTES {
            return Err(invalid("the complete close output exceeds 64 MiB"));
        }
        Ok(bytes)
    }
}

impl CloseRunRehearsalCertificate {
    fn body_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut w = Writer::new();
        w.bytes(CLOSE_RUN_REHEARSAL_CERTIFICATE_FORMAT)
            .bytes(&self.trunk.canonical_bytes().map_err(encoded)?)
            .bytes(&self.body.canonical_bytes().map_err(encoded)?)
            .u64(self.opened_at.0)
            .u32(u32::try_from(self.reviews.len()).map_err(encoded)?);
        for review in &self.reviews {
            let bytes = review.canonical_bytes()?;
            if w.len()
                .saturating_add(bytes.len())
                .saturating_add(self.output.len())
                .saturating_add(128)
                > MAX_CLOSE_RUN_REHEARSAL_CERTIFICATE_BYTES
            {
                return Err(invalid("the complete close certificate exceeds 64 MiB"));
            }
            w.bytes(&bytes);
        }
        w.u128(self.producer.0)
            .fixed(&self.capability_commitment)
            .bytes(&self.output);
        let bytes = w.finish().map_err(encoded)?;
        if bytes.len().saturating_add(32) > MAX_CLOSE_RUN_REHEARSAL_CERTIFICATE_BYTES {
            return Err(invalid("the complete close certificate exceeds 64 MiB"));
        }
        Ok(bytes)
    }

    fn validate(&self) -> Result<(), Refusal> {
        self.body.validate().map_err(encoded)?;
        if self.body.book_id != self.trunk.book_id
            || self.trunk.branch_id != Id128::TRUNK
            || self.trunk.time_selection.is_some()
            || self.opened_at.0 == 0
            || self.opened_at > self.trunk.known_at
            || !matches!(&self.trunk.selection,
                ReportSelection::TrialBalance(TrialBalanceSelection::Periods(periods))
                    if periods.len() == 1 && periods[0] == self.body.period)
        {
            return Err(invalid(
                "the close graph and native baseline select different coordinates",
            ));
        }
        let tasks: Vec<_> = self
            .body
            .tasks
            .iter()
            .filter(|task| matches!(task.action, CloseTaskBodyAction::PromoteDraft { .. }))
            .collect();
        if tasks.len() != self.reviews.len() {
            return Err(invalid(
                "the close certificate must retain every original draft review",
            ));
        }
        for (task, review) in tasks.into_iter().zip(&self.reviews) {
            check_review(&self.body, task, review, None)?;
            if review.known_at() > self.opened_at {
                return Err(invalid(
                    "a close task review cannot postdate its declaration",
                ));
            }
        }
        if domain_digest(DIGEST_DOMAIN, &[&self.body_bytes()?]) != self.digest {
            return Err(invalid("close rehearsal certificate digest mismatch"));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut bytes = self.body_bytes()?;
        bytes.extend_from_slice(&self.digest);
        Ok(bytes)
    }

    /// Canonical decoding checks bounded container integrity. Historical graph,
    /// sources, native effects and every output byte are checked by replay.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_CLOSE_RUN_REHEARSAL_CERTIFICATE_BYTES {
            return Err(invalid("the complete close certificate exceeds 64 MiB"));
        }
        let mut r = Reader::new(bytes);
        if r.bytes(64, "close rehearsal format").map_err(encoded)?
            != CLOSE_RUN_REHEARSAL_CERTIFICATE_FORMAT
        {
            return Err(invalid("not a supported close rehearsal certificate"));
        }
        let trunk = ReportCertificate::decode(
            r.bytes(
                MAX_CLOSE_RUN_REHEARSAL_CERTIFICATE_BYTES,
                "close rehearsal trunk",
            )
            .map_err(encoded)?,
        )?;
        let body = CloseRunBody::decode(
            r.bytes(
                fa_model::limits::MAX_CLOSE_RUN_BYTES,
                "close rehearsal graph",
            )
            .map_err(encoded)?,
        )
        .map_err(encoded)?;
        let opened_at = CommitSeq(r.u64("close rehearsal opened at").map_err(encoded)?);
        let count = r.u32("close rehearsal review count").map_err(encoded)? as usize;
        if count > fa_model::limits::MAX_CLOSE_RUN_TASKS {
            return Err(invalid("too many close draft reviews"));
        }
        let mut reviews = Vec::with_capacity(count);
        for _ in 0..count {
            reviews.push(DraftDiffCertificate::decode(
                r.bytes(
                    MAX_CLOSE_RUN_REHEARSAL_CERTIFICATE_BYTES,
                    "close rehearsal review",
                )
                .map_err(encoded)?,
            )?);
        }
        let producer = VId(r.u128("close rehearsal producer").map_err(encoded)?);
        let capability_commitment = r.fixed("close rehearsal capability").map_err(encoded)?;
        let output = r
            .bytes(
                MAX_CLOSE_RUN_REHEARSAL_CERTIFICATE_BYTES,
                "close rehearsal output",
            )
            .map_err(encoded)?
            .to_vec();
        let digest = r.fixed("close rehearsal digest").map_err(encoded)?;
        r.finish().map_err(encoded)?;
        let certificate = Self {
            trunk,
            body,
            opened_at,
            reviews,
            producer,
            capability_commitment,
            output,
            digest,
        };
        certificate.validate()?;
        if certificate.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical close rehearsal certificate"));
        }
        Ok(certificate)
    }

    #[must_use]
    pub fn format(&self) -> &'static [u8] {
        CLOSE_RUN_REHEARSAL_CERTIFICATE_FORMAT
    }
    #[must_use]
    pub fn trunk(&self) -> &ReportCertificate {
        &self.trunk
    }
    #[must_use]
    pub fn body(&self) -> &CloseRunBody {
        &self.body
    }
    #[must_use]
    pub fn name(&self) -> &str {
        &self.body.name
    }
    #[must_use]
    pub fn period(&self) -> &str {
        &self.body.period
    }
    #[must_use]
    pub fn run(&self) -> VId {
        close_run_vid(self.body.book_id, &self.body.name)
    }
    #[must_use]
    pub fn known_at(&self) -> CommitSeq {
        self.trunk.known_at
    }
    #[must_use]
    pub fn producer(&self) -> VId {
        self.producer
    }
    #[must_use]
    pub fn capability_commitment(&self) -> &[u8; 32] {
        &self.capability_commitment
    }
    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

fn check_combined_batch(
    task: &CloseTaskBody,
    certificate: &DraftDiffCertificate,
    expected: &DraftDiff,
    rehearsal: &DraftRehearsalStep,
    source_at: CommitSeq,
) -> Result<(), Refusal> {
    let mut source = rehearsal.source.clone();
    source.known_at = certificate.source().known_at;
    if source != *certificate.source()
        || rehearsal.source.known_at != source_at
        || rehearsal.batch.already_recorded
        || source_at.0.checked_add(1) != Some(rehearsal.batch.recorded_at.0)
        || rehearsal.batch.entries != expected.entries
    {
        return Err(in_task(
            &task.id,
            invalid(
                "the combined task changed its original membership, reviewed effects or publication coordinates",
            ),
        ));
    }
    Ok(())
}

impl Book {
    fn close_rehearsal_view(
        &mut self,
        capability: &Capability,
        name: &str,
    ) -> Outcome<CloseRunView> {
        Ok(match self.close_run_status(name, capability)? {
            Ok(Some(view)) => Ok(view),
            Ok(None) => Err(invalid("the selected close run does not exist")),
            Err(refusal) => Err(refusal),
        })
    }

    /// Load and fully replay every original retained review before any combined
    /// task is materialized. Embedded copies cannot replace source retention.
    fn close_rehearsal_reviews(
        &mut self,
        principal: VId,
        capability: &Capability,
        body: &CloseRunBody,
        pinned: Option<&[DraftDiffCertificate]>,
    ) -> Outcome<Vec<(DraftDiffCertificate, DraftDiff)>> {
        let mut reviews = Vec::new();
        let mut total = 0_usize;
        for task in &body.tasks {
            let CloseTaskBodyAction::PromoteDraft {
                certificate_digest, ..
            } = &task.action
            else {
                continue;
            };
            let artifact =
                match self.read_report_artifact(principal, capability, certificate_digest)? {
                    Ok(artifact) => artifact,
                    Err(refusal) => return Ok(Err(in_task(&task.id, refusal))),
                };
            if artifact.family() != ReportArtifactFamily::DraftDiff {
                return Ok(Err(in_task(
                    &task.id,
                    invalid("the retained review is not a draft diff"),
                )));
            }
            let bytes = match artifact.canonical_bytes() {
                Ok(bytes) => bytes,
                Err(refusal) => return Ok(Err(in_task(&task.id, refusal))),
            };
            total = total.saturating_add(bytes.len());
            if total > MAX_CLOSE_RUN_REHEARSAL_CERTIFICATE_BYTES {
                return Ok(Err(invalid(
                    "the aggregate retained close reviews exceed 64 MiB",
                )));
            }
            let certificate = match DraftDiffCertificate::decode(&bytes) {
                Ok(certificate) => certificate,
                Err(refusal) => return Ok(Err(in_task(&task.id, refusal))),
            };
            if pinned.is_some_and(|pinned| pinned.get(reviews.len()) != Some(&certificate)) {
                return Ok(Err(in_task(
                    &task.id,
                    invalid("the certificate substituted a retained draft review"),
                )));
            }
            if let Err(refusal) = check_review(body, task, &certificate, None) {
                return Ok(Err(in_task(&task.id, refusal)));
            }
            let report = match self.replay_draft_diff(principal, capability, &certificate)? {
                Ok(report) => report,
                Err(refusal) => return Ok(Err(in_task(&task.id, refusal))),
            };
            if let Err(refusal) = check_review(body, task, &certificate, Some(&report)) {
                return Ok(Err(in_task(&task.id, refusal)));
            }
            reviews.push((certificate, report));
        }
        if pinned.is_some_and(|pinned| pinned.len() != reviews.len()) {
            return Ok(Err(invalid(
                "the certificate omitted or added a close draft review",
            )));
        }
        Ok(Ok(reviews))
    }

    fn rehearse_close_view(
        &mut self,
        principal: VId,
        capability: &Capability,
        view: &CloseRunView,
        trunk: &TrialBalance,
        reviews: &[(DraftDiffCertificate, DraftDiff)],
    ) -> Outcome<CloseRunRehearsal> {
        let source_at = trunk.known_at;
        if view.opened_at > source_at || source_at > self.head()? {
            return Ok(Err(invalid(
                "the close graph did not exist at the selected source prefix",
            )));
        }
        let mut visited = BTreeSet::new();
        let mut tasks = Vec::with_capacity(view.body.tasks.len());
        // All previously committed prerequisites are satisfied from the start.
        // Re-visiting their ids as though they were pending would change the
        // order relative to the live executor after a partial completion.
        for task in &view.body.tasks {
            if let Some(receipt) = view
                .tasks
                .iter()
                .find(|state| state.id == task.id)
                .and_then(|state| state.completion.as_ref())
                .filter(|receipt| receipt.recorded_at <= source_at)
            {
                visited.insert(task.id.clone());
                tasks.push(CloseTaskRehearsal {
                    id: task.id.clone(),
                    outcome: CloseTaskRehearsalOutcome::AlreadyCompleted(receipt.clone()),
                });
            }
        }
        let mut ordered = Vec::new();
        while visited.len() < view.body.tasks.len() {
            let Some(task) = view.body.tasks.iter().find(|task| {
                !visited.contains(&task.id) && task.depends_on.iter().all(|id| visited.contains(id))
            }) else {
                return Ok(Err(invalid(
                    "the close graph has no deterministic ready task",
                )));
            };
            visited.insert(task.id.clone());
            ordered.push(task);
        }
        let pending_drafts: Vec<_> = ordered
            .iter()
            .filter(|task| matches!(task.action, CloseTaskBodyAction::PromoteDraft { .. }))
            .copied()
            .collect();
        let names: Vec<_> = pending_drafts
            .iter()
            .filter_map(|task| match &task.action {
                CloseTaskBodyAction::PromoteDraft { name, .. } => Some(name.clone()),
                _ => None,
            })
            .collect();
        let (scratch, seq_map_digest, steps) = if names.is_empty() {
            (None, None, Vec::new())
        } else {
            let (scratch, sequence) =
                match self.rehearse_drafts_at(principal, capability, names, source_at)? {
                    Ok(rehearsed) => rehearsed,
                    Err(refusal) => {
                        let index = refusal.detail.as_ref().and_then(|detail| {
                            detail.at.iter().find_map(|(key, value)| {
                                if *key == "draft_index"
                                    && let fa_journal::refusal::Locus::Index(index) = value
                                {
                                    return usize::try_from(*index).ok();
                                }
                                None
                            })
                        });
                        return Ok(Err(
                            match index.and_then(|index| pending_drafts.get(index)) {
                                Some(task) => in_task(&task.id, refusal),
                                None => refusal,
                            },
                        ));
                    }
                };
            if sequence.steps.len() != pending_drafts.len()
                || sequence.seq_map.source_book != view.body.book_id
                || sequence.seq_map.source_prefix != source_at
                || !sequence.seq_map.is_monotone()
                || sequence
                    .seq_map
                    .pairs
                    .iter()
                    .any(|pair| pair.source_seq != pair.scratch_seq)
            {
                return Ok(Err(invalid(
                    "the complete native rehearsal changed its source map or task count",
                )));
            }
            (
                Some(scratch),
                Some(sequence.seq_map.digest()?),
                sequence.steps,
            )
        };
        let mut steps = steps.into_iter();
        let mut rehearsal_at = source_at;
        for task in ordered {
            let outcome = match &task.action {
                CloseTaskBodyAction::PeriodTransition { to } => {
                    CloseTaskRehearsalOutcome::AwaitingNativeTransitionReview { to: *to }
                }
                CloseTaskBodyAction::PromoteDraft {
                    certificate_digest, ..
                } => {
                    let Some((certificate, expected)) = reviews
                        .iter()
                        .find(|(certificate, _)| certificate.digest() == certificate_digest)
                    else {
                        return Ok(Err(invalid("a close task is missing its replayed review")));
                    };
                    let Some(rehearsal) = steps.next() else {
                        return Ok(Err(invalid(
                            "the native rehearsal omitted a complete draft",
                        )));
                    };
                    if let Err(refusal) =
                        check_combined_batch(task, certificate, expected, &rehearsal, rehearsal_at)
                    {
                        return Ok(Err(refusal));
                    }
                    rehearsal_at = rehearsal.batch.recorded_at;
                    CloseTaskRehearsalOutcome::Rehearsed {
                        batch_outcome: rehearsal.batch.outcome,
                        recorded_at: rehearsal.batch.recorded_at,
                        entries: rehearsal.batch.entries,
                    }
                }
            };
            tasks.push(CloseTaskRehearsal {
                id: task.id.clone(),
                outcome,
            });
        }
        let after = match scratch.as_ref() {
            Some(scratch) => {
                scratch.trial_balance_at(std::slice::from_ref(&view.body.period), None)?
            }
            None => trunk.clone(),
        };
        if after.known_at != rehearsal_at
            || after.periods != trunk.periods
            || trunk.activity
            || after.activity
            || after.effective_through != trunk.effective_through
        {
            return Ok(Err(invalid(
                "the combined native balance changed its selected coordinate",
            )));
        }
        let rows = match crate::draft_review::difference(trunk, &after) {
            Ok(rows) => rows,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let report = CloseRunRehearsal {
            name: view.body.name.clone(),
            run: view.vid,
            body_digest: view.body.digest().map_err(|error| {
                crate::BookError::Kernel(fa_journal::KernelError::Model(error.into()))
            })?,
            period: view.body.period.clone(),
            opened_at: view.opened_at,
            source_known_at: source_at,
            seq_map_digest,
            rehearsal_known_at: rehearsal_at,
            complete_on_trunk: tasks
                .iter()
                .all(|task| matches!(task.outcome, CloseTaskRehearsalOutcome::AlreadyCompleted(_))),
            tasks,
            rows,
        };
        Ok(report.canonical_bytes().map(|_| report))
    }

    /// Rehearse every unfinished monetary task against its predecessors' real
    /// hypothetical effects. Trunk, drafts and period states remain unchanged.
    pub fn close_run_rehearsal(
        &mut self,
        principal: VId,
        capability: &Capability,
        name: &str,
    ) -> Outcome<CloseRunRehearsal> {
        if let Err(refusal) = authorize(self, principal, capability, false)? {
            return Ok(Err(refusal));
        }
        let view = match self.close_rehearsal_view(capability, name)? {
            Ok(view) => view,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let known_at = self.head()?;
        let reviews = match self.close_rehearsal_reviews(principal, capability, &view.body, None)? {
            Ok(reviews) => reviews,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let trunk =
            self.trial_balance_at(std::slice::from_ref(&view.body.period), Some(known_at))?;
        self.rehearse_close_view(principal, capability, &view, &trunk, &reviews)
    }

    pub fn certify_close_run_rehearsal(
        &mut self,
        principal: VId,
        capability: &Capability,
        name: &str,
    ) -> Outcome<CertifiedCloseRunRehearsal> {
        if let Err(refusal) = authorize(self, principal, capability, true)? {
            return Ok(Err(refusal));
        }
        let view = match self.close_rehearsal_view(capability, name)? {
            Ok(view) => view,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let known_at = self.head()?;
        let reviews = match self.close_rehearsal_reviews(principal, capability, &view.body, None)? {
            Ok(reviews) => reviews,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let certified = match self.certify_report(
            ReportSelection::TrialBalance(TrialBalanceSelection::Periods(vec![
                view.body.period.clone(),
            ])),
            Some(known_at),
        )? {
            Ok(certified) => certified,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let ReportOutput::TrialBalance(trunk) = certified.report else {
            return Ok(Err(invalid(
                "the close baseline is not a native trial balance",
            )));
        };
        let report =
            match self.rehearse_close_view(principal, capability, &view, &trunk, &reviews)? {
                Ok(report) => report,
                Err(refusal) => return Ok(Err(refusal)),
            };
        let seal = || -> Result<CloseRunRehearsalCertificate, Refusal> {
            let mut certificate = CloseRunRehearsalCertificate {
                trunk: certified.certificate,
                body: view.body,
                opened_at: view.opened_at,
                reviews: reviews
                    .into_iter()
                    .map(|(certificate, _)| certificate)
                    .collect(),
                producer: principal,
                capability_commitment: capability.commitment().map_err(encoded)?,
                output: report.canonical_bytes()?,
                digest: [0; 32],
            };
            certificate.digest = domain_digest(DIGEST_DOMAIN, &[&certificate.body_bytes()?]);
            certificate.validate()?;
            Ok(certificate)
        };
        Ok(seal().map(|certificate| CertifiedCloseRunRehearsal {
            report,
            certificate,
        }))
    }

    /// Retain the complete combined review only after replay, with current
    /// whole-book read and Produce authority. Retention records evidence;
    /// it never marks any task complete or authorizes its live execution.
    pub fn retain_close_run_rehearsal(
        &mut self,
        principal: VId,
        capability: &Capability,
        certificate: &CloseRunRehearsalCertificate,
    ) -> Outcome<crate::RetainedCertificate> {
        if let Err(denial) = fa_policy::admit_direct_write(capability) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        if let Err(refusal) = authorize(self, principal, capability, true)? {
            return Ok(Err(refusal));
        }
        let verified_at = self.head()?;
        if let Err(refusal) = self.replay_close_run_rehearsal(principal, capability, certificate)? {
            return Ok(Err(refusal));
        }
        self.retain_replayed_close_run_rehearsal(principal, capability, certificate, verified_at)
    }

    /// Reperform the original combined review, including historical completion
    /// receipts. Later successful execution cannot alter the captured result.
    pub fn replay_close_run_rehearsal(
        &mut self,
        principal: VId,
        capability: &Capability,
        certificate: &CloseRunRehearsalCertificate,
    ) -> Outcome<CloseRunRehearsal> {
        if let Err(refusal) = authorize(self, principal, capability, false)? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = certificate.validate() {
            return Ok(Err(refusal));
        }
        if certificate.body.book_id != self.context().book_id {
            return Ok(Err(invalid("the close rehearsal belongs to another book")));
        }
        let view = match self.close_rehearsal_view(capability, certificate.name())? {
            Ok(view) => view,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if view.body != certificate.body
            || view.opened_at != certificate.opened_at
            || view.vid != certificate.run()
        {
            return Ok(Err(invalid(
                "the original close graph differs from the certified source",
            )));
        }
        let trunk = match self.replay_report(&certificate.trunk)? {
            Ok(ReportOutput::TrialBalance(trunk)) => trunk,
            Ok(_) => {
                return Ok(Err(invalid(
                    "the close baseline did not replay as a native trial balance",
                )));
            }
            Err(refusal) => return Ok(Err(refusal)),
        };
        let reviews = match self.close_rehearsal_reviews(
            principal,
            capability,
            &view.body,
            Some(&certificate.reviews),
        )? {
            Ok(reviews) => reviews,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let report =
            match self.rehearse_close_view(principal, capability, &view, &trunk, &reviews)? {
                Ok(report) => report,
                Err(refusal) => return Ok(Err(refusal)),
            };
        match report.canonical_bytes() {
            Ok(output) if output == certificate.output => Ok(Ok(report)),
            Ok(_) => Ok(Err(invalid(
                "the complete graph, receipts, source map or combined monetary output did not replay",
            ))),
            Err(refusal) => Ok(Err(refusal)),
        }
    }
}
