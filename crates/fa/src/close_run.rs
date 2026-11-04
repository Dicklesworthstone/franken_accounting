//! Reviewed close execution over immutable draft rehearsals (plan §7.5).
//!
//! A run binds its complete dependency graph and each draft's retained review.
//! The journal executes a ready task and records completion in one transaction.
//! The review is evidence of the selected effects; execution still requires
//! current authority, original planner authority and the native posting laws.

use fa_journal::close_run::{CloseRunView, CloseTaskRecorded};
use fa_journal::{Refusal, TransitionPlan};
use fa_model::{ApprovalRef, CloseTaskBodyAction};
use fa_policy::{Capability, Intent, Op, Reach};
use fa_time::PeriodTransition;

use crate::{
    Book, BookError, CertificateStatus, CloseRunRehearsal, CloseRunRehearsalCertificate,
    CloseTaskRehearsalOutcome, Outcome,
};

/// The independently selected evidence or period action for a close task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReviewedCloseAction {
    /// Full digest of a retained DraftDiffCertificate, as returned by
    /// `close dry-run --certify`. Its source and output are replayed before
    /// the run is created; an arbitrary digest is never a completed review.
    DraftCertificate([u8; 32]),
    /// A native period transition. Execution consumes a separately reviewed
    /// TransitionPlan and its required independent approvals.
    PeriodTransition(PeriodTransition),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewedCloseTask {
    pub id: String,
    pub depends_on: Vec<String>,
    pub action: ReviewedCloseAction,
}

/// Input for the graph's one terminal period task. The task ID is explicit:
/// a plan or its approvals can never be applied to a different ready task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseRunTransition {
    /// Prepare a fresh native proposal only after its dependencies complete.
    /// The returned plan still needs independent review and any approvals
    /// required by the native period law before a subsequent invocation.
    Review {
        task: String,
        reason_code: u16,
        idempotency_key: Vec<u8>,
    },
    /// Execute this exact previously reviewed proposal. No approval is
    /// created, inferred from the close review, or transferred between tasks.
    Reviewed {
        task: String,
        plan: Box<TransitionPlan>,
        approvals: Vec<ApprovalRef>,
    },
}

impl CloseRunTransition {
    fn task(&self) -> &str {
        match self {
            Self::Review { task, .. } | Self::Reviewed { task, .. } => task,
        }
    }
}

/// Why a close invocation stopped with tasks still incomplete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseRunStop {
    /// The caller supplied neither an explicit review request nor a reviewed
    /// plan for the now-ready period task. No reason or key is invented.
    TransitionRequired { task: String, to: PeriodTransition },
    /// A fresh native proposal, prepared after the preceding tasks' effects.
    /// Its digest is the value independent approvers must bind.
    TransitionReview {
        task: String,
        plan: Box<TransitionPlan>,
        proposal_digest: [u8; 32],
    },
    /// This task published nothing. Earlier `completed` receipts remain
    /// durable; inspect the refusal, correct its cause, and resume the run.
    Refused { task: String, refusal: Refusal },
}

/// Durable progress from one invocation of [`Book::execute_close_run`].
///
/// A run is deliberately task-atomic, not one transaction spanning its graph.
/// `completed` contains only new effects from this invocation. Tasks already
/// complete on entry remain visible in `run` and are never executed again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseRunExecution {
    pub run: CloseRunView,
    pub completed: Vec<CloseTaskRecorded>,
    pub stop: Option<CloseRunStop>,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::STRUCTURE,
        fa_journal::exit::USAGE,
        message,
        "plan §7.5 (resumable execution of immutable reviewed close tasks)",
        "inspect close status; supply a task-specific review request or its unchanged native plan and independent approvals",
    )
}

const REVIEW_FIX: &str = "review the current result with `fa close dry-run --run <name> --certify --json`, then execute with `fa close run --run <name> --rehearsal C:<full-digest> --yes` and any required native transition plan and approvals";

fn review_invalidated(name: &str, message: &str) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::PLAN_INVALIDATED,
        fa_journal::exit::CONFLICT,
        message,
        "plan §7.5 (execute the same reviewed combined close)",
        REVIEW_FIX,
    )
    .at("run", name)
}

/// Retaining a certificate or an approval advances the source prefix without
/// changing the reviewed accounting work. Only those source/scratch coordinates
/// may differ: task order, native identities, completed receipts, every posted
/// and pending row, and completion/transition states remain exact.
fn same_reviewed_rehearsal(reviewed: &CloseRunRehearsal, mut current: CloseRunRehearsal) -> bool {
    if current.seq_map_digest.is_some() != reviewed.seq_map_digest.is_some() {
        return false;
    }
    current.source_known_at = reviewed.source_known_at;
    current.seq_map_digest = reviewed.seq_map_digest;
    current.rehearsal_known_at = reviewed.rehearsal_known_at;
    for (current, reviewed) in current.tasks.iter_mut().zip(&reviewed.tasks) {
        if let (
            CloseTaskRehearsalOutcome::Rehearsed { recorded_at, .. },
            CloseTaskRehearsalOutcome::Rehearsed {
                recorded_at: reviewed_at,
                ..
            },
        ) = (&mut current.outcome, &reviewed.outcome)
        {
            *recorded_at = *reviewed_at;
        }
    }
    current == *reviewed
}

fn corrupt(message: &str) -> BookError {
    fa_journal::KernelError::Corrupt(message.into()).into()
}

fn transition(to: u8) -> Result<PeriodTransition, BookError> {
    match to {
        2 => Ok(PeriodTransition::SoftClose),
        3 => Ok(PeriodTransition::Close),
        4 => Ok(PeriodTransition::Lock),
        _ => Err(corrupt(
            "a recorded close task has an invalid period target",
        )),
    }
}

/// Validate optional input before the first task can publish. Native
/// execution still authenticates the plan, approval objects, current period
/// and current authority again at its own transaction boundary.
fn validate_transition(
    book: &Book,
    run: &CloseRunView,
    capability: &Capability,
    input: &CloseRunTransition,
) -> Outcome<()> {
    let Some(task) = run.body.tasks.iter().find(|task| task.id == input.task()) else {
        return Ok(Err(invalid(
            "the transition input names no task in this run",
        )));
    };
    let CloseTaskBodyAction::PeriodTransition { to } = task.action else {
        return Ok(Err(invalid(
            "the transition input must name the run's terminal period task",
        )));
    };
    let target = transition(to)?;
    match input {
        CloseRunTransition::Review {
            reason_code,
            idempotency_key,
            ..
        } => {
            if run
                .tasks
                .iter()
                .any(|task| task.id == input.task() && task.completion.is_some())
            {
                return Ok(Err(invalid(
                    "a completed period task cannot prepare a new transition review",
                )));
            }
            if idempotency_key.is_empty()
                || idempotency_key.len() > fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES
            {
                return Ok(Err(invalid(format!(
                    "the transition review key must contain 1..={} bytes",
                    fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES,
                ))));
            }
            let scope = fa_journal::period::reason_scope(target);
            let reasons = fa_registry::reason_codes::ReasonCodes::embedded()
                .map_err(|error| corrupt(&error.to_string()))?;
            if reasons.get(scope, *reason_code).is_none() {
                return Ok(Err(Refusal::new(
                    fa_journal::refusal::code::PERIOD_REASON,
                    fa_journal::exit::REFUSAL,
                    format!("unregistered {scope} reason {reason_code}"),
                    "plan §7.3 (registered period-control reasons)",
                    reasons.listing(scope),
                )));
            }
        }
        CloseRunTransition::Reviewed {
            plan, approvals, ..
        } => {
            if plan.book_id != run.body.book_id
                || plan.period_code != run.body.period
                || plan.to.tag() != to
                || !plan.is_for(target)
                || plan.principal_ref != capability.holder()
            {
                return Ok(Err(invalid(
                    "the reviewed transition plan does not select this task, book, period and executor",
                )));
            }
            let digest = match book.plan_digest(plan)? {
                Ok(digest) => digest,
                Err(refusal) => return Ok(Err(refusal)),
            };
            if approvals.len() > fa_model::limits::MAX_APPROVALS
                || approvals
                    .iter()
                    .any(|approval| approval.approved_digest != digest)
            {
                return Ok(Err(invalid(
                    "transition approvals must form a bounded list binding the exact reviewed proposal",
                )));
            }
        }
    }
    Ok(Ok(()))
}

impl Book {
    /// Resolve and replay each retained draft certificate before journaling
    /// an immutable run. This does not promote any draft or change a period.
    /// Dependencies are part of the definition and are validated by the
    /// kernel's graph checks; a later task cannot silently replace a review.
    pub fn start_close_run(
        &mut self,
        capability: Capability,
        name: &str,
        period: &str,
        tasks: Vec<ReviewedCloseTask>,
        description: &str,
    ) -> Outcome<CloseRunView> {
        self.start_reviewed_close_run(capability, name, period, tasks, description)
    }

    /// Execute ready tasks in lexical task-ID order, resuming from their
    /// durable native receipts. Every task obtains a fresh native basis and
    /// rechecks current authority before publication. This call never creates
    /// approvals and never executes a newly generated transition proposal.
    ///
    /// Invalid request input, initial authorization and the combined rehearsal
    /// of all unfinished draft tasks fail before any task executes. Independent
    /// reviews alone cannot establish that the drafts are compatible: together
    /// they may overspend a limit, settle the same item or claim the same key.
    /// The native rehearsal runs them in this executor's dependency order.
    /// A task refusal is returned in [`CloseRunExecution::stop`],
    /// together with progress already committed by earlier tasks. Foundation
    /// failures and cancellation propagate as outer errors; those same
    /// receipts remain available through [`Book::close_run_status`] on retry.
    pub fn execute_close_run(
        &mut self,
        name: &str,
        capability: Capability,
        description: &str,
        transition_input: Option<CloseRunTransition>,
    ) -> Outcome<CloseRunExecution> {
        self.execute_close_run_with_rehearsal(name, capability, description, transition_input, None)
    }

    /// Execute only the combined close selected by the caller's reviewed
    /// certificate. Full historical replay and current native rehearsal must
    /// agree on the graph, task receipts, exact effects and monetary result.
    /// Later relevant postings invalidate the review even when they offset.
    ///
    /// Certificate retention and approval publications alone do not invalidate
    /// it. Any changed task completion requires a fresh combined review of the
    /// remaining run, including for a completed-run retry. The caller still
    /// needs current execution authority and the terminal task's native plan
    /// and independent approvals. Certificate producer metadata grants none.
    ///
    /// This call holds the same owned book writer lease through verification
    /// and execution. It does not journal a run-level certificate attachment.
    pub fn execute_reviewed_close_run(
        &mut self,
        name: &str,
        capability: Capability,
        description: &str,
        rehearsal: &CloseRunRehearsalCertificate,
        transition_input: Option<CloseRunTransition>,
    ) -> Outcome<CloseRunExecution> {
        self.execute_close_run_with_rehearsal(
            name,
            capability,
            description,
            transition_input,
            Some(rehearsal),
        )
    }

    fn execute_close_run_with_rehearsal(
        &mut self,
        name: &str,
        capability: Capability,
        description: &str,
        transition_input: Option<CloseRunTransition>,
        rehearsal: Option<&CloseRunRehearsalCertificate>,
    ) -> Outcome<CloseRunExecution> {
        let admission =
            fa_policy::admit_read(&capability, capability.holder(), self.context().book_id)
                .and_then(|()| fa_policy::reach(&capability, &Reach::whole_book(true), None))
                .and_then(|()| {
                    fa_policy::admit(
                        &capability,
                        &Intent {
                            principal: capability.holder(),
                            trunk: true,
                            op: Op::Close,
                            book: self.context().book_id,
                            legs: &[],
                        },
                    )
                });
        if let Err(denial) = admission {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        if let Err(refusal) = self.admit_current(&capability)? {
            return Ok(Err(refusal));
        }
        let mut run = match self.close_run_status(name, &capability)? {
            Ok(Some(run)) => run,
            Ok(None) => return Ok(Err(invalid("the close run does not exist"))),
            Err(refusal) => return Ok(Err(refusal)),
        };
        if description.len() > fa_model::limits::MAX_DESCRIPTION_BYTES {
            return Ok(Err(invalid(
                "the close execution description exceeds its byte bound",
            )));
        }
        if let Some(rehearsal) = rehearsal {
            if rehearsal.name() != name {
                return Ok(Err(Refusal::new(
                    fa_journal::refusal::code::STRUCTURE,
                    fa_journal::exit::USAGE,
                    "the selected combined close rehearsal names a different run",
                    "plan §7.5 (the selected certificate binds this close run)",
                    REVIEW_FIX,
                )
                .at("run", name)));
            }
            let reviewed = match self.replay_close_run_rehearsal(
                capability.holder(),
                &capability,
                rehearsal,
            )? {
                Ok(reviewed) => reviewed,
                Err(refusal) => return Ok(Err(refusal)),
            };
            match self.certificate_status(rehearsal.trunk())? {
                Ok(CertificateStatus::Current { .. }) => {}
                Ok(CertificateStatus::SupersededBy { .. }) => {
                    return Ok(Err(review_invalidated(
                        name,
                        "the selected close rehearsal's monetary baseline has later relevant entries",
                    )));
                }
                Err(refusal) => return Ok(Err(refusal)),
            }
            let current = match self.close_run_rehearsal(capability.holder(), &capability, name)? {
                Ok(current) => current,
                Err(refusal) => return Ok(Err(refusal)),
            };
            if !same_reviewed_rehearsal(&reviewed, current) {
                return Ok(Err(review_invalidated(
                    name,
                    "the current close tasks, completion receipts or exact monetary result differ from the selected combined rehearsal",
                )));
            }
        }
        if let Some(input) = &transition_input {
            if let Err(refusal) = validate_transition(self, &run, &capability, input)? {
                return Ok(Err(refusal));
            }
            // A resumed caller may retain its already-consumed transition
            // artifact. Authenticate the exact original effect and approvals
            // through the native retry path; never silently ignore them.
            if run
                .tasks
                .iter()
                .any(|task| task.id == input.task() && task.completion.is_some())
                && let CloseRunTransition::Reviewed {
                    task,
                    plan,
                    approvals,
                } = input
            {
                match self.execute_close_task(
                    name,
                    task,
                    capability.clone(),
                    description,
                    Some(plan.as_ref().clone()),
                    approvals.clone(),
                )? {
                    Ok(recorded) => run = recorded.run,
                    Err(refusal) => return Ok(Err(refusal)),
                }
            }
        }
        // Validate the whole remaining monetary sequence before publishing its
        // first task. This Book owns the writer lease throughout this call;
        // native execution still rechecks authority, witnesses and exact effects
        // at each task's transaction boundary. Historical receipts remain the
        // source of truth on restart and are never applied twice in scratch.
        if rehearsal.is_none()
            && run.tasks.iter().any(|task| {
                task.completion.is_none()
                    && run.body.tasks.iter().any(|body| {
                        body.id == task.id
                            && matches!(body.action, CloseTaskBodyAction::PromoteDraft { .. })
                    })
            })
            && let Err(refusal) =
                self.close_run_rehearsal(capability.holder(), &capability, name)?
        {
            let task = refusal.detail.as_ref().and_then(|detail| {
                detail
                    .at
                    .iter()
                    .find_map(|(key, value)| match (key, value) {
                        (&"task", fa_journal::refusal::Locus::Text(id))
                            if run.body.tasks.iter().any(|task| task.id == *id) =>
                        {
                            Some(id.clone())
                        }
                        _ => None,
                    })
            });
            return Ok(match task {
                Some(task) => Ok(CloseRunExecution {
                    run,
                    completed: Vec::new(),
                    stop: Some(CloseRunStop::Refused { task, refusal }),
                }),
                None => Err(refusal),
            });
        }
        let mut completed = Vec::new();
        for _ in 0..fa_model::limits::MAX_CLOSE_RUN_TASKS {
            if run.complete {
                return Ok(Ok(CloseRunExecution {
                    run,
                    completed,
                    stop: None,
                }));
            }
            let Some(task) = run
                .tasks
                .iter()
                .filter(|task| task.ready && task.completion.is_none())
                .min_by(|left, right| left.id.cmp(&right.id))
                .map(|task| task.id.clone())
            else {
                return Err(corrupt("an incomplete close run has no ready task"));
            };
            let action = run
                .body
                .tasks
                .iter()
                .find(|definition| definition.id == task)
                .ok_or_else(|| corrupt("a close task has no immutable definition"))?
                .action
                .clone();
            let (plan, approvals) = match action {
                CloseTaskBodyAction::PromoteDraft { .. } => (None, Vec::new()),
                CloseTaskBodyAction::PeriodTransition { to } => match transition_input.as_ref() {
                    None => {
                        return Ok(Ok(CloseRunExecution {
                            run,
                            completed,
                            stop: Some(CloseRunStop::TransitionRequired {
                                task,
                                to: transition(to)?,
                            }),
                        }));
                    }
                    Some(CloseRunTransition::Review {
                        task: selected,
                        reason_code,
                        idempotency_key,
                    }) if selected == &task => {
                        let stop = match self.plan_close_task_transition(
                            name,
                            &task,
                            &capability,
                            *reason_code,
                            idempotency_key,
                            description,
                        )? {
                            Ok(plan) => match self.plan_digest(&plan)? {
                                Ok(proposal_digest) => CloseRunStop::TransitionReview {
                                    task,
                                    plan: Box::new(plan),
                                    proposal_digest,
                                },
                                Err(refusal) => CloseRunStop::Refused { task, refusal },
                            },
                            Err(refusal) => CloseRunStop::Refused { task, refusal },
                        };
                        return Ok(Ok(CloseRunExecution {
                            run,
                            completed,
                            stop: Some(stop),
                        }));
                    }
                    Some(CloseRunTransition::Reviewed {
                        task: selected,
                        plan,
                        approvals,
                    }) if selected == &task => (Some(plan.as_ref().clone()), approvals.clone()),
                    Some(_) => {
                        return Err(corrupt(
                            "a validated close transition input does not name the ready period task",
                        ));
                    }
                },
            };
            match self.execute_close_task(
                name,
                &task,
                capability.clone(),
                description,
                plan,
                approvals,
            )? {
                Ok(recorded) => {
                    run = recorded.run.clone();
                    if !recorded.already_recorded {
                        completed.push(recorded);
                    }
                }
                Err(refusal) => {
                    return Ok(Ok(CloseRunExecution {
                        run,
                        completed,
                        stop: Some(CloseRunStop::Refused { task, refusal }),
                    }));
                }
            }
        }
        if run.complete {
            Ok(Ok(CloseRunExecution {
                run,
                completed,
                stop: None,
            }))
        } else {
            Err(corrupt(
                "close execution exceeded the immutable graph's task bound",
            ))
        }
    }
}
