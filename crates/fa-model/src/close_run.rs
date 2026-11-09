//! The immutable, reviewed task graph of a close run (plan §7.5).
//!
//! These bytes describe the work and its retained rehearsal. They do not
//! attest that a task completed: authoritative lifecycle records and native
//! effects supply that evidence. Graph size and byte bounds are independent.

use fgdb_types::{CommitSeq, VId};

use crate::canon::Reason;
use crate::ids::{Id128, domain_digest};
use crate::limits::{MAX_CLOSE_RUN_BYTES, MAX_CLOSE_RUN_TASKS, MAX_CLOSE_RUN_TEXT_BYTES};
use crate::{DecodeError, EncodeError, Reader, Writer};

pub const CLOSE_RUN_VERSION: u16 = 1;
pub const CLOSE_RUN_DIGEST_DOMAIN: &[u8] = b"fa:close-run:v1";
pub const CLOSE_TASK_DIGEST_DOMAIN: &[u8] = b"fa:close-task:v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseRunBody {
    pub book_id: Id128,
    pub name: String,
    pub period: String,
    pub owner: VId,
    /// Strictly ascending task ids; execution order follows dependencies.
    pub tasks: Vec<CloseTaskBody>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseTaskBody {
    pub id: String,
    /// Strictly ascending ids of prerequisites in this run.
    pub depends_on: Vec<String>,
    pub action: CloseTaskBodyAction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseTaskBodyAction {
    /// The exact immutable draft and the effects reviewed in its rehearsal.
    PromoteDraft {
        draft: VId,
        name: String,
        owner: VId,
        source_known_at: CommitSeq,
        source_digest: [u8; 32],
        certificate_digest: [u8; 32],
        entries_digest: [u8; 32],
        entry_count: u32,
    },
    /// Native PeriodState tags: SoftClosed=2, Closed=3, Locked=4.
    /// The actual predecessor and approval requirements are checked live.
    PeriodTransition { to: u8 },
    /// Reproduce the fiscal year's latest intrinsic close and require that
    /// no native or functional nominal balance remains at execution time.
    VerifyYearEndClose { fiscal_year: i32 },
}

fn invalid(what: &'static str) -> DecodeError {
    DecodeError {
        offset: 0,
        what,
        reason: Reason::Invalid,
    }
}

fn bounded_text(value: &str, what: &'static str) -> Result<(), DecodeError> {
    if value.is_empty() || value.len() > MAX_CLOSE_RUN_TEXT_BYTES {
        return Err(invalid(what));
    }
    Ok(())
}

fn bounded_bytes(bytes: &[u8]) -> Result<(), DecodeError> {
    if bytes.len() > MAX_CLOSE_RUN_BYTES {
        return Err(DecodeError {
            offset: 0,
            what: "close_run.bytes",
            reason: Reason::TooLong {
                max: MAX_CLOSE_RUN_BYTES,
                actual: bytes.len(),
            },
        });
    }
    Ok(())
}

impl CloseTaskBody {
    pub fn validate(&self) -> Result<(), DecodeError> {
        bounded_text(&self.id, "close_task.id")?;
        if self.depends_on.len() > MAX_CLOSE_RUN_TASKS
            || !self.depends_on.windows(2).all(|ids| ids[0] < ids[1])
        {
            return Err(invalid("close_task.depends_on"));
        }
        for id in &self.depends_on {
            bounded_text(id, "close_task.depends_on")?;
            if id == &self.id {
                return Err(invalid("close_task.self_dependency"));
            }
        }
        match &self.action {
            CloseTaskBodyAction::PromoteDraft {
                name, entry_count, ..
            } => {
                bounded_text(name, "close_task.draft_name")?;
                if *entry_count == 0 || *entry_count as usize > crate::limits::MAX_BATCH_ENTRIES {
                    return Err(invalid("close_task.entry_count"));
                }
            }
            CloseTaskBodyAction::PeriodTransition { to } if !matches!(*to, 2..=4) => {
                return Err(invalid("close_task.period_state"));
            }
            CloseTaskBodyAction::PeriodTransition { .. } => {}
            CloseTaskBodyAction::VerifyYearEndClose { .. } => {}
        }
        Ok(())
    }

    fn encode(&self, w: &mut Writer) {
        w.u16(CLOSE_RUN_VERSION)
            .str(&self.id)
            .list(&self.depends_on, |w, id| {
                w.str(id);
            });
        match &self.action {
            CloseTaskBodyAction::PromoteDraft {
                draft,
                name,
                owner,
                source_known_at,
                source_digest,
                certificate_digest,
                entries_digest,
                entry_count,
            } => {
                w.u8(0)
                    .u128(draft.0)
                    .str(name)
                    .u128(owner.0)
                    .u64(source_known_at.0)
                    .fixed(source_digest)
                    .fixed(certificate_digest)
                    .fixed(entries_digest)
                    .u32(*entry_count);
            }
            CloseTaskBodyAction::PeriodTransition { to } => {
                w.u8(1).u8(*to);
            }
            CloseTaskBodyAction::VerifyYearEndClose { fiscal_year } => {
                w.u8(2).i32(*fiscal_year);
            }
        }
    }

    /// Validate before encoding caller-constructed values; decoding validates.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        self.encode(&mut w);
        w.finish()
    }

    pub fn digest(&self) -> Result<[u8; 32], EncodeError> {
        Ok(domain_digest(
            CLOSE_TASK_DIGEST_DOMAIN,
            &[&self.canonical_bytes()?],
        ))
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        if r.u16("close_task.version")? != CLOSE_RUN_VERSION {
            return Err(r.invalid("close_task.version"));
        }
        let id = r
            .str(MAX_CLOSE_RUN_TEXT_BYTES, "close_task.id")?
            .to_string();
        let depends_on = r.list(MAX_CLOSE_RUN_TASKS, "close_task.depends_on", |r| {
            Ok(r.str(MAX_CLOSE_RUN_TEXT_BYTES, "close_task.dependency")?
                .to_string())
        })?;
        let action = match r.u8("close_task.action")? {
            0 => CloseTaskBodyAction::PromoteDraft {
                draft: VId(r.u128("close_task.draft")?),
                name: r
                    .str(MAX_CLOSE_RUN_TEXT_BYTES, "close_task.draft_name")?
                    .to_string(),
                owner: VId(r.u128("close_task.draft_owner")?),
                source_known_at: CommitSeq(r.u64("close_task.source_known_at")?),
                source_digest: r.fixed("close_task.source_digest")?,
                certificate_digest: r.fixed("close_task.certificate_digest")?,
                entries_digest: r.fixed("close_task.entries_digest")?,
                entry_count: r.u32("close_task.entry_count")?,
            },
            1 => CloseTaskBodyAction::PeriodTransition {
                to: r.u8("close_task.period_state")?,
            },
            2 => CloseTaskBodyAction::VerifyYearEndClose {
                fiscal_year: r.i32("close_task.fiscal_year")?,
            },
            _ => return Err(r.invalid("close_task.action")),
        };
        let task = Self {
            id,
            depends_on,
            action,
        };
        task.validate()?;
        Ok(task)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        bounded_bytes(bytes)?;
        let mut r = Reader::new(bytes);
        let task = Self::read(&mut r)?;
        r.finish()?;
        Ok(task)
    }
}

impl CloseRunBody {
    pub fn validate(&self) -> Result<(), DecodeError> {
        bounded_text(&self.name, "close_run.name")?;
        bounded_text(&self.period, "close_run.period")?;
        if self.tasks.is_empty()
            || self.tasks.len() > MAX_CLOSE_RUN_TASKS
            || !self.tasks.windows(2).all(|tasks| tasks[0].id < tasks[1].id)
        {
            return Err(invalid("close_run.tasks"));
        }
        for task in &self.tasks {
            task.validate()?;
            if task
                .depends_on
                .iter()
                .any(|id| self.tasks.binary_search_by(|t| t.id.cmp(id)).is_err())
            {
                return Err(invalid("close_run.unknown_dependency"));
            }
        }
        // Bounded topological elimination proves only that the declaration
        // is a DAG. It is never used as evidence of runtime completion.
        let mut visited = vec![false; self.tasks.len()];
        for _ in 0..self.tasks.len() {
            let next = self.tasks.iter().enumerate().position(|(i, task)| {
                !visited[i]
                    && task.depends_on.iter().all(|id| {
                        self.tasks
                            .binary_search_by(|t| t.id.cmp(id))
                            .is_ok_and(|j| visited[j])
                    })
            });
            let Some(next) = next else {
                return Err(invalid("close_run.cycle"));
            };
            visited[next] = true;
        }
        let ancestors_of = |selected: &CloseTaskBody| -> Result<Vec<bool>, DecodeError> {
            let mut ancestors = vec![false; self.tasks.len()];
            let mut pending: Vec<_> = selected.depends_on.iter().collect();
            while let Some(id) = pending.pop() {
                let index = self
                    .tasks
                    .binary_search_by(|task| task.id.cmp(id))
                    .map_err(|_| invalid("close_run.unknown_dependency"))?;
                if !ancestors[index] {
                    ancestors[index] = true;
                    pending.extend(self.tasks[index].depends_on.iter());
                }
            }
            Ok(ancestors)
        };
        let checkpoints: Vec<_> = self
            .tasks
            .iter()
            .filter(|task| matches!(task.action, CloseTaskBodyAction::VerifyYearEndClose { .. }))
            .collect();
        if checkpoints.len() > 1 {
            return Err(invalid("close_run.duplicate_year_end_verification"));
        }
        if let Some(checkpoint) = checkpoints.first() {
            let ancestors = ancestors_of(checkpoint)?;
            if self.tasks.iter().enumerate().any(|(index, task)| {
                matches!(task.action, CloseTaskBodyAction::PromoteDraft { .. }) && !ancestors[index]
            }) {
                return Err(invalid("close_run.verification_precedes_monetary_tasks"));
            }
        }
        // Enforce the same terminal rule when decoding retained graphs, not
        // only when a new declaration reaches the journal. Otherwise a forged
        // graph could place its period effect before its source verification.
        let finals: Vec<_> = self
            .tasks
            .iter()
            .filter(|task| matches!(task.action, CloseTaskBodyAction::PeriodTransition { .. }))
            .collect();
        if finals.len() > 1 {
            return Err(invalid("close_run.multiple_final_transitions"));
        }
        if let Some(terminal) = finals.first()
            && ancestors_of(terminal)?
                .into_iter()
                .filter(|ancestor| *ancestor)
                .count()
                + 1
                != self.tasks.len()
        {
            return Err(invalid("close_run.final_transition_must_follow_all_tasks"));
        }
        let bytes = self
            .canonical_bytes()
            .map_err(|_| invalid("close_run.bytes"))?;
        bounded_bytes(&bytes)
    }

    /// Validate before encoding caller-constructed values; decoding validates.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.u16(CLOSE_RUN_VERSION)
            .fixed(&self.book_id.0)
            .str(&self.name)
            .str(&self.period)
            .u128(self.owner.0)
            .list(&self.tasks, |w, task| task.encode(w));
        w.finish()
    }

    pub fn digest(&self) -> Result<[u8; 32], EncodeError> {
        Ok(domain_digest(
            CLOSE_RUN_DIGEST_DOMAIN,
            &[&self.canonical_bytes()?],
        ))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        bounded_bytes(bytes)?;
        let mut r = Reader::new(bytes);
        if r.u16("close_run.version")? != CLOSE_RUN_VERSION {
            return Err(r.invalid("close_run.version"));
        }
        let body = Self {
            book_id: Id128(r.fixed("close_run.book_id")?),
            name: r
                .str(MAX_CLOSE_RUN_TEXT_BYTES, "close_run.name")?
                .to_string(),
            period: r
                .str(MAX_CLOSE_RUN_TEXT_BYTES, "close_run.period")?
                .to_string(),
            owner: VId(r.u128("close_run.owner")?),
            tasks: r.list(MAX_CLOSE_RUN_TASKS, "close_run.tasks", CloseTaskBody::read)?,
        };
        r.finish()?;
        body.validate()?;
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> CloseRunBody {
        CloseRunBody {
            book_id: Id128([3; 16]),
            name: "march".into(),
            period: "2026-03".into(),
            owner: VId(4),
            tasks: vec![
                CloseTaskBody {
                    id: "accrue".into(),
                    depends_on: vec![],
                    action: CloseTaskBodyAction::PromoteDraft {
                        draft: VId(5),
                        name: "march-accruals".into(),
                        owner: VId(4),
                        source_known_at: CommitSeq(7),
                        source_digest: [8; 32],
                        certificate_digest: [9; 32],
                        entries_digest: [10; 32],
                        entry_count: 1,
                    },
                },
                CloseTaskBody {
                    id: "close".into(),
                    depends_on: vec!["accrue".into()],
                    action: CloseTaskBodyAction::PeriodTransition { to: 3 },
                },
            ],
        }
    }

    #[test]
    fn task_graph_bytes_are_bounded_canonical_and_bind_rehearsal() {
        let body = body();
        body.validate().unwrap();
        let bytes = body.canonical_bytes().unwrap();
        assert_eq!(CloseRunBody::decode(&bytes).unwrap(), body);
        for end in 0..bytes.len() {
            assert!(CloseRunBody::decode(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(CloseRunBody::decode(&trailing).is_err());
        let mut future = bytes;
        future[0] = 2;
        assert!(CloseRunBody::decode(&future).is_err());
        for task in &body.tasks {
            assert_eq!(
                CloseTaskBody::decode(&task.canonical_bytes().unwrap()).unwrap(),
                *task
            );
        }
        let mut changed = body.clone();
        if let CloseTaskBodyAction::PromoteDraft {
            certificate_digest, ..
        } = &mut changed.tasks[0].action
        {
            certificate_digest[0] ^= 1;
        }
        assert_ne!(body.digest().unwrap(), changed.digest().unwrap());
        assert!(CloseRunBody::decode(&vec![0; MAX_CLOSE_RUN_BYTES + 1]).is_err());
    }

    #[test]
    fn invalid_or_ambiguous_task_graphs_do_not_decode() {
        let original = body();
        let mut variants = Vec::new();
        let mut duplicate = original.clone();
        duplicate.tasks[1].id = duplicate.tasks[0].id.clone();
        variants.push(duplicate);
        let mut missing = original.clone();
        missing.tasks[1].depends_on = vec!["missing".into()];
        variants.push(missing);
        let mut cycle = original.clone();
        cycle.tasks[0].depends_on = vec!["close".into()];
        variants.push(cycle);
        let mut self_edge = original.clone();
        self_edge.tasks[0].depends_on = vec!["accrue".into()];
        variants.push(self_edge);
        let mut duplicate_edge = original.clone();
        duplicate_edge.tasks[1].depends_on.push("accrue".into());
        variants.push(duplicate_edge);
        let mut unsorted = original.clone();
        unsorted.tasks.swap(0, 1);
        variants.push(unsorted);
        let mut backwards = original.clone();
        backwards.tasks[1].action = CloseTaskBodyAction::PeriodTransition { to: 1 };
        variants.push(backwards);
        let mut oversized = original;
        oversized.name = "x".repeat(MAX_CLOSE_RUN_TEXT_BYTES + 1);
        variants.push(oversized);
        for body in variants {
            assert!(body.validate().is_err());
            assert!(CloseRunBody::decode(&body.canonical_bytes().unwrap()).is_err());
        }
    }

    #[test]
    fn year_end_verification_is_canonical_and_follows_every_monetary_task() {
        let mut graph = body();
        graph.tasks.push(CloseTaskBody {
            id: "verify".into(),
            depends_on: vec!["accrue".into()],
            action: CloseTaskBodyAction::VerifyYearEndClose { fiscal_year: 2026 },
        });
        graph.tasks[1].depends_on = vec!["verify".into()];
        graph.validate().unwrap();
        assert_eq!(
            CloseRunBody::decode(&graph.canonical_bytes().unwrap()).unwrap(),
            graph
        );
        let original = graph.digest().unwrap();
        graph.tasks[2].action = CloseTaskBodyAction::VerifyYearEndClose { fiscal_year: 2027 };
        assert_ne!(graph.digest().unwrap(), original);

        let mut unordered = graph.clone();
        unordered.tasks[2].depends_on.clear();
        assert!(unordered.validate().is_err());
        assert!(CloseRunBody::decode(&unordered.canonical_bytes().unwrap()).is_err());
        let mut premature_terminal = graph.clone();
        premature_terminal.tasks[1].depends_on = vec!["accrue".into()];
        assert!(premature_terminal.validate().is_err());
        assert!(CloseRunBody::decode(&premature_terminal.canonical_bytes().unwrap()).is_err());
        let mut duplicated = graph.clone();
        duplicated.tasks.push(CloseTaskBody {
            id: "verify-again".into(),
            depends_on: vec!["verify".into()],
            action: CloseTaskBodyAction::VerifyYearEndClose { fiscal_year: 2027 },
        });
        assert!(duplicated.validate().is_err());

        // Depending on the last draft is sufficient only when that draft's
        // own dependency path contains all the preceding monetary work.
        let mut transitive = graph;
        let mut second = transitive.tasks[0].clone();
        second.id = "second".into();
        second.depends_on = vec!["accrue".into()];
        transitive.tasks.insert(2, second);
        transitive.tasks[3].depends_on = vec!["second".into()];
        transitive.validate().unwrap();
        transitive.tasks[2].depends_on.clear();
        assert!(transitive.validate().is_err());
    }
}
