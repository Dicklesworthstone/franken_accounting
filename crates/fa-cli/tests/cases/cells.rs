//! P-cell sweeps through the real binary (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §3.3, §2.6 rule 6; bead fa-yugf.17, A7c).
//!
//! All cells of one entry are decided on one book by `fa post --dry-run`,
//! which admits exactly as a commit does for a Human principal. The book
//! replays its history up to the entry's step; before each transition of
//! the entry's period, the cells of the state it leaves are decided, and
//! past the entry's step the sweep drives the period itself (open,
//! soft-close, close, lock) through the states the remaining cells need.
//! The first cell of each distinct outcome is committed as its
//! representative (`fa commit --plan` for an admit, a real `fa post` for a
//! refusal), which must agree with its dry run (`commit_agrees=ok|fail`).
//! Every cell is posted under its own key, so a committed representative
//! never turns a later dry run into a retry.

use std::collections::BTreeSet;

use fa_oracles::cases::Case;
use fa_oracles::cases::book::{BranchAttribute, StepDef, StepKind};
use fa_oracles::cases::branch::{self, Enumeration};
use fa_oracles::cases::expect::{Expectation, Target};
use fa_oracles::cases::intent_json;
use fa_oracles::cases::log::StepRecord;
use fa_oracles::cases::stub;
use fa_oracles::cases::sweep::{PeriodState, SweepCell, SweepGroup, coresident as coresident_book};
use fa_oracles::cases::tiers::{Tier, tiers};
use fa_oracles::cases::verdict::{RowLine, RowVerdict, cell_label};
use fa_oracles::json::Json;

use super::evaluate::project;
use super::run::{BookRun, Call, reproduce, tmp};

fn s(x: &str) -> String {
    x.to_string()
}

/// A planted divergence (the negative test): extra arguments for the
/// commit of the representative of the cell with this key.
pub struct Plant {
    pub cell: Vec<String>,
    pub commit_args: Vec<String>,
}

/// One swept cell: its row, and the argv that reproduces it when it fails.
pub struct SweptCell {
    pub row: RowLine,
    pub reproduce: Option<String>,
}

/// One group's sweep: its cells in sweep order, the sweep book's step
/// records and its log lines.
pub struct Swept {
    pub cells: Vec<SweptCell>,
    pub steps: Vec<StepRecord>,
    pub lines: Vec<String>,
}

const fn next_state(s: PeriodState) -> Option<PeriodState> {
    match s {
        PeriodState::Future => Some(PeriodState::Open),
        PeriodState::Open => Some(PeriodState::SoftClosed),
        PeriodState::SoftClosed => Some(PeriodState::Closed),
        PeriodState::Closed => Some(PeriodState::Locked),
        PeriodState::Locked => None,
    }
}

/// The state a step moves `period` to, if it is one of its transitions.
fn transition_of(step: &StepDef, period: &str) -> Option<PeriodState> {
    if step.reference != period {
        return None;
    }
    match step.step_kind()? {
        StepKind::PeriodOpen => Some(PeriodState::Open),
        StepKind::PeriodSoftClose => Some(PeriodState::SoftClosed),
        StepKind::PeriodClose => Some(PeriodState::Closed),
        StepKind::PeriodLock => Some(PeriodState::Locked),
        _ => None,
    }
}

struct Sweeper<'r, 'c> {
    run: &'r mut BookRun<'c>,
    group: &'r SweepGroup,
    plant: Option<&'r Plant>,
    /// Outcomes already represented by a committed cell.
    represented: BTreeSet<String>,
    /// The unreviewed placeholder's oid, once added.
    unreviewed: Option<String>,
    out: Vec<SweptCell>,
}

impl Sweeper<'_, '_> {
    /// Decides every remaining cell of `state`, in order.
    fn decide_state(
        &mut self,
        cells: &mut std::collections::VecDeque<&SweepCell>,
        state: PeriodState,
    ) {
        while cells.front().is_some_and(|c| c.state == state) {
            if let Some(c) = cells.pop_front() {
                self.decide(c, state);
            }
        }
    }

    /// The oid of an AgentUpload placeholder no one reviewed: a stub of its
    /// own (`<fact>~unreviewed`), since the entry's placeholder is reviewed
    /// and a document's identity is its bytes.
    fn unreviewed_placeholder(&mut self, fact: &str) -> Option<String> {
        if self.unreviewed.is_none() {
            let bytes = stub::placeholder(&format!("{fact}~unreviewed"));
            let file = self.run.write(&format!("{fact}-unreviewed.stub"), &bytes);
            let call = self.run.call(
                0,
                &format!("{fact}~unreviewed"),
                "document",
                vec![
                    s("document"),
                    s("add"),
                    file,
                    s("--kind"),
                    s("Other"),
                    s("--json"),
                ],
            );
            self.unreviewed = call.str_field("document", "oid");
        }
        self.unreviewed.clone()
    }

    fn decide(&mut self, cell: &SweepCell, state: PeriodState) {
        let book = self.run.book;
        let pairs: Vec<(String, String)> = cell
            .attrs
            .iter()
            .zip(&cell.key)
            .map(|(a, v)| (a.as_str().to_string(), v.clone()))
            .collect();
        let mut row = RowLine {
            verdict: RowVerdict::Unrun,
            id: cell.expectation.clone(),
            kind: "P".into(),
            variant: self.group.variant.clone(),
            target: Some(cell.target.clone()),
            cell: cell_label(&pairs),
            projection: Vec::new(),
            reason: None,
        };
        let Some(it) = book.intents.iter().find(|i| i.id == self.group.intent) else {
            row.verdict = RowVerdict::Fail;
            row.reason = Some(format!(
                "expected intent {} observed none",
                self.group.intent
            ));
            self.out.push(SweptCell {
                row,
                reproduce: None,
            });
            return;
        };
        let mut intent = it.clone();
        intent.idempotency_key = Some(cell.idempotency_key.clone());
        let mut evidence = it
            .evidence
            .as_deref()
            .and_then(|e| self.run.documents.get(e).cloned());
        for (attr, value) in cell.attrs.iter().zip(&cell.key) {
            match attr {
                BranchAttribute::EntryClass => intent.class.clone_from(value),
                BranchAttribute::PeriodStateAtCommit => {}
                BranchAttribute::EvidenceAttached => match value.as_str() {
                    "none" => evidence = None,
                    "placeholder_reviewed" => {}
                    "placeholder_unreviewed" => {
                        evidence = self.unreviewed_placeholder(&it.fact);
                    }
                    other => {
                        row.reason = Some(format!("needs:A7c (evidence_attached={other} cells)"));
                        self.out.push(SweptCell {
                            row,
                            reproduce: None,
                        });
                        return;
                    }
                },
                other => {
                    row.reason = Some(format!("needs:A7c ({} cells)", other.as_str()));
                    self.out.push(SweptCell {
                        row,
                        reproduce: None,
                    });
                    return;
                }
            }
        }
        row.projection.push(("state".into(), state.as_str().into()));
        let vids = self.run.vids.clone();
        let doc = match intent_json::render(book, &intent, &|t| vids.get(t).cloned()) {
            Ok(doc) => doc,
            Err(e) => {
                row.verdict = RowVerdict::Fail;
                row.reason = Some(format!(
                    "expected the cell's intent to render observed {e:?}"
                ));
                self.out.push(SweptCell {
                    row,
                    reproduce: None,
                });
                return;
            }
        };
        let name = format!("{}.json", cell.idempotency_key);
        let file = self.run.write(&name, doc.to_string().as_bytes());
        let plan = self.run.work.join(format!("{}.plan", cell.idempotency_key));
        let post_args = |extra: &[String], dry: bool| {
            let mut args = vec![
                s("post"),
                s("--intent"),
                file.clone(),
                s("--as"),
                intent.principal.clone(),
            ];
            if dry {
                args.extend([s("--dry-run"), s("--plan-out"), plan.display().to_string()]);
            }
            if let Some(e) = &evidence {
                args.extend([s("--evidence"), e.clone()]);
            }
            args.extend(extra.iter().cloned());
            args.push(s("--json"));
            args
        };
        let reference = format!("{}/{}", cell.target, row.cell);
        let dry = self.run.call(0, &reference, "post", post_args(&[], true));
        let observed = outcome(&dry);
        row.projection.push(("refusal".into(), observed.clone()));
        row.projection.push(("exit".into(), dry.exit.to_string()));
        if !cell.record_consistent {
            row.projection
                .push(("record_consistent".into(), "false".into()));
        }
        let mut fails: Vec<String> = Vec::new();
        let mut repro: Vec<String> = Vec::new();
        if self.represented.insert(observed.clone()) {
            let extra: Vec<String> = self
                .plant
                .filter(|p| p.cell == cell.key)
                .map(|p| p.commit_args.clone())
                .unwrap_or_default();
            let committed = if observed == "admitted" {
                let mut args = vec![
                    s("commit"),
                    s("--plan"),
                    plan.display().to_string(),
                    s("--as"),
                    intent.principal.clone(),
                ];
                args.extend(extra);
                args.push(s("--json"));
                self.run.call(0, &reference, "commit", args)
            } else {
                self.run
                    .call(0, &reference, "post", post_args(&extra, false))
            };
            let agrees = outcome(&committed) == observed;
            row.projection.push((
                "commit_agrees".into(),
                if agrees { "ok" } else { "fail" }.into(),
            ));
            if !agrees {
                fails.push(format!(
                    "expected {observed} observed {}",
                    outcome(&committed)
                ));
                repro.push(reproduce(&committed));
            }
        }
        if fails.is_empty()
            && let Some(want) = cell.expect.as_deref()
        {
            let want = if want == "admit" { "admitted" } else { want };
            if want != observed {
                fails.push(format!(
                    "expected refusal={want} observed refusal={observed}"
                ));
                repro.push(reproduce(&dry));
            }
        }
        if fails.is_empty() {
            row.reason = Some(match (&cell.pending, &cell.expect) {
                (Some(p), _) => p.clone(),
                (None, None) => "needs:A5b (the cell's authored outcome)".into(),
                (None, Some(_)) => "reference".into(),
            });
        } else {
            row.verdict = RowVerdict::Fail;
            row.reason = Some(fails.join("; "));
        }
        self.out.push(SweptCell {
            row,
            reproduce: (!repro.is_empty()).then(|| repro.join("\n")),
        });
    }
}

/// A call's outcome: `admitted`, its refusal id, or its exit.
fn outcome(call: &Call) -> String {
    if call.exit == 0 {
        return "admitted".into();
    }
    call.refusal_id()
        .unwrap_or_else(|| format!("exit={}", call.exit))
}

/// Sweeps one entry's cells on a book of its own.
pub fn sweep<'c>(
    case: &'c Case,
    group: &SweepGroup,
    texts: &'c [(&'c str, &'c str)],
    plant: Option<&Plant>,
) -> Swept {
    let book = case.books.get(&group.variant).expect("the variant");
    let work = tmp(&format!("{}-sweep-{}", case.header.id, group.intent));
    let mut run = BookRun::new(case, book, work, texts);
    run.build();
    let it = book.intents.iter().find(|i| i.id == group.intent);
    let period = it
        .and_then(|it| book.periods.iter().find(|p| p.contains(&it.effective_date)))
        .map(|p| p.code.clone())
        .unwrap_or_default();
    let entry_seq = book
        .steps
        .iter()
        .find(|s| s.step_kind() == Some(StepKind::Intent) && s.reference == group.intent)
        .map_or(i128::MAX, |s| s.seq);
    // The history's own principals for the transitions it lacks.
    let closer = book
        .steps
        .iter()
        .find(|s| transition_of(s, &s.reference).is_some() && s.principal.is_some())
        .and_then(|s| s.principal.clone());
    let approvers = book
        .steps
        .iter()
        .find(|s| s.step_kind() == Some(StepKind::PeriodLock))
        .and_then(|s| s.approvers.clone());
    let mut cells: std::collections::VecDeque<&SweepCell> = group.cells.iter().collect();
    let mut sw = Sweeper {
        run: &mut run,
        group,
        plant,
        represented: BTreeSet::new(),
        unreviewed: None,
        out: Vec::new(),
    };
    let mut state = PeriodState::Future;
    for step in &book.steps {
        if sw.run.failure.is_some() || step.seq >= entry_seq {
            break;
        }
        if let Some(next) = transition_of(step, &period) {
            sw.decide_state(&mut cells, state);
            sw.run.step(step);
            state = next;
        } else {
            sw.run.step(step);
        }
    }
    let mut stuck: Option<String> = sw.run.failure.clone();
    while stuck.is_none() && !cells.is_empty() {
        sw.decide_state(&mut cells, state);
        let Some(front) = cells.front().map(|c| c.state) else {
            break;
        };
        if front < state {
            stuck = Some(format!(
                "a {} cell after the history left {}",
                front.as_str(),
                state.as_str()
            ));
            break;
        }
        let Some(next) = next_state(state) else {
            break;
        };
        let kind = match next {
            PeriodState::Open => "period_open",
            PeriodState::SoftClosed => "period_soft_close",
            PeriodState::Closed => "period_close",
            _ => "period_lock",
        };
        if next == PeriodState::Locked && approvers.is_none() {
            stuck = Some("needs:A7c (a period_lock step whose approvers the sweep reuses)".into());
            break;
        }
        let synthetic = StepDef {
            seq: entry_seq,
            kind: kind.into(),
            reference: period.clone(),
            known_at: None,
            branch_class: None,
            principal: closer.clone(),
            approvers: approvers.clone(),
            params: None,
            evidence: None,
            asserts: None,
            document: None,
            line: None,
        };
        let before = sw.run.steps.len();
        sw.run.step(&synthetic);
        if sw.run.steps[before..].iter().any(|r| r.exit != 0) {
            stuck = Some(format!(
                "expected the sweep's {kind} of {period} observed a refused transition"
            ));
            break;
        }
        state = next;
    }
    let mut out = std::mem::take(&mut sw.out);
    // Cells the sweep could not reach are UNRUN (a transition the history
    // gives no principal for) or FAIL (a refused transition), never dropped.
    for c in cells {
        let pairs: Vec<(String, String)> = c
            .attrs
            .iter()
            .zip(&c.key)
            .map(|(a, v)| (a.as_str().to_string(), v.clone()))
            .collect();
        let why = stuck.clone().unwrap_or_else(|| "the sweep ended".into());
        out.push(SweptCell {
            row: RowLine {
                verdict: if why.starts_with("needs:") {
                    RowVerdict::Unrun
                } else {
                    RowVerdict::Fail
                },
                id: c.expectation.clone(),
                kind: "P".into(),
                variant: group.variant.clone(),
                target: Some(c.target.clone()),
                cell: cell_label(&pairs),
                projection: vec![("state".into(), c.state.as_str().into())],
                reason: Some(why),
            },
            reproduce: None,
        });
    }
    Swept {
        cells: out,
        steps: std::mem::take(&mut run.steps),
        lines: std::mem::take(&mut run.lines),
    }
}

/// One D target's branch cells (§3.3): for a tier L or C reader, every cell
/// is a copy of the target posted beside it in one book (each the others'
/// filler); for any other tier, each cell gets a book of its own. The
/// history's own run of the procedure reads them, and each cell is compared
/// with its authored `[[branch_cell]]` row: FAIL on any disagreement, else
/// UNRUN filler_invariance (A11a), or needs:A5b with no authored row.
pub fn d_cells<'c>(
    case: &'c Case,
    e: &Expectation,
    t: &Target,
    texts: &'c [(&'c str, &'c str)],
) -> Swept {
    let variant = e.fields.str("book_variant").unwrap_or_default().to_string();
    let procedure = e.fields.str("procedure").unwrap_or_default().to_string();
    let version = e.fields.int("version");
    let fail = |why: String| Swept {
        cells: vec![SweptCell {
            row: RowLine {
                verdict: RowVerdict::Fail,
                id: e.id.clone(),
                kind: "D".into(),
                variant: variant.clone(),
                target: Some(t.fact.clone()),
                cell: "default".into(),
                projection: Vec::new(),
                reason: Some(why),
            },
            reproduce: None,
        }],
        steps: Vec::new(),
        lines: Vec::new(),
    };
    let table = match branch::enumerate(case, e, t) {
        Ok(table) => table,
        Err(err) => return fail(format!("expected a branch table observed {err}")),
    };
    let coresident = tiers()
        .ok()
        .and_then(|tiers| {
            tiers
                .get(&procedure)
                .map(|r| matches!(r.tier, Tier::L | Tier::C))
        })
        .unwrap_or(false);
    // One table per book: all cells together, or one cell each.
    let tables: Vec<Enumeration> = if coresident {
        vec![table.clone()]
    } else {
        table
            .cells
            .iter()
            .map(|c| Enumeration {
                cells: vec![c.clone()],
                ..table.clone()
            })
            .collect()
    };
    let authored = case
        .expectations
        .as_ref()
        .map(|s| s.branch_cells.as_slice())
        .unwrap_or_default();
    let mut out = Swept {
        cells: Vec::new(),
        steps: Vec::new(),
        lines: Vec::new(),
    };
    for one in &tables {
        let (book, copies) = match coresident_book(case, &variant, one) {
            Ok(x) => x,
            Err(err) => return fail(err.to_string()),
        };
        let mut run = BookRun::new(
            case,
            &book,
            tmp(&format!("{}-dcells-{}", case.header.id, t.fact)),
            texts,
        );
        run.build();
        run.replay();
        for copy in &copies {
            let pairs: Vec<(String, String)> = table
                .attrs
                .iter()
                .zip(&copy.cell.key)
                .map(|(a, v)| (a.as_str().to_string(), v.clone()))
                .collect();
            let mut row = RowLine {
                verdict: RowVerdict::Unrun,
                id: e.id.clone(),
                kind: "D".into(),
                variant: variant.clone(),
                target: Some(t.fact.clone()),
                cell: cell_label(&pairs),
                projection: vec![(
                    "procedure".into(),
                    format!("{procedure}@{}", version.unwrap_or_default()),
                )],
                reason: None,
            };
            let observed = observe_copy(&run, &procedure, &copy.intent, &table.target);
            row.projection.extend(observed.tokens());
            let mut fails = Vec::new();
            if let Some(why) = &run.failure {
                fails.push(format!("expected the cells' book to build observed {why}"));
            }
            let want = authored
                .iter()
                .find(|a| a.expectation == e.id && a.target == t.fact && a.cell == copy.cell.key);
            match want {
                None if fails.is_empty() => {
                    row.reason = Some("needs:A5b (the cell's authored outcome)".into());
                }
                None => {}
                Some(a) => fails.extend(observed.disagreements(a)),
            }
            if !copy.cell.record_consistent {
                row.projection
                    .push(("record_consistent".into(), "false".into()));
            }
            if fails.is_empty() {
                row.reason.get_or_insert_with(|| "filler_invariance".into());
            } else {
                row.verdict = RowVerdict::Fail;
                row.reason = Some(fails.join("; "));
            }
            out.cells.push(SweptCell {
                row,
                reproduce: None,
            });
        }
        out.steps.append(&mut run.steps);
        out.lines
            .extend(run.lines.drain(..).filter(|l| !l.starts_with("PERIODS ")));
    }
    out
}

/// What the procedure's run shows of one cell copy.
struct Observed {
    run: bool,
    finding: bool,
    severity: String,
    statistic: String,
    cites: Vec<String>,
}

impl Observed {
    fn tokens(&self) -> Vec<(String, String)> {
        if !self.run {
            return vec![("finding".into(), "unrun".into())];
        }
        let mut t = vec![(
            "finding".into(),
            if self.finding { "yes" } else { "no" }.into(),
        )];
        if self.finding {
            t.push(("cite".into(), self.cites.join(",")));
            t.push(("severity".into(), self.severity.clone()));
            t.push(("statistic".into(), self.statistic.clone()));
        }
        t
    }

    /// Disagreements with an authored cell (`expect`, `cite`, `severity`,
    /// `statistic_value`).
    fn disagreements(&self, a: &fa_oracles::cases::expect::BranchCell) -> Vec<String> {
        let mut out = Vec::new();
        if !self.run {
            out.push("expected a recorded run observed none".into());
            return out;
        }
        let expect = a.fields.str("expect").unwrap_or("finding");
        let observed = if self.finding {
            "finding"
        } else {
            "no_finding"
        };
        if expect != observed {
            out.push(format!("expected {expect} observed {observed}"));
            return out;
        }
        if !self.finding {
            return out;
        }
        if let Some(want) = a.fields.str("severity")
            && want != self.severity
        {
            out.push(format!(
                "expected severity={want} observed severity={}",
                self.severity
            ));
        }
        if let Some(want) = a.fields.str("statistic_value")
            && want != self.statistic
        {
            out.push(format!(
                "expected statistic={want} observed statistic={}",
                self.statistic
            ));
        }
        if let Some(want) = a.fields.strs("cite") {
            let mut want: Vec<String> = want.to_vec();
            want.sort();
            if want != self.cites {
                out.push(format!(
                    "expected cite={} observed cite={}",
                    want.join(","),
                    self.cites.join(",")
                ));
            }
        }
        out
    }
}

/// The findings of `procedure` that cite the copy's entry, its leg cites
/// projected back to the target (`<target>#<ordinal>`).
fn observe_copy(run: &BookRun<'_>, procedure: &str, copy: &str, target: &str) -> Observed {
    let Some(found) = run.runs.get(procedure) else {
        return Observed {
            run: false,
            finding: false,
            severity: String::new(),
            statistic: String::new(),
            cites: Vec::new(),
        };
    };
    let hit = found
        .findings
        .iter()
        .map(|f| (f, project(run, f)))
        .find(|(_, p)| p.entries.contains(copy));
    let Some((f, p)) = hit else {
        return Observed {
            run: true,
            finding: false,
            severity: String::new(),
            statistic: String::new(),
            cites: Vec::new(),
        };
    };
    let mut cites: Vec<String> = p
        .cites
        .iter()
        .map(|c| match c.strip_prefix(copy) {
            Some(rest) if rest.starts_with('#') => format!("{target}{rest}"),
            _ => c.clone(),
        })
        .collect();
    cites.sort();
    Observed {
        run: true,
        finding: true,
        severity: f
            .get("severity")
            .and_then(Json::as_str)
            .unwrap_or("-")
            .to_string(),
        statistic: f
            .get("statistic")
            .and_then(|s| s.get("value"))
            .and_then(Json::as_int)
            .map_or_else(|| "-".into(), |v| v.to_string()),
        cites,
    }
}
