//! `registries/scoreboard.toml` — Vision workflows (`README.md §Quick example` +
//! plan §15.6 five readers) and convergence gate criteria (plan §19: `G0`,
//! `Genesis`, `G1`–`G4`) (beads `fa-e9z`, `fa-7s6d`).
//!
//! Laws enforced at load time:
//! - `schema_version` is 1.
//! - Workflows match [`WORKFLOW_IDS`] in order and each has at least one step
//!   with dense 1-based ordinals (`1..=k`).
//! - Workflow steps have unique IDs, dense vision-checklist rows `VC-01`..`VC-30`,
//!   non-empty `description` and `argv`, and a valid expectation:
//!   - `works`: `expected_exit == 0`, no `refusal_id`, no `bead`;
//!   - `refused`: `expected_exit != 0` (registered in `exit_codes.toml`),
//!     `expected_event == "error"`, `refusal_id` present in `refusal_catalog.toml`,
//!     and `bead` naming an `fa-...` bead;
//!   - `absent`: `expected_exit == 2`, `expected_event == "error"`, no
//!     `refusal_id`, and `bead` naming an `fa-...` bead.
//! - Gate criteria cover every gate in [`GATE_NAMES`] (`G0`, `Genesis`, `G1`,
//!   `G2`, `G3`, `G4`) with unique IDs, valid `probe_kind` (`cli` | `registry`),
//!   and the same expectation laws.

use std::collections::{BTreeMap, BTreeSet};

use crate::refusal_catalog::RefusalCatalog;
use crate::toml::{Table, Value};
use crate::{ExitCodes, RegistryError, invalid, load, req_int, req_str};

const REGISTRY: &str = "scoreboard.toml";
const SCOREBOARD: &str = include_str!("../../../registries/scoreboard.toml");

/// The seven canonical vision workflow IDs (README Quick Example + §15.6).
pub const WORKFLOW_IDS: [&str; 7] = [
    "readme-quick",
    "agent-closes-month",
    "cpa-audits-fy2025",
    "fdic-examiner-positions",
    "trustee-receiver-takeover",
    "litigation-consultant-damages",
    "investigator-traces-funds",
];

/// The six convergence gates from plan §19, in order.
pub const GATE_NAMES: [&str; 6] = ["G0", "Genesis", "G1", "G2", "G3", "G4"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepExpectation {
    Works,
    Refused { refusal_id: String, bead: String },
    Absent { bead: String },
}

impl StepExpectation {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Works => "works",
            Self::Refused { .. } => "refused",
            Self::Absent { .. } => "absent",
        }
    }

    #[must_use]
    pub fn bead(&self) -> Option<&str> {
        match self {
            Self::Works => None,
            Self::Refused { bead, .. } | Self::Absent { bead } => Some(bead.as_str()),
        }
    }

    #[must_use]
    pub fn refusal_id(&self) -> Option<&str> {
        match self {
            Self::Refused { refusal_id, .. } => Some(refusal_id.as_str()),
            Self::Works | Self::Absent { .. } => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workflow {
    pub id: String,
    pub name: String,
    pub plan_ref: String,
    pub reader: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowStep {
    pub id: String,
    pub workflow: String,
    pub ordinal: u32,
    pub vision_row: String,
    pub description: String,
    pub argv: Vec<String>,
    pub expected: StepExpectation,
    pub expected_exit: u8,
    pub expected_event: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeKind {
    Cli,
    Registry,
}

impl ProbeKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Registry => "registry",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateCriterion {
    pub id: String,
    pub gate: String,
    pub criterion: String,
    pub probe_kind: ProbeKind,
    pub argv: Vec<String>,
    pub expected: StepExpectation,
    pub expected_exit: u8,
    pub expected_event: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scoreboard {
    pub schema_version: u32,
    pub workflows: Vec<Workflow>,
    pub steps: Vec<WorkflowStep>,
    pub gate_criteria: Vec<GateCriterion>,
}

fn check_non_empty(what: &str, field: &str, value: &str) -> Result<(), RegistryError> {
    if value.trim().is_empty() {
        return Err(invalid(REGISTRY, format!("{what} `{field}` is empty")));
    }
    Ok(())
}

fn check_bead_id(what: &str, bead: &str) -> Result<(), RegistryError> {
    if !bead.starts_with("fa-")
        || bead.len() < 5
        || !bead[3..]
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(invalid(
            REGISTRY,
            format!("{what}: invalid bead id `{bead}` (expected `fa-<id>`)"),
        ));
    }
    Ok(())
}

fn req_str_array(t: &Table, key: &str, what: &str) -> Result<Vec<String>, RegistryError> {
    let arr = t
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(REGISTRY, format!("{what}: missing array `{key}`")))?;
    if arr.is_empty() {
        return Err(invalid(
            REGISTRY,
            format!("{what}: `{key}` cannot be empty"),
        ));
    }
    let mut out = Vec::with_capacity(arr.len());
    for v in arr {
        let s = v.as_str().ok_or_else(|| {
            invalid(
                REGISTRY,
                format!("{what}: `{key}` elements must be strings"),
            )
        })?;
        check_non_empty(what, key, s)?;
        out.push(s.to_string());
    }
    Ok(out)
}

fn parse_expectation(
    t: &Table,
    what: &str,
    expected_exit: u8,
    expected_event: &str,
    exits: &ExitCodes,
    refusals: &RefusalCatalog,
) -> Result<StepExpectation, RegistryError> {
    if !exits.rows.iter().any(|r| r.code == expected_exit) {
        return Err(invalid(
            REGISTRY,
            format!("{what}: `expected_exit = {expected_exit}` is not in exit_codes.toml"),
        ));
    }
    let exp = req_str(REGISTRY, t, "expected")?;
    let refusal_id = t.get("refusal_id").and_then(Value::as_str);
    let bead = t.get("bead").and_then(Value::as_str);
    match exp {
        "works" => {
            if expected_exit != 0 {
                return Err(invalid(
                    REGISTRY,
                    format!("{what}: `expected = \"works\"` requires `expected_exit = 0`"),
                ));
            }
            if expected_event == "error" {
                return Err(invalid(
                    REGISTRY,
                    format!("{what}: `expected = \"works\"` cannot expect event `error`"),
                ));
            }
            if refusal_id.is_some() || bead.is_some() {
                return Err(invalid(
                    REGISTRY,
                    format!("{what}: `expected = \"works\"` must not carry `refusal_id` or `bead`"),
                ));
            }
            Ok(StepExpectation::Works)
        }
        "refused" => {
            if expected_exit == 0 {
                return Err(invalid(
                    REGISTRY,
                    format!("{what}: `expected = \"refused\"` requires non-zero `expected_exit`"),
                ));
            }
            if expected_event != "error" {
                return Err(invalid(
                    REGISTRY,
                    format!(
                        "{what}: `expected = \"refused\"` requires `expected_event = \"error\"`"
                    ),
                ));
            }
            let r_id = refusal_id.ok_or_else(|| {
                invalid(
                    REGISTRY,
                    format!("{what}: `expected = \"refused\"` requires `refusal_id`"),
                )
            })?;
            let Some(refusal) = refusals.by_code(r_id) else {
                return Err(invalid(
                    REGISTRY,
                    format!("{what}: unknown `refusal_id` `{r_id}` (not in refusal_catalog.toml)"),
                ));
            };
            if refusal.exit != expected_exit {
                return Err(invalid(
                    REGISTRY,
                    format!(
                        "{what}: `refusal_id = \"{r_id}\"` has exit {} in refusal_catalog.toml, not {expected_exit}",
                        refusal.exit
                    ),
                ));
            }
            let b = bead.ok_or_else(|| {
                invalid(
                    REGISTRY,
                    format!("{what}: `expected = \"refused\"` requires `bead`"),
                )
            })?;
            check_bead_id(what, b)?;
            Ok(StepExpectation::Refused {
                refusal_id: r_id.to_string(),
                bead: b.to_string(),
            })
        }
        "absent" => {
            if expected_exit != 2 {
                return Err(invalid(
                    REGISTRY,
                    format!("{what}: `expected = \"absent\"` requires `expected_exit = 2`"),
                ));
            }
            if expected_event != "error" {
                return Err(invalid(
                    REGISTRY,
                    format!(
                        "{what}: `expected = \"absent\"` requires `expected_event = \"error\"`"
                    ),
                ));
            }
            if refusal_id.is_some() {
                return Err(invalid(
                    REGISTRY,
                    format!("{what}: `expected = \"absent\"` must not carry `refusal_id`"),
                ));
            }
            let b = bead.ok_or_else(|| {
                invalid(
                    REGISTRY,
                    format!("{what}: `expected = \"absent\"` requires `bead`"),
                )
            })?;
            check_bead_id(what, b)?;
            Ok(StepExpectation::Absent {
                bead: b.to_string(),
            })
        }
        other => Err(invalid(
            REGISTRY,
            format!(
                "{what}: unknown `expected = \"{other}\"` (expected `works`, `refused`, or `absent`)"
            ),
        )),
    }
}

impl Scoreboard {
    /// Load and validate the embedded `registries/scoreboard.toml`.
    pub fn embedded() -> Result<Self, RegistryError> {
        let exits = ExitCodes::embedded()?;
        let refusals = RefusalCatalog::embedded()?;
        Self::parse(SCOREBOARD, &exits, &refusals)
    }

    /// Parse `text` as `scoreboard.toml` and cross-check exit codes and refusal IDs.
    pub fn parse(
        text: &str,
        exits: &ExitCodes,
        refusals: &RefusalCatalog,
    ) -> Result<Self, RegistryError> {
        let doc = load(REGISTRY, text)?;
        let v = req_int(REGISTRY, &doc.root, "schema_version")?;
        if v != 1 {
            return Err(invalid(
                REGISTRY,
                format!("unsupported schema_version {v} (expected 1)"),
            ));
        }

        let empty: Vec<Table> = Vec::new();
        let wf_tables = doc.arrays.get("workflow").unwrap_or(&empty);
        if wf_tables.len() != WORKFLOW_IDS.len() {
            return Err(invalid(
                REGISTRY,
                format!(
                    "expected {} workflows, found {}",
                    WORKFLOW_IDS.len(),
                    wf_tables.len()
                ),
            ));
        }
        let mut workflows = Vec::with_capacity(wf_tables.len());
        let mut wf_ids = BTreeSet::new();
        for (idx, t) in wf_tables.iter().enumerate() {
            let id = req_str(REGISTRY, t, "id")?.to_string();
            let expected_id = WORKFLOW_IDS[idx];
            if id != expected_id {
                return Err(invalid(
                    REGISTRY,
                    format!(
                        "workflow #{}: expected id `{expected_id}`, got `{id}`",
                        idx + 1
                    ),
                ));
            }
            let name = req_str(REGISTRY, t, "name")?.to_string();
            let plan_ref = req_str(REGISTRY, t, "plan_ref")?.to_string();
            let reader = req_str(REGISTRY, t, "reader")?.to_string();
            for (k, val) in [
                ("name", &name),
                ("plan_ref", &plan_ref),
                ("reader", &reader),
            ] {
                check_non_empty(&format!("workflow {id}"), k, val)?;
            }
            wf_ids.insert(id.clone());
            workflows.push(Workflow {
                id,
                name,
                plan_ref,
                reader,
            });
        }

        let step_tables = doc.arrays.get("workflow_step").unwrap_or(&empty);
        if step_tables.is_empty() {
            return Err(invalid(REGISTRY, "no `[[workflow_step]]` rows defined"));
        }
        let mut steps = Vec::with_capacity(step_tables.len());
        let mut step_ids = BTreeSet::new();
        let mut per_wf_ordinals: BTreeMap<String, Vec<u32>> = BTreeMap::new();
        for (idx, t) in step_tables.iter().enumerate() {
            let id = req_str(REGISTRY, t, "id")?.to_string();
            check_non_empty("workflow_step", "id", &id)?;
            if !step_ids.insert(id.clone()) {
                return Err(invalid(
                    REGISTRY,
                    format!("duplicate workflow_step id `{id}`"),
                ));
            }
            let what = format!("workflow_step {id}");
            let workflow = req_str(REGISTRY, t, "workflow")?.to_string();
            if !wf_ids.contains(&workflow) {
                return Err(invalid(
                    REGISTRY,
                    format!("{what}: unknown workflow `{workflow}`"),
                ));
            }
            let ord_raw = req_int(REGISTRY, t, "ordinal")?;
            let ordinal = u32::try_from(ord_raw)
                .map_err(|_| invalid(REGISTRY, format!("{what}: invalid ordinal {ord_raw}")))?;
            per_wf_ordinals
                .entry(workflow.clone())
                .or_default()
                .push(ordinal);
            let vision_row = req_str(REGISTRY, t, "vision_row")?.to_string();
            let expected_vc = format!("VC-{:02}", idx + 1);
            if vision_row != expected_vc {
                return Err(invalid(
                    REGISTRY,
                    format!("{what}: expected vision_row `{expected_vc}`, got `{vision_row}`"),
                ));
            }
            let description = req_str(REGISTRY, t, "description")?.to_string();
            check_non_empty(&what, "description", &description)?;
            let argv = req_str_array(t, "argv", &what)?;
            let exit_raw = req_int(REGISTRY, t, "expected_exit")?;
            let expected_exit = u8::try_from(exit_raw).map_err(|_| {
                invalid(
                    REGISTRY,
                    format!("{what}: invalid expected_exit {exit_raw}"),
                )
            })?;
            let expected_event = req_str(REGISTRY, t, "expected_event")?.to_string();
            check_non_empty(&what, "expected_event", &expected_event)?;
            let expected =
                parse_expectation(t, &what, expected_exit, &expected_event, exits, refusals)?;
            steps.push(WorkflowStep {
                id,
                workflow,
                ordinal,
                vision_row,
                description,
                argv,
                expected,
                expected_exit,
                expected_event,
            });
        }

        for wf in &workflows {
            let Some(ords) = per_wf_ordinals.get(&wf.id) else {
                return Err(invalid(
                    REGISTRY,
                    format!("workflow `{}` has no steps", wf.id),
                ));
            };
            let expected_ords: Vec<u32> = (1..=u32::try_from(ords.len()).unwrap_or(0)).collect();
            if *ords != expected_ords {
                return Err(invalid(
                    REGISTRY,
                    format!(
                        "workflow `{}` ordinals {:?} are not dense 1..={}",
                        wf.id,
                        ords,
                        ords.len()
                    ),
                ));
            }
        }

        let gc_tables = doc.arrays.get("gate_criterion").unwrap_or(&empty);
        if gc_tables.is_empty() {
            return Err(invalid(REGISTRY, "no `[[gate_criterion]]` rows defined"));
        }
        let mut gate_criteria = Vec::with_capacity(gc_tables.len());
        let mut gc_ids = BTreeSet::new();
        let mut gates_seen = BTreeSet::new();
        for t in gc_tables {
            let id = req_str(REGISTRY, t, "id")?.to_string();
            check_non_empty("gate_criterion", "id", &id)?;
            if !gc_ids.insert(id.clone()) {
                return Err(invalid(
                    REGISTRY,
                    format!("duplicate gate_criterion id `{id}`"),
                ));
            }
            let what = format!("gate_criterion {id}");
            let gate = req_str(REGISTRY, t, "gate")?.to_string();
            if !GATE_NAMES.contains(&gate.as_str()) {
                return Err(invalid(
                    REGISTRY,
                    format!("{what}: unknown gate `{gate}` (expected one of {GATE_NAMES:?})"),
                ));
            }
            gates_seen.insert(gate.clone());
            let criterion = req_str(REGISTRY, t, "criterion")?.to_string();
            check_non_empty(&what, "criterion", &criterion)?;
            let probe_kind = match req_str(REGISTRY, t, "probe_kind")? {
                "cli" => ProbeKind::Cli,
                "registry" => ProbeKind::Registry,
                other => {
                    return Err(invalid(
                        REGISTRY,
                        format!(
                            "{what}: unknown probe_kind `{other}` (expected `cli` or `registry`)"
                        ),
                    ));
                }
            };
            let argv = req_str_array(t, "argv", &what)?;
            let exit_raw = req_int(REGISTRY, t, "expected_exit")?;
            let expected_exit = u8::try_from(exit_raw).map_err(|_| {
                invalid(
                    REGISTRY,
                    format!("{what}: invalid expected_exit {exit_raw}"),
                )
            })?;
            let expected_event = req_str(REGISTRY, t, "expected_event")?.to_string();
            check_non_empty(&what, "expected_event", &expected_event)?;
            let expected =
                parse_expectation(t, &what, expected_exit, &expected_event, exits, refusals)?;
            gate_criteria.push(GateCriterion {
                id,
                gate,
                criterion,
                probe_kind,
                argv,
                expected,
                expected_exit,
                expected_event,
            });
        }

        for g in GATE_NAMES {
            if !gates_seen.contains(g) {
                return Err(invalid(
                    REGISTRY,
                    format!("gate `{g}` has no `[[gate_criterion]]` rows"),
                ));
            }
        }

        Ok(Self {
            schema_version: 1,
            workflows,
            steps,
            gate_criteria,
        })
    }

    /// Render the canonical Markdown scoreboard (`docs/VISION_AND_GATE_SCOREBOARD.md`).
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# FrankenAccounting Vision & Convergence Gate Scoreboard\n\n");
        out.push_str(
            "> Generated deterministically from [`registries/scoreboard.toml`](../registries/scoreboard.toml) ",
        );
        out.push_str(
            "and verified against the live `fa` binary by `crates/fa-cli/tests/scoreboard.rs` (beads `fa-e9z`, `fa-7s6d`).\n\n",
        );

        let wf_works = self
            .steps
            .iter()
            .filter(|s| matches!(s.expected, StepExpectation::Works))
            .count();
        let wf_refused = self
            .steps
            .iter()
            .filter(|s| matches!(s.expected, StepExpectation::Refused { .. }))
            .count();
        let wf_absent = self
            .steps
            .iter()
            .filter(|s| matches!(s.expected, StepExpectation::Absent { .. }))
            .count();
        let wf_total = self.steps.len();
        let wf_pct = (wf_works * 100) / wf_total.max(1);

        out.push_str("## 1. Vision Workflow Summary (README Quick Example + Plan §15.6)\n\n");
        out.push_str(&format!(
            "- **Total workflow steps:** {wf_total} (`works`: **{wf_works}** [{wf_pct}%], `refused`: **{wf_refused}**, `absent`: **{wf_absent}**)\n\n"
        ));
        out.push_str(
            "| Workflow | Plan Ref | Reader | Works | Refused | Absent | Total | Delivery % |\n",
        );
        out.push_str("|---|---|---|---:|---:|---:|---:|---:|\n");
        for wf in &self.workflows {
            let wf_steps: Vec<&WorkflowStep> =
                self.steps.iter().filter(|s| s.workflow == wf.id).collect();
            let w = wf_steps
                .iter()
                .filter(|s| matches!(s.expected, StepExpectation::Works))
                .count();
            let r = wf_steps
                .iter()
                .filter(|s| matches!(s.expected, StepExpectation::Refused { .. }))
                .count();
            let a = wf_steps
                .iter()
                .filter(|s| matches!(s.expected, StepExpectation::Absent { .. }))
                .count();
            let tot = wf_steps.len();
            let pct = (w * 100) / tot.max(1);
            out.push_str(&format!(
                "| `{}` ({}) | {} | {} | {} | {} | {} | {} | {}% |\n",
                wf.id, wf.name, wf.plan_ref, wf.reader, w, r, a, tot, pct
            ));
        }

        out.push_str("\n### Workflow Steps Detail\n\n");
        out.push_str("| Step | Vision Row | Workflow | Status | Exit | Event / Refusal | Bead | Description |\n");
        out.push_str("|---|---|---|---|---:|---|---|---|\n");
        for s in &self.steps {
            let ev_or_ref = match &s.expected {
                StepExpectation::Works => format!("`{}`", s.expected_event),
                StepExpectation::Refused { refusal_id, .. } => {
                    format!("`{}` (`{refusal_id}`)", s.expected_event)
                }
                StepExpectation::Absent { .. } => format!("`{}`", s.expected_event),
            };
            let bead = s.expected.bead().unwrap_or("—");
            out.push_str(&format!(
                "| `{}` | `{}` | `{}` | `{}` | `{}` | {} | `{}` | {} |\n",
                s.id,
                s.vision_row,
                s.workflow,
                s.expected.as_str(),
                s.expected_exit,
                ev_or_ref,
                bead,
                s.description
            ));
        }

        let gc_works = self
            .gate_criteria
            .iter()
            .filter(|c| matches!(c.expected, StepExpectation::Works))
            .count();
        let gc_refused = self
            .gate_criteria
            .iter()
            .filter(|c| matches!(c.expected, StepExpectation::Refused { .. }))
            .count();
        let gc_absent = self
            .gate_criteria
            .iter()
            .filter(|c| matches!(c.expected, StepExpectation::Absent { .. }))
            .count();
        let gc_total = self.gate_criteria.len();
        let gc_met = gc_works + gc_refused;
        let gc_pct = (gc_met * 100) / gc_total.max(1);

        out.push_str("\n## 2. Convergence Gate Scoreboard (Plan §19: G0, Genesis, G1–G4)\n\n");
        out.push_str(&format!(
            "- **Total gate criteria:** {gc_total} (`works`: **{gc_works}**, `refused` [lawful refusal]: **{gc_refused}**, `absent`: **{gc_absent}**; verified active: **{gc_met}/{gc_total}** [{gc_pct}%])\n\n"
        ));
        out.push_str("| Gate | Works | Lawful Refusal | Absent | Total | Verified Active % |\n");
        out.push_str("|---|---:|---:|---:|---:|---:|\n");
        for g in GATE_NAMES {
            let g_rows: Vec<&GateCriterion> =
                self.gate_criteria.iter().filter(|c| c.gate == g).collect();
            let w = g_rows
                .iter()
                .filter(|c| matches!(c.expected, StepExpectation::Works))
                .count();
            let r = g_rows
                .iter()
                .filter(|c| matches!(c.expected, StepExpectation::Refused { .. }))
                .count();
            let a = g_rows
                .iter()
                .filter(|c| matches!(c.expected, StepExpectation::Absent { .. }))
                .count();
            let tot = g_rows.len();
            let pct = ((w + r) * 100) / tot.max(1);
            out.push_str(&format!("| `{g}` | {w} | {r} | {a} | {tot} | {pct}% |\n"));
        }

        out.push_str("\n### Gate Criteria Detail\n\n");
        out.push_str(
            "| ID | Gate | Probe | Status | Exit | Event / Refusal | Bead | Criterion |\n",
        );
        out.push_str("|---|---|---|---|---:|---|---|---|\n");
        for c in &self.gate_criteria {
            let ev_or_ref = match &c.expected {
                StepExpectation::Works => format!("`{}`", c.expected_event),
                StepExpectation::Refused { refusal_id, .. } => {
                    format!("`{}` (`{refusal_id}`)", c.expected_event)
                }
                StepExpectation::Absent { .. } => format!("`{}`", c.expected_event),
            };
            let bead = c.expected.bead().unwrap_or("—");
            out.push_str(&format!(
                "| `{}` | `{}` | `{}` | `{}` | `{}` | {} | `{}` | {} |\n",
                c.id,
                c.gate,
                c.probe_kind.as_str(),
                c.expected.as_str(),
                c.expected_exit,
                ev_or_ref,
                bead,
                c.criterion
            ));
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_scoreboard_is_valid_and_covers_all_workflows_and_gates() {
        let sb = Scoreboard::embedded().expect("scoreboard.toml is valid");
        assert_eq!(sb.schema_version, 1);
        assert_eq!(sb.workflows.len(), WORKFLOW_IDS.len());
        assert_eq!(sb.steps.len(), 30);
        assert_eq!(sb.gate_criteria.len(), 18);
        let md = sb.render_markdown();
        assert!(md.contains("## 1. Vision Workflow Summary"));
        assert!(md.contains("## 2. Convergence Gate Scoreboard"));
    }

    #[test]
    fn planted_invalid_expectations_and_unknown_refusals_fail() {
        let exits = ExitCodes::embedded().expect("exit_codes.toml");
        let refusals = RefusalCatalog::embedded().expect("refusal_catalog.toml");

        let bad_refusal =
            SCOREBOARD.replace("refusal_id = \"FA-REF-001\"", "refusal_id = \"FA-REF-999\"");
        let err = Scoreboard::parse(&bad_refusal, &exits, &refusals)
            .expect_err("unknown refusal_id must fail")
            .to_string();
        assert!(err.contains("FA-REF-999"), "{err}");

        let missing_bead = SCOREBOARD.replace("bead = \"fa-i7e\"", "");
        let err = Scoreboard::parse(&missing_bead, &exits, &refusals)
            .expect_err("absent step without bead must fail")
            .to_string();
        assert!(err.contains("requires `bead`"), "{err}");
    }
}
