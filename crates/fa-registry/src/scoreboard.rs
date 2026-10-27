//! `registries/scoreboard.toml` v2 — Vision workflows (`README.md §Quick example` +
//! plan §15.6 five readers), verbatim convergence gate criteria (plan §19: `G0`,
//! `Genesis`, `G1`–`G4`), and governance integrity rows (beads `fa-e9z`,
//! `fa-7s6d`, `fa-ubl0`).
//!
//! Laws enforced at load time:
//! - `schema_version` is 2 and `section_19_digest` equals the BLAKE3 digest of
//!   plan §19 (`## 19. Workstreams and Convergence Gates`).
//! - Workflows match [`WORKFLOW_IDS`] in order and each has at least one step
//!   with dense 1-based ordinals (`1..=k`).
//! - Workflow steps have unique IDs, dense vision-checklist rows from `VC-01` in order,
//!   non-empty `description` and `argv`, and a valid expectation:
//!   - `works`: `expected_exit == 0`, no `refusal_id`, no `bead`;
//!   - `refused`: `expected_exit != 0` (registered in `exit_codes.toml`),
//!     `expected_event == "error"`, `refusal_id` present in `refusal_catalog.toml`,
//!     and `bead` naming an `fa-...` bead;
//!   - `absent`: `expected_exit == 2`, `expected_event == "error"`, no
//!     `refusal_id`, and `bead` naming an `fa-...` bead.
//! - Gate criteria transcribe every clause of plan §19 (`G0`, `Genesis`, `G1`,
//!   `G2`, `G3`, `G4`) verbatim (one row per clause, checked 1-to-1 against the
//!   embedded plan text), each with `evidence_class` and `probe_kind` in
//!   [`EvidenceClass`]. A row cannot be `works` or `refused` unless
//!   `probe_kind == evidence_class`, and a `works` row whose `evidence_class`
//!   requires a work-witness artifact (`lab-campaign`, `external-oracle`,
//!   `measurement`, `model`, `proof`, `agent-campaign`) must cite a verified
//!   `FA-ART-*` artifact of matching kind in `evidence_artifacts.toml`.
//! - Governance rows cover [`GOVERNANCE_METRICS`] (`closure_debt`,
//!   `verdict_freshness`, `tier0_coverage`) in order.

use std::collections::{BTreeMap, BTreeSet};

use crate::evidence_artifacts::{ArtifactKind, EvidenceArtifacts, blake3_hex};
use crate::refusal_catalog::RefusalCatalog;
use crate::toml::{Table, Value};
use crate::{ExitCodes, RegistryError, invalid, load, req_int, req_str};

const REGISTRY: &str = "scoreboard.toml";
const SCOREBOARD: &str = include_str!("../../../registries/scoreboard.toml");
const PLAN_MD: &str =
    include_str!("../../../COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md");

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

/// The three canonical governance integrity rows required by `fa-ubl0`.
pub const GOVERNANCE_METRICS: [&str; 3] = ["closure_debt", "verdict_freshness", "tier0_coverage"];

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

/// Evidence and probe class for a convergence gate criterion or governance row (`fa-ubl0`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceClass {
    Cli,
    Registry,
    LabCampaign,
    Differential,
    ExternalOracle,
    Measurement,
    Model,
    Proof,
    AgentCampaign,
}

/// Alias preserving compatibility with callers referencing `ProbeKind`.
pub type ProbeKind = EvidenceClass;

impl EvidenceClass {
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "cli" => Some(Self::Cli),
            "registry" => Some(Self::Registry),
            "lab-campaign" => Some(Self::LabCampaign),
            "differential" => Some(Self::Differential),
            "external-oracle" => Some(Self::ExternalOracle),
            "measurement" => Some(Self::Measurement),
            "model" => Some(Self::Model),
            "proof" => Some(Self::Proof),
            "agent-campaign" => Some(Self::AgentCampaign),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Registry => "registry",
            Self::LabCampaign => "lab-campaign",
            Self::Differential => "differential",
            Self::ExternalOracle => "external-oracle",
            Self::Measurement => "measurement",
            Self::Model => "model",
            Self::Proof => "proof",
            Self::AgentCampaign => "agent-campaign",
        }
    }

    /// Whether a `works` row of this evidence class requires a verified
    /// work-witness artifact in `evidence_artifacts.toml` (`fa-vtzt`).
    #[must_use]
    pub const fn requires_artifact(self) -> bool {
        matches!(
            self,
            Self::LabCampaign
                | Self::ExternalOracle
                | Self::Measurement
                | Self::Model
                | Self::Proof
                | Self::AgentCampaign
        )
    }

    /// Whether `kind` in `evidence_artifacts.toml` satisfies this evidence class.
    #[must_use]
    pub const fn matches_artifact_kind(self, kind: ArtifactKind) -> bool {
        matches!(
            (self, kind),
            (Self::LabCampaign, ArtifactKind::LabCampaign)
                | (Self::ExternalOracle, ArtifactKind::ExternalOracle)
                | (
                    Self::Measurement,
                    ArtifactKind::Benchmark | ArtifactKind::Calibration
                )
                | (Self::Model, ArtifactKind::Tlc)
                | (Self::Proof, ArtifactKind::Lean)
                | (Self::AgentCampaign, ArtifactKind::LabCampaign)
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateCriterion {
    pub id: String,
    pub gate: String,
    pub criterion: String,
    pub evidence_class: EvidenceClass,
    pub probe_kind: EvidenceClass,
    pub artifact: Option<String>,
    pub argv: Vec<String>,
    pub expected: StepExpectation,
    pub expected_exit: u8,
    pub expected_event: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernanceRow {
    pub id: String,
    pub metric: String,
    pub description: String,
    pub evidence_class: EvidenceClass,
    pub probe_kind: EvidenceClass,
    pub artifact: Option<String>,
    pub argv: Vec<String>,
    pub expected: StepExpectation,
    pub expected_exit: u8,
    pub expected_event: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scoreboard {
    pub schema_version: u32,
    pub section_19_digest: String,
    pub workflows: Vec<Workflow>,
    pub steps: Vec<WorkflowStep>,
    pub gate_criteria: Vec<GateCriterion>,
    pub governance_rows: Vec<GovernanceRow>,
}

fn check_non_empty(what: &str, field: &str, value: &str) -> Result<(), RegistryError> {
    if value.trim().is_empty() {
        return Err(invalid(REGISTRY, format!("{what} `{field}` is empty")));
    }
    Ok(())
}

fn check_bead_id(what: &str, bead: &str) -> Result<(), RegistryError> {
    // `fa-<id>`, optionally with numbered child suffixes (`fa-hlnd.1`,
    // `fa-yugf.16`): the tracker's ids for children of an epic.
    let mut parts = bead.split('.');
    let root = parts.next().unwrap_or_default();
    let root_ok = root.starts_with("fa-")
        && root.len() >= 5
        && root[3..]
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    let children_ok = parts.all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    if !root_ok || !children_ok {
        return Err(invalid(
            REGISTRY,
            format!("{what}: invalid bead id `{bead}` (expected `fa-<id>` or `fa-<id>.<n>`)"),
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

fn validate_evidence_and_probe(
    what: &str,
    evidence_class: EvidenceClass,
    probe_kind: EvidenceClass,
    expected: &StepExpectation,
    artifact: Option<&str>,
    artifacts: &EvidenceArtifacts,
) -> Result<(), RegistryError> {
    if probe_kind != evidence_class
        && matches!(
            expected,
            StepExpectation::Works | StepExpectation::Refused { .. }
        )
    {
        return Err(invalid(
            REGISTRY,
            format!(
                "{what}: proxy probe `probe_kind = \"{}\"` cannot satisfy `evidence_class = \"{}\"` for status `{}` (probe_kind must equal evidence_class)",
                probe_kind.as_str(),
                evidence_class.as_str(),
                expected.as_str()
            ),
        ));
    }
    if matches!(expected, StepExpectation::Works) && evidence_class.requires_artifact() {
        let art_id = artifact.ok_or_else(|| {
            invalid(
                REGISTRY,
                format!(
                    "{what}: `expected = \"works\"` with `evidence_class = \"{}\"` requires `artifact = \"FA-ART-...\"`",
                    evidence_class.as_str()
                ),
            )
        })?;
        let Some(art_row) = artifacts.get(art_id) else {
            return Err(invalid(
                REGISTRY,
                format!(
                    "{what}: cites unknown evidence artifact `{art_id}` (not in evidence_artifacts.toml)"
                ),
            ));
        };
        if !evidence_class.matches_artifact_kind(art_row.kind) {
            return Err(invalid(
                REGISTRY,
                format!(
                    "{what}: artifact `{art_id}` has kind `{}`, which does not satisfy `evidence_class = \"{}\"`",
                    art_row.kind.as_str(),
                    evidence_class.as_str()
                ),
            ));
        }
    }
    if let Some(art_id) = artifact
        && artifacts.get(art_id).is_none()
    {
        return Err(invalid(
            REGISTRY,
            format!(
                "{what}: cites unknown evidence artifact `{art_id}` (not in evidence_artifacts.toml)"
            ),
        ));
    }
    Ok(())
}

/// Extract the canonical §19 text (`## 19. Workstreams and Convergence Gates`)
/// and its ordered `(gate, criterion)` clauses from the plan markdown.
pub fn extract_plan_section_19(
    plan_text: &str,
) -> Result<(String, Vec<(String, String)>), RegistryError> {
    let start = plan_text
        .find("## 19. Workstreams and Convergence Gates\n")
        .ok_or_else(|| {
            invalid(
                REGISTRY,
                "plan markdown missing `## 19. Workstreams and Convergence Gates`",
            )
        })?;
    let rest = &plan_text[start..];
    let end_rel = rest
        .find("\n---\n\n## 20. Risks and Mitigations")
        .ok_or_else(|| {
            invalid(
                REGISTRY,
                "plan markdown missing `## 20. Risks and Mitigations` boundary after §19",
            )
        })?;
    let sec19 = format!("{}\n", rest[..end_rel].trim());
    let digest = blake3_hex(sec19.as_bytes());

    let gate_headers: [(&str, &str); 6] = [
        (
            "G0",
            "**Gate G0 — Constitutional Contracts (before any engine code):**",
        ),
        ("Genesis", "**The Genesis slice.**"),
        ("G1", "**Gate G1 — \"The Journal Lives\":**"),
        ("G2", "**Gate G2 — \"Time and Truth\":**"),
        ("G3", "**Gate G3 — \"Agents and Auditors\":**"),
        ("G4", "**Gate G4 — \"Published\":**"),
    ];
    let mut clauses = Vec::new();
    for (gate, prefix) in gate_headers {
        let line = sec19
            .lines()
            .find(|l| l.starts_with(prefix))
            .ok_or_else(|| {
                invalid(
                    REGISTRY,
                    format!("plan §19 missing paragraph starting with `{prefix}`"),
                )
            })?;
        if gate == "Genesis" {
            let marker = "It proves, end to end and under the lab: ";
            let (_, after) = line.split_once(marker).ok_or_else(|| {
                invalid(
                    REGISTRY,
                    "plan §19 Genesis paragraph missing `It proves, end to end and under the lab: `",
                )
            })?;
            let (body, _) = after.split_once(". No stub register").ok_or_else(|| {
                invalid(
                    REGISTRY,
                    "plan §19 Genesis paragraph missing `. No stub register` suffix",
                )
            })?;
            for item in body.split(" → ") {
                clauses.push((gate.to_string(), item.trim().to_string()));
            }
        } else {
            let (_, mut body) = line.split_once(":** ").ok_or_else(|| {
                invalid(
                    REGISTRY,
                    format!("plan §19 `{gate}` paragraph missing `:** ` delimiter"),
                )
            })?;
            if let Some(stripped) =
                body.strip_suffix(". No workstream may invent a missing semantic choice locally.")
            {
                body = stripped;
            } else if let Some(stripped) = body.strip_suffix('.') {
                body = stripped;
            }
            for item in body.split("; ") {
                clauses.push((gate.to_string(), item.trim().to_string()));
            }
        }
    }
    Ok((digest, clauses))
}

impl Scoreboard {
    /// Load and validate the embedded `registries/scoreboard.toml`.
    pub fn embedded() -> Result<Self, RegistryError> {
        let exits = ExitCodes::embedded()?;
        let refusals = RefusalCatalog::embedded()?;
        Self::parse(SCOREBOARD, &exits, &refusals)
    }

    /// Parse `text` as `scoreboard.toml` and cross-check exit codes, refusal IDs,
    /// evidence artifacts, and plan §19 transcription.
    pub fn parse(
        text: &str,
        exits: &ExitCodes,
        refusals: &RefusalCatalog,
    ) -> Result<Self, RegistryError> {
        let artifacts = EvidenceArtifacts::embedded()?;
        Self::parse_with_plan_and_artifacts(text, exits, refusals, &artifacts, PLAN_MD)
    }

    /// Parse `text` as `scoreboard.toml` against explicit `EvidenceArtifacts` and
    /// `plan_text` (used by unit and integration tests for planted negatives).
    pub fn parse_with_plan_and_artifacts(
        text: &str,
        exits: &ExitCodes,
        refusals: &RefusalCatalog,
        artifacts: &EvidenceArtifacts,
        plan_text: &str,
    ) -> Result<Self, RegistryError> {
        let doc = load(REGISTRY, text)?;
        let v = req_int(REGISTRY, &doc.root, "schema_version")?;
        if v != 2 {
            return Err(invalid(
                REGISTRY,
                format!("unsupported schema_version {v} (expected 2)"),
            ));
        }
        let section_19_digest = req_str(REGISTRY, &doc.root, "section_19_digest")?.to_string();
        check_non_empty("scoreboard", "section_19_digest", &section_19_digest)?;

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
            let ev_raw = req_str(REGISTRY, t, "evidence_class")?;
            let evidence_class = EvidenceClass::parse(ev_raw).ok_or_else(|| {
                invalid(
                    REGISTRY,
                    format!("{what}: unknown evidence_class `{ev_raw}`"),
                )
            })?;
            let pk_raw = req_str(REGISTRY, t, "probe_kind")?;
            let probe_kind = EvidenceClass::parse(pk_raw).ok_or_else(|| {
                invalid(REGISTRY, format!("{what}: unknown probe_kind `{pk_raw}`"))
            })?;
            let artifact = t
                .get("artifact")
                .and_then(Value::as_str)
                .map(str::to_string);
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
            validate_evidence_and_probe(
                &what,
                evidence_class,
                probe_kind,
                &expected,
                artifact.as_deref(),
                artifacts,
            )?;
            gate_criteria.push(GateCriterion {
                id,
                gate,
                criterion,
                evidence_class,
                probe_kind,
                artifact,
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

        let gov_tables = doc.arrays.get("governance_row").unwrap_or(&empty);
        if gov_tables.len() != GOVERNANCE_METRICS.len() {
            return Err(invalid(
                REGISTRY,
                format!(
                    "expected {} `[[governance_row]]` entries ({GOVERNANCE_METRICS:?}), found {}",
                    GOVERNANCE_METRICS.len(),
                    gov_tables.len()
                ),
            ));
        }
        let mut governance_rows = Vec::with_capacity(gov_tables.len());
        let mut gov_ids = BTreeSet::new();
        for (idx, t) in gov_tables.iter().enumerate() {
            let id = req_str(REGISTRY, t, "id")?.to_string();
            check_non_empty("governance_row", "id", &id)?;
            if !gov_ids.insert(id.clone()) {
                return Err(invalid(
                    REGISTRY,
                    format!("duplicate governance_row id `{id}`"),
                ));
            }
            let what = format!("governance_row {id}");
            let metric = req_str(REGISTRY, t, "metric")?.to_string();
            let expected_metric = GOVERNANCE_METRICS[idx];
            if metric != expected_metric {
                return Err(invalid(
                    REGISTRY,
                    format!("{what}: expected metric `{expected_metric}`, got `{metric}`"),
                ));
            }
            let description = req_str(REGISTRY, t, "description")?.to_string();
            check_non_empty(&what, "description", &description)?;
            let ev_raw = req_str(REGISTRY, t, "evidence_class")?;
            let evidence_class = EvidenceClass::parse(ev_raw).ok_or_else(|| {
                invalid(
                    REGISTRY,
                    format!("{what}: unknown evidence_class `{ev_raw}`"),
                )
            })?;
            let pk_raw = req_str(REGISTRY, t, "probe_kind")?;
            let probe_kind = EvidenceClass::parse(pk_raw).ok_or_else(|| {
                invalid(REGISTRY, format!("{what}: unknown probe_kind `{pk_raw}`"))
            })?;
            let artifact = t
                .get("artifact")
                .and_then(Value::as_str)
                .map(str::to_string);
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
            validate_evidence_and_probe(
                &what,
                evidence_class,
                probe_kind,
                &expected,
                artifact.as_deref(),
                artifacts,
            )?;
            governance_rows.push(GovernanceRow {
                id,
                metric,
                description,
                evidence_class,
                probe_kind,
                artifact,
                argv,
                expected,
                expected_exit,
                expected_event,
            });
        }

        let sb = Self {
            schema_version: 2,
            section_19_digest,
            workflows,
            steps,
            gate_criteria,
            governance_rows,
        };
        sb.verify_plan_section_19(plan_text)?;
        Ok(sb)
    }

    /// Verify that `self.section_19_digest` matches the BLAKE3 digest of §19 in
    /// `plan_text` and that `self.gate_criteria` transcribes every §19 clause
    /// verbatim in order.
    pub fn verify_plan_section_19(&self, plan_text: &str) -> Result<(), RegistryError> {
        let (actual_digest, plan_clauses) = extract_plan_section_19(plan_text)?;
        if self.section_19_digest != actual_digest {
            return Err(invalid(
                REGISTRY,
                format!(
                    "section_19_digest mismatch: scoreboard declares `{}`, plan §19 hashes to `{actual_digest}`",
                    self.section_19_digest
                ),
            ));
        }
        if self.gate_criteria.len() != plan_clauses.len() {
            return Err(invalid(
                REGISTRY,
                format!(
                    "plan §19 has {} clauses across G0/Genesis/G1–G4, but scoreboard declares {} `[[gate_criterion]]` rows",
                    plan_clauses.len(),
                    self.gate_criteria.len()
                ),
            ));
        }
        for (idx, (row, (expected_gate, expected_text))) in self
            .gate_criteria
            .iter()
            .zip(plan_clauses.iter())
            .enumerate()
        {
            if &row.gate != expected_gate || &row.criterion != expected_text {
                return Err(invalid(
                    REGISTRY,
                    format!(
                        "gate_criterion #{} (`{}`): expected gate `{expected_gate}` criterion `{expected_text}`, got gate `{}` criterion `{}`",
                        idx + 1,
                        row.id,
                        row.gate,
                        row.criterion
                    ),
                ));
            }
        }
        Ok(())
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
            "and verified against the live `fa` binary and registries by `crates/fa-cli/tests/scoreboard.rs` (beads `fa-e9z`, `fa-7s6d`, `fa-ubl0`).\n\n",
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

        out.push_str("\n## 2. Convergence Gate Scoreboard (Plan §19: G0, Genesis, G1–G4)\n\n");
        out.push_str("> **Gate rule:** Gate met only when every row is `works`.\n\n");
        out.push_str(&format!(
            "- **Plan §19 transcription BLAKE3:** `{}` ({gc_total} verbatim clauses: `works`: **{gc_works}**, `refused`: **{gc_refused}**, `absent`: **{gc_absent}**)\n\n",
            self.section_19_digest
        ));
        out.push_str("| Gate | Works | Lawful Refusal | Absent | Total | Gate Status |\n");
        out.push_str("|---|---:|---:|---:|---:|---|\n");
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
            let status = if w == tot && tot > 0 { "MET" } else { "UNMET" };
            out.push_str(&format!(
                "| `{g}` | {w} | {r} | {a} | {tot} | **{status}** |\n"
            ));
        }

        out.push_str("\n### Gate Criteria Detail\n\n");
        out.push_str(
            "| ID | Gate | Evidence Class | Probe | Artifact | Status | Exit | Event / Refusal | Bead | Criterion |\n",
        );
        out.push_str("|---|---|---|---|---|---|---:|---|---|---|\n");
        for c in &self.gate_criteria {
            let ev_or_ref = match &c.expected {
                StepExpectation::Works => format!("`{}`", c.expected_event),
                StepExpectation::Refused { refusal_id, .. } => {
                    format!("`{}` (`{refusal_id}`)", c.expected_event)
                }
                StepExpectation::Absent { .. } => format!("`{}`", s_escape(&c.expected_event)),
            };
            let art = c.artifact.as_deref().unwrap_or("—");
            let bead = c.expected.bead().unwrap_or("—");
            out.push_str(&format!(
                "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | {} | `{}` | {} |\n",
                c.id,
                c.gate,
                c.evidence_class.as_str(),
                c.probe_kind.as_str(),
                art,
                c.expected.as_str(),
                c.expected_exit,
                ev_or_ref,
                bead,
                c.criterion
            ));
        }

        out.push_str(
            "\n## 3. Governance & Verdict Integrity Rows (`fa-8jcr`, `fa-j1fc`, `fa-1qk0`)\n\n",
        );
        out.push_str(
            "| ID | Metric | Evidence Class | Probe | Status | Exit | Bead | Description |\n",
        );
        out.push_str("|---|---|---|---|---|---:|---|---|\n");
        for g in &self.governance_rows {
            let bead = g.expected.bead().unwrap_or("—");
            out.push_str(&format!(
                "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | {} |\n",
                g.id,
                g.metric,
                g.evidence_class.as_str(),
                g.probe_kind.as_str(),
                g.expected.as_str(),
                g.expected_exit,
                bead,
                g.description
            ));
        }

        out
    }
}

fn s_escape(s: &str) -> &str {
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bead_ids_accept_epic_children_and_refuse_malformed_suffixes() {
        for good in ["fa-8jcr", "fa-0hs4.3", "fa-yugf.16", "fa-hlnd.1.2"] {
            assert!(check_bead_id("row", good).is_ok(), "{good}");
        }
        for bad in [
            "fa-0hs4.",
            "fa-0hs4.x",
            "fa-.1",
            "fa-X",
            "fa-",
            "ab-0hs4.1",
            "fa-0hs4..1",
        ] {
            assert!(check_bead_id("row", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn embedded_scoreboard_is_valid_and_covers_all_workflows_and_gates() {
        let sb = Scoreboard::embedded().expect("scoreboard.toml is valid");
        assert_eq!(sb.schema_version, 2);
        assert_eq!(sb.workflows.len(), WORKFLOW_IDS.len());
        assert_eq!(sb.steps.len(), 33);
        assert_eq!(sb.gate_criteria.len(), 55);
        assert_eq!(sb.governance_rows.len(), 3);
        let md = sb.render_markdown();
        assert!(md.contains("## 1. Vision Workflow Summary"));
        assert!(md.contains("## 2. Convergence Gate Scoreboard"));
        assert!(md.contains("Gate met only when every row is `works`."));
        assert!(md.contains("| `G0` | 13 | 0 | 0 | 13 | **MET** |"));
        for unmet in ["Genesis", "G1", "G2", "G3", "G4"] {
            assert!(
                md.contains(&format!("| `{unmet}` |")) && md.contains("**UNMET**"),
                "expected {unmet} to be UNMET in rendered markdown"
            );
        }
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

        let missing_bead = SCOREBOARD.replace("bead = \"fa-p370\"", "");
        let err = Scoreboard::parse(&missing_bead, &exits, &refusals)
            .expect_err("absent step without bead must fail")
            .to_string();
        assert!(err.contains("requires `bead`"), "{err}");

        // Proxy probe cannot satisfy a stronger evidence class.
        let proxy_probe = SCOREBOARD.replacen(
            "id = \"G2-01\"\ngate = \"G2\"\ncriterion = \"period state machine, admissibility matrix, and witness-resolved post-vs-close races proven in both orders\"\nevidence_class = \"lab-campaign\"\nprobe_kind = \"lab-campaign\"",
            "id = \"G2-01\"\ngate = \"G2\"\ncriterion = \"period state machine, admissibility matrix, and witness-resolved post-vs-close races proven in both orders\"\nevidence_class = \"lab-campaign\"\nprobe_kind = \"cli\"",
            1,
        );
        let err = Scoreboard::parse(&proxy_probe, &exits, &refusals)
            .expect_err("proxy cli probe for lab-campaign must fail")
            .to_string();
        assert!(err.contains("proxy probe"), "{err}");
    }
}
