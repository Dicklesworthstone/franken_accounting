//! G0 constitutional registries (plan §18.2, §19 G0, beads `fa-szi`, `fa-tu58`, `fa-i5s`):
//! - `registries/constitution.toml` (`FA-CON-01..14`, `A1..A6`, claim classes)
//! - `registries/evidence.toml` (`FA-EVID-*`, `FA-CAL-*`, `FA-CFG-*`)
//! - `registries/checker_index.toml` (`CHK-*`)
//! - `registries/proof_lanes.toml` (`FA-PROOF-*`, `FA-MODEL-*`)
//! - `registries/period_states.toml` (`PeriodState`, `PeriodKind`, `PeriodTransition`)
//! - `registries/relationship_bases.toml` (`OWNS`, `CONTROLS`, `RELATED_TO` bases)
//! - `registries/claims_lint.toml` (marker resolution families + §18.2 37-registry inventory)
//! - `registries/operation_costs.toml` (Appendix G operation classes, hot-object exceptions, kernel op witnesses)
//! - `registries/slo.toml` (§17 empirical gates and capacity SLOs derived from operation costs)

use std::collections::{BTreeMap, BTreeSet};

use fa_time::period::transition;
use fa_time::{PeriodKind, PeriodState, PeriodTransition};

use crate::invariants::Invariants;
use crate::toml::{Table, Value};
use crate::{RegistryError, invalid, load, req_int, req_str};

const CONSTITUTION_TOML: &str = include_str!("../../../registries/constitution.toml");
const EVIDENCE_TOML: &str = include_str!("../../../registries/evidence.toml");
const CHECKER_INDEX_TOML: &str = include_str!("../../../registries/checker_index.toml");
const PROOF_LANES_TOML: &str = include_str!("../../../registries/proof_lanes.toml");
const PERIOD_STATES_TOML: &str = include_str!("../../../registries/period_states.toml");
const RELATIONSHIP_BASES_TOML: &str = include_str!("../../../registries/relationship_bases.toml");
const CLAIMS_LINT_TOML: &str = include_str!("../../../registries/claims_lint.toml");
const OPERATION_COSTS_TOML: &str = include_str!("../../../registries/operation_costs.toml");
const SLO_TOML: &str = include_str!("../../../registries/slo.toml");
const LOT_LAWS_TOML: &str = include_str!("../../../registries/lot_laws.toml");
const CONVERSION_LAWS_TOML: &str = include_str!("../../../registries/conversion_laws.toml");
const SUPERSESSION_KINDS_TOML: &str = include_str!("../../../registries/supersession_kinds.toml");
const TRACING_LAWS_TOML: &str = include_str!("../../../registries/tracing_laws.toml");
const FX_LAWS_TOML: &str = include_str!("../../../registries/fx_laws.toml");

fn req_bool(registry: &'static str, t: &Table, key: &str) -> Result<bool, RegistryError> {
    t.get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid(registry, format!("missing boolean `{key}`")))
}

fn req_str_vec(registry: &'static str, t: &Table, key: &str) -> Result<Vec<String>, RegistryError> {
    let arr = t
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(registry, format!("missing array `{key}`")))?;
    arr.iter()
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| invalid(registry, format!("`{key}` must contain strings")))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// constitution.toml
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimClassRow {
    pub rank: u8,
    pub name: String,
    pub registry: String,
    pub marker_prefix: String,
    pub statement: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BetRow {
    pub id: String,
    pub name: String,
    pub plan_ref: String,
    pub summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConstraintRow {
    pub id: String,
    pub number: u8,
    pub name: String,
    pub plan_ref: String,
    pub statement: String,
    pub gate: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Constitution {
    pub claim_classes: Vec<ClaimClassRow>,
    pub bets: Vec<BetRow>,
    pub constraints: Vec<ConstraintRow>,
}

impl Constitution {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::parse(CONSTITUTION_TOML)
    }

    pub fn parse(text: &str) -> Result<Self, RegistryError> {
        const R: &str = "constitution.toml";
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        let mut claim_classes = Vec::new();
        for (idx, t) in doc
            .arrays
            .get("claim_class")
            .ok_or_else(|| invalid(R, "missing [[claim_class]]"))?
            .iter()
            .enumerate()
        {
            let rank = u8::try_from(req_int(R, t, "rank")?)
                .map_err(|_| invalid(R, "rank out of u8 range"))?;
            if usize::from(rank) != idx + 1 {
                return Err(invalid(
                    R,
                    format!("claim_class rank {rank} is not contiguous at index {idx}"),
                ));
            }
            claim_classes.push(ClaimClassRow {
                rank,
                name: req_str(R, t, "name")?.to_string(),
                registry: req_str(R, t, "registry")?.to_string(),
                marker_prefix: req_str(R, t, "marker_prefix")?.to_string(),
                statement: req_str(R, t, "statement")?.to_string(),
            });
        }
        if claim_classes.len() != 6 {
            return Err(invalid(
                R,
                format!("expected 6 claim classes, found {}", claim_classes.len()),
            ));
        }

        let mut bets = Vec::new();
        for (idx, t) in doc
            .arrays
            .get("bet")
            .ok_or_else(|| invalid(R, "missing [[bet]]"))?
            .iter()
            .enumerate()
        {
            let id = req_str(R, t, "id")?.to_string();
            let expected_id = format!("A{}", idx + 1);
            if id != expected_id {
                return Err(invalid(
                    R,
                    format!("expected bet `{expected_id}`, found `{id}`"),
                ));
            }
            bets.push(BetRow {
                id,
                name: req_str(R, t, "name")?.to_string(),
                plan_ref: req_str(R, t, "plan_ref")?.to_string(),
                summary: req_str(R, t, "summary")?.to_string(),
            });
        }
        if bets.len() != 6 {
            return Err(invalid(R, format!("expected 6 bets, found {}", bets.len())));
        }

        let mut constraints = Vec::new();
        for (idx, t) in doc
            .arrays
            .get("constraint")
            .ok_or_else(|| invalid(R, "missing [[constraint]]"))?
            .iter()
            .enumerate()
        {
            let id = req_str(R, t, "id")?.to_string();
            let number = u8::try_from(req_int(R, t, "number")?)
                .map_err(|_| invalid(R, "constraint number out of range"))?;
            let expected_num = u8::try_from(idx + 1).unwrap();
            let expected_id = format!("FA-CON-{expected_num:02}");
            if number != expected_num || id != expected_id {
                return Err(invalid(
                    R,
                    format!(
                        "expected constraint ({expected_id}, {expected_num}), found ({id}, {number})"
                    ),
                ));
            }
            constraints.push(ConstraintRow {
                id,
                number,
                name: req_str(R, t, "name")?.to_string(),
                plan_ref: req_str(R, t, "plan_ref")?.to_string(),
                statement: req_str(R, t, "statement")?.to_string(),
                gate: req_str(R, t, "gate")?.to_string(),
            });
        }
        if constraints.len() != 14 {
            return Err(invalid(
                R,
                format!(
                    "expected 14 constraints (FA-CON-01..14), found {}",
                    constraints.len()
                ),
            ));
        }

        Ok(Self {
            claim_classes,
            bets,
            constraints,
        })
    }
}

// ---------------------------------------------------------------------------
// evidence.toml
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceGateRow {
    pub id: String,
    pub kind: String,
    pub claim: String,
    pub required_disclosure: String,
    pub owner: String,
    pub activating_workstream: String,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRegistry {
    pub gates: Vec<EvidenceGateRow>,
}

impl EvidenceRegistry {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::parse(EVIDENCE_TOML)
    }

    pub fn parse(text: &str) -> Result<Self, RegistryError> {
        const R: &str = "evidence.toml";
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        let mut ids = BTreeSet::new();
        let mut gates = Vec::new();
        for t in doc
            .arrays
            .get("gate")
            .ok_or_else(|| invalid(R, "missing [[gate]]"))?
        {
            let id = req_str(R, t, "id")?.to_string();
            let kind = req_str(R, t, "kind")?.to_string();
            let status = req_str(R, t, "status")?.to_string();
            if !matches!(
                kind.as_str(),
                "statistical" | "calibration" | "configuration"
            ) {
                return Err(invalid(R, format!("{id}: invalid kind `{kind}`")));
            }
            if !matches!(status.as_str(), "live" | "dormant") {
                return Err(invalid(R, format!("{id}: invalid status `{status}`")));
            }
            if !ids.insert(id.clone()) {
                return Err(invalid(R, format!("duplicate gate `{id}`")));
            }
            gates.push(EvidenceGateRow {
                id,
                kind,
                claim: req_str(R, t, "claim")?.to_string(),
                required_disclosure: req_str(R, t, "required_disclosure")?.to_string(),
                owner: req_str(R, t, "owner")?.to_string(),
                activating_workstream: req_str(R, t, "activating_workstream")?.to_string(),
                status,
            });
        }
        if gates.len() < 9 {
            return Err(invalid(
                R,
                format!("expected at least 9 Appendix F rows, found {}", gates.len()),
            ));
        }
        Ok(Self { gates })
    }
}

// ---------------------------------------------------------------------------
// checker_index.toml
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckerRow {
    pub id: String,
    pub kind: String,
    pub driver: String,
    pub negative_driver: String,
    pub source_registry: String,
    pub description: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckerIndex {
    pub checkers: Vec<CheckerRow>,
}

impl CheckerIndex {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::parse(CHECKER_INDEX_TOML)
    }

    pub fn parse(text: &str) -> Result<Self, RegistryError> {
        const R: &str = "checker_index.toml";
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        let mut ids = BTreeSet::new();
        let mut checkers = Vec::new();
        for t in doc
            .arrays
            .get("checker")
            .ok_or_else(|| invalid(R, "missing [[checker]]"))?
        {
            let id = req_str(R, t, "id")?.to_string();
            if !ids.insert(id.clone()) {
                return Err(invalid(R, format!("duplicate checker `{id}`")));
            }
            checkers.push(CheckerRow {
                id,
                kind: req_str(R, t, "kind")?.to_string(),
                driver: req_str(R, t, "driver")?.to_string(),
                negative_driver: req_str(R, t, "negative_driver")?.to_string(),
                source_registry: req_str(R, t, "source_registry")?.to_string(),
                description: req_str(R, t, "description")?.to_string(),
            });
        }
        if checkers.is_empty() {
            return Err(invalid(R, "[[checker]] is empty"));
        }
        Ok(Self { checkers })
    }
}

// ---------------------------------------------------------------------------
// proof_lanes.toml
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofLaneRow {
    pub id: String,
    pub engine: String,
    pub claim_class: String,
    pub subject: String,
    pub invariant_clauses: Vec<String>,
    pub artifact_path: String,
    pub owning_bead: String,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofLanes {
    pub lanes: Vec<ProofLaneRow>,
}

impl ProofLanes {
    pub fn embedded(invariants: &Invariants) -> Result<Self, RegistryError> {
        Self::parse(PROOF_LANES_TOML, invariants)
    }

    pub fn parse(text: &str, invariants: &Invariants) -> Result<Self, RegistryError> {
        const R: &str = "proof_lanes.toml";
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        let valid_clauses: BTreeSet<String> = invariants
            .clauses
            .iter()
            .map(|c| format!("{}.{}", c.invariant, c.id))
            .collect();
        let mut ids = BTreeSet::new();
        let mut lanes = Vec::new();
        for t in doc
            .arrays
            .get("lane")
            .ok_or_else(|| invalid(R, "missing [[lane]]"))?
        {
            let id = req_str(R, t, "id")?.to_string();
            let engine = req_str(R, t, "engine")?.to_string();
            let claim_class = req_str(R, t, "claim_class")?.to_string();
            let status = req_str(R, t, "status")?.to_string();
            if !matches!(engine.as_str(), "lean4" | "tlaplus") {
                return Err(invalid(R, format!("{id}: invalid engine `{engine}`")));
            }
            if !matches!(claim_class.as_str(), "proof" | "bounded_model") {
                return Err(invalid(
                    R,
                    format!("{id}: invalid claim_class `{claim_class}`"),
                ));
            }
            if !matches!(status.as_str(), "live" | "dormant") {
                return Err(invalid(R, format!("{id}: invalid status `{status}`")));
            }
            let invariant_clauses = req_str_vec(R, t, "invariant_clauses")?;
            if invariant_clauses.is_empty() {
                return Err(invalid(R, format!("{id}: invariant_clauses is empty")));
            }
            for clause in &invariant_clauses {
                if !valid_clauses.contains(clause) {
                    return Err(invalid(
                        R,
                        format!("{id}: references unknown invariant clause `{clause}`"),
                    ));
                }
            }
            if !ids.insert(id.clone()) {
                return Err(invalid(R, format!("duplicate lane `{id}`")));
            }
            lanes.push(ProofLaneRow {
                id,
                engine,
                claim_class,
                subject: req_str(R, t, "subject")?.to_string(),
                invariant_clauses,
                artifact_path: req_str(R, t, "artifact_path")?.to_string(),
                owning_bead: req_str(R, t, "owning_bead")?.to_string(),
                status,
            });
        }
        if lanes.is_empty() {
            return Err(invalid(R, "[[lane]] is empty"));
        }
        Ok(Self { lanes })
    }
}

// ---------------------------------------------------------------------------
// period_states.toml
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodStateRow {
    pub tag: u8,
    pub name: String,
    pub admits_original: bool,
    pub description: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodKindRow {
    pub tag: u8,
    pub name: String,
    pub requires_discriminator: bool,
    pub description: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodTransitionRow {
    pub action: String,
    pub from: String,
    pub to: String,
    pub capability: String,
    pub approvals: u8,
    pub requires_case: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodStatesRegistry {
    pub states: Vec<PeriodStateRow>,
    pub kinds: Vec<PeriodKindRow>,
    pub transitions: Vec<PeriodTransitionRow>,
}

impl PeriodStatesRegistry {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::parse(PERIOD_STATES_TOML)
    }

    pub fn parse(text: &str) -> Result<Self, RegistryError> {
        const R: &str = "period_states.toml";
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        let mut states = Vec::new();
        for t in doc
            .arrays
            .get("state")
            .ok_or_else(|| invalid(R, "missing [[state]]"))?
        {
            let tag = u8::try_from(req_int(R, t, "tag")?)
                .map_err(|_| invalid(R, "state tag out of range"))?;
            let name = req_str(R, t, "name")?.to_string();
            let code_state = PeriodState::from_tag(tag)
                .ok_or_else(|| invalid(R, format!("unknown PeriodState tag {tag}")))?;
            if code_state.name() != name {
                return Err(invalid(
                    R,
                    format!(
                        "state tag {tag} is `{name}` in TOML but `{}` in fa-time",
                        code_state.name()
                    ),
                ));
            }
            states.push(PeriodStateRow {
                tag,
                name,
                admits_original: req_bool(R, t, "admits_original")?,
                description: req_str(R, t, "description")?.to_string(),
            });
        }
        if states.len() != 5 {
            return Err(invalid(
                R,
                format!("expected 5 PeriodState rows, found {}", states.len()),
            ));
        }

        let expected_kinds = [
            (0u8, "Normal", PeriodKind::Normal),
            (1u8, "Adjustment", PeriodKind::Adjustment),
            (2u8, "Opening", PeriodKind::Opening),
            (3u8, "Closing", PeriodKind::Closing),
            (4u8, "Historical", PeriodKind::Historical),
        ];
        let mut kinds = Vec::new();
        for (idx, t) in doc
            .arrays
            .get("kind")
            .ok_or_else(|| invalid(R, "missing [[kind]]"))?
            .iter()
            .enumerate()
        {
            let tag = u8::try_from(req_int(R, t, "tag")?)
                .map_err(|_| invalid(R, "kind tag out of range"))?;
            let name = req_str(R, t, "name")?.to_string();
            let Some((exp_tag, exp_name, _)) = expected_kinds.get(idx) else {
                return Err(invalid(R, "unexpected extra [[kind]] row"));
            };
            if tag != *exp_tag || name != *exp_name {
                return Err(invalid(
                    R,
                    format!(
                        "kind row {idx} expected ({exp_tag}, {exp_name}), found ({tag}, {name})"
                    ),
                ));
            }
            kinds.push(PeriodKindRow {
                tag,
                name,
                requires_discriminator: req_bool(R, t, "requires_discriminator")?,
                description: req_str(R, t, "description")?.to_string(),
            });
        }
        if kinds.len() != 5 {
            return Err(invalid(
                R,
                format!("expected 5 PeriodKind rows, found {}", kinds.len()),
            ));
        }

        let mut transitions = Vec::new();
        for t in doc
            .arrays
            .get("transition")
            .ok_or_else(|| invalid(R, "missing [[transition]]"))?
        {
            let action = req_str(R, t, "action")?.to_string();
            let from_name = req_str(R, t, "from")?.to_string();
            let to_name = req_str(R, t, "to")?.to_string();
            let from_state = PeriodState::from_name(&from_name)
                .ok_or_else(|| invalid(R, format!("unknown from state `{from_name}`")))?;
            let to_state = PeriodState::from_name(&to_name)
                .ok_or_else(|| invalid(R, format!("unknown to state `{to_name}`")))?;
            let step = match action.as_str() {
                "Open" => PeriodTransition::Open,
                "SoftClose" => PeriodTransition::SoftClose,
                "Close" => PeriodTransition::Close,
                "Lock" => PeriodTransition::Lock,
                "Reopen" => PeriodTransition::Reopen { to: to_state },
                other => return Err(invalid(R, format!("unknown transition action `{other}`"))),
            };
            let actual_to = transition(from_state, step).map_err(|e| invalid(R, e.to_string()))?;
            if actual_to != to_state {
                return Err(invalid(
                    R,
                    format!(
                        "transition {action} from {from_name} yielded {actual_to:?}, expected {to_name}"
                    ),
                ));
            }
            let approvals = u8::try_from(req_int(R, t, "approvals")?)
                .map_err(|_| invalid(R, "approvals out of range"))?;
            transitions.push(PeriodTransitionRow {
                action,
                from: from_name,
                to: to_name,
                capability: req_str(R, t, "capability")?.to_string(),
                approvals,
                requires_case: req_bool(R, t, "requires_case")?,
            });
        }
        if transitions.len() != 10 {
            return Err(invalid(
                R,
                format!(
                    "expected 10 legal PeriodTransition rows, found {}",
                    transitions.len()
                ),
            ));
        }
        Ok(Self {
            states,
            kinds,
            transitions,
        })
    }
}

// ---------------------------------------------------------------------------
// relationship_bases.toml
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationshipBasisRow {
    pub id: u16,
    pub code: String,
    pub edge_kind: String,
    pub standard_ref: String,
    pub description: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationshipBases {
    pub rows: Vec<RelationshipBasisRow>,
}

impl RelationshipBases {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::parse(RELATIONSHIP_BASES_TOML)
    }

    pub fn parse(text: &str) -> Result<Self, RegistryError> {
        const R: &str = "relationship_bases.toml";
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        let mut ids = BTreeSet::new();
        let mut codes = BTreeSet::new();
        let mut rows = Vec::new();
        for t in doc
            .arrays
            .get("basis")
            .ok_or_else(|| invalid(R, "missing [[basis]]"))?
        {
            let id = u16::try_from(req_int(R, t, "id")?)
                .map_err(|_| invalid(R, "basis id out of u16 range"))?;
            let code = req_str(R, t, "code")?.to_string();
            let edge_kind = req_str(R, t, "edge_kind")?.to_string();
            if !matches!(edge_kind.as_str(), "OWNS" | "CONTROLS" | "RELATED_TO") {
                return Err(invalid(
                    R,
                    format!("{code}: invalid edge_kind `{edge_kind}`"),
                ));
            }
            if !ids.insert(id) {
                return Err(invalid(R, format!("duplicate basis id {id}")));
            }
            if !codes.insert(code.clone()) {
                return Err(invalid(R, format!("duplicate basis code `{code}`")));
            }
            rows.push(RelationshipBasisRow {
                id,
                code,
                edge_kind,
                standard_ref: req_str(R, t, "standard_ref")?.to_string(),
                description: req_str(R, t, "description")?.to_string(),
            });
        }
        if rows.is_empty() {
            return Err(invalid(R, "[[basis]] is empty"));
        }
        Ok(Self { rows })
    }
}

// ---------------------------------------------------------------------------
// claims_lint.toml
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkerFamilyRow {
    pub prefix: String,
    pub registry: String,
    pub table: String,
    pub key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct G0RegistryEntry {
    pub path: String,
    pub kind: String,
    pub owner_bead: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimsLintConfig {
    pub scanned_docs: Vec<String>,
    pub marker_families: Vec<MarkerFamilyRow>,
    pub g0_registries: Vec<G0RegistryEntry>,
}

impl ClaimsLintConfig {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::parse(CLAIMS_LINT_TOML)
    }

    pub fn parse(text: &str) -> Result<Self, RegistryError> {
        const R: &str = "claims_lint.toml";
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        let scanned_docs = req_str_vec(R, &doc.root, "scanned_docs")?;
        if scanned_docs.is_empty() {
            return Err(invalid(R, "scanned_docs must not be empty"));
        }
        let mut prefixes = BTreeSet::new();
        let mut marker_families = Vec::new();
        for t in doc
            .arrays
            .get("marker_family")
            .ok_or_else(|| invalid(R, "missing [[marker_family]]"))?
        {
            let prefix = req_str(R, t, "prefix")?.to_string();
            if !prefixes.insert(prefix.clone()) {
                return Err(invalid(R, format!("duplicate marker_family `{prefix}`")));
            }
            marker_families.push(MarkerFamilyRow {
                prefix,
                registry: req_str(R, t, "registry")?.to_string(),
                table: req_str(R, t, "table")?.to_string(),
                key: req_str(R, t, "key")?.to_string(),
            });
        }
        let mut paths = BTreeSet::new();
        let mut g0_registries = Vec::new();
        for t in doc
            .arrays
            .get("g0_registry")
            .ok_or_else(|| invalid(R, "missing [[g0_registry]]"))?
        {
            let path = req_str(R, t, "path")?.to_string();
            let kind = req_str(R, t, "kind")?.to_string();
            if !matches!(kind.as_str(), "file" | "dir") {
                return Err(invalid(R, format!("{path}: invalid kind `{kind}`")));
            }
            if !paths.insert(path.clone()) {
                return Err(invalid(R, format!("duplicate g0_registry `{path}`")));
            }
            g0_registries.push(G0RegistryEntry {
                path,
                kind,
                owner_bead: req_str(R, t, "owner_bead")?.to_string(),
            });
        }
        if g0_registries.len() != 37 {
            return Err(invalid(
                R,
                format!(
                    "expected 37 §18.2 g0_registry entries, found {}",
                    g0_registries.len()
                ),
            ));
        }
        Ok(Self {
            scanned_docs,
            marker_families,
            g0_registries,
        })
    }
}

// ---------------------------------------------------------------------------
// operation_costs.toml (Appendix G, beads fa-tu58, fa-i5s)
// ---------------------------------------------------------------------------

// The 19 Appendix G classes plus the registered native bank-import extension.
// Require their identities, not merely a row count: an unrelated class cannot
// replace an existing operation's cost contract.
const REQUIRED_OPERATION_CLASS_IDS: [&str; 24] = [
    "balance_read_at_watermark",
    "certified_report",
    "single_entry_post",
    "portable_single_entry_plan_and_commit",
    "batch_post",
    "admitted_durable_refusal",
    "release_only_resolution",
    "effect_manifest_closure",
    "draft_promotion",
    "period_transition",
    "close_run_execute",
    "restatement_case_post",
    "register_maintenance_flush",
    "accumulator_checkpoint",
    "expiry_sweep_tick",
    "bundle_production",
    "external_profile_read",
    "ceiling_bearing_post",
    "bulk_migration",
    "bank_statement_import",
    "bank_match_confirmation",
    "bank_match_unmatch",
    "closing_routes_record",
    "year_end_close",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HotObjectExceptionRow {
    pub name: String,
    pub plan_ref: String,
    pub allowed_classes: Vec<String>,
    pub allowed_kernel_ops: Vec<String>,
    pub retirement_condition: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationClassRow {
    pub id: String,
    pub name: String,
    pub substrate_class: String,
    pub substrate_transactions: String,
    pub today_posture: String,
    pub today_transactions: u32,
    pub barrier_count: u64,
    pub today_barrier_count: u64,
    pub derived_objects: String,
    pub hot_object_exceptions: Vec<String>,
    pub external_authorities: String,
    pub complexity_witness: String,
    pub notes: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelOpWitnessRow {
    pub id: String,
    pub operation_class: String,
    pub description: String,
    pub hot_object_exceptions: Vec<String>,
    pub point_reads: u32,
    pub witnesses: u32,
    pub cas_moves: u32,
    pub edges_written: u32,
    pub vertices_written: u32,
    pub transactions: u32,
    pub complexity_witness: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationCosts {
    pub hot_object_exceptions: Vec<HotObjectExceptionRow>,
    pub classes: Vec<OperationClassRow>,
    pub kernel_op_witnesses: Vec<KernelOpWitnessRow>,
}

impl OperationCosts {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::parse(OPERATION_COSTS_TOML)
    }

    pub fn parse(text: &str) -> Result<Self, RegistryError> {
        const R: &str = "operation_costs.toml";
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }

        let mut exc_by_name: BTreeMap<String, HotObjectExceptionRow> = BTreeMap::new();
        let mut hot_object_exceptions = Vec::new();
        for t in doc
            .arrays
            .get("hot_object_exception")
            .ok_or_else(|| invalid(R, "missing [[hot_object_exception]]"))?
        {
            let name = req_str(R, t, "name")?.to_string();
            if !matches!(name.as_str(), "LimitCell" | "UsageCell") {
                return Err(invalid(
                    R,
                    format!(
                        "unregistered hot_object_exception `{name}` (Appendix G Law 3 admits only LimitCell and UsageCell)"
                    ),
                ));
            }
            let allowed_classes = req_str_vec(R, t, "allowed_classes")?;
            let allowed_kernel_ops = req_str_vec(R, t, "allowed_kernel_ops")?;
            if allowed_classes.is_empty() || allowed_kernel_ops.is_empty() {
                return Err(invalid(
                    R,
                    format!(
                        "hot_object_exception `{name}` must have non-empty allowed_classes and allowed_kernel_ops"
                    ),
                ));
            }
            let row = HotObjectExceptionRow {
                name: name.clone(),
                plan_ref: req_str(R, t, "plan_ref")?.to_string(),
                allowed_classes,
                allowed_kernel_ops,
                retirement_condition: req_str(R, t, "retirement_condition")?.to_string(),
            };
            if exc_by_name.insert(name.clone(), row.clone()).is_some() {
                return Err(invalid(
                    R,
                    format!("duplicate hot_object_exception `{name}`"),
                ));
            }
            hot_object_exceptions.push(row);
        }
        if hot_object_exceptions.len() != 2 {
            return Err(invalid(
                R,
                format!(
                    "expected exactly 2 hot_object_exception rows (LimitCell, UsageCell), found {}",
                    hot_object_exceptions.len()
                ),
            ));
        }

        let mut class_ids = BTreeSet::new();
        let mut class_names = BTreeSet::new();
        let mut classes = Vec::new();
        for t in doc
            .arrays
            .get("operation_class")
            .ok_or_else(|| invalid(R, "missing [[operation_class]]"))?
        {
            let id = req_str(R, t, "id")?.to_string();
            let name = req_str(R, t, "name")?.to_string();
            let today_transactions = u32::try_from(req_int(R, t, "today_transactions")?)
                .map_err(|_| invalid(R, format!("{id}: today_transactions must be >= 0")))?;
            let barrier_count = u64::try_from(req_int(R, t, "barrier_count")?)
                .map_err(|_| invalid(R, format!("{id}: barrier_count must be >= 0")))?;
            let today_barrier_count = u64::try_from(req_int(R, t, "today_barrier_count")?)
                .map_err(|_| invalid(R, format!("{id}: today_barrier_count must be >= 0")))?;
            let exceptions = req_str_vec(R, t, "hot_object_exceptions")?;
            for exc in &exceptions {
                let Some(exc_row) = exc_by_name.get(exc) else {
                    return Err(invalid(
                        R,
                        format!(
                            "operation_class `{id}` cites unregistered hot-object exception `{exc}` (Appendix G Law 3)"
                        ),
                    ));
                };
                if !exc_row.allowed_classes.contains(&id) {
                    return Err(invalid(
                        R,
                        format!(
                            "operation_class `{id}` is not scoped for hot-object exception `{exc}` (Appendix G Law 3)"
                        ),
                    ));
                }
            }
            if !class_ids.insert(id.clone()) {
                return Err(invalid(R, format!("duplicate operation_class id `{id}`")));
            }
            if !class_names.insert(name.clone()) {
                return Err(invalid(
                    R,
                    format!("duplicate operation_class name `{name}`"),
                ));
            }
            classes.push(OperationClassRow {
                id,
                name,
                substrate_class: req_str(R, t, "substrate_class")?.to_string(),
                substrate_transactions: req_str(R, t, "substrate_transactions")?.to_string(),
                today_posture: req_str(R, t, "today_posture")?.to_string(),
                today_transactions,
                barrier_count,
                today_barrier_count,
                derived_objects: req_str(R, t, "derived_objects")?.to_string(),
                hot_object_exceptions: exceptions,
                external_authorities: req_str(R, t, "external_authorities")?.to_string(),
                complexity_witness: req_str(R, t, "complexity_witness")?.to_string(),
                notes: req_str(R, t, "notes")?.to_string(),
            });
        }
        for required in REQUIRED_OPERATION_CLASS_IDS {
            if !class_ids.contains(required) {
                return Err(invalid(
                    R,
                    format!("missing required operation_class `{required}`"),
                ));
            }
        }
        for id in &class_ids {
            if !REQUIRED_OPERATION_CLASS_IDS.contains(&id.as_str()) {
                return Err(invalid(R, format!("unregistered operation_class `{id}`")));
            }
        }

        let required_kernel_ops = [
            "post",
            "reserve",
            "resolve",
            "period_transition",
            "document_add",
            "checkpoint",
            "fold_per_entry",
            "verify_per_cell",
            "query_procedure",
        ];
        let mut witness_ids = BTreeSet::new();
        let mut kernel_op_witnesses = Vec::new();
        for t in doc
            .arrays
            .get("kernel_op_witness")
            .ok_or_else(|| invalid(R, "missing [[kernel_op_witness]]"))?
        {
            let id = req_str(R, t, "id")?.to_string();
            let op_class = req_str(R, t, "operation_class")?.to_string();
            if !class_ids.contains(&op_class) {
                return Err(invalid(
                    R,
                    format!(
                        "kernel_op_witness `{id}` references unknown operation_class `{op_class}`"
                    ),
                ));
            }
            let exceptions = req_str_vec(R, t, "hot_object_exceptions")?;
            for exc in &exceptions {
                let Some(exc_row) = exc_by_name.get(exc) else {
                    return Err(invalid(
                        R,
                        format!(
                            "kernel_op_witness `{id}` cites unregistered hot-object exception `{exc}`"
                        ),
                    ));
                };
                if !exc_row.allowed_kernel_ops.contains(&id) {
                    return Err(invalid(
                        R,
                        format!(
                            "kernel_op_witness `{id}` is not scoped for hot-object exception `{exc}`"
                        ),
                    ));
                }
            }
            let point_reads = u32::try_from(req_int(R, t, "point_reads")?)
                .map_err(|_| invalid(R, format!("{id}: point_reads must be >= 0")))?;
            let witnesses = u32::try_from(req_int(R, t, "witnesses")?)
                .map_err(|_| invalid(R, format!("{id}: witnesses must be >= 0")))?;
            let cas_moves = u32::try_from(req_int(R, t, "cas_moves")?)
                .map_err(|_| invalid(R, format!("{id}: cas_moves must be >= 0")))?;
            let edges_written = u32::try_from(req_int(R, t, "edges_written")?)
                .map_err(|_| invalid(R, format!("{id}: edges_written must be >= 0")))?;
            let vertices_written = u32::try_from(req_int(R, t, "vertices_written")?)
                .map_err(|_| invalid(R, format!("{id}: vertices_written must be >= 0")))?;
            let transactions = u32::try_from(req_int(R, t, "transactions")?)
                .map_err(|_| invalid(R, format!("{id}: transactions must be >= 0")))?;
            if !witness_ids.insert(id.clone()) {
                return Err(invalid(R, format!("duplicate kernel_op_witness `{id}`")));
            }
            kernel_op_witnesses.push(KernelOpWitnessRow {
                id,
                operation_class: op_class,
                description: req_str(R, t, "description")?.to_string(),
                hot_object_exceptions: exceptions,
                point_reads,
                witnesses,
                cas_moves,
                edges_written,
                vertices_written,
                transactions,
                complexity_witness: req_str(R, t, "complexity_witness")?.to_string(),
            });
        }
        for req_op in required_kernel_ops {
            if !witness_ids.contains(req_op) {
                return Err(invalid(
                    R,
                    format!("missing required [[kernel_op_witness]] `{req_op}`"),
                ));
            }
        }

        Ok(Self {
            hot_object_exceptions,
            classes,
            kernel_op_witnesses,
        })
    }

    pub fn class(&self, id: &str) -> Option<&OperationClassRow> {
        self.classes.iter().find(|c| c.id == id)
    }

    pub fn witness(&self, id: &str) -> Option<&KernelOpWitnessRow> {
        self.kernel_op_witnesses.iter().find(|w| w.id == id)
    }
}

// ---------------------------------------------------------------------------
// slo.toml (§17 Performance Doctrine and Targets, beads fa-tu58, fa-i5s)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceMachine {
    pub id: String,
    pub cpu: String,
    pub ram_gb: u32,
    pub storage: String,
    pub pinned_fsync_p50_us: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SloRow {
    pub id: String,
    pub name: String,
    pub domain: String,
    pub operation_class: String,
    pub claim_class: String,
    pub counting_unit: String,
    pub pinned_fsync_p50_us: u64,
    pub target_p50_us: u64,
    pub target_p99_us: u64,
    pub max_bytes_per_leg: Option<u64>,
    pub requires_watermark_disclosure: bool,
    pub activated: bool,
    pub provisional_gate: String,
    pub derivation: String,
    pub measurement_command: String,
    pub manifest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SloRegistry {
    pub reference_machine: ReferenceMachine,
    pub rows: Vec<SloRow>,
}

const BALANCE_READ_NAMES: &[&str] = &[
    "balance_read_watermark",
    "trial_balance_100k",
    "known_at_trial_balance",
    "register_watermark_lag",
];

impl SloRegistry {
    pub fn embedded(op_costs: &OperationCosts) -> Result<Self, RegistryError> {
        Self::parse(SLO_TOML, op_costs)
    }

    pub fn parse(text: &str, op_costs: &OperationCosts) -> Result<Self, RegistryError> {
        const R: &str = "slo.toml";
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }

        let rm_table = doc
            .tables
            .get("reference_machine")
            .ok_or_else(|| invalid(R, "missing [reference_machine]"))?;
        let ram_gb = u32::try_from(req_int(R, rm_table, "ram_gb")?)
            .map_err(|_| invalid(R, "reference_machine.ram_gb must be positive"))?;
        let ref_fsync = u64::try_from(req_int(R, rm_table, "pinned_fsync_p50_us")?)
            .map_err(|_| invalid(R, "reference_machine.pinned_fsync_p50_us must be positive"))?;
        if ram_gb == 0 || ref_fsync == 0 {
            return Err(invalid(
                R,
                "reference_machine ram_gb and pinned_fsync_p50_us must be > 0",
            ));
        }
        let reference_machine = ReferenceMachine {
            id: req_str(R, rm_table, "id")?.to_string(),
            cpu: req_str(R, rm_table, "cpu")?.to_string(),
            ram_gb,
            storage: req_str(R, rm_table, "storage")?.to_string(),
            pinned_fsync_p50_us: ref_fsync,
        };

        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut rows = Vec::new();
        for t in doc
            .arrays
            .get("slo")
            .ok_or_else(|| invalid(R, "missing [[slo]]"))?
        {
            let id = req_str(R, t, "id")?.to_string();
            let name = req_str(R, t, "name")?.to_string();
            let claim_class = req_str(R, t, "claim_class")?.to_string();
            if !matches!(claim_class.as_str(), "slo" | "benchmark") {
                return Err(invalid(
                    R,
                    format!(
                        "claims_lint: `{id}` (`{name}`) has forbidden claim_class `{claim_class}` (measured targets must be `slo` or `benchmark`, never `invariant`)"
                    ),
                ));
            }
            let op_class_id = req_str(R, t, "operation_class")?.to_string();
            let Some(op_class) = op_costs.class(&op_class_id) else {
                return Err(invalid(
                    R,
                    format!(
                        "`{id}` (`{name}`) references unknown operation_class `{op_class_id}` (not in operation_costs.toml)"
                    ),
                ));
            };
            let pinned_fsync_p50_us = u64::try_from(req_int(R, t, "pinned_fsync_p50_us")?)
                .map_err(|_| invalid(R, format!("{id}: pinned_fsync_p50_us must be > 0")))?;
            let target_p50_us = u64::try_from(req_int(R, t, "target_p50_us")?)
                .map_err(|_| invalid(R, format!("{id}: target_p50_us must be > 0")))?;
            let target_p99_us = u64::try_from(req_int(R, t, "target_p99_us")?)
                .map_err(|_| invalid(R, format!("{id}: target_p99_us must be > 0")))?;
            if pinned_fsync_p50_us == 0 || target_p50_us == 0 || target_p99_us < target_p50_us {
                return Err(invalid(
                    R,
                    format!(
                        "`{id}` (`{name}`): requires pinned_fsync_p50_us > 0 and target_p99_us >= target_p50_us > 0"
                    ),
                ));
            }
            // Derivability law (§17 & Appendix G Law 1): a gate below
            // `barrier_count * pinned_fsync_p50_us` is a registry error.
            let barrier_floor = op_class.barrier_count.saturating_mul(pinned_fsync_p50_us);
            if target_p50_us < barrier_floor {
                return Err(invalid(
                    R,
                    format!(
                        "derivability law violation on `{id}` (`{name}`): target_p50_us ({target_p50_us} us) < barrier_count ({}) * pinned_fsync_p50_us ({pinned_fsync_p50_us} us) = {barrier_floor} us",
                        op_class.barrier_count
                    ),
                ));
            }
            let requires_watermark_disclosure = req_bool(R, t, "requires_watermark_disclosure")?;
            if BALANCE_READ_NAMES.contains(&name.as_str()) && !requires_watermark_disclosure {
                return Err(invalid(
                    R,
                    format!(
                        "§17 standing law violation on `{id}` (`{name}`): balance-read and trial-balance targets must set `requires_watermark_disclosure = true`"
                    ),
                ));
            }
            let max_bytes_per_leg = match t.get("max_bytes_per_leg") {
                Some(v) => Some(
                    u64::try_from(
                        v.as_int()
                            .ok_or_else(|| invalid(R, format!("{id}: max_bytes_per_leg int")))?,
                    )
                    .map_err(|_| invalid(R, format!("{id}: max_bytes_per_leg > 0")))?,
                ),
                None => None,
            };
            let manifest = req_str(R, t, "manifest")?.to_string();
            if !manifest.starts_with("bench/manifests/") || !manifest.ends_with(".toml") {
                return Err(invalid(
                    R,
                    format!(
                        "`{id}`: manifest `{manifest}` must live under `bench/manifests/*.toml`"
                    ),
                ));
            }
            if !ids.insert(id.clone()) {
                return Err(invalid(R, format!("duplicate slo id `{id}`")));
            }
            if !names.insert(name.clone()) {
                return Err(invalid(R, format!("duplicate slo name `{name}`")));
            }
            rows.push(SloRow {
                id,
                name,
                domain: req_str(R, t, "domain")?.to_string(),
                operation_class: op_class_id,
                claim_class,
                counting_unit: req_str(R, t, "counting_unit")?.to_string(),
                pinned_fsync_p50_us,
                target_p50_us,
                target_p99_us,
                max_bytes_per_leg,
                requires_watermark_disclosure,
                activated: req_bool(R, t, "activated")?,
                provisional_gate: req_str(R, t, "provisional_gate")?.to_string(),
                derivation: req_str(R, t, "derivation")?.to_string(),
                measurement_command: req_str(R, t, "measurement_command")?.to_string(),
                manifest,
            });
        }
        if rows.len() < 19 {
            return Err(invalid(
                R,
                format!(
                    "expected at least 19 §17 [[slo]] rows, found {}",
                    rows.len()
                ),
            ));
        }

        Ok(Self {
            reference_machine,
            rows,
        })
    }

    /// Activated §17 manifest IDs reported by `fa capabilities --json`.
    pub fn activated_manifest_ids(&self) -> Vec<String> {
        self.rows
            .iter()
            .filter(|r| r.activated)
            .map(|r| r.id.clone())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// lot_laws.toml (plan §6.5, §0.4 decision 5; bead fa-2ly)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LotLawRow {
    pub id: u16,
    pub version: u16,
    pub name: String,
    pub ordering: String,
    pub cost_method: String,
    pub rounding_law: String,
    pub admitted_regimes: Vec<String>,
    pub refused_regimes: Vec<String>,
    pub refusal_citation: Option<String>,
    pub citation: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfrsRuleRow {
    pub id: String,
    pub domain: String,
    pub rule: String,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LotLaws {
    pub laws: Vec<LotLawRow>,
    pub ifrs_rules: Vec<IfrsRuleRow>,
}

impl LotLaws {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::parse(LOT_LAWS_TOML)
    }

    pub fn parse(text: &str) -> Result<Self, RegistryError> {
        const R: &str = "lot_laws.toml";
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        let rounding_laws: BTreeSet<String> = crate::rounding_laws_embedded()?
            .into_iter()
            .map(|r| r.name)
            .collect();
        let allowed_regimes: BTreeSet<&str> = BTreeSet::from(["US-GAAP", "US-TAX", "IFRS"]);

        let mut laws = Vec::new();
        let mut seen_ids = BTreeSet::new();
        let mut seen_names = BTreeSet::new();
        for t in doc.arrays.get("law").into_iter().flatten() {
            let id = u16::try_from(req_int(R, t, "id")?)
                .map_err(|_| invalid(R, "law id out of u16 range"))?;
            let version = u16::try_from(req_int(R, t, "version")?)
                .map_err(|_| invalid(R, "law version out of u16 range"))?;
            let name = req_str(R, t, "name")?.to_string();
            if id == 0 || !seen_ids.insert(id) {
                return Err(invalid(R, format!("duplicate or zero lot law id {id}")));
            }
            if !seen_names.insert(name.clone()) {
                return Err(invalid(R, format!("duplicate lot law `{name}`")));
            }
            let ordering = req_str(R, t, "ordering")?.to_string();
            let cost_method = req_str(R, t, "cost_method")?.to_string();
            if !matches!(
                cost_method.as_str(),
                "lot_proportional" | "pooled_weighted_average"
            ) {
                return Err(invalid(
                    R,
                    format!("{name}: unknown cost_method `{cost_method}`"),
                ));
            }
            let rounding_law = req_str(R, t, "rounding_law")?.to_string();
            if !rounding_laws.contains(&rounding_law) {
                return Err(invalid(
                    R,
                    format!("{name}: unregistered rounding_law `{rounding_law}`"),
                ));
            }
            let admitted_regimes = req_str_vec(R, t, "admitted_regimes")?;
            let refused_regimes = req_str_vec(R, t, "refused_regimes")?;
            if admitted_regimes.is_empty() {
                return Err(invalid(
                    R,
                    format!("{name}: admitted_regimes must not be empty"),
                ));
            }
            for r in admitted_regimes.iter().chain(&refused_regimes) {
                if !allowed_regimes.contains(r.as_str()) {
                    return Err(invalid(R, format!("{name}: unknown regime `{r}`")));
                }
            }
            for r in &admitted_regimes {
                if refused_regimes.contains(r) {
                    return Err(invalid(
                        R,
                        format!("{name}: regime `{r}` is both admitted and refused"),
                    ));
                }
            }
            let refusal_citation = t
                .get("refusal_citation")
                .and_then(Value::as_str)
                .map(str::to_string);
            if !refused_regimes.is_empty() && refusal_citation.is_none() {
                return Err(invalid(
                    R,
                    format!("{name}: refused_regimes requires `refusal_citation`"),
                ));
            }
            if name == "LIFO" {
                if !refused_regimes.iter().any(|r| r == "IFRS") {
                    return Err(invalid(R, "LIFO must refuse regime `IFRS` per IAS 2.25"));
                }
                if !refusal_citation
                    .as_deref()
                    .is_some_and(|c| c.contains("IAS 2.25"))
                {
                    return Err(invalid(R, "LIFO refusal_citation must cite IAS 2.25"));
                }
            }
            laws.push(LotLawRow {
                id,
                version,
                name,
                ordering,
                cost_method,
                rounding_law,
                admitted_regimes,
                refused_regimes,
                refusal_citation,
                citation: req_str(R, t, "citation")?.to_string(),
            });
        }
        for required in ["FIFO", "LIFO", "SpecificId", "WeightedAverage"] {
            if !seen_names.contains(required) {
                return Err(invalid(R, format!("missing required lot law `{required}`")));
            }
        }

        let mut ifrs_rules = Vec::new();
        let mut seen_ifrs = BTreeSet::new();
        for t in doc.arrays.get("ifrs_rule").into_iter().flatten() {
            let id = req_str(R, t, "id")?.to_string();
            if !seen_ifrs.insert(id.clone()) {
                return Err(invalid(R, format!("duplicate ifrs_rule `{id}`")));
            }
            let status = req_str(R, t, "status")?.to_string();
            if !matches!(status.as_str(), "enforced" | "registered") {
                return Err(invalid(
                    R,
                    format!("{id}: status `{status}` must be `enforced` or `registered`"),
                ));
            }
            ifrs_rules.push(IfrsRuleRow {
                id,
                domain: req_str(R, t, "domain")?.to_string(),
                rule: req_str(R, t, "rule")?.to_string(),
                status,
            });
        }
        for required_ifrs in ["IAS-2.25", "IAS-29", "IAS-1.40A", "IAS-21"] {
            if !seen_ifrs.contains(required_ifrs) {
                return Err(invalid(
                    R,
                    format!("missing required §0.4 decision 5 IFRS rule `{required_ifrs}`"),
                ));
            }
        }

        Ok(Self { laws, ifrs_rules })
    }

    pub fn by_name(&self, name: &str) -> Option<&LotLawRow> {
        self.laws.iter().find(|l| l.name == name)
    }
}

// ---------------------------------------------------------------------------
// conversion_laws.toml (plan §6.5; bead fa-2ly)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversionLawRow {
    pub id: u16,
    pub version: u16,
    pub name: String,
    pub kind: String,
    pub from_code: String,
    pub from_scale: u8,
    pub to_code: String,
    pub to_scale: u8,
    pub numerator: String,
    pub denominator: String,
    pub rounding_law: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversionLaws {
    pub implicit_conversion: String,
    pub rows: Vec<ConversionLawRow>,
}

fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

impl ConversionLaws {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::parse(CONVERSION_LAWS_TOML)
    }

    pub fn parse(text: &str) -> Result<Self, RegistryError> {
        const R: &str = "conversion_laws.toml";
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        let implicit_conversion = req_str(R, &doc.root, "implicit_conversion")?.to_string();
        if implicit_conversion != "forbidden" {
            return Err(invalid(
                R,
                format!(
                    "implicit_conversion must be `forbidden` (plan §6.5), found `{implicit_conversion}`"
                ),
            ));
        }
        let rounding_laws: BTreeSet<String> = crate::rounding_laws_embedded()?
            .into_iter()
            .map(|r| r.name)
            .collect();

        let mut rows = Vec::new();
        let mut seen_ids = BTreeSet::new();
        let mut seen_names = BTreeSet::new();
        for t in doc.arrays.get("conversion_law").into_iter().flatten() {
            let id = u16::try_from(req_int(R, t, "id")?)
                .map_err(|_| invalid(R, "conversion_law id out of u16 range"))?;
            let version = u16::try_from(req_int(R, t, "version")?)
                .map_err(|_| invalid(R, "conversion_law version out of u16 range"))?;
            let name = req_str(R, t, "name")?.to_string();
            if id == 0 || !seen_ids.insert(id) {
                return Err(invalid(
                    R,
                    format!("duplicate or zero conversion_law id {id}"),
                ));
            }
            if !seen_names.insert(name.clone()) {
                return Err(invalid(R, format!("duplicate conversion_law `{name}`")));
            }
            let kind = req_str(R, t, "kind")?.to_string();
            if !matches!(
                kind.as_str(),
                "unit_conversion" | "scale_migration" | "split_adjustment"
            ) {
                return Err(invalid(R, format!("{name}: unknown kind `{kind}`")));
            }
            let from_code = req_str(R, t, "from_code")?.to_string();
            let from_scale = u8::try_from(req_int(R, t, "from_scale")?)
                .map_err(|_| invalid(R, "from_scale out of u8 range"))?;
            let to_code = req_str(R, t, "to_code")?.to_string();
            let to_scale = u8::try_from(req_int(R, t, "to_scale")?)
                .map_err(|_| invalid(R, "to_scale out of u8 range"))?;
            if from_scale > 38 || to_scale > 38 {
                return Err(invalid(R, format!("{name}: scale exceeds 38")));
            }
            let numerator = req_str(R, t, "numerator")?.to_string();
            let denominator = req_str(R, t, "denominator")?.to_string();
            let num: u128 = numerator.parse().map_err(|_| {
                invalid(
                    R,
                    format!("{name}: numerator `{numerator}` is not a positive u128"),
                )
            })?;
            let den: u128 = denominator.parse().map_err(|_| {
                invalid(
                    R,
                    format!("{name}: denominator `{denominator}` is not a positive u128"),
                )
            })?;
            if num == 0 || den == 0 {
                return Err(invalid(
                    R,
                    format!("{name}: numerator and denominator must be positive"),
                ));
            }
            if gcd_u128(num, den) != 1 {
                return Err(invalid(
                    R,
                    format!("{name}: rational factor {num}/{den} is not reduced to coprime terms"),
                ));
            }
            let rounding_law = req_str(R, t, "rounding_law")?.to_string();
            if !rounding_laws.contains(&rounding_law) {
                return Err(invalid(
                    R,
                    format!("{name}: unregistered rounding_law `{rounding_law}`"),
                ));
            }
            rows.push(ConversionLawRow {
                id,
                version,
                name,
                kind,
                from_code,
                from_scale,
                to_code,
                to_scale,
                numerator,
                denominator,
                rounding_law,
            });
        }
        if rows.is_empty() {
            return Err(invalid(R, "expected at least one [[conversion_law]] row"));
        }
        Ok(Self {
            implicit_conversion,
            rows,
        })
    }

    pub fn by_name(&self, name: &str) -> Option<&ConversionLawRow> {
        self.rows.iter().find(|r| r.name == name)
    }

    pub fn for_pair(&self, from_code: &str, to_code: &str) -> Vec<&ConversionLawRow> {
        self.rows
            .iter()
            .filter(|r| r.from_code == from_code && r.to_code == to_code)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// supersession_kinds.toml (plan §8.1, §8.2, FA-INV-08.net-law, FA-INV-08.replacement-paired; bead fa-oz3)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupersessionKindRow {
    pub tag: u8,
    pub name: String,
    pub netting_law: String,
    pub entry_class: String,
    pub requires_reason: bool,
    pub requires_case: bool,
    pub paired_with: String,
    pub statement: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReversalTargetClassRow {
    pub class: String,
    pub reversible: String,
    pub why: String,
    pub corrective_route: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupersessionKinds {
    pub kinds: Vec<SupersessionKindRow>,
    pub target_classes: Vec<ReversalTargetClassRow>,
}

const VALID_NETTING_LAWS: &[&str] = &[
    "negation",
    "paired_replacement",
    "partial_reclassification",
    "delta",
    "two_phase_resolution",
];

const EXPECTED_SUPERSESSION_KINDS: &[(u8, &str)] = &[
    (1, "Reverses"),
    (2, "Replaces"),
    (3, "Reclassifies"),
    (4, "Revises"),
    (5, "Restates"),
    (6, "Resolves"),
];

impl SupersessionKinds {
    pub fn embedded(classes: &crate::EntryClasses) -> Result<Self, RegistryError> {
        Self::parse(SUPERSESSION_KINDS_TOML, classes)
    }

    pub fn parse(text: &str, classes: &crate::EntryClasses) -> Result<Self, RegistryError> {
        const R: &str = "supersession_kinds.toml";
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }

        let mut kinds = Vec::new();
        let mut seen_tags = BTreeSet::new();
        let mut seen_names = BTreeSet::new();
        for t in doc
            .arrays
            .get("kind")
            .ok_or_else(|| invalid(R, "missing [[kind]]"))?
        {
            let tag = u8::try_from(req_int(R, t, "tag")?)
                .map_err(|_| invalid(R, "kind tag out of u8 range"))?;
            let name = req_str(R, t, "name")?.to_string();
            let netting_law = req_str(R, t, "netting_law")?.to_string();
            let entry_class = req_str(R, t, "entry_class")?.to_string();
            let requires_reason = req_bool(R, t, "requires_reason")?;
            let requires_case = req_bool(R, t, "requires_case")?;
            let paired_with = req_str(R, t, "paired_with")?.to_string();
            let statement = req_str(R, t, "statement")?.to_string();

            if !seen_tags.insert(tag) {
                return Err(invalid(R, format!("duplicate kind tag {tag}")));
            }
            if !seen_names.insert(name.clone()) {
                return Err(invalid(R, format!("duplicate kind `{name}`")));
            }
            if !VALID_NETTING_LAWS.contains(&netting_law.as_str()) {
                return Err(invalid(
                    R,
                    format!(
                        "FA-INV-08.net-law violation on `{name}`: unknown netting_law `{netting_law}`"
                    ),
                ));
            }
            if classes.by_name(&entry_class).is_none() {
                return Err(invalid(
                    R,
                    format!("`{name}` cites unknown entry_class `{entry_class}`"),
                ));
            }
            if name == "Replaces" {
                if paired_with != "Reverses" || netting_law != "paired_replacement" {
                    return Err(invalid(
                        R,
                        "FA-INV-08.replacement-paired violation: `Replaces` must set `paired_with = \"Reverses\"` and `netting_law = \"paired_replacement\"`",
                    ));
                }
            } else if paired_with != "none" {
                return Err(invalid(
                    R,
                    format!("`{name}` has unexpected paired_with `{paired_with}`"),
                ));
            }
            if matches!(name.as_str(), "Revises" | "Restates") && !requires_case {
                return Err(invalid(
                    R,
                    format!("`{name}` must require a RestatementCase (`requires_case = true`)"),
                ));
            }
            if statement.trim().is_empty() {
                return Err(invalid(R, format!("`{name}` requires non-empty statement")));
            }
            kinds.push(SupersessionKindRow {
                tag,
                name,
                netting_law,
                entry_class,
                requires_reason,
                requires_case,
                paired_with,
                statement,
            });
        }

        if kinds.len() != EXPECTED_SUPERSESSION_KINDS.len() {
            return Err(invalid(
                R,
                format!(
                    "expected {} [[kind]] rows, found {}",
                    EXPECTED_SUPERSESSION_KINDS.len(),
                    kinds.len()
                ),
            ));
        }
        for (expected_tag, expected_name) in EXPECTED_SUPERSESSION_KINDS {
            let Some(k) = kinds.iter().find(|r| r.tag == *expected_tag) else {
                return Err(invalid(
                    R,
                    format!("missing supersession kind tag {expected_tag} (`{expected_name}`)"),
                ));
            };
            if k.name != *expected_name {
                return Err(invalid(
                    R,
                    format!(
                        "tag {expected_tag} must be `{expected_name}`, found `{}`",
                        k.name
                    ),
                ));
            }
        }

        let mut target_classes = Vec::new();
        let mut seen_targets = BTreeSet::new();
        for t in doc
            .arrays
            .get("target_class")
            .ok_or_else(|| invalid(R, "missing [[target_class]]"))?
        {
            let class = req_str(R, t, "class")?.to_string();
            let reversible = req_str(R, t, "reversible")?.to_string();
            let why = req_str(R, t, "why")?.to_string();
            let corrective_route = req_str(R, t, "corrective_route")?.to_string();
            if !seen_targets.insert(class.clone()) {
                return Err(invalid(R, format!("duplicate [[target_class]] `{class}`")));
            }
            if !matches!(reversible.as_str(), "yes" | "posts_only" | "no") {
                return Err(invalid(
                    R,
                    format!("`{class}`: invalid reversible value `{reversible}`"),
                ));
            }
            let Some(class_def) = classes.by_name(&class) else {
                return Err(invalid(
                    R,
                    format!("[[target_class]] cites unknown entry class `{class}`"),
                ));
            };
            if class_def.kind == crate::ClassKind::Control && reversible != "no" {
                return Err(invalid(
                    R,
                    format!("control class `{class}` cannot be reversible (`{reversible}`)"),
                ));
            }
            if why.trim().is_empty() || corrective_route.trim().is_empty() {
                return Err(invalid(
                    R,
                    format!("`{class}` requires non-empty `why` and `corrective_route`"),
                ));
            }
            target_classes.push(ReversalTargetClassRow {
                class,
                reversible,
                why,
                corrective_route,
            });
        }

        for c in &classes.rows {
            if !seen_targets.contains(&c.name) {
                return Err(invalid(
                    R,
                    format!(
                        "missing [[target_class]] row for entry class `{}` (plan §8.2 totality)",
                        c.name
                    ),
                ));
            }
        }

        Ok(Self {
            kinds,
            target_classes,
        })
    }

    pub fn by_name(&self, name: &str) -> Option<&SupersessionKindRow> {
        self.kinds.iter().find(|k| k.name == name)
    }

    pub fn by_tag(&self, tag: u8) -> Option<&SupersessionKindRow> {
        self.kinds.iter().find(|k| k.tag == tag)
    }

    pub fn target_class(&self, class: &str) -> Option<&ReversalTargetClassRow> {
        self.target_classes.iter().find(|r| r.class == class)
    }
}

// ---------------------------------------------------------------------------
// tracing_laws.toml (plan §11.5, bead fa-j5ng)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TracingLawRow {
    pub id: u8,
    pub code: String,
    pub procedure_single: String,
    pub procedure_network: String,
    pub name: String,
    pub citation: String,
    pub presumption: String,
    pub supports_replenishment: bool,
    pub rounding_law: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntradayOrderRow {
    pub tag: u8,
    pub name: String,
    pub status: String,
    pub meaning: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplenishmentModeRow {
    pub tag: u8,
    pub name: String,
    pub status: String,
    pub meaning: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TracingLaws {
    pub laws: Vec<TracingLawRow>,
    pub intraday_orders: Vec<IntradayOrderRow>,
    pub replenishment_modes: Vec<ReplenishmentModeRow>,
}

const EXPECTED_TRACING_LAWS: &[(u8, &str, &str, &str)] = &[
    (1, "libr", "trace.libr", "trace.network_libr"),
    (2, "fifo", "trace.fifo", "trace.network_fifo"),
    (3, "lifo", "trace.lifo", "trace.network_lifo"),
    (4, "pro_rata", "trace.pro_rata", "trace.network_pro_rata"),
    (
        5,
        "restitution_order",
        "trace.restitution_order",
        "trace.restitution_order",
    ),
];

impl TracingLaws {
    pub fn embedded(procedures: &crate::procedures::Procedures) -> Result<Self, RegistryError> {
        Self::parse(TRACING_LAWS_TOML, procedures)
    }

    pub fn parse(
        text: &str,
        procedures: &crate::procedures::Procedures,
    ) -> Result<Self, RegistryError> {
        const R: &str = "tracing_laws.toml";
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }

        let mut laws = Vec::new();
        let mut seen_ids = BTreeSet::new();
        let mut seen_codes = BTreeSet::new();
        for t in doc
            .arrays
            .get("law")
            .ok_or_else(|| invalid(R, "missing [[law]]"))?
        {
            let id = u8::try_from(req_int(R, t, "id")?)
                .map_err(|_| invalid(R, "law id out of u8 range"))?;
            let code = req_str(R, t, "code")?.to_string();
            let procedure_single = req_str(R, t, "procedure_single")?.to_string();
            let procedure_network = req_str(R, t, "procedure_network")?.to_string();
            let name = req_str(R, t, "name")?.to_string();
            let citation = req_str(R, t, "citation")?.to_string();
            let presumption = req_str(R, t, "presumption")?.to_string();
            let supports_replenishment = req_bool(R, t, "supports_replenishment")?;
            let rounding_law = req_str(R, t, "rounding_law")?.to_string();

            if !seen_ids.insert(id) {
                return Err(invalid(R, format!("duplicate tracing law id `{id}`")));
            }
            if !seen_codes.insert(code.clone()) {
                return Err(invalid(R, format!("duplicate tracing law code `{code}`")));
            }
            if procedures.get(&procedure_single).is_none() {
                return Err(invalid(
                    R,
                    format!(
                        "`{code}`: procedure_single `{procedure_single}` is not registered in procedures.toml"
                    ),
                ));
            }
            if procedures.get(&procedure_network).is_none() {
                return Err(invalid(
                    R,
                    format!(
                        "`{code}`: procedure_network `{procedure_network}` is not registered in procedures.toml"
                    ),
                ));
            }
            if !matches!(
                presumption.as_str(),
                "clean_dissipated_first"
                    | "oldest_drawn_first"
                    | "newest_drawn_first"
                    | "proportional_co_mingled_pool"
                    | "parameterized_by_order"
            ) {
                return Err(invalid(
                    R,
                    format!("`{code}`: unknown presumption `{presumption}`"),
                ));
            }
            if rounding_law != "LargestRemainder" {
                return Err(invalid(
                    R,
                    format!(
                        "`{code}`: rounding_law must be `LargestRemainder` (got `{rounding_law}`)"
                    ),
                ));
            }
            if name.trim().is_empty() || citation.trim().is_empty() {
                return Err(invalid(
                    R,
                    format!("`{code}` requires non-empty `name` and `citation`"),
                ));
            }
            laws.push(TracingLawRow {
                id,
                code,
                procedure_single,
                procedure_network,
                name,
                citation,
                presumption,
                supports_replenishment,
                rounding_law,
            });
        }

        if laws.len() != EXPECTED_TRACING_LAWS.len() {
            return Err(invalid(
                R,
                format!(
                    "expected {} [[law]] rows, found {}",
                    EXPECTED_TRACING_LAWS.len(),
                    laws.len()
                ),
            ));
        }
        for (exp_id, exp_code, exp_single, exp_net) in EXPECTED_TRACING_LAWS {
            let Some(row) = laws.iter().find(|r| r.id == *exp_id) else {
                return Err(invalid(
                    R,
                    format!("missing tracing law id {exp_id} (`{exp_code}`)"),
                ));
            };
            if row.code != *exp_code
                || row.procedure_single != *exp_single
                || row.procedure_network != *exp_net
            {
                return Err(invalid(
                    R,
                    format!(
                        "tracing law id {exp_id} must map `{exp_code}` -> ({exp_single}, {exp_net})"
                    ),
                ));
            }
        }

        let mut intraday_orders = Vec::new();
        let mut seen_order_tags = BTreeSet::new();
        for t in doc
            .arrays
            .get("intraday_order")
            .ok_or_else(|| invalid(R, "missing [[intraday_order]]"))?
        {
            let tag = u8::try_from(req_int(R, t, "tag")?)
                .map_err(|_| invalid(R, "intraday_order tag out of u8 range"))?;
            let name = req_str(R, t, "name")?.to_string();
            let status = req_str(R, t, "status")?.to_string();
            let meaning = req_str(R, t, "meaning")?.to_string();
            if !seen_order_tags.insert(tag) {
                return Err(invalid(R, format!("duplicate intraday_order tag `{tag}`")));
            }
            if !matches!(status.as_str(), "live" | "reserved") {
                return Err(invalid(
                    R,
                    format!("intraday_order `{name}`: invalid status `{status}`"),
                ));
            }
            if name.trim().is_empty() || meaning.trim().is_empty() {
                return Err(invalid(
                    R,
                    format!("intraday_order tag {tag} requires non-empty name and meaning"),
                ));
            }
            intraday_orders.push(IntradayOrderRow {
                tag,
                name,
                status,
                meaning,
            });
        }
        if intraday_orders.len() != 4 {
            return Err(invalid(
                R,
                format!(
                    "expected 4 [[intraday_order]] rows, found {}",
                    intraday_orders.len()
                ),
            ));
        }

        let mut replenishment_modes = Vec::new();
        let mut seen_rep_tags = BTreeSet::new();
        for t in doc
            .arrays
            .get("replenishment_mode")
            .ok_or_else(|| invalid(R, "missing [[replenishment_mode]]"))?
        {
            let tag = u8::try_from(req_int(R, t, "tag")?)
                .map_err(|_| invalid(R, "replenishment_mode tag out of u8 range"))?;
            let name = req_str(R, t, "name")?.to_string();
            let status = req_str(R, t, "status")?.to_string();
            let meaning = req_str(R, t, "meaning")?.to_string();
            if !seen_rep_tags.insert(tag) {
                return Err(invalid(
                    R,
                    format!("duplicate replenishment_mode tag `{tag}`"),
                ));
            }
            if !matches!(status.as_str(), "live" | "reserved") {
                return Err(invalid(
                    R,
                    format!("replenishment_mode `{name}`: invalid status `{status}`"),
                ));
            }
            if name.trim().is_empty() || meaning.trim().is_empty() {
                return Err(invalid(
                    R,
                    format!("replenishment_mode tag {tag} requires non-empty name and meaning"),
                ));
            }
            replenishment_modes.push(ReplenishmentModeRow {
                tag,
                name,
                status,
                meaning,
            });
        }
        if replenishment_modes.len() != 2 {
            return Err(invalid(
                R,
                format!(
                    "expected 2 [[replenishment_mode]] rows, found {}",
                    replenishment_modes.len()
                ),
            ));
        }

        Ok(Self {
            laws,
            intraday_orders,
            replenishment_modes,
        })
    }

    pub fn by_code(&self, code: &str) -> Option<&TracingLawRow> {
        self.laws.iter().find(|r| r.code == code)
    }
}

// ---------------------------------------------------------------------------
// fx_laws.toml (plan §5.2, §5.7, §6.4; FA-INV-01, FA-INV-04; bead fa-s3c)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FxLawRow {
    pub id: u16,
    pub version: u16,
    pub code: String,
    pub name: String,
    pub rate_purpose: String,
    pub date_selector: String,
    pub rounding_law: String,
    pub residual_mode: String,
    pub admitted_classes: Vec<String>,
    pub status: String,
    pub standard_ref: String,
    pub meaning: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationDifferenceKindRow {
    pub tag: u8,
    pub name: String,
    pub requires_conversion_account: bool,
    pub status: String,
    pub meaning: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FxLaws {
    pub ad_hoc_rate_admission: String,
    pub residual_bound_law: String,
    pub realized_fx_mode: String,
    pub laws: Vec<FxLawRow>,
    pub application_difference_kinds: Vec<ApplicationDifferenceKindRow>,
}

impl FxLaws {
    pub fn embedded(classes: &crate::EntryClasses) -> Result<Self, RegistryError> {
        Self::parse(FX_LAWS_TOML, classes)
    }

    pub fn parse(text: &str, classes: &crate::EntryClasses) -> Result<Self, RegistryError> {
        const R: &str = "fx_laws.toml";
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        let ad_hoc_rate_admission = req_str(R, &doc.root, "ad_hoc_rate_admission")?.to_string();
        if ad_hoc_rate_admission != "forbidden" {
            return Err(invalid(
                R,
                format!("ad_hoc_rate_admission must be `forbidden`, got `{ad_hoc_rate_admission}`"),
            ));
        }
        let residual_bound_law = req_str(R, &doc.root, "residual_bound_law")?.to_string();
        if residual_bound_law != "strictly_less_than_one_base_minor_unit_times_foreign_leg_count" {
            return Err(invalid(
                R,
                format!("invalid residual_bound_law `{residual_bound_law}`"),
            ));
        }
        let realized_fx_mode = req_str(R, &doc.root, "realized_fx_mode")?.to_string();
        if realized_fx_mode != "paired_conversion_account" {
            return Err(invalid(
                R,
                format!(
                    "realized_fx_mode must be `paired_conversion_account`, got `{realized_fx_mode}`"
                ),
            ));
        }

        let valid_rounding = [
            "HalfEven",
            "HalfUp",
            "HalfDown",
            "HalfAwayFromZero",
            "Floor",
            "Ceiling",
            "Truncate",
        ];

        let mut laws = Vec::new();
        let mut seen_ids = BTreeSet::new();
        let mut seen_codes = BTreeSet::new();
        let mut seen_names = BTreeSet::new();
        for t in doc
            .arrays
            .get("law")
            .ok_or_else(|| invalid(R, "missing [[law]]"))?
        {
            let id = u16::try_from(req_int(R, t, "id")?)
                .map_err(|_| invalid(R, "law id out of u16 range"))?;
            let version = u16::try_from(req_int(R, t, "version")?)
                .map_err(|_| invalid(R, "law version out of u16 range"))?;
            if id == 0 || version == 0 {
                return Err(invalid(R, "law id and version must be positive"));
            }
            let code = req_str(R, t, "code")?.to_string();
            let name = req_str(R, t, "name")?.to_string();
            let rate_purpose = req_str(R, t, "rate_purpose")?.to_string();
            let date_selector = req_str(R, t, "date_selector")?.to_string();
            let rounding_law = req_str(R, t, "rounding_law")?.to_string();
            let residual_mode = req_str(R, t, "residual_mode")?.to_string();
            let admitted_classes = req_str_vec(R, t, "admitted_classes")?;
            let status = req_str(R, t, "status")?.to_string();
            let standard_ref = req_str(R, t, "standard_ref")?.to_string();
            let meaning = req_str(R, t, "meaning")?.to_string();

            if !seen_ids.insert(id) {
                return Err(invalid(R, format!("duplicate law id `{id}`")));
            }
            if !seen_codes.insert(code.clone()) {
                return Err(invalid(R, format!("duplicate law code `{code}`")));
            }
            if !seen_names.insert(name.clone()) {
                return Err(invalid(R, format!("duplicate law name `{name}`")));
            }
            if !matches!(
                rate_purpose.as_str(),
                "SpotClose" | "PeriodClose" | "PeriodAverage" | "Settlement"
            ) {
                return Err(invalid(
                    R,
                    format!("law `{code}`: invalid rate_purpose `{rate_purpose}`"),
                ));
            }
            if !matches!(
                date_selector.as_str(),
                "entry_effective_date" | "period_end_date" | "settlement_and_settled_item_dates"
            ) {
                return Err(invalid(
                    R,
                    format!("law `{code}`: invalid date_selector `{date_selector}`"),
                ));
            }
            if !valid_rounding.contains(&rounding_law.as_str()) {
                return Err(invalid(
                    R,
                    format!("law `{code}`: unknown rounding_law `{rounding_law}`"),
                ));
            }
            if !matches!(residual_mode.as_str(), "designated_leg" | "none") {
                return Err(invalid(
                    R,
                    format!("law `{code}`: invalid residual_mode `{residual_mode}`"),
                ));
            }
            if matches!(
                name.as_str(),
                "PeriodEndRevaluation"
                    | "TranslationCurrentRate"
                    | "RemeasurementTemporal"
                    | "RemeasurementIas29Hyperinflation"
            ) && residual_mode != "none"
            {
                return Err(invalid(
                    R,
                    format!("{name} must have residual_mode = `none`"),
                ));
            }
            if admitted_classes.is_empty() {
                return Err(invalid(
                    R,
                    format!("law `{code}` must declare non-empty admitted_classes"),
                ));
            }
            for cls in &admitted_classes {
                let Some(row) = classes.by_name(cls) else {
                    return Err(invalid(
                        R,
                        format!("law `{code}`: unknown entry class `{cls}`"),
                    ));
                };
                if row.kind != crate::ClassKind::Posting {
                    return Err(invalid(
                        R,
                        format!("law `{code}`: control class `{cls}` cannot carry FX valuation"),
                    ));
                }
            }
            if !matches!(status.as_str(), "live" | "reserved") {
                return Err(invalid(
                    R,
                    format!("law `{code}`: invalid status `{status}`"),
                ));
            }
            if standard_ref.trim().is_empty() || meaning.trim().is_empty() {
                return Err(invalid(
                    R,
                    format!("law `{code}` requires non-empty standard_ref and meaning"),
                ));
            }
            laws.push(FxLawRow {
                id,
                version,
                code,
                name,
                rate_purpose,
                date_selector,
                rounding_law,
                residual_mode,
                admitted_classes,
                status,
                standard_ref,
                meaning,
            });
        }
        if laws.len() != 7 {
            return Err(invalid(
                R,
                format!("expected 7 [[law]] rows, found {}", laws.len()),
            ));
        }
        for required_code in [
            "spot_close",
            "period_end_revaluation",
            "period_average",
            "settlement_carrying_basis",
            "translation_current_rate",
            "remeasurement_temporal",
            "remeasurement_ias29_hyperinflation",
        ] {
            if !seen_codes.contains(required_code) {
                return Err(invalid(
                    R,
                    format!("missing required FX law `{required_code}`"),
                ));
            }
        }

        let mut application_difference_kinds = Vec::new();
        let mut seen_diff_tags = BTreeSet::new();
        let mut seen_diff_names = BTreeSet::new();
        for t in doc
            .arrays
            .get("application_difference_kind")
            .ok_or_else(|| invalid(R, "missing [[application_difference_kind]]"))?
        {
            let tag = u8::try_from(req_int(R, t, "tag")?)
                .map_err(|_| invalid(R, "application_difference_kind tag out of u8 range"))?;
            let name = req_str(R, t, "name")?.to_string();
            let requires_conversion_account = req_bool(R, t, "requires_conversion_account")?;
            let status = req_str(R, t, "status")?.to_string();
            let meaning = req_str(R, t, "meaning")?.to_string();
            if !seen_diff_tags.insert(tag) {
                return Err(invalid(
                    R,
                    format!("duplicate application_difference_kind tag `{tag}`"),
                ));
            }
            if !seen_diff_names.insert(name.clone()) {
                return Err(invalid(
                    R,
                    format!("duplicate application_difference_kind name `{name}`"),
                ));
            }
            if name == "RealizedFx" && !requires_conversion_account {
                return Err(invalid(
                    R,
                    "RealizedFx must declare requires_conversion_account = true (FA-INV-01.realized-fx)",
                ));
            }
            if !matches!(status.as_str(), "live" | "reserved") {
                return Err(invalid(
                    R,
                    format!("application_difference_kind `{name}`: invalid status `{status}`"),
                ));
            }
            if meaning.trim().is_empty() {
                return Err(invalid(
                    R,
                    format!("application_difference_kind `{name}` requires non-empty meaning"),
                ));
            }
            application_difference_kinds.push(ApplicationDifferenceKindRow {
                tag,
                name,
                requires_conversion_account,
                status,
                meaning,
            });
        }
        if application_difference_kinds.len() != 5 {
            return Err(invalid(
                R,
                format!(
                    "expected 5 [[application_difference_kind]] rows, found {}",
                    application_difference_kinds.len()
                ),
            ));
        }

        Ok(Self {
            ad_hoc_rate_admission,
            residual_bound_law,
            realized_fx_mode,
            laws,
            application_difference_kinds,
        })
    }

    pub fn by_id(&self, id: u16, version: u16) -> Option<&FxLawRow> {
        self.laws
            .iter()
            .find(|r| r.id == id && r.version == version)
    }

    pub fn by_code(&self, code: &str) -> Option<&FxLawRow> {
        self.laws.iter().find(|r| r.code == code)
    }

    pub fn by_name(&self, name: &str) -> Option<&FxLawRow> {
        self.laws.iter().find(|r| r.name == name)
    }
}

// =============================================================================
// 14. Interop & Conformance Formats (`registries/formats.toml`, bead `fa-npi`)
// =============================================================================

pub const FORMATS_TOML: &str = include_str!("../../../registries/formats.toml");

const VALID_FORMAT_KINDS: &[&str] = &[
    "plain_text_journal",
    "semantic_corpus",
    "audit_data_standard",
    "regulatory_filing",
    "tabular_extract",
    "bank_statement",
    "legacy_gl_export",
    "litigation_load_file",
];

const VALID_FORMAT_DIRECTIONS: &[&str] = &["import", "export", "both"];

/// One format row from `registries/formats.toml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatRow {
    pub id: u16,
    pub name: String,
    pub kind: String,
    pub direction: String,
    pub mime: String,
    pub extension: String,
    pub oracle_tool: String,
    pub round_trip_identity: bool,
    pub certified_coordinate: bool,
    pub plan_ref: String,
    pub summary: String,
}

/// The parsed `registries/formats.toml` registry (`fa-npi`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Formats {
    pub schema_version: u32,
    pub rows: Vec<FormatRow>,
}

impl Formats {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::parse(FORMATS_TOML)
    }

    pub fn parse(src: &str) -> Result<Self, RegistryError> {
        const R: &str = "formats.toml";
        let doc = load(R, src)?;
        let schema_version = u32::try_from(req_int(R, &doc.root, "schema_version")?)
            .map_err(|_| invalid(R, "schema_version out of u32 range"))?;
        if schema_version != 1 {
            return Err(invalid(
                R,
                format!("unsupported schema_version {schema_version}"),
            ));
        }

        let mut seen_ids = BTreeSet::new();
        let mut seen_names = BTreeSet::new();
        let mut rows = Vec::new();
        for sec in doc
            .arrays
            .get("format")
            .ok_or_else(|| invalid(R, "missing [[format]]"))?
        {
            let id = u16::try_from(req_int(R, sec, "id")?)
                .map_err(|_| invalid(R, "format id out of u16 range"))?;
            let name = req_str(R, sec, "name")?.to_string();
            let kind = req_str(R, sec, "kind")?.to_string();
            let direction = req_str(R, sec, "direction")?.to_string();
            let mime = req_str(R, sec, "mime")?.to_string();
            let extension = req_str(R, sec, "extension")?.to_string();
            let oracle_tool = req_str(R, sec, "oracle_tool")?.to_string();
            let round_trip_identity = req_bool(R, sec, "round_trip_identity")?;
            let certified_coordinate = req_bool(R, sec, "certified_coordinate")?;
            let plan_ref = req_str(R, sec, "plan_ref")?.to_string();
            let summary = req_str(R, sec, "summary")?.to_string();

            if id == 0 || !seen_ids.insert(id) {
                return Err(invalid(R, format!("duplicate or zero format id {id}")));
            }
            if name.trim().is_empty() || !seen_names.insert(name.clone()) {
                return Err(invalid(
                    R,
                    format!("duplicate or empty format name {name:?}"),
                ));
            }
            if !VALID_FORMAT_KINDS.contains(&kind.as_str()) {
                return Err(invalid(
                    R,
                    format!(
                        "format {name:?} has unknown kind {kind:?} (expected one of {VALID_FORMAT_KINDS:?})"
                    ),
                ));
            }
            if !VALID_FORMAT_DIRECTIONS.contains(&direction.as_str()) {
                return Err(invalid(
                    R,
                    format!(
                        "format {name:?} has unknown direction {direction:?} (expected one of {VALID_FORMAT_DIRECTIONS:?})"
                    ),
                ));
            }
            if round_trip_identity && direction != "both" {
                return Err(invalid(
                    R,
                    format!(
                        "format {name:?} declares round_trip_identity = true but direction = {direction:?} (requires \"both\")"
                    ),
                ));
            }
            if kind == "audit_data_standard" && (!round_trip_identity || !certified_coordinate) {
                return Err(invalid(
                    R,
                    format!(
                        "audit_data_standard format {name:?} must declare round_trip_identity = true and certified_coordinate = true"
                    ),
                ));
            }
            if mime.trim().is_empty()
                || extension.trim().is_empty()
                || oracle_tool.trim().is_empty()
                || plan_ref.trim().is_empty()
                || summary.trim().is_empty()
            {
                return Err(invalid(
                    R,
                    format!("format {name:?} has empty required string field"),
                ));
            }

            rows.push(FormatRow {
                id,
                name,
                kind,
                direction,
                mime,
                extension,
                oracle_tool,
                round_trip_identity,
                certified_coordinate,
                plan_ref,
                summary,
            });
        }

        for required in [
            "beancount_v3",
            "hledger_journal",
            "ledger_cli_journal",
            "tigerbeetle_corpus_v1",
            "aicpa_ads_gl_v2",
            "oecd_saft_v2",
            "xbrl_gl_instance_v1",
            "csv_gl_v1",
            "ndjson_gl_stream_v1",
            "iso20022_camt053",
            "bai2_v2",
            "ofx_qbo_v2",
            "quickbooks_iif_v1",
            "quickbooks_csv_v1",
            "xero_csv_v1",
            "netsuite_csv_v1",
        ] {
            if !seen_names.contains(required) {
                return Err(invalid(
                    R,
                    format!("missing required interop format {required:?}"),
                ));
            }
        }

        Ok(Self {
            schema_version,
            rows,
        })
    }

    pub fn by_name(&self, name: &str) -> Option<&FormatRow> {
        self.rows.iter().find(|r| r.name == name)
    }

    pub fn by_id(&self, id: u16) -> Option<&FormatRow> {
        self.rows.iter().find(|r| r.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_g0_registries_parse_and_agree_with_code() {
        let constitution = Constitution::embedded().expect("constitution.toml");
        assert_eq!(constitution.claim_classes.len(), 6);
        assert_eq!(constitution.bets.len(), 6);
        assert_eq!(constitution.constraints.len(), 14);

        let evidence = EvidenceRegistry::embedded().expect("evidence.toml");
        assert_eq!(evidence.gates.len(), 9);

        let checkers = CheckerIndex::embedded().expect("checker_index.toml");
        assert_eq!(checkers.checkers.len(), 6);

        let invariants = Invariants::embedded().expect("invariants.toml");
        let lanes = ProofLanes::embedded(&invariants).expect("proof_lanes.toml");
        assert_eq!(lanes.lanes.len(), 11);

        let period_states = PeriodStatesRegistry::embedded().expect("period_states.toml");
        assert_eq!(period_states.states.len(), 5);
        assert_eq!(period_states.kinds.len(), 5);
        assert_eq!(period_states.transitions.len(), 10);

        let rel_bases = RelationshipBases::embedded().expect("relationship_bases.toml");
        assert_eq!(rel_bases.rows.len(), 10);

        let claims_lint = ClaimsLintConfig::embedded().expect("claims_lint.toml");
        assert_eq!(claims_lint.g0_registries.len(), 37);

        let op_costs = OperationCosts::embedded().expect("operation_costs.toml");
        assert_eq!(op_costs.hot_object_exceptions.len(), 2);
        assert_eq!(op_costs.classes.len(), 24);
        assert_eq!(op_costs.kernel_op_witnesses.len(), 9);

        let slo = SloRegistry::embedded(&op_costs).expect("slo.toml");
        assert_eq!(slo.rows.len(), 20);
        assert_eq!(slo.activated_manifest_ids().len(), 20);

        let lot_laws = LotLaws::embedded().expect("lot_laws.toml");
        assert_eq!(lot_laws.laws.len(), 4);
        assert_eq!(lot_laws.ifrs_rules.len(), 4);

        let conversion_laws = ConversionLaws::embedded().expect("conversion_laws.toml");
        assert_eq!(conversion_laws.implicit_conversion, "forbidden");
        assert_eq!(conversion_laws.rows.len(), 8);

        let classes = crate::EntryClasses::embedded().expect("entry_classes.toml");
        let sup_kinds = SupersessionKinds::embedded(&classes).expect("supersession_kinds.toml");
        assert_eq!(sup_kinds.kinds.len(), 6);
        assert_eq!(sup_kinds.target_classes.len(), classes.rows.len());

        let procedures = crate::procedures::Procedures::embedded().expect("procedures.toml");
        let tracing_laws = TracingLaws::embedded(&procedures).expect("tracing_laws.toml");
        assert_eq!(tracing_laws.laws.len(), 5);
        assert_eq!(tracing_laws.intraday_orders.len(), 4);
        assert_eq!(tracing_laws.replenishment_modes.len(), 2);

        let fx_laws = FxLaws::embedded(&classes).expect("fx_laws.toml");
        assert_eq!(fx_laws.laws.len(), 7);
        assert_eq!(fx_laws.application_difference_kinds.len(), 5);

        let formats = Formats::embedded().expect("formats.toml");
        assert_eq!(formats.rows.len(), 19);
    }

    #[test]
    fn operation_cost_classes_require_exact_registered_identities() {
        let op_costs = OperationCosts::embedded().expect("operation_costs.toml");
        let bank = op_costs
            .class("bank_statement_import")
            .expect("bank import has its own cost contract");
        assert_eq!(bank.today_transactions, 1);
        assert_eq!(bank.barrier_count, 2);
        assert_eq!(bank.today_barrier_count, 2);
        assert_eq!(
            bank.substrate_transactions,
            "1 for a new statement; 0 for an exact retry"
        );
        assert!(bank.hot_object_exceptions.is_empty());

        for id in [
            "closing_routes_record",
            "year_end_close",
            "bank_match_confirmation",
            "bank_match_unmatch",
        ] {
            let closing = op_costs.class(id).expect("native closing cost contract");
            assert_eq!(closing.today_transactions, 1);
            assert_eq!(closing.barrier_count, 2);
            assert_eq!(closing.today_barrier_count, 2);
            assert!(closing.hot_object_exceptions.is_empty());
        }

        // Preserve row count and all class references while substituting each
        // identity. A count-only guard would accept every one of these edits.
        for required in REQUIRED_OPERATION_CLASS_IDS {
            let substituted = OPERATION_COSTS_TOML
                .replace(&format!("\"{required}\""), "\"unregistered_operation\"");
            let err = OperationCosts::parse(&substituted)
                .expect_err("another class cannot replace a required operation");
            assert!(
                err.to_string()
                    .contains(&format!("missing required operation_class `{required}`")),
                "{err}"
            );
        }

        let bank_row = OPERATION_COSTS_TOML
            .split("\n\n")
            .find(|row| row.starts_with("[[operation_class]]\nid = \"bank_statement_import\"\n"))
            .expect("bank import registry row");
        let missing = OPERATION_COSTS_TOML.replacen(bank_row, "", 1);
        let err = OperationCosts::parse(&missing)
            .expect_err("the original 19 classes no longer cover every native operation");
        assert!(
            err.to_string()
                .contains("missing required operation_class `bank_statement_import`"),
            "{err}"
        );

        let extra_row = bank_row
            .replace("\"bank_statement_import\"", "\"unregistered_operation\"")
            .replace(
                "Bank statement import with source-linked line documents",
                "Unregistered bank import",
            );
        let extra = format!("{OPERATION_COSTS_TOML}\n\n{extra_row}");
        let err = OperationCosts::parse(&extra)
            .expect_err("an extra class needs an explicit native cost contract");
        assert!(
            err.to_string()
                .contains("unregistered operation_class `unregistered_operation`"),
            "{err}"
        );
    }

    #[test]
    fn planted_slo_and_operation_cost_violations_fail() {
        let op_costs = OperationCosts::embedded().expect("operation_costs.toml");

        // Planted negative 1 (fa-i5s): an slo row typed `invariant` fails the claims lint.
        let bad_claim = SLO_TOML.replacen(
            "claim_class = \"benchmark\"",
            "claim_class = \"invariant\"",
            1,
        );
        let err = SloRegistry::parse(&bad_claim, &op_costs).expect_err("invariant claim on slo");
        assert!(
            err.to_string().contains("claims_lint") && err.to_string().contains("invariant"),
            "{err}"
        );

        // Planted negative 2 (§17 derivability law): a posting gate below barrier_count * fsync_p50 fails.
        let bad_derivability = SLO_TOML.replacen("target_p50_us = 2000", "target_p50_us = 1500", 1);
        let err =
            SloRegistry::parse(&bad_derivability, &op_costs).expect_err("below barrier floor");
        assert!(
            err.to_string().contains("derivability law violation"),
            "{err}"
        );

        // Planted negative 3 (§17 standing law): balance read without watermark disclosure fails.
        let bad_watermark = SLO_TOML.replacen(
            "name = \"balance_read_watermark\"\ndomain = \"Balance read at watermark (SnapshotQuery class)\"\noperation_class = \"balance_read_at_watermark\"\nclaim_class = \"benchmark\"\ncounting_unit = \"balance_read\"\npinned_fsync_p50_us = 1000\ntarget_p50_us = 10\ntarget_p99_us = 50\nrequires_watermark_disclosure = true",
            "name = \"balance_read_watermark\"\ndomain = \"Balance read at watermark (SnapshotQuery class)\"\noperation_class = \"balance_read_at_watermark\"\nclaim_class = \"benchmark\"\ncounting_unit = \"balance_read\"\npinned_fsync_p50_us = 1000\ntarget_p50_us = 10\ntarget_p99_us = 50\nrequires_watermark_disclosure = false",
            1,
        );
        let err = SloRegistry::parse(&bad_watermark, &op_costs)
            .expect_err("missing watermark disclosure");
        assert!(
            err.to_string().contains("requires_watermark_disclosure"),
            "{err}"
        );

        // Planted negative 4 (Appendix G Law 3): unregistered hot object on single_entry_post fails.
        let bad_hot_obj = OPERATION_COSTS_TOML.replacen(
            "id = \"single_entry_post\"\nname = \"Single-entry post\"\nsubstrate_class = \"Autocommit write, fused arm\"\nsubstrate_transactions = \"1\"\ntoday_posture = \"One publication (capsule-first, marker-last, two ordered syncs), no group commit (Appendix H R-GC)\"\ntoday_transactions = 1\nbarrier_count = 2\ntoday_barrier_count = 2\nderived_objects = \"1 Entry + n Leg + edges + ExternalIds + 1 IntentOutcome\"\nhot_object_exceptions = []",
            "id = \"single_entry_post\"\nname = \"Single-entry post\"\nsubstrate_class = \"Autocommit write, fused arm\"\nsubstrate_transactions = \"1\"\ntoday_posture = \"One publication (capsule-first, marker-last, two ordered syncs), no group commit (Appendix H R-GC)\"\ntoday_transactions = 1\nbarrier_count = 2\ntoday_barrier_count = 2\nderived_objects = \"1 Entry + n Leg + edges + ExternalIds + 1 IntentOutcome\"\nhot_object_exceptions = [\"LimitCell\"]",
            1,
        );
        let err = OperationCosts::parse(&bad_hot_obj).expect_err("unscoped hot object");
        assert!(err.to_string().contains("Appendix G Law 3"), "{err}");

        // Planted negative 5 (fa-2ly): LIFO admitted under IFRS or unreduced conversion factor fails.
        let bad_lifo =
            LOT_LAWS_TOML.replacen("refused_regimes = [\"IFRS\"]", "refused_regimes = []", 1);
        let err = LotLaws::parse(&bad_lifo).expect_err("LIFO admitted under IFRS");
        assert!(err.to_string().contains("IAS 2.25"), "{err}");

        let bad_conv = CONVERSION_LAWS_TOML
            .replacen(
                "numerator = \"8\"",
                "numerator = \"16\"\ndenominator = \"2\"",
                1,
            )
            .replacen("denominator = \"1\"", "", 1);
        let err = ConversionLaws::parse(&bad_conv).expect_err("unreduced conversion factor");
        assert!(err.to_string().contains("coprime"), "{err}");

        // Planted negative 6 (fa-oz3): unregistered netting law or unpaired Replaces fails.
        let classes = crate::EntryClasses::embedded().expect("entry_classes.toml");
        let bad_net_law = SUPERSESSION_KINDS_TOML.replacen(
            "netting_law = \"negation\"",
            "netting_law = \"ad_hoc\"",
            1,
        );
        let err =
            SupersessionKinds::parse(&bad_net_law, &classes).expect_err("unregistered netting law");
        assert!(err.to_string().contains("FA-INV-08.net-law"), "{err}");

        let bad_paired = SUPERSESSION_KINDS_TOML.replacen(
            "paired_with = \"Reverses\"",
            "paired_with = \"none\"",
            1,
        );
        let err = SupersessionKinds::parse(&bad_paired, &classes).expect_err("unpaired Replaces");
        assert!(
            err.to_string().contains("FA-INV-08.replacement-paired"),
            "{err}"
        );

        // Planted negative 7 (fa-j5ng): unregistered procedure foreign key in tracing_laws.toml fails.
        let procedures = crate::procedures::Procedures::embedded().expect("procedures.toml");
        let bad_trace_proc = TRACING_LAWS_TOML.replacen(
            "procedure_network = \"trace.network_libr\"",
            "procedure_network = \"trace.no_such_proc\"",
            1,
        );
        let err = TracingLaws::parse(&bad_trace_proc, &procedures)
            .expect_err("unregistered procedure_network");
        assert!(
            err.to_string()
                .contains("not registered in procedures.toml"),
            "{err}"
        );

        // Planted negative 8 (fa-s3c): ad-hoc rate admission or RealizedFx without conversion account fails.
        let bad_fx = FX_LAWS_TOML.replacen(
            "ad_hoc_rate_admission = \"forbidden\"",
            "ad_hoc_rate_admission = \"allowed\"",
            1,
        );
        let err = FxLaws::parse(&bad_fx, &classes).expect_err("ad-hoc rate admission");
        assert!(err.to_string().contains("forbidden"), "{err}");

        let bad_realized = FX_LAWS_TOML.replacen(
            "name = \"RealizedFx\"\nrequires_conversion_account = true",
            "name = \"RealizedFx\"\nrequires_conversion_account = false",
            1,
        );
        let err = FxLaws::parse(&bad_realized, &classes)
            .expect_err("RealizedFx without conversion account");
        assert!(err.to_string().contains("FA-INV-01.realized-fx"), "{err}");

        // Planted negative 9 (fa-npi): audit_data_standard without round_trip_identity fails.
        let bad_ads = FORMATS_TOML.replacen(
            "name = \"aicpa_ads_gl_v2\"\nkind = \"audit_data_standard\"\ndirection = \"both\"\nmime = \"text/tab-separated-values\"\nextension = \"ads\"\noracle_tool = \"none\"\nround_trip_identity = true",
            "name = \"aicpa_ads_gl_v2\"\nkind = \"audit_data_standard\"\ndirection = \"both\"\nmime = \"text/tab-separated-values\"\nextension = \"ads\"\noracle_tool = \"none\"\nround_trip_identity = false",
            1,
        );
        let err = Formats::parse(&bad_ads).expect_err("ADS without round_trip_identity");
        assert!(err.to_string().contains("round_trip_identity"), "{err}");
    }
}
