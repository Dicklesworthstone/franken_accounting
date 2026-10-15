//! G0 constitutional registries (plan §18.2, §19 G0, bead `fa-szi`):
//! - `registries/constitution.toml` (`FA-CON-01..14`, `A1..A6`, claim classes)
//! - `registries/evidence.toml` (`FA-EVID-*`, `FA-CAL-*`, `FA-CFG-*`)
//! - `registries/checker_index.toml` (`CHK-*`)
//! - `registries/proof_lanes.toml` (`FA-PROOF-*`, `FA-MODEL-*`)
//! - `registries/period_states.toml` (`PeriodState`, `PeriodKind`, `PeriodTransition`)
//! - `registries/relationship_bases.toml` (`OWNS`, `CONTROLS`, `RELATED_TO` bases)
//! - `registries/claims_lint.toml` (marker resolution families + §18.2 37-registry inventory)

use std::collections::BTreeSet;

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
    }
}
