//! `registries/threat_model.toml` — threat enumeration (`FA-THR-01`..`FA-THR-08`),
//! trust boundaries (`TB-01`..`TB-05`), surviving public values (`SPV-01`..`SPV-06`),
//! and the INT-10 tamper matrix (`TV-01`..`TV-10`) (plan §8.5, §14.1, §14.2; bead `fa-oaz`).
//!
//! Laws enforced at load time:
//! - `schema_version` is 1.
//! - Trust boundaries have dense IDs `TB-01`..`TB-05`, unique names, a valid
//!   shipped posture (`fa`, `fa-cli`, `fad`, `fa-mcp`, `fa-verify`), and
//!   non-empty `trusted_actors`, `untrusted_inputs`, `enforcement_surface`, and `summary`.
//! - Threats are exactly `FA-THR-01`..`FA-THR-08` in order (`THREAT_IDS`); each
//!   references a declared trust boundary, at least one invariant clause in
//!   `invariants.toml`, at least one refusal code in `refusal_catalog.toml`,
//!   and at least one `Checker` test reference.
//! - A `live` threat may cite only `live` invariant clauses and has no
//!   `activating_beads`; a `dormant` threat names its `activating_beads` and
//!   cites at least one `dormant` invariant clause.
//! - Surviving public values (`SPV-01`..`SPV-06`) and tamper vectors (`TV-01`..`TV-10`)
//!   are dense, non-empty, and every `test_refs` entry parses as a valid
//!   `Checker` (`crate::target::path`) and resolves to a `#[test]` function in
//!   the workspace.

use std::collections::BTreeSet;

use crate::invariants::{Checker, Invariants};
use crate::refusal_catalog::RefusalCatalog;
use crate::toml::{Table, Value};
use crate::{ExitCodes, RegistryError, invalid, load, req_int, req_str};

const REGISTRY: &str = "threat_model.toml";
const THREAT_MODEL: &str = include_str!("../../../registries/threat_model.toml");

/// The eight plan §14.1 threat IDs, in canonical order.
pub const THREAT_IDS: [&str; 8] = [
    "FA-THR-01",
    "FA-THR-02",
    "FA-THR-03",
    "FA-THR-04",
    "FA-THR-05",
    "FA-THR-06",
    "FA-THR-07",
    "FA-THR-08",
];

/// The ten INT-10 tamper vector IDs, in canonical order.
pub const TAMPER_VECTOR_IDS: [&str; 10] = [
    "TV-01", "TV-02", "TV-03", "TV-04", "TV-05", "TV-06", "TV-07", "TV-08", "TV-09", "TV-10",
];

const POSTURES: [&str; 5] = ["fa", "fa-cli", "fad", "fa-mcp", "fa-verify"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustBoundary {
    pub id: String,
    pub name: String,
    pub posture: String,
    pub trusted_actors: Vec<String>,
    pub untrusted_inputs: Vec<String>,
    pub enforcement_surface: String,
    pub summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThreatStatus {
    Live,
    Dormant { activating_beads: Vec<String> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Threat {
    pub id: String,
    pub name: String,
    pub actor: String,
    pub boundary: String,
    pub asset: String,
    pub vector: String,
    pub mitigation_clauses: Vec<String>,
    pub mitigation_refusals: Vec<String>,
    pub status: ThreatStatus,
    pub residual_risk: String,
    pub test_refs: Vec<Checker>,
}

impl Threat {
    #[must_use]
    pub fn is_live(&self) -> bool {
        matches!(self.status, ThreatStatus::Live)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurvivingPublicValue {
    pub id: String,
    pub name: String,
    pub source_fields: Vec<String>,
    pub derivation: String,
    pub post_erasure_survivability: String,
    pub guessing_oracle_mitigation: String,
    pub test_refs: Vec<Checker>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TamperVector {
    pub id: String,
    pub name_or_artifact: String,
    pub tamper_action: String,
    pub detected_by: String,
    pub refusal_or_grade: String,
    pub test_refs: Vec<Checker>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreatModel {
    pub trust_boundaries: Vec<TrustBoundary>,
    pub threats: Vec<Threat>,
    pub surviving_public_values: Vec<SurvivingPublicValue>,
    pub tamper_vectors: Vec<TamperVector>,
}

fn bad(message: impl Into<String>) -> RegistryError {
    invalid(REGISTRY, message)
}

fn req_nonempty_str<'a>(t: &'a Table, key: &str, ctx: &str) -> Result<&'a str, RegistryError> {
    let val =
        req_str(REGISTRY, t, key).map_err(|_| bad(format!("{ctx}: missing string `{key}`")))?;
    if val.trim().is_empty() {
        return Err(bad(format!("{ctx}: `{key}` must not be empty")));
    }
    Ok(val)
}

fn req_nonempty_list(t: &Table, key: &str, ctx: &str) -> Result<Vec<String>, RegistryError> {
    let items = t
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| bad(format!("{ctx}: missing array `{key}`")))?;
    if items.is_empty() {
        return Err(bad(format!("{ctx}: `{key}` must not be empty")));
    }
    let mut out = Vec::with_capacity(items.len());
    let mut seen = BTreeSet::new();
    for item in items {
        let s = item
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| bad(format!("{ctx}: `{key}` must contain non-empty strings")))?;
        if !seen.insert(s) {
            return Err(bad(format!("{ctx}: `{key}` repeats `{s}`")));
        }
        out.push(s.to_string());
    }
    Ok(out)
}

fn parse_test_refs(t: &Table, ctx: &str) -> Result<Vec<Checker>, RegistryError> {
    let raw = req_nonempty_list(t, "test_refs", ctx)?;
    raw.iter()
        .map(|entry| Checker::parse(entry).map_err(|e| bad(format!("{ctx}: {e}"))))
        .collect()
}

fn is_snake(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && !s.starts_with(|c: char| c.is_ascii_digit() || c == '_')
}

fn is_bead(s: &str) -> bool {
    s.strip_prefix("fa-")
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric()))
}

impl ThreatModel {
    pub fn embedded() -> Result<Self, RegistryError> {
        let exits = ExitCodes::embedded()?;
        let refusals = RefusalCatalog::embedded()?;
        let invariants = Invariants::embedded()?;
        let _ = exits;
        Self::parse(THREAT_MODEL, &invariants, &refusals)
    }

    pub fn parse(
        text: &str,
        invariants: &Invariants,
        refusals: &RefusalCatalog,
    ) -> Result<Self, RegistryError> {
        let doc = load(REGISTRY, text)?;
        if req_int(REGISTRY, &doc.root, "schema_version")? != 1 {
            return Err(bad("schema_version must be 1"));
        }
        let empty = Vec::new();

        // 1. Trust boundaries.
        let mut trust_boundaries = Vec::new();
        let mut boundary_ids = BTreeSet::new();
        let mut boundary_names = BTreeSet::new();
        for (idx, t) in doc
            .arrays
            .get("trust_boundary")
            .unwrap_or(&empty)
            .iter()
            .enumerate()
        {
            let id = req_nonempty_str(t, "id", "trust_boundary")?.to_string();
            let expected_id = format!("TB-{:02}", idx + 1);
            if id != expected_id {
                return Err(bad(format!(
                    "trust_boundary ids must be dense TB-01..TB-NN in order, expected `{expected_id}`, found `{id}`"
                )));
            }
            let name = req_nonempty_str(t, "name", &id)?.to_string();
            if !is_snake(&name) {
                return Err(bad(format!("{id}: name `{name}` must be snake_case")));
            }
            if !boundary_names.insert(name.clone()) {
                return Err(bad(format!("{id}: duplicate trust_boundary name `{name}`")));
            }
            let posture = req_nonempty_str(t, "posture", &id)?.to_string();
            if !POSTURES.contains(&posture.as_str()) {
                return Err(bad(format!(
                    "{id}: posture `{posture}` is not one of {POSTURES:?}"
                )));
            }
            boundary_ids.insert(id.clone());
            trust_boundaries.push(TrustBoundary {
                trusted_actors: req_nonempty_list(t, "trusted_actors", &id)?,
                untrusted_inputs: req_nonempty_list(t, "untrusted_inputs", &id)?,
                enforcement_surface: req_nonempty_str(t, "enforcement_surface", &id)?.to_string(),
                summary: req_nonempty_str(t, "summary", &id)?.to_string(),
                id,
                name,
                posture,
            });
        }
        if trust_boundaries.len() < 5 {
            return Err(bad(
                "at least 5 trust boundaries (TB-01..TB-05) are required",
            ));
        }

        // 2. Threats (FA-THR-01 .. FA-THR-08).
        let mut threats = Vec::new();
        let mut threat_names = BTreeSet::new();
        for t in doc.arrays.get("threat").unwrap_or(&empty) {
            let id = req_nonempty_str(t, "id", "threat")?.to_string();
            let name = req_nonempty_str(t, "name", &id)?.to_string();
            if !is_snake(&name) {
                return Err(bad(format!("{id}: name `{name}` must be snake_case")));
            }
            if !threat_names.insert(name.clone()) {
                return Err(bad(format!("{id}: duplicate threat name `{name}`")));
            }
            let boundary = req_nonempty_str(t, "boundary", &id)?.to_string();
            if !boundary_ids.contains(&boundary) {
                return Err(bad(format!(
                    "{id}: references unknown trust_boundary `{boundary}`"
                )));
            }
            let mitigation_clauses = req_nonempty_list(t, "mitigation_clauses", &id)?;
            let mut any_dormant_clause = false;
            for clause_id in &mitigation_clauses {
                let Some(clause) = invariants.clause(clause_id) else {
                    return Err(bad(format!(
                        "{id}: mitigation_clauses references unknown invariant clause `{clause_id}`"
                    )));
                };
                if !clause.is_live() {
                    any_dormant_clause = true;
                }
            }
            let mitigation_refusals = req_nonempty_list(t, "mitigation_refusals", &id)?;
            for code in &mitigation_refusals {
                if refusals.by_code(code).is_none() {
                    return Err(bad(format!(
                        "{id}: mitigation_refusals references unknown refusal code `{code}`"
                    )));
                }
            }
            let status = match req_nonempty_str(t, "status", &id)? {
                "live" => {
                    if any_dormant_clause {
                        return Err(bad(format!(
                            "{id}: status is `live` but at least one mitigation clause is dormant"
                        )));
                    }
                    if t.contains_key("activating_beads") {
                        return Err(bad(format!(
                            "{id}: a `live` threat must not declare `activating_beads`"
                        )));
                    }
                    ThreatStatus::Live
                }
                "dormant" => {
                    if !any_dormant_clause {
                        return Err(bad(format!(
                            "{id}: status is `dormant` but all mitigation clauses are already live"
                        )));
                    }
                    let activating_beads = req_nonempty_list(t, "activating_beads", &id)?;
                    for bead in &activating_beads {
                        if !is_bead(bead) {
                            return Err(bad(format!(
                                "{id}: activating_beads entry `{bead}` is not a valid bead id"
                            )));
                        }
                    }
                    ThreatStatus::Dormant { activating_beads }
                }
                other => {
                    return Err(bad(format!(
                        "{id}: status `{other}` must be `live` or `dormant`"
                    )));
                }
            };
            threats.push(Threat {
                actor: req_nonempty_str(t, "actor", &id)?.to_string(),
                asset: req_nonempty_str(t, "asset", &id)?.to_string(),
                vector: req_nonempty_str(t, "vector", &id)?.to_string(),
                residual_risk: req_nonempty_str(t, "residual_risk", &id)?.to_string(),
                test_refs: parse_test_refs(t, &id)?,
                id,
                name,
                boundary,
                mitigation_clauses,
                mitigation_refusals,
                status,
            });
        }
        let found_threat_ids: Vec<&str> = threats.iter().map(|t| t.id.as_str()).collect();
        if found_threat_ids != THREAT_IDS {
            return Err(bad(format!(
                "threat ids must be exactly FA-THR-01..FA-THR-08 in order, found {found_threat_ids:?}"
            )));
        }

        // 3. Surviving public values (plan §8.5).
        let mut surviving_public_values = Vec::new();
        let mut spv_names = BTreeSet::new();
        for (idx, t) in doc
            .arrays
            .get("surviving_public_value")
            .unwrap_or(&empty)
            .iter()
            .enumerate()
        {
            let id = req_nonempty_str(t, "id", "surviving_public_value")?.to_string();
            let expected_id = format!("SPV-{:02}", idx + 1);
            if id != expected_id {
                return Err(bad(format!(
                    "surviving_public_value ids must be dense SPV-01..SPV-NN in order, expected `{expected_id}`, found `{id}`"
                )));
            }
            let name = req_nonempty_str(t, "name", &id)?.to_string();
            if !is_snake(&name) {
                return Err(bad(format!("{id}: name `{name}` must be snake_case")));
            }
            if !spv_names.insert(name.clone()) {
                return Err(bad(format!(
                    "{id}: duplicate surviving_public_value name `{name}`"
                )));
            }
            surviving_public_values.push(SurvivingPublicValue {
                source_fields: req_nonempty_list(t, "source_fields", &id)?,
                derivation: req_nonempty_str(t, "derivation", &id)?.to_string(),
                post_erasure_survivability: req_nonempty_str(t, "post_erasure_survivability", &id)?
                    .to_string(),
                guessing_oracle_mitigation: req_nonempty_str(t, "guessing_oracle_mitigation", &id)?
                    .to_string(),
                test_refs: parse_test_refs(t, &id)?,
                id,
                name,
            });
        }
        if surviving_public_values.len() < 6 {
            return Err(bad(
                "at least 6 surviving_public_value rows (SPV-01..SPV-06) are required",
            ));
        }

        // 4. Tamper vectors (INT-10).
        let mut tamper_vectors = Vec::new();
        let mut artifacts = BTreeSet::new();
        for t in doc.arrays.get("tamper_vector").unwrap_or(&empty) {
            let id = req_nonempty_str(t, "id", "tamper_vector")?.to_string();
            let artifact = req_nonempty_str(t, "artifact", &id)?.to_string();
            if !is_snake(&artifact) {
                return Err(bad(format!(
                    "{id}: artifact `{artifact}` must be snake_case"
                )));
            }
            if !artifacts.insert(artifact.clone()) {
                return Err(bad(format!(
                    "{id}: duplicate tamper_vector artifact `{artifact}`"
                )));
            }
            tamper_vectors.push(TamperVector {
                tamper_action: req_nonempty_str(t, "tamper_action", &id)?.to_string(),
                detected_by: req_nonempty_str(t, "detected_by", &id)?.to_string(),
                refusal_or_grade: req_nonempty_str(t, "refusal_or_grade", &id)?.to_string(),
                test_refs: parse_test_refs(t, &id)?,
                id,
                name_or_artifact: artifact,
            });
        }
        let found_tv_ids: Vec<&str> = tamper_vectors.iter().map(|tv| tv.id.as_str()).collect();
        if found_tv_ids != TAMPER_VECTOR_IDS {
            return Err(bad(format!(
                "tamper_vector ids must be exactly TV-01..TV-10 in order, found {found_tv_ids:?}"
            )));
        }

        Ok(Self {
            trust_boundaries,
            threats,
            surviving_public_values,
            tamper_vectors,
        })
    }

    /// Return `(row_id, test_ref)` for every `test_refs` entry across threats,
    /// surviving public values, and tamper vectors whose `#[test]` function is
    /// not defined in any candidate file returned by `read_file`.
    pub fn unresolved_test_refs<F>(&self, mut read_file: F) -> Vec<(String, String)>
    where
        F: FnMut(&str) -> Option<String>,
    {
        let mut unresolved = Vec::new();
        let all_refs = self
            .threats
            .iter()
            .flat_map(|t| t.test_refs.iter().map(move |c| (t.id.as_str(), c)))
            .chain(
                self.surviving_public_values
                    .iter()
                    .flat_map(|s| s.test_refs.iter().map(move |c| (s.id.as_str(), c))),
            )
            .chain(
                self.tamper_vectors
                    .iter()
                    .flat_map(|tv| tv.test_refs.iter().map(move |c| (tv.id.as_str(), c))),
            );
        for (owner_id, checker) in all_refs {
            if !checker.resolves_with(&mut read_file) {
                unresolved.push((owner_id.to_string(), checker.to_string()));
            }
        }
        unresolved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn embedded_threat_model_is_complete_and_every_test_ref_resolves() {
        let model = ThreatModel::embedded().expect("threat_model.toml validates");
        assert_eq!(model.trust_boundaries.len(), 5);
        assert_eq!(model.threats.len(), 8);
        assert_eq!(model.surviving_public_values.len(), 6);
        assert_eq!(model.tamper_vectors.len(), 10);

        let workspace = root();
        let unresolved =
            model.unresolved_test_refs(|rel| std::fs::read_to_string(workspace.join(rel)).ok());
        assert!(
            unresolved.is_empty(),
            "unresolved test_refs in threat_model.toml: {unresolved:#?}"
        );
    }

    #[test]
    fn planted_nonexistent_test_ref_and_broken_foreign_keys_are_refused() {
        let invariants = Invariants::embedded().unwrap();
        let refusals = RefusalCatalog::embedded().unwrap();
        let workspace = root();

        // 1. A nonexistent test function in test_refs fails unresolved_test_refs.
        let mutated_test = THREAT_MODEL.replacen(
            "fa-model::lib::entry::tests::tampered_bytes_are_refused",
            "fa-model::lib::entry::tests::nonexistent_threat_test_fn",
            1,
        );
        let parsed = ThreatModel::parse(&mutated_test, &invariants, &refusals)
            .expect("syntactically valid checker path");
        let unresolved =
            parsed.unresolved_test_refs(|rel| std::fs::read_to_string(workspace.join(rel)).ok());
        assert!(
            unresolved
                .iter()
                .any(|(id, c)| id == "FA-THR-01" && c.ends_with("nonexistent_threat_test_fn")),
            "expected FA-THR-01 unresolved test_ref, got {unresolved:?}"
        );

        // 2. Broken foreign key to invariant clause, refusal code, trust boundary, or status mismatch.
        let cases = [
            (
                "unknown invariant clause",
                "\"FA-INV-02.payload-immutable\"",
                "\"FA-INV-02.no-such-clause\"",
                "unknown invariant clause",
            ),
            (
                "unknown refusal code",
                "\"FA-REF-121\"",
                "\"FA-REF-999\"",
                "unknown refusal code",
            ),
            (
                "unknown trust boundary",
                "boundary = \"TB-01\"",
                "boundary = \"TB-99\"",
                "unknown trust_boundary",
            ),
            (
                "live threat citing dormant clause",
                "status = \"dormant\"\nactivating_beads = [\"fa-l3c\"]",
                "status = \"live\"",
                "at least one mitigation clause is dormant",
            ),
            (
                "missing threat id",
                "id = \"FA-THR-08\"",
                "id = \"FA-THR-99\"",
                "FA-THR-01..FA-THR-08",
            ),
        ];
        for (label, from, to, expected) in cases {
            let text = THREAT_MODEL.replacen(from, to, 1);
            assert_ne!(text, THREAT_MODEL, "{label}: replacement did not match");
            let err = ThreatModel::parse(&text, &invariants, &refusals)
                .expect_err(label)
                .to_string();
            assert!(
                err.contains(expected),
                "{label}: expected `{expected}` in `{err}`"
            );
        }
    }
}
