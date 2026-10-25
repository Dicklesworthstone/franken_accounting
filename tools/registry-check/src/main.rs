//! `registry-check` — validates all `registries/*.toml` schemas, cross-registry
//! foreign keys, `FA-REF-*` refusal catalog immutability, cross-document
//! `claims_lint`, and the G0 completeness report (plan §18.2, §19 G0, beads
//! `fa-ad8d`, `fa-szi`).

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode as ProcessExitCode;

use fa_registry::account_roles::AccountRoles;
use fa_registry::document_stores::DocumentStores;
use fa_registry::evidence_artifacts::{
    ArtifactVerificationLog, EvidenceArtifacts, verify_claim_artifact_cross_refs,
    verify_prose_claims_lint,
};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_registry::foundations::Ledger;
use fa_registry::g0::{
    CheckerIndex, ClaimsLintConfig, Constitution, ConversionLaws, EvidenceRegistry, Formats,
    FxLaws, LotLaws, OperationCosts, PeriodStatesRegistry, ProofLanes, RelationshipBases,
    SloRegistry, SupersessionKinds, TracingLaws,
};
use fa_registry::intake_sources::IntakeSources;
use fa_registry::invariants::Invariants;
use fa_registry::lantern_calibration::LanternCalibration;
use fa_registry::mutants::MutantLedger;
use fa_registry::procedures::Procedures;
use fa_registry::reason_codes::ReasonCodes;
use fa_registry::redaction_contracts::RedactionContracts;
use fa_registry::refusal_catalog::RefusalCatalog;
use fa_registry::scoreboard::Scoreboard;
use fa_registry::sod_policy::SodPolicy;
use fa_registry::threat_model::ThreatModel;
use fa_registry::toml::{self, Table, Value};
use fa_registry::topology::Topology;
use fa_registry::unwired_modules::UnwiredModules;
use fa_registry::{
    Admissibility, CapabilityCaveats, ControlKinds, EntryClasses, ExitCodes, IntentDependencies,
    Symbols, parse_units, rounding_laws_embedded,
};

/// Canonical durable `(code, name, exit_name)` tuples that may never be renumbered
/// or repurposed for a different meaning (`refusal_catalog.toml` additive law).
const IMMUTABLE_REFUSALS: &[(&str, &str, &str)] = &[
    ("FA-REF-001", "UNBALANCED", "refusal"),
    ("FA-REF-002", "NOT_A_LEAF", "refusal"),
    ("FA-REF-003", "UNIT_POLICY", "refusal"),
    ("FA-REF-004", "UNKNOWN_ACCOUNT", "refusal"),
    ("FA-REF-005", "DIMENSION_MISSING", "refusal"),
    ("FA-REF-007", "CONFIRMATION_REQUIRED", "safety"),
    ("FA-REF-008", "SOD", "safety"),
    ("FA-REF-010", "PERIOD_LAW", "safety"),
    ("FA-REF-011", "CAPABILITY", "safety"),
    ("FA-REF-012", "APPROVALS", "safety"),
    ("FA-REF-013", "AGENT_TRUNK", "safety"),
    ("FA-REF-020", "PERIOD_RESOLVE", "refusal"),
    ("FA-REF-030", "CONFLICT", "conflict"),
    ("FA-REF-032", "IDEMPOTENCY_CONFLICT", "conflict"),
    ("FA-REF-040", "TRANSITION", "safety"),
    ("FA-REF-050", "REVERSAL_TARGET", "refusal"),
    ("FA-REF-060", "RESOLUTION_TARGET", "refusal"),
    ("FA-REF-070", "SETTLE_TARGET", "refusal"),
    ("FA-REF-080", "EVIDENCE_MINIMUM", "refusal"),
    ("FA-REF-090", "AVAILABILITY_LOWER", "refusal"),
    ("FA-REF-129", "BUNDLE_LIMIT", "refusal"),
];

/// Closed capability-op vocabulary (`crates/fa-policy/src/op.rs`).
const REGISTERED_OPS: &[&str] = &[
    "read",
    "post",
    "post_softclosed",
    "post_closed",
    "approve",
    "reconcile",
    "close",
    "reopen",
    "restate",
    "migrate",
    "schema_change",
    "rule_change",
    "issue_capability",
    "witness",
    "verify",
    "produce",
    "hold",
    "erase",
    "privileged",
    "receivership",
    "partial_view",
];

const EXPECTED_REGISTRIES: &[&str] = &[
    "account_roles.toml",
    "account_types.toml",
    "admissibility.toml",
    "allocation_laws.toml",
    "capability_caveats.toml",
    "checker_index.toml",
    "claims_lint.toml",
    "constitution.toml",
    "conversion_laws.toml",
    "document_stores.toml",
    "entry_classes.toml",
    "evidence.toml",
    "evidence_artifacts.toml",
    "evidence_policy.toml",
    "exit_codes.toml",
    "formats.toml",
    "foundation_dependencies.toml",
    "fx_laws.toml",
    "intake_sources.toml",
    "intents.toml",
    "invariants.toml",
    "lantern_calibration.toml",
    "limits.toml",
    "lot_laws.toml",
    "mutants.toml",
    "operation_costs.toml",
    "period_states.toml",
    "procedures.toml",
    "proof_lanes.toml",
    "reason_codes.toml",
    "redaction_contracts.toml",
    "refusal_catalog.toml",
    "relationship_bases.toml",
    "rounding_laws.toml",
    "scoreboard.toml",
    "slo.toml",
    "sod_policy.toml",
    "supersession_kinds.toml",
    "symbols.toml",
    "threat_model.toml",
    "tracing_laws.toml",
    "units.toml",
    "unwired_modules.toml",
    "verbs.toml",
    "workspace_topology.toml",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckSummary {
    pub files_checked: usize,
    pub invariants_live: usize,
    pub invariants_total: usize,
    pub refusals_checked: usize,
    pub verbs_checked: usize,
    pub mcp_tools_checked: usize,
    /// Tools on the default MCP surface (plan §15.4: at most 40); tools of
    /// on-demand clusters are checked but not exposed by default.
    pub mcp_default_tools: usize,
    pub markers_checked: usize,
    pub evidence_logs: Vec<ArtifactVerificationLog>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum G0Status {
    Present,
    OwnedBy(String),
    Missing(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct G0Row {
    pub path: String,
    pub kind: String,
    pub owner_bead: String,
    pub status: G0Status,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct G0Report {
    pub total: usize,
    pub present: usize,
    pub owned: usize,
    pub missing: usize,
    pub rows: Vec<G0Row>,
}

fn req_str<'a>(file: &str, table: &'a Table, key: &str) -> Result<&'a str, String> {
    table
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| format!("{file}: missing or empty string `{key}`"))
}

fn req_int(file: &str, table: &Table, key: &str) -> Result<i128, String> {
    table
        .get(key)
        .and_then(Value::as_int)
        .ok_or_else(|| format!("{file}: missing integer `{key}`"))
}

fn req_str_array(file: &str, table: &Table, key: &str) -> Result<Vec<String>, String> {
    let arr = table
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{file}: missing array `{key}`"))?;
    arr.iter()
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{file}: `{key}` contains non-string"))
        })
        .collect()
}

/// One nested object/bundle/statement schema. A format's `major` starts at
/// 1; a breaking-major transition (plan Appendix A) is admissible only with
/// its explicit transition: `versions` names every supported version in
/// order, `["1:<name>", …, "<major>:<name>"]`. A bare major bump still fails.
fn check_nested_schema(file: &str, text: &str) -> Result<(), String> {
    let doc = toml::parse(text).map_err(|e| format!("{file}: {e}"))?;
    if req_int(file, &doc.root, "schema_version")? != 1 {
        return Err(format!("{file}: schema_version must be 1"));
    }
    let Some(major) = doc.root.get("major").and_then(Value::as_int) else {
        return Ok(());
    };
    if major < 1 {
        return Err(format!("{file}: major version must be at least 1"));
    }
    if major == 1 {
        return Ok(());
    }
    let versions = doc
        .root
        .get("versions")
        .and_then(Value::as_array)
        .unwrap_or(&[]);
    let declared = usize::try_from(major).is_ok_and(|count| versions.len() == count)
        && versions.iter().enumerate().all(|(index, version)| {
            version
                .as_str()
                .and_then(|text| text.strip_prefix(&format!("{}:", index + 1)))
                .is_some_and(|name| !name.trim().is_empty())
        });
    if !declared {
        return Err(format!(
            "{file}: major version {major} requires its declared transition `versions = [\"1:<name>\", …, \"{major}:<name>\"]`"
        ));
    }
    Ok(())
}

pub fn check_account_types(text: &str) -> Result<usize, String> {
    const F: &str = "account_types.toml";
    let doc = toml::parse(text).map_err(|e| format!("{F}: {e}"))?;
    if req_int(F, &doc.root, "schema_version")? != 1 {
        return Err(format!("{F}: schema_version must be 1"));
    }
    let rows = doc
        .arrays
        .get("account_type")
        .ok_or_else(|| format!("{F}: missing [[account_type]]"))?;
    if rows.is_empty() {
        return Err(format!("{F}: [[account_type]] is empty"));
    }
    let mut tags = BTreeSet::new();
    let mut names = BTreeSet::new();
    for row in rows {
        let tag = req_int(F, row, "tag")?;
        let name = req_str(F, row, "name")?;
        let kind = req_str(F, row, "kind")?;
        let normal = req_int(F, row, "normal_balance")?;
        if !matches!(kind, "stock" | "flow" | "memo") {
            return Err(format!("{F}: `{name}` has invalid kind `{kind}`"));
        }
        if !matches!(normal, 0 | 1) {
            return Err(format!(
                "{F}: `{name}` has invalid normal_balance `{normal}`"
            ));
        }
        if !tags.insert(tag) {
            return Err(format!("{F}: duplicate tag `{tag}`"));
        }
        if !names.insert(name.to_string()) {
            return Err(format!("{F}: duplicate account_type `{name}`"));
        }
    }
    Ok(rows.len())
}

pub fn check_allocation_laws(text: &str) -> Result<usize, String> {
    const F: &str = "allocation_laws.toml";
    let doc = toml::parse(text).map_err(|e| format!("{F}: {e}"))?;
    if req_int(F, &doc.root, "schema_version")? != 1 {
        return Err(format!("{F}: schema_version must be 1"));
    }
    if req_int(F, &doc.root, "max_targets")? <= 0 {
        return Err(format!("{F}: max_targets must be positive"));
    }
    let rows = doc
        .arrays
        .get("law")
        .ok_or_else(|| format!("{F}: missing [[law]]"))?;
    if rows.is_empty() {
        return Err(format!("{F}: [[law]] is empty"));
    }
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for row in rows {
        let id = req_int(F, row, "id")?;
        let _version = req_int(F, row, "version")?;
        let name = req_str(F, row, "name")?;
        let _basis = req_str(F, row, "basis")?;
        let _ordering = req_str(F, row, "ordering")?;
        let _rounding = req_str(F, row, "rounding")?;
        let _signed = req_str(F, row, "signed")?;
        if !ids.insert(id) {
            return Err(format!("{F}: duplicate law id `{id}`"));
        }
        if !names.insert(name.to_string()) {
            return Err(format!("{F}: duplicate law name `{name}`"));
        }
    }
    Ok(rows.len())
}

pub fn check_limits(text: &str) -> Result<usize, String> {
    const F: &str = "limits.toml";
    let doc = toml::parse(text).map_err(|e| format!("{F}: {e}"))?;
    if req_int(F, &doc.root, "schema_version")? != 1 {
        return Err(format!("{F}: schema_version must be 1"));
    }
    let rows = doc
        .arrays
        .get("limit")
        .ok_or_else(|| format!("{F}: missing [[limit]]"))?;
    if rows.is_empty() {
        return Err(format!("{F}: [[limit]] is empty"));
    }
    let mut names = BTreeSet::new();
    for row in rows {
        let name = req_str(F, row, "name")?;
        let value = req_int(F, row, "value")?;
        if value <= 0 {
            return Err(format!("{F}: limit `{name}` must have positive value"));
        }
        if !names.insert(name.to_string()) {
            return Err(format!("{F}: duplicate limit `{name}`"));
        }
    }
    Ok(rows.len())
}

pub fn check_refusal_immutability(text: &str, exits: &ExitCodes) -> Result<usize, String> {
    let catalog = RefusalCatalog::from_text(text, exits).map_err(|e| e.to_string())?;
    let by_code: BTreeMap<&str, (&str, &str)> = catalog
        .rows
        .iter()
        .map(|r| (r.code.as_str(), (r.name.as_str(), r.exit_name.as_str())))
        .collect();
    for (code, expected_name, expected_exit) in IMMUTABLE_REFUSALS {
        let Some((actual_name, actual_exit)) = by_code.get(code) else {
            return Err(format!(
                "refusal_catalog.toml: durable refusal `{code}` (`{expected_name}`) was removed"
            ));
        };
        if actual_name != expected_name || actual_exit != expected_exit {
            return Err(format!(
                "refusal_catalog.toml: durable refusal `{code}` mutated from ({expected_name}, {expected_exit}) to ({actual_name}, {actual_exit})"
            ));
        }
    }
    Ok(catalog.rows.len())
}

/// `(verbs, every mcp.tool row, the default-surface tools)`.
pub fn check_verbs(text: &str, exits: &ExitCodes) -> Result<(usize, usize, usize), String> {
    const F: &str = "verbs.toml";
    let doc = toml::parse(text).map_err(|e| format!("{F}: {e}"))?;
    if req_int(F, &doc.root, "schema_version")? != 1 {
        return Err(format!("{F}: schema_version must be 1"));
    }
    let valid_exits: BTreeSet<i128> = exits.rows.iter().map(|r| i128::from(r.code)).collect();
    let valid_ops: BTreeSet<&str> = REGISTERED_OPS.iter().copied().collect();
    let events = doc
        .arrays
        .get("event")
        .ok_or_else(|| format!("{F}: missing [[event]]"))?;
    let mut event_names = BTreeSet::new();
    for ev in events {
        let name = req_str(F, ev, "name")?;
        if !event_names.insert(name.to_string()) {
            return Err(format!("{F}: duplicate event `{name}`"));
        }
    }
    let verbs = doc
        .arrays
        .get("verb")
        .ok_or_else(|| format!("{F}: missing [[verb]]"))?;
    let mut verb_subs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for v in verbs {
        let name = req_str(F, v, "name")?;
        let subs = req_str_array(F, v, "subcommands")?;
        let v_events = req_str_array(F, v, "events")?;
        for ev in &v_events {
            if !event_names.contains(ev) {
                return Err(format!(
                    "{F}: verb `{name}` references undeclared event `{ev}`"
                ));
            }
        }
        if v.contains_key("ops") {
            for op in req_str_array(F, v, "ops")? {
                if !valid_ops.contains(op.as_str()) {
                    return Err(format!(
                        "{F}: verb `{name}` references unregistered capability op `{op}`"
                    ));
                }
            }
        }
        let exits_arr = v
            .get("exits")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{F}: verb `{name}` missing `exits`"))?;
        for code_val in exits_arr {
            let code = code_val
                .as_int()
                .ok_or_else(|| format!("{F}: verb `{name}` has non-int exit code"))?;
            if !valid_exits.contains(&code) {
                return Err(format!(
                    "{F}: verb `{name}` references unregistered exit code `{code}` (not in exit_codes.toml)"
                ));
            }
        }
        if verb_subs.insert(name.to_string(), subs).is_some() {
            return Err(format!("{F}: duplicate verb `{name}`"));
        }
    }
    if let Some(dangerous_rows) = doc.arrays.get("dangerous") {
        for d in dangerous_rows {
            let verb = req_str(F, d, "verb")?;
            let Some(declared_subs) = verb_subs.get(verb) else {
                return Err(format!(
                    "{F}: [[dangerous]] references unknown verb `{verb}`"
                ));
            };
            if let Some(sub) = d.get("subcommand").and_then(Value::as_str)
                && !declared_subs.iter().any(|s| s == sub)
            {
                return Err(format!(
                    "{F}: [[dangerous]] references unknown subcommand `{verb} {sub}`"
                ));
            }
            let cond = req_str(F, d, "condition")?;
            let _safe = req_str(F, d, "safe")?;
            if let Some(op) = cond.strip_prefix("grant:") {
                if !valid_ops.contains(op) {
                    return Err(format!(
                        "{F}: [[dangerous]] on `{verb}` cites unknown capability op `{op}`"
                    ));
                }
            } else if !matches!(cond, "always" | "disposition:voids" | "existing-cells") {
                return Err(format!(
                    "{F}: [[dangerous]] on `{verb}` has unknown condition `{cond}`"
                ));
            }
        }
    }
    let tools = doc
        .arrays
        .get("mcp.tool")
        .ok_or_else(|| format!("{F}: missing [[mcp.tool]]"))?;
    // Plan §15.4: at most 40 tools are exposed by default; an on-demand
    // cluster (`on_demand = true`, `fa-mcp --cluster <name>`) is outside
    // the default surface.
    let on_demand: BTreeSet<&str> = doc
        .arrays
        .get("mcp.cluster")
        .map(|clusters| {
            clusters
                .iter()
                .filter(|c| c.get("on_demand").and_then(Value::as_bool) == Some(true))
                .filter_map(|c| c.get("name").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    let default_tools = tools
        .iter()
        .filter(|t| {
            t.get("cluster")
                .and_then(Value::as_str)
                .is_none_or(|c| !on_demand.contains(c))
        })
        .count();
    if default_tools > 40 {
        return Err(format!(
            "{F}: mcp.tool count {default_tools} on the default surface exceeds plan §15.4 limit of 40"
        ));
    }
    for t in tools {
        let tool_name = req_str(F, t, "name")?;
        let verb = req_str(F, t, "verb")?;
        let Some(declared_subs) = verb_subs.get(verb) else {
            return Err(format!(
                "{F}: mcp.tool `{tool_name}` references unknown verb `{verb}`"
            ));
        };
        let tool_subs = req_str_array(F, t, "subcommands")?;
        for sc in &tool_subs {
            if !declared_subs.contains(sc) {
                return Err(format!(
                    "{F}: mcp.tool `{tool_name}` references unknown subcommand `{verb} {sc}`"
                ));
            }
        }
    }
    Ok((verbs.len(), tools.len(), default_tools))
}

/// Extract all `FA-<FAMILY>-<DIGITS>` markers from `text` matching one of the
/// registered `prefixes` (e.g. `"FA-INV-"`, `"FA-REF-"`).
pub fn extract_markers(text: &str, prefixes: &[String]) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 7 <= bytes.len() {
        if &bytes[i..i + 3] == b"FA-"
            && (i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_'))
        {
            let rest = &text[i..];
            for prefix in prefixes {
                if let Some(after_prefix) = rest.strip_prefix(prefix.as_str()) {
                    let digit_len = after_prefix
                        .bytes()
                        .take_while(|b| b.is_ascii_digit())
                        .count();
                    if digit_len >= 2 {
                        let next_byte = after_prefix.as_bytes().get(digit_len).copied();
                        // Exclude ellipsis ranges like `FA-CON-01…14` or `FA-INV-01..16` only on the right side,
                        // while still capturing the leading `FA-CON-01` / `FA-INV-01` marker itself!
                        if !next_byte.is_some_and(|b| b.is_ascii_alphabetic() || b == b'_') {
                            let marker = &rest[..prefix.len() + digit_len];
                            found.insert(marker.to_string());
                        }
                    }
                }
            }
        }
        i += 1;
    }
    found
}

pub fn check_claims_lint(
    config: &ClaimsLintConfig,
    known_markers: &BTreeSet<String>,
    docs: &[(&str, &str)],
) -> Result<usize, String> {
    let prefixes: Vec<String> = config
        .marker_families
        .iter()
        .map(|f| f.prefix.clone())
        .collect();
    let mut checked = 0usize;
    for (doc_name, content) in docs {
        let markers = extract_markers(content, &prefixes);
        for marker in markers {
            if !known_markers.contains(&marker) {
                return Err(format!(
                    "claims_lint: `{doc_name}` cites `{marker}`, which has no row in its owning registry"
                ));
            }
            checked += 1;
        }
    }
    Ok(checked)
}

fn load_open_beads(root: &Path) -> Option<BTreeSet<String>> {
    let path = root.join(".beads/issues.jsonl");
    let text = fs::read_to_string(path).ok()?;
    let mut open_ids = BTreeSet::new();
    for line in text.lines() {
        if (line.contains("\"status\":\"open\"") || line.contains("\"status\":\"in_progress\""))
            && let Some(pos) = line.find("\"id\":\"")
        {
            let rest = &line[pos + 6..];
            if let Some(end) = rest.find('"') {
                open_ids.insert(rest[..end].to_string());
            }
        }
    }
    Some(open_ids)
}

pub fn check_g0_report(root: &Path) -> Result<G0Report, String> {
    let reg_dir = root.join("registries");
    let claims_text = fs::read_to_string(reg_dir.join("claims_lint.toml"))
        .map_err(|e| format!("claims_lint.toml: {e}"))?;
    let config = ClaimsLintConfig::parse(&claims_text).map_err(|e| e.to_string())?;
    let open_beads = load_open_beads(root);

    let mut present = 0usize;
    let mut owned = 0usize;
    let mut missing = 0usize;
    let mut rows = Vec::with_capacity(config.g0_registries.len());

    for entry in &config.g0_registries {
        let target = reg_dir.join(&entry.path);
        let exists = match entry.kind.as_str() {
            "file" => target.is_file(),
            "dir" => {
                target.is_dir()
                    && fs::read_dir(&target)
                        .ok()
                        .into_iter()
                        .flatten()
                        .flatten()
                        .any(|f| {
                            f.path()
                                .extension()
                                .and_then(|s| s.to_str())
                                .is_some_and(|ext| matches!(ext, "toml" | "json" | "jsonl"))
                        })
            }
            _ => false,
        };
        let status = if exists {
            present += 1;
            G0Status::Present
        } else if entry.owner_bead == "fa-szi" {
            missing += 1;
            G0Status::Missing("unowned G0 constitutional registry missing on disk".to_string())
        } else if let Some(ref open) = open_beads
            && !open.contains(&entry.owner_bead)
        {
            missing += 1;
            G0Status::Missing(format!(
                "owner bead `{}` is not open in .beads/issues.jsonl",
                entry.owner_bead
            ))
        } else {
            owned += 1;
            G0Status::OwnedBy(entry.owner_bead.clone())
        };
        rows.push(G0Row {
            path: entry.path.clone(),
            kind: entry.kind.clone(),
            owner_bead: entry.owner_bead.clone(),
            status,
        });
    }

    let report = G0Report {
        total: rows.len(),
        present,
        owned,
        missing,
        rows,
    };
    if report.missing > 0 {
        let first_missing = report
            .rows
            .iter()
            .find_map(|r| match &r.status {
                G0Status::Missing(why) => Some(format!("`{}` ({why})", r.path)),
                _ => None,
            })
            .unwrap_or_default();
        return Err(format!(
            "g0 completeness failed: {} missing registry ({first_missing})",
            report.missing
        ));
    }
    Ok(report)
}

pub fn check_workspace_registries(root: &Path) -> Result<CheckSummary, String> {
    let reg_dir = root.join("registries");
    for expected in EXPECTED_REGISTRIES {
        let path = reg_dir.join(expected);
        if !path.is_file() {
            return Err(format!(
                "missing required registry file: {}",
                path.display()
            ));
        }
    }

    // 1. Embedded fa-registry strongly-typed checks.
    let exits = ExitCodes::embedded().map_err(|e| e.to_string())?;
    let classes = EntryClasses::embedded().map_err(|e| e.to_string())?;
    let _intents = IntentDependencies::embedded().map_err(|e| e.to_string())?;
    let _control_kinds = ControlKinds::embedded(&classes).map_err(|e| e.to_string())?;
    let _rounding = rounding_laws_embedded().map_err(|e| e.to_string())?;
    let _symbols = Symbols::embedded().map_err(|e| e.to_string())?;
    let _stores = DocumentStores::embedded().map_err(|e| e.to_string())?;
    let _evidence = EvidencePolicy::embedded().map_err(|e| e.to_string())?;
    let _intake = IntakeSources::embedded().map_err(|e| e.to_string())?;
    let _procedures = Procedures::embedded().map_err(|e| e.to_string())?;
    let _reasons = ReasonCodes::embedded().map_err(|e| e.to_string())?;
    let _roles = AccountRoles::embedded().map_err(|e| e.to_string())?;
    let _redaction = RedactionContracts::embedded().map_err(|e| e.to_string())?;
    let _capability_caveats = CapabilityCaveats::embedded().map_err(|e| e.to_string())?;

    // 2. Disk-backed checks (supports validating mutated registries in --root).
    let read = |name: &str| -> Result<String, String> {
        let p = reg_dir.join(name);
        fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))
    };
    let cap_caveats =
        CapabilityCaveats::parse(&read("capability_caveats.toml")?).map_err(|e| e.to_string())?;
    let cap_ops: Vec<&str> = cap_caveats.ops.iter().map(|o| o.name.as_str()).collect();
    if cap_ops != REGISTERED_OPS {
        return Err(format!(
            "capability_caveats.toml: [[op]] list {cap_ops:?} disagrees with REGISTERED_OPS {REGISTERED_OPS:?}"
        ));
    }
    let classes = EntryClasses::parse(&read("entry_classes.toml")?).map_err(|e| e.to_string())?;
    let _intents =
        IntentDependencies::parse(&classes, &read("intents.toml")?).map_err(|e| e.to_string())?;
    let matrix =
        Admissibility::parse(&classes, &read("admissibility.toml")?).map_err(|e| e.to_string())?;
    let _sod = SodPolicy::parse(&read("sod_policy.toml")?, &classes, &matrix)
        .map_err(|e| e.to_string())?;
    let _units = parse_units(&read("units.toml")?).map_err(|e| e.to_string())?;
    let foundations =
        Ledger::parse(&read("foundation_dependencies.toml")?).map_err(|e| e.to_string())?;
    if root.join("crates").is_dir() {
        fa_registry::foundations::check_api_consumption(&foundations, root)
            .map_err(|e| e.to_string())?;
        fa_registry::foundations::check_conformance_tests(&foundations, root)
            .map_err(|e| e.to_string())?;
    }
    let invariants = Invariants::parse(&read("invariants.toml")?).map_err(|e| e.to_string())?;
    let _topology =
        Topology::parse(&read("workspace_topology.toml")?).map_err(|e| e.to_string())?;

    let constitution =
        Constitution::parse(&read("constitution.toml")?).map_err(|e| e.to_string())?;
    let evidence_reg =
        EvidenceRegistry::parse(&read("evidence.toml")?).map_err(|e| e.to_string())?;
    let _checker_index =
        CheckerIndex::parse(&read("checker_index.toml")?).map_err(|e| e.to_string())?;
    let proof_lanes =
        ProofLanes::parse(&read("proof_lanes.toml")?, &invariants).map_err(|e| e.to_string())?;
    let period_states =
        PeriodStatesRegistry::parse(&read("period_states.toml")?).map_err(|e| e.to_string())?;
    for tr in &period_states.transitions {
        if !REGISTERED_OPS.contains(&tr.capability.as_str()) {
            return Err(format!(
                "period_states.toml: transition `{}` cites unknown capability `{}`",
                tr.action, tr.capability
            ));
        }
    }
    let _rel_bases =
        RelationshipBases::parse(&read("relationship_bases.toml")?).map_err(|e| e.to_string())?;
    let op_costs =
        OperationCosts::parse(&read("operation_costs.toml")?).map_err(|e| e.to_string())?;
    let slo_reg = SloRegistry::parse(&read("slo.toml")?, &op_costs).map_err(|e| e.to_string())?;
    let _lot_laws = LotLaws::parse(&read("lot_laws.toml")?).map_err(|e| e.to_string())?;
    let _conversion_laws =
        ConversionLaws::parse(&read("conversion_laws.toml")?).map_err(|e| e.to_string())?;
    let _supersession_kinds = SupersessionKinds::parse(&read("supersession_kinds.toml")?, &classes)
        .map_err(|e| e.to_string())?;
    let procedures = Procedures::from_text(&read("procedures.toml")?).map_err(|e| e.to_string())?;
    let calibration =
        LanternCalibration::from_text(&read("lantern_calibration.toml")?, &procedures)
            .map_err(|e| e.to_string())?;
    let _tracing_laws =
        TracingLaws::parse(&read("tracing_laws.toml")?, &procedures).map_err(|e| e.to_string())?;
    let _fx_laws = FxLaws::parse(&read("fx_laws.toml")?, &classes).map_err(|e| e.to_string())?;
    let formats = Formats::parse(&read("formats.toml")?).map_err(|e| e.to_string())?;
    let evidence_artifacts = EvidenceArtifacts::from_text(&read("evidence_artifacts.toml")?)
        .map_err(|e| e.to_string())?;
    let evidence_logs = if root.join("evidence").is_dir() {
        evidence_artifacts
            .verify_store(root)
            .map_err(|e| e.to_string())?
    } else {
        Vec::new()
    };
    verify_claim_artifact_cross_refs(
        &evidence_artifacts,
        &slo_reg,
        &invariants,
        &proof_lanes,
        &formats,
        &evidence_reg,
        &procedures,
        &calibration,
    )
    .map_err(|e| e.to_string())?;
    let _unwired =
        UnwiredModules::from_text(&read("unwired_modules.toml")?).map_err(|e| e.to_string())?;
    let claims_config =
        ClaimsLintConfig::parse(&read("claims_lint.toml")?).map_err(|e| e.to_string())?;

    check_account_types(&read("account_types.toml")?)?;
    check_allocation_laws(&read("allocation_laws.toml")?)?;
    check_limits(&read("limits.toml")?)?;
    let refusals_text = read("refusal_catalog.toml")?;
    let refusals_checked = check_refusal_immutability(&refusals_text, &exits)?;
    let refusals = RefusalCatalog::from_text(&refusals_text, &exits).map_err(|e| e.to_string())?;
    let threat_model = ThreatModel::parse(&read("threat_model.toml")?, &invariants, &refusals)
        .map_err(|e| e.to_string())?;
    let unresolved =
        threat_model.unresolved_test_refs(|rel| fs::read_to_string(root.join(rel)).ok());
    if let Some((owner_id, test_ref)) = unresolved.first() {
        return Err(format!(
            "threat_model.toml: {owner_id} references nonexistent test `{test_ref}`"
        ));
    }
    let _scoreboard = Scoreboard::parse(&read("scoreboard.toml")?, &exits, &refusals)
        .map_err(|e| e.to_string())?;
    let mutants = MutantLedger::parse(&read("mutants.toml")?, &invariants, &refusals)
        .map_err(|e| e.to_string())?;
    if root.join("crates").is_dir() {
        mutants.verify_against_workspace(|rel| fs::read_to_string(root.join(rel)).ok())?;
    }
    let (verbs_checked, mcp_tools_checked, mcp_default_tools) =
        check_verbs(&read("verbs.toml")?, &exits)?;

    // 3. Cross-document claims_lint check.
    let mut known_markers = BTreeSet::new();
    for c in &constitution.constraints {
        known_markers.insert(c.id.clone());
    }
    for inv in &invariants.invariants {
        known_markers.insert(inv.id.clone());
    }
    for g in &evidence_reg.gates {
        known_markers.insert(g.id.clone());
    }
    for r in &refusals.rows {
        known_markers.insert(r.code.clone());
    }
    for res in &refusals.reserved {
        known_markers.insert(res.code.clone());
    }
    for th in &threat_model.threats {
        known_markers.insert(th.id.clone());
    }
    for b in &threat_model.trust_boundaries {
        known_markers.insert(b.id.clone());
    }
    for tv in &threat_model.tamper_vectors {
        known_markers.insert(tv.id.clone());
    }
    for lane in &proof_lanes.lanes {
        known_markers.insert(lane.id.clone());
    }
    for s in &slo_reg.rows {
        known_markers.insert(s.id.clone());
    }
    for art in &evidence_artifacts.artifacts {
        known_markers.insert(art.id.clone());
    }

    let mut loaded_docs = Vec::new();
    for rel_doc in &claims_config.scanned_docs {
        let doc_path = root.join(rel_doc);
        if doc_path.is_file() {
            let text = fs::read_to_string(&doc_path)
                .map_err(|e| format!("{}: {e}", doc_path.display()))?;
            loaded_docs.push((rel_doc.clone(), text));
        }
    }
    let doc_refs: Vec<(&str, &str)> = loaded_docs
        .iter()
        .map(|(n, c)| (n.as_str(), c.as_str()))
        .collect();
    let markers_checked = check_claims_lint(&claims_config, &known_markers, &doc_refs)?;
    verify_prose_claims_lint(root, &evidence_artifacts, &invariants).map_err(|e| e.to_string())?;

    // 4. Parse nested TOML schemas under object_schemas/, bundle_schema/, and statements/.
    let mut extra_files = 0usize;
    for sub in ["object_schemas", "bundle_schema", "statements"] {
        let sub_dir = reg_dir.join(sub);
        if sub_dir.is_dir() {
            let entries =
                fs::read_dir(&sub_dir).map_err(|e| format!("{}: {e}", sub_dir.display()))?;
            for entry in entries {
                let entry = entry.map_err(|e| e.to_string())?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                    let content = fs::read_to_string(&path)
                        .map_err(|e| format!("{}: {e}", path.display()))?;
                    check_nested_schema(&path.display().to_string(), &content)?;
                    extra_files += 1;
                }
            }
        }
    }

    // Verify bundle and certificate schemas are explicitly marked externally_verifiable = true.
    for req_ext in ["bundle_schema/fab.toml", "object_schemas/certificate.toml"] {
        let p = reg_dir.join(req_ext);
        let text = fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        let doc = toml::parse(&text).map_err(|e| format!("{}: {e}", p.display()))?;
        if doc
            .root
            .get("externally_verifiable")
            .and_then(Value::as_bool)
            != Some(true)
        {
            return Err(format!(
                "{req_ext}: must declare `externally_verifiable = true`"
            ));
        }
    }

    let _g0 = check_g0_report(root)?;
    let _derived_checked =
        check_operation_costs_derived_objects(root, &read("operation_costs.toml")?)?;
    let fuzz_lib_path = root.join("crates/fa-fuzz/src/lib.rs");
    if fuzz_lib_path.is_file() {
        let fuzz_text = fs::read_to_string(&fuzz_lib_path)
            .map_err(|e| format!("{}: {e}", fuzz_lib_path.display()))?;
        let _fuzz_checked = check_fuzz_targets_cite_existing_beads(root, &fuzz_text)?;
    }
    let readme_path = root.join("README.md");
    let agents_path = root.join("AGENTS.md");
    let check_sh_path = root.join("scripts/check.sh");
    if readme_path.is_file() && agents_path.is_file() && check_sh_path.is_file() {
        let readme_text =
            fs::read_to_string(&readme_path).map_err(|e| format!("{}: {e}", readme_path.display()))?;
        let agents_text =
            fs::read_to_string(&agents_path).map_err(|e| format!("{}: {e}", agents_path.display()))?;
        let check_sh_text = fs::read_to_string(&check_sh_path)
            .map_err(|e| format!("{}: {e}", check_sh_path.display()))?;
        let prefixes: Vec<String> = claims_config
            .marker_families
            .iter()
            .map(|f| f.prefix.clone())
            .collect();
        let _sync_checked = check_readme_agents_sync(
            &readme_text,
            &agents_text,
            &check_sh_text,
            &read("verbs.toml")?,
            &known_markers,
            &prefixes,
        )?;
    }

    let invariants_live = invariants.clauses.iter().filter(|c| c.is_live()).count();
    Ok(CheckSummary {
        files_checked: EXPECTED_REGISTRIES.len() + extra_files,
        invariants_live,
        invariants_total: invariants.clauses.len(),
        refusals_checked,
        verbs_checked,
        mcp_tools_checked,
        mcp_default_tools,
        markers_checked,
        evidence_logs,
    })
}

/// Extract PascalCase and SCREAMING_SNAKE_CASE object/relation tokens from a
/// `derived_objects` description string.
fn extract_derived_object_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
        if raw.len() < 3 || matches!(raw, "CAS" | "MIN" | "MAX") {
            continue;
        }
        let is_screaming = raw
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            && raw.bytes().any(|b| b.is_ascii_uppercase())
            && raw.contains('_');
        let upper_count = raw.bytes().filter(|b| b.is_ascii_uppercase()).count();
        let has_lower = raw.bytes().any(|b| b.is_ascii_lowercase());
        let is_pascal_compound =
            raw.as_bytes()[0].is_ascii_uppercase() && upper_count >= 2 && has_lower;
        let is_core_vertex = matches!(
            raw,
            "Book"
                | "Entry"
                | "Leg"
                | "Period"
                | "Account"
                | "Document"
                | "Approval"
                | "Attestation"
                | "Certificate"
                | "Resolution"
                | "Register"
                | "Bundle"
                | "Migration"
                | "Finalize"
                | "Rehearse"
                | "Post"
                | "Expires"
        );
        if is_screaming || is_pascal_compound || is_core_vertex {
            out.push(raw.to_string());
        }
    }
    out
}

fn collect_write_path_identifiers(root: &Path) -> BTreeSet<String> {
    let mut known = BTreeSet::new();
    let sym_path = root.join("registries/symbols.toml");
    if let Ok(sym_text) = fs::read_to_string(&sym_path) {
        for line in sym_text.lines() {
            if let Some(rest) = line.trim().strip_prefix("name = \"")
                && let Some(name) = rest.strip_suffix('"')
            {
                known.insert(name.to_string());
            }
        }
    }
    let obj_dir = root.join("registries/object_schemas");
    if let Ok(entries) = fs::read_dir(&obj_dir) {
        for entry in entries.flatten() {
            if let Ok(text) = fs::read_to_string(entry.path()) {
                for tok in text.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                    if tok.len() >= 3 && tok.as_bytes()[0].is_ascii_uppercase() {
                        known.insert(tok.to_string());
                    }
                }
            }
        }
    }
    fn walk_rs(dir: &Path, out: &mut BTreeSet<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk_rs(&path, out);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs")
                && let Ok(text) = fs::read_to_string(&path)
            {
                for tok in text.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                    if tok.len() >= 3 && tok.as_bytes()[0].is_ascii_uppercase() {
                        out.insert(tok.to_string());
                    }
                }
            }
        }
    }
    for crate_dir in [
        "crates/fa-model/src",
        "crates/fa-journal/src",
        "crates/fa-docket/src",
        "crates/fa-notary/src",
        "crates/fa-registers/src",
        "crates/fa-escrow/src",
        "crates/fa-palimpsest/src",
    ] {
        walk_rs(&root.join(crate_dir), &mut known);
    }
    known
}

/// Verify that every object/relation kind named in `derived_objects` of
/// `registries/operation_costs.toml` exists in `symbols.toml`, `object_schemas`,
/// or the write-path crates (`fa-vz7e`).
pub fn check_operation_costs_derived_objects(
    root: &Path,
    op_costs_text: &str,
) -> Result<usize, String> {
    let known = collect_write_path_identifiers(root);
    let mut current_id = String::new();
    let mut checked = 0usize;
    for (idx, line) in op_costs_text.lines().enumerate() {
        let lineno = idx + 1;
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("id = \"")
            && let Some(id) = rest.strip_suffix('"')
        {
            current_id = id.to_string();
        } else if let Some(rest) = trimmed.strip_prefix("derived_objects = \"")
            && let Some(derived) = rest.strip_suffix('"')
        {
            for tok in extract_derived_object_tokens(derived) {
                let singular = tok.strip_suffix('s').unwrap_or(&tok);
                if !known.contains(&tok) && !known.contains(singular) {
                    return Err(format!(
                        "registries/operation_costs.toml:{lineno}: operation_class `{current_id}` derived_objects names unknown object kind `{tok}` (not in symbols.toml, object_schemas, or write-path crates)"
                    ));
                }
                checked += 1;
            }
        }
    }
    Ok(checked)
}

fn collect_known_bead_ids(root: &Path) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    let jsonl = root.join(".beads/issues.jsonl");
    if let Ok(text) = fs::read_to_string(&jsonl) {
        for line in text.lines() {
            if let Some(pos) = line.find("\"id\":\"") {
                let rest = &line[pos + 6..];
                if let Some(end) = rest.find('"') {
                    ids.insert(rest[..end].to_string());
                }
            }
        }
    }
    let reg_dir = root.join("registries");
    if let Ok(entries) = fs::read_dir(&reg_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("toml")
                && let Ok(text) = fs::read_to_string(&path)
            {
                let bytes = text.as_bytes();
                let mut i = 0;
                while i + 4 <= bytes.len() {
                    if &bytes[i..i + 3] == b"fa-"
                        && (i == 0
                            || !(bytes[i - 1].is_ascii_alphanumeric()
                                || bytes[i - 1] == b'_'
                                || bytes[i - 1] == b'-'))
                    {
                        let len = text[i + 3..]
                            .bytes()
                            .take_while(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'.')
                            .count();
                        if (3..=6).contains(&len) {
                            let next = text[i + 3 + len..].as_bytes().first().copied();
                            if !next.is_some_and(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                            {
                                ids.insert(text[i..i + 3 + len].to_string());
                            }
                        }
                    }
                    i += 1;
                }
            }
        }
    }
    ids
}

/// Verify that every dormant fuzz target in `crates/fa-fuzz/src/lib.rs` cites an
/// existing bead ID (`fa-vz7e`).
pub fn check_fuzz_targets_cite_existing_beads(
    root: &Path,
    fuzz_lib_text: &str,
) -> Result<usize, String> {
    let known_beads = collect_known_bead_ids(root);
    let mut current_target = String::new();
    let mut checked = 0usize;
    for (idx, line) in fuzz_lib_text.lines().enumerate() {
        let lineno = idx + 1;
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("name: \"")
            && let Some(name) = rest.strip_suffix("\",")
        {
            current_target = name.to_string();
        } else if let Some(rest) = trimmed.strip_prefix("activating_bead: \"")
            && let Some(bead) = rest.strip_suffix("\",")
        {
            if !known_beads.contains(bead) {
                return Err(format!(
                    "crates/fa-fuzz/src/lib.rs:{lineno}: dormant fuzz target `{current_target}` cites unknown bead `{bead}`"
                ));
            }
            checked += 1;
        }
    }
    Ok(checked)
}

fn parse_iso_date_days(ymd: &str) -> Result<i64, String> {
    let parts: Vec<&str> = ymd.split('-').collect();
    if parts.len() != 3 || parts[0].len() != 4 || parts[1].len() != 2 || parts[2].len() != 2 {
        return Err(format!("invalid ISO date `{ymd}`"));
    }
    let y: i64 = parts[0].parse().map_err(|_| format!("invalid year in `{ymd}`"))?;
    let m: i64 = parts[1].parse().map_err(|_| format!("invalid month in `{ymd}`"))?;
    let d: i64 = parts[2].parse().map_err(|_| format!("invalid day in `{ymd}`"))?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return Err(format!("out-of-range month/day in `{ymd}`"));
    }
    // Howard Hinnant civil-from-days formula (exact day difference for ISO dates).
    let y_adj = if m <= 2 { y - 1 } else { y };
    let era = if y_adj >= 0 { y_adj } else { y_adj - 399 } / 400;
    let yoe = y_adj - era * 400;
    let m_adj = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * m_adj + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok(era * 146097 + doe - 719468)
}

/// G0 `README.md` / `AGENTS.md` / `scripts/check.sh` / `verbs.toml` synchronization
/// check (`fa-vz7e`).
pub fn check_readme_agents_sync(
    readme_text: &str,
    agents_text: &str,
    check_sh_text: &str,
    verbs_text: &str,
    known_markers: &BTreeSet<String>,
    prefixes: &[String],
) -> Result<usize, String> {
    // (a) Every FA-* marker in README.md and AGENTS.md resolves, with file:line reporting.
    for (doc_name, doc_text) in [("README.md", readme_text), ("AGENTS.md", agents_text)] {
        for (idx, line) in doc_text.lines().enumerate() {
            let lineno = idx + 1;
            for marker in extract_markers(line, prefixes) {
                if !known_markers.contains(&marker) {
                    return Err(format!(
                        "{doc_name}:{lineno}: unresolved marker `{marker}` (not registered in registries/*.toml)"
                    ));
                }
            }
        }
    }

    // (b) Every `fa ` command above `## TL;DR` in README.md exists in verbs.toml.
    let verbs_doc = toml::parse(verbs_text).map_err(|e| format!("verbs.toml: {e}"))?;
    let mut verb_subs: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    if let Some(verbs) = verbs_doc.arrays.get("verb") {
        for v in verbs {
            let name = req_str("verbs.toml", v, "name")?.to_string();
            let subs: BTreeSet<String> = req_str_array("verbs.toml", v, "subcommands")?
                .into_iter()
                .collect();
            verb_subs.insert(name, subs);
        }
    }
    let mut aliases: Vec<(Vec<String>, Vec<String>)> = Vec::new();
    if let Some(alias_rows) = verbs_doc.arrays.get("alias") {
        for a in alias_rows {
            let from = req_str_array("verbs.toml", a, "from")?;
            let to = req_str_array("verbs.toml", a, "to")?;
            aliases.push((from, to));
        }
    }
    aliases.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

    let (above_tldr, _) = readme_text
        .split_once("\n## TL;DR\n")
        .ok_or_else(|| "README.md:1: missing `## TL;DR` section delimiter".to_string())?;
    let mut in_fence: Option<bool> = None;
    let mut pending = String::new();
    let mut pending_line = 0usize;
    let mut commands_checked = 0usize;
    for (idx, raw) in above_tldr.lines().enumerate() {
        let lineno = idx + 1;
        if let Some(lang) = raw.strip_prefix("```") {
            in_fence = match in_fence {
                None => Some(matches!(
                    lang.trim(),
                    "" | "bash" | "sh" | "shell" | "console"
                )),
                Some(_) => None,
            };
            pending.clear();
            continue;
        }
        if in_fence != Some(true) {
            continue;
        }
        let part = raw.trim();
        if part.is_empty() || part.starts_with('#') {
            continue;
        }
        let joined = if pending.is_empty() {
            pending_line = lineno;
            part.to_string()
        } else {
            format!("{pending} {part}")
        };
        if let Some(head) = joined.strip_suffix('\\') {
            pending = head.trim_end().to_string();
            continue;
        }
        pending.clear();
        if !joined.starts_with("fa ") {
            continue;
        }
        commands_checked += 1;
        let mut words: Vec<String> = joined
            .split_whitespace()
            .skip(1)
            .map(str::to_string)
            .collect();
        for (from, to) in &aliases {
            if words.len() >= from.len() && words[..from.len()] == from[..] {
                let mut expanded = to.clone();
                expanded.extend_from_slice(&words[from.len()..]);
                words = expanded;
                break;
            }
        }
        let Some(vname) = words.first() else {
            continue;
        };
        let Some(subs) = verb_subs.get(vname) else {
            return Err(format!(
                "README.md:{pending_line}: command `{joined}` uses unregistered verb `{vname}` (not in registries/verbs.toml:1)"
            ));
        };
        if !subs.is_empty() && !words.get(1).is_some_and(|sc| subs.contains(sc)) {
            return Err(format!(
                "README.md:{pending_line}: command `{joined}` missing valid subcommand for `{vname}` (registries/verbs.toml:1)"
            ));
        }
    }

    // (c) README status line carries a date within 7 days of the Verified-at verdict line.
    let mut status_date: Option<(usize, String)> = None;
    let mut verified_date: Option<(usize, String)> = None;
    for (idx, line) in readme_text.lines().enumerate() {
        let lineno = idx + 1;
        if status_date.is_none()
            && let Some(pos) = line.find("**Status (")
        {
            let rest = &line[pos + 10..];
            if let Some(end) = rest.find("):") {
                status_date = Some((lineno, rest[..end].to_string()));
            }
        }
        if verified_date.is_none()
            && let Some(pos) = line.find("Verified at ")
            && let Some(lparen) = line[pos..].find('(')
            && let Some(rparen) = line[pos + lparen + 1..].find(')')
        {
            let ymd = &line[pos + lparen + 1..pos + lparen + 1 + rparen];
            verified_date = Some((lineno, ymd.to_string()));
        }
    }
    let (status_line, status_ymd) = status_date
        .ok_or_else(|| "README.md:1: missing `> **Status (YYYY-MM-DD):` status line".to_string())?;
    let status_days = parse_iso_date_days(&status_ymd)
        .map_err(|e| format!("README.md:{status_line}: {e}"))?;
    if let Some((ver_line, ver_ymd)) = verified_date {
        let ver_days = parse_iso_date_days(&ver_ymd)
            .map_err(|e| format!("README.md:{ver_line}: {e}"))?;
        let diff = (ver_days - status_days).abs();
        if diff > 7 {
            return Err(format!(
                "README.md:{status_line}: status date `{status_ymd}` is {diff} days from verdict date `{ver_ymd}` at README.md:{ver_line} (max 7 days)"
            ));
        }
    }

    // (d) AGENTS.md list of check.sh steps equals check.sh's CANONICAL_STEPS header.
    let mut agents_steps: Option<(usize, Vec<String>)> = None;
    for (idx, line) in agents_text.lines().enumerate() {
        if let Some(start) = line.find("<!-- check-sh-steps:")
            && let Some(end) = line[start..].find("-->")
        {
            let inner = &line[start + "<!-- check-sh-steps:".len()..start + end];
            let list: Vec<String> = inner
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            agents_steps = Some((idx + 1, list));
            break;
        }
    }
    let mut check_steps: Option<(usize, Vec<String>)> = None;
    for (idx, line) in check_sh_text.lines().enumerate() {
        if let Some(rest) = line.trim().strip_prefix("# CANONICAL_STEPS:") {
            let list: Vec<String> = rest
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            check_steps = Some((idx + 1, list));
            break;
        }
    }
    let (agents_line, a_list) = agents_steps.ok_or_else(|| {
        "AGENTS.md:1: missing `<!-- check-sh-steps: ... -->` step list".to_string()
    })?;
    let (check_line, c_list) = check_steps.ok_or_else(|| {
        "scripts/check.sh:1: missing `# CANONICAL_STEPS: ...` header".to_string()
    })?;
    if a_list != c_list {
        return Err(format!(
            "AGENTS.md:{agents_line}: check.sh step list {a_list:?} disagrees with scripts/check.sh:{check_line} CANONICAL_STEPS {c_list:?}"
        ));
    }

    Ok(commands_checked)
}

fn default_workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let mut root = default_workspace_root();
    let mut json = false;
    let mut g0 = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => {
                let val = args.next().ok_or_else(|| {
                    "registry-check: --root requires a directory path".to_string()
                })?;
                root = PathBuf::from(val);
            }
            "--json" => json = true,
            "--g0" => g0 = true,
            "-h" | "--help" => {
                println!("Usage: registry-check [--root <workspace-root>] [--g0] [--json]");
                return Ok(());
            }
            other => {
                return Err(format!("registry-check: unknown argument `{other}`"));
            }
        }
    }
    let summary = check_workspace_registries(&root)?;
    if g0 {
        let report = check_g0_report(&root)?;
        if json {
            let mut rows_json = String::new();
            for (idx, r) in report.rows.iter().enumerate() {
                if idx > 0 {
                    rows_json.push(',');
                }
                let status_str = match &r.status {
                    G0Status::Present => "present".to_string(),
                    G0Status::OwnedBy(b) => format!("owned_by {b}"),
                    G0Status::Missing(m) => format!("missing: {m}"),
                };
                rows_json.push_str(&format!(
                    "{{\"path\":\"{}\",\"kind\":\"{}\",\"owner_bead\":\"{}\",\"status\":\"{}\"}}",
                    r.path, r.kind, r.owner_bead, status_str
                ));
            }
            println!(
                "{{\"event\":\"g0_registry_report\",\"status\":\"ok\",\"total\":{},\"present\":{},\"owned\":{},\"missing\":{},\"registries\":[{}]}}",
                report.total, report.present, report.owned, report.missing, rows_json
            );
        } else {
            println!(
                "registry-check --g0: ok ({}/{} present, {} owned by open beads, {} missing)",
                report.present, report.total, report.owned, report.missing
            );
            for r in &report.rows {
                let st = match &r.status {
                    G0Status::Present => "present".to_string(),
                    G0Status::OwnedBy(b) => format!("owned_by {b}"),
                    G0Status::Missing(m) => format!("missing ({m})"),
                };
                println!("  {:28} -> {}", r.path, st);
            }
        }
        return Ok(());
    }
    if json {
        println!(
            "{{\"event\":\"registry_check\",\"status\":\"ok\",\"files_checked\":{},\"invariants_live\":{},\"invariants_total\":{},\"refusals_checked\":{},\"verbs_checked\":{},\"mcp_tools_checked\":{},\"markers_checked\":{},\"evidence_artifacts_verified\":{}}}",
            summary.files_checked,
            summary.invariants_live,
            summary.invariants_total,
            summary.refusals_checked,
            summary.verbs_checked,
            summary.mcp_tools_checked,
            summary.markers_checked,
            summary.evidence_logs.len()
        );
    } else {
        for log in &summary.evidence_logs {
            println!(
                "  evidence artifact_id={} kind={} witness_fields_checked={} verdict={}",
                log.artifact_id,
                log.kind.as_str(),
                log.witness_fields_checked,
                log.verdict
            );
        }
        println!(
            "registry-check: ok ({} TOML files, {}/{} live invariant clauses, {} refusals, {} verbs, {} MCP tools, {} doc markers, {} evidence artifacts)",
            summary.files_checked,
            summary.invariants_live,
            summary.invariants_total,
            summary.refusals_checked,
            summary.verbs_checked,
            summary.mcp_tools_checked,
            summary.markers_checked,
            summary.evidence_logs.len()
        );
    }
    Ok(())
}

fn main() -> ProcessExitCode {
    match run() {
        Ok(()) => ProcessExitCode::SUCCESS,
        Err(err) => {
            eprintln!("FAIL registry-check — {err}");
            ProcessExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_registry::evidence_artifacts::verify_prose_claims_lint_text;

    #[test]
    fn real_workspace_registries_pass() {
        let root = default_workspace_root();
        let summary = check_workspace_registries(&root).expect("workspace registries valid");
        assert!(summary.files_checked >= EXPECTED_REGISTRIES.len());
        assert!(summary.invariants_live >= 18);
        assert!(summary.refusals_checked >= IMMUTABLE_REFUSALS.len());
        assert!(summary.verbs_checked >= 20);
        assert!(summary.mcp_default_tools <= 40);
        assert!(summary.mcp_tools_checked >= summary.mcp_default_tools);
        assert!(summary.markers_checked >= 45);

        let g0 = check_g0_report(&root).expect("g0 report valid");
        assert_eq!(g0.total, 37);
        assert_eq!(g0.missing, 0);
        assert_eq!(g0.present + g0.owned, 37);
    }

    #[test]
    fn planted_schema_majors_require_their_declared_transition() {
        let base = "schema_version = 1\nname = \"X\"\n";
        for admitted in [
            "minor = 0\n",
            "major = 1\n",
            "major = 2\nversions = [\"1:old\", \"2:new\"]\n",
        ] {
            check_nested_schema("x.toml", &format!("{base}{admitted}"))
                .unwrap_or_else(|err| panic!("{admitted}: {err}"));
        }
        for (planted, why) in [
            ("major = 0\n", "at least 1"),
            ("major = 2\n", "declared transition"),
            ("major = 2\nversions = [\"1:old\"]\n", "declared transition"),
            (
                "major = 2\nversions = [\"2:new\", \"1:old\"]\n",
                "declared transition",
            ),
            (
                "major = 2\nversions = [\"1:old\", \"2: \"]\n",
                "declared transition",
            ),
            (
                "major = 2\nversions = [\"1:old\", 2]\n",
                "declared transition",
            ),
            (
                "major = 3\nversions = [\"1:a\", \"2:b\"]\n",
                "declared transition",
            ),
        ] {
            let err =
                check_nested_schema("x.toml", &format!("{base}{planted}")).expect_err(planted);
            assert!(
                err.contains("x.toml") && err.contains(why),
                "{planted}: {err}"
            );
        }
        let err = check_nested_schema("x.toml", "schema_version = 2\n").expect_err("schema 2");
        assert!(err.contains("schema_version must be 1"), "{err}");
    }

    #[test]
    fn planted_refusal_mutation_and_broken_foreign_keys_fail() {
        let root = default_workspace_root();
        let exits = ExitCodes::embedded().expect("exit_codes.toml");
        let refusals = fs::read_to_string(root.join("registries/refusal_catalog.toml"))
            .expect("read refusals");
        let mutated = refusals.replacen("name = \"UNBALANCED\"", "name = \"RENAMED_001\"", 1);
        let err = check_refusal_immutability(&mutated, &exits).expect_err("mutated FA-REF-001");
        assert!(
            err.contains("refusal_catalog.toml") && err.contains("FA-REF-001"),
            "{err}"
        );

        // Planted negative 1 (fa-szi): a refusal code with an unknown exit fails.
        let bad_refusal_exit =
            refusals.replacen("exit = \"refusal\"", "exit = \"nonexistent_exit\"", 1);
        let err = check_refusal_immutability(&bad_refusal_exit, &exits)
            .expect_err("refusal with unknown exit");
        assert!(
            err.contains("refusal_catalog.toml") && err.contains("nonexistent_exit"),
            "{err}"
        );

        let verbs = fs::read_to_string(root.join("registries/verbs.toml")).expect("read verbs");
        let bad_exit = verbs.replacen("exits = [0, 2]", "exits = [0, 99]", 1);
        let err = check_verbs(&bad_exit, &exits).expect_err("broken exit foreign key");
        assert!(
            err.contains("verbs.toml") && err.contains("exit code `99`"),
            "{err}"
        );

        // Planted negative 2 (fa-szi): a verb citing an unknown capability op fails.
        let bad_op = verbs.replacen(
            "condition = \"grant:post_closed\"",
            "condition = \"grant:invented_op\"",
            1,
        );
        let err = check_verbs(&bad_op, &exits).expect_err("verb citing unknown op");
        assert!(
            err.contains("verbs.toml") && err.contains("invented_op"),
            "{err}"
        );

        let bad_event = verbs.replacen(
            "events = [\"capabilities\"]",
            "events = [\"no_such_event\"]",
            1,
        );
        let err = check_verbs(&bad_event, &exits).expect_err("broken event foreign key");
        assert!(
            err.contains("verbs.toml") && err.contains("no_such_event"),
            "{err}"
        );

        // Planted negative 3 (fa-szi): a marker in docs with no registry row fails claims_lint.
        let claims_config = ClaimsLintConfig::embedded().expect("claims_lint.toml");
        let known: BTreeSet<String> = ["FA-INV-01".to_string()].into_iter().collect();
        let err = check_claims_lint(
            &claims_config,
            &known,
            &[("README.md", "See FA-INV-01 and unregistered FA-INV-99.")],
        )
        .expect_err("unregistered marker must fail claims_lint");
        assert!(
            err.contains("claims_lint") && err.contains("FA-INV-99"),
            "{err}"
        );

        let invariants = Invariants::embedded().expect("invariants.toml");
        let catalog = RefusalCatalog::from_text(&refusals, &exits).expect("refusal catalog");
        let threat_text =
            fs::read_to_string(root.join("registries/threat_model.toml")).expect("threat_model");
        let bad_test_ref = threat_text.replacen(
            "fa-model::lib::entry::tests::tampered_bytes_are_refused",
            "fa-model::lib::entry::tests::nonexistent_test_function",
            1,
        );
        let parsed_tm =
            ThreatModel::parse(&bad_test_ref, &invariants, &catalog).expect("valid syntax");
        let unresolved =
            parsed_tm.unresolved_test_refs(|rel| fs::read_to_string(root.join(rel)).ok());
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].0, "FA-THR-01");

        // Planted negative 4 (fa-i5s): an slo row typed `invariant` or below barrier floor fails.
        let op_costs = OperationCosts::embedded().expect("operation_costs.toml");
        let slo_text = fs::read_to_string(root.join("registries/slo.toml")).expect("slo.toml");
        let bad_slo_claim = slo_text.replacen(
            "claim_class = \"benchmark\"",
            "claim_class = \"invariant\"",
            1,
        );
        let err =
            SloRegistry::parse(&bad_slo_claim, &op_costs).expect_err("slo row typed invariant");
        assert!(
            err.to_string().contains("claims_lint") && err.to_string().contains("invariant"),
            "{err}"
        );
        let bad_slo_floor = slo_text.replacen("target_p50_us = 2000", "target_p50_us = 1500", 1);
        let err =
            SloRegistry::parse(&bad_slo_floor, &op_costs).expect_err("slo row below barrier floor");
        assert!(
            err.to_string().contains("derivability law violation"),
            "{err}"
        );
    }

    #[test]
    fn benchmark_artifact_requires_scale_witness() {
        let valid = r#"
schema_version = 1

[[artifact]]
id = "FA-ART-BENCH-01"
kind = "benchmark"
manifest_path = "evidence/benchmark/tb_100k.toml"
manifest_blake3 = "1111111111111111111111111111111111111111111111111111111111111111"
produced_by = "cargo bench -p fa-registers"
git_commit = "a8775e1ca39278488ec5711d241f3502ccddfd79"
summary = "Trial balance 100k benchmark"
scale_witness_entry_count = 100000
scale_witness_leg_count = 200000
iterations = 50
warmup = 10
quantile_samples_ns = [120000, 125000, 131000]
flamegraph_svg_sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
host_cpu_model = "AMD EPYC 9654"
host_kernel = "Linux 6.8"
runner = "rch-worker"
"#;
        EvidenceArtifacts::from_text(valid).expect("valid benchmark artifact parses");

        let zero_scale = valid
            .replace("scale_witness_entry_count = 100000\n", "")
            .replace("scale_witness_leg_count = 200000\n", "");
        let err = EvidenceArtifacts::from_text(&zero_scale)
            .expect_err("benchmark without scale_witness must fail");
        assert!(err.to_string().contains("scale_witness"), "{err}");

        let unsorted = valid.replace(
            "quantile_samples_ns = [120000, 125000, 131000]",
            "quantile_samples_ns = [131000, 120000]",
        );
        let err = EvidenceArtifacts::from_text(&unsorted)
            .expect_err("unsorted quantile_samples_ns must fail");
        assert!(err.to_string().contains("sorted ascending"), "{err}");
    }

    #[test]
    fn oracle_artifact_requires_compared_cells() {
        let valid = r#"
schema_version = 1

[[artifact]]
id = "FA-ART-ORA-01"
kind = "external-oracle"
manifest_path = "evidence/external_oracle/beancount_v3.toml"
manifest_blake3 = "1111111111111111111111111111111111111111111111111111111111111111"
produced_by = "bean-check fixture.beancount"
git_commit = "a8775e1ca39278488ec5711d241f3502ccddfd79"
summary = "External bean-check balance comparison"
tool_binary_path = "/usr/bin/bean-check"
tool_version_stdout = "Beancount 3.0.0"
tool_binary_sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
input_fixture_sha256 = "3333333333333333333333333333333333333333333333333333333333333333"
tool_stdout_sha256 = "4444444444444444444444444444444444444444444444444444444444444444"
tool_exit_code = 0
compared_cells = 42
"#;
        EvidenceArtifacts::from_text(valid).expect("valid external-oracle artifact parses");

        let zero_cells = valid.replace("compared_cells = 42", "compared_cells = 0");
        let err = EvidenceArtifacts::from_text(&zero_cells)
            .expect_err("compared_cells = 0 must be refused");
        assert!(err.to_string().contains("compared_cells"), "{err}");
    }

    #[test]
    fn lean_artifact_requires_theorem_inventory() {
        let valid = r#"
schema_version = 1

[[artifact]]
id = "FA-ART-LEAN-01"
kind = "lean"
manifest_path = "evidence/lean/abacus.toml"
manifest_blake3 = "1111111111111111111111111111111111111111111111111111111111111111"
produced_by = "lake build"
git_commit = "a8775e1ca39278488ec5711d241f3502ccddfd79"
summary = "Lean 4 Abacus theorems"
lean_version = "leanprover/lean4:v4.12.0"
lake_manifest_sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
olean_tar_sha256 = "3333333333333333333333333333333333333333333333333333333333333333"
theorem_inventory = ["abacus_conservation:Fa.Abacus:0:propext"]
"#;
        EvidenceArtifacts::from_text(valid).expect("valid lean artifact parses");

        let with_sorry = valid.replace(
            "abacus_conservation:Fa.Abacus:0:propext",
            "abacus_conservation:Fa.Abacus:1:propext",
        );
        let err = EvidenceArtifacts::from_text(&with_sorry)
            .expect_err("Lean theorem with sorry_count > 0 must fail");
        assert!(err.to_string().contains("sorry_count"), "{err}");

        let with_classical_choice = valid.replace(
            "abacus_conservation:Fa.Abacus:0:propext",
            "abacus_conservation:Fa.Abacus:0:Classical.choice",
        );
        let err = EvidenceArtifacts::from_text(&with_classical_choice)
            .expect_err("Lean theorem with Classical.choice must fail");
        assert!(err.to_string().contains("Classical.choice"), "{err}");
    }

    #[test]
    fn tlc_artifact_requires_state_count() {
        let valid = r#"
schema_version = 1

[[artifact]]
id = "FA-ART-TLC-01"
kind = "tlc"
manifest_path = "evidence/tlc/period_law.toml"
manifest_blake3 = "1111111111111111111111111111111111111111111111111111111111111111"
produced_by = "tlc2.TLC PeriodLaw.tla"
git_commit = "a8775e1ca39278488ec5711d241f3502ccddfd79"
summary = "TLC model check of period transitions"
tlc_version = "TLC 2.18"
spec_sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
cfg_sha256 = "3333333333333333333333333333333333333333333333333333333333333333"
distinct_states = 1840
states_generated = 5120
depth = 12
result = "pass"
"#;
        EvidenceArtifacts::from_text(valid).expect("valid tlc artifact parses");

        let zero_states = valid.replace("distinct_states = 1840", "distinct_states = 0");
        let err = EvidenceArtifacts::from_text(&zero_states)
            .expect_err("distinct_states = 0 must be refused");
        assert!(err.to_string().contains("distinct_states"), "{err}");

        let zero_depth = valid.replace("depth = 12", "depth = 0");
        let err = EvidenceArtifacts::from_text(&zero_depth).expect_err("depth = 0 must be refused");
        assert!(err.to_string().contains("depth"), "{err}");
    }

    #[test]
    fn calibration_artifact_requires_confusion_counts() {
        let valid = r#"
schema_version = 1

[[artifact]]
id = "FA-ART-CAL-99"
kind = "calibration"
manifest_path = "evidence/calibration/sample.toml"
manifest_blake3 = "1111111111111111111111111111111111111111111111111111111111111111"
produced_by = "cargo test -p fa-lantern"
git_commit = "a8775e1ca39278488ec5711d241f3502ccddfd79"
summary = "Sample calibration"
corpus_manifest_sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
case_count = 30
per_procedure_confusion = ["jet.round_amounts:90:0:0:1200"]
"#;
        EvidenceArtifacts::from_text(valid).expect("valid calibration artifact parses");

        let zero_pos = valid.replace(
            "jet.round_amounts:90:0:0:1200",
            "jet.round_amounts:0:0:0:1200",
        );
        let err = EvidenceArtifacts::from_text(&zero_pos)
            .expect_err("calibration with TP + FN = 0 must fail");
        assert!(err.to_string().contains("TP + FN = 0"), "{err}");
    }

    #[test]
    fn claims_lint_covers_docs() {
        let artifacts = EvidenceArtifacts::embedded().expect("evidence_artifacts.toml");
        let invariants = Invariants::embedded().expect("invariants.toml");

        // Backed prose claims pass.
        let backed = "The 12 procedures were measured across 210 synthetic corpora (FA-ART-CAL-01).\n\nEvery balance fold is deterministic and exact (FA-INV-01).";
        verify_prose_claims_lint_text("docs/example.md", backed, &artifacts, &invariants)
            .expect("backed prose claims pass");

        // Unbacked prose claims fail.
        for unbacked in [
            "We measured 500k postings per second on the reference host.",
            "The ledger was verified against an external oracle on 50 fixtures.",
            "Every detector is calibrated on production financial statements.",
            "This formal proof establishes conservation across all currencies.",
            "Balance queries execute in constant-time regardless of history depth.",
            "We observed exact agreement across three independent CLI implementations.",
        ] {
            let err =
                verify_prose_claims_lint_text("docs/planted.md", unbacked, &artifacts, &invariants)
                    .expect_err(unbacked);
            assert!(err.to_string().contains("docs/planted.md"), "{err}");
        }
    }

    #[test]
    fn external_oracle_claim_requires_artifact() {
        let artifacts = EvidenceArtifacts::embedded().expect("evidence_artifacts.toml");
        let op_costs = OperationCosts::embedded().expect("operation_costs.toml");
        let slo = SloRegistry::embedded(&op_costs).expect("slo.toml");
        let invariants = Invariants::embedded().expect("invariants.toml");
        let proof_lanes = ProofLanes::embedded(&invariants).expect("proof_lanes.toml");
        let mut formats = Formats::embedded().expect("formats.toml");
        let evidence = EvidenceRegistry::embedded().expect("evidence.toml");
        let procedures = Procedures::embedded().expect("procedures.toml");
        let calibration = LanternCalibration::embedded().expect("lantern_calibration.toml");

        // Flipping `beancount_v3` from `oracle_status = "unrun"` to `"verified"` without
        // citing an external-oracle artifact must fail cross-check (fa-kkxl / fa-vtzt).
        formats
            .rows
            .iter_mut()
            .find(|r| r.name == "beancount_v3")
            .expect("beancount_v3")
            .oracle_status = "verified".to_string();
        let err = verify_claim_artifact_cross_refs(
            &artifacts,
            &slo,
            &invariants,
            &proof_lanes,
            &formats,
            &evidence,
            &procedures,
            &calibration,
        )
        .expect_err("external oracle claim without artifact must fail");
        assert!(
            err.to_string().contains("beancount_v3") && err.to_string().contains("external-oracle"),
            "{err}"
        );
    }

    #[test]
    fn proof_class_requires_lean_build_artifact() {
        let artifacts = EvidenceArtifacts::embedded().expect("evidence_artifacts.toml");
        let op_costs = OperationCosts::embedded().expect("operation_costs.toml");
        let slo = SloRegistry::embedded(&op_costs).expect("slo.toml");
        let invariants = Invariants::embedded().expect("invariants.toml");
        let mut proof_lanes = ProofLanes::embedded(&invariants).expect("proof_lanes.toml");
        let formats = Formats::embedded().expect("formats.toml");
        let evidence = EvidenceRegistry::embedded().expect("evidence.toml");
        let procedures = Procedures::embedded().expect("procedures.toml");
        let calibration = LanternCalibration::embedded().expect("lantern_calibration.toml");

        // Activating a Lean proof lane (`FA-PROOF-01`) without a Lean build artifact
        // covering its theorems must fail cross-check (fa-2lsv / fa-vtzt).
        proof_lanes.lanes[0].status = "live".to_string();
        let err = verify_claim_artifact_cross_refs(
            &artifacts,
            &slo,
            &invariants,
            &proof_lanes,
            &formats,
            &evidence,
            &procedures,
            &calibration,
        )
        .expect_err("live proof lane without Lean artifact must fail");
        assert!(
            err.to_string().contains("FA-PROOF-01") && err.to_string().contains("artifact"),
            "{err}"
        );
    }

    #[test]
    fn activated_slo_requires_measurement_artifact() {
        let artifacts = EvidenceArtifacts::embedded().expect("evidence_artifacts.toml");
        let op_costs = OperationCosts::embedded().expect("operation_costs.toml");
        let mut slo = SloRegistry::embedded(&op_costs).expect("slo.toml");
        let invariants = Invariants::embedded().expect("invariants.toml");
        let proof_lanes = ProofLanes::embedded(&invariants).expect("proof_lanes.toml");
        let formats = Formats::embedded().expect("formats.toml");
        let evidence = EvidenceRegistry::embedded().expect("evidence.toml");
        let procedures = Procedures::embedded().expect("procedures.toml");
        let calibration = LanternCalibration::embedded().expect("lantern_calibration.toml");

        // Flipping `activated = true` on any SLO row without a benchmark artifact
        // must fail cross-check (fa-e75k / fa-vtzt).
        slo.rows[0].activated = true;
        let err = verify_claim_artifact_cross_refs(
            &artifacts,
            &slo,
            &invariants,
            &proof_lanes,
            &formats,
            &evidence,
            &procedures,
            &calibration,
        )
        .expect_err("activated SLO without benchmark artifact must fail");
        assert!(
            err.to_string().contains(&slo.rows[0].id) && err.to_string().contains("benchmark"),
            "{err}"
        );
    }
}
