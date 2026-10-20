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

use fa_registry::document_stores::DocumentStores;
use fa_registry::evidence_policy::EvidencePolicy;
use fa_registry::foundations::Ledger;
use fa_registry::g0::{
    CheckerIndex, ClaimsLintConfig, Constitution, ConversionLaws, EvidenceRegistry, Formats,
    FxLaws, LotLaws, OperationCosts, PeriodStatesRegistry, ProofLanes, RelationshipBases,
    SloRegistry, SupersessionKinds, TracingLaws,
};
use fa_registry::intake_sources::IntakeSources;
use fa_registry::invariants::Invariants;
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
use fa_registry::{
    Admissibility, CapabilityCaveats, ControlKinds, EntryClasses, ExitCodes, Symbols, parse_units,
    rounding_laws_embedded,
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
    "evidence_policy.toml",
    "exit_codes.toml",
    "formats.toml",
    "foundation_dependencies.toml",
    "fx_laws.toml",
    "intake_sources.toml",
    "invariants.toml",
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
    let _control_kinds = ControlKinds::embedded(&classes).map_err(|e| e.to_string())?;
    let _rounding = rounding_laws_embedded().map_err(|e| e.to_string())?;
    let _symbols = Symbols::embedded().map_err(|e| e.to_string())?;
    let _stores = DocumentStores::embedded().map_err(|e| e.to_string())?;
    let _evidence = EvidencePolicy::embedded().map_err(|e| e.to_string())?;
    let _intake = IntakeSources::embedded().map_err(|e| e.to_string())?;
    let _procedures = Procedures::embedded().map_err(|e| e.to_string())?;
    let _reasons = ReasonCodes::embedded().map_err(|e| e.to_string())?;
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
    let _tracing_laws =
        TracingLaws::parse(&read("tracing_laws.toml")?, &procedures).map_err(|e| e.to_string())?;
    let _fx_laws = FxLaws::parse(&read("fx_laws.toml")?, &classes).map_err(|e| e.to_string())?;
    let _formats = Formats::parse(&read("formats.toml")?).map_err(|e| e.to_string())?;
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
    })
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
            "{{\"event\":\"registry_check\",\"status\":\"ok\",\"files_checked\":{},\"invariants_live\":{},\"invariants_total\":{},\"refusals_checked\":{},\"verbs_checked\":{},\"mcp_tools_checked\":{},\"markers_checked\":{}}}",
            summary.files_checked,
            summary.invariants_live,
            summary.invariants_total,
            summary.refusals_checked,
            summary.verbs_checked,
            summary.mcp_tools_checked,
            summary.markers_checked
        );
    } else {
        println!(
            "registry-check: ok ({} TOML files, {}/{} live invariant clauses, {} refusals, {} verbs, {} MCP tools, {} doc markers)",
            summary.files_checked,
            summary.invariants_live,
            summary.invariants_total,
            summary.refusals_checked,
            summary.verbs_checked,
            summary.mcp_tools_checked,
            summary.markers_checked
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
}
