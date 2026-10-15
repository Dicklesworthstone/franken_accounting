//! `registry-check` — validates all `registries/*.toml` schemas, cross-registry
//! foreign keys, and `FA-REF-*` refusal catalog immutability (plan §18.2, bead `fa-ad8d`).

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode as ProcessExitCode;

use fa_registry::document_stores::DocumentStores;
use fa_registry::evidence_policy::EvidencePolicy;
use fa_registry::foundations::Ledger;
use fa_registry::intake_sources::IntakeSources;
use fa_registry::invariants::Invariants;
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
    Admissibility, ControlKinds, EntryClasses, ExitCodes, Symbols, parse_units,
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

const EXPECTED_REGISTRIES: &[&str] = &[
    "account_types.toml",
    "admissibility.toml",
    "allocation_laws.toml",
    "document_stores.toml",
    "entry_classes.toml",
    "evidence_policy.toml",
    "exit_codes.toml",
    "foundation_dependencies.toml",
    "intake_sources.toml",
    "invariants.toml",
    "limits.toml",
    "procedures.toml",
    "reason_codes.toml",
    "redaction_contracts.toml",
    "refusal_catalog.toml",
    "rounding_laws.toml",
    "scoreboard.toml",
    "sod_policy.toml",
    "symbols.toml",
    "threat_model.toml",
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

pub fn check_verbs(text: &str, exits: &ExitCodes) -> Result<(usize, usize), String> {
    const F: &str = "verbs.toml";
    let doc = toml::parse(text).map_err(|e| format!("{F}: {e}"))?;
    if req_int(F, &doc.root, "schema_version")? != 1 {
        return Err(format!("{F}: schema_version must be 1"));
    }
    let valid_exits: BTreeSet<i128> = exits.rows.iter().map(|r| i128::from(r.code)).collect();
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
    let tools = doc
        .arrays
        .get("mcp.tool")
        .ok_or_else(|| format!("{F}: missing [[mcp.tool]]"))?;
    if tools.len() > 40 {
        return Err(format!(
            "{F}: mcp.tool count {} exceeds plan §15.4 limit of 40",
            tools.len()
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
    Ok((verbs.len(), tools.len()))
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

    // 2. Disk-backed checks (supports validating mutated registries in --root).
    let read = |name: &str| -> Result<String, String> {
        let p = reg_dir.join(name);
        fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))
    };
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
    }
    let invariants = Invariants::parse(&read("invariants.toml")?).map_err(|e| e.to_string())?;
    let _topology =
        Topology::parse(&read("workspace_topology.toml")?).map_err(|e| e.to_string())?;

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
    let _scoreboard =
        Scoreboard::parse(&read("scoreboard.toml")?, &exits, &refusals).map_err(|e| e.to_string())?;
    let (verbs_checked, mcp_tools_checked) = check_verbs(&read("verbs.toml")?, &exits)?;

    // Also parse nested TOML schemas under object_schemas/ and statements/.
    let mut extra_files = 0usize;
    for sub in ["object_schemas", "statements"] {
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
                    toml::parse(&content).map_err(|e| format!("{}: {e}", path.display()))?;
                    extra_files += 1;
                }
            }
        }
    }

    let invariants_live = invariants.clauses.iter().filter(|c| c.is_live()).count();
    Ok(CheckSummary {
        files_checked: EXPECTED_REGISTRIES.len() + extra_files,
        invariants_live,
        invariants_total: invariants.clauses.len(),
        refusals_checked,
        verbs_checked,
        mcp_tools_checked,
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
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => {
                let val = args.next().ok_or_else(|| {
                    "registry-check: --root requires a directory path".to_string()
                })?;
                root = PathBuf::from(val);
            }
            "--json" => json = true,
            "-h" | "--help" => {
                println!("Usage: registry-check [--root <workspace-root>] [--json]");
                return Ok(());
            }
            other => {
                return Err(format!("registry-check: unknown argument `{other}`"));
            }
        }
    }
    let summary = check_workspace_registries(&root)?;
    if json {
        println!(
            "{{\"event\":\"registry_check\",\"status\":\"ok\",\"files_checked\":{},\"invariants_live\":{},\"invariants_total\":{},\"refusals_checked\":{},\"verbs_checked\":{},\"mcp_tools_checked\":{}}}",
            summary.files_checked,
            summary.invariants_live,
            summary.invariants_total,
            summary.refusals_checked,
            summary.verbs_checked,
            summary.mcp_tools_checked
        );
    } else {
        println!(
            "registry-check: ok ({} TOML files, {}/{} live invariant clauses, {} refusals, {} verbs, {} MCP tools)",
            summary.files_checked,
            summary.invariants_live,
            summary.invariants_total,
            summary.refusals_checked,
            summary.verbs_checked,
            summary.mcp_tools_checked
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
        assert!(summary.mcp_tools_checked <= 40);
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

        let verbs = fs::read_to_string(root.join("registries/verbs.toml")).expect("read verbs");
        let bad_exit = verbs.replacen("exits = [0, 2]", "exits = [0, 99]", 1);
        let err = check_verbs(&bad_exit, &exits).expect_err("broken exit foreign key");
        assert!(
            err.contains("verbs.toml") && err.contains("exit code `99`"),
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
    }
}
