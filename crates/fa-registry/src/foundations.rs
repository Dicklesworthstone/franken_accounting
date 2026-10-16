//! `registries/foundation_dependencies.toml`: plan Appendix H as data, the
//! foundation dependency ledger (bead fa-37f).
//!
//! AGENTS.md: before relying on a substrate capability, check its row — live,
//! or interim posture with its switch-over rule; never assume a planned
//! capability is live. The reader enforces the ledger's laws: a capability
//! planned or absent upstream is interim here, and an interim row names a
//! switch-over rule. Its tests pin the rows to Appendix H verbatim and check
//! the foundations against `franken-stack.lock` and the workspace pins (the
//! drift check: a lock revision that differs from a crate's `Cargo.toml` pin
//! is reported).

use std::collections::BTreeSet;
use std::path::Path;

use crate::RegistryError;
use crate::toml::{self, Document, Value};

const REGISTRY: &str = "foundation_dependencies.toml";
const LEDGER: &str = include_str!("../../../registries/foundation_dependencies.toml");

/// Upstream availability, classified from the Status cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Upstream {
    Live,
    Partial,
    Planned,
    Absent,
}

/// How FrankenAccounting consumes the capability today.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaStatus {
    /// Consumed as-is; no interim posture.
    Live,
    /// The registered interim posture holds until the switch-over rule fires.
    Interim,
    /// Upstream capability is usable (`Live` or `Partial`), but FrankenAccounting
    /// has no caller yet; `tracking` is required (`fa-r3d`).
    Unconsumed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    pub row: String,
    pub capability: String,
    /// Appendix H's Status cell, verbatim.
    pub status: String,
    pub posture: String,
    pub switch_over: String,
    pub foundation: String,
    pub upstream: Upstream,
    pub fa_status: FaStatus,
    pub tracking: Option<String>,
    pub consumed_apis: Vec<String>,
    pub unconsumed_apis: Vec<String>,
    pub conformance_tests: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ledger {
    pub capabilities: Vec<Capability>,
}

fn bad(message: impl Into<String>) -> RegistryError {
    RegistryError::Invalid {
        registry: REGISTRY,
        message: message.into(),
    }
}

fn str_list(row: &str, t: &toml::Table, key: &str) -> Result<Vec<String>, RegistryError> {
    let Some(val) = t.get(key) else {
        return Ok(Vec::new());
    };
    let arr = val
        .as_array()
        .ok_or_else(|| bad(format!("{row}: `{key}` must be a string array")))?;
    let mut out = Vec::with_capacity(arr.len());
    let mut seen = BTreeSet::new();
    for item in arr {
        let s = item
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| bad(format!("{row}: `{key}` must contain non-empty strings")))?;
        if !seen.insert(s.to_string()) {
            return Err(bad(format!("{row}: duplicate `{s}` in `{key}`")));
        }
        out.push(s.to_string());
    }
    Ok(out)
}

impl Ledger {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::parse(LEDGER)
    }

    pub fn parse(text: &str) -> Result<Self, RegistryError> {
        let doc = toml::parse(text).map_err(|error| RegistryError::Toml {
            registry: REGISTRY,
            error,
        })?;
        if doc.root.get("schema_version").and_then(Value::as_int) != Some(1) {
            return Err(bad("schema_version must be 1"));
        }
        let empty = Vec::new();
        let mut capabilities = Vec::new();
        let mut rows = BTreeSet::new();
        for t in doc.arrays.get("capability").unwrap_or(&empty) {
            let get = |key: &str| -> Result<String, RegistryError> {
                t.get(key)
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| bad(format!("capability row: missing string `{key}`")))
            };
            let row = get("row")?;
            let upstream = match get("upstream")?.as_str() {
                "live" => Upstream::Live,
                "partial" => Upstream::Partial,
                "planned" => Upstream::Planned,
                "absent" => Upstream::Absent,
                other => return Err(bad(format!("{row}: upstream `{other}` is not registered"))),
            };
            let fa_status = match get("fa_status")?.as_str() {
                "live" => FaStatus::Live,
                "interim" => FaStatus::Interim,
                "unconsumed" => FaStatus::Unconsumed,
                other => {
                    return Err(bad(format!(
                        "{row}: fa_status `{other}` is not live|interim|unconsumed"
                    )));
                }
            };
            let consumed_apis = str_list(&row, t, "consumed_apis")?;
            let unconsumed_apis = str_list(&row, t, "unconsumed_apis")?;
            let conformance_tests = str_list(&row, t, "conformance_tests")?;
            for api in &consumed_apis {
                if unconsumed_apis.contains(api) {
                    return Err(bad(format!(
                        "{row}: `{api}` cannot appear in both consumed_apis and unconsumed_apis"
                    )));
                }
            }
            let c = Capability {
                capability: get("capability")?,
                status: get("status")?,
                posture: get("posture")?,
                switch_over: get("switch_over")?,
                foundation: get("foundation")?,
                tracking: t
                    .get("tracking")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                upstream,
                fa_status,
                row,
                consumed_apis,
                unconsumed_apis,
                conformance_tests,
            };
            if matches!(c.upstream, Upstream::Planned | Upstream::Absent)
                && c.fa_status != FaStatus::Interim
            {
                return Err(bad(format!(
                    "{}: a capability that is not live upstream cannot be {:?} here",
                    c.row, c.fa_status
                )));
            }
            if c.fa_status == FaStatus::Interim
                && (c.switch_over.trim().is_empty() || c.switch_over.trim() == "—")
            {
                return Err(bad(format!(
                    "{}: an interim row names its switch-over rule",
                    c.row
                )));
            }
            if c.fa_status == FaStatus::Unconsumed {
                if c.tracking.as_deref().is_none_or(|s| s.trim().is_empty()) {
                    return Err(bad(format!(
                        "{}: an unconsumed row must name a `tracking` bead",
                        c.row
                    )));
                }
                if !c.consumed_apis.is_empty() {
                    return Err(bad(format!(
                        "{}: an unconsumed row cannot declare `consumed_apis`",
                        c.row
                    )));
                }
            }
            if c.row == "R-API"
                && (c.consumed_apis.is_empty()
                    || c.unconsumed_apis.is_empty()
                    || c.conformance_tests.is_empty())
            {
                return Err(bad(
                    "R-API must declare `consumed_apis`, `unconsumed_apis`, and `conformance_tests`",
                ));
            }
            if !rows.insert(c.row.clone()) {
                return Err(bad(format!("duplicate row `{}`", c.row)));
            }
            capabilities.push(c);
        }
        if capabilities.is_empty() {
            return Err(bad("no capability rows"));
        }
        Ok(Self { capabilities })
    }

    #[must_use]
    pub fn row(&self, id: &str) -> Option<&Capability> {
        self.capabilities.iter().find(|c| c.row == id)
    }
}

fn collect_rust_sources(dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<_> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            collect_rust_sources(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs")
            && let Ok(content) = std::fs::read_to_string(&path)
        {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.starts_with("//") {
                    out.push(trimmed.to_string());
                }
            }
        }
    }
}

/// Verify that every symbol in `consumed_apis` has at least one non-comment call/reference
/// in first-party `crates/` Rust sources, and every symbol in `unconsumed_apis` has zero (`fa-r3d`).
pub fn check_api_consumption(ledger: &Ledger, workspace_root: &Path) -> Result<(), RegistryError> {
    let crates_dir = workspace_root.join("crates");
    let mut code_lines = Vec::new();
    let Ok(crate_entries) = std::fs::read_dir(&crates_dir) else {
        return Err(bad(format!("cannot read {}", crates_dir.display())));
    };
    let mut crate_dirs: Vec<_> = crate_entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    crate_dirs.sort();
    for crate_dir in crate_dirs {
        if crate_dir.file_name().and_then(|s| s.to_str()) == Some("fa-registry") {
            continue;
        }
        collect_rust_sources(&crate_dir.join("src"), &mut code_lines);
        collect_rust_sources(&crate_dir.join("tests"), &mut code_lines);
    }

    for cap in &ledger.capabilities {
        for api in &cap.consumed_apis {
            let found = code_lines.iter().any(|l| l.contains(api.as_str()));
            if !found {
                return Err(bad(format!(
                    "{}: claims consumed API `{api}`, but no call site exists in crates/",
                    cap.row
                )));
            }
        }
        for api in &cap.unconsumed_apis {
            let found = code_lines.iter().any(|l| l.contains(api.as_str()));
            if found {
                return Err(bad(format!(
                    "{}: lists `{api}` in unconsumed_apis, but a call site exists in crates/",
                    cap.row
                )));
            }
        }
    }
    Ok(())
}

/// Verify that every test listed in `conformance_tests` exists in
/// `crates/fa-conformance/tests/substrate.rs`, and every `#[test]` in that file
/// is referenced by at least one capability row (`fa-zy1`).
pub fn check_conformance_tests(
    ledger: &Ledger,
    workspace_root: &Path,
) -> Result<(), RegistryError> {
    let suite_path = workspace_root.join("crates/fa-conformance/tests/substrate.rs");
    let Ok(content) = std::fs::read_to_string(&suite_path) else {
        return Err(bad(format!("cannot read {}", suite_path.display())));
    };
    let mut defined_tests = BTreeSet::new();
    let mut after_test_attr = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "#[test]" {
            after_test_attr = true;
            continue;
        }
        if after_test_attr && let Some(rest) = trimmed.strip_prefix("fn ") {
            if let Some(name) = rest.split('(').next() {
                defined_tests.insert(name.trim().to_string());
            }
            after_test_attr = false;
        } else if !trimmed.starts_with("#[") && !trimmed.starts_with("//") && !trimmed.is_empty() {
            after_test_attr = false;
        }
    }

    let mut referenced_tests = BTreeSet::new();
    for cap in &ledger.capabilities {
        for test_name in &cap.conformance_tests {
            if !defined_tests.contains(test_name.as_str()) {
                return Err(bad(format!(
                    "{}: claims conformance_test `{test_name}`, which does not exist in crates/fa-conformance/tests/substrate.rs",
                    cap.row
                )));
            }
            referenced_tests.insert(test_name.clone());
        }
    }

    for defined in &defined_tests {
        if !referenced_tests.contains(defined.as_str()) {
            return Err(bad(format!(
                "conformance test `{defined}` in crates/fa-conformance/tests/substrate.rs is not referenced by any capability row in foundation_dependencies.toml"
            )));
        }
    }
    Ok(())
}

/// Every `(crate, lock rev, Cargo.toml rev)` where a `franken-stack.lock`
/// foundation's revision differs from the workspace `Cargo.toml` pin of a
/// crate it ships. Crates the workspace does not pin are not compared.
pub fn pin_drift(lock: &Document, cargo_toml: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let empty = Vec::new();
    for f in lock.arrays.get("foundation").unwrap_or(&empty) {
        let Some(rev) = f.get("rev").and_then(Value::as_str) else {
            continue;
        };
        let name = f.get("name").and_then(Value::as_str).unwrap_or("");
        let mut crates: Vec<String> = f
            .get("crates")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if crates.is_empty() {
            crates.push(name.to_string());
        }
        for krate in crates {
            let prefix = format!("{krate} = {{");
            for line in cargo_toml.lines().filter(|l| l.starts_with(&prefix)) {
                let pinned = line
                    .split("rev = \"")
                    .nth(1)
                    .and_then(|r| r.split('"').next())
                    .unwrap_or("");
                if pinned != rev {
                    out.push((krate.clone(), rev.to_string(), pinned.to_string()));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAN: &str =
        include_str!("../../../COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md");
    const STACK_LOCK: &str = include_str!("../../../franken-stack.lock");
    const CARGO_TOML: &str = include_str!("../../../Cargo.toml");

    #[test]
    fn the_ledger_copies_appendix_h_verbatim() {
        let ledger = Ledger::embedded().expect("foundation_dependencies.toml validates");
        let rows: Vec<&str> = PLAN.lines().filter(|l| l.starts_with("| R-")).collect();
        assert_eq!(
            rows.len(),
            ledger.capabilities.len(),
            "one row per Appendix H row"
        );
        for (row, c) in rows.iter().zip(&ledger.capabilities) {
            let cells: Vec<&str> = row.split(" | ").map(str::trim).collect();
            assert_eq!(cells.len(), 5, "{row}");
            println!(
                "judged {}: {:?} upstream, {:?} here",
                c.row, c.upstream, c.fa_status
            );
            assert_eq!(cells[0].trim_start_matches('|').trim(), c.row);
            assert_eq!(cells[1], c.capability, "{}", c.row);
            assert_eq!(cells[2], c.status, "{}", c.row);
            assert_eq!(cells[3], c.posture, "{}", c.row);
            assert_eq!(
                cells[4].trim_end_matches('|').trim_end(),
                c.switch_over,
                "{}",
                c.row
            );
        }
    }

    #[test]
    fn foundations_are_locked_and_the_pins_do_not_drift() {
        let ledger = Ledger::embedded().unwrap();
        let lock = toml::parse(STACK_LOCK).expect("franken-stack.lock parses");
        let locked: BTreeSet<&str> = lock
            .arrays
            .get("foundation")
            .into_iter()
            .flatten()
            .filter_map(|f| f.get("name").and_then(Value::as_str))
            .collect();
        for c in &ledger.capabilities {
            println!("judged {}: foundation {}", c.row, c.foundation);
            assert!(
                locked.contains(c.foundation.as_str()),
                "{}: {}",
                c.row,
                c.foundation
            );
        }
        let drift = pin_drift(&lock, CARGO_TOML);
        assert!(drift.is_empty(), "lock vs Cargo.toml: {drift:?}");
        // The workspace pins fgdb and frankensympy crates, so the comparison
        // is not vacuous.
        assert!(CARGO_TOML.lines().any(|l| l.starts_with("fgdb = {")));
    }

    #[test]
    fn a_drifted_pin_is_reported() {
        let lock = toml::parse(STACK_LOCK).unwrap();
        let drifted = CARGO_TOML.replacen(
            "fgdb-crypto = { git = \"https://github.com/Dicklesworthstone/frankengraphdb\", rev = \"",
            "fgdb-crypto = { git = \"https://github.com/Dicklesworthstone/frankengraphdb\", rev = \"0000",
            1,
        );
        assert_ne!(drifted, CARGO_TOML, "the planted drift applied");
        let drift = pin_drift(&lock, &drifted);
        println!("judged planted drift: {drift:?}");
        assert_eq!(drift.len(), 1);
        assert_eq!(drift[0].0, "fgdb-crypto");
    }

    #[test]
    fn consumed_and_unconsumed_apis_match_actual_workspace_call_sites() {
        let ledger = Ledger::embedded().unwrap();
        assert_eq!(
            ledger.row("R-PRISM").unwrap().fa_status,
            FaStatus::Live
        );
        assert_eq!(ledger.row("R-SUB").unwrap().fa_status, FaStatus::Unconsumed);
        assert_eq!(ledger.row("R-SRV").unwrap().fa_status, FaStatus::Unconsumed);
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root");
        check_api_consumption(&ledger, root)
            .expect("all consumed/unconsumed API claims match crates/");
        check_conformance_tests(&ledger, root)
            .expect("all conformance_tests match crates/fa-conformance/tests/substrate.rs");

        // Planted negative 0: claiming a nonexistent conformance test must fail.
        let mut fake_conf = ledger.clone();
        fake_conf
            .capabilities
            .iter_mut()
            .find(|c| c.row == "R-API")
            .unwrap()
            .conformance_tests
            .push("nonexistent_conformance_test".to_string());
        let err0 = check_conformance_tests(&fake_conf, root)
            .expect_err("claiming nonexistent conformance test must fail");
        assert!(
            err0.to_string().contains("nonexistent_conformance_test"),
            "{err0}"
        );

        // Planted negative 1: claiming `bulk_load` is consumed when no crate calls it must fail.
        let mut fake_consumed = ledger.clone();
        let r_api = fake_consumed
            .capabilities
            .iter_mut()
            .find(|c| c.row == "R-API")
            .unwrap();
        r_api.unconsumed_apis.retain(|a| a != "bulk_load");
        r_api.consumed_apis.push("bulk_load".to_string());
        let err1 = check_api_consumption(&fake_consumed, root)
            .expect_err("claiming unconsumed API as consumed must fail");
        assert!(err1.to_string().contains("bulk_load"), "{err1}");

        // Planted negative 2: claiming `delta_since` is unconsumed when crates call it must fail.
        let mut fake_unconsumed = ledger.clone();
        let r_api2 = fake_unconsumed
            .capabilities
            .iter_mut()
            .find(|c| c.row == "R-API")
            .unwrap();
        r_api2.consumed_apis.retain(|a| a != "delta_since");
        r_api2.unconsumed_apis.push("delta_since".to_string());
        let err2 = check_api_consumption(&fake_unconsumed, root)
            .expect_err("claiming consumed API as unconsumed must fail");
        assert!(err2.to_string().contains("delta_since"), "{err2}");
    }

    #[test]
    fn broken_ledgers_are_refused() {
        let good = LEDGER;
        let planned_live = good.replacen(
            "upstream = \"planned\"\nfa_status = \"interim\"",
            "upstream = \"planned\"\nfa_status = \"live\"",
            1,
        );
        let unconsumed_without_tracking = good.replacen(
            "fa_status = \"unconsumed\"\ntracking = \"fa-z5u\"",
            "fa_status = \"unconsumed\"",
            1,
        );
        let cases = [
            ("planned capability marked live", planned_live),
            (
                "unconsumed capability without tracking bead",
                unconsumed_without_tracking,
            ),
            (
                "bad upstream",
                good.replacen("upstream = \"live\"", "upstream = \"soon\"", 1),
            ),
            (
                "duplicate row",
                good.replacen("row = \"R-API\"", "row = \"R-RATIONAL\"", 1),
            ),
        ];
        for (law, text) in cases {
            assert_ne!(text, good, "{law}: the planted change did not apply");
            let err = Ledger::parse(&text).expect_err(law);
            println!("judged planted `{law}`: refused ({err})");
        }
    }
}
