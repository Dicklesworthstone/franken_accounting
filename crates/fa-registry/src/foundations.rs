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
                other => {
                    return Err(bad(format!(
                        "{row}: fa_status `{other}` is not live|interim"
                    )));
                }
            };
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
            };
            if matches!(c.upstream, Upstream::Planned | Upstream::Absent)
                && c.fa_status != FaStatus::Interim
            {
                return Err(bad(format!(
                    "{}: a capability that is not live upstream cannot be live here",
                    c.row
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
    fn broken_ledgers_are_refused() {
        let good = LEDGER;
        let planned_live = good.replacen(
            "upstream = \"planned\"\nfa_status = \"interim\"",
            "upstream = \"planned\"\nfa_status = \"live\"",
            1,
        );
        let cases = [
            ("planned capability marked live", planned_live),
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
