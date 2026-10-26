//! `registries/workspace_topology.toml`: plan §18.1's crate layers as data
//! (bead fa-37f).
//!
//! The reader validates the registry itself — known layers, one row per
//! crate, allowlists that name rows — and its tests pin every row to the
//! plan's §18.1 table. Whether the actual cargo graph obeys the registry is
//! `scripts/check.sh` step `topology` (it reads `cargo metadata`), so the
//! library performs no I/O.

use std::collections::BTreeSet;

use crate::RegistryError;
use crate::toml::{self, Value};

const REGISTRY: &str = "workspace_topology.toml";
const TOPOLOGY: &str = include_str!("../../../registries/workspace_topology.toml");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrateRow {
    pub name: String,
    pub layer: String,
    pub path: String,
    /// Named by §18.1 but not created yet.
    pub planned: bool,
    /// The complete set of first-party crates this one may depend on, when
    /// registered (plan §18.1: fa-reference, fa-verify).
    pub allowlist: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Topology {
    /// Lowest first.
    pub layers: Vec<String>,
    pub crates: Vec<CrateRow>,
}

fn bad(message: impl Into<String>) -> RegistryError {
    RegistryError::Invalid {
        registry: REGISTRY,
        message: message.into(),
    }
}

fn str_list(v: &Value, what: &str) -> Result<Vec<String>, RegistryError> {
    v.as_array()
        .ok_or_else(|| bad(format!("{what} is not an array")))?
        .iter()
        .map(|x| {
            x.as_str()
                .map(str::to_string)
                .ok_or_else(|| bad(format!("{what} holds a non-string")))
        })
        .collect()
}

impl Topology {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::parse(TOPOLOGY)
    }

    pub fn parse(text: &str) -> Result<Self, RegistryError> {
        let doc = toml::parse(text).map_err(|error| RegistryError::Toml {
            registry: REGISTRY,
            error,
        })?;
        if doc.root.get("schema_version").and_then(Value::as_int) != Some(1) {
            return Err(bad("schema_version must be 1"));
        }
        let layers = str_list(
            doc.root
                .get("layers")
                .ok_or_else(|| bad("missing `layers`"))?,
            "layers",
        )?;
        let unique: BTreeSet<&String> = layers.iter().collect();
        if layers.is_empty() || unique.len() != layers.len() {
            return Err(bad("layers must be a non-empty list of distinct names"));
        }
        let mut crates = Vec::new();
        let empty = Vec::new();
        for t in doc.arrays.get("crate").unwrap_or(&empty) {
            let get = |key: &str| -> Result<String, RegistryError> {
                t.get(key)
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| bad(format!("crate row: missing string `{key}`")))
            };
            let name = get("name")?;
            let row = CrateRow {
                layer: get("layer")?,
                path: get("path")?,
                planned: t
                    .get("planned")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| bad(format!("{name}: missing boolean `planned`")))?,
                allowlist: t
                    .get("allowlist")
                    .map(|v| str_list(v, &format!("{name}.allowlist")))
                    .transpose()?,
                name,
            };
            if !layers.contains(&row.layer) {
                return Err(bad(format!("{}: unknown layer `{}`", row.name, row.layer)));
            }
            crates.push(row);
        }
        let mut names = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for c in &crates {
            if !names.insert(&c.name) || !paths.insert(&c.path) {
                return Err(bad(format!("duplicate crate row or path for `{}`", c.name)));
            }
        }
        for c in &crates {
            for a in c.allowlist.iter().flatten() {
                if !names.contains(a) || a == &c.name {
                    return Err(bad(format!(
                        "{}: allowlist names `{a}`, not another row",
                        c.name
                    )));
                }
            }
        }
        Ok(Self { layers, crates })
    }

    /// The layer's position, lowest first.
    #[must_use]
    pub fn rank(&self, layer: &str) -> Option<usize> {
        self.layers.iter().position(|l| l == layer)
    }

    #[must_use]
    pub fn row(&self, name: &str) -> Option<&CrateRow> {
        self.crates.iter().find(|c| c.name == name)
    }

    /// Whether `from` may depend on `to` through an edge of `kind` (`normal`,
    /// `build` or `dev`) under the layer order and any allowlist.
    #[must_use]
    pub fn edge_allowed(&self, from: &str, to: &str, kind: &str) -> bool {
        let (Some(f), Some(t)) = (self.row(from), self.row(to)) else {
            return false;
        };
        if let Some(allow) = &f.allowlist
            && !allow.contains(&t.name)
        {
            return false;
        }
        let (Some(fr), Some(tr)) = (self.rank(&f.layer), self.rank(&t.layer)) else {
            return false;
        };
        tr <= fr || (kind == "dev" && t.layer == "verification")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAN: &str =
        include_str!("../../../COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md");

    /// §18.1's table as (layer, crate names), read from the plan.
    fn plan_table() -> Vec<(String, Vec<String>)> {
        let section = PLAN
            .split("### 18.1 ")
            .nth(1)
            .and_then(|s| s.split("### 18.2 ").next())
            .expect("plan §18.1");
        let mut out = Vec::new();
        for line in section
            .lines()
            .filter(|l| l.starts_with("| ") && !l.starts_with("| Layer"))
        {
            let cells: Vec<&str> = line.split(" | ").collect();
            if cells.len() != 2 {
                continue;
            }
            let layer = cells[0].trim_start_matches('|').trim();
            let layer = layer
                .split(' ')
                .next()
                .unwrap_or(layer)
                .to_ascii_lowercase();
            out.push((layer, item_names(cells[1])));
        }
        out
    }

    /// The crate names of one §18.1 cell: the backticked tokens outside
    /// parentheses (a description may mention other crates).
    fn item_names(cell: &str) -> Vec<String> {
        let mut names = Vec::new();
        let mut depth = 0usize;
        let mut chars = cell.chars();
        while let Some(c) = chars.next() {
            match c {
                '(' => depth += 1,
                ')' => depth = depth.saturating_sub(1),
                '`' if depth == 0 => {
                    let token: String = chars.by_ref().take_while(|c| *c != '`').collect();
                    names.push(token.trim_start_matches("tools/").to_string());
                }
                _ => {}
            }
        }
        names
    }

    #[test]
    fn the_embedded_topology_is_lawful_and_pinned_to_plan_18_1() {
        let topo = Topology::embedded().expect("workspace_topology.toml validates");
        let table = plan_table();
        assert_eq!(
            topo.layers,
            table.iter().map(|(l, _)| l.clone()).collect::<Vec<_>>(),
            "layer order"
        );
        let mut expected = BTreeSet::new();
        for (layer, names) in &table {
            for name in names {
                let Some(row) = topo.row(name) else {
                    assert!(
                        topo.row(name).is_some(),
                        "no topology row for plan crate `{name}`"
                    );
                    continue;
                };
                println!("judged {name}: layer {} (plan: {layer})", row.layer);
                assert_eq!(&row.layer, layer, "{name}");
                expected.insert(name.clone());
            }
        }
        let rows: BTreeSet<String> = topo.crates.iter().map(|c| c.name.clone()).collect();
        assert_eq!(rows, expected, "rows are exactly the plan's crates");
        assert_eq!(
            topo.row("fa-verify").and_then(|r| r.allowlist.clone()),
            Some(Vec::new())
        );
        assert_eq!(
            topo.row("fa-reference").and_then(|r| r.allowlist.clone()),
            Some(vec!["fa-time".to_string(), "fa-registry".to_string()])
        );
    }

    #[test]
    fn edges_follow_the_layer_order_and_the_allowlists() {
        let topo = Topology::embedded().unwrap();
        let cases = [
            ("fa-journal", "fa-model", "normal", true),
            ("fa-model", "fa-journal", "normal", false),
            ("fa-policy", "fa-reference", "dev", true),
            ("fa-policy", "fa-reference", "normal", false),
            ("fa-notary", "fa-registers", "dev", true),
            ("fa-registry", "fa-cli", "dev", false),
            ("fa-reference", "fa-time", "normal", true),
            ("fa-reference", "fa-money", "normal", false),
            ("fa-verify", "fa-time", "dev", false),
            ("fa-cli", "fa", "normal", true),
            ("fa-mcp", "fa-verify", "dev", true),
            ("fa-mcp", "fa-verify", "normal", false),
            ("fa-mcp", "fa-verify", "build", false),
            ("fa-cli", "no-such-crate", "normal", false),
        ];
        for (from, to, kind, allowed) in cases {
            println!("judged {from} -> {to} ({kind}): {allowed}");
            assert_eq!(
                topo.edge_allowed(from, to, kind),
                allowed,
                "{from} -> {to} {kind}"
            );
        }
    }

    #[test]
    fn broken_topologies_are_refused() {
        let good = TOPOLOGY;
        let cases = [
            (
                "unknown layer",
                good.replacen("layer = \"model\"", "layer = \"middle\"", 1),
            ),
            (
                "duplicate row",
                good.replacen("name = \"fa-types\"", "name = \"fa-money\"", 1),
            ),
            (
                "allowlist names no row",
                good.replacen("allowlist = [\"fa-time\"", "allowlist = [\"fa-nope\"", 1),
            ),
            (
                "missing planned",
                good.replacen("\nplanned = true\n", "\nplanned_x = true\n", 1),
            ),
            (
                "empty layers",
                good.replacen("layers = [\"foundation\"", "layers_x = [\"foundation\"", 1),
            ),
        ];
        for (law, text) in cases {
            assert_ne!(text, good, "{law}: the planted change did not apply");
            let err = Topology::parse(&text).expect_err(law);
            println!("judged planted `{law}`: refused ({err})");
        }
    }
}
