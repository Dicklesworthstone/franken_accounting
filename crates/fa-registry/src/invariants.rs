//! `registries/invariants.toml`: the sixteen FA-INV ids of plan Appendix F and
//! their clauses (bead fa-37f).
//!
//! Hard rule (AGENTS.md): no subsystem ships against an unenforced invariant.
//! This registry is where "enforced" is written down per clause: a `live`
//! clause names the tests that check it and the tests that plant a violation;
//! a `dormant` clause names the bead whose landing activates it. The reader
//! refuses a registry that breaks the laws below, and `scripts/check.sh` step
//! `invariants` requires every live clause's tests to have run and passed in
//! the same gate run.
//!
//! Laws: the sixteen ids appear once each, in order; every invariant has at
//! least one clause; a live clause has an owner bead, at least one checker
//! and at least one negative, and no activating bead; a dormant clause names
//! one or more distinct activating beads and no checkers; every checker is
//! `crate::lib::path` or `crate::tests/<file>.rs::path`; dependencies name
//! existing clauses, form a DAG, and a live clause depends only on live
//! clauses (activation closure); `[gate_g1]` lists each clause whose
//! `first_gate` is G1, once, and no other; `waiver` is always `forbidden`.
//!
//! A dormant G1 clause is lawful: it blocks gate G1 and [`Invariants::g1_blockers`]
//! reports it. Refusing it would only invite dropping the clause from G1 to
//! make the registry parse, so the tests instead pin `[gate_g1]` to the
//! plan's Genesis clause set.
//!
//! The static half of the cross-check (each checker is a `#[test]` fn in the
//! file it names) runs in this module's tests; the runtime half is the gate.
//!
//! No-claim boundary: a resolved checker proves the test exists and (at the
//! gate) passed — not that it is sufficient for its clause.

use std::collections::{BTreeMap, BTreeSet};

use crate::RegistryError;
use crate::toml::{self, Table, Value};

const REGISTRY: &str = "invariants.toml";
const INVARIANTS: &str = include_str!("../../../registries/invariants.toml");

/// The sixteen ids, in order.
pub const INVARIANT_IDS: [&str; 16] = [
    "FA-INV-01",
    "FA-INV-02",
    "FA-INV-03",
    "FA-INV-04",
    "FA-INV-05",
    "FA-INV-06",
    "FA-INV-07",
    "FA-INV-08",
    "FA-INV-09",
    "FA-INV-10",
    "FA-INV-11",
    "FA-INV-12",
    "FA-INV-13",
    "FA-INV-14",
    "FA-INV-15",
    "FA-INV-16",
];

const EVIDENCE_CLASSES: [&str; 3] = ["invariant", "proof", "bounded_model"];
const GATES: [&str; 5] = ["G0", "G1", "G2", "G3", "G4"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invariant {
    pub id: String,
    pub name: String,
    /// Appendix F's Invariant cell, verbatim.
    pub statement: String,
    /// Appendix F's Enforcement cell, verbatim.
    pub enforcement: String,
}

/// Where a checker test lives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// The crate's library unit tests.
    Lib,
    /// An integration test file, `tests/<file>.rs`.
    Test(String),
}

/// A test entrypoint: `crate::target::path`, where `path` is the name libtest
/// prints for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checker {
    pub krate: String,
    pub target: Target,
    pub path: String,
}

impl Checker {
    pub fn parse(text: &str) -> Result<Self, String> {
        let (krate, rest) = text
            .split_once("::")
            .ok_or_else(|| format!("checker `{text}` is not `crate::target::path`"))?;
        let (target, path) = rest
            .split_once("::")
            .ok_or_else(|| format!("checker `{text}` is not `crate::target::path`"))?;
        let valid_crate = (krate == "fa" || krate.starts_with("fa-"))
            && krate
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !valid_crate {
            return Err(format!(
                "checker `{text}` names `{krate}`, not a first-party crate"
            ));
        }
        let target = match target {
            "lib" => Target::Lib,
            t => {
                let file = t
                    .strip_prefix("tests/")
                    .and_then(|f| f.strip_suffix(".rs"))
                    .filter(|f| is_ident(f))
                    .ok_or_else(|| {
                        format!("checker `{text}`: target must be `lib` or `tests/<file>.rs`")
                    })?;
                Target::Test(file.to_string())
            }
        };
        if path.is_empty() || !path.split("::").all(is_ident) {
            return Err(format!(
                "checker `{text}`: path must be `::`-separated identifiers"
            ));
        }
        Ok(Self {
            krate: krate.to_string(),
            target,
            path: path.to_string(),
        })
    }

    /// The test function's own name (the last path segment).
    #[must_use]
    pub fn fn_name(&self) -> &str {
        self.path.rsplit("::").next().unwrap_or(&self.path)
    }

    /// Candidate source files, relative to the workspace root, in which the
    /// test function must be defined.
    #[must_use]
    pub fn candidate_files(&self) -> Vec<String> {
        let base = format!("crates/{}", self.krate);
        match &self.target {
            Target::Test(file) => vec![format!("{base}/tests/{file}.rs")],
            Target::Lib => {
                // `a::b::tests::name` lives in src/a/b.rs, src/a/b/mod.rs,
                // src/a.rs or src/a/mod.rs, or for crate-root tests src/lib.rs.
                let segments: Vec<&str> = self.path.split("::").collect();
                let modules = &segments[..segments.len().saturating_sub(1)];
                let mut out = Vec::new();
                for k in (1..=modules.len()).rev() {
                    let dir = modules[..k].join("/");
                    out.push(format!("{base}/src/{dir}.rs"));
                    out.push(format!("{base}/src/{dir}/mod.rs"));
                }
                out.push(format!("{base}/src/lib.rs"));
                out
            }
        }
    }
}

impl core::fmt::Display for Checker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.target {
            Target::Lib => write!(f, "{}::lib::{}", self.krate, self.path),
            Target::Test(file) => write!(f, "{}::tests/{file}.rs::{}", self.krate, self.path),
        }
    }
}

fn is_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !s.starts_with(|c: char| c.is_ascii_digit())
}

fn is_bead(s: &str) -> bool {
    s.strip_prefix("fa-")
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Live {
        owner: String,
        checkers: Vec<Checker>,
        negatives: Vec<Checker>,
    },
    Dormant {
        /// The beads whose landing activates the clause.
        activating: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clause {
    pub invariant: String,
    pub id: String,
    pub statement: String,
    pub status: Status,
    pub evidence_class: String,
    pub first_gate: String,
    /// Full clause ids (`FA-INV-14.leaf-envelope`).
    pub depends: Vec<String>,
}

impl Clause {
    /// `FA-INV-NN.<clause>`.
    #[must_use]
    pub fn full_id(&self) -> String {
        format!("{}.{}", self.invariant, self.id)
    }

    #[must_use]
    pub fn is_live(&self) -> bool {
        matches!(self.status, Status::Live { .. })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invariants {
    pub invariants: Vec<Invariant>,
    pub clauses: Vec<Clause>,
    /// The clauses gate G1 requires live (those whose `first_gate` is G1).
    pub gate_g1: Vec<String>,
}

fn bad(message: impl Into<String>) -> RegistryError {
    RegistryError::Invalid {
        registry: REGISTRY,
        message: message.into(),
    }
}

fn s<'a>(t: &'a Table, key: &str, what: &str) -> Result<&'a str, RegistryError> {
    t.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| bad(format!("{what}: missing string `{key}`")))
}

fn strings(t: &Table, key: &str, what: &str) -> Result<Vec<String>, RegistryError> {
    match t.get(key) {
        None => Ok(Vec::new()),
        Some(v) => v
            .as_array()
            .ok_or_else(|| bad(format!("{what}: `{key}` is not an array")))?
            .iter()
            .map(|x| {
                x.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| bad(format!("{what}: `{key}` holds a non-string")))
            })
            .collect(),
    }
}

impl Invariants {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::parse(INVARIANTS)
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
        let mut invariants = Vec::new();
        for t in doc.arrays.get("invariant").unwrap_or(&empty) {
            invariants.push(Invariant {
                id: s(t, "id", "invariant")?.to_string(),
                name: s(t, "name", "invariant")?.to_string(),
                statement: s(t, "statement", "invariant")?.to_string(),
                enforcement: s(t, "enforcement", "invariant")?.to_string(),
            });
        }
        let ids: Vec<&str> = invariants.iter().map(|i| i.id.as_str()).collect();
        if ids != INVARIANT_IDS {
            return Err(bad(format!(
                "the invariant ids must be exactly FA-INV-01..16 in order, found {ids:?}"
            )));
        }

        let mut clauses = Vec::new();
        for t in doc.arrays.get("clause").unwrap_or(&empty) {
            clauses.push(Self::parse_clause(t)?);
        }
        let mut by_id: BTreeMap<String, &Clause> = BTreeMap::new();
        for c in &clauses {
            if !INVARIANT_IDS.contains(&c.invariant.as_str()) {
                return Err(bad(format!(
                    "clause `{}` names an unknown invariant",
                    c.full_id()
                )));
            }
            if by_id.insert(c.full_id(), c).is_some() {
                return Err(bad(format!("duplicate clause `{}`", c.full_id())));
            }
        }
        for id in INVARIANT_IDS {
            if !clauses.iter().any(|c| c.invariant == id) {
                return Err(bad(format!("{id} has no clause")));
            }
        }
        // Dependencies: existing clauses, acyclic, and the activation closure.
        for c in &clauses {
            for d in &c.depends {
                let Some(dep) = by_id.get(d) else {
                    return Err(bad(format!(
                        "`{}` depends on unknown clause `{d}`",
                        c.full_id()
                    )));
                };
                if c.is_live() && !dep.is_live() {
                    return Err(bad(format!(
                        "live clause `{}` depends on dormant clause `{d}` (activation closure)",
                        c.full_id()
                    )));
                }
            }
        }
        Self::acyclic(&clauses)?;

        let gate_g1 = match doc.tables.get("gate_g1") {
            Some(t) => strings(t, "clauses", "gate_g1")?,
            None => return Err(bad("missing [gate_g1]")),
        };
        let mut listed = BTreeSet::new();
        for g in &gate_g1 {
            match by_id.get(g) {
                None => return Err(bad(format!("gate_g1 names unknown clause `{g}`"))),
                Some(c) if c.first_gate != "G1" => {
                    return Err(bad(format!(
                        "gate_g1 lists `{g}`, whose first_gate is {}",
                        c.first_gate
                    )));
                }
                Some(_) => {}
            }
            if !listed.insert(g.as_str()) {
                return Err(bad(format!("gate_g1 lists `{g}` twice")));
            }
        }
        if let Some(missing) = clauses
            .iter()
            .find(|c| c.first_gate == "G1" && !listed.contains(c.full_id().as_str()))
        {
            return Err(bad(format!(
                "`{}` has first_gate G1 but gate_g1 does not list it",
                missing.full_id()
            )));
        }
        Ok(Self {
            invariants,
            clauses,
            gate_g1,
        })
    }

    fn parse_clause(t: &Table) -> Result<Clause, RegistryError> {
        let invariant = s(t, "invariant", "clause")?.to_string();
        let id = s(t, "id", "clause")?.to_string();
        let what = format!("{invariant}.{id}");
        let kebab = !id.is_empty()
            && id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !kebab {
            return Err(bad(format!("{what}: clause id must be kebab-case")));
        }
        let evidence_class = s(t, "evidence_class", &what)?.to_string();
        if !EVIDENCE_CLASSES.contains(&evidence_class.as_str()) {
            return Err(bad(format!(
                "{what}: evidence_class `{evidence_class}` is not registered"
            )));
        }
        let first_gate = s(t, "first_gate", &what)?.to_string();
        if !GATES.contains(&first_gate.as_str()) {
            return Err(bad(format!(
                "{what}: first_gate `{first_gate}` is not G0..G4"
            )));
        }
        if s(t, "waiver", &what)? != "forbidden" {
            return Err(bad(format!("{what}: waiver must be \"forbidden\"")));
        }
        let parse_all = |key: &str| -> Result<Vec<Checker>, RegistryError> {
            strings(t, key, &what)?
                .iter()
                .map(|c| Checker::parse(c).map_err(|e| bad(format!("{what}: {e}"))))
                .collect()
        };
        let checkers = parse_all("checkers")?;
        let negatives = parse_all("negatives")?;
        let status = match s(t, "status", &what)? {
            "live" => {
                let owner = s(t, "owner", &what)?.to_string();
                if !is_bead(&owner) {
                    return Err(bad(format!("{what}: owner `{owner}` is not a bead id")));
                }
                if checkers.is_empty() || negatives.is_empty() {
                    return Err(bad(format!(
                        "{what}: a live clause names at least one checker and one negative"
                    )));
                }
                if t.contains_key("activating") {
                    return Err(bad(format!("{what}: a live clause has no activating bead")));
                }
                Status::Live {
                    owner,
                    checkers,
                    negatives,
                }
            }
            "dormant" => {
                let activating = strings(t, "activating", &what)?;
                if activating.is_empty() {
                    return Err(bad(format!(
                        "{what}: a dormant clause names the beads that activate it"
                    )));
                }
                for (i, bead) in activating.iter().enumerate() {
                    if !is_bead(bead) || activating[..i].contains(bead) {
                        return Err(bad(format!(
                            "{what}: activating `{bead}` is not a distinct bead id"
                        )));
                    }
                }
                if !checkers.is_empty() || !negatives.is_empty() || t.contains_key("owner") {
                    return Err(bad(format!(
                        "{what}: a dormant clause names no checkers, negatives or owner"
                    )));
                }
                Status::Dormant { activating }
            }
            other => return Err(bad(format!("{what}: status `{other}` is not live|dormant"))),
        };
        Ok(Clause {
            statement: s(t, "statement", &what)?.to_string(),
            depends: strings(t, "depends", &what)?,
            invariant,
            id,
            status,
            evidence_class,
            first_gate,
        })
    }

    fn acyclic(clauses: &[Clause]) -> Result<(), RegistryError> {
        // Kahn's algorithm over depends edges.
        let mut indegree: BTreeMap<String, usize> =
            clauses.iter().map(|c| (c.full_id(), 0)).collect();
        for c in clauses {
            *indegree.entry(c.full_id()).or_default() += c.depends.len();
        }
        let mut ready: Vec<String> = indegree
            .iter()
            .filter(|(_, n)| **n == 0)
            .map(|(k, _)| k.clone())
            .collect();
        let mut done = BTreeSet::new();
        while let Some(id) = ready.pop() {
            done.insert(id.clone());
            for c in clauses.iter().filter(|c| c.depends.contains(&id)) {
                let n = indegree.entry(c.full_id()).or_default();
                *n -= 1;
                if *n == 0 {
                    ready.push(c.full_id());
                }
            }
        }
        if done.len() != clauses.len() {
            let cyclic: Vec<_> = clauses
                .iter()
                .map(Clause::full_id)
                .filter(|id| !done.contains(id))
                .collect();
            return Err(bad(format!(
                "clause dependencies form a cycle through {cyclic:?}"
            )));
        }
        Ok(())
    }

    /// The live clause ids, in registry order (what `fa capabilities --json`
    /// reports).
    #[must_use]
    pub fn live_clause_ids(&self) -> Vec<String> {
        self.clauses
            .iter()
            .filter(|c| c.is_live())
            .map(Clause::full_id)
            .collect()
    }

    #[must_use]
    pub fn clause(&self, full_id: &str) -> Option<&Clause> {
        self.clauses.iter().find(|c| c.full_id() == full_id)
    }

    /// The G1 clauses that are still dormant: gate G1 cannot pass while any
    /// remains.
    #[must_use]
    pub fn g1_blockers(&self) -> Vec<&Clause> {
        self.gate_g1
            .iter()
            .filter_map(|g| self.clause(g))
            .filter(|c| !c.is_live())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAN: &str =
        include_str!("../../../COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md");

    /// The checkers of `clauses` whose test function is not defined in any of
    /// its candidate files under `workspace_root`: `(clause, checker)` pairs.
    /// Reading source (test-only: no Cx-free I/O in the library) is the static half of the cross-check; the gate's
    /// `invariants` step is the runtime half (the test ran and passed).
    fn unresolved_checkers(
        clauses: &[Clause],
        workspace_root: &std::path::Path,
    ) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for c in clauses {
            let Status::Live {
                checkers,
                negatives,
                ..
            } = &c.status
            else {
                continue;
            };
            for checker in checkers.iter().chain(negatives) {
                let needle = format!("fn {}(", checker.fn_name());
                let found = checker.candidate_files().iter().any(|f| {
                    std::fs::read_to_string(workspace_root.join(f))
                        .is_ok_and(|text| has_test_fn(&text, &needle))
                });
                if !found {
                    out.push((c.full_id(), checker.to_string()));
                }
            }
        }
        out
    }

    /// Whether `text` defines `needle` (`fn name(`) as a `#[test]` function.
    fn has_test_fn(text: &str, needle: &str) -> bool {
        text.match_indices(needle).any(|(at, _)| {
            let before = &text[..at];
            // The attribute block directly above the fn must contain #[test].
            before
                .rsplit_once("\n\n")
                .map_or(before, |(_, tail)| tail)
                .contains("#[test]")
        })
    }

    fn root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn the_embedded_registry_is_total_and_lawful() {
        let reg = Invariants::embedded().expect("invariants.toml validates");
        assert_eq!(reg.invariants.len(), 16);
        for c in &reg.clauses {
            let state = match &c.status {
                Status::Live { .. } => "live".to_string(),
                Status::Dormant { activating } => {
                    format!("dormant until {}", activating.join(", "))
                }
            };
            println!("judged {}: {state}", c.full_id());
        }
        let live = reg.live_clause_ids();
        println!("{} clauses, {} live", reg.clauses.len(), live.len());
        assert!(!live.is_empty());
        let blockers: Vec<String> = reg.g1_blockers().iter().map(|c| c.full_id()).collect();
        println!(
            "G1 requires {} clauses; blocked by {blockers:?}",
            reg.gate_g1.len()
        );
    }

    /// The Genesis clause set in plan §19's Gate G1 paragraph, as written
    /// there (`FA-INV-01`, `03.core`, `14.leaf-and-consistency`, ...).
    fn plan_genesis_clause_set() -> Vec<&'static str> {
        let para = PLAN
            .lines()
            .find(|l| l.starts_with("**Gate G1 — "))
            .expect("plan §19 has a `**Gate G1 — ` paragraph");
        let (_, rest) = para
            .split_once("the Genesis clause set (")
            .expect("the Gate G1 paragraph names `the Genesis clause set (`");
        let (set, _) = rest.split_once(')').expect("the Genesis clause set closes");
        set.split(", ").collect()
    }

    /// `[gate_g1]` covers the plan's Genesis clause set: each named invariant
    /// has a G1 clause, and each named clause (`03.core`; `05.minimum`, which
    /// Appendix F tags `evidence-minimum`; `14.leaf-and-consistency`, two
    /// clauses) is in G1. Dropping a clause from G1 so that the registry
    /// reads green fails here.
    #[test]
    fn the_g1_list_covers_the_plans_genesis_clause_set() {
        let reg = Invariants::embedded().unwrap();
        let set = plan_genesis_clause_set();
        assert_eq!(set.len(), 13, "the Genesis clause set: {set:?}");
        for token in set {
            let token = token.trim_start_matches("FA-INV-");
            let (nn, suffix) = token.split_once('.').unwrap_or((token, ""));
            let inv = format!("FA-INV-{nn}");
            let g1: Vec<&Clause> = reg
                .gate_g1
                .iter()
                .filter_map(|g| reg.clause(g))
                .filter(|c| c.invariant == inv)
                .collect();
            assert!(
                !g1.is_empty(),
                "plan G1 names {inv}; gate_g1 has none of it"
            );
            if !suffix.is_empty() {
                for part in suffix.split("-and-") {
                    let named = |c: &&Clause| {
                        c.id == part
                            || c.id.starts_with(&format!("{part}-"))
                            || c.id.ends_with(&format!("-{part}"))
                    };
                    let hit = g1.iter().copied().find(named);
                    assert!(
                        hit.is_some(),
                        "plan G1 names {inv}.{part}; gate_g1 lacks it"
                    );
                    if let Some(hit) = hit {
                        println!("judged plan G1 `{token}`: {}", hit.full_id());
                    }
                }
            } else {
                println!("judged plan G1 `{token}`: {} clauses in G1", g1.len());
            }
        }
    }

    /// A blocked G1 is reported, not hidden.
    #[test]
    fn a_dormant_g1_clause_is_reported_as_blocking_g1() {
        let mut reg = Invariants::embedded().unwrap();
        let target = reg.gate_g1[0].clone();
        let before = reg.g1_blockers().len();
        let clause = reg
            .clauses
            .iter_mut()
            .find(|c| c.full_id() == target)
            .unwrap();
        assert!(clause.is_live(), "{target}");
        clause.status = Status::Dormant {
            activating: vec!["fa-37f".into()],
        };
        let blockers: Vec<String> = reg.g1_blockers().iter().map(|c| c.full_id()).collect();
        println!("judged {target}: made dormant, G1 blocked by {blockers:?}");
        assert_eq!(blockers.len(), before + 1);
        assert!(blockers.contains(&target));
    }

    /// The table "hash" of Appendix F: every row's Invariant and Enforcement
    /// cells equal the registry's, byte for byte. The rows are read under the
    /// Appendix F heading, so a moved heading or table fails here loudly.
    #[test]
    fn the_rows_copy_appendix_f_verbatim() {
        let reg = Invariants::embedded().unwrap();
        let heading = "\n## Appendix F — Invariant and Evidence Registries\n";
        let (_, appendix) = PLAN
            .split_once(heading)
            .expect("the plan has the Appendix F heading this test reads under");
        let appendix = appendix.split("\n## ").next().unwrap();
        let rows: Vec<&str> = appendix
            .lines()
            .filter(|l| l.starts_with("| FA-INV-"))
            .collect();
        assert_eq!(rows.len(), 16, "Appendix F has sixteen rows");
        assert_eq!(
            PLAN.matches("\n| FA-INV-").count(),
            16,
            "FA-INV rows exist outside Appendix F"
        );
        for (row, inv) in rows.iter().zip(&reg.invariants) {
            let cells: Vec<&str> = row.split(" | ").map(str::trim).collect();
            assert_eq!(cells.len(), 3, "{row}");
            println!("judged {}: Appendix F row copied", inv.id);
            assert_eq!(cells[0].trim_start_matches('|').trim(), inv.id);
            assert_eq!(cells[1], inv.statement, "{} statement", inv.id);
            assert_eq!(
                cells[2].trim_end_matches('|').trim_end(),
                inv.enforcement,
                "{} enforcement",
                inv.id
            );
        }
    }

    /// The static half of the cross-check: every live checker and negative is
    /// a `#[test]` fn in the file its `crate::target::path` names.
    #[test]
    fn every_live_checker_is_a_test_in_the_file_it_names() {
        let reg = Invariants::embedded().unwrap();
        let unresolved = unresolved_checkers(&reg.clauses, &root());
        for c in reg.clauses.iter().filter(|c| c.is_live()) {
            println!("judged {}: checkers resolved", c.full_id());
        }
        assert!(unresolved.is_empty(), "unresolved: {unresolved:#?}");
    }

    /// Planted negative for the static half: a renamed checker is reported.
    #[test]
    fn a_renamed_checker_does_not_resolve() {
        let reg = Invariants::embedded().unwrap();
        let mut clause = reg
            .clauses
            .iter()
            .find(|c| c.is_live())
            .cloned()
            .expect("a live clause");
        if let Status::Live { checkers, .. } = &mut clause.status {
            checkers[0].path.push_str("_renamed_by_test");
        }
        let unresolved = unresolved_checkers(std::slice::from_ref(&clause), &root());
        println!(
            "judged {}: renamed checker {unresolved:?}",
            clause.full_id()
        );
        assert_eq!(unresolved.len(), 1, "{unresolved:?}");
        assert!(unresolved[0].1.ends_with("_renamed_by_test"));
    }

    #[test]
    fn checker_names_parse_into_crate_target_and_path() {
        let c = Checker::parse("fa-model::lib::entry::tests::tampered_bytes_are_refused").unwrap();
        assert_eq!(c.krate, "fa-model");
        assert_eq!(c.target, Target::Lib);
        assert_eq!(c.fn_name(), "tampered_bytes_are_refused");
        assert_eq!(c.candidate_files()[0], "crates/fa-model/src/entry/tests.rs");
        assert!(
            c.candidate_files()
                .contains(&"crates/fa-model/src/entry.rs".to_string())
        );
        let t = Checker::parse("fa-journal::tests/genesis.rs::unbalanced").unwrap();
        assert_eq!(t.target, Target::Test("genesis".into()));
        assert_eq!(
            t.candidate_files(),
            vec!["crates/fa-journal/tests/genesis.rs".to_string()]
        );
        assert_eq!(t.to_string(), "fa-journal::tests/genesis.rs::unbalanced");
        for bad in [
            "fa-model::entry::x",
            "serde::lib::x",
            "fa-model::tests/a b.rs::x",
            "fa-model::lib::",
            "fa-model::lib::a-b",
            "no-separators",
        ] {
            assert!(Checker::parse(bad).is_err(), "{bad}");
        }
    }

    /// Each law refuses a registry that breaks it.
    #[test]
    fn broken_registries_are_refused_with_the_law_they_break() {
        let good = INVARIANTS;
        let first_live = "status = \"live\"";
        let cases: Vec<(&str, String)> = vec![
            (
                "fifteen ids",
                good.replacen("id = \"FA-INV-16\"", "id = \"FA-INV-99\"", 1),
            ),
            (
                "live without negatives",
                good.replacen("negatives = [", "negatives_x = [", 1),
            ),
            (
                "dormant without activating",
                good.replacen("activating = ", "activating_x = ", 1),
            ),
            (
                "dormant with no activating bead",
                good.replacen("activating = [\"fa-bvx\"]", "activating = []", 1),
            ),
            (
                "activating twice",
                good.replacen(
                    "activating = [\"fa-bvx\"]",
                    "activating = [\"fa-bvx\", \"fa-bvx\"]",
                    1,
                ),
            ),
            (
                "G1 drops a G1 clause",
                good.replacen("\"FA-INV-11.core\", ", "", 1),
            ),
            (
                "G1 lists a G2 clause",
                good.replacen(
                    "\"FA-INV-16.core\"]",
                    "\"FA-INV-16.core\", \"FA-INV-08.reversal\"]",
                    1,
                ),
            ),
            (
                "G1 lists a clause twice",
                good.replacen(
                    "\"FA-INV-16.core\"]",
                    "\"FA-INV-16.core\", \"FA-INV-16.core\"]",
                    1,
                ),
            ),
            (
                "waiver",
                good.replacen("\nwaiver = \"forbidden\"", "\nwaiver = \"granted\"", 1),
            ),
            (
                "unknown dependency",
                good.replacen("depends = [\"", "depends = [\"FA-INV-01.nope\", \"", 1),
            ),
            (
                "bad evidence class",
                good.replacen(
                    "evidence_class = \"invariant\"",
                    "evidence_class = \"vibes\"",
                    1,
                ),
            ),
            (
                "bad checker",
                good.replacen(
                    "checkers = [\"fa-",
                    "checkers = [\"serde::lib::x\", \"fa-",
                    1,
                ),
            ),
            (
                "bad status",
                good.replacen(first_live, "status = \"maybe\"", 1),
            ),
        ];
        for (law, text) in cases {
            assert_ne!(text, good, "{law}: the planted change did not apply");
            let err = Invariants::parse(&text).expect_err(law);
            println!("judged planted `{law}`: refused ({err})");
        }
    }

    #[test]
    fn the_activation_closure_and_the_dag_are_enforced() {
        let reg = Invariants::embedded().unwrap();
        // A live clause that depends on a dormant one breaks the closure.
        let live = reg.clauses.iter().find(|c| c.is_live()).unwrap().full_id();
        let dormant = reg.clauses.iter().find(|c| !c.is_live()).unwrap().full_id();
        let mut clauses = reg.clauses.clone();
        let text = INVARIANTS.to_string();
        let (inv, id) = live.split_once('.').unwrap();
        let anchor = format!("invariant = \"{inv}\"\nid = \"{id}\"\n");
        assert!(text.contains(&anchor));
        let planted = text.replacen(&anchor, &format!("{anchor}depends = [\"{dormant}\"]\n"), 1);
        let err = Invariants::parse(&planted).expect_err("closure");
        println!("judged {live}: depending on {dormant} refused ({err})");
        // A cycle is refused even among dormant clauses.
        let a = clauses[0].full_id();
        let b = clauses[1].full_id();
        clauses[0].depends = vec![b.clone()];
        clauses[1].depends = vec![a.clone()];
        assert!(Invariants::acyclic(&clauses).is_err(), "{a} <-> {b}");
    }
}
