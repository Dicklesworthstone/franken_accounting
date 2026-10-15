//! `registries/mutants.toml` — named source mutations of kernel laws and
//! deterministic mutation-lane evaluation (plan §16, bead `fa-9km9`).
//!
//! Each `[[mutant]]` entry defines an exact, single-occurrence source patch
//! (`file`, `find`, `replace`), the broken accounting/verification `law`
//! (`FA-INV-*` or `FA-REF-*`), and the `killed_by` test entrypoints that must
//! fail when the mutation is applied in a scratch copy.

use std::collections::BTreeSet;

use crate::invariants::{Checker, Invariants};
use crate::refusal_catalog::RefusalCatalog;
use crate::toml::{self, Table, Value};
use crate::{RegistryError, invalid};

const REGISTRY: &str = "mutants.toml";
const MUTANTS: &str = include_str!("../../../registries/mutants.toml");

/// Minimum number of named kernel-law mutations required by bead `fa-9km9`.
pub const MIN_MUTANTS: usize = 30;

/// One named source mutation in `registries/mutants.toml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mutant {
    pub id: String,
    pub file: String,
    pub find: String,
    pub replace: String,
    pub law: String,
    pub killed_by: Vec<Checker>,
    pub description: String,
}

impl Mutant {
    /// Applies the mutation in-memory, verifying `find` appears **exactly once**
    /// in `source_text` and that the replacement alters the source.
    pub fn apply_in_memory(&self, source_text: &str) -> Result<String, String> {
        let count = source_text.matches(&self.find).count();
        if count == 0 {
            return Err(format!(
                "{REGISTRY}: {} `find` snippet not found in `{}`",
                self.id, self.file
            ));
        }
        if count > 1 {
            return Err(format!(
                "{REGISTRY}: {} `find` snippet is ambiguous ({count} matches) in `{}`",
                self.id, self.file
            ));
        }
        let mutated = source_text.replacen(&self.find, &self.replace, 1);
        if mutated == source_text {
            return Err(format!(
                "{REGISTRY}: {} replacement produced identical source in `{}`",
                self.id, self.file
            ));
        }
        Ok(mutated)
    }
}

/// Outcome of running a `killed_by` test against a mutated source tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestOutcome {
    /// The test failed as required, killing the mutant.
    Killed,
    /// The test unexpectedly passed, leaving the mutant alive.
    Survived,
}

impl TestOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Killed => "killed",
            Self::Survived => "survived",
        }
    }
}

/// Per-mutant evaluation record in a [`MutationManifest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutantVerdict {
    pub id: String,
    pub file: String,
    pub law: String,
    pub killed_by: Vec<String>,
    pub outcome: TestOutcome,
}

/// Deterministic JSON/text manifest emitted by the mutation lane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutationManifest {
    pub schema_version: u32,
    pub total: usize,
    pub killed: usize,
    pub survivors: Vec<String>,
    pub verdicts: Vec<MutantVerdict>,
}

impl MutationManifest {
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.survivors.is_empty() && self.killed == self.total
    }

    #[must_use]
    pub fn to_json(&self) -> String {
        let status = if self.is_green() { "ok" } else { "fail" };
        let survivors_json: Vec<String> = self
            .survivors
            .iter()
            .map(|s| format!("\"{}\"", escape_json(s)))
            .collect();
        let verdicts_json: Vec<String> = self
            .verdicts
            .iter()
            .map(|v| {
                let tests: Vec<String> = v
                    .killed_by
                    .iter()
                    .map(|t| format!("\"{}\"", escape_json(t)))
                    .collect();
                format!(
                    "{{\"id\":\"{}\",\"file\":\"{}\",\"law\":\"{}\",\"outcome\":\"{}\",\"killed_by\":[{}]}}",
                    escape_json(&v.id),
                    escape_json(&v.file),
                    escape_json(&v.law),
                    v.outcome.as_str(),
                    tests.join(",")
                )
            })
            .collect();
        format!(
            "{{\"event\":\"mutation_manifest\",\"status\":\"{status}\",\"schema_version\":{},\"total\":{},\"killed\":{},\"survivors\":[{}],\"verdicts\":[{}]}}",
            self.schema_version,
            self.total,
            self.killed,
            survivors_json.join(","),
            verdicts_json.join(",")
        )
    }
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

/// Parsed and validated `registries/mutants.toml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutantLedger {
    pub schema_version: u32,
    pub mutants: Vec<Mutant>,
}

fn req_str<'a>(t: &'a Table, key: &str, ctx: &str) -> Result<&'a str, RegistryError> {
    t.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| invalid(REGISTRY, format!("{ctx}: missing or empty string `{key}`")))
}

fn req_str_list(t: &Table, key: &str, ctx: &str) -> Result<Vec<String>, RegistryError> {
    let arr = t
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(REGISTRY, format!("{ctx}: missing array `{key}`")))?;
    if arr.is_empty() {
        return Err(invalid(
            REGISTRY,
            format!("{ctx}: `{key}` must not be empty"),
        ));
    }
    arr.iter()
        .map(|v| {
            v.as_str()
                .filter(|s| !s.trim().is_empty())
                .map(str::to_string)
                .ok_or_else(|| invalid(REGISTRY, format!("{ctx}: `{key}` contains non-string")))
        })
        .collect()
}

impl MutantLedger {
    pub fn embedded() -> Result<Self, RegistryError> {
        let invariants = Invariants::embedded()?;
        let refusals = RefusalCatalog::embedded()?;
        Self::parse(MUTANTS, &invariants, &refusals)
    }

    pub fn parse(
        text: &str,
        invariants: &Invariants,
        refusals: &RefusalCatalog,
    ) -> Result<Self, RegistryError> {
        let doc = toml::parse(text).map_err(|error| RegistryError::Toml {
            registry: REGISTRY,
            error,
        })?;
        let sv = doc
            .root
            .get("schema_version")
            .and_then(Value::as_int)
            .ok_or_else(|| invalid(REGISTRY, "missing schema_version"))?;
        if sv != 1 {
            return Err(invalid(
                REGISTRY,
                format!("schema_version must be 1, got {sv}"),
            ));
        }

        let valid_laws: BTreeSet<String> = invariants
            .invariants
            .iter()
            .map(|i| i.id.clone())
            .chain(
                invariants
                    .clauses
                    .iter()
                    .map(crate::invariants::Clause::full_id),
            )
            .chain(refusals.rows.iter().map(|r| r.code.clone()))
            .collect();

        let rows = doc
            .arrays
            .get("mutant")
            .ok_or_else(|| invalid(REGISTRY, "missing [[mutant]] array"))?;
        if rows.len() < MIN_MUTANTS {
            return Err(invalid(
                REGISTRY,
                format!(
                    "expected at least {MIN_MUTANTS} [[mutant]] rows, found {}",
                    rows.len()
                ),
            ));
        }

        let mut mutants = Vec::with_capacity(rows.len());
        for (idx, row) in rows.iter().enumerate() {
            let expected_id = format!("MUT-{:03}", idx + 1);
            let id = req_str(row, "id", &expected_id)?.to_string();
            if id != expected_id {
                return Err(invalid(
                    REGISTRY,
                    format!(
                        "mutant #{}: expected dense id `{expected_id}`, got `{id}`",
                        idx + 1
                    ),
                ));
            }
            let file = req_str(row, "file", &id)?.to_string();
            if !file.starts_with("crates/") || !file.ends_with(".rs") || file.contains("..") {
                return Err(invalid(
                    REGISTRY,
                    format!("{id}: `file` must be a `crates/.../*.rs` path, got `{file}`"),
                ));
            }
            let find = req_str(row, "find", &id)?.to_string();
            let replace = req_str(row, "replace", &id)?.to_string();
            if find == replace {
                return Err(invalid(
                    REGISTRY,
                    format!("{id}: `find` and `replace` must differ"),
                ));
            }
            let law = req_str(row, "law", &id)?.to_string();
            if !valid_laws.contains(&law) {
                return Err(invalid(
                    REGISTRY,
                    format!(
                        "{id}: unknown law `{law}` (not in invariants.toml or refusal_catalog.toml)"
                    ),
                ));
            }
            let description = req_str(row, "description", &id)?.to_string();
            let raw_killed_by = req_str_list(row, "killed_by", &id)?;
            let mut seen_checkers = BTreeSet::new();
            let mut killed_by = Vec::with_capacity(raw_killed_by.len());
            for entry in raw_killed_by {
                if !seen_checkers.insert(entry.clone()) {
                    return Err(invalid(
                        REGISTRY,
                        format!("{id}: duplicate `killed_by` entry `{entry}`"),
                    ));
                }
                let checker = Checker::parse(&entry)
                    .map_err(|msg| invalid(REGISTRY, format!("{id}: {msg}")))?;
                killed_by.push(checker);
            }

            mutants.push(Mutant {
                id,
                file,
                find,
                replace,
                law,
                killed_by,
                description,
            });
        }

        Ok(Self {
            schema_version: 1,
            mutants,
        })
    }

    /// Verifies against workspace source files that:
    /// 1. Every mutant's target `file` exists and `find` appears **exactly once**.
    /// 2. In-memory replacement succeeds and alters the source text.
    /// 3. Every `killed_by` test entrypoint is defined as a `#[test]` function in
    ///    its target crate/file.
    pub fn verify_against_workspace<F>(&self, read_file: F) -> Result<(), String>
    where
        F: Fn(&str) -> Option<String>,
    {
        for mutant in &self.mutants {
            let source = read_file(&mutant.file).ok_or_else(|| {
                format!(
                    "{REGISTRY}: {} target file `{}` does not exist",
                    mutant.id, mutant.file
                )
            })?;
            mutant.apply_in_memory(&source)?;

            for checker in &mutant.killed_by {
                let resolved = checker
                    .candidate_files()
                    .into_iter()
                    .filter_map(|rel| read_file(&rel))
                    .any(|text| checker.is_defined_in(&text));
                if !resolved {
                    return Err(format!(
                        "{REGISTRY}: {} references nonexistent `#[test]` `{checker}`",
                        mutant.id
                    ));
                }
            }
        }
        Ok(())
    }

    /// Evaluates the mutation lane using `runner` to determine whether each
    /// mutant's `killed_by` tests kill the mutation.
    ///
    /// A mutant is considered `Killed` only if **every** listed `killed_by`
    /// test fails (`TestOutcome::Killed`) when the mutation is active. If any
    /// `killed_by` test passes (`TestOutcome::Survived`), the mutant is
    /// recorded in `survivors`.
    pub fn evaluate_lane<R>(&self, mut runner: R) -> MutationManifest
    where
        R: FnMut(&Mutant, &Checker) -> TestOutcome,
    {
        let mut killed = 0usize;
        let mut survivors = Vec::new();
        let mut verdicts = Vec::with_capacity(self.mutants.len());

        for mutant in &self.mutants {
            let mut all_killed = true;
            for checker in &mutant.killed_by {
                if runner(mutant, checker) == TestOutcome::Survived {
                    all_killed = false;
                }
            }
            let outcome = if all_killed {
                killed += 1;
                TestOutcome::Killed
            } else {
                survivors.push(mutant.id.clone());
                TestOutcome::Survived
            };
            verdicts.push(MutantVerdict {
                id: mutant.id.clone(),
                file: mutant.file.clone(),
                law: mutant.law.clone(),
                killed_by: mutant.killed_by.iter().map(ToString::to_string).collect(),
                outcome,
            });
        }

        MutationManifest {
            schema_version: self.schema_version,
            total: self.mutants.len(),
            killed,
            survivors,
            verdicts,
        }
    }

    /// Runs `evaluate_lane` and fails if any mutant survives.
    pub fn enforce_lane<R>(&self, runner: R) -> Result<MutationManifest, String>
    where
        R: FnMut(&Mutant, &Checker) -> TestOutcome,
    {
        let manifest = self.evaluate_lane(runner);
        if !manifest.is_green() {
            return Err(format!(
                "{REGISTRY}: {} of {} mutant(s) survived: {}",
                manifest.survivors.len(),
                manifest.total,
                manifest.survivors.join(", ")
            ));
        }
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root")
            .to_path_buf()
    }

    #[test]
    fn embedded_mutant_ledger_parses_and_resolves_against_workspace() {
        let ledger = MutantLedger::embedded().expect("mutants.toml must parse");
        assert!(
            ledger.mutants.len() >= MIN_MUTANTS,
            "expected >= {MIN_MUTANTS} mutants, got {}",
            ledger.mutants.len()
        );
        let root = workspace_root();
        ledger
            .verify_against_workspace(|rel| fs::read_to_string(root.join(rel)).ok())
            .expect("all mutant files, single-match snippets, and killed_by tests must resolve");

        let manifest = ledger
            .enforce_lane(|_mutant, _checker| TestOutcome::Killed)
            .expect("all killed lane must pass");
        assert!(manifest.is_green());
        assert_eq!(manifest.total, ledger.mutants.len());
        assert_eq!(manifest.killed, ledger.mutants.len());
        assert!(manifest.survivors.is_empty());
        let json = manifest.to_json();
        assert!(json.contains("\"event\":\"mutation_manifest\""));
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"survivors\":[]"));
    }

    #[test]
    fn planted_always_passing_test_reports_surviving_mutant_and_fails_lane() {
        let ledger = MutantLedger::embedded().expect("mutants.toml");
        // Planted negative (fa-9km9): a test that always passes (`Survived`)
        // on MUT-010 must be reported as a surviving mutant and fail the lane.
        let manifest = ledger.evaluate_lane(|mutant, _checker| {
            if mutant.id == "MUT-010" {
                TestOutcome::Survived
            } else {
                TestOutcome::Killed
            }
        });
        assert!(!manifest.is_green());
        assert_eq!(manifest.survivors, vec!["MUT-010".to_string()]);
        assert_eq!(manifest.killed, manifest.total - 1);
        let json = manifest.to_json();
        assert!(json.contains("\"status\":\"fail\""));
        assert!(json.contains("\"survivors\":[\"MUT-010\"]"));

        let err = ledger
            .enforce_lane(|mutant, _checker| {
                if mutant.id == "MUT-010" {
                    TestOutcome::Survived
                } else {
                    TestOutcome::Killed
                }
            })
            .expect_err("surviving mutant must fail enforce_lane");
        assert!(
            err.contains("1 of") && err.contains("MUT-010"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn planted_ambiguous_or_missing_find_and_bad_foreign_keys_are_refused() {
        let ledger = MutantLedger::embedded().expect("mutants.toml");
        let first = &ledger.mutants[0];
        // Missing snippet fails.
        let err = first
            .apply_in_memory("fn unrelated() {}")
            .expect_err("missing find snippet must fail");
        assert!(err.contains("not found"), "{err}");

        // Ambiguous (duplicate) snippet fails.
        let dup_source = format!("{}\n{}", first.find, first.find);
        let err = first
            .apply_in_memory(&dup_source)
            .expect_err("duplicate find snippet must fail");
        assert!(err.contains("ambiguous (2 matches)"), "{err}");

        // Broken law foreign key fails parse.
        let invariants = Invariants::embedded().expect("invariants");
        let refusals = RefusalCatalog::embedded().expect("refusals");
        let bad_law = MUTANTS.replacen(
            "law = \"FA-INV-06.core\"",
            "law = \"FA-INV-99.nonexistent\"",
            1,
        );
        let err = MutantLedger::parse(&bad_law, &invariants, &refusals)
            .expect_err("unknown law must fail")
            .to_string();
        assert!(err.contains("FA-INV-99.nonexistent"), "{err}");

        // Nonexistent killed_by test fails workspace verification.
        let root = workspace_root();
        let bad_test = MUTANTS.replacen(
            "fa-money::lib::amount::tests::checked_arithmetic_refuses_overflow_and_unit_mixing",
            "fa-money::lib::amount::tests::nonexistent_planted_test_name",
            1,
        );
        let parsed =
            MutantLedger::parse(&bad_test, &invariants, &refusals).expect("syntax is valid");
        let err = parsed
            .verify_against_workspace(|rel| fs::read_to_string(root.join(rel)).ok())
            .expect_err("nonexistent test must fail workspace check");
        assert!(
            err.contains("MUT-001") && err.contains("nonexistent_planted_test_name"),
            "{err}"
        );
    }
}
