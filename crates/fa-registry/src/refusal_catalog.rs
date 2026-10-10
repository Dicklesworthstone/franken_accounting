//! `registries/refusal_catalog.toml`: every typed refusal, one row per
//! `FA-REF` code (plan §15.3, Appendix D): its constant name, the crates that
//! declare it, its single exit class, the law or policy it cites, and the
//! fix template its text follows.
//!
//! The catalog is checked against the code, not trusted: this module's gate
//! test reads every `crates/*/src` file, collects each `FA-REF` constant and
//! each literal `code::NAME, exit::CLASS` call site, and fails when a
//! constant has no row, a row has no constant (or other owners), one code is
//! declared under two names, a reserved code is declared, or a call site
//! uses another exit than the row's.

use std::collections::BTreeSet;

use crate::toml::Value;
use crate::{ExitCodes, RegistryError, invalid, load, req_int, req_str};

const REFUSAL_CATALOG: &str = include_str!("../../../registries/refusal_catalog.toml");
const R: &str = "refusal_catalog.toml";

/// One refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefusalRow {
    /// `FA-REF-nnn`.
    pub code: String,
    /// The constant's name in every crate that declares the code.
    pub name: String,
    /// The crates that declare the code (oracle mirrors excluded).
    pub owners: Vec<String>,
    /// The exit class's registered name and code.
    pub exit_name: String,
    pub exit: u8,
    pub cite: String,
    pub fix: String,
}

/// A code held for a named owner until its row replaces the reservation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reserved {
    pub code: String,
    pub holder: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefusalCatalog {
    pub rows: Vec<RefusalRow>,
    pub reserved: Vec<Reserved>,
}

fn is_code(s: &str) -> bool {
    s.strip_prefix("FA-REF-")
        .is_some_and(|d| d.len() == 3 && d.bytes().all(|b| b.is_ascii_digit()))
}

fn req_text(t: &crate::toml::Table, key: &str, row: &str) -> Result<String, RegistryError> {
    let s = req_str(R, t, key)?;
    if s.trim().is_empty() {
        return Err(invalid(R, format!("{row}: `{key}` is empty")));
    }
    Ok(s.to_string())
}

impl RefusalCatalog {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::from_text(REFUSAL_CATALOG, &ExitCodes::embedded()?)
    }

    pub fn from_text(text: &str, exits: &ExitCodes) -> Result<Self, RegistryError> {
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        let empty = Vec::new();
        let mut codes = BTreeSet::new();
        let mut reserved = Vec::new();
        for t in doc.arrays.get("reserved").unwrap_or(&empty) {
            let code = req_str(R, t, "code")?.to_string();
            if !is_code(&code) || !codes.insert(code.clone()) {
                return Err(invalid(
                    R,
                    format!("reserved `{code}` is malformed or duplicated"),
                ));
            }
            reserved.push(Reserved {
                holder: req_text(t, "holder", &code)?,
                code,
            });
        }
        let mut names = BTreeSet::new();
        let mut rows = Vec::new();
        for t in doc.arrays.get("refusal").unwrap_or(&empty) {
            let code = req_str(R, t, "code")?.to_string();
            if !is_code(&code) {
                return Err(invalid(R, format!("`{code}` is not FA-REF-nnn")));
            }
            if !codes.insert(code.clone()) {
                return Err(invalid(
                    R,
                    format!("`{code}` has two rows (or is reserved)"),
                ));
            }
            let name = req_text(t, "name", &code)?;
            if !names.insert(name.clone()) {
                return Err(invalid(R, format!("`{name}` names two codes")));
            }
            let owners: Vec<String> = match t.get("owners") {
                Some(Value::Array(items)) if !items.is_empty() => items
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .map(str::to_string)
                            .ok_or_else(|| invalid(R, format!("{code}: owners are crate names")))
                    })
                    .collect::<Result<_, _>>()?,
                _ => return Err(invalid(R, format!("{code}: owners is a non-empty list"))),
            };
            let exit_name = req_text(t, "exit", &code)?;
            let exit = exits.code(&exit_name).filter(|e| *e >= 2).ok_or_else(|| {
                invalid(
                    R,
                    format!("{code}: exit `{exit_name}` is not a failure class in exit_codes.toml"),
                )
            })?;
            rows.push(RefusalRow {
                cite: req_text(t, "cite", &code)?,
                fix: req_text(t, "fix", &code)?,
                code,
                name,
                owners,
                exit_name,
                exit,
            });
        }
        if rows.is_empty() {
            return Err(invalid(R, "no refusals"));
        }
        Ok(Self { rows, reserved })
    }

    #[must_use]
    pub fn by_code(&self, code: &str) -> Option<&RefusalRow> {
        self.rows.iter().find(|r| r.code == code)
    }

    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&RefusalRow> {
        self.rows.iter().find(|r| r.name == name)
    }
}

/// The crate whose `FA-REF` constants mirror the kernel's on purpose (the
/// reference oracle keeps its own copy so agreement is evidence): its
/// declarations must match a row's name but never make it an owner.
pub const ORACLE_CRATE: &str = "fa-reference";

/// One `const NAME: &str = "FA-REF-nnn";` in a crate's sources.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declaration {
    pub krate: String,
    pub name: String,
    pub code: String,
}

/// One literal `code::NAME, exit::CLASS` call site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site {
    pub krate: String,
    pub name: String,
    /// The exit constant's name, lowercased (`refusal`, `usage`, …).
    pub exit: String,
}

/// Every disagreement between the catalog and the declared code, as
/// readable lines; empty when they agree.
#[must_use]
pub fn audit(catalog: &RefusalCatalog, decls: &[Declaration], sites: &[Site]) -> Vec<String> {
    let mut out = Vec::new();
    // A code means one thing: one constant name across the workspace.
    let mut by_code: std::collections::BTreeMap<&str, BTreeSet<&str>> = Default::default();
    for d in decls {
        by_code.entry(&d.code).or_default().insert(&d.name);
    }
    for (code, names) in &by_code {
        if names.len() > 1 {
            out.push(format!(
                "{code} is declared under {} names: {names:?}",
                names.len()
            ));
        }
    }
    for d in decls {
        if catalog.reserved.iter().any(|r| r.code == d.code) {
            out.push(format!(
                "{}::{} declares reserved {}",
                d.krate, d.name, d.code
            ));
            continue;
        }
        match catalog.by_code(&d.code) {
            None => out.push(format!(
                "{}::{} = {} has no catalog row",
                d.krate, d.name, d.code
            )),
            Some(row) if row.name != d.name => out.push(format!(
                "{}::{} = {} but the row names it `{}`",
                d.krate, d.name, d.code, row.name
            )),
            Some(row) if d.krate != ORACLE_CRATE && !row.owners.contains(&d.krate) => {
                out.push(format!(
                    "{} declares {} but is not among its owners {:?}",
                    d.krate, d.code, row.owners
                ))
            }
            Some(_) => {}
        }
    }
    for row in &catalog.rows {
        let declared: BTreeSet<&str> = decls
            .iter()
            .filter(|d| d.code == row.code && d.krate != ORACLE_CRATE)
            .map(|d| d.krate.as_str())
            .collect();
        let owners: BTreeSet<&str> = row.owners.iter().map(String::as_str).collect();
        if declared != owners {
            out.push(format!(
                "{} lists owners {owners:?} but is declared by {declared:?}",
                row.code
            ));
        }
    }
    for s in sites.iter().filter(|s| s.krate != ORACLE_CRATE) {
        let Some(d) = decls
            .iter()
            .find(|d| d.krate == s.krate && d.name == s.name)
            .or_else(|| {
                decls
                    .iter()
                    .find(|d| d.name == s.name && d.krate != ORACLE_CRATE)
            })
        else {
            continue;
        };
        if let Some(row) = catalog.by_code(&d.code)
            && row.exit_name != s.exit
        {
            out.push(format!(
                "{}: code::{} is raised with exit `{}` but its row says `{}`",
                s.krate, s.name, s.exit, row.exit_name
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
        paths.sort();
        for p in paths {
            if p.is_dir() {
                rust_files(&p, out);
            } else if p.extension().is_some_and(|e| e == "rs") {
                out.push(p);
            }
        }
    }

    fn ident(s: &str) -> &str {
        let end = s
            .find(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
            .unwrap_or(s.len());
        &s[..end]
    }

    /// `const NAME: &str = "FA-REF-nnn";` declarations in `text`.
    fn declarations(krate: &str, text: &str) -> Vec<Declaration> {
        let mut out = Vec::new();
        for line in text.lines() {
            let Some(at) = line.find("const ") else {
                continue;
            };
            let rest = &line[at + 6..];
            let name = ident(rest);
            if name.is_empty() {
                continue;
            }
            let rest = rest[name.len()..].trim_start();
            let Some(rest) = rest.strip_prefix(':') else {
                continue;
            };
            let Some(rest) = rest.trim_start().strip_prefix("&str") else {
                continue;
            };
            let Some(rest) = rest.trim_start().strip_prefix('=') else {
                continue;
            };
            let Some(rest) = rest.trim_start().strip_prefix('"') else {
                continue;
            };
            let Some(end) = rest.find('"') else { continue };
            if is_code(&rest[..end]) {
                out.push(Declaration {
                    krate: krate.to_string(),
                    name: name.to_string(),
                    code: rest[..end].to_string(),
                });
            }
        }
        out
    }

    /// Literal `code::NAME, exit::CLASS` pairs in `text`.
    fn sites(krate: &str, text: &str) -> Vec<Site> {
        let mut out = Vec::new();
        let mut rest = text;
        while let Some(at) = rest.find("code::") {
            rest = &rest[at + 6..];
            let name = ident(rest);
            if name.is_empty() {
                continue;
            }
            let after = rest[name.len()..].trim_start();
            let Some(after) = after.strip_prefix(',') else {
                continue;
            };
            let Some(after) = after.trim_start().strip_prefix("exit::") else {
                continue;
            };
            let exit = ident(after);
            if !exit.is_empty() {
                out.push(Site {
                    krate: krate.to_string(),
                    name: name.to_string(),
                    exit: exit.to_ascii_lowercase(),
                });
            }
        }
        out
    }

    fn scan_workspace() -> (Vec<Declaration>, Vec<Site>) {
        let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut decls = Vec::new();
        let mut found = Vec::new();
        let mut dirs: Vec<PathBuf> = std::fs::read_dir(&crates)
            .expect("crates dir")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        dirs.sort();
        for dir in dirs {
            let krate = dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            let mut files = Vec::new();
            rust_files(&dir.join("src"), &mut files);
            for f in files {
                let text = std::fs::read_to_string(&f).expect("readable source");
                decls.extend(declarations(&krate, &text));
                found.extend(sites(&krate, &text));
            }
        }
        (decls, found)
    }

    #[test]
    fn the_catalog_and_every_declared_refusal_agree_three_ways() {
        let catalog = RefusalCatalog::embedded().expect("refusal_catalog.toml");
        let (decls, sites) = scan_workspace();
        // The scan is not vacuous: the kernel's, the policy's and the
        // notary's codes are all seen, and so are their exit call sites.
        for (krate, code) in [
            ("fa-journal", "FA-REF-001"),
            ("fa-policy", "FA-REF-013"),
            ("fa-notary", "FA-REF-121"),
            ("fa-reference", "FA-REF-001"),
        ] {
            assert!(
                decls.iter().any(|d| d.krate == krate && d.code == code),
                "the scan missed {krate} {code}"
            );
        }
        assert!(
            sites.len() > 50,
            "only {} exit call sites seen",
            sites.len()
        );
        let findings = audit(&catalog, &decls, &sites);
        assert!(
            findings.is_empty(),
            "catalog drift:\n{}",
            findings.join("\n")
        );
    }

    /// Planted negatives: each direction of the gate fails when it should.
    #[test]
    fn the_audit_catches_each_kind_of_drift() {
        let catalog = RefusalCatalog::embedded().unwrap();
        let decl = |k: &str, n: &str, c: &str| Declaration {
            krate: k.into(),
            name: n.into(),
            code: c.into(),
        };
        let mut base: Vec<Declaration> = catalog
            .rows
            .iter()
            .flat_map(|r| r.owners.iter().map(|o| decl(o, &r.name, &r.code)))
            .collect();
        assert!(
            audit(&catalog, &base, &[]).is_empty(),
            "the rows' own owners agree"
        );
        let cases: Vec<(&str, Vec<Declaration>, Vec<Site>, &str)> = vec![
            (
                "a constant with no row",
                vec![decl("fa-journal", "NEW_THING", "FA-REF-099")],
                vec![],
                "has no catalog row",
            ),
            (
                "one code under two names (the 018 collision, resolved by D-I1)",
                vec![decl("fa-policy", "STALE_APPROVAL_2", "FA-REF-022")],
                vec![],
                "declared under 2 names",
            ),
            (
                "a declared reserved code (the lease before its row lands)",
                vec![decl("fa-cli", "LEASE_HELD", "FA-REF-018")],
                vec![],
                "declares reserved",
            ),
            (
                "an undeclared owner",
                vec![decl("fa-notary", "UNBALANCED", "FA-REF-001")],
                vec![],
                "not among its owners",
            ),
            (
                "a call site with another exit",
                vec![],
                vec![Site {
                    krate: "fa-journal".into(),
                    name: "UNBALANCED".into(),
                    exit: "usage".into(),
                }],
                "is raised with exit `usage`",
            ),
        ];
        for (what, extra_decls, extra_sites, expect) in cases {
            let mut decls = base.clone();
            decls.extend(extra_decls);
            let findings = audit(&catalog, &decls, &extra_sites);
            assert!(
                findings.iter().any(|f| f.contains(expect)),
                "{what}: expected `{expect}` in {findings:?}"
            );
        }
        // A row whose owner never declares it.
        base.retain(|d| d.code != "FA-REF-087");
        let findings = audit(&catalog, &base, &[]);
        assert!(
            findings
                .iter()
                .any(|f| f.contains("FA-REF-087 lists owners")),
            "{findings:?}"
        );
    }

    #[test]
    fn the_scanner_reads_declarations_and_call_sites() {
        let text = "pub const A_B: &str = \"FA-REF-123\";\nconst NOT: &str = \"FA-RE-1\";\nRefusal::new(\n  code::A_B,\n  exit::SAFETY,\n";
        assert_eq!(
            declarations("k", text),
            vec![Declaration {
                krate: "k".into(),
                name: "A_B".into(),
                code: "FA-REF-123".into()
            }]
        );
        assert_eq!(
            sites("k", text),
            vec![Site {
                krate: "k".into(),
                name: "A_B".into(),
                exit: "safety".into()
            }]
        );
    }

    #[test]
    fn malformed_catalogs_are_refused() {
        let exits = ExitCodes::embedded().unwrap();
        let good = REFUSAL_CATALOG;
        assert!(RefusalCatalog::from_text(good, &exits).is_ok());
        for (what, from, to) in [
            (
                "a duplicated code",
                "code = \"FA-REF-002\"",
                "code = \"FA-REF-001\"",
            ),
            (
                "a malformed code",
                "code = \"FA-REF-002\"",
                "code = \"FA-REF-2\"",
            ),
            (
                "a success exit",
                "name = \"NOT_A_LEAF\"\nowners = [\"fa-journal\"]\nexit = \"refusal\"",
                "name = \"NOT_A_LEAF\"\nowners = [\"fa-journal\"]\nexit = \"success\"",
            ),
            (
                "an unknown exit",
                "name = \"NOT_A_LEAF\"\nowners = [\"fa-journal\"]\nexit = \"refusal\"",
                "name = \"NOT_A_LEAF\"\nowners = [\"fa-journal\"]\nexit = \"oops\"",
            ),
            (
                "a duplicated name",
                "name = \"NOT_A_LEAF\"",
                "name = \"UNBALANCED\"",
            ),
            (
                "no owners",
                "name = \"NOT_A_LEAF\"\nowners = [\"fa-journal\"]",
                "name = \"NOT_A_LEAF\"\nowners = []",
            ),
            (
                "a reserved code with a row",
                "code = \"FA-REF-018\"\nholder",
                "code = \"FA-REF-001\"\nholder",
            ),
        ] {
            let text = good.replacen(from, to, 1);
            assert_ne!(text, good, "{what}: the planted edit did not apply");
            assert!(
                RefusalCatalog::from_text(&text, &exits).is_err(),
                "{what} must be refused"
            );
        }
    }
}
