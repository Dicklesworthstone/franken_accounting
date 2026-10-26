//! `registries/unwired_modules.toml`: library modules no surface reaches,
//! each with the open bead that will wire it and an expiry, and modules whose
//! only consumer is a test harness by design (bead fa-2ioe). `xtask
//! reachability` checks the rows against the workspace.

use std::collections::BTreeSet;

use crate::toml::Table;
use crate::{RegistryError, invalid, load, req_int, req_str};

const UNWIRED_MODULES: &str = include_str!("../../../registries/unwired_modules.toml");
const R: &str = "unwired_modules.toml";

/// Wiring debt: a module no surface reaches yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unwired {
    /// `crate_ident::seg::seg`; a crate root is its ident alone.
    pub path: String,
    pub owner_bead: String,
    pub reason: String,
    /// `YYYY-MM-DD`: the row is live through this day.
    pub expires: String,
}

/// A module whose only consumer is a test harness, by design.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationOnly {
    pub path: String,
    /// Workspace-relative test source that references the module.
    pub consumer: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwiredModules {
    pub unwired: Vec<Unwired>,
    pub verification: Vec<VerificationOnly>,
}

impl UnwiredModules {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::from_text(UNWIRED_MODULES)
    }

    pub fn from_text(text: &str) -> Result<Self, RegistryError> {
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        if let Some(key) = doc.root.keys().find(|k| *k != "schema_version") {
            return Err(invalid(R, format!("unknown top-level key `{key}`")));
        }
        if let Some(key) = doc
            .arrays
            .keys()
            .find(|k| *k != "unwired" && *k != "verification")
        {
            return Err(invalid(R, format!("unknown table array `[[{key}]]`")));
        }
        let empty = Vec::new();
        let mut paths = BTreeSet::new();
        let mut unwired = Vec::new();
        for t in doc.arrays.get("unwired").unwrap_or(&empty) {
            only_keys(t, &["path", "owner_bead", "reason", "expires"])?;
            let path = module_path(req_str(R, t, "path")?)?;
            let owner_bead = req_str(R, t, "owner_bead")?.to_string();
            if !is_bead_id(&owner_bead) {
                return Err(invalid(
                    R,
                    format!("{path}: owner_bead `{owner_bead}` is not a bead id (fa-<id>)"),
                ));
            }
            let reason = reason(&path, t)?;
            let expires = req_str(R, t, "expires")?.to_string();
            if parse_date(&expires).is_none() {
                return Err(invalid(
                    R,
                    format!("{path}: expires `{expires}` is not a YYYY-MM-DD date"),
                ));
            }
            if !paths.insert(path.clone()) {
                return Err(invalid(R, format!("{path} is listed twice")));
            }
            unwired.push(Unwired {
                path,
                owner_bead,
                reason,
                expires,
            });
        }
        let mut verification = Vec::new();
        for t in doc.arrays.get("verification").unwrap_or(&empty) {
            only_keys(t, &["path", "consumer", "reason"])?;
            let path = module_path(req_str(R, t, "path")?)?;
            let consumer = req_str(R, t, "consumer")?.to_string();
            let relative = !consumer.starts_with('/')
                && consumer
                    .split('/')
                    .all(|s| !s.is_empty() && s != "." && s != "..");
            if !relative || !consumer.ends_with(".rs") {
                return Err(invalid(
                    R,
                    format!("{path}: consumer `{consumer}` is not a workspace-relative .rs file"),
                ));
            }
            let reason = reason(&path, t)?;
            if !paths.insert(path.clone()) {
                return Err(invalid(R, format!("{path} is listed twice")));
            }
            verification.push(VerificationOnly {
                path,
                consumer,
                reason,
            });
        }
        Ok(Self {
            unwired,
            verification,
        })
    }
}

fn only_keys(t: &Table, allowed: &[&str]) -> Result<(), RegistryError> {
    match t.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(key) => Err(invalid(R, format!("unknown key `{key}`"))),
        None => Ok(()),
    }
}

fn reason(path: &str, t: &Table) -> Result<String, RegistryError> {
    let reason = req_str(R, t, "reason")?;
    if reason.trim().is_empty() {
        return Err(invalid(R, format!("{path}: reason is required")));
    }
    Ok(reason.to_string())
}

/// A module path of lowercase Rust identifiers joined by `::`.
fn module_path(path: &str) -> Result<String, RegistryError> {
    let ok = path.split("::").all(|seg| {
        let mut chars = seg.chars();
        chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
            && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    });
    if ok {
        Ok(path.to_string())
    } else {
        Err(invalid(
            R,
            format!("path `{path}` is not `crate_ident::module::…`"),
        ))
    }
}

fn is_bead_id(id: &str) -> bool {
    id.strip_prefix("fa-").is_some_and(|rest| {
        !rest.is_empty()
            && rest
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.')
    })
}

/// `YYYY-MM-DD` as (year, month, day), refusing impossible dates. Valid
/// dates compare chronologically as strings.
#[must_use]
pub fn parse_date(s: &str) -> Option<(u16, u8, u8)> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u16> {
        s.get(r)
            .filter(|d| d.bytes().all(|c| c.is_ascii_digit()))
            .and_then(|d| d.parse().ok())
    };
    let year = num(0..4)?;
    let month = u8::try_from(num(5..7)?).ok()?;
    let day = u8::try_from(num(8..10)?).ok()?;
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    (year >= 1970 && (1..=days).contains(&day)).then_some((year, month, day))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROW: &str = "schema_version = 1\n\n[[unwired]]\npath = \"fa_x::y\"\nowner_bead = \"fa-abc\"\nreason = \"why\"\nexpires = \"2026-11-21\"\n";

    #[test]
    fn the_embedded_registry_loads_with_unique_rows() {
        let r = UnwiredModules::embedded().expect("unwired_modules.toml");
        assert!(!r.unwired.is_empty());
        assert!(!r.verification.is_empty());
        assert!(
            r.unwired
                .iter()
                .any(|u| u.path == "fa_formats::part370" && u.owner_bead == "fa-p370")
        );
        let parsed = UnwiredModules::from_text(ROW).expect("one row");
        assert_eq!(parsed.unwired[0].expires, "2026-11-21");
    }

    #[test]
    fn malformed_rows_are_refused() {
        for (planted, why) in [
            (ROW.replace("2026-11-21", "2026-02-30"), "YYYY-MM-DD"),
            (ROW.replace("2026-11-21", "2026-11-1"), "YYYY-MM-DD"),
            (ROW.replace("fa-abc", "FA-1"), "not a bead id"),
            (ROW.replace("fa_x::y", "Fa::y"), "is not `crate_ident"),
            (ROW.replace("fa_x::y", "fa_x::"), "is not `crate_ident"),
            (ROW.replace("\"why\"", "\" \""), "reason is required"),
            (
                ROW.replace("reason = ", "note = \"x\"\nreason = "),
                "unknown key",
            ),
            (format!("{ROW}{}", &ROW[18..]), "listed twice"),
            (
                format!(
                    "{ROW}\n[[verification]]\npath = \"fa_z\"\nconsumer = \"../x.rs\"\nreason = \"r\"\n"
                ),
                "workspace-relative",
            ),
            (
                format!("{ROW}\n[[unwireds]]\npath = \"fa_z\"\n"),
                "unknown table",
            ),
        ] {
            let err = UnwiredModules::from_text(&planted)
                .expect_err(&planted)
                .to_string();
            assert!(err.contains(why), "{planted}: {err}");
        }
    }

    #[test]
    fn dates_are_validated_and_compare_as_strings() {
        assert_eq!(parse_date("2028-02-29"), Some((2028, 2, 29)));
        assert_eq!(parse_date("2026-02-29"), None);
        assert_eq!(parse_date("2026-13-01"), None);
        assert_eq!(parse_date("2026-00-10"), None);
        assert_eq!(parse_date("2026-1-010"), None);
        assert!("2026-11-21" < "2026-11-22" && "2026-12-01" > "2026-11-30");
    }
}
