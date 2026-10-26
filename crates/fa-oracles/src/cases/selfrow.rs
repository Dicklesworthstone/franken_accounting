//! The runner-generated self-disclosure rows (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §2.7; bead fa-yugf.15, A7a).
//!
//! For every book variant the runner adds one `jet.self_sourced_evidence`
//! D row with id `<case>-SELF-<variant>`, where `<case>` is the case letter
//! (`W-SELF-native`) or the self-test's id (`_selftest-SELF-native`), and
//! `about = "reconstruction"`: it asserts that the procedure cites every
//! posting that cites a reviewed citation stub, at severity Medium. Case
//! authors never write it (A1c refuses the id). It is a D about our
//! encoding, not about history, so K-EVID's bar on `statement` and `ledger`
//! variants does not apply to it.

use fa_registry::toml::Value as TomlValue;

use super::Case;
use super::header::CaseKind;

/// The procedure the SELF rows run.
pub const PROCEDURE: &str = "jet.self_sourced_evidence";

const PROCEDURES: &str = include_str!("../../../../registries/procedures.toml");

/// One generated row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfRow {
    pub id: String,
    pub variant: String,
    pub procedure: &'static str,
    pub version: i128,
    /// The severity the row expects on each cited posting.
    pub severity: &'static str,
    pub about: &'static str,
}

/// The registered version of [`PROCEDURE`].
///
/// # Errors
///
/// When `registries/procedures.toml` does not parse or lacks the row.
pub fn version() -> Result<i128, String> {
    let doc = fa_registry::toml::parse(PROCEDURES)
        .map_err(|e| format!("registries/procedures.toml:{}: {}", e.line, e.message))?;
    doc.arrays
        .get("procedure")
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .find(|t| t.get("id").and_then(TomlValue::as_str) == Some(PROCEDURE))
        .and_then(|t| t.get("version").and_then(TomlValue::as_int))
        .ok_or_else(|| format!("registries/procedures.toml has no `{PROCEDURE}` row"))
}

/// The id prefix: the case letter, or the self-test's id.
#[must_use]
pub fn prefix(case: &Case) -> String {
    match (case.header.kind, case.header.letter.as_deref()) {
        (CaseKind::Case, Some(letter)) => letter.to_string(),
        _ => case.header.id.clone(),
    }
}

/// One row per book variant, in stem order.
///
/// # Errors
///
/// When the procedure's version cannot be read.
pub fn self_rows(case: &Case) -> Result<Vec<SelfRow>, String> {
    let version = version()?;
    let prefix = prefix(case);
    Ok(case
        .books
        .keys()
        .map(|variant| SelfRow {
            id: format!("{prefix}-SELF-{variant}"),
            variant: variant.clone(),
            procedure: PROCEDURE,
            version,
            severity: "Medium",
            about: "reconstruction",
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cases::CASE_EXTENSIONS;
    use crate::cases::tests::{load_files, pilot};

    #[test]
    fn self_rows_are_one_per_variant_named_by_letter() {
        let mut case = load_files("worldcom", &pilot(), CASE_EXTENSIONS).expect("the pilot loads");
        let rows = self_rows(&case).expect("rows");
        assert_eq!(
            rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            ["W-SELF-native"]
        );
        assert_eq!(rows[0].procedure, "jet.self_sourced_evidence");
        assert_eq!(rows[0].version, 1);
        // A second variant gets its own row; a harness self-test is named by its id.
        let native = case.books["native"].clone();
        let mut ledger = native.clone();
        ledger.stem = "statement-bridge".into();
        case.books.insert("statement-bridge".into(), ledger);
        case.header.kind = CaseKind::HarnessSelftest;
        case.header.letter = None;
        case.header.id = "_selftest".into();
        let ids: Vec<String> = self_rows(&case)
            .expect("rows")
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(
            ids,
            ["_selftest-SELF-native", "_selftest-SELF-statement-bridge"]
        );
    }
}
