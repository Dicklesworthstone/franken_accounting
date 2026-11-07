//! `registries/procedures.toml`: the Lantern procedure registry (plan §11.1,
//! bead fa-nlu). A procedure binds to its row at construction and refuses to
//! run unregistered or at a version other than the row's; its parameters
//! start from the row's pinned defaults (the decision card's deterministic
//! fallback) and only registered names may be set.

use std::collections::BTreeSet;

use crate::{RegistryError, invalid, load, req_int, req_str};

const PROCEDURES: &str = include_str!("../../../registries/procedures.toml");
const R: &str = "procedures.toml";
const LAYERING_V3_SUMMARY_SUFFIX: &str = " Version 3 advances each hop in effective/recorded/entry-identity order; version 2 could revisit an earlier recorded transfer on the same effective day.";
const SUSPENSE_V3_SUMMARY: &str = "Accounts holding the `suspense` role with nonzero open-item residuals older than max_age_days, folded from immutable settlements and reversal lineage. Fully cleared items do not contribute age or citations; offsetting unapplied items remain open even when their net is zero. The date is the coordinate's effective date, or the latest live posting date when omitted. Refused when the role is unassigned or an effective cutoff splits a settlement/reversal. Version 2 aged an account's first-ever posting; version 1 guessed accounts from names.";
const SUSPENSE_V2_SUMMARY: &str = "Accounts holding the `suspense` account role (registries/account_roles.toml, assigned with fa chart role) that retain a non-zero balance or uncleared postings older than max_age_days as of the coordinate's effective date. Refused when no account holds the role. Version 1 guessed the accounts from code and name tokens.";
const SUSPENSE_V3_COMPLEXITY: &str =
    "O((entries + legs + applications) log (entries + legs + applications))";
const LOOKBACK_WINDOW_SUMMARY_SUFFIX: &str = " Window arithmetic preserves the full u32 domain; older versions narrowed civil-day windows to signed i32.";
const LAPPING_V3_SUMMARY_SUFFIX: &str = " Version 3 preserves the full u32 window and widens day subtraction; version 2 retains its signed window arithmetic.";
const LAPPING_V4_SUMMARY_SUFFIX: &str = " Version 4 indexes matching settlements and meters candidate searches; versions 2 and 3 retain their historical work transcripts.";
const LAPPING_V4_COMPLEXITY: &str = "O((legs + parties) log (legs + parties) + legs^2 log legs)";

/// Restore the exact row before indexed, fully metered lapping execution.
pub fn lapping_v3_document(
    mut doc: crate::toml::Document,
) -> Result<crate::toml::Document, RegistryError> {
    let row = doc
        .arrays
        .get_mut("procedure")
        .and_then(|rows| {
            rows.iter_mut().find(|row| {
                row.get("id").and_then(crate::toml::Value::as_str) == Some("recon.lapping")
            })
        })
        .ok_or_else(|| invalid(R, "missing retained lapping row"))?;
    if row.get("version").and_then(crate::toml::Value::as_int) != Some(4)
        || req_str(R, row, "complexity")? != LAPPING_V4_COMPLEXITY
    {
        return Err(invalid(R, "unavailable metered lapping revision"));
    }
    let summary = req_str(R, row, "summary")?
        .strip_suffix(LAPPING_V4_SUMMARY_SUFFIX)
        .ok_or_else(|| invalid(R, "unrecognized metered lapping revision"))?
        .to_string();
    row.insert("version".into(), crate::toml::Value::Int(3));
    row.insert(
        "complexity".into(),
        crate::toml::Value::Str("O(legs log legs)".into()),
    );
    row.insert("summary".into(), crate::toml::Value::Str(summary));
    Ok(doc)
}

/// Preserve the published raw-text row without changing another procedure
/// that happens to share its complexity expression.
pub fn lapping_v3_registry_text(text: &str) -> Result<String, RegistryError> {
    let doc = load(R, text)?;
    let expected = lapping_v3_document(doc.clone())?.canonical_bytes();
    let row = doc
        .arrays
        .get("procedure")
        .and_then(|rows| {
            rows.iter().find(|row| {
                row.get("id").and_then(crate::toml::Value::as_str) == Some("recon.lapping")
            })
        })
        .ok_or_else(|| invalid(R, "missing retained lapping row"))?;
    let summary = req_str(R, row, "summary")?;
    let old_summary = summary
        .strip_suffix(LAPPING_V4_SUMMARY_SUFFIX)
        .ok_or_else(|| invalid(R, "unrecognized metered lapping revision"))?;
    let prefix = "[[procedure]]\nid = \"recon.lapping\"\nversion = 4\n";
    if text.matches(prefix).count() != 1 {
        return Err(invalid(R, "unavailable raw metered lapping revision"));
    }
    let start = text
        .find(prefix)
        .ok_or_else(|| invalid(R, "missing raw lapping row"))?;
    let tail = &text[start + prefix.len()..];
    let end = tail
        .find("\n[[")
        .map_or(text.len(), |offset| start + prefix.len() + offset);
    let block = &text[start..end];
    let complexity = format!("complexity = \"{LAPPING_V4_COMPLEXITY}\"\n");
    let summary_line = format!("summary = \"{summary}\"\n");
    if block.matches(&complexity).count() != 1 || block.matches(&summary_line).count() != 1 {
        return Err(invalid(R, "unavailable raw metered lapping fields"));
    }
    let restored = block
        .replacen(
            prefix,
            "[[procedure]]\nid = \"recon.lapping\"\nversion = 3\n",
            1,
        )
        .replacen(&complexity, "complexity = \"O(legs log legs)\"\n", 1)
        .replacen(&summary_line, &format!("summary = \"{old_summary}\"\n"), 1);
    let retained = format!("{}{restored}{}", &text[..start], &text[end..]);
    if load(R, &retained)?.canonical_bytes() != expected {
        return Err(invalid(
            R,
            "retained raw and canonical lapping v3 registries disagree",
        ));
    }
    Ok(retained)
}

/// Restore only the published lapping-v2 row. Other registry content stays
/// bound, including the separately retained JET, layering and lookback epochs.
pub fn lapping_v2_document(
    mut doc: crate::toml::Document,
) -> Result<crate::toml::Document, RegistryError> {
    if doc
        .arrays
        .get("procedure")
        .and_then(|rows| {
            rows.iter().find(|row| {
                row.get("id").and_then(crate::toml::Value::as_str) == Some("recon.lapping")
            })
        })
        .and_then(|row| row.get("version"))
        .and_then(crate::toml::Value::as_int)
        == Some(4)
    {
        doc = lapping_v3_document(doc)?;
    }
    let row = doc
        .arrays
        .get_mut("procedure")
        .and_then(|rows| {
            rows.iter_mut().find(|row| {
                row.get("id").and_then(crate::toml::Value::as_str) == Some("recon.lapping")
            })
        })
        .ok_or_else(|| invalid(R, "missing retained lapping row"))?;
    if row.get("version").and_then(crate::toml::Value::as_int) != Some(3) {
        return Err(invalid(R, "unavailable lapping registry version"));
    }
    let summary = req_str(R, row, "summary")?
        .strip_suffix(LAPPING_V3_SUMMARY_SUFFIX)
        .ok_or_else(|| invalid(R, "unrecognized lapping registry revision"))?
        .to_string();
    row.insert("version".into(), crate::toml::Value::Int(2));
    row.insert("summary".into(), crate::toml::Value::Str(summary));
    Ok(doc)
}

/// Raw certificates require the original text as well as canonical content.
pub fn lapping_v2_registry_text(text: &str) -> Result<String, RegistryError> {
    let initial = load(R, text)?;
    let version = initial
        .arrays
        .get("procedure")
        .and_then(|rows| {
            rows.iter().find(|row| {
                row.get("id").and_then(crate::toml::Value::as_str) == Some("recon.lapping")
            })
        })
        .and_then(|row| row.get("version"))
        .and_then(crate::toml::Value::as_int);
    let text = if version == Some(4) {
        lapping_v3_registry_text(text)?
    } else {
        text.to_string()
    };
    let text = text.as_str();
    let doc = load(R, text)?;
    let expected = lapping_v2_document(doc.clone())?.canonical_bytes();
    let row = doc
        .arrays
        .get("procedure")
        .and_then(|rows| {
            rows.iter().find(|row| {
                row.get("id").and_then(crate::toml::Value::as_str) == Some("recon.lapping")
            })
        })
        .ok_or_else(|| invalid(R, "missing retained lapping row"))?;
    let summary = req_str(R, row, "summary")?;
    let old_summary = summary
        .strip_suffix(LAPPING_V3_SUMMARY_SUFFIX)
        .ok_or_else(|| invalid(R, "unrecognized lapping registry revision"))?;
    let prefix = "[[procedure]]\nid = \"recon.lapping\"\nversion = 3\n";
    let summary_line = format!("summary = \"{summary}\"\n");
    if text.matches(prefix).count() != 1 || text.matches(&summary_line).count() != 1 {
        return Err(invalid(R, "unavailable raw lapping registry revision"));
    }
    let retained = text
        .replacen(
            prefix,
            "[[procedure]]\nid = \"recon.lapping\"\nversion = 2\n",
            1,
        )
        .replacen(&summary_line, &format!("summary = \"{old_summary}\"\n"), 1);
    if load(R, &retained)?.canonical_bytes() != expected {
        return Err(invalid(
            R,
            "retained raw and canonical lapping registries disagree",
        ));
    }
    Ok(retained)
}

/// Restore only the audited preference-v3 and fraudulent-transfer-v1 rows.
/// Their algorithms remain separately versioned; registry reconstruction
/// never makes an old commitment authorize the corrected window arithmetic.
pub fn legacy_lookback_document(
    mut doc: crate::toml::Document,
) -> Result<crate::toml::Document, RegistryError> {
    let rows = doc
        .arrays
        .get_mut("procedure")
        .ok_or_else(|| invalid(R, "missing procedure rows"))?;
    for (id, current, previous) in [
        ("lookback.preferences", 4, 3),
        ("lookback.fraudulent_transfer", 2, 1),
    ] {
        let row = rows
            .iter_mut()
            .find(|row| row.get("id").and_then(crate::toml::Value::as_str) == Some(id))
            .ok_or_else(|| invalid(R, format!("missing retained procedure {id}")))?;
        if row.get("version").and_then(crate::toml::Value::as_int) != Some(current) {
            return Err(invalid(R, format!("unavailable lookback version for {id}")));
        }
        let summary = req_str(R, row, "summary")?
            .strip_suffix(LOOKBACK_WINDOW_SUMMARY_SUFFIX)
            .ok_or_else(|| invalid(R, format!("unrecognized lookback revision for {id}")))?
            .to_string();
        row.insert("version".into(), crate::toml::Value::Int(previous));
        row.insert("summary".into(), crate::toml::Value::Str(summary));
    }
    Ok(doc)
}

/// Raw certificates additionally require the exact earlier text layout.
pub fn legacy_lookback_registry_text(text: &str) -> Result<String, RegistryError> {
    let doc = load(R, text)?;
    let rows = doc
        .arrays
        .get("procedure")
        .ok_or_else(|| invalid(R, "missing procedure rows"))?;
    let mut retained = text.to_string();
    for (id, current, previous) in [
        ("lookback.preferences", 4, 3),
        ("lookback.fraudulent_transfer", 2, 1),
    ] {
        let row = rows
            .iter()
            .find(|row| row.get("id").and_then(crate::toml::Value::as_str) == Some(id))
            .ok_or_else(|| invalid(R, format!("missing retained procedure {id}")))?;
        let summary = req_str(R, row, "summary")?;
        let old_summary = summary
            .strip_suffix(LOOKBACK_WINDOW_SUMMARY_SUFFIX)
            .ok_or_else(|| invalid(R, format!("unrecognized lookback revision for {id}")))?;
        let prefix = format!("[[procedure]]\nid = \"{id}\"\nversion = {current}\n");
        let summary_line = format!("summary = \"{summary}\"\n");
        if retained.matches(&prefix).count() != 1 || retained.matches(&summary_line).count() != 1 {
            return Err(invalid(
                R,
                format!("unavailable raw lookback revision for {id}"),
            ));
        }
        retained = retained.replacen(
            &prefix,
            &format!("[[procedure]]\nid = \"{id}\"\nversion = {previous}\n"),
            1,
        );
        retained = retained.replacen(&summary_line, &format!("summary = \"{old_summary}\"\n"), 1);
    }
    if load(R, &retained)?.canonical_bytes() != legacy_lookback_document(doc)?.canonical_bytes() {
        return Err(invalid(
            R,
            "retained raw and canonical lookback registries disagree",
        ));
    }
    Ok(retained)
}

/// The canonical registry closure preceding the two effective-window JET
/// algorithms. Durable certificates and authored case references may retain
/// those v1 rows; their other fields and all other procedures remain exact.
/// This is not a fallback for an arbitrary future registry revision.
pub fn legacy_v1_document() -> Result<crate::toml::Document, RegistryError> {
    legacy_v1_document_from_text(PROCEDURES)
}

/// Reconstruct the retained JET rows from a supplied registry for validators
/// that must also reject changed registry inputs. Only the explicit v2
/// optional-window transition is reversible; all other edits remain visible
/// in the canonical bytes and their commitment.
pub fn legacy_v1_document_from_text(text: &str) -> Result<crate::toml::Document, RegistryError> {
    let mut doc = load(R, text)?;
    let rows = doc
        .arrays
        .get_mut("procedure")
        .ok_or_else(|| invalid(R, "missing procedure rows"))?;
    for id in ["jet.round_amounts", "jet.period_end_timing"] {
        let row = rows
            .iter_mut()
            .find(|row| row.get("id").and_then(crate::toml::Value::as_str) == Some(id))
            .ok_or_else(|| invalid(R, format!("missing retained procedure {id}")))?;
        if row.get("version").and_then(crate::toml::Value::as_int) == Some(2)
            && row
                .get("effective_through")
                .and_then(crate::toml::Value::as_str)
                == Some("optional")
        {
            row.insert("version".into(), crate::toml::Value::Int(1));
            row.remove("effective_through");
        }
    }
    Ok(doc)
}

/// Restore only the two layering rows, independently of comments and layout.
/// This composes with the separately retained JET registry revision.
pub fn layering_v2_document(
    mut doc: crate::toml::Document,
) -> Result<crate::toml::Document, RegistryError> {
    let rows = doc
        .arrays
        .get_mut("procedure")
        .ok_or_else(|| invalid(R, "missing procedure rows"))?;
    for id in ["graph.layering", "graph.party_layering"] {
        let row = rows
            .iter_mut()
            .find(|row| row.get("id").and_then(crate::toml::Value::as_str) == Some(id))
            .ok_or_else(|| invalid(R, format!("missing retained procedure {id}")))?;
        let summary = req_str(R, row, "summary")?
            .strip_suffix(LAYERING_V3_SUMMARY_SUFFIX)
            .ok_or_else(|| invalid(R, format!("unrecognized layering revision for {id}")))?
            .to_string();
        if row.get("version").and_then(crate::toml::Value::as_int) != Some(3) {
            return Err(invalid(R, format!("unavailable layering version for {id}")));
        }
        row.insert("version".into(), crate::toml::Value::Int(2));
        row.insert("summary".into(), crate::toml::Value::Str(summary));
    }
    Ok(doc)
}

/// Restore the exact two-row registry revision before layering gained its
/// recorded-order law. Other registry edits stay bound by the returned text.
/// Raw-text certificates need the original bytes as well as canonical content.
pub fn layering_v2_registry_text(text: &str) -> Result<String, RegistryError> {
    let doc = load(R, text)?;
    let rows = doc
        .arrays
        .get("procedure")
        .ok_or_else(|| invalid(R, "missing procedure rows"))?;
    let mut retained = text.to_string();
    for id in ["graph.layering", "graph.party_layering"] {
        let row = rows
            .iter()
            .find(|row| row.get("id").and_then(crate::toml::Value::as_str) == Some(id))
            .ok_or_else(|| invalid(R, format!("missing retained procedure {id}")))?;
        let summary = req_str(R, row, "summary")?;
        let previous = summary
            .strip_suffix(LAYERING_V3_SUMMARY_SUFFIX)
            .ok_or_else(|| invalid(R, format!("unrecognized layering revision for {id}")))?;
        let current_prefix = format!("[[procedure]]\nid = \"{id}\"\nversion = 3\n");
        let current_summary = format!("summary = \"{summary}\"\n");
        if row.get("version").and_then(crate::toml::Value::as_int) != Some(3)
            || retained.matches(&current_prefix).count() != 1
            || retained.matches(&current_summary).count() != 1
        {
            return Err(invalid(
                R,
                format!("unavailable layering registry revision for {id}"),
            ));
        }
        retained = retained.replacen(
            &current_prefix,
            &format!("[[procedure]]\nid = \"{id}\"\nversion = 2\n"),
            1,
        );
        retained = retained.replacen(&current_summary, &format!("summary = \"{previous}\"\n"), 1);
    }
    if load(R, &retained)?.canonical_bytes()
        != layering_v2_document(load(R, text)?)?.canonical_bytes()
    {
        return Err(invalid(
            R,
            "retained raw and canonical layering registries disagree",
        ));
    }
    Ok(retained)
}

/// The published JET-v1 registry also preceded suspense's open-item algorithm.
/// Restore only its audited version, complexity and summary; no other edit is
/// erased. This retains registry content, not an alias for the old algorithm.
pub fn suspense_v2_document(
    mut doc: crate::toml::Document,
) -> Result<crate::toml::Document, RegistryError> {
    let row = doc
        .arrays
        .get_mut("procedure")
        .and_then(|rows| {
            rows.iter_mut().find(|row| {
                row.get("id").and_then(crate::toml::Value::as_str) == Some("jet.suspense_aging")
            })
        })
        .ok_or_else(|| invalid(R, "missing retained suspense row"))?;
    if row.get("version").and_then(crate::toml::Value::as_int) != Some(3)
        || req_str(R, row, "summary")? != SUSPENSE_V3_SUMMARY
        || req_str(R, row, "complexity")? != SUSPENSE_V3_COMPLEXITY
    {
        return Err(invalid(R, "unrecognized suspense registry revision"));
    }
    row.insert("version".into(), crate::toml::Value::Int(2));
    row.insert(
        "summary".into(),
        crate::toml::Value::Str(SUSPENSE_V2_SUMMARY.into()),
    );
    row.insert(
        "complexity".into(),
        crate::toml::Value::Str("O(legs log legs)".into()),
    );
    Ok(doc)
}

/// Exact raw-text counterpart of the published suspense-v2 registry.
pub fn suspense_v2_registry_text(text: &str) -> Result<String, RegistryError> {
    let expected = suspense_v2_document(load(R, text)?)?.canonical_bytes();
    let mut retained = text.to_string();
    for (current, previous) in [
        (
            "[[procedure]]\nid = \"jet.suspense_aging\"\nversion = 3\n".to_string(),
            "[[procedure]]\nid = \"jet.suspense_aging\"\nversion = 2\n".to_string(),
        ),
        (
            format!("summary = \"{SUSPENSE_V3_SUMMARY}\"\n"),
            format!("summary = \"{SUSPENSE_V2_SUMMARY}\"\n"),
        ),
        (
            format!("complexity = \"{SUSPENSE_V3_COMPLEXITY}\"\n"),
            "complexity = \"O(legs log legs)\"\n".to_string(),
        ),
    ] {
        if retained.matches(&current).count() != 1 {
            return Err(invalid(R, "unavailable raw suspense registry revision"));
        }
        retained = retained.replacen(&current, &previous, 1);
    }
    if load(R, &retained)?.canonical_bytes() != expected {
        return Err(invalid(
            R,
            "retained raw and canonical suspense registries disagree",
        ));
    }
    Ok(retained)
}

/// The claim class of a procedure's output (plan §11.9, doctrine 12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Claim {
    /// A score or threshold test: evidence, never an invariant.
    Statistical,
    /// An exact reconciliation derived from an invariant checker.
    Invariant,
}

impl Claim {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "statistical" => Some(Self::Statistical),
            "invariant" => Some(Self::Invariant),
            _ => None,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Statistical => "statistical",
            Self::Invariant => "invariant",
        }
    }
}

/// How a ranking breaks ties (CGSE policy, plan §11.1): by the cited
/// entry's vid, by the account's vid, or not at all (a population statistic
/// with a single finding).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TieBreak {
    EntryVid,
    AccountVid,
    None,
}

impl TieBreak {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "entry_vid" => Some(Self::EntryVid),
            "account_vid" => Some(Self::AccountVid),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// Calibration status (plan §11.10): `planted` = precision/recall measured
/// on a planted-anomaly corpus in the tests; `corpus` = measured on an
/// `fa-gen` labeled corpus; `uncalibrated` = thresholds pinned, not measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Calibration {
    Planted,
    Corpus,
    Uncalibrated,
}

impl Calibration {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "planted" => Some(Self::Planted),
            "corpus" => Some(Self::Corpus),
            "uncalibrated" => Some(Self::Uncalibrated),
            _ => None,
        }
    }
}

/// How a procedure uses the run's effective date (`fa procedure run
/// --effective-through`; bead fa-9pjp). A procedure that does not take one
/// folds every posting regardless of effective date, so a date given to it
/// is refused rather than silently ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectiveThrough {
    /// The date is ignored; giving one is a usage error.
    NotTaken,
    /// Without a date the procedure covers every effective date.
    Optional,
    /// The procedure is defined at a date (an as-of aging, a trace).
    Required,
}

impl EffectiveThrough {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "optional" => Some(Self::Optional),
            "required" => Some(Self::Required),
            _ => None,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::NotTaken => "not_taken",
            Self::Optional => "optional",
            Self::Required => "required",
        }
    }
}

/// A registered parameter with its pinned default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameter {
    pub name: String,
    pub default: i128,
    pub meaning: String,
}

/// A declared input a caller must supply (never read from the environment).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub name: String,
    /// `date`, `period`, `account` or `entry`.
    pub kind: String,
    pub meaning: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Procedure {
    pub id: String,
    pub version: u16,
    pub claim: Claim,
    pub evidence: String,
    pub tie_break: TieBreak,
    pub complexity: String,
    pub calibration: Calibration,
    pub artifact: Option<String>,
    pub summary: String,
    pub effective_through: EffectiveThrough,
    pub inputs: Vec<Input>,
    pub parameters: Vec<Parameter>,
}

impl Procedure {
    #[must_use]
    pub fn parameter(&self, name: &str) -> Option<&Parameter> {
        self.parameters.iter().find(|p| p.name == name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Procedures {
    pub rows: Vec<Procedure>,
}

pub const INPUT_KINDS: [&str; 4] = ["date", "period", "account", "entry"];

fn well_formed_id(id: &str) -> bool {
    let mut parts = id.split('.');
    let (Some(family), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let ok = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            && s.starts_with(|c: char| c.is_ascii_lowercase())
    };
    ok(family) && ok(name)
}

fn well_formed_evidence(e: &str) -> bool {
    let Some(n) = e.strip_prefix("FA-EVID-L") else {
        return false;
    };
    n.len() == 2 && n.chars().all(|c| c.is_ascii_digit()) && n != "00"
}

impl Procedures {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::from_text(PROCEDURES)
    }

    pub fn from_text(text: &str) -> Result<Self, RegistryError> {
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        let empty = Vec::new();
        let mut ids = BTreeSet::new();
        let mut evidence_rows = BTreeSet::new();
        let mut rows = Vec::new();
        for t in doc.arrays.get("procedure").unwrap_or(&empty) {
            let id = req_str(R, t, "id")?.to_string();
            if !well_formed_id(&id) {
                return Err(invalid(
                    R,
                    format!("procedure id `{id}` is not `family.name` in lowercase"),
                ));
            }
            if !ids.insert(id.clone()) {
                return Err(invalid(R, format!("procedure `{id}` is listed twice")));
            }
            let raw = req_int(R, t, "version")?;
            let version = u16::try_from(raw)
                .ok()
                .filter(|v| *v >= 1)
                .ok_or_else(|| invalid(R, format!("{id}: version {raw} is not in 1..=65535")))?;
            let claim_s = req_str(R, t, "claim")?;
            let claim = Claim::parse(claim_s)
                .ok_or_else(|| invalid(R, format!("{id}: unknown claim class `{claim_s}`")))?;
            let evidence = req_str(R, t, "evidence")?.to_string();
            if !well_formed_evidence(&evidence) {
                return Err(invalid(
                    R,
                    format!("{id}: evidence row `{evidence}` is not FA-EVID-L01..L99"),
                ));
            }
            if !evidence_rows.insert(evidence.clone()) {
                return Err(invalid(
                    R,
                    format!("{id}: evidence row `{evidence}` is claimed twice"),
                ));
            }
            let tb = req_str(R, t, "tie_break")?;
            let tie_break = TieBreak::parse(tb)
                .ok_or_else(|| invalid(R, format!("{id}: unknown tie_break `{tb}`")))?;
            let complexity = req_str(R, t, "complexity")?.to_string();
            let cal = req_str(R, t, "calibration")?;
            let calibration = Calibration::parse(cal)
                .ok_or_else(|| invalid(R, format!("{id}: unknown calibration `{cal}`")))?;
            let summary = req_str(R, t, "summary")?.to_string();
            if complexity.is_empty() || summary.trim().is_empty() {
                return Err(invalid(
                    R,
                    format!("{id}: complexity and summary are required"),
                ));
            }
            let effective_through = match t.get("effective_through") {
                None => EffectiveThrough::NotTaken,
                Some(v) => v.as_str().and_then(EffectiveThrough::parse).ok_or_else(|| {
                    invalid(
                        R,
                        format!("{id}: effective_through must be \"optional\" or \"required\" (omit it when the date is not taken)"),
                    )
                })?,
            };
            let artifact = match t.get("artifact") {
                None => None,
                Some(v) => Some(
                    v.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| invalid(R, format!("{id}: `artifact` must be a string")))?,
                ),
            };
            rows.push(Procedure {
                id,
                version,
                claim,
                evidence,
                tie_break,
                complexity,
                calibration,
                artifact,
                summary,
                effective_through,
                inputs: Vec::new(),
                parameters: Vec::new(),
            });
        }
        if rows.is_empty() {
            return Err(invalid(R, "no procedures are registered"));
        }
        for t in doc.arrays.get("parameter").unwrap_or(&empty) {
            let procedure = req_str(R, t, "procedure")?;
            let name = req_str(R, t, "name")?.to_string();
            let default = req_int(R, t, "default")?;
            let meaning = req_str(R, t, "meaning")?.to_string();
            let Some(row) = rows.iter_mut().find(|r| r.id == procedure) else {
                return Err(invalid(
                    R,
                    format!("parameter `{name}` names unregistered procedure `{procedure}`"),
                ));
            };
            if name.is_empty() || meaning.trim().is_empty() {
                return Err(invalid(
                    R,
                    format!("{procedure}: parameter name and meaning are required"),
                ));
            }
            if row.parameters.iter().any(|p| p.name == name) {
                return Err(invalid(
                    R,
                    format!("{procedure}: parameter `{name}` is listed twice"),
                ));
            }
            row.parameters.push(Parameter {
                name,
                default,
                meaning,
            });
        }
        for t in doc.arrays.get("input").unwrap_or(&empty) {
            let procedure = req_str(R, t, "procedure")?;
            let name = req_str(R, t, "name")?.to_string();
            let kind = req_str(R, t, "kind")?.to_string();
            let meaning = req_str(R, t, "meaning")?.to_string();
            let Some(row) = rows.iter_mut().find(|r| r.id == procedure) else {
                return Err(invalid(
                    R,
                    format!("input `{name}` names unregistered procedure `{procedure}`"),
                ));
            };
            if !INPUT_KINDS.contains(&kind.as_str()) {
                return Err(invalid(
                    R,
                    format!("{procedure}: input `{name}` has unknown kind `{kind}`"),
                ));
            }
            if row.inputs.iter().any(|i| i.name == name) || row.parameter(&name).is_some() {
                return Err(invalid(
                    R,
                    format!("{procedure}: input `{name}` collides with another input or parameter"),
                ));
            }
            row.inputs.push(Input {
                name,
                kind,
                meaning,
            });
        }
        Ok(Self { rows })
    }

    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Procedure> {
        self.rows.iter().find(|r| r.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_lapping_row_binds_exact_version_and_preserves_other_inputs() {
        let before = lapping_v2_document(load(R, PROCEDURES).unwrap()).unwrap();
        let raw = lapping_v2_registry_text(PROCEDURES).unwrap();
        assert_eq!(load(R, &raw).unwrap(), before);
        let row = before.arrays["procedure"]
            .iter()
            .find(|row| row.get("id").and_then(crate::toml::Value::as_str) == Some("recon.lapping"))
            .unwrap();
        assert_eq!(
            row.get("version").and_then(crate::toml::Value::as_int),
            Some(2)
        );
        assert!(
            !req_str(R, row, "summary")
                .unwrap()
                .ends_with(LAPPING_V3_SUMMARY_SUFFIX)
        );
        let layout = PROCEDURES.replace(
            "id = \"recon.lapping\"\nversion = 4",
            "id = \"recon.lapping\"\n# layout only\nversion = 4",
        );
        assert_eq!(
            lapping_v2_document(load(R, &layout).unwrap()).unwrap(),
            before
        );
        assert!(lapping_v2_registry_text(&layout).is_err());
        let mut unrelated = load(R, PROCEDURES).unwrap();
        unrelated.arrays.get_mut("procedure").unwrap()[0]
            .insert("evidence".into(), crate::toml::Value::Str("changed".into()));
        assert_ne!(lapping_v2_document(unrelated).unwrap(), before);
        let future = PROCEDURES.replace(
            "id = \"recon.lapping\"\nversion = 4",
            "id = \"recon.lapping\"\nversion = 5",
        );
        assert!(lapping_v2_document(load(R, &future).unwrap()).is_err());
        assert!(lapping_v2_registry_text(&future).is_err());
        let unknown = PROCEDURES.replace(LAPPING_V3_SUMMARY_SUFFIX, " unknown lapping law");
        assert!(lapping_v2_document(load(R, &unknown).unwrap()).is_err());
        assert!(lapping_v2_registry_text(&unknown).is_err());
    }

    #[test]
    fn retained_lapping_v3_keeps_its_real_complexity_and_shared_class_rows() {
        let before = lapping_v3_document(load(R, PROCEDURES).unwrap()).unwrap();
        let raw = lapping_v3_registry_text(PROCEDURES).unwrap();
        assert_eq!(load(R, &raw).unwrap(), before);
        let row = before.arrays["procedure"]
            .iter()
            .find(|row| row.get("id").and_then(crate::toml::Value::as_str) == Some("recon.lapping"))
            .unwrap();
        assert_eq!(
            row.get("version").and_then(crate::toml::Value::as_int),
            Some(3)
        );
        assert_eq!(req_str(R, row, "complexity").unwrap(), "O(legs log legs)");
        assert!(
            req_str(R, row, "summary")
                .unwrap()
                .ends_with(LAPPING_V3_SUMMARY_SUFFIX)
        );
        assert_eq!(
            lapping_v2_document(before).unwrap(),
            lapping_v2_document(load(R, PROCEDURES).unwrap()).unwrap()
        );
        let class_line = format!("complexity = \"{LAPPING_V4_COMPLEXITY}\"");
        let shared = PROCEDURES.replacen("complexity = \"O(legs)\"", &class_line, 1);
        assert_eq!(shared.matches(&class_line).count(), 2);
        let shared_retained = lapping_v3_registry_text(&shared).unwrap();
        assert_eq!(shared_retained.matches(&class_line).count(), 1);
        assert_eq!(
            load(R, &shared_retained).unwrap(),
            lapping_v3_document(load(R, &shared).unwrap()).unwrap()
        );
        let layout = PROCEDURES.replace(
            "id = \"recon.lapping\"\nversion = 4",
            "id = \"recon.lapping\"\n# layout only\nversion = 4",
        );
        assert!(lapping_v3_document(load(R, &layout).unwrap()).is_ok());
        assert!(lapping_v3_registry_text(&layout).is_err());
        let future = PROCEDURES.replace(
            "id = \"recon.lapping\"\nversion = 4",
            "id = \"recon.lapping\"\nversion = 5",
        );
        assert!(lapping_v3_document(load(R, &future).unwrap()).is_err());
        assert!(lapping_v3_registry_text(&future).is_err());
        for changed in [
            PROCEDURES.replace(LAPPING_V4_SUMMARY_SUFFIX, " unknown metering law"),
            PROCEDURES.replace(LAPPING_V4_COMPLEXITY, "O(legs)"),
        ] {
            assert!(lapping_v3_document(load(R, &changed).unwrap()).is_err());
            assert!(lapping_v3_registry_text(&changed).is_err());
        }
    }

    #[test]
    fn retained_layering_rows_preserve_layout_independence_and_unrelated_changes() {
        let before = layering_v2_document(load(R, PROCEDURES).unwrap()).unwrap();
        let layout = PROCEDURES.replace("\nversion = 3\n", "\n# layout only\nversion = 3\n");
        assert_eq!(
            layering_v2_document(load(R, &layout).unwrap()).unwrap(),
            before
        );
        // Raw commitments require their exact earlier layout, independently
        // of the canonical reconstruction above.
        assert!(layering_v2_registry_text(&layout).is_err());
        assert_eq!(
            load(R, &layering_v2_registry_text(PROCEDURES).unwrap()).unwrap(),
            before
        );
        let mut unrelated = load(R, PROCEDURES).unwrap();
        unrelated.arrays.get_mut("procedure").unwrap()[0]
            .insert("evidence".into(), crate::toml::Value::Str("changed".into()));
        assert_ne!(layering_v2_document(unrelated).unwrap(), before);
        let future = PROCEDURES.replacen(
            "id = \"graph.layering\"\nversion = 3",
            "id = \"graph.layering\"\nversion = 4",
            1,
        );
        assert!(layering_v2_document(load(R, &future).unwrap()).is_err());
        assert!(layering_v2_registry_text(&future).is_err());
    }

    #[test]
    fn retained_lookback_rows_bind_exact_versions_and_preserve_other_inputs() {
        let before = legacy_lookback_document(load(R, PROCEDURES).unwrap()).unwrap();
        let raw = legacy_lookback_registry_text(PROCEDURES).unwrap();
        assert_eq!(load(R, &raw).unwrap(), before);
        for (id, expected) in [
            ("lookback.preferences", 3),
            ("lookback.fraudulent_transfer", 1),
        ] {
            let row = before.arrays["procedure"]
                .iter()
                .find(|row| row.get("id").and_then(crate::toml::Value::as_str) == Some(id))
                .unwrap();
            assert_eq!(
                row.get("version").and_then(crate::toml::Value::as_int),
                Some(expected)
            );
        }
        let layout = PROCEDURES.replace(
            "id = \"lookback.preferences\"\nversion = 4",
            "id = \"lookback.preferences\"\n# layout only\nversion = 4",
        );
        assert_eq!(
            legacy_lookback_document(load(R, &layout).unwrap()).unwrap(),
            before
        );
        assert!(legacy_lookback_registry_text(&layout).is_err());
        let mut unrelated = load(R, PROCEDURES).unwrap();
        unrelated.arrays.get_mut("procedure").unwrap()[0]
            .insert("evidence".into(), crate::toml::Value::Str("changed".into()));
        assert_ne!(legacy_lookback_document(unrelated).unwrap(), before);
        for (id, current, future) in [
            ("lookback.preferences", 4, 5),
            ("lookback.fraudulent_transfer", 2, 3),
        ] {
            let future = PROCEDURES.replace(
                &format!("id = \"{id}\"\nversion = {current}"),
                &format!("id = \"{id}\"\nversion = {future}"),
            );
            assert!(legacy_lookback_document(load(R, &future).unwrap()).is_err());
            assert!(legacy_lookback_registry_text(&future).is_err());
        }
        let unknown = PROCEDURES.replace(LOOKBACK_WINDOW_SUMMARY_SUFFIX, " unknown window law");
        assert!(legacy_lookback_document(load(R, &unknown).unwrap()).is_err());
        assert!(legacy_lookback_registry_text(&unknown).is_err());
    }

    const MINIMAL: &str = r#"
schema_version = 1
[[procedure]]
id = "jet.round_amounts"
version = 1
claim = "statistical"
evidence = "FA-EVID-L01"
tie_break = "entry_vid"
complexity = "O(legs)"
calibration = "planted"
summary = "round legs"
[[parameter]]
procedure = "jet.round_amounts"
name = "round_power"
default = 3
meaning = "power of ten"
"#;

    #[test]
    fn the_embedded_registry_loads_with_the_first_slice() {
        let p = Procedures::embedded().expect("procedures.toml");
        for id in [
            "jet.round_amounts",
            "jet.period_end_timing",
            "jet.post_closing",
            "jet.weekend",
            "jet.self_approved",
            "jet.thin_descriptions",
            "duplicates.same_same_same",
            "duplicates.same_same_different",
            "numbers.sequence_gaps",
            "benford.first_digit",
            "cutoff.period_boundary",
            "aging.open_items",
        ] {
            assert!(p.get(id).is_some(), "{id} is registered");
            let row = p.get(id).unwrap();
            // Benford v2 adds account-type scope; the two dated JET v2
            // profiles add an optional effective cutoff. Other rows retain v1.
            let version = match id {
                "benford.first_digit" | "jet.round_amounts" | "jet.period_end_timing" => 2,
                _ => 1,
            };
            assert_eq!(row.version, version, "{id}");
            assert_eq!(
                row.claim,
                Claim::Statistical,
                "{id}: scores are statistical"
            );
        }
        assert_eq!(
            p.get("jet.round_amounts")
                .unwrap()
                .parameter("round_power")
                .unwrap()
                .default,
            3
        );
        assert!(
            p.get("aging.open_items").unwrap().inputs.is_empty(),
            "the aging date is the run's coordinate, not a registered input"
        );
        assert_eq!(
            p.get("graph.round_trips")
                .unwrap()
                .parameter("window_days")
                .unwrap()
                .default,
            5
        );
        assert!(
            p.get("graph.tracing").is_none(),
            "tracing laws are a later slice"
        );
    }

    #[test]
    fn principal_transfers_have_a_new_net_investment_version_without_reinterpreting_distributions()
    {
        let procedures = Procedures::embedded().expect("procedures.toml");
        let net = procedures
            .get("ponzi.net_investment")
            .expect("net investment");
        assert_eq!(net.version, 5);
        assert_eq!(net.claim, Claim::Statistical);
        assert_eq!(net.calibration, Calibration::Uncalibrated);
        assert_eq!(net.effective_through, EffectiveThrough::Optional);
        assert_eq!(net.parameter("cohort_window_days").unwrap().default, 90);
        for id in ["distribution.rising_tide", "distribution.pro_rata"] {
            let distribution = procedures.get(id).expect("cash distribution");
            assert_eq!(distribution.version, 4, "{id} keeps its cash-only version");
            assert_eq!(distribution.claim, Claim::Statistical);
            assert_eq!(distribution.calibration, Calibration::Uncalibrated);
        }
    }

    #[test]
    fn each_procedure_declares_how_it_uses_the_effective_date() {
        let p = Procedures::embedded().unwrap();
        let date = |id: &str| p.get(id).unwrap().effective_through;
        assert_eq!(date("aging.open_items"), EffectiveThrough::Required);
        assert_eq!(date("trace.libr"), EffectiveThrough::Required);
        assert_eq!(date("lookback.preferences"), EffectiveThrough::Optional);
        assert_eq!(date("jet.round_amounts"), EffectiveThrough::Optional);
        assert_eq!(date("jet.period_end_timing"), EffectiveThrough::Optional);
        assert_eq!(date("graph.concentration"), EffectiveThrough::NotTaken);
    }

    #[test]
    fn a_minimal_registry_loads() {
        let p = Procedures::from_text(MINIMAL).unwrap();
        assert_eq!(p.rows.len(), 1);
        assert_eq!(p.rows[0].parameters.len(), 1);
    }

    fn refused(text: &str, needle: &str) {
        let err = Procedures::from_text(text).expect_err("the planted registry is refused");
        let message = match err {
            RegistryError::Invalid { message, .. } => message,
            RegistryError::Toml { error, .. } => format!("toml: {error}"),
        };
        assert!(
            message.contains(needle),
            "{message} should mention {needle}"
        );
    }

    #[test]
    fn malformed_registries_are_refused() {
        // A duplicate id.
        let dup = format!(
            "{MINIMAL}\n{}",
            MINIMAL.trim_start_matches("\nschema_version = 1")
        );
        refused(&dup, "listed twice");
        // An orphan parameter.
        refused(
            &format!(
                "{MINIMAL}\n[[parameter]]\nprocedure = \"jet.nope\"\nname = \"x\"\ndefault = 1\nmeaning = \"m\"\n"
            ),
            "unregistered procedure",
        );
        // An unknown claim class.
        refused(
            &MINIMAL.replace("\"statistical\"", "\"heuristic\""),
            "unknown claim",
        );
        // An evidence row outside the Lantern range.
        refused(
            &MINIMAL.replace("FA-EVID-L01", "FA-EVID-01"),
            "FA-EVID-L01..L99",
        );
        // A duplicate parameter name.
        refused(
            &format!(
                "{MINIMAL}\n[[parameter]]\nprocedure = \"jet.round_amounts\"\nname = \"round_power\"\ndefault = 2\nmeaning = \"again\"\n"
            ),
            "listed twice",
        );
        // An effective-date use outside the vocabulary (fa-9pjp).
        refused(
            &MINIMAL.replace(
                "summary = ",
                "effective_through = \"sometimes\"\nsummary = ",
            ),
            "effective_through must be",
        );
        // An input of an unknown kind.
        refused(
            &format!(
                "{MINIMAL}\n[[input]]\nprocedure = \"jet.round_amounts\"\nname = \"as_of\"\nkind = \"clock\"\nmeaning = \"m\"\n"
            ),
            "unknown kind",
        );
        // A malformed id.
        refused(
            &MINIMAL.replace("jet.round_amounts", "RoundAmounts"),
            "family.name",
        );
        // Version zero.
        refused(
            &MINIMAL.replace("\nversion = 1", "\nversion = 0"),
            "1..=65535",
        );
    }
}
