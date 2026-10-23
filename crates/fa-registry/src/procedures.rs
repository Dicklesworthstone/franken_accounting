//! `registries/procedures.toml`: the Lantern procedure registry (plan §11.1,
//! bead fa-nlu). A procedure binds to its row at construction and refuses to
//! run unregistered or at a version other than the row's; its parameters
//! start from the row's pinned defaults (the decision card's deterministic
//! fallback) and only registered names may be set.

use std::collections::BTreeSet;

use crate::{RegistryError, invalid, load, req_int, req_str};

const PROCEDURES: &str = include_str!("../../../registries/procedures.toml");
const R: &str = "procedures.toml";

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
            rows.push(Procedure {
                id,
                version,
                claim,
                evidence,
                tie_break,
                complexity,
                calibration,
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
            // benford.first_digit gained its account_type scope at version 2.
            let version = if id == "benford.first_digit" { 2 } else { 1 };
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
    fn each_procedure_declares_how_it_uses_the_effective_date() {
        let p = Procedures::embedded().unwrap();
        let date = |id: &str| p.get(id).unwrap().effective_through;
        assert_eq!(date("aging.open_items"), EffectiveThrough::Required);
        assert_eq!(date("trace.libr"), EffectiveThrough::Required);
        assert_eq!(date("lookback.preferences"), EffectiveThrough::Optional);
        assert_eq!(date("jet.round_amounts"), EffectiveThrough::NotTaken);
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
