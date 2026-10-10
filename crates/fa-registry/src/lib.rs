//! The registries FrankenAccounting code branches on (plan §18.2), embedded
//! at compile time from `registries/*.toml`.
//!
//! Boundary test (process-porn doctrine): every registry here is read by
//! running code — the CLI's exit codes, the kernel's class tags and
//! admissibility matrix, the money crate's unit table, the symbol table every
//! GQL statement needs. A registry nothing branches on does not belong here.

#![forbid(unsafe_code)]

pub mod sod_policy;
pub mod toml;

use core::fmt;
use std::collections::BTreeMap;

use fa_time::PeriodState;

use crate::toml::{Document, Table, TomlError, Value};

const EXIT_CODES: &str = include_str!("../../../registries/exit_codes.toml");
const ENTRY_CLASSES: &str = include_str!("../../../registries/entry_classes.toml");
const ADMISSIBILITY: &str = include_str!("../../../registries/admissibility.toml");
const UNITS: &str = include_str!("../../../registries/units.toml");
const ROUNDING_LAWS: &str = include_str!("../../../registries/rounding_laws.toml");
const SYMBOLS: &str = include_str!("../../../registries/symbols.toml");

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryError {
    Toml {
        registry: &'static str,
        error: TomlError,
    },
    Invalid {
        registry: &'static str,
        message: String,
    },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Toml { registry, error } => write!(f, "{registry}: {error}"),
            Self::Invalid { registry, message } => write!(f, "{registry}: {message}"),
        }
    }
}

impl core::error::Error for RegistryError {}

fn invalid(registry: &'static str, message: impl Into<String>) -> RegistryError {
    RegistryError::Invalid {
        registry,
        message: message.into(),
    }
}

fn load(registry: &'static str, text: &str) -> Result<Document, RegistryError> {
    toml::parse(text).map_err(|error| RegistryError::Toml { registry, error })
}

fn req_str<'a>(registry: &'static str, t: &'a Table, key: &str) -> Result<&'a str, RegistryError> {
    t.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(registry, format!("missing string `{key}`")))
}

fn req_int(registry: &'static str, t: &Table, key: &str) -> Result<i128, RegistryError> {
    t.get(key)
        .and_then(Value::as_int)
        .ok_or_else(|| invalid(registry, format!("missing integer `{key}`")))
}

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitCode {
    pub code: u8,
    pub name: String,
    pub meaning: String,
    pub fgdb_equivalent: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ExitCodes {
    pub rows: Vec<ExitCode>,
}

impl ExitCodes {
    pub fn embedded() -> Result<Self, RegistryError> {
        const R: &str = "exit_codes.toml";
        let doc = load(R, EXIT_CODES)?;
        let mut rows = Vec::new();
        for t in doc.arrays.get("exit_code").unwrap_or(&Vec::new()) {
            let code = req_int(R, t, "code")?;
            let code = u8::try_from(code)
                .map_err(|_| invalid(R, format!("exit code {code} out of range")))?;
            rows.push(ExitCode {
                code,
                name: req_str(R, t, "name")?.to_string(),
                meaning: req_str(R, t, "meaning")?.to_string(),
                fgdb_equivalent: t
                    .get("fgdb_equivalent")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        for r in &rows {
            if !seen.insert(r.code) {
                return Err(invalid(R, format!("duplicate exit code {}", r.code)));
            }
            if r.code == 1 {
                return Err(invalid(R, "exit code 1 is never emitted"));
            }
        }
        if !seen.contains(&0) {
            return Err(invalid(R, "exit code 0 must exist"));
        }
        Ok(Self { rows })
    }

    pub fn by_name(&self, name: &str) -> Option<&ExitCode> {
        self.rows.iter().find(|r| r.name == name)
    }

    pub fn code(&self, name: &str) -> Option<u8> {
        self.by_name(name).map(|r| r.code)
    }
}

// ---------------------------------------------------------------------------
// Entry classes
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClassKind {
    Posting,
    Control,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryClass {
    pub tag: u16,
    pub name: String,
    pub kind: ClassKind,
    pub supersession: String,
}

#[derive(Clone, Debug, Default)]
pub struct EntryClasses {
    pub rows: Vec<EntryClass>,
}

impl EntryClasses {
    pub fn embedded() -> Result<Self, RegistryError> {
        const R: &str = "entry_classes.toml";
        let doc = load(R, ENTRY_CLASSES)?;
        let mut rows = Vec::new();
        for t in doc.arrays.get("class").unwrap_or(&Vec::new()) {
            let tag = req_int(R, t, "tag")?;
            let kind = match req_str(R, t, "kind")? {
                "posting" => ClassKind::Posting,
                "control" => ClassKind::Control,
                other => return Err(invalid(R, format!("unknown class kind `{other}`"))),
            };
            rows.push(EntryClass {
                tag: u16::try_from(tag)
                    .map_err(|_| invalid(R, format!("tag {tag} out of range")))?,
                name: req_str(R, t, "name")?.to_string(),
                kind,
                supersession: req_str(R, t, "supersession")?.to_string(),
            });
        }
        let mut tags = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        for r in &rows {
            if !tags.insert(r.tag) {
                return Err(invalid(R, format!("duplicate tag {}", r.tag)));
            }
            if !names.insert(r.name.clone()) {
                return Err(invalid(R, format!("duplicate class `{}`", r.name)));
            }
        }
        Ok(Self { rows })
    }

    pub fn by_name(&self, name: &str) -> Option<&EntryClass> {
        self.rows.iter().find(|r| r.name == name)
    }

    pub fn by_tag(&self, tag: u16) -> Option<&EntryClass> {
        self.rows.iter().find(|r| r.tag == tag)
    }

    pub fn posting(&self) -> impl Iterator<Item = &EntryClass> {
        self.rows.iter().filter(|r| r.kind == ClassKind::Posting)
    }
}

// ---------------------------------------------------------------------------
// Admissibility matrix
// ---------------------------------------------------------------------------

/// One decided cell of plan Appendix C.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Admit,
    With { op: String, approvals: u8 },
    Refuse,
}

/// A row's disposition qualifier (Appendix C notes on `Resolution`): the
/// decision column speaks for `Posts`; releases (`Voids`, `Expires`) follow
/// the qualifier. Parsed from the note's leading token so the registry, not
/// the kernel, owns the rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Qualifier {
    None,
    /// `posts_only_with`: the `with:` requirement binds `Posts` only; releases admit.
    ReleasesAdmit,
    /// `voids_expires`: releases admit; `Posts` is refused.
    PostsRefused,
}

#[derive(Clone, Debug, Default)]
pub struct Admissibility {
    cells: BTreeMap<(String, PeriodState), (Decision, Option<String>, Qualifier)>,
}

impl Admissibility {
    pub fn embedded(classes: &EntryClasses) -> Result<Self, RegistryError> {
        const R: &str = "admissibility.toml";
        let doc = load(R, ADMISSIBILITY)?;
        let mut cells = BTreeMap::new();
        for t in doc.arrays.get("cell").unwrap_or(&Vec::new()) {
            let class = req_str(R, t, "class")?.to_string();
            if classes
                .by_name(&class)
                .is_none_or(|c| c.kind != ClassKind::Posting)
            {
                return Err(invalid(R, format!("`{class}` is not a posting class")));
            }
            let state_s = req_str(R, t, "state")?;
            let state = PeriodState::from_name(state_s)
                .ok_or_else(|| invalid(R, format!("unknown state `{state_s}`")))?;
            let decision = parse_decision(R, req_str(R, t, "decision")?)?;
            let note = t.get("note").and_then(Value::as_str).map(str::to_string);
            let qualifier = match note.as_deref().and_then(|n| n.split(':').next()) {
                Some("posts_only_with") => Qualifier::ReleasesAdmit,
                Some("voids_expires") => Qualifier::PostsRefused,
                _ => Qualifier::None,
            };
            if qualifier != Qualifier::None && class != "Resolution" {
                return Err(invalid(
                    R,
                    format!("disposition qualifier on `{class}`, which has no dispositions"),
                ));
            }
            if cells
                .insert((class.clone(), state), (decision, note, qualifier))
                .is_some()
            {
                return Err(invalid(
                    R,
                    format!("cell ({class}, {state_s}) decided twice"),
                ));
            }
        }
        // Exhaustiveness: every posting class × every state exactly once.
        for c in classes.posting() {
            for s in [
                PeriodState::Future,
                PeriodState::Open,
                PeriodState::SoftClosed,
                PeriodState::Closed,
                PeriodState::Locked,
            ] {
                if !cells.contains_key(&(c.name.clone(), s)) {
                    return Err(invalid(
                        R,
                        format!("undecided cell ({}, {})", c.name, s.name()),
                    ));
                }
            }
        }
        Ok(Self { cells })
    }

    pub fn decide(&self, class: &str, state: PeriodState) -> Option<&Decision> {
        self.cells.get(&(class.to_string(), state)).map(|(d, ..)| d)
    }

    /// The cell's decision for one disposition family (plan §5.4): `release`
    /// is true for `Voids`/`Expires`, false for `Posts` and for every class
    /// that has no dispositions (where this equals [`Self::decide`]).
    pub fn decide_disposition(
        &self,
        class: &str,
        state: PeriodState,
        release: bool,
    ) -> Option<Decision> {
        let (decision, _, qualifier) = self.cells.get(&(class.to_string(), state))?;
        Some(match (qualifier, release) {
            (Qualifier::ReleasesAdmit, true) => Decision::Admit,
            (Qualifier::PostsRefused, false) => Decision::Refuse,
            _ => decision.clone(),
        })
    }

    pub fn note(&self, class: &str, state: PeriodState) -> Option<&str> {
        self.cells
            .get(&(class.to_string(), state))
            .and_then(|(_, n, _)| n.as_deref())
    }

    pub fn len(&self) -> usize {
        self.cells.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }
}

fn parse_decision(registry: &'static str, text: &str) -> Result<Decision, RegistryError> {
    match text {
        "admit" => Ok(Decision::Admit),
        "refuse" => Ok(Decision::Refuse),
        other => {
            let spec = other
                .strip_prefix("with:")
                .ok_or_else(|| invalid(registry, format!("unknown decision `{other}`")))?;
            let (op, approvals) = match spec.split_once(',') {
                Some((op, n)) => (
                    op.trim(),
                    n.trim().parse::<u8>().map_err(|_| {
                        invalid(registry, format!("bad approval count in `{other}`"))
                    })?,
                ),
                None => (spec.trim(), 0),
            };
            if op.is_empty() {
                return Err(invalid(registry, format!("empty op in `{other}`")));
            }
            Ok(Decision::With {
                op: op.to_string(),
                approvals,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Units and rounding laws
// ---------------------------------------------------------------------------

/// Registry data, independent of the production arithmetic implementation.
/// Consumers bind these rows to their own unit representations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitRow {
    pub code: String,
    pub version: u16,
    pub scale: u8,
    pub kind: String,
    pub iso4217: Option<u16>,
}

pub fn units_embedded() -> Result<Vec<UnitRow>, RegistryError> {
    const R: &str = "units.toml";
    let doc = load(R, UNITS)?;
    let mut rows = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for t in doc.arrays.get("unit").unwrap_or(&Vec::new()) {
        let code = req_str(R, t, "code")?.to_string();
        let version = u16::try_from(req_int(R, t, "version")?)
            .map_err(|_| invalid(R, "version out of range"))?;
        let scale =
            u8::try_from(req_int(R, t, "scale")?).map_err(|_| invalid(R, "scale out of range"))?;
        if scale > 18 {
            return Err(invalid(R, format!("`{code}` scale {scale} exceeds 18")));
        }
        let kind = req_str(R, t, "kind")?;
        let iso4217 = match kind {
            "currency" => Some(
                u16::try_from(req_int(R, t, "iso4217")?)
                    .map_err(|_| invalid(R, "iso4217 out of range"))?,
            ),
            "commodity" | "share" | "time" | "count" | "custom" => None,
            other => return Err(invalid(R, format!("unknown unit kind `{other}`"))),
        };
        if !seen.insert((code.clone(), version)) {
            return Err(invalid(R, format!("duplicate unit {code}@v{version}")));
        }
        rows.push(UnitRow {
            code,
            scale,
            version,
            kind: kind.to_owned(),
            iso4217,
        });
    }
    if rows.is_empty() {
        return Err(invalid(R, "no units"));
    }
    Ok(rows)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundingLawRow {
    pub id: u16,
    pub name: String,
    pub definition: String,
}

pub fn rounding_laws_embedded() -> Result<Vec<RoundingLawRow>, RegistryError> {
    const R: &str = "rounding_laws.toml";
    let doc = load(R, ROUNDING_LAWS)?;
    let mut rows = Vec::new();
    for t in doc.arrays.get("law").unwrap_or(&Vec::new()) {
        rows.push(RoundingLawRow {
            id: u16::try_from(req_int(R, t, "id")?).map_err(|_| invalid(R, "id out of range"))?,
            name: req_str(R, t, "name")?.to_string(),
            definition: req_str(R, t, "definition")?.to_string(),
        });
    }
    // Data validity lives here; the arithmetic consumer checks the complete
    // correspondence with its executable RoundingLaw variants.
    let mut ids = std::collections::BTreeSet::new();
    let mut names = std::collections::BTreeSet::new();
    for r in &rows {
        if r.id == 0 || r.name.is_empty() || !ids.insert(r.id) || !names.insert(&r.name) {
            return Err(invalid(R, "invalid or duplicate rounding law id/name"));
        }
    }
    if rows.is_empty() {
        return Err(invalid(R, "no rounding laws"));
    }
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Symbols
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Symbols {
    pub labels: BTreeMap<String, u64>,
    pub properties: BTreeMap<String, u64>,
    pub relations: BTreeMap<String, u64>,
}

impl Symbols {
    pub fn embedded() -> Result<Self, RegistryError> {
        const R: &str = "symbols.toml";
        let doc = load(R, SYMBOLS)?;
        let mut out = Self::default();
        for (section, map) in [
            ("label", &mut out.labels),
            ("property", &mut out.properties),
            ("relation", &mut out.relations),
        ] {
            let mut ids = std::collections::BTreeSet::new();
            for t in doc.arrays.get(section).unwrap_or(&Vec::new()) {
                let id = req_int(R, t, "id")?;
                let id = u64::try_from(id)
                    .map_err(|_| invalid(R, format!("{section} id {id} out of range")))?;
                if id == 0 {
                    return Err(invalid(R, format!("{section} id 0 is reserved")));
                }
                let name = req_str(R, t, "name")?.to_string();
                if !ids.insert(id) {
                    return Err(invalid(R, format!("duplicate {section} id {id}")));
                }
                if map.insert(name.clone(), id).is_some() {
                    return Err(invalid(R, format!("duplicate {section} `{name}`")));
                }
            }
        }
        Ok(out)
    }

    pub fn label(&self, name: &str) -> Option<u64> {
        self.labels.get(name).copied()
    }

    pub fn property(&self, name: &str) -> Option<u64> {
        self.properties.get(name).copied()
    }

    pub fn relation(&self, name: &str) -> Option<u64> {
        self.relations.get(name).copied()
    }

    /// Canonical bytes of the table (sorted sections, `name=id` lines), the
    /// input to the `symbols_digest` a book journals at creation.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        for (section, map) in [
            ("label", &self.labels),
            ("property", &self.properties),
            ("relation", &self.relations),
        ] {
            for (name, id) in map {
                out.push_str(section);
                out.push(':');
                out.push_str(name);
                out.push('=');
                out.push_str(&id.to_string());
                out.push('\n');
            }
        }
        out.into_bytes()
    }
}

/// Everything, loaded once.
#[derive(Clone, Debug)]
pub struct Registries {
    pub exit_codes: ExitCodes,
    pub entry_classes: EntryClasses,
    pub admissibility: Admissibility,
    pub units: Vec<UnitRow>,
    pub rounding_laws: Vec<RoundingLawRow>,
    pub symbols: Symbols,
}

impl Registries {
    pub fn embedded() -> Result<Self, RegistryError> {
        let entry_classes = EntryClasses::embedded()?;
        let admissibility = Admissibility::embedded(&entry_classes)?;
        Ok(Self {
            exit_codes: ExitCodes::embedded()?,
            entry_classes,
            admissibility,
            units: units_embedded()?,
            rounding_laws: rounding_laws_embedded()?,
            symbols: Symbols::embedded()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_embedded_registries_load_and_validate() {
        let r = Registries::embedded().expect("registries");
        assert_eq!(r.exit_codes.code("success"), Some(0));
        assert_eq!(r.exit_codes.code("safety"), Some(7));
        assert_eq!(r.exit_codes.code("verification"), Some(8));
        assert!(r.exit_codes.rows.iter().all(|e| e.code != 1));
        assert_eq!(r.entry_classes.by_name("Original").map(|c| c.tag), Some(1));
        assert_eq!(
            r.entry_classes.by_name("PeriodControl").map(|c| c.kind),
            Some(ClassKind::Control)
        );
        assert_eq!(
            r.units
                .iter()
                .find(|u| u.code == "USD" && u.version == 0)
                .map(|u| u.scale),
            Some(2)
        );
        assert_eq!(r.rounding_laws.len(), 9);
        assert_eq!(r.symbols.label("Entry"), Some(9));
        assert_eq!(r.symbols.relation("POSTS_TO"), Some(2));
        assert_eq!(r.symbols.property("_fa_payload"), Some(1));
    }

    /// Plan Appendix C, exhaustively: every posting class × every state is
    /// decided exactly once, and the universal rules hold.
    #[test]
    fn admissibility_matrix_is_exhaustive_and_obeys_the_universal_rules() {
        let r = Registries::embedded().unwrap();
        let posting: Vec<_> = r.entry_classes.posting().collect();
        assert_eq!(r.admissibility.len(), posting.len() * 5);
        for s in [PeriodState::Closed, PeriodState::Locked] {
            assert_eq!(
                r.admissibility.decide("Original", s),
                Some(&Decision::Refuse),
                "an Original is never admissible in {s:?}"
            );
        }
        assert_eq!(
            r.admissibility.decide("Original", PeriodState::Open),
            Some(&Decision::Admit)
        );
        assert_eq!(
            r.admissibility.decide("Restatement", PeriodState::Locked),
            Some(&Decision::With {
                op: "restate".into(),
                approvals: 2
            })
        );
        assert_eq!(
            r.admissibility.note("Restatement", PeriodState::Locked),
            Some("case")
        );
        // Reservation releases stay admissible in Locked (fa-ctf); Posts do not.
        assert_eq!(
            r.admissibility.decide("Resolution", PeriodState::Locked),
            Some(&Decision::Admit)
        );
        assert!(
            r.admissibility
                .note("Resolution", PeriodState::Locked)
                .unwrap()
                .contains("voids_expires")
        );
        for (state, posts, release) in [
            (PeriodState::Open, Decision::Admit, Decision::Admit),
            (PeriodState::SoftClosed, Decision::Admit, Decision::Admit),
            (
                PeriodState::Closed,
                Decision::With {
                    op: "post_closed".into(),
                    approvals: 0,
                },
                Decision::Admit,
            ),
            (PeriodState::Locked, Decision::Refuse, Decision::Admit),
            (PeriodState::Future, Decision::Refuse, Decision::Refuse),
        ] {
            assert_eq!(
                r.admissibility
                    .decide_disposition("Resolution", state, false),
                Some(posts),
                "Resolution(Posts) in {state:?}"
            );
            assert_eq!(
                r.admissibility
                    .decide_disposition("Resolution", state, true),
                Some(release),
                "Resolution(Voids|Expires) in {state:?}"
            );
        }
        // Classes without dispositions ignore the flag.
        assert_eq!(
            r.admissibility
                .decide_disposition("Original", PeriodState::Closed, true),
            Some(Decision::Refuse)
        );
        // PriorPeriodAdjustment posts in the current open period (fa-xwv).
        assert!(matches!(
            r.admissibility
                .decide("PriorPeriodAdjustment", PeriodState::Open),
            Some(Decision::With { .. })
        ));
        assert_eq!(
            r.admissibility
                .decide("PriorPeriodAdjustment", PeriodState::Locked),
            Some(&Decision::Refuse)
        );
        // Control classes are not period-scoped.
        assert!(
            r.admissibility
                .decide("PeriodControl", PeriodState::Open)
                .is_none()
        );
    }

    #[test]
    fn symbols_digest_input_is_canonical_and_stable() {
        let a = Symbols::embedded().unwrap().canonical_bytes();
        let b = Symbols::embedded().unwrap().canonical_bytes();
        assert_eq!(a, b);
        assert!(
            String::from_utf8(a)
                .unwrap()
                .starts_with("label:Account=3\n")
        );
    }
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

const LIMITS: &str = include_str!("../../../registries/limits.toml");

/// `registries/limits.toml` as `name → value`; fa-model's compiled constants
/// are cross-checked against it.
pub fn limits_embedded() -> Result<BTreeMap<String, u64>, RegistryError> {
    const R: &str = "limits.toml";
    let doc = load(R, LIMITS)?;
    let mut out = BTreeMap::new();
    for t in doc.arrays.get("limit").unwrap_or(&Vec::new()) {
        let name = req_str(R, t, "name")?.to_string();
        let value = req_int(R, t, "value")?;
        let value =
            u64::try_from(value).map_err(|_| invalid(R, format!("`{name}` is negative")))?;
        if value == 0 {
            return Err(invalid(R, format!("`{name}` is zero")));
        }
        if out.insert(name.clone(), value).is_some() {
            return Err(invalid(R, format!("duplicate limit `{name}`")));
        }
    }
    if out.is_empty() {
        return Err(invalid(R, "no limits"));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Account types
// ---------------------------------------------------------------------------

const ACCOUNT_TYPES: &str = include_str!("../../../registries/account_types.toml");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountTypeRow {
    pub tag: u8,
    pub name: String,
    /// `stock` (carries forward), `flow` (closes to equity each fiscal year),
    /// or `memo` (outside the balance law).
    pub kind: String,
    /// 0 = debit-normal, 1 = credit-normal.
    pub normal_balance: u8,
}

/// `registries/account_types.toml`; fa-model's `AccountType` constants are
/// cross-checked against it.
pub fn account_types_embedded() -> Result<Vec<AccountTypeRow>, RegistryError> {
    const R: &str = "account_types.toml";
    let doc = load(R, ACCOUNT_TYPES)?;
    let mut rows = Vec::new();
    let mut tags = std::collections::BTreeSet::new();
    for t in doc.arrays.get("account_type").unwrap_or(&Vec::new()) {
        let tag =
            u8::try_from(req_int(R, t, "tag")?).map_err(|_| invalid(R, "tag out of range"))?;
        let kind = req_str(R, t, "kind")?.to_string();
        if !matches!(kind.as_str(), "stock" | "flow" | "memo") {
            return Err(invalid(R, format!("unknown kind `{kind}`")));
        }
        let normal_balance = u8::try_from(req_int(R, t, "normal_balance")?)
            .map_err(|_| invalid(R, "normal_balance out of range"))?;
        if normal_balance > 1 {
            return Err(invalid(R, "normal_balance is 0 (debit) or 1 (credit)"));
        }
        if !tags.insert(tag) {
            return Err(invalid(R, format!("duplicate tag {tag}")));
        }
        rows.push(AccountTypeRow {
            tag,
            name: req_str(R, t, "name")?.to_string(),
            kind,
            normal_balance,
        });
    }
    if rows.is_empty() {
        return Err(invalid(R, "no account types"));
    }
    Ok(rows)
}
