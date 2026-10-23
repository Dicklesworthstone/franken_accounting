//! The registries FrankenAccounting code branches on (plan §18.2), embedded
//! at compile time from `registries/*.toml`.
//!
//! Boundary test (process-porn doctrine): every registry here is read by
//! running code — the CLI's exit codes, the kernel's class tags and
//! admissibility matrix, the money crate's unit table, the symbol table every
//! GQL statement needs. A registry nothing branches on does not belong here.

#![forbid(unsafe_code)]

pub mod account_roles;
pub mod admissibility_plan;
pub mod capability_caveats;
pub mod document_stores;
pub mod evidence_policy;
pub mod foundations;
pub mod g0;
pub mod intake_sources;
pub mod invariants;
pub mod mutants;
pub mod procedures;
pub mod reason_codes;
pub mod redaction_contracts;
pub mod refusal_catalog;
pub mod scoreboard;
pub mod sod_policy;
pub mod threat_model;
pub mod toml;
pub mod topology;

pub use admissibility_plan::{ALL_KINDS, DispositionFamily, PlanAdmissibility};
pub use capability_caveats::CapabilityCaveats;
pub use foundations::{FoundationPin, FoundationStack, RegistryEpoch};
pub use g0::{
    ApplicationDifferenceKindRow, ConversionLawRow, ConversionLaws, FormatRow, Formats, FxLawRow,
    FxLaws, IfrsRuleRow, IntradayOrderRow, LotLawRow, LotLaws, ReplenishmentModeRow, TracingLawRow,
    TracingLaws,
};

use core::fmt;
use std::collections::BTreeMap;

use fa_time::{PeriodKind, PeriodState};

use crate::toml::{Document, Table, TomlError, Value};

const EXIT_CODES: &str = include_str!("../../../registries/exit_codes.toml");
const ENTRY_CLASSES: &str = include_str!("../../../registries/entry_classes.toml");
const INTENTS: &str = include_str!("../../../registries/intents.toml");
const ADMISSIBILITY: &str = include_str!("../../../registries/admissibility.toml");
const UNITS: &str = include_str!("../../../registries/units.toml");
const ROUNDING_LAWS: &str = include_str!("../../../registries/rounding_laws.toml");
const SYMBOLS: &str = include_str!("../../../registries/symbols.toml");

/// The law registries `fa law list|show` reads, embedded at build time:
/// `(family, the array that holds its laws, the registry text)` (plan
/// §6.2–§6.4; Appendix D "Chart and registries").
pub const LAW_REGISTRIES: [(&str, &str, &str); 6] = [
    ("rounding", "law", ROUNDING_LAWS),
    (
        "allocation",
        "law",
        include_str!("../../../registries/allocation_laws.toml"),
    ),
    ("conversion", "conversion_law", g0::CONVERSION_LAWS_TOML),
    ("fx", "law", g0::FX_LAWS_TOML),
    ("lot", "law", g0::LOT_LAWS_TOML),
    ("tracing", "law", g0::TRACING_LAWS_TOML),
];

/// units.toml as embedded, the unit versions `fa unit list` reads.
pub const UNITS_REGISTRY: &str = UNITS;

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
    pub carries_open_items: bool,
}

#[derive(Clone, Debug, Default)]
pub struct EntryClasses {
    pub rows: Vec<EntryClass>,
}

impl EntryClasses {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::parse(ENTRY_CLASSES)
    }

    pub fn parse(text: &str) -> Result<Self, RegistryError> {
        const R: &str = "entry_classes.toml";
        let doc = load(R, text)?;
        let mut rows = Vec::new();
        for t in doc.arrays.get("class").unwrap_or(&Vec::new()) {
            let tag = req_int(R, t, "tag")?;
            let name = req_str(R, t, "name")?.to_string();
            let kind = match req_str(R, t, "kind")? {
                "posting" => ClassKind::Posting,
                "control" => ClassKind::Control,
                other => return Err(invalid(R, format!("unknown class kind `{other}`"))),
            };
            let carries_open_items = match kind {
                ClassKind::Posting => t
                    .get("carries_open_items")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| {
                        invalid(
                            R,
                            format!(
                                "posting class `{name}` must declare boolean `carries_open_items`"
                            ),
                        )
                    })?,
                ClassKind::Control => {
                    if t.get("carries_open_items").and_then(Value::as_bool) == Some(true) {
                        return Err(invalid(
                            R,
                            format!("control class `{name}` cannot carry open items"),
                        ));
                    }
                    false
                }
            };
            rows.push(EntryClass {
                tag: u16::try_from(tag)
                    .map_err(|_| invalid(R, format!("tag {tag} out of range")))?,
                name,
                kind,
                supersession: req_str(R, t, "supersession")?.to_string(),
                carries_open_items,
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
// Intent dependencies (plan §5.10)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DependencyClass {
    Point,
    Aggregate,
}

/// Dependency law for the current kernel plan protocols. A PostEntry's class
/// refines its intent kind; an unregistered pair never inherits `Point`.
#[derive(Clone, Debug)]
pub struct IntentDependencies {
    rows: BTreeMap<(String, Option<u16>), DependencyClass>,
}

impl IntentDependencies {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::parse(&EntryClasses::embedded()?, INTENTS)
    }

    pub fn parse(classes: &EntryClasses, text: &str) -> Result<Self, RegistryError> {
        const R: &str = "intents.toml";
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "unsupported schema_version"));
        }
        let mut rows = BTreeMap::new();
        for row in doc.arrays.get("intent").into_iter().flatten() {
            let name = req_str(R, row, "name")?;
            let class = match name {
                "PostEntry" => {
                    let class_name = req_str(R, row, "entry_class")?;
                    let class = classes
                        .by_name(class_name)
                        .filter(|c| c.kind == ClassKind::Posting)
                        .ok_or_else(|| {
                            invalid(R, format!("unknown posting class `{class_name}`"))
                        })?;
                    Some(class.tag)
                }
                "FinalizeMigration" | "AbandonMigration" => {
                    if row.contains_key("entry_class") {
                        return Err(invalid(R, format!("`{name}` has no entry_class selector")));
                    }
                    None
                }
                other => return Err(invalid(R, format!("unknown intent `{other}`"))),
            };
            let dependency = match req_str(R, row, "dependency_class")? {
                "point" => DependencyClass::Point,
                "aggregate" => DependencyClass::Aggregate,
                other => return Err(invalid(R, format!("unknown dependency_class `{other}`"))),
            };
            if rows.insert((name.to_string(), class), dependency).is_some() {
                return Err(invalid(
                    R,
                    format!("duplicate intent selector `{name}`/{class:?}"),
                ));
            }
        }
        let registry = Self { rows };
        for class in classes.posting() {
            registry.get("PostEntry", Some(class.tag))?;
        }
        for intent in ["FinalizeMigration", "AbandonMigration"] {
            registry.get(intent, None)?;
        }
        Ok(registry)
    }

    pub fn get(
        &self,
        intent: &str,
        entry_class: Option<u16>,
    ) -> Result<DependencyClass, RegistryError> {
        self.rows
            .get(&(intent.to_string(), entry_class))
            .copied()
            .ok_or_else(|| {
                invalid(
                    "intents.toml",
                    format!("missing dependency_class for `{intent}`/{entry_class:?}"),
                )
            })
    }
}

// ---------------------------------------------------------------------------
// Control kinds (fa-g23)
// ---------------------------------------------------------------------------

/// One registered `EntryOrigin::Control.control_kind`: the act that mints a
/// control record of `class`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlKindRow {
    pub id: u16,
    pub name: String,
    pub class: String,
    pub minted_by: String,
}

/// An id held for a control class that has not landed yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservedControlKind {
    pub id: u16,
    pub name: String,
    pub holder: String,
}

/// The `[[control_kind]]` table of `entry_classes.toml`.
#[derive(Clone, Debug, Default)]
pub struct ControlKinds {
    pub rows: Vec<ControlKindRow>,
    pub reserved: Vec<ReservedControlKind>,
}

impl ControlKinds {
    pub fn embedded(classes: &EntryClasses) -> Result<Self, RegistryError> {
        Self::parse(classes, ENTRY_CLASSES)
    }

    /// The laws: ids (rows and reservations together) are unique and dense
    /// from 1; names are unique; every row names a registered control class
    /// and the code that mints it.
    pub fn parse(classes: &EntryClasses, text: &str) -> Result<Self, RegistryError> {
        const R: &str = "entry_classes.toml";
        let doc = load(R, text)?;
        let id_of = |t: &Table| -> Result<u16, RegistryError> {
            let id = req_int(R, t, "id")?;
            u16::try_from(id).map_err(|_| invalid(R, format!("control kind id {id} out of range")))
        };
        let mut rows = Vec::new();
        for t in doc.arrays.get("control_kind").unwrap_or(&Vec::new()) {
            let row = ControlKindRow {
                id: id_of(t)?,
                name: req_str(R, t, "name")?.to_string(),
                class: req_str(R, t, "class")?.to_string(),
                minted_by: req_str(R, t, "minted_by")?.to_string(),
            };
            match classes.by_name(&row.class) {
                Some(c) if c.kind == ClassKind::Control => {}
                Some(_) => {
                    return Err(invalid(
                        R,
                        format!(
                            "control kind `{}` names `{}`, a posting class",
                            row.name, row.class
                        ),
                    ));
                }
                None => {
                    return Err(invalid(
                        R,
                        format!(
                            "control kind `{}` names unregistered class `{}`",
                            row.name, row.class
                        ),
                    ));
                }
            }
            if row.minted_by.trim().is_empty() {
                return Err(invalid(
                    R,
                    format!("control kind `{}` names no minting code", row.name),
                ));
            }
            rows.push(row);
        }
        let mut reserved = Vec::new();
        for t in doc
            .arrays
            .get("reserved_control_kind")
            .unwrap_or(&Vec::new())
        {
            reserved.push(ReservedControlKind {
                id: id_of(t)?,
                name: req_str(R, t, "name")?.to_string(),
                holder: req_str(R, t, "holder")?.to_string(),
            });
        }
        if rows.is_empty() {
            return Err(invalid(R, "no control kinds"));
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        for (id, name) in rows
            .iter()
            .map(|r| (r.id, r.name.as_str()))
            .chain(reserved.iter().map(|r| (r.id, r.name.as_str())))
        {
            if !ids.insert(id) {
                return Err(invalid(R, format!("duplicate control kind id {id}")));
            }
            if !names.insert(name) {
                return Err(invalid(R, format!("duplicate control kind `{name}`")));
            }
        }
        if let Some((missing, _)) = (1u16..).zip(&ids).find(|(want, got)| want != *got) {
            return Err(invalid(
                R,
                format!("control kind ids are not dense from 1: {missing} is missing"),
            ));
        }
        Ok(Self { rows, reserved })
    }

    pub fn by_id(&self, id: u16) -> Option<&ControlKindRow> {
        self.rows.iter().find(|r| r.id == id)
    }

    pub fn by_name(&self, name: &str) -> Option<&ControlKindRow> {
        self.rows.iter().find(|r| r.name == name)
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

pub const ALL_STATES: [PeriodState; 5] = [
    PeriodState::Future,
    PeriodState::Open,
    PeriodState::SoftClosed,
    PeriodState::Closed,
    PeriodState::Locked,
];

/// A period kind's rule (plan §7.2, Appendix C "Period kinds"): the
/// classes it admits — every other class is refused with `refusal`,
/// whatever the period's state — and the code every transition of such a
/// period is refused with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KindRule {
    pub admits: Vec<String>,
    pub refusal: String,
    pub transition_refusal: String,
}

impl KindRule {
    #[must_use]
    pub fn admits(&self, class: &str) -> bool {
        self.admits.iter().any(|c| c == class)
    }
}

/// A special period narrows posting classes without changing the period's
/// transition law. Historical restrictions are applied separately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecialPeriodRule {
    pub admits: Vec<String>,
    pub refusal: String,
    pub cite: String,
}

impl SpecialPeriodRule {
    #[must_use]
    pub fn admits(&self, class: &str) -> bool {
        self.admits.iter().any(|c| c == class)
    }
}

/// The rule for special periods before the book's opening date (plan §7.2,
/// `[[pre_opening]]`, ruling 3685): a period of one of `kinds` ending on or
/// before the opening date is born `born`, keeps its kind, admits only
/// `admits` (others are refused with `refusal`, whatever its state) and
/// refuses every transition with `transition_refusal`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreOpeningRule {
    pub kinds: Vec<PeriodKind>,
    pub born: PeriodState,
    pub admits: Vec<String>,
    pub refusal: String,
    pub transition_refusal: String,
    pub cite: String,
}

impl PreOpeningRule {
    #[must_use]
    pub fn admits(&self, class: &str) -> bool {
        self.admits.iter().any(|c| c == class)
    }

    /// Whether a period of `kind` ending at `end` is governed by this rule
    /// in a book whose opening date is `opening_date`.
    #[must_use]
    pub fn governs(
        &self,
        kind: PeriodKind,
        end: fa_time::DateDay,
        opening_date: Option<fa_time::DateDay>,
    ) -> bool {
        self.kinds.contains(&kind) && opening_date.is_some_and(|day| end <= day)
    }
}

fn kind_from_name(name: &str) -> Option<PeriodKind> {
    Some(match name {
        "Normal" => PeriodKind::Normal,
        "Adjustment" => PeriodKind::Adjustment,
        "Opening" => PeriodKind::Opening,
        "Closing" => PeriodKind::Closing,
        "Historical" => PeriodKind::Historical,
        _ => return None,
    })
}

fn is_refusal_code(code: &str) -> bool {
    code.strip_prefix("FA-REF-")
        .is_some_and(|n| n.len() == 3 && n.bytes().all(|b| b.is_ascii_digit()))
}

#[derive(Clone, Debug, Default)]
pub struct Admissibility {
    cells: BTreeMap<(String, PeriodState), (Decision, Option<String>, Qualifier)>,
    /// Rules by period kind (`[[kind]]` rows).
    kinds: BTreeMap<String, KindRule>,
    /// Explicit class allowlists for Opening, Adjustment and Closing.
    special_periods: BTreeMap<String, SpecialPeriodRule>,
    /// The special periods before the book's opening date (`[[pre_opening]]`).
    pre_opening: Option<PreOpeningRule>,
    /// `Resolution(Expires)`, the expiry sweep's release, decided per state
    /// by its own rows (`disposition = "Expires"`, plan §5.4, Appendix C).
    expires: BTreeMap<PeriodState, (Decision, Option<String>)>,
}

impl Admissibility {
    pub fn embedded(classes: &EntryClasses) -> Result<Self, RegistryError> {
        Self::parse(classes, ADMISSIBILITY)
    }

    /// Parse a matrix in the `admissibility.toml` format (the embedded one,
    /// or a planted variant in a test).
    pub fn parse(classes: &EntryClasses, text: &str) -> Result<Self, RegistryError> {
        const R: &str = "admissibility.toml";
        let doc = load(R, text)?;
        let mut cells = BTreeMap::new();
        let mut expires = BTreeMap::new();
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
            if let Some(disposition) = t.get("disposition") {
                if class != "Resolution" || disposition.as_str() != Some("Expires") {
                    return Err(invalid(
                        R,
                        format!(
                            "({class}, {state_s}): only Resolution has disposition rows, and only Expires (Posts and Voids follow the class cell)"
                        ),
                    ));
                }
                if expires.insert(state, (decision, note)).is_some() {
                    return Err(invalid(
                        R,
                        format!("cell (Resolution(Expires), {state_s}) decided twice"),
                    ));
                }
                continue;
            }
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
        // Exhaustiveness: every posting class × every state exactly once, and
        // the sweep's Resolution(Expires) × every state exactly once.
        for c in classes.posting() {
            for s in ALL_STATES {
                if !cells.contains_key(&(c.name.clone(), s)) {
                    return Err(invalid(
                        R,
                        format!("undecided cell ({}, {})", c.name, s.name()),
                    ));
                }
            }
        }
        for s in ALL_STATES {
            if !expires.contains_key(&s) {
                return Err(invalid(
                    R,
                    format!("undecided cell (Resolution(Expires), {})", s.name()),
                ));
            }
        }
        let mut kinds = BTreeMap::new();
        for t in doc.arrays.get("kind").unwrap_or(&Vec::new()) {
            let name = req_str(R, t, "name")?;
            match kind_from_name(name) {
                None => return Err(invalid(R, format!("unknown period kind `{name}`"))),
                Some(PeriodKind::Normal) => {
                    return Err(invalid(
                        R,
                        "a Normal period is decided by the cells alone; it has no kind row",
                    ));
                }
                Some(_) => {}
            }
            let admits: Vec<String> = t
                .get("admits")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid(R, format!("kind `{name}`: `admits` must be a list")))?
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| invalid(R, format!("kind `{name}`: `admits` names classes")))
                })
                .collect::<Result<_, _>>()?;
            for class in &admits {
                if classes
                    .by_name(class)
                    .is_none_or(|c| c.kind != ClassKind::Posting)
                {
                    return Err(invalid(
                        R,
                        format!("kind `{name}` admits `{class}`, which is not a posting class"),
                    ));
                }
            }
            let refusal = req_str(R, t, "refusal")?.to_string();
            let transition_refusal = req_str(R, t, "transition_refusal")?.to_string();
            for code in [&refusal, &transition_refusal] {
                if !is_refusal_code(code) {
                    return Err(invalid(
                        R,
                        format!("kind `{name}`: `{code}` is not a refusal code"),
                    ));
                }
            }
            let rule = KindRule {
                admits,
                refusal,
                transition_refusal,
            };
            if kinds.insert(name.to_string(), rule).is_some() {
                return Err(invalid(R, format!("kind `{name}` has two rows")));
            }
        }
        if !kinds.contains_key("Historical") {
            return Err(invalid(
                R,
                "the Historical kind has no row: what its periods admit is unregistered",
            ));
        }
        let mut special_periods = BTreeMap::new();
        for t in doc
            .arrays
            .get("special_period_classes")
            .unwrap_or(&Vec::new())
        {
            let name = req_str(R, t, "kind")?;
            if !matches!(
                kind_from_name(name),
                Some(PeriodKind::Opening | PeriodKind::Adjustment | PeriodKind::Closing)
            ) {
                return Err(invalid(
                    R,
                    format!("special_period_classes: `{name}` is not a special period kind"),
                ));
            }
            let admits: Vec<String> = t
                .get("admits")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    invalid(
                        R,
                        format!("special period `{name}`: `admits` must be a list"),
                    )
                })?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_string)
                        .ok_or_else(|| invalid(R, "special-period admission names classes"))
                })
                .collect::<Result<_, _>>()?;
            let mut seen = std::collections::BTreeSet::new();
            for class in &admits {
                if classes
                    .by_name(class)
                    .is_none_or(|c| c.kind != ClassKind::Posting)
                {
                    return Err(invalid(
                        R,
                        format!(
                            "special period `{name}` admits `{class}`, which is not a posting class"
                        ),
                    ));
                }
                if !seen.insert(class) {
                    return Err(invalid(
                        R,
                        format!("special period `{name}` repeats class `{class}`"),
                    ));
                }
            }
            if admits.is_empty() {
                return Err(invalid(
                    R,
                    format!("special period `{name}` has no admitted classes"),
                ));
            }
            let refusal = req_str(R, t, "refusal")?.to_string();
            if !is_refusal_code(&refusal) {
                return Err(invalid(
                    R,
                    format!("special period `{name}`: `{refusal}` is not a refusal code"),
                ));
            }
            let rule = SpecialPeriodRule {
                admits,
                refusal,
                cite: req_str(R, t, "cite")?.to_string(),
            };
            if special_periods.insert(name.into(), rule).is_some() {
                return Err(invalid(R, format!("special period `{name}` has two rows")));
            }
        }
        for name in ["Opening", "Adjustment", "Closing"] {
            if !special_periods.contains_key(name) {
                return Err(invalid(
                    R,
                    format!("special period `{name}` has no class admission row"),
                ));
            }
        }
        let tables = doc.arrays.get("pre_opening").map_or(&[][..], Vec::as_slice);
        let [t] = tables else {
            return Err(invalid(
                R,
                format!(
                    "exactly one [[pre_opening]] table governs the special periods before the opening date ({} found)",
                    tables.len()
                ),
            ));
        };
        let names = |key: &str| -> Result<Vec<String>, RegistryError> {
            t.get(key)
                .and_then(Value::as_array)
                .ok_or_else(|| invalid(R, format!("pre_opening: `{key}` must be a list")))?
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| invalid(R, format!("pre_opening: `{key}` names strings")))
                })
                .collect()
        };
        let mut pre_kinds = Vec::new();
        for name in names("kinds")? {
            match kind_from_name(&name) {
                None => return Err(invalid(R, format!("pre_opening: unknown kind `{name}`"))),
                Some(PeriodKind::Normal | PeriodKind::Historical) => {
                    return Err(invalid(
                        R,
                        format!("pre_opening governs special periods only, not `{name}`"),
                    ));
                }
                Some(k) => pre_kinds.push(k),
            }
        }
        let admits = names("admits")?;
        for class in &admits {
            if classes
                .by_name(class)
                .is_none_or(|c| c.kind != ClassKind::Posting)
            {
                return Err(invalid(
                    R,
                    format!("pre_opening admits `{class}`, which is not a posting class"),
                ));
            }
        }
        let born_s = req_str(R, t, "born")?;
        let born = PeriodState::from_name(born_s)
            .ok_or_else(|| invalid(R, format!("pre_opening: unknown state `{born_s}`")))?;
        let refusal = req_str(R, t, "refusal")?.to_string();
        let transition_refusal = req_str(R, t, "transition_refusal")?.to_string();
        for code in [&refusal, &transition_refusal] {
            if !is_refusal_code(code) {
                return Err(invalid(
                    R,
                    format!("pre_opening: `{code}` is not a refusal code"),
                ));
            }
        }
        let pre_opening = Some(PreOpeningRule {
            kinds: pre_kinds,
            born,
            admits,
            refusal,
            transition_refusal,
            cite: req_str(R, t, "cite")?.to_string(),
        });
        Ok(Self {
            cells,
            expires,
            kinds,
            special_periods,
            pre_opening,
        })
    }

    /// The rule for special periods before the book's opening date (always
    /// present in a parsed matrix).
    #[must_use]
    pub fn pre_opening(&self) -> Option<&PreOpeningRule> {
        self.pre_opening.as_ref()
    }

    /// The rule for periods of `kind`, when the kind has one (plan §7.2).
    #[must_use]
    pub fn kind_rule(&self, kind: PeriodKind) -> Option<&KindRule> {
        let name = match kind {
            PeriodKind::Normal => return None,
            PeriodKind::Adjustment => "Adjustment",
            PeriodKind::Opening => "Opening",
            PeriodKind::Closing => "Closing",
            PeriodKind::Historical => "Historical",
        };
        self.kinds.get(name)
    }

    /// Class admission for live special periods (plan §7.3). The caller
    /// also applies the ordinary state matrix and any pre-opening rule.
    #[must_use]
    pub fn special_period_rule(&self, kind: PeriodKind) -> Option<&SpecialPeriodRule> {
        let name = match kind {
            PeriodKind::Opening => "Opening",
            PeriodKind::Adjustment => "Adjustment",
            PeriodKind::Closing => "Closing",
            PeriodKind::Normal | PeriodKind::Historical => return None,
        };
        self.special_periods.get(name)
    }

    pub fn decide(&self, class: &str, state: PeriodState) -> Option<&Decision> {
        self.cells.get(&(class.to_string(), state)).map(|(d, ..)| d)
    }

    /// The registered decision for the expiry sweep's `Resolution(Expires)`
    /// in a period of `state` (its own `disposition = "Expires"` rows).
    pub fn decide_expires(&self, state: PeriodState) -> Option<&Decision> {
        self.expires.get(&state).map(|(d, _)| d)
    }

    /// The cell's decision for one disposition family (plan §5.4): `release`
    /// is true for `Voids`, false for `Posts` and for every class that has no
    /// dispositions (where this equals [`Self::decide`]). `Expires` is decided
    /// by its own rows ([`Self::decide_expires`]).
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

    /// Every class a period of `state` admits for one disposition family
    /// (`release` as in [`Self::decide_disposition`]), in class order, with
    /// its decision (`Admit`, or the op and approvals a `with:` cell
    /// requires). A refusal's fix names only these, so it never suggests a
    /// class the matrix refuses.
    #[must_use]
    pub fn admitting(&self, state: PeriodState, release: bool) -> Vec<(&str, Decision)> {
        self.cells
            .keys()
            .filter(|(_, s)| *s == state)
            .filter_map(|(class, _)| {
                let decision = self.decide_disposition(class, state, release)?;
                (decision != Decision::Refuse).then_some((class.as_str(), decision))
            })
            .collect()
    }

    pub fn note(&self, class: &str, state: PeriodState) -> Option<&str> {
        self.cells
            .get(&(class.to_string(), state))
            .and_then(|(_, n, _)| n.as_deref())
    }

    /// Leading qualifier tag (`case`, `run`, `posts_only_with`, `voids_expires`) on `(class, state)`, if any.
    #[must_use]
    pub fn qualifier_tag(&self, class: &str, state: PeriodState) -> Option<&str> {
        let note = self.note(class, state)?;
        let head = note.split(':').next()?.trim();
        match head {
            "case" | "run" | "posts_only_with" | "voids_expires" => Some(head),
            _ => None,
        }
    }

    /// Evaluate the complete admissibility cell `(class, state, family, kind, pre_opening)`.
    #[must_use]
    pub fn decide_cell(
        &self,
        class: &str,
        state: PeriodState,
        family: DispositionFamily,
        kind: PeriodKind,
        pre_opening: bool,
    ) -> Option<Decision> {
        if let Some(rule) = self.kind_rule(kind)
            && !rule.admits(class)
        {
            return Some(Decision::Refuse);
        }
        if pre_opening
            && let Some(rule) = self.pre_opening()
            && rule.kinds.contains(&kind)
            && !rule.admits(class)
        {
            return Some(Decision::Refuse);
        }
        if let Some(rule) = self.special_period_rule(kind)
            && !rule.admits(class)
        {
            return Some(Decision::Refuse);
        }
        match family {
            DispositionFamily::Expires if class == "Resolution" => {
                self.decide_expires(state).cloned()
            }
            DispositionFamily::Expires | DispositionFamily::Voids => {
                self.decide_disposition(class, state, true)
            }
            DispositionFamily::Standard => self.decide_disposition(class, state, false),
        }
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
    pub id: u32,
    pub code: String,
    pub version: u16,
    pub scale: u8,
    pub kind: String,
    pub iso4217: Option<u16>,
    pub rounding_default: u16,
    pub balance_policy: String,
}

pub fn units_embedded() -> Result<Vec<UnitRow>, RegistryError> {
    parse_units(UNITS)
}

/// Parse explicit, append-only unit identities and their immutable defaults.
pub fn parse_units(text: &str) -> Result<Vec<UnitRow>, RegistryError> {
    const R: &str = "units.toml";
    let doc = load(R, text)?;
    let rounding_laws = rounding_laws_embedded()?;
    let mut rows = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for t in doc.arrays.get("unit").unwrap_or(&Vec::new()) {
        let id =
            u32::try_from(req_int(R, t, "id")?).map_err(|_| invalid(R, "unit id out of range"))?;
        if usize::try_from(id).ok() != Some(rows.len()) {
            return Err(invalid(
                R,
                format!("unit id {id} is out of order; expected {}", rows.len()),
            ));
        }
        let code = req_str(R, t, "code")?.to_string();
        if code.is_empty() || code.len() > 64 {
            return Err(invalid(R, "unit code must contain 1..=64 bytes"));
        }
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
        let default_balance_policy = match kind {
            "currency" | "commodity" | "share" => "balanced",
            "time" | "count" | "custom" => "single_sided",
            _ => "balanced",
        };
        let balance_policy = match t.get("balance_policy") {
            None => default_balance_policy.to_string(),
            Some(v) => match v.as_str() {
                Some("balanced" | "single_sided") => v.as_str().unwrap_or("balanced").to_string(),
                _ => {
                    return Err(invalid(
                        R,
                        format!(
                            "`{code}` has invalid balance_policy (expected `balanced` or `single_sided`)"
                        ),
                    ));
                }
            },
        };
        let rounding_default = u16::try_from(req_int(R, t, "rounding_default")?)
            .map_err(|_| invalid(R, "default rounding law out of range"))?;
        if !rounding_laws.iter().any(|law| law.id == rounding_default) {
            return Err(invalid(
                R,
                format!("`{code}` names unregistered default rounding law {rounding_default}"),
            ));
        }
        if !seen.insert((code.clone(), version)) {
            return Err(invalid(R, format!("duplicate unit {code}@v{version}")));
        }
        rows.push(UnitRow {
            id,
            code,
            scale,
            version,
            kind: kind.to_owned(),
            iso4217,
            rounding_default,
            balance_policy,
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
    pub intent_dependencies: IntentDependencies,
    pub control_kinds: ControlKinds,
    pub admissibility: Admissibility,
    pub units: Vec<UnitRow>,
    pub rounding_laws: Vec<RoundingLawRow>,
    pub symbols: Symbols,
}

impl Registries {
    pub fn embedded() -> Result<Self, RegistryError> {
        let entry_classes = EntryClasses::embedded()?;
        let intent_dependencies = IntentDependencies::parse(&entry_classes, INTENTS)?;
        let control_kinds = ControlKinds::embedded(&entry_classes)?;
        let admissibility = Admissibility::embedded(&entry_classes)?;
        Ok(Self {
            exit_codes: ExitCodes::embedded()?,
            entry_classes,
            intent_dependencies,
            control_kinds,
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
    fn every_intent_has_dependency_class() {
        let classes = EntryClasses::embedded().unwrap();
        let registry = IntentDependencies::embedded().unwrap();
        for name in ["Closing", "Revaluation", "Elimination"] {
            let tag = classes.by_name(name).unwrap().tag;
            assert_eq!(
                registry.get("PostEntry", Some(tag)).unwrap(),
                DependencyClass::Aggregate
            );
        }
        for name in [
            "Original",
            "Pending",
            "Resolution",
            "Reversal",
            "Replacement",
            "Reclassification",
            "Adjusting",
            "Allocation",
            "Migration",
            "Revision",
            "Restatement",
            "PriorPeriodAdjustment",
        ] {
            let tag = classes.by_name(name).unwrap().tag;
            assert_eq!(
                registry.get("PostEntry", Some(tag)).unwrap(),
                DependencyClass::Point
            );
        }
        for intent in ["FinalizeMigration", "AbandonMigration"] {
            assert_eq!(
                registry.get(intent, None).unwrap(),
                DependencyClass::Aggregate
            );
        }
        assert_eq!(registry.rows.len(), classes.posting().count() + 2);
        // Unknown kinds/classes are errors even if a caller forgets to extend
        // the registry. Neither a control nor a typo silently becomes point.
        assert!(registry.get("PostEntry", Some(16)).is_err());
        assert!(registry.get("PostEntry", Some(u16::MAX)).is_err());
        assert!(registry.get("PostEntry", None).is_err());
        assert!(registry.get("AllocateAllOfPeriod", None).is_err());

        // Plant each omitted row independently. This exercises completeness,
        // including visibility-only MigrationRun transitions, not just syntax.
        let parts: Vec<_> = INTENTS.split("[[intent]]").collect();
        for omitted in 1..parts.len() {
            let mut missing = parts[0].to_string();
            for (index, part) in parts.iter().enumerate().skip(1) {
                if index != omitted {
                    missing.push_str("[[intent]]");
                    missing.push_str(part);
                }
            }
            assert!(
                IntentDependencies::parse(&classes, &missing).is_err(),
                "omitted row {omitted}"
            );
        }
    }

    #[test]
    fn intent_dependencies_refuse_ambiguous_or_unclassified_rows() {
        let classes = EntryClasses::embedded().unwrap();
        for planted in [
            format!(
                "{INTENTS}\n[[intent]]\nname = \"PostEntry\"\nentry_class = \"Original\"\ndependency_class = \"point\"\n"
            ),
            INTENTS.replacen(
                "dependency_class = \"point\"",
                "dependency_class = \"automatic\"",
                1,
            ),
            INTENTS.replacen("dependency_class = \"point\"", "", 1),
            INTENTS.replacen(
                "entry_class = \"Original\"",
                "entry_class = \"PeriodControl\"",
                1,
            ),
            INTENTS.replacen("name = \"PostEntry\"", "name = \"FutureIntent\"", 1),
            INTENTS.replacen("schema_version = 1", "schema_version = 2", 1),
            INTENTS.replacen(
                "name = \"FinalizeMigration\"",
                "name = \"FinalizeMigration\"\nentry_class = \"Migration\"",
                1,
            ),
        ] {
            assert!(IntentDependencies::parse(&classes, &planted).is_err());
        }
    }

    /// fa-g23: the eight control kinds are registered (6 and 7 held for
    /// their classes), and the laws refuse a planted duplicate id, a gap, a
    /// repeated name, a posting class, an unregistered class, a reservation
    /// colliding with a row, and an empty table.
    #[test]
    fn control_kinds_are_dense_unique_and_name_control_classes() {
        let classes = EntryClasses::embedded().unwrap();
        let kinds = ControlKinds::embedded(&classes).unwrap();
        let mut all: Vec<(u16, &str)> = kinds
            .rows
            .iter()
            .map(|r| (r.id, r.name.as_str()))
            .chain(kinds.reserved.iter().map(|r| (r.id, r.name.as_str())))
            .collect();
        all.sort_unstable();
        assert_eq!(
            all,
            [
                (1, "chart_install"),
                (2, "period_transition"),
                (3, "policy_activation"),
                (4, "time_tick"),
                (5, "schedule_cancel"),
                (6, "import_run"),
                (7, "legal_hold"),
                (8, "capability_revocation"),
                (9, "migration_run"),
                (10, "capability_issuance"),
                (11, "draft_transition"),
                (12, "scenario_transition"),
                (13, "period_creation"),
                (14, "production_transition"),
                (15, "statement_issuance"),
                (16, "engagement_transition"),
                (17, "case_transition"),
                (18, "recurring_schedule"),
            ]
        );
        assert_eq!(
            kinds
                .by_name("capability_revocation")
                .map(|r| (r.id, r.class.as_str())),
            Some((8, "PolicyControl"))
        );
        assert_eq!(
            kinds.by_id(4).map(|r| r.class.as_str()),
            Some("TimeControl")
        );
        let row = |id: u16, name: &str, class: &str| {
            format!(
                "[[control_kind]]\nid = {id}\nname = \"{name}\"\nclass = \"{class}\"\nminted_by = \"test\"\n"
            )
        };
        let cases = [
            (
                format!(
                    "{}{}",
                    row(1, "a", "PeriodControl"),
                    row(1, "b", "TimeControl")
                ),
                "duplicate control kind id 1",
            ),
            (
                format!(
                    "{}{}",
                    row(1, "a", "PeriodControl"),
                    row(3, "b", "TimeControl")
                ),
                "2 is missing",
            ),
            (row(2, "a", "PeriodControl"), "1 is missing"),
            (
                format!(
                    "{}{}",
                    row(1, "a", "PeriodControl"),
                    row(2, "a", "TimeControl")
                ),
                "duplicate control kind `a`",
            ),
            (row(1, "a", "Original"), "a posting class"),
            (row(1, "a", "NoSuchControl"), "unregistered class"),
            (
                format!(
                    "{}[[reserved_control_kind]]\nid = 1\nname = \"b\"\nholder = \"x\"\n",
                    row(1, "a", "PeriodControl")
                ),
                "duplicate control kind id 1",
            ),
            (String::new(), "no control kinds"),
        ];
        for (text, want) in cases {
            let text = format!("schema_version = 1\n{text}");
            let err = ControlKinds::parse(&classes, &text)
                .expect_err(want)
                .to_string();
            assert!(err.contains(want), "{want}: {err}");
        }
    }

    /// fa-ctf: the expiry sweep's `Resolution(Expires)` is decided by its
    /// own registered rows — every state but Future admits (plan §5.4,
    /// Appendix C) — and a matrix missing one, or naming another
    /// disposition, is refused.
    #[test]
    fn expires_rows_are_registered_per_state_and_required() {
        let classes = EntryClasses::embedded().unwrap();
        let m = Admissibility::embedded(&classes).unwrap();
        assert_eq!(
            m.decide_expires(PeriodState::Future),
            Some(&Decision::Refuse)
        );
        for s in [
            PeriodState::Open,
            PeriodState::SoftClosed,
            PeriodState::Closed,
            PeriodState::Locked,
        ] {
            assert_eq!(m.decide_expires(s), Some(&Decision::Admit), "{s:?}");
        }
        let locked_row = "[[cell]]\nclass = \"Resolution\"\ndisposition = \"Expires\"\nstate = \"Locked\"\ndecision = \"admit\"\nnote = \"a reservation release (plan §7.3: Locked admits Voids/Expires)\"\n";
        assert!(ADMISSIBILITY.contains(locked_row), "the Locked Expires row");
        let without = ADMISSIBILITY.replace(locked_row, "");
        let e = Admissibility::parse(&classes, &without).unwrap_err();
        assert!(
            e.to_string()
                .contains("undecided cell (Resolution(Expires), Locked)"),
            "{e}"
        );
        let voids = ADMISSIBILITY.replace(locked_row, &locked_row.replace("Expires", "Voids"));
        let e = Admissibility::parse(&classes, &voids).unwrap_err();
        assert!(e.to_string().contains("only Expires"), "{e}");
        let refusing = ADMISSIBILITY.replace(
            locked_row,
            &locked_row.replace("decision = \"admit\"", "decision = \"refuse\""),
        );
        let planted = Admissibility::parse(&classes, &refusing).unwrap();
        assert_eq!(
            planted.decide_expires(PeriodState::Locked),
            Some(&Decision::Refuse)
        );
    }

    /// Ruling 3654: the Historical kind is registered. Every posting class
    /// is decided against it (only Migration admitted; the rest refused
    /// 010), its transitions are refused 040, the kinds without a row are
    /// decided by the cells alone, and a matrix without the row, or with a
    /// row naming a control class or a malformed code, is refused.
    #[test]
    fn the_historical_kind_is_registered_and_decides_every_posting_class() {
        let classes = EntryClasses::embedded().unwrap();
        let m = Admissibility::embedded(&classes).unwrap();
        let rule = m.kind_rule(PeriodKind::Historical).expect("Historical row");
        for c in classes.posting() {
            assert_eq!(rule.admits(&c.name), c.name == "Migration", "{}", c.name);
        }
        assert_eq!(rule.refusal, "FA-REF-010");
        assert_eq!(rule.transition_refusal, "FA-REF-040");
        for kind in [
            PeriodKind::Normal,
            PeriodKind::Adjustment,
            PeriodKind::Opening,
            PeriodKind::Closing,
        ] {
            assert!(m.kind_rule(kind).is_none(), "{kind:?}");
        }
        let row = "[[kind]]\nname = \"Historical\"\nadmits = [\"Migration\"]\nrefusal = \"FA-REF-010\"\ntransition_refusal = \"FA-REF-040\"\n";
        assert!(ADMISSIBILITY.contains(row), "the Historical row");
        let e = Admissibility::parse(&classes, &ADMISSIBILITY.replace(row, "")).unwrap_err();
        assert!(e.to_string().contains("Historical kind has no row"), "{e}");
        let control =
            ADMISSIBILITY.replace(row, &row.replace("[\"Migration\"]", "[\"PeriodControl\"]"));
        let e = Admissibility::parse(&classes, &control).unwrap_err();
        assert!(e.to_string().contains("not a posting class"), "{e}");
        let malformed = ADMISSIBILITY.replace(row, &row.replace("FA-REF-040", "040"));
        let e = Admissibility::parse(&classes, &malformed).unwrap_err();
        assert!(e.to_string().contains("not a refusal code"), "{e}");
        let twice = ADMISSIBILITY.replace(row, &format!("{row}{row}"));
        let e = Admissibility::parse(&classes, &twice).unwrap_err();
        assert!(e.to_string().contains("two rows"), "{e}");
    }

    #[test]
    fn special_period_class_rules_are_complete_and_distinct_from_transitions() {
        let classes = EntryClasses::embedded().unwrap();
        let matrix = Admissibility::embedded(&classes).unwrap();
        for kind in [
            PeriodKind::Opening,
            PeriodKind::Adjustment,
            PeriodKind::Closing,
        ] {
            let rule = matrix
                .special_period_rule(kind)
                .expect("registered special kind");
            for class in classes.posting() {
                let expected = matches!(
                    class.name.as_str(),
                    "Adjusting"
                        | "Closing"
                        | "Elimination"
                        | "Revision"
                        | "Restatement"
                        | "Migration"
                );
                assert_eq!(
                    rule.admits(&class.name),
                    expected,
                    "{kind:?} {}",
                    class.name
                );
            }
            assert_eq!(rule.refusal, "FA-REF-010");
            assert!(
                matrix.kind_rule(kind).is_none(),
                "live special periods still transition"
            );
        }
        for kind in [PeriodKind::Normal, PeriodKind::Historical] {
            assert!(matrix.special_period_rule(kind).is_none());
        }
        for (from, to) in [
            ("kind = \"Opening\"", "kind = \"Normal\""),
            ("kind = \"Opening\"", "kind = \"Closing\""),
            (
                "[[special_period_classes]]\nkind = \"Opening\"",
                "[[unused]]\nkind = \"Opening\"",
            ),
            (
                "admits = [\"Adjusting\", \"Closing\"",
                "admits = [\"PeriodControl\", \"Closing\"",
            ),
            (
                "admits = [\"Adjusting\", \"Closing\"",
                "admits = [\"Adjusting\", \"Adjusting\"",
            ),
        ] {
            let changed = ADMISSIBILITY.replacen(from, to, 1);
            assert_ne!(changed, ADMISSIBILITY);
            assert!(Admissibility::parse(&classes, &changed).is_err(), "{to}");
        }
    }

    /// Ruling 3685: the pre-opening rule is registered once. Every posting
    /// class is decided against every pre-opening kind (only Migration
    /// admitted), the rule is born Locked and refuses transitions 040, it
    /// governs a special period only when it ends on or before the opening
    /// date, and a matrix without the table, with two, with a Normal kind,
    /// a control class or a malformed code is refused.
    #[test]
    fn the_pre_opening_rule_is_registered_and_decides_every_posting_class() {
        let classes = EntryClasses::embedded().unwrap();
        let m = Admissibility::embedded(&classes).unwrap();
        let rule = m.pre_opening().expect("pre_opening table");
        assert_eq!(
            rule.kinds,
            [
                PeriodKind::Opening,
                PeriodKind::Adjustment,
                PeriodKind::Closing
            ]
        );
        for kind in &rule.kinds {
            for c in classes.posting() {
                assert_eq!(
                    rule.admits(&c.name),
                    c.name == "Migration",
                    "{kind:?} {}",
                    c.name
                );
            }
        }
        assert_eq!(rule.born, PeriodState::Locked);
        assert_eq!(
            (rule.refusal.as_str(), rule.transition_refusal.as_str()),
            ("FA-REF-010", "FA-REF-040")
        );
        let day = |m: u8, d: u8| fa_time::DateDay::from_ymd(2026, m, d).unwrap();
        assert!(rule.governs(PeriodKind::Closing, day(1, 1), Some(day(1, 1))));
        assert!(!rule.governs(PeriodKind::Closing, day(1, 2), Some(day(1, 1))));
        assert!(!rule.governs(PeriodKind::Closing, day(1, 1), None));
        assert!(!rule.governs(PeriodKind::Normal, day(1, 1), Some(day(4, 1))));
        let table = "[[pre_opening]]\nkinds = [\"Opening\", \"Adjustment\", \"Closing\"]\nborn = \"Locked\"\nadmits = [\"Migration\"]\nrefusal = \"FA-REF-010\"\ntransition_refusal = \"FA-REF-040\"\ncite = \"plan §7.2 (periods before the book's opening date)\"\n";
        assert!(ADMISSIBILITY.contains(table), "the pre_opening table");
        for (planted, why) in [
            (
                ADMISSIBILITY.replace(table, ""),
                "exactly one [[pre_opening]]",
            ),
            (
                ADMISSIBILITY.replace(table, &format!("{table}{table}")),
                "exactly one [[pre_opening]]",
            ),
            (
                ADMISSIBILITY.replace(table, &table.replace("\"Opening\", ", "\"Normal\", ")),
                "special periods only",
            ),
            (
                ADMISSIBILITY.replace(
                    table,
                    &table.replace("[\"Migration\"]", "[\"PeriodControl\"]"),
                ),
                "not a posting class",
            ),
            (
                ADMISSIBILITY.replace(table, &table.replace("FA-REF-040", "40")),
                "not a refusal code",
            ),
        ] {
            let e = Admissibility::parse(&classes, &planted).unwrap_err();
            assert!(e.to_string().contains(why), "{why}: {e}");
        }
    }

    #[test]
    fn original_unit_definitions_are_pinned_and_new_ids_are_additive() {
        // Independent fixture: these identities have already been written
        // into amount payloads. Never regenerate it from units.toml.
        let original = [
            (0, "USD", 0, 2, "currency", Some(840), 3),
            (1, "EUR", 0, 2, "currency", Some(978), 3),
            (2, "GBP", 0, 2, "currency", Some(826), 3),
            (3, "JPY", 0, 0, "currency", Some(392), 3),
            (4, "CHF", 0, 2, "currency", Some(756), 3),
            (5, "CAD", 0, 2, "currency", Some(124), 3),
            (6, "AUD", 0, 2, "currency", Some(36), 3),
            (7, "KWD", 0, 3, "currency", Some(414), 3),
            (8, "BTC", 0, 8, "commodity", None, 3),
            (9, "ETH", 0, 18, "commodity", None, 3),
            (10, "SHARE", 0, 6, "share", None, 3),
            (11, "HOUR", 0, 2, "time", None, 3),
            (12, "EACH", 0, 0, "count", None, 3),
        ];
        let rows = units_embedded().unwrap();
        assert!(rows.len() >= original.len(), "existing units were removed");
        for (row, expected) in rows.iter().zip(original) {
            assert_eq!(
                (
                    row.id,
                    row.code.as_str(),
                    row.version,
                    row.scale,
                    row.kind.as_str(),
                    row.iso4217,
                    row.rounding_default,
                ),
                expected,
                "immutable unit {} changed; add a new version instead",
                expected.1
            );
        }
        let appended = format!(
            "{UNITS}\n[[unit]]\nid = {}\ncode = \"NEW\"\nversion = 0\nscale = 2\nkind = \"custom\"\nrounding_default = 3\n",
            rows.len()
        );
        let extended = parse_units(&appended).unwrap();
        assert_eq!(&extended[..rows.len()], rows);
        assert_eq!(extended.len(), rows.len() + 1);
    }

    #[test]
    fn unit_registry_refuses_reordered_missing_duplicate_and_unknown_law_rows() {
        for (text, why) in [
            (UNITS.replacen("id = 0", "id = 1", 1), "out of order"),
            (UNITS.replacen("id = 1\n", "id = 0\n", 1), "out of order"),
            (UNITS.replacen("id = 1\n", "id = 2\n", 1), "out of order"),
            (UNITS.replacen("id = 0\n", "", 1), "missing integer `id`"),
            (
                UNITS.replacen("code = \"EUR\"", "code = \"USD\"", 1),
                "duplicate unit",
            ),
            (
                UNITS.replacen("rounding_default = 3", "rounding_default = 65535", 1),
                "unregistered default rounding",
            ),
        ] {
            let error = parse_units(&text).unwrap_err().to_string();
            assert!(error.contains(why), "{why}: {error}");
        }
    }

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
    fn appendix_c_markdown_matches_admissibility_toml_exhaustively_and_catches_planted_flips() {
        const PLAN: &str =
            include_str!("../../../COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md");
        let r = Registries::embedded().unwrap();
        let plan = PlanAdmissibility::parse(PLAN).expect("Appendix C markdown parses");

        let diff_plan_vs_toml = |plan_mat: &PlanAdmissibility,
                                 toml_mat: &Admissibility|
         -> Option<String> {
            for c in r.entry_classes.posting() {
                let class = c.name.as_str();
                for state in ALL_STATES {
                    let p_qual = plan_mat
                        .qualifiers
                        .get(&(c.name.clone(), state))
                        .map(String::as_str);
                    let t_qual = toml_mat.qualifier_tag(class, state);
                    if p_qual != t_qual {
                        return Some(format!(
                            "qualifier mismatch on ({class}, {state:?}): plan={p_qual:?} toml={t_qual:?}"
                        ));
                    }
                    for family in DispositionFamily::ALL {
                        for kind in ALL_KINDS {
                            for pre_opening in [false, true] {
                                let p_dec =
                                    plan_mat.decide_cell(class, state, family, kind, pre_opening);
                                let t_dec =
                                    toml_mat.decide_cell(class, state, family, kind, pre_opening);
                                if p_dec != t_dec {
                                    return Some(format!(
                                        "cell mismatch on ({class}, {state:?}, {family:?}, {kind:?}, pre_opening={pre_opening}): plan={p_dec:?} toml={t_dec:?}"
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            None
        };

        if let Some(mismatch) = diff_plan_vs_toml(&plan, &r.admissibility) {
            panic!("{mismatch}");
        }

        // Planted negative 1: flip one TOML cell (`Original` in `Open` from `admit` to `refuse`)
        let flipped_toml_text = ADMISSIBILITY.replacen(
            "class = \"Original\"\nstate = \"Open\"\ndecision = \"admit\"",
            "class = \"Original\"\nstate = \"Open\"\ndecision = \"refuse\"",
            1,
        );
        let flipped_toml = Admissibility::parse(&r.entry_classes, &flipped_toml_text)
            .expect("flipped TOML parses");
        let mismatch1 =
            diff_plan_vs_toml(&plan, &flipped_toml).expect("planted TOML flip must be caught");
        assert!(
            mismatch1.contains("(Original, Open, Standard, Normal, pre_opening=false)"),
            "{mismatch1}"
        );

        // Planted negative 2: flip one plan markdown cell (`Reversal` in `Closed` from `W(\`post_closed\`)` to `Refuse`)
        let flipped_plan_md = PLAN.replacen(
            "| `Reversal` | Refuse | Admit | Admit | W(`post_closed`) |",
            "| `Reversal` | Refuse | Admit | Admit | Refuse |",
            1,
        );
        let flipped_plan =
            PlanAdmissibility::parse(&flipped_plan_md).expect("flipped plan markdown parses");
        let mismatch2 = diff_plan_vs_toml(&flipped_plan, &r.admissibility)
            .expect("planted plan markdown flip must be caught");
        assert!(
            mismatch2.contains("(Reversal, Closed, Standard, Normal, pre_opening=false)"),
            "{mismatch2}"
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
                .starts_with("label:AccessEvent=52\nlabel:Account=3\n"),
            "labels sort by name"
        );
    }

    #[test]
    fn posting_classes_require_explicit_carries_open_items_and_reject_planted_omission() {
        let classes = EntryClasses::embedded().unwrap();
        assert_eq!(
            classes.by_name("Allocation").map(|c| c.carries_open_items),
            Some(true)
        );
        assert_eq!(
            classes.by_name("Pending").map(|c| c.carries_open_items),
            Some(false)
        );
        assert_eq!(
            classes.by_name("Reversal").map(|c| c.carries_open_items),
            Some(false)
        );
        assert_eq!(
            classes
                .by_name("PeriodControl")
                .map(|c| c.carries_open_items),
            Some(false)
        );

        let missing_open_items = format!(
            "{ENTRY_CLASSES}\n[[class]]\ntag = 99\nname = \"PlantedPosting\"\nkind = \"posting\"\nsupersession = \"none\"\n"
        );
        let err = EntryClasses::parse(&missing_open_items)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(
                "posting class `PlantedPosting` must declare boolean `carries_open_items`"
            ),
            "{err}"
        );

        let control_open_items = format!(
            "{ENTRY_CLASSES}\n[[class]]\ntag = 99\nname = \"PlantedControl\"\nkind = \"control\"\nsupersession = \"none\"\ncarries_open_items = true\n"
        );
        let err = EntryClasses::parse(&control_open_items)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("control class `PlantedControl` cannot carry open items"),
            "{err}"
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
