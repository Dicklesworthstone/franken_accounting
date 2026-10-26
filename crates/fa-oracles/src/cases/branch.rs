//! Branch classes and their cells (docs/FORENSIC_CASE_STUDIES_PLAN.md §2.6
//! rules 4-5; bead fa-yugf.12, A5a).
//!
//! An input the record does not state is a branch, never a silent choice.
//! Exhaustive enumeration is infeasible, so a branch's values fall into the
//! registered, predicate-derived equivalence classes of
//! `data/case_branch_rules.toml` (residue classes mod 10^round_power, inside
//! or outside a window, ...). [`enumerate`] gives one (expectation, target)'s
//! cells: the product of its branched attributes' classes, with the per-leg
//! assignments the balance law forbids named and set aside ([`feasible`]),
//! record-inconsistent cells kept, and at most the table's `cap` cells. A
//! capped enumeration never yields a single verdict. [`witnesses`] draws
//! concrete members of a cell from the seeded stream, for the runner's
//! property tests.

use fa_registry::procedures::Procedures;
use fa_registry::toml::Value as TomlValue;

use super::Case;
use super::amount::parse_amount;
use super::book::{BookVariant, BranchAttribute, BranchClassDef, StepKind};
use super::date::Day;
use super::error::{LoadError, LoadErrorKind};
use super::expect::{Expectation, Status, Target};
use super::fields::Row;
use super::rows::{root_key_line, row_line};
use super::stream::Stream;
use super::tiers::Tiers;

const TABLE: &str = include_str!("../../data/case_branch_rules.toml");
/// The table's path, as errors name it.
pub const FILE: &str = "case_branch_rules.toml";

closed_set! {
    /// How a rule's input values fall into classes (§2.6 rule 5).
    ClassKind {
        Enum => "enum",
        ResidueMod => "residue_mod",
        InsideWindow => "inside_window",
        BeforeAfter => "before_after",
    }
}

/// A rule's classes, with the parameter values that fix them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClassRule {
    /// The branch class's own values.
    Enum,
    /// Per branched leg: a whole multiple of 10^`power` units, or not.
    ResidueMod { power: u32 },
    /// Inside or outside the last `window_days` days of the period.
    InsideWindow { window_days: u32 },
    /// Before, or on or after, `date`.
    BeforeAfter { date: Day },
}

/// Who reads a branched input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reader {
    /// A procedure at a version with an A4 tier row.
    Procedure { id: String, version: i128 },
    /// A step of `prepare_post_in`, named by its comment text.
    Kernel(String),
}

/// One `[[rule]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchRule {
    pub id: String,
    pub attribute: BranchAttribute,
    pub reader: Reader,
    pub class_rule: ClassRule,
    /// The reader's registry parameters the rule reads.
    pub parameters: Vec<String>,
    /// The closed class list (an empty list leaves an enum rule's values to
    /// its branch classes).
    pub classes: Vec<String>,
    pub code_justification: String,
    pub line: Option<usize>,
}

/// The loaded table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchRules {
    /// The most cells one (expectation, target) enumerates.
    pub cap: usize,
    pub rules: Vec<BranchRule>,
}

impl BranchRules {
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&BranchRule> {
        self.rules.iter().find(|r| r.id == id)
    }

    /// Parses a copy of the table (tests pass edited copies). A procedure
    /// reader must have a tier row at its version, and every parameter a
    /// rule names must be one of the reader's registered parameters.
    ///
    /// # Errors
    ///
    /// Every malformed row.
    pub fn from_text(
        text: &str,
        procedures: &Procedures,
        tiers: &Tiers,
    ) -> Result<Self, Vec<LoadError>> {
        let doc = fa_registry::toml::parse(text).map_err(|e| {
            vec![LoadError {
                file: FILE.into(),
                line: Some(e.line),
                kind: LoadErrorKind::Toml,
                row: None,
                detail: e.message,
            }]
        })?;
        let mut errs = Vec::new();
        let root_err = |key: &str, kind: LoadErrorKind, detail: String| LoadError {
            file: FILE.into(),
            line: root_key_line(text, key),
            kind,
            row: None,
            detail,
        };
        if doc.root.get("schema_version").and_then(TomlValue::as_int) != Some(1) {
            errs.push(root_err(
                "schema_version",
                LoadErrorKind::WrongType,
                "`schema_version` is 1".into(),
            ));
        }
        let cap = match doc.root.get("cap").and_then(TomlValue::as_int) {
            Some(c) if c >= 1 => usize::try_from(c).unwrap_or(usize::MAX),
            _ => {
                errs.push(root_err(
                    "cap",
                    LoadErrorKind::WrongType,
                    "`cap` is a positive integer".into(),
                ));
                1
            }
        };
        let mut rules: Vec<BranchRule> = Vec::new();
        for (i, table) in doc
            .arrays
            .get("rule")
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .enumerate()
        {
            let mut r = Row::new(FILE, row_line(text, "rule", i), table);
            let id = r.req_str("id", &mut errs);
            let attribute = r.req_str("attribute", &mut errs);
            let reader = r.req_str("reader", &mut errs);
            let class_rule = r.req_str("class_rule", &mut errs);
            let class_param = r.opt_str("class_param", &mut errs);
            let parameters = r.req_strs("parameters", &mut errs);
            let classes = r.req_strs("classes", &mut errs);
            let code_justification = r.req_str("code_justification", &mut errs);
            r.finish(&[], " in `[[rule]]`", &mut errs);
            let line = r.line();
            let mut fail = |kind: LoadErrorKind, detail: String| {
                errs.push(r.err(kind, detail));
            };
            if rules.iter().any(|x| x.id == id) {
                fail(LoadErrorKind::DuplicateId, format!("rule `{id}` twice"));
            }
            let Some(attribute) = BranchAttribute::parse(&attribute) else {
                fail(
                    LoadErrorKind::UnknownValue,
                    format!("`attribute = \"{attribute}\"` is outside the §2.6 enum"),
                );
                continue;
            };
            let reader = match reader.strip_prefix("kernel:") {
                Some(step) if !step.trim().is_empty() => Reader::Kernel(step.to_string()),
                Some(_) => {
                    fail(
                        LoadErrorKind::WrongType,
                        "`reader = \"kernel:\"` names its prepare_post_in step".into(),
                    );
                    continue;
                }
                None => {
                    let parsed = reader
                        .split_once('@')
                        .and_then(|(p, v)| Some((p.to_string(), v.parse::<i128>().ok()?)));
                    let Some((pid, version)) = parsed else {
                        fail(
                            LoadErrorKind::WrongType,
                            format!(
                                "`reader = \"{reader}\"` is <procedure>@<version> or kernel:<step>"
                            ),
                        );
                        continue;
                    };
                    match tiers.get(&pid) {
                        Some(t) if t.version == version => {}
                        Some(t) => fail(
                            LoadErrorKind::DanglingKey,
                            format!(
                                "reader `{reader}` has no tier row at its version (the row reads @{}; A4)",
                                t.version
                            ),
                        ),
                        None => fail(
                            LoadErrorKind::DanglingKey,
                            format!("reader `{reader}` has no tier row (A4)"),
                        ),
                    }
                    Reader::Procedure { id: pid, version }
                }
            };
            let registered = |name: &str| -> Option<i128> {
                let Reader::Procedure { id, .. } = &reader else {
                    return None;
                };
                procedures
                    .get(id)
                    .and_then(|p| p.parameter(name))
                    .map(|p| p.default)
            };
            for p in &parameters {
                if registered(p).is_none() {
                    fail(
                        LoadErrorKind::UnknownValue,
                        format!("`{p}` is not a registered parameter of the reader"),
                    );
                }
            }
            let Some(kind) = ClassKind::parse(&class_rule) else {
                fail(
                    LoadErrorKind::UnknownValue,
                    format!(
                        "`class_rule = \"{class_rule}\"` is enum, residue_mod, inside_window or before_after"
                    ),
                );
                continue;
            };
            let param_value = |fail: &mut dyn FnMut(LoadErrorKind, String)| -> Option<u32> {
                let Some(name) = class_param.as_deref() else {
                    fail(
                        LoadErrorKind::MissingField,
                        format!("a {class_rule} rule names its `class_param`"),
                    );
                    return None;
                };
                if !parameters.iter().any(|p| p == name) {
                    fail(
                        LoadErrorKind::UnknownValue,
                        format!("`class_param = \"{name}\"` is not among the rule's `parameters`"),
                    );
                    return None;
                }
                registered(name).and_then(|v| u32::try_from(v).ok())
            };
            let class_rule = match kind {
                ClassKind::Enum => ClassRule::Enum,
                ClassKind::ResidueMod => match param_value(&mut fail) {
                    Some(power) => ClassRule::ResidueMod { power },
                    None => continue,
                },
                ClassKind::InsideWindow => match param_value(&mut fail) {
                    Some(window_days) => ClassRule::InsideWindow { window_days },
                    None => continue,
                },
                ClassKind::BeforeAfter => match class_param.as_deref().and_then(Day::parse) {
                    Some(date) => ClassRule::BeforeAfter { date },
                    None => {
                        fail(
                            LoadErrorKind::WrongType,
                            "a before_after rule's `class_param` is a YYYY-MM-DD date".into(),
                        );
                        continue;
                    }
                },
            };
            let fixed: &[&str] = match &class_rule {
                ClassRule::Enum => &[],
                ClassRule::ResidueMod { .. } => &["multiple", "non_multiple"],
                ClassRule::InsideWindow { .. } => &["inside_window", "outside_window"],
                ClassRule::BeforeAfter { .. } => &["before", "on_or_after"],
            };
            if !fixed.is_empty() && classes != fixed {
                fail(
                    LoadErrorKind::UnknownValue,
                    format!("a {} rule's `classes` are {fixed:?}", kind.as_str()),
                );
            }
            if matches!(class_rule, ClassRule::ResidueMod { .. })
                && !matches!(
                    attribute,
                    BranchAttribute::LegSplit | BranchAttribute::AmountPrecision
                )
            {
                fail(
                    LoadErrorKind::UnknownValue,
                    format!(
                        "a residue_mod rule branches a per-leg attribute, not `{}`",
                        attribute.as_str()
                    ),
                );
            }
            rules.push(BranchRule {
                id,
                attribute,
                reader,
                class_rule,
                parameters,
                classes,
                code_justification,
                line,
            });
        }
        if errs.is_empty() {
            Ok(Self { cap, rules })
        } else {
            Err(errs)
        }
    }
}

/// The committed table, checked against `registries/procedures.toml` and
/// A4's tier table.
///
/// # Errors
///
/// Every malformed row, or a registry that does not load.
pub fn rules() -> Result<BranchRules, Vec<LoadError>> {
    let procedures = Procedures::embedded().map_err(|e| {
        vec![LoadError {
            file: "registries/procedures.toml".into(),
            line: None,
            kind: LoadErrorKind::Toml,
            row: None,
            detail: e.to_string(),
        }]
    })?;
    BranchRules::from_text(TABLE, &procedures, &super::tiers::tiers()?)
}

/// The class of a branch value an enum rule's closed list admits: a
/// `manual_assertion(<code>)` value is the `manual_assertion` class.
fn class_of(value: &str) -> &str {
    value
        .split_once('(')
        .filter(|(_, rest)| rest.ends_with(')'))
        .map_or(value, |(head, _)| head)
}

/// Why a `[[branch_class]]` is not a branch under its rule, if it is not:
/// it names no rule, a rule of another attribute, no values, or a value
/// outside the rule's classes (the book loader's check).
#[must_use]
pub fn class_problem(rules: &BranchRules, class: &BranchClassDef) -> Option<String> {
    let Some(rule) = rules.get(&class.rule) else {
        return Some(format!(
            "branch class `{}`: `rule = \"{}\"` names no rule of {FILE}",
            class.id, class.rule
        ));
    };
    if rule.attribute.as_str() != class.attribute {
        return Some(format!(
            "branch class `{}` branches `{}`, but rule `{}` branches `{}`",
            class.id,
            class.attribute,
            rule.id,
            rule.attribute.as_str()
        ));
    }
    if class.values.is_empty() {
        return Some(format!(
            "branch class `{}` lists no values: an emptied branch set is no branch (§2.6 rule 4)",
            class.id
        ));
    }
    if !rule.classes.is_empty()
        && let Some(v) = class
            .values
            .iter()
            .find(|v| !rule.classes.iter().any(|c| c == class_of(v)))
    {
        return Some(format!(
            "branch class `{}`: `{v}` is not a class of rule `{}` ({:?})",
            class.id, rule.id, rule.classes
        ));
    }
    None
}

/// A branched leg's residue class modulo 10^p units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResidueClass {
    /// A whole multiple (`m`).
    Multiple,
    /// Not a whole multiple (`n`).
    NonMultiple,
}

impl ResidueClass {
    const fn letter(self) -> char {
        match self {
            Self::Multiple => 'm',
            Self::NonMultiple => 'n',
        }
    }
}

/// Whether amounts exist with these residue classes, each at least one minor
/// unit (a multiple at least one `modulus`), summing to `total_minor`: some
/// sum S of the non-multiples' residues, each in `[1, modulus - 1]`, is
/// congruent to the total modulo `modulus` and leaves the multiples at least
/// one `modulus` each (§2.6 rule 4). F4's three credit legs at p = 3 cannot
/// have exactly one non-multiple: their total is a whole multiple.
#[must_use]
pub fn feasible(total_minor: i128, legs: &[ResidueClass], modulus: i128) -> bool {
    if legs.is_empty() || modulus < 1 || total_minor < 1 {
        return false;
    }
    let n = legs
        .iter()
        .filter(|c| **c == ResidueClass::NonMultiple)
        .count() as i128;
    let m = legs.len() as i128 - n;
    let Some(budget) = m
        .checked_mul(modulus)
        .and_then(|floor| total_minor.checked_sub(floor))
    else {
        return false;
    };
    if budget < 0 {
        return false;
    }
    if n == 0 {
        return total_minor.rem_euclid(modulus) == 0;
    }
    if modulus < 2 {
        return false;
    }
    let hi = n.saturating_mul(modulus - 1).min(budget);
    let lo = n;
    lo <= hi && lowest_sum(lo, total_minor, modulus) <= hi
}

/// The least S at or above `lo` congruent to `total` modulo `modulus`.
fn lowest_sum(lo: i128, total: i128, modulus: i128) -> i128 {
    lo + (total.rem_euclid(modulus) - lo).rem_euclid(modulus)
}

/// What one branched attribute's value is in a cell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CellPart {
    /// Per-leg residue classes over the branched legs (ascending ordinal),
    /// their sourced total and the modulus, both in minor units.
    Legs {
        letters: String,
        ordinals: Vec<i128>,
        total: i128,
        modulus: i128,
    },
    /// An enum class.
    Class(String),
    /// Inside or outside the last `window_days` of `[first, last]`.
    Window {
        inside: bool,
        window_days: u32,
        first: Day,
        last: Day,
    },
    /// Before, or on or after, `date`, within `[first, last]`.
    BeforeAfter {
        before: bool,
        date: Day,
        first: Day,
        last: Day,
    },
}

impl CellPart {
    /// The value in A1c's `[[branch_cell]] cell` form.
    fn value(&self) -> String {
        match self {
            Self::Legs { letters, .. } => letters.clone(),
            Self::Class(v) => v.clone(),
            Self::Window { inside, .. } => if *inside {
                "inside_window"
            } else {
                "outside_window"
            }
            .into(),
            Self::BeforeAfter { before, .. } => {
                if *before { "before" } else { "on_or_after" }.into()
            }
        }
    }
}

/// One cell of a target's branch table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cell {
    /// A1c's `[[branch_cell]] cell`: one value per branched attribute, in
    /// the target's `branch_attrs` order (`mmm`, `nnm`, ... for per-leg
    /// residues, in ascending leg ordinal).
    pub key: Vec<String>,
    pub parts: Vec<CellPart>,
    /// From the cell's authored `[[branch_cell]]` row (A5b checks it); a
    /// cell with no authored row is not record-consistent.
    pub record_consistent: bool,
    /// The cell a declared default selects (§2.6 rule 2).
    pub default: bool,
}

impl Cell {
    /// The grouping a per-leg cell belongs to (`all_multiples`,
    /// `two_non_multiples`, ...), which case beads name; never a cell key.
    #[must_use]
    pub fn count_class(&self) -> Option<String> {
        self.parts.iter().find_map(|p| match p {
            CellPart::Legs { letters, .. } => {
                let n = letters.chars().filter(|c| *c == 'n').count();
                Some(match n {
                    0 => "all_multiples".to_string(),
                    1 => "one_non_multiple".to_string(),
                    _ => format!("{}_non_multiples", number_word(n)),
                })
            }
            _ => None,
        })
    }
}

fn number_word(n: usize) -> String {
    const WORDS: [&str; 11] = [
        "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
    ];
    WORDS
        .get(n)
        .map_or_else(|| n.to_string(), |w| (*w).to_string())
}

/// One (expectation, target)'s branch table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enumeration {
    pub expectation: String,
    pub target: String,
    pub attrs: Vec<BranchAttribute>,
    /// Per attribute, its classes after equivalence-class reduction and the
    /// balance law.
    pub class_counts: Vec<usize>,
    /// In fixed order: attributes in `branch_attrs` order, classes in rule
    /// order (per-leg assignments by their count of non-multiples, then `n`
    /// before `m`). Record-inconsistent cells are kept.
    pub cells: Vec<Cell>,
    /// Per-leg assignments the balance law forbids (`leg_split=nmm`): named,
    /// never evaluated.
    pub infeasible: Vec<String>,
    /// More than `cap` cells: no component of the target is single.
    pub capped: bool,
    pub default_cell: Option<Vec<String>>,
}

impl Enumeration {
    /// The `ENUM` log line: attributes, class counts, cell count, the
    /// infeasible assignments, whether capped, and the cells in order, each
    /// with its count class when it has one.
    #[must_use]
    pub fn log_line(&self) -> String {
        let attrs: Vec<&str> = self.attrs.iter().map(|a| a.as_str()).collect();
        let order: Vec<String> = self
            .cells
            .iter()
            .map(|c| {
                let key = c.key.join("/");
                c.count_class()
                    .map_or_else(|| key.clone(), |k| format!("{key}:{k}"))
            })
            .collect();
        format!(
            "ENUM {} {} attrs=[{}] counts=[{}] cells={} infeasible=[{}] capped={} order=[{}]",
            self.expectation,
            self.target,
            attrs.join(","),
            self.class_counts
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
            self.cells.len(),
            self.infeasible.join(","),
            self.capped,
            order.join(",")
        )
    }
}

/// [`enumerate_with`] under the committed rules.
///
/// # Errors
///
/// As [`enumerate_with`], or a rules table that does not load.
pub fn enumerate(
    case: &Case,
    expectation: &Expectation,
    target: &Target,
) -> Result<Enumeration, LoadError> {
    let rules = rules().map_err(|mut errs| errs.remove(0))?;
    enumerate_with(&rules, case, expectation, target)
}

/// One (expectation, target)'s cells under `rules`.
///
/// # Errors
///
/// A target whose variant, intent, branch class or rule cannot be resolved;
/// a per-leg rule with no branched leg; or a capped enumeration on a target
/// that declares a single (S, Sd or Si) component.
pub fn enumerate_with(
    rules: &BranchRules,
    case: &Case,
    expectation: &Expectation,
    target: &Target,
) -> Result<Enumeration, LoadError> {
    let err = |kind: LoadErrorKind, detail: String| LoadError {
        file: "expectations.toml".into(),
        line: target.fields.line,
        kind,
        row: Some(expectation.id.clone()),
        detail,
    };
    let variant = expectation.fields.str("book_variant").unwrap_or_default();
    let book = case.books.get(variant).ok_or_else(|| {
        err(
            LoadErrorKind::DanglingKey,
            format!("`book_variant = \"{variant}\"` has no book"),
        )
    })?;
    let attrs: Vec<BranchAttribute> = target
        .fields
        .strs("branch_attrs")
        .unwrap_or(&[])
        .iter()
        .map(|a| {
            BranchAttribute::parse(a).ok_or_else(|| {
                err(
                    LoadErrorKind::UnknownValue,
                    format!("branch attribute `{a}` is outside the §2.6 enum"),
                )
            })
        })
        .collect::<Result<_, _>>()?;
    let intent = subject_intent(book, &target.fact).ok_or_else(|| {
        err(
            LoadErrorKind::DanglingKey,
            format!(
                "target `{}` names no one intent of `{variant}`",
                target.fact
            ),
        )
    })?;
    let mut infeasible = Vec::new();
    let mut per_attr: Vec<Vec<CellPart>> = Vec::new();
    for attr in &attrs {
        let class =
            class_for(book, &intent, *attr).map_err(|d| err(LoadErrorKind::DanglingKey, d))?;
        let rule = match (class_problem(rules, class), rules.get(&class.rule)) {
            (None, Some(rule)) => rule,
            (problem, _) => {
                return Err(err(
                    LoadErrorKind::UnknownValue,
                    problem.unwrap_or_else(|| format!("rule `{}` is not loaded", class.rule)),
                ));
            }
        };
        let parts = match &rule.class_rule {
            ClassRule::Enum => class.values.iter().cloned().map(CellPart::Class).collect(),
            ClassRule::ResidueMod { power } => {
                let (parts, forbidden) = leg_cells(book, &intent, class, *power)
                    .map_err(|d| err(LoadErrorKind::UnknownValue, d))?;
                infeasible.extend(
                    forbidden
                        .into_iter()
                        .map(|l| format!("{}={l}", attr.as_str())),
                );
                parts
            }
            ClassRule::InsideWindow { window_days } => {
                let (first, last) =
                    period_of(book, &intent).map_err(|d| err(LoadErrorKind::UnknownPeriod, d))?;
                class
                    .values
                    .iter()
                    .map(|v| CellPart::Window {
                        inside: v == "inside_window",
                        window_days: *window_days,
                        first,
                        last,
                    })
                    .collect()
            }
            ClassRule::BeforeAfter { date } => {
                let (first, last) =
                    period_of(book, &intent).map_err(|d| err(LoadErrorKind::UnknownPeriod, d))?;
                class
                    .values
                    .iter()
                    .map(|v| CellPart::BeforeAfter {
                        before: v == "before",
                        date: *date,
                        first,
                        last,
                    })
                    .collect()
            }
        };
        per_attr.push(parts);
    }
    let class_counts: Vec<usize> = per_attr.iter().map(Vec::len).collect();
    let total = class_counts
        .iter()
        .try_fold(1usize, |acc, n| acc.checked_mul(*n))
        .unwrap_or(usize::MAX);
    let capped = total > rules.cap;
    if capped {
        for component in ["cite", "severity", "statistic"] {
            let status = target
                .fields
                .str(&format!("{component}_status"))
                .and_then(Status::parse);
            if matches!(status, Some(Status::S | Status::Sd | Status::Si)) {
                return Err(err(
                    LoadErrorKind::WrongType,
                    format!(
                        "{} {}: {total} cells exceed the cap of {}, so its {component} is a branch, never single (§2.6 rule 4)",
                        expectation.id, target.fact, rules.cap
                    ),
                ));
            }
        }
    }
    let authored = case
        .expectations
        .as_ref()
        .map(|set| {
            set.branch_cells
                .iter()
                .filter(|c| c.expectation == expectation.id && c.target == target.fact)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut cells = Vec::new();
    let mut index = vec![0usize; per_attr.len()];
    while cells.len() < total.min(rules.cap) {
        let parts: Vec<CellPart> = index
            .iter()
            .zip(&per_attr)
            .map(|(i, parts)| parts[*i].clone())
            .collect();
        let key: Vec<String> = parts.iter().map(CellPart::value).collect();
        let row = authored.iter().find(|c| c.cell == key);
        cells.push(Cell {
            record_consistent: row.and_then(|c| c.fields.bool("record_consistent")) == Some(true),
            default: row.and_then(|c| c.fields.bool("default")) == Some(true),
            key,
            parts,
        });
        // The last attribute varies fastest.
        let mut a = index.len();
        loop {
            if a == 0 {
                break;
            }
            a -= 1;
            index[a] += 1;
            if index[a] < per_attr[a].len() {
                break;
            }
            index[a] = 0;
        }
        if a == 0 && index.iter().all(|i| *i == 0) {
            break;
        }
    }
    let default_cell = cells.iter().find(|c| c.default).map(|c| c.key.clone());
    Ok(Enumeration {
        expectation: expectation.id.clone(),
        target: target.fact.clone(),
        attrs,
        class_counts,
        cells,
        infeasible,
        capped,
        default_cell,
    })
}

/// A fact or intent's one intent in `book`.
fn subject_intent(book: &BookVariant, subject: &str) -> Option<String> {
    if book.intents.iter().any(|i| i.id == subject) {
        return Some(subject.to_string());
    }
    let mut by_fact = book.intents.iter().filter(|i| i.fact == subject);
    let one = by_fact.next()?;
    by_fact.next().is_none().then(|| one.id.clone())
}

/// The branch class of `attr` that governs `intent`: the class its own legs
/// name (`amount_rule = "branch:<class>"`), else the class its step names,
/// else the one class of that attribute no other intent's legs or steps
/// name.
fn class_for<'b>(
    book: &'b BookVariant,
    intent: &str,
    attr: BranchAttribute,
) -> Result<&'b BranchClassDef, String> {
    let of_attr = || {
        book.branch_classes
            .iter()
            .filter(move |b| b.attribute == attr.as_str())
    };
    let named_by_legs = |b: &BranchClassDef, who: &dyn Fn(&str) -> bool| {
        let rule = format!("branch:{}", b.id);
        book.legs
            .iter()
            .any(|l| who(&l.intent) && l.amount_rule == rule)
    };
    let named_by_steps = |b: &BranchClassDef, who: &dyn Fn(&str) -> bool| {
        book.steps.iter().any(|s| {
            s.step_kind() == Some(StepKind::Intent)
                && who(&s.reference)
                && s.branch_class.as_deref() == Some(b.id.as_str())
        })
    };
    let this = |i: &str| i == intent;
    let other = |i: &str| i != intent;
    let picks: [Vec<&BranchClassDef>; 3] = [
        of_attr().filter(|b| named_by_legs(b, &this)).collect(),
        of_attr().filter(|b| named_by_steps(b, &this)).collect(),
        of_attr()
            .filter(|b| !named_by_legs(b, &other) && !named_by_steps(b, &other))
            .collect(),
    ];
    for pick in picks {
        match pick.as_slice() {
            [] => {}
            [one] => return Ok(one),
            many => {
                return Err(format!(
                    "{intent}'s `{}` is governed by {} branch classes ({}); name one on its legs or step",
                    attr.as_str(),
                    many.len(),
                    many.iter()
                        .map(|b| b.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
    }
    Err(format!(
        "no `[[branch_class]]` governs {intent}'s `{}`",
        attr.as_str()
    ))
}

/// A per-leg residue class's cells over `intent`'s legs that name it: every
/// assignment of the class's letters, the feasible ones as cells and the
/// rest named.
fn leg_cells(
    book: &BookVariant,
    intent: &str,
    class: &BranchClassDef,
    power: u32,
) -> Result<(Vec<CellPart>, Vec<String>), String> {
    let rule = format!("branch:{}", class.id);
    let mut legs: Vec<_> = book
        .legs
        .iter()
        .filter(|l| l.intent == intent && l.amount_rule == rule)
        .collect();
    legs.sort_by_key(|l| l.ordinal);
    let Some(first) = legs.first() else {
        return Err(format!(
            "no leg of {intent} has `amount_rule = \"{rule}\"`, so `{}` has no legs to branch",
            class.id
        ));
    };
    if legs
        .iter()
        .any(|l| l.side != first.side || l.unit != first.unit)
    {
        return Err(format!(
            "{intent}'s legs under `{}` are on one side and in one unit",
            class.id
        ));
    }
    let scale = fa_registry::units_embedded()
        .ok()
        .and_then(|u| u.into_iter().find(|u| u.code == first.unit))
        .map(|u| u.scale)
        .ok_or_else(|| format!("`{}` is not a registered unit", first.unit))?;
    let modulus = 10i128
        .checked_pow(power + u32::from(scale))
        .ok_or_else(|| format!("10^{power} units at scale {scale} overflows"))?;
    let mut total = 0i128;
    for l in &legs {
        let a = parse_amount(&l.amount_literal, scale).map_err(|e| format!("{e}"))?;
        total = total
            .checked_add(a)
            .ok_or_else(|| "the branched legs' total overflows".to_string())?;
    }
    let letters: Vec<ResidueClass> = class
        .values
        .iter()
        .filter_map(|v| match v.as_str() {
            "multiple" => Some(ResidueClass::Multiple),
            "non_multiple" => Some(ResidueClass::NonMultiple),
            _ => None,
        })
        .collect();
    let k = u32::try_from(legs.len()).map_err(|_| "too many branched legs".to_string())?;
    let count = letters
        .len()
        .checked_pow(k)
        .filter(|c| *c <= 1 << 20)
        .ok_or_else(|| format!("{} legs give too many assignments", legs.len()))?;
    let mut assignments: Vec<Vec<ResidueClass>> = (0..count)
        .map(|mut x| {
            (0..legs.len())
                .map(|_| {
                    let c = letters[x % letters.len()];
                    x /= letters.len();
                    c
                })
                .collect()
        })
        .collect();
    let non = |a: &Vec<ResidueClass>| {
        a.iter()
            .filter(|c| **c == ResidueClass::NonMultiple)
            .count()
    };
    // By count of non-multiples, then `n` before `m` at the first difference.
    assignments.sort_by(|a, b| {
        non(a).cmp(&non(b)).then_with(|| {
            b.iter()
                .map(|c| c.letter())
                .cmp(a.iter().map(|c| c.letter()))
        })
    });
    let ordinals: Vec<i128> = legs.iter().map(|l| l.ordinal).collect();
    let mut parts = Vec::new();
    let mut forbidden = Vec::new();
    for a in assignments {
        let word: String = a.iter().map(|c| c.letter()).collect();
        if feasible(total, &a, modulus) {
            parts.push(CellPart::Legs {
                letters: word,
                ordinals: ordinals.clone(),
                total,
                modulus,
            });
        } else {
            forbidden.push(word);
        }
    }
    Ok((parts, forbidden))
}

/// The first and last day of the declared period containing `intent`'s
/// effective date.
fn period_of(book: &BookVariant, intent: &str) -> Result<(Day, Day), String> {
    let day = book
        .intents
        .iter()
        .find(|i| i.id == intent)
        .map(|i| i.effective_date.as_str())
        .unwrap_or_default();
    book.periods
        .iter()
        .find(|p| p.contains(day))
        .and_then(|p| Some((Day::parse(&p.start)?, Day::parse(&p.end)?)))
        .ok_or_else(|| format!("no declared period contains {intent}'s effective date {day}"))
}

/// One branched attribute's concrete value in a witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WitnessValue {
    /// Each branched leg's amount in minor units, by leg ordinal.
    Legs(Vec<(i128, i128)>),
    /// An enum class's value.
    Class(String),
    /// A day.
    Day(Day),
}

/// A concrete member of a cell (§3.7 item 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    pub index: usize,
    /// One value per branched attribute, in the cell's order.
    pub values: Vec<WitnessValue>,
}

/// `n` concrete members of `cell`, drawn from the stream seeded by
/// SHA-256(case id ‖ 0x00 ‖ expectation id ‖ 0x00 ‖ the cell key joined by
/// `,`), in a fixed order: per witness, per attribute, amounts then days
/// then choices. The same (case, expectation, cell) gives byte-identical
/// witnesses.
#[must_use]
pub fn witnesses(case_id: &str, expectation_id: &str, cell: &Cell, n: usize) -> Vec<Witness> {
    let mut s = Stream::new(witness_seed(case_id, expectation_id, cell));
    (0..n)
        .map(|index| Witness {
            index,
            values: cell.parts.iter().map(|p| draw(&mut s, p)).collect(),
        })
        .collect()
}

/// A cell's witness seed: SHA-256(case id ‖ 0x00 ‖ expectation id ‖ 0x00 ‖
/// the cell key joined by `,`), which a failing property test prints.
#[must_use]
pub fn witness_seed(case_id: &str, expectation_id: &str, cell: &Cell) -> [u8; 32] {
    let key = cell.key.join(",");
    let mut bytes = Vec::new();
    for (i, part) in [case_id, expectation_id, key.as_str()].iter().enumerate() {
        if i > 0 {
            bytes.push(0);
        }
        bytes.extend_from_slice(part.as_bytes());
    }
    crate::sha256::digest(&bytes)
}

/// A draw from `0..=hi` (0 when `hi` is not positive).
fn upto(s: &mut Stream, hi: i128) -> i128 {
    let Ok(hi) = u64::try_from(hi) else {
        return 0;
    };
    i128::from(s.below(hi.saturating_add(1)))
}

fn draw(s: &mut Stream, part: &CellPart) -> WitnessValue {
    match part {
        CellPart::Class(v) => WitnessValue::Class(v.clone()),
        CellPart::Window {
            inside,
            window_days,
            first,
            last,
        } => {
            let span = last.to_days() - first.to_days();
            let w = i64::from(*window_days).min(span + 1);
            let back = if *inside {
                i64::try_from(upto(s, i128::from(w - 1))).unwrap_or(0)
            } else {
                w + i64::try_from(upto(s, i128::from(span - w))).unwrap_or(0)
            };
            WitnessValue::Day(last.add_days(-back))
        }
        CellPart::BeforeAfter {
            before,
            date,
            first,
            last,
        } => {
            let day = if *before {
                let span = date.to_days() - 1 - first.to_days();
                first.add_days(i64::try_from(upto(s, i128::from(span))).unwrap_or(0))
            } else {
                let span = last.to_days() - date.to_days();
                date.add_days(i64::try_from(upto(s, i128::from(span))).unwrap_or(0))
            };
            WitnessValue::Day(day)
        }
        CellPart::Legs {
            letters,
            ordinals,
            total,
            modulus,
        } => WitnessValue::Legs(
            ordinals
                .iter()
                .copied()
                .zip(leg_amounts(s, letters, *total, *modulus))
                .collect(),
        ),
    }
}

/// Amounts with `letters`' residue classes summing to `total` (a feasible
/// cell): the non-multiples' residue sum S is a drawn member of its
/// congruence class within bounds, split with each residue in
/// `[1, modulus - 1]`; the remaining multiples of `modulus` are spread over
/// the legs, each multiple leg keeping at least one.
fn leg_amounts(s: &mut Stream, letters: &str, total: i128, modulus: i128) -> Vec<i128> {
    let k = letters.len();
    let non: Vec<bool> = letters.chars().map(|c| c == 'n').collect();
    let n = non.iter().filter(|x| **x).count() as i128;
    let m = k as i128 - n;
    let budget = total - m * modulus;
    let mut residues = vec![0i128; k];
    if n > 0 {
        let hi = (n * (modulus - 1)).min(budget);
        let lo = lowest_sum(n, total, modulus);
        let sum = lo + upto(s, (hi - lo) / modulus) * modulus;
        let mut rest = sum - n;
        let idx: Vec<usize> = (0..k).filter(|i| non[*i]).collect();
        for (j, i) in idx.iter().enumerate() {
            let room = modulus - 2;
            let take = if j + 1 == idx.len() {
                rest.min(room)
            } else {
                upto(s, rest.min(room))
            };
            residues[*i] = 1 + take;
            rest -= take;
        }
        for i in &idx {
            let take = (modulus - 1 - residues[*i]).min(rest);
            residues[*i] += take;
            rest -= take;
        }
    }
    let sum: i128 = residues.iter().sum();
    let mut quotients: Vec<i128> = non.iter().map(|x| i128::from(!*x)).collect();
    let mut rest = (total - sum) / modulus - m;
    for q in quotients.iter_mut().take(k.saturating_sub(1)) {
        let take = upto(s, rest);
        *q += take;
        rest -= take;
    }
    if let Some(q) = quotients.last_mut() {
        *q += rest;
    }
    quotients
        .iter()
        .zip(&residues)
        .map(|(q, r)| q * modulus + r)
        .collect()
}

#[cfg(test)]
#[path = "branch_tests.rs"]
mod tests;
