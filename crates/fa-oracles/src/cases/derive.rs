//! The derivation rules of the case studies and their exact-integer engine
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §2.4; bead fa-yugf.6, A2).
//!
//! A value that is not literally in its quote is `derived` by a registered
//! rule, or it is an `interpretation` (§2.1). [`Rules`] loads the closed
//! table `data/case_derivations.toml`; [`Rules::evaluate`] computes a rule
//! over checked `i128` at each unit's registered scale (fa-oracles' own
//! arithmetic, never fa-money's) and [`civil dates`](super::date) of its own.
//! K-DERIVE (A3a) recomputes every derived fact with it and refuses a
//! mismatch; every rule row carries one example that the tests recompute.
//!
//! Inputs and outputs are canonical strings (the table's header gives the
//! encodings): integers are minor units at their unit's scale, legs are
//! `<Dr|Cr>:<account>:<amount>:<unit>`, entries `<date>@<leg>;<leg>…`, and a
//! rows input is the text of an M2t rows file.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use fa_registry::toml::{Table, Value as TomlValue};

use super::date::Day;
use super::error::{LoadError, LoadErrorKind};
use super::fact::{Derived, Value};
use super::rows::row_line;

const TABLE: &str = include_str!("../../data/case_derivations.toml");
/// The table's path, as errors name it.
pub const FILE: &str = "data/case_derivations.toml";

/// fa-oracles' own copy of the 10^9-scaled Benford first-digit table:
/// `log10(1 + 1/d)` rounded to nine places sums to 1,000,000,001, and the
/// last value is lowered by one unit so the table sums to exactly 10^9
/// (FA's convention). Never imported from fa-lantern.
pub const BENFORD_1E9: [i128; 9] = [
    301_029_996,
    176_091_259,
    124_938_737,
    96_910_013,
    79_181_246,
    66_946_790,
    57_991_947,
    51_152_522,
    45_757_490,
];

closed_set! {
    /// A rule parameter's type.
    ParamType {
        Int => "int",
        Str => "str",
        Date => "date",
        Unit => "unit",
    }
}

/// One `[[rule]]` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    /// The number of inputs; 0 means one or more.
    pub arity: i128,
    pub params: Vec<(String, ParamType)>,
    pub semantics: String,
    pub rounding_law: String,
    pub interpretive: bool,
    pub registry_params: Vec<String>,
    pub example_inputs: Vec<String>,
    pub example_params: Vec<String>,
    pub example_output: String,
    pub example_basis: String,
    pub line: Option<usize>,
}

/// One `[[chart_rule_row]]`: a concept's account type, role and reads under
/// a chart rule (`role_map{chart_rule}`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChartRuleRow {
    pub chart_rule: String,
    pub concept: String,
    pub account_type: String,
    pub role: String,
    pub balance_side: String,
    pub read: Vec<String>,
    pub reason: Option<String>,
    pub example: String,
    pub line: Option<usize>,
}

/// The loaded table.
#[derive(Clone, Debug)]
pub struct Rules {
    pub rules: Vec<Rule>,
    pub chart_rows: Vec<ChartRuleRow>,
    unit_scales: BTreeMap<String, u8>,
}

/// Resolved parameters, by name.
pub type Params = BTreeMap<String, String>;

/// Why a derivation does not compute, or computes something else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeriveError {
    UnknownRule(String),
    Arity {
        rule: String,
        want: String,
        got: usize,
    },
    BadParam(String),
    Overflow,
    Infeasible(String),
    Mismatch {
        rule: String,
        params: Vec<String>,
        expected: String,
        computed: String,
    },
}

impl fmt::Display for DeriveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRule(id) => write!(f, "`{id}` is not a rule of {FILE}"),
            Self::Arity { rule, want, got } => write!(f, "{rule} takes {want} input(s), not {got}"),
            Self::BadParam(why) => write!(f, "bad parameter or input: {why}"),
            Self::Overflow => f.write_str("the result overflows i128"),
            Self::Infeasible(why) => write!(f, "infeasible: {why}"),
            Self::Mismatch {
                rule,
                params,
                expected,
                computed,
            } => write!(
                f,
                "{rule} [{}]: expected {expected}, computed {computed}",
                params.join(", ")
            ),
        }
    }
}

impl core::error::Error for DeriveError {}

fn bad(why: impl Into<String>) -> DeriveError {
    DeriveError::BadParam(why.into())
}

impl Rules {
    /// The committed table.
    ///
    /// # Errors
    ///
    /// Every malformed row, sorted.
    pub fn embedded() -> Result<Self, Vec<LoadError>> {
        Self::from_text(TABLE)
    }

    /// A table from text (a test copy).
    ///
    /// # Errors
    ///
    /// Every malformed row, sorted.
    pub fn from_text(text: &str) -> Result<Self, Vec<LoadError>> {
        let mut errs = Vec::new();
        let err = |line: Option<usize>, row: Option<&str>, kind: LoadErrorKind, detail: String| {
            LoadError {
                file: FILE.to_string(),
                line,
                kind,
                row: row.map(str::to_string),
                detail,
            }
        };
        let doc = fa_registry::toml::parse(text)
            .map_err(|e| vec![err(Some(e.line), None, LoadErrorKind::Toml, e.message)])?;
        if doc.root.get("schema_version").and_then(TomlValue::as_int) != Some(1) {
            errs.push(err(
                None,
                None,
                LoadErrorKind::MissingField,
                "`schema_version = 1` is required".into(),
            ));
        }
        let mut unit_scales = BTreeMap::new();
        match fa_registry::units_embedded() {
            Ok(rows) => {
                let mut best: BTreeMap<String, (u16, u8)> = BTreeMap::new();
                for u in rows {
                    let e = best.entry(u.code).or_insert((u.version, u.scale));
                    if u.version >= e.0 {
                        *e = (u.version, u.scale);
                    }
                }
                unit_scales = best.into_iter().map(|(k, (_, s))| (k, s)).collect();
            }
            Err(e) => errs.push(err(
                None,
                None,
                LoadErrorKind::Toml,
                format!("registries/units.toml: {e}"),
            )),
        }
        let laws: BTreeSet<String> = match fa_registry::rounding_laws_embedded() {
            Ok(rows) => rows.into_iter().map(|r| r.name).collect(),
            Err(e) => {
                errs.push(err(
                    None,
                    None,
                    LoadErrorKind::Toml,
                    format!("registries/rounding_laws.toml: {e}"),
                ));
                BTreeSet::new()
            }
        };
        let rows = |name: &str| doc.arrays.get(name).map(Vec::as_slice).unwrap_or(&[]);
        let mut rules = Vec::new();
        let mut ids = BTreeSet::new();
        for (i, t) in rows("rule").iter().enumerate() {
            let line = row_line(text, "rule", i);
            let id = str_of(t, "id");
            let row = Some(id.as_str());
            let mut field_err = |k: &str, kind: LoadErrorKind, d: String| {
                errs.push(err(line, row, kind, format!("`{k}`: {d}")));
            };
            for key in t.keys() {
                if !RULE_FIELDS.contains(&key.as_str()) {
                    field_err(key, LoadErrorKind::UnknownField, "unknown field".into());
                }
            }
            for key in RULE_FIELDS {
                if !t.contains_key(key) {
                    field_err(key, LoadErrorKind::MissingField, "required".into());
                }
            }
            if !ids.insert(id.clone()) {
                field_err(
                    "id",
                    LoadErrorKind::DuplicateId,
                    format!("rule `{id}` twice"),
                );
            }
            let mut params = Vec::new();
            for p in strs_of(t, "params") {
                match p
                    .split_once(':')
                    .and_then(|(n, ty)| Some((n, ParamType::parse(ty)?)))
                {
                    Some((n, ty)) if !n.is_empty() => params.push((n.to_string(), ty)),
                    _ => field_err(
                        "params",
                        LoadErrorKind::WrongType,
                        format!("`{p}` is not `<name>:<int|str|date|unit>`"),
                    ),
                }
            }
            let rounding_law = str_of(t, "rounding_law");
            if !rounding_law.is_empty() && !laws.contains(&rounding_law) {
                field_err(
                    "rounding_law",
                    LoadErrorKind::DanglingKey,
                    format!("`{rounding_law}` is not a law of registries/rounding_laws.toml"),
                );
            }
            let arity = t.get("arity").and_then(TomlValue::as_int).unwrap_or(-1);
            if arity < 0 {
                field_err(
                    "arity",
                    LoadErrorKind::WrongType,
                    "a non-negative integer (0 = one or more)".into(),
                );
            }
            rules.push(Rule {
                id,
                arity,
                params,
                semantics: str_of(t, "semantics"),
                rounding_law,
                interpretive: t
                    .get("interpretive")
                    .and_then(TomlValue::as_bool)
                    .unwrap_or(false),
                registry_params: strs_of(t, "registry_params"),
                example_inputs: strs_of(t, "example_inputs"),
                example_params: strs_of(t, "example_params"),
                example_output: str_of(t, "example_output"),
                example_basis: str_of(t, "example_basis"),
                line,
            });
        }
        let chart_rows = chart_rows(text, rows("chart_rule_row"), &mut errs);
        for name in doc
            .arrays
            .keys()
            .filter(|n| !["rule", "chart_rule_row"].contains(&n.as_str()))
        {
            errs.push(err(
                row_line(text, name, 0),
                None,
                LoadErrorKind::UnknownField,
                format!("unknown array `[[{name}]]`"),
            ));
        }
        if errs.is_empty() {
            Ok(Self {
                rules,
                chart_rows,
                unit_scales,
            })
        } else {
            super::error::sort(&mut errs);
            Err(errs)
        }
    }

    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }

    fn scale_of(&self, unit: &str) -> Result<u8, DeriveError> {
        self.unit_scales
            .get(unit)
            .copied()
            .ok_or_else(|| bad(format!("`{unit}` is not a registered unit")))
    }

    /// A rule's `name=value` tokens as checked parameters.
    ///
    /// # Errors
    ///
    /// `BadParam` for an undeclared name, a malformed token or a value of
    /// the wrong type.
    pub fn params(&self, rule: &Rule, tokens: &[String]) -> Result<Params, DeriveError> {
        let mut out = Params::new();
        for t in tokens {
            let (name, value) = t
                .split_once('=')
                .ok_or_else(|| bad(format!("param `{t}` is not `<name>=<value>`")))?;
            let ty = rule
                .params
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, ty)| *ty)
                .ok_or_else(|| bad(format!("`{name}` is not a parameter of {}", rule.id)))?;
            let ok = match ty {
                ParamType::Int => value.parse::<i128>().is_ok(),
                ParamType::Date => Day::parse(value).is_some(),
                ParamType::Unit => value.is_empty() || self.unit_scales.contains_key(value),
                ParamType::Str => true,
            };
            if !ok {
                return Err(bad(format!("`{name}={value}` is not a {}", ty.as_str())));
            }
            out.insert(name.to_string(), value.to_string());
        }
        Ok(out)
    }

    /// A derived fact's parameters: each `name=value` token, a `from:<fact>`
    /// value read from that fact's first `[[value]]` (which must be among the
    /// derived fact's `from`).
    ///
    /// # Errors
    ///
    /// `UnknownRule`, or `BadParam` for an undeclared name or a `from:` fact
    /// outside `from` or without a value.
    pub fn params_of(&self, derived: &Derived, values: &[Value]) -> Result<Params, DeriveError> {
        let rule = self
            .get(&derived.rule)
            .ok_or_else(|| DeriveError::UnknownRule(derived.rule.clone()))?;
        let mut tokens = Vec::new();
        for p in derived.params.iter().flatten() {
            let t = p
                .as_str()
                .ok_or_else(|| bad("a derived fact's params are `<name>=<value>` strings"))?;
            let resolved = match t.split_once("=from:") {
                Some((name, fact)) => {
                    if !derived.from.iter().any(|f| f == fact) {
                        return Err(bad(format!(
                            "`{t}` reads `{fact}`, which is not among the fact's `from`"
                        )));
                    }
                    let v = values
                        .iter()
                        .filter(|v| v.fact == fact)
                        .min_by_key(|v| v.ordinal)
                        .ok_or_else(|| bad(format!("`{fact}` has no [[value]]")))?;
                    format!("{name}={}", v.value)
                }
                None => t.to_string(),
            };
            tokens.push(resolved);
        }
        self.params(rule, &tokens)
    }

    /// Evaluates rule `id` on `inputs` under `params`.
    ///
    /// # Errors
    ///
    /// [`DeriveError`] naming why.
    pub fn evaluate(
        &self,
        id: &str,
        params: &Params,
        inputs: &[String],
    ) -> Result<String, DeriveError> {
        let rule = self
            .get(id)
            .ok_or_else(|| DeriveError::UnknownRule(id.to_string()))?;
        let n = inputs.len();
        let arity_ok = if rule.arity == 0 {
            n >= 1
        } else {
            i128::try_from(n).is_ok_and(|n| n == rule.arity)
        };
        if !arity_ok {
            return Err(DeriveError::Arity {
                rule: id.to_string(),
                want: if rule.arity == 0 {
                    "one or more".into()
                } else {
                    rule.arity.to_string()
                },
                got: n,
            });
        }
        let int = |name: &str, default: i128| -> Result<i128, DeriveError> {
            params.get(name).map_or(Ok(default), |v| {
                v.parse()
                    .map_err(|_| bad(format!("`{name}` is an integer")))
            })
        };
        let text = |name: &str| params.get(name).cloned().unwrap_or_default();
        match id {
            "scale" => self.scale(&inputs[0], params),
            "date_literal" => date_literal(&inputs[0]),
            "number_word" => number_word(&inputs[0]).map(|v| v.to_string()),
            "period_literal" => period_literal(&inputs[0]),
            "date_range_literal" => date_range_literal(&inputs[0]),
            "month_literal" => month_literal(&inputs[0]),
            "sum" => {
                if is_rows(&inputs[0]) {
                    let unit = text("unit");
                    return self
                        .row_sum(&inputs[0], params, &unit)
                        .map(|v| v.to_string());
                }
                let mut total: i128 = 0;
                for v in inputs {
                    total = total
                        .checked_add(integer(v)?)
                        .ok_or(DeriveError::Overflow)?;
                }
                Ok(total.to_string())
            }
            "difference" => {
                let a = if is_rows(&inputs[0]) {
                    self.row_sum(&inputs[0], params, &text("unit"))?
                } else {
                    integer(&inputs[0])?
                };
                a.checked_sub(integer(&inputs[1])?)
                    .ok_or(DeriveError::Overflow)
                    .map(|v| v.to_string())
            }
            "negate" => inputs
                .iter()
                .map(|l| {
                    let leg = Leg::parse(l)?;
                    Ok(Leg {
                        side: if leg.side == "Dr" {
                            "Cr".into()
                        } else {
                            "Dr".into()
                        },
                        ..leg
                    }
                    .to_string())
                })
                .collect::<Result<Vec<_>, DeriveError>>()
                .map(|legs| legs.join(";")),
            "date_offset" => {
                let day = Day::parse(&inputs[0])
                    .ok_or_else(|| bad(format!("`{}` is not a valid date", inputs[0])))?;
                let days = i64::try_from(int("days", 0)?).map_err(|_| DeriveError::Overflow)?;
                Ok(day.add_days(days).to_string())
            }
            "remainder" => {
                let mut rest = integer(&inputs[0])?;
                for v in &inputs[1..] {
                    rest = rest.checked_sub(integer(v)?).ok_or(DeriveError::Overflow)?;
                }
                Ok(rest.to_string())
            }
            "last_balance_on_or_before" => {
                self.last_balance(&inputs[0], params).map(|v| v.to_string())
            }
            "legacy_tb_from_chunks" => legacy_tb(inputs, &text("periods")),
            "round_residue" => {
                let scale = self.scale_of(&text("unit"))?;
                let modulus = pow10(int("power", 0)? + i128::from(scale))?;
                Ok(integer(&inputs[0])?.rem_euclid(modulus).to_string())
            }
            "weekday_of" => Day::parse(&inputs[0])
                .map(|d| d.weekday().to_string())
                .ok_or_else(|| bad(format!("`{}` is not a valid date", inputs[0]))),
            "same_leg_multiset_same_day" | "same_leg_multiset_within" => {
                let a = Entry::parse(&inputs[0])?;
                let b = Entry::parse(&inputs[1])?;
                let gap = (a.day.to_days() - b.day.to_days()).abs();
                let same = a.legs == b.legs;
                let verdict = if id == "same_leg_multiset_same_day" {
                    same && gap == 0
                } else {
                    same && gap > 0 && i128::from(gap) <= int("window_days", 30)?
                };
                Ok(verdict.to_string())
            }
            "rsf_ratio" => {
                let mut amounts = inputs
                    .iter()
                    .map(|v| integer(v))
                    .collect::<Result<Vec<_>, _>>()?;
                amounts.sort_unstable_by(|a, b| b.cmp(a));
                if amounts.len() < 2 || amounts[1] <= 0 {
                    return Err(DeriveError::Infeasible(
                        "a relative size factor needs two positive amounts".into(),
                    ));
                }
                let rsf = amounts[0]
                    .checked_mul(10_000)
                    .ok_or(DeriveError::Overflow)?
                    / amounts[1];
                let size = i128::try_from(amounts.len()).map_err(|_| DeriveError::Overflow)?;
                let flagged =
                    size >= int("min_subset_size", 3)? && rsf >= int("min_rsf_bps", 50_000)?;
                Ok(format!("rsf_bps={rsf} flagged={flagged}"))
            }
            "first_digit_counts" => {
                let mut counts = [0u64; 9];
                for v in inputs {
                    let mut m = integer(v)?;
                    if m <= 0 {
                        return Err(bad(format!("`{v}` is not a positive amount")));
                    }
                    while m >= 10 {
                        m /= 10;
                    }
                    let d = usize::try_from(m - 1).map_err(|_| DeriveError::Overflow)?;
                    counts[d] += 1;
                }
                Ok(counts
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(","))
            }
            "round_density_z2" => {
                let [x, n, big_x, big_n] = [0, 1, 2, 3].map(|i| integer(&inputs[i]));
                round_density(
                    x?,
                    n?,
                    big_x?,
                    big_n?,
                    int("min_legs", 20)?,
                    int("z_squared", 9)?,
                )
            }
            "benford_mad" => {
                let mut counts = [0i128; 9];
                for (slot, v) in counts.iter_mut().zip(inputs) {
                    *slot = integer(v)?;
                }
                benford_mad(
                    &counts,
                    &BENFORD_1E9,
                    int("min_population", 500)?,
                    [
                        int("mad_close", 6)?,
                        int("mad_acceptable", 12)?,
                        int("mad_marginal", 15)?,
                    ],
                )
            }
            "role_map" => {
                let chart = text("chart_rule");
                self.chart_rows
                    .iter()
                    .find(|r| r.chart_rule == chart && r.concept == inputs[0])
                    .map(|r| format!("{}|{}", r.account_type, r.role))
                    .ok_or_else(|| {
                        DeriveError::Infeasible(format!(
                            "chart rule `{chart}` has no row for `{}`",
                            inputs[0]
                        ))
                    })
            }
            "one_leg_per_named_account" => {
                let side = text("side");
                if side != "Dr" && side != "Cr" {
                    return Err(bad("`side` is Dr or Cr"));
                }
                let amount = integer(&inputs[1])?;
                Ok(Leg {
                    side,
                    account: inputs[0].clone(),
                    amount,
                    unit: text("unit"),
                }
                .to_string())
            }
            "subledger_to_gl_legs" => {
                let (total, count, item) = (
                    integer(&inputs[0])?,
                    integer(&inputs[1])?,
                    integer(&inputs[2])?,
                );
                let decomposition = text("decomposition");
                if !matches!(
                    decomposition.as_str(),
                    "one_allocation_entry" | "ten_two_leg_entries"
                ) {
                    return Err(bad(
                        "`decomposition` is one_allocation_entry or ten_two_leg_entries",
                    ));
                }
                let product = count.checked_mul(item).ok_or(DeriveError::Overflow)?;
                if count <= 0 || product != total {
                    return Err(DeriveError::Infeasible(format!(
                        "{count} items of {item} make {product}, not the total {total}: a nonzero residual"
                    )));
                }
                Ok(format!("{decomposition}:{count}x{item}"))
            }
            "round_dollar_lower_bound" => {
                let scale = self.scale_of(&text("unit"))?;
                let modulus = pow10(3 + i128::from(scale))?;
                Ok((integer(&inputs[0])?.rem_euclid(modulus) == 0).to_string())
            }
            "trustee_transfer_credit" => {
                let (amount, principal) = (integer(&inputs[0])?, integer(&inputs[1])?);
                Ok(amount.min(principal.max(0)).to_string())
            }
            "same_day_display_reorder" => {
                let mut net: i128 = 0;
                let mut tokens = Vec::new();
                for v in inputs {
                    let (token, amount) = v
                        .rsplit_once(':')
                        .ok_or_else(|| bad(format!("`{v}` is not `<token>:<signed amount>`")))?;
                    if token != "CHECK" && token != "STOP PAYMENT" {
                        return Err(bad(format!("`{token}` is CHECK or STOP PAYMENT")));
                    }
                    tokens.push(token);
                    net = net
                        .checked_add(integer(amount)?)
                        .ok_or(DeriveError::Overflow)?;
                }
                if net != 0 {
                    return Err(DeriveError::Infeasible(format!(
                        "the pair nets to {net}, not 0"
                    )));
                }
                Ok(format!("net=0 reordered={}", tokens[0] != "CHECK"))
            }
            other => Err(DeriveError::UnknownRule(other.to_string())),
        }
    }

    /// Recomputes a rule's own example and compares (K-DERIVE's comparison).
    ///
    /// # Errors
    ///
    /// The evaluation's error, or `Mismatch`.
    pub fn check_example(&self, rule: &Rule) -> Result<(), DeriveError> {
        let params = self.params(rule, &rule.example_params)?;
        let computed = self.evaluate(&rule.id, &params, &rule.example_inputs)?;
        compare(rule, &rule.example_params, &rule.example_output, &computed)
    }

    /// `scale`: the literal's exact number × 10^k at the target scale.
    fn scale(&self, literal: &str, params: &Params) -> Result<String, DeriveError> {
        let unit = params.get("unit").cloned().unwrap_or_default();
        let unitless = unit.is_empty();
        let (number, frac_digits) = literal_number(literal, unitless)?;
        let k = match params.get("multiplier") {
            Some(m) => {
                let m: i128 = m.parse().map_err(|_| bad("`multiplier` is an integer"))?;
                power_of_ten(m).ok_or_else(|| {
                    bad(format!(
                        "the multiplier {m} is not an exact power of ten 10^k, k >= 0"
                    ))
                })?
            }
            None => params
                .get("k")
                .map_or(Ok(0), |v| v.parse().map_err(|_| bad("`k` is an integer")))?,
        };
        let target_scale = if unitless {
            -params.get("precision").map_or(Ok(0), |v| {
                v.parse::<i128>()
                    .map_err(|_| bad("`precision` is an integer"))
            })?
        } else {
            i128::from(self.scale_of(&unit)?)
        };
        let exponent = k + target_scale - i128::from(frac_digits);
        if exponent >= 0 {
            number
                .checked_mul(pow10(exponent)?)
                .ok_or(DeriveError::Overflow)
                .map(|v| v.to_string())
        } else {
            let divisor = pow10(-exponent)?;
            if number % divisor != 0 {
                return Err(bad(format!(
                    "`{literal}` is finer than its target scale; a scale result is never rounded"
                )));
            }
            Ok((number / divisor).to_string())
        }
    }

    /// The selected rows of a rows input, in printed order.
    fn select<'r>(rows: &'r [Table], params: &Params) -> Result<Vec<&'r Table>, DeriveError> {
        let account = params
            .get("account")
            .ok_or_else(|| bad("a rows input is narrowed by `account=<trustee account id>`"))?;
        let field = |t: &Table, k: &str| t.get(k).and_then(TomlValue::as_str).map(str::to_string);
        let through = params
            .get("through")
            .map(|d| Day::parse(d).ok_or_else(|| bad("`through` is a date")))
            .transpose()?;
        let picked: Vec<&Table> = rows
            .iter()
            .filter(|t| field(t, "account").as_deref() == Some(account.as_str()))
            .filter(|t| {
                params
                    .get("column")
                    .is_none_or(|c| field(t, "column").as_deref() == Some(c.as_str()))
            })
            .filter(|t| {
                params.get("token").is_none_or(|c| {
                    field(t, "transaction_description").as_deref() == Some(c.as_str())
                })
            })
            .filter(|t| {
                through.is_none_or(|end| {
                    field(t, "date")
                        .and_then(|d| Day::parse(&d))
                        .is_some_and(|d| d <= end)
                })
            })
            .collect();
        if picked.is_empty() {
            return Err(DeriveError::Infeasible(format!(
                "no row of `{account}` matches the selection"
            )));
        }
        Ok(picked)
    }

    fn rows_of(text: &str) -> Result<Vec<Table>, DeriveError> {
        let doc = fa_registry::toml::parse(text)
            .map_err(|e| bad(format!("rows input: {}", e.message)))?;
        Ok(doc.arrays.get("row").cloned().unwrap_or_default())
    }

    fn row_sum(&self, text: &str, params: &Params, unit: &str) -> Result<i128, DeriveError> {
        let rows = Self::rows_of(text)?;
        let mut total: i128 = 0;
        for t in Self::select(&rows, params)? {
            let lit = t
                .get("amount_literal")
                .and_then(TomlValue::as_str)
                .ok_or_else(|| bad("a row has no amount_literal"))?;
            let v: i128 = self
                .scale(lit, &Params::from([("unit".to_string(), unit.to_string())]))?
                .parse()
                .map_err(|_| DeriveError::Overflow)?;
            total = total.checked_add(v).ok_or(DeriveError::Overflow)?;
        }
        Ok(total)
    }

    fn last_balance(&self, text: &str, params: &Params) -> Result<i128, DeriveError> {
        let rows = Self::rows_of(text)?;
        let date = params
            .get("date")
            .and_then(|d| Day::parse(d))
            .ok_or_else(|| bad("`date` is required"))?;
        let mut through = params.clone();
        through.insert("through".into(), date.to_string());
        let picked = Self::select(&rows, &through).map_err(|_| {
            DeriveError::Infeasible(format!("`{date}` is before the account's first row"))
        })?;
        let last = picked
            .last()
            .ok_or_else(|| DeriveError::Infeasible("no row".into()))?;
        let lit = last
            .get("balance_literal")
            .and_then(TomlValue::as_str)
            .ok_or_else(|| bad("the row has no balance_literal"))?;
        let unit = params.get("unit").cloned().unwrap_or_default();
        self.scale(lit, &Params::from([("unit".to_string(), unit)]))?
            .parse()
            .map_err(|_| DeriveError::Overflow)
    }
}

const RULE_FIELDS: [&str; 11] = [
    "id",
    "arity",
    "params",
    "semantics",
    "rounding_law",
    "interpretive",
    "registry_params",
    "example_inputs",
    "example_params",
    "example_output",
    "example_basis",
];

fn str_of(t: &Table, key: &str) -> String {
    t.get(key)
        .and_then(TomlValue::as_str)
        .unwrap_or_default()
        .to_string()
}

fn strs_of(t: &Table, key: &str) -> Vec<String> {
    t.get(key)
        .and_then(TomlValue::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn chart_rows(text: &str, rows: &[Table], errs: &mut Vec<LoadError>) -> Vec<ChartRuleRow> {
    let types: BTreeSet<String> = fa_registry::account_types_embedded()
        .map(|r| r.into_iter().map(|t| t.name).collect())
        .unwrap_or_default();
    let roles = fa_registry::account_roles::AccountRoles::embedded()
        .map(|r| r.rows)
        .unwrap_or_default();
    let mut out = Vec::new();
    let mut keys = BTreeSet::new();
    for (i, t) in rows.iter().enumerate() {
        let line = row_line(text, "chart_rule_row", i);
        let row = ChartRuleRow {
            chart_rule: str_of(t, "chart_rule"),
            concept: str_of(t, "concept"),
            account_type: str_of(t, "type"),
            role: str_of(t, "role"),
            balance_side: str_of(t, "balance_side"),
            read: strs_of(t, "read"),
            reason: t
                .get("reason")
                .and_then(TomlValue::as_str)
                .map(str::to_string),
            example: str_of(t, "example"),
            line,
        };
        let mut push = |kind: LoadErrorKind, detail: String| {
            errs.push(LoadError {
                file: FILE.to_string(),
                line,
                kind,
                row: Some(format!("{}/{}", row.chart_rule, row.concept)),
                detail,
            });
        };
        for key in t.keys() {
            if ![
                "chart_rule",
                "concept",
                "type",
                "role",
                "balance_side",
                "read",
                "reason",
                "example",
            ]
            .contains(&key.as_str())
            {
                push(
                    LoadErrorKind::UnknownField,
                    format!("unknown field `{key}`"),
                );
            }
        }
        if !keys.insert((row.chart_rule.clone(), row.concept.clone())) {
            push(
                LoadErrorKind::DuplicateId,
                "a second row for this (chart_rule, concept)".into(),
            );
        }
        if !row.account_type.is_empty() && !types.contains(&row.account_type) {
            push(
                LoadErrorKind::UnknownValue,
                format!("`type = \"{}\"` is not an account type", row.account_type),
            );
        }
        if !row.role.is_empty() {
            match roles.iter().find(|r| r.name == row.role) {
                None => push(
                    LoadErrorKind::UnknownValue,
                    format!("`role = \"{}\"` is not an account role", row.role),
                ),
                Some(r) if !r.admits(&row.account_type) => push(
                    LoadErrorKind::UnknownValue,
                    format!(
                        "role `{}` does not admit type `{}`",
                        row.role, row.account_type
                    ),
                ),
                Some(_) => {}
            }
        }
        if row.balance_side != "debit" && row.balance_side != "credit" {
            push(
                LoadErrorKind::UnknownValue,
                "`balance_side` is debit or credit".into(),
            );
        }
        let mut seen = BTreeSet::new();
        for r in &row.read {
            if !seen.insert(r) {
                push(LoadErrorKind::DuplicateId, format!("read `{r}` twice"));
            }
            let ok = r == "account"
                || r == "not_modelled"
                || r.strip_prefix("bs:")
                    .or_else(|| r.strip_prefix("is:"))
                    .is_some_and(|c| !c.is_empty());
            if !ok {
                push(
                    LoadErrorKind::WrongType,
                    format!("read `{r}` is bs:<line>, is:<line>, account or not_modelled"),
                );
            }
        }
        if row.read.is_empty() {
            push(
                LoadErrorKind::MissingField,
                "a row names its admissible reads".into(),
            );
        }
        if row.read.iter().any(|r| r == "not_modelled") {
            if row.read.len() > 1 {
                push(
                    LoadErrorKind::UnknownValue,
                    "`not_modelled` stands alone; it is never beside a read".into(),
                );
            }
            if row.reason.as_deref().is_none_or(str::is_empty) {
                push(
                    LoadErrorKind::MissingField,
                    "a not_modelled row states its `reason`".into(),
                );
            }
        }
        out.push(row);
    }
    out
}

/// `Mismatch` unless `computed == expected`.
///
/// # Errors
///
/// `Mismatch` naming the rule, its parameters and both values.
pub fn compare(
    rule: &Rule,
    params: &[String],
    expected: &str,
    computed: &str,
) -> Result<(), DeriveError> {
    if expected == computed {
        Ok(())
    } else {
        Err(DeriveError::Mismatch {
            rule: rule.id.clone(),
            params: params.to_vec(),
            expected: expected.to_string(),
            computed: computed.to_string(),
        })
    }
}

fn pow10(exponent: i128) -> Result<i128, DeriveError> {
    let e = u32::try_from(exponent).map_err(|_| DeriveError::Overflow)?;
    10i128.checked_pow(e).ok_or(DeriveError::Overflow)
}

/// k when `m` is exactly 10^k, k ≥ 0.
fn power_of_ten(mut m: i128) -> Option<i128> {
    if m < 1 {
        return None;
    }
    let mut k = 0;
    while m % 10 == 0 {
        m /= 10;
        k += 1;
    }
    (m == 1).then_some(k)
}

fn integer(v: &str) -> Result<i128, DeriveError> {
    let digits = v.strip_prefix('-').unwrap_or(v);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad(format!("`{v}` is not an integer")));
    }
    v.parse().map_err(|_| DeriveError::Overflow)
}

fn is_rows(input: &str) -> bool {
    input.contains("[[row]]")
}

/// `scale`'s literal grammar: (the number's digits as a signed integer, its
/// fractional digit count).
fn literal_number(literal: &str, unitless: bool) -> Result<(i128, u32), DeriveError> {
    let mut t = literal.trim();
    if matches!(t, "-" | "\u{2013}" | "\u{2014}") {
        return Ok((0, 0));
    }
    let mut negative = false;
    if let Some(inner) = t.strip_prefix('(').and_then(|r| r.strip_suffix(')')) {
        negative = true;
        t = inner.trim();
    }
    if let Some(rest) = t.strip_prefix('-').or_else(|| t.strip_prefix('\u{2212}')) {
        negative = !negative;
        t = rest.trim_start();
    }
    for sign in ['$', '\u{20ac}', '\u{a3}'] {
        if let Some(rest) = t.strip_prefix(sign) {
            t = rest.trim_start();
            break;
        }
    }
    let end = t
        .find(|c: char| !(c.is_ascii_digit() || c == ',' || c == '.'))
        .unwrap_or(t.len());
    let (number, suffix) = t.split_at(end);
    let suffix_ok = match suffix {
        "" => true,
        "x" | "%" => {
            if !unitless {
                return Err(bad(format!(
                    "`{literal}`: a trailing x or % belongs to a unitless value"
                )));
            }
            true
        }
        s => s.starts_with(' ') && s.trim().chars().all(|c| c.is_alphabetic() || c == ' '),
    };
    let (whole, frac) = number.split_once('.').unwrap_or((number, ""));
    let grouped = whole.contains(',');
    let whole_ok = if grouped {
        let groups: Vec<&str> = whole.split(',').collect();
        (1..=3).contains(&groups[0].len())
            && groups[0].bytes().all(|b| b.is_ascii_digit())
            && groups[1..]
                .iter()
                .all(|g| g.len() == 3 && g.bytes().all(|b| b.is_ascii_digit()))
    } else {
        !whole.is_empty() && whole.bytes().all(|b| b.is_ascii_digit())
    };
    let frac_ok =
        frac.bytes().all(|b| b.is_ascii_digit()) && !(number.contains('.') && frac.is_empty());
    if !suffix_ok || !whole_ok || !frac_ok {
        return Err(bad(format!("`{literal}` is not a scale literal")));
    }
    let digits: String = whole
        .chars()
        .filter(|c| *c != ',')
        .chain(frac.chars())
        .collect();
    let value: i128 = digits.parse().map_err(|_| DeriveError::Overflow)?;
    let frac_digits = u32::try_from(frac.len()).map_err(|_| DeriveError::Overflow)?;
    Ok((if negative { -value } else { value }, frac_digits))
}

const MONTH_NAMES: [&str; 12] = [
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
];

fn month_of(word: &str) -> Option<u32> {
    let w = word.trim_end_matches(['.', ',']).to_ascii_lowercase();
    MONTH_NAMES
        .iter()
        .position(|m| {
            *m == w || (w.len() >= 3 && m.starts_with(&w) && (w.len() == 3 || w == "sept"))
        })
        .and_then(|i| u32::try_from(i + 1).ok())
}

fn words(literal: &str) -> Vec<String> {
    literal
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect()
}

fn year_of(word: &str) -> Option<i64> {
    let w = word.trim_end_matches(['.', ',']);
    (w.len() == 4 && w.bytes().all(|b| b.is_ascii_digit()))
        .then(|| w.parse().ok())
        .flatten()
}

fn day_num(word: &str) -> Option<u32> {
    let w = word.trim_end_matches(['.', ',']);
    (!w.is_empty() && w.len() <= 2 && w.bytes().all(|b| b.is_ascii_digit()))
        .then(|| w.parse().ok())
        .flatten()
}

fn make_day(year: i64, month: u32, day: u32) -> Result<Day, DeriveError> {
    Day::parse(&format!("{year:04}-{month:02}-{day:02}"))
        .ok_or_else(|| bad(format!("{year}-{month}-{day} is not a calendar day")))
}

fn date_literal(literal: &str) -> Result<String, DeriveError> {
    let w = words(literal);
    for i in 0..w.len() {
        if let Some(m) = month_of(&w[i])
            && let (Some(d), Some(y)) = (
                w.get(i + 1).and_then(|x| day_num(x)),
                w.get(i + 2).and_then(|x| year_of(x)),
            )
        {
            return make_day(y, m, d).map(|d| d.to_string());
        }
        if let Some(d) = day_num(&w[i])
            && let (Some(m), Some(y)) = (
                w.get(i + 1).and_then(|x| month_of(x)),
                w.get(i + 2).and_then(|x| year_of(x)),
            )
        {
            return make_day(y, m, d).map(|d| d.to_string());
        }
    }
    Err(bad(format!("`{literal}` is not a date with its year")))
}

fn date_range_literal(literal: &str) -> Result<String, DeriveError> {
    let w = words(literal);
    let joiner = |s: &str| matches!(s, "and" | "through" | "to" | "-" | "\u{2013}");
    for i in 0..w.len() {
        let Some(m1) = month_of(&w[i]) else {
            continue;
        };
        let Some(d1) = w.get(i + 1).and_then(|x| day_num(x)) else {
            continue;
        };
        // Month D1, YYYY (joiner) Month D2, YYYY
        if let Some(y1) = w.get(i + 2).and_then(|x| year_of(x))
            && w.get(i + 3).is_some_and(|x| joiner(x))
            && let (Some(m2), Some(d2), Some(y2)) = (
                w.get(i + 4).and_then(|x| month_of(x)),
                w.get(i + 5).and_then(|x| day_num(x)),
                w.get(i + 6).and_then(|x| year_of(x)),
            )
        {
            return range(make_day(y1, m1, d1)?, make_day(y2, m2, d2)?);
        }
        // Month D1 (joiner) D2, YYYY
        if w.get(i + 2).is_some_and(|x| joiner(x))
            && let Some(d2) = w.get(i + 3).and_then(|x| day_num(x))
        {
            let year = w.get(i + 4).and_then(|x| year_of(x)).ok_or_else(|| {
                bad(format!(
                    "`{literal}` names no year; a year-less range is never a literal reading"
                ))
            })?;
            return range(make_day(year, m1, d1)?, make_day(year, m1, d2)?);
        }
    }
    Err(bad(format!(
        "`{literal}` is not a closed day range with its year"
    )))
}

fn range(a: Day, b: Day) -> Result<String, DeriveError> {
    if a > b {
        return Err(bad(format!("{a}..{b} runs backwards")));
    }
    Ok(format!("{a}..{b}"))
}

fn month_literal(literal: &str) -> Result<String, DeriveError> {
    let w = words(literal);
    for i in 0..w.len() {
        if let Some(y) = w.get(i + 1).and_then(|x| year_of(x))
            && w[i].chars().all(char::is_alphabetic)
            && i + 2 == w.len()
        {
            let m = month_of(&w[i]).ok_or_else(|| bad(format!("`{}` is not a month", w[i])))?;
            return Ok(format!("{y:04}-{m:02}"));
        }
    }
    Err(bad(format!("`{literal}` is not a month with its year")))
}

fn number_word(literal: &str) -> Result<i128, DeriveError> {
    const SMALL: [&str; 21] = [
        "zero",
        "one",
        "two",
        "three",
        "four",
        "five",
        "six",
        "seven",
        "eight",
        "nine",
        "ten",
        "eleven",
        "twelve",
        "thirteen",
        "fourteen",
        "fifteen",
        "sixteen",
        "seventeen",
        "eighteen",
        "nineteen",
        "twenty",
    ];
    let w = literal.trim().to_ascii_lowercase();
    if let Some(i) = SMALL.iter().position(|s| *s == w) {
        return i128::try_from(i).map_err(|_| DeriveError::Overflow);
    }
    let tens = [
        "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety",
    ];
    if let Some(i) = tens.iter().position(|s| *s == w) {
        return i128::try_from(30 + 10 * i).map_err(|_| DeriveError::Overflow);
    }
    match w.as_str() {
        "hundred" => Ok(100),
        "thousand" => Ok(1_000),
        "million" => Ok(1_000_000),
        "billion" => Ok(1_000_000_000),
        _ => Err(bad(format!("`{literal}` is not a registered number word"))),
    }
}

fn period_literal(literal: &str) -> Result<String, DeriveError> {
    let mut phrase = literal
        .trim()
        .trim_end_matches(['.', ',', ';', ':'])
        .to_string();
    loop {
        let lower = phrase.to_ascii_lowercase();
        let stripped = ["the ", "in ", "for ", "during "].iter().find_map(|p| {
            lower
                .starts_with(p)
                .then(|| phrase[p.len()..].trim_start().to_string())
        });
        match stripped {
            Some(s) => phrase = s,
            None => break,
        }
    }
    let w = words(&phrase);
    let lower: Vec<String> = w.iter().map(|x| x.to_ascii_lowercase()).collect();
    let year4 =
        |s: &str| (s.len() == 4 && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.to_string());
    let q_word = |s: &str| match s {
        "first" => Some(1),
        "second" => Some(2),
        "third" => Some(3),
        "fourth" => Some(4),
        _ => None,
    };
    let result = match lower.as_slice() {
        [one] => {
            let b = one.as_bytes();
            if b.len() == 4
                && (b'1'..=b'4').contains(&b[0])
                && b[1] == b'q'
                && b[2..].iter().all(u8::is_ascii_digit)
            {
                let yy: i64 = one[2..].parse().unwrap_or(0);
                Some(format!(
                    "{}Q{}",
                    if yy < 50 { 2000 + yy } else { 1900 + yy },
                    b[0] - b'0'
                ))
            } else if b.len() == 6
                && b[4] == b'q'
                && (b'1'..=b'4').contains(&b[5])
                && b[..4].iter().all(u8::is_ascii_digit)
            {
                Some(format!("{}Q{}", &one[..4], b[5] - b'0'))
            } else {
                one.strip_prefix("fy")
                    .and_then(year4)
                    .map(|y| format!("FY{y}"))
            }
        }
        [q, y] if q.len() == 2 && q.starts_with('q') => {
            let n = q[1..].parse::<u8>().ok().filter(|n| (1..=4).contains(n));
            n.zip(year4(y)).map(|(n, y)| format!("{y}Q{n}"))
        }
        [fy, y] if fy == "fy" || fy == "fiscal" => year4(y).map(|y| format!("FY{y}")),
        [fiscal, year, y] if fiscal == "fiscal" && year == "year" => {
            year4(y).map(|y| format!("FY{y}"))
        }
        [ord, quarter, rest @ ..] if q_word(ord).is_some() && quarter == "quarter" => {
            let y = match rest {
                [of, y] if of == "of" => year4(y),
                [y] => year4(y),
                _ => None,
            };
            match y {
                Some(y) => Some(format!("{y}Q{}", q_word(ord).unwrap_or(0))),
                None => {
                    return Err(bad(format!(
                        "`{literal}` names no year; a year-less quarter is never a literal reading"
                    )));
                }
            }
        }
        _ => None,
    };
    result.ok_or_else(|| {
        bad(format!(
            "`{literal}` is not exactly one period phrase with its year"
        ))
    })
}

/// One leg token.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Leg {
    side: String,
    account: String,
    amount: i128,
    unit: String,
}

impl Leg {
    fn parse(token: &str) -> Result<Self, DeriveError> {
        let parts: Vec<&str> = token.split(':').collect();
        let [side, account, amount, unit] = parts.as_slice() else {
            return Err(bad(format!(
                "`{token}` is not `<Dr|Cr>:<account>:<amount>:<unit>`"
            )));
        };
        if *side != "Dr" && *side != "Cr" {
            return Err(bad(format!("`{token}`: the side is Dr or Cr")));
        }
        Ok(Self {
            side: (*side).to_string(),
            account: (*account).to_string(),
            amount: integer(amount)?,
            unit: (*unit).to_string(),
        })
    }
}

impl fmt::Display for Leg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}",
            self.side, self.account, self.amount, self.unit
        )
    }
}

/// One entry token: its date and its sorted legs (a multiset).
struct Entry {
    day: Day,
    legs: Vec<Leg>,
}

impl Entry {
    fn parse(token: &str) -> Result<Self, DeriveError> {
        let (date, legs) = token
            .split_once('@')
            .ok_or_else(|| bad(format!("`{token}` is not `<date>@<leg>;<leg>…`")))?;
        let day = Day::parse(date).ok_or_else(|| bad(format!("`{date}` is not a valid date")))?;
        let mut legs = legs
            .split(';')
            .map(Leg::parse)
            .collect::<Result<Vec<_>, _>>()?;
        legs.sort();
        Ok(Self { day, legs })
    }
}

fn legacy_tb(inputs: &[String], periods: &str) -> Result<String, DeriveError> {
    let mut declared = Vec::new();
    for p in periods.split(',').filter(|p| !p.is_empty()) {
        let (label, end) = p
            .split_once('@')
            .ok_or_else(|| bad(format!("period `{p}` is not `<label>@<end date>`")))?;
        let end = Day::parse(end).ok_or_else(|| bad(format!("`{end}` is not a valid date")))?;
        declared.push((label, end));
    }
    if declared.is_empty() {
        return Err(bad("`periods` declares at least one Historical period"));
    }
    let mut legs = Vec::new();
    for line in inputs {
        let parts: Vec<&str> = line.split('|').collect();
        let [date, account, unit, amount] = parts.as_slice() else {
            return Err(bad(format!(
                "`{line}` is not `<date>|<account>|<unit>|<signed amount>`"
            )));
        };
        let day = Day::parse(date).ok_or_else(|| bad(format!("`{date}` is not a valid date")))?;
        legs.push((
            day,
            (*account).to_string(),
            (*unit).to_string(),
            integer(amount)?,
        ));
    }
    let mut out = Vec::new();
    for (label, end) in declared {
        let mut fold: BTreeMap<(String, String), i128> = BTreeMap::new();
        for (day, account, unit, amount) in &legs {
            if day <= &end {
                let slot = fold.entry((account.clone(), unit.clone())).or_default();
                *slot = slot.checked_add(*amount).ok_or(DeriveError::Overflow)?;
            }
        }
        let lines: Vec<String> = fold
            .into_iter()
            .filter(|(_, v)| *v != 0)
            .map(|((a, u), v)| format!("{a}:{u}:{v}"))
            .collect();
        out.push(format!("{label}={}", lines.join(",")));
    }
    Ok(out.join(";"))
}

fn round_density(
    x: i128,
    n: i128,
    big_x: i128,
    big_n: i128,
    min_legs: i128,
    z_squared: i128,
) -> Result<String, DeriveError> {
    if n < min_legs {
        return Ok("untested".into());
    }
    let mul = |a: i128, b: i128| a.checked_mul(b).ok_or(DeriveError::Overflow);
    let lhs = mul(x, big_n)?
        .checked_sub(mul(n, big_x)?)
        .ok_or(DeriveError::Overflow)?;
    if lhs <= 0 {
        return Ok("not_flagged".into());
    }
    let squared = mul(lhs, lhs)?;
    let threshold = mul(
        mul(mul(z_squared, n)?, big_x)?,
        big_n.checked_sub(big_x).ok_or(DeriveError::Overflow)?,
    )?;
    if squared < threshold {
        return Ok("not_flagged".into());
    }
    Ok(if squared >= mul(4, threshold)? {
        "flagged:High"
    } else {
        "flagged:Medium"
    }
    .into())
}

/// Nigrini's MAD at nine places over `table` and its band.
///
/// # Errors
///
/// `Overflow`.
pub fn benford_mad(
    counts: &[i128; 9],
    table: &[i128; 9],
    min_population: i128,
    bands: [i128; 3],
) -> Result<String, DeriveError> {
    let total: i128 = counts
        .iter()
        .try_fold(0i128, |a, c| a.checked_add(*c))
        .ok_or(DeriveError::Overflow)?;
    if total < min_population {
        return Ok(format!("untested population={total}"));
    }
    let mut sum: i128 = 0;
    for (c, p) in counts.iter().zip(table) {
        let observed = c.checked_mul(1_000_000_000).ok_or(DeriveError::Overflow)?;
        let expected = total.checked_mul(*p).ok_or(DeriveError::Overflow)?;
        sum = sum
            .checked_add(
                observed
                    .checked_sub(expected)
                    .ok_or(DeriveError::Overflow)?
                    .abs(),
            )
            .ok_or(DeriveError::Overflow)?;
    }
    let mad = sum / total.checked_mul(9).ok_or(DeriveError::Overflow)?;
    let [close, acceptable, marginal] = bands.map(|b| b * 1_000_000);
    let band = if mad <= close {
        "close"
    } else if mad <= acceptable {
        "acceptable"
    } else if mad <= marginal {
        "marginal"
    } else {
        "nonconformity"
    };
    Ok(format!("mad_1e9={mad} band={band}"))
}

/// Whether a copy of the Benford table sums to exactly 10^9.
///
/// # Errors
///
/// The sum it reaches instead.
pub fn check_benford_table(table: &[i128; 9]) -> Result<(), i128> {
    let sum: i128 = table.iter().sum();
    if sum == 1_000_000_000 {
        Ok(())
    } else {
        Err(sum)
    }
}

#[cfg(test)]
#[path = "derive_tests.rs"]
mod tests;
