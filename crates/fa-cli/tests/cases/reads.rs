//! Certified reads and kernel assertions (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §3.3 step 7, §5.3; bead fa-yugf.16, A7b).
//!
//! After the history, every T and R row's read runs once and is kept on the
//! run, keyed by `<expectation>/<target fact>` (`-` for a row without
//! targets). A `balance` read is `fa explain balance <account> --period
//! <code> --certify --json` (with `--as-originally-reported` or
//! `--as-currently-stated` for those selectors); its value is the cell's
//! net (debits minus credits) in the published unit's minor units. A
//! coordinate is a `[[period]] code`, or a fiscal year label (`FY<yyyy>`),
//! read at that year's last period. An `assert_balance` step records B with
//! `fa assert-balance` and posts its twin, B plus one minor unit, which the
//! kernel must refuse `FA-REF-140` (§5.3, §3.7 item 4).

use fa_oracles::cases::amount::{format_amount, parse_amount};
use fa_oracles::cases::book::StepDef;
use fa_oracles::cases::expect::{Expectation, ExpectationType, Target};
use fa_oracles::json::Json;

use super::run::{BookRun, Call, reproduce};

/// One T or R row's read.
pub struct Read {
    /// `<verb>,<target>,<coordinate>[,<selector>]`, the row's `read=` token.
    pub token: String,
    /// The observed value in minor units, or why there is none.
    pub value: Result<i128, String>,
    /// The certificate the read retained, if any.
    pub certificate: Option<String>,
}

/// One `assert_balance` step's two calls.
pub struct Assertion {
    pub asserted: Call,
    pub twin: Call,
    /// The asserted B, as the step rendered it (`<amount> <UNIT>`).
    pub balance: String,
}

/// A registered unit's scale.
#[must_use]
pub fn scale_of(unit: &str) -> Option<u8> {
    fa_registry::units_embedded()
        .ok()?
        .into_iter()
        .find(|r| r.code == unit)
        .map(|r| r.scale)
}

/// A row's field: its target's, else its expectation's.
pub fn field<'a>(e: &'a Expectation, t: Option<&'a Target>, key: &str) -> Option<&'a str> {
    t.and_then(|t| t.fields.str(key))
        .or_else(|| e.fields.str(key))
}

/// The key a row's read is kept under.
#[must_use]
pub fn key(e: &Expectation, t: Option<&Target>) -> String {
    format!("{}/{}", e.id, t.map_or("-", |t| t.fact.as_str()))
}

impl BookRun<'_> {
    /// The unit and scale of a fact's first `[[value]]`.
    pub(crate) fn value_of(&self, fact: &str) -> Option<(i128, String)> {
        let v = self
            .case
            .values
            .iter()
            .find(|v| v.fact == fact && v.ordinal == 1)?;
        Some((v.value.parse().ok()?, v.unit.clone()))
    }

    /// The book's period code for a coordinate: a `[[period]] code`, or
    /// `FY<yyyy>`, the last period of that fiscal year.
    fn period_code(&self, coordinate: &str) -> Option<String> {
        if let Some(code) = self.periods.get(coordinate) {
            return Some(code.clone());
        }
        let fy: i128 = coordinate.strip_prefix("FY")?.parse().ok()?;
        let last = self
            .book
            .periods
            .iter()
            .filter(|p| p.fiscal_year == fy)
            .max_by(|a, b| a.end.cmp(&b.end))?;
        self.periods.get(&last.code).cloned()
    }

    /// Every T and R row's read of this variant (§3.3 step 7).
    pub(crate) fn reads(&mut self) {
        let case = self.case;
        let Some(set) = case.expectations.as_ref() else {
            return;
        };
        let variant = self.book.stem.as_str();
        let mut wanted: Vec<(&Expectation, Option<&Target>)> = Vec::new();
        for e in set.expectations.iter().filter(|e| {
            matches!(e.kind, ExpectationType::T | ExpectationType::R)
                && e.fields.str("book_variant") == Some(variant)
        }) {
            let targets: Vec<&Target> = set.targets_of(&e.id).collect();
            if targets.is_empty() {
                wanted.push((e, None));
            } else {
                wanted.extend(targets.into_iter().map(|t| (e, Some(t))));
            }
        }
        for (e, t) in wanted {
            let read = self.read(e, t);
            self.reads.insert(key(e, t), read);
        }
    }

    fn read(&mut self, e: &Expectation, t: Option<&Target>) -> Read {
        let verb = field(e, t, "read_verb").unwrap_or("-");
        let target = field(e, t, "read_target").unwrap_or("-");
        let coordinate = field(e, t, "read_coordinate").unwrap_or("-");
        let selector = field(e, t, "read_selector").filter(|s| !s.is_empty());
        let mut token = format!("{verb},{target},{coordinate}");
        if let Some(sel) = selector {
            token.push(',');
            token.push_str(&sel.replace('_', "-"));
        }
        let fail = |token: String, why: String| Read {
            token,
            value: Err(why),
            certificate: None,
        };
        if verb != "balance" {
            return fail(token, format!("needs:A7b ({verb} reads)"));
        }
        let Some(code) = self.period_code(coordinate) else {
            return fail(
                token,
                format!("expected a period for `{coordinate}` observed none"),
            );
        };
        // The published (T) or posted (R) value fixes the unit read.
        let value_key = if e.kind == ExpectationType::T {
            "published"
        } else {
            "posted"
        };
        let unit = field(e, t, value_key)
            .and_then(|f| self.value_of(f))
            .map_or_else(|| self.book.book.base_unit.clone(), |(_, u)| u);
        let mut args = vec![
            "explain".to_string(),
            "balance".to_string(),
            target.to_string(),
            "--period".to_string(),
            code,
        ];
        match selector {
            None => {}
            Some("originally_reported") => args.push("--as-originally-reported".into()),
            Some("currently_stated") => args.push("--as-currently-stated".into()),
            Some(other) => return fail(token, format!("needs:A7b ({other} reads)")),
        }
        args.extend(["--certify".to_string(), "--json".to_string()]);
        let reference = key(e, t);
        let call = self.call(self.head, &reference, "explain", args);
        if call.exit != 0 {
            self.lines.push(reproduce(&call));
            return fail(
                token,
                format!(
                    "expected exit=0 from explain balance observed exit={}",
                    call.exit
                ),
            );
        }
        let certificate = call.str_field("balance_explained", "certificate");
        let net = call
            .array_field("balance_explained", "cells")
            .iter()
            .find(|c| c.get("unit").and_then(Json::as_str) == Some(unit.as_str()))
            .and_then(|c| c.get("net").and_then(Json::as_str).map(str::to_string));
        let value = match (net, scale_of(&unit)) {
            // No cell in the unit: the account holds nothing in it.
            (None, Some(_)) => Ok(0),
            // The net renders with its unit (`1000.00 USD`).
            (Some(n), Some(s)) => match n.strip_suffix(unit.as_str()).map(str::trim_end) {
                Some(amount) => {
                    parse_amount(amount, s).map_err(|err| format!("net `{n}`: {err:?}"))
                }
                None => Err(format!("expected a net in {unit} observed `{n}`")),
            },
            (_, None) => Err(format!("unit `{unit}` is not registered")),
        };
        Read {
            token,
            value,
            certificate,
        }
    }

    /// An `assert_balance` step: B recorded with `fa assert-balance` on the
    /// cell its row reads, citing the step's filing stub, and its twin (B
    /// plus one minor unit) posted to be refused (§5.3).
    pub(crate) fn assert_balance(&mut self, step: &StepDef) {
        let case = self.case;
        let Some(set) = case.expectations.as_ref() else {
            return;
        };
        let (id, fact) = step
            .reference
            .split_once('#')
            .map_or((step.reference.as_str(), None), |(e, f)| (e, Some(f)));
        let Some(e) = set.get(id) else {
            self.fail(format!(
                "expected an expectation {id} for assert_balance (step {}) observed none",
                step.seq
            ));
            return;
        };
        let t = fact.and_then(|f| set.targets_of(id).find(|t| t.fact == f));
        let value_key = if e.kind == ExpectationType::T {
            "published"
        } else {
            "posted"
        };
        let asserts = step.asserts.as_deref().or_else(|| field(e, t, value_key));
        let (Some(account), Some(coordinate), Some(asserts)) = (
            field(e, t, "read_target"),
            field(e, t, "read_coordinate"),
            asserts,
        ) else {
            self.fail(format!(
                "expected the read and the asserted fact of {} (step {}) observed none",
                step.reference, step.seq
            ));
            return;
        };
        let (Some(code), Some((minor, unit))) =
            (self.period_code(coordinate), self.value_of(asserts))
        else {
            self.fail(format!(
                "expected a period and a value for {} (step {}) observed none",
                step.reference, step.seq
            ));
            return;
        };
        let Some(scale) = scale_of(&unit) else {
            self.fail(format!("expected a registered unit `{unit}` observed none"));
            return;
        };
        let evidence = step
            .evidence
            .as_deref()
            .and_then(|d| self.documents.get(d).cloned());
        let principal = step
            .principal
            .clone()
            .unwrap_or_else(|| "examiner-1".to_string());
        let args_for = |amount: i128| {
            let mut args = vec![
                "assert-balance".to_string(),
                "--account".to_string(),
                account.to_string(),
                "--period".to_string(),
                code.clone(),
                "--balance".to_string(),
                format!("{} {unit}", format_amount(amount, scale)),
            ];
            if let Some(oid) = &evidence {
                args.extend(["--evidence".to_string(), oid.clone()]);
            }
            args.extend(["--as".to_string(), principal.clone(), "--json".to_string()]);
            args
        };
        let asserted_args = args_for(minor);
        let twin_args = args_for(minor + 1);
        let asserted = self.call(step.seq, &step.reference, "assert-balance", asserted_args);
        let twin = self.call(step.seq, &step.reference, "assert-balance", twin_args);
        self.assertions.insert(
            step.reference.clone(),
            Assertion {
                asserted,
                twin,
                balance: format!("{} {unit}", format_amount(minor, scale)),
            },
        );
    }
}
