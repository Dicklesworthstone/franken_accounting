//! Certified reads and kernel assertions (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §3.3 step 7, §5.3; bead fa-yugf.16, A7b).
//!
//! After the history, every T and R row's read runs once and is kept on the
//! run, keyed by `<expectation>/<target fact>` (`-` for a row without
//! targets). A `balance` read is `fa explain balance <account> --period
//! <code> --certify --json` (its value the cell's net); a `balance-sheet`
//! or `income-statement` read is `fa statement <verb> --for <code>
//! --certify --json` (its value the current column of the line whose code
//! is the read's target); a `tb` read is `fa tb --period <code> --certify
//! --json` (its value the target account's net). Each reads through the
//! row's selector: `--as-originally-reported`,
//! `--as-currently-stated`, or `--as-reported-in C:<oid>` for
//! `reported_in:<period>[#<n>]`, the certificate the period's n-th `issue`
//! step issued. Its value is the cell's net (debits minus credits) in the
//! published unit's minor units. A coordinate is a `[[period]] code`, or a
//! fiscal year label (`FY<yyyy>`), read at that year's last period. An
//! `assert_balance` step records B with `fa assert-balance` and posts its
//! twins, B plus and B minus one minor unit, which the kernel must each
//! refuse `FA-REF-140` (§5.3, §3.7 item 4).

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

/// One `assert_balance` step's calls.
pub struct Assertion {
    pub asserted: Call,
    /// Its twins, each with its offset from B in minor units (+1, then -1).
    pub twins: Vec<(i128, Call)>,
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
        let (slot, view) = self.view(selector);
        let mut token = format!("{verb},{target},{coordinate}");
        if let Some(slot) = slot {
            token.push(',');
            token.push_str(&slot);
        }
        let fail = |token: String, why: String| Read {
            token,
            value: Err(why),
            certificate: None,
        };
        if !matches!(
            verb,
            "balance" | "balance-sheet" | "income-statement" | "tb"
        ) {
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
        let mut args: Vec<String> = match verb {
            "balance" => ["explain", "balance", target, "--period"]
                .map(str::to_string)
                .into(),
            "tb" => ["tb", "--period"].map(str::to_string).into(),
            _ => ["statement", verb, "--for"].map(str::to_string).into(),
        };
        args.push(code);
        match view {
            Ok(flags) => args.extend(flags),
            Err(why) => return fail(token, why),
        }
        args.extend(["--certify".to_string(), "--json".to_string()]);
        let reference = key(e, t);
        let called = args.first().cloned().unwrap_or_default();
        // The command, as a refusal names it: `explain balance`, `statement
        // <verb>` or `tb`.
        let command = if verb == "tb" {
            called.clone()
        } else {
            args.get(..2).unwrap_or_default().join(" ")
        };
        let call = self.call(self.head, &reference, &called, args);
        if call.exit != 0 {
            self.lines.push(reproduce(&call));
            return fail(
                token,
                format!(
                    "expected exit=0 from {command} observed exit={} {}",
                    call.exit,
                    call.refusal_id().unwrap_or_default()
                )
                .trim_end()
                .to_string(),
            );
        }
        let in_unit = |amount: &str| amount.ends_with(&format!(" {unit}"));
        let (certificate, net) = match verb {
            "balance" => (
                call.str_field("balance_explained", "certificate"),
                call.array_field("balance_explained", "cells")
                    .iter()
                    .find(|c| c.get("unit").and_then(Json::as_str) == Some(unit.as_str()))
                    .and_then(|c| c.get("net").and_then(Json::as_str).map(str::to_string)),
            ),
            "tb" => (
                call.str_field("report_certificate", "oid"),
                call.array_field("trial_balance", "rows")
                    .iter()
                    .filter(|r| r.get("code").and_then(Json::as_str) == Some(target))
                    .filter_map(|r| r.get("net").and_then(Json::as_str))
                    .find(|n| in_unit(n))
                    .map(str::to_string),
            ),
            // A statement line's amounts are in column order; the first is
            // the current period's.
            _ => (
                call.str_field("report_certificate", "oid"),
                call.array_field("statement", "lines")
                    .iter()
                    .find(|l| {
                        l.get("code").and_then(Json::as_str) == Some(target)
                            && l.get("unit").and_then(Json::as_str) == Some(unit.as_str())
                    })
                    .and_then(|l| l.get("amounts").and_then(Json::as_array))
                    .and_then(<[Json]>::first)
                    .and_then(Json::as_str)
                    .map(str::to_string),
            ),
        };
        let value = match (net, scale_of(&unit)) {
            // No cell in the unit: the account holds nothing in it. A
            // statement line or trial-balance row that is not there is
            // no read.
            (None, Some(_)) if verb == "balance" => Ok(0),
            (None, Some(_)) => Err(format!(
                "expected a {verb} line {target} in {unit} observed none"
            )),
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

    /// A read selector's slot in the `read=` token and its flags (§3.3 step
    /// 7): `as-originally-reported`, `as-currently-stated`, or
    /// `as-reported-in=$C_ISSUE_<period>[_<n>]`, the certificate of the
    /// period's n-th issuance.
    fn view(&self, selector: Option<&str>) -> (Option<String>, Result<Vec<String>, String>) {
        let flag = |slot: &str| (Some(slot.to_string()), Ok(vec![format!("--{slot}")]));
        let Some(selector) = selector else {
            return (None, Ok(Vec::new()));
        };
        match selector {
            "originally_reported" => return flag("as-originally-reported"),
            "currently_stated" => return flag("as-currently-stated"),
            _ => {}
        }
        let Some(rest) = selector.strip_prefix("reported_in:") else {
            return (
                Some(selector.to_string()),
                Err(format!(
                    "expected a read_selector originally_reported, currently_stated or reported_in:<period>[#<n>] observed {selector}"
                )),
            );
        };
        let (label, n) = rest
            .split_once('#')
            .map_or((rest, Some(1)), |(l, n)| (l, n.parse::<usize>().ok()));
        let placeholder = match n {
            Some(1) => format!("$C_ISSUE_{label}"),
            Some(n) => format!("$C_ISSUE_{label}_{n}"),
            None => format!("$C_ISSUE_{label}_?"),
        };
        let issued = self.issuances.get(label);
        let oid = n
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| issued.and_then(|v| v.get(i)));
        let flags = match oid {
            Some(oid) => Ok(vec!["--as-reported-in".to_string(), format!("C:{oid}")]),
            None => Err(format!(
                "expected an issuance {placeholder} observed {} issuance(s) of {label}",
                issued.map_or(0, Vec::len)
            )),
        };
        (Some(format!("as-reported-in={placeholder}")), flags)
    }

    /// An `assert_balance` step: B recorded with `fa assert-balance` on the
    /// cell its row reads, citing the step's filing stub, and its twins (B
    /// plus and B minus one minor unit) posted to be refused (§5.3).
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
        let asserted = self.call(step.seq, &step.reference, "assert-balance", args_for(minor));
        let mut twins = Vec::new();
        for offset in [1, -1] {
            // A twin past the i128 range has no cell to differ from.
            if let Some(amount) = minor.checked_add(offset) {
                let call = self.call(
                    step.seq,
                    &step.reference,
                    "assert-balance",
                    args_for(amount),
                );
                twins.push((offset, call));
            }
        }
        self.assertions.insert(
            step.reference.clone(),
            Assertion {
                asserted,
                twins,
                balance: format!("{} {unit}", format_amount(minor, scale)),
            },
        );
    }
}
