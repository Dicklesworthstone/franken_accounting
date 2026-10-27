//! Certified reads and kernel assertions (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §3.3 step 7, §5.3; bead fa-yugf.16, A7b).
//!
//! After the history, every T and R row's read runs once and is kept on the
//! run, keyed by `<expectation>/<target fact>` (`-` for a row without
//! targets). A `balance` read is `fa explain balance <account> --period
//! <code> --certify --json` over every period the read's fold spans, since
//! the command explains one period's cells: every declared period through
//! the read's for a stock account (Asset, Liability, Equity), the read's own
//! periods for a flow account (Revenue, Expense; a fiscal year is each of
//! its periods). Its value is the sum of the cells' nets, and it keeps each
//! posted leg it explained, mapped to the intent that posted it, for the
//! contributing-entry witness (A11b). A `balance-sheet`
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

use std::collections::BTreeMap;

use fa_oracles::cases::amount::{format_amount, parse_amount};
use fa_oracles::cases::book::StepDef;
use fa_oracles::cases::contrib::Contribution;
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
    /// A `balance` read's posted legs, every period it explained (A11b).
    pub contributions: Option<Vec<Contribution>>,
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
            contributions: None,
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
        if verb == "balance" {
            return match view {
                Ok(flags) => self.read_balance(e, t, token, &unit, &flags),
                Err(why) => fail(token, why),
            };
        }
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
            contributions: None,
        }
    }

    /// The periods a `balance` read of `account` at `coordinate` folds, in
    /// calendar order (module doc).
    fn fold_periods(&self, account: &str, coordinate: &str) -> Option<Vec<String>> {
        let book = self.book;
        let own: Vec<&fa_oracles::cases::book::PeriodDef> =
            match book.periods.iter().find(|p| p.code == coordinate) {
                Some(p) => vec![p],
                None => {
                    let fy: i128 = coordinate.strip_prefix("FY")?.parse().ok()?;
                    book.periods
                        .iter()
                        .filter(|p| p.fiscal_year == fy)
                        .collect()
                }
            };
        let end = own.iter().map(|p| p.end.as_str()).max()?;
        let stock = book.accounts.iter().any(|a| {
            a.code == account && matches!(a.account_type.as_str(), "Asset" | "Liability" | "Equity")
        });
        let mut periods: Vec<&fa_oracles::cases::book::PeriodDef> = if stock {
            book.periods
                .iter()
                .filter(|p| p.end.as_str() <= end)
                .collect()
        } else {
            own
        };
        periods.sort_by(|a, b| a.end.cmp(&b.end));
        Some(periods.into_iter().map(|p| p.code.clone()).collect())
    }

    /// A `balance` read: `fa explain balance --certify` in each period of
    /// the read's fold (module doc). The certificate kept is the last
    /// period's, the read's own.
    fn read_balance(
        &mut self,
        e: &Expectation,
        t: Option<&Target>,
        token: String,
        unit: &str,
        flags: &[String],
    ) -> Read {
        let account = field(e, t, "read_target").unwrap_or("-");
        let coordinate = field(e, t, "read_coordinate").unwrap_or("-");
        let fail = |token: String, why: String| Read {
            token,
            value: Err(why),
            certificate: None,
            contributions: None,
        };
        let Some(scale) = scale_of(unit) else {
            return fail(token, format!("unit `{unit}` is not registered"));
        };
        let Some(periods) = self.fold_periods(account, coordinate) else {
            return fail(
                token,
                format!("expected a period for `{coordinate}` observed none"),
            );
        };
        let posted_by: BTreeMap<String, String> = self
            .vids
            .iter()
            .map(|(intent, vid)| (vid.clone(), intent.clone()))
            .collect();
        let reference = key(e, t);
        let (mut total, mut certificate, mut contributions) = (0_i128, None, Vec::new());
        for label in periods {
            let Some(code) = self.periods.get(&label).cloned() else {
                return fail(
                    token,
                    format!("expected a created period for {label} observed none"),
                );
            };
            let mut args = vec![
                "explain".to_string(),
                "balance".to_string(),
                account.to_string(),
                "--period".to_string(),
                code,
            ];
            args.extend(flags.iter().cloned());
            args.extend(["--certify".to_string(), "--json".to_string()]);
            let call = self.call(self.head, &reference, "explain", args);
            self.certificate_kind("ExplainBalance");
            if call.exit != 0 {
                self.lines.push(reproduce(&call));
                return fail(
                    token,
                    format!(
                        "expected exit=0 from explain balance of {label} observed exit={} {}",
                        call.exit,
                        call.refusal_id().unwrap_or_default()
                    )
                    .trim_end()
                    .to_string(),
                );
            }
            certificate = call.str_field("balance_explained", "certificate");
            // No cell in the unit: the account holds nothing in it there.
            let net = call
                .array_field("balance_explained", "cells")
                .iter()
                .find(|c| c.get("unit").and_then(Json::as_str) == Some(unit))
                .and_then(|c| c.get("net").and_then(Json::as_str).map(str::to_string));
            let in_unit = |amount: &str| -> Result<Option<i128>, String> {
                match amount.strip_suffix(unit).map(str::trim_end) {
                    Some(a) => parse_amount(a, scale)
                        .map(Some)
                        .map_err(|err| format!("amount `{amount}`: {err:?}")),
                    None => Ok(None),
                }
            };
            if let Some(n) = net {
                match in_unit(&n) {
                    Ok(Some(v)) => match total.checked_add(v) {
                        Some(sum) => total = sum,
                        None => return fail(token, "the explained nets overflow".into()),
                    },
                    Ok(None) => {
                        return fail(token, format!("expected a net in {unit} observed `{n}`"));
                    }
                    Err(why) => return fail(token, why),
                }
            }
            for c in call.array_field("balance_explained", "contributions") {
                if c.get("column").and_then(Json::as_str) != Some("posted") {
                    continue;
                }
                let amount = c.get("amount").and_then(Json::as_str).unwrap_or_default();
                let minor = match in_unit(amount) {
                    Ok(Some(v)) => v,
                    Ok(None) => continue,
                    Err(why) => return fail(token, why),
                };
                let signed = if c.get("side").and_then(Json::as_str) == Some("debit") {
                    minor
                } else {
                    match minor.checked_neg() {
                        Some(v) => v,
                        None => return fail(token, "a contribution overflows".into()),
                    }
                };
                let entry = c
                    .get("entry")
                    .and_then(Json::as_str)
                    .unwrap_or_default()
                    .to_string();
                contributions.push(Contribution {
                    intent: posted_by.get(&entry).cloned(),
                    entry,
                    account: account.to_string(),
                    signed,
                });
            }
        }
        Read {
            token,
            value: Ok(total),
            certificate,
            contributions: Some(contributions),
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
