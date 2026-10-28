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

use std::cell::Cell;
use std::collections::BTreeMap;

use fa_oracles::cases::amount::{format_amount, parse_amount};
use fa_oracles::cases::book::StepDef;
use fa_oracles::cases::contrib::{self, Contribution, ExplainedLeg, Explanation, Publication};
use fa_oracles::cases::expect::{Expectation, ExpectationType, Target};
use fa_oracles::cases::outsider_kind::READ_VERBS;
use fa_oracles::json::Json;

use super::run::{BookRun, Call, reproduce};

thread_local! {
    /// Test-only: drop the last publication that moves a statement line in
    /// its trace (the trace/explained-balance disagreement negative; the
    /// binary's two reads agree, so only the runner can make them differ).
    pub static DROP_LAST_PUBLICATION: Cell<bool> = const { Cell::new(false) };
}

/// One T or R row's read.
pub struct Read {
    /// `<verb>,<target>,<coordinate>[,<selector>]`, the row's `read=` token.
    pub token: String,
    /// The observed value in minor units, or why there is none.
    pub value: Result<i128, String>,
    /// The certificate the read retained, if any.
    pub certificate: Option<String>,
    /// Every certificate the read retained, in fold order: a `balance` read
    /// retains one per period it explained (A12 bundles each).
    pub certificates: Vec<String>,
    /// A `balance` read's posted legs, every period it explained (A11b).
    pub contributions: Option<Vec<Contribution>>,
    /// An as-originally-reported read: whether its value differs from the
    /// same line as currently stated. `Some(false)` is a line no delta
    /// moved, where the read did not exercise its selector (A11b). `None`
    /// for any other selector, or when either read has no value.
    pub exercised: Option<bool>,
    /// A statement line T read at the head: the line's `fa statement trace`
    /// over the history, or why it has none (A11b). `None` for any other
    /// read.
    pub trace: Option<Result<LineTrace, String>>,
}

/// A statement line's trace from the history's start to the read's head.
pub struct LineTrace {
    pub publications: Vec<Publication>,
    /// The trace's `REPRODUCE` line.
    pub reproduce: String,
}

/// One `assert_balance` step's calls.
pub struct Assertion {
    pub asserted: Call,
    /// The attestation `attestation_recorded` reported: its claim and
    /// whether it holds.
    pub claim: Option<String>,
    pub holds: Option<bool>,
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

    /// A row's read under its own selector. An as-originally-reported read
    /// also reads the same line as currently stated, to tell whether any
    /// delta moved it ([`Read::exercised`]).
    fn read(&mut self, e: &Expectation, t: Option<&Target>) -> Read {
        let selector = field(e, t, "read_selector").filter(|s| !s.is_empty());
        let mut read = self.read_as(e, t, selector);
        if selector == Some("originally_reported")
            && let Ok(original) = read.value
        {
            let current = self.read_as(e, t, Some("currently_stated"));
            read.exercised = current.value.ok().map(|c| c != original);
        }
        read
    }

    fn read_as(&mut self, e: &Expectation, t: Option<&Target>, selector: Option<&str>) -> Read {
        let verb = field(e, t, "read_verb").unwrap_or("-");
        let target = field(e, t, "read_target").unwrap_or("-");
        let coordinate = field(e, t, "read_coordinate").unwrap_or("-");
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
            certificates: Vec::new(),
            contributions: None,
            exercised: None,
            trace: None,
        };
        if !READ_VERBS.contains(&verb) {
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
        let flags = match view {
            Ok(flags) => flags,
            Err(why) => return fail(token, why),
        };
        if verb == "balance" {
            return self.read_balance(e, t, token, &unit, &flags);
        }
        let mut args: Vec<String> = match verb {
            "balance" => ["explain", "balance", target, "--period"]
                .map(str::to_string)
                .into(),
            "tb" => ["tb", "--period"].map(str::to_string).into(),
            _ => ["statement", verb, "--for"].map(str::to_string).into(),
        };
        args.push(code);
        args.extend(flags.iter().cloned());
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
        // A statement line's contributions, for the witness (A11b).
        let contributions = if value.is_ok() && contrib::definition(verb).is_some() {
            match self.line_contributions(&reference, verb, target, coordinate, &unit, &flags) {
                Ok(legs) => Some(legs),
                Err(why) => return fail(token, why),
            }
        } else {
            None
        };
        // A statement line T read at the head is also traced (A11b).
        let trace = (contributions.is_some() && e.kind == ExpectationType::T && selector.is_none())
            .then(|| self.line_trace(&reference, verb, target, coordinate, &unit));
        Read {
            token,
            value,
            certificates: certificate.clone().into_iter().collect(),
            certificate,
            contributions,
            exercised: None,
            trace,
        }
    }

    /// `fa statement trace --definition <verb> --for <code> --before
    /// <history start> --after <head> --certify --json`: each publication
    /// of the history, the entries it lists, and the change of `line` in
    /// `unit` there (zero where the line did not move).
    fn line_trace(
        &mut self,
        reference: &str,
        verb: &str,
        line: &str,
        coordinate: &str,
        unit: &str,
    ) -> Result<LineTrace, String> {
        let scale = scale_of(unit).ok_or_else(|| format!("unit `{unit}` is not registered"))?;
        let code = self
            .period_code(coordinate)
            .ok_or_else(|| format!("expected a period for `{coordinate}` observed none"))?;
        let (before, after) = (self.history_from.to_string(), self.head.to_string());
        let args = [
            "statement",
            "trace",
            "--definition",
            verb,
            "--for",
            code.as_str(),
            "--before",
            before.as_str(),
            "--after",
            after.as_str(),
            "--max-publications",
            "256",
            "--certify",
            "--json",
        ]
        .map(str::to_string)
        .to_vec();
        let call = self.call(self.head, reference, "statement", args);
        self.certificate_kind("StatementTrace");
        let reproduce = reproduce(&call);
        if call.exit != 0 {
            self.lines.push(reproduce);
            return Err(format!(
                "expected exit=0 from statement trace observed exit={} {}",
                call.exit,
                call.refusal_id().unwrap_or_default()
            )
            .trim_end()
            .to_string());
        }
        let mut publications = Vec::new();
        for p in call.array_field("statement_trace", "publications") {
            let entries = p
                .get("entries")
                .and_then(Json::as_array)
                .unwrap_or_default()
                .iter()
                .filter_map(|e| e.get("vid").and_then(Json::as_str).map(str::to_string))
                .collect();
            // A change's amounts are in column order; the first is the
            // read's period.
            let change = p
                .get("changes")
                .and_then(Json::as_array)
                .unwrap_or_default()
                .iter()
                .find(|c| {
                    c.get("code").and_then(Json::as_str) == Some(line)
                        && c.get("unit").and_then(Json::as_str) == Some(unit)
                })
                .and_then(|c| c.get("delta").and_then(Json::as_array))
                .and_then(<[Json]>::first)
                .and_then(Json::as_str)
                .map(|d| match d.strip_suffix(unit).map(str::trim_end) {
                    Some(a) => {
                        parse_amount(a, scale).map_err(|err| format!("delta `{d}`: {err:?}"))
                    }
                    None => Err(format!("expected a delta in {unit} observed `{d}`")),
                })
                .transpose()?
                .unwrap_or(0);
            let recorded_at = p
                .get("recorded_at")
                .and_then(Json::as_int)
                .ok_or("expected a publication's recorded_at observed none")?;
            publications.push(Publication {
                recorded_at,
                entries,
                change,
            });
        }
        if DROP_LAST_PUBLICATION.with(Cell::get)
            && let Some(last) = publications.iter().rposition(|p| p.change != 0)
        {
            publications.remove(last);
        }
        Ok(LineTrace {
            publications,
            reproduce,
        })
    }

    /// `fa explain balance <account> --certify` in each of `periods`, folded
    /// by [`contrib::union`]: the sum of the cells' nets in `unit`, each
    /// period's certificate, and each posted leg (debits positive) mapped to
    /// the intent that posted it. A leg of a class in `excluded` (a
    /// definition's Closing entries) is set aside, outside both the sum and
    /// the legs, and logged as an `EXCLUDED <reference> <account> <period>
    /// class=<class> amount=<minor units> intent=<id|-> excluded_by_definition`
    /// line.
    fn explain(
        &mut self,
        reference: &str,
        account: &str,
        periods: &[String],
        unit: &str,
        flags: &[String],
        excluded: &[String],
    ) -> Result<(i128, Vec<String>, Vec<Contribution>), String> {
        let scale = scale_of(unit).ok_or_else(|| format!("unit `{unit}` is not registered"))?;
        let posted_by: BTreeMap<String, String> = self
            .vids
            .iter()
            .map(|(intent, vid)| (vid.clone(), intent.clone()))
            .collect();
        let in_unit = |amount: &str| -> Result<Option<i128>, String> {
            match amount.strip_suffix(unit).map(str::trim_end) {
                Some(a) => parse_amount(a, scale)
                    .map(Some)
                    .map_err(|err| format!("amount `{amount}`: {err:?}")),
                None => Ok(None),
            }
        };
        let (mut certificates, mut explained) = (Vec::new(), Vec::new());
        for label in periods {
            let code =
                self.periods.get(label).cloned().ok_or_else(|| {
                    format!("expected a created period for {label} observed none")
                })?;
            let mut args = vec![
                "explain".to_string(),
                "balance".to_string(),
                account.to_string(),
                "--period".to_string(),
                code,
            ];
            args.extend(flags.iter().cloned());
            args.extend(["--certify".to_string(), "--json".to_string()]);
            let call = self.call(self.head, reference, "explain", args);
            self.certificate_kind("ExplainBalance");
            if call.exit != 0 {
                self.lines.push(reproduce(&call));
                return Err(format!(
                    "expected exit=0 from explain balance of {label} observed exit={} {}",
                    call.exit,
                    call.refusal_id().unwrap_or_default()
                )
                .trim_end()
                .to_string());
            }
            certificates.extend(call.str_field("balance_explained", "certificate"));
            let mut legs = Vec::new();
            for c in call.array_field("balance_explained", "contributions") {
                if c.get("column").and_then(Json::as_str) != Some("posted") {
                    continue;
                }
                let Some(minor) =
                    in_unit(c.get("amount").and_then(Json::as_str).unwrap_or_default())?
                else {
                    continue;
                };
                let signed = if c.get("side").and_then(Json::as_str) == Some("debit") {
                    minor
                } else {
                    minor.checked_neg().ok_or("a contribution overflows")?
                };
                let entry = c.get("entry").and_then(Json::as_str).unwrap_or_default();
                let class = c.get("class").and_then(Json::as_str).unwrap_or_default();
                legs.push(ExplainedLeg {
                    entry: entry.to_string(),
                    class: class.to_string(),
                    signed,
                });
            }
            // No cell in the unit: the account holds nothing in it there.
            let net = call
                .array_field("balance_explained", "cells")
                .iter()
                .find(|c| c.get("unit").and_then(Json::as_str) == Some(unit))
                .and_then(|c| c.get("net").and_then(Json::as_str).map(str::to_string));
            let net = match net {
                Some(n) => Some(
                    in_unit(&n)?
                        .ok_or_else(|| format!("expected a net in {unit} observed `{n}`"))?,
                ),
                None => None,
            };
            explained.push(Explanation {
                period: label.clone(),
                net,
                legs,
            });
        }
        let folded = contrib::union(account, periods, &explained, excluded, &posted_by)?;
        for (period, class, leg) in &folded.excluded {
            self.lines.push(format!(
                "EXCLUDED {reference} {account} {period} class={class} amount={} intent={} excluded_by_definition",
                leg.signed,
                leg.intent.as_deref().unwrap_or("-")
            ));
        }
        Ok((folded.total, certificates, folded.contributions))
    }

    /// A `balance` read: `fa explain balance --certify` in each period of
    /// the read's fold (module doc). Its certificate is the last period's,
    /// the read's own; every period's is kept for its outsider check.
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
        let stock = contrib::is_stock(self.book, account);
        let explained = contrib::fold_periods(self.book, stock, coordinate)
            .ok_or_else(|| format!("expected a period for `{coordinate}` observed none"))
            .and_then(|periods| self.explain(&key(e, t), account, &periods, unit, flags, &[]));
        match explained {
            Ok((total, certificates, legs)) => Read {
                token,
                value: Ok(total),
                certificate: certificates.last().cloned(),
                certificates,
                contributions: Some(legs),
                exercised: None,
                trace: None,
            },
            Err(why) => Read {
                token,
                value: Err(why),
                certificate: None,
                certificates: Vec::new(),
                contributions: None,
                exercised: None,
                trace: None,
            },
        }
    }

    /// A statement line read's contributions (A11b): every account its
    /// registered definition maps to the line, explained over the
    /// definition's basis (stock through the read's period, or the read's
    /// own periods), each leg signed as the line signs its account type.
    /// The definition's excluded classes (Closing, on the income statement)
    /// are set aside.
    fn line_contributions(
        &mut self,
        reference: &str,
        verb: &str,
        line: &str,
        coordinate: &str,
        unit: &str,
        flags: &[String],
    ) -> Result<Vec<Contribution>, String> {
        let definition =
            contrib::definition(verb).ok_or_else(|| format!("no registered {verb} definition"))?;
        let terms = contrib::line_terms(definition, line)?;
        let excluded = contrib::excluded_classes(definition);
        let periods =
            contrib::fold_periods(self.book, contrib::stock_basis(definition), coordinate)
                .ok_or_else(|| format!("expected a period for `{coordinate}` observed none"))?;
        let accounts: Vec<(String, i128)> = self
            .book
            .accounts
            .iter()
            .filter_map(|a| terms.get(&a.account_type).map(|m| (a.code.clone(), *m)))
            .collect();
        let mut out = Vec::new();
        for (account, sign) in accounts {
            let (_, _, legs) =
                self.explain(reference, &account, &periods, unit, flags, &excluded)?;
            for mut leg in legs {
                leg.signed = leg
                    .signed
                    .checked_mul(sign)
                    .ok_or("a contribution overflows")?;
                out.push(leg);
            }
        }
        Ok(out)
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
        // A finding that cites this attestation names the step that made it.
        if let Some(vid) = asserted.str_field("attestation_recorded", "attestation_vid") {
            self.attestations.insert(vid, step.reference.clone());
        }
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
                claim: asserted.str_field("attestation_recorded", "claim"),
                holds: asserted
                    .event("attestation_recorded")
                    .and_then(|o| o.field("holds"))
                    .and_then(Json::as_bool),
                asserted,
                twins,
                balance: format!("{} {unit}", format_amount(minor, scale)),
            },
        );
    }
}
