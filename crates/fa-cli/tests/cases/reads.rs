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
//! --json` (its value the target account's net). A `scenario-diff` read
//! is the diff the history's `scenario_diff` step certified for the
//! scenario its `scenario:<name>` selector names, read on the account or
//! balance-sheet line its target names; a diff that changes an account
//! none of the row's reads covers fails it. Each other read reads through
//! the row's selector: `--as-originally-reported`,
//! `--as-currently-stated`, or `--as-reported-in C:<oid>` for
//! `reported_in:<period>[#<n>]`, the certificate the period's n-th `issue`
//! step issued. Its value is the cell's net (debits minus credits) in the
//! published unit's minor units; a row compares it with its published or
//! posted figure in the read account's natural sign ([`natural_sign`]: a
//! credit-normal account's net negated). A coordinate is a `[[period]] code`, or a
//! fiscal year label (`FY<yyyy>`), read at that year's last period. An
//! `assert_balance` step records B with `fa assert-balance` (as the cell's
//! net, so a credit-normal account asserts -B) and posts its
//! twins, B plus and B minus one minor unit, which the kernel must each
//! refuse `FA-REF-140` (§5.3, §3.7 item 4).

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use fa_oracles::cases::amount::{format_amount, parse_amount};
use fa_oracles::cases::book::{BookVariant, StepDef};
use fa_oracles::cases::contrib::{self, Contribution, ExplainedLeg, Explanation, Publication};
use fa_oracles::cases::expect::{Expectation, ExpectationType, Target};
use fa_oracles::cases::gql;
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
    /// The recorded sequence a `balance` read resolved (its selector's, or
    /// the head), for the second read path (A12).
    pub known_at: Option<i128>,
    /// The output digest its report certificate recorded (statement, tb and
    /// consolidate reads), for a replay outsider route (A12).
    pub output_digest: Option<String>,
    /// A scenario-diff read: the accounts its diff changed, in the diff's
    /// row order, so a row shows what else the scenario moved.
    pub changed: Option<Vec<String>>,
}

/// One account's explanations over a read's fold (`BookRun::explain`).
pub struct Explained {
    /// The cells' nets summed, the set-aside legs taken out.
    pub total: i128,
    /// Each period's certificate, in fold order.
    pub certificates: Vec<String>,
    pub contributions: Vec<Contribution>,
    /// The recorded sequence the explanations resolved.
    pub known_at: Option<i128>,
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

/// The sign that states an account read's net (debits minus credits) as
/// its published figure: -1 when the account's type is credit-normal
/// (`registries/account_types.toml` `normal_balance = 1`: Liability,
/// Equity, Revenue), so a credit-balance concept such as an XBRL
/// `NetIncomeLoss` compares as filed (X-T-01); 1 otherwise, and for every
/// statement line, whose amounts are already as published.
#[must_use]
pub fn natural_sign(book: &BookVariant, verb: &str, target: &str) -> i128 {
    if !matches!(verb, "balance" | "tb") {
        return 1;
    }
    let Some(kind) = book
        .accounts
        .iter()
        .find(|a| a.code == target)
        .map(|a| a.account_type.as_str())
    else {
        return 1;
    };
    let credit = fa_registry::account_types_embedded()
        .ok()
        .and_then(|rows| rows.into_iter().find(|r| r.name == kind))
        .is_some_and(|r| r.normal_balance == 1);
    if credit { -1 } else { 1 }
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

    /// The second read path (A12, §12.7): each T and R `balance` read with a
    /// value is also read with `fa query --certify` ([`gql::statement`]) at
    /// the sequence its fold path resolved (its selector's, or the head):
    /// a stock account's legs effective from the book's opening through the
    /// read's period end, a flow account's legs of the read's own periods.
    /// The rows, netted by [`gql::net`], must equal the fold path's value.
    /// A scenario-diff read of an account is read on the scenario's branch
    /// and on trunk at its fork ([`Self::gql_diff_read`]).
    pub(crate) fn gql_reads(&mut self) {
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
            if field(e, t, "read_verb") == Some("scenario-diff") {
                let reference = key(e, t);
                let value = match self.reads.get(&reference) {
                    Some(Read {
                        value: Ok(value), ..
                    }) => *value,
                    _ => continue,
                };
                if let Some(verdict) = self.gql_diff_read(e, t, &reference, value) {
                    self.gql.insert(reference, verdict);
                }
                continue;
            }
            if field(e, t, "read_verb") != Some("balance") {
                continue;
            }
            let reference = key(e, t);
            let (value, known_at) = match self.reads.get(&reference) {
                Some(Read {
                    value: Ok(value),
                    known_at: Some(known_at),
                    ..
                }) => (*value, *known_at),
                _ => continue,
            };
            let verdict = self.gql_read(e, t, &reference, value, known_at);
            self.gql.insert(reference, verdict);
        }
    }

    fn gql_read(
        &mut self,
        e: &Expectation,
        t: Option<&Target>,
        reference: &str,
        value: i128,
        known_at: i128,
    ) -> Result<(), String> {
        let account = field(e, t, "read_target").unwrap_or("-");
        let (unit, scale, selection) = self.gql_selection(e, t)?;
        let statement = gql::statement(account, &selection, known_at)?;
        let (net, call) = self.gql_net(reference, statement, true, &unit, scale)?;
        if net == value {
            Ok(())
        } else {
            self.lines.push(reproduce(&call));
            Err(format!(
                "expected the query's net {} observed {}",
                format_amount(value, scale),
                format_amount(net, scale)
            ))
        }
    }

    /// The second read path of a scenario-diff read of an account (§12.7):
    /// the account's legs on the scenario's replay (`AT BRANCH`, read at
    /// the replay's head and uncertified, as the profile requires of a
    /// branch read) less its legs on trunk at the fork's sequence
    /// (certified), in the account's natural sign, must equal the diff's
    /// change. A read of a balance-sheet line has no such path.
    fn gql_diff_read(
        &mut self,
        e: &Expectation,
        t: Option<&Target>,
        reference: &str,
        value: i128,
    ) -> Option<Result<(), String>> {
        let account = field(e, t, "read_target").unwrap_or("-");
        if !self.book.accounts.iter().any(|a| a.code == account) {
            return None;
        }
        let scenario = field(e, t, "read_selector")
            .and_then(|s| s.strip_prefix("scenario:"))?
            .to_string();
        let fork_at = self
            .scenario_diffs
            .iter()
            .rev()
            .find(|d| d.name == scenario)?
            .call
            .event("scenario_diff")
            .and_then(|o| o.field("fork_at"))
            .and_then(Json::as_int);
        Some(self.gql_diff_check(e, t, reference, value, &scenario, fork_at))
    }

    /// [`Self::gql_diff_read`]'s two queries and their comparison.
    fn gql_diff_check(
        &mut self,
        e: &Expectation,
        t: Option<&Target>,
        reference: &str,
        value: i128,
        scenario: &str,
        fork_at: Option<i128>,
    ) -> Result<(), String> {
        let account = field(e, t, "read_target").unwrap_or("-");
        let fork_at = fork_at.ok_or("expected the diff's fork_at observed none")?;
        let (unit, scale, selection) = self.gql_selection(e, t)?;
        let branch = gql::branch_statement(account, &selection, scenario)?;
        let trunk = gql::statement(account, &selection, fork_at)?;
        let (on_branch, branch_call) = self.gql_net(reference, branch, false, &unit, scale)?;
        let (on_trunk, trunk_call) = self.gql_net(reference, trunk, true, &unit, scale)?;
        let net = on_branch
            .checked_sub(on_trunk)
            .and_then(|d| d.checked_mul(natural_sign(self.book, "balance", account)))
            .ok_or("the queries' difference overflows")?;
        if net == value {
            Ok(())
        } else {
            self.lines.push(reproduce(&branch_call));
            self.lines.push(reproduce(&trunk_call));
            Err(format!(
                "expected the branch query less trunk's at {fork_at} to be {} observed {}",
                format_amount(value, scale),
                format_amount(net, scale)
            ))
        }
    }

    /// The unit, scale and leg selection of a row's second-path read: a
    /// stock account's legs effective from the book's opening through the
    /// read's period end, a flow account's legs of the read's own periods.
    fn gql_selection(
        &self,
        e: &Expectation,
        t: Option<&Target>,
    ) -> Result<(String, u8, gql::Selection), String> {
        let account = field(e, t, "read_target").unwrap_or("-");
        let coordinate = field(e, t, "read_coordinate").unwrap_or("-");
        let value_key = if e.kind == ExpectationType::T {
            "published"
        } else {
            "posted"
        };
        let unit = field(e, t, value_key)
            .and_then(|f| self.value_of(f))
            .map_or_else(|| self.book.book.base_unit.clone(), |(_, u)| u);
        let scale = scale_of(&unit).ok_or_else(|| format!("unit `{unit}` is not registered"))?;
        let stock = contrib::is_stock(self.book, account);
        let periods = contrib::fold_periods(self.book, stock, coordinate)
            .ok_or_else(|| format!("expected a period for `{coordinate}` observed none"))?;
        let (first, last) = match (periods.first(), periods.last()) {
            (Some(f), Some(l)) => (f.clone(), l.clone()),
            _ => {
                return Err(format!(
                    "expected a period for `{coordinate}` observed none"
                ));
            }
        };
        let selection = if stock {
            let end = self
                .book
                .periods
                .iter()
                .find(|p| p.code == last)
                .map(|p| p.end.clone())
                .ok_or_else(|| format!("expected a declared period {last} observed none"))?;
            gql::Selection::Stock {
                opening: self.book.book.opening_date.clone(),
                end,
            }
        } else {
            let code = |label: &str| {
                self.periods
                    .get(label)
                    .cloned()
                    .ok_or_else(|| format!("expected a created period for {label} observed none"))
            };
            gql::Selection::Flow {
                from: code(&first)?,
                through: code(&last)?,
            }
        };
        Ok((unit, scale, selection))
    }

    /// `fa query <statement> [--certify] --json`, its rows netted in `unit`,
    /// and the call (for a `REPRODUCE` line on a mismatch).
    fn gql_net(
        &mut self,
        reference: &str,
        statement: String,
        certify: bool,
        unit: &str,
        scale: u8,
    ) -> Result<(i128, Call), String> {
        let mut args = vec!["query".to_string(), statement];
        if certify {
            args.push("--certify".to_string());
        }
        args.push("--json".to_string());
        let call = self.call(self.head, reference, "query", args);
        if certify {
            self.certificate_kind("Query");
        }
        if call.exit != 0 {
            self.lines.push(reproduce(&call));
            return Err(format!(
                "expected exit=0 from query observed exit={} {}",
                call.exit,
                call.refusal_id().unwrap_or_default()
            )
            .trim_end()
            .to_string());
        }
        match gql::net(&call.array_field("query_rows", "rows"), unit, scale) {
            Ok(net) => Ok((net, call)),
            Err(why) => {
                self.lines.push(reproduce(&call));
                Err(why)
            }
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
            known_at: None,
            output_digest: None,
            changed: None,
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
        match (verb, selector.and_then(|s| s.strip_prefix("scenario:"))) {
            ("scenario-diff", Some(scenario)) => {
                return self.read_scenario_diff(token, scenario, e, target, &code, &unit);
            }
            ("scenario-diff", None) | (_, Some(_)) => {
                return fail(
                    token,
                    "expected a scenario-diff read through scenario:<name> and no other read through it observed otherwise".into(),
                );
            }
            _ => {}
        }
        if verb == "balance" {
            return self.read_balance(e, t, token, &unit, &flags);
        }
        if verb == "export-xbrl" {
            return self.read_export_xbrl(e, t, token, &code, &unit, selector);
        }
        let mut args: Vec<String> = match verb {
            "balance" => ["explain", "balance", target, "--period"]
                .map(str::to_string)
                .into(),
            "tb" => ["tb", "--period"].map(str::to_string).into(),
            "consolidate" => ["consolidate", "--period"].map(str::to_string).into(),
            _ => ["statement", verb, "--for"].map(str::to_string).into(),
        };
        args.push(code);
        args.extend(flags.iter().cloned());
        args.extend(["--certify".to_string(), "--json".to_string()]);
        let reference = key(e, t);
        let called = args.first().cloned().unwrap_or_default();
        // The command, as a refusal names it: `explain balance`, `statement
        // <verb>`, `tb` or `consolidate`.
        let command = if matches!(verb, "tb" | "consolidate") {
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
            // The consolidated balance sheet's line, its current column.
            "consolidate" => (
                call.str_field("report_certificate", "oid"),
                call.event("consolidation_run")
                    .and_then(|o| o.field("balance_sheet"))
                    .and_then(|b| b.get("lines"))
                    .and_then(Json::as_array)
                    .unwrap_or_default()
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
            known_at: None,
            output_digest: call.str_field("report_certificate", "output_digest"),
            changed: None,
        }
    }

    /// A `scenario-diff` read: the diff of the scenario its selector names,
    /// as the history's last `scenario_diff` step of it certified it (that
    /// call's `scenario_diff` event), read through `target`'s terms
    /// ([`Self::diff_terms`]) over the accounts the row's reads cover
    /// ([`Self::diff_coverage`]). Its certificate is the diff's retained
    /// one (the replay route, A12).
    fn read_scenario_diff(
        &self,
        token: String,
        scenario: &str,
        e: &Expectation,
        target: &str,
        code: &str,
        unit: &str,
    ) -> Read {
        let diff = self
            .scenario_diffs
            .iter()
            .rev()
            .find(|d| d.name == scenario);
        let value = match diff {
            None => Err(format!(
                "expected a certified diff of scenario {scenario} observed none"
            )),
            Some(d) => self.diff_coverage(e).and_then(|covered| {
                let terms = self.diff_terms(target)?;
                diff_value(&d.call, &terms, &covered, code, unit)
            }),
        };
        let certificate = diff.and_then(|d| d.call.str_field("report_certificate", "oid"));
        Read {
            token,
            value,
            certificates: certificate.clone().into_iter().collect(),
            certificate,
            contributions: None,
            exercised: None,
            trace: None,
            known_at: None,
            output_digest: diff
                .and_then(|d| d.call.str_field("report_certificate", "output_digest")),
            changed: diff.map(|d| {
                d.call
                    .array_field("scenario_diff", "rows")
                    .iter()
                    .filter_map(|r| r.get("code").and_then(Json::as_str).map(str::to_string))
                    .collect()
            }),
        }
    }

    /// The sign a scenario-diff read applies to each account's delta
    /// (debit-positive): an account of the chart is read alone in its
    /// natural sign ([`natural_sign`]); a balance-sheet line reads every
    /// account of a type it folds, with the sign its terms give that type
    /// ([`contrib::line_terms`]), so a credit line reads an increase as
    /// positive.
    fn diff_terms(&self, target: &str) -> Result<BTreeMap<String, i128>, String> {
        if self.book.accounts.iter().any(|a| a.code == target) {
            return Ok([(
                target.to_string(),
                natural_sign(self.book, "balance", target),
            )]
            .into());
        }
        let definition =
            contrib::definition("balance-sheet").ok_or("expected a balance-sheet definition")?;
        let types = contrib::line_terms(definition, target)?;
        Ok(self
            .book
            .accounts
            .iter()
            .filter_map(|a| {
                types
                    .get(a.account_type.as_str())
                    .map(|sign| (a.code.clone(), *sign))
            })
            .collect())
    }

    /// The accounts a row's scenario-diff reads cover, over all of its
    /// reads. The row states what its scenario moves, so a diff that
    /// changes any other account fails each of its reads.
    fn diff_coverage(&self, e: &Expectation) -> Result<BTreeSet<String>, String> {
        let targets: Vec<&str> = match self.case.expectations.as_ref() {
            Some(set) if set.targets_of(&e.id).next().is_some() => set
                .targets_of(&e.id)
                .filter_map(|t| field(e, Some(t), "read_target"))
                .collect(),
            _ => field(e, None, "read_target").into_iter().collect(),
        };
        let mut covered = BTreeSet::new();
        for target in targets {
            covered.extend(self.diff_terms(target)?.into_keys());
        }
        Ok(covered)
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
    ) -> Result<Explained, String> {
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
        let (mut certificates, mut explained, mut known_at) = (Vec::new(), Vec::new(), None);
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
            let call = if let Some(call) = self.explained.get(&args) {
                call.clone()
            } else {
                let call = self.call(self.head, reference, "explain", args.clone());
                if call.exit == 0 {
                    self.explained.insert(args, call.clone());
                }
                call
            };
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
            known_at = known_at.max(call.known_at());
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
        Ok(Explained {
            total: folded.total,
            certificates,
            contributions: folded.contributions,
            known_at,
        })
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
            Ok(explained) => Read {
                token,
                value: Ok(explained.total),
                certificate: explained.certificates.last().cloned(),
                certificates: explained.certificates,
                contributions: Some(explained.contributions),
                exercised: None,
                trace: None,
                known_at: explained.known_at,
                output_digest: None,
                changed: None,
            },
            Err(why) => Read {
                token,
                value: Err(why),
                certificate: None,
                certificates: Vec::new(),
                contributions: None,
                exercised: None,
                trace: None,
                known_at: None,
                output_digest: None,
                changed: None,
            },
        }
    }

    /// An `export-xbrl` read (X-T-02, §10.1). `fa export xbrl --period
    /// <code>` writes the book's instance as currently stated, once per
    /// period, and `fa verify export xbrl` re-reads it in the book (a logged
    /// self-check, never independent evidence). fa-oracles' own reader
    /// (`fa_oracles::cases::instance`) takes the non-dimensional instant fact of the
    /// target QName at the period's last day in the read's unit. The
    /// contributing-entry witness explains the balance-sheet line that
    /// fa-formats' binding table exports under that QName; a QName the
    /// table does not bind has no line, and the read fails.
    fn read_export_xbrl(
        &mut self,
        e: &Expectation,
        t: Option<&Target>,
        token: String,
        code: &str,
        unit: &str,
        selector: Option<&str>,
    ) -> Read {
        let concept = field(e, t, "read_target").unwrap_or("-");
        let coordinate = field(e, t, "read_coordinate").unwrap_or("-");
        let reference = key(e, t);
        let read = |value: Result<i128, String>, contributions| Read {
            token: token.clone(),
            value,
            certificate: None,
            certificates: Vec::new(),
            contributions,
            exercised: None,
            trace: None,
            known_at: None,
            output_digest: None,
            changed: None,
        };
        if !matches!(selector, None | Some("currently_stated")) {
            return read(
                Err(format!(
                    "expected an export read as currently stated observed selector {}",
                    selector.unwrap_or("-")
                )),
                None,
            );
        }
        let line = fa_formats::xbrl::StatementXbrlMapping::us_gaap_type_level_balance_sheet()
            .bindings
            .into_iter()
            .find(|b| b.concept == concept)
            .map(|b| b.line_code);
        let Some(line) = line else {
            return read(
                Err(format!(
                    "expected a balance-sheet line fa export xbrl binds to {concept} observed none"
                )),
                None,
            );
        };
        let end = contrib::fold_periods(self.book, false, coordinate)
            .and_then(|own| own.last().cloned())
            .and_then(|last| self.book.periods.iter().find(|p| p.code == last))
            .map(|p| p.end.clone());
        let (Some(end), Some(scale)) = (end, scale_of(unit)) else {
            return read(
                Err(format!(
                    "expected a period end for `{coordinate}` and a registered unit `{unit}`"
                )),
                None,
            );
        };
        if !self.exports.contains_key(code) {
            let exported = self.export_xbrl(&reference, code);
            self.exports.insert(code.to_string(), exported);
        }
        let instance = match self.exports.get(code).cloned() {
            Some(Ok(xml)) => match fa_oracles::cases::instance::read(&xml) {
                Ok(instance) => instance,
                Err(why) => return read(Err(why.to_string()), None),
            },
            Some(Err(why)) => return read(Err(why), None),
            None => return read(Err("expected an export observed none".into()), None),
        };
        // The exported value itself: the row compares it with B exactly
        // (read_against), so a mismatch FAILs naming both values.
        let value =
            match fa_oracles::cases::instance::instant_value(&instance, concept, &end, unit, scale)
            {
                Ok(value) => value,
                Err(why) => return read(Err(why), None),
            };
        match self.line_contributions(&reference, "balance-sheet", &line, coordinate, unit, &[]) {
            Ok(contributions) => read(Ok(value), Some(contributions)),
            Err(why) => read(Err(format!("the {line} line's contributions: {why}")), None),
        }
    }

    /// `fa export xbrl --period <code>` into the variant's working
    /// directory, and the book's own `fa verify export xbrl` of the file:
    /// the instance text, or why there is none.
    fn export_xbrl(&mut self, reference: &str, code: &str) -> Result<String, String> {
        let out = self.work.join(format!("export-{code}.xbrl"));
        let path = out.display().to_string();
        let args = vec![
            "export".to_string(),
            "xbrl".to_string(),
            "--period".to_string(),
            code.to_string(),
            "--out".to_string(),
            path.clone(),
            "--json".to_string(),
        ];
        let exported = self.call(self.head, reference, "export", args);
        if exported.exit != 0 {
            self.lines.push(reproduce(&exported));
            return Err(format!(
                "expected exit=0 from export xbrl observed exit={} {}",
                exported.exit,
                exported.refusal_id().unwrap_or_default()
            )
            .trim_end()
            .to_string());
        }
        let verified = self.call(
            self.head,
            reference,
            "verify",
            ["verify", "export", "xbrl", path.as_str(), "--json"]
                .map(str::to_string)
                .into(),
        );
        if verified.exit != 0 {
            self.lines.push(reproduce(&verified));
            return Err(format!(
                "expected fa verify export xbrl exit=0 observed exit={} {}",
                verified.exit,
                verified.refusal_id().unwrap_or_default()
            )
            .trim_end()
            .to_string());
        }
        std::fs::read_to_string(&out)
            .map_err(|e| format!("expected the exported {path} observed {e}"))
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
            let explained = self.explain(reference, &account, &periods, unit, flags, &excluded)?;
            for mut leg in explained.contributions {
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
        // A scenario-diff read's scenario: no flag, the diff is read as the
        // history certified it.
        if let Some(name) = selector.strip_prefix("scenario:") {
            return (Some(format!("scenario={name}")), Ok(Vec::new()));
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
        // The kernel asserts the cell's net; the fact states the figure as
        // published.
        let Some(minor) = minor.checked_mul(natural_sign(self.book, "balance", account)) else {
            self.fail(format!(
                "expected {asserts} to have a net in range for {} (step {}) observed none",
                step.reference, step.seq
            ));
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

/// A certified scenario diff's change through `terms` in `unit` over period
/// `code` ([`BookRun::read_scenario_diff`]): each changed row's delta in the
/// unit (the scenario's net less trunk's) times its account's sign. The
/// period is one of the diff's; a changed row with a pending change, or on
/// an account the row's reads do not cover, is no read.
fn diff_value(
    call: &Call,
    terms: &BTreeMap<String, i128>,
    covered: &BTreeSet<String>,
    code: &str,
    unit: &str,
) -> Result<i128, String> {
    let periods: Vec<String> = call
        .array_field("scenario_diff", "periods")
        .iter()
        .filter_map(|p| p.as_str().map(str::to_string))
        .collect();
    if !periods.iter().any(|p| p == code) {
        return Err(format!(
            "expected period {code} among the diff's periods observed [{}]",
            periods.join(",")
        ));
    }
    let scale = scale_of(unit).ok_or_else(|| format!("unit `{unit}` is not registered"))?;
    let suffix = format!(" {unit}");
    let amount = |row: &Json, key: &str| -> Result<Option<i128>, String> {
        let text = row.get(key).and_then(Json::as_str).unwrap_or_default();
        text.strip_suffix(suffix.as_str())
            .map(|a| parse_amount(a, scale).map_err(|e| format!("{key} `{text}`: {e:?}")))
            .transpose()
    };
    let mut sum: i128 = 0;
    for row in call.array_field("scenario_diff", "rows") {
        let account = row.get("code").and_then(Json::as_str).unwrap_or("-");
        if !covered.contains(account) {
            return Err(format!(
                "expected the diff to change only {} observed {account} changed",
                covered.iter().cloned().collect::<Vec<_>>().join(",")
            ));
        }
        let Some(delta) = amount(&row, "delta")? else {
            continue;
        };
        if amount(&row, "pending_delta")?.is_some_and(|p| p != 0) {
            return Err(format!(
                "expected no pending change on {account} observed one"
            ));
        }
        let sign = terms.get(account).copied().unwrap_or(0);
        sum = delta
            .checked_mul(sign)
            .and_then(|d| sum.checked_add(d))
            .ok_or_else(|| "expected the diff's change in range observed overflow".to_string())?;
    }
    Ok(sum)
}
