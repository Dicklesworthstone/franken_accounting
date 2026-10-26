//! Financial statements over a pinned journal snapshot (plan §12.1).
//!
//! The built-in definition is a bounded, canonical input, not a lookup made
//! again during replay. Retaining a statement certificate journals its complete
//! definition snapshot. Independent custom-definition activation, presentation
//! rounding, translation and consolidation remain separate operations.

use std::collections::BTreeMap;

use asupersync::fs::Vfs;
use fa_journal::genesis::BookContext;
use fa_journal::refusal::{Refusal, exit};
use fa_journal::rows::{AccountRow, PeriodRow, bytes};
use fa_model::symbols::{label, property};
use fa_model::{DecodeError, EncodeError, Id128, Reader, Writer, period_vid};
use fa_statements::regulatory::RegulatoryScheduleDefinition;
use fa_statements::{
    Account, AccountBalance, Basis, ColumnInput, Statement, StatementDefinition, StatementInput,
    StatementKind,
};
use fa_time::DateDay;
use fgdb::Database;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, QueryCx, VId};

use crate::{AsyncBook, BookError, Outcome};

pub const STATEMENT_INVALID: &str = "FA-REF-152";
const MAX_PERIODS: usize = 65_536;
const MAX_DEFINITION_BYTES: usize = fa_statements::MAX_DEFINITION_BYTES;
/// A schedule's definition decodes within 65,536 bytes; its form, codes,
/// instruction version and declared inputs fit in the rest.
const MAX_SCHEDULE_BYTES: usize = 131_072;

/// One definition and up to two period columns, all at the same known-at.
/// Stock columns fold inception through the last selected period's end;
/// activity columns fold the exact selected period identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementSelection {
    pub definition: StatementDefinition,
    pub periods: Vec<String>,
    /// An empty list requests no comparative column.
    pub comparative: Vec<String>,
}

impl StatementSelection {
    pub(crate) fn normalize(mut self) -> Self {
        self.periods.sort();
        self.periods.dedup();
        self.comparative.sort();
        self.comparative.dedup();
        self
    }

    pub(crate) fn is_canonical(&self) -> bool {
        !self.periods.is_empty()
            && canonical_periods(&self.periods)
            && canonical_periods(&self.comparative)
            && self
                .definition
                .canonical_bytes()
                .is_ok_and(|bytes| bytes.len() <= MAX_DEFINITION_BYTES)
    }

    pub(crate) fn write(&self, w: &mut Writer) -> Result<(), EncodeError> {
        w.bytes(&self.definition.canonical_bytes()?)
            .list(&self.periods, |w, period| {
                w.str(period);
            })
            .list(&self.comparative, |w, period| {
                w.str(period);
            });
        Ok(())
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let definition =
            StatementDefinition::decode(r.bytes(MAX_DEFINITION_BYTES, "statement definition")?)
                .map_err(|_| r.invalid("canonical statement definition"))?;
        let selection = Self {
            definition,
            periods: read_periods(r)?,
            comparative: read_periods(r)?,
        };
        if !selection.is_canonical() {
            return Err(r.invalid("canonical statement selection"));
        }
        Ok(selection)
    }
}

/// Sorted, unique, bounded period codes.
fn canonical_periods(values: &[String]) -> bool {
    values.len() <= MAX_PERIODS
        && values
            .iter()
            .all(|value| !value.is_empty() && value.len() <= 128)
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn read_periods(r: &mut Reader<'_>) -> Result<Vec<String>, DecodeError> {
    let count = r.count(MAX_PERIODS, "statement periods")?;
    let mut periods = Vec::new();
    for _ in 0..count {
        periods.push(r.str(128, "statement period")?.to_string());
    }
    Ok(periods)
}

/// A regulatory schedule (plan §12.6) and up to two period columns, all at
/// the same known-at. The certificate binds the complete schedule: its form,
/// schedule code, instruction version, its definition, which maps the chart
/// by account code, and the Instrument inputs it declares. Replay decodes
/// that schedule; it never looks one up again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegulatorySelection {
    pub schedule: RegulatoryScheduleDefinition,
    pub periods: Vec<String>,
    /// An empty list requests no comparative column.
    pub comparative: Vec<String>,
}

impl RegulatorySelection {
    pub(crate) fn normalize(mut self) -> Self {
        self.periods.sort();
        self.periods.dedup();
        self.comparative.sort();
        self.comparative.dedup();
        self
    }

    pub(crate) fn is_canonical(&self) -> bool {
        !self.periods.is_empty()
            && canonical_periods(&self.periods)
            && canonical_periods(&self.comparative)
            && self
                .schedule
                .canonical_bytes()
                .is_ok_and(|bytes| bytes.len() <= MAX_SCHEDULE_BYTES)
    }

    /// Only a canonical selection is written: `is_canonical` admitted a
    /// schedule that validates and encodes within its bound.
    pub(crate) fn write(&self, w: &mut Writer) -> Result<(), EncodeError> {
        let schedule = self
            .schedule
            .canonical_bytes()
            .map_err(|_| EncodeError::LengthOverflow)?;
        w.bytes(&schedule)
            .list(&self.periods, |w, period| {
                w.str(period);
            })
            .list(&self.comparative, |w, period| {
                w.str(period);
            });
        Ok(())
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let schedule = RegulatoryScheduleDefinition::decode_canonical(
            r.bytes(MAX_SCHEDULE_BYTES, "regulatory schedule")?,
        )
        .map_err(|_| r.invalid("canonical regulatory schedule"))?;
        let selection = Self {
            schedule,
            periods: read_periods(r)?,
            comparative: read_periods(r)?,
        };
        if !selection.is_canonical() {
            return Err(r.invalid("canonical regulatory schedule selection"));
        }
        Ok(selection)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedStatement {
    pub statement: Statement,
    pub certificate: crate::ReportCertificate,
}

pub(crate) fn invalid(why: impl Into<String>) -> Refusal {
    Refusal::new(
        STATEMENT_INVALID,
        exit::REFUSAL,
        why,
        "plan §12.1 / FA-INV-04 mapping-partition (exact statement over the journal)",
        "select balance-sheet or income-statement with an existing period; correct the named mapping or input and recompute from the journal without adding a balancing entry",
    )
}

/// The definitions `fa statement lint` names: the two registered built-ins,
/// the code-range presets a book can adopt (plan §12.1) and the regulatory
/// schedules, which map the us-bank-call-report template (plan §12.6,
/// fa-doa9).
pub const LINTABLE_DEFINITIONS: &[&str] = &[
    "balance-sheet",
    "income-statement",
    "us_gaap_small_company_balance_sheet",
    "us_gaap_small_company_income_statement",
    "ffiec_041_schedule_rc_2026q1",
    "ffiec_041_schedule_ri_2026q1",
    "fr_y9c_schedule_hc_2026q1",
];

/// The named definitions that map accounts by code rather than by type:
/// the presets and the regulatory schedules.
fn named_custom(name: &str) -> Option<fa_statements::custom::CustomStatementDefinition> {
    use fa_statements::custom::CustomStatementDefinition;
    Some(match name {
        "us_gaap_small_company_balance_sheet" => {
            CustomStatementDefinition::us_gaap_small_company_balance_sheet()
        }
        "us_gaap_small_company_income_statement" => {
            CustomStatementDefinition::us_gaap_small_company_income_statement()
        }
        "ffiec_041_schedule_rc_2026q1" => {
            RegulatoryScheduleDefinition::ffiec_041_schedule_rc_2026q1().statement_definition
        }
        "ffiec_041_schedule_ri_2026q1" => {
            RegulatoryScheduleDefinition::ffiec_041_schedule_ri_2026q1().statement_definition
        }
        "fr_y9c_schedule_hc_2026q1" => {
            RegulatoryScheduleDefinition::fr_y9c_schedule_hc_2026q1().statement_definition
        }
        _ => return None,
    })
}

/// Lint the named definition against a chart (plan §12.1, FA-INV-04 mapping
/// partition): covered leaves no line maps or several lines map, and codes a
/// line names that are unknown, summary or outside the definition's types.
pub(crate) fn lint(
    name: &str,
    chart: &[AccountRow],
) -> Result<fa_statements::custom::StatementLintReport, Refusal> {
    use fa_statements::custom::{lint_custom_statement_definition, lint_statement_definition};
    let accounts: Vec<Account> = chart
        .iter()
        .map(|row| Account {
            id: row.vid.0,
            code: row.code.clone(),
            name: row.name.clone(),
            account_type: row.account_type,
            is_leaf: row.is_leaf,
        })
        .collect();
    let linted = match named_custom(name) {
        Some(definition) => lint_custom_statement_definition(&definition, &accounts),
        None => match StatementDefinition::embedded(name) {
            Ok(definition) => lint_statement_definition(&definition, &accounts),
            Err(_) => {
                return Err(invalid(format!(
                    "unknown statement definition `{name}`; lint names {}",
                    LINTABLE_DEFINITIONS.join(", ")
                )));
            }
        },
    };
    linted.map_err(|error| invalid(error.to_string()))
}

/// One line of a statement definition's share of an engagement's
/// uncorrected misstatements (plan §11.12, `audit.sud` per statement line):
/// the line's amount had every uncorrected proposal been booked, under the
/// line's own sign, in the engagement's unit. A formula line is computed
/// from the lines it names, exactly as the statement computes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UncorrectedLine {
    pub code: String,
    pub label: String,
    pub amount: i128,
}

/// The uncorrected misstatements over one definition's lines: the income
/// statement's under the rollover method, the balance sheet's under the iron
/// curtain method (SAB 108). Mechanics only; materiality stays the
/// auditor's judgment (plan §0.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UncorrectedStatement {
    pub definition: String,
    pub title: String,
    pub kind: fa_statements::StatementKind,
    pub lines: Vec<UncorrectedLine>,
}

/// The kind of the definition `name` names, when it is one `fa statement
/// lint` takes.
#[must_use]
pub fn statement_definition_kind(name: &str) -> Option<fa_statements::StatementKind> {
    mapping_definition(name)
        .ok()
        .map(|definition| definition.kind)
}

/// A definition by a name `fa statement lint` takes, as its line mappings.
pub(crate) fn mapping_definition(
    name: &str,
) -> Result<fa_statements::custom::CustomStatementDefinition, Refusal> {
    use fa_statements::custom::CustomStatementDefinition;
    if let Some(definition) = named_custom(name) {
        return Ok(definition);
    }
    StatementDefinition::embedded(name)
        .map(|definition| CustomStatementDefinition::from_builtin(&definition))
        .map_err(|_| {
            invalid(format!(
                "unknown statement definition `{name}`; one of {}",
                LINTABLE_DEFINITIONS.join(", ")
            ))
        })
}

/// Attribute legs `(account, side, mantissa)` to `definition`'s lines. A leg
/// whose account type the definition does not cover is not on it (an asset
/// leg is not on an income statement); a covered account must map to
/// exactly one line, which is what `fa statement lint` checks.
pub(crate) fn uncorrected_statement(
    definition: &fa_statements::custom::CustomStatementDefinition,
    accounts: &std::collections::BTreeMap<u128, Account>,
    legs: &[(u128, fa_money::Side, i128)],
) -> Result<UncorrectedStatement, Refusal> {
    use fa_money::Side;
    use fa_statements::Sign;
    use fa_statements::custom::CustomLineSource;
    let overflow = || invalid("the uncorrected misstatements overflow a statement line");
    let covered = definition.kind.covered_types();
    let mut mapped_totals: std::collections::BTreeMap<&str, i128> =
        std::collections::BTreeMap::new();
    for &(account_id, side, mantissa) in legs {
        let account = accounts.get(&account_id).ok_or_else(|| {
            invalid(format!(
                "an uncorrected proposal names account {account_id:032x}, which the chart does not have"
            ))
        })?;
        if !covered.contains(&account.account_type) {
            continue;
        }
        let mut mapping = definition
            .lines
            .iter()
            .filter_map(|line| match &line.source {
                CustomLineSource::AccountSet { expr, sign } if expr.matches(account) => {
                    Some((line.code.as_str(), *sign))
                }
                _ => None,
            });
        let (Some((code, sign)), None) = (mapping.next(), mapping.next()) else {
            return Err(invalid(format!(
                "account `{}` does not map to exactly one line of `{}`; fa statement lint --definition {} names the gap",
                account.code, definition.name, definition.name
            )));
        };
        let signed = match (side, sign) {
            (Side::Debit, Sign::Debit) | (Side::Credit, Sign::Credit) => mantissa,
            _ => mantissa.checked_neg().ok_or_else(overflow)?,
        };
        let total = mapped_totals.entry(code).or_insert(0);
        *total = total.checked_add(signed).ok_or_else(overflow)?;
    }
    let mut values: std::collections::BTreeMap<&str, i128> = std::collections::BTreeMap::new();
    let mut lines = Vec::with_capacity(definition.lines.len());
    for line in &definition.lines {
        let amount = match &line.source {
            CustomLineSource::AccountSet { .. } => {
                mapped_totals.get(line.code.as_str()).copied().unwrap_or(0)
            }
            CustomLineSource::Formula { add, subtract } => {
                let mut amount = 0i128;
                for (names, negate) in [(add, false), (subtract, true)] {
                    for name in names {
                        let value = *values.get(name.as_str()).ok_or_else(|| {
                            invalid(format!(
                                "formula line `{}` of `{}` names `{name}`, which is not an earlier line",
                                line.code, definition.name
                            ))
                        })?;
                        amount = if negate {
                            amount.checked_sub(value)
                        } else {
                            amount.checked_add(value)
                        }
                        .ok_or_else(overflow)?;
                    }
                }
                amount
            }
        };
        values.insert(line.code.as_str(), amount);
        lines.push(UncorrectedLine {
            code: line.code.clone(),
            label: line.label.clone(),
            amount,
        });
    }
    Ok(UncorrectedStatement {
        definition: definition.name.clone(),
        title: definition.title.clone(),
        kind: definition.kind,
        lines,
    })
}

pub(crate) fn read<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    selection: StatementSelection,
    known_at: Option<CommitSeq>,
) -> Outcome<Statement> {
    cx.checkpoint().map_err(BookError::Context)?;
    let selection = selection.normalize();
    if !selection.is_canonical() {
        return Ok(Err(invalid("select nonempty, bounded statement periods")));
    }
    let head = db.frontier().map_err(fa_journal::KernelError::from)?;
    let at = known_at.unwrap_or(head);
    if at > head {
        return Ok(Err(invalid(format!(
            "statement known-at {} is beyond book head {}",
            at.0, head.0
        ))));
    }
    crate::certificate::context_at(db, book, at)?;
    report_at(db, book, &selection, at)
}

/// All values originate in the literal fold at `at`. Register cells, cached
/// statement totals and the current chart are never inputs to this function.
pub(crate) fn report_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    selection: &StatementSelection,
    at: CommitSeq,
) -> Outcome<Statement> {
    report_at_basis(db, book, selection, at, false)
}

/// The same historical chart partition and definition, valued from the
/// journal's retained functional amounts. No current rate is selected and no
/// monetary entry is generated. Outstanding pending holds are not earnings or
/// posted stock and are therefore excluded by the authoritative folds.
pub(crate) fn report_functional_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    selection: &StatementSelection,
    at: CommitSeq,
) -> Outcome<Statement> {
    report_at_basis(db, book, selection, at, true)
}

/// The schedules `fa statement regulatory` evaluates, as (form, schedule,
/// the report quarter whose instructions the schedule records).
pub const REGULATORY_SCHEDULES: &[(&str, &str, &str)] = &[
    ("041", "RC", "2026Q1"),
    ("041", "RI", "2026Q1"),
    ("Y9C", "HC", "2026Q1"),
];

fn schedule_refusal(why: impl Into<String>) -> Refusal {
    let registered: Vec<String> = REGULATORY_SCHEDULES
        .iter()
        .map(|(form, schedule, quarter)| {
            format!("--form {form} --schedule {schedule} --quarter {quarter}")
        })
        .collect();
    Refusal::new(
        STATEMENT_INVALID,
        exit::REFUSAL,
        why,
        "plan §12.6 (a regulatory schedule is a registered definition with its instruction version)",
        format!(
            "select a registered schedule: {}; a quarter's schedule records that quarter's instructions, so another quarter is not substituted",
            registered.join(" | ")
        ),
    )
}

/// The registered schedule for `form` (`041` or `FFIEC041`; `Y9C` or
/// `FRY9C`), `schedule` and report `quarter` (`YYYYQn`), compared without
/// case. A quarter selects the instructions registered for exactly that
/// quarter. The FFIEC revises its instructions, so no quarter borrows
/// another's; a quarter without its own is refused, naming those that exist.
pub fn regulatory_schedule(
    form: &str,
    schedule: &str,
    quarter: &str,
) -> Result<RegulatoryScheduleDefinition, Refusal> {
    let form_code = match form.to_ascii_uppercase().as_str() {
        "041" | "FFIEC041" => "041",
        "Y9C" | "FRY9C" => "Y9C",
        _ => {
            return Err(schedule_refusal(format!(
                "unknown regulatory form `{form}`; FrankenAccounting registers FFIEC 041 (041) and FR Y-9C (Y9C)"
            )));
        }
    };
    let schedule_code = schedule.to_ascii_uppercase();
    let quarter_code = quarter.to_ascii_uppercase();
    match (form_code, schedule_code.as_str(), quarter_code.as_str()) {
        ("041", "RC", "2026Q1") => Ok(RegulatoryScheduleDefinition::ffiec_041_schedule_rc_2026q1()),
        ("041", "RI", "2026Q1") => Ok(RegulatoryScheduleDefinition::ffiec_041_schedule_ri_2026q1()),
        ("Y9C", "HC", "2026Q1") => Ok(RegulatoryScheduleDefinition::fr_y9c_schedule_hc_2026q1()),
        _ => Err(schedule_refusal(format!(
            "no {form_code} schedule {schedule_code} is registered for {quarter_code}"
        ))),
    }
}

/// A schedule's edits run over the statement it evaluated to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegulatoryEdits {
    /// `<form>:<schedule>@<quarter>`.
    pub selector: String,
    /// Whether the registry's ids are the regulator's published edit
    /// numbers; the shipped registries are illustrative.
    pub published: bool,
    pub report: fa_statements::regulatory::RegulatoryEditReport,
}

/// The edits registered for `schedule` (plan §12.6,
/// `regulatory.edits(<form>@<quarter>)`, registries/regulatory_edits/), run
/// over the statement it evaluated to. A failed edit is a row, never a
/// refusal. `only`, when not empty, selects edits by id; an id the registry
/// does not hold is refused, naming those it does.
pub fn regulatory_edits_of(
    schedule: &RegulatoryScheduleDefinition,
    statement: &Statement,
    only: &[String],
) -> Result<RegulatoryEdits, Refusal> {
    use fa_statements::regulatory::{EditSource, edits_for_schedule, evaluate_regulatory_edits};
    let set = edits_for_schedule(schedule).map_err(|error| schedule_refusal(error.to_string()))?;
    let quarter = set
        .form_at_quarter
        .split_once('@')
        .map_or("", |(_, quarter)| quarter);
    let selector = format!(
        "{}:{}@{quarter}",
        schedule.form.as_str(),
        schedule.schedule_code
    );
    if let Some(unknown) = only
        .iter()
        .find(|id| !set.edits.iter().any(|edit| edit.edit_id == **id))
    {
        let registered: Vec<&str> = set.edits.iter().map(|edit| edit.edit_id.as_str()).collect();
        return Err(Refusal::new(
            STATEMENT_INVALID,
            exit::REFUSAL,
            format!("edit `{unknown}` is not registered for {selector}"),
            "plan §12.6 (regulatory.edits(<form>@<quarter>) is a versioned data registry)",
            format!(
                "select a registered edit with --edit: {}; or omit --edit to run them all",
                registered.join(", ")
            ),
        ));
    }
    let edits: Vec<_> = set
        .edits
        .iter()
        .filter(|edit| only.is_empty() || only.contains(&edit.edit_id))
        .cloned()
        .collect();
    let report = evaluate_regulatory_edits(statement, &selector, &edits)
        .map_err(|error| invalid(error.to_string()))?;
    Ok(RegulatoryEdits {
        selector,
        published: matches!(set.source, EditSource::Published { .. }),
        report,
    })
}

/// Evaluate a regulatory schedule from journal payloads at one snapshot,
/// without publishing anything. Both columns use the same known-at.
pub(crate) fn read_regulatory<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    selection: RegulatorySelection,
    known_at: Option<CommitSeq>,
) -> Outcome<Statement> {
    cx.checkpoint().map_err(BookError::Context)?;
    let selection = selection.normalize();
    if !selection.is_canonical() {
        return Ok(Err(invalid(
            "select nonempty, bounded statement periods and a valid regulatory schedule",
        )));
    }
    let head = db.frontier().map_err(fa_journal::KernelError::from)?;
    let at = known_at.unwrap_or(head);
    if at > head {
        return Ok(Err(invalid(format!(
            "statement known-at {} is beyond book head {}",
            at.0, head.0
        ))));
    }
    crate::certificate::context_at(db, book, at)?;
    regulatory_at(db, book, &selection, at)
}

/// The schedule over the same exact columns a statement of its kind folds
/// (stock for RC and HC, activity for RI). Its definition maps the chart by
/// account code and must partition the covered leaves, or the evaluation is
/// refused naming the unmapped and multiply mapped codes. Native units only.
pub(crate) fn regulatory_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    selection: &RegulatorySelection,
    at: CommitSeq,
) -> Outcome<Statement> {
    let input = match statement_input(
        db,
        book,
        selection.schedule.statement_definition.kind,
        [&selection.periods, &selection.comparative],
        at,
        false,
    )? {
        Ok(input) => input,
        Err(refusal) => return Ok(Err(refusal)),
    };
    Ok(selection
        .schedule
        .evaluate(&input)
        .map_err(|error| invalid(error.to_string())))
}

fn report_at_basis<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    selection: &StatementSelection,
    at: CommitSeq,
    functional: bool,
) -> Outcome<Statement> {
    let input = match statement_input(
        db,
        book,
        selection.definition.kind(),
        [&selection.periods, &selection.comparative],
        at,
        functional,
    )? {
        Ok(input) => input,
        Err(refusal) => return Ok(Err(refusal)),
    };
    Ok(fa_statements::evaluate(&selection.definition, &input)
        .map_err(|error| invalid(error.to_string())))
}

/// The chart at `at` and one exact column per nonempty period list
/// (`current`, then `comparative`), folded on `kind`'s basis: stock through
/// the last selected period's end, or the selected periods' activity without
/// the classes `kind` excludes. Every definition is evaluated over this one
/// input, whether it maps accounts by type or by code.
fn statement_input<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    kind: StatementKind,
    [periods, comparative]: [&Vec<String>; 2],
    at: CommitSeq,
    functional: bool,
) -> Outcome<StatementInput> {
    let mut accounts = Vec::new();
    for row in db.vertices_at(at).map_err(fa_journal::KernelError::from)? {
        if !row.labels.contains(&label::ACCOUNT) {
            continue;
        }
        if bytes(&row, property::BOOK_ID, "statement account book")? != book.book_id.0 {
            return Err(fa_journal::KernelError::Corrupt(
                "statement account belongs to another book".into(),
            )
            .into());
        }
        let account = AccountRow::decode(&row)?;
        accounts.push(Account {
            id: account.vid.0,
            code: account.code,
            name: account.name,
            account_type: account.account_type,
            is_leaf: account.is_leaf,
        });
    }
    accounts.sort_by(|a, b| a.code.cmp(&b.code).then(a.id.cmp(&b.id)));
    let mut columns = Vec::new();
    let mut functional_unit = None;
    for (name, periods) in [("current", periods), ("comparative", comparative)] {
        if periods.is_empty() {
            continue;
        }
        let mut first = None;
        let mut last = None;
        for code in periods {
            let Some(row) = db
                .vertex_at(period_vid(&book.calendar.id, code), at)
                .map_err(fa_journal::KernelError::from)?
                .filter(|row| row.labels.contains(&label::PERIOD))
            else {
                return Ok(Err(invalid(format!(
                    "unknown statement period `{code}` at sequence {}",
                    at.0
                ))));
            };
            let period = PeriodRow::decode(&row)?;
            if period.calendar_id != book.calendar.id || period.end <= period.start {
                return Err(fa_journal::KernelError::Corrupt(format!(
                    "statement period `{code}` has a different calendar or invalid bounds"
                ))
                .into());
            }
            let through = DateDay(period.end.0.checked_sub(1).ok_or_else(|| {
                fa_journal::KernelError::Corrupt("statement period end underflow".into())
            })?);
            first = Some(first.map_or(period.start, |day: DateDay| day.min(period.start)));
            last = Some(last.map_or(through, |day: DateDay| day.max(through)));
        }
        let Some(through) = last else {
            return Ok(Err(invalid("a statement column has no period cutoff")));
        };
        let balances = if functional {
            let (unit, balances) = match functional_balances(db, book, kind, periods, through, at) {
                Ok(result) => result,
                Err(error) => return register_refusal(error),
            };
            if functional_unit
                .replace(unit)
                .is_some_and(|previous| previous != unit)
            {
                return Err(fa_journal::KernelError::Corrupt(
                    "functional statement columns disagree on the historical base unit".into(),
                )
                .into());
            }
            balances
        } else {
            let fold = match kind.basis() {
                Basis::Stock => fa_registers::balance_as_of(db, book, through, Some(at)),
                Basis::Activity => fa_registers::period_activity_excluding_classes(
                    db,
                    book,
                    periods,
                    Some(at),
                    kind.excluded_classes(),
                ),
            };
            let fold = match fold {
                Ok(fold) => fold,
                Err(error) => return register_refusal(error),
            };
            let mut balances = Vec::new();
            for row in fold.rows {
                if book.units.get(fa_money::UnitId(row.unit_id)).is_none() {
                    return Err(fa_journal::KernelError::Corrupt(format!(
                        "statement fold uses unregistered unit {}",
                        row.unit_id
                    ))
                    .into());
                }
                balances.push(AccountBalance {
                    account_id: row.account.0,
                    unit_id: row.unit_id,
                    debits: row.debits,
                    credits: row.credits,
                });
            }
            balances
        };
        columns.push(ColumnInput {
            label: name.into(),
            periods: periods.clone(),
            effective_from: if kind.basis() == Basis::Activity {
                first
            } else {
                None
            },
            effective_through: through,
            balances,
        });
    }
    Ok(Ok(StatementInput {
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        known_at: at.0,
        accounts,
        units: match functional_unit {
            Some(unit) => vec![unit.0],
            None => book.units.iter().map(|(id, _)| id.0).collect(),
        },
        columns,
    }))
}

fn register_refusal<T>(error: fa_registers::RegisterError) -> Outcome<T> {
    match error {
        fa_registers::RegisterError::InvalidSelection(message) => Ok(Err(invalid(message))),
        fa_registers::RegisterError::Overflow => Ok(Err(invalid(
            "the selected journal amounts exceed the exact register fold range",
        ))),
        error => Err(error.into()),
    }
}

fn functional_balances<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    kind: StatementKind,
    periods: &[String],
    through: DateDay,
    at: CommitSeq,
) -> Result<(fa_money::UnitId, Vec<AccountBalance>), fa_registers::RegisterError> {
    use fa_registers::RegisterError;
    let mut balances: BTreeMap<(VId, u32), (i128, i128)> = BTreeMap::new();
    let mut add = |account, unit, debits, credits| -> Result<(), RegisterError> {
        let total = balances.entry((account, unit)).or_default();
        total.0 = total.0.checked_add(debits).ok_or(RegisterError::Overflow)?;
        total.1 = total
            .1
            .checked_add(credits)
            .ok_or(RegisterError::Overflow)?;
        Ok(())
    };
    let unit = match kind.basis() {
        Basis::Stock => {
            let fold = fa_registers::fold_functional_stock(db, book, through, Some(at))?;
            for cell in fold.cells {
                add(
                    cell.key.account,
                    cell.key.unit_id,
                    cell.debits,
                    cell.credits,
                )?;
            }
            fold.base_unit
        }
        Basis::Activity => {
            let mut unit = None;
            for period in periods {
                let fold = fa_registers::fold_period_functional_excluding_classes(
                    db,
                    book,
                    period,
                    Some(at),
                    kind.excluded_classes(),
                )?;
                if unit
                    .replace(fold.base_unit)
                    .is_some_and(|previous| previous != fold.base_unit)
                {
                    return Err(RegisterError::InvalidSelection(
                        "functional statement periods disagree on the historical base unit".into(),
                    ));
                }
                for cell in fold.cells {
                    add(
                        cell.key.account,
                        cell.key.unit_id,
                        cell.debits,
                        cell.credits,
                    )?;
                }
            }
            unit.ok_or_else(|| {
                RegisterError::InvalidSelection(
                    "a functional statement column needs a period".into(),
                )
            })?
        }
    };
    if book.units.get(unit).is_none() || balances.keys().any(|(_, cell_unit)| *cell_unit != unit.0)
    {
        return Err(RegisterError::InvalidSelection(
            "functional statement amounts must use the book's registered base unit".into(),
        ));
    }
    Ok((
        unit,
        balances
            .into_iter()
            .map(|((account, unit), (debits, credits))| AccountBalance {
                account_id: account.0,
                unit_id: unit,
                debits,
                credits,
            })
            .collect(),
    ))
}

pub(crate) fn certified_functional(
    report: crate::CertifiedReport,
) -> Result<CertifiedStatement, Refusal> {
    match report.report {
        crate::ReportOutput::FunctionalStatement(statement) => Ok(CertifiedStatement {
            statement: *statement,
            certificate: report.certificate,
        }),
        _ => Err(invalid(
            "the certified output is not a functional-currency statement",
        )),
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    pub(crate) fn admit_functional_report(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &fa_policy::Capability,
        known_at: Option<CommitSeq>,
        certify: bool,
    ) -> Outcome<CommitSeq> {
        let admission = fa_policy::admit_read(capability, principal, self.context.book_id)
            .and_then(|()| {
                if certify {
                    fa_policy::require(
                        capability,
                        fa_policy::Op::Produce,
                        "certifying a functional report",
                    )
                } else {
                    Ok(())
                }
            })
            .and_then(|()| {
                fa_policy::reach(
                    capability,
                    &fa_policy::Reach {
                        observes: known_at
                            .map_or(fa_policy::Observes::Head, fa_policy::Observes::At),
                        ..fa_policy::Reach::whole_book(true)
                    },
                    None,
                )
            });
        if let Err(denial) = admission {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        self.query(cx, |db, book| {
            Ok(fa_journal::policy::current_at(db, book, capability)?.map(|current| current.at()))
        })
    }

    pub(crate) async fn prepare_functional_report(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &fa_policy::Capability,
        known_at: Option<CommitSeq>,
        certify: bool,
    ) -> Outcome<CommitSeq> {
        let head =
            match self.admit_functional_report(cx, principal, capability, known_at, certify)? {
                Ok(head) => head,
                Err(refusal) => return Ok(Err(refusal)),
            };
        let at = known_at.unwrap_or(head);
        if at > head {
            return Ok(Err(invalid(format!(
                "functional report known-at {} is beyond book head {}",
                at.0, head.0
            ))));
        }
        if let Err(refusal) = fa_journal::scratch::ensure_history(&mut self.db, cx).await? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) =
            self.admit_functional_report(cx, principal, capability, Some(at), certify)?
        {
            return Ok(Err(refusal));
        }
        Ok(Ok(at))
    }

    /// Evaluate the complete historical chart in the book's functional
    /// currency. Retained valuations and their laws are verified at the fixed
    /// prefix; current whole-book Read authority is required before history is
    /// loaded. This read never selects a new rate or publishes a journal row.
    pub async fn functional_statement(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &fa_policy::Capability,
        selection: StatementSelection,
        known_at: Option<CommitSeq>,
    ) -> Outcome<Statement> {
        let at = match self
            .prepare_functional_report(cx, principal, capability, known_at, false)
            .await?
        {
            Ok(at) => at,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let selection = selection.normalize();
        if !selection.is_canonical() {
            return Ok(Err(invalid("select nonempty, bounded statement periods")));
        }
        let result = self.query(cx, |db, book| {
            crate::certificate::context_at(db, book, at)?;
            if let Err(refusal) = crate::certificate::verify_functional_sources(db, cx, book, at)? {
                return Ok(Err(refusal));
            }
            report_functional_at(db, book, &selection, at)
        })?;
        if let Err(refusal) =
            self.admit_functional_report(cx, principal, capability, Some(at), false)?
        {
            return Ok(Err(refusal));
        }
        Ok(result)
    }

    /// Certify functional stock or activity, with optional comparative
    /// columns, under current whole-book Read and Produce authority.
    pub async fn certify_functional_statement(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &fa_policy::Capability,
        selection: StatementSelection,
        known_at: Option<CommitSeq>,
    ) -> Outcome<CertifiedStatement> {
        let at = match self
            .prepare_functional_report(cx, principal, capability, known_at, true)
            .await?
        {
            Ok(at) => at,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let result = self
            .certify_report(
                cx,
                crate::ReportSelection::FunctionalStatement(Box::new(selection)),
                Some(at),
            )?
            .and_then(certified_functional);
        if let Err(refusal) =
            self.admit_functional_report(cx, principal, capability, Some(at), true)?
        {
            return Ok(Err(refusal));
        }
        Ok(result)
    }

    /// Certify the functional statement with the original TimeEvidence
    /// brackets that resolve the requested instant to a retained prefix.
    pub async fn certify_functional_statement_at_instant(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &fa_policy::Capability,
        selection: StatementSelection,
        requested_utc_ns: u64,
    ) -> Outcome<CertifiedStatement> {
        if let Err(refusal) = self
            .prepare_functional_report(cx, principal, capability, None, true)
            .await?
        {
            return Ok(Err(refusal));
        }
        let result = self
            .certify_report_at_instant(
                cx,
                crate::ReportSelection::FunctionalStatement(Box::new(selection)),
                requested_utc_ns,
            )?
            .and_then(certified_functional);
        if let Err(refusal) = self.admit_functional_report(cx, principal, capability, None, true)? {
            return Ok(Err(refusal));
        }
        Ok(result)
    }
}

pub(crate) fn certified(report: crate::CertifiedReport) -> Result<CertifiedStatement, Refusal> {
    match report.report {
        crate::ReportOutput::Statement(statement) => Ok(CertifiedStatement {
            statement: *statement,
            certificate: report.certificate,
        }),
        _ => Err(invalid("the certified output is not a financial statement")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statement_selection_roundtrip_pins_definition_and_both_columns() {
        let original = StatementSelection {
            definition: StatementDefinition::embedded("balance-sheet").unwrap(),
            periods: vec!["FY2026-P02".into(), "FY2026-P01".into()],
            comparative: vec!["FY2025-P02".into(), "FY2025-P01".into()],
        }
        .normalize();
        let mut w = Writer::new();
        original.write(&mut w).unwrap();
        let bytes = w.finish().unwrap();
        let mut r = Reader::new(&bytes);
        let restored = StatementSelection::read(&mut r).unwrap();
        r.finish().unwrap();
        assert_eq!(restored, original);
        let mut changed = restored.clone();
        changed.comparative = vec!["FY2024-P01".into()];
        let mut w = Writer::new();
        changed.write(&mut w).unwrap();
        assert_ne!(w.finish().unwrap(), bytes);
    }
}
