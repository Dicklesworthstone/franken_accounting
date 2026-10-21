//! Financial statements over a pinned journal snapshot (plan §12.1).
//!
//! The built-in definition is a bounded, canonical input, not a lookup made
//! again during replay. Retaining a statement certificate journals its complete
//! definition snapshot. Independent custom-definition activation, presentation
//! rounding, translation and consolidation remain separate operations.

use asupersync::fs::Vfs;
use fa_journal::genesis::BookContext;
use fa_journal::refusal::{Refusal, exit};
use fa_journal::rows::{AccountRow, PeriodRow, bytes};
use fa_model::symbols::{label, property};
use fa_model::{DecodeError, EncodeError, Id128, Reader, Writer, period_vid};
use fa_statements::{
    Account, AccountBalance, Basis, ColumnInput, Statement, StatementDefinition, StatementInput,
};
use fa_time::DateDay;
use fgdb::Database;
use fgdb_types::{CommitSeq, QueryCx};

use crate::{BookError, Outcome};

pub const STATEMENT_INVALID: &str = "FA-REF-152";
const MAX_PERIODS: usize = 65_536;
const MAX_DEFINITION_BYTES: usize = fa_statements::MAX_DEFINITION_BYTES;

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
        fn periods(values: &[String]) -> bool {
            values.len() <= MAX_PERIODS
                && values
                    .iter()
                    .all(|value| !value.is_empty() && value.len() <= 128)
                && values.windows(2).all(|pair| pair[0] < pair[1])
        }
        !self.periods.is_empty()
            && periods(&self.periods)
            && periods(&self.comparative)
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
        fn periods(r: &mut Reader<'_>) -> Result<Vec<String>, DecodeError> {
            let count = r.count(MAX_PERIODS, "statement periods")?;
            let mut periods = Vec::new();
            for _ in 0..count {
                periods.push(r.str(128, "statement period")?.to_string());
            }
            Ok(periods)
        }
        let definition =
            StatementDefinition::decode(r.bytes(MAX_DEFINITION_BYTES, "statement definition")?)
                .map_err(|_| r.invalid("canonical statement definition"))?;
        let selection = Self {
            definition,
            periods: periods(r)?,
            comparative: periods(r)?,
        };
        if !selection.is_canonical() {
            return Err(r.invalid("canonical statement selection"));
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

/// The definitions `fa statement lint` names: the two registered built-ins
/// and the code-range presets a book can adopt (plan §12.1).
pub const LINTABLE_DEFINITIONS: &[&str] = &[
    "balance-sheet",
    "income-statement",
    "us_gaap_small_company_balance_sheet",
    "us_gaap_small_company_income_statement",
];

/// Lint the named definition against a chart (plan §12.1, FA-INV-04 mapping
/// partition): covered leaves no line maps or several lines map, and codes a
/// line names that are unknown, summary or outside the definition's types.
pub(crate) fn lint(
    name: &str,
    chart: &[AccountRow],
) -> Result<fa_statements::custom::StatementLintReport, Refusal> {
    use fa_statements::custom::{
        CustomStatementDefinition, lint_custom_statement_definition, lint_statement_definition,
    };
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
    let linted = match name {
        "us_gaap_small_company_balance_sheet" => lint_custom_statement_definition(
            &CustomStatementDefinition::us_gaap_small_company_balance_sheet(),
            &accounts,
        ),
        "us_gaap_small_company_income_statement" => lint_custom_statement_definition(
            &CustomStatementDefinition::us_gaap_small_company_income_statement(),
            &accounts,
        ),
        _ => match StatementDefinition::embedded(name) {
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
    for (name, periods) in [
        ("current", &selection.periods),
        ("comparative", &selection.comparative),
    ] {
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
        let fold = match selection.definition.basis() {
            Basis::Stock => fa_registers::balance_as_of(db, book, through, Some(at)),
            Basis::Activity => fa_registers::period_activity_excluding_classes(
                db,
                book,
                periods,
                Some(at),
                selection.definition.excluded_classes(),
            ),
        };
        let fold = match fold {
            Ok(fold) => fold,
            Err(fa_registers::RegisterError::InvalidSelection(message)) => {
                return Ok(Err(invalid(message)));
            }
            Err(fa_registers::RegisterError::Overflow) => {
                return Ok(Err(invalid(
                    "the selected journal amounts exceed the exact register fold range",
                )));
            }
            Err(error) => return Err(error.into()),
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
        columns.push(ColumnInput {
            label: name.into(),
            periods: periods.clone(),
            effective_from: if selection.definition.basis() == Basis::Activity {
                first
            } else {
                None
            },
            effective_through: through,
            balances,
        });
    }
    let input = StatementInput {
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        known_at: at.0,
        accounts,
        units: book.units.iter().map(|(id, _)| id.0).collect(),
        columns,
    };
    Ok(fa_statements::evaluate(&selection.definition, &input)
        .map_err(|error| invalid(error.to_string())))
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
