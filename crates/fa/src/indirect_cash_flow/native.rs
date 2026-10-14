//! One native prefix supplies direct cash, income and adjustment citations.

use asupersync::fs::Vfs;
use fa_journal::rows::PeriodRow;
use fa_journal::KernelError;
use fa_model::symbols::label;
use fa_policy::Capability;
use fa_time::DateDay;
use fgdb_types::context::PurposeContexts;
use fgdb_types::VId;

use super::*;
use crate::{AsyncBook, StatementDefinition, StatementSelection};

/// Period identities, not just their minimum/maximum dates, must cover the
/// interval. Special periods are included even when a normal period already
/// covers their days. Overlapping periods may not be sliced at either boundary.
fn coverage(
    all: &[(String, DateDay, DateDay)], expected: &[String],
    from: DateDay, through: DateDay,
) -> Result<(), Refusal> {
    let end = through.0.checked_add(1).map(DateDay)
        .ok_or_else(|| invalid("indirect cash-flow interval has no representable exclusive end"))?;
    let mut spans = Vec::new();
    let mut names = BTreeSet::new();
    for (code, start, stop) in all {
        if start >= stop { return Err(invalid("historical income period has invalid bounds")); }
        if *start >= end || *stop <= from { continue; }
        if *start < from || *stop > end || !names.insert(code.clone()) {
            return Err(invalid("indirect cash flow requires whole, uniquely identified overlapping periods"));
        }
        spans.push((*start, *stop));
    }
    if names.into_iter().collect::<Vec<_>>().as_slice() != expected {
        return Err(invalid("income periods must include exactly every historical period overlapping the cash interval, including special periods"));
    }
    spans.sort_unstable();
    let mut covered = from;
    for (start, stop) in spans {
        if start > covered { return Err(invalid("income periods leave a gap inside the cash interval")); }
        covered = covered.max(stop);
    }
    if covered != end { return Err(invalid("income periods do not cover the complete cash interval")); }
    Ok(())
}

/// Called only AFTER native cash read/certification/replay has admitted current
/// whole-book authority. Its source closure covers Account, Entry, Period, Book,
/// FiscalCalendar, Unit and MigrationRun, not merely the displayed cash legs.
pub(super) fn from_cash<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>, cx: &PurposeContexts, principal: VId, capability: &Capability,
    cash: CashFlow, income_periods: &[String], definition: &IndirectCashFlowDefinition,
) -> Outcome<IndirectCashFlow> {
    let selected = match periods(income_periods) { Ok(v) => v, Err(r) => return Ok(Err(r)) };
    let definition = match normalize(definition) { Ok(v) => v, Err(r) => return Ok(Err(r)) };
    let source = cash.source();
    let at = source.known_at();
    let query = cx.query();
    query.checkpoint().map_err(BookError::Context)?;
    let metadata = query.with_restriction(|| -> Result<Vec<VId>, Error> {
        let mut all_periods = Vec::new();
        for (index, row) in book.db.vertices_at(at).map_err(KernelError::from).map_err(BookError::from)?.into_iter().enumerate() {
            if index % 256 == 0 { query.checkpoint().map_err(BookError::Context)?; }
            if row.labels.contains(&label::PERIOD) {
                let period = PeriodRow::decode(&row).map_err(BookError::from)?;
                if period.calendar_id == book.context().calendar.id {
                    all_periods.push((period.code, period.start, period.end));
                }
            }
        }
        coverage(&all_periods, &selected, source.effective_from(), source.effective_through())?;
        let cash_ids: BTreeSet<_> = source.accounts().iter().map(|a| a.id).collect();
        let chart = fa_journal::chart::read_at(&book.db, book.context(), at).map_err(BookError::from)?;
        let mut accounts = Vec::new();
        for (index, account) in chart.accounts().values().enumerate() {
            if index % 256 == 0 { query.checkpoint().map_err(BookError::Context)?; }
            if account.is_leaf && (1..=5).contains(&account.account_type) && !cash_ids.contains(&account.vid.0) {
                if accounts.len() == 4096 { return Err(invalid("non-cash adjustment source exceeds 4,096 monetary leaves").into()); }
                accounts.push(account.vid);
            }
        }
        Ok(accounts)
    });
    let accounts = match outcome(metadata)? { Ok(v) => v, Err(r) => return Ok(Err(r)) };
    let detail = if accounts.is_empty() { None } else {
        let request = RollForwardRequest { accounts, units: source.units().to_vec(),
            label: source.label().to_string(), effective_from: source.effective_from(),
            effective_through: source.effective_through(), known_at: Some(at) };
        match book.general_ledger(cx, principal, capability, &request)? {
            Ok(v) => Some(v), Err(r) => return Ok(Err(r)),
        }
    };
    let income_definition = match StatementDefinition::embedded("income-statement") {
        Ok(v) => v, Err(e) => return Ok(Err(invalid(e.to_string()))),
    };
    // Use the existing native income fold, including Closing reversal lineage,
    // rather than reconstructing earnings from nominal account closing stock.
    let income = query.with_restriction(|| crate::statements::read(
        &book.db, &query, book.context(), StatementSelection {
            definition: income_definition, periods: selected, comparative: Vec::new(),
        }, Some(at),
    ));
    let income = match income? { Ok(v) => v, Err(r) => return Ok(Err(r)) };
    project(cash, income, detail, &definition, &query)
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Read an indirect earnings-to-cash workpaper at one native prefix under
    /// current whole-book Read authority. HEAD resolves once in the direct cash
    /// reader. Income, historical chart expansion and all adjustment citations
    /// use that same prefix. No posting, new runtime or protected text read.
    pub fn indirect_cash_flow(
        &self, cx: &PurposeContexts, principal: VId, capability: &Capability,
        request: &IndirectCashFlowRequest,
    ) -> Outcome<IndirectCashFlow> {
        let cash = match self.cash_flow(cx, principal, capability, &request.cash, &request.cash_definition)? {
            Ok(v) => v, Err(r) => return Ok(Err(r)),
        };
        from_cash(self, cx, principal, capability, cash, &request.income_periods, &request.definition)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn span(code: &str, a: i32, b: i32) -> (String, DateDay, DateDay) { (code.into(), DateDay(a), DateDay(b)) }
    #[test]
    fn special_period_omission_is_refused_even_when_normal_period_covers_every_day() {
        let all = [span("P1", 1, 32), span("ADJ", 31, 32)];
        assert!(coverage(&all, &["P1".into()], DateDay(1), DateDay(31)).is_err());
        coverage(&all, &["ADJ".into(), "P1".into()], DateDay(1), DateDay(31)).unwrap();
    }
    #[test]
    fn same_outer_bounds_do_not_hide_gaps_or_partial_periods() {
        let expected = ["P1".into(), "P2".into()];
        assert!(coverage(&[span("P1", 1, 10), span("P2", 11, 21)], &expected, DateDay(1), DateDay(20)).is_err());
        assert!(coverage(&[span("P1", 1, 11)], &["P1".into()], DateDay(2), DateDay(10)).is_err());
        coverage(&[span("P2", 11, 21), span("P1", 1, 11)], &expected, DateDay(1), DateDay(20)).unwrap();
    }
}
