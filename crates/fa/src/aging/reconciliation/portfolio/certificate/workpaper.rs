//! Buffered recipient-bound portfolio workpapers. Every selected item,
//! application, aging band/cell and control row is retained. Unselected leaves
//! are identified as uncovered, not printed as zero or silently dropped.

use fa_money::{Side, UnitRegistry};
use fgdb_types::QueryCx;
use super::*;

fn append(out: &mut String, text: &str) -> Result<(), Refusal> {
    bounded([out.len(), text.len()])?;
    out.try_reserve(text.len()).map_err(|_| invalid("cannot reserve portfolio workpaper output"))?;
    out.push_str(text);
    Ok(())
}

fn quoted(out: &mut String, text: &str) -> Result<(), Refusal> {
    append(out, "\"")?;
    for ch in text.chars() {
        match ch {
            '"' => append(out, "\\\"")?,
            '\\' => append(out, "\\\\")?,
            '\n' => append(out, "\\n")?,
            '\r' => append(out, "\\r")?,
            '\t' => append(out, "\\t")?,
            c if c < '\u{20}' => append(out, &format!("\\u{:04x}", u32::from(c)))?,
            c => { let mut bytes = [0; 4]; append(out, c.encode_utf8(&mut bytes))?; }
        }
    }
    append(out, "\"")
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }

enum ExportError { Refusal(Refusal), Book(BookError) }
impl From<Refusal> for ExportError { fn from(r: Refusal) -> Self { Self::Refusal(r) } }
impl From<BookError> for ExportError { fn from(e: BookError) -> Self { Self::Book(e) } }

fn account_line(text: &mut String, account: &AccountRow, included: bool) -> Result<(), Refusal> {
    append(text, &format!("{{\"event\":\"aging_portfolio_account\",\"account\":\"{:032x}\",\"selected\":{},\"code\":", account.vid.0, included))?;
    quoted(text, &account.code)?;
    append(text, ",\"name\":")?;
    quoted(text, &account.name)?;
    append(text, &format!(",\"account_type\":\"{}\",\"normal_balance\":\"{}\",\"created_at\":\"{}\"}}\n",
        account.account_type, account.normal_balance, account.created_at.0))
}

fn render(report: &AgingPortfolio, certificate: &AgingPortfolioCertificate,
    units: &UnitRegistry, query: &QueryCx) -> Result<String, ExportError>
{
    let mut text = String::new();
    let request = report.request();
    let at = request.known_at.ok_or_else(|| invalid("workpaper has no fixed recorded prefix"))?;
    let scope = match &request.scope { AgingAccountScope::AllPosting => "all_posting", AgingAccountScope::Selected(_) => "selected_posting" };
    append(&mut text, &format!(
        "{{\"event\":\"aging_portfolio\",\"format\":\"fa:aging-portfolio-workpaper:v1\",\"book\":\"{}\",\"known_at\":\"{}\",\"effective_through\":\"{}\",\"scope\":\"{}\",\"certificate_digest\":\"{}\",\"aging_digest\":\"{}\",\"control_digest\":\"{}\",\"signatures\":\"unsigned\"}}\n",
        hex(&report.book_id().0), at.0, request.effective_through, scope,
        hex(certificate.digest()), hex(certificate.aging_source().digest()), hex(&certificate.control_source().digest)))?;
    let unit_ids: BTreeSet<_> = report.accounts().iter().flat_map(|a| a.rows()).map(|row| row.unit_id).collect();
    for id in unit_ids {
        query.checkpoint().map_err(BookError::Context)?;
        let unit = units.get(UnitId(id)).ok_or_else(|| invalid("unknown portfolio workpaper unit"))?;
        append(&mut text, &format!("{{\"event\":\"aging_portfolio_unit\",\"unit_id\":\"{id}\",\"code\":"))?;
        quoted(&mut text, &unit.code)?;
        append(&mut text, &format!(",\"scale\":\"{}\",\"version\":\"{}\"}}\n", unit.scale, unit.version))?;
    }
    for (index, band) in request.buckets.bands().iter().enumerate() {
        append(&mut text, &format!("{{\"event\":\"aging_portfolio_band\",\"bucket\":\"{index}\",\"lower_inclusive\":\"{}\",\"upper_inclusive\":", band.lower_inclusive))?;
        match band.upper_inclusive {
            Some(upper) => quoted(&mut text, &upper.to_string())?,
            None => append(&mut text, "null")?,
        }
        append(&mut text, "}\n")?;
    }
    for account in report.accounts() {
        query.checkpoint().map_err(BookError::Context)?;
        account_line(&mut text, account.account(), true)?;
        for row in account.rows() {
            query.checkpoint().map_err(BookError::Context)?;
            append(&mut text, &format!(
                "{{\"event\":\"aging_portfolio_control\",\"account\":\"{:032x}\",\"unit_id\":\"{}\",\"posted_debits\":\"{}\",\"posted_credits\":\"{}\",\"pending_debits\":\"{}\",\"pending_credits\":\"{}\",\"open_debits\":\"{}\",\"open_credits\":\"{}\",\"open_item_count\":\"{}\",\"posted_net\":\"{}\",\"open_net\":\"{}\",\"difference\":\"{}\"}}\n",
                account.account().vid.0, row.unit_id, row.posted_debits, row.posted_credits,
                row.pending_debits, row.pending_credits, row.open_debits, row.open_credits,
                row.open_item_count, row.posted_net, row.open_net, row.difference))?;
        }
        for aged in &account.aging().items {
            query.checkpoint().map_err(BookError::Context)?;
            let item = &aged.item;
            append(&mut text, &format!(
                "{{\"event\":\"aging_portfolio_item\",\"account\":\"{:032x}\",\"entry\":\"{:032x}\",\"ordinal\":\"{}\",\"unit_id\":\"{}\",\"side\":\"{}\",\"effective_date\":\"{}\",\"recorded_at\":\"{}\",\"original\":\"{}\",\"applied\":\"{}\",\"applied_out\":\"{}\",\"open\":\"{}\",\"age_days\":\"{}\",\"bucket\":\"{}\"}}\n",
                item.account.0, item.entry.0, item.ordinal, item.unit_id,
                match item.side { Side::Debit => "debit", Side::Credit => "credit" },
                item.effective_date, item.recorded_at.0, item.original, item.applied,
                item.applied_out, item.open, aged.age_days, aged.bucket))?;
            for application in &item.applications {
                query.checkpoint().map_err(BookError::Context)?;
                append(&mut text, &format!(
                    "{{\"event\":\"aging_portfolio_application\",\"target_entry\":\"{:032x}\",\"target_ordinal\":\"{}\",\"entry\":\"{:032x}\",\"ordinal\":\"{}\",\"amount\":\"{}\",\"recorded_at\":\"{}\",\"live\":{}}}\n",
                    item.entry.0, item.ordinal, application.entry.0, application.ordinal,
                    application.amount, application.recorded_at.0, application.live))?;
            }
        }
        for cell in &account.aging().cells {
            query.checkpoint().map_err(BookError::Context)?;
            append(&mut text, &format!(
                "{{\"event\":\"aging_portfolio_cell\",\"account\":\"{:032x}\",\"unit_id\":\"{}\",\"bucket\":\"{}\",\"debits\":\"{}\",\"credits\":\"{}\",\"item_count\":\"{}\"}}\n",
                cell.account.0, cell.unit_id, cell.bucket, cell.amounts.debits, cell.amounts.credits, cell.amounts.item_count))?;
        }
    }
    for account in report.uncovered_accounts() {
        query.checkpoint().map_err(BookError::Context)?;
        account_line(&mut text, account, false)?;
    }
    append(&mut text, &format!(
        "{{\"event\":\"aging_portfolio_result\",\"selected_accounts\":\"{}\",\"uncovered_accounts\":\"{}\",\"complete\":{},\"selected_reconciled\":{},\"complete_and_reconciled\":{},\"has_pending_reservations\":{},\"external_subledger_attestation\":false,\"period_close_authorized\":false}}\n",
        report.accounts().len(), report.uncovered_accounts().len(), report.is_complete(), report.is_reconciled(),
        report.is_complete_and_reconciled(), report.has_pending_reservations()))?;
    query.checkpoint().map_err(BookError::Context)?;
    Ok(text)
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Verify both original sources, exact recipient scope and coverage before
    /// returning complete selected-account detail. Integers are decimal strings;
    /// control-only units and zero accounts remain visible. Current read+produce
    /// authority is required. No protected text is opened and no file is written.
    /// Verification, allocation, size or cancellation failure returns no text.
    pub fn aging_portfolio_jsonl(&self, cx: &PurposeContexts, principal: VId,
        capability: &Capability, certificate: &AgingPortfolioCertificate,
        expected: &AgingPortfolioRequest) -> Outcome<String>
    {
        if let Err(r) = authorize(self, cx, principal, capability, true)? { return Ok(Err(r)); }
        let report = match self.replay_aging_portfolio(cx, principal, capability, certificate, expected)? {
            Ok(report) => report, Err(r) => return Ok(Err(r)),
        };
        match render(&report, certificate, &self.context().units, &cx.query()) {
            Ok(text) => Ok(Ok(text)), Err(ExportError::Refusal(r)) => Ok(Err(r)), Err(ExportError::Book(e)) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quoted_text_and_output_bounds_are_exact() {
        let mut text = String::new();
        quoted(&mut text, "€\"\\\n\r\t\0").unwrap();
        assert_eq!(text, "\"€\\\"\\\\\\n\\r\\t\\u0000\"");
        assert_eq!(bounded([MAX_AGING_PORTFOLIO_BYTES]).unwrap(), MAX_AGING_PORTFOLIO_BYTES);
        assert!(bounded([MAX_AGING_PORTFOLIO_BYTES, 1]).is_err());
        assert!(bounded([usize::MAX, 1]).is_err());
    }
}
