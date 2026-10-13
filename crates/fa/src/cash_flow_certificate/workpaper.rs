//! Recipient-facing cash workpapers, rendered only after authorized native replay.
//! The confidential whole-book input certificate is identified, never embedded.

use fa_money::{UnitId, UnitRegistry};
use fa_policy::Op;
use fgdb_types::QueryCx;

use super::*;

pub const CASH_FLOW_WORKPAPER_FORMAT: &str = "fa:cash-flow-workpaper:v1";
pub const MAX_CASH_FLOW_WORKPAPER_BYTES: usize = 64 * 1024 * 1024;

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Recheck current read+produce authority and replay the independently
    /// expected request/definition before emitting selected cash detail. Amounts
    /// and counts are decimal strings, never JSON floating-point numbers.
    /// All output is buffered: refusal, cancellation and size failure return no
    /// prefix. Source certificates and protected text are never included.
    pub fn cash_flow_jsonl(
        &self, cx: &PurposeContexts, principal: VId, capability: &Capability,
        certificate: &CashFlowCertificate, expected: &RollForwardRequest,
        expected_definition: &CashFlowDefinition,
    ) -> Outcome<String> {
        let admitted = fa_policy::admit_read(capability, principal, self.context().book_id)
            .and_then(|()| fa_policy::require(capability, Op::Produce, "producing cash-flow workpapers"));
        if let Err(denial) = admitted {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        // The replay checks current expiry/revocation, the whole native input
        // closure and every exact output byte before any financial rendering.
        let report = match self.replay_cash_flow(
            cx, principal, capability, certificate, expected, expected_definition,
        )? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        match render(&report, certificate, &self.context().units, &cx.query()) {
            Ok(text) => Ok(Ok(text)),
            Err(RenderError::Refusal(refusal)) => Ok(Err(refusal)),
            Err(RenderError::Book(error)) => Err(error),
        }
    }
}

enum RenderError {
    Refusal(Refusal),
    Book(BookError),
}
impl From<Refusal> for RenderError {
    fn from(value: Refusal) -> Self { Self::Refusal(value) }
}
impl From<BookError> for RenderError {
    fn from(value: BookError) -> Self { Self::Book(value) }
}

fn size(current: usize, extra: usize) -> Result<usize, Refusal> {
    current.checked_add(extra).filter(|n| *n <= MAX_CASH_FLOW_WORKPAPER_BYTES)
        .ok_or_else(|| invalid("cash-flow workpaper exceeds its 64 MiB bound; narrow the scope"))
}

fn append(out: &mut String, text: &str) -> Result<(), Refusal> {
    size(out.len(), text.len())?;
    out.try_reserve(text.len()).map_err(|_| invalid("cannot reserve cash-flow workpaper"))?;
    out.push_str(text);
    Ok(())
}

fn quoted(out: &mut String, value: &str, mut checkpoint: impl FnMut() -> Result<(), BookError>)
    -> Result<(), RenderError>
{
    append(out, "\"")?;
    for (index, ch) in value.chars().enumerate() {
        if index % 256 == 0 { checkpoint()?; }
        match ch {
            '"' => append(out, "\\\"")?,
            '\\' => append(out, "\\\\")?,
            '\n' => append(out, "\\n")?,
            '\r' => append(out, "\\r")?,
            '\t' => append(out, "\\t")?,
            c if c < '\u{20}' => append(out, &format!("\\u{:04x}", u32::from(c)))?,
            c => {
                let mut bytes = [0; 4];
                append(out, c.encode_utf8(&mut bytes))?;
            }
        }
    }
    checkpoint()?;
    append(out, "\"")?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }

fn activity_name(activity: CashFlowActivity) -> &'static str {
    match activity {
        CashFlowActivity::Operating => "operating",
        CashFlowActivity::Investing => "investing",
        CashFlowActivity::Financing => "financing",
        CashFlowActivity::ExchangeEffect => "exchange_effects",
        CashFlowActivity::InternalTransfer => "internal_transfer",
    }
}

fn render(
    report: &CashFlow, certificate: &CashFlowCertificate, units: &UnitRegistry, query: &QueryCx,
) -> Result<String, RenderError> {
    let checkpoint = || query.checkpoint().map_err(BookError::Context);
    checkpoint()?;
    let mut out = String::new();
    let ledger = report.source();
    append(&mut out, &format!(
        "{{\"event\":\"cash_flow\",\"format\":\"{}\",\"book\":\"{}\",\"branch\":\"{}\",\"known_at\":\"{}\",\"effective_from\":\"{}\",\"effective_through\":\"{}\",\"certificate_digest\":\"{}\",\"source_certificate_digest\":\"{}\",\"scope\":\"explicit_cash_accounts_and_units\",\"method\":\"classified_cash_movements\",\"sign_convention\":\"debit_minus_credit\",\"definition\":",
        CASH_FLOW_WORKPAPER_FORMAT, hex(&ledger.book_id().0), hex(&ledger.branch_id().0),
        ledger.known_at().0, ledger.effective_from(), ledger.effective_through(),
        hex(certificate.digest()), hex(certificate.source_certificate().digest()),
    ))?;
    quoted(&mut out, &report.definition().name, checkpoint)?;
    append(&mut out, ",\"label\":")?;
    quoted(&mut out, ledger.label(), checkpoint)?;
    append(&mut out, "}\n")?;
    for account in ledger.accounts() {
        checkpoint()?;
        append(&mut out, &format!("{{\"event\":\"cash_flow_account\",\"account\":\"{:032x}\",\"code\":", account.id))?;
        quoted(&mut out, &account.code, checkpoint)?;
        append(&mut out, ",\"name\":")?;
        quoted(&mut out, &account.name, checkpoint)?;
        append(&mut out, &format!(",\"account_type\":\"{}\",\"is_leaf\":{}}}\n", account.account_type, account.is_leaf))?;
    }
    for row in report.units() {
        checkpoint()?;
        let unit = units.get(UnitId(row.unit_id)).ok_or_else(|| invalid("unregistered cash-flow workpaper unit"))?;
        append(&mut out, &format!("{{\"event\":\"cash_flow_unit\",\"unit_id\":\"{}\",\"code\":", row.unit_id))?;
        quoted(&mut out, &unit.code, checkpoint)?;
        append(&mut out, &format!(",\"scale\":\"{}\",\"version\":\"{}\"}}\n", unit.scale, unit.version))?;
        for (activity, section) in [
            (CashFlowActivity::Operating, row.operating),
            (CashFlowActivity::Investing, row.investing),
            (CashFlowActivity::Financing, row.financing),
            (CashFlowActivity::ExchangeEffect, row.exchange_effects),
        ] {
            append(&mut out, &format!(
                "{{\"event\":\"cash_flow_section\",\"unit_id\":\"{}\",\"activity\":\"{}\",\"inflows\":\"{}\",\"outflows\":\"{}\",\"net\":\"{}\"}}\n",
                row.unit_id, activity_name(activity), section.inflows, section.outflows, section.net,
            ))?;
        }
        append(&mut out, &format!(
            "{{\"event\":\"cash_flow_total\",\"unit_id\":\"{}\",\"opening\":\"{}\",\"net_change\":\"{}\",\"closing\":\"{}\",\"reconciled\":true}}\n",
            row.unit_id, row.opening, row.net_change, row.closing,
        ))?;
    }
    for (index, bucket) in ledger.buckets().iter().enumerate() {
        checkpoint()?;
        append(&mut out, &format!("{{\"event\":\"cash_flow_bucket\",\"bucket\":\"{index}\",\"class\":\"{}\",\"reason_code\":", bucket.class.0))?;
        quoted(&mut out, &bucket.reason_code, checkpoint)?;
        append(&mut out, ",\"rule_digest\":")?;
        match bucket.rule_digest {
            Some(digest) => quoted(&mut out, &hex(&digest), checkpoint)?,
            None => append(&mut out, "null")?,
        }
        append(&mut out, "}\n")?;
    }
    for (index, cell) in ledger.cells().iter().enumerate() {
        checkpoint()?;
        append(&mut out, &format!(
            "{{\"event\":\"cash_flow_account_balance\",\"cell\":\"{index}\",\"account\":\"{:032x}\",\"unit_id\":\"{}\",\"opening\":\"{}\",\"debits\":\"{}\",\"credits\":\"{}\",\"net_change\":\"{}\",\"closing\":\"{}\"}}\n",
            cell.account_id, cell.unit_id, cell.opening, cell.debits, cell.credits, cell.net_change, cell.closing,
        ))?;
    }
    let assignments = &report.definition().assignments;
    for line in ledger.lines() {
        checkpoint()?;
        let cell = ledger.cells().get(line.cell_index as usize)
            .ok_or_else(|| invalid("cash-flow workpaper movement has no selected cell"))?;
        let index = assignments.binary_search_by_key(&(line.entry_digest, line.leg_index),
            |a| (a.entry_digest, a.leg_index))
            .map_err(|_| invalid("cash-flow workpaper movement has no unique classification"))?;
        append(&mut out, &format!(
            "{{\"event\":\"cash_flow_leg\",\"cell\":\"{}\",\"account\":\"{:032x}\",\"unit_id\":\"{}\",\"entry_digest\":\"{}\",\"leg_index\":\"{}\",\"recorded_at\":\"{}\",\"effective_date\":\"{}\",\"bucket\":\"{}\",\"activity\":\"{}\",\"debits\":\"{}\",\"credits\":\"{}\",\"running_balance\":\"{}\"}}\n",
            line.cell_index, cell.account_id, cell.unit_id, hex(&line.entry_digest), line.leg_index,
            line.recorded_seq, line.effective_day, line.bucket_index, activity_name(assignments[index].activity),
            line.debits, line.credits, line.running_balance,
        ))?;
    }
    append(&mut out, &format!(
        "{{\"event\":\"cash_flow_result\",\"accounts\":\"{}\",\"units\":\"{}\",\"legs\":\"{}\",\"each_unit_reconciled\":true,\"native_history_replayed\":true,\"classification_judgment_verified\":false,\"pending_included\":false,\"protected_text_disclosed\":false,\"full_native_evidence_disclosed\":false,\"outsider_completeness_proof\":false,\"period_close_authorized\":false}}\n",
        ledger.accounts().len(), report.units().len(), ledger.lines().len(),
    ))?;
    checkpoint()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workpaper_strings_escape_controls_and_preserve_unicode() {
        let mut out = String::new();
        assert!(quoted(&mut out, "€\"\\\n\r\t\0", || Ok(())).is_ok());
        assert_eq!(out, "\"€\\\"\\\\\\n\\r\\t\\u0000\"");
        for byte in 0u8..32 {
            let mut out = String::new();
            assert!(quoted(&mut out, &char::from(byte).to_string(), || Ok(())).is_ok());
            assert!(!out.chars().any(|ch| ch < '\u{20}'));
        }
    }

    #[test]
    fn oversized_workpapers_refuse_without_integer_wraparound() {
        assert_eq!(size(MAX_CASH_FLOW_WORKPAPER_BYTES, 0).unwrap(), MAX_CASH_FLOW_WORKPAPER_BYTES);
        assert!(size(MAX_CASH_FLOW_WORKPAPER_BYTES, 1).is_err());
        assert!(size(usize::MAX, 1).is_err());
    }

    #[test]
    fn long_metadata_checks_the_callers_budget_inside_the_string() {
        let mut calls = 0;
        let mut out = String::new();
        assert!(quoted(&mut out, &"x".repeat(1025), || { calls += 1; Ok(()) }).is_ok());
        assert_eq!(calls, 6); // indices 0/256/512/768/1024 and final check
        assert_eq!(out.len(), 1027);
    }
}
