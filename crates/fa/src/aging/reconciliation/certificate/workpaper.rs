//! The existing replayed aging JSONL followed by the exact control-side
//! comparison. No files are opened or published; failure returns no text.

use super::*;
use fa_money::UnitRegistry;
use fgdb_types::QueryCx;

fn append(out: &mut String, text: &str) -> Result<(), Refusal> {
    bounded([out.len(), text.len()])?;
    out.try_reserve(text.len())
        .map_err(|_| invalid("cannot reserve reconciliation workpaper output"))?;
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
            c => {
                let mut bytes = [0; 4];
                append(out, c.encode_utf8(&mut bytes))?;
            }
        }
    }
    append(out, "\"")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

enum ExportError {
    Refusal(Refusal),
    Book(BookError),
}
impl From<Refusal> for ExportError {
    fn from(r: Refusal) -> Self {
        Self::Refusal(r)
    }
}
impl From<BookError> for ExportError {
    fn from(e: BookError) -> Self {
        Self::Book(e)
    }
}

fn finish(
    mut text: String,
    report: &AgingReconciliation,
    certificate: &AgingReconciliationCertificate,
    units: &UnitRegistry,
    query: &QueryCx,
) -> Result<String, ExportError> {
    for row in report.rows() {
        query.checkpoint().map_err(BookError::Context)?;
        let unit = units
            .get(UnitId(row.unit_id))
            .ok_or_else(|| invalid("unregistered reconciliation unit"))?;
        // Include control-only units, even when the final item was fully paid
        // and the aging portion consequently has no unit definition row.
        append(
            &mut text,
            &format!(
                "{{\"event\":\"aging_control_unit\",\"unit_id\":\"{}\",\"code\":",
                row.unit_id
            ),
        )?;
        quoted(&mut text, &unit.code)?;
        append(
            &mut text,
            &format!(
                ",\"scale\":\"{}\",\"version\":\"{}\"}}\n",
                unit.scale, unit.version
            ),
        )?;
        append(
            &mut text,
            &format!(
                "{{\"event\":\"aging_control_row\",\"account\":\"{:032x}\",\"unit_id\":\"{}\",\"posted_debits\":\"{}\",\"posted_credits\":\"{}\",\"pending_debits\":\"{}\",\"pending_credits\":\"{}\",\"open_debits\":\"{}\",\"open_credits\":\"{}\",\"open_item_count\":\"{}\",\"posted_net\":\"{}\",\"open_net\":\"{}\",\"difference\":\"{}\"}}\n",
                report.account().vid.0,
                row.unit_id,
                row.posted_debits,
                row.posted_credits,
                row.pending_debits,
                row.pending_credits,
                row.open_debits,
                row.open_credits,
                row.open_item_count,
                row.posted_net,
                row.open_net,
                row.difference
            ),
        )?;
    }
    query.checkpoint().map_err(BookError::Context)?;
    append(
        &mut text,
        &format!(
            "{{\"event\":\"aging_control_reconciliation\",\"format\":\"fa:aging-reconciliation-workpaper:v1\",\"scope\":\"selected_account_native_unit_net_balances\",\"account\":\"{:032x}\",\"known_at\":\"{}\",\"effective_through\":\"{}\",\"unit_count\":\"{}\",\"reconciled\":{},\"certificate_digest\":\"{}\",\"aging_digest\":\"{}\",\"control_digest\":\"{}\",\"signatures\":\"unsigned\",\"external_subledger_attestation\":false}}\n",
            report.account().vid.0,
            report.known_at().0,
            report.effective_through(),
            report.rows().len(),
            report.is_reconciled(),
            hex(certificate.digest()),
            hex(certificate.aging_source().digest()),
            hex(&certificate.control_source().digest)
        ),
    )?;
    query.checkpoint().map_err(BookError::Context)?;
    Ok(text)
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Replay BOTH sources and the exact recipient question before returning
    /// the existing complete aging workpaper plus control rows and a conclusion.
    /// Numbers are decimal strings; native unit definitions include units only
    /// present on the control side. The combined UTF-8 result is bounded to
    /// 64 MiB. No partial result, protected text, signature or corrective post.
    pub fn effective_date_aging_reconciliation_jsonl(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &AgingReconciliationCertificate,
        expected: &AgingReconciliationRequest,
    ) -> Outcome<String> {
        if let Err(r) = authorize(self, cx, principal, capability, true)? {
            return Ok(Err(r));
        }
        let report = match self.replay_effective_date_aging_reconciliation(
            cx,
            principal,
            capability,
            certificate,
            expected,
        )? {
            Ok(report) => report,
            Err(r) => return Ok(Err(r)),
        };
        let request = AgingRequest {
            account: Some(expected.account),
            effective_through: expected.effective_through,
            known_at: expected.known_at,
            buckets: expected.buckets.clone(),
        };
        let text = match self.effective_date_aging_jsonl(
            cx,
            principal,
            capability,
            certificate.aging_source(),
            &request,
        )? {
            Ok(text) => text,
            Err(r) => return Ok(Err(r)),
        };
        match finish(
            text,
            &report,
            certificate,
            &self.context().units,
            &cx.query(),
        ) {
            Ok(text) => Ok(Ok(text)),
            Err(ExportError::Refusal(r)) => Ok(Err(r)),
            Err(ExportError::Book(e)) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn code_strings_escape_controls_and_preserve_unicode() {
        let mut text = String::new();
        quoted(&mut text, "€\"\\\n\r\t\0").unwrap();
        assert_eq!(text, "\"€\\\"\\\\\\n\\r\\t\\u0000\"");
        assert!(bounded([MAX_AGING_RECONCILIATION_BYTES, 1]).is_err());
        assert!(bounded([usize::MAX, 1]).is_err());
        assert_eq!(
            bounded([MAX_AGING_RECONCILIATION_BYTES]).unwrap(),
            MAX_AGING_RECONCILIATION_BYTES
        );
    }
}
