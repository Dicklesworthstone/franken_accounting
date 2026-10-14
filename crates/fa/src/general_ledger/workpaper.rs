//! Native-history-backed general-ledger views and buffered recipient workpapers.
//! Reuse the complete existing roll-forward certificate rather than inventing
//! another proof format or treating matching totals as a completeness check.

use fa_money::{UnitId, UnitRegistry};
use fa_policy::Op;

use super::*;
use crate::roll_forward::RollForwardCertificate;

pub const GENERAL_LEDGER_WORKPAPER_FORMAT: &str = "fa:general-ledger-workpaper:v1";

/// A native-certified source and its deterministic ledger view. The source
/// certificate's portable bytes are the existing RollForwardCertificate format.
/// They contain whole-book input evidence: keep them confidential even when
/// only selected accounts appear in the general-ledger view or workpaper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedGeneralLedger {
    report: GeneralLedger,
    source: RollForwardCertificate,
}

impl CertifiedGeneralLedger {
    #[must_use]
    pub fn report(&self) -> &GeneralLedger {
        &self.report
    }
    #[must_use]
    pub fn source_certificate(&self) -> &RollForwardCertificate {
        &self.source
    }
    #[must_use]
    pub fn into_source_certificate(self) -> RollForwardCertificate {
        self.source
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Certify the complete native source at one prefix, then derive exact
    /// effective-date detail. Read+produce authority is required by the source
    /// producer. No duplicate certificate format or journal write is introduced.
    pub fn certify_general_ledger(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &RollForwardRequest,
    ) -> Outcome<CertifiedGeneralLedger> {
        let source = match self.certify_roll_forward(cx, principal, capability, request)? {
            Ok(source) => source,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let report = match project(source.report, &cx.query())? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        Ok(Ok(CertifiedGeneralLedger {
            report,
            source: source.certificate,
        }))
    }

    /// Rebuild detail only after the existing source verifier has checked its
    /// complete retained native closure AND the recipient's independent request.
    /// `expected.known_at` must be explicit. Do not derive expected scope from
    /// an untrusted delivered certificate. Current read authority is required;
    /// later postings cannot silently replace the original prefix or its legs.
    pub fn replay_general_ledger(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        source: &RollForwardCertificate,
        expected: &RollForwardRequest,
    ) -> Outcome<GeneralLedger> {
        let source =
            match self.replay_roll_forward_for(cx, principal, capability, source, expected)? {
                Ok(source) => source,
                Err(refusal) => return Ok(Err(refusal)),
            };
        project(source, &cx.query())
    }

    /// Return selected-scope JSONL only after native replay and exact independent
    /// request binding. Every amount/count is a decimal string. Buffered output
    /// never exceeds 64 MiB and never returns a prefix on a failure. The source's
    /// whole-book native input closure and protected entry/document text are NOT
    /// included. This is a readable workpaper, not an outsider proof or approval.
    pub fn general_ledger_jsonl(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        source: &RollForwardCertificate,
        expected: &RollForwardRequest,
    ) -> Outcome<String> {
        let admitted = fa_policy::admit_read(capability, principal, self.context().book_id)
            .and_then(|()| {
                fa_policy::require(
                    capability,
                    Op::Produce,
                    "producing general-ledger workpapers",
                )
            });
        if let Err(denial) = admitted {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        // Replay checks current expiry, revocation, historical registry identity
        // and source integrity before any financial byte is rendered.
        let report =
            match self.replay_general_ledger(cx, principal, capability, source, expected)? {
                Ok(report) => report,
                Err(refusal) => return Ok(Err(refusal)),
            };
        match render(&report, source, &self.context().units, &cx.query()) {
            Ok(text) => Ok(Ok(text)),
            Err(ProjectionError::Refusal(refusal)) => Ok(Err(refusal)),
            Err(ProjectionError::Book(error)) => Err(error),
        }
    }
}

fn append(out: &mut String, text: &str) -> Result<(), Refusal> {
    length(out.len(), text.len())?;
    out.try_reserve(text.len())
        .map_err(|_| invalid("cannot reserve general-ledger workpaper"))?;
    out.push_str(text);
    Ok(())
}

fn quoted(out: &mut String, value: &str) -> Result<(), Refusal> {
    append(out, "\"")?;
    for ch in value.chars() {
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

fn render(
    report: &GeneralLedger,
    source: &RollForwardCertificate,
    units: &UnitRegistry,
    query: &QueryCx,
) -> Result<String, ProjectionError> {
    query.checkpoint().map_err(BookError::Context)?;
    let mut out = String::new();
    append(
        &mut out,
        &format!(
            "{{\"event\":\"general_ledger\",\"format\":\"{}\",\"book\":\"{}\",\"branch\":\"{}\",\"known_at\":\"{}\",\"effective_from\":\"{}\",\"effective_through\":\"{}\",\"source_certificate_digest\":\"{}\",\"scope\":\"selected_accounts_and_units\",\"sign_convention\":\"debit_minus_credit\",\"running_order\":\"account_unit_effective_recorded_entry_leg\",\"label\":",
            GENERAL_LEDGER_WORKPAPER_FORMAT,
            hex(&report.book_id.0),
            hex(&report.branch_id.0),
            report.known_at.0,
            report.effective_from,
            report.effective_through,
            hex(source.digest())
        ),
    )?;
    quoted(&mut out, &report.label)?;
    append(&mut out, "}\n")?;
    for account in &report.accounts {
        query.checkpoint().map_err(BookError::Context)?;
        append(
            &mut out,
            &format!(
                "{{\"event\":\"general_ledger_account\",\"account\":\"{:032x}\",\"code\":",
                account.id
            ),
        )?;
        quoted(&mut out, &account.code)?;
        append(&mut out, ",\"name\":")?;
        quoted(&mut out, &account.name)?;
        append(
            &mut out,
            &format!(
                ",\"account_type\":\"{}\",\"is_leaf\":{}}}\n",
                account.account_type, account.is_leaf
            ),
        )?;
    }
    for id in &report.units {
        query.checkpoint().map_err(BookError::Context)?;
        let unit = units
            .get(UnitId(*id))
            .ok_or_else(|| invalid("unregistered general-ledger workpaper unit"))?;
        append(
            &mut out,
            &format!("{{\"event\":\"general_ledger_unit\",\"unit_id\":\"{id}\",\"code\":"),
        )?;
        quoted(&mut out, &unit.code)?;
        append(
            &mut out,
            &format!(
                ",\"scale\":\"{}\",\"version\":\"{}\"}}\n",
                unit.scale, unit.version
            ),
        )?;
    }
    for (index, bucket) in report.buckets.iter().enumerate() {
        query.checkpoint().map_err(BookError::Context)?;
        append(
            &mut out,
            &format!(
                "{{\"event\":\"general_ledger_bucket\",\"bucket\":\"{index}\",\"class\":\"{}\",\"reason_code\":",
                bucket.class.0
            ),
        )?;
        quoted(&mut out, &bucket.reason_code)?;
        append(&mut out, ",\"rule_digest\":")?;
        match bucket.rule_digest {
            Some(digest) => quoted(&mut out, &hex(&digest))?,
            None => append(&mut out, "null")?,
        }
        append(&mut out, "}\n")?;
    }
    for (index, cell) in report.cells.iter().enumerate() {
        query.checkpoint().map_err(BookError::Context)?;
        append(
            &mut out,
            &format!(
                "{{\"event\":\"general_ledger_cell\",\"cell\":\"{index}\",\"account\":\"{:032x}\",\"unit_id\":\"{}\",\"opening\":\"{}\",\"debits\":\"{}\",\"credits\":\"{}\",\"net_change\":\"{}\",\"closing\":\"{}\",\"line_start\":\"{}\",\"line_end\":\"{}\"}}\n",
                cell.account_id,
                cell.unit_id,
                cell.opening,
                cell.debits,
                cell.credits,
                cell.net_change,
                cell.closing,
                cell.line_start,
                cell.line_end
            ),
        )?;
        for line in &report.lines[cell.line_start as usize..cell.line_end as usize] {
            query.checkpoint().map_err(BookError::Context)?;
            append(
                &mut out,
                &format!(
                    "{{\"event\":\"general_ledger_line\",\"cell\":\"{}\",\"entry_digest\":\"{}\",\"leg_index\":\"{}\",\"recorded_at\":\"{}\",\"effective_date\":\"{}\",\"bucket\":\"{}\",\"debits\":\"{}\",\"credits\":\"{}\",\"running_balance\":\"{}\"}}\n",
                    line.cell_index,
                    hex(&line.entry_digest),
                    line.leg_index,
                    line.recorded_seq,
                    line.effective_day,
                    line.bucket_index,
                    line.debits,
                    line.credits,
                    line.running_balance
                ),
            )?;
        }
    }
    append(
        &mut out,
        &format!(
            "{{\"event\":\"general_ledger_result\",\"cells\":\"{}\",\"lines\":\"{}\",\"each_cell_reconciled\":true,\"native_history_replayed\":true,\"pending_included\":false,\"protected_text_disclosed\":false,\"outsider_completeness_proof\":false,\"period_close_authorized\":false}}\n",
            report.cells.len(),
            report.lines.len()
        ),
    )?;
    query.checkpoint().map_err(BookError::Context)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strings_escape_every_control_character_and_preserve_unicode() {
        let mut out = String::new();
        quoted(&mut out, "€\"\\\n\r\t\0").unwrap();
        assert_eq!(out, "\"€\\\"\\\\\\n\\r\\t\\u0000\"");
        for byte in 0u8..32 {
            let mut text = String::new();
            quoted(&mut text, &char::from(byte).to_string()).unwrap();
            assert!(!text.chars().any(|ch| ch < '\u{20}'));
        }
    }

    #[test]
    fn append_refuses_excess_output_before_copying_it() {
        let mut text = String::new();
        let too_large = "x".repeat(MAX_GENERAL_LEDGER_BYTES + 1);
        assert!(append(&mut text, &too_large).is_err());
        assert!(text.is_empty());
    }
}
