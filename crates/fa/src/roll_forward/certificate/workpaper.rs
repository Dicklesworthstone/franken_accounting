//! Selected-scope JSONL after exact request binding and native-history replay.
//! All amounts are native integer mantissas encoded as decimal strings. This
//! is a readable workpaper, not an independently verifiable outsider proof.

use fa_money::{UnitId, UnitRegistry};
use fgdb_types::QueryCx;

use super::*;

/// Complete buffered document bound; failure never returns a partial workpaper.
pub const MAX_ROLL_FORWARD_WORKPAPER_BYTES: usize = 64 * 1024 * 1024;

fn checked_len(current: usize, additional: usize) -> Result<usize, Refusal> {
    current
        .checked_add(additional)
        .filter(|size| *size <= MAX_ROLL_FORWARD_WORKPAPER_BYTES)
        .ok_or_else(|| invalid("roll-forward workpaper exceeds its 64 MiB output bound"))
}

fn append(out: &mut String, text: &str) -> Result<(), Refusal> {
    checked_len(out.len(), text.len())?;
    out.try_reserve(text.len())
        .map_err(|_| invalid("cannot reserve roll-forward workpaper output"))?;
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

fn render(
    report: &RollForward,
    certificate: &RollForwardCertificate,
    units: &UnitRegistry,
    query: &QueryCx,
) -> Result<String, ExportError> {
    let mut text = String::new();
    append(
        &mut text,
        &format!(
            "{{\"event\":\"roll_forward\",\"format\":\"fa:roll-forward-workpaper:v1\",\"book\":\"{}\",\"branch\":\"{}\",\"known_at\":\"{}\",\"effective_from\":\"{}\",\"effective_through\":\"{}\",\"scope\":\"selected_accounts_and_units\",\"sign_convention\":\"debit_minus_credit\",\"certificate_digest\":\"{}\",\"verification\":\"retained_history_replay\",\"signatures\":\"unsigned\",\"label\":",
            hex(&report.book_id.0),
            hex(&report.branch_id.0),
            report.known_at,
            report.effective_from,
            report.effective_through,
            hex(certificate.digest())
        ),
    )?;
    quoted(&mut text, &report.label)?;
    append(&mut text, "}\n")?;
    // Native replay's context_at checked this registry against the selected
    // historical prefix. Do not guess a scale or print an unknown unit.
    for id in &report.units {
        query.checkpoint().map_err(BookError::Context)?;
        let unit = units
            .get(UnitId(*id))
            .ok_or_else(|| invalid("unknown workpaper native unit"))?;
        append(
            &mut text,
            &format!("{{\"event\":\"roll_forward_unit\",\"unit_id\":\"{id}\",\"code\":"),
        )?;
        quoted(&mut text, &unit.code)?;
        append(
            &mut text,
            &format!(
                ",\"scale\":\"{}\",\"version\":\"{}\"}}\n",
                unit.scale, unit.version
            ),
        )?;
    }
    for account in &report.accounts {
        query.checkpoint().map_err(BookError::Context)?;
        append(
            &mut text,
            &format!(
                "{{\"event\":\"roll_forward_account\",\"account\":\"{:032x}\",\"code\":",
                account.id
            ),
        )?;
        quoted(&mut text, &account.code)?;
        append(&mut text, ",\"name\":")?;
        quoted(&mut text, &account.name)?;
        append(
            &mut text,
            &format!(
                ",\"account_type\":\"{}\",\"is_leaf\":{}}}\n",
                account.account_type, account.is_leaf
            ),
        )?;
    }
    let mut indexes = BTreeMap::new();
    for (index, bucket) in report.buckets.iter().enumerate() {
        query.checkpoint().map_err(BookError::Context)?;
        indexes.insert(bucket.clone(), index);
        append(
            &mut text,
            &format!(
                "{{\"event\":\"roll_forward_bucket\",\"bucket\":\"{index}\",\"class\":\"{}\",\"reason_code\":",
                bucket.class.0
            ),
        )?;
        quoted(&mut text, &bucket.reason_code)?;
        append(&mut text, ",\"rule_digest\":")?;
        match bucket.rule_digest {
            Some(digest) => quoted(&mut text, &hex(&digest))?,
            None => append(&mut text, "null")?,
        }
        append(&mut text, "}\n")?;
    }
    for row in &report.rows {
        query.checkpoint().map_err(BookError::Context)?;
        append(
            &mut text,
            &format!(
                "{{\"event\":\"roll_forward_row\",\"account\":\"{:032x}\",\"unit_id\":\"{}\",\"opening\":\"{}\",\"activity\":[",
                row.account_id, row.unit_id, row.opening
            ),
        )?;
        for (index, amount) in row.activity.iter().enumerate() {
            if index != 0 {
                append(&mut text, ",")?;
            }
            quoted(&mut text, &amount.to_string())?;
        }
        append(
            &mut text,
            &format!(
                "],\"net_change\":\"{}\",\"closing\":\"{}\"}}\n",
                row.net_change, row.closing
            ),
        )?;
    }
    for movement in &report.movements {
        query.checkpoint().map_err(BookError::Context)?;
        let bucket = indexes
            .get(&movement.bucket)
            .ok_or_else(|| invalid("workpaper movement has no classified bucket"))?;
        append(
            &mut text,
            &format!(
                "{{\"event\":\"roll_forward_movement\",\"entry_digest\":\"{}\",\"leg_index\":\"{}\",\"recorded_at\":\"{}\",\"effective_date\":\"{}\",\"account\":\"{:032x}\",\"unit_id\":\"{}\",\"bucket\":\"{}\",\"debits\":\"{}\",\"credits\":\"{}\"}}\n",
                hex(&movement.entry_digest),
                movement.leg_index,
                movement.recorded_seq,
                movement.effective_day,
                movement.account_id,
                movement.unit_id,
                bucket,
                movement.debits,
                movement.credits
            ),
        )?;
    }
    append(
        &mut text,
        &format!(
            "{{\"event\":\"roll_forward_result\",\"accounts\":\"{}\",\"units\":\"{}\",\"buckets\":\"{}\",\"rows\":\"{}\",\"movements\":\"{}\",\"native_history_replayed\":true,\"outsider_completeness_proof\":false,\"period_close_authorized\":false}}\n",
            report.accounts.len(),
            report.units.len(),
            report.buckets.len(),
            report.rows.len(),
            report.movements.len()
        ),
    )?;
    query.checkpoint().map_err(BookError::Context)?;
    Ok(text)
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Replay the exact independently requested historical schedule, then return
    /// buffered JSONL with every selected account/unit (including zero cells),
    /// bucket and journal-leg citation. Whole-book read+produce authority is
    /// required, but the native whole-book certificate closure is NOT exported
    /// in this selected workpaper. All integers are decimal strings. No file,
    /// journal or protected document is written/read by rendering. Verification,
    /// cancellation, output bound or allocation failure returns no partial text.
    pub fn roll_forward_jsonl(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &RollForwardCertificate,
        expected: &RollForwardRequest,
    ) -> Outcome<String> {
        if let Err(refusal) = authorize(self, cx, principal, capability, true)? {
            return Ok(Err(refusal));
        }
        let report =
            match self.replay_roll_forward_for(cx, principal, capability, certificate, expected)? {
                Ok(report) => report,
                Err(refusal) => return Ok(Err(refusal)),
            };
        match render(&report, certificate, &self.context().units, &cx.query()) {
            Ok(text) => Ok(Ok(text)),
            Err(ExportError::Refusal(refusal)) => Ok(Err(refusal)),
            Err(ExportError::Book(error)) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_text_escapes_control_characters_without_losing_unicode() {
        let mut text = String::new();
        quoted(&mut text, "€\"\\\n\r\t\0").unwrap();
        assert_eq!(text, "\"€\\\"\\\\\\n\\r\\t\\u0000\"");
    }

    #[test]
    fn complete_workpaper_bound_uses_checked_lengths() {
        assert_eq!(
            checked_len(MAX_ROLL_FORWARD_WORKPAPER_BYTES, 0).unwrap(),
            MAX_ROLL_FORWARD_WORKPAPER_BYTES
        );
        assert!(checked_len(MAX_ROLL_FORWARD_WORKPAPER_BYTES, 1).is_err());
        assert!(checked_len(usize::MAX, 1).is_err());
    }
}
