//! Recipient-selected, replay-gated aging workpapers. This is an export of
//! historical accounting data, not an overdue notice or signed audit opinion.

use std::collections::BTreeSet;

use fa_journal::rows::AccountRow;
use fa_model::symbols::label;
use fa_money::{UnitId, UnitRegistry};

use super::*;

struct Jsonl {
    bytes: String,
    limit: usize,
}
impl Jsonl {
    fn new(limit: usize) -> Self {
        Self {
            bytes: String::new(),
            limit,
        }
    }
    fn push(&mut self, text: &str) -> Result<(), Refusal> {
        let next = self
            .bytes
            .len()
            .checked_add(text.len())
            .ok_or_else(|| invalid("aging workpaper length overflow"))?;
        if next > self.limit {
            return Err(invalid(
                "complete aging workpaper exceeds its output bound; no partial report returned",
            ));
        }
        self.bytes
            .try_reserve(text.len())
            .map_err(|_| invalid("cannot reserve aging workpaper output"))?;
        self.bytes.push_str(text);
        Ok(())
    }
    fn string(&mut self, text: &str) -> Result<(), Refusal> {
        self.push("\"")?;
        for c in text.chars() {
            match c {
                '"' => self.push("\\\"")?,
                '\\' => self.push("\\\\")?,
                '\n' => self.push("\\n")?,
                '\r' => self.push("\\r")?,
                '\t' => self.push("\\t")?,
                c if c < '\u{20}' => self.push(&format!("\\u{:04x}", u32::from(c)))?,
                c => {
                    let mut encoded = [0; 4];
                    self.push(c.encode_utf8(&mut encoded))?;
                }
            }
        }
        self.push("\"")
    }
    fn begin(&mut self, event: &str) -> Result<(), Refusal> {
        self.push("{\"event\":")?;
        self.string(event)
    }
    fn key(&mut self, name: &str) -> Result<(), Refusal> {
        self.push(",")?;
        self.string(name)?;
        self.push(":")
    }
    fn text(&mut self, name: &str, text: &str) -> Result<(), Refusal> {
        self.key(name)?;
        self.string(text)
    }
    // All integer values use strings, even currently-small counters. Consumers
    // never need to guess which sequence or money field can exceed 2^53.
    fn number(&mut self, name: &str, number: impl core::fmt::Display) -> Result<(), Refusal> {
        self.text(name, &number.to_string())
    }
    fn boolean(&mut self, name: &str, value: bool) -> Result<(), Refusal> {
        self.key(name)?;
        self.push(if value { "true" } else { "false" })
    }
    fn null(&mut self, name: &str) -> Result<(), Refusal> {
        self.key(name)?;
        self.push("null")
    }
    fn end(&mut self) -> Result<(), Refusal> {
        self.push("}\n")
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn vid(id: VId) -> String {
    format!("{:032x}", id.0)
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
    report: &EffectiveDateAging,
    certificate: &AgingCertificate,
    accounts: &[AccountRow],
    units: &UnitRegistry,
    mut checkpoint: impl FnMut() -> Result<(), BookError>,
) -> Result<String, ExportError> {
    let mut out = Jsonl::new(MAX_AGING_CERTIFICATE_BYTES);
    out.begin("aging_workpaper")?;
    out.text("format", "fa:aging-workpaper:v1")?;
    out.text("scope", "retained_history_effective_date_aging")?;
    out.text("book_id", &hex(&report.book_id.0))?;
    out.number("known_at", report.known_at.0)?;
    out.text("effective_through", &report.effective_through.to_string())?;
    if let Some(account) = report.account {
        out.text("account_filter", &vid(account))?;
    } else {
        out.null("account_filter")?;
    }
    out.text("age_basis", "effective_date")?;
    out.boolean("due_date_claim", false)?;
    out.text("signatures", "unsigned")?;
    out.text("certificate_digest", &hex(certificate.digest()))?;
    out.text("source_digest", &hex(&certificate.source.digest))?;
    out.text("journal_root", &hex(&certificate.source.journal_root))?;
    out.number("journal_leaves", certificate.source.journal_leaves)?;
    out.text("producer", &vid(certificate.producer()))?;
    out.end()?;
    for account in accounts {
        checkpoint()?;
        out.begin("aging_account")?;
        out.text("account", &vid(account.vid))?;
        out.text("code", &account.code)?;
        out.text("name", &account.name)?;
        out.number("account_type", account.account_type)?;
        out.number("normal_balance", account.normal_balance)?;
        out.number("created_at", account.created_at.0)?;
        out.end()?;
    }
    let unit_ids: BTreeSet<_> = report.items.iter().map(|item| item.item.unit_id).collect();
    for id in unit_ids {
        checkpoint()?;
        let unit = units
            .get(UnitId(id))
            .ok_or_else(|| invalid("aging workpaper names an unregistered unit"))?;
        out.begin("aging_unit")?;
        out.number("unit_id", id)?;
        out.text("code", &unit.code)?;
        out.number("scale", unit.scale)?;
        out.number("version", unit.version)?;
        out.end()?;
    }
    for (index, band) in report.bands.iter().enumerate() {
        checkpoint()?;
        out.begin("aging_band")?;
        out.number("bucket", index)?;
        out.number("lower_inclusive", band.lower_inclusive)?;
        if let Some(upper) = band.upper_inclusive {
            out.number("upper_inclusive", upper)?;
        } else {
            out.null("upper_inclusive")?;
        }
        out.end()?;
    }
    for aged in &report.items {
        checkpoint()?;
        let item = &aged.item;
        out.begin("aged_open_item")?;
        out.text("entry", &vid(item.entry))?;
        out.number("ordinal", item.ordinal)?;
        out.text("account", &vid(item.account))?;
        out.number("unit_id", item.unit_id)?;
        out.text(
            "side",
            match item.side {
                Side::Debit => "debit",
                Side::Credit => "credit",
            },
        )?;
        out.text("effective_date", &item.effective_date.to_string())?;
        out.number("recorded_at", item.recorded_at.0)?;
        out.number("age_days", aged.age_days)?;
        out.number("bucket", aged.bucket)?;
        out.number("original_mantissa", item.original)?;
        out.number("applied_mantissa", item.applied)?;
        out.number("applied_out_mantissa", item.applied_out)?;
        out.number("open_mantissa", item.open)?;
        out.number("application_count", item.applications.len())?;
        out.end()?;
        for application in &item.applications {
            checkpoint()?;
            out.begin("aging_application")?;
            out.text("target_entry", &vid(item.entry))?;
            out.number("target_ordinal", item.ordinal)?;
            out.text("entry", &vid(application.entry))?;
            out.number("ordinal", application.ordinal)?;
            out.number("recorded_at", application.recorded_at.0)?;
            out.number("amount_mantissa", application.amount)?;
            out.boolean("live", application.live)?;
            out.end()?;
        }
    }
    for cell in &report.cells {
        checkpoint()?;
        out.begin("aging_cell")?;
        out.text("account", &vid(cell.account))?;
        out.number("unit_id", cell.unit_id)?;
        out.number("bucket", cell.bucket)?;
        out.number("debit_mantissa", cell.amounts.debits)?;
        out.number("credit_mantissa", cell.amounts.credits)?;
        out.number("item_count", cell.amounts.item_count)?;
        out.end()?;
    }
    for total in &report.totals {
        checkpoint()?;
        out.begin("aging_total")?;
        out.text("account", &vid(total.account))?;
        out.number("unit_id", total.unit_id)?;
        out.number("debit_mantissa", total.amounts.debits)?;
        out.number("credit_mantissa", total.amounts.credits)?;
        out.number("item_count", total.amounts.item_count)?;
        out.end()?;
    }
    checkpoint()?;
    Ok(out.bytes)
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Replay only the exact recipient-selected account, cutoff, recorded
    /// sequence and buckets. An unresolved HEAD expectation is refused rather
    /// than letting an untrusted certificate choose the recipient's question.
    pub fn replay_effective_date_aging_for(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &AgingCertificate,
        expected: &AgingRequest,
    ) -> Outcome<EffectiveDateAging> {
        if let Err(r) = authorize(
            self,
            cx,
            principal,
            capability,
            Some(certificate.source.known_at),
            false,
        )? {
            return Ok(Err(r));
        }
        if expected.known_at.is_none() {
            return Ok(Err(invalid_request(
                "recipient aging expectations require a fixed known-at, not HEAD",
            )));
        }
        if let Err(r) = bounded_buckets(&expected.buckets) {
            return Ok(Err(r));
        }
        let actual = match certificate.request() {
            Ok(request) => request,
            Err(r) => return Ok(Err(r)),
        };
        if actual != *expected {
            return Ok(Err(invalid(
                "aging certificate answers a different recipient-selected question",
            )));
        }
        self.replay_effective_date_aging(cx, principal, capability, certificate)
    }

    /// Export exact JSONL only after recipient binding and complete replay.
    /// Current read+produce is required. Account names come from the certified
    /// historical native Account closure, not from HEAD or an all-time item
    /// table that can omit an account whose last item was later reversed.
    /// Numbers are decimal strings; no cross-unit or debit/credit netting occurs.
    /// This returns no partial text on cancellation, refusal or output failure.
    pub fn effective_date_aging_jsonl(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &AgingCertificate,
        expected: &AgingRequest,
    ) -> Outcome<String> {
        if let Err(r) = authorize(
            self,
            cx,
            principal,
            capability,
            Some(certificate.source.known_at),
            true,
        )? {
            return Ok(Err(r));
        }
        let report = match self.replay_effective_date_aging_for(
            cx,
            principal,
            capability,
            certificate,
            expected,
        )? {
            Ok(report) => report,
            Err(r) => return Ok(Err(r)),
        };
        let mut ids: BTreeSet<_> = report.items.iter().map(|item| item.item.account).collect();
        if let Some(account) = report.account {
            ids.insert(account);
        }
        let query = cx.query();
        let accounts = query.with_restriction(|| -> Result<Vec<AccountRow>, BookError> {
            let mut accounts = Vec::new();
            for id in ids {
                query.checkpoint().map_err(BookError::Context)?;
                let row = self
                    .db
                    .vertex_at(id, report.known_at)
                    .map_err(KernelError::from)?
                    .filter(|row| row.labels.contains(&label::ACCOUNT))
                    .ok_or_else(|| {
                        KernelError::Corrupt(
                            "certified aging account is absent at its prefix".into(),
                        )
                    })?;
                accounts.push(AccountRow::decode(&row)?);
            }
            Ok(accounts)
        })?;
        match render(
            &report,
            certificate,
            &accounts,
            &self.context().units,
            || query.checkpoint().map_err(BookError::Context),
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
    fn json_strings_escape_controls_without_losing_unicode_or_integer_digits() {
        let mut out = Jsonl::new(4096);
        out.begin("test").unwrap();
        out.text("value", "€\"\\\n\r\t\0\u{1f}").unwrap();
        out.number("mantissa", i128::MAX).unwrap();
        out.number("sequence", u64::MAX).unwrap();
        out.end().unwrap();
        assert!(out.bytes.contains("€\\\"\\\\\\n\\r\\t\\u0000\\u001f"));
        assert!(
            out.bytes
                .contains(&format!("\"mantissa\":\"{}\"", i128::MAX))
        );
        assert!(
            out.bytes
                .contains(&format!("\"sequence\":\"{}\"", u64::MAX))
        );
        assert_eq!(out.bytes.lines().count(), 1);
    }

    #[test]
    fn output_bounds_count_encoded_utf8_and_escape_bytes_before_each_append() {
        let mut out = Jsonl::new(3);
        out.push("€").unwrap();
        assert!(out.push("x").is_err());
        assert_eq!(out.bytes, "€");
        let mut out = Jsonl::new(4);
        assert!(out.string("\0").is_err());
        assert!(out.bytes.len() <= 4);
        let mut out = Jsonl::new(8);
        out.string("\0").unwrap();
        assert_eq!(out.bytes, "\"\\u0000\"");
    }
}
