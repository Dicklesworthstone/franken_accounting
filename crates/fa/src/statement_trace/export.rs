//! Deterministic JSONL delivery after complete retained-history replay.
//!
//! Every monetary mantissa and sequence is a decimal STRING, not a JSON float.
//! Record/unit/column identities and every entry digest remain explicit. This
//! exporter never opens protected descriptions, memos, or source documents.

use asupersync::fs::Vfs;
use fa_journal::Refusal;
use fa_model::EntryRef;
use fa_policy::Capability;
use fgdb_types::VId;
use fgdb_types::context::PurposeContexts;
use crate::{AsyncBook, BookError, Outcome, StatementLineChange, StatementMappingChange};
use crate::statement_trace::{StatementEntryEvent, StatementTrace};
use super::{StatementTraceCertificate, MAX_STATEMENT_TRACE_CERTIFICATE_BYTES, authorize, invalid};

struct Json {
    output: String,
    max_bytes: usize,
}
impl Json {
    fn new(max_bytes: usize) -> Self { Self { output: String::new(), max_bytes } }
    fn raw(&mut self, text: &str) -> Result<(), Refusal> {
        if self.output.len().checked_add(text.len()).is_none_or(|size| size > self.max_bytes) {
            return Err(invalid("statement trace JSONL exceeds its 64 MiB output bound"));
        }
        self.output.try_reserve(text.len()).map_err(|_| invalid("statement trace JSONL buffer allocation failed"))?;
        self.output.push_str(text);
        Ok(())
    }
    fn quoted(&mut self, text: &str) -> Result<(), Refusal> {
        self.raw("\"")?;
        for ch in text.chars() {
            match ch {
                '"' => self.raw("\\\"")?, '\\' => self.raw("\\\\")?,
                '\n' => self.raw("\\n")?, '\r' => self.raw("\\r")?, '\t' => self.raw("\\t")?,
                '\u{2028}' => self.raw("\\u2028")?, '\u{2029}' => self.raw("\\u2029")?,
                ch if ch <= '\u{1f}' => self.raw(&format!("\\u{:04x}", u32::from(ch)))?,
                ch => { let mut buffer = [0; 4]; self.raw(ch.encode_utf8(&mut buffer))?; }
            }
        }
        self.raw("\"")
    }
    fn begin(&mut self, kind: &str) -> Result<(), Refusal> {
        self.raw("{\"record_type\":")?; self.quoted(kind)
    }
    fn key(&mut self, key: &str) -> Result<(), Refusal> {
        self.raw(",")?; self.quoted(key)?; self.raw(":")
    }
    fn string(&mut self, key: &str, value: &str) -> Result<(), Refusal> {
        self.key(key)?; self.quoted(value)
    }
    fn boolean(&mut self, key: &str, value: bool) -> Result<(), Refusal> {
        self.key(key)?; self.raw(if value { "true" } else { "false" })
    }
    fn number(&mut self, key: &str, value: impl std::fmt::Display) -> Result<(), Refusal> {
        self.key(key)?; self.raw(&value.to_string())
    }
    fn end(&mut self) -> Result<(), Refusal> { self.raw("}\n") }
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
fn reference(out: &mut Json, reference: &EntryRef) -> Result<(), Refusal> {
    out.raw("{\"vid\":")?; out.quoted(&format!("{:032x}", reference.vid.0))?;
    out.string("entry_digest", &hex(&reference.entry_digest))?; out.raw("}")
}
fn line(out: &mut Json, kind: &str, sequence: Option<u64>, row: &StatementLineChange, column: usize) -> Result<(), Refusal> {
    out.begin(kind)?;
    if let Some(sequence) = sequence { out.string("recorded_at", &sequence.to_string())?; }
    out.string("line", &row.code)?; out.string("label", &row.label)?;
    out.number("unit_id", row.unit_id)?; out.number("column", column)?;
    out.string("before_mantissa", &row.before[column].to_string())?;
    out.string("after_mantissa", &row.after[column].to_string())?;
    out.string("delta_mantissa", &row.delta[column].to_string())?;
    out.end()
}
fn mapping(out: &mut Json, kind: &str, sequence: Option<u64>, change: &StatementMappingChange) -> Result<(), Refusal> {
    out.begin(kind)?;
    if let Some(sequence) = sequence { out.string("recorded_at", &sequence.to_string())?; }
    out.string("account_vid", &format!("{:032x}", change.account_id))?;
    for (name, value) in [("before", change.before.as_ref()), ("after", change.after.as_ref())] {
        out.key(name)?;
        if let Some(mapping) = value {
            out.raw("{\"code\":")?; out.quoted(&mapping.account.code)?;
            out.string("name", &mapping.account.name)?;
            out.number("account_type", mapping.account.account_type)?;
            out.boolean("is_leaf", mapping.account.is_leaf)?;
            out.string("line", &mapping.line_code)?; out.raw("}")?;
        } else { out.raw("null")?; }
    }
    out.end()
}

fn render(cx: &PurposeContexts, trace: &StatementTrace, certificate: &StatementTraceCertificate) -> Outcome<String> {
    let mut out = Json::new(MAX_STATEMENT_TRACE_CERTIFICATE_BYTES);
    // Preserve the facade's distinction between a bounded-output refusal and
    // cancellation/foundation failure without returning any partly built text.
    macro_rules! emit {
        ($operation:expr) => {
            if let Err(refusal) = $operation { return Ok(Err(refusal)); }
        };
    }
    let query = cx.query();
    query.checkpoint().map_err(BookError::Context)?;
    let summary = trace.summary();
    emit!(out.begin("statement_trace"));
    emit!(out.string("format", "fa:statement-trace-jsonl:v1"));
    emit!(out.string("certificate_digest", &hex(certificate.digest())));
    emit!(out.string("book_id", &summary.book_id().to_hex()));
    emit!(out.string("branch_id", &summary.before().branch_id.to_hex()));
    emit!(out.string("before", &summary.before().known_at.to_string()));
    emit!(out.string("after", &summary.after().known_at.to_string()));
    emit!(out.string("definition", &summary.before().definition_name));
    emit!(out.string("definition_digest", &hex(&summary.before().definition_digest)));
    emit!(out.string("scope", "retained-history-replay"));
    emit!(out.string("attribution", "atomic-publication; entry links are associated records, not individual causal allocations"));
    emit!(out.boolean("signed", false));
    emit!(out.boolean("case_approval_verified", false));
    emit!(out.boolean("outsider_completeness_verified", false));
    emit!(out.boolean("net_amounts_changed", summary.amounts_changed()));
    emit!(out.boolean("intermediate_changes", trace.had_changes()));
    emit!(out.end());
    for (index, column) in summary.before().columns.iter().enumerate() {
        query.checkpoint().map_err(BookError::Context)?;
        emit!(out.begin("column")); emit!(out.number("column", index));
        emit!(out.string("label", &column.label)); emit!(out.key("periods")); emit!(out.raw("["));
        for (index, period) in column.periods.iter().enumerate() {
            if index != 0 { emit!(out.raw(",")); } emit!(out.quoted(period));
        }
        emit!(out.raw("]")); emit!(out.key("effective_from_day"));
        match column.effective_from { Some(day) => emit!(out.raw(&day.0.to_string())), None => emit!(out.raw("null")) }
        emit!(out.number("effective_through_day", column.effective_through.0)); emit!(out.end());
    }
    for source in certificate.sources() {
        query.checkpoint().map_err(BookError::Context)?;
        emit!(out.begin("source")); emit!(out.string("known_at", &source.known_at.0.to_string()));
        emit!(out.string("certificate_digest", &hex(&source.digest))); emit!(out.end());
    }
    for row in summary.lines() {
        query.checkpoint().map_err(BookError::Context)?;
        for column in 0..row.delta.len() { emit!(line(&mut out, "net_line", None, row, column)); }
    }
    for change in summary.mapping_changes() {
        query.checkpoint().map_err(BookError::Context)?;
        emit!(mapping(&mut out, "net_mapping", None, change));
    }
    for step in trace.publications() {
        query.checkpoint().map_err(BookError::Context)?;
        emit!(out.begin("publication")); emit!(out.string("recorded_at", &step.recorded_at.0.to_string()));
        emit!(out.string("before_source_digest", &hex(&step.before_source_digest)));
        emit!(out.string("after_source_digest", &hex(&step.after_source_digest)));
        emit!(out.boolean("unchanged", step.is_unchanged())); emit!(out.number("entry_count", step.entries.len())); emit!(out.end());
        for entry in &step.entries {
            query.checkpoint().map_err(BookError::Context)?;
            emit!(out.begin("entry_link")); emit!(out.string("publication", &step.recorded_at.0.to_string()));
            emit!(out.string("event", match entry.event { StatementEntryEvent::Recorded => "recorded", StatementEntryEvent::BecameVisible => "became_visible" }));
            emit!(out.string("recorded_at", &entry.recorded_at.0.to_string()));
            emit!(out.key("entry")); emit!(reference(&mut out, &entry.entry_ref));
            emit!(out.number("class", entry.class.0)); emit!(out.string("principal", &format!("{:032x}", entry.principal.0)));
            emit!(out.key("posting_day"));
            match entry.posting_date { Some(day) => emit!(out.raw(&day.0.to_string())), None => emit!(out.raw("null")) }
            emit!(out.key("migration_run"));
            match entry.migration_run { Some(run) => emit!(out.quoted(&format!("{:032x}", run.0))), None => emit!(out.raw("null")) }
            emit!(out.key("references")); emit!(out.raw("["));
            for (index, target) in entry.references.iter().enumerate() {
                if index != 0 { emit!(out.raw(",")); } emit!(reference(&mut out, target));
            }
            emit!(out.raw("]")); emit!(out.end());
        }
        for row in &step.changes {
            query.checkpoint().map_err(BookError::Context)?;
            for column in 0..row.delta.len() { emit!(line(&mut out, "line_change", Some(step.recorded_at.0), row, column)); }
        }
        for change in &step.mapping_changes {
            query.checkpoint().map_err(BookError::Context)?;
            emit!(mapping(&mut out, "mapping_change", Some(step.recorded_at.0), change));
        }
    }
    query.checkpoint().map_err(BookError::Context)?;
    emit!(out.begin("complete")); emit!(out.number("publications", trace.publications().len()));
    emit!(out.number("sources", certificate.sources().len())); emit!(out.end());
    Ok(Ok(out.output))
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Replay every source and link under current read+produce authority, then
    /// return bounded exact JSONL. No bytes are returned after partial replay
    /// or output-bound failure. Saved certificate provenance grants no access.
    pub fn statement_trace_jsonl(&self, cx: &PurposeContexts, principal: VId, capability: &Capability,
        certificate: &StatementTraceCertificate) -> Outcome<String>
    {
        if let Err(r) = authorize(self, cx, principal, capability, true)? { return Ok(Err(r)); }
        let trace = match self.replay_statement_trace(cx, principal, capability, certificate)? {
            Ok(trace) => trace, Err(r) => return Ok(Err(r)),
        };
        render(cx, &trace, certificate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::statement_trace::acceptance::{Harness, PRINCIPAL, cap};

    #[test]
    fn json_escaping_preserves_unicode_without_injecting_records() {
        let mut out = Json::new(1024);
        out.quoted("a\"b\\c\n\r\t\0\u{1f}é\u{2028}\u{2029}").unwrap();
        assert_eq!(out.output, "\"a\\\"b\\\\c\\n\\r\\t\\u0000\\u001fé\\u2028\\u2029\"");
        assert!(!out.output.contains('\n'));
    }
    #[test]
    fn output_append_is_bounded_before_mutation_and_mantissas_are_strings() {
        let mut out = Json::new(2); out.raw("ab").unwrap();
        assert!(out.raw("c").is_err()); assert_eq!(out.output, "ab");
        let exact = (1i128 << 100) + 7;
        let row = StatementLineChange { code: "cash".into(), label: "cash".into(), unit_id: 1,
            before: vec![-exact], after: vec![0], delta: vec![exact] };
        let mut out = Json::new(4096); line(&mut out, "line_change", Some(u64::MAX), &row, 0).unwrap();
        assert!(out.output.contains(&format!("\"delta_mantissa\":\"{exact}\"")));
        assert!(out.output.contains("\"recorded_at\":\"18446744073709551615\""));
    }
    #[test]
    fn saved_trace_export_keeps_cancellation_and_every_zero_net_line_after_head_moves() {
        let mut h = Harness::new(); let before = h.head();
        h.post("plus", "2026-03-15", h.usd, ("cash", "sales"), 15, false);
        h.post("minus", "2026-03-15", h.usd, ("sales", "cash"), 15, false);
        let good = h.book.certify_statement_trace(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), &h.request(before, "balance-sheet")).unwrap().unwrap();
        let output = h.book.statement_trace_jsonl(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), &good.certificate).unwrap().unwrap();
        assert!(output.contains("\"net_amounts_changed\":false,\"intermediate_changes\":true"));
        assert!(output.contains("\"delta_mantissa\":\"15\""));
        assert!(output.contains("\"delta_mantissa\":\"-15\""));
        assert_eq!(output.lines().filter(|line| line.starts_with("{\"record_type\":\"net_line\"")).count(),
            good.report.summary().lines().len() * good.report.summary().before().columns.len());
        assert_eq!(output.lines().filter(|line| line.starts_with("{\"record_type\":\"entry_link\"")).count(), 2);
        assert!(output.ends_with("{\"record_type\":\"complete\",\"publications\":2,\"sources\":3}\n"));
        let mut h = h.reopen();
        h.post("later", "2026-03-20", h.usd, ("expense", "cash"), 3, false);
        let head = h.head();
        assert_eq!(h.book.statement_trace_jsonl(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), &good.certificate).unwrap().unwrap(), output);
        for ops in [&["read"][..], &["produce"][..], &["post"][..]] {
            let refusal = h.book.statement_trace_jsonl(&h.cx(), PRINCIPAL, &cap(ops), &good.certificate).unwrap().unwrap_err();
            assert_eq!(refusal.code, fa_journal::refusal::code::CAPABILITY);
        }
        assert_eq!(h.head(), head);
    }
    #[test]
    fn a_resealed_false_trace_is_not_exported_as_a_verified_workpaper() {
        let mut h = Harness::new(); let before = h.head();
        h.post("real", "2026-03-15", h.usd, ("cash", "sales"), 15, false);
        let good = h.book.certify_statement_trace(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), &h.request(before, "balance-sheet")).unwrap().unwrap();
        let mut forged = good.report; forged.publications[0].entries.clear();
        let certificate = StatementTraceCertificate::seal(good.certificate.sources.clone(), PRINCIPAL, [0; 32], forged.canonical_bytes().unwrap()).unwrap();
        let head = h.head();
        let refusal = h.book.statement_trace_jsonl(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), &certificate).unwrap().unwrap_err();
        assert_eq!(refusal.exit, fa_journal::exit::VERIFICATION);
        assert_eq!(h.head(), head);
    }
}
