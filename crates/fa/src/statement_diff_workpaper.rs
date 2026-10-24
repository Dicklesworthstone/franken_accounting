//! Reviewable workpapers generated ONLY after both statement sources replay.
//!
//! JSONL preserves every exact amount, column, valuation basis and mapping change.
//! Markdown is an escaped presentation of the same rows. The retained binary
//! certificate travels beside them; it is not replaced by a checksum of text.
//! Identical certificates produce identical workpapers despite later postings.

use std::fmt::{self, Write as _};

use asupersync::fs::Vfs;
use fa_journal::Refusal;
use fa_policy::{Capability, Op};
use fgdb_types::VId;
use fgdb_types::context::PurposeContexts;

use crate::statement_diff::{StatementDiff, StatementDiffCertificate};
use crate::{AsyncBook, BookError, Outcome};

pub const MAX_STATEMENT_DIFF_WORKPAPER_BYTES: usize = 64 * 1024 * 1024;
const FORMAT: &str = "fa:statement-diff-workpaper:v1";

/// Three deterministic artifacts. No fields are caller-mutable, no amount is
/// rounded, and no source is selected from a workpaper's unsigned provenance.
/// Save all three: the text is for review, the certificate is for later replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementDiffWorkpaper {
    id: String,
    certificate: Vec<u8>,
    jsonl: String,
    markdown: String,
}

impl StatementDiffWorkpaper {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    #[must_use]
    pub fn certificate_bytes(&self) -> &[u8] {
        &self.certificate
    }
    #[must_use]
    pub fn jsonl(&self) -> &str {
        &self.jsonl
    }
    #[must_use]
    pub fn markdown(&self) -> &str {
        &self.markdown
    }
}

// fmt::Write checks the byte budget BEFORE each allocation-causing append.
// Formatting numbers is direct: even i128::MIN never passes through a float.
struct Text {
    bytes: String,
    limit: usize,
}
impl Text {
    fn new(limit: usize) -> Self {
        Self {
            bytes: String::new(),
            limit,
        }
    }
}
impl fmt::Write for Text {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if self
            .bytes
            .len()
            .checked_add(text.len())
            .is_none_or(|n| n > self.limit)
        {
            return Err(fmt::Error);
        }
        self.bytes.push_str(text);
        Ok(())
    }
}

fn quote(out: &mut Text, text: &str) -> fmt::Result {
    out.write_char('"')?;
    for c in text.chars() {
        match c {
            '"' => out.write_str("\\\"")?,
            '\\' => out.write_str("\\\\")?,
            '\n' => out.write_str("\\n")?,
            '\r' => out.write_str("\\r")?,
            '\t' => out.write_str("\\t")?,
            c if c <= '\u{1f}' => write!(out, "\\u{:04x}", u32::from(c))?,
            c => out.write_char(c)?,
        }
    }
    out.write_char('"')
}

fn strings(out: &mut Text, values: &[String]) -> fmt::Result {
    out.write_char('[')?;
    for (i, value) in values.iter().enumerate() {
        if i != 0 {
            out.write_char(',')?;
        }
        quote(out, value)?;
    }
    out.write_char(']')
}

fn amounts(out: &mut Text, values: &[i128]) -> fmt::Result {
    out.write_char('[')?;
    for (i, value) in values.iter().enumerate() {
        if i != 0 {
            out.write_char(',')?;
        }
        write!(out, "\"{value}\"")?;
    }
    out.write_char(']')
}

fn mapping(out: &mut Text, value: Option<&fa_statements::AccountMapping>) -> fmt::Result {
    let Some(value) = value else {
        return out.write_str("null");
    };
    write!(
        out,
        "{{\"account\":\"{:032x}\",\"account_type\":{},\"code\":",
        value.account.id, value.account.account_type
    )?;
    quote(out, &value.account.code)?;
    write!(out, ",\"is_leaf\":{},\"line\":", value.account.is_leaf)?;
    quote(out, &value.line_code)?;
    out.write_str(",\"name\":")?;
    quote(out, &value.account.name)?;
    out.write_char('}')
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn json(
    out: &mut Text,
    id: &str,
    diff: &StatementDiff,
    certificate: &StatementDiffCertificate,
) -> fmt::Result {
    let (before, after) = certificate.sources();
    write!(
        out,
        "{{\"book\":\"{}\",\"certificate\":\"{}\",\"definition\":",
        hex(&diff.book_id().0),
        hex(certificate.digest())
    )?;
    quote(out, &diff.before().definition_name)?;
    if let Some(unit) = diff.functional_unit() {
        // Numeric registry IDs match the existing line-unit contract. The
        // retained source certificates bind the historical unit registry.
        write!(
            out,
            ",\"functional\":true,\"base_unit\":{},\"valuation_basis\":\"retained-base-amounts\"",
            unit.0
        )?;
    }
    writeln!(
        out,
        ",\"definition_digest\":\"{}\",\"event\":\"manifest\",\"format\":\"{FORMAT}\",\"known_at_after\":\"{}\",\"known_at_before\":\"{}\",\"line_count\":{},\"mapping_changes\":{},\"scope\":\"retained_history_replay\",\"source_after\":\"{}\",\"source_before\":\"{}\",\"workpaper\":\"{id}\"}}",
        hex(&diff.before().definition_digest),
        after.known_at.0,
        before.known_at.0,
        diff.lines().len(),
        diff.mapping_changes().len(),
        hex(&after.digest),
        hex(&before.digest)
    )?;
    for (index, column) in diff.before().columns.iter().enumerate() {
        write!(out, "{{\"effective_from_day\":")?;
        match column.effective_from {
            Some(day) => write!(out, "{}", day.0)?,
            None => out.write_str("null")?,
        }
        write!(
            out,
            ",\"effective_through_day\":{},\"event\":\"column\",\"index\":{index},\"label\":",
            column.effective_through.0
        )?;
        quote(out, &column.label)?;
        out.write_str(",\"periods\":")?;
        strings(out, &column.periods)?;
        out.write_str("}\n")?;
    }
    for line in diff.lines() {
        out.write_str("{\"after_mantissas\":")?;
        amounts(out, &line.after)?;
        out.write_str(",\"before_mantissas\":")?;
        amounts(out, &line.before)?;
        out.write_str(",\"code\":")?;
        quote(out, &line.code)?;
        out.write_str(",\"delta_mantissas\":")?;
        amounts(out, &line.delta)?;
        out.write_str(",\"event\":\"line\",\"label\":")?;
        quote(out, &line.label)?;
        writeln!(out, ",\"unit\":{}}}", line.unit_id)?;
    }
    for change in diff.mapping_changes() {
        write!(
            out,
            "{{\"account\":\"{:032x}\",\"after\":",
            change.account_id
        )?;
        mapping(out, change.after.as_ref())?;
        out.write_str(",\"before\":")?;
        mapping(out, change.before.as_ref())?;
        out.write_str(",\"event\":\"mapping_change\"}\n")?;
    }
    Ok(())
}

// Source labels may contain Markdown/HTML. Render data, never active markup.
fn markdown_text(out: &mut Text, text: &str) -> fmt::Result {
    for c in text.chars() {
        match c {
            '&' => out.write_str("&amp;")?,
            '<' => out.write_str("&lt;")?,
            '>' => out.write_str("&gt;")?,
            '|' => out.write_str("&#124;")?,
            '\n' | '\r' => out.write_char(' ')?,
            '\\' | '`' | '*' | '_' | '[' | ']' | '!' | '#' => write!(out, "\\{c}")?,
            c if c.is_control() => write!(out, "\\u{{{:04x}}}", u32::from(c))?,
            c => out.write_char(c)?,
        }
    }
    Ok(())
}

fn markdown(
    out: &mut Text,
    id: &str,
    diff: &StatementDiff,
    certificate: &StatementDiffCertificate,
) -> fmt::Result {
    let (before, after) = certificate.sources();
    writeln!(
        out,
        "# Statement comparison\n\nWorkpaper: `{id}`\n\nBook: `{}`; known-at **{} → {}**.\n",
        hex(&diff.book_id().0),
        before.known_at.0,
        after.known_at.0
    )?;
    out.write_str("Definition: ")?;
    markdown_text(out, &diff.before().definition_name)?;
    let amounts_description = if diff.is_functional() {
        "Amounts below are exact functional base-unit integer mantissas from verified retained base amounts; no new rates or presentation rounding are applied."
    } else {
        "Amounts below are exact native-unit integer mantissas; no presentation rounding or cross-unit aggregation is applied."
    };
    writeln!(
        out,
        " (version {}).\n\nBoth sources were replayed against retained book history. This is not an assertion of issuance, case approval, signed authenticity, or economic truth.\n\n{amounts_description} All lines, including unchanged and zero lines, are shown. Do not sum subtotals as though they were disjoint accounts.\n",
        diff.before().definition_version
    )?;
    writeln!(
        out,
        "Comparison certificate: `{}`  \nBefore source: `{}`  \nAfter source: `{}`\n",
        hex(certificate.digest()),
        hex(&before.digest),
        hex(&after.digest)
    )?;
    for (index, column) in diff.before().columns.iter().enumerate() {
        write!(out, "## Column {}: ", index + 1)?;
        markdown_text(out, &column.label)?;
        out.write_str("\n\nPeriods: ")?;
        for (i, period) in column.periods.iter().enumerate() {
            if i != 0 {
                out.write_str(", ")?;
            }
            markdown_text(out, period)?;
        }
        match column.effective_from {
            Some(day) => write!(out, "; activity starts on civil day {}", day.0)?,
            None => out.write_str("; stock from inception")?,
        }
        let unit_label = if diff.is_functional() {
            "Base unit ID"
        } else {
            "Native unit ID"
        };
        writeln!(
            out,
            "; inclusive cutoff day {}.\n\n| Line | Description | {unit_label} | Before | After | Delta |\n| --- | --- | ---: | ---: | ---: | ---: |",
            column.effective_through.0
        )?;
        for line in diff.lines() {
            out.write_str("| ")?;
            markdown_text(out, &line.code)?;
            out.write_str(" | ")?;
            markdown_text(out, &line.label)?;
            writeln!(
                out,
                " | {} | {} | {} | {} |",
                line.unit_id, line.before[index], line.after[index], line.delta[index]
            )?;
        }
        out.write_char('\n')?;
    }
    out.write_str("## Account mapping changes\n\nThese changes include zero-balance accounts. They describe chart membership or metadata, not necessarily new postings.\n\n")?;
    if diff.mapping_changes().is_empty() {
        out.write_str("None.\n")?;
    } else {
        out.write_str("| Account ID | Change | Before code / name / line | After code / name / line |\n| --- | --- | --- | --- |\n")?;
        for c in diff.mapping_changes() {
            let change = match (&c.before, &c.after) {
                (None, _) => "Added",
                (_, None) => "Removed",
                _ => "Changed",
            };
            write!(out, "| {:032x} | {change} | ", c.account_id)?;
            for (i, mapping) in [c.before.as_ref(), c.after.as_ref()]
                .into_iter()
                .enumerate()
            {
                if i != 0 {
                    out.write_str(" | ")?;
                }
                if let Some(m) = mapping {
                    markdown_text(out, &m.account.code)?;
                    out.write_str(" / ")?;
                    markdown_text(out, &m.account.name)?;
                    out.write_str(" / ")?;
                    markdown_text(out, &m.line_code)?;
                } else {
                    out.write_str("—")?;
                }
            }
            out.write_str(" |\n")?;
        }
    }
    Ok(())
}

fn render(
    diff: &StatementDiff,
    certificate: &StatementDiffCertificate,
) -> Result<StatementDiffWorkpaper, Refusal> {
    let certificate_bytes = certificate.canonical_bytes()?;
    let remaining = MAX_STATEMENT_DIFF_WORKPAPER_BYTES
        .checked_sub(certificate_bytes.len())
        .ok_or_else(|| {
            crate::statement_diff::invalid(
                "statement workpaper exceeds its total 64 MiB byte bound",
            )
        })?;
    let id = format!(
        "FA-{}-WP-{}",
        hex(&diff.book_id().0),
        hex(certificate.digest())
    );
    let refusal = |_| {
        crate::statement_diff::invalid(
            "statement workpaper exceeds its total 64 MiB byte bound; no partial package is returned",
        )
    };
    let mut jsonl = Text::new(remaining);
    json(&mut jsonl, &id, diff, certificate).map_err(refusal)?;
    let mut md = Text::new(remaining - jsonl.bytes.len());
    markdown(&mut md, &id, diff, certificate).map_err(refusal)?;
    Ok(StatementDiffWorkpaper {
        id,
        certificate: certificate_bytes,
        jsonl: jsonl.bytes,
        markdown: md.bytes,
    })
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Replay first, then produce a bounded deterministic review package.
    /// Current read+produce authority is required before any book observation.
    /// Re-running later uses the saved source sequences and produces identical
    /// bytes. The caller owns saving/distributing these files; the book is not
    /// mutated and no unverified text is returned after a replay refusal.
    pub fn statement_diff_workpaper(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &StatementDiffCertificate,
    ) -> Outcome<StatementDiffWorkpaper> {
        let admitted = fa_policy::admit_read(capability, principal, self.context().book_id)
            .and_then(|()| {
                fa_policy::require(capability, Op::Produce, "exporting statement workpapers")
            });
        if let Err(denial) = admitted {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        // Replay rechecks current expiry/revocation before historical reads.
        // The operation above only adds the required production authority.
        let diff = match self.replay_statement_diff(cx, principal, capability, certificate)? {
            Ok(diff) => diff,
            Err(r) => return Ok(Err(r)),
        };
        let workpaper = render(&diff, certificate);
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(workpaper)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escapes_source_text_and_preserves_exact_integer_mantissas() {
        let mut out = Text::new(1000);
        quote(&mut out, "A\"\\\n\r\t\u{1f} 零").unwrap();
        assert_eq!(out.bytes, "\"A\\\"\\\\\\n\\r\\t\\u001f 零\"");
        let mut out = Text::new(1000);
        amounts(&mut out, &[0, -1, i128::MIN, i128::MAX]).unwrap();
        assert_eq!(
            out.bytes,
            format!("[\"0\",\"-1\",\"{}\",\"{}\"]", i128::MIN, i128::MAX)
        );
    }

    #[test]
    fn markdown_treats_source_labels_as_inert_table_data() {
        let mut out = Text::new(1000);
        markdown_text(&mut out, "<script>|[link](x)\n`cash` & \\ 零").unwrap();
        assert_eq!(
            out.bytes,
            "&lt;script&gt;&#124;\\[link\\](x) \\`cash\\` &amp; \\\\ 零"
        );
    }

    #[test]
    fn text_bound_is_enforced_before_the_failing_append() {
        let mut out = Text::new(4);
        out.write_str("1234").unwrap();
        assert!(out.write_str("5").is_err());
        assert_eq!(out.bytes, "1234");
        let mut out = Text::new(2);
        assert!(quote(&mut out, "\u{1f}").is_err());
        assert!(out.bytes.len() <= 2);
        let mut out = Text::new(0);
        assert!(out.write_char('x').is_err());
        assert!(out.bytes.is_empty());
    }
}
