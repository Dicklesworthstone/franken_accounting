//! Deterministic review text and a portable replay package for recorded findings.
//! The immutable run's native publication sequence supplies the workpaper number.
//! The complete original procedure certificate travels with the text. Decoding
//! checks framing and integrity only; replay must check the original book too.

use std::fmt::{self, Write as _};

use super::*;
use fa_model::Reader;

pub const FINDING_WORKPAPER_FORMAT: &[u8] = b"fa:finding-workpaper:v1";
pub const MAX_FINDING_WORKPAPER_BYTES: usize = 64 * 1024 * 1024;
const DOMAIN: &[u8] = b"fa:finding-workpaper-digest:v1";

/// Source-preserving review package. The JSONL contains exact integers as strings,
/// full typed citation order and deterministic parameters; Markdown escapes data.
/// No public constructor accepts a graph row, modified report or caller numbering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingWorkpaper {
    id: String,
    recorded_at: CommitSeq,
    certificate: Vec<u8>,
    jsonl: String,
    markdown: String,
    digest: [u8; 32],
}

impl FindingWorkpaper {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    #[must_use]
    pub fn recorded_at(&self) -> CommitSeq {
        self.recorded_at
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
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    fn body(&self) -> Result<Vec<u8>, Refusal> {
        let size = [
            self.id.len(),
            self.certificate.len(),
            self.jsonl.len(),
            self.markdown.len(),
        ]
        .into_iter()
        .try_fold(128usize, |n, v| n.checked_add(v));
        if size.is_none_or(|n| n > MAX_FINDING_WORKPAPER_BYTES) {
            return Err(invalid(
                "finding workpaper exceeds the 64 MiB complete-package bound",
            ));
        }
        let mut w = Writer::new();
        w.bytes(FINDING_WORKPAPER_FORMAT)
            .str(&self.id)
            .u64(self.recorded_at.0)
            .bytes(&self.certificate)
            .str(&self.jsonl)
            .str(&self.markdown);
        encoded(w)
    }

    /// Integrity transport only. A recipient must replay, not trust this digest.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut bytes = self.body()?;
        if domain_digest(DOMAIN, &[&bytes]) != self.digest {
            return Err(invalid("finding workpaper content digest does not match"));
        }
        bytes.extend_from_slice(&self.digest);
        Ok(bytes)
    }

    /// Bounded decode never certifies the displayed findings or the run number.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_FINDING_WORKPAPER_BYTES {
            return Err(invalid("finding workpaper too large"));
        }
        let fail = |e| invalid(format!("finding workpaper decoding: {e}"));
        let mut r = Reader::new(bytes);
        if r.bytes(64, "workpaper format").map_err(fail)? != FINDING_WORKPAPER_FORMAT {
            return Err(invalid("unsupported finding workpaper format"));
        }
        let id = r.str(128, "workpaper id").map_err(fail)?.to_string();
        let recorded_at = CommitSeq(r.u64("workpaper publication").map_err(fail)?);
        let certificate = r
            .bytes(MAX_FINDING_WORKPAPER_BYTES, "procedure certificate")
            .map_err(fail)?
            .to_vec();
        let jsonl = r
            .str(MAX_FINDING_WORKPAPER_BYTES, "workpaper JSONL")
            .map_err(fail)?
            .to_string();
        let markdown = r
            .str(MAX_FINDING_WORKPAPER_BYTES, "workpaper Markdown")
            .map_err(fail)?
            .to_string();
        let digest = r.fixed::<32>("workpaper digest").map_err(fail)?;
        r.finish().map_err(fail)?;
        let result = Self {
            id,
            recorded_at,
            certificate,
            jsonl,
            markdown,
            digest,
        };
        let source = ProcedureCertificate::decode(&result.certificate)?;
        if result.recorded_at <= source.known_at()
            || result.id != number(source.book_id(), result.recorded_at)
        {
            return Err(invalid(
                "finding workpaper number does not match its claimed book/publication",
            ));
        }
        if result.canonical_bytes()? != bytes {
            return Err(invalid("noncanonical finding workpaper"));
        }
        Ok(result)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn number(book: Id128, seq: CommitSeq) -> String {
    format!("FA-{}-WP-{}", hex(&book.0), seq.0)
}

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
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self
            .bytes
            .len()
            .checked_add(value.len())
            .is_none_or(|n| n > self.limit)
        {
            return Err(fmt::Error);
        }
        self.bytes.push_str(value);
        Ok(())
    }
}
fn quote(out: &mut Text, value: &str) -> fmt::Result {
    out.write_char('"')?;
    for c in value.chars() {
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
fn inert(out: &mut Text, value: &str) -> fmt::Result {
    for c in value.chars() {
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

fn cite_json(out: &mut Text, cite: &Cite) -> fmt::Result {
    match cite {
        Cite::Entry(v) => write!(out, "{{\"kind\":\"entry\",\"vid\":\"{:032x}\"}}", v.0),
        Cite::Account(v) => write!(out, "{{\"kind\":\"account\",\"vid\":\"{:032x}\"}}", v.0),
        Cite::Principal(v) => write!(out, "{{\"kind\":\"principal\",\"vid\":\"{:032x}\"}}", v.0),
        Cite::Approval(v) => write!(out, "{{\"kind\":\"approval\",\"vid\":\"{:032x}\"}}", v.0),
        Cite::Attestation(v) => {
            write!(out, "{{\"kind\":\"attestation\",\"vid\":\"{:032x}\"}}", v.0)
        }
        Cite::Document(oid) => write!(out, "{{\"kind\":\"document\",\"oid\":\"{}\"}}", hex(&oid.0)),
        Cite::Leg { entry, ordinal } => write!(
            out,
            "{{\"kind\":\"leg\",\"entry\":\"{:032x}\",\"ordinal\":{ordinal}}}",
            entry.0
        ),
        Cite::Period(code) => {
            out.write_str("{\"kind\":\"period\",\"code\":")?;
            quote(out, code)?;
            out.write_char('}')
        }
    }
}
fn cite_markdown(out: &mut Text, cite: &Cite) -> fmt::Result {
    match cite {
        Cite::Entry(v) => write!(out, "Entry {:032x}", v.0),
        Cite::Account(v) => write!(out, "Account {:032x}", v.0),
        Cite::Principal(v) => write!(out, "Principal {:032x}", v.0),
        Cite::Approval(v) => write!(out, "Approval {:032x}", v.0),
        Cite::Attestation(v) => write!(out, "Attestation {:032x}", v.0),
        Cite::Document(oid) => write!(out, "Document {}", hex(&oid.0)),
        Cite::Leg { entry, ordinal } => write!(out, "Leg {:032x}/{ordinal}", entry.0),
        Cite::Period(code) => {
            out.write_str("Period ")?;
            inert(out, code)
        }
    }
}

fn json(out: &mut Text, id: &str, run: &RecordedFindings) -> fmt::Result {
    let report = &run.report;
    write!(
        out,
        "{{\"event\":\"manifest\",\"format\":\"fa:finding-workpaper:v1\",\"workpaper\":\"{id}\",\"book\":\"{}\",\"run_vid\":\"{:032x}\",\"recorded_at\":\"{}\",\"known_at\":\"{}\",\"effective_through\":",
        hex(&report.coordinate.book_id.0),
        run.run_vid.0,
        run.recorded_at.0,
        report.coordinate.known_at.0
    )?;
    match report.coordinate.effective_through {
        Some(day) => quote(out, &day.render())?,
        None => out.write_str("null")?,
    }
    out.write_str(",\"procedure\":")?;
    quote(out, &report.procedure)?;
    write!(out, ",\"version\":{},\"claim\":", report.version)?;
    quote(out, report.claim.name())?;
    writeln!(
        out,
        ",\"producer\":\"{:032x}\",\"certificate\":\"{}\",\"parameters_digest\":\"{}\",\"inputs_digest\":\"{}\",\"findings_digest\":\"{}\",\"decision_card_digest\":\"{}\",\"finding_count\":{},\"population\":\"{}\",\"scope\":\"retained_history_replay\"}}",
        run.producer.0,
        hex(&run.certificate_digest),
        hex(&report.parameters_digest),
        hex(&report.inputs_digest),
        hex(&report.findings_digest),
        hex(&report.decision_card_digest),
        report.findings.len(),
        report.population
    )?;
    for (name, value) in &report.parameters {
        out.write_str("{\"event\":\"parameter\",\"name\":")?;
        quote(out, name)?;
        writeln!(out, ",\"value\":\"{value}\"}}")?;
    }
    for (name, value) in &report.inputs {
        out.write_str("{\"event\":\"input\",\"name\":")?;
        quote(out, name)?;
        out.write_str(",\"value\":")?;
        quote(out, value)?;
        out.write_str("}\n")?;
    }
    writeln!(
        out,
        "{{\"event\":\"work\",\"entries\":\"{}\",\"legs\":\"{}\",\"comparisons\":\"{}\"}}",
        report.work.entries, report.work.legs, report.work.comparisons
    )?;
    for (ordinal, (vid, finding)) in run.finding_ids.iter().zip(&report.findings).enumerate() {
        write!(
            out,
            "{{\"event\":\"finding\",\"ordinal\":{ordinal},\"vid\":\"{:032x}\",\"observation_state\":\"Open\",\"severity\":",
            vid.0
        )?;
        quote(out, finding.severity.name())?;
        out.write_str(",\"statistic\":")?;
        quote(out, &finding.statistic.name)?;
        write!(
            out,
            ",\"value\":\"{}\",\"scale\":{},\"population\":\"{}\",\"narrative\":",
            finding.statistic.value, finding.statistic.scale, finding.statistic.population
        )?;
        quote(out, &finding.narrative)?;
        out.write_str(",\"cites\":[")?;
        for (i, cite) in finding.cites.iter().enumerate() {
            if i != 0 {
                out.write_char(',')?;
            }
            cite_json(out, cite)?;
        }
        out.write_str("]}\n")?;
    }
    Ok(())
}

fn markdown(out: &mut Text, id: &str, run: &RecordedFindings) -> fmt::Result {
    let report = &run.report;
    writeln!(
        out,
        "# Finding workpaper\n\nWorkpaper: `{id}`\n\nBook: `{}`; run: `{:032x}`; publication sequence: **{}**.\n\nSource known-at: **{}**; effective cutoff: **{}**.\n\nCertificate: `{}`\n",
        hex(&report.coordinate.book_id.0),
        run.run_vid.0,
        run.recorded_at.0,
        report.coordinate.known_at.0,
        report
            .coordinate
            .effective_through
            .map_or_else(|| "all".into(), |day| day.render()),
        hex(&run.certificate_digest)
    )?;
    out.write_str("Procedure: ")?;
    inert(out, &report.procedure)?;
    write!(out, " (version {}, claim ", report.version)?;
    inert(out, report.claim.name())?;
    writeln!(
        out,
        "). Population: {}.\n\nThese are original Open observations, not human review decisions, accusations, legal conclusions, or an offline proof. The original complete certificate must accompany this text for replay. A later backdated posting does not change the saved source coordinate.\n\nValues below are exact integer statistics at their stated scale. Do not sum unrelated scores, units, overlapping populations, or intermediate path citations. JSONL retains all ordered typed references, including repeats.\n",
        report.population
    )?;
    out.write_str("## Parameters and source handles\n\n")?;
    for (name, value) in &report.parameters {
        inert(out, name)?;
        writeln!(out, " = {value}  ")?;
    }
    for (name, value) in &report.inputs {
        inert(out, name)?;
        out.write_str(" = ")?;
        inert(out, value)?;
        out.write_str("  \n")?;
    }
    if report.findings.is_empty() {
        out.write_str("\nNo observations were emitted by this complete recorded run. This does not assert the absence of matters outside its scope.\n")?;
    }
    for (i, (vid, finding)) in run.finding_ids.iter().zip(&report.findings).enumerate() {
        writeln!(out, "\n## Observation {}: {:032x}\n", i + 1, vid.0)?;
        inert(out, finding.severity.name())?;
        out.write_str("; ")?;
        inert(out, &finding.statistic.name)?;
        writeln!(
            out,
            " = **{}**, scale {}, population {}.\n",
            finding.statistic.value, finding.statistic.scale, finding.statistic.population
        )?;
        inert(out, &finding.narrative)?;
        out.write_str("\n\nOrdered references:\n\n")?;
        for (n, cite) in finding.cites.iter().enumerate() {
            write!(out, "{}. ", n + 1)?;
            cite_markdown(out, cite)?;
            out.write_char('\n')?;
        }
    }
    Ok(())
}

fn render(run: &RecordedFindings, certificate: Vec<u8>) -> Result<FindingWorkpaper, Refusal> {
    let limit = MAX_FINDING_WORKPAPER_BYTES
        .checked_sub(certificate.len())
        .and_then(|n| n.checked_sub(1024))
        .ok_or_else(|| invalid("finding workpaper exceeds the total byte bound"))?;
    let id = number(run.report.coordinate.book_id, run.recorded_at);
    let refusal =
        |_| invalid("finding workpaper exceeds the total byte bound; no partial package returned");
    let mut jsonl = Text::new(limit);
    json(&mut jsonl, &id, run).map_err(refusal)?;
    let mut md = Text::new(limit - jsonl.bytes.len());
    markdown(&mut md, &id, run).map_err(refusal)?;
    let mut result = FindingWorkpaper {
        id,
        recorded_at: run.recorded_at,
        certificate,
        jsonl: jsonl.bytes,
        markdown: md.bytes,
        digest: [0; 32],
    };
    result.digest = domain_digest(DOMAIN, &[&result.body()?]);
    Ok(result)
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Export after reopening under current read+produce authority and the
    /// retained procedure's additional admission, before loading bank history.
    pub async fn finding_workpaper_with_history(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        digest: &[u8; 32],
    ) -> Outcome<FindingWorkpaper> {
        if let Err(r) = authorize(self, cx, principal, capability, true)? {
            return Ok(Err(r));
        }
        if let Err(r) = self
            .prepare_retained_procedure_history(cx, principal, capability, digest)
            .await?
        {
            return Ok(Err(r));
        }
        self.finding_workpaper(cx, principal, capability, digest)
            .await
    }

    /// Export a complete immutable observation run, after native replay and
    /// graph-integrity verification, under current whole-book read+produce scope.
    /// Does not publish a new vertex, renumber the run, or redact/truncate citations.
    pub async fn finding_workpaper(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        digest: &[u8; 32],
    ) -> Outcome<FindingWorkpaper> {
        if let Err(r) = authorize(self, cx, principal, capability, true)? {
            return Ok(Err(r));
        }
        let run = match self
            .read_findings(cx, principal, capability, digest)
            .await?
        {
            Ok(r) => r,
            Err(r) => return Ok(Err(r)),
        };
        let artifact = match self
            .read_report_artifact(cx, principal, capability, digest)
            .await?
        {
            Ok(a) => a,
            Err(r) => return Ok(Err(r)),
        };
        let bytes = match artifact.canonical_bytes() {
            Ok(b) => b,
            Err(r) => return Ok(Err(r)),
        };
        let result = render(&run, bytes);
        if let Err(r) = authorize(self, cx, principal, capability, true)? {
            return Ok(Err(r));
        }
        Ok(result)
    }

    /// Replay an observation package after reopening. Package framing and the
    /// admitted retained certificate identify the procedure; bank authority is
    /// required before its native history is loaded or its observations returned.
    pub async fn replay_finding_workpaper_with_history(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        bytes: &[u8],
    ) -> Outcome<RecordedFindings> {
        if let Err(r) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(r));
        }
        let saved = match FindingWorkpaper::decode(bytes) {
            Ok(saved) => saved,
            Err(r) => return Ok(Err(r)),
        };
        let certificate = match ProcedureCertificate::decode(&saved.certificate) {
            Ok(certificate) => certificate,
            Err(r) => return Ok(Err(r)),
        };
        if let Err(r) = self
            .prepare_retained_procedure_history(cx, principal, capability, certificate.digest())
            .await?
        {
            return Ok(Err(r));
        }
        self.replay_finding_workpaper(cx, principal, capability, bytes)
            .await
    }

    /// Recompute the complete package from the retained certificate and original
    /// native run. A rehashed but altered narrative, statistic, source or number
    /// cannot pass. Decoding alone is never returned as a successful replay.
    pub async fn replay_finding_workpaper(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        bytes: &[u8],
    ) -> Outcome<RecordedFindings> {
        if let Err(r) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(r));
        }
        let saved = match FindingWorkpaper::decode(bytes) {
            Ok(s) => s,
            Err(r) => return Ok(Err(r)),
        };
        let certificate = match ProcedureCertificate::decode(&saved.certificate) {
            Ok(c) => c,
            Err(r) => return Ok(Err(r)),
        };
        let run = match self
            .read_findings(cx, principal, capability, certificate.digest())
            .await?
        {
            Ok(r) => r,
            Err(r) => return Ok(Err(r)),
        };
        let actual = match render(&run, saved.certificate.clone()) {
            Ok(a) => a,
            Err(r) => return Ok(Err(r)),
        };
        if actual != saved {
            return Ok(Err(invalid(
                "finding workpaper text or original publication does not replay",
            )));
        }
        if let Err(r) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(r));
        }
        Ok(Ok(run))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn presentation_escapes_data_and_never_rounds_signed_boundaries() {
        let mut text = Text::new(1024);
        quote(&mut text, "\"\\\n\r\t\u{1f} 零").unwrap();
        assert_eq!(text.bytes, "\"\\\"\\\\\\n\\r\\t\\u001f 零\"");
        let mut text = Text::new(1024);
        inert(&mut text, "<script>|[x](y)\n`cash` &").unwrap();
        assert_eq!(
            text.bytes,
            "&lt;script&gt;&#124;\\[x\\](y) \\`cash\\` &amp;"
        );
        let mut text = Text::new(1024);
        write!(text, "\"{}\" \"{}\"", i128::MIN, i128::MAX).unwrap();
        assert_eq!(
            text.bytes,
            "\"-170141183460469231731687303715884105728\" \"170141183460469231731687303715884105727\""
        );
    }
    #[test]
    fn output_bound_precedes_each_append_and_unknown_frames_are_refused() {
        let mut text = Text::new(4);
        text.write_str("1234").unwrap();
        assert!(text.write_char('5').is_err());
        assert_eq!(text.bytes, "1234");
        for bytes in [b"".as_slice(), b"fa:finding-workpaper:v2", &[255; 32]] {
            assert!(FindingWorkpaper::decode(bytes).is_err());
        }
    }
}
