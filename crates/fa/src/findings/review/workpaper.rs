//! A source-preserving workpaper plus the complete human review timeline at an
//! explicit native cutoff. Original observations keep their v1 bytes and number;
//! this separate review revision never rewrites or reclassifies those findings.
//! A decoded package has content integrity only. Replay requires the retained
//! original book and current read authority, and checks later damage as well.

use std::fmt::{self, Write as _};

use super::*;

mod delivery;
pub use delivery::FindingReviewExpectation;

pub const FINDING_REVIEW_WORKPAPER_FORMAT: &[u8] = b"fa:finding-review-workpaper:v1";
pub const MAX_FINDING_REVIEW_WORKPAPER_BYTES: usize = 64 * 1024 * 1024;
const DOMAIN: &[u8] = b"fa:finding-review-workpaper-digest:v1";

/// Complete original workpaper and separately labeled review appendices. The
/// appendices alone are not a complete finding export. Private construction
/// prevents a caller's edited review rows from acquiring verification status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingReviewWorkpaper {
    id: String,
    review_known_at: CommitSeq,
    original: FindingWorkpaper,
    jsonl: String,
    markdown: String,
    digest: [u8; 32],
}

impl FindingReviewWorkpaper {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    #[must_use]
    pub fn review_known_at(&self) -> CommitSeq {
        self.review_known_at
    }
    #[must_use]
    pub fn observation_workpaper(&self) -> &FindingWorkpaper {
        &self.original
    }
    #[must_use]
    pub fn review_jsonl(&self) -> &str {
        &self.jsonl
    }
    #[must_use]
    pub fn review_markdown(&self) -> &str {
        &self.markdown
    }
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    fn body(&self) -> Result<Vec<u8>, Refusal> {
        let original = self.original.canonical_bytes()?;
        let size = [
            self.id.len(),
            original.len(),
            self.jsonl.len(),
            self.markdown.len(),
        ]
        .into_iter()
        .try_fold(256usize, |n, v| n.checked_add(v));
        if size.is_none_or(|n| n > MAX_FINDING_REVIEW_WORKPAPER_BYTES) {
            return Err(invalid(
                "review workpaper exceeds the complete-package bound",
            ));
        }
        let mut w = Writer::new();
        w.bytes(FINDING_REVIEW_WORKPAPER_FORMAT)
            .str(&self.id)
            .u64(self.review_known_at.0)
            .bytes(&original)
            .str(&self.jsonl)
            .str(&self.markdown);
        encoded(w)
    }

    /// Transport integrity only: a public checksum is not a native replay.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut bytes = self.body()?;
        if domain_digest(DOMAIN, &[&bytes]) != self.digest {
            return Err(invalid(
                "review workpaper checksum differs from its contents",
            ));
        }
        bytes.extend_from_slice(&self.digest);
        Ok(bytes)
    }

    /// Validate bounded framing, the nested original package and the two native
    /// coordinates. The displayed decisions are deliberately not trusted here.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_FINDING_REVIEW_WORKPAPER_BYTES || bytes.len() < 32 {
            return Err(invalid(
                "review workpaper is truncated or exceeds its bound",
            ));
        }
        let body_end = bytes.len() - 32;
        if domain_digest(DOMAIN, &[&bytes[..body_end]]).as_slice() != &bytes[body_end..] {
            return Err(invalid("review workpaper checksum mismatch"));
        }
        let fail = |e| invalid(format!("review workpaper decoding: {e}"));
        let mut r = Reader::new(bytes);
        if r.bytes(64, "review workpaper format").map_err(fail)? != FINDING_REVIEW_WORKPAPER_FORMAT
        {
            return Err(invalid("unsupported review workpaper format"));
        }
        let id = r.str(160, "review workpaper id").map_err(fail)?;
        let review_known_at = CommitSeq(r.u64("review cutoff").map_err(fail)?);
        let original = r
            .bytes(MAX_FINDING_REVIEW_WORKPAPER_BYTES, "original workpaper")
            .map_err(fail)?;
        let jsonl = r
            .str(MAX_FINDING_REVIEW_WORKPAPER_BYTES, "review JSONL")
            .map_err(fail)?;
        let markdown = r
            .str(MAX_FINDING_REVIEW_WORKPAPER_BYTES, "review Markdown")
            .map_err(fail)?;
        let digest = r.fixed::<32>("review workpaper digest").map_err(fail)?;
        r.finish().map_err(fail)?;
        let original = FindingWorkpaper::decode(original)?;
        if review_known_at < original.recorded_at() || id != revision(&original, review_known_at) {
            return Err(invalid(
                "review cutoff or revision does not match the original workpaper",
            ));
        }
        let saved = Self {
            id: id.to_owned(),
            review_known_at,
            original,
            jsonl: jsonl.to_owned(),
            markdown: markdown.to_owned(),
            digest,
        };
        if saved.canonical_bytes()? != bytes {
            return Err(invalid("noncanonical review workpaper"));
        }
        Ok(saved)
    }
}

fn revision(original: &FindingWorkpaper, at: CommitSeq) -> String {
    format!("{}-R-{}", original.id(), at.0)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// Bound each escaped append before allocating; no partial transcript escapes.
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
fn inert(out: &mut Text, text: &str) -> fmt::Result {
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
fn status_name(status: FindingReviewStatus) -> &'static str {
    match status {
        FindingReviewStatus::Open => "Open",
        FindingReviewStatus::Reviewed => "Reviewed",
        FindingReviewStatus::Dismissed { .. } => "Dismissed",
    }
}
fn action_name(action: FindingReviewAction) -> &'static str {
    match action {
        FindingReviewAction::Acknowledge => "Acknowledge",
        FindingReviewAction::Dismiss(_) => "Dismiss",
        FindingReviewAction::Reopen => "Reopen",
    }
}
fn reason_name(reason: DismissalReason) -> &'static str {
    match reason {
        DismissalReason::Explained => "Explained",
        DismissalReason::Duplicate => "Duplicate",
        DismissalReason::DataQuality => "DataQuality",
        DismissalReason::OutsideScope => "OutsideScope",
        DismissalReason::Other => "Other",
    }
}
fn optional_id(out: &mut Text, id: Option<VId>) -> fmt::Result {
    match id {
        Some(id) => write!(out, "\"{:032x}\"", id.0),
        None => out.write_str("null"),
    }
}

fn json(
    out: &mut Text,
    id: &str,
    original: &FindingWorkpaper,
    history: &FindingRunReviewHistory,
) -> fmt::Result {
    let counts = history.histories.iter().fold([0usize; 3], |mut counts, h| {
        counts[match h.status() {
            FindingReviewStatus::Open => 0,
            FindingReviewStatus::Reviewed => 1,
            FindingReviewStatus::Dismissed { .. } => 2,
        }] += 1;
        counts
    });
    writeln!(
        out,
        "{{\"event\":\"review_workpaper\",\"id\":\"{id}\",\"original_workpaper\":\"{}\",\"certificate\":\"{}\",\"source_known_at\":\"{}\",\"review_known_at\":\"{}\",\"finding_count\":{},\"open\":{},\"reviewed\":{},\"dismissed\":{},\"scope\":\"one_complete_recorded_run\",\"proof_class\":\"retained_history_replay\"}}",
        original.id(),
        hex(&history.run.certificate_digest),
        history.run.report.coordinate.known_at.0,
        history.known_at.0,
        history.histories.len(),
        counts[0],
        counts[1],
        counts[2]
    )?;
    for h in &history.histories {
        write!(
            out,
            "{{\"event\":\"finding_review_state\",\"finding\":\"{:032x}\",\"ordinal\":{},\"status\":\"{}\",\"latest_review\":",
            h.finding.finding_vid.0,
            h.finding.ordinal,
            status_name(h.status())
        )?;
        optional_id(out, h.latest_review())?;
        writeln!(out, ",\"decision_count\":{}}}", h.reviews.len())?;
        for review in &h.reviews {
            write!(
                out,
                "{{\"event\":\"finding_review_decision\",\"finding\":\"{:032x}\",\"review\":\"{:032x}\",\"ordinal\":{},\"recorded_at\":\"{}\",\"principal\":\"{:032x}\",\"capability_commitment\":\"{}\",\"expected_previous\":",
                review.request.finding_vid.0,
                review.review_vid.0,
                review.ordinal,
                review.recorded_at.0,
                review.principal.0,
                hex(&review.capability_commitment)
            )?;
            optional_id(out, review.request.expected_previous)?;
            write!(
                out,
                ",\"action\":\"{}\",\"dismissal_reason\":",
                action_name(review.request.action)
            )?;
            match review.request.action {
                FindingReviewAction::Dismiss(reason) => write!(
                    out,
                    "{{\"code\":{},\"name\":\"{}\"}}",
                    reason as u16,
                    reason_name(reason)
                )?,
                _ => out.write_str("null")?,
            }
            out.write_str(",\"note\":")?;
            quote(out, &review.request.note)?;
            out.write_str(",\"evidence\":[")?;
            for (i, oid) in review.request.evidence.iter().enumerate() {
                if i != 0 {
                    out.write_char(',')?;
                }
                write!(out, "{{\"kind\":\"document\",\"oid\":\"{}\"}}", hex(&oid.0))?;
            }
            out.write_str("]}\n")?;
        }
    }
    Ok(())
}

fn markdown(
    out: &mut Text,
    id: &str,
    original: &FindingWorkpaper,
    history: &FindingRunReviewHistory,
) -> fmt::Result {
    writeln!(
        out,
        "# Finding review appendix\n\nRevision: `{id}`\n\nOriginal observation workpaper: `{}`. Source known-at: **{}**. Review decisions through: **{}**.\n\nThis appendix accompanies the complete unchanged original workpaper. It reports human decisions, not changes to observations, proof of reviewer identity, economic truth, or an offline proof. Later decisions are outside this fixed review cutoff; successful replay still checks for later damage to retained records.\n\nComplete run: **{} observations**. Never-reviewed findings remain explicit below. Evidence references identify retained Document records, not exported document bytes.\n",
        original.id(),
        history.run.report.coordinate.known_at.0,
        history.known_at.0,
        history.histories.len()
    )?;
    if history.histories.is_empty() {
        out.write_str("This recorded run has no observations and no finding decisions. It was recorded, not omitted.\n")?;
    }
    for h in &history.histories {
        writeln!(
            out,
            "## Observation {}: {:032x}\n\nStatus at review cutoff: **{}**. Decisions: {}.\n",
            h.finding.ordinal + 1,
            h.finding.finding_vid.0,
            status_name(h.status()),
            h.reviews.len()
        )?;
        if h.reviews.is_empty() {
            out.write_str("No review was recorded through the selected cutoff.\n")?;
        }
        for review in &h.reviews {
            writeln!(
                out,
                "### Decision {}: {}\n\nReview: `{:032x}`. Native sequence: **{}**. Reviewer: `{:032x}`.\n\nCapability commitment: `{}`. Previous review: `{}`.\n",
                review.ordinal + 1,
                action_name(review.request.action),
                review.review_vid.0,
                review.recorded_at.0,
                review.principal.0,
                hex(&review.capability_commitment),
                review
                    .request
                    .expected_previous
                    .map_or_else(|| "none".into(), |id| format!("{:032x}", id.0))
            )?;
            if let FindingReviewAction::Dismiss(reason) = review.request.action {
                writeln!(
                    out,
                    "Dismissal reason: **{}** (registered code {}).\n",
                    reason_name(reason),
                    reason as u16
                )?;
            }
            out.write_str("Explanation: ")?;
            inert(out, &review.request.note)?;
            out.write_str("\n\nRetained evidence:")?;
            if review.request.evidence.is_empty() {
                out.write_str(" none")?;
            }
            for oid in &review.request.evidence {
                write!(out, " `D:{}`", hex(&oid.0))?;
            }
            out.write_str("\n\n")?;
        }
    }
    Ok(())
}

type Appendices = (String, String, String);
fn render(
    original: &FindingWorkpaper,
    history: &FindingRunReviewHistory,
) -> Result<Appendices, Refusal> {
    if history.known_at < history.run.recorded_at
        || original.recorded_at() != history.run.recorded_at
        || history.histories.len() != history.run.finding_ids.len()
    {
        return Err(invalid(
            "review workpaper does not cover its complete original run",
        ));
    }
    let source = ProcedureCertificate::decode(original.certificate_bytes())?;
    if *source.digest() != history.run.certificate_digest {
        return Err(invalid(
            "review workpaper source differs from its review histories",
        ));
    }
    let limit = MAX_FINDING_REVIEW_WORKPAPER_BYTES
        .checked_sub(original.canonical_bytes()?.len())
        .and_then(|n| n.checked_sub(512))
        .ok_or_else(|| invalid("review workpaper exceeds the complete-package bound"))?;
    let id = revision(original, history.known_at);
    let refusal =
        |_| invalid("review appendices exceed the complete-package bound; no partial workpaper");
    let mut jsonl = Text::new(limit);
    json(&mut jsonl, &id, original, history).map_err(refusal)?;
    let mut md = Text::new(limit - jsonl.bytes.len());
    markdown(&mut md, &id, original, history).map_err(refusal)?;
    Ok((id, jsonl.bytes, md.bytes))
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Export the unchanged original workpaper and all human review decisions at
    /// one cutoff. Read+produce authority is current; no record is written and
    /// no workpaper counter is advanced. Later checks do not change these bytes.
    pub async fn finding_review_workpaper(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &[u8; 32],
        known_at: Option<CommitSeq>,
    ) -> Outcome<FindingReviewWorkpaper> {
        if let Err(r) = authorize(self, cx, principal, capability, true)? {
            return Ok(Err(r));
        }
        let history = match self
            .finding_run_review_history(cx, principal, capability, certificate, known_at)
            .await?
        {
            Ok(h) => h,
            Err(r) => return Ok(Err(r)),
        };
        let original = match self
            .finding_workpaper(cx, principal, capability, certificate)
            .await?
        {
            Ok(p) => p,
            Err(r) => return Ok(Err(r)),
        };
        let (id, jsonl, markdown) = match render(&original, &history) {
            Ok(p) => p,
            Err(r) => return Ok(Err(r)),
        };
        let mut result = FindingReviewWorkpaper {
            id,
            review_known_at: history.known_at,
            original,
            jsonl,
            markdown,
            digest: [0; 32],
        };
        result.digest = match result.body() {
            Ok(b) => domain_digest(DOMAIN, &[&b]),
            Err(r) => return Ok(Err(r)),
        };
        if let Err(r) = authorize(self, cx, principal, capability, true)? {
            return Ok(Err(r));
        }
        Ok(Ok(result))
    }

    /// Local as-supplied replay; this does not establish that a delivery answers
    /// a separately requested cutoff. Use replay_finding_review_workpaper_for
    /// with an independently retained expectation for recipient verification.
    /// Verify the original certificate-backed observations and recompute every
    /// displayed decision, including omission-sensitive Open states. Only read
    /// authority is required. The returned receipt names today's checked_through;
    /// that advancing frontier is never part of the immutable exported package.
    pub async fn replay_finding_review_workpaper(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        bytes: &[u8],
    ) -> Outcome<FindingRunReviewHistory> {
        if let Err(r) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(r));
        }
        let saved = match FindingReviewWorkpaper::decode(bytes) {
            Ok(s) => s,
            Err(r) => return Ok(Err(r)),
        };
        let original_bytes = match saved.original.canonical_bytes() {
            Ok(b) => b,
            Err(r) => return Ok(Err(r)),
        };
        let original = match self
            .replay_finding_workpaper_with_history(cx, principal, capability, &original_bytes)
            .await?
        {
            Ok(r) => r,
            Err(r) => return Ok(Err(r)),
        };
        let history = match self
            .finding_run_review_history(
                cx,
                principal,
                capability,
                &original.certificate_digest,
                Some(saved.review_known_at),
            )
            .await?
        {
            Ok(h) => h,
            Err(r) => return Ok(Err(r)),
        };
        if original != history.run {
            return Ok(Err(invalid(
                "review workpaper original run changed during replay",
            )));
        }
        let actual = match render(&saved.original, &history) {
            Ok(p) => p,
            Err(r) => return Ok(Err(r)),
        };
        if actual.0 != saved.id || actual.1 != saved.jsonl || actual.2 != saved.markdown {
            return Ok(Err(invalid(
                "review workpaper decisions, coverage or presentations do not replay",
            )));
        }
        if let Err(r) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(r));
        }
        Ok(Ok(history))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn review_text_is_escaped_and_bounds_precede_each_append() {
        let mut out = Text::new(128);
        quote(&mut out, "\"\\\n\t\u{1f} 零").unwrap();
        assert_eq!(out.bytes, "\"\\\"\\\\\\n\\t\\u001f 零\"");
        let mut out = Text::new(128);
        inert(&mut out, "<script>|[x](y)\n`cash` &").unwrap();
        assert_eq!(out.bytes, "&lt;script&gt;&#124;\\[x\\](y) \\`cash\\` &amp;");
        let mut out = Text::new(2);
        out.write_str("é").unwrap();
        assert!(out.write_str("x").is_err());
        assert_eq!(out.bytes, "é");
        for bytes in [b"".as_slice(), b"unknown workpaper", &[0; 32]] {
            assert!(FindingReviewWorkpaper::decode(bytes).is_err());
        }
    }
}
