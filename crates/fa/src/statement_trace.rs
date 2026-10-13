//! Publication-by-publication attribution of a historical statement bridge.
//!
//! Each step refolds the SAME statement at adjacent retained sequences. This
//! uses the production statement engine, not a second interpretation of posted
//! legs, Closing lineage, reservations or migration visibility. No publication
//! is skipped, including a zero-effect publication or changes which later net
//! to zero. Native units and comparative columns are never combined.
//!
//! Entry links identify records published, or migration chunks made visible,
//! at a step. The line delta belongs to the atomic PUBLICATION. A multi-entry
//! batch is not split into invented per-entry effects; a linked record need not
//! affect the selected periods. No case approval, issuance or economic cause
//! is inferred. Descriptions, memos and document bytes are not opened.
//!
//! Work is bounded explicitly: at most 256 publications, one literal statement
//! per frontier and one historical entry scan per step. A larger request is a
//! refusal, never a partial trace. All reads retain the caller's purpose context.

use std::collections::BTreeMap;

use asupersync::fs::Vfs;
use fa_journal::{KernelError, Refusal, exit};
use fa_model::symbols::{label, property};
use fa_model::{ControlPayload, Entry, EntryClass, EntryOrigin, EntryRef, Id128, Writer, domain_digest};
use fa_policy::{Capability, Op};
use fa_time::DateDay;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, BookError, Outcome, Statement, StatementDiff, StatementDiffRequest, StatementLineChange, StatementMappingChange};

mod certificate;
pub use certificate::{CertifiedStatementTrace, StatementTraceCertificate, MAX_STATEMENT_TRACE_CERTIFICATE_BYTES};

pub const OUTPUT_FORMAT: &[u8] = b"fa:statement-trace:v1";
const SOURCE_DOMAIN: &[u8] = b"fa:statement-trace-source:v1";
pub const MAX_STATEMENT_TRACE_PUBLICATIONS: usize = 256;
pub const MAX_STATEMENT_TRACE_BYTES: usize = 64 * 1024 * 1024;
const MAX_LINKS: usize = 65_536;
const MAX_REFERENCES: usize = 4096;

/// A finite interval of publications, (before, after], at one statement
/// selection. The caller's limit must be in 1..=256; zero-length intervals
/// are valid and return their initial statement with no publication steps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementTraceRequest {
    pub comparison: StatementDiffRequest,
    pub max_publications: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatementEntryEvent {
    Recorded,
    /// A previously recorded migration chunk became visible at this step.
    /// Its real recorded_at is preserved; the finalize sequence is not its date.
    BecameVisible,
}

/// Metadata-only drilldown. References are the canonical SET of entry targets
/// mentioned by supersession, resolution or settlement. Edge kinds and reasons
/// remain in the immutable entry named by entry_ref, rather than being guessed
/// from a statement line. A migration control or chunk also names its run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementEntryLink {
    pub event: StatementEntryEvent,
    pub entry_ref: EntryRef,
    pub class: EntryClass,
    pub recorded_at: CommitSeq,
    /// Present for leg-bearing records only; no posting date is invented for
    /// a control or a zero-leg release. The full entry retains its own scope.
    pub posting_date: Option<DateDay>,
    pub principal: VId,
    pub references: Vec<EntryRef>,
    pub migration_run: Option<VId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementPublication {
    pub recorded_at: CommitSeq,
    pub before_source_digest: [u8; 32],
    pub after_source_digest: [u8; 32],
    /// Entry-id order, not a proposed ordering inside an atomic publication.
    pub entries: Vec<StatementEntryLink>,
    /// Sparse monetary changes in definition/unit order. An omitted line has
    /// zero delta in every column; the summary still contains every line.
    pub changes: Vec<StatementLineChange>,
    pub mapping_changes: Vec<StatementMappingChange>,
}

impl StatementPublication {
    #[must_use]
    pub fn is_unchanged(&self) -> bool {
        self.changes.is_empty() && self.mapping_changes.is_empty()
    }
}

/// Immutable complete interval. A zero net bridge does not imply that every
/// intermediate publication was unchanged: inspect had_changes/publications.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementTrace {
    summary: StatementDiff,
    publications: Vec<StatementPublication>,
}

pub(crate) fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::statements::STATEMENT_INVALID, exit::REFUSAL, message,
        "plan §7.1 / §8.3 / §12.5 (complete historical statement-publication attribution)",
        "select the same statement over a smaller retained sequence interval, within the explicit publication and byte limits; no partial trace is returned",
    )
}

fn size(parts: impl IntoIterator<Item = usize>) -> Result<usize, Refusal> {
    let bytes = parts.into_iter().try_fold(0usize, |sum, part| sum.checked_add(part))
        .ok_or_else(|| invalid("statement trace length overflow"))?;
    if bytes > MAX_STATEMENT_TRACE_BYTES {
        return Err(invalid("statement trace exceeds its 64 MiB output bound"));
    }
    Ok(bytes)
}

fn mapping_size(mapping: &fa_statements::AccountMapping) -> Result<usize, Refusal> {
    size([30, mapping.account.code.len(), mapping.account.name.len(), mapping.line_code.len()])
}

fn changes_size(lines: &[StatementLineChange], mappings: &[StatementMappingChange]) -> Result<usize, Refusal> {
    let mut bytes = 0;
    for line in lines {
        let amounts = line.before.len().checked_add(line.after.len())
            .and_then(|n| n.checked_add(line.delta.len()))
            .and_then(|n| n.checked_mul(16)).ok_or_else(|| invalid("trace amount length overflow"))?;
        bytes = size([bytes, 24, line.code.len(), line.label.len(), amounts])?;
    }
    for change in mappings {
        bytes = size([bytes, 18])?;
        for mapping in [change.before.as_ref(), change.after.as_ref()].into_iter().flatten() {
            bytes = size([bytes, mapping_size(mapping)?])?;
        }
    }
    Ok(bytes)
}

fn bridge_size(report: &StatementDiff) -> Result<usize, Refusal> {
    // The existing fa:statement-diff:v1 layout, priced before its encoder is
    // called. Equality with the emitted length is checked below, not assumed.
    let mut bytes = size([4, crate::statement_diff::OUTPUT_FORMAT.len(), 16, 16, 8, 8, 32, 32, 32, 4, 4, 4])?;
    for column in &report.before().columns {
        bytes = size([bytes, 4, column.label.len(), 4, 1, usize::from(column.effective_from.is_some()) * 4, 4])?;
        for period in &column.periods { bytes = size([bytes, 4, period.len()])?; }
    }
    size([bytes, changes_size(report.lines(), report.mapping_changes())?])
}

fn link_size(link: &StatementEntryLink) -> Result<usize, Refusal> {
    let references = link.references.len().checked_mul(48)
        .ok_or_else(|| invalid("trace reference length overflow"))?;
    size([81, usize::from(link.posting_date.is_some()) * 4,
        usize::from(link.migration_run.is_some()) * 16, references])
}

fn publication_size(step: &StatementPublication) -> Result<usize, Refusal> {
    let mut bytes = size([84, changes_size(&step.changes, &step.mapping_changes)?])?;
    for entry in &step.entries { bytes = size([bytes, link_size(entry)?])?; }
    Ok(bytes)
}

fn write_reference(w: &mut Writer, reference: &EntryRef) {
    w.u128(reference.vid.0).fixed(&reference.entry_digest);
}

fn write_mapping(w: &mut Writer, mapping: &fa_statements::AccountMapping) {
    w.u128(mapping.account.id).str(&mapping.account.code).str(&mapping.account.name)
        .u8(mapping.account.account_type).bool(mapping.account.is_leaf).str(&mapping.line_code);
}

fn write_changes(w: &mut Writer, lines: &[StatementLineChange], mappings: &[StatementMappingChange]) {
    w.list(lines, |w, line| {
        w.str(&line.code).str(&line.label).u32(line.unit_id)
            .list(&line.before, |w, value| { w.i128(*value); })
            .list(&line.after, |w, value| { w.i128(*value); })
            .list(&line.delta, |w, value| { w.i128(*value); });
    }).list(mappings, |w, change| {
        w.u128(change.account_id).opt(change.before.as_ref(), write_mapping)
            .opt(change.after.as_ref(), write_mapping);
    });
}

fn write_publication(w: &mut Writer, step: &StatementPublication) {
    w.u64(step.recorded_at.0).fixed(&step.before_source_digest).fixed(&step.after_source_digest)
        .list(&step.entries, |w, link| {
            w.u8(match link.event { StatementEntryEvent::Recorded => 0, StatementEntryEvent::BecameVisible => 1 })
                .u64(link.recorded_at.0);
            write_reference(w, &link.entry_ref);
            w.u16(link.class.0).opt(link.posting_date.as_ref(), |w, day| { w.i32(day.0); })
                .u128(link.principal.0).list(&link.references, write_reference)
                .opt(link.migration_run.as_ref(), |w, run| { w.u128(run.0); });
        });
    write_changes(w, &step.changes, &step.mapping_changes);
}

impl StatementTrace {
    #[must_use]
    pub fn summary(&self) -> &StatementDiff { &self.summary }
    #[must_use]
    pub fn publications(&self) -> &[StatementPublication] { &self.publications }
    #[must_use]
    pub fn had_changes(&self) -> bool { self.publications.iter().any(|step| !step.is_unchanged()) }

    fn encoded_len(&self) -> Result<usize, Refusal> {
        let mut bytes = size([12, OUTPUT_FORMAT.len(), bridge_size(&self.summary)?])?;
        for step in &self.publications { bytes = size([bytes, publication_size(step)?])?; }
        Ok(bytes)
    }

    /// Includes the complete net bridge plus EVERY adjacent publication, its
    /// exact source commitments, sparse changes and metadata-only entry links.
    /// Encoding commits content, not the validity of its historical source.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let length = self.encoded_len()?;
        let summary = self.summary.canonical_bytes().map_err(|e| invalid(e.to_string()))?;
        if summary.len() != bridge_size(&self.summary)? {
            return Err(invalid("statement bridge encoding differs from the trace's size contract"));
        }
        let mut w = Writer::with_capacity(length);
        w.bytes(OUTPUT_FORMAT).bytes(&summary).list(&self.publications, write_publication);
        let bytes = w.finish().map_err(|e| invalid(e.to_string()))?;
        if bytes.len() != length { return Err(invalid("statement trace encoding length mismatch")); }
        Ok(bytes)
    }
}

// Bound owned historical reports before any trace-specific cloning. This
// prices structure only; the existing comparison engine still validates all
// definition, mapping, unit and arithmetic laws.
fn admit_source(source: &Statement) -> Result<(), Refusal> {
    if source.columns.len() > 8 || source.lines.len() > 64 * 4096 || source.mappings.len() > 1_000_000 {
        return Err(invalid("statement trace source cardinality exceeds its bound"));
    }
    let mut bytes = size([256, source.definition_name.len(), source.definition_bytes.len()])?;
    for column in &source.columns {
        bytes = size([bytes, 32, column.label.len()])?;
        if column.periods.len() > 256 { return Err(invalid("too many source periods")); }
        for period in &column.periods { bytes = size([bytes, 4, period.len()])?; }
    }
    for line in &source.lines {
        if line.amounts.len() > 8 { return Err(invalid("too many source amount columns")); }
        bytes = size([bytes, 16, line.code.len(), line.label.len(), line.amounts.len() * 16])?;
    }
    for mapping in &source.mappings { bytes = size([bytes, mapping_size(mapping)?])?; }
    if bytes > MAX_STATEMENT_TRACE_BYTES / 2 { return Err(invalid("statement trace source exceeds 32 MiB")); }
    Ok(())
}

struct Builder {
    first: Statement,
    previous: Statement,
    after: CommitSeq,
    publications: Vec<StatementPublication>,
    step_bytes: usize,
    links: usize,
}

impl Builder {
    fn new(first: Statement, after: CommitSeq) -> Result<Self, Refusal> {
        admit_source(&first)?;
        let span = after.0.checked_sub(first.known_at).ok_or_else(|| invalid("trace frontiers are reversed"))?;
        if span > MAX_STATEMENT_TRACE_PUBLICATIONS as u64 { return Err(invalid("trace exceeds 256 publications")); }
        StatementDiff::between(first.clone(), first.clone())?;
        Ok(Self { previous: first.clone(), first, after, publications: Vec::new(), step_bytes: 0, links: 0 })
    }

    fn push(&mut self, next: Statement, entries: Vec<StatementEntryLink>) -> Result<(), Refusal> {
        admit_source(&next)?;
        if self.previous.known_at.checked_add(1) != Some(next.known_at) || next.known_at > self.after.0 {
            return Err(invalid("trace sources must cover every adjacent sequence without gaps or duplicates"));
        }
        if entries.windows(2).any(|pair| pair[0].entry_ref.vid >= pair[1].entry_ref.vid) {
            return Err(invalid("trace entry links must be unique and ordered by identity"));
        }
        for link in &entries {
            let admitted = match link.event {
                StatementEntryEvent::Recorded => link.recorded_at.0 == next.known_at,
                StatementEntryEvent::BecameVisible => link.recorded_at.0 < next.known_at
                    && link.class == EntryClass::MIGRATION && link.migration_run.is_some(),
            };
            if !admitted || link.class.name().is_none() || link.references.len() > MAX_REFERENCES
                || link.references.windows(2).any(|pair| pair[0].vid >= pair[1].vid)
            { return Err(invalid("trace link has an invalid event, class, coordinate or reference set")); }
        }
        let links = self.links.checked_add(entries.len()).ok_or_else(|| invalid("trace link count overflow"))?;
        if links > MAX_LINKS { return Err(invalid("trace exceeds 65536 entry links")); }
        let diff = StatementDiff::between(self.previous.clone(), next.clone())?;
        // between validated both bounded source shapes before these encodings.
        let old = diff.before().canonical_bytes().map_err(|e| invalid(e.to_string()))?;
        let new = diff.after().canonical_bytes().map_err(|e| invalid(e.to_string()))?;
        // Admit the aggregate payload before cloning sparse changes. Individual
        // sources were already bounded by the existing comparison engine.
        let mut incoming = 84;
        for entry in &entries { incoming = size([incoming, link_size(entry)?])?; }
        for line in diff.lines().iter().filter(|line| line.delta.iter().any(|amount| *amount != 0)) {
            incoming = size([incoming, changes_size(std::slice::from_ref(line), &[])?])?;
        }
        incoming = size([incoming, changes_size(&[], diff.mapping_changes())?])?;
        let bytes = size([self.step_bytes, incoming])?;
        let step = StatementPublication {
            recorded_at: CommitSeq(next.known_at),
            before_source_digest: domain_digest(SOURCE_DOMAIN, &[&old]),
            after_source_digest: domain_digest(SOURCE_DOMAIN, &[&new]),
            entries,
            changes: diff.lines().iter().filter(|line| line.delta.iter().any(|delta| *delta != 0)).cloned().collect(),
            mapping_changes: diff.mapping_changes().to_vec(),
        };
        self.publications.push(step);
        self.previous = next;
        self.step_bytes = bytes;
        self.links = links;
        Ok(())
    }

    fn finish(self) -> Result<StatementTrace, Refusal> {
        if self.previous.known_at != self.after.0 {
            return Err(invalid("trace stops before its requested final sequence"));
        }
        let summary = StatementDiff::between(self.first, self.previous)?;
        let trace = StatementTrace { summary, publications: self.publications };
        trace.encoded_len()?;
        Ok(trace)
    }
}

fn authorize<V: Vfs + Clone, B: Vfs + Clone>(book: &AsyncBook<V, B>, cx: &PurposeContexts,
    principal: VId, capability: &Capability, produce: bool) -> Outcome<CommitSeq>
{
    if let Err(denial) = fa_policy::admit_read(capability, principal, book.context().book_id).and_then(|()| {
        if produce { fa_policy::require(capability, Op::Produce, "producing statement attribution") } else { Ok(()) }
    }) { return Ok(Err(fa_journal::policy::refusal(&denial))); }
    let query = cx.query();
    query.checkpoint().map_err(BookError::Context)?;
    query.with_restriction(|| {
        let head = book.db.frontier().map_err(KernelError::from)?;
        if let Err(denial) = fa_policy::current(capability, head) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        if let Err(refusal) = fa_journal::policy::capability_admitted(&book.db, book.context(), capability)? {
            return Ok(Err(refusal));
        }
        Ok(Ok(head))
    })
}

fn resolved(request: &StatementTraceRequest, head: CommitSeq) -> Result<StatementDiffRequest, Refusal> {
    let before = request.comparison.before;
    let after = request.comparison.after.unwrap_or(head);
    if request.max_publications == 0 || request.max_publications > MAX_STATEMENT_TRACE_PUBLICATIONS
        || before > after || after > head
        || after.0 - before.0 > request.max_publications as u64
    { return Err(invalid("trace needs before <= after <= head and a sufficient explicit limit in 1..=256")); }
    let selection = request.comparison.selection.clone().normalize();
    if !selection.is_canonical() { return Err(invalid("trace requires a valid nonempty statement selection")); }
    Ok(StatementDiffRequest { selection, before, after: Some(after) })
}

fn references(entry: &Entry) -> Result<Vec<EntryRef>, Refusal> {
    let mut references = BTreeMap::new();
    let targets = entry.proposal.supersession.iter().map(|supersession| supersession.target)
        .chain(entry.proposal.pending.as_ref().and_then(|pending| pending.resolution_of))
        .chain(entry.proposal.legs.iter().flat_map(|leg| leg.settles.iter().map(|settlement| settlement.target)));
    for target in targets {
        if let Some(digest) = references.insert(target.vid, target.entry_digest)
            && digest != target.entry_digest
        { return Err(invalid("an entry names conflicting digests for the same lineage target")); }
        if references.len() > MAX_REFERENCES { return Err(invalid("trace entry references exceed 4096")); }
    }
    Ok(references.into_iter().map(|(vid, entry_digest)| EntryRef { vid, entry_digest }).collect())
}

fn publication_entries<V: Vfs + Clone, B: Vfs + Clone>(book: &AsyncBook<V, B>, cx: &PurposeContexts,
    at: CommitSeq) -> Outcome<Vec<StatementEntryLink>>
{
    let before = CommitSeq(at.0.checked_sub(1).ok_or_else(|| KernelError::Corrupt("trace publication has no predecessor".into()))?);
    let query = cx.query();
    query.checkpoint().map_err(BookError::Context)?;
    query.with_restriction(|| {
        let mut links = Vec::new();
        let mut link_bytes = 0;
        let mut old_runs = BTreeMap::new();
        let mut new_runs = BTreeMap::new();
        for row in book.db.vertices_at(at).map_err(KernelError::from)? {
            query.checkpoint().map_err(BookError::Context)?;
            if !row.labels.contains(&label::ENTRY) { continue; }
            let entry = Entry::decode(&fa_journal::rows::bytes(&row, property::FA_PAYLOAD, "trace entry payload")?)
                .map_err(KernelError::from)?;
            if entry.proposal.book_id != book.context().book_id || entry.proposal.branch_id != Id128::TRUNK
                || row.created_at > at
                || fa_journal::rows::bytes(&row, property::FA_DIGEST, "trace entry digest")? != entry.entry_digest
            { return Err(KernelError::Corrupt("trace entry coordinate or digest mirror differs".into()).into()); }
            let event = if row.created_at == at { StatementEntryEvent::Recorded }
            else if matches!(&entry.proposal.origin, EntryOrigin::Migration { .. })
                && fa_journal::migration::visible_at(&book.db, &entry, at, &mut new_runs)?
                && !fa_journal::migration::visible_at(&book.db, &entry, before, &mut old_runs)?
            { StatementEntryEvent::BecameVisible }
            else { continue; };
            if links.len() == MAX_LINKS { return Ok(Err(invalid("publication exceeds 65536 entry links"))); }
            let references = match references(&entry) { Ok(value) => value, Err(r) => return Ok(Err(r)) };
            let migration_run = match (&entry.proposal.origin, &entry.proposal.control) {
                (EntryOrigin::Migration { run_ref, .. }, _) | (_, Some(ControlPayload::MigrationControl { run_ref, .. })) => Some(*run_ref),
                _ => None,
            };
            let link = StatementEntryLink {
                event, entry_ref: EntryRef { vid: row.vid, entry_digest: entry.entry_digest },
                class: entry.proposal.class, recorded_at: row.created_at,
                posting_date: (!entry.proposal.legs.is_empty()).then_some(entry.proposal.effective_date),
                principal: entry.proposal.principal_ref, references, migration_run,
            };
            link_bytes = match link_size(&link).and_then(|length| size([link_bytes, length])) {
                Ok(bytes) => bytes, Err(r) => return Ok(Err(r)),
            };
            links.push(link);
        }
        links.sort_by_key(|link| link.entry_ref.vid);
        Ok(Ok(links))
    })
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Reconcile a complete adjacent-publication trace to its net statement
    /// comparison. Authority precedes even selector/frontier observation.
    /// This method is read-only; it is not a retained-history certificate.
    pub fn statement_trace(&self, cx: &PurposeContexts, principal: VId, capability: &Capability,
        request: &StatementTraceRequest) -> Outcome<StatementTrace>
    {
        let head = match authorize(self, cx, principal, capability, false)? { Ok(h) => h, Err(r) => return Ok(Err(r)) };
        let request = match resolved(request, head) { Ok(r) => r, Err(r) => return Ok(Err(r)) };
        let after = request.after.unwrap_or(head);
        let first = match self.statement(cx, request.selection.clone(), Some(request.before))? { Ok(s) => s, Err(r) => return Ok(Err(r)) };
        let mut builder = match Builder::new(first, after) { Ok(b) => b, Err(r) => return Ok(Err(r)) };
        // Offset arithmetic is safe even for an empty interval at u64::MAX.
        for offset in 1..=after.0 - request.before.0 {
            let at = CommitSeq(request.before.0 + offset);
            cx.query().checkpoint().map_err(BookError::Context)?;
            let statement = match self.statement(cx, request.selection.clone(), Some(at))? { Ok(s) => s, Err(r) => return Ok(Err(r)) };
            let entries = match publication_entries(self, cx, at)? { Ok(e) => e, Err(r) => return Ok(Err(r)) };
            if let Err(r) = builder.push(statement, entries) { return Ok(Err(r)); }
        }
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(builder.finish())
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod acceptance;
