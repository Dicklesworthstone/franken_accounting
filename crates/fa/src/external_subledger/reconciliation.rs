//! Whole-feed source detail against every posting on an explicitly selected
//! control leaf. This report detects uncovered activity; it reserves no account.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_journal::{AccountRow, BookContext, KernelError, Refusal};
use fa_model::{Entry, EntryClass, EntryRef, Id128, SupersessionKind, Writer};
use fa_money::{Side, UnitId};
use fa_policy::{Capability, Op};
use fa_registers::{RegisterError, TrialBalance};
use fa_time::DateDay;
use fgdb::Database;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use super::{ExternalSubledgerBatch, ExternalSubledgerReconciliation, invalid};
use crate::{AsyncBook, BookError, Outcome};

pub const EXTERNAL_FEED_REPORT_FORMAT: &str = "fa:external-feed-reconciliation:v1";
pub(super) const OUTPUT: &[u8] = EXTERNAL_FEED_REPORT_FORMAT.as_bytes();
const MAX_REPORT_LEGS: usize = 100_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalFeedRequest {
    pub feed: String,
    pub control_account: VId,
    pub effective_through: DateDay,
    pub known_at: Option<CommitSeq>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalFeedContribution {
    pub entry: EntryRef,
    pub recorded_at: CommitSeq,
    pub effective_date: DateDay,
    pub source: EntryRef,
    /// Odd reversal ancestry swaps the original source's gross sides.
    pub reversed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalFeedLeg {
    pub entry: EntryRef,
    pub ordinal: u32,
    pub unit: UnitId,
    pub side: Side,
    pub amount: i128,
    pub dimension_set: Vec<(u32, VId)>,
    pub pending: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalFeedRow {
    pub unit_id: u32,
    pub dimension_set: Vec<(u32, VId)>,
    pub detail_debits: i128,
    pub detail_credits: i128,
    pub control_debits: i128,
    pub control_credits: i128,
    pub pending_debits: i128,
    pub pending_credits: i128,
}

impl ExternalFeedRow {
    #[must_use]
    pub const fn is_reconciled(&self) -> bool {
        self.detail_debits == self.control_debits
            && self.detail_credits == self.control_credits
            && self.pending_debits == 0
            && self.pending_credits == 0
    }

    fn columns(&self) -> [i128; 6] {
        [
            self.detail_debits,
            self.detail_credits,
            self.control_debits,
            self.control_credits,
            self.pending_debits,
            self.pending_credits,
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalFeedTotal {
    pub unit_id: u32,
    pub detail_debits: i128,
    pub detail_credits: i128,
    pub control_debits: i128,
    pub control_credits: i128,
    pub pending_debits: i128,
    pub pending_credits: i128,
    pub register_debits: i128,
    pub register_credits: i128,
    pub register_debits_pending: i128,
    pub register_credits_pending: i128,
}

impl ExternalFeedTotal {
    #[must_use]
    pub const fn is_reconciled(&self) -> bool {
        self.detail_debits == self.control_debits
            && self.detail_credits == self.control_credits
            && self.pending_debits == 0
            && self.pending_credits == 0
            && self.control_debits == self.register_debits
            && self.control_credits == self.register_credits
            && self.pending_debits == self.register_debits_pending
            && self.pending_credits == self.register_credits_pending
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalFeedReconciliation {
    pub book_id: Id128,
    pub known_at: CommitSeq,
    pub feed: String,
    pub control_account: VId,
    pub effective_through: DateDay,
    /// Every selected batch, plus a source outside the effective cutoff when
    /// a qualifying reversal cites it. Each is independently checked in full.
    pub batches: Vec<ExternalSubledgerReconciliation>,
    pub contributions: Vec<ExternalFeedContribution>,
    pub unattributed: Vec<ExternalFeedLeg>,
    pub rows: Vec<ExternalFeedRow>,
    pub totals: Vec<ExternalFeedTotal>,
    pub reconciled: bool,
}

fn entry_ref(w: &mut Writer, value: EntryRef) {
    w.u128(value.vid.0).fixed(&value.entry_digest);
}

fn dimensions(w: &mut Writer, values: &[(u32, VId)]) {
    w.list(values, |w, (kind, value)| {
        w.u32(*kind).u128(value.0);
    });
}

impl ExternalFeedReconciliation {
    /// Price nested rows before allocating a canonical output buffer. An
    /// oversized comparison refuses in full rather than omitting citations.
    fn canonical_size(&self) -> Result<usize, Refusal> {
        const MAX_OUTPUT: usize = 64 * 1024 * 1024;
        let oversized = || invalid("external-feed output exceeds 64 MiB; no rows were truncated");
        let mut size = 4 + OUTPUT.len() + 16 + 8 + 4 + 16 + 4 + 5 * 4 + 1;
        let mut add = |count: usize, width: usize| -> Result<(), Refusal> {
            let amount = count.checked_mul(width).ok_or_else(oversized)?;
            size = size.checked_add(amount).ok_or_else(oversized)?;
            if size > MAX_OUTPUT {
                return Err(oversized());
            }
            Ok(())
        };
        add(self.feed.len(), 1)?;
        for batch in &self.batches {
            add(1, 178)?;
            add(batch.feed.len(), 1)?;
            add(batch.batch_key.len(), 1)?;
            for leg in &batch.summary_legs {
                add(1, 41)?;
                add(leg.dimension_set.len(), 20)?;
            }
        }
        add(self.contributions.len(), 109)?;
        for leg in &self.unattributed {
            add(1, 78)?;
            add(leg.dimension_set.len(), 20)?;
        }
        for row in &self.rows {
            add(1, 104)?;
            add(row.dimension_set.len(), 20)?;
        }
        add(self.totals.len(), 164)?;
        Ok(size)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let size = self.canonical_size()?;
        let mut w = Writer::with_capacity(size);
        w.bytes(OUTPUT)
            .fixed(&self.book_id.0)
            .u64(self.known_at.0)
            .str(&self.feed)
            .u128(self.control_account.0)
            .i32(self.effective_through.0);
        w.list(&self.batches, |w, batch| {
            entry_ref(w, batch.entry);
            w.u64(batch.recorded_at.0)
                .str(&batch.feed)
                .str(&batch.batch_key)
                .i32(batch.effective_date.0)
                .fixed(&batch.evidence.document_oid.0)
                .fixed(&batch.evidence.doc_commit)
                .u8(batch.evidence.role)
                .u128(batch.review.attestation.0)
                .u128(batch.review.reviewer.0)
                .u64(batch.detail_rows as u64)
                .bool(batch.reconciled);
            w.list(&batch.summary_legs, |w, leg| {
                w.u128(leg.account_ref.0)
                    .u32(leg.amount.unit.0)
                    .u8(u8::from(leg.side == Side::Credit))
                    .i128(leg.amount.mantissa);
                dimensions(w, &leg.dimension_set);
            });
        });
        w.list(&self.contributions, |w, contribution| {
            entry_ref(w, contribution.entry);
            entry_ref(w, contribution.source);
            w.u64(contribution.recorded_at.0)
                .i32(contribution.effective_date.0)
                .bool(contribution.reversed);
        });
        w.list(&self.unattributed, |w, leg| {
            entry_ref(w, leg.entry);
            w.u32(leg.ordinal)
                .u32(leg.unit.0)
                .u8(u8::from(leg.side == Side::Credit))
                .i128(leg.amount)
                .bool(leg.pending);
            dimensions(w, &leg.dimension_set);
        });
        w.list(&self.rows, |w, row| {
            w.u32(row.unit_id);
            dimensions(w, &row.dimension_set);
            for value in row.columns() {
                w.i128(value);
            }
        });
        w.list(&self.totals, |w, row| {
            w.u32(row.unit_id);
            for value in [
                row.detail_debits,
                row.detail_credits,
                row.control_debits,
                row.control_credits,
                row.pending_debits,
                row.pending_credits,
                row.register_debits,
                row.register_credits,
                row.register_debits_pending,
                row.register_credits_pending,
            ] {
                w.i128(value);
            }
        });
        w.bool(self.reconciled);
        let bytes = w.finish().map_err(|error| invalid(error.to_string()))?;
        if bytes.len() != size {
            return Err(invalid(
                "external-feed output size differs from its encoding",
            ));
        }
        Ok(bytes)
    }

    /// Used for status: a later unrelated publication changes the coordinate
    /// but not this assertion. Exact source and entry citations still matter.
    #[must_use]
    pub fn same_assertion(&self, other: &Self) -> bool {
        self.book_id == other.book_id
            && self.feed == other.feed
            && self.control_account == other.control_account
            && self.effective_through == other.effective_through
            && self.batches == other.batches
            && self.contributions == other.contributions
            && self.unattributed == other.unattributed
            && self.rows == other.rows
            && self.totals == other.totals
            && self.reconciled == other.reconciled
    }
}

pub(super) fn normalize(
    request: &ExternalFeedRequest,
    at: CommitSeq,
) -> Result<ExternalFeedRequest, Refusal> {
    if request.feed.is_empty()
        || request.feed.len() > 64
        || !request
            .feed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
    {
        return Err(invalid(
            "feed must be a nonempty bounded identifier using letters, digits or ._:/-",
        ));
    }
    Ok(ExternalFeedRequest {
        known_at: Some(at),
        ..request.clone()
    })
}

pub(super) fn authorize<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    principal: VId,
    capability: &Capability,
    known_at: Option<CommitSeq>,
    produce: bool,
) -> Outcome<CommitSeq> {
    if let Err(d) =
        fa_policy::admit_read(capability, principal, book.context().book_id).and_then(|()| {
            if produce {
                fa_policy::require(
                    capability,
                    Op::Produce,
                    "certifying an external-feed reconciliation",
                )
            } else {
                Ok(())
            }
        })
    {
        return Ok(Err(fa_journal::policy::refusal(&d)));
    }
    book.query(cx, |db, context| {
        crate::subledger::admitted_at(db, context, capability, known_at)
    })
}

pub(super) type Entries = BTreeMap<VId, (Entry, CommitSeq)>;
type RowKey = (u32, Vec<(u32, VId)>);

pub(super) fn source_of(
    entries: &Entries,
    start: VId,
    feed: &str,
) -> Result<Option<(VId, bool, ExternalSubledgerBatch)>, Refusal> {
    let mut current = start;
    let mut seen = BTreeSet::new();
    let mut reversed = false;
    loop {
        if !seen.insert(current) {
            return Err(invalid("cycle in an external summary's reversal ancestry"));
        }
        let (entry, recorded_at) = entries
            .get(&current)
            .ok_or_else(|| invalid("external summary reversal names a missing target"))?;
        if let Some(batch) = fa_journal::external_subledger::validate_summary(&entry.proposal)? {
            return Ok((batch.feed == feed).then_some((current, reversed, batch)));
        }
        if entry.proposal.class != EntryClass::REVERSAL {
            return Ok(None);
        }
        let [target] = entry.proposal.supersession.as_slice() else {
            return Err(invalid("reversal requires exactly one immutable target"));
        };
        let (prior, prior_at) = entries
            .get(&target.target.vid)
            .ok_or_else(|| invalid("external summary reversal target is unavailable"))?;
        if target.kind != SupersessionKind::Reverses
            || prior.entry_ref(target.target.vid) != target.target
            || prior_at > recorded_at
            || !fa_palimpsest::is_exact_side_swap(&prior.proposal.legs, &entry.proposal.legs)
        {
            return Err(invalid(
                "reversal does not reproduce its original target's exact gross effects",
            ));
        }
        current = target.target.vid;
        reversed = !reversed;
    }
}

fn add(columns: &mut [i128; 6], index: usize, amount: i128) -> Result<(), BookError> {
    columns[index] = columns[index]
        .checked_add(amount)
        .ok_or(RegisterError::Overflow)?;
    Ok(())
}

pub(super) fn assemble<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    request: &ExternalFeedRequest,
    control: TrialBalance,
) -> Outcome<ExternalFeedReconciliation> {
    let at = request
        .known_at
        .ok_or_else(|| KernelError::Corrupt("external report has no fixed prefix".into()))?;
    crate::certificate::context_at(db, book, at)?;
    let Some(account) = db
        .vertex_at(request.control_account, at)
        .map_err(KernelError::from)?
        .filter(|row| row.labels.contains(&fa_model::symbols::label::ACCOUNT))
    else {
        return Ok(Err(invalid(
            "control account is absent at the selected prefix",
        )));
    };
    let account = AccountRow::decode(&account)?;
    if !account.is_leaf
        || AccountRow::vid_for(book.book_id, &account.code) != request.control_account
    {
        return Ok(Err(invalid(
            "external-feed reconciliation requires a valid posting leaf",
        )));
    }
    let entries: Entries = fa_registers::entries_at(db, book, at)?
        .into_iter()
        .map(|(vid, entry, seq)| (vid, (entry, seq)))
        .collect();
    let resolved: BTreeSet<_> = entries
        .values()
        .filter_map(|(entry, _)| {
            (entry.proposal.class == EntryClass::RESOLUTION)
                .then_some(&entry.proposal)
                .and_then(|p| p.pending.as_ref())
                .and_then(|p| p.resolution_of)
                .map(|r| r.vid)
        })
        .collect();
    let mut columns: BTreeMap<RowKey, [i128; 6]> = BTreeMap::new();
    let mut batches = BTreeMap::new();
    let mut identities = BTreeSet::new();
    let mut contributions = Vec::new();
    let mut unattributed = Vec::new();
    let mut count = 0usize;
    for (vid, (entry, recorded_at)) in &entries {
        cx.query().checkpoint().map_err(BookError::Context)?;
        let p = &entry.proposal;
        let pending = p.class == EntryClass::PENDING;
        if p.effective_date > request.effective_through || (pending && resolved.contains(vid)) {
            continue;
        }
        let source = match source_of(&entries, *vid, &request.feed) {
            Ok(source) => source,
            Err(r) => return Ok(Err(r)),
        };
        if let Some((source_vid, reversed, batch)) = &source {
            let original = &entries[source_vid].0;
            if !batches.contains_key(source_vid) {
                let report = match fa_journal::external_subledger::reconcile_unchanged_at(
                    db,
                    book,
                    original.entry_ref(*source_vid),
                    at,
                )? {
                    Ok(report) => report,
                    Err(r) => return Ok(Err(r)),
                };
                if !identities.insert(batch.identity()) {
                    return Ok(Err(invalid(
                        "two summaries consume the same external source batch",
                    )));
                }
                batches.insert(*source_vid, report);
            }
            contributions.push(ExternalFeedContribution {
                entry: entry.entry_ref(*vid),
                recorded_at: *recorded_at,
                effective_date: p.effective_date,
                source: original.entry_ref(*source_vid),
                reversed: *reversed,
            });
            if contributions.len() > MAX_REPORT_LEGS {
                return Ok(Err(invalid(
                    "feed reconciliation exceeds 100000 contributing entries; no entries were truncated",
                )));
            }
            // Fold the original retained detail independently of posted summary
            // legs, swapping sides only for validated exact reversal ancestry.
            for row in &batch.rows {
                if row.account != request.control_account {
                    continue;
                }
                let credit = (row.side == Side::Credit) != *reversed;
                add(
                    columns
                        .entry((row.amount.unit.0, row.dimensions.clone()))
                        .or_default(),
                    usize::from(credit),
                    row.amount.mantissa,
                )?;
            }
        }
        for (ordinal, leg) in p.legs.iter().enumerate() {
            if leg.account_ref != request.control_account {
                continue;
            }
            count = count.checked_add(1).ok_or(RegisterError::Overflow)?;
            if count > MAX_REPORT_LEGS {
                return Ok(Err(invalid(
                    "control reconciliation exceeds 100000 legs; no rows were truncated",
                )));
            }
            let index = if pending { 4 } else { 2 } + usize::from(leg.side == Side::Credit);
            add(
                columns
                    .entry((leg.amount.unit.0, leg.dimension_set.clone()))
                    .or_default(),
                index,
                leg.amount.mantissa,
            )?;
            if source.is_none() {
                unattributed.push(ExternalFeedLeg {
                    entry: entry.entry_ref(*vid),
                    ordinal: u32::try_from(ordinal).map_err(|_| RegisterError::Overflow)?,
                    unit: leg.amount.unit,
                    side: leg.side,
                    amount: leg.amount.mantissa,
                    dimension_set: leg.dimension_set.clone(),
                    pending,
                });
            }
        }
    }
    let rows: Vec<_> = columns
        .into_iter()
        .map(|((unit_id, dimension_set), c)| ExternalFeedRow {
            unit_id,
            dimension_set,
            detail_debits: c[0],
            detail_credits: c[1],
            control_debits: c[2],
            control_credits: c[3],
            pending_debits: c[4],
            pending_credits: c[5],
        })
        .collect();
    let mut sums: BTreeMap<u32, [i128; 6]> = BTreeMap::new();
    for row in &rows {
        let total = sums.entry(row.unit_id).or_default();
        for (index, amount) in row.columns().into_iter().enumerate() {
            add(total, index, amount)?;
        }
    }
    let registers: BTreeMap<_, _> = control
        .rows
        .into_iter()
        .filter(|row| row.account == request.control_account)
        .map(|row| {
            (
                row.unit_id,
                [
                    row.debits,
                    row.credits,
                    row.debits_pending,
                    row.credits_pending,
                ],
            )
        })
        .collect();
    let units: BTreeSet<_> = sums.keys().chain(registers.keys()).copied().collect();
    let totals: Vec<_> = units
        .into_iter()
        .map(|unit_id| {
            let s = sums.get(&unit_id).copied().unwrap_or([0; 6]);
            let r = registers.get(&unit_id).copied().unwrap_or([0; 4]);
            ExternalFeedTotal {
                unit_id,
                detail_debits: s[0],
                detail_credits: s[1],
                control_debits: s[2],
                control_credits: s[3],
                pending_debits: s[4],
                pending_credits: s[5],
                register_debits: r[0],
                register_credits: r[1],
                register_debits_pending: r[2],
                register_credits_pending: r[3],
            }
        })
        .collect();
    let reconciled = unattributed.is_empty()
        && rows.iter().all(ExternalFeedRow::is_reconciled)
        && totals.iter().all(ExternalFeedTotal::is_reconciled);
    let report = ExternalFeedReconciliation {
        book_id: book.book_id,
        known_at: at,
        feed: request.feed.clone(),
        control_account: request.control_account,
        effective_through: request.effective_through,
        batches: batches.into_values().collect(),
        contributions,
        unattributed,
        rows,
        totals,
        reconciled,
    };
    if let Err(refusal) = report.canonical_size() {
        return Ok(Err(refusal));
    }
    Ok(Ok(report))
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Compare the complete named feed with every gross side on one control leaf.
    /// Zero-net ordinary postings remain explicit uncovered activity.
    pub fn reconcile_external_feed(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &ExternalFeedRequest,
    ) -> Outcome<ExternalFeedReconciliation> {
        let at = match authorize(self, cx, principal, capability, request.known_at, false)? {
            Ok(at) => at,
            Err(r) => return Ok(Err(r)),
        };
        let request = match normalize(request, at) {
            Ok(r) => r,
            Err(r) => return Ok(Err(r)),
        };
        self.query(cx, |db, book| {
            let control =
                fa_registers::balance_as_of(db, book, request.effective_through, Some(at))?;
            assemble(db, cx, book, &request, control)
        })
    }
}
