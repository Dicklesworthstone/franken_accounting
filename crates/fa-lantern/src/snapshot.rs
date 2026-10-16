//! The pinned snapshot a procedure reads (plan §11.1): the trunk entry stream
//! as known at one commit sequence, read once through fa-registers' entry
//! stream reader (so the migration predicate of FA-INV-07 is applied in one
//! place), with each entry's period and approvers, the chart, the periods and
//! their transition history, and, when an effective date is declared,
//! fa-registers' historical open-item fold through it. Nothing here is a
//! clock: `known_at` is a commit sequence and `effective_through` is a
//! declared civil date.

use std::collections::BTreeMap;

use fa_journal::KernelError;
use fa_journal::genesis::BookContext;
use fa_journal::rows::{AccountRow, PeriodRow, bytes, prop};
use fa_model::symbols::{label, property};
use fa_model::{ControlPayload, Entry, EntryClass, Writer};
use fa_registers::open_items::history::{OpenItemSnapshot, open_items_as_of};
use fa_registers::{entries_at, entry_period, resolve_known_at};
use fa_time::{DateDay, PeriodState};
use fgdb::Database;
use fgdb_crypto::Hasher;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::{Coordinate, LanternError};

pub const INPUTS_DIGEST_DOMAIN: &[u8] = b"fa:lantern-inputs:v1";

/// One entry of the stream with what every procedure needs beside it.
#[derive(Clone, Debug)]
pub struct SnapshotEntry {
    pub vid: VId,
    pub entry: Entry,
    pub recorded_at: CommitSeq,
    /// The period its effective date resolves to; empty for an undated
    /// book-scoped control.
    pub period: String,
    /// Its recorded approvals as `(approval vid, approver)`, ascending by
    /// approval vid.
    pub approvals: Vec<(VId, VId)>,
}

impl SnapshotEntry {
    /// The principals behind its approvals, sorted and deduplicated.
    #[must_use]
    pub fn approvers(&self) -> Vec<VId> {
        let mut v: Vec<VId> = self.approvals.iter().map(|(_, p)| *p).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// A posting entry: carries legs and is not a reservation.
    #[must_use]
    pub fn posts(&self) -> bool {
        !self.entry.proposal.legs.is_empty() && self.entry.proposal.class != EntryClass::PENDING
    }
}

/// One journaled period transition (a `PeriodControl` record).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transition {
    pub recorded_at: CommitSeq,
    pub from: PeriodState,
    pub to: PeriodState,
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub coordinate: Coordinate,
    /// Ascending by vid.
    pub entries: Vec<SnapshotEntry>,
    pub accounts: BTreeMap<VId, AccountRow>,
    /// By period code, this book's calendar only.
    pub periods: BTreeMap<String, PeriodRow>,
    /// By period code, ascending by commit.
    pub transitions: BTreeMap<String, Vec<Transition>>,
    /// fa-registers' historical open-item fold through the coordinate's
    /// effective date; `None` when the run declared no effective date.
    pub open_items_as_of: Option<OpenItemSnapshot>,
    /// Validated REA graph snapshot (`Party`, `Instrument`, `LegalEntity`,
    /// `ExternalId`, and valid-time `OWNS`/`CONTROLS`/`RELATED_TO` edges) at `known_at`.
    pub rea: fa_journal::rea::ReaSnapshot,
    /// Journaled attestations (`Reviewed`, `ManualAssertion`, `RegisterEquals`)
    /// belonging to this book as known at `known_at`.
    pub attestations: BTreeMap<VId, fa_journal::attestation::StoredAttestation>,
    /// `H(domain ‖ known_at ‖ (vid, entry_digest, recorded_at)*)`.
    pub inputs_digest: [u8; 32],
}

impl Snapshot {
    /// Read the trunk of `book` as known at `known_at` (the head when `None`)
    /// and, when `effective_through` is declared, fa-registers' historical
    /// open-item fold through it.
    pub fn read<V: asupersync::fs::Vfs + Clone>(
        db: &Database<V>,
        book: &BookContext,
        known_at: Option<CommitSeq>,
        effective_through: Option<DateDay>,
    ) -> Result<Self, LanternError> {
        let seq = resolve_known_at(db, known_at)?;
        let mut entries = Vec::new();
        let mut transitions: BTreeMap<String, Vec<Transition>> = BTreeMap::new();
        for (vid, entry, recorded_at) in entries_at(db, book, seq)? {
            if let Some(ControlPayload::PeriodTransition {
                period_ref,
                from,
                to,
                ..
            }) = &entry.proposal.control
            {
                let (Some(from), Some(to)) =
                    (PeriodState::from_tag(*from), PeriodState::from_tag(*to))
                else {
                    return Err(KernelError::Corrupt(
                        "period transition carries an unknown state tag".into(),
                    )
                    .into());
                };
                transitions
                    .entry(period_ref.code.clone())
                    .or_default()
                    .push(Transition {
                        recorded_at,
                        from,
                        to,
                    });
            }
            let period = match entry_period(book, &entry) {
                Ok(p) => p,
                Err(_) if entry.proposal.legs.is_empty() => String::new(),
                Err(e) => return Err(e.into()),
            };
            let mut approvals = Vec::with_capacity(entry.approvals.len());
            for a in &entry.approvals {
                let Some(row) = db.vertex_at(a.approval_vid, seq)? else {
                    return Err(KernelError::Corrupt(
                        "an entry cites an approval the book does not hold".into(),
                    )
                    .into());
                };
                let payload = bytes(&row, property::FA_PAYLOAD, "approval.payload")?;
                approvals.push((
                    a.approval_vid,
                    fa_policy::Approval::decode(&payload)?.principal,
                ));
            }
            approvals.sort_by_key(|(vid, _)| *vid);
            entries.push(SnapshotEntry {
                vid,
                entry,
                recorded_at,
                period,
                approvals,
            });
        }
        entries.sort_by_key(|e| e.vid);
        for list in transitions.values_mut() {
            list.sort_by_key(|t| t.recorded_at);
        }
        let mut accounts = BTreeMap::new();
        let mut periods = BTreeMap::new();
        let mut attestations = BTreeMap::new();
        for row in db.vertices_at(seq)? {
            if row.labels.contains(&label::ACCOUNT) {
                let same_book = matches!(
                    prop(&row, property::BOOK_ID),
                    Some(CanonicalScalar::Bytes(b)) if b.as_slice() == &book.book_id.0[..]
                );
                if same_book {
                    let a = AccountRow::decode(&row)?;
                    accounts.insert(a.vid, a);
                }
            } else if row.labels.contains(&label::PERIOD) {
                let p = PeriodRow::decode(&row)?;
                if p.calendar_id == book.calendar.id {
                    periods.insert(p.code.clone(), p);
                }
            } else if row.labels.contains(&label::ATTESTATION) {
                let same_book = matches!(
                    prop(&row, property::BOOK_ID),
                    Some(CanonicalScalar::Bytes(b)) if b.as_slice() == &book.book_id.0[..]
                );
                if same_book {
                    let payload = bytes(&row, property::FA_PAYLOAD, "attestation.payload")?;
                    let att = fa_journal::attestation::StoredAttestation::decode(&payload)?;
                    attestations.insert(row.vid, att);
                }
            }
        }
        let rea = match fa_journal::rea::read_rea_at(db, book, seq) {
            Ok(s) => s,
            Err(KernelError::Corrupt(msg)) if msg.contains("no book spec") => {
                fa_journal::rea::ReaSnapshot {
                    known_at: seq,
                    parties: BTreeMap::new(),
                    instruments: BTreeMap::new(),
                    legal_entities: BTreeMap::new(),
                    external_ids: BTreeMap::new(),
                    relationships: Vec::new(),
                    events: BTreeMap::new(),
                }
            }
            Err(e) => return Err(e.into()),
        };
        let open_items_as_of = match effective_through {
            Some(through) => Some(open_items_as_of(db, book, None, through, Some(seq))?),
            None => None,
        };
        let inputs_digest = {
            let mut w = Writer::new();
            w.u64(seq.0).opt(effective_through.as_ref(), |w, d| {
                w.i32(d.0);
            });
            w.list(&entries, |w, e| {
                w.u128(e.vid.0)
                    .fixed(&e.entry.entry_digest)
                    .u64(e.recorded_at.0);
            });
            let mut h = Hasher::new();
            h.update(INPUTS_DIGEST_DOMAIN);
            h.update(&w.finish()?);
            h.finalize().0
        };
        Ok(Self {
            coordinate: Coordinate {
                book_id: book.book_id,
                known_at: seq,
                effective_through,
            },
            entries,
            accounts,
            periods,
            transitions,
            open_items_as_of,
            rea,
            attestations,
            inputs_digest,
        })
    }

    /// The period row an entry resolves to, when this calendar has it.
    #[must_use]
    pub fn period_of(&self, e: &SnapshotEntry) -> Option<&PeriodRow> {
        self.periods.get(&e.period)
    }

    /// The period code a date resolves to in this book's calendar.
    pub fn period_code_of(
        &self,
        book: &BookContext,
        date: fa_time::DateDay,
    ) -> Result<String, LanternError> {
        self.document_period_code_of(book, date, None)
    }

    /// Resolve a document date to its period code, honoring the entry's
    /// explicit period discriminator (`hint`) when the document date lies
    /// inside that special period (e.g. an adjustment period sharing the
    /// year-end civil date with the final normal period).
    pub fn document_period_code_of(
        &self,
        book: &BookContext,
        date: fa_time::DateDay,
        hint: Option<&str>,
    ) -> Result<String, LanternError> {
        let fy = book
            .calendar
            .fiscal_year_of(date)
            .map_err(KernelError::from)?;
        let periods = book
            .calendar
            .periods_for_year(fy)
            .map_err(KernelError::from)?;
        if let Some(code) = hint
            && let Ok(p) = fa_time::resolve_period(&periods, date, Some(code))
        {
            return Ok(p.code.clone());
        }
        fa_time::resolve_period(&periods, date, None)
            .map(|p| p.code.clone())
            .map_err(|e| KernelError::Corrupt(format!("period of date: {e:?}")).into())
    }

    /// Live posting entries under the §8.2 supersession netting laws,
    /// optionally bounded by an effective-date cutoff (`through`).
    ///
    /// A `Reversal` entry (`SupersessionKind::Reverses`) negates its target;
    /// a chain of reversals of reversals alternates liveness by parity
    /// (`fa_registers::open_items::is_live`). A live `Replacement` entry
    /// (`SupersessionKind::Replaces`) supersedes its target. Neither a
    /// `Reversal` entry nor a superseded target survives into the net
    /// posting stream.
    pub fn live_postings_through(
        &self,
        through: Option<DateDay>,
    ) -> Result<Vec<&SnapshotEntry>, LanternError> {
        let in_window = |e: &&SnapshotEntry| {
            e.posts() && through.is_none_or(|d| e.entry.proposal.effective_date <= d)
        };
        let mut reversed_by: BTreeMap<VId, VId> = BTreeMap::new();
        for e in self.entries.iter().filter(in_window) {
            if e.entry.proposal.class != EntryClass::REVERSAL {
                continue;
            }
            for s in &e.entry.proposal.supersession {
                if s.kind == fa_model::SupersessionKind::Reverses
                    && reversed_by.insert(s.target.vid, e.vid).is_some()
                {
                    return Err(KernelError::Corrupt("an entry is reversed twice".into()).into());
                }
            }
        }
        let mut unreversed = std::collections::BTreeSet::new();
        for e in self.entries.iter().filter(in_window) {
            if fa_registers::open_items::is_live(e.vid, &reversed_by)? {
                unreversed.insert(e.vid);
            }
        }
        let mut replaced = std::collections::BTreeSet::new();
        for e in self.entries.iter().filter(in_window) {
            if !unreversed.contains(&e.vid) {
                continue;
            }
            for s in &e.entry.proposal.supersession {
                if s.kind == fa_model::SupersessionKind::Replaces {
                    replaced.insert(s.target.vid);
                }
            }
        }
        Ok(self
            .entries
            .iter()
            .filter(in_window)
            .filter(|e| {
                e.entry.proposal.class != EntryClass::REVERSAL
                    && unreversed.contains(&e.vid)
                    && !replaced.contains(&e.vid)
            })
            .collect())
    }

    /// Live posting entries across the snapshot (`live_postings_through(None)`).
    pub fn live_postings(&self) -> Result<Vec<&SnapshotEntry>, LanternError> {
        self.live_postings_through(None)
    }

    /// Whether `a` and `b` are connected by a directed supersession chain in
    /// either direction.
    #[must_use]
    pub fn shares_supersession_lineage(&self, a: VId, b: VId) -> bool {
        if a == b {
            return true;
        }
        let by_vid: BTreeMap<VId, &[fa_model::Supersession]> = self
            .entries
            .iter()
            .filter(|e| !e.entry.proposal.supersession.is_empty())
            .map(|e| (e.vid, e.entry.proposal.supersession.as_slice()))
            .collect();
        if !by_vid.contains_key(&a) && !by_vid.contains_key(&b) {
            return false;
        }
        let reaches = |start: VId, goal: VId| -> bool {
            let Some(initial) = by_vid.get(&start) else {
                return false;
            };
            let mut stack: Vec<VId> = initial.iter().map(|s| s.target.vid).collect();
            let mut seen = std::collections::BTreeSet::new();
            seen.insert(start);
            while let Some(cur) = stack.pop() {
                if cur == goal {
                    return true;
                }
                if !seen.insert(cur) {
                    continue;
                }
                if let Some(edges) = by_vid.get(&cur) {
                    for s in *edges {
                        stack.push(s.target.vid);
                    }
                }
            }
            false
        };
        reaches(a, b) || reaches(b, a)
    }

    /// The same snapshot with its entry order reversed: the determinism
    /// witness's probe for iteration-order dependence.
    #[must_use]
    pub fn with_entries_reversed(&self) -> Self {
        let mut s = self.clone();
        s.entries.reverse();
        s
    }

    /// The same snapshot with every entry's legs reversed (ordinals move with
    /// them, so only statistics are comparable across this probe).
    #[must_use]
    pub fn with_legs_reversed(&self) -> Self {
        let mut s = self.clone();
        for e in &mut s.entries {
            e.entry.proposal.legs.reverse();
        }
        s
    }
}
