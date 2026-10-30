//! Prepublication representability, independent of derived registers.
//!
//! The interim implementation folds the final transaction overlay. Its full
//! vertex scan retains the substrate's insertion/read witnesses for staged
//! batches. A prepared post checks the current prefix under the database's
//! exclusive publication borrow without adding unrelated old-basis witnesses.
//! No balance is persisted.
//! Each account/unit stock gross column bounds its period, entity and dimension
//! subsets because monetary legs are nonnegative. Cross-account report totals
//! are not registered cells and are deliberately outside this admission law.

use std::collections::{BTreeMap, BTreeSet};

use fa_model::symbols::{label, property};
use fa_model::{Entry, EntryClass, EntryOrigin, EntryPayload, Id128, LegPayload};
use fa_money::{Side, UnitId};
use fgdb::{Database, VertexRow, WriteTxn, WriteTxnError};
use fgdb_delta_types::{DeltaRow, ElementId};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, MarkerRef, VId};

use crate::refusal::{KernelError, Outcome, Refusal, code, exit};

/// The (unit, functional, mantissa) cells one leg adds to: its native amount,
/// and its functional valuation in the base unit where it has one. Native-only
/// interim paths have no functional projection; absence is not a fabricated
/// zero valuation.
fn leg_columns(leg: &LegPayload, base: UnitId) -> Result<Vec<(UnitId, bool, i128)>, KernelError> {
    let functional = match leg.base_amount {
        Some(amount) if amount.unit == base && amount.mantissa >= 0 => {
            if leg.amount.unit == base && amount != leg.amount {
                return Err(KernelError::Corrupt(
                    "base-unit leg has inconsistent functional valuation".into(),
                ));
            }
            Some(amount.mantissa)
        }
        Some(_) => return Err(KernelError::Corrupt("invalid functional valuation".into())),
        None if leg.amount.unit == base => Some(leg.amount.mantissa),
        None => None,
    };
    Ok(
        std::iter::once((leg.amount.unit, false, leg.amount.mantissa))
            .chain(functional.map(|m| (base, true, m)))
            .collect(),
    )
}

/// The registered `max_register_mantissa`, parsed once per process.
fn maximum() -> Result<i128, KernelError> {
    static MAXIMUM: std::sync::OnceLock<Result<i128, String>> = std::sync::OnceLock::new();
    MAXIMUM
        .get_or_init(|| fa_registry::register_capacity_embedded().map_err(|e| e.to_string()))
        .clone()
        .map_err(KernelError::Corrupt)
}

pub(crate) fn accounts<'a>(proposals: impl IntoIterator<Item = &'a EntryPayload>) -> BTreeSet<VId> {
    proposals
        .into_iter()
        .flat_map(|p| p.legs.iter().map(|l| l.account_ref))
        .collect()
}

/// Called only after payload scope/authority admission. Restrict financial
/// evaluation, diagnostics, and point-read conflict witnesses to accounts in
/// the authorized proposed effects.
pub(crate) fn admit<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    ctx: &PurposeContexts,
    book_id: Id128,
    accounts: &BTreeSet<VId>,
    staged: impl IntoIterator<Item = VId>,
) -> Outcome<()> {
    admit_including(txn, db, ctx, book_id, accounts, staged, &[])
}

/// Re-evaluate a prepared post's financial effects at the publication frontier.
/// The caller retains `&mut Database` through this synchronous check and the
/// immediately following native commit: the substrate's single writer lease
/// and Rust borrow exclude another publication between them. The fresh read
/// transaction is aborted, not substituted for the preparation's original
/// period, authority, policy, identity and accounting witnesses.
pub(crate) fn admit_publication<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book_id: Id128,
    entries: &[(VId, &Entry)],
) -> Outcome<()> {
    ctx.txn().checkpoint().map_err(WriteTxnError::Interrupted)?;
    let accounts = accounts(entries.iter().map(|(_, entry)| &entry.proposal));
    let txn = db.begin(&ctx.txn())?;
    let outcome = admit_including(
        &txn,
        db,
        ctx,
        book_id,
        &accounts,
        std::iter::empty(),
        entries,
    );
    txn.abort();
    outcome
}

/// Automatic effects need a verdict before staging, so a blocked schedule
/// can be skipped without leaving any of its financial effects in the batch.
pub(crate) fn admit_addition<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    ctx: &PurposeContexts,
    staged: impl IntoIterator<Item = VId>,
    vid: VId,
    entry: &Entry,
) -> Outcome<()> {
    let accounts = accounts([&entry.proposal]);
    admit_including(
        txn,
        db,
        ctx,
        entry.proposal.book_id,
        &accounts,
        staged,
        &[(vid, entry)],
    )
}

fn admit_including<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    ctx: &PurposeContexts,
    book_id: Id128,
    accounts: &BTreeSet<VId>,
    staged: impl IntoIterator<Item = VId>,
    extra: &[(VId, &Entry)],
) -> Outcome<()> {
    ctx.txn().checkpoint().map_err(WriteTxnError::Interrupted)?;
    if accounts.is_empty() {
        return Ok(Ok(()));
    }
    for account in accounts {
        txn.vertex(db, *account)?;
    }
    let maximum = maximum()?;
    let base = crate::genesis::read_book_spec_at(db, txn.basis())?
        .ok_or_else(|| KernelError::Corrupt("register capacity requires a book".into()))?
        .base_unit;
    let mut rows: BTreeMap<VId, _> = db
        .vertices_at(txn.basis())?
        .into_iter()
        .filter(|row| row.labels.contains(&label::ENTRY))
        .map(|row| (row.vid, row))
        .collect();
    for vid in staged {
        if let Some(row) = txn.vertex(db, vid)?
            && row.labels.contains(&label::ENTRY)
        {
            rows.insert(vid, row);
        }
    }
    let mut entries = Vec::new();
    let mut runs = BTreeMap::new();
    for row in rows.into_values() {
        ctx.txn().checkpoint().map_err(WriteTxnError::Interrupted)?;
        let entry = Entry::decode(&crate::rows::bytes(
            &row,
            property::FA_PAYLOAD,
            "entry._fa_payload",
        )?)?;
        if entry.proposal.book_id != book_id || entry.proposal.branch_id != Id128::TRUNK {
            continue;
        }
        let relevant = entry.proposal.class == EntryClass::RESOLUTION
            || entry
                .proposal
                .legs
                .iter()
                .any(|l| accounts.contains(&l.account_ref));
        if !relevant {
            continue;
        }
        if !crate::migration::visible_in(txn, db, &entry, &mut runs)? {
            continue;
        }
        entries.push((row.vid, entry));
    }
    for &(vid, entry) in extra {
        // An intervening publication may already have spent this identity.
        // The original transaction decides that race; never count it twice.
        if !entries.iter().any(|(existing, _)| *existing == vid)
            && crate::migration::visible_in(txn, db, entry, &mut runs)?
        {
            entries.push((vid, entry.clone()));
        }
    }
    let mut resolved = BTreeSet::new();
    for (_, entry) in &entries {
        if entry.proposal.class == EntryClass::RESOLUTION {
            let target = entry
                .proposal
                .pending
                .as_ref()
                .and_then(|p| p.resolution_of)
                .ok_or_else(|| KernelError::Corrupt("resolution has no pending target".into()))?;
            resolved.insert(target.vid);
        }
    }
    // Resolve first: an old hold may have exceeded a prospective sum yet be
    // released in this same atomic publication, including across periods.
    let mut cells: BTreeMap<(VId, UnitId, bool), [i128; 4]> = BTreeMap::new();
    for (vid, entry) in entries {
        ctx.txn().checkpoint().map_err(WriteTxnError::Interrupted)?;
        let pending = entry.proposal.class == EntryClass::PENDING;
        if pending && resolved.contains(&vid) {
            continue;
        }
        for leg in &entry.proposal.legs {
            if !accounts.contains(&leg.account_ref) {
                continue;
            }
            let column = usize::from(pending) * 2 + usize::from(leg.side == Side::Credit);
            for (unit, functional, mantissa) in leg_columns(leg, base)? {
                let cell = cells
                    .entry((leg.account_ref, unit, functional))
                    .or_default();
                let next = cell[column].checked_add(mantissa);
                if mantissa < 0 {
                    return Err(KernelError::Corrupt("negative register leg".into()));
                }
                let Some(next) = next.filter(|v| *v <= maximum) else {
                    return Ok(Err(Refusal::new(
                        code::REGISTER_CAPACITY,
                        exit::REFUSAL,
                        format!(
                            "account {:032x}, unit {}, {} stock {}: fold addition {} + {} at entry {:032x} exceeds max_register_mantissa {} at guarded prefix {}",
                            leg.account_ref.0,
                            unit.0,
                            if functional { "functional" } else { "native" },
                            [
                                "posted debit",
                                "posted credit",
                                "pending debit",
                                "pending credit"
                            ][column],
                            cell[column],
                            mantissa,
                            vid.0,
                            maximum,
                            txn.basis().0
                        ),
                        "plan §5.2; limits.toml register_capacity",
                        "reduce the proposed gross activity; a reversal increases gross activity, so preserve any historical over-cap prefix for diagnosis rather than attempting a corrective reversal",
                    )));
                };
                cell[column] = next;
            }
        }
    }
    Ok(Ok(()))
}

/// The gross columns of every committed entry of the book at one prefix,
/// carried between a long-lived book's own writes so admission reads only
/// what changed since (fa-rcw1). It is never more authoritative than the
/// scan: it only ever lets admission answer "fits" where the scan above would
/// answer the same, and every other case runs that scan.
#[derive(Clone, Debug)]
pub struct CapacityHistory {
    at: CommitSeq,
    /// The Chronicle marker of the commit at `at`: the summary is only ever
    /// carried forward on the database whose prefix it describes.
    marker: Option<MarkerRef>,
    /// `None` once the book holds something the summary cannot stand for: an
    /// entry that does not decode or whose leg is invalid, a column past the
    /// maximum, or a change to a committed entry. Migration visibility is
    /// summarized at this prefix and witnessed again for affected accounts.
    cells: Option<Cells>,
    /// The delta rows examined to carry this summary forward, or `None` when
    /// it was summarized from the whole book.
    carried_rows: Option<u64>,
    /// Work of the last admission attempt, separate from carrying the
    /// committed prefix. A carried prefix alone does not prove that admission
    /// avoided the literal scan.
    admission: SummaryAdmission,
}

impl CapacityHistory {
    /// The delta rows examined to carry this summary forward from the
    /// previous one, or `None` when the book was summarized in full (fa-rcw1's
    /// work witness: a carried post reads the new commits, not the book).
    #[must_use]
    pub fn carried_rows(&self) -> Option<u64> {
        self.carried_rows
    }

    /// The committed prefix this summary describes.
    #[must_use]
    pub fn verified_at(&self) -> CommitSeq {
        self.at
    }

    /// Whether admission can still answer from this summary.
    #[must_use]
    pub fn summarized(&self) -> bool {
        self.cells.is_some()
    }

    /// Whether the last carried admission answered from the summary rather
    /// than falling back to the literal whole-book capacity scan. This does
    /// not count the initial construction or later extension of the summary.
    #[must_use]
    pub fn admitted_from_summary(&self) -> bool {
        self.admission.fits
    }

    /// Original Pending targets point-read by the last carried admission.
    /// This excludes the earlier history extension and any literal fallback.
    #[must_use]
    pub fn resolution_targets_read(&self) -> usize {
        self.admission.targets_read
    }

    /// Migration runs point-witnessed for affected accounts by the last
    /// carried admission. This counts runs, never their imported chunks.
    #[must_use]
    pub fn migration_runs_read(&self) -> usize {
        self.admission.migration_runs_read
    }
}

#[derive(Clone, Debug, Default)]
struct SummaryAdmission {
    fits: bool,
    targets_read: usize,
    migration_runs_read: usize,
}

#[derive(Clone, Debug)]
struct Cells {
    book_id: Id128,
    base: UnitId,
    maximum: i128,
    columns: BTreeMap<(VId, UnitId, bool), [i128; 4]>,
    /// Pending entries a committed Resolution released.
    released: BTreeSet<VId>,
    /// Both visible and hidden migration chunks depend on their run's body
    /// and state. Retain that exact row once per run, and index the accounts
    /// it can affect so ordinary admissions witness only relevant runs.
    migration_runs: BTreeMap<VId, VertexRow>,
    migration_accounts: BTreeMap<VId, BTreeSet<VId>>,
}

impl Cells {
    /// Apply the literal scan's migration predicate while retaining its
    /// dependencies even for staged, abandoned, or opening-summarized detail.
    /// A later Finalize or a changed run body invalidates these cells before
    /// they can be used at the new prefix.
    fn visible<V: asupersync::fs::Vfs + Clone>(
        &mut self,
        db: &Database<V>,
        entry: &Entry,
        at: CommitSeq,
        visibility: &mut BTreeMap<VId, crate::migration::RunVisibility>,
    ) -> Result<bool, KernelError> {
        if let EntryOrigin::Migration { run_ref, .. } = &entry.proposal.origin {
            if entry.proposal.class != EntryClass::MIGRATION {
                return Err(KernelError::Corrupt(
                    "non-Migration entry claims migration provenance".into(),
                ));
            }
            if !self.migration_runs.contains_key(run_ref) {
                let row = db
                    .vertex_at(*run_ref, at)?
                    .ok_or_else(|| KernelError::Corrupt("migration run is missing".into()))?;
                self.migration_runs.insert(*run_ref, row);
            }
            for leg in &entry.proposal.legs {
                self.migration_accounts
                    .entry(leg.account_ref)
                    .or_default()
                    .insert(*run_ref);
            }
        }
        crate::migration::visible_at(db, entry, at, visibility)
    }

    /// Add (or remove) `entry`'s legs; `false` when the summary can no
    /// longer stand for the scan.
    fn fold(&mut self, entry: &Entry, remove: bool) -> bool {
        let pending = entry.proposal.class == EntryClass::PENDING;
        for leg in &entry.proposal.legs {
            let column = usize::from(pending) * 2 + usize::from(leg.side == Side::Credit);
            let Ok(cells) = leg_columns(leg, self.base) else {
                return false;
            };
            for (unit, functional, mantissa) in cells {
                if mantissa < 0 {
                    return false;
                }
                let cell = self
                    .columns
                    .entry((leg.account_ref, unit, functional))
                    .or_default();
                let next = if remove {
                    cell[column].checked_sub(mantissa)
                } else {
                    cell[column].checked_add(mantissa)
                };
                let Some(next) = next.filter(|v| (0..=self.maximum).contains(v)) else {
                    return false;
                };
                cell[column] = next;
            }
        }
        true
    }

    /// Fold newly committed entries: their releases first, so no column
    /// passes through a sum its final state does not have. `earlier` reads a
    /// pending entry committed before them.
    fn absorb(
        &mut self,
        entries: &[(VId, Entry)],
        mut earlier: impl FnMut(VId) -> Result<Option<Entry>, KernelError>,
    ) -> Result<bool, KernelError> {
        let mut released = BTreeSet::new();
        for (_, entry) in entries {
            if entry.proposal.class == EntryClass::RESOLUTION {
                let Some(target) = entry
                    .proposal
                    .pending
                    .as_ref()
                    .and_then(|p| p.resolution_of)
                else {
                    return Ok(false);
                };
                released.insert(target.vid);
            }
        }
        for target in &released {
            if self.released.contains(target) || entries.iter().any(|(vid, _)| vid == target) {
                continue;
            }
            if let Some(hold) = earlier(*target)?
                && hold.proposal.class == EntryClass::PENDING
                && !self.fold(&hold, true)
            {
                return Ok(false);
            }
        }
        self.released.extend(released);
        for (vid, entry) in entries {
            if entry.proposal.class == EntryClass::PENDING && self.released.contains(vid) {
                continue;
            }
            if !self.fold(entry, false) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// This book's trunk entry at `vid` as of `at`, or `None` for another kind of
/// vertex, another book's entry, or an undecodable payload.
fn entry_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book_id: Id128,
    vid: VId,
    at: CommitSeq,
) -> Result<Result<Option<Entry>, ()>, KernelError> {
    let Some(row) = db.vertex_at(vid, at)? else {
        return Ok(Ok(None));
    };
    if !row.labels.contains(&label::ENTRY) {
        return Ok(Ok(None));
    }
    let Ok(bytes) = crate::rows::bytes(&row, property::FA_PAYLOAD, "entry._fa_payload") else {
        return Ok(Err(()));
    };
    let Ok(entry) = Entry::decode(&bytes) else {
        return Ok(Err(()));
    };
    if entry.proposal.book_id != book_id || entry.proposal.branch_id != Id128::TRUNK {
        return Ok(Ok(None));
    }
    Ok(Ok(Some(entry)))
}

/// Summarize the whole book at `at`, as the scan folds it for every account.
fn summarize<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    ctx: &PurposeContexts,
    book_id: Id128,
    at: CommitSeq,
) -> Result<CapacityHistory, KernelError> {
    let marker = crate::rows::marker_at(db, at)?;
    let unusable = CapacityHistory {
        at,
        marker,
        cells: None,
        carried_rows: None,
        admission: SummaryAdmission::default(),
    };
    let Some(spec) = crate::genesis::read_book_spec_at(db, at)? else {
        return Ok(unusable);
    };
    let mut cells = Cells {
        book_id,
        base: spec.base_unit,
        maximum: maximum()?,
        columns: BTreeMap::new(),
        released: BTreeSet::new(),
        migration_runs: BTreeMap::new(),
        migration_accounts: BTreeMap::new(),
    };
    let mut entries = Vec::new();
    let mut visibility = BTreeMap::new();
    for row in db.vertices_at(at)? {
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        ctx.txn().checkpoint().map_err(WriteTxnError::Interrupted)?;
        match entry_at(db, book_id, row.vid, at)? {
            Ok(Some(entry)) => match cells.visible(db, &entry, at, &mut visibility) {
                Ok(true) => entries.push((row.vid, entry)),
                Ok(false) => {}
                // A bad unrelated run must not introduce a new verdict:
                // let the account-scoped literal admission decide it.
                Err(_) => return Ok(unusable),
            },
            Ok(None) => {}
            Err(()) => return Ok(unusable),
        }
    }
    if !cells.absorb(&entries, |_| Ok(None))? {
        return Ok(unusable);
    }
    Ok(CapacityHistory {
        at,
        marker,
        cells: Some(cells),
        carried_rows: None,
        admission: SummaryAdmission::default(),
    })
}

/// `history` carried forward to `at` over the commits since, or `None` when
/// it cannot be (another database, a prefix behind it, a sequence gap): the
/// caller then summarizes the book afresh.
fn carry<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    ctx: &PurposeContexts,
    history: CapacityHistory,
    at: CommitSeq,
) -> Result<Option<CapacityHistory>, KernelError> {
    if history.at > at
        || history.marker.is_none()
        || crate::rows::marker_at(db, history.at)? != history.marker
    {
        return Ok(None);
    }
    let marker = crate::rows::marker_at(db, at)?;
    let Some(mut cells) = history.cells else {
        // A book the summary could not stand for stays so: entries are
        // immutable, and every such cause persists.
        return Ok(Some(CapacityHistory {
            at,
            marker,
            cells: None,
            carried_rows: Some(0),
            admission: SummaryAdmission::default(),
        }));
    };
    let mut born = Vec::new();
    let mut usable = true;
    let mut migration_changed = false;
    let mut through = history.at.0;
    let mut examined = 0u64;
    for batch in db.delta_since(history.at)? {
        let seq = batch.commit_seq();
        if seq > at {
            break;
        }
        if through.checked_add(1) != Some(seq.0) {
            return Ok(None);
        }
        for coordinate in batch.coordinate_entries() {
            for delta in &coordinate.rows {
                ctx.txn().checkpoint().map_err(WriteTxnError::Interrupted)?;
                examined = examined.saturating_add(1);
                match delta {
                    DeltaRow::CreateVertex { vid, labels, .. } => {
                        if labels.contains(&label::ENTRY) {
                            born.push(*vid);
                        }
                    }
                    DeltaRow::CreateEdge { .. }
                    | DeltaRow::DeleteEdge { .. }
                    | DeltaRow::Property {
                        elem: ElementId::Edge(_),
                        ..
                    } => {}
                    DeltaRow::Property {
                        elem: ElementId::Vertex(vid),
                        ..
                    }
                    | DeltaRow::LabelMembership { vid, .. }
                    | DeltaRow::DeleteVertex { vid, .. }
                        if cells.migration_runs.contains_key(vid) =>
                    {
                        // Finalize makes prior chunks visible without new
                        // Entry births. Rebuild once at this prefix instead
                        // of poisoning every later ordinary admission.
                        // Any other run mutation takes the same exact path.
                        migration_changed = true;
                    }
                    DeltaRow::LabelMembership { label: flipped, .. }
                        if *flipped == label::ENTRY =>
                    {
                        usable = false;
                    }
                    DeltaRow::LabelMembership { vid, .. }
                    | DeltaRow::Property {
                        elem: ElementId::Vertex(vid),
                        ..
                    } => {
                        // A committed entry is immutable; a change to one is
                        // beyond what the summary stands for.
                        if db
                            .vertex_at(*vid, at)?
                            .is_some_and(|row| row.labels.contains(&label::ENTRY))
                        {
                            usable = false;
                        }
                    }
                    _ => usable = false,
                }
            }
        }
        through = seq.0;
    }
    if through != at.0 {
        return Ok(None);
    }
    if usable && migration_changed {
        return Ok(None);
    }
    if usable {
        let mut entries = Vec::new();
        let mut visibility = BTreeMap::new();
        for vid in born {
            match entry_at(db, cells.book_id, vid, at)? {
                Ok(Some(entry)) => match cells.visible(db, &entry, at, &mut visibility) {
                    Ok(true) => entries.push((vid, entry)),
                    Ok(false) => {}
                    Err(_) => {
                        usable = false;
                        break;
                    }
                },
                Ok(None) => {}
                Err(()) => {
                    usable = false;
                    break;
                }
            }
        }
        let book_id = cells.book_id;
        usable = usable
            && cells.absorb(&entries, |vid| {
                Ok(entry_at(db, book_id, vid, history.at)?.unwrap_or(None))
            })?;
    }
    Ok(Some(CapacityHistory {
        at,
        marker,
        cells: usable.then_some(cells),
        carried_rows: Some(examined),
        admission: SummaryAdmission::default(),
    }))
}

/// Whether the summarized columns plus the staged and proposed legs fit, for
/// the affected accounts. `true` only where the scan would also admit: every
/// migration run retains its summarized visibility, every leg is valid, and
/// every final column is within the maximum.
/// Resolutions remove their original Pending vectors before any additions,
/// including new holds in the same atomic batch. Only columns touched by
/// these effects are copied from the summary; unrelated history is not read.
/// Anything this shortcut cannot prove still receives the original scan and
/// its original first error. The scan's account witnesses are retained.
fn fits<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    cells: &Cells,
    book_id: Id128,
    accounts: &BTreeSet<VId>,
    staged: &[VId],
    extra: Option<(VId, &Entry)>,
) -> Result<SummaryAdmission, KernelError> {
    let mut admission = SummaryAdmission::default();
    for account in accounts {
        txn.vertex(db, *account)?;
    }
    if cells.book_id != book_id || cells.maximum != maximum()? {
        return Ok(admission);
    }
    match crate::genesis::read_book_spec_at(db, txn.basis())? {
        Some(spec) if spec.base_unit == cells.base => {}
        _ => return Ok(admission),
    }
    let runs: BTreeSet<_> = accounts
        .iter()
        .filter_map(|account| cells.migration_accounts.get(account))
        .flatten()
        .copied()
        .collect();
    for run in runs {
        admission.migration_runs_read = admission.migration_runs_read.saturating_add(1);
        let Some(expected) = cells.migration_runs.get(&run) else {
            return Ok(admission);
        };
        let Some(current) = txn.vertex(db, run)? else {
            return Ok(admission);
        };
        // These are the same full-row and state point witnesses that
        // visible_in retains in the literal path. A staged transition or
        // changed body must be judged by that path, never stale totals.
        let state = txn.vertex_property(db, run, property::STATE)?;
        if current.labels != expected.labels
            || current.props != expected.props
            || current.created_at != expected.created_at
            || current.birth_ordinal != expected.birth_ordinal
            || current.retired_at != expected.retired_at
            || state.as_ref() != crate::rows::prop(expected, property::STATE)
        {
            return Ok(admission);
        }
    }
    // The literal scan overlays staged identities in a map. Preserve that
    // set rather than charging a repeated staged identity more than once.
    let mut proposed = BTreeMap::new();
    for vid in staged {
        if let Some(row) = txn.vertex(db, *vid)?
            && row.labels.contains(&label::ENTRY)
        {
            let Ok(bytes) = crate::rows::bytes(&row, property::FA_PAYLOAD, "entry._fa_payload")
            else {
                return Ok(admission);
            };
            let Ok(entry) = Entry::decode(&bytes) else {
                return Ok(admission);
            };
            if entry.proposal.book_id == book_id && entry.proposal.branch_id == Id128::TRUNK {
                proposed.insert(*vid, entry);
            }
        }
    }
    if let Some((vid, entry)) = extra {
        proposed.entry(vid).or_insert_with(|| entry.clone());
    }
    let mut releases = BTreeMap::new();
    for entry in proposed.values() {
        if matches!(entry.proposal.origin, EntryOrigin::Migration { .. }) {
            return Ok(admission);
        }
        if entry.proposal.class == EntryClass::RESOLUTION {
            let Some(target) = entry
                .proposal
                .pending
                .as_ref()
                .and_then(|pending| pending.resolution_of)
            else {
                return Ok(admission);
            };
            if cells.released.contains(&target.vid)
                || releases.insert(target.vid, target.entry_digest).is_some()
            {
                return Ok(admission);
            }
        }
    }
    let mut columns: BTreeMap<(VId, UnitId, bool), [i128; 4]> = BTreeMap::new();
    for (target, digest) in &releases {
        admission.targets_read = admission.targets_read.saturating_add(1);
        let original = match entry_at(db, book_id, *target, txn.basis())? {
            Ok(original) => original,
            Err(()) => return Ok(admission),
        };
        // An original born inside this batch has never contributed to the
        // committed summary. It is omitted below, not subtracted from an
        // older hold that happens to use the same account and unit.
        let Some(hold) = original.as_ref().or_else(|| proposed.get(target)) else {
            return Ok(admission);
        };
        if hold.proposal.class != EntryClass::PENDING || hold.entry_digest != *digest {
            return Ok(admission);
        }
        if original.is_some() && !fit_columns(cells, accounts, &mut columns, hold, true) {
            return Ok(admission);
        }
    }
    for (vid, entry) in &proposed {
        if entry.proposal.class == EntryClass::PENDING && releases.contains_key(vid) {
            continue;
        }
        if !fit_columns(cells, accounts, &mut columns, entry, false) {
            return Ok(admission);
        }
    }
    admission.fits = true;
    Ok(admission)
}

/// One proposed contribution to the sparse admission overlay. Removal is
/// used only for an exactly identified, committed Pending target. Native and
/// functional columns obey the same checked bounds as the literal scan.
fn fit_columns(
    cells: &Cells,
    accounts: &BTreeSet<VId>,
    columns: &mut BTreeMap<(VId, UnitId, bool), [i128; 4]>,
    entry: &Entry,
    remove: bool,
) -> bool {
    let pending = entry.proposal.class == EntryClass::PENDING;
    for leg in &entry.proposal.legs {
        if !accounts.contains(&leg.account_ref) {
            continue;
        }
        let column = usize::from(pending) * 2 + usize::from(leg.side == Side::Credit);
        let Ok(legs) = leg_columns(leg, cells.base) else {
            return false;
        };
        for (unit, functional, mantissa) in legs {
            if mantissa < 0 {
                return false;
            }
            let key = (leg.account_ref, unit, functional);
            let cell = columns
                .entry(key)
                .or_insert_with(|| cells.columns.get(&key).copied().unwrap_or_default());
            let next = if remove {
                cell[column].checked_sub(mantissa)
            } else {
                cell[column].checked_add(mantissa)
            };
            let Some(next) = next.filter(|v| (0..=cells.maximum).contains(v)) else {
                return false;
            };
            cell[column] = next;
        }
    }
    true
}

/// [`admit`] for a long-lived book that carries `history` between its own
/// writes: where the carried summary proves the effects fit, admission
/// answers from it; otherwise it scans exactly as [`admit`] does.
pub(crate) fn admit_carried<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    ctx: &PurposeContexts,
    book_id: Id128,
    accounts: &BTreeSet<VId>,
    staged: impl IntoIterator<Item = VId>,
    history: &mut Option<CapacityHistory>,
) -> Outcome<()> {
    let staged: Vec<VId> = staged.into_iter().collect();
    admit_carried_including(txn, db, ctx, book_id, accounts, staged, None, history)
}

/// [`admit_addition`] through a carried summary, as [`admit_carried`].
pub(crate) fn admit_addition_carried<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    ctx: &PurposeContexts,
    vid: VId,
    entry: &Entry,
    history: &mut Option<CapacityHistory>,
) -> Outcome<()> {
    let accounts = accounts([&entry.proposal]);
    admit_carried_including(
        txn,
        db,
        ctx,
        entry.proposal.book_id,
        &accounts,
        Vec::new(),
        Some((vid, entry)),
        history,
    )
}

#[allow(clippy::too_many_arguments)]
fn admit_carried_including<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    ctx: &PurposeContexts,
    book_id: Id128,
    accounts: &BTreeSet<VId>,
    staged: Vec<VId>,
    extra: Option<(VId, &Entry)>,
    history: &mut Option<CapacityHistory>,
) -> Outcome<()> {
    if accounts.is_empty() {
        return Ok(Ok(()));
    }
    let basis = txn.basis();
    let carried = match history.take() {
        Some(previous) => carry(db, ctx, previous, basis)?,
        None => None,
    };
    let mut summary = match carried {
        Some(summary) => summary,
        None => summarize(db, ctx, book_id, basis)?,
    };
    summary.admission = match &summary.cells {
        Some(cells) => fits(txn, db, cells, book_id, accounts, &staged, extra)?,
        None => SummaryAdmission::default(),
    };
    let fit = summary.admission.fits;
    *history = Some(summary);
    if fit {
        return Ok(Ok(()));
    }
    admit_including(txn, db, ctx, book_id, accounts, staged, extra.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_capacity_cancellation_precedes_any_prefix_observation() {
        let runtime = asupersync::runtime::RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let ctx = PurposeContexts::narrow_runtime_root(&root);
        let keys = fgdb::DatabaseKeys::new(
            [0x5a; 32],
            fgdb_types::ids::DatabaseSecurityNamespaceId([0x5b; 32]),
            [0x5c; 32],
        );
        let mut db = runtime
            .block_on(Database::open_memory(&ctx.commit(), keys))
            .unwrap();
        let head = db.frontier().unwrap();
        let txn = db.begin(&ctx.txn()).unwrap();
        root.cancel_fast(asupersync::types::CancelKind::User);
        let accounts = BTreeSet::from([VId(1)]);
        // This database deliberately has no Book. Observing its prefix
        // before cancellation would produce Corrupt instead of Interrupted.
        let result = admit(
            &txn,
            &db,
            &ctx,
            Id128([1; 16]),
            &accounts,
            std::iter::empty(),
        );
        assert!(
            matches!(result, Err(KernelError::Txn(WriteTxnError::Interrupted(_)))),
            "{result:?}"
        );
        txn.abort();
        assert_eq!(db.frontier().unwrap(), head);
    }
}
