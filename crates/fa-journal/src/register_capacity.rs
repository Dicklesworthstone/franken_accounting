//! Prepublication representability, independent of derived registers.
//!
//! The interim implementation folds the final transaction overlay. Its full
//! vertex scan retains the substrate's insertion/read witnesses, so a prepared
//! writer cannot publish against a changed prefix. No balance is persisted.
//! Each account/unit stock gross column bounds its period, entity and dimension
//! subsets because monetary legs are nonnegative. Cross-account report totals
//! are not registered cells and are deliberately outside this admission law.

use std::collections::{BTreeMap, BTreeSet};

use fa_model::symbols::{label, property};
use fa_model::{Entry, EntryClass, EntryOrigin, EntryPayload, Id128, LegPayload};
use fa_money::{Side, UnitId};
use fgdb::{Database, WriteTxn, WriteTxnError};
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
    admit_including(txn, db, ctx, book_id, accounts, staged, None)
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
        Some((vid, entry)),
    )
}

fn admit_including<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    ctx: &PurposeContexts,
    book_id: Id128,
    accounts: &BTreeSet<VId>,
    staged: impl IntoIterator<Item = VId>,
    extra: Option<(VId, &Entry)>,
) -> Outcome<()> {
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
    let mut resolved = BTreeSet::new();
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
        if entry.proposal.class == EntryClass::RESOLUTION {
            let target = entry
                .proposal
                .pending
                .as_ref()
                .and_then(|p| p.resolution_of)
                .ok_or_else(|| KernelError::Corrupt("resolution has no pending target".into()))?;
            resolved.insert(target.vid);
        }
        entries.push((row.vid, entry));
    }
    if let Some((vid, entry)) = extra {
        entries.push((vid, entry.clone()));
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
                            "account {:032x}, unit {}, {} stock {} exceeds max_register_mantissa {} at transaction prefix {}; nothing was published",
                            leg.account_ref.0,
                            unit.0,
                            if functional { "functional" } else { "native" },
                            [
                                "posted debit",
                                "posted credit",
                                "pending debit",
                                "pending credit"
                            ][column],
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
    /// `None` once the book holds something the summary cannot stand for: a
    /// migration chunk (its visibility is a run-state read, a transaction
    /// witness), an entry that does not decode or whose leg is invalid, a
    /// column past the maximum, or a change to a committed entry.
    cells: Option<Cells>,
}

impl CapacityHistory {
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
}

#[derive(Clone, Debug)]
struct Cells {
    book_id: Id128,
    base: UnitId,
    maximum: i128,
    columns: BTreeMap<(VId, UnitId, bool), [i128; 4]>,
    /// Pending entries a committed Resolution released.
    released: BTreeSet<VId>,
}

impl Cells {
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
            if matches!(entry.proposal.origin, EntryOrigin::Migration { .. }) {
                return Ok(false);
            }
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
    };
    let mut entries = Vec::new();
    for row in db.vertices_at(at)? {
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        ctx.txn().checkpoint().map_err(WriteTxnError::Interrupted)?;
        match entry_at(db, book_id, row.vid, at)? {
            Ok(Some(entry)) => entries.push((row.vid, entry)),
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
        }));
    };
    let mut born = Vec::new();
    let mut usable = true;
    let mut through = history.at.0;
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
    if usable {
        let mut entries = Vec::new();
        for vid in born {
            match entry_at(db, cells.book_id, vid, at)? {
                Ok(Some(entry)) => entries.push((vid, entry)),
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
    }))
}

/// Whether the summarized columns plus the staged and proposed legs fit, for
/// the affected accounts. `true` only where the scan would also admit: no
/// staged Resolution or migration chunk, every leg valid, every final column
/// within the maximum (legs are nonnegative, so every partial sum is too).
/// The scan's witnesses are read the same way.
fn fits<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    cells: &Cells,
    book_id: Id128,
    accounts: &BTreeSet<VId>,
    staged: &[VId],
    extra: Option<(VId, &Entry)>,
) -> Result<bool, KernelError> {
    for account in accounts {
        txn.vertex(db, *account)?;
    }
    if cells.book_id != book_id || cells.maximum != maximum()? {
        return Ok(false);
    }
    match crate::genesis::read_book_spec_at(db, txn.basis())? {
        Some(spec) if spec.base_unit == cells.base => {}
        _ => return Ok(false),
    }
    let mut proposed = Vec::new();
    for vid in staged {
        if let Some(row) = txn.vertex(db, *vid)?
            && row.labels.contains(&label::ENTRY)
        {
            let Ok(bytes) = crate::rows::bytes(&row, property::FA_PAYLOAD, "entry._fa_payload")
            else {
                return Ok(false);
            };
            let Ok(entry) = Entry::decode(&bytes) else {
                return Ok(false);
            };
            if entry.proposal.book_id == book_id && entry.proposal.branch_id == Id128::TRUNK {
                proposed.push(entry);
            }
        }
    }
    if let Some((_, entry)) = extra {
        proposed.push(entry.clone());
    }
    let mut columns: BTreeMap<(VId, UnitId, bool), [i128; 4]> = BTreeMap::new();
    for entry in &proposed {
        if entry.proposal.class == EntryClass::RESOLUTION
            || matches!(entry.proposal.origin, EntryOrigin::Migration { .. })
        {
            return Ok(false);
        }
        let pending = entry.proposal.class == EntryClass::PENDING;
        for leg in &entry.proposal.legs {
            if !accounts.contains(&leg.account_ref) {
                continue;
            }
            let column = usize::from(pending) * 2 + usize::from(leg.side == Side::Credit);
            let Ok(legs) = leg_columns(leg, cells.base) else {
                return Ok(false);
            };
            for (unit, functional, mantissa) in legs {
                if mantissa < 0 {
                    return Ok(false);
                }
                let key = (leg.account_ref, unit, functional);
                let cell = columns
                    .entry(key)
                    .or_insert_with(|| cells.columns.get(&key).copied().unwrap_or_default());
                let Some(next) = cell[column]
                    .checked_add(mantissa)
                    .filter(|v| *v <= cells.maximum)
                else {
                    return Ok(false);
                };
                cell[column] = next;
            }
        }
    }
    Ok(true)
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
    let summary = match carried {
        Some(summary) => summary,
        None => summarize(db, ctx, book_id, basis)?,
    };
    let fit = match &summary.cells {
        Some(cells) => fits(txn, db, cells, book_id, accounts, &staged, extra)?,
        None => false,
    };
    *history = Some(summary);
    if fit {
        return Ok(Ok(()));
    }
    admit_including(txn, db, ctx, book_id, accounts, staged, extra)
}
