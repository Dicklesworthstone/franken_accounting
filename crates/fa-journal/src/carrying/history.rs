//! One fixed-prefix observation shared by an allocated item population.
//!
//! The source population is selected separately by revaluation's migration,
//! entity and effective-date laws. This history deliberately retains the whole
//! native prefix: a later-effective application must still prevent an earlier
//! close, and an allocation that omits an open item must still be visited.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use super::*;
use crate::chart::{ChartSnapshot, FxRevaluationRoute, FxRevaluationRoutes};
use crate::genesis::BookSpec;
use fa_model::{Entry, FxRevaluationItem};

type ItemKey = (VId, u16);
type ApplicationPositions = BTreeMap<usize, Vec<(usize, usize)>>;

/// Counted work for the shared carrying observation within one revaluation.
/// Historical verification may perform additional, separately pinned
/// observations; these counts describe the selected population only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CarryingPopulationWork {
    pub history_scans: usize,
    pub entries_decoded: usize,
    pub applications_indexed: usize,
    pub reversal_links_examined: usize,
    pub source_guard_entries: usize,
    pub item_effect_entries: usize,
    pub settlement_legs_examined: usize,
    pub release_items_examined: usize,
    pub release_legs_examined: usize,
    /// Actual historical point reads while recognizing allocated release
    /// reversal suffixes in the selected observation, before item selection.
    pub release_lineage_entries_read: usize,
}

impl CarryingPopulationWork {
    pub(crate) fn accumulate(&mut self, other: Self) {
        self.history_scans += other.history_scans;
        self.entries_decoded += other.entries_decoded;
        self.applications_indexed += other.applications_indexed;
        self.reversal_links_examined += other.reversal_links_examined;
        self.source_guard_entries += other.source_guard_entries;
        self.item_effect_entries += other.item_effect_entries;
        self.settlement_legs_examined += other.settlement_legs_examined;
        self.release_items_examined += other.release_items_examined;
        self.release_legs_examined += other.release_legs_examined;
        self.release_lineage_entries_read += other.release_lineage_entries_read;
    }
}

struct Adjustment {
    basis: FxRevaluationBasis,
    items: BTreeMap<ItemKey, usize>,
}

enum GuardFailure {
    Refusal(Refusal),
    Corrupt(&'static str),
}

/// The literal guard visits native vertex order, not recorded order. Retain
/// its first eligible failure for every recorded-at lower bound without
/// rescanning old failures once per source item.
struct SourceGuard {
    failures: Vec<(CommitSeq, usize, GuardFailure)>,
    first_in_suffix: Vec<usize>,
}

impl SourceGuard {
    fn new(mut failures: Vec<(CommitSeq, usize, GuardFailure)>) -> Self {
        failures.sort_by_key(|(seq, order, _)| (*seq, *order));
        let mut first_in_suffix = vec![0; failures.len()];
        let mut first = None;
        for index in (0..failures.len()).rev() {
            if first.is_none_or(|prior: usize| failures[index].1 < failures[prior].1) {
                first = Some(index);
            }
            first_in_suffix[index] = first.unwrap_or(index);
        }
        Self {
            failures,
            first_in_suffix,
        }
    }

    fn check(&self, recorded: CommitSeq) -> Outcome<()> {
        let first = self.failures.partition_point(|(seq, _, _)| *seq < recorded);
        let Some(index) = self.first_in_suffix.get(first) else {
            return Ok(Ok(()));
        };
        match &self.failures[*index].2 {
            GuardFailure::Refusal(refusal) => Ok(Err(refusal.clone())),
            GuardFailure::Corrupt(detail) => Err(KernelError::Corrupt((*detail).into())),
        }
    }
}

/// Immutable entry payloads and structural event indexes. A historical view
/// supplies its own cutoff and every cutoff-dependent cache below.
pub(crate) struct CarryingIndex {
    at: CommitSeq,
    book_id: Id128,
    entries: Vec<(CommitSeq, VId, Entry)>,
    by_id: BTreeMap<VId, usize>,
    native_rank: Vec<usize>,
    reversals: BTreeMap<VId, (CommitSeq, VId)>,
    first_duplicate_reversal: Option<CommitSeq>,
    applications: BTreeMap<ItemKey, ApplicationPositions>,
    adjustments: BTreeMap<usize, Adjustment>,
    adjustments_by_source: BTreeMap<(VId, Option<VId>), Vec<usize>>,
    // These proofs are pinned to their own exact historical coordinates,
    // independent of the carrying view's cutoff. Never cache a head route
    // as a substitute for a historical projection.
    route_observations: RefCell<BTreeMap<(DateDay, CommitSeq), Option<Rc<FxRevaluationRoutes>>>>,
    route_reads: Cell<usize>,
    route_reuses: Cell<usize>,
    work: CarryingPopulationWork,
}

pub(crate) struct CarryingHistory {
    pub(crate) at: CommitSeq,
    pub(crate) spec: BookSpec,
    index: Rc<CarryingIndex>,
    end: usize,
    chart: RefCell<Option<ChartSnapshot>>,
    live: RefCell<BTreeMap<VId, Result<bool, &'static str>>>,
    guards: RefCell<BTreeMap<VId, SourceGuard>>,
    routes: RefCell<BTreeMap<usize, Result<FxRevaluationRoute, Refusal>>>,
    release_indices: RefCell<BTreeMap<usize, Result<allocated::ReleaseIndex, Refusal>>>,
    release_shapes: RefCell<BTreeMap<usize, Result<(), Refusal>>>,
    range_shapes: RefCell<BTreeMap<usize, bool>>,
    work: Cell<CarryingPopulationWork>,
}

impl CarryingIndex {
    pub(crate) fn read_at<V: Vfs + Clone>(
        db: &Database<V>,
        cx: &PurposeContexts,
        book: &BookContext,
        at: CommitSeq,
    ) -> Result<Self, KernelError> {
        let mut entries = Vec::new();
        let mut work = CarryingPopulationWork {
            history_scans: 1,
            ..CarryingPopulationWork::default()
        };
        for row in db.vertices_at(at)? {
            cx.query()
                .checkpoint()
                .map_err(fgdb::WriteTxnError::Interrupted)?;
            if !row.labels.contains(&label::ENTRY) {
                continue;
            }
            work.entries_decoded += 1;
            // Entry::decode validates every known extension before filtering
            // by book/branch, exactly as the literal read_entry_at path does.
            // A malformed FX basis cannot be hidden in an older/unrelated row.
            let entry = crate::entry_storage::decode_at(db, &row, at)?;
            if entry.proposal.book_id != book.book_id || entry.proposal.branch_id != Id128::TRUNK {
                continue;
            }
            // read_entry_at returns this same selected row's created_at;
            // revaluation has already authenticated immutable Entry history.
            entries.push((row.created_at, row.vid, entry));
        }
        let native_order: Vec<_> = entries.iter().map(|(_, vid, _)| *vid).collect();
        entries.sort_by_key(|(seq, vid, _)| (*seq, *vid));
        let by_id: BTreeMap<_, _> = entries
            .iter()
            .enumerate()
            .map(|(index, (_, vid, _))| (*vid, index))
            .collect();
        let mut native_rank = vec![0; entries.len()];
        for (rank, vid) in native_order.iter().enumerate() {
            native_rank[by_id[vid]] = rank;
        }
        let mut applications: BTreeMap<ItemKey, ApplicationPositions> = BTreeMap::new();
        let mut affected: BTreeMap<VId, BTreeSet<ItemKey>> = BTreeMap::new();
        let mut adjustments = BTreeMap::new();
        let mut adjustments_by_source: BTreeMap<(VId, Option<VId>), Vec<usize>> = BTreeMap::new();
        let mut reversals = BTreeMap::new();
        let mut first_duplicate_reversal = None;
        for (index, (seq, vid, entry)) in entries.iter().enumerate() {
            cx.query()
                .checkpoint()
                .map_err(fgdb::WriteTxnError::Interrupted)?;
            if let Some((_, raw)) = entry
                .proposal
                .extensions
                .iter()
                .find(|(tag, _)| *tag == FX_REVALUATION_EXTENSION)
            {
                let basis = FxRevaluationBasis::decode(raw)
                    .map_err(|error| KernelError::Corrupt(error.to_string()))?;
                let mut items = BTreeMap::new();
                if let Some(allocation) = &basis.item_allocation {
                    for (ordinal, item) in allocation.items.iter().enumerate() {
                        // Match the literal fold's first matching item. The
                        // canonical basis decoder also enforces uniqueness.
                        items
                            .entry((item.target.vid, item.ordinal))
                            .or_insert(ordinal);
                    }
                }
                adjustments_by_source
                    .entry((basis.source_account, basis.entity))
                    .or_default()
                    .push(index);
                adjustments.insert(index, Adjustment { basis, items });
            }

            let mut targets = BTreeSet::new();
            if entry.proposal.class == EntryClass::REVERSAL {
                for link in &entry.proposal.supersession {
                    if link.kind == SupersessionKind::Reverses {
                        if let std::collections::btree_map::Entry::Vacant(slot) =
                            reversals.entry(link.target.vid)
                        {
                            slot.insert((*seq, *vid));
                        } else {
                            // Do not let damage in a later prefix poison a
                            // historical view that predates its second edge.
                            first_duplicate_reversal.get_or_insert(*seq);
                        }
                    }
                }
                // Only preceding recorded effects exist in the literal fold.
                // Propagating that same relation once avoids a whole ledger
                // walk (or another ancestry walk) for each affected item.
                for link in &entry.proposal.supersession {
                    if link.kind == SupersessionKind::Reverses
                        && let Some(prior) = affected.get(&link.target.vid)
                    {
                        targets.extend(prior.iter().copied());
                    }
                }
                for target in &targets {
                    applications
                        .entry(*target)
                        .or_default()
                        .entry(index)
                        .or_default();
                }
            } else if entry.proposal.class.carries_open_items() {
                for (leg_ordinal, leg) in entry.proposal.legs.iter().enumerate() {
                    for (application_ordinal, application) in leg.settles.iter().enumerate() {
                        work.applications_indexed += 1;
                        let target = (application.target.vid, application.ordinal);
                        applications
                            .entry(target)
                            .or_default()
                            .entry(index)
                            .or_default()
                            .push((leg_ordinal, application_ordinal));
                        targets.insert(target);
                    }
                }
            }
            if !targets.is_empty() {
                affected.insert(*vid, targets);
            }
        }
        Ok(Self {
            at,
            book_id: book.book_id,
            entries,
            by_id,
            native_rank,
            reversals,
            first_duplicate_reversal,
            applications,
            adjustments,
            adjustments_by_source,
            route_observations: RefCell::new(BTreeMap::new()),
            route_reads: Cell::new(0),
            route_reuses: Cell::new(0),
            work,
        })
    }

    pub(crate) fn entries(&self) -> &[(CommitSeq, VId, Entry)] {
        &self.entries
    }

    pub(crate) fn position(&self, vid: VId) -> Option<usize> {
        self.by_id.get(&vid).copied()
    }

    pub(crate) fn build_work(&self) -> CarryingPopulationWork {
        self.work
    }

    pub(crate) fn route_work(&self) -> (usize, usize) {
        (self.route_reads.get(), self.route_reuses.get())
    }

    pub(crate) fn routes_at<V: Vfs + Clone>(
        &self,
        db: &Database<V>,
        book: &BookContext,
        date: DateDay,
        at: CommitSeq,
    ) -> Result<Option<Rc<FxRevaluationRoutes>>, KernelError> {
        if book.book_id != self.book_id {
            return Err(KernelError::Corrupt(
                "historical routes belong to another indexed book".into(),
            ));
        }
        if let Some(routes) = self.route_observations.borrow().get(&(date, at)) {
            self.route_reuses.set(self.route_reuses.get() + 1);
            return Ok(routes.clone());
        }
        self.route_reads.set(self.route_reads.get() + 1);
        let routes = crate::chart::fx_revaluation_routes_at(db, book, date, at)?.map(Rc::new);
        self.route_observations
            .borrow_mut()
            .insert((date, at), routes.clone());
        Ok(routes)
    }
}

impl CarryingHistory {
    pub(crate) fn read_at<V: Vfs + Clone>(
        db: &Database<V>,
        cx: &PurposeContexts,
        book: &BookContext,
        at: CommitSeq,
    ) -> Result<Self, KernelError> {
        let spec = crate::fx::book_spec_at(db, book, at)?;
        let index = Rc::new(CarryingIndex::read_at(db, cx, book, at)?);
        Self::from_index(spec, index, at, true)
    }

    pub(crate) fn from_index(
        spec: BookSpec,
        index: Rc<CarryingIndex>,
        at: CommitSeq,
        include_build_work: bool,
    ) -> Result<Self, KernelError> {
        if spec.book_id != index.book_id || at > index.at {
            return Err(KernelError::Corrupt(
                "carrying view exceeds its indexed book prefix".into(),
            ));
        }
        if index.first_duplicate_reversal.is_some_and(|seq| seq <= at) {
            return Err(KernelError::Corrupt(
                "an application has duplicate reversal successors".into(),
            ));
        }
        let end = index.entries.partition_point(|(seq, _, _)| *seq <= at);
        let work = if include_build_work {
            index.work
        } else {
            CarryingPopulationWork::default()
        };
        Ok(Self {
            at,
            spec,
            index,
            end,
            chart: RefCell::new(None),
            live: RefCell::new(BTreeMap::new()),
            guards: RefCell::new(BTreeMap::new()),
            routes: RefCell::new(BTreeMap::new()),
            release_indices: RefCell::new(BTreeMap::new()),
            release_shapes: RefCell::new(BTreeMap::new()),
            range_shapes: RefCell::new(BTreeMap::new()),
            work: Cell::new(work),
        })
    }

    pub(crate) fn original(&self, vid: VId) -> Option<(&Entry, CommitSeq)> {
        let position = *self.index.by_id.get(&vid)?;
        if position >= self.end {
            return None;
        }
        let (seq, _, entry) = self.index.entries.get(position)?;
        Some((entry, *seq))
    }

    fn live_state(
        &self,
        cx: &PurposeContexts,
        vid: VId,
    ) -> Result<Result<bool, &'static str>, KernelError> {
        let mut work = self.work.get();
        let result = cached_liveness_with(
            vid,
            |target| {
                self.index
                    .reversals
                    .get(&target)
                    .filter(|(seq, _)| *seq <= self.at)
                    .map(|(_, successor)| *successor)
            },
            &mut self.live.borrow_mut(),
            cx,
            &mut work,
        );
        self.work.set(work);
        result
    }

    pub(crate) fn is_live(&self, cx: &PurposeContexts, vid: VId) -> Result<bool, KernelError> {
        self.live_state(cx, vid)?
            .map_err(|detail| KernelError::Corrupt(detail.into()))
    }

    pub(crate) fn work(&self) -> CarryingPopulationWork {
        self.work.get()
    }

    pub(crate) fn check_source<V: Vfs + Clone>(
        &self,
        db: &Database<V>,
        cx: &PurposeContexts,
        book: &BookContext,
        source: VId,
        recorded: CommitSeq,
    ) -> Outcome<()> {
        if !self.guards.borrow().contains_key(&source) {
            if self.chart.borrow().is_none() {
                let chart = crate::chart::read_at(db, book, self.at)?;
                *self.chart.borrow_mut() = Some(chart);
            }
            let chart = self.chart.borrow();
            let chart = chart
                .as_ref()
                .ok_or_else(|| KernelError::Corrupt("carrying chart disappeared".into()))?;
            let mut failures = Vec::new();
            let mut seen_routes = BTreeSet::new();
            let routes: Vec<_> = chart
                .fx_revaluation_routes()
                .iter()
                .filter_map(|epoch| epoch.routes.get(&source).copied())
                .filter(|route| {
                    seen_routes.insert((route.valuation_account, route.unrealized_account))
                })
                .collect();
            let valuation_accounts: BTreeSet<_> =
                routes.iter().map(|route| route.valuation_account).collect();
            let mut route_positions: BTreeMap<VId, Vec<usize>> = BTreeMap::new();
            for (index, route) in routes.iter().enumerate() {
                route_positions
                    .entry(route.valuation_account)
                    .or_default()
                    .push(index);
            }
            // Per-row failures are retained, never returned early. Visit
            // only this prefix and attach each entry's original native rank;
            // SourceGuard still selects exactly the literal first refusal.
            for (index, (seq, vid, entry)) in self.index.entries[..self.end].iter().enumerate() {
                let order = self.index.native_rank[index];
                cx.query()
                    .checkpoint()
                    .map_err(fgdb::WriteTxnError::Interrupted)?;
                let mut work = self.work.get();
                work.source_guard_entries += 1;
                self.work.set(work);
                match self.live_state(cx, *vid)? {
                    Err(detail) => {
                        failures.push((*seq, order, GuardFailure::Corrupt(detail)));
                        continue;
                    }
                    Ok(false) => continue,
                    Ok(true) if entry.proposal.class == EntryClass::REVERSAL => continue,
                    Ok(true) => {}
                }
                let refusal = if has_allocated_basis(&entry.proposal) {
                    self.retained_allocated_shape(index)
                        .and_then(|()| {
                            self.with_release_index(index, |release, work| {
                                // A route whose valuation account occurs in
                                // neither a declaration nor a leg is an exact
                                // no-op for covers_valuation_account. Keep the
                                // original epoch order among relevant routes.
                                let mut selected = BTreeSet::new();
                                for account in release.valuation_accounts() {
                                    if let Some(positions) = route_positions.get(&account) {
                                        selected.extend(positions.iter().copied());
                                    }
                                }
                                for position in selected {
                                    release.covers_valuation_account(
                                        &entry.proposal,
                                        source,
                                        &routes[position],
                                        work,
                                    )?;
                                }
                                Ok(())
                            })
                        })
                        .err()
                } else {
                    let adjustment = self.index.adjustments.get(&index).map(|value| &value.basis);
                    if adjustment.is_some_and(|basis| {
                        basis.source_account == source && basis.item_allocation.is_some()
                    }) {
                        continue;
                    }
                    (adjustment.is_some_and(|basis| basis.source_account == source)
                        || entry.proposal.legs.iter().any(|leg| valuation_accounts.contains(&leg.account_ref)))
                        .then(|| invalid(
                            "the source account has valuation adjustments without a registered per-item relief allocation; its carrying basis cannot be inferred",
                        ))
                };
                if let Some(refusal) = refusal {
                    failures.push((*seq, order, GuardFailure::Refusal(refusal)));
                }
            }
            self.guards
                .borrow_mut()
                .insert(source, SourceGuard::new(failures));
        }
        self.guards.borrow()[&source].check(recorded)
    }

    pub(crate) fn events(
        &self,
        target: ItemKey,
        source: VId,
        entity: Option<VId>,
        recorded: CommitSeq,
    ) -> BTreeSet<usize> {
        let first = self
            .index
            .entries
            .partition_point(|(seq, _, _)| *seq < recorded);
        let mut selected = BTreeSet::new();
        if let Some(events) = self.index.applications.get(&target) {
            selected.extend(events.range(first..self.end).map(|(index, _)| *index));
        }
        if let Some(events) = self.index.adjustments_by_source.get(&(source, entity)) {
            selected.extend(
                events[events.partition_point(|index| *index < first)
                    ..events.partition_point(|index| *index < self.end)]
                    .iter()
                    .copied(),
            );
        }
        selected
    }

    pub(crate) fn event(&self, index: usize) -> &(CommitSeq, VId, Entry) {
        let mut work = self.work.get();
        work.item_effect_entries += 1;
        self.work.set(work);
        &self.index.entries[index]
    }

    pub(crate) fn applications(&self, target: ItemKey, index: usize) -> &[(usize, usize)] {
        self.index
            .applications
            .get(&target)
            .and_then(|events| events.get(&index))
            .map_or(&[], Vec::as_slice)
    }

    fn with_release_index<T>(
        &self,
        index: usize,
        operation: impl FnOnce(
            &allocated::ReleaseIndex,
            &mut CarryingPopulationWork,
        ) -> Result<T, Refusal>,
    ) -> Result<T, Refusal> {
        if !self.release_indices.borrow().contains_key(&index) {
            let mut work = self.work.get();
            let result =
                allocated::ReleaseIndex::new(&self.index.entries[index].2.proposal, &mut work);
            self.work.set(work);
            self.release_indices.borrow_mut().insert(index, result);
        }
        let indices = self.release_indices.borrow();
        let release = indices[&index].as_ref().map_err(Clone::clone)?;
        let mut work = self.work.get();
        let result = operation(release, &mut work);
        self.work.set(work);
        result
    }

    fn retained_allocated_shape(&self, index: usize) -> Result<(), Refusal> {
        if let Some(result) = self.release_shapes.borrow().get(&index) {
            return result.clone();
        }
        let result = self.with_release_index(index, |release, work| {
            release.retained_shape(&self.index.entries[index].2.proposal, work)
        });
        self.release_shapes
            .borrow_mut()
            .insert(index, result.clone());
        result
    }

    pub(crate) fn settlement_ranges_valid(&self, index: usize) -> bool {
        if let Some(valid) = self.range_shapes.borrow().get(&index) {
            return *valid;
        }
        if let Some(Ok(release)) = self.release_indices.borrow().get(&index) {
            return release.ranges_valid();
        }
        let mut work = self.work.get();
        let valid = settlement_ranges_counted(
            &self.index.entries[index].2.proposal,
            &mut work.settlement_legs_examined,
        )
        .is_ok();
        self.work.set(work);
        self.range_shapes.borrow_mut().insert(index, valid);
        valid
    }

    pub(crate) fn check_release(
        &self,
        index: usize,
        expected: &fa_model::FxSettlementValuationRelease,
    ) -> Result<(), Refusal> {
        let proposal = &self.index.entries[index].2.proposal;
        if proposal
            .base_totals
            .as_ref()
            .is_none_or(|total| total.fx_law_oid != FxLawId::SettlementAllocatedCarrying.oid())
        {
            return Err(invalid(
                "allocated valuation relief requires SettlementAllocatedCarrying",
            ));
        }
        self.with_release_index(index, |release, work| {
            release.check_release(proposal, expected, work)
        })
    }

    pub(crate) fn adjustment(&self, index: usize) -> Option<&FxRevaluationBasis> {
        self.index.adjustments.get(&index).map(|value| &value.basis)
    }

    pub(crate) fn allocation_item(
        &self,
        index: usize,
        target: ItemKey,
    ) -> Option<&FxRevaluationItem> {
        let adjustment = self.index.adjustments.get(&index)?;
        let ordinal = *adjustment.items.get(&target)?;
        adjustment
            .basis
            .item_allocation
            .as_ref()?
            .items
            .get(ordinal)
    }

    pub(crate) fn route<V: Vfs + Clone>(
        &self,
        db: &Database<V>,
        book: &BookContext,
        index: usize,
    ) -> Outcome<FxRevaluationRoute> {
        if let Some(result) = self.routes.borrow().get(&index) {
            return Ok(result.clone());
        }
        let basis = &self.index.adjustments[&index].basis;
        let result = match self
            .index
            .routes_at(db, book, basis.closing_date, basis.observed_at)?
        {
            None => Err(invalid("item allocation has no retained route map")),
            Some(routes) => match routes.routes.get(&basis.source_account).copied() {
                None => Err(invalid("item allocation has no source route")),
                Some(_)
                    if routes.control_entry != basis.routes_entry
                        || routes.digest != basis.routes_digest =>
                {
                    Err(invalid(
                        "item allocation route commitment differs from history",
                    ))
                }
                Some(route) => Ok(route),
            },
        };
        self.routes.borrow_mut().insert(index, result.clone());
        Ok(result)
    }
}

pub(crate) fn cached_liveness(
    start: VId,
    reversals: &BTreeMap<VId, VId>,
    cached: &mut BTreeMap<VId, Result<bool, &'static str>>,
    cx: &PurposeContexts,
    work: &mut CarryingPopulationWork,
) -> Result<Result<bool, &'static str>, KernelError> {
    cached_liveness_with(start, |vid| reversals.get(&vid).copied(), cached, cx, work)
}

fn cached_liveness_with(
    start: VId,
    next: impl Fn(VId) -> Option<VId>,
    cached: &mut BTreeMap<VId, Result<bool, &'static str>>,
    cx: &PurposeContexts,
    work: &mut CarryingPopulationWork,
) -> Result<Result<bool, &'static str>, KernelError> {
    let mut path = Vec::new();
    let mut seen = BTreeSet::new();
    let mut current = start;
    let mut live = loop {
        cx.query()
            .checkpoint()
            .map_err(fgdb::WriteTxnError::Interrupted)?;
        if let Some(live) = cached.get(&current) {
            break *live;
        }
        if !seen.insert(current) {
            break Err("cyclic application reversal lineage");
        }
        let Some(successor) = next(current) else {
            cached.insert(current, Ok(true));
            break Ok(true);
        };
        work.reversal_links_examined += 1;
        path.push(current);
        current = successor;
    };
    for vid in path.into_iter().rev() {
        live = live.map(|value| !value);
        cached.insert(vid, live);
    }
    Ok(live)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_guard_suffix_preserves_the_literal_native_order_of_failures() {
        // Native scan rank deliberately disagrees with recorded sequence,
        // including two different failures in the same creating commit.
        let failures = [
            (80, "native-first"),
            (10, "oldest"),
            (50, "middle"),
            (80, "same-seq"),
        ];
        let guard = SourceGuard::new(
            failures
                .iter()
                .enumerate()
                .map(|(order, (seq, name))| {
                    (CommitSeq(*seq), order, GuardFailure::Refusal(invalid(name)))
                })
                .collect(),
        );
        for cutoff in 0..=100 {
            let expected = failures
                .iter()
                .find(|(seq, _)| *seq >= cutoff)
                .map(|(_, name)| invalid(name));
            assert_eq!(
                guard.check(CommitSeq(cutoff)).unwrap().err(),
                expected,
                "cutoff={cutoff}"
            );
        }
    }

    #[test]
    fn an_ineligible_old_cycle_does_not_replace_a_later_source_refusal() {
        let guard = SourceGuard::new(vec![
            (
                CommitSeq(1),
                0,
                GuardFailure::Corrupt("cyclic application reversal lineage"),
            ),
            (
                CommitSeq(9),
                1,
                GuardFailure::Refusal(invalid("later source refusal")),
            ),
        ]);
        assert!(matches!(
            guard.check(CommitSeq(1)),
            Err(KernelError::Corrupt(_))
        ));
        assert_eq!(
            guard.check(CommitSeq(2)).unwrap(),
            Err(invalid("later source refusal"))
        );
        assert_eq!(guard.check(CommitSeq(10)).unwrap(), Ok(()));
    }
}
