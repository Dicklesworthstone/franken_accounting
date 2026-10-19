//! Independent refold of native immutable admission births, never live labels.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::symbols::{label, property, relation};
use fa_model::{ControlPayload, EntryRef, Id128};
use fgdb::{Database, WriteTxnError};
use fgdb_delta_types::{DeltaRow, ElementId, RelationId};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, EId, QueryCx, VId};

use super::codec::corrupt;
use super::{UsageCell, UsageDebit, UsageKey, cite_targets, gross_debits, issued_capability};
use crate::genesis::{BookContext, BookSpec};
use crate::rows::{book_root, bytes, edge_id};
use crate::{KernelError, policy};

/// One complete prefix, with every retained immutable charge and derived cell
/// checked. Counts describe the recorded population, including corrupt births.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageVerification {
    pub known_at: CommitSeq,
    pub charges_checked: usize,
    pub cells_checked: usize,
    pub drift: Vec<String>,
}

impl UsageVerification {
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.drift.is_empty()
    }
}

fn checkpoint(cx: &QueryCx) -> Result<(), KernelError> {
    cx.checkpoint().map_err(WriteTxnError::Interrupted)?;
    Ok(())
}

/// Current authority belongs to the caller; this kernel verifier observes
/// exactly the requested prefix and never publishes repairs. Load the complete
/// retained history first when the database was opened from a checkpoint.
pub fn verify_usage<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    known_at: Option<CommitSeq>,
) -> Result<UsageVerification, KernelError> {
    let query = cx.query();
    checkpoint(&query)?;
    query.with_restriction(|| verify(db, cx, &query, book, known_at))
}

fn verify<V: Vfs + Clone>(
    db: &Database<V>,
    contexts: &PurposeContexts,
    cx: &QueryCx,
    book: &BookContext,
    known_at: Option<CommitSeq>,
) -> Result<UsageVerification, KernelError> {
    let known_at = known_at.unwrap_or(db.frontier()?);
    let rows: BTreeMap<_, _> = db
        .vertices_at(known_at)?
        .into_iter()
        .map(|row| (row.vid, row.seen_at(known_at)))
        .collect();
    let mut report = UsageVerification {
        known_at,
        charges_checked: 0,
        cells_checked: 0,
        drift: Vec::new(),
    };
    let mut debits = BTreeMap::<VId, CommitSeq>::new();
    let mut cells = BTreeMap::<VId, CommitSeq>::new();
    let mut entries = BTreeMap::<VId, CommitSeq>::new();
    let mut source_edges = BTreeMap::<EId, (CommitSeq, RelationId, VId, VId, bool)>::new();
    let mut genesis = None;
    let mut through = 0_u64;
    for batch in db.delta_since(CommitSeq(0))? {
        let seq = batch.commit_seq();
        if seq > known_at {
            break;
        }
        checkpoint(cx)?;
        if through.checked_add(1) != Some(seq.0) {
            return Err(corrupt(
                "usage verification requires complete native history from sequence zero",
            ));
        }
        // Canonical coordinate order is not causal; discover every birth first.
        for coordinate in batch.coordinate_entries() {
            for row in &coordinate.rows {
                checkpoint(cx)?;
                if let DeltaRow::CreateVertex { vid, labels, .. } = row {
                    if *vid == book_root() {
                        genesis = Some(seq);
                    }
                    for (kind, births) in [
                        (label::USAGE_DEBIT, &mut debits),
                        (label::USAGE_CELL, &mut cells),
                        (label::ENTRY, &mut entries),
                    ] {
                        if labels.contains(&kind) && births.insert(*vid, seq).is_some() {
                            report.drift.push(format!(
                                "identity {:032x} has more than one native creation",
                                vid.0
                            ));
                        }
                    }
                }
            }
        }
        for coordinate in batch.coordinate_entries() {
            for row in &coordinate.rows {
                checkpoint(cx)?;
                if let DeltaRow::CreateEdge {
                    eid,
                    src,
                    dst,
                    props,
                    ..
                } = row
                    && debits.contains_key(src)
                {
                    source_edges.insert(
                        *eid,
                        (seq, coordinate.relation, *src, *dst, props.is_empty()),
                    );
                }
                if let DeltaRow::LabelMembership {
                    vid,
                    label: changed,
                    after: true,
                    ..
                } = row
                    && ((*changed == label::USAGE_DEBIT && !debits.contains_key(vid))
                        || (*changed == label::USAGE_CELL && !cells.contains_key(vid)))
                {
                    report.drift.push(format!(
                        "a label cannot manufacture usage birth {:032x}",
                        vid.0
                    ));
                }
                let touched = match row {
                    DeltaRow::Property {
                        elem: ElementId::Vertex(vid),
                        ..
                    }
                    | DeltaRow::LabelMembership { vid, .. }
                    | DeltaRow::DeleteVertex { vid, .. } => Some(vid),
                    _ => None,
                };
                if let Some(vid) = touched
                    && debits.get(vid).is_some_and(|born| *born < seq)
                {
                    report.drift.push(format!("immutable usage receipt {:032x} was modified at {}; restoration cannot erase its mutation", vid.0, seq.0));
                }
            }
        }
        through = seq.0;
    }
    if through != known_at.0 {
        return Err(corrupt("usage history ends before the requested prefix"));
    }
    report.charges_checked = debits.len();
    report.cells_checked = cells.len();
    if debits.is_empty() && cells.is_empty() {
        return Ok(report);
    }
    // Source entries, issuance controls and ticks must be their native birth
    // rows too. This also catches an exact restoration after an illicit edit.
    if let Err(error) =
        crate::entry_history::verify_entry_history(db, contexts, book, Some(known_at))
    {
        report.drift.push(format!("usage source history: {error}"));
    }
    let born = genesis.ok_or_else(|| corrupt("usage has no retained book genesis"))?;
    let root = db
        .vertex_at(book_root(), born)?
        .ok_or_else(|| corrupt("book genesis snapshot is missing"))?;
    let policy_bytes = bytes(&root, property::FA_PAYLOAD, "usage calendar genesis")?;
    let spec = BookSpec::decode(&policy_bytes)?;
    let time_zone = spec
        .time_zone_policy
        .ok_or_else(|| corrupt("usage was recorded without a declared book calendar policy"))?;
    if rows.get(&book_root()).is_none_or(|row| {
        bytes(row, property::FA_PAYLOAD, "usage calendar")
            .ok()
            .as_ref()
            != Some(&policy_bytes)
    }) {
        report
            .drift
            .push("book calendar policy differs from its retained genesis".into());
    }
    let mut ticks = BTreeMap::<CommitSeq, (EntryRef, u64, bool)>::new();
    for (&vid, &created) in &entries {
        checkpoint(cx)?;
        let Some(row) = db.vertex_at(vid, created)? else {
            continue;
        };
        let (entry, _) = match crate::post::entry_of(&row) {
            Ok(value) => value,
            Err(error) => {
                report.drift.push(error.to_string());
                continue;
            }
        };
        if let Some(ControlPayload::TimeTick {
            observed_utc_ns,
            monotonic_ok,
            ..
        }) = entry.proposal.control.as_ref()
        {
            if entry.proposal.book_id != book.book_id || entry.proposal.branch_id != Id128::TRUNK {
                report
                    .drift
                    .push("usage tick belongs to a different book coordinate".into());
            }
            if ticks
                .insert(
                    created,
                    (entry.entry_ref(vid), *observed_utc_ns, *monotonic_ok),
                )
                .is_some()
            {
                report.drift.push(format!(
                    "more than one clock observation at sequence {}",
                    created.0
                ));
            }
        }
    }
    let mut receipts = Vec::with_capacity(debits.len());
    let current_edges: BTreeMap<_, _> = db
        .edges_at(known_at)?
        .into_iter()
        .map(|edge| (edge.entry.eid, edge))
        .collect();
    for (&vid, &created) in &debits {
        checkpoint(cx)?;
        let Some(original) = db.vertex_at(vid, created)?.map(|row| row.seen_at(created)) else {
            report.drift.push(format!(
                "usage receipt {:032x} has no creating snapshot",
                vid.0
            ));
            continue;
        };
        let current = rows.get(&vid);
        if current.is_none_or(|row| {
            row.created_at != created
                || row.birth_ordinal != original.birth_ordinal
                || row.labels != original.labels
                || row.props != original.props
                || row.retired_at.is_some()
        }) {
            report.drift.push(format!(
                "usage receipt {:032x} is missing, relabeled or rewritten",
                vid.0
            ));
        }
        let debit = match UsageDebit::from_row(&original) {
            Ok(debit) => debit,
            Err(error) => {
                report.drift.push(error.to_string());
                continue;
            }
        };
        if let Err(error) = validate_source(db, book, &debit, created, &entries, &ticks, time_zone)
        {
            report
                .drift
                .push(format!("usage receipt {:032x}: {error}", vid.0));
        }
        for (relation, targets) in [
            (relation::CITES, cite_targets(&debit)),
            (relation::IN_BOOK, BTreeSet::from([book_root()])),
        ] {
            for target in targets {
                let id = edge_id(relation, vid, target);
                if source_edges.get(&id) != Some(&(created, relation, vid, target, true))
                    || current_edges.get(&id).is_none_or(|row| {
                        row.entry.relation != relation
                            || row.entry.src != vid
                            || row.entry.dst != target
                            || !row.props.is_empty()
                    })
                {
                    report.drift.push(format!("usage receipt {:032x} is missing its same-publication retained source edge", vid.0));
                }
            }
        }
        receipts.push((debit, created));
    }
    receipts.sort_by_key(|(debit, _)| (debit.key, debit.generation));
    let mut expected = BTreeMap::<UsageKey, (UsageCell, CommitSeq)>::new();
    let mut source_units = BTreeSet::new();
    for (debit, created) in receipts {
        checkpoint(cx)?;
        if !source_units.insert((debit.entry.vid, debit.key.unit)) {
            report.drift.push(format!(
                "entry {:032x} native unit {} is charged more than once",
                debit.entry.vid.0, debit.key.unit.0
            ));
        }
        let previous = expected.get(&debit.key);
        let prior_gross = previous.map_or(0, |(cell, _)| cell.gross_debits);
        let prior_generation = previous.map_or(0, |(cell, _)| cell.generation);
        if prior_gross != debit.previous_gross_debits
            || prior_generation.checked_add(1) != Some(debit.generation)
            || prior_gross.checked_add(debit.gross_debits) != Some(debit.total_gross_debits)
            || previous.is_some_and(|(_, prior_at)| *prior_at > created)
        {
            report.drift.push(format!(
                "usage {:032x} generation {} does not continue its retained gross-debit prefix",
                debit.key.cell_vid().0,
                debit.generation
            ));
        }
        expected.insert(
            debit.key,
            (
                UsageCell {
                    key: debit.key,
                    gross_debits: debit.total_gross_debits,
                    generation: debit.generation,
                },
                created,
            ),
        );
    }
    for (&key, &(cell, _)) in &expected {
        checkpoint(cx)?;
        let id = key.cell_vid();
        match rows
            .get(&id)
            .map(|row| UsageCell::from_row(row, key))
            .transpose()
        {
            Ok(Some(actual)) if actual == cell && cells.contains_key(&id) => {}
            _ => report.drift.push(format!(
                "usage cell {:032x} differs from the complete immutable gross-debit refold",
                id.0
            )),
        }
    }
    for id in cells.keys() {
        if !expected.keys().any(|key| key.cell_vid() == *id) {
            report.drift.push(format!(
                "usage cell {:032x} has no immutable charge history",
                id.0
            ));
        }
    }
    for row in rows.values() {
        if (row.labels.contains(&label::USAGE_DEBIT) && !debits.contains_key(&row.vid))
            || (row.labels.contains(&label::USAGE_CELL) && !cells.contains_key(&row.vid))
        {
            report.drift.push(format!(
                "visible usage object {:032x} has no native birth",
                row.vid.0
            ));
        }
    }
    report.drift.sort();
    report.drift.dedup();
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn validate_source<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    debit: &UsageDebit,
    created: CommitSeq,
    entries: &BTreeMap<VId, CommitSeq>,
    ticks: &BTreeMap<CommitSeq, (EntryRef, u64, bool)>,
    time_zone: crate::TimeZonePolicy,
) -> Result<(), KernelError> {
    let before = CommitSeq(
        created
            .0
            .checked_sub(1)
            .ok_or_else(|| corrupt("charge before genesis"))?,
    );
    if debit.key.book_id != book.book_id || entries.get(&debit.entry.vid) != Some(&created) {
        return Err(corrupt(
            "charge source was not created in this book in the same publication",
        ));
    }
    let row = db
        .vertex_at(debit.entry.vid, created)?
        .ok_or_else(|| corrupt("charge entry missing"))?;
    let (entry, _) = crate::post::entry_of(&row)?;
    if entry.entry_ref(row.vid) != debit.entry
        || entry.proposal.book_id != book.book_id
        || entry.proposal.branch_id != Id128::TRUNK
        || gross_debits(&entry.proposal)?.get(&debit.key.unit) != Some(&debit.gross_debits)
    {
        return Err(corrupt(
            "charge differs from the actual positive gross debit of its unchanged entry",
        ));
    }
    let issuance = |commitment: &[u8; 32]| -> Result<fa_policy::Capability, KernelError> {
        let id = policy::issuance_vid(book.book_id, commitment);
        if entries.get(&id).is_none_or(|at| *at > before) {
            return Err(corrupt(
                "charge capability has no preceding retained issuance",
            ));
        }
        let row = db
            .vertex_at(id, before)?
            .ok_or_else(|| corrupt("charge issuance is missing"))?;
        let (capability, _) = issued_capability(&row, book.book_id, commitment)?;
        if fa_policy::current(&capability, before).is_err()
            || db
                .vertex_at(policy::revocation_vid(book.book_id, commitment), before)?
                .is_some()
        {
            return Err(corrupt(
                "charge used authority expired or revoked at its admission prefix",
            ));
        }
        Ok(capability)
    };
    let capability = issuance(&debit.capability)?;
    let root = issuance(&debit.key.root_issuance)?;
    let root_id = capability.daily_root().unwrap_or(debit.capability);
    if root_id != debit.key.root_issuance
        || root.daily_root().is_some()
        || capability.holder() != entry.proposal.principal_ref
        || root.daily_totals().is_empty()
    {
        return Err(corrupt(
            "charge changes its presented capability's original quota root or holder",
        ));
    }
    let limit = capability
        .daily_totals()
        .get(&debit.key.unit)
        .ok_or_else(|| corrupt("charge unit has no presented daily limit"))?;
    if root
        .daily_totals()
        .get(&debit.key.unit)
        .is_none_or(|bound| limit > bound)
        || debit.total_gross_debits > *limit
    {
        return Err(corrupt(
            "shared cumulative charge exceeds the presented or root daily limit",
        ));
    }
    let Some((_, &(tick_ref, observed, corroborated))) = ticks.range(..created).next_back() else {
        return Err(corrupt(
            "charge has no strictly preceding committed time evidence",
        ));
    };
    if !corroborated
        || tick_ref != debit.tick
        || debit.time_zone_policy != time_zone.tag()
        || time_zone.civil_date(observed) != debit.key.day
    {
        return Err(corrupt(
            "charge day is not the declared calendar date of the latest corroborated preceding tick",
        ));
    }
    Ok(())
}
