//! `recon.assertion_drift` (plan §9.4, bead fa-nwgf, `claim = "invariant"`):
//! every `RegisterEquals` attestation re-evaluated against the posted journal
//! gross period fold at the snapshot coordinate. Version 1 instead netted
//! supersession across periods, incorrectly erasing an attested accrual when
//! its reversal posted in a later period.
//!
//! An attestation stays a historical fact: it held at the prefix it evaluated
//! (`evaluated_known_at`). A finding says only that its cell no longer folds
//! to the attested amount, and names why: the entries recorded after that
//! prefix whose legs move the cell. It cites the Attestation itself, the
//! account, the period and every such entry; a population that needs more
//! citations than one finding carries refuses the run rather than omit one.
//! Entries in other cells (another account, unit, entity, period, or dated
//! after the cell's as-of day) never contribute.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::attestation::AttestationClaim;
use fa_journal::genesis::BookContext;
use fa_model::LegPayload;
use fa_money::{Amount, Side, UnitId};
use fa_time::DateDay;
use fgdb_types::{CommitSeq, VId};

use crate::jet::{finding, procedure_boilerplate};
use crate::snapshot::SnapshotEntry;
use crate::{
    Cite, Finding, LanternError, MAX_CITES, Meter, Params, Procedure, Severity, Snapshot, Statistic,
};

pub struct AssertionDrift {
    params: Params,
}

procedure_boilerplate!(AssertionDrift, "recon.assertion_drift");

impl Procedure for AssertionDrift {
    fn id(&self) -> &'static str {
        Self::ID
    }
    fn version(&self) -> u16 {
        2
    }
    fn params(&self) -> &Params {
        &self.params
    }
    fn run(
        &self,
        snapshot: &Snapshot,
        book: &BookContext,
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        // RegisterEquals attests the period's posted activity, not the net
        // effect of supersession across the book. A reversal contributes in
        // its own period; it never removes the original from another period
        // or from an earlier effective cutoff. Pending reservations do not
        // post, while their posted resolutions do.
        // Match fa-registers::entity::entity_of: legal entities declared by
        // BookSpec determine the cells, not every informational REA entity.
        // An omitted dimension belongs to the sole declared entity; None is
        // the unassigned cell, never an all-entities aggregate.
        let entity_value = &snapshot.declared_entities;
        let declared_values: BTreeSet<VId> = entity_value.values().copied().collect();
        let implicit_entity = if entity_value.len() == 1 {
            entity_value.values().next().copied()
        } else {
            None
        };
        let claims: Vec<_> = snapshot
            .attestations
            .iter()
            .filter_map(|(vid, stored)| match &stored.attestation.claim {
                AttestationClaim::RegisterEquals(claim) => Some((*vid, claim)),
                _ => None,
            })
            .collect();
        let population = u64::try_from(claims.len()).unwrap_or(u64::MAX).max(1);
        if claims.is_empty() {
            return Ok(Vec::new());
        }
        let cells = indexed_cells(snapshot, &declared_values, implicit_entity, work)?;
        let mut out = Vec::new();
        for (attestation, claim) in claims {
            work.compare(1)?;
            let entity = match &claim.entity {
                Some(code) => Some(entity_value.get(code.as_str()).copied().ok_or_else(|| {
                    LanternError::Parameter {
                        procedure: Self::ID.into(),
                        name: "attestation".into(),
                        message: format!(
                            "attestation {:032x} names entity `{code}`, which this book does not declare",
                            attestation.0
                        ),
                    }
                })?),
                None => None,
            };
            let key = (claim.account, claim.period.as_str(), claim.unit_id, entity);
            let cell = cells.get(&key);
            let (fold, through) = cell.map_or(Ok((0, 0)), |cell| {
                cell.fold_at(
                    &key,
                    claim.as_of_effective,
                    &declared_values,
                    implicit_entity,
                    work,
                )
            })?;
            if fold == claim.mantissa {
                continue;
            }
            let drift = fold
                .checked_sub(claim.mantissa)
                .ok_or(LanternError::Overflow("assertion_drift drift"))?;
            let magnitude = i128::try_from(drift.unsigned_abs())
                .map_err(|_| LanternError::Overflow("assertion_drift drift magnitude"))?;
            let mut cites = vec![Cite::Attestation(attestation), Cite::Account(claim.account)];
            if snapshot.periods.contains_key(&claim.period) {
                cites.push(Cite::Period(claim.period.clone()));
            }
            let later = cell.map_or(Ok(LaterEntries::default()), |cell| {
                cell.later(
                    through,
                    claim.as_of_effective,
                    claim.evaluated_known_at,
                    work,
                )
            })?;
            if later.count > MAX_CITES - cites.len() {
                return Err(LanternError::Parameter {
                    procedure: Self::ID.into(),
                    name: "attestation".into(),
                    message: format!(
                        "attestation {:032x} drifted through {} later entries, more than one finding cites ({MAX_CITES}); no entry is omitted and no partial run is returned",
                        attestation.0, later.count
                    ),
                });
            }
            let later = later.entries;
            let cause = if later.is_empty() {
                "no entry recorded after the evaluated prefix moves this cell; this run compares the selected fold and does not re-evaluate the original prefix".to_string()
            } else {
                format!(
                    "{} entr{} recorded after the attestation move{} the cell",
                    later.len(),
                    if later.len() == 1 { "y" } else { "ies" },
                    if later.len() == 1 { "s" } else { "" }
                )
            };
            cites.extend(later.into_iter().map(Cite::Entry));
            let shown =
                |mantissa: i128| Amount::new(UnitId(claim.unit_id), mantissa).render(&book.units);
            let code = snapshot
                .accounts
                .get(&claim.account)
                .map_or("?", |a| a.code.as_str());
            out.push(finding(
                Self::ID,
                Severity::Critical,
                Statistic {
                    name: "assertion_drift".into(),
                    value: magnitude,
                    scale: crate::unit_scale(book, claim.unit_id)?,
                    population,
                },
                cites,
                format!(
                    "account {code} period {}{}: attested {} at sequence {}; the posted fold at this snapshot is {} (drift {}); {cause}",
                    claim.period,
                    claim
                        .entity
                        .as_ref()
                        .map_or_else(String::new, |e| format!(" entity {e}")),
                    shown(claim.mantissa),
                    claim.evaluated_known_at.0,
                    shown(fold),
                    shown(drift)
                ),
            ));
        }
        Ok(out)
    }
}

type DriftKey<'a> = (VId, &'a str, u32, Option<VId>);

struct Contribution<'a> {
    entry: &'a SnapshotEntry,
    source_index: usize,
    // Initially this entry's cell net; after indexing, the day-prefix net.
    net: i128,
}

struct DriftCell<'a> {
    entries: Vec<Contribution<'a>>,
    gross: [Option<i128>; 2],
    indexed: bool,
    max_recorded: Vec<CommitSeq>,
}

impl Default for DriftCell<'_> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            gross: [Some(0); 2],
            indexed: false,
            max_recorded: Vec::new(),
        }
    }
}

fn entity_of(leg: &LegPayload, declared: &BTreeSet<VId>, implicit: Option<VId>) -> Option<VId> {
    leg.dimension_set
        .iter()
        .find(|(dimension, _)| *dimension == fa_model::LEGAL_ENTITY_DIMENSION)
        .filter(|(_, value)| declared.contains(value))
        .map(|(_, value)| *value)
        .or(implicit)
}

fn signed_leg(leg: &LegPayload) -> Result<i128, LanternError> {
    let magnitude = i128::try_from(leg.amount.mantissa.unsigned_abs())
        .map_err(|_| LanternError::Overflow("assertion_drift leg magnitude"))?;
    match leg.side {
        Side::Debit => Ok(magnitude),
        Side::Credit => magnitude
            .checked_neg()
            .ok_or(LanternError::Overflow("assertion_drift leg sign")),
    }
}

fn charge_sort(work: &mut Meter<'_>, len: usize) -> Result<(), LanternError> {
    let n = u64::try_from(len).unwrap_or(u64::MAX);
    work.compare(n.saturating_mul(u64::from(n.max(1).ilog2()) + 1))
}

fn indexed_cells<'a>(
    snapshot: &'a Snapshot,
    declared: &BTreeSet<VId>,
    implicit: Option<VId>,
    work: &mut Meter<'_>,
) -> Result<BTreeMap<DriftKey<'a>, DriftCell<'a>>, LanternError> {
    let mut cells: BTreeMap<DriftKey<'a>, DriftCell<'a>> = BTreeMap::new();
    for (source_index, entry) in snapshot.entries.iter().enumerate() {
        work.entry()?;
        if !entry.posts() {
            continue;
        }
        // Each claim supplies its own cutoff. The snapshot's optional
        // effective_through is deliberately not a second posting filter.
        for leg in &entry.entry.proposal.legs {
            work.leg()?;
            work.compare(1)?;
            cells
                .entry((
                    leg.account_ref,
                    entry.period.as_str(),
                    leg.amount.unit.0,
                    entity_of(leg, declared, implicit),
                ))
                .or_default()
                .append(entry, source_index, leg);
        }
    }
    for cell in cells.values_mut() {
        cell.prepare(work)?;
    }
    Ok(cells)
}

impl<'a> DriftCell<'a> {
    fn append(&mut self, entry: &'a SnapshotEntry, source_index: usize, leg: &LegPayload) {
        let side = usize::from(leg.side == Side::Credit);
        let magnitude = i128::try_from(leg.amount.mantissa.unsigned_abs()).ok();
        self.gross[side] = self.gross[side]
            .zip(magnitude)
            .and_then(|(gross, magnitude)| gross.checked_add(magnitude));
        let signed = signed_leg(leg).ok();
        if let Some(last) = self.entries.last_mut()
            && last.source_index == source_index
        {
            if let Some(net) = signed.and_then(|signed| last.net.checked_add(signed)) {
                last.net = net;
            } else {
                self.gross[side] = None;
            }
        } else {
            self.entries.push(Contribution {
                entry,
                source_index,
                net: signed.unwrap_or(0),
            });
        }
    }

    fn prepare(&mut self, work: &mut Meter<'_>) -> Result<(), LanternError> {
        charge_sort(work, self.entries.len())?;
        // Stable order preserves the old fold even for a malformed snapshot
        // that repeats a VID. Such a cell also needs literal cite deduplication.
        self.entries.sort_by_key(|c| c.entry.vid);
        work.compare(self.entries.len() as u64)?;
        if self.gross.iter().any(Option::is_none)
            || self
                .entries
                .windows(2)
                .any(|pair| pair[0].entry.vid == pair[1].entry.vid)
        {
            return Ok(());
        }
        // Gross debit and credit bounds prove that every intermediate in
        // every ordering fits i128. Only then may day prefixes replace the
        // checked VID/leg fold. Otherwise the requested cell is folded
        // literally, preserving the original overflow label and precedence.
        charge_sort(work, self.entries.len())?;
        self.entries
            .sort_by_key(|c| c.entry.entry.proposal.effective_date);
        let mut net = 0i128;
        let mut safe = true;
        for contribution in &mut self.entries {
            work.compare(1)?;
            if let Some(next) = net.checked_add(contribution.net) {
                net = next;
                contribution.net = next;
            } else {
                safe = false;
                break;
            }
        }
        if !safe {
            charge_sort(work, self.entries.len())?;
            self.entries.sort_by_key(|c| c.entry.vid);
            return Ok(());
        }
        // A compact max tree over the day-ordered entries prunes recorded
        // history at or before the claim's evaluated prefix. A discrepancy
        // with no new contributors never scans the whole cell to prove it.
        let n = self.entries.len();
        self.max_recorded = vec![CommitSeq(0); n];
        for contribution in &self.entries {
            work.compare(1)?;
            self.max_recorded.push(contribution.entry.recorded_at);
        }
        for node in (1..n).rev() {
            work.compare(1)?;
            self.max_recorded[node] =
                self.max_recorded[2 * node].max(self.max_recorded[2 * node + 1]);
        }
        self.indexed = true;
        Ok(())
    }

    fn fold_at(
        &self,
        key: &DriftKey<'_>,
        day: DateDay,
        declared: &BTreeSet<VId>,
        implicit: Option<VId>,
        work: &mut Meter<'_>,
    ) -> Result<(i128, usize), LanternError> {
        if self.indexed {
            let (mut lo, mut hi) = (0, self.entries.len());
            while lo < hi {
                work.compare(1)?;
                let mid = lo + (hi - lo) / 2;
                if self.entries[mid].entry.entry.proposal.effective_date <= day {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            return Ok((self.entries[..lo].last().map_or(0, |c| c.net), lo));
        }
        let mut net = 0i128;
        for contribution in &self.entries {
            work.compare(1)?;
            let entry = contribution.entry;
            if entry.entry.proposal.effective_date > day {
                continue;
            }
            for leg in &entry.entry.proposal.legs {
                work.compare(1)?;
                if leg.account_ref == key.0
                    && leg.amount.unit.0 == key.2
                    && entity_of(leg, declared, implicit) == key.3
                {
                    net = net
                        .checked_add(signed_leg(leg)?)
                        .ok_or(LanternError::Overflow("assertion_drift fold"))?;
                }
            }
        }
        Ok((net, self.entries.len()))
    }

    fn later(
        &self,
        through: usize,
        day: DateDay,
        evaluated: CommitSeq,
        work: &mut Meter<'_>,
    ) -> Result<LaterEntries, LanternError> {
        if !self.indexed {
            let mut entries = BTreeSet::new();
            for contribution in &self.entries {
                work.compare(1)?;
                let entry = contribution.entry;
                if entry.entry.proposal.effective_date <= day && entry.recorded_at > evaluated {
                    entries.insert(entry.vid);
                }
            }
            return Ok(LaterEntries {
                count: entries.len(),
                entries: entries.into_iter().take(MAX_CITES).collect(),
            });
        }
        let n = self.entries.len();
        let (mut lo, mut hi) = (n, n + through);
        let mut nodes = Vec::new();
        while lo < hi {
            work.compare(1)?;
            if !lo.is_multiple_of(2) {
                nodes.push(lo);
                lo += 1;
            }
            if !hi.is_multiple_of(2) {
                hi -= 1;
                nodes.push(hi);
            }
            lo /= 2;
            hi /= 2;
        }
        let mut later = LaterEntries::default();
        while let Some(node) = nodes.pop() {
            work.compare(1)?;
            if self.max_recorded[node] <= evaluated {
                continue;
            }
            if node < n {
                nodes.push(2 * node);
                nodes.push(2 * node + 1);
            } else {
                later.count += 1;
                // Count every contributor for the original exact refusal,
                // without allocating an unbounded list for a refused finding.
                if later.entries.len() < MAX_CITES {
                    later.entries.push(self.entries[node - n].entry.vid);
                }
            }
        }
        charge_sort(work, later.entries.len())?;
        later.entries.sort_unstable();
        Ok(later)
    }
}

#[derive(Default)]
struct LaterEntries {
    count: usize,
    entries: Vec<VId>,
}
