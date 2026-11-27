//! Declaration-aware native intercompany coverage (recon.intercompany v3).
//!
//! The journal's atomic pairs authenticate reciprocal legs, not an aggregate
//! balance on an account. A zero aggregate cannot establish that two unrelated
//! postings are counterparts. Roles select the additional legs whose missing
//! declarations must be reported; declared pairs need no account-role guess.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::KernelError;
use fa_journal::genesis::BookContext;
use fa_model::{
    EntryClass, EntryOrigin, EntryPayload, LEGAL_ENTITY_DIMENSION, LegPayload, SupersessionKind,
};
use fgdb_types::VId;

use crate::jet::ordinal;
use crate::{Cite, Finding, LanternError, Meter, Severity, Snapshot, SnapshotEntry, Statistic};

const ID: &str = "recon.intercompany";

fn corrupt(message: impl Into<String>) -> LanternError {
    KernelError::Corrupt(format!(
        "intercompany declaration history: {}",
        message.into()
    ))
    .into()
}

fn pair_bytes(proposal: &EntryPayload) -> Option<&[u8]> {
    proposal
        .extensions
        .iter()
        .find(|(tag, _)| *tag == fa_model::entry::INTERCOMPANY_PAIRS_EXTENSION)
        .map(|(_, bytes)| bytes.as_slice())
}

fn entity(leg: &LegPayload, declared: &BTreeSet<VId>) -> Result<VId, LanternError> {
    let mut values = leg
        .dimension_set
        .iter()
        .filter(|(kind, _)| *kind == LEGAL_ENTITY_DIMENSION)
        .map(|(_, value)| *value);
    match (values.next(), values.next()) {
        (Some(value), None) if declared.contains(&value) => Ok(value),
        _ => Err(corrupt(
            "a paired leg must name exactly one declared legal entity",
        )),
    }
}

/// Check the complete authenticated prefix before interpreting its selected
/// live postings. Reversing a pair does not make its original key reusable;
/// an invalid declaration outside the effective window is still invalid
/// retained evidence.
fn history(
    snapshot: &Snapshot,
    book: &BookContext,
    work: &mut Meter<'_>,
) -> Result<(BTreeMap<VId, BTreeSet<u16>>, bool), LanternError> {
    let mut by_vid = BTreeMap::new();
    let mut reversed_by = BTreeMap::new();
    for entry in &snapshot.entries {
        work.entry()?;
        if by_vid.insert(entry.vid, entry).is_some() {
            return Err(corrupt("duplicate entry identity"));
        }
        if entry.entry.proposal.class == EntryClass::REVERSAL {
            for supersession in &entry.entry.proposal.supersession {
                if supersession.kind == SupersessionKind::Reverses
                    && reversed_by
                        .insert(supersession.target.vid, entry.vid)
                        .is_some()
                {
                    return Err(corrupt("an entry is reversed more than once"));
                }
            }
        }
    }
    let declared: BTreeSet<_> = snapshot.declared_entities.values().copied().collect();
    let mut original_keys = BTreeSet::new();
    let mut covered = BTreeMap::new();
    let mut selected_declaration = false;
    let mut liveness = fa_registers::open_items::ReversalLiveness::new(&reversed_by);
    for entry in by_vid.values() {
        work.compare(1)?;
        // This also checks cycles outside the requested effective window.
        liveness.is_live(entry.vid)?;
        let proposal = &entry.entry.proposal;
        let pairs = proposal
            .intercompany_pairs()
            .map_err(|error| corrupt(error.to_string()))?;
        let has_pairs = pairs.is_some();
        let unit = proposal.legs.first().map(|leg| leg.amount.unit);
        let mut entity_totals: BTreeMap<VId, (i128, i128)> = BTreeMap::new();
        for leg in &proposal.legs {
            work.leg()?;
            if !has_pairs {
                continue;
            }
            if leg.base_amount.is_some() || Some(leg.amount.unit) != unit {
                return Err(corrupt(
                    "native paired entries require one unit without functional valuations",
                ));
            }
            if leg.amount.mantissa < 0 {
                return Err(corrupt("a paired entry carries a negative leg amount"));
            }
            let totals = entity_totals.entry(entity(leg, &declared)?).or_default();
            let total = match leg.side {
                fa_money::Side::Debit => &mut totals.0,
                fa_money::Side::Credit => &mut totals.1,
            };
            *total = total
                .checked_add(leg.amount.mantissa)
                .ok_or_else(|| corrupt("paired entry entity totals overflow"))?;
        }
        // Counterlegs belong to the same per-entity accounting law as the
        // declared endpoints; a reciprocal pair cannot excuse an imbalance.
        for (debits, credits) in entity_totals.values() {
            work.compare(1)?;
            if debits != credits {
                return Err(corrupt(
                    "a paired entry does not balance in each legal entity",
                ));
            }
        }
        if let Some(pairs) = pairs {
            pairs
                .validate_shape(proposal.legs.len())
                .map_err(|error| corrupt(error.to_string()))?;
            if proposal.schema_minor < fa_model::entry::INTERCOMPANY_PAIRS_SCHEMA_MINOR
                || proposal.book_id != book.book_id
                || !matches!(
                    proposal.class,
                    EntryClass::ORIGINAL | EntryClass::ADJUSTING | EntryClass::REVERSAL
                )
                || (proposal.class != EntryClass::REVERSAL
                    && !matches!(&proposal.origin, EntryOrigin::Intent { .. }))
                || proposal.base_totals.is_some()
                || unit.is_none_or(|unit| book.units.get(unit).is_none())
            {
                return Err(corrupt("unsupported native pair proposal"));
            }
            selected_declaration |= snapshot
                .coordinate
                .effective_through
                .is_none_or(|through| proposal.effective_date <= through);
            let mut ordinals = BTreeSet::new();
            for pair in pairs.pairs {
                work.compare(1)?;
                let left = &proposal.legs[usize::from(pair.left_leg)];
                let right = &proposal.legs[usize::from(pair.right_leg)];
                if left.amount.mantissa <= 0
                    || left.amount != right.amount
                    || left.side == right.side
                    || left.account_ref == right.account_ref
                    || entity(left, &declared)? == entity(right, &declared)?
                {
                    return Err(corrupt(format!(
                        "pair {:?} is not reciprocal across distinct declared entities and accounts",
                        pair.pair_key
                    )));
                }
                if proposal.class != EntryClass::REVERSAL && !original_keys.insert(pair.pair_key) {
                    return Err(corrupt("an original pair_key is reused"));
                }
                ordinals.insert(pair.left_leg);
                ordinals.insert(pair.right_leg);
            }
            covered.insert(entry.vid, ordinals);
        }
        if proposal.class != EntryClass::REVERSAL {
            continue;
        }
        let [supersession] = proposal.supersession.as_slice() else {
            return Err(corrupt("a reversal requires one immutable target"));
        };
        if supersession.kind != SupersessionKind::Reverses {
            return Err(corrupt("a reversal must reverse its target"));
        }
        let target = by_vid
            .get(&supersession.target.vid)
            .ok_or_else(|| corrupt("a reversal target is absent"))?;
        if !has_pairs && pair_bytes(&target.entry.proposal).is_none() {
            continue;
        }
        if target.vid == entry.vid
            || target.recorded_at > entry.recorded_at
            || target.entry.entry_digest != supersession.target.entry_digest
            || pair_bytes(&target.entry.proposal) != pair_bytes(proposal)
            || target.entry.proposal.legs.len() != proposal.legs.len()
        {
            return Err(corrupt(
                "a pair reversal does not preserve its immutable target",
            ));
        }
        for (original, reversal) in target.entry.proposal.legs.iter().zip(&proposal.legs) {
            work.compare(1)?;
            if original.account_ref != reversal.account_ref
                || original.amount != reversal.amount
                || original.base_amount != reversal.base_amount
                || original.dimension_set != reversal.dimension_set
                || original.side.flipped() != reversal.side
            {
                return Err(corrupt(
                    "a pair reversal is not the exact monetary side-swap",
                ));
            }
        }
    }
    Ok((covered, selected_declaration))
}

pub(super) fn run(
    snapshot: &Snapshot,
    book: &BookContext,
    work: &mut Meter<'_>,
) -> Result<Vec<Finding>, LanternError> {
    let (covered, selected_declaration) = history(snapshot, book, work)?;
    let roles: BTreeSet<_> = ["intercompany", "intercompany_activity"]
        .into_iter()
        .flat_map(|role| snapshot.roles.accounts_with(role))
        .collect();
    if roles.is_empty() && !selected_declaration {
        return Err(LanternError::RoleUnassigned {
            procedure: ID.into(),
            role: "intercompany or intercompany_activity".into(),
        });
    }
    // A later-effective reversal cannot erase a leg at an earlier cutoff.
    // Fully reversed declared history is a valid, empty selected population.
    let live = snapshot.live_postings_through(snapshot.coordinate.effective_through)?;
    let mut population = 0_u64;
    let mut missing: Vec<(&SnapshotEntry, u16, &LegPayload)> = Vec::new();
    for entry in live {
        for (index, leg) in entry.entry.proposal.legs.iter().enumerate() {
            work.compare(1)?;
            if leg.amount.mantissa <= 0 {
                continue;
            }
            let ordinal = ordinal(index)?;
            let declared = covered
                .get(&entry.vid)
                .is_some_and(|ordinals| ordinals.contains(&ordinal));
            let selected_role = roles.contains(&leg.account_ref);
            if !declared && !selected_role {
                continue;
            }
            population = population
                .checked_add(1)
                .ok_or(LanternError::Overflow("intercompany candidate population"))?;
            if selected_role && !declared {
                missing.push((entry, ordinal, leg));
            }
        }
    }
    let mut findings = Vec::with_capacity(missing.len());
    for (entry, ordinal, leg) in missing {
        let mut cites = vec![
            Cite::Entry(entry.vid),
            Cite::Leg {
                entry: entry.vid,
                ordinal,
            },
            Cite::Account(leg.account_ref),
        ];
        if snapshot.periods.contains_key(&entry.period) {
            cites.push(Cite::Period(entry.period.clone()));
        }
        findings.push(Finding {
            procedure: ID.into(),
            version: 3,
            severity: Severity::Critical,
            statistic: Statistic {
                name: "intercompany_undeclared".into(),
                value: leg.amount.mantissa,
                scale: crate::unit_scale(book, leg.amount.unit.0)?,
                population,
            },
            cites,
            narrative: format!(
                "intercompany leg {ordinal} in entry {:032x} on account {:032x} in period {} unit {} has no declared reciprocal pair",
                entry.vid.0, leg.account_ref.0, entry.period, leg.amount.unit.0,
            ),
        });
    }
    Ok(findings)
}
