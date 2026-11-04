//! Exact cells and effective prefixes for `RegisterEquals` comparisons.
//!
//! The native register is a gross period fold. Supersession never deletes a
//! posting from that fold: a reversal contributes in its own period and day.
//! Resolve entities exactly as `fa_registers::entity::entity_of` does, from
//! declared balancing entities and the legal-entity dimension, not REA metadata.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::attestation::RegisterEqualsClaim;
use fa_model::{LEGAL_ENTITY_DIMENSION, LegPayload};
use fa_time::DateDay;
use fgdb_types::VId;

use crate::amount::signed_leg;
use crate::{Cite, LanternError, MAX_CITES, Meter, Snapshot};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct CellKey {
    pub account: VId,
    pub period: String,
    pub unit_id: u32,
    pub entity: Option<VId>,
}

pub(super) struct CellScope<'a> {
    entities: &'a BTreeMap<String, VId>,
    names: BTreeMap<VId, &'a str>,
    implicit: Option<VId>,
}

impl<'a> CellScope<'a> {
    pub fn new(snapshot: &'a Snapshot) -> Self {
        let entities = &snapshot.declared_entities;
        Self {
            entities,
            names: entities.iter().map(|(k, v)| (*v, k.as_str())).collect(),
            implicit: (entities.len() == 1)
                .then(|| entities.values().next().copied())
                .flatten(),
        }
    }

    pub fn leg_key(&self, period: &str, leg: &LegPayload) -> CellKey {
        let entity = leg
            .dimension_set
            .iter()
            .find(|(dimension, _)| *dimension == LEGAL_ENTITY_DIMENSION)
            .filter(|(_, value)| self.names.contains_key(value))
            .map(|(_, value)| *value)
            .or(self.implicit);
        CellKey {
            account: leg.account_ref,
            period: period.into(),
            unit_id: leg.amount.unit.0,
            entity,
        }
    }

    pub fn claim_key(
        &self,
        procedure: &'static str,
        attestation: VId,
        claim: &RegisterEqualsClaim,
    ) -> Result<CellKey, LanternError> {
        // None denotes the unassigned cell, even in a single-entity book.
        // Native untagged postings in that book belong to its implicit entity.
        let entity = claim
            .entity
            .as_ref()
            .map(|code| {
                self.entities
                    .get(code)
                    .copied()
                    .ok_or_else(|| LanternError::Parameter {
                        procedure: procedure.into(),
                        name: "attestation".into(),
                        message: format!(
                            "attestation {:032x} names entity `{code}`, which this book does not declare",
                            attestation.0
                        ),
                    })
            })
            .transpose()?;
        Ok(CellKey {
            account: claim.account,
            period: claim.period.clone(),
            unit_id: claim.unit_id,
            entity,
        })
    }

    pub fn entity_name(&self, entity: Option<VId>) -> &str {
        entity
            .and_then(|value| self.names.get(&value).copied())
            .unwrap_or("<unassigned>")
    }
}

struct Contribution {
    day: DateDay,
    entry: VId,
    ordinal: usize,
    net: i128,
}

/// Per-cell, day-ordered prefix nets. Claim lookup is logarithmic; only the
/// contributing entries of a nonzero finding need to be visited again to cite.
pub(super) struct PostedFold {
    cells: BTreeMap<CellKey, Vec<Contribution>>,
}

impl PostedFold {
    pub fn read(
        snapshot: &Snapshot,
        scope: &CellScope<'_>,
        work: &mut Meter<'_>,
    ) -> Result<Self, LanternError> {
        let mut cells: BTreeMap<CellKey, Vec<Contribution>> = BTreeMap::new();
        for entry in &snapshot.entries {
            work.entry()?;
            if !entry.posts()
                || snapshot
                    .coordinate
                    .effective_through
                    .is_some_and(|day| entry.entry.proposal.effective_date > day)
            {
                continue;
            }
            for (ordinal, leg) in entry.entry.proposal.legs.iter().enumerate() {
                work.leg()?;
                cells
                    .entry(scope.leg_key(&entry.period, leg))
                    .or_default()
                    .push(Contribution {
                        day: entry.entry.proposal.effective_date,
                        entry: entry.vid,
                        ordinal,
                        net: signed_leg(leg.side, leg.amount.mantissa)?,
                    });
            }
        }
        for contributions in cells.values_mut() {
            let n = u64::try_from(contributions.len()).unwrap_or(u64::MAX);
            work.compare(n.saturating_mul(u64::from(n.max(1).ilog2()) + 1))?;
            contributions.sort_by_key(|c| (c.day, c.entry, c.ordinal));
            let mut net = 0i128;
            for contribution in contributions {
                work.compare(1)?;
                net = net
                    .checked_add(contribution.net)
                    .ok_or(LanternError::Overflow("RegisterEquals gross period prefix"))?;
                contribution.net = net;
            }
        }
        Ok(Self { cells })
    }

    pub fn at(
        &self,
        key: &CellKey,
        day: DateDay,
        work: &mut Meter<'_>,
    ) -> Result<CellAt<'_>, LanternError> {
        let entries = self.cells.get(key).map_or(&[][..], Vec::as_slice);
        let (mut lo, mut hi) = (0, entries.len());
        while lo < hi {
            work.compare(1)?;
            let mid = lo + (hi - lo) / 2;
            if entries[mid].day <= day {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        Ok(CellAt {
            contributions: &entries[..lo],
        })
    }
}

pub(super) struct CellAt<'a> {
    contributions: &'a [Contribution],
}

impl CellAt<'_> {
    pub fn net(&self) -> i128 {
        self.contributions.last().map_or(0, |c| c.net)
    }

    pub fn entries(&self, work: &mut Meter<'_>) -> Result<BTreeSet<VId>, LanternError> {
        let mut entries = BTreeSet::new();
        for contribution in self.contributions {
            work.compare(1)?;
            entries.insert(contribution.entry);
        }
        Ok(entries)
    }
}

/// A comparison is useful only if every participating entry and the asserted
/// baseline can be named. Never turn citation overflow into partial evidence.
pub(super) fn cites(
    procedure: &'static str,
    snapshot: &Snapshot,
    key: &CellKey,
    attestation: Option<VId>,
    entries: BTreeSet<VId>,
) -> Result<Vec<Cite>, LanternError> {
    let mut cites = Vec::new();
    if let Some(vid) = attestation {
        cites.push(Cite::Attestation(vid));
    }
    cites.push(Cite::Account(key.account));
    if snapshot.periods.contains_key(&key.period) {
        cites.push(Cite::Period(key.period.clone()));
    }
    if entries.len() > MAX_CITES - cites.len() {
        return Err(LanternError::Parameter {
            procedure: procedure.into(),
            name: "citations".into(),
            message: format!(
                "register comparison needs {} entry citations, more than one finding carries ({MAX_CITES}); no entry is omitted and no partial run is returned",
                entries.len()
            ),
        });
    }
    cites.extend(entries.into_iter().map(Cite::Entry));
    Ok(cites)
}
