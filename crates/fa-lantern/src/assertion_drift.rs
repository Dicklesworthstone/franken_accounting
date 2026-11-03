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

use std::collections::BTreeSet;

use fa_journal::attestation::AttestationClaim;
use fa_journal::genesis::BookContext;
use fa_money::{Amount, Side, UnitId};
use fgdb_types::VId;

use crate::jet::{finding, procedure_boilerplate};
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
        let mut posted: Vec<_> = snapshot.entries.iter().filter(|e| e.posts()).collect();
        posted.sort_by_key(|e| e.vid);
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
            let mut fold = 0i128;
            let mut later = Vec::new();
            for e in &posted {
                if e.period != claim.period
                    || e.entry.proposal.effective_date > claim.as_of_effective
                {
                    continue;
                }
                let mut moved = false;
                for leg in &e.entry.proposal.legs {
                    work.compare(1)?;
                    if leg.account_ref != claim.account || leg.amount.unit.0 != claim.unit_id {
                        continue;
                    }
                    let leg_entity = leg
                        .dimension_set
                        .iter()
                        .find(|(dimension, _)| *dimension == fa_model::LEGAL_ENTITY_DIMENSION)
                        .filter(|(_, value)| declared_values.contains(value))
                        .map(|(_, value)| *value)
                        .or(implicit_entity);
                    if leg_entity != entity {
                        continue;
                    }
                    let magnitude = i128::try_from(leg.amount.mantissa.unsigned_abs())
                        .map_err(|_| LanternError::Overflow("assertion_drift leg magnitude"))?;
                    let signed = match leg.side {
                        Side::Debit => magnitude,
                        Side::Credit => magnitude
                            .checked_neg()
                            .ok_or(LanternError::Overflow("assertion_drift leg sign"))?,
                    };
                    fold = fold
                        .checked_add(signed)
                        .ok_or(LanternError::Overflow("assertion_drift fold"))?;
                    moved = true;
                }
                if moved && e.recorded_at > claim.evaluated_known_at {
                    later.push(e.vid);
                }
            }
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
            later.sort_unstable();
            later.dedup();
            if later.len() > MAX_CITES - cites.len() {
                return Err(LanternError::Parameter {
                    procedure: Self::ID.into(),
                    name: "attestation".into(),
                    message: format!(
                        "attestation {:032x} drifted through {} later entries, more than one finding cites ({MAX_CITES}); no entry is omitted and no partial run is returned",
                        attestation.0,
                        later.len()
                    ),
                });
            }
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
