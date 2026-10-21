//! `recon.assertion_drift` (plan §9.4, bead fa-nwgf, `claim = "invariant"`):
//! every `RegisterEquals` attestation re-evaluated against the posted journal
//! fold at the snapshot coordinate.
//!
//! An attestation stays a historical fact: it held at the prefix it evaluated
//! (`evaluated_known_at`). A finding says only that its cell no longer folds
//! to the attested amount, and names why: the entries recorded after that
//! prefix whose legs move the cell. It cites the Attestation itself, the
//! account, the period and every such entry; a population that needs more
//! citations than one finding carries refuses the run rather than omit one.
//! Entries in other cells (another account, unit, entity, period, or dated
//! after the cell's as-of day) never contribute.

use std::collections::BTreeMap;

use fa_journal::attestation::AttestationClaim;
use fa_journal::genesis::BookContext;
use fa_money::{Amount, Side, UnitId};
use fgdb_types::VId;

use crate::jet::{finding, procedure_boilerplate};
use crate::{
    Cite, Finding, LanternError, MAX_CITES, Params, Procedure, Severity, Snapshot, Statistic, Work,
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
        1
    }
    fn params(&self) -> &Params {
        &self.params
    }
    fn run(
        &self,
        snapshot: &Snapshot,
        book: &BookContext,
        work: &mut Work,
    ) -> Result<Vec<Finding>, LanternError> {
        let mut live = snapshot.live_postings()?;
        live.sort_by_key(|e| e.vid);
        let entity_value: BTreeMap<&str, VId> = snapshot
            .rea
            .legal_entities
            .values()
            .map(|le| (le.code.as_str(), le.dimension_value_vid))
            .collect();
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
            work.compare(1);
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
            for e in &live {
                if e.period != claim.period
                    || e.entry.proposal.effective_date > claim.as_of_effective
                {
                    continue;
                }
                let mut moved = false;
                for leg in &e.entry.proposal.legs {
                    work.compare(1);
                    if leg.account_ref != claim.account
                        || leg.amount.unit.0 != claim.unit_id
                        || entity.is_some_and(|d| !leg.dimension_set.iter().any(|(_, v)| *v == d))
                    {
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
                "no entry recorded after the attestation moves the cell, so the attested amount never matched its own prefix".to_string()
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
