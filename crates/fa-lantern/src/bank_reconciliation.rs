//! Operational drift of exact native bank statement closes. Admission, source
//! history, cash folding and match lifecycle verification happen in the native
//! reader before this pure adapter receives its pinned snapshot. The original
//! claim remains a historical fact; observations describe subsequent changes.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::attestation::AttestationClaim;
use fa_journal::bank::{BankDecisionRef, BankReconciliationState};
use fa_journal::genesis::BookContext;

use crate::jet::{finding, procedure_boilerplate};
use crate::{
    Cite, Finding, LanternError, MAX_CITES, Params, Procedure, Severity, Snapshot, Statistic, Work,
};

pub const MAX_BANK_DRIFT_FINDINGS: usize = 100_000;
pub const MAX_BANK_DRIFT_FINDING_BYTES: usize = 16 * 1024 * 1024;

pub struct BankStatementDrift {
    params: Params,
}

procedure_boilerplate!(BankStatementDrift, "recon.bank_statement_drift");

fn invalid(message: impl Into<String>) -> LanternError {
    LanternError::Parameter {
        procedure: BankStatementDrift::ID.into(),
        name: "native_reconciliation_states".into(),
        message: message.into(),
    }
}

fn base_cites(state: &BankReconciliationState) -> Vec<Cite> {
    let recorded = &state.recorded;
    vec![
        Cite::Account(recorded.claim.manifest.account),
        Cite::Attestation(recorded.attestation_vid),
        Cite::Document(recorded.claim.manifest_oid),
        Cite::Document(recorded.claim.manifest.statement_oid),
    ]
}

fn cash_cites(state: &BankReconciliationState, work: &mut Work) -> Result<Vec<Cite>, LanternError> {
    let mut cites = base_cites(state);
    let mut entries = BTreeSet::new();
    for reference in state.changed_entries.iter().chain(&state.citing_entries) {
        work.compare(1);
        entries.insert(reference.vid);
        if entries.len() > MAX_CITES - cites.len() {
            return Err(invalid(format!(
                "the complete cash-drift observation exceeds {MAX_CITES} citations; no changed or durably citing Entry may be omitted and no partial run is returned"
            )));
        }
    }
    cites.extend(entries.into_iter().map(Cite::Entry));
    Ok(cites)
}

fn match_cites(
    state: &BankReconciliationState,
    work: &mut Work,
) -> Result<Vec<Cite>, LanternError> {
    let mut cites = base_cites(state);
    if state.recorded.claim.manifest.line_oids.len() > MAX_CITES - cites.len() {
        return Err(invalid(format!(
            "the complete match-drift source closure exceeds {MAX_CITES} citations; no statement line may be omitted and no partial run is returned"
        )));
    }
    for oid in &state.recorded.claim.manifest.line_oids {
        work.compare(1);
        cites.push(Cite::Document(*oid));
    }
    Ok(cites)
}

fn changed_matches(state: &BankReconciliationState, work: &mut Work) -> usize {
    let original: BTreeSet<BankDecisionRef> = state
        .recorded
        .claim
        .matches
        .iter()
        .copied()
        .inspect(|_| work.compare(1))
        .collect();
    let current: BTreeSet<BankDecisionRef> = state
        .active_matches
        .iter()
        .copied()
        .inspect(|_| work.compare(1))
        .collect();
    original.symmetric_difference(&current).count()
}

fn push(
    findings: &mut Vec<Finding>,
    finding: Finding,
    bytes: &mut usize,
) -> Result<(), LanternError> {
    if findings.len() >= MAX_BANK_DRIFT_FINDINGS {
        return Err(invalid(format!(
            "bank statement drift exceeds {MAX_BANK_DRIFT_FINDINGS} observations; the complete run is refused"
        )));
    }
    let size = finding.canonical_bytes()?.len();
    *bytes = bytes
        .checked_add(size)
        .filter(|total| *total <= MAX_BANK_DRIFT_FINDING_BYTES)
        .ok_or_else(|| {
            invalid(format!(
                "bank statement drift exceeds {MAX_BANK_DRIFT_FINDING_BYTES} finding bytes; the complete run is refused"
            ))
        })?;
    findings.push(finding);
    Ok(())
}

impl Procedure for BankStatementDrift {
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
        if snapshot.coordinate.book_id != book.book_id {
            return Err(invalid(
                "the snapshot and current Book context name different books",
            ));
        }
        let Some(states) = &snapshot.bank_reconciliations else {
            return Err(invalid(
                "the complete native statement-close history has not been admitted and evaluated at this snapshot; use the bank-aware procedure entry point with current Read and Reconcile authority",
            ));
        };
        let mut by_attestation = BTreeMap::new();
        for state in states {
            work.entry();
            let recorded = &state.recorded;
            if by_attestation
                .insert(recorded.attestation_vid, state)
                .is_some()
                || recorded.claim.manifest.book_id != snapshot.coordinate.book_id
                || recorded.recorded_at > snapshot.coordinate.known_at
                || recorded.claim.evaluated_known_at.0.checked_add(1)
                    != Some(recorded.recorded_at.0)
                || state.balance_drift != (state.cash_balance != recorded.claim.cash_balance)
                || state.cash_drift != (state.cash_fold_digest != recorded.claim.cash_fold_digest)
                || state.match_drift != (state.active_matches != recorded.claim.matches)
                || (state.balance_drift && !state.cash_drift)
                || (state.cash_drift && state.changed_entries.is_empty())
            {
                return Err(invalid(
                    "native bank states repeat, disagree with their original claims or fall outside the selected snapshot",
                ));
            }
            work.compare(1);
        }
        let mut population = 0_u64;
        let mut original_count = 0_usize;
        for (vid, stored) in &snapshot.attestations {
            work.compare(1);
            let AttestationClaim::Reconciled(claim) = &stored.attestation.claim else {
                continue;
            };
            original_count += 1;
            let Some(state) = by_attestation.get(vid) else {
                return Err(invalid(
                    "the native bank states omit a Reconciled attestation in the snapshot",
                ));
            };
            if stored.signed_digest != state.recorded.attestation_digest
                || stored.attestation.principal != state.recorded.principal
                || claim.as_ref() != &state.recorded.claim
            {
                return Err(invalid(
                    "the native bank state and snapshot bind different attestation facts",
                ));
            }
            if snapshot
                .coordinate
                .effective_through
                .is_none_or(|through| claim.manifest.statement_date <= through)
            {
                population += 1;
            }
        }
        if original_count != by_attestation.len() {
            return Err(invalid(
                "the native bank states contain an attestation absent from the snapshot",
            ));
        }

        let mut findings = Vec::new();
        let mut output_bytes = 0_usize;
        for state in by_attestation.values() {
            let claim = &state.recorded.claim;
            let manifest = &claim.manifest;
            if snapshot
                .coordinate
                .effective_through
                .is_some_and(|through| manifest.statement_date > through)
            {
                continue;
            }
            let account = snapshot.accounts.get(&manifest.account).ok_or_else(|| {
                invalid("a verified statement close has no account in the snapshot")
            })?;
            if state.balance_drift {
                let difference = i128::try_from(state.cash_balance.abs_diff(claim.cash_balance))
                    .map_err(|_| LanternError::Overflow("bank statement cash discrepancy"))?;
                push(
                    &mut findings,
                    finding(
                        Self::ID,
                        Severity::High,
                        Statistic {
                            name: "bank_statement_balance_drift".into(),
                            value: difference,
                            scale: crate::unit_scale(book, manifest.unit.0)?,
                            population,
                        },
                        cash_cites(state, work)?,
                        format!(
                            "account {} unit {}: statement closed on {} at {}, evaluated at prefix {} and attested at {}; cumulative cash through that statement date is {} at selected prefix {} (absolute difference {}). The original close remains a verified historical claim.",
                            account.code,
                            manifest.unit.0,
                            manifest.statement_date.render(),
                            claim.cash_balance,
                            claim.evaluated_known_at.0,
                            state.recorded.recorded_at.0,
                            state.cash_balance,
                            snapshot.coordinate.known_at.0,
                            difference,
                        ),
                    ),
                    &mut output_bytes,
                )?;
            } else if state.cash_drift {
                push(
                    &mut findings,
                    finding(
                        Self::ID,
                        Severity::Medium,
                        Statistic::count(
                            "bank_statement_contribution_drift",
                            state.changed_entries.len() as u64,
                            population,
                        ),
                        cash_cites(state, work)?,
                        format!(
                            "account {} unit {}: cumulative cash through statement close {} still equals {}, but {} contributing Entry references changed between original evaluated prefix {} and selected prefix {}; the exact cash contribution digest differs. Net-zero later changes preserve the amount, not the original contribution set.",
                            account.code,
                            manifest.unit.0,
                            manifest.statement_date.render(),
                            claim.cash_balance,
                            state.changed_entries.len(),
                            claim.evaluated_known_at.0,
                            snapshot.coordinate.known_at.0,
                        ),
                    ),
                    &mut output_bytes,
                )?;
            }
            if state.match_drift {
                let changed = changed_matches(state, work);
                if changed == 0 {
                    return Err(invalid(
                        "match drift was reported without a changed immutable confirmation reference",
                    ));
                }
                push(
                    &mut findings,
                    finding(
                        Self::ID,
                        Severity::High,
                        Statistic::count("bank_statement_match_drift", changed as u64, population),
                        match_cites(state, work)?,
                        format!(
                            "account {} unit {}: statement close {} bound {} confirmed matches at evaluated prefix {}; {} are active at selected prefix {}, and {} original/current immutable references differ. The original close is preserved; the retained line documents identify the statement population requiring review.",
                            account.code,
                            manifest.unit.0,
                            manifest.statement_date.render(),
                            claim.matches.len(),
                            claim.evaluated_known_at.0,
                            state.active_matches.len(),
                            snapshot.coordinate.known_at.0,
                            changed,
                        ),
                    ),
                    &mut output_bytes,
                )?;
            }
        }
        Ok(findings)
    }
}
