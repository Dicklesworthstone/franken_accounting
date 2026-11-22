//! A close prerequisite derived exclusively from native reconciliation history.

use asupersync::fs::Vfs;
use fa_model::symbols::label;
use fa_model::{Oid, Writer, domain_digest, period_vid};
use fa_money::UnitId;
use fa_policy::Capability;
use fa_time::DateDay;
use fgdb::Database;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::BookContext;
use crate::bank::{BankDecisionRef, admit_bank_match_history, reconciliation_states_at};
use crate::refusal::{Outcome, Refusal, code, exit};
use crate::rows::PeriodRow;

/// The exact native reconciliation checked at one recorded prefix. These
/// fields cannot be supplied independently by a caller or a checklist action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankReconciliationCheckpoint {
    manifest_oid: Oid,
    period: String,
    known_at: CommitSeq,
    attestation: BankDecisionRef,
    statement_date: DateDay,
    account: VId,
    unit: UnitId,
    source_digest: [u8; 32],
}

impl BankReconciliationCheckpoint {
    pub fn manifest_oid(&self) -> Oid {
        self.manifest_oid
    }

    pub fn period(&self) -> &str {
        &self.period
    }

    pub fn known_at(&self) -> CommitSeq {
        self.known_at
    }

    pub fn attestation(&self) -> BankDecisionRef {
        self.attestation
    }

    pub fn statement_date(&self) -> DateDay {
        self.statement_date
    }

    pub fn account(&self) -> VId {
        self.account
    }

    pub fn unit(&self) -> UnitId {
        self.unit
    }

    /// The period and immutable native attestation, after exact current
    /// cash-contribution and match checks. Unrelated publications do not
    /// change this identity; `known_at` is deliberately not part of it.
    pub fn source_digest(&self) -> &[u8; 32] {
        &self.source_digest
    }
}

fn unavailable(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::PLAN_INVALIDATED,
        exit::CONFLICT,
        message,
        "plan §7.5 (reconcile bank instruments before period close), §9.4 (reconciliation drift)",
        "retain and reconcile the bank statement through the period's final day, resolve any cash or match drift, and review the close again",
    )
}

/// Reproduce an exact statement reconciliation covering the close period's
/// final day. Current whole-book Read and Reconcile admission precedes every
/// source observation. The caller must hydrate native history after admission
/// when opening a checkpointed book, as for the bank metadata reader.
pub fn verify_bank_reconciliation_checkpoint<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    manifest_oid: Oid,
    period: &str,
    known_at: Option<CommitSeq>,
) -> Outcome<BankReconciliationCheckpoint> {
    let at = match admit_bank_match_history(db, book, capability, known_at)? {
        Ok(at) => at,
        Err(refusal) => return Ok(Err(refusal)),
    };
    bank_reconciliation_checkpoint_at(db, cx, book, manifest_oid, period, at)
}

/// Internal integrity replay uses the receipt's original prefix, without
/// inventing authority or reviving a historical controller's current grant.
pub(super) fn bank_reconciliation_checkpoint_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    manifest_oid: Oid,
    period_code: &str,
    at: CommitSeq,
) -> Outcome<BankReconciliationCheckpoint> {
    if at.0 == 0 || at > db.frontier()? {
        return Ok(Err(unavailable(
            "the bank verification selects an unavailable recorded prefix",
        )));
    }
    let period_id = period_vid(&book.calendar.id, period_code);
    let Some(row) = db.vertex_at(period_id, at)? else {
        return Ok(Err(unavailable(
            "the bank verification's close period does not exist at this prefix",
        )));
    };
    let period = PeriodRow::decode(&row)?;
    if !row.labels.contains(&label::PERIOD)
        || period.vid != period_id
        || period.calendar_id != book.calendar.id
        || period.code != period_code
        || period.start >= period.end
    {
        return Err(super::corrupt(
            "bank verification period differs from its native identity or bounds",
        ));
    }
    let spec = crate::fx::book_spec_at(db, book, at)?;
    let creation = crate::period_creation::PeriodCreation::from_spec(&spec, period.fiscal_year)?;
    let Some((definition, _)) = creation
        .periods
        .iter()
        .find(|(definition, _)| definition.code == period_code)
    else {
        return Err(super::corrupt(
            "bank verification period is absent from its canonical fiscal year",
        ));
    };
    // Period vertices are projections. An altered scalar end must not turn
    // a partial-period statement into a complete close. Reproduce the original
    // birth definition, including the legitimate pre-opening Historical kind.
    if period.fiscal_year != definition.fiscal_year
        || period.ordinal != definition.ordinal
        || period.kind != definition.kind
        || period.start != definition.start
        || period.end != definition.end
    {
        return Err(super::corrupt(
            "bank verification period differs from its canonical birth definition",
        ));
    }
    let statements = match reconciliation_states_at(db, cx, book, Some(manifest_oid), at)? {
        Ok(statements) => statements,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let Some(latest) = statements
        .into_iter()
        .max_by_key(|state| (state.recorded.recorded_at, state.recorded.attestation_vid))
    else {
        return Ok(Err(unavailable(
            "the selected bank import has no native reconciliation at this prefix",
        )));
    };
    let manifest = &latest.recorded.claim.manifest;
    // Native period bounds are exclusive at the end, including fiscal
    // calendars with weeks or non-January starts. Never infer dates from a
    // period's display code or accept an earlier partially covering statement.
    if manifest.statement_date.0 != period.end.0 - 1 {
        return Ok(Err(unavailable(
            "the reconciled bank statement must end on this close period's final day",
        )));
    }
    if latest.balance_drift || latest.cash_drift || latest.match_drift {
        return Ok(Err(unavailable(
            "the selected bank reconciliation has cash-contribution, balance, or match drift",
        )));
    }
    let attestation = BankDecisionRef {
        vid: latest.recorded.attestation_vid,
        digest: latest.recorded.attestation_digest,
    };
    let mut source = Writer::new();
    source
        .u16(1)
        .fixed(&book.book_id.0)
        .fixed(&manifest_oid.0)
        .u128(period.vid.0)
        .str(&period.calendar_id)
        .str(&period.code)
        .i32(period.fiscal_year)
        .u16(period.ordinal)
        .u8(crate::rows::kind_tag(period.kind) as u8)
        .i32(period.start.0)
        .i32(period.end.0)
        .u128(attestation.vid.0)
        .fixed(&attestation.digest)
        .u128(manifest.account.0)
        .u32(manifest.unit.0)
        .i32(manifest.statement_date.0);
    let source_digest = domain_digest(
        b"fa:close-bank-reconciliation-checkpoint:v1",
        &[&source.finish().map_err(super::encode)?],
    );
    Ok(Ok(BankReconciliationCheckpoint {
        manifest_oid,
        period: period.code,
        known_at: at,
        attestation,
        statement_date: manifest.statement_date,
        account: manifest.account,
        unit: manifest.unit,
        source_digest,
    }))
}
