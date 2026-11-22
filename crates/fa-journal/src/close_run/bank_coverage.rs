//! Complete registered-bank coverage, reconstructed from native REA controls.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::close_run::MAX_BANK_INSTRUMENT_COVERAGE;
use fa_model::symbols::{label, property};
use fa_model::{InstrumentKind, InstrumentSpec, Oid, Writer, domain_digest};
use fa_money::UnitId;
use fa_policy::Capability;
use fa_time::DateDay;
use fgdb::Database;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::BookContext;
use crate::bank::{BankDecisionRef, admit_bank_match_history, reconciliation_states_at};
use crate::refusal::{Outcome, Refusal, code, exit};
use crate::rows::{book_root, bytes};

use super::bank_checkpoint::{checkpoint_for_state, period_at};

/// One registered bank instrument and the explicitly selected native
/// reconciliation that covers its own account and unit through period end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankInstrumentCoverageItem {
    pub instrument: VId,
    pub code: String,
    pub account: VId,
    pub unit: UnitId,
    pub manifest_oid: Oid,
    pub attestation: BankDecisionRef,
    pub statement_date: DateDay,
    pub checkpoint_digest: [u8; 32],
}

/// An authenticated inventory and its complete, one-to-one bank coverage.
/// The inventory includes every BankAccount registered at `known_at`.
/// Instrument registration has no independent civil-date lifecycle, so this
/// never infers an opening or closing date from a schema-control envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankInstrumentCoverageCheckpoint {
    period: String,
    known_at: CommitSeq,
    manifest_oids: Vec<Oid>,
    instruments: Vec<BankInstrumentCoverageItem>,
    inventory_digest: [u8; 32],
    source_digest: [u8; 32],
}

impl BankInstrumentCoverageCheckpoint {
    pub fn period(&self) -> &str {
        &self.period
    }

    pub fn known_at(&self) -> CommitSeq {
        self.known_at
    }

    pub fn manifest_oids(&self) -> &[Oid] {
        &self.manifest_oids
    }

    /// Stable ascending instrument-identity order, including an empty result
    /// when the complete authenticated inventory contains no BankAccounts.
    pub fn instruments(&self) -> &[BankInstrumentCoverageItem] {
        &self.instruments
    }

    pub fn inventory_digest(&self) -> &[u8; 32] {
        &self.inventory_digest
    }

    pub fn source_digest(&self) -> &[u8; 32] {
        &self.source_digest
    }
}

fn incomplete(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::PLAN_INVALIDATED,
        exit::CONFLICT,
        message,
        "plan §7.5 (reconcile every registered bank instrument), §4.5 (Instrument MIRRORS Account)",
        "select exactly one clean period-end reconciliation manifest for each registered BankAccount account/unit; resolve missing or ambiguous instrument mappings and review the complete close again",
    )
}

/// Verify all registered bank instruments under current whole-book Read and
/// Reconcile authority. Manifest identities are explicit; the kernel never
/// guesses bank accounts from chart balances or chooses a competing statement.
pub fn verify_bank_instrument_coverage_checkpoint<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    manifest_oids: &[Oid],
    period: &str,
    known_at: Option<CommitSeq>,
) -> Outcome<BankInstrumentCoverageCheckpoint> {
    let at = match admit_bank_match_history(db, book, capability, known_at)? {
        Ok(at) => at,
        Err(refusal) => return Ok(Err(refusal)),
    };
    bank_instrument_coverage_checkpoint_at(db, cx, book, manifest_oids, period, at)
}

/// The caller already admitted source access, or is authenticating an
/// original receipt at its recorded prefix. Both paths reproduce native
/// history; a caller-supplied count is never evidence of completeness.
pub(super) fn bank_instrument_coverage_checkpoint_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    manifest_oids: &[Oid],
    period_code: &str,
    at: CommitSeq,
) -> Outcome<BankInstrumentCoverageCheckpoint> {
    if manifest_oids.len() > MAX_BANK_INSTRUMENT_COVERAGE {
        return Ok(Err(incomplete(format!(
            "bank coverage exceeds the {MAX_BANK_INSTRUMENT_COVERAGE}-manifest close-graph bound",
        ))));
    }
    let mut selected = manifest_oids.to_vec();
    selected.sort_by_key(|oid| oid.0);
    if selected.windows(2).any(|pair| pair[0] == pair[1]) {
        return Ok(Err(incomplete("bank coverage contains duplicate manifests")));
    }
    let period = match period_at(db, book, period_code, at)? {
        Ok(period) => period,
        Err(refusal) => return Ok(Err(refusal)),
    };
    // This is also required for empty inventories: retiring a CreateInstrument
    // control together with its projection must not erase an omitted bank.
    crate::entry_history::verify_entry_history(db, cx, book, Some(at))?;
    let rea = crate::rea::read_rea_at(db, book, at)?;
    let banks: Vec<_> = rea
        .instruments
        .values()
        .filter(|instrument| instrument.kind == InstrumentKind::BankAccount)
        .collect();
    if banks.len() > MAX_BANK_INSTRUMENT_COVERAGE {
        return Ok(Err(incomplete(format!(
            "all {} registered bank instruments exceed the {MAX_BANK_INSTRUMENT_COVERAGE}-instrument close-graph bound; partial coverage is not admissible",
            banks.len(),
        ))));
    }
    let mut by_account = BTreeMap::new();
    for instrument in &banks {
        if let Some(prior) =
            by_account.insert((instrument.mirrors_account, instrument.unit), *instrument)
        {
            return Ok(Err(incomplete(format!(
                "registered bank instruments `{}` and `{}` share one account/unit; an account-level reconciliation cannot establish separate instrument coverage",
                prior.code, instrument.code,
            ))));
        }
    }
    if selected.len() != banks.len() {
        return Ok(Err(incomplete(format!(
            "bank coverage selects {} manifests for {} registered bank instruments; every instrument requires one distinct manifest",
            selected.len(), banks.len(),
        ))));
    }
    let root = db
        .vertex_at(book_root(), at)?
        .filter(|root| root.labels.contains(&label::BOOK))
        .ok_or_else(|| super::corrupt("bank coverage has no authentic Book source subject"))?;
    let root_payload = bytes(&root, property::FA_PAYLOAD, "bank coverage Book payload")?;
    let mut inventory = Writer::new();
    inventory
        .u16(1)
        .fixed(&book.book_id.0)
        .u128(root.vid.0)
        .bytes(&root_payload)
        .u32(banks.len() as u32);
    for instrument in &banks {
        let spec = InstrumentSpec {
            code: instrument.code.clone(),
            name: instrument.name.clone(),
            kind: instrument.kind,
            unit: instrument.unit,
            held_at_party: instrument.held_at_party,
            mirrors_account: instrument.mirrors_account,
            external_ids: instrument.external_ids.clone(),
        };
        inventory
            .u128(instrument.vid.0)
            .u64(instrument.created_at.0)
            .bytes(&spec.encode().map_err(super::encode)?);
    }
    let inventory_digest = domain_digest(
        b"fa:close-bank-instrument-inventory:v1",
        &[&inventory.finish().map_err(super::encode)?],
    );
    let states = if selected.is_empty() {
        Vec::new()
    } else {
        match reconciliation_states_at(db, cx, book, None, at)? {
            Ok(states) => states,
            Err(refusal) => return Ok(Err(refusal)),
        }
    };
    let mut instruments = Vec::with_capacity(banks.len());
    let mut attestations = BTreeSet::new();
    for manifest_oid in &selected {
        let Some(latest) = states
            .iter()
            .filter(|state| state.recorded.claim.manifest_oid == *manifest_oid)
            .max_by_key(|state| (state.recorded.recorded_at, state.recorded.attestation_vid))
        else {
            return Ok(Err(incomplete(format!(
                "selected manifest {:02x?} has no native reconciliation at this prefix",
                manifest_oid.0,
            ))));
        };
        let checkpoint = match checkpoint_for_state(book, *manifest_oid, &period, at, latest)? {
            Ok(checkpoint) => checkpoint,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let Some(instrument) = by_account.remove(&(checkpoint.account(), checkpoint.unit())) else {
            return Ok(Err(incomplete(
                "a selected manifest duplicates covered account/unit scope or names no registered BankAccount instrument",
            )));
        };
        if !attestations.insert(checkpoint.attestation().vid) {
            return Ok(Err(incomplete(
                "one reconciliation attestation cannot cover multiple registered banks",
            )));
        }
        instruments.push(BankInstrumentCoverageItem {
            instrument: instrument.vid,
            code: instrument.code.clone(),
            account: instrument.mirrors_account,
            unit: instrument.unit,
            manifest_oid: *manifest_oid,
            attestation: checkpoint.attestation(),
            statement_date: checkpoint.statement_date(),
            checkpoint_digest: *checkpoint.source_digest(),
        });
    }
    if !by_account.is_empty() {
        return Ok(Err(incomplete(
            "a registered BankAccount has no selected period-end reconciliation",
        )));
    }
    instruments.sort_by_key(|item| item.instrument);
    let mut source = Writer::new();
    source
        .u16(1)
        .fixed(&book.book_id.0)
        .u128(root.vid.0)
        .fixed(&inventory_digest)
        .u128(period.vid.0)
        .str(&period.calendar_id)
        .str(&period.code)
        .i32(period.fiscal_year)
        .u16(period.ordinal)
        .u8(crate::rows::kind_tag(period.kind) as u8)
        .i32(period.start.0)
        .i32(period.end.0)
        .list(&instruments, |w, item| {
            w.u128(item.instrument.0)
                .fixed(&item.manifest_oid.0)
                .u128(item.attestation.vid.0)
                .fixed(&item.attestation.digest)
                .fixed(&item.checkpoint_digest);
        });
    let source_digest = domain_digest(
        b"fa:close-bank-instrument-coverage:v1",
        &[&source.finish().map_err(super::encode)?],
    );
    Ok(Ok(BankInstrumentCoverageCheckpoint {
        period: period.code,
        known_at: at,
        manifest_oids: selected,
        instruments,
        inventory_digest,
        source_digest,
    }))
}
