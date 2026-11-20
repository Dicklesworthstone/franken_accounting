//! A conservative bank-float cycle screen (plan §11.4, fa-m35p).
//!
//! The facade authenticates the complete active bank-match population, original
//! statement receipts and parser replay before supplying these paired lines.
//! Only exact native two-leg cash transfers are eligible. Amounts, units and
//! legal entities come from their immutable entries, never guessed references.
//! A positive result is an equal-amount cycle with a common positive float
//! interval; it is neither proof of check availability nor an allegation of
//! intent. Unmatched, split and differently sized transfers remain outside v1.

mod search;

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::genesis::BookContext;
use fa_model::{AccountType, EntryRef, Id128, Oid, Writer};
use fa_money::{Side, UnitKind};
use fa_time::DateDay;
use fgdb_crypto::Hasher;
use fgdb_types::VId;

use crate::jet::procedure_boilerplate;
use crate::projection::{entity, scoped_entity};
use crate::{Cite, Finding, LanternError, Meter, Params, Procedure, Severity, Snapshot, Statistic};

pub use fa_model::limits::{
    MAX_KITING_FINDING_BYTES, MAX_KITING_FINDINGS,
    MAX_KITING_INSTRUMENT_BYTES as MAX_INSTRUMENT_BYTES, MAX_KITING_TRANSFERS,
};
const INPUTS_DOMAIN: &[u8] = b"fa:lantern-bank-transfer-inputs:v1";

/// One retained BankLine authenticated against its original statement, exact
/// active native match and the manifest's account. Instrument identity is the
/// original statement's identifier, not a name inferred from the chart.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MatchedBankLine {
    pub manifest_oid: Oid,
    pub line_oid: Oid,
    pub account: VId,
    pub instrument: String,
    pub booking_date: DateDay,
    pub value_date: DateDay,
}

/// Two exact active bank matches belonging to the same native two-leg entry.
/// Source: bank debit / ledger credit. Destination: bank credit / ledger debit.
/// An accounting reversal does not erase an observed bank movement; native
/// unmatch history determines whether each original match remains active.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BankTransfer {
    pub entry: EntryRef,
    pub source_ordinal: u16,
    pub destination_ordinal: u16,
    pub source: MatchedBankLine,
    pub destination: MatchedBankLine,
}

impl MatchedBankLine {
    fn encode(&self, writer: &mut Writer) {
        writer
            .fixed(&self.manifest_oid.0)
            .fixed(&self.line_oid.0)
            .u128(self.account.0)
            .str(&self.instrument)
            .i32(self.booking_date.0)
            .i32(self.value_date.0);
    }
}

impl BankTransfer {
    fn encode(&self, writer: &mut Writer) {
        self.entry.encode(writer);
        writer
            .u16(self.source_ordinal)
            .u16(self.destination_ordinal);
        self.source.encode(writer);
        self.destination.encode(writer);
    }
}

pub struct Kiting {
    params: Params,
}

procedure_boilerplate!(Kiting, "graph.kiting");

fn invalid(message: impl Into<String>) -> LanternError {
    LanternError::Parameter {
        procedure: Kiting::ID.into(),
        name: "native_bank_transfers".into(),
        message: message.into(),
    }
}

fn inputs(snapshot: &Snapshot) -> Result<&[BankTransfer], LanternError> {
    let transfers = snapshot.bank_transfers.as_deref().ok_or_else(|| {
        invalid(
            "the complete native active-match and original-statement closure has not been admitted; use the bank-aware procedure entry point with current Read, Reconcile and Privileged authority",
        )
    })?;
    if transfers.len() > MAX_KITING_TRANSFERS {
        return Err(invalid(format!(
            "the paired transfer population exceeds {MAX_KITING_TRANSFERS}; narrow the selected history; no truncated population is accepted"
        )));
    }
    Ok(transfers)
}

/// Bind even empty/no-hit results to the exact paired bank dates and sources.
/// Native certificate replay separately authenticates how this vector was
/// derived; this hash is a commitment, not an authentication substitute.
pub(crate) fn inputs_digest(
    snapshot: &Snapshot,
    work: &mut Meter<'_>,
) -> Result<[u8; 32], LanternError> {
    let transfers = inputs(snapshot)?;
    let count = transfers.len() as u64;
    work.compare(count.saturating_mul(u64::from(count.saturating_add(1).ilog2().max(1)) + 1))?;
    let mut ordered: Vec<_> = transfers.iter().collect();
    ordered.sort_unstable();
    let mut hash = Hasher::new();
    hash.update(INPUTS_DOMAIN);
    hash.update(&snapshot.inputs_digest);
    hash.update(&count.to_le_bytes());
    for transfer in ordered {
        work.compare(1)?;
        let mut writer = Writer::new();
        transfer.encode(&mut writer);
        let bytes = writer.finish()?;
        hash.update(&(bytes.len() as u64).to_le_bytes());
        hash.update(&bytes);
    }
    Ok(hash.finalize().0)
}

fn line_shape(
    snapshot: &Snapshot,
    line: &MatchedBankLine,
    seen_lines: &mut BTreeSet<Oid>,
    line_kind: u8,
    manifest_kind: u8,
) -> Result<(), LanternError> {
    if line.instrument.trim().is_empty()
        || line.instrument.len() > MAX_INSTRUMENT_BYTES
        || line.instrument.chars().any(char::is_control)
        || line.line_oid == line.manifest_oid
        || !seen_lines.insert(line.line_oid)
    {
        return Err(invalid(
            "instrument identifiers must be bounded and nonempty and each original BankLine may support only one transfer",
        ));
    }
    for (oid, kind) in [
        (line.line_oid, line_kind),
        (line.manifest_oid, manifest_kind),
    ] {
        if snapshot
            .documents
            .get(&oid)
            .is_none_or(|document| document.kind != kind)
        {
            return Err(invalid(
                "a paired BankLine or its Workpaper manifest is absent from the authenticated snapshot",
            ));
        }
    }
    Ok(())
}

fn prepare<'a>(
    snapshot: &'a Snapshot,
    book: &BookContext,
    work: &mut Meter<'_>,
) -> Result<Vec<search::Transfer<'a>>, LanternError> {
    if snapshot.coordinate.book_id != book.book_id {
        return Err(invalid("snapshot and Book context name different books"));
    }
    let cash = snapshot.required_role(Kiting::ID, "cash")?;
    let transfers = inputs(snapshot)?;
    let evidence = fa_registry::evidence_policy::EvidencePolicy::embedded()?;
    // Native imports store canonical bank lines as Other + BANK_LINE_MIME.
    // SnapshotDocument omits MIME; the facade verifies it and replays the
    // original statement before admitting these transfer inputs.
    let line_kind = evidence
        .kind_by_name("Other")
        .ok_or_else(|| invalid("Other document kind is not registered"))?
        .tag;
    let manifest_kind = evidence
        .kind_by_name("Workpaper")
        .ok_or_else(|| invalid("Workpaper kind is not registered"))?
        .tag;
    let mut wanted = BTreeSet::new();
    for transfer in transfers {
        work.compare(1)?;
        if !wanted.insert(transfer.entry.vid) {
            return Err(invalid("a native two-leg transfer occurs more than once"));
        }
    }
    let mut source_entries = BTreeMap::new();
    let mut scope = entity::Scope::default();
    for entity in snapshot.declared_entities.values() {
        work.compare(1)?;
        scope.observe(Some(entity.0));
    }
    let lookup_work = u64::from((transfers.len() as u64).saturating_add(1).ilog2().max(1)) + 1;
    for entry in &snapshot.entries {
        work.entry()?;
        work.compare(lookup_work)?;
        if !wanted.contains(&entry.vid) {
            continue;
        }
        if entry.entry.proposal.legs.len() != 2 {
            return Err(invalid(
                "a paired transfer source must have exactly two original legs",
            ));
        }
        if source_entries.insert(entry.vid, entry).is_some() {
            return Err(invalid("the snapshot repeats a transfer entry identity"));
        }
        for leg in &entry.entry.proposal.legs {
            work.leg()?;
            for (dimension, value) in &leg.dimension_set {
                work.compare(1)?;
                if *dimension == fa_model::LEGAL_ENTITY_DIMENSION {
                    scope.observe(Some(value.0));
                }
            }
        }
    }
    let mut seen_lines = BTreeSet::new();
    let mut prepared = Vec::with_capacity(transfers.len());
    for transfer in transfers {
        work.compare(1)?;
        let source_entry = source_entries.get(&transfer.entry.vid).ok_or_else(|| {
            invalid("a paired bank match names an entry absent from this snapshot")
        })?;
        let proposal = &source_entry.entry.proposal;
        if source_entry.entry.entry_ref(source_entry.vid) != transfer.entry
            || source_entry.recorded_at > snapshot.coordinate.known_at
            || proposal.book_id != book.book_id
            || proposal.branch_id != Id128::TRUNK
            || !source_entry.posts()
            || proposal.legs.len() != 2
            || transfer.source_ordinal > 1
            || transfer.destination_ordinal > 1
            || transfer.source_ordinal == transfer.destination_ordinal
        {
            return Err(invalid(
                "a paired transfer must name both original ordinals and the exact immutable two-leg trunk posting at the selected prefix",
            ));
        }
        let source = &proposal.legs[usize::from(transfer.source_ordinal)];
        let destination = &proposal.legs[usize::from(transfer.destination_ordinal)];
        if source.side != Side::Credit
            || destination.side != Side::Debit
            || source.account_ref != transfer.source.account
            || destination.account_ref != transfer.destination.account
            || source.amount != destination.amount
            || source.amount.mantissa <= 0
            || !cash.contains(&source.account_ref)
            || !cash.contains(&destination.account_ref)
            || [source, destination].iter().any(|leg| {
                snapshot
                    .accounts
                    .get(&leg.account_ref)
                    .is_none_or(|account| {
                        !account.is_leaf || account.account_type != AccountType::ASSET.0
                    })
            })
        {
            return Err(invalid(
                "bank transfers require equal positive same-unit amounts on opposite leaf cash-asset legs; source is ledger credit and destination ledger debit",
            ));
        }
        let unit = book
            .units
            .get(source.amount.unit)
            .ok_or_else(|| invalid("transfer unit is not registered"))?;
        if !matches!(&unit.kind, UnitKind::Currency { .. }) {
            return Err(invalid("bank transfer units must be monetary"));
        }
        let entity = scoped_entity(&scope, source)?;
        if entity != scoped_entity(&scope, destination)? {
            return Err(invalid("a two-leg bank transfer crosses legal entities"));
        }
        for line in [&transfer.source, &transfer.destination] {
            work.compare(1)?;
            line_shape(snapshot, line, &mut seen_lines, line_kind, manifest_kind)?;
        }
        let dates = [
            transfer.source.booking_date.0,
            transfer.source.value_date.0,
            transfer.destination.booking_date.0,
            transfer.destination.value_date.0,
        ];
        let start = dates[2].max(dates[3]);
        let end = dates[1];
        // Same-day clearance, reverse-dated debits and self transfers are
        // valid records but cannot establish this positive-float motif.
        if start >= end
            || dates[1] < dates[0]
            || transfer.source.account == transfer.destination.account
            || transfer.source.instrument == transfer.destination.instrument
        {
            continue;
        }
        prepared.push(search::Transfer {
            source: transfer,
            group: search::Group {
                unit: source.amount.unit.0,
                entity,
                amount: source.amount.mantissa,
            },
            start,
            end,
            earliest: dates.into_iter().min().expect("four dates"),
            latest: dates.into_iter().max().expect("four dates"),
        });
    }
    let n = prepared.len() as u64;
    work.compare(n.saturating_mul(u64::from(n.saturating_add(1).ilog2().max(1))))?;
    prepared.sort_unstable_by_key(|transfer| transfer.source.entry);
    Ok(prepared)
}

fn cycle_cites(transfers: &[search::Transfer<'_>], cycle: &search::Cycle) -> Vec<Cite> {
    let mut entries = BTreeSet::new();
    let mut legs = BTreeSet::new();
    let mut accounts = BTreeSet::new();
    let mut documents = BTreeSet::new();
    for index in &cycle.transfers {
        let transfer = transfers[*index].source;
        entries.insert(transfer.entry.vid);
        legs.insert((transfer.entry.vid, transfer.source_ordinal));
        legs.insert((transfer.entry.vid, transfer.destination_ordinal));
        for line in [&transfer.source, &transfer.destination] {
            accounts.insert(line.account);
            documents.insert(line.line_oid);
            documents.insert(line.manifest_oid);
        }
    }
    entries
        .into_iter()
        .map(Cite::Entry)
        .chain(
            legs.into_iter()
                .map(|(entry, ordinal)| Cite::Leg { entry, ordinal }),
        )
        .chain(accounts.into_iter().map(Cite::Account))
        .chain(documents.into_iter().map(Cite::Document))
        .collect()
}

impl Procedure for Kiting {
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
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        let window = self.params.get_u32("window_days")?;
        let max_hops = self.params.get_u32("max_hops")?;
        let max_steps = self.params.get_u32("max_search_steps")?;
        if !(1..=365).contains(&window)
            || !(2..=8).contains(&max_hops)
            || !(1..=10_000_000).contains(&max_steps)
        {
            return Err(invalid(
                "window_days must be 1..=365, max_hops 2..=8 and max_search_steps 1..=10000000",
            ));
        }
        let transfers = prepare(snapshot, book, work)?;
        let searched = search::cycles(
            &transfers,
            max_hops as usize,
            window,
            u64::from(max_steps),
            snapshot.coordinate.effective_through.map(|day| day.0),
            work,
        )?;
        let mut cgse = String::with_capacity(64);
        for byte in searched.witness.decision_path_blake3 {
            use core::fmt::Write as _;
            let _ = write!(&mut cgse, "{byte:02x}");
        }
        let cycles = searched.cycles;
        work.compare(cycles.len() as u64)?;
        let mut findings = Vec::with_capacity(cycles.len());
        let mut output_bytes = 0_usize;
        for cycle in cycles {
            work.compare((cycle.transfers.len() * 12) as u64)?;
            let group = transfers[cycle.transfers[0]].group;
            let unit = book
                .units
                .get(fa_money::UnitId(group.unit))
                .ok_or_else(|| invalid("cycle unit is not registered"))?;
            let entity = group.entity.map_or_else(
                || "implicit book entity".into(),
                |id| format!("entity {:032x}", id.0),
            );
            let finding = Finding {
                procedure: Self::ID.into(),
                version: 1,
                severity: Severity::High,
                statistic: Statistic {
                    name: "bank_float_cycle_amount".into(),
                    value: group.amount,
                    scale: unit.scale,
                    population: transfers.len() as u64,
                },
                cites: cycle_cites(&transfers, &cycle),
                narrative: format!(
                    "{} exact matched bank transfers form an equal-amount cycle in {} (unit {}, scale {}), {}. Every receiving credit is booked and value-dated by {}, while every funding debit clears after that day; common float interval [{}, {}) within {} civil days. Scope: paired native two-leg cash transfers only; unmatched and split transfers are not tested. Bank value dates are the stated availability/clearance proxy; this observation does not establish intent or actual bank availability. Canonical temporal DFS (cgse_witness={cgse}).",
                    cycle.transfers.len(),
                    unit.code,
                    group.unit,
                    unit.scale,
                    entity,
                    DateDay(cycle.start).render(),
                    DateDay(cycle.start).render(),
                    DateDay(cycle.end).render(),
                    window,
                ),
            };
            output_bytes = output_bytes.checked_add(finding.canonical_bytes()?.len())
                .filter(|bytes| *bytes <= MAX_KITING_FINDING_BYTES)
                .ok_or_else(|| invalid(format!("complete cycle findings exceed {MAX_KITING_FINDING_BYTES} bytes; narrow the history, no partial result is returned")))?;
            findings.push(finding);
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests;
