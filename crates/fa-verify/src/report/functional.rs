//! Independently repriced functional-currency trial balances and statements.
//!
//! Complete signed history supplies entries, chart, fiscal periods and Rate
//! intake receipts. Book parameters are certificate/receipt-bound inputs, not
//! a proof of genesis. Carrying transfers and migration activation require
//! separate source proofs; this profile implements direct SpotClose/Average.

mod arithmetic;
mod valuation;

use super::{
    Certificate, ReportError, Selection, failed, metadata, open_items, registry, statement, text,
};
use crate::blake3::hash_parts;
use crate::codec::{Reader, Writer};
use crate::envelope::{LeafEnvelope, Leg};
use std::collections::{BTreeMap, BTreeSet};

pub(super) use valuation::{MAX_RATE_BYTES, MAX_RATES};
pub(super) const MAX_BOOK_BYTES: usize = 1024 * 1024;
pub(super) const OUTPUT_FORMAT: &[u8] = b"fa:functional-trial-balance:v1";
pub(super) const STATEMENT_OUTPUT_FORMAT: &[u8] = b"fa:functional-statement:v1";
const BOOK_PARAMETERS_SOURCE: &str =
    "certificate-bound-report-parameters; genesis-registration-not-proved";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedFunctionalStatement {
    pub base_unit: u32,
    /// Every line uses independently checked retained base amounts. The
    /// complete historical chart supplies mappings, including zero balances.
    pub statement: statement::VerifiedStatement,
    /// The checkpoint does not authenticate the separate Book root vertex.
    pub book_parameters_source: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedFunctionalCell {
    pub account: u128,
    pub unit_id: u32,
    pub entity: Option<String>,
    pub debits: i128,
    pub credits: i128,
    pub entry_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedFunctionalTrialBalance {
    pub base_unit: u32,
    pub effective_through: Option<i32>,
    pub activity: bool,
    pub periods: Vec<String>,
    pub cells: Vec<VerifiedFunctionalCell>,
    pub pending: Vec<VerifiedFunctionalCell>,
    pub watermark: Option<u64>,
    pub entries: u64,
    pub fold_digest: [u8; 32],
    pub accounts: BTreeMap<u128, super::VerifiedReportAccount>,
    /// The checkpoint does not authenticate the separate Book root vertex.
    pub book_parameters_source: &'static str,
}

fn add(a: i128, b: i128) -> Result<i128, ReportError> {
    a.checked_add(b)
        .ok_or_else(|| failed("functional_arithmetic", "functional amount overflow"))
}
fn framed_hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut w = Writer::default();
    for part in parts {
        w.bytes(part);
    }
    hash_parts(domain, &[&w.buf])
}

struct BookParameters {
    book: [u8; 16],
    base: u32,
    calendar: String,
    entities: BTreeMap<u128, String>,
}
impl BookParameters {
    fn read(bytes: &[u8], expected_book: &[u8; 16]) -> Result<Self, ReportError> {
        if bytes.len() > MAX_BOOK_BYTES {
            return Err(failed("bounded_input", "Book parameters exceed 1 MiB"));
        }
        let mut r = Reader::new(bytes);
        if r.u16("book.version")? != 2 {
            return Err(failed(
                "supported_report",
                "functional reports require version-2 Book parameters and complete period controls",
            ));
        }
        let book = r.fixed("book.id")?;
        if book != *expected_book {
            return Err(failed(
                "functional_book",
                "Book parameters belong to another book",
            ));
        }
        text(&mut r, 256, "book.name")?;
        let base = r.u32("book.base_unit")?;
        let calendar = text(&mut r, 64, "book.calendar")?.to_string();
        if calendar.is_empty() {
            return Err(failed("functional_book", "Book calendar is empty"));
        }
        r.u8("calendar.adjustment_periods")?;
        match r.u8("calendar.kind")? {
            0 => {
                if !(1..=12).contains(&r.u8("calendar.year_start_month")?) {
                    return Err(failed("functional_book", "invalid monthly calendar"));
                }
            }
            kind @ (1 | 2) => {
                if kind == 1 && r.u8("calendar.pattern")? > 2 {
                    return Err(failed("functional_book", "invalid week pattern"));
                }
                if r.u8("calendar.rule")? > 1
                    || r.u8("calendar.weekday")? > 6
                    || !(1..=12).contains(&r.u8("calendar.month")?)
                {
                    return Err(failed("functional_book", "invalid weekly calendar"));
                }
            }
            3 => {
                let count = r.count(4096, 8, "calendar.years")?;
                let mut last_year = None;
                for _ in 0..count {
                    let year = r.i32("calendar.year")?;
                    if last_year.is_some_and(|last| last >= year) {
                        return Err(failed(
                            "functional_book",
                            "custom calendar years are unordered",
                        ));
                    }
                    last_year = Some(year);
                    let bounds = r.count(4096, 4, "calendar.bounds")?;
                    if bounds < 2 {
                        return Err(failed("functional_book", "custom calendar has no period"));
                    }
                    let mut last = None;
                    for _ in 0..bounds {
                        let day = r.i32("calendar.bound")?;
                        if last.is_some_and(|last| last >= day) {
                            return Err(failed(
                                "functional_book",
                                "custom calendar bounds are unordered",
                            ));
                        }
                        last = Some(day);
                    }
                }
                if count == 0 {
                    return Err(failed("functional_book", "custom calendar has no year"));
                }
            }
            _ => return Err(failed("functional_book", "unsupported calendar kind")),
        }
        if r.remaining() > 0 {
            let zone = r.u8("book.time_zone")?;
            if zone > 1 || zone == 0 && r.remaining() == 0 {
                return Err(failed(
                    "functional_book",
                    "noncanonical time-zone parameter",
                ));
            }
        }
        let mut entities = BTreeMap::new();
        if r.remaining() > 0 {
            let count = r.count(256, 12, "book.entities")?;
            for _ in 0..count {
                let code = text(&mut r, 32, "entity.code")?;
                text(&mut r, 256, "entity.name")?;
                let functional_unit = r.u32("entity.functional_unit")?;
                let digest = framed_hash(
                    b"fa:vid:dimension-value:v1",
                    &[&book, b"legal_entity", code.as_bytes()],
                );
                let identity = u128::from_le_bytes(digest[..16].try_into().expect("sixteen bytes"));
                if code.is_empty()
                    || functional_unit != base
                    || entities.insert(identity, code.into()).is_some()
                {
                    return Err(failed(
                        "functional_book",
                        "entities must be unique and share the declared base currency",
                    ));
                }
            }
            if count == 0 && r.remaining() == 0 {
                return Err(failed("functional_book", "noncanonical empty entity list"));
            }
        }
        if r.remaining() > 0 {
            r.i32("book.opening_date")?;
        }
        r.finish("functional Book parameters")?;
        Ok(Self {
            book,
            base,
            calendar,
            entities,
        })
    }

    fn entity(&self, dimensions: &[(u32, u128)]) -> Result<Option<String>, ReportError> {
        if dimensions
            .iter()
            .any(|(kind, _)| !matches!(kind, 1..=9 | 12))
        {
            return Err(failed(
                "supported_report",
                "unregistered functional leg dimension",
            ));
        }
        if let Some((_, value)) = dimensions.iter().find(|(kind, _)| *kind == 1) {
            return self.entities.get(value).cloned().map(Some).ok_or_else(|| {
                failed("functional_entity", "leg names an undeclared legal entity")
            });
        }
        match self.entities.len() {
            0 => Ok(None),
            1 => Ok(self.entities.values().next().cloned()),
            _ => Err(failed(
                "functional_entity",
                "multi-entity leg lacks its legal entity",
            )),
        }
    }
}

type CellKey = (u128, u32, Option<String>);
fn add_cells(
    cells: &mut BTreeMap<CellKey, VerifiedFunctionalCell>,
    legs: &[Leg],
    entry: &valuation::CheckedEntry,
    base: u32,
) -> Result<(), ReportError> {
    let mut touched = BTreeSet::new();
    for ((leg, amount), entity) in legs.iter().zip(&entry.amounts).zip(&entry.entities) {
        let key = (leg.account, base, entity.clone());
        let cell = cells
            .entry(key.clone())
            .or_insert_with(|| VerifiedFunctionalCell {
                account: leg.account,
                unit_id: base,
                entity: entity.clone(),
                debits: 0,
                credits: 0,
                entry_count: 0,
            });
        if leg.debit {
            cell.debits = add(cell.debits, *amount)?;
        } else {
            cell.credits = add(cell.credits, *amount)?;
        }
        touched.insert(key);
    }
    for key in touched {
        let cell = cells
            .get_mut(&key)
            .ok_or_else(|| failed("functional_arithmetic", "missing functional cell"))?;
        cell.entry_count = cell
            .entry_count
            .checked_add(1)
            .ok_or_else(|| failed("functional_arithmetic", "entry count overflow"))?;
    }
    Ok(())
}
fn option_entity(w: &mut Writer, entity: Option<&str>) {
    w.u8(u8::from(entity.is_some()));
    if let Some(entity) = entity {
        w.bytes(entity.as_bytes());
    }
}
fn option_seq(w: &mut Writer, sequence: Option<u64>) {
    w.u8(u8::from(sequence.is_some()));
    if let Some(sequence) = sequence {
        w.u64(sequence);
    }
}
fn cells_bytes(w: &mut Writer, cells: &[VerifiedFunctionalCell], period: Option<&str>) {
    w.count(cells.len());
    for cell in cells {
        w.u128(cell.account).u32(cell.unit_id);
        if let Some(period) = period {
            w.bytes(period.as_bytes());
        }
        option_entity(w, cell.entity.as_deref());
        w.i128(cell.debits).i128(cell.credits).u64(cell.entry_count);
    }
}
fn contribution(
    mut previous: [u8; 32],
    seq: u64,
    identity: u128,
    base: u32,
    legs: &[Leg],
    entry: &valuation::CheckedEntry,
) -> [u8; 32] {
    for (ordinal, ((leg, amount), entity)) in legs
        .iter()
        .zip(&entry.amounts)
        .zip(&entry.entities)
        .enumerate()
    {
        let mut w = Writer::default();
        w.fixed(&previous)
            .u64(seq)
            .u128(identity)
            .u16(ordinal as u16)
            .u128(leg.account)
            .u32(base);
        option_entity(&mut w, entity.as_deref());
        w.u8(u8::from(!leg.debit)).i128(*amount);
        previous = hash_parts(b"fa:register-functional-leg-contribution:v1", &[&w.buf]);
    }
    previous
}

/// Validate the entire retained valuation prefix before any report selection.
/// An unsupported or forged entry outside a displayed column cannot escape
/// the functional accounting predicate by choosing a narrower report.
#[allow(clippy::too_many_arguments)]
fn sources(
    cert: &Certificate<'_>,
    registry: &registry::FunctionalRegistry,
    book_bytes: &[u8],
    documents: &[([u8; 32], &[u8])],
    schema: &metadata::Schema,
    envelopes: &[LeafEnvelope],
    records: &[(usize, &[u8])],
    legs: &[Vec<Leg>],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
) -> Result<(BookParameters, BTreeMap<usize, valuation::CheckedEntry>), ReportError> {
    if cert.time_selection.is_some() || cert.branch != [0; 16] {
        return Err(failed(
            "supported_report",
            "functional profile requires a sequence-selected trunk",
        ));
    }
    let spec = BookParameters::read(book_bytes, &cert.book)?;
    if !schema.calendar_matches(&spec.calendar)
        || !registry
            .units
            .get(&spec.base)
            .is_some_and(|unit| unit.currency)
    {
        return Err(failed(
            "functional_book",
            "declared calendar disagrees with signed period controls or base is not a registered currency",
        ));
    }
    let checked = valuation::verify_history(
        cert.known_at,
        &spec,
        registry,
        documents,
        schema,
        envelopes,
        records,
        legs,
        infos,
    )?;
    Ok((spec, checked))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn replay_statement(
    cert: &Certificate<'_>,
    selection: &statement::Selection,
    registry: &registry::FunctionalRegistry,
    book_bytes: &[u8],
    documents: &[([u8; 32], &[u8])],
    schema: &metadata::Schema,
    envelopes: &[LeafEnvelope],
    records: &[(usize, &[u8])],
    legs: &[Vec<Leg>],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    resolved: &BTreeSet<usize>,
) -> Result<(VerifiedFunctionalStatement, Vec<u8>), ReportError> {
    let (spec, checked) = sources(
        cert, registry, book_bytes, documents, schema, envelopes, records, legs, infos,
    )?;
    // Preserve the authenticated entry selection and lineage while supplying
    // the statement fold only the independently reproduced functional amounts.
    // The original native legs remain intact for all source validation.
    let mut valued_legs = vec![Vec::new(); legs.len()];
    for (index, entry) in checked {
        valued_legs[index] = legs[index]
            .iter()
            .zip(entry.amounts)
            .map(|(leg, amount)| Leg {
                debit: leg.debit,
                account: leg.account,
                unit: spec.base,
                mantissa: amount,
            })
            .collect();
    }
    let (statement, inner) = statement::replay(
        selection,
        &cert.book,
        &cert.branch,
        cert.known_at,
        &[spec.base],
        schema,
        envelopes,
        infos,
        &valued_legs,
        &BTreeSet::new(),
        resolved,
    )?;
    let mut output = Writer::default();
    output
        .fixed(STATEMENT_OUTPUT_FORMAT)
        .bytes(b"retained-base-amounts")
        .bytes(&inner);
    if output.buf.len() > super::MAX_REPORT_BUNDLE_BYTES {
        return Err(failed(
            "bounded_input",
            "reconstructed functional statement exceeds 64 MiB",
        ));
    }
    Ok((
        VerifiedFunctionalStatement {
            base_unit: spec.base,
            statement,
            book_parameters_source: BOOK_PARAMETERS_SOURCE,
        },
        output.buf,
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn replay(
    cert: &Certificate<'_>,
    registry: &registry::FunctionalRegistry,
    book_bytes: &[u8],
    documents: &[([u8; 32], &[u8])],
    schema: &metadata::Schema,
    envelopes: &[LeafEnvelope],
    records: &[(usize, &[u8])],
    legs: &[Vec<Leg>],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    releases: &BTreeMap<usize, u64>,
) -> Result<(VerifiedFunctionalTrialBalance, Vec<u8>), ReportError> {
    if matches!(&cert.selection, Selection::Periods(codes) | Selection::Activity(codes) if codes.len() != 1)
    {
        return Err(failed(
            "report_selector",
            "functional trial balances select exactly one period",
        ));
    }
    let (spec, checked) = sources(
        cert, registry, book_bytes, documents, schema, envelopes, records, legs, infos,
    )?;
    let (periods, through, activity) = schema.selection(&cert.selection)?;
    let mut indices: Vec<_> = infos.keys().copied().collect();
    indices.sort_by_key(|index| (envelopes[*index].commit_seq, infos[index].identity));
    let mut identities = BTreeSet::new();
    let mut by_digest = BTreeMap::new();
    for &index in &indices {
        if !identities.insert(infos[&index].identity) {
            return Err(failed(
                "entry_identity",
                "duplicate functional source identity",
            ));
        }
        by_digest.insert(envelopes[index].record_digest, index);
    }
    let mut release_sources = BTreeMap::new();
    for (&index, info) in infos {
        if envelopes[index].class != 3 {
            continue;
        }
        let (_, digest) = info
            .resolution
            .ok_or_else(|| failed("pending_resolution", "resolution lacks a target"))?;
        let target = *by_digest
            .get(&digest)
            .ok_or_else(|| failed("pending_resolution", "resolution target is absent"))?;
        release_sources.insert(target, index);
    }
    let mut cells = BTreeMap::new();
    let mut pending = BTreeMap::new();
    let mut watermark: Option<u64> = None;
    let mut entries = 0u64;
    let mut source = Writer::default();
    let mut posted_chain = [0; 32];
    let mut pending_holds = BTreeMap::new();
    for index in indices {
        if legs[index].is_empty() {
            continue;
        }
        let envelope = &envelopes[index];
        let info = &infos[&index];
        let effective = envelope
            .effective_day
            .ok_or_else(|| failed("report_selector", "functional entry has no date"))?;
        let selected = match through {
            Some(day) => effective <= day,
            None => periods
                .binary_search(&schema.entry_period(info, effective)?)
                .is_ok(),
        };
        if !selected {
            continue;
        }
        let seq = envelope.commit_seq;
        let entry = &checked[&index];
        watermark = Some(watermark.map_or(seq, |at| at.max(seq)));
        source
            .u64(seq)
            .u128(info.identity)
            .fixed(&envelope.record_digest)
            .u64(seq)
            .u8(0);
        if envelope.class == 2 {
            if let Some(&release) = releases.get(&index) {
                let witness = *release_sources
                    .get(&index)
                    .ok_or_else(|| failed("pending_resolution", "missing release source"))?;
                if envelopes[witness].commit_seq != release {
                    return Err(failed(
                        "pending_resolution",
                        "release source sequence disagrees",
                    ));
                }
                source
                    .u8(1)
                    .u64(release)
                    .u128(infos[&witness].identity)
                    .fixed(&envelopes[witness].record_digest);
                watermark = Some(watermark.map_or(release, |at| at.max(release)));
            } else {
                source.u8(0);
                add_cells(&mut pending, &legs[index], entry, spec.base)?;
                pending_holds.insert(
                    (seq, info.identity),
                    contribution([0; 32], seq, info.identity, spec.base, &legs[index], entry),
                );
            }
        } else {
            source.u8(0);
            add_cells(&mut cells, &legs[index], entry, spec.base)?;
            posted_chain = contribution(
                posted_chain,
                seq,
                info.identity,
                spec.base,
                &legs[index],
                entry,
            );
            entries = entries
                .checked_add(1)
                .ok_or_else(|| failed("functional_arithmetic", "posted entry count overflow"))?;
        }
    }
    let cells: Vec<_> = cells.into_values().collect();
    let pending: Vec<_> = pending.into_values().collect();
    let mut fold = Writer::default();
    let fold_digest = if let Some(through) = through {
        fold.bytes(book_bytes)
            .i32(through)
            .u32(spec.base)
            .u64(entries);
        option_seq(&mut fold, watermark);
        fold.fixed(&hash_parts(
            b"fa:register-functional-stock-sources:v1",
            &[&source.buf],
        ));
        cells_bytes(&mut fold, &cells, None);
        cells_bytes(&mut fold, &pending, None);
        hash_parts(b"fa:register-functional-stock:v1", &[&fold.buf])
    } else {
        let period = periods
            .first()
            .ok_or_else(|| failed("report_selector", "functional activity has no period"))?;
        fold.bytes(period.as_bytes()).u32(spec.base);
        option_seq(&mut fold, watermark);
        fold.fixed(&posted_chain).count(pending_holds.len());
        for ((seq, identity), digest) in pending_holds {
            fold.u64(seq).u128(identity).fixed(&digest);
        }
        cells_bytes(&mut fold, &cells, Some(period));
        cells_bytes(&mut fold, &pending, Some(period));
        hash_parts(b"fa:register-functional-fold:v1", &[&fold.buf])
    };
    let mut accounts = BTreeMap::new();
    for cell in cells.iter().chain(&pending) {
        if let std::collections::btree_map::Entry::Vacant(account) = accounts.entry(cell.account) {
            account.insert(open_items::account(cell.account, schema)?);
        }
    }
    let result = VerifiedFunctionalTrialBalance {
        base_unit: spec.base,
        effective_through: through,
        activity,
        periods,
        cells,
        pending,
        watermark,
        entries,
        fold_digest,
        accounts,
        book_parameters_source: BOOK_PARAMETERS_SOURCE,
    };
    let output = output(&result, &cert.selection, cert.known_at)?;
    Ok((result, output))
}

fn selection(w: &mut Writer, selected: &Selection) -> Result<(), ReportError> {
    match selected {
        Selection::Periods(codes) | Selection::Activity(codes) => {
            w.u8(u8::from(matches!(selected, Selection::Activity(_))) * 2)
                .count(codes.len());
            for code in codes {
                w.bytes(code.as_bytes());
            }
        }
        Selection::AsOf(day) => {
            w.u8(1).i32(*day);
        }
        _ => {
            return Err(failed(
                "supported_report",
                "functional output requires a trial-balance selector",
            ));
        }
    }
    Ok(())
}
fn output(
    report: &VerifiedFunctionalTrialBalance,
    selected: &Selection,
    known_at: u64,
) -> Result<Vec<u8>, ReportError> {
    let mut w = Writer::default();
    w.fixed(OUTPUT_FORMAT).bytes(b"retained-base-amounts");
    selection(&mut w, selected)?;
    w.u8(u8::from(report.effective_through.is_some()));
    if let Some(day) = report.effective_through {
        w.i32(day);
    }
    w.u32(report.base_unit).u64(known_at);
    option_seq(&mut w, report.watermark);
    w.u64(report.entries).fixed(&report.fold_digest);
    cells_bytes(&mut w, &report.cells, None);
    cells_bytes(&mut w, &report.pending, None);
    w.count(report.accounts.len());
    for (&identity, account) in &report.accounts {
        w.u128(identity)
            .u128(account.account)
            .bytes(account.code.as_bytes())
            .bytes(account.name.as_bytes())
            .u8(account.account_type)
            .u8(account.normal_balance)
            .u8(u8::from(account.is_leaf));
        match account.unit_policy {
            super::OpenItemUnitPolicy::Single(unit) => {
                w.u8(0).u32(unit);
            }
            super::OpenItemUnitPolicy::AnyCurrency => {
                w.u8(1);
            }
            super::OpenItemUnitPolicy::AnyUnit => {
                w.u8(2);
            }
        }
        w.u8(u8::from(account.limit.is_some()));
        if let Some(limit) = &account.limit {
            for value in [limit.lower, limit.upper] {
                w.u8(u8::from(value.is_some()));
                if let Some(value) = value {
                    w.i128(value);
                }
            }
            w.u8(u8::from(limit.period_scoped));
        }
        w.u64(account.created_at);
    }
    Ok(w.buf)
}

#[cfg(test)]
mod tests;
