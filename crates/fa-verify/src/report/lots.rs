//! Independent lot schedules over a complete, authenticated OpenItems source.
//!
//! This profile proves acquisition quantity/cost pairing and the complete
//! settlement/reversal provenance. It does not assert that a disposal followed
//! FIFO, LIFO, SpecificId or weighted-average admission. The recipient supplies
//! the expected base unit: a journal prefix does not authenticate Book genesis.

use super::{
    MAX_REPORT_BUNDLE_BYTES, MAX_ROWS, OpenItemUnitPolicy, ReportError, VerifiedApplication,
    VerifiedOpenItem, VerifiedOpenItems, failed, hash_parts, metadata, registry,
};
use crate::codec::{Reader, Writer};
use crate::envelope::{LeafEnvelope, Leg, proposal_leg_details};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub(super) const CERTIFICATE_FORMAT: &[u8] = b"fa:lots-certificate:v1";
pub(super) const OUTPUT_FORMAT: &[u8] = b"fa:lots:v1";
pub(super) const DIGEST_DOMAIN: &[u8] = b"fa:lots-certificate-digest:v1";

pub(super) struct Certificate<'a> {
    pub source: &'a [u8],
    pub base_unit: u32,
    pub effective_through: Option<i32>,
    pub output: &'a [u8],
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedLotAmount {
    pub unit: u32,
    pub mantissa: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLotRelief {
    pub disposal_entry: u128,
    /// Absent when pooled relief consumes only this layer's remaining cost.
    pub qty_ordinal: Option<u16>,
    pub cost_ordinal: Option<u16>,
    pub quantity: VerifiedLotAmount,
    pub cost: VerifiedLotAmount,
    pub recorded_at: u64,
    pub live: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLot {
    pub entry: u128,
    pub entry_digest: [u8; 32],
    pub qty_ordinal: u16,
    pub cost_ordinal: u16,
    pub account: u128,
    pub debit: bool,
    pub effective_date: i32,
    pub recorded_at: u64,
    pub original_quantity: VerifiedLotAmount,
    pub relieved_quantity: VerifiedLotAmount,
    pub open_quantity: VerifiedLotAmount,
    pub original_cost: VerifiedLotAmount,
    pub relieved_cost: VerifiedLotAmount,
    pub open_cost: VerifiedLotAmount,
    pub relieves: Vec<VerifiedLotRelief>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLots {
    pub book_id: [u8; 16],
    pub known_at: u64,
    pub effective_through: Option<i32>,
    pub account: u128,
    pub account_code: String,
    pub account_name: String,
    /// An explicit recipient-checked premise, not an authenticated genesis fact.
    pub base_unit: u32,
    pub source_certificate_digest: [u8; 32],
    pub lots: Vec<VerifiedLot>,
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    bytes.starts_with(&(CERTIFICATE_FORMAT.len() as u32).to_le_bytes())
        && bytes.get(4..4 + CERTIFICATE_FORMAT.len()) == Some(CERTIFICATE_FORMAT)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    if bytes.len() > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed("bounded_input", "lot certificate exceeds 64 MiB"));
    }
    let mut r = Reader::new(bytes);
    if r.bytes(64, "lots.format")? != CERTIFICATE_FORMAT {
        return Err(failed(
            "supported_report",
            "unsupported lot certificate format",
        ));
    }
    r.u128("lots.producer")?;
    r.fixed::<32>("lots.capability_commitment")?;
    let source = r.bytes(MAX_REPORT_BUNDLE_BYTES, "lots.source")?;
    let base_unit = r.u32("lots.base_unit")?;
    let effective_through = if r.present("lots.effective_through")? {
        Some(r.i32("lots.effective_through")?)
    } else {
        None
    };
    let output = r.bytes(MAX_REPORT_BUNDLE_BYTES, "lots.output")?;
    let digest = r.fixed("lots.digest")?;
    r.finish("lot certificate")?;
    let body = &bytes[..bytes.len() - 32];
    if hash_parts(DIGEST_DOMAIN, &[&(body.len() as u32).to_le_bytes(), body]) != digest {
        return Err(failed(
            "certificate_digest",
            "lot certificate bytes differ from their commitment",
        ));
    }
    Ok(Certificate {
        source,
        base_unit,
        effective_through,
        output,
        digest,
    })
}

/// Check the entire visible account history, before any effective cutoff.
/// Unsupported layers cannot disappear from the asserted schedule simply by
/// being exhausted, reversed, pending or later-effective. Invisible migrations
/// are excluded under the same authenticated activation law as OpenItems.
#[allow(clippy::too_many_arguments)]
pub(super) fn check_history(
    account: u128,
    base_unit: u32,
    units: &registry::LotUnits,
    envelopes: &[LeafEnvelope],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    legs: &[Vec<Leg>],
    records: &[(usize, &[u8])],
    visible_migrations: &BTreeSet<u64>,
) -> Result<BTreeMap<u128, [u8; 32]>, ReportError> {
    if !units.currencies.contains(&base_unit) {
        return Err(failed(
            "lots_profile",
            "lot cost base must be a registered currency",
        ));
    }
    let mut digests = BTreeMap::new();
    for (&index, info) in infos {
        if envelopes[index].class == 12 && !visible_migrations.contains(&(index as u64)) {
            continue;
        }
        let selected: Vec<_> = legs[index]
            .iter()
            .enumerate()
            .filter(|(_, leg)| leg.account == account)
            .collect();
        if selected.is_empty() {
            continue;
        }
        let (length, bytes) = records[index];
        let details = proposal_leg_details(&bytes[..length])?;
        let mut acquisitions = 0usize;
        let mut applications = 0usize;
        let mut quantities = 0usize;
        let mut costs = 0usize;
        for (ordinal, leg) in &selected {
            let detail = &details[*ordinal];
            if !detail.dimensions.is_empty() || detail.base_amount.is_some() {
                return Err(failed(
                    "lots_profile",
                    "lot schedules require dimensionless native-cost account history",
                ));
            }
            if leg.unit != base_unit && !units.quantities.contains(&leg.unit) {
                return Err(failed(
                    "lots_profile",
                    "lot quantities must be registered balanced noncurrency units",
                ));
            }
            if envelopes[index].class == 4 {
                // The complete OpenItems source checks exact reversal shape
                // and target lineage; restoration never reprices old relief.
                continue;
            }
            if leg.debit && detail.settlements.is_empty() {
                acquisitions += 1;
                if leg.unit == base_unit {
                    costs += 1;
                    if leg.mantissa < 0 {
                        return Err(failed(
                            "lots_profile",
                            "acquisition cost cannot be negative",
                        ));
                    }
                } else {
                    quantities += 1;
                    if leg.mantissa <= 0 {
                        return Err(failed(
                            "lots_profile",
                            "acquisition quantity must be positive",
                        ));
                    }
                }
            } else if !leg.debit && !detail.settlements.is_empty() && leg.mantissa > 0 {
                applications += 1;
                let amount = detail
                    .settlements
                    .iter()
                    .try_fold(0i128, |total, application| {
                        total.checked_add(application.amount).ok_or_else(|| {
                            failed("exact_arithmetic", "lot outgoing application sum overflow")
                        })
                    })?;
                if amount != leg.mantissa {
                    return Err(failed(
                        "lots_profile",
                        "a lot disposal credit must be completely applied to acquisition legs",
                    ));
                }
            } else {
                return Err(failed(
                    "lots_profile",
                    "unpaired credits and debit applications are outside the certified lot profile",
                ));
            }
        }
        if envelopes[index].class != 4
            && !((acquisitions == 2 && quantities == 1 && costs == 1 && applications == 0)
                || (acquisitions == 0 && applications == selected.len()))
        {
            return Err(failed(
                "lots_profile",
                "each acquisition must have exactly one quantity debit and one base-cost debit; applying entries cannot also acquire lots",
            ));
        }
        if digests
            .insert(info.identity, envelopes[index].record_digest)
            .is_some()
        {
            return Err(failed("entry_identity", "duplicate lot entry identity"));
        }
    }
    Ok(digests)
}

fn amount(unit: u32, mantissa: i128) -> VerifiedLotAmount {
    VerifiedLotAmount { unit, mantissa }
}

fn validate_item(item: &VerifiedOpenItem) -> Result<(), ReportError> {
    if item.original < 0
        || item.applied < 0
        || item.applied_out < 0
        || item.open < 0
        || item
            .original
            .checked_sub(item.applied_out)
            .and_then(|value| value.checked_sub(item.applied))
            != Some(item.open)
    {
        return Err(failed(
            "lots_capacity",
            "lot source amounts do not conserve their capacity",
        ));
    }
    Ok(())
}

fn bounded(sum: usize, count: usize, size: usize) -> Result<usize, ReportError> {
    count
        .checked_mul(size)
        .and_then(|bytes| sum.checked_add(bytes))
        .filter(|bytes| *bytes <= MAX_REPORT_BUNDLE_BYTES)
        .ok_or_else(|| failed("bounded_input", "complete lot output exceeds 64 MiB"))
}

/// Pair independently reconstructed acquiring legs and preserve every relief.
/// Work is linear in source items and applications apart from ordered maps and
/// canonical sorting; matching repeated applications never removes Vec fronts.
pub(super) fn replay(
    certificate: &Certificate<'_>,
    book_id: [u8; 16],
    known_at: u64,
    source_certificate_digest: [u8; 32],
    snapshot: VerifiedOpenItems,
    digests: &BTreeMap<u128, [u8; 32]>,
) -> Result<(VerifiedLots, Vec<u8>), ReportError> {
    let account = snapshot.account_filter.ok_or_else(|| {
        failed(
            "lots_profile",
            "a certified lot schedule requires one selected account",
        )
    })?;
    let row = snapshot.accounts.get(&account).ok_or_else(|| {
        failed(
            "account_metadata",
            "lot account lacks an authenticated declaration",
        )
    })?;
    if snapshot.accounts.len() != 1
        || !row.is_leaf
        || row.account_type != 1
        || row.normal_balance != 0
        || row.unit_policy != OpenItemUnitPolicy::AnyUnit
    {
        return Err(failed(
            "lots_profile",
            "lot account must be a debit-normal AnyUnit Asset posting leaf",
        ));
    }
    if snapshot.items.len() > MAX_ROWS {
        return Err(failed("bounded_input", "lot source exceeds the item bound"));
    }
    let mut by_entry: BTreeMap<u128, Vec<&VerifiedOpenItem>> = BTreeMap::new();
    let mut application_count = 0usize;
    for item in &snapshot.items {
        validate_item(item)?;
        if item.account != account {
            return Err(failed(
                "lots_profile",
                "lot source contains another account",
            ));
        }
        application_count = application_count
            .checked_add(item.applications.len())
            .filter(|count| *count <= MAX_ROWS)
            .ok_or_else(|| failed("bounded_input", "lot source exceeds the application bound"))?;
        if item.applied_out == 0 {
            by_entry.entry(item.entry).or_default().push(item);
        } else if item.debit
            || item.applied_out != item.original
            || item.open != 0
            || item.applied != 0
        {
            return Err(failed(
                "lots_profile",
                "partly applying or debit source legs cannot be omitted from lots",
            ));
        }
    }
    let header = bounded(
        71 + usize::from(certificate.effective_through.is_some()) * 4,
        row.code
            .len()
            .checked_add(row.name.len())
            .ok_or_else(|| failed("bounded_input", "lot metadata length overflow"))?,
        1,
    )?;
    let mut output_size = bounded(header, by_entry.len(), 205)?;
    let mut lots = Vec::with_capacity(by_entry.len());
    for (entry, items) in by_entry {
        if items.len() != 2 || items.iter().any(|item| !item.debit) {
            return Err(failed(
                "lots_profile",
                "an acquisition is not exactly one debit quantity/cost pair",
            ));
        }
        let quantity = items
            .iter()
            .find(|item| item.unit_id != certificate.base_unit)
            .copied();
        let cost = items
            .iter()
            .find(|item| item.unit_id == certificate.base_unit)
            .copied();
        let (Some(quantity), Some(cost)) = (quantity, cost) else {
            return Err(failed(
                "lots_profile",
                "an acquisition omits its quantity or base-cost leg",
            ));
        };
        if quantity.original <= 0
            || quantity.effective_date != cost.effective_date
            || quantity.recorded_at != cost.recorded_at
        {
            return Err(failed(
                "lots_profile",
                "quantity/cost acquisition coordinates disagree",
            ));
        }
        let entry_digest = *digests.get(&entry).ok_or_else(|| {
            failed(
                "entry_identity",
                "lot acquisition has no authenticated record digest",
            )
        })?;
        let mut cost_applications: BTreeMap<(u128, u64, bool), VecDeque<&VerifiedApplication>> =
            BTreeMap::new();
        for application in &cost.applications {
            cost_applications
                .entry((application.entry, application.recorded_at, application.live))
                .or_default()
                .push_back(application);
        }
        let mut relieves =
            Vec::with_capacity(quantity.applications.len() + cost.applications.len());
        for application in &quantity.applications {
            let matched = cost_applications
                .get_mut(&(application.entry, application.recorded_at, application.live))
                .and_then(VecDeque::pop_front);
            relieves.push(VerifiedLotRelief {
                disposal_entry: application.entry,
                qty_ordinal: Some(application.ordinal),
                cost_ordinal: matched.map(|value| value.ordinal),
                quantity: amount(quantity.unit_id, application.amount),
                cost: amount(
                    certificate.base_unit,
                    matched.map_or(0, |value| value.amount),
                ),
                recorded_at: application.recorded_at,
                live: application.live,
            });
        }
        for ((disposal_entry, recorded_at, live), applications) in cost_applications {
            for application in applications {
                relieves.push(VerifiedLotRelief {
                    disposal_entry,
                    qty_ordinal: None,
                    cost_ordinal: Some(application.ordinal),
                    quantity: amount(quantity.unit_id, 0),
                    cost: amount(certificate.base_unit, application.amount),
                    recorded_at,
                    live,
                });
            }
        }
        relieves.sort_by_key(|relief| {
            (
                relief.recorded_at,
                relief.disposal_entry,
                relief.qty_ordinal,
                relief.cost_ordinal,
            )
        });
        for relief in &relieves {
            output_size = bounded(
                output_size,
                1,
                67 + usize::from(relief.qty_ordinal.is_some()) * 2
                    + usize::from(relief.cost_ordinal.is_some()) * 2,
            )?;
        }
        lots.push(VerifiedLot {
            entry,
            entry_digest,
            qty_ordinal: quantity.ordinal,
            cost_ordinal: cost.ordinal,
            account,
            debit: true,
            effective_date: quantity.effective_date,
            recorded_at: quantity.recorded_at,
            original_quantity: amount(quantity.unit_id, quantity.original),
            relieved_quantity: amount(quantity.unit_id, quantity.applied),
            open_quantity: amount(quantity.unit_id, quantity.open),
            original_cost: amount(certificate.base_unit, cost.original),
            relieved_cost: amount(certificate.base_unit, cost.applied),
            open_cost: amount(certificate.base_unit, cost.open),
            relieves,
        });
    }
    lots.sort_by_key(|lot| {
        (
            lot.effective_date,
            lot.recorded_at,
            lot.entry,
            lot.qty_ordinal,
        )
    });
    let report = VerifiedLots {
        book_id,
        known_at,
        effective_through: certificate.effective_through,
        account,
        account_code: row.code.clone(),
        account_name: row.name.clone(),
        base_unit: certificate.base_unit,
        source_certificate_digest,
        lots,
    };
    let output = encode(&report);
    if output.len() > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed(
            "bounded_input",
            "complete lot output exceeds 64 MiB",
        ));
    }
    if output != certificate.output {
        return Err(failed(
            "lots_recomputation",
            "lot quantities, costs, acquisition identities or complete relief histories differ from independent replay",
        ));
    }
    Ok((report, output))
}

fn write_amount(w: &mut Writer, amount: VerifiedLotAmount) {
    w.u32(amount.unit).i128(amount.mantissa);
}

fn write_ordinal(w: &mut Writer, ordinal: Option<u16>) {
    w.u8(u8::from(ordinal.is_some()));
    if let Some(ordinal) = ordinal {
        w.u16(ordinal);
    }
}

fn encode(report: &VerifiedLots) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(OUTPUT_FORMAT)
        .fixed(&report.book_id)
        .u64(report.known_at)
        .u8(u8::from(report.effective_through.is_some()));
    if let Some(cutoff) = report.effective_through {
        w.i32(cutoff);
    }
    w.u128(report.account)
        .bytes(report.account_code.as_bytes())
        .bytes(report.account_name.as_bytes())
        .u32(report.base_unit)
        .count(report.lots.len());
    for lot in &report.lots {
        w.u128(lot.entry)
            .fixed(&lot.entry_digest)
            .u16(lot.qty_ordinal)
            .u16(lot.cost_ordinal)
            .u128(lot.account)
            .u8(u8::from(!lot.debit))
            .i32(lot.effective_date)
            .u64(lot.recorded_at);
        for value in [
            lot.original_quantity,
            lot.relieved_quantity,
            lot.open_quantity,
            lot.original_cost,
            lot.relieved_cost,
            lot.open_cost,
        ] {
            write_amount(&mut w, value);
        }
        w.count(lot.relieves.len());
        for relief in &lot.relieves {
            w.u128(relief.disposal_entry);
            write_ordinal(&mut w, relief.qty_ordinal);
            write_ordinal(&mut w, relief.cost_ordinal);
            write_amount(&mut w, relief.quantity);
            write_amount(&mut w, relief.cost);
            w.u64(relief.recorded_at).u8(u8::from(relief.live));
        }
    }
    w.buf
}
