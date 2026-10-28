//! Independent aging-to-control comparison over two sources authenticated by
//! the same complete journal prefix. A nonzero difference is verified data.
use super::{
    Certificate as NativeCertificate, MAX_REPORT_BUNDLE_BYTES, ReportError, ReportRow, Selection,
    VerifiedAging, VerifiedAgingAmounts, VerifiedReportAccount, aging, failed, hash_parts,
};
use crate::codec::{Reader, Writer};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const CERTIFICATE_FORMAT: &[u8] = b"fa:aging-reconciliation-certificate:v1";
pub(super) const OUTPUT_FORMAT: &[u8] = b"fa:aging-control-reconciliation:v1";
pub(super) const DIGEST_DOMAIN: &[u8] = b"fa:aging-reconciliation-digest:v1";

pub(super) struct Certificate<'a> {
    pub aging: &'a [u8],
    pub control: &'a [u8],
    pub output: &'a [u8],
    pub digest: [u8; 32],
}

/// Exact native-unit amounts. Positive nets mean debit balances regardless of
/// the account's normal side. Pending amounts never enter the comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAgingReconciliationRow {
    pub unit_id: u32,
    pub posted_debits: i128,
    pub posted_credits: i128,
    pub pending_debits: i128,
    pub pending_credits: i128,
    pub open_debits: i128,
    pub open_credits: i128,
    pub open_item_count: u64,
    pub posted_net: i128,
    pub open_net: i128,
    pub difference: i128,
}

/// A selected-account consistency workpaper. Both complete source outputs are
/// independently replayed; this does not certify an external subledger or the
/// economic truth of the authenticated entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAgingReconciliation {
    pub book_id: [u8; 16],
    pub known_at: u64,
    pub effective_through: i32,
    pub account: VerifiedReportAccount,
    pub aging: VerifiedAging,
    pub control_rows: Vec<ReportRow>,
    pub rows: Vec<VerifiedAgingReconciliationRow>,
    pub aging_certificate_digest: [u8; 32],
    pub control_certificate_digest: [u8; 32],
}

impl VerifiedAgingReconciliation {
    /// A valid empty account reconciles without inventing a unit row.
    pub fn is_reconciled(&self) -> bool {
        self.rows.iter().all(|row| row.difference == 0)
    }
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    bytes.starts_with(&(CERTIFICATE_FORMAT.len() as u32).to_le_bytes())
        && bytes.get(4..4 + CERTIFICATE_FORMAT.len()) == Some(CERTIFICATE_FORMAT)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    decode_format(bytes, CERTIFICATE_FORMAT, DIGEST_DOMAIN)
}

pub(super) fn decode_format<'a>(
    bytes: &'a [u8],
    format: &[u8],
    domain: &[u8],
) -> Result<Certificate<'a>, ReportError> {
    if bytes.len() > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed(
            "bounded_input",
            "reconciliation certificate exceeds 64 MiB",
        ));
    }
    let mut r = Reader::new(bytes);
    if r.bytes(64, "reconciliation.format")? != format {
        return Err(failed(
            "supported_report",
            "unsupported reconciliation certificate format",
        ));
    }
    r.u128("reconciliation.producer")?;
    r.fixed::<32>("reconciliation.capability_commitment")?;
    let aging = r.bytes(MAX_REPORT_BUNDLE_BYTES, "reconciliation.aging")?;
    let control = r.bytes(MAX_REPORT_BUNDLE_BYTES, "reconciliation.control")?;
    let output = r.bytes(MAX_REPORT_BUNDLE_BYTES, "reconciliation.output")?;
    let digest = r.fixed("reconciliation.digest")?;
    r.finish("reconciliation certificate")?;
    let body = &bytes[..bytes.len() - 32];
    let body_len = (body.len() as u32).to_le_bytes();
    if hash_parts(domain, &[&body_len, body]) != digest {
        return Err(failed(
            "certificate_digest",
            "reconciliation certificate bytes differ from their commitment",
        ));
    }
    Ok(Certificate {
        aging,
        control,
        output,
        digest,
    })
}

/// Bind both questions before trusting either source's selector or registry.
/// A single disclosed checkpoint prefix must authenticate both native sources.
pub(super) fn bind(
    aging: &aging::Certificate<'_>,
    source: &NativeCertificate<'_>,
    control: &NativeCertificate<'_>,
) -> Result<u128, ReportError> {
    bind_at(aging.effective_through, source, control)
}

pub(super) fn bind_at(
    effective_through: i32,
    source: &NativeCertificate<'_>,
    control: &NativeCertificate<'_>,
) -> Result<u128, ReportError> {
    let Selection::OpenItems(Some(account)) = &source.selection else {
        return Err(failed(
            "reconciliation_selection",
            "reconciliation requires one explicit aging account",
        ));
    };
    if source.branch != [0; 16]
        || control.branch != [0; 16]
        || source.time_selection.is_some()
        || control.time_selection.is_some()
        || source.dimension.is_some()
        || control.dimension.is_some()
        || source.book != control.book
        || source.known_at != control.known_at
        || source.journal_root != control.journal_root
        || source.leaves != control.leaves
        || control.selection != Selection::AsOf(effective_through)
    {
        return Err(failed(
            "reconciliation_selection",
            "aging and control must name the same book, recorded prefix and inclusive effective cutoff",
        ));
    }
    if source.registry_digest != control.registry_digest {
        return Err(failed(
            "registry_closure",
            "both reconciliation sources must bind the same original registry closure",
        ));
    }
    Ok(*account)
}

fn subtract(left: i128, right: i128) -> Result<i128, ReportError> {
    left.checked_sub(right).ok_or_else(|| {
        failed(
            "exact_arithmetic",
            "reconciliation net or difference overflow",
        )
    })
}

pub(super) fn replay(
    certificate: &Certificate<'_>,
    aging_digest: [u8; 32],
    control_digest: [u8; 32],
    account: VerifiedReportAccount,
    aging: VerifiedAging,
    control_rows: Vec<ReportRow>,
    units: &[u32],
) -> Result<(VerifiedAgingReconciliation, Vec<u8>), ReportError> {
    if !account.is_leaf || aging.account_filter != Some(account.account) {
        return Err(failed(
            "reconciliation_selection",
            "reconciliation requires the authenticated selected posting account",
        ));
    }
    let mut controls = BTreeMap::new();
    for row in control_rows
        .into_iter()
        .filter(|row| row.account == account.account)
    {
        if row.code != account.code
            || row.name != account.name
            || row.account_type != account.account_type
            || [
                row.debits,
                row.credits,
                row.debits_pending,
                row.credits_pending,
            ]
            .iter()
            .any(|amount| *amount < 0)
            || controls.insert(row.unit, row).is_some()
        {
            return Err(failed(
                "reconciliation_sources",
                "invalid or repeated control account row",
            ));
        }
    }
    let mut opens = BTreeMap::new();
    for total in &aging.totals {
        if total.account != account.account
            || total.amounts.debits < 0
            || total.amounts.credits < 0
            || opens.insert(total.unit_id, &total.amounts).is_some()
        {
            return Err(failed(
                "reconciliation_sources",
                "invalid or repeated aging account total",
            ));
        }
    }
    let selected_units: BTreeSet<_> = controls.keys().chain(opens.keys()).copied().collect();
    let mut rows = Vec::with_capacity(selected_units.len());
    for unit_id in selected_units {
        if units.binary_search(&unit_id).is_err() {
            return Err(failed(
                "registry_closure",
                "reconciliation uses an unregistered native unit",
            ));
        }
        let control = controls.get(&unit_id);
        let empty = VerifiedAgingAmounts::default();
        let open = opens.get(&unit_id).copied().unwrap_or(&empty);
        let posted_debits = control.map_or(0, |row| row.debits);
        let posted_credits = control.map_or(0, |row| row.credits);
        let posted_net = subtract(posted_debits, posted_credits)?;
        let open_net = subtract(open.debits, open.credits)?;
        rows.push(VerifiedAgingReconciliationRow {
            unit_id,
            posted_debits,
            posted_credits,
            pending_debits: control.map_or(0, |row| row.debits_pending),
            pending_credits: control.map_or(0, |row| row.credits_pending),
            open_debits: open.debits,
            open_credits: open.credits,
            open_item_count: open.item_count,
            posted_net,
            open_net,
            difference: subtract(posted_net, open_net)?,
        });
    }
    let report = VerifiedAgingReconciliation {
        book_id: aging.book_id,
        known_at: aging.known_at,
        effective_through: aging.effective_through,
        account,
        aging,
        control_rows: controls.into_values().collect(),
        rows,
        aging_certificate_digest: aging_digest,
        control_certificate_digest: control_digest,
    };
    let output = encode(&report);
    if output != certificate.output {
        return Err(failed(
            "report_recomputation",
            "reconciliation account, native-unit nets, pending columns or exact comparison bytes differ from independent replay",
        ));
    }
    Ok((report, output))
}

fn encode(report: &VerifiedAgingReconciliation) -> Vec<u8> {
    let account = &report.account;
    let mut w = Writer::default();
    w.bytes(OUTPUT_FORMAT)
        .fixed(&report.book_id)
        .u64(report.known_at)
        .i32(report.effective_through)
        .u128(account.account)
        .bytes(account.code.as_bytes())
        .bytes(account.name.as_bytes())
        .u8(account.account_type)
        .u8(account.normal_balance)
        .u8(u8::from(account.is_leaf))
        .u64(account.created_at)
        .count(report.rows.len());
    for row in &report.rows {
        w.u32(row.unit_id)
            .i128(row.posted_debits)
            .i128(row.posted_credits)
            .i128(row.pending_debits)
            .i128(row.pending_credits)
            .i128(row.open_debits)
            .i128(row.open_credits)
            .u64(row.open_item_count)
            .i128(row.posted_net)
            .i128(row.open_net)
            .i128(row.difference);
    }
    w.u8(u8::from(report.is_reconciled()));
    w.buf
}
