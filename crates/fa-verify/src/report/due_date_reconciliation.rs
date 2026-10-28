//! Contractual due-date aging reconciled to the independently replayed native
//! stock fold. Unscheduled items remain in the comparison; installment parts
//! never inflate the number of distinct original open items.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    Certificate as NativeCertificate, ReportError, ReportRow, VerifiedAgingAmounts,
    VerifiedAgingReconciliationRow, VerifiedDueDateAging, VerifiedReportAccount, due_date, failed,
    reconciliation,
};
use crate::codec::Writer;

pub(super) const CERTIFICATE_FORMAT: &[u8] = b"fa:due-date-aging-reconciliation-certificate:v1";
const OUTPUT_FORMAT: &[u8] = b"fa:due-date-aging-control-reconciliation:v1";
const DIGEST_DOMAIN: &[u8] = b"fa:due-date-aging-reconciliation-digest:v1";

pub(super) use reconciliation::Certificate;

/// Both source folds and an exact selected-account consistency comparison.
/// Scheduled and unscheduled balances together cover all open items. This
/// verifies the authenticated journal, not external subledger completeness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDueDateAgingReconciliation {
    pub book_id: [u8; 16],
    pub known_at: u64,
    pub effective_through: i32,
    pub account: VerifiedReportAccount,
    pub aging: VerifiedDueDateAging,
    pub control_rows: Vec<ReportRow>,
    pub rows: Vec<VerifiedAgingReconciliationRow>,
    pub aging_certificate_digest: [u8; 32],
    pub control_certificate_digest: [u8; 32],
}

impl VerifiedDueDateAgingReconciliation {
    pub fn is_reconciled(&self) -> bool {
        self.rows.iter().all(|row| row.difference == 0)
    }
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    bytes.starts_with(&(CERTIFICATE_FORMAT.len() as u32).to_le_bytes())
        && bytes.get(4..4 + CERTIFICATE_FORMAT.len()) == Some(CERTIFICATE_FORMAT)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    reconciliation::decode_format(bytes, CERTIFICATE_FORMAT, DIGEST_DOMAIN)
}

pub(super) fn bind(
    aging: &due_date::Certificate<'_>,
    source: &NativeCertificate<'_>,
    control: &NativeCertificate<'_>,
) -> Result<u128, ReportError> {
    if source.functional || control.functional {
        return Err(failed(
            "reconciliation_selection",
            "due-date reconciliation requires native-unit source reports",
        ));
    }
    reconciliation::bind_at(aging.effective_through, source, control)
}

fn add(left: i128, right: i128) -> Result<i128, ReportError> {
    left.checked_add(right).ok_or_else(|| {
        failed(
            "exact_arithmetic",
            "due-date reconciliation open total overflow",
        )
    })
}

fn subtract(left: i128, right: i128) -> Result<i128, ReportError> {
    left.checked_sub(right).ok_or_else(|| {
        failed(
            "exact_arithmetic",
            "due-date reconciliation net or difference overflow",
        )
    })
}

pub(super) fn replay(
    certificate: &Certificate<'_>,
    aging_digest: [u8; 32],
    control_digest: [u8; 32],
    account: VerifiedReportAccount,
    aging: VerifiedDueDateAging,
    control_rows: Vec<ReportRow>,
    units: &[u32],
) -> Result<(VerifiedDueDateAgingReconciliation, Vec<u8>), ReportError> {
    if !account.is_leaf || aging.account_filter != Some(account.account) {
        return Err(failed(
            "reconciliation_selection",
            "due-date reconciliation requires the authenticated selected posting account",
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
                "invalid or repeated due-date reconciliation control row",
            ));
        }
    }
    let mut opens: BTreeMap<u32, VerifiedAgingAmounts> = BTreeMap::new();
    for totals in [&aging.totals, &aging.unscheduled_totals] {
        let mut seen = BTreeSet::new();
        for total in totals {
            if total.account != account.account
                || total.amounts.debits < 0
                || total.amounts.credits < 0
                || !seen.insert(total.unit_id)
            {
                return Err(failed(
                    "reconciliation_sources",
                    "invalid or repeated due-date aging account total",
                ));
            }
            let open = opens.entry(total.unit_id).or_default();
            open.debits = add(open.debits, total.amounts.debits)?;
            open.credits = add(open.credits, total.amounts.credits)?;
        }
    }
    let mut identities: BTreeMap<u32, BTreeSet<(u128, u16)>> = BTreeMap::new();
    for item in aging
        .items
        .iter()
        .map(|part| &part.item)
        .chain(aging.unscheduled.iter().map(|row| &row.item))
    {
        if item.account != account.account || !opens.contains_key(&item.unit_id) {
            return Err(failed(
                "reconciliation_sources",
                "due-date open item lacks its selected-account total",
            ));
        }
        identities
            .entry(item.unit_id)
            .or_default()
            .insert((item.entry, item.ordinal));
    }
    let selected_units: BTreeSet<_> = controls.keys().chain(opens.keys()).copied().collect();
    let mut rows = Vec::with_capacity(selected_units.len());
    for unit_id in selected_units {
        if units.binary_search(&unit_id).is_err() {
            return Err(failed(
                "registry_closure",
                "due-date reconciliation uses an unregistered native unit",
            ));
        }
        let control = controls.get(&unit_id);
        let empty = VerifiedAgingAmounts::default();
        let open = opens.get(&unit_id).unwrap_or(&empty);
        let posted_debits = control.map_or(0, |row| row.debits);
        let posted_credits = control.map_or(0, |row| row.credits);
        let posted_net = subtract(posted_debits, posted_credits)?;
        let open_net = subtract(open.debits, open.credits)?;
        let open_item_count = u64::try_from(identities.get(&unit_id).map_or(0, BTreeSet::len))
            .map_err(|_| failed("exact_arithmetic", "due-date open-item count overflow"))?;
        rows.push(VerifiedAgingReconciliationRow {
            unit_id,
            posted_debits,
            posted_credits,
            pending_debits: control.map_or(0, |row| row.debits_pending),
            pending_credits: control.map_or(0, |row| row.credits_pending),
            open_debits: open.debits,
            open_credits: open.credits,
            open_item_count,
            posted_net,
            open_net,
            difference: subtract(posted_net, open_net)?,
        });
    }
    let report = VerifiedDueDateAgingReconciliation {
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
            "due-date reconciliation totals, distinct open-item counts or exact comparison bytes differ from independent replay",
        ));
    }
    Ok((report, output))
}

fn encode(report: &VerifiedDueDateAgingReconciliation) -> Vec<u8> {
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
