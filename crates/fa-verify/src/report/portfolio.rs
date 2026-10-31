//! Whole-chart aging/control coverage reconstructed from two authenticated
//! native sources. Selection never hides zero accounts or source defects, and
//! a net zero across accounts or units never establishes reconciliation.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    Certificate as NativeCertificate, MAX_REPORT_BUNDLE_BYTES, ReportError, ReportRow, Selection,
    VerifiedAging, VerifiedAgingAmounts, VerifiedAgingReconciliationRow, VerifiedReportAccount,
    aging, failed, hash_parts, metadata, open_items,
};
use crate::codec::{Reader, Writer};

const FORMAT: &[u8] = b"fa:aging-portfolio-certificate:v1";
const OUTPUT_FORMAT: &[u8] = b"fa:aging-portfolio:v1";
const DIGEST_DOMAIN: &[u8] = b"fa:aging-portfolio-digest:v1";
const MAX_ACCOUNTS: usize = 4096;
const MAX_DETAIL_ROWS: usize = 100_000;

/// The exact accounting question, distinct from disclosure authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgingPortfolioScope {
    AllPosting,
    /// Strict identity order; an empty subset remains distinct from AllPosting.
    Selected(Vec<u128>),
}

/// A recipient-owned portfolio question. Supply this independently of the
/// certificate, with a fixed recorded prefix and strictly increasing bucket
/// bounds. Selected account identities must be sorted and distinct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgingPortfolioRequest {
    pub scope: AgingPortfolioScope,
    pub known_at: u64,
    pub effective_through: i32,
    pub upper_bounds: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAgingPortfolioAccount {
    pub account: VerifiedReportAccount,
    pub rows: Vec<VerifiedAgingReconciliationRow>,
}

/// Every selected posting account and every omitted posting account at the
/// historical prefix, including zero-activity leaves. This is an internal
/// accounting comparison, not an attestation by an external subledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAgingPortfolio {
    pub book_id: [u8; 16],
    pub scope: AgingPortfolioScope,
    pub known_at: u64,
    pub effective_through: i32,
    pub upper_bounds: Vec<u32>,
    /// Account-code order, including selected leaves with no native-unit row.
    pub accounts: Vec<VerifiedAgingPortfolioAccount>,
    pub uncovered_accounts: Vec<VerifiedReportAccount>,
    pub aging_certificate_digest: [u8; 32],
    pub control_certificate_digest: [u8; 32],
}

impl VerifiedAgingPortfolio {
    pub fn is_complete(&self) -> bool {
        self.uncovered_accounts.is_empty()
    }
    pub fn is_reconciled(&self) -> bool {
        self.accounts
            .iter()
            .flat_map(|account| &account.rows)
            .all(|row| row.difference == 0)
    }
    pub fn is_complete_and_reconciled(&self) -> bool {
        self.is_complete() && self.is_reconciled()
    }
    pub fn has_pending_reservations(&self) -> bool {
        self.accounts
            .iter()
            .flat_map(|account| &account.rows)
            .any(|row| row.pending_debits != 0 || row.pending_credits != 0)
    }
}

pub(super) fn expect(
    report: &VerifiedAgingPortfolio,
    expected: &AgingPortfolioRequest,
) -> Result<(), ReportError> {
    if let AgingPortfolioScope::Selected(accounts) = &expected.scope
        && (accounts.len() > MAX_ACCOUNTS || !accounts.windows(2).all(|pair| pair[0] < pair[1]))
    {
        return Err(failed(
            "portfolio_request",
            "recipient account identities must be distinct, strictly ordered and bounded to 4096",
        ));
    }
    if expected.upper_bounds.len() > 128
        || !expected
            .upper_bounds
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || report.scope != expected.scope
        || report.known_at != expected.known_at
        || report.effective_through != expected.effective_through
        || report.upper_bounds != expected.upper_bounds
    {
        return Err(failed(
            "portfolio_request",
            "verified portfolio does not answer the recipient's exact scope, recorded prefix, cutoff and bucket question",
        ));
    }
    Ok(())
}

pub(super) struct Certificate<'a> {
    pub scope: AgingPortfolioScope,
    pub aging: &'a [u8],
    pub control: &'a [u8],
    pub output: &'a [u8],
    pub digest: [u8; 32],
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    Reader::new(bytes)
        .bytes(64, "portfolio.format")
        .is_ok_and(|format| format == FORMAT)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    if bytes.len() > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed("bounded_input", "portfolio exceeds 64 MiB"));
    }
    let mut r = Reader::new(bytes);
    if r.bytes(64, "portfolio.format")? != FORMAT {
        return Err(failed("supported_report", "unsupported aging portfolio"));
    }
    r.u128("portfolio.producer")?;
    r.fixed::<32>("portfolio.capability")?;
    let scope = match r.u8("portfolio.scope")? {
        0 => AgingPortfolioScope::AllPosting,
        1 => {
            let count = r.count(MAX_ACCOUNTS, 16, "portfolio.accounts")?;
            let mut accounts = Vec::with_capacity(count);
            for _ in 0..count {
                accounts.push(r.u128("portfolio.account")?);
            }
            if !accounts.windows(2).all(|pair| pair[0] < pair[1]) {
                return Err(failed(
                    "portfolio_selection",
                    "selected account identities must be distinct and strictly ordered",
                ));
            }
            AgingPortfolioScope::Selected(accounts)
        }
        _ => return Err(failed("portfolio_selection", "unknown portfolio scope")),
    };
    let aging = r.bytes(MAX_REPORT_BUNDLE_BYTES, "portfolio.aging")?;
    let control = r.bytes(MAX_REPORT_BUNDLE_BYTES, "portfolio.control")?;
    let output = r.bytes(MAX_REPORT_BUNDLE_BYTES, "portfolio.output")?;
    let digest = r.fixed("portfolio.digest")?;
    r.finish("portfolio certificate")?;
    let body = &bytes[..bytes.len() - 32];
    if hash_parts(DIGEST_DOMAIN, &[&(body.len() as u32).to_le_bytes(), body]) != digest {
        return Err(failed(
            "certificate_digest",
            "portfolio commitment differs from its exact canonical body",
        ));
    }
    Ok(Certificate {
        scope,
        aging,
        control,
        output,
        digest,
    })
}

pub(super) fn bind(
    aging: &aging::Certificate<'_>,
    source: &NativeCertificate<'_>,
    control: &NativeCertificate<'_>,
) -> Result<(), ReportError> {
    if source.selection != Selection::OpenItems(None)
        || control.selection != Selection::AsOf(aging.effective_through)
        || source.book != control.book
        || source.branch != [0; 16]
        || control.branch != [0; 16]
        || source.known_at != control.known_at
        || source.journal_root != control.journal_root
        || source.leaves != control.leaves
        || source.time_selection.is_some()
        || control.time_selection.is_some()
        || source.dimension.is_some()
        || control.dimension.is_some()
        || source.functional
        || control.functional
    {
        return Err(failed(
            "portfolio_selection",
            "portfolio requires whole-book native aging and stock at the same trunk prefix and cutoff",
        ));
    }
    if source.registry_digest != control.registry_digest {
        return Err(failed(
            "registry_closure",
            "both portfolio sources must bind one original registry closure",
        ));
    }
    Ok(())
}

fn subtract(left: i128, right: i128) -> Result<i128, ReportError> {
    left.checked_sub(right)
        .ok_or_else(|| failed("exact_arithmetic", "portfolio net or difference overflow"))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn replay(
    certificate: &Certificate<'_>,
    aging_certificate: &aging::Certificate<'_>,
    control_digest: [u8; 32],
    schema: &metadata::Schema,
    aging: VerifiedAging,
    control_rows: Vec<ReportRow>,
    units: &[u32],
) -> Result<(VerifiedAgingPortfolio, Vec<u8>), ReportError> {
    if schema.accounts.len() > MAX_ACCOUNTS {
        return Err(failed(
            "bounded_input",
            "portfolio historical chart exceeds 4096 accounts",
        ));
    }
    let row_count = [
        aging.items.len(),
        aging.cells.len(),
        aging.totals.len(),
        control_rows.len(),
    ]
    .into_iter()
    .chain(aging.items.iter().map(|item| item.item.applications.len()))
    .try_fold(0usize, |sum, n| sum.checked_add(n));
    if row_count.is_none_or(|n| n > MAX_DETAIL_ROWS) {
        return Err(failed(
            "bounded_input",
            "complete portfolio source exceeds 100000 detail rows",
        ));
    }
    let selected: BTreeSet<u128> = match &certificate.scope {
        AgingPortfolioScope::AllPosting => schema
            .accounts
            .iter()
            .filter(|(_, account)| account.is_leaf)
            .map(|(id, _)| *id)
            .collect(),
        AgingPortfolioScope::Selected(accounts) => {
            for id in accounts {
                if !schema.accounts.get(id).is_some_and(|a| a.is_leaf) {
                    return Err(failed(
                        "portfolio_selection",
                        "portfolio selects an absent or summary account",
                    ));
                }
            }
            accounts.iter().copied().collect()
        }
    };
    // Partition complete source rows once. Even unselected rows must refer to
    // real posting accounts and registered units; selection is not validation.
    let leaf = |id: u128, unit: u32| -> Result<(), ReportError> {
        if !schema.accounts.get(&id).is_some_and(|a| a.is_leaf)
            || units.binary_search(&unit).is_err()
        {
            return Err(failed(
                "portfolio_sources",
                "a source row uses an absent/summary account or unregistered unit",
            ));
        }
        Ok(())
    };
    let mut controls: BTreeMap<u128, BTreeMap<u32, ReportRow>> = BTreeMap::new();
    for row in control_rows {
        leaf(row.account, row.unit)?;
        if controls
            .entry(row.account)
            .or_default()
            .insert(row.unit, row)
            .is_some()
        {
            return Err(failed("portfolio_sources", "repeated control cell"));
        }
    }
    let mut opens: BTreeMap<u128, BTreeMap<u32, VerifiedAgingAmounts>> = BTreeMap::new();
    for total in aging.totals {
        leaf(total.account, total.unit_id)?;
        if opens
            .entry(total.account)
            .or_default()
            .insert(total.unit_id, total.amounts)
            .is_some()
        {
            return Err(failed("portfolio_sources", "repeated aging total"));
        }
    }
    for cell in &aging.cells {
        leaf(cell.account, cell.unit_id)?;
    }
    for item in &aging.items {
        leaf(item.item.account, item.item.unit_id)?;
    }
    let mut accounts = Vec::with_capacity(selected.len());
    let mut uncovered_accounts = Vec::new();
    for (&id, declared) in &schema.accounts {
        if !declared.is_leaf {
            continue;
        }
        let account = open_items::account(id, schema)?;
        if !selected.contains(&id) {
            uncovered_accounts.push(account);
            continue;
        }
        let controls = controls.remove(&id).unwrap_or_default();
        let opens = opens.remove(&id).unwrap_or_default();
        let units: BTreeSet<_> = controls.keys().chain(opens.keys()).copied().collect();
        let mut rows = Vec::with_capacity(units.len());
        for unit_id in units {
            let control = controls.get(&unit_id);
            let empty = VerifiedAgingAmounts::default();
            let open = opens.get(&unit_id).unwrap_or(&empty);
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
        accounts.push(VerifiedAgingPortfolioAccount { account, rows });
    }
    accounts.sort_by(|a, b| a.account.code.cmp(&b.account.code));
    uncovered_accounts.sort_by(|a, b| a.code.cmp(&b.code));
    let report = VerifiedAgingPortfolio {
        book_id: aging.book_id,
        scope: certificate.scope.clone(),
        known_at: aging.known_at,
        effective_through: aging.effective_through,
        upper_bounds: aging_certificate.upper_bounds.clone(),
        accounts,
        uncovered_accounts,
        aging_certificate_digest: aging_certificate.digest,
        control_certificate_digest: control_digest,
    };
    let output = encode(&report);
    if output != certificate.output {
        return Err(failed(
            "report_recomputation",
            "portfolio selection, chart coverage, metadata, native-unit comparisons or verdicts differ from independent replay",
        ));
    }
    Ok((report, output))
}

fn write_account(w: &mut Writer, account: &VerifiedReportAccount) {
    w.u128(account.account)
        .bytes(account.code.as_bytes())
        .bytes(account.name.as_bytes())
        .u8(account.account_type)
        .u8(account.normal_balance)
        .u8(u8::from(account.is_leaf))
        .u64(account.created_at);
}

fn encode(report: &VerifiedAgingPortfolio) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(OUTPUT_FORMAT).fixed(&report.book_id);
    match &report.scope {
        AgingPortfolioScope::AllPosting => {
            w.u8(0);
        }
        AgingPortfolioScope::Selected(accounts) => {
            w.u8(1).count(accounts.len());
            for account in accounts {
                w.u128(*account);
            }
        }
    }
    w.u64(report.known_at)
        .i32(report.effective_through)
        .count(report.upper_bounds.len());
    for bound in &report.upper_bounds {
        w.u32(*bound);
    }
    w.count(report.accounts.len());
    for account in &report.accounts {
        write_account(&mut w, &account.account);
        w.count(account.rows.len());
        for row in &account.rows {
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
    }
    w.count(report.uncovered_accounts.len());
    for account in &report.uncovered_accounts {
        write_account(&mut w, account);
    }
    w.u8(u8::from(report.is_complete()))
        .u8(u8::from(report.is_reconciled()))
        .u8(u8::from(report.is_complete_and_reconciled()))
        .u8(u8::from(report.has_pending_reservations()));
    w.buf
}
