//! Summary trial balances derived from the complete authenticated native fold.
//!
//! Roots select a presentation, not a smaller disclosure or authorization
//! scope. Every historical posting leaf is retained as a group member or an
//! explicit uncovered leaf, including accounts with no source balance row.
//! A promoted account's old balance belongs to its selected ancestor, without
//! turning the promoted account back into a posting leaf.

use super::{
    MAX_REPORT_BUNDLE_BYTES, OpenItemUnitPolicy, ReportError, ReportRow, VerifiedReportAccount,
    failed, hash_parts, metadata, open_items,
};
use crate::codec::{Reader, Writer};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const CERTIFICATE_FORMAT: &[u8] = b"fa:summary-certificate:v1";
pub(super) const OUTPUT_FORMAT: &[u8] = b"fa:summary-trial-balance:v1";
const DIGEST_DOMAIN: &[u8] = b"fa:summary-certificate-digest:v1";
const MAX_ROOTS: usize = 65_536;

/// The outer certificate authenticates this choice independently of the
/// source trial balance. An empty selected list differs from all roots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SummaryScope {
    AllRoots,
    Selected(Vec<u128>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSummaryGroup {
    pub account: VerifiedReportAccount,
    /// All descendant posting leaves, including zero-activity accounts.
    pub leaves: Vec<VerifiedReportAccount>,
    /// Exact gross posted and pending amounts, ordered by native unit.
    pub rows: Vec<ReportRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSummaryTrialBalance {
    pub book_id: [u8; 16],
    pub known_at: u64,
    pub source_certificate_digest: [u8; 32],
    pub scope: SummaryScope,
    /// Groups are ordered by root code, independently of selector ordering.
    pub groups: Vec<VerifiedSummaryGroup>,
    pub uncovered_leaves: Vec<VerifiedReportAccount>,
    /// Selected monetary source rows only; memo/statistical rows do not foot.
    pub unit_totals: BTreeMap<u32, (i128, i128)>,
    pub pending_unit_totals: BTreeMap<u32, (i128, i128)>,
}

impl VerifiedSummaryTrialBalance {
    /// Coverage of posting leaves, not a claim that the selected totals balance
    /// or that the report authenticates any economic event.
    pub fn is_complete(&self) -> bool {
        self.uncovered_leaves.is_empty()
    }
}

#[derive(Debug)]
pub(super) struct Certificate<'a> {
    pub source: &'a [u8],
    pub scope: SummaryScope,
    pub output: &'a [u8],
    pub digest: [u8; 32],
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    bytes.starts_with(&(CERTIFICATE_FORMAT.len() as u32).to_le_bytes())
        && bytes.get(4..4 + CERTIFICATE_FORMAT.len()) == Some(CERTIFICATE_FORMAT)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    if bytes.len() > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed(
            "bounded_input",
            "summary certificate exceeds 64 MiB",
        ));
    }
    let mut r = Reader::new(bytes);
    if r.bytes(64, "summary.format")? != CERTIFICATE_FORMAT {
        return Err(failed(
            "supported_report",
            "unsupported summary certificate format",
        ));
    }
    let source = r.bytes(MAX_REPORT_BUNDLE_BYTES, "summary.source")?;
    let scope = match r.u8("summary.scope")? {
        0 => SummaryScope::AllRoots,
        1 => {
            let count = r.count(MAX_ROOTS, 16, "summary.roots")?;
            let mut roots = Vec::with_capacity(count);
            for _ in 0..count {
                roots.push(r.u128("summary.root")?);
            }
            if !roots.windows(2).all(|pair| pair[0] < pair[1]) {
                return Err(failed(
                    "summary_selection",
                    "summary roots must be strictly increasing",
                ));
            }
            SummaryScope::Selected(roots)
        }
        _ => return Err(failed("summary_selection", "unsupported summary scope")),
    };
    let output = r.bytes(MAX_REPORT_BUNDLE_BYTES, "summary.output")?;
    if !output.starts_with(OUTPUT_FORMAT) {
        return Err(failed(
            "supported_report",
            "unsupported summary output format",
        ));
    }
    let digest = r.fixed("summary.digest")?;
    r.finish("summary certificate")?;
    let body = &bytes[..bytes.len() - 32];
    if hash_parts(DIGEST_DOMAIN, &[&(body.len() as u32).to_le_bytes(), body]) != digest {
        return Err(failed(
            "certificate_digest",
            "summary certificate bytes differ from their commitment",
        ));
    }
    Ok(Certificate {
        source,
        scope,
        output,
        digest,
    })
}

fn add(sum: &mut [i128; 4], row: &ReportRow) -> Result<(), ReportError> {
    for (slot, value) in sum.iter_mut().zip([
        row.debits,
        row.credits,
        row.debits_pending,
        row.credits_pending,
    ]) {
        if value < 0 {
            return Err(failed("exact_arithmetic", "negative summary source amount"));
        }
        *slot = slot
            .checked_add(value)
            .ok_or_else(|| failed("exact_arithmetic", "summary column overflow"))?;
    }
    Ok(())
}

/// Validate the entire forest, then propagate one selected owner down each
/// tree. This also rejects overlapping empty summaries. The iterative walk
/// bounds stack use and visits each account once, even for a very deep chart.
fn groups(
    scope: &SummaryScope,
    schema: &metadata::Schema,
) -> Result<(Vec<VerifiedSummaryGroup>, BTreeMap<u128, usize>), ReportError> {
    let mut children: BTreeMap<u128, Vec<u128>> = BTreeMap::new();
    for (&child, &parent) in &schema.parents {
        if !schema.accounts.contains_key(&child) {
            return Err(failed("summary_chart", "parent link has no child account"));
        }
        let account = schema
            .accounts
            .get(&parent)
            .ok_or_else(|| failed("summary_chart", "parent account is absent"))?;
        if account.is_leaf {
            return Err(failed("summary_chart", "a posting leaf has children"));
        }
        children.entry(parent).or_default().push(child);
    }
    let top: Vec<_> = schema
        .accounts
        .keys()
        .filter(|id| !schema.parents.contains_key(id))
        .copied()
        .collect();
    let mut roots = match scope {
        SummaryScope::AllRoots => top.clone(),
        SummaryScope::Selected(roots) => roots.clone(),
    };
    if roots.iter().any(|id| !schema.accounts.contains_key(id)) {
        return Err(failed(
            "summary_selection",
            "selected root is absent from the historical chart",
        ));
    }
    roots.sort_by(|a, b| {
        schema.accounts[a]
            .code
            .cmp(&schema.accounts[b].code)
            .then(a.cmp(b))
    });
    let selected: BTreeMap<_, _> = roots
        .iter()
        .enumerate()
        .map(|(index, root)| (*root, index))
        .collect();
    if selected.len() != roots.len() {
        return Err(failed("summary_selection", "duplicate selected root"));
    }
    let mut groups = roots
        .iter()
        .map(|&root| {
            Ok(VerifiedSummaryGroup {
                account: open_items::account(root, schema)?,
                leaves: Vec::new(),
                rows: Vec::new(),
            })
        })
        .collect::<Result<Vec<_>, ReportError>>()?;
    let mut owners = BTreeMap::new();
    let mut pending: Vec<_> = top.into_iter().map(|id| (id, None)).collect();
    let mut visited = 0usize;
    while let Some((id, ancestor)) = pending.pop() {
        visited += 1;
        if visited > schema.accounts.len() {
            return Err(failed("summary_chart", "historical chart has a cycle"));
        }
        let owner = match (ancestor, selected.get(&id).copied()) {
            (Some(_), Some(_)) => {
                return Err(failed(
                    "summary_selection",
                    "selected roots overlap through an ancestor relationship",
                ));
            }
            (ancestor, selected) => selected.or(ancestor),
        };
        if let Some(index) = owner {
            owners.insert(id, index);
            if schema.accounts[&id].is_leaf {
                groups[index].leaves.push(open_items::account(id, schema)?);
            }
        }
        if let Some(children) = children.get(&id) {
            pending.extend(children.iter().map(|child| (*child, owner)));
        }
    }
    if visited != schema.accounts.len() {
        return Err(failed("summary_chart", "historical chart has a cycle"));
    }
    for group in &mut groups {
        group.leaves.sort_by(|a, b| a.code.cmp(&b.code));
    }
    Ok((groups, owners))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn replay(
    certificate: &Certificate<'_>,
    book_id: [u8; 16],
    known_at: u64,
    source_certificate_digest: [u8; 32],
    schema: &metadata::Schema,
    source_rows: &[ReportRow],
    source_output: &[u8],
    units: &[u32],
) -> Result<(VerifiedSummaryTrialBalance, Vec<u8>), ReportError> {
    let (mut groups, owners) = groups(&certificate.scope, schema)?;
    let mut selected_sums = BTreeMap::<u32, [i128; 4]>::new();
    let mut group_sums = vec![BTreeMap::<u32, [i128; 4]>::new(); groups.len()];
    let mut seen = BTreeSet::new();
    for row in source_rows {
        let account = schema
            .accounts
            .get(&row.account)
            .ok_or_else(|| failed("account_metadata", "summary source account is absent"))?;
        if (!account.is_leaf && !schema.promoted_accounts.contains(&row.account))
            || account.code != row.code
            || account.name != row.name
            || account.account_type != row.account_type
            || !seen.insert((row.account, row.unit))
        {
            return Err(failed(
                "account_metadata",
                "summary source row is duplicate, nonposting or has different historical metadata",
            ));
        }
        if units.binary_search(&row.unit).is_err() {
            return Err(failed(
                "registry_closure",
                "summary source uses a unit outside its authenticated registry",
            ));
        }
        if let Some(&index) = owners.get(&row.account) {
            add(group_sums[index].entry(row.unit).or_default(), row)?;
            if row.account_type <= 5 {
                add(selected_sums.entry(row.unit).or_default(), row)?;
            }
        }
    }
    for (group, sums) in groups.iter_mut().zip(group_sums) {
        group.rows = sums
            .into_iter()
            .map(|(unit, values)| ReportRow {
                account: group.account.account,
                code: group.account.code.clone(),
                name: group.account.name.clone(),
                account_type: group.account.account_type,
                unit,
                debits: values[0],
                credits: values[1],
                debits_pending: values[2],
                credits_pending: values[3],
            })
            .collect();
    }
    let mut uncovered_leaves = schema
        .accounts
        .iter()
        .filter(|(id, account)| account.is_leaf && !owners.contains_key(id))
        .map(|(&id, _)| open_items::account(id, schema))
        .collect::<Result<Vec<_>, _>>()?;
    uncovered_leaves.sort_by(|a, b| a.code.cmp(&b.code));
    let report = VerifiedSummaryTrialBalance {
        book_id,
        known_at,
        source_certificate_digest,
        scope: certificate.scope.clone(),
        groups,
        uncovered_leaves,
        unit_totals: selected_sums
            .iter()
            .map(|(&unit, values)| (unit, (values[0], values[1])))
            .collect(),
        pending_unit_totals: selected_sums
            .iter()
            .map(|(&unit, values)| (unit, (values[2], values[3])))
            .collect(),
    };
    let output = encode(&report, source_output)?;
    if output != certificate.output {
        return Err(failed(
            "report_recomputation",
            "summary roots, complete leaf coverage, historical metadata, promoted balances, totals or canonical bytes differ from independent replay",
        ));
    }
    Ok((report, output))
}

fn budget(size: &mut usize, bytes: usize) -> Result<(), ReportError> {
    *size = size
        .checked_add(bytes)
        .filter(|size| *size <= MAX_REPORT_BUNDLE_BYTES)
        .ok_or_else(|| failed("bounded_input", "summary reconstruction exceeds 64 MiB"))?;
    Ok(())
}

fn account_size(account: &VerifiedReportAccount) -> usize {
    35 + account.code.len()
        + account.name.len()
        + if matches!(account.unit_policy, OpenItemUnitPolicy::Single(_)) {
            5
        } else {
            1
        }
        + 1
        + account.limit.as_ref().map_or(0, |limit| {
            3 + 16 * (usize::from(limit.lower.is_some()) + usize::from(limit.upper.is_some()))
        })
}

fn write_account(w: &mut Writer, account: &VerifiedReportAccount) {
    w.u128(account.account)
        .bytes(account.code.as_bytes())
        .bytes(account.name.as_bytes())
        .u8(account.account_type)
        .u8(account.normal_balance)
        .u8(u8::from(account.is_leaf));
    match account.unit_policy {
        OpenItemUnitPolicy::Single(unit) => {
            w.u8(0).u32(unit);
        }
        OpenItemUnitPolicy::AnyCurrency => {
            w.u8(1);
        }
        OpenItemUnitPolicy::AnyUnit => {
            w.u8(2);
        }
    }
    w.u8(u8::from(account.limit.is_some()));
    if let Some(limit) = &account.limit {
        for bound in [limit.lower, limit.upper] {
            w.u8(u8::from(bound.is_some()));
            if let Some(bound) = bound {
                w.i128(bound);
            }
        }
        w.u8(u8::from(limit.period_scoped));
    }
    w.u64(account.created_at);
}

fn encode(
    report: &VerifiedSummaryTrialBalance,
    source_output: &[u8],
) -> Result<Vec<u8>, ReportError> {
    let mut size = OUTPUT_FORMAT.len() + 16 + 4 + 16;
    budget(&mut size, source_output.len())?;
    for group in &report.groups {
        budget(&mut size, account_size(&group.account) + 8)?;
        for leaf in &group.leaves {
            budget(&mut size, account_size(leaf))?;
        }
        for row in &group.rows {
            budget(&mut size, 93 + row.code.len() + row.name.len())?;
        }
    }
    for account in &report.uncovered_leaves {
        budget(&mut size, account_size(account))?;
    }
    for totals in [&report.unit_totals, &report.pending_unit_totals] {
        budget(&mut size, 36 * totals.len())?;
    }
    let mut w = Writer {
        buf: Vec::with_capacity(size),
    };
    w.fixed(OUTPUT_FORMAT)
        .fixed(&report.book_id)
        .bytes(source_output)
        .count(report.groups.len());
    for group in &report.groups {
        write_account(&mut w, &group.account);
        w.count(group.leaves.len());
        for leaf in &group.leaves {
            write_account(&mut w, leaf);
        }
        w.count(group.rows.len());
        for row in &group.rows {
            w.u128(row.account)
                .bytes(row.code.as_bytes())
                .bytes(row.name.as_bytes())
                .u8(row.account_type)
                .u32(row.unit)
                .i128(row.debits)
                .i128(row.credits)
                .i128(row.debits_pending)
                .i128(row.credits_pending);
        }
    }
    w.count(report.uncovered_leaves.len());
    for account in &report.uncovered_leaves {
        write_account(&mut w, account);
    }
    for totals in [&report.unit_totals, &report.pending_unit_totals] {
        w.count(totals.len());
        for (&unit, &(debits, credits)) in totals {
            w.u32(unit).i128(debits).i128(credits);
        }
    }
    debug_assert_eq!(w.buf.len(), size);
    Ok(w.buf)
}
