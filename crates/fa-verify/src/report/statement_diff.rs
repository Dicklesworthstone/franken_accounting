//! Independently recomputed statement bridges between two recorded frontiers.
//!
//! Both native sources are checked against the complete authenticated prefix
//! at their own known-at coordinates. The outer certificate selects the same
//! accounting question twice; it cannot substitute source amounts, omit zero
//! lines, or hide chart changes behind unchanged monetary values. Approval,
//! issuance and the economic meaning of a restatement are not asserted here.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    Certificate as NativeCertificate, MAX_REPORT_BUNDLE_BYTES, ReportError, Selection,
    StatementMapping, VerifiedStatement, failed,
};
use crate::blake3::hash_parts;
use crate::codec::{Reader, Writer};

const FORMAT: &[u8] = b"fa:statement-diff-certificate:v1";
const FUNCTIONAL_FORMAT: &[u8] = b"fa:functional-statement-diff-certificate:v1";
const DIGEST_DOMAIN: &[u8] = b"fa:statement-diff-certificate-digest:v1";
const SOURCE_DOMAIN: &[u8] = b"fa:statement-diff-source:v1";
const OUTPUT_FORMAT: &[u8] = b"fa:statement-diff:v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementLineChange {
    pub code: String,
    pub label: String,
    pub unit: u32,
    pub before: Vec<i128>,
    pub after: Vec<i128>,
    pub delta: Vec<i128>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementMappingChange {
    pub account: u128,
    pub before: Option<StatementMapping>,
    pub after: Option<StatementMapping>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedStatementDiff {
    pub before_known_at: u64,
    pub after_known_at: u64,
    /// Domain-separated commitments to the complete reconstructed statements.
    pub before_digest: [u8; 32],
    pub after_digest: [u8; 32],
    pub before: VerifiedStatement,
    pub after: VerifiedStatement,
    /// Every line/unit pair, including unchanged and all-zero columns.
    pub lines: Vec<StatementLineChange>,
    /// Every changed mapping, sorted by account identity rather than label.
    pub mapping_changes: Vec<StatementMappingChange>,
}

pub(super) struct Certificate<'a> {
    pub before: &'a [u8],
    pub after: &'a [u8],
    pub output: &'a [u8],
    pub digest: [u8; 32],
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    Reader::new(bytes)
        .bytes(64, "statement_diff.format")
        .is_ok_and(|format| format == FORMAT || format == FUNCTIONAL_FORMAT)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    if bytes.len() > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed(
            "bounded_input",
            "statement comparison exceeds 64 MiB",
        ));
    }
    let mut r = Reader::new(bytes);
    if r.bytes(64, "statement_diff.format")? != FORMAT {
        return Err(failed(
            "supported_report",
            "portable statement comparisons require the native v1 family; functional comparisons need their own two-source valuation closure",
        ));
    }
    // These fields are retained provenance, not an authorization grant.
    r.u128("statement_diff.producer")?;
    r.fixed::<32>("statement_diff.capability")?;
    let before = r.bytes(MAX_REPORT_BUNDLE_BYTES, "statement_diff.before")?;
    let after = r.bytes(MAX_REPORT_BUNDLE_BYTES, "statement_diff.after")?;
    if !before.starts_with(super::STATEMENT_CERTIFICATE_FORMAT)
        || !after.starts_with(super::STATEMENT_CERTIFICATE_FORMAT)
    {
        return Err(failed(
            "supported_report",
            "both comparison sources must be native v4 financial statements",
        ));
    }
    let output = r.bytes(MAX_REPORT_BUNDLE_BYTES, "statement_diff.output")?;
    if Reader::new(output).bytes(64, "statement_diff.output_format")? != OUTPUT_FORMAT {
        return Err(failed(
            "supported_report",
            "statement comparison has an unrelated output format",
        ));
    }
    let body_len = bytes.len() - r.remaining();
    let digest = r.fixed::<32>("statement_diff.digest")?;
    r.finish("statement comparison certificate")?;
    // Model identities frame each part with its u32 byte length. The
    // accumulator/report-output hashes elsewhere deliberately use raw parts.
    if hash_parts(
        DIGEST_DOMAIN,
        &[&(body_len as u32).to_le_bytes(), &bytes[..body_len]],
    ) != digest
    {
        return Err(failed(
            "certificate_digest",
            "statement comparison digest differs from its exact body",
        ));
    }
    Ok(Certificate {
        before,
        after,
        output,
        digest,
    })
}

pub(super) fn bind(
    before: &NativeCertificate<'_>,
    after: &NativeCertificate<'_>,
) -> Result<(), ReportError> {
    if before.book != after.book
        || before.branch != [0; 16]
        || after.branch != [0; 16]
        || before.known_at > after.known_at
        || before.selection != after.selection
        || !matches!(before.selection, Selection::Statement(_))
        || before.time_selection.is_some()
        || after.time_selection.is_some()
        || before.dimension.is_some()
        || after.dimension.is_some()
        || before.functional
        || after.functional
    {
        return Err(failed(
            "statement_diff_selection",
            "comparison sources must ask the same native sequence-selected trunk statement at ordered frontiers",
        ));
    }
    if before.registry_digest != after.registry_digest {
        return Err(failed(
            "registry_closure",
            "comparison sources require the same authenticated four-registry closure; cross-epoch comparison is unsupported",
        ));
    }
    Ok(())
}

/// Each source report and its exact bytes have already been independently
/// replayed against its own historical prefix by the caller.
#[allow(clippy::too_many_arguments)]
pub(super) fn replay(
    request: &Certificate<'_>,
    before_certificate: &NativeCertificate<'_>,
    after_certificate: &NativeCertificate<'_>,
    before: VerifiedStatement,
    before_bytes: &[u8],
    after: VerifiedStatement,
    after_bytes: &[u8],
) -> Result<(VerifiedStatementDiff, Vec<u8>), ReportError> {
    bind(before_certificate, after_certificate)?;
    if before.definition_digest != after.definition_digest
        || before.definition_name != after.definition_name
        || before.definition_version != after.definition_version
        || before.kind != after.kind
        || before.units != after.units
        || before.columns != after.columns
        || before.lines.len() != after.lines.len()
    {
        return Err(failed(
            "statement_diff_selection",
            "historical statements differ in their definition, columns or complete unit universe",
        ));
    }
    let mut lines = Vec::with_capacity(before.lines.len());
    for (old, new) in before.lines.iter().zip(&after.lines) {
        if old.code != new.code
            || old.label != new.label
            || old.unit != new.unit
            || old.amounts.len() != new.amounts.len()
            || old.amounts.len() != before.columns.len()
        {
            return Err(failed(
                "statement_diff_selection",
                "historical statements have different line identities or amount columns",
            ));
        }
        let delta = old
            .amounts
            .iter()
            .zip(&new.amounts)
            .map(|(old, new)| {
                new.checked_sub(*old).ok_or_else(|| {
                    failed(
                        "exact_arithmetic",
                        "statement comparison delta exceeds i128",
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        lines.push(StatementLineChange {
            code: old.code.clone(),
            label: old.label.clone(),
            unit: old.unit,
            before: old.amounts.clone(),
            after: new.amounts.clone(),
            delta,
        });
    }
    let old: BTreeMap<_, _> = before.mappings.iter().map(|m| (m.account, m)).collect();
    let new: BTreeMap<_, _> = after.mappings.iter().map(|m| (m.account, m)).collect();
    let identities: BTreeSet<_> = old.keys().chain(new.keys()).copied().collect();
    let mapping_changes = identities
        .into_iter()
        .filter_map(|account| {
            let before = old.get(&account).copied();
            let after = new.get(&account).copied();
            (before != after).then(|| StatementMappingChange {
                account,
                before: before.cloned(),
                after: after.cloned(),
            })
        })
        .collect();
    let result = VerifiedStatementDiff {
        before_known_at: before_certificate.known_at,
        after_known_at: after_certificate.known_at,
        before_digest: hash_parts(
            SOURCE_DOMAIN,
            &[&(before_bytes.len() as u32).to_le_bytes(), before_bytes],
        ),
        after_digest: hash_parts(
            SOURCE_DOMAIN,
            &[&(after_bytes.len() as u32).to_le_bytes(), after_bytes],
        ),
        before,
        after,
        lines,
        mapping_changes,
    };
    let output = encode(
        &result,
        &before_certificate.book,
        &before_certificate.branch,
    )?;
    if output != request.output {
        return Err(failed(
            "statement_diff_recomputation",
            "statement source commitments, complete lines, checked deltas, mapping changes or exact canonical bytes differ from independent replay",
        ));
    }
    Ok((result, output))
}

fn encode(
    report: &VerifiedStatementDiff,
    book: &[u8; 16],
    branch: &[u8; 16],
) -> Result<Vec<u8>, ReportError> {
    // Bound the full encoding before allocation. A bridge carries three
    // amount vectors per line and both sides of every mapping change.
    let mut size = 4 + OUTPUT_FORMAT.len() + 16 + 16 + 8 + 8 + 32 * 3 + 4 * 3;
    let mut charge = |bytes: usize| -> Result<(), ReportError> {
        size = size
            .checked_add(bytes)
            .filter(|size| *size <= MAX_REPORT_BUNDLE_BYTES)
            .ok_or_else(|| {
                failed(
                    "bounded_input",
                    "recomputed statement bridge exceeds 64 MiB",
                )
            })?;
        Ok(())
    };
    for column in &report.before.columns {
        charge(4 + column.label.len() + 4 + 1 + 4)?;
        if column.effective_from.is_some() {
            charge(4)?;
        }
        for period in &column.periods {
            charge(4 + period.len())?;
        }
    }
    for line in &report.lines {
        charge(24 + line.code.len() + line.label.len() + line.before.len() * 48)?;
    }
    for change in &report.mapping_changes {
        charge(18)?;
        for mapping in [change.before.as_ref(), change.after.as_ref()]
            .into_iter()
            .flatten()
        {
            charge(30 + mapping.code.len() + mapping.name.len() + mapping.line_code.len())?;
        }
    }
    let mut w = Writer::default();
    w.bytes(OUTPUT_FORMAT)
        .fixed(book)
        .fixed(branch)
        .u64(report.before_known_at)
        .u64(report.after_known_at)
        .fixed(&report.before_digest)
        .fixed(&report.after_digest)
        .fixed(&report.before.definition_digest)
        .count(report.before.columns.len());
    for column in &report.before.columns {
        w.bytes(column.label.as_bytes()).count(column.periods.len());
        for period in &column.periods {
            w.bytes(period.as_bytes());
        }
        w.u8(u8::from(column.effective_from.is_some()));
        if let Some(from) = column.effective_from {
            w.i32(from);
        }
        w.i32(column.effective_through);
    }
    w.count(report.lines.len());
    for line in &report.lines {
        w.bytes(line.code.as_bytes())
            .bytes(line.label.as_bytes())
            .u32(line.unit);
        for amounts in [&line.before, &line.after, &line.delta] {
            w.count(amounts.len());
            for amount in amounts {
                w.i128(*amount);
            }
        }
    }
    w.count(report.mapping_changes.len());
    for change in &report.mapping_changes {
        w.u128(change.account);
        for mapping in [&change.before, &change.after] {
            w.u8(u8::from(mapping.is_some()));
            if let Some(mapping) = mapping {
                w.u128(mapping.account)
                    .bytes(mapping.code.as_bytes())
                    .bytes(mapping.name.as_bytes())
                    .u8(mapping.account_type)
                    .u8(u8::from(mapping.is_leaf))
                    .bytes(mapping.line_code.as_bytes());
            }
        }
    }
    if w.buf.len() != size {
        return Err(failed(
            "canonical_encoding",
            "statement bridge length differs from its bounded encoding",
        ));
    }
    Ok(w.buf)
}
