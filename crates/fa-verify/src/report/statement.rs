//! Independent statement replay over the authenticated historical journal.
//! Account mappings include every covered leaf, even without a balance. Lines
//! use the complete bound unit table and retain current/comparative ordering.
mod arithmetic;
mod definition;
#[cfg(test)]
mod tests;

use super::{ReportError, failed, metadata};
use crate::blake3::hash_parts;
use crate::codec::Writer;
use crate::envelope::{LeafEnvelope, Leg};
pub(super) use arithmetic::Sum;
use definition::{Definition, Source};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementColumn {
    pub label: String,
    pub periods: Vec<String>,
    pub effective_from: Option<i32>,
    pub effective_through: i32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementLine {
    pub code: String,
    pub label: String,
    pub unit: u32,
    pub amounts: Vec<i128>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementMapping {
    pub account: u128,
    pub code: String,
    pub name: String,
    pub account_type: u8,
    pub is_leaf: bool,
    pub line_code: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedStatement {
    pub definition_name: String,
    pub definition_version: u32,
    pub definition_digest: [u8; 32],
    pub kind: &'static str,
    /// Complete numeric unit universe, supplied independently for v1 bundles
    /// or authenticated by the certificate-bound registry for v2 bundles.
    pub units: Vec<u32>,
    pub columns: Vec<StatementColumn>,
    pub lines: Vec<StatementLine>,
    pub mappings: Vec<StatementMapping>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Selection {
    definition: Definition,
    pub periods: Vec<String>,
    pub comparative: Vec<String>,
}
impl Selection {
    pub fn new(
        bytes: &[u8],
        periods: Vec<String>,
        comparative: Vec<String>,
    ) -> Result<Self, ReportError> {
        if periods.is_empty() || periods.len() > 256 || comparative.len() > 256 {
            return Err(failed(
                "report_selector",
                "statement requires 1..=256 current periods and at most 256 comparative periods",
            ));
        }
        Ok(Self {
            definition: Definition::decode(bytes)?,
            periods,
            comparative,
        })
    }
    pub fn activity(&self) -> bool {
        self.definition.activity
    }
}

#[derive(Default)]
pub(super) struct Lineage {
    origins: BTreeMap<usize, usize>,
    /// Actual uncached ancestry inspections, retained only in tests.
    #[cfg(test)]
    inspected: Vec<usize>,
}

/// Resolve reversal ancestry from content-bound targets at this frontier.
/// Memoization bounds repeated lineage walks without accepting cycles, missing
/// targets, or a target that became known after the reversing entry.
pub(super) fn origin(
    index: usize,
    envelopes: &[LeafEnvelope],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    by_identity: &BTreeMap<u128, usize>,
    lineage: &mut Lineage,
) -> Result<usize, ReportError> {
    let mut at = index;
    let mut path = BTreeSet::new();
    let original = loop {
        if let Some(original) = lineage.origins.get(&at) {
            break *original;
        }
        if !path.insert(at) {
            return Err(failed(
                "entry_lineage",
                "reversal ancestry contains a cycle",
            ));
        }
        #[cfg(test)]
        lineage.inspected.push(at);
        if envelopes[at].class != 4 {
            break at;
        }
        let (target, digest, kind) = match infos[&at].supersession.as_slice() {
            [target] => *target,
            _ => {
                return Err(failed(
                    "entry_lineage",
                    "reversal must name exactly one Reverses target",
                ));
            }
        };
        if kind != 1 {
            return Err(failed(
                "entry_lineage",
                "reversal carries another supersession kind",
            ));
        }
        let next = *by_identity.get(&target).ok_or_else(|| {
            failed(
                "entry_lineage",
                "reversal target is absent from the visible prefix",
            )
        })?;
        if envelopes[next].record_digest != digest
            || envelopes[next].commit_seq > envelopes[at].commit_seq
        {
            return Err(failed(
                "entry_lineage",
                "reversal target digest differs or target is known later",
            ));
        }
        at = next;
    };
    // Cache only after every edge in the new path has authenticated. Include
    // the terminal original so comparative traversals inspect every record at
    // most once. Reaching a cached ancestor never excuses its incoming edge.
    for at in path {
        lineage.origins.insert(at, original);
    }
    Ok(original)
}

fn mappings(
    definition: &Definition,
    schema: &metadata::Schema,
) -> Result<Vec<StatementMapping>, ReportError> {
    if schema.accounts.len() > 1_000_000 {
        return Err(failed(
            "statement_partition",
            "historical chart exceeds the statement bound",
        ));
    }
    let mut mapped = Vec::new();
    for (id, account) in &schema.accounts {
        if account.name.len() > 1024 * 1024 {
            return Err(failed(
                "account_metadata",
                "statement account name exceeds the chart-schema bound",
            ));
        }
        if !account.is_leaf || !definition.covered(account.account_type) {
            continue;
        }
        let codes: Vec<_> = definition
            .lines
            .iter()
            .filter_map(|line| match &line.source {
                Source::Accounts { types, .. } if types.contains(&account.account_type) => {
                    Some(&line.code)
                }
                _ => None,
            })
            .collect();
        let code = match codes.as_slice() {
            [code] => *code,
            _ => {
                return Err(failed(
                    "statement_partition",
                    format!(
                        "covered account {} maps to {} lines; exactly one is required even for zero balances",
                        account.code,
                        codes.len()
                    ),
                ));
            }
        };
        mapped.push(StatementMapping {
            account: *id,
            code: account.code.clone(),
            name: account.name.clone(),
            account_type: account.account_type,
            is_leaf: account.is_leaf,
            line_code: code.clone(),
        });
    }
    mapped.sort_by(|a, b| a.code.cmp(&b.code).then(a.account.cmp(&b.account)));
    Ok(mapped)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn replay(
    selection: &Selection,
    book: &[u8; 16],
    branch: &[u8; 16],
    known_at: u64,
    units: &[u32],
    schema: &metadata::Schema,
    envelopes: &[LeafEnvelope],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    legs: &[Vec<Leg>],
    visible_migrations: &BTreeSet<u64>,
    resolved: &BTreeSet<usize>,
) -> Result<(VerifiedStatement, Vec<u8>), ReportError> {
    if units.is_empty() || units.len() > 4096 || !units.windows(2).all(|u| u[0] < u[1]) {
        return Err(failed(
            "registry_closure",
            "statement units are incomplete or noncanonical",
        ));
    }
    let definition = &selection.definition;
    let mappings = mappings(definition, schema)?;
    // The recipient's unit universe can enlarge an otherwise small input.
    // Bound the reconstructed output before allocating per-unit line values.
    let column_count = 1 + usize::from(!selection.comparative.is_empty());
    let mut output_budget = 13
        + 4
        + 16
        + 16
        + 8
        + 4
        + definition.name.len()
        + 4
        + 32
        + 4
        + definition.bytes.len()
        + 4
        + 4
        + 4;
    for (label, periods) in [
        ("current", &selection.periods),
        ("comparative", &selection.comparative),
    ] {
        if periods.is_empty() {
            continue;
        }
        output_budget += 4 + label.len() + 4 + 1 + 4 + if definition.activity { 4 } else { 0 };
        output_budget += periods.iter().map(|period| 4 + period.len()).sum::<usize>();
    }
    for line in &definition.lines {
        output_budget +=
            units.len() * (4 + line.code.len() + 4 + line.label.len() + 4 + 4 + 16 * column_count);
    }
    for account in &mappings {
        output_budget +=
            16 + 4 + account.code.len() + 4 + account.name.len() + 2 + 4 + account.line_code.len();
    }
    if output_budget > super::MAX_REPORT_BUNDLE_BYTES {
        return Err(failed(
            "bounded_input",
            "reconstructed statement exceeds 64 MiB",
        ));
    }
    let line_indexes: BTreeMap<_, _> = definition
        .lines
        .iter()
        .enumerate()
        .map(|(index, line)| (line.code.as_str(), index))
        .collect();
    let account_lines: BTreeMap<_, _> = mappings
        .iter()
        .map(|m| (m.account, line_indexes[m.line_code.as_str()]))
        .collect();
    let mut by_identity = BTreeMap::new();
    for (index, info) in infos {
        let envelope = &envelopes[*index];
        if !(1..=30).contains(&envelope.class) {
            return Err(failed(
                "registry_closure",
                "entry class is outside the bound registry vocabulary",
            ));
        }
        if envelope.class == 12 && !visible_migrations.contains(&(*index as u64)) {
            continue;
        }
        for identity in info.identities() {
            if by_identity
                .insert(identity, *index)
                .is_some_and(|old| old != *index)
            {
                return Err(failed(
                    "entry_identity",
                    "duplicate entry identity in the visible prefix",
                ));
            }
        }
    }
    let mut ancestry = Lineage::default();
    let mut columns = Vec::new();
    let mut values = Vec::new();
    for (label, periods) in [
        ("current", &selection.periods),
        ("comparative", &selection.comparative),
    ] {
        if periods.is_empty() {
            continue;
        }
        let (first, last) = schema.bounds(periods)?;
        columns.push(StatementColumn {
            label: label.into(),
            periods: periods.clone(),
            effective_from: definition.activity.then_some(first),
            effective_through: last,
        });
        let mut gross: BTreeMap<(u128, u32), [i128; 4]> = BTreeMap::new();
        for (index, info) in infos {
            let envelope = &envelopes[*index];
            if legs[*index].is_empty()
                || (envelope.class == 2 && resolved.contains(index))
                || (envelope.class == 12 && !visible_migrations.contains(&(*index as u64)))
            {
                continue;
            }
            let effective = envelope.effective_day.ok_or_else(|| {
                failed("report_selector", "monetary entry lacks an effective day")
            })?;
            let selected = if definition.activity {
                periods
                    .binary_search(&schema.entry_period(info, effective)?)
                    .is_ok()
            } else {
                effective <= last
            };
            if !selected {
                continue;
            }
            if definition.activity {
                let original = origin(*index, envelopes, infos, &by_identity, &mut ancestry)?;
                if envelope.class == 8 || envelopes[original].class == 8 {
                    continue;
                }
                if envelopes[original].class == 12 {
                    let original_day = envelopes[original].effective_day.ok_or_else(|| {
                        failed("entry_lineage", "migration origin lacks an effective day")
                    })?;
                    let period = schema.entry_period(&infos[&original], original_day)?;
                    if schema.period_kind(&period)? == 3 {
                        return Err(failed(
                            "entry_lineage",
                            "a migration in a Closing period does not retain its original accounting class",
                        ));
                    }
                }
            }
            for leg in &legs[*index] {
                if leg.mantissa < 0 {
                    return Err(failed("exact_arithmetic", "negative journal leg magnitude"));
                }
                let columns = gross.entry((leg.account, leg.unit)).or_insert([0; 4]);
                let column = usize::from(!leg.debit) + if envelope.class == 2 { 2 } else { 0 };
                columns[column] = columns[column].checked_add(leg.mantissa).ok_or_else(|| {
                    failed(
                        "exact_arithmetic",
                        "statement source account gross sum overflows",
                    )
                })?;
            }
        }
        if gross.len() > 2_000_000 {
            return Err(failed(
                "bounded_input",
                "statement source has too many balance rows",
            ));
        }
        let mut sums: BTreeMap<_, _> = units
            .iter()
            .map(|unit| (*unit, vec![Sum::default(); definition.lines.len()]))
            .collect();
        let mut totals: BTreeMap<u32, [i128; 4]> = BTreeMap::new();
        for ((account, unit), gross) in gross {
            let metadata = schema.accounts.get(&account).ok_or_else(|| {
                failed(
                    "account_metadata",
                    "statement balance names an undeclared account",
                )
            })?;
            if !metadata.is_leaf {
                return Err(failed(
                    "statement_partition",
                    "statement balance names a summary account",
                ));
            }
            let sums = sums.get_mut(&unit).ok_or_else(|| {
                failed(
                    "registry_closure",
                    "statement balance names an undeclared unit",
                )
            })?;
            if metadata.account_type <= 5 {
                let total = totals.entry(unit).or_insert([0; 4]);
                for i in 0..4 {
                    total[i] = total[i].checked_add(gross[i]).ok_or_else(|| {
                        failed("exact_arithmetic", "statement source unit total overflows")
                    })?;
                }
            }
            if let Some(&index) = account_lines.get(&account) {
                let Source::Accounts { credit, .. } = definition.lines[index].source else {
                    return Err(failed(
                        "statement_partition",
                        "mapped account names a formula",
                    ));
                };
                sums[index]
                    .add(gross[0], credit)
                    .and_then(|()| sums[index].add(gross[1], !credit))
                    .ok_or_else(|| failed("exact_arithmetic", "statement accumulator overflow"))?;
            }
        }
        if totals.values().any(|v| v[0] != v[1] || v[2] != v[3]) {
            return Err(failed(
                "monetary_footing",
                "statement source posted or pending values do not balance",
            ));
        }
        let mut column = BTreeMap::new();
        for (unit, mut sums) in sums {
            let mut amounts: Vec<i128> = Vec::with_capacity(definition.lines.len());
            for (index, line) in definition.lines.iter().enumerate() {
                if let Source::Formula { add, subtract } = &line.source {
                    for (operands, subtracting) in [(add, false), (subtract, true)] {
                        for operand in operands {
                            sums[index]
                                .add(amounts[line_indexes[operand.as_str()]], subtracting)
                                .ok_or_else(|| {
                                    failed(
                                        "exact_arithmetic",
                                        "statement formula accumulator overflow",
                                    )
                                })?;
                        }
                    }
                }
                let amount = sums[index].value().ok_or_else(|| {
                    failed(
                        "exact_arithmetic",
                        format!(
                            "statement line {} in {label}, unit {unit}, exceeds i128",
                            line.code
                        ),
                    )
                })?;
                if amount != 0 && definition.checks.contains(&line.code) {
                    return Err(failed(
                        "statement_identity",
                        format!(
                            "statement identity {} in {label}, unit {unit}, has residual {amount}",
                            line.code
                        ),
                    ));
                }
                amounts.push(amount);
            }
            column.insert(unit, amounts);
        }
        values.push(column);
    }
    let mut lines = Vec::with_capacity(definition.lines.len() * units.len());
    for (index, line) in definition.lines.iter().enumerate() {
        for unit in units {
            lines.push(StatementLine {
                code: line.code.clone(),
                label: line.label.clone(),
                unit: *unit,
                amounts: values.iter().map(|column| column[unit][index]).collect(),
            });
        }
    }
    let statement = VerifiedStatement {
        definition_name: definition.name.clone(),
        definition_version: definition.version,
        kind: if definition.activity {
            "IncomeStatement"
        } else {
            "BalanceSheet"
        },
        units: units.to_vec(),
        definition_digest: hash_parts(
            b"fa:statement-definition:v1",
            &[
                &(definition.bytes.len() as u32).to_le_bytes(),
                &definition.bytes,
            ],
        ),
        columns,
        lines,
        mappings,
    };
    let output = encode(&statement, &definition.bytes, book, branch, known_at)?;
    Ok((statement, output))
}

fn encode(
    statement: &VerifiedStatement,
    definition: &[u8],
    book: &[u8; 16],
    branch: &[u8; 16],
    known_at: u64,
) -> Result<Vec<u8>, ReportError> {
    let mut w = Writer::default();
    w.fixed(b"FA-STATEMENT\0")
        .u16(1)
        .u16(0)
        .fixed(book)
        .fixed(branch)
        .u64(known_at)
        .bytes(statement.definition_name.as_bytes())
        .u32(statement.definition_version)
        .fixed(&statement.definition_digest)
        .bytes(definition)
        .count(statement.columns.len());
    for column in &statement.columns {
        w.bytes(column.label.as_bytes()).count(column.periods.len());
        for period in &column.periods {
            w.bytes(period.as_bytes());
        }
        w.u8(u8::from(column.effective_from.is_some()));
        if let Some(day) = column.effective_from {
            w.i32(day);
        }
        w.i32(column.effective_through);
    }
    w.count(statement.lines.len());
    for line in &statement.lines {
        w.bytes(line.code.as_bytes())
            .bytes(line.label.as_bytes())
            .u32(line.unit)
            .count(line.amounts.len());
        for amount in &line.amounts {
            w.i128(*amount);
        }
        if w.buf.len() > super::MAX_REPORT_BUNDLE_BYTES {
            return Err(failed(
                "bounded_input",
                "recomputed statement output exceeds 64 MiB",
            ));
        }
    }
    w.count(statement.mappings.len());
    for mapping in &statement.mappings {
        w.u128(mapping.account)
            .bytes(mapping.code.as_bytes())
            .bytes(mapping.name.as_bytes())
            .u8(mapping.account_type)
            .u8(u8::from(mapping.is_leaf))
            .bytes(mapping.line_code.as_bytes());
        if w.buf.len() > super::MAX_REPORT_BUNDLE_BYTES {
            return Err(failed(
                "bounded_input",
                "recomputed statement output exceeds 64 MiB",
            ));
        }
    }
    Ok(w.buf)
}
