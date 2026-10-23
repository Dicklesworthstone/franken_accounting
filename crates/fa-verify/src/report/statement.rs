//! Native statement replay with a recipient-owned numeric unit universe.
//! Definitions are bounded report parameters. Chart membership, historical
//! periods and accounting legs come exclusively from the authenticated prefix.

use std::collections::{BTreeMap, BTreeSet};

use super::{Certificate, ReportError, failed, metadata, strings, text};
use crate::blake3::hash_parts;
use crate::codec::{Reader, Writer};
use crate::envelope::{LeafEnvelope, Leg};

const DEFINITION_MAGIC: &[u8; 17] = b"FA-STATEMENT-DEF\0";
const OUTPUT_MAGIC: &[u8; 13] = b"FA-STATEMENT\0";
const MAX_DEFINITION: usize = 64 * 1024;

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
    /// Exact mantissas in the declared unit, aligned to statement columns.
    pub amounts: Vec<i128>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedStatement {
    pub definition_name: String,
    pub definition_digest: [u8; 32],
    pub kind: &'static str,
    pub columns: Vec<StatementColumn>,
    pub lines: Vec<StatementLine>,
    /// Independently supplied by the recipient, not inferred from output.
    pub units: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Source {
    Accounts {
        types: Vec<u8>,
        credit: bool,
    },
    Formula {
        add: Vec<String>,
        subtract: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Line {
    code: String,
    label: String,
    source: Source,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Definition {
    bytes: Vec<u8>,
    name: String,
    version: u32,
    pub income: bool,
    lines: Vec<Line>,
    checks: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Selection {
    pub definition: Definition,
    pub periods: Vec<String>,
    comparative: Vec<String>,
}

fn definition_error(detail: impl Into<String>) -> ReportError {
    failed("statement_definition", detail)
}

fn identifier(r: &mut Reader<'_>, field: &'static str) -> Result<String, ReportError> {
    let value = text(r, 64, field)?;
    if value.is_empty()
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err(definition_error(format!("invalid identifier {field}")));
    }
    Ok(value.into())
}

fn label(r: &mut Reader<'_>, field: &'static str) -> Result<String, ReportError> {
    let value = text(r, 256, field)?;
    if value.trim().is_empty() {
        return Err(definition_error(format!("empty {field}")));
    }
    Ok(value.into())
}

fn operands(r: &mut Reader<'_>, field: &'static str) -> Result<Vec<String>, ReportError> {
    let count = r.count(64, 5, field)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(identifier(r, field)?);
    }
    if !values.windows(2).all(|p| p[0] < p[1]) {
        return Err(definition_error("operands must be sorted and distinct"));
    }
    Ok(values)
}

impl Definition {
    fn decode(bytes: &[u8]) -> Result<Self, ReportError> {
        if bytes.len() > MAX_DEFINITION {
            return Err(definition_error("definition exceeds 64 KiB"));
        }
        let mut r = Reader::new(bytes);
        if &r.fixed::<17>("definition.magic")? != DEFINITION_MAGIC
            || r.u16("definition.major")? != 1
            || r.u16("definition.minor")? != 0
        {
            return Err(definition_error("unsupported statement definition format"));
        }
        let name = identifier(&mut r, "definition.name")?;
        label(&mut r, "definition.title")?;
        let version = r.u32("definition.version")?;
        let income = match r.u8("definition.kind")? {
            0 => false,
            1 => true,
            _ => return Err(definition_error("unsupported statement kind")),
        };
        let count = r.count(64, 11, "definition.lines")?;
        if version == 0 || count == 0 {
            return Err(definition_error(
                "a definition needs a positive version and lines",
            ));
        }
        let mut earlier = BTreeSet::new();
        let mut lines = Vec::with_capacity(count);
        for _ in 0..count {
            let code = identifier(&mut r, "line.code")?;
            let label = label(&mut r, "line.label")?;
            if earlier.contains(&code) {
                return Err(definition_error("duplicate line code"));
            }
            let source = match r.u8("line.source")? {
                0 => {
                    let n = r.count(5, 1, "line.account_types")?;
                    let mut types = Vec::with_capacity(n);
                    for _ in 0..n {
                        types.push(r.u8("line.account_type")?);
                    }
                    if types.is_empty()
                        || !types.windows(2).all(|p| p[0] < p[1])
                        || types.iter().any(|t| {
                            if income {
                                !matches!(t, 4 | 5)
                            } else {
                                !(1..=5).contains(t)
                            }
                        })
                    {
                        return Err(definition_error(
                            "account types must be sorted, distinct and covered by the statement kind",
                        ));
                    }
                    let credit = match r.u8("line.sign")? {
                        0 => false,
                        1 => true,
                        _ => return Err(definition_error("invalid account sign")),
                    };
                    Source::Accounts { types, credit }
                }
                1 => {
                    let add = operands(&mut r, "formula.add")?;
                    let subtract = operands(&mut r, "formula.subtract")?;
                    if add.is_empty() && subtract.is_empty() {
                        return Err(definition_error("empty formula"));
                    }
                    let mut seen = BTreeSet::new();
                    for operand in add.iter().chain(&subtract) {
                        if !earlier.contains(operand) || !seen.insert(operand) {
                            return Err(definition_error(
                                "formula repeats an operand or references an unknown, forward or cyclic line",
                            ));
                        }
                    }
                    Source::Formula { add, subtract }
                }
                _ => return Err(definition_error("unknown statement expression")),
            };
            earlier.insert(code.clone());
            lines.push(Line {
                code,
                label,
                source,
            });
        }
        let checks = operands(&mut r, "definition.checks")?;
        r.finish("statement definition")?;
        if (!income && checks.is_empty())
            || checks.iter().any(|code| {
                !lines
                    .iter()
                    .any(|line| line.code == *code && matches!(line.source, Source::Formula { .. }))
            })
        {
            return Err(definition_error(
                "zero identities must name formula lines; a balance sheet requires an identity",
            ));
        }
        Ok(Self {
            bytes: bytes.into(),
            name,
            version,
            income,
            lines,
            checks,
        })
    }

    fn covers(&self, account_type: u8) -> bool {
        if self.income {
            matches!(account_type, 4 | 5)
        } else {
            (1..=5).contains(&account_type)
        }
    }

    fn digest(&self) -> [u8; 32] {
        hash_parts(
            b"fa:statement-definition:v1",
            &[&(self.bytes.len() as u32).to_le_bytes(), &self.bytes],
        )
    }
}

impl Selection {
    pub fn read(r: &mut Reader<'_>) -> Result<Self, ReportError> {
        let definition = Definition::decode(r.bytes(MAX_DEFINITION, "statement.definition")?)?;
        let periods = strings(r, "statement.periods")?;
        let comparative = strings(r, "statement.comparative")?;
        if periods.is_empty() || periods.len() > 256 || comparative.len() > 256 {
            return Err(failed(
                "report_selector",
                "statement columns need 1..=256 current periods and at most 256 comparative periods",
            ));
        }
        Ok(Self {
            definition,
            periods,
            comparative,
        })
    }
}

/// A signed sum of bounded i128 terms. Independent two-limb magnitudes avoid
/// rejecting a valid final value merely because intermediate terms cancel.
#[derive(Clone, Copy, Default)]
struct Sum {
    positive: (u128, u128),
    negative: (u128, u128),
}
impl Sum {
    fn add(&mut self, value: i128, subtract: bool) -> Result<(), ReportError> {
        let target = if (value < 0) != subtract {
            &mut self.negative
        } else {
            &mut self.positive
        };
        let (low, carry) = target.1.overflowing_add(value.unsigned_abs());
        target.0 = target
            .0
            .checked_add(u128::from(carry))
            .ok_or_else(arithmetic)?;
        target.1 = low;
        Ok(())
    }
    fn value(self) -> Result<i128, ReportError> {
        let negative = self.negative > self.positive;
        let (large, small) = if negative {
            (self.negative, self.positive)
        } else {
            (self.positive, self.negative)
        };
        let (low, borrow) = large.1.overflowing_sub(small.1);
        let high = large
            .0
            .checked_sub(small.0)
            .and_then(|v| v.checked_sub(u128::from(borrow)))
            .ok_or_else(arithmetic)?;
        if high != 0 {
            return Err(arithmetic());
        }
        if negative && low == i128::MIN.unsigned_abs() {
            return Ok(i128::MIN);
        }
        let value = i128::try_from(low).map_err(|_| arithmetic())?;
        if negative {
            value.checked_neg().ok_or_else(arithmetic)
        } else {
            Ok(value)
        }
    }
}

fn arithmetic() -> ReportError {
    failed(
        "exact_arithmetic",
        "statement amount exceeds its exact integer range",
    )
}

pub(super) struct Sources<'a, 'b> {
    pub certificate: &'a Certificate<'b>,
    pub schema: &'a metadata::Schema,
    pub envelopes: &'a [LeafEnvelope],
    pub legs: &'a [Vec<Leg>],
    pub infos: &'a BTreeMap<usize, metadata::EntryInfo<'b>>,
    pub by_digest: &'a BTreeMap<[u8; 32], usize>,
    pub visible_migrations: &'a BTreeSet<u64>,
    pub resolved: &'a BTreeSet<usize>,
}

#[derive(Default)]
struct Lineage {
    classes: BTreeMap<usize, bool>,
    /// Test-only work witness emitted where an uncached record is inspected.
    #[cfg(test)]
    inspected: Vec<usize>,
}

impl Sources<'_, '_> {
    fn income_included(
        &self,
        mut index: usize,
        lineage: &mut Lineage,
    ) -> Result<bool, ReportError> {
        let mut visited = BTreeSet::new();
        let mut path = Vec::new();
        let included = loop {
            if let Some(included) = lineage.classes.get(&index) {
                break *included;
            }
            if !visited.insert(index) {
                return Err(failed(
                    "accounting_lineage",
                    "reversal lineage contains a cycle",
                ));
            }
            path.push(index);
            #[cfg(test)]
            lineage.inspected.push(index);
            let original = &self.envelopes[index];
            if original.class != 4 {
                if original.class == 12 {
                    let day = original.effective_day.ok_or_else(|| {
                        failed("accounting_lineage", "migration has no effective day")
                    })?;
                    if self.schema.is_closing_period(&self.infos[&index], day)? {
                        return Err(failed(
                            "accounting_lineage",
                            "Closing-period migration does not retain its original accounting class",
                        ));
                    }
                }
                break original.class != 8;
            }
            let [(identity, digest, 1)] = self.infos[&index].supersession.as_slice() else {
                return Err(failed(
                    "accounting_lineage",
                    "reversal needs exactly one Reverses link",
                ));
            };
            let target = *self.by_digest.get(digest).ok_or_else(|| {
                failed(
                    "accounting_lineage",
                    "reversal target is absent from the authenticated prefix",
                )
            })?;
            if !self.infos[&target].matches_identity(*identity)
                || self.envelopes[target].commit_seq > self.envelopes[index].commit_seq
                || (self.envelopes[target].class == 12
                    && !self.visible_migrations.contains(&(target as u64)))
            {
                return Err(failed(
                    "accounting_lineage",
                    "reversal target has a mismatched identity, later birth or invisible migration origin",
                ));
            }
            index = target;
        };
        // Publish classifications only after the whole new path is verified.
        // A cached ancestor never excuses checking the edge that reaches it.
        for index in path {
            lineage.classes.insert(index, included);
        }
        Ok(included)
    }
}

pub(super) fn recompute(
    selection: &Selection,
    sources: &Sources<'_, '_>,
    units: &[u32],
) -> Result<(VerifiedStatement, Vec<u8>), ReportError> {
    let definition = &selection.definition;
    let schema = sources.schema;
    if schema.accounts.len() > 1_000_000 {
        return Err(failed(
            "bounded_input",
            "statement chart exceeds one million accounts",
        ));
    }
    let mut mappings = Vec::new();
    let mut account_lines = BTreeMap::new();
    for (id, account) in &schema.accounts {
        if !account.is_leaf || !definition.covers(account.account_type) {
            continue;
        }
        let mut matches = definition.lines.iter().enumerate().filter(|(_, line)| {
            matches!(&line.source, Source::Accounts { types, .. } if types.contains(&account.account_type))
        });
        let Some((line, _)) = matches.next() else {
            return Err(failed(
                "mapping_partition",
                format!("account {} is unmapped", account.code),
            ));
        };
        if matches.next().is_some() {
            return Err(failed(
                "mapping_partition",
                format!("account {} maps more than once", account.code),
            ));
        }
        account_lines.insert(*id, line);
        mappings.push((*id, account, line));
    }
    mappings.sort_by(|a, b| a.1.code.cmp(&b.1.code).then(a.0.cmp(&b.0)));
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
        output_budget += 4 + label.len() + 4 + 1 + 4 + if definition.income { 4 } else { 0 };
        output_budget += periods.iter().map(|period| 4 + period.len()).sum::<usize>();
    }
    for line in &definition.lines {
        output_budget +=
            units.len() * (4 + line.code.len() + 4 + line.label.len() + 4 + 4 + 16 * column_count);
    }
    for (_, account, line) in &mappings {
        output_budget += 16
            + 4
            + account.code.len()
            + 4
            + account.name.len()
            + 2
            + 4
            + definition.lines[*line].code.len();
    }
    if output_budget > super::MAX_REPORT_BUNDLE_BYTES {
        return Err(failed(
            "bounded_input",
            "reconstructed statement exceeds 64 MiB",
        ));
    }
    let indexes: BTreeMap<_, _> = definition
        .lines
        .iter()
        .enumerate()
        .map(|(i, line)| (line.code.as_str(), i))
        .collect();
    let mut columns = Vec::new();
    let mut values = Vec::new();
    let mut lineage = Lineage::default();
    for (label, periods) in [
        ("current", &selection.periods),
        ("comparative", &selection.comparative),
    ] {
        if periods.is_empty() {
            continue;
        }
        let (first, last) = schema.bounds(periods)?;
        let mut balances: BTreeMap<(u128, u32), [i128; 4]> = BTreeMap::new();
        for (index, info) in sources.infos {
            let envelope = &sources.envelopes[*index];
            if sources.legs[*index].is_empty()
                || (envelope.class == 2 && sources.resolved.contains(index))
                || (envelope.class == 12 && !sources.visible_migrations.contains(&(*index as u64)))
            {
                continue;
            }
            let day = envelope.effective_day.ok_or_else(|| {
                failed("report_selector", "monetary entry lacks an effective day")
            })?;
            let selected = if definition.income {
                periods
                    .binary_search(&schema.entry_period(info, day)?)
                    .is_ok()
            } else {
                day <= last
            };
            if !selected || (definition.income && !sources.income_included(*index, &mut lineage)?) {
                continue;
            }
            for leg in &sources.legs[*index] {
                let account = schema.accounts.get(&leg.account).ok_or_else(|| {
                    failed(
                        "account_metadata",
                        "statement leg names an undeclared account",
                    )
                })?;
                if !account.is_leaf {
                    return Err(failed(
                        "account_metadata",
                        "statement leg names a summary account",
                    ));
                }
                if units.binary_search(&leg.unit).is_err() {
                    return Err(failed(
                        "statement_units",
                        format!(
                            "selected posting unit {} is outside the recipient's unit universe",
                            leg.unit
                        ),
                    ));
                }
                if leg.mantissa < 0 {
                    return Err(arithmetic());
                }
                let values = balances.entry((leg.account, leg.unit)).or_insert([0; 4]);
                let column = usize::from(!leg.debit) + if envelope.class == 2 { 2 } else { 0 };
                values[column] = values[column]
                    .checked_add(leg.mantissa)
                    .ok_or_else(arithmetic)?;
            }
        }
        if balances.len() > 2_000_000 {
            return Err(failed(
                "bounded_input",
                "statement column exceeds two million balances",
            ));
        }
        let mut totals: BTreeMap<u32, [i128; 4]> = BTreeMap::new();
        let mut sums: BTreeMap<_, _> = units
            .iter()
            .map(|unit| (*unit, vec![Sum::default(); definition.lines.len()]))
            .collect();
        for ((account, unit), balance) in balances {
            if schema.accounts[&account].account_type <= 5 {
                let total = totals.entry(unit).or_insert([0; 4]);
                for (value, amount) in total.iter_mut().zip(balance) {
                    *value = value.checked_add(amount).ok_or_else(arithmetic)?;
                }
            }
            let Some(&line) = account_lines.get(&account) else {
                continue;
            };
            let Source::Accounts { credit, .. } = &definition.lines[line].source else {
                return Err(definition_error("account mapping names a formula"));
            };
            let unit_sums = sums
                .get_mut(&unit)
                .ok_or_else(|| failed("statement_units", "undeclared native unit"))?;
            unit_sums[line].add(balance[0], *credit)?;
            unit_sums[line].add(balance[1], !*credit)?;
        }
        if totals.values().any(|t| t[0] != t[1] || t[2] != t[3]) {
            return Err(failed(
                "monetary_footing",
                "selected statement postings do not balance by unit",
            ));
        }
        let mut column_values = BTreeMap::new();
        for (unit, mut sums) in sums {
            let mut results: Vec<i128> = Vec::with_capacity(definition.lines.len());
            for (i, line) in definition.lines.iter().enumerate() {
                if let Source::Formula { add, subtract } = &line.source {
                    for (operands, negative) in [(add, false), (subtract, true)] {
                        for operand in operands {
                            sums[i].add(results[indexes[operand.as_str()]], negative)?;
                        }
                    }
                }
                let value = sums[i].value()?;
                if value != 0 && definition.checks.binary_search(&line.code).is_ok() {
                    return Err(failed(
                        "statement_identity",
                        format!(
                            "line {} in {label}, unit {unit}, has nonzero residual {value}",
                            line.code
                        ),
                    ));
                }
                results.push(value);
            }
            column_values.insert(unit, results);
        }
        columns.push(StatementColumn {
            label: label.into(),
            periods: periods.clone(),
            effective_from: definition.income.then_some(first),
            effective_through: last,
        });
        values.push(column_values);
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
    let definition_digest = definition.digest();
    let report = VerifiedStatement {
        definition_name: definition.name.clone(),
        definition_digest,
        kind: if definition.income {
            "IncomeStatement"
        } else {
            "BalanceSheet"
        },
        columns,
        lines,
        units: units.into(),
    };
    let mut w = Writer::default();
    w.fixed(OUTPUT_MAGIC)
        .u16(1)
        .u16(0)
        .fixed(&sources.certificate.book)
        .fixed(&sources.certificate.branch)
        .u64(sources.certificate.known_at)
        .bytes(definition.name.as_bytes())
        .u32(definition.version)
        .fixed(&definition_digest)
        .bytes(&definition.bytes)
        .count(report.columns.len());
    for column in &report.columns {
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
    w.count(report.lines.len());
    for line in &report.lines {
        w.bytes(line.code.as_bytes())
            .bytes(line.label.as_bytes())
            .u32(line.unit)
            .count(line.amounts.len());
        for value in &line.amounts {
            w.i128(*value);
        }
    }
    w.count(mappings.len());
    for (id, account, line) in mappings {
        w.u128(id)
            .bytes(account.code.as_bytes())
            .bytes(account.name.as_bytes())
            .u8(account.account_type)
            .u8(u8::from(account.is_leaf))
            .bytes(definition.lines[line].code.as_bytes());
    }
    Ok((report, w.buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lineage_record(
        ordinal: u64,
        target: Option<(u128, [u8; 32])>,
    ) -> (Vec<u8>, usize, LeafEnvelope, u128) {
        let mut w = Writer::default();
        w.u16(1)
            .u16(0)
            .fixed(&[3; 16])
            .fixed(&[0; 16])
            .u16(if target.is_some() { 4 } else { 1 })
            .i32(0)
            .u8(0);
        w.fixed(&[0; 32]).u8(0).fixed(&[0; 24]).bytes(&[]);
        w.u8(0).count(2);
        for (account, side) in [(1, 0), (2, 1)] {
            w.u8(side ^ ((ordinal & 1) as u8))
                .u128(account)
                .u32(1)
                .i128(10)
                .u8(0)
                .count(0)
                .u8(0)
                .count(0);
        }
        w.u8(0)
            .count(1)
            .u32(1)
            .i128(10)
            .i128(10)
            .u8(0)
            .bytes(&ordinal.to_le_bytes())
            .u8(0)
            .fixed(&[0; 32])
            .u16(1)
            .u128(99)
            .u8(0)
            .count(0)
            .count(usize::from(target.is_some()));
        if let Some((identity, digest)) = target {
            w.u128(identity).fixed(&digest).u8(1).u16(1);
        }
        w.u8(0).count(0).count(0);
        let length = w.buf.len();
        let proposal = hash_parts(crate::envelope::PROPOSAL_DIGEST_DOMAIN, &[&w.buf]);
        let digest = hash_parts(crate::envelope::ENTRY_DIGEST_DOMAIN, &[&proposal, &[]]);
        w.fixed(&proposal).fixed(&digest);
        let envelope = crate::envelope::envelope_of_entry(&w.buf, length, ordinal + 1, 0).unwrap();
        let identity = metadata::entry_info(&w.buf[..length], &envelope)
            .unwrap()
            .identity;
        (w.buf, length, envelope, identity)
    }

    #[test]
    fn long_reversal_ancestry_is_inspected_once_and_cached_edges_still_authenticate() {
        const COUNT: usize = 4096;
        let mut records = Vec::with_capacity(COUNT + 1);
        let mut target = None;
        for index in 0..COUNT {
            let record = lineage_record(index as u64, target);
            target = Some((record.3, record.2.record_digest));
            records.push(record);
        }
        // A new branch reaches a cached, genuine payload with the wrong
        // identity. Memoization must not make that edge authoritative.
        records.push(lineage_record(
            COUNT as u64,
            Some((records[0].3 ^ 1, records[0].2.record_digest)),
        ));
        let envelopes: Vec<_> = records.iter().map(|record| record.2.clone()).collect();
        let infos = records
            .iter()
            .enumerate()
            .map(|(index, record)| {
                (
                    index,
                    metadata::entry_info(&record.0[..record.1], &record.2).unwrap(),
                )
            })
            .collect();
        let by_digest = envelopes
            .iter()
            .enumerate()
            .map(|(index, record)| (record.record_digest, index))
            .collect();
        let schema = metadata::Schema::default();
        let certificate = Certificate {
            book: [3; 16],
            branch: [0; 16],
            known_at: (COUNT + 1) as u64,
            selection: crate::report::Selection::AsOf(0),
            journal_root: [0; 32],
            leaves: (COUNT + 1) as u64,
            output: &[],
            output_digest: [0; 32],
            digest: [0; 32],
        };
        let sources = Sources {
            certificate: &certificate,
            schema: &schema,
            envelopes: &envelopes,
            legs: &[],
            infos: &infos,
            by_digest: &by_digest,
            visible_migrations: &BTreeSet::new(),
            resolved: &BTreeSet::new(),
        };
        let mut lineage = Lineage::default();
        assert!(sources.income_included(COUNT - 1, &mut lineage).unwrap());
        // Revisit the entire source population in both orders, as comparative
        // columns do, while observing actual ancestry inspections rather than
        // timing or merely counting cache entries.
        for index in (0..COUNT).chain((0..COUNT).rev()) {
            assert!(sources.income_included(index, &mut lineage).unwrap());
        }
        let mut inspected = lineage.inspected.clone();
        inspected.sort_unstable();
        assert_eq!(inspected, (0..COUNT).collect::<Vec<_>>());
        assert_eq!(
            sources
                .income_included(COUNT, &mut lineage)
                .unwrap_err()
                .predicate,
            "accounting_lineage"
        );
        assert!(!lineage.classes.contains_key(&COUNT));
        assert_eq!(lineage.inspected.len(), COUNT + 1);
    }

    #[test]
    fn wide_statement_sum_cancels_before_narrowing_and_detects_real_overflow() {
        let mut sum = Sum::default();
        for _ in 0..4096 {
            sum.add(i128::MAX, false).unwrap();
        }
        assert!(sum.value().is_err());
        for _ in 0..4095 {
            sum.add(i128::MAX, true).unwrap();
        }
        assert_eq!(sum.value().unwrap(), i128::MAX);
        sum.add(i128::MAX, true).unwrap();
        sum.add(i128::MIN, false).unwrap();
        assert_eq!(sum.value().unwrap(), i128::MIN);
        sum.add(-1, false).unwrap();
        assert!(sum.value().is_err());
        sum.add(1, false).unwrap();
        assert_eq!(sum.value().unwrap(), i128::MIN);
        sum.add(i128::MIN, true).unwrap();
        assert_eq!(sum.value().unwrap(), 0);
    }
}
