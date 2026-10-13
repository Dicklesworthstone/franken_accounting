//! Exact statement bridges between two recorded frontiers (plan §8.3/§12.5).
//!
//! Both sides must ask the SAME accounting question: book, branch, definition,
//! period columns and native-unit universe. Only recorded time may differ.
//! This is not a restatement-case approval or an assertion that either prefix
//! was issued to anyone. The storage-facing API certifies/replays both sources.
//! The pure comparison checks structure, not journal membership or source truth.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::{Refusal, exit};
use fa_model::{Id128, Writer, domain_digest};
use fa_statements::{AccountMapping, Statement, StatementDefinition};
use fgdb_types::CommitSeq;

use crate::StatementSelection;

mod certificate;
pub use certificate::{CertifiedStatementDiff, StatementDiffCertificate, MAX_STATEMENT_DIFF_CERTIFICATE_BYTES};

pub const OUTPUT_FORMAT: &[u8] = b"fa:statement-diff:v1";
const SOURCE_DOMAIN: &[u8] = b"fa:statement-diff-source:v1";
const MAX_SOURCE_BYTES: usize = 32 * 1024 * 1024;
const MAX_UNITS: usize = 4096;
const MAX_COLUMNS: usize = 8;
const MAX_MAPPINGS: usize = 1_000_000;

/// Compare one definition/period selection at two recorded frontiers.
/// `after: None` resolves HEAD once, not separately for each source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementDiffRequest {
    pub selection: StatementSelection,
    pub before: CommitSeq,
    pub after: Option<CommitSeq>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementLineChange {
    pub code: String,
    pub label: String,
    pub unit_id: u32,
    pub before: Vec<i128>,
    pub after: Vec<i128>,
    /// Exact `after - before`, in the corresponding native unit and column.
    pub delta: Vec<i128>,
}

/// Includes zero-balance chart changes. Identity, not code or display order,
/// pairs the accounts. A changed mapping is not silently treated as a posting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementMappingChange {
    pub account_id: u128,
    pub before: Option<AccountMapping>,
    pub after: Option<AccountMapping>,
}

/// Immutable computed bridge, including both source reports for drilldown.
/// A bridge's unchanged monetary amounts do NOT imply unchanged chart coverage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementDiff {
    before: Statement,
    after: Statement,
    before_digest: [u8; 32],
    after_digest: [u8; 32],
    lines: Vec<StatementLineChange>,
    mapping_changes: Vec<StatementMappingChange>,
}

pub(crate) fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::statements::STATEMENT_INVALID,
        exit::REFUSAL,
        message,
        "plan §8.3 / §12.5 (same statement question at two recorded frontiers)",
        "use the same book, branch, definition, periods and native units on both sides, with before <= after; compare policy or presentation changes separately",
    )
}

fn bounded_source(statement: &Statement) -> Result<Vec<u8>, Refusal> {
    // Bound the complete serialization BEFORE materializing it. Public inputs
    // already own their strings; no length supplied by a producer is trusted.
    let mut bytes = 256usize;
    let mut charge = |length: usize| -> Result<(), Refusal> {
        bytes = bytes.checked_add(length).ok_or_else(|| invalid("statement source length overflow"))?;
        if bytes > MAX_SOURCE_BYTES {
            return Err(invalid("statement comparison source exceeds 32 MiB"));
        }
        Ok(())
    };
    charge(statement.definition_name.len())?;
    charge(statement.definition_bytes.len())?;
    for column in &statement.columns {
        charge(32 + column.label.len())?;
        for period in &column.periods {
            charge(4 + period.len())?;
        }
    }
    for line in &statement.lines {
        charge(16 + line.code.len() + line.label.len())?;
        charge(line.amounts.len().checked_mul(16).ok_or_else(|| invalid("statement amount count overflow"))?)?;
    }
    for mapping in &statement.mappings {
        charge(32 + mapping.account.code.len() + mapping.account.name.len() + mapping.line_code.len())?;
    }
    let encoded = statement.canonical_bytes().map_err(|e| invalid(e.to_string()))?;
    if encoded.len() > MAX_SOURCE_BYTES {
        return Err(invalid("statement comparison source exceeds 32 MiB"));
    }
    Ok(encoded)
}

/// Validate shape against the definition, including the complete ordered
/// line/unit product and the mapping metadata. Source completeness still needs
/// the historical chart/journal; it cannot be inferred from these rows alone.
fn validate_source(statement: &Statement) -> Result<Vec<u32>, Refusal> {
    if statement.columns.is_empty() || statement.columns.len() > MAX_COLUMNS
        || statement.mappings.len() > MAX_MAPPINGS || statement.lines.len() > 64 * MAX_UNITS
    {
        return Err(invalid("statement source cardinality exceeds the comparison contract"));
    }
    let definition = StatementDefinition::decode(&statement.definition_bytes)
        .map_err(|e| invalid(e.to_string()))?;
    if definition.name() != statement.definition_name
        || definition.version() != statement.definition_version
        || definition.digest().map_err(|e| invalid(e.to_string()))? != statement.definition_digest
        || definition.canonical_bytes().map_err(|e| invalid(e.to_string()))? != statement.definition_bytes
    {
        return Err(invalid("statement definition bytes and identity disagree"));
    }
    let mut labels = BTreeSet::new();
    for column in &statement.columns {
        if column.label.is_empty() || column.label.len() > 128 || !labels.insert(&column.label)
            || column.periods.is_empty() || column.periods.len() > 256
            || column.periods.iter().any(|p| p.is_empty() || p.len() > 128)
            || column.periods.windows(2).any(|p| p[0] >= p[1])
            || column.effective_from.is_some_and(|start| start > column.effective_through)
        {
            return Err(invalid("statement source has an invalid or noncanonical column"));
        }
        match (definition.basis(), column.effective_from) {
            (fa_statements::Basis::Stock, None) | (fa_statements::Basis::Activity, Some(_)) => {}
            _ => return Err(invalid("statement column confuses stock and activity")),
        }
    }
    let first_code = &definition.lines()[0].code;
    let units: Vec<u32> = statement.lines.iter().take_while(|l| &l.code == first_code)
        .map(|l| l.unit_id).collect();
    if units.is_empty() || units.len() > MAX_UNITS || units.windows(2).any(|u| u[0] >= u[1])
        || statement.lines.len() != definition.lines().len() * units.len()
    {
        return Err(invalid("statement source is not a complete canonical line/unit table"));
    }
    for (definition_line, actual) in definition.lines().iter().zip(statement.lines.chunks(units.len())) {
        for (line, unit) in actual.iter().zip(&units) {
            if line.code != definition_line.code || line.label != definition_line.label
                || line.unit_id != *unit || line.amounts.len() != statement.columns.len()
            {
                return Err(invalid("statement source line identity, unit, order or column count differs"));
            }
        }
    }
    let accounts: Vec<_> = statement.mappings.iter().map(|m| m.account.clone()).collect();
    let mappings = fa_statements::map_accounts(&definition, &accounts)
        .map_err(|e| invalid(e.to_string()))?;
    if mappings != statement.mappings {
        return Err(invalid("statement source mappings disagree with its definition or canonical order"));
    }
    Ok(units)
}

impl StatementDiff {
    /// Compare already obtained reports. This is a pure arithmetic operation,
    /// NOT certificate verification. Use `AsyncBook::certify_statement_diff`
    /// and `replay_statement_diff` to bind it to retained journal history.
    pub fn between(before: Statement, after: Statement) -> Result<Self, Refusal> {
        let before_units = validate_source(&before)?;
        let after_units = validate_source(&after)?;
        if before.book_id != after.book_id || before.branch_id != after.branch_id
            || before.known_at > after.known_at
            || before.definition_bytes != after.definition_bytes
            || before.columns != after.columns || before_units != after_units
            || (before.known_at == after.known_at && before != after)
        {
            return Err(invalid("statement comparison changes more than the recorded frontier"));
        }
        let before_digest = domain_digest(SOURCE_DOMAIN, &[&bounded_source(&before)?]);
        let after_digest = domain_digest(SOURCE_DOMAIN, &[&bounded_source(&after)?]);
        let mut lines = Vec::with_capacity(before.lines.len());
        for (old, new) in before.lines.iter().zip(&after.lines) {
            let mut delta = Vec::with_capacity(old.amounts.len());
            for (column, (old_amount, new_amount)) in old.amounts.iter().zip(&new.amounts).enumerate() {
                delta.push(new_amount.checked_sub(*old_amount).ok_or_else(|| invalid(format!(
                    "delta for line `{}`, column `{}`, unit {} exceeds i128; neither source is rounded or truncated",
                    old.code, before.columns[column].label, old.unit_id,
                )))?);
            }
            lines.push(StatementLineChange {
                code: old.code.clone(), label: old.label.clone(), unit_id: old.unit_id,
                before: old.amounts.clone(), after: new.amounts.clone(), delta,
            });
        }
        let old: BTreeMap<_, _> = before.mappings.iter().map(|m| (m.account.id, m)).collect();
        let new: BTreeMap<_, _> = after.mappings.iter().map(|m| (m.account.id, m)).collect();
        let ids: BTreeSet<_> = old.keys().chain(new.keys()).copied().collect();
        let mapping_changes = ids.into_iter().filter_map(|id| {
            let a = old.get(&id).copied();
            let b = new.get(&id).copied();
            (a != b).then(|| StatementMappingChange {
                account_id: id, before: a.cloned(), after: b.cloned(),
            })
        }).collect();
        Ok(Self { before, after, before_digest, after_digest, lines, mapping_changes })
    }

    #[must_use]
    pub fn before(&self) -> &Statement { &self.before }
    #[must_use]
    pub fn after(&self) -> &Statement { &self.after }
    #[must_use]
    pub fn lines(&self) -> &[StatementLineChange] { &self.lines }
    #[must_use]
    pub fn mapping_changes(&self) -> &[StatementMappingChange] { &self.mapping_changes }
    #[must_use]
    pub fn amounts_changed(&self) -> bool {
        self.lines.iter().any(|line| line.delta.iter().any(|amount| *amount != 0))
    }
    #[must_use]
    pub fn is_unchanged(&self) -> bool {
        !self.amounts_changed() && self.mapping_changes.is_empty()
    }
    #[must_use]
    pub fn book_id(&self) -> Id128 { self.before.book_id }

    /// Commit source identities, every amount (including unchanged/zero lines)
    /// and every chart change. Subtotals are not added together as though they
    /// were disjoint balances. Definitions and complete sources travel in the
    /// composed certificate; their hashes here prevent output substitution.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        fn mapping(w: &mut Writer, m: &AccountMapping) {
            w.u128(m.account.id).str(&m.account.code).str(&m.account.name)
                .u8(m.account.account_type).bool(m.account.is_leaf).str(&m.line_code);
        }
        let mut w = Writer::new();
        w.bytes(OUTPUT_FORMAT).fixed(&self.book_id().0).fixed(&self.before.branch_id.0)
            .u64(self.before.known_at).u64(self.after.known_at)
            .fixed(&self.before_digest).fixed(&self.after_digest)
            .fixed(&self.before.definition_digest)
            .list(&self.before.columns, |w, c| {
                w.str(&c.label).list(&c.periods, |w, p| { w.str(p); })
                    .opt(c.effective_from.as_ref(), |w, d| { w.i32(d.0); })
                    .i32(c.effective_through.0);
            })
            .list(&self.lines, |w, line| {
                w.str(&line.code).str(&line.label).u32(line.unit_id)
                    .list(&line.before, |w, v| { w.i128(*v); })
                    .list(&line.after, |w, v| { w.i128(*v); })
                    .list(&line.delta, |w, v| { w.i128(*v); });
            })
            .list(&self.mapping_changes, |w, change| {
                w.u128(change.account_id)
                    .opt(change.before.as_ref(), mapping)
                    .opt(change.after.as_ref(), mapping);
            });
        w.finish()
    }
}

#[cfg(test)]
mod tests;
