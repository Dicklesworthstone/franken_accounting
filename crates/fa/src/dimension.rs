//! Dimension values (plan §4.1, bead fa-ficc): the cost centers,
//! departments, projects and other registered kinds a leg tags beside its
//! legal entity and party, each created by a journaled schema control.

use std::collections::BTreeSet;

use asupersync::fs::Vfs;
use fa_journal::refusal::{Refusal, code, exit};
use fa_policy::Capability;
use fa_registers::{DimensionFilter, TrialBalance};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, Outcome, TrialBalanceSelection};

pub use fa_journal::dimension::{
    DimensionCloseSpec, DimensionRequirementRecorded, DimensionRequirementSpec,
    DimensionValueRecorded, DimensionValueRow, DimensionValueSpec,
};

/// Each registered dimension's requiring accounts (dimensions with a value only).
pub type DimensionRequirements = Vec<(fa_model::DimensionKind, BTreeSet<VId>)>;

/// A trial balance over the legs tagged with one dimension value or one of
/// its descendants (`fa tb --dimension`).
#[derive(Clone, Debug)]
pub struct DimensionTrialBalance {
    pub trial_balance: TrialBalance,
    pub dimension: String,
    pub value: String,
    /// The value and its descendants by code, whose tagged legs it folds.
    pub values: Vec<String>,
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Create one value of a registered dimension under SchemaChange
    /// authority; an identical retry of the same key writes nothing.
    pub async fn create_dimension_value(
        &mut self,
        cx: &PurposeContexts,
        spec: &DimensionValueSpec,
        principal: VId,
        key: &[u8],
        capability: &Capability,
    ) -> Outcome<DimensionValueRecorded> {
        let description = self.seal_text(cx, &format!("add {} {}", spec.dimension, spec.code))?;
        Ok(fa_journal::dimension::create_dimension_value(
            &mut self.db,
            cx,
            &self.context,
            spec,
            principal,
            key,
            description,
            capability,
        )
        .await?)
    }

    /// Close one value from `spec.closed_on` under SchemaChange authority;
    /// a value already closed on that date writes nothing.
    pub async fn close_dimension_value(
        &mut self,
        cx: &PurposeContexts,
        spec: &DimensionCloseSpec,
        principal: VId,
        key: &[u8],
        capability: &Capability,
    ) -> Outcome<DimensionValueRecorded> {
        let description = self.seal_text(cx, &format!("close {} {}", spec.dimension, spec.code))?;
        Ok(fa_journal::dimension::close_dimension_value(
            &mut self.db,
            cx,
            &self.context,
            spec,
            principal,
            key,
            description,
            capability,
        )
        .await?)
    }

    /// Require, or stop requiring, a dimension on one account's legs under
    /// SchemaChange authority; an account already in (or out of) the
    /// requirement writes nothing.
    pub async fn record_dimension_requirement(
        &mut self,
        cx: &PurposeContexts,
        spec: &DimensionRequirementSpec,
        principal: VId,
        key: &[u8],
        capability: &Capability,
    ) -> Outcome<DimensionRequirementRecorded> {
        let verb = if spec.required {
            "require"
        } else {
            "stop requiring"
        };
        let description = self.seal_text(cx, &format!("{verb} {}", spec.dimension))?;
        Ok(fa_journal::dimension::record_dimension_requirement(
            &mut self.db,
            cx,
            &self.context,
            spec,
            principal,
            key,
            description,
            capability,
        )
        .await?)
    }

    /// Every registered kind's value at `known_at` (the head when `None`),
    /// and each dimension's requiring accounts, under current whole-book
    /// read authority, with the prefix they were read at.
    pub fn dimension_values(
        &self,
        cx: &PurposeContexts,
        known_at: Option<CommitSeq>,
        capability: &Capability,
    ) -> Outcome<(CommitSeq, Vec<DimensionValueRow>, DimensionRequirements)> {
        self.query(cx, |db, book| {
            let at = match crate::subledger::admitted_at(db, book, capability, known_at)? {
                Ok(at) => at,
                Err(refusal) => return Ok(Err(refusal)),
            };
            Ok(Ok((
                at,
                fa_journal::dimension::dimension_values_at(db, at)?,
                fa_journal::dimension::requirements_at(db, book, at)?,
            )))
        })
    }

    /// The trial balance `selection` selects over only the legs tagged with
    /// `dimension`'s `value` or a value under it, folded literally from the
    /// journal at `known_at` (the head when `None`) under current whole-book
    /// read authority: a filter crosses accounts and periods, so a scoped
    /// capability is refused, never filtered.
    pub fn dimension_trial_balance(
        &self,
        cx: &PurposeContexts,
        selection: &TrialBalanceSelection,
        known_at: Option<CommitSeq>,
        dimension: &str,
        value: &str,
        capability: &Capability,
    ) -> Outcome<DimensionTrialBalance> {
        self.query(cx, |db, book| {
            let at = match crate::subledger::admitted_at(db, book, capability, known_at)? {
                Ok(at) => at,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let Some(kind) = fa_model::dimension_kind(dimension) else {
                return Ok(Err(Refusal::new(
                    code::STRUCTURE,
                    exit::USAGE,
                    format!("`{dimension}` is not a registered dimension"),
                    "plan §4.1 (Dimension)",
                    format!("name one of: {}", fa_journal::dimension::kinds_listing()),
                )));
            };
            let values: Vec<DimensionValueRow> =
                fa_journal::dimension::dimension_values_at(db, at)?
                    .into_iter()
                    .filter(|row| row.dimension_id == kind.id)
                    .collect();
            if !values.iter().any(|row| row.spec.code == value) {
                return Ok(Err(Refusal::new(
                    code::STRUCTURE,
                    exit::USAGE,
                    format!(
                        "{dimension} `{value}` does not exist in this book at {}",
                        at.0
                    ),
                    "plan §4.1 (a dimension filter names a created value)",
                    format!("fa dimension list {dimension} lists its values"),
                )));
            }
            // The value and every value under it, by the parent each declares.
            let mut included: BTreeSet<&str> = BTreeSet::from([value]);
            loop {
                let before = included.len();
                for row in &values {
                    if row
                        .spec
                        .parent
                        .as_deref()
                        .is_some_and(|parent| included.contains(parent))
                    {
                        included.insert(row.spec.code.as_str());
                    }
                }
                if included.len() == before {
                    break;
                }
            }
            let filter = DimensionFilter {
                dimension: kind.id,
                values: values
                    .iter()
                    .filter(|row| included.contains(row.spec.code.as_str()))
                    .map(|row| row.vid)
                    .collect(),
            };
            let trial_balance = match selection {
                TrialBalanceSelection::Periods(periods) => {
                    fa_registers::trial_balance_tagged(db, book, periods, Some(at), &filter)?
                }
                TrialBalanceSelection::Activity(periods) => {
                    fa_registers::period_activity_tagged(db, book, periods, Some(at), &filter)?
                }
                TrialBalanceSelection::AsOf(day) => {
                    fa_registers::balance_as_of_tagged(db, book, *day, Some(at), &filter)?
                }
            };
            Ok(Ok(DimensionTrialBalance {
                trial_balance,
                dimension: dimension.to_string(),
                value: value.to_string(),
                values: included.into_iter().map(str::to_string).collect(),
            }))
        })
    }
}
