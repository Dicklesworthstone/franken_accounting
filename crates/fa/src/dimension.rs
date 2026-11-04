//! Dimension values (plan §4.1, bead fa-ficc): the cost centers,
//! departments, projects and other registered kinds a leg tags beside its
//! legal entity and party, each created by a journaled schema control.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_journal::genesis::BookContext;
use fa_journal::refusal::{Refusal, code, exit};
use fa_journal::rows::{book_root, bytes, prop, text};
use fa_model::symbols::{label, property, relation};
use fa_model::{ControlPayload, EntryClass, Id128, Writer};
use fa_policy::Capability;
use fa_registers::{DimensionFilter, TrialBalance};
use fgdb::Database;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, BookError, Outcome, TrialBalanceSelection};

pub use fa_journal::dimension::{
    DimensionCloseSpec, DimensionConstraintRecorded, DimensionConstraintRow,
    DimensionConstraintSpec, DimensionRequirementRecorded, DimensionRequirementSpec,
    DimensionValueRecorded, DimensionValueRow, DimensionValueSpec,
};

/// Each registered dimension's requiring accounts (dimensions with a value only).
pub type DimensionRequirements = Vec<(fa_model::DimensionKind, BTreeSet<VId>)>;

/// A trial balance over the legs tagged with one dimension value or one of
/// its descendants (`fa tb --dimension`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DimensionTrialBalance {
    pub trial_balance: TrialBalance,
    pub dimension: String,
    pub value: String,
    /// The value and its descendants by code, whose tagged legs it folds.
    pub values: Vec<String>,
}

impl DimensionTrialBalance {
    /// The certified output (`fa:dimension-trial-balance:v1`): the filter it
    /// folded, then the tagged trial balance's own canonical bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut w = Writer::new();
        w.fixed(crate::certificate::DIMENSION_TRIAL_BALANCE_OUTPUT_FORMAT.as_bytes())
            .str(&self.dimension)
            .str(&self.value)
            .list(&self.values, |w, value| {
                w.str(value);
            })
            .bytes(&self.trial_balance.canonical_bytes()?);
        w.finish()
    }

    /// Does `leg` carry one of the values this report folds?
    pub(crate) fn tags(&self, book: Id128, leg: &fa_model::LegPayload) -> bool {
        tags(&self.dimension, &self.values, book, leg)
    }
}

/// Exact functional carrying values for one historical dimension subtree.
/// Entity cells remain separate; an analytic slice need not balance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionalDimensionTrialBalance {
    pub trial_balance: crate::FunctionalTrialBalance,
    pub dimension: String,
    pub value: String,
    pub values: Vec<String>,
}

impl FunctionalDimensionTrialBalance {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut w = Writer::new();
        w.fixed(crate::certificate::FUNCTIONAL_DIMENSION_TRIAL_BALANCE_OUTPUT_FORMAT.as_bytes())
            .str(&self.dimension)
            .str(&self.value)
            .list(&self.values, |w, value| {
                w.str(value);
            })
            .bytes(&self.trial_balance.canonical_bytes()?);
        w.finish()
    }

    pub(crate) fn tags(&self, book: Id128, leg: &fa_model::LegPayload) -> bool {
        tags(&self.dimension, &self.values, book, leg)
    }
}

fn tags(dimension: &str, values: &[String], book: Id128, leg: &fa_model::LegPayload) -> bool {
    let Some(kind) = fa_model::dimension_kind(dimension) else {
        return false;
    };
    leg.dimension_set.iter().any(|(id, vid)| {
        *id == kind.id
            && values
                .iter()
                .any(|code| fa_model::dimension_value_vid(book, kind.code, code) == *vid)
    })
}

/// `value` and every value of `kind` under it at `at`, by the parent each
/// declares, as code → vertex; `None` when the book holds no such value then.
pub(crate) fn values_under<V: Vfs + Clone>(
    db: &Database<V>,
    kind: &fa_model::DimensionKind,
    value: &str,
    at: CommitSeq,
) -> Result<Option<BTreeMap<String, VId>>, BookError> {
    let values: Vec<DimensionValueRow> = fa_journal::dimension::dimension_values_at(db, at)?
        .into_iter()
        .filter(|row| row.dimension_id == kind.id)
        .collect();
    if !values.iter().any(|row| row.spec.code == value) {
        return Ok(None);
    }
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
    Ok(Some(
        values
            .iter()
            .filter(|row| included.contains(row.spec.code.as_str()))
            .map(|row| (row.spec.code.clone(), row.vid))
            .collect(),
    ))
}

/// Check v13 hierarchy projections against the original declaration/close
/// controls at this prefix. Callers first verify the immutable Entry history.
/// This proves the report's selected hierarchy, not every posting's original
/// dimension requirements or valid-time admission. Native v8 stays unchanged.
pub(crate) fn verify_functional_hierarchy<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    dimension: &str,
    at: CommitSeq,
) -> Result<(), BookError> {
    let Some(kind) = fa_model::dimension_kind(dimension) else {
        // The ordinary selector validator supplies the user-facing refusal.
        return Ok(());
    };
    let corrupt = |why: &str| {
        fa_journal::KernelError::Corrupt(format!(
            "functional dimension hierarchy differs from immutable controls: {why}"
        ))
    };
    let rows = db.vertices_at(at).map_err(fa_journal::KernelError::from)?;
    let by_id: BTreeMap<_, _> = rows.iter().map(|row| (row.vid, row)).collect();
    let mut controls: Vec<_> = rows
        .iter()
        .filter(|row| row.labels.contains(&label::ENTRY))
        .collect();
    controls.sort_by_key(|row| (row.created_at, row.birth_ordinal));
    let mut declared: BTreeMap<VId, (DimensionValueSpec, CommitSeq)> = BTreeMap::new();
    for row in controls {
        let entry = fa_journal::entry_storage::decode_at(db, row, at)?;
        let Some(ControlPayload::SchemaChange {
            kind: change,
            canonical_bytes,
        }) = &entry.proposal.control
        else {
            continue;
        };
        if !matches!(
            *change,
            fa_journal::dimension::SCHEMA_CHANGE_DIMENSION_VALUE
                | fa_journal::dimension::SCHEMA_CHANGE_DIMENSION_CLOSE
        ) {
            continue;
        }
        if entry.proposal.class != EntryClass::SCHEMA_CONTROL
            || entry.proposal.book_id != book.book_id
            || entry.proposal.branch_id != Id128::TRUNK
            || !entry.proposal.legs.is_empty()
        {
            return Err(corrupt("a declaration or close is not a same-book schema control").into());
        }
        if *change == fa_journal::dimension::SCHEMA_CHANGE_DIMENSION_VALUE {
            let spec = DimensionValueSpec::decode(canonical_bytes)?;
            if spec.dimension != kind.code {
                continue;
            }
            if spec.parent.as_ref().is_some_and(|parent| {
                !declared.contains_key(&fa_model::dimension_value_vid(
                    book.book_id,
                    kind.code,
                    parent,
                ))
            }) {
                return Err(
                    corrupt("a parent was not previously declared in this dimension").into(),
                );
            }
            let vid = fa_model::dimension_value_vid(book.book_id, kind.code, &spec.code);
            if declared.insert(vid, (spec, row.created_at)).is_some() {
                return Err(corrupt("a dimension value was declared more than once").into());
            }
        } else {
            let close = DimensionCloseSpec::decode(canonical_bytes)?;
            if close.dimension != kind.code {
                continue;
            }
            let vid = fa_model::dimension_value_vid(book.book_id, kind.code, &close.code);
            let Some((spec, projection_at)) = declared.get_mut(&vid) else {
                return Err(corrupt("a close precedes the value's declaration").into());
            };
            if spec.valid_from.is_some_and(|from| close.closed_on <= from)
                || spec.valid_to.is_some_and(|to| close.closed_on > to)
            {
                return Err(corrupt("a close empties or extends a validity window").into());
            }
            spec.valid_to = Some(close.closed_on);
            // A close updates the value's payload in this publication. The
            // substrate's created_at names that visible projection version,
            // not the original vertex birth. Its expected version must move
            // only with the authenticated close whose exact spec we replay.
            *projection_at = row.created_at;
        }
    }
    let in_book: BTreeSet<_> = db
        .in_neighbours_at(book_root(), relation::IN_BOOK, at)
        .map_err(fa_journal::KernelError::from)?
        .into_iter()
        .collect();
    for (vid, (spec, projection_at)) in &declared {
        let row = by_id
            .get(vid)
            .ok_or_else(|| corrupt("a declared value projection is missing"))?;
        let actual = DimensionValueRow::decode(row)?
            .ok_or_else(|| corrupt("a declared value projection is relabeled"))?;
        if actual.dimension_id != kind.id
            || actual.spec != *spec
            || actual.created_at != *projection_at
            || !in_book.contains(vid)
            || bytes(row, property::BOOK_ID, "dimension value book")? != book.book_id.0
            || text(row, property::CODE, "dimension value code")? != spec.code
        {
            return Err(corrupt(
                "a value projection changes its declaration, parent, close or book",
            )
            .into());
        }
    }
    for row in &rows {
        if row.labels.contains(&label::DIMENSION_VALUE)
            && prop(row, property::DIMENSION_ID)
                == Some(&fgdb_types::CanonicalScalar::Int(i64::from(kind.id)))
            && !declared.contains_key(&row.vid)
        {
            return Err(corrupt("a value projection has no immutable declaration").into());
        }
    }
    Ok(())
}

/// The trial balance `selection` selects at `at` over only the legs tagged
/// with `dimension`'s `value` or a value under it: the literal journal fold
/// both `fa tb --dimension` and its certificate's replay run.
pub(crate) fn trial_balance_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    selection: &TrialBalanceSelection,
    dimension: &str,
    value: &str,
    at: CommitSeq,
) -> Outcome<DimensionTrialBalance> {
    let (filter, values) = match filter_at(db, dimension, value, at)? {
        Ok(selected) => selected,
        Err(refusal) => return Ok(Err(refusal)),
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
        values,
    }))
}

fn filter_at<V: Vfs + Clone>(
    db: &Database<V>,
    dimension: &str,
    value: &str,
    at: CommitSeq,
) -> Outcome<(DimensionFilter, Vec<String>)> {
    let Some(kind) = fa_model::dimension_kind(dimension) else {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!("`{dimension}` is not a registered dimension"),
            "plan §4.1 (Dimension)",
            format!("name one of: {}", fa_journal::dimension::kinds_listing()),
        )));
    };
    let Some(values) = values_under(db, &kind, value, at)? else {
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
    };
    let filter = DimensionFilter {
        dimension: kind.id,
        values: values.values().copied().collect(),
    };
    Ok(Ok((filter, values.into_keys().collect())))
}

pub(crate) fn functional_trial_balance_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    selection: &TrialBalanceSelection,
    dimension: &str,
    value: &str,
    at: CommitSeq,
) -> Outcome<FunctionalDimensionTrialBalance> {
    verify_functional_hierarchy(db, book, dimension, at)?;
    let (filter, values) = match filter_at(db, dimension, value, at)? {
        Ok(selected) => selected,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let trial_balance = match crate::functional_trial_balance::report_tagged_at(
        db, book, selection, at, &filter,
    )? {
        Ok(report) => report,
        Err(refusal) => return Ok(Err(refusal)),
    };
    Ok(Ok(FunctionalDimensionTrialBalance {
        trial_balance,
        dimension: dimension.to_string(),
        value: value.to_string(),
        values,
    }))
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

    /// Replace one posting account's exact allowed and forbidden values for
    /// a dimension under SchemaChange authority. This does not change
    /// whether that dimension is required. `allowed: None` with no forbidden
    /// values clears the restriction, retaining its journaled history.
    pub async fn record_dimension_constraint(
        &mut self,
        cx: &PurposeContexts,
        spec: &DimensionConstraintSpec,
        principal: VId,
        key: &[u8],
        capability: &Capability,
    ) -> Outcome<DimensionConstraintRecorded> {
        if let Err(refusal) = self.admit_rea_change(cx, principal, capability)? {
            return Ok(Err(refusal));
        }
        let description = self.seal_text(
            cx,
            &format!("constrain {} on {:032x}", spec.dimension, spec.account.0),
        )?;
        Ok(fa_journal::dimension::record_dimension_constraint(
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

    /// Account-specific value policies at the requested prefix, including
    /// journaled clears, under current whole-book read authority.
    pub fn dimension_constraints(
        &self,
        cx: &PurposeContexts,
        known_at: Option<CommitSeq>,
        capability: &Capability,
    ) -> Outcome<(CommitSeq, Vec<DimensionConstraintRow>)> {
        self.query(cx, |db, book| {
            let at = match crate::subledger::admitted_at(db, book, capability, known_at)? {
                Ok(at) => at,
                Err(refusal) => return Ok(Err(refusal)),
            };
            Ok(Ok((
                at,
                fa_journal::dimension::constraints_at(db, book, at)?,
            )))
        })
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
            trial_balance_at(db, book, selection, dimension, value, at)
        })
    }

    /// Read committed functional carrying amounts in one dimension subtree,
    /// under current whole-book authority and at one retained prefix.
    pub async fn functional_dimension_trial_balance(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        selection: TrialBalanceSelection,
        known_at: Option<CommitSeq>,
        dimension: &str,
        value: &str,
    ) -> Outcome<FunctionalDimensionTrialBalance> {
        let at = match self
            .prepare_functional_report(cx, capability.holder(), capability, known_at, false)
            .await?
        {
            Ok(at) => at,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let result = self.query(cx, |db, book| {
            crate::certificate::context_at(db, book, at)?;
            fa_journal::entry_history::verify_entry_history(db, cx, book, Some(at))?;
            functional_trial_balance_at(db, book, &selection, dimension, value, at)
        })?;
        if let Err(refusal) =
            self.admit_functional_report(cx, capability.holder(), capability, Some(at), false)?
        {
            return Ok(Err(refusal));
        }
        Ok(result)
    }

    /// Certify the selected dimension hierarchy, exact functional cells and
    /// original Rate/law closure under current whole-book Read and Produce.
    pub async fn certify_functional_dimension_trial_balance(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        selection: TrialBalanceSelection,
        known_at: Option<CommitSeq>,
        dimension: &str,
        value: &str,
    ) -> Outcome<crate::CertifiedReport> {
        let at = match self
            .prepare_functional_report(cx, capability.holder(), capability, known_at, true)
            .await?
        {
            Ok(at) => at,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if !crate::functional_trial_balance::supported_selection(&selection) {
            return Ok(Err(crate::functional_trial_balance::invalid_selection()));
        }
        let result = self.certify_report(
            cx,
            crate::ReportSelection::FunctionalDimensionTrialBalance {
                selection,
                dimension: dimension.to_string(),
                value: value.to_string(),
            },
            Some(at),
        )?;
        if let Err(refusal) =
            self.admit_functional_report(cx, capability.holder(), capability, Some(at), true)?
        {
            return Ok(Err(refusal));
        }
        Ok(result)
    }

    /// Retain the original TimeEvidence brackets along with the dimension and
    /// functional valuation inputs. Portable export keeps its sequence-only law.
    pub async fn certify_functional_dimension_trial_balance_at_instant(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        selection: TrialBalanceSelection,
        requested_utc_ns: u64,
        dimension: &str,
        value: &str,
    ) -> Outcome<crate::CertifiedReport> {
        if let Err(refusal) = self
            .prepare_functional_report(cx, capability.holder(), capability, None, true)
            .await?
        {
            return Ok(Err(refusal));
        }
        if !crate::functional_trial_balance::supported_selection(&selection) {
            return Ok(Err(crate::functional_trial_balance::invalid_selection()));
        }
        let result = self.certify_report_at_instant(
            cx,
            crate::ReportSelection::FunctionalDimensionTrialBalance {
                selection,
                dimension: dimension.to_string(),
                value: value.to_string(),
            },
            requested_utc_ns,
        )?;
        if let Err(refusal) =
            self.admit_functional_report(cx, capability.holder(), capability, None, true)?
        {
            return Ok(Err(refusal));
        }
        Ok(result)
    }
}
