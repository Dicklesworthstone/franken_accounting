//! Dimension values (plan §4.1, bead fa-ficc): the cost centers,
//! departments, projects and other registered kinds a leg tags beside its
//! legal entity and party, each created by a journaled schema control.

use asupersync::fs::Vfs;
use fa_policy::Capability;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, Outcome};

pub use fa_journal::dimension::{DimensionValueRecorded, DimensionValueRow, DimensionValueSpec};

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

    /// Every registered kind's value at `known_at` (the head when `None`)
    /// under current whole-book read authority, with the prefix they were
    /// read at.
    pub fn dimension_values(
        &self,
        cx: &PurposeContexts,
        known_at: Option<CommitSeq>,
        capability: &Capability,
    ) -> Outcome<(CommitSeq, Vec<DimensionValueRow>)> {
        self.query(cx, |db, book| {
            let at = match crate::subledger::admitted_at(db, book, capability, known_at)? {
                Ok(at) => at,
                Err(refusal) => return Ok(Err(refusal)),
            };
            Ok(Ok((
                at,
                fa_journal::dimension::dimension_values_at(db, at)?,
            )))
        })
    }
}
