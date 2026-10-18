//! Complete native creation history for immutable Finding-family records.
//!
//! A live scan cannot detect a retired final review. Enumerate actual births,
//! including objects subsequently hidden by deletion or relabeling, and reject
//! every later mutation. This is retained-history integrity, not a signature or
//! a substitute for replaying the source procedure and validating review policy.

use std::collections::BTreeMap;

use asupersync::fs::Vfs;
use fa_model::symbols::label;
use fgdb::{Database, WriteTxnError};
use fgdb_delta_types::{DeltaRow, ElementId};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::KernelError;

/// Admission bound for the entire native Finding population, not a truncated
/// result size. The caller must load history from zero with scratch::ensure_history.
pub const MAX_FINDING_HISTORY_RECORDS: usize = 100_000;

pub fn finding_births<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    through: CommitSeq,
) -> Result<BTreeMap<VId, CommitSeq>, KernelError> {
    let query = cx.query();
    query.with_restriction(|| {
        let mut births = BTreeMap::new();
        let mut seen = 0_u64;
        for batch in db.delta_since(CommitSeq(0))? {
            let seq = batch.commit_seq();
            if seq > through { break; }
            query.checkpoint().map_err(WriteTxnError::Interrupted)?;
            if seen.checked_add(1) != Some(seq.0) {
                return Err(KernelError::Corrupt("finding integrity requires complete native history from sequence zero".into()));
            }
            // Coordinate order is canonical, not causal: discover every birth
            // before interpreting label membership rows in this same commit.
            for coordinate in batch.coordinate_entries() {
                for row in &coordinate.rows {
                    query.checkpoint().map_err(WriteTxnError::Interrupted)?;
                    if let DeltaRow::CreateVertex { vid, labels, .. } = row
                        && labels.contains(&label::FINDING)
                    {
                        if births.len() >= MAX_FINDING_HISTORY_RECORDS {
                            return Err(KernelError::Corrupt("finding history exceeds its complete-population bound; no partial result".into()));
                        }
                        if births.insert(*vid, seq).is_some() {
                            return Err(KernelError::Corrupt("a Finding identity has multiple native births".into()));
                        }
                    }
                }
            }
            for coordinate in batch.coordinate_entries() {
                for row in &coordinate.rows {
                    query.checkpoint().map_err(WriteTxnError::Interrupted)?;
                    if let DeltaRow::LabelMembership { vid, label: changed, after: true, .. } = row
                        && *changed == label::FINDING && !births.contains_key(vid)
                    {
                        return Err(KernelError::Corrupt("a later label cannot manufacture a Finding birth".into()));
                    }
                    let touched = match row {
                        DeltaRow::Property { elem: ElementId::Vertex(vid), .. }
                        | DeltaRow::LabelMembership { vid, .. }
                        | DeltaRow::DeleteVertex { vid, .. } => Some(vid),
                        _ => None,
                    };
                    if let Some(vid) = touched
                        && births.get(vid).is_some_and(|born| *born < seq)
                    {
                        return Err(KernelError::Corrupt(format!("Finding-family record {:032x} was modified at {}; restoring its bytes cannot erase that history", vid.0, seq.0)));
                    }
                }
            }
            seen = seq.0;
        }
        if seen != through.0 {
            return Err(KernelError::Corrupt("finding history ends before the requested native frontier".into()));
        }
        for (&vid, &birth) in &births {
            query.checkpoint().map_err(WriteTxnError::Interrupted)?;
            let row = db.vertex_at(vid, through)?.ok_or_else(|| KernelError::Corrupt("a Finding birth is missing at the checked frontier".into()))?;
            if row.created_at != birth || row.retired_at.is_some()
                || row.labels.as_slice() != [label::FINDING]
                || db.vertex_at(vid, birth)?.as_ref() != Some(&row)
            {
                return Err(KernelError::Corrupt("Finding birth and retained row disagree".into()));
            }
        }
        Ok(births)
    })
}
