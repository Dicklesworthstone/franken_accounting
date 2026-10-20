//! Migration visibility is a projection of immutable run controls. A changed
//! state or FullDetail body must never suppress a finalized opening balance.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::symbols::{label, property};
use fa_model::{ControlKind, ControlPayload, Entry, EntryClass, EntryOrigin, Id128};
use fa_time::DateDay;
use fgdb::Database;
use fgdb_delta_types::{DeltaRow, ElementId};
use fgdb_types::{CommitSeq, VId};

use crate::genesis::BookContext;
use crate::refusal::KernelError;
use crate::rows::{bytes, prop, text};

use super::{RunState, kind, read_run};

struct Control {
    at: CommitSeq,
    kind: u8,
    body_digest: [u8; 32],
    tie_out_digest: [u8; 32],
    effective: DateDay,
}

fn corrupt(detail: impl core::fmt::Display) -> KernelError {
    KernelError::Corrupt(format!("migration visibility integrity: {detail}"))
}

/// Validate the run population at one retained prefix before applying
/// [`super::visible_at`]. Every run body and state must match its immutable
/// Open and optional Finalize/Abandon entries. Native history admits only
/// that terminal state write; body edits, relabeling, deletion and exact
/// restoration are refused. Later damage never poisons an earlier prefix.
///
/// Callers admit current whole-book authority and load complete native history
/// first. Entry immutability is checked separately by `verify_entry_history`;
/// this function supplies the run projection/history half of that proof.
pub fn verify_run_visibility_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    at: CommitSeq,
) -> Result<(), KernelError> {
    if at > db.frontier()? {
        return Err(corrupt("selected prefix exceeds the current head"));
    }
    let rows = db.vertices_at(at)?;
    let current: BTreeMap<_, _> = rows.iter().map(|row| (row.vid, row)).collect();
    let mut runs = BTreeSet::new();
    let mut controls: BTreeMap<VId, Vec<Control>> = BTreeMap::new();
    for row in &rows {
        if row.labels.contains(&label::MIGRATION_RUN) {
            runs.insert(row.vid);
        }
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = Entry::decode(&bytes(row, property::FA_PAYLOAD, "migration source entry")?)?;
        let proposal = &entry.proposal;
        if proposal.book_id != book.book_id || proposal.branch_id != Id128::TRUNK {
            return Err(corrupt("source entry belongs to another book or branch"));
        }
        if let EntryOrigin::Migration { run_ref, .. } = &proposal.origin {
            runs.insert(*run_ref);
            if proposal.class != EntryClass::MIGRATION {
                return Err(corrupt("a non-Migration entry claims migration provenance"));
            }
        }
        let Some(ControlPayload::MigrationControl {
            run_ref,
            kind,
            tie_out_digest,
        }) = &proposal.control
        else {
            continue;
        };
        let EntryOrigin::Control {
            control_kind: ControlKind::MIGRATION_RUN,
            spec_body_digest,
        } = &proposal.origin
        else {
            return Err(corrupt("run control has no canonical migration origin"));
        };
        if proposal.class != EntryClass::MIGRATION_CONTROL {
            return Err(corrupt("run control has the wrong entry class"));
        }
        runs.insert(*run_ref);
        controls.entry(*run_ref).or_default().push(Control {
            at: row.created_at,
            kind: *kind,
            body_digest: *spec_body_digest,
            tie_out_digest: *tie_out_digest,
            effective: proposal.effective_date,
        });
    }
    let mut expected = BTreeMap::new();
    for vid in runs {
        let run = read_run(db, vid, Some(at))?
            .ok_or_else(|| corrupt(format!("retained run {vid:?} is absent")))?;
        let row = current
            .get(&vid)
            .ok_or_else(|| corrupt("run has no selected row"))?;
        let digest = run.body.digest()?;
        if run.body.book_id != book.book_id
            || row.labels.as_slice() != [label::MIGRATION_RUN]
            || row.retired_at.is_some_and(|retired| retired <= at)
            || bytes(row, property::FA_DIGEST, "migration body digest")? != digest
            || bytes(row, property::BOOK_ID, "migration book")? != book.book_id.0
            || text(row, property::CODE, "migration run key")? != run.body.run_key
        {
            return Err(corrupt(format!(
                "run {vid:?} has a changed canonical mirror"
            )));
        }
        let mut ordered = controls.remove(&vid).unwrap_or_default();
        ordered.sort_by_key(|control| control.at);
        let mut state = None;
        let mut terminal_at = None;
        for control in ordered {
            if control.body_digest != digest || control.effective != run.body.opening_date {
                return Err(corrupt(format!(
                    "run {vid:?} body differs from its controls"
                )));
            }
            state = match (control.kind, state) {
                (kind::OPEN, None)
                    if control.at == run.opened_at && control.tie_out_digest == digest =>
                {
                    Some(RunState::Open)
                }
                (kind::FINALIZE, Some(RunState::Open)) if control.at > run.opened_at => {
                    terminal_at = Some(control.at);
                    Some(RunState::Finalized)
                }
                (kind::ABANDON, Some(RunState::Open)) if control.at > run.opened_at => {
                    terminal_at = Some(control.at);
                    Some(RunState::Abandoned)
                }
                _ => {
                    return Err(corrupt(format!(
                        "run {vid:?} has an invalid control lifecycle"
                    )));
                }
            };
        }
        if state != Some(run.state) {
            return Err(corrupt(format!(
                "run {vid:?} state differs from its controls"
            )));
        }
        expected.insert(vid, (run, terminal_at));
    }

    let mut births = BTreeMap::new();
    let mut terminal_writes = BTreeSet::new();
    let mut through = 0u64;
    for batch in db.delta_since(CommitSeq(0))? {
        let seq = batch.commit_seq();
        if seq > at {
            break;
        }
        if through.checked_add(1) != Some(seq.0) {
            return Err(corrupt(
                "complete native history from sequence zero is required",
            ));
        }
        // Native coordinates sort canonically, not causally: discover every
        // birth in a commit before examining its property/label rows.
        for coordinate in batch.coordinate_entries() {
            for delta in &coordinate.rows {
                if let DeltaRow::CreateVertex {
                    vid,
                    labels,
                    birth_ordinal,
                    ..
                } = delta
                    && labels.contains(&label::MIGRATION_RUN)
                    && (labels.as_slice() != [label::MIGRATION_RUN]
                        || births.insert(*vid, (seq, *birth_ordinal)).is_some())
                {
                    return Err(corrupt("invalid or repeated native run birth"));
                }
            }
        }
        for coordinate in batch.coordinate_entries() {
            for delta in &coordinate.rows {
                if let DeltaRow::LabelMembership {
                    vid,
                    label: changed,
                    after: true,
                    ..
                } = delta
                    && *changed == label::MIGRATION_RUN
                    && !births.contains_key(vid)
                {
                    return Err(corrupt("a later label cannot manufacture a run"));
                }
                let touched = match delta {
                    DeltaRow::Property {
                        elem: ElementId::Vertex(vid),
                        ..
                    }
                    | DeltaRow::LabelMembership { vid, .. }
                    | DeltaRow::DeleteVertex { vid, .. } => Some(vid),
                    _ => None,
                };
                let Some(vid) = touched else { continue };
                let Some((born, _)) = births.get(vid) else {
                    continue;
                };
                if *born == seq && !matches!(delta, DeltaRow::DeleteVertex { .. }) {
                    continue;
                }
                let Some((run, terminal_at)) = expected.get(vid) else {
                    return Err(corrupt("a native run was deleted or relabeled"));
                };
                let admitted = matches!(delta,
                    DeltaRow::Property {
                        property: changed,
                        before,
                        after,
                        ..
                    } if *changed == property::STATE
                        && *terminal_at == Some(seq)
                        && before.as_ref() == Some(&RunState::Open.scalar())
                        && after.as_ref() == Some(&run.state.scalar()));
                if !admitted || !terminal_writes.insert(*vid) {
                    return Err(corrupt(format!(
                        "run {vid:?} was modified outside its terminal control at {}; restoration cannot erase the mutation",
                        seq.0
                    )));
                }
            }
        }
        through = seq.0;
    }
    if through != at.0 || births.len() != expected.len() {
        return Err(corrupt(
            "run population or native history differs from the selected prefix",
        ));
    }
    for (vid, (run, terminal_at)) in expected {
        let row = current
            .get(&vid)
            .ok_or_else(|| corrupt("native run disappeared"))?;
        if births.get(&vid) != Some(&(run.opened_at, row.birth_ordinal))
            || terminal_at.is_some() != terminal_writes.contains(&vid)
        {
            return Err(corrupt(
                "run creation or terminal write lacks its native witness",
            ));
        }
        let born = db
            .vertex_at(vid, run.opened_at)?
            .ok_or_else(|| corrupt("run birth snapshot is unavailable"))?;
        // Only the terminal state write re-stamps the selected version, at
        // its control's sequence; an open run is still its birth version.
        if born.created_at != run.opened_at
            || row.created_at != terminal_at.unwrap_or(run.opened_at)
            || born.birth_ordinal != row.birth_ordinal
            || born.labels != row.labels
            || prop(&born, property::STATE) != Some(&RunState::Open.scalar())
            || born
                .props
                .iter()
                .filter(|(key, _)| *key != property::STATE)
                .collect::<Vec<_>>()
                != row
                    .props
                    .iter()
                    .filter(|(key, _)| *key != property::STATE)
                    .collect::<Vec<_>>()
        {
            return Err(corrupt(
                "run differs from its native creation apart from admitted state",
            ));
        }
    }
    Ok(())
}
