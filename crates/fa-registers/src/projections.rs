//! FA-INV-16, projections equal payloads (bead fa-avx): every derived `Leg`
//! vertex and its `HAS_LEG` and `POSTS_TO` edges equal what the entry's
//! payload derives, and were written in the entry's own commit.
//!
//! The check decodes every live `Entry` payload and re-derives, with the
//! same functions the kernel writes with, the entry's mirror properties
//! (`entry_mirrors`) and each leg's (`leg_mirrors`). It compares them with
//! the stored rows key by key, then requires, per leg ordinal, the `Leg`
//! vertex, the `HAS_LEG` edge from the entry carrying that ordinal, and the
//! `POSTS_TO` edge to the leg's account, each created in the entry's commit,
//! and no further `HAS_LEG` edge from the entry.
//!
//! Not checked here, by design: a leg's `applied` mirror, which moves with
//! settlement and is the open-item fold's (`verify_open_items`); properties
//! a kernel path adds beside an entry's mirrors (a control record's state),
//! which their own verifiers judge. Plan Appendix F also names `FOR` and
//! `IN_UNIT` edges; the kernel does not write them, so they are neither
//! checked nor claimed. A finding names the entry, the leg ordinal and what
//! differs. Nothing is repaired: the payload is the truth (FA-INV-02), and
//! its own correctness is FA-INV-01's.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::KernelError;
use fa_journal::genesis::BookContext;
use fa_journal::rows::{edge_id, leg_vid};
use fa_model::symbols::{label, property, relation};
use fa_model::{Entry, entry_mirrors, leg_mirrors};
use fgdb::Database;
use fgdb_delta_types::PropertyKeyId;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::RegisterError;

/// What [`verify_projections`] checked and found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionVerification {
    pub entries_checked: usize,
    pub legs_checked: usize,
    /// One line per departure, naming the entry, the leg and the property
    /// or edge; empty when every projection equals its payload.
    pub findings: Vec<String>,
}

impl ProjectionVerification {
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.findings.is_empty()
    }
}

fn compare(
    what: &str,
    stored: &[(PropertyKeyId, CanonicalScalar)],
    derived: &[(PropertyKeyId, CanonicalScalar)],
    findings: &mut Vec<String>,
) {
    let stored: BTreeMap<_, _> = stored.iter().map(|(k, v)| (k.0, v)).collect();
    for (key, value) in derived {
        match stored.get(&key.0) {
            Some(found) if *found == value => {}
            Some(found) => findings.push(format!(
                "{what}: property {} is {found:?}; the payload derives {value:?}",
                key.0
            )),
            None => findings.push(format!(
                "{what}: property {} is missing; the payload derives {value:?}",
                key.0
            )),
        }
    }
}

/// Present at the entry's sequence and not just before it.
fn written_at(at: bool, earlier: bool) -> bool {
    at && !earlier
}

/// Check every live entry's derived projections against its payload at the
/// head (see the module docs). Reads the whole book once.
pub fn verify_projections<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
) -> Result<ProjectionVerification, RegisterError> {
    let rows = db.vertices()?;
    let by_vid: BTreeMap<VId, _> = rows.iter().map(|r| (r.vid, r)).collect();
    let edges = db.edges()?;
    let mut has_leg: BTreeMap<VId, usize> = BTreeMap::new();
    for e in &edges {
        if e.entry.relation == relation::HAS_LEG && e.entry.retired_at.is_none() {
            *has_leg.entry(e.entry.src).or_default() += 1;
        }
    }
    let posts_to: BTreeSet<(VId, VId)> = edges
        .iter()
        .filter(|e| e.entry.relation == relation::POSTS_TO && e.entry.retired_at.is_none())
        .map(|e| (e.entry.src, e.entry.dst))
        .collect();
    let mut out = ProjectionVerification {
        entries_checked: 0,
        legs_checked: 0,
        findings: Vec::new(),
    };
    for row in &rows {
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let Some(CanonicalScalar::Bytes(payload)) = row
            .props
            .iter()
            .find(|(k, _)| *k == property::FA_PAYLOAD)
            .map(|(_, v)| v)
        else {
            out.findings
                .push(format!("entry {:032x}: no payload bytes", row.vid.0));
            continue;
        };
        let entry = Entry::decode(payload.as_slice()).map_err(KernelError::from)?;
        out.entries_checked += 1;
        let what = format!("entry {:032x}", row.vid.0);
        compare(
            &what,
            &row.props,
            &entry_mirrors(&entry).map_err(KernelError::from)?,
            &mut out.findings,
        );
        let legs = &entry.proposal.legs;
        let seq = row.created_at;
        let before = seq.0.checked_sub(1).map(CommitSeq);
        // A missing HAS_LEG edge is named per leg below; only an edge the
        // payload has no leg for is reported here, so one departure is one
        // finding.
        let stored_edges = has_leg.get(&row.vid).copied().unwrap_or(0);
        let named_edges = legs
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                u16::try_from(*i).is_ok_and(|ordinal| {
                    let lvid = leg_vid(row.vid, ordinal);
                    db.edge(edge_id(relation::HAS_LEG, row.vid, lvid))
                        .is_ok_and(|e| e.is_some_and(|e| e.entry.retired_at.is_none()))
                })
            })
            .count();
        if stored_edges > named_edges {
            out.findings.push(format!(
                "{what}: {} HAS_LEG edges beyond its {} inline legs",
                stored_edges - named_edges,
                legs.len()
            ));
        }
        for (i, leg) in legs.iter().enumerate() {
            let ordinal = u16::try_from(i)
                .map_err(|_| KernelError::Corrupt(format!("{what}: more than u16 legs")))?;
            out.legs_checked += 1;
            let leg_what = format!("{what} leg {ordinal}");
            let lvid = leg_vid(row.vid, ordinal);
            match by_vid.get(&lvid) {
                None => out.findings.push(format!("{leg_what}: no Leg vertex")),
                Some(leg_row) => {
                    if !leg_row.labels.contains(&label::LEG) {
                        out.findings
                            .push(format!("{leg_what}: the vertex is not labeled Leg"));
                    }
                    // Written in the entry's commit: present at its sequence
                    // and absent just before. A later settlement update of
                    // `applied` does not move this, so it is not judged by
                    // the row's current version.
                    if !written_at(
                        db.vertex_at(lvid, seq)?.is_some(),
                        match before {
                            Some(b) => db.vertex_at(lvid, b)?.is_some(),
                            None => false,
                        },
                    ) {
                        out.findings.push(format!(
                            "{leg_what}: not written in the entry's commit {}",
                            seq.0
                        ));
                    }
                    let derived =
                        leg_mirrors(leg, ordinal, entry.proposal.effective_date, &book.units)
                            .map_err(KernelError::from)?;
                    compare(&leg_what, &leg_row.props, &derived, &mut out.findings);
                }
            }
            match db.edge(edge_id(relation::HAS_LEG, row.vid, lvid))? {
                Some(edge) if edge.entry.retired_at.is_none() => {
                    let ordinal_prop = edge
                        .props
                        .iter()
                        .find(|(k, _)| *k == property::ORDINAL)
                        .map(|(_, v)| v);
                    if ordinal_prop != Some(&CanonicalScalar::Int(i64::from(ordinal))) {
                        out.findings
                            .push(format!("{leg_what}: HAS_LEG ordinal is {ordinal_prop:?}"));
                    }
                    let eid = edge_id(relation::HAS_LEG, row.vid, lvid);
                    if !written_at(
                        db.edge_at(eid, seq)?.is_some(),
                        match before {
                            Some(b) => db.edge_at(eid, b)?.is_some(),
                            None => false,
                        },
                    ) {
                        out.findings.push(format!(
                            "{leg_what}: HAS_LEG not written in the entry's commit {}",
                            seq.0
                        ));
                    }
                }
                _ => out
                    .findings
                    .push(format!("{leg_what}: no HAS_LEG edge from the entry")),
            }
            if !posts_to.contains(&(lvid, leg.account_ref)) {
                out.findings.push(format!(
                    "{leg_what}: no POSTS_TO edge to account {:032x}",
                    leg.account_ref.0
                ));
            }
        }
    }
    Ok(out)
}
