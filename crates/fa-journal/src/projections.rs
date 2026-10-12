//! Leg projections of the immutable entry payload (plan §4.2, FA-INV-16).
//!
//! The posting kernel and the scheduled-reversal path stage the same complete
//! topology. Verification derives the expected legs and edges from decoded
//! payloads at one committed prefix; it never uses HAS_LEG to discover the
//! journal or an entry's legs. Staged and abandoned migration entries and
//! pending holds still have projections and are checked too.
//!
//! The mutable application counter belongs to the open-item fold and is
//! checked by `verify_open_items`. This module checks the immutable leg
//! mirrors and HAS_LEG / POSTS_TO / FOR / IN_UNIT topology. It does not
//! rebuild projections or claim payload completeness or immutability.

use std::collections::{BTreeMap, BTreeSet};

use fa_model::symbols::{label, property, relation};
use fa_model::{Entry, Id128, leg_mirrors, unit_vid};
use fgdb::{Database, WriteBatch};
use fgdb_delta_types::{PropertyKeyId, RelationId};
use fgdb_types::{CanonicalScalar, CommitSeq, EId, VId};

use crate::genesis::BookContext;
use crate::refusal::KernelError;
use crate::rows::{bytes, edge_id, leg_vid, mantissa_scalar, prop};

/// A complete comparison of the stored leg projections with a journal prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionVerification {
    pub known_at: CommitSeq,
    pub entries_checked: usize,
    pub legs_checked: usize,
    /// The number of expected projection edges derived from the payloads.
    pub edges_checked: usize,
    /// Deterministically ordered discrepancies, naming their entry and leg
    /// whenever an authoritative owner exists.
    pub drift: Vec<String>,
}

impl ProjectionVerification {
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.drift.is_empty()
    }
}

/// Stage every leg and its four projection relations. All callers publish
/// these batches in the same transaction as the immutable entry vertex.
pub(crate) fn stage_legs(
    has_leg: &mut WriteBatch,
    entry_vid: VId,
    entry: &Entry,
    book: &BookContext,
) -> Result<[WriteBatch; 3], KernelError> {
    let mut posts_to = WriteBatch::new(relation::POSTS_TO);
    let mut in_unit = WriteBatch::new(relation::IN_UNIT);
    let mut dimensions = WriteBatch::new(relation::FOR);
    for (i, leg) in entry.proposal.legs.iter().enumerate() {
        let ordinal =
            u16::try_from(i).map_err(|_| KernelError::Corrupt("more than u16 legs".into()))?;
        let lvid = leg_vid(entry_vid, ordinal);
        let mut mirrors = leg_mirrors(leg, ordinal, entry.proposal.effective_date, &book.units)?;
        mirrors.push((property::APPLIED, mantissa_scalar("applied", 0)?));
        has_leg.create_vertex(lvid, vec![label::LEG], mirrors);
        has_leg.add_edge(
            edge_id(relation::HAS_LEG, entry_vid, lvid),
            entry_vid,
            lvid,
            vec![(property::ORDINAL, CanonicalScalar::Int(i64::from(ordinal)))],
        );
        posts_to.add_edge(
            edge_id(relation::POSTS_TO, lvid, leg.account_ref),
            lvid,
            leg.account_ref,
            vec![],
        );
        let unit = book
            .units
            .get(leg.amount.unit)
            .ok_or_else(|| KernelError::Corrupt("unregistered projected unit".into()))?;
        let uvid = unit_vid(book.book_id, &format!("{}@v{}", unit.code, unit.version));
        in_unit.add_edge(edge_id(relation::IN_UNIT, lvid, uvid), lvid, uvid, vec![]);
        for (dimension, value) in &leg.dimension_set {
            dimensions.add_edge(
                edge_id(relation::FOR, lvid, *value),
                lvid,
                *value,
                vec![(
                    property::DIMENSION_ID,
                    CanonicalScalar::Int(i64::from(*dimension)),
                )],
            );
        }
    }
    Ok([posts_to, in_unit, dimensions])
}

const LEG_PROPERTIES: [PropertyKeyId; 7] = [
    property::FA_EFFECTIVE_DAY,
    property::SIDE,
    property::ACCOUNT_REF,
    property::UNIT_ID,
    property::AMOUNT,
    property::AMOUNT_BYTES,
    property::ORDINAL,
];

struct ExpectedEdge {
    relation: RelationId,
    src: VId,
    dst: VId,
    props: Vec<(PropertyKeyId, CanonicalScalar)>,
    entry: VId,
    ordinal: u16,
}

fn expect_edge(
    edges: &mut BTreeMap<EId, ExpectedEdge>,
    topology: (RelationId, VId, VId),
    owner: (VId, u16),
    props: Vec<(PropertyKeyId, CanonicalScalar)>,
) -> Result<(), KernelError> {
    let (relation, src, dst) = topology;
    let (entry, ordinal) = owner;
    let eid = edge_id(relation, src, dst);
    if edges
        .insert(
            eid,
            ExpectedEdge {
                relation,
                src,
                dst,
                props,
                entry,
                ordinal,
            },
        )
        .is_some()
    {
        return Err(KernelError::Corrupt(format!(
            "payloads require duplicate projection edge {:032x}",
            eid.0
        )));
    }
    Ok(())
}

fn is_projection(relation: RelationId) -> bool {
    matches!(
        relation,
        relation::HAS_LEG | relation::POSTS_TO | relation::FOR | relation::IN_UNIT
    )
}

fn relation_name(relation: RelationId) -> &'static str {
    relation::ALL
        .iter()
        .find(|(_, id)| *id == relation.0)
        .map_or("unknown", |(name, _)| *name)
}

fn property_name(property: PropertyKeyId) -> &'static str {
    property::ALL
        .iter()
        .find(|(_, id)| *id == property.0)
        .map_or("unknown", |(name, _)| *name)
}

/// Verify the immutable leg mirrors and exact projection edge sets at one
/// committed snapshot. A damaged mirror, missing leg or edge, unexpected
/// projection, malformed entry payload, or foreign coordinate produces a
/// red report. Storage/snapshot failures remain typed kernel errors.
///
/// Entry payloads supply the expected set independently of every projection.
/// In particular, deleting HAS_LEG cannot hide a leg, and changing a leg's
/// account or unit cannot change its expected edge. Both absent and surplus
/// `amount_bytes` are checked, including the Decimal-to-Bytes fallback.
/// The application counters and settlement edges have their own fold checker.
pub fn verify_projections<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    known_at: Option<CommitSeq>,
) -> Result<ProjectionVerification, KernelError> {
    let known_at = known_at.unwrap_or(db.frontier()?);
    let rows = db.vertices_at(known_at)?;
    let stored_edges = db.edges_at(known_at)?;
    let vertices: BTreeMap<_, _> = rows.iter().map(|row| (row.vid, row)).collect();
    let mut expected_legs = BTreeSet::new();
    let mut expected_edges = BTreeMap::new();
    let mut report = ProjectionVerification {
        known_at,
        entries_checked: 0,
        legs_checked: 0,
        edges_checked: 0,
        drift: Vec::new(),
    };
    for row in rows.iter().filter(|row| row.labels.contains(&label::ENTRY)) {
        report.entries_checked += 1;
        let entry = match bytes(row, property::FA_PAYLOAD, "entry._fa_payload")
            .and_then(|payload| Entry::decode(&payload).map_err(KernelError::from))
        {
            Ok(entry) => entry,
            Err(error) => {
                report.drift.push(format!(
                    "entry {:032x}: cannot verify projections without its canonical payload: {error}",
                    row.vid.0
                ));
                continue;
            }
        };
        if entry.proposal.book_id != book.book_id || entry.proposal.branch_id != Id128::TRUNK {
            report.drift.push(format!(
                "entry {:032x}: payload coordinate does not belong to this trunk book",
                row.vid.0
            ));
            continue;
        }
        for (i, leg) in entry.proposal.legs.iter().enumerate() {
            let ordinal =
                u16::try_from(i).map_err(|_| KernelError::Corrupt("more than u16 legs".into()))?;
            let lvid = leg_vid(row.vid, ordinal);
            let owner = (row.vid, ordinal);
            let description = format!("entry {:032x} leg {ordinal} ({:032x})", row.vid.0, lvid.0);
            report.legs_checked += 1;
            if !expected_legs.insert(lvid) {
                return Err(KernelError::Corrupt(format!(
                    "{description}: duplicate derived leg identity"
                )));
            }
            let mirrors =
                match leg_mirrors(leg, ordinal, entry.proposal.effective_date, &book.units) {
                    Ok(mirrors) => mirrors,
                    Err(error) => {
                        report.drift.push(format!(
                            "{description}: cannot derive canonical mirrors: {error}"
                        ));
                        continue;
                    }
                };
            match vertices.get(&lvid) {
                None => report
                    .drift
                    .push(format!("{description}: missing Leg vertex")),
                Some(stored) => {
                    if stored.labels != vec![label::LEG] {
                        report.drift.push(format!(
                            "{description}: labels differ from the Leg projection"
                        ));
                    }
                    for key in LEG_PROPERTIES {
                        let expected = mirrors
                            .iter()
                            .find(|(candidate, _)| *candidate == key)
                            .map(|(_, value)| value);
                        if prop(stored, key) != expected {
                            report.drift.push(format!(
                                "{description}: {} mirror differs from the payload",
                                property_name(key)
                            ));
                        }
                    }
                }
            }
            expect_edge(
                &mut expected_edges,
                (relation::HAS_LEG, row.vid, lvid),
                owner,
                vec![(property::ORDINAL, CanonicalScalar::Int(i64::from(ordinal)))],
            )?;
            expect_edge(
                &mut expected_edges,
                (relation::POSTS_TO, lvid, leg.account_ref),
                owner,
                vec![],
            )?;
            if !vertices
                .get(&leg.account_ref)
                .is_some_and(|target| target.labels.contains(&label::ACCOUNT))
            {
                report.drift.push(format!(
                    "{description}: POSTS_TO target {:032x} is not an Account",
                    leg.account_ref.0
                ));
            }
            let Some(unit) = book.units.get(leg.amount.unit) else {
                report
                    .drift
                    .push(format!("{description}: unit is not registered"));
                continue;
            };
            let uvid = unit_vid(book.book_id, &format!("{}@v{}", unit.code, unit.version));
            expect_edge(
                &mut expected_edges,
                (relation::IN_UNIT, lvid, uvid),
                owner,
                vec![],
            )?;
            if !vertices
                .get(&uvid)
                .is_some_and(|target| target.labels.contains(&label::UNIT))
            {
                report.drift.push(format!(
                    "{description}: IN_UNIT target {:032x} is not a Unit",
                    uvid.0
                ));
            }
            for (dimension, value) in &leg.dimension_set {
                expect_edge(
                    &mut expected_edges,
                    (relation::FOR, lvid, *value),
                    owner,
                    vec![(
                        property::DIMENSION_ID,
                        CanonicalScalar::Int(i64::from(*dimension)),
                    )],
                )?;
                if !vertices
                    .get(value)
                    .is_some_and(|target| target.labels.contains(&label::DIMENSION_VALUE))
                {
                    report.drift.push(format!(
                        "{description}: FOR target {:032x} is not a DimensionValue",
                        value.0
                    ));
                }
            }
        }
    }
    for row in rows.iter().filter(|row| row.labels.contains(&label::LEG)) {
        if !expected_legs.contains(&row.vid) {
            report.drift.push(format!(
                "leg {:032x}: no decoded entry payload owns this projection",
                row.vid.0
            ));
        }
    }
    report.edges_checked = expected_edges.len();
    for stored in &stored_edges {
        if !is_projection(stored.entry.relation) {
            continue;
        }
        let eid = stored.entry.eid;
        match expected_edges.remove(&eid) {
            None => report.drift.push(format!(
                "unexpected {} edge {:032x} from {:032x} to {:032x}",
                relation_name(stored.entry.relation),
                eid.0,
                stored.entry.src.0,
                stored.entry.dst.0
            )),
            Some(expected) => {
                if stored.entry.relation != expected.relation
                    || stored.entry.src != expected.src
                    || stored.entry.dst != expected.dst
                    || stored.props != expected.props
                {
                    report.drift.push(format!(
                        "entry {:032x} leg {}: {} edge {:032x} has different endpoints or properties",
                        expected.entry.0,
                        expected.ordinal,
                        relation_name(expected.relation),
                        eid.0
                    ));
                }
            }
        }
    }
    for (eid, expected) in expected_edges {
        report.drift.push(format!(
            "entry {:032x} leg {}: missing {} edge {:032x}",
            expected.entry.0,
            expected.ordinal,
            relation_name(expected.relation),
            eid.0
        ));
    }
    report.drift.sort();
    Ok(report)
}
