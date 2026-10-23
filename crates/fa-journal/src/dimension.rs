//! Dimension values (plan §4.1 `Dimension` / `DimensionValue`, bead
//! fa-ficc): the cost centers, departments, projects and other registered
//! kinds (`fa_model::DIMENSION_KINDS`) a leg tags in its `dimension_set`,
//! beside its legal entity and its party.
//!
//! A value is created by an immutable schema control whose canonical body
//! is the value's whole declaration: its kind, code, name, parent within the
//! same dimension, and valid time `[valid_from, valid_to)`. The same
//! transaction materializes its `DimensionValue` vertex (and, for a kind's
//! first value, the `Dimension` vertex), carrying that body as its payload,
//! with a `CHILD_OF` edge to its parent. The posting kernel judges a leg's
//! value by one point read of that vertex, never a scan (plan §5.1): it must
//! be a value of the leg's dimension, effective on the entry's date.

use asupersync::fs::Vfs;
use fa_model::rea::{MAX_REA_CODE_BYTES, MAX_REA_NAME_BYTES};
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ControlPayload, DIMENSION_KINDS, DimensionKind, Entry, EntryPayload, Erasable, LegPayload,
    Reader, Writer, dimension_kind, dimension_kind_of, dimension_value_vid, dimension_vid,
    entry_mirrors, entry_vid,
};
use fa_policy::Capability;
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::chart::{admit_schema_change, schema_control_proposal};
use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{book_root, bytes, edge_id, prop, scalar_bytes, scalar_text};

pub const SCHEMA_CHANGE_DIMENSION_VALUE: u16 = 17;
const FORMAT: &[u8] = b"fa:dimension-value:v1";

/// One dimension value's declaration, the canonical body of its control.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DimensionValueSpec {
    /// A registered kind's code (`cost_center`, `department`, ...).
    pub dimension: String,
    pub code: String,
    pub name: String,
    /// A value of the same dimension this one rolls up to.
    pub parent: Option<String>,
    /// Effective from this date (inclusive); always, when absent.
    pub valid_from: Option<DateDay>,
    /// Effective before this date (exclusive); always after, when absent.
    pub valid_to: Option<DateDay>,
}

impl DimensionValueSpec {
    pub fn encode(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut w = Writer::new();
        w.fixed(FORMAT)
            .str(&self.dimension)
            .str(&self.code)
            .str(&self.name)
            .opt(self.parent.as_ref(), |w, parent| {
                w.str(parent);
            })
            .opt(self.valid_from.as_ref(), |w, day| {
                w.i32(day.0);
            })
            .opt(self.valid_to.as_ref(), |w, day| {
                w.i32(day.0);
            });
        w.finish()
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(encoded);
        let bad = |error: fa_model::DecodeError| corrupt(error.to_string());
        if r.fixed::<{ FORMAT.len() }>("dimension value format")
            .map_err(bad)?
            .as_slice()
            != FORMAT
        {
            return Err(corrupt("unknown dimension value encoding"));
        }
        let dimension = r
            .str(MAX_REA_CODE_BYTES, "dimension")
            .map_err(bad)?
            .to_string();
        let code = r
            .str(MAX_REA_CODE_BYTES, "dimension value code")
            .map_err(bad)?
            .to_string();
        let name = r
            .str(MAX_REA_NAME_BYTES, "dimension value name")
            .map_err(bad)?
            .to_string();
        let parent = r
            .opt("dimension value parent", |r| {
                Ok(r.str(MAX_REA_CODE_BYTES, "dimension value parent")?
                    .to_string())
            })
            .map_err(bad)?;
        let valid_from = r
            .opt("dimension value valid_from", |r| {
                Ok(DateDay(r.i32("dimension value valid_from")?))
            })
            .map_err(bad)?;
        let valid_to = r
            .opt("dimension value valid_to", |r| {
                Ok(DateDay(r.i32("dimension value valid_to")?))
            })
            .map_err(bad)?;
        r.finish().map_err(bad)?;
        let spec = Self {
            dimension,
            code,
            name,
            parent,
            valid_from,
            valid_to,
        };
        if let Some(problem) = spec.problem() {
            return Err(corrupt(problem));
        }
        Ok(spec)
    }

    /// What makes this declaration inadmissible, if anything.
    #[must_use]
    pub fn problem(&self) -> Option<String> {
        let code_ok = |code: &str| {
            !code.is_empty()
                && code.len() <= MAX_REA_CODE_BYTES
                && code.chars().all(|c| c.is_ascii_graphic())
        };
        if dimension_kind(&self.dimension).is_none() {
            return Some(format!(
                "`{}` is not a registered dimension; the dimensions are {}",
                self.dimension,
                kinds_listing()
            ));
        }
        if !code_ok(&self.code) {
            return Some(format!(
                "dimension value code `{}` must be 1..={MAX_REA_CODE_BYTES} printable ASCII bytes without spaces",
                self.code
            ));
        }
        if self.name.trim().is_empty() || self.name.len() > MAX_REA_NAME_BYTES {
            return Some(format!(
                "dimension value name must be 1..={MAX_REA_NAME_BYTES} bytes and not blank"
            ));
        }
        if let Some(parent) = &self.parent {
            if !code_ok(parent) {
                return Some(format!("parent code `{parent}` is not a value code"));
            }
            if *parent == self.code {
                return Some(format!("value `{}` cannot be its own parent", self.code));
            }
        }
        if let (Some(from), Some(to)) = (self.valid_from, self.valid_to)
            && to <= from
        {
            return Some(format!(
                "valid_to {} must be after valid_from {}",
                to.render(),
                from.render()
            ));
        }
        None
    }

    /// Half-open `[valid_from, valid_to)` effectivity.
    #[must_use]
    pub fn is_effective_at(&self, day: DateDay) -> bool {
        self.valid_from.is_none_or(|from| day >= from) && self.valid_to.is_none_or(|to| day < to)
    }
}

/// A dimension value as the book holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DimensionValueRow {
    pub vid: VId,
    /// The dimension id legs carry it under.
    pub dimension_id: u32,
    pub spec: DimensionValueSpec,
    pub created_at: CommitSeq,
}

impl DimensionValueRow {
    /// Decode a registered kind's DimensionValue vertex; `None` for any other
    /// vertex, including the legal-entity and party values.
    pub fn decode(row: &VertexRow) -> Result<Option<Self>, KernelError> {
        if !row.labels.contains(&label::DIMENSION_VALUE) {
            return Ok(None);
        }
        let Some(CanonicalScalar::Int(id)) = prop(row, property::DIMENSION_ID) else {
            return Err(corrupt("a dimension value has no dimension id"));
        };
        let Some(kind) = u32::try_from(*id).ok().and_then(dimension_kind_of) else {
            return Ok(None);
        };
        let spec = DimensionValueSpec::decode(&bytes(
            row,
            property::FA_PAYLOAD,
            "dimension value payload",
        )?)?;
        if spec.dimension != kind.code {
            return Err(corrupt(format!(
                "value `{}` declares dimension `{}` but carries id {}",
                spec.code, spec.dimension, kind.id
            )));
        }
        Ok(Some(Self {
            vid: row.vid,
            dimension_id: kind.id,
            spec,
            created_at: row.created_at,
        }))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DimensionValueRecorded {
    pub value: DimensionValueRow,
    pub control_entry: VId,
    /// True when nothing was written: an identical retry of the same key.
    pub already_recorded: bool,
}

fn corrupt(message: impl Into<String>) -> KernelError {
    KernelError::Corrupt(format!("dimension value: {}", message.into()))
}

/// The registered dimensions, for messages.
#[must_use]
pub fn kinds_listing() -> String {
    DIMENSION_KINDS
        .iter()
        .map(|kind| kind.code)
        .collect::<Vec<_>>()
        .join(", ")
}

fn usage_refusal(message: String, fix: impl Into<String>) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §4.1 (Dimension / DimensionValue)",
        fix,
    )
}

/// The sealed control `create_dimension_value` journals for `spec`: one
/// book-scoped SchemaControl with no legs, under the idempotency `key`.
pub fn dimension_value_control(
    book: &BookContext,
    spec: &DimensionValueSpec,
    principal: VId,
    key: &[u8],
    description: Erasable<String>,
) -> Result<(EntryPayload, Entry), KernelError> {
    let proposal = schema_control_proposal(
        book,
        SCHEMA_CHANGE_DIMENSION_VALUE,
        spec.encode()?,
        principal,
        DateDay(0),
        key,
        description,
    );
    let entry = proposal.clone().seal(Vec::new(), None)?;
    Ok((proposal, entry))
}

/// Every registered kind's value the book holds at `at`, by dimension id
/// then code. Reads the book's structure vertices, never its entries.
pub fn dimension_values_at<V: Vfs + Clone>(
    db: &Database<V>,
    at: CommitSeq,
) -> Result<Vec<DimensionValueRow>, KernelError> {
    if at > db.frontier()? {
        return Err(corrupt("known-at is beyond the book head"));
    }
    let mut values = Vec::new();
    for vid in db.in_neighbours_at(book_root(), relation::IN_BOOK, at)? {
        let Some(row) = db.vertex_at(vid, at)? else {
            continue;
        };
        if let Some(value) = DimensionValueRow::decode(&row)? {
            values.push(value);
        }
    }
    values.sort_by(|a, b| (a.dimension_id, &a.spec.code).cmp(&(b.dimension_id, &b.spec.code)));
    Ok(values)
}

/// Create one value of a registered dimension under current whole-book
/// SchemaChange authority (plan §4.1). Its code is unique in its dimension,
/// and a parent must already be a value of the same dimension. An identical
/// retry of the same key writes nothing.
#[allow(clippy::too_many_arguments)]
pub async fn create_dimension_value<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    spec: &DimensionValueSpec,
    principal: VId,
    key: &[u8],
    description: Erasable<String>,
    capability: &Capability,
) -> Outcome<DimensionValueRecorded> {
    if let Some(refusal) = admit_schema_change(db, book, principal, capability)? {
        return Ok(Err(refusal));
    }
    if let Some(problem) = spec.problem() {
        return Ok(Err(usage_refusal(
            problem,
            "fa dimension add <dimension> <code> --name <name> [--parent <code>] [--from YYYY-MM-DD] [--to YYYY-MM-DD]",
        )));
    }
    let Some(kind) = dimension_kind(&spec.dimension) else {
        return Err(corrupt("an admitted spec names no registered kind"));
    };
    let (proposal, entry) = dimension_value_control(book, spec, principal, key, description)?;
    let evid = entry_vid(book.book_id, &principal.0.to_le_bytes(), key);
    let dim_vid = dimension_vid(book.book_id, kind.code);
    let value_vid = dimension_value_vid(book.book_id, kind.code, &spec.code);
    let mut txn = db.begin(&ctx.txn())?;
    if let Err(refusal) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let _epoch = crate::policy::epoch_witness(&txn, db)?;
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        let stored = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "entry payload")?)?;
        if stored.proposal.semantic_digest(&book.seal_key)?
            != proposal.semantic_digest(&book.seal_key)?
        {
            return Ok(Err(Refusal::new(
                code::IDEMPOTENCY_CONFLICT,
                exit::CONFLICT,
                "this idempotency key already records different content",
                "FA-INV-09",
                "retry the original dimension value or use a new key",
            )));
        }
        let Some(ControlPayload::SchemaChange {
            kind: SCHEMA_CHANGE_DIMENSION_VALUE,
            canonical_bytes,
        }) = &stored.proposal.control
        else {
            return Err(corrupt("the retried key records another control"));
        };
        return Ok(Ok(DimensionValueRecorded {
            value: DimensionValueRow {
                vid: value_vid,
                dimension_id: kind.id,
                spec: DimensionValueSpec::decode(canonical_bytes)?,
                created_at: row.created_at,
            },
            control_entry: evid,
            already_recorded: true,
        }));
    }
    if txn.vertex(db, value_vid)?.is_some() {
        txn.abort();
        return Ok(Err(usage_refusal(
            format!("{} `{}` already exists in this book", kind.code, spec.code),
            format!(
                "fa dimension list {} lists its values; use another code",
                kind.code
            ),
        )));
    }
    let parent_vid = match &spec.parent {
        None => None,
        Some(parent) => {
            let vid = dimension_value_vid(book.book_id, kind.code, parent);
            let row = txn.vertex(db, vid)?;
            if !row
                .as_ref()
                .and_then(|row| DimensionValueRow::decode(row).transpose())
                .transpose()?
                .is_some_and(|value| value.dimension_id == kind.id)
            {
                txn.abort();
                return Ok(Err(usage_refusal(
                    format!(
                        "parent {} `{parent}` does not exist in this book",
                        kind.code
                    ),
                    format!(
                        "create the parent first (fa dimension add {} {parent} --name <name>)",
                        kind.code
                    ),
                )));
            }
            Some(vid)
        }
    };
    let need_dimension = txn.vertex(db, dim_vid)?.is_none();
    let root = book_root();
    let book_id = scalar_bytes("book_id", book.book_id.0.to_vec())?;
    let dimension_id = CanonicalScalar::Int(i64::from(kind.id));
    let mut in_book = WriteBatch::new(relation::IN_BOOK);
    in_book.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    if need_dimension {
        let mut props = vec![
            (property::BOOK_ID, book_id.clone()),
            (property::CODE, scalar_text("code", kind.code)?),
            (property::NAME, scalar_text("name", kind.code)?),
            (property::DIMENSION_ID, dimension_id.clone()),
            (property::DIMENSION_KIND, CanonicalScalar::Int(kind.tag)),
        ];
        props.sort_by_key(|(k, _)| k.0);
        in_book.create_vertex(dim_vid, vec![label::DIMENSION], props);
        in_book.add_edge(
            edge_id(relation::IN_BOOK, dim_vid, root),
            dim_vid,
            root,
            vec![],
        );
    }
    let mut props = vec![
        (property::BOOK_ID, book_id),
        (property::CODE, scalar_text("code", &spec.code)?),
        (property::DIMENSION_ID, dimension_id),
        (
            property::FA_PAYLOAD,
            scalar_bytes("dimension_value._fa_payload", spec.encode()?)?,
        ),
    ];
    props.sort_by_key(|(k, _)| k.0);
    in_book.create_vertex(value_vid, vec![label::DIMENSION_VALUE], props);
    in_book.add_edge(
        edge_id(relation::IN_BOOK, value_vid, root),
        value_vid,
        root,
        vec![],
    );
    let mut batches = vec![in_book];
    if let Some(parent) = parent_vid {
        let mut child_of = WriteBatch::new(relation::CHILD_OF);
        child_of.add_edge(
            edge_id(relation::CHILD_OF, value_vid, parent),
            value_vid,
            parent,
            vec![],
        );
        batches.push(child_of);
    }
    if let Err(error) = txn.write_ordered(db, batches) {
        txn.abort();
        return Err(error.into());
    }
    if let Err(denial) = fa_policy::current(capability, db.frontier()?) {
        txn.abort();
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(recorded_at) => Ok(Ok(DimensionValueRecorded {
            value: DimensionValueRow {
                vid: value_vid,
                dimension_id: kind.id,
                spec: spec.clone(),
                created_at: recorded_at,
            },
            control_entry: evid,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("a dimension value witness changed: {detail}"),
                "FG-LAW-FCW-01",
                "retry against the current frontier",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            "a concurrent dimension value collided on a derived identity",
            "FA-INV-09",
            "fa dimension list shows the recorded value; retry its original key",
        ))),
        Err(error) => Err(error.into()),
    }
}

/// Judge leg `i`'s registered-kind dimension values at `effective_date` by
/// point reads: each must be a value of the dimension the leg names it
/// under, effective on that date. The legal entity and the party are judged
/// by their own laws.
pub(crate) fn admit_leg_dimensions(
    leg: &LegPayload,
    i: usize,
    effective_date: DateDay,
    mut read_vertex: impl FnMut(VId) -> Result<Option<VertexRow>, KernelError>,
) -> Result<Option<Refusal>, KernelError> {
    for (dimension_id, value) in &leg.dimension_set {
        let Some(kind) = dimension_kind_of(*dimension_id) else {
            continue;
        };
        let decoded = match read_vertex(*value)? {
            Some(row) => DimensionValueRow::decode(&row)?,
            None => None,
        };
        let Some(row) = decoded.filter(|row| row.dimension_id == kind.id) else {
            return Ok(Some(unknown_value(kind, *value, i)));
        };
        if !row.spec.is_effective_at(effective_date) {
            let window = match (row.spec.valid_from, row.spec.valid_to) {
                (Some(from), Some(to)) => format!("from {} before {}", from.render(), to.render()),
                (Some(from), None) => format!("from {}", from.render()),
                (None, Some(to)) => format!("before {}", to.render()),
                (None, None) => "always".into(),
            };
            return Ok(Some(
                Refusal::new(
                    code::DIMENSION_NOT_EFFECTIVE,
                    exit::REFUSAL,
                    format!(
                        "leg {i}: {} `{}` is effective {window}, not on {}",
                        kind.code,
                        row.spec.code,
                        effective_date.render()
                    ),
                    "plan §4.1 (DimensionValue valid-time effectivity)",
                    format!(
                        "tag the leg with a {} value effective on {} (fa dimension list {}), or date the entry inside {window}",
                        kind.code,
                        effective_date.render(),
                        kind.code
                    ),
                )
                .at("leg", i)
                .at(kind.code, row.spec.code.clone()),
            ));
        }
    }
    Ok(None)
}

fn unknown_value(kind: DimensionKind, value: VId, i: usize) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        format!(
            "leg {i} names {} value {:032x}, which does not exist in this book",
            kind.code, value.0
        ),
        "plan §4.1 (a leg's DimensionSet references created values)",
        format!(
            "fa dimension list {0} lists them; fa dimension add {0} <code> --name <name> creates one",
            kind.code
        ),
    )
    .at("leg", i)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> DimensionValueSpec {
        DimensionValueSpec {
            dimension: "cost_center".into(),
            code: "CC10".into(),
            name: "Operations".into(),
            parent: Some("CC".into()),
            valid_from: Some(DateDay::parse("2026-01-01").unwrap()),
            valid_to: Some(DateDay::parse("2027-01-01").unwrap()),
        }
    }

    #[test]
    fn a_declaration_round_trips_and_is_effective_in_its_half_open_window() {
        let spec = spec();
        let decoded = DimensionValueSpec::decode(&spec.encode().unwrap()).unwrap();
        assert_eq!(decoded, spec);
        assert!(spec.is_effective_at(DateDay::parse("2026-01-01").unwrap()));
        assert!(spec.is_effective_at(DateDay::parse("2026-12-31").unwrap()));
        assert!(!spec.is_effective_at(DateDay::parse("2025-12-31").unwrap()));
        assert!(!spec.is_effective_at(DateDay::parse("2027-01-01").unwrap()));
        let open = DimensionValueSpec {
            parent: None,
            valid_from: None,
            valid_to: None,
            ..spec
        };
        assert_eq!(
            DimensionValueSpec::decode(&open.encode().unwrap()).unwrap(),
            open
        );
        assert!(open.is_effective_at(DateDay(0)));
    }

    #[test]
    fn inadmissible_declarations_name_their_problem() {
        let planted = [
            DimensionValueSpec {
                dimension: "cost_centre".into(),
                ..spec()
            },
            DimensionValueSpec {
                code: "CC 10".into(),
                ..spec()
            },
            DimensionValueSpec {
                code: String::new(),
                ..spec()
            },
            DimensionValueSpec {
                name: "  ".into(),
                ..spec()
            },
            DimensionValueSpec {
                parent: Some("CC10".into()),
                ..spec()
            },
            DimensionValueSpec {
                valid_to: Some(DateDay::parse("2026-01-01").unwrap()),
                ..spec()
            },
        ];
        for spec in planted {
            assert!(spec.problem().is_some(), "{spec:?}");
            assert!(DimensionValueSpec::decode(&spec.encode().unwrap()).is_err());
        }
        assert!(spec().problem().is_none());
    }
}
