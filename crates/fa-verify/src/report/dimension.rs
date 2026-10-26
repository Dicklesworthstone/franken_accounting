//! Dimension membership reconstructed from authenticated SchemaControl records.
//!
//! A declaration fixes a value's parent for its lifetime. Closing a value only
//! shortens its posting-validity window: closed and future-effective descendants
//! remain part of the historical rollup, matching the native tagged fold. The
//! caller applies controls only through the report's recorded-time frontier.
//!
//! This module reconstructs report selection; it does not prove that every
//! posting satisfied dimension requirements or effectivity at admission.

use std::collections::{BTreeMap, BTreeSet};

use super::{ReportError, failed, text};
use crate::blake3::hash_parts;
use crate::codec::{Reader, Reason, Writer};
use crate::envelope::{MAX_ENVELOPE_LIST, MAX_RECORD_BYTES, skip_erasable};

const VALUE_FORMAT: &[u8] = b"fa:dimension-value:v1";
const CLOSE_FORMAT: &[u8] = b"fa:dimension-close:v1";
const MAX_CODE_BYTES: usize = 64;
const MAX_NAME_BYTES: usize = 256;
const MAX_DIMENSIONS_PER_LEG: usize = 64;
const MAX_SETTLES_PER_LEG: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Selection {
    pub dimension: String,
    pub value: String,
}

/// The requested dimension and every selected value, independently rebuilt
/// from the complete authenticated control history at the report coordinate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDimensionSelection {
    pub dimension: String,
    pub value: String,
    /// The requested value and its descendants, in strictly ascending order.
    /// A closed value remains included so its historical postings are retained.
    pub values: Vec<String>,
}

struct Value {
    parent: Option<String>,
    valid_from: Option<i32>,
    valid_to: Option<i32>,
}

#[derive(Default)]
pub(super) struct History {
    book: Option<[u8; 16]>,
    values: BTreeMap<String, BTreeMap<String, Value>>,
}

/// The registered dimension identifiers, independently encoded from the model
/// contract. Legal entity (1) and party (12) are separate report selectors.
fn dimension_id(code: &str) -> Option<u32> {
    match code {
        "cost_center" => Some(2),
        "department" => Some(3),
        "project" => Some(4),
        "product" => Some(5),
        "region" => Some(6),
        "fund" => Some(7),
        "grant" => Some(8),
        "segment" => Some(9),
        _ => None,
    }
}

fn code<'a>(r: &mut Reader<'a>, field: &'static str) -> Result<&'a str, ReportError> {
    let value = text(r, MAX_CODE_BYTES, field)?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(failed(
            "dimension_history",
            format!("{field} must be nonempty printable ASCII without spaces"),
        ));
    }
    Ok(value)
}

impl History {
    /// Apply a journaled declaration (17) or close (19). Other schema controls
    /// do not define hierarchy membership and are left to their own verifier.
    pub(super) fn apply(
        &mut self,
        kind: u16,
        body: &[u8],
        book: &[u8; 16],
    ) -> Result<(), ReportError> {
        if !matches!(kind, 17 | 19) {
            return Ok(());
        }
        if self.book.is_some_and(|known| known != *book) {
            return Err(failed(
                "dimension_history",
                "dimension controls cross book namespaces",
            ));
        }
        let mut r = Reader::new(body);
        if kind == 17 {
            if r.fixed::<{ VALUE_FORMAT.len() }>("dimension.format")?
                .as_slice()
                != VALUE_FORMAT
            {
                return Err(failed(
                    "dimension_history",
                    "unknown value declaration format",
                ));
            }
            let dimension = code(&mut r, "dimension.kind")?.to_string();
            let value = code(&mut r, "dimension.code")?.to_string();
            let name = text(&mut r, MAX_NAME_BYTES, "dimension.name")?;
            if dimension_id(&dimension).is_none() || name.trim().is_empty() {
                return Err(failed(
                    "dimension_history",
                    "a value requires a registered dimension and a nonblank name",
                ));
            }
            let parent = if r.present("dimension.parent")? {
                Some(code(&mut r, "dimension.parent")?.to_string())
            } else {
                None
            };
            let valid_from = if r.present("dimension.valid_from")? {
                Some(r.i32("dimension.valid_from")?)
            } else {
                None
            };
            let valid_to = if r.present("dimension.valid_to")? {
                Some(r.i32("dimension.valid_to")?)
            } else {
                None
            };
            r.finish("dimension declaration")?;
            if parent.as_deref() == Some(value.as_str())
                || matches!((valid_from, valid_to), (Some(from), Some(to)) if from >= to)
            {
                return Err(failed(
                    "dimension_history",
                    "a value cannot parent itself or have an empty validity window",
                ));
            }
            let values = self.values.get(&dimension);
            if values.is_some_and(|known| known.contains_key(&value)) {
                return Err(failed(
                    "dimension_history",
                    "a dimension value is declared more than once",
                ));
            }
            if parent
                .as_ref()
                .is_some_and(|parent| values.is_none_or(|known| !known.contains_key(parent)))
            {
                return Err(failed(
                    "dimension_history",
                    "a parent must already be declared in the same dimension",
                ));
            }
            self.values.entry(dimension).or_default().insert(
                value,
                Value {
                    parent,
                    valid_from,
                    valid_to,
                },
            );
            self.book = Some(*book);
        } else {
            if r.fixed::<{ CLOSE_FORMAT.len() }>("dimension.close_format")?
                .as_slice()
                != CLOSE_FORMAT
            {
                return Err(failed(
                    "dimension_history",
                    "unknown dimension close format",
                ));
            }
            let dimension = code(&mut r, "dimension.close_kind")?;
            let value = code(&mut r, "dimension.close_code")?;
            let closed_on = r.i32("dimension.closed_on")?;
            r.finish("dimension close")?;
            let current = self
                .values
                .get_mut(dimension)
                .and_then(|values| values.get_mut(value))
                .ok_or_else(|| failed("dimension_history", "a close names an undeclared value"))?;
            if current.valid_from.is_some_and(|from| closed_on <= from)
                || current.valid_to.is_some_and(|to| closed_on > to)
            {
                return Err(failed(
                    "dimension_history",
                    "a close cannot empty or extend a value's validity window",
                ));
            }
            current.valid_to = Some(closed_on);
        }
        Ok(())
    }

    pub(super) fn select(
        &self,
        selection: &Selection,
    ) -> Result<VerifiedDimensionSelection, ReportError> {
        let values = self.values.get(&selection.dimension).ok_or_else(|| {
            failed(
                "dimension_history",
                "the requested dimension has no declared values",
            )
        })?;
        if !values.contains_key(&selection.value) {
            return Err(failed(
                "dimension_history",
                "the requested value is not declared at the report coordinate",
            ));
        }
        let mut children: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for (value, declaration) in values {
            if let Some(parent) = &declaration.parent {
                children.entry(parent).or_default().push(value);
            }
        }
        let mut included = BTreeSet::new();
        let mut pending = vec![selection.value.as_str()];
        while let Some(value) = pending.pop() {
            if included.insert(value)
                && let Some(descendants) = children.get(value)
            {
                pending.extend(descendants.iter().copied());
            }
        }
        Ok(VerifiedDimensionSelection {
            dimension: selection.dimension.clone(),
            value: selection.value.clone(),
            values: included.into_iter().map(str::to_string).collect(),
        })
    }
}

fn value_vid(book: &[u8; 16], dimension: &str, value: &str) -> u128 {
    let mut framed = Writer::default();
    framed
        .bytes(book)
        .bytes(dimension.as_bytes())
        .bytes(value.as_bytes());
    let digest = hash_parts(b"fa:vid:dimension-value:v1", &[&framed.buf]);
    let mut low = [0; 16];
    low.copy_from_slice(&digest[..16]);
    u128::from_le_bytes(low)
}

/// Resolve the authenticated value hierarchy once per report. Reusing these
/// identities avoids deriving every descendant again for every journal entry.
pub(super) struct LegFilter {
    book: [u8; 16],
    dimension: u32,
    values: BTreeSet<u128>,
}

impl LegFilter {
    pub(super) fn new(
        book: &[u8; 16],
        selection: &VerifiedDimensionSelection,
    ) -> Result<Self, ReportError> {
        let dimension = dimension_id(&selection.dimension)
            .ok_or_else(|| failed("dimension_history", "unknown selected dimension"))?;
        let values = selection
            .values
            .iter()
            .map(|value| value_vid(book, &selection.dimension, value))
            .collect();
        Ok(Self {
            book: *book,
            dimension,
            values,
        })
    }
}

/// A mask in canonical payload leg order. The caller has authenticated the
/// complete proposal and independently decoded its monetary legs; neither
/// projection mirrors nor the report's claimed output supplies these tags.
pub(super) fn selected_legs(proposal: &[u8], filter: &LegFilter) -> Result<Vec<bool>, ReportError> {
    let mut r = Reader::new(proposal);
    let major = r.u16("entry.schema_major")?;
    if major != 1 {
        return Err(failed("dimension_tags", "unsupported entry schema major"));
    }
    r.u16("entry.schema_minor")?;
    if r.fixed::<16>("entry.book")? != filter.book {
        return Err(failed(
            "dimension_tags",
            "entry tags belong to another book",
        ));
    }
    r.fixed::<16>("entry.branch")?;
    r.u16("entry.class")?;
    r.i32("entry.effective")?;
    if r.present("entry.document_date")? {
        r.i32("entry.document_date")?;
    }
    skip_erasable(&mut r, "entry.description")?;
    if r.present("entry.period")? {
        r.bytes(MAX_RECORD_BYTES, "entry.calendar")?;
        r.bytes(MAX_RECORD_BYTES, "entry.period")?;
    }
    let count = r.count(MAX_ENVELOPE_LIST, 47, "entry.legs")?;
    let mut mask = Vec::with_capacity(count);
    for _ in 0..count {
        let side = r.u8("leg.side")?;
        if side > 1 {
            return Err(r.error("leg.side", Reason::BadTag(side)).into());
        }
        r.u128("leg.account")?;
        r.fixed::<20>("leg.amount")?;
        if r.present("leg.base_amount")? {
            r.fixed::<20>("leg.base_amount")?;
        }
        let count = r.count(MAX_DIMENSIONS_PER_LEG, 20, "leg.dimension_set")?;
        let mut previous = None;
        let mut matches = false;
        for _ in 0..count {
            let kind = r.u32("dimension.id")?;
            let value = r.u128("dimension.value")?;
            if previous.is_some_and(|previous| previous >= kind) {
                return Err(r.error("leg.dimension_set", Reason::Unsorted).into());
            }
            previous = Some(kind);
            matches |= kind == filter.dimension && filter.values.contains(&value);
        }
        mask.push(matches);
        if r.present("leg.memo")? {
            skip_erasable(&mut r, "leg.memo")?;
        }
        let count = r.count(MAX_SETTLES_PER_LEG, 70, "leg.settles")?;
        for _ in 0..count {
            r.fixed::<70>("leg.settles")?;
        }
    }
    Ok(mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOK: [u8; 16] = [3; 16];

    fn declaration(
        dimension: &str,
        value: &str,
        parent: Option<&str>,
        from: Option<i32>,
        to: Option<i32>,
    ) -> Vec<u8> {
        let mut w = Writer::default();
        w.fixed(VALUE_FORMAT)
            .bytes(dimension.as_bytes())
            .bytes(value.as_bytes())
            .bytes(value.as_bytes())
            .u8(u8::from(parent.is_some()));
        if let Some(parent) = parent {
            w.bytes(parent.as_bytes());
        }
        for day in [from, to] {
            w.u8(u8::from(day.is_some()));
            if let Some(day) = day {
                w.i32(day);
            }
        }
        w.buf
    }

    fn close(value: &str, day: i32) -> Vec<u8> {
        let mut w = Writer::default();
        w.fixed(CLOSE_FORMAT)
            .bytes(b"cost_center")
            .bytes(value.as_bytes())
            .i32(day);
        w.buf
    }

    #[test]
    fn validity_windows_do_not_erase_historical_descendants() {
        let mut history = History::default();
        for (value, parent, from, to) in [
            ("root", None, None, None),
            ("future", Some("root"), Some(100), None),
            ("closed", Some("root"), Some(0), Some(20)),
            ("grandchild", Some("closed"), None, None),
        ] {
            history
                .apply(
                    17,
                    &declaration("cost_center", value, parent, from, to),
                    &BOOK,
                )
                .unwrap();
        }
        history.apply(19, &close("closed", 10), &BOOK).unwrap();
        let selected = history
            .select(&Selection {
                dimension: "cost_center".into(),
                value: "root".into(),
            })
            .unwrap();
        assert_eq!(selected.values, ["closed", "future", "grandchild", "root"]);
    }

    #[test]
    fn close_windows_are_nonempty_and_never_extend() {
        let mut history = History::default();
        history
            .apply(
                17,
                &declaration("cost_center", "root", None, Some(10), Some(30)),
                &BOOK,
            )
            .unwrap();
        for day in [10, 9, 31] {
            assert_eq!(
                history
                    .apply(19, &close("root", day), &BOOK)
                    .unwrap_err()
                    .predicate,
                "dimension_history",
            );
        }
        history.apply(19, &close("root", 20), &BOOK).unwrap();
        assert!(history.apply(19, &close("root", 21), &BOOK).is_err());
        history.apply(19, &close("root", 19), &BOOK).unwrap();
    }

    #[test]
    fn declarations_require_valid_identity_hierarchy_and_windows() {
        for body in [
            declaration("legal_entity", "root", None, None, None),
            declaration("cost_center", "has space", None, None, None),
            declaration("cost_center", "root", Some("root"), None, None),
            declaration("cost_center", "root", Some("missing"), None, None),
            declaration("cost_center", "root", None, Some(5), Some(5)),
            declaration("cost_center", "root", None, Some(6), Some(5)),
        ] {
            assert_eq!(
                History::default()
                    .apply(17, &body, &BOOK)
                    .unwrap_err()
                    .predicate,
                "dimension_history",
            );
        }
        let mut history = History::default();
        let root = declaration("cost_center", "root", None, None, None);
        history.apply(17, &root, &BOOK).unwrap();
        assert!(history.apply(17, &root, &BOOK).is_err());
        assert!(
            history
                .apply(
                    17,
                    &declaration("department", "child", Some("root"), None, None),
                    &BOOK,
                )
                .is_err()
        );
        assert!(history.apply(19, &close("root", 20), &[9; 16]).is_err());
    }

    #[test]
    fn every_registered_dimension_has_its_own_value_namespace() {
        let mut ids = BTreeSet::new();
        for (dimension, expected_id) in [
            ("cost_center", 2),
            ("department", 3),
            ("project", 4),
            ("product", 5),
            ("region", 6),
            ("fund", 7),
            ("grant", 8),
            ("segment", 9),
        ] {
            assert_eq!(dimension_id(dimension), Some(expected_id));
            ids.insert(value_vid(&BOOK, dimension, "root"));
            let mut history = History::default();
            history
                .apply(17, &declaration(dimension, "root", None, None, None), &BOOK)
                .unwrap();
            assert_eq!(
                history
                    .select(&Selection {
                        dimension: dimension.into(),
                        value: "root".into(),
                    })
                    .unwrap()
                    .values,
                ["root"],
            );
        }
        assert_eq!(ids.len(), 8);
        assert_ne!(
            value_vid(&BOOK, "cost_center", "root"),
            value_vid(&[9; 16], "cost_center", "root"),
        );
    }
}
