//! Recipient-supplied display units for the monetary rows of an audit extract.

use std::collections::{BTreeMap, BTreeSet};

use super::{Extracted, Units};

/// The unit IDs, case-sensitive codes and decimal scales the recipient expects.
/// Both export formats identify a unit by its code, so a selected code has one
/// version (ID and scale). Definitions for unused units are permitted.
#[derive(Debug)]
pub struct UnitDefinitions {
    by_code: BTreeMap<String, (u32, u8)>,
}

impl UnitDefinitions {
    /// Build a one-to-one table. Scales are native decimal scales, 0 through 38.
    pub fn new(definitions: impl IntoIterator<Item = (u32, String, u8)>) -> Result<Self, String> {
        let mut ids = BTreeSet::new();
        let mut by_code = BTreeMap::new();
        for (id, code, scale) in definitions {
            if code.is_empty() || code.len() > 64 || code.chars().any(char::is_control) {
                return Err(
                    "a unit definition requires a code of 1 to 64 bytes without control characters"
                        .into(),
                );
            }
            if scale > 38 {
                return Err(format!(
                    "unit {code} has scale {scale}, outside 0 through 38"
                ));
            }
            if !ids.insert(id) || by_code.insert(code, (id, scale)).is_some() {
                return Err("each unit definition needs a distinct code and ID".into());
            }
        }
        if by_code.is_empty() {
            return Err("supply at least one unit definition".into());
        }
        Ok(Self { by_code })
    }

    pub(super) fn resolve(&self, entries: &[Extracted]) -> Result<Units, String> {
        let mut units = Units::default();
        for entry in entries {
            for row in &entry.rows {
                let (id, scale) = self.by_code.get(&row.unit).ok_or_else(|| {
                    format!(
                        "entry {} names unit {:?} without a recipient definition",
                        entry.journal_id, row.unit
                    )
                })?;
                if row.scale != u32::from(*scale) {
                    return Err(format!(
                        "entry {} shows unit {} at scale {}, but the recipient specified {scale}",
                        entry.journal_id, row.unit, row.scale
                    ));
                }
                if let std::collections::btree_map::Entry::Vacant(slot) = units.by_id.entry(*id) {
                    slot.insert(row.unit.clone());
                    units.by_code.insert(row.unit.clone(), *id);
                }
            }
        }
        Ok(units)
    }
}
