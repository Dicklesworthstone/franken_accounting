//! Atomic native intercompany declarations (plan §12.3).
//!
//! A declaration names both reciprocal legs of one immutable entry. Accounts,
//! entities, signs and amounts remain in those legs and are approval-bound by
//! the proposal digest. The kernel claims each key with the complete entry.

use std::collections::BTreeSet;

use crate::limits::{MAX_EXTENSION_BYTES, MAX_IDEMPOTENCY_KEY_BYTES, MAX_LEGS_PER_ENTRY};
use crate::{DecodeError, EntryClass, EntryError, EntryOrigin, EntryPayload, Reader, Writer};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntercompanyPair {
    /// Book-wide identity of this economic pair. Exact reversals retain it;
    /// another original posting may never reuse it.
    pub pair_key: String,
    /// Ascending leg ordinals, independent of debit/credit parity.
    pub left_leg: u16,
    pub right_leg: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntercompanyPairs {
    /// Strictly ascending keys; a leg belongs to at most one pair.
    pub pairs: Vec<IntercompanyPair>,
}

fn invalid(why: &'static str) -> EntryError {
    EntryError::Invalid {
        what: "extensions.intercompany_pairs",
        why,
    }
}

impl IntercompanyPairs {
    pub fn validate_shape(&self, leg_count: usize) -> Result<(), EntryError> {
        if self.pairs.is_empty() || self.pairs.len() > MAX_LEGS_PER_ENTRY / 2 {
            return Err(invalid(
                "pairs require 1..=max_legs_per_entry/2 declarations",
            ));
        }
        let mut previous: Option<&str> = None;
        let mut legs = BTreeSet::new();
        for pair in &self.pairs {
            if pair.pair_key.trim().is_empty()
                || pair.pair_key.len() > MAX_IDEMPOTENCY_KEY_BYTES
                || previous.is_some_and(|key| key >= pair.pair_key.as_str())
            {
                return Err(invalid(
                    "pair keys must be nonempty, strictly ascending and within max_idempotency_key_bytes",
                ));
            }
            if pair.left_leg >= pair.right_leg
                || usize::from(pair.right_leg) >= leg_count
                || !legs.insert(pair.left_leg)
                || !legs.insert(pair.right_leg)
            {
                return Err(invalid(
                    "each pair needs two ascending in-range leg ordinals, with no leg reused",
                ));
            }
            previous = Some(&pair.pair_key);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, EntryError> {
        self.validate_shape(MAX_LEGS_PER_ENTRY)?;
        let mut writer = Writer::new();
        writer.u16(1).list(&self.pairs, |writer, pair| {
            writer
                .str(&pair.pair_key)
                .u16(pair.left_leg)
                .u16(pair.right_leg);
        });
        let bytes = writer.finish()?;
        if bytes.len() > MAX_EXTENSION_BYTES {
            return Err(invalid("pair declarations exceed max_extension_bytes"));
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        if bytes.len() > MAX_EXTENSION_BYTES || reader.u16("intercompany.version")? != 1 {
            return Err(reader.invalid("intercompany.version"));
        }
        let count = reader.count(MAX_LEGS_PER_ENTRY / 2, "intercompany.pairs")?;
        let mut pairs = Vec::with_capacity(count);
        for _ in 0..count {
            pairs.push(IntercompanyPair {
                pair_key: reader
                    .str(MAX_IDEMPOTENCY_KEY_BYTES, "intercompany.pair_key")?
                    .to_string(),
                left_leg: reader.u16("intercompany.left_leg")?,
                right_leg: reader.u16("intercompany.right_leg")?,
            });
        }
        reader.finish()?;
        let decoded = Self { pairs };
        decoded
            .validate_shape(MAX_LEGS_PER_ENTRY)
            .map_err(|_| Reader::new(bytes).invalid("intercompany.pairs"))?;
        Ok(decoded)
    }
}

pub(crate) fn validate_entry(entry: &EntryPayload) -> Result<(), EntryError> {
    let Some((_, bytes)) = entry
        .extensions
        .iter()
        .find(|(tag, _)| *tag == crate::entry::INTERCOMPANY_PAIRS_EXTENSION)
    else {
        return Ok(());
    };
    if entry.schema_minor < crate::entry::INTERCOMPANY_PAIRS_SCHEMA_MINOR
        || !matches!(
            entry.class,
            EntryClass::ORIGINAL | EntryClass::ADJUSTING | EntryClass::REVERSAL
        )
        || (entry.class != EntryClass::REVERSAL
            && !matches!(&entry.origin, EntryOrigin::Intent { .. }))
    {
        return Err(invalid(
            "requires an Original/Adjusting Intent or its exact Reversal at schema minor 12 or later",
        ));
    }
    IntercompanyPairs::decode(bytes)?.validate_shape(entry.legs.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(key: &str, left_leg: u16, right_leg: u16) -> IntercompanyPair {
        IntercompanyPair {
            pair_key: key.into(),
            left_leg,
            right_leg,
        }
    }

    #[test]
    fn canonical_pairs_refuse_duplicate_keys_reused_legs_and_truncation() {
        let valid = IntercompanyPairs {
            pairs: vec![pair("loan-1", 0, 2), pair("loan-2", 1, 3)],
        };
        let bytes = valid.encode().unwrap();
        assert_eq!(IntercompanyPairs::decode(&bytes).unwrap(), valid);
        for end in 0..bytes.len() {
            assert!(IntercompanyPairs::decode(&bytes[..end]).is_err());
        }
        for pairs in [
            vec![],
            vec![pair("loan-1", 0, 2), pair("loan-1", 1, 3)],
            vec![pair("loan-2", 0, 2), pair("loan-1", 1, 3)],
            vec![pair("loan-1", 0, 2), pair("loan-2", 2, 3)],
            vec![pair("loan-1", 2, 0)],
            vec![pair(" ", 0, 1)],
            vec![pair(&"x".repeat(MAX_IDEMPOTENCY_KEY_BYTES + 1), 0, 1)],
        ] {
            assert!(IntercompanyPairs { pairs }.encode().is_err());
        }
        assert!(valid.validate_shape(3).is_err());
    }
}
