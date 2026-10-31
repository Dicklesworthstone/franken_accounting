//! A schema-control proposal (a lot policy or an asset schedule) retained
//! before its independently recorded approvals.
//!
//! The review is request data, not a PostEntry intent: PostIntent keeps its
//! Intent-origin boundary, and only the typed control operation that
//! rebuilds this exact proposal can publish it. It is neither an approval,
//! certificate, signature nor publication permit. When the control is
//! recorded the kernel still checks the canonical control bytes, current
//! authority and every approval against the proposal digest.

use fa_model::limits::MAX_ENTRY_BYTES;
use fa_model::{
    ControlKind, ControlPayload, Entry, EntryClass, EntryOrigin, EntryPayload, Reader, Writer,
    domain_digest,
};

use crate::{IntentError, bounded, version};

/// One bounded sealed Entry plus the magic, version, and its length field.
pub const MAX_SCHEMA_CONTROL_REVIEW_BYTES: usize = MAX_ENTRY_BYTES + 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaControlReview {
    entry: Entry,
}

impl SchemaControlReview {
    pub const MAGIC: &'static [u8; 17] = b"FA-SCHEMA-REVIEW\0";

    /// Retain one unapproved schema-control proposal. This validates its
    /// request shape only; the typed control operation decides whether the
    /// control is lawful and canonical in the current book.
    pub fn new(proposal: EntryPayload) -> Result<Self, IntentError> {
        let schema_change = matches!(proposal.control, Some(ControlPayload::SchemaChange { .. }));
        let control_origin = matches!(
            proposal.origin,
            EntryOrigin::Control {
                control_kind: ControlKind::CHART_INSTALL,
                ..
            }
        );
        if proposal.class != EntryClass::SCHEMA_CONTROL || !schema_change || !control_origin {
            return Err(IntentError::Invalid(
                "a schema-control review retains one Control-origin SchemaChange proposal",
            ));
        }
        let review = Self {
            entry: proposal.seal(Vec::new(), None)?,
        };
        review.canonical_bytes()?;
        Ok(review)
    }

    #[must_use]
    pub fn proposal(&self) -> &EntryPayload {
        &self.entry.proposal
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IntentError> {
        let mut writer = Writer::new();
        writer
            .fixed(Self::MAGIC)
            .u16(1)
            .u16(0)
            .bytes(&self.entry.encode()?);
        let bytes = writer.finish()?;
        bounded(&bytes, MAX_SCHEMA_CONTROL_REVIEW_BYTES)?;
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IntentError> {
        bounded(bytes, MAX_SCHEMA_CONTROL_REVIEW_BYTES)?;
        let mut reader = Reader::new(bytes);
        if reader.fixed::<17>("schema_control_review.magic")? != *Self::MAGIC {
            return Err(IntentError::Invalid("wrong schema-control review magic"));
        }
        version(&mut reader)?;
        let entry = Entry::decode(reader.bytes(MAX_ENTRY_BYTES, "schema_control_review.entry")?)?;
        reader.finish()?;
        if !entry.approvals.is_empty() || entry.plan_certificate.is_some() {
            return Err(IntentError::Invalid(
                "a schema-control review carries no approvals or plan certificate",
            ));
        }
        Self::new(entry.proposal)
    }

    /// The identity of every byte in the unapproved proposal. A caller must
    /// retain this independently of the review it later restores; approvals
    /// bind the proposal digest, never this container.
    pub fn digest(&self) -> Result<[u8; 32], IntentError> {
        Ok(domain_digest(
            b"fa:schema-control-review:v1",
            &[&self.canonical_bytes()?],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_control_review_lengths_are_checked_before_allocation() {
        let mut bytes = SchemaControlReview::MAGIC.to_vec();
        bytes.extend_from_slice(&[1, 0, 0, 0]);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            SchemaControlReview::decode(&bytes),
            Err(IntentError::Decode(_))
        ));
        assert!(matches!(
            SchemaControlReview::decode(&vec![0; MAX_SCHEMA_CONTROL_REVIEW_BYTES + 1]),
            Err(IntentError::TooLarge { .. })
        ));
    }

    #[test]
    fn a_post_intent_or_unknown_version_is_not_a_schema_control_review() {
        let mut intent = b"FA-INTENT\0".to_vec();
        intent.extend_from_slice(&[1, 0, 0, 0, 0]);
        assert!(matches!(
            SchemaControlReview::decode(&intent),
            Err(IntentError::Invalid(_) | IntentError::Decode(_))
        ));
        let mut future = SchemaControlReview::MAGIC.to_vec();
        future.extend_from_slice(&[2, 0, 0, 0]);
        assert!(matches!(
            SchemaControlReview::decode(&future),
            Err(IntentError::Invalid("unsupported schema version"))
        ));
    }
}
