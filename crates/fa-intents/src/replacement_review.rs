//! A correction pair retained before its independently recorded approvals.
//!
//! The review is an unexecuted request, not a successful rehearsal, certificate,
//! signature, or grant of authority. It keeps both sealed proposals unchanged
//! while their approvals are recorded. The native pair planner, draft planner,
//! or posting kernel still evaluates every current law after those approvals
//! are attached. No member may be restored from a different review.

use fa_model::{
    ApprovalRef, EntryClass, EntryRef, Reader, SupersessionKind, Writer, domain_digest,
};

use crate::{IntentError, MAX_INTENT_BYTES, PostIntent, bounded, version};

/// Two bounded PostIntents plus the magic, version, and two length fields.
pub const MAX_REPLACEMENT_REVIEW_BYTES: usize = 2 * MAX_INTENT_BYTES + 30;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplacementReview {
    reversal: PostIntent,
    replacement: PostIntent,
}

impl ReplacementReview {
    pub const MAGIC: &'static [u8; 18] = b"FA-REPLACE-REVIEW\0";

    /// Retain one unapproved pair. This validates its canonical request shape;
    /// only the posting kernel can decide whether its target and effects are
    /// lawful in the current book.
    pub fn new(reversal: PostIntent, replacement: PostIntent) -> Result<Self, IntentError> {
        let rev = reversal.proposal();
        let rep = replacement.proposal();
        let paired = match (rev.supersession.as_slice(), rep.supersession.as_slice()) {
            ([a], [b]) => {
                rev.class == EntryClass::REVERSAL
                    && rep.class == EntryClass::REPLACEMENT
                    && a.kind == SupersessionKind::Reverses
                    && b.kind == SupersessionKind::Replaces
                    && a.target == b.target
                    && a.reason_code == b.reason_code
            }
            _ => false,
        };
        if !paired {
            return Err(IntentError::Invalid(
                "a correction review retains one Reversal and one Replacement of the same target and reason",
            ));
        }
        if rev.book_id != rep.book_id
            || rev.branch_id != rep.branch_id
            || rev.principal_ref != rep.principal_ref
            || rev.session_ref != rep.session_ref
        {
            return Err(IntentError::Invalid(
                "correction review members have different books, branches, preparers, or sessions",
            ));
        }
        if !reversal.approvals().is_empty() || !replacement.approvals().is_empty() {
            return Err(IntentError::Invalid(
                "a correction review contains no approvals; record and attach them separately",
            ));
        }
        let review = Self {
            reversal,
            replacement,
        };
        review.canonical_bytes()?;
        Ok(review)
    }

    #[must_use]
    pub fn reversal(&self) -> &PostIntent {
        &self.reversal
    }

    #[must_use]
    pub fn replacement(&self) -> &PostIntent {
        &self.replacement
    }

    #[must_use]
    pub fn target(&self) -> EntryRef {
        // Construction admits exactly one common target and exposes no mutation.
        self.reversal.proposal().supersession[0].target
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IntentError> {
        let mut writer = Writer::new();
        writer
            .fixed(Self::MAGIC)
            .u16(1)
            .u16(0)
            .bytes(&self.reversal.canonical_bytes()?)
            .bytes(&self.replacement.canonical_bytes()?);
        let bytes = writer.finish()?;
        bounded(&bytes, MAX_REPLACEMENT_REVIEW_BYTES)?;
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IntentError> {
        bounded(bytes, MAX_REPLACEMENT_REVIEW_BYTES)?;
        let mut reader = Reader::new(bytes);
        if reader.fixed::<18>("replacement_review.magic")? != *Self::MAGIC {
            return Err(IntentError::Invalid("wrong correction review magic"));
        }
        version(&mut reader)?;
        let reversal = PostIntent::decode(reader.bytes(MAX_INTENT_BYTES, "review.reversal")?)?;
        let replacement =
            PostIntent::decode(reader.bytes(MAX_INTENT_BYTES, "review.replacement")?)?;
        reader.finish()?;
        Self::new(reversal, replacement)
    }

    /// The identity of every byte in both unapproved proposals. A caller must
    /// retain this independently of the review it later restores.
    pub fn digest(&self) -> Result<[u8; 32], IntentError> {
        Ok(domain_digest(
            b"fa:replacement-review:v1",
            &[&self.canonical_bytes()?],
        ))
    }

    /// Restore the exact pair after checking the caller's independently saved
    /// review digest. Approval references bind their own member's proposal,
    /// never the review container or the other member. Their existence,
    /// authenticity, current applicability and SoD are checked by the kernel.
    pub fn with_approvals(
        &self,
        expected_review_digest: [u8; 32],
        reversal_approvals: Vec<ApprovalRef>,
        replacement_approvals: Vec<ApprovalRef>,
    ) -> Result<(PostIntent, PostIntent), IntentError> {
        if self.digest()? != expected_review_digest {
            return Err(IntentError::Invalid(
                "correction review does not match the independently retained digest",
            ));
        }
        let restore = |intent: &PostIntent, approvals: Vec<ApprovalRef>| {
            let proposal = intent.proposal();
            let digest = proposal.proposal_digest()?;
            if approvals
                .iter()
                .any(|approval| approval.approved_digest != digest)
            {
                return Err(IntentError::Invalid(
                    "correction approval reference binds another member or proposal",
                ));
            }
            PostIntent::new(proposal.clone(), approvals)
        };
        Ok((
            restore(&self.reversal, reversal_approvals)?,
            restore(&self.replacement, replacement_approvals)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correction_review_lengths_are_checked_before_member_allocation() {
        let mut bytes = ReplacementReview::MAGIC.to_vec();
        bytes.extend_from_slice(&[1, 0, 0, 0]);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            ReplacementReview::decode(&bytes),
            Err(IntentError::Decode(_))
        ));
        assert!(matches!(
            ReplacementReview::decode(&vec![0; MAX_REPLACEMENT_REVIEW_BYTES + 1]),
            Err(IntentError::TooLarge { .. })
        ));
    }
}
