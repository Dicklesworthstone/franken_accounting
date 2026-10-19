//! Recipient-held scope for a reviewed workpaper delivery. A valid historical
//! packet is not necessarily the packet answering the recipient's request.

use super::*;

/// Keep this expectation independently of the delivered bytes. In particular,
/// never fill it by decoding the delivery being checked: an older genuine Open
/// workpaper must not answer a request for status after a later dismissal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingReviewExpectation {
    pub book_id: Id128,
    pub certificate_digest: [u8; 32],
    pub review_known_at: CommitSeq,
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Replay a delivery only if it answers an independently retained source
    /// and review cutoff. Current whole-book read authority precedes framing and
    /// scope inspection. A matching request does not replace native replay.
    pub async fn replay_finding_review_workpaper_for(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        bytes: &[u8],
        expected: &FindingReviewExpectation,
    ) -> Outcome<FindingRunReviewHistory> {
        if let Err(r) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(r));
        }
        let saved = match FindingReviewWorkpaper::decode(bytes) {
            Ok(saved) => saved,
            Err(r) => return Ok(Err(r)),
        };
        let source =
            match ProcedureCertificate::decode(saved.observation_workpaper().certificate_bytes()) {
                Ok(source) => source,
                Err(r) => return Ok(Err(r)),
            };
        if self.context().book_id != expected.book_id
            || source.book_id() != expected.book_id
            || *source.digest() != expected.certificate_digest
            || saved.review_known_at() != expected.review_known_at
        {
            return Ok(Err(invalid(
                "review workpaper does not answer the independently expected book, source certificate and review cutoff",
            )));
        }
        self.replay_finding_review_workpaper(cx, principal, capability, bytes)
            .await
    }
}
