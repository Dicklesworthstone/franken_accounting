//! Retained-history certification for native account lead schedules.
//!
//! A closing-stock ReportCertificate commits the ENTIRE native read closure
//! at the selected prefix, not only entries effective before the closing day.
//! The outer transcript binds the explicit account/unit/date selector and
//! every opening, bucket, closing and journal-leg citation in the schedule.
//! Replay verifies that source, then rebuilds the whole lead schedule. A
//! self-consistent digest or a balancing schedule alone is never evidence of
//! completeness: omitted offsetting movements must also be detected.
//!
//! This is embedded-owner retained-history replay, not a signed checkpoint,
//! outsider proof, recipient authorization or attestation to economic truth.
//! Canonical bytes may be saved by the caller. Nothing is appended to the book.
//! The nested source contains whole-book information despite selected output
//! scope: keep certificate bytes confidential. Selected JSONL workpapers do
//! not include that native source closure.

mod codec;
mod workpaper;

pub use workpaper::MAX_ROLL_FORWARD_WORKPAPER_BYTES;

use std::collections::BTreeMap;

use asupersync::fs::Vfs;
use fa_journal::{KernelError, Refusal, exit};
use fa_policy::{Capability, Op};
use fa_registers::TrialBalance;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use super::{RollForward, RollForwardRequest};
use crate::{AsyncBook, BookError, Outcome, ReportCertificate, TrialBalanceSelection};

pub const ROLL_FORWARD_CERTIFICATE_FORMAT: &[u8] = b"fa:roll-forward-certificate:v1";
/// Total envelope bound, including the native source and exact schedule bytes.
pub const MAX_ROLL_FORWARD_CERTIFICATE_BYTES: usize = 64 * 1024 * 1024;
const DIGEST_DOMAIN: &[u8] = b"fa:roll-forward-certificate-digest:v1";

/// Private fields prevent relabeling one schedule with another selection.
/// Decoding establishes canonical framing and content integrity only. Call
/// `AsyncBook::replay_roll_forward` to check historical inputs and all effects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollForwardCertificate {
    source: ReportCertificate,
    request: RollForwardRequest,
    output: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedRollForward {
    pub report: RollForward,
    pub certificate: RollForwardCertificate,
}

impl RollForwardCertificate {
    #[must_use]
    pub fn source_certificate(&self) -> &ReportCertificate {
        &self.source
    }

    /// Canonically ordered scope with an explicit, never-HEAD recorded prefix.
    #[must_use]
    pub fn request(&self) -> &RollForwardRequest {
        &self.request
    }

    /// Exact original RollForward::canonical_bytes, not a new report encoding.
    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output
    }

    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    #[must_use]
    pub fn known_at(&self) -> CommitSeq {
        self.source.known_at
    }
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §12.1 / §13.6 (the complete native lead schedule must replay)",
        "recreate the certificate from its original book, explicit scope and retained prefix; a matching closing balance cannot replace missing activity",
    )
}

fn encoded(report: &RollForward) -> Result<Vec<u8>, BookError> {
    report
        .canonical_bytes()
        .map_err(|error| KernelError::Model(error.into()).into())
}

fn authorize<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    principal: VId,
    capability: &Capability,
    produce: bool,
) -> Outcome<CommitSeq> {
    let context = book.context();
    let admitted = fa_policy::admit_read(capability, principal, context.book_id).and_then(|()| {
        if produce {
            fa_policy::require(capability, Op::Produce, "certifying account roll-forwards")
        } else {
            Ok(())
        }
    });
    if let Err(denial) = admitted {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    let query = cx.query();
    query.checkpoint().map_err(BookError::Context)?;
    query.with_restriction(|| {
        let head = book.db.frontier().map_err(KernelError::from)?;
        if let Err(denial) = fa_policy::current(capability, head) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        if let Err(refusal) =
            fa_journal::policy::capability_admitted(&book.db, context, capability)?
        {
            return Ok(Err(refusal));
        }
        Ok(Ok(head))
    })
}

/// The independent source fold must agree cell-by-cell, not merely in total.
/// It intentionally covers the whole book; the roll-forward is explicit scope.
fn check_closing(report: &RollForward, stock: &TrialBalance) -> Result<(), Refusal> {
    if stock.known_at.0 != report.known_at
        || stock.activity
        || stock.effective_through != Some(report.effective_through)
    {
        return Err(invalid(
            "closing source and roll-forward have different coordinates",
        ));
    }
    let mut amounts = BTreeMap::new();
    for row in &stock.rows {
        let net = row
            .debits
            .checked_sub(row.credits)
            .ok_or_else(|| invalid("closing source amount overflow"))?;
        if amounts.insert((row.account.0, row.unit_id), net).is_some() {
            return Err(invalid("closing source repeats an account/unit cell"));
        }
    }
    for row in &report.rows {
        if amounts
            .get(&(row.account_id, row.unit_id))
            .copied()
            .unwrap_or(0)
            != row.closing
        {
            return Err(invalid(
                "roll-forward closing differs from its certified native stock",
            ));
        }
    }
    Ok(())
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Bind an exact lead schedule to its native chart, journal, migration and
    /// registry closure at ONE recorded prefix. Require current whole-book
    /// read+produce authority before observing financial data. Output includes
    /// zero leaves, native units and every selected movement, even net-zero ones.
    pub fn certify_roll_forward(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &RollForwardRequest,
    ) -> Outcome<CertifiedRollForward> {
        let head = match authorize(self, cx, principal, capability, true)? {
            Ok(head) => head,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let request = match codec::normalize(request, request.known_at.unwrap_or(head)) {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let report = match self.roll_forward(cx, principal, capability, &request)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let source = match self.certify_trial_balance(
            cx,
            TrialBalanceSelection::AsOf(request.effective_through),
            request.known_at,
        )? {
            Ok(source) => source,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if let Err(refusal) = check_closing(&report, &source.report) {
            return Ok(Err(refusal));
        }
        let certificate =
            match RollForwardCertificate::seal(source.certificate, request, encoded(&report)?) {
                Ok(certificate) => certificate,
                Err(refusal) => return Ok(Err(refusal)),
            };
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(CertifiedRollForward {
            report,
            certificate,
        }))
    }

    /// Verify native historical reads BEFORE rebuilding the schedule at the
    /// certificate's original prefix. Current holder, read scope, expiry and
    /// revocation are checked on every call. Never substitute today's chart,
    /// balances or movement set. Neither a decoder pass nor matching totals
    /// can bypass the exact-output comparison, including entry-leg citations.
    pub fn replay_roll_forward(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &RollForwardCertificate,
    ) -> Outcome<RollForward> {
        if let Err(refusal) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(refusal));
        }
        if certificate.source.book_id != self.context().book_id {
            return Ok(Err(invalid(
                "roll-forward certificate belongs to another book",
            )));
        }
        if let Err(refusal) = certificate.canonical_bytes() {
            return Ok(Err(refusal));
        }
        let stock = match self.replay_trial_balance(cx, &certificate.source)? {
            Ok(stock) => stock,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let report = match self.roll_forward(cx, principal, capability, &certificate.request)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if let Err(refusal) = check_closing(&report, &stock) {
            return Ok(Err(refusal));
        }
        if encoded(&report)? != certificate.output {
            return Ok(Err(invalid(
                "roll-forward scope, stock, buckets or journal-leg citations did not replay",
            )));
        }
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(report))
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Replay only the independently supplied expected scope and coordinate.
    /// Account/unit permutations are equivalent; duplicates, different labels,
    /// dates, omitted zero leaves, different units and a different prefix are
    /// not. `known_at` MUST be explicit: accepting HEAD here could silently
    /// accept an older delivered artifact. Do not obtain `expected` from the
    /// artifact itself when checking another party's response to a request.
    pub fn replay_roll_forward_for(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &RollForwardCertificate,
        expected: &RollForwardRequest,
    ) -> Outcome<RollForward> {
        if let Err(refusal) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(refusal));
        }
        let Some(at) = expected.known_at else {
            return Ok(Err(invalid(
                "roll-forward replay needs an independently selected fixed prefix",
            )));
        };
        let expected = match codec::normalize(expected, at) {
            Ok(expected) => expected,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if expected != certificate.request {
            return Ok(Err(invalid(
                "delivered roll-forward differs from the expected scope or coordinate",
            )));
        }
        self.replay_roll_forward(cx, principal, capability, certificate)
    }
}
