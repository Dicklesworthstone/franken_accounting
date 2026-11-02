//! Exact changes between two original Statements of Changes in Equity.
//!
//! The sources retain their complete v2 movement/case provenance. Only recorded
//! time may differ: the caller independently supplies the common dates, units
//! and owner-account roles. This comparison does not issue a statement, approve
//! a restatement case or assign a cause to a numerical change.

use asupersync::fs::Vfs;
use fa_journal::{KernelError, Refusal, exit};
use fa_model::{Id128, Reader, Writer, domain_digest};
use fa_policy::{Capability, Op};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{
    AsyncBook, BookError, EquityRollForwardCertificate, EquityRollForwardReport,
    EquityRollForwardRequest, EquityRollForwardUnit, Outcome,
};

pub const EQUITY_DIFF_OUTPUT_FORMAT: &[u8] = b"fa:equity-roll-forward-diff:v1";
pub const EQUITY_DIFF_CERTIFICATE_FORMAT: &[u8] = b"fa:equity-roll-forward-diff-certificate:v1";
pub const EQUITY_DIFF_REQUEST_FORMAT: &[u8] = b"fa:equity-roll-forward-diff-request:v1";
pub const MAX_EQUITY_DIFF_CERTIFICATE_BYTES: usize = 64 * 1024 * 1024;
const DIGEST_DOMAIN: &[u8] = b"fa:equity-roll-forward-diff-certificate-digest:v1";
const SOURCE_DOMAIN: &[u8] = b"fa:equity-roll-forward-diff-source:v1";
const MAX_SCOPE: usize = 4096;
const MAX_REQUEST_BYTES: usize = 4 + 64 + 16 + 4 + 256 + 8 + 12 + MAX_SCOPE * 36;
const LINE_CODES: [&str; 15] = [
    "opening_contributed_equity",
    "opening_unclosed_earnings",
    "opening_total_equity",
    "prior_period_adjustments",
    "opening_equity_as_adjusted",
    "net_income",
    "issuances",
    "distributions",
    "other_equity_movements",
    "closing_transfers_net",
    "net_equity_change",
    "closing_contributed_equity",
    "closing_unclosed_earnings",
    "closing_total_equity",
    "equity_tie_out_residual",
];

/// An independently chosen common question at two fixed recorded frontiers.
/// `before.known_at` must be `Some`; neither frontier is replaced with HEAD.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquityRollForwardDiffRequest {
    pub before: EquityRollForwardRequest,
    pub after: CommitSeq,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquityRollForwardDiffLine {
    pub code: &'static str,
    pub before: i128,
    pub after: i128,
    /// Checked exact `after - before`, in the unit's registered integer scale.
    pub delta: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquityRollForwardDiffUnit {
    pub unit_id: u32,
    /// All fifteen rows in the equity statement's canonical order, including
    /// zero deltas and the closing-transfer and tie-out checks.
    pub lines: Vec<EquityRollForwardDiffLine>,
}

/// Computed comparison with complete original sources for evidence drilldown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquityRollForwardDiff {
    before: EquityRollForwardReport,
    after: EquityRollForwardReport,
    before_digest: [u8; 32],
    after_digest: [u8; 32],
    units: Vec<EquityRollForwardDiffUnit>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquityRollForwardDiffCertificate {
    before: EquityRollForwardCertificate,
    after: EquityRollForwardCertificate,
    producer: VId,
    capability_commitment: [u8; 32],
    output: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedEquityRollForwardDiff {
    pub report: EquityRollForwardDiff,
    pub certificate: EquityRollForwardDiffCertificate,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §8.3 / §12.1 / §13.6 (same equity question at two recorded frontiers)",
        "supply both original v2 equity certificates and the independently retained fixed frontiers, dates, units and issuance/distribution accounts; only known-at may differ",
    )
}

fn bounded_total(parts: impl IntoIterator<Item = usize>) -> Result<usize, Refusal> {
    parts
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .filter(|size| *size <= MAX_EQUITY_DIFF_CERTIFICATE_BYTES)
        .ok_or_else(|| invalid("equity comparison exceeds the 64 MiB aggregate limit"))
}

impl EquityRollForwardDiffRequest {
    fn normalized(&self) -> Result<Self, Refusal> {
        let at = self.before.known_at.ok_or_else(|| {
            invalid("equity comparison requires an independently selected fixed before prefix")
        })?;
        if at > self.after {
            return Err(invalid("equity comparison requires before <= after"));
        }
        Ok(Self {
            before: crate::equity_certificate::normalize(&self.before, at)?,
            after: self.after,
        })
    }

    fn after_request(&self) -> EquityRollForwardRequest {
        EquityRollForwardRequest {
            known_at: Some(self.after),
            ..self.before.clone()
        }
    }

    /// Portable independent recipient expectation. Keep this apart from the
    /// delivered bundle: reconstructing it from that bundle grants no assurance
    /// that the result answers the recipient's intended accounting question.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let request = self.normalized()?;
        let before = request
            .before
            .known_at
            .ok_or_else(|| invalid("missing fixed before prefix"))?;
        let mut w = Writer::new();
        w.bytes(EQUITY_DIFF_REQUEST_FORMAT)
            .u64(before.0)
            .u64(request.after.0)
            .str(&request.before.label)
            .i32(request.before.effective_from.0)
            .i32(request.before.effective_through.0)
            .list(&request.before.units, |w, unit| {
                w.u32(*unit);
            })
            .list(&request.before.issuance_accounts, |w, id| {
                w.u128(id.0);
            })
            .list(&request.before.distribution_accounts, |w, id| {
                w.u128(id.0);
            });
        w.finish().map_err(|e| invalid(e.to_string()))
    }

    /// Decode only canonical, bounded expectations, never a report certificate.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(invalid("equity comparison request exceeds its scope bound"));
        }
        let mut r = Reader::new(bytes);
        let decoded = (|| -> Result<Self, fa_model::DecodeError> {
            if r.bytes(64, "equity comparison request format")? != EQUITY_DIFF_REQUEST_FORMAT {
                return Err(r.invalid("unsupported equity comparison request format"));
            }
            let before = CommitSeq(r.u64("before prefix")?);
            let after = CommitSeq(r.u64("after prefix")?);
            let label = r.str(256, "equity label")?.to_string();
            let effective_from = fa_time::DateDay(r.i32("equity from")?);
            let effective_through = fa_time::DateDay(r.i32("equity through")?);
            let units = r.list(MAX_SCOPE, "equity units", |r| r.u32("equity unit"))?;
            let issuance_accounts = r.list(MAX_SCOPE, "issuance accounts", |r| {
                r.u128("issuance account").map(VId)
            })?;
            let distribution_accounts = r.list(MAX_SCOPE, "distribution accounts", |r| {
                r.u128("distribution account").map(VId)
            })?;
            r.finish()?;
            Ok(Self {
                before: EquityRollForwardRequest {
                    units,
                    label,
                    effective_from,
                    effective_through,
                    known_at: Some(before),
                    issuance_accounts,
                    distribution_accounts,
                },
                after,
            })
        })()
        .map_err(|e| invalid(e.to_string()))?;
        if decoded.canonical_bytes()? != bytes {
            return Err(invalid("noncanonical equity comparison request"));
        }
        Ok(decoded)
    }
}

fn amounts(unit: &EquityRollForwardUnit) -> [i128; 15] {
    [
        unit.opening_contributed_equity,
        unit.opening_unclosed_earnings,
        unit.opening_total_equity,
        unit.prior_period_adjustments,
        unit.opening_equity_as_adjusted,
        unit.net_income,
        unit.issuances,
        unit.distributions,
        unit.other_equity_movements,
        unit.closing_transfers_net,
        unit.net_equity_change,
        unit.closing_contributed_equity,
        unit.closing_unclosed_earnings,
        unit.closing_total_equity,
        unit.equity_tie_out_residual,
    ]
}

impl EquityRollForwardDiff {
    // Inputs have already been replayed by the original equity engine. This
    // function performs no second monetary fold or fresh role classification.
    fn between(
        before: EquityRollForwardReport,
        after: EquityRollForwardReport,
    ) -> Result<Self, Refusal> {
        let a = &before.statement;
        let b = &after.statement;
        if a.book_id != b.book_id
            || a.branch_id != Id128::TRUNK
            || b.branch_id != Id128::TRUNK
            || a.known_at > b.known_at
            || a.label != b.label
            || a.effective_from != b.effective_from
            || a.effective_through != b.effective_through
            || a.units.is_empty()
            || a.units.len() > MAX_SCOPE
            || a.units.len() != b.units.len()
            || a.units.windows(2).any(|u| u[0].unit_id >= u[1].unit_id)
        {
            return Err(invalid("equity report coordinates or unit scope differ"));
        }
        let units = a
            .units
            .iter()
            .zip(&b.units)
            .map(|(old, new)| {
                if old.unit_id != new.unit_id {
                    return Err(invalid("equity comparison unit identities differ"));
                }
                let lines = LINE_CODES
                    .into_iter()
                    .zip(amounts(old))
                    .zip(amounts(new))
                    .map(|((code, before), after)| {
                        let delta = after.checked_sub(before).ok_or_else(|| {
                            invalid(format!("equity comparison overflow in {code}"))
                        })?;
                        Ok(EquityRollForwardDiffLine {
                            code,
                            before,
                            after,
                            delta,
                        })
                    })
                    .collect::<Result<Vec<_>, Refusal>>()?;
                Ok(EquityRollForwardDiffUnit {
                    unit_id: old.unit_id,
                    lines,
                })
            })
            .collect::<Result<Vec<_>, Refusal>>()?;
        // The commitment includes the original accounts and every movement's
        // exact entry, case and relates-to citation, even when all deltas net to 0.
        let before_bytes = before.canonical_bytes()?;
        let after_bytes = after.canonical_bytes()?;
        bounded_total([before_bytes.len(), after_bytes.len()])?;
        Ok(Self {
            before_digest: domain_digest(SOURCE_DOMAIN, &[&before_bytes]),
            after_digest: domain_digest(SOURCE_DOMAIN, &[&after_bytes]),
            before,
            after,
            units,
        })
    }

    #[must_use]
    pub fn before(&self) -> &EquityRollForwardReport {
        &self.before
    }
    #[must_use]
    pub fn after(&self) -> &EquityRollForwardReport {
        &self.after
    }
    #[must_use]
    pub fn units(&self) -> &[EquityRollForwardDiffUnit] {
        &self.units
    }
    /// True only for the monetary rows. Source accounts and movement evidence
    /// may have changed; inspect the complete before/after reports for those.
    #[must_use]
    pub fn is_unchanged(&self) -> bool {
        self.units
            .iter()
            .flat_map(|u| &u.lines)
            .all(|l| l.delta == 0)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let a = &self.before.statement;
        let b = &self.after.statement;
        let mut w = Writer::new();
        w.bytes(EQUITY_DIFF_OUTPUT_FORMAT)
            .fixed(&a.book_id.0)
            .fixed(&a.branch_id.0)
            .u64(a.known_at)
            .u64(b.known_at)
            .fixed(&self.before_digest)
            .fixed(&self.after_digest)
            .str(&a.label)
            .i32(a.effective_from.0)
            .i32(a.effective_through.0)
            .list(&self.units, |w, unit| {
                w.u32(unit.unit_id);
                for line in &unit.lines {
                    w.i128(line.before).i128(line.after).i128(line.delta);
                }
            });
        w.finish().map_err(|e| invalid(e.to_string()))
    }
}

/// Structural same-question binding precedes either historical replay. An
/// artifact may not smuggle a policy/date/unit change into a recorded-time diff.
fn sources(
    before: &EquityRollForwardCertificate,
    after: &EquityRollForwardCertificate,
) -> Result<EquityRollForwardDiffRequest, Refusal> {
    if before.is_legacy() || after.is_legacy() {
        return Err(invalid(
            "equity comparisons require two original v2 certificates; legacy v1 classification cannot be silently upgraded",
        ));
    }
    let a = before.source_certificate().source_certificate();
    let b = after.source_certificate().source_certificate();
    let request = EquityRollForwardDiffRequest {
        before: before.request().clone(),
        after: after.known_at(),
    }
    .normalized()?;
    if request.before != *before.request()
        || request.after_request() != *after.request()
        || request.before.known_at != Some(before.known_at())
        || a.book_id != b.book_id
        || a.branch_id != Id128::TRUNK
        || b.branch_id != Id128::TRUNK
        || a.time_selection.is_some()
        || b.time_selection.is_some()
        || (before.known_at() == after.known_at() && before != after)
    {
        return Err(invalid(
            "equity sources must retain the same book, trunk, dates, units and roles at ordered sequence frontiers; equal frontiers require the identical original certificate",
        ));
    }
    Ok(request)
}

fn bind_expected(
    before: &EquityRollForwardCertificate,
    after: &EquityRollForwardCertificate,
    expected: &EquityRollForwardDiffRequest,
) -> Result<EquityRollForwardDiffRequest, Refusal> {
    let actual = sources(before, after)?;
    let expected = expected.normalized()?;
    if actual != expected {
        return Err(invalid(
            "equity comparison differs from the independently expected frontiers, dates, units or owner-account roles",
        ));
    }
    Ok(expected)
}

impl EquityRollForwardDiffCertificate {
    #[must_use]
    pub fn sources(&self) -> (&EquityRollForwardCertificate, &EquityRollForwardCertificate) {
        (&self.before, &self.after)
    }
    /// Inspect the delivered question. This is not an independent expectation.
    pub fn request(&self) -> Result<EquityRollForwardDiffRequest, Refusal> {
        sources(&self.before, &self.after)
    }
    #[must_use]
    pub fn known_at(&self) -> CommitSeq {
        self.after.known_at()
    }
    #[must_use]
    pub fn producer(&self) -> VId {
        self.producer
    }
    #[must_use]
    pub fn capability_commitment(&self) -> &[u8; 32] {
        &self.capability_commitment
    }
    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    fn body_bytes(&self) -> Result<Vec<u8>, Refusal> {
        sources(&self.before, &self.after)?;
        let mut r = Reader::new(&self.output);
        if r.bytes(64, "equity comparison output format")
            .map_err(|e| invalid(e.to_string()))?
            != EQUITY_DIFF_OUTPUT_FORMAT
        {
            return Err(invalid("unsupported equity comparison output format"));
        }
        let before = self.before.canonical_bytes()?;
        let after = self.after.canonical_bytes()?;
        let size = bounded_total([
            4 + EQUITY_DIFF_CERTIFICATE_FORMAT.len(),
            4 + before.len(),
            4 + after.len(),
            16 + 32,
            4 + self.output.len(),
            32,
        ])?;
        let mut w = Writer::with_capacity(size);
        w.bytes(EQUITY_DIFF_CERTIFICATE_FORMAT)
            .bytes(&before)
            .bytes(&after)
            .u128(self.producer.0)
            .fixed(&self.capability_commitment)
            .bytes(&self.output);
        w.finish().map_err(|e| invalid(e.to_string()))
    }

    fn seal(
        before: EquityRollForwardCertificate,
        after: EquityRollForwardCertificate,
        producer: VId,
        capability_commitment: [u8; 32],
        report: &EquityRollForwardDiff,
    ) -> Result<Self, Refusal> {
        let mut certificate = Self {
            before,
            after,
            producer,
            capability_commitment,
            output: report.canonical_bytes()?,
            digest: [0; 32],
        };
        certificate.digest = domain_digest(DIGEST_DOMAIN, &[&certificate.body_bytes()?]);
        Ok(certificate)
    }

    /// Bounded framing and content integrity only. Both original equity claims
    /// and the output still require replay against an independent expectation.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_EQUITY_DIFF_CERTIFICATE_BYTES {
            return Err(invalid("equity comparison certificate exceeds 64 MiB"));
        }
        let mut r = Reader::new(bytes);
        if r.bytes(64, "equity comparison certificate format")
            .map_err(|e| invalid(e.to_string()))?
            != EQUITY_DIFF_CERTIFICATE_FORMAT
        {
            return Err(invalid("unsupported equity comparison certificate format"));
        }
        let before = EquityRollForwardCertificate::decode(
            r.bytes(
                MAX_EQUITY_DIFF_CERTIFICATE_BYTES,
                "before equity certificate",
            )
            .map_err(|e| invalid(e.to_string()))?,
        )?;
        let after = EquityRollForwardCertificate::decode(
            r.bytes(
                MAX_EQUITY_DIFF_CERTIFICATE_BYTES,
                "after equity certificate",
            )
            .map_err(|e| invalid(e.to_string()))?,
        )?;
        let producer = VId(r
            .u128("equity comparison producer")
            .map_err(|e| invalid(e.to_string()))?);
        let capability_commitment = r
            .fixed::<32>("equity comparison capability")
            .map_err(|e| invalid(e.to_string()))?;
        let output = r
            .bytes(
                MAX_EQUITY_DIFF_CERTIFICATE_BYTES,
                "equity comparison output",
            )
            .map_err(|e| invalid(e.to_string()))?
            .to_vec();
        let digest = r
            .fixed::<32>("equity comparison digest")
            .map_err(|e| invalid(e.to_string()))?;
        r.finish().map_err(|e| invalid(e.to_string()))?;
        let certificate = Self {
            before,
            after,
            producer,
            capability_commitment,
            output,
            digest,
        };
        if certificate.canonical_bytes()? != bytes {
            return Err(invalid("noncanonical equity comparison certificate"));
        }
        Ok(certificate)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut bytes = self.body_bytes()?;
        if domain_digest(DIGEST_DOMAIN, &[&bytes]) != self.digest {
            return Err(invalid(
                "equity comparison digest differs from its contents",
            ));
        }
        bytes.extend_from_slice(&self.digest);
        Ok(bytes)
    }
}

fn authorize<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    principal: VId,
    capability: &Capability,
    produce: bool,
) -> Outcome<()> {
    if let Err(denial) = fa_policy::admit_read(capability, principal, book.context().book_id)
        .and_then(|()| {
            if produce {
                fa_policy::require(capability, Op::Produce, "certifying equity comparisons")
            } else {
                Ok(())
            }
        })
        .and_then(|()| fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None))
    {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    book.query(cx, |db, context| {
        let head = db.frontier().map_err(KernelError::from)?;
        if let Err(denial) = fa_policy::current(capability, head) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        Ok(fa_journal::policy::capability_admitted(
            db, context, capability,
        )?)
    })
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    #[allow(clippy::too_many_arguments)]
    fn retained_equity_diff(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        before: &EquityRollForwardCertificate,
        after: &EquityRollForwardCertificate,
        expected: &EquityRollForwardDiffRequest,
    ) -> Outcome<EquityRollForwardDiff> {
        let expected = match bind_expected(before, after, expected) {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let old = match self.replay_equity_roll_forward(
            cx,
            principal,
            capability,
            before,
            &expected.before,
        )? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let new = match self.replay_equity_roll_forward(
            cx,
            principal,
            capability,
            after,
            &expected.after_request(),
        )? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(EquityRollForwardDiff::between(old, new))
    }

    /// Read exact changes between original v2 equity certificates. Both claims
    /// replay against the caller's fixed question before any difference is shown.
    #[allow(clippy::too_many_arguments)]
    pub fn diff_equity_roll_forward_certificates(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        before: &EquityRollForwardCertificate,
        after: &EquityRollForwardCertificate,
        expected: &EquityRollForwardDiffRequest,
    ) -> Outcome<EquityRollForwardDiff> {
        if let Err(refusal) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(refusal));
        }
        self.retained_equity_diff(cx, principal, capability, before, after, expected)
    }

    /// Certify an exact comparison, preserving both original v2 sources rather
    /// than issuing replacements. Requires current whole-book Read and Produce.
    #[allow(clippy::too_many_arguments)]
    pub fn compare_equity_roll_forward_certificates(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        before: &EquityRollForwardCertificate,
        after: &EquityRollForwardCertificate,
        expected: &EquityRollForwardDiffRequest,
    ) -> Outcome<CertifiedEquityRollForwardDiff> {
        if let Err(refusal) = authorize(self, cx, principal, capability, true)? {
            return Ok(Err(refusal));
        }
        let report =
            match self.retained_equity_diff(cx, principal, capability, before, after, expected)? {
                Ok(report) => report,
                Err(refusal) => return Ok(Err(refusal)),
            };
        let commitment = capability
            .commitment()
            .map_err(|e| KernelError::Corrupt(format!("capability commitment: {e}")))?;
        let certificate = match EquityRollForwardDiffCertificate::seal(
            before.clone(),
            after.clone(),
            principal,
            commitment,
            &report,
        ) {
            Ok(certificate) => certificate,
            Err(refusal) => return Ok(Err(refusal)),
        };
        Ok(Ok(CertifiedEquityRollForwardDiff {
            report,
            certificate,
        }))
    }

    /// Verify both original closures and recompute every signed row delta.
    /// The saved producer and capability commitment never grant read authority.
    pub fn replay_equity_roll_forward_diff(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &EquityRollForwardDiffCertificate,
        expected: &EquityRollForwardDiffRequest,
    ) -> Outcome<EquityRollForwardDiff> {
        if let Err(refusal) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = bind_expected(&certificate.before, &certificate.after, expected)
            .and_then(|_| certificate.canonical_bytes())
        {
            return Ok(Err(refusal));
        }
        let report = match self.retained_equity_diff(
            cx,
            principal,
            capability,
            &certificate.before,
            &certificate.after,
            expected,
        )? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        match report.canonical_bytes() {
            Ok(output) if output == certificate.output => Ok(Ok(report)),
            Ok(_) => Ok(Err(invalid(
                "both equity sources replayed but the comparison amounts or source commitments differ",
            ))),
            Err(refusal) => Ok(Err(refusal)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(at: u64, total: i128) -> EquityRollForwardReport {
        EquityRollForwardReport {
            statement: crate::EquityRollForward {
                book_id: Id128([9; 16]),
                branch_id: Id128::TRUNK,
                known_at: at,
                label: "Equity".into(),
                effective_from: fa_time::DateDay(1),
                effective_through: fa_time::DateDay(2),
                units: vec![EquityRollForwardUnit {
                    unit_id: 1,
                    opening_contributed_equity: total,
                    opening_unclosed_earnings: 0,
                    opening_total_equity: total,
                    prior_period_adjustments: 0,
                    opening_equity_as_adjusted: total,
                    net_income: 0,
                    issuances: 0,
                    distributions: 0,
                    other_equity_movements: 0,
                    closing_transfers_net: 0,
                    net_equity_change: 0,
                    closing_contributed_equity: total,
                    closing_unclosed_earnings: 0,
                    closing_total_equity: total,
                    equity_tie_out_residual: 0,
                }],
            },
            accounts: Vec::new(),
            movements: Vec::new(),
        }
    }

    #[test]
    fn representable_equity_endpoints_cannot_overflow_a_delta() {
        let refusal = EquityRollForwardDiff::between(report(10, i128::MIN), report(11, i128::MAX))
            .unwrap_err();
        assert!(
            refusal
                .message
                .contains("overflow in opening_contributed_equity")
        );
        let boundary =
            EquityRollForwardDiff::between(report(10, -1), report(11, i128::MAX - 1)).unwrap();
        assert_eq!(boundary.units()[0].lines[0].delta, i128::MAX);
        assert_eq!(boundary.units()[0].lines[14].delta, 0);
    }

    #[test]
    fn independent_request_codec_refuses_noncanonical_or_ambiguous_scope() {
        let request = EquityRollForwardDiffRequest {
            before: EquityRollForwardRequest {
                units: vec![2, 1],
                label: "Equity".into(),
                effective_from: fa_time::DateDay(1),
                effective_through: fa_time::DateDay(2),
                known_at: Some(CommitSeq(10)),
                issuance_accounts: vec![VId(300)],
                distribution_accounts: vec![VId(400)],
            },
            after: CommitSeq(11),
        };
        let bytes = request.canonical_bytes().unwrap();
        assert_eq!(
            EquityRollForwardDiffRequest::decode(&bytes)
                .unwrap()
                .before
                .units,
            [1, 2]
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(EquityRollForwardDiffRequest::decode(&trailing).is_err());
        assert!(EquityRollForwardDiffRequest::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut ambiguous = request.clone();
        ambiguous.before.distribution_accounts = ambiguous.before.issuance_accounts.clone();
        assert!(ambiguous.canonical_bytes().is_err());
        let mut duplicate = request.clone();
        duplicate.before.units = vec![1, 1];
        assert!(duplicate.canonical_bytes().is_err());
        let mut excessive = request;
        excessive.before.units = (0..=MAX_SCOPE as u32).collect();
        assert!(excessive.canonical_bytes().is_err());

        let mut w = Writer::new();
        w.bytes(EQUITY_DIFF_REQUEST_FORMAT)
            .u64(10)
            .u64(11)
            .str("Equity")
            .i32(1)
            .i32(2)
            .list(&[2, 1], |w, unit| {
                w.u32(*unit);
            })
            .list(&[300], |w, account| {
                w.u128(*account);
            })
            .list(&[400], |w, account| {
                w.u128(*account);
            });
        assert!(
            EquityRollForwardDiffRequest::decode(&w.finish().unwrap()).is_err(),
            "received scope lists must already be canonical"
        );
    }
}
