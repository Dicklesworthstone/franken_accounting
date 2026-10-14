//! Saved two-source reconciliation. Content decoding is not verification:
//! both original native closures must replay in the retained book, and the
//! recipient must choose the exact account, cutoff, sequence and age bands.

use fa_model::{DecodeError, Id128, Reader, Writer, domain_digest};

use super::*;
use crate::aging::{AgingCertificate, AgingRequest};
use crate::{ReportCertificate, ReportOutput, ReportSelection, TrialBalanceSelection};

mod workpaper;

pub const MAX_AGING_RECONCILIATION_BYTES: usize = 64 * 1024 * 1024;
const FORMAT: &[u8] = b"fa:aging-reconciliation-certificate:v1";
const OUTPUT: &[u8] = b"fa:aging-control-reconciliation:v1";
const DIGEST: &[u8] = b"fa:aging-reconciliation-digest:v1";

#[derive(Clone, PartialEq, Eq)]
pub struct AgingReconciliationCertificate {
    aging: AgingCertificate,
    control: ReportCertificate,
    producer: VId,
    capability_commitment: [u8; 32],
    output: Vec<u8>,
    digest: [u8; 32],
}

impl core::fmt::Debug for AgingReconciliationCertificate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AgingReconciliationCertificate")
            .field("digest", &self.digest)
            .field("output_len", &self.output.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedAgingReconciliation {
    pub report: AgingReconciliation,
    pub certificate: AgingReconciliationCertificate,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §5.6–§5.7 / §13.6 (the original aging and control prefixes must replay)",
        "retain both original sources and the book history; supply the recipient's exact account, civil cutoff, recorded sequence and age bands",
    )
}

fn bounded(parts: impl IntoIterator<Item = usize>) -> Result<usize, Refusal> {
    let size = parts
        .into_iter()
        .try_fold(0usize, |n, part| n.checked_add(part))
        .ok_or_else(|| invalid("reconciliation encoding size overflow"))?;
    if size > MAX_AGING_RECONCILIATION_BYTES {
        return Err(invalid(
            "complete reconciliation artifact exceeds 64 MiB; no sources or rows were truncated",
        ));
    }
    Ok(size)
}

fn question(
    aging: &AgingCertificate,
    control: &ReportCertificate,
) -> Result<AgingReconciliationRequest, Refusal> {
    let request = aging.request()?;
    let account = request
        .account
        .ok_or_else(|| invalid("reconciliation requires one explicit aging account"))?;
    let source = aging.source();
    if source.book_id != control.book_id
        || source.branch_id != Id128::TRUNK
        || control.branch_id != Id128::TRUNK
        || control.time_selection.is_some()
        || source.known_at != control.known_at
        || source.journal_root != control.journal_root
        || source.journal_leaves != control.journal_leaves
        || control.selection
            != ReportSelection::TrialBalance(TrialBalanceSelection::AsOf(request.effective_through))
    {
        return Err(invalid(
            "aging and control certificates name different books, prefixes or effective selectors",
        ));
    }
    Ok(AgingReconciliationRequest {
        account,
        effective_through: request.effective_through,
        known_at: request.known_at,
        buckets: request.buckets,
    })
}

fn expected_question(
    expected: &AgingReconciliationRequest,
    actual: &AgingReconciliationRequest,
) -> Result<(), Refusal> {
    if expected.known_at.is_none() {
        return Err(selection_error(
            "recipient reconciliation expectations require a fixed known-at, not HEAD",
        ));
    }
    if expected != actual {
        return Err(invalid(
            "reconciliation certificate answers a different recipient-selected question",
        ));
    }
    Ok(())
}

// This emitted comparison is bound alongside both COMPLETE original sources.
// The source aging artifact retains every band, item and application; the
// native closures retain all historical account/unit metadata, including the
// properties not printed in this comparison. No digest replaces source bytes.
fn comparison_bytes(report: &AgingReconciliation) -> Result<Vec<u8>, Refusal> {
    let row_bytes = report
        .rows
        .len()
        .checked_mul(156)
        .ok_or_else(|| invalid("reconciliation row count overflow"))?;
    let a = &report.account;
    let size = bounded([
        4,
        OUTPUT.len(),
        16,
        8,
        4,
        16,
        4,
        a.code.len(),
        4,
        a.name.len(),
        1,
        1,
        1,
        8,
        4,
        row_bytes,
        1,
    ])?;
    let mut w = Writer::with_capacity(size);
    w.bytes(OUTPUT)
        .fixed(&report.aging.book_id.0)
        .u64(report.known_at().0)
        .i32(report.effective_through().0)
        .u128(a.vid.0)
        .str(&a.code)
        .str(&a.name)
        .u8(a.account_type)
        .u8(a.normal_balance)
        .bool(a.is_leaf)
        .u64(a.created_at.0)
        .list(&report.rows, |w, row| {
            w.u32(row.unit_id)
                .i128(row.posted_debits)
                .i128(row.posted_credits)
                .i128(row.pending_debits)
                .i128(row.pending_credits)
                .i128(row.open_debits)
                .i128(row.open_credits)
                .u64(row.open_item_count)
                .i128(row.posted_net)
                .i128(row.open_net)
                .i128(row.difference);
        })
        .bool(report.is_reconciled());
    let bytes = w.finish().map_err(|e| invalid(e.to_string()))?;
    if bytes.len() != size {
        return Err(invalid(
            "reconciliation output size disagrees with its encoding",
        ));
    }
    Ok(bytes)
}

impl AgingReconciliationCertificate {
    #[must_use]
    pub fn aging_source(&self) -> &AgingCertificate {
        &self.aging
    }
    #[must_use]
    pub fn control_source(&self) -> &ReportCertificate {
        &self.control
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
    pub fn request(&self) -> Result<AgingReconciliationRequest, Refusal> {
        question(&self.aging, &self.control)
    }

    fn body_bytes(&self) -> Result<Vec<u8>, Refusal> {
        self.request()?;
        bounded([self.output.len()])?;
        let aging = self.aging.canonical_bytes()?;
        let control = self
            .control
            .canonical_bytes()
            .map_err(|e| invalid(e.to_string()))?;
        // ReportCertificate has public fields; encoding alone is not validation.
        ReportCertificate::decode(&control)?;
        let size = bounded([
            4,
            FORMAT.len(),
            16,
            32,
            4,
            aging.len(),
            4,
            control.len(),
            4,
            self.output.len(),
            32,
        ])?;
        let mut w = Writer::with_capacity(size);
        w.bytes(FORMAT)
            .u128(self.producer.0)
            .fixed(&self.capability_commitment)
            .bytes(&aging)
            .bytes(&control)
            .bytes(&self.output);
        w.finish().map_err(|e| invalid(e.to_string()))
    }

    fn seal(
        aging: AgingCertificate,
        control: ReportCertificate,
        producer: VId,
        capability_commitment: [u8; 32],
        output: Vec<u8>,
    ) -> Result<Self, Refusal> {
        let mut value = Self {
            aging,
            control,
            producer,
            capability_commitment,
            output,
            digest: [0; 32],
        };
        value.digest = domain_digest(DIGEST, &[&value.body_bytes()?]);
        Ok(value)
    }

    /// Bounded canonical container, not a signature or accounting verdict.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut body = self.body_bytes()?;
        if domain_digest(DIGEST, &[&body]) != self.digest {
            return Err(invalid("reconciliation certificate digest mismatch"));
        }
        body.extend_from_slice(&self.digest);
        Ok(body)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        bounded([bytes.len()])?;
        let malformed =
            |e: DecodeError| invalid(format!("malformed reconciliation certificate: {e}"));
        let mut r = Reader::new(bytes);
        if r.bytes(64, "reconciliation format").map_err(malformed)? != FORMAT {
            return Err(invalid("unsupported reconciliation certificate format"));
        }
        let producer = VId(r.u128("reconciliation producer").map_err(malformed)?);
        let capability_commitment = r
            .fixed::<32>("reconciliation capability")
            .map_err(malformed)?;
        let aging = AgingCertificate::decode(
            r.bytes(MAX_AGING_RECONCILIATION_BYTES, "aging source")
                .map_err(malformed)?,
        )?;
        let control = ReportCertificate::decode(
            r.bytes(MAX_AGING_RECONCILIATION_BYTES, "control source")
                .map_err(malformed)?,
        )?;
        let output = r
            .bytes(MAX_AGING_RECONCILIATION_BYTES, "comparison output")
            .map_err(malformed)?
            .to_vec();
        let digest = r.fixed::<32>("reconciliation digest").map_err(malformed)?;
        r.finish().map_err(malformed)?;
        let value = Self {
            aging,
            control,
            producer,
            capability_commitment,
            output,
            digest,
        };
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical reconciliation certificate"));
        }
        Ok(value)
    }
}

fn package(
    report: AgingReconciliation,
    aging: AgingCertificate,
    control: ReportCertificate,
    principal: VId,
    capability: &Capability,
) -> Result<CertifiedAgingReconciliation, Refusal> {
    let output = comparison_bytes(&report)?;
    let commitment = capability
        .commitment()
        .map_err(|e| invalid(e.to_string()))?;
    let certificate =
        AgingReconciliationCertificate::seal(aging, control, principal, commitment, output)?;
    Ok(CertifiedAgingReconciliation {
        report,
        certificate,
    })
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Certify a comparison, including a discrepancy, without posting anything.
    /// Current whole-book read+produce authority is required. HEAD resolves once
    /// before either source is produced; the returned request records that prefix.
    pub fn certify_effective_date_aging_reconciliation(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &AgingReconciliationRequest,
    ) -> Outcome<CertifiedAgingReconciliation> {
        let head = match authorize(self, cx, principal, capability, true)? {
            Ok(head) => head,
            Err(r) => return Ok(Err(r)),
        };
        let request = match fixed_request(request, head) {
            Ok(request) => request,
            Err(r) => return Ok(Err(r)),
        };
        let at = request.known_at.unwrap_or(head);
        let account = match selected_account(self, cx, request.account, at)? {
            Ok(a) => a,
            Err(r) => return Ok(Err(r)),
        };
        let aging_request = AgingRequest {
            account: Some(request.account),
            effective_through: request.effective_through,
            known_at: Some(at),
            buckets: request.buckets,
        };
        let aging =
            match self.certify_effective_date_aging(cx, principal, capability, &aging_request)? {
                Ok(aging) => aging,
                Err(r) => return Ok(Err(r)),
            };
        let query = cx.query();
        let control = match query.with_restriction(|| {
            crate::certificate::certify_report(
                &self.db,
                &query,
                self.context(),
                TrialBalanceSelection::AsOf(request.effective_through).into(),
                Some(at),
            )
        })? {
            Ok(control) => control,
            Err(r) => return Ok(Err(r)),
        };
        let ReportOutput::TrialBalance(balance) = control.report else {
            return Ok(Err(invalid(
                "control source did not produce a trial balance",
            )));
        };
        let report = assemble(account, aging.report, balance)?;
        validate_units(&report, &self.context().units)?;
        let result = package(
            report,
            aging.certificate,
            control.certificate,
            principal,
            capability,
        );
        query.checkpoint().map_err(BookError::Context)?;
        Ok(result)
    }

    /// Reuse saved sources BYTE-FOR-BYTE, never substitute today's HEAD or a
    /// newly generated report with equal totals. A recipient expectation must
    /// independently fix the account, prefix, effective cutoff and age bands.
    pub fn certify_effective_date_aging_reconciliation_from_sources(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        aging: &AgingCertificate,
        control: &ReportCertificate,
        expected: &AgingReconciliationRequest,
    ) -> Outcome<CertifiedAgingReconciliation> {
        if let Err(r) = authorize(self, cx, principal, capability, true)? {
            return Ok(Err(r));
        }
        let report = match self
            .replay_aging_control_sources(cx, principal, capability, aging, control, expected)?
        {
            Ok(report) => report,
            Err(r) => return Ok(Err(r)),
        };
        let result = package(
            report,
            aging.clone(),
            control.clone(),
            principal,
            capability,
        );
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(result)
    }

    fn replay_aging_control_sources(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        aging: &AgingCertificate,
        control: &ReportCertificate,
        expected: &AgingReconciliationRequest,
    ) -> Outcome<AgingReconciliation> {
        let actual = match question(aging, control) {
            Ok(actual) => actual,
            Err(r) => return Ok(Err(r)),
        };
        if let Err(r) = expected_question(expected, &actual) {
            return Ok(Err(r));
        }
        let report = match self.replay_effective_date_aging(cx, principal, capability, aging)? {
            Ok(report) => report,
            Err(r) => return Ok(Err(r)),
        };
        let balance = match self.replay_report(cx, control)? {
            Ok(ReportOutput::TrialBalance(balance)) => balance,
            Ok(_) => {
                return Ok(Err(invalid(
                    "replayed control source is not a trial balance",
                )));
            }
            Err(r) => return Ok(Err(r)),
        };
        let account = match selected_account(self, cx, actual.account, report.known_at)? {
            Ok(account) => account,
            Err(r) => return Ok(Err(invalid(r.message))),
        };
        let report = assemble(account, report, balance)?;
        validate_units(&report, &self.context().units)?;
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(report))
    }

    /// Decoding or repairing a checksum never establishes the accounting claim.
    /// Replay both native sources, then compare every output byte; the saved
    /// producer/capability metadata does not authorize today's recipient.
    pub fn replay_effective_date_aging_reconciliation(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &AgingReconciliationCertificate,
        expected: &AgingReconciliationRequest,
    ) -> Outcome<AgingReconciliation> {
        if let Err(r) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(r));
        }
        if let Err(r) = certificate.canonical_bytes() {
            return Ok(Err(r));
        }
        let report = match self.replay_aging_control_sources(
            cx,
            principal,
            capability,
            &certificate.aging,
            &certificate.control,
            expected,
        )? {
            Ok(report) => report,
            Err(r) => return Ok(Err(r)),
        };
        let output = match comparison_bytes(&report) {
            Ok(output) => output,
            Err(r) => return Ok(Err(r)),
        };
        if output != certificate.output {
            return Ok(Err(invalid(
                "replayed aging/control comparison differs from its saved output",
            )));
        }
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(report))
    }
}
