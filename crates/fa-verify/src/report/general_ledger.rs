//! A recipient-side detail view of an independently verified roll-forward.
//! The source certificate remains the authenticated accounting question; this
//! projection introduces neither a new certificate nor another trust premise.

use super::{ReportError, VerifiedGeneralLedger, VerifiedReport, cash_flow, failed, hash_parts};

/// Complete general-ledger detail derived from a verified roll-forward source.
///
/// `source_certificate_digest` and `source_output_digest` identify the original
/// verified report. `output` is the separately encoded `fa:general-ledger:v1`
/// view, and `output_digest` uses the `fa:report-output:v1` domain. The source
/// certificate authenticates its roll-forward bytes, not these derived bytes;
/// the latter are reproduced deterministically from the verified source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGeneralLedgerDetail {
    pub ledger: VerifiedGeneralLedger,
    pub output: Vec<u8>,
    pub output_digest: [u8; 32],
    pub source_certificate_digest: [u8; 32],
    pub source_output_digest: [u8; 32],
}

impl VerifiedReport {
    /// Project an **unmodified result of report verification** into complete
    /// general-ledger detail. Only a RollForwardCertificate report is admitted.
    /// This method does not authenticate caller-constructed or modified public
    /// result structs; first use the normal report verifier with recipient-owned
    /// keys and its required outer certificate pin or production receipt.
    ///
    /// Selected zero-activity account/unit cells and every original leg remain
    /// present, including offsetting movements. Within each cell the order is
    /// effective day, recorded sequence, entry digest, then leg index. Running
    /// balances are debit minus credit at the selected recorded prefix in that
    /// effective order, not a claim about balances contemporaneously observed
    /// when each entry was recorded. Pending legs remain excluded by the source
    /// report's posted-only semantics.
    ///
    /// The original output and certificate digests are unchanged. Detail is
    /// bounded to 65,536 cells, 250,000 lines and 64 MiB of canonical output;
    /// exact intermediate running balances and gross turnover must fit i128.
    pub fn general_ledger_detail(&self) -> Result<VerifiedGeneralLedgerDetail, ReportError> {
        let source = self.roll_forward.as_ref().ok_or_else(|| {
            failed(
                "report_view",
                "general-ledger detail requires a verified RollForwardCertificate report",
            )
        })?;
        // A valid roll-forward may have more cells than a detail view permits.
        // Refuse before cloning its potentially large source vectors.
        if source.rows.len() > cash_flow::MAX_CELLS || source.movements.len() > cash_flow::MAX_LINES
        {
            return Err(failed(
                "bounded_input",
                "general-ledger detail exceeds 65,536 cells or 250,000 movements",
            ));
        }
        let ledger = cash_flow::ledger(source.clone())?;
        let output = cash_flow::ledger_bytes(&ledger)?;
        Ok(VerifiedGeneralLedgerDetail {
            ledger,
            output_digest: hash_parts(b"fa:report-output:v1", &[&output]),
            output,
            source_certificate_digest: self.certificate_digest,
            source_output_digest: self.output_digest,
        })
    }
}
