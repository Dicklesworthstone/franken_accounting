//! Independent recomputation of balances, statements, open items and aging (plan §13.3).
//!
//! Report bundles disclose the complete signed checkpoint prefix, including
//! every payload that derives its selectors. The verifier reconstructs the
//! certificate's older entries-only prefix, journaled chart and fiscal periods,
//! migration visibility, and pending resolutions before comparing every output
//! byte. Native database read attestations are retained, but are not an outsider
//! proof and never supply the arithmetic or metadata used here.
//!
//! Version 1 supports sequence-selected native trial balances and v4 native
//! statements using an independently supplied numeric unit universe. The latter
//! explicitly treats the definition and unit list as report parameters, not
//! authenticated registration or approval. Bundle version 2 carries the exact
//! registry closure and requires a recipient certificate pin or signed production
//! receipt to authenticate that definition and registry closure. Version 2 also
//! supports native v3 OpenItems and ExplainBalance with complete history and
//! historical account metadata. ExplainBalance also binds whole-period register
//! commitments and committed evidence/lineage under its fifth reason-code registry.
//! Effective-date AgingCertificate v1 wraps a complete v3 OpenItems source;
//! its cutoff is applied before settlement/reversal netting, and its outer
//! digest binds every age band and output row. AgingReconciliationCertificate v1
//! additionally binds an independently recomputed stock trial balance at the
//! same prefix and cutoff; nonzero per-unit differences are verified data.
//! DueDateAgingCertificate v1 independently decodes journaled maturity terms,
//! relieves the earliest installments, and retains every unscheduled open item.
//! Its reconciliation wrapper compares scheduled and unscheduled totals to the
//! same native stock fold and counts distinct original open items.
//! RollForwardCertificate v1 wraps a native as-of trial balance and recomputes
//! opening, every classified posted movement, closing and exact leg citations.
//! Direct CashFlowCertificate v1 further reproduces the complete general ledger,
//! per-entry gross cash turnover and selected native-unit stocks. Its policy
//! wrapper additionally derives every assignment from original counterpart legs
//! and explicit overrides; economic classification and approval are not judged.
//! Equity roll-forwards independently reproduce the complete equity/income
//! chart, owner movements, closing transfers and opening-to-closing identity.
//! Native statement comparisons replay both historical statements before
//! deriving every line delta and zero-balance chart mapping change. Both
//! sources retain one exact shared registry closure and selected definition.
//! Summary trial balances retain the complete native source and independently
//! reconstruct selected subtrees, zero-activity leaf coverage, historical
//! metadata and promoted-account balances under the outer certificate digest.
//! Native v2 trial balances, v3 reports and v4
//! statements can additionally prove their retained tick-bucket
//! selection from the complete TimeControl history. Migrated/genesis-policy
//! histories remain unsupported. Native v8
//! dimension trial balances reconstruct declarations and closes from the signed
//! journal, then fold only legs tagged with the authenticated value hierarchy.
//! A filtered view need not balance across the selected legs. The scope is accounting
//! recomputation, not economic truth, source-document authenticity, journaled
//! registry activation, or database read attestations.
//!
//! Version 3 independently replays v10 functional trial balances and v5
//! functional balance sheets and income statements under direct
//! SpotClose/PeriodAverage laws with exact Rate bodies, signed intake receipts,
//! six registries and explicit Book parameters. Recipient pins or production
//! receipts authenticate those parameters; Book genesis is not proved.

mod aging;
mod cash_flow;
mod cash_flow_split;
mod dimension;
mod due_date;
mod due_date_reconciliation;
mod equity;
mod explain;
mod functional;
mod indirect_cash_flow;
mod lots;
mod metadata;
mod open_items;
mod reconciliation;
mod registry;
mod roll_forward;
mod statement;
mod statement_diff;
mod summary;
mod temporal;
pub use aging::{
    VerifiedAgedOpenItem, VerifiedAging, VerifiedAgingAmounts, VerifiedAgingBand,
    VerifiedAgingCell, VerifiedAgingTotal,
};
pub use cash_flow::{
    CashFlowAccountRule, CashFlowActivity, CashFlowAssignment, CashFlowDecisionBasis,
    CashFlowDefinition, CashFlowPolicy, CashFlowPolicyDecision, CashFlowSection, CashFlowUnit,
    GeneralLedgerCell, GeneralLedgerLine, VerifiedCashFlow, VerifiedCashFlowPolicy,
    VerifiedGeneralLedger,
};
pub use cash_flow_split::{
    CashFlowLegSplit, CashFlowPortion, CashFlowSplitDefinition, VerifiedSplitCashFlow,
};
pub use dimension::VerifiedDimensionSelection;
pub use due_date::{
    VerifiedDueDateAgedItem, VerifiedDueDateAging, VerifiedUnscheduled, VerifiedUnscheduledItem,
};
pub use due_date_reconciliation::VerifiedDueDateAgingReconciliation;
pub use equity::{
    EquityActivityKind, EquityMovement, EquityRollForwardUnit, VerifiedEquityRollForward,
};
pub use explain::{
    ExplanationCell, ExplanationCellChange, ExplanationColumn, ExplanationContribution,
    ExplanationEvidence, ExplanationSupersession, VerifiedBalanceExplanation,
};
pub use functional::{
    VerifiedFunctionalCell, VerifiedFunctionalStatement, VerifiedFunctionalTrialBalance,
};
pub use indirect_cash_flow::{
    AdjustmentCategory, AdjustmentSign, IndirectCashFlowAdjustment, IndirectCashFlowContribution,
    IndirectCashFlowDefinition, IndirectCashFlowUnit, VerifiedCashFlowBasis,
    VerifiedIndirectCashFlow,
};
pub use lots::{VerifiedLot, VerifiedLotAmount, VerifiedLotRelief, VerifiedLots};
pub(crate) use metadata::{DeclaredAccount, declared_chart};
pub use open_items::VerifiedOpenItemAccount as VerifiedReportAccount;
pub use open_items::{
    OpenItemBalanceLimit, OpenItemUnitPolicy, VerifiedApplication, VerifiedOpenItem,
    VerifiedOpenItemAccount, VerifiedOpenItems,
};
pub use reconciliation::{VerifiedAgingReconciliation, VerifiedAgingReconciliationRow};
pub use registry::Reason as ExplanationReason;
pub use roll_forward::{
    RollForwardAccount, RollForwardBucket, RollForwardMovement, RollForwardRow, VerifiedRollForward,
};
pub use statement::{StatementColumn, StatementLine, StatementMapping, VerifiedStatement};
pub use statement_diff::{StatementLineChange, StatementMappingChange, VerifiedStatementDiff};
pub use summary::{SummaryScope, VerifiedSummaryGroup, VerifiedSummaryTrialBalance};
pub use temporal::{TimeObservation, VerifiedInstantSelection};
#[cfg(test)]
mod tests;

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::blake3::hash_parts;
use crate::bundle::ReceiptFacts;
use crate::checkpoint::{SignedCheckpoint, verify_checkpoint};
use crate::codec::{DecodeError, Reader, Writer};
use crate::envelope::{KIND_ENTRY, MAX_RECORD_BYTES, check_record};
use crate::proof::{Checkpoint, VerifyError, verify_prefix};
use crate::tree::{leaf_hash, root_of};

pub const REPORT_BUNDLE_FORMAT: &[u8] = b"fa:report-bundle:v1";
pub const MAX_REPORT_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
const CERTIFICATE_FORMAT: &[u8; 24] = b"fa:report-certificate:v1";
const INSTANT_CERTIFICATE_FORMAT: &[u8; 24] = b"fa:report-certificate:v2";
const OPEN_ITEMS_CERTIFICATE_FORMAT: &[u8; 24] = b"fa:report-certificate:v3";
const STATEMENT_CERTIFICATE_FORMAT: &[u8; 24] = b"fa:report-certificate:v4";
const FUNCTIONAL_STATEMENT_CERTIFICATE_FORMAT: &[u8; 24] = b"fa:report-certificate:v5";
const DIMENSION_CERTIFICATE_FORMAT: &[u8; 24] = b"fa:report-certificate:v8";
const DIMENSION_OUTPUT_FORMAT: &[u8] = b"fa:dimension-trial-balance:v1";
const FUNCTIONAL_CERTIFICATE_FORMAT: &[u8; 25] = b"fa:report-certificate:v10";
const OUTPUT_FORMAT: &[u8; 19] = b"fa:trial-balance:v1";
const MAX_ROWS: usize = 1 << 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportError {
    /// The failed predicate, suitable for machine-readable verification output.
    pub predicate: &'static str,
    pub detail: String,
}
impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.predicate, self.detail)
    }
}
impl core::error::Error for ReportError {}
impl From<DecodeError> for ReportError {
    fn from(error: DecodeError) -> Self {
        failed("canonical_encoding", error.to_string())
    }
}
impl From<VerifyError> for ReportError {
    fn from(error: VerifyError) -> Self {
        failed("authenticated_prefix", error.to_string())
    }
}
fn failed(predicate: &'static str, detail: impl Into<String>) -> ReportError {
    ReportError {
        predicate,
        detail: detail.into(),
    }
}

/// Each row is independently reconstructed from authenticated entry payloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportRow {
    pub account: u128,
    pub code: String,
    pub name: String,
    pub account_type: u8,
    pub unit: u32,
    pub debits: i128,
    pub credits: i128,
    pub debits_pending: i128,
    pub credits_pending: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedReport {
    pub scope: &'static str,
    /// Selected summary groups and complete historical posting-leaf coverage.
    /// `rows` still contains the entire native source, not only these groups.
    pub summary: Option<VerifiedSummaryTrialBalance>,
    pub bundle_digest: [u8; 32],
    pub certificate_digest: [u8; 32],
    pub output_digest: [u8; 32],
    pub checkpoint: SignedCheckpoint,
    pub known_at: u64,
    /// Complete authenticated tick-bucket resolution, when the report was
    /// selected by an instant. This proves no external UTC or genesis policy.
    pub time_selection: Option<VerifiedInstantSelection>,
    pub effective_through: Option<i32>,
    pub activity: bool,
    pub periods: Vec<String>,
    pub rows: Vec<ReportRow>,
    /// Present for independently reconstructed native financial statements.
    pub statement: Option<VerifiedStatement>,
    /// Two complete native statements and their exact historical bridge.
    pub statement_diff: Option<VerifiedStatementDiff>,
    /// Authenticated dimension hierarchy and exact values included in the fold.
    pub dimension: Option<VerifiedDimensionSelection>,
    /// Present for independently reconstructed native open-item reports.
    pub open_items: Option<VerifiedOpenItems>,
    /// Complete native-cost lot schedule and every recorded relief application.
    /// This does not assert independent admission under a disposal cost-flow law.
    pub lots: Option<VerifiedLots>,
    /// Exact period cells, whole-period commitment, contributions and history.
    pub explanation: Option<VerifiedBalanceExplanation>,
    /// Present for independently reconstructed historical effective-date aging.
    pub aging: Option<VerifiedAging>,
    /// Contractual installments and unscheduled items from journaled maturity terms.
    pub due_date_aging: Option<VerifiedDueDateAging>,
    /// Both source folds and their selected-account consistency comparison.
    pub aging_reconciliation: Option<VerifiedAgingReconciliation>,
    /// Due-date installments and unscheduled amounts compared to native stock.
    pub due_date_aging_reconciliation: Option<VerifiedDueDateAgingReconciliation>,
    /// Complete account/unit lead schedule with every classified posted leg.
    pub roll_forward: Option<VerifiedRollForward>,
    /// Complete direct cash flow, with independently derived policy decisions
    /// when its outer certificate carries a counterpart policy.
    pub cash_flow: Option<VerifiedCashFlow>,
    pub split_cash_flow: Option<VerifiedSplitCashFlow>,
    pub indirect_cash_flow: Option<VerifiedIndirectCashFlow>,
    /// Complete Statement of Changes in Equity, including owner role inputs.
    pub equity_roll_forward: Option<VerifiedEquityRollForward>,
    /// Functional cells independently repriced from original Rate evidence.
    pub functional_trial_balance: Option<VerifiedFunctionalTrialBalance>,
    /// Financial-statement rows computed from independently repriced base amounts.
    pub functional_statement: Option<VerifiedFunctionalStatement>,
    /// Whether report units are recipient parameters or come from a
    /// certificate-bound registry authenticated by a receipt or independent pin.
    pub unit_universe_source: &'static str,
    /// Exact canonical report bytes, independently reconstructed.
    pub output: Vec<u8>,
    pub checked_records: usize,
    pub receipt: Option<ReceiptFacts>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Selection {
    Periods(Vec<String>),
    AsOf(i32),
    Activity(Vec<String>),
    Statement(statement::Selection),
    OpenItems(Option<u128>),
    ExplainBalance { account: u128, period: String },
}
struct Certificate<'a> {
    book: [u8; 16],
    branch: [u8; 16],
    known_at: u64,
    time_selection: Option<VerifiedInstantSelection>,
    selection: Selection,
    dimension: Option<dimension::Selection>,
    functional: bool,
    registry_digest: [u8; 32],
    journal_root: [u8; 32],
    leaves: u64,
    output: &'a [u8],
    output_digest: [u8; 32],
    digest: [u8; 32],
}
fn text<'a>(r: &mut Reader<'a>, max: usize, field: &'static str) -> Result<&'a str, ReportError> {
    std::str::from_utf8(r.bytes(max, field)?)
        .map_err(|_| failed("canonical_encoding", format!("{field} is not UTF-8")))
}
fn strings(r: &mut Reader<'_>, field: &'static str) -> Result<Vec<String>, ReportError> {
    let n = r.count(65_536, 4, field)?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(text(r, 128, field)?.to_string());
    }
    if out.iter().any(String::is_empty) || !out.windows(2).all(|p| p[0] < p[1]) {
        return Err(failed(
            "canonical_encoding",
            "period codes must be nonempty and strictly ordered",
        ));
    }
    Ok(out)
}
fn certificate(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    let mut r = Reader::new(bytes);
    let functional_trial_balance = bytes.starts_with(FUNCTIONAL_CERTIFICATE_FORMAT);
    let format = if functional_trial_balance {
        r.fixed::<25>("certificate.format")?.to_vec()
    } else {
        r.fixed::<24>("certificate.format")?.to_vec()
    };
    let functional_statement = format.as_slice() == FUNCTIONAL_STATEMENT_CERTIFICATE_FORMAT;
    let functional = functional_trial_balance || functional_statement;
    let statement = format.as_slice() == STATEMENT_CERTIFICATE_FORMAT || functional_statement;
    let instant = format.as_slice() == INSTANT_CERTIFICATE_FORMAT;
    let dimension = format.as_slice() == DIMENSION_CERTIFICATE_FORMAT;
    let open_items = format.as_slice() == OPEN_ITEMS_CERTIFICATE_FORMAT;
    if format.as_slice() != CERTIFICATE_FORMAT
        && !statement
        && !instant
        && !dimension
        && !open_items
        && !functional
    {
        return Err(failed(
            "supported_report",
            "expected a native v1/v2 trial balance, v3 OpenItems/ExplainBalance, v4 statement, v5 functional statement, v8 dimension trial balance, or v10 functional trial balance",
        ));
    }
    for (field, expected) in [
        ("certificate.scope", "fa-fold-over-prefix"),
        ("certificate.authority", "embedded-owner"),
    ] {
        if text(&mut r, 64, field)? != expected {
            return Err(failed("supported_report", field));
        }
    }
    let output_format = text(&mut r, 64, "certificate.output_format")?;
    let book = r.fixed("certificate.book")?;
    let branch = r.fixed("certificate.branch")?;
    let known_at = r.u64("certificate.known_at")?;
    let selector = r.u8("certificate.selector")?;
    let selector = if functional_trial_balance {
        if selector != 8 {
            return Err(failed(
                "supported_report",
                "native v10 requires a functional selector",
            ));
        }
        r.u8("certificate.functional.selection")?
    } else if dimension {
        if selector != 6 {
            return Err(failed(
                "supported_report",
                "native v8 requires a dimension selector",
            ));
        }
        r.u8("certificate.dimension.selection")?
    } else {
        selector
    };
    let selection = if statement {
        if selector != if functional_statement { 3 } else { 2 } {
            return Err(failed(
                "supported_report",
                "native v4/v5 requires its native/functional statement selector",
            ));
        }
        let definition = r.bytes(64 * 1024, "certificate.definition")?;
        let periods = strings(&mut r, "certificate.periods")?;
        let comparative = strings(&mut r, "certificate.comparative")?;
        Selection::Statement(statement::Selection::new(definition, periods, comparative)?)
    } else if open_items {
        match selector {
            0 if output_format == "fa:balance-explanation:v1" => {
                let account = r.u128("certificate.account")?;
                let period = text(&mut r, 128, "certificate.period")?.to_string();
                if period.is_empty() {
                    return Err(failed(
                        "report_selector",
                        "balance explanation period is empty",
                    ));
                }
                Selection::ExplainBalance { account, period }
            }
            1 if output_format == "fa:open-items:v1" => Selection::OpenItems(
                r.present("certificate.account")?
                    .then(|| r.u128("certificate.account"))
                    .transpose()?,
            ),
            _ => {
                return Err(failed(
                    "supported_report",
                    "native v3 selector and output format disagree",
                ));
            }
        }
    } else {
        match selector {
            0 => Selection::Periods(strings(&mut r, "certificate.periods")?),
            1 => Selection::AsOf(r.i32("certificate.as_of")?),
            2 => Selection::Activity(strings(&mut r, "certificate.periods")?),
            _ => return Err(failed("supported_report", "unknown trial-balance selector")),
        }
    };
    let expected_format = match &selection {
        Selection::ExplainBalance { .. } => "fa:balance-explanation:v1",
        Selection::OpenItems(_) => "fa:open-items:v1",
        Selection::Statement(_) if functional => "fa:functional-statement:v1",
        Selection::Statement(_) => "fa:statement:v1",
        _ if dimension => "fa:dimension-trial-balance:v1",
        _ if functional => "fa:functional-trial-balance:v1",
        _ => "fa:trial-balance:v1",
    };
    if output_format != expected_format {
        return Err(failed(
            "supported_report",
            "certificate output format disagrees with its selector",
        ));
    }
    if matches!(&selection, Selection::Periods(p) | Selection::Activity(p) if p.is_empty()) {
        return Err(failed("report_selector", "period selection is empty"));
    }
    let dimension_selection = if dimension {
        Some(dimension::Selection {
            dimension: text(&mut r, 128, "certificate.dimension")?.to_string(),
            value: text(&mut r, 128, "certificate.dimension_value")?.to_string(),
        })
    } else {
        None
    };
    let registry_digest = r.fixed("certificate.registry_digest")?;
    let journal_root = r.fixed("certificate.journal_root")?;
    let leaves = r.u64("certificate.leaves")?;
    let expected_inputs = if dimension || functional { 8 } else { 7 };
    let inputs = r.count(expected_inputs, 4, "certificate.native_inputs")?;
    if inputs != expected_inputs {
        return Err(failed(
            "certificate_closure",
            "certificate must retain every native input attestation for its report family",
        ));
    }
    for _ in 0..inputs {
        r.bytes(1024 * 1024, "certificate.native_input")?;
    }
    let output = r.bytes(MAX_REPORT_BUNDLE_BYTES, "certificate.output")?;
    let output_digest = r.fixed("certificate.output_digest")?;
    let time_selection = if instant
        || (statement || dimension || open_items || functional)
            && r.present("certificate.time_selection")?
    {
        Some(VerifiedInstantSelection::read(&mut r)?)
    } else {
        None
    };
    let digest = r.fixed("certificate.digest")?;
    r.finish("report certificate")?;
    if hash_parts(b"fa:report-output:v1", &[output]) != output_digest {
        return Err(failed(
            "output_digest",
            "certificate output differs from its commitment",
        ));
    }
    if hash_parts(&format, &[&bytes[..bytes.len() - 32]]) != digest {
        return Err(failed(
            "certificate_digest",
            "certificate bytes differ from their commitment",
        ));
    }
    Ok(Certificate {
        book,
        branch,
        known_at,
        time_selection,
        selection,
        dimension: dimension_selection,
        functional,
        registry_digest,
        journal_root,
        leaves,
        output,
        output_digest,
        digest,
    })
}

/// Verify an offline report against recipient-owned keys and, when supplied,
/// an exact independently selected checkpoint. An optional detached receipt is
/// verified over this report bundle's digest using those same trusted keys.
/// An embedded checkpoint is never a trust anchor merely because it is present.
/// Version-2 reports require a receipt through this convenience API; use
/// verify_report_expected to supply a recipient-selected certificate instead.
/// Version-1 statements require verify_statement_report and recipient unit IDs.
pub fn verify_report(
    bundle: &[u8],
    trusted_keys: &[[u8; 32]],
    expected_checkpoint: Option<&Checkpoint>,
    receipt: Option<&[u8]>,
) -> Result<VerifiedReport, ReportError> {
    verify_report_expected(bundle, trusted_keys, expected_checkpoint, receipt, None)
}

/// Verify a report with an independently selected source certificate digest.
/// For version-2 native reports, either this recipient-owned pin or a valid
/// production receipt is required: a checkpoint authenticates the journal, but cannot by
/// itself authenticate the certificate's definition and complete unit registry.
/// Never derive this expected digest from the untrusted bundle being verified.
pub fn verify_report_expected(
    bundle: &[u8],
    trusted_keys: &[[u8; 32]],
    expected_checkpoint: Option<&Checkpoint>,
    receipt: Option<&[u8]>,
    expected_certificate: Option<&[u8; 32]>,
) -> Result<VerifiedReport, ReportError> {
    verify_report_with(
        bundle,
        trusted_keys,
        expected_checkpoint,
        receipt,
        expected_certificate,
        verify_checkpoint,
    )
}

/// Verify a complete lot schedule with a recipient-selected cost base unit.
/// The base is a report premise, not an authenticated Book-genesis assertion.
/// Existing checkpoint, outer-certificate pin and receipt requirements remain
/// unchanged. This entry point refuses every report family other than lots.
pub fn verify_lots_report_expected(
    bundle: &[u8],
    trusted_keys: &[[u8; 32]],
    expected_checkpoint: Option<&Checkpoint>,
    receipt: Option<&[u8]>,
    expected_base_unit: u32,
    expected_certificate: Option<&[u8; 32]>,
) -> Result<VerifiedReport, ReportError> {
    verify_report_with_lots_input(
        bundle,
        trusted_keys,
        expected_checkpoint,
        receipt,
        expected_certificate,
        None,
        Some(expected_base_unit),
        verify_checkpoint,
    )
}

/// Recompute a v4 statement with a recipient-owned complete numeric unit list.
/// For version-1 bundles the definition is a report parameter: this authenticates
/// the underlying journal and arithmetic, not unit registration or definition
/// approval. Version-2 bundles still require a signed receipt, and the supplied
/// IDs must exactly match the authenticated registry closure.
pub fn verify_statement_report(
    bundle: &[u8],
    trusted_keys: &[[u8; 32]],
    expected_checkpoint: Option<&Checkpoint>,
    receipt: Option<&[u8]>,
    units: &[u32],
) -> Result<VerifiedReport, ReportError> {
    verify_statement_report_expected(
        bundle,
        trusted_keys,
        expected_checkpoint,
        receipt,
        units,
        None,
    )
}

/// The explicit-unit verifier with an independently selected certificate pin.
/// Both the pin and any supplied receipt are checked; neither bypasses the other.
pub fn verify_statement_report_expected(
    bundle: &[u8],
    trusted_keys: &[[u8; 32]],
    expected_checkpoint: Option<&Checkpoint>,
    receipt: Option<&[u8]>,
    units: &[u32],
    expected_certificate: Option<&[u8; 32]>,
) -> Result<VerifiedReport, ReportError> {
    verify_report_with_inputs(
        bundle,
        trusted_keys,
        expected_checkpoint,
        receipt,
        expected_certificate,
        Some(units),
        verify_checkpoint,
    )
}

fn validate_units(units: &[u32]) -> Result<(), ReportError> {
    if units.is_empty() || units.len() > 4096 || !units.windows(2).all(|p| p[0] < p[1]) {
        return Err(failed(
            "statement_units",
            "supply 1..=4096 strictly ascending, distinct recipient-owned unit identifiers",
        ));
    }
    Ok(())
}

fn verify_report_with(
    bundle: &[u8],
    trusted_keys: &[[u8; 32]],
    expected_checkpoint: Option<&Checkpoint>,
    receipt: Option<&[u8]>,
    expected_certificate: Option<&[u8; 32]>,
    authenticate: impl FnOnce(&[u8], &[[u8; 32]]) -> Result<SignedCheckpoint, VerifyError>,
) -> Result<VerifiedReport, ReportError> {
    verify_report_with_inputs(
        bundle,
        trusted_keys,
        expected_checkpoint,
        receipt,
        expected_certificate,
        None,
        authenticate,
    )
}

#[cfg(test)]
fn verify_report_with_units(
    bundle: &[u8],
    trusted_keys: &[[u8; 32]],
    expected_checkpoint: Option<&Checkpoint>,
    receipt: Option<&[u8]>,
    units: Option<&[u32]>,
    authenticate: impl FnOnce(&[u8], &[[u8; 32]]) -> Result<SignedCheckpoint, VerifyError>,
) -> Result<VerifiedReport, ReportError> {
    verify_report_with_inputs(
        bundle,
        trusted_keys,
        expected_checkpoint,
        receipt,
        None,
        units,
        authenticate,
    )
}

fn verify_report_with_inputs(
    bundle: &[u8],
    trusted_keys: &[[u8; 32]],
    expected_checkpoint: Option<&Checkpoint>,
    receipt: Option<&[u8]>,
    expected_certificate: Option<&[u8; 32]>,
    recipient_units: Option<&[u32]>,
    authenticate: impl FnOnce(&[u8], &[[u8; 32]]) -> Result<SignedCheckpoint, VerifyError>,
) -> Result<VerifiedReport, ReportError> {
    verify_report_with_lots_input(
        bundle,
        trusted_keys,
        expected_checkpoint,
        receipt,
        expected_certificate,
        recipient_units,
        None,
        authenticate,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_report_with_lots_input(
    bundle: &[u8],
    trusted_keys: &[[u8; 32]],
    expected_checkpoint: Option<&Checkpoint>,
    receipt: Option<&[u8]>,
    expected_certificate: Option<&[u8; 32]>,
    recipient_units: Option<&[u32]>,
    recipient_base_unit: Option<u32>,
    authenticate: impl FnOnce(&[u8], &[[u8; 32]]) -> Result<SignedCheckpoint, VerifyError>,
) -> Result<VerifiedReport, ReportError> {
    if let Some(units) = recipient_units {
        validate_units(units)?;
    }
    if bundle.len() > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed("bounded_input", "report bundle exceeds 64 MiB"));
    }
    let mut r = Reader::new(bundle);
    if r.bytes(64, "report_bundle.format")? != REPORT_BUNDLE_FORMAT {
        return Err(failed(
            "supported_report",
            "unsupported report bundle domain",
        ));
    }
    let major = r.u16("report_bundle.major")?;
    if !matches!(major, 1..=3) || r.u16("report_bundle.minor")? != 0 {
        return Err(failed(
            "supported_report",
            "unsupported report bundle format",
        ));
    }
    let certificate_bytes = r.bytes(MAX_REPORT_BUNDLE_BYTES, "report_bundle.certificate")?;
    let lots = if lots::recognizes(certificate_bytes) {
        Some(lots::decode(certificate_bytes)?)
    } else {
        None
    };
    match (&lots, recipient_base_unit) {
        (Some(certificate), Some(base)) if certificate.base_unit == base => {}
        (None, None) => {}
        _ => {
            return Err(failed(
                "lots_base_unit",
                "lot reports require the recipient's matching expected base unit; that premise is not applicable to another report family",
            ));
        }
    }
    let summary = if summary::recognizes(certificate_bytes) {
        Some(summary::decode(certificate_bytes)?)
    } else {
        None
    };
    let statement_diff = if statement_diff::recognizes(certificate_bytes) {
        Some(statement_diff::decode(certificate_bytes)?)
    } else {
        None
    };
    // Each supported composition has a fixed depth. Equity has one roll-forward
    // source; split cash flow also retains its original roll-forward directly,
    // and policy cash flow has one direct-cash source over a roll-forward.
    // No generic recursive certificate dispatch is accepted.
    let equity = if equity::recognizes(certificate_bytes) {
        Some(equity::decode(certificate_bytes)?)
    } else {
        None
    };
    let indirect_cash = if indirect_cash_flow::recognizes(certificate_bytes) {
        Some(indirect_cash_flow::decode(certificate_bytes)?)
    } else {
        None
    };
    let cash_certificate_bytes = indirect_cash
        .as_ref()
        .map_or(certificate_bytes, |value| value.source);
    let cash_policy = if cash_flow::policy::recognizes(cash_certificate_bytes) {
        Some(cash_flow::policy::decode(cash_certificate_bytes)?)
    } else {
        None
    };
    let split_cash = if cash_flow_split::recognizes(cash_certificate_bytes) {
        Some(cash_flow_split::decode(cash_certificate_bytes)?)
    } else {
        None
    };
    let cash_bytes = cash_policy
        .as_ref()
        .map_or(cash_certificate_bytes, |value| value.source);
    let cash = if cash_flow::recognizes(cash_bytes) {
        Some(cash_flow::decode(cash_bytes)?)
    } else {
        None
    };
    let roll_forward_bytes = cash
        .as_ref()
        .map(|value| value.source)
        .or_else(|| equity.as_ref().map(|value| value.source))
        .or_else(|| split_cash.as_ref().map(|value| value.source))
        .unwrap_or(certificate_bytes);
    let reconciliation = if reconciliation::recognizes(certificate_bytes) {
        Some(reconciliation::decode(certificate_bytes)?)
    } else {
        None
    };
    let due_date_reconciliation = if due_date_reconciliation::recognizes(certificate_bytes) {
        Some(due_date_reconciliation::decode(certificate_bytes)?)
    } else {
        None
    };
    let aging = if let Some(value) = &reconciliation {
        Some(aging::decode(value.aging)?)
    } else if aging::recognizes(certificate_bytes) {
        Some(aging::decode(certificate_bytes)?)
    } else {
        None
    };
    let due_date = if let Some(value) = &due_date_reconciliation {
        Some(due_date::decode(value.aging)?)
    } else if due_date::recognizes(certificate_bytes) {
        Some(due_date::decode(certificate_bytes)?)
    } else {
        None
    };
    let roll_forward = if roll_forward::recognizes(roll_forward_bytes) {
        Some(roll_forward::decode(roll_forward_bytes)?)
    } else {
        None
    };
    let source = aging
        .as_ref()
        .map(|value| value.source)
        .or_else(|| due_date.as_ref().map(|value| value.source))
        .or_else(|| roll_forward.as_ref().map(|value| value.source))
        .or_else(|| statement_diff.as_ref().map(|value| value.after))
        .or_else(|| summary.as_ref().map(|value| value.source))
        .or_else(|| lots.as_ref().map(|value| value.source))
        .unwrap_or(certificate_bytes);
    let cert = certificate(source)?;
    if lots.is_some()
        && (!matches!(cert.selection, Selection::OpenItems(Some(_)))
            || cert.time_selection.is_some()
            || cert.branch != [0; 16]
            || cert.dimension.is_some()
            || cert.functional)
    {
        return Err(failed(
            "supported_report",
            "lots require a sequence-selected trunk OpenItems source for one account",
        ));
    }
    if summary.is_some()
        && (cert.branch != [0; 16]
            || cert.time_selection.is_some()
            || cert.dimension.is_some()
            || cert.functional
            || !matches!(
                cert.selection,
                Selection::Periods(_) | Selection::AsOf(_) | Selection::Activity(_)
            ))
    {
        return Err(failed(
            "supported_report",
            "summary v1 requires a sequence-selected trunk native trial balance",
        ));
    }
    let before_statement = statement_diff
        .as_ref()
        .map(|comparison| certificate(comparison.before))
        .transpose()?;
    if let Some(before) = &before_statement {
        statement_diff::bind(before, &cert)?;
    }
    if (aging.is_some() || due_date.is_some())
        && (!matches!(cert.selection, Selection::OpenItems(_)) || cert.time_selection.is_some())
    {
        return Err(failed(
            "supported_report",
            "aging requires a sequence-selected native OpenItems source",
        ));
    }
    if let Some(request) = &roll_forward
        && (cert.selection != Selection::AsOf(request.effective_through)
            || cert.time_selection.is_some()
            || cert.dimension.is_some()
            || cert.functional)
    {
        return Err(failed(
            "supported_report",
            "roll-forward requires a sequence-selected native trial balance as of its closing day",
        ));
    }
    let control = reconciliation
        .as_ref()
        .or(due_date_reconciliation.as_ref())
        .map(|value| certificate(value.control))
        .transpose()?;
    if let (Some(aging), Some(control)) = (&aging, &control) {
        reconciliation::bind(aging, &cert, control)?;
    }
    if let (Some(aging), Some(control)) = (&due_date, &control) {
        due_date_reconciliation::bind(aging, &cert, control)?;
    }
    let certificate_digest = indirect_cash
        .as_ref()
        .map(|value| value.digest)
        .or_else(|| equity.as_ref().map(|value| value.digest))
        .or_else(|| cash_policy.as_ref().map(|value| value.digest))
        .or_else(|| cash.as_ref().map(|value| value.digest))
        .or_else(|| split_cash.as_ref().map(|value| value.digest))
        .or_else(|| reconciliation.as_ref().map(|value| value.digest))
        .or_else(|| due_date_reconciliation.as_ref().map(|value| value.digest))
        .or_else(|| aging.as_ref().map(|value| value.digest))
        .or_else(|| due_date.as_ref().map(|value| value.digest))
        .or_else(|| roll_forward.as_ref().map(|value| value.digest))
        .or_else(|| statement_diff.as_ref().map(|value| value.digest))
        .or_else(|| summary.as_ref().map(|value| value.digest))
        .or_else(|| lots.as_ref().map(|value| value.digest))
        .unwrap_or(cert.digest);
    if cert.functional != (major == 3) {
        return Err(failed(
            "supported_report",
            "functional v5/v10 certificates require version-3 bundles; v1/v2 report semantics are unchanged",
        ));
    }
    let is_statement = matches!(cert.selection, Selection::Statement(_));
    let is_open_items = matches!(cert.selection, Selection::OpenItems(_));
    let is_explanation = matches!(cert.selection, Selection::ExplainBalance { .. });
    if ((!is_statement || cert.functional) && recipient_units.is_some())
        || (!is_statement
            && !is_open_items
            && !is_explanation
            && roll_forward.is_none()
            && summary.is_none()
            && major == 2)
    {
        return Err(failed(
            "supported_report",
            "registry bundles require a native statement, OpenItems, ExplainBalance, summary, roll-forward, equity or direct cash flow; explicit unit universes require a v4 statement",
        ));
    }
    if (is_open_items
        || is_explanation
        || roll_forward.is_some()
        || statement_diff.is_some()
        || summary.is_some())
        && major != 2
    {
        return Err(failed(
            "registry_closure",
            "native v3 reports, summaries, roll-forwards, equity, direct cash flows and statement comparisons require a version-2 bundle with their authenticated complete registry closure",
        ));
    }
    if is_statement && major == 1 && recipient_units.is_none() {
        return Err(failed(
            "statement_units",
            "a version-1 native statement requires independently supplied unit identifiers; use verify_statement_report or fa-verify report --units",
        ));
    }
    if expected_certificate.is_some_and(|expected| *expected != certificate_digest) {
        return Err(failed(
            "recipient_certificate",
            "report uses another certificate than the recipient requested",
        ));
    }
    if major >= 2 && receipt.is_none() && expected_certificate.is_none() {
        return Err(failed(
            "report_input_authority",
            "native report inputs, composed report selections and complete unit registries require a valid production receipt or an independently selected outer report certificate digest",
        ));
    }
    let signed_bytes = r.bytes(1024 * 1024, "report_bundle.checkpoint")?;
    let signed = authenticate(signed_bytes, trusted_keys)
        .map_err(|e| failed("checkpoint_signature", e.to_string()))?;
    if expected_checkpoint.is_some_and(|expected| *expected != signed.checkpoint) {
        return Err(failed(
            "recipient_checkpoint",
            "bundle uses another checkpoint than the recipient requested",
        ));
    }
    let anchor = &signed.checkpoint;
    if cert.branch != [0; 16]
        || (cert.book, cert.branch) != (anchor.book_id, anchor.branch_id)
        || cert.known_at > anchor.through_seq
    {
        return Err(failed(
            "report_coordinate",
            "report coordinate is outside the authenticated checkpoint prefix",
        ));
    }
    let prefix = verify_prefix(
        r.bytes(MAX_REPORT_BUNDLE_BYTES, "report_bundle.prefix")?,
        anchor,
    )?;
    let n = r.count(MAX_ROWS, 8, "report_bundle.records")?;
    if n != prefix.envelopes.len() {
        return Err(failed(
            "record_completeness",
            "every checkpoint leaf must have exactly one payload",
        ));
    }
    let mut records = Vec::with_capacity(n);
    let mut legs = Vec::with_capacity(n);
    for envelope in &prefix.envelopes {
        let len = r.u32("record.proposal_len")? as usize;
        let payload = r.bytes(MAX_RECORD_BYTES, "record.payload")?;
        legs.push(
            check_record(envelope, payload, len)
                .map_err(|e| failed("record_derivation", format!("{e:?}")))?,
        );
        records.push((len, payload));
    }
    let n = r.count(records.len(), 12, "report_bundle.migrations")?;
    let mut bodies = Vec::with_capacity(n);
    for _ in 0..n {
        bodies.push((
            r.u64("migration.open_index")?,
            r.bytes(MAX_RECORD_BYTES, "migration.body")?,
        ));
    }
    let mut functional_registry = None;
    let mut lot_units = None;
    let (units, supersession_reasons) = if major >= 2 {
        let n = r.count(
            if major == 3 {
                6
            } else if is_explanation {
                5
            } else {
                4
            },
            8,
            "report_bundle.registries",
        )?;
        let mut inputs = Vec::with_capacity(n);
        for _ in 0..n {
            inputs.push((
                text(&mut r, 64, "registry.name")?,
                r.bytes(1024 * 1024, "registry.canonical")?,
            ));
        }
        let (units, reasons) = if major == 3 {
            let definitions = registry::verify_functional(&inputs, &cert.registry_digest)?;
            let units = definitions.units.keys().copied().collect();
            functional_registry = Some(definitions);
            (units, BTreeMap::new())
        } else {
            let verified = registry::verify(&inputs, &cert.registry_digest, is_explanation)?;
            if lots.is_some() {
                lot_units = Some(registry::lot_units(&inputs)?);
            }
            verified
        };
        if recipient_units.is_some_and(|expected| expected != units.as_slice()) {
            return Err(failed(
                "statement_units",
                "recipient unit identifiers differ from the authenticated complete registry universe",
            ));
        }
        (units, reasons)
    } else {
        (
            recipient_units.unwrap_or_default().to_vec(),
            BTreeMap::new(),
        )
    };
    let mut functional_book = None;
    let mut functional_rates = Vec::new();
    if major == 3 {
        functional_book = Some(r.bytes(functional::MAX_BOOK_BYTES, "functional.book_parameters")?);
        let count = r.count(functional::MAX_RATES, 36, "functional.rates")?;
        for _ in 0..count {
            functional_rates.push((
                r.fixed("functional.rate_oid")?,
                r.bytes(functional::MAX_RATE_BYTES, "functional.rate_document")?,
            ));
        }
    }
    r.finish("report bundle")?;
    let digest = hash_parts(REPORT_BUNDLE_FORMAT, &[bundle]);
    let receipt = receipt
        .map(|raw| {
            crate::bundle::receipt_grade(raw, &digest, trusted_keys)
                .map_err(|e| failed("production_receipt", e))
        })
        .transpose()?;
    let envelopes = &prefix.envelopes;
    if let Some(time) = &cert.time_selection {
        temporal::verify(time, cert.known_at, anchor.through_seq, envelopes, &records)?;
    }
    let HistoricalInputs {
        visible_migrations,
        migration_activations,
        migration_activation_sources,
        schema,
        dimension_history,
        infos,
        by_digest,
        resolved,
        releases,
    } = historical_inputs(&cert, envelopes, &records, &bodies)?;
    let dimension = cert
        .dimension
        .as_ref()
        .map(|selection| dimension_history.select(selection))
        .transpose()?;
    if cert.functional {
        let definitions = functional_registry
            .as_ref()
            .ok_or_else(|| failed("registry_closure", "missing functional registries"))?;
        let book =
            functional_book.ok_or_else(|| failed("functional_book", "missing Book parameters"))?;
        let (functional_trial_balance, functional_statement, output) =
            if let Selection::Statement(selection) = &cert.selection {
                let (report, output) = functional::replay_statement(
                    &cert,
                    selection,
                    definitions,
                    book,
                    &functional_rates,
                    &schema,
                    envelopes,
                    &records,
                    &legs,
                    &infos,
                    &resolved,
                    &visible_migrations,
                    &migration_activations,
                )?;
                (None, Some(report), output)
            } else {
                let (report, output) = functional::replay(
                    &cert,
                    definitions,
                    book,
                    &functional_rates,
                    &schema,
                    envelopes,
                    &records,
                    &legs,
                    &infos,
                    &releases,
                    &visible_migrations,
                    &migration_activations,
                    &migration_activation_sources,
                )?;
                (Some(report), None, output)
            };
        if output != cert.output {
            return Err(failed(
                "report_recomputation",
                "functional amounts, statement lines, historical metadata, source commitments or exact canonical bytes differ from independent Rate replay",
            ));
        }
        let (effective_through, activity, periods) = if let Some(report) = &functional_trial_balance
        {
            (
                report.effective_through,
                report.activity,
                report.periods.clone(),
            )
        } else {
            let report = &functional_statement
                .as_ref()
                .ok_or_else(|| failed("supported_report", "functional report family is absent"))?
                .statement;
            (
                Some(report.columns[0].effective_through),
                report.kind == "IncomeStatement",
                report.columns[0].periods.clone(),
            )
        };
        return Ok(VerifiedReport {
            scope: "recomputation",
            summary: None,
            bundle_digest: digest,
            certificate_digest: cert.digest,
            output_digest: cert.output_digest,
            checkpoint: signed,
            known_at: cert.known_at,
            time_selection: cert.time_selection,
            effective_through,
            activity,
            periods,
            rows: Vec::new(),
            statement: None,
            statement_diff: None,
            dimension: None,
            open_items: None,
            lots: None,
            explanation: None,
            aging: None,
            due_date_aging: None,
            aging_reconciliation: None,
            due_date_aging_reconciliation: None,
            roll_forward: None,
            cash_flow: None,
            split_cash_flow: None,
            indirect_cash_flow: None,
            equity_roll_forward: None,
            functional_trial_balance,
            functional_statement,
            unit_universe_source: "authenticated-registry",
            output,
            checked_records: records.len(),
            receipt,
        });
    }
    if let Selection::OpenItems(account_filter) = &cert.selection {
        let (open_items, output) = open_items::replay(
            cert.known_at,
            *account_filter,
            &units,
            &schema,
            envelopes,
            &infos,
            &legs,
            &records,
            &visible_migrations,
            &migration_activations,
        )?;
        if output != cert.output {
            return Err(failed(
                "report_recomputation",
                "open-item amounts, complete application history, account metadata or canonical bytes differ from independent replay",
            ));
        }
        if let Some(request) = &lots {
            // The authenticated source retains these exact bytes already.
            drop(output);
            let account = account_filter.ok_or_else(|| {
                failed("lots_profile", "lot source requires one selected account")
            })?;
            let units_profile = lot_units
                .as_ref()
                .ok_or_else(|| failed("registry_closure", "lot unit definitions are absent"))?;
            let digests = lots::check_history(
                account,
                request.base_unit,
                units_profile,
                envelopes,
                &infos,
                &legs,
                &records,
                &visible_migrations,
            )?;
            let snapshot = match request.effective_through {
                Some(cutoff) => {
                    // The complete source has passed. Release its item and
                    // application vectors before allocating the date view.
                    drop(open_items);
                    open_items::replay_as_of(
                        cert.known_at,
                        *account_filter,
                        cutoff,
                        &units,
                        &schema,
                        envelopes,
                        &infos,
                        &legs,
                        &records,
                        &visible_migrations,
                        &migration_activations,
                    )?
                }
                None => open_items,
            };
            let (report, output) = lots::replay(
                request,
                cert.book,
                cert.known_at,
                cert.digest,
                snapshot,
                &digests,
            )?;
            return Ok(VerifiedReport {
                scope: "recomputation",
                summary: None,
                bundle_digest: digest,
                certificate_digest,
                output_digest: hash_parts(b"fa:report-output:v1", &[&output]),
                checkpoint: signed,
                known_at: cert.known_at,
                time_selection: None,
                effective_through: request.effective_through,
                activity: false,
                periods: Vec::new(),
                rows: Vec::new(),
                statement: None,
                statement_diff: None,
                dimension: None,
                open_items: None,
                lots: Some(report),
                explanation: None,
                aging: None,
                due_date_aging: None,
                aging_reconciliation: None,
                due_date_aging_reconciliation: None,
                roll_forward: None,
                cash_flow: None,
                split_cash_flow: None,
                indirect_cash_flow: None,
                equity_roll_forward: None,
                functional_trial_balance: None,
                functional_statement: None,
                unit_universe_source: "authenticated-registry",
                output,
                checked_records: records.len(),
                receipt,
            });
        }
        if let Some(request) = &due_date {
            let historical = open_items::replay_as_of(
                cert.known_at,
                *account_filter,
                request.effective_through,
                &units,
                &schema,
                envelopes,
                &infos,
                &legs,
                &records,
                &visible_migrations,
                &migration_activations,
            )?;
            let (report, output) = due_date::replay(
                request,
                cert.book,
                cert.known_at,
                cert.digest,
                historical,
                &infos,
                &legs,
            )?;
            if let (Some(comparison_certificate), Some(control_certificate)) =
                (&due_date_reconciliation, &control)
            {
                let account = open_items::account(
                    account_filter.ok_or_else(|| {
                        failed("reconciliation_selection", "missing selected account")
                    })?,
                    &schema,
                )?;
                let control = replay_trial_balance(
                    control_certificate,
                    &schema,
                    None,
                    &dimension_history,
                    envelopes,
                    &records,
                    &legs,
                    &infos,
                    &resolved,
                    &visible_migrations,
                )?;
                let (comparison, output) = due_date_reconciliation::replay(
                    comparison_certificate,
                    request.digest,
                    control_certificate.digest,
                    account,
                    report,
                    control.rows,
                    &units,
                )?;
                return Ok(VerifiedReport {
                    scope: "recomputation",
                    summary: None,
                    bundle_digest: digest,
                    certificate_digest,
                    output_digest: hash_parts(b"fa:report-output:v1", &[&output]),
                    checkpoint: signed,
                    known_at: cert.known_at,
                    time_selection: None,
                    effective_through: Some(comparison.effective_through),
                    activity: false,
                    periods: control.periods,
                    rows: Vec::new(),
                    statement: None,
                    statement_diff: None,
                    dimension: None,
                    open_items: None,
                    lots: None,
                    explanation: None,
                    aging: None,
                    due_date_aging: None,
                    aging_reconciliation: None,
                    due_date_aging_reconciliation: Some(comparison),
                    roll_forward: None,
                    cash_flow: None,
                    split_cash_flow: None,
                    indirect_cash_flow: None,
                    equity_roll_forward: None,
                    functional_trial_balance: None,
                    functional_statement: None,
                    unit_universe_source: "authenticated-registry",
                    output,
                    checked_records: records.len(),
                    receipt,
                });
            }
            return Ok(VerifiedReport {
                scope: "recomputation",
                summary: None,
                bundle_digest: digest,
                certificate_digest,
                output_digest: hash_parts(b"fa:report-output:v1", &[&output]),
                checkpoint: signed,
                known_at: cert.known_at,
                time_selection: None,
                effective_through: Some(report.effective_through),
                activity: false,
                periods: Vec::new(),
                rows: Vec::new(),
                statement: None,
                statement_diff: None,
                dimension: None,
                open_items: None,
                lots: None,
                explanation: None,
                aging: None,
                due_date_aging: Some(report),
                aging_reconciliation: None,
                due_date_aging_reconciliation: None,
                roll_forward: None,
                cash_flow: None,
                split_cash_flow: None,
                indirect_cash_flow: None,
                equity_roll_forward: None,
                functional_trial_balance: None,
                functional_statement: None,
                unit_universe_source: "authenticated-registry",
                output,
                checked_records: records.len(),
                receipt,
            });
        }
        if let Some(aging_certificate) = &aging {
            let historical = open_items::replay_as_of(
                cert.known_at,
                *account_filter,
                aging_certificate.effective_through,
                &units,
                &schema,
                envelopes,
                &infos,
                &legs,
                &records,
                &visible_migrations,
                &migration_activations,
            )?;
            let (aging, output) = aging::replay(
                aging_certificate,
                cert.book,
                cert.known_at,
                cert.digest,
                historical,
            )?;
            if let (Some(reconciliation_certificate), Some(control_certificate)) =
                (&reconciliation, &control)
            {
                let account = open_items::account(
                    account_filter.ok_or_else(|| {
                        failed("reconciliation_selection", "missing selected account")
                    })?,
                    &schema,
                )?;
                let control = replay_trial_balance(
                    control_certificate,
                    &schema,
                    None,
                    &dimension_history,
                    envelopes,
                    &records,
                    &legs,
                    &infos,
                    &resolved,
                    &visible_migrations,
                )?;
                let (comparison, output) = reconciliation::replay(
                    reconciliation_certificate,
                    aging_certificate.digest,
                    control_certificate.digest,
                    account,
                    aging,
                    control.rows,
                    &units,
                )?;
                return Ok(VerifiedReport {
                    scope: "recomputation",
                    summary: None,
                    bundle_digest: digest,
                    certificate_digest,
                    output_digest: hash_parts(b"fa:report-output:v1", &[&output]),
                    checkpoint: signed,
                    known_at: cert.known_at,
                    time_selection: None,
                    effective_through: Some(comparison.effective_through),
                    activity: false,
                    periods: control.periods,
                    rows: Vec::new(),
                    statement: None,
                    statement_diff: None,
                    dimension: None,
                    open_items: None,
                    lots: None,
                    explanation: None,
                    aging: None,
                    due_date_aging: None,
                    aging_reconciliation: Some(comparison),
                    due_date_aging_reconciliation: None,
                    roll_forward: None,
                    cash_flow: None,
                    split_cash_flow: None,
                    indirect_cash_flow: None,
                    equity_roll_forward: None,
                    functional_trial_balance: None,
                    functional_statement: None,
                    unit_universe_source: "authenticated-registry",
                    output,
                    checked_records: records.len(),
                    receipt,
                });
            }
            return Ok(VerifiedReport {
                scope: "recomputation",
                summary: None,
                bundle_digest: digest,
                certificate_digest,
                output_digest: hash_parts(b"fa:report-output:v1", &[&output]),
                checkpoint: signed,
                known_at: cert.known_at,
                time_selection: None,
                effective_through: Some(aging.effective_through),
                activity: false,
                periods: Vec::new(),
                rows: Vec::new(),
                statement: None,
                statement_diff: None,
                dimension: None,
                open_items: None,
                lots: None,
                explanation: None,
                aging: Some(aging),
                due_date_aging: None,
                aging_reconciliation: None,
                due_date_aging_reconciliation: None,
                roll_forward: None,
                cash_flow: None,
                split_cash_flow: None,
                indirect_cash_flow: None,
                equity_roll_forward: None,
                functional_trial_balance: None,
                functional_statement: None,
                unit_universe_source: "authenticated-registry",
                output,
                checked_records: records.len(),
                receipt,
            });
        }
        return Ok(VerifiedReport {
            scope: "recomputation",
            summary: None,
            bundle_digest: digest,
            certificate_digest: cert.digest,
            output_digest: cert.output_digest,
            checkpoint: signed,
            known_at: cert.known_at,
            time_selection: cert.time_selection,
            effective_through: None,
            activity: false,
            periods: Vec::new(),
            rows: Vec::new(),
            statement: None,
            statement_diff: None,
            dimension: None,
            open_items: Some(open_items),
            lots: None,
            explanation: None,
            aging: None,
            due_date_aging: None,
            aging_reconciliation: None,
            due_date_aging_reconciliation: None,
            roll_forward: None,
            cash_flow: None,
            split_cash_flow: None,
            indirect_cash_flow: None,
            equity_roll_forward: None,
            functional_trial_balance: None,
            functional_statement: None,
            unit_universe_source: "authenticated-registry",
            output,
            checked_records: records.len(),
            receipt,
        });
    }
    if let Selection::ExplainBalance { account, period } = &cert.selection {
        let (explanation, output) = explain::replay(
            cert.known_at,
            *account,
            period,
            &units,
            &supersession_reasons,
            &schema,
            envelopes,
            &infos,
            &legs,
            &visible_migrations,
            &migration_activations,
            &releases,
        )?;
        if output != cert.output {
            return Err(failed(
                "report_recomputation",
                "balance explanation cells, whole-period commitment, provenance or complete history differ from independent replay",
            ));
        }
        return Ok(VerifiedReport {
            scope: "recomputation",
            summary: None,
            bundle_digest: digest,
            certificate_digest: cert.digest,
            output_digest: cert.output_digest,
            checkpoint: signed,
            known_at: cert.known_at,
            time_selection: cert.time_selection,
            effective_through: None,
            activity: false,
            periods: vec![period.clone()],
            rows: Vec::new(),
            statement: None,
            statement_diff: None,
            dimension: None,
            open_items: None,
            lots: None,
            explanation: Some(explanation),
            aging: None,
            due_date_aging: None,
            aging_reconciliation: None,
            due_date_aging_reconciliation: None,
            roll_forward: None,
            cash_flow: None,
            split_cash_flow: None,
            indirect_cash_flow: None,
            equity_roll_forward: None,
            functional_trial_balance: None,
            functional_statement: None,
            unit_universe_source: "authenticated-registry",
            output,
            checked_records: records.len(),
            receipt,
        });
    }
    if let Selection::Statement(selection) = &cert.selection {
        let (statement, output) = statement::replay(
            selection,
            &cert.book,
            &cert.branch,
            cert.known_at,
            &units,
            &schema,
            envelopes,
            &infos,
            &legs,
            &visible_migrations,
            &resolved,
        )
        .map_err(|error| {
            if major == 1 && error.predicate == "registry_closure" {
                failed("statement_units", error.detail)
            } else {
                error
            }
        })?;
        if output != cert.output {
            return Err(failed(
                "report_recomputation",
                "statement definition, columns, lines, complete mappings or canonical bytes differ from independent replay",
            ));
        }
        let effective_through = Some(statement.columns[0].effective_through);
        let (statement, statement_diff, output, output_digest) = if let (
            Some(request),
            Some(before_certificate),
        ) =
            (&statement_diff, &before_statement)
        {
            let Selection::Statement(before_selection) = &before_certificate.selection else {
                return Err(failed(
                    "supported_report",
                    "comparison source is not a statement",
                ));
            };
            let before_bodies = crate::migration_balance::report_bodies_at(
                envelopes,
                &records,
                &bodies,
                before_certificate.known_at,
            )
            .map_err(|e| failed("migration_visibility", e.to_string()))?;
            let before_inputs =
                historical_inputs(before_certificate, envelopes, &records, &before_bodies)?;
            let (before, before_output) = statement::replay(
                before_selection,
                &before_certificate.book,
                &before_certificate.branch,
                before_certificate.known_at,
                &units,
                &before_inputs.schema,
                envelopes,
                &before_inputs.infos,
                &legs,
                &before_inputs.visible_migrations,
                &before_inputs.resolved,
            )?;
            if before_output != before_certificate.output {
                return Err(failed(
                    "report_recomputation",
                    "the comparison's earlier statement differs from its independently replayed historical source",
                ));
            }
            let (comparison, output) = statement_diff::replay(
                request,
                before_certificate,
                &cert,
                before,
                &before_output,
                statement,
                &output,
            )?;
            let output_digest = hash_parts(b"fa:report-output:v1", &[&output]);
            (None, Some(comparison), output, output_digest)
        } else {
            (Some(statement), None, output, cert.output_digest)
        };
        return Ok(VerifiedReport {
            scope: "recomputation",
            summary: None,
            bundle_digest: digest,
            certificate_digest,
            output_digest,
            checkpoint: signed,
            known_at: cert.known_at,
            time_selection: cert.time_selection,
            effective_through,
            activity: selection.activity(),
            periods: selection.periods.clone(),
            rows: Vec::new(),
            statement,
            statement_diff,
            dimension: None,
            open_items: None,
            lots: None,
            explanation: None,
            aging: None,
            due_date_aging: None,
            aging_reconciliation: None,
            due_date_aging_reconciliation: None,
            roll_forward: None,
            cash_flow: None,
            split_cash_flow: None,
            indirect_cash_flow: None,
            equity_roll_forward: None,
            functional_trial_balance: None,
            functional_statement: None,
            unit_universe_source: if major == 2 {
                "authenticated-registry"
            } else {
                "recipient-supplied"
            },
            output,
            checked_records: records.len(),
            receipt,
        });
    }
    let TrialBalanceReplay {
        effective_through: through,
        activity,
        periods,
        rows,
        output,
    } = replay_trial_balance(
        &cert,
        &schema,
        dimension.as_ref(),
        &dimension_history,
        envelopes,
        &records,
        &legs,
        &infos,
        &resolved,
        &visible_migrations,
    )?;
    if let Some(certificate) = &roll_forward {
        let (roll_forward, output) = roll_forward::replay(
            certificate,
            cert.book,
            cert.known_at,
            cert.digest,
            &units,
            &schema,
            envelopes,
            &infos,
            &legs,
            &visible_migrations,
            &rows,
        )?;
        if let Some(equity_certificate) = &equity {
            let (equity_roll_forward, output) = equity::replay(
                equity_certificate,
                roll_forward,
                certificate.digest,
                &schema,
                envelopes,
                &infos,
            )?;
            return Ok(VerifiedReport {
                scope: "recomputation",
                summary: None,
                bundle_digest: digest,
                certificate_digest,
                output_digest: hash_parts(b"fa:report-output:v1", &[&output]),
                checkpoint: signed,
                known_at: cert.known_at,
                time_selection: None,
                effective_through: Some(equity_roll_forward.effective_through),
                activity: false,
                periods: Vec::new(),
                rows: Vec::new(),
                statement: None,
                statement_diff: None,
                dimension: None,
                open_items: None,
                lots: None,
                explanation: None,
                aging: None,
                due_date_aging: None,
                aging_reconciliation: None,
                due_date_aging_reconciliation: None,
                roll_forward: None,
                cash_flow: None,
                split_cash_flow: None,
                indirect_cash_flow: None,
                equity_roll_forward: Some(equity_roll_forward),
                functional_trial_balance: None,
                functional_statement: None,
                unit_universe_source: "authenticated-registry",
                output,
                checked_records: records.len(),
                receipt,
            });
        }
        if cash.is_some() || split_cash.is_some() {
            let (basis, output) = if let Some(cash_certificate) = &cash {
                let (mut cash_flow, mut output) =
                    cash_flow::replay(cash_certificate, roll_forward, certificate.digest)?;
                if let Some(policy) = &cash_policy {
                    output = cash_flow::policy::replay(
                        policy,
                        &mut cash_flow,
                        cash_certificate.digest,
                        &output,
                        &schema,
                        envelopes,
                        &legs,
                        &by_digest,
                    )?;
                    (VerifiedCashFlowBasis::Policy(cash_flow), output)
                } else {
                    (VerifiedCashFlowBasis::Explicit(cash_flow), output)
                }
            } else {
                let split_certificate = split_cash
                    .as_ref()
                    .ok_or_else(|| failed("supported_report", "cash source is missing"))?;
                let (split, output) =
                    cash_flow_split::replay(split_certificate, roll_forward, certificate.digest)?;
                (VerifiedCashFlowBasis::Split(split), output)
            };
            let effective_through = Some(basis.ledger().effective_through);
            let (cash_flow, split_cash_flow, indirect_cash_flow, output) = if let Some(indirect) =
                &indirect_cash
            {
                let (report, output) = indirect_cash_flow::replay(
                    indirect,
                    basis,
                    &output,
                    indirect_cash_flow::Sources {
                        native_source_digest: cert.digest,
                        registered_units: &units,
                        schema: &schema,
                        envelopes,
                        infos: &infos,
                        legs: &legs,
                        visible_migrations: &visible_migrations,
                        resolved: &resolved,
                        source_rows: &rows,
                    },
                )?;
                (None, None, Some(report), output)
            } else {
                match basis {
                    VerifiedCashFlowBasis::Explicit(report)
                    | VerifiedCashFlowBasis::Policy(report) => (Some(report), None, None, output),
                    VerifiedCashFlowBasis::Split(report) => (None, Some(report), None, output),
                }
            };
            return Ok(VerifiedReport {
                scope: "recomputation",
                summary: None,
                bundle_digest: digest,
                certificate_digest,
                output_digest: hash_parts(b"fa:report-output:v1", &[&output]),
                checkpoint: signed,
                known_at: cert.known_at,
                time_selection: None,
                effective_through,
                activity: false,
                periods: Vec::new(),
                rows: Vec::new(),
                statement: None,
                statement_diff: None,
                dimension: None,
                open_items: None,
                lots: None,
                explanation: None,
                aging: None,
                due_date_aging: None,
                aging_reconciliation: None,
                due_date_aging_reconciliation: None,
                roll_forward: None,
                cash_flow,
                split_cash_flow,
                indirect_cash_flow,
                equity_roll_forward: None,
                functional_trial_balance: None,
                functional_statement: None,
                unit_universe_source: "authenticated-registry",
                output,
                checked_records: records.len(),
                receipt,
            });
        }
        return Ok(VerifiedReport {
            scope: "recomputation",
            summary: None,
            bundle_digest: digest,
            certificate_digest,
            output_digest: hash_parts(b"fa:report-output:v1", &[&output]),
            checkpoint: signed,
            known_at: cert.known_at,
            time_selection: None,
            effective_through: Some(roll_forward.effective_through),
            activity: false,
            periods: Vec::new(),
            rows: Vec::new(),
            statement: None,
            statement_diff: None,
            dimension: None,
            open_items: None,
            lots: None,
            explanation: None,
            aging: None,
            due_date_aging: None,
            aging_reconciliation: None,
            due_date_aging_reconciliation: None,
            roll_forward: Some(roll_forward),
            cash_flow: None,
            split_cash_flow: None,
            indirect_cash_flow: None,
            equity_roll_forward: None,
            functional_trial_balance: None,
            functional_statement: None,
            unit_universe_source: "authenticated-registry",
            output,
            checked_records: records.len(),
            receipt,
        });
    }
    let (summary, output) = if let Some(certificate) = &summary {
        let (report, output) = summary::replay(
            certificate,
            cert.book,
            cert.known_at,
            cert.digest,
            &schema,
            &rows,
            &output,
            &units,
        )?;
        (Some(report), output)
    } else {
        (None, output)
    };
    let unit_universe_source = if summary.is_some() {
        "authenticated-registry"
    } else {
        "not-applicable"
    };
    Ok(VerifiedReport {
        scope: "recomputation",
        summary,
        bundle_digest: digest,
        certificate_digest,
        output_digest: hash_parts(b"fa:report-output:v1", &[&output]),
        checkpoint: signed,
        known_at: cert.known_at,
        time_selection: cert.time_selection,
        effective_through: through,
        activity,
        periods,
        rows,
        statement: None,
        statement_diff: None,
        dimension,
        open_items: None,
        lots: None,
        explanation: None,
        aging: None,
        due_date_aging: None,
        aging_reconciliation: None,
        due_date_aging_reconciliation: None,
        roll_forward: None,
        cash_flow: None,
        split_cash_flow: None,
        indirect_cash_flow: None,
        equity_roll_forward: None,
        functional_trial_balance: None,
        functional_statement: None,
        unit_universe_source,
        output,
        checked_records: records.len(),
        receipt,
    })
}

struct HistoricalInputs<'a> {
    visible_migrations: BTreeSet<u64>,
    migration_activations: BTreeMap<u64, u64>,
    migration_activation_sources: BTreeMap<u64, usize>,
    schema: metadata::Schema,
    dimension_history: dimension::History,
    infos: BTreeMap<usize, metadata::EntryInfo<'a>>,
    by_digest: BTreeMap<[u8; 32], usize>,
    resolved: BTreeSet<usize>,
    releases: BTreeMap<usize, u64>,
}

/// Reconstruct one source at its exact historical frontier. A comparison must
/// call this for each side: later chart controls, finalized migrations and
/// pending resolutions cannot change the earlier source's meaning.
fn historical_inputs<'a>(
    cert: &Certificate<'_>,
    envelopes: &[crate::envelope::LeafEnvelope],
    records: &[(usize, &'a [u8])],
    bodies: &[(u64, &[u8])],
) -> Result<HistoricalInputs<'a>, ReportError> {
    let mut hashes = Vec::new();
    let mut last_seq = None;
    let mut ordinal = 0u32;
    for e in envelopes
        .iter()
        .filter(|e| e.kind == KIND_ENTRY && e.commit_seq <= cert.known_at)
    {
        if last_seq != Some(e.commit_seq) {
            ordinal = 0;
            last_seq = Some(e.commit_seq);
        }
        let mut historical = e.clone();
        historical.within_commit_ordinal = ordinal;
        ordinal = ordinal
            .checked_add(1)
            .ok_or_else(|| failed("historical_prefix", "entry ordinal overflow"))?;
        hashes.push(leaf_hash(&historical.encode()));
    }
    if hashes.len() as u64 != cert.leaves || root_of(&hashes) != cert.journal_root {
        return Err(failed(
            "historical_prefix",
            "the authenticated entries at known-at do not reproduce the certificate's journal root",
        ));
    }
    let crate::migration_balance::ReportVisibility {
        visible: visible_migrations,
        activations: migration_activations,
        activation_sources: migration_activation_sources,
    } = crate::migration_balance::report_visibility_with_sources(
        envelopes,
        records,
        bodies,
        cert.known_at,
    )
    .map_err(|e| failed("migration_visibility", e.to_string()))?;
    let mut schema = metadata::Schema::default();
    let mut dimension_history = dimension::History::default();
    let mut infos = BTreeMap::new();
    let mut by_digest = BTreeMap::new();
    for (index, (envelope, (len, payload))) in envelopes.iter().zip(records).enumerate() {
        if envelope.kind != KIND_ENTRY || envelope.commit_seq > cert.known_at {
            continue;
        }
        let info = metadata::entry_info(&payload[..*len], envelope)?;
        if let Some((kind, body)) = info.schema {
            schema.apply(kind, body, &cert.book, envelope.commit_seq)?;
            if cert.dimension.is_some() {
                dimension_history.apply(kind, body, &cert.book)?;
            }
        }
        if by_digest.insert(envelope.record_digest, index).is_some() {
            return Err(failed(
                "entry_identity",
                "duplicate entry digest in the prefix",
            ));
        }
        infos.insert(index, info);
    }
    let mut resolved = BTreeSet::new();
    let mut releases = BTreeMap::new();
    for (index, info) in &infos {
        let e = &envelopes[*index];
        if e.class != 3 {
            continue;
        }
        let target = info
            .resolution
            .ok_or_else(|| failed("pending_resolution", "resolution lacks a pending target"))?;
        let target_index = *by_digest
            .get(&target.1)
            .ok_or_else(|| failed("pending_resolution", "pending target is missing"))?;
        let original = &envelopes[target_index];
        if original.class != 2
            // An atomic batch can publish its Pending and Resolution together.
            // Prefix ordinals order identities, not member execution. The
            // authenticated target digest, derived VId and single resolution
            // establish the snapshot's lifecycle without trusting that order.
            || original.commit_seq > e.commit_seq
            || !infos[&target_index].matches_identity(target.0)
            || !resolved.insert(target_index)
        {
            return Err(failed(
                "pending_resolution",
                "invalid or duplicate pending resolution",
            ));
        }
        releases.insert(target_index, e.commit_seq);
    }
    Ok(HistoricalInputs {
        visible_migrations,
        migration_activations,
        migration_activation_sources,
        schema,
        dimension_history,
        infos,
        by_digest,
        resolved,
        releases,
    })
}

struct TrialBalanceReplay {
    effective_through: Option<i32>,
    activity: bool,
    periods: Vec<String>,
    rows: Vec<ReportRow>,
    output: Vec<u8>,
}

/// The native standalone and reconciliation control reports share the same
/// independent fold and exact output comparison.
#[allow(clippy::too_many_arguments)]
fn replay_trial_balance(
    cert: &Certificate<'_>,
    schema: &metadata::Schema,
    dimension: Option<&VerifiedDimensionSelection>,
    dimension_history: &dimension::History,
    envelopes: &[crate::envelope::LeafEnvelope],
    records: &[(usize, &[u8])],
    legs: &[Vec<crate::envelope::Leg>],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    resolved: &BTreeSet<usize>,
    visible_migrations: &BTreeSet<u64>,
) -> Result<TrialBalanceReplay, ReportError> {
    if cert.functional {
        return Err(failed(
            "supported_report",
            "native compositions cannot reinterpret functional sources",
        ));
    }
    let (periods, through, activity) = schema.selection(&cert.selection)?;
    let dimension_filter = dimension
        .as_ref()
        .map(|selection| dimension::LegFilter::new(&cert.book, selection, dimension_history))
        .transpose()?;
    let mut sums: BTreeMap<(u128, u32), [i128; 4]> = BTreeMap::new();
    for (index, info) in infos {
        let e = &envelopes[*index];
        if legs[*index].is_empty()
            || (e.class == 2 && resolved.contains(index))
            || (e.class == 12 && !visible_migrations.contains(&(*index as u64)))
        {
            continue;
        }
        let effective = e
            .effective_day
            .ok_or_else(|| failed("report_selector", "monetary entry has no effective date"))?;
        let selected = match through {
            Some(cutoff) => effective <= cutoff,
            None => periods
                .binary_search(&schema.entry_period(info, effective)?)
                .is_ok(),
        };
        if !selected {
            continue;
        }
        let selected_legs = dimension_filter
            .as_ref()
            .map(|filter| dimension::selected_legs(&records[*index].1[..records[*index].0], filter))
            .transpose()?;
        if selected_legs
            .as_ref()
            .is_some_and(|mask| mask.len() != legs[*index].len())
        {
            return Err(failed(
                "dimension_tags",
                "dimension and monetary leg counts disagree",
            ));
        }
        for (leg_index, leg) in legs[*index].iter().enumerate() {
            if selected_legs.as_ref().is_some_and(|mask| !mask[leg_index]) {
                continue;
            }
            if leg.mantissa < 0 {
                return Err(failed("exact_arithmetic", "a leg has a negative mantissa"));
            }
            let columns = sums.entry((leg.account, leg.unit)).or_insert([0; 4]);
            let column = usize::from(!leg.debit) + if e.class == 2 { 2 } else { 0 };
            columns[column] = columns[column]
                .checked_add(leg.mantissa)
                .ok_or_else(|| failed("exact_arithmetic", "trial balance column overflow"))?;
        }
    }
    let mut rows = Vec::with_capacity(sums.len());
    let mut totals: BTreeMap<u32, [i128; 4]> = BTreeMap::new();
    for ((account, unit), values) in sums {
        let a = schema.accounts.get(&account).ok_or_else(|| {
            failed(
                "account_metadata",
                format!("account {account:032x} has no authenticated chart declaration"),
            )
        })?;
        if a.account_type <= 5 {
            let t = totals.entry(unit).or_insert([0; 4]);
            for i in 0..4 {
                t[i] = t[i]
                    .checked_add(values[i])
                    .ok_or_else(|| failed("exact_arithmetic", "unit total overflow"))?;
            }
        }
        rows.push(ReportRow {
            account,
            code: a.code.clone(),
            name: a.name.clone(),
            account_type: a.account_type,
            unit,
            debits: values[0],
            credits: values[1],
            debits_pending: values[2],
            credits_pending: values[3],
        });
    }
    rows.sort_by(|a, b| a.code.cmp(&b.code).then(a.unit.cmp(&b.unit)));
    // A dimension view selects individual legs. Its counterpart can be
    // untagged or belong to another value, so its own totals need not balance.
    if dimension.is_none() && totals.values().any(|t| t[0] != t[1] || t[2] != t[3]) {
        return Err(failed(
            "monetary_footing",
            "posted or pending monetary totals do not balance",
        ));
    }
    let trial_balance = output(&periods, cert.known_at, through, activity, &rows, &totals);
    let output = match &dimension {
        None => trial_balance,
        Some(filter) => {
            let mut w = Writer::default();
            w.fixed(DIMENSION_OUTPUT_FORMAT)
                .bytes(filter.dimension.as_bytes())
                .bytes(filter.value.as_bytes())
                .count(filter.values.len());
            for value in &filter.values {
                w.bytes(value.as_bytes());
            }
            w.bytes(&trial_balance);
            w.buf
        }
    };
    if output != cert.output {
        return Err(failed(
            "report_recomputation",
            if dimension.is_some() {
                "dimension filter, authenticated descendants, tagged balances or canonical bytes differ from independent replay".to_string()
            } else {
                mismatch(&rows, cert.output)?
            },
        ));
    }
    Ok(TrialBalanceReplay {
        effective_through: through,
        activity,
        periods,
        rows,
        output,
    })
}

fn output(
    periods: &[String],
    known_at: u64,
    through: Option<i32>,
    activity: bool,
    rows: &[ReportRow],
    totals: &BTreeMap<u32, [i128; 4]>,
) -> Vec<u8> {
    let mut w = Writer::default();
    w.fixed(OUTPUT_FORMAT).count(periods.len());
    for p in periods {
        w.bytes(p.as_bytes());
    }
    w.u64(known_at).u8(u8::from(through.is_some()));
    if let Some(day) = through {
        w.i32(day);
    }
    w.u8(u8::from(activity)).count(rows.len());
    for row in rows {
        w.u128(row.account)
            .bytes(row.code.as_bytes())
            .bytes(row.name.as_bytes())
            .u8(row.account_type)
            .u32(row.unit)
            .i128(row.debits)
            .i128(row.credits)
            .i128(row.debits_pending)
            .i128(row.credits_pending);
    }
    for start in [0, 2] {
        w.count(totals.len());
        for (unit, values) in totals {
            w.u32(*unit).i128(values[start]).i128(values[start + 1]);
        }
    }
    w.buf
}

fn mismatch(rows: &[ReportRow], expected: &[u8]) -> Result<String, ReportError> {
    let mut r = Reader::new(expected);
    if &r.fixed::<19>("output.format")? != OUTPUT_FORMAT {
        return Ok("unknown trial balance output format".into());
    }
    strings(&mut r, "output.periods")?;
    r.u64("output.known_at")?;
    if r.present("output.through")? {
        r.i32("output.through")?;
    }
    r.present("output.activity")?;
    let n = r.count(MAX_ROWS, 16 + 4 + 4 + 1 + 4 + 64, "output.rows")?;
    if n != rows.len() {
        return Ok(format!(
            "expected {} complete rows, certificate contains {n}",
            rows.len()
        ));
    }
    for row in rows {
        let claimed = ReportRow {
            account: r.u128("row.account")?,
            code: text(&mut r, 64, "row.code")?.into(),
            name: text(&mut r, MAX_RECORD_BYTES, "row.name")?.into(),
            account_type: r.u8("row.type")?,
            unit: r.u32("row.unit")?,
            debits: r.i128("row.debits")?,
            credits: r.i128("row.credits")?,
            debits_pending: r.i128("row.debits_pending")?,
            credits_pending: r.i128("row.credits_pending")?,
        };
        if claimed != *row {
            return Ok(format!(
                "account {} unit {} differs: independently computed posted ({}, {}), pending ({}, {}) with authenticated labels",
                row.code,
                row.unit,
                row.debits,
                row.credits,
                row.debits_pending,
                row.credits_pending
            ));
        }
    }
    Ok(
        "report coordinate, unit totals, or canonical bytes differ from the independent fold"
            .into(),
    )
}
