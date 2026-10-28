//! Contractual aging reconciled to the same historical posting account.
//!
//! Scheduled installments and explicitly unscheduled items together supply
//! the complete open balance. The comparison counts original open items, not
//! installment parts, and never nets different native units. Its separate
//! format preserves the existing effective-date reconciliation v1 contract.

use fa_model::{DecodeError, Id128, Reader, Writer, domain_digest};

use super::*;
use crate::{
    AgingRequest, AgingTotal, DueDateAging, DueDateAgingCertificate, ReportCertificate,
    ReportOutput, ReportSelection, TrialBalanceSelection,
};

pub const DUE_DATE_AGING_RECONCILIATION_CERTIFICATE_FORMAT: &[u8] =
    b"fa:due-date-aging-reconciliation-certificate:v1";
const OUTPUT: &[u8] = b"fa:due-date-aging-control-reconciliation:v1";
const DIGEST: &[u8] = b"fa:due-date-aging-reconciliation-digest:v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DueDateAgingReconciliation {
    account: AccountRow,
    aging: DueDateAging,
    control_rows: Vec<TbRow>,
    rows: Vec<AgingReconciliationRow>,
}

impl DueDateAgingReconciliation {
    #[must_use]
    pub fn account(&self) -> &AccountRow {
        &self.account
    }
    #[must_use]
    pub fn aging(&self) -> &DueDateAging {
        &self.aging
    }
    #[must_use]
    pub fn control_rows(&self) -> &[TbRow] {
        &self.control_rows
    }
    #[must_use]
    pub fn rows(&self) -> &[AgingReconciliationRow] {
        &self.rows
    }
    #[must_use]
    pub fn known_at(&self) -> CommitSeq {
        self.aging.known_at
    }
    #[must_use]
    pub fn effective_through(&self) -> DateDay {
        self.aging.effective_through
    }
    #[must_use]
    pub fn is_reconciled(&self) -> bool {
        self.rows.iter().all(|row| row.difference == 0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DueDateAgingReconciliationCertificate {
    aging: DueDateAgingCertificate,
    control: ReportCertificate,
    producer: VId,
    capability_commitment: [u8; 32],
    output: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedDueDateAgingReconciliation {
    pub report: DueDateAgingReconciliation,
    pub certificate: DueDateAgingReconciliationCertificate,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §5.6–§5.7 / §11.7 / §13.6 (complete due-date aging and stock at one coordinate)",
        "retain the original due-date aging and stock certificates with their book history; select the exact account, recorded prefix, civil cutoff and due-date bands",
    )
}

fn bounded(parts: impl IntoIterator<Item = usize>) -> Result<usize, Refusal> {
    let size = parts
        .into_iter()
        .try_fold(0usize, |sum, part| sum.checked_add(part))
        .ok_or_else(|| invalid("due-date reconciliation encoding size overflow"))?;
    if size > MAX_AGING_RECONCILIATION_BYTES {
        return Err(invalid("complete due-date reconciliation exceeds 64 MiB"));
    }
    Ok(size)
}

fn question(
    aging: &DueDateAgingCertificate,
    control: &ReportCertificate,
) -> Result<AgingReconciliationRequest, Refusal> {
    let request = aging.request()?;
    let account = request
        .account
        .ok_or_else(|| invalid("due-date reconciliation requires one explicit account"))?;
    let source = aging.source();
    if source.book_id != control.book_id
        || source.branch_id != Id128::TRUNK
        || control.branch_id != Id128::TRUNK
        || source.time_selection.is_some()
        || control.time_selection.is_some()
        || source.known_at != control.known_at
        || source.journal_root != control.journal_root
        || source.journal_leaves != control.journal_leaves
        || source.registry_digest != control.registry_digest
        || control.selection
            != ReportSelection::TrialBalance(TrialBalanceSelection::AsOf(request.effective_through))
    {
        return Err(invalid(
            "due-date aging and control name different books, prefixes, registry closures or effective selectors",
        ));
    }
    Ok(AgingReconciliationRequest {
        account,
        effective_through: request.effective_through,
        known_at: request.known_at,
        buckets: request.buckets,
    })
}

fn assemble_due_date(
    account: AccountRow,
    aging: DueDateAging,
    control: TrialBalance,
) -> Result<DueDateAgingReconciliation, BookError> {
    if !account.is_leaf
        || aging.account != Some(account.vid)
        || aging.known_at != control.known_at
        || control.activity
        || control.effective_through != Some(aging.effective_through)
    {
        return Err(corruption(
            "due-date aging and control disagree on their selection",
        ));
    }
    // Each original open item may have several remaining installments. Count
    // it once while summing ALL scheduled and unscheduled native amounts.
    let mut item_ids: BTreeMap<u32, BTreeSet<(VId, u16)>> = BTreeMap::new();
    for item in aging
        .items
        .iter()
        .map(|row| &row.item)
        .chain(aging.unscheduled.iter().map(|row| &row.item))
    {
        item_ids
            .entry(item.unit_id)
            .or_default()
            .insert((item.entry, item.ordinal));
    }
    let mut combined: BTreeMap<u32, AgingAmounts> = BTreeMap::new();
    for totals in [&aging.totals, &aging.unscheduled_totals] {
        let mut seen = BTreeSet::new();
        for total in totals {
            if total.account != account.vid
                || total.amounts.debits < 0
                || total.amounts.credits < 0
                || !seen.insert(total.unit_id)
            {
                return Err(corruption("invalid or repeated due-date aging total"));
            }
            let amount = combined.entry(total.unit_id).or_default();
            amount.debits = amount
                .debits
                .checked_add(total.amounts.debits)
                .ok_or(RegisterError::Overflow)?;
            amount.credits = amount
                .credits
                .checked_add(total.amounts.credits)
                .ok_or(RegisterError::Overflow)?;
        }
    }
    let totals: Vec<_> = combined
        .into_iter()
        .map(|(unit_id, mut amounts)| {
            amounts.item_count = item_ids.get(&unit_id).map_or(0, |items| items.len() as u64);
            AgingTotal {
                account: account.vid,
                unit_id,
                amounts,
            }
        })
        .collect();
    let (control_rows, rows) = compare_totals(&account, &totals, control)?;
    Ok(DueDateAgingReconciliation {
        account,
        aging,
        control_rows,
        rows,
    })
}

fn validate(
    report: &DueDateAgingReconciliation,
    units: &fa_money::UnitRegistry,
) -> Result<(), BookError> {
    if report
        .rows
        .iter()
        .any(|row| units.get(UnitId(row.unit_id)).is_none())
    {
        return Err(corruption(
            "due-date reconciliation uses an unregistered native unit",
        ));
    }
    Ok(())
}

fn comparison_bytes(report: &DueDateAgingReconciliation) -> Result<Vec<u8>, Refusal> {
    certificate::comparison_bytes_for(
        OUTPUT,
        &report.account,
        report.aging.book_id,
        report.known_at(),
        report.effective_through(),
        &report.rows,
    )
}

impl DueDateAgingReconciliationCertificate {
    #[must_use]
    pub fn aging_source(&self) -> &DueDateAgingCertificate {
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
        ReportCertificate::decode(&control)?;
        let size = bounded([
            4,
            DUE_DATE_AGING_RECONCILIATION_CERTIFICATE_FORMAT.len(),
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
        w.bytes(DUE_DATE_AGING_RECONCILIATION_CERTIFICATE_FORMAT)
            .u128(self.producer.0)
            .fixed(&self.capability_commitment)
            .bytes(&aging)
            .bytes(&control)
            .bytes(&self.output);
        w.finish().map_err(|e| invalid(e.to_string()))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut body = self.body_bytes()?;
        if domain_digest(DIGEST, &[&body]) != self.digest {
            return Err(invalid(
                "due-date reconciliation certificate digest mismatch",
            ));
        }
        body.extend_from_slice(&self.digest);
        Ok(body)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        bounded([bytes.len()])?;
        let malformed = |e: DecodeError| invalid(format!("malformed due-date reconciliation: {e}"));
        let mut r = Reader::new(bytes);
        if r.bytes(64, "due-date reconciliation format")
            .map_err(malformed)?
            != DUE_DATE_AGING_RECONCILIATION_CERTIFICATE_FORMAT
        {
            return Err(invalid("unsupported due-date reconciliation format"));
        }
        let producer = VId(r.u128("producer").map_err(malformed)?);
        let capability_commitment = r.fixed("capability").map_err(malformed)?;
        let aging = DueDateAgingCertificate::decode(
            r.bytes(MAX_AGING_RECONCILIATION_BYTES, "due-date aging source")
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
        let digest = r.fixed("digest").map_err(malformed)?;
        r.finish().map_err(malformed)?;
        let value = Self {
            aging,
            control,
            producer,
            capability_commitment,
            output,
            digest,
        };
        if value.canonical_bytes()? != bytes {
            return Err(invalid("noncanonical due-date reconciliation certificate"));
        }
        Ok(value)
    }
}

fn package(
    report: DueDateAgingReconciliation,
    aging: DueDateAgingCertificate,
    control: ReportCertificate,
    principal: VId,
    capability: &Capability,
) -> Result<CertifiedDueDateAgingReconciliation, Refusal> {
    let mut certificate = DueDateAgingReconciliationCertificate {
        aging,
        control,
        producer: principal,
        capability_commitment: capability
            .commitment()
            .map_err(|e| invalid(e.to_string()))?,
        output: comparison_bytes(&report)?,
        digest: [0; 32],
    };
    certificate.digest = domain_digest(DIGEST, &[&certificate.body_bytes()?]);
    Ok(CertifiedDueDateAgingReconciliation {
        report,
        certificate,
    })
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Compare all scheduled and unscheduled open amounts with stock at the
    /// same prefix and inclusive cutoff. Missing terms never drop a balance.
    pub fn reconcile_due_date_aging(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &AgingReconciliationRequest,
    ) -> Outcome<DueDateAgingReconciliation> {
        let head = match authorize(self, cx, principal, capability, false)? {
            Ok(head) => head,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let request = match fixed_request(request, head) {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let at = request.known_at.unwrap_or(head);
        let account = match selected_account(self, cx, request.account, at)? {
            Ok(account) => account,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let aging = match self.due_date_aging(
            cx,
            Some(request.account),
            request.effective_through,
            Some(at),
            &request.buckets,
        ) {
            Ok(report) => report,
            Err(BookError::Registers(RegisterError::InvalidSelection(message))) => {
                return Ok(Err(selection_error(message)));
            }
            Err(error) => return Err(error),
        };
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        let control = query.with_restriction(|| {
            fa_registers::balance_as_of(
                &self.db,
                self.context(),
                request.effective_through,
                Some(at),
            )
        })?;
        let report = assemble_due_date(account, aging, control)?;
        validate(&report, &self.context().units)?;
        query.checkpoint().map_err(BookError::Context)?;
        Ok(Ok(report))
    }

    /// Certify both complete sources at one fixed coordinate. This writes
    /// nothing; explicit artifact retention performs its own authorization.
    pub fn certify_due_date_aging_reconciliation(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &AgingReconciliationRequest,
    ) -> Outcome<CertifiedDueDateAgingReconciliation> {
        let head = match authorize(self, cx, principal, capability, true)? {
            Ok(head) => head,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let request = match fixed_request(request, head) {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let at = request.known_at.unwrap_or(head);
        let account = match selected_account(self, cx, request.account, at)? {
            Ok(account) => account,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let aging_request = AgingRequest {
            account: Some(request.account),
            effective_through: request.effective_through,
            known_at: Some(at),
            buckets: request.buckets,
        };
        let aging = match self.certify_due_date_aging(cx, principal, capability, &aging_request)? {
            Ok(aging) => aging,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let query = cx.query();
        let control = match query.with_restriction(|| {
            crate::certificate::certify_report(
                &self.db,
                cx,
                self.context(),
                TrialBalanceSelection::AsOf(request.effective_through).into(),
                Some(at),
            )
        })? {
            Ok(control) => control,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let ReportOutput::TrialBalance(balance) = control.report else {
            return Ok(Err(invalid("control source is not a trial balance")));
        };
        let report = assemble_due_date(account, aging.report, balance)?;
        validate(&report, &self.context().units)?;
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

    /// Reuse independently retained due-date aging and stock certificates
    /// exactly; neither a newer prefix nor equal current totals substitutes.
    pub fn certify_due_date_aging_reconciliation_from_sources(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        aging: &DueDateAgingCertificate,
        control: &ReportCertificate,
        expected: &AgingReconciliationRequest,
    ) -> Outcome<CertifiedDueDateAgingReconciliation> {
        if let Err(refusal) = authorize(self, cx, principal, capability, true)? {
            return Ok(Err(refusal));
        }
        let report = match self
            .replay_due_date_control_sources(cx, principal, capability, aging, control, expected)?
        {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        Ok(package(
            report,
            aging.clone(),
            control.clone(),
            principal,
            capability,
        ))
    }

    fn replay_due_date_control_sources(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        aging: &DueDateAgingCertificate,
        control: &ReportCertificate,
        expected: &AgingReconciliationRequest,
    ) -> Outcome<DueDateAgingReconciliation> {
        let actual = match question(aging, control) {
            Ok(actual) => actual,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if let Err(refusal) = certificate::expected_question(expected, &actual) {
            return Ok(Err(refusal));
        }
        let aging = match self.replay_due_date_aging(cx, principal, capability, aging)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let control = match self.replay_report(cx, control)? {
            Ok(ReportOutput::TrialBalance(control)) => control,
            Ok(_) => return Ok(Err(invalid("replayed control is not a trial balance"))),
            Err(refusal) => return Ok(Err(refusal)),
        };
        let account = match selected_account(self, cx, actual.account, aging.known_at)? {
            Ok(account) => account,
            Err(refusal) => return Ok(Err(invalid(refusal.message))),
        };
        let report = assemble_due_date(account, aging, control)?;
        validate(&report, &self.context().units)?;
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(report))
    }

    /// Historical replay still requires the recipient's current authority
    /// and independently fixed question. A repaired digest grants neither.
    pub fn replay_due_date_aging_reconciliation(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &DueDateAgingReconciliationCertificate,
        expected: &AgingReconciliationRequest,
    ) -> Outcome<DueDateAgingReconciliation> {
        if let Err(refusal) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = certificate.canonical_bytes() {
            return Ok(Err(refusal));
        }
        let report = match self.replay_due_date_control_sources(
            cx,
            principal,
            capability,
            &certificate.aging,
            &certificate.control,
            expected,
        )? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let output = match comparison_bytes(&report) {
            Ok(output) => output,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if output != certificate.output {
            return Ok(Err(invalid(
                "replayed due-date/control comparison differs from its saved output",
            )));
        }
        Ok(Ok(report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_due_totals_expose_discrepancies_and_keep_pending_separate() {
        // Plant a control discrepancy directly, without claiming these
        // altered totals came from an admitted journal source.
        let (account, effective, control) = super::super::tests::pieces();
        let mut scheduled = effective.totals[0].clone();
        scheduled.amounts.debits = 45;
        let mut unscheduled = scheduled.clone();
        unscheduled.amounts.debits = 15;
        let aging = DueDateAging {
            book_id: effective.book_id,
            known_at: effective.known_at,
            effective_through: effective.effective_through,
            account: effective.account,
            bands: effective.bands,
            items: Vec::new(),
            cells: Vec::new(),
            totals: vec![scheduled],
            unscheduled: Vec::new(),
            unscheduled_totals: vec![unscheduled],
        };
        let report = assemble_due_date(account.clone(), aging.clone(), control.clone()).unwrap();
        assert!(report.is_reconciled());
        assert_eq!(
            (report.rows[0].open_net, report.rows[0].posted_net),
            (60, 60)
        );
        assert_eq!(
            (
                report.rows[0].pending_debits,
                report.rows[0].pending_credits
            ),
            (13, 17)
        );
        let mut discrepancy = aging.clone();
        discrepancy.unscheduled_totals[0].amounts.debits = 14;
        let report = assemble_due_date(account.clone(), discrepancy, control.clone()).unwrap();
        assert!(!report.is_reconciled());
        assert_eq!(report.rows[0].difference, 1);
        let mut overflow = aging.clone();
        overflow.totals[0].amounts.debits = i128::MAX;
        assert!(matches!(
            assemble_due_date(account.clone(), overflow, control.clone()),
            Err(BookError::Registers(RegisterError::Overflow))
        ));
        let mut duplicate = aging;
        duplicate
            .unscheduled_totals
            .push(duplicate.unscheduled_totals[0].clone());
        assert!(assemble_due_date(account, duplicate, control).is_err());
    }
}
