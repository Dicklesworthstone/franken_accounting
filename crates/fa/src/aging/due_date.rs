//! Certified contractual due-date aging over an authenticated journal prefix.
//!
//! The native OpenItems source binds the complete immutable history, including
//! extension 33 maturity terms. The historical fold selects entries before
//! evaluating applications and then relieves earliest installments first.
//! Missing or disputed terms remain explicit unscheduled amounts.
//!
//! This separate format preserves effective-date aging v1 bytes. The unsigned
//! certificate requires current read authority and original retained history
//! for local replay; its digest alone is not a signature or proof of economic
//! truth. Extension 33 v1 retains its credit-only maturity contract; v2 also
//! admits contractual terms on debit receivables. A missing due date remains
//! unscheduled on either side and is never inferred from the posting date.

use asupersync::fs::Vfs;
use fa_journal::{KernelError, Refusal, exit};
use fa_model::{DecodeError, Id128, Reader, Writer, domain_digest};
use fa_money::Side;
use fa_policy::{Capability, Op};
use fa_time::DateDay;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use super::{
    AgingBuckets, AgingRequest, AgingTotal, DueDateAging, MAX_AGING_BUCKET_BOUNDS,
    MAX_AGING_CERTIFICATE_BYTES, Unscheduled,
};
use crate::{AsyncBook, BookError, Outcome, ReportCertificate, ReportOutput, ReportSelection};
use fa_registers::open_items::OpenItem;

pub const DUE_DATE_AGING_CERTIFICATE_FORMAT: &[u8] = b"fa:due-date-aging-certificate:v1";
pub const DUE_DATE_AGING_OUTPUT_FORMAT: &[u8] = b"fa:due-date-aging:v1";

const DIGEST_DOMAIN: &[u8] = b"fa:due-date-aging-certificate-digest:v1";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DueDateAgingCertificate {
    source: ReportCertificate,
    effective_through: DateDay,
    buckets: AgingBuckets,
    producer: VId,
    capability_commitment: [u8; 32],
    output: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedDueDateAging {
    pub report: DueDateAging,
    pub certificate: DueDateAgingCertificate,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §5.7 / §11.7 / §13.6 (due-date aging over journaled maturity terms)",
        "retain the original book history and exact cutoff/bucket selection; replay before using the unsigned artifact",
    )
}

fn invalid_request(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §5.7 / §11.7 (explicit effective and recorded coordinates)",
        "use a retained recorded prefix, an inclusive civil date and at most 128 strictly increasing age bounds; a cutoff must not split a backdated settlement or reversal",
    )
}

fn total(parts: impl IntoIterator<Item = usize>) -> Result<usize, Refusal> {
    let size = parts
        .into_iter()
        .try_fold(0usize, |sum, n| sum.checked_add(n))
        .ok_or_else(|| invalid("aging encoding size overflow"))?;
    if size > MAX_AGING_CERTIFICATE_BYTES {
        return Err(invalid(
            "complete aging artifact exceeds 64 MiB; no rows were truncated",
        ));
    }
    Ok(size)
}

fn bounded_buckets(buckets: &AgingBuckets) -> Result<(), Refusal> {
    if buckets.upper_bounds().len() > MAX_AGING_BUCKET_BOUNDS {
        return Err(invalid_request(
            "aging admits at most 128 finite bucket bounds",
        ));
    }
    Ok(())
}

fn source_account(source: &ReportCertificate) -> Result<Option<VId>, Refusal> {
    if source.branch_id != Id128::TRUNK || source.time_selection.is_some() {
        return Err(invalid("aging requires a sequence-selected trunk source"));
    }
    match &source.selection {
        ReportSelection::OpenItems { account } => Ok(*account),
        _ => Err(invalid(
            "aging source must be a complete OpenItems report certificate",
        )),
    }
}

/// The open-item encoding is shared with the effective-date aging format.
/// Price the complete application history before allocating either output.
fn item_size(item: &OpenItem) -> Result<usize, Refusal> {
    let applications = item
        .applications
        .len()
        .checked_mul(43)
        .ok_or_else(|| invalid("due-date aging application count overflow"))?;
    total([16, 2, 16, 4, 1, 4, 8, 64, 4, applications])
}

fn write_item(w: &mut Writer, item: &OpenItem) {
    w.u128(item.entry.0)
        .u16(item.ordinal)
        .u128(item.account.0)
        .u32(item.unit_id)
        .u8(match item.side {
            Side::Debit => 0,
            Side::Credit => 1,
        })
        .i32(item.effective_date.0)
        .u64(item.recorded_at.0)
        .i128(item.original)
        .i128(item.applied)
        .i128(item.applied_out)
        .i128(item.open)
        .list(&item.applications, |w, application| {
            w.u128(application.entry.0)
                .u16(application.ordinal)
                .i128(application.amount)
                .u64(application.recorded_at.0)
                .bool(application.live);
        });
}

fn write_total(w: &mut Writer, total: &AgingTotal) {
    w.u128(total.account.0)
        .u32(total.unit_id)
        .i128(total.amounts.debits)
        .i128(total.amounts.credits)
        .u64(total.amounts.item_count);
}

/// Price every nested row before allocating the output. Both scheduled
/// installments and explicitly unscheduled items are covered: nothing is
/// omitted merely because it has no authenticated contractual maturity.
fn output_bytes(report: &DueDateAging) -> Result<Vec<u8>, Refusal> {
    if report.bands.is_empty() || report.bands.len() > MAX_AGING_BUCKET_BOUNDS + 1 {
        return Err(invalid("invalid due-date aging band count"));
    }
    let mut size = total([
        4,
        DUE_DATE_AGING_OUTPUT_FORMAT.len(),
        16,
        8,
        4,
        1,
        usize::from(report.account.is_some()) * 16,
        // Six list lengths: bands, items, cells, totals, unscheduled items
        // and unscheduled totals.
        24,
    ])?;
    for band in &report.bands {
        size = total([size, 8, 1, usize::from(band.upper_inclusive.is_some()) * 8])?;
    }
    for aged in &report.items {
        size = total([size, item_size(&aged.item)?, 4, 16, 8, 4])?;
        if aged.bucket >= report.bands.len() {
            return Err(invalid("due-date aging item names an absent band"));
        }
    }
    for row in &report.unscheduled {
        let reason_bytes = match row.reason {
            Unscheduled::NoTerms | Unscheduled::MissingMaturity => 1,
            Unscheduled::Disputed { .. } => 5,
        };
        size = total([size, item_size(&row.item)?, reason_bytes])?;
    }
    for (count, width) in [
        (report.cells.len(), 64),
        (report.totals.len(), 60),
        (report.unscheduled_totals.len(), 60),
    ] {
        let rows = count
            .checked_mul(width)
            .ok_or_else(|| invalid("due-date aging row count overflow"))?;
        size = total([size, rows])?;
    }
    if report
        .cells
        .iter()
        .any(|cell| cell.bucket >= report.bands.len())
    {
        return Err(invalid("due-date aging cell names an absent band"));
    }
    let mut w = Writer::with_capacity(size);
    w.bytes(DUE_DATE_AGING_OUTPUT_FORMAT)
        .fixed(&report.book_id.0)
        .u64(report.known_at.0)
        .i32(report.effective_through.0)
        .opt(report.account.as_ref(), |w, account| {
            w.u128(account.0);
        })
        .list(&report.bands, |w, band| {
            w.u64(band.lower_inclusive)
                .opt(band.upper_inclusive.as_ref(), |w, upper| {
                    w.u64(*upper);
                });
        })
        .list(&report.items, |w, aged| {
            write_item(w, &aged.item);
            w.i32(aged.due_date.0)
                .i128(aged.open)
                .u64(aged.days_past_due)
                .u32(aged.bucket as u32);
        })
        .list(&report.cells, |w, cell| {
            w.u128(cell.account.0)
                .u32(cell.unit_id)
                .u32(cell.bucket as u32)
                .i128(cell.amounts.debits)
                .i128(cell.amounts.credits)
                .u64(cell.amounts.item_count);
        })
        .list(&report.totals, write_total)
        .list(&report.unscheduled, |w, row| {
            write_item(w, &row.item);
            match row.reason {
                Unscheduled::NoTerms => {
                    w.u8(0);
                }
                Unscheduled::MissingMaturity => {
                    w.u8(1);
                }
                Unscheduled::Disputed { reason_code } => {
                    w.u8(2).u32(u32::from(reason_code));
                }
            }
        })
        .list(&report.unscheduled_totals, write_total);
    let bytes = w.finish().map_err(|error| invalid(error.to_string()))?;
    if bytes.len() != size {
        return Err(invalid(
            "due-date aging output size disagrees with its canonical encoding",
        ));
    }
    Ok(bytes)
}

impl DueDateAgingCertificate {
    #[must_use]
    pub fn source(&self) -> &ReportCertificate {
        &self.source
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

    pub fn request(&self) -> Result<AgingRequest, Refusal> {
        Ok(AgingRequest {
            account: source_account(&self.source)?,
            effective_through: self.effective_through,
            known_at: Some(self.source.known_at),
            buckets: self.buckets.clone(),
        })
    }

    fn body_bytes(&self) -> Result<Vec<u8>, Refusal> {
        source_account(&self.source)?;
        bounded_buckets(&self.buckets)?;
        total([self.output.len()])?;
        // Never treat public/mutable ReportCertificate fields as prevalidated.
        let source = self
            .source
            .canonical_bytes()
            .map_err(|e| invalid(e.to_string()))?;
        ReportCertificate::decode(&source)?;
        let size = total([
            4,
            DUE_DATE_AGING_CERTIFICATE_FORMAT.len(),
            16,
            32,
            4,
            source.len(),
            4,
            4,
            self.buckets.upper_bounds().len() * 4,
            4,
            self.output.len(),
            32,
        ])?;
        let mut w = Writer::with_capacity(size);
        w.bytes(DUE_DATE_AGING_CERTIFICATE_FORMAT)
            .u128(self.producer.0)
            .fixed(&self.capability_commitment)
            .bytes(&source)
            .i32(self.effective_through.0)
            .list(self.buckets.upper_bounds(), |w, n| {
                w.u32(*n);
            })
            .bytes(&self.output);
        w.finish().map_err(|e| invalid(e.to_string()))
    }

    fn seal(
        source: ReportCertificate,
        effective_through: DateDay,
        buckets: AgingBuckets,
        producer: VId,
        capability_commitment: [u8; 32],
        output: Vec<u8>,
    ) -> Result<Self, Refusal> {
        let mut value = Self {
            source,
            effective_through,
            buckets,
            producer,
            capability_commitment,
            output,
            digest: [0; 32],
        };
        value.digest = domain_digest(DIGEST_DOMAIN, &[&value.body_bytes()?]);
        Ok(value)
    }

    /// Content integrity only. The saved source, cutoff and every output row
    /// must still replay before any historical accounting claim is accepted.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut bytes = self.body_bytes()?;
        if domain_digest(DIGEST_DOMAIN, &[&bytes]) != self.digest {
            return Err(invalid("aging certificate digest mismatch"));
        }
        bytes.extend_from_slice(&self.digest);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        total([bytes.len()])?;
        let malformed = |e: DecodeError| invalid(format!("malformed aging certificate: {e}"));
        let mut r = Reader::new(bytes);
        if r.bytes(64, "aging certificate format").map_err(malformed)?
            != DUE_DATE_AGING_CERTIFICATE_FORMAT
        {
            return Err(invalid("unsupported aging certificate format"));
        }
        let producer = VId(r.u128("aging producer").map_err(malformed)?);
        let capability_commitment = r
            .fixed::<32>("aging capability commitment")
            .map_err(malformed)?;
        let source = ReportCertificate::decode(
            r.bytes(MAX_AGING_CERTIFICATE_BYTES, "aging native source")
                .map_err(malformed)?,
        )?;
        let effective_through = DateDay(r.i32("aging cutoff").map_err(malformed)?);
        let count = r
            .count(MAX_AGING_BUCKET_BOUNDS, "aging bucket bounds")
            .map_err(malformed)?;
        let mut upper_bounds = Vec::with_capacity(count);
        for _ in 0..count {
            upper_bounds.push(r.u32("aging bound").map_err(malformed)?);
        }
        let buckets = AgingBuckets::new(upper_bounds).map_err(|e| invalid(e.to_string()))?;
        let output = r
            .bytes(MAX_AGING_CERTIFICATE_BYTES, "aging output")
            .map_err(malformed)?
            .to_vec();
        let digest = r.fixed::<32>("aging digest").map_err(malformed)?;
        r.finish().map_err(malformed)?;
        let value = Self {
            source,
            effective_through,
            buckets,
            producer,
            capability_commitment,
            output,
            digest,
        };
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical aging certificate"));
        }
        Ok(value)
    }
}

fn authorize<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    principal: VId,
    capability: &Capability,
    known_at: Option<CommitSeq>,
    produce: bool,
) -> Outcome<CommitSeq> {
    let admitted = fa_policy::admit_read(capability, principal, book.context().book_id)
        .and_then(|()| {
            if produce {
                fa_policy::require(capability, Op::Produce, "certifying historical aging")
            } else {
                Ok(())
            }
        })
        .and_then(|()| {
            fa_policy::reach(
                capability,
                &fa_policy::Reach {
                    observes: known_at.map_or(fa_policy::Observes::Head, fa_policy::Observes::At),
                    ..fa_policy::Reach::whole_book(true)
                },
                None,
            )
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
            fa_journal::policy::capability_admitted(&book.db, book.context(), capability)?
        {
            return Ok(Err(refusal));
        }
        Ok(Ok(head))
    })
}

fn fold<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    request: &AgingRequest,
) -> Outcome<DueDateAging> {
    let result = book.due_date_aging(
        cx,
        request.account,
        request.effective_through,
        request.known_at,
        &request.buckets,
    );
    match result {
        Ok(report) => Ok(Ok(report)),
        Err(BookError::Registers(fa_registers::RegisterError::InvalidSelection(message))) => {
            Ok(Err(invalid_request(message)))
        }
        Err(error) => Err(error),
    }
}

fn package(
    report: DueDateAging,
    source: ReportCertificate,
    buckets: AgingBuckets,
    principal: VId,
    capability: &Capability,
) -> Result<CertifiedDueDateAging, Refusal> {
    if report.book_id != source.book_id
        || report.known_at != source.known_at
        || report.account != source_account(&source)?
        || report.bands != buckets.bands()
    {
        return Err(invalid(
            "aging fold and native source name different coordinates or buckets",
        ));
    }
    let output = output_bytes(&report)?;
    let certificate = DueDateAgingCertificate::seal(
        source,
        report.effective_through,
        buckets,
        principal,
        capability
            .commitment()
            .map_err(|e| invalid(e.to_string()))?,
        output,
    )?;
    Ok(CertifiedDueDateAging {
        report,
        certificate,
    })
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Certify one explicit due-date aging request, including maturity terms and
    /// unscheduled amounts. Terms attach to credit obligations (v1) or debit
    /// receivables (v2); missing maturity is never inferred from a posting date. Current whole-book
    /// read+produce authority precedes observation; HEAD resolves only once.
    /// Neither the source nor this composed certificate is written to the book.
    pub fn certify_due_date_aging(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &AgingRequest,
    ) -> Outcome<CertifiedDueDateAging> {
        let head = match authorize(self, cx, principal, capability, request.known_at, true)? {
            Ok(head) => head,
            Err(r) => return Ok(Err(r)),
        };
        if let Err(r) = bounded_buckets(&request.buckets) {
            return Ok(Err(r));
        }
        let at = request.known_at.unwrap_or(head);
        if at > head {
            return Ok(Err(invalid_request(
                "aging known-at is beyond the observed head",
            )));
        }
        let query = cx.query();
        let source = match query.with_restriction(|| {
            crate::certificate::certify_report(
                &self.db,
                cx,
                self.context(),
                ReportSelection::OpenItems {
                    account: request.account,
                },
                Some(at),
            )
        })? {
            Ok(source) => source.certificate,
            Err(r) => return Ok(Err(r)),
        };
        let fixed = AgingRequest {
            known_at: Some(at),
            ..request.clone()
        };
        let report = match fold(self, cx, &fixed)? {
            Ok(report) => report,
            Err(r) => return Ok(Err(r)),
        };
        let result = package(report, source, fixed.buckets, principal, capability);
        query.checkpoint().map_err(BookError::Context)?;
        Ok(result)
    }

    /// Age a previously retained native OpenItems prefix without replacing it
    /// with HEAD. Replays the complete native closure, not just the net items.
    pub fn certify_due_date_aging_from_source(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        source: &ReportCertificate,
        effective_through: DateDay,
        buckets: &AgingBuckets,
    ) -> Outcome<CertifiedDueDateAging> {
        if let Err(r) = authorize(self, cx, principal, capability, Some(source.known_at), true)? {
            return Ok(Err(r));
        }
        if let Err(r) = bounded_buckets(buckets) {
            return Ok(Err(r));
        }
        let account = match source_account(source) {
            Ok(account) => account,
            Err(r) => return Ok(Err(r)),
        };
        match self.replay_report(cx, source)? {
            Ok(ReportOutput::OpenItems(_)) => {}
            Ok(_) => return Ok(Err(invalid("aging source did not replay as open items"))),
            Err(r) => return Ok(Err(r)),
        }
        let request = AgingRequest {
            account,
            effective_through,
            known_at: Some(source.known_at),
            buckets: buckets.clone(),
        };
        let report = match fold(self, cx, &request)? {
            Ok(report) => report,
            Err(r) => return Ok(Err(r)),
        };
        let result = package(
            report,
            source.clone(),
            buckets.clone(),
            principal,
            capability,
        );
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(result)
    }

    /// Replay only the recipient's fixed recorded prefix, account, cutoff
    /// and buckets. The due-date certificate type binds the aging basis as
    /// well; a certificate for effective-date aging cannot answer this request.
    pub fn replay_due_date_aging_for(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &DueDateAgingCertificate,
        expected: &AgingRequest,
    ) -> Outcome<DueDateAging> {
        if let Err(refusal) = authorize(
            self,
            cx,
            principal,
            capability,
            Some(certificate.source.known_at),
            false,
        )? {
            return Ok(Err(refusal));
        }
        if expected.known_at.is_none() {
            return Ok(Err(invalid_request(
                "recipient due-date aging expectations require a fixed known-at, not HEAD",
            )));
        }
        if let Err(refusal) = bounded_buckets(&expected.buckets) {
            return Ok(Err(refusal));
        }
        let actual = match certificate.request() {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if actual != *expected {
            return Ok(Err(invalid(
                "due-date aging certificate answers a different recipient-selected question",
            )));
        }
        self.replay_due_date_aging(cx, principal, capability, certificate)
    }

    /// Recompute every native input, immutable prefix entry, historical open
    /// item, application, band and total. A repaired outer digest cannot make
    /// a false aging result true. Saved provenance never grants authority.
    pub fn replay_due_date_aging(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &DueDateAgingCertificate,
    ) -> Outcome<DueDateAging> {
        if let Err(r) = authorize(
            self,
            cx,
            principal,
            capability,
            Some(certificate.source.known_at),
            false,
        )? {
            return Ok(Err(r));
        }
        if let Err(r) = certificate.canonical_bytes() {
            return Ok(Err(r));
        }
        let request = match certificate.request() {
            Ok(request) => request,
            Err(r) => return Ok(Err(r)),
        };
        match self.replay_report(cx, &certificate.source)? {
            Ok(ReportOutput::OpenItems(_)) => {}
            Ok(_) => return Ok(Err(invalid("aging source did not replay as open items"))),
            Err(r) => return Ok(Err(r)),
        }
        let report = match fold(self, cx, &request)? {
            Ok(report) => report,
            Err(r) => return Ok(Err(invalid(r.message))),
        };
        let output = match output_bytes(&report) {
            Ok(output) => output,
            Err(r) => return Ok(Err(r)),
        };
        if output != certificate.output {
            return Ok(Err(invalid(
                "historical aging differs from its certified output",
            )));
        }
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(report))
    }
}

#[cfg(test)]
mod tests;
