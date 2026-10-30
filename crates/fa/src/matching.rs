//! Three-way matching over exact retained source documents (plan §5.7/§11.7;
//! fa-2ek, fa-y1vr). Current authority is checked before any observation, and
//! every source passes the ordinary governed Document reader. The selected
//! historical prefix binds source visibility; it never restores old authority.
//!
//! The result is an advisory comparison of a declared CSV interpretation. It
//! establishes what the retained bytes say, not that a purchase, delivery or
//! invoice is economically genuine. It grants no approval, posts no amounts,
//! and is not a ReportCertificate or a journaled match confirmation.

use asupersync::fs::Vfs;
use fa_formats::UnitCatalog;
use fa_formats::matching::{
    ThreeWaySourceLine, parse_invoice_csv, parse_purchase_order_csv, parse_receiving_report_csv,
};
use fa_journal::custody::{CustodyBody, CustodyEvent};
use fa_journal::evidence::{Document, document_vid};
use fa_journal::refusal::{Refusal, code, exit};
use fa_journal::{DocumentRead, KernelError};
use fa_model::{Id128, Oid, Writer, domain_digest};
use fa_policy::{Capability, Op, Reach};
use fa_registers::reconciliation::{
    PurchaseOrderLine, ReceivingReportLine, ThreeWayMatchResult, ThreeWayMatchVerdict,
    VendorInvoiceLine,
};
use fa_registry::evidence_policy::EvidencePolicy;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, BookError, Outcome};

pub use fa_formats::matching::THREE_WAY_PROFILE;

const RESULT_DOMAIN: &[u8] = b"fa:three-way-match-report:v1";

/// Source identities are handles printed by ordinary Document intake. The
/// receipt and invoice must themselves name this exact PurchaseOrder OID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreeWayMatchRequest {
    pub purchase_order_oid: Oid,
    pub receiving_report_oid: Oid,
    pub invoice_oid: Oid,
    pub item_code: String,
    pub known_at: Option<CommitSeq>,
    /// Independently retained original result digest. Replaying requires an
    /// explicit recorded prefix, so HEAD is never silently substituted.
    pub expected_digest: Option<[u8; 32]>,
}

/// Verified source identity and actual intake attribution. `line_ordinal` is
/// the one-based data-record ordinal under THREE_WAY_PROFILE, excluding header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreeWayMatchSource {
    pub oid: Oid,
    pub doc_commit: [u8; 32],
    pub kind: u8,
    pub grade: u8,
    pub uploader: VId,
    pub recorded_at: CommitSeq,
    pub line_ordinal: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreeWayMatchReport {
    pub book_id: Id128,
    pub known_at: CommitSeq,
    pub item_code: String,
    pub purchase_order_source: ThreeWayMatchSource,
    pub receiving_report_source: ThreeWayMatchSource,
    pub invoice_source: ThreeWayMatchSource,
    pub purchase_order: PurchaseOrderLine,
    pub receiving_report: ReceivingReportLine,
    pub invoice: VendorInvoiceLine,
    pub result: ThreeWayMatchResult,
    pub result_digest: [u8; 32],
}

fn structure(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §5.7 / §11.7; fa_three_way_csv_v1 (exact retained source comparison)",
        "upload PurchaseOrder, ReceivingReport and Invoice documents with the declared CSV headers; select one exact item and the document OIDs printed by document add",
    )
}

fn corrupt(message: impl Into<String>) -> BookError {
    BookError::Kernel(KernelError::Corrupt(message.into()))
}

fn drift(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::DOCUMENT_DRIFT,
        exit::VERIFICATION,
        message,
        "FA-INV-05 / FA-INV-07 / FA-INV-16 (retained source identity, custody and historical visibility)",
        "preserve the book and its source documents; restore the exact committed evidence before replaying the match",
    )
}

fn amount(w: &mut Writer, value: fa_money::Amount) {
    w.u32(value.unit.0).i128(value.mantissa);
}

fn result_digest(report: &ThreeWayMatchReport) -> Result<[u8; 32], BookError> {
    let mut w = Writer::new();
    w.str(THREE_WAY_PROFILE)
        .fixed(&report.book_id.0)
        .u64(report.known_at.0)
        .str(&report.item_code);
    for source in [
        &report.purchase_order_source,
        &report.receiving_report_source,
        &report.invoice_source,
    ] {
        w.fixed(&source.oid.0)
            .fixed(&source.doc_commit)
            .u8(source.kind)
            .u8(source.grade)
            .u128(source.uploader.0)
            .u64(source.recorded_at.0)
            .u32(source.line_ordinal);
    }
    let po = &report.purchase_order;
    let receipt = &report.receiving_report;
    let invoice = &report.invoice;
    w.fixed(&po.po_oid.0)
        .str(&po.vendor)
        .str(&po.item_code)
        .i128(po.quantity);
    amount(&mut w, po.unit_price);
    w.fixed(&receipt.receipt_oid.0)
        .fixed(&receipt.po_oid.0)
        .str(&receipt.item_code)
        .i128(receipt.quantity_received)
        .fixed(&invoice.invoice_oid.0)
        .fixed(&invoice.po_oid.0)
        .str(&invoice.vendor)
        .str(&invoice.item_code)
        .i128(invoice.quantity_billed);
    amount(&mut w, invoice.unit_price_billed);
    amount(&mut w, invoice.total_billed);
    match &report.result.verdict {
        ThreeWayMatchVerdict::Matched => {
            w.u8(0);
        }
        ThreeWayMatchVerdict::QuantityVariance {
            po_qty,
            receipt_qty,
            invoice_qty,
        } => {
            w.u8(1).i128(*po_qty).i128(*receipt_qty).i128(*invoice_qty);
        }
        ThreeWayMatchVerdict::PriceVariance {
            po_unit_price,
            invoice_unit_price,
        } => {
            w.u8(2);
            amount(&mut w, *po_unit_price);
            amount(&mut w, *invoice_unit_price);
        }
        ThreeWayMatchVerdict::ExtensionMismatch {
            expected_total,
            invoice_total,
        } => {
            w.u8(3);
            amount(&mut w, *expected_total);
            amount(&mut w, *invoice_total);
        }
    }
    let decision = report
        .result
        .decision_card
        .canonical_bytes()
        .map_err(|error| corrupt(format!("three-way decision encoding: {error}")))?;
    w.bytes(&decision);
    let bytes = w
        .finish()
        .map_err(|error| KernelError::Model(error.into()))?;
    Ok(domain_digest(RESULT_DOMAIN, &[&bytes]))
}

fn select<T>(
    lines: Vec<ThreeWaySourceLine<T>>,
    requested: &str,
    item: impl Fn(&T) -> &str,
    source: &str,
) -> Result<ThreeWaySourceLine<T>, Refusal> {
    lines
        .into_iter()
        .find(|line| item(&line.line) == requested)
        .ok_or_else(|| structure(format!("{source} has no line for item_code {requested:?}")))
}

fn source_text(document: &Document) -> Result<&str, Refusal> {
    core::str::from_utf8(&document.bytes)
        .map_err(|_| structure("three-way CSV sources must be UTF-8"))
}

/// The native custody reader verifies each retained event's own payload and
/// mirrors. Check its inter-event links as well before relying on attribution.
fn intake_at(
    book_id: Id128,
    document: &Document,
    oid: Oid,
    at: CommitSeq,
    custody: &[(CustodyEvent, CommitSeq)],
) -> Outcome<CommitSeq> {
    let Some((receipt, recorded_at)) = custody.first() else {
        return Ok(Err(drift("source has no retained custody receipt")));
    };
    let CustodyBody::Receipt {
        source,
        received_by,
        digest_at_receipt,
        ..
    } = &receipt.body
    else {
        return Ok(Err(drift(
            "source custody does not begin with an import receipt",
        )));
    };
    if receipt.book_id != book_id
        || receipt.document_oid != oid
        || receipt.index != 0
        || receipt.prev_digest != [0; 32]
        || *received_by != document.retrieved_by
        || *digest_at_receipt != document.doc_commit()
        || *recorded_at > at
    {
        return Ok(Err(drift(
            "source intake receipt does not bind this document at the selected prefix",
        )));
    }
    if let Err(refusal) = fa_journal::custody::admit_source(source) {
        return Ok(Err(refusal));
    }
    for pair in custody.windows(2) {
        let (previous, previous_at) = &pair[0];
        let (next, next_at) = &pair[1];
        let CustodyBody::Transfer { from, .. } = &next.body else {
            return Ok(Err(drift("source custody repeats its initial receipt")));
        };
        if next.book_id != book_id
            || next.document_oid != oid
            || previous.index.checked_add(1) != Some(next.index)
            || next.prev_digest != previous.digest()?
            || *from != previous.holder()
            || next_at < previous_at
        {
            return Ok(Err(drift(
                "source custody transfer does not continue its preceding retained event",
            )));
        }
    }
    Ok(Ok(*recorded_at))
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    fn authorize_three_way(
        &self,
        cx: &PurposeContexts,
        capability: &Capability,
    ) -> Outcome<CommitSeq> {
        cx.query().checkpoint().map_err(BookError::Context)?;
        if let Err(denial) =
            fa_policy::admit_read(capability, capability.holder(), self.context.book_id)
                .and_then(|()| {
                    fa_policy::require(
                        capability,
                        Op::Reconcile,
                        "comparing retained purchase documents",
                    )
                })
                .and_then(|()| fa_policy::reach(capability, &Reach::whole_book(true), None))
        {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        self.query(cx, |db, book| {
            Ok(fa_journal::policy::current_at(db, book, capability)?.map(|current| current.at()))
        })
    }

    async fn three_way_source(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        oid: Oid,
        kind: &str,
        at: CommitSeq,
    ) -> Outcome<(Document, ThreeWayMatchSource)> {
        // The governed reader decides disclosure before payload or blob I/O.
        // A redacted view is never parsed as though it were a complete source.
        let document = match self.read_document_for(cx, capability, &oid).await? {
            Ok(DocumentRead::Full(document)) => document,
            Ok(DocumentRead::Redacted(_)) => {
                return Ok(Err(Refusal::new(
                    code::CAPABILITY,
                    exit::SAFETY,
                    "three-way matching requires the complete retained source; this capability receives a redacted view",
                    "plan §9.6 (governed source disclosure precedes interpretation)",
                    "use a capability authorized to read all three sources in full; a match never substitutes omitted fields",
                )));
            }
            Err(refusal) => return Ok(Err(refusal)),
        };
        let policy = EvidencePolicy::embedded()?;
        let expected_kind = policy
            .kind_by_name(kind)
            .ok_or_else(|| corrupt(format!("evidence policy has no {kind} kind")))?
            .tag;
        if document.kind != expected_kind
            || !matches!(
                document.mime.as_str(),
                "text/csv" | "text/csv; charset=utf-8"
            )
        {
            return Ok(Err(structure(format!(
                "the selected {kind} must have that exact registered kind and text/csv media type"
            ))));
        }
        if u64::try_from(document.bytes.len()).map_or(true, |size| size > policy.max_document_bytes)
        {
            return Ok(Err(structure(format!(
                "the {kind} exceeds evidence_policy.max_document_bytes={}",
                policy.max_document_bytes
            ))));
        }
        let recorded_at = match self.query(cx, |db, book| {
            let Some(row) = db.vertex_at(document_vid(&oid), at).map_err(KernelError::from)? else {
                return Ok(Err(Refusal::new(
                    code::COORDINATE,
                    exit::USAGE,
                    format!("the selected {kind} did not exist at known-at {}", at.0),
                    "FA-INV-07 (only retained sources visible at the selected prefix may contribute)",
                    "select a recorded prefix containing all three source documents",
                )));
            };
            let stored = match fa_journal::evidence::verify_row(&row, &policy) {
                Ok(stored) => stored,
                Err(why) => return Ok(Err(drift(why))),
            };
            if stored.book_id != book.book_id
                || stored.oid() != oid
                || stored.doc_commit != document.doc_commit()
                || stored.kind != document.kind
                || stored.mime != document.mime
                || stored.grade != document.grade
                || stored.retrieved_by != document.retrieved_by
            {
                return Ok(Err(drift("historical source metadata differs from its governed bytes")));
            }
            let custody = fa_journal::custody::custody_chain(db, &oid)?;
            intake_at(book.book_id, &document, oid, at, &custody)
        })? {
            Ok(recorded_at) => recorded_at,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let source = ThreeWayMatchSource {
            oid,
            doc_commit: document.doc_commit(),
            kind: document.kind,
            grade: document.grade,
            uploader: document.retrieved_by,
            recorded_at,
            line_ordinal: 0,
        };
        Ok(Ok((document, source)))
    }

    /// Compare one unambiguous item under the declared retained-source CSV
    /// profile. Replaying checks a separately retained digest at a fixed
    /// historical prefix while rechecking current authority and disclosure.
    pub async fn match_three_way(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        request: ThreeWayMatchRequest,
    ) -> Outcome<ThreeWayMatchReport> {
        let head = match self.authorize_three_way(cx, capability)? {
            Ok(head) => head,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if request.item_code.is_empty()
            || request.item_code.trim() != request.item_code
            || request.item_code.len() > fa_model::limits::MAX_EXTERNAL_ID_BYTES
            || request.item_code.chars().any(char::is_control)
        {
            return Ok(Err(structure(format!(
                "item_code must be an exact nonempty identifier of at most {} bytes, without surrounding whitespace or control characters",
                fa_model::limits::MAX_EXTERNAL_ID_BYTES
            ))));
        }
        if request.purchase_order_oid == request.receiving_report_oid
            || request.purchase_order_oid == request.invoice_oid
            || request.receiving_report_oid == request.invoice_oid
        {
            return Ok(Err(structure(
                "three-way matching requires three distinct document OIDs",
            )));
        }
        if request.expected_digest.is_some() && request.known_at.is_none() {
            return Ok(Err(structure(
                "digest-bound replay requires the original numeric known-at sequence",
            )));
        }
        let at = request.known_at.unwrap_or(head);
        if at > head {
            return Ok(Err(structure(format!(
                "known-at {} exceeds the current recorded head {}",
                at.0, head.0
            ))));
        }
        if let Err(refusal) = self
            .prepare_report_history(cx, capability.holder(), capability, Some(at))
            .await?
        {
            return Ok(Err(refusal));
        }
        let (po_doc, mut po_source) = match self
            .three_way_source(
                cx,
                capability,
                request.purchase_order_oid,
                "PurchaseOrder",
                at,
            )
            .await?
        {
            Ok(source) => source,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let (receipt_doc, mut receipt_source) = match self
            .three_way_source(
                cx,
                capability,
                request.receiving_report_oid,
                "ReceivingReport",
                at,
            )
            .await?
        {
            Ok(source) => source,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let (invoice_doc, mut invoice_source) = match self
            .three_way_source(cx, capability, request.invoice_oid, "Invoice", at)
            .await?
        {
            Ok(source) => source,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let parsed = (|| {
            let units = UnitCatalog::embedded().map_err(|error| structure(error.to_string()))?;
            let po = parse_purchase_order_csv(source_text(&po_doc)?, po_source.oid, &units)
                .map_err(|error| structure(error.to_string()))?;
            let receipt =
                parse_receiving_report_csv(source_text(&receipt_doc)?, receipt_source.oid)
                    .map_err(|error| structure(error.to_string()))?;
            let invoice = parse_invoice_csv(source_text(&invoice_doc)?, invoice_source.oid, &units)
                .map_err(|error| structure(error.to_string()))?;
            Ok::<_, Refusal>((
                select(
                    po,
                    &request.item_code,
                    |line| &line.item_code,
                    "PurchaseOrder",
                )?,
                select(
                    receipt,
                    &request.item_code,
                    |line| &line.item_code,
                    "ReceivingReport",
                )?,
                select(
                    invoice,
                    &request.item_code,
                    |line| &line.item_code,
                    "Invoice",
                )?,
            ))
        })();
        let (po, receipt, invoice) = match parsed {
            Ok(lines) => lines,
            Err(refusal) => return Ok(Err(refusal)),
        };
        po_source.line_ordinal = po.ordinal;
        receipt_source.line_ordinal = receipt.ordinal;
        invoice_source.line_ordinal = invoice.ordinal;
        let epoch = fa_journal::policy::steward()?.policy_oid;
        let result = match fa_registers::reconciliation::match_three_way(
            &po.line,
            &receipt.line,
            &invoice.line,
            Some(epoch),
            epoch,
        ) {
            Ok(result) => result,
            Err(error) => {
                return Ok(Err(Refusal::new(
                    code::STRUCTURE,
                    exit::REFUSAL,
                    format!("three-way source comparison refused: {error}"),
                    "plan §5.7 / FA-INV-06 (references, vendor and item must agree; arithmetic must remain exact)",
                    "select corresponding source documents and the same exact item; no numerical agreement may override a different source identity",
                )));
            }
        };
        let mut report = ThreeWayMatchReport {
            book_id: self.context.book_id,
            known_at: at,
            item_code: request.item_code,
            purchase_order_source: po_source,
            receiving_report_source: receipt_source,
            invoice_source,
            purchase_order: po.line,
            receiving_report: receipt.line,
            invoice: invoice.line,
            result,
            result_digest: [0; 32],
        };
        report.result_digest = result_digest(&report)?;
        // Protected reads may await blob I/O; an old source coordinate never
        // exempts delivery from the current authority check.
        if let Err(refusal) = self.authorize_three_way(cx, capability)? {
            return Ok(Err(refusal));
        }
        if request
            .expected_digest
            .is_some_and(|expected| expected != report.result_digest)
        {
            return Ok(Err(Refusal::new(
                code::CERTIFICATE_INVALID,
                exit::VERIFICATION,
                "three-way replay differs from the independently retained result digest",
                "FA-INV-11 (the same exact source selection reproduces the same advisory result)",
                "use the original source OIDs, item, numeric known-at and result digest; do not replace the expected digest with this run's output",
            )));
        }
        Ok(Ok(report))
    }
}

#[cfg(test)]
mod tests;
