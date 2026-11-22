//! Complete item-inventory comparison of three authenticated source documents.
//!
//! Missing lines are explicit exceptions over the union of all source items.
//! They never become zero quantities, invented prices or a successful match.

use std::collections::BTreeMap;

use super::*;
use fa_money::Amount;

pub const THREE_WAY_DOCUMENT_PROFILE: &str = "fa_three_way_documents_v1";
const DOCUMENT_RESULT_DOMAIN: &[u8] = b"fa:three-way-document-match-report:v1";

/// Compare every item in these three complete retained documents. This profile
/// describes one purchase order and one vendor; it does not aggregate separate
/// deliveries/invoices or infer a missing source row from another document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreeWayDocumentMatchRequest {
    pub purchase_order_oid: Oid,
    pub receiving_report_oid: Oid,
    pub invoice_oid: Oid,
    pub known_at: Option<CommitSeq>,
    pub expected_digest: Option<[u8; 32]>,
}

/// Complete source attribution, including its parsed data-record count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreeWayDocumentSource {
    pub oid: Oid,
    pub doc_commit: [u8; 32],
    pub kind: u8,
    pub grade: u8,
    pub uploader: VId,
    pub recorded_at: CommitSeq,
    pub line_count: u32,
}

impl ThreeWayDocumentSource {
    fn from_source(source: ThreeWayMatchSource, line_count: usize) -> Result<Self, BookError> {
        Ok(Self {
            oid: source.oid,
            doc_commit: source.doc_commit,
            kind: source.kind,
            grade: source.grade,
            uploader: source.uploader,
            recorded_at: source.recorded_at,
            line_count: u32::try_from(line_count)
                .map_err(|_| corrupt("three-way source line count exceeds u32"))?,
        })
    }
}

/// Every present line retains its one-based source ordinal and exact values.
/// A comparison exists only when all three lines are present; otherwise the
/// absent Options identify the missing sources without fabricating an input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreeWayDocumentMatchItem {
    pub item_code: String,
    pub purchase_order: Option<ThreeWaySourceLine<PurchaseOrderLine>>,
    pub receiving_report: Option<ThreeWaySourceLine<ReceivingReportLine>>,
    pub invoice: Option<ThreeWaySourceLine<VendorInvoiceLine>>,
    pub invoice_expected_total: Option<Amount>,
    pub result: Option<ThreeWayMatchResult>,
}

impl ThreeWayDocumentMatchItem {
    fn empty(item_code: String) -> Self {
        Self {
            item_code,
            purchase_order: None,
            receiving_report: None,
            invoice: None,
            invoice_expected_total: None,
            result: None,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.purchase_order.is_some() && self.receiving_report.is_some() && self.invoice.is_some()
    }

    pub fn is_matched(&self) -> bool {
        self.is_complete()
            && self
                .result
                .as_ref()
                .is_some_and(|result| result.verdict == ThreeWayMatchVerdict::Matched)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreeWayDocumentMatchReport {
    pub book_id: Id128,
    pub known_at: CommitSeq,
    pub vendor: String,
    pub purchase_order_source: ThreeWayDocumentSource,
    pub receiving_report_source: ThreeWayDocumentSource,
    pub invoice_source: ThreeWayDocumentSource,
    /// Complete union of exact item codes, in ascending identifier order.
    /// Each source is bounded by MAX_THREE_WAY_LINES; no row is truncated.
    pub items: Vec<ThreeWayDocumentMatchItem>,
    pub result_digest: [u8; 32],
}

impl ThreeWayDocumentMatchReport {
    pub fn is_matched(&self) -> bool {
        !self.items.is_empty() && self.items.iter().all(ThreeWayDocumentMatchItem::is_matched)
    }
}

fn document_digest(report: &ThreeWayDocumentMatchReport) -> Result<[u8; 32], BookError> {
    let mut w = Writer::new();
    w.str(THREE_WAY_DOCUMENT_PROFILE)
        .str(THREE_WAY_PROFILE)
        .fixed(&report.book_id.0)
        .u64(report.known_at.0)
        .str(&report.vendor);
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
            .u32(source.line_count);
    }
    w.u32(u32::try_from(report.items.len()).map_err(|_| corrupt("too many three-way items"))?);
    for item in &report.items {
        w.str(&item.item_code);
        w.opt(item.purchase_order.as_ref(), |w, source| {
            let line = &source.line;
            w.u32(source.ordinal)
                .fixed(&line.po_oid.0)
                .str(&line.vendor)
                .str(&line.item_code)
                .i128(line.quantity);
            amount(w, line.unit_price);
        });
        w.opt(item.receiving_report.as_ref(), |w, source| {
            let line = &source.line;
            w.u32(source.ordinal)
                .fixed(&line.receipt_oid.0)
                .fixed(&line.po_oid.0)
                .str(&line.item_code)
                .i128(line.quantity_received);
        });
        w.opt(item.invoice.as_ref(), |w, source| {
            let line = &source.line;
            w.u32(source.ordinal)
                .fixed(&line.invoice_oid.0)
                .fixed(&line.po_oid.0)
                .str(&line.vendor)
                .str(&line.item_code)
                .i128(line.quantity_billed);
            amount(w, line.unit_price_billed);
            amount(w, line.total_billed);
        });
        w.opt(item.invoice_expected_total.as_ref(), |w, expected| {
            amount(w, *expected);
        });
        let Some(result) = &item.result else {
            w.u8(0);
            continue;
        };
        w.u8(1)
            .fixed(&result.po_oid.0)
            .fixed(&result.receipt_oid.0)
            .fixed(&result.invoice_oid.0);
        match &result.verdict {
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
        let card = result
            .decision_card
            .canonical_bytes()
            .map_err(|error| corrupt(format!("three-way decision encoding: {error}")))?;
        w.bytes(&card);
    }
    let bytes = w
        .finish()
        .map_err(|error| KernelError::Model(error.into()))?;
    Ok(domain_digest(DOCUMENT_RESULT_DOMAIN, &[&bytes]))
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Compare the complete item union in three retained sources. Missing and
    /// extra lines are advisory exceptions, even when a selected item matches.
    /// The digest commits to all inputs, omissions, ordinals and comparisons;
    /// replay rechecks current authority while retaining the original prefix.
    pub async fn match_three_way_documents(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        request: ThreeWayDocumentMatchRequest,
    ) -> Outcome<ThreeWayDocumentMatchReport> {
        let head = match self.authorize_three_way(cx, capability)? {
            Ok(head) => head,
            Err(refusal) => return Ok(Err(refusal)),
        };
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
        let (po_doc, po_source) = match self
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
        let (receipt_doc, receipt_source) = match self
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
        let (invoice_doc, invoice_source) = match self
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
            Ok::<_, Refusal>((po, receipt, invoice))
        })();
        let (po, receipt, invoice) = match parsed {
            Ok(lines) => lines,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let vendor = po
            .first()
            .ok_or_else(|| corrupt("purchase-order parser returned an empty source"))?
            .line
            .vendor
            .clone();
        // Validate every source's identity before comparing any row, including
        // items missing from one of the other documents. Equal numbers cannot
        // make a different vendor or purchase order part of this comparison.
        if po.iter().any(|source| source.line.vendor != vendor)
            || invoice.iter().any(|source| source.line.vendor != vendor)
        {
            return Ok(Err(structure(
                "complete-document matching requires one exact vendor across every purchase-order and invoice line",
            )));
        }
        if receipt
            .iter()
            .any(|source| source.line.po_oid != po_source.oid)
            || invoice
                .iter()
                .any(|source| source.line.po_oid != po_source.oid)
        {
            return Ok(Err(structure(
                "every receiving-report and invoice line must name the exact retained purchase-order OID, including unmatched items",
            )));
        }
        let po_source = ThreeWayDocumentSource::from_source(po_source, po.len())?;
        let receipt_source = ThreeWayDocumentSource::from_source(receipt_source, receipt.len())?;
        let invoice_source = ThreeWayDocumentSource::from_source(invoice_source, invoice.len())?;
        let mut items = BTreeMap::new();
        for source in po {
            let item_code = source.line.item_code.clone();
            items
                .entry(item_code.clone())
                .or_insert_with(|| ThreeWayDocumentMatchItem::empty(item_code))
                .purchase_order = Some(source);
        }
        for source in receipt {
            let item_code = source.line.item_code.clone();
            items
                .entry(item_code.clone())
                .or_insert_with(|| ThreeWayDocumentMatchItem::empty(item_code))
                .receiving_report = Some(source);
        }
        for source in invoice {
            let item_code = source.line.item_code.clone();
            let Some(total) = source
                .line
                .quantity_billed
                .checked_mul(source.line.unit_price_billed.mantissa)
            else {
                return Ok(Err(structure(
                    "an invoice extension exceeds the exact i128 range, including on an unmatched item",
                )));
            };
            let row = items
                .entry(item_code.clone())
                .or_insert_with(|| ThreeWayDocumentMatchItem::empty(item_code));
            row.invoice_expected_total =
                Some(Amount::new(source.line.unit_price_billed.unit, total));
            row.invoice = Some(source);
        }
        let epoch = fa_journal::policy::steward()?.policy_oid;
        for item in items.values_mut() {
            if let (Some(po), Some(receipt), Some(invoice)) =
                (&item.purchase_order, &item.receiving_report, &item.invoice)
            {
                item.result = Some(
                    match fa_registers::reconciliation::match_three_way(
                        &po.line,
                        &receipt.line,
                        &invoice.line,
                        Some(epoch),
                        epoch,
                    ) {
                        Ok(result) => result,
                        Err(error) => {
                            return Ok(Err(structure(format!(
                                "three-way source comparison for {:?} refused: {error}",
                                item.item_code
                            ))));
                        }
                    },
                );
            }
        }
        let mut report = ThreeWayDocumentMatchReport {
            book_id: self.context.book_id,
            known_at: at,
            vendor,
            purchase_order_source: po_source,
            receiving_report_source: receipt_source,
            invoice_source,
            items: items.into_values().collect(),
            result_digest: [0; 32],
        };
        report.result_digest = document_digest(&report)?;
        if let Err(refusal) = self.authorize_three_way(cx, capability)? {
            return Ok(Err(refusal));
        }
        if request
            .expected_digest
            .is_some_and(|expected| expected != report.result_digest)
        {
            return Ok(Err(Refusal::new(
                crate::certificate::code::CERTIFICATE_INVALID,
                exit::VERIFICATION,
                "complete-document three-way replay differs from the independently retained result digest",
                "FA-INV-11 (the complete source inventory reproduces the same advisory result)",
                "use the original three source OIDs, all-items selection, numeric known-at and result digest",
            )));
        }
        Ok(Ok(report))
    }
}
