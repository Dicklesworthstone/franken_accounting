use super::*;

fn whole(request: &ThreeWayMatchRequest) -> ThreeWayDocumentMatchRequest {
    ThreeWayDocumentMatchRequest {
        purchase_order_oid: request.purchase_order_oid,
        receiving_report_oid: request.receiving_report_oid,
        invoice_oid: request.invoice_oid,
        known_at: request.known_at,
        expected_digest: None,
    }
}

fn compare(
    h: &mut Harness,
    capability: &Capability,
    request: ThreeWayDocumentMatchRequest,
) -> Result<ThreeWayDocumentMatchReport, Refusal> {
    let cx = h.cx();
    h.runtime
        .block_on(h.book.match_three_way_documents(&cx, capability, request))
        .unwrap()
}

#[test]
fn whole_document_matching_preserves_every_ordinal_and_original_source_grade() {
    let mut h = Harness::new();
    let request = h.sources(false);
    let before = h.head();
    let report = compare(&mut h, &reader(), whole(&request)).unwrap();
    assert!(report.is_matched());
    assert_eq!(report.known_at, before);
    assert_eq!(report.items.len(), 2);
    assert_eq!(report.purchase_order_source.line_count, 2);
    assert_eq!(report.receiving_report_source.line_count, 2);
    assert_eq!(report.invoice_source.line_count, 2);
    assert_eq!(report.items[0].item_code, "SKU-1");
    assert_eq!(report.items[1].item_code, "SKU-2");
    assert_eq!(
        report.items[0].receiving_report.as_ref().unwrap().ordinal,
        2
    );
    assert_eq!(
        report.items[1].receiving_report.as_ref().unwrap().ordinal,
        1
    );
    assert_eq!(report.receiving_report_source.uploader, AGENT);
    assert_eq!(
        report.receiving_report_source.grade,
        EvidencePolicy::embedded()
            .unwrap()
            .grade_by_name("AgentUpload")
            .unwrap()
            .tag
    );
    for item in &report.items {
        let mut selected = request.clone();
        selected.item_code = item.item_code.clone();
        let single = h.compare(&reader(), selected).unwrap();
        assert_eq!(item.result.as_ref(), Some(&single.result));
        assert_eq!(
            item.purchase_order.as_ref().unwrap().line,
            single.purchase_order
        );
        assert_eq!(item.invoice.as_ref().unwrap().line, single.invoice);
        assert_eq!(item.invoice_expected_total.unwrap().mantissa, 3702);
    }
    assert_eq!(h.head(), before, "the complete comparison is a read");
}

#[test]
fn complete_inventory_exposes_every_missing_source_and_each_numeric_variance() {
    let mut h = Harness::new();
    let po = h.upload(&human_upload(), "PurchaseOrder", "text/csv", format!(
        "{PURCHASE_ORDER_HEADER}\nVendor,MATCH,3,10.00,USD\nVendor,QTY,3,10.00,USD\nVendor,PRICE,3,10.00,USD\nVendor,EXT,3,10.00,USD\nVendor,ORDERED,1,1.00,USD\n"
    ));
    let po_hex = hex(po.oid);
    let receipt = h.upload(&human_upload(), "ReceivingReport", "text/csv", format!(
        "{RECEIVING_REPORT_HEADER}\n{po_hex},MATCH,3\n{po_hex},QTY,2\n{po_hex},PRICE,3\n{po_hex},EXT,3\n{po_hex},ONLY-RECEIVED,2\n"
    ));
    let invoice = h.upload(&human_upload(), "Invoice", "text/csv", format!(
        "{INVOICE_HEADER}\n{po_hex},Vendor,MATCH,3,10.00,30.00,USD\n{po_hex},Vendor,QTY,2,10.00,20.00,USD\n{po_hex},Vendor,PRICE,3,11.00,33.00,USD\n{po_hex},Vendor,EXT,3,10.00,29.99,USD\n{po_hex},Vendor,EXTRA,3,10.00,30.00,USD\n"
    ));
    let before = h.head();
    let report = compare(
        &mut h,
        &reader(),
        ThreeWayDocumentMatchRequest {
            purchase_order_oid: po.oid,
            receiving_report_oid: receipt.oid,
            invoice_oid: invoice.oid,
            known_at: None,
            expected_digest: None,
        },
    )
    .unwrap();
    assert!(!report.is_matched());
    assert_eq!(report.items.len(), 7);
    assert_eq!(
        report.items.iter().filter(|item| item.is_matched()).count(),
        1
    );
    assert_eq!(
        report
            .items
            .iter()
            .filter(|item| !item.is_complete())
            .count(),
        3
    );
    let item = |code: &str| {
        report
            .items
            .iter()
            .find(|item| item.item_code == code)
            .unwrap()
    };
    assert!(matches!(
        item("QTY").result.as_ref().unwrap().verdict,
        ThreeWayMatchVerdict::QuantityVariance {
            po_qty: 3,
            receipt_qty: 2,
            invoice_qty: 2
        }
    ));
    assert!(matches!(
        item("PRICE").result.as_ref().unwrap().verdict,
        ThreeWayMatchVerdict::PriceVariance { .. }
    ));
    assert!(matches!(
        item("EXT").result.as_ref().unwrap().verdict,
        ThreeWayMatchVerdict::ExtensionMismatch { .. }
    ));
    for code in ["ORDERED", "ONLY-RECEIVED", "EXTRA"] {
        assert!(item(code).result.is_none());
        assert!(!item(code).is_matched());
    }
    assert!(item("ORDERED").purchase_order.is_some());
    assert!(item("ORDERED").receiving_report.is_none());
    assert!(item("ORDERED").invoice.is_none());
    assert!(item("ONLY-RECEIVED").purchase_order.is_none());
    assert!(item("ONLY-RECEIVED").receiving_report.is_some());
    assert!(item("ONLY-RECEIVED").invoice.is_none());
    assert!(item("EXTRA").purchase_order.is_none());
    assert!(item("EXTRA").receiving_report.is_none());
    assert!(item("EXTRA").invoice.is_some());
    assert_eq!(item("EXTRA").invoice_expected_total.unwrap().mantissa, 3000);
    assert_eq!(h.head(), before);
}

#[test]
fn unmatched_items_cannot_hide_another_purchase_order_vendor_or_invalid_extension() {
    let mut h = Harness::new();
    let request = h.sources(false);
    let po = hex(request.purchase_order_oid);
    let original = format!("{INVOICE_HEADER}\n{po},Vendor,SKU-1,3,12.34,37.02,USD\n");
    for extra in [
        format!("{},Vendor,EXTRA,1,1.00,1.00,USD\n", "ff".repeat(32)),
        format!("{po},Other Vendor,EXTRA,1,1.00,1.00,USD\n"),
        format!("{po},Vendor,EXTRA,{},2.00,1.00,USD\n", i128::MAX),
        format!("{po},Vendor,EXTRA,invalid,1.00,1.00,USD\n"),
        format!("{po},Vendor,SKU-1,1,1.00,1.00,USD\n"),
    ] {
        let invoice = h.upload(
            &human_upload(),
            "Invoice",
            "text/csv",
            format!("{original}{extra}"),
        );
        let mut complete = whole(&request);
        complete.invoice_oid = invoice.oid;
        let before = h.head();
        assert_eq!(
            compare(&mut h, &reader(), complete).unwrap_err().code,
            code::STRUCTURE
        );
        assert_eq!(h.head(), before);
    }
    let receipt = h.upload(
        &human_upload(),
        "ReceivingReport",
        "text/csv",
        format!(
            "{RECEIVING_REPORT_HEADER}\n{po},SKU-1,3\n{},UNORDERED,1\n",
            "fe".repeat(32)
        ),
    );
    let mut complete = whole(&request);
    complete.receiving_report_oid = receipt.oid;
    assert_eq!(
        compare(&mut h, &reader(), complete).unwrap_err().code,
        code::STRUCTURE
    );
}

#[test]
fn complete_source_replay_retains_missing_inventory_after_compaction_and_later_intake() {
    let mut h = Harness::new();
    let mut request = whole(&h.sources(false));
    let po = hex(request.purchase_order_oid);
    let invoice = h.upload(&human_upload(), "Invoice", "text/csv", format!(
        "{INVOICE_HEADER}\n{po},Vendor,SKU-1,3,12.34,37.02,USD\n{po},Vendor,EXTRA,1,0.01,0.01,USD\n"
    ));
    request.invoice_oid = invoice.oid;
    let original = compare(&mut h, &reader(), request.clone()).unwrap();
    assert!(!original.is_matched());
    request.known_at = Some(original.known_at);
    request.expected_digest = Some(original.result_digest);
    let other = h.upload(&human_upload(), "Invoice", "text/csv", format!(
        "{INVOICE_HEADER}\n{po},Vendor,SKU-1,3,12.34,37.02,USD\n{po},Vendor,OTHER,1,0.01,0.01,USD\n"
    ));
    let before = h.head();
    let cx = h.cx();
    h.runtime.block_on(h.book.compact_storage(&cx)).unwrap();
    let mut h = h.reopen();
    assert_eq!(
        compare(&mut h, &reader(), request.clone()).unwrap(),
        original
    );
    let mut changed = request.clone();
    changed.invoice_oid = other.oid;
    changed.known_at = Some(before);
    assert_eq!(
        compare(&mut h, &reader(), changed).unwrap_err().exit,
        exit::VERIFICATION
    );
    request.expected_digest.as_mut().unwrap()[0] ^= 1;
    assert_eq!(
        compare(&mut h, &reader(), request).unwrap_err().exit,
        exit::VERIFICATION
    );
    assert_eq!(h.head(), before);
}

#[test]
fn complete_matching_checks_authority_before_shape_or_source_and_rechecks_revocation() {
    let mut h = Harness::new();
    let request = whole(&h.sources(false));
    let before = h.head();
    let mut unknown = request.clone();
    unknown.purchase_order_oid = Oid([0; 32]);
    unknown.invoice_oid = Oid([0; 32]);
    for capability in [
        cap(READER, Profile::Human, &[Op::Read]),
        cap(READER, Profile::Human, &[Op::Reconcile]),
        reader().for_accounts(&["1000"]).unwrap(),
        reader().known_at_most(before),
        reader().for_books(&[Id128([19; 16])]).unwrap(),
        reader().expiring_at(before),
    ] {
        assert_eq!(
            compare(&mut h, &capability, request.clone()).unwrap_err(),
            compare(&mut h, &capability, unknown.clone()).unwrap_err(),
        );
    }
    let capability = reader();
    let original = compare(&mut h, &capability, request.clone()).unwrap();
    let mut replay = request;
    replay.known_at = Some(original.known_at);
    replay.expected_digest = Some(original.result_digest);
    let cx = h.cx();
    h.runtime
        .block_on(h.book.revoke_capability(
            &cx,
            cap(VId(45), Profile::Human, &[Op::IssueCapability]),
            capability.commitment().unwrap(),
            DateDay::from_ymd(2026, 1, 1).unwrap(),
            b"revoke-whole-purchase-reader",
            "Revoke full-document reader after comparison",
        ))
        .unwrap()
        .unwrap();
    let before = h.head();
    assert!(
        compare(&mut h, &capability, replay)
            .unwrap_err()
            .message
            .contains("revok")
    );
    assert_eq!(h.head(), before);
}
