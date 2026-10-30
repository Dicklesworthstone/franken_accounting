use super::*;

use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_formats::matching::{INVOICE_HEADER, PURCHASE_ORDER_HEADER, RECEIVING_REPORT_HEADER};
use fa_journal::{BookSpec, DocumentAdded, UploadRequest};
use fa_policy::Profile;
use fa_time::{DateDay, FiscalCalendar};
use fgdb::MemVfs;

use crate::{BookKeys, Entropy};

const HUMAN: VId = VId(41);
const AGENT: VId = VId(42);
const READER: VId = VId(43);
const BOOK_DIR: &str = "retained-three-way-sources";
const SEED: u8 = 225;

fn cap(holder: VId, profile: Profile, ops: &[Op]) -> Capability {
    Capability::new(holder, profile, ops, VId(1)).unwrap()
}

fn reader() -> Capability {
    cap(READER, Profile::Human, &[Op::Read, Op::Reconcile])
}

fn human_upload() -> Capability {
    cap(HUMAN, Profile::Human, &[Op::Post])
}

fn hex(oid: Oid) -> String {
    fa_formats::hex_encode(&oid.0)
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    vfs: MemVfs,
    book: AsyncBook<MemVfs>,
}

impl Harness {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let units = fa_money::UnitRegistry::embedded().unwrap();
        let spec = BookSpec {
            book_id: Id128([SEED; 16]),
            name: "Retained purchase comparison".into(),
            base_unit: units.lookup("USD").unwrap(),
            calendar: FiscalCalendar::monthly("three-way", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs.clone(),
                Path::new(BOOK_DIR),
                BookKeys::for_development(SEED),
                spec,
                Entropy::deterministic(u64::from(SEED)),
            ))
            .unwrap();
        Self {
            runtime,
            root,
            vfs,
            book,
        }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn head(&self) -> CommitSeq {
        self.book.head(&self.cx()).unwrap()
    }

    fn upload(
        &mut self,
        capability: &Capability,
        kind: &str,
        mime: &str,
        bytes: impl Into<Vec<u8>>,
    ) -> DocumentAdded {
        let policy = EvidencePolicy::embedded().unwrap();
        let cx = self.cx();
        self.runtime
            .block_on(self.book.upload_document(
                &cx,
                capability,
                UploadRequest {
                    kind: policy.kind_by_name(kind).unwrap().tag,
                    mime: mime.into(),
                    bytes: bytes.into(),
                    asserted_grade: None,
                },
            ))
            .unwrap()
            .unwrap()
    }

    fn sources(&mut self, external_po: bool) -> ThreeWayMatchRequest {
        let mut po = format!(
            "{PURCHASE_ORDER_HEADER}\nVendor,SKU-1,3,12.34,USD\nVendor,SKU-2,3,12.34,USD\n"
        );
        if external_po {
            let vendor = "V".repeat(128);
            for index in 0..128 {
                po.push_str(&format!("{vendor},UNSELECTED-{index},1,0.00,USD\n"));
            }
            assert!(
                u64::try_from(po.len()).unwrap()
                    > fa_journal::evidence::inline_document_bound(
                        &EvidencePolicy::embedded().unwrap()
                    )
            );
        }
        let po = self.upload(&human_upload(), "PurchaseOrder", "text/csv", po);
        let receipt = self.upload(
            &cap(AGENT, Profile::Agent, &[Op::Post]),
            "ReceivingReport",
            "text/csv; charset=utf-8",
            format!(
                "{RECEIVING_REPORT_HEADER}\n{},SKU-2,3\n{},SKU-1,3\n",
                hex(po.oid),
                hex(po.oid)
            ),
        );
        let invoice = self.upload(
            &human_upload(),
            "Invoice",
            "text/csv",
            format!(
                "{INVOICE_HEADER}\n{},Vendor,SKU-1,3,12.34,37.02,USD\n{},Vendor,SKU-2,3,12.34,37.02,USD\n",
                hex(po.oid),
                hex(po.oid)
            ),
        );
        ThreeWayMatchRequest {
            purchase_order_oid: po.oid,
            receiving_report_oid: receipt.oid,
            invoice_oid: invoice.oid,
            item_code: "SKU-1".into(),
            known_at: None,
            expected_digest: None,
        }
    }

    fn compare(
        &mut self,
        capability: &Capability,
        request: ThreeWayMatchRequest,
    ) -> Result<ThreeWayMatchReport, Refusal> {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.match_three_way(&cx, capability, request))
            .unwrap()
    }

    fn reopen(self) -> Self {
        let Self {
            runtime,
            root,
            vfs,
            book,
        } = self;
        drop(book);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let book = runtime
            .block_on(AsyncBook::open_with_vfs(
                &cx,
                vfs.clone(),
                Path::new(BOOK_DIR),
                BookKeys::for_development(SEED),
                Entropy::deterministic(u64::from(SEED)),
            ))
            .unwrap();
        Self {
            runtime,
            root,
            vfs,
            book,
        }
    }
}

#[test]
fn retained_sources_match_without_writes_or_upgrading_agent_evidence() {
    let mut h = Harness::new();
    let request = h.sources(false);
    let before = h.head();
    let matched = h.compare(&reader(), request.clone()).unwrap();
    assert_eq!(matched.known_at, before);
    assert_eq!(matched.result.verdict, ThreeWayMatchVerdict::Matched);
    assert_eq!(matched.purchase_order_source.line_ordinal, 1);
    assert_eq!(matched.receiving_report_source.line_ordinal, 2);
    assert_eq!(matched.invoice_source.line_ordinal, 1);
    assert_eq!(matched.purchase_order_source.uploader, HUMAN);
    assert_eq!(matched.receiving_report_source.uploader, AGENT);
    assert_eq!(matched.invoice_source.uploader, HUMAN);
    let policy = EvidencePolicy::embedded().unwrap();
    assert_eq!(
        matched.receiving_report_source.grade,
        policy.grade_by_name("AgentUpload").unwrap().tag
    );
    assert_eq!(
        matched.purchase_order_source.grade,
        policy.grade_by_name("HumanUpload").unwrap().tag
    );
    assert!(
        matched.purchase_order_source.recorded_at < matched.receiving_report_source.recorded_at
    );
    assert!(matched.receiving_report_source.recorded_at < matched.invoice_source.recorded_at);
    assert_eq!(h.head(), before);

    // An Agent may obtain the same advisory comparison. Numerical agreement
    // and a Human repeat intake never upgrade that Agent's original source.
    let repeated = h.upload(
        &human_upload(),
        "ReceivingReport",
        "text/csv; charset=utf-8",
        format!(
            "{RECEIVING_REPORT_HEADER}\n{},SKU-2,3\n{},SKU-1,3\n",
            hex(request.purchase_order_oid),
            hex(request.purchase_order_oid)
        ),
    );
    assert!(repeated.already_recorded);
    assert_eq!(repeated.grade, matched.receiving_report_source.grade);
    let agent = cap(VId(44), Profile::Agent, &[Op::Read, Op::Reconcile]);
    assert_eq!(h.compare(&agent, request).unwrap(), matched);
    assert_eq!(h.head(), before);
}

#[test]
fn external_source_replays_after_compaction_reopen_and_later_intake() {
    let mut h = Harness::new();
    let mut request = h.sources(true);
    let original = h.compare(&reader(), request.clone()).unwrap();
    request.known_at = Some(original.known_at);
    request.expected_digest = Some(original.result_digest);
    h.upload(
        &human_upload(),
        "Invoice",
        "text/plain",
        b"Unrelated later source advances the recorded head".to_vec(),
    );
    let before = h.head();
    assert!(before > original.known_at);
    let cx = h.cx();
    h.runtime.block_on(h.book.compact_storage(&cx)).unwrap();
    let mut h = h.reopen();
    assert_eq!(h.compare(&reader(), request.clone()).unwrap(), original);
    assert_eq!(h.head(), before);

    // A different valid item can have identical quantities/prices/verdict;
    // the independent digest still binds its exact selection and ordinals.
    let mut changed_item = request.clone();
    changed_item.item_code = "SKU-2".into();
    let refusal = h.compare(&reader(), changed_item.clone()).unwrap_err();
    assert_eq!(refusal.exit, exit::VERIFICATION);
    changed_item.expected_digest = None;
    let changed = h.compare(&reader(), changed_item).unwrap();
    assert_eq!(changed.result.verdict, ThreeWayMatchVerdict::Matched);
    assert_ne!(changed.result_digest, original.result_digest);
    assert_eq!(changed.purchase_order_source.line_ordinal, 2);
    assert_eq!(changed.receiving_report_source.line_ordinal, 1);

    let mut changed_prefix = request.clone();
    changed_prefix.known_at = Some(before);
    assert_eq!(
        h.compare(&reader(), changed_prefix).unwrap_err().exit,
        exit::VERIFICATION
    );
    request.expected_digest.as_mut().unwrap()[0] ^= 1;
    assert_eq!(
        h.compare(&reader(), request).unwrap_err().exit,
        exit::VERIFICATION
    );
    assert_eq!(h.head(), before);
}

#[test]
fn source_identity_kind_shape_and_all_records_are_enforced() {
    let mut h = Harness::new();
    let request = h.sources(false);
    let po = hex(request.purchase_order_oid);
    let valid_invoice = format!("{INVOICE_HEADER}\n{po},Vendor,SKU-1,3,12.34,37.02,USD\n");
    for (kind, mime, text, expected_exit) in [
        ("Bill", "text/csv", valid_invoice.clone(), exit::USAGE),
        ("Invoice", "text/plain", valid_invoice.clone(), exit::USAGE),
        (
            "Invoice",
            "text/csv",
            format!(
                "{INVOICE_HEADER}\n{},Vendor,SKU-1,3,12.34,37.02,USD\n",
                hex(Oid([7; 32]))
            ),
            exit::USAGE,
        ),
        (
            "Invoice",
            "text/csv",
            format!("{INVOICE_HEADER}\n{po},Other Vendor,SKU-1,3,12.34,37.02,USD\n"),
            exit::USAGE,
        ),
        (
            "Invoice",
            "text/csv",
            format!("{valid_invoice}{po},Vendor,UNSELECTED,invalid,1.00,1.00,USD\n"),
            exit::USAGE,
        ),
        (
            "Invoice",
            "text/csv",
            format!("{valid_invoice}{po},Vendor,SKU-1,3,12.34,37.02,USD\n"),
            exit::USAGE,
        ),
    ] {
        let source = h.upload(&human_upload(), kind, mime, text);
        let before = h.head();
        let mut invalid = request.clone();
        invalid.invoice_oid = source.oid;
        assert_eq!(
            h.compare(&reader(), invalid).unwrap_err().exit,
            expected_exit
        );
        assert_eq!(h.head(), before);
    }
    let invalid_utf8 = h.upload(&human_upload(), "Invoice", "text/csv", vec![0xff]);
    let mut invalid = request.clone();
    invalid.invoice_oid = invalid_utf8.oid;
    assert_eq!(h.compare(&reader(), invalid).unwrap_err().exit, exit::USAGE);

    let mut absent_at_prefix = request.clone();
    absent_at_prefix.known_at = Some(CommitSeq(1));
    assert_eq!(
        h.compare(&reader(), absent_at_prefix).unwrap_err().code,
        code::COORDINATE
    );
    let mut missing_item = request;
    missing_item.item_code = "NOT-PRESENT".into();
    assert_eq!(
        h.compare(&reader(), missing_item).unwrap_err().exit,
        exit::USAGE
    );
}

#[test]
fn quantities_prices_and_stated_totals_produce_distinct_advisory_variances() {
    let mut h = Harness::new();
    let request = h.sources(false);
    let po = hex(request.purchase_order_oid);
    let usd = h.book.context().units.lookup("USD").unwrap();
    for (quantity, price, total, verdict) in [
        (
            "2",
            "12.34",
            "24.68",
            ThreeWayMatchVerdict::QuantityVariance {
                po_qty: 3,
                receipt_qty: 3,
                invoice_qty: 2,
            },
        ),
        (
            "3",
            "12.35",
            "37.05",
            ThreeWayMatchVerdict::PriceVariance {
                po_unit_price: fa_money::Amount::new(usd, 1234),
                invoice_unit_price: fa_money::Amount::new(usd, 1235),
            },
        ),
        (
            "3",
            "12.34",
            "37.01",
            ThreeWayMatchVerdict::ExtensionMismatch {
                expected_total: fa_money::Amount::new(usd, 3702),
                invoice_total: fa_money::Amount::new(usd, 3701),
            },
        ),
    ] {
        let invoice = h.upload(
            &human_upload(),
            "Invoice",
            "text/csv",
            format!("{INVOICE_HEADER}\n{po},Vendor,SKU-1,{quantity},{price},{total},USD\n"),
        );
        let mut selected = request.clone();
        selected.invoice_oid = invoice.oid;
        let before = h.head();
        let report = h.compare(&reader(), selected).unwrap();
        assert_eq!(report.result.verdict, verdict);
        assert!(
            !report
                .result
                .decision_card
                .canonical_bytes()
                .unwrap()
                .is_empty()
        );
        assert_eq!(h.head(), before);
    }
}

#[test]
fn authority_and_request_shape_refuse_before_missing_source_observation() {
    let mut h = Harness::new();
    let request = ThreeWayMatchRequest {
        purchase_order_oid: Oid([1; 32]),
        receiving_report_oid: Oid([2; 32]),
        invoice_oid: Oid([3; 32]),
        item_code: "SKU-1".into(),
        known_at: None,
        expected_digest: None,
    };
    let before = h.head();
    for capability in [
        cap(READER, Profile::Human, &[Op::Read]),
        cap(READER, Profile::Human, &[Op::Reconcile]),
        reader().for_accounts(&["1000"]).unwrap(),
        reader().known_at_most(before),
        reader().for_books(&[Id128([19; 16])]).unwrap(),
    ] {
        let refused = h.compare(&capability, request.clone()).unwrap_err();
        assert_eq!(refused.code, code::CAPABILITY);
    }
    let expired = h
        .compare(&reader().expiring_at(before), request.clone())
        .unwrap_err();
    assert!(expired.message.contains("expir"));
    for item in ["", " ", " SKU-1", "SKU-1\n"] {
        let mut invalid = request.clone();
        invalid.item_code = item.into();
        assert_eq!(
            h.compare(&reader(), invalid).unwrap_err().code,
            code::STRUCTURE
        );
    }
    let mut duplicate = request.clone();
    duplicate.invoice_oid = duplicate.purchase_order_oid;
    assert_eq!(
        h.compare(&reader(), duplicate).unwrap_err().code,
        code::STRUCTURE
    );
    let mut no_prefix = request;
    no_prefix.expected_digest = Some([4; 32]);
    assert_eq!(
        h.compare(&reader(), no_prefix).unwrap_err().code,
        code::STRUCTURE
    );
    assert_eq!(h.head(), before);
}

#[test]
fn original_prefix_and_digest_never_restore_revoked_authority() {
    let mut h = Harness::new();
    let mut request = h.sources(false);
    let capability = reader();
    let original = h.compare(&capability, request.clone()).unwrap();
    request.known_at = Some(original.known_at);
    request.expected_digest = Some(original.result_digest);
    let cx = h.cx();
    h.runtime
        .block_on(h.book.revoke_capability(
            &cx,
            cap(VId(45), Profile::Human, &[Op::IssueCapability]),
            capability.commitment().unwrap(),
            DateDay::from_ymd(2026, 1, 1).unwrap(),
            b"revoke-three-way-reader",
            "Revoke reader after retained source comparison",
        ))
        .unwrap()
        .unwrap();
    let before = h.head();
    let refused = h.compare(&capability, request).unwrap_err();
    assert!(refused.message.contains("revok"));
    assert_eq!(h.head(), before);
}

#[test]
fn intact_custody_payloads_must_also_form_one_linked_chain() {
    let mut h = Harness::new();
    let request = h.sources(false);
    let at = h.head();
    let cx = h.cx();
    let document = match h
        .runtime
        .block_on(
            h.book
                .read_document_for(&cx, &reader(), &request.purchase_order_oid),
        )
        .unwrap()
        .unwrap()
    {
        DocumentRead::Full(document) => document,
        DocumentRead::Redacted(_) => panic!("purchase source unexpectedly redacted"),
    };
    let mut chain = h
        .book
        .query(&cx, |db, _| {
            Ok(fa_journal::custody::custody_chain(
                db,
                &request.purchase_order_oid,
            )?)
        })
        .unwrap();
    let receipt = chain[0].0.clone();
    let recorded_at = chain[0].1;
    let transfer = CustodyEvent {
        book_id: document.book_id,
        document_oid: request.purchase_order_oid,
        index: 1,
        prev_digest: receipt.digest().unwrap(),
        body: CustodyBody::Transfer {
            from: HUMAN,
            to: VId(90),
        },
    };
    chain.push((transfer, at));
    let check = |chain: &[(CustodyEvent, CommitSeq)]| {
        // Each mutated event still has a canonically encodable, self-valid
        // payload. Its relationship to the preceding event is the risk.
        for (event, _) in chain {
            assert_eq!(
                CustodyEvent::decode(&event.canonical_bytes().unwrap()).unwrap(),
                *event
            );
        }
        intake_at(
            document.book_id,
            &document,
            request.purchase_order_oid,
            at,
            chain,
        )
        .unwrap()
    };
    assert_eq!(check(&chain).unwrap(), recorded_at);
    let mut wrong_predecessor = chain.clone();
    wrong_predecessor[1].0.prev_digest = [9; 32];
    assert_eq!(
        check(&wrong_predecessor).unwrap_err().exit,
        exit::VERIFICATION
    );
    let mut wrong_holder = chain.clone();
    wrong_holder[1].0.body = CustodyBody::Transfer {
        from: VId(91),
        to: VId(90),
    };
    assert_eq!(check(&wrong_holder).unwrap_err().exit, exit::VERIFICATION);
    let mut other_document = chain;
    other_document[1].0.document_oid = request.invoice_oid;
    assert_eq!(check(&other_document).unwrap_err().exit, exit::VERIFICATION);
    assert_eq!(h.head(), at);
}
