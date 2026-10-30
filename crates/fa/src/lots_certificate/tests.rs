use super::*;

use crate::{
    BookKeys, CertificateStatus, Entropy, ReportArtifactExpectation, ReportArtifactFamily,
};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest};
use fa_model::{
    EntryOrigin, EntryPayload, EntryRef, EvidenceRef, LegPayload, Oid, Settlement, Supersession,
    SupersessionKind, account_vid,
};
use fa_money::UnitRegistry;
use fa_time::{FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;
use std::path::Path;

const BOOK: Id128 = Id128([0x79; 16]);
const PRINCIPAL: VId = VId(7);
const PATH: &str = "lots-certificate-book";
fn day(value: &str) -> DateDay {
    DateDay::parse(value).unwrap()
}
fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}
fn keys() -> BookKeys {
    BookKeys::for_development(0x79)
}
fn account(code: &str, kind: AccountType, units: UnitPolicy) -> AccountSpec {
    AccountSpec {
        code: code.into(),
        name: format!("{code} account"),
        account_type: kind.0,
        normal_balance: u8::from(kind == AccountType::EQUITY),
        is_leaf: true,
        unit_policy: units,
        parent_code: None,
        limit: None,
    }
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    vfs: MemVfs,
    book: AsyncBook<MemVfs>,
    usd: UnitId,
    qty: UnitId,
    evidence: EvidenceRef,
}
impl Harness {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let qty = units.lookup("SHARE").unwrap();
        let vfs = MemVfs::new().unwrap();
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs.clone(),
                Path::new(PATH),
                keys(),
                BookSpec {
                    book_id: BOOK,
                    name: "Certified native lots".into(),
                    base_unit: usd,
                    calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(121),
            ))
            .unwrap();
        runtime
            .block_on(book.install_chart(
                &cx,
                &[
                    account("inventory", AccountType::ASSET, UnitPolicy::AnyUnit),
                    account("other", AccountType::ASSET, UnitPolicy::AnyUnit),
                    account("quantity-offset", AccountType::EQUITY, UnitPolicy::AnyUnit),
                    account("cash", AccountType::ASSET, UnitPolicy::AnyCurrency),
                    account("expense", AccountType::EXPENSE, UnitPolicy::AnyCurrency),
                ],
                PRINCIPAL,
                day("2026-01-01"),
                b"chart",
                &cap(&["schema_change"]),
            ))
            .unwrap()
            .unwrap();
        runtime
            .block_on(book.create_periods(&cx, 2026, PRINCIPAL, &cap(&["schema_change"])))
            .unwrap()
            .unwrap();
        runtime
            .block_on(book.transition_period(
                &cx,
                "FY2026-P03",
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                b"open",
                &cap(&["close"]),
            ))
            .unwrap()
            .unwrap();
        let document = Document {
            book_id: BOOK,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"Native lots acquisition and disposal evidence".to_vec(),
        };
        runtime
            .block_on(book.add_document(&cx, &document))
            .unwrap()
            .unwrap();
        Self {
            runtime,
            root,
            vfs,
            book,
            usd,
            qty,
            evidence: document.evidence_ref(1),
        }
    }
    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }
    fn head(&self) -> CommitSeq {
        self.book.head(&self.cx()).unwrap()
    }
    fn id(&self, code: &str) -> VId {
        account_vid(BOOK, code)
    }
    fn leg(&self, side: Side, code: &str, unit: UnitId, value: i128) -> LegPayload {
        LegPayload::simple(side, self.id(code), Amount::new(unit, value))
    }
    fn proposal(&self, key: &str, date: &str, legs: Vec<LegPayload>) -> EntryPayload {
        EntryPayload {
            schema_minor: 0,
            book_id: BOOK,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day(date),
            document_date: None,
            description: self.book.seal_text(&self.cx(), key).unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.as_bytes().to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([9; 32]),
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: vec![self.evidence],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        }
    }
    fn publish(&mut self, proposal: EntryPayload) -> EntryRef {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.post(
                &cx,
                PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    plan_certificate: None,
                    capability: cap(&["post"]),
                },
            ))
            .unwrap()
            .unwrap()
            .entry_ref()
    }
    fn acquisition_legs(&self, account: &str, quantity: i128, cost: i128) -> Vec<LegPayload> {
        vec![
            self.leg(Side::Debit, account, self.qty, quantity),
            self.leg(Side::Credit, "quantity-offset", self.qty, quantity),
            self.leg(Side::Debit, account, self.usd, cost),
            self.leg(Side::Credit, "cash", self.usd, cost),
        ]
    }
    fn acquire(&mut self, key: &str, date: &str, quantity: i128, cost: i128) -> EntryRef {
        self.publish(self.proposal(
            key,
            date,
            self.acquisition_legs("inventory", quantity, cost),
        ))
    }
    fn dispose(
        &mut self,
        key: &str,
        date: &str,
        quantity: i128,
        cost: i128,
        quantities: &[(EntryRef, i128)],
        costs: &[(EntryRef, i128)],
    ) -> EntryRef {
        let mut legs = vec![
            self.leg(Side::Credit, "inventory", self.qty, quantity),
            self.leg(Side::Debit, "quantity-offset", self.qty, quantity),
            self.leg(Side::Credit, "inventory", self.usd, cost),
            self.leg(Side::Debit, "expense", self.usd, cost),
        ];
        legs[0].settles = quantities
            .iter()
            .map(|(target, amount)| Settlement {
                target: *target,
                ordinal: 0,
                amount: Amount::new(self.qty, *amount),
            })
            .collect();
        legs[2].settles = costs
            .iter()
            .map(|(target, amount)| Settlement {
                target: *target,
                ordinal: 2,
                amount: Amount::new(self.usd, *amount),
            })
            .collect();
        for leg in &mut legs {
            leg.settles.sort_by_key(|s| (s.target.vid, s.ordinal));
        }
        self.publish(self.proposal(key, date, legs))
    }
    fn reverse(&mut self, key: &str, date: &str, target: EntryRef) -> EntryRef {
        let (entry, _) = self
            .book
            .read_entry(&self.cx(), target.vid)
            .unwrap()
            .unwrap();
        let mut legs = entry.proposal.legs;
        for leg in &mut legs {
            leg.side = match leg.side {
                Side::Debit => Side::Credit,
                Side::Credit => Side::Debit,
            };
            leg.settles.clear();
        }
        let mut proposal = self.proposal(key, date, legs);
        proposal.class = EntryClass::REVERSAL;
        proposal.supersession = vec![Supersession {
            kind: SupersessionKind::Reverses,
            target,
            reason_code: 1,
        }];
        self.publish(proposal)
    }
    fn request(&self, cutoff: Option<&str>) -> LotsRequest {
        LotsRequest {
            account: self.id("inventory"),
            effective_through: cutoff.map(day),
            known_at: None,
        }
    }
    fn certify(&self, request: &LotsRequest) -> CertifiedLots {
        self.book
            .certify_lots(&self.cx(), PRINCIPAL, &cap(&["read", "produce"]), request)
            .unwrap()
            .unwrap()
    }
    fn replay(&self, certificate: &LotsCertificate) -> LotsReport {
        self.book
            .replay_lots(&self.cx(), PRINCIPAL, &cap(&["read"]), certificate)
            .unwrap()
            .unwrap()
    }
    fn status(&self, certificate: &LotsCertificate) -> CertificateStatus {
        self.book
            .report_artifact_status(
                &self.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &certificate.canonical_bytes().unwrap(),
                Some(certificate.digest()),
                ReportArtifactExpectation::Lots(&certificate.request().unwrap()),
            )
            .unwrap()
            .unwrap()
    }
    fn reopen(self) -> Self {
        let Self {
            runtime,
            root,
            vfs,
            book,
            usd,
            qty,
            evidence,
        } = self;
        drop(book);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let book = runtime
            .block_on(AsyncBook::open_with_vfs(
                &cx,
                vfs.clone(),
                Path::new(PATH),
                keys(),
                Entropy::deterministic(122),
            ))
            .unwrap();
        Self {
            runtime,
            root,
            vfs,
            book,
            usd,
            qty,
            evidence,
        }
    }
}

#[test]
fn cutoff_is_selected_before_relief_netting_and_saved_prefix_stays_fixed() {
    let mut h = Harness::new();
    let acquired = h.acquire("acquire", "2026-03-01", 10, 1000);
    let before = h.head();
    h.dispose(
        "first-sale",
        "2026-03-15",
        4,
        400,
        &[(acquired, 4)],
        &[(acquired, 400)],
    );
    h.dispose(
        "later-sale",
        "2026-03-25",
        2,
        200,
        &[(acquired, 2)],
        &[(acquired, 200)],
    );
    let head = h.head();
    for (cutoff, quantity, cost, applications) in [
        ("2026-03-10", 10, 1000, 0),
        ("2026-03-20", 6, 600, 1),
        ("2026-03-31", 4, 400, 2),
    ] {
        let certified = h.certify(&h.request(Some(cutoff)));
        let lot = &certified.report.lots[0];
        assert_eq!(lot.entry_digest, acquired.entry_digest);
        assert_eq!(
            (lot.open_quantity.mantissa, lot.open_cost.mantissa),
            (quantity, cost)
        );
        assert_eq!(lot.relieves.len(), applications);
        assert_eq!(h.replay(&certified.certificate), certified.report);
    }
    let mut old_request = h.request(None);
    old_request.known_at = Some(before);
    let old = h.certify(&old_request);
    assert_eq!(old.report.lots[0].open_quantity.mantissa, 10);
    let current = h.certify(&h.request(None));
    assert_eq!(current.report.lots[0].open_quantity.mantissa, 4);
    assert_eq!(h.head(), head, "certification and replay publish nothing");
}

#[test]
fn complete_cost_only_reliefs_and_reversals_roundtrip_without_fabricated_digests() {
    let mut h = Harness::new();
    let expensive = h.acquire("expensive", "2026-03-01", 1, 300);
    let cheap = h.acquire("cheap", "2026-03-02", 1, 100);
    h.dispose(
        "weighted-first",
        "2026-03-10",
        1,
        200,
        &[(expensive, 1)],
        &[(expensive, 200)],
    );
    let middle = h.certify(&h.request(None));
    assert_eq!(
        (
            middle.report.lots[0].open_quantity.mantissa,
            middle.report.lots[0].open_cost.mantissa
        ),
        (0, 100)
    );
    let last = h.dispose(
        "weighted-last",
        "2026-03-15",
        1,
        200,
        &[(cheap, 1)],
        &[(expensive, 100), (cheap, 100)],
    );
    let final_report = h.certify(&h.request(None));
    let edge = &final_report.report.lots[0].relieves[1];
    assert_eq!(edge.disposal_entry, last.vid);
    assert_eq!(edge.qty_ordinal, None);
    assert_eq!(edge.cost_ordinal, Some(2));
    assert_eq!((edge.quantity.mantissa, edge.cost.mantissa), (0, 100));
    assert!(
        final_report
            .report
            .lots
            .iter()
            .all(|lot| lot.open_quantity.mantissa == 0 && lot.open_cost.mantissa == 0)
    );
    h.reverse("reverse-last", "2026-03-20", last);
    let restored = h.certify(&h.request(None));
    assert_eq!(
        (
            restored.report.lots[0].open_quantity.mantissa,
            restored.report.lots[0].open_cost.mantissa
        ),
        (0, 100)
    );
    assert!(!restored.report.lots[0].relieves[1].live);
    assert_eq!(restored.report.lots[1].open_quantity.mantissa, 1);
    let bytes = restored.certificate.canonical_bytes().unwrap();
    let decoded = LotsCertificate::decode(&bytes).unwrap();
    assert_eq!(
        decoded.output(),
        lots_output_bytes(&restored.report).unwrap()
    );
    assert_eq!(h.replay(&decoded), restored.report);
    assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
}

#[test]
fn retention_dispatch_and_historical_replay_survive_reopen() {
    let mut h = Harness::new();
    h.acquire("first", "2026-03-01", 7, 770);
    let certified = h.certify(&h.request(Some("2026-03-31")));
    let bytes = certified.certificate.canonical_bytes().unwrap();
    let cx = h.cx();
    let retained = h
        .runtime
        .block_on(h.book.retain_report_artifact(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &bytes,
            Some(certified.certificate.digest()),
        ))
        .unwrap()
        .unwrap();
    let after = h.head();
    let retry = h
        .runtime
        .block_on(h.book.retain_report_artifact(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &bytes,
            Some(certified.certificate.digest()),
        ))
        .unwrap()
        .unwrap();
    assert_eq!(retained, retry);
    assert_eq!(h.head(), after);
    h.acquire("later", "2026-03-02", 2, 220);
    let h = h.reopen();
    let cx = h.cx();
    let stored = h
        .runtime
        .block_on(h.book.read_report_artifact(
            &cx,
            PRINCIPAL,
            &cap(&["read"]),
            certified.certificate.digest(),
        ))
        .unwrap()
        .unwrap();
    assert_eq!(stored.family(), ReportArtifactFamily::Lots);
    assert_eq!(stored.canonical_bytes().unwrap(), bytes);
    assert_eq!(
        stored.output(),
        lots_output_bytes(&certified.report).unwrap()
    );
    assert_eq!(h.replay(&certified.certificate), certified.report);
    let from_source = h
        .book
        .certify_lots_from_source(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            certified.certificate.source(),
            Some(day("2026-03-31")),
        )
        .unwrap()
        .unwrap();
    assert_eq!(from_source.report, certified.report);
    assert_eq!(
        from_source.certificate.source().canonical_bytes().unwrap(),
        certified.certificate.source().canonical_bytes().unwrap()
    );
    let replayed = h
        .book
        .replay_report_artifact_for(
            &cx,
            PRINCIPAL,
            &cap(&["read"]),
            &bytes,
            Some(certified.certificate.digest()),
            ReportArtifactExpectation::Lots(&certified.certificate.request().unwrap()),
        )
        .unwrap()
        .unwrap();
    assert_eq!(replayed.output, stored.output());
}

#[test]
fn repaired_outer_hash_does_not_make_false_cost_currency_or_digest_true() {
    let mut h = Harness::new();
    h.acquire("basis", "2026-03-01", 10, 1000);
    let certified = h.certify(&h.request(None));
    let mut false_report = certified.report.clone();
    false_report.lots[0].open_cost.mantissa += 1;
    let mut false_digest = certified.report.clone();
    false_digest.lots[0].entry_digest[0] ^= 1;
    let mut false_currency = certified.report.clone();
    false_currency.base_unit = UnitRegistry::embedded().unwrap().lookup("EUR").unwrap();
    for report in [false_report, false_digest, false_currency] {
        let forged = LotsCertificate::seal(
            certified.certificate.source.clone(),
            &report,
            PRINCIPAL,
            certified.certificate.capability_commitment,
        )
        .unwrap();
        let encoded = forged.canonical_bytes().unwrap();
        assert!(
            LotsCertificate::decode(&encoded).is_ok(),
            "outer content integrity alone is insufficient"
        );
        assert!(
            h.book
                .replay_lots(&h.cx(), PRINCIPAL, &cap(&["read"]), &forged)
                .unwrap()
                .is_err()
        );
        assert!(
            h.book
                .replay_report_artifact(&h.cx(), PRINCIPAL, &cap(&["read"]), &encoded, None)
                .unwrap()
                .is_err()
        );
    }
    let mut wrong = certified.certificate.request().unwrap();
    wrong.account = h.id("other");
    assert!(
        h.book
            .replay_lots_for(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &certified.certificate,
                &wrong
            )
            .unwrap()
            .is_err()
    );
    wrong = certified.certificate.request().unwrap();
    wrong.known_at = None;
    assert!(
        h.book
            .replay_lots_for(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &certified.certificate,
                &wrong
            )
            .unwrap()
            .is_err()
    );
}

#[test]
fn unsupported_selected_history_refuses_instead_of_silently_disappearing() {
    for kind in ["bare-cost", "multiple-pairs", "partial-credit"] {
        let mut h = Harness::new();
        let acquired = h.acquire("valid", "2026-03-01", 10, 1000);
        match kind {
            "bare-cost" => {
                let legs = vec![
                    h.leg(Side::Debit, "inventory", h.usd, 10),
                    h.leg(Side::Credit, "cash", h.usd, 10),
                ];
                let orphan = h.publish(h.proposal("bare-cost", "2026-03-25", legs));
                h.reverse("reverse-orphan", "2026-03-26", orphan);
            }
            "multiple-pairs" => {
                let mut legs = h.acquisition_legs("inventory", 1, 10);
                legs.extend(h.acquisition_legs("inventory", 2, 20));
                h.publish(h.proposal("multiple-pairs", "2026-03-25", legs));
                assert_eq!(
                    h.book
                        .lots(&h.cx(), h.id("inventory"), None, None)
                        .unwrap()
                        .lots
                        .len(),
                    3,
                    "ordinary multi-pair advisory lots remain supported"
                );
            }
            _ => {
                h.dispose(
                    "partial-credit",
                    "2026-03-25",
                    2,
                    200,
                    &[(acquired, 1)],
                    &[(acquired, 100)],
                );
            }
        }
        let refused = h
            .book
            .certify_lots(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &h.request(Some("2026-03-10")),
            )
            .unwrap()
            .unwrap_err();
        assert!(
            refused.message.contains("pair") || refused.message.contains("partially applied"),
            "{kind}: {}",
            refused.message
        );
    }
}

#[test]
fn unrelated_history_and_after_cutoff_acquisitions_do_not_supersede_the_schedule() {
    let mut h = Harness::new();
    h.acquire("original", "2026-03-01", 10, 1000);
    let certified = h.certify(&h.request(Some("2026-03-10")));
    assert!(matches!(
        h.status(&certified.certificate),
        CertificateStatus::Current { .. }
    ));
    // An unsupported native-cost shape on another account must not poison this account's profile.
    h.publish(h.proposal(
        "unrelated",
        "2026-03-02",
        vec![
            h.leg(Side::Debit, "other", h.usd, 10),
            h.leg(Side::Credit, "cash", h.usd, 10),
        ],
    ));
    h.acquire("future", "2026-03-25", 2, 200);
    assert!(matches!(
        h.status(&certified.certificate),
        CertificateStatus::Current { .. }
    ));
    let backdated = h.acquire("backdated", "2026-03-05", 3, 300);
    let CertificateStatus::SupersededBy { later_entries, .. } = h.status(&certified.certificate)
    else {
        panic!("a new contribution inside the original coordinates supersedes the schedule")
    };
    assert_eq!(later_entries, vec![backdated.vid]);
    assert_eq!(h.replay(&certified.certificate), certified.report);
}

#[test]
fn production_requires_current_authority_and_historical_pins_do_not_read_head() {
    let mut h = Harness::new();
    h.acquire("original", "2026-03-01", 10, 1000);
    let certified = h.certify(&h.request(None));
    let fixed = certified.certificate.request().unwrap();
    let pinned = cap(&["read", "produce"]).known_at_most(certified.report.known_at);
    h.acquire("later", "2026-03-02", 1, 100);
    let head = h.head();
    assert_eq!(
        h.book
            .certify_lots(&h.cx(), PRINCIPAL, &pinned, &fixed)
            .unwrap()
            .unwrap()
            .report,
        certified.report
    );
    assert!(
        h.book
            .certify_lots(&h.cx(), PRINCIPAL, &pinned, &h.request(None))
            .unwrap()
            .is_err()
    );
    assert!(
        h.book
            .certify_lots(&h.cx(), PRINCIPAL, &cap(&["read"]), &fixed)
            .unwrap()
            .is_err()
    );
    let scoped = cap(&["read", "produce"])
        .for_accounts(&["inventory"])
        .unwrap();
    assert!(
        h.book
            .certify_lots(&h.cx(), PRINCIPAL, &scoped, &fixed)
            .unwrap()
            .is_err()
    );
    assert!(
        h.book
            .replay_lots(&h.cx(), VId(8), &cap(&["read"]), &certified.certificate)
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), head);
}

#[test]
fn portable_bundle_recomputes_real_native_cost_only_reliefs_independently() {
    let mut h = Harness::new();
    let expensive = h.acquire("portable-expensive", "2026-03-01", 1, 300);
    let cheap = h.acquire("portable-cheap", "2026-03-02", 1, 100);
    h.dispose(
        "portable-first",
        "2026-03-10",
        1,
        200,
        &[(expensive, 1)],
        &[(expensive, 200)],
    );
    h.dispose(
        "portable-final",
        "2026-03-15",
        1,
        200,
        &[(cheap, 1)],
        &[(expensive, 100), (cheap, 100)],
    );
    let certified = h.certify(&h.request(Some("2026-03-31")));
    let cx = h.cx();
    let checkpoint = h
        .runtime
        .block_on(
            h.book
                .checkpoint(&cx, PRINCIPAL, &cap(&["read", "produce", "witness"])),
        )
        .unwrap()
        .unwrap();
    let state = checkpoint.checkpoint.checkpoint.body.state_oid;
    let before = h.head();
    let produced = h
        .runtime
        .block_on(h.book.produce_lots_bundle(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            Some(state),
            &certified.certificate,
        ))
        .unwrap()
        .unwrap()
        .unwrap();
    let again = h
        .runtime
        .block_on(h.book.produce_lots_bundle(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            Some(state),
            &certified.certificate,
        ))
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(produced, again);
    assert_eq!(
        h.head(),
        before,
        "portable production appends no accounting entry"
    );
    let key = h.book.checkpoint_public_key();
    let anchor = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    let verified = fa_verify::report::verify_lots_report_expected(
        &produced.bundle.bytes,
        &[key],
        Some(&anchor.checkpoint),
        Some(&produced.receipt),
        h.usd.0,
        Some(certified.certificate.digest()),
    )
    .expect("independent replay of the actual native bundle");
    assert_eq!(verified.output, certified.certificate.output());
    assert_eq!(verified.certificate_digest, *certified.certificate.digest());
    let lots = verified.lots.unwrap();
    assert_eq!(lots.account, h.id("inventory").0);
    assert_eq!(lots.known_at, certified.report.known_at.0);
    assert_eq!(lots.base_unit, h.usd.0);
    assert_eq!(lots.lots.len(), 2);
    assert_eq!(lots.lots[0].entry_digest, expensive.entry_digest);
    assert_eq!(lots.lots[0].relieves[1].qty_ordinal, None);
    assert_eq!(lots.lots[0].relieves[1].cost.mantissa, 100);
    assert_eq!(lots.lots[0].open_cost.mantissa, 0);
    assert!(
        fa_verify::report::verify_lots_report_expected(
            &produced.bundle.bytes,
            &[key],
            Some(&anchor.checkpoint),
            Some(&produced.receipt),
            h.qty.0,
            Some(certified.certificate.digest())
        )
        .is_err(),
        "the delivery cannot choose its own currency basis"
    );
    assert!(
        fa_verify::report::verify_report_expected(
            &produced.bundle.bytes,
            &[key],
            Some(&anchor.checkpoint),
            Some(&produced.receipt),
            Some(certified.certificate.digest())
        )
        .is_err(),
        "generic verification supplies no independently selected base currency"
    );
}
