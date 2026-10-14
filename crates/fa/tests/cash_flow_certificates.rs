//! Native producer/replay regressions: no caller-supplied balances or mock proofs.

use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa::general_ledger::{CashFlowActivity, CashFlowAssignment, CashFlowDefinition};
use fa::{
    AsyncBook, BookKeys, Capability, CashFlowCertificate, CertifiedCashFlow, Entropy,
    RollForwardRequest,
};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, UnitPolicy};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, EvidenceRef, Id128, LegPayload, Oid,
    account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

const PRINCIPAL: VId = VId(1);
fn day(d: u8) -> DateDay {
    DateDay::from_ymd(2026, 1, d).unwrap()
}
fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    book: AsyncBook<MemVfs>,
    usd: UnitId,
    jpy: UnitId,
    evidence: Vec<EvidenceRef>,
}

impl Harness {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let jpy = units.lookup("JPY").unwrap();
        let book_id = Id128([123; 16]);
        let spec = BookSpec {
            book_id,
            name: "Cash-flow native replay".into(),
            base_unit: usd,
            calendar: FiscalCalendar::monthly("cash-replay", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs,
                Path::new("cash-flow-replay-book"),
                BookKeys::for_development(123),
                spec,
                Entropy::deterministic(123),
            ))
            .unwrap();
        let accounts: Vec<_> = [
            ("1000", AccountType::ASSET),
            ("1010", AccountType::ASSET),
            ("3000", AccountType::EQUITY),
        ]
        .into_iter()
        .map(|(code, kind)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type: kind.0,
            normal_balance: u8::from(kind == AccountType::EQUITY),
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        })
        .collect();
        runtime
            .block_on(book.install_chart(&cx, &accounts, PRINCIPAL, day(1), b"cash-chart"))
            .unwrap()
            .unwrap();
        runtime.block_on(book.create_periods(&cx, 2026)).unwrap();
        runtime
            .block_on(book.transition_period(
                &cx,
                "FY2026-P01",
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                day(1),
                b"cash-open",
                &cap(&["close"]),
            ))
            .unwrap()
            .unwrap();
        let doc = Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"Confidential underlying cash evidence".to_vec(),
        };
        runtime
            .block_on(book.add_document(&cx, &doc))
            .unwrap()
            .unwrap();
        Self {
            runtime,
            root,
            book,
            usd,
            jpy,
            evidence: vec![doc.evidence_ref(1)],
        }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }
    fn id(&self, code: &str) -> VId {
        account_vid(self.book.context().book_id, code)
    }
    fn head(&self) -> CommitSeq {
        self.book.head(&self.cx()).unwrap()
    }
    fn request(&self) -> RollForwardRequest {
        RollForwardRequest {
            accounts: vec![self.id("1000"), self.id("1010")],
            units: vec![self.usd.0, self.jpy.0],
            label: "January cash €\nworkpaper".into(),
            effective_from: day(10),
            effective_through: day(20),
            known_at: Some(self.head()),
        }
    }
    fn post(&mut self, date: u8, key: &[u8], unit: UnitId, net: i128) {
        let cx = self.cx();
        let (debit, credit) = if net >= 0 {
            ("1000", "3000")
        } else {
            ("3000", "1000")
        };
        let amount = Amount::new(unit, net.abs());
        let legs = vec![
            LegPayload::simple(Side::Debit, self.id(debit), amount),
            LegPayload::simple(Side::Credit, self.id(credit), amount),
        ];
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id: self.book.context().book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day(date),
            document_date: None,
            description: self
                .book
                .seal_text(&cx, "Private cash posting narrative")
                .unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([57; 32]),
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: self.evidence.clone(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            tags: Vec::new(),
            extensions: Vec::new(),
        };
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
            .unwrap();
    }
    fn definition(&self, request: &RollForwardRequest) -> CashFlowDefinition {
        let ledger = self
            .book
            .general_ledger(&self.cx(), PRINCIPAL, &cap(&["read"]), request)
            .unwrap()
            .unwrap();
        CashFlowDefinition {
            name: "Explicit cash policy v1".into(),
            cash_accounts: request.accounts.iter().map(|id| id.0).collect(),
            assignments: ledger
                .lines()
                .iter()
                .map(|line| CashFlowAssignment {
                    entry_digest: line.entry_digest,
                    leg_index: line.leg_index,
                    activity: if line.debits > 0 {
                        CashFlowActivity::Operating
                    } else {
                        CashFlowActivity::Investing
                    },
                })
                .collect(),
        }
    }
    fn certify(
        &self,
        request: &RollForwardRequest,
        definition: &CashFlowDefinition,
    ) -> CertifiedCashFlow {
        self.book
            .certify_cash_flow(
                &self.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                request,
                definition,
            )
            .unwrap()
            .unwrap()
    }
}

#[test]
fn native_cash_flow_certificate_roundtrips_exactly_with_zero_cells_and_large_native_units() {
    let mut h = Harness::new();
    let large = (1i128 << 100) + 17;
    h.post(1, b"opening", h.usd, 100);
    h.post(10, b"inflow", h.usd, large);
    h.post(20, b"outflow", h.jpy, -7);
    let request = h.request();
    let definition = h.definition(&request);
    let before = h.head();
    let certified = h.certify(&request, &definition);
    let bytes = certified.certificate().canonical_bytes().unwrap();
    let decoded = CashFlowCertificate::decode(&bytes).unwrap();
    assert_eq!(&decoded, certified.certificate());
    assert_eq!(decoded.known_at(), before);
    assert_eq!(
        decoded.output(),
        certified.report().canonical_bytes().unwrap()
    );
    let report = h
        .book
        .replay_cash_flow(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            &decoded,
            &request,
            &definition,
        )
        .unwrap()
        .unwrap();
    assert_eq!(&report, certified.report());
    assert_eq!(report.source().cells().len(), 4); // zero leaf and both units retained
    let usd = report
        .units()
        .iter()
        .find(|unit| unit.unit_id == h.usd.0)
        .unwrap();
    assert_eq!(
        (usd.opening, usd.operating.inflows, usd.closing),
        (100, large, large + 100)
    );
    let jpy = report
        .units()
        .iter()
        .find(|unit| unit.unit_id == h.jpy.0)
        .unwrap();
    assert_eq!((jpy.investing.outflows, jpy.closing), (7, -7));
    assert_eq!(h.head(), before);
}

#[test]
fn old_cash_flow_replays_after_later_and_backdated_postings_without_moving_the_cutoff() {
    let mut h = Harness::new();
    h.post(1, b"opening", h.usd, 100);
    h.post(15, b"original", h.usd, 20);
    let request = h.request();
    let definition = h.definition(&request);
    let certified = h.certify(&request, &definition);
    let portable = certified.certificate().canonical_bytes().unwrap();
    h.post(12, b"backdated", h.usd, -9);
    h.post(21, b"later", h.usd, 7);
    let before = h.head();
    let decoded = CashFlowCertificate::decode(&portable).unwrap();
    let report = h
        .book
        .replay_cash_flow(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            &decoded,
            &request,
            &definition,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        report.canonical_bytes().unwrap(),
        certified.report().canonical_bytes().unwrap()
    );
    assert_eq!(h.head(), before);
    assert!(
        h.book
            .certify_cash_flow(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &h.request(),
                &definition
            )
            .unwrap()
            .is_err()
    ); // stale assignment omits new leg
}

#[test]
fn equivalent_scope_and_assignment_permutations_keep_one_certificate_identity() {
    let mut h = Harness::new();
    h.post(10, b"one", h.usd, 30);
    h.post(12, b"two", h.usd, -5);
    let mut request = h.request();
    let mut definition = h.definition(&request);
    let original = h.certify(&request, &definition);
    request.accounts.reverse();
    request.units.reverse();
    definition.cash_accounts.reverse();
    definition.assignments.reverse();
    let permuted = h.certify(&request, &definition);
    assert_eq!(original.certificate(), permuted.certificate());
    assert_eq!(
        h.book
            .replay_cash_flow(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                original.certificate(),
                &request,
                &definition
            )
            .unwrap()
            .unwrap(),
        *original.report()
    );
}

#[test]
fn native_replay_catches_a_forged_output_even_when_the_attacker_recomputes_its_digest() {
    let mut h = Harness::new();
    h.post(10, b"one", h.usd, 30);
    let request = h.request();
    let definition = h.definition(&request);
    let certified = h.certify(&request, &definition);
    let mut bytes = certified.certificate().canonical_bytes().unwrap();
    // The final output field is the final native unit's closing i128; it is
    // intentionally opaque to the envelope decoder, but NOT to native replay.
    let end = bytes.len() - 32;
    bytes[end - 16] ^= 1;
    let digest = fa_model::domain_digest(b"fa:cash-flow-certificate-digest:v1", &[&bytes[..end]]);
    bytes[end..].copy_from_slice(&digest);
    let forged = CashFlowCertificate::decode(&bytes).unwrap();
    assert_ne!(forged.digest(), certified.certificate().digest());
    let refusal = h
        .book
        .replay_cash_flow(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            &forged,
            &request,
            &definition,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.exit, 8);
}

#[test]
fn valid_reclassification_cannot_substitute_for_the_recipients_expected_definition() {
    let mut h = Harness::new();
    h.post(10, b"one", h.usd, 30);
    let request = h.request();
    let definition = h.definition(&request);
    let original = h.certify(&request, &definition);
    let mut other = definition.clone();
    other.assignments[0].activity = CashFlowActivity::Financing;
    let substituted = h.certify(&request, &other);
    let original_usd = original
        .report()
        .units()
        .iter()
        .find(|unit| unit.unit_id == h.usd.0)
        .unwrap();
    let other_usd = substituted
        .report()
        .units()
        .iter()
        .find(|unit| unit.unit_id == h.usd.0)
        .unwrap();
    assert_eq!(
        (original_usd.operating.inflows, other_usd.financing.inflows),
        (30, 30)
    );
    assert_eq!(original_usd.net_change, other_usd.net_change);
    assert_ne!(
        original.certificate().digest(),
        substituted.certificate().digest()
    );
    assert!(
        h.book
            .replay_cash_flow(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                substituted.certificate(),
                &request,
                &definition
            )
            .unwrap()
            .is_err()
    );
    let mut renamed = definition.clone();
    renamed.name.push_str(" revised");
    assert!(
        h.book
            .replay_cash_flow(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                original.certificate(),
                &request,
                &renamed
            )
            .unwrap()
            .is_err()
    );
}

#[test]
fn independent_request_rejects_head_substitution_and_omitted_zero_accounts_or_units() {
    let mut h = Harness::new();
    h.post(10, b"one", h.usd, 30);
    let request = h.request();
    let definition = h.definition(&request);
    let certified = h.certify(&request, &definition);
    for expected in [
        RollForwardRequest {
            known_at: None,
            ..request.clone()
        },
        RollForwardRequest {
            known_at: Some(CommitSeq(h.head().0 - 1)),
            ..request.clone()
        },
        RollForwardRequest {
            accounts: vec![h.id("1000")],
            ..request.clone()
        },
        RollForwardRequest {
            units: vec![h.usd.0],
            ..request.clone()
        },
        RollForwardRequest {
            effective_from: day(11),
            ..request.clone()
        },
        RollForwardRequest {
            label: "Another workpaper".into(),
            ..request.clone()
        },
    ] {
        assert!(
            h.book
                .replay_cash_flow(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read"]),
                    certified.certificate(),
                    &expected,
                    &definition
                )
                .unwrap()
                .is_err()
        );
    }
}

#[test]
fn current_read_and_produce_authority_are_not_granted_by_certificate_possession() {
    let mut h = Harness::new();
    h.post(10, b"one", h.usd, 30);
    let request = h.request();
    let definition = h.definition(&request);
    let certified = h.certify(&request, &definition);
    for capability in [cap(&["read"]), cap(&["produce"]), cap(&["post"])] {
        assert!(
            h.book
                .certify_cash_flow(&h.cx(), PRINCIPAL, &capability, &request, &definition)
                .unwrap()
                .is_err()
        );
    }
    for (principal, capability) in [(PRINCIPAL, cap(&["post"])), (VId(99), cap(&["read"]))] {
        assert!(
            h.book
                .replay_cash_flow(
                    &h.cx(),
                    principal,
                    &capability,
                    certified.certificate(),
                    &request,
                    &definition
                )
                .unwrap()
                .is_err()
        );
    }
    assert!(
        h.book
            .replay_cash_flow(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                certified.certificate(),
                &request,
                &definition
            )
            .unwrap()
            .is_ok()
    );
}

#[test]
fn portable_envelope_rejects_malformed_lengths_versions_trailing_data_and_digest_changes() {
    let h = Harness::new();
    let request = h.request();
    let definition = h.definition(&request);
    let bytes = h
        .certify(&request, &definition)
        .certificate()
        .canonical_bytes()
        .unwrap();
    for end in (0..bytes.len())
        .step_by((bytes.len() / 64).max(1))
        .chain([bytes.len() - 1, bytes.len() - 32])
    {
        assert!(
            CashFlowCertificate::decode(&bytes[..end]).is_err(),
            "prefix {end}"
        );
    }
    let mut bad = bytes.clone();
    bad[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(CashFlowCertificate::decode(&bad).is_err());
    let mut bad = bytes.clone();
    bad[4] ^= 1;
    assert!(CashFlowCertificate::decode(&bad).is_err());
    let mut bad = bytes.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(CashFlowCertificate::decode(&bad).is_err());
    let mut bad = bytes;
    bad.push(0);
    assert!(CashFlowCertificate::decode(&bad).is_err());
}

#[test]
fn recipient_cash_workpaper_preserves_exact_rows_and_omits_whole_book_evidence() {
    let mut h = Harness::new();
    let large = (1i128 << 100) + 17;
    h.post(1, b"opening", h.usd, 100);
    h.post(10, b"inflow", h.usd, large);
    h.post(20, b"outflow", h.jpy, -7);
    let request = h.request();
    let mut definition = h.definition(&request);
    definition.name = "Cash policy € \"quoted\"\nline\0".into();
    let certified = h.certify(&request, &definition);
    let before = h.head();
    let text = h
        .book
        .cash_flow_jsonl(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            certified.certificate(),
            &request,
            &definition,
        )
        .unwrap()
        .unwrap();
    assert!(text.contains("\"format\":\"fa:cash-flow-workpaper:v1\""));
    assert!(text.contains("\"definition\":\"Cash policy € \\\"quoted\\\"\\nline\\u0000\""));
    assert!(text.contains("\"label\":\"January cash €\\nworkpaper\""));
    assert!(text.contains(&format!("\"inflows\":\"{large}\"")));
    assert!(text.contains("\"closing\":\"-7\""));
    assert!(text.contains("\"code\":\"USD\",\"scale\":\"2\""));
    assert!(text.contains("\"code\":\"JPY\",\"scale\":\"0\""));
    for (event, count) in [
        ("cash_flow_account", 2),
        ("cash_flow_unit", 2),
        ("cash_flow_section", 8),
        ("cash_flow_total", 2),
        ("cash_flow_account_balance", 4),
        ("cash_flow_leg", 2),
        ("cash_flow_result", 1),
    ] {
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with(&format!("{{\"event\":\"{event}\",")))
                .count(),
            count
        );
    }
    for assignment in &definition.assignments {
        let digest: String = assignment
            .entry_digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert!(text.contains(&digest));
    }
    assert!(!text.contains(&format!("{:032x}", h.id("3000").0)));
    assert!(!text.contains("Confidential underlying cash evidence"));
    assert!(!text.contains("Private cash posting narrative"));
    assert!(text.contains("\"full_native_evidence_disclosed\":false"));
    assert!(text.contains("\"classification_judgment_verified\":false"));
    assert!(text.contains("\"outsider_completeness_proof\":false"));
    assert!(text.contains("\"native_history_replayed\":true"));
    assert!(text.ends_with("}\n"));
    assert_eq!(h.head(), before);
}

#[test]
fn recipient_workpaper_replays_byte_identically_after_backdating_and_cannot_export_without_produce()
{
    let mut h = Harness::new();
    h.post(10, b"original", h.usd, 30);
    let request = h.request();
    let definition = h.definition(&request);
    let certified = h.certify(&request, &definition);
    let before = h
        .book
        .cash_flow_jsonl(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            certified.certificate(),
            &request,
            &definition,
        )
        .unwrap()
        .unwrap();
    h.post(12, b"backdated", h.usd, -8);
    let after = h
        .book
        .cash_flow_jsonl(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            certified.certificate(),
            &request,
            &definition,
        )
        .unwrap()
        .unwrap();
    assert_eq!(after, before);
    for capability in [cap(&["read"]), cap(&["produce"]), cap(&["post"])] {
        assert!(
            h.book
                .cash_flow_jsonl(
                    &h.cx(),
                    PRINCIPAL,
                    &capability,
                    certified.certificate(),
                    &request,
                    &definition
                )
                .unwrap()
                .is_err()
        );
    }
    assert!(
        h.book
            .cash_flow_jsonl(
                &h.cx(),
                VId(99),
                &cap(&["read", "produce"]),
                certified.certificate(),
                &request,
                &definition
            )
            .unwrap()
            .is_err()
    );
}

#[test]
fn cash_workpaper_never_returns_a_prefix_for_a_self_consistent_forged_certificate() {
    let mut h = Harness::new();
    h.post(10, b"original", h.usd, 30);
    let request = h.request();
    let definition = h.definition(&request);
    let certified = h.certify(&request, &definition);
    let mut bytes = certified.certificate().canonical_bytes().unwrap();
    let end = bytes.len() - 32;
    bytes[end - 16] ^= 1;
    let digest = fa_model::domain_digest(b"fa:cash-flow-certificate-digest:v1", &[&bytes[..end]]);
    bytes[end..].copy_from_slice(&digest);
    let forged = CashFlowCertificate::decode(&bytes).unwrap();
    let result = h
        .book
        .cash_flow_jsonl(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &forged,
            &request,
            &definition,
        )
        .unwrap();
    assert_eq!(result.unwrap_err().exit, 8);
}
