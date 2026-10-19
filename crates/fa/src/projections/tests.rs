//! Real kernel postings and substrate mutations; no mocked repair or balances.

use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, UnitPolicy};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, EntryRef, EvidenceRef, LegPayload, Oid,
    Pending, Settlement, Supersession, SupersessionKind, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;

use super::*;
use crate::{BookKeys, Entropy, Profile};

const PRINCIPAL: VId = VId(1);
fn day() -> DateDay {
    DateDay::from_ymd(2026, 1, 10).unwrap()
}
fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}
fn repair_cap() -> Capability {
    cap(&["read", "verify", "schema_change"])
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    book: AsyncBook<MemVfs>,
    usd: UnitId,
    evidence: Vec<EvidenceRef>,
}

impl Harness {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
        let book_id = Id128([131; 16]);
        let spec = BookSpec {
            book_id,
            name: "Projection recovery".into(),
            base_unit: usd,
            calendar: FiscalCalendar::monthly("recovery", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs,
                Path::new("projection-recovery-book"),
                BookKeys::for_development(131),
                spec,
                Entropy::deterministic(131),
            ))
            .unwrap();
        let accounts: Vec<_> = [("1000", AccountType::ASSET), ("3000", AccountType::EQUITY)]
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
            .block_on(book.install_chart(
                &cx,
                &accounts,
                PRINCIPAL,
                day(),
                b"chart",
                &fa_journal::Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        runtime
            .block_on(book.create_periods(
                &cx,
                2026,
                fgdb_types::VId(1),
                &fa_journal::Capability::embedded(fgdb_types::VId(1), &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        runtime
            .block_on(book.transition_period(
                &cx,
                "FY2026-P01",
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                day(),
                b"open",
                &cap(&["close"]),
            ))
            .unwrap()
            .unwrap();
        let document = Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"PRIVATE_PROJECTION_RECOVERY_EVIDENCE".to_vec(),
        };
        runtime
            .block_on(book.add_document(&cx, &document))
            .unwrap()
            .unwrap();
        Self {
            runtime,
            root,
            book,
            usd,
            evidence: vec![document.evidence_ref(1)],
        }
    }
    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }
    fn head(&self) -> CommitSeq {
        self.book.head(&self.cx()).unwrap()
    }
    fn id(&self, code: &str) -> VId {
        account_vid(self.book.context().book_id, code)
    }
    fn proposal(&self, key: &[u8], amount: i128, target: Option<EntryRef>) -> EntryPayload {
        let (debit, credit) = if target.is_some() {
            ("3000", "1000")
        } else {
            ("1000", "3000")
        };
        let mut legs = vec![
            LegPayload::simple(Side::Debit, self.id(debit), Amount::new(self.usd, amount)),
            LegPayload::simple(Side::Credit, self.id(credit), Amount::new(self.usd, amount)),
        ];
        if let Some(target) = target {
            legs[1].settles.push(Settlement {
                target,
                ordinal: 0,
                amount: Amount::new(self.usd, amount),
            });
        }
        EntryPayload {
            schema_minor: 0,
            book_id: self.book.context().book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day(),
            document_date: None,
            description: self
                .book
                .seal_text(&self.cx(), "PRIVATE_RECOVERY_ENTRY_DESCRIPTION")
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
        }
    }
    fn try_post(&mut self, proposal: EntryPayload) -> Outcome<fa_journal::Posted> {
        let cx = self.cx();
        self.runtime.block_on(self.book.post(
            &cx,
            PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(&["post", "reconcile"]),
            },
        ))
    }
    fn post(&mut self, key: &[u8], amount: i128, target: Option<EntryRef>) -> EntryRef {
        let proposal = self.proposal(key, amount, target);
        self.try_post(proposal).unwrap().unwrap().entry_ref()
    }
    fn reverse(&mut self, target: EntryRef) -> EntryRef {
        let row = self.book.db.vertex(target.vid).unwrap().unwrap();
        let mut proposal = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "entry").unwrap())
            .unwrap()
            .proposal;
        proposal.class = EntryClass::REVERSAL;
        proposal.idempotency_key = b"reverse-payment".to_vec();
        proposal.description = self.book.seal_text(&self.cx(), "reverse payment").unwrap();
        proposal.supersession = vec![Supersession {
            target,
            kind: SupersessionKind::Reverses,
            reason_code: 1,
        }];
        for leg in &mut proposal.legs {
            leg.side = match leg.side {
                Side::Debit => Side::Credit,
                Side::Credit => Side::Debit,
            };
            leg.settles.clear();
        }
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        self.try_post(proposal).unwrap().unwrap().entry_ref()
    }
    fn mutate(&mut self, batch: WriteBatch) {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.db.write(&cx.commit(), batch))
            .unwrap();
    }
    fn damage_applied(&mut self, target: EntryRef, value: i128) {
        let mut batch = WriteBatch::new(relation::HAS_LEG);
        batch.set_vertex_property(
            leg_vid(target.vid, 0),
            property::APPLIED,
            Some(mantissa_scalar("applied", value).unwrap()),
        );
        self.mutate(batch);
    }
    fn rebuild(&mut self) -> ProjectionRebuild {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.rebuild_projections(&cx, PRINCIPAL, &repair_cap()))
            .unwrap()
            .unwrap()
    }
    fn source_entries(&self) -> Vec<(VId, Vec<u8>, CommitSeq)> {
        self.book
            .db
            .vertices_at(self.head())
            .unwrap()
            .into_iter()
            .filter(|row| row.labels.contains(&label::ENTRY))
            .map(|row| {
                (
                    row.vid,
                    bytes(&row, property::FA_PAYLOAD, "entry").unwrap(),
                    row.created_at,
                )
            })
            .collect()
    }
    fn assert_green(&self) {
        assert!(
            self.book
                .verify_projections(&self.cx(), None)
                .unwrap()
                .is_green()
        );
        assert!(self.book.verify_open_items(&self.cx()).unwrap().is_green());
    }
}

#[test]
fn repairs_mirrors_exactly_in_one_commit_preserving_history_payloads_and_noop_retry() {
    let mut h = Harness::new();
    let invoice = h.post(b"invoice", 100, None);
    h.post(b"payment", 40, Some(invoice));
    let large = h.post(b"wide", (1i128 << 100) + 17, None);
    let clean = h.head();
    let journal = h.source_entries();
    let ordinary_leg = leg_vid(invoice.vid, 0);
    let wide_leg = leg_vid(large.vid, 0);
    let mut bad = WriteBatch::new(relation::HAS_LEG);
    bad.set_vertex_property(
        ordinary_leg,
        property::AMOUNT_BYTES,
        Some(mantissa_scalar("wrong", 999).unwrap()),
    );
    bad.set_vertex_property(ordinary_leg, property::SIDE, Some(CanonicalScalar::Int(1)));
    bad.set_vertex_property(
        ordinary_leg,
        property::APPLIED,
        Some(mantissa_scalar("wrong", 0).unwrap()),
    );
    bad.set_vertex_property(wide_leg, property::AMOUNT_BYTES, None);
    bad.set_vertex_property(wide_leg, property::UNIT_ID, Some(CanonicalScalar::Int(999)));
    bad.set_vertex_label(wide_leg, label::LEG, false);
    h.mutate(bad);
    let damaged = h.head();
    assert!(!h.book.verify_projections(&h.cx(), None).unwrap().is_green());
    let prepared = h
        .book
        .prepare_projection_rebuild(&h.cx(), PRINCIPAL, &repair_cap())
        .unwrap()
        .unwrap();
    assert_eq!(h.head(), damaged);
    assert_eq!(prepared.preview().legs_repaired, 2);
    assert_eq!(prepared.preview().legs_checked, 6);
    assert!(!format!("{prepared:?}").contains("PRIVATE_RECOVERY"));
    let cx = h.cx();
    let repair = h
        .runtime
        .block_on(
            h.book
                .publish_projection_rebuild(&cx, PRINCIPAL, &repair_cap(), prepared),
        )
        .unwrap()
        .unwrap();
    assert!(repair.wrote);
    assert_eq!(repair.published_at, CommitSeq(damaged.0 + 1));
    assert_eq!(h.source_entries(), journal);
    h.assert_green();
    assert!(
        h.book
            .verify_projections(&h.cx(), Some(clean))
            .unwrap()
            .is_green()
    );
    assert!(
        !h.book
            .verify_projections(&h.cx(), Some(damaged))
            .unwrap()
            .is_green()
    );
    let again = h.rebuild();
    assert!(!again.wrote);
    assert_eq!(again.published_at, repair.published_at);
    assert_eq!(again.legs_repaired, 0);
    assert_eq!(again.edges_repaired, 0);
}

#[test]
fn recovered_applied_counter_prevents_double_settlement_and_allows_exact_remaining_payment() {
    let mut h = Harness::new();
    let invoice = h.post(b"invoice", 100, None);
    h.post(b"first-payment", 40, Some(invoice));
    h.damage_applied(invoice, 0);
    assert!(!h.book.verify_open_items(&h.cx()).unwrap().is_green());
    h.rebuild();
    let before = h.head();
    let over = h.proposal(b"over-apply", 70, Some(invoice));
    assert!(h.try_post(over).unwrap().is_err());
    assert_eq!(h.head(), before);
    h.post(b"remaining", 60, Some(invoice));
    let items = h.book.open_items(&h.cx(), None, None).unwrap();
    let item = items
        .iter()
        .find(|item| item.entry == invoice.vid && item.ordinal == 0)
        .unwrap();
    assert_eq!((item.applied, item.open), (100, 0));
    h.assert_green();
}

#[test]
fn repair_uses_reversal_liveness_instead_of_reapplying_undone_settlements() {
    let mut h = Harness::new();
    let invoice = h.post(b"invoice", 100, None);
    let payment = h.post(b"payment", 40, Some(invoice));
    h.reverse(payment);
    h.damage_applied(invoice, 40);
    let journal = h.source_entries();
    h.rebuild();
    assert_eq!(h.source_entries(), journal);
    let items = h.book.open_items(&h.cx(), None, None).unwrap();
    let invoice = items
        .iter()
        .find(|item| item.entry == invoice.vid && item.ordinal == 0)
        .unwrap();
    assert_eq!((invoice.applied, invoice.open), (0, 100));
    assert_eq!(invoice.applications.len(), 1);
    assert!(!invoice.applications[0].live);
    h.assert_green();
}

#[test]
fn pending_legs_are_repaired_without_becoming_posted_open_items() {
    let mut h = Harness::new();
    let mut proposal = h.proposal(b"hold", 100, None);
    proposal.class = EntryClass::PENDING;
    proposal.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    let pending = h.try_post(proposal).unwrap().unwrap().entry_ref();
    h.damage_applied(pending, 90);
    h.rebuild();
    assert!(
        !h.book
            .open_items(&h.cx(), None, None)
            .unwrap()
            .iter()
            .any(|item| item.entry == pending.vid)
    );
    let row = h.book.db.vertex(leg_vid(pending.vid, 0)).unwrap().unwrap();
    assert_eq!(
        prop(&row, property::APPLIED),
        Some(&mantissa_scalar("applied", 0).unwrap())
    );
    h.assert_green();
}

#[test]
fn fills_never_created_legacy_legs_and_edges_from_real_payloads_not_synthetic_zero_counters() {
    let mut source = Harness::new();
    let invoice = source.post(b"invoice", 100, None);
    let payment = source.post(b"payment", 40, Some(invoice));
    let mut h = Harness::new();
    // Model an old publisher which committed the same real Entry payloads
    // without leg projections. Never delete spent identities to simulate this.
    let mut legacy = WriteBatch::new(relation::HAS_LEG);
    for reference in [invoice, payment] {
        let row = source.book.db.vertex(reference.vid).unwrap().unwrap();
        legacy.create_vertex(row.vid, row.labels, row.props);
    }
    h.mutate(legacy);
    let journal = h.source_entries();
    let basis = h.head();
    let repair = h.rebuild();
    assert_eq!(repair.legs_created, 4);
    assert_eq!(repair.edges_created, 12);
    assert_eq!(repair.published_at, CommitSeq(basis.0 + 1));
    assert_eq!(h.source_entries(), journal);
    let row = h.book.db.vertex(leg_vid(invoice.vid, 0)).unwrap().unwrap();
    assert_eq!(
        prop(&row, property::APPLIED),
        Some(&mantissa_scalar("applied", 40).unwrap())
    );
    h.assert_green();
}

#[test]
fn edge_property_drift_and_owned_extras_repair_without_touching_settlement_edges() {
    let mut h = Harness::new();
    let invoice = h.post(b"invoice", 100, None);
    h.post(b"payment", 40, Some(invoice));
    let before_settlements: Vec<_> = h
        .book
        .db
        .edges_at(h.head())
        .unwrap()
        .into_iter()
        .filter(|edge| edge.entry.relation == relation::SETTLES)
        .collect();
    assert!(!before_settlements.is_empty());
    let leg = leg_vid(invoice.vid, 0);
    let eid = edge_id(relation::HAS_LEG, invoice.vid, leg);
    let mut bad = WriteBatch::new(relation::HAS_LEG);
    bad.set_edge_property(eid, property::ORDINAL, Some(CanonicalScalar::Int(99)));
    bad.set_edge_property(eid, property::AMOUNT, Some(CanonicalScalar::Int(7)));
    // A noncanonical but journal-owned duplicate projection may be retired.
    bad.add_edge(EId(1), invoice.vid, leg, Vec::new());
    h.mutate(bad);
    let report = h.rebuild();
    assert_eq!((report.edges_repaired, report.edges_retired), (1, 1));
    let after: Vec<_> = h
        .book
        .db
        .edges_at(h.head())
        .unwrap()
        .into_iter()
        .filter(|edge| edge.entry.relation == relation::SETTLES)
        .collect();
    assert_eq!(after, before_settlements);
    h.assert_green();
}

#[test]
fn spent_identity_failure_cannot_publish_earlier_mirror_repairs() {
    let mut h = Harness::new();
    let invoice = h.post(b"invoice", 100, None);
    let leg = leg_vid(invoice.vid, 0);
    let mut bad = WriteBatch::new(relation::HAS_LEG);
    bad.set_vertex_property(leg, property::SIDE, Some(CanonicalScalar::Int(1)));
    bad.delete_edge(edge_id(relation::HAS_LEG, invoice.vid, leg));
    h.mutate(bad);
    let basis = h.head();
    let row = h.book.db.vertex(leg).unwrap().unwrap();
    let cx = h.cx();
    assert!(
        h.runtime
            .block_on(h.book.rebuild_projections(&cx, PRINCIPAL, &repair_cap()))
            .is_err()
    );
    assert_eq!(h.head(), basis);
    assert_eq!(h.book.db.vertex(leg).unwrap().unwrap(), row);
    assert!(!h.book.verify_projections(&h.cx(), None).unwrap().is_green());
}

#[test]
fn stale_plans_refuse_projection_only_changes_and_cannot_rewind_new_postings() {
    let mut h = Harness::new();
    let invoice = h.post(b"invoice", 100, None);
    for monetary in [false, true] {
        if !monetary {
            h.damage_applied(invoice, 7);
        }
        let prepared = h
            .book
            .prepare_projection_rebuild(&h.cx(), PRINCIPAL, &repair_cap())
            .unwrap()
            .unwrap();
        if monetary {
            h.post(b"new-payment", 40, Some(invoice));
        } else {
            h.damage_applied(invoice, 9);
        }
        let basis = h.head();
        let root = h.book.db.partition_root().unwrap();
        let cx = h.cx();
        let error = h
            .runtime
            .block_on(
                h.book
                    .publish_projection_rebuild(&cx, PRINCIPAL, &repair_cap(), prepared),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            BookError::Registers(fa_registers::RegisterError::StaleFold)
        ));
        assert_eq!(h.head(), basis);
        assert_eq!(h.book.db.partition_root().unwrap(), root);
        h.rebuild();
    }
}

#[test]
fn malformed_sources_authoritative_collisions_and_orphans_refuse_without_partial_write() {
    for attack in 0..4 {
        let mut h = Harness::new();
        let invoice = h.post(b"invoice", 100, None);
        let leg = leg_vid(invoice.vid, 0);
        let mut bad = WriteBatch::new(relation::HAS_LEG);
        bad.set_vertex_property(leg, property::SIDE, Some(CanonicalScalar::Int(1)));
        match attack {
            0 => {
                bad.set_vertex_property(
                    invoice.vid,
                    property::FA_PAYLOAD,
                    Some(mantissa_scalar("invalid entry bytes", 1).unwrap()),
                );
            }
            1 => {
                bad.set_vertex_label(leg, label::DOCUMENT, true);
            }
            2 => {
                bad.create_vertex(VId(13), vec![label::LEG], Vec::new());
            }
            _ => {
                bad.set_vertex_label(invoice.vid, label::ENTRY, false);
            }
        }
        h.mutate(bad);
        let basis = h.head();
        let root = h.book.db.partition_root().unwrap();
        assert!(
            h.book
                .prepare_projection_rebuild(&h.cx(), PRINCIPAL, &repair_cap())
                .is_err()
        );
        assert_eq!(h.head(), basis);
        assert_eq!(h.book.db.partition_root().unwrap(), root);
    }
}

#[test]
fn authority_precedes_corrupt_data_and_is_rechecked_at_publication() {
    let mut h = Harness::new();
    let invoice = h.post(b"invoice", 100, None);
    h.damage_applied(invoice, 7);
    let prepared = h
        .book
        .prepare_projection_rebuild(&h.cx(), PRINCIPAL, &repair_cap())
        .unwrap()
        .unwrap();
    let before = h.head();
    let cx = h.cx();
    assert!(
        h.runtime
            .block_on(h.book.publish_projection_rebuild(
                &cx,
                PRINCIPAL,
                &cap(&["read", "verify"]),
                prepared
            ))
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), before);
    let mut bad = WriteBatch::new(relation::HAS_LEG);
    bad.set_vertex_property(
        invoice.vid,
        property::FA_PAYLOAD,
        Some(mantissa_scalar("invalid entry bytes", 1).unwrap()),
    );
    h.mutate(bad);
    let before = h.head();
    for capability in [
        cap(&[]),
        cap(&["read"]),
        cap(&["read", "verify"]),
        Capability::new(
            PRINCIPAL,
            Profile::Agent,
            &[Op::Read, Op::Verify],
            PRINCIPAL,
        )
        .unwrap(),
        repair_cap().for_books(&[Id128([99; 16])]).unwrap(),
    ] {
        // A lawful authority refusal, NOT the malformed-payload error.
        assert!(
            h.book
                .prepare_projection_rebuild(&h.cx(), PRINCIPAL, &capability)
                .unwrap()
                .is_err()
        );
    }
    assert!(
        h.book
            .prepare_projection_rebuild(&h.cx(), VId(2), &repair_cap())
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), before);
}
