//! Recovery must not make damaged projections agree with rewritten source data.
//! Real kernel posts provide valid inputs; raw writes are explicit fault injection.

use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, UnitPolicy};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, EntryRef, EvidenceRef, LegPayload, Oid,
    account_vid, entry_mirrors,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;

use super::*;
use crate::{BookKeys, Entropy};

const PRINCIPAL: VId = VId(1);
const DIRECTORY: &str = "history-gated-recovery";

fn day() -> DateDay {
    DateDay::from_ymd(2026, 3, 1).unwrap()
}
fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}
fn authority() -> Capability {
    cap(&["read", "verify", "schema_change"])
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    book: AsyncBook<MemVfs>,
    vfs: MemVfs,
    keys: BookKeys,
    usd: UnitId,
    evidence: Vec<EvidenceRef>,
}

impl Harness {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let keys = BookKeys::for_development(177);
        let book_id = Id128([177; 16]);
        let spec = BookSpec {
            book_id,
            name: "History-gated projection recovery".into(),
            base_unit: usd,
            calendar: FiscalCalendar::monthly("history-recovery", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs.clone(),
                Path::new(DIRECTORY),
                keys.clone(),
                spec,
                Entropy::deterministic(177),
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
                b"history-chart",
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
                "FY2026-P03",
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                b"history-open",
                &cap(&["close"]),
            ))
            .unwrap()
            .unwrap();
        let source = Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"source evidence for history-gated recovery".to_vec(),
        };
        runtime
            .block_on(book.add_document(&cx, &source))
            .unwrap()
            .unwrap();
        Self {
            runtime,
            root,
            book,
            vfs,
            keys,
            usd,
            evidence: vec![source.evidence_ref(1)],
        }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }
    fn head(&self) -> CommitSeq {
        self.book.head(&self.cx()).unwrap()
    }
    fn post(&mut self, key: &[u8]) -> EntryRef {
        let cx = self.cx();
        let book = self.book.context().book_id;
        let legs = vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book, "1000"),
                Amount::new(self.usd, 100),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(book, "3000"),
                Amount::new(self.usd, 100),
            ),
        ];
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id: book,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day(),
            document_date: None,
            description: self
                .book
                .seal_text(&cx, "history recovery posting")
                .unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([177; 32]),
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
            .unwrap()
            .entry_ref()
    }
    fn entry(&self, vid: VId) -> Entry {
        let row = self.book.db.vertex(vid).unwrap().unwrap();
        Entry::decode(&bytes(&row, property::FA_PAYLOAD, "fixture source").unwrap()).unwrap()
    }
    fn mutate(&mut self, batch: WriteBatch) {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.db.write(&cx.commit(), batch))
            .unwrap();
    }
    fn rewrite(&mut self, vid: VId, entry: &Entry) {
        let mut batch = WriteBatch::new(relation::HAS_LEG);
        for (key, value) in entry_mirrors(entry).unwrap() {
            batch.set_vertex_property(vid, key, Some(value));
        }
        self.mutate(batch);
    }
    fn reject_recovery(&mut self) {
        let before = self.head();
        let root = self.book.db.partition_root().unwrap();
        let cx = self.cx();
        assert!(matches!(
            self.book
                .prepare_projection_rebuild(&cx, PRINCIPAL, &authority()),
            Err(BookError::Kernel(KernelError::Corrupt(_)))
        ));
        assert!(matches!(
            self.runtime
                .block_on(self.book.prepare_projection_rebuild_with_history(
                    &cx,
                    PRINCIPAL,
                    &authority()
                )),
            Err(BookError::Kernel(KernelError::Corrupt(_)))
        ));
        assert!(matches!(
            self.runtime
                .block_on(self.book.rebuild_projections(&cx, PRINCIPAL, &authority())),
            Err(BookError::Kernel(KernelError::Corrupt(_)))
        ));
        assert_eq!(
            self.head(),
            before,
            "no failed preflight may publish a repair"
        );
        assert_eq!(self.book.db.partition_root().unwrap(), root);
    }
    fn reopen(self) -> Self {
        let Self {
            runtime,
            root,
            book,
            vfs,
            keys,
            usd,
            evidence,
        } = self;
        drop(book);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let book = runtime
            .block_on(AsyncBook::open_with_vfs(
                &cx,
                vfs.clone(),
                Path::new(DIRECTORY),
                keys.clone(),
                Entropy::deterministic(178),
            ))
            .unwrap();
        Self {
            runtime,
            root,
            book,
            vfs,
            keys,
            usd,
            evidence,
        }
    }
}

#[test]
fn self_consistent_monetary_rewrites_cannot_be_laundered_into_rebuilt_legs() {
    let mut h = Harness::new();
    let reference = h.post(b"rewrite-amount");
    let original = h.entry(reference.vid);
    let mut proposal = original.proposal.clone();
    for leg in &mut proposal.legs {
        leg.amount.mantissa = 200;
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    let replacement = proposal.seal(Vec::new(), None).unwrap();
    h.rewrite(reference.vid, &replacement);
    assert_eq!(
        h.entry(reference.vid),
        replacement,
        "the replacement is fully decodable and balanced"
    );
    assert!(!h.book.verify_projections(&h.cx(), None).unwrap().is_green());
    let leg_before = h
        .book
        .db
        .vertex(leg_vid(reference.vid, 0))
        .unwrap()
        .unwrap();
    h.reject_recovery();
    assert_eq!(
        h.book
            .db
            .vertex(leg_vid(reference.vid, 0))
            .unwrap()
            .unwrap(),
        leg_before
    );
}

#[test]
fn an_exact_restoration_is_not_an_integrity_pass_even_when_all_projections_are_green() {
    let mut h = Harness::new();
    let reference = h.post(b"restore");
    let original = h.entry(reference.vid);
    let mut corrupted = WriteBatch::new(relation::HAS_LEG);
    corrupted.set_vertex_property(
        reference.vid,
        property::FA_DIGEST,
        Some(fa_journal::rows::scalar_bytes("wrong digest", vec![0; 32]).unwrap()),
    );
    h.mutate(corrupted);
    h.rewrite(reference.vid, &original);
    assert_eq!(h.entry(reference.vid), original);
    assert!(h.book.verify_projections(&h.cx(), None).unwrap().is_green());
    assert!(h.book.verify_open_items(&h.cx()).unwrap().is_green());
    h.reject_recovery();
}

#[test]
fn a_relabelled_control_entry_cannot_disappear_from_recovery_preflight() {
    let mut h = Harness::new();
    h.post(b"unchanged-money");
    let control = h
        .book
        .db
        .vertices_at(h.head())
        .unwrap()
        .into_iter()
        .find(|row| {
            row.labels.contains(&label::ENTRY) && h.entry(row.vid).proposal.class.is_control()
        })
        .unwrap()
        .vid;
    let mut hidden = WriteBatch::new(relation::HAS_LEG);
    hidden.set_vertex_label(control, label::ENTRY, false);
    hidden.set_vertex_label(control, label::DOCUMENT, true);
    h.mutate(hidden);
    // This control owns no legs: the ordinary live-row projection checker
    // cannot discover it through orphan projections or malformed payloads.
    assert!(h.book.verify_projections(&h.cx(), None).unwrap().is_green());
    h.reject_recovery();
}

#[test]
fn even_a_previewed_clean_plan_cannot_survive_a_later_source_rewrite() {
    let mut h = Harness::new();
    let reference = h.post(b"stale-source");
    let cx = h.cx();
    let prepared = h
        .runtime
        .block_on(
            h.book
                .prepare_projection_rebuild_with_history(&cx, PRINCIPAL, &authority()),
        )
        .unwrap()
        .unwrap();
    assert_eq!(prepared.preview().legs_repaired, 0);
    let mut bad = WriteBatch::new(relation::HAS_LEG);
    bad.set_vertex_property(
        reference.vid,
        property::FA_DIGEST,
        Some(fa_journal::rows::scalar_bytes("bad digest", vec![0; 32]).unwrap()),
    );
    h.mutate(bad);
    let before = h.head();
    let root = h.book.db.partition_root().unwrap();
    assert!(matches!(
        h.runtime.block_on(h.book.publish_projection_rebuild(
            &cx,
            PRINCIPAL,
            &authority(),
            prepared
        )),
        Err(BookError::Registers(fa_registers::RegisterError::StaleFold))
    ));
    assert_eq!(h.head(), before);
    assert_eq!(h.book.db.partition_root().unwrap(), root);
}

#[test]
fn authorized_history_loading_after_reopen_keeps_projection_only_damage_repairable() {
    let mut h = Harness::new();
    let reference = h.post(b"reopened");
    let original = h.entry(reference.vid);
    let mut bad = WriteBatch::new(relation::HAS_LEG);
    bad.set_vertex_property(
        leg_vid(reference.vid, 0),
        property::SIDE,
        Some(CanonicalScalar::Int(1)),
    );
    h.mutate(bad);
    let before = h.head();
    let mut h = h.reopen();
    let cx = h.cx();
    let prepared = h
        .runtime
        .block_on(
            h.book
                .prepare_projection_rebuild_with_history(&cx, PRINCIPAL, &authority()),
        )
        .unwrap()
        .unwrap();
    assert_eq!(prepared.preview().legs_repaired, 1);
    assert_eq!(
        h.head(),
        before,
        "loading retained history does not publish"
    );
    let repaired = h
        .runtime
        .block_on(
            h.book
                .publish_projection_rebuild(&cx, PRINCIPAL, &authority(), prepared),
        )
        .unwrap()
        .unwrap();
    assert!(repaired.wrote);
    assert_eq!(repaired.published_at.0, before.0 + 1);
    assert_eq!(h.entry(reference.vid), original);
    assert!(h.book.verify_projections(&cx, None).unwrap().is_green());
    fa_journal::verify_entry_history(&h.book.db, &cx, h.book.context(), None).unwrap();
    let retry = h
        .runtime
        .block_on(h.book.rebuild_projections(&cx, PRINCIPAL, &authority()))
        .unwrap()
        .unwrap();
    assert!(!retry.wrote);
    assert_eq!(retry.published_at, repaired.published_at);
}

#[test]
fn authority_refuses_before_history_loading_or_corruption_disclosure() {
    let mut h = Harness::new();
    let reference = h.post(b"denied");
    let mut bad = WriteBatch::new(relation::HAS_LEG);
    bad.set_vertex_property(
        reference.vid,
        property::FA_PAYLOAD,
        Some(fa_journal::rows::scalar_bytes("unreadable source", vec![255]).unwrap()),
    );
    h.mutate(bad);
    let before = h.head();
    let cx = h.cx();
    for denied in [
        cap(&[]),
        cap(&["read", "verify"]),
        authority().expiring_at(before),
        authority().for_books(&[Id128([255; 16])]).unwrap(),
    ] {
        let refusal = h
            .runtime
            .block_on(
                h.book
                    .prepare_projection_rebuild_with_history(&cx, PRINCIPAL, &denied),
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, fa_journal::exit::SAFETY);
        let refusal = h
            .runtime
            .block_on(h.book.rebuild_projections(&cx, PRINCIPAL, &denied))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, fa_journal::exit::SAFETY);
    }
    assert_eq!(h.head(), before);
}
