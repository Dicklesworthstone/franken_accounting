//! Genuine native genesis fixtures distinguish an older supported symbol
//! table from a newer book whose mutable mirror impersonates that table.

use std::path::Path;

use asupersync::fs::{UnixVfs, Vfs};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::blob::DurableDirectory;
use fa_journal::policy::{
    ActivationRequest, ApprovalRequest, activate_policy, activation_proposal, record_approval,
};
use fa_journal::rows::{book_root, bytes, prop, scalar_bytes};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, UnitPolicy};
use fa_model::symbols::{SYMBOLS_DIGEST_DOMAIN, label, property, relation};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, Id128, LegPayload, Oid, SymbolTable,
    account_vid,
};
use fa_money::{Amount, Side, UnitRegistry};
use fa_policy::Capability;
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::{Database, MemVfs, ReadError, WriteBatch};
use fgdb_crypto::Hasher;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::{AsyncBook, BookError, BookKeys, CertifiedReport, Entropy, ReportOutput};

const BOOK: Id128 = Id128([0xd4; 16]);
const PRINCIPAL: VId = VId(54);
const PERIOD: &str = "FY2026-P01";
const SEED: u8 = 212;

fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

fn day() -> DateDay {
    DateDay::from_ymd(2026, 1, 15).unwrap()
}

fn spec() -> BookSpec {
    BookSpec {
        book_id: BOOK,
        name: "Retained symbol compatibility".into(),
        base_unit: UnitRegistry::embedded().unwrap().lookup("USD").unwrap(),
        calendar: FiscalCalendar::monthly("symbol-context", 1, 1).unwrap(),
        time_zone_policy: None,
        entities: Vec::new(),
        opening_date: None,
    }
}

fn registry_digest(registry: &fa_registry::Symbols) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(SYMBOLS_DIGEST_DOMAIN);
    h.update(&registry.canonical_bytes());
    h.finalize().0
}

fn prefix_digest(ceiling: u64) -> [u8; 32] {
    let mut registry = fa_registry::Symbols::embedded().unwrap();
    registry.labels.retain(|_, id| *id <= ceiling);
    registry_digest(&registry)
}

/// Create a separate persisted database whose first native transaction has
/// the historical digest. All other genesis bytes come from the real native
/// constructor. This never rewrites a newer Book to manufacture old ancestry.
fn born_with<V: Vfs + Clone>(
    runtime: &Runtime,
    cx: &PurposeContexts,
    vfs: V,
    directory: &Path,
    symbols_digest: [u8; 32],
) -> AsyncBook<V> {
    let template = runtime
        .block_on(AsyncBook::create_with_vfs(
            cx,
            vfs.clone(),
            &directory.with_extension("template"),
            BookKeys::for_development(SEED),
            spec(),
            Entropy::deterministic(u64::from(SEED)),
        ))
        .unwrap();
    let at = template.head(cx).unwrap();
    let mut rows = template.db.vertices_at(at).unwrap();
    rows.sort_by_key(|row| row.birth_ordinal);
    let edges = template.db.edges_at(at).unwrap();
    assert!(rows.iter().all(|row| {
        row.labels.as_slice() == [label::BOOK] || row.labels.as_slice() == [label::UNIT]
    }));
    let mut genesis = WriteBatch::new(relation::IN_BOOK);
    for mut row in rows {
        if row.vid == book_root() {
            let (_, value) = row
                .props
                .iter_mut()
                .find(|(key, _)| *key == property::SYMBOLS_DIGEST)
                .unwrap();
            *value = scalar_bytes("original symbols", symbols_digest.to_vec()).unwrap();
        }
        genesis.create_vertex(row.vid, row.labels, row.props);
    }
    for edge in edges {
        assert_eq!(edge.entry.relation, relation::IN_BOOK);
        genesis.add_edge(edge.entry.eid, edge.entry.src, edge.entry.dst, edge.props);
    }
    let commit = cx.commit();
    let durable_directory = runtime
        .block_on(DurableDirectory::create(&commit, vfs.clone(), directory))
        .unwrap();
    runtime
        .block_on(durable_directory.child(&commit, "blobs"))
        .unwrap();
    let mut db = runtime
        .block_on(Database::create_with_vfs(
            &commit,
            vfs.clone(),
            durable_directory.path().join("store"),
            BookKeys::for_development(SEED).inner,
        ))
        .unwrap();
    let born = runtime.block_on(db.write(&commit, genesis)).unwrap();
    assert_eq!(born, CommitSeq(1));
    let native = db.vertex_at(book_root(), born).unwrap().unwrap();
    assert_eq!(
        bytes(&native, property::SYMBOLS_DIGEST, "birth digest").unwrap(),
        symbols_digest,
    );
    drop(db);
    drop(template);
    // The facade takes the caller's namespace path, not MemVfs's resolved
    // private host path used by the native database and its writer lease.
    runtime
        .block_on(AsyncBook::open_with_vfs(
            cx,
            vfs,
            directory,
            BookKeys::for_development(SEED),
            Entropy::deterministic(u64::from(SEED) + 1),
        ))
        .unwrap()
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    book: AsyncBook<MemVfs>,
}

impl Harness {
    fn new(digest: [u8; 32]) -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let book = born_with(&runtime, &cx, vfs, Path::new("symbol-book"), digest);
        Self {
            runtime,
            root,
            book,
        }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn head(&self) -> CommitSeq {
        self.book.head(&self.cx()).unwrap()
    }

    fn certificate(&mut self, at: Option<CommitSeq>) -> Result<CertifiedReport, BookError> {
        let cx = self.cx();
        // Reopening leaves retained native history outside the read window.
        // Use the same admitted preparation seam as a production report host.
        self.runtime
            .block_on(
                self.book
                    .prepare_report_history(&cx, PRINCIPAL, &cap(&["read"]), at),
            )?
            .unwrap();
        self.book
            .certify_report(&cx, super::TrialBalanceSelection::AsOf(day()).into(), at)
            .map(|result| result.unwrap())
    }

    fn populate(&mut self) {
        let cx = self.cx();
        populate(&self.runtime, &cx, &mut self.book);
    }

    fn change_digest(&mut self, value: CanonicalScalar) {
        let mut batch = WriteBatch::new(relation::IN_BOOK);
        batch.set_vertex_property(book_root(), property::SYMBOLS_DIGEST, Some(value));
        let cx = self.cx();
        self.runtime
            .block_on(self.book.db.write(&cx.commit(), batch))
            .unwrap();
    }
}

fn populate<V: Vfs + Clone>(runtime: &Runtime, cx: &PurposeContexts, book: &mut AsyncBook<V>) {
    let accounts: Vec<_> = [
        ("1000", AccountType::ASSET, 0),
        ("4000", AccountType::REVENUE, 1),
    ]
    .into_iter()
    .map(|(code, kind, normal_balance)| AccountSpec {
        code: code.into(),
        name: code.into(),
        account_type: kind.0,
        normal_balance,
        is_leaf: true,
        unit_policy: UnitPolicy::AnyCurrency,
        parent_code: None,
        limit: None,
    })
    .collect();
    runtime
        .block_on(book.install_chart(
            cx,
            &accounts,
            PRINCIPAL,
            day(),
            b"symbol-chart",
            &cap(&["schema_change"]),
        ))
        .unwrap()
        .unwrap();
    runtime
        .block_on(book.create_periods(cx, 2026, PRINCIPAL, &cap(&["schema_change"])))
        .unwrap()
        .unwrap();
    runtime
        .block_on(book.transition_period(
            cx,
            PERIOD,
            PeriodTransition::Open,
            PRINCIPAL,
            1,
            day(),
            b"symbol-open",
            &cap(&["close"]),
        ))
        .unwrap()
        .unwrap();
    let source = Document {
        book_id: BOOK,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: b"Original source for the symbol-upgrade report".to_vec(),
    };
    runtime
        .block_on(book.add_document(cx, &source))
        .unwrap()
        .unwrap();
    let usd = book.context().units.lookup("USD").unwrap();
    let legs = vec![
        LegPayload::simple(
            Side::Debit,
            account_vid(BOOK, "1000"),
            Amount::new(usd, 12_550),
        ),
        LegPayload::simple(
            Side::Credit,
            account_vid(BOOK, "4000"),
            Amount::new(usd, 12_550),
        ),
    ];
    let proposal = EntryPayload {
        schema_minor: 0,
        book_id: BOOK,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: day(),
        document_date: None,
        description: book
            .seal_text(cx, "Revenue with a retained source")
            .unwrap(),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: b"symbol-post".to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([0xd5; 32]),
            intent_kind: 1,
        },
        principal_ref: PRINCIPAL,
        session_ref: None,
        evidence: vec![source.evidence_ref(1)],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    runtime
        .block_on(book.post(
            cx,
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

#[test]
fn native_label_prefix_birth_can_issue_new_certificates_without_weakening_old_closures() {
    for ceiling in [43, 44, 46] {
        let mut h = Harness::new(prefix_digest(ceiling));
        h.populate();
        let head = h.head();
        let certified = h.certificate(None).unwrap();
        let ReportOutput::TrialBalance(report) = &certified.report else {
            panic!("trial balance selection returned another report");
        };
        assert_eq!(report.rows.len(), 2);
        assert_eq!(
            report
                .rows
                .iter()
                .find(|row| row.code == "1000")
                .unwrap()
                .debits,
            12_550
        );
        assert_eq!(
            h.book
                .replay_report(&h.cx(), &certified.certificate)
                .unwrap()
                .unwrap(),
            certified.report,
        );
        let older_closure = certified.certificate.resealed_under([0x35; 32]);
        let refusal = h
            .book
            .replay_report(&h.cx(), &older_closure)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, super::code::CERTIFICATE_REGISTRY_UNAVAILABLE);
        assert_eq!(refusal.exit, fa_journal::exit::ENVIRONMENT);
        assert_eq!(h.head(), head);
    }
}

#[test]
fn a_current_book_cannot_impersonate_an_older_symbol_birth() {
    let mut h = Harness::new(SymbolTable::compiled().digest().0);
    h.populate();
    let before = h.head();
    let original = h.certificate(Some(before)).unwrap();
    h.change_digest(scalar_bytes("forged prefix", prefix_digest(43).to_vec()).unwrap());
    let damaged = h.head();
    assert!(
        h.certificate(None)
            .unwrap_err()
            .to_string()
            .contains("context differs")
    );
    assert_eq!(h.certificate(Some(before)).unwrap().report, original.report);
    assert_eq!(h.head(), damaged);
}

#[test]
fn an_older_book_needs_literal_unchanged_label_property_and_relation_bindings() {
    let current = fa_registry::Symbols::embedded().unwrap();
    let mut gap_filled = current.clone();
    gap_filled.labels.insert("UnknownLegacyLabel".into(), 32);
    let mut non_prefix = current.clone();
    non_prefix.labels.remove("UsageCell");
    let mut property_changed = current.clone();
    property_changed.properties.insert("amount".into(), 69);
    let mut relation_changed = current;
    relation_changed.relations.insert("POSTS_TO".into(), 38);
    for digest in [
        [0xa7; 32],
        registry_digest(&gap_filled),
        registry_digest(&non_prefix),
        registry_digest(&property_changed),
        registry_digest(&relation_changed),
    ] {
        let mut h = Harness::new(digest);
        let before = h.head();
        assert!(
            h.certificate(None)
                .unwrap_err()
                .to_string()
                .contains("context differs")
        );
        assert_eq!(h.head(), before);
    }
}

#[test]
fn legal_tick_and_policy_updates_do_not_rewrite_the_original_symbol_evidence() {
    let mut h = Harness::new(prefix_digest(43));
    h.populate();
    let original_at = h.head();
    let original = h.certificate(Some(original_at)).unwrap();
    let cx = h.cx();
    h.runtime
        .block_on(
            h.book
                .record_tick(&cx, 1_768_435_200_000_000_000, true, &cap(&["witness"])),
        )
        .unwrap()
        .unwrap();
    let context = h.book.context().clone();
    let proposal = activation_proposal(
        &context,
        PRINCIPAL,
        fa_journal::policy::steward().unwrap().policy_oid,
        day(),
        b"symbol-policy",
        h.book
            .seal_text(&cx, "Activate the retained security policy")
            .unwrap(),
    );
    let digest = proposal.proposal_digest().unwrap();
    let mut approvals = Vec::new();
    for reviewer in [VId(55), VId(56)] {
        let approved = h
            .runtime
            .block_on(record_approval(
                &mut h.book.db,
                &cx,
                &context,
                ApprovalRequest {
                    capability: Capability::embedded(reviewer, &["approve"]).unwrap(),
                    approved_proposal_digest: digest,
                    role: 0,
                },
            ))
            .unwrap()
            .unwrap();
        approvals.push(approved.approval());
    }
    h.runtime
        .block_on(activate_policy(
            &mut h.book.db,
            &cx,
            &context,
            ActivationRequest {
                proposal,
                capability: cap(&["post", "rule_change"]),
                approvals,
            },
        ))
        .unwrap()
        .unwrap();
    let selected = h.book.db.vertex_at(book_root(), h.head()).unwrap().unwrap();
    assert!(selected.created_at > CommitSeq(1));
    assert!(prop(&selected, property::LATEST_TICK).is_some());
    assert_eq!(
        prop(&selected, property::SECURITY_POLICY_EPOCH),
        Some(&CanonicalScalar::Int(1))
    );
    h.certificate(None).unwrap();
    assert_eq!(
        h.book
            .replay_report(&cx, &original.certificate)
            .unwrap()
            .unwrap(),
        original.report
    );

    h.change_digest(CanonicalScalar::Int(0));
    let head = h.head();
    h.runtime
        .block_on(
            h.book
                .prepare_report_history(&cx, PRINCIPAL, &cap(&["read"]), Some(original_at)),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        h.certificate(Some(original_at)).unwrap().report,
        original.report
    );
    assert!(h.certificate(None).is_err());
    assert_eq!(h.head(), head);
}

#[test]
fn checkpointed_prefix_books_load_genesis_only_after_current_whole_book_admission() {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    for (original_digest, forge_current) in [
        (prefix_digest(43), false),
        (SymbolTable::compiled().digest().0, false),
        (prefix_digest(43), true),
    ] {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let directory = std::env::temp_dir().join(format!(
            "fa-symbol-history-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        let mut book = born_with(&runtime, &cx, UnixVfs, &directory, original_digest);
        populate(&runtime, &cx, &mut book);
        let original_at = book.head(&cx).unwrap();
        if forge_current {
            let mut change = WriteBatch::new(relation::IN_BOOK);
            change.set_vertex_property(
                book_root(),
                property::SYMBOLS_DIGEST,
                Some(
                    scalar_bytes(
                        "forged current symbols",
                        SymbolTable::compiled().digest().0.to_vec(),
                    )
                    .unwrap(),
                ),
            );
            runtime
                .block_on(book.db.write(&cx.commit(), change))
                .unwrap();
        }
        let selected = forge_current.then_some(original_at);
        let at = book.head(&cx).unwrap();
        runtime.block_on(book.db.compact(&cx.commit())).unwrap();
        drop(book);
        let mut book = runtime
            .block_on(AsyncBook::open_with_vfs(
                &cx,
                UnixVfs,
                &directory,
                BookKeys::for_development(SEED),
                Entropy::deterministic(u64::from(SEED) + 2),
            ))
            .unwrap();
        let storage_root = book.db.partition_root().unwrap();
        assert!(matches!(
            book.db.delta_since(CommitSeq(0)),
            Err(ReadError::DeltaCursorRetired { .. })
        ));
        for denied in [
            cap(&[]),
            cap(&["verify"]),
            Capability::embedded(VId(55), &["read"]).unwrap(),
            cap(&["read"]).for_books(&[Id128([0xff; 16])]).unwrap(),
            cap(&["read"]).for_accounts(&["1000"]).unwrap(),
            cap(&["read"]).for_periods(&[PERIOD]).unwrap(),
            cap(&["read"]).expiring_at(at),
        ] {
            let refusal = runtime
                .block_on(book.prepare_report_history(&cx, PRINCIPAL, &denied, selected))
                .unwrap()
                .unwrap_err();
            assert_eq!(refusal.exit, fa_journal::exit::SAFETY);
            assert!(matches!(
                book.db.delta_since(CommitSeq(0)),
                Err(ReadError::DeltaCursorRetired { .. })
            ));
            assert_eq!(book.db.partition_root().unwrap(), storage_root);
        }
        runtime
            .block_on(book.prepare_report_history(&cx, PRINCIPAL, &cap(&["read"]), selected))
            .unwrap()
            .unwrap();
        if original_digest == SymbolTable::compiled().digest().0 && selected.is_none() {
            assert!(
                matches!(
                    book.db.delta_since(CommitSeq(0)),
                    Err(ReadError::DeltaCursorRetired { .. })
                ),
                "current compiled HEAD preparation must remain a no-op"
            );
        } else {
            assert!(book.db.delta_since(CommitSeq(0)).is_ok());
        }
        let certified = book
            .certify_report(
                &cx,
                super::TrialBalanceSelection::AsOf(day()).into(),
                selected,
            )
            .unwrap()
            .unwrap();
        assert_eq!(certified.certificate.known_at, selected.unwrap_or(at));
        assert_eq!(
            book.replay_report(&cx, &certified.certificate)
                .unwrap()
                .unwrap(),
            certified.report
        );
        assert_eq!(book.head(&cx).unwrap(), at);
        assert_eq!(book.db.partition_root().unwrap(), storage_root);
    }
}
