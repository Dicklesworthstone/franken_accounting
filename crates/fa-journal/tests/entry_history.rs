//! Entry-history integrity against real committed native deltas. Chart creation
//! uses the production kernel; later raw writes deliberately inject corruption.

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::entry_history::{EntryHistoryVerification, verify_entry_history};
use fa_journal::rows::{bytes, scalar_bytes};
use fa_journal::{
    AccountSpec, BookContext, BookSpec, KernelError, UnitPolicy, create_book, install_chart,
};
use fa_model::symbols::{label, property, relation};
use fa_model::{Entry, Erasable, Id128, SealKey, SymbolTable, entry_mirrors};
use fa_money::UnitRegistry;
use fa_time::{DateDay, FiscalCalendar};
use fgdb::{Database, DatabaseKeys, MemVfs, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CommitSeq, VId};

struct Harness {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
    source: VId,
    original: Entry,
}

impl Harness {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let mut db = runtime
            .block_on(Database::open_memory(
                &cx.commit(),
                DatabaseKeys::new([31; 32], DatabaseSecurityNamespaceId([32; 32]), [33; 32]),
            ))
            .unwrap();
        let units = UnitRegistry::embedded().unwrap();
        let calendar = FiscalCalendar::monthly("entry-history", 1, 1).unwrap();
        let symbols = SymbolTable::compiled();
        let book = BookContext {
            book_id: Id128([34; 16]),
            calendar: calendar.clone(),
            units: units.clone(),
            seal_key: SealKey([35; 32]),
            symbols: symbols.clone(),
        };
        let spec = BookSpec {
            book_id: book.book_id,
            name: "Immutable entry history".into(),
            base_unit: units.lookup("USD").unwrap(),
            calendar,
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        runtime
            .block_on(create_book(&mut db, &cx, &spec, &units, &symbols))
            .unwrap();
        let accounts = [AccountSpec {
            code: "1000".into(),
            name: "Cash".into(),
            account_type: 1,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        }];
        let description = Erasable::seal(
            &"original chart".to_string(),
            None,
            &book.seal_key,
            [36; 32],
            [37; 24],
        );
        runtime
            .block_on(install_chart(
                &mut db,
                &cx,
                &book,
                &accounts,
                VId(1),
                DateDay::from_ymd(2026, 3, 1).unwrap(),
                b"integrity-chart",
                description,
                &fa_journal::Capability::embedded(VId(1), &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        let row = db
            .vertices_at(db.frontier().unwrap())
            .unwrap()
            .into_iter()
            .find(|row| row.labels.contains(&label::ENTRY))
            .unwrap();
        let original =
            Entry::decode(&bytes(&row, property::FA_PAYLOAD, "fixture entry").unwrap()).unwrap();
        Self {
            runtime,
            root,
            db,
            book,
            source: row.vid,
            original,
        }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }
    fn head(&self) -> CommitSeq {
        self.db.frontier().unwrap()
    }
    fn check(&self, known_at: Option<CommitSeq>) -> Result<EntryHistoryVerification, KernelError> {
        verify_entry_history(&self.db, &self.cx(), &self.book, known_at)
    }
    fn write(&mut self, batch: WriteBatch) -> CommitSeq {
        let cx = self.cx();
        self.runtime
            .block_on(self.db.write(&cx.commit(), batch))
            .unwrap()
    }
    fn replace(&mut self, entry: &Entry) {
        let mut batch = WriteBatch::new(relation::HAS_LEG);
        for (key, value) in entry_mirrors(entry).unwrap() {
            batch.set_vertex_property(self.source, key, Some(value));
        }
        self.write(batch);
    }
}

#[test]
fn intact_history_counts_all_commits_and_ignores_non_entry_typed_payloads() {
    let mut h = Harness::new();
    let original_head = h.head();
    let expected = h.check(None).unwrap();
    assert_eq!(expected.known_at, original_head);
    assert_eq!(expected.commits_checked, original_head.0);
    assert_eq!(expected.entries_checked, 1);
    let mut maintenance = WriteBatch::new(relation::DERIVED_FROM);
    // A typed object may store Entry bytes as data; its label is not Entry.
    maintenance.create_vertex(
        VId(500),
        vec![label::CERTIFICATE],
        vec![(
            property::FA_PAYLOAD,
            scalar_bytes(
                "opaque stored bytes",
                bytes(
                    &h.db.vertex(h.source).unwrap().unwrap(),
                    property::FA_PAYLOAD,
                    "entry",
                )
                .unwrap(),
            )
            .unwrap(),
        )],
    );
    h.write(maintenance);
    let before = h.head();
    let checked = h.check(None).unwrap();
    assert_eq!(checked.entries_checked, 1);
    assert_eq!(checked.commits_checked, before.0);
    assert_eq!(h.check(Some(original_head)).unwrap(), expected);
    assert_eq!(h.head(), before, "verification never publishes maintenance");
}

#[test]
fn a_self_consistent_entry_rewrite_is_not_an_immutable_journal() {
    let mut h = Harness::new();
    let intact = h.head();
    let mut proposal = h.original.proposal.clone();
    proposal.description = Erasable::seal(
        &"rewritten chart narrative".to_string(),
        None,
        &h.book.seal_key,
        [41; 32],
        [42; 24],
    );
    let replaced = proposal.seal(Vec::new(), None).unwrap();
    h.replace(&replaced);
    let before = h.head();
    // Both the payload and its mirrored hashes agree with the replacement.
    let row = h.db.vertex(h.source).unwrap().unwrap();
    let decoded = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "changed").unwrap()).unwrap();
    assert_eq!(decoded.entry_digest, replaced.entry_digest);
    assert!(matches!(h.check(None), Err(KernelError::Corrupt(_))));
    assert_eq!(h.check(Some(intact)).unwrap().entries_checked, 1);
    assert_eq!(h.head(), before);
}

#[test]
fn exact_byte_restoration_does_not_erase_the_rewrite() {
    let mut h = Harness::new();
    let mut damaged = WriteBatch::new(relation::HAS_LEG);
    damaged.set_vertex_property(
        h.source,
        property::FA_DIGEST,
        Some(scalar_bytes("bad digest", vec![0; 32]).unwrap()),
    );
    h.write(damaged);
    let original = h.original.clone();
    h.replace(&original);
    let row = h.db.vertex(h.source).unwrap().unwrap();
    assert_eq!(
        Entry::decode(&bytes(&row, property::FA_PAYLOAD, "restored").unwrap()).unwrap(),
        original
    );
    let before = h.head();
    assert!(matches!(h.check(None), Err(KernelError::Corrupt(_))));
    assert_eq!(h.head(), before);
}

#[test]
fn removing_and_restoring_the_entry_label_cannot_hide_its_history() {
    let mut h = Harness::new();
    let mut relabel = WriteBatch::new(relation::HAS_LEG);
    relabel.set_vertex_label(h.source, label::ENTRY, false);
    relabel.set_vertex_label(h.source, label::DOCUMENT, true);
    h.write(relabel);
    assert!(
        !h.db
            .vertex(h.source)
            .unwrap()
            .unwrap()
            .labels
            .contains(&label::ENTRY)
    );
    assert!(h.check(None).is_err());
    let mut restore = WriteBatch::new(relation::HAS_LEG);
    restore.set_vertex_label(h.source, label::DOCUMENT, false);
    restore.set_vertex_label(h.source, label::ENTRY, true);
    h.write(restore);
    let before = h.head();
    assert!(h.check(None).is_err());
    assert_eq!(h.head(), before);
}

#[test]
fn a_new_entry_with_dishonest_mirrors_is_rejected_even_without_a_rewrite() {
    let mut h = Harness::new();
    let mut proposal = h.original.proposal.clone();
    proposal.idempotency_key = b"bad-born-mirror".to_vec();
    let entry = proposal.seal(Vec::new(), None).unwrap();
    let mut mirrors = entry_mirrors(&entry).unwrap();
    mirrors
        .iter_mut()
        .find(|(key, _)| *key == property::FA_DIGEST)
        .unwrap()
        .1 = scalar_bytes("incorrect mirror", vec![0; 32]).unwrap();
    let mut insertion = WriteBatch::new(relation::HAS_LEG);
    insertion.create_vertex(VId(600), vec![label::ENTRY], mirrors);
    h.write(insertion);
    let before = h.head();
    assert!(matches!(h.check(None), Err(KernelError::Corrupt(_))));
    assert_eq!(h.head(), before);
}

#[test]
fn promoting_a_non_entry_vertex_does_not_manufacture_an_entry_birth() {
    let mut h = Harness::new();
    let mut insertion = WriteBatch::new(relation::HAS_LEG);
    insertion.create_vertex(
        VId(700),
        vec![label::REGISTER],
        entry_mirrors(&h.original).unwrap(),
    );
    h.write(insertion);
    assert_eq!(h.check(None).unwrap().entries_checked, 1);
    let mut promotion = WriteBatch::new(relation::HAS_LEG);
    promotion.set_vertex_label(VId(700), label::REGISTER, false);
    promotion.set_vertex_label(VId(700), label::ENTRY, true);
    h.write(promotion);
    let before = h.head();
    assert!(h.check(None).is_err());
    assert_eq!(h.head(), before);
}

#[test]
fn later_prefixes_and_foreign_book_contexts_cannot_be_claimed() {
    let h = Harness::new();
    let before = h.head();
    assert!(h.check(Some(CommitSeq(before.0 + 1))).is_err());
    let mut foreign = h.book.clone();
    foreign.book_id = Id128([0xff; 16]);
    assert!(verify_entry_history(&h.db, &h.cx(), &foreign, None).is_err());
    assert_eq!(h.head(), before);
}
