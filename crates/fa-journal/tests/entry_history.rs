//! Entry-history integrity against real committed native deltas. Chart creation
//! uses the production kernel; later raw writes deliberately inject corruption.

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, CancelKind, Cx};
use fa_journal::entry_history::{
    EntryHistoryMemo, EntryHistoryVerification, verify_entry_history, verify_entry_history_carried,
};
use fa_journal::rows::{bytes, scalar_bytes};
use fa_journal::{
    AccountSpec, BookContext, BookSpec, KernelError, UnitPolicy, create_book, install_chart,
};
use fa_model::symbols::{label, property, relation};
use fa_model::{Entry, Erasable, ExternalId, Id128, SealKey, SymbolTable, entry_mirrors};
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
        Self::named("Immutable entry history")
    }

    fn named(name: &str) -> Self {
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
            name: name.into(),
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

    fn carried(
        &self,
        at: Option<CommitSeq>,
        memo: &mut EntryHistoryMemo,
    ) -> Result<EntryHistoryVerification, KernelError> {
        verify_entry_history_carried(&self.db, &self.cx(), &self.book, at, memo)
    }

    fn append(&mut self, vid: VId, large: bool) -> Entry {
        let mut proposal = self.original.proposal.clone();
        proposal.idempotency_key = format!("integrity-{:032x}", vid.0).into_bytes();
        if large {
            // Several bounded, canonical provenance fields grow a valid
            // Entry beyond the inline row limit without oversized text.
            proposal.external_ids = (0_u8..32)
                .map(|i| ExternalId {
                    system: format!("source-{i:02}"),
                    id: Erasable::seal(
                        &"retained-reference".repeat(8),
                        None,
                        &self.book.seal_key,
                        [i; 32],
                        [i; 24],
                    ),
                })
                .collect();
        }
        let entry = proposal.seal(Vec::new(), None).unwrap();
        let mut batch = WriteBatch::new(relation::HAS_LEG);
        fa_journal::entry_storage::stage(&self.cx().query(), &mut batch, &entry, vid).unwrap();
        batch.create_vertex(
            vid,
            vec![label::ENTRY],
            fa_journal::entry_storage::stored_mirrors(&entry).unwrap(),
        );
        self.write(batch);
        entry
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

#[test]
fn carried_entry_history_matches_literal_folds_without_revisiting_the_verified_prefix() {
    let mut h = Harness::new();
    let mut memo = EntryHistoryMemo::default();
    assert_eq!(h.carried(None, &mut memo).unwrap(), h.check(None).unwrap());
    assert!(memo.read_work().rebuilt);
    assert_eq!(memo.read_work().snapshot_scans, 1);
    assert_eq!(memo.read_work().entries_decoded, 1);
    let first = h.head();
    let mut suffix_cost = None;
    for index in 0..64 {
        h.append(VId(10_000 + index), false);
        let before = h.head();
        assert_eq!(h.carried(None, &mut memo).unwrap(), h.check(None).unwrap());
        let work = memo.read_work();
        assert!(!work.rebuilt);
        assert_eq!(work.snapshot_scans, 0);
        assert_eq!(work.snapshot_rows, 0);
        assert_eq!(work.entries_decoded, 1);
        assert!(work.delta_rows > 0);
        assert_eq!(
            *suffix_cost.get_or_insert(work.delta_rows),
            work.delta_rows,
            "one equal-sized suffix costs the same as the book grows"
        );
        assert_eq!(h.head(), before, "verification never publishes");
    }
    let latest = h.head();
    let expected = h.check(None).unwrap();
    assert_eq!(expected.entries_checked, 65);
    assert_eq!(h.carried(None, &mut memo).unwrap(), expected);
    assert_eq!(
        memo.read_work(),
        Default::default(),
        "same prefix has no row visits"
    );
    assert_eq!(
        h.carried(Some(first), &mut memo).unwrap(),
        h.check(Some(first)).unwrap()
    );
    assert!(
        memo.read_work().rebuilt,
        "historical reads use the literal oracle"
    );
    assert_eq!(
        memo.verified_at(),
        Some(latest),
        "history does not evict the forward prefix"
    );
    assert_eq!(h.carried(None, &mut memo).unwrap(), expected);
    assert_eq!(memo.read_work(), Default::default());
}

#[test]
fn carried_entry_history_handles_maintenance_and_fragmented_births() {
    let mut h = Harness::new();
    let mut memo = EntryHistoryMemo::default();
    h.carried(None, &mut memo).unwrap();
    let mut batch = WriteBatch::new(relation::DERIVED_FROM);
    batch.create_vertex(
        VId(1000),
        vec![label::CERTIFICATE],
        vec![(
            property::FA_PAYLOAD,
            scalar_bytes("opaque", h.original.encode().unwrap()).unwrap(),
        )],
    );
    h.write(batch);
    assert_eq!(h.carried(None, &mut memo).unwrap(), h.check(None).unwrap());
    assert_eq!(memo.read_work().entries_decoded, 0);
    assert!(!memo.read_work().rebuilt);
    h.append(VId(1001), true);
    assert!(
        h.db.vertices_at(h.head())
            .unwrap()
            .iter()
            .any(|row| row.labels.contains(&label::ENTRY_FRAGMENT))
    );
    assert_eq!(h.carried(None, &mut memo).unwrap(), h.check(None).unwrap());
    assert_eq!(memo.read_work().entries_decoded, 1);
    assert!(!memo.read_work().rebuilt);
    let verified = h.head();
    let fragment =
        h.db.vertices_at(verified)
            .unwrap()
            .into_iter()
            .find(|row| row.labels.contains(&label::ENTRY_FRAGMENT))
            .unwrap();
    let mut damage = WriteBatch::new(relation::HAS_LEG);
    damage.set_vertex_property(
        fragment.vid,
        property::FA_DIGEST,
        Some(scalar_bytes("bad fragment", vec![0; 32]).unwrap()),
    );
    h.write(damage);
    assert!(h.carried(None, &mut memo).is_err());
    assert!(h.check(None).is_err());
    assert_eq!(memo.verified_at(), Some(verified));
    let mut restoration = WriteBatch::new(relation::HAS_LEG);
    for (key, value) in fragment.props {
        restoration.set_vertex_property(fragment.vid, key, Some(value));
    }
    h.write(restoration);
    assert!(
        h.carried(None, &mut memo).is_err(),
        "restoration cannot replace native birth"
    );
    assert!(h.check(None).is_err());
    assert_eq!(
        h.carried(Some(verified), &mut memo).unwrap(),
        h.check(Some(verified)).unwrap()
    );
}

#[test]
fn carried_entry_history_refuses_every_entry_tamper_at_the_literal_verifiers_prefix() {
    for attack in 0..6 {
        let mut h = Harness::new();
        let mut memo = EntryHistoryMemo::default();
        let intact = h.head();
        let expected = h.carried(None, &mut memo).unwrap();
        let saved_work = memo.read_work();
        let mut damage = WriteBatch::new(relation::HAS_LEG);
        match attack {
            0 => {
                damage.set_vertex_property(
                    h.source,
                    property::FA_DIGEST,
                    Some(scalar_bytes("bad digest", vec![0; 32]).unwrap()),
                );
            }
            1 => {
                damage.set_vertex_label(h.source, label::ENTRY, false);
                damage.set_vertex_label(h.source, label::DOCUMENT, true);
            }
            2 => {
                damage.delete_vertex(h.source);
            }
            3 => {
                let mut mirrors = entry_mirrors(&h.original).unwrap();
                mirrors
                    .iter_mut()
                    .find(|(key, _)| *key == property::FA_DIGEST)
                    .unwrap()
                    .1 = scalar_bytes("bad born mirror", vec![0; 32]).unwrap();
                damage.create_vertex(VId(900), vec![label::ENTRY], mirrors);
            }
            4 => {
                damage.create_vertex(
                    VId(901),
                    vec![label::DOCUMENT],
                    entry_mirrors(&h.original).unwrap(),
                );
                h.write(damage);
                assert_eq!(h.carried(None, &mut memo).unwrap(), h.check(None).unwrap());
                damage = WriteBatch::new(relation::HAS_LEG);
                damage.set_vertex_label(VId(901), label::DOCUMENT, false);
                damage.set_vertex_label(VId(901), label::ENTRY, true);
            }
            5 => {
                damage.set_vertex_property(
                    h.source,
                    property::FA_DIGEST,
                    Some(scalar_bytes("temporary rewrite", vec![0; 32]).unwrap()),
                );
                h.write(damage);
                damage = WriteBatch::new(relation::HAS_LEG);
                for (key, value) in entry_mirrors(&h.original).unwrap() {
                    damage.set_vertex_property(h.source, key, Some(value));
                }
            }
            _ => unreachable!(),
        }
        let verified = memo.verified_at();
        let previous_work = memo.read_work();
        h.write(damage);
        assert!(
            matches!(h.carried(None, &mut memo), Err(KernelError::Corrupt(_))),
            "attack {attack}"
        );
        assert!(
            matches!(h.check(None), Err(KernelError::Corrupt(_))),
            "literal attack {attack}"
        );
        assert_eq!(
            memo.verified_at(),
            verified,
            "failed verification cannot advance a prefix"
        );
        assert_eq!(
            memo.read_work(),
            previous_work,
            "failed work is not a successful verdict"
        );
        assert_eq!(h.carried(Some(intact), &mut memo).unwrap(), expected);
        if attack != 4 {
            assert_eq!(saved_work.entries_decoded, 1);
        }
    }
}

#[test]
fn carried_entry_history_authenticates_the_marker_and_book_not_just_a_sequence() {
    let a = Harness::named("first native history");
    let b = Harness::named("a different native genesis at the same sequence");
    assert_eq!(a.head(), b.head());
    assert_eq!(a.book.book_id, b.book.book_id);
    let mut memo = EntryHistoryMemo::default();
    a.carried(None, &mut memo).unwrap();
    assert_eq!(b.carried(None, &mut memo).unwrap(), b.check(None).unwrap());
    assert!(
        memo.read_work().rebuilt,
        "same sequence in a different history cannot reuse evidence"
    );
    assert_eq!(memo.read_work().snapshot_scans, 1);
    let saved = memo.verified_at();
    let mut foreign = b.book.clone();
    foreign.book_id = Id128([0xff; 16]);
    assert!(verify_entry_history_carried(&b.db, &b.cx(), &foreign, None, &mut memo).is_err());
    assert_eq!(memo.verified_at(), saved);
    assert!(
        b.carried(Some(CommitSeq(b.head().0 + 1)), &mut memo)
            .is_err()
    );
    assert_eq!(memo.verified_at(), saved);
    assert_eq!(b.carried(None, &mut memo).unwrap(), b.check(None).unwrap());
    assert_eq!(memo.read_work(), Default::default());
}

#[test]
fn cancelled_integrity_checks_cannot_reuse_or_install_a_verified_prefix() {
    for warm in [false, true] {
        let h = Harness::new();
        let mut memo = EntryHistoryMemo::default();
        if warm {
            h.carried(None, &mut memo).unwrap();
        }
        let verified = memo.verified_at();
        let work = memo.read_work();
        h.root
            .cancel_with(CancelKind::User, Some("cancelled history observation"));
        assert!(h.carried(None, &mut memo).is_err());
        assert!(h.check(None).is_err());
        assert_eq!(memo.verified_at(), verified);
        assert_eq!(memo.read_work(), work);
    }
}
