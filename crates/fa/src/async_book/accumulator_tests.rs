//! Cold facade verification must hydrate only an admitted, useful interval.
//! The existing immutable verifier remains the independent result oracle.

use super::*;
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_model::Id128;
use fa_policy::Capability;
use fa_time::FiscalCalendar;
use fgdb::{MemVfs, WriteBatch};

const PRINCIPAL: VId = VId(177);
const DIRECTORY: &str = "accumulator-history";

fn capability(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

fn verifier() -> Capability {
    capability(&["read", "verify"])
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    vfs: MemVfs,
    book: AsyncBook<MemVfs>,
    states: Vec<fa_notary::StoredState>,
}

impl Harness {
    fn new(count: usize) -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let spec = BookSpec {
            book_id: Id128([177; 16]),
            name: "Accumulator history".into(),
            base_unit: fa_money::UnitRegistry::embedded()
                .unwrap()
                .lookup("USD")
                .unwrap(),
            calendar: FiscalCalendar::monthly("accumulator-history", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs.clone(),
                Path::new(DIRECTORY),
                BookKeys::for_development(177),
                spec,
                Entropy::deterministic(177),
            ))
            .unwrap();
        let mut states = Vec::new();
        for index in 0..count {
            runtime
                .block_on(book.create_periods(
                    &cx,
                    2026 + i32::try_from(index).unwrap(),
                    PRINCIPAL,
                    &capability(&["schema_change"]),
                ))
                .unwrap()
                .unwrap();
            states.push(
                runtime
                    .block_on(book.checkpoint(&cx, PRINCIPAL, &capability(&["witness"])))
                    .unwrap()
                    .unwrap()
                    .stored,
            );
        }
        Self {
            runtime,
            root,
            vfs,
            book,
            states,
        }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn reopen(self) -> Self {
        let Self {
            runtime,
            root,
            vfs,
            book,
            states,
        } = self;
        drop(book);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let book = runtime
            .block_on(AsyncBook::open_with_vfs(
                &cx,
                vfs.clone(),
                Path::new(DIRECTORY),
                BookKeys::for_development(177),
                Entropy::deterministic(178),
            ))
            .unwrap();
        Self {
            runtime,
            root,
            vfs,
            book,
            states,
        }
    }

    fn verify(&mut self, capability: &Capability) -> Outcome<fa_notary::AccumulatorVerification> {
        let cx = self.cx();
        self.runtime.block_on(
            self.book
                .verify_accumulator_with_history(&cx, PRINCIPAL, capability),
        )
    }

    fn counted(
        &self,
    ) -> (
        fa_notary::AccumulatorVerification,
        fa_notary::AccumulatorReadWork,
    ) {
        let cx = self.cx();
        self.book
            .query(&cx, |db, book| {
                Ok(fa_notary::verify_accumulator_counted(
                    db,
                    &cx,
                    book,
                    &self.book.signer,
                )?)
            })
            .unwrap()
    }
}

#[test]
fn cold_accumulator_verification_loads_only_its_admitted_checkpoint_interval() {
    let mut h = Harness::new(3).reopen();
    let oldest = h.states[0].state.through_seq;
    let head = h.book.head(&h.cx()).unwrap();
    let root = h.book.db.partition_root().unwrap();
    assert!(h.book.db.delta_since(oldest).is_err());
    let expected = h.book.verify_accumulator(&h.cx()).unwrap();
    assert!(expected.is_green(), "{expected:?}");
    let (_, before) = h.counted();
    assert_eq!(before.shared_prefixes, 0);
    assert_eq!(before.literal_prefixes, 3);

    for denied in [
        capability(&["read"]),
        capability(&["verify"]),
        Capability::embedded(VId(178), &["read", "verify"]).unwrap(),
        verifier().for_books(&[Id128([255; 16])]).unwrap(),
        verifier().for_accounts(&["1000"]).unwrap(),
        verifier().for_periods(&["FY2026-P01"]).unwrap(),
        verifier().expiring_at(head),
    ] {
        let refusal = h.verify(&denied).unwrap().unwrap_err();
        assert_eq!(refusal.exit, fa_journal::exit::SAFETY, "{refusal:?}");
        assert!(
            h.book.db.delta_since(oldest).is_err(),
            "denied authority must not load native history"
        );
    }

    assert_eq!(h.verify(&verifier()).unwrap().unwrap(), expected);
    let (actual, work) = h.counted();
    assert_eq!(actual, expected);
    assert_eq!(work.shared_prefixes, 3, "{work:?}");
    assert_eq!(work.literal_prefixes, 0, "{work:?}");
    assert_eq!(work.journal_full_reads, 1, "{work:?}");
    assert!(h.book.db.delta_since(oldest).is_ok());
    assert!(
        h.book.db.delta_since(CommitSeq(oldest.0 - 1)).is_err(),
        "verification must not load history before its earliest checkpoint"
    );
    assert_eq!(h.book.head(&h.cx()).unwrap(), head);
    assert_eq!(h.book.db.partition_root().unwrap(), root);
}

#[test]
fn cold_accumulator_verification_skips_history_without_multiple_checkpoints() {
    for count in [0, 1] {
        let mut h = Harness::new(count).reopen();
        let expected = h.book.verify_accumulator(&h.cx()).unwrap();
        let head = h.book.head(&h.cx()).unwrap();
        assert_eq!(expected.states.len(), count);
        assert!(h.book.db.delta_since(CommitSeq(0)).is_err());
        assert_eq!(h.verify(&verifier()).unwrap().unwrap(), expected);
        assert!(h.book.db.delta_since(CommitSeq(0)).is_err());
        assert_eq!(h.book.head(&h.cx()).unwrap(), head);
    }
}

#[test]
fn cold_accumulator_verification_preserves_broken_chain_findings() {
    let mut h = Harness::new(2);
    let mut damage = WriteBatch::new(fa_model::symbols::relation::DERIVED_FROM);
    damage.set_vertex_property(
        fa_journal::rows::book_root(),
        fa_model::symbols::property::ACCUMULATOR_HEAD,
        Some(fgdb_types::CanonicalScalar::bytes(vec![0xff; 32]).unwrap()),
    );
    let cx = h.cx();
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), damage))
        .unwrap();
    let mut h = h.reopen();
    let oldest = h.states[0].state.through_seq;
    let head = h.book.head(&h.cx()).unwrap();
    let expected = h.book.verify_accumulator(&h.cx()).unwrap();
    assert!(expected.broken.is_some(), "{expected:?}");
    assert!(!expected.is_green());
    assert_eq!(h.verify(&verifier()).unwrap().unwrap(), expected);
    assert!(h.book.db.delta_since(oldest).is_err());
    assert_eq!(h.book.head(&h.cx()).unwrap(), head);
}
