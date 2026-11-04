//! Native final-state admission at a small hold bound. The production bound
//! remains MAX_BATCH_ENTRIES; using two here exercises the same literal and
//! carried checks without creating thousands of unrelated posting fixtures.

use super::*;
use crate::batch::tests::{make_entry_intent, setup_batch_test_book};
use crate::batch::{self, BatchStage, StagedBatch};
use crate::genesis::{BookContext, UnitPolicy};
use crate::post::Admission;
use fa_intents::{PostBatch, PostIntent};
use fa_model::{ControlPayload, Disposition, EntryRef, Erasable, Pending};
use fa_policy::Capability;
use fa_time::{DateDay, PeriodTransition};
use fgdb::MemVfs;

struct Fixture {
    runtime: asupersync::runtime::Runtime,
    root: asupersync::Cx,
    db: Database<MemVfs>,
    book: BookContext,
    usd: UnitId,
    cash: VId,
    rent: VId,
    evidence: Vec<fa_model::EvidenceRef>,
}

impl Fixture {
    fn new() -> Self {
        let (runtime, root, db, book, usd, cash, rent, evidence) = setup_batch_test_book();
        Self {
            runtime,
            root,
            db,
            book,
            usd,
            cash,
            rent,
            evidence,
        }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn hold(&self, key: &[u8]) -> EntryPayload {
        let mut proposal = make_entry_intent(
            &self.book,
            self.usd,
            self.cash,
            self.rent,
            &self.evidence,
            1,
            key,
        )
        .proposal()
        .clone();
        proposal.class = EntryClass::PENDING;
        proposal.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: None,
            disposition: None,
        });
        proposal
    }

    fn release(&self, target: EntryRef, key: &[u8]) -> EntryPayload {
        let mut proposal = self.hold(key);
        proposal.class = EntryClass::RESOLUTION;
        proposal.legs.clear();
        proposal.unit_totals.clear();
        proposal.control = Some(ControlPayload::ReservationRelease);
        proposal.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: Some(target),
            disposition: Some(Disposition::Voids),
        });
        proposal
    }

    fn release_posting(&self, target: EntryRef, key: &[u8]) -> EntryPayload {
        let mut proposal = self.hold(key);
        proposal.class = EntryClass::RESOLUTION;
        proposal.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: Some(target),
            disposition: Some(Disposition::Posts {
                source_ordinals: vec![0, 1],
            }),
        });
        proposal
    }

    fn batch(&self, key: &[u8], members: Vec<EntryPayload>) -> PostBatch {
        // Outcome and member idempotency namespaces are intentionally disjoint.
        let mut batch_key = b"hold-count/".to_vec();
        batch_key.extend_from_slice(key);
        PostBatch::new(
            batch_key,
            members
                .into_iter()
                .map(|proposal| PostIntent::new(proposal, Vec::new()).unwrap())
                .collect(),
        )
        .unwrap()
    }

    fn stage(&mut self, batch: &PostBatch) -> Result<Box<StagedBatch>, Refusal> {
        let capabilities =
            vec![Capability::embedded(VId(7), &["post"]).unwrap(); batch.members().len()];
        let cx = self.cx();
        match batch::stage_batch(
            &mut self.db,
            &cx,
            &self.book,
            &capabilities,
            batch,
            Admission::Commit,
        )
        .unwrap()?
        {
            BatchStage::Staged(staged) => Ok(staged),
            BatchStage::Recorded(_) => panic!("a new fixture batch must be staged"),
        }
    }

    fn check(&self, staged: &StagedBatch, limit: usize) -> Result<(), Refusal> {
        let accounts = accounts(
            staged
                .prepared_entries()
                .iter()
                .map(|entry| &entry.proposal),
        );
        let vids: Vec<_> = staged
            .entries
            .iter()
            .map(|reference| reference.vid)
            .collect();
        let literal = admit_including_with_pending_limit(
            &staged.txn,
            &self.db,
            &self.cx(),
            self.book.book_id,
            &accounts,
            vids.iter().copied(),
            &[],
            limit,
        )
        .unwrap();
        let summary =
            summarize(&self.db, &self.cx(), self.book.book_id, staged.txn.basis()).unwrap();
        let carried = fits(
            &staged.txn,
            &self.db,
            summary.cells.as_ref().expect("valid native history"),
            self.book.book_id,
            &accounts,
            &vids,
            None,
            limit,
        )
        .unwrap();
        assert_eq!(
            carried.fits,
            literal.is_ok(),
            "literal and carried admission must judge the same final hold state: {literal:?}",
        );
        literal
    }

    fn commit(
        &mut self,
        batch: &PostBatch,
        staged: Box<StagedBatch>,
    ) -> Result<batch::BatchPosted, Refusal> {
        let capabilities =
            vec![Capability::embedded(VId(7), &["post"]).unwrap(); batch.members().len()];
        let cx = self.cx();
        self.runtime
            .block_on(batch::commit_batch(
                &mut self.db,
                &cx,
                &self.book,
                &capabilities,
                batch,
                Admission::Commit,
                staged,
            ))
            .unwrap()
    }

    fn post(&mut self, key: &[u8], proposal: EntryPayload) -> EntryRef {
        let batch = self.batch(key, vec![proposal]);
        let staged = self.stage(&batch).unwrap();
        self.commit(&batch, staged).unwrap().entries[0]
    }

    fn open_april(&mut self) {
        let cx = self.cx();
        self.runtime
            .block_on(crate::period::transition_period(
                &mut self.db,
                &cx,
                &self.book,
                "FY2026-P04",
                PeriodTransition::Open,
                VId(7),
                1,
                b"hold-bound-open-april",
                Erasable::seal(
                    &"open April".to_string(),
                    None,
                    &self.book.seal_key,
                    [3; 32],
                    [4; 24],
                ),
                &Capability::embedded(VId(7), &["close"]).unwrap(),
                &[],
            ))
            .unwrap()
            .unwrap();
    }

    fn another_pair(&mut self) -> (VId, VId) {
        let accounts: Vec<_> = [("1100", 1), ("6100", 5)]
            .into_iter()
            .map(|(code, account_type)| crate::genesis::AccountSpec {
                code: code.into(),
                name: code.into(),
                account_type,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(self.usd),
                parent_code: None,
                limit: None,
            })
            .collect();
        let cx = self.cx();
        self.runtime
            .block_on(crate::genesis::install_chart(
                &mut self.db,
                &cx,
                &self.book,
                &accounts,
                VId(7),
                DateDay::from_ymd(2026, 3, 1).unwrap(),
                b"hold-bound-other-accounts",
                Erasable::seal(
                    &"other accounts".to_string(),
                    None,
                    &self.book.seal_key,
                    [5; 32],
                    [6; 24],
                ),
                &Capability::embedded(VId(7), &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        (
            fa_model::account_vid(self.book.book_id, "1100"),
            fa_model::account_vid(self.book.book_id, "6100"),
        )
    }
}

#[test]
fn pending_hold_count_native_admission_and_summary_agree_at_boundaries() {
    let mut fixture = Fixture::new();
    let other = fixture.another_pair();
    for (index, key) in [
        b"count-minus-one".as_slice(),
        b"count-at-cap",
        b"count-over-cap",
    ]
    .into_iter()
    .enumerate()
    {
        let mut hold = fixture.hold(key);
        if index == 2 {
            // Capacity belongs to the period, not these untouched accounts.
            hold.legs[0].account_ref = other.1;
            hold.legs[1].account_ref = other.0;
        }
        let batch = fixture.batch(key, vec![hold]);
        let staged = fixture.stage(&batch).unwrap();
        let at = fixture.db.frontier().unwrap();
        let result = fixture.check(&staged, 2);
        if index < 2 {
            result.expect("cap-1 and cap are admitted");
            fixture.commit(&batch, staged).unwrap();
        } else {
            let refusal = result.expect_err("cap+1 is refused before publication");
            assert_eq!(refusal.code, code::REGISTER_CAPACITY);
            assert!(refusal.message.contains("max_batch_entries 2"));
            assert!(refusal.fix.contains("resolve or void"));
            staged.txn.abort();
            assert_eq!(fixture.db.frontier().unwrap(), at);
        }
    }

    // The count law also names the actual registered boundary without
    // manufacturing an 8,190-entry accounting success fixture.
    let maximum = fa_model::limits::MAX_BATCH_ENTRIES;
    let before = PendingCounts::from([("P".into(), maximum - 1)]);
    for (count, refused) in [(maximum - 1, false), (maximum, false), (maximum + 1, true)] {
        assert_eq!(
            pending_count_refusal(
                &before,
                &PendingCounts::from([("P".into(), count)]),
                maximum,
                CommitSeq(1),
            )
            .is_some(),
            refused,
        );
    }
}

#[test]
fn pending_hold_count_releases_origin_period_in_either_atomic_member_order() {
    for release_first in [false, true] {
        let mut fixture = Fixture::new();
        let first = fixture.post(b"first", fixture.hold(b"first-hold"));
        fixture.post(b"second", fixture.hold(b"second-hold"));
        fixture.open_april();
        let next = fixture.hold(b"replacement-hold");
        let mut release = fixture.release(first, b"april-release");
        release.effective_date = DateDay::from_ymd(2026, 4, 1).unwrap();
        let members = if release_first {
            vec![release, next]
        } else {
            vec![next, release]
        };
        let batch = fixture.batch(b"replace-at-cap", members);
        let staged = fixture.stage(&batch).unwrap();
        fixture
            .check(&staged, 2)
            .expect("the later-period release frees its original hold's slot");
        fixture.commit(&batch, staged).unwrap();
        let summary = summarize(
            &fixture.db,
            &fixture.cx(),
            fixture.book.book_id,
            fixture.db.frontier().unwrap(),
        )
        .unwrap();
        let counts = &summary.cells.unwrap().pending_counts;
        assert_eq!(counts.get("FY2026-P03"), Some(&2));
        assert_eq!(counts.get("FY2026-P04").copied().unwrap_or_default(), 0);
    }
}

#[test]
fn pending_hold_count_allows_legacy_repair_and_same_batch_transient_holds() {
    let mut fixture = Fixture::new();
    let first = fixture.post(b"legacy-first", fixture.hold(b"legacy-first-hold"));
    fixture.post(b"legacy-second", fixture.hold(b"legacy-second-hold"));
    fixture.post(b"legacy-third", fixture.hold(b"legacy-third-hold"));
    // Three genuine native holds are a legacy over-cap state in the same
    // small-domain law. Replacing one keeps it at three, so does not worsen it.
    let batch = fixture.batch(
        b"non-increasing-legacy",
        vec![
            fixture.hold(b"legacy-replacement"),
            fixture.release(first, b"legacy-release"),
        ],
    );
    let staged = fixture.stage(&batch).unwrap();
    fixture
        .check(&staged, 2)
        .expect("an over-cap period can be repaired without an admission dead end");
    let posted = fixture.commit(&batch, staged).unwrap();

    for (posts, hold_key, release_key) in [
        (
            false,
            b"transient-void".as_slice(),
            b"release-transient-void".as_slice(),
        ),
        (true, b"transient-posts", b"release-transient-posts"),
    ] {
        let transient = fixture.hold(hold_key);
        let reference = EntryRef {
            vid: fa_model::entry_vid(
                fixture.book.book_id,
                &VId(7).0.to_le_bytes(),
                &transient.idempotency_key,
            ),
            entry_digest: transient
                .clone()
                .seal(Vec::new(), None)
                .unwrap()
                .entry_digest,
        };
        let release = if posts {
            fixture.release_posting(reference, release_key)
        } else {
            fixture.release(reference, release_key)
        };
        let batch = fixture.batch(hold_key, vec![transient, release]);
        let staged = fixture.stage(&batch).unwrap();
        fixture
            .check(&staged, 2)
            .expect("a hold resolved in the same atomic publication consumes no final slot");
        fixture.commit(&batch, staged).unwrap();
    }

    let repair = fixture.batch(
        b"repair-count",
        vec![fixture.release(posted.entries[0], b"repair-release")],
    );
    let staged = fixture.stage(&repair).unwrap();
    fixture
        .check(&staged, 2)
        .expect("a pure Void remains admissible");
    fixture.commit(&repair, staged).unwrap();
    let summary = summarize(
        &fixture.db,
        &fixture.cx(),
        fixture.book.book_id,
        fixture.db.frontier().unwrap(),
    )
    .unwrap();
    assert_eq!(
        summary.cells.unwrap().pending_counts.get("FY2026-P03"),
        Some(&2)
    );
}

#[test]
fn pending_hold_count_never_credits_duplicate_or_forged_resolutions() {
    let mut fixture = Fixture::new();
    let first = fixture.post(b"negative-first", fixture.hold(b"negative-first-hold"));
    fixture.post(b"negative-second", fixture.hold(b"negative-second-hold"));
    let before = fixture.db.frontier().unwrap();
    let mut second_release = fixture.release(first, b"negative-release-two");
    second_release.description = Erasable::seal(
        &"a distinct second resolution of the same target".to_string(),
        None,
        &fixture.book.seal_key,
        [7; 32],
        [8; 24],
    );
    let duplicate = fixture.batch(
        b"duplicate-release",
        vec![
            fixture.hold(b"negative-new-one"),
            fixture.hold(b"negative-new-two"),
            fixture.release(first, b"negative-release-one"),
            second_release,
        ],
    );
    let refusal = fixture
        .stage(&duplicate)
        .err()
        .expect("one target cannot free two slots");
    assert_eq!(refusal.code, code::ALREADY_RESOLVED);
    assert_eq!(fixture.db.frontier().unwrap(), before);

    let mut forged = first;
    forged.entry_digest[0] ^= 1;
    let bad_digest = fixture.batch(
        b"forged-release",
        vec![
            fixture.hold(b"negative-new-three"),
            fixture.release(forged, b"negative-release-forged"),
        ],
    );
    let refusal = fixture
        .stage(&bad_digest)
        .err()
        .expect("a forged target cannot free capacity");
    assert_eq!(refusal.code, code::RESOLUTION_TARGET);
    assert_eq!(fixture.db.frontier().unwrap(), before);

    let extra = fixture.batch(
        b"unchanged-after-refusal",
        vec![fixture.hold(b"still-over-cap")],
    );
    let staged = fixture.stage(&extra).unwrap();
    assert_eq!(
        fixture.check(&staged, 2).unwrap_err().code,
        code::REGISTER_CAPACITY
    );
    staged.txn.abort();
    assert_eq!(fixture.db.frontier().unwrap(), before);
}

#[test]
fn pending_batches_recheck_capacity_after_an_intervening_publication() {
    let mut fixture = Fixture::new();
    let maximum_hold = |fixture: &Fixture, key: &[u8]| {
        let mut hold = fixture.hold(key);
        for leg in &mut hold.legs {
            leg.amount.mantissa = i128::MAX;
        }
        hold.unit_totals = EntryPayload::fold_unit_totals(&hold.legs).unwrap();
        hold
    };
    let first = fixture.batch(
        b"first-capacity-batch",
        vec![maximum_hold(&fixture, b"first-max-hold")],
    );
    let second = fixture.batch(
        b"second-capacity-batch",
        vec![maximum_hold(&fixture, b"second-max-hold")],
    );
    let first_stage = fixture.stage(&first).unwrap();
    let second_stage = fixture.stage(&second).unwrap();
    assert_eq!(first_stage.txn.basis(), second_stage.txn.basis());
    fixture.commit(&first, first_stage).unwrap();
    let at = fixture.db.frontier().unwrap();
    let refusal = fixture
        .commit(&second, second_stage)
        .expect_err("two preparations cannot jointly exhaust final capacity");
    assert_eq!(
        (refusal.code, refusal.exit),
        (code::CONFLICT, exit::CONFLICT)
    );
    assert!(refusal.message.contains("exhausted register capacity"));
    assert_eq!(fixture.db.frontier().unwrap(), at);
    let refusal = fixture
        .stage(&second)
        .err()
        .expect("a fresh attempt sees the capacity refusal");
    assert_eq!(refusal.code, code::REGISTER_CAPACITY);
}

#[test]
fn pending_batch_publication_keeps_a_fitting_changed_prefix() {
    let mut fixture = Fixture::new();
    let first = fixture.batch(b"fitting-first", vec![fixture.hold(b"fitting-first-hold")]);
    let delayed = fixture.batch(
        b"fitting-delayed",
        vec![fixture.hold(b"fitting-delayed-hold")],
    );
    let first_stage = fixture.stage(&first).unwrap();
    let delayed_stage = fixture.stage(&delayed).unwrap();
    fixture.commit(&first, first_stage).unwrap();
    fixture
        .commit(&delayed, delayed_stage)
        .expect("a changed prefix alone does not invalidate a fitting point operation");
}

#[test]
fn capacity_reconstruction_handles_a_hundred_thousand_hold_and_release_entries() {
    let fixture = Fixture::new();
    let mut cells = summarize(
        &fixture.db,
        &fixture.cx(),
        fixture.book.book_id,
        fixture.db.frontier().unwrap(),
    )
    .unwrap()
    .cells
    .unwrap();
    let outstanding = fixture
        .hold(b"capacity-history-outstanding")
        .seal(Vec::new(), None)
        .unwrap();
    assert!(cells.fold(&outstanding, false));
    let before_columns = cells.columns.clone();
    let before_counts = cells.pending_counts.clone();

    // Exercise the actual reconstruction fold at ledger scale without
    // conflating its work with substrate transaction staging. Its input is
    // a set of already decoded native entries, just as after a full scan.
    const HOLDS: u128 = 50_000;
    let mut holds = Vec::new();
    let mut entries = Vec::new();
    for index in 0..HOLDS {
        let hold = fixture
            .hold(format!("capacity-history-hold-{index}").as_bytes())
            .seal(Vec::new(), None)
            .unwrap();
        let vid = VId(index + 1);
        let release = fixture
            .release(
                hold.entry_ref(vid),
                format!("capacity-history-release-{index}").as_bytes(),
            )
            .seal(Vec::new(), None)
            .unwrap();
        holds.push((vid, hold));
        entries.push((VId(HOLDS + index + 1), release));
    }
    // Scan order is not commit order. Put all targets after their releases,
    // so a nested linear target search would traverse billions of entries.
    entries.extend(holds);
    assert_eq!(entries.len(), 100_000);
    assert!(
        cells
            .absorb(&entries, |_| {
                panic!("a hold in this reconstruction must not be read from an earlier prefix")
            })
            .unwrap()
    );
    assert_eq!(cells.columns, before_columns);
    assert_eq!(cells.pending_counts, before_counts);
    assert_eq!(cells.released.len(), 50_000);
    assert!((1..=HOLDS).all(|vid| cells.released.contains(&VId(vid))));
}

#[test]
fn capacity_reconstruction_reads_each_older_hold_once_and_preserves_unreleased_holds() {
    let fixture = Fixture::new();
    let mut cells = summarize(
        &fixture.db,
        &fixture.cx(),
        fixture.book.book_id,
        fixture.db.frontier().unwrap(),
    )
    .unwrap()
    .cells
    .unwrap();
    let hold = fixture
        .hold(b"capacity-older-hold")
        .seal(Vec::new(), None)
        .unwrap();
    let untouched = fixture
        .hold(b"capacity-untouched-hold")
        .seal(Vec::new(), None)
        .unwrap();
    assert!(cells.fold(&untouched, false));
    let expected_columns = cells.columns.clone();
    let expected_counts = cells.pending_counts.clone();
    assert!(cells.fold(&hold, false));
    let target = hold.entry_ref(VId(1));
    let releases: Vec<_> = [b"capacity-release-one".as_slice(), b"capacity-release-two"]
        .into_iter()
        .enumerate()
        .map(|(index, key)| {
            (
                VId(index as u128 + 2),
                fixture.release(target, key).seal(Vec::new(), None).unwrap(),
            )
        })
        .collect();
    let mut reads = 0;
    assert!(
        cells
            .absorb(&releases, |vid| {
                assert_eq!(vid, target.vid);
                reads += 1;
                Ok(Some(hold.clone()))
            })
            .unwrap()
    );
    assert_eq!(reads, 1, "a release target is subtracted only once");
    assert_eq!(cells.columns, expected_columns);
    assert_eq!(cells.pending_counts, expected_counts);
    assert!(
        cells
            .absorb(&releases, |_| {
                panic!("an already released hold must never be subtracted again")
            })
            .unwrap()
    );
    assert_eq!(cells.columns, expected_columns);
    assert_eq!(cells.pending_counts, expected_counts);
}
