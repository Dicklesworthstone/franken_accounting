//! The schedule-only capacity overlay against the unchanged literal checker.
//! Native staging tests exercise real stored entry payloads; the large work
//! fixture isolates this disposable cache, not whole-transaction throughput.

use super::*;
use crate::batch::tests::{make_entry_intent, setup_batch_test_book};
use crate::genesis::BookContext;
use crate::migration;
use fa_model::symbols::relation;
use fa_model::{ScheduleTrigger, Supersession, SupersessionKind};
use fa_money::Amount;
use fgdb::{MemVfs, WriteBatch};
use std::cell::Cell;

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

    fn entry(&self, number: usize, amount: i128, reversal: bool) -> Entry {
        let key = format!("scheduled-capacity-{number}");
        let mut proposal = make_entry_intent(
            &self.book,
            self.usd,
            self.cash,
            self.rent,
            &self.evidence,
            1,
            key.as_bytes(),
        )
        .proposal()
        .clone();
        for leg in &mut proposal.legs {
            leg.amount = Amount::new(self.usd, amount);
        }
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        if reversal {
            let original = proposal.clone().seal(Vec::new(), None).unwrap();
            proposal.class = EntryClass::REVERSAL;
            proposal.origin = EntryOrigin::Schedule {
                schedule_ref: VId(20_000 + number as u128),
                trigger: ScheduleTrigger::Sweep { tick_ref: VId(9) },
            };
            proposal.supersession = vec![Supersession {
                target: original.entry_ref(VId(30_000 + number as u128)),
                kind: SupersessionKind::Reverses,
                reason_code: fa_registry::reason_codes::SCHEDULED_ACCRUAL_REVERSAL,
            }];
            for leg in &mut proposal.legs {
                leg.side = leg.side.flipped();
            }
            proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        }
        proposal.seal(Vec::new(), None).unwrap()
    }

    fn commit_entry(&mut self, vid: VId, entry: &Entry) {
        let ctx = self.cx();
        let batch = entry_batch(&ctx, vid, entry);
        self.runtime
            .block_on(self.db.write(&ctx.commit(), batch))
            .unwrap();
    }

    fn hidden_migration(&mut self, amount: i128) -> VId {
        // Open through the real migration API so the summary must decode an
        // authentic native run body. As with the other capacity fixtures,
        // the chunk uses native entry storage; migration admission itself
        // remains covered by the migration integration tests.
        let body = migration::RunBody {
            book_id: self.book.book_id,
            run_key: "scheduled-capacity-import".into(),
            source_system: "legacy-scheduled-capacity".into(),
            mode: migration::RunMode::OpeningOnly,
            trial_balance: self.evidence[0].document_oid,
            opening_date: fa_time::DateDay::from_ymd(2026, 1, 1).unwrap(),
            lines: vec![
                migration::TrialBalanceLine {
                    account_code: "1000".into(),
                    unit: self.usd,
                    mantissa: amount,
                },
                migration::TrialBalanceLine {
                    account_code: "6000".into(),
                    unit: self.usd,
                    mantissa: amount.checked_neg().unwrap(),
                },
            ],
            periods: Vec::new(),
            detail_base: Vec::new(),
            sole_opening_source: false,
        };
        let mut chunk = self.entry(90, amount, true).proposal;
        let proposal = migration::open_proposal(
            &self.book,
            VId(7),
            &body,
            self.evidence.clone(),
            b"open-scheduled-capacity-import",
            chunk.description.clone(),
        )
        .unwrap();
        let ctx = self.cx();
        let run = self
            .runtime
            .block_on(migration::open_run(
                &mut self.db,
                &ctx,
                &self.book,
                &body,
                migration::RunControlRequest {
                    proposal,
                    capability: fa_policy::Capability::embedded(VId(7), &["migrate"]).unwrap(),
                    approvals: Vec::new(),
                },
            ))
            .unwrap()
            .unwrap()
            .run;
        chunk.class = EntryClass::MIGRATION;
        chunk.effective_date = body.opening_date;
        chunk.effective_period = Some(fa_model::PeriodRef {
            calendar: self.book.calendar.id.clone(),
            code: self
                .book
                .calendar
                .periods_for_year(2026)
                .unwrap()
                .into_iter()
                .find(|period| period.kind == fa_time::PeriodKind::Opening)
                .unwrap()
                .code,
        });
        chunk.origin = EntryOrigin::Migration {
            run_ref: run,
            source_system: body.source_system,
            source_id: chunk.description.clone(),
            source_recorded_at_ns: None,
            source_entered_by: None,
            source_approved_by: None,
            batch_oid: body.trial_balance,
        };
        chunk.supersession.clear();
        self.commit_entry(VId(40_090), &chunk.seal(Vec::new(), None).unwrap());
        run
    }
}

fn entry_batch(ctx: &PurposeContexts, vid: VId, entry: &Entry) -> WriteBatch {
    let mut batch = WriteBatch::new(relation::IN_PERIOD);
    batch.create_vertex(
        vid,
        vec![label::ENTRY],
        crate::entry_storage::stored_mirrors(entry).unwrap(),
    );
    crate::entry_storage::stage(&ctx.query(), &mut batch, entry, vid).unwrap();
    batch
}

#[test]
fn scheduled_capacity_matches_literal_for_each_native_staged_prefix() {
    let mut fixture = Fixture::new();
    let seed = fixture.entry(0, 13, false);
    fixture.commit_entry(VId(40_000), &seed);
    let ctx = fixture.cx();
    let basis = fixture.db.frontier().unwrap();
    let mut txn = fixture.db.begin(&ctx.txn()).unwrap();
    let mut capacity = ScheduledReversalCapacity::default();
    let mut accepted = Vec::new();
    let mut accepted_amount = 0i128;
    for number in 1..=8 {
        let amount = i128::try_from(number).unwrap();
        let entry = fixture.entry(number, amount, true);
        let vid = VId(50_000 + number as u128);
        let literal = admit_addition(
            &txn,
            &fixture.db,
            &ctx,
            accepted.iter().copied(),
            vid,
            &entry,
        )
        .unwrap();
        let prepared = capacity
            .prepare(
                &txn,
                &fixture.db,
                &ctx,
                accepted.iter().copied(),
                vid,
                &entry,
            )
            .unwrap();
        assert_eq!(prepared.as_ref().map(|_| ()), literal.as_ref().map(|_| ()));
        let prepared = prepared.unwrap();
        assert!(prepared.from_summary);
        if number % 2 == 0 {
            txn.write_ordered(&mut fixture.db, vec![entry_batch(&ctx, vid, &entry)])
                .unwrap();
            capacity.accept(prepared);
            accepted.push(vid);
            accepted_amount = accepted_amount.checked_add(amount).unwrap();
        }
    }
    let cells = capacity.cells.as_ref().unwrap();
    for functional in [false, true] {
        assert_eq!(
            cells.columns[&(fixture.cash, fixture.usd, functional)],
            [accepted_amount, 13, 0, 0],
        );
        assert_eq!(
            cells.columns[&(fixture.rent, fixture.usd, functional)],
            [13, accepted_amount, 0, 0],
        );
    }
    assert_eq!(capacity.work.summary_builds, 1);
    assert_eq!(capacity.work.summary_checks, 8);
    assert_eq!(capacity.work.accepted_folds, 4);
    assert_eq!(capacity.work.literal_fallbacks, 0);
    txn.abort();
    assert_eq!(fixture.db.frontier().unwrap(), basis);
}

#[test]
fn scheduled_capacity_refuses_cumulative_native_and_functional_overflow_exactly() {
    for functional_only in [false, true] {
        let mut fixture = Fixture::new();
        let mut seed = fixture
            .entry(0, maximum().unwrap().checked_sub(2).unwrap(), true)
            .proposal;
        let eur = fixture.book.units.lookup("EUR").unwrap();
        if functional_only {
            // This component test supplies the already-admitted valuation
            // vector; the existing scheduled-admission tests own FX authority.
            for leg in &mut seed.legs {
                leg.base_amount = Some(leg.amount);
                leg.amount = Amount::new(eur, 1);
            }
            seed.unit_totals = EntryPayload::fold_unit_totals(&seed.legs).unwrap();
        }
        let seed = seed.seal(Vec::new(), None).unwrap();
        fixture.commit_entry(VId(40_001), &seed);
        let ctx = fixture.cx();
        let mut txn = fixture.db.begin(&ctx.txn()).unwrap();
        let mut capacity = ScheduledReversalCapacity::default();
        let mut accepted = Vec::new();
        for (number, amount) in [(1, 1), (2, 2)] {
            let mut proposal = fixture.entry(number, amount, true).proposal;
            if functional_only {
                for leg in &mut proposal.legs {
                    leg.base_amount = Some(leg.amount);
                    leg.amount = Amount::new(eur, 1);
                }
                proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
            }
            let entry = proposal.seal(Vec::new(), None).unwrap();
            let vid = VId(51_000 + number as u128);
            // Each candidate alone fits the committed prefix. The accepted
            // first candidate must be present when the second is judged.
            assert!(
                admit_addition(&txn, &fixture.db, &ctx, [], vid, &entry)
                    .unwrap()
                    .is_ok()
            );
            let literal = admit_addition(
                &txn,
                &fixture.db,
                &ctx,
                accepted.iter().copied(),
                vid,
                &entry,
            )
            .unwrap();
            let staged_reads = Cell::new(0usize);
            let prepared = capacity
                .prepare(
                    &txn,
                    &fixture.db,
                    &ctx,
                    accepted.iter().copied().inspect(|_| {
                        staged_reads.set(staged_reads.get() + 1);
                    }),
                    vid,
                    &entry,
                )
                .unwrap();
            assert_eq!(prepared.as_ref().map(|_| ()), literal.as_ref().map(|_| ()));
            assert_eq!(
                staged_reads.get(),
                if number == 1 { 0 } else { accepted.len() }
            );
            if number == 1 {
                txn.write_ordered(&mut fixture.db, vec![entry_batch(&ctx, vid, &entry)])
                    .unwrap();
                capacity.accept(prepared.unwrap());
                accepted.push(vid);
            } else {
                let refusal = prepared.unwrap_err();
                assert_eq!(refusal.code, code::REGISTER_CAPACITY);
                assert_eq!(
                    refusal.message.contains("functional stock"),
                    functional_only
                );
            }
        }
        assert_eq!(capacity.work.summary_builds, 1);
        assert_eq!(capacity.work.accepted_folds, 1);
        assert_eq!(capacity.work.literal_fallbacks, 1);
        txn.abort();
    }
}

#[test]
fn scheduled_capacity_discards_blocked_and_budget_stopped_candidates() {
    let mut fixture = Fixture::new();
    let seed = fixture.entry(0, maximum().unwrap().checked_sub(4).unwrap(), true);
    fixture.commit_entry(VId(40_002), &seed);
    let ctx = fixture.cx();
    let mut txn = fixture.db.begin(&ctx.txn()).unwrap();
    let mut capacity = ScheduledReversalCapacity::default();
    for (number, why) in [(1, "availability blocked"), (2, "byte budget stopped")] {
        let entry = fixture.entry(number, 3, true);
        {
            let prepared = capacity
                .prepare(
                    &txn,
                    &fixture.db,
                    &ctx,
                    [],
                    VId(52_000 + number as u128),
                    &entry,
                )
                .unwrap()
                .unwrap();
            assert!(prepared.from_summary, "{why}");
        }
        assert_eq!(capacity.work.accepted_folds, 0);
    }
    // The entire four-unit capacity remains available after both discards.
    let entry = fixture.entry(3, 4, true);
    let vid = VId(52_003);
    let prepared = capacity
        .prepare(&txn, &fixture.db, &ctx, [], vid, &entry)
        .unwrap()
        .unwrap();
    assert!(
        admit_addition(&txn, &fixture.db, &ctx, [], vid, &entry)
            .unwrap()
            .is_ok()
    );
    txn.write_ordered(&mut fixture.db, vec![entry_batch(&ctx, vid, &entry)])
        .unwrap();
    capacity.accept(prepared);
    assert_eq!(
        capacity.cells.as_ref().unwrap().columns[&(fixture.cash, fixture.usd, false)][0],
        maximum().unwrap(),
    );
    assert_eq!(capacity.work.summary_builds, 1);
    assert_eq!(capacity.work.accepted_folds, 1);
    txn.abort();
}

#[test]
fn scheduled_capacity_keeps_corruption_and_unsupported_effects_on_the_literal_path() {
    let mut fixture = Fixture::new();
    let ctx = fixture.cx();
    let mut txn = fixture.db.begin(&ctx.txn()).unwrap();
    let mut capacity = ScheduledReversalCapacity::default();
    let reversal = fixture.entry(1, 1, true);
    {
        let first = capacity
            .prepare(&txn, &fixture.db, &ctx, [], VId(53_001), &reversal)
            .unwrap()
            .unwrap();
        assert!(first.from_summary);
    }
    let original = fixture.entry(2, 7, false);
    let vid = VId(53_002);
    let prepared = capacity
        .prepare(&txn, &fixture.db, &ctx, [], vid, &original)
        .unwrap()
        .unwrap();
    assert!(!prepared.from_summary);
    txn.write_ordered(&mut fixture.db, vec![entry_batch(&ctx, vid, &original)])
        .unwrap();
    capacity.accept(prepared);
    assert!(capacity.cells.is_none());
    {
        let next = capacity
            .prepare(&txn, &fixture.db, &ctx, [vid], VId(53_003), &reversal)
            .unwrap()
            .unwrap();
        assert!(!next.from_summary);
    }
    assert_eq!(
        capacity.work.summary_builds, 1,
        "never omit accepted effects by rebuilding"
    );
    txn.abort();

    let mut corrupt = entry_batch(&ctx, VId(40_003), &original);
    corrupt.set_vertex_property(
        VId(40_003),
        property::FA_PAYLOAD,
        Some(crate::rows::scalar_bytes("corrupt entry", vec![0]).unwrap()),
    );
    fixture
        .runtime
        .block_on(fixture.db.write(&ctx.commit(), corrupt))
        .unwrap();
    let txn = fixture.db.begin(&ctx.txn()).unwrap();
    let mut capacity = ScheduledReversalCapacity::default();
    for vid in [VId(54_001), VId(54_002)] {
        let literal = admit_addition(&txn, &fixture.db, &ctx, [], vid, &reversal)
            .unwrap_err()
            .to_string();
        let actual = capacity
            .prepare(&txn, &fixture.db, &ctx, [], vid, &reversal)
            .unwrap_err()
            .to_string();
        assert_eq!(actual, literal);
    }
    assert_eq!(capacity.work.summary_builds, 1);
    assert_eq!(capacity.work.literal_fallbacks, 2);
    txn.abort();
}

#[test]
fn scheduled_capacity_invalidates_after_an_accepted_reversal_and_staged_run_change() {
    let mut fixture = Fixture::new();
    let run = fixture.hidden_migration(maximum().unwrap().checked_sub(2).unwrap());
    let ctx = fixture.cx();
    let mut txn = fixture.db.begin(&ctx.txn()).unwrap();
    let mut capacity = ScheduledReversalCapacity::default();
    let mut accepted = Vec::new();
    let first = fixture.entry(1, 1, true);
    let first_vid = VId(58_001);
    let prepared = capacity
        .prepare(&txn, &fixture.db, &ctx, [], first_vid, &first)
        .unwrap()
        .unwrap();
    assert!(prepared.from_summary, "the Open run's chunk is hidden");
    txn.write_ordered(&mut fixture.db, vec![entry_batch(&ctx, first_vid, &first)])
        .unwrap();
    capacity.accept(prepared);
    accepted.push(first_vid);
    assert_eq!(capacity.cells.as_ref().unwrap().migration_runs.len(), 1);

    let next = fixture.entry(2, 1, true);
    let next_vid = VId(58_002);
    let staged_reads = Cell::new(0usize);
    {
        let prepared = capacity
            .prepare(
                &txn,
                &fixture.db,
                &ctx,
                accepted.iter().copied().inspect(|_| {
                    staged_reads.set(staged_reads.get() + 1);
                }),
                next_vid,
                &next,
            )
            .unwrap()
            .unwrap();
        assert!(prepared.from_summary);
        assert_eq!(
            staged_reads.get(),
            0,
            "accepted IDs are not read on a proof"
        );
    }
    // Inject the native staged state projection that changes visibility.
    // This is the invalidation boundary, not a second migration-finalization
    // implementation: the literal checker remains the authority below.
    let mut state_change = WriteBatch::new(relation::IN_MIGRATION_RUN);
    state_change.set_vertex_property(
        run,
        property::STATE,
        Some(migration::RunState::Finalized.scalar()),
    );
    txn.write_ordered(&mut fixture.db, vec![state_change])
        .unwrap();
    let literal = admit_addition(
        &txn,
        &fixture.db,
        &ctx,
        accepted.iter().copied(),
        next_vid,
        &next,
    )
    .unwrap();
    let prepared = capacity
        .prepare(
            &txn,
            &fixture.db,
            &ctx,
            accepted.iter().copied().inspect(|_| {
                staged_reads.set(staged_reads.get() + 1);
            }),
            next_vid,
            &next,
        )
        .unwrap();
    assert_eq!(prepared.as_ref().map(|_| ()), literal.as_ref().map(|_| ()));
    assert!(
        literal.is_ok(),
        "the imported chunk plus both reversals fit exactly"
    );
    let prepared = prepared.unwrap();
    assert!(
        !prepared.from_summary,
        "the staged run state invalidates the proof"
    );
    assert_eq!(staged_reads.get(), accepted.len());
    txn.write_ordered(&mut fixture.db, vec![entry_batch(&ctx, next_vid, &next)])
        .unwrap();
    capacity.accept(prepared);
    accepted.push(next_vid);
    assert!(
        capacity.cells.is_none(),
        "an accepted fallback disables the cache"
    );

    let over = fixture.entry(3, 1, true);
    let over_vid = VId(58_003);
    let literal = admit_addition(
        &txn,
        &fixture.db,
        &ctx,
        accepted.iter().copied(),
        over_vid,
        &over,
    )
    .unwrap()
    .unwrap_err();
    staged_reads.set(0);
    let refusal = capacity
        .prepare(
            &txn,
            &fixture.db,
            &ctx,
            accepted.iter().copied().inspect(|_| {
                staged_reads.set(staged_reads.get() + 1);
            }),
            over_vid,
            &over,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal, literal);
    assert_eq!(refusal.code, code::REGISTER_CAPACITY);
    assert_eq!(staged_reads.get(), accepted.len());
    assert_eq!(capacity.work.summary_builds, 1);
    assert_eq!(capacity.work.summary_checks, 3);
    assert_eq!(capacity.work.accepted_folds, 1);
    assert_eq!(capacity.work.literal_fallbacks, 2);
    txn.abort();
}

#[test]
fn scheduled_capacity_preserves_affected_migration_run_witnesses() {
    for affected in [false, true] {
        let mut fixture = Fixture::new();
        let run = fixture.hidden_migration(10);
        let ctx = fixture.cx();
        let mut txn = fixture.db.begin(&ctx.txn()).unwrap();
        let mut capacity = ScheduledReversalCapacity::default();
        let entry = fixture.entry(1, 1, true);
        let vid = VId(59_001);
        let prepared = capacity
            .prepare(&txn, &fixture.db, &ctx, [], vid, &entry)
            .unwrap()
            .unwrap();
        assert!(prepared.from_summary);
        txn.write_ordered(&mut fixture.db, vec![entry_batch(&ctx, vid, &entry)])
            .unwrap();
        capacity.accept(prepared);

        let mut winner = WriteBatch::new(relation::IN_MIGRATION_RUN);
        if affected {
            winner.set_vertex_property(
                run,
                property::STATE,
                Some(migration::RunState::Abandoned.scalar()),
            );
        } else {
            winner.create_vertex(VId(59_999), vec![], vec![]);
        }
        fixture
            .runtime
            .block_on(fixture.db.write(&ctx.commit(), winner))
            .unwrap();
        let outcome = fixture
            .runtime
            .block_on(txn.commit(&mut fixture.db, &ctx.commit()));
        if affected {
            assert!(matches!(
                outcome,
                Err(WriteTxnError::Write(
                    fgdb::WriteError::FirstCommitterWins { .. }
                ))
            ));
            assert!(fixture.db.vertex(vid).unwrap().is_none());
        } else {
            outcome.expect("a run point witness does not witness every vertex");
            assert!(fixture.db.vertex(vid).unwrap().is_some());
        }
    }
}

#[test]
fn scheduled_capacity_preserves_account_witnesses_without_a_table_witness() {
    for affected in [false, true] {
        let mut fixture = Fixture::new();
        let ctx = fixture.cx();
        let mut txn = fixture.db.begin(&ctx.txn()).unwrap();
        let mut capacity = ScheduledReversalCapacity::default();
        let entry = fixture.entry(1, 1, true);
        let vid = VId(55_001);
        let prepared = capacity
            .prepare(&txn, &fixture.db, &ctx, [], vid, &entry)
            .unwrap()
            .unwrap();
        assert!(prepared.from_summary);
        txn.write_ordered(&mut fixture.db, vec![entry_batch(&ctx, vid, &entry)])
            .unwrap();
        capacity.accept(prepared);
        let mut winner = WriteBatch::new(relation::IN_BOOK);
        if affected {
            winner.set_vertex_property(
                fixture.cash,
                property::NORMAL_BALANCE,
                Some(fgdb_types::CanonicalScalar::Int(1)),
            );
        } else {
            winner.create_vertex(VId(55_999), vec![], vec![]);
        }
        fixture
            .runtime
            .block_on(fixture.db.write(&ctx.commit(), winner))
            .unwrap();
        let outcome = fixture
            .runtime
            .block_on(txn.commit(&mut fixture.db, &ctx.commit()));
        if affected {
            assert!(matches!(
                outcome,
                Err(WriteTxnError::Write(
                    fgdb::WriteError::FirstCommitterWins { .. }
                ))
            ));
            assert!(fixture.db.vertex(vid).unwrap().is_none());
        } else {
            outcome.expect("an unrelated insertion is not a full-table conflict");
            assert!(fixture.db.vertex(vid).unwrap().is_some());
        }
    }
}

#[test]
fn scheduled_capacity_never_rebuilds_accepted_effects_at_a_different_basis() {
    let mut fixture = Fixture::new();
    let ctx = fixture.cx();
    let mut txn = fixture.db.begin(&ctx.txn()).unwrap();
    let mut capacity = ScheduledReversalCapacity::default();
    let entry = fixture.entry(1, 1, true);
    let prepared = capacity
        .prepare(&txn, &fixture.db, &ctx, [], VId(56_001), &entry)
        .unwrap()
        .unwrap();
    txn.write_ordered(
        &mut fixture.db,
        vec![entry_batch(&ctx, VId(56_001), &entry)],
    )
    .unwrap();
    capacity.accept(prepared);
    txn.abort();
    let seed = fixture.entry(2, 1, false);
    fixture.commit_entry(VId(56_002), &seed);
    let txn = fixture.db.begin(&ctx.txn()).unwrap();
    let next = fixture.entry(3, 1, true);
    let prepared = capacity
        .prepare(&txn, &fixture.db, &ctx, [], VId(56_003), &next)
        .unwrap()
        .unwrap();
    assert!(!prepared.from_summary);
    assert!(capacity.cells.is_none());
    assert_eq!(capacity.work.summary_builds, 1);
    assert_eq!(capacity.work.literal_fallbacks, 1);
    txn.abort();
}

#[test]
fn scheduled_capacity_checks_cancellation_before_initializing_history() {
    let mut fixture = Fixture::new();
    let entry = fixture.entry(1, 1, true);
    let ctx = fixture.cx();
    let txn = fixture.db.begin(&ctx.txn()).unwrap();
    fixture
        .root
        .cancel_fast(asupersync::types::CancelKind::User);
    let mut capacity = ScheduledReversalCapacity::default();
    let result = capacity.prepare(&txn, &fixture.db, &ctx, [], VId(57_001), &entry);
    assert!(matches!(
        result,
        Err(KernelError::Txn(WriteTxnError::Interrupted(_)))
    ));
    assert_eq!(capacity.work, ScheduledCapacityWork::default());
    txn.abort();
}

#[test]
fn scheduled_capacity_work_does_not_revisit_a_growing_accepted_prefix() {
    // Isolate the capacity cache from fa-wo2n's native staging cost. The
    // preceding tests prove native accepted-prefix equivalence. This work
    // fixture applies 100,000 accepted proofs to the cache without claiming
    // to admit or publish a native transaction larger than its registered cap.
    const CANDIDATES: usize = 100_000;
    let mut fixture = Fixture::new();
    let ctx = fixture.cx();
    let txn = fixture.db.begin(&ctx.txn()).unwrap();
    let mut capacity = ScheduledReversalCapacity::default();
    let visited = std::cell::Cell::new(0usize);
    for number in 0..CANDIDATES {
        let entry = fixture.entry(number, 1, true);
        let staged = std::iter::repeat_n(VId(1), number).inspect(|_| {
            visited.set(visited.get() + 1);
        });
        let prepared = capacity
            .prepare(
                &txn,
                &fixture.db,
                &ctx,
                staged,
                VId(100_000 + number as u128),
                &entry,
            )
            .unwrap()
            .unwrap();
        assert!(prepared.from_summary);
        capacity.accept(prepared);
    }
    assert_eq!(visited.get(), 0, "no accepted entry ID was revisited");
    assert_eq!(capacity.work.summary_builds, 1);
    assert_eq!(capacity.work.summary_checks, CANDIDATES);
    assert_eq!(capacity.work.accepted_folds, CANDIDATES);
    assert_eq!(capacity.work.accepted_legs, 2 * CANDIDATES);
    assert_eq!(capacity.work.literal_fallbacks, 0);
    assert_eq!(
        capacity.cells.as_ref().unwrap().columns[&(fixture.cash, fixture.usd, false)][0],
        i128::try_from(CANDIDATES).unwrap(),
    );
    eprintln!(
        "scheduled capacity: {:?}; accepted IDs revisited={}",
        capacity.work,
        visited.get()
    );
    txn.abort();
}
