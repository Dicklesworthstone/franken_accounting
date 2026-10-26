//! The reference differential (plan §16.2, bead fa-d93): one seeded history
//! of posts, reversals, retries, and period transitions is applied to the
//! real kernel on the substrate and to the naive oracle; every verdict and
//! every register cell must agree. The oracle has its own arithmetic and its
//! own copy of the refusal codes, so agreement is evidence about the kernel,
//! not an echo.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::evidence::{Document, add_document};
use fa_journal::*;
use fa_model::{
    ControlPayload, Disposition, EntryClass, EntryOrigin, EntryPayload, EntryRef, Erasable,
    EvidenceRef, Id128, LegPayload, Oid, Pending, PeriodRef, SealKey, Settlement, Supersession,
    SupersessionKind, SymbolTable, account_vid, dimension_vid, entity_value_vid, legal_entity_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_reference::{
    Account, Cell, DimensionTag, DimensionValue, DraftVerdict, Int, Intent, Leg, Limit, Oracle,
    Resolve, Settle, Verdict,
};
use fa_registers::{
    EntityCellKey, RegisterEquals, TrialBalance, balance_as_of, check_register_equals,
    explain_balance, fold_period, fold_period_by_entity, open_items, period_activity,
    register_equals, trial_balance, trial_balance_at, verify_availability, verify_entities,
    verify_open_items,
};
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodState, PeriodTransition};
use fgdb::{Database, DatabaseKeys, MemVfs, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CommitSeq, VId};

const PRINCIPAL: VId = VId(7);

fn maintain(k: &mut Kernel, period: &str) -> fa_registers::Advance {
    let ctx = k.ctx();
    let result = k
        .runtime
        .block_on(fa_registers::advance(&mut k.db, &ctx, &k.book, period))
        .expect("advance registers");
    assert_eq!(result.fold, fold_period(&k.db, &k.book, period).unwrap());
    assert!(
        fa_registers::verify_period(&k.db, &k.book, period)
            .unwrap()
            .is_green()
    );
    result
}

fn maintenance_intent(class: &str, date: DateDay, amount: i128, key: &str) -> Intent {
    let unit = UnitRegistry::with_defaults().lookup("USD").unwrap().0;
    Intent {
        class: class.into(),
        date,
        discriminator: None,
        legs: if amount == 0 {
            Vec::new()
        } else {
            vec![
                Leg {
                    side: fa_reference::Side::Debit,
                    account: "6000".into(),
                    unit,
                    entity: None,
                    mantissa: amount,
                },
                Leg {
                    side: fa_reference::Side::Credit,
                    account: "1000".into(),
                    unit,
                    entity: None,
                    mantissa: amount,
                },
            ]
        },
        key: key.as_bytes().to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    }
}

fn maintained_matches_oracle(maintained: &fa_registers::Advance, oracle: &Oracle, book: Id128) {
    for (cells, expected) in [
        (&maintained.fold.cells, oracle.fold(&maintained.period)),
        (
            &maintained.fold.pending,
            oracle.pending_fold(&maintained.period),
        ),
    ] {
        assert_eq!(cells.len(), expected.len());
        for ((code, unit), expected) in expected {
            let cell = cells
                .iter()
                .find(|cell| {
                    cell.key.account == account_vid(book, &code) && cell.key.unit_id == unit
                })
                .expect("oracle cell exists in maintained result");
            assert_eq!(
                (cell.debits, cell.credits, cell.entry_count),
                (
                    expected.debits.to_i128().unwrap(),
                    expected.credits.to_i128().unwrap(),
                    expected.entry_count
                )
            );
        }
    }
}

fn correction_outcome(
    kernel: &mut Kernel,
    oracle: &mut Oracle,
    refs: &mut Vec<EntryRef>,
    intent: &Intent,
    expected: Result<&str, &'static str>,
) -> Option<usize> {
    let usd = kernel.book.units.lookup("USD").unwrap();
    let head = kernel.db.frontier().unwrap();
    let actual = kernel_post(kernel, intent, usd, refs);
    let reference = oracle.post(intent);
    match expected {
        Ok(period) => {
            let index = refs.len();
            assert_eq!(
                reference,
                Verdict::Posted {
                    index,
                    period: period.into()
                },
                "{intent:?}"
            );
            let posted = actual.expect("kernel admits the specified lawful correction");
            assert_eq!(posted.period(), Some(period));
            refs.push(posted.entry_ref());
            Some(index)
        }
        Err(code) => {
            assert_eq!(reference, Verdict::Refused { code }, "{intent:?}");
            assert_eq!(actual.unwrap_err().code, code, "{intent:?}");
            assert_eq!(kernel.db.frontier().unwrap(), head, "refusal wrote nothing");
            None
        }
    }
}

/// One Reclassification of `refs[target]` on both engines (fa-xvba): the
/// kernel receives the intent with a `Reclassifies` supersession, the oracle
/// [`Oracle::reclassify`]; both give `expected`, and a refusal writes nothing.
fn reclass_outcome(
    kernel: &mut Kernel,
    oracle: &mut Oracle,
    refs: &mut Vec<EntryRef>,
    intent: &Intent,
    target: usize,
    expected: Result<&str, &'static str>,
) -> Option<usize> {
    let usd = kernel.book.units.lookup("USD").unwrap();
    let head = kernel.db.frontier().unwrap();
    let mut req = kernel_request(kernel, intent, usd, refs);
    req.proposal.supersession = vec![Supersession {
        target: refs[target],
        kind: SupersessionKind::Reclassifies,
        reason_code: intent.supersession_reason,
    }];
    let ctx = kernel.ctx();
    let db = &mut kernel.db;
    let book = &kernel.book;
    let actual = kernel
        .runtime
        .block_on(async move { post(db, &ctx, book, req).await })
        .expect("kernel");
    let reference = oracle.reclassify(intent, target);
    match expected {
        Ok(period) => {
            let index = refs.len();
            assert_eq!(
                reference,
                Verdict::Posted {
                    index,
                    period: period.into()
                },
                "{intent:?}"
            );
            let posted = actual.expect("kernel admits the reclassification");
            assert_eq!(posted.period(), Some(period));
            refs.push(posted.entry_ref());
            Some(index)
        }
        Err(code) => {
            assert_eq!(reference, Verdict::Refused { code }, "{intent:?}");
            assert_eq!(actual.unwrap_err().code, code, "{intent:?}");
            assert_eq!(kernel.db.frontier().unwrap(), head, "refusal wrote nothing");
            None
        }
    }
}

/// fa-xvba (plan §8.2 Reclassifies): the kernel and the independent oracle
/// agree on every reclassification of one entry: partial moves bounded by
/// what earlier live ones left, a move back where it came from, an
/// unregistered reason, a reversed reclassification giving its amount back,
/// and the Closed period's post_closed and approval; their folds agree.
#[test]
fn reclass_agrees_with_reference() {
    let (mut kernel, mut oracle, _) = setup();
    open_period(&mut kernel, &mut oracle, "FY2026-P04", 0);
    let mut refs = Vec::new();
    let day = DateDay::parse("2026-04-15").unwrap();
    let original = maintenance_intent("Original", day, 1_000, "rc-original");
    let target = correction_outcome(
        &mut kernel,
        &mut oracle,
        &mut refs,
        &original,
        Ok("FY2026-P04"),
    )
    .unwrap();
    let unit = UnitRegistry::with_defaults().lookup("USD").unwrap().0;
    let leg = |side, account: &str, mantissa| Leg {
        side,
        account: account.into(),
        unit,
        entity: None,
        mantissa,
    };
    let mv = |amount: i128, key: &str, to: &str| {
        let mut intent = maintenance_intent("Reclassification", day, 0, key);
        intent.legs = vec![
            leg(fa_reference::Side::Credit, "6000", amount),
            leg(fa_reference::Side::Debit, to, amount),
        ];
        intent
    };
    let (k, o, r) = (&mut kernel, &mut oracle, &mut refs);
    let first = reclass_outcome(
        k,
        o,
        r,
        &mv(300, "rc-300", "1200"),
        target,
        Ok("FY2026-P04"),
    )
    .unwrap();
    reclass_outcome(
        k,
        o,
        r,
        &mv(800, "rc-800", "1200"),
        target,
        Err("FA-REF-185"),
    );
    reclass_outcome(
        k,
        o,
        r,
        &mv(100, "rc-back", "6000"),
        target,
        Err("FA-REF-185"),
    );
    let mut unreasoned = mv(100, "rc-zero", "1200");
    unreasoned.supersession_reason = 0;
    reclass_outcome(k, o, r, &unreasoned, target, Err("FA-REF-054"));
    // Reversing the first reclassification gives its 300 back.
    let mut undo = mv(300, "rc-undo", "1200");
    undo.class = "Reversal".into();
    undo.reverses = Some(first);
    for l in &mut undo.legs {
        l.side = l.side.flipped();
    }
    correction_outcome(k, o, r, &undo, Ok("FY2026-P04"));
    reclass_outcome(
        k,
        o,
        r,
        &mv(1_000, "rc-all", "1200"),
        target,
        Ok("FY2026-P04"),
    );
    reclass_outcome(k, o, r, &mv(1, "rc-1", "1200"), target, Err("FA-REF-185"));
    let maintained = maintain(&mut kernel, "FY2026-P04");
    maintained_matches_oracle(&maintained, &oracle, kernel.book.book_id);

    // A Closed period admits a reclassification only under post_closed with
    // one approval, in both engines.
    let other = maintenance_intent("Original", day, 50, "rc-other");
    let other = correction_outcome(
        &mut kernel,
        &mut oracle,
        &mut refs,
        &other,
        Ok("FY2026-P04"),
    )
    .unwrap();
    let closed = kernel_transition(&mut kernel, "FY2026-P04", PeriodTransition::Close, 1)
        .expect("close the real period");
    let expected = oracle
        .transition("FY2026-P04", PeriodTransition::Close)
        .expect("close the oracle period");
    assert_eq!((closed.from, closed.to), expected);
    let (k, o, r) = (&mut kernel, &mut oracle, &mut refs);
    reclass_outcome(
        k,
        o,
        r,
        &mv(10, "rc-closed", "1200"),
        other,
        Err("FA-REF-011"),
    );
    let mut granted = mv(10, "rc-closed", "1200");
    granted.ops.push("post_closed".into());
    reclass_outcome(k, o, r, &granted, other, Err("FA-REF-012"));
}

#[test]
fn correction_period_order_and_reasons_match_independent_oracle_across_seeds() {
    for seed in [7, 0x529a_4571, 0x9812_73bb] {
        let (mut kernel, mut oracle, _) = setup();
        let mut rng = Rng(seed);
        for (step, period) in [
            "FY2026-OPEN",
            "FY2026-P01",
            "FY2026-P03",
            "FY2026-P04",
            "FY2026-P05",
            "FY2026-P12",
            "FY2026-A1",
        ]
        .into_iter()
        .enumerate()
        {
            open_period(&mut kernel, &mut oracle, period, step as u64);
        }
        let ctx = kernel.ctx();
        kernel
            .runtime
            .block_on(create_periods(
                &mut kernel.db,
                &ctx,
                &kernel.book,
                2027,
                fgdb_types::VId(1),
                fa_model::Erasable::seal(
                    &"periods".to_string(),
                    None,
                    &kernel.book.seal_key,
                    [1; 32],
                    [2; 24],
                ),
                &fa_journal::Capability::embedded(fgdb_types::VId(1), &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        oracle.create_periods(2027);
        open_period(&mut kernel, &mut oracle, "FY2027-P01", 8);
        let mut refs = Vec::new();
        for n in 0..6 {
            let amount = i128::from(rng.below(1_000_000)) + 1;
            let original = maintenance_intent(
                "Original",
                DateDay::parse("2026-04-15").unwrap(),
                amount,
                &format!("order-original-{n}"),
            );
            let target = correction_outcome(
                &mut kernel,
                &mut oracle,
                &mut refs,
                &original,
                Ok("FY2026-P04"),
            )
            .unwrap();
            let mut reversal = original.clone();
            reversal.class = "Reversal".into();
            reversal.key = format!("order-reversal-{n}").into_bytes();
            reversal.reverses = Some(target);
            reversal.supersession_reason = if n % 2 == 0 { 2 } else { 4 };
            for leg in &mut reversal.legs {
                leg.side = leg.side.flipped();
            }
            reversal.date = DateDay::parse("2026-03-31").unwrap();
            correction_outcome(
                &mut kernel,
                &mut oracle,
                &mut refs,
                &reversal,
                Err("FA-REF-053"),
            );
            let chosen_reason = reversal.supersession_reason;
            // 12 (ScheduledAccrualReversal) is reserved for the scheduler (fa-cvg).
            for invalid_reason in [0, 12, u16::MAX] {
                reversal.supersession_reason = invalid_reason;
                correction_outcome(
                    &mut kernel,
                    &mut oracle,
                    &mut refs,
                    &reversal,
                    Err("FA-REF-054"),
                );
            }
            reversal.supersession_reason = chosen_reason;
            let (day, period) = if n % 2 == 0 {
                ("2026-04-01", "FY2026-P04")
            } else {
                ("2026-05-01", "FY2026-P05")
            };
            reversal.date = DateDay::parse(day).unwrap();
            correction_outcome(&mut kernel, &mut oracle, &mut refs, &reversal, Ok(period));
            reversal.supersession_reason = 9;
            correction_outcome(
                &mut kernel,
                &mut oracle,
                &mut refs,
                &reversal,
                Err("FA-REF-052"),
            );
        }
        let mut opening = maintenance_intent(
            "Adjusting",
            DateDay::parse("2026-01-01").unwrap(),
            i128::from(rng.below(10_000)) + 1,
            "opening-order",
        );
        opening.discriminator = Some("FY2026-OPEN".into());
        let target = correction_outcome(
            &mut kernel,
            &mut oracle,
            &mut refs,
            &opening,
            Ok("FY2026-OPEN"),
        )
        .unwrap();
        opening.class = "Reversal".into();
        opening.key = b"reverse-opening-order".to_vec();
        opening.reverses = Some(target);
        opening.date = DateDay::parse("2026-01-02").unwrap();
        opening.discriminator = None;
        for leg in &mut opening.legs {
            leg.side = leg.side.flipped();
        }
        correction_outcome(
            &mut kernel,
            &mut oracle,
            &mut refs,
            &opening,
            Ok("FY2026-P01"),
        );
        let mut adjusted = maintenance_intent(
            "Original",
            DateDay::parse("2026-12-31").unwrap(),
            i128::from(rng.below(10_000)) + 1,
            "adjustment-order",
        );
        adjusted.discriminator = Some("FY2026-A1".into());
        correction_outcome(
            &mut kernel,
            &mut oracle,
            &mut refs,
            &adjusted,
            Err("FA-REF-010"),
        );
        adjusted.class = "Adjusting".into();
        let target = correction_outcome(
            &mut kernel,
            &mut oracle,
            &mut refs,
            &adjusted,
            Ok("FY2026-A1"),
        )
        .unwrap();
        adjusted.class = "Reversal".into();
        adjusted.key = b"reverse-adjustment-order".to_vec();
        adjusted.reverses = Some(target);
        for leg in &mut adjusted.legs {
            leg.side = leg.side.flipped();
        }
        correction_outcome(
            &mut kernel,
            &mut oracle,
            &mut refs,
            &adjusted,
            Err("FA-REF-010"),
        );
        adjusted.discriminator = None;
        correction_outcome(
            &mut kernel,
            &mut oracle,
            &mut refs,
            &adjusted,
            Err("FA-REF-053"),
        );
        adjusted.date = DateDay::parse("2027-01-01").unwrap();
        correction_outcome(
            &mut kernel,
            &mut oracle,
            &mut refs,
            &adjusted,
            Ok("FY2027-P01"),
        );
        for period in [
            "FY2026-OPEN",
            "FY2026-P01",
            "FY2026-P03",
            "FY2026-P04",
            "FY2026-P05",
            "FY2026-P12",
            "FY2026-A1",
            "FY2027-P01",
        ] {
            let maintained = maintain(&mut kernel, period);
            maintained_matches_oracle(&maintained, &oracle, kernel.book.book_id);
        }
    }
}

#[test]
fn incremental_registers_consume_only_new_entries_and_release_the_original_period() {
    let (mut k, mut oracle, periods) = setup();
    open_period(&mut k, &mut oracle, &periods[2], 1);
    open_period(&mut k, &mut oracle, &periods[3], 2);
    let usd = k.book.units.lookup("USD").unwrap();
    let march = DateDay::from_ymd(2026, 3, 15).unwrap();
    let april = DateDay::from_ymd(2026, 4, 15).unwrap();
    maintain(&mut k, &periods[2]);
    maintain(&mut k, &periods[3]);
    let mut refs = Vec::new();
    for n in 1..=24 {
        let i = maintenance_intent("Original", march, n, &format!("inc-{n}"));
        refs.push(kernel_post(&mut k, &i, usd, &refs).unwrap().entry_ref());
        assert!(matches!(oracle.post(&i), Verdict::Posted { .. }));
        let result = maintain(&mut k, &periods[2]);
        maintained_matches_oracle(&result, &oracle, k.book.book_id);
        assert_eq!(
            result.entries_decoded, 1,
            "prior entries must not be decoded again"
        );
        assert_eq!(result.fold.entries, n as u64);
        let head = k.db.frontier().unwrap();
        assert!(!maintain(&mut k, &periods[2]).wrote);
        assert_eq!(
            k.db.frontier().unwrap(),
            head,
            "no self-generated maintenance loop"
        );
    }
    // A reversal contributes opposite legs without removing the original.
    let mut reversal = maintenance_intent("Reversal", march, 1, "undo-first");
    for leg in &mut reversal.legs {
        leg.side = match leg.side {
            fa_reference::Side::Debit => fa_reference::Side::Credit,
            fa_reference::Side::Credit => fa_reference::Side::Debit,
        };
    }
    reversal.reverses = Some(0);
    refs.push(
        kernel_post(&mut k, &reversal, usd, &refs)
            .unwrap()
            .entry_ref(),
    );
    assert!(matches!(oracle.post(&reversal), Verdict::Posted { .. }));
    let reversed = maintain(&mut k, &periods[2]);
    maintained_matches_oracle(&reversed, &oracle, k.book.book_id);
    assert_eq!(reversed.entries_decoded, 1);
    assert_eq!(reversed.fold.entries, 25);
    assert_eq!(reversed.fold.cells.len(), 2);
    assert!(
        reversed
            .fold
            .cells
            .iter()
            .all(|c| c.debits + c.credits == 301)
    );
    // Several holds arrive before one advance; the two columns remain distinct.
    let first_hold = refs.len();
    for n in 0..3 {
        let i = maintenance_intent("Pending", march, 80, &format!("hold-{n}"));
        refs.push(kernel_post(&mut k, &i, usd, &refs).unwrap().entry_ref());
        assert!(matches!(oracle.post(&i), Verdict::Posted { .. }));
    }
    let held = maintain(&mut k, &periods[2]);
    assert_eq!(held.entries_decoded, 3);
    maintained_matches_oracle(&held, &oracle, k.book.book_id);
    assert_eq!(held.fold.pending.len(), 2);
    assert!(
        held.fold
            .pending
            .iter()
            .all(|c| c.debits + c.credits == 240)
    );
    let mut partial = maintenance_intent("Resolution", april, 60, "partial");
    partial.resolves = Some(Resolve {
        target: first_hold,
        posts: Some(vec![0, 1]),
    });
    refs.push(
        kernel_post(&mut k, &partial, usd, &refs)
            .unwrap()
            .entry_ref(),
    );
    assert!(matches!(oracle.post(&partial), Verdict::Posted { .. }));
    let released = maintain(&mut k, &periods[2]);
    maintained_matches_oracle(&released, &oracle, k.book.book_id);
    assert_eq!(released.fold.pending.len(), 2);
    assert!(
        released
            .fold
            .pending
            .iter()
            .all(|c| c.debits + c.credits == 160)
    );
    let posted = maintain(&mut k, &periods[3]);
    maintained_matches_oracle(&posted, &oracle, k.book.book_id);
    assert_eq!(posted.fold.cells.len(), 2);
    assert_eq!(posted.fold.entries, 1);
    assert!(posted.fold.cells.iter().all(|c| c.debits + c.credits == 60));
    // Empty-legged cross-period voids release the full remaining reservations.
    for target in [first_hold + 1, first_hold + 2] {
        let mut void = maintenance_intent("Resolution", april, 0, &format!("void-{target}"));
        void.resolves = Some(Resolve {
            target,
            posts: None,
        });
        refs.push(kernel_post(&mut k, &void, usd, &refs).unwrap().entry_ref());
        assert!(matches!(oracle.post(&void), Verdict::Posted { .. }));
    }
    assert!(maintain(&mut k, &periods[2]).fold.pending.is_empty());
    maintained_matches_oracle(&maintain(&mut k, &periods[2]), &oracle, k.book.book_id);
    maintained_matches_oracle(&maintain(&mut k, &periods[3]), &oracle, k.book.book_id);
    // Recovery replaces the derived values but leaves the exact fold unchanged.
    let before = fold_period(&k.db, &k.book, &periods[2]).unwrap();
    let ctx = k.ctx();
    let rebuilt = k
        .runtime
        .block_on(fa_registers::rebuild(&mut k.db, &ctx, &k.book, &periods[2]))
        .unwrap();
    assert!(rebuilt.rebuilt);
    assert_eq!(rebuilt.fold, before);
    assert_eq!(maintain(&mut k, &periods[2]).fold, before);
}

#[test]
fn incremental_pending_overflow_can_resolve_before_the_consumed_frontier() {
    for cached_hold in [false, true] {
        let (mut k, mut oracle, periods) = setup();
        let period = &periods[2];
        open_period(&mut k, &mut oracle, period, 1);
        let usd = k.book.units.lookup("USD").unwrap();
        let date = DateDay::from_ymd(2026, 3, 15).unwrap();
        let mut refs = Vec::new();
        let large = maintenance_intent("Pending", date, i128::MAX, "large-hold");
        refs.push(kernel_post(&mut k, &large, usd, &refs).unwrap().entry_ref());
        assert!(matches!(oracle.post(&large), Verdict::Posted { .. }));
        if cached_hold {
            maintained_matches_oracle(&maintain(&mut k, period), &oracle, k.book.book_id);
        }
        let small = maintenance_intent("Pending", date, 1, "small-hold");
        let before = k.db.frontier().unwrap();
        let refusal = kernel_post(&mut k, &small, usd, &refs).unwrap_err();
        assert_eq!(refusal.code, "FA-REF-198", "{refusal}");
        assert_eq!(oracle.post(&small), Verdict::Refused { code: "FA-REF-198" });
        // Even unlimited accounts have representability bounds. Refusing
        // before publication preserves both the journal and cached cursor.
        let at_cap = fold_period(&k.db, &k.book, period).unwrap();
        assert_eq!(at_cap.pending.len(), 2);
        assert!(
            at_cap
                .pending
                .iter()
                .all(|cell| cell.debits.checked_add(cell.credits) == Some(i128::MAX))
        );
        assert_eq!(k.db.frontier().unwrap(), before);

        let mut release = maintenance_intent("Resolution", date, 0, "release-large-hold");
        release.resolves = Some(Resolve {
            target: 0,
            posts: None,
        });
        let resolution_vid = fa_journal::rows::resolution_vid(refs[0].vid);
        let mut small = small;
        for step in 0u64.. {
            let candidate = format!("small-hold-{step}").into_bytes();
            if fa_model::entry_vid(k.book.book_id, &PRINCIPAL.0.to_le_bytes(), &candidate).0
                < resolution_vid.0
            {
                small.key = candidate;
                break;
            }
        }
        // The rejected key was not consumed; freeing the old reservation in the
        // same atomic batch makes the one-unit hold legal without changing
        // either amount, while ordering the hold's VId before its resolution in
        // that commit exercises the incremental tail's overflow-rebuild path.
        let batch = [small.clone(), release.clone()];
        let posted = kernel_batch(&mut k, "release-and-rebook", &batch, usd, &refs).unwrap();
        refs.extend(posted.entries);
        assert!(matches!(
            oracle.post_batch(b"release-and-rebook", &batch),
            fa_reference::BatchVerdict::Posted { .. }
        ));

        // At the target frontier only the one-unit hold contributes. Both a cold rebuild
        // and advancement from a cached large hold must reach that result.
        let recovered = maintain(&mut k, period);
        assert!(recovered.rebuilt);
        maintained_matches_oracle(&recovered, &oracle, k.book.book_id);
        assert_eq!(recovered.fold.pending.len(), 2);
        assert!(
            recovered
                .fold
                .pending
                .iter()
                .all(|cell| cell.debits + cell.credits == 1)
        );
        assert!(!maintain(&mut k, period).wrote);

        release.key = b"release-small-hold".to_vec();
        release.resolves.as_mut().unwrap().target = 1;
        kernel_post(&mut k, &release, usd, &refs).unwrap();
        assert!(matches!(oracle.post(&release), Verdict::Posted { .. }));
        let empty = maintain(&mut k, period);
        assert!(!empty.rebuilt);
        assert!(empty.fold.pending.is_empty());
        maintained_matches_oracle(&empty, &oracle, k.book.book_id);
    }
}

#[test]
fn atomic_pending_resolutions_agree_with_oracle_and_maintained_registers() {
    for resolution_first_in_journal in [false, true] {
        let (mut k, mut oracle, periods) = setup();
        let (march, april) = (&periods[2], &periods[3]);
        open_period(&mut k, &mut oracle, march, 1);
        open_period(&mut k, &mut oracle, april, 2);
        let usd = k.book.units.lookup("USD").unwrap();
        let held_on = DateDay::from_ymd(2026, 3, 15).unwrap();
        let resolved_on = DateDay::from_ymd(2026, 4, 10).unwrap();
        let mut refs = Vec::new();
        maintain(&mut k, march);
        maintain(&mut k, april);
        for amount in [0, 60] {
            let mut hold = maintenance_intent("Pending", held_on, 150, "atomic-hold");
            for nonce in 0u64.. {
                hold.key = format!("atomic-hold-{amount}-{nonce}").into_bytes();
                let vid = fa_model::entry_vid(k.book.book_id, &PRINCIPAL.0.to_le_bytes(), &hold.key);
                if (fa_journal::rows::resolution_vid(vid).0 < vid.0)
                    == resolution_first_in_journal
                {
                    break;
                }
            }
            let mut release = maintenance_intent(
                "Resolution",
                resolved_on,
                amount,
                &format!("atomic-resolution-{amount}"),
            );
            release.resolves = Some(Resolve {
                target: refs.len(),
                posts: (amount != 0).then(|| vec![0, 1]),
            });
            let mut extended = refs.clone();
            extended.push(predicted_ref(&k, &hold, usd, &refs));
            let members = [hold, release];
            let batch_key = format!("atomic-hold-and-release-{amount}");
            let before = k.db.frontier().unwrap();
            let historical = fa_registers::fold_period_at(&k.db, &k.book, march, Some(before))
                .unwrap();
            let posted = kernel_batch(&mut k, &batch_key, &members, usd, &extended).unwrap();
            assert_eq!(posted.recorded_at.0, before.0 + 1);
            assert!(matches!(
                oracle.post_batch(batch_key.as_bytes(), &members),
                fa_reference::BatchVerdict::Posted { .. }
            ));
            refs.extend(posted.entries);
            assert_eq!(
                fa_registers::fold_period_at(&k.db, &k.book, march, Some(before)).unwrap(),
                historical,
                "atomic publication cannot expose an intermediate reservation"
            );
            for period in [march, april] {
                let advance = maintain(&mut k, period);
                assert!(!advance.rebuilt, "same-commit ordering is handled in the delta fold");
                assert!(advance.fold.pending.is_empty());
                assert!(advance.fold.pending_holds.is_empty());
                maintained_matches_oracle(&advance, &oracle, k.book.book_id);
                assert!(!maintain(&mut k, period).wrote);
            }
        }
    }
}

/// fa-715: a trial balance and a period activity at the head served from
/// maintained cells plus the exact tail equal the literal fold at every
/// step of a history of postings, holds and releases in four periods whose
/// registers advance at random points. The maintained path must actually
/// answer both.
#[test]
fn maintained_trial_balances_equal_the_literal_fold_at_every_step() {
    let (mut k, mut oracle, periods) = setup();
    for (i, code) in periods[..4].iter().enumerate() {
        open_period(&mut k, &mut oracle, code, 70_000 + i as u64);
    }
    let usd = k.book.units.lookup("USD").unwrap();
    let mut rng = Rng(0x0715_5EED_715A_0715);
    let mut refs: Vec<EntryRef> = Vec::new();
    let mut live_holds: Vec<(usize, DateDay)> = Vec::new();
    let selections: Vec<Vec<String>> = vec![
        vec![periods[0].clone()],
        vec![periods[1].clone()],
        vec![periods[3].clone()],
        vec![periods[0].clone(), periods[2].clone()],
    ];
    let mut maintained_reads = 0usize;
    let mut maintained_activity = 0usize;
    for step in 0..96u64 {
        let month = 1 + u8::try_from(rng.below(4)).expect("month");
        let date = DateDay::from_ymd(2026, month, 10).unwrap();
        let key = format!("tb-{step}");
        match rng.below(10) {
            0..=5 => {
                let amount = 1 + i128::from(rng.below(1_000));
                let intent = maintenance_intent("Original", date, amount, &key);
                let posted = kernel_post(&mut k, &intent, usd, &refs).expect("original posts");
                refs.push(posted.entry_ref());
            }
            6 | 7 => {
                let amount = 1 + i128::from(rng.below(1_000));
                let intent = maintenance_intent("Pending", date, amount, &key);
                let posted = kernel_post(&mut k, &intent, usd, &refs).expect("hold posts");
                live_holds.push((refs.len(), date));
                refs.push(posted.entry_ref());
            }
            8 if !live_holds.is_empty() => {
                let pick = usize::try_from(rng.below(live_holds.len() as u64)).expect("index");
                let (target, held_on) = live_holds.remove(pick);
                let mut release = maintenance_intent("Resolution", held_on, 0, &key);
                release.resolves = Some(Resolve {
                    target,
                    posts: None,
                });
                let posted = kernel_post(&mut k, &release, usd, &refs).expect("release posts");
                refs.push(posted.entry_ref());
            }
            _ => {
                let period = periods[usize::try_from(rng.below(4)).expect("period")].clone();
                maintain(&mut k, &period);
            }
        }
        for selection in &selections {
            let literal = trial_balance(&k.db, &k.book, selection).unwrap();
            let (served, how) =
                fa_registers::trial_balance_served(&k.db, &k.book, selection).unwrap();
            assert_eq!(
                served, literal,
                "step {step}, {selection:?}, served {how:?}"
            );
            if matches!(how, fa_registers::Served::Maintained(_)) {
                maintained_reads += 1;
            }
            let literal = period_activity(&k.db, &k.book, selection, None).unwrap();
            let (served, how) =
                fa_registers::period_activity_served(&k.db, &k.book, selection).unwrap();
            assert_eq!(
                served, literal,
                "step {step}, activity {selection:?}, served {how:?}"
            );
            if matches!(how, fa_registers::Served::Maintained(_)) {
                maintained_activity += 1;
            }
        }
    }
    assert!(maintained_reads > 0, "maintained cells never answered");
    assert!(
        maintained_activity > 0,
        "maintained cells never answered an activity read"
    );
}

/// fa-715 complexity witness: once maintenance has caught up, a head trial
/// balance decodes only the entries committed after the cursors (its
/// tail), however much unrelated history the journal holds. 300 postings
/// to a later period change neither the answer nor the decoded tail; one
/// new March posting is decoded once per maintained contributing period.
#[test]
fn a_maintained_head_read_decodes_only_its_tail_regardless_of_unrelated_history() {
    let (mut k, mut oracle, periods) = setup();
    let (january, march, april) = (periods[0].clone(), periods[2].clone(), periods[3].clone());
    for (i, code) in [&january, &march, &april].into_iter().enumerate() {
        open_period(&mut k, &mut oracle, code, 71_000 + i as u64);
    }
    let usd = k.book.units.lookup("USD").unwrap();
    let in_march = DateDay::from_ymd(2026, 3, 10).unwrap();
    let in_april = DateDay::from_ymd(2026, 4, 10).unwrap();
    let mut refs = Vec::new();
    let first = maintenance_intent("Original", in_march, 500, "march-0");
    refs.push(kernel_post(&mut k, &first, usd, &refs).unwrap().entry_ref());
    for i in 0..300 {
        let later = maintenance_intent("Original", in_april, 1 + i, &format!("april-{i}"));
        refs.push(kernel_post(&mut k, &later, usd, &refs).unwrap().entry_ref());
    }
    let selection = vec![march.clone()];
    let (_, cold) = fa_registers::trial_balance_served(&k.db, &k.book, &selection).unwrap();
    assert!(
        matches!(&cold, fa_registers::Served::Literal(reason) if reason.contains(&march)),
        "March has postings and no cells yet: {cold:?}"
    );
    maintain(&mut k, &january);
    maintain(&mut k, &march);
    let (served, how) = fa_registers::trial_balance_served(&k.db, &k.book, &selection).unwrap();
    assert_eq!(served, trial_balance(&k.db, &k.book, &selection).unwrap());
    assert_eq!(how.tail_length(), Some(0), "{how:?}");
    let second = maintenance_intent("Original", in_march, 7, "march-1");
    refs.push(
        kernel_post(&mut k, &second, usd, &refs)
            .unwrap()
            .entry_ref(),
    );
    let (served, how) = fa_registers::trial_balance_served(&k.db, &k.book, &selection).unwrap();
    assert_eq!(served, trial_balance(&k.db, &k.book, &selection).unwrap());
    assert_eq!(how.tail_length(), Some(2), "{how:?}");
}

/// fa-715 planted negative: a register cell whose amount no longer matches
/// its fold digest is never served. The read falls back to the literal fold
/// (the right answer) and `verify registers` reports the drift.
#[test]
fn a_drifted_register_cell_is_never_served() {
    use fa_model::symbols::{property, relation};

    let (mut k, mut oracle, periods) = setup();
    let march = periods[2].clone();
    open_period(&mut k, &mut oracle, &march, 72_000);
    let usd = k.book.units.lookup("USD").unwrap();
    let in_march = DateDay::from_ymd(2026, 3, 10).unwrap();
    let intent = maintenance_intent("Original", in_march, 500, "march-0");
    kernel_post(&mut k, &intent, usd, &[]).unwrap();
    maintain(&mut k, &march);
    let selection = vec![march.clone()];
    let literal = trial_balance(&k.db, &k.book, &selection).unwrap();
    let (served, how) = fa_registers::trial_balance_served(&k.db, &k.book, &selection).unwrap();
    assert_eq!(served, literal);
    assert!(
        matches!(how, fa_registers::Served::Maintained(_)),
        "{how:?}"
    );

    let cell = fa_registers::register_vid(
        k.book.book_id,
        &fa_registers::CellKey {
            account: account_vid(k.book.book_id, "6000"),
            unit_id: usd.0,
            period: march.clone(),
        },
    );
    let mut write = WriteBatch::new(relation::IN_PERIOD);
    write.set_vertex_property(
        cell,
        property::DEBITS_POSTED,
        Some(rows::scalar_bytes("debits", 501i128.to_le_bytes().to_vec()).unwrap()),
    );
    let ctx = k.ctx();
    k.runtime
        .block_on(k.db.write(&ctx.commit(), write))
        .unwrap();
    let (served, how) = fa_registers::trial_balance_served(&k.db, &k.book, &selection).unwrap();
    assert!(matches!(how, fa_registers::Served::Literal(_)), "{how:?}");
    assert_eq!(served.rows, literal.rows, "the literal fold still answers");
    assert!(
        !fa_registers::verify_period(&k.db, &k.book, &march)
            .unwrap()
            .is_green()
    );
}

#[test]
fn incremental_registers_reject_stale_or_foreign_preparation_and_recover_after_reopen() {
    let chart: Vec<ChartRow> = ACCOUNTS
        .iter()
        .map(|(code, ty, leaf)| (*code, *ty, *leaf, 0, None))
        .collect();
    let (mut k, mut oracle, periods, vfs) = setup_store(&chart);
    open_period(&mut k, &mut oracle, &periods[2], 1);
    let usd = k.book.units.lookup("USD").unwrap();
    let march = DateDay::from_ymd(2026, 3, 15).unwrap();
    maintain(&mut k, &periods[2]);
    let ctx = k.ctx();
    let before = k.db.frontier().unwrap();
    let abandoned = k
        .runtime
        .block_on(fa_registers::prepare_advance(
            &mut k.db,
            &ctx,
            &k.book,
            &periods[2],
        ))
        .unwrap();
    drop(abandoned);
    assert_eq!(
        k.db.frontier().unwrap(),
        before,
        "preparation never publishes cells/cursor"
    );
    let stale = k
        .runtime
        .block_on(fa_registers::prepare_advance(
            &mut k.db,
            &ctx,
            &k.book,
            &periods[2],
        ))
        .unwrap();
    kernel_post(
        &mut k,
        &maintenance_intent("Original", march, 17, "after-plan"),
        usd,
        &[],
    )
    .unwrap();
    let posted = k.db.frontier().unwrap();
    let result = k.runtime.block_on(fa_registers::publish_advance(
        &mut k.db, &ctx, &k.book, stale,
    ));
    assert!(matches!(
        result,
        Err(fa_registers::RegisterError::StaleFold)
    ));
    assert_eq!(k.db.frontier().unwrap(), posted);
    // Drop the actual substrate handle with an unconsumed posting and reopen.
    let Kernel {
        runtime,
        root,
        db,
        book,
        evidence,
        agent_evidence,
    } = k;
    drop(db);
    let db = runtime
        .block_on(Database::open_with_vfs(
            &ctx.commit(),
            vfs.clone(),
            vfs.database_dir(),
            db_keys(),
        ))
        .unwrap();
    let mut k = Kernel {
        runtime,
        root,
        db,
        book,
        evidence,
        agent_evidence,
    };
    let advanced = maintain(&mut k, &periods[2]);
    assert_eq!(advanced.entries_decoded, 1);
    assert_eq!(advanced.fold.entries, 1);

    // Same book id and same numeric frontier do not identify the same journal.
    let (mut other, mut other_oracle, other_periods) = setup();
    open_period(&mut other, &mut other_oracle, &other_periods[2], 1);
    maintain(&mut other, &other_periods[2]);
    kernel_post(
        &mut other,
        &maintenance_intent("Original", march, 999, "after-plan"),
        usd,
        &[],
    )
    .unwrap();
    maintain(&mut other, &other_periods[2]);
    assert_eq!(other.db.frontier().unwrap(), k.db.frontier().unwrap());
    assert_ne!(
        other.db.partition_root().unwrap(),
        k.db.partition_root().unwrap()
    );
    let foreign = k
        .runtime
        .block_on(fa_registers::prepare_advance(
            &mut k.db,
            &ctx,
            &k.book,
            &periods[2],
        ))
        .unwrap();
    let other_ctx = other.ctx();
    let before = other.db.frontier().unwrap();
    let result = other.runtime.block_on(fa_registers::publish_advance(
        &mut other.db,
        &other_ctx,
        &other.book,
        foreign,
    ));
    assert!(matches!(
        result,
        Err(fa_registers::RegisterError::StaleFold)
    ));
    assert_eq!(other.db.frontier().unwrap(), before);
    maintain(&mut other, &other_periods[2]);
}

#[test]
fn incremental_registers_verify_corruption_and_rebuild_without_changing_journal() {
    use fa_model::symbols::{property, relation};
    let (mut k, mut oracle, periods) = setup();
    open_period(&mut k, &mut oracle, &periods[2], 1);
    let usd = k.book.units.lookup("USD").unwrap();
    let march = DateDay::from_ymd(2026, 3, 15).unwrap();
    let posted = kernel_post(
        &mut k,
        &maintenance_intent("Original", march, 123, "fund"),
        usd,
        &[],
    )
    .unwrap();
    let good = maintain(&mut k, &periods[2]).fold;
    let ctx = k.ctx();
    let state = fa_registers::maintainer::state_vid(k.book.book_id, &periods[2]);
    for forged_checksum in [false, true] {
        let row = k.db.vertex(state).unwrap().unwrap();
        let mut payload = rows::bytes(&row, property::FA_PAYLOAD, "state").unwrap();
        // Change the entry counter while leaving every amount and fold digest intact.
        assert_eq!(payload[14], 1, "this fixture has a contribution watermark");
        payload[23] ^= 1;
        let mut write = WriteBatch::new(relation::IN_PERIOD);
        write.set_vertex_property(
            state,
            property::FA_PAYLOAD,
            Some(rows::scalar_bytes("state", payload.clone()).unwrap()),
        );
        if forged_checksum {
            let mut h = fgdb_crypto::Hasher::new();
            h.update(b"fa:register-state-payload:v1");
            h.update(&k.book.book_id.0);
            h.update(&(periods[2].len() as u64).to_le_bytes());
            h.update(periods[2].as_bytes());
            h.update(&payload);
            write.set_vertex_property(
                state,
                property::FA_DIGEST,
                Some(rows::scalar_bytes("digest", h.finalize().0.to_vec()).unwrap()),
            );
        }
        k.runtime
            .block_on(k.db.write(&ctx.commit(), write))
            .unwrap();
        assert!(
            !fa_registers::verify_period(&k.db, &k.book, &periods[2])
                .unwrap()
                .is_green(),
            "neither a broken checksum nor a coherently forged counter is proof"
        );
        if !forged_checksum {
            let frontier = k.db.frontier().unwrap();
            assert!(
                k.runtime
                    .block_on(fa_registers::advance(&mut k.db, &ctx, &k.book, &periods[2]))
                    .is_err()
            );
            assert_eq!(k.db.frontier().unwrap(), frontier);
        }
        let result = k
            .runtime
            .block_on(fa_registers::rebuild(&mut k.db, &ctx, &k.book, &periods[2]))
            .unwrap();
        assert_eq!(result.fold, good);
        maintain(&mut k, &periods[2]);
    }
    // An omitted/changed amount is caught independently, then repaired from truth.
    let rvid = fa_registers::register_vid(k.book.book_id, &good.cells[0].key);
    let mut write = WriteBatch::new(relation::IN_PERIOD);
    write.set_vertex_property(
        rvid,
        property::DEBITS_POSTED,
        Some(rows::scalar_bytes("amount", 999i128.to_le_bytes().to_vec()).unwrap()),
    );
    k.runtime
        .block_on(k.db.write(&ctx.commit(), write))
        .unwrap();
    assert!(
        !fa_registers::verify_period(&k.db, &k.book, &periods[2])
            .unwrap()
            .is_green()
    );
    assert!(
        k.runtime
            .block_on(fa_registers::advance(&mut k.db, &ctx, &k.book, &periods[2]))
            .is_err()
    );
    // The existing materialize API repairs both cells and maintenance state.
    k.runtime
        .block_on(fa_registers::materialize(&mut k.db, &ctx, &k.book, &good))
        .unwrap();
    assert_eq!(
        fa_journal::post::read_entry(&k.db, posted.entry_ref().vid)
            .unwrap()
            .unwrap()
            .0
            .entry_digest,
        posted.entry_ref().entry_digest,
        "repair never edits the committed posting"
    );
    maintain(&mut k, &periods[2]);

    // Forge a cursor across a real unconsumed posting, recomputing the state
    // checksum. Integrity alone is not verification of the omitted contribution.
    kernel_post(
        &mut k,
        &maintenance_intent("Original", march, 7, "skipped"),
        usd,
        &[],
    )
    .unwrap();
    let frontier = k.db.frontier().unwrap();
    let row = k.db.vertex(state).unwrap().unwrap();
    let mut payload = rows::bytes(&row, property::FA_PAYLOAD, "state").unwrap();
    payload[6..14].copy_from_slice(&frontier.0.to_le_bytes());
    let mut h = fgdb_crypto::Hasher::new();
    h.update(b"fa:register-state-payload:v1");
    h.update(&k.book.book_id.0);
    h.update(&(periods[2].len() as u64).to_le_bytes());
    h.update(periods[2].as_bytes());
    h.update(&payload);
    let mut write = WriteBatch::new(relation::IN_PERIOD);
    write.set_vertex_property(
        state,
        property::FA_PAYLOAD,
        Some(rows::scalar_bytes("state", payload).unwrap()),
    );
    write.set_vertex_property(
        state,
        property::FA_DIGEST,
        Some(rows::scalar_bytes("digest", h.finalize().0.to_vec()).unwrap()),
    );
    k.runtime
        .block_on(k.db.write(&ctx.commit(), write))
        .unwrap();
    let verified = fa_registers::verify_period(&k.db, &k.book, &periods[2]).unwrap();
    assert!(!verified.is_green());
    assert!(
        verified
            .projection_errors
            .iter()
            .any(|e| e.contains("journal prefix"))
    );
    let repaired = k
        .runtime
        .block_on(fa_registers::rebuild(&mut k.db, &ctx, &k.book, &periods[2]))
        .unwrap();
    assert_eq!(repaired.fold.entries, 2);
    assert_eq!(repaired.fold.cells.len(), 2);
    assert!(
        repaired
            .fold
            .cells
            .iter()
            .all(|c| c.debits + c.credits == 130)
    );
    maintain(&mut k, &periods[2]);
}

#[test]
fn incremental_registers_consume_every_expiry_in_a_single_commit() {
    let (mut k, mut oracle, periods) = setup();
    open_period(&mut k, &mut oracle, &periods[2], 1);
    let usd = k.book.units.lookup("USD").unwrap();
    let march = DateDay::from_ymd(2026, 3, 15).unwrap();
    kernel_tick(&mut k, 100, "initial").unwrap();
    for n in 0..5 {
        kernel_post_timed(
            &mut k,
            &maintenance_intent("Pending", march, 80, &format!("timed-{n}")),
            usd,
            &[],
            10,
        )
        .unwrap();
    }
    let held = maintain(&mut k, &periods[2]);
    assert_eq!(held.fold.pending.len(), 2);
    assert!(held.fold.pending.iter().all(|c| c.entry_count == 5));
    kernel_tick(&mut k, 110, "due").unwrap();
    let batch = kernel_sweep(&mut k, 3).unwrap().unwrap();
    assert_eq!(batch.expired.len(), 3);
    let partial = maintain(&mut k, &periods[2]);
    assert_eq!(partial.fold.pending.len(), 2);
    assert!(
        partial
            .fold
            .pending
            .iter()
            .all(|c| c.entry_count == 2 && c.debits + c.credits == 160)
    );
    assert_eq!(kernel_sweep(&mut k, 3).unwrap().unwrap().expired.len(), 2);
    assert!(maintain(&mut k, &periods[2]).fold.pending.is_empty());
}

/// Public caller claims must agree with the independent model before any
/// journal effect, including when the same identity is retried without them.
#[test]
fn public_post_provenance_and_envelope_claims_match_the_independent_oracle() {
    use fa_reference::{ClaimedBaseTotals, ClaimedOrigin, PostClaims};

    #[derive(Clone, Copy)]
    enum Claim {
        Native,
        Certificate,
        BaseTotals,
        Rule,
        Sweep,
        Schedule,
        Control,
    }
    let cases = [
        Claim::Native,
        Claim::Certificate,
        Claim::BaseTotals,
        Claim::Rule,
        Claim::Sweep,
        Claim::Schedule,
        Claim::Control,
    ];
    let mut observed = [0; 7];
    for seed in [0x51a9_u64, 0xb42d] {
        let (mut k, mut oracle, periods) = setup();
        open_period(&mut k, &mut oracle, &periods[2], 1);
        let usd = k.book.units.lookup("USD").unwrap();
        let date = DateDay::from_ymd(2026, 3, 15).unwrap();
        let mut rng = Rng(seed);
        for (kind, (case, count)) in cases.into_iter().zip(observed.iter_mut()).enumerate() {
            *count += 1;
            let amount = i128::from(rng.below(10_000) + 1);
            let intent =
                maintenance_intent("Original", date, amount, &format!("claims-{seed}-{kind}"));
            let mut request = kernel_request(&k, &intent, usd, &[]);
            let mut claims = PostClaims::default();
            let oid = [rng.below(256) as u8; 32];
            match case {
                Claim::Native => {}
                Claim::Certificate => {
                    request.plan_certificate = Some(Oid(oid));
                    claims.plan_certificate = Some(oid);
                }
                Claim::BaseTotals => {
                    request.proposal.base_totals = Some(fa_model::BaseTotals {
                        unit_id: usd.0,
                        debits: amount,
                        credits: amount,
                        fx_law_oid: Oid(oid),
                        rate_doc_oids: vec![Oid([0x91; 32])],
                        residual: None,
                    });
                    claims.base_totals = Some(ClaimedBaseTotals {
                        unit: usd.0,
                        debits: amount,
                        credits: amount,
                    });
                }
                Claim::Rule => {
                    request.proposal.origin = EntryOrigin::Rule {
                        rule_version_oid: Oid(oid),
                        event_ref: VId(u128::from(rng.next())),
                        inputs_digest: [0x92; 32],
                    };
                    claims.origin = ClaimedOrigin::Rule;
                }
                Claim::Sweep => {
                    request.proposal.origin = EntryOrigin::Sweep {
                        sweep_kind: 1,
                        tick_evidence_oid: Oid(oid),
                    };
                    claims.origin = ClaimedOrigin::Sweep;
                }
                Claim::Schedule => {
                    request.proposal.origin = EntryOrigin::Schedule {
                        schedule_ref: VId(u128::from(rng.next())),
                        trigger: fa_model::ScheduleTrigger::Sweep {
                            tick_ref: VId(u128::from(rng.next())),
                        },
                    };
                    claims.origin = ClaimedOrigin::Schedule;
                }
                Claim::Control => {
                    request.proposal.origin = EntryOrigin::Control {
                        control_kind: fa_model::ControlKind::TIME_TICK,
                        spec_body_digest: oid,
                    };
                    claims.origin = ClaimedOrigin::Control;
                }
            }
            request.proposal.validate().expect("one encodable claim");
            let before = k.db.frontier().unwrap();
            let known = oracle.known();
            let ctx = k.ctx();
            let actual = k
                .runtime
                .block_on(post(&mut k.db, &ctx, &k.book, request))
                .expect("kernel");
            let expected = oracle.post_with_claims(&intent, &claims);
            if kind == 0 {
                assert!(matches!(actual, Ok(Posted::Committed { .. })), "{actual:?}");
                assert!(matches!(expected, Verdict::Posted { .. }), "{expected:?}");
            } else {
                let refusal = actual.expect_err("unverified public claim");
                // A claimed rule origin is verified rather than refused outright:
                // its event's closure comes first (fa-c34), and no event exists.
                let (kernel_code, model_code) = if matches!(case, Claim::Rule) {
                    ("FA-REF-080", fa_reference::evidence::EVIDENCE_MINIMUM)
                } else {
                    ("FA-REF-102", fa_reference::code::CLASS_NOT_IMPLEMENTED)
                };
                assert_eq!(
                    refusal.code, kernel_code,
                    "seed={seed} kind={kind}: {refusal}"
                );
                assert_eq!(expected, Verdict::Refused { code: model_code });
                assert_eq!(k.db.frontier().unwrap(), before, "refusal changes no state");
                assert_eq!(oracle.known(), known, "oracle refusal changes no state");
            }
            // The same identity is usable after a refusal, and an ordinary
            // successful request is still idempotent in both implementations.
            let native = kernel_post(&mut k, &intent, usd, &[]).unwrap();
            let model_native = oracle.post(&intent);
            if kind == 0 {
                assert!(matches!(native, Posted::AlreadyRecorded { .. }));
                assert!(matches!(model_native, Verdict::Recorded { .. }));
            } else {
                assert!(matches!(native, Posted::Committed { .. }));
                assert!(matches!(model_native, Verdict::Posted { .. }));
            }
            assert!(matches!(
                kernel_post(&mut k, &intent, usd, &[]).unwrap(),
                Posted::AlreadyRecorded { .. }
            ));
            assert!(matches!(oracle.post(&intent), Verdict::Recorded { .. }));
            let maintained = maintain(&mut k, &periods[2]);
            maintained_matches_oracle(&maintained, &oracle, k.book.book_id);
        }
    }
    assert_eq!(
        observed, [2; 7],
        "every claim and the native control ran for both seeds"
    );
}

/// xorshift64*: deterministic, dependency-free.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
}

struct Kernel {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
    /// A real source document recorded at setup; every generated intent cites
    /// it (FA-INV-05 evidence-minimum). The oracle does not model evidence, so
    /// every generated intent satisfies the minimum by construction.
    evidence: Vec<EvidenceRef>,
    /// An AgentUpload document recorded at setup: cited alone it is
    /// self-sourced, so the planted evidence negatives reach FA-REF-086.
    agent_evidence: EvidenceRef,
}

impl Kernel {
    fn ctx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }
}

const ACCOUNTS: &[(&str, u8, bool)] = &[
    ("1000", 1, true),
    ("6000", 5, true),
    ("4000", 4, true),
    ("1200", 1, true),
    ("1", 1, false),
];

/// One chart row: code, type, leaf, normal side (0 debit, 1 credit), limit.
type ChartRow = (&'static str, u8, bool, u8, Option<BalanceLimit>);

fn setup() -> (Kernel, Oracle, Vec<String>) {
    let chart: Vec<ChartRow> = ACCOUNTS
        .iter()
        .map(|(code, ty, leaf)| (*code, *ty, *leaf, 0, None))
        .collect();
    setup_with(&chart)
}

fn setup_with(rows: &[ChartRow]) -> (Kernel, Oracle, Vec<String>) {
    let (k, oracle, periods, _) = setup_store(rows);
    (k, oracle, periods)
}

fn db_keys() -> DatabaseKeys {
    DatabaseKeys::new(
        [0x7a; 32],
        DatabaseSecurityNamespaceId([0x7b; 32]),
        [0x7c; 32],
    )
}

/// [`setup_with`], also returning the in-memory filesystem the store lives
/// on, so a test can drop the handle (a crash) and reopen what committed.
fn setup_store(rows: &[ChartRow]) -> (Kernel, Oracle, Vec<String>, MemVfs) {
    setup_entities(rows, &[])
}

/// [`setup_store`] for a book declaring `entities` (plan §4.1
/// `Book.entities`); the oracle is told the same declaration.
fn setup_entities(rows: &[ChartRow], entities: &[&str]) -> (Kernel, Oracle, Vec<String>, MemVfs) {
    let runtime = RuntimeBuilder::new().build().expect("runtime");
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let ctx = PurposeContexts::narrow_runtime_root(&root);
    // Database::open_memory, with the filesystem kept.
    let vfs = MemVfs::new().expect("memory filesystem");
    let dir = vfs.database_dir();
    let mut db = runtime
        .block_on(async {
            Database::create_with_vfs(&ctx.commit(), vfs.clone(), dir, db_keys()).await
        })
        .expect("open");
    let units = UnitRegistry::with_defaults();
    let usd = units.lookup("USD").unwrap();
    let calendar = FiscalCalendar::monthly("cal", 1, 1).unwrap();
    let book_id = Id128([0xd; 16]);
    let spec = BookSpec {
        book_id,
        name: "Diff Co".into(),
        base_unit: usd,
        calendar: calendar.clone(),
        // Declared: the scheduled-reversal tests need ticks to become dates.
        time_zone_policy: Some(TimeZonePolicy::Utc),
        entities: entities
            .iter()
            .map(|code| LegalEntitySpec {
                code: (*code).into(),
                name: format!("{code} entity"),
                functional_unit: usd,
            })
            .collect(),
        opening_date: None,
    };
    let symbols = SymbolTable::compiled();
    runtime
        .block_on(async { create_book(&mut db, &ctx, &spec, &units, &symbols).await })
        .expect("create_book");
    let book = BookContext {
        book_id,
        calendar: calendar.clone(),
        units,
        seal_key: SealKey([0x11; 32]),
        symbols,
    };
    let chart: Vec<AccountSpec> = rows
        .iter()
        .map(|(code, ty, leaf, normal, limit)| AccountSpec {
            code: (*code).into(),
            name: (*code).into(),
            account_type: *ty,
            normal_balance: *normal,
            is_leaf: *leaf,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: *limit,
        })
        .collect();
    let day = DateDay::from_ymd(2026, 1, 1).unwrap();
    runtime
        .block_on(async {
            install_chart(
                &mut db,
                &ctx,
                &book,
                &chart,
                PRINCIPAL,
                day,
                b"chart",
                Erasable::seal(&"chart".to_string(), None, &book.seal_key, [5; 32], [6; 24]),
                &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
            )
            .await
        })
        .expect("kernel")
        .expect("installs");
    let (_, periods) = runtime
        .block_on(async {
            create_periods(
                &mut db,
                &ctx,
                &book,
                2026,
                fgdb_types::VId(1),
                fa_model::Erasable::seal(
                    &"periods".to_string(),
                    None,
                    &book.seal_key,
                    [1; 32],
                    [2; 24],
                ),
                &fa_journal::Capability::embedded(fgdb_types::VId(1), &["schema_change"]).unwrap(),
            )
            .await
        })
        .expect("periods")
        .expect("admitted");
    let normal: Vec<String> = periods
        .iter()
        .filter(|p| p.kind == PeriodKind::Normal)
        .map(|p| p.code.clone())
        .collect();
    let source = Document {
        book_id: book.book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: b"INVOICE (differential fixture source document)".to_vec(),
    };
    runtime
        .block_on(async { add_document(&mut db, &ctx, &book, &source).await })
        .expect("kernel")
        .expect("the fixture document is admitted");
    let evidence = vec![source.evidence_ref(1)];
    let agent_upload = Document {
        book_id: book.book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 4,
        retrieved_by: PRINCIPAL,
        bytes: b"INVOICE (agent upload, differential fixture)".to_vec(),
    };
    runtime
        .block_on(async { add_document(&mut db, &ctx, &book, &agent_upload).await })
        .expect("kernel")
        .expect("the agent's document is admitted");
    let agent_evidence = agent_upload.evidence_ref(1);

    let mut oracle = Oracle::new(calendar);
    oracle.declare_entities(entities);
    for (code, _, leaf, normal, limit) in rows {
        oracle.add_account(Account {
            code: (*code).into(),
            is_leaf: *leaf,
            unit: Some(usd.0),
        });
        if let Some(l) = limit {
            oracle.set_limit(
                code,
                Limit {
                    normal: if *normal == 0 {
                        fa_reference::Side::Debit
                    } else {
                        fa_reference::Side::Credit
                    },
                    lower: l.lower,
                    upper: l.upper,
                    per_period: l.scope == LimitScope::Period,
                },
            );
        }
    }
    oracle.create_periods(2026);
    (
        Kernel {
            runtime,
            root,
            db,
            book,
            evidence,
            agent_evidence,
        },
        oracle,
        normal,
        vfs,
    )
}

fn to_kernel_legs(book_id: Id128, usd: UnitId, legs: &[Leg]) -> Vec<LegPayload> {
    legs.iter()
        .map(|l| {
            let mut leg = LegPayload::simple(
                if l.side == fa_reference::Side::Debit {
                    Side::Debit
                } else {
                    Side::Credit
                },
                account_vid(book_id, &l.account),
                Amount::new(usd, l.mantissa),
            );
            // The legal entity rides in the leg's dimension_set (plan §5.2).
            if let Some(e) = &l.entity {
                leg.dimension_set = vec![(
                    fa_model::LEGAL_ENTITY_DIMENSION,
                    fa_model::entity_value_vid(book_id, e),
                )];
            }
            leg
        })
        .collect()
}

fn kernel_post(
    k: &mut Kernel,
    intent: &Intent,
    usd: UnitId,
    refs: &[EntryRef],
) -> Result<Posted, Refusal> {
    kernel_post_raw(k, intent, usd, refs).expect("kernel")
}

/// `kernel_post` with the intent citing `evidence` instead of the fixture
/// document (the planted evidence negatives, fa-lp6).
fn kernel_post_citing(
    k: &mut Kernel,
    intent: &Intent,
    usd: UnitId,
    refs: &[EntryRef],
    evidence: Vec<EvidenceRef>,
) -> Result<Posted, Refusal> {
    let saved = std::mem::replace(&mut k.evidence, evidence);
    let out = kernel_post(k, intent, usd, refs);
    k.evidence = saved;
    out
}

fn kernel_post_raw(
    k: &mut Kernel,
    intent: &Intent,
    usd: UnitId,
    refs: &[EntryRef],
) -> Result<Result<Posted, Refusal>, KernelError> {
    let req = kernel_request(k, intent, usd, refs);
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    k.runtime
        .block_on(async move { post(db, &ctx, book, req).await })
}

/// A balancing post (plan §5.5) of the same request the oracle receives.
fn kernel_post_balancing(
    k: &mut Kernel,
    intent: &Intent,
    usd: UnitId,
    refs: &[EntryRef],
    leg: u16,
) -> Result<Balanced, Refusal> {
    let req = kernel_request(k, intent, usd, refs);
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    k.runtime
        .block_on(async move { post_balancing(db, &ctx, book, req, leg).await })
        .expect("kernel")
}

/// The kernel request for an oracle intent.
fn kernel_request(k: &Kernel, intent: &Intent, usd: UnitId, refs: &[EntryRef]) -> PostRequest {
    let mut legs = to_kernel_legs(k.book.book_id, usd, &intent.legs);
    for s in &intent.settles {
        legs[s.leg].settles.push(Settlement {
            target: refs[s.target],
            ordinal: u16::try_from(s.ordinal).expect("small ordinal"),
            amount: Amount::new(usd, s.mantissa),
        });
    }
    let unit_totals =
        EntryPayload::fold_unit_totals(&legs).expect("no overflow in generated amounts");
    let pending = match (intent.class.as_str(), &intent.resolves) {
        ("Pending", _) => Some(Pending {
            timeout_ns: None,
            resolution_of: None,
            disposition: None,
        }),
        (_, Some(r)) => Some(Pending {
            timeout_ns: None,
            resolution_of: Some(refs[r.target]),
            disposition: Some(match &r.posts {
                Some(ordinals) => Disposition::Posts {
                    source_ordinals: ordinals.clone(),
                },
                None => Disposition::Voids,
            }),
        }),
        _ => None,
    };
    let control = match &pending {
        Some(Pending {
            disposition: Some(Disposition::Voids),
            ..
        }) => Some(ControlPayload::ReservationRelease),
        _ => None,
    };
    let supersession = intent
        .reverses
        .map(|i| {
            vec![Supersession {
                target: refs[i],
                kind: SupersessionKind::Reverses,
                reason_code: intent.supersession_reason,
            }]
        })
        .unwrap_or_default();
    let proposal = EntryPayload {
        schema_minor: 0,
        book_id: k.book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::from_name(&intent.class).expect("registered class"),
        effective_date: intent.date,
        document_date: None,
        // Constant on purpose: the retry comparison covers it, and the oracle
        // does not model descriptions.
        description: Erasable::seal(
            &"generated".to_string(),
            None,
            &k.book.seal_key,
            [1; 32],
            [2; 24],
        ),
        effective_period: intent.discriminator.as_ref().map(|c| PeriodRef {
            calendar: "cal".into(),
            code: c.clone(),
        }),
        legs,
        control,
        unit_totals,
        base_totals: None,
        idempotency_key: intent.key.clone(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([1; 32]),
            intent_kind: 1,
        },
        principal_ref: PRINCIPAL,
        session_ref: None,
        evidence: k.evidence.clone(),
        supersession,
        pending,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    let ops: Vec<&str> = intent.ops.iter().map(String::as_str).collect();
    PostRequest {
        proposal,
        approvals: Vec::new(),
        plan_certificate: None,
        capability: Capability::embedded(PRINCIPAL, &ops).expect("registered ops"),
    }
}

/// The date the generated revocations, activations and drafts carry. A
/// period transition carries none: its period dates it (fa-87r).
fn control_day() -> DateDay {
    DateDay::from_ymd(2026, 1, 1).unwrap()
}

/// The effective date the kernel journaled on control entry `vid`.
fn journaled_date(k: &Kernel, vid: VId) -> DateDay {
    fa_journal::post::read_entry(&k.db, vid)
        .expect("read")
        .expect("control entry")
        .0
        .proposal
        .effective_date
}

fn period_description(k: &Kernel) -> Erasable<String> {
    Erasable::seal(
        &"period".to_string(),
        None,
        &k.book.seal_key,
        [3; 32],
        [4; 24],
    )
}

/// The digest of the PeriodControl proposal `kernel_transition_under`
/// commits at `step`, so an approver can bind it.
fn period_digest(
    k: &Kernel,
    code: &str,
    from: PeriodState,
    to: PeriodState,
    step: u64,
) -> [u8; 32] {
    transition_proposal(
        &k.book,
        &fa_journal::policy::calendar_period(&k.book, code).expect("calendar period"),
        from,
        to,
        PRINCIPAL,
        1,
        format!("t-{step}").as_bytes(),
        period_description(k),
    )
    .proposal_digest()
    .expect("digest")
}

/// Record an approval of `digest` under `capability`.
fn kernel_approve_as(
    k: &mut Kernel,
    capability: Capability,
    digest: [u8; 32],
) -> fa_model::ApprovalRef {
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    let req = ApprovalRequest {
        capability,
        approved_proposal_digest: digest,
        role: 0,
    };
    k.runtime
        .block_on(async move { record_approval(db, &ctx, book, req).await })
        .expect("kernel")
        .expect("approval recorded")
        .approval()
}

/// A second Human (principal 70, never the preparer) approves `digest`.
fn kernel_approve(k: &mut Kernel, digest: [u8; 32]) -> fa_model::ApprovalRef {
    kernel_approve_as(
        k,
        Capability::embedded(VId(70), &["approve"]).expect("approve"),
        digest,
    )
}

/// Journal the revocation of `revoked` by an issuer holding `issue_capability`.
fn kernel_revoke(k: &mut Kernel, revoked: &Capability, step: u64) {
    let req = RevocationRequest {
        capability: Capability::embedded(VId(90), &["issue_capability"]).expect("issuer"),
        revoked: revoked.commitment().expect("commitment"),
        effective_date: control_day(),
        idempotency_key: format!("revoke-{step}").into_bytes(),
        description: Erasable::seal(
            &"revoke".to_string(),
            None,
            &k.book.seal_key,
            [5; 32],
            [6; 24],
        ),
    };
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    let done = k
        .runtime
        .block_on(async move { revoke_capability(db, &ctx, book, req).await })
        .expect("kernel")
        .expect("revoked");
    assert!(!done.already_recorded, "step {step}: a fresh token");
}

/// A dual-controlled activation of the embedded policy: the security policy
/// epoch advances, so every earlier approval is stale.
fn kernel_activate(k: &mut Kernel, step: u64) {
    let key = format!("activate-{step}");
    let proposal = activation_proposal(
        &k.book,
        PRINCIPAL,
        fa_journal::policy::steward().expect("policy").policy_oid,
        control_day(),
        key.as_bytes(),
        Erasable::seal(
            &"activate".to_string(),
            None,
            &k.book.seal_key,
            [7; 32],
            [8; 24],
        ),
    );
    let digest = proposal.proposal_digest().expect("digest");
    let approvals = vec![
        kernel_approve_as(
            k,
            Capability::embedded(VId(71), &["approve"]).expect("approve"),
            digest,
        ),
        kernel_approve_as(
            k,
            Capability::embedded(VId(72), &["approve"]).expect("approve"),
            digest,
        ),
    ];
    let req = ActivationRequest {
        proposal,
        capability: Capability::embedded(PRINCIPAL, &["post", "rule_change"]).expect("controller"),
        approvals,
    };
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    k.runtime
        .block_on(async move { activate_policy(db, &ctx, book, req).await })
        .expect("kernel")
        .expect("activated");
}

/// One transition by `PRINCIPAL` giving `reason` under `capability`, citing
/// `approvals`.
fn kernel_transition_under(
    k: &mut Kernel,
    code: &str,
    t: PeriodTransition,
    step: u64,
    reason: u16,
    capability: &Capability,
    approvals: &[fa_model::ApprovalRef],
) -> Result<Transitioned, Refusal> {
    let key = format!("t-{step}");
    let description = period_description(k);
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    k.runtime
        .block_on(async move {
            transition_period(
                db,
                &ctx,
                book,
                code,
                t,
                PRINCIPAL,
                reason,
                key.as_bytes(),
                description,
                capability,
                approvals,
            )
            .await
        })
        .expect("kernel")
}

/// The approvals a transition keyed by `step` needs. Lock and Reopen are
/// dual-controlled (sod_policy.toml, fa-llx): a second Human approves exactly
/// the proposal the transition will commit, so the random walk keeps
/// exercising Locked periods. The case-bound reopens still refuse, in both
/// engines.
fn transition_approvals(
    k: &mut Kernel,
    code: &str,
    t: PeriodTransition,
    step: u64,
) -> Vec<fa_model::ApprovalRef> {
    let from =
        k.db.vertex(fa_model::period_vid(&k.book.calendar.id, code))
            .expect("read")
            .map(|row| PeriodRow::decode(&row).expect("period row").state);
    match (from, t) {
        (Some(from), PeriodTransition::Lock | PeriodTransition::Reopen { .. }) => {
            match fa_time::period::transition(from, t) {
                Ok(to) => {
                    let digest = period_digest(k, code, from, to, step);
                    vec![kernel_approve(k, digest)]
                }
                Err(_) => Vec::new(),
            }
        }
        _ => Vec::new(),
    }
}

fn kernel_transition(
    k: &mut Kernel,
    code: &str,
    t: PeriodTransition,
    step: u64,
) -> Result<Transitioned, Refusal> {
    let approvals = transition_approvals(k, code, t, step);
    kernel_transition_under(
        k,
        code,
        t,
        step,
        1,
        &Capability::embedded(PRINCIPAL, &["close", "reopen", "post"]).expect("ops"),
        &approvals,
    )
}

/// fa-cvg: once the period law admits a transition, its reason must be
/// registered in its scope (`period_control`, or `period_reopen` for a
/// reopen), in both engines. At every step of a period's life (open, soft
/// close, reopen, soft close, close, lock) each unregistered reason is
/// refused FA-REF-041 with an unchanged frontier, and the registered reason
/// then moves both engines.
#[test]
fn kernel_and_oracle_agree_on_period_transition_reasons() {
    let (mut k, mut oracle, periods) = setup();
    let code = periods[4].clone();
    let capability = Capability::embedded(PRINCIPAL, &["close", "reopen"]).expect("ops");
    let control = [0, 4, 99, u16::MAX];
    let steps = [
        (PeriodTransition::Open, control),
        (PeriodTransition::SoftClose, control),
        (
            PeriodTransition::Reopen {
                to: PeriodState::Open,
            },
            [0, 5, 99, u16::MAX],
        ),
        (PeriodTransition::SoftClose, control),
        (PeriodTransition::Close, control),
        (PeriodTransition::Lock, control),
    ];
    for (i, (t, unregistered)) in steps.into_iter().enumerate() {
        for (j, reason) in unregistered.into_iter().enumerate() {
            let before = k.db.frontier().unwrap();
            let step = 50_000 + 10 * i as u64 + j as u64;
            let kernel = kernel_transition_under(&mut k, &code, t, step, reason, &capability, &[])
                .expect_err("an unregistered reason is refused");
            let model = oracle
                .transition_with_reason(&code, t, reason)
                .expect_err("the oracle refuses an unregistered reason");
            assert_eq!(
                (kernel.code, kernel.exit),
                (model, fa_journal::refusal::exit::REFUSAL),
                "{code} {t:?} reason {reason}: {kernel}"
            );
            assert_eq!(
                k.db.frontier().unwrap(),
                before,
                "{code} {t:?} reason {reason}: nothing written"
            );
        }
        let kernel = kernel_transition(&mut k, &code, t, 50_100 + i as u64)
            .expect("the registered reason 1 admits");
        let model = oracle
            .transition_with_reason(&code, t, 1)
            .expect("the oracle admits reason 1");
        assert_eq!((kernel.from, kernel.to), model, "{code} {t:?}");
    }
}

#[test]
fn kernel_and_oracle_agree_on_a_generated_history() {
    generated_history_campaign(0x9E37_79B9_7F4A_7C15, false)
        .assert_minimums("seed 0x9e3779b97f4a7c15");
}

/// fa-2ihd: the same campaign, every assertion included, over more seeds.
/// Tier 1 runs 8 seeds; `FA_DIFFERENTIAL_SEEDS=<n>` runs n (tier 2), from
/// `FA_DIFFERENTIAL_SEED_FROM=<k>` for a shard ([`seed_indices`]). Each seed
/// builds its own book and history, and a divergence names its seed.
#[test]
fn kernel_and_oracle_agree_on_generated_histories_across_seeds() {
    let seeds = seed_indices();
    let mut total = Coverage::default();
    for i in seeds.clone() {
        let seed = splitmix(i);
        match std::panic::catch_unwind(|| generated_history_campaign(seed, true)) {
            Ok(coverage) => total.add(&coverage),
            Err(_) => {
                panic!(
                    "the generated history diverged at seed {seed:#018x} (index {i} of {seeds:?})"
                )
            }
        }
    }
    // One seed's luck decides how often each plant fires; across the seeds
    // the campaign must still reach every one of a single seed's minimums.
    eprintln!(
        "fa-2ihd coverage over seed indices {seeds:?}: {} (class, state, outcome) cells: {:?}",
        total.cells.len(),
        total.cells
    );
    total.assert_minimums(&format!("seed indices {seeds:?}"));
    total.assert_coverage(&format!("seed indices {seeds:?}"));
}

/// Delta debugging (Zeller and Hildebrandt's ddmin, complements first) over
/// a failing schedule: a subset of its steps that still `fails`, from which
/// removing any one chunk at the final granularity no longer fails.
fn ddmin(mut steps: Vec<TraceStep>, fails: &dyn Fn(&[TraceStep]) -> bool) -> Vec<TraceStep> {
    let mut n = 2usize;
    while steps.len() >= 2 {
        let chunk = steps.len().div_ceil(n);
        // The first chunk whose removal still fails, as its complement.
        let reduced = (0..n).find_map(|i| {
            let start = i * chunk;
            if start >= steps.len() {
                return None;
            }
            let end = (start + chunk).min(steps.len());
            let complement: Vec<TraceStep> = steps[..start]
                .iter()
                .chain(&steps[end..])
                .copied()
                .collect();
            (!complement.is_empty() && fails(&complement)).then_some(complement)
        });
        match reduced {
            Some(complement) => {
                steps = complement;
                n = n.saturating_sub(1).max(2);
            }
            None => {
                if n >= steps.len() {
                    break;
                }
                n = (n * 2).min(steps.len());
            }
        }
    }
    steps
}

/// The panic message of a campaign that failed, or `None` when it passed.
fn campaign_failure(
    seed: u64,
    schedule: Schedule<'_>,
    plant: Option<&'static str>,
) -> Option<String> {
    let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        campaign(seed, schedule, plant, false)
    }));
    run.err().map(|payload| {
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
            .unwrap_or_default()
    })
}

/// fa-2ihd acceptance (found and shrunk): a planted divergence, the harness
/// treating the period law's closed-period refusal (FA-REF-011) as a
/// disagreement, which is what a kernel admitting an Original in a Closed
/// period produces (registries/mutants.toml MUT-035 is that kernel
/// mutation), is found on the canonical seed's history and shrunk by ddmin
/// to at most 10 steps that still diverge at the same step. The reproducer
/// (seed and steps) is printed.
#[test]
fn planted_mutation_found_and_shrunk() {
    let seed = 0x9E37_79B9_7F4A_7C15;
    let plant = Some("FA-REF-011");
    let trace = campaign(seed, Schedule::All, None, false).trace;
    assert_eq!(trace.len(), 640);
    let full = campaign_failure(seed, Schedule::Steps(&trace), plant)
        .expect("the canonical history reaches a closed-period refusal");
    let at = full
        .split("step ")
        .nth(1)
        .and_then(|rest| rest.split(':').next())
        .and_then(|n| n.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("no step in {full}"));
    assert!(full.contains("planted divergence: FA-REF-011"), "{full}");
    let marker = format!("step {at}: planted divergence: FA-REF-011");
    let fails = |kept: &[TraceStep]| {
        campaign_failure(seed, Schedule::Steps(kept), plant).is_some_and(|m| m.contains(&marker))
    };
    let prefix: Vec<TraceStep> = trace.iter().copied().filter(|s| s.step <= at).collect();
    assert!(fails(&prefix), "the replayed prefix reproduces {marker}");
    let shrunk = ddmin(prefix, &fails);
    let steps: Vec<u64> = shrunk.iter().map(|s| s.step).collect();
    eprintln!("fa-2ihd reproducer: seed {seed:#x}, steps {steps:?} ({marker})");
    assert!(
        shrunk.len() <= 10,
        "shrunk to {} steps: {steps:?}",
        shrunk.len()
    );
    assert!(fails(&shrunk), "the shrunk schedule still diverges");
    assert!(steps.contains(&at), "{steps:?}");
}

/// ddmin over a synthetic predicate: the steps it needs, and only those.
#[test]
fn ddmin_keeps_exactly_the_steps_a_failure_needs() {
    let steps: Vec<TraceStep> = (0..100u64)
        .map(|step| TraceStep {
            step,
            state: step,
            plant: None,
        })
        .collect();
    let needed = [3u64, 41, 97];
    let fails = |kept: &[TraceStep]| needed.iter().all(|n| kept.iter().any(|s| s.step == *n));
    let shrunk = ddmin(steps, &fails);
    assert_eq!(
        shrunk.iter().map(|s| s.step).collect::<Vec<_>>(),
        needed.to_vec()
    );
}

/// What one generated history exercised, so that agreement is not vacuous.
#[derive(Debug, Default)]
struct Coverage {
    evidence_refused: BTreeMap<&'static str, u32>,
    posted: u32,
    recorded: u32,
    posted_holds: u32,
    applications_posted: u32,
    undone: u32,
    resolutions: (u32, u32),
    refused: BTreeSet<&'static str>,
    explained_legs: usize,
    march_cash_history: usize,
    open_item_legs: usize,
    corruption_planted: u32,
    /// Committed entries and transitions the serial replay re-admitted.
    serial_replayed: usize,
    /// The coverage map: (class, period state before the post, outcome)
    /// cells the history hit (fa-2ihd).
    cells: BTreeSet<(String, &'static str, &'static str)>,
    /// The steps run, for replay and shrinking (never summed).
    trace: Vec<TraceStep>,
}

impl Coverage {
    fn add(&mut self, other: &Coverage) {
        for (code, count) in &other.evidence_refused {
            *self.evidence_refused.entry(code).or_insert(0) += count;
        }
        self.posted += other.posted;
        self.recorded += other.recorded;
        self.posted_holds += other.posted_holds;
        self.applications_posted += other.applications_posted;
        self.undone += other.undone;
        self.resolutions.0 += other.resolutions.0;
        self.resolutions.1 += other.resolutions.1;
        self.refused.extend(other.refused.iter().copied());
        self.explained_legs += other.explained_legs;
        self.march_cash_history += other.march_cash_history;
        self.open_item_legs += other.open_item_legs;
        self.corruption_planted += other.corruption_planted;
        self.serial_replayed += other.serial_replayed;
        self.cells.extend(other.cells.iter().cloned());
    }

    fn assert_minimums(&self, what: &str) {
        // Every evidence refusal the plants aim at was produced.
        for code in ["FA-REF-080", "FA-REF-081", "FA-REF-082", "FA-REF-086"] {
            assert!(
                self.evidence_refused.get(code).copied().unwrap_or(0) >= 3,
                "{what}: evidence plant {code}: {:?}",
                self.evidence_refused
            );
        }
        // The history exercised every outcome kind.
        assert!(self.posted >= 30, "{what}: posted {}", self.posted);
        assert!(self.recorded >= 3, "{what}: recorded {}", self.recorded);
        assert!(
            self.posted_holds >= 5,
            "{what}: holds {}",
            self.posted_holds
        );
        assert!(
            self.applications_posted >= 5,
            "{what}: applications {}",
            self.applications_posted
        );
        assert!(self.undone >= 1, "{what}: no reversal undid an application");
        assert!(
            self.resolutions.0 >= 3 && self.resolutions.1 >= 3,
            "{what}: resolutions (posts, voids) {:?}",
            self.resolutions
        );
        for must in [
            "FA-REF-001",
            "FA-REF-010",
            "FA-REF-032",
            "FA-REF-051",
            "FA-REF-060",
            "FA-REF-061",
            "FA-REF-062",
            "FA-REF-070",
            "FA-REF-071",
            "FA-REF-072",
            "FA-REF-073",
            "FA-REF-102",
            "FA-REF-160",
        ] {
            assert!(
                self.refused.contains(must),
                "{what}: refusal {must} never exercised: {:?}",
                self.refused
            );
        }
        assert!(
            self.explained_legs > 0,
            "{what}: the history explains no legs"
        );
        assert!(
            self.march_cash_history > 3,
            "{what}: March cash has a history of {}",
            self.march_cash_history
        );
        assert!(self.open_item_legs > 0, "{what}: no open-item leg checked");
        assert!(
            self.corruption_planted >= 1,
            "{what}: no live leg had an application to corrupt"
        );
        assert!(
            self.serial_replayed > self.posted as usize,
            "{what}: the serial replay re-admitted {} of {} posts and their transitions",
            self.serial_replayed,
            self.posted
        );
    }

    /// The coverage map against Appendix C: every (class, state) cell the
    /// matrix admits under an op the generator grants, with no approvals,
    /// posted at least once, and every other cell was refused at least once.
    fn assert_coverage(&self, what: &str) {
        let matrix = fa_registry::Admissibility::embedded(
            &fa_registry::EntryClasses::embedded().expect("entry_classes.toml"),
        )
        .expect("admissibility.toml");
        for class in STEERED {
            for state in fa_registry::ALL_STATES {
                let admits = admitting_op(&matrix, class, state).is_some();
                let wanted = |outcome: &str| {
                    if admits {
                        outcome == "posted"
                    } else {
                        outcome.starts_with("FA-REF-")
                    }
                };
                assert!(
                    self.cells
                        .iter()
                        .any(|(c, s, o)| c == class && *s == state.name() && wanted(o)),
                    "{what}: {class} in a {} period never {}; cells: {:?}",
                    state.name(),
                    if admits { "posted" } else { "refused" },
                    self.cells
                );
            }
        }
    }
}

/// A nonzero xorshift seed derived from `i` (SplitMix64).
/// The seed indices both multi-seed campaigns run: `FA_DIFFERENTIAL_SEEDS=<n>`
/// of them (8, tier 1, by default) from `FA_DIFFERENTIAL_SEED_FROM=<k>` (1 by
/// default). A tier-2 run splits into disjoint shards across workers whose
/// ranges together cover 1..=N, each shard's seeds the ones a single run
/// would draw.
fn seed_indices() -> std::ops::Range<u64> {
    let var = |name: &str, default: u64| {
        std::env::var(name)
            .ok()
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(default)
    };
    let from = var("FA_DIFFERENTIAL_SEED_FROM", 1).max(1);
    from..from.saturating_add(var("FA_DIFFERENTIAL_SEEDS", 8))
}

fn splitmix(i: u64) -> u64 {
    let mut z = i.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    (z ^ (z >> 31)) | 1
}

/// One generated history: 640 random steps of posts, holds, resolutions,
/// reversals, replacements, invoices and receipts and period transitions,
/// each compared with the reference oracle, then the registers, open items
/// and planted corruption. Returns what it exercised.
///
/// `steering` aims some draws at unhit Appendix C cells (the multi-seed
/// coverage campaign). Off, the generator draws exactly as it did before
/// steering existed, so the canonical seed's history, its per-seed floors
/// and the shrinker's reproducer stay what they were.
fn generated_history_campaign(seed: u64, steering: bool) -> Coverage {
    campaign(seed, Schedule::All, None, steering)
}

/// The classes coverage steering aims at, and the ops it may grant.
const STEERED: [&str; 5] = ["Original", "Adjusting", "Pending", "Reversal", "Resolution"];
const GRANTED: [&str; 3] = ["post", "post_closed", "post_softclosed"];

/// The op a generated post of `class` needs in a period of `state` under
/// Appendix C, when the generator can grant it: `post` where the cell
/// admits, the cell's op where it needs one and no approvals; `None`
/// otherwise.
fn admitting_op(
    matrix: &fa_registry::Admissibility,
    class: &str,
    state: PeriodState,
) -> Option<&'static str> {
    match matrix.decide(class, state)? {
        fa_registry::Decision::Admit => Some("post"),
        fa_registry::Decision::With { op, approvals: 0 } => {
            GRANTED.iter().copied().find(|g| *g == op.as_str())
        }
        _ => None,
    }
}

/// Coverage steering's target: the first admissible (class, state) cell the
/// history has not posted whose state some period is in now, as the class,
/// a day in that period, and the op to grant.
fn unposted_cell(
    matrix: &fa_registry::Admissibility,
    cells: &BTreeSet<(String, &'static str, &'static str)>,
    oracle: &Oracle,
    defs: &[fa_time::period::PeriodDef],
    dates: &[DateDay; 4],
) -> Option<(&'static str, DateDay, &'static str)> {
    STEERED.iter().find_map(|class| {
        dates.iter().find_map(|day| {
            let period = fa_time::period::resolve_period(defs, *day, None).ok()?;
            let state = oracle.period_state(&period.code)?;
            let op = admitting_op(matrix, class, state)?;
            let posted = cells.contains(&((*class).to_string(), state.name(), "posted"));
            (!posted).then_some((*class, *day, op))
        })
    })
}

/// Which steps a campaign runs. `All` is the full 640-step history and
/// records each step in `Coverage::trace`. `Steps` replays chosen steps of
/// such a trace, each from its recorded generator state and with the plant
/// it fired then, so a subset is the same history less the skipped steps:
/// the input the shrinker reduces.
#[derive(Clone, Copy)]
enum Schedule<'a> {
    All,
    Steps(&'a [TraceStep]),
}

/// One step of a full run: its index, the generator state it started from,
/// and the deterministic plant it fired (a planted refusal fires at the first
/// step its precondition holds, so a replay fires it only where it fired).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TraceStep {
    step: u64,
    state: u64,
    plant: Option<&'static str>,
}

/// The campaign under `schedule`. `plant` names a refusal code the harness
/// treats as a divergence (`step N: planted divergence`), standing in for a
/// kernel that admits what the oracle refuses, so the shrinker can be
/// exercised without mutating the kernel.
fn campaign(
    seed: u64,
    schedule: Schedule<'_>,
    plant: Option<&'static str>,
    steering: bool,
) -> Coverage {
    let (mut k, mut oracle, periods) = setup();
    let usd = k.book.units.lookup("USD").unwrap();
    // The serial replay starts from the book as set up, and replays each
    // committed key under the ops it was posted with.
    let genesis = oracle.clone();
    let since = k.db.frontier().unwrap();
    let mut authority: BTreeMap<Vec<u8>, Vec<String>> = BTreeMap::new();
    let period_defs = k.book.calendar.periods_for_year(2026).unwrap();
    let matrix = fa_registry::Admissibility::embedded(
        &fa_registry::EntryClasses::embedded().expect("entry_classes.toml"),
    )
    .expect("admissibility.toml");
    let mut cells: BTreeSet<(String, &'static str, &'static str)> = BTreeSet::new();
    let mut rng = Rng(seed);
    let dates = [
        DateDay::from_ymd(2026, 2, 10).unwrap(),
        DateDay::from_ymd(2026, 3, 15).unwrap(),
        DateDay::from_ymd(2026, 3, 31).unwrap(),
        DateDay::from_ymd(2026, 4, 2).unwrap(),
    ];
    let classes = [
        "Original",
        "Original",
        "Original",
        "Adjusting",
        "Reversal",
        "Reversal",
        "Replacement",
        "Pending",
        "Pending",
        "Resolution",
        "Resolution",
        "Resolution",
        "Invoice",
        "Invoice",
        "Receipt",
        "Receipt",
        "Receipt",
    ];
    let leaf_codes = ["1000", "6000", "4000"];
    let mut history: Vec<Intent> = Vec::new();
    let mut posted_intents: Vec<Intent> = Vec::new();
    let mut reversed_targets: BTreeSet<usize> = BTreeSet::new();
    // Journal indexes of posted holds, and of holds that have a resolution.
    let mut holds: Vec<usize> = Vec::new();
    let mut resolved_targets: BTreeSet<usize> = BTreeSet::new();
    let mut posted_holds = 0u32;
    let mut posted_resolutions = (0u32, 0u32); // (Posts, Voids)
    // Journal indexes of posted invoices (Dr 1200 / Cr 4000) and counts of
    // posted applications and of reversals that undid one.
    let mut invoices: Vec<usize> = Vec::new();
    // Planted negative: the first Posts resolution against an open hold is
    // deliberately malformed (FA-REF-061), so the shape law is exercised on
    // every seed rather than by luck.
    let mut planted_shape = false;
    // Planted negatives: each of these refusals is produced deterministically
    // at the first step where its precondition holds, then removed; the rest
    // of the history is random. Coverage by construction, not by seed luck.
    let mut needed: BTreeSet<&'static str> = [
        "FA-REF-032",
        "FA-REF-070",
        "FA-REF-071",
        "FA-REF-072",
        "FA-REF-073",
    ]
    .into_iter()
    .collect();
    let mut applications_posted = 0u32;
    let mut undone = 0u32;
    // Kernel handles of posted entries, indexed like the oracle's journal.
    let mut refs: Vec<EntryRef> = Vec::new();
    let mut posted = 0u32;
    let mut recorded = 0u32;
    let mut refused: BTreeMap<&'static str, u32> = BTreeMap::new();
    // Planted evidence negatives (fa-lp6): the documents the evidence oracle
    // holds are the kernel's two fixtures; `ghost` was never recorded.
    let evidence_law = fa_reference::evidence::Law::embedded().expect("evidence registries");
    let held: BTreeMap<u64, fa_reference::evidence::Doc> = [
        (1u64, k.evidence[0], "HumanUpload"),
        (2u64, k.agent_evidence, "AgentUpload"),
    ]
    .into_iter()
    .map(|(id, e, grade)| {
        (
            id,
            fa_reference::evidence::Doc {
                kind: "Invoice".into(),
                grade: grade.into(),
                commit: e.doc_commit,
                uploader: 7,
                custody: fa_reference::evidence::Custody::uploaded(),
            },
        )
    })
    .collect();
    let ghost = Document {
        book_id: k.book.book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: b"an invoice nobody recorded".to_vec(),
    }
    .evidence_ref(1);
    let mut evidence_refused: BTreeMap<&'static str, u32> = BTreeMap::new();
    let mut evidence_plants = 0u32;

    let steps: Vec<(u64, Option<TraceStep>)> = match schedule {
        Schedule::All => (0..640u64).map(|s| (s, None)).collect(),
        Schedule::Steps(kept) => kept.iter().map(|s| (s.step, Some(*s))).collect(),
    };
    let mut trace: Vec<TraceStep> = Vec::with_capacity(steps.len());
    for (step, replay) in steps {
        if let Some(r) = replay {
            rng.0 = r.state;
        }
        trace.push(TraceStep {
            step,
            state: rng.0,
            plant: None,
        });
        // A full run plants each refusal at the first step its precondition
        // holds (`needed`); a replay plants only where the full run did.
        let wants = |code: &str| match replay {
            None => needed.contains(code),
            Some(r) => r.plant == Some(code),
        };
        let mut fired: Option<&'static str> = None;
        if rng.chance(15) {
            let code = periods[1 + rng.below(3) as usize].clone(); // Feb, Mar, Apr
            // Closed and Locked are absorbing until restatement cases land
            // (fa-llx: Closed/Locked -> Reopen is case-bound, fa-oz3), so
            // only February closes and locks. For March and April the close
            // and lock draws become an approved SoftClosed -> Reopen, so they
            // stay mostly Open and keep taking posts and holds. The draw
            // itself is unchanged.
            let closable = code == periods[1];
            let t = match rng.below(5) {
                0 => PeriodTransition::Open,
                1 => PeriodTransition::SoftClose,
                2 | 3 if !closable => PeriodTransition::Reopen {
                    to: PeriodState::Open,
                },
                2 => PeriodTransition::Close,
                3 => PeriodTransition::Lock,
                _ => PeriodTransition::Reopen {
                    to: PeriodState::Open,
                },
            };
            let kernel = kernel_transition(&mut k, &code, t, step);
            let model = oracle.transition(&code, t);
            match (kernel, model) {
                (Ok(tr), Ok((from, to))) => {
                    assert_eq!(
                        (tr.from, tr.to),
                        (from, to),
                        "step {step}: transition {code} {t:?}"
                    );
                    // fa-87r: both engines date the control by its period.
                    if !tr.already_recorded {
                        assert_eq!(
                            Some(journaled_date(&k, tr.control_entry)),
                            oracle.transition_date(&code, t),
                            "step {step}: transition {code} {t:?} control date"
                        );
                    }
                }
                (Err(r), Err(c)) => {
                    assert_eq!(r.code, c, "step {step}: transition refusal {code} {t:?}")
                }
                (kr, mr) => assert_eq!(
                    format!("kernel {kr:?}"),
                    format!("oracle {mr:?}"),
                    "step {step}: transition {code} {t:?} disagreement"
                ),
            }
            continue;
        }

        let open_now = oracle.open_items();
        let mut planted: Option<Intent> = None;
        let fresh_key = format!("planted-{step}").into_bytes();
        let leg = |side: fa_reference::Side, account: &str, mantissa: i128| Leg {
            side,
            account: account.into(),
            unit: usd.0,
            entity: None,
            mantissa,
        };
        if wants("FA-REF-032")
            && let Some(plain) = posted_intents
                .iter()
                .find(|i| i.reverses.is_none() && i.resolves.is_none() && i.settles.is_empty())
        {
            // Same key, different date: an idempotency conflict.
            let mut again = plain.clone();
            again.date = if again.date == dates[0] {
                dates[1]
            } else {
                dates[0]
            };
            planted = Some(again);
            fired = Some("FA-REF-032");
        } else if wants("FA-REF-073")
            && let Some((i, _)) = invoices
                .iter()
                .filter_map(|i| open_now.get(&(*i, 0)).map(|(_, a, _)| (*i, *a)))
                .find(|(_, applied)| *applied > 0)
        {
            // Reversing an invoice with a live application.
            let original = oracle.entry(i).expect("posted invoice");
            fired = Some("FA-REF-073");
            planted = Some(Intent {
                class: "Reversal".into(),
                date: dates[1],
                discriminator: None,
                legs: original
                    .legs
                    .iter()
                    .map(|l| leg(l.side.flipped(), &l.account, l.mantissa))
                    .collect(),
                key: fresh_key.clone(),
                ops: vec!["post".into(), "post_closed".into()],
                approvals: 0,
                reverses: Some(i),
                supersession_reason: 1,
                resolves: None,
                settles: Vec::new(),
            });
        } else if (wants("FA-REF-072") || wants("FA-REF-071"))
            && let Some((i, open)) = invoices
                .iter()
                .filter_map(|i| open_now.get(&(*i, 0)).map(|(o, a, out)| (*i, o - out - a)))
                .find(|(_, open)| *open > 0)
        {
            // Over the open amount (072) or against the revenue leg (071).
            let (amount, ordinal) = if wants("FA-REF-072") {
                fired = Some("FA-REF-072");
                (open + 1, 0)
            } else {
                fired = Some("FA-REF-071");
                (1, 1)
            };
            planted = Some(Intent {
                class: "Original".into(),
                date: dates[1],
                discriminator: None,
                legs: vec![
                    leg(fa_reference::Side::Debit, "1000", amount),
                    leg(fa_reference::Side::Credit, "1200", amount),
                ],
                key: fresh_key.clone(),
                ops: vec!["post".into(), "post_closed".into()],
                approvals: 0,
                reverses: None,
                supersession_reason: 1,
                resolves: None,
                settles: vec![Settle {
                    leg: 1,
                    target: i,
                    ordinal,
                    mantissa: amount,
                }],
            });
        } else if wants("FA-REF-070")
            && let Some(h) = holds.first()
        {
            // A hold is not an open item.
            fired = Some("FA-REF-070");
            planted = Some(Intent {
                class: "Original".into(),
                date: dates[1],
                discriminator: None,
                legs: vec![
                    leg(fa_reference::Side::Debit, "1000", 7),
                    leg(fa_reference::Side::Credit, "1200", 7),
                ],
                key: fresh_key,
                ops: vec!["post".into(), "post_closed".into()],
                approvals: 0,
                reverses: None,
                supersession_reason: 1,
                resolves: None,
                settles: vec![Settle {
                    leg: 1,
                    target: *h,
                    ordinal: 1,
                    mantissa: 7,
                }],
            });
        }
        // Retry an earlier intent: identical (expect recorded) or with a
        // different date (expect an idempotency conflict).
        let intent = if let Some(p) = planted {
            p
        } else if !history.is_empty() && rng.chance(12) {
            if rng.chance(50) && !posted_intents.is_empty() {
                // An exact resubmission of something that posted: recorded.
                posted_intents[rng.below(posted_intents.len() as u64) as usize].clone()
            } else {
                // The same key with a different date: a conflict (or the
                // same refusal as before, when the original never posted).
                let mut again = history[rng.below(history.len() as u64) as usize].clone();
                again.date = dates[rng.below(4) as usize];
                again
            }
        } else {
            // Coverage steering (fa-2ihd): now and then the draw aims at an
            // admissible (class, state) cell this history has not posted,
            // dated into a period in that state under the op its Appendix C
            // cell needs.
            let steer = if steering && rng.chance(20) {
                unposted_cell(&matrix, &cells, &oracle, &period_defs, &dates)
            } else {
                None
            };
            let class = match steer {
                Some((class, ..)) => class,
                None => classes[rng.below(classes.len() as u64) as usize],
            };
            // The ops a capability grants: post alone, or with the op a
            // Closed or a SoftClosed period requires.
            let ops: Vec<String> = match steer {
                Some((_, _, "post")) => vec!["post".into()],
                Some((_, _, op)) => vec!["post".into(), op.into()],
                None if rng.chance(35) => vec!["post".into(), "post_closed".into()],
                None if steering && rng.chance(30) => {
                    vec!["post".into(), "post_softclosed".into()]
                }
                None => vec!["post".into()],
            };
            let key = format!("k{step}").into_bytes();
            let mut drawn = if class == "Invoice" {
                let amount = 1_000 + rng.below(90_000) as i128;
                Intent {
                    class: "Original".into(),
                    date: dates[rng.below(4) as usize],
                    discriminator: None,
                    legs: vec![
                        Leg {
                            side: fa_reference::Side::Debit,
                            account: "1200".into(),
                            unit: usd.0,
                            entity: None,
                            mantissa: amount,
                        },
                        Leg {
                            side: fa_reference::Side::Credit,
                            account: "4000".into(),
                            unit: usd.0,
                            entity: None,
                            mantissa: amount,
                        },
                    ],
                    key,
                    ops,
                    approvals: 0,
                    reverses: None,
                    supersession_reason: 1,
                    resolves: None,
                    settles: Vec::new(),
                }
            } else if class == "Receipt" && !refs.is_empty() {
                // A receipt applies its credit leg to an open invoice leg:
                // mostly within the open amount, sometimes over it
                // (FA-REF-072), sometimes to the revenue leg (071), sometimes
                // to a non-invoice or a reversed one (070).
                let open_now = oracle.open_items();
                let live_invoices: Vec<(usize, i128)> = invoices
                    .iter()
                    .filter_map(|i| {
                        open_now
                            .get(&(*i, 0))
                            .map(|(orig, applied, out)| (*i, orig - out - applied))
                            .filter(|(_, open)| *open > 0)
                    })
                    .collect();
                let (target, open) = if !live_invoices.is_empty() && rng.chance(85) {
                    live_invoices[rng.below(live_invoices.len() as u64) as usize]
                } else {
                    (rng.below(refs.len() as u64) as usize, 0)
                };
                let amount = if open > 0 && rng.chance(75) {
                    1 + rng.below(open as u64) as i128
                } else {
                    open + 1 + rng.below(5_000) as i128
                };
                let ordinal = if rng.chance(10) { 1 } else { 0 };
                Intent {
                    class: "Original".into(),
                    date: dates[rng.below(4) as usize],
                    discriminator: None,
                    legs: vec![
                        Leg {
                            side: fa_reference::Side::Debit,
                            account: "1000".into(),
                            unit: usd.0,
                            entity: None,
                            mantissa: amount,
                        },
                        Leg {
                            side: fa_reference::Side::Credit,
                            account: "1200".into(),
                            unit: usd.0,
                            entity: None,
                            mantissa: amount,
                        },
                    ],
                    key,
                    ops,
                    approvals: 0,
                    reverses: None,
                    supersession_reason: 1,
                    resolves: None,
                    settles: vec![Settle {
                        leg: 1,
                        target,
                        ordinal,
                        mantissa: amount,
                    }],
                }
            } else if class == "Resolution" && !refs.is_empty() {
                // Prefer an unresolved hold, so the resolution law itself is
                // exercised; sometimes a posted non-hold (FA-REF-060) or an
                // already-resolved hold (FA-REF-062).
                let open: Vec<usize> = holds
                    .iter()
                    .copied()
                    .filter(|i| !resolved_targets.contains(i))
                    .collect();
                let shape_due = match replay {
                    None => !planted_shape,
                    Some(r) => r.plant == Some("FA-REF-061"),
                };
                let force_shape = shape_due && !open.is_empty();
                if force_shape {
                    fired = Some("FA-REF-061");
                }
                let target = if force_shape || (!open.is_empty() && rng.chance(80)) {
                    open[rng.below(open.len() as u64) as usize]
                } else {
                    rng.below(refs.len() as u64) as usize
                };
                let original = oracle.entry(target).expect("posted entry");
                let (legs, posts) = if force_shape || rng.chance(50) {
                    // A balanced sub-vector: a total t ≤ T allocated greedily
                    // over the debit legs and over the credit legs, in order.
                    let total: i128 = original
                        .legs
                        .iter()
                        .filter(|l| l.side == fa_reference::Side::Debit)
                        .map(|l| l.mantissa)
                        .sum();
                    let t = 1 + rng.below(total.max(1) as u64) as i128;
                    let mut legs: Vec<Leg> = Vec::new();
                    let mut ordinals: Vec<u16> = Vec::new();
                    let mut remaining = [t, t];
                    for (i, l) in original.legs.iter().enumerate() {
                        let slot = if l.side == fa_reference::Side::Debit {
                            0
                        } else {
                            1
                        };
                        let take = remaining[slot].min(l.mantissa);
                        if take > 0 {
                            remaining[slot] -= take;
                            legs.push(Leg {
                                side: l.side,
                                account: l.account.clone(),
                                unit: l.unit,
                                entity: l.entity.clone(),
                                mantissa: take,
                            });
                            ordinals.push(i as u16);
                        }
                    }
                    if (force_shape || rng.chance(25)) && !legs.is_empty() {
                        // Same amounts (still balanced), different account:
                        // not drawn from the hold (FA-REF-061).
                        legs[0].account = if legs[0].account == "1000" {
                            "6000".into()
                        } else {
                            "1000".into()
                        };
                    }
                    (legs, Some(ordinals))
                } else {
                    (Vec::new(), None)
                };
                Intent {
                    class: class.into(),
                    date: dates[rng.below(4) as usize],
                    discriminator: None,
                    legs,
                    key,
                    ops,
                    approvals: 0,
                    reverses: None,
                    supersession_reason: 1,
                    resolves: Some(Resolve { target, posts }),
                    settles: Vec::new(),
                }
            } else if class == "Reversal" && !refs.is_empty() {
                // Prefer a target nobody has reversed yet, so the reversal
                // law itself (shape, identity) is exercised, not only the
                // already-reversed conflict.
                let unreversed: Vec<usize> = (0..refs.len())
                    .filter(|i| !reversed_targets.contains(i))
                    .collect();
                let target = if !unreversed.is_empty() && rng.chance(80) {
                    unreversed[rng.below(unreversed.len() as u64) as usize]
                } else {
                    rng.below(refs.len() as u64) as usize
                };
                let original = oracle.entry(target).expect("posted entry");
                let mut legs: Vec<Leg> = original
                    .legs
                    .iter()
                    .map(|l| Leg {
                        side: l.side.flipped(),
                        account: l.account.clone(),
                        unit: l.unit,
                        entity: l.entity.clone(),
                        mantissa: l.mantissa,
                    })
                    .collect();
                if rng.chance(15) && !legs.is_empty() {
                    // Same amounts (still balanced), different account: not
                    // the exact side-swap. (A voided hold has no legs; its
                    // "reversal" is refused as a non-posted target.)
                    legs[0].account = if legs[0].account == "1000" {
                        "6000".into()
                    } else {
                        "1000".into()
                    };
                }
                Intent {
                    class: class.into(),
                    date: dates[rng.below(4) as usize],
                    discriminator: None,
                    legs,
                    key,
                    ops,
                    approvals: 0,
                    reverses: Some(target),
                    supersession_reason: 1,
                    resolves: None,
                    settles: Vec::new(),
                }
            } else {
                let class = if matches!(class, "Reversal" | "Resolution" | "Receipt") {
                    "Original"
                } else {
                    class
                };
                let n_legs = 2 + rng.below(3) as usize;
                let mut legs = Vec::with_capacity(n_legs);
                for i in 0..n_legs {
                    let account = if rng.chance(4) {
                        "1"
                    } else {
                        leaf_codes[rng.below(3) as usize]
                    };
                    let mantissa = 1 + rng.below(50_000) as i128;
                    let side = if i < n_legs - 1 && rng.chance(50) {
                        fa_reference::Side::Debit
                    } else {
                        fa_reference::Side::Credit
                    };
                    legs.push(Leg {
                        side,
                        account: account.into(),
                        unit: usd.0,
                        entity: None,
                        mantissa,
                    });
                }
                // Balance most of the time by fixing the last leg.
                let debits: i128 = legs[..n_legs - 1]
                    .iter()
                    .filter(|l| l.side == fa_reference::Side::Debit)
                    .map(|l| l.mantissa)
                    .sum();
                let credits: i128 = legs[..n_legs - 1]
                    .iter()
                    .filter(|l| l.side == fa_reference::Side::Credit)
                    .map(|l| l.mantissa)
                    .sum();
                if rng.chance(85) {
                    let last = &mut legs[n_legs - 1];
                    if debits > credits {
                        last.side = fa_reference::Side::Credit;
                        last.mantissa = debits - credits;
                    } else {
                        last.side = fa_reference::Side::Debit;
                        last.mantissa = (credits - debits).max(1);
                    }
                }
                let date = dates[rng.below(4) as usize];
                let discriminator =
                    (date == dates[2] && rng.chance(30)).then(|| "FY2026-A1".to_string());
                Intent {
                    class: class.into(),
                    date,
                    discriminator,
                    legs,
                    key,
                    ops,
                    approvals: 0,
                    reverses: None,
                    supersession_reason: 1,
                    resolves: None,
                    settles: Vec::new(),
                }
            };
            if let Some((_, day, _)) = steer {
                drawn.date = day;
                drawn.discriminator = None;
            }
            drawn
        };
        history.push(intent.clone());
        if let Some(last) = trace.last_mut() {
            last.plant = fired;
        }

        // The coverage cell: the class, the state its period was in before
        // the post (`None`: no period), and the reference's outcome.
        let state = fa_time::period::resolve_period(
            &period_defs,
            intent.date,
            intent.discriminator.as_deref(),
        )
        .ok()
        .and_then(|p| oracle.period_state(&p.code));
        let kernel = kernel_post(&mut k, &intent, usd, &refs);
        let model = oracle.post(&intent);
        cells.insert((
            intent.class.clone(),
            state.map_or("none", PeriodState::name),
            match &model {
                Verdict::Posted { .. } => "posted",
                Verdict::Recorded { .. } => "recorded",
                Verdict::Refused { code } => code,
            },
        ));
        match (&kernel, &model) {
            (
                Ok(Posted::Committed {
                    period, entry_ref, ..
                }),
                Verdict::Posted { period: p, index },
            ) => {
                assert_eq!(period, p, "step {step}: period");
                assert_eq!(*index, refs.len(), "step {step}: journal index");
                refs.push(*entry_ref);
                authority.insert(intent.key.clone(), intent.ops.clone());
                posted += 1;
                posted_intents.push(intent.clone());
                if let Some(t) = intent.reverses {
                    reversed_targets.insert(t);
                }
                if intent.class == "Pending" {
                    holds.push(*index);
                    posted_holds += 1;
                }
                if intent.class == "Original"
                    && intent.legs.len() == 2
                    && intent.legs[0].account == "1200"
                    && intent.settles.is_empty()
                {
                    invoices.push(*index);
                }
                if !intent.settles.is_empty() {
                    applications_posted += 1;
                }
                if let Some(t) = intent.reverses
                    && oracle.entry(t).is_some_and(|e| !e.settles.is_empty())
                {
                    undone += 1;
                }
                if let Some(r) = &intent.resolves {
                    resolved_targets.insert(r.target);
                    if r.posts.is_some() {
                        posted_resolutions.0 += 1;
                    } else {
                        posted_resolutions.1 += 1;
                    }
                }
            }
            (Ok(Posted::AlreadyRecorded { entry_ref, .. }), Verdict::Recorded { index }) => {
                assert_eq!(*entry_ref, refs[*index], "step {step}: recorded handle");
                recorded += 1;
            }
            (Err(r), Verdict::Refused { code }) => {
                assert_eq!(r.code, *code, "step {step}: refusal code for {intent:?}");
                assert!(
                    plant != Some(*code),
                    "step {step}: planted divergence: {code} on {intent:?}"
                );
                *refused.entry(code).or_insert(0) += 1;
                if *code == "FA-REF-061" {
                    planted_shape = true;
                }
                needed.remove(*code);
            }
            _ => assert_eq!(
                format!("kernel {kernel:?}"),
                format!("oracle {model:?}"),
                "step {step}: disagreement on {intent:?}"
            ),
        }
        let projections = verify_projections(&k.db, &k.book, None).unwrap();
        assert!(
            projections.is_green(),
            "step {step}: leg projections differ from payloads: {projections:?}"
        );
        // Planted evidence negatives (fa-lp6): a committed Original, Adjusting
        // or Pending without applications, copied under a fresh key and
        // citing nothing, only the agent's upload, a document never recorded,
        // or the source under a wrong commitment, reaches the evidence law
        // (step 5b follows the period law the original just passed) and is
        // refused with exactly the evidence oracle's code. Nothing is written,
        // so the history stays in step with the oracle.
        if matches!(
            (&kernel, &model),
            (Ok(Posted::Committed { .. }), Verdict::Posted { .. })
        ) && matches!(intent.class.as_str(), "Original" | "Adjusting" | "Pending")
            && intent.settles.is_empty()
        {
            let mut copy = intent.clone();
            copy.key.extend_from_slice(b"-ev");
            let mut wrong = k.evidence[0];
            wrong.doc_commit = [0; 32];
            let cite = |doc: u64, commit: [u8; 32]| fa_reference::evidence::Citation {
                doc,
                commit,
                role: 1,
            };
            let (evidence, citations) = match evidence_plants % 4 {
                0 => (Vec::new(), Vec::new()),
                1 => (
                    vec![k.agent_evidence],
                    vec![cite(2, k.agent_evidence.doc_commit)],
                ),
                2 => (vec![ghost], vec![cite(99, ghost.doc_commit)]),
                _ => (vec![wrong], vec![cite(1, [0; 32])]),
            };
            let expected = fa_reference::evidence::verdict(
                &evidence_law,
                &copy.class,
                &held,
                &citations,
                &fa_reference::evidence::Attestations::default(),
            )
            .expect("the evidence oracle refuses every plant");
            let r = kernel_post_citing(&mut k, &copy, usd, &refs, evidence)
                .expect_err("an evidence plant was admitted");
            assert_eq!(
                r.code,
                expected,
                "step {step}: evidence plant {} for {copy:?}",
                evidence_plants % 4
            );
            *evidence_refused.entry(expected).or_insert(0) += 1;
            evidence_plants += 1;
        }
    }

    // What the history exercised; the caller asserts the minimums (one
    // seed's, or the sum over many).
    let mut coverage = Coverage {
        evidence_refused,
        posted,
        recorded,
        posted_holds,
        applications_posted,
        undone,
        resolutions: posted_resolutions,
        trace,
        cells,
        ..Coverage::default()
    };
    // FA-REF-102: a registered class this slice does not post. Replacement
    // alone is refused as unpaired (FA-REF-160, fa-giar), so the generated
    // history no longer reaches 102; one deterministic Closing intent keeps
    // it compared, without perturbing the seeded histories above.
    {
        let closing = maintenance_intent(
            "Closing",
            DateDay::from_ymd(2026, 3, 15).unwrap(),
            100,
            "closing-plant",
        );
        let model = oracle.post(&closing);
        let kernel = kernel_post(&mut k, &closing, usd, &refs);
        match (&kernel, &model) {
            (Err(r), Verdict::Refused { code }) => {
                assert_eq!(r.code, *code, "closing plant: {r}");
                *refused.entry(code).or_insert(0) += 1;
            }
            _ => panic!("closing plant: kernel {kernel:?}, oracle {model:?}"),
        }
    }
    coverage.refused = refused.keys().copied().collect();
    assert_eq!(oracle.journal_len() as u32, posted);
    coverage.serial_replayed =
        assert_serial_replay(&k, &genesis, since, &authority, &oracle, &periods);

    // Every register cell of every period agrees, cell by cell, and the
    // kernel's trial balance over all periods nets to zero per unit.
    for code in &periods {
        let kernel_fold = fold_period(&k.db, &k.book, code).unwrap();
        let model_fold = oracle.fold(code);
        assert_eq!(
            kernel_fold.cells.len(),
            model_fold.len(),
            "{code}: cell count"
        );
        for cell in &kernel_fold.cells {
            let account_code = ACCOUNTS
                .iter()
                .map(|(c, ..)| *c)
                .find(|c| account_vid(k.book.book_id, c) == cell.key.account)
                .expect("known account");
            let m = model_fold.get(&(account_code.to_string(), cell.key.unit_id));
            assert!(m.is_some(), "{code}: oracle lacks cell {account_code}");
            let m = m.expect("asserted above");
            assert_eq!(
                m.debits.to_i128(),
                Some(cell.debits),
                "{code}/{account_code} debits"
            );
            assert_eq!(
                m.credits.to_i128(),
                Some(cell.credits),
                "{code}/{account_code} credits"
            );
            assert_eq!(
                m.entry_count, cell.entry_count,
                "{code}/{account_code} entry_count"
            );
        }
    }
    // The pending registers agree too: unresolved holds, keyed on the hold's
    // own period; a resolution in any period releases the full hold once.
    for code in &periods {
        let kernel_fold = fold_period(&k.db, &k.book, code).unwrap();
        let model_pending = oracle.pending_fold(code);
        assert_eq!(
            kernel_fold.pending.len(),
            model_pending.len(),
            "{code}: pending cell count"
        );
        for cell in &kernel_fold.pending {
            let account_code = ACCOUNTS
                .iter()
                .map(|(c, ..)| *c)
                .find(|c| account_vid(k.book.book_id, c) == cell.key.account)
                .expect("known account");
            let m = model_pending.get(&(account_code.to_string(), cell.key.unit_id));
            assert!(
                m.is_some(),
                "{code}: oracle lacks pending cell {account_code}"
            );
            let m = m.expect("asserted above");
            assert_eq!(
                m.debits.to_i128(),
                Some(cell.debits),
                "{code}/{account_code} pending debits"
            );
            assert_eq!(
                m.credits.to_i128(),
                Some(cell.credits),
                "{code}/{account_code} pending credits"
            );
            assert_eq!(
                m.entry_count, cell.entry_count,
                "{code}/{account_code} pending count"
            );
        }
    }
    // `fa explain balance` agrees with the oracle's journal leg by leg, for
    // every (period, leaf account): the posted legs of the period's posting
    // entries, the pending legs of its unresolved holds, and the released
    // legs of its resolved holds — identified by the kernel handle of the
    // oracle's journal index, so the selection is checked against the model,
    // not against the kernel's own fold. Its cells are the fold's cells, and
    // its known-at history ends at them.
    let resolved_holds: BTreeSet<usize> = (0..oracle.journal_len())
        .filter_map(|i| oracle.entry(i).and_then(|e| e.resolves))
        .collect();
    let mut explained_legs = 0usize;
    for code in &periods {
        let fold = fold_period(&k.db, &k.book, code).unwrap();
        for (account, _, is_leaf) in ACCOUNTS {
            let vid = account_vid(k.book.book_id, account);
            let explanation = explain_balance(&k.db, &k.book, vid, code, None);
            if !is_leaf {
                assert!(
                    matches!(&explanation, Err(fa_registers::RegisterError::InvalidSelection(message)) if message.contains("is a summary")),
                    "{code}/{account}: summary accounts require a leaf selection: {explanation:?}"
                );
                continue;
            }
            let ex = explanation.expect("a leaf account has a balance explanation");
            let mut kernel: Vec<(VId, u16, bool, i128, &str)> = ex
                .contributions
                .iter()
                .map(|c| {
                    (
                        c.entry,
                        c.ordinal,
                        c.side == Side::Debit,
                        c.mantissa,
                        c.column.name(),
                    )
                })
                .collect();
            let mut model = Vec::new();
            for (i, handle) in refs.iter().enumerate() {
                let e = oracle.entry(i).expect("journal index");
                if e.period != *code {
                    continue;
                }
                let column = match (e.class.as_str(), resolved_holds.contains(&i)) {
                    ("Pending", true) => "released",
                    ("Pending", false) => "pending",
                    _ => "posted",
                };
                for (ordinal, l) in e.legs.iter().enumerate() {
                    if l.account == *account {
                        model.push((
                            handle.vid,
                            u16::try_from(ordinal).expect("small ordinal"),
                            l.side == fa_reference::Side::Debit,
                            l.mantissa,
                            column,
                        ));
                    }
                }
            }
            kernel.sort();
            model.sort();
            assert_eq!(kernel, model, "{code}/{account}: explained legs");
            explained_legs += kernel.len();
            let own = |cells: &[fa_registers::Cell]| -> Vec<fa_registers::Cell> {
                cells
                    .iter()
                    .filter(|c| c.key.account == vid)
                    .cloned()
                    .collect()
            };
            assert_eq!(ex.cells, own(&fold.cells), "{code}/{account}: cells");
            assert_eq!(ex.pending, own(&fold.pending), "{code}/{account}: pending");
            assert_eq!(ex.fold_digest, fold.fold_digest, "{code}: fold digest");
            let units: BTreeSet<u32> = ex
                .history
                .iter()
                .map(|h| h.unit_id)
                .chain(ex.cells.iter().chain(&ex.pending).map(|c| c.key.unit_id))
                .collect();
            for unit in units {
                let column = |cells: &[fa_registers::Cell]| {
                    cells
                        .iter()
                        .find(|c| c.key.unit_id == unit)
                        .map_or((0, 0), |c| (c.debits, c.credits))
                };
                let last = ex.history.iter().rev().find(|h| h.unit_id == unit);
                assert_eq!(
                    last.map(|h| ((h.debits, h.credits), (h.debits_pending, h.credits_pending))),
                    Some((column(&ex.cells), column(&ex.pending))),
                    "{code}/{account}: the history ends at the cells"
                );
            }
        }
    }
    coverage.explained_legs = explained_legs;
    // The busiest cell's history replays: each point is the explanation as
    // known at that sequence (a fresh read of the journal prefix).
    let cash = account_vid(k.book.book_id, "1000");
    let ex = explain_balance(&k.db, &k.book, cash, &periods[2], None).unwrap();
    coverage.march_cash_history = ex.history.len();
    for h in &ex.history {
        let then = explain_balance(&k.db, &k.book, cash, &periods[2], Some(h.recorded_at)).unwrap();
        let posted = then.cells.iter().find(|c| c.key.unit_id == h.unit_id);
        let pending = then.pending.iter().find(|c| c.key.unit_id == h.unit_id);
        assert_eq!(
            (
                posted.map_or(0, |c| c.debits),
                posted.map_or(0, |c| c.credits),
                pending.map_or(0, |c| c.debits),
                pending.map_or(0, |c| c.credits),
            ),
            (h.debits, h.credits, h.debits_pending, h.credits_pending),
            "March cash as known at {}",
            h.recorded_at.0
        );
    }
    // Open items agree leg by leg (original, applied, open), and the kernel's
    // applied mirrors verify against the fold.
    let kernel_items = open_items(&k.db, &k.book, None, None).unwrap();
    let model_items = oracle.open_items();
    assert_eq!(kernel_items.len(), model_items.len(), "open item count");
    for item in &kernel_items {
        let index = refs
            .iter()
            .position(|r| r.vid == item.entry)
            .expect("kernel open item belongs to a posted entry");
        let model = model_items
            .get(&(index, usize::from(item.ordinal)))
            .copied();
        assert!(
            model.is_some(),
            "oracle lacks open item {index}/{}",
            item.ordinal
        );
        let (original, applied, applied_out) = model.expect("asserted above");
        assert_eq!(item.original, original, "{index}/{} original", item.ordinal);
        assert_eq!(item.applied, applied, "{index}/{} applied", item.ordinal);
        assert_eq!(
            item.applied_out, applied_out,
            "{index}/{} applied_out",
            item.ordinal
        );
        assert_eq!(
            item.open,
            original - applied_out - applied,
            "{index}/{} open",
            item.ordinal
        );
    }
    let verified = verify_open_items(&k.db, &k.book, None).unwrap();
    assert!(verified.is_green(), "{verified:?}");
    coverage.open_item_legs = verified.legs_checked;

    // Corruption negative: a leg whose applied mirror is removed is drift to
    // the verifier and corruption to the kernel — never an implicit zero
    // that would admit a fresh over-application.
    // A history without an application has nothing to corrupt; the caller
    // requires the plant (one seed's, or at least once over many).
    if let Some(victim) = kernel_items.iter().find(|i| i.applied > 0) {
        coverage.corruption_planted += 1;
        let victim_leg = fa_journal::rows::leg_vid(victim.entry, victim.ordinal);
        {
            let ctx = k.ctx();
            let mut batch = WriteBatch::new(fa_model::symbols::relation::HAS_LEG);
            batch.set_vertex_property(victim_leg, fa_model::symbols::property::APPLIED, None);
            k.runtime
                .block_on(async { k.db.write(&ctx.commit(), batch).await })
                .expect("plant the missing mirror");
        }
        let verified = verify_open_items(&k.db, &k.book, None).unwrap();
        assert!(!verified.is_green(), "{verified:?}");
        assert!(
            verified.drift.iter().any(|d| d.entry == victim.entry
                && d.ordinal == victim.ordinal
                && d.stored.is_none()),
            "{verified:?}"
        );
        let victim_index = refs
            .iter()
            .position(|r| r.vid == victim.entry)
            .expect("victim is a posted entry");
        // The corruption check lives behind the period law, so post into a
        // period both engines agree is Open. The random walk may leave March
        // Closed or Locked, and reopening those is case-bound (fa-llx, fa-oz3),
        // so take May, which the walk never touches, through Open, SoftClose and
        // an approved SoftClosed -> Reopen in both engines.
        let may = periods[4].clone();
        for (n, t) in [
            PeriodTransition::Open,
            PeriodTransition::SoftClose,
            PeriodTransition::Reopen {
                to: PeriodState::Open,
            },
        ]
        .into_iter()
        .enumerate()
        {
            let kernel = kernel_transition(&mut k, &may, t, 9_000 + n as u64);
            let model = oracle.transition(&may, t);
            assert!(
                kernel.is_ok() && model.is_ok(),
                "May {t:?} for the probe: kernel {kernel:?} oracle {model:?}"
            );
        }
        assert_eq!(
            oracle.period_state(&may),
            Some(PeriodState::Open),
            "May must be Open for the corruption probe"
        );
        let receipt = Intent {
            class: "Original".into(),
            date: DateDay::from_ymd(2026, 5, 15).unwrap(),
            discriminator: None,
            legs: vec![
                Leg {
                    side: fa_reference::Side::Debit,
                    account: "1000".into(),
                    unit: usd.0,
                    entity: None,
                    mantissa: 1,
                },
                Leg {
                    side: fa_reference::Side::Credit,
                    account: "1200".into(),
                    unit: usd.0,
                    entity: None,
                    mantissa: 1,
                },
            ],
            key: b"after-corruption".to_vec(),
            ops: vec!["post".into(), "post_closed".into()],
            approvals: 0,
            reverses: None,
            supersession_reason: 1,
            resolves: None,
            settles: vec![Settle {
                leg: 1,
                target: victim_index,
                ordinal: usize::from(victim.ordinal),
                mantissa: 1,
            }],
        };
        let outcome = kernel_post_raw(&mut k, &receipt, usd, &refs);
        assert!(
            matches!(outcome, Err(KernelError::Corrupt(_))),
            "a missing mirror must be corruption, got {outcome:?}"
        );
        // A negative mirror (which would inflate the open amount) and a mirror
        // above the leg's capacity are corruption too, and drift to the verifier.
        for (what, bad) in [("negative", -100i128), ("oversized", i128::MAX / 4)] {
            let ctx = k.ctx();
            let mut batch = WriteBatch::new(fa_model::symbols::relation::HAS_LEG);
            batch.set_vertex_property(
                victim_leg,
                fa_model::symbols::property::APPLIED,
                Some(fa_journal::rows::mantissa_scalar("applied", bad).unwrap()),
            );
            k.runtime
                .block_on(async { k.db.write(&ctx.commit(), batch).await })
                .expect("plant the bad mirror");
            let verified = verify_open_items(&k.db, &k.book, None).unwrap();
            assert!(!verified.is_green(), "{what}: {verified:?}");
            let mut probe = receipt.clone();
            probe.key = format!("after-{what}").into_bytes();
            let outcome = kernel_post_raw(&mut k, &probe, usd, &refs);
            assert!(
                matches!(outcome, Err(KernelError::Corrupt(_))),
                "a {what} mirror must be corruption, got {outcome:?}"
            );
        }
    }
    let tb = trial_balance(&k.db, &k.book, &periods).unwrap();
    assert!(tb.is_balanced(), "{:?}", tb.unit_totals);
    coverage
}

// ---- fa-2ihd: the serial-equivalence oracle ---------------------------------

/// One committed operation, decoded from the engine's journal.
#[derive(Debug)]
enum Decoded {
    /// A posting entry as the reference intent it records, and the period
    /// the engine journaled it in.
    Post(Box<Intent>, String),
    /// A period transition and the states it moved between.
    Transition(String, PeriodTransition, (PeriodState, PeriodState)),
}

/// The transition that moves a period from `from` to `to` (exactly one does).
fn transition_between(from: PeriodState, to: PeriodState) -> PeriodTransition {
    let moving: Vec<PeriodTransition> = [
        PeriodTransition::Open,
        PeriodTransition::SoftClose,
        PeriodTransition::Close,
        PeriodTransition::Lock,
        PeriodTransition::Reopen {
            to: PeriodState::Open,
        },
        PeriodTransition::Reopen {
            to: PeriodState::SoftClosed,
        },
    ]
    .into_iter()
    .filter(|t| fa_time::period::transition(from, *t) == Ok(to))
    .collect();
    assert_eq!(moving.len(), 1, "{from:?} -> {to:?}: {moving:?}");
    moving[0]
}

/// The chart code of account vertex `vid`.
fn account_code(k: &Kernel, vid: VId) -> String {
    ACCOUNTS
        .iter()
        .map(|(c, ..)| *c)
        .find(|c| account_vid(k.book.book_id, c) == vid)
        .expect("a chart account")
        .to_string()
}

/// The engine's journal after `since`, decoded from the committed payloads
/// alone, in commit order. Only the capability a writer presented is not
/// journaled: `authority` holds the ops each committed key was posted under,
/// so the replay's period law sees the authority the admission saw.
fn decode_journal(
    k: &Kernel,
    since: CommitSeq,
    authority: &BTreeMap<Vec<u8>, Vec<String>>,
) -> Vec<(CommitSeq, Decoded)> {
    let head = k.db.frontier().unwrap();
    // Entry vertex -> its index in the replayed reference journal.
    let mut index: BTreeMap<VId, usize> = BTreeMap::new();
    let mut decoded = Vec::new();
    for (vid, entry, seq) in fa_registers::entries_at(&k.db, &k.book, head).unwrap() {
        if seq <= since {
            continue;
        }
        let p = &entry.proposal;
        match &p.control {
            Some(ControlPayload::PeriodTransition {
                period_ref,
                from,
                to,
                ..
            }) => {
                let moved = (
                    PeriodState::from_tag(*from).expect("state tag"),
                    PeriodState::from_tag(*to).expect("state tag"),
                );
                let t = transition_between(moved.0, moved.1);
                decoded.push((seq, Decoded::Transition(period_ref.code.clone(), t, moved)));
                continue;
            }
            None | Some(ControlPayload::ReservationRelease) => {}
            Some(other) => panic!(
                "serial replay: no reference form for control {other:?} at {}",
                seq.0
            ),
        }
        let target = |r: &EntryRef| {
            *index.get(&r.vid).unwrap_or_else(|| {
                panic!(
                    "serial replay: entry {} cites {} ahead of its commit",
                    vid.0, r.vid.0
                )
            })
        };
        let mut legs = Vec::with_capacity(p.legs.len());
        let mut settles = Vec::new();
        for (ordinal, l) in p.legs.iter().enumerate() {
            assert!(
                l.dimension_set.is_empty(),
                "serial replay: a dimensioned leg"
            );
            legs.push(Leg {
                side: match l.side {
                    Side::Debit => fa_reference::Side::Debit,
                    Side::Credit => fa_reference::Side::Credit,
                },
                account: account_code(k, l.account_ref),
                unit: l.amount.unit.0,
                entity: None,
                mantissa: l.amount.mantissa,
            });
            settles.extend(l.settles.iter().map(|s| Settle {
                leg: ordinal,
                target: target(&s.target),
                ordinal: usize::from(s.ordinal),
                mantissa: s.amount.mantissa,
            }));
        }
        let reverses = match p.supersession.as_slice() {
            [] => None,
            [s] if s.kind == SupersessionKind::Reverses => Some((target(&s.target), s.reason_code)),
            other => panic!("serial replay: no reference form for supersession {other:?}"),
        };
        let resolves = p.pending.as_ref().and_then(|hold| {
            assert!(hold.timeout_ns.is_none(), "serial replay: a timed hold");
            hold.resolution_of.as_ref().map(|of| Resolve {
                target: target(of),
                posts: match &hold.disposition {
                    Some(Disposition::Posts { source_ordinals }) => Some(source_ordinals.clone()),
                    Some(Disposition::Voids) => None,
                    other => panic!("serial replay: no reference form for disposition {other:?}"),
                },
            })
        });
        let ops = authority
            .get(&p.idempotency_key)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "serial replay: no recorded authority for key {}",
                    String::from_utf8_lossy(&p.idempotency_key)
                )
            });
        let intent = Intent {
            class: p.class.name().expect("registered class").to_string(),
            date: p.effective_date,
            discriminator: p.effective_period.as_ref().map(|r| r.code.clone()),
            legs,
            key: p.idempotency_key.clone(),
            ops,
            approvals: entry.approvals.len(),
            reverses: reverses.map(|(t, _)| t),
            supersession_reason: reverses.map_or(1, |(_, reason)| reason),
            resolves,
            settles,
        };
        let period = fa_registers::entry_period(&k.book, &entry).unwrap();
        index.insert(vid, index.len());
        decoded.push((seq, Decoded::Post(Box::new(intent), period)));
    }
    decoded
}

/// The serial-equivalence oracle: the engine's committed journal, decoded
/// and replayed in CommitSeq order through a fresh reference (`genesis`, the
/// reference as the book was set up), re-admits every entry into the period
/// the engine journaled it in and every transition between the same states,
/// and reaches the lockstep reference's registers, open items and period
/// states. A history the engine admitted only through a stale witness has no
/// serial order the reference accepts. Returns the operations replayed.
fn assert_serial_replay(
    k: &Kernel,
    genesis: &Oracle,
    since: CommitSeq,
    authority: &BTreeMap<Vec<u8>, Vec<String>>,
    lockstep: &Oracle,
    periods: &[String],
) -> usize {
    let decoded = decode_journal(k, since, authority);
    let mut replay = genesis.clone();
    for (seq, op) in &decoded {
        match op {
            Decoded::Post(intent, period) => match replay.post(intent) {
                Verdict::Posted { period: p, .. } => {
                    assert_eq!(&p, period, "serial replay at {}: period", seq.0)
                }
                other => panic!(
                    "serial replay at {}: the reference gives {other:?} for the committed {intent:?}",
                    seq.0
                ),
            },
            Decoded::Transition(code, t, moved) => assert_eq!(
                replay.transition(code, *t),
                Ok(*moved),
                "serial replay at {}: {code} {t:?}",
                seq.0
            ),
        }
    }
    assert_eq!(
        replay.journal_len(),
        lockstep.journal_len(),
        "serial replay: journal length"
    );
    for code in periods {
        assert_eq!(
            replay.fold(code),
            lockstep.fold(code),
            "serial replay: {code}"
        );
        assert_eq!(
            replay.pending_fold(code),
            lockstep.pending_fold(code),
            "serial replay: {code} pending"
        );
        assert_eq!(
            replay.period_state(code),
            lockstep.period_state(code),
            "serial replay: {code} state"
        );
    }
    assert_eq!(
        replay.open_items(),
        lockstep.open_items(),
        "serial replay: open items"
    );
    decoded.len()
}

/// Every register cell (posted and pending) of every period, and every open
/// item, agree between the engine and the reference.
fn assert_registers_agree(
    k: &Kernel,
    oracle: &Oracle,
    periods: &[String],
    refs: &[EntryRef],
    what: &str,
) {
    type Cells = BTreeMap<(String, u32), (i128, i128, u64)>;
    for code in periods {
        let fold = fold_period(&k.db, &k.book, code).unwrap();
        for (kernel, model) in [
            (&fold.cells, oracle.fold(code)),
            (&fold.pending, oracle.pending_fold(code)),
        ] {
            let kernel: Cells = kernel
                .iter()
                .map(|c| {
                    (
                        (account_code(k, c.key.account), c.key.unit_id),
                        (c.debits, c.credits, c.entry_count),
                    )
                })
                .collect();
            let model: Cells = model
                .into_iter()
                .map(|(key, c)| {
                    let wide = |v: &Int| v.to_i128().expect("a register in range");
                    (key, (wide(&c.debits), wide(&c.credits), c.entry_count))
                })
                .collect();
            assert_eq!(kernel, model, "{what}: {code} registers");
        }
    }
    let kernel: BTreeMap<(usize, usize), (i128, i128, i128)> =
        open_items(&k.db, &k.book, None, None)
            .unwrap()
            .iter()
            .map(|item| {
                let index = refs
                    .iter()
                    .position(|r| r.vid == item.entry)
                    .expect("an open item of a posted entry");
                (
                    (index, usize::from(item.ordinal)),
                    (item.original, item.applied, item.applied_out),
                )
            })
            .collect();
    assert_eq!(kernel, oracle.open_items(), "{what}: open items");
}

/// One writer's operation in a race.
#[derive(Clone, Debug)]
enum RaceOp {
    Post(Intent),
    Transition(String, PeriodTransition),
}

/// A race operation staged at the race's prefix, not yet published.
enum Ready {
    Post(Box<PreparedPost>),
    Transition(Box<PreparedTransition>),
}

/// [`kernel_post`]'s preparation without its publication: the staged entry
/// and its read witnesses at the current prefix.
fn kernel_prepare_post(
    k: &mut Kernel,
    intent: &Intent,
    usd: UnitId,
    refs: &[EntryRef],
) -> Result<PostPreparation, Refusal> {
    let req = kernel_request(k, intent, usd, refs);
    let ctx = k.ctx();
    let db = &mut k.db;
    k.runtime
        .block_on(async { fa_journal::scratch::ensure_history(db, &ctx).await })
        .expect("kernel")
        .expect("retained history");
    prepare_post(&mut k.db, &ctx, &k.book, req).expect("kernel")
}

/// [`kernel_transition`]'s preparation without its publication.
fn kernel_prepare_transition(
    k: &mut Kernel,
    code: &str,
    t: PeriodTransition,
    step: u64,
    approvals: &[fa_model::ApprovalRef],
) -> Result<PreparedTransition, Refusal> {
    let key = format!("t-{step}");
    let description = period_description(k);
    let ctx = k.ctx();
    let db = &mut k.db;
    k.runtime
        .block_on(async { fa_journal::scratch::ensure_history(db, &ctx).await })
        .expect("kernel")
        .expect("retained history");
    prepare_transition(
        &mut k.db,
        &ctx,
        &k.book,
        code,
        t,
        PRINCIPAL,
        1,
        key.as_bytes(),
        description,
        &Capability::embedded(PRINCIPAL, &["close", "reopen", "post"]).expect("ops"),
        approvals,
    )
    .expect("kernel")
}

/// Reference-side bookkeeping for a race campaign: the kernel handle of each
/// posted entry (indexed like the reference journal), the ops each committed
/// key was posted under, and the targets writers contend for.
#[derive(Default)]
struct Ledger {
    refs: Vec<EntryRef>,
    authority: BTreeMap<Vec<u8>, Vec<String>>,
    invoices: Vec<usize>,
    holds: Vec<usize>,
    reversed: BTreeSet<usize>,
    resolved: BTreeSet<usize>,
    keys: u64,
}

impl Ledger {
    fn key(&mut self) -> Vec<u8> {
        self.keys += 1;
        format!("race-{}", self.keys).into_bytes()
    }

    /// Compare one post's verdicts in the two engines; true when it posted.
    fn agree(
        &mut self,
        what: &str,
        intent: &Intent,
        kernel: Result<Posted, Refusal>,
        model: Verdict,
    ) -> bool {
        match (kernel, model) {
            (
                Ok(Posted::Committed {
                    period, entry_ref, ..
                }),
                Verdict::Posted { period: p, index },
            ) => {
                assert_eq!(period, p, "{what}: period of {intent:?}");
                assert_eq!(index, self.refs.len(), "{what}: journal index");
                self.refs.push(entry_ref);
                self.authority
                    .insert(intent.key.clone(), intent.ops.clone());
                if intent.class == "Pending" {
                    self.holds.push(index);
                }
                if intent.settles.is_empty()
                    && intent.reverses.is_none()
                    && intent.legs.first().is_some_and(|l| l.account == "1200")
                {
                    self.invoices.push(index);
                }
                if let Some(t) = intent.reverses {
                    self.reversed.insert(t);
                }
                if let Some(r) = &intent.resolves {
                    self.resolved.insert(r.target);
                }
                true
            }
            (Ok(Posted::AlreadyRecorded { entry_ref, .. }), Verdict::Recorded { index }) => {
                assert_eq!(entry_ref, self.refs[index], "{what}: recorded handle");
                false
            }
            (Err(r), Verdict::Refused { code }) => {
                assert_eq!(r.code, code, "{what}: refusal of {intent:?}");
                false
            }
            (kernel, model) => {
                panic!("{what}: kernel {kernel:?}, reference {model:?} for {intent:?}")
            }
        }
    }
}

/// Two legs of one amount.
fn two_legs(usd: UnitId, debit: &str, credit: &str, mantissa: i128) -> Vec<Leg> {
    [
        (fa_reference::Side::Debit, debit),
        (fa_reference::Side::Credit, credit),
    ]
    .into_iter()
    .map(|(side, account)| Leg {
        side,
        account: account.into(),
        unit: usd.0,
        entity: None,
        mantissa,
    })
    .collect()
}

fn race_intent(class: &str, date: DateDay, legs: Vec<Leg>, key: Vec<u8>, ops: &[&str]) -> Intent {
    Intent {
        class: class.into(),
        date,
        discriminator: None,
        legs,
        key,
        ops: ops.iter().map(|o| (*o).to_string()).collect(),
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    }
}

/// The exact side-swap of posted entry `target`.
fn reversal_of(oracle: &Oracle, target: usize, date: DateDay, key: Vec<u8>) -> Intent {
    let legs = oracle
        .entry(target)
        .expect("a posted entry")
        .legs
        .iter()
        .map(|l| Leg {
            side: l.side.flipped(),
            ..l.clone()
        })
        .collect();
    Intent {
        reverses: Some(target),
        ..race_intent("Reversal", date, legs, key, &["post"])
    }
}

/// A resolution of hold `target`: posting all of it, or voiding it.
fn resolution_of(
    oracle: &Oracle,
    target: usize,
    posts: bool,
    date: DateDay,
    key: Vec<u8>,
) -> Intent {
    let hold = oracle.entry(target).expect("a posted hold");
    let (legs, ordinals) = if posts {
        let ordinals = (0..hold.legs.len())
            .map(|o| u16::try_from(o).expect("small ordinal"))
            .collect();
        (hold.legs.clone(), Some(ordinals))
    } else {
        (Vec::new(), None)
    };
    Intent {
        resolves: Some(Resolve {
            target,
            posts: ordinals,
        }),
        ..race_intent("Resolution", date, legs, key, &["post"])
    }
}

/// A receipt applying `amount` to invoice `target`'s receivable leg.
fn receipt_of(usd: UnitId, target: usize, amount: i128, date: DateDay, key: Vec<u8>) -> Intent {
    Intent {
        settles: vec![Settle {
            leg: 1,
            target,
            ordinal: 0,
            mantissa: amount,
        }],
        ..race_intent(
            "Original",
            date,
            two_legs(usd, "1000", "1200", amount),
            key,
            &["post"],
        )
    }
}

/// The races a campaign draws: two writers contending for one thing; two
/// that share only a cited document; and a control pair that shares nothing
/// but the book's unit (see `RaceCoverage::assert_minimums`).
const RACES: [&str; 8] = [
    "post-vs-transition",
    "double-reversal",
    "double-resolution",
    "receipt-pair",
    "same-key",
    "reversal-vs-receipt",
    "same-document",
    "disjoint",
];

/// Draw a race over the current book. A race whose target does not exist yet
/// becomes the disjoint pair.
fn draw_race(
    rng: &mut Rng,
    book: &mut Ledger,
    oracle: &Oracle,
    racing: &[String],
    days: &[DateDay; 3],
    usd: UnitId,
) -> (&'static str, [RaceOp; 2]) {
    let open = oracle.open_items();
    let live_invoices: Vec<(usize, i128)> = book
        .invoices
        .iter()
        .filter(|i| !book.reversed.contains(i))
        .filter_map(|i| {
            open.get(&(*i, 0))
                .map(|(original, applied, out)| (*i, original - out - applied))
        })
        .filter(|(_, left)| *left > 1)
        .collect();
    let unreversed: Vec<usize> = (0..book.refs.len())
        .filter(|i| !book.reversed.contains(i))
        .filter(|i| {
            oracle.entry(*i).is_some_and(|e| {
                matches!(e.class.as_str(), "Original" | "Adjusting")
                    && e.reverses.is_none()
                    && e.settles.is_empty()
            })
        })
        .collect();
    let unresolved: Vec<usize> = book
        .holds
        .iter()
        .copied()
        .filter(|h| !book.resolved.contains(h))
        .collect();
    // March or April: the periods that stay mostly Open.
    let day = |rng: &mut Rng| days[1 + rng.below(2) as usize];
    let amount = |rng: &mut Rng| 100 + rng.below(5_000) as i128;
    let race = RACES[rng.below(RACES.len() as u64) as usize];
    let ops = match race {
        "post-vs-transition" => {
            // February closes and locks; March and April soft-close and
            // reopen (Closed and Locked are absorbing without a case).
            let p = [0usize, 1, 1, 2, 2][rng.below(5) as usize];
            let code = &racing[p];
            let t = match (p, oracle.period_state(code)) {
                (_, Some(PeriodState::Open)) => PeriodTransition::SoftClose,
                (0, Some(PeriodState::SoftClosed)) if rng.chance(50) => PeriodTransition::Close,
                (_, Some(PeriodState::SoftClosed)) => PeriodTransition::Reopen {
                    to: PeriodState::Open,
                },
                (_, Some(PeriodState::Closed)) => PeriodTransition::Lock,
                // Locked: refused at preparation, in both engines.
                _ => PeriodTransition::SoftClose,
            };
            let granted: &[&str] = if rng.chance(50) {
                &["post"]
            } else {
                &["post", "post_closed"]
            };
            let class = if rng.chance(70) {
                "Original"
            } else {
                "Adjusting"
            };
            let legs = two_legs(usd, "6000", "1000", amount(rng));
            let post = race_intent(class, days[p], legs, book.key(), granted);
            Some([RaceOp::Post(post), RaceOp::Transition(code.clone(), t)])
        }
        "double-reversal" if !unreversed.is_empty() => {
            let target = unreversed[rng.below(unreversed.len() as u64) as usize];
            let a = reversal_of(oracle, target, day(rng), book.key());
            let b = reversal_of(oracle, target, day(rng), book.key());
            Some([RaceOp::Post(a), RaceOp::Post(b)])
        }
        "double-resolution" if !unresolved.is_empty() => {
            let target = unresolved[rng.below(unresolved.len() as u64) as usize];
            let a = resolution_of(oracle, target, false, day(rng), book.key());
            let b = resolution_of(oracle, target, rng.chance(50), day(rng), book.key());
            Some([RaceOp::Post(a), RaceOp::Post(b)])
        }
        "receipt-pair" if !live_invoices.is_empty() => {
            let (target, left) = live_invoices[rng.below(live_invoices.len() as u64) as usize];
            // Each fits; together they mostly over-apply.
            let a = 1 + rng.below(left as u64) as i128;
            let b = if rng.chance(70) {
                left - a + 1 + rng.below(a as u64) as i128
            } else {
                1 + rng.below((left - a).max(1) as u64) as i128
            };
            Some([
                RaceOp::Post(receipt_of(usd, target, a, day(rng), book.key())),
                RaceOp::Post(receipt_of(usd, target, b, day(rng), book.key())),
            ])
        }
        "same-key" => {
            // One key, two contents (dates): one writer's entry, the other's
            // idempotency conflict.
            let key = book.key();
            let legs = two_legs(usd, "6000", "1000", amount(rng));
            Some([
                RaceOp::Post(race_intent(
                    "Original",
                    days[1],
                    legs.clone(),
                    key.clone(),
                    &["post"],
                )),
                RaceOp::Post(race_intent("Original", days[2], legs, key, &["post"])),
            ])
        }
        "reversal-vs-receipt" if !live_invoices.is_empty() => {
            let (target, left) = live_invoices[rng.below(live_invoices.len() as u64) as usize];
            let paid = 1 + rng.below(left as u64) as i128;
            Some([
                RaceOp::Post(reversal_of(oracle, target, day(rng), book.key())),
                RaceOp::Post(receipt_of(usd, target, paid, day(rng), book.key())),
            ])
        }
        "same-document" => {
            // Disjoint accounts and periods, one cited document (the race
            // campaign gives this pair no second source).
            let plain = two_legs(usd, "6000", "1000", amount(rng));
            let invoice = two_legs(usd, "1200", "4000", amount(rng));
            Some([
                RaceOp::Post(race_intent(
                    "Original",
                    days[1],
                    plain,
                    book.key(),
                    &["post"],
                )),
                RaceOp::Post(race_intent(
                    "Original",
                    days[2],
                    invoice,
                    book.key(),
                    &["post"],
                )),
            ])
        }
        _ => None,
    };
    match ops {
        Some(ops) => (race, ops),
        None => {
            let plain = two_legs(usd, "6000", "1000", amount(rng));
            let invoice = two_legs(usd, "1200", "4000", amount(rng));
            (
                "disjoint",
                [
                    RaceOp::Post(race_intent(
                        "Original",
                        days[1],
                        plain,
                        book.key(),
                        &["post"],
                    )),
                    RaceOp::Post(race_intent(
                        "Original",
                        days[2],
                        invoice,
                        book.key(),
                        &["post"],
                    )),
                ],
            )
        }
    }
}

/// `f` with the kernel citing `cite`, when given, instead of the fixture
/// source document.
fn citing<T>(k: &mut Kernel, cite: Option<EvidenceRef>, f: impl FnOnce(&mut Kernel) -> T) -> T {
    let saved = cite.map(|e| std::mem::replace(&mut k.evidence, vec![e]));
    let out = f(k);
    if let Some(saved) = saved {
        k.evidence = saved;
    }
    out
}

/// How one race came out.
#[derive(Clone, Copy, Debug, Default)]
struct RaceCount {
    ran: u32,
    /// Both operations prepared at one prefix: two live writers to order.
    contended: u32,
    both_committed: u32,
    /// A prepared operation lost at commit with a conflict (exit 6).
    conflicted: u32,
    /// A conflict's loser, retried on the current book, was admitted.
    retried_in: u32,
}

/// Race two operations: both are prepared at one prefix, as two writers
/// would, then published in a seeded order. First committer wins: whatever
/// commits, the reference admits in commit order; a loser loses with a
/// conflict (exit 6) and, retried on the current book, gets the reference's
/// verdict. A preparation refused at the prefix is refused by the reference
/// at that prefix.
#[allow(clippy::too_many_arguments)]
fn run_race(
    k: &mut Kernel,
    oracle: &mut Oracle,
    book: &mut Ledger,
    usd: UnitId,
    rng: &mut Rng,
    what: &str,
    step: u64,
    ops: &[RaceOp; 2],
    second: Option<EvidenceRef>,
) -> RaceCount {
    // The second writer's post cites `second`, when given, instead of the
    // fixture source.
    let cite = |i: usize| if i == 1 { second } else { None };
    let keys = [300_000 + 2 * step, 300_001 + 2 * step];
    // Dual control first: an approval is a commit, so both operations are
    // prepared after it, at one prefix.
    let approvals: Vec<Vec<fa_model::ApprovalRef>> = ops
        .iter()
        .zip(keys)
        .map(|(op, key)| match op {
            RaceOp::Transition(code, t) => transition_approvals(k, code, *t, key),
            RaceOp::Post(_) => Vec::new(),
        })
        .collect();
    let basis = k.db.frontier().unwrap();
    let at_basis = oracle.clone();
    let mut ready: Vec<(usize, Ready)> = Vec::new();
    for (i, op) in ops.iter().enumerate() {
        match op {
            RaceOp::Post(intent) => match citing(k, cite(i), |k| {
                kernel_prepare_post(k, intent, usd, &book.refs)
            }) {
                Ok(PostPreparation::Ready(prepared)) => {
                    assert_eq!(prepared.basis(), basis, "{what}: basis");
                    ready.push((i, Ready::Post(prepared)));
                }
                Ok(PostPreparation::AlreadyRecorded(posted)) => {
                    let model = at_basis.clone().post(intent);
                    book.agree(
                        &format!("{what}: preparation {i}"),
                        intent,
                        Ok(posted),
                        model,
                    );
                }
                Err(refused) => {
                    let model = at_basis.clone().post(intent);
                    book.agree(
                        &format!("{what}: preparation {i}"),
                        intent,
                        Err(refused),
                        model,
                    );
                }
            },
            RaceOp::Transition(code, t) => {
                match kernel_prepare_transition(k, code, *t, keys[i], &approvals[i]) {
                    Ok(prepared) => {
                        assert_eq!(prepared.basis(), basis, "{what}: basis");
                        ready.push((i, Ready::Transition(Box::new(prepared))));
                    }
                    Err(r) => assert_eq!(
                        at_basis.clone().transition(code, *t).err(),
                        Some(r.code),
                        "{what}: preparation {i} of {code} {t:?}"
                    ),
                }
            }
        }
    }
    let mut count = RaceCount {
        ran: 1,
        contended: u32::from(ready.len() == 2),
        ..RaceCount::default()
    };
    if rng.chance(50) {
        ready.reverse();
    }
    let mut committed = 0u32;
    let mut losers = Vec::new();
    for (i, prepared) in ready {
        let ctx = k.ctx();
        let db = &mut k.db;
        match (prepared, &ops[i]) {
            (Ready::Post(prepared), RaceOp::Post(intent)) => {
                match k
                    .runtime
                    .block_on(async { prepared.commit(db, &ctx).await })
                    .expect("kernel")
                {
                    Err(r) if r.exit == 6 => {
                        eprintln!("{what}: writer {i} lost: {} {}", r.code, r.message);
                        losers.push(i);
                    }
                    out => {
                        let model = oracle.post(intent);
                        if book.agree(
                            &format!("{what}: commit {i}, in commit order"),
                            intent,
                            out,
                            model,
                        ) {
                            committed += 1;
                        }
                    }
                }
            }
            (Ready::Transition(prepared), RaceOp::Transition(code, t)) => {
                match k
                    .runtime
                    .block_on(async { prepared.commit(db, &ctx).await })
                    .expect("kernel")
                {
                    Ok(moved) => {
                        assert_eq!(
                            oracle.transition(code, *t),
                            Ok((moved.from, moved.to)),
                            "{what}: commit {i} of {code} {t:?}, in commit order"
                        );
                        committed += 1;
                    }
                    Err(r) if r.exit == 6 => {
                        eprintln!("{what}: writer {i} lost: {} {}", r.code, r.message);
                        losers.push(i);
                    }
                    Err(r) => assert_eq!(
                        oracle.transition(code, *t).err(),
                        Some(r.code),
                        "{what}: commit {i} of {code} {t:?}"
                    ),
                }
            }
            _ => unreachable!("each preparation is of its own operation"),
        }
    }
    count.both_committed = u32::from(committed == 2);
    count.conflicted = u32::try_from(losers.len()).expect("two writers");
    for i in losers {
        match &ops[i] {
            RaceOp::Post(intent) => {
                let kernel = citing(k, cite(i), |k| kernel_post(k, intent, usd, &book.refs));
                let model = oracle.post(intent);
                if book.agree(&format!("{what}: retry of {i}"), intent, kernel, model) {
                    count.retried_in += 1;
                }
            }
            RaceOp::Transition(code, t) => {
                let kernel = kernel_transition(k, code, *t, keys[i] + 100_000);
                match (kernel, oracle.transition(code, *t)) {
                    (Ok(moved), Ok(model)) => {
                        assert_eq!(
                            (moved.from, moved.to),
                            model,
                            "{what}: retry of {code} {t:?}"
                        );
                        count.retried_in += 1;
                    }
                    (Err(r), Err(c)) => assert_eq!(r.code, c, "{what}: retry of {code} {t:?}"),
                    (kernel, model) => {
                        panic!(
                            "{what}: retry of {code} {t:?}: kernel {kernel:?}, reference {model:?}"
                        )
                    }
                }
            }
        }
    }
    count
}

/// What the race campaigns exercised.
#[derive(Debug, Default)]
struct RaceCoverage {
    races: BTreeMap<&'static str, RaceCount>,
    /// Committed operations the serial replay re-admitted.
    replayed: usize,
}

impl RaceCoverage {
    fn add(&mut self, other: &RaceCoverage) {
        for (race, c) in &other.races {
            let total = self.races.entry(*race).or_default();
            total.ran += c.ran;
            total.contended += c.contended;
            total.both_committed += c.both_committed;
            total.conflicted += c.conflicted;
            total.retried_in += c.retried_in;
        }
        self.replayed += other.replayed;
    }

    fn assert_minimums(&self, what: &str) {
        for race in RACES {
            let c = self.races.get(race).copied().unwrap_or_default();
            assert!(c.ran >= 5 && c.contended >= 1, "{what}: {race} {c:?}");
        }
        // Where two prepared writers want one thing, one of them lost.
        for race in [
            "post-vs-transition",
            "double-reversal",
            "double-resolution",
            "same-key",
        ] {
            let c = self.races[race];
            assert!(c.conflicted >= 1, "{what}: {race} never conflicted: {c:?}");
        }
        // Pure-create posts commit through fgdb's append-only rebase
        // (`commit_append_only_rebased`), so disjoint writers in one unit do
        // not conflict on the shared unit vertex (`IN_UNIT` endpoint) and
        // both commit (`both_committed == contended`, `conflicted == 0`).
        let disjoint = self.races["disjoint"];
        assert!(
            disjoint.both_committed >= 1
                && disjoint.both_committed == disjoint.contended
                && disjoint.conflicted == 0,
            "{what}: disjoint writers must both commit without conflict: {disjoint:?}"
        );
        assert!(self.replayed > 0, "{what}: nothing replayed");
    }
}

/// One race campaign: February, March and April open, then 40 races over a
/// book the campaign keeps stocked with invoices, holds and plain entries
/// (posted serially, in lockstep), then the registers and the serial replay.
fn race_campaign(seed: u64) -> RaceCoverage {
    let (mut k, mut oracle, periods) = setup();
    let usd = k.book.units.lookup("USD").unwrap();
    // A second source document. Two posts citing one document both add an
    // EVIDENCED_BY edge into it, and an ordinary commit conflicts on an
    // edge's endpoints (fgdb write_txn finish) whatever else they contend
    // for. So the second writer of each two-post race cites this one, and
    // only the same-document race shares a document. (Posts in one unit
    // still share the unit vertex the same way; see RaceCoverage.)
    let second_source = {
        let doc = Document {
            book_id: k.book.book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"INVOICE (race fixture, a second source document)".to_vec(),
        };
        let ctx = k.ctx();
        let db = &mut k.db;
        let book = &k.book;
        k.runtime
            .block_on(async { add_document(db, &ctx, book, &doc).await })
            .expect("kernel")
            .expect("the second source is admitted");
        doc.evidence_ref(1)
    };
    let genesis = oracle.clone();
    let since = k.db.frontier().unwrap();
    let mut rng = Rng(seed);
    let mut book = Ledger::default();
    let mut coverage = RaceCoverage::default();
    let racing = &periods[1..4];
    let days = [
        DateDay::from_ymd(2026, 2, 10).unwrap(),
        DateDay::from_ymd(2026, 3, 15).unwrap(),
        DateDay::from_ymd(2026, 4, 2).unwrap(),
    ];
    for (n, code) in racing.iter().enumerate() {
        let kernel = kernel_transition(&mut k, code, PeriodTransition::Open, 200_000 + n as u64);
        let model = oracle.transition(code, PeriodTransition::Open);
        assert!(
            kernel.is_ok() && model.is_ok(),
            "open {code}: kernel {kernel:?}, reference {model:?}"
        );
    }
    for step in 0..40u64 {
        let what = format!("seed {seed:#x} race {step}");
        if book.refs.len() < 6 || rng.chance(40) {
            let day = days[1 + rng.below(2) as usize];
            let amount = 1_000 + rng.below(9_000) as i128;
            let (class, debit, credit) = match rng.below(3) {
                0 => ("Original", "1200", "4000"),
                1 => ("Pending", "6000", "1000"),
                _ => ("Original", "6000", "1000"),
            };
            let target = race_intent(
                class,
                day,
                two_legs(usd, debit, credit, amount),
                book.key(),
                &["post"],
            );
            let kernel = kernel_post(&mut k, &target, usd, &book.refs);
            let model = oracle.post(&target);
            book.agree(&format!("{what}: target"), &target, kernel, model);
        }
        let (race, ops) = draw_race(&mut rng, &mut book, &oracle, racing, &days, usd);
        let c = run_race(
            &mut k,
            &mut oracle,
            &mut book,
            usd,
            &mut rng,
            &format!("{what} ({race})"),
            step,
            &ops,
            (race != "same-document").then_some(second_source),
        );
        let mut one = RaceCoverage::default();
        one.races.insert(race, c);
        coverage.add(&one);
    }
    let what = format!("seed {seed:#x}");
    assert_registers_agree(&k, &oracle, &periods, &book.refs, &what);
    coverage.replayed =
        assert_serial_replay(&k, &genesis, since, &book.authority, &oracle, &periods);
    let tb = trial_balance(&k.db, &k.book, &periods).unwrap();
    assert!(tb.is_balanced(), "{what}: {:?}", tb.unit_totals);
    coverage
}

/// fa-2ihd acceptance (serial-equivalence oracle): race campaigns over many
/// seeds, each race two writers prepared at one committed prefix and
/// published in a seeded order, checked in commit order against the
/// reference, then the committed journal replayed serially. Tier 1 runs 8
/// seeds; `FA_DIFFERENTIAL_SEEDS=<n>` runs n (tier 2), sharded by
/// `FA_DIFFERENTIAL_SEED_FROM=<k>` ([`seed_indices`]). A divergence names its
/// seed.
#[test]
fn serial_equivalence_oracle() {
    let seeds = seed_indices();
    let mut total = RaceCoverage::default();
    for i in seeds.clone() {
        // Distinct from the generated-history campaign's seeds.
        let seed = splitmix(i.wrapping_add(0x5E71_A1E0));
        match std::panic::catch_unwind(|| race_campaign(seed)) {
            Ok(coverage) => total.add(&coverage),
            Err(_) => {
                panic!("the race campaign diverged at seed {seed:#018x} (index {i} of {seeds:?})")
            }
        }
    }
    eprintln!(
        "fa-2ihd races over seed indices {seeds:?}: {:?}",
        total.races
    );
    total.assert_minimums(&format!("seed indices {seeds:?}"));
}

/// The message a caught panic carried.
fn panic_text(payload: Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
        .unwrap_or_default()
}

/// fa-2ihd planted negatives for the serial replay itself. The replay
/// re-judges the committed journal, so it must fail a history the reference
/// would not admit in commit order. A real book opens February, posts into
/// it, soft-closes it, and posts again under `post_softclosed`. Replayed
/// faithfully, all four operations are re-admitted. Told that the second
/// key held only `post`, the replay refuses that entry (FA-REF-011). Started
/// from a reference whose February is already soft closed, it refuses the
/// first operation.
#[test]
fn serial_replay_refuses_a_history_the_reference_would_not_admit() {
    let (mut k, mut oracle, periods) = setup();
    let usd = k.book.units.lookup("USD").unwrap();
    let genesis = oracle.clone();
    let since = k.db.frontier().unwrap();
    let feb = &periods[1];
    let day = DateDay::from_ymd(2026, 2, 10).unwrap();
    let mut authority: BTreeMap<Vec<u8>, Vec<String>> = BTreeMap::new();
    let mut posted = Vec::new();
    for (n, (key, ops)) in [
        ("replay-open", &["post"][..]),
        ("replay-softclosed", &["post", "post_softclosed"][..]),
    ]
    .into_iter()
    .enumerate()
    {
        let t = if n == 0 {
            PeriodTransition::Open
        } else {
            PeriodTransition::SoftClose
        };
        let kernel = kernel_transition(&mut k, feb, t, 700_000 + n as u64);
        let model = oracle.transition(feb, t);
        assert!(
            kernel.is_ok() && model.is_ok(),
            "{feb} {t:?}: kernel {kernel:?}, reference {model:?}"
        );
        let legs = two_legs(usd, "6000", "1000", 500 + n as i128);
        let intent = race_intent("Original", day, legs, key.as_bytes().to_vec(), ops);
        let kernel = kernel_post(&mut k, &intent, usd, &[]);
        let model = oracle.post(&intent);
        assert!(
            matches!(kernel, Ok(Posted::Committed { .. }))
                && matches!(model, Verdict::Posted { .. }),
            "{key}: kernel {kernel:?}, reference {model:?}"
        );
        authority.insert(intent.key.clone(), intent.ops.clone());
        posted.push(intent);
    }
    assert_eq!(
        assert_serial_replay(&k, &genesis, since, &authority, &oracle, &periods),
        4,
        "two transitions and two posts"
    );
    let refused = |from: &Oracle, authority: &BTreeMap<Vec<u8>, Vec<String>>| {
        panic_text(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_serial_replay(&k, from, since, authority, &oracle, &periods)
            }))
            .expect_err("the replay admitted a history the reference refuses"),
        )
    };
    let mut weaker = authority.clone();
    weaker.insert(posted[1].key.clone(), vec!["post".into()]);
    let message = refused(&genesis, &weaker);
    assert!(
        message.contains("FA-REF-011") && message.contains("mantissa: 501"),
        "{message}"
    );
    let mut soft_closed = genesis.clone();
    for t in [PeriodTransition::Open, PeriodTransition::SoftClose] {
        soft_closed.transition(feb, t).expect("the planted start");
    }
    let message = refused(&soft_closed, &authority);
    assert!(
        message.contains("serial replay at") && message.contains("Open"),
        "{message}"
    );
}

fn create_year(k: &mut Kernel, oracle: &mut Oracle, year: i32) -> CommitSeq {
    let ctx = k.ctx();
    let (seq, _) = k
        .runtime
        .block_on(async {
            create_periods(
                &mut k.db,
                &ctx,
                &k.book,
                year,
                fgdb_types::VId(1),
                fa_model::Erasable::seal(
                    &"periods".to_string(),
                    None,
                    &k.book.seal_key,
                    [1; 32],
                    [2; 24],
                ),
                &fa_journal::Capability::embedded(fgdb_types::VId(1), &["schema_change"]).unwrap(),
            )
            .await
        })
        .expect("create real period definitions")
        .expect("admitted");
    oracle.create_periods(year);
    seq
}

fn open_period(k: &mut Kernel, oracle: &mut Oracle, code: &str, step: u64) {
    let transition =
        kernel_transition(k, code, PeriodTransition::Open, step).expect("open real period");
    let expected = oracle
        .transition(code, PeriodTransition::Open)
        .expect("open oracle period");
    assert_eq!((transition.from, transition.to), expected);
}

fn temporal_intent(
    date: (i32, u8, u8),
    adjustment: Option<&str>,
    debit: &str,
    credit: &str,
    amount: i128,
    key: &[u8],
    unit: UnitId,
) -> Intent {
    Intent {
        class: if adjustment.is_some() {
            "Adjusting"
        } else {
            "Original"
        }
        .into(),
        date: DateDay::from_ymd(date.0, date.1, date.2).unwrap(),
        discriminator: adjustment.map(str::to_owned),
        legs: vec![
            Leg {
                side: fa_reference::Side::Debit,
                account: debit.into(),
                unit: unit.0,
                entity: None,
                mantissa: amount,
            },
            Leg {
                side: fa_reference::Side::Credit,
                account: credit.into(),
                unit: unit.0,
                entity: None,
                mantissa: amount,
            },
        ],
        key: key.to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    }
}

/// Record the correspondence without teaching the oracle about CommitSeq.
/// Period creation and control commits advance only the substrate sequence.
fn post_temporal(k: &mut Kernel, oracle: &mut Oracle, intent: &Intent) -> (CommitSeq, usize) {
    let usd = k.book.units.lookup("USD").unwrap();
    let posted = kernel_post(k, intent, usd, &[]).expect("real monetary commit");
    let Posted::Committed {
        recorded_at,
        period,
        ..
    } = posted
    else {
        panic!("fixture must append a new entry: {posted:?}");
    };
    let expected_index = oracle.journal_len();
    assert_eq!(
        oracle.post(intent),
        Verdict::Posted {
            index: expected_index,
            period
        }
    );
    (recorded_at, oracle.journal_len())
}

fn assert_temporal_report(
    report: &TrialBalance,
    expected: BTreeMap<(String, u32), Cell>,
    known_at: CommitSeq,
    cutoff: Option<DateDay>,
) {
    assert_eq!(report.known_at, known_at);
    assert_eq!(report.effective_through, cutoff);
    assert_eq!(report.activity, cutoff.is_none());
    let actual: BTreeMap<_, _> = report
        .rows
        .iter()
        .map(|row| ((row.code.clone(), row.unit_id), (row.debits, row.credits)))
        .collect();
    assert_eq!(actual.len(), report.rows.len(), "duplicate report row");
    let expected_rows: BTreeMap<_, _> = expected
        .iter()
        .map(|(key, cell)| {
            (
                key.clone(),
                (
                    cell.debits.to_i128().unwrap(),
                    cell.credits.to_i128().unwrap(),
                ),
            )
        })
        .collect();
    assert_eq!(actual, expected_rows);

    // Totals use the oracle's limb arithmetic as well, independently of the
    // report's money path and independently of its is_balanced convenience.
    let mut totals: BTreeMap<u32, (Int, Int)> = BTreeMap::new();
    for ((_, unit), cell) in expected {
        let total = totals.entry(unit).or_insert((Int::zero(), Int::zero()));
        total.0 = total.0.add(&cell.debits);
        total.1 = total.1.add(&cell.credits);
    }
    let totals: BTreeMap<_, _> = totals
        .into_iter()
        .map(|(unit, (d, c))| (unit, (d.to_i128().unwrap(), c.to_i128().unwrap())))
        .collect();
    assert_eq!(report.unit_totals, totals);
}

fn assert_amounts(report: &TrialBalance, code: &str, debits: i128, credits: i128) {
    let row = report
        .rows
        .iter()
        .find(|row| row.code == code)
        .expect("account row");
    assert_eq!((row.debits, row.credits), (debits, credits), "{code}");
}

#[test]
fn temporal_stock_and_activity_agree_with_literal_journal_prefixes() {
    let (mut k, mut oracle, _) = setup();
    let usd = k.book.units.lookup("USD").unwrap();
    create_year(&mut k, &mut oracle, 2025);
    create_year(&mut k, &mut oracle, 2027);
    for (step, code) in ["FY2025-P12", "FY2026-P12", "FY2026-A1", "FY2027-P01"]
        .iter()
        .enumerate()
    {
        open_period(&mut k, &mut oracle, code, step as u64);
    }
    // §7.5: no opening entry. Prior-year cash 100 carries through a normal
    // Dec31 receipt 40 and a distinct same-date audit adjustment 7.
    let posts = [
        temporal_intent((2025, 12, 20), None, "1000", "4000", 100, b"prior", usd),
        temporal_intent((2026, 12, 31), None, "1000", "4000", 40, b"dec", usd),
        temporal_intent(
            (2026, 12, 31),
            Some("FY2026-A1"),
            "1000",
            "4000",
            7,
            b"adj",
            usd,
        ),
        temporal_intent((2027, 1, 10), None, "1000", "4000", 20, b"jan", usd),
        temporal_intent((2027, 1, 25), None, "6000", "1000", 9, b"later-day", usd),
    ];
    let checkpoints: Vec<_> = posts
        .iter()
        .map(|intent| post_temporal(&mut k, &mut oracle, intent))
        .collect();
    let (old_seq, old_prefix) = checkpoints[4];
    assert_eq!(old_prefix, 5);
    let dec31 = DateDay::from_ymd(2026, 12, 31).unwrap();
    let jan15 = DateDay::from_ymd(2027, 1, 15).unwrap();
    let jan31 = DateDay::from_ymd(2027, 1, 31).unwrap();
    let december = vec!["FY2026-P12".to_string()];
    let january = vec!["FY2027-P01".to_string()];
    let adjustment = vec!["FY2026-A1".to_string()];

    let dec_stock = trial_balance_at(&k.db, &k.book, &december, Some(old_seq)).unwrap();
    assert_temporal_report(
        &dec_stock,
        oracle.stock_at(dec31, old_prefix),
        old_seq,
        Some(dec31),
    );
    assert_amounts(&dec_stock, "1000", 147, 0);
    assert_amounts(&dec_stock, "4000", 0, 147);
    // Selecting the adjustment period has the same stock cutoff as Dec31,
    // but activity has a separate identity and includes only the 7 entry.
    let adj_stock = trial_balance_at(&k.db, &k.book, &adjustment, Some(old_seq)).unwrap();
    assert_temporal_report(
        &adj_stock,
        oracle.stock_at(dec31, old_prefix),
        old_seq,
        Some(dec31),
    );
    let dec_flow = period_activity(&k.db, &k.book, &december, Some(old_seq)).unwrap();
    assert_temporal_report(
        &dec_flow,
        oracle.activity_at(&["FY2026-P12"], old_prefix),
        old_seq,
        None,
    );
    assert_amounts(&dec_flow, "1000", 40, 0);
    let adj_flow = period_activity(&k.db, &k.book, &adjustment, Some(old_seq)).unwrap();
    assert_temporal_report(
        &adj_flow,
        oracle.activity_at(&["FY2026-A1"], old_prefix),
        old_seq,
        None,
    );
    assert_amounts(&adj_flow, "1000", 7, 0);

    let jan_stock = trial_balance_at(&k.db, &k.book, &january, Some(old_seq)).unwrap();
    assert_temporal_report(
        &jan_stock,
        oracle.stock_at(jan31, old_prefix),
        old_seq,
        Some(jan31),
    );
    assert_amounts(&jan_stock, "1000", 167, 9);
    assert_amounts(&jan_stock, "6000", 9, 0);
    let jan_flow = period_activity(&k.db, &k.book, &january, Some(old_seq)).unwrap();
    assert_temporal_report(
        &jan_flow,
        oracle.activity_at(&["FY2027-P01"], old_prefix),
        old_seq,
        None,
    );
    assert_amounts(&jan_flow, "1000", 20, 9);
    let midmonth = balance_as_of(&k.db, &k.book, jan15, Some(old_seq)).unwrap();
    assert_temporal_report(
        &midmonth,
        oracle.stock_at(jan15, old_prefix),
        old_seq,
        Some(jan15),
    );
    assert_amounts(&midmonth, "1000", 167, 0);
    assert!(
        midmonth.rows.iter().all(|row| row.code != "6000"),
        "Jan25 expense leaked into Jan15"
    );

    // This late-recorded backdate changes HEAD stock and December flow, but
    // cannot change either report at the saved recorded-time coordinate.
    let late = temporal_intent((2026, 12, 5), None, "1000", "4000", 3, b"backdate", usd);
    let (new_seq, new_prefix) = post_temporal(&mut k, &mut oracle, &late);
    assert_eq!(new_prefix, 6);
    assert!(new_seq > old_seq);
    assert_eq!(
        trial_balance_at(&k.db, &k.book, &december, Some(old_seq)).unwrap(),
        dec_stock
    );
    assert_eq!(
        period_activity(&k.db, &k.book, &december, Some(old_seq)).unwrap(),
        dec_flow
    );
    assert_eq!(
        balance_as_of(&k.db, &k.book, jan15, Some(old_seq)).unwrap(),
        midmonth
    );
    let new_dec = trial_balance_at(&k.db, &k.book, &december, None).unwrap();
    assert_temporal_report(
        &new_dec,
        oracle.stock_at(dec31, new_prefix),
        new_seq,
        Some(dec31),
    );
    assert_amounts(&new_dec, "1000", 150, 0);
    let new_jan = trial_balance_at(&k.db, &k.book, &january, None).unwrap();
    assert_temporal_report(
        &new_jan,
        oracle.stock_at(jan31, new_prefix),
        new_seq,
        Some(jan31),
    );
    assert_amounts(&new_jan, "1000", 170, 9);
    let new_flow = period_activity(&k.db, &k.book, &december, None).unwrap();
    assert_temporal_report(
        &new_flow,
        oracle.activity_at(&["FY2026-P12"], new_prefix),
        new_seq,
        None,
    );
    assert_amounts(&new_flow, "1000", 43, 0);
    let repeated = vec!["FY2026-P12".into(), "FY2026-A1".into(), "FY2026-P12".into()];
    let combined = period_activity(&k.db, &k.book, &repeated, None).unwrap();
    assert_temporal_report(
        &combined,
        oracle.activity_at(&["FY2026-P12", "FY2026-A1", "FY2026-P12"], new_prefix),
        new_seq,
        None,
    );
    assert_amounts(&combined, "1000", 50, 0);
    let unique = vec!["FY2026-A1".into(), "FY2026-P12".into()];
    assert_eq!(
        combined,
        period_activity(&k.db, &k.book, &unique, None).unwrap()
    );
}

#[test]
fn temporal_reports_resolve_period_metadata_at_the_recorded_snapshot() {
    let (mut k, mut oracle, _) = setup();
    open_period(&mut k, &mut oracle, "FY2026-P01", 0);
    let usd = k.book.units.lookup("USD").unwrap();
    let intent = temporal_intent((2026, 1, 10), None, "1000", "4000", 11, b"snapshot", usd);
    let (seq, prefix) = post_temporal(&mut k, &mut oracle, &intent);
    let year_end = DateDay::from_ymd(2026, 12, 31).unwrap();
    let year_end_period = vec!["FY2026-P12".to_string()];
    let before = trial_balance_at(&k.db, &k.book, &year_end_period, Some(seq)).unwrap();
    assert_temporal_report(
        &before,
        oracle.stock_at(year_end, prefix),
        seq,
        Some(year_end),
    );
    assert_amounts(&before, "1000", 11, 0);
    let future_day = DateDay::from_ymd(2027, 1, 31).unwrap();
    let day_before = balance_as_of(&k.db, &k.book, future_day, Some(seq)).unwrap();

    let metadata_seq = create_year(&mut k, &mut oracle, 2027);
    assert!(metadata_seq > seq);
    assert_eq!(
        oracle.journal_len(),
        prefix,
        "metadata is not a monetary entry"
    );
    assert_eq!(
        trial_balance_at(&k.db, &k.book, &year_end_period, Some(seq)).unwrap(),
        before
    );
    assert_eq!(
        balance_as_of(&k.db, &k.book, future_day, Some(seq)).unwrap(),
        day_before
    );
    let later_period = vec!["FY2027-P01".to_string()];
    assert!(
        trial_balance_at(&k.db, &k.book, &later_period, Some(seq)).is_err(),
        "period created later leaked into old snapshot"
    );
    assert!(
        period_activity(&k.db, &k.book, &later_period, Some(seq)).is_err(),
        "activity resolved a period that did not exist yet"
    );
    let current = trial_balance_at(&k.db, &k.book, &later_period, None).unwrap();
    assert_temporal_report(
        &current,
        oracle.stock_at(future_day, prefix),
        metadata_seq,
        Some(future_day),
    );
    assert_amounts(&current, "1000", 11, 0);
}

// ---------------------------------------------------------------------------
// Reserved availability (plan §5.4, §5.5; bead fa-rqe)
// ---------------------------------------------------------------------------

/// Cash is debit-normal with a floor of 0 and a cap; the credit facility is
/// credit-normal with a cap on drawn principal; the rest are unlimited.
const LIMITED: &[ChartRow] = &[
    (
        "1000",
        1,
        true,
        0,
        Some(BalanceLimit {
            lower: Some(0),
            upper: Some(400_000),
            scope: LimitScope::Lifetime,
        }),
    ),
    (
        "2100",
        2,
        true,
        1,
        Some(BalanceLimit {
            lower: None,
            upper: Some(150_000),
            scope: LimitScope::Lifetime,
        }),
    ),
    ("3000", 3, true, 1, None),
    ("4000", 4, true, 1, None),
    ("6000", 5, true, 0, None),
];

/// `(L, U) = (net − pending_out, net + pending_in)` of a limited account on
/// the oracle's literal fold, in its normal-balance sign.
fn oracle_lu(oracle: &Oracle, code: &str, debit_normal: bool) -> (i128, i128) {
    let a = oracle.availability(code);
    let v = |x: &Int| x.to_i128().expect("generated sums fit i128");
    let (dp, cp, dr, cr) = (
        v(&a.debits_posted),
        v(&a.credits_posted),
        v(&a.debits_pending),
        v(&a.credits_pending),
    );
    if debit_normal {
        (dp - cp - cr, dp - cp + dr)
    } else {
        (cp - dp - dr, cp - dp + cr)
    }
}

/// The kernel's stored cell equals the oracle's literal fold, generation
/// included, after every step.
fn assert_cell(k: &Kernel, oracle: &Oracle, code: &str, step: u64) {
    let vid = limit_cell_vid(account_vid(k.book.book_id, code));
    let row = k.db.vertex(vid).expect("read").expect("limit cell exists");
    let cell = LimitCell::decode(&row).expect("decodes");
    let a = oracle.availability(code);
    assert_eq!(
        (
            Some(cell.debits_posted),
            Some(cell.credits_posted),
            Some(cell.debits_pending),
            Some(cell.credits_pending),
            u64::try_from(cell.generation).expect("non-negative"),
        ),
        (
            a.debits_posted.to_i128(),
            a.credits_posted.to_i128(),
            a.debits_pending.to_i128(),
            a.credits_pending.to_i128(),
            a.generation,
        ),
        "step {step}: limit cell of {code}"
    );
}

/// An amount near a boundary: exactly it, one over, strictly inside, or a
/// random size that may land anywhere.
fn near(rng: &mut Rng, edge: i128) -> i128 {
    match rng.below(5) {
        0 if edge > 0 => edge,
        1 => edge.max(0) + 1,
        2 if edge > 1 => 1 + rng.below(edge as u64 - 1) as i128,
        _ => 1 + rng.below(60_000) as i128,
    }
}

#[test]
fn kernel_and_oracle_agree_on_limited_accounts() {
    let (mut k, mut oracle, periods) = setup_with(LIMITED);
    let usd = k.book.units.lookup("USD").unwrap();
    open_period(&mut k, &mut oracle, &periods[2], 1);
    let dates = [
        DateDay::from_ymd(2026, 3, 2).unwrap(),
        DateDay::from_ymd(2026, 3, 10).unwrap(),
        DateDay::from_ymd(2026, 3, 20).unwrap(),
    ];
    let mut rng = Rng(0xA5A5_5A5A_0F0F_F0F0);
    let leg = |side: fa_reference::Side, account: &str, mantissa: i128| Leg {
        side,
        account: account.into(),
        unit: usd.0,
        entity: None,
        mantissa,
    };
    let dr = fa_reference::Side::Debit;
    let cr = fa_reference::Side::Credit;
    let mut refs: Vec<EntryRef> = Vec::new();
    let mut posted_intents: Vec<Intent> = Vec::new();
    let mut holds: Vec<usize> = Vec::new();
    let mut resolved: BTreeSet<usize> = BTreeSet::new();
    let mut reversed: BTreeSet<usize> = BTreeSet::new();
    let mut refused: BTreeMap<&'static str, u32> = BTreeMap::new();
    let (mut posted, mut recorded) = (0u32, 0u32);
    // Boundary evidence: an outflow of exactly the available amount posts,
    // one more is refused; likewise for inflows against a cap.
    let (mut exact_out, mut over_out, mut exact_in, mut over_in) = (0u32, 0u32, 0u32, 0u32);
    let mut posts_resolutions = 0u32;
    let mut voids = 0u32;
    let mut outflow_holds = 0u32;

    for step in 0..700u64 {
        let (cash_l, cash_u) = oracle_lu(&oracle, "1000", true);
        let (_, loan_u) = oracle_lu(&oracle, "2100", false);
        let cash_avail = cash_l; // lower bound 0
        let cash_room = 400_000 - cash_u;
        let loan_room = 150_000 - loan_u;
        let key = format!("l{step}").into_bytes();
        let plain = |legs: Vec<Leg>, key: Vec<u8>, date: DateDay| Intent {
            class: "Original".into(),
            date,
            discriminator: None,
            legs,
            key,
            ops: vec!["post".into()],
            approvals: 0,
            reverses: None,
            supersession_reason: 1,
            resolves: None,
            settles: Vec::new(),
        };
        let date = dates[rng.below(3) as usize];
        // (intent, boundary: Some((edge, amount, is_outflow)))
        let (intent, boundary) = match rng.below(20) {
            0..=2 => {
                // Fund cash from equity: an inflow against the cash cap.
                let a = near(&mut rng, cash_room);
                (
                    plain(vec![leg(dr, "1000", a), leg(cr, "3000", a)], key, date),
                    Some((cash_room, a, false)),
                )
            }
            3..=5 => {
                // Spend cash: an outflow against the floor.
                let a = near(&mut rng, cash_avail);
                (
                    plain(vec![leg(dr, "6000", a), leg(cr, "1000", a)], key, date),
                    Some((cash_avail, a, true)),
                )
            }
            6..=7 => {
                // Hold an outflow: it reserves against the floor.
                let a = near(&mut rng, cash_avail);
                let mut i = plain(vec![leg(dr, "6000", a), leg(cr, "1000", a)], key, date);
                i.class = "Pending".into();
                (i, Some((cash_avail, a, true)))
            }
            8 => {
                // Hold an inflow: it never finances, but counts against the cap.
                let a = near(&mut rng, cash_room);
                let mut i = plain(vec![leg(dr, "1000", a), leg(cr, "4000", a)], key, date);
                i.class = "Pending".into();
                (i, Some((cash_room, a, false)))
            }
            9..=10 => {
                // Draw on the facility: an inflow on both limited accounts.
                let a = near(&mut rng, loan_room.min(cash_room));
                (
                    plain(vec![leg(dr, "1000", a), leg(cr, "2100", a)], key, date),
                    None,
                )
            }
            11 => {
                // Repay: an outflow of cash, an improvement on the facility.
                let a = near(&mut rng, cash_avail);
                (
                    plain(vec![leg(dr, "2100", a), leg(cr, "1000", a)], key, date),
                    None,
                )
            }
            12..=14 if holds.iter().any(|h| !resolved.contains(h)) => {
                // Resolve an open hold: post part of it, or void it.
                let open: Vec<usize> = holds
                    .iter()
                    .copied()
                    .filter(|h| !resolved.contains(h))
                    .collect();
                let target = open[rng.below(open.len() as u64) as usize];
                let hold = oracle.entry(target).expect("hold").clone();
                let (legs, posts) = if rng.chance(55) {
                    let t = 1 + rng.below(hold.legs[0].mantissa as u64) as i128;
                    (
                        hold.legs
                            .iter()
                            .map(|l| leg(l.side, &l.account, t))
                            .collect(),
                        Some(vec![0u16, 1]),
                    )
                } else {
                    (Vec::new(), None)
                };
                let mut i = plain(legs, key, date);
                i.class = "Resolution".into();
                i.resolves = Some(Resolve { target, posts });
                (i, None)
            }
            15 if !refs.is_empty() => {
                // Reverse a posted entry: reversing a funding is an outflow.
                let candidates: Vec<usize> = (0..refs.len())
                    .filter(|i| !reversed.contains(i))
                    .filter(|i| {
                        oracle.entry(*i).is_some_and(|e| {
                            matches!(e.class.as_str(), "Original" | "Reversal")
                                || (e.class == "Resolution" && !e.legs.is_empty())
                        })
                    })
                    .collect();
                if candidates.is_empty() {
                    continue;
                }
                let target = candidates[rng.below(candidates.len() as u64) as usize];
                let original = oracle.entry(target).expect("posted").clone();
                let mut i = plain(
                    original
                        .legs
                        .iter()
                        .map(|l| leg(l.side.flipped(), &l.account, l.mantissa))
                        .collect(),
                    key,
                    date,
                );
                i.class = "Reversal".into();
                i.reverses = Some(target);
                (i, None)
            }
            16 => {
                // Two legs on cash in one entry: judged on the net movement.
                let a = 1 + rng.below(40_000) as i128;
                let b = near(&mut rng, cash_avail + a);
                let (big, small) = if b >= a { (b, a) } else { (a, b) };
                let mut legs = vec![leg(dr, "1000", a), leg(cr, "1000", b)];
                legs.push(if b >= a {
                    leg(dr, "6000", big - small)
                } else {
                    leg(cr, "4000", big - small)
                });
                if big == small {
                    legs.pop();
                    legs.push(leg(dr, "6000", 1));
                    legs.push(leg(cr, "4000", 1));
                }
                (plain(legs, key, date), None)
            }
            17 if !posted_intents.is_empty() => {
                // An exact resubmission: the recorded outcome, never re-judged.
                let again = posted_intents[rng.below(posted_intents.len() as u64) as usize].clone();
                (again, None)
            }
            _ => {
                // Unlimited accounts only: never touches a cell.
                let a = 1 + rng.below(9_000) as i128;
                (
                    plain(vec![leg(dr, "6000", a), leg(cr, "4000", a)], key, date),
                    None,
                )
            }
        };

        let kernel = kernel_post(&mut k, &intent, usd, &refs);
        let model = oracle.post(&intent);
        match (&kernel, &model) {
            (Ok(Posted::Committed { entry_ref, .. }), Verdict::Posted { index, .. }) => {
                assert_eq!(*index, refs.len(), "step {step}: journal index");
                refs.push(*entry_ref);
                posted += 1;
                posted_intents.push(intent.clone());
                match intent.class.as_str() {
                    "Pending" => {
                        holds.push(*index);
                        if intent.legs[1].account == "1000" {
                            outflow_holds += 1;
                        }
                    }
                    "Resolution" => {
                        let r = intent.resolves.as_ref().expect("resolution");
                        resolved.insert(r.target);
                        if r.posts.is_some() {
                            posts_resolutions += 1;
                        } else {
                            voids += 1;
                        }
                    }
                    "Reversal" => {
                        reversed.insert(intent.reverses.expect("target"));
                    }
                    _ => {}
                }
                if let Some((edge, amount, out)) = boundary
                    && amount == edge
                {
                    if out {
                        exact_out += 1;
                    } else {
                        exact_in += 1;
                    }
                }
            }
            (Ok(Posted::AlreadyRecorded { entry_ref, .. }), Verdict::Recorded { index }) => {
                assert_eq!(*entry_ref, refs[*index], "step {step}: recorded handle");
                recorded += 1;
            }
            (Err(r), Verdict::Refused { code }) => {
                assert_eq!(r.code, *code, "step {step}: refusal for {intent:?}: {r}");
                *refused.entry(code).or_insert(0) += 1;
                if matches!(*code, "FA-REF-090" | "FA-REF-091") {
                    // A breach names the bound, the net, the reservations,
                    // and the fix.
                    assert!(
                        r.message.contains("bound") && r.message.contains("net"),
                        "{r}"
                    );
                    assert!(r.cite.contains("§5.4"), "{r}");
                    assert!(r.fix.contains("Resolution(Voids)"), "{r}");
                    assert_eq!(r.exit, exit::REFUSAL);
                }
                if let Some((edge, amount, out)) = boundary
                    && amount == edge.max(0) + 1
                {
                    if out && *code == "FA-REF-090" {
                        over_out += 1;
                    }
                    if !out && *code == "FA-REF-091" {
                        over_in += 1;
                    }
                }
            }
            _ => assert_eq!(
                format!("kernel {kernel:?}"),
                format!("oracle {model:?}"),
                "step {step}: disagreement on {intent:?}"
            ),
        }
        assert_cell(&k, &oracle, "1000", step);
        assert_cell(&k, &oracle, "2100", step);
        // The law is an invariant of every committed prefix here: both
        // accounts were born inside their bounds.
        let (l, u) = oracle_lu(&oracle, "1000", true);
        assert!(l >= 0 && u <= 400_000, "step {step}: cash L {l} U {u}");
        assert!(oracle_lu(&oracle, "2100", false).1 <= 150_000);
    }

    // Agreement is not vacuous: every outcome kind happened, and the
    // boundary was hit from both sides on both bounds.
    assert!(posted >= 120, "posted {posted}");
    assert!(recorded >= 3, "recorded {recorded}");
    assert!(outflow_holds >= 5, "outflow holds {outflow_holds}");
    assert!(
        posts_resolutions >= 5 && voids >= 5,
        "resolutions {posts_resolutions}/{voids}"
    );
    assert!(reversed.len() >= 5, "reversals {}", reversed.len());
    assert!(
        exact_out >= 3 && over_out >= 3,
        "outflow boundary {exact_out}/{over_out}"
    );
    assert!(
        exact_in >= 2 && over_in >= 2,
        "inflow boundary {exact_in}/{over_in}"
    );
    for must in ["FA-REF-090", "FA-REF-091"] {
        assert!(
            refused.get(must).is_some_and(|n| *n >= 5),
            "refusal {must} under-exercised: {refused:?}"
        );
    }

    // `fa verify availability` refolds both cells from the payloads.
    let verified = verify_availability(&k.db, &k.book, None).unwrap();
    assert!(verified.is_green(), "{verified:?}");
    assert_eq!(verified.accounts_checked, 2);
    for a in &verified.accounts {
        let model = oracle.availability_in(&a.code, a.period.as_deref());
        assert_eq!(a.cell.generation as u64, model.generation, "{}", a.code);
        assert_eq!(
            Some(a.cell.credits_pending),
            model.credits_pending.to_i128()
        );
    }

    // Race: a transaction that witnessed the cash cell loses to a post that
    // moved the cell first — first committer wins, never an overdraft by
    // interleaving. The racer is whichever move is admissible now: fund if
    // there is room under the cap, spend if anything is available, else
    // void an open hold (some hold must be open when U = cap and L = 0).
    let cash = account_vid(k.book.book_id, "1000");
    let cash_cell = limit_cell_vid(cash);
    let (l, u) = oracle_lu(&oracle, "1000", true);
    let base = Intent {
        class: "Original".into(),
        date: dates[0],
        discriminator: None,
        legs: vec![leg(dr, "1000", 1), leg(cr, "3000", 1)],
        key: b"race".to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    };
    let racer = if u < 400_000 {
        base.clone()
    } else if l >= 1 {
        Intent {
            legs: vec![leg(dr, "6000", 1), leg(cr, "1000", 1)],
            ..base.clone()
        }
    } else {
        let target = holds
            .iter()
            .copied()
            .find(|h| !resolved.contains(h))
            .expect("an open hold when cash is pinned at both bounds");
        Intent {
            class: "Resolution".into(),
            legs: Vec::new(),
            resolves: Some(Resolve {
                target,
                posts: None,
            }),
            ..base.clone()
        }
    };
    let ctx = k.ctx();
    let txn_cx = ctx.txn();
    // The slow transaction witnesses the cash cell; a control transaction
    // witnesses only the facility's cell, which the racer never moves.
    let mut slow = k.db.begin(&txn_cx).expect("begin the slow transaction");
    let witnessed = LimitCell::decode(
        &slow
            .vertex(&k.db, cash_cell)
            .expect("read")
            .expect("cash cell"),
    )
    .expect("decode");
    let mut control = k.db.begin(&txn_cx).expect("begin the control transaction");
    let loan_cell = limit_cell_vid(account_vid(k.book.book_id, "2100"));
    assert!(control.vertex(&k.db, loan_cell).expect("read").is_some());
    let won = kernel_post(&mut k, &racer, usd, &refs);
    assert!(matches!(won, Ok(Posted::Committed { .. })), "{won:?}");
    assert!(matches!(oracle.post(&racer), Verdict::Posted { .. }));
    refs.push(won.expect("committed").entry_ref());
    // Staging a move computed from the stale witness is refused outright:
    // the workspace's snapshot is behind the commit stream.
    let stale = LimitCell {
        credits_posted: witnessed.credits_posted + 1,
        generation: witnessed.generation + 1,
        ..witnessed
    };
    let mut batch = WriteBatch::new(fa_model::symbols::relation::HAS_LEG);
    witnessed
        .stage(&stale, cash_cell, &mut batch)
        .expect("stage the stale move");
    let staged = slow.write_ordered(&mut k.db, vec![batch.clone()]);
    assert!(
        matches!(staged, Err(fgdb::WriteTxnError::SnapshotAdvanced { .. })),
        "{staged:?}"
    );
    // Advancing the snapshot validates every observation: the witnessed
    // cash cell moved, so the slow transaction loses (first committer
    // wins), never re-reads its way into an overdraft.
    let refreshed = slow.refresh_snapshot(&k.db, &txn_cx);
    assert!(
        matches!(
            refreshed,
            Err(fgdb::WriteTxnError::Write(
                fgdb::WriteError::FirstCommitterWins { .. }
            ))
        ),
        "a stale availability witness must lose: {refreshed:?}"
    );
    slow.abort();
    // Positive control: the same refresh succeeds for a transaction whose
    // witness the racer did not touch, so the loss above is the cell's.
    let advanced = control.refresh_snapshot(&k.db, &txn_cx);
    assert!(advanced.is_ok(), "{advanced:?}");
    control.abort();
    assert_cell(&k, &oracle, "1000", 10_000);
    assert!(
        verify_availability(&k.db, &k.book, None)
            .unwrap()
            .is_green()
    );
    let fund = base;

    // Corruption negatives: a cell whose sums are wrong is drift to the
    // verifier; a cell without its generation is drift to the verifier and
    // corruption to the kernel, which then admits nothing on that account
    // (fail closed) while unlimited accounts still post.
    let ctx = k.ctx();
    let stored = LimitCell::decode(&k.db.vertex(cash_cell).unwrap().unwrap()).unwrap();
    let mut batch = WriteBatch::new(fa_model::symbols::relation::HAS_LEG);
    batch.set_vertex_property(
        cash_cell,
        fa_model::symbols::property::CREDITS_PENDING,
        Some(
            fa_journal::rows::mantissa_scalar("credits_pending", stored.credits_pending + 7)
                .unwrap(),
        ),
    );
    k.runtime
        .block_on(async { k.db.write(&ctx.commit(), batch).await })
        .expect("plant a drifted cell");
    let drifted = verify_availability(&k.db, &k.book, None).unwrap();
    assert!(!drifted.is_green());
    assert!(
        drifted.drift.iter().any(|d| d.code == "1000"
            && d.stored
                .is_some_and(|c| c.credits_pending == stored.credits_pending + 7)),
        "{drifted:?}"
    );
    let mut batch = WriteBatch::new(fa_model::symbols::relation::HAS_LEG);
    batch.set_vertex_property(cash_cell, fa_model::symbols::property::GENERATION, None);
    k.runtime
        .block_on(async { k.db.write(&ctx.commit(), batch).await })
        .expect("plant a cell without generation");
    let broken = verify_availability(&k.db, &k.book, None).unwrap();
    assert!(
        broken
            .drift
            .iter()
            .any(|d| d.code == "1000" && d.stored.is_none()),
        "{broken:?}"
    );
    let probe = Intent {
        key: b"after-corruption".to_vec(),
        ..fund.clone()
    };
    assert!(
        matches!(
            kernel_post_raw(&mut k, &probe, usd, &refs),
            Err(KernelError::Corrupt(_))
        ),
        "a post on a corrupt limited account fails closed"
    );
    let elsewhere = Intent {
        key: b"unlimited-after-corruption".to_vec(),
        legs: vec![leg(dr, "6000", 5), leg(cr, "4000", 5)],
        ..fund
    };
    assert!(matches!(
        kernel_post(&mut k, &elsewhere, usd, &refs),
        Ok(Posted::Committed { .. })
    ));
}

// ---------------------------------------------------------------------------
// Budget caps and balancing legs (plan §5.5; bead fa-rqe 2c)
// ---------------------------------------------------------------------------

/// Cash has a floor, the facility a cap on drawn principal, and expense 6100
/// a budget cap per period (6200 is budget-capped after its periods exist,
/// so its cells come from chart install rather than period creation).
const BUDGETED: &[ChartRow] = &[
    (
        "1000",
        1,
        true,
        0,
        Some(BalanceLimit {
            lower: Some(0),
            upper: None,
            scope: LimitScope::Lifetime,
        }),
    ),
    (
        "2100",
        2,
        true,
        1,
        Some(BalanceLimit {
            lower: None,
            upper: Some(150_000),
            scope: LimitScope::Lifetime,
        }),
    ),
    (
        "6100",
        5,
        true,
        0,
        Some(BalanceLimit {
            lower: None,
            upper: Some(50_000),
            scope: LimitScope::Period,
        }),
    ),
    ("3000", 3, true, 1, None),
    ("4000", 4, true, 1, None),
    ("6000", 5, true, 0, None),
];

/// `(L, U)` of one cell on the oracle's literal fold (`period: None` is the
/// lifetime cell), in the account's normal-balance sign.
fn oracle_lu_in(
    oracle: &Oracle,
    code: &str,
    period: Option<&str>,
    debit_normal: bool,
) -> (i128, i128) {
    let a = oracle.availability_in(code, period);
    let v = |x: &Int| x.to_i128().expect("generated sums fit i128");
    let (dp, cp, dr, cr) = (
        v(&a.debits_posted),
        v(&a.credits_posted),
        v(&a.debits_pending),
        v(&a.credits_pending),
    );
    if debit_normal {
        (dp - cp - cr, dp - cp + dr)
    } else {
        (cp - dp - dr, cp - dp + cr)
    }
}

/// The kernel's stored cell (bound to its account and period) equals the
/// oracle's literal fold, generation included.
fn assert_cell_in(k: &Kernel, oracle: &Oracle, code: &str, period: Option<&str>, step: u64) {
    let account = account_vid(k.book.book_id, code);
    let row =
        k.db.vertex(fa_journal::limit::cell_vid(account, period))
            .expect("read")
            .expect("limit cell exists");
    let cell = LimitCell::decode_bound(&row, account, period).expect("bound cell");
    let a = oracle.availability_in(code, period);
    assert_eq!(
        (
            Some(cell.debits_posted),
            Some(cell.credits_posted),
            Some(cell.debits_pending),
            Some(cell.credits_pending),
            u64::try_from(cell.generation).expect("non-negative"),
        ),
        (
            a.debits_posted.to_i128(),
            a.credits_posted.to_i128(),
            a.debits_pending.to_i128(),
            a.credits_pending.to_i128(),
            a.generation,
        ),
        "step {step}: cell of {code} in {period:?}"
    );
}

#[test]
fn kernel_and_oracle_agree_on_budget_caps_and_balancing() {
    let (mut k, mut oracle, periods) = setup_with(BUDGETED);
    let usd = k.book.units.lookup("USD").unwrap();
    for (n, p) in periods[1..4].iter().enumerate() {
        open_period(&mut k, &mut oracle, p, 1 + n as u64);
    }
    // 6200: budget-capped after its periods exist (chart-install cells).
    {
        let spec = AccountSpec {
            code: "6200".into(),
            name: "6200".into(),
            account_type: 5,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: Some(BalanceLimit {
                lower: None,
                upper: Some(20_000),
                scope: LimitScope::Period,
            }),
        };
        let ctx = k.ctx();
        let db = &mut k.db;
        let book = &k.book;
        let day = DateDay::from_ymd(2026, 1, 1).unwrap();
        let description =
            Erasable::seal(&"chart".to_string(), None, &book.seal_key, [5; 32], [6; 24]);
        k.runtime
            .block_on(async move {
                install_chart(
                    db,
                    &ctx,
                    book,
                    &[spec],
                    PRINCIPAL,
                    day,
                    b"6200",
                    description,
                    &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
                )
                .await
            })
            .expect("kernel")
            .expect("installs");
        oracle.add_account(Account {
            code: "6200".into(),
            is_leaf: true,
            unit: Some(usd.0),
        });
        oracle.set_limit(
            "6200",
            Limit {
                normal: fa_reference::Side::Debit,
                lower: None,
                upper: Some(20_000),
                per_period: true,
            },
        );
    }
    let dated = [
        (DateDay::from_ymd(2026, 2, 10).unwrap(), periods[1].clone()),
        (DateDay::from_ymd(2026, 3, 15).unwrap(), periods[2].clone()),
        (DateDay::from_ymd(2026, 4, 20).unwrap(), periods[3].clone()),
    ];
    let leg = |side: fa_reference::Side, account: &str, mantissa: i128| Leg {
        side,
        account: account.into(),
        unit: usd.0,
        entity: None,
        mantissa,
    };
    let dr = fa_reference::Side::Debit;
    let cr = fa_reference::Side::Credit;
    let plain = |class: &str, legs: Vec<Leg>, key: Vec<u8>, date: DateDay| Intent {
        class: class.into(),
        date,
        discriminator: None,
        legs,
        key,
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    };
    let mut rng = Rng(0x0BAD_C0DE_5EED_1234);
    let mut refs: Vec<EntryRef> = Vec::new();
    let mut plain_posted: Vec<Intent> = Vec::new();
    // (request, balancing leg, journal index, moved)
    let mut balanced: Vec<(Intent, u16, usize, i128)> = Vec::new();
    let mut holds: Vec<usize> = Vec::new();
    let mut resolved: BTreeSet<usize> = BTreeSet::new();
    let mut reversed: BTreeSet<usize> = BTreeSet::new();
    let mut refused: BTreeMap<&'static str, u32> = BTreeMap::new();
    let (mut posted, mut recorded) = (0u32, 0u32);
    let (mut reduced, mut full) = (0u32, 0u32);
    let mut budget_exact = 0u32;
    let mut cross_period_posts = 0u32;
    // Planted negatives and identity probes: each fires once, at the first
    // step where its precondition holds.
    let mut needed: BTreeSet<&'static str> = [
        "shape-legs",
        "shape-unequal",
        "shape-account",
        "shape-leg",
        "shape-class",
        "retry-same",
        "retry-other-amount",
        "retry-other-leg",
        "retry-same-later",
        "cross-period",
    ]
    .into_iter()
    .collect();
    let (mut identity_recorded, mut identity_conflicts) = (0u32, 0u32);
    // The first reduced balancing post: the identity probes' subject.
    let mut probe: Option<(Intent, u16, usize, i128)> = None;

    for step in 0..640u64 {
        let key = format!("b{step}").into_bytes();
        let (date, period) = dated[rng.below(3) as usize].clone();
        let budget_room = |o: &Oracle, code: &str, cap: i128, p: &str| {
            cap - oracle_lu_in(o, code, Some(p), true).1
        };
        let (cash_avail, _) = oracle_lu_in(&oracle, "1000", None, true);
        let (_, loan_u) = oracle_lu_in(&oracle, "2100", None, false);
        let mut planted: Option<(Intent, Option<u16>)> = None;
        // Which identity probe this step is, if any (only planted probes count).
        let mut probe_tag: Option<&'static str> = None;
        if let Some(tag) = needed.iter().copied().find(|t| t.starts_with("shape-")) {
            let two = vec![leg(dr, "6000", 10), leg(cr, "1000", 10)];
            let (intent, l) = match tag {
                "shape-legs" => (
                    plain(
                        "Original",
                        vec![leg(dr, "6000", 10), leg(cr, "1000", 6), leg(cr, "3000", 4)],
                        key.clone(),
                        date,
                    ),
                    0,
                ),
                "shape-unequal" => (
                    plain(
                        "Original",
                        vec![leg(dr, "6000", 10), leg(cr, "1000", 9)],
                        key.clone(),
                        date,
                    ),
                    0,
                ),
                "shape-account" => (
                    plain(
                        "Original",
                        vec![leg(dr, "1000", 10), leg(cr, "1000", 10)],
                        key.clone(),
                        date,
                    ),
                    1,
                ),
                "shape-leg" => (plain("Original", two, key.clone(), date), 2),
                _ => (plain("Reversal", two, key.clone(), date), 0),
            };
            needed.remove(tag);
            planted = Some((intent, Some(l)));
        } else if let Some((request, l, _, _)) = probe.clone() {
            if needed.contains("retry-same") {
                needed.remove("retry-same");
                probe_tag = Some("retry-same");
                planted = Some((request, Some(l)));
            } else if needed.contains("retry-other-amount") {
                needed.remove("retry-other-amount");
                probe_tag = Some("retry-other-amount");
                let mut other = request.clone();
                for x in &mut other.legs {
                    x.mantissa -= 1;
                }
                planted = Some((other, Some(l)));
            } else if needed.contains("retry-other-leg") {
                needed.remove("retry-other-leg");
                probe_tag = Some("retry-other-leg");
                planted = Some((request, Some(1 - l)));
            } else if needed.contains("retry-same-later") && step > 300 {
                // Availability has moved on since; the recorded outcome holds.
                needed.remove("retry-same-later");
                probe_tag = Some("retry-same-later");
                planted = Some((request, Some(l)));
            }
        }
        if planted.is_none()
            && needed.contains("cross-period")
            && step % 7 == 0
            && let Some(h) = holds.iter().copied().find(|h| {
                !resolved.contains(h) && oracle.entry(*h).is_some_and(|e| e.period == periods[1])
            })
        {
            // A February encumbrance posted in April: releases February's
            // budget cell, charges April's (retried until April has room).
            let hold = oracle.entry(h).expect("hold").clone();
            let t = 1;
            let mut i = plain(
                "Resolution",
                hold.legs
                    .iter()
                    .map(|x| leg(x.side, &x.account, t))
                    .collect(),
                key.clone(),
                dated[2].0,
            );
            i.resolves = Some(Resolve {
                target: h,
                posts: Some(vec![0, 1]),
            });
            planted = Some((i, None));
        }
        let (intent, balancing) = if let Some(p) = planted {
            p
        } else {
            match rng.below(24) {
                0..=2 => {
                    let a = 1 + rng.below(80_000) as i128;
                    (
                        plain(
                            "Original",
                            vec![leg(dr, "1000", a), leg(cr, "3000", a)],
                            key,
                            date,
                        ),
                        None,
                    )
                }
                3..=5 => {
                    let edge = budget_room(&oracle, "6100", 50_000, &period);
                    let a = near(&mut rng, edge.min(cash_avail.max(1)));
                    (
                        plain(
                            "Original",
                            vec![leg(dr, "6100", a), leg(cr, "1000", a)],
                            key,
                            date,
                        ),
                        None,
                    )
                }
                6..=7 => {
                    let edge = budget_room(&oracle, "6100", 50_000, &period);
                    let a = near(&mut rng, edge);
                    (
                        plain(
                            "Pending",
                            vec![leg(dr, "6100", a), leg(cr, "3000", a)],
                            key,
                            date,
                        ),
                        None,
                    )
                }
                8..=10 if holds.iter().any(|h| !resolved.contains(h)) => {
                    let open: Vec<usize> = holds
                        .iter()
                        .copied()
                        .filter(|h| !resolved.contains(h))
                        .collect();
                    let target = open[rng.below(open.len() as u64) as usize];
                    let hold = oracle.entry(target).expect("hold").clone();
                    let (legs, posts) = if rng.chance(60) {
                        let t = 1 + rng.below(hold.legs[0].mantissa as u64) as i128;
                        (
                            hold.legs
                                .iter()
                                .map(|x| leg(x.side, &x.account, t))
                                .collect(),
                            Some(vec![0u16, 1]),
                        )
                    } else {
                        (Vec::new(), None)
                    };
                    let mut i = plain("Resolution", legs, key, date);
                    i.resolves = Some(Resolve { target, posts });
                    (i, None)
                }
                11..=14 => {
                    // Balancing budget spend: the budget leg balances. Mostly
                    // over the room (moves the room), sometimes within it
                    // (moves the whole request).
                    let edge = budget_room(&oracle, "6100", 50_000, &period);
                    let r = if rng.chance(30) && edge > 1 {
                        1 + rng.below(edge as u64) as i128
                    } else {
                        edge.max(0) + 1 + rng.below(30_000) as i128
                    };
                    (
                        plain(
                            "Original",
                            vec![leg(dr, "6100", r), leg(cr, "1000", r)],
                            key,
                            date,
                        ),
                        Some(0),
                    )
                }
                15..=16 => {
                    // Balancing cash spend: the cash leg balances.
                    let r = if rng.chance(30) && cash_avail > 1 {
                        1 + rng.below(cash_avail as u64) as i128
                    } else {
                        cash_avail.max(0) + 1 + rng.below(20_000) as i128
                    };
                    (
                        plain(
                            "Original",
                            vec![leg(dr, "6000", r), leg(cr, "1000", r)],
                            key,
                            date,
                        ),
                        Some(1),
                    )
                }
                17 => {
                    // Balancing draw on the facility (credit-normal, capped).
                    let r = (150_000 - loan_u).max(0) + rng.below(20_000) as i128 + 1;
                    (
                        plain(
                            "Original",
                            vec![leg(dr, "1000", r), leg(cr, "2100", r)],
                            key,
                            date,
                        ),
                        Some(1),
                    )
                }
                18 => {
                    // Balancing encumbrance on 6200: reserve up to its room.
                    let edge = budget_room(&oracle, "6200", 20_000, &period);
                    let r = edge.max(0) + 1 + rng.below(10_000) as i128;
                    (
                        plain(
                            "Pending",
                            vec![leg(dr, "6200", r), leg(cr, "3000", r)],
                            key,
                            date,
                        ),
                        Some(0),
                    )
                }
                19 if !refs.is_empty() => {
                    let candidates: Vec<usize> = (0..refs.len())
                        .filter(|i| !reversed.contains(i))
                        .filter(|i| {
                            oracle.entry(*i).is_some_and(|e| {
                                matches!(e.class.as_str(), "Original" | "Reversal")
                                    || (e.class == "Resolution" && !e.legs.is_empty())
                            })
                        })
                        .collect();
                    if candidates.is_empty() {
                        continue;
                    }
                    let target = candidates[rng.below(candidates.len() as u64) as usize];
                    let original = oracle.entry(target).expect("posted").clone();
                    let mut i = plain(
                        "Reversal",
                        original
                            .legs
                            .iter()
                            .map(|x| leg(x.side.flipped(), &x.account, x.mantissa))
                            .collect(),
                        key,
                        date,
                    );
                    i.reverses = Some(target);
                    (i, None)
                }
                20 if !plain_posted.is_empty() || !balanced.is_empty() => {
                    if !balanced.is_empty() && rng.chance(50) {
                        let (r, l, _, _) =
                            balanced[rng.below(balanced.len() as u64) as usize].clone();
                        (r, Some(l))
                    } else if !plain_posted.is_empty() {
                        (
                            plain_posted[rng.below(plain_posted.len() as u64) as usize].clone(),
                            None,
                        )
                    } else {
                        continue;
                    }
                }
                21 => {
                    // Two legs on the budgeted account in one entry.
                    let a = 1 + rng.below(20_000) as i128;
                    let b = 1 + rng.below(20_000) as i128;
                    let mut legs = vec![leg(dr, "6100", a), leg(cr, "6100", b)];
                    if a > b {
                        legs.push(leg(cr, "3000", a - b));
                    } else if b > a {
                        legs.push(leg(dr, "6000", b - a));
                    } else {
                        legs.push(leg(dr, "6000", 1));
                        legs.push(leg(cr, "3000", 1));
                    }
                    (plain("Original", legs, key, date), None)
                }
                _ => {
                    let a = 1 + rng.below(9_000) as i128;
                    (
                        plain(
                            "Original",
                            vec![leg(dr, "6000", a), leg(cr, "4000", a)],
                            key,
                            date,
                        ),
                        None,
                    )
                }
            }
        };
        let budget_edge = (intent.legs.len() == 2
            && intent.legs[0].account == "6100"
            && intent.resolves.is_none()
            && balancing.is_none())
        .then(|| budget_room(&oracle, "6100", 50_000, &period));
        let is_cross_period = intent.resolves.as_ref().is_some_and(|r| {
            r.posts.is_some()
                && oracle
                    .entry(r.target)
                    .is_some_and(|h| h.period == periods[1] && intent.date == dated[2].0)
        });

        match balancing {
            None => {
                let kernel = kernel_post(&mut k, &intent, usd, &refs);
                let model = oracle.post(&intent);
                match (&kernel, &model) {
                    (Ok(Posted::Committed { entry_ref, .. }), Verdict::Posted { index, .. }) => {
                        assert_eq!(*index, refs.len(), "step {step}: journal index");
                        refs.push(*entry_ref);
                        posted += 1;
                        plain_posted.push(intent.clone());
                        match intent.class.as_str() {
                            "Pending" => holds.push(*index),
                            "Resolution" => {
                                resolved.insert(intent.resolves.as_ref().expect("r").target);
                                if is_cross_period {
                                    cross_period_posts += 1;
                                    needed.remove("cross-period");
                                }
                            }
                            "Reversal" => {
                                reversed.insert(intent.reverses.expect("target"));
                            }
                            _ => {}
                        }
                        if budget_edge
                            .is_some_and(|e| intent.legs.first().is_some_and(|l| l.mantissa == e))
                        {
                            budget_exact += 1;
                        }
                    }
                    (
                        Ok(Posted::AlreadyRecorded { entry_ref, .. }),
                        Verdict::Recorded { index },
                    ) => {
                        assert_eq!(*entry_ref, refs[*index], "step {step}: recorded handle");
                        recorded += 1;
                    }
                    (Err(r), Verdict::Refused { code }) => {
                        assert_eq!(r.code, *code, "step {step}: refusal for {intent:?}: {r}");
                        *refused.entry(code).or_insert(0) += 1;
                    }
                    _ => assert_eq!(
                        format!("kernel {kernel:?}"),
                        format!("oracle {model:?}"),
                        "step {step}: disagreement on {intent:?}"
                    ),
                }
            }
            Some(l) => {
                let kernel = kernel_post_balancing(&mut k, &intent, usd, &refs, l);
                let model = oracle.post_balancing(&intent, l);
                let requested = intent.legs[0].mantissa;
                match (&kernel, &model) {
                    (
                        Ok(Balanced {
                            posted: Posted::Committed { entry_ref, .. },
                            requested: kr,
                            moved,
                        }),
                        Verdict::Posted { index, .. },
                    ) => {
                        assert_eq!(*index, refs.len(), "step {step}: journal index");
                        let model_moved =
                            oracle.entry(*index).expect("entry").legs[usize::from(l)].mantissa;
                        assert_eq!(
                            (*kr, *moved),
                            (requested, model_moved),
                            "step {step}: moved"
                        );
                        assert!(*moved > 0 && *moved <= requested);
                        refs.push(*entry_ref);
                        posted += 1;
                        if *moved < requested {
                            reduced += 1;
                            if probe.is_none() {
                                probe = Some((intent.clone(), l, *index, *moved));
                            }
                        } else {
                            full += 1;
                        }
                        if intent.class == "Pending" {
                            holds.push(*index);
                        }
                        balanced.push((intent.clone(), l, *index, *moved));
                    }
                    (
                        Ok(Balanced {
                            posted: Posted::AlreadyRecorded { entry_ref, .. },
                            moved,
                            ..
                        }),
                        Verdict::Recorded { index },
                    ) => {
                        assert_eq!(*entry_ref, refs[*index], "step {step}: recorded handle");
                        let model_moved =
                            oracle.entry(*index).expect("entry").legs[usize::from(l)].mantissa;
                        assert_eq!(*moved, model_moved, "step {step}: recorded moved");
                        recorded += 1;
                        if matches!(probe_tag, Some("retry-same" | "retry-same-later")) {
                            assert!(
                                probe.as_ref().is_some_and(|(r, pl, pi, pm)| {
                                    r == &intent && *pl == l && *pi == *index && *pm == *moved
                                }),
                                "step {step}: the probe replays its recorded outcome"
                            );
                            identity_recorded += 1;
                        }
                    }
                    (Err(r), Verdict::Refused { code }) => {
                        assert_eq!(
                            r.code, *code,
                            "step {step}: balancing refusal for {intent:?}: {r}"
                        );
                        *refused.entry(code).or_insert(0) += 1;
                        if matches!(probe_tag, Some("retry-other-amount" | "retry-other-leg")) {
                            assert_eq!(
                                *code, "FA-REF-032",
                                "step {step}: a changed request conflicts"
                            );
                            identity_conflicts += 1;
                        }
                    }
                    _ => assert_eq!(
                        format!("kernel {kernel:?}"),
                        format!("oracle {model:?}"),
                        "step {step}: balancing disagreement on {intent:?} leg {l}"
                    ),
                }
            }
        }
        assert_cell_in(&k, &oracle, "1000", None, step);
        assert_cell_in(&k, &oracle, "2100", None, step);
        for p in &periods {
            assert_cell_in(&k, &oracle, "6100", Some(p), step);
            assert_cell_in(&k, &oracle, "6200", Some(p), step);
            // Budget caps hold in every period cell at every prefix.
            assert!(oracle_lu_in(&oracle, "6100", Some(p), true).1 <= 50_000);
            assert!(oracle_lu_in(&oracle, "6200", Some(p), true).1 <= 20_000);
        }
    }

    // Agreement is not vacuous.
    assert!(posted >= 150, "posted {posted}");
    assert!(recorded >= 3, "recorded {recorded}");
    assert!(
        reduced >= 8 && full >= 3,
        "balancing reduced/full {reduced}/{full}"
    );
    assert!(budget_exact >= 2, "budget boundary posts {budget_exact}");
    assert!(
        cross_period_posts >= 1,
        "cross-period encumbrance posts {cross_period_posts}"
    );
    assert!(needed.is_empty(), "planted probes never fired: {needed:?}");
    assert_eq!(
        (identity_recorded, identity_conflicts),
        (2, 2),
        "identity: same request recorded (now and later), other amount/leg conflict"
    );
    assert!(
        refused.get("FA-REF-093").is_some_and(|n| *n >= 5),
        "{refused:?}"
    );
    assert!(
        refused.get("FA-REF-091").is_some_and(|n| *n >= 5),
        "{refused:?}"
    );
    assert!(
        refused.get("FA-REF-090").is_some_and(|n| *n >= 2),
        "{refused:?}"
    );

    // `fa verify availability` refolds every expected cell.
    let all_periods = k.book.calendar.periods_for_year(2026).unwrap().len();
    let verified = verify_availability(&k.db, &k.book, None).unwrap();
    assert!(verified.is_green(), "{verified:?}");
    assert_eq!(verified.accounts_checked, 4);
    assert_eq!(verified.cells_checked, 2 + 2 * all_periods);
    for a in &verified.accounts {
        let model = oracle.availability_in(&a.code, a.period.as_deref());
        assert_eq!(
            a.cell.generation as u64, model.generation,
            "{} {:?}",
            a.code, a.period
        );
        assert_eq!(Some(a.cell.debits_posted), model.debits_posted.to_i128());
        assert_eq!(Some(a.cell.debits_pending), model.debits_pending.to_i128());
    }

    // Corruption negative: rebind March's 6100 cell to February. Verify
    // names the period binding; the kernel refuses every post on 6100 dated
    // in March (fail closed) while April still posts.
    let budget = account_vid(k.book.book_id, "6100");
    let march_cell = fa_journal::limit::period_cell_vid(budget, &periods[2]);
    {
        let ctx = k.ctx();
        let mut batch = WriteBatch::new(fa_model::symbols::relation::HAS_LEG);
        batch.set_vertex_property(
            march_cell,
            fa_model::symbols::property::EFFECTIVE_PERIOD,
            Some(fgdb_types::CanonicalScalar::ucs_basic_text(&periods[1]).unwrap()),
        );
        k.runtime
            .block_on(async { k.db.write(&ctx.commit(), batch).await })
            .expect("plant a rebound period cell");
    }
    let rebound = verify_availability(&k.db, &k.book, None).unwrap();
    assert!(
        rebound.drift.iter().any(|d| d.code == "6100"
            && d.period.as_deref() == Some(periods[2].as_str())
            && d.stored_period.as_deref() == Some(periods[1].as_str())),
        "{rebound:?}"
    );
    let credit_back = |key: &[u8], date: DateDay| Intent {
        class: "Original".into(),
        date,
        discriminator: None,
        legs: vec![
            Leg {
                side: fa_reference::Side::Debit,
                account: "1000".into(),
                unit: usd.0,
                entity: None,
                mantissa: 1,
            },
            Leg {
                side: fa_reference::Side::Credit,
                account: "6100".into(),
                unit: usd.0,
                entity: None,
                mantissa: 1,
            },
        ],
        key: key.to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    };
    assert!(matches!(
        kernel_post_raw(
            &mut k,
            &credit_back(b"march-after-rebind", dated[1].0),
            usd,
            &refs
        ),
        Err(KernelError::Corrupt(_))
    ));
    assert!(matches!(
        kernel_post(
            &mut k,
            &credit_back(b"april-after-rebind", dated[2].0),
            usd,
            &refs
        ),
        Ok(Posted::Committed { .. })
    ));
}

// ---------------------------------------------------------------------------
// TimeEvidence ticks, timed holds, and the expiry sweep (plan §5.4, §7.1a;
// bead fa-ctf)
// ---------------------------------------------------------------------------

/// The book's intrinsic actor: its System principal, the sweep's principal
/// and the preparer of everything the book mints itself.
fn system(k: &Kernel) -> VId {
    rows::system_principal(k.book.book_id)
}

/// A description sealed under fresh salt and nonce, so no nonce is ever
/// reused under the book key with a different plaintext.
fn fresh_seal(key: &SealKey, text: &str) -> Erasable<String> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let n = NEXT
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        .to_le_bytes();
    let mut salt = [0x5e; 32];
    salt[..8].copy_from_slice(&n);
    let mut nonce = [0x6f; 24];
    nonce[..8].copy_from_slice(&n);
    Erasable::seal(&text.to_string(), None, key, salt, nonce)
}

fn tick_request(k: &Kernel, observed_utc_ns: u64, key: &str) -> TickRequest {
    TickRequest {
        observed_utc_ns,
        source: fa_journal::sweep::SOURCE_DAEMON_CLOCK,
        monotonic_ok: true,
        principal_ref: PRINCIPAL,
        capability: Capability::embedded(PRINCIPAL, &["witness"]).expect("registered ops"),
        idempotency_key: key.as_bytes().to_vec(),
        description: fresh_seal(&k.book.seal_key, "tick"),
    }
}

fn kernel_tick_raw(k: &mut Kernel, req: TickRequest) -> Result<Ticked, Refusal> {
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    k.runtime
        .block_on(async move { record_tick(db, &ctx, book, req).await })
        .expect("kernel")
}

fn kernel_tick(k: &mut Kernel, observed_utc_ns: u64, key: &str) -> Result<Ticked, Refusal> {
    let req = tick_request(k, observed_utc_ns, key);
    kernel_tick_raw(k, req)
}

/// A timed hold: the oracle intent's kernel request with `timeout_ns`.
fn kernel_post_timed(
    k: &mut Kernel,
    intent: &Intent,
    usd: UnitId,
    refs: &[EntryRef],
    timeout_ns: u64,
) -> Result<Posted, Refusal> {
    let mut req = kernel_request(k, intent, usd, refs);
    if let Some(p) = req.proposal.pending.as_mut() {
        p.timeout_ns = Some(timeout_ns);
    }
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    k.runtime
        .block_on(async move { post(db, &ctx, book, req).await })
        .expect("kernel")
}

fn sweeper(k: &Kernel, max_batch: usize) -> SweepRequest {
    let system = system(k);
    SweepRequest {
        principal_ref: system,
        capability: Capability::new(system, Profile::System, &[Op::Post], system)
            .expect("a System capability"),
        max_batch,
    }
}

fn kernel_sweep_raw(k: &mut Kernel, req: &SweepRequest) -> Result<Option<SweepBatch>, Refusal> {
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    k.runtime
        .block_on(async move {
            let mut describe = |text: &str| Ok::<_, KernelError>(fresh_seal(&book.seal_key, text));
            sweep_batch(db, &ctx, book, req, &mut describe).await
        })
        .expect("kernel")
}

fn kernel_sweep(k: &mut Kernel, max_batch: usize) -> Result<Option<SweepBatch>, Refusal> {
    let req = sweeper(k, max_batch);
    kernel_sweep_raw(k, &req)
}

/// The kernel's due backlog as oracle journal indices.
fn kernel_due(k: &Kernel, refs: &[EntryRef]) -> Vec<usize> {
    due_holds(&k.db, None)
        .expect("due scan")
        .iter()
        .map(|d| {
            refs.iter()
                .position(|r| *r == d.hold)
                .expect("a due hold the differential posted")
        })
        .collect()
}

/// One sweep batch on both engines; the verdicts, the expired holds, their
/// derived identities, and the backlog must agree. The resolutions join
/// `refs` at the oracle's journal indices. `Some(batch)` when one committed.
fn sweep_both(
    k: &mut Kernel,
    oracle: &mut Oracle,
    refs: &mut Vec<EntryRef>,
    max_batch: usize,
    step: u64,
) -> Option<fa_reference::SweepBatch> {
    let kernel = kernel_sweep(k, max_batch);
    let model = oracle.sweep_batch(max_batch);
    match (&kernel, &model) {
        (Ok(None), Ok(None)) => None,
        (Ok(Some(b)), Ok(Some(m))) => {
            assert_eq!(b.tick.observed_utc_ns, m.tick, "step {step}: sweep tick");
            assert_eq!(b.remaining_due, m.remaining_due, "step {step}: backlog");
            assert_eq!(b.expired.len(), m.expired.len(), "step {step}: batch size");
            assert!(b.expired.len() <= max_batch, "step {step}: batch bound");
            for ((hold, expires), (h, index)) in b.expired.iter().zip(&m.expired) {
                assert_eq!(*hold, refs[*h], "step {step}: expired hold");
                assert_eq!(*index, refs.len(), "step {step}: journal index");
                assert_eq!(expires.vid, rows::resolution_vid(hold.vid));
                refs.push(*expires);
            }
            let last = b.expired.last().expect("a committed batch expires").0;
            assert_eq!(
                b.cursor_entry.vid,
                rows::sweep_cursor_vid(b.tick.entry, last.vid),
                "step {step}: cursor identity"
            );
            Some(m.clone())
        }
        (Err(r), Err(code)) => {
            assert_eq!(r.code, *code, "step {step}: sweep refusal {r}");
            None
        }
        _ => {
            assert_eq!(
                format!("kernel {kernel:?}"),
                format!("oracle {model:?}"),
                "step {step}: sweep disagreement"
            );
            None
        }
    }
}

/// The pending registers of `periods` agree with the oracle's literal fold:
/// a due-but-unswept hold is still pending; an expired one released its own
/// period's reservation exactly once.
fn assert_pending_registers(k: &Kernel, oracle: &Oracle, periods: &[String], step: u64) {
    for code in periods {
        let kernel_fold = fold_period(&k.db, &k.book, code).unwrap();
        let model = oracle.pending_fold(code);
        assert_eq!(
            kernel_fold.pending.len(),
            model.len(),
            "step {step}: {code} pending cell count"
        );
        for cell in &kernel_fold.pending {
            let account = BUDGETED
                .iter()
                .map(|(c, ..)| *c)
                .find(|c| account_vid(k.book.book_id, c) == cell.key.account)
                .expect("known account");
            let m = model
                .get(&(account.to_string(), cell.key.unit_id))
                .expect("the oracle has the pending cell");
            assert_eq!(
                (m.debits.to_i128(), m.credits.to_i128()),
                (Some(cell.debits), Some(cell.credits)),
                "step {step}: {code}/{account} pending"
            );
        }
    }
}

/// A timed hold on both engines: the verdicts and the derived deadline
/// agree. `Some(index)` when it posted.
#[allow(clippy::too_many_arguments)]
fn post_timed_both(
    k: &mut Kernel,
    oracle: &mut Oracle,
    refs: &mut Vec<EntryRef>,
    refused: &mut BTreeMap<&'static str, u32>,
    intent: &Intent,
    usd: UnitId,
    timeout: u64,
    step: u64,
) -> Option<usize> {
    let kernel = kernel_post_timed(k, intent, usd, refs, timeout);
    let model = oracle.post_timed(intent, timeout);
    match (&kernel, &model) {
        (Ok(Posted::Committed { entry_ref, .. }), Verdict::Posted { index, .. }) => {
            assert_eq!(*index, refs.len(), "step {step}: journal index");
            refs.push(*entry_ref);
            let seq =
                k.db.vertex(entry_ref.vid)
                    .unwrap()
                    .expect("hold row")
                    .created_at;
            assert_eq!(
                oracle.deadline(*index),
                fa_journal::sweep::deadline(&k.db, seq, timeout).ok(),
                "step {step}: the deadline derived from the hold's journal position"
            );
            Some(*index)
        }
        (Err(r), Verdict::Refused { code }) => {
            assert_eq!(r.code, *code, "step {step}: {r}");
            *refused.entry(code).or_insert(0) += 1;
            None
        }
        _ => {
            assert_eq!(
                format!("kernel {kernel:?}"),
                format!("oracle {model:?}"),
                "step {step}: timed hold disagreement on {intent:?}"
            );
            None
        }
    }
}

fn close_and_maybe_lock(k: &mut Kernel, oracle: &mut Oracle, code: &str, lock: bool, step: u64) {
    let mut moves = vec![PeriodTransition::SoftClose, PeriodTransition::Close];
    if lock {
        moves.push(PeriodTransition::Lock);
    }
    for (i, t) in moves.into_iter().enumerate() {
        let kernel = kernel_transition(k, code, t, step * 10 + i as u64).expect("transition");
        let model = oracle.transition(code, t).expect("oracle transition");
        assert_eq!((kernel.from, kernel.to), model, "{code} {t:?}");
        assert_eq!(
            Some(journaled_date(k, kernel.control_entry)),
            oracle.transition_date(code, t),
            "{code} {t:?} control date"
        );
    }
}

#[test]
fn kernel_and_oracle_agree_on_ticks_timed_holds_and_the_expiry_sweep() {
    let (mut k, mut oracle, periods) = setup_with(BUDGETED);
    let usd = k.book.units.lookup("USD").unwrap();
    for (i, p) in periods.iter().take(4).enumerate() {
        open_period(&mut k, &mut oracle, p, 9_000 + i as u64);
    }
    let watched: Vec<String> = periods.iter().take(4).cloned().collect();
    let dated = [
        DateDay::from_ymd(2026, 1, 20).unwrap(),
        DateDay::from_ymd(2026, 2, 10).unwrap(),
        DateDay::from_ymd(2026, 3, 15).unwrap(),
        DateDay::from_ymd(2026, 4, 20).unwrap(),
    ];
    let leg = |side: fa_reference::Side, account: &str, mantissa: i128| Leg {
        side,
        account: account.into(),
        unit: usd.0,
        entity: None,
        mantissa,
    };
    let dr = fa_reference::Side::Debit;
    let cr = fa_reference::Side::Credit;
    let plain = |class: &str, legs: Vec<Leg>, key: Vec<u8>, date: DateDay| Intent {
        class: class.into(),
        date,
        discriminator: None,
        legs,
        key,
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    };
    let mut rng = Rng(0x7135_EED5_0FA0_C7F1);
    let mut refs: Vec<EntryRef> = Vec::new();
    let mut holds: Vec<usize> = Vec::new();
    let mut resolved: BTreeSet<usize> = BTreeSet::new();
    let mut expired: BTreeSet<usize> = BTreeSet::new();
    let mut refused: BTreeMap<&'static str, u32> = BTreeMap::new();
    let mut now: u64 = 0;
    let mut tick_seq = 0u64;
    // Coverage floors (asserted at the end).
    let mut timed_posted = 0u32;
    let mut posts_before_due = 0u32;
    let mut voids_on_due = 0u32;
    let mut batches = 0u32;
    let mut backlog_batches = 0u32;
    let mut expired_in: BTreeMap<PeriodState, u32> = BTreeMap::new();
    let mut due_seen = 0u32;
    let mut equal_deadline = 0u32;

    // Planted: a timed hold before any tick has nothing to anchor on.
    let first = plain(
        "Pending",
        vec![leg(dr, "6100", 10), leg(cr, "1000", 10)],
        b"timed-before-tick".to_vec(),
        dated[2],
    );
    let kernel = kernel_post_timed(&mut k, &first, usd, &refs, 5);
    assert_eq!(
        oracle.post_timed(&first, 5),
        Verdict::Refused { code: "FA-REF-095" }
    );
    let r = kernel.expect_err("no tick yet");
    assert_eq!((r.code, r.exit), ("FA-REF-095", exit::REFUSAL), "{r}");
    *refused.entry("FA-REF-095").or_insert(0) += 1;
    // Fund cash so outflow holds have room.
    let fund = plain(
        "Original",
        vec![leg(dr, "1000", 400_000), leg(cr, "3000", 400_000)],
        b"fund".to_vec(),
        dated[0],
    );
    let funded = kernel_post(&mut k, &fund, usd, &refs).expect("funds");
    assert!(matches!(funded, Posted::Committed { .. }));
    assert!(matches!(
        oracle.post(&fund),
        Verdict::Posted { index: 0, .. }
    ));
    refs.push(funded.entry_ref());

    for step in 0..600u64 {
        // Origin periods close and lock under live holds (plan §5.4: a hold
        // never becomes unreleasable because its period closed). Just before
        // each, timed holds dated in that period, due after it closes.
        if step == 199 || step == 379 {
            let date = if step == 199 { dated[0] } else { dated[1] };
            for n in 0..6 {
                let i = plain(
                    "Pending",
                    vec![leg(dr, "6100", 1), leg(cr, "1000", 1)],
                    format!("pre-close-{step}-{n}").into_bytes(),
                    date,
                );
                let posted = post_timed_both(
                    &mut k,
                    &mut oracle,
                    &mut refs,
                    &mut refused,
                    &i,
                    usd,
                    60,
                    step,
                );
                let h = posted.expect("a pre-close hold posts");
                holds.push(h);
                timed_posted += 1;
            }
        }
        if step == 200 {
            close_and_maybe_lock(&mut k, &mut oracle, &periods[0], true, step);
        }
        if step == 380 {
            close_and_maybe_lock(&mut k, &mut oracle, &periods[1], false, step);
        }
        let key = format!("x{step}").into_bytes();
        let date = dated[rng.below(4) as usize];
        let open: Vec<usize> = holds
            .iter()
            .copied()
            .filter(|h| !resolved.contains(h))
            .collect();
        match rng.below(20) {
            0..=2 => {
                // A tick: usually forward; sometimes planted at or behind the
                // latest (FA-REF-094).
                let planted = now > 0 && rng.chance(12);
                let ns = if planted {
                    now - rng.below(2)
                } else {
                    now + 1 + rng.below(25)
                };
                tick_seq += 1;
                let kernel = kernel_tick(&mut k, ns, &format!("tick-{tick_seq}"));
                let model = oracle.record_tick(ns);
                match (&kernel, &model) {
                    (Ok(t), Ok(_)) => {
                        assert!(!t.already_recorded);
                        assert_eq!(t.tick.observed_utc_ns, ns);
                        now = ns;
                    }
                    (Err(r), Err(code)) => {
                        assert_eq!(r.code, *code, "step {step}: {r}");
                        assert!(r.message.contains(&now.to_string()), "{r}");
                        *refused.entry(code).or_insert(0) += 1;
                    }
                    _ => assert_eq!(
                        format!("kernel {kernel:?}"),
                        format!("oracle {model:?}"),
                        "step {step}: tick disagreement"
                    ),
                }
            }
            3..=7 => {
                // A timed hold: an outflow from cash into a budget-capped
                // expense, in a random period, timing out soon. Rarely the
                // timeout overflows the deadline (FA-REF-096).
                let a = 1 + rng.below(9_000) as i128;
                let timeout = if now > 0 && rng.chance(5) {
                    u64::MAX - now + 1
                } else {
                    rng.below(40)
                };
                let i = plain(
                    "Pending",
                    vec![leg(dr, "6100", a), leg(cr, "1000", a)],
                    key,
                    date,
                );
                if let Some(h) = post_timed_both(
                    &mut k,
                    &mut oracle,
                    &mut refs,
                    &mut refused,
                    &i,
                    usd,
                    timeout,
                    step,
                ) {
                    holds.push(h);
                    timed_posted += 1;
                }
            }
            8 => {
                // An untimed hold: never due, never swept.
                let a = 1 + rng.below(9_000) as i128;
                let i = plain(
                    "Pending",
                    vec![leg(dr, "6100", a), leg(cr, "1000", a)],
                    key,
                    date,
                );
                let kernel = kernel_post(&mut k, &i, usd, &refs);
                let model = oracle.post(&i);
                if let (Ok(Posted::Committed { entry_ref, .. }), Verdict::Posted { index, .. }) =
                    (&kernel, &model)
                {
                    refs.push(*entry_ref);
                    holds.push(*index);
                } else {
                    assert_eq!(
                        kernel.as_ref().err().map(|r| r.code),
                        match model {
                            Verdict::Refused { code } => Some(code),
                            _ => None,
                        },
                        "step {step}: untimed hold"
                    );
                }
            }
            9..=11 if !open.is_empty() || !expired.is_empty() => {
                // A manual resolution: Posts part of an open hold, Voids it,
                // or (planted) void a hold the sweep already expired.
                let planted = !expired.is_empty() && (open.is_empty() || rng.chance(15));
                let target = if planted {
                    let e: Vec<usize> = expired.iter().copied().collect();
                    e[rng.below(e.len() as u64) as usize]
                } else {
                    open[rng.below(open.len() as u64) as usize]
                };
                let hold = oracle.entry(target).expect("hold").clone();
                let was_due = oracle.due().contains(&target);
                let posts = !planted && rng.chance(55);
                let (legs, ordinals) = if posts {
                    let t = 1 + rng.below(hold.legs[0].mantissa as u64) as i128;
                    (
                        hold.legs
                            .iter()
                            .map(|l| leg(l.side, &l.account, t))
                            .collect(),
                        Some(vec![0u16, 1]),
                    )
                } else {
                    (Vec::new(), None)
                };
                let mut i = plain("Resolution", legs, key, dated[2 + rng.below(2) as usize]);
                i.resolves = Some(Resolve {
                    target,
                    posts: ordinals,
                });
                let kernel = kernel_post(&mut k, &i, usd, &refs);
                let model = oracle.post(&i);
                match (&kernel, &model) {
                    (Ok(Posted::Committed { entry_ref, .. }), Verdict::Posted { index, .. }) => {
                        assert_eq!(*index, refs.len(), "step {step}");
                        refs.push(*entry_ref);
                        resolved.insert(target);
                        if posts && oracle.deadline(target).is_some() {
                            posts_before_due += 1;
                        }
                        if !posts && was_due {
                            voids_on_due += 1;
                        }
                    }
                    (Err(r), Verdict::Refused { code }) => {
                        assert_eq!(r.code, *code, "step {step}: {r}");
                        *refused.entry(code).or_insert(0) += 1;
                        if *code == "FA-REF-097" {
                            assert!(was_due, "step {step}: 097 on a hold not due");
                            assert!(r.fix.contains("Resolution(Voids)"), "{r}");
                        }
                        if planted {
                            assert_eq!(*code, "FA-REF-062", "step {step}: void after expiry");
                        }
                    }
                    _ => assert_eq!(
                        format!("kernel {kernel:?}"),
                        format!("oracle {model:?}"),
                        "step {step}: resolution disagreement on {i:?}"
                    ),
                }
            }
            12..=15 => {
                // The sweep, under the latest tick, with a small batch bound
                // so a backlog takes several batches.
                let max = 1 + rng.below(3) as usize;
                let states: BTreeMap<usize, PeriodState> = oracle
                    .due()
                    .iter()
                    .map(|h| {
                        let p = oracle.entry(*h).expect("hold").period.clone();
                        (*h, oracle.period_state(&p).expect("created"))
                    })
                    .collect();
                if let Some(m) = sweep_both(&mut k, &mut oracle, &mut refs, max, step) {
                    batches += 1;
                    if m.remaining_due > 0 {
                        backlog_batches += 1;
                    }
                    for (h, _) in &m.expired {
                        expired.insert(*h);
                        resolved.insert(*h);
                        *expired_in.entry(states[h]).or_insert(0) += 1;
                        if oracle.deadline(*h) == Some(m.tick) {
                            equal_deadline += 1;
                        }
                    }
                }
            }
            16 => {
                // More cash, so holds keep finding room.
                let a = 1 + rng.below(50_000) as i128;
                let i = plain(
                    "Original",
                    vec![leg(dr, "1000", a), leg(cr, "3000", a)],
                    key,
                    dated[2 + rng.below(2) as usize],
                );
                let kernel = kernel_post(&mut k, &i, usd, &refs);
                let model = oracle.post(&i);
                match (&kernel, &model) {
                    (Ok(Posted::Committed { entry_ref, .. }), Verdict::Posted { .. }) => {
                        refs.push(*entry_ref);
                    }
                    (Err(r), Verdict::Refused { code }) => assert_eq!(r.code, *code),
                    _ => assert_eq!(format!("{kernel:?}"), format!("{model:?}")),
                }
            }
            _ => {
                // Spend: an unlimited move that never touches a cell.
                let a = 1 + rng.below(900) as i128;
                let i = plain(
                    "Original",
                    vec![leg(dr, "6000", a), leg(cr, "4000", a)],
                    key,
                    dated[2 + rng.below(2) as usize],
                );
                let kernel = kernel_post(&mut k, &i, usd, &refs);
                let model = oracle.post(&i);
                if let (Ok(Posted::Committed { entry_ref, .. }), Verdict::Posted { .. }) =
                    (&kernel, &model)
                {
                    refs.push(*entry_ref);
                } else {
                    assert_eq!(format!("{kernel:?}"), format!("{model:?}"));
                }
            }
        }
        // After every step: the due backlog and every reservation cell agree.
        let due = oracle.due();
        assert_eq!(kernel_due(&k, &refs), due, "step {step}: due backlog");
        if !due.is_empty() {
            due_seen += 1;
        }
        assert_cell_in(&k, &oracle, "1000", None, step);
        for p in &watched {
            assert_cell_in(&k, &oracle, "6100", Some(p.as_str()), step);
        }
        if step % 50 == 0 {
            assert_pending_registers(&k, &oracle, &watched, step);
        }
    }
    // Drain: one more tick past every deadline, then sweep to the end.
    now += 1_000;
    assert!(kernel_tick(&mut k, now, "tick-final").is_ok());
    assert!(oracle.record_tick(now).is_ok());
    while let Some(m) = sweep_both(&mut k, &mut oracle, &mut refs, 2, 10_000) {
        for (h, _) in &m.expired {
            expired.insert(*h);
        }
    }
    assert!(oracle.due().is_empty() && kernel_due(&k, &refs).is_empty());
    assert_pending_registers(&k, &oracle, &watched, 10_001);
    assert_cell_in(&k, &oracle, "1000", None, 10_001);
    for p in &watched {
        assert_cell_in(&k, &oracle, "6100", Some(p.as_str()), 10_001);
    }
    let verified = verify_availability(&k.db, &k.book, None).unwrap();
    assert!(verified.is_green(), "{verified:?}");

    // Agreement is not vacuous: every law fired, a backlog took several
    // batches, and holds expired out of Closed and Locked origin periods.
    assert!(timed_posted >= 60, "timed holds {timed_posted}");
    assert!(expired.len() >= 30, "expired {}", expired.len());
    assert!(
        batches >= 15 && backlog_batches >= 5,
        "batches {batches}/{backlog_batches}"
    );
    assert!(due_seen >= 20, "due-but-unswept observed {due_seen}");
    assert!(posts_before_due >= 3, "posts before due {posts_before_due}");
    assert!(voids_on_due >= 1, "voids of due holds {voids_on_due}");
    assert!(
        equal_deadline >= 1,
        "expiry at deadline equality {equal_deadline}"
    );
    for state in [PeriodState::Closed, PeriodState::Locked] {
        assert!(
            expired_in.get(&state).is_some_and(|n| *n >= 2),
            "expired out of {state:?}: {expired_in:?}"
        );
    }
    for (must, floor) in [
        ("FA-REF-094", 3),
        ("FA-REF-095", 1),
        ("FA-REF-096", 1),
        ("FA-REF-097", 3),
        ("FA-REF-062", 2),
    ] {
        assert!(
            refused.get(must).is_some_and(|n| *n >= floor),
            "refusal {must} under-exercised: {refused:?}"
        );
    }
}

/// Plan §5.4 timing on the real substrate: the anchor is a point witness (a
/// tick committed between plan and publication is a first-committer-wins
/// loss), equality at the deadline is due, Posts stops at the deadline while
/// Voids does not, and `Expires` is never posted.
#[test]
fn timed_holds_anchor_on_a_witnessed_tick_and_posts_stop_at_the_deadline() {
    let (mut k, mut oracle, periods) = setup_with(BUDGETED);
    let usd = k.book.units.lookup("USD").unwrap();
    open_period(&mut k, &mut oracle, &periods[2], 1);
    let march = DateDay::from_ymd(2026, 3, 15).unwrap();
    let leg = |side: fa_reference::Side, account: &str, mantissa: i128| Leg {
        side,
        account: account.into(),
        unit: usd.0,
        entity: None,
        mantissa,
    };
    let dr = fa_reference::Side::Debit;
    let cr = fa_reference::Side::Credit;
    let intent = |class: &str, legs: Vec<Leg>, key: &str, resolves: Option<Resolve>| Intent {
        class: class.into(),
        date: march,
        discriminator: None,
        legs,
        key: key.as_bytes().to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves,
        settles: Vec::new(),
    };
    let mut refs: Vec<EntryRef> = Vec::new();
    let fund = intent(
        "Original",
        vec![leg(dr, "1000", 1_000), leg(cr, "3000", 1_000)],
        "fund",
        None,
    );
    refs.push(
        kernel_post(&mut k, &fund, usd, &refs)
            .expect("funds")
            .entry_ref(),
    );
    assert!(matches!(oracle.post(&fund), Verdict::Posted { .. }));
    let hold_legs = vec![leg(dr, "6100", 100), leg(cr, "1000", 100)];

    // Ticks are journaled controls: book-scoped, strictly increasing,
    // idempotent per key, `witness`-authorized, daemon-clock only.
    let t0 = kernel_tick(&mut k, 1_000, "t0").expect("first tick");
    assert_eq!(oracle.record_tick(1_000), Ok(0));
    let (entry, _) = fa_journal::post::read_entry(&k.db, t0.entry_ref.vid)
        .unwrap()
        .expect("tick entry");
    assert_eq!(entry.proposal.class, EntryClass::TIME_CONTROL);
    assert!(entry.proposal.legs.is_empty() && entry.proposal.effective_period.is_none());
    assert_eq!(latest_tick(&k.db).unwrap(), Some(t0.tick));
    let again = kernel_tick(&mut k, 1_000, "t0").expect("same request");
    assert!(again.already_recorded && again.entry_ref == t0.entry_ref);
    let r = kernel_tick(&mut k, 1_000, "t0-dup").expect_err("not increasing");
    assert_eq!((r.code, r.exit), ("FA-REF-094", exit::REFUSAL), "{r}");
    let mut foreign = tick_request(&k, 2_000, "t-source");
    foreign.source = 2;
    let r = kernel_tick_raw(&mut k, foreign).expect_err("SubstrateMarker is not live");
    assert_eq!(r.code, "FA-REF-102", "{r}");
    let mut unwitnessed = tick_request(&k, 2_000, "t-op");
    unwitnessed.capability = Capability::embedded(PRINCIPAL, &["post"]).expect("ops");
    let r = kernel_tick_raw(&mut k, unwitnessed).expect_err("needs witness");
    assert_eq!(r.exit, exit::SAFETY, "{r}");
    assert_eq!(latest_tick(&k.db).unwrap(), Some(t0.tick));

    // Holds anchored at 1_000: A (timeout 10), B (timeout 10), C (timeout 30).
    let post_hold =
        |k: &mut Kernel, oracle: &mut Oracle, refs: &mut Vec<EntryRef>, key: &str, t: u64| {
            let i = intent("Pending", hold_legs.clone(), key, None);
            let posted = kernel_post_timed(k, &i, usd, refs, t).expect("timed hold");
            assert!(matches!(oracle.post_timed(&i, t), Verdict::Posted { .. }));
            refs.push(posted.entry_ref());
            refs.len() - 1
        };
    let a = post_hold(&mut k, &mut oracle, &mut refs, "A", 10);
    let b = post_hold(&mut k, &mut oracle, &mut refs, "B", 10);
    let c = post_hold(&mut k, &mut oracle, &mut refs, "C", 30);
    // The anchor is derived from journal position: the tick strictly before
    // the hold's commit.
    let a_row = k.db.vertex(refs[a].vid).unwrap().unwrap();
    assert_eq!(
        fa_journal::sweep::tick_before(&k.db, a_row.created_at).unwrap(),
        Some(t0.tick)
    );
    assert_eq!(
        fa_journal::sweep::deadline(&k.db, a_row.created_at, 10).unwrap(),
        1_010
    );
    let posts = |target: usize, key: &str, t: i128| {
        intent(
            "Resolution",
            vec![leg(dr, "6100", t), leg(cr, "1000", t)],
            key,
            Some(Resolve {
                target,
                posts: Some(vec![0, 1]),
            }),
        )
    };

    // Before the deadline a Posts is admissible (A posts 40 of 100).
    kernel_tick(&mut k, 1_009, "t1").expect("tick");
    oracle.record_tick(1_009).unwrap();
    let pa = posts(a, "posts-A", 40);
    refs.push(
        kernel_post(&mut k, &pa, usd, &refs)
            .expect("posts before due")
            .entry_ref(),
    );
    assert!(matches!(oracle.post(&pa), Verdict::Posted { .. }));

    // A tick committed between plan and publication: a transaction that
    // witnessed the latest tick (as the kernel's 7e does) loses to it.
    let ctx = k.ctx();
    let txn_cx = ctx.txn();
    let mut slow = k.db.begin(&txn_cx).expect("begin");
    let witnessed = slow
        .vertex_property(
            &k.db,
            rows::book_root(),
            fa_model::symbols::property::LATEST_TICK,
        )
        .expect("read");
    assert!(witnessed.is_some());
    let mut control = k.db.begin(&txn_cx).expect("begin");
    assert!(control.vertex(&k.db, refs[c].vid).expect("read").is_some());
    let t_due = kernel_tick(&mut k, 1_010, "t2").expect("the due tick");
    oracle.record_tick(1_010).unwrap();
    let mut batch = WriteBatch::new(fa_model::symbols::relation::IN_PERIOD);
    batch.set_vertex_property(
        refs[b].vid,
        fa_model::symbols::property::DISPOSITION,
        Some(fgdb_types::CanonicalScalar::Int(0)),
    );
    let staged = slow.write_ordered(&mut k.db, vec![batch]);
    assert!(
        matches!(staged, Err(fgdb::WriteTxnError::SnapshotAdvanced { .. })),
        "{staged:?}"
    );
    let refreshed = slow.refresh_snapshot(&k.db, &txn_cx);
    assert!(
        matches!(
            refreshed,
            Err(fgdb::WriteTxnError::Write(
                fgdb::WriteError::FirstCommitterWins { .. }
            ))
        ),
        "a stale tick witness must lose: {refreshed:?}"
    );
    slow.abort();
    assert!(control.refresh_snapshot(&k.db, &txn_cx).is_ok());
    control.abort();

    // Re-planned after the due tick, at equality with the deadline: refused.
    let pb = posts(b, "posts-B", 40);
    let r = kernel_post(&mut k, &pb, usd, &refs).expect_err("due at equality");
    assert_eq!(oracle.post(&pb), Verdict::Refused { code: "FA-REF-097" });
    assert_eq!((r.code, r.exit), ("FA-REF-097", exit::REFUSAL), "{r}");
    assert!(
        r.message.contains("1010") && r.message.contains(&t_due.tick.observed_utc_ns.to_string())
    );
    // C is not due yet (deadline 1_030): its Posts is admissible.
    let pc = posts(c, "posts-C", 1);
    refs.push(
        kernel_post(&mut k, &pc, usd, &refs)
            .expect("C not due")
            .entry_ref(),
    );
    assert!(matches!(oracle.post(&pc), Verdict::Posted { .. }));
    // B is due but a Voids still releases it (the identity race with the
    // sweep, not the deadline, decides).
    let vb = intent(
        "Resolution",
        Vec::new(),
        "void-B",
        Some(Resolve {
            target: b,
            posts: None,
        }),
    );
    refs.push(
        kernel_post(&mut k, &vb, usd, &refs)
            .expect("voids a due hold")
            .entry_ref(),
    );
    assert!(matches!(oracle.post(&vb), Verdict::Posted { .. }));
    assert_cell_in(&k, &oracle, "1000", None, 1);
    assert_cell_in(&k, &oracle, "6100", Some(periods[2].as_str()), 1);

    // Expires is the sweep's: through `post` it is refused, nothing written.
    let d = intent("Pending", hold_legs.clone(), "D", None);
    let d_ref = kernel_post_timed(&mut k, &d, usd, &refs, 1)
        .expect("D")
        .entry_ref();
    let mut req = kernel_request(&k, &vb, usd, &refs);
    req.proposal.idempotency_key = b"expires-by-hand".to_vec();
    req.proposal.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: Some(d_ref),
        disposition: Some(Disposition::Expires { at_tick: 2_000 }),
    });
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    let r = k
        .runtime
        .block_on(async move { post(db, &ctx, book, req).await })
        .expect("kernel")
        .expect_err("Expires is never posted");
    assert_eq!((r.code, r.exit), ("FA-REF-098", exit::USAGE), "{r}");
    assert!(
        k.db.vertex(rows::resolution_vid(d_ref.vid))
            .unwrap()
            .is_none()
    );
}

/// Plan §5.4 on the real substrate: one resolution per hold, by identity.
/// A manual void before the sweep leaves the sweep nothing to do for that
/// hold; a manual void after it is the one-resolution conflict; a void and a
/// sweep in flight together race on the resolution identity and the second
/// loses first-committer-wins, never a double release. The sweep refuses a
/// non-System capability and a batch bound outside `1..=max_batch_entries`.
#[test]
fn the_sweep_and_manual_resolution_race_by_identity_never_double_release() {
    let (mut k, mut oracle, periods) = setup_with(BUDGETED);
    let usd = k.book.units.lookup("USD").unwrap();
    open_period(&mut k, &mut oracle, &periods[2], 1);
    let march = DateDay::from_ymd(2026, 3, 15).unwrap();
    let leg = |side: fa_reference::Side, account: &str, mantissa: i128| Leg {
        side,
        account: account.into(),
        unit: usd.0,
        entity: None,
        mantissa,
    };
    let dr = fa_reference::Side::Debit;
    let cr = fa_reference::Side::Credit;
    let intent = |class: &str, legs: Vec<Leg>, key: &str, resolves: Option<Resolve>| Intent {
        class: class.into(),
        date: march,
        discriminator: None,
        legs,
        key: key.as_bytes().to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves,
        settles: Vec::new(),
    };
    let void = |target: usize, key: &str| {
        intent(
            "Resolution",
            Vec::new(),
            key,
            Some(Resolve {
                target,
                posts: None,
            }),
        )
    };
    let mut refs: Vec<EntryRef> = Vec::new();
    let fund = intent(
        "Original",
        vec![leg(dr, "1000", 5_000), leg(cr, "3000", 5_000)],
        "fund",
        None,
    );
    refs.push(
        kernel_post(&mut k, &fund, usd, &refs)
            .expect("funds")
            .entry_ref(),
    );
    assert!(matches!(oracle.post(&fund), Verdict::Posted { .. }));
    kernel_tick(&mut k, 100, "t0").expect("tick");
    oracle.record_tick(100).unwrap();
    let mut holds = Vec::new();
    for key in ["H0", "H1", "H2", "H3", "H4"] {
        let i = intent(
            "Pending",
            vec![leg(dr, "6100", 100), leg(cr, "1000", 100)],
            key,
            None,
        );
        refs.push(
            kernel_post_timed(&mut k, &i, usd, &refs, 10)
                .expect("hold")
                .entry_ref(),
        );
        assert!(matches!(oracle.post_timed(&i, 10), Verdict::Posted { .. }));
        holds.push(refs.len() - 1);
    }
    // Before any due tick the sweep has nothing to do and writes nothing.
    let frontier = k.db.frontier().unwrap();
    assert_eq!(kernel_sweep(&mut k, 5), Ok(None));
    assert_eq!(k.db.frontier().unwrap(), frontier);

    // The sweep's authority: System only, `post`, a batch bound in range.
    let mut human = sweeper(&k, 2);
    human.capability = Capability::embedded(system(&k), &["post"]).expect("ops");
    let r = kernel_sweep_raw(&mut k, &human).expect_err("not System");
    assert_eq!((r.code, r.exit), ("FA-REF-011", exit::SAFETY), "{r}");
    // A System capability held by any other principal is not the book's
    // System principal.
    let mut stranger = sweeper(&k, 2);
    stranger.principal_ref = VId(99);
    stranger.capability =
        Capability::new(VId(99), Profile::System, &[Op::Post], VId(99)).expect("cap");
    let r = kernel_sweep_raw(&mut k, &stranger).expect_err("not the book's System");
    assert_eq!((r.code, r.exit), ("FA-REF-011", exit::SAFETY), "{r}");
    for bad in [0, fa_model::limits::MAX_BATCH_ENTRIES + 1] {
        let r = kernel_sweep(&mut k, bad).expect_err("batch bound");
        assert_eq!((r.code, r.exit), ("FA-REF-100", exit::USAGE), "{r}");
    }

    kernel_tick(&mut k, 110, "t1").expect("the due tick");
    oracle.record_tick(110).unwrap();
    assert_eq!(kernel_due(&k, &refs), holds);

    // Manual void, then the sweep: H0 is resolved and no longer due.
    refs.push(
        kernel_post(&mut k, &void(holds[0], "void-H0"), usd, &refs)
            .expect("void")
            .entry_ref(),
    );
    assert!(matches!(
        oracle.post(&void(holds[0], "void-H0")),
        Verdict::Posted { .. }
    ));
    assert_eq!(kernel_due(&k, &refs), holds[1..].to_vec());

    // In flight together: a manual void of H1 that witnessed H1's
    // resolution identity as absent (its step 4) loses to the sweep that
    // expires H1 first.
    let ctx = k.ctx();
    let txn_cx = ctx.txn();
    let mut manual = k.db.begin(&txn_cx).expect("begin");
    let h1 = refs[holds[1]].vid;
    assert!(
        manual
            .vertex(&k.db, rows::resolution_vid(h1))
            .expect("read")
            .is_none()
    );
    let batch = sweep_both(&mut k, &mut oracle, &mut refs, 2, 1).expect("expires H1, H2");
    assert_eq!(
        batch.expired.iter().map(|(h, _)| *h).collect::<Vec<_>>(),
        holds[1..3].to_vec()
    );
    assert_eq!(batch.remaining_due, 2);
    let mut write = WriteBatch::new(fa_model::symbols::relation::IN_PERIOD);
    write.create_vertex(
        rows::resolution_vid(h1),
        vec![fa_model::symbols::label::ENTRY],
        Vec::new(),
    );
    let staged = manual.write_ordered(&mut k.db, vec![write]);
    assert!(
        matches!(staged, Err(fgdb::WriteTxnError::SnapshotAdvanced { .. })),
        "{staged:?}"
    );
    let refreshed = manual.refresh_snapshot(&k.db, &txn_cx);
    assert!(
        matches!(
            refreshed,
            Err(fgdb::WriteTxnError::Write(
                fgdb::WriteError::FirstCommitterWins { .. }
            ))
        ),
        "the manual void must lose the identity race: {refreshed:?}"
    );
    manual.abort();

    // The converse: a sweep transaction that witnessed H3's identity as
    // absent loses to a manual void that commits first.
    let mut swept = k.db.begin(&txn_cx).expect("begin");
    let h3 = refs[holds[3]].vid;
    assert!(
        swept
            .vertex(&k.db, rows::resolution_vid(h3))
            .expect("read")
            .is_none()
    );
    refs.push(
        kernel_post(&mut k, &void(holds[3], "void-H3"), usd, &refs)
            .expect("void")
            .entry_ref(),
    );
    assert!(matches!(
        oracle.post(&void(holds[3], "void-H3")),
        Verdict::Posted { .. }
    ));
    let refreshed = swept.refresh_snapshot(&k.db, &txn_cx);
    assert!(
        matches!(
            refreshed,
            Err(fgdb::WriteTxnError::Write(
                fgdb::WriteError::FirstCommitterWins { .. }
            ))
        ),
        "the stale sweep must lose the identity race: {refreshed:?}"
    );
    swept.abort();

    // The next batch continues after the cursor: only H4 is left (H3 was
    // voided by hand); then nothing.
    let rest = sweep_both(&mut k, &mut oracle, &mut refs, 2, 2).expect("expires H4");
    assert_eq!(
        rest.expired.iter().map(|(h, _)| *h).collect::<Vec<_>>(),
        vec![holds[4]]
    );
    assert_eq!(rest.remaining_due, 0);
    assert!(sweep_both(&mut k, &mut oracle, &mut refs, 2, 3).is_none());

    // After the sweep, a manual void of an expired hold is the
    // one-resolution conflict, citing the sweep's resolution.
    let late = void(holds[2], "void-H2-late");
    let r = kernel_post(&mut k, &late, usd, &refs).expect_err("already expired");
    assert_eq!(oracle.post(&late), Verdict::Refused { code: "FA-REF-062" });
    assert_eq!((r.code, r.exit), ("FA-REF-062", exit::CONFLICT), "{r}");
    assert!(
        r.message.contains(&format!(
            "{:032x}",
            rows::resolution_vid(refs[holds[2]].vid).0
        )),
        "{r}"
    );
    // Every hold released exactly once: the cells and registers agree.
    assert_cell_in(&k, &oracle, "1000", None, 4);
    assert_cell_in(&k, &oracle, "6100", Some(periods[2].as_str()), 4);
    assert_pending_registers(&k, &oracle, &periods[2..3], 4);
    assert!(
        verify_availability(&k.db, &k.book, None)
            .unwrap()
            .is_green()
    );
}

/// A crash between batches: the committed batch and its cursor survive a
/// restart, an uncommitted batch leaves nothing, and the rerun continues
/// after the cursor with the same derived identities.
#[test]
fn a_crashed_sweep_leaves_nothing_partial_and_the_cursor_survives_restart() {
    let (mut k, mut oracle, periods, vfs) = setup_store(BUDGETED);
    let usd = k.book.units.lookup("USD").unwrap();
    open_period(&mut k, &mut oracle, &periods[2], 1);
    let march = DateDay::from_ymd(2026, 3, 15).unwrap();
    let leg = |side: fa_reference::Side, account: &str, mantissa: i128| Leg {
        side,
        account: account.into(),
        unit: usd.0,
        entity: None,
        mantissa,
    };
    let dr = fa_reference::Side::Debit;
    let cr = fa_reference::Side::Credit;
    let intent = |class: &str, legs: Vec<Leg>, key: &str| Intent {
        class: class.into(),
        date: march,
        discriminator: None,
        legs,
        key: key.as_bytes().to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    };
    let mut refs: Vec<EntryRef> = Vec::new();
    let fund = intent(
        "Original",
        vec![leg(dr, "1000", 5_000), leg(cr, "3000", 5_000)],
        "fund",
    );
    refs.push(
        kernel_post(&mut k, &fund, usd, &refs)
            .expect("funds")
            .entry_ref(),
    );
    assert!(matches!(oracle.post(&fund), Verdict::Posted { .. }));
    kernel_tick(&mut k, 50, "t0").expect("tick");
    oracle.record_tick(50).unwrap();
    for n in 0..5 {
        let i = intent(
            "Pending",
            vec![leg(dr, "6100", 10 + n), leg(cr, "1000", 10 + n)],
            &format!("H{n}"),
        );
        refs.push(
            kernel_post_timed(&mut k, &i, usd, &refs, 5)
                .expect("hold")
                .entry_ref(),
        );
        assert!(matches!(oracle.post_timed(&i, 5), Verdict::Posted { .. }));
    }
    let tick = kernel_tick(&mut k, 60, "t1").expect("due tick").tick;
    oracle.record_tick(60).unwrap();
    let first = sweep_both(&mut k, &mut oracle, &mut refs, 2, 1).expect("first batch");
    assert_eq!(first.remaining_due, 3);

    // A crash mid-batch: a transaction stages the next batch's resolutions
    // and the process dies before commit.
    let ctx = k.ctx();
    let txn_cx = ctx.txn();
    let mut doomed = k.db.begin(&txn_cx).expect("begin");
    let mut write = WriteBatch::new(fa_model::symbols::relation::IN_PERIOD);
    for h in [3usize, 4] {
        write.create_vertex(
            rows::resolution_vid(refs[h].vid),
            vec![fa_model::symbols::label::ENTRY],
            Vec::new(),
        );
    }
    doomed
        .write_ordered(&mut k.db, vec![write])
        .expect("staged, never committed");
    let committed = k.db.frontier().unwrap();
    drop(doomed);
    let Kernel {
        runtime,
        root,
        db,
        book,
        evidence,
        agent_evidence,
    } = k;
    drop(db);
    let ctx = PurposeContexts::narrow_runtime_root(&root);
    let dir = vfs.database_dir();
    let db = runtime
        .block_on(async {
            Database::open_with_vfs(&ctx.commit(), vfs.clone(), dir, db_keys()).await
        })
        .expect("reopen after the crash");
    let mut k = Kernel {
        runtime,
        root,
        db,
        book,
        evidence,
        agent_evidence,
    };
    // Exactly what committed survived: the first batch and its cursor; the
    // staged resolutions did not.
    assert_eq!(k.db.frontier().unwrap(), committed);
    assert_eq!(latest_tick(&k.db).unwrap(), Some(tick));
    for h in [3usize, 4] {
        assert!(
            k.db.vertex(rows::resolution_vid(refs[h].vid))
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(kernel_due(&k, &refs), oracle.due());
    assert_cell_in(&k, &oracle, "1000", None, 2);
    assert_cell_in(&k, &oracle, "6100", Some(periods[2].as_str()), 2);
    // The rerun continues after the persisted cursor, batch by batch, with
    // the same derived identities, and stops when nothing is due.
    let second = sweep_both(&mut k, &mut oracle, &mut refs, 2, 3).expect("second batch");
    assert_eq!(
        second.expired.iter().map(|(h, _)| *h).collect::<Vec<_>>(),
        vec![3, 4]
    );
    let third = sweep_both(&mut k, &mut oracle, &mut refs, 2, 4).expect("third batch");
    assert_eq!(
        third.expired.iter().map(|(h, _)| *h).collect::<Vec<_>>(),
        vec![5]
    );
    assert_eq!(third.remaining_due, 0);
    assert!(sweep_both(&mut k, &mut oracle, &mut refs, 2, 5).is_none());
    assert_cell_in(&k, &oracle, "1000", None, 6);
    assert_cell_in(&k, &oracle, "6100", Some(periods[2].as_str()), 6);
    assert_pending_registers(&k, &oracle, &periods[2..3], 6);
    assert!(
        verify_availability(&k.db, &k.book, None)
            .unwrap()
            .is_green()
    );
}

/// A sweep `describe` whose `fail_at`-th call (0-based) reports the
/// caller's entropy source unavailable; every other call seals as usual.
fn failing_describe(
    seal_key: &SealKey,
    fail_at: usize,
) -> impl FnMut(&str) -> Result<Erasable<String>, KernelError> + '_ {
    let mut calls = 0usize;
    move |text: &str| {
        let n = calls;
        calls += 1;
        if n == fail_at {
            Err(KernelError::Entropy(
                fgdb_crypto::EntropyError::Unavailable {
                    source_id: "differential",
                    detail: "the entropy device failed".into(),
                },
            ))
        } else {
            Ok(fresh_seal(seal_key, text))
        }
    }
}

fn kernel_sweep_failing(
    k: &mut Kernel,
    max_batch: usize,
    fail_at: usize,
) -> Result<Result<Option<SweepBatch>, Refusal>, KernelError> {
    let req = sweeper(k, max_batch);
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    k.runtime.block_on(async move {
        let mut describe = failing_describe(&book.seal_key, fail_at);
        sweep_batch(db, &ctx, book, &req, &mut describe).await
    })
}

fn kernel_sweep_reversals_failing(
    k: &mut Kernel,
    max_batch: usize,
    fail_at: usize,
) -> Result<Result<Option<ReversalBatch>, Refusal>, KernelError> {
    let req = sweeper(k, max_batch);
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    k.runtime.block_on(async move {
        let mut describe = failing_describe(&book.seal_key, fail_at);
        sweep_reversals_batch(db, &ctx, book, &req, &mut describe).await
    })
}

/// The sweep's seals come from the caller's entropy, which can fail
/// (WhiteCreek 3300, GrayPike 3303/3304). A failure sealing the first
/// expiry, and one sealing the cursor after the batch's expiries were
/// prepared, both abort the open transaction: nothing commits, the cursor
/// does not move, the backlog is unchanged, and the retry sweeps exactly
/// the batch the oracle sweeps — also from a persisted cursor.
#[test]
fn an_entropy_failure_in_the_sweep_commits_nothing_and_the_retry_sweeps_the_same_holds() {
    let (mut k, mut oracle, periods) = setup_with(BUDGETED);
    let usd = k.book.units.lookup("USD").unwrap();
    open_period(&mut k, &mut oracle, &periods[2], 1);
    let march = DateDay::from_ymd(2026, 3, 15).unwrap();
    let leg = |side: fa_reference::Side, account: &str, mantissa: i128| Leg {
        side,
        account: account.into(),
        unit: usd.0,
        entity: None,
        mantissa,
    };
    let dr = fa_reference::Side::Debit;
    let cr = fa_reference::Side::Credit;
    let intent = |class: &str, legs: Vec<Leg>, key: &str| Intent {
        class: class.into(),
        date: march,
        discriminator: None,
        legs,
        key: key.as_bytes().to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    };
    let mut refs: Vec<EntryRef> = Vec::new();
    let fund = intent(
        "Original",
        vec![leg(dr, "1000", 5_000), leg(cr, "3000", 5_000)],
        "fund",
    );
    refs.push(
        kernel_post(&mut k, &fund, usd, &refs)
            .expect("funds")
            .entry_ref(),
    );
    assert!(matches!(oracle.post(&fund), Verdict::Posted { .. }));
    kernel_tick(&mut k, 50, "t0").expect("tick");
    oracle.record_tick(50).unwrap();
    for n in 0..5 {
        let i = intent(
            "Pending",
            vec![leg(dr, "6100", 10 + n), leg(cr, "1000", 10 + n)],
            &format!("H{n}"),
        );
        refs.push(
            kernel_post_timed(&mut k, &i, usd, &refs, 5)
                .expect("hold")
                .entry_ref(),
        );
        assert!(matches!(oracle.post_timed(&i, 5), Verdict::Posted { .. }));
    }
    kernel_tick(&mut k, 60, "t1").expect("due tick");
    oracle.record_tick(60).unwrap();
    let due = kernel_due(&k, &refs);
    assert_eq!(due, oracle.due());
    let frontier = k.db.frontier().unwrap();
    // Call 0 seals the first expiry's description; call 2 the cursor's,
    // after both of the batch's expiries were prepared.
    for fail_at in [0, 2] {
        let r = kernel_sweep_failing(&mut k, 2, fail_at);
        assert!(
            matches!(r, Err(KernelError::Entropy(_))),
            "fail_at {fail_at}: {r:?}"
        );
        assert_eq!(k.db.frontier().unwrap(), frontier, "fail_at {fail_at}");
        assert_eq!(kernel_due(&k, &refs), due, "fail_at {fail_at}");
        for hold in &refs[1..] {
            assert!(
                k.db.vertex(rows::resolution_vid(hold.vid))
                    .unwrap()
                    .is_none()
            );
        }
    }
    let first = sweep_both(&mut k, &mut oracle, &mut refs, 2, 1).expect("the retried batch");
    assert_eq!(
        first.expired.iter().map(|(h, _)| *h).collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(first.remaining_due, 3);
    // From the persisted cursor: a failure at the next cursor's seal.
    let frontier = k.db.frontier().unwrap();
    let due = kernel_due(&k, &refs);
    let r = kernel_sweep_failing(&mut k, 2, 2);
    assert!(matches!(r, Err(KernelError::Entropy(_))), "{r:?}");
    assert_eq!(k.db.frontier().unwrap(), frontier);
    assert_eq!(kernel_due(&k, &refs), due);
    let second = sweep_both(&mut k, &mut oracle, &mut refs, 2, 2).expect("second batch");
    assert_eq!(
        second.expired.iter().map(|(h, _)| *h).collect::<Vec<_>>(),
        vec![3, 4]
    );
    assert_cell_in(&k, &oracle, "1000", None, 3);
    assert_cell_in(&k, &oracle, "6100", Some(periods[2].as_str()), 3);
}

/// The reversal sweep seals one description, its cursor's, after the
/// batch's reversals were minted into the open transaction: a failure
/// there commits nothing, and the retry mints what the oracle mints.
#[test]
fn an_entropy_failure_in_the_reversal_sweep_commits_nothing_and_the_retry_mints_the_same() {
    let (mut k, mut oracle, periods) = setup_with(BUDGETED);
    oracle.declare_time_zone();
    let usd = k.book.units.lookup("USD").unwrap();
    open_period(&mut k, &mut oracle, &periods[2], 1);
    let leg = |side: fa_reference::Side, account: &str, mantissa: i128| Leg {
        side,
        account: account.into(),
        unit: usd.0,
        entity: None,
        mantissa,
    };
    let march = |d: u8| DateDay::from_ymd(2026, 3, d).unwrap();
    let accrual = |key: &str| Intent {
        class: "Adjusting".into(),
        date: march(2),
        discriminator: None,
        legs: vec![
            leg(fa_reference::Side::Debit, "6000", 50),
            leg(fa_reference::Side::Credit, "3000", 50),
        ],
        key: key.as_bytes().to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    };
    let mut refs: Vec<EntryRef> = Vec::new();
    kernel_tick(&mut k, noon(march(1)), "t0").expect("tick");
    oracle.record_tick(noon(march(1))).unwrap();
    for key in ["A", "B"] {
        let i = accrual(key);
        refs.push(
            kernel_post_scheduled(&mut k, &i, usd, &refs, march(10))
                .expect("scheduled")
                .entry_ref(),
        );
        assert!(matches!(
            oracle.post_scheduled(&i, march(10)),
            Verdict::Posted { .. }
        ));
    }
    kernel_tick(&mut k, noon(march(10)), "t1").expect("the date's tick");
    oracle.record_tick(noon(march(10))).unwrap();
    let reached = kernel_reached(&k, &refs);
    let frontier = k.db.frontier().unwrap();
    let r = kernel_sweep_reversals_failing(&mut k, 5, 0);
    assert!(matches!(r, Err(KernelError::Entropy(_))), "{r:?}");
    assert_eq!(k.db.frontier().unwrap(), frontier);
    assert_eq!(kernel_reached(&k, &refs), reached);
    for target in &refs {
        assert!(
            k.db.vertex(rows::reversal_vid(target.vid))
                .unwrap()
                .is_none()
        );
    }
    let batch =
        reversal_sweep_both(&mut k, &mut oracle, &mut refs, 5, 1).expect("the retried batch");
    assert_eq!(batch.minted.len(), 2);
    assert_eq!(batch.remaining, 0);
}

/// Plan §5.4 per-leg sub-vectors across units: a USD+EUR hold posts a
/// partial sub-vector balanced per unit, an unbalanced one is refused per
/// unit, and a timed multi-unit hold the sweep expires releases both units'
/// cells. Kernel and oracle agree on every verdict and cell.
#[test]
fn multi_unit_holds_post_partially_per_unit_and_expire_in_every_unit() {
    let (mut k, mut oracle, periods) = setup_with(BUDGETED);
    let usd = k.book.units.lookup("USD").unwrap();
    let eur = k.book.units.lookup("EUR").unwrap();
    open_period(&mut k, &mut oracle, &periods[2], 1);
    // EUR cash (with a floor) and EUR expense, in a second chart effect.
    let eur_chart = [
        AccountSpec {
            code: "1010".into(),
            name: "Cash EUR".into(),
            account_type: 1,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(eur),
            parent_code: None,
            limit: Some(BalanceLimit {
                lower: Some(0),
                upper: None,
                scope: LimitScope::Lifetime,
            }),
        },
        AccountSpec {
            code: "6010".into(),
            name: "Expense EUR".into(),
            account_type: 5,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(eur),
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "3010".into(),
            name: "Equity EUR".into(),
            account_type: 3,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(eur),
            parent_code: None,
            limit: None,
        },
    ];
    {
        let ctx = k.ctx();
        let db = &mut k.db;
        let book = &k.book;
        let day = DateDay::from_ymd(2026, 1, 1).unwrap();
        let description = fresh_seal(&book.seal_key, "eur chart");
        k.runtime
            .block_on(async move {
                install_chart(
                    db,
                    &ctx,
                    book,
                    &eur_chart,
                    PRINCIPAL,
                    day,
                    b"eur",
                    description,
                    &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
                )
                .await
            })
            .expect("kernel")
            .expect("installs");
    }
    for code in ["1010", "6010", "3010"] {
        oracle.add_account(Account {
            code: code.into(),
            is_leaf: true,
            unit: Some(eur.0),
        });
    }
    oracle.set_limit(
        "1010",
        Limit {
            normal: fa_reference::Side::Debit,
            lower: Some(0),
            upper: None,
            per_period: false,
        },
    );
    let march = DateDay::from_ymd(2026, 3, 15).unwrap();
    let leg = |side: fa_reference::Side, account: &str, unit: UnitId, mantissa: i128| Leg {
        side,
        account: account.into(),
        unit: unit.0,
        entity: None,
        mantissa,
    };
    let dr = fa_reference::Side::Debit;
    let cr = fa_reference::Side::Credit;
    let intent = |class: &str, legs: Vec<Leg>, key: &str, resolves: Option<Resolve>| Intent {
        class: class.into(),
        date: march,
        discriminator: None,
        legs,
        key: key.as_bytes().to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves,
        settles: Vec::new(),
    };
    // The kernel request with each leg in its own unit (the shared helper
    // writes USD).
    let in_units = |k: &Kernel, i: &Intent, refs: &[EntryRef], timeout: Option<u64>| {
        let mut req = kernel_request(k, i, usd, refs);
        for (l, m) in req.proposal.legs.iter_mut().zip(&i.legs) {
            l.amount = Amount::new(UnitId(m.unit), l.amount.mantissa);
        }
        req.proposal.unit_totals =
            EntryPayload::fold_unit_totals(&req.proposal.legs).expect("totals");
        if let (Some(t), Some(p)) = (timeout, req.proposal.pending.as_mut()) {
            p.timeout_ns = Some(t);
        }
        req
    };
    let run = |k: &mut Kernel, i: &Intent, refs: &[EntryRef], timeout: Option<u64>| {
        let req = in_units(k, i, refs, timeout);
        let ctx = k.ctx();
        let db = &mut k.db;
        let book = &k.book;
        k.runtime
            .block_on(async move { post(db, &ctx, book, req).await })
            .expect("kernel")
    };
    let mut refs: Vec<EntryRef> = Vec::new();
    for (key, legs) in [
        (
            "fund-usd",
            vec![leg(dr, "1000", usd, 1_000), leg(cr, "3000", usd, 1_000)],
        ),
        (
            "fund-eur",
            vec![leg(dr, "1010", eur, 800), leg(cr, "3010", eur, 800)],
        ),
    ] {
        let i = intent("Original", legs, key, None);
        refs.push(run(&mut k, &i, &refs, None).expect("funds").entry_ref());
        assert!(matches!(oracle.post(&i), Verdict::Posted { .. }));
    }
    // Hold: Dr 6000 USD 100, Dr 6010 EUR 50 / Cr 1000 USD 100, Cr 1010 EUR 50.
    let hold_legs = vec![
        leg(dr, "6000", usd, 100),
        leg(dr, "6010", eur, 50),
        leg(cr, "1000", usd, 100),
        leg(cr, "1010", eur, 50),
    ];
    let hold = intent("Pending", hold_legs.clone(), "hold", None);
    refs.push(run(&mut k, &hold, &refs, None).expect("hold").entry_ref());
    assert!(matches!(
        oracle.post(&hold),
        Verdict::Posted { index: 2, .. }
    ));
    let posts = |legs: Vec<Leg>, key: &str| {
        intent(
            "Resolution",
            legs,
            key,
            Some(Resolve {
                target: 2,
                posts: Some(vec![0, 1, 2, 3]),
            }),
        )
    };
    // Unbalanced in EUR (20 vs 30): refused per unit, by both.
    let bad = posts(
        vec![
            leg(dr, "6000", usd, 60),
            leg(dr, "6010", eur, 20),
            leg(cr, "1000", usd, 60),
            leg(cr, "1010", eur, 30),
        ],
        "bad",
    );
    let r = run(&mut k, &bad, &refs, None).expect_err("EUR unbalanced");
    assert_eq!(oracle.post(&bad), Verdict::Refused { code: "FA-REF-001" });
    assert_eq!(r.code, "FA-REF-001", "{r}");
    assert!(r.message.contains("EUR"), "{r}");
    // A EUR leg drawn from a USD pending leg: refused, by both.
    let crossed = intent(
        "Resolution",
        vec![leg(dr, "6010", eur, 20), leg(cr, "1010", eur, 20)],
        "crossed",
        Some(Resolve {
            target: 2,
            posts: Some(vec![0, 3]),
        }),
    );
    let r = run(&mut k, &crossed, &refs, None).expect_err("wrong source");
    assert_eq!(
        oracle.post(&crossed),
        Verdict::Refused { code: "FA-REF-061" }
    );
    assert_eq!(r.code, "FA-REF-061", "{r}");
    // Partial in both units, balanced per unit: posted; the full hold is
    // released in both units and only the sub-vector posts.
    let good = posts(
        vec![
            leg(dr, "6000", usd, 60),
            leg(dr, "6010", eur, 20),
            leg(cr, "1000", usd, 60),
            leg(cr, "1010", eur, 20),
        ],
        "good",
    );
    refs.push(
        run(&mut k, &good, &refs, None)
            .expect("partial")
            .entry_ref(),
    );
    assert!(matches!(
        oracle.post(&good),
        Verdict::Posted { index: 3, .. }
    ));
    assert_cell_in(&k, &oracle, "1000", None, 1);
    assert_cell_in(&k, &oracle, "1010", None, 1);
    let eur_cash = oracle.availability("1010");
    assert_eq!(
        (
            eur_cash.credits_posted.to_i128(),
            eur_cash.credits_pending.to_i128()
        ),
        (Some(20), Some(0))
    );

    // A timed multi-unit hold the sweep expires releases both units.
    kernel_tick(&mut k, 7, "t0").expect("tick");
    oracle.record_tick(7).unwrap();
    let timed = intent("Pending", hold_legs, "timed", None);
    refs.push(
        run(&mut k, &timed, &refs, Some(3))
            .expect("timed")
            .entry_ref(),
    );
    assert!(matches!(
        oracle.post_timed(&timed, 3),
        Verdict::Posted { index: 4, .. }
    ));
    assert_eq!(
        oracle.availability("1010").credits_pending.to_i128(),
        Some(50)
    );
    kernel_tick(&mut k, 10, "t1").expect("due tick");
    oracle.record_tick(10).unwrap();
    let swept = sweep_both(&mut k, &mut oracle, &mut refs, 4, 2).expect("expires");
    assert_eq!(
        swept.expired.iter().map(|(h, _)| *h).collect::<Vec<_>>(),
        vec![4]
    );
    assert_cell_in(&k, &oracle, "1000", None, 3);
    assert_cell_in(&k, &oracle, "1010", None, 3);
    assert_eq!(
        oracle.availability("1010").credits_pending.to_i128(),
        Some(0)
    );
    assert_eq!(
        oracle.availability("1000").credits_pending.to_i128(),
        Some(0)
    );
    assert!(
        verify_availability(&k.db, &k.book, None)
            .unwrap()
            .is_green()
    );
}

// ---------------------------------------------------------------------------
// Scheduled reversals (plan §7.6; bead fa-ctf slice 2)
// ---------------------------------------------------------------------------

const NS_PER_DAY: u64 = 86_400_000_000_000;

/// A tick at noon UTC of `day`.
fn noon(day: DateDay) -> u64 {
    u64::try_from(day.0).expect("after 1970") * NS_PER_DAY + NS_PER_DAY / 2
}

/// The kernel request of an Adjusting accrual that schedules its reversal.
fn kernel_post_scheduled(
    k: &mut Kernel,
    intent: &Intent,
    usd: UnitId,
    refs: &[EntryRef],
    reverse_on: DateDay,
) -> Result<Posted, Refusal> {
    let mut req = kernel_request(k, intent, usd, refs);
    req.proposal = with_auto_reverse(req.proposal, reverse_on);
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    k.runtime
        .block_on(async move { post(db, &ctx, book, req).await })
        .expect("kernel")
}

fn kernel_sweep_reversals(
    k: &mut Kernel,
    max_batch: usize,
) -> Result<Option<ReversalBatch>, Refusal> {
    let req = sweeper(k, max_batch);
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    k.runtime
        .block_on(async move {
            let mut describe = |text: &str| Ok::<_, KernelError>(fresh_seal(&book.seal_key, text));
            sweep_reversals_batch(db, &ctx, book, &req, &mut describe).await
        })
        .expect("kernel")
}

fn index_of(refs: &[EntryRef], r: &EntryRef) -> usize {
    refs.iter()
        .position(|x| x == r)
        .expect("an entry the differential posted")
}

/// The kernel's reached schedules as `(target index, status)`.
fn kernel_reached(k: &Kernel, refs: &[EntryRef]) -> Vec<(usize, fa_reference::Reached)> {
    due_reversals(&k.db, &k.book)
        .expect("due scan")
        .iter()
        .map(|d| {
            (
                index_of(refs, &d.schedule.target),
                match d.status {
                    ReversalStatus::Due => fa_reference::Reached::Due,
                    ReversalStatus::Waiting { .. } => fa_reference::Reached::Waiting,
                    ReversalStatus::Blocked { .. } => fa_reference::Reached::Blocked,
                },
            )
        })
        .collect()
}

/// One reversal-sweep batch on both engines: minted (with their derived
/// identities), blocked, and the backlog agree; the minted reversals join
/// `refs` at the oracle's indices.
fn reversal_sweep_both(
    k: &mut Kernel,
    oracle: &mut Oracle,
    refs: &mut Vec<EntryRef>,
    max_batch: usize,
    step: u64,
) -> Option<fa_reference::ReversalSweep> {
    let kernel = kernel_sweep_reversals(k, max_batch);
    let model = oracle.sweep_reversals_batch(max_batch);
    match (&kernel, &model) {
        (Ok(None), Ok(None)) => None,
        (Ok(Some(b)), Ok(Some(m))) => {
            assert_eq!(b.tick.observed_utc_ns, m.tick, "step {step}: tick");
            assert_eq!(b.remaining, m.remaining, "step {step}: reversal backlog");
            assert_eq!(
                b.blocked
                    .iter()
                    .map(|(t, _)| index_of(refs, t))
                    .collect::<Vec<_>>(),
                m.blocked,
                "step {step}: blocked"
            );
            assert_eq!(b.minted.len(), m.minted.len(), "step {step}: minted");
            assert!(b.minted.len() + b.blocked.len() <= max_batch);
            for ((target, reversal), (t, index)) in b.minted.iter().zip(&m.minted) {
                assert_eq!(*target, refs[*t], "step {step}: minted target");
                assert_eq!(*index, refs.len(), "step {step}: journal index");
                assert_eq!(reversal.vid, rows::reversal_vid(target.vid));
                refs.push(*reversal);
            }
            Some(m.clone())
        }
        (Err(r), Err(code)) => {
            assert_eq!(r.code, *code, "step {step}: {r}");
            None
        }
        _ => {
            assert_eq!(
                format!("kernel {kernel:?}"),
                format!("oracle {model:?}"),
                "step {step}: reversal sweep disagreement"
            );
            None
        }
    }
}

/// Open `code` on both engines; the reversals minted inside the transition
/// agree. Returns how many were minted.
fn open_both(
    k: &mut Kernel,
    oracle: &mut Oracle,
    refs: &mut Vec<EntryRef>,
    code: &str,
    step: u64,
) -> usize {
    let kernel = kernel_transition(k, code, PeriodTransition::Open, step).expect("opens");
    let (from, to, minted, blocked) = oracle
        .transition_minting(code, PeriodTransition::Open)
        .expect("oracle opens");
    assert_eq!((kernel.from, kernel.to), (from, to));
    assert_eq!(
        kernel
            .blocked
            .iter()
            .map(|(t, _)| index_of(refs, t))
            .collect::<Vec<_>>(),
        blocked,
        "{code}: blocked at Open"
    );
    assert_eq!(kernel.minted.len(), minted.len(), "{code}: minted at Open");
    for ((target, reversal), (t, index)) in kernel.minted.iter().zip(&minted) {
        assert_eq!(*target, refs[*t]);
        assert_eq!(*index, refs.len());
        assert_eq!(reversal.vid, rows::reversal_vid(target.vid));
        refs.push(*reversal);
        // The book's own entry, triggered by this transition (rule (b)).
        let (e, _) = fa_journal::post::read_entry(&k.db, reversal.vid)
            .unwrap()
            .expect("minted");
        assert_eq!(e.proposal.principal_ref, system(k));
        assert!(matches!(
            e.proposal.origin,
            EntryOrigin::Schedule {
                trigger: fa_model::ScheduleTrigger::OpenPeriod { transition_ref },
                ..
            } if transition_ref == kernel.control_entry
        ));
    }
    minted.len()
}

#[test]
fn kernel_and_oracle_agree_on_scheduled_reversals() {
    let (mut k, mut oracle, periods) = setup_with(BUDGETED);
    oracle.declare_time_zone();
    let usd = k.book.units.lookup("USD").unwrap();
    for (i, p) in periods.iter().take(3).enumerate() {
        open_period(&mut k, &mut oracle, p, 9_100 + i as u64);
    }
    let leg = |side: fa_reference::Side, account: &str, mantissa: i128| Leg {
        side,
        account: account.into(),
        unit: usd.0,
        entity: None,
        mantissa,
    };
    let dr = fa_reference::Side::Debit;
    let cr = fa_reference::Side::Credit;
    let plain = |class: &str, legs: Vec<Leg>, key: Vec<u8>, date: DateDay| Intent {
        class: class.into(),
        date,
        discriminator: None,
        legs,
        key,
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    };
    let day0 = DateDay::from_ymd(2026, 1, 5).unwrap();
    let mut today = day0;
    let mut rng = Rng(0x5C4E_D01E_D0AF_7E57);
    let mut refs: Vec<EntryRef> = Vec::new();
    let mut scheduled: Vec<usize> = Vec::new();
    let mut refused: BTreeMap<&'static str, u32> = BTreeMap::new();
    let (mut swept_minted, mut open_minted, mut blocked_seen) = (0usize, 0usize, 0usize);
    let (mut cancelled, mut by_hand_after_block, mut backlog_batches) = (0u32, 0u32, 0u32);
    let mut blocked_closed: BTreeSet<usize> = BTreeSet::new();

    let fund = plain(
        "Original",
        vec![leg(dr, "1000", 200_000), leg(cr, "3000", 200_000)],
        b"fund".to_vec(),
        day0,
    );
    refs.push(
        kernel_post(&mut k, &fund, usd, &refs)
            .expect("funds")
            .entry_ref(),
    );
    assert!(matches!(oracle.post(&fund), Verdict::Posted { .. }));
    kernel_tick(&mut k, noon(today), "s-tick-0").expect("tick");
    oracle.record_tick(noon(today)).unwrap();
    let mut tick_seq = 0u64;

    for step in 0..420u64 {
        // Origin periods of live schedules close (P02) and lock (P01): just
        // before each, two accruals scheduled to reverse inside it, already
        // reached, so the sweep meets them Closed / Locked (R4).
        if step == 230 || step == 330 {
            let month = if step == 230 { 1 } else { 2 };
            for n in 0..2 {
                let i = plain(
                    "Adjusting",
                    vec![leg(dr, "6000", 10 + n), leg(cr, "3000", 10 + n)],
                    format!("pre-close-{step}-{n}").into_bytes(),
                    DateDay::from_ymd(2026, month, 10).unwrap(),
                );
                let reverse_on = DateDay::from_ymd(2026, month, 20).unwrap();
                let posted = kernel_post_scheduled(&mut k, &i, usd, &refs, reverse_on)
                    .expect("a pre-close accrual posts");
                assert!(matches!(
                    oracle.post_scheduled(&i, reverse_on),
                    Verdict::Posted { .. }
                ));
                refs.push(posted.entry_ref());
                scheduled.push(refs.len() - 1);
            }
            let code = periods[usize::from(month) - 1].clone();
            close_and_maybe_lock(&mut k, &mut oracle, &code, step == 230, step);
        }
        match step {
            150 => open_minted += open_both(&mut k, &mut oracle, &mut refs, &periods[3], step),
            300 => open_minted += open_both(&mut k, &mut oracle, &mut refs, &periods[4], step),
            _ => {}
        }
        let mut months: Vec<u8> = Vec::new();
        if step < 230 {
            months.push(1);
        }
        if step < 330 {
            months.push(2);
        }
        months.push(3);
        if step >= 150 {
            months.push(4);
        }
        if step >= 300 {
            months.push(5);
        }
        let pick_open = |rng: &mut Rng| {
            let month = months[rng.below(months.len() as u64) as usize];
            DateDay::from_ymd(2026, month, 1 + rng.below(27) as u8).unwrap()
        };
        let key = format!("r{step}").into_bytes();
        match rng.below(20) {
            0..=3 => {
                // Time passes: one to six days.
                today = DateDay(today.0 + 1 + rng.below(6) as i32);
                tick_seq += 1;
                kernel_tick(&mut k, noon(today), &format!("s-tick-{tick_seq}")).expect("tick");
                oracle.record_tick(noon(today)).unwrap();
            }
            4..=8 => {
                // An accrual that schedules its reversal 1..45 days later:
                // a cash accrual (its reversal is an outflow the floor may
                // block) or a budget-capped expense accrual.
                let a = 1 + rng.below(30_000) as i128;
                let date = pick_open(&mut rng);
                let legs = if rng.chance(50) {
                    vec![leg(dr, "1000", a), leg(cr, "3000", a)]
                } else {
                    vec![leg(dr, "6100", a.min(9_000)), leg(cr, "3000", a.min(9_000))]
                };
                // Planted: a reversal date not after the entry, or a class
                // that cannot schedule.
                let planted = rng.chance(6);
                let reverse_on = if planted && rng.chance(50) {
                    date
                } else {
                    DateDay(date.0 + 1 + rng.below(45) as i32)
                };
                let mut i = plain("Adjusting", legs, key, date);
                if planted && reverse_on != date {
                    i.class = "Original".into();
                }
                let kernel = kernel_post_scheduled(&mut k, &i, usd, &refs, reverse_on);
                let model = oracle.post_scheduled(&i, reverse_on);
                match (&kernel, &model) {
                    (Ok(Posted::Committed { entry_ref, .. }), Verdict::Posted { index, .. }) => {
                        assert_eq!(*index, refs.len(), "step {step}");
                        refs.push(*entry_ref);
                        scheduled.push(*index);
                        let svid = rows::schedule_vid(entry_ref.vid);
                        let row = k.db.vertex(svid).unwrap().expect("schedule vertex");
                        let s = fa_journal::schedule::decode_schedule(&row).unwrap();
                        assert_eq!(s.reverse_on, reverse_on);
                        assert_eq!(
                            Some(s.period.as_str()),
                            oracle.schedule(*index).map(|x| x.period.as_str())
                        );
                    }
                    (Err(r), Verdict::Refused { code }) => {
                        assert_eq!(r.code, *code, "step {step}: {r}");
                        *refused.entry(code).or_insert(0) += 1;
                    }
                    _ => assert_eq!(
                        format!("kernel {kernel:?}"),
                        format!("oracle {model:?}"),
                        "step {step}: scheduled accrual disagreement"
                    ),
                }
            }
            9..=10 => {
                // Spend cash: a later cash reversal may meet the floor.
                let a = 1 + rng.below(40_000) as i128;
                let i = plain(
                    "Original",
                    vec![leg(dr, "6000", a), leg(cr, "1000", a)],
                    key,
                    pick_open(&mut rng),
                );
                let kernel = kernel_post(&mut k, &i, usd, &refs);
                let model = oracle.post(&i);
                match (&kernel, &model) {
                    (Ok(Posted::Committed { entry_ref, .. }), Verdict::Posted { .. }) => {
                        refs.push(*entry_ref);
                    }
                    (Err(r), Verdict::Refused { code }) => assert_eq!(r.code, *code),
                    _ => assert_eq!(format!("{kernel:?}"), format!("{model:?}")),
                }
            }
            11..=12 if !scheduled.is_empty() => {
                // Reverse a scheduled target by hand: before execution it
                // cancels the schedule by lineage; after, it is the
                // one-reversal conflict (exit 6).
                let target = scheduled[rng.below(scheduled.len() as u64) as usize];
                let original = oracle.entry(target).expect("target").clone();
                let mut i = plain(
                    "Reversal",
                    original
                        .legs
                        .iter()
                        .map(|l| leg(l.side.flipped(), &l.account, l.mantissa))
                        .collect(),
                    key,
                    pick_open(&mut rng),
                );
                i.reverses = Some(target);
                let was_blocked = blocked_closed.contains(&target);
                let kernel = kernel_post(&mut k, &i, usd, &refs);
                let model = oracle.post(&i);
                match (&kernel, &model) {
                    (Ok(Posted::Committed { entry_ref, .. }), Verdict::Posted { index, .. }) => {
                        assert_eq!(*index, refs.len(), "step {step}");
                        refs.push(*entry_ref);
                        assert!(oracle.schedule(target).is_some_and(|s| s.cancelled));
                        let svid = rows::schedule_vid(refs[target].vid);
                        assert!(
                            k.db.vertex(rows::schedule_cancel_vid(svid))
                                .unwrap()
                                .is_some(),
                            "step {step}: the cancellation is journaled with the reversal"
                        );
                        cancelled += 1;
                        if was_blocked {
                            by_hand_after_block += 1;
                        }
                    }
                    (Err(r), Verdict::Refused { code }) => {
                        assert_eq!(r.code, *code, "step {step}: {r}");
                        if *code == "FA-REF-052" {
                            assert_eq!(r.exit, exit::CONFLICT);
                        }
                        *refused.entry(code).or_insert(0) += 1;
                    }
                    _ => assert_eq!(
                        format!("kernel {kernel:?}"),
                        format!("oracle {model:?}"),
                        "step {step}: manual reversal disagreement"
                    ),
                }
            }
            _ => {
                let max = 1 + rng.below(3) as usize;
                if let Some(m) = reversal_sweep_both(&mut k, &mut oracle, &mut refs, max, step) {
                    swept_minted += m.minted.len();
                    blocked_seen += m.blocked.len();
                    if m.remaining > 0 {
                        backlog_batches += 1;
                    }
                }
            }
        }
        let projections = verify_projections(&k.db, &k.book, None).unwrap();
        assert!(
            projections.is_green(),
            "step {step}: scheduled leg projections: {projections:?}"
        );
        // Every step: the reached schedules and every limit cell agree.
        let reached = oracle.reached_reversals();
        assert_eq!(kernel_reached(&k, &refs), reached, "step {step}: reached");
        for (t, s) in &reached {
            if *s == fa_reference::Reached::Blocked
                && oracle.schedule(*t).is_some_and(|x| {
                    matches!(
                        oracle.period_state(&x.period),
                        Some(PeriodState::Closed | PeriodState::Locked)
                    )
                })
            {
                blocked_closed.insert(*t);
            }
        }
        assert_cell_in(&k, &oracle, "1000", None, step);
        for p in periods.iter().take(6) {
            assert_cell_in(&k, &oracle, "6100", Some(p.as_str()), step);
        }
    }
    // Every schedule still blocked in the locked period is reversed by hand
    // in an open one, which cancels it.
    for t in blocked_closed.clone() {
        if !oracle.schedule(t).is_some_and(|s| !s.cancelled)
            || oracle.entry(t).is_none()
            || k.db
                .vertex(rows::reversal_vid(refs[t].vid))
                .unwrap()
                .is_some()
        {
            continue;
        }
        let original = oracle.entry(t).expect("target").clone();
        let mut i = plain(
            "Reversal",
            original
                .legs
                .iter()
                .map(|l| leg(l.side.flipped(), &l.account, l.mantissa))
                .collect(),
            format!("by-hand-{t}").into_bytes(),
            DateDay::from_ymd(2026, 3, 20).unwrap(),
        );
        i.reverses = Some(t);
        let kernel = kernel_post(&mut k, &i, usd, &refs);
        let model = oracle.post(&i);
        match (&kernel, &model) {
            (Ok(Posted::Committed { entry_ref, .. }), Verdict::Posted { .. }) => {
                refs.push(*entry_ref);
                by_hand_after_block += 1;
                cancelled += 1;
            }
            (Err(r), Verdict::Refused { code }) => assert_eq!(r.code, *code),
            _ => assert_eq!(format!("{kernel:?}"), format!("{model:?}")),
        }
    }
    let verified = verify_schedules(&k.db, &k.book).unwrap();
    assert!(verified.is_green(), "{verified:?}");
    assert_eq!(verified.schedules_checked, scheduled.len());
    assert_eq!(verified.cancelled as u32, cancelled);
    assert_eq!(verified.executed, swept_minted + open_minted);
    assert!(
        verify_availability(&k.db, &k.book, None)
            .unwrap()
            .is_green()
    );

    // Not vacuous: both execution paths minted, schedules were cancelled by
    // hand, a locked period blocked some that were then reversed by hand,
    // availability blocked some, a backlog took several batches, and the
    // planted refusals fired.
    assert!(scheduled.len() >= 60, "scheduled {}", scheduled.len());
    assert!(swept_minted >= 15, "minted by the sweep {swept_minted}");
    assert!(open_minted >= 2, "minted at Open {open_minted}");
    assert!(cancelled >= 5, "cancelled {cancelled}");
    assert!(blocked_seen >= 3, "blocked at execution {blocked_seen}");
    assert!(
        blocked_closed.len() >= 4 && by_hand_after_block >= 2,
        "closed/locked-period blocks {blocked_closed:?}, reversed by hand {by_hand_after_block}"
    );
    assert!(backlog_batches >= 3, "backlog batches {backlog_batches}");
    for (must, floor) in [("FA-REF-100", 2), ("FA-REF-052", 2)] {
        assert!(
            refused.get(must).is_some_and(|n| *n >= floor),
            "refusal {must} under-exercised: {refused:?}"
        );
    }
}

/// Plan §7.6 on the real substrate: a manual Reversal and the reversal
/// sweep race on the target's reversal identity — the one that witnessed
/// the identity absent loses first-committer-wins — and after execution a
/// manual reversal is the one-reversal conflict (exit 6). A ScheduleControl
/// is never posted (099).
#[test]
fn a_manual_reversal_and_the_reversal_sweep_race_by_identity() {
    let (mut k, mut oracle, periods) = setup_with(BUDGETED);
    oracle.declare_time_zone();
    let usd = k.book.units.lookup("USD").unwrap();
    open_period(&mut k, &mut oracle, &periods[2], 1);
    let leg = |side: fa_reference::Side, account: &str, mantissa: i128| Leg {
        side,
        account: account.into(),
        unit: usd.0,
        entity: None,
        mantissa,
    };
    let march = |d: u8| DateDay::from_ymd(2026, 3, d).unwrap();
    let accrual = |key: &str| Intent {
        class: "Adjusting".into(),
        date: march(2),
        discriminator: None,
        legs: vec![
            leg(fa_reference::Side::Debit, "6000", 50),
            leg(fa_reference::Side::Credit, "3000", 50),
        ],
        key: key.as_bytes().to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    };
    let mut refs: Vec<EntryRef> = Vec::new();
    kernel_tick(&mut k, noon(march(1)), "t0").expect("tick");
    oracle.record_tick(noon(march(1))).unwrap();
    for key in ["A", "B"] {
        let i = accrual(key);
        refs.push(
            kernel_post_scheduled(&mut k, &i, usd, &refs, march(10))
                .expect("scheduled")
                .entry_ref(),
        );
        assert!(matches!(
            oracle.post_scheduled(&i, march(10)),
            Verdict::Posted { .. }
        ));
    }
    // Before the date nothing is reached; the sweep writes nothing.
    let frontier = k.db.frontier().unwrap();
    assert_eq!(kernel_sweep_reversals(&mut k, 5), Ok(None));
    assert_eq!(k.db.frontier().unwrap(), frontier);
    kernel_tick(&mut k, noon(march(10)), "t1").expect("the date's tick");
    oracle.record_tick(noon(march(10))).unwrap();
    assert_eq!(
        kernel_reached(&k, &refs),
        vec![
            (0, fa_reference::Reached::Due),
            (1, fa_reference::Reached::Due)
        ]
    );

    // A manual reversal of A that witnessed A's reversal identity as absent
    // loses to the sweep that mints it first.
    let ctx = k.ctx();
    let txn_cx = ctx.txn();
    let mut manual = k.db.begin(&txn_cx).expect("begin");
    let a = refs[0].vid;
    assert!(
        manual
            .vertex(&k.db, rows::reversal_vid(a))
            .expect("read")
            .is_none()
    );
    let batch = reversal_sweep_both(&mut k, &mut oracle, &mut refs, 1, 1).expect("mints A");
    assert_eq!(batch.minted.len(), 1);
    assert_eq!(batch.remaining, 1);
    let mut write = WriteBatch::new(fa_model::symbols::relation::IN_PERIOD);
    write.create_vertex(
        rows::reversal_vid(a),
        vec![fa_model::symbols::label::ENTRY],
        Vec::new(),
    );
    let staged = manual.write_ordered(&mut k.db, vec![write]);
    assert!(
        matches!(staged, Err(fgdb::WriteTxnError::SnapshotAdvanced { .. })),
        "{staged:?}"
    );
    let refreshed = manual.refresh_snapshot(&k.db, &txn_cx);
    assert!(
        matches!(
            refreshed,
            Err(fgdb::WriteTxnError::Write(
                fgdb::WriteError::FirstCommitterWins { .. }
            ))
        ),
        "the manual reversal must lose the identity race: {refreshed:?}"
    );
    manual.abort();
    // Through `post`, after execution: the one-reversal conflict, exit 6.
    let mut by_hand = accrual("by-hand-A");
    by_hand.class = "Reversal".into();
    by_hand.date = march(12);
    by_hand.legs = by_hand
        .legs
        .iter()
        .map(|l| Leg {
            side: l.side.flipped(),
            ..l.clone()
        })
        .collect();
    by_hand.reverses = Some(0);
    let r = kernel_post(&mut k, &by_hand, usd, &refs).expect_err("already reversed");
    assert_eq!(
        oracle.post(&by_hand),
        Verdict::Refused { code: "FA-REF-052" }
    );
    assert_eq!((r.code, r.exit), ("FA-REF-052", exit::CONFLICT), "{r}");
    // The minted reversal is the bound effect: the exact swap, dated
    // reverse_on, the original preparer, the date basis recorded.
    let (minted, _) = fa_journal::post::read_entry(&k.db, rows::reversal_vid(a))
        .unwrap()
        .expect("minted");
    assert_eq!(minted.proposal.class, EntryClass::REVERSAL);
    assert_eq!(minted.proposal.effective_date, march(10));
    assert_eq!(minted.proposal.principal_ref, system(&k));
    assert_eq!(
        minted.proposal.origin,
        EntryOrigin::Schedule {
            schedule_ref: rows::schedule_vid(a),
            trigger: fa_model::ScheduleTrigger::Sweep {
                tick_ref: latest_tick(&k.db).unwrap().expect("tick").entry,
            },
        }
    );
    assert!(matches!(
        fa_journal::schedule::date_basis(&minted.proposal),
        Ok(Some((TimeZonePolicy::Utc, _)))
    ));
    // A ScheduleControl is never posted.
    let mut req = kernel_request(&k, &accrual("ctl"), usd, &refs);
    req.proposal.class = EntryClass::SCHEDULE_CONTROL;
    req.proposal.legs = Vec::new();
    req.proposal.unit_totals = Vec::new();
    req.proposal.control = Some(ControlPayload::ScheduleCancelled {
        schedule_ref: rows::schedule_vid(refs[1].vid),
        cause_ref: VId(1),
    });
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    let r = k
        .runtime
        .block_on(async move { post(db, &ctx, book, req).await })
        .expect("kernel")
        .expect_err("never posted");
    assert_eq!((r.code, r.exit), ("FA-REF-099", exit::USAGE), "{r}");
    // B still fires, and verify agrees.
    let rest = reversal_sweep_both(&mut k, &mut oracle, &mut refs, 5, 2).expect("mints B");
    assert_eq!(rest.minted.len(), 1);
    let v = verify_schedules(&k.db, &k.book).unwrap();
    assert!(v.is_green() && v.executed == 2 && v.cancelled == 0, "{v:?}");
}

// ---------------------------------------------------------------------------
// The per-entity balance law (plan §4.1, §5.2, FA-INV-01 `per-entity`;
// bead fa-bvx slice 3)
// ---------------------------------------------------------------------------

/// Cash with a floor, intercompany due-from (1500) and due-to (2500), equity,
/// revenue, expense.
const ENTITY_CHART: &[ChartRow] = &[
    (
        "1000",
        1,
        true,
        0,
        Some(BalanceLimit {
            lower: Some(0),
            upper: None,
            scope: LimitScope::Lifetime,
        }),
    ),
    ("1500", 1, true, 0, None),
    ("2500", 2, true, 1, None),
    ("3000", 3, true, 1, None),
    ("4000", 4, true, 1, None),
    ("6000", 5, true, 0, None),
];

const ENTITIES: &[&str] = &["US", "UK", "DE"];

/// `(account code, unit, entity) → (debits, credits, entry_count)`.
type EntityTable = BTreeMap<(String, u32, Option<String>), (i128, i128, u64)>;

/// The kernel's per-entity fold of `period` as the oracle's map.
fn kernel_entity_fold(
    k: &Kernel,
    period: &str,
    known_at: Option<CommitSeq>,
) -> (EntityTable, [u8; 32]) {
    let fold = fold_period_by_entity(&k.db, &k.book, period, known_at).unwrap();
    let code_of = |vid: VId| {
        ENTITY_CHART
            .iter()
            .map(|(c, ..)| *c)
            .find(|c| account_vid(k.book.book_id, c) == vid)
            .expect("a chart account")
            .to_string()
    };
    (
        fold.cells
            .iter()
            .map(|c| {
                (
                    (code_of(c.key.account), c.key.unit_id, c.key.entity.clone()),
                    (c.debits, c.credits, c.entry_count),
                )
            })
            .collect(),
        fold.fold_digest,
    )
}

fn oracle_entity_fold(oracle: &Oracle, period: &str) -> EntityTable {
    oracle
        .fold_by_entity(period)
        .into_iter()
        .map(|(k, c)| {
            (
                k,
                (
                    c.debits.to_i128().expect("fits"),
                    c.credits.to_i128().expect("fits"),
                    c.entry_count,
                ),
            )
        })
        .collect()
}

#[test]
fn kernel_and_oracle_agree_on_the_per_entity_balance_law() {
    let (mut k, mut oracle, periods, _) = setup_entities(ENTITY_CHART, ENTITIES);
    let usd = k.book.units.lookup("USD").unwrap();
    let march = periods[2].clone();
    open_period(&mut k, &mut oracle, &march, 1);
    let day = |d: u64| DateDay::from_ymd(2026, 3, 1 + (d % 28) as u8).unwrap();
    let leg = |side: fa_reference::Side, account: &str, entity: Option<&str>, m: i128| Leg {
        side,
        account: account.into(),
        unit: usd.0,
        entity: entity.map(str::to_string),
        mantissa: m,
    };
    let dr = fa_reference::Side::Debit;
    let cr = fa_reference::Side::Credit;
    let plain = |class: &str, legs: Vec<Leg>, key: Vec<u8>, date: DateDay| Intent {
        class: class.into(),
        date,
        discriminator: None,
        legs,
        key,
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    };
    let mut rng = Rng(0x00E7_1717_B41A_7CE5);
    let mut refs: Vec<EntryRef> = Vec::new();
    let mut holds: Vec<usize> = Vec::new();
    let mut resolved: BTreeSet<usize> = BTreeSet::new();
    let mut reversed: BTreeSet<usize> = BTreeSet::new();
    let mut posted_entries: Vec<usize> = Vec::new();
    let mut refused: BTreeMap<&'static str, u32> = BTreeMap::new();
    let (mut posted, mut intercompany, mut balancing_ok) = (0u32, 0u32, 0u32);
    let (mut cross_entity, mut cross_balancing) = (0u32, 0u32);
    let mut claims: Vec<(RegisterEquals, i128)> = Vec::new();
    let (mut claims_checked, mut drifted) = (0u32, 0u32);

    // Fund every entity's cash.
    for (n, e) in ENTITIES.iter().enumerate() {
        let i = plain(
            "Original",
            vec![
                leg(dr, "1000", Some(e), 500_000),
                leg(cr, "3000", Some(e), 500_000),
            ],
            format!("fund-{e}").into_bytes(),
            day(n as u64),
        );
        refs.push(
            kernel_post(&mut k, &i, usd, &refs)
                .expect("funds")
                .entry_ref(),
        );
        assert!(matches!(oracle.post(&i), Verdict::Posted { .. }));
        posted_entries.push(refs.len() - 1);
    }

    for step in 0..440u64 {
        let key = format!("e{step}").into_bytes();
        let date = day(rng.below(28));
        let pick = |rng: &mut Rng| ENTITIES[rng.below(ENTITIES.len() as u64) as usize];
        let e1 = pick(&mut rng);
        let mut e2 = pick(&mut rng);
        if e2 == e1 {
            e2 = ENTITIES[(ENTITIES.iter().position(|x| *x == e1).unwrap() + 1) % ENTITIES.len()];
        }
        let a = 1 + rng.below(20_000) as i128;
        // (intent, planted code, balancing leg)
        let (intent, planted, balancing): (Intent, Option<&'static str>, Option<u16>) =
            match rng.below(22) {
                0..=4 => (
                    // Within one entity: revenue or spend.
                    if rng.chance(50) {
                        plain(
                            "Original",
                            vec![leg(dr, "1000", Some(e1), a), leg(cr, "4000", Some(e1), a)],
                            key,
                            date,
                        )
                    } else {
                        plain(
                            "Original",
                            vec![leg(dr, "6000", Some(e1), a), leg(cr, "1000", Some(e1), a)],
                            key,
                            date,
                        )
                    },
                    None,
                    None,
                ),
                5..=7 => (
                    // Intercompany: e1 pays e2's expense; each entity
                    // balances through its due-from / due-to account.
                    plain(
                        "Original",
                        vec![
                            leg(dr, "6000", Some(e2), a),
                            leg(cr, "2500", Some(e2), a),
                            leg(dr, "1500", Some(e1), a),
                            leg(cr, "1000", Some(e1), a),
                        ],
                        key,
                        date,
                    ),
                    None,
                    None,
                ),
                8 => (
                    // Planted: balanced per unit, not per entity.
                    plain(
                        "Original",
                        vec![leg(dr, "6000", Some(e2), a), leg(cr, "1000", Some(e1), a)],
                        key,
                        date,
                    ),
                    Some("FA-REF-001"),
                    None,
                ),
                9 => (
                    // Planted: an entity the book never declared.
                    plain(
                        "Original",
                        vec![
                            leg(dr, "6000", Some("ZZ"), a),
                            leg(cr, "1000", Some("ZZ"), a),
                        ],
                        key,
                        date,
                    ),
                    Some("FA-REF-104"),
                    None,
                ),
                10 => (
                    // Planted: a leg naming no entity in a multi-entity book.
                    plain(
                        "Original",
                        vec![leg(dr, "6000", Some(e1), a), leg(cr, "1000", None, a)],
                        key,
                        date,
                    ),
                    Some("FA-REF-005"),
                    None,
                ),
                11..=12 => (
                    // A balancing request: within one entity, or (planted)
                    // across two.
                    {
                        let across = rng.chance(40);
                        plain(
                            "Original",
                            vec![
                                leg(dr, "6000", Some(if across { e2 } else { e1 }), a),
                                leg(cr, "1000", Some(e1), a),
                            ],
                            key,
                            date,
                        )
                    },
                    None,
                    Some(1),
                ),
                13..=14 => {
                    // A hold within one entity.
                    let mut i = plain(
                        "Pending",
                        vec![leg(dr, "6000", Some(e1), a), leg(cr, "1000", Some(e1), a)],
                        key,
                        date,
                    );
                    i.class = "Pending".into();
                    (i, None, None)
                }
                15..=16 if holds.iter().any(|h| !resolved.contains(h)) => {
                    // Resolve a hold: Posts part of it (same entities) or Voids.
                    let open: Vec<usize> = holds
                        .iter()
                        .copied()
                        .filter(|h| !resolved.contains(h))
                        .collect();
                    let target = open[rng.below(open.len() as u64) as usize];
                    let hold = oracle.entry(target).expect("hold").clone();
                    let (legs, posts) = if rng.chance(60) {
                        let t = 1 + rng.below(hold.legs[0].mantissa as u64) as i128;
                        (
                            hold.legs
                                .iter()
                                .map(|l| Leg {
                                    mantissa: t,
                                    ..l.clone()
                                })
                                .collect(),
                            Some(vec![0u16, 1]),
                        )
                    } else {
                        (Vec::new(), None)
                    };
                    let mut i = plain("Resolution", legs, key, date);
                    i.resolves = Some(Resolve { target, posts });
                    (i, None, None)
                }
                17 if posted_entries.iter().any(|p| !reversed.contains(p)) => {
                    // Reverse a posted entry: the swap keeps every entity.
                    let live: Vec<usize> = posted_entries
                        .iter()
                        .copied()
                        .filter(|p| !reversed.contains(p))
                        .collect();
                    let target = live[rng.below(live.len() as u64) as usize];
                    let original = oracle.entry(target).expect("posted").clone();
                    let mut i = plain(
                        "Reversal",
                        original
                            .legs
                            .iter()
                            .map(|l| Leg {
                                side: l.side.flipped(),
                                ..l.clone()
                            })
                            .collect(),
                        key,
                        date,
                    );
                    i.reverses = Some(target);
                    (i, None, None)
                }
                _ => (
                    plain(
                        "Original",
                        vec![leg(dr, "6000", Some(e1), a), leg(cr, "4000", Some(e1), a)],
                        key,
                        date,
                    ),
                    None,
                    None,
                ),
            };
        let crosses = intent
            .legs
            .iter()
            .filter_map(|l| l.entity.clone())
            .collect::<BTreeSet<_>>()
            .len()
            > 1;
        let (kernel, model) = match balancing {
            Some(l) => (
                kernel_post_balancing_raw(&mut k, &intent, usd, &refs, l),
                oracle.post_balancing(&intent, l),
            ),
            None => (
                kernel_post(&mut k, &intent, usd, &refs).map(|p| (p, None)),
                oracle.post(&intent),
            ),
        };
        match (&kernel, &model) {
            (Ok((Posted::Committed { entry_ref, .. }, _)), Verdict::Posted { index, .. }) => {
                assert!(planted.is_none(), "step {step}: a planted negative posted");
                assert_eq!(*index, refs.len(), "step {step}: journal index");
                refs.push(*entry_ref);
                posted += 1;
                match intent.class.as_str() {
                    "Pending" => holds.push(*index),
                    "Resolution" => {
                        resolved.insert(intent.resolves.as_ref().expect("target").target);
                    }
                    "Reversal" => {
                        reversed.insert(intent.reverses.expect("target"));
                    }
                    _ => {
                        posted_entries.push(*index);
                        if intent.legs.len() == 4 {
                            intercompany += 1;
                        }
                        if balancing.is_some() {
                            balancing_ok += 1;
                        }
                    }
                }
            }
            (Err(r), Verdict::Refused { code }) => {
                assert_eq!(r.code, *code, "step {step}: {r}");
                *refused.entry(code).or_insert(0) += 1;
                if let Some(p) = planted {
                    assert_eq!(*code, p, "step {step}: planted refusal");
                }
                if *code == "FA-REF-001" && crosses {
                    // Balanced per unit, unbalanced per entity: the refusal
                    // names the entities, never a leg to invent.
                    assert!(r.message.contains("per legal entity"), "{r}");
                    for l in &intent.legs {
                        let e = l.entity.as_deref().expect("named");
                        assert!(r.message.contains(&format!("`{e}`")), "{r}");
                    }
                    assert!(r.fix.contains("never invents"), "{r}");
                    if balancing.is_some() {
                        cross_balancing += 1;
                    } else {
                        cross_entity += 1;
                    }
                }
                if *code == "FA-REF-005" {
                    assert!(r.message.contains("US, UK, DE"), "{r}");
                }
            }
            _ => assert_eq!(
                format!("kernel {kernel:?}"),
                format!("oracle {model:?}"),
                "step {step}: disagreement on {intent:?}"
            ),
        }
        let projections = verify_projections(&k.db, &k.book, None).unwrap();
        assert!(
            projections.is_green(),
            "step {step}: dimension projections: {projections:?}"
        );
        // The per-entity register agrees with the literal fold.
        if step % 40 == 0 {
            let (kernel_fold, digest) = kernel_entity_fold(&k, &march, None);
            assert_eq!(
                kernel_fold,
                oracle_entity_fold(&oracle, &march),
                "step {step}"
            );
            // Refolding is byte-identical.
            assert_eq!(kernel_entity_fold(&k, &march, None).1, digest);
            // A balance assertion on one entity's cash binds this fold.
            let cell = EntityCellKey {
                account: account_vid(k.book.book_id, "1000"),
                unit_id: usd.0,
                period: march.clone(),
                entity: Some(e1.to_string()),
            };
            let claim = register_equals(&k.db, &k.book, &cell, None).unwrap();
            assert_eq!(claim.fold_digest, digest);
            claims.push((claim.clone(), claim.amount.mantissa));
        }
    }
    // Every claim still holds at its own sequence; the head moved under
    // most of them (drift is a head-following comparison, never a change to
    // the claim).
    for (claim, amount) in &claims {
        assert!(check_register_equals(&k.db, &k.book, claim).unwrap());
        claims_checked += 1;
        let now = register_equals(&k.db, &k.book, &claim.cell_key, None).unwrap();
        if now.amount.mantissa != *amount || now.fold_digest != claim.fold_digest {
            drifted += 1;
        }
        // A tampered claim does not check.
        let mut forged = claim.clone();
        forged.amount = Amount::new(usd, amount + 1);
        assert!(!check_register_equals(&k.db, &k.book, &forged).unwrap());
    }
    let verified = verify_entities(&k.db, &k.book, &march, None).unwrap();
    assert!(verified.is_green(), "{verified:?}");
    assert!(verified.entries_checked >= 150);
    assert!(
        verify_availability(&k.db, &k.book, None)
            .unwrap()
            .is_green()
    );

    // Not vacuous.
    assert!(posted >= 150, "posted {posted}");
    assert!(intercompany >= 20, "intercompany {intercompany}");
    assert!(balancing_ok >= 3, "within-entity balancing {balancing_ok}");
    assert!(cross_entity >= 3, "cross-entity imbalances {cross_entity}");
    assert!(
        cross_balancing >= 3,
        "cross-entity balancing {cross_balancing}"
    );
    assert!(
        claims_checked >= 10 && drifted >= 3,
        "claims {claims_checked}/{drifted}"
    );
    for must in ["FA-REF-104", "FA-REF-005"] {
        assert!(
            refused.get(must).is_some_and(|n| *n >= 3),
            "refusal {must} under-exercised: {refused:?}"
        );
    }
}

/// A balancing post on the kernel without unwrapping its refusal.
fn kernel_post_balancing_raw(
    k: &mut Kernel,
    intent: &Intent,
    usd: UnitId,
    refs: &[EntryRef],
    leg: u16,
) -> Result<(Posted, Option<i128>), Refusal> {
    kernel_post_balancing(k, intent, usd, refs, leg).map(|b| (b.posted, Some(b.moved)))
}

/// A book declaring exactly one entity: a leg may omit it (it is that
/// entity), naming it is the same cell, and naming another is refused. A
/// book declaring none keeps its genesis bytes.
#[test]
fn one_entity_books_and_entityless_books_keep_the_per_unit_law() {
    let (mut k, mut oracle, periods, _) = setup_entities(ENTITY_CHART, &["SOLO"]);
    let usd = k.book.units.lookup("USD").unwrap();
    open_period(&mut k, &mut oracle, &periods[2], 1);
    let date = DateDay::from_ymd(2026, 3, 9).unwrap();
    let leg = |side, account: &str, entity: Option<&str>, m| Leg {
        side,
        account: account.into(),
        unit: usd.0,
        entity: entity.map(str::to_string),
        mantissa: m,
    };
    let dr = fa_reference::Side::Debit;
    let cr = fa_reference::Side::Credit;
    let intent = |legs, key: &str| Intent {
        class: "Original".into(),
        date,
        discriminator: None,
        legs,
        key: key.as_bytes().to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    };
    let mut refs = Vec::new();
    for (key, legs) in [
        (
            "omitted",
            vec![leg(dr, "1000", None, 70), leg(cr, "3000", None, 70)],
        ),
        (
            "named",
            vec![
                leg(dr, "6000", Some("SOLO"), 20),
                leg(cr, "1000", Some("SOLO"), 20),
            ],
        ),
        (
            "mixed",
            vec![leg(dr, "6000", Some("SOLO"), 5), leg(cr, "1000", None, 5)],
        ),
    ] {
        let i = intent(legs, key);
        refs.push(kernel_post(&mut k, &i, usd, &refs).expect(key).entry_ref());
        assert!(matches!(oracle.post(&i), Verdict::Posted { .. }), "{key}");
    }
    let other = intent(
        vec![
            leg(dr, "6000", Some("OTHER"), 1),
            leg(cr, "1000", Some("OTHER"), 1),
        ],
        "other",
    );
    let r = kernel_post(&mut k, &other, usd, &refs).expect_err("undeclared");
    assert_eq!(oracle.post(&other), Verdict::Refused { code: "FA-REF-104" });
    assert_eq!((r.code, r.exit), ("FA-REF-104", exit::REFUSAL), "{r}");
    assert!(r.message.contains("SOLO"), "{r}");
    // Every leg belongs to SOLO: one cash cell, 70 − 20 − 5.
    let (fold, _) = kernel_entity_fold(&k, &periods[2], None);
    assert_eq!(fold, oracle_entity_fold(&oracle, &periods[2]));
    assert_eq!(
        fold.get(&("1000".to_string(), usd.0, Some("SOLO".to_string()))),
        Some(&(70, 25, 3))
    );
    assert!(
        verify_entities(&k.db, &k.book, &periods[2], None)
            .unwrap()
            .is_green()
    );
    // The declaration is journaled: a LegalEntity, the legal-entity
    // dimension, and its value bound by REPRESENTS.
    let book_id = k.book.book_id;
    let entity =
        k.db.vertex(legal_entity_vid(book_id, "SOLO"))
            .unwrap()
            .expect("entity");
    assert!(
        entity
            .labels
            .contains(&fa_model::symbols::label::LEGAL_ENTITY)
    );
    let dim =
        k.db.vertex(dimension_vid(
            book_id,
            fa_model::LEGAL_ENTITY_DIMENSION_CODE,
        ))
        .unwrap()
        .expect("dimension");
    assert!(dim.labels.contains(&fa_model::symbols::label::DIMENSION));
    let value = entity_value_vid(book_id, "SOLO");
    assert!(
        k.db.vertex(value)
            .unwrap()
            .expect("value")
            .labels
            .contains(&fa_model::symbols::label::DIMENSION_VALUE)
    );
    assert_eq!(
        k.db.in_neighbours(value, fa_model::symbols::relation::REPRESENTS)
            .unwrap(),
        vec![legal_entity_vid(book_id, "SOLO")]
    );

    // A book declaring none: its genesis bytes have no entity trailer (the
    // pre-fa-bvx bytes), and its entity cells carry no entity.
    let (k0, oracle0, periods0, _) = setup_store(ENTITY_CHART);
    let spec = fa_journal::genesis::read_book_spec(&k0.db)
        .unwrap()
        .expect("spec");
    assert!(spec.entities.is_empty());
    let none = BookSpec {
        time_zone_policy: None,
        ..spec.clone()
    };
    let utc_only = spec.canonical_bytes().unwrap();
    assert_eq!(utc_only.len(), none.canonical_bytes().unwrap().len() + 1);
    let (fold0, _) = kernel_entity_fold(&k0, &periods0[2], None);
    assert!(fold0.is_empty() && oracle_entity_fold(&oracle0, &periods0[2]).is_empty());
}

/// Plan §5.4 with §5.2: a two-phase sub-vector satisfies each native
/// `(unit, legal_entity)` equality. From an intercompany hold, posting the
/// expense of one entity against the cash of the other balances per unit but
/// not per entity and is refused by both engines; the per-entity sub-vector
/// posts, and the hold's full original legs release in every entity.
#[test]
fn two_phase_sub_vectors_balance_per_entity() {
    let (mut k, mut oracle, periods, _) = setup_entities(ENTITY_CHART, ENTITIES);
    let usd = k.book.units.lookup("USD").unwrap();
    open_period(&mut k, &mut oracle, &periods[2], 1);
    let date = DateDay::from_ymd(2026, 3, 12).unwrap();
    let leg = |side, account: &str, entity: &str, m| Leg {
        side,
        account: account.into(),
        unit: usd.0,
        entity: Some(entity.to_string()),
        mantissa: m,
    };
    let dr = fa_reference::Side::Debit;
    let cr = fa_reference::Side::Credit;
    let intent = |class: &str, legs, key: &str, resolves| Intent {
        class: class.into(),
        date,
        discriminator: None,
        legs,
        key: key.as_bytes().to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves,
        settles: Vec::new(),
    };
    let mut refs = Vec::new();
    let fund = intent(
        "Original",
        vec![leg(dr, "1000", "US", 1_000), leg(cr, "3000", "US", 1_000)],
        "fund",
        None,
    );
    refs.push(
        kernel_post(&mut k, &fund, usd, &refs)
            .expect("funds")
            .entry_ref(),
    );
    assert!(matches!(oracle.post(&fund), Verdict::Posted { .. }));
    // US holds cash to pay UK's expense: each entity balanced on its own.
    let hold = intent(
        "Pending",
        vec![
            leg(dr, "6000", "UK", 300),
            leg(cr, "2500", "UK", 300),
            leg(dr, "1500", "US", 300),
            leg(cr, "1000", "US", 300),
        ],
        "hold",
        None,
    );
    refs.push(
        kernel_post(&mut k, &hold, usd, &refs)
            .expect("hold")
            .entry_ref(),
    );
    assert!(matches!(
        oracle.post(&hold),
        Verdict::Posted { index: 1, .. }
    ));
    let posts = |legs, ordinals: Vec<u16>, key: &str| {
        intent(
            "Resolution",
            legs,
            key,
            Some(Resolve {
                target: 1,
                posts: Some(ordinals),
            }),
        )
    };
    // UK's expense against US's cash: balanced per unit, not per entity.
    let crossed = posts(
        vec![leg(dr, "6000", "UK", 100), leg(cr, "1000", "US", 100)],
        vec![0, 3],
        "crossed",
    );
    let r = kernel_post(&mut k, &crossed, usd, &refs).expect_err("cross-entity");
    assert_eq!(
        oracle.post(&crossed),
        Verdict::Refused { code: "FA-REF-001" }
    );
    assert_eq!(r.code, "FA-REF-001", "{r}");
    assert!(
        r.message.contains("`UK`") && r.message.contains("`US`"),
        "{r}"
    );
    // The per-entity sub-vector posts 100 of 300 in every entity.
    let good = posts(
        vec![
            leg(dr, "6000", "UK", 100),
            leg(cr, "2500", "UK", 100),
            leg(dr, "1500", "US", 100),
            leg(cr, "1000", "US", 100),
        ],
        vec![0, 1, 2, 3],
        "good",
    );
    refs.push(
        kernel_post(&mut k, &good, usd, &refs)
            .expect("per-entity")
            .entry_ref(),
    );
    assert!(matches!(
        oracle.post(&good),
        Verdict::Posted { index: 2, .. }
    ));
    let (fold, _) = kernel_entity_fold(&k, &periods[2], None);
    assert_eq!(fold, oracle_entity_fold(&oracle, &periods[2]));
    assert_eq!(
        fold.get(&("1000".to_string(), usd.0, Some("US".to_string()))),
        Some(&(1_000, 100, 2))
    );
    let pending = fold_period_by_entity(&k.db, &k.book, &periods[2], None).unwrap();
    assert!(pending.pending.is_empty(), "the hold released in full");
    assert!(
        verify_entities(&k.db, &k.book, &periods[2], None)
            .unwrap()
            .is_green()
    );
}

/// The authority a step of the period-authority walk acts under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Variant {
    /// `close` and `reopen`, no caveats.
    Sound,
    /// Sound, with caveats that admit: this book (and another) and an
    /// expiry bound after the admission point.
    Scoped,
    /// Holds only the op the transition does not need.
    WithoutOp,
    /// A `books` caveat naming only another book.
    WrongBook,
    /// Expires at the admission point.
    Expired,
    /// A fresh token, journaled as revoked before it is used.
    Revoked,
    /// Another principal's token.
    NotHolder,
}

/// The approvals a step cites (only for a transition legal from the
/// period's state, so there is a proposal to approve).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Unapproved,
    /// A second Human under the current epoch.
    Fresh,
    /// The preparer approves its own proposal.
    SelfApproved,
    /// A second Human, then a policy activation supersedes the epoch.
    Stale,
}

struct Seen {
    variant: Variant,
    mode: Mode,
    t: PeriodTransition,
    from: PeriodState,
    outcome: String,
}

/// Period authority (fa-llx; plan §14.2, Appendix C PeriodControl): a seeded
/// walk of transitions under varied capabilities and approvals, applied to
/// the kernel and to the oracle's literal authority model. Every step must
/// agree on the outcome and the refusal code. The capability defects are
/// planted three times each at the start (admission precedes any read, so
/// they do not depend on state); a script then takes January..March through
/// every approval defect and every positive; then the walk is random over
/// April..December. Every negative and every positive is floored: coverage
/// by construction, not by seed luck.
#[test]
fn kernel_and_oracle_agree_on_period_authority() {
    let (mut k, mut oracle, periods) = setup();
    let book = u128::from_le_bytes(k.book.book_id.0);
    let elsewhere = Id128([0xee; 16]);
    let other_book = u128::from_le_bytes(elsewhere.0);
    let reopen = PeriodTransition::Reopen {
        to: PeriodState::Open,
    };
    let any = [
        PeriodTransition::Open,
        PeriodTransition::SoftClose,
        PeriodTransition::Close,
        PeriodTransition::Lock,
        reopen,
    ];
    let planted = [
        (Variant::WithoutOp, PeriodTransition::Close),
        (Variant::WithoutOp, reopen),
        (Variant::WrongBook, PeriodTransition::Open),
        (Variant::Expired, PeriodTransition::SoftClose),
        (Variant::Revoked, PeriodTransition::Close),
        (Variant::NotHolder, PeriodTransition::Lock),
    ];
    // Scripted on January..March, three times over: every approval defect
    // and every positive, in the order the period law reaches them.
    let script: Vec<(usize, PeriodTransition, Variant, Mode)> = (0..3)
        .flat_map(|p| {
            [
                (p, PeriodTransition::Open, Variant::Sound, Mode::Unapproved),
                (
                    p,
                    PeriodTransition::SoftClose,
                    Variant::Sound,
                    Mode::Unapproved,
                ),
                (p, reopen, Variant::Sound, Mode::Unapproved),
                (p, reopen, Variant::Sound, Mode::SelfApproved),
                (p, reopen, Variant::Sound, Mode::Stale),
                (p, reopen, Variant::Sound, Mode::Fresh),
                (
                    p,
                    PeriodTransition::Close,
                    Variant::Scoped,
                    Mode::Unapproved,
                ),
                (p, reopen, Variant::Sound, Mode::Fresh),
                (p, PeriodTransition::Lock, Variant::Sound, Mode::Unapproved),
                (p, PeriodTransition::Lock, Variant::Sound, Mode::Fresh),
                (p, PeriodTransition::Close, Variant::Sound, Mode::Unapproved),
                (p, reopen, Variant::Sound, Mode::Fresh),
            ]
        })
        .collect();
    let mut rng = Rng(0xC105_ED0F_FA11_5EED);
    let mut seen: Vec<Seen> = Vec::new();
    for step in 0..480u64 {
        let i = step as usize;
        let phase1 = 3 * planted.len();
        let (code, variant, t, scripted) = if i < phase1 {
            let (variant, t) = planted[i % planted.len()];
            let code = periods[rng.below(periods.len() as u64) as usize].clone();
            (code, variant, t, None)
        } else if i < phase1 + script.len() {
            let (p, t, variant, mode) = script[i - phase1];
            (periods[p].clone(), variant, t, Some(mode))
        } else {
            // Random on April..December, biased toward the period's next
            // natural transition.
            let code = periods[3 + rng.below(periods.len() as u64 - 3) as usize].clone();
            let natural = match oracle.period_state(&code).expect("created period") {
                PeriodState::Future => PeriodTransition::Open,
                PeriodState::Open if rng.chance(50) => PeriodTransition::SoftClose,
                PeriodState::Open => PeriodTransition::Close,
                PeriodState::SoftClosed if rng.chance(40) => reopen,
                PeriodState::SoftClosed => PeriodTransition::Close,
                PeriodState::Closed if rng.chance(70) => PeriodTransition::Lock,
                PeriodState::Closed | PeriodState::Locked => reopen,
            };
            let t = if rng.chance(75) {
                natural
            } else {
                any[rng.below(any.len() as u64) as usize]
            };
            let variant = match rng.below(20) {
                0 => Variant::WithoutOp,
                1 => Variant::WrongBook,
                2 => Variant::Expired,
                3 => Variant::Revoked,
                4 => Variant::NotHolder,
                5..=7 => Variant::Scoped,
                _ => Variant::Sound,
            };
            (code, variant, t, None)
        };
        let from = oracle.period_state(&code).expect("created period");
        let dual = matches!(t, PeriodTransition::Lock | PeriodTransition::Reopen { .. });
        let legal = fa_time::period::transition(from, t).ok();
        let mode = match (scripted, legal) {
            (Some(mode), _) => mode,
            (None, None) => Mode::Unapproved,
            (None, Some(_)) if !dual => {
                if rng.chance(5) {
                    Mode::Stale
                } else if rng.chance(10) {
                    Mode::Fresh
                } else {
                    Mode::Unapproved
                }
            }
            (None, Some(_)) => match rng.below(10) {
                0 => Mode::Unapproved,
                1 => Mode::SelfApproved,
                2 => Mode::Stale,
                _ => Mode::Fresh,
            },
        };

        // Approvals first (they commit), so the admission point is read last.
        let mut approvals = Vec::new();
        let mut recorded = Vec::new();
        if let Some(to) = legal {
            let digest = period_digest(&k, &code, from, to, step);
            let approver = |p: u128| fa_reference::sod::Approval {
                principal: p,
                profile: "Human".into(),
                op: "approve".into(),
            };
            match mode {
                Mode::Unapproved => {}
                Mode::Fresh | Mode::Stale => {
                    approvals.push(kernel_approve(&mut k, digest));
                    recorded.push(fa_reference::Recorded {
                        approval: approver(70),
                        epoch: oracle.epoch(),
                    });
                    if mode == Mode::Stale {
                        kernel_activate(&mut k, step);
                        oracle.activate_policy();
                    }
                }
                Mode::SelfApproved => {
                    approvals.push(kernel_approve_as(
                        &mut k,
                        Capability::embedded(PRINCIPAL, &["approve"]).expect("approve"),
                        digest,
                    ));
                    recorded.push(fa_reference::Recorded {
                        approval: approver(PRINCIPAL.0),
                        epoch: oracle.epoch(),
                    });
                }
            }
        }
        let both = Capability::embedded(PRINCIPAL, &["close", "reopen"]).expect("ops");
        let mut authority = fa_reference::Authority {
            token: 0,
            holder: PRINCIPAL.0,
            profile: "Human".into(),
            ops: vec!["close".into(), "reopen".into()],
            books: None,
            expires_at: None,
        };
        let revoked_bound = u64::MAX - step;
        let capability = match variant {
            Variant::Revoked => {
                let doomed = both.expiring_at(CommitSeq(revoked_bound));
                kernel_revoke(&mut k, &doomed, step);
                oracle.revoke(step + 1);
                authority.token = step + 1;
                authority.expires_at = Some(revoked_bound);
                doomed
            }
            _ => both,
        };
        let at = k.db.frontier().expect("frontier");
        let capability = match variant {
            Variant::Sound | Variant::Revoked => capability,
            Variant::Scoped => {
                authority.books = Some(vec![book, other_book]);
                authority.expires_at = Some(at.0 + 1);
                capability
                    .for_books(&[k.book.book_id, elsewhere])
                    .expect("books")
                    .expiring_at(CommitSeq(at.0 + 1))
            }
            Variant::WithoutOp => {
                let other = if matches!(t, PeriodTransition::Reopen { .. }) {
                    "close"
                } else {
                    "reopen"
                };
                authority.ops = vec![other.into()];
                Capability::embedded(PRINCIPAL, &[other]).expect("op")
            }
            Variant::WrongBook => {
                authority.books = Some(vec![other_book]);
                capability.for_books(&[elsewhere]).expect("books")
            }
            Variant::Expired => {
                authority.expires_at = Some(at.0);
                capability.expiring_at(at)
            }
            Variant::NotHolder => {
                authority.holder = 8;
                Capability::embedded(VId(8), &["close", "reopen"]).expect("ops")
            }
        };

        let kernel = kernel_transition_under(&mut k, &code, t, step, 1, &capability, &approvals);
        let model =
            oracle.transition_under(&code, t, PRINCIPAL.0, &authority, book, at.0, &recorded);
        assert_eq!(
            kernel.is_ok(),
            model.is_ok(),
            "step {step}: {code} {t:?} from {from:?} {variant:?} {mode:?}: kernel {kernel:?} oracle {model:?}"
        );
        let outcome = match (&kernel, &model) {
            (Ok(tr), Ok(m)) => {
                assert_eq!((tr.from, tr.to), *m, "step {step}: {code} {t:?}");
                "ok".to_string()
            }
            (Err(r), Err(c)) => {
                assert_eq!(
                    r.code, *c,
                    "step {step}: {code} {t:?} from {from:?} {variant:?} {mode:?}: {}",
                    r.message
                );
                r.code.to_string()
            }
            _ => String::new(),
        };
        seen.push(Seen {
            variant,
            mode,
            t,
            from,
            outcome,
        });
    }

    let n = |f: &dyn Fn(&Seen) -> bool| seen.iter().filter(|s| f(s)).count();
    let is_reopen = |t: PeriodTransition| matches!(t, PeriodTransition::Reopen { .. });
    let floors = [
        (
            "open",
            n(&|s| s.outcome == "ok" && s.t == PeriodTransition::Open),
        ),
        (
            "soft-close",
            n(&|s| s.outcome == "ok" && s.t == PeriodTransition::SoftClose),
        ),
        (
            "close",
            n(&|s| s.outcome == "ok" && s.t == PeriodTransition::Close),
        ),
        (
            "lock (approved)",
            n(&|s| s.outcome == "ok" && s.t == PeriodTransition::Lock),
        ),
        (
            "reopen soft-closed (approved)",
            n(&|s| s.outcome == "ok" && is_reopen(s.t)),
        ),
        (
            "admitting caveats",
            n(&|s| s.outcome == "ok" && s.variant == Variant::Scoped),
        ),
        (
            "close without close",
            n(
                &|s| {
                    s.outcome == "FA-REF-011" && s.variant == Variant::WithoutOp && !is_reopen(s.t)
                },
            ),
        ),
        (
            "reopen without reopen",
            n(&|s| s.outcome == "FA-REF-011" && s.variant == Variant::WithoutOp && is_reopen(s.t)),
        ),
        (
            "wrong book",
            n(&|s| s.outcome == "FA-REF-011" && s.variant == Variant::WrongBook),
        ),
        (
            "not the holder",
            n(&|s| s.outcome == "FA-REF-011" && s.variant == Variant::NotHolder),
        ),
        (
            "expired",
            n(&|s| s.outcome == "FA-REF-014" && s.variant == Variant::Expired),
        ),
        (
            "revoked",
            n(&|s| s.outcome == "FA-REF-023" && s.variant == Variant::Revoked),
        ),
        (
            "stale approval",
            n(&|s| s.outcome == "FA-REF-022" && s.mode == Mode::Stale),
        ),
        (
            "dual control without an approver",
            n(&|s| s.outcome == "FA-REF-012" && s.mode == Mode::Unapproved),
        ),
        (
            "self-approval",
            n(&|s| {
                s.outcome == "FA-REF-008"
                    && s.mode == Mode::SelfApproved
                    && !case_bound(s.t, s.from)
            }),
        ),
        (
            "case-bound reopen",
            n(&|s| s.outcome == "FA-REF-008" && case_bound(s.t, s.from)),
        ),
        ("illegal transition", n(&|s| s.outcome == "FA-REF-040")),
    ];
    for (name, count) in floors {
        assert!(
            count >= 3,
            "floor `{name}`: {count} of {} steps",
            seen.len()
        );
    }
    assert_eq!(
        security_policy_epoch(&k.db).expect("epoch"),
        oracle.epoch(),
        "both engines saw the same activations"
    );
}

/// Closed/Locked -> Reopen: `W(reopen, 2, case)`, refused until restatement
/// cases land (fa-oz3).
fn case_bound(t: PeriodTransition, from: PeriodState) -> bool {
    matches!(t, PeriodTransition::Reopen { .. })
        && matches!(from, PeriodState::Closed | PeriodState::Locked)
}

#[test]
fn a_reversal_chain_cannot_strand_payments_on_a_revived_invoice() {
    let (mut k, mut oracle, periods) = setup();
    open_period(&mut k, &mut oracle, &periods[0], 1);
    let usd = k.book.units.lookup("USD").unwrap();
    let jan = DateDay::from_ymd(2026, 1, 15).unwrap();
    let leg = |side, account: &str, mantissa| Leg {
        side,
        account: account.into(),
        unit: usd.0,
        entity: None,
        mantissa,
    };
    let mut refs: Vec<EntryRef> = Vec::new();
    let mut post_both = |intent: &Intent| {
        let kernel = kernel_post(&mut k, intent, usd, &refs);
        if let Ok(Posted::Committed { entry_ref, .. }) = &kernel {
            refs.push(*entry_ref);
        }
        let model = oracle.post(intent);
        let check = verify_open_items(&k.db, &k.book, None).unwrap();
        assert!(
            check.is_green(),
            "open items drifted after {intent:?}: {check:?}"
        );
        (kernel, model)
    };

    // 0: Invoice I (1200 Dr 100 / 4000 Cr 100)
    let inv = Intent {
        class: "Original".into(),
        date: jan,
        discriminator: None,
        legs: vec![
            leg(fa_reference::Side::Debit, "1200", 100),
            leg(fa_reference::Side::Credit, "4000", 100),
        ],
        key: b"inv-chain-0".to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    };
    let (Ok(Posted::Committed { .. }), Verdict::Posted { index: 0, .. }) = post_both(&inv) else {
        panic!("invoice must post");
    };

    // 1: R1 reverses I
    let r1 = Intent {
        class: "Reversal".into(),
        date: jan,
        discriminator: None,
        legs: vec![
            leg(fa_reference::Side::Credit, "1200", 100),
            leg(fa_reference::Side::Debit, "4000", 100),
        ],
        key: b"rev-1".to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: Some(0),
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    };
    let (Ok(Posted::Committed { .. }), Verdict::Posted { index: 1, .. }) = post_both(&r1) else {
        panic!("R1 must post");
    };

    // 2: R2 reverses R1 (revives I)
    let r2 = Intent {
        class: "Reversal".into(),
        date: jan,
        discriminator: None,
        legs: vec![
            leg(fa_reference::Side::Debit, "1200", 100),
            leg(fa_reference::Side::Credit, "4000", 100),
        ],
        key: b"rev-2".to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: Some(1),
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    };
    let (Ok(Posted::Committed { .. }), Verdict::Posted { index: 2, .. }) = post_both(&r2) else {
        panic!("R2 must post");
    };

    // 3: Receipt S settles 40 against revived I (index 0, leg 0)
    let rcpt = Intent {
        class: "Original".into(),
        date: jan,
        discriminator: None,
        legs: vec![
            leg(fa_reference::Side::Debit, "1000", 40),
            leg(fa_reference::Side::Credit, "1200", 40),
        ],
        key: b"rcpt-s".to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles: vec![Settle {
            leg: 1,
            target: 0,
            ordinal: 0,
            mantissa: 40,
        }],
    };
    let (Ok(Posted::Committed { .. }), Verdict::Posted { index: 3, .. }) = post_both(&rcpt) else {
        panic!("receipt S must post against revived invoice");
    };

    // R3 reversing R2 while S is live on I must be refused with FA-REF-073 by both!
    let r3 = Intent {
        class: "Reversal".into(),
        date: jan,
        discriminator: None,
        legs: vec![
            leg(fa_reference::Side::Credit, "1200", 100),
            leg(fa_reference::Side::Debit, "4000", 100),
        ],
        key: b"rev-3".to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: Some(2),
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    };
    let (Err(refusal), Verdict::Refused { code }) = post_both(&r3) else {
        panic!("R3 must be refused while S is applied to I");
    };
    assert_eq!(refusal.code, "FA-REF-073");
    assert_eq!(code, "FA-REF-073");

    // 4: Reverse S first, undoing the application on I
    let rev_s = Intent {
        class: "Reversal".into(),
        date: jan,
        discriminator: None,
        legs: vec![
            leg(fa_reference::Side::Credit, "1000", 40),
            leg(fa_reference::Side::Debit, "1200", 40),
        ],
        key: b"rev-s".to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: Some(3),
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    };
    let (Ok(Posted::Committed { .. }), Verdict::Posted { index: 4, .. }) = post_both(&rev_s) else {
        panic!("reversal of receipt S must post");
    };

    // 5: Now R3 reversing R2 succeeds and leaves open items green!
    let (Ok(Posted::Committed { .. }), Verdict::Posted { index: 5, .. }) = post_both(&r3) else {
        panic!("R3 must post once S is reversed");
    };
    assert!(
        open_items(&k.db, &k.book, None, None).unwrap().is_empty(),
        "reversed invoice has no open item"
    );
    assert!(oracle.open_items().is_empty());
}

/// Four-way exhaustive Appendix C admissibility cross-check (`fa-nfq`):
/// 1. `PlanAdmissibility::parse(PLAN_MARKDOWN)` (plan Appendix C Markdown table + prose)
/// 2. `Admissibility::load()` (`registries/admissibility.toml`)
/// 3. `fa_reference::admissibility::decide_cell` (hand-transcribed independent oracle)
/// 4. `fa_journal::decide_admissibility_cell` (kernel four-stage period-law gate)
///
/// Sweeps all `15 posting classes × 5 period states × 3 disposition families × 5 period kinds × 2 pre_opening = 1,125`
/// cells plus all `(class, state)` cell qualifiers, and proves that a single-cell mutation in either
/// `admissibility.toml` or the plan Appendix C Markdown is caught with a cell-naming discrepancy.
#[test]
fn admissibility_four_way_plan_toml_oracle_and_kernel_agree_on_every_cell_and_catch_flips() {
    use fa_journal::decide_admissibility_cell;
    use fa_registry::{
        ALL_KINDS, ALL_STATES, Admissibility, DispositionFamily, EntryClasses, PlanAdmissibility,
    };

    const PLAN_MD: &str =
        include_str!("../../../COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md");
    const ADMISSIBILITY_RAW: &str = include_str!("../../../registries/admissibility.toml");

    let classes = EntryClasses::embedded().expect("entry_classes.toml");
    let toml_matrix = Admissibility::embedded(&classes).expect("admissibility.toml");
    let plan_matrix = PlanAdmissibility::parse(PLAN_MD).expect("plan Appendix C markdown");

    let posting_classes: Vec<&str> = classes.posting().map(|c| c.name.as_str()).collect();
    assert_eq!(posting_classes.len(), 15, "15 posting classes");

    let mut checked_cells = 0usize;
    for &class in &posting_classes {
        for state in ALL_STATES {
            // Check qualifiers across plan, toml, and oracle
            let plan_qual = plan_matrix
                .qualifiers
                .get(&(class.to_string(), state))
                .map(String::as_str);
            let toml_qual = toml_matrix.qualifier_tag(class, state);
            let oracle_qual = fa_reference::admissibility::qualifier_tag(class, state);
            assert_eq!(
                plan_qual, toml_qual,
                "qualifier mismatch between plan and toml at ({class}, {state:?})"
            );
            assert_eq!(
                toml_qual, oracle_qual,
                "qualifier mismatch between toml and oracle at ({class}, {state:?})"
            );

            for family in DispositionFamily::ALL {
                for kind in ALL_KINDS {
                    for pre_opening in [false, true] {
                        let d_plan = plan_matrix
                            .decide_cell(class, state, family, kind, pre_opening)
                            .expect("plan decision");
                        let d_toml = toml_matrix
                            .decide_cell(class, state, family, kind, pre_opening)
                            .expect("toml decision");
                        let d_oracle = fa_reference::admissibility::decide_cell(
                            class,
                            state,
                            family,
                            kind,
                            pre_opening,
                        )
                        .expect("oracle decision");
                        let d_kernel = decide_admissibility_cell(
                            &toml_matrix,
                            class,
                            state,
                            family,
                            kind,
                            pre_opening,
                        )
                        .expect("kernel decision");

                        assert_eq!(
                            d_plan, d_toml,
                            "plan vs toml mismatch at ({class}, {state:?}, {family:?}, {kind:?}, pre_opening={pre_opening})"
                        );
                        assert_eq!(
                            d_toml, d_oracle,
                            "toml vs oracle mismatch at ({class}, {state:?}, {family:?}, {kind:?}, pre_opening={pre_opening})"
                        );
                        assert_eq!(
                            d_oracle, d_kernel,
                            "oracle vs kernel mismatch at ({class}, {state:?}, {family:?}, {kind:?}, pre_opening={pre_opening})"
                        );
                        checked_cells += 1;
                    }
                }
            }
        }
    }
    assert_eq!(checked_cells, 15 * 5 * 3 * 5 * 2);

    // Planted negative 1: flip a single cell in admissibility.toml (`Reversal` in `Closed` from `with:post_closed` to `admit`)
    // and verify the four-way comparison catches the exact `(Reversal, Closed)` cell discrepancy against both plan and oracle.
    let mutated_toml_str = ADMISSIBILITY_RAW.replacen(
        "class = \"Reversal\"\nstate = \"Closed\"\ndecision = \"with:post_closed\"",
        "class = \"Reversal\"\nstate = \"Closed\"\ndecision = \"admit\"",
        1,
    );
    assert_ne!(
        mutated_toml_str, ADMISSIBILITY_RAW,
        "planted toml flip applied"
    );
    let mutated_toml = Admissibility::parse(&classes, &mutated_toml_str)
        .expect("mutated admissibility.toml still satisfies structural rules");
    let mut caught_toml_vs_oracle = Vec::new();
    for &class in &posting_classes {
        for state in ALL_STATES {
            let d_mut = decide_admissibility_cell(
                &mutated_toml,
                class,
                state,
                DispositionFamily::Standard,
                fa_time::PeriodKind::Normal,
                false,
            )
            .unwrap();
            let d_ora = fa_reference::admissibility::decide_cell(
                class,
                state,
                DispositionFamily::Standard,
                fa_time::PeriodKind::Normal,
                false,
            )
            .unwrap();
            if d_mut != d_ora {
                caught_toml_vs_oracle.push((class, state));
            }
        }
    }
    assert_eq!(
        caught_toml_vs_oracle,
        vec![("Reversal", fa_time::PeriodState::Closed)],
        "oracle catches single-cell flip in admissibility.toml because oracle does not read admissibility.toml"
    );

    // Planted negative 2: flip a single cell in the plan Appendix C Markdown table and verify
    // the four-way check catches the exact cell discrepancy.
    let mutated_plan_str = PLAN_MD.replacen(
        "| `Reversal` | Refuse | Admit | Admit | W(`post_closed`) |",
        "| `Reversal` | Refuse | Admit | Admit | Refuse |",
        1,
    );
    assert_ne!(
        mutated_plan_str, PLAN_MD,
        "planted plan markdown flip applied"
    );
    let mutated_plan = PlanAdmissibility::parse(&mutated_plan_str).expect("mutated plan parses");
    let mut caught_plan_vs_toml = Vec::new();
    for &class in &posting_classes {
        for state in ALL_STATES {
            let d_p = mutated_plan
                .decide_cell(
                    class,
                    state,
                    DispositionFamily::Standard,
                    fa_time::PeriodKind::Normal,
                    false,
                )
                .unwrap();
            let d_t = toml_matrix
                .decide_cell(
                    class,
                    state,
                    DispositionFamily::Standard,
                    fa_time::PeriodKind::Normal,
                    false,
                )
                .unwrap();
            if d_p != d_t {
                caught_plan_vs_toml.push((class, state));
            }
        }
    }
    assert_eq!(
        caught_plan_vs_toml,
        vec![("Reversal", fa_time::PeriodState::Closed)],
        "plan parser catches single-cell flip in Appendix C markdown"
    );
}

#[test]
fn planted_u64_max_and_far_future_skew_ticks_do_not_brick_time_axis() {
    let (mut k, mut oracle, periods) = setup_with(BUDGETED);
    let usd = k.book.units.lookup("USD").unwrap();
    open_period(&mut k, &mut oracle, &periods[2], 1);
    let march = DateDay::from_ymd(2026, 3, 15).unwrap();
    let leg = |side: fa_reference::Side, account: &str, mantissa: i128| Leg {
        side,
        account: account.into(),
        unit: usd.0,
        entity: None,
        mantissa,
    };
    let dr = fa_reference::Side::Debit;
    let cr = fa_reference::Side::Credit;
    let intent = |class: &str, legs: Vec<Leg>, key: &str, resolves: Option<Resolve>| Intent {
        class: class.into(),
        date: march,
        discriminator: None,
        legs,
        key: key.as_bytes().to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves,
        settles: Vec::new(),
    };
    let mut refs: Vec<EntryRef> = Vec::new();
    let fund = intent(
        "Original",
        vec![leg(dr, "1000", 1_000), leg(cr, "3000", 1_000)],
        "fund",
        None,
    );
    refs.push(
        kernel_post(&mut k, &fund, usd, &refs)
            .expect("funds")
            .entry_ref(),
    );
    assert!(matches!(oracle.post(&fund), Verdict::Posted { .. }));

    // 1. Out-of-range ticks (u64::MAX, MAX_TICK_UTC_NS + 1) are refused with FA-REF-100.
    for (idx, bad) in [u64::MAX, fa_model::limits::MAX_TICK_UTC_NS + 1]
        .into_iter()
        .enumerate()
    {
        let r = kernel_tick(&mut k, bad, &format!("bad-tick-{idx}")).expect_err("out of range");
        assert_eq!((r.code, r.exit), ("FA-REF-100", exit::USAGE), "{r}");
        assert_eq!(oracle.record_tick(bad), Err("FA-REF-100"));
    }
    assert_eq!(latest_tick(&k.db).unwrap(), None);

    // 2. Honest baseline tick at 1_000 and timed hold A (timeout 20 -> deadline 1_020).
    let t0 = kernel_tick(&mut k, 1_000, "t0").expect("t0");
    assert_eq!(oracle.record_tick(1_000), Ok(0));
    let hold_legs = vec![leg(dr, "6100", 100), leg(cr, "1000", 100)];
    let ha = intent("Pending", hold_legs.clone(), "hold-A", None);
    let posted_a = kernel_post_timed(&mut k, &ha, usd, &refs, 20).expect("hold A");
    assert!(matches!(oracle.post_timed(&ha, 20), Verdict::Posted { .. }));
    refs.push(posted_a.entry_ref());
    let a = refs.len() - 1;

    // 3. Planted far-future tick exceeding MAX_CLOCK_SKEW_NS is downgraded to
    //    monotonic_ok = false even when the caller supplies monotonic_ok = true.
    let jumped_ns = 1_000 + fa_model::limits::MAX_CLOCK_SKEW_NS + 500;
    let jumped = kernel_tick(&mut k, jumped_ns, "t-jump").expect("jump recorded");
    assert_eq!(oracle.record_tick(jumped_ns), Ok(1));
    let (jump_entry, _) = fa_journal::post::read_entry(&k.db, jumped.entry_ref.vid)
        .unwrap()
        .expect("jump entry");
    assert_eq!(
        jump_entry.proposal.control,
        Some(fa_model::ControlPayload::TimeTick {
            observed_utc_ns: jumped_ns,
            source: 0,
            monotonic_ok: false,
        })
    );
    assert_eq!(
        fa_journal::sweep::latest_corroborated_tick(&k.db, None).unwrap(),
        Some(t0.tick)
    );

    // Sweeps refuse under the uncorroborated tick.
    let r = kernel_sweep(&mut k, 2).expect_err("uncorroborated sweep refused");
    assert_eq!(r.code, "FA-REF-144");
    assert_eq!(oracle.sweep_batch(2), Err("FA-REF-144"));

    // A timed hold posted after the uncorroborated jump still anchors on the
    // latest corroborated tick (1_000), and Posts on hold A (deadline 1_020)
    // is NOT falsely refused as HOLD_DUE.
    let hb = intent("Pending", hold_legs.clone(), "hold-B", None);
    let posted_b = kernel_post_timed(&mut k, &hb, usd, &refs, 20).expect("hold B");
    assert!(matches!(oracle.post_timed(&hb, 20), Verdict::Posted { .. }));
    refs.push(posted_b.entry_ref());
    let b = refs.len() - 1;
    let b_row = k.db.vertex(refs[b].vid).unwrap().unwrap();
    assert_eq!(
        fa_journal::sweep::deadline(&k.db, b_row.created_at, 20).unwrap(),
        1_020
    );
    assert_eq!(oracle.deadline(b), Some(1_020));

    let pa = intent(
        "Resolution",
        vec![leg(dr, "6100", 25), leg(cr, "1000", 25)],
        "posts-A-during-jump",
        Some(Resolve {
            target: a,
            posts: Some(vec![0, 1]),
        }),
    );
    refs.push(
        kernel_post(&mut k, &pa, usd, &refs)
            .expect("Posts on A still admissible before corroborated deadline")
            .entry_ref(),
    );
    assert!(matches!(oracle.post(&pa), Verdict::Posted { .. }));

    // 4. Subsequent honest tick at 1_020 (> 1_000, < jumped_ns) is admitted,
    //    restores corroboration, and sweeps hold B (deadline 1_020).
    let t_honest = kernel_tick(&mut k, 1_020, "t-honest").expect("honest recovery tick");
    assert_eq!(oracle.record_tick(1_020), Ok(2));
    assert_eq!(latest_tick(&k.db).unwrap(), Some(t_honest.tick));
    assert_eq!(
        fa_journal::sweep::latest_corroborated_tick(&k.db, None).unwrap(),
        Some(t_honest.tick)
    );

    let swept = sweep_both(&mut k, &mut oracle, &mut refs, 2, 1).expect("sweep after recovery");
    assert_eq!(swept.tick, 1_020);
    assert_eq!(swept.expired.len(), 1);
    assert_eq!(swept.expired[0].0, b);

    // 5. Instant-based temporal query at 1_015 (between t0=1_000 and t_honest=1_020)
    //    is not poisoned by the superseded uncorroborated jump.
    let ctx = k.ctx();
    let sel = fa_journal::resolve_instant_at(&k.db, &ctx.query(), &k.book, 1_015, None)
        .unwrap()
        .expect("instant selector succeeds after honest recovery");
    assert_eq!(sel.lower_entry, t0.entry_ref.vid);
    assert_eq!(sel.upper_entry, Some(t_honest.entry_ref.vid));
}

#[test]
fn settlement_requires_matching_legal_entity_dimension() {
    let (mut k, mut oracle, periods, _) = setup_entities(ENTITY_CHART, ENTITIES);
    let usd = k.book.units.lookup("USD").unwrap();
    let march = periods[2].clone();
    open_period(&mut k, &mut oracle, &march, 1);
    let date = DateDay::from_ymd(2026, 3, 10).unwrap();
    let dr = fa_reference::Side::Debit;
    let cr = fa_reference::Side::Credit;
    let leg = |side: fa_reference::Side, account: &str, entity: Option<&str>, m: i128| Leg {
        side,
        account: account.into(),
        unit: usd.0,
        entity: entity.map(str::to_string),
        mantissa: m,
    };
    let plain = |legs: Vec<Leg>, key: &str, settles: Vec<Settle>| Intent {
        class: "Original".into(),
        date,
        discriminator: None,
        legs,
        key: key.as_bytes().to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles,
    };

    let mut refs = Vec::new();
    // 1. Invoice for US on receivable 1500: Dr 1500 (US) 1_000 / Cr 4000 (US) 1_000.
    let inv_us = plain(
        vec![
            leg(dr, "1500", Some("US"), 1_000),
            leg(cr, "4000", Some("US"), 1_000),
        ],
        "inv-us",
        Vec::new(),
    );
    refs.push(
        kernel_post(&mut k, &inv_us, usd, &refs)
            .expect("invoice US")
            .entry_ref(),
    );
    assert!(matches!(oracle.post(&inv_us), Verdict::Posted { .. }));

    // 2. Invoice for UK on receivable 1500: Dr 1500 (UK) 800 / Cr 4000 (UK) 800.
    let inv_uk = plain(
        vec![
            leg(dr, "1500", Some("UK"), 800),
            leg(cr, "4000", Some("UK"), 800),
        ],
        "inv-uk",
        Vec::new(),
    );
    refs.push(
        kernel_post(&mut k, &inv_uk, usd, &refs)
            .expect("invoice UK")
            .entry_ref(),
    );
    assert!(matches!(oracle.post(&inv_uk), Verdict::Posted { .. }));

    // 3. Cross-entity settlement: UK receipt attempting to settle US's open item on 1500.
    //    Balanced within UK, opposite side on 1500, same unit, but entity UK != US.
    let cross_settle = plain(
        vec![
            leg(dr, "1000", Some("UK"), 400),
            leg(cr, "1500", Some("UK"), 400),
        ],
        "cross-settle-uk-on-us",
        vec![Settle {
            leg: 1,
            target: 0,
            ordinal: 0,
            mantissa: 400,
        }],
    );
    let r = kernel_post(&mut k, &cross_settle, usd, &refs)
        .expect_err("cross-entity settlement must be refused");
    assert_eq!(
        oracle.post(&cross_settle),
        Verdict::Refused { code: "FA-REF-071" }
    );
    assert_eq!((r.code, r.exit), ("FA-REF-071", exit::REFUSAL), "{r}");
    assert!(
        r.message.contains("`UK`") && r.message.contains("`US`"),
        "refusal must name both legal entities: {r}"
    );

    // 4. Same-entity settlement: US receipt settling 400 of US's invoice, and UK receipt settling 300 of UK's.
    let same_us = plain(
        vec![
            leg(dr, "1000", Some("US"), 400),
            leg(cr, "1500", Some("US"), 400),
        ],
        "settle-us",
        vec![Settle {
            leg: 1,
            target: 0,
            ordinal: 0,
            mantissa: 400,
        }],
    );
    refs.push(
        kernel_post(&mut k, &same_us, usd, &refs)
            .expect("same-entity US settlement")
            .entry_ref(),
    );
    assert!(matches!(oracle.post(&same_us), Verdict::Posted { .. }));

    let same_uk = plain(
        vec![
            leg(dr, "1000", Some("UK"), 300),
            leg(cr, "1500", Some("UK"), 300),
        ],
        "settle-uk",
        vec![Settle {
            leg: 1,
            target: 1,
            ordinal: 0,
            mantissa: 300,
        }],
    );
    refs.push(
        kernel_post(&mut k, &same_uk, usd, &refs)
            .expect("same-entity UK settlement")
            .entry_ref(),
    );
    assert!(matches!(oracle.post(&same_uk), Verdict::Posted { .. }));

    // 5. Open items and per-entity fold agree between kernel and oracle.
    let kernel_items = open_items(&k.db, &k.book, None, None).unwrap();
    let model_items = oracle.open_items();
    assert_eq!(kernel_items.len(), model_items.len());
    for item in &kernel_items {
        let index = refs.iter().position(|r| r.vid == item.entry).unwrap();
        let (orig, app, app_out) = model_items[&(index, usize::from(item.ordinal))];
        assert_eq!(
            (item.original, item.applied, item.applied_out, item.open),
            (orig, app, app_out, orig - app_out - app)
        );
    }
    assert!(verify_open_items(&k.db, &k.book, None).unwrap().is_green());
    assert_eq!(
        kernel_entity_fold(&k, &march, None).0,
        oracle_entity_fold(&oracle, &march)
    );
}

/// The kernel's verdict on an atomic batch of oracle intents (fa-nl7).
/// `refs` maps oracle journal indices to kernel entries, and already holds
/// the predicted refs of earlier members a member may settle.
fn kernel_batch(
    k: &mut Kernel,
    key: &str,
    members: &[Intent],
    usd: UnitId,
    refs: &[EntryRef],
) -> Result<BatchPosted, Refusal> {
    let intents = members
        .iter()
        .map(|m| {
            let req = kernel_request(k, m, usd, refs);
            PostIntent::new(req.proposal, req.approvals).expect("typed intent")
        })
        .collect();
    let batch = PostBatch::new(key.as_bytes().to_vec(), intents).expect("batch shape");
    let capability = kernel_request(k, &members[0], usd, refs).capability;
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    k.runtime
        .block_on(async move { post_batch(db, &ctx, book, capability, batch).await })
        .expect("batch kernel")
}

/// The ref the kernel derives for an intent before it commits: the key's
/// identity and the sealed digest.
fn predicted_ref(k: &Kernel, intent: &Intent, usd: UnitId, refs: &[EntryRef]) -> EntryRef {
    let req = kernel_request(k, intent, usd, refs);
    let sealed = req.proposal.clone().seal(Vec::new(), None).expect("seal");
    EntryRef {
        vid: fa_model::entry_vid(k.book.book_id, &PRINCIPAL.0.to_le_bytes(), &intent.key),
        entry_digest: sealed.entry_digest,
    }
}

/// fa-nl7: atomic batches against the independent oracle's literal batch
/// model (clone the oracle, post every member, keep the clone only when all
/// post) over seeded histories. Planted: an unbalanced member, a member
/// whose key an earlier batch recorded, a forward settlement, a changed
/// retry under a recorded key; and lawful in-batch applications (a receipt
/// settling an invoice earlier in its own batch) and identical retries.
/// Every verdict agrees, a refused batch writes nothing, and every register
/// cell of every period agrees at the end.
#[test]
fn batches_are_atomic_and_agree_with_the_independent_oracle_across_seeds() {
    for seed in [3_u64, 0x51ed_270b, 0x9e37_79b9] {
        let (mut k, mut oracle, periods) = setup();
        open_period(&mut k, &mut oracle, "FY2026-P03", 0);
        open_period(&mut k, &mut oracle, "FY2026-P04", 1);
        let usd = k.book.units.lookup("USD").unwrap();
        let dates = [
            DateDay::parse("2026-03-10").unwrap(),
            DateDay::parse("2026-04-20").unwrap(),
        ];
        let leg = |side, account: &str, mantissa| Leg {
            side,
            account: account.into(),
            unit: usd.0,
            entity: None,
            mantissa,
        };
        let mut rng = Rng(seed);
        let mut refs: Vec<EntryRef> = Vec::new();
        let mut recorded: Vec<(String, Vec<Intent>)> = Vec::new();
        let mut used_keys: Vec<Vec<u8>> = Vec::new();
        let (mut committed, mut refused, mut retried, mut in_batch_applications) = (0, 0, 0, 0);
        for b in 0..24 {
            let key = format!("batch-{seed}-{b}");
            let n = 1 + rng.below(3) as usize;
            let mut members: Vec<Intent> = Vec::new();
            for m in 0..n {
                let amount = 1 + rng.below(50_000) as i128;
                let date = dates[rng.below(2) as usize];
                let member_key = format!("{key}-m{m}").into_bytes();
                let mut intent = maintenance_intent("Original", date, amount, "");
                intent.key = member_key;
                // An invoice, sometimes followed by its own application.
                if rng.chance(40) {
                    intent.legs = vec![
                        leg(fa_reference::Side::Debit, "1200", amount),
                        leg(fa_reference::Side::Credit, "4000", amount),
                    ];
                }
                members.push(intent);
            }
            // An in-batch application: the last member pays an earlier
            // invoice member, within its amount.
            if let Some(pos) = members
                .iter()
                .position(|i| i.legs[0].account == "1200")
                .filter(|_| rng.chance(70))
            {
                let invoice_amount = members[pos].legs[0].mantissa;
                let paid = 1 + rng.below(invoice_amount as u64) as i128;
                let mut receipt = maintenance_intent("Original", dates[1], paid, "");
                receipt.key = format!("{key}-rcpt").into_bytes();
                receipt.legs = vec![
                    leg(fa_reference::Side::Debit, "1000", paid),
                    leg(fa_reference::Side::Credit, "1200", paid),
                ];
                receipt.settles = vec![Settle {
                    leg: 1,
                    target: refs.len() + pos,
                    ordinal: 0,
                    mantissa: paid,
                }];
                members.push(receipt);
            }
            // Plants.
            match rng.below(10) {
                0 => {
                    let last = members.len() - 1;
                    members[last].legs[1].mantissa += 1;
                }
                1 if !used_keys.is_empty() => {
                    members[0].key = used_keys[rng.below(used_keys.len() as u64) as usize].clone();
                }
                2 => {
                    // A forward settlement: the first member pays a member
                    // that comes later in the batch.
                    let mut later = maintenance_intent("Original", dates[0], 900, "");
                    later.key = format!("{key}-later").into_bytes();
                    later.legs = vec![
                        leg(fa_reference::Side::Debit, "1200", 900),
                        leg(fa_reference::Side::Credit, "4000", 900),
                    ];
                    let mut early = maintenance_intent("Original", dates[0], 100, "");
                    early.key = format!("{key}-early").into_bytes();
                    early.legs = vec![
                        leg(fa_reference::Side::Debit, "1000", 100),
                        leg(fa_reference::Side::Credit, "1200", 100),
                    ];
                    early.settles = vec![Settle {
                        leg: 1,
                        target: refs.len() + 1,
                        ordinal: 0,
                        mantissa: 100,
                    }];
                    members = vec![early, later];
                }
                _ => {}
            }
            // Predicted refs for in-batch targets, in member order.
            let mut extended = refs.clone();
            for intent in &members {
                if intent.settles.iter().all(|s| s.target < extended.len()) {
                    let predicted = predicted_ref(&k, intent, usd, &extended);
                    extended.push(predicted);
                } else {
                    // A forward target: give the kernel a placeholder ref
                    // that names no entry, as an unstaged member would.
                    extended.push(EntryRef {
                        vid: VId(u128::from(rng.next())),
                        entry_digest: [0; 32],
                    });
                }
            }
            let head = k.db.frontier().unwrap();
            let expected = oracle.post_batch(key.as_bytes(), &members);
            let actual = kernel_batch(&mut k, &key, &members, usd, &extended);
            match (&expected, actual) {
                (fa_reference::BatchVerdict::Posted { indices }, Ok(posted)) => {
                    assert!(!posted.already_recorded, "seed {seed} batch {b}");
                    assert_eq!(indices.len(), posted.entries.len(), "seed {seed} batch {b}");
                    assert_eq!(indices[0], refs.len(), "seed {seed} batch {b}");
                    assert_eq!(posted.recorded_at.0, head.0 + 1, "one commit");
                    in_batch_applications +=
                        members.iter().filter(|m| !m.settles.is_empty()).count();
                    refs.extend(posted.entries.iter().copied());
                    used_keys.extend(members.iter().map(|m| m.key.clone()));
                    recorded.push((key.clone(), members.clone()));
                    committed += 1;
                }
                (fa_reference::BatchVerdict::Refused { member, code }, Err(r)) => {
                    assert_eq!(r.code, *code, "seed {seed} batch {b}: {r}");
                    if let Some(i) = member {
                        assert!(
                            r.message.starts_with(&format!("batch member {i}")),
                            "seed {seed} batch {b}: {r}"
                        );
                    }
                    assert_eq!(
                        k.db.frontier().unwrap(),
                        head,
                        "a refused batch wrote nothing"
                    );
                    refused += 1;
                }
                (expected, actual) => {
                    panic!("seed {seed} batch {b}: oracle {expected:?}, kernel {actual:?}")
                }
            }
            // Retries of a recorded batch: identical (the outcome) or changed
            // (a conflict).
            if !recorded.is_empty() && rng.chance(30) {
                let (rkey, rmembers) = recorded[rng.below(recorded.len() as u64) as usize].clone();
                let head = k.db.frontier().unwrap();
                let ov = oracle.post_batch(rkey.as_bytes(), &rmembers);
                let kv =
                    kernel_batch(&mut k, &rkey, &rmembers, usd, &refs).expect("identical retry");
                let fa_reference::BatchVerdict::Recorded { indices } = ov else {
                    panic!("seed {seed}: oracle retry {ov:?}");
                };
                assert!(kv.already_recorded);
                assert_eq!(
                    kv.entries,
                    indices.iter().map(|i| refs[*i]).collect::<Vec<_>>()
                );
                let changed = vec![rmembers[0].clone()];
                if changed != rmembers {
                    let ov = oracle.post_batch(rkey.as_bytes(), &changed);
                    let r = kernel_batch(&mut k, &rkey, &changed, usd, &refs).unwrap_err();
                    assert_eq!(
                        ov,
                        fa_reference::BatchVerdict::Refused {
                            member: None,
                            code: r.code
                        }
                    );
                }
                assert_eq!(k.db.frontier().unwrap(), head, "retries write nothing");
                retried += 1;
            }
        }
        eprintln!(
            "seed {seed}: committed {committed} refused {refused} retried {retried} in-batch applications {in_batch_applications}"
        );
        assert!(
            committed >= 8 && refused >= 2 && retried >= 2,
            "seed {seed}"
        );
        assert!(
            in_batch_applications >= 2,
            "seed {seed}: in-batch applications"
        );
        assert_eq!(oracle.journal_len(), refs.len());
        for code in &periods {
            let kernel_fold = fold_period(&k.db, &k.book, code).unwrap();
            let model_fold = oracle.fold(code);
            assert_eq!(
                kernel_fold.cells.len(),
                model_fold.len(),
                "{code}: cell count"
            );
            for cell in &kernel_fold.cells {
                let account_code = ACCOUNTS
                    .iter()
                    .map(|(c, ..)| *c)
                    .find(|c| account_vid(k.book.book_id, c) == cell.key.account)
                    .expect("known account");
                let m = model_fold
                    .get(&(account_code.to_string(), cell.key.unit_id))
                    .expect("oracle cell");
                assert_eq!(
                    m.debits.to_i128(),
                    Some(cell.debits),
                    "{code}/{account_code}"
                );
                assert_eq!(
                    m.credits.to_i128(),
                    Some(cell.credits),
                    "{code}/{account_code}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Drafts (plan §15.2, bead fa-s7x)
// ---------------------------------------------------------------------------

const APPROVER: VId = VId(70);
const CLERK: VId = VId(71);

fn draft_request(k: &Kernel, capability: Capability) -> DraftRequest {
    DraftRequest {
        capability,
        effective_date: control_day(),
        description: fresh_seal(&k.book.seal_key, "draft record"),
    }
}

fn kernel_open_draft(k: &mut Kernel, name: &str) -> Result<DraftRecorded, Refusal> {
    let req = draft_request(k, Capability::embedded(PRINCIPAL, &["post"]).unwrap());
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    k.runtime
        .block_on(async move { open_draft(db, &ctx, book, name, req).await })
        .expect("draft kernel")
}

fn kernel_plan_draft(
    k: &mut Kernel,
    name: &str,
    intent: &Intent,
    usd: UnitId,
    refs: &[EntryRef],
) -> Result<DraftPlanned, Refusal> {
    let post = kernel_request(k, intent, usd, refs);
    let typed = PostIntent::new(post.proposal, post.approvals).expect("typed intent");
    let req = draft_request(k, post.capability);
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    k.runtime
        .block_on(async move { plan_into_draft(db, &ctx, book, name, typed, req).await })
        .expect("draft kernel")
}

fn kernel_promote_draft(
    k: &mut Kernel,
    name: &str,
    capability: Capability,
) -> Result<DraftPromoted, Refusal> {
    let req = draft_request(k, capability);
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    k.runtime
        .block_on(async move { promote_draft(db, &ctx, book, name, req).await })
        .expect("draft kernel")
}

fn kernel_discard_draft(
    k: &mut Kernel,
    name: &str,
    capability: Capability,
) -> Result<DraftRecorded, Refusal> {
    let req = draft_request(k, capability);
    let ctx = k.ctx();
    let db = &mut k.db;
    let book = &k.book;
    k.runtime
        .block_on(async move { discard_draft(db, &ctx, book, name, req).await })
        .expect("draft kernel")
}

/// fa-s7x: drafts against the independent oracle's literal draft model
/// (an owned intent log; a plan is a rehearsal on a thrown-away copy; a
/// promotion is the oracle's own batch law, behind its approver and
/// segregation rules) over seeded histories. Planted: an unbalanced
/// intent, another intent under a planned key, an unknown draft, a promoter
/// without approve, the owner promoting, April closing between planning and
/// promotion, planning into a promoted or discarded draft; and identical
/// re-plans, re-promotions and re-discards. Every verdict agrees, every
/// refusal writes nothing, and every period fold agrees at the end.
#[test]
fn drafts_agree_with_the_independent_oracle_across_seeds() {
    for seed in [5_u64, 0x00d0_cafe, 0x7f4a_7c15] {
        let (mut k, mut oracle, periods) = setup();
        open_period(&mut k, &mut oracle, "FY2026-P03", 0);
        open_period(&mut k, &mut oracle, "FY2026-P04", 1);
        let usd = k.book.units.lookup("USD").unwrap();
        let dates = [
            DateDay::parse("2026-03-10").unwrap(),
            DateDay::parse("2026-04-20").unwrap(),
        ];
        let mut rng = Rng(seed);
        let mut refs: Vec<EntryRef> = Vec::new();
        let mut names: Vec<String> = Vec::new();
        let mut april_closed = false;
        let (mut promoted, mut refused, mut retried) = (0, 0, 0);
        let approver = || Capability::embedded(APPROVER, &["approve", "post"]).unwrap();
        for step in 0..60_u64 {
            let head = k.db.frontier().unwrap();
            let action = rng.below(10);
            let label = format!("seed {seed} step {step} action {action}");
            // Live targets, so positives occur as often as the planted
            // negatives (unknown, empty, closed drafts) do.
            let open_names: Vec<String> = names
                .iter()
                .filter(|n| {
                    oracle
                        .draft(n)
                        .is_some_and(|d| d.state == fa_reference::DraftState::Open)
                })
                .cloned()
                .collect();
            let ready: Vec<String> = open_names
                .iter()
                .filter(|n| oracle.draft(n).is_some_and(|d| !d.intents.is_empty()))
                .cloned()
                .collect();
            // Whether the oracle's verdict is a new record (one commit).
            let mut commits = false;
            match action {
                // Open a new draft (sometimes the identical retry).
                0 | 1 => {
                    let name = if !names.is_empty() && rng.chance(20) {
                        names[rng.below(names.len() as u64) as usize].clone()
                    } else {
                        let n = format!("d{seed}-{step}");
                        names.push(n.clone());
                        n
                    };
                    let expected = oracle.open_draft(&name, "p7");
                    let actual = kernel_open_draft(&mut k, &name);
                    match (&expected, &actual) {
                        (DraftVerdict::Recorded, Ok(r)) => {
                            assert!(!r.already_recorded, "{label}");
                            commits = true;
                        }
                        (DraftVerdict::AlreadyRecorded, Ok(r)) => {
                            assert!(r.already_recorded, "{label}");
                            retried += 1;
                        }
                        _ => panic!("{label}: oracle {expected:?}, kernel {actual:?}"),
                    }
                }
                // Plan an intent (planted: unbalanced, a reused key, unknown).
                2..=5 => {
                    let name = if names.is_empty() || rng.chance(5) {
                        format!("nope-{step}")
                    } else if !open_names.is_empty() && rng.chance(80) {
                        open_names[rng.below(open_names.len() as u64) as usize].clone()
                    } else {
                        names[rng.below(names.len() as u64) as usize].clone()
                    };
                    let amount = 1 + rng.below(40_000) as i128;
                    let date = dates[rng.below(2) as usize];
                    let mut intent = maintenance_intent(
                        "Original",
                        date,
                        amount,
                        &format!("plan-{seed}-{step}"),
                    );
                    match rng.below(8) {
                        0 => intent.legs[1].mantissa += 1,
                        1 => {
                            if let Some(planned) =
                                oracle.draft(&name).and_then(|d| d.intents.first()).cloned()
                            {
                                // The identical intent, or another under its key.
                                intent = planned;
                                if rng.chance(50) {
                                    intent.legs[0].mantissa += 1;
                                    intent.legs[1].mantissa += 1;
                                }
                            }
                        }
                        _ => {}
                    }
                    let expected = oracle.plan_into_draft(&name, "p7", &intent);
                    let actual = kernel_plan_draft(&mut k, &name, &intent, usd, &refs);
                    eprintln!("{label}: plan into {name}: oracle {expected:?}");
                    match (&expected, &actual) {
                        (DraftVerdict::Recorded, Ok(p)) => {
                            assert!(!p.recorded.already_recorded && p.plan.is_some(), "{label}");
                            commits = true;
                        }
                        (DraftVerdict::AlreadyRecorded, Ok(p)) => {
                            assert!(p.recorded.already_recorded && p.plan.is_none(), "{label}");
                            retried += 1;
                        }
                        (DraftVerdict::Refused { code, .. }, Err(r)) => {
                            assert_eq!(r.code, *code, "{label}: {r}");
                            refused += 1;
                        }
                        _ => panic!("{label}: oracle {expected:?}, kernel {actual:?}"),
                    }
                }
                // Promote (planted: a clerk without approve, the owner).
                6 | 7 => {
                    let Some(name) = (if !ready.is_empty() && rng.chance(70) {
                        Some(ready[rng.below(ready.len() as u64) as usize].clone())
                    } else {
                        (!names.is_empty())
                            .then(|| names[rng.below(names.len() as u64) as usize].clone())
                    }) else {
                        continue;
                    };
                    let (who, ops, cap) = match rng.below(6) {
                        0 => (
                            "clerk",
                            vec!["post"],
                            Capability::embedded(CLERK, &["post"]).unwrap(),
                        ),
                        1 => (
                            "p7",
                            vec!["approve", "post"],
                            Capability::embedded(PRINCIPAL, &["approve", "post"]).unwrap(),
                        ),
                        _ => ("approver", vec!["approve", "post"], approver()),
                    };
                    let expected = oracle.promote_draft(&name, who, &ops);
                    let actual = kernel_promote_draft(&mut k, &name, cap);
                    eprintln!("{label}: promote {name} by {who}: oracle {expected:?}");
                    match (&expected, &actual) {
                        (DraftVerdict::Promoted { indices, already }, Ok(p)) => {
                            assert_eq!(p.already_recorded, *already, "{label}");
                            if *already {
                                assert_eq!(
                                    p.entries,
                                    indices.iter().map(|i| refs[*i]).collect::<Vec<_>>(),
                                    "{label}"
                                );
                                retried += 1;
                            } else {
                                assert_eq!(indices.len(), p.entries.len(), "{label}");
                                assert_eq!(indices[0], refs.len(), "{label}");
                                assert_eq!(p.recorded_at.0, head.0 + 1, "{label}: one commit");
                                refs.extend(p.entries.iter().copied());
                                promoted += 1;
                                commits = true;
                            }
                        }
                        (DraftVerdict::Refused { member, code }, Err(r)) => {
                            assert_eq!(r.code, *code, "{label}: {r}");
                            if let Some(i) = member {
                                assert!(
                                    r.message.starts_with(&format!("batch member {i}")),
                                    "{label}: {r}"
                                );
                            }
                            refused += 1;
                        }
                        _ => panic!("{label}: oracle {expected:?}, kernel {actual:?}"),
                    }
                }
                // Discard (the owner, or an approver; sometimes a retry).
                8 => {
                    let Some(name) = (!names.is_empty())
                        .then(|| names[rng.below(names.len() as u64) as usize].clone())
                    else {
                        continue;
                    };
                    let (who, ops, cap) = if rng.chance(50) {
                        (
                            "p7",
                            vec!["post"],
                            Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
                        )
                    } else {
                        ("approver", vec!["approve", "post"], approver())
                    };
                    let expected = oracle.discard_draft(&name, who, &ops);
                    let actual = kernel_discard_draft(&mut k, &name, cap);
                    match (&expected, &actual) {
                        (DraftVerdict::Recorded, Ok(r)) => {
                            assert!(!r.already_recorded, "{label}");
                            commits = true;
                        }
                        (DraftVerdict::AlreadyRecorded, Ok(r)) => {
                            assert!(r.already_recorded, "{label}");
                            retried += 1;
                        }
                        (DraftVerdict::Refused { code, .. }, Err(r)) => {
                            assert_eq!(r.code, *code, "{label}: {r}");
                            refused += 1;
                        }
                        _ => panic!("{label}: oracle {expected:?}, kernel {actual:?}"),
                    }
                }
                // Trunk moves under the drafts: April closes, once.
                _ => {
                    if april_closed || step < 20 {
                        continue;
                    }
                    for (i, t) in [PeriodTransition::SoftClose, PeriodTransition::Close]
                        .into_iter()
                        .enumerate()
                    {
                        let kt =
                            kernel_transition(&mut k, "FY2026-P04", t, 1000 + 2 * step + i as u64)
                                .expect("April moves");
                        assert_eq!(
                            Ok((kt.from, kt.to)),
                            oracle.transition("FY2026-P04", t),
                            "{label}"
                        );
                    }
                    april_closed = true;
                    continue;
                }
            }
            assert_eq!(
                k.db.frontier().unwrap().0 - head.0,
                u64::from(commits),
                "{label}: a new record is one commit; a refusal or retry writes nothing"
            );
        }
        eprintln!("seed {seed}: drafts promoted {promoted} refused {refused} retried {retried}");
        assert!(
            promoted >= 2 && refused >= 4 && retried >= 1,
            "seed {seed}: promoted {promoted} refused {refused} retried {retried}"
        );
        assert_eq!(oracle.journal_len(), refs.len());
        for code in &periods {
            let kernel_fold = fold_period(&k.db, &k.book, code).unwrap();
            let model_fold = oracle.fold(code);
            assert_eq!(
                kernel_fold.cells.len(),
                model_fold.len(),
                "{code}: cell count"
            );
            for cell in &kernel_fold.cells {
                let account_code = ACCOUNTS
                    .iter()
                    .map(|(c, ..)| *c)
                    .find(|c| account_vid(k.book.book_id, c) == cell.key.account)
                    .expect("known account");
                let m = model_fold
                    .get(&(account_code.to_string(), cell.key.unit_id))
                    .expect("oracle cell");
                assert_eq!(
                    m.debits.to_i128(),
                    Some(cell.debits),
                    "{code}/{account_code}"
                );
                assert_eq!(
                    m.credits.to_i128(),
                    Some(cell.credits),
                    "{code}/{account_code}"
                );
            }
        }
    }
}

const COST_CENTER: u32 = 2;
const DEPARTMENT: u32 = 3;

/// The schema_change capability the fixture's chart was installed with: a
/// dimension control is a book-scoped schema change (fa-ficc).
fn schema_change_capability() -> Capability {
    Capability::embedded(PRINCIPAL, &["schema_change"]).expect("schema_change")
}

fn dimension_note(k: &Kernel) -> Erasable<String> {
    Erasable::seal(
        &"dimension control".to_string(),
        None,
        &k.book.seal_key,
        [3; 32],
        [4; 24],
    )
}

/// `fa dimension add` on the kernel for the oracle's `value`.
fn kernel_declare(k: &mut Kernel, value: &DimensionValue, key: &str) -> Result<(), Refusal> {
    let kind = fa_model::dimension_kind_of(value.kind).expect("registered kind");
    let spec = fa_journal::dimension::DimensionValueSpec {
        dimension: kind.code.into(),
        code: value.code.clone(),
        name: value.code.clone(),
        parent: value.parent.clone(),
        valid_from: value.valid_from,
        valid_to: value.valid_to,
    };
    let (ctx, note, capability) = (k.ctx(), dimension_note(k), schema_change_capability());
    let (db, book) = (&mut k.db, &k.book);
    k.runtime
        .block_on(async move {
            fa_journal::dimension::create_dimension_value(
                db,
                &ctx,
                book,
                &spec,
                PRINCIPAL,
                key.as_bytes(),
                note,
                &capability,
            )
            .await
        })
        .expect("kernel")
        .map(|_| ())
}

/// `fa dimension require` (or `--remove`) on the kernel.
fn kernel_require(
    k: &mut Kernel,
    dimension: &str,
    account: &str,
    required: bool,
    key: &str,
) -> Result<(), Refusal> {
    let spec = fa_journal::dimension::DimensionRequirementSpec {
        dimension: dimension.into(),
        account: account_vid(k.book.book_id, account),
        required,
    };
    let (ctx, note, capability) = (k.ctx(), dimension_note(k), schema_change_capability());
    let (db, book) = (&mut k.db, &k.book);
    k.runtime
        .block_on(async move {
            fa_journal::dimension::record_dimension_requirement(
                db,
                &ctx,
                book,
                &spec,
                PRINCIPAL,
                key.as_bytes(),
                note,
                &capability,
            )
            .await
        })
        .expect("kernel")
        .map(|_| ())
}

/// `fa dimension close` on the kernel.
fn kernel_close(
    k: &mut Kernel,
    dimension: &str,
    code: &str,
    closed_on: DateDay,
    key: &str,
) -> Result<(), Refusal> {
    let spec = fa_journal::dimension::DimensionCloseSpec {
        dimension: dimension.into(),
        code: code.into(),
        closed_on,
    };
    let (ctx, note, capability) = (k.ctx(), dimension_note(k), schema_change_capability());
    let (db, book) = (&mut k.db, &k.book);
    k.runtime
        .block_on(async move {
            fa_journal::dimension::close_dimension_value(
                db,
                &ctx,
                book,
                &spec,
                PRINCIPAL,
                key.as_bytes(),
                note,
                &capability,
            )
            .await
        })
        .expect("kernel")
        .map(|_| ())
}

/// The kernel post of `intent` with each leg's registered-kind tags in its
/// dimension_set, sorted by dimension id as the leg format requires.
fn kernel_post_tagged(
    k: &mut Kernel,
    intent: &Intent,
    usd: UnitId,
    refs: &[EntryRef],
    tags: &[Vec<DimensionTag>],
) -> Result<Posted, Refusal> {
    let mut req = kernel_request(k, intent, usd, refs);
    for (leg, tags) in req.proposal.legs.iter_mut().zip(tags) {
        for tag in tags {
            let kind = fa_model::dimension_kind_of(tag.value_kind).expect("registered kind");
            leg.dimension_set.push((
                tag.dimension,
                fa_model::dimension_value_vid(k.book.book_id, kind.code, &tag.code),
            ));
        }
        leg.dimension_set.sort_unstable_by_key(|(id, _)| *id);
    }
    let ctx = k.ctx();
    let (db, book) = (&mut k.db, &k.book);
    k.runtime
        .block_on(async move { post(db, &ctx, book, req).await })
        .expect("kernel")
}

fn tag(dimension: u32, value_kind: u32, code: &str) -> Vec<DimensionTag> {
    vec![DimensionTag {
        dimension,
        value_kind,
        code: code.into(),
    }]
}

/// fa-ficc, FA-INV-01.dimensions: the kernel and the reference agree on the
/// dimension law over seeded histories, step by step, and on the registers
/// at the end. Each history declares cost_center values (one always
/// effective, its child, one with a February–March window) and a department
/// value, then interleaves:
/// - Originals whose 6000 leg names no cost_center, a held value, an
///   unknown one, or a department value under cost_center, and whose 1000
///   leg sometimes names the department;
/// - turning 6000's cost_center requirement on and off;
/// - Reversals of earlier posts dated anywhere in the open months, which
///   carry their target's tags and are dictated, so neither a requirement
///   nor a closed window binds them;
/// - closes of values on dates that are lawful, already the end, extending,
///   emptying, or behind a tagged leg.
///
/// Every outcome the law can give is reached across the seeds.
#[test]
fn kernel_and_oracle_agree_on_the_dimension_law_across_seeds() {
    let mut total: BTreeMap<&'static str, usize> = BTreeMap::new();
    for i in 1..=8u64 {
        for (label, n) in dimension_campaign(splitmix(i.wrapping_add(0x00D1_A5E7))) {
            *total.entry(label).or_default() += n;
        }
    }
    eprintln!("fa-ficc dimension law over 8 seeds: {total:?}");
    for label in [
        "posted untagged",
        "posted tagged",
        "refused missing",
        "refused unknown",
        "refused wrong kind",
        "refused outside window",
        "reversal of a tagged entry",
        "reversal outside its tag's window",
        "reversal of an untagged entry under a requirement",
        "close",
        "close at its end",
        "close refused behind a tagged leg",
        "close refused extending or emptying",
        "requirement",
        "tagged fold",
    ] {
        assert!(
            total.get(label).copied().unwrap_or(0) > 0,
            "the campaign never reached `{label}`: {total:?}"
        );
    }
}

/// One seeded dimension history (see
/// [`kernel_and_oracle_agree_on_the_dimension_law_across_seeds`]); the
/// counts of each outcome it reached.
fn dimension_campaign(seed: u64) -> BTreeMap<&'static str, usize> {
    let (mut k, mut oracle, periods) = setup();
    let usd = k.book.units.lookup("USD").unwrap();
    for month in 1..=6u64 {
        open_period(
            &mut k,
            &mut oracle,
            &format!("FY2026-P{month:02}"),
            7_000 + month,
        );
    }
    let day = |m: u8, d: u8| DateDay::from_ymd(2026, m, d).unwrap();
    let values = [
        DimensionValue {
            kind: COST_CENTER,
            code: "CC10".into(),
            parent: None,
            valid_from: None,
            valid_to: None,
        },
        DimensionValue {
            kind: COST_CENTER,
            code: "CC11".into(),
            parent: Some("CC10".into()),
            valid_from: None,
            valid_to: None,
        },
        DimensionValue {
            kind: COST_CENTER,
            code: "CC20".into(),
            parent: None,
            valid_from: Some(day(2, 1)),
            valid_to: Some(day(4, 1)),
        },
        DimensionValue {
            kind: DEPARTMENT,
            code: "D1".into(),
            parent: None,
            valid_from: None,
            valid_to: None,
        },
    ];
    // The test's own copy of each cost_center window, to label outcomes.
    let mut windows: BTreeMap<String, (Option<DateDay>, Option<DateDay>)> = BTreeMap::new();
    for (n, value) in values.iter().enumerate() {
        kernel_declare(&mut k, value, &format!("dimension-{n}")).expect("the kernel declares");
        oracle
            .declare_dimension_value(value.clone())
            .expect("the oracle declares");
        if value.kind == COST_CENTER {
            windows.insert(value.code.clone(), (value.valid_from, value.valid_to));
        }
    }
    let effective = |windows: &BTreeMap<String, (Option<DateDay>, Option<DateDay>)>,
                     code: &str,
                     date: DateDay| {
        windows
            .get(code)
            .is_some_and(|(from, to)| from.is_none_or(|f| date >= f) && to.is_none_or(|t| date < t))
    };
    let mut rng = Rng(seed);
    let mut seen: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut refs: Vec<EntryRef> = Vec::new();
    let mut tags_of: BTreeMap<usize, Vec<Vec<DimensionTag>>> = BTreeMap::new();
    let mut originals: Vec<usize> = Vec::new();
    let mut required = false;
    for step in 0..60u64 {
        let what = format!("seed {seed:#018x} step {step}");
        let head = k.db.frontier().unwrap();
        match rng.below(10) {
            0 => {
                required = !required;
                kernel_require(
                    &mut k,
                    "cost_center",
                    "6000",
                    required,
                    &format!("req-{step}"),
                )
                .unwrap_or_else(|r| panic!("{what}: the kernel refused a requirement: {r}"));
                oracle.require_dimension(COST_CENTER, "6000", required);
                *seen.entry("requirement").or_default() += 1;
            }
            1 => {
                let (code, closed_on) = [
                    ("CC20", day(3, 1)),
                    ("CC20", day(4, 1)),
                    ("CC20", day(5, 1)),
                    ("CC20", day(2, 1)),
                    ("CC10", day(5, 15)),
                    ("CC11", day(1, 10)),
                ][rng.below(6) as usize];
                let at_end = windows
                    .get(code)
                    .is_some_and(|(_, to)| *to == Some(closed_on));
                let kernel = kernel_close(
                    &mut k,
                    "cost_center",
                    code,
                    closed_on,
                    &format!("close-{step}"),
                );
                let reference = oracle.close_dimension_value(COST_CENTER, code, closed_on);
                assert_eq!(
                    kernel.as_ref().map(|_| ()).map_err(|r| r.code),
                    reference,
                    "{what}: close {code} on {closed_on:?}"
                );
                let label = match reference {
                    Ok(()) if at_end => "close at its end",
                    Ok(()) => {
                        if let Some(window) = windows.get_mut(code) {
                            window.1 = Some(closed_on);
                        }
                        "close"
                    }
                    Err("FA-REF-195") => "close refused behind a tagged leg",
                    Err(_) => "close refused extending or emptying",
                };
                *seen.entry(label).or_default() += 1;
            }
            2 if !originals.is_empty() => {
                let target = originals[rng.below(originals.len() as u64) as usize];
                let date = day(1 + rng.below(6) as u8, 1 + rng.below(28) as u8);
                let intent = reversal_of(&oracle, target, date, format!("rev-{step}").into_bytes());
                let tags = tags_of.get(&target).cloned().unwrap_or_default();
                let kernel = kernel_post_tagged(&mut k, &intent, usd, &refs, &tags);
                let reference = oracle.post(&intent);
                let index = refs.len();
                match (&kernel, &reference) {
                    (Ok(posted), Verdict::Posted { index: at, .. }) => {
                        assert_eq!(*at, index, "{what}");
                        refs.push(posted.entry_ref());
                        let cost: Vec<&DimensionTag> = tags
                            .iter()
                            .flatten()
                            .filter(|t| t.dimension == COST_CENTER)
                            .collect();
                        if !cost.is_empty() {
                            tags_of.insert(index, tags.clone());
                            *seen.entry("reversal of a tagged entry").or_default() += 1;
                            if cost.iter().any(|t| !effective(&windows, &t.code, date)) {
                                *seen.entry("reversal outside its tag's window").or_default() += 1;
                            }
                        } else if required {
                            *seen
                                .entry("reversal of an untagged entry under a requirement")
                                .or_default() += 1;
                        }
                    }
                    (Err(r), Verdict::Refused { code }) => {
                        assert_eq!(r.code, *code, "{what}: reversal of {target}");
                        assert_eq!(k.db.frontier().unwrap(), head, "{what}: a refusal wrote");
                    }
                    other => panic!("{what}: reversal of {target} diverged: {other:?}"),
                }
            }
            _ => {
                let date = day(1 + rng.below(6) as u8, 1 + rng.below(28) as u8);
                let legs = two_legs(usd, "6000", "1000", 1 + rng.below(5_000) as i128);
                let intent = race_intent(
                    "Original",
                    date,
                    legs,
                    format!("post-{step}").into_bytes(),
                    &["post"],
                );
                let (cost, chosen) = match rng.below(7) {
                    0 | 1 => (Vec::new(), "untagged"),
                    2 => (tag(COST_CENTER, COST_CENTER, "CC10"), "held"),
                    3 => (tag(COST_CENTER, COST_CENTER, "CC11"), "held"),
                    4 => (tag(COST_CENTER, COST_CENTER, "CC20"), "held"),
                    5 => (tag(COST_CENTER, COST_CENTER, "CC99"), "unknown"),
                    _ => (tag(COST_CENTER, DEPARTMENT, "D1"), "wrong kind"),
                };
                let department = if rng.chance(30) {
                    tag(DEPARTMENT, DEPARTMENT, "D1")
                } else {
                    Vec::new()
                };
                let tags = vec![cost, department];
                let kernel = kernel_post_tagged(&mut k, &intent, usd, &refs, &tags);
                let reference = oracle.post_dimensioned(&intent, &tags);
                let index = refs.len();
                match (&kernel, &reference) {
                    (Ok(posted), Verdict::Posted { index: at, .. }) => {
                        assert_eq!(*at, index, "{what}");
                        refs.push(posted.entry_ref());
                        originals.push(index);
                        if tags.iter().any(|t| !t.is_empty()) {
                            tags_of.insert(index, tags.clone());
                        }
                        let label = if chosen == "untagged" {
                            "posted untagged"
                        } else {
                            "posted tagged"
                        };
                        *seen.entry(label).or_default() += 1;
                    }
                    (Err(r), Verdict::Refused { code }) => {
                        assert_eq!(r.code, *code, "{what}: {chosen} on {date:?}");
                        assert_eq!(k.db.frontier().unwrap(), head, "{what}: a refusal wrote");
                        let label = match (*code, chosen) {
                            ("FA-REF-005", _) => "refused missing",
                            ("FA-REF-195", _) => "refused outside window",
                            ("FA-REF-100", "unknown") => "refused unknown",
                            ("FA-REF-100", "wrong kind") => "refused wrong kind",
                            _ => "refused otherwise",
                        };
                        *seen.entry(label).or_default() += 1;
                    }
                    other => panic!("{what}: {chosen} post on {date:?} diverged: {other:?}"),
                }
            }
        }
    }
    // fa-ficc: `fa tb --dimension`'s literal tagged fold agrees with the
    // reference's own, for a value with its child, the child alone, the
    // windowed value and the department value.
    let through = day(6, 30);
    for (dimension, codes) in [
        (COST_CENTER, &["CC10", "CC11"][..]),
        (COST_CENTER, &["CC11"][..]),
        (COST_CENTER, &["CC20"][..]),
        (DEPARTMENT, &["D1"][..]),
    ] {
        let kind = fa_model::dimension_kind_of(dimension).expect("registered kind");
        let filter = fa_registers::DimensionFilter {
            dimension,
            values: codes
                .iter()
                .map(|code| fa_model::dimension_value_vid(k.book.book_id, kind.code, code))
                .collect(),
        };
        let kernel: BTreeMap<(String, u32), (i128, i128)> =
            fa_registers::balance_as_of_tagged(&k.db, &k.book, through, None, &filter)
                .expect("the kernel's tagged fold")
                .rows
                .iter()
                .filter(|row| row.debits != 0 || row.credits != 0)
                .map(|row| ((row.code.clone(), row.unit_id), (row.debits, row.credits)))
                .collect();
        let values: BTreeSet<String> = codes.iter().map(|code| (*code).to_string()).collect();
        let reference: BTreeMap<(String, u32), (i128, i128)> = oracle
            .stock_tagged(through, dimension, &values)
            .into_iter()
            .map(|(cell, folded)| {
                let debits = folded.debits.to_i128().expect("i128 debits");
                let credits = folded.credits.to_i128().expect("i128 credits");
                (cell, (debits, credits))
            })
            .filter(|(_, (debits, credits))| *debits != 0 || *credits != 0)
            .collect();
        assert_eq!(
            kernel, reference,
            "seed {seed:#018x}: the tagged fold of {codes:?}"
        );
        if !reference.is_empty() {
            *seen.entry("tagged fold").or_default() += 1;
        }
    }
    assert_registers_agree(&k, &oracle, &periods, &refs, &format!("seed {seed:#018x}"));
    seen
}
