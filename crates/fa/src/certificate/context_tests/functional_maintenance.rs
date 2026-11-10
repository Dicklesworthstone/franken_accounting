//! Real native postings exercise durable functional state and exact tails.

#[path = "functional_health.rs"]
mod functional_health;
#[path = "functional_history.rs"]
mod functional_history;

use super::*;
use fa_registers::functional_maintainer as maintained;

fn authority() -> Capability {
    cap(&["read", "verify", "maintain"])
}

fn advance(h: &mut Harness) -> maintained::Advance {
    let cx = h.cx();
    h.runtime
        .block_on(
            h.book
                .advance_functional_registers(&cx, PRINCIPAL, &authority(), PERIOD),
        )
        .unwrap()
        .unwrap()
}

fn post(h: &mut Harness, proposal: EntryPayload) -> fa_journal::Posted {
    let cx = h.cx();
    h.runtime
        .block_on(h.book.post(
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
}

fn proposal(h: &Harness, key: &[u8], amount: i128) -> EntryPayload {
    let mut proposal = original(h);
    proposal.idempotency_key = key.to_vec();
    for leg in &mut proposal.legs {
        leg.amount.mantissa = amount;
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    proposal
}

fn literal(h: &Harness, at: CommitSeq) -> fa_registers::FunctionalFold {
    fa_registers::fold_period_functional(&h.book.db, h.book.context(), PERIOD, Some(at)).unwrap()
}

fn served(h: &Harness, at: CommitSeq) -> Option<maintained::HeadFold> {
    maintained::fold_at_with_context(&h.book.db, &h.cx().query(), h.book.context(), PERIOD, at)
        .unwrap()
}

#[test]
fn maintained_activity_extends_foreign_values_and_reversals_without_refolding_the_prefix() {
    let (mut h, _) = fixture();
    let before = h.head();
    assert!(served(&h, before).is_none());
    let first = advance(&mut h);
    assert!(first.rebuilt && first.wrote);
    assert_eq!(first.legs_folded, 4);
    assert_eq!(first.fold, literal(&h, before));
    assert_eq!(first.fold.total_debits().unwrap(), 25_050);
    let first_publication = h.head();
    let warm = served(&h, first_publication).unwrap();
    assert_eq!(warm.tail_entries, 0);
    assert_eq!(warm.fold, literal(&h, first_publication));
    let noop = advance(&mut h);
    assert!(!noop.wrote && !noop.rebuilt);
    assert_eq!((noop.entries_decoded, noop.legs_folded), (0, 0));
    assert_eq!(h.head(), first_publication);

    let extra = proposal(&h, b"functional-maintained-tail", 700);
    let posted = post(&mut h, extra.clone());
    let at = h.head();
    let tail = served(&h, at).unwrap();
    assert_eq!(tail.tail_entries, 1);
    assert_eq!(tail.fold, literal(&h, at));
    let second = advance(&mut h);
    assert!(!second.rebuilt);
    assert_eq!((second.entries_decoded, second.legs_folded), (1, 2));

    let mut reversal = extra;
    reversal.class = EntryClass::REVERSAL;
    reversal.idempotency_key = b"functional-maintained-reversal".to_vec();
    for leg in &mut reversal.legs {
        leg.side = match leg.side {
            Side::Debit => Side::Credit,
            Side::Credit => Side::Debit,
        };
    }
    reversal.unit_totals = EntryPayload::fold_unit_totals(&reversal.legs).unwrap();
    reversal.supersession = vec![fa_model::Supersession {
        target: posted.entry_ref(),
        kind: fa_model::SupersessionKind::Reverses,
        reason_code: 1,
    }];
    post(&mut h, reversal);
    let at = h.head();
    let reversed = served(&h, at).unwrap();
    assert_eq!(reversed.tail_entries, 1);
    assert_eq!(reversed.fold, literal(&h, at));
    assert_eq!(reversed.fold.total_debits().unwrap(), 26_450);
    assert_ne!(reversed.fold.fold_digest, first.fold.fold_digest);
    let old = served(&h, first_publication).unwrap();
    assert_eq!(old.tail_entries, 0);
    assert_eq!(old.fold, literal(&h, first_publication));
    assert_eq!(old.fold.total_debits().unwrap(), 25_050);

    let cx = h.cx();
    let read = h
        .runtime
        .block_on(
            h.book
                .functional_trial_balance(&cx, &cap(&["read"]), activity(), Some(at)),
        )
        .unwrap()
        .unwrap();
    let certified = certify(&mut h, activity());
    assert_eq!(
        read.canonical_bytes().unwrap(),
        certified.certificate.output
    );
    assert!(
        maintained::verify(&h.book.db, &cx.query(), h.book.context(), PERIOD, None)
            .unwrap()
            .is_green()
    );
}

fn held_proposal(h: &Harness, key: &[u8], amount: i128) -> EntryPayload {
    let mut held = proposal(h, key, amount);
    held.class = EntryClass::PENDING;
    held.pending = Some(fa_model::Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    held
}

fn release_proposal(
    mut held: EntryPayload,
    target: fa_model::EntryRef,
    key: &[u8],
) -> EntryPayload {
    held.class = EntryClass::RESOLUTION;
    held.idempotency_key = key.to_vec();
    held.legs.clear();
    held.unit_totals.clear();
    held.control = Some(fa_model::ControlPayload::ReservationRelease);
    held.pending = Some(fa_model::Pending {
        timeout_ns: None,
        resolution_of: Some(target),
        disposition: Some(fa_model::Disposition::Voids),
    });
    held
}

#[test]
fn maintained_pending_release_in_another_period_preserves_the_original_snapshot() {
    let (mut h, _) = fixture();
    let held = held_proposal(&h, b"functional-maintained-hold", 100);
    let target = post(&mut h, held.clone()).entry_ref();
    let first = advance(&mut h);
    let held_at = h.head();
    assert_eq!(first.fold.pending.len(), 2);
    let cx = h.cx();
    h.runtime
        .block_on(h.book.transition_period(
            &cx,
            "FY2026-P02",
            PeriodTransition::Open,
            PRINCIPAL,
            1,
            b"functional-maintained-open-february",
            &cap(&["close"]),
        ))
        .unwrap()
        .unwrap();
    let mut release = release_proposal(held, target, b"functional-maintained-release");
    release.effective_date = DateDay::from_ymd(2026, 2, 5).unwrap();
    let released = post(&mut h, release);
    let at = h.head();
    let current = served(&h, at).unwrap();
    assert_eq!(current.tail_entries, 2);
    assert!(current.fold.pending.is_empty());
    assert_eq!(current.fold.watermark, Some(released.recorded_at()));
    assert_eq!(current.fold, literal(&h, at));
    assert_eq!(served(&h, held_at).unwrap().fold.pending.len(), 2);
    let advanced = advance(&mut h);
    assert!(!advanced.rebuilt);
    assert_eq!((advanced.entries_decoded, advanced.legs_folded), (2, 0));
}

#[test]
fn one_publication_can_create_and_release_a_hold_in_either_vertex_order() {
    for resolution_sorts_first in [false, true] {
        let (mut h, _) = fixture();
        advance(&mut h);
        let held = (0..256u16)
            .find_map(|index| {
                let key = format!("functional-atomic-held-{index}");
                let held = held_proposal(&h, key.as_bytes(), 100);
                let vid = fa_model::entry_vid(BOOK, &PRINCIPAL.0.to_le_bytes(), key.as_bytes());
                ((fa_journal::rows::resolution_vid(vid) < vid) == resolution_sorts_first)
                    .then_some((held, vid))
            })
            .expect("both deterministic vertex orders exist in the fixture key range");
        let target = held
            .0
            .clone()
            .seal(Vec::new(), None)
            .unwrap()
            .entry_ref(held.1);
        let release = release_proposal(held.0.clone(), target, b"functional-atomic-release");
        let batch = fa_intents::PostBatch::new(
            b"functional-atomic-hold-and-release".to_vec(),
            vec![
                fa_intents::PostIntent::new(held.0, Vec::new()).unwrap(),
                fa_intents::PostIntent::new(release, Vec::new()).unwrap(),
            ],
        )
        .unwrap();
        let cx = h.cx();
        h.runtime
            .block_on(h.book.post_batch(&cx, batch, &cap(&["post"])))
            .unwrap()
            .unwrap();
        let at = h.head();
        let current = served(&h, at).unwrap();
        assert_eq!(current.tail_entries, 2);
        assert!(current.fold.pending.is_empty());
        assert_eq!(current.fold.watermark, Some(at));
        assert_eq!(current.fold, literal(&h, at));
        let advanced = advance(&mut h);
        assert!(!advanced.rebuilt);
        assert_eq!((advanced.entries_decoded, advanced.legs_folded), (2, 2));
    }
}

#[test]
fn rewritten_then_restored_snapshot_falls_back_and_explicit_rebuild_recovers() {
    let (mut h, _) = fixture();
    let first = advance(&mut h);
    let original_at = h.head();
    let reference = first.checkpoint.unwrap();
    let root = maintained::checkpoint_vid(BOOK, PERIOD, reference);
    let original = h.book.db.vertex(root).unwrap().unwrap();
    let payload = prop(&original, property::FA_PAYLOAD).unwrap().clone();
    let cx = h.cx();
    let mut corrupt = WriteBatch::new(relation::IN_PERIOD);
    corrupt.set_vertex_property(
        root,
        property::FA_PAYLOAD,
        Some(scalar_bytes("broken cache", vec![0]).unwrap()),
    );
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), corrupt))
        .unwrap();
    assert!(served(&h, h.head()).is_none());
    let mut restore = WriteBatch::new(relation::IN_PERIOD);
    restore.set_vertex_property(root, property::FA_PAYLOAD, Some(payload));
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), restore))
        .unwrap();
    assert!(
        served(&h, h.head()).is_none(),
        "restoration does not restore immutable birth"
    );
    assert!(served(&h, original_at).is_some());
    let verified =
        maintained::verify(&h.book.db, &cx.query(), h.book.context(), PERIOD, None).unwrap();
    assert!(verified.available && !verified.is_green());
    let read = h
        .runtime
        .block_on(
            h.book
                .functional_trial_balance(&cx, &cap(&["read"]), activity(), None),
        )
        .unwrap()
        .unwrap();
    assert_eq!(read.total_debits().unwrap(), 25_050);
    let repaired = h
        .runtime
        .block_on(
            h.book
                .rebuild_functional_registers(&cx, PRINCIPAL, &authority(), PERIOD),
        )
        .unwrap()
        .unwrap();
    assert!(repaired.rebuilt && repaired.wrote);
    assert_eq!(served(&h, h.head()).unwrap().fold, literal(&h, h.head()));
    assert!(
        maintained::verify(&h.book.db, &cx.query(), h.book.context(), PERIOD, None)
            .unwrap()
            .is_green()
    );
}

#[test]
fn a_warm_projection_does_not_hide_an_entry_rewrite_or_accept_a_stale_preparation() {
    let (mut h, _) = fixture();
    advance(&mut h);
    let before = h.head();
    let cx = h.cx();
    let book = h.book.context.clone();
    let prepared = h
        .runtime
        .block_on(maintained::prepare_advance(
            &mut h.book.db,
            &cx,
            &book,
            PERIOD,
        ))
        .unwrap();
    let extra = proposal(&h, b"functional-moving-preparation", 80);
    post(&mut h, extra);
    assert!(matches!(
        h.runtime.block_on(maintained::publish_advance(
            &mut h.book.db,
            &cx,
            &book,
            prepared
        )),
        Err(fa_registers::RegisterError::StaleFold)
    ));
    let target = fa_model::entry_vid(BOOK, &PRINCIPAL.0.to_le_bytes(), b"symbol-post");
    let mut rewrite = WriteBatch::new(relation::IN_BOOK);
    rewrite.set_vertex_property(
        target,
        property::CODE,
        Some(fa_journal::rows::scalar_text("source rewrite", "changed").unwrap()),
    );
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), rewrite))
        .unwrap();
    assert!(matches!(
        maintained::fold_at_with_context(&h.book.db, &cx.query(), &book, PERIOD, h.head()),
        Err(fa_registers::RegisterError::Kernel(
            fa_journal::KernelError::Corrupt(_)
        ))
    ));
    assert!(served(&h, before).is_some());
    assert!(
        h.runtime
            .block_on(
                h.book
                    .functional_trial_balance(&cx, &cap(&["read"]), activity(), None)
            )
            .is_err()
    );
}

#[test]
fn persisted_entity_state_hydrates_an_unloaded_tail_after_reopen_and_compaction() {
    for compact in [false, true] {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let directory = Path::new("functional-maintained-book");
        let mut book_spec = spec();
        book_spec.entities = vec![fa_journal::genesis::LegalEntitySpec {
            code: "ORG".into(),
            name: "Organization".into(),
            functional_unit: book_spec.base_unit,
        }];
        let book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs.clone(),
                directory,
                BookKeys::for_development(SEED),
                book_spec,
                Entropy::deterministic(u64::from(SEED)),
            ))
            .unwrap();
        let mut h = Harness {
            runtime,
            root,
            book,
        };
        h.populate();
        let initial = advance(&mut h);
        let extra = proposal(&h, b"functional-persisted-tail", 80);
        post(&mut h, extra);
        let expected = literal(&h, h.head());
        assert!(
            expected
                .cells
                .iter()
                .all(|cell| cell.key.entity.as_deref() == Some("ORG"))
        );
        if compact {
            h.runtime.block_on(h.book.compact_storage(&cx)).unwrap();
        }
        let Harness {
            runtime,
            root,
            book,
        } = h;
        drop(book);
        let book = runtime
            .block_on(AsyncBook::open_with_vfs(
                &cx,
                vfs,
                directory,
                BookKeys::for_development(SEED),
                Entropy::deterministic(u64::from(SEED) + 1),
            ))
            .unwrap();
        let mut h = Harness {
            runtime,
            root,
            book,
        };
        // Both opens initially expose a lazy resident window. Compaction
        // preserves Chronicle, so its authenticated suffix is recoverable.
        assert!(h.book.db.delta_since(initial.through).is_err());
        let advanced = advance(&mut h);
        assert!(!advanced.rebuilt);
        assert_eq!(advanced.from, initial.through);
        assert_eq!((advanced.entries_decoded, advanced.legs_folded), (1, 2));
        assert!(h.book.db.delta_since(initial.through).is_ok());
        assert_eq!(advanced.fold.cells, expected.cells);
        assert_eq!(advanced.fold.pending, expected.pending);
        assert_eq!(advanced.fold.fold_digest, expected.fold_digest);
        assert_eq!(served(&h, h.head()).unwrap().fold, literal(&h, h.head()));
    }
}

#[test]
fn functional_maintenance_and_verification_require_their_whole_book_operations() {
    let (mut h, _) = fixture();
    let at = h.head();
    let cx = h.cx();
    for capability in [
        cap(&["read", "verify"]),
        cap(&["read", "maintain"]),
        cap(&["verify", "maintain"]),
    ] {
        assert!(
            h.runtime
                .block_on(
                    h.book
                        .advance_functional_registers(&cx, PRINCIPAL, &capability, PERIOD)
                )
                .unwrap()
                .is_err()
        );
        assert_eq!(h.head(), at);
    }
    for capability in [cap(&["read"]), cap(&["verify"])] {
        assert!(
            h.runtime
                .block_on(h.book.verify_functional_registers(
                    &cx,
                    PRINCIPAL,
                    &capability,
                    PERIOD,
                    None,
                ))
                .unwrap()
                .is_err()
        );
        assert_eq!(h.head(), at);
    }
    let absent = h
        .runtime
        .block_on(h.book.verify_functional_registers(
            &cx,
            PRINCIPAL,
            &cap(&["read", "verify"]),
            PERIOD,
            None,
        ))
        .unwrap()
        .unwrap();
    assert!(!absent.available && absent.through.is_none() && absent.is_green());
    assert_eq!(h.head(), at);
}

#[test]
fn a_later_base_unit_rewrite_cannot_reinterpret_cached_functional_cells() {
    let (mut h, _) = fixture();
    advance(&mut h);
    let original_at = h.head();
    let expected = served(&h, original_at).unwrap().fold;
    let cx = h.cx();
    let mut changed = h.book.spec(&cx).unwrap();
    changed.base_unit = h.book.context().units.lookup("EUR").unwrap();
    let mut rewrite = WriteBatch::new(relation::IN_BOOK);
    rewrite.set_vertex_property(
        book_root(),
        property::FA_PAYLOAD,
        Some(scalar_bytes("changed base unit", changed.canonical_bytes().unwrap()).unwrap()),
    );
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), rewrite))
        .unwrap();
    assert!(served(&h, h.head()).is_none());
    assert!(matches!(
        fa_registers::fold_period_functional(&h.book.db, h.book.context(), PERIOD, None),
        Err(fa_registers::RegisterError::ProjectionDrift(_))
    ));
    assert_eq!(served(&h, original_at).unwrap().fold, expected);
}
