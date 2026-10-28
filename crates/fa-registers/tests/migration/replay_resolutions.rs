//! Replay verification on reserve/release histories: exact native folds and
//! bounded release work, including cross-period partial posts and expiry.

use super::*;
use fa_model::symbols::{label, property, relation};
use fa_model::{ControlPayload, Disposition, Entry, Pending};
use fa_registers::replay::{ReplayWork, verify_replay_counted};

const P02: &str = "FY2026-P02";

fn hold(k: &Kernel, key: &str, amount: i128) -> EntryPayload {
    let intent = trunk_intent(
        key,
        vec![
            leg(fa_reference::Side::Debit, "6000", amount),
            leg(fa_reference::Side::Credit, "1000", amount),
        ],
    );
    let mut proposal = chunk_payload(k, VId(0), &intent, Shape::NoRun, None);
    proposal.class = EntryClass::PENDING;
    proposal.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    proposal
}

fn release(
    original: &EntryPayload,
    target: EntryRef,
    key: &str,
    posts: Option<i128>,
) -> EntryPayload {
    let mut proposal = original.clone();
    proposal.class = EntryClass::RESOLUTION;
    proposal.idempotency_key = key.as_bytes().to_vec();
    let disposition = if let Some(amount) = posts {
        // One debit and one credit from an original that can have multiple
        // legs sharing a cell. Every omitted or unused amount is released.
        let credit = proposal.legs.len() / 2;
        proposal.legs = vec![proposal.legs[0].clone(), proposal.legs[credit].clone()];
        for leg in &mut proposal.legs {
            leg.amount.mantissa = amount;
        }
        proposal.effective_date = DateDay::from_ymd(2026, 2, 15).unwrap();
        Disposition::Posts {
            source_ordinals: vec![0, u16::try_from(credit).unwrap()],
        }
    } else {
        proposal.legs.clear();
        proposal.control = Some(ControlPayload::ReservationRelease);
        Disposition::Voids
    };
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    proposal.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: Some(target),
        disposition: Some(disposition),
    });
    proposal
}

fn tick(k: &mut Kernel, observed_utc_ns: u64) {
    let request = TickRequest {
        observed_utc_ns,
        source: fa_journal::sweep::SOURCE_DAEMON_CLOCK,
        monotonic_ok: true,
        principal_ref: PRINCIPAL,
        capability: capability(&["witness"]),
        idempotency_key: format!("replay-release-tick-{observed_utc_ns}").into_bytes(),
        description: sealed(&k.book, "replay release tick"),
    };
    let ctx = k.ctx();
    k.runtime
        .block_on(record_tick(&mut k.db, &ctx, &k.book, request))
        .unwrap()
        .unwrap();
}

fn expire(k: &mut Kernel) -> Option<SweepBatch> {
    let system = fa_journal::rows::system_principal(k.book.book_id);
    let request = SweepRequest {
        principal_ref: system,
        capability: Capability::new(system, Profile::System, &[Op::Post], system).unwrap(),
        max_batch: 8,
    };
    let ctx = k.ctx();
    let book = &k.book;
    let mut describe = |text: &str| Ok(sealed(book, text));
    k.runtime
        .block_on(sweep_batch(&mut k.db, &ctx, book, &request, &mut describe))
        .unwrap()
        .unwrap()
}

fn checked(k: &mut Kernel, prefixes: &[(CommitSeq, usize)]) -> Vec<ReplayWork> {
    let frontier = k.db.frontier().unwrap();
    let mut scratch = empty_scratch(k);
    let map = replay(k, &mut scratch, frontier).unwrap();
    let mut results = Vec::new();
    for &(prefix, releases) in prefixes {
        let selected = SeqMap {
            source_book: map.source_book,
            source_prefix: prefix,
            pairs: map
                .pairs
                .iter()
                .filter(|pair| pair.source_seq <= prefix)
                .cloned()
                .collect(),
        };
        let (verdict, work) = verify_replay_counted(&k.db, &scratch, &k.book, &selected).unwrap();
        assert_eq!(
            Ok(verdict.unwrap()),
            literal_replay_pairs(k, &scratch, &selected),
            "every mapped prefix has the literal verdict"
        );
        let entries = fa_registers::entries_at(&k.db, &k.book, prefix).unwrap();
        eprintln!("release replay prefix={prefix:?} releases={releases} work={work:?}");
        assert_eq!(work.identities_compared, 2 * entries.len());
        assert_eq!(
            work.full_fold_pairs, 1,
            "only the initial empty prefix refolds"
        );
        assert_eq!(work.resolved_holds, 2 * releases);
        for side in [&work.source, &work.scratch] {
            assert_eq!(side.full_reads, 1);
            assert_eq!(side.entries_decoded, entries.len());
        }
        results.push(work);
    }
    assert_eq!(
        k.db.frontier().unwrap(),
        frontier,
        "verification never writes the source"
    );
    results
}

#[test]
fn replay_verification_releases_native_holds_without_full_refolds() {
    let (mut k, _) = setup();
    transition(&mut k, P02, PeriodTransition::Open, "release-open-february");
    let survivor = hold(&k, "surviving-reservation", 7);
    kernel_post(&mut k, survivor, &["post"], false).unwrap();
    let mut prefixes = Vec::new();
    for index in 0..12usize {
        let mut original = hold(&k, &format!("release-history-hold-{index}"), 500);
        // Two legs on each cell: releasing subtracts every leg but decrements
        // each cell's entry count once. A different hold keeps both rows live.
        original.legs = vec![
            original.legs[0].clone(),
            original.legs[0].clone(),
            original.legs[1].clone(),
            original.legs[1].clone(),
        ];
        for leg in &mut original.legs {
            leg.amount.mantissa = 250;
        }
        original.unit_totals = EntryPayload::fold_unit_totals(&original.legs).unwrap();
        if index % 3 == 2 {
            tick(&mut k, 1_000 + (index as u64) * 20);
            original.pending.as_mut().unwrap().timeout_ns = Some(10);
        }
        let held = kernel_post(&mut k, original.clone(), &["post"], false).unwrap();
        post_replay_native(&mut k, 300 + index);
        if index % 3 == 2 {
            tick(&mut k, 1_010 + (index as u64) * 20);
            let expired = expire(&mut k).expect("the native timed hold expires");
            assert_eq!(expired.expired.len(), 1);
            assert_eq!(expired.expired[0].0, held.entry_ref());
            let before = k.db.frontier().unwrap();
            assert!(expire(&mut k).is_none());
            assert_eq!(
                k.db.frontier().unwrap(),
                before,
                "sweep retry adds no release"
            );
        } else {
            let resolution = release(
                &original,
                held.entry_ref(),
                &format!("release-history-resolution-{index}"),
                index.is_multiple_of(3).then_some(125),
            );
            let posted = kernel_post(&mut k, resolution.clone(), &["post"], false).unwrap();
            let before = k.db.frontier().unwrap();
            let retry = kernel_post(&mut k, resolution, &["post"], false).unwrap();
            assert_eq!(retry.entry_ref(), posted.entry_ref());
            assert_eq!(
                k.db.frontier().unwrap(),
                before,
                "idempotent retry releases once"
            );
        }
        if matches!(index, 3 | 7 | 11) {
            prefixes.push((k.db.frontier().unwrap(), index + 1));
        }
        let fold = fold_period_at(&k.db, &k.book, P01, None).unwrap();
        assert_eq!(fold.pending.len(), 2);
        assert!(fold.pending.iter().all(|cell| cell.entry_count == 1));
        assert_eq!(fold.pending.iter().map(|cell| cell.debits).sum::<i128>(), 7);
        assert_eq!(
            fold.pending.iter().map(|cell| cell.credits).sum::<i128>(),
            7
        );
    }
    let february = fold_period_at(&k.db, &k.book, P02, None).unwrap();
    assert!(february.pending.is_empty());
    assert_eq!(february.entries, 4);
    assert_eq!(
        february.cells.iter().map(|cell| cell.debits).sum::<i128>(),
        500
    );
    assert_eq!(
        february.cells.iter().map(|cell| cell.credits).sum::<i128>(),
        500
    );
    let work = checked(&mut k, &prefixes);
    for (result, (_, releases)) in work.iter().zip(&prefixes) {
        assert_eq!(
            result.released_legs,
            8 * releases,
            "four original legs once per side"
        );
    }
    for pair in work.windows(2) {
        assert_eq!(pair[1].released_legs - pair[0].released_legs, 8 * 4);
        assert_eq!(pair[1].resolved_holds - pair[0].resolved_holds, 2 * 4);
    }
}

#[test]
fn replay_verification_releases_before_additions_in_one_atomic_batch() {
    let (mut k, _) = setup();
    let original = hold(&k, "old-max-reservation", i128::MAX);
    let held = kernel_post(&mut k, original.clone(), &["post"], false).unwrap();
    let replacement = hold(&k, "one-cent-reservation", 1);
    let old_release = release(&original, held.entry_ref(), "release-old-max", None);

    // The native batch stages the hold first. Its immutable identities sort
    // the resolution first in the selected journal, so the verifier must use
    // the complete same-commit target set rather than VId order as causality.
    let (temporary, temporary_ref) = (0..64)
        .find_map(|index| {
            let proposal = hold(&k, &format!("temporary-max-{index}"), i128::MAX);
            let vid = fa_model::entry_vid(
                k.book.book_id,
                &PRINCIPAL.0.to_le_bytes(),
                &proposal.idempotency_key,
            );
            let reference = proposal
                .clone()
                .seal(Vec::new(), None)
                .unwrap()
                .entry_ref(vid);
            (fa_journal::rows::resolution_vid(vid) < vid).then_some((proposal, reference))
        })
        .expect("a deterministic key with resolution-before-hold identity order");
    let temporary_release = release(&temporary, temporary_ref, "release-temporary-max", None);
    let members = vec![replacement, old_release, temporary, temporary_release]
        .into_iter()
        .map(|proposal| PostIntent::new(proposal, Vec::new()).unwrap())
        .collect();
    let batch = PostBatch::new(b"release-and-reserve-atomically".to_vec(), members).unwrap();
    let ctx = k.ctx();
    let published = k
        .runtime
        .block_on(post_batch(
            &mut k.db,
            &ctx,
            &k.book,
            capability(&["post"]),
            batch,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(published.entries.len(), 4);
    let fold = fold_period_at(&k.db, &k.book, P01, None).unwrap();
    assert!(fold.cells.is_empty());
    assert_eq!(fold.pending.len(), 2);
    assert!(fold.pending.iter().all(|cell| cell.entry_count == 1));
    assert_eq!(fold.pending.iter().map(|cell| cell.debits).sum::<i128>(), 1);
    let head = k.db.frontier().unwrap();
    let work = checked(&mut k, &[(head, 2)]).pop().unwrap();
    assert_eq!(
        work.released_legs, 4,
        "only the old hold was previously counted"
    );
    assert_eq!(
        work.appended_legs, 8,
        "same-commit temporary MAX never enters a cell"
    );
}

fn inject(k: &mut Kernel, vid: VId, entry: &Entry) {
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(
        vid,
        vec![label::ENTRY],
        fa_model::entry_mirrors(entry).unwrap(),
    );
    write_raw(k, batch);
}

#[test]
fn replay_verification_malformed_resolutions_keep_the_literal_first_error() {
    for planted in [
        "missing-target",
        "wrong-digest",
        "wrong-class",
        "wrong-identity",
        "duplicate",
    ] {
        let (mut k, _) = setup();
        let original = hold(&k, "malformed-release-hold", 500);
        let held = kernel_post(&mut k, original.clone(), &["post"], false).unwrap();
        let mut target = held.entry_ref();
        match planted {
            "missing-target" => target.vid = VId(0x7a11_1000),
            "wrong-digest" => target.entry_digest[0] ^= 1,
            "wrong-class" => target = post_replay_native(&mut k, 400).entry_ref(),
            "duplicate" => {
                let first = release(&original, target, "first-real-release", None);
                kernel_post(&mut k, first, &["post"], false).unwrap();
            }
            _ => {}
        }
        let proposal = release(&original, target, "planted-release", None);
        let entry = proposal.seal(Vec::new(), None).unwrap();
        let vid = if matches!(planted, "wrong-identity" | "duplicate") {
            VId(0x7a11_2000)
        } else {
            fa_journal::rows::resolution_vid(target.vid)
        };
        inject(&mut k, vid, &entry);
        let head = k.db.frontier().unwrap();
        let mut scratch = empty_scratch(&k);
        let map = replay(&mut k, &mut scratch, head).unwrap();
        let expected = literal_replay_pairs(&k, &scratch, &map);
        assert!(
            expected.as_ref().unwrap_err().contains("resolution"),
            "{planted}: {expected:?}"
        );
        let actual = replay_result(fa_registers::replay::verify_replay(
            &k.db, &scratch, &k.book, &map,
        ));
        assert_eq!(
            actual, expected,
            "{planted}: same first error at the same pair"
        );
    }
}

#[test]
fn replay_verification_rejects_changed_resolution_payloads_even_after_hash_repair() {
    let (mut k, _) = setup();
    transition(
        &mut k,
        P02,
        PeriodTransition::Open,
        "changed-release-open-february",
    );
    let original = hold(&k, "changed-release-hold", 500);
    let held = kernel_post(&mut k, original.clone(), &["post"], false).unwrap();
    let resolved = kernel_post(
        &mut k,
        release(&original, held.entry_ref(), "changed-release", Some(250)),
        &["post"],
        false,
    )
    .unwrap();
    let head = k.db.frontier().unwrap();
    let mut scratch = empty_scratch(&k);
    let mut map = replay(&mut k, &mut scratch, head).unwrap();
    let original_bytes = fa_journal::rows::bytes(
        &scratch.vertex(resolved.entry_ref().vid).unwrap().unwrap(),
        property::FA_PAYLOAD,
        "resolution.payload",
    )
    .unwrap();
    let mut changed = Entry::decode(&original_bytes).unwrap();
    for leg in &mut changed.proposal.legs {
        leg.amount.mantissa = 125;
    }
    changed.proposal.unit_totals = EntryPayload::fold_unit_totals(&changed.proposal.legs).unwrap();
    let changed = changed
        .proposal
        .seal(changed.approvals, changed.plan_certificate)
        .unwrap();
    for (round, bytes) in [changed.encode().unwrap(), original_bytes]
        .into_iter()
        .enumerate()
    {
        let mut metadata = WriteBatch::new(relation::IN_BOOK);
        metadata.set_vertex_property(
            fa_journal::rows::book_root(),
            property::NAME,
            Some(
                fa_journal::rows::scalar_text(
                    "book.name",
                    &format!("changed resolution probe {round}"),
                )
                .unwrap(),
            ),
        );
        write_raw(&mut k, metadata.clone());
        metadata.set_vertex_property(
            resolved.entry_ref().vid,
            property::FA_PAYLOAD,
            Some(fa_journal::rows::scalar_bytes("resolution.payload", bytes).unwrap()),
        );
        let ctx = k.ctx();
        k.runtime
            .block_on(scratch.write(&ctx.commit(), metadata))
            .unwrap();
        let source_seq = k.db.frontier().unwrap();
        map.source_prefix = source_seq;
        map.pairs.push(SeqPair {
            source_seq,
            source_marker: k
                .db
                .delta_since(CommitSeq(source_seq.0 - 1))
                .unwrap()
                .next()
                .unwrap()
                .commit_marker_identity()
                .marker_oid
                .0,
            scratch_seq: scratch.frontier().unwrap(),
        });
    }
    let expected = literal_replay_pairs(&k, &scratch, &map);
    assert!(expected.as_ref().unwrap_err().contains("different entries"));
    assert_eq!(
        replay_result(fa_registers::replay::verify_replay(
            &k.db, &scratch, &k.book, &map
        )),
        expected,
        "restoring a valid head does not hide the earlier changed release"
    );
}
