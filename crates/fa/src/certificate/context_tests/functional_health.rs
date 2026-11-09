//! Functional cache integrity and currentness are separate public observations.

use super::*;

fn verify(h: &mut Harness, at: Option<CommitSeq>) -> maintained::Verification {
    let cx = h.cx();
    h.runtime
        .block_on(h.book.verify_functional_registers(
            &cx,
            PRINCIPAL,
            &cap(&["read", "verify"]),
            PERIOD,
            at,
        ))
        .unwrap()
        .unwrap()
}

#[test]
fn functional_currentness_counts_entries_not_cache_or_document_commits() {
    let (mut h, mut rate) = fixture();
    let original_at = h.head();
    let absent = verify(&mut h, None);
    assert!(absent.is_green() && !absent.available && absent.stale);
    assert!(absent.through.is_none() && absent.lag_entries > 0);
    assert_eq!(h.head(), original_at);

    let first = advance(&mut h);
    let published = h.head();
    assert!(published > first.through);
    let current = verify(&mut h, None);
    assert!(current.is_green() && current.available && !current.stale);
    assert_eq!(
        (current.through, current.lag_entries),
        (Some(first.through), 0)
    );

    // A retained Rate document changes the database frontier, but creates no
    // Entry for the maintained projection to consume.
    let cx = h.cx();
    rate.source = "functional health document without a journal entry".into();
    let document = Document {
        book_id: BOOK,
        kind: RATE_DOCUMENT_KIND,
        mime: "application/vnd.fa.fx-rate".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: rate.canonical_bytes().unwrap(),
    };
    h.runtime
        .block_on(h.book.add_document(&cx, &document))
        .unwrap()
        .unwrap();
    let after_document = h.head();
    assert!(after_document > published);
    let current = verify(&mut h, None);
    assert!(!current.stale && current.is_green());
    assert_eq!(current.lag_entries, 0);

    let extra = proposal(&h, b"functional-health-unread-entry", 700);
    post(&mut h, extra);
    let before_verify = h.head();
    let lagging = verify(&mut h, None);
    assert!(lagging.available && lagging.is_green() && lagging.stale);
    assert_eq!(lagging.lag_entries, 1);
    assert_eq!(lagging.through, Some(first.through));
    let historical = verify(&mut h, Some(after_document));
    assert!(historical.available && historical.is_green() && !historical.stale);
    assert_eq!(historical.lag_entries, 0);
    assert_eq!(
        h.head(),
        before_verify,
        "verification never advances a cache"
    );

    // One cohort retains caller order and distinguishes an absent period
    // from an available stale one at the same selected observation.
    let cohort = h
        .runtime
        .block_on(h.book.verify_functional_registers_each(
            &cx,
            PRINCIPAL,
            &cap(&["read", "verify"]),
            &["FY2026-P02", PERIOD],
            None,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(cohort.len(), 2);
    assert!(!cohort[0].available && cohort[0].stale && cohort[0].is_green());
    assert!(cohort[0].lag_entries > cohort[1].lag_entries);
    assert!(cohort[1].available && cohort[1].stale && cohort[1].is_green());
    assert_eq!(cohort[1].lag_entries, 1);
    advance(&mut h);
    let caught_up = verify(&mut h, None);
    assert!(caught_up.is_green() && !caught_up.stale);
    assert_eq!(caught_up.lag_entries, 0);
    assert!(verify(&mut h, Some(original_at)).through.is_none());
}

#[test]
fn functional_currentness_includes_controls_and_cross_period_hold_release() {
    let (mut h, _) = fixture();
    let held = held_proposal(&h, b"functional-health-hold", 100);
    let target = post(&mut h, held.clone()).entry_ref();
    advance(&mut h);
    let held_at = h.head();
    let cx = h.cx();
    h.runtime
        .block_on(h.book.transition_period(
            &cx,
            "FY2026-P02",
            PeriodTransition::Open,
            PRINCIPAL,
            1,
            b"functional-health-open-february",
            &cap(&["close"]),
        ))
        .unwrap()
        .unwrap();
    let control_only = verify(&mut h, None);
    assert!(control_only.is_green() && control_only.stale);
    assert_eq!(control_only.lag_entries, 1);
    let mut release = release_proposal(held, target, b"functional-health-release");
    release.effective_date = DateDay::from_ymd(2026, 2, 5).unwrap();
    post(&mut h, release);
    let lagging = verify(&mut h, None);
    assert!(lagging.is_green() && lagging.stale);
    assert_eq!(lagging.lag_entries, 2);
    let old = verify(&mut h, Some(held_at));
    assert!(old.is_green() && !old.stale);
    assert_eq!(old.lag_entries, 0);
    let advanced = advance(&mut h);
    assert_eq!(advanced.entries_decoded, 2);
    assert!(advanced.fold.pending.is_empty());
    let verified = verify(&mut h, None);
    assert!(verified.is_green() && !verified.stale);
    assert_eq!(verified.lag_entries, 0);
}

#[test]
fn functional_prefix_entry_rewrite_is_drift_instead_of_new_work() {
    let (mut h, _) = fixture();
    advance(&mut h);
    let intact = h.head();
    let entry = fa_model::entry_vid(BOOK, &PRINCIPAL.0.to_le_bytes(), b"symbol-post");
    let cx = h.cx();
    let mut corrupt = WriteBatch::new(relation::IN_BOOK);
    corrupt.set_vertex_property(
        entry,
        property::FA_DIGEST,
        Some(scalar_bytes("rewritten Entry identity", vec![0; 32]).unwrap()),
    );
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), corrupt))
        .unwrap();
    let before_verify = h.head();
    let damaged =
        maintained::verify(&h.book.db, &cx.query(), h.book.context(), PERIOD, None).unwrap();
    assert!(damaged.available && !damaged.is_green() && !damaged.stale);
    assert_eq!(damaged.lag_entries, 0);
    assert!(
        damaged
            .drift
            .iter()
            .any(|finding| finding.contains("changed or disappeared"))
    );
    let original = maintained::verify(
        &h.book.db,
        &cx.query(),
        h.book.context(),
        PERIOD,
        Some(intact),
    )
    .unwrap();
    assert!(original.is_green() && !original.stale);
    assert_eq!(h.head(), before_verify);
}

#[test]
fn functional_cache_drift_cannot_be_presented_as_ordinary_lag() {
    let (mut h, _) = fixture();
    let first = advance(&mut h);
    let intact = h.head();
    let root = maintained::checkpoint_vid(BOOK, PERIOD, first.checkpoint.unwrap());
    let extra = proposal(&h, b"functional-health-lag-before-damage", 80);
    post(&mut h, extra);
    let cx = h.cx();
    let mut corrupt = WriteBatch::new(relation::IN_PERIOD);
    corrupt.set_vertex_property(
        root,
        property::FA_PAYLOAD,
        Some(scalar_bytes("broken functional health cache", vec![0]).unwrap()),
    );
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), corrupt))
        .unwrap();
    let before_verify = h.head();
    let damaged = verify(&mut h, None);
    assert!(damaged.available && !damaged.is_green() && !damaged.stale);
    assert!(!damaged.drift.is_empty());
    let historical = verify(&mut h, Some(intact));
    assert!(historical.is_green() && !historical.stale);
    assert_eq!(h.head(), before_verify);

    h.root.cancel_with(
        asupersync::CancelKind::User,
        Some("cancelled functional health verification"),
    );
    let cancelled = h.cx();
    assert!(
        h.runtime
            .block_on(h.book.verify_functional_registers_each(
                &cancelled,
                PRINCIPAL,
                &cap(&["read", "verify"]),
                &[PERIOD, "FY2026-P02"],
                None,
            ))
            .is_err()
    );
}
