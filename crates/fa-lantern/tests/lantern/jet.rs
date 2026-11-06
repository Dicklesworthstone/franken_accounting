//! Journal-entry findings over native postings: evidence provenance (fa-81lu)
//! and the registered debit/credit account-pair population (fa-3afh).

use super::*;
use fa_journal::attestation::record_review;
use fa_journal::evidence::{SupplementalEvidence, attach_evidence};
use fa_lantern::jet::{SelfSourcedEvidence, UnusualAccounts};
use fa_lantern::{default_budget, run_over_metered};
use fa_model::EntryRef;

/// evidence_policy.toml's `AgentUpload` grade (self-sourced).
const AGENT_UPLOAD: u8 = 4;

/// Records a document of `grade` that `by` brought in; its citation in
/// role 1.
fn document(h: &mut Harness, grade: u8, by: VId, text: &[u8]) -> EvidenceRef {
    let doc = Document {
        book_id: h.book.book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade,
        retrieved_by: by,
        bytes: text.to_vec(),
    };
    let ctx = h.ctx();
    let (db, book) = (&mut h.db, &h.book);
    h.runtime
        .block_on(async { add_document(db, &ctx, book, &doc).await })
        .expect("kernel")
        .expect("admitted");
    doc.evidence_ref(1)
}

/// `reviewer` records a Reviewed attestation over `document`.
fn review(h: &mut Harness, reviewer: VId, document: Oid) {
    let capability = Capability::embedded(reviewer, &["approve"]).expect("approve");
    let ctx = h.ctx();
    let (db, book) = (&mut h.db, &h.book);
    h.runtime
        .block_on(async {
            record_review(
                db,
                &ctx,
                book,
                &capability,
                None,
                reviewer,
                document,
                Vec::new(),
            )
            .await
        })
        .expect("kernel")
        .expect("admitted");
}

/// The preparer attaches `documents` to the committed `entry`.
fn attach(h: &mut Harness, entry: VId, documents: Vec<EvidenceRef>) {
    let snapshot = Snapshot::read(&h.db, &h.ctx().query(), &h.book, None, None).unwrap();
    let entry_digest = snapshot
        .entries
        .iter()
        .find(|e| e.vid == entry)
        .expect("posted")
        .entry
        .entry_digest;
    let supplement = SupplementalEvidence {
        book_id: h.book.book_id,
        entry_ref: EntryRef {
            vid: entry,
            entry_digest,
        },
        documents,
        attached_by: PREPARER,
    };
    let capability = Capability::embedded(PREPARER, &["post"]).expect("post");
    let ctx = h.ctx();
    let (db, book) = (&mut h.db, &h.book);
    h.runtime
        .block_on(async { attach_evidence(db, &ctx, book, &capability, &supplement).await })
        .expect("kernel")
        .expect("admitted");
}

fn flagged(run: &ProcedureRun) -> Vec<VId> {
    let entries: Vec<VId> = run
        .findings
        .iter()
        .filter_map(|f| match f.cites.first() {
            Some(Cite::Entry(v)) => Some(*v),
            _ => None,
        })
        .collect();
    assert_eq!(
        entries.len(),
        run.findings.len(),
        "a finding cites its entry first"
    );
    entries
}

fn retained_jet(id: &str, version: u16) -> Box<dyn Procedure> {
    fa_lantern::catalog::build_version(
        id,
        version,
        Params::defaults(id).unwrap(),
        fa_lantern::catalog::Inputs::default(),
    )
    .unwrap()
}

/// Journal an exact reversal through the native posting boundary, including
/// reversals of reversals; no snapshot mutation supplies its recorded time.
fn reverse_at(h: &mut Harness, target: VId, date: DateDay) -> VId {
    let (original, _) = read_entry(&h.db, target).unwrap().unwrap();
    let mut proposal = h.proposal(&Spec::simple(date, "6000", "1000", 1));
    proposal.class = EntryClass::REVERSAL;
    proposal.legs = original.proposal.legs.clone();
    for leg in &mut proposal.legs {
        leg.side = match leg.side {
            Side::Debit => Side::Credit,
            Side::Credit => Side::Debit,
        };
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    proposal.supersession = vec![fa_model::Supersession {
        target: EntryRef {
            vid: target,
            entry_digest: original.entry_digest,
        },
        kind: SupersessionKind::Reverses,
        reason_code: 1,
    }];
    let request = PostRequest {
        proposal,
        approvals: Vec::new(),
        plan_certificate: None,
        capability: Capability::embedded(PREPARER, &["post"]).unwrap(),
    };
    let contexts = h.ctx();
    let posted = h
        .runtime
        .block_on(post(&mut h.db, &contexts, &h.book, request))
        .expect("native reversal publication")
        .expect("the exact reversal is admitted");
    let Posted::Committed {
        entry_ref,
        recorded_at,
        ..
    } = posted
    else {
        panic!("the fresh reversal must commit");
    };
    h.posted.push((entry_ref.vid, recorded_at));
    entry_ref.vid
}

/// A correction is one native commit, even when its two members take effect
/// on different days. Selection must not confuse either date with publication.
fn replace_at(
    h: &mut Harness,
    target: VId,
    reversal_date: DateDay,
    replacement_date: DateDay,
    cents: i128,
) -> (VId, VId) {
    let (original, _) = read_entry(&h.db, target).unwrap().unwrap();
    let target = EntryRef {
        vid: target,
        entry_digest: original.entry_digest,
    };
    let mut reversal = h.proposal(&Spec::simple(reversal_date, "6000", "1000", 1));
    reversal.class = EntryClass::REVERSAL;
    reversal.legs = original.proposal.legs.clone();
    for leg in &mut reversal.legs {
        leg.side = match leg.side {
            Side::Debit => Side::Credit,
            Side::Credit => Side::Debit,
        };
    }
    reversal.unit_totals = EntryPayload::fold_unit_totals(&reversal.legs).unwrap();
    reversal.supersession = vec![fa_model::Supersession {
        target,
        kind: SupersessionKind::Reverses,
        reason_code: 1,
    }];
    let mut replacement = h.proposal(&Spec::simple(replacement_date, "6000", "1000", cents));
    replacement.class = EntryClass::REPLACEMENT;
    replacement.supersession = vec![fa_model::Supersession {
        target,
        kind: SupersessionKind::Replaces,
        reason_code: 1,
    }];
    let request = |proposal| PostRequest {
        proposal,
        approvals: Vec::new(),
        plan_certificate: None,
        capability: Capability::embedded(PREPARER, &["post"]).unwrap(),
    };
    let before = h.db.frontier().unwrap();
    let contexts = h.ctx();
    let (reversal, replacement) = h
        .runtime
        .block_on(fa_journal::post::post_replacement_pair(
            &mut h.db,
            &contexts,
            &h.book,
            request(reversal),
            request(replacement),
            None,
        ))
        .expect("native correction publication")
        .expect("the exact reversal and corrected entry are admitted together");
    assert!(matches!(reversal, Posted::Committed { .. }));
    assert!(matches!(replacement, Posted::Committed { .. }));
    assert_eq!(reversal.recorded_at(), replacement.recorded_at());
    assert_eq!(replacement.recorded_at().0, before.0 + 1);
    for member in [&reversal, &replacement] {
        h.posted
            .push((member.entry_ref().vid, member.recorded_at()));
    }
    (reversal.entry_ref().vid, replacement.entry_ref().vid)
}

#[test]
fn versioned_jet_effective_cutoffs_are_inclusive_without_truncating_source_entries() {
    let mut h = harness();
    h.post(&Spec::simple(day(2026, 3, 15), "6000", "1000", 123));
    let before = h.post(&Spec::simple(day(2026, 3, 29), "6000", "1000", 100_000));
    let boundary = h.post(&Spec::simple(day(2026, 3, 30), "6000", "1000", 200_000));
    let after = h.post(&Spec::simple(day(2026, 3, 31), "6000", "1000", 300_000));
    h.transition("FY2026-P04", PeriodTransition::SoftClose, b"future-control");
    let frontier = h.db.frontier().unwrap();
    let snapshot = Snapshot::read(
        &h.db,
        &h.ctx().query(),
        &h.book,
        Some(frontier),
        Some(day(2026, 3, 30)),
    )
    .unwrap();
    let all_dates = Snapshot::read(&h.db, &h.ctx().query(), &h.book, Some(frontier), None).unwrap();
    assert_eq!(snapshot.entries.len(), all_dates.entries.len());
    assert!(
        snapshot.entries.len() > h.posted.len(),
        "book controls remain in the source"
    );
    assert!(
        snapshot.entries.iter().any(|entry| {
            entry.entry.proposal.legs.is_empty()
                && entry.entry.proposal.effective_date > day(2026, 3, 30)
        }),
        "the source retains the future period control"
    );
    assert!(snapshot.entries.iter().any(|entry| entry.vid == after));

    for id in [RoundAmounts::ID, PeriodEndTiming::ID] {
        let current = retained_jet(id, 2);
        let selected = run_over(&snapshot, &h.book, current.as_ref()).unwrap();
        assert_eq!(selected.version, 2);
        assert_eq!(selected.population, snapshot.entries.len() as u64);
        assert_eq!(
            selected.work.entries, 3,
            "three live postings are on or before the cutoff"
        );
        assert_eq!(
            flagged(&selected).into_iter().collect::<BTreeSet<_>>(),
            BTreeSet::from([before, boundary])
        );
        for finding in &selected.findings {
            assert_eq!(finding.version, 2);
            let entry = match finding.cites[0] {
                Cite::Entry(entry) => entry,
                _ => panic!("entry citation"),
            };
            assert_eq!(
                finding.statistic,
                if id == RoundAmounts::ID {
                    Statistic::count("round_legs", 2, 6)
                } else {
                    Statistic::count("days_to_period_end", u64::from(entry == before) + 1, 3)
                }
            );
        }
        h.assert_cites_resolve(&selected);
        assert!(
            determinism(&snapshot, &h.book, current.as_ref())
                .unwrap()
                .deterministic()
        );

        let historic = retained_jet(id, 1);
        let legacy = run_over(&snapshot, &h.book, historic.as_ref()).unwrap();
        assert_eq!(legacy.version, 1);
        assert_eq!(legacy.work.entries, 4);
        assert_eq!(
            flagged(&legacy).into_iter().collect::<BTreeSet<_>>(),
            BTreeSet::from([before, boundary, after])
        );

        let current_all = run_over(&all_dates, &h.book, current.as_ref()).unwrap();
        let legacy_all = run_over(&all_dates, &h.book, historic.as_ref()).unwrap();
        let mut normalized = current_all.findings.clone();
        for finding in &mut normalized {
            finding.version = 1;
        }
        assert_eq!(
            normalized, legacy_all.findings,
            "without a cutoff the selected findings retain v1 semantics"
        );
        assert_eq!(current_all.work, legacy_all.work);
        assert_eq!(current_all.population, legacy_all.population);
    }
    assert_eq!(
        h.db.frontier().unwrap(),
        frontier,
        "procedures publish nothing"
    );
}

#[test]
fn versioned_jet_applies_cutoffs_before_reversal_parity_and_preserves_known_at() {
    let mut h = harness();
    let original = h.post(&Spec::simple(day(2026, 1, 31), "6000", "1000", 100_000));
    let original_at = h.db.frontier().unwrap();
    let reversed = reverse_at(&mut h, original, day(2026, 2, 1));
    let reversed_at = h.db.frontier().unwrap();
    reverse_at(&mut h, reversed, day(2026, 2, 2));
    let restored_at = h.db.frontier().unwrap();

    for id in [RoundAmounts::ID, PeriodEndTiming::ID] {
        let current = retained_jet(id, 2);
        let historic = retained_jet(id, 1);
        for (known_at, cutoff, expected) in [
            (restored_at, day(2026, 1, 30), false),
            (restored_at, day(2026, 1, 31), true),
            (restored_at, day(2026, 2, 1), false),
            (restored_at, day(2026, 2, 2), true),
            (original_at, day(2026, 2, 2), true),
            (reversed_at, day(2026, 2, 2), false),
            (reversed_at, day(2026, 1, 31), true),
        ] {
            let result = run(
                &h.db,
                &h.ctx().query(),
                &h.book,
                Some(known_at),
                Some(cutoff),
                current.as_ref(),
            )
            .unwrap();
            assert_eq!(result.coordinate.known_at, known_at);
            assert_eq!(result.coordinate.effective_through, Some(cutoff));
            assert_eq!(
                flagged(&result),
                if expected { vec![original] } else { vec![] },
                "{id}: known_at={} cutoff={cutoff}",
                known_at.0
            );
            assert_eq!(result.work.entries, u64::from(expected));
        }
        let before_future_reversal = run(
            &h.db,
            &h.ctx().query(),
            &h.book,
            Some(reversed_at),
            Some(day(2026, 1, 31)),
            historic.as_ref(),
        )
        .unwrap();
        assert!(
            before_future_reversal.findings.is_empty(),
            "retained v1 still nets its all-date population"
        );
        let before_future_restoration = run(
            &h.db,
            &h.ctx().query(),
            &h.book,
            Some(restored_at),
            Some(day(2026, 2, 1)),
            historic.as_ref(),
        )
        .unwrap();
        assert_eq!(
            flagged(&before_future_restoration),
            vec![original],
            "retained v1 still sees the later reverse-of-reversal"
        );
    }
    assert_eq!(h.db.frontier().unwrap(), restored_at);
}

#[test]
fn versioned_jet_selects_replacement_chains_at_recorded_and_effective_boundaries() {
    let mut h = harness();
    let original = h.post(&Spec::simple(day(2026, 1, 30), "6000", "1000", 100_000));
    let original_at = h.db.frontier().unwrap();
    let (_, first) = replace_at(
        &mut h,
        original,
        day(2026, 2, 27),
        day(2026, 2, 28),
        200_000,
    );
    let first_at = h.db.frontier().unwrap();
    let (_, second) = replace_at(&mut h, first, day(2026, 3, 29), day(2026, 3, 30), 300_000);
    let second_at = h.db.frontier().unwrap();
    let undo = reverse_at(&mut h, second, day(2026, 4, 29));
    let undone_at = h.db.frontier().unwrap();
    reverse_at(&mut h, undo, day(2026, 4, 30));
    let restored_at = h.db.frontier().unwrap();

    for (known_at, cutoff, expected) in [
        (original_at, day(2026, 4, 30), Some(original)),
        (first_at, day(2026, 2, 26), Some(original)),
        (first_at, day(2026, 2, 27), None),
        (first_at, day(2026, 2, 28), Some(first)),
        (second_at, day(2026, 2, 28), Some(first)),
        (second_at, day(2026, 3, 29), None),
        (second_at, day(2026, 3, 30), Some(second)),
        (undone_at, day(2026, 4, 28), Some(second)),
        (undone_at, day(2026, 4, 29), None),
        (restored_at, day(2026, 4, 29), None),
        (restored_at, day(2026, 4, 30), Some(second)),
        (restored_at, day(2026, 2, 26), Some(original)),
    ] {
        let snapshot = Snapshot::read(
            &h.db,
            &h.ctx().query(),
            &h.book,
            Some(known_at),
            Some(cutoff),
        )
        .unwrap();
        let selected: Vec<VId> = snapshot
            .live_postings_through(Some(cutoff))
            .unwrap()
            .iter()
            .map(|entry| entry.vid)
            .collect();
        assert_eq!(selected, expected.into_iter().collect::<Vec<_>>());
        for id in [RoundAmounts::ID, PeriodEndTiming::ID] {
            let result = run_over(&snapshot, &h.book, retained_jet(id, 2).as_ref()).unwrap();
            assert_eq!(result.population, snapshot.entries.len() as u64);
            assert_eq!(result.work.entries, u64::from(expected.is_some()));
            assert_eq!(
                flagged(&result),
                selected,
                "{id}: known_at={} cutoff={cutoff}",
                known_at.0
            );
            h.assert_cites_resolve(&result);
        }
    }
    assert_eq!(h.db.frontier().unwrap(), restored_at);
}

#[test]
fn versioned_jet_restores_a_replaced_target_only_when_its_replacement_is_not_live() {
    let mut h = harness();
    let original = h.post(&Spec::simple(day(2026, 1, 30), "6000", "1000", 100_000));
    let (undo, corrected) = replace_at(
        &mut h,
        original,
        day(2026, 2, 27),
        day(2026, 2, 28),
        200_000,
    );
    let paired_at = h.db.frontier().unwrap();
    reverse_at(&mut h, undo, day(2026, 3, 29));
    let revived_target_at = h.db.frontier().unwrap();
    let undo_corrected = reverse_at(&mut h, corrected, day(2026, 3, 30));
    let undone_replacement_at = h.db.frontier().unwrap();
    reverse_at(&mut h, undo_corrected, day(2026, 3, 31));
    let restored_replacement_at = h.db.frontier().unwrap();

    // Reversing a pair's negation revives the original by parity, but its
    // live correction still supersedes it. Reversing that correction lets
    // the revived original stand; restoring it suppresses the original again.
    for (known_at, cutoff, expected) in [
        (paired_at, day(2026, 3, 31), corrected),
        (revived_target_at, day(2026, 3, 29), corrected),
        (undone_replacement_at, day(2026, 3, 29), corrected),
        (undone_replacement_at, day(2026, 3, 30), original),
        (restored_replacement_at, day(2026, 3, 30), original),
        (restored_replacement_at, day(2026, 3, 31), corrected),
    ] {
        let snapshot = Snapshot::read(
            &h.db,
            &h.ctx().query(),
            &h.book,
            Some(known_at),
            Some(cutoff),
        )
        .unwrap();
        for id in [RoundAmounts::ID, PeriodEndTiming::ID] {
            let result = run_over(&snapshot, &h.book, retained_jet(id, 2).as_ref()).unwrap();
            assert_eq!(result.work.entries, 1);
            assert_eq!(
                flagged(&result),
                vec![expected],
                "{id}: known_at={} cutoff={cutoff}",
                known_at.0
            );
        }
    }
    assert_eq!(h.db.frontier().unwrap(), restored_replacement_at);
}

#[test]
fn retained_jet_versions_refuse_unknown_algorithms_without_fallback() {
    for id in [RoundAmounts::ID, PeriodEndTiming::ID] {
        for version in [0, 3, u16::MAX] {
            assert!(matches!(
                fa_lantern::catalog::build_version(id, version, Params::defaults(id).unwrap(), fa_lantern::catalog::Inputs::default()),
                Err(LanternError::Version { code, registry: 2, .. }) if code == version
            ));
            assert!(matches!(
                fa_lantern::bind_version(id, version),
                Err(LanternError::Version { code, registry: 2, .. }) if code == version
            ));
        }
        assert_eq!(retained_jet(id, 1).version(), 1);
        assert_eq!(retained_jet(id, 2).version(), 2);
    }
}

#[test]
fn period_end_timing_widens_civil_day_distances_before_comparing_the_window() {
    let mut h = harness();
    let posted = h.post(&Spec::simple(day(2026, 3, 15), "6000", "1000", 100));
    let mut source = h.snapshot();
    source.entries.retain(|entry| entry.vid == posted);
    source.coordinate.effective_through = None;
    // Exercise the public procedure snapshot boundary, starting with a real
    // posting. These altered snapshots are arithmetic inputs, not certificates
    // of posting admission at the extreme dates.
    for (start, end, effective, window, expected) in [
        (i32::MIN, i32::MAX, i32::MIN, 3, None),
        (i32::MIN, i32::MIN + 1, i32::MIN, 3, Some(0)),
        (i32::MAX - 4, i32::MAX, i32::MAX - 1, 3, Some(0)),
        (i32::MAX - 4, i32::MAX, i32::MAX - 3, 3, Some(2)),
        (i32::MAX - 4, i32::MAX, i32::MAX - 4, 3, None),
        (i32::MIN, i32::MAX, -1, i32::MAX, None),
        (i32::MIN, i32::MAX, 0, i32::MAX, Some(2_147_483_646)),
    ] {
        let calendar = FiscalCalendar::custom(
            "boundary",
            vec![fa_time::CustomYear {
                fiscal_year: 2026,
                bounds: vec![DateDay(start), DateDay(end)],
            }],
            0,
        )
        .unwrap();
        assert!(calendar.periods_for_year(2026).unwrap()[0].contains(DateDay(effective)));

        let mut snapshot = source.clone();
        snapshot.entries[0].entry.proposal.effective_date = DateDay(effective);
        let code = snapshot.entries[0].period.clone();
        let period = snapshot.periods.get_mut(&code).unwrap();
        period.start = DateDay(start);
        period.end = DateDay(end);
        let procedure = PeriodEndTiming::with(
            Params::defaults(PeriodEndTiming::ID)
                .unwrap()
                .set("window_days", i128::from(window))
                .unwrap(),
        );
        let result = run_over(&snapshot, &h.book, &procedure).unwrap();
        assert_eq!(result.work.entries, 1);
        assert_eq!(result.work.legs, 0);
        assert_eq!(
            flagged(&result),
            if expected.is_some() {
                vec![posted]
            } else {
                vec![]
            }
        );
        if let Some(days) = expected {
            assert_eq!(
                result.findings[0].statistic,
                Statistic::count("days_to_period_end", days, 1)
            );
            assert_eq!(
                result.findings[0].cites,
                vec![Cite::Entry(posted), Cite::Period(code.clone())]
            );
        }

        let rows = [naive::Row {
            index: 0,
            date: DateDay(effective),
            document_date: None,
            period: code,
            period_start: Some(DateDay(start)),
            period_end: DateDay(end),
            legs: Vec::new(),
            preparer: "P7".into(),
            approvers: Vec::new(),
            description_chars: None,
            external_ids: Vec::new(),
            recorded_after_close: false,
            reverses: None,
            replaces: None,
        }];
        assert_eq!(
            naive::period_end_timing(&rows, window),
            if expected.is_some() { vec![0] } else { vec![] }
        );
    }
}

#[test]
fn self_sourced_evidence_flags_agent_upload_only() {
    let mut h = harness();
    let person = h.evidence[0];
    let agent = document(
        &mut h,
        AGENT_UPLOAD,
        PREPARER,
        b"RECEIPT (an agent's upload)",
    );
    let late = document(
        &mut h,
        AGENT_UPLOAD,
        PREPARER,
        b"MEMO (an agent's later upload)",
    );
    // An Original needs one document; a self-sourced one counts once a
    // principal other than its uploader reviews it (FA-REF-086 before).
    review(&mut h, REVIEWER, agent.document_oid);
    let mut both = vec![person, agent];
    both.sort();

    h.evidence = vec![agent];
    let own = h.post(&Spec::simple(day(2026, 3, 9), "6000", "1000", 4_200));
    h.evidence = both;
    let mixed = h.post(&Spec::simple(day(2026, 3, 10), "6000", "1000", 4_300));
    h.evidence = vec![person];
    let independent = h.post(&Spec::simple(day(2026, 3, 11), "6000", "1000", 4_400));
    // A supplement of the agent's own leaves a person-supported entry alone.
    attach(&mut h, independent, vec![late]);

    let procedure = SelfSourcedEvidence::new().unwrap();
    let snapshot = Snapshot::read(&h.db, &h.ctx().query(), &h.book, None, None).unwrap();
    assert_eq!(snapshot.supplements[&independent][0].documents, vec![late]);
    let r = run_over(&snapshot, &h.book, &procedure).unwrap();
    h.assert_cites_resolve(&r);
    println!("self_sourced findings={:?}", r.findings);
    assert_eq!(
        flagged(&r),
        vec![own],
        "only the entry whose only evidence is the agent's"
    );
    let f = &r.findings[0];
    assert_eq!(
        f.cites,
        vec![Cite::Entry(own), Cite::Document(agent.document_oid)]
    );
    assert_eq!(
        f.statistic,
        Statistic::count("self_sourced_documents", 1, 3)
    );
    assert_eq!(
        f.severity,
        Severity::Medium,
        "reviewed by someone other than its uploader"
    );
    assert!(!flagged(&r).contains(&mixed) && !flagged(&r).contains(&independent));
    let row = fa_lantern::bind(SelfSourcedEvidence::ID).unwrap();
    assert!(
        r.work.within_registered_bound(&row.complexity, &snapshot),
        "{:?}",
        r.work
    );
    assert!(
        determinism(&snapshot, &h.book, &procedure)
            .unwrap()
            .deterministic()
    );

    // The same entry without its review is High: severity reads the reviews.
    let mut unreviewed = snapshot.clone();
    unreviewed.attestations.clear();
    let r = run_over(&unreviewed, &h.book, &procedure).unwrap();
    assert_eq!(flagged(&r), vec![own]);
    assert_eq!(r.findings[0].severity, Severity::High);

    // A supplement a person supplied takes the entry out of the population's
    // hits: its evidence is no longer only the book's own.
    let receipt = document(&mut h, 3, REVIEWER, b"BANK ADVICE (a person's upload)");
    attach(&mut h, own, vec![receipt]);
    let snapshot = Snapshot::read(&h.db, &h.ctx().query(), &h.book, None, None).unwrap();
    let r = run_over(&snapshot, &h.book, &procedure).unwrap();
    assert!(r.findings.is_empty(), "{:?}", r.findings);
}

fn pair_procedure(max_pair_count: u32, min_population: u32) -> UnusualAccounts {
    UnusualAccounts::with(
        Params::defaults(UnusualAccounts::ID)
            .unwrap()
            .set("max_pair_count", i128::from(max_pair_count))
            .unwrap()
            .set("min_population", i128::from(min_population))
            .unwrap(),
    )
}

/// Reference inputs come from the same posting intents, never the procedure's
/// account keys, frequency map or findings.
fn pair_reference_rows(h: &Harness, specs: &[Spec]) -> Vec<naive::Row> {
    specs
        .iter()
        .enumerate()
        .map(|(index, spec)| naive::Row {
            index,
            date: spec.date,
            document_date: spec.document_date,
            period: h.period_code(spec.date),
            period_start: None,
            period_end: h.period_end(spec.date),
            legs: spec
                .legs
                .iter()
                .map(|(account, side, mantissa)| naive::Leg {
                    account: (*account).into(),
                    debit: *side == Side::Debit,
                    unit: h.usd.0,
                    scale: 2,
                    mantissa: *mantissa,
                })
                .collect(),
            preparer: "P7".into(),
            approvers: Vec::new(),
            description_chars: Some(spec.description.chars().count()),
            external_ids: Vec::new(),
            recorded_after_close: false,
            reverses: None,
            replaces: None,
        })
        .collect()
}

#[test]
fn unusual_accounts_counts_account_pairs_as_registered() {
    let mut h = harness();
    let date = day(2026, 3, 9);
    let mut specs = Vec::new();
    // Each cash/revenue and cash/payable pair is ordinary. Combining those
    // two credits into one entry does not make either pair rare.
    for _ in 0..3 {
        specs.push(Spec::simple(date, "1000", "4000", 100));
        specs.push(Spec::simple(date, "1000", "2000", 10));
    }
    let mut combined = Spec::simple(date, "1000", "4000", 100);
    combined.legs = vec![
        ("1000", Side::Debit, 110),
        ("4000", Side::Credit, 100),
        ("2000", Side::Credit, 10),
    ];
    specs.push(combined);
    for spec in &specs {
        h.post(spec);
    }
    let procedure = UnusualAccounts::new().unwrap();
    let control = h.run(&procedure);
    let reference = naive::unusual_accounts(&pair_reference_rows(&h, &specs), 1, 5);
    assert!(reference.is_empty());
    assert_eq!(h.cited_entries(&control), reference.into_iter().collect());
    assert!(control.findings.is_empty(), "{:?}", control.findings);

    // A genuinely new pair is still reported beside that clean control.
    specs.push(Spec::simple(date, "1010", "1200", 50));
    let rare = h.post(specs.last().unwrap());
    let result = h.run(&procedure);
    let reference = naive::unusual_accounts(&pair_reference_rows(&h, &specs), 1, 5);
    assert_eq!(reference, vec![7]);
    assert_eq!(h.cited_entries(&result), reference.into_iter().collect());
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].cites[0], Cite::Entry(rare));
    assert_eq!(
        result.findings[0].statistic,
        Statistic::count("pair_occurrences", 1, 8)
    );
    assert_eq!(result.version, 2);
    h.assert_cites_resolve(&result);

    // The minimum population is inclusive, and a zero occurrence threshold
    // cannot flag a pair that actually appeared in the admitted population.
    assert_eq!(
        h.cited_entries(&h.run(&pair_procedure(1, 8))),
        BTreeSet::from([7])
    );
    assert!(h.run(&pair_procedure(1, 9)).findings.is_empty());
    assert!(h.run(&pair_procedure(0, 1)).findings.is_empty());
}

#[test]
fn unusual_account_pairs_deduplicate_legs_and_directions_and_keep_stable_citations() {
    let mut h = harness();
    let date = day(2026, 3, 10);
    let make = |legs| {
        let mut spec = Spec::simple(date, "1000", "4000", 25);
        spec.legs = legs;
        spec
    };
    let specs = vec![
        Spec::simple(date, "1000", "4000", 25),
        Spec::simple(date, "4000", "1000", 25),
        make(vec![
            ("1000", Side::Debit, 10),
            ("1000", Side::Debit, 15),
            ("4000", Side::Credit, 12),
            ("4000", Side::Credit, 13),
        ]),
        // Both directions of the same pair coexist in one entry. This also
        // introduces one self-pair per account, a valid net-zero posting.
        make(vec![
            ("1000", Side::Debit, 7),
            ("4000", Side::Debit, 3),
            ("1000", Side::Credit, 2),
            ("4000", Side::Credit, 8),
        ]),
        Spec::simple(date, "1000", "1000", 3),
        Spec::simple(date, "4000", "4000", 3),
        // The two debit accounts must not add another cash/revenue pair.
        make(vec![
            ("1000", Side::Debit, 10),
            ("4000", Side::Debit, 10),
            ("1010", Side::Credit, 20),
        ]),
    ];
    for spec in &specs {
        h.post(spec);
    }
    let procedure = pair_procedure(4, 1);
    let result = h.run(&procedure);
    let reference = naive::unusual_accounts(&pair_reference_rows(&h, &specs), 4, 1);
    assert_eq!(reference, vec![0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(h.cited_entries(&result), reference.into_iter().collect());
    let counts: BTreeMap<_, _> = result
        .findings
        .iter()
        .map(|finding| (h.entry_index(&finding.cites[0]), finding.statistic.value))
        .collect();
    assert_eq!(
        counts,
        BTreeMap::from([(0, 4), (1, 4), (2, 4), (3, 2), (4, 2), (5, 2), (6, 1)])
    );
    assert_eq!(
        h.cited_entries(&h.run(&pair_procedure(1, 1))),
        BTreeSet::from([6])
    );
    let both_directions = result
        .findings
        .iter()
        .find(|finding| h.entry_index(&finding.cites[0]) == 3)
        .unwrap();
    assert_eq!(
        both_directions.cites,
        vec![
            Cite::Entry(h.posted[3].0),
            Cite::Account(h.account("1000").min(h.account("4000"))),
        ],
        "equal-frequency self-pairs select one canonical witness, without duplicate citations"
    );
    h.assert_cites_resolve(&result);

    let snapshot = h.snapshot();
    for permuted in [
        snapshot.with_entries_reversed(),
        snapshot.with_legs_reversed(),
    ] {
        let replay = run_over(&permuted, &h.book, &procedure).unwrap();
        assert_eq!(replay.findings, result.findings);
        assert_eq!(replay.findings_digest, result.findings_digest);
        assert_eq!(replay.work, result.work);
    }
    assert!(
        determinism(&snapshot, &h.book, &procedure)
            .unwrap()
            .deterministic()
    );
}

#[test]
fn unusual_account_pairs_match_reference_across_generated_posting_histories() {
    const ACCOUNTS: [&str; 8] = [
        "1000", "1010", "1020", "1200", "2000", "4000", "6000", "7000",
    ];
    for seed in [7_u64, 31, 509, 65_537] {
        let mut state = seed;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            usize::try_from(state >> 32).unwrap()
        };
        let mut h = harness();
        let mut specs = Vec::new();
        for _ in 0..16 {
            let debit_count = 1 + next() % 3;
            let credit_count = 1 + next() % 3;
            let mut spec = Spec::simple(day(2026, 3, 11), "1000", "4000", 1);
            spec.legs.clear();
            for _ in 0..debit_count {
                spec.legs.push((
                    ACCOUNTS[next() % ACCOUNTS.len()],
                    Side::Debit,
                    i128::try_from(credit_count).unwrap(),
                ));
            }
            for _ in 0..credit_count {
                spec.legs.push((
                    ACCOUNTS[next() % ACCOUNTS.len()],
                    Side::Credit,
                    i128::try_from(debit_count).unwrap(),
                ));
            }
            h.post(&spec);
            specs.push(spec);
        }
        let rows = pair_reference_rows(&h, &specs);
        for threshold in [0_u32, 1, 2, 4, 16] {
            let procedure = pair_procedure(threshold, 5);
            let result = h.run(&procedure);
            let expected = naive::unusual_accounts(&rows, usize::try_from(threshold).unwrap(), 5);
            assert_eq!(
                h.cited_entries(&result),
                expected.into_iter().collect(),
                "seed={seed} threshold={threshold} findings={:?}",
                result.findings
            );
            h.assert_cites_resolve(&result);
        }
    }
}

#[test]
fn unusual_account_pairs_refuse_dense_expansion_at_the_work_budget() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    let mut proposal = h.proposal(&Spec::simple(day(2026, 3, 12), "1000", "4000", 64));
    proposal.legs.clear();
    let prototype = snapshot.accounts[&h.account("1000")].clone();
    for i in 0_u64..128 {
        let vid = VId(100_000 + u128::from(i));
        let mut account = prototype.clone();
        account.vid = vid;
        account.code = format!("pair-{i}");
        snapshot.accounts.insert(vid, account);
        proposal.legs.push(LegPayload::simple(
            if i < 64 { Side::Debit } else { Side::Credit },
            vid,
            Amount::new(h.usd, 1),
        ));
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    snapshot.entries = vec![fa_lantern::SnapshotEntry {
        vid: VId(200_000),
        entry: proposal.seal(Vec::new(), None).unwrap(),
        recorded_at: snapshot.coordinate.known_at,
        period: h.period_code(day(2026, 3, 12)),
        approvals: Vec::new(),
    }];
    let procedure = pair_procedure(1, 1);
    // Entry + 128 legs consume 129 units. Stop inside pair generation, after
    // 50 of the 4096 candidates, before any partial finding can escape.
    let error = run_over_metered(&snapshot, &h.book, &procedure, Some(179), None)
        .expect_err("dense pair expansion must be metered inside the entry");
    assert!(
        matches!(&error, LanternError::BudgetExhausted { procedure, used: 180, budget: 179, .. }
            if procedure == UnusualAccounts::ID),
        "{error:?}"
    );
    assert!(error.fix_hint().unwrap().contains("work budget"));

    let budget = default_budget(UnusualAccounts::ID, &snapshot).unwrap();
    let complete = run_over_metered(&snapshot, &h.book, &procedure, Some(budget), None).unwrap();
    assert_eq!(complete.findings.len(), 1);
    assert_eq!(complete.work.entries, 1);
    assert_eq!(complete.work.legs, 128);
    assert_eq!(complete.work.comparisons, 8193);
    assert_eq!(
        complete.findings[0].statistic,
        Statistic::count("pair_occurrences", 1, 1)
    );
    let row = fa_lantern::bind(UnusualAccounts::ID).unwrap();
    assert!(
        complete
            .work
            .within_registered_bound(&row.complexity, &snapshot)
    );
    let error = run_over_metered(
        &snapshot,
        &h.book,
        &procedure,
        Some(complete.work.total() - 1),
        None,
    )
    .expect_err("the second pass must also charge every pair lookup");
    assert!(matches!(error, LanternError::BudgetExhausted { .. }));
}
