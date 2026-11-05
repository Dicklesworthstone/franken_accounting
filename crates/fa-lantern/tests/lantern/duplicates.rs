//! fa-m35p: `duplicates.near` (plan §11.3) pairs entries on the same accounts
//! whose amounts are inside a tolerance and whose descriptions are similar.
//! It leaves alone exact duplicates, other accounts, dissimilar text, and
//! pairs outside the window or the tolerance.

use super::*;

/// An invoice: `debit` against Payables, posted through the kernel.
fn invoice(
    h: &mut Harness,
    date: DateDay,
    debit: &'static str,
    cents: i128,
    description: &'static str,
) -> VId {
    let mut spec = Spec::simple(date, debit, "2000", cents);
    spec.description = description;
    h.post(&spec)
}

fn pairs(r: &ProcedureRun) -> Vec<Vec<Cite>> {
    r.findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .map(|f| f.cites.clone())
        .collect()
}

fn with(name: &str, value: i128) -> Near {
    Near::with(
        Params::defaults(Near::ID)
            .unwrap()
            .set(name, value)
            .unwrap(),
    )
}

#[test]
fn near_duplicates_pair_amounts_inside_tolerance_with_similar_descriptions() {
    let mut h = harness();
    let a = invoice(
        &mut h,
        day(2026, 1, 10),
        "6000",
        100_000,
        "Invoice 1043 Acme Supplies",
    );
    // The same text and amount on another expense account: another shape.
    let other = invoice(
        &mut h,
        day(2026, 1, 11),
        "7000",
        100_000,
        "Invoice 1043 Acme Supplies",
    );
    // 30 bp from a, but a dissimilar description.
    let rent = invoice(
        &mut h,
        day(2026, 1, 12),
        "6000",
        100_300,
        "Quarterly rent payment",
    );
    // a's description, 2% from a: outside the 100 bp tolerance.
    let far = invoice(
        &mut h,
        day(2026, 1, 15),
        "6000",
        102_000,
        "Invoice 1043 Acme Supplies",
    );
    // The near duplicate: 50 bp from a, the invoice number transposed.
    let b = invoice(
        &mut h,
        day(2026, 1, 20),
        "6000",
        100_500,
        "INVOICE #1034 - ACME SUPPLIES",
    );
    // b's exact legs again: the exact procedures' pair, not this one's.
    let exact = invoice(
        &mut h,
        day(2026, 1, 25),
        "6000",
        100_500,
        "INVOICE #1034 - ACME SUPPLIES",
    );
    // a's text, 10 bp from a, but 64 days after the last entry above.
    let late = invoice(
        &mut h,
        day(2026, 3, 30),
        "6000",
        100_100,
        "Invoice 1043 Acme Supplies",
    );

    let snapshot = h.snapshot();
    let procedure = Near::new().unwrap();
    let r = run_over(&snapshot, &h.book, &procedure).unwrap();
    h.assert_cites_resolve(&r);
    println!("near findings={:?}", r.findings);
    assert_eq!(r.findings.len(), 1, "{:?}", r.findings);
    let f = &r.findings[0];
    assert_eq!(
        f.cites,
        vec![Cite::Entry(a), Cite::Entry(b)],
        "earlier, then later"
    );
    assert_eq!(f.severity, Severity::Low);
    // 22 of 25 bigrams shared: 2 * 22 * 100 / 50; all seven entries compared.
    assert_eq!(f.statistic, Statistic::count("similarity_pct", 88, 7));
    assert!(f.narrative.contains("10 day(s) apart"), "{}", f.narrative);
    for untouched in [other, rent, far, exact, late] {
        assert!(
            !f.cites.contains(&Cite::Entry(untouched)),
            "{untouched:?} is not a near duplicate"
        );
    }
    let row = fa_lantern::bind(Near::ID).unwrap();
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

    // The similarity threshold is inclusive: 88 passes at 88, not at 89.
    let at = run_over(&snapshot, &h.book, &with("min_similarity_pct", 88)).unwrap();
    assert_eq!(pairs(&at), vec![vec![Cite::Entry(a), Cite::Entry(b)]]);
    let above = run_over(&snapshot, &h.book, &with("min_similarity_pct", 89)).unwrap();
    assert!(above.findings.is_empty(), "{:?}", above.findings);

    // At 200 bp, far is inside the tolerance of both a and b. Each entry
    // pairs with its nearest qualifying later entry only.
    let wide = pairs(&run_over(&snapshot, &h.book, &with("tolerance_bp", 200)).unwrap());
    assert_eq!(wide.len(), 2, "{wide:?}");
    assert!(
        wide.contains(&vec![Cite::Entry(a), Cite::Entry(far)]),
        "{wide:?}"
    );
    assert!(
        wide.contains(&vec![Cite::Entry(far), Cite::Entry(b)]),
        "{wide:?}"
    );

    // A window of 9 days no longer reaches from a to b.
    let narrow = run_over(&snapshot, &h.book, &with("window_days", 9)).unwrap();
    assert!(narrow.findings.is_empty(), "{:?}", narrow.findings);

    // Out-of-range parameters are refused, never clamped.
    for (name, value) in [
        ("tolerance_bp", 10_001),
        ("min_similarity_pct", 0),
        ("min_similarity_pct", 101),
    ] {
        let refused = run_over(&snapshot, &h.book, &with(name, value));
        assert!(
            matches!(&refused, Err(LanternError::Parameter { name: n, .. }) if n == name),
            "{name}={value}: {refused:?}"
        );
    }
}

#[test]
fn near_duplicates_report_an_entry_past_the_candidate_cap() {
    let mut h = harness();
    // 66 entries of one shape on one day: the first has 65 later candidates,
    // one more than the cap, so it alone is reported as capped. Each pair is
    // an exact duplicate, so there is no near pair to find.
    let posted: Vec<VId> = (0..66)
        .map(|_| invoice(&mut h, day(2026, 2, 2), "6000", 42_000, "Monthly retainer"))
        .collect();
    let snapshot = h.snapshot();
    let r = run_over(&snapshot, &h.book, &Near::new().unwrap()).unwrap();
    assert_eq!(r.findings.len(), 1, "{:?}", r.findings);
    let f = &r.findings[0];
    assert_eq!(f.severity, Severity::Info);
    assert_eq!(f.statistic, Statistic::count("capped_entries", 1, 66));
    assert_eq!(f.cites, vec![Cite::Entry(posted[0])]);
    assert_eq!(r.work.comparisons, {
        // One sparse-lineage scan, the sort's charge, then 64 comparisons
        // for the first entry and 65 - i for every later entry i.
        let sort = 66 * u64::from(66_u64.ilog2());
        snapshot.entries.len() as u64 + sort + 64 + (1..66).map(|i| 65 - i).sum::<u64>()
    });
    let row = fa_lantern::bind(Near::ID).unwrap();
    assert!(
        r.work.within_registered_bound(&row.complexity, &snapshot),
        "{:?}",
        r.work
    );
}

#[test]
fn exact_duplicate_procedures_handle_hundred_thousand_postings_with_linear_scan_work() {
    const N: u64 = 100_000;
    let mut h = harness();
    let date = day(2026, 1, 10);
    let period = h.period_code(date);
    let usd = h.usd;
    let template = make_snapshot_entry(
        &mut h,
        VId(1),
        CommitSeq(1),
        date,
        &period,
        EntryClass::ORIGINAL,
        vec![
            ("6000", Side::Debit, usd, 100),
            ("1000", Side::Credit, usd, 100),
        ],
        Vec::new(),
        None,
        None,
        None,
        Vec::new(),
    );
    let mut snapshot = h.snapshot();
    // This isolates the analytical read path from posting/storage costs.
    // The old next-date search rebuilt the entire snapshot's lineage map
    // for each of the 50,000 first-date entries, even without corrections.
    snapshot.entries = (1..=N)
        .map(|i| {
            let mut entry = template.clone();
            entry.vid = VId(u128::from(i));
            entry.recorded_at = CommitSeq(i);
            if i > N / 2 {
                entry.entry.proposal.effective_date = day(2026, 2, 10);
            }
            entry
        })
        .collect();
    let mut work = Meter::new(SameSameDifferent::ID, Some(6 * N), None);
    let findings = SameSameDifferent::new()
        .unwrap()
        .run(&snapshot, &h.book, &mut work)
        .unwrap();
    assert!(findings.is_empty()); // The two dates are 31 days apart.
    assert_eq!(work.work().entries, N);
    assert_eq!(work.work().legs, 2 * N);
    assert!(work.work().comparisons <= 3 * N);
    assert!(work.work().within_registered_bound(
        &fa_lantern::bind(SameSameDifferent::ID).unwrap().complexity,
        &snapshot
    ));

    for entry in &mut snapshot.entries {
        entry.entry.proposal.effective_date = date;
    }
    // One unrelated correction used to force every duplicate to compare
    // against all earlier group members, scanning the whole snapshot each
    // time. It must neither change the group nor multiply its work.
    let unrelated = make_snapshot_entry(
        &mut h,
        VId(u128::from(N + 1)),
        CommitSeq(N + 1),
        date,
        &period,
        EntryClass::REPLACEMENT,
        vec![
            ("6000", Side::Debit, usd, 200),
            ("1000", Side::Credit, usd, 200),
        ],
        vec![fa_model::Supersession {
            target: fa_model::EntryRef {
                vid: VId(u128::from(N + 2)),
                entry_digest: [0; 32],
            },
            kind: SupersessionKind::Replaces,
            reason_code: 1,
        }],
        None,
        None,
        None,
        Vec::new(),
    );
    snapshot.entries.push(unrelated);
    let mut work = Meter::new(SameSameSame::ID, Some(32 * N), None);
    let findings = SameSameSame::new()
        .unwrap()
        .run(&snapshot, &h.book, &mut work)
        .unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].statistic, Statistic::count("entries", N, N + 1));
    assert_eq!(findings[0].cites.len(), fa_lantern::MAX_CITES);
    assert_eq!(findings[0].cites[0], Cite::Entry(VId(1)));
    assert!(work.work().within_registered_bound(
        &fa_lantern::bind(SameSameSame::ID).unwrap().complexity,
        &snapshot
    ));
}
