//! Source-shaped principal transfers and independently stated cash/principal
//! margins. The distributions retain their existing v4 cash-only semantics.

use super::*;

fn funded() -> (Harness, Snapshot, VId, VId) {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    snapshot.coordinate.effective_through = None;
    let a = party(&h, &mut snapshot, "INV-A");
    let b = party(&h, &mut snapshot, "INV-B");
    snapshot.entries = vec![entry(
        &mut h,
        1501,
        day(2026, 1, 10),
        None,
        &[
            ("1000", Side::Debit, 10_000, None, None),
            ("2000", Side::Credit, 10_000, Some(a), None),
        ],
    )];
    assign(
        &h,
        &mut snapshot,
        &[
            ("1000", "cash"),
            ("2000", "investor_capital"),
            ("1010", "investor_transfer"),
        ],
    );
    (h, snapshot, a, b)
}

fn run_ponzi(h: &Harness, snapshot: &Snapshot) -> ProcedureRun {
    run_over(snapshot, &h.book, &PonziNetInvestment::new().unwrap()).unwrap()
}

#[test]
fn ponzi_v5_counts_clearing_and_direct_transfers_without_inventing_cash() {
    let (mut h, mut snapshot, a, b) = funded();
    // Source exhibits carry the out and in as separate rows. Neither clearing
    // row is an outside cash movement, and B has never contributed cash.
    for (vid, legs) in [
        (
            1502,
            vec![
                ("2000", Side::Debit, 4_000, Some(a), None),
                ("1010", Side::Credit, 4_000, None, None),
            ],
        ),
        (
            1503,
            vec![
                ("1010", Side::Debit, 4_000, None, None),
                ("2000", Side::Credit, 4_000, Some(b), None),
            ],
        ),
        (
            1504,
            vec![
                ("2000", Side::Debit, 1_000, Some(a), None),
                ("2000", Side::Credit, 1_000, Some(b), None),
            ],
        ),
        // A fee and a same-owner reclassification are not transfers to B.
        (
            1505,
            vec![
                ("2000", Side::Debit, 500, Some(a), None),
                ("4000", Side::Credit, 500, None, None),
            ],
        ),
        (
            1506,
            vec![
                ("2000", Side::Debit, 700, Some(a), None),
                ("2000", Side::Credit, 700, Some(a), None),
            ],
        ),
    ] {
        snapshot
            .entries
            .push(entry(&mut h, vid, day(2026, 4, 20), None, &legs));
    }
    let r = run_ponzi(&h, &snapshot);
    assert_eq!(r.version, 5);
    assert_eq!(r.findings.len(), 2);
    for who in ["INV-A", "INV-B"] {
        let rows = of(&r.findings, who);
        assert_eq!((rows[0].0, rows[0].1), ("net_equity_claim", 5_000));
        assert!(
            rows[0]
                .2
                .contains("principal_rule=posted_principal_transfer_v1")
        );
        assert!(rows[0].2.contains("attribution=complete"));
    }
    let a_row = of(&r.findings, "INV-A");
    assert!(
        a_row[0]
            .2
            .contains("cash_in=10000, cash_out=0, transfer_in=0, transfer_out=5000")
    );
    let b_row = of(&r.findings, "INV-B");
    assert!(
        b_row[0].2.contains("cohort 2"),
        "transfer-in starts B's funding cohort"
    );
    assert!(
        b_row[0]
            .2
            .contains("cash_in=0, cash_out=0, transfer_in=5000, transfer_out=0")
    );

    let permuted = run_ponzi(&h, &snapshot.with_entries_reversed().with_legs_reversed());
    assert_eq!(
        permuted.findings, r.findings,
        "source iteration cannot reassign principal"
    );
    let mut without = snapshot.clone();
    without.entries.retain(|entry| entry.vid != VId(1504));
    let changed = run_ponzi(&h, &without);
    assert_eq!(of(&changed.findings, "INV-A")[0].1, 6_000);
    assert_eq!(of(&changed.findings, "INV-B")[0].1, 4_000);
    assert_ne!(
        changed.findings, r.findings,
        "removing the direct leg changes both principal positions"
    );

    let mut before_transfers = snapshot.clone();
    before_transfers
        .entries
        .retain(|entry| !(1502..=1506).contains(&entry.vid.0));
    for procedure in [
        Box::new(DistributionProRata::with(
            Params::defaults(DistributionProRata::ID)
                .unwrap()
                .set("distributable_pool", 9_000)
                .unwrap(),
        )) as Box<dyn Procedure>,
        Box::new(DistributionRisingTide::with(
            Params::defaults(DistributionRisingTide::ID)
                .unwrap()
                .set("distributable_pool", 9_000)
                .unwrap(),
        )),
    ] {
        let before = run_over(&before_transfers, &h.book, procedure.as_ref()).unwrap();
        let after = run_over(&snapshot, &h.book, procedure.as_ref()).unwrap();
        assert_eq!(
            before.findings,
            after.findings,
            "{} remains cash-only",
            procedure.id()
        );
        assert_eq!(after.version, 4);
        assert_eq!(of(&after.findings, "INV-A")[0].1, 9_000);
        assert!(of(&after.findings, "INV-B").is_empty());
    }
}

#[test]
fn ponzi_v5_never_guesses_an_unmarked_clearing_or_fee_transfer() {
    let (mut h, mut snapshot, a, b) = funded();
    // 1020 has a plausible bank-like name but no investor_transfer role.
    for (vid, legs) in [
        (
            1510,
            vec![
                ("2000", Side::Debit, 4_000, Some(a), None),
                ("1020", Side::Credit, 4_000, None, None),
            ],
        ),
        (
            1511,
            vec![
                ("1020", Side::Debit, 4_000, None, None),
                ("2000", Side::Credit, 4_000, Some(b), None),
            ],
        ),
        (
            1512,
            vec![
                ("2000", Side::Debit, 500, Some(a), None),
                ("4000", Side::Credit, 500, None, None),
            ],
        ),
    ] {
        snapshot
            .entries
            .push(entry(&mut h, vid, day(2026, 2, 10), None, &legs));
    }
    let r = run_ponzi(&h, &snapshot);
    assert_eq!(r.findings.len(), 1);
    assert_eq!(of(&r.findings, "INV-A")[0].1, 10_000);
    assert!(of(&r.findings, "INV-B").is_empty());
}

#[test]
fn ponzi_v5_transfer_cohort_never_overflows_the_full_date_domain() {
    let (mut h, mut snapshot, a, b) = funded();
    snapshot.entries[0].entry.proposal.effective_date = DateDay(i32::MIN);
    let mut transfer = entry(
        &mut h,
        1513,
        day(2026, 2, 10),
        None,
        &[
            ("2000", Side::Debit, 10_000, Some(a), None),
            ("2000", Side::Credit, 10_000, Some(b), None),
        ],
    );
    transfer.entry.proposal.effective_date = DateDay(i32::MAX);
    snapshot.entries.push(transfer);
    let procedure = PonziNetInvestment::with(
        Params::defaults(PonziNetInvestment::ID)
            .unwrap()
            .set("cohort_window_days", 1)
            .unwrap(),
    );
    let report = run_over(&snapshot, &h.book, &procedure).unwrap();
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].statistic.value, 10_000);
    assert!(
        report.findings[0]
            .narrative
            .contains("investor INV-B (cohort 4294967296,")
    );
}

#[test]
fn ponzi_v5_refuses_missing_named_mixed_and_ambiguous_transfer_attribution() {
    let (mut h, snapshot, a, b) = funded();
    let c = fa_model::party_value_vid(h.book.book_id, "INV-C");
    for (label, legs) in [
        (
            "unnamed investor",
            vec![
                ("2000", Side::Debit, 100, None, None),
                ("1010", Side::Credit, 100, None, None),
            ],
        ),
        (
            "named clearing",
            vec![
                ("2000", Side::Debit, 100, Some(a), None),
                ("1010", Side::Credit, 100, Some(b), None),
            ],
        ),
        (
            "marked cash without investor",
            vec![
                ("1000", Side::Debit, 100, Some(a), None),
                ("1010", Side::Credit, 100, None, None),
            ],
        ),
        (
            "marked expense without investor",
            vec![
                ("6000", Side::Debit, 100, None, None),
                ("1010", Side::Credit, 100, None, None),
            ],
        ),
        (
            "mixed fee",
            vec![
                ("2000", Side::Debit, 100, Some(a), None),
                ("1010", Side::Credit, 90, None, None),
                ("4000", Side::Credit, 10, None, None),
            ],
        ),
        (
            "mixed cash",
            vec![
                ("2000", Side::Debit, 100, Some(a), None),
                ("1010", Side::Credit, 90, None, None),
                ("1000", Side::Credit, 10, None, None),
            ],
        ),
        (
            "direct transfer with a fee",
            vec![
                ("2000", Side::Debit, 100, Some(a), None),
                ("2000", Side::Credit, 90, Some(b), None),
                ("4000", Side::Credit, 10, None, None),
            ],
        ),
        (
            "direct transfer with a cash withdrawal",
            vec![
                ("2000", Side::Debit, 10_000, Some(a), None),
                ("2000", Side::Credit, 9_000, Some(b), None),
                ("1000", Side::Credit, 1_000, None, None),
            ],
        ),
        (
            "three parties",
            vec![
                ("2000", Side::Debit, 100, Some(a), None),
                ("2000", Side::Credit, 40, Some(b), None),
                ("2000", Side::Credit, 60, Some(c), None),
            ],
        ),
    ] {
        let mut invalid = snapshot.clone();
        invalid
            .entries
            .push(entry(&mut h, 1520, day(2026, 2, 10), None, &legs));
        let failure = run_over(&invalid, &h.book, &PonziNetInvestment::new().unwrap());
        assert!(
            matches!(failure, Err(LanternError::Parameter { ref name, .. }) if name == "posted_principal_transfer_v1"),
            "{label}: {failure:?}"
        );
    }
}

#[test]
fn ponzi_v5_never_borrows_principal_across_units_or_legal_entities() {
    let (mut h, snapshot, a, b) = funded();
    for split_entity in [false, true] {
        let mut invalid = snapshot.clone();
        // Keep only role declarations so the multi-entity witness has no
        // untagged funding legs that would independently make it ambiguous.
        invalid.entries.retain(|entry| !entry.posts());
        let mut transfer = entry(
            &mut h,
            1530,
            day(2026, 2, 10),
            None,
            &[
                ("2000", Side::Debit, 100, Some(a), None),
                ("2000", Side::Credit, 100, Some(b), None),
            ],
        );
        if split_entity {
            for (i, leg) in transfer.entry.proposal.legs.iter_mut().enumerate() {
                leg.dimension_set
                    .push((fa_model::LEGAL_ENTITY_DIMENSION, VId(10 + i as u128)));
                leg.dimension_set.sort();
            }
        } else {
            transfer.entry.proposal.legs[1].amount.unit = h.book.units.lookup("EUR").unwrap();
        }
        invalid.entries.push(transfer);
        let failure = run_over(&invalid, &h.book, &PonziNetInvestment::new().unwrap());
        assert!(
            matches!(failure, Err(LanternError::Parameter { ref name, .. }) if name == "posted_principal_transfer_v1"),
            "split_entity={split_entity}: {failure:?}"
        );
    }
}

/// A deliberately independent reader for this pinned, single-line factual CSV
/// fixture. It is not a product CSV parser or a generalized import path.
fn fixture_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut text = String::new();
    let mut quoted = false;
    for ch in line.chars() {
        match ch {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                fields.push(std::mem::take(&mut text));
            }
            _ => text.push(ch),
        }
    }
    assert!(!quoted, "pinned source field must close its quote");
    fields.push(text);
    fields
}

fn source_cents(text: &str) -> i128 {
    if text == "-" {
        return 0;
    }
    let negative = text.starts_with('(');
    let digits: String = text
        .trim_matches(['(', ')'])
        .chars()
        .filter(|&ch| ch != ',')
        .collect();
    assert!(!digits.is_empty() && digits.bytes().all(|ch| ch.is_ascii_digit()));
    let cents = digits.parse::<i128>().unwrap().checked_mul(100).unwrap();
    if negative { -cents } else { cents }
}

#[test]
fn ponzi_v5_reconciles_all_75_glantz_source_observations_and_exposes_the_cash_only_gap() {
    // Every factual row of Exhibit B-2 is retained in this checked-in fixture.
    // Columns 6/7 are trustee-credited transfer inputs, not an independent
    // legal determination. The printed principal column is only an oracle.
    const SOURCE: &str = include_str!("../../../fa-oracles/data/blmis_glantz_1za192/rows.csv");
    let mut h = harness();
    let mut snapshot = h.snapshot();
    snapshot.coordinate.effective_through = None;
    snapshot.entries.clear();
    let investor = party(&h, &mut snapshot, "BLMIS-1ZA192");
    let mut count = 0;
    let mut zero = 0;
    let mut totals = [0i128; 4];
    let mut running_principal = 0i128;
    for (i, line) in SOURCE.lines().skip(1).enumerate() {
        let row = fixture_fields(line);
        assert_eq!(row.len(), 16);
        assert_eq!(row[1], "1ZA192");
        let date: Vec<_> = row[6].split('/').collect();
        let date = day(
            date[2].parse().unwrap(),
            date[0].parse().unwrap(),
            date[1].parse().unwrap(),
        );
        let values = [
            source_cents(&row[9]),
            source_cents(&row[10]),
            source_cents(&row[11]),
            source_cents(&row[12]),
        ];
        for (sum, value) in totals.iter_mut().zip(values) {
            *sum += value;
        }
        let movement = values.iter().sum::<i128>();
        running_principal += movement;
        assert_eq!(
            running_principal,
            source_cents(&row[13]),
            "printed principal at {}",
            row[0]
        );
        count += 1;
        if movement == 0 {
            zero += 1;
            continue;
        }
        assert_eq!(values.iter().filter(|&&v| v != 0).count(), 1);
        let contra = if values[2] != 0 || values[3] != 0 {
            "1010"
        } else {
            "1000"
        };
        let (principal_side, contra_side) = if movement > 0 {
            (Side::Credit, Side::Debit)
        } else {
            (Side::Debit, Side::Credit)
        };
        snapshot.entries.push(entry(
            &mut h,
            2000 + i as u128,
            date,
            None,
            &[
                ("2000", principal_side, movement.abs(), Some(investor), None),
                (contra, contra_side, movement.abs(), None, None),
            ],
        ));
    }
    assert_eq!((count, zero, snapshot.entries.len()), (75, 1, 74));
    // Independently printed footer totals, all exact integer cents.
    assert_eq!(
        totals,
        [1_043_998_300, -1_692_438_000, 53_736_600, -400_000_000]
    );
    assert_eq!(running_principal, -994_703_100);
    assign(
        &h,
        &mut snapshot,
        &[
            ("1000", "cash"),
            ("2000", "investor_capital"),
            ("1010", "investor_transfer"),
        ],
    );
    let r = run_ponzi(&h, &snapshot);
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.version, 5);
    let finding = &r.findings[0];
    assert_eq!(finding.statistic.name, "fictitious_profit_clawback");
    assert_eq!(finding.statistic.value, 994_703_100);
    assert_eq!(finding.statistic.scale, 2);
    assert!(finding.narrative.contains(
        "cash_in=1043998300, cash_out=1692438000, transfer_in=53736600, transfer_out=400000000"
    ));
    assert!(finding.narrative.contains("attribution=complete"));
    assert_eq!(
        finding
            .cites
            .iter()
            .filter(|cite| matches!(cite, Cite::Entry(_)))
            .count(),
        74
    );

    // Remove only the transfer role, retaining every source amount and leg.
    // This recreates the old cash-only schedule and its exact reported gap.
    let mut cash_only = snapshot.clone();
    cash_only
        .entries
        .retain(|entry| entry.vid != snapshot.entries.last().unwrap().vid);
    cash_only.fold_roles().unwrap();
    let cash_only = run_ponzi(&h, &cash_only);
    assert_eq!(cash_only.findings[0].statistic.value, 648_439_700);
    assert_eq!(
        finding.statistic.value - cash_only.findings[0].statistic.value,
        346_263_400
    );
}
