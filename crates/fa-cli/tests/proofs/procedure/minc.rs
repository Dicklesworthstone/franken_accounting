//! Terminal FIFO comparison with In re Minc, docket 95 (July 25, 2025).
//! The appendices omit individual dates for several aggregate movements.

use super::*;
use fa_oracles::cases::commingled::{Endpoint, Movement, MovementKind, Transcript, render_batch};
use fa_oracles::cases::date::Day;
use fgdb_types::CommitSeq;
use std::collections::{BTreeMap, BTreeSet};

const PETITION: &str = "2024-09-19";

fn trace_at(fixture: &Fixture, vid: &str, through: &str) -> i128 {
    let report = ok(
        &fixture.book,
        &[
            "procedure",
            "run",
            "trace.fifo@2",
            "--account",
            "1000",
            "--source",
            vid,
            "--effective-through",
            through,
            "--param",
            "intraday_order=0",
        ],
    );
    assert_eq!(text(&report, "procedure"), "trace.fifo");
    assert_eq!(integer(&report, "version"), 2);
    assert_eq!(text(&report, "evidence"), "FA-EVID-L16");
    let findings = get(&report, "findings").as_arr().unwrap();
    assert_eq!(findings.len(), 1);
    let statistic = get(&findings[0], "statistic");
    assert_eq!(text(statistic, "name"), "traced_mantissa");
    assert_eq!(integer(statistic, "scale"), 2);
    integer(statistic, "value")
}

fn evidence(fixture: &Fixture, path: &str) -> String {
    // Roles exercise intake and review in the replay book only.
    let doc = ok(
        &fixture.book,
        &[
            "document",
            "add",
            path,
            "--kind",
            "Workpaper",
            "--grade",
            "AgentUpload",
        ],
    );
    let oid = text(&doc, "oid");
    ok(
        &fixture.book,
        &["attest", "review", oid, "--as", "reviewer"],
    );
    oid.to_owned()
}

fn dollars(cents: i128) -> String {
    format!("{}.{:02}", cents / 100, cents % 100)
}

fn post_observation(
    fixture: &Fixture,
    movements: &[&Movement<'_>],
    evidence: &str,
) -> (CommitSeq, Vec<String>) {
    let observed = movements[0].observed;
    let request = render_batch(
        "minc-observation",
        observed,
        movements,
        "1000",
        "4000",
        evidence,
    );
    let file = write(
        &fixture.dir,
        &format!("{observed}.json"),
        &request.to_string(),
    );
    let before = fixture.head();
    let posted = ok(&fixture.book, &["batch", "--intent", &file]);
    assert_eq!(text(&posted, "event"), "batch_posted");
    assert_eq!(integer(&posted, "recorded_at"), i128::from(before + 1));
    let members = get(&posted, "members").as_arr().unwrap();
    assert_eq!(members.len(), movements.len());
    let vids = members
        .iter()
        .enumerate()
        .map(|(index, member)| {
            assert_eq!(integer(member, "index"), index as i128);
            text(member, "vid").to_owned()
        })
        .collect();
    (CommitSeq(before + 1), vids)
}

fn cash_at(fixture: &Fixture, through: Day, known_at: CommitSeq) -> i128 {
    let day = fa_time::DateDay::parse(&through.to_string()).unwrap();
    let report = fixture.open().balance_as_of(day, Some(known_at)).unwrap();
    assert_eq!(report.known_at, known_at);
    assert_eq!(report.effective_through, Some(day));
    let cash = report.rows.iter().find(|row| row.code == "1000").unwrap();
    cash.debits - cash.credits
}

struct RecipientClaim {
    source: String,
    pin: String,
    cents: i128,
}

struct RecipientCohort {
    claims: Vec<RecipientClaim>,
    total: i128,
}

// The recipient can open only these three exported files. The trusted key
// comes from book creation, and the selected certificate comes from the
// requested source and coordinate before the report bundle is produced.
fn judge(dir: &Path, source: &str, key: &str, pin: &str, receipt: &str) -> fa_verify::cli::Output {
    let bundle = format!("{source}.fab");
    let anchor = "checkpoint.signed";
    fa_verify::cli::run(
        &[
            "report",
            &bundle,
            "--checkpoint",
            anchor,
            "--key",
            key,
            "--expect",
            pin,
            "--receipt",
            receipt,
            "--json",
        ]
        .map(str::to_owned),
        &|name| {
            assert!([bundle.as_str(), anchor, receipt].contains(&name));
            std::fs::read(dir.join(name))
        },
    )
}

fn verify_sources(
    fixture: &Fixture,
    group: &str,
    key: &str,
    sources: &[(&Movement<'_>, String)],
) -> RecipientCohort {
    let known_at = fixture.head();
    let mut selected = Vec::new();
    for (_, source) in sources {
        let (run, cert) = certified(
            fixture,
            &[
                "procedure",
                "run",
                "trace.fifo@2",
                "--account",
                "1000",
                "--source",
                source,
                "--effective-through",
                PETITION,
                "--known-at",
                &known_at.to_string(),
                "--param",
                "intraday_order=0",
                "--certify",
            ],
        );
        assert_eq!(integer(&run, "known_at"), i128::from(known_at));
        selected.push(text(&cert, "oid").to_owned());
    }
    let state = fixture.checkpoint();
    let signed = exported(
        &fixture.book,
        &["signed-checkpoint", "--state", text(&state, "oid")],
    );
    assert_eq!(text(&signed, "checkpoint_public_key"), key);
    let dir = fixture.dir.join(group);
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("checkpoint.signed"), bytes(&signed)).unwrap();
    let account = format!("{:032x}", account_vid(BOOK_ID, "1000").0);
    let mut inventory =
        String::from("source\tclassification\tprinted\tcertificate\tknown_at\taccount\n");
    let usd = fa_money::UnitRegistry::embedded()
        .unwrap()
        .lookup("USD")
        .unwrap();
    let mut reports = Vec::new();
    for ((movement, source), pin) in sources.iter().zip(&selected) {
        let produced = ok(
            &fixture.book,
            &[
                "bundle",
                "produce",
                "--certificate",
                &format!("C:{pin}"),
                "--state",
                text(&state, "oid"),
            ],
        );
        let receipt = format!("{source}.receipt");
        std::fs::write(dir.join(format!("{source}.fab")), bytes(&produced)).unwrap();
        std::fs::write(dir.join(&receipt), unhex(text(&produced, "receipt"))).unwrap();
        let result = judge(&dir, source, key, pin, &receipt);
        assert_eq!(result.exit, 0, "{}\n{}", result.stdout, result.stderr);
        reports.push(result.stdout);
        use std::fmt::Write as _;
        writeln!(
            &mut inventory,
            "{source}\t{}\t{}\t{pin}\t{known_at}\t{account}",
            movement.kind.as_str(),
            movement.printed
        )
        .unwrap();
    }
    std::fs::write(dir.join("sources.tsv"), inventory).unwrap();
    use fa_oracles::cases::verify_report::{FifoCoordinate, fifo_cohort};
    let book = BOOK_ID.to_hex();
    let coordinate = FifoCoordinate {
        book: &book,
        branch: "00000000000000000000000000000000",
        account: &account,
        known_at,
        effective_through: fa_time::DateDay::parse(PETITION).unwrap().0,
        intraday_order: 0,
        unit: usd.0,
        scale: 2,
    };
    let pins: Vec<_> = sources
        .iter()
        .zip(&selected)
        .map(|((_, id), pin)| (id.as_str(), pin.as_str()))
        .collect();
    // The recipient's source selection is fixed before delivery. A validly
    // signed but incomplete or repeated delivery cannot supply the cohort.
    if reports.len() > 1 {
        let missing = &reports[1..];
        assert!(
            fifo_cohort(&coordinate, &pins, missing)
                .err()
                .unwrap()
                .starts_with("missing FIFO report")
        );
        reports.push(reports[0].clone());
        assert!(
            fifo_cohort(&coordinate, &pins, &reports)
                .err()
                .unwrap()
                .starts_with("duplicate FIFO report")
        );
        reports.pop();
        let mut swapped = pins.clone();
        let wrong = swapped[1].1;
        swapped[0].1 = wrong;
        assert!(
            fifo_cohort(&coordinate, &swapped, &reports)
                .err()
                .unwrap()
                .starts_with("unselected certificate")
        );
        reports.reverse();
    }
    let observed = fifo_cohort(&coordinate, &pins, &reports).unwrap();
    let claims = sources
        .iter()
        .zip(selected)
        .map(|((_, source), pin)| RecipientClaim {
            source: source.clone(),
            pin,
            cents: observed.sources[source],
        })
        .collect();
    RecipientCohort {
        claims,
        total: observed.total,
    }
}

#[test]
fn minc_fifo_matches_both_opening_classifications_and_both_petition_debits() {
    use fa_oracles::cases::{check, embedded::MINC};
    let files = MINC.case_files();
    let case = fa_oracles::cases::load(&files).unwrap();
    let published = "MINC-FIFO-RESULT";
    let binding = check::bind::check(&check::Context::new(&case));
    assert_eq!(binding.verdict, check::Verdict::Pass, "{binding}");
    assert!(binding.rows.iter().any(|id| id == published));
    let values: Vec<_> = case.values.iter().filter(|v| v.fact == published).collect();
    let [value] = values.as_slice() else {
        panic!("expected one published FIFO result")
    };
    assert_eq!(value.unit, "USD");
    // The receipt binds the court's numerical result on p. 10. Only the
    // distinct gross movement transcription from its appendices enters a book.
    let court_other_cents: i128 = value.value.parse().unwrap();
    let movement_file = |id| {
        assert!(binding.rows.iter().any(|row| row == id));
        let exhibit = case
            .facts
            .iter()
            .find(|f| f.id == id)
            .unwrap()
            .sourced()
            .unwrap();
        assert_eq!(
            exhibit.rows_layout,
            Some(fa_oracles::cases::fact::RowsLayout::CommingledFifoV1)
        );
        exhibit.rows_file.as_deref().unwrap()
    };
    let source_file = movement_file("MINC-APPENDIX-1");
    assert_eq!(source_file, movement_file("MINC-APPENDIX-2"));
    let movement_table = case.rows[source_file].as_str();
    let transcript = Transcript::parse(movement_table).unwrap();
    for (selection, expected_balance) in [
        (Endpoint::Schedule, 3_778_946),
        (Endpoint::Trustee, 3_753_741),
    ] {
        let endpoint = selection.as_str();
        let movements: Vec<_> = transcript.movements(selection).collect();
        let funding = transcript.funding_bound(selection).unwrap();
        assert_eq!(funding.ending_cents, expected_balance);
        assert_eq!(funding.minimum_cents, 2_287_531);
        // Independent bound: even all withdrawals before all deposits in any
        // observation interval are funded by its prior balance. Thus every
        // admissible ordering consumes a prefix of the same deposit dollars.
        // The three oldest deposits have explicit, strictly increasing dates.
        let mut balance = 0;
        let mut debits = 0;
        let mut prior_date = None;
        for group in movements.chunk_by(|a, b| a.observed == b.observed) {
            let observed = group[0].observed;
            assert!(prior_date.is_none_or(|day| observed > day));
            prior_date = Some(observed);
            let withdrawals = group
                .iter()
                .filter(|m| m.kind.is_debit())
                .map(|m| m.cents)
                .sum::<i128>();
            assert!(
                withdrawals <= balance,
                "possible overdraft in interval ending {observed}"
            );
            debits += withdrawals;
            balance += group
                .iter()
                .filter(|m| !m.kind.is_debit())
                .map(|m| m.cents)
                .sum::<i128>()
                - withdrawals;
        }
        assert_eq!(balance, expected_balance);
        assert_eq!(debits, funding.withdrawals_cents);
        let oldest: Vec<_> = movements
            .iter()
            .filter(|m| !m.kind.is_debit())
            .take(4)
            .collect();
        assert_eq!(
            oldest
                .iter()
                .map(|m| (m.printed, m.kind.as_str()))
                .collect::<Vec<_>>(),
            [
                ("03/24/23", "opening"),
                ("04/03/23", "other"),
                ("04/12/23", "social"),
                ("04/18/23", "other")
            ]
        );
        assert!(
            movements
                .iter()
                .filter(|m| m.printed.starts_with("unknown"))
                .all(|m| m.observed >= Day::parse("2023-06-26").unwrap())
        );
        assert!(
            movements
                .iter()
                .filter(|m| !m.kind.is_debit())
                .skip(3)
                .all(|m| m.earliest > Day::parse("2023-04-12").unwrap())
        );
        let before_social = oldest[0].cents + oldest[1].cents;
        assert!(before_social < debits && debits < before_social + oldest[2].cents);

        let fixture = Fixture::new();
        let trusted_key = fa_verify::blake3::hex(&fixture.open().checkpoint_public_key());
        std::fs::write(fixture.dir.join("trusted-checkpoint-key.txt"), &trusted_key).unwrap();
        let chart = write(
            &fixture.dir,
            "minc-chart.json",
            r#"{"accounts":[{"code":"1000","name":"Chase account","type":"Asset","unit":"USD"},{"code":"4000","name":"Reconstruction offset","type":"Equity","unit":"USD"}]}"#,
        );
        ok(&fixture.book, &["chart", "import", &chart]);
        for year in ["2023", "2024"] {
            ok(&fixture.book, &["period", "create", "--fiscal-year", year]);
        }
        let transcription = write(&fixture.dir, "fifo-movements.tsv", movement_table);
        let doc = evidence(&fixture, &transcription);
        let periods: BTreeSet<_> = movements
            .iter()
            .map(|movement| {
                let date = movement.reconstruction_day();
                format!("FY{}-P{:02}", date.year, date.month)
            })
            .collect();
        for period in periods {
            ok(&fixture.book, &["period", "open", &period]);
        }
        let mut sources = Vec::new();
        let mut frontiers = BTreeMap::new();
        let mut observed_cash = 0;
        for group in movements.chunk_by(|a, b| a.observed == b.observed) {
            let observed = group[0].observed;
            let (known_at, entries) = post_observation(&fixture, group, &doc);
            assert!(frontiers.insert(observed, known_at).is_none());
            for (m, entry) in group.iter().copied().zip(entries) {
                observed_cash += if m.kind.is_debit() { -m.cents } else { m.cents };
                if matches!(m.kind, MovementKind::Opening | MovementKind::Other) {
                    sources.push((m, entry));
                }
            }
            assert_eq!(cash_at(&fixture, observed, known_at), observed_cash);
        }
        assert_eq!(frontiers.len(), 18);
        assert_eq!(observed_cash, expected_balance);
        let december = Day::parse("2023-12-26").unwrap();
        let petition = Day::parse(PETITION).unwrap();
        assert_eq!(cash_at(&fixture, december, frontiers[&december]), 2_850_675);
        assert_eq!(cash_at(&fixture, december, frontiers[&petition]), 3_006_875);
        let (opening, others) = sources.split_first().unwrap();
        assert_eq!(opening.0.kind, MovementKind::Opening);
        assert_eq!(others.len(), 20);
        let opening_remaining = trace_at(&fixture, &opening.1, PETITION);
        let other_remaining: i128 = others
            .iter()
            .map(|(m, vid)| {
                let cents = trace_at(&fixture, vid, PETITION);
                assert_eq!(
                    cents,
                    if m.printed == "04/03/23" { 0 } else { m.cents },
                    "{endpoint}, {}",
                    m.printed
                );
                cents
            })
            .sum();
        assert_eq!(
            other_remaining, court_other_cents,
            "{endpoint}, opening Social Security"
        );
        assert_eq!(
            other_remaining + opening_remaining,
            court_other_cents,
            "{endpoint}, opening other"
        );

        let cohort = verify_sources(&fixture, endpoint, &trusted_key, &sources);
        let claims = &cohort.claims;
        let (opening_claim, other_claims) = claims.split_first().unwrap();
        let recipient_other: i128 = other_claims.iter().map(|c| c.cents).sum();
        assert_eq!(recipient_other, court_other_cents);
        assert_eq!(recipient_other + opening_claim.cents, court_other_cents);
        assert_eq!(cohort.total, court_other_cents);

        if endpoint == "schedule-debit" {
            // The hypotheses really differ before exhaustion: the April 25
            // other-source balances in Appendices 1 and 2 (pp. 44 and 51).
            let april_other: i128 = others
                .iter()
                .filter(|(m, _)| m.observed == Day::parse("2023-04-25").unwrap())
                .map(|(_, vid)| trace_at(&fixture, vid, "2023-04-25"))
                .sum();
            assert_eq!(april_other, 600_917);
            assert_eq!(
                april_other + trace_at(&fixture, &opening.1, "2023-04-25"),
                3_177_716
            );
            // A further debit that consumes the April 12 remainder plus one
            // cent must now reach the April 18 other-source deposit.
            let extra = before_social + oldest[2].cents - debits + 1;
            let hypothetical = write(
                &fixture.dir,
                "counterfactual.txt",
                "Sensitivity test only: exhaust the April 12 deposit plus one cent. This withdrawal was not reported by the court.",
            );
            let scenario_doc = evidence(&fixture, &hypothetical);
            withdrawal(
                &fixture,
                "counterfactual",
                PETITION,
                &dollars(extra),
                &scenario_doc,
            );
            let changed: i128 = others
                .iter()
                .map(|(_, vid)| trace_at(&fixture, vid, PETITION))
                .sum();
            assert_eq!(changed, other_remaining - 1);

            // A genuine, freshly signed changed claim for the same April 18
            // deposit is valid on its later frontier. It cannot replace the
            // originally selected claim or use its signed production receipt.
            let at = sources
                .iter()
                .position(|(m, _)| m.printed == "04/18/23")
                .unwrap();
            let original = &claims[at];
            let changed =
                verify_sources(&fixture, "counterfactual", &trusted_key, &sources[at..=at]);
            let changed = &changed.claims[0];
            assert_eq!(changed.source, original.source);
            assert_eq!(changed.cents, original.cents - 1);
            let dir = fixture.dir.join("counterfactual");
            let receipt = format!("{}.receipt", changed.source);
            std::fs::copy(
                fixture.dir.join(endpoint).join(&receipt),
                dir.join("original.receipt"),
            )
            .unwrap();
            for (pin, receipt, expected_check) in [
                (
                    original.pin.as_str(),
                    receipt.as_str(),
                    "recipient_certificate",
                ),
                (
                    changed.pin.as_str(),
                    "original.receipt",
                    "production_receipt",
                ),
            ] {
                let refusal = judge(&dir, &changed.source, &trusted_key, pin, receipt);
                assert_eq!(refusal.exit, 8, "{}\n{}", refusal.stdout, refusal.stderr);
                let report = json::parse(&refusal.stdout).unwrap();
                let rejected = get(&report, "checks")
                    .as_arr()
                    .unwrap()
                    .iter()
                    .any(|r| text(r, "check") == expected_check && text(r, "result") == "fail");
                assert!(rejected, "{}", refusal.stdout);
            }
        }
    }
}
