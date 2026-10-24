//! Integration tests for `fa-demo` (`fa demo init`, convergence gate `G3-02`, bead `fa-v6j`).

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fa::TrialBalanceSelection;
use fa::book::{Book, BookKeys, Entropy};
use fa_demo::{Scenario, init_dir, us_bank_call_report_accounts, us_gaap_smb_accounts};
use fa_money::UnitRegistry;

fn temp_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("fa-demo-test-{}-{tag}-{n}", std::process::id()));
        if std::fs::create_dir(&dir).is_ok() {
            return dir;
        }
    }
}

#[test]
fn retail_seed_7_is_byte_deterministic_across_runs() {
    let d1 = temp_dir("retail-7-a").join("book");
    let d2 = temp_dir("retail-7-b").join("book");
    let k1 = d1.join("book.keys");
    let k2 = d2.join("book.keys");

    let r1 = init_dir(&d1, &k1, Scenario::Retail, 7).expect("init_dir run 1");
    let r2 = init_dir(&d2, &k2, Scenario::Retail, 7).expect("init_dir run 2");

    assert_eq!(r1.book_id, r2.book_id);
    assert_eq!(r1.journal_digest, r2.journal_digest);
    assert_eq!(r1.checkpoint_oid, r2.checkpoint_oid);
    assert_eq!(r1.migration_run_vid, r2.migration_run_vid);
    assert_eq!(r1.head_seq, r2.head_seq);
    assert_eq!(r1.planted_facts, r2.planted_facts);
    assert_eq!(
        std::fs::read(&r1.readme).expect("readme 1"),
        std::fs::read(&r2.readme).expect("readme 2"),
        "README.md must be byte-identical across seeded runs"
    );
    assert_eq!(
        std::fs::read(&k1).expect("keys 1"),
        std::fs::read(&k2).expect("keys 2"),
        "book.keys must be byte-identical across seeded runs"
    );

    let r_other = init_dir(
        &temp_dir("retail-42").join("book"),
        &temp_dir("retail-42-k").join("book.keys"),
        Scenario::Retail,
        42,
    )
    .expect("init_dir seed 42");
    assert_ne!(r1.book_id, r_other.book_id);
    assert_ne!(r1.journal_digest, r_other.journal_digest);
}

#[test]
fn all_scenarios_initialize_verify_and_trigger_planted_lantern_findings() {
    let units = UnitRegistry::embedded().expect("units");
    let usd = units.lookup("USD").expect("USD");
    assert_eq!(us_gaap_smb_accounts(usd).len(), 52);
    assert_eq!(us_bank_call_report_accounts(usd).len(), 58);

    for scenario in Scenario::ALL {
        let dir = temp_dir(scenario.as_str()).join("book");
        let keys_path = dir.join("book.keys");
        let info = init_dir(&dir, &keys_path, scenario, 7)
            .unwrap_or_else(|e| panic!("init_dir failed for {scenario}: {e}"));

        assert!(info.readme.is_file(), "{scenario}: README.md must exist");
        assert!(
            info.planted_facts.len() >= 5,
            "{scenario}: expected at least 5 planted facts, got {}",
            info.planted_facts.len()
        );

        let keys = BookKeys::load(&keys_path).expect("load keys");
        let book = Book::open_dir(&dir, keys, Entropy::deterministic(7)).expect("open_dir");
        let tb = book
            .certify_trial_balance(
                TrialBalanceSelection::Periods(vec!["FY2026-P03".into()]),
                None,
            )
            .expect("certify_trial_balance")
            .expect("tb ok");
        assert!(!tb.report.rows.is_empty(), "{scenario}: non-empty TB");

        let proc: Box<dyn fa_lantern::Procedure> = match scenario {
            Scenario::Retail | Scenario::GhostPayroll => {
                Box::new(fa_lantern::duplicates::SameSameSame::new().expect("same_same_same"))
            }
            Scenario::Bank | Scenario::Ponzi | Scenario::ShellNetwork => {
                Box::new(fa_lantern::graph::RoundTrips::new().expect("round_trips"))
            }
            Scenario::WorldCom => Box::new(fa_lantern::jet::Weekend::new().expect("weekend")),
            Scenario::ChannelStuffing => {
                Box::new(fa_lantern::cutoff::PeriodBoundary::new().expect("period_boundary"))
            }
        };
        let run = book
            .run_procedure(
                proc.as_ref(),
                None,
                Some(fa_time::DateDay::from_ymd(2026, 3, 31).expect("date")),
                None,
            )
            .unwrap_or_else(|e| panic!("{scenario}/{}: {e}", proc.id()));
        assert!(
            !run.findings.is_empty(),
            "{scenario}: expected planted finding from `{}`",
            proc.id()
        );
    }
}

/// A demo book journals its chart template's account roles and its planted
/// schemes' parties (beads fa-kxc4, fa-b6xs, fa-6l8g), so the role-selected
/// and party-level procedures run on the book itself: every role-selected
/// procedure whose roles the template carries runs instead of refusing, the
/// shell network's conduit cycle is found through its parties, and the Ponzi
/// book's net-equity schedule holds each investor's own money.
#[test]
fn role_selected_and_party_procedures_run_on_demo_books() {
    use fa_lantern::{Params, catalog};

    let through = Some(fa_time::DateDay::from_ymd(2026, 3, 31).expect("date"));
    let open = |scenario: Scenario| {
        let dir = temp_dir(&format!("parties-{scenario}")).join("book");
        let keys_path = dir.join("book.keys");
        init_dir(&dir, &keys_path, scenario, 7)
            .unwrap_or_else(|e| panic!("init_dir failed for {scenario}: {e}"));
        let keys = BookKeys::load(&keys_path).expect("load keys");
        Book::open_dir(&dir, keys, Entropy::deterministic(7)).expect("open_dir")
    };
    let run = |book: &Book, id: &str, params: &[(&str, i128)]| {
        let mut p = Params::defaults(id).expect("defaults");
        for (name, value) in params {
            p = p.set(name, *value).expect("param");
        }
        let procedure = catalog::build(id, p, catalog::Inputs::default()).expect("build");
        book.run_procedure(procedure.as_ref(), None, through, None)
            .unwrap_or_else(|e| panic!("{id}: {e}"))
    };

    // Every role these procedures read is in the us-gaap-smb template; a book
    // without journaled roles refuses each with RoleUnassigned.
    let retail = open(Scenario::Retail);
    for id in [
        "recon.lapping",
        "expense.capitalization",
        "aging.inventory",
        "payroll.ghost",
        "confirm.coverage",
        "solvency.cash_flow_test",
        "lookback.preferences",
    ] {
        let r = run(&retail, id, &[]);
        println!("retail {id}: {} findings", r.findings.len());
    }

    let shell = open(Scenario::ShellNetwork);
    let r = run(&shell, "graph.party_circular_flows", &[]);
    println!("shell-network party cycles: {:?}", r.findings);
    assert!(
        r.findings.iter().any(|f| f
            .narrative
            .contains("through parties SHELL-A -> SHELL-B -> SHELL-C -> SHELL-A")),
        "{:?}",
        r.findings
    );

    let ponzi = open(Scenario::Ponzi);
    let r = run(&ponzi, "ponzi.net_investment", &[]);
    println!("ponzi net investment: {:?}", r.findings);
    let mut claims: Vec<(String, i128)> = r
        .findings
        .iter()
        .map(|f| {
            (
                f.narrative
                    .split_whitespace()
                    .nth(1)
                    .expect("investor")
                    .to_string(),
                f.statistic.value,
            )
        })
        .collect();
    claims.sort();
    // INV-A: 100,000.00 in, 50,000.00 back; INV-B: 60,000.00 in.
    assert_eq!(
        claims,
        vec![
            ("INV-A".to_string(), 5_000_000),
            ("INV-B".to_string(), 6_000_000)
        ]
    );
    let r = run(&ponzi, "graph.ponzi_motif", &[("window_days", 14)]);
    println!("ponzi motif: {:?}", r.findings);
    assert!(
        r.findings
            .iter()
            .any(|f| f.narrative.contains("new investors [INV-B]")
                && f.narrative.contains("earlier investors [INV-A]")),
        "{:?}",
        r.findings
    );
}
