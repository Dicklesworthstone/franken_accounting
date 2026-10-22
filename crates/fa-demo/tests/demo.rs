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
