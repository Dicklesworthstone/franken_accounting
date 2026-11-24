//! Large native scenario plans remain replayable after a directory reopen.
//! This uses real producer certificates and exact posted scratch amounts.

use fa::{Book, BookKeys, Entropy};
use fa_intents::PostIntent;
use fa_journal::{AccountSpec, BookSpec, Capability, Document, ScenarioFork, UnitPolicy};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, Id128, LegPayload, Oid, account_vid,
    entry_vid,
};
use fa_money::{Amount, Side, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb_types::VId;

#[test]
fn oversized_scenario_plan_reopens_and_replays_real_certified_accounting() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("fa-large-scenario-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let seed = 236;
    let principal = VId(1);
    let day = DateDay::from_ymd(2026, 3, 15).unwrap();
    let period = "FY2026-P03".to_string();
    let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
    let book_id = Id128([seed; 16]);
    let mut book = Book::create_dir(
        &directory,
        BookKeys::for_development(seed),
        BookSpec {
            book_id,
            name: "Large scenario storage".into(),
            base_unit: usd,
            calendar: FiscalCalendar::monthly("large-scenario", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(u64::from(seed)),
    )
    .unwrap();
    let schema = Capability::embedded(principal, &["schema_change"]).unwrap();
    let accounts = [("1000", AccountType::ASSET), ("6000", AccountType::EXPENSE)].map(
        |(code, account_type)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type: account_type.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        },
    );
    book.install_chart(&accounts, principal, day, b"chart", &schema)
        .unwrap()
        .unwrap();
    book.create_periods(2026, principal, &schema)
        .unwrap()
        .unwrap();
    book.transition_period(
        &period,
        PeriodTransition::Open,
        principal,
        1,
        b"open",
        &Capability::embedded(principal, &["close"]).unwrap(),
    )
    .unwrap()
    .unwrap();
    let document = Document {
        book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: principal,
        bytes: b"Reviewed counterfactual expense allocation".to_vec(),
    };
    book.add_document(&document).unwrap().unwrap();
    let planner = Capability::embedded(principal, &["read", "post"]).unwrap();
    book.open_scenario(
        planner.clone(),
        "large",
        ScenarioFork::default(),
        day,
        "What if every approved cost center incurred the expense?",
    )
    .unwrap()
    .unwrap();
    let legs: Vec<_> = (0..256)
        .flat_map(|_| {
            [
                LegPayload::simple(
                    Side::Debit,
                    account_vid(book_id, "6000"),
                    Amount::new(usd, 100),
                ),
                LegPayload::simple(
                    Side::Credit,
                    account_vid(book_id, "1000"),
                    Amount::new(usd, 100),
                ),
            ]
        })
        .collect();
    let proposal = EntryPayload {
        schema_minor: 0,
        book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: day,
        document_date: None,
        description: book
            .seal_text("Complete 256-pair expense scenario")
            .unwrap(),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: b"large-scenario-source".to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([236; 32]),
            intent_kind: 1,
        },
        principal_ref: principal,
        session_ref: None,
        evidence: vec![document.evidence_ref(1)],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    let intent = PostIntent::new(proposal, Vec::new()).unwrap();
    assert!(intent.canonical_bytes().unwrap().len() > 16 * 1024);
    let before = book.head().unwrap();
    let baseline = book.trial_balance(&[period.clone()]).unwrap();
    let ran = book
        .run_in_scenario(planner.clone(), "large", intent.clone())
        .unwrap()
        .unwrap();
    assert!(ran.rehearsed.is_some());
    assert_eq!(ran.ordinal, 1);
    assert_eq!(book.head().unwrap().0, before.0 + 1);
    let retained_control = book
        .read_entry(ran.recorded.control_entry)
        .unwrap()
        .unwrap();
    assert!(retained_control.0.encode().unwrap().len() > 16 * 1024);
    assert_eq!(
        retained_control.0.proposal.class,
        EntryClass::SCENARIO_CONTROL
    );
    assert_eq!(
        book.trial_balance(&[period.clone()]).unwrap().rows,
        baseline.rows
    );
    assert!(
        book.read_entry(entry_vid(
            book_id,
            &principal.0.to_le_bytes(),
            b"large-scenario-source",
        ))
        .unwrap()
        .is_none(),
        "a scenario cannot publish its monetary proposal to trunk"
    );

    let producer = Capability::embedded(principal, &["read", "produce"]).unwrap();
    let certified_at = book.head().unwrap();
    let certified = book
        .certify_scenario_diff(principal, &producer, "large", &[period.clone()], false)
        .unwrap()
        .unwrap();
    assert_eq!(book.head().unwrap(), certified_at);
    assert_eq!(certified.report.intents, 1);
    assert_eq!(
        certified
            .report
            .rows
            .iter()
            .map(|row| (row.code.as_str(), row.delta))
            .collect::<Vec<_>>(),
        [("1000", -25_600), ("6000", 25_600)],
    );
    book.retain_scenario_diff(principal, &producer, &certified.certificate)
        .unwrap()
        .unwrap();
    let saved_at = book.head().unwrap();
    drop(book);

    let mut book = Book::open_dir(
        &directory,
        BookKeys::for_development(seed),
        Entropy::deterministic(237),
    )
    .unwrap();
    assert_eq!(book.head().unwrap(), saved_at);
    assert_eq!(
        book.read_entry(ran.recorded.control_entry)
            .unwrap()
            .unwrap(),
        retained_control
    );
    let view = book.scenario("large").unwrap().unwrap();
    assert_eq!(view.intents.len(), 1);
    assert_eq!(view.intents[0].intent, intent);
    assert_eq!(
        book.replay_scenario_diff(principal, &producer, &certified.certificate)
            .unwrap()
            .unwrap(),
        certified.report,
    );
    let retry = book
        .run_in_scenario(planner, "large", intent)
        .unwrap()
        .unwrap();
    assert!(retry.recorded.already_recorded);
    assert!(retry.rehearsed.is_none());
    assert_eq!(retry.recorded.control_entry, ran.recorded.control_entry);
    assert_eq!(retry.recorded.recorded_at, ran.recorded.recorded_at);
    assert_eq!(book.head().unwrap(), saved_at);
    assert_eq!(book.trial_balance(&[period]).unwrap().rows, baseline.rows);
}
