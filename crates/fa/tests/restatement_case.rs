//! Restatement cases through the public facade (plan §8.3, bead fa-75j4):
//! a journaled case body, its determination, its numbering and its
//! refusals, over a real memory book.

use std::collections::{BTreeMap, BTreeSet};

use fa::{Book, BookKeys, Entropy, ScenarioDiff};
use fa_intents::PostIntent;
use fa_journal::refusal::code;
use fa_journal::{
    AccountSpec, BookSpec, Capability, CaseKind, CaseState, Determination, Document, PostRequest,
    ScenarioFork, UnitPolicy,
};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, Id128, LegPayload, Oid, account_vid,
};
use fa_money::{Amount, Side, UnitRegistry};
use fa_policy::{Op, Profile};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb_types::VId;

const PRINCIPAL: VId = VId(1);

/// fa-75j4 acceptance: the rehearsal's diff is the posted diff. Every
/// (account, unit) the case's Post moved moved by exactly the rehearsal's
/// delta, and nothing else moved.
fn assert_posted_diff_is_the_rehearsed_one(
    before: &fa_registers::TrialBalance,
    after: &fa_registers::TrialBalance,
    rehearsed: &ScenarioDiff,
) {
    let net = |tb: &fa_registers::TrialBalance| -> BTreeMap<(String, u32), i128> {
        tb.rows
            .iter()
            .map(|row| ((row.code.clone(), row.unit_id), row.debits - row.credits))
            .collect()
    };
    let (before, after) = (net(before), net(after));
    let cells: BTreeSet<(String, u32)> = before.keys().chain(after.keys()).cloned().collect();
    let posted: BTreeMap<(String, u32), i128> = cells
        .into_iter()
        .filter_map(|cell| {
            let moved =
                after.get(&cell).copied().unwrap_or(0) - before.get(&cell).copied().unwrap_or(0);
            (moved != 0).then_some((cell, moved))
        })
        .collect();
    let rehearsal: BTreeMap<(String, u32), i128> = rehearsed
        .rows
        .iter()
        .filter(|row| row.delta != 0)
        .map(|row| ((row.code.clone(), row.unit_id), row.delta))
        .collect();
    assert!(!rehearsal.is_empty(), "the rehearsal changes something");
    assert_eq!(posted, rehearsal, "the posted diff is the rehearsed diff");
}

fn day(year: i32, month: u8, day: u8) -> DateDay {
    DateDay::from_ymd(year, month, day).unwrap()
}

fn retain_case_comparisons(book: &mut Book, ordinal: u32) -> Vec<[u8; 32]> {
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap();
    let requests = book
        .case_statement_diff_requests(PRINCIPAL, &capability, ordinal, None)
        .unwrap()
        .unwrap();
    let mut digests = Vec::new();
    for request in requests {
        let certificate = if request.functional {
            book.certify_functional_statement_diff(PRINCIPAL, &capability, &request.request)
        } else {
            book.certify_statement_diff(PRINCIPAL, &capability, &request.request)
        }
        .unwrap()
        .unwrap()
        .certificate;
        let digest = *certificate.digest();
        book.retain_report_artifact(
            PRINCIPAL,
            &capability,
            &certificate.canonical_bytes().unwrap(),
            Some(&digest),
        )
        .unwrap()
        .unwrap();
        digests.push(digest);
    }
    digests.sort();
    digests.dedup();
    digests
}

fn issue_original_case_statement(book: &mut Book, period: &str) {
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce", "close"]).unwrap();
    let certificate = book
        .certify_statement(
            fa::StatementSelection {
                definition: fa::StatementDefinition::embedded("balance-sheet").unwrap(),
                periods: vec![period.into()],
                comparative: Vec::new(),
            },
            None,
        )
        .unwrap()
        .unwrap()
        .certificate;
    book.retain_certificate(PRINCIPAL, &capability, &certificate)
        .unwrap()
        .unwrap();
    let plan = book
        .plan_statement_issuance(
            &capability,
            &certificate.digest,
            Some(period),
            fa_journal::IssuedTo::Auditor,
            None,
            day(2026, 1, 10),
            b"original-case-statement",
        )
        .unwrap()
        .unwrap();
    let approval = book
        .approve(
            Capability::embedded(VId(9), &["approve"]).unwrap(),
            plan.proposal_digest(book.context()).unwrap(),
        )
        .unwrap()
        .unwrap()
        .approval();
    book.issue_statements(&capability, plan, vec![approval])
        .unwrap()
        .unwrap();
}

fn book(seed: u8) -> (Book, Oid, Oid) {
    let units = UnitRegistry::embedded().unwrap();
    let book_id = Id128([seed; 16]);
    let spec = BookSpec {
        book_id,
        name: "Restatement case fixture".into(),
        base_unit: units.lookup("USD").unwrap(),
        calendar: FiscalCalendar::monthly("case-calendar", 1, 1).unwrap(),
        time_zone_policy: None,
        entities: Vec::new(),
        opening_date: None,
    };
    let mut book = Book::create_memory(
        BookKeys::for_development(seed),
        spec,
        Entropy::deterministic(u64::from(seed)),
    )
    .unwrap();
    let schema = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
    book.install_chart(
        &[
            AccountSpec {
                code: "1000".into(),
                name: "Cash".into(),
                account_type: AccountType::ASSET.0,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::AnyCurrency,
                parent_code: None,
                limit: None,
            },
            AccountSpec {
                code: "3000".into(),
                name: "Retained earnings".into(),
                account_type: AccountType::EQUITY.0,
                normal_balance: 1,
                is_leaf: true,
                unit_policy: UnitPolicy::AnyCurrency,
                parent_code: None,
                limit: None,
            },
        ],
        PRINCIPAL,
        day(2025, 1, 1),
        b"case-chart",
        &schema,
    )
    .unwrap()
    .unwrap();
    book.create_periods(2025, schema.holder(), &schema)
        .unwrap()
        .unwrap();
    let mut add = |bytes: &[u8]| {
        let document = Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: bytes.to_vec(),
        };
        book.add_document(&document).unwrap().unwrap();
        document.oid()
    };
    let narrative = add(b"Restatement memo: revenue cutoff error in December 2025");
    let authority =
        add(b"Audit committee minutes: the 2025 statements should no longer be relied on");
    (book, narrative, authority)
}

#[test]
fn a_case_is_journaled_numbered_determined_once_and_read_back() {
    let (mut book, narrative, authority) = book(0xc5);
    let restate = Capability::embedded(PRINCIPAL, &["restate"]).unwrap();
    let date = day(2026, 2, 1);
    assert!(book.cases().unwrap().is_empty());

    let opened = book
        .open_case(
            restate.clone(),
            CaseKind::Restatement,
            vec!["FY2025-P12".into(), "FY2025-P11".into()],
            Some(narrative),
            None,
            date,
            b"cutoff",
        )
        .unwrap()
        .unwrap();
    assert!(!opened.already_recorded);
    let case = &opened.case;
    assert_eq!(case.body.ordinal, 1);
    assert_eq!(case.state, CaseState::Proposed);
    assert_eq!(case.body.periods, ["FY2025-P11", "FY2025-P12"], "sorted");
    assert_eq!(case.body.narrative, Some(narrative));
    assert_eq!(case.determination, None);
    assert_eq!(case.transitions.len(), 1);
    assert_eq!(case.transitions[0].from, None);
    assert_eq!(case.transitions[0].to, CaseState::Proposed);
    assert_eq!(case.transitions[0].control_entry, opened.control_entry);
    let head = book.head().unwrap();
    assert_eq!(head, opened.recorded_at);

    // The identical request returns the recorded case and writes nothing.
    let again = book
        .open_case(
            restate.clone(),
            CaseKind::Restatement,
            vec!["FY2025-P11".into(), "FY2025-P12".into()],
            Some(narrative),
            None,
            date,
            b"cutoff",
        )
        .unwrap()
        .unwrap();
    assert!(again.already_recorded);
    assert_eq!(again.case, opened.case);
    assert_eq!(book.head().unwrap(), head);
    // Another request under the same key is a conflict.
    assert_eq!(
        book.open_case(
            restate.clone(),
            CaseKind::Revision,
            vec!["FY2025-P12".into()],
            None,
            None,
            date,
            b"cutoff",
        )
        .unwrap()
        .unwrap_err()
        .code,
        code::IDEMPOTENCY_CONFLICT
    );

    let determination = Determination {
        day: day(2026, 1, 28),
        authority,
    };
    let determined = book
        .determine_case(restate.clone(), 1, determination, date, b"non-reliance")
        .unwrap()
        .unwrap();
    assert_eq!(determined.case.state, CaseState::Determined);
    assert_eq!(determined.case.determination, Some(determination));
    assert_eq!(
        determined
            .case
            .transitions
            .iter()
            .map(|t| (t.from, t.to))
            .collect::<Vec<_>>(),
        [
            (None, CaseState::Proposed),
            (Some(CaseState::Proposed), CaseState::Determined)
        ]
    );
    // Determining again is refused: each transition is journaled once.
    let twice = book
        .determine_case(restate.clone(), 1, determination, date, b"again")
        .unwrap()
        .unwrap_err();
    assert_eq!((twice.code, twice.exit), (code::CASE_STATE, 3));

    // A case opened with its determination starts Determined, numbered next.
    let second = book
        .open_case(
            restate.clone(),
            CaseKind::Revision,
            vec!["FY2025-P10".into()],
            None,
            Some(determination),
            date,
            b"little-r",
        )
        .unwrap()
        .unwrap();
    assert_eq!(second.case.body.ordinal, 2);
    assert_eq!(second.case.state, CaseState::Determined);
    assert_eq!(
        book.cases()
            .unwrap()
            .iter()
            .map(|c| (c.body.ordinal, c.state))
            .collect::<Vec<_>>(),
        [(1, CaseState::Determined), (2, CaseState::Determined)]
    );
    assert_eq!(book.case(1).unwrap().unwrap(), determined.case);
    assert!(book.case(3).unwrap().is_none());
}

#[test]
fn a_case_is_refused_before_anything_is_written() {
    let (mut book, narrative, authority) = book(0xc6);
    let restate = Capability::embedded(PRINCIPAL, &["restate"]).unwrap();
    let date = day(2026, 2, 1);
    let head = book.head().unwrap();
    let open = |book: &mut Book, cap: &Capability, periods: &[&str], narrative: Option<Oid>| {
        book.open_case(
            cap.clone(),
            CaseKind::Restatement,
            periods.iter().map(|p| (*p).to_string()).collect(),
            narrative,
            None,
            date,
            b"k",
        )
        .unwrap()
        .unwrap_err()
    };
    // Authority first: no restate, and an Agent (which cannot hold restate).
    let no_restate = Capability::embedded(PRINCIPAL, &["post", "close"]).unwrap();
    assert_eq!(
        open(&mut book, &no_restate, &["FY2025-P12"], None).code,
        code::CAPABILITY
    );
    let agent = Capability::new(VId(9), Profile::Agent, &[Op::Read, Op::Post], PRINCIPAL).unwrap();
    assert!(
        [code::CAPABILITY, "FA-REF-013"]
            .contains(&open(&mut book, &agent, &["FY2025-P12"], None).code)
    );
    // The body: no period, an unknown period, an unknown narrative document.
    assert_eq!(open(&mut book, &restate, &[], None).code, code::STRUCTURE);
    assert_eq!(
        open(&mut book, &restate, &["FY2099-P01"], None).code,
        code::PERIOD_UNKNOWN
    );
    assert_eq!(
        open(&mut book, &restate, &["FY2025-P12"], Some(Oid([0x77; 32]))).code,
        code::EVIDENCE_UNKNOWN
    );
    // Determining a case that does not exist, or with an unknown authority.
    let determination = Determination {
        day: day(2026, 1, 28),
        authority,
    };
    assert_eq!(
        book.determine_case(restate.clone(), 1, determination, date, b"d")
            .unwrap()
            .unwrap_err()
            .code,
        code::CASE_UNKNOWN
    );
    assert_eq!(book.head().unwrap(), head, "every refusal writes nothing");
    book.open_case(
        restate.clone(),
        CaseKind::Restatement,
        vec!["FY2025-P12".into()],
        Some(narrative),
        None,
        date,
        b"open",
    )
    .unwrap()
    .unwrap();
    let opened_at = book.head().unwrap();
    assert_eq!(
        book.determine_case(
            restate,
            1,
            Determination {
                day: day(2026, 1, 28),
                authority: Oid([0x66; 32]),
            },
            date,
            b"d",
        )
        .unwrap()
        .unwrap_err()
        .code,
        code::EVIDENCE_UNKNOWN
    );
    assert_eq!(book.head().unwrap(), opened_at);
    assert_eq!(book.case(1).unwrap().unwrap().state, CaseState::Proposed);
}

/// fa-75j4 slice 2 (plan §8.3: Rehearsed "on a branch or scratch book, with
/// the as-reported-vs-as-restated diff certificate attached"): a Determined
/// case is rehearsed with its scenario's replayed and retained diff
/// certificate, once; a diff that misses an affected period, a discarded
/// scenario and a case not yet Determined are refused before any record.
#[test]
fn a_determined_case_is_rehearsed_with_its_retained_diff_certificate() {
    let (mut book, narrative, authority) = book(0xc7);
    let restate = Capability::embedded(PRINCIPAL, &["restate", "read", "produce"]).unwrap();
    let post = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let date = day(2026, 2, 1);
    let determination = Determination {
        day: day(2026, 1, 28),
        authority,
    };
    let opened = book
        .open_case(
            restate.clone(),
            CaseKind::Restatement,
            vec!["FY2025-P12".into()],
            Some(narrative),
            Some(determination),
            date,
            b"determined",
        )
        .unwrap()
        .unwrap();
    assert_eq!(opened.case.state, CaseState::Determined);
    book.open_scenario(
        post.clone(),
        "restated",
        ScenarioFork::default(),
        date,
        "The December cutoff, corrected",
    )
    .unwrap()
    .unwrap();
    let periods = |codes: &[&str]| codes.iter().map(|c| (*c).to_string()).collect::<Vec<_>>();
    let covering = book
        .certify_scenario_diff(
            PRINCIPAL,
            &restate,
            "restated",
            &periods(&["FY2025-P12"]),
            false,
        )
        .unwrap()
        .unwrap()
        .certificate;
    let elsewhere = book
        .certify_scenario_diff(
            PRINCIPAL,
            &restate,
            "restated",
            &periods(&["FY2025-P11"]),
            false,
        )
        .unwrap()
        .unwrap()
        .certificate;

    // A diff over another period does not rehearse this case.
    let head = book.head().unwrap();
    let missed = book
        .rehearse_case(restate.clone(), 1, &elsewhere, date, b"elsewhere")
        .unwrap()
        .unwrap_err();
    assert_eq!(missed.code, code::CASE_REHEARSAL, "{missed:?}");
    assert!(missed.message.contains("FY2025-P12"), "{missed:?}");
    assert_eq!(book.case(1).unwrap().unwrap().state, CaseState::Determined);
    assert!(
        book.head().unwrap() > head,
        "the replayed certificate was retained"
    );

    let rehearsed = book
        .rehearse_case(restate.clone(), 1, &covering, date, b"rehearsal")
        .unwrap()
        .unwrap();
    assert!(!rehearsed.already_recorded);
    let case = &rehearsed.case;
    assert_eq!(case.state, CaseState::Rehearsed);
    let attached = case.rehearsal.as_ref().unwrap();
    assert_eq!(attached.scenario, "restated");
    assert_eq!(&attached.certificate, covering.digest());
    assert_eq!(attached.fork_at, covering.trunk().known_at);
    assert_eq!(attached.periods, ["FY2025-P12"]);
    assert_eq!(attached.intents, covering.intents());
    assert_eq!(
        case.transitions.last().map(|t| (t.from, t.to)),
        Some((Some(CaseState::Determined), CaseState::Rehearsed))
    );
    // The identical request is the recorded rehearsal; another is refused.
    let head = book.head().unwrap();
    let again = book
        .rehearse_case(restate.clone(), 1, &covering, date, b"rehearsal")
        .unwrap()
        .unwrap();
    assert!(again.already_recorded);
    assert_eq!(again.case, rehearsed.case);
    assert_eq!(book.head().unwrap(), head);
    let twice = book
        .rehearse_case(restate.clone(), 1, &covering, date, b"second")
        .unwrap()
        .unwrap_err();
    assert_eq!(twice.code, code::CASE_STATE, "{twice:?}");

    // A Proposed case is not rehearsed; nor is any case on a discarded
    // scenario.
    book.open_case(
        restate.clone(),
        CaseKind::Revision,
        vec!["FY2025-P12".into()],
        None,
        None,
        date,
        b"proposed",
    )
    .unwrap()
    .unwrap();
    let early = book
        .rehearse_case(restate.clone(), 2, &covering, date, b"early")
        .unwrap()
        .unwrap_err();
    assert_eq!(early.code, code::CASE_STATE, "{early:?}");
    book.determine_case(restate.clone(), 2, determination, date, b"determine-2")
        .unwrap()
        .unwrap();
    book.discard_scenario(post, "restated", date, "superseded")
        .unwrap()
        .unwrap();
    let gone = book
        .rehearse_case(restate.clone(), 2, &covering, date, b"gone")
        .unwrap()
        .unwrap_err();
    assert_eq!(gone.code, code::CASE_REHEARSAL, "{gone:?}");
    assert_eq!(book.case(2).unwrap().unwrap().state, CaseState::Determined);

    // Without restate nothing is replayed, retained or recorded.
    let head = book.head().unwrap();
    let reader = Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap();
    let denied = book
        .rehearse_case(reader, 2, &covering, date, b"denied")
        .unwrap()
        .unwrap_err();
    assert_eq!(denied.exit, 7, "{denied:?}");
    assert_eq!(book.head().unwrap(), head);
}

/// fa-75j4 slice 3 (plan §8.3: Approved "dual control, by principals with
/// restate capability, neither of whom prepared any entry in the case"):
/// the manifest's digest is what approvers approve; one approval, or one by
/// the case record's preparer, is refused; two distinct Human approvers
/// approve it, once.
#[test]
fn a_rehearsed_case_is_approved_under_dual_control() {
    let (mut book, narrative, authority) = book(0xc9);
    let restate = Capability::embedded(PRINCIPAL, &["restate", "read", "produce"]).unwrap();
    let post = Capability::embedded(PRINCIPAL, &["post"]).unwrap();
    let date = day(2026, 2, 1);
    book.open_case(
        restate.clone(),
        CaseKind::Restatement,
        vec!["FY2025-P12".into()],
        Some(narrative),
        Some(Determination {
            day: day(2026, 1, 28),
            authority,
        }),
        date,
        b"determined",
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        book.case_manifest(1).unwrap().unwrap_err().code,
        code::CASE_STATE,
        "only a Rehearsed case has a manifest"
    );
    book.open_scenario(post, "restated", ScenarioFork::default(), date, "corrected")
        .unwrap()
        .unwrap();
    let certificate = book
        .certify_scenario_diff(
            PRINCIPAL,
            &restate,
            "restated",
            &["FY2025-P12".to_string()],
            false,
        )
        .unwrap()
        .unwrap()
        .certificate;
    book.rehearse_case(restate.clone(), 1, &certificate, date, b"rehearsal")
        .unwrap()
        .unwrap();
    let manifest = book.case_manifest(1).unwrap().unwrap();
    let digest = manifest.digest().unwrap();
    let approve = |book: &mut Book, who: u128| {
        book.approve(
            Capability::embedded(VId(who), &["approve"]).unwrap(),
            digest,
        )
        .unwrap()
        .unwrap()
        .approval()
        .approval_vid
    };
    let alice = approve(&mut book, 2);
    let bob = approve(&mut book, 3);
    let own = approve(&mut book, PRINCIPAL.0);

    let one = book
        .approve_case(restate.clone(), 1, vec![alice], date, b"one")
        .unwrap()
        .unwrap_err();
    assert_eq!(one.code, "FA-REF-012", "{one:?}");
    let selfish = book
        .approve_case(restate.clone(), 1, vec![alice, own], date, b"self")
        .unwrap()
        .unwrap_err();
    assert_eq!(selfish.code, "FA-REF-008", "{selfish:?}");
    assert_eq!(book.case(1).unwrap().unwrap().state, CaseState::Rehearsed);

    let approved = book
        .approve_case(restate.clone(), 1, vec![alice, bob], date, b"dual")
        .unwrap()
        .unwrap();
    assert!(!approved.already_recorded);
    assert_eq!(approved.case.state, CaseState::Approved);
    let record = approved.case.approval.as_ref().unwrap();
    assert_eq!(record.manifest, manifest);
    assert_eq!(record.approvals.len(), 2);
    let head = book.head().unwrap();
    let again = book
        .approve_case(restate.clone(), 1, vec![alice, bob], date, b"dual")
        .unwrap()
        .unwrap();
    assert!(again.already_recorded);
    assert_eq!(book.head().unwrap(), head);
    let twice = book
        .approve_case(restate, 1, vec![alice, bob], date, b"again")
        .unwrap()
        .unwrap_err();
    assert_eq!(twice.code, code::CASE_STATE, "{twice:?}");
}

/// fa-75j4 slice 4a (plan §8.3 Posted: "the case's entries commit in one
/// batch"): an Approved PriorPeriodAdjustment case posts its manifest's
/// entry — the planned intent as a PriorPeriodAdjustment under the poster —
/// with its Post record in one commit, once. The entry reaches trunk no
/// other way, its row's approvals are the case's, and an approver may not
/// post it.
#[test]
fn a_prior_period_adjustment_case_posts_its_approved_manifest_once() {
    let (mut book, narrative, authority) = book(0xcb);
    issue_original_case_statement(&mut book, "FY2025-P12");
    let book_id = book.context().book_id;
    let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
    let schema = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
    book.create_periods(2026, PRINCIPAL, &schema)
        .unwrap()
        .unwrap();
    book.record_account_role(
        &fa::account_role::AccountRoleSpec {
            account: account_vid(book_id, "3000"),
            role: "retained_earnings".into(),
            assigned: true,
        },
        PRINCIPAL,
        b"retained-earnings-role",
        &schema,
    )
    .unwrap()
    .unwrap();
    book.transition_period(
        "FY2026-P02",
        PeriodTransition::Open,
        PRINCIPAL,
        1,
        b"open-february",
        &Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
    )
    .unwrap()
    .unwrap();
    let receipt = Document {
        book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: b"Bank advice: a December 2025 receipt never recorded".to_vec(),
    };
    book.add_document(&receipt).unwrap().unwrap();
    let restate = Capability::embedded(PRINCIPAL, &["restate", "read", "produce"]).unwrap();
    let poster = Capability::embedded(PRINCIPAL, &["restate", "post", "read"]).unwrap();
    let planner_vid = VId(4);
    let planner = Capability::embedded(planner_vid, &["post", "read"]).unwrap();
    let date = day(2026, 2, 12);
    book.open_case(
        restate.clone(),
        CaseKind::PriorPeriodAdjustment,
        vec!["FY2025-P12".into()],
        Some(narrative),
        Some(Determination {
            day: day(2026, 2, 10),
            authority,
        }),
        date,
        b"adjustment",
    )
    .unwrap()
    .unwrap();
    book.open_scenario(
        planner.clone(),
        "adjusted",
        ScenarioFork::default(),
        date,
        "The unrecorded December receipt",
    )
    .unwrap()
    .unwrap();
    let legs = vec![
        LegPayload::simple(
            Side::Debit,
            account_vid(book_id, "1000"),
            Amount::new(usd, 50_000),
        ),
        LegPayload::simple(
            Side::Credit,
            account_vid(book_id, "3000"),
            Amount::new(usd, 50_000),
        ),
    ];
    let mut planned = EntryPayload {
        schema_minor: 0,
        book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: date,
        document_date: None,
        description: book.seal_text("Prior-period receipt").unwrap(),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: b"december-receipt".to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([0xcb; 32]),
            intent_kind: 1,
        },
        principal_ref: planner_vid,
        session_ref: None,
        evidence: vec![receipt.evidence_ref(1)],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    planned
        .with_prior_period_adjustment(&fa_model::PeriodRef {
            calendar: book.context().calendar.id.clone(),
            code: "FY2025-P12".into(),
        })
        .unwrap();
    // The scratch role lookup may retain the planner's Read, never invent
    // it or erase scope caveats while building its embedded capability.
    for refused in [
        Capability::embedded(planner_vid, &["post"]).unwrap(),
        planner.clone().for_accounts(&["1000", "3000"]).unwrap(),
    ] {
        let head = book.head().unwrap();
        let denial = book
            .run_in_scenario(
                refused,
                "adjusted",
                PostIntent::new(planned.clone(), Vec::new()).unwrap(),
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(denial.code, "FA-REF-011");
        assert_eq!(book.head().unwrap(), head);
        assert!(
            book.scenario("adjusted")
                .unwrap()
                .unwrap()
                .intents
                .is_empty()
        );
    }
    book.run_in_scenario(
        planner,
        "adjusted",
        PostIntent::new(planned.clone(), Vec::new()).unwrap(),
    )
    .unwrap()
    .unwrap();
    let certificate = book
        .certify_scenario_diff(
            PRINCIPAL,
            &restate,
            "adjusted",
            &["FY2025-P12".to_string(), "FY2026-P02".to_string()],
            false,
        )
        .unwrap()
        .unwrap()
        .certificate;
    book.rehearse_case(restate.clone(), 1, &certificate, date, b"rehearsal")
        .unwrap()
        .unwrap();
    // Not yet Approved: nothing posts.
    let early = book
        .post_case(poster.clone(), 1, date, b"post")
        .unwrap()
        .unwrap_err();
    assert_eq!(early.code, code::CASE_STATE, "{early:?}");
    let manifest = book.case_manifest(1).unwrap().unwrap();
    let plan = manifest.entries[0].plan;
    let digest = manifest.digest().unwrap();
    let approve = |book: &mut Book, who: u128| {
        book.approve(
            Capability::embedded(VId(who), &["approve"]).unwrap(),
            digest,
        )
        .unwrap()
        .unwrap()
        .approval()
        .approval_vid
    };
    let alice = approve(&mut book, 2);
    let bob = approve(&mut book, 3);
    // FA-INV-10.self-promotion (plan §8.3): no approver prepared any entry
    // in the case. The planner of its one entry did not open the case, and
    // still cannot approve it; nothing is written.
    let planned_by = approve(&mut book, planner_vid.0);
    let head = book.head().unwrap();
    let own_entry = book
        .approve_case(
            restate.clone(),
            1,
            vec![alice, planned_by],
            date,
            b"own-entry",
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(own_entry.code, "FA-REF-008", "{own_entry:?}");
    assert_eq!(book.head().unwrap(), head);
    assert_eq!(book.case(1).unwrap().unwrap().state, CaseState::Rehearsed);
    book.approve_case(restate.clone(), 1, vec![alice, bob], date, b"dual")
        .unwrap()
        .unwrap();

    // The case's exact entry, posted on its own, is refused, as is any
    // other entry claiming the case; nothing is written.
    let derived = fa_journal::derive_member(
        book_id,
        CaseKind::PriorPeriodAdjustment,
        1,
        plan,
        &planned,
        PRINCIPAL,
    )
    .unwrap()
    .unwrap();
    assert_eq!(derived.class, EntryClass::PRIOR_PERIOD_ADJUSTMENT);
    let head = book.head().unwrap();
    let alone = book
        .post(PostRequest {
            proposal: derived.clone(),
            approvals: Vec::new(),
            plan_certificate: None,
            capability: poster.clone(),
        })
        .unwrap()
        .unwrap_err();
    assert_eq!(alone.code, code::CASE_MEMBERSHIP, "{alone:?}");
    assert_eq!(book.head().unwrap(), head);
    // A PPA marker cannot be repurposed for another case kind. This is a
    // distinct guard from the delta-law shape of an ordinary template.
    let wrong_kind =
        fa_journal::derive_member(book_id, CaseKind::Restatement, 1, plan, &planned, PRINCIPAL)
            .unwrap()
            .unwrap_err();
    assert_eq!(
        wrong_kind.code,
        code::PRIOR_PERIOD_ADJUSTMENT,
        "{wrong_kind:?}"
    );
    // A superseding case kind posts only delta-law entries: a Restatement
    // case's derivation refuses a plain posting.
    let mut plain = planned.clone();
    plain
        .extensions
        .retain(|(tag, _)| *tag != fa_model::entry::PRIOR_PERIOD_ADJUSTMENT_EXTENSION);
    assert!(plain.prior_period_adjustment().unwrap().is_none());
    let delta =
        fa_journal::derive_member(book_id, CaseKind::Restatement, 1, plan, &plain, PRINCIPAL)
            .unwrap()
            .unwrap_err();
    assert_eq!(delta.code, code::CASE_MEMBERSHIP, "{delta:?}");
    assert_eq!(book.head().unwrap(), head);

    // An approver may not post: the entry's row excludes its preparer.
    let approver = Capability::embedded(VId(2), &["restate", "post", "read"]).unwrap();
    let own = book
        .post_case(approver, 1, date, b"post")
        .unwrap()
        .unwrap_err();
    assert_eq!(own.exit, 7, "{own:?}");
    assert_eq!(book.head().unwrap(), head);
    assert_eq!(book.case(1).unwrap().unwrap().state, CaseState::Approved);

    let statement_selection = |period: &str| fa::StatementSelection {
        definition: fa::StatementDefinition::embedded("balance-sheet").unwrap(),
        periods: vec![period.into()],
        comparative: Vec::new(),
    };
    let statement_before = book
        .certify_statement(statement_selection("FY2026-P02"), None)
        .unwrap()
        .unwrap()
        .certificate;
    let unaffected_statement = book
        .certify_statement(statement_selection("FY2025-P12"), None)
        .unwrap()
        .unwrap()
        .certificate;
    assert!(matches!(
        book.certificate_status(&statement_before).unwrap().unwrap(),
        fa::CertificateStatus::Current { .. }
    ));
    let before_adjustment = book.head().unwrap();
    let posted = book
        .post_case(poster.clone(), 1, date, b"post")
        .unwrap()
        .unwrap();
    assert!(!posted.already_recorded);
    let case = &posted.case;
    assert_eq!(case.state, CaseState::Posted);
    assert_eq!(case.posted.len(), 1);
    assert_eq!(case.posted[0].plan, plan);
    assert_eq!(
        case.transitions.last().map(|t| (t.from, t.to)),
        Some((Some(CaseState::Approved), CaseState::Posted))
    );
    let (entry, recorded_at) = book.read_entry(case.posted[0].entry).unwrap().unwrap();
    assert_eq!(recorded_at, posted.recorded_at, "one commit");
    assert_eq!(
        entry.proposal.proposal_digest().unwrap(),
        derived.proposal_digest().unwrap()
    );
    assert_eq!(entry.entry_digest, case.posted[0].entry_digest);
    assert_eq!(entry.proposal.principal_ref, PRINCIPAL);
    assert!(
        entry.approvals.is_empty(),
        "the case's approvals are its own"
    );
    let mut expected_case = fa::CertificateSupersedingCase {
        ordinal: 1,
        kind: CaseKind::PriorPeriodAdjustment,
        disclosure_document: None,
        disclosure_digest: None,
    };
    assert_eq!(
        book.certificate_status(&statement_before).unwrap().unwrap(),
        fa::CertificateStatus::SupersededBy {
            checked_at: book.head().unwrap(),
            later_entries: vec![case.posted[0].entry],
            cases: vec![expected_case.clone()],
        }
    );
    assert!(
        matches!(
            book.certificate_status(&unaffected_statement)
                .unwrap()
                .unwrap(),
            fa::CertificateStatus::Current { .. }
        ),
        "a case's declared source period does not supersede a statement whose values it did not change"
    );
    let statement_after = book
        .certify_statement(statement_selection("FY2026-P02"), None)
        .unwrap()
        .unwrap()
        .certificate;
    // The identical request is the recorded case; another is refused.
    let head = book.head().unwrap();
    let again = book
        .post_case(poster.clone(), 1, date, b"post")
        .unwrap()
        .unwrap();
    assert!(again.already_recorded);
    assert_eq!(again.case, posted.case);
    assert_eq!(book.head().unwrap(), head);
    let twice = book
        .post_case(poster, 1, date, b"again")
        .unwrap()
        .unwrap_err();
    assert_eq!(twice.code, code::CASE_STATE, "{twice:?}");

    // The real case posting is a correction of opening equity, never current
    // income or an inferred owner contribution, and it carries its provenance
    // through retention, historical replay and the independent verifier.
    let read = Capability::embedded(PRINCIPAL, &["read", "produce", "witness"]).unwrap();
    let request = fa::EquityRollForwardRequest {
        units: vec![usd.0],
        label: "FY2026 equity after prior-period correction".into(),
        effective_from: day(2026, 1, 1),
        effective_through: day(2026, 12, 31),
        known_at: Some(book.head().unwrap()),
        // The class wins even when a recipient designates this equity account
        // as an issuance account. That choice cannot hide the adjustment.
        issuance_accounts: vec![account_vid(book_id, "3000")],
        distribution_accounts: Vec::new(),
    };
    let certified = book
        .certify_equity_roll_forward(PRINCIPAL, &read, &request)
        .unwrap()
        .unwrap();
    let unit = &certified.report.statement.units[0];
    assert_eq!(unit.opening_total_equity, 0);
    assert_eq!(unit.prior_period_adjustments, 50_000);
    assert_eq!(unit.opening_equity_as_adjusted, 50_000);
    assert_eq!(unit.net_income, 0);
    assert_eq!(unit.issuances, 0);
    assert_eq!(unit.other_equity_movements, 0);
    assert_eq!(unit.closing_total_equity, 50_000);
    assert_eq!(unit.equity_tie_out_residual, 0);
    assert_eq!(certified.report.movements.len(), 1);
    let movement = &certified.report.movements[0];
    assert_eq!(movement.entry_digest, entry.entry_digest);
    assert_eq!(movement.case_ordinal, Some(1));
    assert_eq!(movement.relates_to.as_ref().unwrap().code, "FY2025-P12");
    let mut historical = request.clone();
    historical.known_at = Some(before_adjustment);
    let before = book
        .equity_roll_forward(PRINCIPAL, &read, &historical)
        .unwrap()
        .unwrap();
    assert_eq!(before.statement.units[0].prior_period_adjustments, 0);
    assert!(before.movements.is_empty());
    assert_eq!(
        book.replay_equity_roll_forward(PRINCIPAL, &read, &certified.certificate, &request)
            .unwrap()
            .unwrap(),
        certified.report
    );
    let state = book
        .checkpoint(PRINCIPAL, &read)
        .unwrap()
        .unwrap()
        .checkpoint
        .checkpoint
        .body
        .state_oid;
    let bundle = book
        .produce_equity_roll_forward_bundle(PRINCIPAL, &read, Some(state), &certified.certificate)
        .unwrap()
        .unwrap()
        .unwrap();
    let verified = fa_verify::report::verify_report_expected(
        &bundle.bundle.bytes,
        &[book.checkpoint_public_key()],
        None,
        Some(&bundle.receipt),
        Some(certified.certificate.digest()),
    )
    .expect("the standalone verifier recomputes the actual posted PPA");
    assert_eq!(verified.output, certified.certificate.output());
    let equity = verified.equity_roll_forward.unwrap();
    assert_eq!(equity.units[0].prior_period_adjustments, 50_000);
    assert_eq!(equity.units[0].opening_equity_as_adjusted, 50_000);
    assert_eq!(equity.movements[0].case_ordinal, Some(1));
    assert_eq!(
        equity.movements[0].relates_to.as_ref().unwrap().1,
        "FY2025-P12"
    );

    // fa-75j4 slice 5: disclosed in a Disclosure document a principal other
    // than its uploader reviewed, then closed, each once.
    let closer = Capability::embedded(PRINCIPAL, &["restate", "read"]).unwrap();
    let comparisons = retain_case_comparisons(&mut book, 1);
    assert_eq!(
        book.close_case(closer.clone(), 1, date, b"early")
            .unwrap()
            .unwrap_err()
            .code,
        code::CASE_STATE,
        "a Posted case is not closed"
    );
    let invoice = book
        .disclose_case(
            closer.clone(),
            1,
            receipt.oid(),
            &comparisons,
            date,
            b"invoice",
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(invoice.code, code::CASE_DISCLOSURE, "{invoice:?}");
    assert!(invoice.message.contains("not a Disclosure"), "{invoice:?}");
    let note = Document {
        book_id,
        kind: 20,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: b"Note 2: correction of an error in the 2025 statements".to_vec(),
    };
    book.add_document(&note).unwrap().unwrap();
    let head = book.head().unwrap();
    let unreviewed = book
        .disclose_case(closer.clone(), 1, note.oid(), &comparisons, date, b"note")
        .unwrap()
        .unwrap_err();
    assert_eq!(unreviewed.code, code::CASE_DISCLOSURE, "{unreviewed:?}");
    assert!(
        unreviewed.message.contains("no Reviewed attestation"),
        "{unreviewed:?}"
    );
    assert_eq!(book.head().unwrap(), head);
    book.record_review(
        &Capability::embedded(VId(5), &["approve"]).unwrap(),
        &note.oid(),
        Vec::new(),
    )
    .unwrap()
    .unwrap();
    // Every comparison is mandatory and must answer the exact original
    // statement question at the immutable case Post. A valid but unrelated
    // retained report is no disclosure evidence for this case.
    let mut tampered = comparisons.clone();
    tampered[0][0] ^= 1;
    let mut duplicated = comparisons.clone();
    duplicated[1] = duplicated[0];
    let mut extra = comparisons.clone();
    extra.push([0xfe; 32]);
    for (key, supplied) in [
        (b"no-comparisons".as_slice(), Vec::new()),
        (b"missing-comparison".as_slice(), comparisons[1..].to_vec()),
        (b"tampered-comparison".as_slice(), tampered),
        (b"duplicate-comparison".as_slice(), duplicated),
        (b"extra-comparison".as_slice(), extra),
    ] {
        let head = book.head().unwrap();
        let refusal = book
            .disclose_case(closer.clone(), 1, note.oid(), &supplied, date, key)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, code::CASE_STATEMENT_DIFF, "{refusal:?}");
        assert_eq!(
            book.head().unwrap(),
            head,
            "invalid comparison set writes nothing"
        );
    }
    let original_artifact = book
        .read_report_artifact(PRINCIPAL, &read, &comparisons[0])
        .unwrap()
        .unwrap();
    let original_artifact =
        fa::StatementDiffCertificate::decode(&original_artifact.canonical_bytes().unwrap())
            .unwrap();
    let original_request = original_artifact.request().unwrap();
    for wrong_coordinate in [false, true] {
        let mut request = original_request.clone();
        if wrong_coordinate {
            request.after = Some(book.head().unwrap());
        } else {
            request.selection.periods = vec!["FY2025-P10".into()];
            request.selection.comparative.clear();
        }
        let wrong = book
            .certify_statement_diff(PRINCIPAL, &read, &request)
            .unwrap()
            .unwrap()
            .certificate;
        book.retain_report_artifact(
            PRINCIPAL,
            &read,
            &wrong.canonical_bytes().unwrap(),
            Some(wrong.digest()),
        )
        .unwrap()
        .unwrap();
        let mut supplied = comparisons.clone();
        supplied[0] = *wrong.digest();
        let head = book.head().unwrap();
        let refusal = book
            .disclose_case(
                closer.clone(),
                1,
                note.oid(),
                &supplied,
                date,
                b"wrong-question",
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, code::CASE_STATEMENT_DIFF, "{refusal:?}");
        assert_eq!(book.head().unwrap(), head);
    }
    let wrong_measure = book
        .certify_functional_statement_diff(PRINCIPAL, &read, &original_request)
        .unwrap()
        .unwrap()
        .certificate;
    book.retain_report_artifact(
        PRINCIPAL,
        &read,
        &wrong_measure.canonical_bytes().unwrap(),
        Some(wrong_measure.digest()),
    )
    .unwrap()
    .unwrap();
    let mut supplied = comparisons.clone();
    supplied[0] = *wrong_measure.digest();
    let head = book.head().unwrap();
    let refusal = book
        .disclose_case(
            closer.clone(),
            1,
            note.oid(),
            &supplied,
            date,
            b"wrong-measure",
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, code::CASE_STATEMENT_DIFF, "{refusal:?}");
    assert_eq!(book.head().unwrap(), head);
    let denied = book
        .disclose_case(
            Capability::embedded(PRINCIPAL, &["restate"]).unwrap(),
            1,
            note.oid(),
            &[[0; 32]],
            date,
            b"no-read",
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(
        denied.code, "FA-REF-011",
        "authorization precedes malformed digests: {denied:?}"
    );
    assert_eq!(book.head().unwrap(), head);
    let disclosed = book
        .disclose_case(closer.clone(), 1, note.oid(), &comparisons, date, b"note")
        .unwrap()
        .unwrap();
    assert_eq!(disclosed.case.state, CaseState::Disclosed);
    let disclosure = disclosed.case.disclosure.unwrap();
    assert_eq!(disclosure.document, note.oid());
    assert_eq!(disclosure.comparisons, comparisons);
    assert_eq!(disclosure.post.unwrap().entry, posted.control_entry);
    assert_eq!(disclosure.post.unwrap().recorded_at, posted.recorded_at);
    let disclosed_state = book
        .checkpoint(PRINCIPAL, &read)
        .unwrap()
        .unwrap()
        .checkpoint
        .checkpoint
        .body
        .state_oid;
    let comparison_bundle = book
        .produce_statement_diff_bundle(PRINCIPAL, &read, Some(disclosed_state), &original_artifact)
        .unwrap()
        .unwrap()
        .unwrap();
    let verified = fa_verify::report::verify_report_expected(
        &comparison_bundle.bundle.bytes,
        &[book.checkpoint_public_key()],
        None,
        Some(&comparison_bundle.receipt),
        Some(original_artifact.digest()),
    )
    .expect(
        "a cited comparison recomputes offline under the checkpoint including its v2 disclosure",
    );
    assert_eq!(verified.output, original_artifact.output());
    let mut tampered_bundle = comparison_bundle.bundle.bytes.clone();
    let middle = tampered_bundle.len() / 2;
    tampered_bundle[middle] ^= 1;
    assert!(
        fa_verify::report::verify_report_expected(
            &tampered_bundle,
            &[book.checkpoint_public_key()],
            None,
            Some(&comparison_bundle.receipt),
            Some(original_artifact.digest()),
        )
        .is_err(),
        "one changed bundle byte cannot verify as the disclosed comparison"
    );
    let (disclose_entry, _) = book.read_entry(disclosed.control_entry).unwrap().unwrap();
    expected_case.disclosure_document = Some(note.oid());
    expected_case.disclosure_digest = Some(disclose_entry.entry_digest);
    let statement_bytes = statement_before.canonical_bytes().unwrap();
    let status_at = book.head().unwrap();
    assert_eq!(
        book.report_artifact_status(
            PRINCIPAL,
            &read,
            &statement_bytes,
            Some(&statement_before.digest),
            fa::ReportArtifactExpectation::AsSupplied,
        )
        .unwrap()
        .unwrap(),
        fa::CertificateStatus::SupersededBy {
            checked_at: status_at,
            later_entries: vec![posted.case.posted[0].entry],
            cases: vec![expected_case.clone()],
        }
    );
    let denied = book
        .report_artifact_status(
            PRINCIPAL,
            &Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
            b"malformed certificate must not precede admission",
            None,
            fa::ReportArtifactExpectation::AsSupplied,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(denied.code, "FA-REF-011", "{denied:?}");
    assert_eq!(
        book.head().unwrap(),
        status_at,
        "freshness and attribution never write"
    );
    assert_eq!(
        book.replay_report(&statement_before)
            .unwrap()
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        statement_before.output,
        "current disclosure attribution does not rewrite the historical report"
    );
    let again = book
        .disclose_case(closer.clone(), 1, note.oid(), &comparisons, date, b"note")
        .unwrap()
        .unwrap();
    assert!(again.already_recorded);
    let closed = book
        .close_case(closer.clone(), 1, date, b"close")
        .unwrap()
        .unwrap();
    assert_eq!(closed.case.state, CaseState::Closed);
    assert_eq!(closed.case.disclosure, Some(disclosure));
    assert_eq!(
        closed
            .case
            .transitions
            .iter()
            .map(|t| t.to)
            .collect::<Vec<_>>(),
        CaseState::ALL[1..].to_vec(),
        "every transition journaled once, in order"
    );
    let reclosed = book
        .close_case(closer, 1, date, b"reclose")
        .unwrap()
        .unwrap_err();
    assert_eq!(reclosed.code, code::CASE_STATE, "{reclosed:?}");
    book.open_case(
        restate.clone(),
        CaseKind::Revision,
        vec!["FY2026-P02".into()],
        None,
        None,
        date,
        b"unrelated-overlapping-case",
    )
    .unwrap()
    .unwrap();
    assert!(
        matches!(
            book.certificate_status(&statement_after).unwrap().unwrap(),
            fa::CertificateStatus::Current { .. }
        ),
        "disclosure and opening another overlapping case are not monetary corrections"
    );
    let fa::CertificateStatus::SupersededBy { cases, .. } =
        book.certificate_status(&statement_before).unwrap().unwrap()
    else {
        panic!("the original case member remains a superseding contributor");
    };
    assert_eq!(cases, vec![expected_case.clone()]);

    // Exact reversals retain the economic class and original case/period,
    // including when the original PPA lies before the report's date window.
    // Reverse once to cancel the correction, then reverse again to revive it.
    let mut target = entry.entry_ref(posted.case.posted[0].entry);
    for (offset, expected_total, expected_movement) in [(0, 0, -50_000), (1, 50_000, 50_000)] {
        let effective = day(2026, 2, 13 + offset);
        let (original, _) = book.read_entry(target.vid).unwrap().unwrap();
        let mut reversal = original.proposal.clone();
        reversal.class = EntryClass::REVERSAL;
        reversal.principal_ref = PRINCIPAL;
        reversal.effective_date = effective;
        reversal.effective_period = None;
        reversal.idempotency_key = format!("reverse-ppa-{offset}").into_bytes();
        reversal.extensions.clear();
        reversal.supersession = vec![fa_model::Supersession {
            target,
            kind: fa_model::SupersessionKind::Reverses,
            reason_code: 2, // WrongAccount, a registered correction reason.
        }];
        for leg in &mut reversal.legs {
            leg.side = match leg.side {
                Side::Debit => Side::Credit,
                Side::Credit => Side::Debit,
            };
            leg.settles.clear();
        }
        reversal.unit_totals = EntryPayload::fold_unit_totals(&reversal.legs).unwrap();
        let reversed = book
            .post(PostRequest {
                proposal: reversal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
            })
            .unwrap()
            .unwrap();
        target = reversed.entry_ref();
        let fa::CertificateStatus::SupersededBy {
            cases,
            later_entries,
            ..
        } = book.certificate_status(&statement_after).unwrap().unwrap()
        else {
            panic!("a reversal of a case correction changes the saved statement");
        };
        assert!(later_entries.contains(&target.vid));
        assert_eq!(
            cases,
            vec![expected_case.clone()],
            "exact reversals retain original case attribution"
        );
        let mut current = request.clone();
        current.known_at = Some(book.head().unwrap());
        let report = book
            .equity_roll_forward(PRINCIPAL, &read, &current)
            .unwrap()
            .unwrap();
        let unit = &report.statement.units[0];
        assert_eq!(unit.prior_period_adjustments, expected_total);
        assert_eq!(unit.opening_equity_as_adjusted, expected_total);
        assert_eq!(unit.closing_total_equity, expected_total);
        assert_eq!(
            unit.issuances, 0,
            "owner labels cannot reclassify a reversal"
        );
        assert_eq!(unit.other_equity_movements, 0);
        assert_eq!(unit.equity_tie_out_residual, 0);
        assert!(report.movements.iter().all(|movement| {
            movement.kind == fa_statements::cash_flow::EquityActivityKind::PriorPeriodAdjustment
                && movement.case_ordinal == Some(1)
                && movement.relates_to.as_ref().unwrap().code == "FY2025-P12"
        }));

        current.effective_from = effective;
        current.effective_through = effective;
        let narrow = book
            .certify_equity_roll_forward(PRINCIPAL, &read, &current)
            .unwrap()
            .unwrap();
        assert_eq!(narrow.report.movements.len(), 1);
        let movement = &narrow.report.movements[0];
        assert_eq!(movement.class, EntryClass::REVERSAL);
        assert_eq!(movement.entry_digest, target.entry_digest);
        assert_eq!(movement.case_ordinal, Some(1));
        assert_eq!(movement.relates_to.as_ref().unwrap().code, "FY2025-P12");
        assert_eq!(
            narrow.report.statement.units[0].prior_period_adjustments,
            expected_movement
        );
        assert_eq!(
            book.replay_equity_roll_forward(PRINCIPAL, &read, &narrow.certificate, &current)
                .unwrap()
                .unwrap(),
            narrow.report
        );
        let state = book
            .checkpoint(PRINCIPAL, &read)
            .unwrap()
            .unwrap()
            .checkpoint
            .checkpoint
            .body
            .state_oid;
        let bundle = book
            .produce_equity_roll_forward_bundle(PRINCIPAL, &read, Some(state), &narrow.certificate)
            .unwrap()
            .unwrap()
            .unwrap();
        let verified = fa_verify::report::verify_report_expected(
            &bundle.bundle.bytes,
            &[book.checkpoint_public_key()],
            None,
            Some(&bundle.receipt),
            Some(narrow.certificate.digest()),
        )
        .expect("offline verification follows authenticated PPA reversal ancestry");
        assert_eq!(verified.output, narrow.certificate.output());
        let equity = verified.equity_roll_forward.unwrap();
        assert_eq!(equity.units[0].prior_period_adjustments, expected_movement);
        assert_eq!(equity.units[0].other_equity_movements, 0);
        assert_eq!(equity.movements[0].case_ordinal, Some(1));
        assert_eq!(
            equity.movements[0].relates_to.as_ref().unwrap().1,
            "FY2025-P12"
        );
    }
    assert_eq!(
        book.replay_equity_roll_forward(PRINCIPAL, &read, &certified.certificate, &request)
            .unwrap()
            .unwrap(),
        certified.report,
        "later reversals never reinterpret the original retained certificate"
    );
}

/// fa-75j4 slice 4b: a Revision case revises a Closed period's posting.
/// - The Revision is planned in the case's scenario and rehearsed in its
///   scratch replay; planning refuses a revision of an entry that is not
///   there.
/// - The posted entry is the case's derivation: class Revision, still
///   revising the target, in the period the case affects. The period's
///   trial balance moves by the delta.
/// - On its own, the same entry is refused (FA-REF-178).
#[test]
fn a_revision_case_revises_a_closed_periods_posting_through_its_post() {
    let (mut book, narrative, authority) = book(0xcd);
    let book_id = book.context().book_id;
    let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
    let close = Capability::embedded(PRINCIPAL, &["close"]).unwrap();
    book.transition_period(
        "FY2025-P12",
        PeriodTransition::Open,
        PRINCIPAL,
        1,
        b"open-december",
        &close,
    )
    .unwrap()
    .unwrap();
    let receipt = Document {
        book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: b"Bank advice: December 2025 receipt of 200.00 USD, recorded as 150.00".to_vec(),
    };
    book.add_document(&receipt).unwrap().unwrap();
    let legs = |cents: i128| {
        vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book_id, "1000"),
                Amount::new(usd, cents),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(book_id, "3000"),
                Amount::new(usd, cents),
            ),
        ]
    };
    let december = day(2025, 12, 15);
    let entry = |book: &Book, class, legs: Vec<LegPayload>, key: &[u8], who: VId| EntryPayload {
        schema_minor: 0,
        book_id,
        branch_id: Id128::TRUNK,
        class,
        effective_date: december,
        document_date: None,
        description: book.seal_text("December receipt").unwrap(),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: key.to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([0xcd; 32]),
            intent_kind: 1,
        },
        principal_ref: who,
        session_ref: None,
        evidence: vec![receipt.evidence_ref(1)],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    let original = entry(
        &book,
        EntryClass::ORIGINAL,
        legs(15_000),
        b"receipt",
        PRINCIPAL,
    );
    let posted = book
        .post(PostRequest {
            proposal: original,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        })
        .unwrap()
        .unwrap();
    let target = posted.entry_ref();
    book.transition_period(
        "FY2025-P12",
        PeriodTransition::Close,
        PRINCIPAL,
        1,
        b"close-december",
        &close,
    )
    .unwrap()
    .unwrap();

    let restate = Capability::embedded(PRINCIPAL, &["restate", "read", "produce"]).unwrap();
    let poster = Capability::embedded(PRINCIPAL, &["restate", "post", "read"]).unwrap();
    let planner_vid = VId(4);
    let planner = Capability::embedded(planner_vid, &["post", "read", "restate"]).unwrap();
    let date = day(2026, 2, 12);
    book.open_case(
        restate.clone(),
        CaseKind::Revision,
        vec!["FY2025-P12".into()],
        Some(narrative),
        Some(Determination {
            day: day(2026, 2, 10),
            authority,
        }),
        date,
        b"revision",
    )
    .unwrap()
    .unwrap();
    book.open_scenario(
        planner.clone(),
        "revised",
        ScenarioFork::default(),
        december,
        "The December receipt was 50.00 short",
    )
    .unwrap()
    .unwrap();
    let revises = |target| fa_model::Supersession {
        target,
        kind: fa_model::SupersessionKind::Revises,
        reason_code: 4,
    };
    // A revision of an entry that is not there is refused in the scenario's
    // replay; the scenario stays without it.
    let mut missing = entry(
        &book,
        EntryClass::REVISION,
        legs(5_000),
        b"ghost",
        planner_vid,
    );
    missing.supersession = vec![revises(fa_model::EntryRef {
        vid: VId(0xdead),
        entry_digest: [7; 32],
    })];
    let ghost = book
        .run_in_scenario(
            planner.clone(),
            "revised",
            PostIntent::new(missing, Vec::new()).unwrap(),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(ghost.code, code::REVISION_SHAPE, "{ghost:?}");
    let mut planned = entry(
        &book,
        EntryClass::REVISION,
        legs(5_000),
        b"short",
        planner_vid,
    );
    planned.supersession = vec![revises(target)];
    book.run_in_scenario(
        planner,
        "revised",
        PostIntent::new(planned.clone(), Vec::new()).unwrap(),
    )
    .unwrap()
    .unwrap();
    let rehearsed = book
        .certify_scenario_diff(
            PRINCIPAL,
            &restate,
            "revised",
            &["FY2025-P12".to_string()],
            false,
        )
        .unwrap()
        .unwrap();
    let certificate = rehearsed.certificate.clone();
    book.rehearse_case(restate.clone(), 1, &certificate, date, b"rehearsal")
        .unwrap()
        .unwrap();
    let manifest = book.case_manifest(1).unwrap().unwrap();
    let plan = manifest.entries[0].plan;
    let digest = manifest.digest().unwrap();
    let approve = |book: &mut Book, who: u128| {
        book.approve(
            Capability::embedded(VId(who), &["approve"]).unwrap(),
            digest,
        )
        .unwrap()
        .unwrap()
        .approval()
        .approval_vid
    };
    let alice = approve(&mut book, 2);
    let bob = approve(&mut book, 3);
    book.approve_case(restate, 1, vec![alice, bob], date, b"dual")
        .unwrap()
        .unwrap();

    // The derivation keeps the class and its Revises link. On its own it is
    // refused; a plain posting is not a Revision case's Plan record.
    let derived =
        fa_journal::derive_member(book_id, CaseKind::Revision, 1, plan, &planned, PRINCIPAL)
            .unwrap()
            .unwrap();
    assert_eq!(derived.class, EntryClass::REVISION);
    assert_eq!(derived.supersession, planned.supersession);
    let head = book.head().unwrap();
    let alone = book
        .post(PostRequest {
            proposal: derived.clone(),
            approvals: Vec::new(),
            plan_certificate: None,
            capability: poster.clone(),
        })
        .unwrap()
        .unwrap_err();
    assert_eq!(alone.code, code::CASE_MEMBERSHIP, "{alone:?}");
    assert_eq!(book.head().unwrap(), head);
    let plain = entry(
        &book,
        EntryClass::ORIGINAL,
        legs(5_000),
        b"plain",
        planner_vid,
    );
    let refused =
        fa_journal::derive_member(book_id, CaseKind::Revision, 1, plan, &plain, PRINCIPAL)
            .unwrap()
            .unwrap_err();
    assert_eq!(refused.code, code::CASE_MEMBERSHIP, "{refused:?}");

    let before = book.trial_balance(&["FY2025-P12".to_string()]).unwrap();
    let posted = book.post_case(poster, 1, date, b"post").unwrap().unwrap();
    assert_eq!(posted.case.state, CaseState::Posted);
    let (revision, _) = book
        .read_entry(posted.case.posted[0].entry)
        .unwrap()
        .unwrap();
    assert_eq!(
        revision.proposal.proposal_digest().unwrap(),
        derived.proposal_digest().unwrap()
    );
    assert_eq!(revision.proposal.class, EntryClass::REVISION);
    let after = book.trial_balance(&["FY2025-P12".to_string()]).unwrap();
    let cash = |tb: &fa_registers::TrialBalance| {
        tb.rows
            .iter()
            .find(|row| row.code == "1000")
            .map(|row| row.debits - row.credits)
    };
    assert_eq!(cash(&before), Some(15_000));
    assert_eq!(cash(&after), Some(20_000), "the target plus the delta");
    assert_posted_diff_is_the_rehearsed_one(&before, &after, &rehearsed.report);
}

/// fa-651f slice 1 (plan §8.3, §14.3): a Restatement case restates a Locked
/// period's posting through its own Post. Its entries' rule names
/// `session_lineage`, decided over each approval's journaled issuance
/// chain: the case's Approve refuses an approver whose capability another
/// approver issued, or the case's planner issued, and leaves the case
/// Rehearsed; two approvers a steward issued independently approve it, and
/// the Post moves the Locked period by the delta.
#[test]
fn a_restatement_case_restates_a_locked_periods_posting_under_independent_approvals() {
    use fa_policy::possession_digest;
    let (mut book, narrative, authority) = book(0xce);
    let book_id = book.context().book_id;
    let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
    let close = Capability::embedded(PRINCIPAL, &["close"]).unwrap();
    book.transition_period(
        "FY2025-P12",
        PeriodTransition::Open,
        PRINCIPAL,
        1,
        b"open-december",
        &close,
    )
    .unwrap()
    .unwrap();
    let receipt = Document {
        book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: b"Bank advice: December 2025 receipt of 200.00 USD, recorded as 150.00".to_vec(),
    };
    book.add_document(&receipt).unwrap().unwrap();
    let legs = |cents: i128| {
        vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book_id, "1000"),
                Amount::new(usd, cents),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(book_id, "3000"),
                Amount::new(usd, cents),
            ),
        ]
    };
    let december = day(2025, 12, 15);
    let entry = |book: &Book, class, legs: Vec<LegPayload>, key: &[u8], who: VId| EntryPayload {
        schema_minor: 0,
        book_id,
        branch_id: Id128::TRUNK,
        class,
        effective_date: december,
        document_date: None,
        description: book.seal_text("December receipt").unwrap(),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: key.to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([0xce; 32]),
            intent_kind: 1,
        },
        principal_ref: who,
        session_ref: None,
        evidence: vec![receipt.evidence_ref(1)],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    let posted = book
        .post(PostRequest {
            proposal: entry(
                &book,
                EntryClass::ORIGINAL,
                legs(15_000),
                b"receipt",
                PRINCIPAL,
            ),
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        })
        .unwrap()
        .unwrap();
    let target = posted.entry_ref();
    book.transition_period(
        "FY2025-P12",
        PeriodTransition::Close,
        PRINCIPAL,
        1,
        b"close-december",
        &close,
    )
    .unwrap()
    .unwrap();
    // Lock December under its one approval (Appendix C: Closed Lock W(close, 1)).
    let lock = book
        .plan_transition(
            "FY2025-P12",
            PeriodTransition::Lock,
            PRINCIPAL,
            1,
            b"lock-december",
        )
        .unwrap()
        .unwrap();
    let lock_digest = book.plan_digest(&lock).unwrap().unwrap();
    let lock_approval = book
        .approve(
            Capability::embedded(VId(9), &["approve"]).unwrap(),
            lock_digest,
        )
        .unwrap()
        .unwrap()
        .approval();
    book.transition_planned(&lock, PeriodTransition::Lock, &close, &[lock_approval])
        .unwrap()
        .unwrap();

    // Approver capabilities, issued and journaled: a steward issues Alice's
    // and Bob's; Alice issues Dave's; the case's planner issues Carol's.
    let date = day(2026, 2, 12);
    let planner_vid = VId(4);
    let planner = Capability::embedded(
        planner_vid,
        &["post", "read", "restate", "issue_capability", "approve"],
    )
    .unwrap();
    let steward = Capability::embedded(VId(7), &["issue_capability", "approve"]).unwrap();
    let issue = |book: &mut Book, by: &Capability, holder: u128, ops: &[Op], key: &[u8]| {
        let token = Capability::new(VId(holder), Profile::Human, ops, by.holder())
            .unwrap()
            .holder_bound(possession_digest(&[u8::try_from(holder).unwrap(); 32]));
        book.issue_capability(by.clone(), token.clone(), date, key, "approver")
            .unwrap()
            .unwrap();
        token
    };
    let alice = issue(
        &mut book,
        &steward,
        2,
        &[Op::Approve, Op::IssueCapability],
        b"alice",
    );
    let bob = issue(&mut book, &steward, 3, &[Op::Approve], b"bob");
    let dave = issue(&mut book, &alice, 6, &[Op::Approve], b"dave");
    let carol = issue(&mut book, &planner, 5, &[Op::Approve], b"carol");

    let restate = Capability::embedded(PRINCIPAL, &["restate", "read", "produce"]).unwrap();
    let poster = Capability::embedded(PRINCIPAL, &["restate", "post", "read"]).unwrap();
    book.open_case(
        restate.clone(),
        CaseKind::Restatement,
        vec!["FY2025-P12".into()],
        Some(narrative),
        Some(Determination {
            day: day(2026, 2, 10),
            authority,
        }),
        date,
        b"restatement",
    )
    .unwrap()
    .unwrap();
    book.open_scenario(
        planner.clone(),
        "restated",
        ScenarioFork::default(),
        december,
        "The December receipt was 50.00 short",
    )
    .unwrap()
    .unwrap();
    let supersedes = |kind| fa_model::Supersession {
        target,
        kind,
        reason_code: 4,
    };
    // A Restatement restates: a Revises link is the wrong shape.
    let mut misshapen = entry(
        &book,
        EntryClass::RESTATEMENT,
        legs(5_000),
        b"misshapen",
        planner_vid,
    );
    misshapen.supersession = vec![supersedes(fa_model::SupersessionKind::Revises)];
    let wrong = book
        .run_in_scenario(
            planner.clone(),
            "restated",
            PostIntent::new(misshapen, Vec::new()).unwrap(),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(wrong.code, code::RESTATEMENT_SHAPE, "{wrong:?}");
    let mut planned = entry(
        &book,
        EntryClass::RESTATEMENT,
        legs(5_000),
        b"short",
        planner_vid,
    );
    planned.supersession = vec![supersedes(fa_model::SupersessionKind::Restates)];
    book.run_in_scenario(
        planner,
        "restated",
        PostIntent::new(planned.clone(), Vec::new()).unwrap(),
    )
    .unwrap()
    .unwrap();
    let rehearsed = book
        .certify_scenario_diff(
            PRINCIPAL,
            &restate,
            "restated",
            &["FY2025-P12".to_string()],
            false,
        )
        .unwrap()
        .unwrap();
    let certificate = rehearsed.certificate.clone();
    book.rehearse_case(restate.clone(), 1, &certificate, date, b"rehearsal")
        .unwrap()
        .unwrap();
    let manifest = book.case_manifest(1).unwrap().unwrap();
    let plan = manifest.entries[0].plan;
    let digest = manifest.digest().unwrap();
    let approve = |book: &mut Book, cap: &Capability| {
        book.approve(cap.clone(), digest)
            .unwrap()
            .unwrap()
            .approval()
            .approval_vid
    };
    let (a, b, d, c) = (
        approve(&mut book, &alice),
        approve(&mut book, &bob),
        approve(&mut book, &dave),
        approve(&mut book, &carol),
    );

    // Dave's authority comes from Alice, and Carol's from the planner: each
    // shares a session lineage with a party to the case. Nothing is written.
    for (pair, approver, issuer) in [
        (vec![a, d], VId(6), VId(2)),
        (vec![a, c], VId(5), planner_vid),
    ] {
        let head = book.head().unwrap();
        let refused = book
            .approve_case(restate.clone(), 1, pair, date, b"lineage")
            .unwrap()
            .unwrap_err();
        assert_eq!(refused.code, "FA-REF-008", "{refused:?}");
        assert!(
            refused.message.contains(&format!("{:032x}", approver.0))
                && refused.message.contains(&format!("{:032x}", issuer.0))
                && refused.message.contains("session lineage"),
            "{refused:?}"
        );
        assert!(refused.cite.contains("restatement-"), "{}", refused.cite);
        assert_eq!(book.head().unwrap(), head);
        assert_eq!(book.case(1).unwrap().unwrap().state, CaseState::Rehearsed);
    }
    // Alice and Bob share only their issuer, the steward, who is no party.
    book.approve_case(restate, 1, vec![a, b], date, b"dual")
        .unwrap()
        .unwrap();

    let derived =
        fa_journal::derive_member(book_id, CaseKind::Restatement, 1, plan, &planned, PRINCIPAL)
            .unwrap()
            .unwrap();
    assert_eq!(derived.class, EntryClass::RESTATEMENT);
    assert_eq!(derived.supersession, planned.supersession);
    let alone = book
        .post(PostRequest {
            proposal: derived.clone(),
            approvals: Vec::new(),
            plan_certificate: None,
            capability: poster.clone(),
        })
        .unwrap()
        .unwrap_err();
    assert_eq!(alone.code, code::CASE_MEMBERSHIP, "{alone:?}");

    let before = book.trial_balance(&["FY2025-P12".to_string()]).unwrap();
    let posted = book.post_case(poster, 1, date, b"post").unwrap().unwrap();
    assert_eq!(posted.case.state, CaseState::Posted);
    let (restatement, _) = book
        .read_entry(posted.case.posted[0].entry)
        .unwrap()
        .unwrap();
    assert_eq!(restatement.proposal.class, EntryClass::RESTATEMENT);
    assert_eq!(
        restatement.proposal.proposal_digest().unwrap(),
        derived.proposal_digest().unwrap()
    );
    let after = book.trial_balance(&["FY2025-P12".to_string()]).unwrap();
    let cash = |tb: &fa_registers::TrialBalance| {
        tb.rows
            .iter()
            .find(|row| row.code == "1000")
            .map(|row| row.debits - row.credits)
    };
    assert_eq!(cash(&before), Some(15_000));
    assert_eq!(cash(&after), Some(20_000), "the target plus the delta");
    assert_posted_diff_is_the_rehearsed_one(&before, &after, &rehearsed.report);
}

/// fa-yugf.93 (H13; plan §8.3): a PolicyChangeRetrospective case posts
/// Restatement entries into a Locked period under independent dual-control
/// approvals with session-lineage enforcement, then discloses and closes.
#[test]
fn a_policy_change_retrospective_case_restates_a_locked_periods_posting_under_independent_approvals()
 {
    use fa_policy::possession_digest;
    let (mut book, narrative, authority) = book(0xcf);
    let book_id = book.context().book_id;
    let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
    let close = Capability::embedded(PRINCIPAL, &["close"]).unwrap();
    book.transition_period(
        "FY2025-P12",
        PeriodTransition::Open,
        PRINCIPAL,
        1,
        b"open-december",
        &close,
    )
    .unwrap()
    .unwrap();
    let receipt = Document {
        book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: b"Contract schedule: December 2025 recognition recast under ASC 606".to_vec(),
    };
    book.add_document(&receipt).unwrap().unwrap();
    let legs = |cents: i128| {
        vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book_id, "1000"),
                Amount::new(usd, cents),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(book_id, "3000"),
                Amount::new(usd, cents),
            ),
        ]
    };
    let december = day(2025, 12, 15);
    let entry = |book: &Book, class, legs: Vec<LegPayload>, key: &[u8], who: VId| EntryPayload {
        schema_minor: 0,
        book_id,
        branch_id: Id128::TRUNK,
        class,
        effective_date: december,
        document_date: None,
        description: book.seal_text("December policy recast").unwrap(),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: key.to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([0xcf; 32]),
            intent_kind: 1,
        },
        principal_ref: who,
        session_ref: None,
        evidence: vec![receipt.evidence_ref(1)],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    let posted = book
        .post(PostRequest {
            proposal: entry(
                &book,
                EntryClass::ORIGINAL,
                legs(15_000),
                b"original-policy",
                PRINCIPAL,
            ),
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        })
        .unwrap()
        .unwrap();
    let target = posted.entry_ref();
    book.transition_period(
        "FY2025-P12",
        PeriodTransition::Close,
        PRINCIPAL,
        1,
        b"close-december",
        &close,
    )
    .unwrap()
    .unwrap();
    let lock = book
        .plan_transition(
            "FY2025-P12",
            PeriodTransition::Lock,
            PRINCIPAL,
            1,
            b"lock-december",
        )
        .unwrap()
        .unwrap();
    let lock_digest = book.plan_digest(&lock).unwrap().unwrap();
    let lock_approval = book
        .approve(
            Capability::embedded(VId(9), &["approve"]).unwrap(),
            lock_digest,
        )
        .unwrap()
        .unwrap()
        .approval();
    book.transition_planned(&lock, PeriodTransition::Lock, &close, &[lock_approval])
        .unwrap()
        .unwrap();

    let date = day(2026, 2, 12);
    let planner_vid = VId(4);
    let planner = Capability::embedded(
        planner_vid,
        &["post", "read", "restate", "issue_capability", "approve"],
    )
    .unwrap();
    let steward = Capability::embedded(VId(7), &["issue_capability", "approve"]).unwrap();
    let issue = |book: &mut Book, by: &Capability, holder: u128, ops: &[Op], key: &[u8]| {
        let token = Capability::new(VId(holder), Profile::Human, ops, by.holder())
            .unwrap()
            .holder_bound(possession_digest(&[u8::try_from(holder).unwrap(); 32]));
        book.issue_capability(by.clone(), token.clone(), date, key, "approver")
            .unwrap()
            .unwrap();
        token
    };
    let alice = issue(
        &mut book,
        &steward,
        2,
        &[Op::Approve, Op::IssueCapability],
        b"alice",
    );
    let bob = issue(&mut book, &steward, 3, &[Op::Approve], b"bob");
    let dave = issue(&mut book, &alice, 6, &[Op::Approve], b"dave");
    let carol = issue(&mut book, &planner, 5, &[Op::Approve], b"carol");

    let restate = Capability::embedded(PRINCIPAL, &["restate", "read", "produce"]).unwrap();
    let poster = Capability::embedded(PRINCIPAL, &["restate", "post", "read"]).unwrap();
    let opened = book
        .open_case(
            restate.clone(),
            CaseKind::PolicyChangeRetrospective,
            vec!["FY2025-P12".into()],
            Some(narrative),
            None,
            date,
            b"pcr-open",
        )
        .unwrap()
        .unwrap();
    assert_eq!(opened.case.state, CaseState::Proposed);
    assert_eq!(opened.case.body.kind, CaseKind::PolicyChangeRetrospective);
    let determined = book
        .determine_case(
            restate.clone(),
            1,
            Determination {
                day: day(2026, 2, 10),
                authority,
            },
            date,
            b"pcr-determine",
        )
        .unwrap()
        .unwrap();
    assert_eq!(determined.case.state, CaseState::Determined);

    book.open_scenario(
        planner.clone(),
        "pcr-scenario",
        ScenarioFork::default(),
        december,
        "Retrospective policy change adds 50.00 to December",
    )
    .unwrap()
    .unwrap();
    let supersedes = |kind| fa_model::Supersession {
        target,
        kind,
        reason_code: 4,
    };
    let mut misshapen = entry(
        &book,
        EntryClass::RESTATEMENT,
        legs(5_000),
        b"pcr-misshapen",
        planner_vid,
    );
    misshapen.supersession = vec![supersedes(fa_model::SupersessionKind::Revises)];
    let wrong = book
        .run_in_scenario(
            planner.clone(),
            "pcr-scenario",
            PostIntent::new(misshapen, Vec::new()).unwrap(),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(wrong.code, code::RESTATEMENT_SHAPE, "{wrong:?}");

    let mut planned = entry(
        &book,
        EntryClass::RESTATEMENT,
        legs(5_000),
        b"pcr-delta",
        planner_vid,
    );
    planned.supersession = vec![supersedes(fa_model::SupersessionKind::Restates)];
    book.run_in_scenario(
        planner,
        "pcr-scenario",
        PostIntent::new(planned.clone(), Vec::new()).unwrap(),
    )
    .unwrap()
    .unwrap();
    let rehearsed = book
        .certify_scenario_diff(
            PRINCIPAL,
            &restate,
            "pcr-scenario",
            &["FY2025-P12".to_string()],
            false,
        )
        .unwrap()
        .unwrap();
    let certificate = rehearsed.certificate.clone();
    book.rehearse_case(restate.clone(), 1, &certificate, date, b"pcr-rehearsal")
        .unwrap()
        .unwrap();
    let manifest = book.case_manifest(1).unwrap().unwrap();
    let plan = manifest.entries[0].plan;
    let digest = manifest.digest().unwrap();
    let approve = |book: &mut Book, cap: &Capability| {
        book.approve(cap.clone(), digest)
            .unwrap()
            .unwrap()
            .approval()
            .approval_vid
    };
    let (a, b, d, c) = (
        approve(&mut book, &alice),
        approve(&mut book, &bob),
        approve(&mut book, &dave),
        approve(&mut book, &carol),
    );
    for (pair, approver, issuer) in [
        (vec![a, d], VId(6), VId(2)),
        (vec![a, c], VId(5), planner_vid),
    ] {
        let head = book.head().unwrap();
        let refused = book
            .approve_case(restate.clone(), 1, pair, date, b"pcr-lineage")
            .unwrap()
            .unwrap_err();
        assert_eq!(refused.code, "FA-REF-008", "{refused:?}");
        assert!(
            refused.message.contains(&format!("{:032x}", approver.0))
                && refused.message.contains(&format!("{:032x}", issuer.0))
                && refused.message.contains("session lineage"),
            "{refused:?}"
        );
        assert_eq!(book.head().unwrap(), head);
        assert_eq!(book.case(1).unwrap().unwrap().state, CaseState::Rehearsed);
    }
    book.approve_case(restate.clone(), 1, vec![a, b], date, b"pcr-dual")
        .unwrap()
        .unwrap();

    let derived = fa_journal::derive_member(
        book_id,
        CaseKind::PolicyChangeRetrospective,
        1,
        plan,
        &planned,
        PRINCIPAL,
    )
    .unwrap()
    .unwrap();
    assert_eq!(derived.class, EntryClass::RESTATEMENT);
    assert_eq!(derived.supersession, planned.supersession);
    let alone = book
        .post(PostRequest {
            proposal: derived.clone(),
            approvals: Vec::new(),
            plan_certificate: None,
            capability: poster.clone(),
        })
        .unwrap()
        .unwrap_err();
    assert_eq!(alone.code, code::CASE_MEMBERSHIP, "{alone:?}");

    let before = book.trial_balance(&["FY2025-P12".to_string()]).unwrap();
    let posted = book
        .post_case(poster, 1, date, b"pcr-post")
        .unwrap()
        .unwrap();
    assert_eq!(posted.case.state, CaseState::Posted);
    let (restatement, _) = book
        .read_entry(posted.case.posted[0].entry)
        .unwrap()
        .unwrap();
    assert_eq!(restatement.proposal.class, EntryClass::RESTATEMENT);
    assert_eq!(
        restatement.proposal.proposal_digest().unwrap(),
        derived.proposal_digest().unwrap()
    );
    let after = book.trial_balance(&["FY2025-P12".to_string()]).unwrap();
    let cash = |tb: &fa_registers::TrialBalance| {
        tb.rows
            .iter()
            .find(|row| row.code == "1000")
            .map(|row| row.debits - row.credits)
    };
    assert_eq!(cash(&before), Some(15_000));
    assert_eq!(cash(&after), Some(20_000), "the target plus the delta");
    assert_posted_diff_is_the_rehearsed_one(&before, &after, &rehearsed.report);

    let closer = Capability::embedded(PRINCIPAL, &["restate", "read"]).unwrap();
    let note = Document {
        book_id,
        kind: 20,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: b"Note 2: retrospective adoption of ASC 606".to_vec(),
    };
    book.add_document(&note).unwrap().unwrap();
    book.record_review(
        &Capability::embedded(VId(5), &["approve"]).unwrap(),
        &note.oid(),
        Vec::new(),
    )
    .unwrap()
    .unwrap();
    let comparisons = retain_case_comparisons(&mut book, 1);
    let disclosed = book
        .disclose_case(
            closer.clone(),
            1,
            note.oid(),
            &comparisons,
            date,
            b"pcr-disclose",
        )
        .unwrap()
        .unwrap();
    assert_eq!(disclosed.case.state, CaseState::Disclosed);
    let closed = book
        .close_case(closer, 1, date, b"pcr-close")
        .unwrap()
        .unwrap();
    assert_eq!(closed.case.state, CaseState::Closed);
}
