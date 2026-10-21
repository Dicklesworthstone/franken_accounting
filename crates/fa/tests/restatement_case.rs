//! Restatement cases through the public facade (plan §8.3, bead fa-75j4):
//! a journaled case body, its determination, its numbering and its
//! refusals, over a real memory book.

use fa::{Book, BookKeys, Entropy};
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

fn day(year: i32, month: u8, day: u8) -> DateDay {
    DateDay::from_ymd(year, month, day).unwrap()
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
    let book_id = book.context().book_id;
    let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
    let schema = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
    book.create_periods(2026, PRINCIPAL, &schema)
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
    let planned = EntryPayload {
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
    // A superseding case kind's entries are not posted in this build.
    let delta =
        fa_journal::derive_member(book_id, CaseKind::Restatement, 1, plan, &planned, PRINCIPAL)
            .unwrap()
            .unwrap_err();
    assert_eq!(delta.code, code::CASE_MEMBERSHIP, "{delta:?}");

    // An approver may not post: the entry's row excludes its preparer.
    let approver = Capability::embedded(VId(2), &["restate", "post", "read"]).unwrap();
    let own = book
        .post_case(approver, 1, date, b"post")
        .unwrap()
        .unwrap_err();
    assert_eq!(own.exit, 7, "{own:?}");
    assert_eq!(book.head().unwrap(), head);
    assert_eq!(book.case(1).unwrap().unwrap().state, CaseState::Approved);

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
}
