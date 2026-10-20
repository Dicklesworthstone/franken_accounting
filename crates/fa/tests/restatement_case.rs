//! Restatement cases through the public facade (plan §8.3, bead fa-75j4):
//! a journaled case body, its determination, its numbering and its
//! refusals, over a real memory book.

use fa::{Book, BookKeys, Entropy};
use fa_journal::refusal::code;
use fa_journal::{
    AccountSpec, BookSpec, Capability, CaseKind, CaseState, Determination, Document, UnitPolicy,
};
use fa_model::{AccountType, Id128, Oid};
use fa_money::UnitRegistry;
use fa_policy::{Op, Profile};
use fa_time::{DateDay, FiscalCalendar};
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
        &[AccountSpec {
            code: "1000".into(),
            name: "Cash".into(),
            account_type: AccountType::ASSET.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        }],
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
