//! Read-only asset reports hydrate a reopened storage checkpoint before the
//! authenticated source fold, and reject unauthorized callers before loading.

use std::path::Path;

use fa::{
    AssetChargeRequest, AssetCostKind, AssetRegister, AssetScheduleRequest, AssetScheduleSpec,
    Book, BookKeys, Entropy,
};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, UnitPolicy};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, Id128, LegPayload, Oid, PeriodRef,
    account_vid,
};
use fa_money::{Amount, RoundingLaw, Side, UnitRegistry};
use fa_policy::Capability;
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb_types::{CommitSeq, VId};

const PRINCIPAL: VId = VId(197);
const PERIOD: &str = "FY2026-P03";

fn capability(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

fn create_charged_book(dir: &Path, keys: BookKeys) -> (Book, AssetRegister) {
    let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
    let book_id = Id128([197; 16]);
    let day = DateDay::from_ymd(2026, 3, 1).unwrap();
    let mut book = Book::create_dir(
        dir,
        keys,
        BookSpec {
            book_id,
            name: "Checkpointed asset register".into(),
            base_unit: usd,
            calendar: FiscalCalendar::monthly("asset-register-cold", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(197),
    )
    .unwrap();
    let accounts = [
        ("1000", AccountType::ASSET, 0),
        ("1500", AccountType::ASSET, 0),
        ("1590", AccountType::ASSET, 1),
        ("6000", AccountType::EXPENSE, 0),
    ]
    .map(|(code, kind, normal)| AccountSpec {
        code: code.into(),
        name: code.into(),
        account_type: kind.0,
        normal_balance: normal,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(usd),
        parent_code: None,
        limit: None,
    });
    let schema = capability(&["read", "schema_change"]);
    book.install_chart(&accounts, PRINCIPAL, day, b"register-chart", &schema)
        .unwrap()
        .unwrap();
    book.create_periods(2026, PRINCIPAL, &schema)
        .unwrap()
        .unwrap();
    book.transition_period(
        PERIOD,
        PeriodTransition::Open,
        PRINCIPAL,
        1,
        b"register-open",
        &capability(&["close"]),
    )
    .unwrap()
    .unwrap();
    let document = Document {
        book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: b"Retained equipment acquisition invoice".to_vec(),
    };
    book.add_document(&document).unwrap().unwrap();
    let source_legs = vec![
        LegPayload::simple(
            Side::Debit,
            account_vid(book_id, "1500"),
            Amount::new(usd, 10_000),
        ),
        LegPayload::simple(
            Side::Credit,
            account_vid(book_id, "1000"),
            Amount::new(usd, 10_000),
        ),
    ];
    let mut source = EntryPayload {
        schema_minor: 0,
        book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: day,
        document_date: None,
        description: book.seal_text("Equipment acquisition").unwrap(),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&source_legs).unwrap(),
        legs: source_legs,
        control: None,
        base_totals: None,
        idempotency_key: b"register-acquisition".to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([197; 32]),
            intent_kind: 1,
        },
        principal_ref: PRINCIPAL,
        session_ref: None,
        evidence: vec![document.evidence_ref(1)],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    let author = capability(&["read", "post"]);
    let acquisition = book
        .post(PostRequest {
            proposal: source.clone(),
            approvals: Vec::new(),
            plan_certificate: None,
            capability: author.clone(),
        })
        .unwrap()
        .unwrap()
        .entry_ref();
    let selected = PeriodRef {
        calendar: book.context().calendar.id.clone(),
        code: PERIOD.into(),
    };
    let schedule = book
        .create_asset_schedule(
            AssetScheduleRequest {
                principal: PRINCIPAL,
                spec: AssetScheduleSpec {
                    name: "press".into(),
                    kind: AssetCostKind::Depreciation,
                    acquisition,
                    acquisition_ordinal: 0,
                    first_period: selected.clone(),
                    useful_life_periods: 3,
                    salvage: Amount::new(usd, 0),
                    expense_account: account_vid(book_id, "6000"),
                    accumulated_account: account_vid(book_id, "1590"),
                    rounding_law: RoundingLaw::HalfEven,
                },
                effective_date: day,
                idempotency_key: b"register-schedule".to_vec(),
                description: book
                    .seal_text("Finite acquisition cost allocation")
                    .unwrap(),
                approvals: Vec::new(),
            },
            &schema,
        )
        .unwrap()
        .unwrap();
    source.class = EntryClass::ADJUSTING;
    source.idempotency_key = b"register-charge".to_vec();
    source.effective_date = DateDay::from_ymd(2026, 3, 31).unwrap();
    source.effective_period = Some(selected.clone());
    source.legs.clear();
    source.unit_totals.clear();
    let prepared = book
        .prepare_asset_charge(
            &author,
            &AssetChargeRequest {
                schedule: schedule.entry,
                through_period: selected,
                kind: AssetCostKind::Depreciation,
            },
            &source,
        )
        .unwrap()
        .unwrap();
    let proposal = prepared.proposal(source).unwrap();
    book.post(PostRequest {
        proposal,
        approvals: Vec::new(),
        plan_certificate: None,
        capability: author,
    })
    .unwrap()
    .unwrap();
    let expected = book
        .asset_register(None, &capability(&["read"]))
        .unwrap()
        .unwrap();
    assert_eq!(expected.rows[0].recognized.mantissa, 3333);
    assert_eq!(expected.rows[0].carrying_amount.mantissa, 6667);
    (book, expected)
}

#[test]
fn reopened_checkpoint_head_hydrates_asset_reports_only_after_read_authorization() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("fa-asset-register-{}-{nonce}", std::process::id()));
    let keys = BookKeys::for_development(197);
    let (mut book, expected) = create_charged_book(&dir, keys.clone());
    book.compact_storage().unwrap();
    drop(book);

    let mut book = Book::open_dir(&dir, keys.clone(), Entropy::deterministic(198)).unwrap();
    assert!(
        !book.has_delta_since(CommitSeq(0)).unwrap(),
        "test must start from a cold checkpoint"
    );
    let head = book.head().unwrap();
    assert_eq!(
        book.asset_register(None, &capability(&["post"]))
            .unwrap()
            .unwrap_err()
            .exit,
        7
    );
    assert!(
        !book.has_delta_since(CommitSeq(0)).unwrap(),
        "denied reads must not hydrate history"
    );
    let read = capability(&["read"]);
    assert_eq!(book.asset_register(None, &read).unwrap().unwrap(), expected);
    assert!(
        book.has_delta_since(CommitSeq(0)).unwrap(),
        "authorized HEAD report must load complete source history"
    );
    assert_eq!(
        book.head().unwrap(),
        head,
        "hydration is not a journal publication"
    );
    drop(book);

    // Terms-only reads need the same source-integrity history. Reopen again
    // so this assertion cannot accidentally reuse the register's hydration.
    let mut book = Book::open_dir(&dir, keys, Entropy::deterministic(199)).unwrap();
    assert!(!book.has_delta_since(CommitSeq(0)).unwrap());
    let expired = read.clone().expiring_at(CommitSeq(0));
    assert_eq!(
        book.asset_schedules(None, &expired)
            .unwrap()
            .unwrap_err()
            .exit,
        7
    );
    assert!(!book.has_delta_since(CommitSeq(0)).unwrap());
    let schedules = book.asset_schedules(None, &read).unwrap().unwrap();
    assert_eq!(schedules, vec![expected.rows[0].schedule.clone()]);
    assert!(book.has_delta_since(CommitSeq(0)).unwrap());
    assert_eq!(book.head().unwrap(), head);
}
