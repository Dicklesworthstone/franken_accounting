use crate::query::{QueryCell, QueryRows, code};
use crate::{Book, BookKeys, Entropy};
use fa_journal::{AccountSpec, BookSpec, Capability, Document, PostRequest, Refusal, UnitPolicy};
use fa_model::{
    EntryClass, EntryOrigin, EntryPayload, EntryRef, EvidenceRef, Id128, LegPayload, Oid, Pending,
    Settlement, Supersession, SupersessionKind, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb_types::{CommitSeq, VId};

const BOOK: Id128 = Id128([0x95; 16]);
const PRINCIPAL: VId = VId(7);

fn day(text: &str) -> DateDay {
    DateDay::parse(text).unwrap()
}
fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

pub(crate) struct Fixture {
    pub(crate) book: Book,
    evidence: EvidenceRef,
    pub(crate) usd: UnitId,
    eur: UnitId,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let eur = units.lookup("EUR").unwrap();
        let mut book = Book::create_memory(
            BookKeys::for_development(0x95),
            BookSpec {
                book_id: BOOK,
                name: "Per-row native accounting".into(),
                base_unit: usd,
                calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            },
            Entropy::deterministic(149),
        )
        .unwrap();
        let chart = ["ar", "cash", "sales"]
            .into_iter()
            .map(|code| AccountSpec {
                code: code.into(),
                name: code.into(),
                account_type: if code == "sales" { 4 } else { 1 },
                normal_balance: u8::from(code == "sales"),
                is_leaf: true,
                unit_policy: UnitPolicy::AnyCurrency,
                parent_code: None,
                limit: None,
            })
            .collect::<Vec<_>>();
        book.install_chart(
            &chart,
            PRINCIPAL,
            day("2026-03-01"),
            b"chart",
            &cap(&["schema_change"]),
        )
        .unwrap()
        .unwrap();
        book.create_periods(2026, PRINCIPAL, &cap(&["schema_change"]))
            .unwrap()
            .unwrap();
        book.transition_period(
            "FY2026-P03",
            PeriodTransition::Open,
            PRINCIPAL,
            1,
            b"open",
            &cap(&["close"]),
        )
        .unwrap()
        .unwrap();
        let document = Document {
            book_id: BOOK,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"Per-row query invoice and remittance evidence".to_vec(),
        };
        book.add_document(&document).unwrap().unwrap();
        Self {
            book,
            evidence: document.evidence_ref(1),
            usd,
            eur,
        }
    }

    pub(crate) fn proposal(
        &self,
        key: &str,
        date: &str,
        unit: UnitId,
        debit: &str,
        credit: &str,
        amount: i128,
    ) -> EntryPayload {
        let legs = vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(BOOK, debit),
                Amount::new(unit, amount),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(BOOK, credit),
                Amount::new(unit, amount),
            ),
        ];
        EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: BOOK,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day(date),
            document_date: None,
            description: self.book.seal_text(key).unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.as_bytes().to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([0x95; 32]),
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: vec![self.evidence],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        }
    }

    pub(crate) fn post(&mut self, proposal: EntryPayload) -> EntryRef {
        self.book
            .post(PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(&["post"]),
            })
            .unwrap()
            .unwrap()
            .entry_ref()
    }

    fn query(&self, tail: &str, cutoff: &str, seq: CommitSeq) -> Result<QueryRows, Refusal> {
        let text = format!(
            "MATCH (l:Leg)-[:POSTS_TO]->(a:Account {{code:'ar'}}), (l)-[:IN_UNIT]->(u:Unit) CALL fa.open_amount(l) YIELD open, age_days {tail} EFFECTIVE AT '{cutoff}' AS KNOWN AT {}",
            seq.0
        );
        let fa_query::Selection::Native(native) = fa_query::rewrite(&text).unwrap().selection
        else {
            panic!("native pipeline");
        };
        self.book.query_native(&native, seq, None).unwrap()
    }
}

#[test]
fn native_pipeline_uses_historical_settlements_and_filters_after_the_fold() {
    let mut f = Fixture::new();
    let invoice = f.post(f.proposal("invoice", "2026-03-01", f.usd, "ar", "sales", 10_000));
    let original = f.book.head().unwrap();
    let mut receipt = f.proposal("receipt", "2026-03-10", f.usd, "cash", "ar", 4_000);
    receipt.legs[1].settles.push(Settlement {
        target: invoice,
        ordinal: 0,
        amount: Amount::new(f.usd, 4_000),
    });
    let receipt_ref = f.post(receipt.clone());
    let paid = f.book.head().unwrap();
    let tail = "WHERE age_days > 15 RETURN a.code AS account, open, age_days ORDER BY age_days DESC LIMIT 1";
    let paid_rows = f.query(tail, "2026-03-20", paid).unwrap();
    assert_eq!(paid_rows.columns, ["account", "open", "age_days"]);
    assert_eq!(
        paid_rows.rows,
        vec![vec![
            QueryCell::Text("ar".into()),
            QueryCell::Decimal("60".into()),
            QueryCell::Int(19)
        ]]
    );
    assert!(paid_rows.statement.contains("UNWIND $__fa_rows"));
    assert_eq!(
        f.query(tail, "2026-03-20", original).unwrap().rows[0][1],
        QueryCell::Decimal("100".into())
    );
    let earlier = f
        .query("RETURN open, age_days", "2026-03-05", paid)
        .unwrap();
    assert_eq!(
        earlier.rows,
        vec![vec![QueryCell::Decimal("100".into()), QueryCell::Int(4)]]
    );

    let mut pending = f.proposal("pending", "2026-03-02", f.usd, "ar", "cash", 9_000);
    pending.class = EntryClass::PENDING;
    pending.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    f.post(pending);
    let head = f.book.head().unwrap();
    assert_eq!(
        f.query(tail, "2026-03-20", head).unwrap().rows,
        paid_rows.rows
    );
    let all = f
        .query("RETURN open, age_days", "2026-03-20", head)
        .unwrap();
    assert_eq!(all.rows.len(), 3);
    assert!(all.rows.contains(&vec![QueryCell::Null, QueryCell::Null]));
    assert_eq!(
        f.query("RETURN u.code, SUM(open)", "2026-03-20", head)
            .unwrap_err()
            .code,
        code::QUERY_AMOUNT_LAW
    );
    assert_eq!(
        f.query(
            "WHERE open IS NOT NULL RETURN u.code, SUM(open)",
            "2026-03-20",
            head
        )
        .unwrap()
        .rows,
        vec![vec![
            QueryCell::Text("USD".into()),
            QueryCell::Decimal("60".into())
        ]]
    );

    // A later-recorded reversal does not change the earlier prefix. Its
    // effective date also cannot reopen the item before that civil cutoff.
    receipt.class = EntryClass::REVERSAL;
    receipt.effective_date = day("2026-03-22");
    receipt.idempotency_key = b"reverse-receipt".to_vec();
    receipt.description = f.book.seal_text("reverse receipt").unwrap();
    receipt.supersession = vec![Supersession {
        target: receipt_ref,
        kind: SupersessionKind::Reverses,
        reason_code: 1,
    }];
    for leg in &mut receipt.legs {
        leg.side = match leg.side {
            Side::Debit => Side::Credit,
            Side::Credit => Side::Debit,
        };
        leg.settles.clear();
    }
    receipt.unit_totals = EntryPayload::fold_unit_totals(&receipt.legs).unwrap();
    f.post(receipt);
    let later = f.book.head().unwrap();
    assert_eq!(
        f.query(tail, "2026-03-20", later).unwrap().rows,
        paid_rows.rows
    );
    assert_eq!(
        f.query(tail, "2026-03-31", later).unwrap().rows[0][1],
        QueryCell::Decimal("100".into())
    );
    assert_eq!(
        f.query(tail, "2026-03-20", paid)
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        paid_rows.canonical_bytes().unwrap()
    );
    assert_eq!(f.book.head().unwrap(), later, "queries never publish");
}

#[test]
fn native_pipeline_preserves_exact_units_and_refuses_unsupported_certification() {
    let mut f = Fixture::new();
    f.post(f.proposal("usd", "2026-03-01", f.usd, "ar", "sales", 123));
    f.post(f.proposal("eur", "2026-03-02", f.eur, "ar", "sales", 7));
    let at = f.book.head().unwrap();
    let rows = f
        .query(
            "RETURN u.code AS unit, SUM(open) AS total ORDER BY unit",
            "2026-03-31",
            at,
        )
        .unwrap();
    assert_eq!(
        rows.rows,
        vec![
            vec![
                QueryCell::Text("EUR".into()),
                QueryCell::Decimal("0.07".into())
            ],
            vec![
                QueryCell::Text("USD".into()),
                QueryCell::Decimal("1.23".into())
            ],
        ]
    );
    let statement = "MATCH (l:Leg) CALL fa.open_amount(l) YIELD open, age_days RETURN open EFFECTIVE AT '2026-03-31'";
    let certified = f
        .book
        .certify_query(PRINCIPAL, &cap(&["read", "produce"]), statement)
        .unwrap()
        .unwrap();
    assert_eq!(
        certified.certificate.format(),
        crate::query::QUERY_CERTIFICATE_FORMAT_V2
    );
    assert!(certified.certificate.pipeline_source().is_some());
    assert!(certified.certificate.parameters_digest().is_some());
    assert_eq!(
        f.book
            .replay_query(PRINCIPAL, &cap(&["read"]), &certified.certificate)
            .unwrap()
            .unwrap(),
        certified.rows
    );
    for branch in ["scenario:forecast", "draft:forecast"] {
        let refusal = f
            .book
            .certify_query(
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &format!("{statement} AT BRANCH '{branch}'"),
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, code::QUERY_PROFILE);
        assert!(refusal.message.contains("trunk"));
    }
    let denied = f
        .book
        .certify_query(PRINCIPAL, &cap(&["produce"]), statement)
        .unwrap()
        .unwrap_err();
    assert_ne!(
        denied.code,
        code::QUERY_PROFILE,
        "current read authority is checked first"
    );
    assert_eq!(f.book.head().unwrap(), at);
}

#[test]
fn historical_query_authority_binds_native_reads_certification_and_typed_replay() {
    let mut f = Fixture::new();
    f.post(f.proposal(
        "historical-invoice",
        "2026-03-01",
        f.usd,
        "ar",
        "sales",
        10_000,
    ));
    let pin = f.book.head().unwrap();
    let statement = format!(
        "MATCH (l:Leg) RETURN COUNT(*) AS legs AS KNOWN AT {}",
        pin.0
    );
    let fa_query::Selection::Native(native) = fa_query::rewrite(&statement).unwrap().selection
    else {
        panic!("native statement");
    };
    let reader = cap(&["read"]).known_at_most(pin);
    let producer = cap(&["read", "produce"]).known_at_most(pin);
    let original = f
        .book
        .query_native_for(PRINCIPAL, &reader, &native, pin, None)
        .unwrap()
        .unwrap();
    assert_eq!(original.rows, vec![vec![QueryCell::Int(2)]]);
    let certified = f
        .book
        .certify_query(PRINCIPAL, &producer, &statement)
        .unwrap()
        .unwrap();
    assert_eq!(certified.rows, original);
    let pipeline = format!(
        "MATCH (l:Leg)-[:POSTS_TO]->(a:Account {{code:'ar'}}) CALL fa.open_amount(l) YIELD open, age_days RETURN open, age_days EFFECTIVE AT '2026-03-20' AS KNOWN AT {}",
        pin.0
    );
    let certified_pipeline = f
        .book
        .certify_query(PRINCIPAL, &producer, &pipeline)
        .unwrap()
        .unwrap();
    assert!(certified_pipeline.certificate.pipeline_source().is_some());

    // The current graph now differs. Both certificate versions and a fresh
    // native query still read the selected old snapshot under current authority.
    f.post(f.proposal("later-invoice", "2026-03-02", f.usd, "ar", "sales", 4_000));
    let head = f.book.head().unwrap();
    assert_eq!(
        f.book
            .query_native(&native, head, None)
            .unwrap()
            .unwrap()
            .rows,
        vec![vec![QueryCell::Int(4)]]
    );
    assert_eq!(
        f.book
            .query_native_for(PRINCIPAL, &reader, &native, pin, None)
            .unwrap()
            .unwrap(),
        original
    );
    assert_eq!(
        f.book
            .certify_query(PRINCIPAL, &producer, &statement)
            .unwrap()
            .unwrap()
            .rows,
        original
    );
    for certified in [&certified, &certified_pipeline] {
        assert_eq!(
            f.book
                .replay_query(PRINCIPAL, &reader, &certified.certificate)
                .unwrap()
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            certified.rows.canonical_bytes().unwrap()
        );
        assert_eq!(
            f.book
                .query_certificate_status(PRINCIPAL, &reader, &certified.certificate)
                .unwrap()
                .unwrap_err()
                .code,
            "FA-REF-011",
            "status observes HEAD even when replay itself is authorized"
        );
    }

    // No selector inferred from a predicate narrows the graph's reach. These
    // refusals precede even looking up the deliberately nonexistent period.
    let scopes = [
        producer.clone().known_at_most(CommitSeq(pin.0 - 1)),
        producer.clone().for_accounts(&["ar"]).unwrap(),
        producer.clone().for_periods(&["FY2026-P03"]).unwrap(),
        producer.clone().effective_through(day("2026-03-31")),
        producer
            .clone()
            .for_classes(&[EntryClass::ORIGINAL])
            .unwrap(),
        producer.clone().on_branch(Id128([0x96; 16])).unwrap(),
        producer.clone().for_books(&[Id128([0x96; 16])]).unwrap(),
    ];
    for scoped in scopes {
        assert_eq!(
            f.book
                .query_native_for(PRINCIPAL, &scoped, &native, pin, Some("missing-period"))
                .unwrap()
                .unwrap_err()
                .code,
            "FA-REF-011"
        );
        assert_eq!(
            f.book
                .certify_query(PRINCIPAL, &scoped, &statement)
                .unwrap()
                .unwrap_err()
                .code,
            "FA-REF-011"
        );
        assert_eq!(
            f.book
                .replay_query(PRINCIPAL, &scoped, &certified.certificate)
                .unwrap()
                .unwrap_err()
                .code,
            "FA-REF-011"
        );
    }
    assert_eq!(
        f.book
            .query_native_for(PRINCIPAL, &reader, &native, head, None)
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-011"
    );
    for suffix in ["", " AS KNOWN AT HEAD", " AS CURRENTLY STATED"] {
        assert_eq!(
            f.book
                .certify_query(
                    PRINCIPAL,
                    &producer,
                    &format!("MATCH (l:Leg) RETURN COUNT(*) AS legs{suffix}"),
                )
                .unwrap()
                .unwrap_err()
                .code,
            "FA-REF-011"
        );
    }
    assert!(
        fa_query::rewrite("MATCH (l:Leg) FOR SYSTEM_TIME AS OF SEQ 999 RETURN l").is_err(),
        "Native cannot smuggle a second sequence past the authorized binding"
    );
    assert_eq!(
        f.book.head().unwrap(),
        head,
        "read-only operations do not publish"
    );
}

#[test]
fn historical_query_authority_expires_and_revokes_at_the_current_head() {
    let mut f = Fixture::new();
    f.post(f.proposal(
        "original-invoice",
        "2026-03-01",
        f.usd,
        "ar",
        "sales",
        10_000,
    ));
    let pin = f.book.head().unwrap();
    let statement = format!(
        "MATCH (l:Leg) RETURN COUNT(*) AS legs AS KNOWN AT {}",
        pin.0
    );
    let fa_query::Selection::Native(native) = fa_query::rewrite(&statement).unwrap().selection
    else {
        panic!("native statement");
    };
    let pinned = cap(&["read", "produce"]).known_at_most(pin);
    let expiring = pinned.clone().expiring_at(CommitSeq(pin.0 + 1));
    let certified = f
        .book
        .certify_query(PRINCIPAL, &expiring, &statement)
        .unwrap()
        .unwrap();
    f.post(f.proposal("expiry-advances", "2026-03-02", f.usd, "ar", "sales", 100));
    f.book
        .revoke_capability(
            cap(&["issue_capability"]),
            pinned.commitment().unwrap(),
            day("2026-03-03"),
            b"withdraw-query-reader",
            "Withdraw historical query authority",
        )
        .unwrap()
        .unwrap();
    let head = f.book.head().unwrap();
    for (capability, expected) in [(&expiring, "FA-REF-014"), (&pinned, "FA-REF-023")] {
        assert_eq!(
            f.book
                .query_native_for(PRINCIPAL, capability, &native, pin, Some("missing-period"))
                .unwrap()
                .unwrap_err()
                .code,
            expected,
            "authority refusal wins over protected historical metadata"
        );
        assert_eq!(
            f.book
                .certify_query(PRINCIPAL, capability, &statement)
                .unwrap()
                .unwrap_err()
                .code,
            expected
        );
        assert_eq!(
            f.book
                .replay_query(PRINCIPAL, capability, &certified.certificate)
                .unwrap()
                .unwrap_err()
                .code,
            expected
        );
    }
    assert_eq!(f.book.head().unwrap(), head);
}
