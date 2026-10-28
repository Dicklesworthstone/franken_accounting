//! Native source-bound payments must remain independently exportable through
//! zero and partial relief, final application, grouped items and exact undos.

use super::*;
use fa::FxSettlementRequest;
use fa_model::{Supersession, SupersessionKind};

#[path = "settlements/drafts.rs"]
mod drafts;

fn settlement_fixture() -> Fixture {
    let mut fixture = Fixture::new();
    let accounts = [
        ("1000", AccountType::ASSET),
        ("1299", AccountType::ASSET),
        ("4900", AccountType::REVENUE),
    ]
    .into_iter()
    .map(|(code, kind)| AccountSpec {
        code: code.into(),
        name: code.into(),
        account_type: kind.0,
        normal_balance: u8::from(kind == AccountType::REVENUE),
        is_leaf: true,
        unit_policy: UnitPolicy::AnyCurrency,
        parent_code: None,
        limit: None,
    })
    .collect::<Vec<_>>();
    fixture
        .book
        .install_chart(
            &accounts,
            PRINCIPAL,
            day(1, 1),
            b"portable-settlement-chart",
            &cap(&["schema_change"]),
        )
        .unwrap()
        .unwrap();
    fixture
}

fn settlement_rate(fixture: &mut Fixture) -> Oid {
    // A retained Settlement quote may precede the payment date. It must not
    // be silently replaced by a current SpotClose quote during verification.
    let rate = FxRateDocument::new(
        FxRateTerms {
            base_unit: fixture.usd,
            quote_unit: fixture.eur,
            rate_num: 2,
            rate_den: 1,
            rounding: RoundingLaw::HalfEven,
        },
        day(1, 5),
        1_767_571_200_000_000_000,
        FxRatePurpose::Settlement,
        "Original retained settlement quote",
    )
    .unwrap();
    fixture
        .book
        .upload_fx_rate(&cap(&["post"]), &rate)
        .unwrap()
        .unwrap()
        .oid
}

fn template(fixture: &Fixture, key: &[u8], effective: DateDay) -> EntryPayload {
    let mut proposal = fixture.proposal(key, effective, 1);
    proposal.legs.clear();
    proposal.unit_totals.clear();
    proposal
}

fn application(
    fixture: &Fixture,
    target: EntryRef,
    amount: i128,
    rate: Oid,
) -> FxSettlementRequest {
    let book = fixture.book.context().book_id;
    FxSettlementRequest {
        target,
        target_ordinal: 0,
        amount: Amount::new(fixture.eur, amount),
        settlement_amount: Amount::new(fixture.usd, amount * 2),
        settlement_account: account_vid(book, "1000"),
        conversion_account: account_vid(book, "1299"),
        realized_fx_account: account_vid(book, "4900"),
        rate_document: rate,
    }
}

fn post_settlement(fixture: &mut Fixture, proposal: EntryPayload) -> EntryRef {
    fixture
        .book
        .post(PostRequest {
            capability: cap(&["read", "post"]),
            ..request(proposal)
        })
        .unwrap()
        .unwrap()
        .entry_ref()
}

fn pay(
    fixture: &mut Fixture,
    request: &FxSettlementRequest,
    key: &[u8],
    date: DateDay,
    expected_relief: i128,
) -> EntryRef {
    let proposal = template(fixture, key, date);
    let prepared = fixture
        .book
        .prepare_fx_settlement(&cap(&["read", "post"]), request, proposal)
        .unwrap()
        .unwrap();
    assert_eq!(
        prepared.base_relief(),
        Amount::new(fixture.usd, expected_relief)
    );
    post_settlement(fixture, prepared.into_proposal())
}

fn undo(fixture: &mut Fixture, target: EntryRef, key: &[u8], effective: DateDay) -> EntryRef {
    let (entry, _) = fixture.book.read_entry(target.vid).unwrap().unwrap();
    let mut proposal = entry.proposal.clone();
    proposal.class = EntryClass::REVERSAL;
    proposal.idempotency_key = key.to_vec();
    proposal.effective_date = effective;
    proposal.description = fixture.book.seal_text("Exact payment undo").unwrap();
    proposal.supersession = vec![Supersession {
        target,
        kind: SupersessionKind::Reverses,
        reason_code: 1,
    }];
    for leg in &mut proposal.legs {
        // Reversal effects follow the authenticated supersession; they must
        // not issue a fresh application of the original native amount.
        leg.settles.clear();
        leg.side = match leg.side {
            Side::Debit => Side::Credit,
            Side::Credit => Side::Debit,
        };
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    post_settlement(fixture, proposal)
}

struct Snapshot {
    trial_balance: ReportCertificate,
    statements: Vec<(ReportCertificate, &'static str, Vec<i128>)>,
    receivable: i128,
    cash: i128,
    realized: i128,
}

fn capture(
    fixture: &mut Fixture,
    receivable: i128,
    cash: i128,
    realized: i128,
    original_revenue: i128,
) -> Snapshot {
    let trial_balance = certify(fixture, TrialBalanceSelection::AsOf(day(2, 28)));
    let mut statements = Vec::new();
    for (definition, line, expected) in [
        (
            "balance-sheet",
            "assets",
            vec![receivable + cash, original_revenue],
        ),
        (
            "income-statement",
            "net_income",
            vec![realized, original_revenue],
        ),
    ] {
        let certified = fixture
            .book
            .certify_functional_statement(
                PRINCIPAL,
                &producer(),
                statement_selection(definition, true),
                None,
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            statement_amounts(&certified.statement, line, fixture.usd),
            expected
        );
        statements.push((certified.certificate, line, expected));
    }
    Snapshot {
        trial_balance,
        statements,
        receivable,
        cash,
        realized,
    }
}

fn check_exports(fixture: &mut Fixture, snapshots: Vec<Snapshot>, rate_count: usize) {
    let state = checkpoint(&mut fixture.book);
    let head = fixture.book.head().unwrap();
    for snapshot in snapshots {
        let produced = produce(fixture, state, &snapshot.trial_balance);
        assert_eq!(produced.documents.len(), rate_count);
        let verified = verify(fixture, &produced, &snapshot.trial_balance);
        assert_eq!(verified.output, snapshot.trial_balance.output);
        let trial_balance = verified.functional_trial_balance.unwrap();
        let book = fixture.book.context().book_id;
        let net = |code: &str| {
            trial_balance
                .cells
                .iter()
                .filter(|cell| cell.account == account_vid(book, code).0)
                .map(|cell| cell.debits - cell.credits)
                .sum::<i128>()
        };
        assert_eq!(net("1200"), snapshot.receivable);
        assert_eq!(net("1000"), snapshot.cash);
        assert_eq!(net("1299"), 0);
        assert_eq!(net("4900"), -snapshot.realized);
        assert!(trial_balance.pending.is_empty());
        for (certificate, line, expected) in snapshot.statements {
            let produced = produce(fixture, state, &certificate);
            assert_eq!(produced.documents.len(), rate_count);
            let verified = verify(fixture, &produced, &certificate);
            assert_eq!(verified.output, certificate.output);
            let statement = verified.functional_statement.unwrap();
            assert_eq!(statement.base_unit, fixture.usd.0);
            assert_eq!(
                statement
                    .statement
                    .lines
                    .iter()
                    .find(|row| row.code == line)
                    .unwrap()
                    .amounts,
                expected
            );
        }
    }
    assert_eq!(fixture.book.head().unwrap(), head);
}

#[test]
fn payments_export_zero_partial_final_relief_and_exact_undo_history() {
    let mut fixture = settlement_fixture();
    // Four native minor units carry two base minor units. The first one-unit
    // payment rounds 2/4 to even zero; the next rounds 2/3 to one, and the
    // final two-unit payment takes the exact remaining one.
    let target = fixture.post(b"portable-tiny-invoice", day(1, 5), 4, 5);
    let rate = settlement_rate(&mut fixture);
    let first = application(&fixture, target, 1, rate);
    let zero = pay(&mut fixture, &first, b"portable-zero-relief", day(2, 5), 0);
    let mut snapshots = vec![capture(&mut fixture, 2, 2, 2, 2)];
    pay(
        &mut fixture,
        &first,
        b"portable-partial-relief",
        day(2, 6),
        1,
    );
    let final_request = application(&fixture, target, 2, rate);
    let final_payment = pay(
        &mut fixture,
        &final_request,
        b"portable-final-relief",
        day(2, 7),
        1,
    );
    snapshots.push(capture(&mut fixture, 0, 8, 6, 2));
    undo(
        &mut fixture,
        final_payment,
        b"portable-final-undo",
        day(2, 10),
    );
    snapshots.push(capture(&mut fixture, 1, 4, 3, 2));
    // Re-prepare against the restored pool. Native admission requires a new
    // payment instead of reversing an applying entry's reversal.
    pay(
        &mut fixture,
        &final_request,
        b"portable-final-repayment",
        day(2, 11),
        1,
    );
    undo(&mut fixture, zero, b"portable-zero-undo", day(2, 12));
    snapshots.push(capture(&mut fixture, 0, 6, 4, 2));
    pay(
        &mut fixture,
        &first,
        b"portable-zero-repayment",
        day(2, 13),
        0,
    );
    snapshots.push(capture(&mut fixture, 0, 8, 6, 2));
    fixture.rate(day(1, 5), 99, "Later unused quote");
    fixture.post(b"portable-after-payment-backdate", day(1, 20), 100, 12);
    check_exports(&mut fixture, snapshots, 2);
}

#[test]
fn grouped_payments_export_each_original_target_and_realized_fx() {
    let mut fixture = settlement_fixture();
    let first = fixture.post(b"portable-group-first", day(1, 5), 100, 11);
    let second = fixture.post(b"portable-group-second", day(1, 6), 50, 12);
    let rate = settlement_rate(&mut fixture);
    let requests = [
        application(&fixture, first, 100, rate),
        application(&fixture, second, 50, rate),
    ];
    let proposal = template(&fixture, b"portable-group-payment", day(2, 5));
    let prepared = fixture
        .book
        .prepare_fx_settlement_group(&cap(&["read", "post"]), &requests, proposal)
        .unwrap()
        .unwrap();
    assert_eq!(
        prepared
            .items()
            .iter()
            .map(|item| item.base_relief.mantissa)
            .collect::<Vec<_>>(),
        vec![110, 60]
    );
    post_settlement(&mut fixture, prepared.into_proposal());
    let snapshot = capture(&mut fixture, 0, 300, 130, 170);
    check_exports(&mut fixture, vec![snapshot], 3);
}
