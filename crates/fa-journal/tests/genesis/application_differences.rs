//! Explicit base-unit cash differences through the native posting pipeline.
//! Cash, settled principal and every economic difference remain separate legs.

use super::*;
use fa_journal::refusal::code;
use fa_model::application::{
    ApplicationDifference, ApplicationDifferenceKind, ApplicationDirection, ApplicationTerms,
};
use fa_model::entry::APPLICATION_TERMS_EXTENSION;

use ApplicationDifferenceKind::{BankCharge, Discount, Writeoff};
use ApplicationDirection::{Payment, Receipt};

#[derive(Clone, Copy)]
struct Source {
    entry: EntryRef,
    ordinal: u16,
}

struct Fixture {
    h: Harness,
    payable: VId,
    discount: VId,
    writeoff: VId,
    bank_fee: VId,
}

impl Fixture {
    fn new() -> Self {
        let mut h = harness();
        let accounts: Vec<_> = [
            ("2100", "Trade payable", fa_model::AccountType::LIABILITY, 1),
            (
                "6100",
                "Settlement discount",
                fa_model::AccountType::EXPENSE,
                0,
            ),
            (
                "6200",
                "Settlement write-off",
                fa_model::AccountType::EXPENSE,
                0,
            ),
            ("6300", "Bank charges", fa_model::AccountType::EXPENSE, 0),
        ]
        .into_iter()
        .map(|(code, name, kind, normal_balance)| AccountSpec {
            code: code.into(),
            name: name.into(),
            account_type: kind.0,
            normal_balance,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(h.usd),
            parent_code: None,
            limit: None,
        })
        .collect();
        let cx = h.ctx();
        let day = h.day();
        let description = h
            .proposal(vec![], b"application-chart", EntryClass::ORIGINAL)
            .description;
        h.runtime
            .block_on(install_chart(
                &mut h.db,
                &cx,
                &h.book,
                &accounts,
                PRINCIPAL,
                day,
                b"application-chart",
                description,
                &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        Self {
            payable: account_vid(h.book.book_id, "2100"),
            discount: account_vid(h.book.book_id, "6100"),
            writeoff: account_vid(h.book.book_id, "6200"),
            bank_fee: account_vid(h.book.book_id, "6300"),
            h,
        }
    }

    fn source(&mut self, direction: ApplicationDirection, amount: i128, key: &[u8]) -> Source {
        let (proposal, ordinal) = match direction {
            Receipt => (self.h.invoice(amount, key), 0),
            Payment => (
                self.h.proposal(
                    vec![
                        LegPayload::simple(
                            Side::Debit,
                            self.h.rent,
                            Amount::new(self.h.usd, amount),
                        ),
                        LegPayload::simple(
                            Side::Credit,
                            self.payable,
                            Amount::new(self.h.usd, amount),
                        ),
                    ],
                    key,
                    EntryClass::ORIGINAL,
                ),
                1,
            ),
        };
        Source {
            entry: self.post(proposal).unwrap().entry_ref(),
            ordinal,
        }
    }

    fn application(
        &self,
        direction: ApplicationDirection,
        target: Source,
        principal: i128,
        cash: i128,
        differences: &[(ApplicationDifferenceKind, i128)],
        key: &[u8],
    ) -> EntryPayload {
        let (cash_side, applying_side, account) = match direction {
            Receipt => (Side::Debit, Side::Credit, self.h.receivable),
            Payment => (Side::Credit, Side::Debit, self.payable),
        };
        let mut applying =
            LegPayload::simple(applying_side, account, Amount::new(self.h.usd, principal));
        applying.settles = vec![settle(target.entry, target.ordinal, self.h.usd, principal)];
        let mut legs = vec![
            LegPayload::simple(cash_side, self.h.cash, Amount::new(self.h.usd, cash)),
            applying,
        ];
        let mut rows = Vec::new();
        for &(kind, amount) in differences {
            let account = match kind {
                Discount => self.discount,
                Writeoff => self.writeoff,
                BankCharge => self.bank_fee,
            };
            let side = match (direction, kind) {
                (Payment, Discount | Writeoff) => Side::Credit,
                _ => Side::Debit,
            };
            rows.push(ApplicationDifference {
                leg_ordinal: u16::try_from(legs.len()).unwrap(),
                kind,
            });
            legs.push(LegPayload::simple(
                side,
                account,
                Amount::new(self.h.usd, amount),
            ));
        }
        let mut proposal = self.h.proposal(legs, key, EntryClass::ORIGINAL);
        proposal
            .set_application_terms(&ApplicationTerms {
                direction,
                cash_ordinal: 0,
                applying_ordinal: 1,
                differences: rows,
            })
            .unwrap();
        proposal
    }

    fn post(&mut self, proposal: EntryPayload) -> Result<Posted, Refusal> {
        self.h.post(self.h.request(proposal, &["read", "post"]))
    }

    fn reversal(&self, target: EntryRef, key: &[u8]) -> EntryPayload {
        let original = read_entry(&self.h.db, target.vid).unwrap().unwrap().0;
        let mut proposal = self.h.reversal_of_entry(target, key);
        proposal.schema_minor = original.proposal.schema_minor;
        proposal.extensions = original.proposal.extensions;
        proposal
    }

    fn applied(&self, source: Source) -> i128 {
        self.h.applied_to(source.entry.vid, source.ordinal)
    }

    fn refuses_without_writes(
        &mut self,
        proposal: EntryPayload,
        source: Source,
        expected: &str,
        case: &str,
    ) {
        let head = self.h.db.frontier().unwrap();
        let rows = self.h.db.vertices().unwrap();
        let applied = self.applied(source);
        let candidate = entry_vid(
            self.h.book.book_id,
            &proposal.principal_ref.0.to_le_bytes(),
            &proposal.idempotency_key,
        );
        let refusal = self.post(proposal).expect_err(case);
        assert_eq!(refusal.code, expected, "{case}: {refusal}");
        assert_eq!(self.h.db.frontier().unwrap(), head, "{case}");
        assert_eq!(self.h.db.vertices().unwrap(), rows, "{case}");
        assert_eq!(self.applied(source), applied, "{case}");
        assert!(self.h.db.vertex(candidate).unwrap().is_none(), "{case}");
    }
}

fn refold(proposal: &mut EntryPayload) {
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
}

/// Exercise raw proposals, not only the setter's checks.
fn replace_marker(proposal: &mut EntryPayload, terms: &ApplicationTerms) {
    proposal
        .extensions
        .iter_mut()
        .find(|(tag, _)| *tag == APPLICATION_TERMS_EXTENSION)
        .unwrap()
        .1 = terms.encode().unwrap();
}

const MIXED: [(ApplicationDifferenceKind, i128); 3] =
    [(Discount, 200), (Writeoff, 300), (BankCharge, 400)];

#[test]
fn receipt_and_payment_differences_clear_the_declared_principal_not_the_cash_amount() {
    for direction in [Receipt, Payment] {
        for class in [EntryClass::ORIGINAL, EntryClass::ADJUSTING] {
            let mut f = Fixture::new();
            let source = f.source(direction, 10_000, b"mixed-open-item");
            let (cash, total) = match direction {
                Receipt => (9_100, 10_000),
                Payment => (9_900, 10_400),
            };
            let mut proposal = f.application(
                direction,
                source,
                10_000,
                cash,
                &MIXED,
                b"mixed-application",
            );
            proposal.class = class;
            let expected_terms = proposal.application_terms().unwrap().unwrap();
            let posted = f.post(proposal).unwrap().entry_ref();
            let stored = read_entry(&f.h.db, posted.vid).unwrap().unwrap().0.proposal;
            assert_eq!(stored.application_terms().unwrap(), Some(expected_terms));
            assert_eq!(stored.legs.len(), 5);
            assert_eq!(stored.legs[0].amount, Amount::new(f.h.usd, cash));
            assert_eq!(stored.legs[1].amount, Amount::new(f.h.usd, 10_000));
            assert_eq!(
                stored.legs.iter().map(|leg| leg.side).collect::<Vec<_>>(),
                match direction {
                    Receipt => vec![
                        Side::Debit,
                        Side::Credit,
                        Side::Debit,
                        Side::Debit,
                        Side::Debit
                    ],
                    Payment => vec![
                        Side::Credit,
                        Side::Debit,
                        Side::Credit,
                        Side::Credit,
                        Side::Debit
                    ],
                },
            );
            assert_eq!(
                stored
                    .legs
                    .iter()
                    .map(|leg| leg.account_ref)
                    .collect::<Vec<_>>(),
                vec![
                    f.h.cash,
                    if direction == Receipt {
                        f.h.receivable
                    } else {
                        f.payable
                    },
                    f.discount,
                    f.writeoff,
                    f.bank_fee,
                ],
            );
            assert_eq!(
                (stored.unit_totals[0].debits, stored.unit_totals[0].credits),
                (total, total)
            );
            assert_eq!(
                stored.legs[1].settles,
                vec![settle(source.entry, source.ordinal, f.h.usd, 10_000)],
            );
            assert!(
                stored
                    .legs
                    .iter()
                    .enumerate()
                    .all(|(ordinal, leg)| { ordinal == 1 || leg.settles.is_empty() })
            );
            assert_eq!(f.applied(source), 10_000);
            assert_leg_projections(&f.h);
        }
    }
}

#[test]
fn cash_differences_remain_exact_above_the_binary_float_integer_boundary() {
    const PRINCIPAL_AMOUNT: i128 = 9_007_199_254_740_993;
    for direction in [Receipt, Payment] {
        let mut f = Fixture::new();
        let source = f.source(direction, PRINCIPAL_AMOUNT, b"large-open-item");
        let cash = match direction {
            Receipt => PRINCIPAL_AMOUNT.checked_sub(7).unwrap(),
            Payment => PRINCIPAL_AMOUNT.checked_add(7).unwrap(),
        };
        let proposal = f.application(
            direction,
            source,
            PRINCIPAL_AMOUNT,
            cash,
            &[(BankCharge, 7)],
            b"large-application",
        );
        let posted = f.post(proposal).unwrap().entry_ref();
        let stored = read_entry(&f.h.db, posted.vid).unwrap().unwrap().0.proposal;
        assert_eq!(stored.legs[0].amount.mantissa, cash);
        assert_eq!(stored.legs[1].amount.mantissa, PRINCIPAL_AMOUNT);
        assert_eq!(stored.legs[2].amount.mantissa, 7);
        assert_eq!(f.applied(source), PRINCIPAL_AMOUNT);
    }
}

#[test]
fn balanced_raw_proposals_cannot_forge_cash_control_difference_or_application_bindings() {
    for direction in [Receipt, Payment] {
        let mut f = Fixture::new();
        let source = f.source(direction, 10_000, b"forgery-open-item");
        let original = f.application(
            direction,
            source,
            10_000,
            9_000,
            &[(Discount, 1_000)],
            b"forged-application",
        );
        let mut cases = Vec::new();
        let mut bad = original.clone();
        bad.legs[0].account_ref = bad.legs[1].account_ref;
        cases.push(("cash aliases control account", bad));
        let mut bad = original.clone();
        bad.legs[2].account_ref = bad.legs[0].account_ref;
        cases.push(("difference aliases cash account", bad));
        let mut bad = original.clone();
        bad.legs[2].account_ref = bad.legs[1].account_ref;
        cases.push(("difference aliases control account", bad));
        let mut bad = original.clone();
        bad.legs[1].settles[0].amount.mantissa = 9_999;
        cases.push(("principal contains an unexplained unapplied unit", bad));
        let mut bad = original.clone();
        let mut terms = bad.application_terms().unwrap().unwrap();
        std::mem::swap(&mut terms.cash_ordinal, &mut terms.applying_ordinal);
        replace_marker(&mut bad, &terms);
        cases.push(("cash and applying bindings exchanged", bad));
        let mut bad = original.clone();
        let mut terms = bad.application_terms().unwrap().unwrap();
        terms.direction = if direction == Receipt {
            Payment
        } else {
            Receipt
        };
        replace_marker(&mut bad, &terms);
        cases.push(("wrong declared direction", bad));
        let mut bad = original.clone();
        bad.legs[2].side = if bad.legs[2].side == Side::Debit {
            Side::Credit
        } else {
            Side::Debit
        };
        bad.legs[0].amount.mantissa = 11_000;
        refold(&mut bad);
        cases.push(("balanced but economically reversed difference", bad));
        let mut bad = original.clone();
        let foreign = f.h.book.units.lookup("EUR").unwrap();
        for leg in &mut bad.legs {
            leg.amount.unit = foreign;
            for settlement in &mut leg.settles {
                settlement.amount.unit = foreign;
            }
        }
        refold(&mut bad);
        cases.push((
            "a balanced foreign-unit claim is outside the base-unit law",
            bad,
        ));
        if direction == Payment {
            let mut bad = original;
            let mut terms = bad.application_terms().unwrap().unwrap();
            terms.differences[0].kind = BankCharge;
            replace_marker(&mut bad, &terms);
            cases.push(("credit discount relabelled as a debit bank charge", bad));
        }
        for (name, proposal) in cases {
            assert_eq!(
                proposal.unit_totals[0].debits, proposal.unit_totals[0].credits,
                "{name}"
            );
            f.refuses_without_writes(proposal, source, code::SETTLE_SHAPE, name);
        }
    }
}

#[test]
fn raw_markers_must_bind_every_leg_and_use_the_registered_canonical_frame() {
    let mut f = Fixture::new();
    let source = f.source(Receipt, 10_000, b"marker-open-item");
    let original = f.application(Receipt, source, 10_000, 9_100, &MIXED, b"bad-marker");
    let mut cases = Vec::new();
    let mut bad = original.clone();
    let mut terms = bad.application_terms().unwrap().unwrap();
    let _ = terms.differences.pop();
    replace_marker(&mut bad, &terms);
    cases.push(("one difference leg is unclassified", bad));
    let mut bad = original.clone();
    bad.legs.extend([
        LegPayload::simple(Side::Debit, f.h.rent, Amount::new(f.h.usd, 1)),
        LegPayload::simple(Side::Credit, f.h.revenue, Amount::new(f.h.usd, 1)),
    ]);
    refold(&mut bad);
    cases.push(("an unclassified balanced pair cannot be a plug", bad));
    let mut bad = original.clone();
    bad.extensions
        .iter_mut()
        .find(|(tag, _)| *tag == APPLICATION_TERMS_EXTENSION)
        .unwrap()
        .1
        .push(0);
    cases.push(("trailing marker bytes", bad));
    let mut bad = original;
    bad.schema_minor = 8;
    cases.push(("new economic semantics under an older minor", bad));
    for (name, proposal) in cases {
        f.refuses_without_writes(proposal, source, code::STRUCTURE, name);
    }
}

#[test]
fn differences_never_authorize_overapplication_even_when_cash_fits_the_open_item() {
    for direction in [Receipt, Payment] {
        let mut f = Fixture::new();
        let source = f.source(direction, 10_000, b"capacity-open-item");
        let too_much = f.application(
            direction,
            source,
            11_000,
            10_000,
            &[(Discount, 1_000)],
            b"capacity-application",
        );
        f.refuses_without_writes(
            too_much,
            source,
            code::OVER_APPLICATION,
            "cash fits but requested principal exceeds open capacity",
        );
        // A rejected request reserves neither the key nor any open amount.
        let fits = f.application(
            direction,
            source,
            10_000,
            9_000,
            &[(Discount, 1_000)],
            b"capacity-application",
        );
        f.post(fits).unwrap();
        assert_eq!(f.applied(source), 10_000);
    }
}

#[test]
fn retry_preserves_original_terms_and_does_not_apply_the_principal_twice() {
    let mut f = Fixture::new();
    let source = f.source(Receipt, 10_000, b"retry-open-item");
    let proposal = f.application(
        Receipt,
        source,
        6_000,
        5_500,
        &[(Discount, 500)],
        b"retry-application",
    );
    let posted = f.post(proposal.clone()).unwrap();
    let rows = f.h.db.vertices().unwrap();
    let head = f.h.db.frontier().unwrap();
    let retry = f.post(proposal.clone()).unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(f.applied(source), 6_000);
    assert_eq!(f.h.db.frontier().unwrap(), head);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
    let mut changed = proposal;
    let mut terms = changed.application_terms().unwrap().unwrap();
    terms.differences[0].kind = Writeoff;
    replace_marker(&mut changed, &terms);
    let refusal = f.post(changed).unwrap_err();
    assert_eq!(refusal.code, code::IDEMPOTENCY_CONFLICT);
    assert_eq!(f.applied(source), 6_000);
    assert_eq!(f.h.db.frontier().unwrap(), head);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
}

#[test]
fn reversal_requires_exact_inherited_terms_and_reversal_parity_restores_applications() {
    for direction in [Receipt, Payment] {
        let mut f = Fixture::new();
        let source = f.source(direction, 10_000, b"reversal-open-item");
        let cash = if direction == Receipt { 9_100 } else { 9_900 };
        let proposal = f.application(
            direction,
            source,
            10_000,
            cash,
            &MIXED,
            b"reversible-application",
        );
        let original_terms = proposal.application_terms().unwrap().unwrap();
        let application = f.post(proposal.clone()).unwrap().entry_ref();
        let exact = f.reversal(application, b"undo-application");
        assert!(exact.legs.iter().all(|leg| leg.settles.is_empty()));
        let mut dropped = exact.clone();
        dropped
            .extensions
            .retain(|(tag, _)| *tag != APPLICATION_TERMS_EXTENSION);
        let mut changed = exact.clone();
        let mut terms = changed.application_terms().unwrap().unwrap();
        terms.differences[0].kind = Writeoff;
        replace_marker(&mut changed, &terms);
        let mut changed_amounts = exact.clone();
        changed_amounts.legs[0].amount.mantissa = changed_amounts.legs[0]
            .amount
            .mantissa
            .checked_add(1)
            .unwrap();
        changed_amounts.legs[2].amount.mantissa = changed_amounts.legs[2]
            .amount
            .mantissa
            .checked_sub(1)
            .unwrap();
        refold(&mut changed_amounts);
        for (name, bad) in [
            ("dropped economic terms", dropped),
            ("relabeled economic terms", changed),
            (
                "same terms with changed cash and difference",
                changed_amounts,
            ),
        ] {
            let head = f.h.db.frontier().unwrap();
            let rows = f.h.db.vertices().unwrap();
            let refusal = f.post(bad).unwrap_err();
            assert_eq!(refusal.code, code::REVERSAL_SHAPE, "{name}: {refusal}");
            assert_eq!(f.applied(source), 10_000, "{name}");
            assert_eq!(f.h.db.frontier().unwrap(), head, "{name}");
            assert_eq!(f.h.db.vertices().unwrap(), rows, "{name}");
        }
        let undone = f.post(exact.clone()).unwrap().entry_ref();
        assert_eq!(f.applied(source), 0);
        let undo_terms = read_entry(&f.h.db, undone.vid)
            .unwrap()
            .unwrap()
            .0
            .proposal
            .application_terms()
            .unwrap();
        assert_eq!(undo_terms, Some(original_terms.clone()));
        let head = f.h.db.frontier().unwrap();
        assert!(matches!(
            f.post(exact).unwrap(),
            Posted::AlreadyRecorded { .. }
        ));
        assert!(matches!(
            f.post(proposal).unwrap(),
            Posted::AlreadyRecorded { .. }
        ));
        assert_eq!(
            f.applied(source),
            0,
            "retry must not revive a reversed application"
        );
        assert_eq!(f.h.db.frontier().unwrap(), head);
        let revived = f
            .post(f.reversal(undone, b"restore-application"))
            .unwrap()
            .entry_ref();
        assert_eq!(
            read_entry(&f.h.db, revived.vid)
                .unwrap()
                .unwrap()
                .0
                .proposal
                .application_terms()
                .unwrap(),
            Some(original_terms),
        );
        assert_eq!(f.applied(source), 10_000);
        assert_leg_projections(&f.h);
    }
}

#[test]
fn typed_receipt_and_payment_share_one_publication_and_retry_without_reapplication() {
    let mut f = Fixture::new();
    let receivable = f.source(Receipt, 10_000, b"batch-receivable");
    let payable = f.source(Payment, 10_000, b"batch-payable");
    let receipt = f.application(Receipt, receivable, 10_000, 9_100, &MIXED, b"batch-receipt");
    let payment = f.application(Payment, payable, 10_000, 9_900, &MIXED, b"batch-payment");
    let batch = f.h.batch(b"batch-differences", vec![receipt, payment]);
    let before = f.h.db.frontier().unwrap();
    let posted = f.h.post_batch(batch.clone()).unwrap();
    assert_eq!(posted.recorded_at.0, before.0 + 1);
    assert_eq!(posted.entries.len(), 2);
    assert_eq!(
        (f.applied(receivable), f.applied(payable)),
        (10_000, 10_000)
    );
    for entry in &posted.entries {
        let (stored, at) = read_entry(&f.h.db, entry.vid).unwrap().unwrap();
        assert_eq!(at, posted.recorded_at);
        assert!(stored.proposal.application_terms().unwrap().is_some());
    }
    let rows = f.h.db.vertices().unwrap();
    let retry = f.h.post_batch(batch).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, posted.entries);
    assert_eq!(retry.recorded_at, posted.recorded_at);
    assert_eq!(f.h.db.frontier().unwrap(), posted.recorded_at);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
    assert_eq!(
        (f.applied(receivable), f.applied(payable)),
        (10_000, 10_000)
    );
}

#[test]
fn a_later_invalid_difference_application_rolls_back_the_entire_batch_and_staged_sources() {
    for staged_sources in [false, true] {
        let mut f = Fixture::new();
        let mut members = Vec::new();
        let sources = if staged_sources {
            let first = f.h.invoice(10_000, b"rollback-invoice-one");
            let second = f.h.invoice(10_000, b"rollback-invoice-two");
            let sources = [
                Source {
                    entry: f.h.member_ref(&first),
                    ordinal: 0,
                },
                Source {
                    entry: f.h.member_ref(&second),
                    ordinal: 0,
                },
            ];
            members.extend([first, second]);
            sources
        } else {
            [
                f.source(Receipt, 10_000, b"rollback-invoice-one"),
                f.source(Receipt, 10_000, b"rollback-invoice-two"),
            ]
        };
        members.push(f.application(
            Receipt,
            sources[0],
            10_000,
            9_000,
            &[(Discount, 1_000)],
            b"rollback-first",
        ));
        members.push(f.application(
            Receipt,
            sources[1],
            11_000,
            10_000,
            &[(Discount, 1_000)],
            b"rollback-later",
        ));
        let expected_refs: Vec<_> = members.iter().map(|p| f.h.member_ref(p)).collect();
        let batch = f.h.batch(b"rollback-differences", members);
        let outcome = fa_journal::batch::outcome_vid(&f.h.book, &batch);
        let head = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let refusal = f.h.post_batch(batch).unwrap_err();
        assert_eq!(refusal.code, code::OVER_APPLICATION, "{refusal}");
        assert!(refusal.message.contains("member"), "{refusal}");
        assert_eq!(f.h.db.frontier().unwrap(), head);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert!(f.h.db.vertex(outcome).unwrap().is_none());
        for reference in expected_refs {
            assert!(read_entry(&f.h.db, reference.vid).unwrap().is_none());
        }
        if !staged_sources {
            assert_eq!((f.applied(sources[0]), f.applied(sources[1])), (0, 0));
        }
    }
}
