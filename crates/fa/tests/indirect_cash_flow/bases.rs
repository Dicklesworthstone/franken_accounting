//! Native earnings-to-cash regressions for complete policy and split bases.
//! Expected amounts come from literal journal events, independently of the
//! source report's calculations or certificate delivery.

use super::*;
use fa::cash_flow_policy::{CashFlowAccountRule, CashFlowDecisionBasis, CashFlowPolicy};
use fa::cash_flow_split::{CashFlowLegSplit, CashFlowPortion, CashFlowSplitDefinition};
use fa::indirect_cash_flow::{
    CertifiedIndirectCashFlow, INDIRECT_CASH_FLOW_FORMAT, INDIRECT_CASH_FLOW_FORMAT_V2,
    IndirectCashFlowCertificate,
};
use fa::{CashFlowBasis, CashFlowBasisCertificate, CashFlowBasisKind};

fn february(day: u8) -> DateDay {
    DateDay::from_ymd(2026, 2, day).unwrap()
}

fn certify(h: &Harness, request: &IndirectCashFlowRequest) -> CertifiedIndirectCashFlow {
    h.book
        .certify_indirect_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), request)
        .unwrap()
        .unwrap()
}

fn replay_refuses(
    h: &Harness,
    certificate: &IndirectCashFlowCertificate,
    expected: &IndirectCashFlowRequest,
) {
    let before = h.head();
    assert!(
        h.book
            .replay_indirect_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), certificate, expected)
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), before);
}

fn loan_fixture(k: i128) -> (Harness, IndirectCashFlowRequest) {
    use Side::{Credit as C, Debit as D};
    let mut h = Harness::new();
    h.post(
        1,
        b"loan-funding-before-report-month",
        h.usd,
        &[("1000", D, 1000 * k), ("2000", C, 1000 * k)],
    );
    let cx = h.cx();
    h.runtime
        .block_on(h.book.transition_period(
            &cx,
            "FY2026-P02",
            PeriodTransition::Open,
            PRINCIPAL,
            2,
            b"indirect-open-february",
            &cap(&["close"]),
        ))
        .unwrap()
        .unwrap();
    h.post_on(
        february(2),
        b"customer-cash-revenue",
        h.usd,
        &[("1000", D, 200 * k), ("4000", C, 200 * k)],
    );
    // One original bank leg pays two different activities. Neither the journal
    // nor the indirect workpaper may manufacture two replacement cash legs.
    h.post_on(
        february(3),
        b"principal-and-interest-one-payment",
        h.usd,
        &[
            ("2000", D, 100 * k),
            ("6000", D, 10 * k),
            ("1000", C, 110 * k),
        ],
    );
    h.post_on(
        february(4),
        b"february-depreciation",
        h.usd,
        &[("6100", D, 20 * k), ("1590", C, 20 * k)],
    );
    let cash = RollForwardRequest {
        accounts: vec![h.id("1000")],
        units: vec![h.usd.0, h.jpy.0],
        label: "February operating cash and loan repayment".into(),
        effective_from: february(1),
        effective_through: february(28),
        known_at: Some(h.head()),
    };
    let ledger = h
        .book
        .general_ledger(&h.cx(), PRINCIPAL, &cap(&["read"]), &cash)
        .unwrap()
        .unwrap();
    assert_eq!(ledger.lines().len(), 2);
    let cash_definition = CashFlowSplitDefinition {
        name: "Loan principal financing; interest operating".into(),
        cash_accounts: vec![h.id("1000").0],
        splits: ledger
            .lines()
            .iter()
            .map(|line| CashFlowLegSplit {
                entry_digest: line.entry_digest,
                leg_index: line.leg_index,
                reason: if line.effective_day == february(2) {
                    "Cash revenue receipt".into()
                } else {
                    assert_eq!(line.effective_day, february(3));
                    "Loan agreement: principal 100, interest 10".into()
                },
                portions: if line.effective_day == february(2) {
                    vec![CashFlowPortion {
                        activity: CashFlowActivity::Operating,
                        amount: 200 * k,
                    }]
                } else {
                    vec![
                        CashFlowPortion {
                            activity: CashFlowActivity::Financing,
                            amount: 100 * k,
                        },
                        CashFlowPortion {
                            activity: CashFlowActivity::Operating,
                            amount: 10 * k,
                        },
                    ]
                },
            })
            .collect(),
    };
    let expense = RollForwardRequest {
        accounts: vec![h.id("6100")],
        ..cash.clone()
    };
    let depreciation = h
        .book
        .general_ledger(&h.cx(), PRINCIPAL, &cap(&["read"]), &expense)
        .unwrap()
        .unwrap();
    assert_eq!(depreciation.lines().len(), 1);
    let line = &depreciation.lines()[0];
    let request = IndirectCashFlowRequest {
        cash,
        cash_definition: CashFlowBasisDefinition::Split(cash_definition),
        income_periods: vec!["FY2026-P02".into()],
        definition: IndirectCashFlowDefinition {
            name: "February earnings plus noncash depreciation".into(),
            adjustments: vec![IndirectCashFlowAdjustment {
                entry_digest: line.entry_digest,
                leg_index: line.leg_index,
                category: AdjustmentCategory::NonCash,
                sign: AdjustmentSign::DebitMinusCredit,
                reason: "Depreciation expense has no cash movement".into(),
            }],
        },
    };
    (h, request)
}

fn policy_request(h: &Harness) -> IndirectCashFlowRequest {
    let mut request = h.request();
    let ledger = h
        .book
        .general_ledger(&h.cx(), PRINCIPAL, &cap(&["read"]), &request.cash)
        .unwrap()
        .unwrap();
    let disposal = ledger
        .lines()
        .iter()
        .find(|line| line.effective_day == day(7))
        .unwrap();
    request.cash_definition = CashFlowBasisDefinition::Policy(CashFlowPolicy {
        name: "Cash classification v1".into(),
        cash_accounts: vec![h.id("1000").0],
        account_rules: [
            ("3000", CashFlowActivity::Financing),
            ("1500", CashFlowActivity::Investing),
            ("1200", CashFlowActivity::Operating),
            ("6000", CashFlowActivity::Operating),
            ("1590", CashFlowActivity::Investing),
            ("4100", CashFlowActivity::Operating),
            // There is no loan payment in this scenario. The unused rule still
            // belongs to the independently selected policy and its identity.
            ("2000", CashFlowActivity::Financing),
        ]
        .into_iter()
        .map(|(account, activity)| CashFlowAccountRule {
            account_id: h.id(account).0,
            activity,
        })
        .collect(),
        overrides: vec![CashFlowAssignment {
            entry_digest: disposal.entry_digest,
            leg_index: disposal.leg_index,
            activity: CashFlowActivity::Investing,
        }],
    });
    request
}

#[test]
fn one_bank_leg_preserves_principal_interest_and_literal_indirect_totals() {
    for k in [1, (1i128 << 80) + 17] {
        let (h, expected) = loan_fixture(k);
        let before = h.head();
        let mut at_head = expected.clone();
        at_head.cash.known_at = None;
        let original = certify(&h, &at_head);
        assert_eq!(original.certificate().known_at(), before);
        assert_eq!(
            original
                .certificate()
                .source_certificate()
                .request()
                .known_at,
            Some(before)
        );
        let report = original.report();
        assert_eq!(report.format(), INDIRECT_CASH_FLOW_FORMAT_V2);
        assert_eq!(report.cash().kind(), CashFlowBasisKind::Split);
        let CashFlowBasis::Split(cash) = report.cash() else {
            panic!("the split source family must survive the indirect bridge");
        };
        assert_eq!(cash.source().lines().len(), 2);
        let bank_leg = cash
            .source()
            .lines()
            .iter()
            .find(|line| line.effective_day == february(3))
            .unwrap();
        assert_eq!((bank_leg.debits, bank_leg.credits), (0, 110 * k));
        let payment = cash
            .definition()
            .splits
            .iter()
            .filter(|split| {
                (split.entry_digest, split.leg_index) == (bank_leg.entry_digest, bank_leg.leg_index)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            payment.len(),
            1,
            "one split cites the one original bank leg"
        );
        assert_eq!(payment[0].portions.len(), 2);
        for (activity, amount) in [
            (CashFlowActivity::Operating, 10 * k),
            (CashFlowActivity::Financing, 100 * k),
        ] {
            assert!(
                payment[0]
                    .portions
                    .contains(&CashFlowPortion { activity, amount })
            );
        }
        let usd = report
            .units()
            .iter()
            .find(|u| u.unit_id == h.usd.0)
            .unwrap();
        assert_eq!(
            (
                usd.net_income,
                usd.non_cash,
                usd.working_capital,
                usd.non_operating
            ),
            (170 * k, 20 * k, 0, 0)
        );
        assert_eq!(
            (usd.operating, usd.direct_operating, usd.operating_residual),
            (190 * k, 190 * k, 0)
        );
        assert_eq!(
            (
                usd.opening,
                usd.investing,
                usd.financing,
                usd.exchange_effects,
                usd.net_change,
                usd.closing
            ),
            (1000 * k, 0, -100 * k, 0, 90 * k, 1090 * k)
        );
        let direct = cash.units().iter().find(|u| u.unit_id == h.usd.0).unwrap();
        assert_eq!(
            (
                direct.operating.inflows,
                direct.operating.outflows,
                direct.operating.net
            ),
            (200 * k, 10 * k, 190 * k)
        );
        assert_eq!(
            (
                direct.financing.inflows,
                direct.financing.outflows,
                direct.financing.net
            ),
            (0, 100 * k, -100 * k)
        );
        let zero = report
            .units()
            .iter()
            .find(|u| u.unit_id == h.jpy.0)
            .unwrap();
        assert_eq!(
            (
                zero.net_income,
                zero.non_cash,
                zero.operating,
                zero.financing,
                zero.opening,
                zero.net_change,
                zero.closing
            ),
            (0, 0, 0, 0, 0, 0, 0)
        );
        let decoded =
            IndirectCashFlowCertificate::decode(&original.certificate().canonical_bytes().unwrap())
                .unwrap();
        assert!(matches!(
            decoded.source_certificate(),
            CashFlowBasisCertificate::Split(_)
        ));
        let Harness {
            runtime,
            root,
            vfs,
            book,
            ..
        } = h;
        drop(book);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let reopened = runtime
            .block_on(AsyncBook::open_with_vfs(
                &cx,
                vfs,
                Path::new("indirect-cash-book"),
                BookKeys::for_development(124),
                Entropy::deterministic(125),
            ))
            .unwrap();
        let replayed = reopened
            .replay_indirect_cash_flow(&cx, PRINCIPAL, &cap(&["read"]), &decoded, &expected)
            .unwrap()
            .unwrap();
        assert_eq!(&replayed, report);
        assert_eq!(reopened.head(&cx).unwrap(), before);
    }
}

#[test]
fn equal_section_totals_never_authorize_substitution_of_a_different_source_family() {
    let mut h = Harness::new();
    h.scenario(1);
    let explicit = h.request();
    let policy = policy_request(&h);
    let direct = h
        .book
        .cash_flow(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            &explicit.cash,
            explicit_definition(&explicit.cash_definition),
        )
        .unwrap()
        .unwrap();
    let definition = explicit_definition(&explicit.cash_definition);
    let split = IndirectCashFlowRequest {
        cash_definition: CashFlowBasisDefinition::Split(CashFlowSplitDefinition {
            name: definition.name.clone(),
            cash_accounts: definition.cash_accounts.clone(),
            splits: definition
                .assignments
                .iter()
                .map(|assignment| {
                    let line = direct
                        .source()
                        .lines()
                        .iter()
                        .find(|line| {
                            (line.entry_digest, line.leg_index)
                                == (assignment.entry_digest, assignment.leg_index)
                        })
                        .unwrap();
                    CashFlowLegSplit {
                        entry_digest: assignment.entry_digest,
                        leg_index: assignment.leg_index,
                        reason: "Independent whole-leg portion classification".into(),
                        portions: vec![CashFlowPortion {
                            activity: assignment.activity,
                            amount: line.debits + line.credits,
                        }],
                    }
                })
                .collect(),
        }),
        ..explicit.clone()
    };
    let requests = [explicit, policy, split];
    let certificates: Vec<_> = requests
        .iter()
        .map(|request| certify(&h, request))
        .collect();
    assert_eq!(certificates[0].report().format(), INDIRECT_CASH_FLOW_FORMAT);
    assert_eq!(
        certificates[1].report().format(),
        INDIRECT_CASH_FLOW_FORMAT_V2
    );
    assert_eq!(
        certificates[2].report().format(),
        INDIRECT_CASH_FLOW_FORMAT_V2
    );
    for (index, original) in certificates.iter().enumerate() {
        assert_eq!(original.report().units(), certificates[0].report().units());
        for (other, expected) in requests.iter().enumerate() {
            if index != other {
                assert_ne!(
                    original.certificate().digest(),
                    certificates[other].certificate().digest()
                );
                replay_refuses(&h, original.certificate(), expected);
            }
        }
    }
}

#[test]
fn unused_policy_rules_and_redundant_overrides_remain_independent_replay_inputs() {
    let mut h = Harness::new();
    h.scenario(1);
    let expected = policy_request(&h);
    let original = certify(&h, &expected);
    let CashFlowBasis::Policy(cash) = original.report().cash() else {
        panic!("the indirect source must retain policy derivation");
    };
    assert_eq!(cash.policy().account_rules.len(), 7);
    assert_eq!(cash.policy().overrides.len(), 1);
    assert_eq!(cash.decisions().len(), cash.report().source().lines().len());
    assert_eq!(
        cash.decisions()
            .iter()
            .filter(|d| d.basis == CashFlowDecisionBasis::ExplicitOverride)
            .count(),
        1
    );
    assert_eq!(
        cash.decisions()
            .iter()
            .filter(|d| d.basis == CashFlowDecisionBasis::AccountRules)
            .count(),
        4
    );
    let receipt = cash
        .report()
        .source()
        .lines()
        .iter()
        .find(|line| line.effective_day == day(4))
        .unwrap();
    let mut unused_rule = expected.clone();
    let CashFlowBasisDefinition::Policy(policy) = &mut unused_rule.cash_definition else {
        unreachable!()
    };
    policy
        .account_rules
        .iter_mut()
        .find(|rule| rule.account_id == h.id("2000").0)
        .unwrap()
        .activity = CashFlowActivity::Investing;
    let mut redundant_override = expected.clone();
    let CashFlowBasisDefinition::Policy(policy) = &mut redundant_override.cash_definition else {
        unreachable!()
    };
    policy.overrides.push(CashFlowAssignment {
        entry_digest: receipt.entry_digest,
        leg_index: receipt.leg_index,
        activity: CashFlowActivity::Operating,
    });
    for changed in [unused_rule, redundant_override] {
        let alternative = certify(&h, &changed);
        assert_eq!(alternative.report().units(), original.report().units());
        assert_ne!(
            alternative.certificate().digest(),
            original.certificate().digest()
        );
        replay_refuses(&h, original.certificate(), &changed);
        replay_refuses(&h, alternative.certificate(), &expected);
    }
    let mut missing_override = expected.clone();
    let CashFlowBasisDefinition::Policy(policy) = &mut missing_override.cash_definition else {
        unreachable!()
    };
    policy.overrides.clear();
    assert!(
        h.book
            .indirect_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &missing_override)
            .unwrap()
            .is_err(),
        "mixed disposal counterparts still require the explicit override"
    );
    let mut out_of_scope = expected;
    let CashFlowBasisDefinition::Policy(policy) = &mut out_of_scope.cash_definition else {
        unreachable!()
    };
    policy.overrides.push(CashFlowAssignment {
        entry_digest: out_of_scope.definition.adjustments[0].entry_digest,
        leg_index: out_of_scope.definition.adjustments[0].leg_index,
        activity: CashFlowActivity::Operating,
    });
    assert!(
        h.book
            .certify_indirect_cash_flow(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &out_of_scope
            )
            .unwrap()
            .is_err(),
        "an unused noncash override may not be silently dropped"
    );
    replay_refuses(&h, original.certificate(), &out_of_scope);
}
