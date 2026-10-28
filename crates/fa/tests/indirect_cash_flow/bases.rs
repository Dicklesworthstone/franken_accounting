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

pub(super) fn loan_fixture(k: i128) -> (Harness, IndirectCashFlowRequest) {
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

pub(super) fn policy_request(h: &Harness) -> IndirectCashFlowRequest {
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

fn reopen(h: Harness) -> Harness {
    let Harness {
        runtime,
        root,
        vfs,
        book,
        usd,
        jpy,
        evidence,
    } = h;
    drop(book);
    let cx = PurposeContexts::narrow_runtime_root(&root);
    let book = runtime
        .block_on(AsyncBook::open_with_vfs(
            &cx,
            vfs.clone(),
            Path::new("indirect-cash-book"),
            BookKeys::for_development(124),
            Entropy::deterministic(126),
        ))
        .unwrap();
    Harness {
        runtime,
        root,
        vfs,
        book,
        usd,
        jpy,
        evidence,
    }
}

fn artifact_status(
    h: &Harness,
    artifact: &fa::ReportArtifact,
    expected: &IndirectCashFlowRequest,
) -> fa::CertificateStatus {
    h.book
        .report_artifact_status(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            &artifact.canonical_bytes().unwrap(),
            Some(artifact.digest()),
            fa::ReportArtifactExpectation::IndirectCashFlow(expected),
        )
        .unwrap()
        .unwrap()
}

fn superseding_keys(
    h: &Harness,
    artifact: &fa::ReportArtifact,
    expected: &IndirectCashFlowRequest,
) -> Vec<Vec<u8>> {
    let fa::CertificateStatus::SupersededBy {
        checked_at,
        later_entries,
        cases,
    } = artifact_status(h, artifact, expected)
    else {
        panic!("later selected journal entries must supersede the historical report");
    };
    assert_eq!(checked_at, h.head());
    assert!(cases.is_empty());
    let mut keys: Vec<_> = later_entries
        .into_iter()
        .map(|id| {
            let (entry, _) = h.book.read_entry(&h.cx(), id).unwrap().unwrap();
            entry.proposal.idempotency_key
        })
        .collect();
    keys.sort();
    keys
}

#[test]
fn split_reasons_and_portions_are_bound_without_changing_original_cash_citations() {
    let (h, expected) = loan_fixture(1);
    let before = h.head();
    let original = certify(&h, &expected);
    let mut permuted = expected.clone();
    permuted.cash.units.reverse();
    let CashFlowBasisDefinition::Split(split) = &mut permuted.cash_definition else {
        unreachable!()
    };
    split.splits.reverse();
    for leg in &mut split.splits {
        leg.portions.reverse();
    }
    assert_eq!(certify(&h, &permuted).certificate(), original.certificate());

    let mut reason = expected.clone();
    let CashFlowBasisDefinition::Split(split) = &mut reason.cash_definition else {
        unreachable!()
    };
    split
        .splits
        .iter_mut()
        .find(|leg| leg.portions.len() == 2)
        .unwrap()
        .reason
        .push_str("; separately reviewed judgment");
    let changed_reason = certify(&h, &reason);
    assert_eq!(changed_reason.report().units(), original.report().units());
    assert_ne!(
        changed_reason.certificate().digest(),
        original.certificate().digest()
    );
    replay_refuses(&h, original.certificate(), &reason);
    replay_refuses(&h, changed_reason.certificate(), &expected);

    // A recipient may select a different non-operating partition that keeps
    // operating cash, net change and closing stock identical. It is still a
    // different statement and may never replace the expected principal split.
    let mut partition = expected.clone();
    let CashFlowBasisDefinition::Split(split) = &mut partition.cash_definition else {
        unreachable!()
    };
    let payment = split
        .splits
        .iter_mut()
        .find(|leg| leg.portions.len() == 2)
        .unwrap();
    payment
        .portions
        .iter_mut()
        .find(|portion| portion.activity == CashFlowActivity::Financing)
        .unwrap()
        .amount = 99;
    payment.portions.push(CashFlowPortion {
        activity: CashFlowActivity::Investing,
        amount: 1,
    });
    let alternative = certify(&h, &partition);
    let usd = alternative
        .report()
        .units()
        .iter()
        .find(|unit| unit.unit_id == h.usd.0)
        .unwrap();
    assert_eq!(
        (
            usd.operating,
            usd.investing,
            usd.financing,
            usd.net_change,
            usd.closing
        ),
        (190, -1, -99, 90, 1090)
    );
    assert_eq!(
        alternative.report().cash().source().lines(),
        original.report().cash().source().lines()
    );
    replay_refuses(&h, original.certificate(), &partition);
    replay_refuses(&h, alternative.certificate(), &expected);

    let mut incomplete = expected.clone();
    let CashFlowBasisDefinition::Split(split) = &mut incomplete.cash_definition else {
        unreachable!()
    };
    split
        .splits
        .iter_mut()
        .find(|leg| leg.portions.len() == 2)
        .unwrap()
        .portions
        .iter_mut()
        .find(|portion| portion.activity == CashFlowActivity::Financing)
        .unwrap()
        .amount = 99;
    let mut altered_interest = expected.clone();
    let CashFlowBasisDefinition::Split(split) = &mut altered_interest.cash_definition else {
        unreachable!()
    };
    let payment = split
        .splits
        .iter_mut()
        .find(|leg| leg.portions.len() == 2)
        .unwrap();
    for portion in &mut payment.portions {
        portion.amount = if portion.activity == CashFlowActivity::Operating {
            11
        } else {
            99
        };
    }
    for invalid in [incomplete, altered_interest] {
        assert!(
            h.book
                .certify_indirect_cash_flow(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read", "produce"]),
                    &invalid,
                )
                .unwrap()
                .is_err(),
            "cash portions must be complete and operating cash must equal the independent earnings bridge"
        );
        replay_refuses(&h, original.certificate(), &invalid);
    }
    assert_eq!(h.head(), before);
}

#[test]
fn retained_policy_and_split_bridges_keep_historical_replay_and_report_backdated_changes_after_reopen()
 {
    use Side::{Credit as C, Debit as D};
    for kind in [CashFlowBasisKind::Policy, CashFlowBasisKind::Split] {
        let (mut h, expected) = if kind == CashFlowBasisKind::Split {
            loan_fixture(1)
        } else {
            let mut h = Harness::new();
            h.scenario(1);
            let request = policy_request(&h);
            (h, request)
        };
        let original = certify(&h, &expected);
        let artifact = fa::ReportArtifact::try_from(original.certificate()).unwrap();
        assert_eq!(
            artifact.family(),
            fa::ReportArtifactFamily::IndirectCashFlow
        );
        let bytes = artifact.canonical_bytes().unwrap();
        let original_head = h.head();
        let cx = h.cx();
        for (principal, capability) in [
            (PRINCIPAL, cap(&["read"])),
            (PRINCIPAL, cap(&["produce"])),
            (VId(2), cap(&["read", "produce"])),
        ] {
            assert!(
                h.runtime
                    .block_on(h.book.retain_report_artifact_for(
                        &cx,
                        principal,
                        &capability,
                        &bytes,
                        Some(artifact.digest()),
                        fa::ReportArtifactExpectation::IndirectCashFlow(&expected),
                    ))
                    .unwrap()
                    .is_err()
            );
            assert_eq!(h.head(), original_head);
        }
        let receipt = h
            .runtime
            .block_on(h.book.retain_report_artifact_for(
                &cx,
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &bytes,
                Some(artifact.digest()),
                fa::ReportArtifactExpectation::IndirectCashFlow(&expected),
            ))
            .unwrap()
            .unwrap();
        assert_eq!(receipt.recorded_at.0, original_head.0 + 1);
        assert_eq!(
            artifact_status(&h, &artifact, &expected),
            fa::CertificateStatus::Current {
                checked_at: h.head()
            }
        );

        let date = if kind == CashFlowBasisKind::Split {
            february(5)
        } else {
            day(8)
        };
        let eur = h.book.context().units.lookup("EUR").unwrap();
        // Neither selected-unit detail nor the income statement changes.
        h.post_on(
            date,
            b"unselected-eur-capital",
            eur,
            &[("1200", D, 7), ("3000", C, 7)],
        );
        assert_eq!(
            artifact_status(&h, &artifact, &expected),
            fa::CertificateStatus::Current {
                checked_at: h.head()
            }
        );
        h.post_on(
            date,
            b"later-depreciation",
            h.usd,
            &[("6100", D, 1), ("1590", C, 1)],
        );
        assert_eq!(
            superseding_keys(&h, &artifact, &expected),
            vec![b"later-depreciation".to_vec()]
        );
        // For February this is before the report interval: it changes opening
        // cash, so the original opening-stock assertion must become stale.
        let cash_date = if kind == CashFlowBasisKind::Split {
            day(20)
        } else {
            day(9)
        };
        h.post_on(
            cash_date,
            b"later-opening-cash",
            h.usd,
            &[("1000", D, 7), ("3000", C, 7)],
        );
        let later_keys = vec![
            b"later-depreciation".to_vec(),
            b"later-opening-cash".to_vec(),
        ];
        assert_eq!(superseding_keys(&h, &artifact, &expected), later_keys);
        let latest_head = h.head();

        h = reopen(h);
        assert_eq!(h.head(), latest_head);
        let stored = h
            .runtime
            .block_on(h.book.read_report_artifact(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                artifact.digest(),
            ))
            .unwrap()
            .unwrap();
        assert_eq!(stored, artifact);
        let replay = h
            .runtime
            .block_on(h.book.replay_retained_report_artifact(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                artifact.digest(),
                fa::ReportArtifactExpectation::IndirectCashFlow(&expected),
            ))
            .unwrap()
            .unwrap();
        assert_eq!(replay.known_at, original_head);
        assert_eq!(replay.output, original.report().canonical_bytes().unwrap());
        assert_eq!(superseding_keys(&h, &stored, &expected), later_keys);

        let mut changed = expected.clone();
        match &mut changed.cash_definition {
            CashFlowBasisDefinition::Policy(policy) => {
                policy
                    .account_rules
                    .iter_mut()
                    .find(|rule| rule.account_id == h.id("2000").0)
                    .unwrap()
                    .activity = CashFlowActivity::Investing;
            }
            CashFlowBasisDefinition::Split(split) => {
                split.splits[0]
                    .reason
                    .push_str("; substituted recipient definition");
            }
            CashFlowBasisDefinition::Explicit(_) => unreachable!(),
        }
        assert!(
            h.runtime
                .block_on(h.book.replay_retained_report_artifact(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read"]),
                    artifact.digest(),
                    fa::ReportArtifactExpectation::IndirectCashFlow(&changed),
                ))
                .unwrap()
                .is_err()
        );
        assert!(
            h.book
                .report_artifact_status(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read"]),
                    &bytes,
                    Some(artifact.digest()),
                    fa::ReportArtifactExpectation::IndirectCashFlow(&changed),
                )
                .unwrap()
                .is_err()
        );
        for (principal, capability) in [(PRINCIPAL, cap(&["produce"])), (VId(2), cap(&["read"]))] {
            assert!(
                h.runtime
                    .block_on(h.book.replay_retained_report_artifact(
                        &h.cx(),
                        principal,
                        &capability,
                        artifact.digest(),
                        fa::ReportArtifactExpectation::IndirectCashFlow(&expected),
                    ))
                    .unwrap()
                    .is_err()
            );
            assert!(
                h.book
                    .report_artifact_status(
                        &h.cx(),
                        principal,
                        &capability,
                        &bytes,
                        Some(artifact.digest()),
                        fa::ReportArtifactExpectation::IndirectCashFlow(&expected),
                    )
                    .unwrap()
                    .is_err()
            );
        }
        assert_eq!(h.head(), latest_head);
    }
}

fn reseal_indirect_delivery(bytes: &mut [u8], domain: &[u8]) {
    let body_len = bytes.len() - 32;
    let digest = fa_model::domain_digest(domain, &[&bytes[..body_len]]);
    bytes[body_len..].copy_from_slice(&digest);
}

#[test]
fn v2_native_deliveries_reject_wrong_family_framing_and_resealed_false_results() {
    for kind in [CashFlowBasisKind::Policy, CashFlowBasisKind::Split] {
        let (mut h, expected) = if kind == CashFlowBasisKind::Split {
            loan_fixture(1)
        } else {
            let mut h = Harness::new();
            h.scenario(1);
            let request = policy_request(&h);
            (h, request)
        };
        let original = certify(&h, &expected);
        let bytes = original.certificate().canonical_bytes().unwrap();
        let format = b"fa:indirect-cash-flow-certificate:v2";
        let kind_offset = 4 + format.len();
        assert_eq!(&bytes[4..kind_offset], format);
        assert_eq!(bytes[kind_offset], kind as u8);
        for cut in [
            0,
            4,
            kind_offset,
            kind_offset + 1,
            kind_offset + 5,
            bytes.len() - 1,
        ] {
            assert!(IndirectCashFlowCertificate::decode(&bytes[..cut]).is_err());
        }
        for tag in [
            0,
            3,
            255,
            if kind == CashFlowBasisKind::Policy {
                2
            } else {
                1
            },
        ] {
            let mut wrong = bytes.clone();
            wrong[kind_offset] = tag;
            reseal_indirect_delivery(&mut wrong, b"fa:indirect-cash-flow-certificate-digest:v2");
            assert!(
                IndirectCashFlowCertificate::decode(&wrong).is_err(),
                "an intact nested certificate must agree with its outer kind"
            );
        }
        let mut length = bytes.clone();
        length[kind_offset + 1..kind_offset + 5].copy_from_slice(&u32::MAX.to_le_bytes());
        reseal_indirect_delivery(&mut length, b"fa:indirect-cash-flow-certificate-digest:v2");
        assert!(IndirectCashFlowCertificate::decode(&length).is_err());
        let mut downgraded = bytes.clone();
        downgraded[kind_offset - 1] = b'1';
        downgraded.remove(kind_offset);
        reseal_indirect_delivery(
            &mut downgraded,
            b"fa:indirect-cash-flow-certificate-digest:v1",
        );
        assert!(
            IndirectCashFlowCertificate::decode(&downgraded).is_err(),
            "a full policy or split source cannot impersonate an explicit v1 source"
        );

        let mut forged = bytes;
        let body_len = forged.len() - 32;
        // Alter the last native closing amount only. Source family output and
        // income/source headers stay intact, so local framing still succeeds.
        forged[body_len - 1] ^= 1;
        reseal_indirect_delivery(&mut forged, b"fa:indirect-cash-flow-certificate-digest:v2");
        let decoded = IndirectCashFlowCertificate::decode(&forged).unwrap();
        assert_ne!(decoded.output(), original.certificate().output());
        let before = h.head();
        let refusal = h
            .book
            .replay_indirect_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read"]), &decoded, &expected)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, "FA-REF-150");
        assert_eq!(refusal.exit, 8);
        let artifact = fa::ReportArtifact::try_from(&decoded).unwrap();
        assert_eq!(
            artifact.family(),
            fa::ReportArtifactFamily::IndirectCashFlow
        );
        let cx = h.cx();
        assert!(
            h.runtime
                .block_on(h.book.retain_report_artifact_for(
                    &cx,
                    PRINCIPAL,
                    &cap(&["read", "produce"]),
                    &forged,
                    Some(artifact.digest()),
                    fa::ReportArtifactExpectation::IndirectCashFlow(&expected),
                ))
                .unwrap()
                .is_err(),
            "correctly hashed false output must not acquire a retained root"
        );
        assert!(
            h.book
                .report_artifact_status(
                    &cx,
                    PRINCIPAL,
                    &cap(&["read"]),
                    &forged,
                    Some(artifact.digest()),
                    fa::ReportArtifactExpectation::IndirectCashFlow(&expected),
                )
                .unwrap()
                .is_err()
        );
        assert_eq!(h.head(), before);
    }
}
