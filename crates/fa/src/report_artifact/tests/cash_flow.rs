use super::*;
use crate::{
    CashFlowActivity, CashFlowAssignment, CashFlowDefinition, IndirectCashFlowDefinition,
    IndirectCashFlowRequest, ReportArtifactExpectation,
};

struct CashFixture {
    direct: ReportArtifact,
    indirect: ReportArtifact,
    expected: IndirectCashFlowRequest,
}

impl CashFixture {
    fn new(h: &Harness) -> Self {
        let cx = h.cx();
        let at = h.head();
        let request = RollForwardRequest {
            accounts: vec![h.id("1000")],
            units: vec![h.unit.0],
            label: "January funding".into(),
            effective_from: day(1),
            effective_through: day(31),
            known_at: Some(at),
        };
        // The recipient fixes expectations from its own source observation,
        // not by decoding a later certificate delivery.
        let ledger = h
            .book
            .general_ledger(&cx, PRINCIPAL, &cap(&["read"]), &request)
            .unwrap()
            .unwrap();
        assert_eq!(ledger.lines().len(), 1);
        let definition = CashFlowDefinition {
            name: "Capital receipts are financing".into(),
            cash_accounts: vec![h.id("1000").0],
            assignments: ledger
                .lines()
                .iter()
                .map(|line| CashFlowAssignment {
                    entry_digest: line.entry_digest,
                    leg_index: line.leg_index,
                    activity: CashFlowActivity::Financing,
                })
                .collect(),
        };
        // Include all overlapping historical periods, including Opening.
        // A normal period covering those dates does not replace a special one.
        let income_periods = h
            .book
            .query(&cx, |db, _| {
                let mut periods = Vec::new();
                for row in db.vertices_at(at).map_err(KernelError::from)? {
                    if row.labels.contains(&fa_model::symbols::label::PERIOD) {
                        let period = fa_journal::rows::PeriodRow::decode(&row)?;
                        if period.start <= day(31) && period.end > day(1) {
                            periods.push(period.code);
                        }
                    }
                }
                periods.sort();
                Ok(periods)
            })
            .unwrap();
        let expected = IndirectCashFlowRequest {
            cash: request,
            cash_definition: definition,
            income_periods,
            definition: IndirectCashFlowDefinition {
                name: "No operating income or adjustments".into(),
                adjustments: Vec::new(),
            },
        };
        let direct = h
            .book
            .certify_cash_flow(
                &cx,
                PRINCIPAL,
                &cap(&["read", "produce"]),
                &expected.cash,
                &expected.cash_definition,
            )
            .unwrap()
            .unwrap();
        let indirect = h
            .book
            .certify_indirect_cash_flow(&cx, PRINCIPAL, &cap(&["read", "produce"]), &expected)
            .unwrap()
            .unwrap();
        assert_eq!(indirect.report().units().len(), 1);
        let amounts = &indirect.report().units()[0];
        assert_eq!(
            (amounts.operating, amounts.financing, amounts.closing),
            (0, 100, 100)
        );
        assert_eq!(amounts.operating_residual, 0);
        assert_eq!(h.head(), at);
        Self {
            direct: ReportArtifact::try_from(direct.certificate()).unwrap(),
            indirect: ReportArtifact::try_from(indirect.certificate()).unwrap(),
            expected,
        }
    }

    fn expectation(&self, family: ReportArtifactFamily) -> ReportArtifactExpectation<'_> {
        match family {
            ReportArtifactFamily::CashFlow => ReportArtifactExpectation::CashFlow {
                request: &self.expected.cash,
                definition: &self.expected.cash_definition,
            },
            ReportArtifactFamily::IndirectCashFlow => {
                ReportArtifactExpectation::IndirectCashFlow(&self.expected)
            }
            _ => panic!("cash fixture only"),
        }
    }
}

#[test]
fn direct_and_indirect_reports_use_the_same_dispatch_and_keep_the_original_prefix() {
    let mut h = Harness::new(81);
    let fixture = CashFixture::new(&h);
    let original = h.head();
    h.post(b"later funding", 17);
    let head = h.head();
    for artifact in [&fixture.direct, &fixture.indirect] {
        let bytes = artifact.canonical_bytes().unwrap();
        assert_eq!(&ReportArtifact::decode(&bytes).unwrap(), artifact);
        let replay = h
            .book
            .replay_report_artifact_for(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &bytes,
                Some(artifact.digest()),
                fixture.expectation(artifact.family()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(replay.family, artifact.family());
        assert_eq!(replay.known_at, original);
        assert_eq!(replay.output, artifact.output());
        assert_eq!(replay.certificate_digest, *artifact.digest());
        assert_eq!(h.head(), head);
    }
}

#[test]
fn matching_digest_never_replaces_independent_cash_scope_or_classification() {
    let h = Harness::new(82);
    let fixture = CashFixture::new(&h);
    let head = h.head();
    let bytes = fixture.direct.canonical_bytes().unwrap();
    // Even the exact digest does not enable the legacy AsSupplied route.
    for artifact in [&fixture.direct, &fixture.indirect] {
        assert!(
            h.book
                .replay_report_artifact(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read"]),
                    &artifact.canonical_bytes().unwrap(),
                    Some(artifact.digest()),
                )
                .unwrap()
                .is_err()
        );
    }
    for mutate in 0..4 {
        let mut request = fixture.expected.cash.clone();
        let mut definition = fixture.expected.cash_definition.clone();
        match mutate {
            0 => request.known_at = None,
            1 => request.label.push_str(" changed"),
            2 => definition.assignments[0].activity = CashFlowActivity::Investing,
            _ => definition.name.push_str(" changed"),
        }
        assert!(
            h.book
                .replay_report_artifact_for(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read"]),
                    &bytes,
                    Some(fixture.direct.digest()),
                    ReportArtifactExpectation::CashFlow {
                        request: &request,
                        definition: &definition
                    },
                )
                .unwrap()
                .is_err()
        );
    }
    let indirect = fixture.indirect.canonical_bytes().unwrap();
    for mutate in 0..3 {
        let mut request = fixture.expected.clone();
        match mutate {
            0 => request.cash.known_at = None,
            1 => request.definition.name.push_str(" changed"),
            _ => {
                request.income_periods.clear();
            }
        }
        assert!(
            h.book
                .replay_report_artifact_for(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read"]),
                    &indirect,
                    Some(fixture.indirect.digest()),
                    ReportArtifactExpectation::IndirectCashFlow(&request),
                )
                .unwrap()
                .is_err()
        );
    }
    // Expectations for another family are never silently ignored.
    assert!(
        h.book
            .replay_report_artifact_for(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &indirect,
                None,
                fixture.expectation(ReportArtifactFamily::CashFlow),
            )
            .unwrap()
            .is_err()
    );
    let refusal = h
        .book
        .replay_report_artifact_for(
            &h.cx(),
            PRINCIPAL,
            &cap(&["post"]),
            b"malformed",
            None,
            fixture.expectation(ReportArtifactFamily::CashFlow),
        )
        .unwrap()
        .unwrap_err();
    assert_ne!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
    assert_eq!(h.head(), head);
}

#[test]
fn repaired_cash_output_hashes_cannot_bypass_native_replay() {
    let h = Harness::new(83);
    let fixture = CashFixture::new(&h);
    let head = h.head();
    for (artifact, domain) in [
        (
            &fixture.direct,
            b"fa:cash-flow-certificate-digest:v1".as_slice(),
        ),
        (
            &fixture.indirect,
            b"fa:indirect-cash-flow-certificate-digest:v1".as_slice(),
        ),
    ] {
        let mut bytes = artifact.canonical_bytes().unwrap();
        let end = bytes.len() - 32;
        bytes[end - 1] ^= 1;
        let digest = domain_digest(domain, &[&bytes[..end]]);
        bytes[end..].copy_from_slice(&digest);
        assert!(
            ReportArtifact::decode(&bytes).is_ok(),
            "reach native replay, not digest refusal"
        );
        assert!(
            h.book
                .replay_report_artifact_for(
                    &h.cx(),
                    PRINCIPAL,
                    &cap(&["read"]),
                    &bytes,
                    None,
                    fixture.expectation(artifact.family()),
                )
                .unwrap()
                .is_err()
        );
    }
    assert_eq!(h.head(), head);
}

#[test]
fn retained_cash_artifacts_still_require_independent_classifications_on_every_replay() {
    let mut h = Harness::new(97);
    let fixture = CashFixture::new(&h);
    let original = h.head();
    for artifact in [&fixture.direct, &fixture.indirect] {
        let cx = h.cx();
        let bytes = artifact.canonical_bytes().unwrap();
        let before = h.head();
        assert!(h.runtime.block_on(h.book.retain_report_artifact(
            &cx, PRINCIPAL, &cap(&["read", "produce"]), &bytes, Some(artifact.digest()),
        )).unwrap().is_err());
        assert_eq!(h.head(), before);
        let mut wrong = fixture.expected.clone();
        wrong.cash_definition.assignments[0].activity = CashFlowActivity::Investing;
        let wrong = if artifact.family() == ReportArtifactFamily::CashFlow {
            ReportArtifactExpectation::CashFlow { request: &wrong.cash, definition: &wrong.cash_definition }
        } else {
            ReportArtifactExpectation::IndirectCashFlow(&wrong)
        };
        assert!(h.runtime.block_on(h.book.retain_report_artifact_for(
            &cx, PRINCIPAL, &cap(&["read", "produce"]), &bytes, Some(artifact.digest()), wrong,
        )).unwrap().is_err());
        assert_eq!(h.head(), before);
        let receipt = h.runtime.block_on(h.book.retain_report_artifact_for(
            &cx, PRINCIPAL, &cap(&["read", "produce"]), &bytes, Some(artifact.digest()), fixture.expectation(artifact.family()),
        )).unwrap().unwrap();
        assert_eq!(receipt.recorded_at.0, before.0 + 1);
        assert_eq!(h.runtime.block_on(h.book.read_report_artifact(
            &cx, PRINCIPAL, &cap(&["read"]), artifact.digest(),
        )).unwrap().unwrap(), *artifact);
        assert!(h.runtime.block_on(h.book.replay_retained_report_artifact(
            &cx, PRINCIPAL, &cap(&["read"]), artifact.digest(), ReportArtifactExpectation::AsSupplied,
        )).unwrap().is_err());
        let replay = h.runtime.block_on(h.book.replay_retained_report_artifact(
            &cx, PRINCIPAL, &cap(&["read"]), artifact.digest(), fixture.expectation(artifact.family()),
        )).unwrap().unwrap();
        assert_eq!(replay.known_at, original);
        assert_eq!(replay.output, artifact.output());
        assert_eq!(h.head(), receipt.recorded_at);
        assert_eq!(h.runtime.block_on(h.book.retain_report_artifact_for(
            &cx, PRINCIPAL, &cap(&["read", "produce"]), &bytes, Some(artifact.digest()), fixture.expectation(artifact.family()),
        )).unwrap().unwrap(), receipt);
        assert_eq!(h.head(), receipt.recorded_at);
    }
}


#[test]
fn policy_and_split_cash_artifacts_retain_full_definitions_and_replay_original_history() {
    use crate::cash_flow_policy::{CashFlowAccountRule, CashFlowPolicy};
    use crate::cash_flow_split::{CashFlowLegSplit, CashFlowPortion, CashFlowSplitDefinition};

    let mut h = Harness::new(85);
    let fixture = CashFixture::new(&h);
    let request = &fixture.expected.cash;
    let assignment = &fixture.expected.cash_definition.assignments[0];
    let policy = CashFlowPolicy {
        name: "Funding policy".into(),
        cash_accounts: vec![h.id("1000").0],
        account_rules: vec![CashFlowAccountRule {
            account_id: h.id("3000").0,
            activity: CashFlowActivity::Financing,
        }],
        overrides: Vec::new(),
    };
    let split = CashFlowSplitDefinition {
        name: "Recipient-approved split".into(),
        cash_accounts: vec![h.id("1000").0],
        splits: vec![CashFlowLegSplit {
            entry_digest: assignment.entry_digest,
            leg_index: assignment.leg_index,
            reason: "Declared allocation of this receipt".into(),
            portions: vec![
                CashFlowPortion { activity: CashFlowActivity::Operating, amount: 40 },
                CashFlowPortion { activity: CashFlowActivity::Financing, amount: 60 },
            ],
        }],
    };
    let cx = h.cx();
    let authority = cap(&["read", "produce"]);
    let policy_report = h.book.certify_cash_flow_with_policy(
        &cx, PRINCIPAL, &authority, request, &policy,
    ).unwrap().unwrap();
    let split_report = h.book.certify_split_cash_flow(
        &cx, PRINCIPAL, &authority, request, &split,
    ).unwrap().unwrap();
    let policy_artifact = ReportArtifact::try_from(policy_report.certificate()).unwrap();
    let split_artifact = ReportArtifact::try_from(split_report.certificate()).unwrap();
    assert_eq!(policy_artifact.family(), ReportArtifactFamily::PolicyCashFlow);
    assert_eq!(split_artifact.family(), ReportArtifactFamily::SplitCashFlow);
    assert_eq!(policy_artifact.output(), policy_report.report().canonical_bytes().unwrap());
    assert_ne!(policy_artifact.output(), policy_report.certificate().source_certificate().output(),
        "policy and derivation decisions are part of the complete report output");
    for (artifact, expected) in [
        (&policy_artifact, ReportArtifactExpectation::PolicyCashFlow { request, policy: &policy }),
        (&split_artifact, ReportArtifactExpectation::SplitCashFlow { request, definition: &split }),
    ] {
        let bytes = artifact.canonical_bytes().unwrap();
        assert_eq!(&ReportArtifact::decode(&bytes).unwrap(), artifact);
        let head = h.head();
        assert!(h.runtime.block_on(h.book.retain_report_artifact(
            &cx, PRINCIPAL, &authority, &bytes, Some(artifact.digest()),
        )).unwrap().is_err(), "a digest never waives independent financial definitions");
        assert_eq!(h.head(), head);
        h.runtime.block_on(h.book.retain_report_artifact_for(
            &cx, PRINCIPAL, &authority, &bytes, Some(artifact.digest()), expected,
        )).unwrap().unwrap();
    }
    h.post(b"later classified cash", 19);
    let head = h.head();
    for (artifact, expected) in [
        (&policy_artifact, ReportArtifactExpectation::PolicyCashFlow { request, policy: &policy }),
        (&split_artifact, ReportArtifactExpectation::SplitCashFlow { request, definition: &split }),
    ] {
        let replay = h.runtime.block_on(h.book.replay_retained_report_artifact(
            &cx, PRINCIPAL, &cap(&["read"]), artifact.digest(), expected,
        )).unwrap().unwrap();
        assert_eq!(replay.output, artifact.output());
        assert_eq!(Some(replay.known_at), request.known_at);
        assert_eq!(h.head(), head);
    }
    let mut wrong_policy = policy.clone();
    wrong_policy.account_rules[0].activity = CashFlowActivity::Operating;
    assert!(h.book.replay_report_artifact_for(
        &cx, PRINCIPAL, &cap(&["read"]), &policy_artifact.canonical_bytes().unwrap(),
        Some(policy_artifact.digest()),
        ReportArtifactExpectation::PolicyCashFlow { request, policy: &wrong_policy },
    ).unwrap().is_err());
    let mut wrong_split = split.clone();
    wrong_split.splits[0].portions[0].amount = 60;
    wrong_split.splits[0].portions[1].amount = 40;
    assert!(h.book.replay_report_artifact_for(
        &cx, PRINCIPAL, &cap(&["read"]), &split_artifact.canonical_bytes().unwrap(),
        Some(split_artifact.digest()),
        ReportArtifactExpectation::SplitCashFlow { request, definition: &wrong_split },
    ).unwrap().is_err(), "equal total cash does not authenticate a different partition");
    assert_eq!(h.head(), head);
}
