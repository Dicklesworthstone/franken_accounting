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
