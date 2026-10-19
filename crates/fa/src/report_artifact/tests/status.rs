use super::*;
use crate::{CashFlowActivity, CashFlowAssignment, CashFlowDefinition, CertificateStatus};

fn request(h: &Harness) -> RollForwardRequest {
    RollForwardRequest {
        accounts: vec![h.id("1000")],
        units: vec![h.unit.0],
        label: "Selected cash January 10–20".into(),
        effective_from: day(10),
        effective_through: day(20),
        known_at: Some(h.head()),
    }
}

fn roll(h: &Harness, request: &RollForwardRequest) -> ReportArtifact {
    let report = h
        .book
        .certify_roll_forward(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), request)
        .unwrap()
        .unwrap();
    ReportArtifact::try_from(&report.certificate).unwrap()
}

fn status(h: &Harness, artifact: &ReportArtifact) -> CertificateStatus {
    h.book
        .report_artifact_status(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            &artifact.canonical_bytes().unwrap(),
            Some(artifact.digest()),
            ReportArtifactExpectation::AsSupplied,
        )
        .unwrap()
        .unwrap()
}

#[test]
fn status_uses_selected_accounts_units_and_cutoff_including_opening_stock() {
    let mut h = Harness::new(90);
    let cx = h.cx();
    let extra: Vec<_> = [("4000", AccountType::REVENUE), ("5000", AccountType::ASSET)]
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
        .collect();
    h.runtime
        .block_on(h.book.install_chart(
            &cx,
            &extra,
            PRINCIPAL,
            day(1),
            b"extra chart",
            &cap(&["schema_change"]),
        ))
        .unwrap()
        .unwrap();
    let cash = roll(&h, &request(&h));
    let mut yen_request = request(&h);
    yen_request.units = vec![h.book.context().units.lookup("JPY").unwrap().0];
    let yen = roll(&h, &yen_request);
    let initial = h.head();
    assert_eq!(
        status(&h, &cash),
        CertificateStatus::Current {
            checked_at: initial
        }
    );

    h.post_at(b"unrelated account", 23, day(12), "5000", "4000");
    h.post_at(b"beyond cutoff", 37, day(21), "1000", "3000");
    assert_eq!(
        status(&h, &cash),
        CertificateStatus::Current {
            checked_at: h.head()
        }
    );
    let opening = h.post_at(b"late opening", 11, day(2), "1000", "3000");
    assert_eq!(
        status(&h, &cash),
        CertificateStatus::SupersededBy {
            checked_at: h.head(),
            later_entries: vec![opening],
        }
    );
    // USD changes neither the selected JPY schedule nor its zero-valued cell.
    assert_eq!(
        status(&h, &yen),
        CertificateStatus::Current {
            checked_at: h.head()
        }
    );
    let after = h.head();
    h.book
        .replay_report_artifact(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            &cash.canonical_bytes().unwrap(),
            Some(cash.digest()),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        h.head(),
        after,
        "status and historical replay publish nothing"
    );
}

#[test]
fn offsetting_new_movements_supersede_a_schedule_even_when_closing_cash_is_unchanged() {
    let mut h = Harness::new(91);
    let artifact = roll(&h, &request(&h));
    let debit = h.post_at(b"new debit", 19, day(11), "1000", "3000");
    let credit = h.post_at(b"offsetting credit", 19, day(12), "3000", "1000");
    assert_eq!(
        status(&h, &artifact),
        CertificateStatus::SupersededBy {
            checked_at: h.head(),
            later_entries: vec![debit, credit],
        }
    );
}

#[test]
fn cash_status_requires_independent_policy_and_replays_before_inspecting_later_activity() {
    let mut h = Harness::new(92);
    let request = request(&h);
    let ledger = h
        .book
        .general_ledger(&h.cx(), PRINCIPAL, &cap(&["read"]), &request)
        .unwrap()
        .unwrap();
    let definition = CashFlowDefinition {
        name: "Funding".into(),
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
    let certified = h
        .book
        .certify_cash_flow(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &request,
            &definition,
        )
        .unwrap()
        .unwrap();
    let artifact = ReportArtifact::try_from(certified.certificate()).unwrap();
    let bytes = artifact.canonical_bytes().unwrap();
    let expected = ReportArtifactExpectation::CashFlow {
        request: &request,
        definition: &definition,
    };
    assert_eq!(
        h.book
            .report_artifact_status(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &bytes,
                Some(artifact.digest()),
                expected,
            )
            .unwrap()
            .unwrap(),
        CertificateStatus::Current {
            checked_at: h.head()
        }
    );
    let later = h.post_at(b"unclassified later cash", 7, day(15), "1000", "3000");
    assert_eq!(
        h.book
            .report_artifact_status(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &bytes,
                Some(artifact.digest()),
                expected,
            )
            .unwrap()
            .unwrap(),
        CertificateStatus::SupersededBy {
            checked_at: h.head(),
            later_entries: vec![later],
        }
    );
    assert!(
        h.book
            .report_artifact_status(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &bytes,
                Some(artifact.digest()),
                ReportArtifactExpectation::AsSupplied,
            )
            .unwrap()
            .is_err(),
        "a matching digest is not an independent policy"
    );
    let mut wrong = definition.clone();
    wrong.assignments[0].activity = CashFlowActivity::Operating;
    assert!(
        h.book
            .report_artifact_status(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &bytes,
                Some(artifact.digest()),
                ReportArtifactExpectation::CashFlow {
                    request: &request,
                    definition: &wrong
                },
            )
            .unwrap()
            .is_err(),
        "a wrong policy never produces a freshness verdict"
    );
    let mut damaged = bytes.clone();
    *damaged.last_mut().unwrap() ^= 1;
    assert!(
        h.book
            .report_artifact_status(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &damaged,
                Some(artifact.digest()),
                expected,
            )
            .unwrap()
            .is_err(),
        "later activity never masks an invalid original artifact"
    );
    let head = h.head();
    let refusal = h
        .book
        .report_artifact_status(
            &h.cx(),
            PRINCIPAL,
            &cap(&["post"]),
            b"malformed",
            None,
            ReportArtifactExpectation::AsSupplied,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.exit, fa_journal::exit::SAFETY);
    assert_eq!(h.head(), head);
}
