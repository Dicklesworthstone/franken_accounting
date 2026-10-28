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
    status_for(h, artifact, ReportArtifactExpectation::AsSupplied)
}

fn status_for(
    h: &Harness,
    artifact: &ReportArtifact,
    expected: ReportArtifactExpectation<'_>,
) -> CertificateStatus {
    h.book
        .report_artifact_status(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            &artifact.canonical_bytes().unwrap(),
            Some(artifact.digest()),
            expected,
        )
        .unwrap()
        .unwrap()
}

fn add_accounts(h: &mut Harness, accounts: &[(&str, AccountType)]) {
    let specs: Vec<_> = accounts
        .iter()
        .map(|(code, kind)| AccountSpec {
            code: (*code).into(),
            name: (*code).into(),
            account_type: kind.0,
            normal_balance: u8::from(matches!(*kind, AccountType::REVENUE | AccountType::EQUITY)),
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        })
        .collect();
    let cx = h.cx();
    h.runtime
        .block_on(h.book.install_chart(
            &cx,
            &specs,
            PRINCIPAL,
            day(1),
            b"status chart extension",
            &cap(&["schema_change"]),
        ))
        .unwrap()
        .unwrap();
}

#[test]
fn aging_families_track_their_own_accounts_and_inclusive_cutoff() {
    use crate::aging::portfolio::{AgingAccountScope, AgingPortfolioRequest};
    let mut h = Harness::new(93);
    add_accounts(
        &mut h,
        &[("4000", AccountType::REVENUE), ("5000", AccountType::ASSET)],
    );
    let aging = AgingRequest {
        account: Some(h.id("1000")),
        effective_through: day(20),
        known_at: Some(h.head()),
        buckets: AgingBuckets::new(vec![0, 10, 30]).unwrap(),
    };
    let reconciliation = crate::AgingReconciliationRequest {
        account: h.id("1000"),
        effective_through: aging.effective_through,
        known_at: aging.known_at,
        buckets: aging.buckets.clone(),
    };
    let portfolio = AgingPortfolioRequest {
        scope: AgingAccountScope::Selected(vec![h.id("1000")]),
        effective_through: aging.effective_through,
        known_at: aging.known_at,
        buckets: aging.buckets.clone(),
    };
    let authority = cap(&["read", "produce"]);
    let artifacts = [
        (
            ReportArtifact::try_from(
                &h.book
                    .certify_effective_date_aging(&h.cx(), PRINCIPAL, &authority, &aging)
                    .unwrap()
                    .unwrap()
                    .certificate,
            )
            .unwrap(),
            ReportArtifactExpectation::AsSupplied,
        ),
        (
            ReportArtifact::try_from(
                &h.book
                    .certify_effective_date_aging_reconciliation(
                        &h.cx(),
                        PRINCIPAL,
                        &authority,
                        &reconciliation,
                    )
                    .unwrap()
                    .unwrap()
                    .certificate,
            )
            .unwrap(),
            ReportArtifactExpectation::AgingReconciliation(&reconciliation),
        ),
        (
            ReportArtifact::try_from(
                &h.book
                    .certify_aging_portfolio(&h.cx(), PRINCIPAL, &authority, &portfolio)
                    .unwrap()
                    .unwrap()
                    .certificate,
            )
            .unwrap(),
            ReportArtifactExpectation::AgingPortfolio(&portfolio),
        ),
    ];
    for (artifact, expected) in &artifacts {
        assert_eq!(
            status_for(&h, artifact, *expected),
            CertificateStatus::Current {
                checked_at: h.head()
            }
        );
    }
    h.post_at(b"unselected aging account", 23, day(12), "5000", "4000");
    h.post_at(b"after aging cutoff", 37, day(21), "1000", "3000");
    for (artifact, expected) in &artifacts {
        assert_eq!(
            status_for(&h, artifact, *expected),
            CertificateStatus::Current {
                checked_at: h.head()
            }
        );
    }
    let later = h.post_at(b"backdated aging at cutoff", 11, day(20), "1000", "3000");
    let head = h.head();
    for (artifact, expected) in &artifacts {
        assert_eq!(
            status_for(&h, artifact, *expected),
            CertificateStatus::SupersededBy {
                checked_at: head,
                later_entries: vec![later],
                cases: Vec::new(),
            }
        );
        let replayed = h
            .book
            .replay_report_artifact_for(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &artifact.canonical_bytes().unwrap(),
                Some(artifact.digest()),
                *expected,
            )
            .unwrap()
            .unwrap();
        assert_eq!(replayed.output, artifact.output());
    }
    let mut wrong = portfolio.clone();
    wrong.scope = AgingAccountScope::AllPosting;
    assert!(
        h.book
            .report_artifact_status(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &artifacts[2].0.canonical_bytes().unwrap(),
                Some(artifacts[2].0.digest()),
                ReportArtifactExpectation::AgingPortfolio(&wrong),
            )
            .unwrap()
            .is_err(),
        "new activity cannot mask a wrong independent scope"
    );
    assert_eq!(h.head(), head, "status and replay never publish");
}

#[test]
fn portfolio_status_tracks_new_zero_leaves_in_coverage_but_single_account_status_does_not() {
    use crate::aging::portfolio::{AgingAccountScope, AgingPortfolioRequest};
    let mut h = Harness::new(94);
    let known_at = h.head();
    let authority = cap(&["read", "produce"]);
    let requests = [
        AgingAccountScope::AllPosting,
        AgingAccountScope::Selected(vec![h.id("1000")]),
    ]
    .map(|scope| AgingPortfolioRequest {
        scope,
        effective_through: day(20),
        known_at: Some(known_at),
        buckets: AgingBuckets::new(vec![30]).unwrap(),
    });
    let portfolios = requests
        .iter()
        .map(|request| {
            ReportArtifact::try_from(
                &h.book
                    .certify_aging_portfolio(&h.cx(), PRINCIPAL, &authority, request)
                    .unwrap()
                    .unwrap()
                    .certificate,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let request = crate::AgingReconciliationRequest {
        account: h.id("1000"),
        effective_through: day(20),
        known_at: Some(known_at),
        buckets: AgingBuckets::new(vec![30]).unwrap(),
    };
    let single = ReportArtifact::try_from(
        &h.book
            .certify_effective_date_aging_reconciliation(&h.cx(), PRINCIPAL, &authority, &request)
            .unwrap()
            .unwrap()
            .certificate,
    )
    .unwrap();
    add_accounts(&mut h, &[("5000", AccountType::ASSET)]);
    for (artifact, request) in portfolios.iter().zip(&requests) {
        let result = status_for(
            &h,
            artifact,
            ReportArtifactExpectation::AgingPortfolio(request),
        );
        let CertificateStatus::SupersededBy {
            checked_at,
            later_entries,
            cases,
        } = result
        else {
            panic!("a new zero leaf changes selected coverage or uncovered coverage");
        };
        assert_eq!(checked_at, h.head());
        assert!(cases.is_empty());
        assert_eq!(later_entries.len(), 1);
        let (entry, recorded_at) = h
            .book
            .read_entry(&h.cx(), later_entries[0])
            .unwrap()
            .unwrap();
        assert_eq!(entry.proposal.class, EntryClass::SCHEMA_CONTROL);
        assert_eq!(recorded_at, checked_at);
    }
    assert_eq!(
        status_for(
            &h,
            &single,
            ReportArtifactExpectation::AgingReconciliation(&request)
        ),
        CertificateStatus::Current {
            checked_at: h.head()
        }
    );
}

#[test]
fn aging_ignores_holds_but_reconciliation_tracks_them_and_later_effective_releases() {
    let mut h = Harness::new(95);
    let ordinary = h.post_at(b"hold template", 13, day(12), "1000", "3000");
    let cx = h.cx();
    let mut pending = h
        .book
        .read_entry(&cx, ordinary)
        .unwrap()
        .unwrap()
        .0
        .proposal;
    pending.class = EntryClass::PENDING;
    pending.idempotency_key = b"aging pending hold".to_vec();
    pending.pending = Some(fa_model::Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    let authority = cap(&["read", "produce"]);
    let aging_request = AgingRequest {
        account: Some(h.id("1000")),
        effective_through: day(20),
        known_at: Some(h.head()),
        buckets: AgingBuckets::new(vec![30]).unwrap(),
    };
    let aging = ReportArtifact::try_from(
        &h.book
            .certify_effective_date_aging(&cx, PRINCIPAL, &authority, &aging_request)
            .unwrap()
            .unwrap()
            .certificate,
    )
    .unwrap();
    let mut request = crate::AgingReconciliationRequest {
        account: h.id("1000"),
        effective_through: day(20),
        known_at: Some(h.head()),
        buckets: aging_request.buckets.clone(),
    };
    let before_hold = ReportArtifact::try_from(
        &h.book
            .certify_effective_date_aging_reconciliation(&cx, PRINCIPAL, &authority, &request)
            .unwrap()
            .unwrap()
            .certificate,
    )
    .unwrap();
    let target = h
        .runtime
        .block_on(h.book.post(
            &cx,
            PostRequest {
                proposal: pending.clone(),
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(&["post"]),
            },
        ))
        .unwrap()
        .unwrap()
        .entry_ref();
    assert_eq!(
        status(&h, &aging),
        CertificateStatus::Current {
            checked_at: h.head()
        }
    );
    assert_eq!(
        status_for(
            &h,
            &before_hold,
            ReportArtifactExpectation::AgingReconciliation(&request)
        ),
        CertificateStatus::SupersededBy {
            checked_at: h.head(),
            later_entries: vec![target.vid],
            cases: Vec::new(),
        }
    );
    request.known_at = Some(h.head());
    let with_hold = ReportArtifact::try_from(
        &h.book
            .certify_effective_date_aging_reconciliation(&cx, PRINCIPAL, &authority, &request)
            .unwrap()
            .unwrap()
            .certificate,
    )
    .unwrap();
    pending.class = EntryClass::RESOLUTION;
    pending.effective_date = day(25);
    pending.idempotency_key = b"aging pending release".to_vec();
    pending.legs.clear();
    pending.unit_totals.clear();
    pending.control = Some(fa_model::ControlPayload::ReservationRelease);
    pending.pending = Some(fa_model::Pending {
        timeout_ns: None,
        resolution_of: Some(target),
        disposition: Some(fa_model::Disposition::Voids),
    });
    let release = h
        .runtime
        .block_on(h.book.post(
            &cx,
            PostRequest {
                proposal: pending,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(&["post"]),
            },
        ))
        .unwrap()
        .unwrap()
        .entry_ref()
        .vid;
    assert_eq!(
        status(&h, &aging),
        CertificateStatus::Current {
            checked_at: h.head()
        }
    );
    assert_eq!(
        status_for(
            &h,
            &with_hold,
            ReportArtifactExpectation::AgingReconciliation(&request)
        ),
        CertificateStatus::SupersededBy {
            checked_at: h.head(),
            later_entries: vec![release],
            cases: Vec::new(),
        }
    );
}

#[test]
fn indirect_status_tracks_non_cash_sources_and_keeps_unselected_units_current() {
    use crate::{
        CashFlowBasisCertificate, CashFlowBasisDefinition, IndirectCashFlowDefinition,
        IndirectCashFlowRequest,
    };
    let mut h = Harness::new(96);
    add_accounts(&mut h, &[("2000", AccountType::ASSET)]);
    let cash = RollForwardRequest {
        accounts: vec![h.id("1000")],
        units: vec![h.unit.0],
        label: "January funding".into(),
        effective_from: day(1),
        effective_through: day(31),
        known_at: Some(h.head()),
    };
    let ledger = h
        .book
        .general_ledger(&h.cx(), PRINCIPAL, &cap(&["read"]), &cash)
        .unwrap()
        .unwrap();
    let cash_definition = CashFlowDefinition {
        name: "Capital financing".into(),
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
    let income_periods = h
        .book
        .query(&h.cx(), |db, _| {
            let mut periods = Vec::new();
            for row in db.vertices_at(h.head()).map_err(KernelError::from)? {
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
    let request = IndirectCashFlowRequest {
        cash,
        cash_definition: CashFlowBasisDefinition::Explicit(cash_definition),
        income_periods,
        definition: IndirectCashFlowDefinition {
            name: "No operating activity".into(),
            adjustments: Vec::new(),
        },
    };
    let certified = h
        .book
        .certify_indirect_cash_flow(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), &request)
        .unwrap()
        .unwrap();
    let artifact = ReportArtifact::try_from(certified.certificate()).unwrap();
    assert_eq!(
        status_for(
            &h,
            &artifact,
            ReportArtifactExpectation::IndirectCashFlow(&request)
        ),
        CertificateStatus::Current {
            checked_at: h.head()
        }
    );
    let usd = h.unit;
    h.unit = h.book.context().units.lookup("JPY").unwrap();
    h.post_at(b"unselected noncash unit", 17, day(15), "2000", "3000");
    h.unit = usd;
    assert_eq!(
        status_for(
            &h,
            &artifact,
            ReportArtifactExpectation::IndirectCashFlow(&request)
        ),
        CertificateStatus::Current {
            checked_at: h.head()
        }
    );
    let later = h.post_at(b"noncash source changed", 19, day(15), "2000", "3000");
    assert_eq!(
        status_for(
            &h,
            &artifact,
            ReportArtifactExpectation::IndirectCashFlow(&request)
        ),
        CertificateStatus::SupersededBy {
            checked_at: h.head(),
            later_entries: vec![later],
            cases: Vec::new(),
        }
    );
    let CashFlowBasisCertificate::Explicit(cash_certificate) =
        certified.certificate().source_certificate()
    else {
        panic!("this fixture requires an explicit cash certificate");
    };
    let CashFlowBasisDefinition::Explicit(cash_definition) = &request.cash_definition else {
        panic!("this fixture requires an explicit cash definition");
    };
    let cash_source = ReportArtifact::try_from(cash_certificate).unwrap();
    assert_eq!(
        status_for(
            &h,
            &cash_source,
            ReportArtifactExpectation::CashFlow {
                request: &request.cash,
                definition: cash_definition,
            }
        ),
        CertificateStatus::Current {
            checked_at: h.head()
        },
        "direct cash did not change"
    );
    assert!(
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
            .is_err(),
        "freshness cannot bypass independent indirect expectations"
    );
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
            cases: Vec::new(),
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
            cases: Vec::new(),
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
            cases: Vec::new(),
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
