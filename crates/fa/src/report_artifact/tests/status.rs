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

fn summary(h: &Harness, scope: SummaryScope, selection: TrialBalanceSelection) -> ReportArtifact {
    let certified = h
        .book
        .certify_summary_trial_balance(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &SummaryRequest {
                selection,
                scope,
                known_at: Some(h.head()),
            },
        )
        .unwrap()
        .unwrap();
    ReportArtifact::try_from(&certified.certificate).unwrap()
}

#[test]
fn summary_status_tracks_its_cutoff_and_emitted_source_for_partial_roots() {
    let mut h = Harness::new(100);
    add_accounts(
        &mut h,
        &[("5000", AccountType::ASSET), ("4000", AccountType::REVENUE)],
    );
    let artifacts = [
        SummaryScope::AllRoots,
        SummaryScope::Selected(vec![h.id("1000")]),
        SummaryScope::Selected(Vec::new()),
    ]
    .map(|scope| summary(&h, scope, TrialBalanceSelection::AsOf(day(20))));
    for artifact in &artifacts {
        assert_eq!(
            status(&h, artifact),
            CertificateStatus::Current {
                checked_at: h.head()
            }
        );
    }
    h.post_at(b"summary after cutoff", 23, day(21), "5000", "4000");
    for artifact in &artifacts {
        assert_eq!(
            status(&h, artifact),
            CertificateStatus::Current {
                checked_at: h.head()
            }
        );
    }
    let later = h.post_at(b"summary backdated source", 37, day(20), "5000", "4000");
    let head = h.head();
    for artifact in &artifacts {
        // A partial summary retains the complete leaf source as emitted
        // drilldown. Its unselected source rows are not merely extra inputs.
        assert_eq!(
            status(&h, artifact),
            CertificateStatus::SupersededBy {
                checked_at: head,
                later_entries: vec![later],
                cases: Vec::new(),
            }
        );
        let replayed = h
            .book
            .replay_report_artifact(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &artifact.canonical_bytes().unwrap(),
                Some(artifact.digest()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(replayed.output, artifact.output());
    }
    assert_eq!(h.head(), head, "freshness and replay publish nothing");
}

#[test]
fn summary_status_distinguishes_opening_stock_from_selected_period_activity() {
    let mut h = Harness::new(101);
    let period = vec!["FY2026-P02".into()];
    let stock = summary(
        &h,
        SummaryScope::AllRoots,
        TrialBalanceSelection::Periods(period.clone()),
    );
    let activity = summary(
        &h,
        SummaryScope::AllRoots,
        TrialBalanceSelection::Activity(period),
    );
    let opening = h.post_at(b"summary prior month", 19, day(31), "1000", "3000");
    assert_eq!(
        status(&h, &stock),
        CertificateStatus::SupersededBy {
            checked_at: h.head(),
            later_entries: vec![opening],
            cases: Vec::new(),
        }
    );
    assert_eq!(
        status(&h, &activity),
        CertificateStatus::Current {
            checked_at: h.head()
        }
    );
}

#[test]
fn summary_status_attributes_only_period_births_emitted_by_its_selector() {
    let mut h = Harness::new(106);
    let as_of = summary(
        &h,
        SummaryScope::Selected(vec![h.id("1000")]),
        TrialBalanceSelection::AsOf(day(20)),
    );
    let period = vec!["FY2026-P01".into()];
    let stock = summary(
        &h,
        SummaryScope::AllRoots,
        TrialBalanceSelection::Periods(period.clone()),
    );
    let activity = summary(
        &h,
        SummaryScope::AllRoots,
        TrialBalanceSelection::Activity(period),
    );
    let cx = h.cx();
    for year in [2027, 2025] {
        h.runtime
            .block_on(
                h.book
                    .create_periods(&cx, year, PRINCIPAL, &cap(&["schema_change"])),
            )
            .unwrap()
            .unwrap();
        let head = h.head();
        for (is_as_of, artifact) in [(true, &as_of), (false, &stock), (false, &activity)] {
            assert_eq!(
                status(&h, artifact),
                if is_as_of && year == 2025 {
                    CertificateStatus::SupersededBy {
                        checked_at: head,
                        later_entries: vec![fa_journal::period_creation::creation_vid(
                            h.book.context(),
                            year,
                        )],
                        cases: Vec::new(),
                    }
                } else {
                    CertificateStatus::Current { checked_at: head }
                },
                "only the AsOf report emits the newly created prior-year periods"
            );
        }
        assert_eq!(h.head(), head, "period-birth attribution publishes nothing");
    }
    let head = h.head();
    for artifact in [&as_of, &stock, &activity] {
        let replayed = h
            .book
            .replay_report_artifact(
                &cx,
                PRINCIPAL,
                &cap(&["read"]),
                &artifact.canonical_bytes().unwrap(),
                Some(artifact.digest()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(replayed.output, artifact.output());
    }
    assert_eq!(h.head(), head, "historical replay publishes nothing");
}

#[test]
fn summary_status_attributes_group_membership_and_uncovered_leaf_changes() {
    let mut h = Harness::new(102);
    let all = summary(
        &h,
        SummaryScope::AllRoots,
        TrialBalanceSelection::AsOf(day(20)),
    );
    let partial = summary(
        &h,
        SummaryScope::Selected(vec![h.id("1000")]),
        TrialBalanceSelection::AsOf(day(20)),
    );
    let root = AccountSpec {
        code: "2000".into(),
        name: "Unposted summary".into(),
        account_type: AccountType::ASSET.0,
        normal_balance: 0,
        is_leaf: false,
        unit_policy: UnitPolicy::AnyCurrency,
        parent_code: None,
        limit: None,
    };
    let cx = h.cx();
    let installed = h
        .runtime
        .block_on(h.book.install_chart(
            &cx,
            std::slice::from_ref(&root),
            PRINCIPAL,
            day(1),
            b"summary empty root",
            &cap(&["schema_change"]),
        ))
        .unwrap()
        .unwrap();
    assert_eq!(
        status(&h, &all),
        CertificateStatus::SupersededBy {
            checked_at: h.head(),
            later_entries: vec![installed.control_entry],
            cases: Vec::new(),
        }
    );
    assert_eq!(
        status(&h, &partial),
        CertificateStatus::Current {
            checked_at: h.head()
        },
        "an unselected empty summary changes no emitted field"
    );
    let selected = summary(
        &h,
        SummaryScope::Selected(vec![h.id("2000")]),
        TrialBalanceSelection::AsOf(day(20)),
    );
    // A leaf under an installed summary is opened, not installed: a chart
    // install resolves parents within its own batch.
    let opened = h
        .runtime
        .block_on(h.book.open_account(
            &cx,
            &AccountSpec {
                code: "2100".into(),
                name: "Zero-activity leaf".into(),
                is_leaf: true,
                parent_code: Some(root.code.clone()),
                ..root
            },
            day(1),
            None,
            PRINCIPAL,
            day(1),
            b"summary new descendant",
            &cap(&["schema_change"]),
        ))
        .unwrap()
        .unwrap();
    for artifact in [&partial, &selected] {
        assert_eq!(
            status(&h, artifact),
            CertificateStatus::SupersededBy {
                checked_at: h.head(),
                later_entries: vec![opened.control_entry],
                cases: Vec::new(),
            },
            "a new leaf changes either selected membership or uncovered coverage"
        );
    }
}

#[test]
fn summary_status_tracks_pending_holds_and_later_effective_releases() {
    let mut h = Harness::new(103);
    let ordinary = h.post_at(b"summary hold template", 13, day(12), "1000", "3000");
    let cx = h.cx();
    let mut proposal = h
        .book
        .read_entry(&cx, ordinary)
        .unwrap()
        .unwrap()
        .0
        .proposal;
    proposal.class = EntryClass::PENDING;
    proposal.idempotency_key = b"summary pending hold".to_vec();
    proposal.pending = Some(fa_model::Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    let before = summary(
        &h,
        SummaryScope::AllRoots,
        TrialBalanceSelection::AsOf(day(20)),
    );
    let target = h
        .runtime
        .block_on(h.book.post(
            &cx,
            PostRequest {
                proposal: proposal.clone(),
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(&["post"]),
            },
        ))
        .unwrap()
        .unwrap()
        .entry_ref();
    assert_eq!(
        status(&h, &before),
        CertificateStatus::SupersededBy {
            checked_at: h.head(),
            later_entries: vec![target.vid],
            cases: Vec::new(),
        }
    );
    let with_hold = summary(
        &h,
        SummaryScope::AllRoots,
        TrialBalanceSelection::AsOf(day(20)),
    );
    proposal.class = EntryClass::RESOLUTION;
    proposal.effective_date = day(25);
    proposal.idempotency_key = b"summary pending release".to_vec();
    proposal.legs.clear();
    proposal.unit_totals.clear();
    proposal.control = Some(fa_model::ControlPayload::ReservationRelease);
    proposal.pending = Some(fa_model::Pending {
        timeout_ns: None,
        resolution_of: Some(target),
        disposition: Some(fa_model::Disposition::Voids),
    });
    let released = h
        .runtime
        .block_on(h.book.post(
            &cx,
            PostRequest {
                proposal,
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
        status(&h, &with_hold),
        CertificateStatus::SupersededBy {
            checked_at: h.head(),
            later_entries: vec![released],
            cases: Vec::new(),
        },
        "the release changes a selected hold even after the effective cutoff"
    );
}

#[test]
fn summary_status_checks_current_authority_before_tampered_artifact_bytes() {
    let mut h = Harness::new(104);
    let artifact = summary(
        &h,
        SummaryScope::AllRoots,
        TrialBalanceSelection::AsOf(day(20)),
    );
    let original = artifact.canonical_bytes().unwrap();
    let mut damaged = original.clone();
    *damaged.last_mut().unwrap() ^= 1;
    h.post_at(b"summary later activity", 7, day(15), "1000", "3000");
    let cx = h.cx();
    assert_eq!(
        h.book
            .report_artifact_status(
                &cx,
                PRINCIPAL,
                &cap(&["read"]),
                &damaged,
                Some(artifact.digest()),
                ReportArtifactExpectation::AsSupplied,
            )
            .unwrap()
            .unwrap_err()
            .exit,
        exit::VERIFICATION,
        "later activity must not hide original artifact corruption"
    );
    let reader = cap(&["read"]);
    h.runtime
        .block_on(h.book.revoke_capability(
            &cx,
            cap(&["issue_capability"]),
            reader.commitment().unwrap(),
            day(1),
            b"summary reader revocation",
            "Revoke summary reader",
        ))
        .unwrap()
        .unwrap();
    let head = h.head();
    for bytes in [&original, &damaged] {
        let refused = h
            .book
            .report_artifact_status(
                &cx,
                PRINCIPAL,
                &reader,
                bytes,
                Some(artifact.digest()),
                ReportArtifactExpectation::AsSupplied,
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(refused.code, "FA-REF-023");
        assert_eq!(refused.exit, exit::SAFETY);
    }
    assert_eq!(h.head(), head);
}

#[test]
fn summary_status_refuses_current_chart_corruption_despite_later_postings() {
    use fa_model::symbols::{property, relation};
    use fgdb::{WriteBatch, WriteMismatchPolicy};

    let mut h = Harness::new(105);
    let artifact = summary(
        &h,
        SummaryScope::AllRoots,
        TrialBalanceSelection::AsOf(day(20)),
    );
    h.post_at(
        b"summary legitimate later entry",
        7,
        day(15),
        "1000",
        "3000",
    );
    let cx = h.cx();
    let account = h.id("1000");
    let row = cx
        .query()
        .with_restriction(|| h.book.db.vertex(account))
        .unwrap()
        .unwrap();
    let previous = fa_journal::rows::prop(&row, property::NAME).cloned();
    let mut damage = WriteBatch::new(relation::CHILD_OF);
    damage.compare_and_set_vertex_property(
        account,
        property::NAME,
        previous,
        fa_journal::rows::scalar_text("account.name", "Unjournaled rename").unwrap(),
        WriteMismatchPolicy::AbortWrite,
    );
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), damage))
        .unwrap();
    let head = h.head();
    assert!(!matches!(
        h.book.report_artifact_status(
            &cx,
            PRINCIPAL,
            &cap(&["read"]),
            &artifact.canonical_bytes().unwrap(),
            Some(artifact.digest()),
            ReportArtifactExpectation::AsSupplied,
        ),
        Ok(Ok(_))
    ));
    assert_eq!(h.head(), head);
}

#[test]
fn summary_status_refuses_current_book_or_unit_context_corruption() {
    use fa_model::symbols::{property, relation};
    use fgdb::{WriteBatch, WriteMismatchPolicy};
    use fgdb_types::CanonicalScalar;

    for corrupt_unit in [false, true] {
        for later_post in [false, true] {
            let mut h = Harness::new(107 + 2 * u8::from(corrupt_unit) + u8::from(later_post));
            let artifact = summary(
                &h,
                SummaryScope::AllRoots,
                TrialBalanceSelection::AsOf(day(20)),
            );
            if later_post {
                h.post_at(
                    b"summary later context contribution",
                    7,
                    day(15),
                    "1000",
                    "3000",
                );
            }
            let (target, key, corruption) = if corrupt_unit {
                let unit = h.book.context().units.get(h.unit).unwrap();
                (
                    fa_model::unit_vid(
                        h.book.context().book_id,
                        &format!("{}@v{}", unit.code, unit.version),
                    ),
                    property::SCALE,
                    CanonicalScalar::Int(i64::from(unit.scale) + 1),
                )
            } else {
                let mut digest =
                    fa_model::unit::unit_table_digest(&h.book.context().units).unwrap();
                digest[0] ^= 1;
                (
                    fa_journal::rows::book_root(),
                    property::UNIT_TABLE_DIGEST,
                    fa_journal::rows::scalar_bytes("book.unit_table_digest", digest.to_vec())
                        .unwrap(),
                )
            };
            let cx = h.cx();
            let row = cx
                .query()
                .with_restriction(|| h.book.db.vertex(target))
                .unwrap()
                .unwrap();
            let previous = fa_journal::rows::prop(&row, key).cloned();
            let mut damage = WriteBatch::new(relation::IN_BOOK);
            damage.compare_and_set_vertex_property(
                target,
                key,
                previous,
                corruption,
                WriteMismatchPolicy::AbortWrite,
            );
            h.runtime
                .block_on(h.book.db.write(&cx.commit(), damage))
                .unwrap();
            let head = h.head();
            let bytes = artifact.canonical_bytes().unwrap();
            let replayed = h
                .book
                .replay_report_artifact(
                    &cx,
                    PRINCIPAL,
                    &cap(&["read"]),
                    &bytes,
                    Some(artifact.digest()),
                )
                .unwrap()
                .unwrap();
            assert_eq!(replayed.output, artifact.output());
            let refused = h
                .book
                .report_artifact_status(
                    &cx,
                    PRINCIPAL,
                    &cap(&["read"]),
                    &bytes,
                    Some(artifact.digest()),
                    ReportArtifactExpectation::AsSupplied,
                )
                .unwrap()
                .unwrap_err();
            assert_eq!(refused.code, crate::certificate::code::CERTIFICATE_INVALID);
            assert_eq!(
                refused.exit,
                exit::VERIFICATION,
                "corrupt_unit={corrupt_unit}, later_post={later_post}: {refused:?}"
            );
            assert_eq!(h.head(), head, "failed freshness checks publish nothing");
        }
    }
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
