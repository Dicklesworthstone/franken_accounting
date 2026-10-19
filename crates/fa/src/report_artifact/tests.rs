mod cash_flow;
mod retention;
mod status;

use super::*;
use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, UnitPolicy};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, EvidenceRef, LegPayload, Oid, Writer,
    account_vid, domain_digest,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;

use crate::{
    AgingBuckets, AgingRequest, BookKeys, Entropy, RollForwardRequest, SummaryRequest,
    SummaryScope, TrialBalanceSelection,
};

const PRINCIPAL: VId = VId(71);
fn day(n: u8) -> DateDay {
    DateDay::from_ymd(2026, 1, n).unwrap()
}
fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    book: AsyncBook<MemVfs>,
    vfs: MemVfs,
    seed: u8,
    unit: UnitId,
    evidence: Vec<EvidenceRef>,
}

impl Harness {
    fn new(seed: u8) -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let unit = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
        let book_id = Id128([seed; 16]);
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs.clone(),
                Path::new("artifact-book"),
                BookKeys::for_development(seed),
                BookSpec {
                    book_id,
                    name: "Unified artifact replay".into(),
                    base_unit: unit,
                    calendar: FiscalCalendar::monthly("artifact", 1, 0).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(u64::from(seed)),
            ))
            .unwrap();
        let accounts: Vec<_> = [("1000", AccountType::ASSET), ("3000", AccountType::EQUITY)]
            .into_iter()
            .map(|(code, kind)| AccountSpec {
                code: code.into(),
                name: code.into(),
                account_type: kind.0,
                normal_balance: u8::from(kind == AccountType::EQUITY),
                is_leaf: true,
                unit_policy: UnitPolicy::AnyCurrency,
                parent_code: None,
                limit: None,
            })
            .collect();
        runtime
            .block_on(book.install_chart(
                &cx,
                &accounts,
                PRINCIPAL,
                day(1),
                b"chart",
                &fa_journal::Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        runtime
            .block_on(book.create_periods(&cx, 2026, PRINCIPAL, &cap(&["schema_change"])))
            .unwrap()
            .unwrap();
        runtime
            .block_on(book.transition_period(
                &cx,
                "FY2026-P01",
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                day(1),
                b"open",
                &cap(&["close"]),
            ))
            .unwrap()
            .unwrap();
        let document = Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"Independent source fixture".to_vec(),
        };
        runtime
            .block_on(book.add_document(&cx, &document))
            .unwrap()
            .unwrap();
        let mut h = Self {
            runtime,
            root,
            book,
            vfs,
            seed,
            unit,
            evidence: vec![document.evidence_ref(1)],
        };
        h.post(b"initial", 100);
        h
    }
    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }
    fn head(&self) -> CommitSeq {
        self.book.head(&self.cx()).unwrap()
    }
    fn id(&self, code: &str) -> VId {
        account_vid(self.book.context().book_id, code)
    }
    fn post(&mut self, key: &[u8], amount: i128) {
        self.post_at(key, amount, day(10), "1000", "3000");
    }
    fn post_at(
        &mut self,
        key: &[u8],
        amount: i128,
        date: DateDay,
        debit: &str,
        credit: &str,
    ) -> VId {
        let cx = self.cx();
        let legs = vec![
            LegPayload::simple(Side::Debit, self.id(debit), Amount::new(self.unit, amount)),
            LegPayload::simple(
                Side::Credit,
                self.id(credit),
                Amount::new(self.unit, amount),
            ),
        ];
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id: self.book.context().book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: date,
            document_date: None,
            description: self.book.seal_text(&cx, "Artifact source posting").unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([53; 32]),
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: self.evidence.clone(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            tags: Vec::new(),
            extensions: Vec::new(),
        };
        self.runtime
            .block_on(self.book.post(
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
            .vid
    }
    fn artifacts(&self) -> Vec<ReportArtifact> {
        let cx = self.cx();
        let at = Some(self.head());
        let authority = cap(&["read", "produce"]);
        let native = self
            .book
            .certify_trial_balance(&cx, TrialBalanceSelection::AsOf(day(20)), at)
            .unwrap()
            .unwrap();
        assert_eq!(
            native
                .report
                .rows
                .iter()
                .find(|r| r.account == self.id("1000"))
                .unwrap()
                .debits,
            100
        );
        let summary = self
            .book
            .certify_summary_trial_balance(
                &cx,
                PRINCIPAL,
                &authority,
                &SummaryRequest {
                    selection: TrialBalanceSelection::AsOf(day(20)),
                    scope: SummaryScope::AllRoots,
                    known_at: at,
                },
            )
            .unwrap()
            .unwrap();
        let aging = self
            .book
            .certify_effective_date_aging(
                &cx,
                PRINCIPAL,
                &authority,
                &AgingRequest {
                    account: None,
                    effective_through: day(20),
                    known_at: at,
                    buckets: AgingBuckets::new(vec![30, 60, 90]).unwrap(),
                },
            )
            .unwrap()
            .unwrap();
        let roll = self
            .book
            .certify_roll_forward(
                &cx,
                PRINCIPAL,
                &authority,
                &RollForwardRequest {
                    accounts: vec![self.id("1000"), self.id("3000")],
                    units: vec![self.unit.0],
                    label: "January".into(),
                    effective_from: day(1),
                    effective_through: day(20),
                    known_at: at,
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            roll.report
                .rows
                .iter()
                .find(|r| r.account_id == self.id("1000").0)
                .unwrap()
                .closing,
            100
        );
        vec![
            ReportArtifact::try_from(&native.certificate).unwrap(),
            ReportArtifact::try_from(&summary.certificate).unwrap(),
            ReportArtifact::try_from(&aging.certificate).unwrap(),
            ReportArtifact::try_from(&roll.certificate).unwrap(),
        ]
    }
}

#[test]
fn all_families_replay_their_original_bytes_after_a_later_backdated_post() {
    let mut h = Harness::new(71);
    let before = h.head();
    let artifacts = h.artifacts();
    assert_eq!(h.head(), before, "certification publishes nothing");
    assert_eq!(
        artifacts
            .iter()
            .map(ReportArtifact::family)
            .collect::<Vec<_>>(),
        vec![
            ReportArtifactFamily::Native,
            ReportArtifactFamily::Summary,
            ReportArtifactFamily::EffectiveDateAging,
            ReportArtifactFamily::RollForward,
        ]
    );
    h.post(b"backdated", 17);
    let head = h.head();
    assert!(head > before);
    for artifact in artifacts {
        let bytes = artifact.canonical_bytes().unwrap();
        let decoded = ReportArtifact::decode(&bytes).unwrap();
        assert_eq!(decoded, artifact);
        assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
        let replayed = h
            .book
            .replay_report_artifact(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &bytes,
                Some(artifact.digest()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(replayed.output, artifact.output());
        assert_eq!(replayed.certificate_digest, *artifact.digest());
        assert_eq!(replayed.family, artifact.family());
        assert_eq!(replayed.known_at, before);
        assert_eq!(h.head(), head, "replay publishes nothing");
    }
}

#[test]
fn intact_but_wrong_artifacts_and_repaired_false_outputs_do_not_pass() {
    let h = Harness::new(72);
    let artifacts = h.artifacts();
    let summary = &artifacts[1];
    let head = h.head();
    let bytes = summary.canonical_bytes().unwrap();
    assert!(
        h.book
            .replay_report_artifact(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &bytes,
                Some(artifacts[0].digest())
            )
            .unwrap()
            .is_err(),
        "nested source digest is not outer identity"
    );
    let mut forged = bytes;
    let end = forged.len() - 32;
    // Change output, then repair its PUBLIC outer hash. The family decoder may
    // accept this intact unsigned container; only historical replay disproves it.
    forged[end - 1] ^= 1;
    let digest = domain_digest(b"fa:summary-certificate-digest:v1", &[&forged[..end]]);
    forged[end..].copy_from_slice(&digest);
    assert!(
        ReportArtifact::decode(&forged).is_ok(),
        "reach historical replay, not hash rejection"
    );
    assert!(
        h.book
            .replay_report_artifact(&h.cx(), PRINCIPAL, &cap(&["read"]), &forged, Some(&digest))
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), head);
}

#[test]
fn statement_bridges_retain_and_replay_both_endpoints_and_the_complete_trace() {
    let mut h = Harness::new(75);
    let before = h.head();
    h.post(b"bridge correction", 17);
    let after = h.head();
    let request = crate::StatementDiffRequest {
        selection: crate::StatementSelection {
            definition: crate::StatementDefinition::embedded("balance-sheet").unwrap(),
            periods: vec!["FY2026-P01".into()],
            comparative: Vec::new(),
        },
        before,
        after: Some(after),
    };
    let authority = cap(&["read", "produce"]);
    let diff = h
        .book
        .certify_statement_diff(&h.cx(), PRINCIPAL, &authority, &request)
        .unwrap()
        .unwrap();
    let trace = h
        .book
        .certify_statement_trace(
            &h.cx(),
            PRINCIPAL,
            &authority,
            &crate::StatementTraceRequest {
                comparison: request,
                max_publications: 16,
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(trace.report.publications().len(), 1);
    let artifacts = [
        (
            ReportArtifact::try_from(&diff.certificate).unwrap(),
            b"fa:statement-diff-certificate-digest:v1".as_slice(),
        ),
        (
            ReportArtifact::try_from(&trace.certificate).unwrap(),
            b"fa:statement-trace-certificate-digest:v1".as_slice(),
        ),
    ];
    h.post(b"later correction outside saved trace", 9);
    for (artifact, domain) in artifacts {
        assert_eq!(
            artifact.known_at(),
            after,
            "terminal source, not first source"
        );
        let bytes = artifact.canonical_bytes().unwrap();
        assert_eq!(ReportArtifact::decode(&bytes).unwrap(), artifact);
        let cx = h.cx();
        let retained = h
            .runtime
            .block_on(h.book.retain_report_artifact(
                &cx,
                PRINCIPAL,
                &authority,
                &bytes,
                Some(artifact.digest()),
            ))
            .unwrap()
            .unwrap();
        let head = h.head();
        let retry = h
            .runtime
            .block_on(h.book.retain_report_artifact(
                &cx,
                PRINCIPAL,
                &authority,
                &bytes,
                Some(artifact.digest()),
            ))
            .unwrap()
            .unwrap();
        assert_eq!(retry, retained);
        assert_eq!(h.head(), head);
        let read = h
            .runtime
            .block_on(h.book.read_report_artifact(
                &cx,
                PRINCIPAL,
                &cap(&["read"]),
                artifact.digest(),
            ))
            .unwrap()
            .unwrap();
        assert_eq!(read, artifact);
        let replay = h
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
        assert_eq!(replay.output, artifact.output());
        assert_eq!(replay.known_at, after);
        assert_ne!(
            replay.certificate_digest,
            artifact.source_certificate().digest
        );

        // Rehashing a false outer output must not authenticate a bridge or its
        // publication attribution, even when both native endpoints are intact.
        let mut forged = bytes;
        let end = forged.len() - 32;
        forged[end - 1] ^= 1;
        let forged_digest = domain_digest(domain, &[&forged[..end]]);
        forged[end..].copy_from_slice(&forged_digest);
        assert!(ReportArtifact::decode(&forged).is_ok());
        assert!(
            h.runtime
                .block_on(h.book.retain_report_artifact(
                    &cx,
                    PRINCIPAL,
                    &authority,
                    &forged,
                    Some(&forged_digest),
                ))
                .unwrap()
                .is_err()
        );
        assert_eq!(
            h.head(),
            head,
            "failed replay cannot publish a forged artifact"
        );
    }
}

#[test]
fn portfolio_dispatch_binds_the_full_independent_account_coverage() {
    use crate::aging::portfolio::{AgingAccountScope, AgingPortfolioRequest};
    let mut h = Harness::new(76);
    let request = AgingPortfolioRequest {
        scope: AgingAccountScope::AllPosting,
        effective_through: day(20),
        known_at: Some(h.head()),
        buckets: AgingBuckets::new(vec![30, 60, 90]).unwrap(),
    };
    let authority = cap(&["read", "produce"]);
    let certified = h
        .book
        .certify_aging_portfolio(&h.cx(), PRINCIPAL, &authority, &request)
        .unwrap()
        .unwrap();
    let artifact = ReportArtifact::try_from(&certified.certificate).unwrap();
    assert_eq!(artifact.family(), ReportArtifactFamily::AgingPortfolio);
    let bytes = artifact.canonical_bytes().unwrap();
    let cx = h.cx();
    let head = h.head();
    assert!(
        h.runtime
            .block_on(h.book.retain_report_artifact(
                &cx,
                PRINCIPAL,
                &authority,
                &bytes,
                Some(artifact.digest()),
            ))
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), head, "a hash cannot waive independent coverage");
    let mut wrong = request.clone();
    wrong.scope = AgingAccountScope::Selected(vec![h.id("1000")]);
    assert!(
        h.book
            .replay_report_artifact_for(
                &cx,
                PRINCIPAL,
                &cap(&["read"]),
                &bytes,
                Some(artifact.digest()),
                ReportArtifactExpectation::AgingPortfolio(&wrong),
            )
            .unwrap()
            .is_err()
    );
    h.runtime
        .block_on(h.book.retain_report_artifact_for(
            &cx,
            PRINCIPAL,
            &authority,
            &bytes,
            Some(artifact.digest()),
            ReportArtifactExpectation::AgingPortfolio(&request),
        ))
        .unwrap()
        .unwrap();
    h.post(b"later portfolio history", 13);
    let replay = h
        .runtime
        .block_on(h.book.replay_retained_report_artifact(
            &cx,
            PRINCIPAL,
            &cap(&["read"]),
            artifact.digest(),
            ReportArtifactExpectation::AgingPortfolio(&request),
        ))
        .unwrap()
        .unwrap();
    assert_eq!(replay.output, certified.report.canonical_bytes().unwrap());
    assert_eq!(Some(replay.known_at), request.known_at);
}

#[test]
fn current_authority_precedes_decoding_and_cannot_come_from_the_artifact() {
    let h = Harness::new(73);
    let head = h.head();
    let no_read = h
        .book
        .replay_report_artifact(&h.cx(), PRINCIPAL, &cap(&["post"]), b"bad", None)
        .unwrap()
        .unwrap_err();
    assert_ne!(no_read.code, crate::certificate::code::CERTIFICATE_INVALID);
    let wrong_holder = h
        .book
        .replay_report_artifact(&h.cx(), VId(99), &cap(&["read"]), b"bad", None)
        .unwrap()
        .unwrap_err();
    assert_ne!(
        wrong_holder.code,
        crate::certificate::code::CERTIFICATE_INVALID
    );
    for authority in [
        cap(&["read"]).expiring_at(head),
        cap(&["read"]).for_books(&[Id128([255; 16])]).unwrap(),
        cap(&["read"]).for_accounts(&["1000"]).unwrap(),
    ] {
        let refused = h
            .book
            .replay_report_artifact(&h.cx(), PRINCIPAL, &authority, b"bad", None)
            .unwrap()
            .unwrap_err();
        assert_ne!(refused.code, crate::certificate::code::CERTIFICATE_INVALID);
    }
    let other = Harness::new(74);
    for artifact in h.artifacts() {
        assert!(
            other
                .book
                .replay_report_artifact(
                    &other.cx(),
                    PRINCIPAL,
                    &cap(&["read"]),
                    &artifact.canonical_bytes().unwrap(),
                    None
                )
                .unwrap()
                .is_err()
        );
    }
    assert_eq!(h.head(), head);
}

#[test]
fn bounded_format_dispatch_rejects_unknown_versions_and_malformed_frames() {
    for bytes in [
        vec![],
        vec![0],
        vec![255; 16],
        b"fa:report-certificate:v1".to_vec(),
    ] {
        assert!(ReportArtifact::decode(&bytes).is_err());
    }
    for tag in [
        b"fa:report-certificate:v5".as_slice(),
        b"fa:summary-certificate:v2",
        b"unregistered",
    ] {
        let mut w = Writer::new();
        w.bytes(tag);
        assert!(ReportArtifact::decode(&w.finish().unwrap()).is_err());
    }
    assert!(ReportArtifact::decode(&vec![0; MAX_REPORT_ARTIFACT_BYTES + 1]).is_err());
    let h = Harness::new(75);
    for artifact in h.artifacts() {
        let bytes = artifact.canonical_bytes().unwrap();
        for length in [0, 1, 4, bytes.len() / 2, bytes.len() - 1] {
            assert!(ReportArtifact::decode(&bytes[..length]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ReportArtifact::decode(&trailing).is_err());
        let mut corrupt = bytes;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(ReportArtifact::decode(&corrupt).is_err());
    }
}

#[test]
fn public_native_fields_cannot_bypass_validation_via_typed_conversion() {
    let h = Harness::new(76);
    let mut native = h.artifacts()[0].source_certificate().clone();
    native.digest[0] ^= 1;
    assert!(ReportArtifact::try_from(&native).is_err());
}

#[test]
fn aging_reconciliation_requires_independent_scope_and_replays_both_sources() {
    let mut h = Harness::new(84);
    let at = h.head();
    let request = crate::AgingReconciliationRequest {
        account: h.id("1000"),
        effective_through: day(20),
        known_at: Some(at),
        buckets: AgingBuckets::new(vec![30, 60, 90]).unwrap(),
    };
    let certified = h
        .book
        .certify_effective_date_aging_reconciliation(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &request,
        )
        .unwrap()
        .unwrap();
    assert_eq!(h.head(), at, "certification publishes nothing");
    let artifact = ReportArtifact::try_from(&certified.certificate).unwrap();
    assert_eq!(artifact.family(), ReportArtifactFamily::AgingReconciliation);
    let bytes = artifact.canonical_bytes().unwrap();
    assert!(
        h.book
            .replay_report_artifact(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &bytes,
                Some(artifact.digest()),
            )
            .unwrap()
            .is_err(),
        "recipient scope is mandatory for reconciliation"
    );
    h.post(b"later reconciliation history", 7);
    let head = h.head();
    let replayed = h
        .book
        .replay_report_artifact_for(
            &h.cx(),
            PRINCIPAL,
            &cap(&["read"]),
            &bytes,
            Some(artifact.digest()),
            ReportArtifactExpectation::AgingReconciliation(&request),
        )
        .unwrap()
        .unwrap();
    assert_eq!(replayed.family, ReportArtifactFamily::AgingReconciliation);
    assert_eq!(replayed.known_at, at);
    assert_eq!(replayed.output, artifact.output());
    assert_eq!(h.head(), head, "replay publishes nothing");

    let mut changed = request.clone();
    changed.known_at = None;
    assert!(
        h.book
            .replay_report_artifact_for(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &bytes,
                None,
                ReportArtifactExpectation::AgingReconciliation(&changed),
            )
            .unwrap()
            .is_err()
    );
    changed = request.clone();
    changed.account = h.id("3000");
    assert!(
        h.book
            .replay_report_artifact_for(
                &h.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &bytes,
                None,
                ReportArtifactExpectation::AgingReconciliation(&changed),
            )
            .unwrap()
            .is_err()
    );
}
