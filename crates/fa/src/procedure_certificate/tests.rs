use super::*;
use crate::{BookKeys, Entropy, ReportArtifact, ReportArtifactFamily};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, Posted, UnitPolicy};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, EvidenceRef, LegPayload, Oid, account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{FiscalCalendar, PeriodTransition};
use fgdb::MemVfs;
use std::path::Path;

const PRINCIPAL: VId = VId(73);
fn day(n: u8) -> DateDay {
    DateDay::from_ymd(2026, 1, n).unwrap()
}
fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}
struct Fixture {
    runtime: Runtime,
    root: Cx,
    book: AsyncBook<MemVfs>,
    vfs: MemVfs,
    unit: UnitId,
    evidence: Vec<EvidenceRef>,
    next: u8,
}
impl Fixture {
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
                Path::new("procedures"),
                BookKeys::for_development(seed),
                BookSpec {
                    book_id,
                    name: "Certified procedure fixture".into(),
                    base_unit: unit,
                    calendar: FiscalCalendar::monthly("procedure", 1, 0).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(u64::from(seed)),
            ))
            .unwrap();
        let accounts: Vec<_> = [
            ("1000", AccountType::ASSET),
            ("1010", AccountType::ASSET),
            ("1020", AccountType::ASSET),
            ("3000", AccountType::EQUITY),
            ("6000", AccountType::EXPENSE),
        ]
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
            .block_on(book.install_chart(&cx, &accounts, PRINCIPAL, day(1), b"chart"))
            .unwrap()
            .unwrap();
        runtime.block_on(book.create_periods(&cx, 2026)).unwrap();
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
        let source = Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: b"Actual evidence for replay tests".to_vec(),
        };
        runtime
            .block_on(book.add_document(&cx, &source))
            .unwrap()
            .unwrap();
        Self {
            runtime,
            root,
            book,
            vfs,
            unit,
            evidence: vec![source.evidence_ref(1)],
            next: 1,
        }
    }
    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }
    fn id(&self, code: &str) -> VId {
        account_vid(self.book.context().book_id, code)
    }
    fn head(&self) -> CommitSeq {
        self.book.head(&self.cx()).unwrap()
    }
    fn post(
        &mut self,
        date: u8,
        from: &str,
        to: &str,
        amount: i128,
        approve: bool,
    ) -> (VId, Option<VId>) {
        let cx = self.cx();
        self.next += 1;
        let legs = vec![
            LegPayload::simple(Side::Credit, self.id(from), Amount::new(self.unit, amount)),
            LegPayload::simple(Side::Debit, self.id(to), Amount::new(self.unit, amount)),
        ];
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id: self.book.context().book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day(date),
            document_date: None,
            description: self.book.seal_text(&cx, "Replay source transfer").unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: vec![self.next],
            origin: EntryOrigin::Intent {
                intent_oid: Oid([1; 32]),
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
        let approvals = if approve {
            let approved = self
                .runtime
                .block_on(self.book.approve(
                    &cx,
                    Capability::embedded(VId(74), &["approve"]).unwrap(),
                    proposal.proposal_digest().unwrap(),
                ))
                .unwrap()
                .unwrap();
            vec![match approved {
                fa_journal::Approved::Recorded { approval, .. }
                | fa_journal::Approved::AlreadyRecorded { approval, .. } => approval,
            }]
        } else {
            Vec::new()
        };
        let approval = approvals.first().map(|a| a.approval_vid);
        let posted = self
            .runtime
            .block_on(self.book.post(
                &cx,
                PostRequest {
                    proposal,
                    approvals,
                    plan_certificate: None,
                    capability: cap(&["post"]),
                },
            ))
            .unwrap()
            .unwrap();
        match posted {
            Posted::Committed { entry_ref, .. } => (entry_ref.vid, approval),
            _ => panic!("fresh posting"),
        }
    }
    fn request(&self, id: &str, source: VId) -> ProcedureRequest {
        let row = fa_lantern::bind(id).unwrap();
        let mut req = ProcedureRequest::new(
            id,
            catalog::Inputs {
                account: row
                    .inputs
                    .iter()
                    .any(|i| i.name == "account")
                    .then(|| self.id("1000")),
                source: row
                    .inputs
                    .iter()
                    .any(|i| i.name == "source")
                    .then_some(source),
            },
        )
        .unwrap();
        req.known_at = Some(self.head());
        req.effective_through = Some(day(31));
        req
    }
    fn certify(&self, request: &ProcedureRequest) -> CertifiedProcedure {
        self.book
            .certify_procedure(&self.cx(), PRINCIPAL, &cap(&["read", "produce"]), request)
            .unwrap()
            .unwrap()
    }
}

#[test]
fn every_supported_procedure_has_a_native_replayable_certificate_and_does_not_write() {
    let mut f = Fixture::new(81);
    let (source, _) = f.post(1, "3000", "1000", 100, true);
    f.post(2, "1000", "1010", 80, false);
    f.post(3, "1010", "1020", 60, false);
    f.post(4, "1020", "6000", 10, false);
    let before = f.head();
    let mut certificates = Vec::new();
    assert_eq!(CERTIFIABLE_PROCEDURES.len(), 22);
    for &(id, _) in CERTIFIABLE_PROCEDURES {
        let row = fa_lantern::bind(id).unwrap();
        let certified = f.certify(&f.request(&row.id, source));
        let bytes = certified.certificate.canonical_bytes().unwrap();
        let decoded = ProcedureCertificate::decode(&bytes).unwrap();
        assert_eq!(decoded.report(), &certified.report);
        assert_eq!(decoded, certified.certificate);
        assert_eq!(bytes, decoded.canonical_bytes().unwrap());
        assert_eq!(f.head(), before, "certification published {}", row.id);
        certificates.push(decoded);
    }
    f.post(1, "3000", "1000", 300, false);
    let after = f.head();
    assert!(after > before);
    for certificate in certificates {
        let bytes = certificate.canonical_bytes().unwrap();
        let replayed = f
            .book
            .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &certificate)
            .unwrap()
            .unwrap();
        assert_eq!(replayed, certificate.report);
        let artifact = ReportArtifact::decode(&bytes).unwrap();
        assert_eq!(artifact.family(), ReportArtifactFamily::Procedure);
        let replayed = f
            .book
            .replay_report_artifact(
                &f.cx(),
                PRINCIPAL,
                &cap(&["read"]),
                &bytes,
                Some(certificate.digest()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(replayed.output, certificate.output);
        assert_eq!(replayed.known_at, before);
        assert_eq!(f.head(), after, "replay wrote metadata");
        println!(
            "procedure={} findings={} native_inputs={} immutable=true",
            certificate.report.procedure,
            certificate.report.findings.len(),
            certificate.source.inputs.len() + 1
        );
    }
}

#[test]
fn new_catalog_rows_cannot_silently_omit_their_additional_native_inputs() {
    let mut f = Fixture::new(89);
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    for row in catalog::registered()
        .unwrap()
        .into_iter()
        .filter(|r| !supported(&r.id, r.version))
    {
        let before = f.head();
        let req = f.request(&row.id, source);
        let result = f.book.certify_procedure(&f.cx(), PRINCIPAL, &cap(&["read", "produce"]), &req).unwrap();
        if extended::supported(&row.id, row.version) {
            let mut certificate = result.unwrap().certificate;
            assert_eq!(certificate.supplemental_inputs().len(), extended::COUNT);
            certificate.extended_inputs.clear();
            assert!(certificate.body().is_err(), "a v1 downgrade cannot erase {} inputs", row.id);
        } else {
            assert!(result.is_err(), "unaudited new procedures must remain refused");
        }
        assert_eq!(f.head(), before);
    }
    assert!(!supported("future.unaudited", 1) && !extended::supported("future.unaudited", 1));
}

#[test]
fn all_four_network_paths_survive_the_full_certificate_round_trip() {
    let mut f = Fixture::new(82);
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    f.post(2, "1000", "1010", 80, false);
    f.post(3, "1010", "1020", 60, false);
    f.post(4, "1020", "6000", 10, false);
    for id in [
        "trace.network_fifo",
        "trace.network_lifo",
        "trace.network_libr",
        "trace.network_pro_rata",
    ] {
        let c = f.certify(&f.request(id, source)).certificate;
        let replayed = f
            .book
            .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &c)
            .unwrap()
            .unwrap();
        assert_eq!(
            replayed
                .findings
                .iter()
                .map(|f| f.statistic.value)
                .sum::<i128>(),
            100
        );
        let spent = replayed
            .findings
            .iter()
            .find(|f| f.statistic.name == "spent_mantissa")
            .unwrap();
        assert_eq!(spent.statistic.value, 10);
        assert_eq!(spent.cites.len(), 14);
        for cite in &spent.cites {
            assert!(
                cite.resolves(&f.book.db, f.book.context(), c.known_at())
                    .unwrap()
            );
        }
    }
}

#[test]
fn intact_rehashed_false_output_is_not_mistaken_for_a_successful_replay() {
    let mut f = Fixture::new(83);
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    let mut c = f
        .certify(&f.request("trace.network_fifo", source))
        .certificate;
    c.report.findings[0].statistic.value += 1;
    let mut w = Writer::new();
    w.str(&c.report.procedure)
        .u16(c.report.version)
        .fixed(&c.report.parameters_digest)
        .fixed(&c.report.inputs_digest);
    c.report.coordinate.encode(&mut w);
    w.list(&c.report.findings, |w, f| f.encode(w));
    c.report.findings_digest = raw_digest(fa_lantern::FINDINGS_DIGEST_DOMAIN, &w.finish().unwrap());
    c.output = encode_run(&c.report).unwrap();
    c.digest = domain_digest(CERTIFICATE_DOMAIN, &[&c.body().unwrap()]);
    let intact = ProcedureCertificate::decode(&c.canonical_bytes().unwrap())
        .expect("public hashes repaired; integrity is not historical validity");
    let refusal = f
        .book
        .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &intact)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.exit, exit::VERIFICATION);
    assert!(refusal.message.contains("does not replay"));
}

#[test]
fn authority_and_full_scope_are_current_not_inherited_from_the_saved_producer() {
    let mut f = Fixture::new(84);
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    let req = f.request("trace.network_fifo", source);
    let c = f.certify(&req).certificate;
    let bytes = c.canonical_bytes().unwrap();
    assert!(
        f.book
            .certify_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &req)
            .unwrap()
            .is_err()
    );
    for cap in [
        cap(&["post"]),
        cap(&["read"]).expiring_at(f.head()),
        cap(&["read"]).for_accounts(&["1000"]).unwrap(),
        cap(&["read"]).for_books(&[Id128([255; 16])]).unwrap(),
    ] {
        let r = f
            .book
            .replay_report_artifact(&f.cx(), PRINCIPAL, &cap, b"bad", None)
            .unwrap()
            .unwrap_err();
        assert_ne!(
            r.code,
            crate::certificate::code::CERTIFICATE_INVALID,
            "authority precedes decoder"
        );
    }
    assert!(
        f.book
            .replay_procedure(&f.cx(), VId(99), &cap(&["read"]), &c)
            .unwrap()
            .is_err()
    );
    assert!(
        f.book
            .replay_report_artifact(&f.cx(), PRINCIPAL, &cap(&["read"]), &bytes, Some(&[0; 32]))
            .unwrap()
            .is_err()
    );
    let other = Fixture::new(85);
    assert!(
        other
            .book
            .replay_procedure(&other.cx(), PRINCIPAL, &cap(&["read"]), &c)
            .unwrap()
            .is_err()
    );
}

#[test]
fn truncation_unknown_format_wrong_epoch_and_mixed_native_snapshots_are_refused() {
    let mut f = Fixture::new(86);
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    let c = f
        .certify(&f.request("trace.network_fifo", source))
        .certificate;
    let bytes = c.canonical_bytes().unwrap();
    for end in [0, 1, 8, 30, bytes.len() / 2, bytes.len() - 1] {
        assert!(ProcedureCertificate::decode(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ProcedureCertificate::decode(&trailing).is_err());
    let mut bad = bytes;
    bad[4] ^= 1;
    assert!(ProcedureCertificate::decode(&bad).is_err());
    let mut changed = c.clone();
    changed.registry[0] ^= 1;
    changed.digest = domain_digest(CERTIFICATE_DOMAIN, &[&changed.body().unwrap()]);
    let intact = ProcedureCertificate::decode(&changed.canonical_bytes().unwrap()).unwrap();
    assert!(
        f.book
            .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &intact)
            .unwrap()
            .is_err()
    );
    f.post(2, "1000", "1010", 10, false);
    let later = f
        .certify(&f.request("trace.network_fifo", source))
        .certificate;
    let mut mixed = c;
    mixed.approvals = later.approvals;
    assert!(
        mixed.body().is_err(),
        "never mix native input snapshots even after repairing outer hashes"
    );
}

#[test]
fn rewriting_an_approval_outside_the_entry_accumulator_blocks_historical_replay() {
    let mut f = Fixture::new(87);
    let (source, approval) = f.post(1, "3000", "1000", 100, true);
    let certificate = f
        .certify(&f.request("jet.self_approved", source))
        .certificate;
    assert!(certificate.report.findings.is_empty());
    let approval = approval.expect("a real recorded approval");
    // The kernel correctly refuses self-approval. Use an admitted independent
    // review: even a no-finding JET run must bind the actual Approval record.
    assert!(
        f.book
            .db
            .vertex_at(approval, certificate.known_at())
            .unwrap()
            .expect("retained independent approval")
            .labels
            .contains(&label::APPROVAL)
    );
    assert!(
        f.book
            .replay_procedure(&f.cx(), PRINCIPAL, &cap(&["read"]), &certificate)
            .unwrap()
            .is_ok(),
        "baseline replay before rewriting the approval"
    );
    let mut batch = fgdb::WriteBatch::new(fa_model::symbols::relation::SUPERSEDES);
    batch.set_vertex_property(
        approval,
        property::FA_DIGEST,
        Some(fgdb_types::CanonicalScalar::bytes(vec![0; 32]).unwrap()),
    );
    let cx = f.cx();
    f.runtime
        .block_on(f.book.db.write(&cx.commit(), batch))
        .unwrap();
    // Native historical replay alone still sees the old row. The additional
    // immutable-approval check must reject a current-head rewrite nonetheless.
    let refusal = f
        .book
        .replay_procedure(&cx, PRINCIPAL, &cap(&["read"]), &certificate)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.exit, exit::VERIFICATION);
    assert!(refusal.message.contains("approval"));
}

#[test]
fn revocation_after_certification_cannot_be_undone_by_a_historical_selector() {
    let mut f = Fixture::new(88);
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    let certificate = f
        .certify(&f.request("trace.network_fifo", source))
        .certificate;
    let reader = cap(&["read"]);
    let cx = f.cx();
    let revoked = reader.commitment().unwrap();
    f.runtime
        .block_on(f.book.revoke_capability(
            &cx,
            cap(&["issue_capability"]),
            revoked,
            day(2),
            b"revoke-analytic-reader",
            "Revoke this reader",
        ))
        .unwrap()
        .unwrap();
    let refusal = f
        .book
        .replay_procedure(&cx, PRINCIPAL, &reader, &certificate)
        .unwrap()
        .unwrap_err();
    assert_ne!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
    assert!(refusal.message.to_lowercase().contains("revok"));
}

#[test]
fn incomplete_or_misspecified_runs_never_receive_a_certificate() {
    let mut f = Fixture::new(90);
    let (source, _) = f.post(1, "3000", "1000", 100, false);
    f.post(2, "1000", "1010", 80, false);
    let before = f.head();
    let capability = cap(&["read", "produce"]);
    for id in [
        "trace.network_fifo",
        "trace.network_lifo",
        "trace.network_libr",
        "trace.network_pro_rata",
    ] {
        let mut request = f.request(id, source);
        request.parameters = request.parameters.set("max_hops", 1).unwrap();
        let error = f
            .book
            .certify_procedure(&f.cx(), PRINCIPAL, &capability, &request)
            .expect_err("a partial bounded computation cannot be a CertifiedProcedure");
        assert!(
            matches!(error, BookError::Lantern(fa_lantern::LanternError::Parameter { name, .. }) if name == "max_hops")
        );
        assert_eq!(f.head(), before);
        request.parameters = Params::defaults(id).unwrap();
        request.inputs.source = None;
        assert!(
            f.book
                .certify_procedure(&f.cx(), PRINCIPAL, &capability, &request)
                .unwrap()
                .is_err(),
            "required source handle: {id}"
        );
        assert_eq!(f.head(), before);
    }
    let mut request = f.request("jet.round_amounts", source);
    request.inputs.account = Some(f.id("1000"));
    assert!(
        f.book
            .certify_procedure(&f.cx(), PRINCIPAL, &capability, &request)
            .unwrap()
            .is_err(),
        "an undeclared handle cannot silently change scope"
    );
    request.inputs = catalog::Inputs::default();
    request.parameters = Params::defaults("jet.thin_descriptions").unwrap();
    assert!(
        matches!(f.book.certify_procedure(&f.cx(), PRINCIPAL, &capability, &request),
        Err(BookError::Lantern(fa_lantern::LanternError::Parameter { name, .. })) if name == "params")
    );
    assert_eq!(f.head(), before);
}

#[path = "tests/extended.rs"]
mod input_cases;
