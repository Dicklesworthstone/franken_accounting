use super::*;
use crate::{ProcedureRequest, RetainedCertificate};
use fa_model::symbols::{label, property, relation};
use fgdb::WriteBatch;

fn retain(h: &mut Harness, artifact: &ReportArtifact) -> RetainedCertificate {
    let cx = h.cx();
    h.runtime
        .block_on(h.book.retain_report_artifact(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &artifact.canonical_bytes().unwrap(),
            Some(artifact.digest()),
        ))
        .unwrap()
        .unwrap()
}

fn read(h: &Harness, digest: &[u8; 32]) -> Result<ReportArtifact, Refusal> {
    h.runtime
        .block_on(h.book.read_report_artifact(&h.cx(), PRINCIPAL, &cap(&["read"]), digest))
        .unwrap()
}

fn reopen(h: Harness) -> Harness {
    let Harness { runtime, root, book, vfs, seed, unit, evidence } = h;
    drop(book);
    let cx = PurposeContexts::narrow_runtime_root(&root);
    let book = runtime
        .block_on(AsyncBook::open_with_vfs(
            &cx,
            vfs.clone(),
            Path::new("artifact-book"),
            BookKeys::for_development(seed),
            Entropy::deterministic(u64::from(seed)),
        ))
        .unwrap();
    Harness { runtime, root, book, vfs, seed, unit, evidence }
}

fn journal_count(h: &Harness) -> usize {
    h.book.query(&h.cx(), |db, book| {
        Ok(fa_registers::entries_at(db, book, db.frontier().map_err(KernelError::from)?)?.len())
    }).unwrap()
}

#[test]
fn original_families_and_all_network_laws_are_retained_reopened_and_replayed_by_digest() {
    let mut h = Harness::new(91);
    let at = h.head();
    let source = h.book.query(&h.cx(), |db, book| {
        Ok(fa_registers::entries_at(db, book, at)?.into_iter()
            .find(|(_, entry, _)| entry.proposal.class == EntryClass::ORIGINAL).unwrap().0)
    }).unwrap();
    let mut artifacts = h.artifacts();
    for id in ["trace.network_fifo", "trace.network_lifo", "trace.network_libr", "trace.network_pro_rata"] {
        let mut request = ProcedureRequest::new(id, fa_lantern::catalog::Inputs {
            account: Some(h.id("1000")), source: Some(source),
        }).unwrap();
        request.known_at = Some(at);
        request.effective_through = Some(day(20));
        let certified = h.book.certify_procedure(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), &request)
            .unwrap().unwrap();
        artifacts.push(ReportArtifact::try_from(&certified.certificate).unwrap());
    }
    let entries = journal_count(&h);
    let mut receipts = Vec::new();
    for artifact in &artifacts {
        let before = h.head();
        let receipt = retain(&mut h, artifact);
        assert_eq!(receipt.recorded_at.0, before.0 + 1, "one publication per complete artifact");
        assert_eq!(receipt.digest, *artifact.digest());
        assert_eq!(journal_count(&h), entries, "retention never adds an Entry");
        assert_eq!(read(&h, artifact.digest()).unwrap(), *artifact);
        let head = h.head();
        assert_eq!(retain(&mut h, artifact), receipt);
        assert_eq!(h.head(), head, "an exact retry is a no-op");
        receipts.push(receipt);
    }
    h = reopen(h);
    h.post(b"later backdated source", 17);
    let head = h.head();
    for (artifact, receipt) in artifacts.iter().zip(receipts) {
        assert_eq!(read(&h, artifact.digest()).unwrap().canonical_bytes().unwrap(), artifact.canonical_bytes().unwrap());
        let replayed = h.runtime.block_on(h.book.replay_retained_report_artifact(
            &h.cx(), PRINCIPAL, &cap(&["read"]), artifact.digest(), ReportArtifactExpectation::AsSupplied,
        )).unwrap().unwrap();
        assert_eq!(replayed.output, artifact.output());
        assert_eq!(replayed.known_at, at);
        assert_eq!(replayed.family, artifact.family());
        assert_eq!(retain(&mut h, artifact), receipt);
        assert_eq!(h.head(), head, "lookup, replay and duplicate retention preserve the frontier");
        if artifact.family() != ReportArtifactFamily::Native {
            assert!(h.runtime.block_on(h.book.read_certificate(&h.cx(), artifact.digest())).unwrap().is_err(),
                "a typed native lookup must not return a non-native artifact's nested source");
        }
    }
}

#[test]
fn retention_and_lookup_require_current_whole_book_authority_before_inspecting_input() {
    let mut h = Harness::new(92);
    let artifact = h.artifacts().remove(1);
    let at = h.head();
    for authority in [
        cap(&["read"]),
        cap(&["produce"]),
        cap(&["read", "produce"]).expiring_at(at),
        cap(&["read", "produce"]).for_books(&[Id128([255; 16])]).unwrap(),
        cap(&["read", "produce"]).for_accounts(&["1000"]).unwrap(),
    ] {
        let cx = h.cx();
        let refusal = h.runtime.block_on(h.book.retain_report_artifact(
            &cx, PRINCIPAL, &authority, b"not a certificate", None,
        )).unwrap().unwrap_err();
        assert_eq!(refusal.exit, fa_journal::exit::SAFETY);
        assert_eq!(h.head(), at);
    }
    retain(&mut h, &artifact);
    let head = h.head();
    for authority in [cap(&["post"]), cap(&["read"]).for_accounts(&["1000"]).unwrap(), cap(&["read"]).expiring_at(head)] {
        let refusal = h.runtime.block_on(h.book.read_report_artifact(
            &h.cx(), PRINCIPAL, &authority, artifact.digest(),
        )).unwrap().unwrap_err();
        assert_eq!(refusal.exit, fa_journal::exit::SAFETY);
    }
    let cx = h.cx();
    assert_eq!(h.runtime.block_on(h.book.retain_report_artifact(
        &cx, VId(99), &cap(&["read", "produce"]), b"bad", None,
    )).unwrap().unwrap_err().exit, fa_journal::exit::SAFETY);
    assert_eq!(h.head(), head);
}

#[test]
fn rehashed_false_output_wrong_digest_and_wrong_book_never_publish_a_storage_record() {
    let mut h = Harness::new(93);
    let artifact = h.artifacts().remove(1);
    let mut forged = artifact.canonical_bytes().unwrap();
    let end = forged.len() - 32;
    forged[end - 1] ^= 1;
    let digest = domain_digest(b"fa:summary-certificate-digest:v1", &[&forged[..end]]);
    forged[end..].copy_from_slice(&digest);
    assert!(ReportArtifact::decode(&forged).is_ok(), "test must reach replay, not hash rejection");
    let other = Harness::new(94).artifacts().remove(0).canonical_bytes().unwrap();
    let head = h.head();
    for (bytes, expected) in [
        (forged, digest),
        (artifact.canonical_bytes().unwrap(), [0; 32]),
        (other, *artifact.digest()),
    ] {
        let cx = h.cx();
        assert!(h.runtime.block_on(h.book.retain_report_artifact(
            &cx, PRINCIPAL, &cap(&["read", "produce"]), &bytes, Some(&expected),
        )).unwrap().is_err());
        assert_eq!(h.head(), head);
        assert!(read(&h, &expected).is_err());
    }
}

#[test]
fn fragmented_outer_artifacts_have_one_birth_and_cannot_be_rewritten_or_repaired() {
    let mut h = Harness::new(95);
    // A summary is compact regardless of posting count. Weekend findings retain
    // one real observation per Saturday posting and exercise the outer fragments.
    for i in 0..120u64 { h.post(&i.to_le_bytes(), 3); }
    let mut request = ProcedureRequest::new("jet.weekend", fa_lantern::catalog::Inputs::default()).unwrap();
    request.effective_through = Some(day(20));
    let certified = h.book.certify_procedure(
        &h.cx(), PRINCIPAL, &cap(&["read", "produce"]), &request,
    ).unwrap().unwrap();
    assert!(certified.report.findings.len() >= 120);
    let artifact = ReportArtifact::try_from(&certified.certificate).unwrap();
    assert!(artifact.canonical_bytes().unwrap().len() > crate::MAX_INLINE_CERTIFICATE_BYTES);
    let receipt = retain(&mut h, &artifact);
    let root = crate::certificate_store::certificate_vid(h.book.context().book_id, artifact.digest());
    let rows = h.book.query(&h.cx(), |db, _| {
        Ok(db.vertices_at(receipt.recorded_at).map_err(KernelError::from)?.into_iter()
            .filter(|row| row.labels.contains(&label::CERTIFICATE)).collect::<Vec<_>>())
    }).unwrap();
    assert!(rows.len() > 2);
    assert!(rows.iter().all(|row| row.created_at == receipt.recorded_at));
    h = reopen(h);
    assert_eq!(read(&h, artifact.digest()).unwrap(), artifact);
    let part = rows.iter().find(|row| row.vid != root).unwrap();
    let mut batch = WriteBatch::new(relation::DERIVED_FROM);
    batch.set_vertex_property(part.vid, property::FA_DIGEST, Some(fgdb_types::CanonicalScalar::bytes(vec![0; 32]).unwrap()));
    let cx = h.cx();
    h.runtime.block_on(h.book.db.write(&cx.commit(), batch)).unwrap();
    let changed = h.head();
    assert!(read(&h, artifact.digest()).is_err());
    assert!(h.runtime.block_on(h.book.retain_report_artifact(
        &cx, PRINCIPAL, &cap(&["read", "produce"]), &artifact.canonical_bytes().unwrap(), Some(artifact.digest()),
    )).unwrap().is_err());
    assert_eq!(h.head(), changed, "retry must not repair the fragment");
    let mut restore = WriteBatch::new(relation::DERIVED_FROM);
    restore.set_vertex_property(part.vid, property::FA_DIGEST,
        Some(fgdb_types::CanonicalScalar::bytes(artifact.digest().to_vec()).unwrap()));
    h.runtime.block_on(h.book.db.write(&cx.commit(), restore)).unwrap();
    assert!(read(&h, artifact.digest()).is_err(), "byte-identical restoration still violates original birth");
}

#[test]
fn reconciliation_retention_requires_the_independent_request_and_preserves_both_sources() {
    let mut h = Harness::new(96);
    let cx = h.cx();
    let request = AgingReconciliationRequest {
        account: h.id("1000"), effective_through: day(20), known_at: Some(h.head()),
        buckets: AgingBuckets::new(vec![30, 60, 90]).unwrap(),
    };
    let certified = h.book.certify_effective_date_aging_reconciliation(
        &cx, PRINCIPAL, &cap(&["read", "produce"]), &request,
    ).unwrap().unwrap();
    let artifact = ReportArtifact::try_from(&certified.certificate).unwrap();
    let bytes = artifact.canonical_bytes().unwrap();
    let before = h.head();
    assert!(h.runtime.block_on(h.book.retain_report_artifact(
        &cx, PRINCIPAL, &cap(&["read", "produce"]), &bytes, Some(artifact.digest()),
    )).unwrap().is_err());
    assert_eq!(h.head(), before);
    let receipt = h.runtime.block_on(h.book.retain_report_artifact_for(
        &cx, PRINCIPAL, &cap(&["read", "produce"]), &bytes, Some(artifact.digest()),
        ReportArtifactExpectation::AgingReconciliation(&request),
    )).unwrap().unwrap();
    h = reopen(h);
    let result = h.runtime.block_on(h.book.replay_retained_report_artifact(
        &h.cx(), PRINCIPAL, &cap(&["read"]), &receipt.digest,
        ReportArtifactExpectation::AgingReconciliation(&request),
    )).unwrap().unwrap();
    assert_eq!(result.output, artifact.output());
    assert_eq!(result.known_at, before);
}
