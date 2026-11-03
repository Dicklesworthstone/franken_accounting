//! Source completeness is a native admission law, even when omitted economic
//! events cancel exactly and the old net trial-balance controls still agree.

use super::*;
use fa_journal::migration::{SourceChunk, SourceManifest};
use fa_model::symbols::label;
use fa_model::{Writer, migration_entry_vid};
use fgdb::WriteBatch;
use fgdb_types::CommitSeq;

fn package(h: &mut Harness, run_vid: VId, proposals: &[EntryPayload]) -> (SourceManifest, Vec<u8>) {
    let run = migration::read_run(&h.db, run_vid, None).unwrap().unwrap();
    let mut writer = Writer::new();
    writer
        .fixed(b"FA-LEGACY-OPENING-IMPORT\0")
        .u16(1)
        .fixed(&h.book.book_id.0)
        .u128(run_vid.0)
        .fixed(&run.body.digest().unwrap())
        .fixed(&h.evidence[0].document_oid.0)
        .fixed(&h.evidence[0].doc_commit);
    h.statement("retained source mapping", 83)
        .encode(&mut writer);
    writer.list(proposals, |writer, proposal| {
        writer.bytes(
            &proposal
                .clone()
                .seal(Vec::new(), None)
                .unwrap()
                .encode()
                .unwrap(),
        );
    });
    let bytes = writer.finish().unwrap();
    let document = h.document(RECEIPT, HUMAN_UPLOAD, &bytes);
    let store = blob_store(h, "migration-source-package");
    let added = h.add_external_to(&store, &document).unwrap();
    let manifest = SourceManifest {
        book_id: h.book.book_id,
        run_ref: run_vid,
        run_body_digest: run.body.digest().unwrap(),
        source_oid: h.evidence[0].document_oid,
        source_commit: h.evidence[0].doc_commit,
        package_oid: added.oid,
        package_commit: added.doc_commit,
        source_rows: proposals.len() as u64 * 2,
        chunks: proposals
            .iter()
            .map(|proposal| SourceChunk {
                entry_vid: migration_entry_vid(h.book.book_id, run_vid, &proposal.idempotency_key),
                proposal_digest: proposal.proposal_digest().unwrap(),
            })
            .collect(),
    };
    (manifest, bytes)
}

fn binding_request(h: &Harness, manifest: &SourceManifest) -> RunControlRequest {
    let run = migration::read_run(&h.db, manifest.run_ref, None)
        .unwrap()
        .unwrap();
    RunControlRequest {
        proposal: migration::source_binding_proposal(
            &h.book,
            PRINCIPAL,
            &run,
            manifest,
            h.statement("bind retained package", 84),
        )
        .unwrap(),
        capability: Capability::embedded(PRINCIPAL, &["migrate"]).unwrap(),
        approvals: Vec::new(),
    }
}

fn bind(
    h: &mut Harness,
    manifest: &SourceManifest,
    bytes: &[u8],
    request: RunControlRequest,
) -> Result<RunControlled, Refusal> {
    let ctx = h.ctx();
    h.runtime
        .block_on(migration::bind_source(
            &mut h.db, &ctx, &h.book, manifest, bytes, request,
        ))
        .expect("source binding kernel")
}

fn missing_population(h: &Harness, run: VId) -> migration::TieOut {
    let run = migration::read_run(&h.db, run, None).unwrap().unwrap();
    migration::tie_out(&h.db, &h.book, &run, h.db.frontier().unwrap()).unwrap()
}

#[test]
fn equal_net_control_cannot_finalize_an_omitted_increase_and_exact_reversal() {
    let mut h = lock_opening(harness());
    let run = open(&mut h, "source-net-zero", &[("1000", 100), ("4000", -100)]);
    let proposals = [
        chunk(&h, run, cash_legs(&h, 100), b"source-opening"),
        chunk(&h, run, cash_legs(&h, 700), b"source-increase"),
        chunk(&h, run, cash_legs(&h, -700), b"source-reversal"),
    ];
    let (manifest, bytes) = package(&mut h, run, &proposals);
    let request = binding_request(&h, &manifest);
    let bound = bind(&mut h, &manifest, &bytes, request.clone()).unwrap();
    assert_eq!(bound.kind, migration::kind::BIND_SOURCE);
    let first = stage(&mut h, proposals[0].clone()).unwrap();
    let tie = missing_population(&h, run);
    assert!(
        tie.mismatches.is_empty(),
        "the omitted pair cancels exactly"
    );
    let source = tie.source.unwrap();
    assert!(!source.complete());
    assert_eq!((source.recorded_chunks, source.expected_chunks), (1, 3));
    assert_eq!(source.missing_chunks.len(), 2);
    let head = h.db.frontier().unwrap();
    let refusal = migration::plan_run_transition(
        &h.db,
        &h.book,
        run,
        migration::kind::FINALIZE,
        PRINCIPAL,
        b"incomplete-finalize",
        h.statement("cannot omit source pair", 85),
    )
    .unwrap()
    .unwrap_err();
    assert_eq!(refusal.code, code::TIE_OUT_MISMATCH);
    assert_eq!(h.db.frontier().unwrap(), head);

    // Bypass the transition planner too: real native Finalize must still refuse.
    let run_body = migration::read_run_body_at(&h.db, run, head)
        .unwrap()
        .unwrap();
    let forged = migration::control_proposal(
        &h.book,
        PRINCIPAL,
        run,
        run_body.digest().unwrap(),
        migration::kind::FINALIZE,
        missing_population(&h, run).digest,
        run_body.opening_date,
        b"direct-incomplete-finalize",
        h.statement("direct incomplete attempt", 86),
        Vec::new(),
    );
    let authorized = approvals(&mut h, &forged);
    let refusal = transition(
        &mut h,
        RunControlRequest {
            proposal: forged,
            capability: Capability::embedded(PRINCIPAL, &["migrate"]).unwrap(),
            approvals: authorized,
        },
    )
    .unwrap_err();
    assert_eq!(refusal.code, code::TIE_OUT_MISMATCH);

    // Source order is immutable, but native publication order is independent.
    stage(&mut h, proposals[2].clone()).unwrap();
    stage(&mut h, proposals[1].clone()).unwrap();
    let tie = missing_population(&h, run);
    assert!(tie.source.unwrap().complete());
    assert!(tie.mismatches.is_empty());
    let finalize = control(&mut h, run, migration::kind::FINALIZE, b"complete-source");
    transition(&mut h, finalize).unwrap();
    let head = h.db.frontier().unwrap();
    migration::verify_run_visibility_at(&h.db, &h.book, head).unwrap();
    let again = bind(&mut h, &manifest, &bytes, request).unwrap();
    assert!(again.already_recorded);
    assert_eq!(again.recorded_at, bound.recorded_at);
    let retry = h.request(proposals[0].clone(), &["migrate", "post"]);
    assert_eq!(h.post(retry).unwrap().entry_ref(), first.entry_ref());
    assert_eq!(
        h.db.frontier().unwrap(),
        head,
        "exact finalized retries publish nothing"
    );
}

#[test]
fn native_bind_refuses_subset_laundering_reordering_wrong_bytes_and_late_binding() {
    let mut h = lock_opening(harness());
    let run = open(
        &mut h,
        "source-exact-package",
        &[("1000", 100), ("4000", -100)],
    );
    let proposals = [
        chunk(&h, run, cash_legs(&h, 100), b"package-a"),
        chunk(&h, run, cash_legs(&h, 90), b"package-b"),
        chunk(&h, run, cash_legs(&h, -90), b"package-c"),
    ];
    let (manifest, bytes) = package(&mut h, run, &proposals);
    let mut subset = manifest.clone();
    subset.chunks.truncate(1);
    let mut reordered = manifest.clone();
    reordered.chunks.swap(0, 1);
    let mut changed = manifest.clone();
    changed.chunks[1].proposal_digest[0] ^= 1;
    let mut self_citing = manifest.clone();
    self_citing.package_oid = self_citing.source_oid;
    self_citing.package_commit = self_citing.source_commit;
    for invalid in [subset, reordered, changed, self_citing] {
        let request = binding_request(&h, &invalid);
        let head = h.db.frontier().unwrap();
        let refusal = bind(&mut h, &invalid, &bytes, request).unwrap_err();
        assert_eq!(refusal.code, code::TIE_OUT_MISMATCH);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert!(h.db.vertex(manifest.vid()).unwrap().is_none());
    }
    let mut modified_bytes = bytes.clone();
    modified_bytes[0] ^= 1;
    let request = binding_request(&h, &manifest);
    assert_eq!(
        bind(&mut h, &manifest, &modified_bytes, request)
            .unwrap_err()
            .code,
        code::TIE_OUT_MISMATCH
    );
    let mut wrong_citation = proposals.clone();
    wrong_citation[1].evidence[0].doc_commit[0] ^= 1;
    let (wrong_manifest, wrong_package) = package(&mut h, run, &wrong_citation);
    let request = binding_request(&h, &wrong_manifest);
    assert_eq!(
        bind(&mut h, &wrong_manifest, &wrong_package, request)
            .unwrap_err()
            .code,
        code::TIE_OUT_MISMATCH,
        "authentic package bytes cannot launder a conflicting source commitment"
    );
    // A legacy run with an already-published chunk cannot manufacture a later
    // native completeness claim, even from a perfectly matching source file.
    stage(&mut h, proposals[0].clone()).unwrap();
    let request = binding_request(&h, &manifest);
    let head = h.db.frontier().unwrap();
    assert_eq!(
        bind(&mut h, &manifest, &bytes, request).unwrap_err().code,
        code::TIE_OUT_MISMATCH
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert!(missing_population(&h, run).source.is_none());
}

#[test]
fn native_stage_rejects_foreign_or_changed_members_and_binding_is_immutable() {
    let mut h = lock_opening(harness());
    let run = open(&mut h, "source-admission", &[("1000", 100), ("4000", -100)]);
    let original = chunk(&h, run, cash_legs(&h, 100), b"source-member");
    let (manifest, bytes) = package(&mut h, run, &[original.clone()]);
    let request = binding_request(&h, &manifest);
    bind(&mut h, &manifest, &bytes, request).unwrap();
    let foreign = chunk(&h, run, cash_legs(&h, 100), b"foreign-member");
    let changed = chunk(&h, run, cash_legs(&h, 200), b"source-member");
    for proposal in [foreign, changed] {
        // Pass all existing dual-human Migration approval rules; only source
        // membership should cause refusal, without a chunk publication.
        let refs = approvals(&mut h, &proposal);
        let mut request = h.request(proposal, &["migrate", "post"]);
        request.approvals = refs;
        let head = h.db.frontier().unwrap();
        assert_eq!(h.post(request).unwrap_err().code, code::TIE_OUT_MISMATCH);
        assert_eq!(h.db.frontier().unwrap(), head);
    }
    let mut replacement = manifest.clone();
    replacement.source_rows += 1;
    let request = binding_request(&h, &replacement);
    assert_eq!(
        bind(&mut h, &replacement, &bytes, request)
            .unwrap_err()
            .code,
        code::TIE_OUT_MISMATCH
    );
    stage(&mut h, original).unwrap();
    assert!(missing_population(&h, run).source.unwrap().complete());
}

#[test]
fn fragmented_source_retains_prefix_integrity_and_ignores_state_projection_for_read() {
    let mut h = lock_opening(harness());
    let run = open(&mut h, "source-fragments", &[("1000", 100), ("4000", -100)]);
    let proposals: Vec<_> = (0..100)
        .map(|index| {
            chunk(
                &h,
                run,
                cash_legs(&h, 1),
                format!("member-{index}").as_bytes(),
            )
        })
        .collect();
    let (manifest, bytes) = package(&mut h, run, &proposals);
    assert!(manifest.canonical_bytes().unwrap().len() > 4096);
    let request = binding_request(&h, &manifest);
    let bound = bind(&mut h, &manifest, &bytes, request).unwrap();
    let fragments: Vec<_> =
        h.db.vertices_at(bound.recorded_at)
            .unwrap()
            .into_iter()
            .filter(|row| row.labels == [label::MIGRATION_SOURCE_FRAGMENT])
            .collect();
    assert!(fragments.len() >= 2);
    assert!(
        fragments
            .iter()
            .all(|row| row.created_at == bound.recorded_at)
    );
    assert_eq!(
        migration::read_source_manifest_at(&h.db, h.book.book_id, run, bound.recorded_at).unwrap(),
        Some(manifest.clone())
    );
    // A proof producer reads immutable source and original body, never STATE.
    let mut write = WriteBatch::new(relation::IN_MIGRATION_RUN);
    write.set_vertex_property(run, property::STATE, Some(CanonicalScalar::Int(99)));
    let ctx = h.ctx();
    h.runtime
        .block_on(h.db.write(&ctx.commit(), write))
        .unwrap();
    let head = h.db.frontier().unwrap();
    assert_eq!(
        migration::read_source_manifest_at(&h.db, h.book.book_id, run, head).unwrap(),
        Some(manifest.clone())
    );
    assert!(migration::verify_run_visibility_at(&h.db, &h.book, head).is_err());
    let fragment = &fragments[0];
    let mut write = WriteBatch::new(relation::IN_MIGRATION_RUN);
    write.set_vertex_property(
        fragment.vid,
        property::FA_PAYLOAD,
        Some(fa_journal::rows::scalar_bytes("tampered source fragment", vec![1, 2, 3]).unwrap()),
    );
    h.runtime
        .block_on(h.db.write(&ctx.commit(), write))
        .unwrap();
    assert!(
        migration::read_source_manifest_at(&h.db, h.book.book_id, run, h.db.frontier().unwrap())
            .is_err()
    );
    assert_eq!(
        migration::read_source_manifest_at(&h.db, h.book.book_id, run, bound.recorded_at).unwrap(),
        Some(manifest)
    );
    assert!(
        migration::read_source_manifest_at(
            &h.db,
            h.book.book_id,
            run,
            CommitSeq(bound.recorded_at.0 - 1)
        )
        .unwrap()
        .is_none()
    );
}
