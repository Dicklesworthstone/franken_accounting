//! Immutable native membership for a retained legacy source package.

use fa_model::migration_source::{
    MAX_SOURCE_CHUNKS, MAX_SOURCE_MANIFEST_BYTES, source_manifest_vid,
};
use fa_model::{EntryOrigin, migration_entry_vid};

use super::*;

const MAX_PACKAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
pub const SOURCE_TIE_OUT_DOMAIN: &[u8] = b"fa:migration-tie-out:v2";

fn decode_error(error: DecodeError) -> KernelError {
    KernelError::Model(error.into())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceCoverage {
    pub manifest_digest: [u8; 32],
    pub source_rows: u64,
    pub expected_chunks: usize,
    pub recorded_chunks: usize,
    pub missing_chunks: Vec<VId>,
    pub unexpected_chunks: Vec<VId>,
}

impl SourceCoverage {
    #[must_use]
    pub fn complete(&self) -> bool {
        self.missing_chunks.is_empty()
            && self.unexpected_chunks.is_empty()
            && self.expected_chunks == self.recorded_chunks
    }
}

fn source_refusal(detail: impl Into<String>) -> Refusal {
    Refusal::new(
        code::TIE_OUT_MISMATCH,
        exit::REFUSAL,
        detail,
        "plan §5.8/§8.6 (immutable source membership, exact chunk digests and gap-free finalization)",
        "stage every original retained source chunk with its exact approved proposal; preserve the bound package and never replace or omit a source member",
    )
}

fn source_key(run: VId) -> Vec<u8> {
    format!("migration-source:v1:{:032x}", run.0).into_bytes()
}

fn citations(manifest: &SourceManifest) -> Vec<EvidenceRef> {
    let mut values = vec![
        EvidenceRef {
            document_oid: manifest.source_oid,
            doc_commit: manifest.source_commit,
            role: 1,
        },
        EvidenceRef {
            document_oid: manifest.package_oid,
            doc_commit: manifest.package_commit,
            role: 1,
        },
    ];
    values.sort();
    values.dedup();
    values
}

/// The caller retains the source package before constructing this proposal.
/// Binding never changes the original immutable RunBody or activates a chunk.
pub fn source_binding_proposal(
    book: &BookContext,
    principal: VId,
    run: &Run,
    manifest: &SourceManifest,
    description: Erasable<String>,
) -> Result<EntryPayload, KernelError> {
    Ok(control_proposal(
        book,
        principal,
        run.vid,
        run.body.digest()?,
        kind::BIND_SOURCE,
        manifest.digest()?,
        run.body.opening_date,
        &source_key(run.vid),
        description,
        citations(manifest),
    ))
}

fn validate_manifest(
    run_vid: VId,
    run_body: &RunBody,
    book: Id128,
    manifest: &SourceManifest,
) -> Outcome<()> {
    if let Some(problem) = manifest.problem() {
        return Ok(Err(source_refusal(problem)));
    }
    if manifest.source_oid == manifest.package_oid {
        return Ok(Err(source_refusal(
            "the retained import package must be distinct from its original source document",
        )));
    }
    if manifest.book_id != book
        || manifest.run_ref != run_vid
        || manifest.run_body_digest != run_body.digest()?
    {
        return Ok(Err(source_refusal(
            "source manifest names another book, run or immutable run body",
        )));
    }
    Ok(Ok(()))
}

/// Authenticate the full source package before accepting its smaller native
/// membership manifest. A caller cannot cite a complete package but bind only a
/// convenient subset. CSV parsing/mapping is still the explicit producer's job.
fn package_members(
    manifest: &SourceManifest,
    mode: RunMode,
    source_system: &str,
    bytes: &[u8],
) -> Result<(), KernelError> {
    let domain: &[u8] = match mode {
        RunMode::OpeningOnly => b"FA-LEGACY-OPENING-IMPORT\0",
        RunMode::PeriodBalances => b"FA-LEGACY-PERIOD-BALANCES-IMPORT\0",
        RunMode::FullDetail => b"FA-LEGACY-FULL-DETAIL-IMPORT\0",
    };
    if bytes.len() > MAX_PACKAGE_BYTES || !bytes.starts_with(domain) {
        return Err(KernelError::Corrupt(
            "source package has the wrong domain or exceeds its bound".into(),
        ));
    }
    let mut reader = Reader::new(&bytes[domain.len()..]);
    if reader.u16("source_package.version").map_err(decode_error)? != 1
        || Id128(reader.fixed("source_package.book").map_err(decode_error)?) != manifest.book_id
        || VId(reader.u128("source_package.run").map_err(decode_error)?) != manifest.run_ref
        || reader
            .fixed::<32>("source_package.run_body")
            .map_err(decode_error)?
            != manifest.run_body_digest
        || Oid(reader
            .fixed("source_package.source")
            .map_err(decode_error)?)
            != manifest.source_oid
        || reader
            .fixed::<32>("source_package.source_commit")
            .map_err(decode_error)?
            != manifest.source_commit
    {
        return Err(KernelError::Corrupt(
            "source package envelope differs from the manifest".into(),
        ));
    }
    let _configuration =
        Erasable::<String>::decode(&mut reader, MAX_REQUEST_BYTES).map_err(decode_error)?;
    let count = reader
        .count(MAX_SOURCE_CHUNKS, "source_package.proposals")
        .map_err(decode_error)?;
    if count != manifest.chunks.len() {
        return Err(KernelError::Corrupt(
            "source manifest omits or adds retained package proposals".into(),
        ));
    }
    for expected in &manifest.chunks {
        let bytes = reader
            .bytes(fa_model::limits::MAX_ENTRY_BYTES, "source_package.proposal")
            .map_err(decode_error)?;
        let entry = Entry::decode(bytes)?;
        let proposal = &entry.proposal;
        if !entry.approvals.is_empty()
            || entry.plan_certificate.is_some()
            || proposal.book_id != manifest.book_id
            || proposal.branch_id != Id128::TRUNK
            || proposal.class != EntryClass::MIGRATION
            || !proposal.evidence.contains(&EvidenceRef {
                document_oid: manifest.source_oid,
                doc_commit: manifest.source_commit,
                role: 1,
            })
            || proposal.evidence.iter().any(|evidence| {
                evidence.document_oid == manifest.source_oid
                    && evidence.doc_commit != manifest.source_commit
            })
            || !matches!(&proposal.origin,
                EntryOrigin::Migration { run_ref, source_system: system, batch_oid, .. }
                    if *run_ref == manifest.run_ref && system == source_system
                        && *batch_oid == manifest.source_oid)
            || migration_entry_vid(
                manifest.book_id,
                manifest.run_ref,
                &proposal.idempotency_key,
            ) != expected.entry_vid
            || entry.proposal_digest != expected.proposal_digest
        {
            return Err(KernelError::Corrupt(
                "source manifest changes a retained package proposal or its order".into(),
            ));
        }
    }
    reader.finish().map_err(decode_error)?;
    Ok(())
}

fn from_row<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: Id128,
    run_vid: VId,
    run_body: &RunBody,
    row: &VertexRow,
    at: CommitSeq,
) -> Result<SourceManifest, KernelError> {
    let corrupt = |message: &str| KernelError::Corrupt(format!("migration source: {message}"));
    if row.vid != source_manifest_vid(book, run_vid)
        || row.labels.as_slice() != [label::MIGRATION_SOURCE]
        || row.created_at > at
        || row.retired_at.is_some_and(|retired| retired <= at)
        || bytes(row, property::BOOK_ID, "source.book_id")? != book.0
    {
        return Err(corrupt("manifest root identity or birth differs"));
    }
    let raw = object::read_bounded(
        db,
        book,
        row,
        label::MIGRATION_SOURCE_FRAGMENT,
        ObjectKind::MigrationSource,
        at,
        MAX_SOURCE_MANIFEST_BYTES,
    )?;
    let manifest = SourceManifest::decode(&raw).map_err(decode_error)?;
    if let Err(refusal) = validate_manifest(run_vid, run_body, book, &manifest)? {
        return Err(corrupt(&refusal.to_string()));
    }
    let digest = manifest.digest()?;
    if bytes(row, property::FA_DIGEST, "source.digest")? != digest {
        return Err(corrupt("manifest digest differs"));
    }
    let pointer: [u8; 16] = bytes(row, property::TARGET_REF, "source.control")?
        .try_into()
        .map_err(|_| corrupt("invalid binding control reference"))?;
    let control_vid = VId(u128::from_le_bytes(pointer));
    let control_row = db
        .vertex_at(control_vid, at)?
        .ok_or_else(|| corrupt("binding control is missing"))?;
    let entry = Entry::decode(&bytes(
        &control_row,
        property::FA_PAYLOAD,
        "source.control.payload",
    )?)?;
    let proposal = &entry.proposal;
    if control_row.created_at != row.created_at
        || control_row.labels.as_slice() != [label::ENTRY]
        || control_row.retired_at.is_some_and(|retired| retired <= at)
        || entry_vid(
            book,
            &proposal.principal_ref.0.to_le_bytes(),
            &proposal.idempotency_key,
        ) != control_vid
    {
        return Err(corrupt(
            "manifest and binding control do not share their original publication",
        ));
    }
    if proposal.book_id != book
        || proposal.branch_id != Id128::TRUNK
        || proposal.class != EntryClass::MIGRATION_CONTROL
        || proposal.effective_period.is_some()
        || proposal.effective_date != run_body.opening_date
        || proposal.idempotency_key != source_key(run_vid)
        || proposal.evidence != citations(&manifest)
        || !matches!(proposal.control, Some(ControlPayload::MigrationControl {
            run_ref, kind: kind::BIND_SOURCE, tie_out_digest,
        }) if run_ref == run_vid && tie_out_digest == digest)
        || !matches!(proposal.origin, EntryOrigin::Control {
            control_kind: ControlKind::MIGRATION_RUN, spec_body_digest,
        } if spec_body_digest == manifest.run_body_digest)
    {
        return Err(corrupt(
            "binding control differs from its manifest or original run",
        ));
    }
    // Both roots are immutable. Restoring the same bytes after an edit is not
    // the original publication and cannot be blessed by its old control.
    if let Some(before) = row.created_at.0.checked_sub(1)
        && (db.vertex_at(row.vid, CommitSeq(before))?.is_some()
            || db.vertex_at(control_vid, CommitSeq(before))?.is_some())
    {
        return Err(corrupt(
            "source binding was rewritten after its native birth",
        ));
    }
    Ok(manifest)
}

/// Read the immutable source object and its original control at this prefix.
/// An absent root is legacy-unbound only if no BindSource control names it.
pub fn read_source_manifest_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: Id128,
    run_vid: VId,
    at: CommitSeq,
) -> Result<Option<SourceManifest>, KernelError> {
    if at > db.frontier()? {
        return Err(KernelError::Corrupt(
            "source manifest prefix exceeds the native head".into(),
        ));
    }
    let Some(body) = read_run_body_at(db, run_vid, at)? else {
        return Ok(None);
    };
    if let Some(row) = db.vertex_at(source_manifest_vid(book, run_vid), at)? {
        return from_row(db, book, run_vid, &body, &row, at).map(Some);
    }
    // This inspects authoritative control entries, not arbitrary documents.
    // A deleted manifest must never silently turn a bound run into legacy mode.
    for row in db.vertices_at(at)? {
        if row.labels.contains(&label::ENTRY) {
            let entry =
                Entry::decode(&bytes(&row, property::FA_PAYLOAD, "source control search")?)?;
            if matches!(entry.proposal.control, Some(ControlPayload::MigrationControl {
                run_ref, kind: kind::BIND_SOURCE, ..
            }) if run_ref == run_vid)
            {
                return Err(KernelError::Corrupt(
                    "bound migration source object is missing".into(),
                ));
            }
        }
    }
    Ok(None)
}

/// Native admission for any exact member, independent of submission order.
/// Even legacy absence is a point witness against a concurrent BindSource.
pub(crate) fn witness_source_member<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    run: &Run,
    proposal: &EntryPayload,
) -> Outcome<()> {
    let _root = txn.vertex(db, source_manifest_vid(book.book_id, run.vid))?;
    let Some(manifest) = read_source_manifest_at(db, book.book_id, run.vid, txn.basis())? else {
        return Ok(Ok(()));
    };
    let identity = migration_entry_vid(book.book_id, run.vid, &proposal.idempotency_key);
    let digest = proposal.proposal_digest()?;
    if !manifest
        .chunks
        .iter()
        .any(|chunk| chunk.entry_vid == identity && chunk.proposal_digest == digest)
    {
        return Ok(Err(source_refusal(
            "migration proposal is not an exact member of the bound source package",
        )));
    }
    Ok(Ok(()))
}

pub(crate) fn source_coverage(
    manifest: &SourceManifest,
    chunks: &[RunChunk],
) -> Result<SourceCoverage, KernelError> {
    let expected: BTreeMap<_, _> = manifest
        .chunks
        .iter()
        .map(|chunk| (chunk.entry_vid, chunk.proposal_digest))
        .collect();
    let actual: BTreeMap<_, _> = chunks
        .iter()
        .map(|chunk| (chunk.vid, chunk.proposal_digest))
        .collect();
    Ok(SourceCoverage {
        manifest_digest: manifest.digest()?,
        source_rows: manifest.source_rows,
        expected_chunks: manifest.chunks.len(),
        recorded_chunks: chunks.len(),
        missing_chunks: expected
            .iter()
            .filter_map(|(vid, digest)| (actual.get(vid) != Some(digest)).then_some(*vid))
            .collect(),
        unexpected_chunks: actual
            .iter()
            .filter_map(|(vid, digest)| (expected.get(vid) != Some(digest)).then_some(*vid))
            .collect(),
    })
}

pub(crate) fn completeness_refusal(run: &Run, source: &SourceCoverage) -> Refusal {
    source_refusal(format!(
        "run `{}` has {} of {} exact source chunks; {} missing and {} unexpected; equal net trial balances cannot establish source completeness",
        run.body.run_key,
        source.recorded_chunks,
        source.expected_chunks,
        source.missing_chunks.len(),
        source.unexpected_chunks.len(),
    ))
}

/// Atomically bind one immutable package population to an empty Open run.
/// The supplied package bytes must reproduce the retained public commitment.
pub async fn bind_source<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    manifest: &SourceManifest,
    package_bytes: &[u8],
    req: RunControlRequest,
) -> Outcome<RunControlled> {
    let proposal = &req.proposal;
    if let Err(refusal) = check_control(proposal, book, kind::BIND_SOURCE, manifest.run_ref) {
        return Ok(Err(refusal));
    }
    if let Err(refusal) = admit_control(db, book, &req, "BindSource")? {
        return Ok(Err(refusal));
    }
    if let Err(refusal) = crate::policy::capability_admitted(db, book, &req.capability)? {
        return Ok(Err(refusal));
    }
    let digest = proposal.proposal_digest()?;
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(refusal) = capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let root = source_manifest_vid(book.book_id, manifest.run_ref);
    if let Some(existing) = txn.vertex(db, root)? {
        let body = read_run_body_at(db, manifest.run_ref, txn.basis())?
            .ok_or_else(|| KernelError::Corrupt("source binding has no run".into()))?;
        let retained = from_row(
            db,
            book.book_id,
            manifest.run_ref,
            &body,
            &existing,
            txn.basis(),
        )?;
        if retained != *manifest {
            txn.abort();
            return Ok(Err(source_refusal(
                "migration source population is immutable; a different package or manifest cannot replace it",
            )));
        }
        let pointer: [u8; 16] = bytes(&existing, property::TARGET_REF, "source.control")?
            .try_into()
            .map_err(|_| KernelError::Corrupt("source control identity length".into()))?;
        let row = txn
            .vertex(db, VId(u128::from_le_bytes(pointer)))?
            .ok_or_else(|| KernelError::Corrupt("source binding control is missing".into()))?;
        txn.abort();
        return recorded_or_conflict(book, &row, proposal, &digest, manifest.run_ref);
    }
    let run = match witness_open(&txn, db, manifest.run_ref)? {
        Ok(run) => run,
        Err(refusal) => {
            txn.abort();
            return Ok(Err(refusal));
        }
    };
    if let Err(refusal) = validate_manifest(run.vid, &run.body, book.book_id, manifest)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let expected = source_binding_proposal(
        book,
        proposal.principal_ref,
        &run,
        manifest,
        proposal.description.clone(),
    )?;
    if *proposal != expected {
        txn.abort();
        return Ok(Err(source_refusal(
            "source binding proposal differs from the exact manifest, evidence or fixed identity",
        )));
    }
    let tie = tie_out(db, book, &run, txn.basis())?;
    if !tie.chunks.is_empty() {
        txn.abort();
        return Ok(Err(source_refusal(
            "bind the complete source before the first staged chunk; late binding is refused",
        )));
    }
    if let Err(refusal) = authorize(&txn, db, book, &req, &digest, "BindSource")? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let policy =
        EvidencePolicy::embedded().map_err(|error| KernelError::Corrupt(error.to_string()))?;
    let documents = match resolve_documents(&txn, db, &policy, &proposal.evidence)? {
        Ok(documents) => documents,
        Err(refusal) => {
            txn.abort();
            return Ok(Err(refusal));
        }
    };
    let package_row = txn
        .vertex(db, crate::evidence::document_vid(&manifest.package_oid))?
        .ok_or_else(|| KernelError::Corrupt("resolved package document is missing".into()))?;
    let record =
        crate::evidence::verify_row(&package_row, &policy).map_err(KernelError::Corrupt)?;
    if package_bytes.len() > MAX_PACKAGE_BYTES
        || record.with_bytes(package_bytes.to_vec()).is_none()
    {
        txn.abort();
        return Ok(Err(source_refusal(
            "supplied package bytes do not reproduce the retained document commitment",
        )));
    }
    if let Err(error) = package_members(
        manifest,
        run.body.mode,
        &run.body.source_system,
        package_bytes,
    ) {
        txn.abort();
        return Ok(Err(source_refusal(error.to_string())));
    }
    let bytes = manifest.canonical_bytes()?;
    let evid = control_vid(book, proposal);
    let entry = proposal.clone().seal(req.approvals.clone(), None)?;
    let mut batch = WriteBatch::new(relation::IN_MIGRATION_RUN);
    object::stage(
        &ctx.query(),
        &mut batch,
        book.book_id,
        root,
        label::MIGRATION_SOURCE_FRAGMENT,
        ObjectKind::MigrationSource,
        &bytes,
    )?;
    batch.create_vertex(
        root,
        vec![label::MIGRATION_SOURCE],
        vec![
            (
                property::FA_PAYLOAD,
                scalar_bytes(
                    "source.payload",
                    object::payload(ObjectKind::MigrationSource, &bytes)?,
                )?,
            ),
            (
                property::FA_DIGEST,
                scalar_bytes("source.digest", manifest.digest()?.to_vec())?,
            ),
            (
                property::BOOK_ID,
                scalar_bytes("source.book", book.book_id.0.to_vec())?,
            ),
            (
                property::TARGET_REF,
                scalar_bytes("source.control", evid.0.to_le_bytes().to_vec())?,
            ),
        ],
    );
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    batch.add_edge(
        edge_id(relation::IN_MIGRATION_RUN, evid, run.vid),
        evid,
        run.vid,
        vec![],
    );
    let mut batches = vec![batch];
    if let Some(cited) = evidenced_by(
        evid,
        &documents.iter().map(|doc| doc.vid).collect::<Vec<_>>(),
    ) {
        batches.push(cited);
    }
    txn.write_ordered(db, batches)?;
    finish(
        db,
        ctx,
        book,
        txn,
        proposal,
        &digest,
        RunControlled {
            run: run.vid,
            kind: kind::BIND_SOURCE,
            from: Some(RunState::Open),
            to: RunState::Open,
            recorded_at: CommitSeq(0),
            control_entry: evid,
            already_recorded: false,
            chunks: Vec::new(),
        },
    )
    .await
}
