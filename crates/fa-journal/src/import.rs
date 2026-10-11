//! Import runs (plan §9.3; fa-txf): a batch of documents brought into the
//! book in one transaction, journaled as an `ImportControl` control record
//! whose payload is the run's receipt.
//!
//! The receipt states what came in and from where: the registered intake
//! source, the number of distinct documents and their bytes, the Merkle root
//! over the documents' oids in ascending order, and
//! `receipt_hash = H("fa:import-receipt:v1" ‖ book ‖ run ‖ source ‖ counts ‖
//! root)` — the one value the external party keeps. Every document the run
//! records gets its `ImportReceipt` (custody event 0) naming the run, with an
//! `IMPORTED_BY` edge to it; a document the book already held is counted in
//! the run and keeps its earlier receipt.
//!
//! No-claim boundary: `receipt_hash` binds which documents (by oid) the run
//! counted, how many and how many bytes it stated, and the registered source
//! the run asserted — not that the source was truthful, and not when. The
//! sequence that recorded the run (`RunReceipt::recorded_at`) is outside the
//! hash: [`verify_receipt`], the external party's check from the oids alone,
//! makes no claim about it; [`verify_receipt_in`], the book holder's check,
//! binds the whole receipt, `recorded_at` included, to the run's
//! `ImportControl` row in the journal.

use fa_model::symbols::{label, relation};
use fa_model::{
    ControlPayload, Entry, EntryClass, EntryOrigin, EntryPayload, Erasable, Id128, IntakeSource,
    Oid, Writer, domain_digest, entry_mirrors, entry_vid,
};
use fa_policy::{Capability, Intent, Party};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::custody::{admit_source, custody_vid, stage_receipt};
use crate::evidence::{
    Document, document_vid, drift, hex, intake_check, stage_document, verify_row,
};
use crate::genesis::BookContext;
use crate::policy::{authorize_approvals, capability_witness, epoch_witness, refusal, steward};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{edge_id, prop};

/// Domain of `receipt_hash`.
pub const IMPORT_RECEIPT_DOMAIN: &[u8] = b"fa:import-receipt:v1";
const LEAF_DOMAIN: &[u8] = b"fa:import:leaf:v1";
const NODE_DOMAIN: &[u8] = b"fa:import:node:v1";

/// The Merkle root over `oids` (the caller passes them in canonical,
/// ascending order): leaf `i` is `H("fa:import:leaf:v1" ‖ u64 i ‖ oid)`, a
/// node `H("fa:import:node:v1" ‖ left ‖ right)`, an unpaired node promoted.
#[must_use]
pub fn oids_root(oids: &[Oid]) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = oids
        .iter()
        .enumerate()
        .map(|(i, o)| {
            let index = u64::try_from(i).unwrap_or(u64::MAX);
            domain_digest(LEAF_DOMAIN, &[&index.to_le_bytes(), &o.0])
        })
        .collect();
    if level.is_empty() {
        return domain_digest(LEAF_DOMAIN, &[]);
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [l, r] => domain_digest(NODE_DOMAIN, &[l, r]),
                // `chunks(2)` yields a lone last element only.
                _ => pair[0],
            })
            .collect();
    }
    level[0]
}

/// `receipt_hash = H("fa:import-receipt:v1" ‖ book ‖ run ‖ source ‖
/// document_count ‖ byte_count ‖ oids_root)`.
pub fn receipt_hash(
    book: Id128,
    run: VId,
    source: &IntakeSource,
    document_count: u32,
    byte_count: u64,
    root: &[u8; 32],
) -> Result<[u8; 32], KernelError> {
    let mut w = Writer::new();
    w.fixed(&book.0).u128(run.0);
    source.encode(&mut w);
    w.u32(document_count).u64(byte_count).fixed(root);
    let body = w.finish().map_err(|e| KernelError::Model(e.into()))?;
    Ok(domain_digest(IMPORT_RECEIPT_DOMAIN, &[&body]))
}

/// One import run.
#[derive(Clone, Debug)]
pub struct ImportRequest {
    /// Who runs the import (the capability's holder).
    pub principal: VId,
    pub source: IntakeSource,
    pub idempotency_key: Vec<u8>,
    /// The business date the run is recorded under (the class is undated:
    /// it resolves no period).
    pub effective_date: DateDay,
    pub description: Erasable<String>,
    pub documents: Vec<Document>,
}

/// A run's receipt, as journaled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunReceipt {
    /// The run's control entry.
    pub run: VId,
    pub source: IntakeSource,
    pub document_count: u32,
    pub byte_count: u64,
    pub oids_root: [u8; 32],
    pub receipt_hash: [u8; 32],
    pub recorded_at: CommitSeq,
}

/// The outcome of an import run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportRecorded {
    pub receipt: RunReceipt,
    /// Documents this run recorded (each with a receipt naming the run).
    pub recorded: Vec<Oid>,
    /// Documents the book already held, counted in the run.
    pub already_held: Vec<Oid>,
    /// The same run was already recorded; nothing was written.
    pub already_recorded: bool,
}

fn structure(message: impl Into<String>, fix: &str) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §9.3 (an import run brings 1..=max_import_documents distinct documents from one registered source)",
        fix,
    )
}

/// The run's control proposal and its documents in canonical order, after
/// every structural and intake law; refused before any read.
fn prepare(
    book: &BookContext,
    policy: &EvidencePolicy,
    req: &ImportRequest,
) -> Result<(EntryPayload, Vec<(Document, String)>), Refusal> {
    if req.documents.is_empty() || req.documents.len() > fa_model::limits::MAX_IMPORT_DOCUMENTS {
        return Err(structure(
            format!(
                "an import run carries 1..={} documents; this one carries {}",
                fa_model::limits::MAX_IMPORT_DOCUMENTS,
                req.documents.len()
            ),
            "split the batch into runs of at most max_import_documents",
        ));
    }
    admit_source(&req.source)?;
    let mut docs: Vec<(Document, String)> = Vec::with_capacity(req.documents.len());
    for (i, doc) in req.documents.iter().enumerate() {
        match intake_check(policy, book, doc, policy.max_document_bytes) {
            Ok(kind) => docs.push((doc.clone(), kind)),
            Err(mut r) => {
                r.message = format!("documents[{i}]: {}", r.message);
                return Err(r);
            }
        }
    }
    docs.sort_by_key(|(d, _)| d.oid());
    if docs.windows(2).any(|w| w[0].0.oid() == w[1].0.oid()) {
        return Err(structure(
            "an import run lists each document once",
            "remove the repeated document",
        ));
    }
    let oids: Vec<Oid> = docs.iter().map(|(d, _)| d.oid()).collect();
    let document_count = u32::try_from(oids.len())
        .map_err(|_| structure("too many documents", "split the batch"))?;
    let mut byte_count: u64 = 0;
    for (d, _) in &docs {
        let size = u64::try_from(d.bytes.len()).unwrap_or(u64::MAX);
        byte_count = byte_count
            .checked_add(size)
            .ok_or_else(|| structure("the run's byte count overflows", "split the batch"))?;
    }
    let root = oids_root(&oids);
    let run = entry_vid(
        book.book_id,
        &req.principal.0.to_le_bytes(),
        &req.idempotency_key,
    );
    let hash = receipt_hash(
        book.book_id,
        run,
        &req.source,
        document_count,
        byte_count,
        &root,
    )
    .map_err(|e| structure(e.to_string(), "report this"))?;
    let proposal = EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::IMPORT_CONTROL,
        effective_date: req.effective_date,
        document_date: None,
        description: req.description.clone(),
        effective_period: None,
        legs: Vec::new(),
        control: Some(ControlPayload::ImportRun {
            source: req.source.clone(),
            document_count,
            byte_count,
            oids_root: root,
            receipt_hash: hash,
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: req.idempotency_key.clone(),
        origin: EntryOrigin::Control {
            control_kind: fa_model::ControlKind::IMPORT_RUN,
            spec_body_digest: hash,
        },
        principal_ref: req.principal,
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    if let Err(e) = proposal.validate() {
        return Err(structure(
            format!("the run's control record is malformed: {e}"),
            "fix the named field",
        ));
    }
    Ok((proposal, docs))
}

fn receipt_of(entry: &Entry, run: VId, recorded_at: CommitSeq) -> Option<RunReceipt> {
    match (&entry.proposal.class, &entry.proposal.control) {
        (
            &EntryClass::IMPORT_CONTROL,
            Some(ControlPayload::ImportRun {
                source,
                document_count,
                byte_count,
                oids_root,
                receipt_hash,
            }),
        ) => Some(RunReceipt {
            run,
            source: source.clone(),
            document_count: *document_count,
            byte_count: *byte_count,
            oids_root: *oids_root,
            receipt_hash: *receipt_hash,
            recorded_at,
        }),
        _ => None,
    }
}

fn stored_entry(row: &VertexRow) -> Result<Entry, KernelError> {
    match prop(row, fa_model::symbols::property::FA_PAYLOAD) {
        Some(CanonicalScalar::Bytes(b)) => Ok(Entry::decode(b.as_slice())?),
        other => Err(KernelError::Corrupt(format!(
            "entry _fa_payload: {other:?}"
        ))),
    }
}

/// The receipt of the import run whose control entry is `run`.
pub fn read_run<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    run: VId,
) -> Result<Option<RunReceipt>, KernelError> {
    let Some(row) = db.vertex(run)? else {
        return Ok(None);
    };
    let entry = stored_entry(&row)?;
    Ok(receipt_of(&entry, run, row.created_at))
}

fn mismatch(receipt: &RunReceipt, what: String) -> Refusal {
    Refusal::new(
        code::RECEIPT_MISMATCH,
        exit::VERIFICATION,
        format!("import run {:032x}: {what}", receipt.run.0),
        "plan §9.3 (an import receipt binds exactly the documents imported)",
        "present the run's oids exactly as imported, in ascending order; a list that does not recompute the receipt is not the run's",
    )
}

/// What the external party can check with the oids alone: the list is the
/// run's, in canonical (ascending) order, of the recorded count, and it
/// recomputes the root and the receipt hash. Otherwise FA-REF-115 (exit 8),
/// naming what disagrees. The byte count needs the bytes and is checked by
/// whoever holds them. `recorded_at` is not in the hash and not checked
/// here: a receipt that differs only there passes (see [`verify_receipt_in`]).
pub fn verify_receipt(receipt: &RunReceipt, book: Id128, oids: &[Oid]) -> Result<(), Refusal> {
    let mismatch = |what: String| mismatch(receipt, what);
    if !oids.windows(2).all(|w| w[0] < w[1]) {
        return Err(mismatch(
            "the presented oids are not in canonical ascending order".into(),
        ));
    }
    if u32::try_from(oids.len()).ok() != Some(receipt.document_count) {
        return Err(mismatch(format!(
            "{} oids presented; the receipt counts {}",
            oids.len(),
            receipt.document_count
        )));
    }
    let root = oids_root(oids);
    if root != receipt.oids_root {
        return Err(mismatch(format!(
            "the presented oids recompute root {}, not the receipt's {}",
            hex(&root),
            hex(&receipt.oids_root)
        )));
    }
    let hash = receipt_hash(
        book,
        receipt.run,
        &receipt.source,
        receipt.document_count,
        receipt.byte_count,
        &root,
    )
    .map_err(|e| mismatch(e.to_string()))?;
    if hash != receipt.receipt_hash {
        return Err(mismatch(format!(
            "the receipt's fields recompute hash {}, not its receipt_hash {}",
            hex(&hash),
            hex(&receipt.receipt_hash)
        )));
    }
    Ok(())
}

/// What the book's holder can check: the presented receipt is the one the
/// journal recorded — its run is an `ImportControl` entry of this book, and
/// every field, `recorded_at` included, equals that entry's receipt at the
/// sequence that recorded it — and the oids verify as in [`verify_receipt`].
/// Otherwise FA-REF-115 (exit 8), naming what disagrees.
pub fn verify_receipt_in<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: Id128,
    receipt: &RunReceipt,
    oids: &[Oid],
) -> Outcome<()> {
    let Some(journal) = read_run(db, receipt.run)? else {
        return Ok(Err(mismatch(
            receipt,
            "is not an import run this book recorded".into(),
        )));
    };
    if journal.recorded_at != receipt.recorded_at {
        return Ok(Err(mismatch(
            receipt,
            format!(
                "was recorded at sequence {}, not the presented {}",
                journal.recorded_at.0, receipt.recorded_at.0
            ),
        )));
    }
    if journal != *receipt {
        return Ok(Err(mismatch(
            receipt,
            "the presented receipt differs from the one the journal recorded".into(),
        )));
    }
    Ok(verify_receipt(receipt, book, oids))
}

fn recorded_or_conflict(
    book: &BookContext,
    row: &VertexRow,
    proposal: &EntryPayload,
    digest: &[u8; 32],
) -> Outcome<ImportRecorded> {
    let stored = stored_entry(row)?;
    let same = &stored.proposal_digest == digest
        || matches!(
            (
                stored.proposal.semantic_digest(&book.seal_key),
                proposal.semantic_digest(&book.seal_key),
            ),
            (Ok(a), Ok(b)) if a == b
        );
    match receipt_of(&stored, row.vid, row.created_at) {
        Some(receipt) if same => Ok(Ok(ImportRecorded {
            receipt,
            recorded: Vec::new(),
            already_held: Vec::new(),
            already_recorded: true,
        })),
        _ => Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            format!(
                "idempotency key reused with a different import run; the recorded run is {:032x}",
                row.vid.0
            ),
            "plan §4.9 (identity is derived from the key; content is bound by proposal_digest)",
            "resubmit the identical run to get its recorded receipt, or use a new idempotency key",
        ))),
    }
}

/// Record an import run (plan §9.3): refused before any read on structure,
/// an unregistered source, any document's intake laws, or authority (the
/// `import-run` SoD row's preparer op, a current capability that is the
/// principal's own). Then, in one transaction: the run's identity (the same
/// run again is its recorded receipt), the SoD rule over the witnessed
/// policy epoch, each document either held already (verified, counted) or
/// recorded with its receipt naming the run, and the `ImportControl` entry.
pub async fn import_run<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    req: ImportRequest,
) -> Outcome<ImportRecorded> {
    let policy = EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let (proposal, docs) = match prepare(book, &policy, &req) {
        Ok(p) => p,
        Err(r) => return Ok(Err(r)),
    };
    let steward = steward()?;
    let key = fa_policy::sod::control_key("ImportControl", None, "Import");
    let Some(op) = steward.preparer_op(&key) else {
        return Err(KernelError::Corrupt(
            "sod_policy.toml has no import-run rule".into(),
        ));
    };
    if let Err(d) = fa_policy::admit(
        capability,
        &Intent {
            principal: req.principal,
            trunk: true,
            op,
            book: book.book_id,
            legs: &[],
        },
    ) {
        return Ok(Err(refusal(&d)));
    }
    if let Err(d) = fa_policy::current(capability, db.frontier()?) {
        return Ok(Err(refusal(&d)));
    }
    let digest = proposal.proposal_digest()?;
    let run = entry_vid(
        book.book_id,
        &req.principal.0.to_le_bytes(),
        &req.idempotency_key,
    );
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    if let Some(row) = txn.vertex(db, run)? {
        txn.abort();
        return recorded_or_conflict(book, &row, &proposal, &digest);
    }
    let epoch = epoch_witness(&txn, db)?;
    let preparer = Party {
        principal: req.principal,
        profile: capability.profile(),
    };
    if let Err(r) = authorize_approvals(&txn, db, book, &[], &digest, epoch, &key, 0, preparer)? {
        txn.abort();
        return Ok(Err(r));
    }
    let entry = proposal.clone().seal(Vec::new(), None)?;
    let mut custody = WriteBatch::new(relation::CUSTODY_OF);
    custody.create_vertex(run, vec![label::ENTRY], entry_mirrors(&entry)?);
    let mut imported = WriteBatch::new(relation::IMPORTED_BY);
    let mut recorded = Vec::new();
    let mut already_held = Vec::new();
    for (doc, kind) in &docs {
        let oid = doc.oid();
        match txn.vertex(db, document_vid(&oid))? {
            Some(row) => {
                if let Err(why) = verify_row(&row, &policy) {
                    txn.abort();
                    return Ok(Err(drift(&oid, &why)));
                }
                already_held.push(oid);
            }
            None => {
                stage_document(&mut custody, book, doc, kind)?;
                let receipt = stage_receipt(
                    &mut custody,
                    book,
                    doc,
                    req.source.clone(),
                    req.principal,
                    Some(run),
                )?;
                debug_assert_eq!(receipt, custody_vid(book.book_id, &oid, 0));
                imported.add_edge(
                    edge_id(relation::IMPORTED_BY, receipt, run),
                    receipt,
                    run,
                    vec![],
                );
                recorded.push(oid);
            }
        }
    }
    let mut batches = vec![custody, imported];
    batches.retain(|b| !b.is_empty());
    if let Err(e) = txn.write_ordered(db, batches) {
        txn.abort();
        return Err(e.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => {
            let receipt = receipt_of(&entry, run, seq)
                .ok_or_else(|| KernelError::Corrupt("an import run without its receipt".into()))?;
            Ok(Ok(ImportRecorded {
                receipt,
                recorded,
                already_held,
                already_recorded: false,
            }))
        }
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("a concurrent commit invalidated a witness this import read: {detail}"),
                "FG-LAW-FCW-01 (first committer wins)",
                "retry the import run; documents another run recorded meanwhile are counted, not re-recorded",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => match db.vertex(run)? {
            Some(row) => recorded_or_conflict(book, &row, &proposal, &digest),
            // A document identity raced (another intake of the same bytes
            // committed first): retry counts it as held.
            None => Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                "a document in this run was recorded concurrently",
                "FG-LAW-FCW-01 (first committer wins)",
                "retry the import run; the document is then counted as already held",
            ))),
        },
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(b: u8) -> Oid {
        Oid([b; 32])
    }

    #[test]
    fn the_root_binds_every_oid_and_its_position() {
        let oids: Vec<Oid> = (1..=5).map(oid).collect();
        let root = oids_root(&oids);
        assert_eq!(root, oids_root(&oids), "deterministic");
        // ((l0 l1) (l2 l3)) l4 — the unpaired leaf is promoted.
        let leaf = |i: u64, o: &Oid| domain_digest(LEAF_DOMAIN, &[&i.to_le_bytes(), &o.0]);
        let node = |l: &[u8; 32], r: &[u8; 32]| domain_digest(NODE_DOMAIN, &[l, r]);
        let l: Vec<[u8; 32]> = oids
            .iter()
            .enumerate()
            .map(|(i, o)| leaf(i as u64, o))
            .collect();
        assert_eq!(
            root,
            node(&node(&node(&l[0], &l[1]), &node(&l[2], &l[3])), &l[4])
        );
        for i in 0..oids.len() {
            let mut t = oids.clone();
            t[i].0[0] ^= 1;
            assert_ne!(root, oids_root(&t), "oid {i} is bound");
        }
        assert_ne!(root, oids_root(&oids[..4]), "the count is bound");
    }

    #[test]
    fn a_receipt_verifies_only_against_its_exact_oid_list() {
        let book = Id128([5; 16]);
        let source = IntakeSource::Connector {
            name: "fa-import".into(),
            version: "1".into(),
        };
        let oids: Vec<Oid> = vec![oid(1), oid(4), oid(9)];
        let root = oids_root(&oids);
        let receipt = RunReceipt {
            run: VId(77),
            source: source.clone(),
            document_count: 3,
            byte_count: 300,
            oids_root: root,
            receipt_hash: receipt_hash(book, VId(77), &source, 3, 300, &root).unwrap(),
            recorded_at: CommitSeq(9),
        };
        assert!(verify_receipt(&receipt, book, &oids).is_ok());
        let tampered = vec![oid(1), oid(5), oid(9)];
        let missing = vec![oid(1), oid(9)];
        let extra = vec![oid(1), oid(4), oid(9), oid(10)];
        let reordered = vec![oid(4), oid(1), oid(9)];
        for (what, list) in [
            ("a tampered oid", &tampered),
            ("a missing oid", &missing),
            ("an extra oid", &extra),
            ("a reordered list", &reordered),
        ] {
            let r = verify_receipt(&receipt, book, list).unwrap_err();
            assert_eq!(
                (r.code, r.exit),
                (code::RECEIPT_MISMATCH, exit::VERIFICATION),
                "{what}"
            );
        }
        // A receipt whose stated fields were altered no longer hashes.
        let forged = RunReceipt {
            byte_count: 301,
            ..receipt.clone()
        };
        assert_eq!(
            verify_receipt(&forged, book, &oids).unwrap_err().code,
            code::RECEIPT_MISMATCH
        );
        // Another book's receipt is not this one's.
        assert!(verify_receipt(&receipt, Id128([6; 16]), &oids).is_err());
        // The boundary (WhiteCreek 3382): `recorded_at` is not in the hash, so
        // the offline check neither binds nor refuses it; only the journal
        // check (`verify_receipt_in`) does.
        let shifted = RunReceipt {
            recorded_at: CommitSeq(10),
            ..receipt.clone()
        };
        assert!(verify_receipt(&shifted, book, &oids).is_ok());
    }
}
