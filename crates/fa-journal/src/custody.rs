//! Chain of custody (plan §9.3; fa-txf).
//!
//! Every document the book ingests carries an immutable, hash-chained
//! sequence of custody events. Event 0 is its `ImportReceipt`: the
//! registered intake source (`intake_sources.toml`), the principal that
//! received the bytes, `digest_at_receipt = doc_commit`, and the import run
//! that brought it in, if any. Each later event is a `CustodyTransfer` from
//! the current custodian to another principal, chained to its predecessor by
//! `prev_digest`. Event identities are derived —
//! `H("fa:vid:custody:v1" ‖ book ‖ oid ‖ u32 index)` — and the document's
//! `custody_len` counts them, moved by compare-and-set when a transfer is
//! recorded.
//!
//! The posting kernel admits a citation only when the cited document's chain
//! is complete: every event `0..custody_len` is present and verifies, each
//! names this document at its index, event 0 is a receipt from a registered
//! source whose digest is the document's commitment, and each later event
//! chains to its predecessor. Otherwise the citation is refused with
//! FA-REF-114, naming the first missing or broken link.
//!
//! Interim postures, stated rather than hidden: `transformations` (the
//! receipt's derived projections, §9.3) is written as an empty list and
//! refused otherwise until parsers exist; a transfer records who held the
//! document, not why (reason codes join with productions, §13.2).

use fa_model::symbols::{label, property, relation};
use fa_model::{DecodeError, Id128, IntakeSource, Oid, Reader, Writer, domain_digest};
use fa_policy::{Capability, Op};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_registry::intake_sources::IntakeSources;
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::evidence::{Document, document_vid, drift, hex, verify_row};
use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{edge_id, prop, scalar_bytes};

/// Domain of a custody event's digest.
pub const CUSTODY_DOMAIN: &[u8] = b"fa:custody:v1";
const CUSTODY_VERSION: u16 = 1;
const BODY_RECEIPT: u8 = 1;
const BODY_TRANSFER: u8 = 2;

/// What happened at one custody event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CustodyBody {
    /// Event 0: how the bytes entered the book.
    Receipt {
        source: IntakeSource,
        received_by: VId,
        /// The document's commitment as observed at receipt.
        digest_at_receipt: [u8; 32],
        /// The import run (its control entry) that brought it in.
        run_ref: Option<VId>,
    },
    /// A later event: custody passed from one principal to another.
    Transfer { from: VId, to: VId },
}

/// One custody event, as journaled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyEvent {
    pub book_id: Id128,
    pub document_oid: Oid,
    pub index: u32,
    /// The digest of event `index - 1` (zero for the receipt).
    pub prev_digest: [u8; 32],
    pub body: CustodyBody,
}

/// `vid(event) = H("fa:vid:custody:v1" ‖ book ‖ oid ‖ u32 index)`.
#[must_use]
pub fn custody_vid(book: Id128, document: &Oid, index: u32) -> VId {
    let d = domain_digest(
        b"fa:vid:custody:v1",
        &[&book.0, &document.0, &index.to_le_bytes()],
    );
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d[..16]);
    VId(u128::from_le_bytes(lo))
}

impl CustodyEvent {
    fn body_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::new();
        w.u16(CUSTODY_VERSION)
            .fixed(&self.book_id.0)
            .fixed(&self.document_oid.0)
            .u32(self.index)
            .fixed(&self.prev_digest);
        match &self.body {
            CustodyBody::Receipt {
                source,
                received_by,
                digest_at_receipt,
                run_ref,
            } => {
                w.u8(BODY_RECEIPT);
                source.encode(&mut w);
                w.u128(received_by.0)
                    .fixed(digest_at_receipt)
                    .opt(run_ref.as_ref(), |w, v| {
                        w.u128(v.0);
                    });
                // `transformations`: empty until parsers exist.
                let none: [u8; 0] = [];
                w.list(&none, |w, b| {
                    w.u8(*b);
                });
            }
            CustodyBody::Transfer { from, to } => {
                w.u8(BODY_TRANSFER).u128(from.0).u128(to.0);
            }
        }
        w.finish().map_err(|e| KernelError::Model(e.into()))
    }

    /// `BLAKE3("fa:custody:v1" ‖ body)`: what the next event chains to.
    pub fn digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(CUSTODY_DOMAIN, &[&self.body_bytes()?]))
    }

    /// `body ‖ digest`: the stored payload.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut bytes = self.body_bytes()?;
        bytes.extend_from_slice(&self.digest()?);
        Ok(bytes)
    }

    /// Decode and verify: the trailing digest is the body's; a receipt sits
    /// only at index 0 and a transfer only after it.
    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(bytes);
        let (event, digest) = (|| -> Result<(Self, [u8; 32]), DecodeError> {
            if r.u16("custody.version")? != CUSTODY_VERSION {
                return Err(r.invalid("custody.version"));
            }
            let book_id = Id128(r.fixed("custody.book_id")?);
            let document_oid = Oid(r.fixed("custody.document_oid")?);
            let index = r.u32("custody.index")?;
            let prev_digest = r.fixed("custody.prev_digest")?;
            let body = match r.u8("custody.body")? {
                BODY_RECEIPT => {
                    let source = IntakeSource::decode(&mut r)?;
                    let received_by = VId(r.u128("custody.received_by")?);
                    let digest_at_receipt = r.fixed("custody.digest_at_receipt")?;
                    let run_ref =
                        r.opt("custody.run_ref", |r| r.u128("custody.run_ref").map(VId))?;
                    r.count(0, "custody.transformations")?;
                    CustodyBody::Receipt {
                        source,
                        received_by,
                        digest_at_receipt,
                        run_ref,
                    }
                }
                BODY_TRANSFER => CustodyBody::Transfer {
                    from: VId(r.u128("custody.from")?),
                    to: VId(r.u128("custody.to")?),
                },
                t => return Err(r.bad_tag("custody.body", t)),
            };
            let digest: [u8; 32] = r.fixed("custody.digest")?;
            r.finish()?;
            Ok((
                Self {
                    book_id,
                    document_oid,
                    index,
                    prev_digest,
                    body,
                },
                digest,
            ))
        })()
        .map_err(|e| KernelError::Model(e.into()))?;
        let shape_ok = match event.body {
            CustodyBody::Receipt { .. } => event.index == 0 && event.prev_digest == [0; 32],
            CustodyBody::Transfer { .. } => event.index > 0,
        };
        if !shape_ok || event.digest()? != digest {
            return Err(KernelError::Corrupt(format!(
                "custody event {} of document {}: the payload does not verify",
                event.index,
                hex(&event.document_oid.0)
            )));
        }
        Ok(event)
    }

    /// The custodian after this event.
    #[must_use]
    pub fn holder(&self) -> VId {
        match self.body {
            CustodyBody::Receipt { received_by, .. } => received_by,
            CustodyBody::Transfer { to, .. } => to,
        }
    }
}

fn sources() -> Result<IntakeSources, KernelError> {
    IntakeSources::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))
}

/// Why `source` is not one this book admits, or `None` when it is.
fn unadmitted(registry: &IntakeSources, source: &IntakeSource) -> Option<String> {
    if !source.within_bounds() {
        return Some(format!(
            "the {} source's text fields must be 1..={} bytes",
            source.kind_name(),
            fa_model::limits::MAX_INTAKE_TEXT_BYTES
        ));
    }
    if !registry.admits_kind(source.kind_name()) {
        return Some(format!(
            "intake source kind `{}` is not registered",
            source.kind_name()
        ));
    }
    match source {
        IntakeSource::Connector { name, version } if !registry.admits_connector(name, version) => {
            Some(format!(
                "connector `{name}` version `{version}` is not registered (registered: {})",
                registry.connector_listing()
            ))
        }
        IntakeSource::Scan { device } if !registry.admits_device(device) => {
            Some(format!("scanning device `{device}` is not registered"))
        }
        _ => None,
    }
}

/// Intake refuses a source this book does not admit (FA-REF-083), before
/// anything is written.
pub fn admit_source(source: &IntakeSource) -> Result<(), Refusal> {
    let registry = sources().map_err(|e| {
        Refusal::new(
            code::DOCUMENT_INTAKE,
            exit::USAGE,
            e.to_string(),
            "registries/intake_sources.toml",
            "repair the registry",
        )
    })?;
    match unadmitted(&registry, source) {
        None => Ok(()),
        Some(why) => Err(Refusal::new(
            code::DOCUMENT_INTAKE,
            exit::USAGE,
            why,
            "registries/intake_sources.toml; plan §9.3 (ImportReceipt.source)",
            "use a registered intake source, or register it (an additive registry row) first",
        )),
    }
}

/// Stage `event` (vertex, mirrors, `CUSTODY_OF` edge) in a batch whose
/// relation is `CUSTODY_OF`.
fn stage_event(batch: &mut WriteBatch, event: &CustodyEvent) -> Result<VId, KernelError> {
    let vid = custody_vid(event.book_id, &event.document_oid, event.index);
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("_fa_payload", event.canonical_bytes()?)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("_fa_digest", event.digest()?.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("book_id", event.book_id.0.to_vec())?,
        ),
    ];
    props.sort_by_key(|(k, _)| k.0);
    let event_label = if event.index == 0 {
        label::IMPORT_RECEIPT
    } else {
        label::CUSTODY_TRANSFER
    };
    batch.create_vertex(vid, vec![event_label], props);
    let dvid = document_vid(&event.document_oid);
    batch.add_edge(edge_id(relation::CUSTODY_OF, vid, dvid), vid, dvid, vec![]);
    Ok(vid)
}

/// Stage `doc`'s receipt (custody event 0) beside its Document vertex.
/// Returns the receipt's vertex.
pub(crate) fn stage_receipt(
    batch: &mut WriteBatch,
    book: &BookContext,
    doc: &Document,
    source: IntakeSource,
    received_by: VId,
    run_ref: Option<VId>,
) -> Result<VId, KernelError> {
    stage_event(
        batch,
        &CustodyEvent {
            book_id: book.book_id,
            document_oid: doc.oid(),
            index: 0,
            prev_digest: [0; 32],
            body: CustodyBody::Receipt {
                source,
                received_by,
                digest_at_receipt: doc.doc_commit(),
                run_ref,
            },
        },
    )
}

fn custody_len_of(row: &VertexRow) -> Result<Option<u32>, String> {
    match prop(row, property::CUSTODY_LEN) {
        None => Ok(None),
        Some(CanonicalScalar::Int(n)) => u32::try_from(*n)
            .map(Some)
            .map_err(|_| format!("custody_len {n} is out of range")),
        Some(other) => Err(format!("custody_len is not an integer: {other:?}")),
    }
}

fn verify_event(row: &VertexRow) -> Result<CustodyEvent, String> {
    let Some(CanonicalScalar::Bytes(payload)) = prop(row, property::FA_PAYLOAD) else {
        return Err("it carries no payload".into());
    };
    let event = CustodyEvent::decode(payload.as_slice()).map_err(|e| e.to_string())?;
    let want_label = if event.index == 0 {
        label::IMPORT_RECEIPT
    } else {
        label::CUSTODY_TRANSFER
    };
    if !row.labels.contains(&want_label) {
        return Err("its label is not its event kind".into());
    }
    let digest = event.digest().map_err(|e| e.to_string())?;
    match prop(row, property::FA_DIGEST) {
        Some(CanonicalScalar::Bytes(b)) if b.as_slice() == digest.as_slice() => {}
        _ => return Err("its digest mirror differs from its payload".into()),
    }
    match prop(row, property::BOOK_ID) {
        Some(CanonicalScalar::Bytes(b)) if b.as_slice() == event.book_id.0.as_slice() => {}
        _ => return Err("its book_id mirror differs from its payload".into()),
    }
    Ok(event)
}

fn incomplete(oid: &Oid, index: u32, vid: VId, why: &str) -> Refusal {
    Refusal::new(
        code::CUSTODY_INCOMPLETE,
        exit::REFUSAL,
        format!(
            "document {}: custody link {index} (vertex {:032x}) {why}",
            hex(&oid.0),
            vid.0
        ),
        "plan §9.3 (a document is evidence only through a complete chain of custody from a registered intake source); registries/intake_sources.toml",
        "cite a document recorded with `fa document add <file> --json` (its receipt is written with it); a document whose chain is broken stays uncitable until the break is explained",
    )
}

/// Inside `txn`: `oid`'s custody chain is complete (see the module docs),
/// every event read as a point witness. The document row itself was read
/// and verified by the caller in the same transaction.
pub fn witness_custody<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    policy: &EvidencePolicy,
    oid: &Oid,
) -> Outcome<()> {
    let registry = sources()?;
    let dvid = document_vid(oid);
    let Some(row) = txn.vertex(db, dvid)? else {
        return Err(KernelError::Corrupt(format!(
            "document {} vanished inside its own transaction",
            hex(&oid.0)
        )));
    };
    let doc = match verify_row(&row, policy) {
        Ok(doc) => doc,
        Err(why) => return Ok(Err(drift(oid, &why))),
    };
    let len = match custody_len_of(&row) {
        Ok(Some(len)) if len > 0 => len,
        Ok(_) => {
            return Ok(Err(incomplete(
                oid,
                0,
                custody_vid(doc.book_id, oid, 0),
                "is missing: the document has no ImportReceipt",
            )));
        }
        Err(why) => return Ok(Err(drift(oid, &why))),
    };
    let mut prev: Option<CustodyEvent> = None;
    for index in 0..len {
        let vid = custody_vid(doc.book_id, oid, index);
        let Some(event_row) = txn.vertex(db, vid)? else {
            return Ok(Err(incomplete(oid, index, vid, "is missing")));
        };
        let event = match verify_event(&event_row) {
            Ok(event) => event,
            Err(why) => {
                return Ok(Err(incomplete(
                    oid,
                    index,
                    vid,
                    &format!("does not verify: {why}"),
                )));
            }
        };
        if event.index != index || event.document_oid != *oid || event.book_id != doc.book_id {
            return Ok(Err(incomplete(
                oid,
                index,
                vid,
                "is another document's or another index's event",
            )));
        }
        match (&prev, &event.body) {
            (
                None,
                CustodyBody::Receipt {
                    source,
                    digest_at_receipt,
                    ..
                },
            ) => {
                if *digest_at_receipt != doc.doc_commit() {
                    return Ok(Err(incomplete(
                        oid,
                        index,
                        vid,
                        "is a receipt for other bytes (digest_at_receipt is not the document's commitment)",
                    )));
                }
                if let Some(why) = unadmitted(&registry, source) {
                    return Ok(Err(incomplete(
                        oid,
                        index,
                        vid,
                        &format!("is a receipt from an unregistered source: {why}"),
                    )));
                }
            }
            (Some(p), CustodyBody::Transfer { from, .. }) => {
                if event.prev_digest != p.digest()? {
                    return Ok(Err(incomplete(
                        oid,
                        index,
                        vid,
                        "does not chain to the previous event (prev_digest)",
                    )));
                }
                if *from != p.holder() {
                    return Ok(Err(incomplete(
                        oid,
                        index,
                        vid,
                        "transfers from a principal that did not hold the document",
                    )));
                }
            }
            _ => {
                return Ok(Err(incomplete(
                    oid,
                    index,
                    vid,
                    "is out of order (a receipt opens the chain; transfers follow)",
                )));
            }
        }
        prev = Some(event);
    }
    Ok(Ok(()))
}

/// Every custody event of `oid`, verified, oldest first, with the sequence
/// that recorded it. A gap or a broken link is an error naming it.
pub fn custody_chain<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    oid: &Oid,
) -> Result<Vec<(CustodyEvent, CommitSeq)>, KernelError> {
    let Some(row) = db.vertex(document_vid(oid))? else {
        return Ok(Vec::new());
    };
    let len = custody_len_of(&row)
        .map_err(KernelError::Corrupt)?
        .unwrap_or(0);
    let book_id = match prop(&row, property::BOOK_ID) {
        Some(CanonicalScalar::Bytes(b)) if b.len() == 16 => {
            let mut id = [0u8; 16];
            id.copy_from_slice(b.as_slice());
            Id128(id)
        }
        _ => {
            return Err(KernelError::Corrupt(format!(
                "document {} carries no book_id",
                hex(&oid.0)
            )));
        }
    };
    let mut out = Vec::with_capacity(len as usize);
    for index in 0..len {
        let vid = custody_vid(book_id, oid, index);
        let Some(event_row) = db.vertex(vid)? else {
            return Err(KernelError::Corrupt(format!(
                "{} document {}: custody link {index} is missing",
                code::CUSTODY_INCOMPLETE,
                hex(&oid.0)
            )));
        };
        let event = verify_event(&event_row).map_err(|why| {
            KernelError::Corrupt(format!(
                "{} document {}: custody link {index} does not verify: {why}",
                code::CUSTODY_INCOMPLETE,
                hex(&oid.0)
            ))
        })?;
        out.push((event, event_row.created_at));
    }
    Ok(out)
}

/// The outcome of a custody transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyMoved {
    pub event: VId,
    pub index: u32,
    pub recorded_at: CommitSeq,
}

/// Pass custody of `document` from `from` (the capability's holder, who must
/// be the current custodian) to `to`, as custody event `custody_len`, in one
/// transaction that moves `custody_len` by compare-and-set. Admission (the
/// capability is `from`'s, current, holds `post`) precedes any read; the
/// document must be held and verify, and its chain must already be complete.
pub async fn transfer_custody<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    document: Oid,
    from: VId,
    to: VId,
) -> Outcome<CustodyMoved> {
    let policy = EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    if from == to {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "a custody transfer names two different principals",
            "plan §9.3 (chain of custody)",
            "name the principal that receives the document",
        )));
    }
    if let Err(d) = fa_policy::admit(
        capability,
        &fa_policy::Intent {
            principal: from,
            trunk: true,
            op: Op::Post,
            book: book.book_id,
            legs: &[],
        },
    ) {
        return Ok(Err(crate::policy::refusal(&d)));
    }
    if let Err(d) = fa_policy::current(capability, db.frontier()?) {
        return Ok(Err(crate::policy::refusal(&d)));
    }
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let dvid = document_vid(&document);
    let Some(row) = txn.vertex(db, dvid)? else {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::EVIDENCE_UNKNOWN,
            exit::REFUSAL,
            format!("document {} is not in this book", hex(&document.0)),
            "FA-INV-05 (custody is recorded for documents the book holds)",
            "record it first with `fa document add <file> --json`",
        )));
    };
    if let Err(why) = verify_row(&row, &policy) {
        txn.abort();
        return Ok(Err(drift(&document, &why)));
    }
    if let Err(r) = witness_custody(&txn, db, &policy, &document)? {
        txn.abort();
        return Ok(Err(r));
    }
    let len = match custody_len_of(&row) {
        Ok(Some(len)) => len,
        _ => {
            txn.abort();
            return Err(KernelError::Corrupt(
                "custody_len vanished after the chain verified".into(),
            ));
        }
    };
    let last_vid = custody_vid(book.book_id, &document, len - 1);
    let last = match txn.vertex(db, last_vid)?.map(|r| verify_event(&r)) {
        Some(Ok(event)) => event,
        _ => {
            txn.abort();
            return Err(KernelError::Corrupt(
                "the last custody event vanished after the chain verified".into(),
            ));
        }
    };
    if last.holder() != from {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::NOT_CUSTODIAN,
            exit::SAFETY,
            format!(
                "document {} is held by principal {:032x}, not {:032x}",
                hex(&document.0),
                last.holder().0,
                from.0
            ),
            "plan §9.3 (only the current custodian hands a document on)",
            "have the current custodian record the transfer",
        )));
    }
    let event = CustodyEvent {
        book_id: book.book_id,
        document_oid: document,
        index: len,
        prev_digest: last.digest()?,
        body: CustodyBody::Transfer { from, to },
    };
    let next = len
        .checked_add(1)
        .ok_or_else(|| KernelError::Corrupt("custody_len overflow".into()))?;
    let mut batch = WriteBatch::new(relation::CUSTODY_OF);
    let vid = stage_event(&mut batch, &event)?;
    batch.compare_and_set_vertex_property(
        dvid,
        property::CUSTODY_LEN,
        Some(CanonicalScalar::Int(i64::from(len))),
        CanonicalScalar::Int(i64::from(next)),
        WriteMismatchPolicy::AbortWrite,
    );
    if let Err(e) = txn.write(db, batch) {
        txn.abort();
        return Err(e.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(CustodyMoved {
            event: vid,
            index: len,
            recorded_at: seq,
        })),
        Err(
            WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { .. })
            | WriteTxnError::Write(fgdb::WriteError::CompareAndSetMismatch(_))
            | WriteTxnError::Write(fgdb::WriteError::AlreadyLive { .. }),
        ) => Ok(Err(Refusal::new(
            code::CONFLICT,
            exit::CONFLICT,
            "a concurrent custody transfer of this document won",
            "FG-LAW-FCW-01 (first committer wins)",
            "re-read the document's custody chain and retry from its current custodian",
        ))),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt() -> CustodyEvent {
        CustodyEvent {
            book_id: Id128([5; 16]),
            document_oid: Oid([9; 32]),
            index: 0,
            prev_digest: [0; 32],
            body: CustodyBody::Receipt {
                source: IntakeSource::Connector {
                    name: "fa-import".into(),
                    version: "1".into(),
                },
                received_by: VId(7),
                digest_at_receipt: [3; 32],
                run_ref: Some(VId(44)),
            },
        }
    }

    #[test]
    fn events_round_trip_and_their_digest_binds_every_byte() {
        let r = receipt();
        let t = CustodyEvent {
            index: 1,
            prev_digest: r.digest().unwrap(),
            body: CustodyBody::Transfer {
                from: VId(7),
                to: VId(8),
            },
            ..r.clone()
        };
        for e in [&r, &t] {
            let bytes = e.canonical_bytes().unwrap();
            assert_eq!(&CustodyEvent::decode(&bytes).unwrap(), e);
            for i in 0..bytes.len() - 32 {
                let mut x = bytes.clone();
                x[i] ^= 0x01;
                assert!(CustodyEvent::decode(&x).is_err(), "byte {i}");
            }
        }
        assert_eq!(t.holder(), VId(8));
        assert_eq!(r.holder(), VId(7));
        // A receipt anywhere but index 0, or a transfer at 0, never decodes.
        let misplaced = CustodyEvent {
            index: 2,
            ..r.clone()
        };
        assert!(CustodyEvent::decode(&misplaced.canonical_bytes().unwrap()).is_err());
        let early = CustodyEvent { index: 0, ..t };
        assert!(CustodyEvent::decode(&early.canonical_bytes().unwrap()).is_err());
    }

    #[test]
    fn sources_are_admitted_only_as_registered() {
        let reg = IntakeSources::embedded().unwrap();
        let ok = [
            IntakeSource::Upload { principal: VId(7) },
            IntakeSource::Connector {
                name: "fa-import".into(),
                version: "1".into(),
            },
            IntakeSource::Email {
                message_id: "<a@b>".into(),
            },
        ];
        for s in &ok {
            assert_eq!(unadmitted(&reg, s), None, "{s:?}");
        }
        for s in [
            IntakeSource::Connector {
                name: "bank-feed".into(),
                version: "1".into(),
            },
            IntakeSource::Scan {
                device: "office-scanner".into(),
            },
            IntakeSource::Email {
                message_id: String::new(),
            },
        ] {
            assert!(unadmitted(&reg, &s).is_some(), "{s:?}");
            assert_eq!(admit_source(&s).unwrap_err().code, code::DOCUMENT_INTAKE);
        }
    }

    #[test]
    fn custody_identities_are_per_document_and_index() {
        let a = custody_vid(Id128([5; 16]), &Oid([9; 32]), 0);
        assert_ne!(a, custody_vid(Id128([5; 16]), &Oid([9; 32]), 1));
        assert_ne!(a, custody_vid(Id128([5; 16]), &Oid([8; 32]), 0));
        assert_ne!(a, custody_vid(Id128([6; 16]), &Oid([9; 32]), 0));
    }
}
