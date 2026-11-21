//! A book's adjustment-layer anchor is an admitted immutable schema control.
//!
//! The v1 document remains the evidence artifact; uploading its bytes alone
//! grants no authority. Only a SchemaChange control published with its intent
//! claim activates the anchor, and later controls may only advance its parent.

use asupersync::fs::Vfs;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ControlKind, ControlPayload, EntryClass, EntryOrigin, EntryRef, Erasable, Id128, IntakeSource,
    Oid, Reader, Writer, entry_mirrors, entry_vid,
};
use fa_policy::Capability;
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::DateDay;
use fgdb::{Database, WriteBatch, WriteTxnError};
use fgdb_types::CommitSeq;
use fgdb_types::context::PurposeContexts;

use crate::chart::{admit_schema_change, schema_control_proposal};
use crate::evidence::{Document, Storage, document_vid};
use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};

pub const SCHEMA_CHANGE_ADJUSTMENT_LAYER: u16 = 26;
pub const DOCUMENT_KIND: u8 = 21;
pub const MIME: &str = "application/vnd.franken.adjustment-layer.v1";
pub const DOMAIN: &[u8] = b"fa:adjustment-layer:v1";
const KEY_DOMAIN: &[u8] = b"fa:adjustment-layer-control:v1";
const CITE: &str = "plan §12.2, FA-INV-13 (adjustment-layer parent anchors)";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdjustmentLayerAnchor {
    pub book_id: Id128,
    pub parent_book_id: Id128,
    pub parent_known_at: CommitSeq,
}

impl AdjustmentLayerAnchor {
    pub fn encode(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut writer = Writer::new();
        writer
            .fixed(DOMAIN)
            .fixed(&self.book_id.0)
            .fixed(&self.parent_book_id.0)
            .u64(self.parent_known_at.0);
        writer.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        let mut reader = Reader::new(bytes);
        let bad = |error: fa_model::DecodeError| corrupt(error.to_string());
        if reader
            .fixed::<{ DOMAIN.len() }>("anchor format")
            .map_err(bad)?
            .as_slice()
            != DOMAIN
        {
            return Err(corrupt("unknown anchor encoding"));
        }
        let anchor = Self {
            book_id: Id128(reader.fixed::<16>("book").map_err(bad)?),
            parent_book_id: Id128(reader.fixed::<16>("parent book").map_err(bad)?),
            parent_known_at: CommitSeq(reader.u64("parent known-at").map_err(bad)?),
        };
        reader.finish().map_err(bad)?;
        if anchor.book_id == anchor.parent_book_id || anchor.parent_known_at.0 == 0 {
            return Err(corrupt(
                "an anchor needs a distinct parent and a committed prefix",
            ));
        }
        Ok(anchor)
    }

    pub fn document_commit(&self) -> Result<[u8; 32], KernelError> {
        Ok(crate::evidence::doc_commit(DOCUMENT_KIND, &self.encode()?))
    }

    pub fn document_oid(&self) -> Result<Oid, KernelError> {
        Ok(crate::evidence::document_oid(
            self.book_id,
            &self.document_commit()?,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorControl {
    pub anchor: AdjustmentLayerAnchor,
    pub entry: EntryRef,
    pub recorded_at: CommitSeq,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorRecorded {
    pub control: AnchorControl,
    pub already_recorded: bool,
}

fn corrupt(message: impl Into<String>) -> KernelError {
    KernelError::Corrupt(format!("adjustment-layer anchor: {}", message.into()))
}

fn refusal(message: impl Into<String>, fix: impl Into<String>) -> Refusal {
    Refusal::new("FA-REF-194", exit::REFUSAL, message, CITE, fix)
}

/// Fold only authorized controls. Documents carrying the anchor MIME are
/// ordinary evidence, including legacy documents with no activating control.
pub fn anchor_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    at: CommitSeq,
) -> Result<Option<AnchorControl>, KernelError> {
    if at > db.frontier()? {
        return Err(corrupt("known-at is beyond the book head"));
    }
    let policy = EvidencePolicy::embedded().map_err(|e| corrupt(e.to_string()))?;
    let mut controls = Vec::new();
    for row in db.vertices_at(at)? {
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = crate::entry_storage::decode_at(db, &row, at)?;
        let Some(ControlPayload::SchemaChange {
            kind: SCHEMA_CHANGE_ADJUSTMENT_LAYER,
            canonical_bytes,
        }) = &entry.proposal.control
        else {
            continue;
        };
        let anchor = AdjustmentLayerAnchor::decode(canonical_bytes)?;
        if anchor.book_id != book.book_id
            || entry.proposal.book_id != book.book_id
            || entry.proposal.class != EntryClass::SCHEMA_CONTROL
            || entry.proposal.branch_id != Id128::TRUNK
            || !entry.proposal.legs.is_empty()
            || !entry.approvals.is_empty()
            || entry.plan_certificate.is_some()
            || !matches!(
                entry.proposal.origin,
                EntryOrigin::Control {
                    control_kind: ControlKind::CHART_INSTALL,
                    ..
                }
            )
            || row.labels.as_slice() != [label::ENTRY]
            || row.props != entry_mirrors(&entry)?
            || db
                .vertex_at(
                    crate::outcome::entry_outcome_vid(&entry.proposal),
                    row.created_at,
                )?
                .is_none()
            || !crate::outcome::verify_control_recorded(db, &row, &entry)?
        {
            return Err(corrupt(
                "the activating control or its atomic claim does not verify",
            ));
        }
        let oid = anchor.document_oid()?;
        // Custody transfers legitimately version the Document's custody_len.
        // The activation binds the evidence it observed at publication, not
        // a later metadata version's creation sequence.
        let document_row = db
            .vertex_at(document_vid(&oid), row.created_at)?
            .ok_or_else(|| corrupt("the activating control's document is absent"))?;
        let document = crate::evidence::verify_row(&document_row, &policy).map_err(corrupt)?;
        if document.book_id != book.book_id
            || document.kind != DOCUMENT_KIND
            || document.doc_commit != anchor.document_commit()?
            || !matches!(&document.storage, Storage::Inline(bytes) if bytes == canonical_bytes)
            || document_row.created_at > row.created_at
        {
            return Err(corrupt("the activating control's document differs"));
        }
        let receipt_vid = crate::custody::custody_vid(book.book_id, &oid, 0);
        let receipt_row = db
            .vertex_at(receipt_vid, at)?
            .ok_or_else(|| corrupt("the anchor document lacks its intake receipt"))?;
        let receipt = crate::custody::CustodyEvent::decode(&crate::rows::bytes(
            &receipt_row,
            property::FA_PAYLOAD,
            "anchor document receipt",
        )?)?;
        if receipt_row.labels.as_slice() != [label::IMPORT_RECEIPT]
            || receipt_row.created_at > row.created_at
            || !crate::outcome::original(db, &receipt_row)?
            || receipt.book_id != book.book_id
            || receipt.document_oid != oid
            || receipt.index != 0
            || receipt.prev_digest != [0; 32]
            || !matches!(receipt.body, crate::custody::CustodyBody::Receipt {
                digest_at_receipt, ..
            } if digest_at_receipt == document.doc_commit)
        {
            return Err(corrupt("the anchor document's intake receipt differs"));
        }
        controls.push(AnchorControl {
            anchor,
            entry: entry.entry_ref(row.vid),
            recorded_at: row.created_at,
        });
    }
    controls.sort_by_key(|control| (control.recorded_at, control.entry.vid));
    for pair in controls.windows(2) {
        if pair[0].anchor.parent_book_id != pair[1].anchor.parent_book_id
            || pair[0].anchor.parent_known_at >= pair[1].anchor.parent_known_at
        {
            return Err(corrupt(
                "control history changes parent or fails to advance its prefix",
            ));
        }
    }
    Ok(controls.pop())
}

/// Activate an anchor and its evidence in one native transaction. An exact
/// retry keeps the original activation sequence; a restatement must advance.
#[allow(clippy::too_many_arguments)]
pub async fn record_anchor<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    parent_book_id: Id128,
    parent_known_at: CommitSeq,
    description: Erasable<String>,
) -> Outcome<AnchorRecorded> {
    if let Err(denial) = fa_policy::admit_direct_write(capability) {
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    if let Some(refusal) = admit_schema_change(db, book, capability.holder(), capability)? {
        return Ok(Err(refusal));
    }
    if let Err(refusal) = crate::policy::capability_admitted(db, book, capability)? {
        return Ok(Err(refusal));
    }
    if parent_book_id == book.book_id || parent_known_at.0 == 0 {
        return Ok(Err(refusal(
            "an adjustment layer needs a distinct parent book and parent_known_at >= 1",
            "name the parent book's committed prefix",
        )));
    }
    if let Err(refusal) = crate::scratch::ensure_history(db, cx).await? {
        return Ok(Err(refusal));
    }
    let prior = anchor_at(db, book, db.frontier()?)?;
    if let Some(prior) = &prior {
        if prior.anchor.parent_book_id != parent_book_id
            || parent_known_at < prior.anchor.parent_known_at
        {
            return Ok(Err(refusal(
                "an adjustment-layer anchor cannot switch parent books or regress parent_known_at",
                "advance the current parent's prefix, or create another adjustment-layer book",
            )));
        }
        if parent_known_at == prior.anchor.parent_known_at {
            return Ok(Ok(AnchorRecorded {
                control: prior.clone(),
                already_recorded: true,
            }));
        }
    }
    let anchor = AdjustmentLayerAnchor {
        book_id: book.book_id,
        parent_book_id,
        parent_known_at,
    };
    let bytes = anchor.encode()?;
    let key = fa_model::domain_digest(KEY_DOMAIN, &[&bytes]);
    let proposal = schema_control_proposal(
        book,
        SCHEMA_CHANGE_ADJUSTMENT_LAYER,
        bytes.clone(),
        capability.holder(),
        DateDay(0),
        &key,
        description,
    );
    let entry = proposal.clone().seal(Vec::new(), None)?;
    let evid = entry_vid(book.book_id, &capability.holder().0.to_le_bytes(), &key);
    let policy = EvidencePolicy::embedded().map_err(|e| corrupt(e.to_string()))?;
    let document = Document {
        book_id: book.book_id,
        kind: DOCUMENT_KIND,
        mime: MIME.into(),
        grade: crate::upload::upload_grade(&policy, capability.sod_profile())?,
        retrieved_by: capability.holder(),
        bytes,
    };
    let kind_name = match crate::evidence::intake_check(
        &policy,
        book,
        &document,
        crate::evidence::inline_document_bound(&policy),
    ) {
        Ok(kind) => kind,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let mut txn = db.begin(&cx.txn())?;
    if let Err(refusal) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let _epoch = crate::policy::epoch_witness(&txn, db)?;
    if let Err(refusal) =
        crate::outcome::witness_named_key(&txn, db, book.book_id, capability.holder(), &key, evid)?
    {
        txn.abort();
        return Ok(Err(refusal));
    }
    if txn.vertex(db, evid)?.is_some() {
        txn.abort();
        return Ok(Err(crate::outcome::key_conflict()));
    }
    if let Err(refusal) = crate::outcome::require_unused_legacy_key(
        &txn,
        db,
        book,
        crate::outcome::entry_outcome_vid(&proposal),
    )? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let mut batch = WriteBatch::new(relation::CUSTODY_OF);
    if let Some(row) = txn.vertex(db, document_vid(&document.oid()))? {
        let existing = crate::evidence::verify_row(&row, &policy).map_err(corrupt)?;
        if existing.book_id != book.book_id
            || existing.kind != DOCUMENT_KIND
            || existing.doc_commit != document.doc_commit()
            || !matches!(&existing.storage, Storage::Inline(bytes) if bytes == &document.bytes)
        {
            txn.abort();
            return Err(corrupt("pre-existing document does not match the anchor"));
        }
        if let Err(refusal) = crate::custody::witness_custody(&txn, db, &policy, &document.oid())? {
            txn.abort();
            return Ok(Err(refusal));
        }
    } else {
        crate::evidence::stage_document(&mut batch, book, &document, &kind_name)?;
        crate::custody::stage_receipt(
            &mut batch,
            book,
            &document,
            IntakeSource::Upload {
                principal: capability.holder(),
            },
            capability.holder(),
            None,
        )?;
    }
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    crate::outcome::stage_control(&mut batch, &entry, evid)?;
    if let Err(error) = txn.write(db, batch) {
        txn.abort();
        return Err(error.into());
    }
    if let Err(denial) = fa_policy::current(capability, db.frontier()?) {
        txn.abort();
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    match txn.commit(db, &cx.commit()).await {
        Ok(recorded_at) => Ok(Ok(AnchorRecorded {
            control: AnchorControl {
                anchor,
                entry: entry.entry_ref(evid),
                recorded_at,
            },
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!("an adjustment-layer anchor witness changed: {detail}"),
                "FG-LAW-FCW-01",
                "retry against the current frontier",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => Ok(Err(crate::outcome::key_conflict())),
        Err(error) => Err(error.into()),
    }
}
