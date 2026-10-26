//! Transaction-local storage for bounded canonical payloads (fa-nd7g).
//!
//! The caller owns the root, authority checks and transaction. This module
//! only stages immutable fragments; it never publishes, repairs or opens a
//! second store. Consumers include posting plans and committed intent outcomes.

use asupersync::fs::Vfs;
use fa_model::symbols::property;
use fa_model::{Id128, Reader, Writer, domain_digest};
use fgdb::{Database, VertexRow, WriteBatch, WriteTxnError};
use fgdb_delta_types::LabelId;
use fgdb_types::{CanonicalScalar, CommitSeq, QueryCx, VId};

use crate::refusal::KernelError;
use crate::rows::{prop, scalar_bytes};

pub const CHUNK_BYTES: usize = fa_model::limits::OBJECT_CHUNK_BYTES;
const FORMAT: &[u8] = b"fa:object:v1";

/// Registered wire discriminators; adding a consumer must register its kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ObjectKind {
    PostPlan = 1,
    ReplacementPlan = 2,
    BatchPlan = 3,
    IntentOutcome = 4,
    RegistryEpoch = 5,
}

/// Public content identity, separate from a caller's graph locator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectRef {
    pub digest: [u8; 32],
    pub len: u64,
    pub chunk_root: [u8; 32],
}

fn corrupt(root: VId, message: &str) -> KernelError {
    KernelError::Corrupt(format!("object {:032x}: {message}", root.0))
}

fn identity(kind: ObjectKind, bytes: &[u8]) -> ObjectRef {
    ObjectRef {
        digest: domain_digest(
            b"fa:object-content:v1",
            &[&(kind as u16).to_le_bytes(), bytes],
        ),
        len: bytes.len() as u64,
        chunk_root: crate::evidence::chunk_root(bytes),
    }
}

/// Inline bytes remain unchanged. A larger body becomes a fixed-size manifest.
/// The caller's format bound applies before this storage encoding.
pub fn payload(kind: ObjectKind, bytes: &[u8]) -> Result<Vec<u8>, KernelError> {
    if bytes.len() <= CHUNK_BYTES {
        return Ok(bytes.to_vec());
    }
    let object = identity(kind, bytes);
    let mut w = Writer::new();
    w.fixed(FORMAT)
        .u16(kind as u16)
        .u64(object.len)
        .fixed(&object.digest)
        .fixed(&object.chunk_root);
    Ok(w.finish()?)
}

fn fragment_vid(book: Id128, root: VId, object: ObjectRef, index: usize) -> VId {
    let hash = domain_digest(
        b"fa:object-fragment:v1",
        &[
            &book.0,
            &root.0.to_le_bytes(),
            &object.digest,
            &(index as u64).to_le_bytes(),
        ],
    );
    let mut low = [0; 16];
    low.copy_from_slice(&hash[..16]);
    VId(u128::from_le_bytes(low))
}

/// Add fragments to the SAME batch as their root; no root or commit is created.
/// The caller supplies the storage label so fragments inherit its observation
/// and scratch-replay policy. Plans and source epochs use Certificate;
/// outcomes use IntentOutcome.
pub fn stage(
    cx: &QueryCx,
    batch: &mut WriteBatch,
    book: Id128,
    root: VId,
    label: LabelId,
    kind: ObjectKind,
    bytes: &[u8],
) -> Result<(), KernelError> {
    cx.checkpoint().map_err(WriteTxnError::Interrupted)?;
    if bytes.len() <= CHUNK_BYTES {
        return Ok(());
    }
    let object = identity(kind, bytes);
    for (index, part) in bytes.chunks(CHUNK_BYTES).enumerate() {
        cx.checkpoint().map_err(WriteTxnError::Interrupted)?;
        batch.create_vertex(
            fragment_vid(book, root, object, index),
            vec![label],
            vec![
                (
                    property::FA_PAYLOAD,
                    scalar_bytes("object fragment", part.to_vec())?,
                ),
                (
                    property::FA_DIGEST,
                    scalar_bytes("object digest", object.digest.to_vec())?,
                ),
                (
                    property::BOOK_ID,
                    scalar_bytes("object book", book.0.to_vec())?,
                ),
            ],
        );
    }
    Ok(())
}

/// Reassemble at one pinned snapshot. All fragments must be original records
/// born with the root. A later restoration of identical bytes is corruption.
/// The caller validates root immutability and its own logical digest as well.
#[allow(clippy::too_many_arguments)]
pub fn read<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: Id128,
    root: &VertexRow,
    label: LabelId,
    kind: ObjectKind,
    at: CommitSeq,
    max_bytes: usize,
) -> Result<Vec<u8>, KernelError> {
    cx.checkpoint().map_err(WriteTxnError::Interrupted)?;
    let Some(CanonicalScalar::Bytes(encoded)) = prop(root, property::FA_PAYLOAD) else {
        return Err(corrupt(root.vid, "missing canonical payload"));
    };
    let encoded = encoded.as_slice();
    if !encoded.starts_with(FORMAT) {
        if encoded.len() > max_bytes {
            return Err(corrupt(root.vid, "inline payload exceeds its format bound"));
        }
        return Ok(encoded.to_vec());
    }
    let mut r = Reader::new(encoded);
    let bad = |error: fa_model::DecodeError| corrupt(root.vid, &error.to_string());
    r.fixed::<{ FORMAT.len() }>("object format").map_err(bad)?;
    if r.u16("object kind").map_err(bad)? != kind as u16 {
        return Err(corrupt(root.vid, "object kind differs from its consumer"));
    }
    let object = ObjectRef {
        len: r.u64("object length").map_err(bad)?,
        digest: r.fixed("object digest").map_err(bad)?,
        chunk_root: r.fixed("object chunk root").map_err(bad)?,
    };
    r.finish().map_err(bad)?;
    let size = usize::try_from(object.len)
        .map_err(|_| corrupt(root.vid, "object length is not addressable"))?;
    if size <= CHUNK_BYTES || size > max_bytes {
        return Err(corrupt(
            root.vid,
            "manifest length is outside its format bound",
        ));
    }
    let before = CommitSeq(
        root.created_at
            .0
            .checked_sub(1)
            .ok_or_else(|| corrupt(root.vid, "root has no creating commit"))?,
    );
    let mut bytes = Vec::with_capacity(size);
    for index in 0..size.div_ceil(CHUNK_BYTES) {
        cx.checkpoint().map_err(WriteTxnError::Interrupted)?;
        let vid = fragment_vid(book, root.vid, object, index);
        let Some(row) = db.vertex_at(vid, at)? else {
            return Err(corrupt(root.vid, "missing or retired fragment"));
        };
        if row.labels.as_slice() != [label]
            || row.retired_at.is_some_and(|retired| retired <= at)
            || row.props.len() != 3
            || row.created_at != root.created_at
            || db.vertex_at(vid, before)?.is_some()
            || db.vertex_at(vid, row.created_at)?.as_ref() != Some(&row)
            || !matches!(prop(&row, property::BOOK_ID), Some(CanonicalScalar::Bytes(v)) if v.as_slice() == book.0)
            || !matches!(prop(&row, property::FA_DIGEST), Some(CanonicalScalar::Bytes(v)) if v.as_slice() == object.digest)
        {
            return Err(corrupt(
                root.vid,
                "fragment identity or immutable birth differs",
            ));
        }
        let Some(CanonicalScalar::Bytes(part)) = prop(&row, property::FA_PAYLOAD) else {
            return Err(corrupt(root.vid, "fragment has no bytes"));
        };
        if part.len() != (size - bytes.len()).min(CHUNK_BYTES) {
            return Err(corrupt(root.vid, "fragment length differs from manifest"));
        }
        bytes.extend_from_slice(part.as_slice());
    }
    if identity(kind, &bytes) != object {
        return Err(corrupt(root.vid, "content digest or chunk root mismatch"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;
    use fa_model::symbols::{label, relation};
    use fgdb::{DatabaseKeys, MemVfs};
    use fgdb_types::context::PurposeContexts;
    use fgdb_types::ids::DatabaseSecurityNamespaceId;

    #[test]
    fn native_boundaries_round_trip_and_rewritten_fragment_is_corruption() {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root_cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root_cx);
        let mut db: Database<MemVfs> = runtime
            .block_on(Database::open_memory(
                &cx.commit(),
                DatabaseKeys::new([11; 32], DatabaseSecurityNamespaceId([12; 32]), [13; 32]),
            ))
            .unwrap();
        let book = Id128([14; 16]);
        for (n, (kind, size)) in [
            ObjectKind::PostPlan,
            ObjectKind::ReplacementPlan,
            ObjectKind::BatchPlan,
            ObjectKind::IntentOutcome,
            ObjectKind::RegistryEpoch,
        ]
        .into_iter()
        .flat_map(|kind| {
            [4095, 4096, 4097, 16383, 16384, 16385, 1024 * 1024]
                .into_iter()
                .map(move |size| (kind, size))
        })
        .enumerate()
        {
            let root = VId(n as u128 + 1);
            let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let mut batch = WriteBatch::new(relation::CITES);
            stage(
                &cx.query(),
                &mut batch,
                book,
                root,
                label::CERTIFICATE,
                kind,
                &bytes,
            )
            .unwrap();
            batch.create_vertex(
                root,
                vec![label::CERTIFICATE],
                vec![(
                    property::FA_PAYLOAD,
                    scalar_bytes("object", payload(kind, &bytes).unwrap()).unwrap(),
                )],
            );
            let before = db.frontier().unwrap();
            assert!(
                db.vertex(root).unwrap().is_none(),
                "staging must not publish"
            );
            let seq = runtime.block_on(db.write(&cx.commit(), batch)).unwrap();
            let row = db.vertex(root).unwrap().unwrap();
            assert!(db.vertex_at(root, before).unwrap().is_none());
            assert_eq!(row.created_at, seq);
            assert_eq!(
                read(
                    &db,
                    &cx.query(),
                    book,
                    &row,
                    label::CERTIFICATE,
                    kind,
                    seq,
                    size
                )
                .unwrap(),
                bytes
            );
            assert!(
                read(
                    &db,
                    &cx.query(),
                    book,
                    &row,
                    label::CERTIFICATE,
                    kind,
                    seq,
                    size - 1
                )
                .is_err()
            );
            if size <= CHUNK_BYTES {
                continue;
            }
            let wrong_kind = match kind {
                ObjectKind::PostPlan => ObjectKind::ReplacementPlan,
                ObjectKind::ReplacementPlan
                | ObjectKind::BatchPlan
                | ObjectKind::IntentOutcome
                | ObjectKind::RegistryEpoch => ObjectKind::PostPlan,
            };
            assert!(
                read(
                    &db,
                    &cx.query(),
                    book,
                    &row,
                    label::CERTIFICATE,
                    wrong_kind,
                    seq,
                    size
                )
                .is_err()
            );
            let vid = fragment_vid(book, root, identity(kind, &bytes), 0);
            let mut rewrite = WriteBatch::new(relation::CITES);
            let mut damaged = bytes[..CHUNK_BYTES].to_vec();
            damaged[0] ^= 1;
            rewrite.set_vertex_property(
                vid,
                property::FA_PAYLOAD,
                Some(scalar_bytes("damaged fragment", damaged).unwrap()),
            );
            runtime.block_on(db.write(&cx.commit(), rewrite)).unwrap();
            assert!(
                read(
                    &db,
                    &cx.query(),
                    book,
                    &row,
                    label::CERTIFICATE,
                    kind,
                    db.frontier().unwrap(),
                    size
                )
                .is_err()
            );
            // Restoring identical bytes still cannot masquerade as original.
            let mut restore = WriteBatch::new(relation::CITES);
            restore.set_vertex_property(
                vid,
                property::FA_PAYLOAD,
                Some(scalar_bytes("restored fragment", bytes[..CHUNK_BYTES].to_vec()).unwrap()),
            );
            runtime.block_on(db.write(&cx.commit(), restore)).unwrap();
            assert!(
                read(
                    &db,
                    &cx.query(),
                    book,
                    &row,
                    label::CERTIFICATE,
                    kind,
                    db.frontier().unwrap(),
                    size,
                )
                .is_err()
            );
            assert_eq!(
                read(
                    &db,
                    &cx.query(),
                    book,
                    &row,
                    label::CERTIFICATE,
                    kind,
                    seq,
                    size
                )
                .unwrap(),
                bytes
            );
        }
    }

    #[test]
    fn manifest_has_independent_wire_prefix_and_document_merkle_root() {
        assert_eq!(CHUNK_BYTES, crate::evidence::CHUNK_BYTES);
        let bytes = vec![7; CHUNK_BYTES + 1];
        let wire = payload(ObjectKind::PostPlan, &bytes).unwrap();
        let mut prefix = b"fa:object:v1".to_vec();
        prefix.extend_from_slice(&[1, 0, 1, 16, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&wire[..prefix.len()], prefix);
        assert_eq!(
            &wire[wire.len() - 32..],
            crate::evidence::chunk_root(&bytes)
        );
        assert_ne!(
            identity(ObjectKind::PostPlan, &bytes),
            identity(ObjectKind::ReplacementPlan, &bytes)
        );
    }

    #[test]
    fn same_birth_corrupt_bytes_fail_the_content_check() {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root_cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root_cx);
        let mut db: Database<MemVfs> = runtime
            .block_on(Database::open_memory(
                &cx.commit(),
                DatabaseKeys::new([21; 32], DatabaseSecurityNamespaceId([22; 32]), [23; 32]),
            ))
            .unwrap();
        let book = Id128([24; 16]);
        let root = VId(25);
        let bytes = vec![3; CHUNK_BYTES + 1];
        let mut batch = WriteBatch::new(relation::CITES);
        stage(
            &cx.query(),
            &mut batch,
            book,
            root,
            label::CERTIFICATE,
            ObjectKind::PostPlan,
            &bytes,
        )
        .unwrap();
        batch.create_vertex(
            root,
            vec![label::CERTIFICATE],
            vec![(
                property::FA_PAYLOAD,
                scalar_bytes("manifest", payload(ObjectKind::PostPlan, &bytes).unwrap()).unwrap(),
            )],
        );
        // Native identity/birth checks all pass: the planted defect is in the
        // first committed bytes, so only the content commitment can catch it.
        let fragment = fragment_vid(book, root, identity(ObjectKind::PostPlan, &bytes), 0);
        batch.set_vertex_property(
            fragment,
            property::FA_PAYLOAD,
            Some(scalar_bytes("planted corrupt fragment", vec![4; CHUNK_BYTES]).unwrap()),
        );
        let seq = runtime.block_on(db.write(&cx.commit(), batch)).unwrap();
        let row = db.vertex(root).unwrap().unwrap();
        let error = read(
            &db,
            &cx.query(),
            book,
            &row,
            label::CERTIFICATE,
            ObjectKind::PostPlan,
            seq,
            bytes.len(),
        )
        .unwrap_err();
        assert!(
            matches!(error, KernelError::Corrupt(ref message) if message.contains("content digest or chunk root mismatch")),
            "{error}"
        );
    }

    #[test]
    fn registered_object_storage_matches_the_live_wire_contract() {
        let schema = fa_registry::toml::parse(include_str!(
            "../../../registries/object_schemas/object_storage.toml"
        ))
        .unwrap();
        for (key, expected) in [
            ("manifest_format", FORMAT),
            ("content_domain", b"fa:object-content:v1".as_slice()),
            ("fragment_domain", b"fa:object-fragment:v1".as_slice()),
        ] {
            assert_eq!(
                schema.root.get(key).unwrap().as_str().unwrap().as_bytes(),
                expected
            );
        }
        for (key, expected) in [
            ("chunk_bytes", CHUNK_BYTES as i128),
            ("inline_bytes", CHUNK_BYTES as i128),
            ("post_plan_kind", ObjectKind::PostPlan as i128),
            ("replacement_plan_kind", ObjectKind::ReplacementPlan as i128),
            ("registry_epoch_kind", ObjectKind::RegistryEpoch as i128),
        ] {
            assert_eq!(schema.root.get(key).unwrap().as_int().unwrap(), expected);
        }
    }
}
