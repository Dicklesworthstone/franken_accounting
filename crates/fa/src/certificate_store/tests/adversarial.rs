//! Distinguish immutable layout validation from full artifact validation.
//! These fixtures deliberately publish malformed storage through the raw
//! native test handle. The public retention API cannot publish these states.

use super::*;
use fa_model::Writer;
use fgdb::DatabaseKeys;
use fgdb_types::ids::DatabaseSecurityNamespaceId;

#[test]
fn same_birth_complete_fragments_still_require_the_full_certificate_digest() {
    for corrupt in [false, true] {
        let (mut h, certificate) = Harness::populated();
        let mut bytes = certificate.canonical_bytes().unwrap();
        if corrupt {
            // Shape, count, per-part ordinal, full digest mirrors and birth
            // sequence remain correct. Only the reconstructed bytes differ.
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
        }
        let cx = h.cx();
        let batch = chunks::stage(&cx.query(), h.book.context(), &certificate.digest,
            certificate_vid(BOOK, &certificate.digest), bytes).unwrap().unwrap();
        let seq = h.write(batch);
        if corrupt {
            let refused = h.read(&certificate.digest).unwrap_err();
            assert_eq!(refused.code, crate::certificate::code::CERTIFICATE_INVALID);
            assert!(refused.message.contains("content digest"), "{refused}");
            assert!(h.retain(&certificate).is_err());
        } else {
            assert_eq!(h.read(&certificate.digest).unwrap(), certificate);
            assert_eq!(h.retain(&certificate).unwrap().recorded_at, seq);
        }
        assert_eq!(h.head(), seq);
    }
}

#[test]
fn complete_but_late_fragments_cannot_repair_a_previously_published_root() {
    let (mut h, certificate) = Harness::populated();
    let bytes = certificate.canonical_bytes().unwrap();
    let manifest = chunks::Manifest::new(bytes.len()).unwrap();
    let mut root = WriteBatch::new(relation::DERIVED_FROM);
    stage_record(&mut root, h.book.context(), &certificate.digest,
        certificate_vid(BOOK, &certificate.digest), manifest.encode().unwrap()).unwrap();
    let root_seq = h.write(root);
    assert!(h.read(&certificate.digest).is_err());
    let mut pieces = WriteBatch::new(relation::DERIVED_FROM);
    for (index, part) in bytes.chunks(chunks::CHUNK_BYTES).enumerate() {
        let index = u32::try_from(index).unwrap();
        // Independent wire construction from the registered representation.
        let mut w = Writer::new();
        w.fixed(b"fa:certificate-fragment:v1").u32(index).bytes(part);
        stage_record(&mut pieces, h.book.context(), &certificate.digest,
            chunks::fragment_vid(BOOK, &certificate.digest, index), w.finish().unwrap()).unwrap();
    }
    let parts_seq = h.write(pieces);
    assert!(parts_seq > root_seq);
    let refused = h.read(&certificate.digest).unwrap_err();
    assert!(refused.message.contains("not published with"), "{refused}");
    assert!(h.retain(&certificate).is_err());
    assert_eq!(h.head(), parts_seq);
}

#[test]
fn scratch_replay_excludes_the_complete_physical_certificate_representation() {
    let (mut h, certificate) = Harness::populated();
    h.retain(&certificate).unwrap();
    let before = h.head();
    let rows = h.book.db.vertices_at(before).unwrap();
    assert!(rows.iter().filter(|row| row.labels.contains(&label::CERTIFICATE)).count() >= 3);
    let cx = h.cx();
    let target = h.runtime.block_on(Database::open_memory(&cx.commit(), DatabaseKeys::new(
        [0xe1; 32], DatabaseSecurityNamespaceId([0xe2; 32]), [0xe3; 32],
    ))).unwrap();
    let (scratch, map) = h.runtime.block_on(h.book.replay_into(
        &cx,
        target,
        &BookKeys::for_development(0xc1),
        Some(before),
        Entropy::deterministic(225),
    )).unwrap().unwrap();
    assert!(!scratch.db.vertices_at(scratch.head(&cx).unwrap()).unwrap()
        .iter().any(|row| row.labels.contains(&label::CERTIFICATE)));
    h.book.verify_replay(&cx, &scratch, &map).unwrap().unwrap();
    assert_eq!(h.read(&certificate.digest).unwrap(), certificate);
    assert_eq!(h.head(), before);
}
