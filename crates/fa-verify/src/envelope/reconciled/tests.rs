use super::*;
use crate::codec::Writer;
use crate::envelope::{
    ATTESTATION_DIGEST_DOMAIN, KIND_ATTESTATION, LeafEnvelope, RecordError, check_record,
    envelope_of_record, framed_digest,
};

const BOOK: [u8; 16] = [0x5a; 16];
const STATEMENT: [u8; 32] = [0x22; 32];

fn manifest_bytes(previous: Option<&[u8]>) -> Vec<u8> {
    let mut w = Writer::default();
    w.fixed(b"FA-BANK-IMPORT")
        .u16(if previous.is_some() { 2 } else { 1 })
        .u16(0)
        .fixed(&BOOK)
        .u128(19)
        .u8(6)
        .u16(1)
        .fixed(&STATEMENT)
        .fixed(&[0x23; 32])
        .u32(1)
        .u64(if previous.is_some() { 8 } else { 7 })
        .i32(20_500)
        .i128(50_000)
        .i128(60_000)
        .count(2)
        .fixed(&[0x31; 32])
        .fixed(&[0x32; 32]);
    if let Some(previous) = previous {
        let commitment = crate::document::doc_commit(WORKPAPER_KIND, previous);
        w.fixed(&document_oid(&BOOK, &commitment))
            .fixed(&commitment)
            .fixed(&[0x12; 32])
            .fixed(&[0x13; 32])
            .u128(42)
            .fixed(&[0x44; 32])
            .u64(4)
            .u64(7)
            .i32(20_470)
            .i128(50_000);
    }
    w.buf
}

fn previous_manifest() -> Vec<u8> {
    let mut w = Writer::default();
    w.fixed(b"FA-BANK-IMPORT")
        .u16(1)
        .u16(0)
        .fixed(&BOOK)
        .u128(19)
        .u8(6)
        .u16(1)
        .fixed(&[0x12; 32])
        .fixed(&[0x13; 32])
        .u32(1)
        .u64(7)
        .i32(20_470)
        .i128(0)
        .i128(50_000)
        .count(1)
        .fixed(&[0x11; 32]);
    w.buf
}

#[derive(Clone)]
struct Fixture {
    manifest: Vec<u8>,
    manifest_oid: [u8; 32],
    predecessors: Vec<Vec<u8>>,
    imported: u64,
    evaluated: u64,
    cash: i128,
    matches: Vec<(u128, [u8; 32])>,
    subject: [u8; 32],
    evidence: Vec<[u8; 32]>,
    profile: u8,
}

impl Fixture {
    fn new(linked: bool) -> Self {
        let predecessors = if linked {
            vec![previous_manifest()]
        } else {
            Vec::new()
        };
        let mut fixture = Self {
            manifest: manifest_bytes(predecessors.first().map(Vec::as_slice)),
            manifest_oid: [0; 32],
            predecessors,
            imported: 6,
            evaluated: 8,
            cash: 60_000,
            matches: vec![(100, [0x41; 32]), (101, [0x42; 32])],
            subject: [0; 32],
            evidence: Vec::new(),
            profile: 0,
        };
        fixture.rebind_manifest();
        fixture
    }

    fn rebind_manifest(&mut self) {
        let commitment = crate::document::doc_commit(WORKPAPER_KIND, &self.manifest);
        self.manifest_oid = document_oid(&BOOK, &commitment);
        self.subject = self.manifest_oid;
        self.evidence = vec![self.manifest_oid, STATEMENT];
        self.evidence.sort();
    }

    fn record(&self) -> (Vec<u8>, usize) {
        let mut w = Writer::default();
        w.u16(1)
            .fixed(&BOOK)
            .u8(3)
            .fixed(&self.manifest_oid)
            .bytes(&self.manifest)
            .count(self.predecessors.len());
        for previous in &self.predecessors {
            w.bytes(previous);
        }
        w.u128(43)
            .fixed(&[0x45; 32])
            .u64(self.imported)
            .u64(self.evaluated)
            .i128(self.cash)
            .fixed(&[0x46; 32])
            .count(self.matches.len());
        for (vid, digest) in &self.matches {
            w.u128(*vid).fixed(digest);
        }
        w.count(1)
            .u8(1)
            .fixed(&self.subject)
            .u128(17)
            .count(self.evidence.len());
        for oid in &self.evidence {
            w.fixed(oid);
        }
        let split = w.buf.len();
        let digest = framed_digest(ATTESTATION_DIGEST_DOMAIN, &w.buf);
        w.fixed(&digest).u8(0).u8(self.profile).fixed(&[0x55; 32]);
        (w.buf, split)
    }

    fn verify(&self) -> Result<LeafEnvelope, RecordError> {
        let (record, split) = self.record();
        envelope_of_record(KIND_ATTESTATION, &record, split, 9, 2)
    }
}

#[test]
fn reconciled_records_preserve_envelopes_for_unlinked_and_linked_manifests() {
    for linked in [false, true] {
        let f = Fixture::new(linked);
        let (record, split) = f.record();
        let envelope = f.verify().unwrap();
        assert_eq!(envelope.kind, KIND_ATTESTATION);
        assert_eq!(envelope.book_id, BOOK);
        assert_eq!(envelope.branch_id, [0; 16]);
        assert_eq!(envelope.class, 3);
        assert_eq!(envelope.commit_seq, 9);
        assert_eq!(envelope.within_commit_ordinal, 2);
        assert_eq!(envelope.effective_day, None);
        assert!(envelope.account_vids.is_empty());
        assert!(envelope.unit_ids.is_empty());
        assert_eq!(
            envelope.record_digest,
            framed_digest(ATTESTATION_DIGEST_DOMAIN, &record[..split])
        );
        assert!(check_record(&envelope, &record, split).unwrap().is_empty());
        let mut wrong_envelope = envelope;
        wrong_envelope.class = 4;
        assert_eq!(
            check_record(&wrong_envelope, &record, split),
            Err(RecordError::Envelope)
        );
    }
}

#[test]
fn reconciled_records_require_publication_immediately_after_the_reviewed_prefix() {
    let fixture = Fixture::new(false);
    let (record, split) = fixture.record();
    // This original body evaluates prefix 8, so only native publication 9
    // can carry it. A later position cannot silently adopt the old review.
    for commit_seq in [0, 7, 8, 10, u64::MAX] {
        assert!(
            matches!(
                envelope_of_record(KIND_ATTESTATION, &record, split, commit_seq, 2),
                Err(RecordError::Decode(DecodeError {
                    what: "reconciled.recorded_at",
                    ..
                }))
            ),
            "accepted impossible publication at {commit_seq} for evaluated prefix 8"
        );
    }
    assert!(envelope_of_record(KIND_ATTESTATION, &record, split, 9, 2).is_ok());

    let mut overflow = fixture;
    overflow.evaluated = u64::MAX;
    let (record, split) = overflow.record();
    for commit_seq in [0, u64::MAX] {
        assert!(matches!(
            envelope_of_record(KIND_ATTESTATION, &record, split, commit_seq, 2),
            Err(RecordError::Decode(DecodeError {
                what: "reconciled.recorded_at",
                ..
            }))
        ));
    }
}

#[test]
fn reconciled_records_refuse_false_sources_subjects_evidence_and_exact_close_shape() {
    let good = Fixture::new(false);
    let mut cases = Vec::new();
    let mut wrong = good.clone();
    wrong.manifest_oid[0] ^= 1;
    cases.push(("source identity", wrong));
    let mut wrong = good.clone();
    wrong.subject[0] ^= 1;
    cases.push(("subject", wrong));
    let mut wrong = good.clone();
    wrong.evidence.reverse();
    cases.push(("evidence order", wrong));
    let mut wrong = good.clone();
    wrong.evidence.pop();
    cases.push(("missing evidence", wrong));
    let mut wrong = good.clone();
    wrong.evidence.push([0xff; 32]);
    cases.push(("extra evidence", wrong));
    let mut wrong = good.clone();
    wrong.profile = 1;
    cases.push(("non-Human signer", wrong));
    let mut wrong = good.clone();
    wrong.cash += 1;
    cases.push(("different closing amount", wrong));
    let mut wrong = good.clone();
    wrong.imported = 0;
    cases.push(("no native import", wrong));
    let mut wrong = good.clone();
    wrong.imported = wrong.evaluated + 1;
    cases.push(("import after evaluated prefix", wrong));
    let mut wrong = good.clone();
    wrong.matches.pop();
    cases.push(("missing confirmed line", wrong));
    let mut wrong = good.clone();
    wrong.matches.reverse();
    cases.push(("noncanonical matches", wrong));
    let mut wrong = good;
    wrong.matches[1] = wrong.matches[0];
    cases.push(("repeated confirmation", wrong));
    for (case, malformed) in cases {
        assert!(malformed.verify().is_err(), "accepted {case}");
    }
}

#[test]
fn reconciled_records_refuse_broken_predecessor_closure_and_bounded_manifest_encodings() {
    let linked = Fixture::new(true);
    let mut missing = linked.clone();
    missing.predecessors.clear();
    assert!(missing.verify().is_err());
    let mut extra = linked.clone();
    extra.predecessors.push(previous_manifest());
    assert!(extra.verify().is_err());
    let mut changed = linked.clone();
    changed.predecessors[0][34] ^= 1; // The predecessor's cash account.
    assert!(changed.verify().is_err());
    let mut late = linked;
    late.imported = 4; // Its predecessor was also published at 4.
    assert!(late.verify().is_err());

    // Re-sign and rebind malformed manifest bytes: the failure is its exact
    // decoding contract, not a stale outer attestation or document digest.
    for (offset, byte) in [(0, b'X'), (14, 3), (16, 1), (50, 7), (51, 2)] {
        let mut malformed = Fixture::new(false);
        malformed.manifest[offset] = byte;
        malformed.rebind_manifest();
        assert!(
            malformed.verify().is_err(),
            "accepted manifest byte {offset}"
        );
    }
    let mut duplicate = Fixture::new(false);
    let last = duplicate.manifest.len();
    duplicate
        .manifest
        .copy_within(last - 64..last - 32, last - 32);
    duplicate.rebind_manifest();
    assert!(duplicate.verify().is_err());
    let mut trailing = Fixture::new(false);
    trailing.manifest.push(0);
    trailing.rebind_manifest();
    assert!(trailing.verify().is_err());
    let mut oversized_lines = Fixture::new(false);
    oversized_lines.manifest[165..169]
        .copy_from_slice(&((MAX_BANK_LINES + 1) as u32).to_le_bytes());
    oversized_lines.rebind_manifest();
    assert!(matches!(
        oversized_lines.verify(),
        Err(RecordError::Decode(DecodeError {
            what: "bank_import.lines",
            reason: Reason::TooLong { .. },
            ..
        }))
    ));
    let mut oversized_history = Fixture::new(false);
    oversized_history.predecessors = vec![Vec::new(); MAX_PREDECESSORS + 1];
    assert!(matches!(
        oversized_history.verify(),
        Err(RecordError::Decode(DecodeError {
            what: "reconciled.predecessors",
            reason: Reason::TooLong { .. },
            ..
        }))
    ));
    let mut oversized_matches = Fixture::new(false);
    oversized_matches
        .matches
        .resize(MAX_BANK_LINES + 1, (102, [0x43; 32]));
    assert!(matches!(
        oversized_matches.verify(),
        Err(RecordError::Decode(DecodeError {
            what: "reconciled.matches",
            reason: Reason::TooLong { .. },
            ..
        }))
    ));

    let good = Fixture::new(false);
    let (record, split) = good.record();
    assert!(
        envelope_of_record(KIND_ATTESTATION, &record[..record.len() - 1], split, 9, 2).is_err()
    );
    let mut overlong = record;
    overlong.resize(MAX_RECORD_BYTES + 1, 0);
    assert!(matches!(
        envelope_of_record(KIND_ATTESTATION, &overlong, split, 9, 2),
        Err(RecordError::Decode(DecodeError {
            reason: Reason::TooLong { .. },
            ..
        }))
    ));
}

fn declared_layout_bytes(sequence: u64) -> Vec<u8> {
    let mut w = Writer::default();
    w.fixed(b"fa:bank-csv-layout:v1")
        .bytes(b"declared-v1")
        .count(3)
        .bytes(b"Date")
        .bytes(b"Reference")
        .bytes(b"Amount")
        .u8(b';')
        .u8(b',')
        .u8(2)
        .bytes(b"Date")
        .u8(0)
        .u8(0)
        .u8(1)
        .bytes(b"Reference")
        .u8(0)
        .bytes(b"Amount")
        .u8(1)
        .bytes(b"BANK-123")
        .u64(sequence)
        .bytes(b"USD")
        .i32(20_500)
        .bytes(b"500,00")
        .bytes(b"600,00");
    w.buf
}

fn declare_layout(fixture: &mut Fixture, layout: &[u8]) {
    let boundary = manifest_bytes(None).len();
    let predecessor = fixture.manifest.split_off(boundary);
    fixture.manifest[14..16].copy_from_slice(&3_u16.to_le_bytes());
    let mut w = Writer::default();
    w.bytes(layout)
        .u8(u8::from(!predecessor.is_empty()))
        .fixed(&predecessor);
    fixture.manifest.extend(w.buf);
    fixture.rebind_manifest();
}

#[test]
fn reconciled_v3_layouts_are_independently_decoded_with_and_without_predecessors() {
    for linked in [false, true] {
        let mut f = Fixture::new(linked);
        let layout = declared_layout_bytes(if linked { 8 } else { 7 });
        declare_layout(&mut f, &layout);
        assert!(f.verify().is_ok(), "declared layout linked={linked}");
        let (record, split) = f.record();
        let envelope = f.verify().unwrap();
        assert!(check_record(&envelope, &record, split).unwrap().is_empty());

        for length in 0..layout.len() {
            let mut truncated = Fixture::new(linked);
            declare_layout(&mut truncated, &layout[..length]);
            assert!(truncated.verify().is_err(), "layout truncation {length}");
        }
        let mut wrong_parser = f.clone();
        wrong_parser.manifest[50] = 1;
        wrong_parser.rebind_manifest();
        assert!(wrong_parser.verify().is_err());
        let mut trailing_layout = layout.clone();
        trailing_layout.push(0);
        let mut trailing = Fixture::new(linked);
        declare_layout(&mut trailing, &trailing_layout);
        assert!(trailing.verify().is_err());
    }
    let mut wrong_sequence = Fixture::new(false);
    declare_layout(&mut wrong_sequence, &declared_layout_bytes(8));
    assert!(wrong_sequence.verify().is_err());
    let mut oversized = Fixture::new(false);
    declare_layout(&mut oversized, &vec![0; 16 * 1024 + 1]);
    assert!(oversized.verify().is_err());
}
