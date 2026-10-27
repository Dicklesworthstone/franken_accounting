//! Independent AccessEvent v1 payload validation (plan §9.7 and §13.2).
//!
//! The historical payload has no digest trailer. Its full bytes are the
//! record body, and its identity hashes domain || payload_len:u32 || payload.
//! Accumulator coverage retains that framing and the fixed eighteen-byte tag.

use super::{
    ACCESS_EVENT_DIGEST_DOMAIN, KIND_ACCESS_EVENT, LeafEnvelope, MAX_RECORD_BYTES, RecordError,
    framed_digest, non_empty_str,
};
use crate::codec::{DecodeError, Reader, Reason};

const FORMAT: &[u8; 18] = b"fa:access-event:v1";
const MAX_NAME: usize = 256;
const MAX_COMMAND: usize = 128;
const MAX_OPS: usize = 32;
const MAX_OP: usize = 64;

pub(super) fn record(
    payload: &[u8],
    body_len: usize,
    commit_seq: u64,
    within_commit_ordinal: u32,
) -> Result<LeafEnvelope, RecordError> {
    if payload.len() > MAX_RECORD_BYTES {
        return Err(RecordError::Decode(DecodeError {
            offset: 0,
            what: "access.payload",
            reason: Reason::TooLong {
                max: MAX_RECORD_BYTES,
                actual: payload.len(),
            },
        }));
    }
    if body_len != payload.len() {
        return Err(RecordError::Split);
    }
    let book_id = (|| -> Result<[u8; 16], DecodeError> {
        let mut r = Reader::new(payload);
        if r.fixed::<18>("access.format")? != *FORMAT {
            return Err(r.error("access.format", Reason::BadTag(0)));
        }
        let book_id = r.fixed("access.book_id")?;
        r.u128("access.principal")?;
        non_empty_str(&mut r, MAX_NAME, "access.principal_name")?;
        r.fixed::<32>("access.capability_commitment")?;
        let count = r.count(MAX_OPS, 5, "access.ops")?;
        let mut previous = None;
        for _ in 0..count {
            let op = non_empty_str(&mut r, MAX_OP, "access.op")?;
            // Valid UTF-8 byte order is the producer's String order. The
            // empty set is supported; duplicate or descending ops are not.
            if previous.is_some_and(|prev| prev >= op) {
                return Err(r.error("access.ops", Reason::Unsorted));
            }
            previous = Some(op);
        }
        non_empty_str(&mut r, MAX_COMMAND, "access.command")?;
        r.fixed::<32>("access.request_digest")?;
        let observed_at = r.u64("access.observed_at")?;
        if observed_at >= commit_seq {
            return Err(r.error("access.observed_at", Reason::BadTag(0)));
        }
        r.finish("access.payload")?;
        Ok(book_id)
    })()
    .map_err(RecordError::Decode)?;
    Ok(LeafEnvelope {
        kind: KIND_ACCESS_EVENT,
        book_id,
        branch_id: [0; 16],
        commit_seq,
        within_commit_ordinal,
        record_digest: framed_digest(ACCESS_EVENT_DIGEST_DOMAIN, payload),
        class: 1,
        effective_day: None,
        account_vids: Vec::new(),
        unit_ids: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blake3::hash_parts;
    use crate::codec::Writer;
    use crate::envelope::{check_record, envelope_of_record};
    use crate::proof::production::derivation::{PREFIX_FORMAT_V2, verify_prefix_with_records};
    use crate::proof::{Checkpoint, INCLUSION_FORMAT, RecordCheck, VerifyError};
    use crate::tree::leaf_hash;

    // Independent fixtures deliberately permit invalid values: even an
    // authentically hashed malformed payload must fail canonical validation.
    fn encode(name: &[u8], ops: &[&[u8]], command: &[u8], observed: u64) -> Vec<u8> {
        let mut w = Writer::default();
        w.fixed(b"fa:access-event:v1")
            .fixed(&[8; 16])
            .u128(7)
            .bytes(name)
            .fixed(&[3; 32])
            .count(ops.len());
        for op in ops {
            w.bytes(op);
        }
        w.bytes(command).fixed(&[4; 32]).u64(observed);
        w.buf
    }

    fn sample() -> Vec<u8> {
        encode(b"auditor-1", &[b"produce", b"read"], b"tb", 41)
    }

    fn derive(payload: &[u8]) -> Result<LeafEnvelope, RecordError> {
        envelope_of_record(KIND_ACCESS_EVENT, payload, payload.len(), 42, 0)
    }

    fn decoded_error(payload: &[u8]) -> DecodeError {
        match derive(payload) {
            Err(RecordError::Decode(error)) => error,
            result => panic!("expected malformed AccessEvent refusal, got {result:?}"),
        }
    }

    fn anchor(envelope: &LeafEnvelope) -> Checkpoint {
        Checkpoint {
            book_id: envelope.book_id,
            branch_id: envelope.branch_id,
            through_seq: 42,
            leaf_count: 1,
            root: leaf_hash(&envelope.encode()),
        }
    }

    fn inclusion(envelope: &LeafEnvelope, payload: &[u8]) -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes(INCLUSION_FORMAT)
            .fixed(&anchor(envelope).encode())
            .u64(0)
            .bytes(&envelope.encode())
            .u8(1)
            .u32(u32::try_from(payload.len()).unwrap())
            .bytes(payload)
            .count(0);
        w.buf
    }

    fn prefix(envelope: &LeafEnvelope, payload: &[u8]) -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes(PREFIX_FORMAT_V2)
            .fixed(&anchor(envelope).encode())
            .count(1)
            .bytes(&envelope.encode())
            .count(1)
            .u64(0)
            .u32(u32::try_from(payload.len()).unwrap())
            .bytes(payload);
        w.buf
    }

    #[test]
    fn access_payloads_reconstruct_the_existing_framed_digest_and_selection() {
        let payload = sample();
        assert_eq!(&payload[..18], b"fa:access-event:v1");
        let envelope = derive(&payload).unwrap();
        let len = u32::try_from(payload.len()).unwrap().to_le_bytes();
        assert_eq!(
            envelope.record_digest,
            hash_parts(b"fa:access-event-digest:v1", &[&len, &payload])
        );
        assert_ne!(
            envelope.record_digest,
            hash_parts(b"fa:access-event-digest:v1", &[&payload]),
            "the historical identity includes the payload length frame"
        );
        assert_eq!(envelope.kind, 6);
        assert_eq!(envelope.book_id, [8; 16]);
        assert_eq!(envelope.branch_id, [0; 16]);
        assert_eq!(envelope.class, 1);
        assert_eq!(envelope.position(), (42, 0));
        assert_eq!(envelope.effective_day, None);
        assert!(envelope.account_vids.is_empty());
        assert!(envelope.unit_ids.is_empty());
        assert_eq!(LeafEnvelope::decode(&envelope.encode()).unwrap(), envelope);
        assert!(
            check_record(&envelope, &payload, payload.len())
                .unwrap()
                .is_empty()
        );
        let cp = anchor(&envelope);
        let verified = crate::verify_inclusion(&inclusion(&envelope, &payload), &cp).unwrap();
        assert_eq!(verified.record, RecordCheck::Recomputed);
        assert_eq!(verified.envelope, envelope);
        assert_eq!(
            verify_prefix_with_records(&prefix(&envelope, &payload), &cp)
                .unwrap()
                .envelopes,
            vec![envelope]
        );
    }

    #[test]
    fn access_payload_fields_enforce_nonempty_utf8_bounds_and_canonical_ops() {
        for (name, ops, command, field) in [
            (
                Vec::new(),
                vec![b"read".to_vec()],
                b"tb".to_vec(),
                "access.principal_name",
            ),
            (
                vec![b'x'; 257],
                vec![],
                b"tb".to_vec(),
                "access.principal_name",
            ),
            (vec![0xff], vec![], b"tb".to_vec(), "access.principal_name"),
            (b"a".to_vec(), vec![Vec::new()], b"tb".to_vec(), "access.op"),
            (
                b"a".to_vec(),
                vec![vec![b'x'; 65]],
                b"tb".to_vec(),
                "access.op",
            ),
            (b"a".to_vec(), vec![vec![0xff]], b"tb".to_vec(), "access.op"),
            (
                b"a".to_vec(),
                vec![b"read".to_vec(); 33],
                b"tb".to_vec(),
                "access.ops",
            ),
            (b"a".to_vec(), vec![], Vec::new(), "access.command"),
            (b"a".to_vec(), vec![], vec![b'x'; 129], "access.command"),
            (b"a".to_vec(), vec![], vec![0xff], "access.command"),
        ] {
            let ops: Vec<_> = ops.iter().map(Vec::as_slice).collect();
            assert_eq!(
                decoded_error(&encode(&name, &ops, &command, 41)).what,
                field
            );
        }
        for ops in [
            vec![b"read".as_slice(), b"produce".as_slice()],
            vec![b"read".as_slice(), b"read".as_slice()],
        ] {
            let error = decoded_error(&encode(b"a", &ops, b"tb", 41));
            assert_eq!((error.what, error.reason), ("access.ops", Reason::Unsorted));
        }
        // Bounds count bytes, and canonical String order includes UTF-8.
        derive(&encode(
            "审核员".as_bytes(),
            &[b"Z", "é".as_bytes(), "界".as_bytes()],
            b"tb",
            0,
        ))
        .unwrap();
        derive(&encode(b"a", &[], b"tb", 41)).unwrap();
        let ops: Vec<_> = (0..32)
            .map(|n| format!("{n:02}{}", "x".repeat(62)))
            .collect();
        let ops: Vec<_> = ops.iter().map(String::as_bytes).collect();
        derive(&encode(
            &vec![b'n'; MAX_NAME],
            &ops,
            &vec![b'c'; MAX_COMMAND],
            41,
        ))
        .unwrap();
        assert_eq!(
            decoded_error(&encode("é".repeat(129).as_bytes(), &[], b"tb", 41)).what,
            "access.principal_name"
        );
    }

    #[test]
    fn access_payloads_refuse_wrong_frames_splits_and_nonhistorical_observations() {
        let payload = sample();
        for end in 0..payload.len() {
            assert!(derive(&payload[..end]).is_err(), "truncation at {end}");
        }
        let mut wrong_format = payload.clone();
        wrong_format[17] = b'2';
        assert_eq!(decoded_error(&wrong_format).what, "access.format");
        let mut trailing = payload.clone();
        trailing.push(0);
        assert_eq!(decoded_error(&trailing).reason, Reason::Trailing);
        for body_len in [0, payload.len() - 1, payload.len() + 1, usize::MAX] {
            assert_eq!(record(&payload, body_len, 42, 0), Err(RecordError::Split));
        }
        for observed in [42, 43, u64::MAX] {
            assert_eq!(
                decoded_error(&encode(b"a", &[], b"tb", observed)).what,
                "access.observed_at"
            );
        }
        let initial = encode(b"a", &[], b"tb", 0);
        assert!(record(&initial, initial.len(), 0, 0).is_err());
        assert!(record(&initial, initial.len(), 1, 0).is_ok());
    }

    #[test]
    fn access_record_tampering_and_rehashed_malformed_payloads_fail_offline() {
        let original = sample();
        let envelope = derive(&original).unwrap();
        let cp = anchor(&envelope);
        let changed = encode(b"other-reader", &[b"produce", b"read"], b"tb", 41);
        assert_eq!(
            check_record(&envelope, &changed, changed.len()),
            Err(RecordError::Envelope)
        );
        assert!(crate::verify_inclusion(&inclusion(&envelope, &changed), &cp).is_err());
        assert!(verify_prefix_with_records(&prefix(&envelope, &changed), &cp).is_err());

        let mut mismatches = Vec::new();
        let mut other = envelope.clone();
        other.book_id[0] ^= 1;
        mismatches.push(other);
        let mut other = envelope.clone();
        other.branch_id[0] = 1;
        mismatches.push(other);
        let mut other = envelope.clone();
        other.class = 2;
        mismatches.push(other);
        let mut other = envelope.clone();
        other.effective_day = Some(0);
        mismatches.push(other);
        let mut other = envelope.clone();
        other.account_vids.push(7);
        mismatches.push(other);
        let mut other = envelope.clone();
        other.unit_ids.push(1);
        mismatches.push(other);
        for wrong in mismatches {
            assert_eq!(
                check_record(&wrong, &original, original.len()),
                Err(RecordError::Envelope)
            );
        }
        for bad in [
            encode(b"", &[b"read"], b"tb", 41),
            encode(b"reader", &[b"read", b"read"], b"tb", 41),
            encode(b"reader", &[b"read"], &[0xff], 41),
            encode(b"reader", &[b"read"], b"tb", 42),
        ] {
            // A trusted root over a matching digest does not make malformed
            // fields canonical or an observation historical.
            let mut dishonest = envelope.clone();
            dishonest.record_digest = framed_digest(ACCESS_EVENT_DIGEST_DOMAIN, &bad);
            assert!(matches!(
                crate::verify_inclusion(&inclusion(&dishonest, &bad), &anchor(&dishonest)),
                Err(VerifyError::Record(RecordError::Decode(_)))
            ));
            assert!(matches!(
                verify_prefix_with_records(&prefix(&dishonest, &bad), &anchor(&dishonest)),
                Err(VerifyError::Record(RecordError::Decode(_)))
            ));
        }
    }
}
