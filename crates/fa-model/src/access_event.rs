//! The existing `fa:access-event:v1` payload, shared by its recorder and
//! accumulator (plan §9.7, §14.5; bead fa-0hs4.12).
//!
//! Moving the codec into the model does not change stored bytes, their
//! digest, or their vertex identity. An AccessEvent records an attempted
//! disclosure under an asserted capability; it is not a principal signature
//! or an acknowledgment that every protected byte was delivered.

use fgdb_types::{CommitSeq, VId};

use crate::{DecodeError, EncodeError, Id128, Reader, Writer, access_event_vid, domain_digest};

pub const ACCESS_EVENT_FORMAT: &[u8; 18] = b"fa:access-event:v1";
pub const ACCESS_EVENT_DIGEST_DOMAIN: &[u8] = b"fa:access-event-digest:v1";
pub const MAX_ACCESS_NAME: usize = 256;
pub const MAX_ACCESS_COMMAND: usize = 128;
pub const MAX_ACCESS_OPS: usize = 32;
pub const MAX_ACCESS_OP: usize = 64;

/// What one recorded read names. These fields retain their original facade
/// representation and canonical order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessRecord {
    pub principal: VId,
    pub principal_name: String,
    pub capability_commitment: [u8; 32],
    /// Strictly ascending operation names.
    pub ops: Vec<String>,
    pub command: String,
    pub request_digest: [u8; 32],
}

impl AccessRecord {
    /// The bounded shape required before a record can be published.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.principal_name.is_empty() || self.principal_name.len() > MAX_ACCESS_NAME {
            return Err("the access record's principal name is empty or too long");
        }
        if self.command.is_empty() || self.command.len() > MAX_ACCESS_COMMAND {
            return Err("the access record's command is empty or too long");
        }
        if self.ops.len() > MAX_ACCESS_OPS
            || self
                .ops
                .iter()
                .any(|op| op.is_empty() || op.len() > MAX_ACCESS_OP)
            || self.ops.windows(2).any(|w| w[0] >= w[1])
        {
            return Err("the access record's ops are not a bounded ascending set");
        }
        Ok(())
    }
}

/// The complete retained payload. Its recorded sequence comes from the
/// substrate row, not from this object; `observed_at` must precede it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessEvent {
    pub book_id: Id128,
    pub record: AccessRecord,
    pub observed_at: CommitSeq,
}

impl AccessEvent {
    /// The unchanged v1 bytes. As with other model encoders, the caller
    /// validates the record's shape before publication; decoding always
    /// validates it.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let record = &self.record;
        let mut w = Writer::new();
        w.fixed(ACCESS_EVENT_FORMAT)
            .fixed(&self.book_id.0)
            .u128(record.principal.0)
            .str(&record.principal_name)
            .fixed(&record.capability_commitment)
            .list(&record.ops, |w, op| {
                w.str(op);
            })
            .str(&record.command)
            .fixed(&record.request_digest)
            .u64(self.observed_at.0);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        if &r.fixed::<18>("access_event.format")? != ACCESS_EVENT_FORMAT {
            return Err(r.invalid("access_event.format"));
        }
        let book_id = Id128(r.fixed("access_event.book")?);
        let principal = VId(r.u128("access_event.principal")?);
        let principal_name = r
            .str(MAX_ACCESS_NAME, "access_event.principal_name")?
            .to_string();
        let capability_commitment = r.fixed("access_event.capability")?;
        let ops = r.list(MAX_ACCESS_OPS, "access_event.ops", |r| {
            r.str(MAX_ACCESS_OP, "access_event.op").map(str::to_string)
        })?;
        let command = r
            .str(MAX_ACCESS_COMMAND, "access_event.command")?
            .to_string();
        let request_digest = r.fixed("access_event.request")?;
        let observed_at = CommitSeq(r.u64("access_event.observed_at")?);
        let record = AccessRecord {
            principal,
            principal_name,
            capability_commitment,
            ops,
            command,
            request_digest,
        };
        if record.validate().is_err() {
            return Err(r.invalid("access_event.record"));
        }
        r.finish()?;
        Ok(Self {
            book_id,
            record,
            observed_at,
        })
    }

    pub fn digest(&self) -> Result<[u8; 32], EncodeError> {
        Ok(domain_digest(
            ACCESS_EVENT_DIGEST_DOMAIN,
            &[&self.canonical_bytes()?],
        ))
    }

    pub fn vid(&self) -> Result<VId, EncodeError> {
        Ok(access_event_vid(self.book_id, &self.digest()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> AccessEvent {
        AccessEvent {
            book_id: Id128([1; 16]),
            record: AccessRecord {
                principal: VId(7),
                principal_name: "auditor-1".into(),
                capability_commitment: [3; 32],
                ops: vec!["produce".into(), "read".into()],
                command: "tb".into(),
                request_digest: [4; 32],
            },
            observed_at: CommitSeq(9),
        }
    }

    #[test]
    fn access_event_codec_preserves_the_retained_v1_wire_bytes() {
        // Literal vector from the pre-extraction facade format, independently
        // constructed from its fixed-width fields and u32 length prefixes.
        let hex = concat!(
            "66613a6163636573732d6576656e743a7631",
            "01010101010101010101010101010101",
            "07000000000000000000000000000000",
            "0900000061756469746f722d31",
            "0303030303030303030303030303030303030303030303030303030303030303",
            "020000000700000070726f647563650400000072656164020000007462",
            "0404040404040404040404040404040404040404040404040404040404040404",
            "0900000000000000"
        );
        let bytes: Vec<u8> = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let original = event();
        assert_eq!(original.canonical_bytes().unwrap(), bytes);
        assert_eq!(AccessEvent::decode(&bytes).unwrap(), original);
        let mut changed = original.clone();
        changed.observed_at = CommitSeq(10);
        assert_ne!(changed.digest().unwrap(), original.digest().unwrap());
        assert_ne!(changed.vid().unwrap(), original.vid().unwrap());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(AccessEvent::decode(&trailing).is_err());
        for end in 0..bytes.len() {
            assert!(AccessEvent::decode(&bytes[..end]).is_err(), "prefix {end}");
        }
    }

    #[test]
    fn access_event_decode_refuses_noncanonical_record_shapes() {
        for ops in [
            vec!["read".into(), "produce".into()],
            vec!["read".into(), "read".into()],
            vec![String::new()],
            vec!["x".repeat(MAX_ACCESS_OP + 1)],
        ] {
            let mut bad = event();
            bad.record.ops = ops;
            assert!(bad.record.validate().is_err());
            assert!(AccessEvent::decode(&bad.canonical_bytes().unwrap()).is_err());
        }
        let mut bad = event();
        bad.record.principal_name.clear();
        assert!(AccessEvent::decode(&bad.canonical_bytes().unwrap()).is_err());
        bad = event();
        bad.record.command.clear();
        assert!(AccessEvent::decode(&bad.canonical_bytes().unwrap()).is_err());
    }
}
