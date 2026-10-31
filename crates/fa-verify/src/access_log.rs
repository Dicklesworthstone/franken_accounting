//! Offline extraction of recorded pre-disclosure access attempts (plan §9.7).
//!
//! The recipient supplies the sequence interval, optional principal ID, and
//! trusted signing keys. The signed checkpoint authenticates both the full
//! prefix and the canonical state's access-coverage boundary. Every prefix
//! payload is independently checked before filtering, including records that
//! will not appear in the result. Only native complete-prefix v2 is admitted.
//!
//! This proves a complete extract of recorded attempts in `(after, through]`,
//! not successful delivery, human identity, object-level access, current
//! authorization, or economic truth. It neither creates a retained report
//! artifact nor establishes coverage before the state's declared boundary.

use std::fmt;

use crate::checkpoint::{SignedCheckpoint, verify_checkpoint};
use crate::codec::Reader;
use crate::envelope::{KIND_ACCESS_EVENT, MAX_RECORD_BYTES, access};
use crate::proof::production::derivation::{
    MAX_PREFIX_PROOF_BYTES, PREFIX_FORMAT_V2, verify_prefix_with_records,
};
use crate::state::verify_state;

pub const SCOPE_ACCESS_LOG: &str = "access_log_complete";
pub const MAX_ACCESS_STATE_BYTES: usize = 4096;
pub const MAX_ACCESS_CHECKPOINT_BYTES: usize = 128 * 1024;
pub const MAX_ACCESS_TRUSTED_KEYS: usize = 64;

/// Recipient-owned selection by journal recording sequence, not observed time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessLogRequest {
    /// Exclusive lower bound, at or after authenticated access coverage.
    pub after_seq: u64,
    /// Inclusive upper bound, at or before the signed checkpoint.
    pub through_seq: u64,
    /// The recorded principal ID. Display names are not identity selectors.
    pub principal: Option<u128>,
}

/// A fully authenticated access-attempt payload at its journal position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAccessEvent {
    pub recorded_at: u64,
    pub within_commit_ordinal: u32,
    pub record_digest: [u8; 32],
    pub principal: u128,
    pub principal_name: String,
    pub capability_commitment: [u8; 32],
    pub ops: Vec<String>,
    pub command: String,
    pub request_digest: [u8; 32],
    pub observed_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAccessLog {
    pub scope: &'static str,
    pub checkpoint: SignedCheckpoint,
    pub access_after_seq: u64,
    pub request: AccessLogRequest,
    /// Every prefix record was checked, including excluded records.
    pub checked_records: usize,
    /// Complete selected attempts, ordered by sequence and within-commit ordinal.
    pub events: Vec<VerifiedAccessEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessLogError {
    pub predicate: &'static str,
    pub detail: String,
}

impl fmt::Display for AccessLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.predicate, self.detail)
    }
}

impl std::error::Error for AccessLogError {}

fn error(predicate: &'static str, detail: impl ToString) -> AccessLogError {
    AccessLogError {
        predicate,
        detail: detail.to_string(),
    }
}

/// Authenticate the existing canonical state, signed checkpoint, and native
/// v2 full prefix, then answer exactly the recipient's bounded selection.
/// No input supplies its own trust anchor or changes the recipient's scope.
pub fn verify_access_log(
    prefix: &[u8],
    state: &[u8],
    signed_checkpoint: &[u8],
    trusted_keys: &[[u8; 32]],
    request: &AccessLogRequest,
) -> Result<VerifiedAccessLog, AccessLogError> {
    if request.after_seq > request.through_seq {
        return Err(error("access.selection", "after_seq exceeds through_seq"));
    }
    for (bytes, max, label) in [
        (prefix, MAX_PREFIX_PROOF_BYTES, "prefix"),
        (state, MAX_ACCESS_STATE_BYTES, "state"),
        (signed_checkpoint, MAX_ACCESS_CHECKPOINT_BYTES, "checkpoint"),
    ] {
        if bytes.len() > max {
            return Err(error(
                "access.bounds",
                format!("{label} exceeds {max} bytes"),
            ));
        }
    }
    if trusted_keys.is_empty() || trusted_keys.len() > MAX_ACCESS_TRUSTED_KEYS {
        return Err(error(
            "access.trust",
            "supply 1..=64 recipient-trusted signing keys",
        ));
    }
    let tag = Reader::new(prefix)
        .bytes(64, "proof.format")
        .map_err(|e| error("access.prefix", e))?;
    if tag != PREFIX_FORMAT_V2 {
        return Err(error(
            "access.prefix",
            "access logs require native complete-prefix v2 with every payload",
        ));
    }
    let checkpoint = verify_checkpoint(signed_checkpoint, trusted_keys)
        .map_err(|e| error("access.checkpoint", e))?;
    extract(prefix, state, checkpoint, request)
}

// Private: the public entry point always verifies signatures over raw bytes.
fn extract(
    prefix: &[u8],
    state_bytes: &[u8],
    checkpoint: SignedCheckpoint,
    request: &AccessLogRequest,
) -> Result<VerifiedAccessLog, AccessLogError> {
    let state = verify_state(state_bytes).map_err(|e| error("access.state", e))?;
    if state.oid != checkpoint.state_oid || state.checkpoint != checkpoint.checkpoint {
        return Err(error(
            "access.state_binding",
            "state identity and checkpoint coordinates must match the signed checkpoint",
        ));
    }
    let access_after_seq = state.access_after_seq.ok_or_else(|| {
        error(
            "access.coverage",
            "state does not authenticate access-event coverage",
        )
    })?;
    if request.after_seq < access_after_seq {
        return Err(error(
            "access.coverage",
            "requested history starts before authenticated access coverage",
        ));
    }
    if request.after_seq > request.through_seq
        || request.through_seq > checkpoint.checkpoint.through_seq
    {
        return Err(error(
            "access.selection",
            "request must satisfy after_seq <= through_seq <= signed through_seq",
        ));
    }
    let verified = verify_prefix_with_records(prefix, &checkpoint.checkpoint)
        .map_err(|e| error("access.prefix", e))?;
    // Re-read the same immutable, fully verified bytes without retaining a
    // second copy of every payload. Bounds match the verified prefix exactly.
    let mut r = Reader::new(prefix);
    r.bytes(64, "proof.format")
        .map_err(|e| error("access.prefix", e))?;
    r.fixed::<80>("proof.checkpoint")
        .map_err(|e| error("access.prefix", e))?;
    let count = r
        .count(verified.envelopes.len(), 4, "prefix.envelopes")
        .map_err(|e| error("access.prefix", e))?;
    for _ in 0..count {
        r.bytes(MAX_RECORD_BYTES, "prefix.envelope")
            .map_err(|e| error("access.prefix", e))?;
    }
    r.count(verified.envelopes.len(), 16, "prefix.records")
        .map_err(|e| error("access.prefix", e))?;
    let mut events = Vec::new();
    for envelope in &verified.envelopes {
        r.u64("prefix.record.leaf_index")
            .map_err(|e| error("access.prefix", e))?;
        r.u32("prefix.record.proposal_len")
            .map_err(|e| error("access.prefix", e))?;
        let payload = r
            .bytes(MAX_RECORD_BYTES, "prefix.record.payload")
            .map_err(|e| error("access.prefix", e))?;
        if envelope.kind != KIND_ACCESS_EVENT {
            continue;
        }
        if envelope.commit_seq <= access_after_seq {
            return Err(error(
                "access.coverage",
                "access leaf precedes the state's exclusive coverage boundary",
            ));
        }
        let fields =
            access::fields(payload, envelope.commit_seq).map_err(|e| error("access.payload", e))?;
        if envelope.commit_seq <= request.after_seq
            || envelope.commit_seq > request.through_seq
            || request
                .principal
                .is_some_and(|principal| principal != fields.principal)
        {
            continue;
        }
        events.push(VerifiedAccessEvent {
            recorded_at: envelope.commit_seq,
            within_commit_ordinal: envelope.within_commit_ordinal,
            record_digest: envelope.record_digest,
            principal: fields.principal,
            principal_name: fields.principal_name.to_string(),
            capability_commitment: fields.capability_commitment,
            ops: fields.ops.into_iter().map(str::to_string).collect(),
            command: fields.command.to_string(),
            request_digest: fields.request_digest,
            observed_at: fields.observed_at,
        });
    }
    r.finish("complete access prefix")
        .map_err(|e| error("access.prefix", e))?;
    Ok(VerifiedAccessLog {
        scope: SCOPE_ACCESS_LOG,
        checkpoint,
        access_after_seq,
        request: *request,
        checked_records: verified.envelopes.len(),
        events,
    })
}
