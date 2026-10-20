//! The signed `TransparencyCheckpoint` (plan §13.2, Appendix A), on the
//! verifier's side.
//!
//! ```text
//! body = schema_major u16 (1) ‖ schema_minor u16 (0)
//!      ‖ Checkpoint (book_id [16] ‖ branch_id [16] ‖ through_seq u64 ‖ leaf_count u64 ‖ root [32])
//!      ‖ state_oid [32] ‖ scope_index_root [32] ‖ substrate_chain_commitment [32]
//!      ‖ opt([32] witness_policy_oid) ‖ opt([32] time_evidence_oid)
//! body_digest    = BLAKE3("fa:checkpoint:v1" ‖ body)
//! signed message = "fa:checkpoint-signature:v1" ‖ body_digest
//! signature      = signer_key_id [32] ‖ scheme u16 ‖ bytes(signature)
//!                  signer_key_id = BLAKE3("fa:signer-key:v1" ‖ public key); scheme 1 = Ed25519
//! checkpoint     = body ‖ list(signature), strictly ascending by (signer_key_id, scheme)
//! oid            = BLAKE3("fa:transparency-checkpoint:v1" ‖ checkpoint)
//! ```
//!
//! [`verify_checkpoint`] takes the public keys the caller trusts (given out
//! of band; no trust-anchor set exists yet) and checks every signature made
//! by one of them with this crate's own Ed25519. At least one must be
//! present and every one must verify; signatures by keys the caller did
//! not name are reported, not judged. [`witness`] adds a separately configured
//! publisher requirement and distinct-key witness quorum without changing this
//! legacy any-trusted-signer interface.
//!
//! What a verified checkpoint establishes: the holder of a trusted key
//! signed this body, which presumes the key was validly generated. Every
//! trusted key is admitted first: one that is not a curve point, or is a
//! small-order point (no generated key is, and such a key would satisfy
//! the equation for any body), is refused with
//! [`CheckpointError::TrustedKey`] before any signature is read. It does not
//! establish that the scope index was derived correctly or that the ledger
//! is true (plan §13.2): [`crate::scope`] labels the premise.

pub mod witness;

use std::fmt;

use crate::blake3::hash_parts;
use crate::codec::{DecodeError, Reader, Reason};
use crate::ed25519::{self, SignatureError};
use crate::proof::{Checkpoint, VerifyError};
use crate::tree::Digest;

pub const CHECKPOINT_BODY_DOMAIN: &[u8] = b"fa:checkpoint:v1";
pub const CHECKPOINT_SIGNATURE_DOMAIN: &[u8] = b"fa:checkpoint-signature:v1";
pub const SIGNER_KEY_DOMAIN: &[u8] = b"fa:signer-key:v1";
pub const CHECKPOINT_OID_DOMAIN: &[u8] = b"fa:transparency-checkpoint:v1";
pub const CHECKPOINT_SCHEMA_MAJOR: u16 = 1;
pub const CHECKPOINT_SCHEMA_MINOR: u16 = 0;
/// Ed25519 (RFC 8032), the one registered scheme.
pub const SCHEME_ED25519: u16 = 1;

const MAX_SIGNATURES: usize = 64;
const MAX_SIGNATURE_BYTES: usize = 1024;

#[must_use]
pub fn signer_key_id(public_key: &[u8; 32]) -> Digest {
    hash_parts(SIGNER_KEY_DOMAIN, &[public_key])
}

/// Why a checkpoint's signatures do not verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckpointError {
    /// A key the caller named as trusted cannot be a validly generated
    /// Ed25519 key (not a curve point, or a small-order point).
    TrustedKey {
        signer_key_id: Digest,
        reason: SignatureError,
    },
    /// No signature was made by a key the caller trusts.
    NoTrustedSignature,
    /// A trusted key's signature uses a scheme this verifier does not know.
    Scheme { signer_key_id: Digest, scheme: u16 },
    /// A trusted key's Ed25519 signature is not 64 bytes.
    Length { signer_key_id: Digest, len: usize },
    /// A trusted key's signature does not verify over this body.
    Signature {
        signer_key_id: Digest,
        reason: SignatureError,
    },
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TrustedKey {
                signer_key_id,
                reason,
            } => write!(
                f,
                "the trusted key {} cannot be trusted: {reason}",
                crate::blake3::hex(signer_key_id)
            ),
            Self::NoTrustedSignature => {
                write!(f, "no signature by a key you trust")
            }
            Self::Scheme {
                signer_key_id,
                scheme,
            } => write!(
                f,
                "key {} signed with unregistered scheme {scheme}",
                crate::blake3::hex(signer_key_id)
            ),
            Self::Length { signer_key_id, len } => write!(
                f,
                "the signature by key {} is {len} bytes, not 64",
                crate::blake3::hex(signer_key_id)
            ),
            Self::Signature {
                signer_key_id,
                reason,
            } => write!(
                f,
                "the signature by key {} does not verify: {reason}",
                crate::blake3::hex(signer_key_id)
            ),
        }
    }
}

/// A checkpoint whose trusted signatures verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCheckpoint {
    /// The statement every accumulator proof is checked against.
    pub checkpoint: Checkpoint,
    pub state_oid: Digest,
    pub scope_index_root: Digest,
    pub substrate_chain_commitment: Digest,
    pub witness_policy_oid: Option<Digest>,
    pub time_evidence_oid: Option<Digest>,
    pub body_digest: Digest,
    pub oid: Digest,
    /// Key ids of the trusted keys whose signatures verified.
    pub signed_by: Vec<Digest>,
    /// Key ids of signatures by keys the caller did not trust (not judged).
    pub not_judged: Vec<Digest>,
}

struct Signature<'a> {
    signer_key_id: Digest,
    scheme: u16,
    bytes: &'a [u8],
}

/// Decode `bytes` as a checkpoint and verify every signature by a key in
/// `trusted_keys`; at least one is required.
pub fn verify_checkpoint(
    bytes: &[u8],
    trusted_keys: &[[u8; 32]],
) -> Result<SignedCheckpoint, VerifyError> {
    for key in trusted_keys {
        ed25519::check_public_key(key).map_err(|reason| {
            VerifyError::Checkpoint(CheckpointError::TrustedKey {
                signer_key_id: signer_key_id(key),
                reason,
            })
        })?;
    }
    let mut r = Reader::new(bytes);
    let major = r.u16("checkpoint.schema_major")?;
    if major != CHECKPOINT_SCHEMA_MAJOR {
        return Err(r
            .error(
                "checkpoint.schema_major",
                Reason::BadTag(major.to_le_bytes()[0]),
            )
            .into());
    }
    let minor = r.u16("checkpoint.schema_minor")?;
    if minor != CHECKPOINT_SCHEMA_MINOR {
        return Err(r
            .error(
                "checkpoint.schema_minor",
                Reason::BadTag(minor.to_le_bytes()[0]),
            )
            .into());
    }
    let checkpoint = Checkpoint::read(&mut r)?;
    let state_oid = r.fixed("checkpoint.state_oid")?;
    let scope_index_root = r.fixed("checkpoint.scope_index_root")?;
    let substrate_chain_commitment = r.fixed("checkpoint.substrate_chain_commitment")?;
    let witness_policy_oid = opt_digest(&mut r, "checkpoint.witness_policy_oid")?;
    let time_evidence_oid = opt_digest(&mut r, "checkpoint.time_evidence_oid")?;
    let body_len = bytes.len() - r.remaining();
    let body_digest = hash_parts(CHECKPOINT_BODY_DOMAIN, &[&bytes[..body_len]]);
    let n = r.count(MAX_SIGNATURES, 32 + 2 + 4, "checkpoint.signatures")?;
    let mut signatures = Vec::with_capacity(n);
    for _ in 0..n {
        signatures.push(Signature {
            signer_key_id: r.fixed("checkpoint.signer_key_id")?,
            scheme: r.u16("checkpoint.scheme")?,
            bytes: r.bytes(MAX_SIGNATURE_BYTES, "checkpoint.signature")?,
        });
    }
    if !signatures
        .windows(2)
        .all(|w| (w[0].signer_key_id, w[0].scheme) < (w[1].signer_key_id, w[1].scheme))
    {
        return Err(r.error("checkpoint.signatures", Reason::Unsorted).into());
    }
    r.finish("checkpoint")?;

    let mut message = CHECKPOINT_SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(&body_digest);
    let mut signed_by = Vec::new();
    let mut not_judged = Vec::new();
    for s in &signatures {
        let Some(key) = trusted_keys
            .iter()
            .find(|k| signer_key_id(k) == s.signer_key_id)
        else {
            not_judged.push(s.signer_key_id);
            continue;
        };
        if s.scheme != SCHEME_ED25519 {
            return Err(VerifyError::Checkpoint(CheckpointError::Scheme {
                signer_key_id: s.signer_key_id,
                scheme: s.scheme,
            }));
        }
        let sig: [u8; 64] = s.bytes.try_into().map_err(|_| {
            VerifyError::Checkpoint(CheckpointError::Length {
                signer_key_id: s.signer_key_id,
                len: s.bytes.len(),
            })
        })?;
        ed25519::verify(key, &message, &sig).map_err(|reason| {
            VerifyError::Checkpoint(CheckpointError::Signature {
                signer_key_id: s.signer_key_id,
                reason,
            })
        })?;
        signed_by.push(s.signer_key_id);
    }
    if signed_by.is_empty() {
        return Err(VerifyError::Checkpoint(CheckpointError::NoTrustedSignature));
    }
    Ok(SignedCheckpoint {
        checkpoint,
        state_oid,
        scope_index_root,
        substrate_chain_commitment,
        witness_policy_oid,
        time_evidence_oid,
        body_digest,
        oid: hash_parts(CHECKPOINT_OID_DOMAIN, &[bytes]),
        signed_by,
        not_judged,
    })
}

fn opt_digest(r: &mut Reader<'_>, what: &'static str) -> Result<Option<Digest>, DecodeError> {
    if r.present(what)? {
        Ok(Some(r.fixed(what)?))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHECKPOINT: &str = include_str!("../tests/fixtures/checkpoint_v1.txt");

    fn pinned() -> Vec<u8> {
        let hexed = CHECKPOINT
            .lines()
            .find_map(|l| l.strip_prefix("checkpoint "))
            .expect("pinned checkpoint");
        (0..hexed.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hexed[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// The pinned body (both optional oids absent: 2 + 2 + 80 + 3 × 32 + 2
    /// bytes) under one forged signature entry by `key` with `sig`.
    fn forged(body: &[u8], key: &[u8; 32], sig: &[u8; 64]) -> Vec<u8> {
        let mut out = body.to_vec();
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&signer_key_id(key));
        out.extend_from_slice(&SCHEME_ED25519.to_le_bytes());
        out.extend_from_slice(&64u32.to_le_bytes());
        out.extend_from_slice(sig);
        out
    }

    /// Ruling 3392 (WhiteCreek 3391): the identity key with R = identity,
    /// S = 0 would "sign" any body. As a trusted key it is refused at
    /// admission, typed, for two distinct bodies; so is every torsion
    /// encoding; the pinned checkpoint under its generated key still
    /// verifies.
    #[test]
    fn small_order_trusted_keys_are_refused_at_admission() {
        let checkpoint = pinned();
        let body = &checkpoint[..182];
        let mut other_body = body.to_vec();
        other_body[100] ^= 1;
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut candidate = [0u8; 64];
        candidate[..32].copy_from_slice(&identity);
        for b in [body, &other_body[..]] {
            assert_eq!(
                verify_checkpoint(&forged(b, &identity, &candidate), &[identity]),
                Err(VerifyError::Checkpoint(CheckpointError::TrustedKey {
                    signer_key_id: signer_key_id(&identity),
                    reason: SignatureError::SmallOrderKey,
                }))
            );
        }
        let torsion = crate::ed25519::tests::torsion_encodings();
        assert_eq!(torsion.len(), 8);
        for t in &torsion {
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(t);
            assert!(matches!(
                verify_checkpoint(&forged(body, t, &sig), &[*t]),
                Err(VerifyError::Checkpoint(CheckpointError::TrustedKey {
                    reason: SignatureError::SmallOrderKey,
                    ..
                }))
            ));
        }
        // Positive control: the generated key of the pinned checkpoint.
        let key_hex = CHECKPOINT
            .lines()
            .find_map(|l| l.strip_prefix("public_key "))
            .expect("pinned key");
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = u8::from_str_radix(&key_hex[2 * i..2 * i + 2], 16).expect("hex");
        }
        assert!(verify_checkpoint(&checkpoint, &[key]).is_ok());
    }
}
