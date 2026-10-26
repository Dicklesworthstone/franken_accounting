//! Signed `TransparencyCheckpoint`s (plan §13.2, Appendix A).
//!
//! ```text
//! body = schema_major u16 (1) ‖ schema_minor u16 (0)
//!      ‖ Statement (book_id [16] ‖ branch_id [16] ‖ through_seq u64 ‖ leaf_count u64 ‖ root [32])
//!      ‖ state_oid [32] ‖ scope_index_root [32] ‖ substrate_chain_commitment [32]
//!      ‖ opt([32] witness_policy_oid) ‖ opt([32] time_evidence_oid)
//! body_digest    = BLAKE3("fa:checkpoint:v1" ‖ body)
//! signed message = "fa:checkpoint-signature:v1" ‖ body_digest
//! signature      = signer_key_id [32] ‖ scheme u16 ‖ bytes(signature)
//!                  signer_key_id = BLAKE3("fa:signer-key:v1" ‖ public key)
//! checkpoint     = body ‖ list(signature), signatures strictly ascending by (signer_key_id, scheme)
//! oid            = BLAKE3("fa:transparency-checkpoint:v1" ‖ checkpoint)
//! vid            = low 128 bits of BLAKE3("fa:vid:transparency-checkpoint:v1" ‖ state_oid)
//! ```
//!
//! One checkpoint stands beside each journaled `AccumulatorState`, written
//! in the same transaction: it binds the state's statement and oid to the
//! prefix's scope-index root and to the substrate's chain commitment at the
//! same sequence (the Chronicle marker-chain hash, `snapshot_identity` of a
//! certified read there), and the book's signer signs the body's digest.
//! The signed message excludes the signatures, so witnesses can co-sign
//! the same body later as a new object.
//!
//! `time_evidence_oid`, when present, is the complete Entry digest of the
//! latest TimeEvidence in the covered journal prefix. New checkpoints bind
//! that tick without changing its source or corroboration grade. A prefix
//! without ticks and historical checkpoints made before this binding retain
//! `None`. This observation is not an exact physical checkpoint timestamp.
//! The independent signature verifier authenticates the reference; the
//! in-book verifier also re-derives it from the retained prefix (fa-7uhr).
//! `witness_policy_oid` remains absent until a policy is bound at creation.
//!
//! Every signer's public key is admitted before it signs (ruling 3392): a
//! key that is not a curve point, or is a small-order point, signs nothing
//! ([`SignError::UntrustableKey`]); fa-verify applies its own copy of the
//! same boundary to the keys a verifier trusts.
//!
//! No-claim boundary: a verified signature says the holder of the
//! configured key signed this body, which presumes the key was validly
//! generated. It does not attest that the scope index was derived correctly
//! or that the ledger is true (plan §13.2); a verifier who needs the index
//! recomputes it from a verified complete prefix.

use fa_model::{DecodeError, EncodeError, Id128, Oid, Reader, Writer};
use fgdb_crypto::Hasher;
use fgdb_types::{CommitSeq, VId};

use crate::Statement;
use crate::sign::CheckpointSigner;
use crate::sign::ed25519::{KeyError, check_public_key};
use crate::tree::Digest;

pub const CHECKPOINT_BODY_DOMAIN: &[u8] = b"fa:checkpoint:v1";
pub const CHECKPOINT_SIGNATURE_DOMAIN: &[u8] = b"fa:checkpoint-signature:v1";
pub const SIGNER_KEY_DOMAIN: &[u8] = b"fa:signer-key:v1";
pub const CHECKPOINT_OID_DOMAIN: &[u8] = b"fa:transparency-checkpoint:v1";
pub const CHECKPOINT_VID_DOMAIN: &[u8] = b"fa:vid:transparency-checkpoint:v1";
pub const CHECKPOINT_SCHEMA_MAJOR: u16 = 1;
pub const CHECKPOINT_SCHEMA_MINOR: u16 = 0;
/// Bounds for the decoder: signers per checkpoint and signature length.
pub const MAX_SIGNATURES: usize = 64;
const MAX_SIGNATURE_BYTES: usize = 1024;

fn hash(domain: &[u8], parts: &[&[u8]]) -> Digest {
    let mut h = Hasher::new();
    h.update(domain);
    for p in parts {
        h.update(p);
    }
    h.finalize().0
}

/// The id a signature names its key by.
#[must_use]
pub fn signer_key_id(public_key: &[u8; 32]) -> [u8; 32] {
    hash(SIGNER_KEY_DOMAIN, &[public_key])
}

#[must_use]
pub fn checkpoint_oid(canonical_bytes: &[u8]) -> Oid {
    Oid(hash(CHECKPOINT_OID_DOMAIN, &[canonical_bytes]))
}

/// The checkpoint vertex of the state `state_oid`: one per state.
#[must_use]
pub fn checkpoint_vid(state_oid: &Oid) -> VId {
    let d = hash(CHECKPOINT_VID_DOMAIN, &[&state_oid.0]);
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d[..16]);
    VId(u128::from_le_bytes(lo))
}

/// The signed part of a checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointBody {
    pub statement: Statement,
    pub state_oid: Oid,
    pub scope_index_root: Digest,
    pub substrate_chain_commitment: Digest,
    pub witness_policy_oid: Option<Oid>,
    pub time_evidence_oid: Option<Oid>,
}

impl CheckpointBody {
    fn encode(&self, w: &mut Writer) {
        w.u16(CHECKPOINT_SCHEMA_MAJOR).u16(CHECKPOINT_SCHEMA_MINOR);
        self.statement.encode(w);
        w.fixed(&self.state_oid.0)
            .fixed(&self.scope_index_root)
            .fixed(&self.substrate_chain_commitment)
            .opt(self.witness_policy_oid.as_ref(), |w, o| {
                w.fixed(&o.0);
            })
            .opt(self.time_evidence_oid.as_ref(), |w, o| {
                w.fixed(&o.0);
            });
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        if r.u16("checkpoint.schema_major")? != CHECKPOINT_SCHEMA_MAJOR {
            return Err(r.invalid("checkpoint.schema_major"));
        }
        if r.u16("checkpoint.schema_minor")? != CHECKPOINT_SCHEMA_MINOR {
            return Err(r.invalid("checkpoint.schema_minor"));
        }
        Ok(Self {
            statement: Statement {
                book_id: Id128(r.fixed("checkpoint.book_id")?),
                branch_id: Id128(r.fixed("checkpoint.branch_id")?),
                through_seq: CommitSeq(r.u64("checkpoint.through_seq")?),
                leaf_count: r.u64("checkpoint.leaf_count")?,
                root: r.fixed("checkpoint.root")?,
            },
            state_oid: Oid(r.fixed("checkpoint.state_oid")?),
            scope_index_root: r.fixed("checkpoint.scope_index_root")?,
            substrate_chain_commitment: r.fixed("checkpoint.substrate_chain_commitment")?,
            witness_policy_oid: r.opt("checkpoint.witness_policy_oid", |r| {
                r.fixed("checkpoint.witness_policy_oid").map(Oid)
            })?,
            time_evidence_oid: r.opt("checkpoint.time_evidence_oid", |r| {
                r.fixed("checkpoint.time_evidence_oid").map(Oid)
            })?,
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::with_capacity(256);
        self.encode(&mut w);
        w.finish()
    }

    pub fn digest(&self) -> Result<Digest, EncodeError> {
        Ok(hash(CHECKPOINT_BODY_DOMAIN, &[&self.canonical_bytes()?]))
    }

    /// The message every signer signs: the domain, then the body digest.
    pub fn signed_message(&self) -> Result<Vec<u8>, EncodeError> {
        let mut m = CHECKPOINT_SIGNATURE_DOMAIN.to_vec();
        m.extend_from_slice(&self.digest()?);
        Ok(m)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointSignature {
    pub signer_key_id: [u8; 32],
    pub scheme: u16,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparencyCheckpoint {
    pub body: CheckpointBody,
    /// Strictly ascending by `(signer_key_id, scheme)`.
    pub signatures: Vec<CheckpointSignature>,
}

/// Why a checkpoint could not be signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignError {
    Encode(EncodeError),
    /// A signer's public key cannot be trusted (ruling 3392): not a curve
    /// point, or a small-order point no validly generated key is.
    UntrustableKey {
        signer_key_id: [u8; 32],
        reason: KeyError,
    },
    /// The checkpoint already holds the most signatures a decoder admits.
    Full,
}

impl From<EncodeError> for SignError {
    fn from(e: EncodeError) -> Self {
        Self::Encode(e)
    }
}

impl core::fmt::Display for SignError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Encode(e) => write!(f, "checkpoint encoding: {e:?}"),
            Self::UntrustableKey { reason, .. } => {
                write!(f, "the checkpoint signer's key cannot be trusted: {reason}")
            }
            Self::Full => write!(
                f,
                "the checkpoint already holds {MAX_SIGNATURES} signatures, the most a verifier decodes"
            ),
        }
    }
}

impl TransparencyCheckpoint {
    /// `body` signed by each of `signers`, after admitting every signer's
    /// public key: one that is not a curve point or is a small-order point
    /// signs nothing.
    pub fn sign(
        body: CheckpointBody,
        signers: &[&dyn CheckpointSigner],
    ) -> Result<Self, SignError> {
        for s in signers {
            let key = s.public_key();
            check_public_key(&key).map_err(|reason| SignError::UntrustableKey {
                signer_key_id: signer_key_id(&key),
                reason,
            })?;
        }
        let message = body.signed_message()?;
        let mut signatures: Vec<CheckpointSignature> = signers
            .iter()
            .map(|s| CheckpointSignature {
                signer_key_id: signer_key_id(&s.public_key()),
                scheme: s.scheme(),
                bytes: s.sign(&message).to_vec(),
            })
            .collect();
        signatures.sort_by_key(|s| (s.signer_key_id, s.scheme));
        signatures.dedup_by_key(|s| (s.signer_key_id, s.scheme));
        Ok(Self { body, signatures })
    }

    /// This checkpoint with `witness`'s signature added beside the others
    /// (plan §13.5): the same body, so a cosignature attests the root a
    /// witness observed, never the ledger's content. A key that already
    /// signed is not added twice. The result is a new object: its oid
    /// covers the signatures, the body digest does not.
    pub fn cosign(&self, witness: &dyn CheckpointSigner) -> Result<Self, SignError> {
        let key = witness.public_key();
        let id = signer_key_id(&key);
        check_public_key(&key).map_err(|reason| SignError::UntrustableKey {
            signer_key_id: id,
            reason,
        })?;
        let mut signatures = self.signatures.clone();
        if !signatures
            .iter()
            .any(|s| (s.signer_key_id, s.scheme) == (id, witness.scheme()))
        {
            if signatures.len() >= MAX_SIGNATURES {
                return Err(SignError::Full);
            }
            signatures.push(CheckpointSignature {
                signer_key_id: id,
                scheme: witness.scheme(),
                bytes: witness.sign(&self.body.signed_message()?).to_vec(),
            });
            signatures.sort_by_key(|s| (s.signer_key_id, s.scheme));
        }
        Ok(Self {
            body: self.body.clone(),
            signatures,
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::with_capacity(256 + 112 * self.signatures.len());
        self.body.encode(&mut w);
        w.list(&self.signatures, |w, s| {
            w.fixed(&s.signer_key_id).u16(s.scheme).bytes(&s.bytes);
        });
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let body = CheckpointBody::read(&mut r)?;
        let signatures = r.list(MAX_SIGNATURES, "checkpoint.signatures", |r| {
            Ok(CheckpointSignature {
                signer_key_id: r.fixed("checkpoint.signer_key_id")?,
                scheme: r.u16("checkpoint.scheme")?,
                bytes: r
                    .bytes(MAX_SIGNATURE_BYTES, "checkpoint.signature")?
                    .to_vec(),
            })
        })?;
        if !signatures
            .windows(2)
            .all(|w| (w[0].signer_key_id, w[0].scheme) < (w[1].signer_key_id, w[1].scheme))
        {
            return Err(r.unsorted("checkpoint.signatures"));
        }
        r.finish()?;
        Ok(Self { body, signatures })
    }

    pub fn oid(&self) -> Result<Oid, EncodeError> {
        Ok(checkpoint_oid(&self.canonical_bytes()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::SigningKey;

    fn body() -> CheckpointBody {
        CheckpointBody {
            statement: Statement {
                book_id: Id128([1; 16]),
                branch_id: Id128::TRUNK,
                through_seq: CommitSeq(9),
                leaf_count: 4,
                root: [2; 32],
            },
            state_oid: Oid([3; 32]),
            scope_index_root: [4; 32],
            substrate_chain_commitment: [5; 32],
            witness_policy_oid: None,
            time_evidence_oid: None,
        }
    }

    /// Round trip; signatures sorted and deduplicated; the signed message
    /// covers every body field and no signature; any byte changed is
    /// another object or refused.
    #[test]
    fn checkpoints_round_trip_and_bind_every_body_field() {
        let a = SigningKey::from_seed(&[7; 32]);
        let b = SigningKey::from_seed(&[8; 32]);
        let cp = TransparencyCheckpoint::sign(body(), &[&b, &a, &b]).unwrap();
        assert_eq!(cp.signatures.len(), 2);
        let bytes = cp.canonical_bytes().unwrap();
        assert_eq!(TransparencyCheckpoint::decode(&bytes).unwrap(), cp);
        let message = cp.body.signed_message().unwrap();
        let mut variants = Vec::new();
        let mut v = body();
        v.statement.leaf_count = 5;
        variants.push(v);
        let mut v = body();
        v.scope_index_root[0] ^= 1;
        variants.push(v);
        let mut v = body();
        v.substrate_chain_commitment[31] ^= 1;
        variants.push(v);
        let mut v = body();
        v.time_evidence_oid = Some(Oid([6; 32]));
        variants.push(v);
        for v in variants {
            assert_ne!(v.signed_message().unwrap(), message);
        }
        // The body bytes are a prefix of the object; trailing bytes refused.
        let mut long = bytes.clone();
        long.push(0);
        assert!(TransparencyCheckpoint::decode(&long).is_err());
        // Unsorted signatures are refused.
        let mut swapped = cp.clone();
        swapped.signatures.reverse();
        assert!(TransparencyCheckpoint::decode(&swapped.canonical_bytes().unwrap()).is_err());
    }

    /// A witness cosigns the same body (fa-qtfd): the result keeps the
    /// body, holds both signatures in order, is another object, verifies
    /// under both keys with the independent verifier, and cosigning again
    /// changes nothing; an untrustable witness key and a full signature
    /// list are refused.
    #[test]
    fn a_witness_cosigns_the_same_body_as_a_new_object() {
        let book = SigningKey::from_seed(&[7; 32]);
        let witness = SigningKey::from_seed(&[9; 32]);
        let signed = TransparencyCheckpoint::sign(body(), &[&book]).unwrap();
        let cosigned = signed.cosign(&witness).unwrap();
        assert_eq!(cosigned.body, signed.body);
        assert_eq!(cosigned.signatures.len(), 2);
        assert!(
            cosigned
                .signatures
                .windows(2)
                .all(|w| (w[0].signer_key_id, w[0].scheme) < (w[1].signer_key_id, w[1].scheme))
        );
        assert_ne!(cosigned.oid().unwrap(), signed.oid().unwrap());
        assert_eq!(cosigned.cosign(&witness).unwrap(), cosigned, "once per key");
        let bytes = cosigned.canonical_bytes().unwrap();
        assert_eq!(TransparencyCheckpoint::decode(&bytes).unwrap(), cosigned);
        let verified =
            fa_verify::verify_checkpoint(&bytes, &[book.public_key(), witness.public_key()])
                .unwrap();
        assert_eq!(verified.signed_by.len(), 2);

        let mut identity = [0u8; 32];
        identity[0] = 1;
        let untrustable = Fixed {
            public: identity,
            sig: [0; 64],
        };
        assert!(matches!(
            signed.cosign(&untrustable),
            Err(SignError::UntrustableKey { .. })
        ));
        let keys: Vec<SigningKey> = (0..MAX_SIGNATURES)
            .map(|i| SigningKey::from_seed(&[u8::try_from(i).unwrap() + 10; 32]))
            .collect();
        let signers: Vec<&dyn CheckpointSigner> =
            keys.iter().map(|k| k as &dyn CheckpointSigner).collect();
        let full = TransparencyCheckpoint::sign(body(), &signers).unwrap();
        assert_eq!(full.signatures.len(), MAX_SIGNATURES);
        assert!(matches!(full.cosign(&witness), Err(SignError::Full)));
    }

    /// A signer reporting `public` and signing every message with `sig`.
    struct Fixed {
        public: [u8; 32],
        sig: [u8; 64],
    }

    impl CheckpointSigner for Fixed {
        fn scheme(&self) -> u16 {
            crate::sign::scheme::ED25519
        }
        fn public_key(&self) -> [u8; 32] {
            self.public
        }
        fn sign(&self, _: &[u8]) -> [u8; 64] {
            self.sig
        }
    }

    /// Ruling 3392 (WhiteCreek 3391): the identity key with R = identity,
    /// S = 0 "signs" any body under the bare cofactored equation. The
    /// producer refuses to sign with it (typed), for two distinct bodies and
    /// for every torsion encoding; a checkpoint forged with it by hand is
    /// refused by the independent verifier at trusted-key admission; a
    /// generated key signs and verifies.
    #[test]
    fn small_order_signer_keys_sign_nothing_and_verify_nothing() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut candidate = [0u8; 64];
        candidate[..32].copy_from_slice(&identity);
        let mut other = body();
        other.scope_index_root[0] ^= 1;
        let fixed = Fixed {
            public: identity,
            sig: candidate,
        };
        for b in [body(), other.clone()] {
            assert_eq!(
                TransparencyCheckpoint::sign(b.clone(), &[&fixed]),
                Err(SignError::UntrustableKey {
                    signer_key_id: signer_key_id(&identity),
                    reason: KeyError::SmallOrder,
                })
            );
            // Forged by hand, past the producer: the verifier refuses the key.
            let forged = TransparencyCheckpoint {
                body: b,
                signatures: vec![CheckpointSignature {
                    signer_key_id: signer_key_id(&identity),
                    scheme: crate::sign::scheme::ED25519,
                    bytes: candidate.to_vec(),
                }],
            };
            let refused =
                fa_verify::verify_checkpoint(&forged.canonical_bytes().unwrap(), &[identity]);
            assert!(
                matches!(
                    refused,
                    Err(fa_verify::VerifyError::Checkpoint(
                        fa_verify::CheckpointError::TrustedKey { .. }
                    ))
                ),
                "{refused:?}"
            );
        }
        for t in crate::sign::ed25519::tests::torsion_encodings() {
            let fixed = Fixed {
                public: t,
                sig: [0; 64],
            };
            assert!(matches!(
                TransparencyCheckpoint::sign(body(), &[&fixed]),
                Err(SignError::UntrustableKey {
                    reason: KeyError::SmallOrder,
                    ..
                })
            ));
        }
        let key = SigningKey::from_seed(&[9; 32]);
        let signed = TransparencyCheckpoint::sign(other, &[&key]).unwrap();
        assert!(
            fa_verify::verify_checkpoint(&signed.canonical_bytes().unwrap(), &[key.public_key()])
                .is_ok(),
            "positive control"
        );
    }
}
