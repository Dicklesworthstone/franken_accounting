//! Principal signing keys (plan §14.5 non-repudiation, Appendix A
//! `TrustAnchorSet` and `signature: { scheme, key_id, bytes }`, bead
//! fa-kae).
//!
//! A principal's keys form a chain of generations, each journaled as one
//! PolicyControl record. Generation 0 registers the first key; generation
//! `g > 0` rotates to a new key and must be endorsed by generation `g − 1`'s
//! key, so holding the principal's capability alone never replaces its key.
//! Every generation carries proof of possession: the new key's signature
//! over the registration statement. Generation `g` is valid from its
//! recorded sequence until generation `g + 1`'s.
//!
//! Once a principal has a key, each approval it records carries a signature
//! by its current key over [`approval_message`] of the approval's digest;
//! the signature sits outside that digest, as Appendix A places it. A
//! signature proves possession of the key, not that a human pressed it.
//!
//! This crate is pure: [`SignatureVerifier`] is implemented above the kernel
//! (fa-notary's Ed25519) and passed down by the facade.

use fa_model::{DecodeError, EncodeError, Id128, Reader, Writer, domain_digest};
use fgdb_types::VId;

/// Appendix A `signature.scheme`: Ed25519 (RFC 8032), the one scheme.
pub const SCHEME_ED25519: u16 = 1;
/// A chain is at most this long; a longer one is refused, never walked.
pub const MAX_KEY_GENERATIONS: u32 = 64;

const KEY_VERSION: u16 = 1;
const KEY_ID_DOMAIN: &[u8] = b"fa:principal-key-id:v1";
const REGISTRATION_DOMAIN: &[u8] = b"fa:principal-key-registration:v1";
const APPROVAL_SIGNATURE_DOMAIN: &[u8] = b"fa:approval-signature:v1";

/// Ed25519 verification, supplied by the layer that owns the signer.
pub trait SignatureVerifier: Send + Sync + core::fmt::Debug {
    /// Whether `signature` is `public_key`'s valid Ed25519 signature of
    /// `message`.
    fn verify_ed25519(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool;
}

/// `key_id = BLAKE3("fa:principal-key-id:v1" ‖ len ‖ public_key)`.
#[must_use]
pub fn key_id(public_key: &[u8; 32]) -> [u8; 32] {
    domain_digest(KEY_ID_DOMAIN, &[public_key])
}

/// What a signed approval's signature covers: the approval's digest
/// (`Approval::digest`) under its own domain.
#[must_use]
pub fn approval_message(approval_digest: &[u8; 32]) -> Vec<u8> {
    let mut message = APPROVAL_SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(approval_digest);
    message
}

/// The statement a registration's possession proof and endorsement sign.
#[must_use]
pub fn registration_message(
    book_id: Id128,
    principal: VId,
    generation: u32,
    public_key: &[u8; 32],
) -> Vec<u8> {
    let mut message = REGISTRATION_DOMAIN.to_vec();
    message.extend_from_slice(&domain_digest(
        REGISTRATION_DOMAIN,
        &[
            &book_id.0,
            &principal.0.to_le_bytes(),
            &generation.to_le_bytes(),
            &SCHEME_ED25519.to_le_bytes(),
            public_key,
        ],
    ));
    message
}

/// One generation of a principal's key chain: the body of its
/// PolicyControl record (extension `fa:principal-key:v1`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalKey {
    pub book_id: Id128,
    pub principal: VId,
    pub generation: u32,
    pub public_key: [u8; 32],
    /// The new key's signature over [`registration_message`].
    pub possession: [u8; 64],
    /// Generation `g − 1`'s signature over the same statement; absent
    /// exactly for generation 0.
    pub endorsement: Option<[u8; 64]>,
}

/// Why a key generation or a signature is not admissible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// The chain already holds `expected` generations.
    Generation { expected: u32, found: u32 },
    /// The chain is at [`MAX_KEY_GENERATIONS`].
    ChainFull,
    /// Generation 0 carries an endorsement, or a later one lacks it.
    Endorsement,
    /// The new key's possession proof does not verify.
    Possession,
    /// The previous generation's endorsement does not verify.
    EndorsementSignature,
    /// A keyed principal's approval carries no signature.
    Unsigned,
    /// An unkeyed principal's approval carries a signature.
    NoKey,
    /// The signature names a scheme other than Ed25519.
    Scheme(u16),
    /// The signature names a generation or key other than the current one.
    NotCurrent { generation: u32, current: u32 },
    /// The signature does not verify against the current key.
    Signature,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Generation { expected, found } => write!(
                f,
                "the principal's key chain holds {expected} generations, so the next is generation {expected}, not {found}"
            ),
            Self::ChainFull => write!(
                f,
                "the principal's key chain is at its {MAX_KEY_GENERATIONS}-generation bound"
            ),
            Self::Endorsement => write!(
                f,
                "generation 0 is not endorsed, and every later generation is endorsed by the one before it"
            ),
            Self::Possession => write!(
                f,
                "the possession proof is not the new key's signature of the registration statement"
            ),
            Self::EndorsementSignature => write!(
                f,
                "the endorsement is not the current key's signature of the registration statement"
            ),
            Self::Unsigned => write!(
                f,
                "the approving principal has a registered signing key, so its approval must be signed"
            ),
            Self::NoKey => write!(
                f,
                "the approving principal has no registered signing key, so a signature has nothing to verify against"
            ),
            Self::Scheme(scheme) => write!(f, "signature scheme {scheme} is not Ed25519 (1)"),
            Self::NotCurrent {
                generation,
                current,
            } => write!(
                f,
                "the signature names key generation {generation}; the current generation is {current}"
            ),
            Self::Signature => write!(
                f,
                "the signature is not the current key's signature of this approval's digest"
            ),
        }
    }
}

impl PrincipalKey {
    /// `key_id` of this generation's public key.
    #[must_use]
    pub fn key_id(&self) -> [u8; 32] {
        key_id(&self.public_key)
    }

    /// The statement this generation's proofs sign.
    #[must_use]
    pub fn message(&self) -> Vec<u8> {
        registration_message(
            self.book_id,
            self.principal,
            self.generation,
            &self.public_key,
        )
    }

    /// Admit this generation onto a chain whose current public key is
    /// `previous` (`None` when the chain is empty) and which holds
    /// `generations` records.
    pub fn check(
        &self,
        generations: u32,
        previous: Option<&[u8; 32]>,
        verifier: &dyn SignatureVerifier,
    ) -> Result<(), KeyError> {
        if generations >= MAX_KEY_GENERATIONS {
            return Err(KeyError::ChainFull);
        }
        if self.generation != generations {
            return Err(KeyError::Generation {
                expected: generations,
                found: self.generation,
            });
        }
        let message = self.message();
        if !verifier.verify_ed25519(&self.public_key, &message, &self.possession) {
            return Err(KeyError::Possession);
        }
        match (previous, &self.endorsement) {
            (None, None) => Ok(()),
            (Some(previous), Some(endorsement)) => {
                if verifier.verify_ed25519(previous, &message, endorsement) {
                    Ok(())
                } else {
                    Err(KeyError::EndorsementSignature)
                }
            }
            _ => Err(KeyError::Endorsement),
        }
    }

    /// `u16 version ‖ id128 book ‖ u128 principal ‖ u32 generation ‖ u16
    /// scheme ‖ [32] public_key ‖ [64] possession ‖ opt [64] endorsement`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::with_capacity(2 + 16 + 16 + 4 + 2 + 32 + 64 + 65);
        w.u16(KEY_VERSION)
            .fixed(&self.book_id.0)
            .u128(self.principal.0)
            .u32(self.generation)
            .u16(SCHEME_ED25519)
            .fixed(&self.public_key)
            .fixed(&self.possession)
            .opt(self.endorsement.as_ref(), |w, e| {
                w.fixed(e);
            });
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.u16("principal_key.version")? != KEY_VERSION {
            return Err(r.invalid("principal_key.version"));
        }
        let book_id = Id128(r.fixed("principal_key.book_id")?);
        let principal = VId(r.u128("principal_key.principal")?);
        let generation = r.u32("principal_key.generation")?;
        if r.u16("principal_key.scheme")? != SCHEME_ED25519 {
            return Err(r.invalid("principal_key.scheme"));
        }
        let public_key = r.fixed("principal_key.public_key")?;
        let possession = r.fixed("principal_key.possession")?;
        let endorsement = r.opt("principal_key.endorsement", |r| {
            r.fixed("principal_key.endorsement")
        })?;
        r.finish()?;
        if (generation == 0) != endorsement.is_none() {
            return Err(DecodeError {
                offset: 0,
                what: "principal_key.endorsement",
                reason: fa_model::canon::Reason::Invalid,
            });
        }
        Ok(Self {
            book_id,
            principal,
            generation,
            public_key,
            possession,
            endorsement,
        })
    }
}

/// Appendix A `signature`: an approval's signature by its principal's key
/// generation `generation` (whose `key_id` it names).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApprovalSignature {
    pub scheme: u16,
    pub generation: u32,
    pub key_id: [u8; 32],
    pub bytes: [u8; 64],
}

impl ApprovalSignature {
    /// Admit this signature of the approval digest `digest` against the
    /// principal's current key, generation `current` with `public_key`.
    pub fn check(
        &self,
        digest: &[u8; 32],
        current: u32,
        public_key: &[u8; 32],
        verifier: &dyn SignatureVerifier,
    ) -> Result<(), KeyError> {
        if self.scheme != SCHEME_ED25519 {
            return Err(KeyError::Scheme(self.scheme));
        }
        if self.generation != current || self.key_id != key_id(public_key) {
            return Err(KeyError::NotCurrent {
                generation: self.generation,
                current,
            });
        }
        if verifier.verify_ed25519(public_key, &approval_message(digest), &self.bytes) {
            Ok(())
        } else {
            Err(KeyError::Signature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for Ed25519 that exercises the chain's logic, not the
    /// curve: a "signature" is a digest binding the key and the message.
    /// The real scheme is fa-notary's, run end to end through the CLI.
    #[derive(Debug)]
    struct Stand;

    fn sign(public_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&domain_digest(b"test-sig-a", &[public_key, message]));
        out[32..].copy_from_slice(&domain_digest(b"test-sig-b", &[public_key, message]));
        out
    }

    impl SignatureVerifier for Stand {
        fn verify_ed25519(
            &self,
            public_key: &[u8; 32],
            message: &[u8],
            signature: &[u8; 64],
        ) -> bool {
            let expected = sign(public_key, message);
            expected
                .iter()
                .zip(signature)
                .fold(0u8, |diff, (a, b)| diff | (a ^ b))
                == 0
        }
    }

    const BOOK: Id128 = Id128([3; 16]);
    const WHO: VId = VId(77);

    fn generation(g: u32, public_key: [u8; 32], previous: Option<[u8; 32]>) -> PrincipalKey {
        let message = registration_message(BOOK, WHO, g, &public_key);
        PrincipalKey {
            book_id: BOOK,
            principal: WHO,
            generation: g,
            public_key,
            possession: sign(&public_key, &message),
            endorsement: previous.map(|prev| sign(&prev, &message)),
        }
    }

    #[test]
    fn a_chain_admits_its_next_generation_only_with_possession_and_endorsement() {
        let first = generation(0, [1; 32], None);
        assert_eq!(first.check(0, None, &Stand), Ok(()));
        let second = generation(1, [2; 32], Some([1; 32]));
        assert_eq!(second.check(1, Some(&[1; 32]), &Stand), Ok(()));
        assert_eq!(
            second.check(2, Some(&[1; 32]), &Stand),
            Err(KeyError::Generation {
                expected: 2,
                found: 1
            })
        );
        let mut unendorsed = second.clone();
        unendorsed.endorsement = None;
        assert_eq!(
            unendorsed.check(1, Some(&[1; 32]), &Stand),
            Err(KeyError::Endorsement)
        );
        // Endorsed by a key that is not the chain's current one.
        let usurper = generation(1, [9; 32], Some([8; 32]));
        assert_eq!(
            usurper.check(1, Some(&[1; 32]), &Stand),
            Err(KeyError::EndorsementSignature)
        );
        let mut forged = first.clone();
        forged.possession[0] ^= 1;
        assert_eq!(forged.check(0, None, &Stand), Err(KeyError::Possession));
        let mut endorsed_first = first.clone();
        endorsed_first.endorsement = Some([0; 64]);
        assert_eq!(
            endorsed_first.check(0, None, &Stand),
            Err(KeyError::Endorsement)
        );
        // The statement binds book, principal and generation: a proof made
        // for one principal does not register another.
        let mut moved = second;
        moved.principal = VId(78);
        assert_eq!(
            moved.check(1, Some(&[1; 32]), &Stand),
            Err(KeyError::Possession)
        );
        assert_eq!(
            first.check(MAX_KEY_GENERATIONS, None, &Stand),
            Err(KeyError::ChainFull)
        );
    }

    #[test]
    fn a_generation_round_trips_and_refuses_a_misplaced_endorsement() {
        for key in [
            generation(0, [1; 32], None),
            generation(1, [2; 32], Some([1; 32])),
        ] {
            let bytes = key.canonical_bytes().unwrap();
            assert_eq!(PrincipalKey::decode(&bytes).unwrap(), key);
            let mut long = bytes;
            long.push(0);
            assert!(PrincipalKey::decode(&long).is_err());
        }
        let mut endorsed_first = generation(0, [1; 32], None);
        endorsed_first.endorsement = Some([5; 64]);
        assert!(PrincipalKey::decode(&endorsed_first.canonical_bytes().unwrap()).is_err());
    }

    #[test]
    fn an_approval_signature_must_be_the_current_keys_over_this_digest() {
        let digest = [7u8; 32];
        let public_key = [2u8; 32];
        let signature = ApprovalSignature {
            scheme: SCHEME_ED25519,
            generation: 1,
            key_id: key_id(&public_key),
            bytes: sign(&public_key, &approval_message(&digest)),
        };
        assert_eq!(signature.check(&digest, 1, &public_key, &Stand), Ok(()));
        assert_eq!(
            signature.check(&[8; 32], 1, &public_key, &Stand),
            Err(KeyError::Signature)
        );
        assert_eq!(
            signature.check(&digest, 2, &public_key, &Stand),
            Err(KeyError::NotCurrent {
                generation: 1,
                current: 2
            })
        );
        assert_eq!(
            signature.check(&digest, 1, &[3; 32], &Stand),
            Err(KeyError::NotCurrent {
                generation: 1,
                current: 1
            })
        );
        let other = ApprovalSignature {
            scheme: 2,
            ..signature
        };
        assert_eq!(
            other.check(&digest, 1, &public_key, &Stand),
            Err(KeyError::Scheme(2))
        );
    }
}
