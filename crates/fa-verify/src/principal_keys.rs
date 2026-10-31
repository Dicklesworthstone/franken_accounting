//! Principal signing keys, read independently of the producer (plan §14.5,
//! Appendix A `TrustAnchorSet` and `signature`, bead fa-kae).
//!
//! ```text
//! key record   = u16 1 ‖ [16] book ‖ u128 principal ‖ u32 generation ‖ u16 scheme (1)
//!              ‖ [32] public_key ‖ [64] possession ‖ opt [64] endorsement
//!                (the canonical bytes of a PolicyControl SchemaChange of kind 24)
//! registration = "fa:principal-key-registration:v1" ‖ BLAKE3("fa:principal-key-registration:v1"
//!                ‖ each of book, principal, generation, scheme, public_key as u32 len ‖ bytes)
//! key_id       = BLAKE3("fa:principal-key-id:v1" ‖ u32 32 ‖ public_key)
//! attestation signature message = "fa:attestation-signature:v1" ‖ signed_digest
//! ```
//!
//! A chain runs from generation 0 without a gap. Every generation proves
//! possession by signing its registration with its own key, and each after
//! the first is also endorsed: the previous generation's key signs the same
//! registration. Bundle approvals ([`crate::bundle`]) and prefix
//! attestations ([`crate::attestation_signatures`]) both judge chains here.

use crate::blake3::hash_parts;
use crate::codec::{DecodeError, Reader, Reason};
use crate::ed25519;
use crate::tree::Digest;

pub(crate) const KEY_ID_DOMAIN: &[u8] = b"fa:principal-key-id:v1";
const REGISTRATION_DOMAIN: &[u8] = b"fa:principal-key-registration:v1";
const ATTESTATION_SIGNATURE_DOMAIN: &[u8] = b"fa:attestation-signature:v1";
/// Appendix A `signature.scheme`: Ed25519, the one scheme.
pub(crate) const SCHEME_ED25519: u16 = 1;
pub(crate) const KEY_VERSION: u16 = 1;
/// The kernel walks at most this many generations of one chain.
pub(crate) const MAX_KEY_GENERATIONS: usize = 64;

/// `BLAKE3(domain ‖ (u32 len ‖ part)...)`, fa-model's `domain_digest`.
pub(crate) fn framed(domain: &[u8], parts: &[&[u8]]) -> Digest {
    let mut framed: Vec<u8> = Vec::new();
    for part in parts {
        let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
        framed.extend_from_slice(&len.to_le_bytes());
        framed.extend_from_slice(part);
    }
    hash_parts(domain, &[&framed])
}

/// Digest equality without an early exit. Key ids are public, so this only
/// keeps one comparison shape for everything a signature names.
pub(crate) fn same_digest(a: &Digest, b: &Digest) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// What an attestation's signature covers.
pub(crate) fn attestation_message(signed_digest: &Digest) -> Vec<u8> {
    let mut message = ATTESTATION_SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(signed_digest);
    message
}

/// One generation of a principal's key chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeyGeneration {
    pub book_id: [u8; 16],
    pub principal: u128,
    pub generation: u32,
    pub public_key: [u8; 32],
    pub possession: [u8; 64],
    pub endorsement: Option<[u8; 64]>,
}

impl KeyGeneration {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let version = r.u16("principal_key.version")?;
        if version != KEY_VERSION {
            return Err(r.error(
                "principal_key.version",
                Reason::BadTag(version.to_le_bytes()[0]),
            ));
        }
        let book_id = r.fixed("principal_key.book_id")?;
        let principal = r.u128("principal_key.principal")?;
        let generation = r.u32("principal_key.generation")?;
        let scheme = r.u16("principal_key.scheme")?;
        if scheme != SCHEME_ED25519 {
            return Err(r.error(
                "principal_key.scheme",
                Reason::BadTag(scheme.to_le_bytes()[0]),
            ));
        }
        let public_key = r.fixed("principal_key.public_key")?;
        let possession = r.fixed("principal_key.possession")?;
        let endorsement = if r.present("principal_key.endorsement")? {
            Some(r.fixed("principal_key.endorsement")?)
        } else {
            None
        };
        r.finish("principal key")?;
        Ok(Self {
            book_id,
            principal,
            generation,
            public_key,
            possession,
            endorsement,
        })
    }

    pub(crate) fn key_id(&self) -> Digest {
        framed(KEY_ID_DOMAIN, &[&self.public_key])
    }

    /// The statement this generation's possession proof and endorsement
    /// sign.
    pub(crate) fn registration(&self) -> Vec<u8> {
        let mut message = REGISTRATION_DOMAIN.to_vec();
        message.extend_from_slice(&framed(
            REGISTRATION_DOMAIN,
            &[
                &self.book_id,
                &self.principal.to_le_bytes(),
                &self.generation.to_le_bytes(),
                &SCHEME_ED25519.to_le_bytes(),
                &self.public_key,
            ],
        ));
        message
    }

    /// Admit this generation after `previous` (`None` for an empty chain)
    /// on a chain that already holds `held` generations.
    pub(crate) fn admit(&self, previous: Option<&Self>, held: usize) -> Result<(), String> {
        if held >= MAX_KEY_GENERATIONS {
            return Err(format!(
                "a chain of more than {MAX_KEY_GENERATIONS} generations"
            ));
        }
        let expected = u32::try_from(held).unwrap_or(u32::MAX);
        if self.generation != expected {
            return Err(format!(
                "generation {} stands where generation {expected} belongs",
                self.generation
            ));
        }
        let message = self.registration();
        ed25519::verify(&self.public_key, &message, &self.possession).map_err(|e| {
            format!(
                "generation {expected}'s possession proof is not its key's signature of its registration: {e}"
            )
        })?;
        match (previous, &self.endorsement) {
            (None, None) => Ok(()),
            (Some(before), Some(endorsement)) => {
                ed25519::verify(&before.public_key, &message, endorsement).map_err(|e| {
                    format!(
                        "generation {expected} is not endorsed by generation {}'s key: {e}",
                        before.generation
                    )
                })
            }
            (None, Some(_)) => Err("generation 0 carries an endorsement".to_string()),
            (Some(_), None) => Err(format!("generation {expected} carries no endorsement")),
        }
    }
}

/// Generations 0..n in order, each admitted after the one before.
pub(crate) fn chain_grade(chain: &[KeyGeneration]) -> Result<(), String> {
    let mut previous: Option<&KeyGeneration> = None;
    for (held, key) in chain.iter().enumerate() {
        key.admit(previous, held)?;
        previous = Some(key);
    }
    Ok(())
}
