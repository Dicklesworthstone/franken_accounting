//! Checkpoint signing (plan §13.2): Ed25519 (RFC 8032) over a
//! domain-separated transcript that excludes the signature fields.
//!
//! **Interim (Appendix H R-SIGN).** The substrate's crypto crate,
//! `fgdb-crypto`, has no signature scheme at the pinned revision, and no
//! suite project exposes one as its own API (asupersync's Ed25519 is the
//! third-party `nkeys` behind it). Until fgdb-crypto ships Ed25519
//! (upstream request: frankengraphdb#3), the notary signs with its own
//! [`ed25519`] and [`sha512`]. Callers see only [`CheckpointSigner`], so the
//! switch-over is one module: implement the trait over fgdb-crypto's
//! signer and delete these two files. `fa-verify` keeps its own,
//! independent verifier permanently (plan §13.3), and the differential
//! between the two is the evidence that they agree.
//!
//! Constant-time claim, verbatim and no stronger: constant-time by
//! construction (fixed-base table, mask-select behind an optimization
//! barrier, no secret-dependent branch or index); timed per host by a
//! dudect-style harness, `statistical` evidence per run (fa-cs80). Claim
//! class `bounded_model`, never `invariant`.

pub mod ed25519;
pub mod sha512;

pub use ed25519::SigningKey;

/// The registered signature schemes (`TransparencyCheckpoint` signatures'
/// `scheme`).
pub mod scheme {
    /// Ed25519, RFC 8032 §5.1, pure (no context, no prehash).
    pub const ED25519: u16 = 1;
}

/// What the notary needs from a checkpoint signer.
pub trait CheckpointSigner {
    /// A registered [`scheme`] id.
    fn scheme(&self) -> u16;
    /// The 32-byte public key a verifier is given out of band.
    fn public_key(&self) -> [u8; 32];
    /// The signature over `message` (the domain-separated transcript).
    fn sign(&self, message: &[u8]) -> [u8; 64];
}

impl CheckpointSigner for SigningKey {
    fn scheme(&self) -> u16 {
        scheme::ED25519
    }

    fn public_key(&self) -> [u8; 32] {
        SigningKey::public_key(self)
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        SigningKey::sign(self, message)
    }
}
