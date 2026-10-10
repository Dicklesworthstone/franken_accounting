//! Field-level erasure (plan §8.5, §14.6, Appendix A `Erasable<T>`).
//!
//! An erasable field stores a digest that survives erasure and bytes sealed
//! under a subject key (or the book key when the field has no subject).
//! Payload digests cover `field_digest` only, so destroying the key erases
//! the value without changing any digest, amount, or proof.
//!
//! The digest is `BLAKE3("fa:field:v1" ‖ salt ‖ canonical(T))` where the
//! 32-byte salt travels only inside the ciphertext. Without the salt a short
//! field (a name, a memo) could be recovered after erasure by hashing
//! candidates against the digest; with it the digest is a hiding commitment.
//! Entropy for `salt` and `nonce` is the kernel's to supply under its `Cx` —
//! this module is deterministic.

use core::fmt;
use core::marker::PhantomData;

use fgdb_crypto::{Hasher, xchacha20poly1305_open, xchacha20poly1305_seal};
use fgdb_types::VId;

use crate::canon::{DecodeError, Reader, Writer};

pub const FIELD_DIGEST_DOMAIN: &[u8] = b"fa:field:v1";
pub const SEAL_AAD_DOMAIN: &[u8] = b"fa:erasable:v1";
const SALT_BYTES: usize = 32;
const TAG_BYTES: usize = 16;

/// A value with a canonical byte form.
pub trait Canonical: Sized {
    fn write_canonical(&self, w: &mut Writer);
    /// `max` bounds the value's own byte length.
    fn read_canonical(r: &mut Reader<'_>, max: usize) -> Result<Self, DecodeError>;
}

impl Canonical for String {
    fn write_canonical(&self, w: &mut Writer) {
        w.str(self);
    }

    fn read_canonical(r: &mut Reader<'_>, max: usize) -> Result<Self, DecodeError> {
        Ok(r.str(max, "erasable.string")?.to_string())
    }
}

/// A 32-byte symmetric key. Its bytes never print.
#[derive(Clone)]
pub struct SealKey(pub [u8; 32]);

impl fmt::Debug for SealKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealKey(<redacted>)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EraseError {
    /// The key did not open the bytes (wrong key, erased subject, or tamper).
    Sealed,
    /// The bytes opened but their digest is not `field_digest`.
    DigestMismatch,
    Decode(DecodeError),
}

impl fmt::Display for EraseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sealed => write!(f, "the field cannot be opened with this key"),
            Self::DigestMismatch => write!(f, "the opened value does not match field_digest"),
            Self::Decode(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for EraseError {}

/// The wire form: `field_digest ‖ opt(subject_ref) ‖ nonce ‖ bytes(sealed)`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Erasable<T> {
    field_digest: [u8; 32],
    subject_ref: Option<VId>,
    nonce: [u8; 24],
    sealed: Vec<u8>,
    _value: PhantomData<T>,
}

impl<T> fmt::Debug for Erasable<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Erasable(digest={}, subject={:?}, sealed_len={})",
            hex(&self.field_digest[..8]),
            self.subject_ref,
            self.sealed.len()
        )
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn field_digest(salt: &[u8; SALT_BYTES], canonical: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(FIELD_DIGEST_DOMAIN);
    h.update(salt);
    h.update(canonical);
    h.finalize().0
}

fn aad(field_digest: &[u8; 32]) -> Vec<u8> {
    let mut a = Vec::with_capacity(SEAL_AAD_DOMAIN.len() + 32);
    a.extend_from_slice(SEAL_AAD_DOMAIN);
    a.extend_from_slice(field_digest);
    a
}

impl<T: Canonical> Erasable<T> {
    /// Seal `value` under `key`. `salt` and `nonce` must be fresh entropy
    /// from the caller's `Cx`; reusing a nonce under one key is a caller bug.
    pub fn seal(
        value: &T,
        subject_ref: Option<VId>,
        key: &SealKey,
        salt: [u8; SALT_BYTES],
        nonce: [u8; 24],
    ) -> Self {
        let mut w = Writer::new();
        value.write_canonical(&mut w);
        // A canonical value never exceeds u32 lengths once validated; the
        // writer's overflow flag cannot trip for a bounded field.
        let canonical = w.finish().unwrap_or_default();
        let digest = field_digest(&salt, &canonical);
        let mut plain = Vec::with_capacity(SALT_BYTES + canonical.len());
        plain.extend_from_slice(&salt);
        plain.extend_from_slice(&canonical);
        let sealed = xchacha20poly1305_seal(&key.0, &nonce, &aad(&digest), &plain);
        Self {
            field_digest: digest,
            subject_ref,
            nonce,
            sealed,
            _value: PhantomData,
        }
    }

    /// Open with `key`; `max` bounds the value's byte length.
    pub fn open(&self, key: &SealKey, max: usize) -> Result<T, EraseError> {
        let plain =
            xchacha20poly1305_open(&key.0, &self.nonce, &aad(&self.field_digest), &self.sealed)
                .map_err(|_| EraseError::Sealed)?;
        if plain.len() < SALT_BYTES {
            return Err(EraseError::DigestMismatch);
        }
        let (salt, canonical) = plain.split_at(SALT_BYTES);
        let mut s = [0u8; SALT_BYTES];
        s.copy_from_slice(salt);
        if field_digest(&s, canonical) != self.field_digest {
            return Err(EraseError::DigestMismatch);
        }
        let mut r = Reader::new(canonical);
        let v = T::read_canonical(&mut r, max).map_err(EraseError::Decode)?;
        r.finish().map_err(EraseError::Decode)?;
        Ok(v)
    }
}

impl<T> Erasable<T> {
    #[must_use]
    pub fn field_digest(&self) -> [u8; 32] {
        self.field_digest
    }

    #[must_use]
    pub fn subject_ref(&self) -> Option<VId> {
        self.subject_ref
    }

    /// Bytes on the wire for this field (what the tag-size bound counts).
    #[must_use]
    pub fn wire_len(&self) -> usize {
        32 + 1 + if self.subject_ref.is_some() { 16 } else { 0 } + 24 + 4 + self.sealed.len()
    }

    pub fn encode(&self, w: &mut Writer) {
        w.fixed(&self.field_digest)
            .opt(self.subject_ref.as_ref(), |w, v| {
                w.u128(v.0);
            })
            .fixed(&self.nonce)
            .bytes(&self.sealed);
    }

    /// `max_plain` bounds the value's canonical length; the sealed bound
    /// follows from it (salt, length prefix, and tag).
    pub fn decode(r: &mut Reader<'_>, max_plain: usize) -> Result<Self, DecodeError> {
        let field_digest = r.fixed("erasable.digest")?;
        let subject_ref = r.opt("erasable.subject", |r| r.u128("erasable.subject").map(VId))?;
        let nonce = r.fixed("erasable.nonce")?;
        let sealed = r
            .bytes(SALT_BYTES + 4 + max_plain + TAG_BYTES, "erasable.sealed")?
            .to_vec();
        Ok(Self {
            field_digest,
            subject_ref,
            nonce,
            sealed,
            _value: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: SealKey = SealKey([0x11; 32]);

    #[test]
    fn seal_open_round_trip_and_wire_form() {
        let e = Erasable::seal(
            &"Rent — March".to_string(),
            Some(VId(5)),
            &KEY,
            [1; 32],
            [2; 24],
        );
        assert_eq!(e.open(&KEY, 1024).unwrap(), "Rent — March");
        let mut w = Writer::new();
        e.encode(&mut w);
        let b = w.finish().unwrap();
        assert_eq!(b.len(), e.wire_len());
        let mut r = Reader::new(&b);
        let d = Erasable::<String>::decode(&mut r, 1024).unwrap();
        r.finish().unwrap();
        assert_eq!(d, e);
        assert_eq!(d.open(&KEY, 1024).unwrap(), "Rent — March");
        assert_eq!(d.subject_ref(), Some(VId(5)));
        assert!(!format!("{e:?}").contains("Rent"));
    }

    #[test]
    fn wrong_key_tamper_and_bound_are_refused() {
        let e = Erasable::seal(&"secret".to_string(), None, &KEY, [1; 32], [2; 24]);
        assert_eq!(
            e.open(&SealKey([0x22; 32]), 64).unwrap_err(),
            EraseError::Sealed
        );
        // Flip a ciphertext byte: the AEAD tag fails.
        let mut t = e.clone();
        t.sealed[0] ^= 1;
        assert_eq!(t.open(&KEY, 64).unwrap_err(), EraseError::Sealed);
        // Swap the digest: the AAD binds it, so the open fails too.
        let mut t = e.clone();
        t.field_digest[0] ^= 1;
        assert_eq!(t.open(&KEY, 64).unwrap_err(), EraseError::Sealed);
        // A value longer than the caller's bound is refused at open.
        assert!(matches!(
            e.open(&KEY, 3).unwrap_err(),
            EraseError::Decode(_)
        ));
    }

    #[test]
    fn digest_hides_the_value_behind_the_salt() {
        let a = Erasable::seal(&"J. Smith".to_string(), None, &KEY, [1; 32], [2; 24]);
        let b = Erasable::seal(&"J. Smith".to_string(), None, &KEY, [9; 32], [2; 24]);
        let c = Erasable::seal(&"J. Smith".to_string(), None, &KEY, [1; 32], [3; 24]);
        // Same value, different salt: different digest — a guess cannot be
        // checked against the digest without the (erasable) salt.
        assert_ne!(a.field_digest(), b.field_digest());
        // Same value and salt: same digest regardless of nonce (the digest is
        // a function of the value, not of the ciphertext).
        assert_eq!(a.field_digest(), c.field_digest());
        assert_ne!(a.sealed, c.sealed);
    }
}
